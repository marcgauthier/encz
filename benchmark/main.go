package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/marcgauthier/encz"
	_ "github.com/duckdb/duckdb-go/v2"
)

const (
	defaultPassword                     = "Password123"
	defaultCompression                  = "zstd"
	defaultRowCount                     = 1000
	defaultIndexedSelectIterations      = 5000
	defaultPlainSelectIterations        = 1000
	defaultWriteBenchmarkRowCount       = 2000
	defaultJoinIndexedIterations        = 5000
	defaultJoinPlainIterations          = 500
	defaultConcurrentInsertGoroutines   = 25
	defaultConcurrentInsertPerGoroutine = 100
)

type userRecord struct {
	Username string
	Email    string
	City     string
	Age      int
	Profile  string
	Payload  []byte
}

type orderRecord struct {
	UserID      int
	ProductName string
	Amount      float64
	OrderDate   string
}

type benchResult struct {
	InsertBatch      time.Duration
	InsertSingle     time.Duration
	InsertConcurrent time.Duration
	IndexedSelect    time.Duration
	PlainSelect      time.Duration
	AggregationQuery time.Duration
	JoinIndexed      time.Duration
	JoinPlain        time.Duration
	DatabaseSize     int64
}

type validationResult struct {
	userCount            int
	benchmarkWriteCount  int
	singleWriteCount     int
	concurrentWriteCount int
	orderCount           int
	payloadVerified      bool
	sampleUsername       string
}

type config struct {
	dbPath                  string
	duckdbPath              string
	password                string
	compression             string
	rowCount                int
	writeBenchmarkRows      int
	singleInsertRows        int
	indexedSelectIterations int
	plainSelectIterations   int
	aggregationIterations   int
	joinIndexedIterations   int
	joinPlainIterations     int
	concurrentGoroutines    int
	concurrentPerGoroutine  int
}

func main() {
	var cfg config
	flag.StringVar(&cfg.dbPath, "db", filepath.Join(".", "encz-benchmark.db"), "path to the encz database file")
	flag.StringVar(&cfg.duckdbPath, "duckdb", filepath.Join(".", "duckdb-benchmark.db"), "path to the DuckDB database file")
	flag.StringVar(&cfg.password, "key", defaultPassword, "encz encryption key")
	flag.StringVar(&cfg.compression, "compression", defaultCompression, "encz compression mode: none, zstd, or deflate")
	flag.IntVar(&cfg.rowCount, "rows", defaultRowCount, "number of validation rows to persist before reopen")
	flag.IntVar(&cfg.writeBenchmarkRows, "write-rows", defaultWriteBenchmarkRowCount, "number of rows to insert during the write benchmark")
	flag.IntVar(&cfg.singleInsertRows, "single-rows", 100, "number of rows to insert individually (unbatched)")
	flag.IntVar(&cfg.indexedSelectIterations, "indexed-iterations", defaultIndexedSelectIterations, "number of indexed select benchmark iterations")
	flag.IntVar(&cfg.plainSelectIterations, "plain-iterations", defaultPlainSelectIterations, "number of non-indexed select benchmark iterations")
	flag.IntVar(&cfg.aggregationIterations, "agg-iterations", 100, "number of aggregation query iterations")
	flag.IntVar(&cfg.joinIndexedIterations, "join-indexed-iterations", defaultJoinIndexedIterations, "number of indexed join query iterations")
	flag.IntVar(&cfg.joinPlainIterations, "join-plain-iterations", defaultJoinPlainIterations, "number of plain join query iterations")
	flag.IntVar(&cfg.concurrentGoroutines, "concurrent-goroutines", defaultConcurrentInsertGoroutines, "number of concurrent goroutines for write benchmark")
	flag.IntVar(&cfg.concurrentPerGoroutine, "concurrent-per-goroutine", defaultConcurrentInsertPerGoroutine, "number of inserts per concurrent goroutine")
	flag.Parse()

	if err := cfg.validate(); err != nil {
		log.Fatal(err)
	}

	// 1. Generate seed, benchmark batch, single, and concurrent users
	seedUsers, err := generateUsers(cfg.rowCount, 0)
	if err != nil {
		log.Fatal(err)
	}
	benchmarkUsers, err := generateUsers(cfg.writeBenchmarkRows, cfg.rowCount)
	if err != nil {
		log.Fatal(err)
	}
	singleUsers, err := generateUsers(cfg.singleInsertRows, cfg.rowCount+cfg.writeBenchmarkRows)
	if err != nil {
		log.Fatal(err)
	}
	concurrentCount := cfg.concurrentGoroutines * cfg.concurrentPerGoroutine
	concurrentUsers, err := generateUsers(concurrentCount, cfg.rowCount+cfg.writeBenchmarkRows+cfg.singleInsertRows)
	if err != nil {
		log.Fatal(err)
	}
	orders := generateOrders(seedUsers)

	// 2. ENCZ Benchmark
	log.Println("Running encz (SQLite + RocksDB) benchmark...")
	if err := cleanupDatabaseArtifacts(cfg.dbPath); err != nil {
		log.Fatal(err)
	}
	// Also clean up rocksdb directory
	_ = os.RemoveAll(cfg.dbPath + ".rocksdb")

	busyTimeout := 5000
	enczDb, err := encz.OpenWithOptions(cfg.dbPath, encz.Options{
		Key:               cfg.password,
		Compression:       cfg.compression,
		JournalMode:       "WAL",
		BusyTimeoutMillis: &busyTimeout,
	})
	if err != nil {
		log.Fatal(err)
	}
	enczDb.SetMaxOpenConns(1) // Serialize connections in Go's pool

	if err := createSchema(enczDb); err != nil {
		_ = enczDb.Close()
		log.Fatal(err)
	}
	if err := insertUsers(context.Background(), enczDb, "users", seedUsers, 0); err != nil {
		_ = enczDb.Close()
		log.Fatal(err)
	}
	if err := insertOrders(context.Background(), enczDb, orders); err != nil {
		_ = enczDb.Close()
		log.Fatal(err)
	}

	enczBench, err := runBenchmarks(context.Background(), enczDb, seedUsers, benchmarkUsers, singleUsers, concurrentUsers, cfg)
	if err != nil {
		_ = enczDb.Close()
		log.Fatal(err)
	}
	if _, err := enczDb.ExecContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		_ = enczDb.Close()
		log.Fatal(err)
	}
	if err := enczDb.Close(); err != nil {
		log.Fatal(err)
	}

	enczVal, err := validateReopen(cfg, seedUsers, benchmarkUsers, singleUsers, concurrentUsers, orders)
	if err != nil {
		log.Fatal(err)
	}

	// Measure ENCZ size on disk
	enczSize, err := getDatabaseSize(cfg.dbPath, true)
	if err != nil {
		log.Fatal(err)
	}
	enczBench.DatabaseSize = enczSize

	// 3. DuckDB Benchmark
	log.Println("Running DuckDB benchmark...")
	if err := cleanupDatabaseArtifacts(cfg.duckdbPath); err != nil {
		log.Fatal(err)
	}

	duckDb, err := sql.Open("duckdb", "")
	if err != nil {
		log.Fatal(err)
	}
	duckDb.SetMaxOpenConns(1) // Serialize connections in Go's pool

	attachQuery := fmt.Sprintf("ATTACH '%s' AS duckdb_bench (ENCRYPTION_KEY '%s', ENCRYPTION_CIPHER 'GCM')", cfg.duckdbPath, cfg.password)
	if _, err := duckDb.ExecContext(context.Background(), attachQuery); err != nil {
		_ = duckDb.Close()
		log.Fatal(err)
	}

	if _, err := duckDb.ExecContext(context.Background(), "USE duckdb_bench"); err != nil {
		_ = duckDb.Close()
		log.Fatal(err)
	}
	duckCompression := "zstd"
	if cfg.compression == "none" {
		duckCompression = "uncompressed"
	}
	if _, err := duckDb.ExecContext(context.Background(), fmt.Sprintf("SET force_compression = '%s'", duckCompression)); err != nil {
		_ = duckDb.Close()
		log.Fatal(err)
	}

	if err := createSchema(duckDb); err != nil {
		_ = duckDb.Close()
		log.Fatal(err)
	}
	if err := insertUsers(context.Background(), duckDb, "users", seedUsers, 0); err != nil {
		_ = duckDb.Close()
		log.Fatal(err)
	}
	if err := insertOrders(context.Background(), duckDb, orders); err != nil {
		_ = duckDb.Close()
		log.Fatal(err)
	}

	duckBench, err := runBenchmarks(context.Background(), duckDb, seedUsers, benchmarkUsers, singleUsers, concurrentUsers, cfg)
	if err != nil {
		_ = duckDb.Close()
		log.Fatal(err)
	}
	if err := duckDb.Close(); err != nil {
		log.Fatal(err)
	}

	// Measure DuckDB size on disk
	duckSize, err := getDatabaseSize(cfg.duckdbPath, false)
	if err != nil {
		log.Fatal(err)
	}
	duckBench.DatabaseSize = duckSize

	// 4. Output Comparison Results
	fmt.Println()
	fmt.Println("================================================================================")
	fmt.Println("                            BENCHMARK COMPARISON REPORT                         ")
	fmt.Println("================================================================================")
	fmt.Printf("Seed Rows Persisted:  %d\n", cfg.rowCount)
	fmt.Printf("Encz Compression:     %s\n", cfg.compression)
	fmt.Printf("Reopen Validation:    Encz Persisted Users=%d, Batch=%d, Single=%d, Concurrent=%d, Orders=%d, Payload Verified=%t, Sample=%s\n",
		enczVal.userCount, enczVal.benchmarkWriteCount, enczVal.singleWriteCount, enczVal.concurrentWriteCount, enczVal.orderCount, enczVal.payloadVerified, enczVal.sampleUsername)
	fmt.Println("--------------------------------------------------------------------------------")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.Debug)
	fmt.Fprintln(w, " Benchmark Step\t encz (SQLite+RocksDB)\t DuckDB")
	fmt.Fprintln(w, " ----\t ----\t ----")
	fmt.Fprintf(w, " Insert Batch (%d rows)\t %v\t %v\n", cfg.writeBenchmarkRows, enczBench.InsertBatch, duckBench.InsertBatch)
	fmt.Fprintf(w, " Insert Single (%d rows)\t %v\t %v\n", cfg.singleInsertRows, enczBench.InsertSingle, duckBench.InsertSingle)
	fmt.Fprintf(w, " Insert Concurrent (%d goroutines x %d)\t %v\t %v\n", cfg.concurrentGoroutines, cfg.concurrentPerGoroutine, enczBench.InsertConcurrent, duckBench.InsertConcurrent)
	fmt.Fprintf(w, " Indexed Select (%d lookups)\t %v\t %v\n", cfg.indexedSelectIterations, enczBench.IndexedSelect, duckBench.IndexedSelect)
	fmt.Fprintf(w, " Plain Select (%d scans)\t %v\t %v\n", cfg.plainSelectIterations, enczBench.PlainSelect, duckBench.PlainSelect)
	fmt.Fprintf(w, " Aggregation (%d queries)\t %v\t %v\n", cfg.aggregationIterations, enczBench.AggregationQuery, duckBench.AggregationQuery)
	fmt.Fprintf(w, " Join Indexed (%d lookups)\t %v\t %v\n", cfg.joinIndexedIterations, enczBench.JoinIndexed, duckBench.JoinIndexed)
	fmt.Fprintf(w, " Join Plain (%d scans)\t %v\t %v\n", cfg.joinPlainIterations, enczBench.JoinPlain, duckBench.JoinPlain)
	fmt.Fprintf(w, " Database Size on Disk\t %s\t %s\n", formatBytes(enczBench.DatabaseSize), formatBytes(duckBench.DatabaseSize))
	w.Flush()
	fmt.Println("================================================================================")
}

func (c config) validate() error {
	if c.dbPath == "" {
		return errors.New("db path is required")
	}
	if c.duckdbPath == "" {
		return errors.New("duckdb path is required")
	}
	if c.password == "" {
		return errors.New("key is required")
	}
	if c.rowCount <= 0 {
		return errors.New("rows must be > 0")
	}
	if c.writeBenchmarkRows <= 0 {
		return errors.New("write-rows must be > 0")
	}
	if c.singleInsertRows <= 0 {
		return errors.New("single-rows must be > 0")
	}
	if c.indexedSelectIterations <= 0 {
		return errors.New("indexed-iterations must be > 0")
	}
	if c.plainSelectIterations <= 0 {
		return errors.New("plain-iterations must be > 0")
	}
	if c.aggregationIterations <= 0 {
		return errors.New("agg-iterations must be > 0")
	}
	if c.joinIndexedIterations <= 0 {
		return errors.New("join-indexed-iterations must be > 0")
	}
	if c.joinPlainIterations <= 0 {
		return errors.New("join-plain-iterations must be > 0")
	}
	if c.concurrentGoroutines <= 0 {
		return errors.New("concurrent-goroutines must be > 0")
	}
	if c.concurrentPerGoroutine <= 0 {
		return errors.New("concurrent-per-goroutine must be > 0")
	}
	return nil
}

func cleanupDatabaseArtifacts(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm", "-wal.cvmeta", ".wal", ".tmp"} {
		_ = os.Remove(path + suffix)
	}
	return nil
}

func createSchema(db *sql.DB) error {
	statements := []string{
		`CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			email TEXT NOT NULL,
			city TEXT NOT NULL,
			age INTEGER NOT NULL,
			profile_json TEXT NOT NULL,
			payload BLOB NOT NULL
		)`,
		`CREATE TABLE benchmark_writes (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			email TEXT NOT NULL,
			city TEXT NOT NULL,
			age INTEGER NOT NULL,
			profile_json TEXT NOT NULL,
			payload BLOB NOT NULL
		)`,
		`CREATE TABLE single_writes (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			email TEXT NOT NULL,
			city TEXT NOT NULL,
			age INTEGER NOT NULL,
			profile_json TEXT NOT NULL,
			payload BLOB NOT NULL
		)`,
		`CREATE TABLE concurrent_writes (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			email TEXT NOT NULL,
			city TEXT NOT NULL,
			age INTEGER NOT NULL,
			profile_json TEXT NOT NULL,
			payload BLOB NOT NULL
		)`,
		`CREATE TABLE user_orders (
			id INTEGER PRIMARY KEY,
			user_id INTEGER NOT NULL,
			product_name TEXT NOT NULL,
			amount REAL NOT NULL,
			order_date TEXT NOT NULL
		)`,
		`CREATE INDEX idx_users_email ON users(email)`,
		`CREATE INDEX idx_orders_user_id ON user_orders(user_id)`,
	}
	for _, stmt := range statements {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			return fmt.Errorf("exec schema: %w", err)
		}
	}
	return nil
}

func insertUsers(ctx context.Context, db *sql.DB, table string, users []userRecord, startID int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, fmt.Sprintf("INSERT INTO %s(id, username, email, city, age, profile_json, payload) VALUES(?, ?, ?, ?, ?, ?, ?)", table))
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for i, user := range users {
		id := startID + i + 1
		if _, err := stmt.ExecContext(ctx, id, user.Username, user.Email, user.City, user.Age, user.Profile, user.Payload); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func runBenchmarks(ctx context.Context, db *sql.DB, seedUsers, writeUsers, singleUsers, concurrentUsers []userRecord, cfg config) (benchResult, error) {
	var out benchResult

	// 1. Batch inserts
	start := time.Now()
	if err := insertUsers(ctx, db, "benchmark_writes", writeUsers, len(seedUsers)); err != nil {
		return out, err
	}
	out.InsertBatch = time.Since(start)

	// 2. Single inserts (auto-commit)
	start = time.Now()
	if err := insertUsersSingle(ctx, db, "single_writes", singleUsers, len(seedUsers)+len(writeUsers)); err != nil {
		return out, err
	}
	out.InsertSingle = time.Since(start)

	// 3. Concurrent inserts
	start = time.Now()
	if err := benchmarkConcurrentInserts(ctx, db, concurrentUsers, cfg.concurrentGoroutines, cfg.concurrentPerGoroutine); err != nil {
		return out, err
	}
	out.InsertConcurrent = time.Since(start)

	// 4. Indexed select (point lookups)
	indexedTarget := seedUsers[len(seedUsers)/2].Email
	start = time.Now()
	if err := benchmarkIndexedSelect(ctx, db, indexedTarget, cfg.indexedSelectIterations); err != nil {
		return out, err
	}
	out.IndexedSelect = time.Since(start)

	// 5. Plain select (unindexed scans)
	plainTarget := seedUsers[0].City
	start = time.Now()
	if err := benchmarkPlainSelect(ctx, db, plainTarget, cfg.plainSelectIterations); err != nil {
		return out, err
	}
	out.PlainSelect = time.Since(start)

	// 6. Aggregation
	start = time.Now()
	if err := benchmarkAggregation(ctx, db, cfg.aggregationIterations); err != nil {
		return out, err
	}
	out.AggregationQuery = time.Since(start)

	// 7. Join Indexed (point lookup join)
	indexedJoinTarget := seedUsers[len(seedUsers)/2].Email
	start = time.Now()
	if err := benchmarkJoinIndexed(ctx, db, indexedJoinTarget, cfg.joinIndexedIterations); err != nil {
		return out, err
	}
	out.JoinIndexed = time.Since(start)

	// 8. Join Plain (scan join)
	plainJoinTarget := seedUsers[0].City
	start = time.Now()
	if err := benchmarkJoinPlain(ctx, db, plainJoinTarget, cfg.joinPlainIterations); err != nil {
		return out, err
	}
	out.JoinPlain = time.Since(start)

	return out, nil
}

func benchmarkIndexedSelect(ctx context.Context, db *sql.DB, email string, iterations int) error {
	stmt, err := db.PrepareContext(ctx, "SELECT id, username FROM users WHERE email = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := 0; i < iterations; i++ {
		rows, err := stmt.QueryContext(ctx, email)
		if err != nil {
			return err
		}
		if err := exhaustRows(rows); err != nil {
			return err
		}
	}
	return nil
}

func benchmarkPlainSelect(ctx context.Context, db *sql.DB, city string, iterations int) error {
	for i := 0; i < iterations; i++ {
		rows, err := db.QueryContext(ctx, "SELECT id, username FROM users WHERE city = ?", city)
		if err != nil {
			return err
		}
		if err := exhaustRows(rows); err != nil {
			return err
		}
	}
	return nil
}

func insertUsersSingle(ctx context.Context, db *sql.DB, table string, users []userRecord, startID int) error {
	stmt, err := db.PrepareContext(ctx, fmt.Sprintf("INSERT INTO %s(id, username, email, city, age, profile_json, payload) VALUES(?, ?, ?, ?, ?, ?, ?)", table))
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i, user := range users {
		id := startID + i + 1
		if _, err := stmt.ExecContext(ctx, id, user.Username, user.Email, user.City, user.Age, user.Profile, user.Payload); err != nil {
			return err
		}
	}
	return nil
}

func benchmarkConcurrentInserts(ctx context.Context, db *sql.DB, users []userRecord, numGoroutines, insertsPerGoroutine int) error {
	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gId int) {
			defer wg.Done()
			
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				errChan <- err
				return
			}
			
			stmt, err := tx.PrepareContext(ctx, "INSERT INTO concurrent_writes(id, username, email, city, age, profile_json, payload) VALUES(?, ?, ?, ?, ?, ?, ?)")
			if err != nil {
				_ = tx.Rollback()
				errChan <- err
				return
			}
			defer stmt.Close()

			startIdx := gId * insertsPerGoroutine
			for i := 0; i < insertsPerGoroutine; i++ {
				idx := startIdx + i
				user := users[idx]
				id := 1000000 + idx + 1
				if _, err := stmt.ExecContext(ctx, id, user.Username, user.Email, user.City, user.Age, user.Profile, user.Payload); err != nil {
					_ = tx.Rollback()
					errChan <- err
					return
				}
			}
			
			if err := tx.Commit(); err != nil {
				errChan <- err
			}
		}(g)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}
	return nil
}

func benchmarkAggregation(ctx context.Context, db *sql.DB, iterations int) error {
	for i := 0; i < iterations; i++ {
		rows, err := db.QueryContext(ctx, "SELECT city, AVG(age), COUNT(*) FROM users GROUP BY city")
		if err != nil {
			return err
		}
		for rows.Next() {
			var city string
			var avgAge float64
			var count int
			if err := rows.Scan(&city, &avgAge, &count); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	return nil
}

func benchmarkJoinIndexed(ctx context.Context, db *sql.DB, email string, iterations int) error {
	stmt, err := db.PrepareContext(ctx, `
		SELECT u.username, o.product_name, o.amount, o.order_date
		FROM users u
		JOIN user_orders o ON u.id = o.user_id
		WHERE u.email = ?
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := 0; i < iterations; i++ {
		rows, err := stmt.QueryContext(ctx, email)
		if err != nil {
			return err
		}
		for rows.Next() {
			var username, product, date string
			var amount float64
			if err := rows.Scan(&username, &product, &amount, &date); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	return nil
}

func benchmarkJoinPlain(ctx context.Context, db *sql.DB, city string, iterations int) error {
	for i := 0; i < iterations; i++ {
		rows, err := db.QueryContext(ctx, `
			SELECT u.username, o.product_name, o.amount, o.order_date
			FROM users u
			JOIN user_orders o ON u.id = o.user_id
			WHERE u.city = ?
		`, city)
		if err != nil {
			return err
		}
		for rows.Next() {
			var username, product, date string
			var amount float64
			if err := rows.Scan(&username, &product, &amount, &date); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	return nil
}

func insertOrders(ctx context.Context, db *sql.DB, orders []orderRecord) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO user_orders(id, user_id, product_name, amount, order_date) VALUES(?, ?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for i, order := range orders {
		orderID := i + 1
		if _, err := stmt.ExecContext(ctx, orderID, order.UserID, order.ProductName, order.Amount, order.OrderDate); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func generateOrders(users []userRecord) []orderRecord {
	orders := make([]orderRecord, 0, len(users)*2)
	products := []string{"Laptop", "Smartphone", "Headphones", "Smartwatch", "Keyboard", "Mouse", "Monitor", "Tablet"}
	for i := range users {
		userID := i + 1
		for j := 0; j < 2; j++ {
			prod := products[(userID+j)%len(products)]
			amount := float64(10 + (userID+j)%100)
			date := fmt.Sprintf("2026-06-%02d", 1+(userID+j)%28)
			orders = append(orders, orderRecord{
				UserID:      userID,
				ProductName: prod,
				Amount:      amount,
				OrderDate:   date,
			})
		}
	}
	return orders
}

func exhaustRows(rows *sql.Rows) error {
	defer rows.Close()
	var id int
	var username string
	found := false
	for rows.Next() {
		found = true
		if err := rows.Scan(&id, &username); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !found {
		return errors.New("query returned no rows")
	}
	return nil
}

func validateReopen(cfg config, seedUsers, writeUsers, singleUsers, concurrentUsers []userRecord, orders []orderRecord) (validationResult, error) {
	db, err := encz.OpenWithOptions(cfg.dbPath, encz.Options{
		Key:         cfg.password,
		Compression: cfg.compression,
		JournalMode: "WAL",
	})
	if err != nil {
		return validationResult{}, err
	}
	defer db.Close()

	var out validationResult
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM users").Scan(&out.userCount); err != nil {
		return out, err
	}
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM benchmark_writes").Scan(&out.benchmarkWriteCount); err != nil {
		return out, err
	}
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM single_writes").Scan(&out.singleWriteCount); err != nil {
		return out, err
	}
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM concurrent_writes").Scan(&out.concurrentWriteCount); err != nil {
		return out, err
	}
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM user_orders").Scan(&out.orderCount); err != nil {
		return out, err
	}
	if err := db.QueryRowContext(context.Background(), "SELECT username FROM users WHERE email = ?", seedUsers[0].Email).Scan(&out.sampleUsername); err != nil {
		return out, err
	}
	if out.sampleUsername != seedUsers[0].Username {
		return out, fmt.Errorf("sample mismatch: got %q want %q", out.sampleUsername, seedUsers[0].Username)
	}
	if err := verifyUsers(context.Background(), db, "users", seedUsers); err != nil {
		return out, err
	}
	if err := verifyUsers(context.Background(), db, "benchmark_writes", writeUsers); err != nil {
		return out, err
	}
	if err := verifyUsers(context.Background(), db, "single_writes", singleUsers); err != nil {
		return out, err
	}
	if err := verifyUsers(context.Background(), db, "concurrent_writes", concurrentUsers); err != nil {
		return out, err
	}
	out.payloadVerified = true
	return out, nil
}

func verifyUsers(ctx context.Context, db *sql.DB, table string, expected []userRecord) error {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT username, email, city, age, profile_json, payload FROM %s ORDER BY id", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	index := 0
	for rows.Next() {
		if index >= len(expected) {
			return fmt.Errorf("table %s returned more rows than expected", table)
		}
		var got userRecord
		if err := rows.Scan(&got.Username, &got.Email, &got.City, &got.Age, &got.Profile, &got.Payload); err != nil {
			return err
		}
		if err := compareUser(expected[index], got, table, index+1); err != nil {
			return err
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if index != len(expected) {
		return fmt.Errorf("table %s returned %d rows, want %d", table, index, len(expected))
	}
	return nil
}

func compareUser(expected, got userRecord, table string, row int) error {
	if expected.Username != got.Username ||
		expected.Email != got.Email ||
		expected.City != got.City ||
		expected.Age != got.Age ||
		expected.Profile != got.Profile ||
		!equalBytes(expected.Payload, got.Payload) {
		return fmt.Errorf("table %s row %d mismatch", table, row)
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func generateUsers(count int, startID int) ([]userRecord, error) {
	users := make([]userRecord, 0, count)
	for i := 0; i < count; i++ {
		user, err := randomUser(startID + i + 1)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func randomUser(i int) (userRecord, error) {
	adjective, err := pick([]string{"amber", "brisk", "crimson", "daring", "ember", "frozen", "golden", "hidden", "indigo", "jade", "lunar", "mellow"})
	if err != nil {
		return userRecord{}, err
	}
	noun, err := pick([]string{"otter", "falcon", "maple", "harbor", "quartz", "willow", "rocket", "summit", "cinder", "spruce", "meadow", "signal"})
	if err != nil {
		return userRecord{}, err
	}
	suffix, err := randInt(1000, 9999)
	if err != nil {
		return userRecord{}, err
	}
	username := fmt.Sprintf("%s_%s_%d", adjective, noun, suffix)
	email := fmt.Sprintf("%s@example.com", username)
	city, err := pick([]string{"Toronto", "Montreal", "Vancouver", "Calgary", "Ottawa", "Halifax", "Quebec City", "Victoria"})
	if err != nil {
		return userRecord{}, err
	}
	age, err := randInt(18, 78)
	if err != nil {
		return userRecord{}, err
	}
	profilePayload, err := randomBytes(256 + (i % 5 * 64))
	if err != nil {
		return userRecord{}, err
	}
	profile := fmt.Sprintf(`{"id":%d,"role":"user","city":"%s","username":"%s","bio":"benchmark profile","checksum":"%s"}`,
		i, city, username, hex.EncodeToString(profilePayload[:16]))
	blob, err := randomBytes(1024 + (i % 7 * 128))
	if err != nil {
		return userRecord{}, err
	}
	return userRecord{
		Username: username,
		Email:    email,
		City:     city,
		Age:      age,
		Profile:  profile,
		Payload:  blob,
	}, nil
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func pick(values []string) (string, error) {
	index, err := randInt(0, len(values)-1)
	if err != nil {
		return "", err
	}
	return values[index], nil
}

func randInt(min, max int) (int, error) {
	if min == max {
		return min, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func getDatabaseSize(dbPath string, isEncz bool) (int64, error) {
	var totalSize int64

	// File size of main database file
	fi, err := os.Stat(dbPath)
	if err == nil {
		totalSize += fi.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}

	if isEncz {
		// Also add RocksDB directory size
		rocksPath := dbPath + ".rocksdb"
		rocksSize, err := getDirSize(rocksPath)
		if err == nil {
			totalSize += rocksSize
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
	}

	return totalSize, nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

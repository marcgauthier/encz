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
	"time"

	"github.com/marcgauthier/encz"
)

const (
	defaultPassword                = "Password123"
	defaultCompression             = "none"
	defaultRowCount                = 5000
	defaultIndexedSelectIterations = 20000
	defaultPlainSelectIterations   = 1000
	defaultWriteBenchmarkRowCount  = 5000
)

type userRecord struct {
	Username string
	Email    string
	City     string
	Age      int
	Profile  string
	Payload  []byte
}

type benchResult struct {
	InsertBatch   time.Duration
	IndexedSelect time.Duration
	PlainSelect   time.Duration
}

type validationResult struct {
	userCount           int
	benchmarkWriteCount int
	payloadVerified     bool
	sampleUsername      string
}

type config struct {
	dbPath                  string
	password                string
	compression             string
	rowCount                int
	writeBenchmarkRows      int
	indexedSelectIterations int
	plainSelectIterations   int
}

func main() {
	var cfg config
	flag.StringVar(&cfg.dbPath, "db", filepath.Join(".", "encz-benchmark.db"), "path to the encz database file")
	flag.StringVar(&cfg.password, "key", defaultPassword, "encz encryption key")
	flag.StringVar(&cfg.compression, "compression", defaultCompression, "encz compression mode: none, zstd, or deflate")
	flag.IntVar(&cfg.rowCount, "rows", defaultRowCount, "number of validation rows to persist before reopen")
	flag.IntVar(&cfg.writeBenchmarkRows, "write-rows", defaultWriteBenchmarkRowCount, "number of rows to insert during the write benchmark")
	flag.IntVar(&cfg.indexedSelectIterations, "indexed-iterations", defaultIndexedSelectIterations, "number of indexed select benchmark iterations")
	flag.IntVar(&cfg.plainSelectIterations, "plain-iterations", defaultPlainSelectIterations, "number of non-indexed select benchmark iterations")
	flag.Parse()

	if err := cfg.validate(); err != nil {
		log.Fatal(err)
	}

	if err := cleanupDatabaseArtifacts(cfg.dbPath); err != nil {
		log.Fatal(err)
	}

	seedUsers, err := generateUsers(cfg.rowCount, 0)
	if err != nil {
		log.Fatal(err)
	}
	benchmarkUsers, err := generateUsers(cfg.writeBenchmarkRows, cfg.rowCount)
	if err != nil {
		log.Fatal(err)
	}

	db, err := encz.OpenEncz(cfg.dbPath, cfg.password, cfg.compression)
	if err != nil {
		log.Fatal(err)
	}

	if err := configureDatabase(db, cfg.compression); err != nil {
		_ = db.Close()
		log.Fatal(err)
	}
	if err := createSchema(db); err != nil {
		_ = db.Close()
		log.Fatal(err)
	}
	if err := insertUsers(context.Background(), db, "users", seedUsers); err != nil {
		_ = db.Close()
		log.Fatal(err)
	}

	bench, err := runBenchmarks(context.Background(), db, seedUsers, benchmarkUsers, cfg)
	if err != nil {
		_ = db.Close()
		log.Fatal(err)
	}
	if err := db.Close(); err != nil {
		log.Fatal(err)
	}

	validation, err := validateReopen(cfg, seedUsers, benchmarkUsers)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("created %s with %d persisted rows using encz compression=%s\n", cfg.dbPath, len(seedUsers), cfg.compression)
	fmt.Printf("reopen validation: users=%d benchmark_writes=%d payload_verified=%t sample=%s\n",
		validation.userCount,
		validation.benchmarkWriteCount,
		validation.payloadVerified,
		validation.sampleUsername,
	)
	fmt.Println("benchmark results")
	fmt.Printf("insert batch (%d rows): %s\n", cfg.writeBenchmarkRows, bench.InsertBatch)
	fmt.Printf("indexed select (%d lookups by indexed email): %s\n", cfg.indexedSelectIterations, bench.IndexedSelect)
	fmt.Printf("plain select (%d scans by unindexed city): %s\n", cfg.plainSelectIterations, bench.PlainSelect)
}

func (c config) validate() error {
	if c.dbPath == "" {
		return errors.New("db path is required")
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
	if c.indexedSelectIterations <= 0 {
		return errors.New("indexed-iterations must be > 0")
	}
	if c.plainSelectIterations <= 0 {
		return errors.New("plain-iterations must be > 0")
	}
	return nil
}

func cleanupDatabaseArtifacts(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm", "-wal.cvmeta", ".wal"} {
		_ = os.Remove(path + suffix)
	}
	return nil
}

func configureDatabase(db *sql.DB, compression string) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		fmt.Sprintf("PRAGMA crypto_compression=%s", sqlQuote(compression)),
	}
	for _, pragma := range pragmas {
		if _, err := db.ExecContext(context.Background(), pragma); err != nil {
			return fmt.Errorf("exec %q: %w", pragma, err)
		}
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
		`CREATE INDEX idx_users_email ON users(email)`,
	}
	for _, stmt := range statements {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			return fmt.Errorf("exec schema: %w", err)
		}
	}
	return nil
}

func insertUsers(ctx context.Context, db *sql.DB, table string, users []userRecord) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, fmt.Sprintf("INSERT INTO %s(username, email, city, age, profile_json, payload) VALUES(?, ?, ?, ?, ?, ?)", table))
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, user := range users {
		if _, err := stmt.ExecContext(ctx, user.Username, user.Email, user.City, user.Age, user.Profile, user.Payload); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func runBenchmarks(ctx context.Context, db *sql.DB, seedUsers, writeUsers []userRecord, cfg config) (benchResult, error) {
	var out benchResult

	start := time.Now()
	if err := insertUsers(ctx, db, "benchmark_writes", writeUsers); err != nil {
		return out, err
	}
	out.InsertBatch = time.Since(start)

	indexedTarget := seedUsers[len(seedUsers)/2].Email
	start = time.Now()
	if err := benchmarkIndexedSelect(ctx, db, indexedTarget, cfg.indexedSelectIterations); err != nil {
		return out, err
	}
	out.IndexedSelect = time.Since(start)

	plainTarget := seedUsers[0].City
	start = time.Now()
	if err := benchmarkPlainSelect(ctx, db, plainTarget, cfg.plainSelectIterations); err != nil {
		return out, err
	}
	out.PlainSelect = time.Since(start)

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

func validateReopen(cfg config, seedUsers, writeUsers []userRecord) (validationResult, error) {
	db, err := encz.OpenEncz(cfg.dbPath, cfg.password, cfg.compression)
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

func sqlQuote(value string) string {
	return "'" + replaceAll(value, "'", "''") + "'"
}

func replaceAll(s, old, new string) string {
	for {
		index := indexOf(s, old)
		if index < 0 {
			return s
		}
		s = s[:index] + new + s[index+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
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

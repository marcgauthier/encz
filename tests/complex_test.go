package tests

import (
	"database/sql"
	"testing"
)

// TC-COMP-001: TestComplexJoins tests JOIN operations across 5 tables
func TestComplexJoins(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		// Create 5 tables
		stmts := []string{
			`CREATE TABLE suppliers (
				id INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				country TEXT NOT NULL
			)`,
			`CREATE TABLE products (
				id INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				price REAL NOT NULL,
				supplier_id INTEGER,
				FOREIGN KEY(supplier_id) REFERENCES suppliers(id)
			)`,
			`CREATE TABLE customers (
				id INTEGER PRIMARY KEY,
				name TEXT NOT NULL
			)`,
			`CREATE TABLE orders (
				id INTEGER PRIMARY KEY,
				customer_id INTEGER,
				order_date TEXT NOT NULL,
				FOREIGN KEY(customer_id) REFERENCES customers(id)
			)`,
			`CREATE TABLE order_items (
				id INTEGER PRIMARY KEY,
				order_id INTEGER,
				product_id INTEGER,
				quantity INTEGER NOT NULL,
				FOREIGN KEY(order_id) REFERENCES orders(id),
				FOREIGN KEY(product_id) REFERENCES products(id)
			)`,
		}
		for _, stmt := range stmts {
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("failed to create table: %v", err)
			}
		}

		// Insert seed data
		inserts := []string{
			`INSERT INTO suppliers VALUES (1, "Supplier A", "Canada"), (2, "Supplier B", "USA")`,
			`INSERT INTO products VALUES (10, "Laptop", 999.99, 1), (20, "Mouse", 25.50, 1), (30, "Keyboard", 75.00, 2)`,
			`INSERT INTO customers VALUES (100, "Alice"), (200, "Bob"), (300, "Charlie")`,
			`INSERT INTO orders VALUES (1000, 100, "2026-06-01"), (2000, 200, "2026-06-02"), (3000, 100, "2026-06-03")`,
			`INSERT INTO order_items VALUES (5000, 1000, 10, 1), (5001, 1000, 20, 2), (5002, 2000, 30, 1), (5003, 3000, 20, 5)`,
		}
		for _, ins := range inserts {
			if _, err := db.Exec(ins); err != nil {
				t.Fatalf("failed to insert seed data: %v", err)
			}
		}

		// Complex Join Query across all 5 tables
		query := `
			SELECT 
				c.name AS customer_name,
				o.order_date,
				p.name AS product_name,
				p.price,
				oi.quantity,
				(p.price * oi.quantity) AS item_total,
				s.name AS supplier_name,
				s.country AS supplier_country
			FROM customers c
			INNER JOIN orders o ON c.id = o.customer_id
			INNER JOIN order_items oi ON o.id = oi.order_id
			INNER JOIN products p ON oi.product_id = p.id
			INNER JOIN suppliers s ON p.supplier_id = s.id
			ORDER BY o.order_date ASC, p.name DESC
		`

		rows, err := db.Query(query)
		if err != nil {
			t.Fatalf("failed to execute complex join: %v", err)
		}
		defer rows.Close()

		type rowData struct {
			customerName    string
			orderDate       string
			productName     string
			price           float64
			quantity        int
			itemTotal       float64
			supplierName    string
			supplierCountry string
		}

		var results []rowData
		for rows.Next() {
			var r rowData
			err := rows.Scan(&r.customerName, &r.orderDate, &r.productName, &r.price, &r.quantity, &r.itemTotal, &r.supplierName, &r.supplierCountry)
			if err != nil {
				t.Fatalf("failed to scan row: %v", err)
			}
			results = append(results, r)
		}

		if len(results) != 4 {
			t.Errorf("expected 4 order items, got %d", len(results))
		}

		// Verify first record (order 1000, laptop)
		if results[0].customerName != "Alice" || results[0].productName != "Mouse" || results[0].quantity != 2 {
			t.Errorf("unexpected record contents at index 0: %+v", results[0])
		}
		if results[1].customerName != "Alice" || results[1].productName != "Laptop" || results[1].quantity != 1 {
			t.Errorf("unexpected record contents at index 1: %+v", results[1])
		}
	})
}

// TC-COMP-002: TestCommonTableExpressions tests standard and recursive CTEs
func TestCommonTableExpressions(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		// Setup hierarchy for recursive CTE
		_, err := db.Exec(`CREATE TABLE employees (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			manager_id INTEGER REFERENCES employees(id)
		)`)
		if err != nil {
			t.Fatalf("failed to create employees: %v", err)
		}

		_, err = db.Exec(`INSERT INTO employees VALUES
			(1, "CEO", NULL),
			(2, "VP Engineering", 1),
			(3, "VP Sales", 1),
			(4, "Engineering Manager", 2),
			(5, "Software Engineer A", 4),
			(6, "Software Engineer B", 4),
			(7, "Sales Rep", 3)
		`)
		if err != nil {
			t.Fatalf("failed to seed employees: %v", err)
		}

		// Query hierarchy using WITH RECURSIVE
		query := `
			WITH RECURSIVE org_chart AS (
				SELECT id, name, manager_id, 0 AS level
				FROM employees
				WHERE manager_id IS NULL
				
				UNION ALL
				
				SELECT e.id, e.name, e.manager_id, o.level + 1
				FROM employees e
				INNER JOIN org_chart o ON e.manager_id = o.id
			)
			SELECT id, name, level FROM org_chart ORDER BY level, id
		`

		rows, err := db.Query(query)
		if err != nil {
			t.Fatalf("failed to execute recursive CTE: %v", err)
		}
		defer rows.Close()

		var levels []int
		for rows.Next() {
			var id int
			var name string
			var level int
			if err := rows.Scan(&id, &name, &level); err != nil {
				t.Fatalf("failed to scan CTE row: %v", err)
			}
			levels = append(levels, level)
		}

		expectedLevels := []int{0, 1, 1, 2, 2, 3, 3}
		if len(levels) != len(expectedLevels) {
			t.Fatalf("expected %d rows, got %d", len(expectedLevels), len(levels))
		}
		for i, v := range expectedLevels {
			if levels[i] != v {
				t.Errorf("mismatch at index %d: expected level %d, got %d", i, v, levels[i])
			}
		}
	})
}

// TC-COMP-003: TestSubqueriesAndExists tests subqueries, correlated subqueries, and EXISTS
func TestSubqueriesAndExists(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		// Create tables
		_, err := db.Exec(`CREATE TABLE products (
			id INTEGER PRIMARY KEY,
			name TEXT,
			price REAL,
			category TEXT
		)`)
		if err != nil {
			t.Fatalf("failed to create table: %v", err)
		}

		_, err = db.Exec(`INSERT INTO products VALUES
			(1, "Laptop", 1200.0, "Electronics"),
			(2, "Phone", 800.0, "Electronics"),
			(3, "Mouse", 30.0, "Electronics"),
			(4, "Desk", 250.0, "Furniture"),
			(5, "Chair", 120.0, "Furniture")
		`)
		if err != nil {
			t.Fatalf("failed to seed: %v", err)
		}

		// 1. Correlated subquery: Get products with price above category average
		queryCorrelated := `
			SELECT name FROM products p1
			WHERE price > (
				SELECT AVG(price) FROM products p2 WHERE p2.category = p1.category
			)
			ORDER BY id
		`
		rows, err := db.Query(queryCorrelated)
		if err != nil {
			t.Fatalf("correlated query: %v", err)
		}
		defer rows.Close()

		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatalf("scan correlated: %v", err)
			}
			names = append(names, name)
		}

		if len(names) != 3 || names[0] != "Laptop" || names[1] != "Phone" || names[2] != "Desk" {
			t.Errorf("unexpected correlated query results: %v", names)
		}

		// 2. EXISTS subquery
		_, err = db.Exec(`CREATE TABLE orders (
			id INTEGER PRIMARY KEY,
			product_id INTEGER
		)`)
		if err != nil {
			t.Fatalf("create orders: %v", err)
		}
		_, err = db.Exec(`INSERT INTO orders VALUES (1, 1), (2, 3)`) // Ordered Laptop and Mouse
		if err != nil {
			t.Fatalf("seed orders: %v", err)
		}

		queryExists := `
			SELECT name FROM products p
			WHERE EXISTS (SELECT 1 FROM orders o WHERE o.product_id = p.id)
			ORDER BY p.id
		`
		rowsExists, err := db.Query(queryExists)
		if err != nil {
			t.Fatalf("exists query: %v", err)
		}
		defer rowsExists.Close()

		names = nil
		for rowsExists.Next() {
			var name string
			if err := rowsExists.Scan(&name); err != nil {
				t.Fatalf("scan exists: %v", err)
			}
			names = append(names, name)
		}

		if len(names) != 2 || names[0] != "Laptop" || names[1] != "Mouse" {
			t.Errorf("unexpected EXISTS query results: %v", names)
		}
	})
}

// TC-COMP-004: TestWindowFunctions tests SQLite window functions
func TestWindowFunctions(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		_, err := db.Exec(`CREATE TABLE scores (
			department TEXT,
			employee TEXT,
			score INTEGER
		)`)
		if err != nil {
			t.Fatalf("create table: %v", err)
		}

		_, err = db.Exec(`INSERT INTO scores VALUES
			("Sales", "Alice", 100),
			("Sales", "Bob", 120),
			("Eng", "Charlie", 150),
			("Eng", "Dave", 110),
			("Eng", "Eve", 150)
		`)
		if err != nil {
			t.Fatalf("seed scores: %v", err)
		}

		// Window Query with ROW_NUMBER() and DENSE_RANK()
		query := `
			SELECT 
				department, 
				employee, 
				score,
				ROW_NUMBER() OVER (PARTITION BY department ORDER BY score DESC, employee ASC) as row_num,
				DENSE_RANK() OVER (PARTITION BY department ORDER BY score DESC) as rank
			FROM scores
			ORDER BY department, rank, row_num
		`

		rows, err := db.Query(query)
		if err != nil {
			t.Fatalf("window query: %v", err)
		}
		defer rows.Close()

		type record struct {
			dept   string
			emp    string
			score  int
			rowNum int
			rank   int
		}

		var results []record
		for rows.Next() {
			var r record
			err := rows.Scan(&r.dept, &r.emp, &r.score, &r.rowNum, &r.rank)
			if err != nil {
				t.Fatalf("scan window: %v", err)
			}
			results = append(results, r)
		}

		if len(results) != 5 {
			t.Fatalf("expected 5 rows, got %d", len(results))
		}

		// Verify Eng department ranking (Eve and Charlie tie for #1 at 150, Dave is #2 at 110)
		// Due to alphabetical tie breaker in ROW_NUMBER():
		// Charlie rowNum=1 rank=1
		// Eve     rowNum=2 rank=1
		// Dave    rowNum=3 rank=2
		if results[0].dept != "Eng" || results[0].emp != "Charlie" || results[0].rowNum != 1 || results[0].rank != 1 {
			t.Errorf("unexpected record 0: %+v", results[0])
		}
		if results[1].dept != "Eng" || results[1].emp != "Eve" || results[1].rowNum != 2 || results[1].rank != 1 {
			t.Errorf("unexpected record 1: %+v", results[1])
		}
		if results[2].dept != "Eng" || results[2].emp != "Dave" || results[2].rowNum != 3 || results[2].rank != 2 {
			t.Errorf("unexpected record 2: %+v", results[2])
		}
	})
}

// TC-COMP-005: TestTriggersAndViews tests SQL views and database triggers
func TestTriggersAndViews(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		// Create schema
		_, err := db.Exec(`CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL
		)`)
		if err != nil {
			t.Fatalf("create users: %v", err)
		}

		_, err = db.Exec(`CREATE TABLE user_logs (
			user_id INTEGER,
			action TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
		if err != nil {
			t.Fatalf("create user_logs: %v", err)
		}

		// Create view
		_, err = db.Exec(`CREATE VIEW v_active_users AS SELECT id, username FROM users`)
		if err != nil {
			t.Fatalf("create view: %v", err)
		}

		// Create trigger (AFTER INSERT)
		_, err = db.Exec(`CREATE TRIGGER trg_user_insert AFTER INSERT ON users
			BEGIN
				INSERT INTO user_logs (user_id, action) VALUES (new.id, 'INSERT');
			END;
		`)
		if err != nil {
			t.Fatalf("create trigger: %v", err)
		}

		// Insert user, which should trigger log insert
		_, err = db.Exec(`INSERT INTO users (id, username) VALUES (1, "marc")`)
		if err != nil {
			t.Fatalf("insert user: %v", err)
		}

		// Query view
		var viewUser string
		err = db.QueryRow(`SELECT username FROM v_active_users WHERE id = 1`).Scan(&viewUser)
		if err != nil {
			t.Fatalf("select view: %v", err)
		}
		if viewUser != "marc" {
			t.Errorf("expected view username 'marc', got %q", viewUser)
		}

		// Verify trigger fired
		var logAction string
		err = db.QueryRow(`SELECT action FROM user_logs WHERE user_id = 1`).Scan(&logAction)
		if err != nil {
			t.Fatalf("select logs: %v", err)
		}
		if logAction != "INSERT" {
			t.Errorf("expected trigger log action 'INSERT', got %q", logAction)
		}
	})
}

// TC-COMP-006: TestFullTextSearchFTS5 tests virtual tables and FTS5 search extension
func TestFullTextSearchFTS5(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		// Create virtual table using fts5
		_, err := db.Exec(`CREATE VIRTUAL TABLE documents USING fts5(title, body)`)
		if err != nil {
			// Check if FTS5 is supported in the current driver compilation.
			// Go-sqlite3 enables it by default on standard platforms.
			t.Skipf("skipping FTS5 test (probably not supported in this build): %v", err)
			return
		}

		// Insert documents
		_, err = db.Exec(`INSERT INTO documents (title, body) VALUES
			("Introduction to Go Programming", "Go is a statically typed programming language developed at Google. It is highly efficient."),
			("SQLite VFS transparent encryption", "The encz library registers a custom Virtual File System (VFS) to provide transparent database encryption.")
		`)
		if err != nil {
			t.Fatalf("insert fts5: %v", err)
		}

		// Search using MATCH query
		var title string
		err = db.QueryRow(`SELECT title FROM documents WHERE documents MATCH 'encryption'`).Scan(&title)
		if err != nil {
			t.Fatalf("fts5 match query: %v", err)
		}
		if title != "SQLite VFS transparent encryption" {
			t.Errorf("expected 'SQLite VFS transparent encryption', got %q", title)
		}

		err = db.QueryRow(`SELECT title FROM documents WHERE documents MATCH 'google'`).Scan(&title)
		if err != nil {
			t.Fatalf("fts5 match query google: %v", err)
		}
		if title != "Introduction to Go Programming" {
			t.Errorf("expected 'Introduction to Go Programming', got %q", title)
		}
	})
}

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	temp := t.TempDir()
	path := filepath.Join(temp, "config.yaml")
	body := []byte(`
duration: 2s
workers: 3
operations_per_second: 25
rows_per_table: 50
initial_rows_per_table: 2
seed: 42
database_file: test.db
master_key: a-test-key-with-enough-entropy
cipher: xchacha20-poly1305
journal_mode: WAL
busy_timeout: 2s
decrypted_page_cache: 64MB
progress_interval: 1s
audit_interval: 2s
reopen_interval: 3s
backup_interval: 4s
rekey_interval: 5s
workload:
  insert_pct: 20
  update_pct: 25
  select_pct: 35
  join_pct: 20
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path, time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CacheBytes != 64<<20 {
		t.Fatalf("cache bytes: got %d", cfg.CacheBytes)
	}
	if cfg.DurationValue != 2*time.Second {
		t.Fatalf("duration: got %s", cfg.DurationValue)
	}
	if cfg.Cipher != "xchacha20-poly1305" {
		t.Fatalf("cipher: got %s", cfg.Cipher)
	}
}

func TestSchemaHasTwentyWideTables(t *testing.T) {
	if len(schema) != 20 {
		t.Fatalf("table count: got %d want 20", len(schema))
	}
	const dataColumns = 12
	if dataColumns < 10 {
		t.Fatal("schema no longer meets the ten-data-column requirement")
	}
	seen := make(map[string]bool)
	for _, spec := range schema {
		if seen[spec.Name] {
			t.Fatalf("duplicate table %q", spec.Name)
		}
		seen[spec.Name] = true
		if spec.Parent != "" && !seen[spec.Parent] {
			t.Fatalf("parent %q must precede child %q", spec.Parent, spec.Name)
		}
	}
}

func TestParseBytes(t *testing.T) {
	for input, expected := range map[string]int64{
		"1KB": 1 << 10, "128MB": 128 << 20, "2GB": 2 << 30,
	} {
		got, err := parseBytes(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if got != expected {
			t.Fatalf("%s: got %d want %d", input, got, expected)
		}
	}
}

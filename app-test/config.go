package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sqliteseal "github.com/marcgauthier/SQLiteSeal"
	"gopkg.in/yaml.v3"
)

type workloadConfig struct {
	InsertPct int `yaml:"insert_pct"`
	UpdatePct int `yaml:"update_pct"`
	SelectPct int `yaml:"select_pct"`
	JoinPct   int `yaml:"join_pct"`
}

type rawConfig struct {
	Duration            string         `yaml:"duration"`
	Workers             int            `yaml:"workers"`
	OperationsPerSecond int            `yaml:"operations_per_second"`
	RowsPerTable        int            `yaml:"rows_per_table"`
	InitialRowsPerTable int            `yaml:"initial_rows_per_table"`
	Seed                int64          `yaml:"seed"`
	DatabaseFile        string         `yaml:"database_file"`
	MasterKey           string         `yaml:"master_key"`
	Cipher              string         `yaml:"cipher"`
	JournalMode         string         `yaml:"journal_mode"`
	BusyTimeout         string         `yaml:"busy_timeout"`
	DecryptedPageCache  string         `yaml:"decrypted_page_cache"`
	ProgressInterval    string         `yaml:"progress_interval"`
	AuditInterval       string         `yaml:"audit_interval"`
	ReopenInterval      string         `yaml:"reopen_interval"`
	BackupInterval      string         `yaml:"backup_interval"`
	RekeyInterval       string         `yaml:"rekey_interval"`
	Workload            workloadConfig `yaml:"workload"`
}

type config struct {
	rawConfig
	DurationValue         time.Duration
	BusyTimeoutValue      time.Duration
	CacheBytes            int64
	ProgressEvery         time.Duration
	AuditEvery            time.Duration
	ReopenEvery           time.Duration
	BackupEvery           time.Duration
	RekeyEvery            time.Duration
	CipherValue           sqliteseal.Cipher
	RunDir                string
	DBPath                string
	LogPath               string
	EffectiveDatabaseName string
}

func loadConfig(path string, now time.Time) (config, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var raw rawConfig
	if err := yaml.Unmarshal(blob, &raw); err != nil {
		return config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg := config{rawConfig: raw}
	if cfg.Workers < 1 {
		return config{}, errors.New("workers must be at least 1")
	}
	if cfg.OperationsPerSecond < 1 {
		return config{}, errors.New("operations_per_second must be at least 1")
	}
	if cfg.RowsPerTable < 10 {
		return config{}, errors.New("rows_per_table must be at least 10")
	}
	if cfg.InitialRowsPerTable < 1 || cfg.InitialRowsPerTable > cfg.RowsPerTable {
		return config{}, errors.New("initial_rows_per_table must be between 1 and rows_per_table")
	}
	if strings.TrimSpace(cfg.MasterKey) == "" {
		return config{}, errors.New("master_key is required")
	}
	if filepath.Base(cfg.DatabaseFile) != cfg.DatabaseFile || cfg.DatabaseFile == "." {
		return config{}, errors.New("database_file must be a file name, not a path")
	}
	if sum := cfg.Workload.InsertPct + cfg.Workload.UpdatePct + cfg.Workload.SelectPct + cfg.Workload.JoinPct; sum != 100 {
		return config{}, fmt.Errorf("workload percentages must total 100, got %d", sum)
	}
	if cfg.DurationValue, err = optionalDuration("duration", cfg.Duration); err != nil {
		return config{}, err
	}
	if cfg.BusyTimeoutValue, err = positiveDuration("busy_timeout", cfg.BusyTimeout); err != nil {
		return config{}, err
	}
	if cfg.ProgressEvery, err = positiveDuration("progress_interval", cfg.ProgressInterval); err != nil {
		return config{}, err
	}
	if cfg.AuditEvery, err = positiveDuration("audit_interval", cfg.AuditInterval); err != nil {
		return config{}, err
	}
	if cfg.ReopenEvery, err = positiveDuration("reopen_interval", cfg.ReopenInterval); err != nil {
		return config{}, err
	}
	if cfg.BackupEvery, err = positiveDuration("backup_interval", cfg.BackupInterval); err != nil {
		return config{}, err
	}
	if cfg.RekeyEvery, err = positiveDuration("rekey_interval", cfg.RekeyInterval); err != nil {
		return config{}, err
	}
	if cfg.CacheBytes, err = parseBytes(cfg.DecryptedPageCache); err != nil {
		return config{}, fmt.Errorf("decrypted_page_cache: %w", err)
	}
	switch sqliteseal.Cipher(cfg.Cipher) {
	case sqliteseal.CipherAES256GCM, sqliteseal.CipherChaCha20Poly1305, sqliteseal.CipherXChaCha20Poly1305:
		cfg.CipherValue = sqliteseal.Cipher(cfg.Cipher)
	default:
		return config{}, fmt.Errorf("unsupported cipher %q", cfg.Cipher)
	}
	switch strings.ToUpper(cfg.JournalMode) {
	case "WAL", "MEMORY":
	default:
		return config{}, errors.New("journal_mode must be WAL or MEMORY")
	}

	cfg.RunDir = filepath.Join("runs", now.Format("20060102-150405.000"))
	cfg.EffectiveDatabaseName = cfg.DatabaseFile
	cfg.DBPath = filepath.Join(cfg.RunDir, cfg.DatabaseFile)
	cfg.LogPath = filepath.Join(cfg.RunDir, "runner.log")
	return cfg, nil
}

func positiveDuration(name, value string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return d, nil
}

func optionalDuration(name, value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	return positiveDuration(name, value)
}

func parseBytes(value string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(value))
	units := []struct {
		suffix string
		scale  int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}}
	for _, unit := range units {
		if strings.HasSuffix(s, unit.suffix) {
			number := strings.TrimSpace(strings.TrimSuffix(s, unit.suffix))
			n, err := strconv.ParseInt(number, 10, 64)
			if err != nil || n <= 0 {
				return 0, errors.New("must be a positive size such as 128MB")
			}
			return n * unit.scale, nil
		}
	}
	return 0, errors.New("must include B, KB, MB, or GB")
}

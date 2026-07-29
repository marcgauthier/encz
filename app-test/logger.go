package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type liveLogger struct {
	mu       sync.Mutex
	file     *os.File
	out      io.Writer
	errOut   io.Writer
	progress bool
	history  []string
	next     int
}

func newLiveLogger(path string) (*liveLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &liveLogger{
		file:    f,
		out:     os.Stdout,
		errOut:  os.Stderr,
		history: make([]string, 200),
	}, nil
}

func (l *liveLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clearProgress()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func (l *liveLogger) record(level, message string, console bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().UTC().Format(time.RFC3339Nano), level, message)
	if l.file != nil {
		_, _ = io.WriteString(l.file, line)
	}
	l.history[l.next] = line
	l.next = (l.next + 1) % len(l.history)
	if console {
		l.clearProgress()
		_, _ = io.WriteString(l.errOut, line)
	}
}

func (l *liveLogger) Info(format string, args ...any) {
	l.record("INFO", fmt.Sprintf(format, args...), false)
}

func (l *liveLogger) Error(format string, args ...any) {
	l.record("ERROR", fmt.Sprintf(format, args...), true)
}

func (l *liveLogger) Progress(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintf(l.out, "\r\033[2K%s", message)
	l.progress = true
}

func (l *liveLogger) DumpHistory() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clearProgress()
	header := "\n================ SQLiteSeal failure history ================\n"
	_, _ = io.WriteString(l.errOut, header)
	if l.file != nil {
		_, _ = io.WriteString(l.file, header)
	}
	for i := 0; i < len(l.history); i++ {
		line := l.history[(l.next+i)%len(l.history)]
		if strings.TrimSpace(line) == "" {
			continue
		}
		_, _ = io.WriteString(l.errOut, line)
		if l.file != nil {
			_, _ = io.WriteString(l.file, line)
		}
	}
	footer := "============================================================\n"
	_, _ = io.WriteString(l.errOut, footer)
	if l.file != nil {
		_, _ = io.WriteString(l.file, footer)
		_ = l.file.Sync()
	}
}

func (l *liveLogger) clearProgress() {
	if l.progress {
		_, _ = io.WriteString(l.out, "\r\033[2K")
		l.progress = false
	}
}

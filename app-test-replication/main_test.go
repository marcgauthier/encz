package main

import (
	"testing"
	"time"
)

func TestTwoNodeReplication(t *testing.T) {
	if testing.Short() {
		t.Skip("two-node integration")
	}
	if err := run(90 * time.Second); err != nil {
		t.Fatal(err)
	}
}

package sqliteseal

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"strings"
	"testing"
)

func TestReplicationFrameRoundTripAndLimits(t *testing.T) {
	var b bytes.Buffer
	want := wireMessage{Type: "pull", Since: 7}
	if err := writeReplicationFrame(&b, want, 1024); err != nil {
		t.Fatal(err)
	}
	got, err := readReplicationFrame(&b, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Since != 7 {
		t.Fatalf("got %+v", got)
	}
	var oversized bytes.Buffer
	_ = writeReplicationFrame(&oversized, want, 1024)
	if _, err = readReplicationFrame(&oversized, 1, 1024); err == nil {
		t.Fatal("compressed limit accepted")
	}
}
func TestReplicationFrameRejectsDuplicateAndNonCanonicalJSON(t *testing.T) {
	for _, raw := range []string{`{"type":"pull","type":"push"}`, `{ "type":"pull"}`} {
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		_, _ = gz.Write([]byte(raw))
		_ = gz.Close()
		var frame bytes.Buffer
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], uint32(compressed.Len()))
		frame.Write(h[:])
		frame.Write(compressed.Bytes())
		if _, err := readReplicationFrame(&frame, 1024, 1024); err == nil {
			t.Fatalf("accepted %s", strings.TrimSpace(raw))
		}
	}
}
func TestReplicationVersionOrdering(t *testing.T) {
	if compareReplicationVersion(1, 0, "b", 1, 0, "a") <= 0 {
		t.Fatal("UUID tie break")
	}
	if compareReplicationVersion(1, 2, "a", 1, 3, "z") >= 0 {
		t.Fatal("logical order")
	}
	if compareReplicationVersion(2, 0, "a", 1, 99, "z") <= 0 {
		t.Fatal("physical order")
	}
}

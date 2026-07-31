package sqliteseal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
)

const replicationSnapshotChunkBytes = 64 << 10

func snapshotChunkHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readSnapshotFileChunk(file *os.File, offset, size int64, buffer []byte) ([]byte, error) {
	if offset < 0 || offset >= size {
		return nil, errors.New("replication: invalid snapshot chunk offset")
	}
	length := int64(len(buffer))
	if remaining := size - offset; remaining < length {
		length = remaining
	}
	data := buffer[:length]
	n, err := file.ReadAt(data, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n != len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func provideSnapshotChunks(c net.Conn, snapshot replicationSnapshotFile, maxCompressed, maxUncompressed int) error {
	file, err := os.Open(snapshot.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	buffer := make([]byte, replicationSnapshotChunkBytes)
	for {
		request, readErr := readReplicationFrame(c, maxCompressed, maxUncompressed)
		if readErr != nil {
			return readErr
		}
		if request.Type != "snapshot_fetch" || request.SnapshotChunk == nil || request.SnapshotChunk.SnapshotUUID != snapshot.Manifest.SnapshotUUID {
			return errors.New("replication: invalid snapshot fetch request")
		}
		offset := request.SnapshotChunk.Offset
		data, readErr := readSnapshotFileChunk(file, offset, snapshot.Manifest.ContentSizeBytes, buffer)
		if readErr != nil {
			return readErr
		}
		end := offset + int64(len(data))
		chunk := wireSnapshotChunk{SnapshotUUID: snapshot.Manifest.SnapshotUUID, Offset: offset, Data: data, ChunkHash: snapshotChunkHash(data), Done: end == snapshot.Manifest.ContentSizeBytes}
		if err = writeReplicationFrame(c, wireMessage{Type: "snapshot_chunk", SnapshotChunk: &chunk}, maxCompressed); err != nil {
			return err
		}
		if chunk.Done {
			return nil
		}
	}
}

func (r *replicationRuntime) requestSnapshotChunks(c net.Conn, manifest replicationSnapshotManifest, maximumBytes int64, maxCompressed, maxUncompressed int) (string, error) {
	if err := manifest.validate(maximumBytes); err != nil {
		return "", err
	}
	file, temporaryPath, err := r.createSnapshotTemporaryFile(manifest.SnapshotUUID)
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	hasher := sha256.New()
	var offset int64
	for offset < manifest.ContentSizeBytes {
		request := wireSnapshotChunk{SnapshotUUID: manifest.SnapshotUUID, Offset: offset}
		if err = writeReplicationFrame(c, wireMessage{Type: "snapshot_fetch", SnapshotChunk: &request}, maxCompressed); err != nil {
			return "", err
		}
		message, readErr := readReplicationFrame(c, maxCompressed, maxUncompressed)
		if readErr != nil {
			return "", readErr
		}
		if message.Type != "snapshot_chunk" || message.SnapshotChunk == nil {
			return "", errors.New("replication: invalid snapshot chunk response")
		}
		chunk := message.SnapshotChunk
		if chunk.SnapshotUUID != manifest.SnapshotUUID || chunk.Offset != offset || len(chunk.Data) == 0 || len(chunk.Data) > replicationSnapshotChunkBytes || chunk.ChunkHash != snapshotChunkHash(chunk.Data) || int64(len(chunk.Data)) > manifest.ContentSizeBytes-offset {
			return "", errors.New("replication: invalid snapshot chunk")
		}
		written, writeErr := file.Write(chunk.Data)
		if writeErr != nil {
			return "", writeErr
		}
		if written != len(chunk.Data) {
			return "", io.ErrShortWrite
		}
		_, _ = hasher.Write(chunk.Data)
		offset += int64(len(chunk.Data))
		if chunk.Done != (offset == manifest.ContentSizeBytes) {
			return "", errors.New("replication: invalid snapshot completion marker")
		}
	}
	if hex.EncodeToString(hasher.Sum(nil)) != manifest.ContentHash {
		return "", errors.New("replication: transferred snapshot integrity failure")
	}
	if err = file.Sync(); err != nil {
		return "", err
	}
	if err = file.Close(); err != nil {
		return "", err
	}
	keep = true
	return temporaryPath, nil
}

func answerSnapshotFetch(c net.Conn, first wireMessage, snapshot replicationSnapshotFile, maxCompressed, maxUncompressed int) (wireMessage, error) {
	file, err := os.Open(snapshot.Path)
	if err != nil {
		return wireMessage{}, err
	}
	defer file.Close()
	buffer := make([]byte, replicationSnapshotChunkBytes)
	message := first
	for message.Type == "snapshot_fetch" {
		request := message.SnapshotChunk
		if request == nil || request.SnapshotUUID != snapshot.Manifest.SnapshotUUID {
			return wireMessage{}, errors.New("replication: invalid uploaded snapshot request")
		}
		data, readErr := readSnapshotFileChunk(file, request.Offset, snapshot.Manifest.ContentSizeBytes, buffer)
		if readErr != nil {
			return wireMessage{}, readErr
		}
		end := request.Offset + int64(len(data))
		chunk := wireSnapshotChunk{SnapshotUUID: snapshot.Manifest.SnapshotUUID, Offset: request.Offset, Data: data, ChunkHash: snapshotChunkHash(data), Done: end == snapshot.Manifest.ContentSizeBytes}
		if err = writeReplicationFrame(c, wireMessage{Type: "snapshot_chunk", SnapshotChunk: &chunk}, maxCompressed); err != nil {
			return wireMessage{}, err
		}
		message, err = readReplicationFrame(c, maxCompressed, maxUncompressed)
		if err != nil {
			return wireMessage{}, err
		}
	}
	return message, nil
}

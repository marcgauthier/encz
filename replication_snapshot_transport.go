package sqliteseal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
)

const replicationSnapshotChunkBytes = 64 << 10

func snapshotChunkHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func provideSnapshotChunks(c net.Conn, manifest replicationSnapshotManifest, raw []byte, maxCompressed, maxUncompressed int) error {
	for {
		request, err := readReplicationFrame(c, maxCompressed, maxUncompressed)
		if err != nil {
			return err
		}
		if request.Type != "snapshot_fetch" || request.SnapshotChunk == nil || request.SnapshotChunk.SnapshotUUID != manifest.SnapshotUUID {
			return errors.New("replication: invalid snapshot fetch request")
		}
		offset := request.SnapshotChunk.Offset
		if offset < 0 || offset >= int64(len(raw)) {
			return errors.New("replication: invalid snapshot chunk offset")
		}
		end := offset + replicationSnapshotChunkBytes
		if end > int64(len(raw)) {
			end = int64(len(raw))
		}
		data := append([]byte(nil), raw[offset:end]...)
		chunk := wireSnapshotChunk{SnapshotUUID: manifest.SnapshotUUID, Offset: offset, Data: data, ChunkHash: snapshotChunkHash(data), Done: end == int64(len(raw))}
		if err = writeReplicationFrame(c, wireMessage{Type: "snapshot_chunk", SnapshotChunk: &chunk}, maxCompressed); err != nil {
			return err
		}
		if chunk.Done {
			return nil
		}
	}
}

func requestSnapshotChunks(c net.Conn, manifest replicationSnapshotManifest, maxCompressed, maxUncompressed int) ([]byte, error) {
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	raw := make([]byte, 0, manifest.ContentSizeBytes)
	for int64(len(raw)) < manifest.ContentSizeBytes {
		request := wireSnapshotChunk{SnapshotUUID: manifest.SnapshotUUID, Offset: int64(len(raw))}
		if err := writeReplicationFrame(c, wireMessage{Type: "snapshot_fetch", SnapshotChunk: &request}, maxCompressed); err != nil {
			return nil, err
		}
		message, err := readReplicationFrame(c, maxCompressed, maxUncompressed)
		if err != nil {
			return nil, err
		}
		if message.Type != "snapshot_chunk" || message.SnapshotChunk == nil {
			return nil, errors.New("replication: invalid snapshot chunk response")
		}
		chunk := message.SnapshotChunk
		if chunk.SnapshotUUID != manifest.SnapshotUUID || chunk.Offset != int64(len(raw)) || len(chunk.Data) == 0 || len(chunk.Data) > replicationSnapshotChunkBytes || chunk.ChunkHash != snapshotChunkHash(chunk.Data) || int64(len(raw)+len(chunk.Data)) > manifest.ContentSizeBytes {
			return nil, errors.New("replication: invalid snapshot chunk")
		}
		raw = append(raw, chunk.Data...)
		if chunk.Done != (int64(len(raw)) == manifest.ContentSizeBytes) {
			return nil, errors.New("replication: invalid snapshot completion marker")
		}
	}
	if snapshotHash(raw) != manifest.ContentHash {
		return nil, errors.New("replication: transferred snapshot integrity failure")
	}
	return raw, nil
}

func answerSnapshotFetch(c net.Conn, first wireMessage, manifest replicationSnapshotManifest, raw []byte, maxCompressed, maxUncompressed int) (wireMessage, error) {
	message := first
	for message.Type == "snapshot_fetch" {
		request := message.SnapshotChunk
		if request == nil || request.SnapshotUUID != manifest.SnapshotUUID || request.Offset < 0 || request.Offset >= int64(len(raw)) {
			return wireMessage{}, errors.New("replication: invalid uploaded snapshot request")
		}
		end := request.Offset + replicationSnapshotChunkBytes
		if end > int64(len(raw)) {
			end = int64(len(raw))
		}
		data := append([]byte(nil), raw[request.Offset:end]...)
		chunk := wireSnapshotChunk{SnapshotUUID: manifest.SnapshotUUID, Offset: request.Offset, Data: data, ChunkHash: snapshotChunkHash(data), Done: end == int64(len(raw))}
		if err := writeReplicationFrame(c, wireMessage{Type: "snapshot_chunk", SnapshotChunk: &chunk}, maxCompressed); err != nil {
			return wireMessage{}, err
		}
		var err error
		message, err = readReplicationFrame(c, maxCompressed, maxUncompressed)
		if err != nil {
			return wireMessage{}, err
		}
	}
	return message, nil
}

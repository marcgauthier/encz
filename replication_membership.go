package sqliteseal

import (
	"context"
	"errors"
	"fmt"
)

func (db *DB) validateMembershipManifest(ctx context.Context, manifest MembershipManifest) error {
	if manifest.PolicyHash == "" || len(manifest.Nodes) == 0 {
		return ErrReplicationMembershipMismatch
	}
	type configuredNode struct {
		incarnation string
		listens     bool
		local       bool
	}
	configured := map[string]configuredNode{}
	rows, err := db.QueryContext(ctx, `SELECT node_uuid,incarnation_uuid,listen_enabled,is_local FROM replication_nodes`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, incarnation string
		var listens, local int
		if err = rows.Scan(&id, &incarnation, &listens, &local); err != nil {
			rows.Close()
			return err
		}
		configured[id] = configuredNode{incarnation: incarnation, listens: listens == 1, local: local == 1}
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if len(configured) != len(manifest.Nodes) {
		return fmt.Errorf("%w: manifest is not the complete configured member set", ErrReplicationMembershipMismatch)
	}
	members := make(map[string]MembershipNode, len(manifest.Nodes))
	localActive := false
	for _, node := range manifest.Nodes {
		if !isCanonicalUUID(node.NodeUUID) || !isCanonicalUUID(node.IncarnationUUID) {
			return fmt.Errorf("%w: invalid member identity", ErrReplicationMembershipMismatch)
		}
		if node.State != "joining" && node.State != "active" && node.State != "retired" {
			return fmt.Errorf("%w: invalid member state", ErrReplicationMembershipMismatch)
		}
		if _, duplicate := members[node.NodeUUID]; duplicate {
			return fmt.Errorf("%w: duplicate member", ErrReplicationMembershipMismatch)
		}
		registered, ok := configured[node.NodeUUID]
		if !ok || registered.incarnation != node.IncarnationUUID || registered.listens != node.ListenEnabled {
			return fmt.Errorf("%w: member registration mismatch", ErrReplicationMembershipMismatch)
		}
		if registered.local && node.State == "active" {
			localActive = true
		}
		members[node.NodeUUID] = node
	}
	if !localActive {
		return fmt.Errorf("%w: local node is not active", ErrReplicationMembershipMismatch)
	}
	for _, left := range manifest.Nodes {
		if left.State != "active" {
			continue
		}
		for _, right := range manifest.Nodes {
			if right.State != "active" || left.NodeUUID >= right.NodeUUID {
				continue
			}
			leftRole := left.RoleByPeer[right.NodeUUID]
			rightRole := right.RoleByPeer[left.NodeUUID]
			if !((leftRole == ReplicationDial && rightRole == ReplicationAccept) || (leftRole == ReplicationAccept && rightRole == ReplicationDial)) {
				return fmt.Errorf("%w: peer roles are not complementary", ErrReplicationMembershipMismatch)
			}
			if leftRole == ReplicationDial && !right.ListenEnabled {
				return fmt.Errorf("%w: dial target does not listen", ErrReplicationMembershipMismatch)
			}
			if rightRole == ReplicationDial && !left.ListenEnabled {
				return fmt.Errorf("%w: dial target does not listen", ErrReplicationMembershipMismatch)
			}
		}
	}
	return nil
}

func (r *replicationRuntime) closeUnauthorizedSessions(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for node, connection := range r.connections {
		var enabled int
		err := r.db.QueryRowContext(ctx, `SELECT enabled FROM replication_nodes WHERE node_uuid=?`, node).Scan(&enabled)
		if errors.Is(err, context.Canceled) {
			return err
		}
		if err != nil || enabled == 0 {
			_ = connection.Close()
			delete(r.connections, node)
		}
	}
	return nil
}

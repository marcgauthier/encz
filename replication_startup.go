package sqliteseal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

func (r *replicationRuntime) validateInstalledReplicationSchema(ctx context.Context) error {
	var storedHash string
	if err := r.db.QueryRowContext(ctx, `SELECT schema_hash FROM replication_local_state`).Scan(&storedHash); err != nil {
		return err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT descriptor_json FROM replication_table_descriptors ORDER BY table_name`)
	if err != nil {
		return err
	}
	var installed []replicationTableDescriptor
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var descriptor replicationTableDescriptor
		if err = json.Unmarshal([]byte(raw), &descriptor); err != nil {
			rows.Close()
			return err
		}
		installed = append(installed, descriptor)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if len(installed) == 0 {
		return errors.New("replication: no installed table descriptors")
	}
	current := make([]replicationTableDescriptor, 0, len(installed))
	for _, descriptor := range installed {
		actual, buildErr := tableDescriptor(ctx, r.db, descriptor.Table)
		if buildErr != nil {
			return buildErr
		}
		if actual.DescriptorID != descriptor.DescriptorID || actual.TableSQL != descriptor.TableSQL {
			return fmt.Errorf("%w: replicated table %s drifted", ErrReplicationSchemaMismatch, descriptor.Table.Name)
		}
		current = append(current, actual)
		expected := []struct{ kind, name string }{{"table", descriptor.DescriptorID + "__replication_changes"}}
		for _, suffix := range []string{"insert", "update", "delete", "immutable_pk", "event_hash", "nfc_insert", "nfc_update"} {
			expected = append(expected, struct{ kind, name string }{"trigger", "sqliteseal_" + descriptor.DescriptorID + "_" + suffix})
		}
		for _, column := range descriptor.Table.Columns {
			expected = append(expected, struct{ kind, name string }{"trigger", "sqliteseal_" + descriptor.DescriptorID + "_fv_" + column})
		}
		for _, object := range expected {
			var count int
			if err = r.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type=? AND name=?`, object.kind, object.name).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("%w: missing generated %s %s", ErrReplicationSchemaMismatch, object.kind, object.name)
			}
		}
	}
	computed, err := descriptorsHash(current)
	if err != nil {
		return err
	}
	if computed != storedHash {
		return fmt.Errorf("%w: descriptor hash drift", ErrReplicationSchemaMismatch)
	}
	return nil
}

func (r *replicationRuntime) fenceStartup(reason error) {
	_, _ = r.db.Exec(`UPDATE replication_local_state SET network_enabled=0,blocked_reason=?,updated_at_utc=sqliteseal_utc_now()`, reason.Error())
	r.log("replication startup fenced: %v", reason)
}

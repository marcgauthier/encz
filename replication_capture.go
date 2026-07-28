package sqliteseal

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

func installCaptureSchema(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor, schemaHash string) error {
	by := map[string]replicationColumn{}
	for _, c := range d.Columns {
		by[c.Name] = c
	}
	payload := quoteReplicationIdent(d.DescriptorID + "__replication_changes")
	defs := []string{`change_uuid TEXT PRIMARY KEY`, `field_versions_json TEXT NOT NULL`}
	for _, n := range d.Table.Columns {
		typ := by[n].DeclaredType
		if typ == "" {
			typ = "BLOB"
		}
		defs = append(defs, quoteReplicationIdent(n+"__value")+" "+typ, quoteReplicationIdent(n+"__present")+" INTEGER NOT NULL CHECK("+quoteReplicationIdent(n+"__present")+" IN(0,1))")
	}
	createSQL := "CREATE TABLE " + payload + "(" + strings.Join(defs, ",") + ")"
	if _, err := tx.ExecContext(ctx, createSQL); err != nil {
		return fmt.Errorf("create capture table for %s: %w", d.Table.Name, err)
	}
	if err := installEventHashTrigger(ctx, tx, d, payload); err != nil {
		return err
	}
	if err := installLocalFieldVersionTriggers(ctx, tx, d, payload); err != nil {
		return err
	}
	if err := installImmutablePrimaryKeyTrigger(ctx, tx, d); err != nil {
		return err
	}
	if err := installNFCValidationTriggers(ctx, tx, d); err != nil {
		return err
	}
	rowKey := func(prefix string) string {
		parts := []string{}
		for _, n := range d.Table.PrimaryKeyColumns {
			parts = append(parts, strconv.Quote(n), prefix+"."+quoteReplicationIdent(n))
		}
		return "sqliteseal_canonical_object(" + strings.Join(parts, ",") + ")"
	}
	allNames := []string{}
	for _, n := range d.Table.Columns {
		allNames = append(allNames, strconv.Quote(n))
	}
	updateChanged := func() string {
		parts := []string{}
		for _, n := range d.Table.Columns {
			parts = append(parts, "SELECT "+strconv.Quote(n)+" AS name WHERE OLD."+quoteReplicationIdent(n)+" IS NOT NEW."+quoteReplicationIdent(n))
		}
		return "(SELECT coalesce(json_group_array(name),'[]') FROM (" + strings.Join(parts, " UNION ALL ") + "))"
	}
	makeTrigger := func(op, prefix, changed, when string) error {
		rk := rowKey(prefix)
		name := quoteReplicationIdent("sqliteseal_" + d.DescriptorID + "_" + op)
		values := []string{}
		for _, n := range d.Table.Columns {
			present := "1"
			if op == "update" {
				present = "CASE WHEN OLD." + quoteReplicationIdent(n) + " IS NOT NEW." + quoteReplicationIdent(n) + " THEN 1 ELSE 0 END"
			} else if op == "delete" {
				present = "0"
			}
			values = append(values, prefix+"."+quoteReplicationIdent(n), present)
		}
		eventID := "sqliteseal_event_uuid(local_node_uuid,last_origin_counter)"
		created := "sqliteseal_time_from_us(last_hlc_physical_utc_us)"
		createdStored := "(SELECT created_at_utc FROM replication_changes ORDER BY change_seq DESC LIMIT 1)"
		body := `UPDATE replication_local_state SET last_origin_counter=last_origin_counter+1,last_hlc_logical=CASE WHEN sqliteseal_time_us()>last_hlc_physical_utc_us THEN 0 ELSE last_hlc_logical+1 END,last_hlc_physical_utc_us=max(last_hlc_physical_utc_us,sqliteseal_time_us()),updated_at_utc=sqliteseal_utc_now();`
		body += `INSERT INTO replication_changes(change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,stored_at_utc,payload_hash) SELECT ` + eventID + `,local_node_uuid,last_origin_counter,` + strconv.Quote(op) + `,` + strconv.Quote(d.Table.Name) + `,` + rk + `,` + changed + `,last_hlc_physical_utc_us,last_hlc_logical,schema_version,schema_hash,replication_domain,` + created + `,` + created + `,lower(hex(zeroblob(32))) FROM replication_local_state;`
		vals := []string{"(SELECT change_uuid FROM replication_changes ORDER BY change_seq DESC LIMIT 1)", "'{}'"}
		vals = append(vals, values...)
		body += `INSERT INTO ` + payload + ` VALUES(` + strings.Join(vals, ",") + `);`
		state := "live"
		if op == "delete" {
			state = "deleted"
		}
		body += `INSERT INTO replication_row_versions VALUES(` + strconv.Quote(d.Table.Name) + `,` + rk + `,` + strconv.Quote(state) + `,(SELECT last_hlc_physical_utc_us FROM replication_local_state),(SELECT last_hlc_logical FROM replication_local_state),(SELECT local_node_uuid FROM replication_local_state),(SELECT change_uuid FROM replication_changes ORDER BY change_seq DESC LIMIT 1),` + createdStored + `,` + createdStored + `) ON CONFLICT(table_name,row_key_json) DO UPDATE SET row_state=excluded.row_state,winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,winner_hlc_logical=excluded.winner_hlc_logical,winner_origin_node_uuid=excluded.winner_origin_node_uuid,winner_change_uuid=excluded.winner_change_uuid,winner_changed_at_utc=excluded.winner_changed_at_utc,updated_at_utc=excluded.updated_at_utc;`
		body += `INSERT INTO replication_origin_cursors SELECT local_node_uuid,local_node_uuid,last_origin_counter,last_origin_counter,NULL,0,` + created + ` FROM replication_local_state WHERE 1 ON CONFLICT(tracking_node_uuid,origin_node_uuid) DO UPDATE SET contiguous_counter=excluded.contiguous_counter,highest_seen_counter=excluded.highest_seen_counter,updated_at_utc=excluded.updated_at_utc;`
		body += `SELECT sqliteseal_identity_guard(local_node_uuid,last_origin_counter) FROM replication_local_state;`
		triggerSQL := `CREATE TRIGGER ` + name + ` AFTER ` + strings.ToUpper(op) + ` ON ` + quoteReplicationIdent(d.Table.Name) + ` WHEN sqliteseal_replication_mode()='local'` + when + ` BEGIN ` + body + ` END`
		if _, err := tx.ExecContext(ctx, triggerSQL); err != nil {
			return fmt.Errorf("create %s trigger for %s: %w", op, d.Table.Name, err)
		}
		return nil
	}
	if err := makeTrigger("insert", "NEW", "json_array("+strings.Join(allNames, ",")+")", ""); err != nil {
		return err
	}
	if err := makeTrigger("delete", "OLD", "json_array()", ""); err != nil {
		return err
	}
	conditions := []string{}
	for _, n := range d.Table.Columns {
		conditions = append(conditions, "OLD."+quoteReplicationIdent(n)+" IS NOT NEW."+quoteReplicationIdent(n))
	}
	return makeTrigger("update", "NEW", updateChanged(), " AND ("+strings.Join(conditions, " OR ")+")")
}

func installEventHashTrigger(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor, payload string) error {
	args := []string{"change_uuid", "origin_node_uuid", "origin_counter", "operation", "table_name", "row_key_json", "changed_fields_json", "is_explicit_recreation", "hlc_physical_utc_us", "hlc_logical", "schema_version", "schema_hash", "replication_domain", "created_at_utc"}
	for _, column := range d.Table.Columns {
		args = append(args, strconv.Quote(column), "NEW."+quoteReplicationIdent(column+"__value"), "NEW."+quoteReplicationIdent(column+"__present"))
	}
	statement := `CREATE TRIGGER ` + quoteReplicationIdent("sqliteseal_"+d.DescriptorID+"_event_hash") + ` AFTER INSERT ON ` + payload + ` BEGIN UPDATE replication_changes SET payload_hash=sqliteseal_event_hash(` + strings.Join(args, ",") + `) WHERE change_uuid=NEW.change_uuid; END`
	if _, err := tx.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("create event-hash trigger for %s: %w", d.Table.Name, err)
	}
	return nil
}

func installLocalFieldVersionTriggers(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor, payload string) error {
	for _, column := range d.Table.Columns {
		name := quoteReplicationIdent("sqliteseal_" + d.DescriptorID + "_fv_" + column)
		present := quoteReplicationIdent(column + "__present")
		statement := `CREATE TRIGGER ` + name + ` AFTER INSERT ON ` + payload + ` WHEN sqliteseal_replication_mode()='local' AND NEW.` + present + `=1 BEGIN ` +
			`INSERT INTO replication_field_versions SELECT c.table_name,c.row_key_json,` + strconv.Quote(column) + `,c.hlc_physical_utc_us,c.hlc_logical,c.origin_node_uuid,c.change_uuid,c.created_at_utc,NULL,sqliteseal_utc_now() FROM replication_changes c WHERE c.change_uuid=NEW.change_uuid ON CONFLICT(table_name,row_key_json,field_name) DO UPDATE SET winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,winner_hlc_logical=excluded.winner_hlc_logical,winner_origin_node_uuid=excluded.winner_origin_node_uuid,winner_change_uuid=excluded.winner_change_uuid,winner_changed_at_utc=excluded.winner_changed_at_utc,updated_at_utc=excluded.updated_at_utc; END`
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create field-version trigger for %s.%s: %w", d.Table.Name, column, err)
		}
	}
	return nil
}

func installImmutablePrimaryKeyTrigger(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor) error {
	columns := []string{}
	changed := []string{}
	for _, n := range d.Table.PrimaryKeyColumns {
		columns = append(columns, quoteReplicationIdent(n))
		changed = append(changed, "OLD."+quoteReplicationIdent(n)+" IS NOT NEW."+quoteReplicationIdent(n))
	}
	statement := `CREATE TRIGGER ` + quoteReplicationIdent("sqliteseal_"+d.DescriptorID+"_immutable_pk") + ` BEFORE UPDATE OF ` + strings.Join(columns, ",") + ` ON ` + quoteReplicationIdent(d.Table.Name) + ` WHEN ` + strings.Join(changed, " OR ") + ` BEGIN SELECT RAISE(ABORT,'replicated primary key is immutable'); END`
	if _, err := tx.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("create immutable primary-key trigger for %s: %w", d.Table.Name, err)
	}
	return nil
}

func installNFCValidationTriggers(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor) error {
	checks := make([]string, 0, len(d.Table.Columns))
	for _, column := range d.Table.Columns {
		checks = append(checks, "sqliteseal_is_nfc(NEW."+quoteReplicationIdent(column)+")=0")
	}
	when := strings.Join(checks, " OR ")
	for _, operation := range []string{"INSERT", "UPDATE"} {
		name := quoteReplicationIdent("sqliteseal_" + d.DescriptorID + "_nfc_" + strings.ToLower(operation))
		statement := `CREATE TRIGGER ` + name + ` BEFORE ` + operation + ` ON ` + quoteReplicationIdent(d.Table.Name) + ` WHEN sqliteseal_replication_mode()='local' AND (` + when + `) BEGIN SELECT RAISE(ABORT,'replicated text must be Unicode NFC'); END`
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create NFC validation trigger for %s: %w", d.Table.Name, err)
		}
	}
	return nil
}

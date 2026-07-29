package sqliteseal

import (
	"context"
	"path/filepath"
	"testing"
)

func openSchemaSyncTestDB(t *testing.T, id string, level int, ddl string, tables []ReplicatedTable) *DB {
	t.Helper()
	db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), "schema.db"), "schema-test-key")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if ddl != "" {
		if _, err = db.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.InitializeReplication(context.Background(), LocalNodeConfig{NodeUUID: id, NodeName: "node-" + id[len(id)-2:], ReplicationDomain: "schema-test", Level: level}, tables); err != nil {
		t.Fatal(err)
	}
	return db
}

func addSchemaAuthorityMember(t *testing.T, db *DB, id string, level int) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO replication_nodes(node_uuid,incarnation_uuid,node_name,replication_domain,node_level,is_local,membership_state,membership_epoch,listen_enabled,address,auth_mode,credential_name,enabled,rebootstrap_required,created_at_utc,updated_at_utc) VALUES(?,?,?, 'schema-test',?,0,'active',1,0,'','psk','',1,0,sqliteseal_utc_now(),sqliteseal_utc_now())`, id, id+"-incarnation", "remote-"+id[len(id)-2:], level)
	if err != nil {
		t.Fatal(err)
	}
}

func declaredType(t *testing.T, db *DB, table, column string) string {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + quoteReplicationIdent(table) + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err = rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		if name == column {
			return typ
		}
	}
	t.Fatalf("column %s.%s not found", table, column)
	return ""
}

func TestSchemaAgreementEqualLevelWaitsForLowerAuthorityAndPropagates(t *testing.T) {
	ctx := context.Background()
	aID := "00000000-0000-4000-8000-000000000201"
	bID := "00000000-0000-4000-8000-000000000202"
	cID := "00000000-0000-4000-8000-000000000203"
	tables := []ReplicatedTable{{Name: "items"}}
	a := openSchemaSyncTestDB(t, aID, 2, `CREATE TABLE items(id TEXT PRIMARY KEY,value TEXT)`, tables)
	b := openSchemaSyncTestDB(t, bID, 2, `CREATE TABLE items(id TEXT PRIMARY KEY,value INTEGER)`, tables)
	c := openSchemaSyncTestDB(t, cID, 1, `CREATE TABLE items(id TEXT PRIMARY KEY,value REAL)`, tables)
	addSchemaAuthorityMember(t, a, bID, 2)
	bDeclarations, err := b.replication.loadSchemaDeclarations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.replication.mergeSchemaDeclarations(ctx, bDeclarations); err != nil {
		t.Fatal(err)
	}
	pending, err := a.replication.reconcileSchemas(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("equal-level type conflict did not remain pending")
	}
	status, err := a.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.SchemaConflicts) != 1 || status.SchemaConflicts[0].AuthorityLevel != 2 {
		t.Fatalf("conflicts=%+v", status.SchemaConflicts)
	}

	addSchemaAuthorityMember(t, a, cID, 1)
	cDeclarations, err := c.replication.loadSchemaDeclarations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.replication.mergeSchemaDeclarations(ctx, cDeclarations); err != nil {
		t.Fatal(err)
	}
	pending, err = a.replication.reconcileSchemas(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending || declaredType(t, a, "items", "value") != "REAL" {
		t.Fatalf("pending=%v type=%s", pending, declaredType(t, a, "items", "value"))
	}

	addSchemaAuthorityMember(t, b, aID, 2)
	addSchemaAuthorityMember(t, b, cID, 1)
	propagated, err := a.replication.loadSchemaDeclarations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.replication.mergeSchemaDeclarations(ctx, propagated); err != nil {
		t.Fatal(err)
	}
	pending, err = b.replication.reconcileSchemas(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending || declaredType(t, b, "items", "value") != "REAL" {
		t.Fatalf("transitive pending=%v type=%s", pending, declaredType(t, b, "items", "value"))
	}
}

func TestSchemaAgreementCreatesMissingTableAndColumn(t *testing.T) {
	ctx := context.Background()
	sourceID := "00000000-0000-4000-8000-000000000211"
	targetID := "00000000-0000-4000-8000-000000000212"
	tables := []ReplicatedTable{{Name: "items"}}
	source := openSchemaSyncTestDB(t, sourceID, 0, `CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT)`, tables)
	target := openSchemaSyncTestDB(t, targetID, 1, "", tables)
	addSchemaAuthorityMember(t, target, sourceID, 0)
	declarations, err := source.replication.loadSchemaDeclarations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.replication.mergeSchemaDeclarations(ctx, declarations); err != nil {
		t.Fatal(err)
	}
	pending, err := target.replication.reconcileSchemas(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending || declaredType(t, target, "items", "name") != "TEXT" {
		t.Fatalf("pending=%v", pending)
	}

	columnTargetID := "00000000-0000-4000-8000-000000000213"
	columnTarget := openSchemaSyncTestDB(t, columnTargetID, 1, `CREATE TABLE items(id TEXT PRIMARY KEY)`, tables)
	addSchemaAuthorityMember(t, columnTarget, sourceID, 0)
	if err = columnTarget.replication.mergeSchemaDeclarations(ctx, declarations); err != nil {
		t.Fatal(err)
	}
	pending, err = columnTarget.replication.reconcileSchemas(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending || declaredType(t, columnTarget, "items", "name") != "TEXT" {
		t.Fatalf("column pending=%v", pending)
	}
}

func TestSchemaAgreementBackfillsNewlySelectedLocalColumn(t *testing.T) {
	ctx := context.Background()
	aID := "00000000-0000-4000-8000-000000000221"
	bID := "00000000-0000-4000-8000-000000000222"
	a := openSchemaSyncTestDB(t, aID, 1, `CREATE TABLE items(id TEXT PRIMARY KEY,private TEXT); INSERT INTO items VALUES('one','local-value')`, []ReplicatedTable{{Name: "items", Columns: []string{"id"}}})
	b := openSchemaSyncTestDB(t, bID, 1, `CREATE TABLE items(id TEXT PRIMARY KEY,private TEXT)`, []ReplicatedTable{{Name: "items"}})
	addSchemaAuthorityMember(t, a, bID, 1)
	declarations, err := b.replication.loadSchemaDeclarations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.replication.mergeSchemaDeclarations(ctx, declarations); err != nil {
		t.Fatal(err)
	}
	pending, err := a.replication.reconcileSchemas(ctx)
	if err != nil || pending {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	events, err := a.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Operation != "update" || events[1].ChangedFieldsJSON != `["private"]` || events[1].Values["private"].Value != "local-value" {
		t.Fatalf("events=%+v", events)
	}
}

func TestReplicationMigrationRetainsHistoryForOfflinePeer(t *testing.T) {
	ctx := context.Background()
	localID := "00000000-0000-4000-8000-000000000231"
	peerID := "00000000-0000-4000-8000-000000000232"
	db := openSchemaSyncTestDB(t, localID, 0, `CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT); INSERT INTO items VALUES('old','before')`, []ReplicatedTable{{Name: "items"}})
	if err := db.UpsertReplicationPeer(ctx, PeerConfig{NodeUUID: peerID, IncarnationUUID: "00000000-0000-4000-8000-000000000233", NodeName: "offline", Address: "127.0.0.1:1", Role: ReplicationDial, AuthMode: ReplicationAuthPSK}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE replication_nodes SET enabled=1,membership_state='active' WHERE node_uuid=?`, peerID); err != nil {
		t.Fatal(err)
	}
	migration := ReplicationMigration{FromVersion: 1, ToVersion: 2, Statements: []string{`ALTER TABLE items ADD COLUMN note TEXT`}, Tables: []ReplicatedTable{{Name: "items"}}}
	if err := db.ApplyReplicationMigration(ctx, migration); err != nil {
		t.Fatal(err)
	}
	events, err := db.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].SchemaVersion != 1 || events[0].Values["name"].Value != "before" || events[1].Operation != "update" || events[1].ChangedFieldsJSON != `["note"]` {
		t.Fatalf("events=%+v", events)
	}
	var revision int64
	if err = db.QueryRow(`SELECT schema_revision FROM replication_local_state`).Scan(&revision); err != nil || revision != 2 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
}

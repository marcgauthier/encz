package sqliteseal

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestReplicationCapturesExistingRowsAndOnlyChangedFields(t *testing.T) {
	db, e := OpenSQLiteSeal(filepath.Join(t.TempDir(), "baseline.db"), "key")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	_, e = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT,quantity INTEGER,note TEXT); INSERT INTO items VALUES('existing','old',1,NULL)`)
	if e != nil {
		t.Fatal(e)
	}
	e = db.InitializeReplication(context.Background(), LocalNodeConfig{NodeName: "n", ReplicationDomain: "d"}, []ReplicatedTable{{Name: "items"}})
	if e != nil {
		t.Fatal(e)
	}
	var count int
	if e = db.QueryRow(`SELECT count(*) FROM replication_changes`).Scan(&count); e != nil || count != 1 {
		t.Fatalf("baseline count=%d err=%v", count, e)
	}
	_, e = db.Exec(`UPDATE items SET quantity=2 WHERE id='existing'`)
	if e != nil {
		t.Fatal(e)
	}
	var changed string
	if e = db.QueryRow(`SELECT changed_fields_json FROM replication_changes ORDER BY origin_counter DESC LIMIT 1`).Scan(&changed); e != nil {
		t.Fatal(e)
	}
	if changed != `["quantity"]` {
		t.Fatalf("changed=%s", changed)
	}
	var presentName, presentQty int
	capture := quoteReplicationIdent((mustDescriptor(t, db, "items")).DescriptorID + "__replication_changes")
	if e = db.QueryRow(`SELECT name__present,quantity__present FROM `+capture+` ORDER BY rowid DESC LIMIT 1`).Scan(&presentName, &presentQty); e != nil {
		t.Fatal(e)
	}
	if presentName != 0 || presentQty != 1 {
		t.Fatalf("presence name=%d qty=%d", presentName, presentQty)
	}
	_, e = db.Exec(`UPDATE items SET id='new' WHERE id='existing'`)
	if e == nil {
		t.Fatal("mutable primary key accepted")
	}
}
func mustDescriptor(t *testing.T, db *DB, table string) replicationTableDescriptor {
	t.Helper()
	d, e := db.replication.descriptor(context.Background(), table)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestReplicationRejectsNonPrimaryUniqueIndex(t *testing.T) {
	db, e := OpenSQLiteSeal(filepath.Join(t.TempDir(), "unique.db"), "key")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT UNIQUE)`)
	e = db.InitializeReplication(context.Background(), LocalNodeConfig{NodeName: "n", ReplicationDomain: "d"}, []ReplicatedTable{{Name: "users"}})
	if !errors.Is(e, ErrReplicationSchemaUnsupported) {
		t.Fatalf("got %v", e)
	}
}

func TestReplicationManagedConstraintsAcceptForeignKeysUniqueIndexesAndCascades(t *testing.T) {
	db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), "constraints.db"), "key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE parents(id TEXT PRIMARY KEY); CREATE TABLE children(id TEXT PRIMARY KEY,parent_id TEXT NOT NULL REFERENCES parents(id) ON DELETE CASCADE); CREATE TABLE users(id TEXT PRIMARY KEY,tenant TEXT,email TEXT,active INTEGER,UNIQUE(tenant,email)); CREATE UNIQUE INDEX ux_users_active_email ON users(email) WHERE active=1`); err != nil {
		t.Fatal(err)
	}
	tables := []ReplicatedTable{
		{Name: "parents"},
		{Name: "children", ConstraintPolicy: ReplicationConstraintsManaged},
		{Name: "users", ConstraintPolicy: ReplicationConstraintsManaged},
	}
	if err = db.InitializeReplication(context.Background(), LocalNodeConfig{NodeName: "managed", ReplicationDomain: "test"}, tables); err != nil {
		t.Fatal(err)
	}
	children := mustDescriptor(t, db, "children")
	users := mustDescriptor(t, db, "users")
	if len(children.ForeignKeys) != 1 || len(users.Indexes) < 3 {
		t.Fatalf("foreign_keys=%d user_indexes=%d", len(children.ForeignKeys), len(users.Indexes))
	}
	if _, err = db.Exec(`INSERT INTO parents VALUES(?); INSERT INTO children VALUES(?,?); DELETE FROM parents WHERE id=?`, "p", "c", "p", "p"); err != nil {
		t.Fatal(err)
	}
	var deleteEvents int
	if err = db.QueryRow(`SELECT count(*) FROM replication_changes WHERE operation=? AND table_name IN (?,?)`, "delete", "parents", "children").Scan(&deleteEvents); err != nil {
		t.Fatal(err)
	}
	if deleteEvents != 2 {
		t.Fatalf("cascade delete events=%d", deleteEvents)
	}
}

func TestReplicationManagedUniqueConflictUsesDeterministicLWW(t *testing.T) {
	ctx := context.Background()
	open := func(name, id string) *DB {
		db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), name+".db"), "key")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err = db.Exec(`CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT UNIQUE)`); err != nil {
			t.Fatal(err)
		}
		if err = db.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: id, NodeName: name, ReplicationDomain: "test"}, []ReplicatedTable{{Name: "users", ConstraintPolicy: ReplicationConstraintsManaged}}); err != nil {
			t.Fatal(err)
		}
		return db
	}
	sourceID := "00000000-0000-4000-8000-000000000071"
	targetID := "00000000-0000-4000-8000-000000000072"
	source := open("unique-source", sourceID)
	target := open("unique-target", targetID)
	if _, err := source.Exec(`INSERT INTO users VALUES(?,?)`, "source", "alice.com"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, err := target.Exec(`INSERT INTO users VALUES(?,?)`, "target", "alice.com"); err != nil {
		t.Fatal(err)
	}
	sourceEvents, err := source.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(sourceEvents) != 1 {
		t.Fatalf("source events=%d err=%v", len(sourceEvents), err)
	}
	targetEvents, err := target.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(targetEvents) != 1 {
		t.Fatalf("target events=%d err=%v", len(targetEvents), err)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, sourceEvents[0]); err != nil {
		t.Fatal(err)
	}
	if err = source.replication.applyRemoteEvent(ctx, targetID, targetEvents[0]); err != nil {
		t.Fatal(err)
	}
	for name, db := range map[string]*DB{"source": source, "target": target} {
		var id string
		if err = db.QueryRow(`SELECT id FROM users WHERE email=?`, "alice.com").Scan(&id); err != nil || id != "target" {
			t.Fatalf("%s id=%s err=%v", name, id, err)
		}
		conflicts, conflictErr := db.ReplicationConflicts(ctx)
		if conflictErr != nil || len(conflicts) != 0 {
			t.Fatalf("%s conflicts=%+v err=%v", name, conflicts, conflictErr)
		}
	}
	var loserState string
	if err = source.QueryRow(`SELECT row_state FROM replication_row_versions WHERE table_name=? AND row_key_json=?`, "users", `{"id":"source"}`).Scan(&loserState); err != nil || loserState != "unique_deleted" {
		t.Fatalf("loser state=%s err=%v", loserState, err)
	}
}

func TestReplicationManagedForeignKeyWaitsForParentEvent(t *testing.T) {
	ctx := context.Background()
	open := func(name, id string) *DB {
		db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), name+".db"), "key")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err = db.Exec(`CREATE TABLE parents(id TEXT PRIMARY KEY); CREATE TABLE children(id TEXT PRIMARY KEY,parent_id TEXT NOT NULL REFERENCES parents(id))`); err != nil {
			t.Fatal(err)
		}
		tables := []ReplicatedTable{{Name: "parents"}, {Name: "children", ConstraintPolicy: ReplicationConstraintsManaged}}
		if err = db.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: id, NodeName: name, ReplicationDomain: "test"}, tables); err != nil {
			t.Fatal(err)
		}
		return db
	}
	sourceID := "00000000-0000-4000-8000-000000000081"
	source := open("fk-source", sourceID)
	target := open("fk-target", "00000000-0000-4000-8000-000000000082")
	if _, err := source.Exec(`PRAGMA foreign_keys=OFF; INSERT INTO children VALUES(?,?)`, "child", "parent"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`PRAGMA foreign_keys=ON; INSERT INTO parents VALUES(?)`, "parent"); err != nil {
		t.Fatal(err)
	}
	events, err := source.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, events[0]); err != nil {
		t.Fatal(err)
	}
	var state, reason string
	if err = target.QueryRow(`SELECT apply_state,quarantine_reason FROM replication_changes WHERE change_uuid=?`, events[0].ChangeUUID).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || reason != "foreign_key_dependency" {
		t.Fatalf("state=%s reason=%s", state, reason)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, events[1]); err != nil {
		t.Fatal(err)
	}
	if err = target.RetryReplicationDeferred(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = target.QueryRow(`SELECT count(*) FROM children WHERE id=? AND parent_id=?`, "child", "parent").Scan(&count); err != nil || count != 1 {
		_ = target.QueryRow(`SELECT apply_state,coalesce(quarantine_reason,?) FROM replication_changes WHERE change_uuid=?`, "", events[0].ChangeUUID).Scan(&state, &reason)
		var parents int
		_ = target.QueryRow(`SELECT count(*) FROM parents`).Scan(&parents)
		t.Fatalf("children=%d parents=%d state=%s reason=%s events=%s/%s err=%v", count, parents, state, reason, events[0].TableName, events[1].TableName, err)
	}
}

func TestReplicationMigrationRebuildsCaptureSchemaAndFencesNetworking(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migration.db")
	db, err := OpenSQLiteSeal(path, "key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err = db.InitializeReplication(ctx, LocalNodeConfig{NodeName: "migration", ReplicationDomain: "test", SchemaVersion: 1}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO items VALUES(?,?)`, "old", "before"); err != nil {
		t.Fatal(err)
	}
	migration := ReplicationMigration{
		FromVersion: 1,
		ToVersion:   2,
		Statements: []string{
			`ALTER TABLE items ADD COLUMN note TEXT`,
			`CREATE UNIQUE INDEX ux_items_name ON items(name)`,
		},
		Tables: []ReplicatedTable{{Name: "items", ConstraintPolicy: ReplicationConstraintsManaged}},
	}
	if err = db.ApplyReplicationMigration(ctx, migration); err != nil {
		t.Fatal(err)
	}
	status, err := db.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.SchemaVersion != 2 || status.NetworkEnabled {
		t.Fatalf("status=%+v", status)
	}
	if _, err = db.Exec(`INSERT INTO items VALUES(?,?,?)`, "new", "after", "captured"); err != nil {
		t.Fatal(err)
	}
	events, err := db.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(events) != 3 || events[0].OriginCounter != 1 || events[0].SchemaVersion != 1 || events[1].OriginCounter != 2 || events[1].Operation != "update" || events[1].ChangedFieldsJSON != `["note"]` || events[2].OriginCounter != 3 || events[2].SchemaVersion != 2 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenSQLiteSeal(path, "key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	status, err = db.ReplicationStatus(ctx)
	if err != nil || status.SchemaVersion != 2 || status.BlockedReason == "" {
		t.Fatalf("reopened status=%+v err=%v", status, err)
	}
}

func TestReplicationManagedUniqueLWWHandlesPartialCompoundAndCollation(t *testing.T) {
	ctx := context.Background()
	open := func(name, id string) *DB {
		db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), name+".db"), "key")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err = db.Exec(`CREATE TABLE accounts(id TEXT PRIMARY KEY,tenant TEXT,email TEXT COLLATE NOCASE,active INTEGER,UNIQUE(tenant,email)); CREATE UNIQUE INDEX ux_accounts_active_email ON accounts(email COLLATE NOCASE)
WHERE active=1`); err != nil {
			t.Fatal(err)
		}
		if err = db.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: id, NodeName: name, ReplicationDomain: "test"}, []ReplicatedTable{{Name: "accounts", ConstraintPolicy: ReplicationConstraintsManaged}}); err != nil {
			t.Fatal(err)
		}
		return db
	}
	leftID := "00000000-0000-4000-8000-000000000091"
	rightID := "00000000-0000-4000-8000-000000000092"
	left := open("index-left", leftID)
	right := open("index-right", rightID)
	if _, err := left.Exec(`INSERT INTO accounts VALUES(?,?,?,?)`, "partial-old", "left", "Alice@Example.com", 1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, err := right.Exec(`INSERT INTO accounts VALUES(?,?,?,?)`, "partial-new", "right", "alice@example.com", 1); err != nil {
		t.Fatal(err)
	}
	leftEvents, err := left.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	rightEvents, err := right.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = right.replication.applyRemoteEvent(ctx, leftID, leftEvents[0]); err != nil {
		t.Fatal(err)
	}
	if err = left.replication.applyRemoteEvent(ctx, rightID, rightEvents[0]); err != nil {
		t.Fatal(err)
	}
	for name, db := range map[string]*DB{"left": left, "right": right} {
		var id string
		if err = db.QueryRow(`SELECT id FROM accounts WHERE active=1 AND email=? COLLATE NOCASE`, "ALICE@example.com").Scan(&id); err != nil || id != "partial-new" {
			t.Fatalf("%s partial winner=%s err=%v", name, id, err)
		}
	}
	if _, err = left.Exec(`INSERT INTO accounts VALUES(?,?,?,?)`, "compound-old", "shared", "compound@example.com", 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, err = right.Exec(`INSERT INTO accounts VALUES(?,?,?,?)`, "compound-new", "shared", "COMPOUND@example.com", 0); err != nil {
		t.Fatal(err)
	}
	leftEvents, err = left.replication.loadOriginEvents(ctx, 1, 10)
	if err != nil || len(leftEvents) != 1 {
		t.Fatalf("left events=%d err=%v", len(leftEvents), err)
	}
	rightEvents, err = right.replication.loadOriginEvents(ctx, 1, 10)
	if err != nil || len(rightEvents) != 1 {
		t.Fatalf("right events=%d err=%v", len(rightEvents), err)
	}
	if err = right.replication.applyRemoteEvent(ctx, leftID, leftEvents[0]); err != nil {
		t.Fatal(err)
	}
	if err = left.replication.applyRemoteEvent(ctx, rightID, rightEvents[0]); err != nil {
		t.Fatal(err)
	}
	for name, db := range map[string]*DB{"left": left, "right": right} {
		var id string
		if err = db.QueryRow(`SELECT id FROM accounts WHERE tenant=? AND email=? COLLATE NOCASE`, "shared", "compound@example.com").Scan(&id); err != nil || id != "compound-new" {
			t.Fatalf("%s compound winner=%s err=%v", name, id, err)
		}
	}
}

func TestReplicationManagedUniqueLWWConvergesConflictingUpdates(t *testing.T) {
	ctx := context.Background()
	open := func(name, id string) *DB {
		db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), name+".db"), "key")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err = db.Exec(`CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT UNIQUE)`); err != nil {
			t.Fatal(err)
		}
		if err = db.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: id, NodeName: name, ReplicationDomain: "test"}, []ReplicatedTable{{Name: "users", ConstraintPolicy: ReplicationConstraintsManaged}}); err != nil {
			t.Fatal(err)
		}
		return db
	}
	leftID := "00000000-0000-4000-8000-000000000101"
	rightID := "00000000-0000-4000-8000-000000000102"
	left := open("update-left", leftID)
	right := open("update-right", rightID)
	if _, err := left.Exec(`INSERT INTO users VALUES(?,?),(?,?)`, "left-user", "left@example.com", "right-user", "right@example.com"); err != nil {
		t.Fatal(err)
	}
	baseline, err := left.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(baseline) != 2 {
		t.Fatalf("baseline=%d err=%v", len(baseline), err)
	}
	for _, event := range baseline {
		if err = right.replication.applyRemoteEvent(ctx, leftID, event); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = left.Exec(`UPDATE users SET email=? WHERE id=?`, "shared@example.com", "left-user"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, err = right.Exec(`UPDATE users SET email=? WHERE id=?`, "shared@example.com", "right-user"); err != nil {
		t.Fatal(err)
	}
	leftEvents, err := left.replication.loadOriginEvents(ctx, 2, 10)
	if err != nil || len(leftEvents) != 1 {
		t.Fatalf("left events=%d err=%v", len(leftEvents), err)
	}
	rightEvents, err := right.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(rightEvents) != 1 {
		t.Fatalf("right events=%d err=%v", len(rightEvents), err)
	}
	if err = right.replication.applyRemoteEvent(ctx, leftID, leftEvents[0]); err != nil {
		t.Fatal(err)
	}
	if err = left.replication.applyRemoteEvent(ctx, rightID, rightEvents[0]); err != nil {
		t.Fatal(err)
	}
	for name, db := range map[string]*DB{"left": left, "right": right} {
		var id string
		if err = db.QueryRow(`SELECT id FROM users WHERE email=?`, "shared@example.com").Scan(&id); err != nil || id != "right-user" {
			t.Fatalf("%s winner=%s err=%v", name, id, err)
		}
		var count int
		if err = db.QueryRow(`SELECT count(*) FROM users WHERE id=?`, "left-user").Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s loser count=%d err=%v", name, count, err)
		}
	}
}

func TestReplicationManagedRejectsExpressionUniqueIndex(t *testing.T) {
	db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), "expression-unique.db"), "key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT); CREATE UNIQUE INDEX ux_users_lower_email ON users(lower(email))`); err != nil {
		t.Fatal(err)
	}
	err = db.InitializeReplication(context.Background(), LocalNodeConfig{NodeName: "expression", ReplicationDomain: "test"}, []ReplicatedTable{{Name: "users", ConstraintPolicy: ReplicationConstraintsManaged}})
	if !errors.Is(err, ErrReplicationSchemaUnsupported) {
		t.Fatalf("got %v", err)
	}
}

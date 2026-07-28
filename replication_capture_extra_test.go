package sqliteseal

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
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

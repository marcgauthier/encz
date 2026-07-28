package sqliteseal

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReplicationGeneratedSchemaReopens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "reopen.db")
	db, e := OpenSQLiteSeal(p, "key")
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT,quantity INTEGER,note TEXT,updated_at TEXT)`)
	if e != nil {
		t.Fatal(e)
	}
	e = db.InitializeReplication(context.Background(), LocalNodeConfig{NodeName: "n", ReplicationDomain: "d"}, []ReplicatedTable{{Name: "items"}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`INSERT INTO items VALUES('a','b',1,'n','u')`)
	if e != nil {
		t.Fatal(e)
	}
	var sqlText string
	if e = db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'sqliteseal_%_insert'`).Scan(&sqlText); e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e = OpenSQLiteSeal(p, "key")
	if e != nil {
		t.Fatal(e)
	}
	_ = db.Close()
}

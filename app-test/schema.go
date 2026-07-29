package main

import (
	"fmt"
	"strings"
)

type tableSpec struct {
	Name   string
	Parent string
}

var schema = []tableSpec{
	{Name: "tenants"},
	{Name: "users", Parent: "tenants"},
	{Name: "profiles", Parent: "users"},
	{Name: "teams", Parent: "tenants"},
	{Name: "team_members", Parent: "teams"},
	{Name: "addresses", Parent: "users"},
	{Name: "categories", Parent: "tenants"},
	{Name: "suppliers", Parent: "tenants"},
	{Name: "products", Parent: "categories"},
	{Name: "warehouses", Parent: "tenants"},
	{Name: "inventory", Parent: "products"},
	{Name: "customers", Parent: "tenants"},
	{Name: "orders", Parent: "customers"},
	{Name: "order_items", Parent: "orders"},
	{Name: "payments", Parent: "orders"},
	{Name: "shipments", Parent: "orders"},
	{Name: "projects", Parent: "teams"},
	{Name: "tasks", Parent: "projects"},
	{Name: "task_assignments", Parent: "tasks"},
	{Name: "audit_events", Parent: "users"},
}

func schemaDDL() []string {
	ddl := []string{`PRAGMA foreign_keys=ON`}
	for _, spec := range schema {
		parentConstraint := ""
		if spec.Parent != "" {
			parentConstraint = fmt.Sprintf(", FOREIGN KEY(parent_id) REFERENCES %s(id) ON DELETE CASCADE", quoteIdent(spec.Parent))
		}
		ddl = append(ddl, fmt.Sprintf(`CREATE TABLE %s (
			id INTEGER PRIMARY KEY,
			parent_id INTEGER,
			generation INTEGER NOT NULL,
			code TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			status TEXT NOT NULL,
			quantity INTEGER NOT NULL,
			amount REAL NOT NULL,
			active INTEGER NOT NULL CHECK(active IN (0,1)),
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			note TEXT,
			payload BLOB NOT NULL
			%s
		)`, quoteIdent(spec.Name), parentConstraint))
		ddl = append(ddl,
			fmt.Sprintf(`CREATE INDEX %s ON %s(parent_id, status, id)`,
				quoteIdent("idx_"+spec.Name+"_parent_status"), quoteIdent(spec.Name)),
			fmt.Sprintf(`CREATE INDEX %s ON %s(active, amount, id)`,
				quoteIdent("idx_"+spec.Name+"_active_amount"), quoteIdent(spec.Name)),
		)
	}
	return ddl
}

func quoteIdent(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func tableByName(name string) (tableSpec, bool) {
	for _, spec := range schema {
		if spec.Name == name {
			return spec, true
		}
	}
	return tableSpec{}, false
}

const (
	rowColumns = `id,parent_id,generation,code,name,status,quantity,amount,active,created_at,updated_at,note,payload`
	rowMarkers = `?,?,?,?,?,?,?,?,?,?,?,?,?`
)

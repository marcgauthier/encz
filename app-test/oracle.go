package main

import (
	"fmt"
	"sort"
)

type oracle struct {
	tables map[string]map[int64]record
	nextID map[string]int64
}

func newOracle() *oracle {
	o := &oracle{
		tables: make(map[string]map[int64]record, len(schema)),
		nextID: make(map[string]int64, len(schema)),
	}
	for _, spec := range schema {
		o.tables[spec.Name] = make(map[int64]record)
		o.nextID[spec.Name] = 1
	}
	return o
}

func (o *oracle) allocateID(table string) int64 {
	id := o.nextID[table]
	o.nextID[table] = id + 1
	return id
}

func (o *oracle) add(table string, row record) {
	row.Payload = append([]byte(nil), row.Payload...)
	o.tables[table][row.ID] = row
	if o.nextID[table] <= row.ID {
		o.nextID[table] = row.ID + 1
	}
}

func (o *oracle) update(table string, row record) {
	o.add(table, row)
}

func (o *oracle) get(table string, id int64) (record, bool) {
	row, ok := o.tables[table][id]
	row.Payload = append([]byte(nil), row.Payload...)
	return row, ok
}

func (o *oracle) ids(table string) []int64 {
	ids := make([]int64, 0, len(o.tables[table]))
	for id := range o.tables[table] {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (o *oracle) rows(table string) []record {
	ids := o.ids(table)
	rows := make([]record, 0, len(ids))
	for _, id := range ids {
		row, _ := o.get(table, id)
		rows = append(rows, row)
	}
	return rows
}

func (o *oracle) count() int {
	total := 0
	for _, rows := range o.tables {
		total += len(rows)
	}
	return total
}

func (o *oracle) deleteCascade(table string, id int64) {
	delete(o.tables[table], id)
	for _, child := range schema {
		if child.Parent != table {
			continue
		}
		var victims []int64
		for childID, row := range o.tables[child.Name] {
			if row.ParentID.Valid && row.ParentID.Int64 == id {
				victims = append(victims, childID)
			}
		}
		for _, childID := range victims {
			o.deleteCascade(child.Name, childID)
		}
	}
}

func (o *oracle) trimVictims(maxRows int) map[string][]int64 {
	victims := make(map[string][]int64)
	// Delete children first. Parent cascades are then harmless if a parent also
	// falls outside its own rolling window.
	for i := len(schema) - 1; i >= 0; i-- {
		table := schema[i].Name
		ids := o.ids(table)
		if excess := len(ids) - maxRows; excess > 0 {
			victims[table] = append(victims[table], ids[:excess]...)
		}
	}
	return victims
}

func (o *oracle) applyVictims(victims map[string][]int64) {
	for i := len(schema) - 1; i >= 0; i-- {
		table := schema[i].Name
		for _, id := range victims[table] {
			o.deleteCascade(table, id)
		}
	}
}

type joinedRecord struct {
	Child  record
	Parent record
}

func (o *oracle) joinRows(childTable string, activeOnly bool, limit int) ([]joinedRecord, error) {
	spec, ok := tableByName(childTable)
	if !ok || spec.Parent == "" {
		return nil, fmt.Errorf("%s has no join parent", childTable)
	}
	out := make([]joinedRecord, 0)
	for _, child := range o.rows(childTable) {
		if activeOnly && !child.Active {
			continue
		}
		if !child.ParentID.Valid {
			continue
		}
		parent, ok := o.get(spec.Parent, child.ParentID.Int64)
		if !ok {
			return nil, fmt.Errorf("oracle missing %s parent %d for %s %d", spec.Parent, child.ParentID.Int64, childTable, child.ID)
		}
		out = append(out, joinedRecord{Child: child, Parent: parent})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Child.Amount == out[j].Child.Amount {
			return out[i].Child.ID < out[j].Child.ID
		}
		return out[i].Child.Amount > out[j].Child.Amount
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

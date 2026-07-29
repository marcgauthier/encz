package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"math"
	"time"
)

type record struct {
	ID         int64
	ParentID   sql.NullInt64
	Generation int64
	Code       string
	Name       string
	Status     string
	Quantity   int64
	Amount     float64
	Active     bool
	CreatedAt  string
	UpdatedAt  string
	Note       sql.NullString
	Payload    []byte
}

func (r record) values() []any {
	var parent, note any
	if r.ParentID.Valid {
		parent = r.ParentID.Int64
	}
	if r.Note.Valid {
		note = r.Note.String
	}
	return []any{
		r.ID, parent, r.Generation, r.Code, r.Name, r.Status, r.Quantity,
		r.Amount, boolInt(r.Active), r.CreatedAt, r.UpdatedAt, note, r.Payload,
	}
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(s rowScanner) (record, error) {
	var got record
	var active int64
	if err := s.Scan(
		&got.ID, &got.ParentID, &got.Generation, &got.Code, &got.Name,
		&got.Status, &got.Quantity, &got.Amount, &active, &got.CreatedAt,
		&got.UpdatedAt, &got.Note, &got.Payload,
	); err != nil {
		return record{}, err
	}
	got.Active = active != 0
	got.Payload = append([]byte(nil), got.Payload...)
	return got, nil
}

func compareRecord(expected, actual record) error {
	switch {
	case expected.ID != actual.ID:
		return fmt.Errorf("id: expected %d got %d", expected.ID, actual.ID)
	case expected.ParentID != actual.ParentID:
		return fmt.Errorf("parent_id: expected %v got %v", expected.ParentID, actual.ParentID)
	case expected.Generation != actual.Generation:
		return fmt.Errorf("generation: expected %d got %d", expected.Generation, actual.Generation)
	case expected.Code != actual.Code:
		return fmt.Errorf("code: expected %q got %q", expected.Code, actual.Code)
	case expected.Name != actual.Name:
		return fmt.Errorf("name: expected %q got %q", expected.Name, actual.Name)
	case expected.Status != actual.Status:
		return fmt.Errorf("status: expected %q got %q", expected.Status, actual.Status)
	case expected.Quantity != actual.Quantity:
		return fmt.Errorf("quantity: expected %d got %d", expected.Quantity, actual.Quantity)
	case math.Float64bits(expected.Amount) != math.Float64bits(actual.Amount):
		return fmt.Errorf("amount: expected %.17g got %.17g", expected.Amount, actual.Amount)
	case expected.Active != actual.Active:
		return fmt.Errorf("active: expected %t got %t", expected.Active, actual.Active)
	case expected.CreatedAt != actual.CreatedAt:
		return fmt.Errorf("created_at: expected %q got %q", expected.CreatedAt, actual.CreatedAt)
	case expected.UpdatedAt != actual.UpdatedAt:
		return fmt.Errorf("updated_at: expected %q got %q", expected.UpdatedAt, actual.UpdatedAt)
	case expected.Note != actual.Note:
		return fmt.Errorf("note: expected %v got %v", expected.Note, actual.Note)
	case !bytes.Equal(expected.Payload, actual.Payload):
		return fmt.Errorf("payload: expected %x got %x", expected.Payload, actual.Payload)
	default:
		return nil
	}
}

func makeRecord(table string, id, parentID, generation int64, now time.Time) record {
	statuses := [...]string{"new", "active", "paused", "complete"}
	stamp := now.UTC().Format(time.RFC3339Nano)
	r := record{
		ID:         id,
		Generation: generation,
		Code:       fmt.Sprintf("%s-%d-%d", table, generation, id),
		Name:       fmt.Sprintf("%s item %d", table, id),
		Status:     statuses[(id+generation)%int64(len(statuses))],
		Quantity:   (id*17 + generation) % 10000,
		Amount:     float64((id*7919+generation*101)%100000) / 100,
		Active:     id%3 != 0,
		CreatedAt:  stamp,
		UpdatedAt:  stamp,
		Payload:    []byte(fmt.Sprintf("\x00%s:%d:%d\xff", table, generation, id)),
	}
	if parentID > 0 {
		r.ParentID = sql.NullInt64{Int64: parentID, Valid: true}
	}
	if id%4 != 0 {
		r.Note = sql.NullString{String: fmt.Sprintf("note/%s/%d", table, id), Valid: true}
	}
	return r
}

func mutateRecord(r record, sequence int64, now time.Time) record {
	statuses := [...]string{"new", "active", "paused", "complete"}
	r.Name = fmt.Sprintf("%s updated %d", r.Name, sequence)
	r.Status = statuses[sequence%int64(len(statuses))]
	r.Quantity = (r.Quantity + sequence%97 + 1) % 10000
	r.Amount += float64(sequence%113+1) / 100
	r.Active = !r.Active
	r.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	if r.Note.Valid {
		r.Note = sql.NullString{}
	} else {
		r.Note = sql.NullString{String: fmt.Sprintf("updated-note-%d", sequence), Valid: true}
	}
	r.Payload = []byte(fmt.Sprintf("\x00update:%d:%d\xff", r.ID, sequence))
	return r
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

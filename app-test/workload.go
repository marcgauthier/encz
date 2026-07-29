package main

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

func (r *runner) insertOne(workerID int, rnd *rand.Rand) error {
	r.gate.Lock()
	defer r.gate.Unlock()
	spec := schema[rnd.Intn(len(schema))]
	id := r.oracle.allocateID(spec.Name)
	var parentID int64
	if spec.Parent != "" {
		ids := r.oracle.ids(spec.Parent)
		if len(ids) == 0 {
			return fmt.Errorf("insert table=%s: oracle parent %s is empty", spec.Name, spec.Parent)
		}
		parentID = ids[rnd.Intn(len(ids))]
	}
	seq := r.sequence.Add(1)
	row := makeRecord(spec.Name, id, parentID, seq, time.Now())
	var victim int64
	if ids := r.oracle.ids(spec.Name); len(ids) >= r.cfg.RowsPerTable {
		victim = ids[0]
	}

	err := retryBusy(r.ctx, func() error {
		tx, err := r.db.BeginTx(r.ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if victim != 0 {
			query := fmt.Sprintf("DELETE FROM %s WHERE id=?", quoteIdent(spec.Name))
			if _, err := tx.ExecContext(r.ctx, query, victim); err != nil {
				return err
			}
		}
		if err := insertRecord(r.ctx, tx, spec.Name, row); err != nil {
			return err
		}
		got, err := queryRecord(r.ctx, tx, spec.Name, id)
		if err != nil {
			return err
		}
		if err := compareRecord(row, got); err != nil {
			return fmt.Errorf("insert readback table=%s id=%d: %w", spec.Name, id, err)
		}
		return tx.Commit()
	})
	if err != nil {
		return fmt.Errorf("insert table=%s id=%d parent=%d: %w", spec.Name, id, parentID, err)
	}
	if victim != 0 {
		r.oracle.deleteCascade(spec.Name, victim)
		r.stats.retention.Add(1)
	}
	r.oracle.add(spec.Name, row)
	r.stats.lastOracleRows.Store(int64(r.oracle.count()))
	r.stats.inserts.Add(1)
	r.log.Info("op=insert worker=%d table=%s id=%d parent=%d", workerID, spec.Name, id, parentID)
	return nil
}

func (r *runner) updateOne(workerID int, rnd *rand.Rand) error {
	r.gate.Lock()
	defer r.gate.Unlock()
	spec := schema[rnd.Intn(len(schema))]
	ids := r.oracle.ids(spec.Name)
	if len(ids) == 0 {
		return nil
	}
	id := ids[rnd.Intn(len(ids))]
	expected, _ := r.oracle.get(spec.Name, id)
	updated := mutateRecord(expected, r.sequence.Add(1), time.Now())
	query := fmt.Sprintf(`UPDATE %s SET name=?,status=?,quantity=?,amount=?,active=?,updated_at=?,note=?,payload=? WHERE id=?`, quoteIdent(spec.Name))
	var note any
	if updated.Note.Valid {
		note = updated.Note.String
	}
	err := retryBusy(r.ctx, func() error {
		tx, err := r.db.BeginTx(r.ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		result, err := tx.ExecContext(r.ctx, query, updated.Name, updated.Status, updated.Quantity, updated.Amount, boolInt(updated.Active), updated.UpdatedAt, note, updated.Payload, id)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return fmt.Errorf("affected rows expected 1 got %d: %w", affected, err)
		}
		got, err := queryRecord(r.ctx, tx, spec.Name, id)
		if err != nil {
			return err
		}
		if err := compareRecord(updated, got); err != nil {
			return fmt.Errorf("update readback table=%s id=%d: %w", spec.Name, id, err)
		}
		return tx.Commit()
	})
	if err != nil {
		return fmt.Errorf("update table=%s id=%d: %w", spec.Name, id, err)
	}
	r.oracle.update(spec.Name, updated)
	r.stats.updates.Add(1)
	r.log.Info("op=update worker=%d table=%s id=%d", workerID, spec.Name, id)
	return nil
}

func (r *runner) selectOne(workerID int, rnd *rand.Rand) error {
	r.gate.RLock()
	defer r.gate.RUnlock()
	spec := schema[rnd.Intn(len(schema))]
	ids := r.oracle.ids(spec.Name)
	if len(ids) == 0 {
		return nil
	}
	if rnd.Intn(2) == 0 {
		id := ids[rnd.Intn(len(ids))]
		expected, _ := r.oracle.get(spec.Name, id)
		got, err := queryRecord(r.ctx, r.db.SQLDB(), spec.Name, id)
		if err != nil {
			return fmt.Errorf("point select table=%s id=%d: %w", spec.Name, id, err)
		}
		if err := compareRecord(expected, got); err != nil {
			return fmt.Errorf("point select mismatch table=%s id=%d: %w", spec.Name, id, err)
		}
	} else {
		sample, _ := r.oracle.get(spec.Name, ids[rnd.Intn(len(ids))])
		if err := r.validateList(spec.Name, sample.Status, sample.Active, 25); err != nil {
			return err
		}
	}
	r.stats.selects.Add(1)
	r.log.Info("op=select worker=%d table=%s", workerID, spec.Name)
	return nil
}

func (r *runner) validateList(table, status string, active bool, limit int) error {
	expected := make([]record, 0)
	for _, row := range r.oracle.rows(table) {
		if row.Status == status && row.Active == active {
			expected = append(expected, row)
		}
	}
	sort.Slice(expected, func(i, j int) bool {
		if expected[i].UpdatedAt == expected[j].UpdatedAt {
			return expected[i].ID < expected[j].ID
		}
		return expected[i].UpdatedAt > expected[j].UpdatedAt
	})
	if len(expected) > limit {
		expected = expected[:limit]
	}
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE status=? AND active=? ORDER BY updated_at DESC,id ASC LIMIT ?`, rowColumns, quoteIdent(table))
	rows, err := r.db.QueryContext(r.ctx, query, status, boolInt(active), limit)
	if err != nil {
		return fmt.Errorf("list select table=%s: %w", table, err)
	}
	defer rows.Close()
	actual := make([]record, 0)
	for rows.Next() {
		got, err := scanRecord(rows)
		if err != nil {
			return err
		}
		actual = append(actual, got)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(expected) != len(actual) {
		return fmt.Errorf("list mismatch table=%s status=%s active=%t: expected count %d got %d", table, status, active, len(expected), len(actual))
	}
	for i := range expected {
		if err := compareRecord(expected[i], actual[i]); err != nil {
			return fmt.Errorf("list mismatch table=%s index=%d expected_id=%d actual_id=%d: %w", table, i, expected[i].ID, actual[i].ID, err)
		}
	}
	return nil
}

func (r *runner) joinOne(workerID int, rnd *rand.Rand) error {
	r.gate.RLock()
	defer r.gate.RUnlock()
	candidates := schema[1:]
	spec := candidates[rnd.Intn(len(candidates))]
	activeOnly := rnd.Intn(2) == 0
	expected, err := r.oracle.joinRows(spec.Name, activeOnly, 30)
	if err != nil {
		return err
	}
	where := ""
	args := []any{30}
	if activeOnly {
		where = " WHERE c.active=1"
	}
	query := fmt.Sprintf(`SELECT c.%s,p.%s FROM %s c JOIN %s p ON p.id=c.parent_id%s ORDER BY c.amount DESC,c.id ASC LIMIT ?`,
		strings.ReplaceAll(rowColumns, ",", ",c."),
		strings.ReplaceAll(rowColumns, ",", ",p."),
		quoteIdent(spec.Name), quoteIdent(spec.Parent), where)
	rows, err := r.db.QueryContext(r.ctx, query, args...)
	if err != nil {
		return fmt.Errorf("join %s->%s: %w", spec.Name, spec.Parent, err)
	}
	defer rows.Close()
	var actual []joinedRecord
	for rows.Next() {
		pair, err := scanJoined(rows)
		if err != nil {
			return err
		}
		actual = append(actual, pair)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(expected) != len(actual) {
		return fmt.Errorf("join mismatch %s->%s: expected count %d got %d", spec.Name, spec.Parent, len(expected), len(actual))
	}
	for i := range expected {
		if err := compareRecord(expected[i].Child, actual[i].Child); err != nil {
			return fmt.Errorf("join child mismatch table=%s index=%d: %w", spec.Name, i, err)
		}
		if err := compareRecord(expected[i].Parent, actual[i].Parent); err != nil {
			return fmt.Errorf("join parent mismatch table=%s index=%d: %w", spec.Parent, i, err)
		}
	}
	r.stats.joins.Add(1)
	r.log.Info("op=join worker=%d child=%s parent=%s rows=%d", workerID, spec.Name, spec.Parent, len(actual))
	return nil
}

func queryRecord(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, table string, id int64) (record, error) {
	query := fmt.Sprintf("SELECT %s FROM %s WHERE id=?", rowColumns, quoteIdent(table))
	return scanRecord(q.QueryRowContext(ctx, query, id))
}

func scanJoined(rows *sql.Rows) (joinedRecord, error) {
	var child, parent record
	var childActive, parentActive int64
	err := rows.Scan(
		&child.ID, &child.ParentID, &child.Generation, &child.Code, &child.Name, &child.Status, &child.Quantity, &child.Amount, &childActive, &child.CreatedAt, &child.UpdatedAt, &child.Note, &child.Payload,
		&parent.ID, &parent.ParentID, &parent.Generation, &parent.Code, &parent.Name, &parent.Status, &parent.Quantity, &parent.Amount, &parentActive, &parent.CreatedAt, &parent.UpdatedAt, &parent.Note, &parent.Payload,
	)
	if err != nil {
		return joinedRecord{}, err
	}
	child.Active, parent.Active = childActive != 0, parentActive != 0
	child.Payload = append([]byte(nil), child.Payload...)
	parent.Payload = append([]byte(nil), parent.Payload...)
	return joinedRecord{Child: child, Parent: parent}, nil
}

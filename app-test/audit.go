package main

import (
	"context"
	"database/sql"
	"fmt"
)

func (r *runner) fullAudit(ctx context.Context, db *sql.DB) error {
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("integrity_check: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("integrity_check returned %q", integrity)
	}
	for _, spec := range schema {
		query := fmt.Sprintf("SELECT %s FROM %s ORDER BY id", rowColumns, quoteIdent(spec.Name))
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			return fmt.Errorf("audit query table=%s: %w", spec.Name, err)
		}
		actual := make([]record, 0)
		for rows.Next() {
			row, scanErr := scanRecord(rows)
			if scanErr != nil {
				rows.Close()
				return fmt.Errorf("audit scan table=%s: %w", spec.Name, scanErr)
			}
			actual = append(actual, row)
		}
		iterErr := rows.Err()
		rows.Close()
		if iterErr != nil {
			return fmt.Errorf("audit rows table=%s: %w", spec.Name, iterErr)
		}
		expected := r.oracle.rows(spec.Name)
		if len(expected) != len(actual) {
			return fmt.Errorf("audit table=%s count mismatch expected=%d actual=%d", spec.Name, len(expected), len(actual))
		}
		for i := range expected {
			if err := compareRecord(expected[i], actual[i]); err != nil {
				return fmt.Errorf("audit table=%s index=%d id=%d: %w", spec.Name, i, expected[i].ID, err)
			}
		}
	}

	// Exercise each relationship with independently generated expected rows.
	for _, spec := range schema {
		if spec.Parent == "" {
			continue
		}
		expected, err := r.oracle.joinRows(spec.Name, false, 100_000)
		if err != nil {
			return err
		}
		query := fmt.Sprintf(`SELECT c.id,p.id FROM %s c JOIN %s p ON p.id=c.parent_id ORDER BY c.amount DESC,c.id ASC`,
			quoteIdent(spec.Name), quoteIdent(spec.Parent))
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			return fmt.Errorf("audit join %s->%s: %w", spec.Name, spec.Parent, err)
		}
		index := 0
		for rows.Next() {
			var childID, parentID int64
			if err := rows.Scan(&childID, &parentID); err != nil {
				rows.Close()
				return err
			}
			if index >= len(expected) || expected[index].Child.ID != childID || expected[index].Parent.ID != parentID {
				rows.Close()
				return fmt.Errorf("audit join %s index=%d expected=%v actual=(%d,%d)", spec.Name, index, joinIDs(expected, index), childID, parentID)
			}
			index++
		}
		iterErr := rows.Err()
		rows.Close()
		if iterErr != nil {
			return iterErr
		}
		if index != len(expected) {
			return fmt.Errorf("audit join %s count mismatch expected=%d actual=%d", spec.Name, len(expected), index)
		}
	}
	return nil
}

func joinIDs(rows []joinedRecord, index int) any {
	if index >= len(rows) {
		return "<no row>"
	}
	return fmt.Sprintf("(%d,%d)", rows[index].Child.ID, rows[index].Parent.ID)
}

package sqliteseal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func insertRemoteWireRow(ctx context.Context, tx *sql.Tx, descriptor replicationTableDescriptor, event wireEvent) error {
	columns := make([]string, 0, len(descriptor.Table.Columns))
	markers := make([]string, 0, len(descriptor.Table.Columns))
	values := make([]any, 0, len(descriptor.Table.Columns))
	key, keyValues, err := wireKey(descriptor, event)
	if err != nil {
		return err
	}
	for i, name := range descriptor.Table.PrimaryKeyColumns {
		columns = append(columns, quoteReplicationIdent(name))
		markers = append(markers, "?")
		values = append(values, keyValues[i])
	}
	_ = key
	for _, column := range descriptor.Table.Columns {
		isKey := false
		for _, keyName := range descriptor.Table.PrimaryKeyColumns {
			if keyName == column {
				isKey = true
				break
			}
		}
		if isKey {
			continue
		}
		wire, ok := event.Values[column]
		if !ok || !wire.Present {
			continue
		}
		value, err := decodeWireValue(wire)
		if err != nil {
			return err
		}
		columns = append(columns, quoteReplicationIdent(column))
		markers = append(markers, "?")
		values = append(values, value)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO `+quoteReplicationIdent(event.TableName)+`(`+
		strings.Join(columns, ",")+`) VALUES(`+strings.Join(markers, ",")+`)`, values...)
	return err
}

func isReplicationConstraint(err error) bool {
	var sqliteErr sqlite3.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrConstraint
}

func replicationConstraintReason(err error) string {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return ""
	}
	switch sqliteErr.ExtendedCode {
	case sqlite3.ErrConstraintForeignKey:
		return "foreign_key_dependency"
	case sqlite3.ErrConstraintUnique, sqlite3.ErrConstraintPrimaryKey:
		return "unique_conflict"
	default:
		return ""
	}
}

type replicationConflictingRow struct {
	rowKeyJSON string
	keyArgs    []any
}

type replicationWinnerVersion struct {
	physical, logical             int64
	origin, changeUUID, changedAt string
}

func materializeManagedUniqueLWW(ctx context.Context, tx *sql.Tx, local string, d replicationTableDescriptor, e wireEvent, now string, constraintErr error) (bool, error) {
	if replicationConstraintReason(constraintErr) != "unique_conflict" {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO sqliteseal_materialize`); err != nil {
		return true, err
	}
	if _, err := tx.ExecContext(ctx, `RELEASE sqliteseal_materialize`); err != nil {
		return true, err
	}
	candidate, winningFields, exists, err := managedUniqueCandidate(ctx, tx, d, e)
	if err != nil {
		return true, err
	}
	conflicts, err := managedUniqueConflictingRows(ctx, tx, d, e.RowKeyJSON, candidate)
	if err != nil {
		return true, err
	}
	if len(conflicts) == 0 {
		return true, fmt.Errorf("replication: unique constraint could not be mapped to a supported index: %w", constraintErr)
	}
	incomingWins := true
	var owner replicationWinnerVersion
	for _, conflict := range conflicts {
		var physical, logical int64
		var origin, changeUUID, changedAt string
		err = tx.QueryRowContext(ctx, `SELECT winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid,winner_change_uuid,winner_changed_at_utc FROM replication_row_versions WHERE table_name=? AND row_key_json=?`, e.TableName, conflict.rowKeyJSON).Scan(&physical, &logical, &origin, &changeUUID, &changedAt)
		if err == sql.ErrNoRows {
			return true, fmt.Errorf("%w: unique owner %s has no replication version", ErrReplicationNotReady, conflict.rowKeyJSON)
		}
		if err != nil {
			return true, err
		}
		if compareReplicationVersion(owner.physical, owner.logical, owner.origin, physical, logical, origin) < 0 {
			owner = replicationWinnerVersion{physical: physical, logical: logical, origin: origin, changeUUID: changeUUID, changedAt: changedAt}
		}
		if compareReplicationVersion(e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, physical, logical, origin) <= 0 {
			incomingWins = false
		}
	}
	if !incomingWins {
		return true, finishManagedUniqueLoser(ctx, tx, local, d, e, now, owner)
	}
	if _, err = tx.ExecContext(ctx, `SAVEPOINT sqliteseal_unique_lww`); err != nil {
		return true, err
	}
	where := make([]string, len(d.Table.PrimaryKeyColumns))
	for i, column := range d.Table.PrimaryKeyColumns {
		where[i] = quoteReplicationIdent(column) + "=?"
	}
	for _, conflict := range conflicts {
		if _, err = tx.ExecContext(ctx, `DELETE FROM `+quoteReplicationIdent(e.TableName)+` WHERE `+strings.Join(where, " AND "), conflict.keyArgs...); err != nil {
			_ = rollbackReplicationSavepoint(ctx, tx, "sqliteseal_unique_lww")
			if replicationConstraintReason(err) == "foreign_key_dependency" {
				if _, updateErr := tx.ExecContext(ctx, `UPDATE replication_changes SET apply_state=?,quarantine_reason=? WHERE change_uuid=?`, "pending", "foreign_key_dependency", e.ChangeUUID); updateErr != nil {
					return true, updateErr
				}
				if cursorErr := advanceRemoteCursor(ctx, tx, local, e.OriginNodeUUID, e.OriginCounter, now); cursorErr != nil {
					return true, cursorErr
				}
				return true, tx.Commit()
			}
			return true, err
		}
	}
	if exists {
		sets := make([]string, 0, len(d.Table.Columns))
		args := make([]any, 0, len(d.Table.Columns)+len(d.Table.PrimaryKeyColumns))
		primary := make(map[string]bool, len(d.Table.PrimaryKeyColumns))
		for _, column := range d.Table.PrimaryKeyColumns {
			primary[column] = true
		}
		for _, column := range d.Table.Columns {
			if primary[column] {
				continue
			}
			sets = append(sets, quoteReplicationIdent(column)+"=?")
			args = append(args, candidate[column])
		}
		_, keyArgs, keyErr := wireKey(d, e)
		if keyErr != nil {
			return true, keyErr
		}
		args = append(args, keyArgs...)
		if _, err = tx.ExecContext(ctx, `UPDATE `+quoteReplicationIdent(e.TableName)+` SET `+strings.Join(sets, ",")+` WHERE `+strings.Join(where, " AND "), args...); err != nil {
			return true, err
		}
	} else {
		columns := make([]string, 0, len(d.Table.Columns))
		markers := make([]string, 0, len(d.Table.Columns))
		args := make([]any, 0, len(d.Table.Columns))
		for _, column := range d.Table.Columns {
			columns = append(columns, quoteReplicationIdent(column))
			markers = append(markers, "?")
			args = append(args, candidate[column])
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO `+quoteReplicationIdent(e.TableName)+`(`+strings.Join(columns, ",")+`) VALUES(`+strings.Join(markers, ",")+`)`, args...); err != nil {
			return true, err
		}
	}
	if _, err = tx.ExecContext(ctx, `RELEASE sqliteseal_unique_lww`); err != nil {
		return true, err
	}
	return true, finishManagedUniqueEvent(ctx, tx, local, d, e, now, true, winningFields, conflicts)
}

func finishManagedUniqueLoser(ctx context.Context, tx *sql.Tx, local string, d replicationTableDescriptor, e wireEvent, now string, owner replicationWinnerVersion) error {
	_, keyArgs, err := wireKey(d, e)
	if err != nil {
		return err
	}
	where := make([]string, len(d.Table.PrimaryKeyColumns))
	for i, column := range d.Table.PrimaryKeyColumns {
		where[i] = quoteReplicationIdent(column) + "=?"
	}
	if _, err = tx.ExecContext(ctx, `SAVEPOINT sqliteseal_unique_loser`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM `+quoteReplicationIdent(e.TableName)+` WHERE `+strings.Join(where, " AND "), keyArgs...); err != nil {
		_ = rollbackReplicationSavepoint(ctx, tx, "sqliteseal_unique_loser")
		if replicationConstraintReason(err) == "foreign_key_dependency" {
			if _, updateErr := tx.ExecContext(ctx, `UPDATE replication_changes SET apply_state=?,quarantine_reason=? WHERE change_uuid=?`, "pending", "foreign_key_dependency", e.ChangeUUID); updateErr != nil {
				return updateErr
			}
			if cursorErr := advanceRemoteCursor(ctx, tx, local, e.OriginNodeUUID, e.OriginCounter, now); cursorErr != nil {
				return cursorErr
			}
			return tx.Commit()
		}
		return err
	}
	if _, err = tx.ExecContext(ctx, `RELEASE sqliteseal_unique_loser`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO replication_row_versions VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(table_name,row_key_json) DO UPDATE SET row_state=excluded.row_state,winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,winner_hlc_logical=excluded.winner_hlc_logical,winner_origin_node_uuid=excluded.winner_origin_node_uuid,winner_change_uuid=excluded.winner_change_uuid,winner_changed_at_utc=excluded.winner_changed_at_utc,updated_at_utc=excluded.updated_at_utc`, e.TableName, e.RowKeyJSON, "unique_deleted", owner.physical, owner.logical, owner.origin, owner.changeUUID, owner.changedAt, now); err != nil {
		return err
	}
	return finishManagedUniqueEvent(ctx, tx, local, d, e, now, false, nil, nil)
}

func rollbackReplicationSavepoint(ctx context.Context, tx *sql.Tx, name string) error {
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO `+quoteReplicationIdent(name)); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `RELEASE `+quoteReplicationIdent(name))
	return err
}

func managedUniqueCandidate(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor, e wireEvent) (map[string]any, []string, bool, error) {
	_, keyArgs, err := wireKey(d, e)
	if err != nil {
		return nil, nil, false, err
	}
	where := make([]string, len(d.Table.PrimaryKeyColumns))
	for i, column := range d.Table.PrimaryKeyColumns {
		where[i] = quoteReplicationIdent(column) + "=?"
	}
	selectColumns := make([]string, len(d.Table.Columns))
	for i, column := range d.Table.Columns {
		selectColumns[i] = quoteReplicationIdent(column)
	}
	values := make([]any, len(d.Table.Columns))
	pointers := make([]any, len(values))
	for i := range values {
		pointers[i] = &values[i]
	}
	err = tx.QueryRowContext(ctx, `SELECT `+strings.Join(selectColumns, ",")+` FROM `+quoteReplicationIdent(e.TableName)+` WHERE `+strings.Join(where, " AND "), keyArgs...).Scan(pointers...)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return nil, nil, false, err
	}
	candidate := make(map[string]any, len(d.Table.Columns))
	if exists {
		for i, column := range d.Table.Columns {
			candidate[column] = values[i]
		}
	} else {
		for _, column := range d.Table.Columns {
			value, decodeErr := decodeWireValue(e.Values[column])
			if decodeErr != nil {
				return nil, nil, false, decodeErr
			}
			candidate[column] = value
		}
	}
	winning := make([]string, 0, len(d.Table.Columns))
	for _, column := range d.Table.Columns {
		wire := e.Values[column]
		if !wire.Present {
			continue
		}
		var physical, logical int64
		var origin string
		versionErr := tx.QueryRowContext(ctx, `SELECT winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid FROM replication_field_versions WHERE table_name=? AND row_key_json=? AND field_name=?`, e.TableName, e.RowKeyJSON, column).Scan(&physical, &logical, &origin)
		if versionErr != nil && versionErr != sql.ErrNoRows {
			return nil, nil, false, versionErr
		}
		if versionErr == nil && compareReplicationVersion(e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, physical, logical, origin) <= 0 {
			continue
		}
		value, decodeErr := decodeWireValue(wire)
		if decodeErr != nil {
			return nil, nil, false, decodeErr
		}
		candidate[column] = value
		winning = append(winning, column)
	}
	return candidate, winning, exists, nil
}

func managedUniqueConflictingRows(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor, incomingKey string, candidate map[string]any) ([]replicationConflictingRow, error) {
	found := map[string]replicationConflictingRow{}
	for _, index := range d.Indexes {
		if index.Unique != 1 || index.Origin == "pk" {
			continue
		}
		keyColumns := make([]replicationIndexColumn, 0, len(index.Columns))
		supported := true
		for _, column := range index.Columns {
			if column.Key != 1 {
				continue
			}
			if column.ColumnID < 0 || column.Name == "" {
				supported = false
				break
			}
			keyColumns = append(keyColumns, column)
		}
		if !supported || len(keyColumns) == 0 {
			continue
		}
		qualifies, err := managedPartialIndexCandidate(ctx, tx, d, index, candidate)
		if err != nil {
			return nil, err
		}
		if !qualifies {
			continue
		}
		conditions := make([]string, 0, len(keyColumns)+1)
		args := make([]any, 0, len(keyColumns))
		skip := false
		for _, column := range keyColumns {
			value := candidate[column.Name]
			if value == nil {
				skip = true
				break
			}
			condition := quoteReplicationIdent(column.Name) + "=?"
			if column.Collation != "" && column.Collation != "BINARY" {
				condition += " COLLATE " + quoteReplicationIdent(column.Collation)
			}
			conditions = append(conditions, condition)
			args = append(args, value)
		}
		if skip {
			continue
		}
		if predicate := replicationPartialIndexPredicate(index.SQL); predicate != "" {
			conditions = append(conditions, "("+predicate+")")
		}
		pkColumns := make([]string, len(d.Table.PrimaryKeyColumns))
		for i, column := range d.Table.PrimaryKeyColumns {
			pkColumns[i] = quoteReplicationIdent(column)
		}
		rows, err := tx.QueryContext(ctx, `SELECT `+strings.Join(pkColumns, ",")+` FROM `+quoteReplicationIdent(d.Table.Name)+` WHERE `+strings.Join(conditions, " AND "), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			keyValues := make([]any, len(d.Table.PrimaryKeyColumns))
			pointers := make([]any, len(keyValues))
			for i := range keyValues {
				pointers[i] = &keyValues[i]
			}
			if err = rows.Scan(pointers...); err != nil {
				rows.Close()
				return nil, err
			}
			canonicalArgs := make([]any, 0, len(keyValues)*2)
			for i, column := range d.Table.PrimaryKeyColumns {
				canonicalArgs = append(canonicalArgs, column, keyValues[i])
			}
			rowKey, keyErr := canonicalRowKeySQL(canonicalArgs...)
			if keyErr != nil {
				rows.Close()
				return nil, keyErr
			}
			if rowKey != incomingKey {
				found[rowKey] = replicationConflictingRow{rowKeyJSON: rowKey, keyArgs: keyValues}
			}
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
	}
	out := make([]replicationConflictingRow, 0, len(found))
	for _, conflict := range found {
		out = append(out, conflict)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rowKeyJSON < out[j].rowKeyJSON })
	return out, nil
}

func managedPartialIndexCandidate(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor, index replicationIndex, candidate map[string]any) (bool, error) {
	predicate := replicationPartialIndexPredicate(index.SQL)
	if predicate == "" {
		return true, nil
	}
	columns := make([]string, 0, len(d.Table.Columns))
	args := make([]any, 0, len(d.Table.Columns))
	for _, column := range d.Table.Columns {
		columns = append(columns, "? AS "+quoteReplicationIdent(column))
		args = append(args, candidate[column])
	}
	var qualifies int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT `+strings.Join(columns, ",")+`) AS `+quoteReplicationIdent(d.Table.Name)+` WHERE `+predicate, args...).Scan(&qualifies)
	return qualifies != 0, err
}

func replicationPartialIndexPredicate(statement string) string {
	depth := 0
	var quote byte
	for i := 0; i < len(statement); i++ {
		character := statement[i]
		if quote != 0 {
			if quote == ']' {
				if character == ']' {
					quote = 0
				}
				continue
			}
			if character == quote {
				if i+1 < len(statement) && statement[i+1] == quote {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch character {
		case '\'', '"', '`':
			quote = character
		case '[':
			quote = ']'
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && i+5 <= len(statement) && strings.EqualFold(statement[i:i+5], "WHERE") {
				leftBoundary := i == 0 || statement[i-1] == ' ' || statement[i-1] == '\t' || statement[i-1] == '\n' || statement[i-1] == '\r'
				rightBoundary := i+5 == len(statement) || statement[i+5] == ' ' || statement[i+5] == '\t' || statement[i+5] == '\n' || statement[i+5] == '\r'
				if leftBoundary && rightBoundary {
					return strings.TrimSpace(statement[i+5:])
				}
			}
		}
	}
	return ""
}

func finishManagedUniqueEvent(ctx context.Context, tx *sql.Tx, local string, d replicationTableDescriptor, e wireEvent, now string, applied bool, winningFields []string, conflicts []replicationConflictingRow) error {
	for _, field := range winningFields {
		if _, err := tx.ExecContext(ctx, `INSERT INTO replication_field_versions VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(table_name,row_key_json,field_name) DO UPDATE SET winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,winner_hlc_logical=excluded.winner_hlc_logical,winner_origin_node_uuid=excluded.winner_origin_node_uuid,winner_change_uuid=excluded.winner_change_uuid,winner_changed_at_utc=excluded.winner_changed_at_utc,updated_at_utc=excluded.updated_at_utc`, e.TableName, e.RowKeyJSON, field, e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, e.ChangeUUID, e.CreatedAtUTC, nil, now); err != nil {
			return err
		}
	}
	if applied {
		if _, err := tx.ExecContext(ctx, `INSERT INTO replication_row_versions VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(table_name,row_key_json) DO UPDATE SET row_state=excluded.row_state,winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,winner_hlc_logical=excluded.winner_hlc_logical,winner_origin_node_uuid=excluded.winner_origin_node_uuid,winner_change_uuid=excluded.winner_change_uuid,winner_changed_at_utc=excluded.winner_changed_at_utc,updated_at_utc=excluded.updated_at_utc`, e.TableName, e.RowKeyJSON, "live", e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, e.ChangeUUID, e.CreatedAtUTC, now); err != nil {
			return err
		}
		for _, conflict := range conflicts {
			if _, err := tx.ExecContext(ctx, `INSERT INTO replication_row_versions VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(table_name,row_key_json) DO UPDATE SET row_state=excluded.row_state,winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,winner_hlc_logical=excluded.winner_hlc_logical,winner_origin_node_uuid=excluded.winner_origin_node_uuid,winner_change_uuid=excluded.winner_change_uuid,winner_changed_at_utc=excluded.winner_changed_at_utc,updated_at_utc=excluded.updated_at_utc`, e.TableName, conflict.rowKeyJSON, "unique_deleted", e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, e.ChangeUUID, e.CreatedAtUTC, now); err != nil {
				return err
			}
		}
	}
	state := "ignored"
	if applied {
		state = "applied"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE replication_changes SET apply_state=?,quarantine_reason=NULL WHERE change_uuid=?`, state, e.ChangeUUID); err != nil {
		return err
	}
	if err := mergeRemoteHLC(ctx, tx, e.HLCPhysicalUS, e.HLCLogical, time.Now().UTC().UnixMicro(), now); err != nil {
		return err
	}
	if err := advanceRemoteCursor(ctx, tx, local, e.OriginNodeUUID, e.OriginCounter, now); err != nil {
		return err
	}
	return tx.Commit()
}

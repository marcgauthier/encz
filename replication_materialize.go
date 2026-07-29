package sqliteseal

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func insertRemoteWireRow(ctx context.Context, tx *sql.Tx, descriptor replicationTableDescriptor, event wireEvent) error {
	columns := make([]string, 0, len(descriptor.Table.Columns))
	markers := make([]string, 0, len(descriptor.Table.Columns))
	values := make([]any, 0, len(descriptor.Table.Columns))
	for _, column := range descriptor.Table.Columns {
		value, err := decodeWireValue(event.Values[column])
		if err != nil {
			return err
		}
		columns = append(columns, quoteReplicationIdent(column))
		markers = append(markers, "?")
		values = append(values, value)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO `+quoteReplicationIdent(event.TableName)+`(`+
		strings.Join(columns, ",")+`) VALUES(`+strings.Join(markers, ",")+`)`, values...)
	return err
}

func isReplicationConstraint(err error) bool {
	var sqliteErr sqlite3.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrConstraint
}

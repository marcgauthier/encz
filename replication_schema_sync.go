package sqliteseal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"unicode"
)

type wireSchemaDeclaration struct {
	OriginNodeUUID string                      `json:"origin_node_uuid"`
	OriginLevel    int                         `json:"origin_level"`
	SchemaRevision int64                       `json:"schema_revision"`
	Table          ReplicatedTable             `json:"table"`
	Descriptor     *replicationTableDescriptor `json:"descriptor,omitempty"`
}

type schemaDeclaration struct {
	wireSchemaDeclaration
	active bool
}

func replicatedDescriptorProjection(descriptor replicationTableDescriptor) replicationTableDescriptor {
	selected := make(map[string]bool, len(descriptor.Table.Columns)+len(descriptor.Table.PrimaryKeyColumns))
	for _, name := range descriptor.Table.Columns {
		selected[name] = true
	}
	for _, name := range descriptor.Table.PrimaryKeyColumns {
		selected[name] = true
	}
	columns := make([]replicationColumn, 0, len(selected))
	for _, column := range descriptor.Columns {
		if selected[column.Name] {
			columns = append(columns, column)
		}
	}
	descriptor.Columns = columns
	descriptor.ForeignKeys = nil
	descriptor.Indexes = nil
	descriptor.Triggers = nil
	descriptor.TableSQL = ""
	raw, _ := json.Marshal(descriptor)
	sum := sha256Bytes(raw)
	descriptor.DescriptorID = fmt.Sprintf("%x", sum[:8])
	return descriptor
}

func initializeSchemaDeclarations(ctx context.Context, tx *sql.Tx, node string, revision int64, tables []ReplicatedTable, descriptors []replicationTableDescriptor) error {
	byName := make(map[string]replicationTableDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		byName[descriptor.Table.Name] = descriptor
	}
	now := "sqliteseal_utc_now()"
	for _, table := range tables {
		tableJSON, err := json.Marshal(table)
		if err != nil {
			return err
		}
		var descriptorJSON any
		if descriptor, ok := byName[table.Name]; ok {
			descriptor = replicatedDescriptorProjection(descriptor)
			raw, marshalErr := json.Marshal(descriptor)
			if marshalErr != nil {
				return marshalErr
			}
			descriptorJSON = string(raw)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_schema_declarations(origin_node_uuid,schema_revision,table_name,table_json,descriptor_json,updated_at_utc) VALUES(?,?,?,?,?,`+now+`)`, node, revision, table.Name, string(tableJSON), descriptorJSON); err != nil {
			return err
		}
	}
	return nil
}

func (r *replicationRuntime) seedSchemaDeclarations(ctx context.Context) error {
	var count int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM replication_schema_declarations`).Scan(&count); err != nil || count != 0 {
		return err
	}
	var node string
	var revision int64
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid,schema_revision FROM replication_local_state`).Scan(&node, &revision); err != nil {
		return err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT descriptor_json FROM replication_table_descriptors ORDER BY table_name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var descriptors []replicationTableDescriptor
	var tables []ReplicatedTable
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		var descriptor replicationTableDescriptor
		if err = json.Unmarshal([]byte(raw), &descriptor); err != nil {
			return err
		}
		descriptors = append(descriptors, descriptor)
		tables = append(tables, descriptor.Table)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = initializeSchemaDeclarations(ctx, tx, node, revision, tables, descriptors); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *replicationRuntime) loadSchemaDeclarations(ctx context.Context) ([]wireSchemaDeclaration, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT d.origin_node_uuid,n.node_level,d.schema_revision,d.table_json,d.descriptor_json FROM replication_schema_declarations d JOIN replication_nodes n ON n.node_uuid=d.origin_node_uuid WHERE n.membership_state!='retired' ORDER BY d.origin_node_uuid,d.table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var declarations []wireSchemaDeclaration
	for rows.Next() {
		var declaration wireSchemaDeclaration
		var tableRaw string
		var descriptorRaw sql.NullString
		if err = rows.Scan(&declaration.OriginNodeUUID, &declaration.OriginLevel, &declaration.SchemaRevision, &tableRaw, &descriptorRaw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(tableRaw), &declaration.Table); err != nil {
			return nil, err
		}
		if descriptorRaw.Valid {
			var descriptor replicationTableDescriptor
			if err = json.Unmarshal([]byte(descriptorRaw.String), &descriptor); err != nil {
				return nil, err
			}
			declaration.Descriptor = &descriptor
		}
		declarations = append(declarations, declaration)
	}
	return declarations, rows.Err()
}

func (r *replicationRuntime) mergeSchemaDeclarations(ctx context.Context, declarations []wireSchemaDeclaration) error {
	if len(declarations) > 4096 {
		return errors.New("replication: schema declaration limit exceeded")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, declaration := range declarations {
		if !isCanonicalUUID(declaration.OriginNodeUUID) || declaration.OriginLevel < 0 || declaration.SchemaRevision <= 0 || declaration.Table.Name == "" || strings.HasPrefix(declaration.Table.Name, "replication_") {
			return errors.New("replication: invalid schema declaration")
		}
		var level int
		var state string
		var existingRevision int64
		var existingTable string
		var existingDescriptor sql.NullString
		if err = tx.QueryRowContext(ctx, `SELECT node_level,membership_state FROM replication_nodes WHERE node_uuid=?`, declaration.OriginNodeUUID).Scan(&level, &state); err != nil {
			return errors.New("replication: schema declaration origin is not a member")
		}
		if level != declaration.OriginLevel || state == "retired" {
			return errors.New("replication: schema declaration authority mismatch")
		}
		if declaration.Descriptor != nil {
			if declaration.Descriptor.Table.Name != declaration.Table.Name {
				return errors.New("replication: schema declaration table mismatch")
			}
			for _, column := range declaration.Descriptor.Columns {
				if _, normalizeErr := normalizeReplicationDeclaredType(column.DeclaredType); normalizeErr != nil {
					return normalizeErr
				}
			}
		}
		tableRaw, _ := json.Marshal(declaration.Table)
		var descriptorRaw any
		if declaration.Descriptor != nil {
			raw, marshalErr := json.Marshal(declaration.Descriptor)
			if marshalErr != nil {
				return marshalErr
			}
			descriptorRaw = string(raw)
		}
		existingErr := tx.QueryRowContext(ctx, `SELECT schema_revision,table_json,descriptor_json FROM replication_schema_declarations WHERE origin_node_uuid=? AND table_name=?`, declaration.OriginNodeUUID, declaration.Table.Name).Scan(&existingRevision, &existingTable, &existingDescriptor)
		if existingErr != nil && existingErr != sql.ErrNoRows {
			return existingErr
		}
		if existingErr == nil && existingRevision == declaration.SchemaRevision {
			incomingDescriptor, _ := descriptorRaw.(string)
			if existingTable != string(tableRaw) || existingDescriptor.Valid != (descriptorRaw != nil) || existingDescriptor.Valid && existingDescriptor.String != incomingDescriptor {
				return errors.New("replication: conflicting schema declaration revision")
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_schema_declarations(origin_node_uuid,schema_revision,table_name,table_json,descriptor_json,updated_at_utc) VALUES(?,?,?,?,?,sqliteseal_utc_now()) ON CONFLICT(origin_node_uuid,table_name) DO UPDATE SET schema_revision=excluded.schema_revision,table_json=excluded.table_json,descriptor_json=excluded.descriptor_json,updated_at_utc=excluded.updated_at_utc WHERE excluded.schema_revision>replication_schema_declarations.schema_revision`, declaration.OriginNodeUUID, declaration.SchemaRevision, declaration.Table.Name, string(tableRaw), descriptorRaw); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func normalizeReplicationDeclaredType(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "BLOB", nil
	}
	for _, r := range value {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) || r == '_' || r == '(' || r == ')' || r == ',') {
			return "", fmt.Errorf("%w: unsafe declared type %q", ErrReplicationSchemaUnsupported, value)
		}
	}
	value = strings.Join(strings.Fields(value), " ")
	for _, token := range strings.FieldsFunc(strings.ToUpper(value), func(r rune) bool { return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_') }) {
		switch token {
		case "PRIMARY", "KEY", "NOT", "NULL", "UNIQUE", "CHECK", "DEFAULT", "COLLATE", "REFERENCES", "GENERATED", "CONSTRAINT":
			return "", fmt.Errorf("%w: constraint keyword in declared type %q", ErrReplicationSchemaUnsupported, value)
		}
	}
	return strings.ToUpper(value), nil
}

type schemaColumnCandidate struct {
	column replicationColumn
	origin string
	level  int
}

func schemaColumnMap(descriptor replicationTableDescriptor) map[string]replicationColumn {
	result := make(map[string]replicationColumn, len(descriptor.Columns))
	for _, column := range descriptor.Columns {
		result[column.Name] = column
	}
	return result
}

func sameStringSlice(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		if first[i] != second[i] {
			return false
		}
	}
	return true
}

func (r *replicationRuntime) resolveEffectiveSchemas(ctx context.Context, declarations []wireSchemaDeclaration) ([]replicationTableDescriptor, []ReplicationSchemaConflict, error) {
	byTable := make(map[string][]wireSchemaDeclaration)
	for _, declaration := range declarations {
		byTable[declaration.Table.Name] = append(byTable[declaration.Table.Name], declaration)
	}
	names := make([]string, 0, len(byTable))
	for name := range byTable {
		names = append(names, name)
	}
	sort.Strings(names)
	var effective []replicationTableDescriptor
	var conflicts []ReplicationSchemaConflict
	for _, name := range names {
		items := byTable[name]
		var definitions []wireSchemaDeclaration
		for _, item := range items {
			if item.Descriptor != nil {
				definitions = append(definitions, item)
			}
		}
		if len(definitions) == 0 {
			conflicts = append(conflicts, ReplicationSchemaConflict{TableName: name, ColumnName: "<table>", DeclaredTypes: []string{"missing definition"}, AuthorityLevel: -1})
			continue
		}
		primaryKey := definitions[0].Descriptor.Table.PrimaryKeyColumns
		policy := definitions[0].Descriptor.Table.ConstraintPolicy
		allowRecreation := definitions[0].Descriptor.Table.AllowExplicitRecreation
		compatible := true
		for _, definition := range definitions[1:] {
			if !sameStringSlice(primaryKey, definition.Descriptor.Table.PrimaryKeyColumns) || policy != definition.Descriptor.Table.ConstraintPolicy || allowRecreation != definition.Descriptor.Table.AllowExplicitRecreation {
				compatible = false
			}
		}
		if !compatible {
			conflicts = append(conflicts, ReplicationSchemaConflict{TableName: name, ColumnName: "<primary-key-or-policy>", DeclaredTypes: []string{"incompatible definitions"}, AuthorityLevel: -1})
			continue
		}
		selectedSet := make(map[string]bool)
		for _, key := range primaryKey {
			selectedSet[key] = true
		}
		for _, item := range items {
			for _, column := range item.Table.Columns {
				selectedSet[column] = true
			}
			if item.Descriptor == nil {
				continue
			}
			for _, column := range item.Descriptor.Table.Columns {
				selectedSet[column] = true
			}
		}
		selected := make([]string, 0, len(selectedSet))
		for column := range selectedSet {
			selected = append(selected, column)
		}
		sort.Strings(selected)
		chosen := make(map[string]replicationColumn)
		for _, columnName := range selected {
			var candidates []schemaColumnCandidate
			for _, definition := range definitions {
				if column, ok := schemaColumnMap(*definition.Descriptor)[columnName]; ok {
					candidates = append(candidates, schemaColumnCandidate{column: column, origin: definition.OriginNodeUUID, level: definition.OriginLevel})
				}
			}
			if len(candidates) == 0 {
				conflicts = append(conflicts, ReplicationSchemaConflict{TableName: name, ColumnName: columnName, DeclaredTypes: []string{"missing definition"}, AuthorityLevel: -1})
				continue
			}
			minimum := candidates[0].level
			for _, candidate := range candidates[1:] {
				if candidate.level < minimum {
					minimum = candidate.level
				}
			}
			types := make(map[string][]string)
			columns := make(map[string]replicationColumn)
			for _, candidate := range candidates {
				if candidate.level != minimum {
					continue
				}
				typeName, normalizeErr := normalizeReplicationDeclaredType(candidate.column.DeclaredType)
				if normalizeErr != nil {
					return nil, nil, normalizeErr
				}
				types[typeName] = append(types[typeName], candidate.origin)
				candidate.column.DeclaredType = typeName
				columns[typeName] = candidate.column
			}
			if len(types) != 1 {
				var typeNames, origins []string
				for typeName, nodes := range types {
					typeNames = append(typeNames, typeName)
					origins = append(origins, nodes...)
				}
				sort.Strings(typeNames)
				sort.Strings(origins)
				conflicts = append(conflicts, ReplicationSchemaConflict{TableName: name, ColumnName: columnName, DeclaredTypes: typeNames, OriginNodeUUIDs: origins, AuthorityLevel: minimum})
				continue
			}
			for typeName := range types {
				chosen[columnName] = columns[typeName]
			}
		}
		if len(chosen) != len(selected) {
			continue
		}
		base := *definitions[0].Descriptor
		base.Table = ReplicatedTable{Name: name, PrimaryKeyColumns: append([]string(nil), primaryKey...), Columns: selected, AllowExplicitRecreation: allowRecreation, ConstraintPolicy: policy}
		base.Columns = base.Columns[:0]
		for _, name := range selected {
			base.Columns = append(base.Columns, chosen[name])
		}
		base.ForeignKeys = nil
		base.Indexes = nil
		base.Triggers = nil
		base.TableSQL = ""
		raw, _ := json.Marshal(base)
		sum := sha256Bytes(raw)
		base.DescriptorID = fmt.Sprintf("%x", sum[:8])
		effective = append(effective, base)
	}
	return effective, conflicts, nil
}

func createEffectiveTableSQL(descriptor replicationTableDescriptor) string {
	byName := schemaColumnMap(descriptor)
	definitions := make([]string, 0, len(descriptor.Table.Columns)+1)
	for _, name := range descriptor.Table.Columns {
		column := byName[name]
		definitions = append(definitions, quoteReplicationIdent(name)+" "+column.DeclaredType)
	}
	keys := make([]string, len(descriptor.Table.PrimaryKeyColumns))
	for i, key := range descriptor.Table.PrimaryKeyColumns {
		keys[i] = quoteReplicationIdent(key)
	}
	definitions = append(definitions, "PRIMARY KEY("+strings.Join(keys, ",")+")")
	return `CREATE TABLE ` + quoteReplicationIdent(descriptor.Table.Name) + `(` + strings.Join(definitions, ",") + `)`
}

func (r *replicationRuntime) applyEffectiveSchemas(ctx context.Context, descriptors []replicationTableDescriptor) error {
	r.writer.Lock()
	defer r.writer.Unlock()
	return r.withReplicationModeTransaction(ctx, "maintenance", func(tx *sql.Tx) error {
		var current []replicationTableDescriptor
		rows, err := tx.QueryContext(ctx, `SELECT descriptor_json FROM replication_table_descriptors ORDER BY table_name`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var raw string
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			var descriptor replicationTableDescriptor
			if err = json.Unmarshal([]byte(raw), &descriptor); err != nil {
				rows.Close()
				return err
			}
			current = append(current, descriptor)
		}
		if err = rows.Close(); err != nil {
			return err
		}
		if err = materializeHistoricalWireValues(ctx, tx, current); err != nil {
			return err
		}
		if effectiveSchemasMatch(current, descriptors) {
			return nil
		}
		currentByName := make(map[string]replicationTableDescriptor, len(current))
		for _, descriptor := range current {
			currentByName[descriptor.Table.Name] = descriptor
			if err = dropCaptureTriggers(ctx, tx, descriptor); err != nil {
				return err
			}
		}
		var installed []replicationTableDescriptor
		newlyManagedTables := make(map[string]bool)
		newlySelectedColumns := make(map[string][]string)
		for _, desired := range descriptors {
			var exists int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, desired.Table.Name).Scan(&exists); err != nil {
				return err
			}
			newlyManaged := false
			if exists == 0 {
				if _, err = tx.ExecContext(ctx, createEffectiveTableSQL(desired)); err != nil {
					return fmt.Errorf("replication: create agreed table %s: %w", desired.Table.Name, err)
				}
				newlyManaged = true
			} else {
				rows, infoErr := tx.QueryContext(ctx, `PRAGMA table_xinfo(`+quoteReplicationIdent(desired.Table.Name)+`)`)
				if infoErr != nil {
					return infoErr
				}
				existingTypes := make(map[string]string)
				for rows.Next() {
					var cid, notnull, pk, hidden int
					var name, declaredType string
					var defaultValue any
					if infoErr = rows.Scan(&cid, &name, &declaredType, &notnull, &defaultValue, &pk, &hidden); infoErr != nil {
						rows.Close()
						return infoErr
					}
					normalized, normalizeErr := normalizeReplicationDeclaredType(declaredType)
					if normalizeErr != nil {
						rows.Close()
						return normalizeErr
					}
					existingTypes[name] = normalized
				}
				rows.Close()
				for _, column := range desired.Columns {
					if existing, ok := existingTypes[column.Name]; !ok {
						if _, err = tx.ExecContext(ctx, `ALTER TABLE `+quoteReplicationIdent(desired.Table.Name)+` ADD COLUMN `+quoteReplicationIdent(column.Name)+` `+column.DeclaredType); err != nil {
							return fmt.Errorf("replication: add agreed column %s.%s: %w", desired.Table.Name, column.Name, err)
						}
					} else if existing != column.DeclaredType {
						if err = rebuildReplicationTableTypes(ctx, tx, desired); err != nil {
							return err
						}
						break
					}
				}
				_, newlyManaged = currentByName[desired.Table.Name]
				newlyManaged = !newlyManaged
			}
			actual, descriptorErr := tableDescriptor(ctx, tx, desired.Table)
			if descriptorErr != nil {
				return descriptorErr
			}
			installed = append(installed, actual)
			if newlyManaged {
				newlyManagedTables[actual.Table.Name] = true
			}
			if previous, ok := currentByName[actual.Table.Name]; ok {
				old := make(map[string]bool, len(previous.Table.Columns))
				for _, name := range previous.Table.Columns {
					old[name] = true
				}
				for _, name := range actual.Table.Columns {
					if !old[name] {
						newlySelectedColumns[actual.Table.Name] = append(newlySelectedColumns[actual.Table.Name], name)
					}
				}
			}
		}
		hash, err := descriptorsHash(installed)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE replication_local_state SET schema_hash=?,updated_at_utc=sqliteseal_utc_now()`, hash); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM replication_table_descriptors`); err != nil {
			return err
		}
		for _, descriptor := range installed {
			if err = installCaptureSchema(ctx, tx, descriptor, hash); err != nil {
				return err
			}
			if newlyManagedTables[descriptor.Table.Name] {
				if err = captureExistingRows(ctx, tx, descriptor); err != nil {
					return err
				}
			} else if columns := newlySelectedColumns[descriptor.Table.Name]; len(columns) != 0 {
				if err = captureExistingColumnValues(ctx, tx, descriptor, columns); err != nil {
					return err
				}
			}
			raw, _ := json.Marshal(descriptor)
			if _, err = tx.ExecContext(ctx, `INSERT INTO replication_table_descriptors(table_name,descriptor_id,descriptor_json,schema_hash,allow_recreation,created_at_utc) VALUES(?,?,?,?,?,sqliteseal_utc_now())`, descriptor.Table.Name, descriptor.DescriptorID, string(raw), hash, boolInt(descriptor.Table.AllowExplicitRecreation)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *replicationRuntime) persistSchemaConflicts(ctx context.Context, conflicts []ReplicationSchemaConflict) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM replication_schema_conflicts`); err != nil {
		return err
	}
	for _, conflict := range conflicts {
		typesRaw, _ := json.Marshal(conflict.DeclaredTypes)
		nodesRaw, _ := json.Marshal(conflict.OriginNodeUUIDs)
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_schema_conflicts VALUES(?,?,?,?,?,sqliteseal_utc_now())`, conflict.TableName, conflict.ColumnName, conflict.AuthorityLevel, string(typesRaw), string(nodesRaw)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *replicationRuntime) reconcileSchemas(ctx context.Context) (bool, error) {
	declarations, err := r.loadSchemaDeclarations(ctx)
	if err != nil {
		return false, err
	}
	descriptors, conflicts, err := r.resolveEffectiveSchemas(ctx, declarations)
	if err != nil {
		return false, err
	}
	if err = r.persistSchemaConflicts(ctx, conflicts); err != nil {
		return false, err
	}
	if len(conflicts) != 0 {
		return true, nil
	}
	if err = r.applyEffectiveSchemas(ctx, descriptors); err != nil {
		return true, err
	}
	return false, nil
}

func (r *replicationRuntime) schemaSyncClient(c net.Conn, p peerRuntimeConfig) (bool, error) {
	declarations, err := r.loadSchemaDeclarations(r.ctx)
	if err != nil {
		return false, err
	}
	if err = writeReplicationFrame(c, wireMessage{Type: "schema_request", Schemas: declarations}, p.MaxCompressed); err != nil {
		return false, err
	}
	response, err := readReplicationFrame(c, p.MaxCompressed, p.MaxUncompressed)
	if err != nil {
		return false, err
	}
	if response.Type != "schema_response" {
		return false, errors.New("replication: invalid schema response")
	}
	if response.Error != "" && !response.SchemaPending {
		return false, errors.New(response.Error)
	}
	if err = r.mergeSchemaDeclarations(r.ctx, response.Schemas); err != nil {
		return false, err
	}
	pending, reconcileErr := r.reconcileSchemas(r.ctx)
	return pending || response.SchemaPending, reconcileErr
}

func materializeHistoricalWireValues(ctx context.Context, tx *sql.Tx, descriptors []replicationTableDescriptor) error {
	for _, descriptor := range descriptors {
		columns := make([]string, 0, len(descriptor.Table.Columns)*2)
		for _, name := range descriptor.Table.Columns {
			columns = append(columns, quoteReplicationIdent(name+"__value"), quoteReplicationIdent(name+"__present"))
		}
		if len(columns) == 0 {
			continue
		}
		rows, err := tx.QueryContext(ctx, `SELECT c.change_uuid,`+strings.Join(columns, ",")+` FROM replication_changes c JOIN `+quoteReplicationIdent(descriptor.DescriptorID+"__replication_changes")+` p ON p.change_uuid=c.change_uuid WHERE c.table_name=? AND c.wire_values_json IS NULL`, descriptor.Table.Name)
		if err != nil {
			return err
		}
		type stored struct{ id, raw string }
		var updates []stored
		for rows.Next() {
			var id string
			values := make([]any, len(descriptor.Table.Columns)*2)
			pointers := make([]any, 0, len(values)+1)
			pointers = append(pointers, &id)
			for i := range values {
				pointers = append(pointers, &values[i])
			}
			if err = rows.Scan(pointers...); err != nil {
				rows.Close()
				return err
			}
			wireValues := make(map[string]wireValue, len(descriptor.Table.Columns))
			for i, name := range descriptor.Table.Columns {
				present, ok := values[i*2+1].(int64)
				if !ok {
					rows.Close()
					return errors.New("replication: invalid stored presence marker")
				}
				wireValues[name] = encodeWireValue(values[i*2], present == 1)
			}
			raw, _ := json.Marshal(wireValues)
			updates = append(updates, stored{id: id, raw: string(raw)})
		}
		if err = rows.Close(); err != nil {
			return err
		}
		for _, update := range updates {
			if _, err = tx.ExecContext(ctx, `UPDATE replication_changes SET wire_values_json=? WHERE change_uuid=?`, update.raw, update.id); err != nil {
				return err
			}
		}
	}
	return nil
}

func rebuildReplicationTableTypes(ctx context.Context, tx *sql.Tx, desired replicationTableDescriptor) error {
	actual, err := tableDescriptor(ctx, tx, ReplicatedTable{Name: desired.Table.Name, ConstraintPolicy: desired.Table.ConstraintPolicy})
	if err != nil {
		return err
	}
	upperSQL := strings.ToUpper(actual.TableSQL)
	if len(actual.ForeignKeys) != 0 || strings.Contains(upperSQL, " CHECK") || strings.Contains(upperSQL, " GENERATED") || strings.Contains(upperSQL, " WITHOUT ROWID") || strings.Contains(upperSQL, " STRICT") {
		return fmt.Errorf("%w: %s cannot be rebuilt automatically without changing constraints", ErrReplicationSchemaUnsupported, desired.Table.Name)
	}
	for _, index := range actual.Indexes {
		if index.Origin != "c" && index.Origin != "pk" {
			return fmt.Errorf("%w: %s has a table-level unique constraint", ErrReplicationSchemaUnsupported, desired.Table.Name)
		}
	}
	winning := schemaColumnMap(desired)
	definitions := make([]string, 0, len(actual.Columns)+1)
	columnNames := make([]string, 0, len(actual.Columns))
	for _, column := range actual.Columns {
		if column.Hidden != 0 {
			return fmt.Errorf("%w: %s has a hidden or generated column", ErrReplicationSchemaUnsupported, desired.Table.Name)
		}
		if replacement, ok := winning[column.Name]; ok {
			column.DeclaredType = replacement.DeclaredType
		}
		typeName, normalizeErr := normalizeReplicationDeclaredType(column.DeclaredType)
		if normalizeErr != nil {
			return normalizeErr
		}
		definition := quoteReplicationIdent(column.Name) + " " + typeName
		if column.NotNull != 0 {
			definition += " NOT NULL"
		}
		if column.DefaultSQL != "" {
			definition += " DEFAULT " + column.DefaultSQL
		}
		definitions = append(definitions, definition)
		columnNames = append(columnNames, quoteReplicationIdent(column.Name))
	}
	keys := make([]string, len(actual.Table.PrimaryKeyColumns))
	for i, key := range actual.Table.PrimaryKeyColumns {
		keys[i] = quoteReplicationIdent(key)
	}
	definitions = append(definitions, "PRIMARY KEY("+strings.Join(keys, ",")+")")
	temporary := "sqliteseal_schema_" + desired.DescriptorID
	if _, err = tx.ExecContext(ctx, `DROP TABLE IF EXISTS `+quoteReplicationIdent(temporary)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE `+quoteReplicationIdent(temporary)+`(`+strings.Join(definitions, ",")+`)`); err != nil {
		return err
	}
	joined := strings.Join(columnNames, ",")
	if _, err = tx.ExecContext(ctx, `INSERT INTO `+quoteReplicationIdent(temporary)+`(`+joined+`) SELECT `+joined+` FROM `+quoteReplicationIdent(actual.Table.Name)); err != nil {
		return fmt.Errorf("replication: convert agreed types for %s: %w", actual.Table.Name, err)
	}
	if _, err = tx.ExecContext(ctx, `DROP TABLE `+quoteReplicationIdent(actual.Table.Name)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `ALTER TABLE `+quoteReplicationIdent(temporary)+` RENAME TO `+quoteReplicationIdent(actual.Table.Name)); err != nil {
		return err
	}
	for _, index := range actual.Indexes {
		if index.SQL != "" {
			if _, err = tx.ExecContext(ctx, index.SQL); err != nil {
				return err
			}
		}
	}
	for _, trigger := range actual.Triggers {
		if trigger.SQL != "" {
			if _, err = tx.ExecContext(ctx, trigger.SQL); err != nil {
				return err
			}
		}
	}
	return nil
}

func publishLocalSchemaDeclarations(ctx context.Context, tx *sql.Tx, descriptors []replicationTableDescriptor) error {
	var node string
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT local_node_uuid,schema_revision FROM replication_local_state`).Scan(&node, &revision); err != nil {
		return err
	}
	revision++
	for _, descriptor := range descriptors {
		tableRaw, err := json.Marshal(descriptor.Table)
		if err != nil {
			return err
		}
		projected := replicatedDescriptorProjection(descriptor)
		descriptorRaw, err := json.Marshal(projected)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_schema_declarations(origin_node_uuid,schema_revision,table_name,table_json,descriptor_json,updated_at_utc) VALUES(?,?,?,?,?,sqliteseal_utc_now()) ON CONFLICT(origin_node_uuid,table_name) DO UPDATE SET schema_revision=excluded.schema_revision,table_json=excluded.table_json,descriptor_json=excluded.descriptor_json,updated_at_utc=excluded.updated_at_utc`, node, revision, descriptor.Table.Name, string(tableRaw), string(descriptorRaw)); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE replication_local_state SET schema_revision=? WHERE state_id=1`, revision)
	return err
}

func captureExistingColumnValues(ctx context.Context, tx *sql.Tx, descriptor replicationTableDescriptor, changedColumns []string) error {
	wanted := append([]string(nil), descriptor.Table.PrimaryKeyColumns...)
	seen := make(map[string]bool, len(wanted)+len(changedColumns))
	for _, name := range wanted {
		seen[name] = true
	}
	for _, name := range changedColumns {
		if !seen[name] {
			wanted = append(wanted, name)
			seen[name] = true
		}
	}
	quoted := make([]string, len(wanted))
	for i, name := range wanted {
		quoted[i] = quoteReplicationIdent(name)
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+strings.Join(quoted, ",")+` FROM `+quoteReplicationIdent(descriptor.Table.Name))
	if err != nil {
		return err
	}
	var records [][]any
	for rows.Next() {
		values := make([]any, len(wanted))
		pointers := make([]any, len(wanted))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err = rows.Scan(pointers...); err != nil {
			rows.Close()
			return err
		}
		records = append(records, values)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	index := make(map[string]int, len(wanted))
	for i, name := range wanted {
		index[name] = i
	}
	changedRaw, _ := json.Marshal(changedColumns)
	for _, record := range records {
		key := make(map[string]any, len(descriptor.Table.PrimaryKeyColumns))
		for _, name := range descriptor.Table.PrimaryKeyColumns {
			key[name] = record[index[name]]
		}
		rowKey, _ := json.Marshal(key)
		if _, err = tx.ExecContext(ctx, `UPDATE replication_local_state SET last_origin_counter=last_origin_counter+1,last_hlc_logical=CASE WHEN sqliteseal_time_us()>last_hlc_physical_utc_us THEN 0 ELSE last_hlc_logical+1 END,last_hlc_physical_utc_us=max(last_hlc_physical_utc_us,sqliteseal_time_us()),updated_at_utc=sqliteseal_utc_now()`); err != nil {
			return err
		}
		var node, domain, schema string
		var counter, physical, logical, version int64
		if err = tx.QueryRowContext(ctx, `SELECT local_node_uuid,replication_domain,schema_hash,last_origin_counter,last_hlc_physical_utc_us,last_hlc_logical,schema_version FROM replication_local_state`).Scan(&node, &domain, &schema, &counter, &physical, &logical, &version); err != nil {
			return err
		}
		eventID := replicationEventUUID(node, counter)
		created := replicationTimeFromUS(physical)
		wireValues := make(map[string]wireValue, len(descriptor.Table.Columns))
		changed := make(map[string]bool, len(changedColumns))
		for _, name := range changedColumns {
			changed[name] = true
		}
		for _, name := range descriptor.Table.Columns {
			if changed[name] {
				wireValues[name] = encodeWireValue(record[index[name]], true)
			} else {
				wireValues[name] = encodeWireValue(nil, false)
			}
		}
		event := wireEvent{ChangeUUID: eventID, OriginNodeUUID: node, OriginCounter: counter, Operation: "update", TableName: descriptor.Table.Name, RowKeyJSON: string(rowKey), ChangedFieldsJSON: string(changedRaw), HLCPhysicalUS: physical, HLCLogical: logical, SchemaVersion: version, SchemaHash: schema, Domain: domain, CreatedAtUTC: created, Values: wireValues}
		payloadHash, _, hashErr := replicationEventHash(event)
		if hashErr != nil {
			return hashErr
		}
		valuesJSON, _ := json.Marshal(wireValues)
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_changes(change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,stored_at_utc,payload_hash,wire_values_json) VALUES(?,?,?,'update',?,?,?,?,?,?,?,?,?,?,?,?)`, eventID, node, counter, descriptor.Table.Name, string(rowKey), string(changedRaw), physical, logical, version, schema, domain, created, created, payloadHash, string(valuesJSON)); err != nil {
			return err
		}
		event.StoredValuesJSON = string(valuesJSON)
		if err = persistWirePayload(ctx, tx, descriptor, event); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_origin_cursors VALUES(?,?,?, ?,NULL,0,?) ON CONFLICT(tracking_node_uuid,origin_node_uuid) DO UPDATE SET contiguous_counter=excluded.contiguous_counter,highest_seen_counter=excluded.highest_seen_counter,updated_at_utc=excluded.updated_at_utc`, node, node, counter, counter, created); err != nil {
			return err
		}
	}
	return nil
}

func effectiveSchemasMatch(current, desired []replicationTableDescriptor) bool {
	if len(current) != len(desired) {
		return false
	}
	byName := make(map[string]replicationTableDescriptor, len(current))
	for _, descriptor := range current {
		byName[descriptor.Table.Name] = descriptor
	}
	for _, wanted := range desired {
		have, ok := byName[wanted.Table.Name]
		if !ok || !sameStringSlice(have.Table.PrimaryKeyColumns, wanted.Table.PrimaryKeyColumns) || have.Table.ConstraintPolicy != wanted.Table.ConstraintPolicy || have.Table.AllowExplicitRecreation != wanted.Table.AllowExplicitRecreation {
			return false
		}
		haveSelected := make(map[string]bool, len(have.Table.Columns))
		for _, name := range have.Table.Columns {
			haveSelected[name] = true
		}
		if len(haveSelected) != len(wanted.Table.Columns) {
			return false
		}
		haveColumns := schemaColumnMap(have)
		for _, column := range wanted.Columns {
			if !haveSelected[column.Name] {
				return false
			}
			existing, ok := haveColumns[column.Name]
			if !ok {
				return false
			}
			normalized, err := normalizeReplicationDeclaredType(existing.DeclaredType)
			if err != nil || normalized != column.DeclaredType {
				return false
			}
		}
	}
	return true
}

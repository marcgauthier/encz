package sqliteseal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
)

const (
	replicationCanonicalizationVersion = 1
	replicationMergePolicyVersion      = 1
	defaultMaximumEventBytes           = 8 << 20
)

type canonicalReplicationEvent struct {
	CanonicalizationVersion int                  `json:"canonicalization_version"`
	MergePolicyVersion      int                  `json:"merge_policy_version"`
	ChangeUUID              string               `json:"change_uuid"`
	OriginNodeUUID          string               `json:"origin_node_uuid"`
	OriginCounter           int64                `json:"origin_counter"`
	Operation               string               `json:"operation"`
	TableName               string               `json:"table_name"`
	RowKey                  json.RawMessage      `json:"row_key"`
	ChangedFields           json.RawMessage      `json:"changed_fields"`
	ExplicitRecreation      bool                 `json:"is_explicit_recreation"`
	HLCPhysicalUS           int64                `json:"hlc_physical_utc_us"`
	HLCLogical              int64                `json:"hlc_logical"`
	SchemaVersion           int64                `json:"schema_version"`
	SchemaHash              string               `json:"schema_hash"`
	Domain                  string               `json:"replication_domain"`
	CreatedAtUTC            string               `json:"created_at_utc"`
	Values                  map[string]wireValue `json:"values"`
}

func canonicalReplicationEventBytes(e wireEvent) ([]byte, error) {
	rowKey, err := canonicalJSON([]byte(e.RowKeyJSON))
	if err != nil {
		return nil, fmt.Errorf("replication: canonical row key: %w", err)
	}
	changed, err := canonicalJSON([]byte(e.ChangedFieldsJSON))
	if err != nil {
		return nil, fmt.Errorf("replication: canonical changed fields: %w", err)
	}
	values := make(map[string]wireValue, len(e.Values))
	for name, value := range e.Values {
		name = norm.NFC.String(name)
		if value.Type == "text" {
			value.Value = norm.NFC.String(value.Value)
		}
		values[name] = value
	}
	payload := canonicalReplicationEvent{
		CanonicalizationVersion: replicationCanonicalizationVersion,
		MergePolicyVersion:      replicationMergePolicyVersion,
		ChangeUUID:              norm.NFC.String(e.ChangeUUID),
		OriginNodeUUID:          norm.NFC.String(e.OriginNodeUUID),
		OriginCounter:           e.OriginCounter,
		Operation:               norm.NFC.String(e.Operation),
		TableName:               norm.NFC.String(e.TableName),
		RowKey:                  rowKey,
		ChangedFields:           changed,
		ExplicitRecreation:      e.ExplicitRecreation,
		HLCPhysicalUS:           e.HLCPhysicalUS,
		HLCLogical:              e.HLCLogical,
		SchemaVersion:           e.SchemaVersion,
		SchemaHash:              e.SchemaHash,
		Domain:                  norm.NFC.String(e.Domain),
		CreatedAtUTC:            e.CreatedAtUTC,
		Values:                  values,
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err = enc.Encode(payload); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func canonicalJSON(raw []byte) ([]byte, error) {
	if err := validateReplicationJSON(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	value = normalizeJSONStrings(value)
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func normalizeJSONStrings(value any) any {
	switch x := value.(type) {
	case string:
		return norm.NFC.String(x)
	case []any:
		for i := range x {
			x[i] = normalizeJSONStrings(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, item := range x {
			out[norm.NFC.String(key)] = normalizeJSONStrings(item)
		}
		return out
	default:
		return value
	}
}

func replicationEventHash(e wireEvent) (string, int, error) {
	raw, err := canonicalReplicationEventBytes(e)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), len(raw), nil
}

func replicationEventUUID(origin string, counter int64) string {
	sum := sha256.Sum256([]byte(origin + "\x00" + strconv.FormatInt(counter, 10)))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

func replicationTimeFromUS(value int64) string {
	return time.UnixMicro(value).UTC().Format("2006-01-02T15:04:05.000000Z")
}

func isCanonicalUUID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(value, "-", "")
	_, err := hex.DecodeString(raw)
	return err == nil
}

func validateWireEvent(d replicationTableDescriptor, e wireEvent, domain, _ string, _ int64, maximumBytes int) error {
	if maximumBytes <= 0 {
		maximumBytes = defaultMaximumEventBytes
	}
	if !isCanonicalUUID(e.ChangeUUID) || !isCanonicalUUID(e.OriginNodeUUID) || e.OriginCounter <= 0 {
		return errors.New("replication: invalid event identity")
	}
	if e.ChangeUUID != replicationEventUUID(e.OriginNodeUUID, e.OriginCounter) {
		return errors.New("replication: event UUID does not match origin counter")
	}
	if e.Operation != "insert" && e.Operation != "update" && e.Operation != "delete" {
		return errors.New("replication: invalid operation")
	}
	if e.TableName != d.Table.Name || e.Domain != domain {
		return ErrReplicationSchemaMismatch
	}
	if e.HLCPhysicalUS <= 0 || e.HLCLogical < 0 {
		return errors.New("replication: invalid HLC")
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000000Z", e.CreatedAtUTC); err != nil {
		return errors.New("replication: invalid creation time")
	}
	if e.ExplicitRecreation && (e.Operation != "insert" || !d.Table.AllowExplicitRecreation) {
		return errors.New("replication: unauthorized explicit recreation")
	}
	canonicalKey, err := canonicalJSON([]byte(e.RowKeyJSON))
	if err != nil || string(canonicalKey) != e.RowKeyJSON {
		return errors.New("replication: non-canonical row key")
	}
	var key map[string]any
	dec := json.NewDecoder(bytes.NewReader(canonicalKey))
	dec.UseNumber()
	if err = dec.Decode(&key); err != nil || len(key) != len(d.Table.PrimaryKeyColumns) {
		return errors.New("replication: invalid row key")
	}
	for _, name := range d.Table.PrimaryKeyColumns {
		if _, ok := key[name]; !ok {
			return errors.New("replication: incomplete row key")
		}
	}
	canonicalChanged, err := canonicalJSON([]byte(e.ChangedFieldsJSON))
	if err != nil || string(canonicalChanged) != e.ChangedFieldsJSON {
		return errors.New("replication: non-canonical changed fields")
	}
	var changed []string
	if err = json.Unmarshal(canonicalChanged, &changed); err != nil {
		return errors.New("replication: invalid changed fields")
	}
	changedSet := make(map[string]bool, len(changed))
	allowed := make(map[string]bool, len(d.Table.Columns))
	for _, name := range d.Table.Columns {
		allowed[name] = true
	}
	for _, name := range changed {
		if !allowed[name] || changedSet[name] || !norm.NFC.IsNormalString(name) {
			return errors.New("replication: invalid changed field")
		}
		changedSet[name] = true
	}
	for name, value := range e.Values {
		if !allowed[name] || value.Present != changedSet[name] {
			return errors.New("replication: field presence mismatch")
		}
		if err = validateWireValue(value); err != nil {
			return fmt.Errorf("replication: invalid field %s: %w", name, err)
		}
	}
	for name := range changedSet {
		if _, ok := e.Values[name]; !ok {
			return errors.New("replication: incomplete typed row image")
		}
	}
	if (e.Operation == "insert" && len(changed) == 0) || (e.Operation == "update" && len(changed) == 0) || (e.Operation == "delete" && len(changed) != 0) {
		return errors.New("replication: operation and changed fields disagree")
	}
	hash, size, err := replicationEventHash(e)
	if err != nil {
		return err
	}
	if size > maximumBytes {
		return errors.New("replication: event exceeds uncompressed limit")
	}
	if len(e.PayloadHash) != 64 || e.PayloadHash != strings.ToLower(e.PayloadHash) || hash != e.PayloadHash {
		return errors.New("replication: payload hash mismatch")
	}
	return nil
}

func validateWireValue(value wireValue) error {
	if !value.Present && value.Type == "" {
		return errors.New("missing type")
	}
	if value.Type == "null" && value.Value != "" {
		return errors.New("null value has payload")
	}
	if value.Type == "text" && !norm.NFC.IsNormalString(value.Value) {
		return errors.New("text is not NFC")
	}
	_, err := decodeWireValue(value)
	return err
}

func canonicalRowKeySQL(args ...any) (string, error) {
	if len(args) == 0 || len(args)%2 != 0 {
		return "", errors.New("replication: invalid row-key arguments")
	}
	value := make(map[string]any, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		name, ok := args[i].(string)
		if !ok || name == "" || !norm.NFC.IsNormalString(name) {
			return "", errors.New("replication: invalid row-key name")
		}
		switch args[i+1].(type) {
		case nil, int64, float64, string:
		default:
			return "", errors.New("replication: unsupported primary-key type")
		}
		value[name] = args[i+1]
	}
	raw, err := json.Marshal(value)
	return string(raw), err
}

func replicationEventHashSQL(args ...any) (string, error) {
	if len(args) < 14 || (len(args)-14)%3 != 0 {
		return "", errors.New("replication: invalid event-hash arguments")
	}
	text := func(index int) (string, error) {
		value, ok := args[index].(string)
		if !ok {
			return "", errors.New("replication: invalid event text")
		}
		return value, nil
	}
	integer := func(index int) (int64, error) {
		switch value := args[index].(type) {
		case int64:
			return value, nil
		case int:
			return int64(value), nil
		default:
			return 0, errors.New("replication: invalid event integer")
		}
	}
	var event wireEvent
	var err error
	if event.ChangeUUID, err = text(0); err != nil {
		return "", err
	}
	if event.OriginNodeUUID, err = text(1); err != nil {
		return "", err
	}
	if event.OriginCounter, err = integer(2); err != nil {
		return "", err
	}
	if event.Operation, err = text(3); err != nil {
		return "", err
	}
	if event.TableName, err = text(4); err != nil {
		return "", err
	}
	if event.RowKeyJSON, err = text(5); err != nil {
		return "", err
	}
	if event.ChangedFieldsJSON, err = text(6); err != nil {
		return "", err
	}
	recreation, err := integer(7)
	if err != nil {
		return "", err
	}
	event.ExplicitRecreation = recreation == 1
	if event.HLCPhysicalUS, err = integer(8); err != nil {
		return "", err
	}
	if event.HLCLogical, err = integer(9); err != nil {
		return "", err
	}
	if event.SchemaVersion, err = integer(10); err != nil {
		return "", err
	}
	if event.SchemaHash, err = text(11); err != nil {
		return "", err
	}
	if event.Domain, err = text(12); err != nil {
		return "", err
	}
	if event.CreatedAtUTC, err = text(13); err != nil {
		return "", err
	}
	event.Values = make(map[string]wireValue, (len(args)-14)/3)
	for i := 14; i < len(args); i += 3 {
		name, ok := args[i].(string)
		if !ok {
			return "", errors.New("replication: invalid field name")
		}
		present, err := integer(i + 2)
		if err != nil {
			return "", err
		}
		event.Values[name] = encodeWireValue(args[i+1], present == 1)
	}
	hash, _, err := replicationEventHash(event)
	return hash, err
}

func replicationIsNFC(value any) int {
	text, ok := value.(string)
	if !ok || norm.NFC.IsNormalString(text) {
		return 1
	}
	return 0
}

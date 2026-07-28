package sqliteseal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func validateReplicationJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := validateReplicationJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("replication: trailing JSON value")
	}
	return nil
}
func validateReplicationJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("replication: object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("replication: duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err = validateReplicationJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("replication: invalid JSON object")
		}
	case '[':
		for dec.More() {
			if err = validateReplicationJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("replication: invalid JSON array")
		}
	default:
		return errors.New("replication: unexpected JSON delimiter")
	}
	return nil
}

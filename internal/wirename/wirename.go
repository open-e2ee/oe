// Package wirename reads and writes a JSON object field that has two names
// during a customer support window. Each Pair names the field that the Go
// type decodes and encodes, and the alias that the other side of the window
// uses. Accept reads either name. Emit writes both names. The contract
// release removes each Pair and its alias.
package wirename

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Pair is one renamed field. Name is the JSON name in the Go type. Alias is
// the other name of the same field.
type Pair struct {
	Name  string
	Alias string
}

// ConflictError is an object that sets both names of a Pair to different
// values.
type ConflictError struct {
	Pair Pair
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("the object sets %s and %s to different values", e.Pair.Name, e.Pair.Alias)
}

// Accept returns data with the value of each alias moved to its Name, so the
// Go type decodes the field from either name. When the object sets both names
// to the same value, Accept keeps one. When the values differ, Accept returns
// a *ConflictError. Data that is not a JSON object passes through unchanged.
func Accept(data []byte, pairs ...Pair) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return data, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return nil, err
	}
	moved := false
	for _, pair := range pairs {
		alias, ok := fields[pair.Alias]
		if !ok {
			continue
		}
		if name, ok := fields[pair.Name]; ok && !sameValue(name, alias) {
			return nil, &ConflictError{Pair: pair}
		}
		fields[pair.Name] = alias
		delete(fields, pair.Alias)
		moved = true
	}
	if !moved {
		return data, nil
	}
	return json.Marshal(fields)
}

// Emit returns the encoded object data with each alias added after the other
// fields, with the value of its Name. A Pair whose Name data leaves out adds
// nothing. Data must be a compact JSON object, as json.Marshal writes it.
func Emit(data []byte, pairs ...Pair) ([]byte, error) {
	if len(data) < 2 || data[0] != '{' || data[len(data)-1] != '}' {
		return nil, fmt.Errorf("wirename: %s is not a JSON object", data)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	result := bytes.Clone(data[:len(data)-1])
	for _, pair := range pairs {
		value, ok := fields[pair.Name]
		if !ok {
			continue
		}
		if _, ok := fields[pair.Alias]; ok {
			return nil, fmt.Errorf("wirename: the object already has %s", pair.Alias)
		}
		if len(result) > 1 {
			result = append(result, ',')
		}
		key, err := json.Marshal(pair.Alias)
		if err != nil {
			return nil, err
		}
		result = append(result, key...)
		result = append(result, ':')
		result = append(result, value...)
	}
	return append(result, '}'), nil
}

// sameValue compares two encoded values byte for byte after it removes
// insignificant space.
func sameValue(left, right json.RawMessage) bool {
	var a, b bytes.Buffer
	if json.Compact(&a, left) != nil || json.Compact(&b, right) != nil {
		return false
	}
	return bytes.Equal(a.Bytes(), b.Bytes())
}

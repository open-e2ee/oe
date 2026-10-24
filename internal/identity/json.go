package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var ErrIdentityValue = errors.New("Identity value is invalid.")

const MaximumSafeInteger uint64 = 9007199254740991

type SafeInteger uint64

func (v SafeInteger) Validate() error {
	if uint64(v) > MaximumSafeInteger {
		return ErrIdentityValue
	}
	return nil
}
func (v SafeInteger) MarshalJSON() ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrIdentityValue
	}
	return strconv.AppendUint(nil, uint64(v), 10), nil
}
func (v *SafeInteger) UnmarshalJSON(data []byte) error {
	if !json.Valid(data) || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return ErrIdentityValue
	}
	n, err := strconv.ParseFloat(string(bytes.TrimSpace(data)), 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > float64(MaximumSafeInteger) || math.Trunc(n) != n {
		return ErrIdentityValue
	}
	*v = SafeInteger(n)
	return nil
}
func positive(v SafeInteger) bool { return v > 0 && v.Validate() == nil }

// ContractText stores JavaScript UTF-16 code units without replacement.
type ContractText struct{ units []uint16 }

func Text(value string) (ContractText, error) {
	if !utf8.ValidString(value) {
		return ContractText{}, ErrIdentityValue
	}
	return ContractText{utf16.Encode([]rune(value))}, nil
}
func TextFromUnits(value []uint16) ContractText      { return ContractText{slices.Clone(value)} }
func (v ContractText) Units() []uint16               { return slices.Clone(v.units) }
func (v ContractText) Len() int                      { return len(v.units) }
func (v ContractText) Equal(other ContractText) bool { return slices.Equal(v.units, other.units) }
func (v ContractText) ScalarString() (string, bool) {
	for i := 0; i < len(v.units); i++ {
		u := v.units[i]
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(v.units) || v.units[i+1] < 0xdc00 || v.units[i+1] > 0xdfff {
				return "", false
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", false
		}
	}
	return string(utf16.Decode(v.units)), true
}
func (v ContractText) webString() string { return string(utf16.Decode(v.units)) }
func (v ContractText) MarshalJSON() ([]byte, error) {
	out := []byte{'"'}
	for _, u := range v.units {
		out = fmt.Appendf(out, "\\u%04x", u)
	}
	return append(out, '"'), nil
}
func (v *ContractText) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if !utf8.Valid(data) || !json.Valid(data) || len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return ErrIdentityValue
	}
	var units []uint16
	for i := 1; i < len(data)-1; {
		if data[i] != '\\' {
			r, n := utf8.DecodeRune(data[i:])
			units = append(units, utf16.Encode([]rune{r})...)
			i += n
			continue
		}
		i++
		c := data[i]
		i++
		switch c {
		case 'u':
			n, e := strconv.ParseUint(string(data[i:i+4]), 16, 16)
			if e != nil {
				return ErrIdentityValue
			}
			units = append(units, uint16(n))
			i += 4
		case '"', '\\', '/':
			units = append(units, uint16(c))
		case 'b':
			units = append(units, 8)
		case 'f':
			units = append(units, 12)
		case 'n':
			units = append(units, 10)
		case 'r':
			units = append(units, 13)
		case 't':
			units = append(units, 9)
		default:
			return ErrIdentityValue
		}
	}
	v.units = units
	return nil
}
func textBound(v ContractText, low, high int) bool {
	return v.Len() >= low && (high < 0 || v.Len() <= high)
}
func asciiText(v ContractText, pattern string) bool {
	s, ok := v.ScalarString()
	return ok && matches(pattern, s)
}
func textLiteral(v ContractText, s string) bool { return v.webString() == s && v.Len() == len(s) }
func containsNUL(v ContractText) bool           { return slices.Contains(v.units, 0) }

// checkJSON checks all objects before typed receivers inspect their fields.
func checkJSON(data []byte) error {
	if !utf8.Valid(data) {
		return ErrIdentityValue
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var visit func() error
	visit = func() error {
		token, err := d.Token()
		if err != nil {
			return ErrIdentityValue
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return ErrIdentityValue
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return ErrIdentityValue
				}
				seen[name] = true
				if visit() != nil {
					return ErrIdentityValue
				}
			}
			token, err = d.Token()
			if err != nil || token != json.Delim('}') {
				return ErrIdentityValue
			}
		case '[':
			for d.More() {
				if visit() != nil {
					return ErrIdentityValue
				}
			}
			token, err = d.Token()
			if err != nil || token != json.Delim(']') {
				return ErrIdentityValue
			}
		default:
			return ErrIdentityValue
		}
		return nil
	}
	if visit() != nil {
		return ErrIdentityValue
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrIdentityValue
	}
	return nil
}
func decodeClosed(data []byte, destination any) error {
	if checkJSON(data) != nil {
		return ErrIdentityValue
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return ErrIdentityValue
	}
	t := reflect.TypeOf(destination).Elem()
	allowed := map[string]reflect.StructField{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")
		if tag[0] != "" && tag[0] != "-" {
			allowed[tag[0]] = f
		}
	}
	for name, value := range fields {
		f, ok := allowed[name]
		if !ok {
			return ErrIdentityValue
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && f.Tag.Get("nullable") != "true" {
			return ErrIdentityValue
		}
	}
	for name, f := range allowed {
		if _, ok := fields[name]; !ok && !strings.Contains(f.Tag.Get("json"), ",omitempty") {
			return ErrIdentityValue
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(destination) != nil {
		return ErrIdentityValue
	}
	return nil
}
func encodeChecked(value any, validate func() error) ([]byte, error) {
	if validate() != nil {
		return nil, ErrIdentityValue
	}
	data, e := json.Marshal(value)
	if e != nil {
		return nil, ErrIdentityValue
	}
	return data, nil
}
func cloneValue[T any](value T) (T, error) {
	var out T
	data, e := json.Marshal(value)
	if e != nil {
		return out, ErrIdentityValue
	}
	if json.Unmarshal(data, &out) != nil {
		return out, ErrIdentityValue
	}
	return out, nil
}
func equalValue[T any](left, right T) bool {
	a, e := json.Marshal(left)
	if e != nil {
		return false
	}
	b, e := json.Marshal(right)
	return e == nil && bytes.Equal(a, b)
}
func optionalTextEqual(a, b *ContractText) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}

package config

import (
	"slices"
	"strings"
)

// Format is the schema form of a config file. The forms differ only in the
// names of the Relay policy keys.
type Format int

const (
	// FormatV3 is the config-v3.json form. Its policy key is signalRelay and
	// its receipts key is signalRelayReceipts. oe writes this form.
	FormatV3 Format = iota
	// FormatV2 is the deprecated config-v2.json form. Its policy key is relay
	// and its receipts key is relayReceipts. oe reads it until
	// FormatV2RemovalRelease.
	FormatV2
)

// FormatV2RemovalRelease is the oe release that stops reading the
// config-v2.json form.
const FormatV2RemovalRelease = "v7.0.0"

// v2Names maps each config-v2.json key to its config-v3.json key, and
// v3Names maps each config-v3.json key back.
var (
	v2Names = map[string]string{"relay": "signalRelay", "relayReceipts": "signalRelayReceipts"}
	v3Names = map[string]string{"signalRelay": "relay", "signalRelayReceipts": "relayReceipts"}
)

// formatOf returns the form of the config value. A value that sets both
// policy keys has no form, and formatOf returns CONFIG_INVALID.
func formatOf(value any) (Format, error) {
	object, _ := value.(map[string]any)
	_, v2 := object["relay"]
	_, v3 := object["signalRelay"]
	switch {
	case v2 && v3:
		return 0, invalid([]FieldError{{
			Path:    "relay",
			Message: "is not allowed with signalRelay; remove relay and keep signalRelay",
		}})
	case v2:
		return FormatV2, nil
	default:
		return FormatV3, nil
	}
}

// Path returns the dotted path in a file of this form for a path in the
// config-v3.json form.
func (f Format) Path(path ...string) string {
	return strings.Join(f.filePath(path), ".")
}

// filePath returns path with the key names of this form.
func (f Format) filePath(path []string) []string {
	if f != FormatV2 {
		return path
	}
	result := slices.Clone(path)
	for index, key := range path {
		if renamed, ok := v3Names[key]; ok && policyPosition(path[:index+1]) {
			result[index] = renamed
		}
	}
	return result
}

// fileChange returns change with the key names of this form, in the path and
// in a section value.
func (f Format) fileChange(change Change) Change {
	value := normalize(change.Value)
	if f != FormatV2 {
		return Change{Path: change.Path, Value: value}
	}
	return Change{Path: f.filePath(change.Path), Value: renameKeys(value, change.Path, v3Names)}
}

// renameKeys returns a copy of value, the section at path, with each policy
// key that names maps renamed. It renames a key only at a policy position,
// so an identity section keeps every key.
func renameKeys(value any, path []string, names map[string]string) any {
	object, ok := value.(map[string]any)
	if !ok {
		return value
	}
	result := make(map[string]any, len(object))
	for key, field := range object {
		child := append(slices.Clip(path), key)
		name := key
		if renamed, ok := names[key]; ok && policyPosition(child) {
			name = renamed
		}
		result[name] = renameKeys(field, child, names)
	}
	return result
}

// policyPosition reports whether the last key of path can be a policy key or
// a receipts key: the shared policy key, the receipts key in the shared
// policy, the policy key of an environment, or the receipts key in it.
func policyPosition(path []string) bool {
	policy := func(key string) bool { return key == "relay" || key == "signalRelay" }
	switch len(path) {
	case 1:
		return true
	case 2:
		return policy(path[0])
	case 3:
		return path[0] == "environments"
	case 4:
		return path[0] == "environments" && policy(path[2])
	}
	return false
}

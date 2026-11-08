// Package schema embeds the JSON Schemas of the project config. oe validates
// the config with these copies, and each release publishes the same files at
// each schema's $id.
package schema

import _ "embed"

// ConfigV3 is config-v3.json. Its shared policy key is signalRelay.
//
//go:embed config-v3.json
var ConfigV3 []byte

// ConfigV2 is config-v2.json. Its shared policy key is relay. The file is
// frozen: oe reads it during the customer window, and it never changes.
//
//go:embed config-v2.json
var ConfigV2 []byte

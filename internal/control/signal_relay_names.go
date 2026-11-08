package control

import (
	"encoding/json"

	"github.com/open-e2ee/oe/internal/wirename"
)

// The Console renames these response fields to Signal Protocol Relay names.
// During the customer window, each reader below accepts the old name and the
// new name, so oe works before and after the Console change. The Go types
// keep the old name, because oe still sends the old name in each request
// until the Console accepts the new name. The contract release deletes this
// file and gives the types the new names.
var (
	sandboxSignalRelayURLName = wirename.Pair{Name: "sandboxRelayUrl", Alias: "sandboxSignalProtocolRelayUrl"}
	signalRelayURLName        = wirename.Pair{Name: "relayUrl", Alias: "signalRelayUrl"}
	signalRelayReceiptsName   = wirename.Pair{Name: "relayReceipts", Alias: "signalRelayReceipts"}
	signalRelayMAUName        = wirename.Pair{Name: "relayMau", Alias: "signalRelayMau"}
)

// decodeRenamed decodes data into target after it moves each alias in pairs
// to its old name.
func decodeRenamed(data []byte, target any, pairs ...wirename.Pair) error {
	accepted, err := wirename.Accept(data, pairs...)
	if err != nil {
		return err
	}
	return json.Unmarshal(accepted, target)
}

func (b *Bootstrap) UnmarshalJSON(data []byte) error {
	type wire Bootstrap
	return decodeRenamed(data, (*wire)(b), sandboxSignalRelayURLName)
}

func (d *Deployment) UnmarshalJSON(data []byte) error {
	type wire Deployment
	return decodeRenamed(data, (*wire)(d), signalRelayURLName)
}

func (e *ProjectEnvironment) UnmarshalJSON(data []byte) error {
	type wire ProjectEnvironment
	return decodeRenamed(data, (*wire)(e), signalRelayURLName, signalRelayReceiptsName)
}

func (u *UsageReported) UnmarshalJSON(data []byte) error {
	type wire UsageReported
	return decodeRenamed(data, (*wire)(u), signalRelayMAUName)
}

// MarshalJSON writes relayMau and signalRelayMau, because oe project usage
// prints the usage snapshot in its JSON output.
func (u UsageReported) MarshalJSON() ([]byte, error) {
	type wire UsageReported
	data, err := json.Marshal(wire(u))
	if err != nil {
		return nil, err
	}
	return wirename.Emit(data, signalRelayMAUName)
}

func (l *UsageLimits) UnmarshalJSON(data []byte) error {
	type wire UsageLimits
	return decodeRenamed(data, (*wire)(l), signalRelayMAUName)
}

// MarshalJSON writes relayMau and signalRelayMau, as UsageReported does.
func (l UsageLimits) MarshalJSON() ([]byte, error) {
	type wire UsageLimits
	data, err := json.Marshal(wire(l))
	if err != nil {
		return nil, err
	}
	return wirename.Emit(data, signalRelayMAUName)
}

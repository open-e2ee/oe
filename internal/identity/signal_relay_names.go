package identity

import "github.com/open-e2ee/oe/internal/wirename"

// signalRelayScopeName is the Console rename of relayScopeId to
// signalRelayScopeId. During the customer window, Scope and
// AdmissionReadiness accept either name. They still encode relayScopeId,
// because oe sends the scope back in each precondition and the Console
// accepts the new name there only after its own change. The contract release
// deletes this file and renames the field.
var signalRelayScopeName = wirename.Pair{Name: "relayScopeId", Alias: "signalRelayScopeId"}

// decodeSignalRelayScope checks data as decodeClosed does, then decodes it
// with signalRelayScopeId read as relayScopeId. When data sets both names,
// the values must be equal.
func decodeSignalRelayScope(data []byte, destination any) error {
	if checkJSON(data) != nil {
		return ErrIdentityValue
	}
	accepted, err := wirename.Accept(data, signalRelayScopeName)
	if err != nil {
		return ErrIdentityValue
	}
	return decodeClosed(accepted, destination)
}

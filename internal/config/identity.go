package config

import (
	"encoding/json"

	"github.com/open-e2ee/oe/internal/identity"
)

func identityConfigError(path string) *Error {
	return &Error{Code: "CONFIG_INVALID", Message: "The public identity configuration is invalid.",
		Data: map[string]any{"errors": []FieldError{{Path: path, Message: "must match a supported public identity policy"}}}}
}

// IdentityFor returns a detached desired policy. A missing value stays unmanaged.
func (c Config) IdentityFor(environment string) (*identity.SelectionTarget, error) {
	var value *identity.SelectionTarget
	switch environment {
	case "sandbox":
		value = c.Environments.Sandbox.Identity
	case "production":
		if c.Environments.Production == nil {
			return nil, identityConfigError("environments.production")
		}
		value = c.Environments.Production.Identity
	default:
		return nil, identityConfigError("environments")
	}
	if value == nil {
		return nil, nil
	}
	result, err := value.Clone()
	if err != nil {
		return nil, identityConfigError("environments." + environment + ".identity")
	}
	return &result, nil
}

// ProjectInstalledIdentity refuses historical values that cannot form a new write.
// It preserves the broad installed receiver and every public policy field.
func ProjectInstalledIdentity(value identity.CompleteConfiguration) (identity.SelectionTarget, error) {
	if value.Validate() != nil || value.IdentityMigration != nil {
		return identity.SelectionTarget{}, identityConfigError("identity")
	}
	if value.IdentityProfile.Mode == "device-owned" {
		return identity.SelectionTarget{Mode: "device-owned"}, nil
	}
	data, err := json.Marshal(value.IdentityProfile)
	if err != nil {
		return identity.SelectionTarget{}, identityConfigError("identity")
	}
	var target identity.SelectionTarget
	if json.Unmarshal(data, &target) != nil {
		return identity.SelectionTarget{}, identityConfigError("identity")
	}
	return target, nil
}

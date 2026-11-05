// Package envvar owns the names of the environment variables that a customer
// sets: the variables that oe reads from the shell, and the variables that hold
// the Relay connection in the app's env files.
//
// Every name starts with OPEN_E2EE_, after any framework prefix. Each name has
// the deprecated name that it replaces. oe reads the deprecated name when the
// current name is empty, until RemovalRelease.
package envvar

import (
	"fmt"
	"slices"
	"sync"
)

// RemovalRelease is the oe release that stops reading the deprecated names.
const RemovalRelease = "v6.0.0"

// Name is the current name of one variable and the deprecated name that it
// replaces.
type Name struct {
	Current    string
	Deprecated string
}

// The variables that oe reads from the shell.
var (
	AccessToken       = Name{"OPEN_E2EE_ACCESS_TOKEN", "OE_ACCESS_TOKEN"}
	AccessTokenScopes = Name{"OPEN_E2EE_ACCESS_TOKEN_SCOPES", "OE_ACCESS_TOKEN_SCOPES"}
	ProtectionBypass  = Name{"OPEN_E2EE_PROTECTION_BYPASS", "OE_PROTECTION_BYPASS"}
	Environment       = Name{"OPEN_E2EE_ENV", "OE_ENV"}
	OperationID       = Name{"OPEN_E2EE_OPERATION_ID", "OE_OPERATION_ID"}
)

// The variables that hold the Relay connection URL in the app's env files.
// Next.js, Expo, and Vite expose a variable to client code only when it has
// the framework prefix.
var (
	SignalRelayURL     = Name{"OPEN_E2EE_SIGNAL_RELAY_URL", "OPEN_E2EE_RELAY_URL"}
	NextSignalRelayURL = Name{"NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL"}
	ExpoSignalRelayURL = Name{"EXPO_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", "EXPO_PUBLIC_OPEN_E2EE_RELAY_URL"}
	ViteSignalRelayURL = Name{"VITE_OPEN_E2EE_SIGNAL_RELAY_URL", "VITE_OPEN_E2EE_RELAY_URL"}
)

var shell = []Name{AccessToken, AccessTokenScopes, ProtectionBypass, Environment, OperationID}

// Shell returns the variables that oe reads from the shell.
func Shell() []Name { return slices.Clone(shell) }

// Lookup returns the value of n.Current. When that value is empty, Lookup
// returns the value of n.Deprecated, and deprecated is true.
func (n Name) Lookup(getenv func(string) string) (value string, deprecated bool) {
	if value := getenv(n.Current); value != "" {
		return value, false
	}
	if value := getenv(n.Deprecated); value != "" {
		return value, true
	}
	return "", false
}

// Warning tells a person who set n.Deprecated in the shell to set n.Current.
func (n Name) Warning() string {
	return fmt.Sprintf("warning: %s is deprecated. Set %s instead. oe %s stops reading %s.", n.Deprecated, n.Current, RemovalRelease, n.Deprecated)
}

// Reader returns a getenv that reads each shell variable by its current name,
// then by its deprecated name. It calls warn once for each variable whose
// value comes from the deprecated name. Every other name passes through to
// getenv unchanged.
func Reader(getenv func(string) string, warn func(Name)) func(string) string {
	var mu sync.Mutex
	warned := map[string]bool{}
	return func(name string) string {
		for _, candidate := range shell {
			if name != candidate.Current {
				continue
			}
			value, deprecated := candidate.Lookup(getenv)
			if deprecated {
				mu.Lock()
				first := !warned[name]
				warned[name] = true
				mu.Unlock()
				if first {
					warn(candidate)
				}
			}
			return value
		}
		return getenv(name)
	}
}

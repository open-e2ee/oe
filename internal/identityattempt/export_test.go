package identityattempt

import "testing"

// FixtureLocation is present only in this package's test variant. It delegates
// the complete owned-root, default-root exclusion and native fixture policy.
func FixtureLocation(t *testing.T) Location {
	t.Helper()
	return storeFixtureLocation(t)
}

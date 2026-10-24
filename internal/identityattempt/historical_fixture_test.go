package identityattempt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
)

// FixtureRetainHistoricalLifecycle writes a synthetic old envelope through the
// native commit boundary in an owned fixture. It proves no original-client recovery.
// New Retain calls must still refuse this unprepared historical identifier.
func FixtureRetainHistoricalLifecycle(t *testing.T, ctx context.Context, lease *Lease, expected Envelope, original identity.LifecycleAttempt) {
	t.Helper()
	base := os.Getenv("OE_IDENTITY_STORE_FIXTURE_ROOT")
	canonical, err := filepath.EvalSymlinks(base)
	if err != nil || canonical != base || !filepath.IsAbs(base) || !strings.HasPrefix(filepath.Base(base), "ca8-store-fixtures-") {
		t.Fatal("an explicitly owned canonical fixture root is required")
	}
	if lease == nil || lease.namespace == nil || lease.namespace.root == nil {
		t.Fatal("the actual native fixture lease is required")
	}
	relative, err := filepath.Rel(base, lease.namespace.root.path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		t.Fatal("the native lease is outside the owned fixture")
	}
	if original.Validate() != nil || identity.ValidateResumeOperationID(original.OperationID) != nil || identity.ValidatePreparedOperationID(original.OperationID) == nil {
		t.Fatal("the fixture requires a valid historical continuation identifier")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	stop, err := lease.activateCaller(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	current, err := lease.expected(expected)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := current.RetainedAttempt()
	if err != nil || retained != nil || lease.slot.Kind() != Lifecycle {
		t.Fatal("the historical fixture requires an empty lifecycle slot")
	}
	attempt, err := NewLifecycleAttempt(original)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := nextRevision(current)
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewOccupiedEnvelope(lease.slot, revision, attempt)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.commit(value); err != nil {
		t.Fatal(err)
	}
}

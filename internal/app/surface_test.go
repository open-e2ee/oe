package app

import (
	"strings"
	"testing"
)

func TestIdentityHelpDisclosesTransientDraftCheckLimits(t *testing.T) {
	for _, args := range [][]string{{"--agent", "no", "help", "identity"}, {"--json", "help", "identity"}, {"--agent", "no", "identity", "--help"}} {
		exit, out, stderr := run(t, Dependencies{}, args...)
		if exit != 0 || stderr != "" {
			t.Fatalf("identity help failed: %s %s", out, stderr)
		}
		for _, contract := range []string{"--profile", "--assertion-stdin", "sandbox|production", "transient", "authenticated Console", "Device-owned", "historical", "installed configuration", "member binding", "lifecycle"} {
			if !strings.Contains(out, contract) {
				t.Errorf("identity help omitted %q", contract)
			}
		}
	}
}

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

func TestAliasHelpNamesCanonicalCommand(t *testing.T) {
	for _, test := range []struct{ alias, canonical string }{
		{"app", "project"}, {"projects", "project"}, {"apps", "project"},
		{"orgs", "org"}, {"organizations", "org"},
	} {
		exit, stdout, _ := run(t, Dependencies{}, "--json", "help", test.alias)
		result := decodeEvent(t, []byte(stdout))
		if exit != 0 || result.Command != test.canonical || result.Data["name"] != test.canonical || result.Data["aliases"] == nil {
			t.Fatalf("help %s: exit=%d %s", test.alias, exit, stdout)
		}
	}
	exit, stdout, _ := run(t, Dependencies{}, "--agent", "no", "help", "project")
	if exit != 0 || !strings.Contains(stdout, "oe app view [PROJECT]") || !strings.Contains(stdout, "oe projects list") {
		t.Fatalf("project help did not show its aliases: exit=%d %s", exit, stdout)
	}
}

func TestPublicIdentityHelpPublishesExactRetainedAndFirstUsePaths(t *testing.T) {
	spec, ok := lookupCommand("identity")
	if !ok || len(spec.Usage) != 11 {
		t.Fatal("identity help omitted a frozen command")
	}
	for _, path := range []string{
		"identity current", "identity select", "identity keys rotate",
		"identity lifecycle target", "identity lifecycle suspend", "identity lifecycle activate",
		"identity operation status", "identity operation retry", "identity operation resume", "identity operation cancel",
	} {
		for _, mode := range [][]string{{"--json"}, {"--agent", "no"}} {
			args := append(append([]string{}, mode...), strings.Fields(path)...)
			exit, stdout, stderr := run(t, Dependencies{}, append(args, "--help")...)
			if exit != 0 || stderr != "" || !strings.Contains(stdout, path) {
				t.Fatal("frozen identity path has no contextual help", path, exit, stdout, stderr)
			}
		}
	}
	exit, stdout, stderr := run(t, Dependencies{}, "--json", "help", "identity")
	if exit != 0 || stderr != "" {
		t.Fatal("machine identity help failed")
	}
	for _, expected := range []string{"--confirm-state-never-used", "--confirm-slot-never-used", "--target-stdin", "--kind lifecycle", "--kind selection|keys-only"} {
		if !strings.Contains(stdout, expected) {
			t.Fatal("machine identity help omitted a frozen input", expected)
		}
	}
	for _, forbidden := range []string{"--target SUBJECT", "--assertion TOKEN", "operation forget", "operation replace"} {
		if strings.Contains(stdout, forbidden) {
			t.Fatal("machine identity help exposed an unsupported input", forbidden)
		}
	}
}

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/credential"
)

// cliContract records the public process result of one isolated app.Run call.
// It protects the existing machine output and parser behavior while human help
// moves to Cobra. Text help cases are checked separately for the new layout.
type cliContract struct {
	Name   string   `json:"name"`
	Mode   string   `json:"mode"`
	Args   []string `json:"args"`
	Exit   int      `json:"exit"`
	Stdout string   `json:"stdout"`
	Stderr string   `json:"stderr"`
}

func cliContractCases() []struct {
	name string
	args []string
} {
	cases := []struct {
		name string
		args []string
	}{
		{"empty", nil},
		{"bare terminator", []string{"--"}},
		{"bare help", []string{"help"}},
		{"root short help", []string{"-h"}},
		{"root long help", []string{"--help"}},
		{"root version", []string{"--version"}},
		{"version", []string{"version"}},
		{"help project usage", []string{"help", "project", "usage"}},
		{"help bogus", []string{"help", "bogus"}},
		{"help project bogus", []string{"help", "project", "bogus"}},
		{"project usage help", []string{"project", "usage", "--help"}},
		{"project bogus help", []string{"project", "bogus", "--help"}},
		{"doctor extra help", []string{"doctor", "extra", "--help"}},
		{"doctor local flag then help", []string{"doctor", "--bogus", "--help"}},
		{"doctor help then local flag", []string{"doctor", "--help", "--bogus"}},
		{"new value help", []string{"new", "--name", "--help"}},
		{"link value help", []string{"link", "--env-var", "-h"}},
		{"doctor timeout help", []string{"doctor", "--timeout", "--help"}},
		{"doctor terminator help", []string{"doctor", "--", "--help"}},
		{"unknown help", []string{"bogus", "--help"}},
		{"retired help", []string{"init", "--help"}},
		{"replaced help", []string{"deploy", "--help"}},
		{"completion help", []string{"completion", "--help"}},
		{"hidden completion help", []string{"__complete", "--help"}},
		{"leading terminator help", []string{"--", "--help"}},
		{"leading terminator short help", []string{"--", "-h"}},
		{"leading terminator version", []string{"--", "--version"}},
		{"leading terminator json", []string{"--", "--json"}},
		{"leading terminator repeated help", []string{"--", "--help", "--help"}},
		{"doctor terminator json", []string{"doctor", "--", "--json"}},
		{"doctor terminator env", []string{"doctor", "--", "--env", "production"}},
		{"projects terminator agent", []string{"projects", "--", "--agent", "no"}},
		{"doctor unknown flag", []string{"doctor", "--bogus"}},
		{"json after command", []string{"doctor", "--json"}},
		{"json stream after command", []string{"doctor", "--json-stream"}},
		{"agent after command", []string{"doctor", "--agent", "no"}},
		{"invalid env after command", []string{"doctor", "--env", "staging"}},
		{"invalid inline env after command", []string{"doctor", "--env=staging"}},
		{"invalid inline short env after command", []string{"doctor", "-e=staging"}},
		{"invalid inline agent after command", []string{"doctor", "--agent=maybe"}},
		{"invalid inline control URL", []string{"doctor", "--control-url=not-a-url"}},
		{"doctor missing timeout", []string{"doctor", "--timeout"}},
		{"doctor extra", []string{"doctor", "extra"}},
		{"project unknown child", []string{"project", "foo"}},
		{"auth flag before subcommand", []string{"auth", "--timeout", "5s", "login"}},
		{"notifications flag before subcommand", []string{"notifications", "setup", "--profile", "visible-alert", "ios"}},
		{"project flag before subcommand", []string{"project", "--yes=true", "show"}},
		{"config flag before subcommand", []string{"config", "--dry-run", "push"}},
		{"auth flag before subcommand help", []string{"auth", "--timeout", "5s", "login", "--help"}},
		{"login replacement", []string{"login"}},
		{"logout replacement", []string{"logout"}},
		{"whoami replacement", []string{"whoami"}},
		{"config bare", []string{"config"}},
		{"notifications bare setup", []string{"notifications", "setup"}},
		{"completion", []string{"completion"}},
		{"hidden completion", []string{"__complete"}},
		{"hidden completion no description", []string{"__completeNoDesc"}},
		{"short version", []string{"-v"}},
		{"missing env", []string{"doctor", "--env"}},
		{"missing short env", []string{"projects", "-e"}},
		{"missing control URL", []string{"--control-url"}},
		{"missing agent", []string{"--agent"}},
		{"invalid env", []string{"--env", "staging", "doctor"}},
		{"invalid agent", []string{"--agent", "maybe", "doctor"}},
		{"unknown global flag", []string{"--bogus", "doctor"}},
		{"root help before command", []string{"-h", "doctor"}},
		{"root help before unknown", []string{"-h", "bogus"}},
		{"root version before command", []string{"--version", "doctor"}},
		{"false help", []string{"doctor", "--help=false"}},
		{"true help", []string{"doctor", "--help=true"}},
		{"short help value", []string{"doctor", "-h=false"}},
		{"combined short help", []string{"doctor", "-xh"}},
	}
	for _, spec := range commandSurface {
		cases = append(cases, struct {
			name string
			args []string
		}{"help " + spec.Name, []string{"help", spec.Name}})
		cases = append(cases, struct {
			name string
			args []string
		}{spec.Name + " --help", []string{spec.Name, "--help"}})
	}
	for _, alias := range []string{"app", "apps", "projects", "orgs", "organizations"} {
		cases = append(cases, struct {
			name string
			args []string
		}{"help alias " + alias, []string{"help", alias}})
	}
	for _, alias := range []string{"app", "apps", "projects", "orgs", "organizations", "project", "org", "auth", "notifications", "agent"} {
		cases = append(cases, struct {
			name string
			args []string
		}{"alias help " + alias, []string{alias, "--help"}})
	}
	for _, name := range []string{"init", "setup", "create", "sandbox", "plan", "deploy", "diff"} {
		cases = append(cases, struct {
			name string
			args []string
		}{"legacy " + name, []string{name}})
	}
	return cases
}

func TestCLIContract(t *testing.T) {
	modes := []struct {
		name   string
		prefix []string
		agent  bool
	}{
		{"text", []string{"--agent", "no"}, false},
		{"json", []string{"--json"}, false},
		{"json-stream", []string{"--json-stream"}, false},
		{"agent-auto", nil, true},
	}
	var actual []cliContract
	for _, mode := range modes {
		for _, test := range cliContractCases() {
			args := append(append([]string(nil), mode.prefix...), test.args...)
			var stdout, stderr bytes.Buffer
			directory := t.TempDir()
			getenv := func(name string) string {
				if mode.agent && name == "CLAUDECODE" {
					return "1"
				}
				return ""
			}
			exit := Run(t.Context(), args, Dependencies{
				Out: &stdout, Err: &stderr, WorkingDir: directory,
				Getenv: getenv, Store: credential.NewMemory(), API: &fakeAPI{},
				HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return nil, errors.New("unexpected network request")
				})},
				Interactive: func() bool { return false },
				OpenURL:     func(string) error { return errors.New("unexpected browser request") },
			})
			actual = append(actual, cliContract{
				test.name, mode.name, args, exit,
				normalizeContractDirectory(stdout.String(), directory),
				normalizeContractDirectory(stderr.String(), directory),
			})
		}
	}
	// CH0 writes the source baseline to the proof root. CH1 checks in the same
	// JSON as a fixture so a future change cannot silently alter machine output.
	if target := os.Getenv("OE_CAPTURE_CLI_CONTRACT"); target != "" {
		data, err := json.MarshalIndent(actual, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(filepath.Join("testdata", "cli_contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected []cliContract
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) != len(actual) {
		t.Fatalf("contract rows: got %d, want %d", len(actual), len(expected))
	}
	for i := range actual {
		// Only human help is intentionally changed. Its exact content is
		// checked by the layout tests; all other bytes remain contractual.
		if path, ok := humanHelpTarget(expected[i]); ok {
			if !strings.Contains(actual[i].Stdout, "Usage: oe "+path) && !strings.Contains(actual[i].Stdout, "Usage:\n  oe "+path) {
				t.Errorf("%s/%s: human help does not name %q: %q", actual[i].Mode, actual[i].Name, path, actual[i].Stdout)
			}
			actual[i].Stdout = expected[i].Stdout
		}
		if !reflect.DeepEqual(actual[i], expected[i]) {
			t.Errorf("%s/%s: got exit=%d stdout=%q stderr=%q; want exit=%d stdout=%q stderr=%q", actual[i].Mode, actual[i].Name, actual[i].Exit, actual[i].Stdout, actual[i].Stderr, expected[i].Exit, expected[i].Stdout, expected[i].Stderr)
		}
	}
}

func normalizeContractDirectory(output, directory string) string {
	encoded, _ := json.Marshal(directory)
	output = strings.ReplaceAll(output, string(encoded[1:len(encoded)-1]), "<WORKDIR>")
	return strings.ReplaceAll(output, directory, "<WORKDIR>")
}

func TestNormalizeContractDirectory(t *testing.T) {
	for _, test := range []struct {
		output, directory, want string
	}{
		{`missing in /tmp/oe-test`, `/tmp/oe-test`, `missing in <WORKDIR>`},
		{`missing in C:\Users\runner\Temp\oe-test`, `C:\Users\runner\Temp\oe-test`, `missing in <WORKDIR>`},
		{`{"error":"missing in C:\\Users\\runner\\Temp\\oe-test"}`, `C:\Users\runner\Temp\oe-test`, `{"error":"missing in <WORKDIR>"}`},
	} {
		if got := normalizeContractDirectory(test.output, test.directory); got != test.want {
			t.Errorf("normalizeContractDirectory(%q, %q) = %q, want %q", test.output, test.directory, got, test.want)
		}
	}
}

// humanHelpTarget is intentionally a narrow list. A test with a help token
// after -- or in a flag-value slot still has to show the right command path.
func humanHelpTarget(row cliContract) (string, bool) {
	if row.Mode != "text" || row.Exit != 0 {
		return "", false
	}
	switch row.Name {
	case "empty", "bare terminator", "bare help", "root short help", "root long help":
		return "<command>", true
	case "project usage help":
		return "project usage", true
	case "project bogus help", "help alias app", "help alias apps", "help alias projects", "alias help app", "alias help apps", "alias help projects", "alias help project":
		return "project", true
	case "help alias orgs", "help alias organizations", "alias help orgs", "alias help organizations", "alias help org":
		return "org", true
	case "doctor extra help", "doctor local flag then help", "doctor help then local flag", "doctor timeout help", "doctor terminator help":
		return "doctor", true
	case "new value help":
		return "new", true
	case "link value help":
		return "link", true
	case "alias help auth":
		return "auth", true
	case "auth flag before subcommand help":
		return "auth", true
	case "alias help notifications":
		return "notifications", true
	case "alias help agent":
		return "agent", true
	case "root help before command", "root help before unknown":
		return "doctor", true
	case "help --help":
		return "help", true
	}
	if strings.HasPrefix(row.Name, "help ") {
		return strings.TrimPrefix(row.Name, "help "), true
	}
	if strings.HasSuffix(row.Name, " --help") {
		return strings.TrimSuffix(row.Name, " --help"), true
	}
	return "", false
}

func TestCLIContractCaseNamesUnique(t *testing.T) {
	var names []string
	for _, test := range cliContractCases() {
		names = append(names, test.name)
	}
	sort.Strings(names)
	for i := 1; i < len(names); i++ {
		if names[i] == names[i-1] {
			t.Fatalf("duplicate contract case %q", names[i])
		}
	}
}

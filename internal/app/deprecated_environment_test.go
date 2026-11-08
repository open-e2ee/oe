package app

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
	"github.com/open-e2ee/oe/internal/envvar"
)

// Until v7.0.0, oe reads each shell variable by its OE_ name when the
// OPEN_E2EE_ name is empty, and warns once on stderr. The OPEN_E2EE_ name
// wins when both are set.
func TestDeprecatedEnvironmentNameSelectsTheEnvironment(t *testing.T) {
	directory := initializedProject(t, "variable-chat")
	if err := writeSignalProtocolRelayEnvironment(directory, ".env.production.local", envfile.Default, productionSignalProtocolRelayURL, noWarning(t)); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	var read []string
	for _, test := range []struct {
		name, want, stderr string
		values             map[string]string
	}{
		{"deprecated name", productionSignalProtocolRelayURL, envvar.Environment.Warning() + "\n", map[string]string{"OE_ENV": "production"}},
		{"both names", sandboxSignalProtocolRelayURL, "", map[string]string{"OPEN_E2EE_ENV": "sandbox", "OE_ENV": "production"}},
		{"current name", productionSignalProtocolRelayURL, "", map[string]string{"OPEN_E2EE_ENV": "production"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := Dependencies{API: twoEnvironments(&read), Store: store, WorkingDir: directory, Getenv: environment(test.values)}
			exit, stdout, stderr := run(t, dependencies, "project", "connection")
			if exit != 0 || stdout != test.want+"\n" || stderr != test.stderr {
				t.Fatalf("project connection: exit=%d stdout=%q stderr=%q; want %q and stderr %q", exit, stdout, stderr, test.want, test.stderr)
			}
		})
	}
}

func TestDeprecatedAccessTokenNameSignsIn(t *testing.T) {
	server := newConsole(t, "accepted", true)
	server.session = personSession()
	for _, test := range []struct {
		name, stderr string
		values       map[string]string
	}{
		{"deprecated name", envvar.AccessToken.Warning() + "\n", map[string]string{"OE_ACCESS_TOKEN": sessionToken()}},
		{"both names", "", map[string]string{"OPEN_E2EE_ACCESS_TOKEN": sessionToken(), "OE_ACCESS_TOKEN": "refused-old-token"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := server.dependencies(keychainStore{credential.NewMemory()}, environment(test.values))
			exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "status")
			want := "Signed in as Jane Doe (jane@example.com) in Acme Inc. (OPEN_E2EE_ACCESS_TOKEN)\nAcme Inc. has accepted the OpenE2EE terms.\n"
			if exit != 0 || stdout != want || stderr != test.stderr {
				t.Fatalf("auth status: exit=%d stdout=%q stderr=%q; want stderr %q", exit, stdout, stderr, test.stderr)
			}
		})
	}
}

func TestDeprecatedProtectionBypassNameReachesTheControlURL(t *testing.T) {
	const bypass = "old-name-bypass"
	store := credential.NewMemory()
	storeCredential(t, store)
	var sent string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		sent = request.Header.Get("x-vercel-protection-bypass")
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":"UNAUTHORIZED"}`))}, nil
	})}
	var stdout, stderr bytes.Buffer
	Run(t.Context(), []string{"--json", "auth", "status"}, Dependencies{
		Store: store, HTTP: client, Out: &stdout, Err: &stderr, WorkingDir: t.TempDir(),
		Getenv: environment(map[string]string{"OE_PROTECTION_BYPASS": bypass}),
	})
	if sent != bypass || stderr.String() != envvar.ProtectionBypass.Warning()+"\n" || strings.Contains(stdout.String(), bypass) {
		t.Fatalf("bypass %q, stderr %q, stdout %q", sent, stderr.String(), stdout.String())
	}
}

func TestDeprecatedOperationIDNameKeysTheCreateCall(t *testing.T) {
	server := startNewControl(t, created)
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())
	directory := emptyDirectory(t, "acme-chat")
	exit, stdout, stderr := run(t, Dependencies{
		API: server.api, Store: store, WorkingDir: directory,
		Getenv: environment(map[string]string{"OE_OPERATION_ID": "op_repeat_create"}),
	}, "--json", "new")
	keys, _, _ := server.calls()
	if exit != 0 || len(keys) != 1 || keys[0] != "op_repeat_create" || stderr != envvar.OperationID.Warning()+"\n" {
		t.Fatalf("oe new: exit=%d keys=%q stdout=%s stderr=%q", exit, keys, stdout, stderr)
	}
}

// A file that an earlier oe wrote assigns the deprecated variable. oe writes
// the current variable, keeps the deprecated line current, and warns.
func TestWriteKeepsTheDeprecatedRelayLineCurrent(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, ".env.production.local")
	if err := os.WriteFile(path, []byte("OPEN_E2EE_RELAY_URL=https://stale.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var warnings []string
	if err := writeSignalProtocolRelayEnvironment(directory, ".env.production.local", envfile.Default, productionSignalProtocolRelayURL, func(message string) {
		warnings = append(warnings, message)
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"OPEN_E2EE_SIGNAL_RELAY_URL", "OPEN_E2EE_RELAY_URL"} {
		if value, err := envfile.Read(path, name); err != nil || value != productionSignalProtocolRelayURL {
			t.Fatalf("%s holds %q (%v)", name, value, err)
		}
	}
	if len(warnings) != 1 || warnings[0] != envfile.DeprecationWarning(".env.production.local", envfile.Default, false) {
		t.Fatalf("warnings = %q", warnings)
	}
}

func TestDoctorReadsTheDeprecatedRelayLineAndWarns(t *testing.T) {
	directory := initializedProject(t, "variable-chat")
	if err := os.WriteFile(filepath.Join(directory, ".env.production.local"), []byte("OPEN_E2EE_RELAY_URL="+productionSignalProtocolRelayURL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	var read []string
	signalRelay := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != productionSignalProtocolRelayURL {
			t.Fatalf("doctor requested an unexpected URL: %s", request.URL)
		}
		return &http.Response{Body: io.NopCloser(strings.NewReader(`{"schemaVersion":1}`)), Header: make(http.Header), StatusCode: http.StatusOK}, nil
	})}
	exit, stdout, stderr := run(t, Dependencies{
		API: twoEnvironments(&read), HTTP: signalRelay, Store: store, WorkingDir: directory,
		Getenv: environment(map[string]string{"OPEN_E2EE_ENV": "production"}),
	}, "--json", "doctor")
	if checks := decodeEvent(t, []byte(stdout)); exit != 0 || checks.Data["configurationSource"] != ".env.production.local" {
		t.Fatalf("doctor: exit=%d %s", exit, stdout)
	}
	if want := envfile.DeprecationWarning(".env.production.local", envfile.Default, true) + "\n"; stderr != want {
		t.Fatalf("doctor stderr = %q; want %q", stderr, want)
	}
}

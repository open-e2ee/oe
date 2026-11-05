package acceptance_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// TestBuiltBinaryCreatesAProjectAndPassesDoctor runs the built binary
// outside the repository, so the config loader can come only from the copy
// that the binary embeds. oe new creates the project against a control API
// on loopback, and doctor passes only after the written config loads and the
// written Relay connection matches the project.
func TestBuiltBinaryCreatesAProjectAndPassesDoctor(t *testing.T) {
	t.Parallel()

	binary := filepath.Join(t.TempDir(), "oe")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "./cmd/oe")
	build.Dir = repositoryRoot(t)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build oe: %v\n%s", err, output)
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	signalRelayURL := server.URL + "/signal/v1/connection/pk_sandbox_public"
	mux.HandleFunc("POST /v1/projects/bootstrap", func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(response, `{"created":true,"project":"loaded-chat","writer":"config","revision":"1","environment":"sandbox","sandboxRelayUrl":%q}`, signalRelayURL)
	})
	mux.HandleFunc("GET /v1/health", func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(response, `{"status":"ok"}`)
	})
	mux.HandleFunc("GET /v1/projects/loaded-chat", func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(response, `{"slug":"loaded-chat","writer":"config","sandbox":{"relayUrl":%q,"revision":"1"}}`, signalRelayURL)
	})
	mux.HandleFunc("GET /signal/v1/connection/pk_sandbox_public", func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(response, `{"schemaVersion":1}`)
	})

	project := filepath.Join(t.TempDir(), "loaded-chat")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"new"}, {"doctor"}} {
		command := exec.Command(binary, append([]string{"--json", "--agent", "no", "--control-url", server.URL}, args...)...)
		command.Dir = project
		command.Env = append(os.Environ(), "OE_ACCESS_TOKEN=test-token", "OE_ACCESS_TOKEN_SCOPES=project:write project:read", "OE_ENV=", "OE_OPERATION_ID=")
		output, err := command.Output()
		var result struct {
			Status  string `json:"status"`
			Command string `json:"command"`
		}
		if decodeErr := json.Unmarshal(output, &result); decodeErr != nil || err != nil || result.Status != "ok" || result.Command != args[0] {
			t.Fatalf("oe %s failed: %v %v\n%s", args[0], err, decodeErr, output)
		}
	}
}

func TestCommandSurfaceGolden(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	command := exec.Command("go", "run", "./cmd/oe", "--json", "help")
	command.Dir = root

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("command surface failed: %v\n%s", err, output)
	}

	golden, err := os.ReadFile(filepath.Join("testdata", "help.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotValue any
	var wantValue any
	if err := json.Unmarshal(output, &gotValue); err != nil {
		t.Fatalf("decode command output: %v", err)
	}
	if err := json.Unmarshal(golden, &wantValue); err != nil {
		t.Fatalf("decode golden output: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("command surface drifted\nwant: %s\n got: %s", golden, output)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test filename")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

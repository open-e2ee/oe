package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
)

const binaryIdentityKey = `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"owned-key"}`
const binaryIdentityProfile = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://members.example","audience":"members","subjectClaim":"sub","keys":[` + binaryIdentityKey + `]}`
const binaryIdentityScope = `{"environmentId":"owned_env","environmentKind":"sandbox","projectId":"owned_project","protocolProfile":"signal","relayScopeId":"owned_relay"}`
const binaryIdentityFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const binaryIdentityComplete = `{"configurationVersion":1,"admissionRevision":0,"verificationPolicyFingerprint":"` + binaryIdentityFingerprint + `","identityProfile":` + binaryIdentityProfile + `,"inventory":{"everAdmitted":false,"bindingCount":0,"historyCount":0,"pendingOperationId":null},"identityRecovery":null,"identityMigration":null,"mixedModeMigration":{"available":false},"selection":null,"providerValidation":{"state":"not_checked"},"applicationIntegration":{"state":"unverified"},"admissionReadiness":{"relayScopeId":"owned_relay","evidence":{"state":"current","checkedAtSeconds":0},"state":"ready","sourceGeneration":{"kind":"provision","admissionRevision":0,"policyFingerprint":"` + binaryIdentityFingerprint + `"},"reason":null},"selectionOperation":null}`
const binaryIdentityCurrent = `{"configuration":` + binaryIdentityComplete + `,"precondition":{"publishableKey":"pk_owned","recoveryGeneration":1,"scope":` + binaryIdentityScope + `}}`

// The binary embeds its config loader and schema. These loopback reads do not
// establish Console authorization, native Relay effects or provider acceptance.
func TestBuiltBinaryLinksExistingProjectAndReadsExplicitIdentity(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "oe")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	buildContext, cancelBuild := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelBuild()
	build := exec.CommandContext(buildContext, "go", "build", "-o", binary, "./cmd/oe")
	build.Dir = repositoryRoot(t)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build identity binary: %v\n%s", err, output)
	}
	var current identity.CurrentContext
	if json.Unmarshal([]byte(binaryIdentityCurrent), &current) != nil {
		t.Fatal("invalid built-binary current fixture")
	}
	var mutex sync.Mutex
	actions := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owned_binary_token" {
			t.Error("built-binary credential changed")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		action := r.URL.Query().Get("action")
		if action == "" {
			action = r.URL.Path
		}
		mutex.Lock()
		actions = append(actions, action)
		mutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/session":
			_ = json.NewEncoder(w).Encode(control.Session{SchemaVersion: 1,
				User:         control.SessionUser{ID: "owned_user", Email: "owned@example.com"},
				Organization: control.SessionOrganization{ID: "owned_org", Name: "Owned fixture"}})
		case "/v1/projects/loaded-chat":
			receipts := true
			_ = json.NewEncoder(w).Encode(control.Project{Slug: "loaded-chat", Writer: "config",
				Sandbox: &control.ProjectEnvironment{State: "active", Revision: "1", RelayReceipts: &receipts,
					DeliveryRetentionSeconds: 86400, AttachmentRetentionSeconds: 86400,
					RelayURL: "https://relay.example/signal/v1/connection/pk_owned"}})
		case "/v1/projects/loaded-chat/deploys/plan":
			_ = json.NewEncoder(w).Encode(control.Plan{ID: "owned_plan", ProjectSlug: "loaded-chat", Environment: "sandbox", ExpectedRevision: "1", Changes: []control.Change{}})
		case "/v1/projects/loaded-chat/identity":
			if r.URL.Query().Get("environment") != "sandbox" {
				t.Error("built-binary environment changed")
				w.WriteHeader(500)
				return
			}
			switch action {
			case "current", "keys-read":
				_ = json.NewEncoder(w).Encode(current)
			case "preview":
				var body map[string]json.RawMessage
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("built-binary preview body invalid")
					w.WriteHeader(500)
					return
				}
				delete(body, "action")
				data, err := json.Marshal(body)
				var request identity.PreviewRequest
				if err != nil || json.Unmarshal(data, &request) != nil {
					t.Error("built-binary preview request invalid")
					w.WriteHeader(500)
					return
				}
				_ = json.NewEncoder(w).Encode(identity.PreviewResult{Kind: request.Kind,
					ExpectedConfigurationVersion: request.ExpectedConfigurationVersion, Target: request.Target, Keys: request.Keys,
					Current: current, NativeCapabilities: identity.NativeCapabilities{Clerk: "closed", Firebase: "closed"}})
			default:
				t.Error("built-binary read caused an unexpected identity action", action)
				w.WriteHeader(500)
			}
		default:
			t.Error("built-binary existing-project journey caused an unexpected route", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	count := func(action string) int {
		mutex.Lock()
		defer mutex.Unlock()
		total := 0
		for _, value := range actions {
			if value == action {
				total++
			}
		}
		return total
	}
	run := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, append([]string{"--json", "--agent", "no", "--control-url", server.URL}, args...)...)
		command.Dir = directory
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			switch name {
			case "OE_ACCESS_TOKEN", "OE_ACCESS_TOKEN_SCOPES", "OE_ENV", "OE_OPERATION_ID", "OE_PROTECTION_BYPASS":
				continue
			}
			command.Env = append(command.Env, entry)
		}
		command.Env = append(command.Env, "OE_ACCESS_TOKEN=owned_binary_token", "OE_ACCESS_TOKEN_SCOPES=project:read project:write", "OE_ENV=", "OE_OPERATION_ID=", "OE_PROTECTION_BYPASS=")
		var stderr bytes.Buffer
		command.Stderr = &stderr
		data, err := command.Output()
		var result struct {
			Status string `json:"status"`
		}
		if err != nil || json.Unmarshal(data, &result) != nil || result.Status != "ok" || stderr.Len() != 0 {
			t.Fatalf("built-binary command %v failed: %v\n%s\n%s", args, err, data, stderr.String())
		}
		if bytes.Contains(data, []byte("owned_binary_token")) {
			t.Fatal("built-binary output exposed its credential")
		}
		return data
	}
	run("link", "loaded-chat")
	path := filepath.Join(directory, config.Filename)
	linked, err := config.Load(path)
	if err != nil || linked.Project != "loaded-chat" || linked.Environments.Sandbox.Identity != nil || count("current") != 0 {
		t.Fatal("existing-project link selected or imported identity", err)
	}
	run("config", "pull", "--identity", "--env", "sandbox")
	pulled, err := config.Load(path)
	if err != nil || pulled.Environments.Sandbox.Identity == nil {
		t.Fatal("explicit built-binary pull did not add desired identity", err)
	}
	var expected identity.SelectionTarget
	if json.Unmarshal([]byte(binaryIdentityProfile), &expected) != nil || !pulled.Environments.Sandbox.Identity.Equal(expected) {
		t.Fatal("built-binary pull changed public policy")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	run("link")
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("argument-free link changed the identity config", err)
	}
	run("config", "pull", "--env", "sandbox")
	run("config", "push", "--dry-run", "--env", "sandbox")
	run("identity", "current", "--env", "sandbox")
	run("identity", "select", "--dry-run", "--env", "sandbox")
	keys := filepath.Join(directory, "public-keys.json")
	if err := os.WriteFile(keys, []byte("["+binaryIdentityKey+"]"), 0600); err != nil {
		t.Fatal(err)
	}
	run("identity", "keys", "rotate", "--keys", keys, "--dry-run", "--env", "sandbox")
	if count("preview") != 2 || count("keys-read") != 1 {
		t.Fatal("built-binary dry-run did not use its actual read/preview routes")
	}
	for _, forbidden := range []string{"select", "replace", "keys-replace", "prepare", "apply", "resume", "selection-cancel", "keys-cancel", "/v1/projects/bootstrap", "/v1/deploys"} {
		if count(forbidden) != 0 {
			t.Fatal("existing-project read journey caused mutation", forbidden)
		}
	}
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only built-binary journey changed config", err)
	}
}

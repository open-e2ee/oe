package control

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

const keyWire = `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"key-one"}`
const configuredWire = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://members.example","audience":"members","subjectClaim":"sub","keys":[` + keyWire + `]}`
const fingerprintWire = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const scopeWire = `{"environmentId":"env","environmentKind":"sandbox","projectId":"project","protocolProfile":"signal","relayScopeId":"relay_scope"}`
const preconditionWire = `{"publishableKey":"pk_public","recoveryGeneration":1,"scope":` + scopeWire + `}`
const completeWire = `{"configurationVersion":1,"admissionRevision":0,"verificationPolicyFingerprint":"` + fingerprintWire + `","identityProfile":` + configuredWire + `,"inventory":{"everAdmitted":false,"bindingCount":0,"historyCount":0,"pendingOperationId":null},"identityRecovery":null,"identityMigration":null,"mixedModeMigration":{"available":false},"selection":null,"providerValidation":{"state":"not_checked"},"applicationIntegration":{"state":"unverified"},"admissionReadiness":{"relayScopeId":"relay_scope","evidence":{"state":"current","checkedAtSeconds":0},"state":"ready","sourceGeneration":{"kind":"provision","admissionRevision":0,"policyFingerprint":"` + fingerprintWire + `"},"reason":null},"selectionOperation":null}`
const currentWire = `{"configuration":` + completeWire + `,"precondition":` + preconditionWire + `}`

type identityRoundTrip func(*http.Request) (*http.Response, error)

func (f identityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func identityDecode[T any](t *testing.T, wire string) T {
	t.Helper()
	var value T
	if err := json.Unmarshal([]byte(wire), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func identityFixture(t *testing.T, kind identityattempt.Kind, fn identityRoundTrip) *identityHTTP {
	t.Helper()
	base, err := identity.ParseControlBaseURL("https://console.example/api/cli")
	if err != nil {
		t.Fatal(err)
	}
	slot, err := identityattempt.NewSlot(base, "org_actual", "sample", "sandbox", kind)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(base.String(), &http.Client{Transport: fn})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := client.Identity(slot)
	if err != nil {
		t.Fatal(err)
	}
	return transport.(*identityHTTP)
}

func identityResponse(status int, wire string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(wire))}
}

func identityCode(t *testing.T, err error, code string) {
	t.Helper()
	failure, ok := errors.AsType[*APIError](err)
	if !ok || failure.Code != code {
		t.Fatalf("wanted fixed %s refusal, got %v", code, err)
	}
	if strings.Contains(err.Error(), "CANARY") {
		t.Fatal("fixed error leaked input")
	}
}

func TestIdentityHTTPExactEndpointAndBoundedDeadline(t *testing.T) {
	calls := 0
	client := identityFixture(t, identityattempt.Selection, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/api/cli/v1/projects/sample/identity" ||
			r.URL.Query().Encode() != "action=current&environment=sandbox" || r.ContentLength != 0 ||
			r.Header.Get("Authorization") != "Bearer token_CANARY" || r.Header.Get("Idempotency-Key") != "" {
			t.Error("the fixed endpoint, selectors or bearer changed")
		}
		deadline, present := r.Context().Deadline()
		if !present || time.Until(deadline) > 20*time.Second {
			t.Error("identity call is not bounded")
		}
		return identityResponse(200, currentWire), nil
	})
	_, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token_CANARY", OperationID: "ignored_CANARY"})
	if err != nil || calls != 1 {
		t.Fatalf("one current request failed: %v", err)
	}
}

func TestIdentityHTTPNeverFollowsRedirectOrRetries(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308, 408, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
				calls++
				response := identityResponse(status, `{"code":"UNKNOWN","message":"CANARY"}`)
				response.Header.Set("Location", "https://CANARY.invalid/changed")
				return response, nil
			})
			_, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token"})
			identityCode(t, err, "IDENTITY_UNAVAILABLE")
			if calls != 1 {
				t.Fatal("identity followed or retried")
			}
		})
	}
}

func TestIdentityHTTPResponseAvailabilityCeiling(t *testing.T) {
	for _, status := range []int{200, 503} {
		for _, extra := range []int{0, 1} {
			t.Run(http.StatusText(status)+string(rune('0'+extra)), func(t *testing.T) {
				wire := currentWire
				if status != 200 {
					wire = `{"code":"IDENTITY_UNAVAILABLE"}`
				}
				wire += strings.Repeat(" ", identityResponseLimit-len(wire)+extra)
				client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
					return identityResponse(status, wire), nil
				})
				_, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token"})
				if extra != 0 {
					identityCode(t, err, "IDENTITY_RESPONSE_TOO_LARGE")
				} else if status == 200 && err != nil {
					t.Fatal("exact availability boundary refused", err)
				} else if status != 200 {
					identityCode(t, err, "IDENTITY_UNAVAILABLE")
				}
			})
		}
	}
}

type identityFaultBody struct {
	reader                io.Reader
	readErr, errorOnClose error
	closes                int
}

func (b *identityFaultBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.reader.Read(p)
}
func (b *identityFaultBody) Close() error {
	b.closes++
	return b.errorOnClose
}

func TestIdentityHTTPCheckedReadCloseAndLoss(t *testing.T) {
	for _, fault := range []string{"read", "close", "loss"} {
		t.Run(fault, func(t *testing.T) {
			body := &identityFaultBody{reader: strings.NewReader(currentWire)}
			if fault == "read" {
				body.readErr = errors.New("read_CANARY")
			}
			if fault == "close" {
				body.errorOnClose = errors.New("close_CANARY")
			}
			calls := 0
			client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
				calls++
				if fault == "loss" {
					return nil, errors.New("loss_CANARY")
				}
				return &http.Response{StatusCode: 200, Body: body}, nil
			})
			_, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token"})
			identityCode(t, err, "IDENTITY_UNAVAILABLE")
			if calls != 1 || fault != "loss" && body.closes != 1 {
				t.Fatal("request or close count changed")
			}
		})
	}
}

func TestIdentityHTTPCompleteReceiversRefuseMalformedSuccess(t *testing.T) {
	for _, wire := range []string{
		`null`, `{}`, currentWire + `{}`, strings.Replace(currentWire, `"configuration":`, `"Configuration":`, 1),
		strings.Replace(currentWire, `"configurationVersion":1`, `"configurationVersion":1,"configurationVersion":1`, 1),
		strings.Replace(currentWire, `"identityRecovery":null,`, "", 1),
		strings.Replace(currentWire, `"recoveryGeneration":1`, `"recoveryGeneration":0`, 1),
	} {
		client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
			return identityResponse(200, wire), nil
		})
		_, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token"})
		identityCode(t, err, "IDENTITY_RESULT_INVALID")
	}
}

func TestIdentityHTTPFixedFailureStatusPairing(t *testing.T) {
	for code, failure := range identityTransportFailures {
		if code == "IDENTITY_RESPONSE_TOO_LARGE" {
			continue
		}
		t.Run(code, func(t *testing.T) {
			for _, status := range []int{failure.status, 599} {
				client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
					return identityResponse(status, `{"code":"`+code+`","message":"body_CANARY","url":"https://CANARY.invalid"}`), nil
				})
				_, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token"})
				expected := code
				if status == 599 {
					expected = "IDENTITY_UNAVAILABLE"
				}
				identityCode(t, err, expected)
			}
		})
	}
}

func TestIdentityHTTPRefusesInvalidRequestBeforeDispatch(t *testing.T) {
	calls := 0
	client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
		calls++
		return identityResponse(200, currentWire), nil
	})
	for _, credential := range []CredentialRequest{{}, {AccessToken: "bad\r\nCANARY"}} {
		_, err := client.Current(context.Background(), credential)
		if err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	var result identity.CurrentContext
	credential := CredentialRequest{AccessToken: "token"}
	if err := client.request(context.Background(), credential, "preview", strings.Repeat("x", identityRequestLimit), &result); err == nil {
		t.Fatal("oversize actual request accepted")
	}
	if calls != 0 {
		t.Fatal("invalid request dispatched")
	}
}

func TestIdentityHTTPStandardTransportIsIsolatedFromTransparentReplay(t *testing.T) {
	inherited := &http.Transport{MaxIdleConns: 7,
		TLSClientConfig: &tls.Config{NextProtos: []string{"h2", "http/1.1"}},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
			"h2": func(string, *tls.Conn) http.RoundTripper { return nil },
		},
	}
	for _, configured := range []*http.Transport{nil, inherited} {
		base, err := identity.ParseControlBaseURL("https://console.example/api/cli")
		if err != nil {
			t.Fatal(err)
		}
		slot, err := identityattempt.NewSlot(base, "org_actual", "sample", "sandbox", identityattempt.Selection)
		if err != nil {
			t.Fatal(err)
		}
		client, err := New(base.String(), &http.Client{Transport: configured})
		if err != nil {
			t.Fatal(err)
		}
		// A typed nil RoundTripper is not the default. Use a nil interface.
		if configured == nil {
			client.http.Transport = nil
		}
		transport, err := client.Identity(slot)
		if err != nil {
			t.Fatal(err)
		}
		actual := transport.(*identityHTTP).client.Transport.(*http.Transport)
		if actual == configured || !actual.DisableKeepAlives || actual.Protocols == nil || !actual.Protocols.HTTP1() || actual.Protocols.HTTP2() || actual.TLSNextProto != nil {
			t.Fatal("identity can reuse a connection or negotiate replaying HTTP/2")
		}
		if actual.TLSClientConfig != nil && strings.Join(actual.TLSClientConfig.NextProtos, ",") != "http/1.1" {
			t.Fatal("cloned identity TLS still offers an alternate protocol")
		}
		if configured != nil && (configured.DisableKeepAlives || configured.MaxIdleConns != 7 ||
			strings.Join(configured.TLSClientConfig.NextProtos, ",") != "h2,http/1.1" ||
			len(configured.TLSNextProto) != 1 || configured.TLSNextProto["h2"] == nil) {
			t.Fatal("identity changed caller transport, handler or TLS configuration")
		}
	}
}

// This controlled context models delayed notification with a stable deadline.
// Tests advance the private HTTP clock. They do not measure timer or kernel time.
type controlledIdentityDeadline struct {
	context.Context
	deadline time.Time
}

func (c *controlledIdentityDeadline) Deadline() (time.Time, bool) {
	return c.deadline, true
}

type controlledIdentityDeadlineBody struct {
	io.ReadCloser
	expire func()
	closes int
}

func (b *controlledIdentityDeadlineBody) Close() error {
	b.closes++
	err := b.ReadCloser.Close()
	b.expire()
	return err
}

type controlledIdentityDecodedCurrent struct {
	value  identity.CurrentContext
	expire func()
}

func (v *controlledIdentityDecodedCurrent) UnmarshalJSON(data []byte) error {
	// The real complete receiver must qualify before advancing the clock.
	if err := json.Unmarshal(data, &v.value); err != nil {
		return err
	}
	v.expire()
	return nil
}

func TestIdentityHTTPControlledLogicalDeadlineBeforeDispatch(t *testing.T) {
	parent := &controlledIdentityDeadline{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
	if parent.Err() != nil {
		t.Fatal("controlled delayed-notification fixture is invalid")
	}
	calls := 0
	client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
		calls++
		return identityResponse(200, currentWire), nil
	})
	_, err := client.Current(parent, CredentialRequest{AccessToken: "token"})
	identityCode(t, err, "IDENTITY_UNAVAILABLE")
	if calls != 0 || parent.Err() != nil {
		t.Fatal("logical expiration dispatched or required a timer notification")
	}
}

func TestIdentityHTTPControlledLogicalDeadlineAfterClose(t *testing.T) {
	now := time.Now()
	parent := &controlledIdentityDeadline{Context: context.Background(), deadline: now.Add(time.Second)}
	body := &controlledIdentityDeadlineBody{ReadCloser: io.NopCloser(strings.NewReader(currentWire)),
		expire: func() { now = parent.deadline.Add(time.Second) }}
	calls := 0
	client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: body}, nil
	})
	client.now = func() time.Time { return now }
	_, err := client.Current(parent, CredentialRequest{AccessToken: "token"})
	identityCode(t, err, "IDENTITY_UNAVAILABLE")
	if calls != 1 || body.closes != 1 || parent.Err() != nil {
		t.Fatal("post-close logical expiration was not checked with one completed request")
	}
}

func TestIdentityHTTPControlledLogicalDeadlineAfterCompleteDecode(t *testing.T) {
	now := time.Now()
	parent := &controlledIdentityDeadline{Context: context.Background(), deadline: now.Add(time.Second)}
	result := controlledIdentityDecodedCurrent{expire: func() { now = parent.deadline.Add(time.Second) }}
	calls := 0
	client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
		calls++
		return identityResponse(200, currentWire), nil
	})
	client.now = func() time.Time { return now }
	err := client.request(parent, CredentialRequest{AccessToken: "token"}, "current", nil, &result)
	identityCode(t, err, "IDENTITY_UNAVAILABLE")
	if calls != 1 || parent.Err() != nil || result.value.Validate() != nil {
		t.Fatal("complete decoding did not qualify before the logical deadline refusal")
	}
}

func TestIdentityHTTPInvalidClockCannotGrantARequest(t *testing.T) {
	var absent *identityHTTP
	if absent.callCurrent(context.Background()) || (&identityHTTP{}).callCurrent(context.Background()) {
		t.Fatal("invalid HTTP clock or receiver granted a live call")
	}
	calls := 0
	client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
		calls++
		return identityResponse(200, currentWire), nil
	})
	client.now = nil
	_, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token"})
	identityCode(t, err, "IDENTITY_UNAVAILABLE")
	if calls != 0 {
		t.Fatal("invalid clock reached HTTP")
	}
}

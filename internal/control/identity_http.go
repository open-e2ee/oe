package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

const identityResponseLimit = 1_048_576
const identityRequestLimit = 100_000

var identityTransportFailures = map[string]struct {
	status  int
	message string
}{
	"AUTHENTICATION_REQUIRED":      {401, "An authenticated session is required."},
	"INVALID_SESSION":              {401, "The authenticated session is invalid."},
	"ORGANIZATION_REQUIRED":        {409, "A current Organization is required."},
	"IDENTITY_INPUT_INVALID":       {400, "The identity input is invalid."},
	"IDENTITY_METHOD_NOT_ALLOWED":  {405, "This identity method is not allowed."},
	"IDENTITY_CONTEXT_CHANGED":     {409, "The addressed identity authority changed. Preserve the retained attempt."},
	"IDENTITY_CHANGE_REFUSED":      {409, "The identity change was refused."},
	"NATIVE_IDENTITY_UNAVAILABLE":  {409, "This native identity operation is unavailable."},
	"IDENTITY_CONFLICT":            {409, "The identity operation conflicts with current state."},
	"PROJECT_NOT_FOUND":            {404, "The addressed project is unavailable."},
	"ENVIRONMENT_NOT_FOUND":        {404, "The addressed environment is unavailable."},
	"IDENTITY_OPERATION_NOT_FOUND": {404, "The exact identity operation was not found."},
	"IMPERSONATED_SESSION":         {403, "This session cannot perform the identity operation."},
	"IDENTITY_CONTROL_DENIED":      {403, "Current resource authority refused the identity operation."},
	"IDENTITY_RESULT_INVALID":      {502, "The identity result is invalid. Preserve the retained attempt."},
	"AUTHORITY_UNAVAILABLE":        {503, "Current resource authority is unavailable."},
	"IDENTITY_UNAVAILABLE":         {503, "The identity operation is unavailable. Preserve the retained attempt."},
	"IDENTITY_RESPONSE_TOO_LARGE":  {503, "The identity response exceeds this transport's availability limit. Preserve the retained attempt."},
}

func identityTransportFailure(code string) error {
	failure, ok := identityTransportFailures[code]
	if !ok {
		code = "IDENTITY_UNAVAILABLE"
		failure = identityTransportFailures[code]
	}
	return &APIError{Status: failure.status, Code: code, Message: failure.message}
}

type identityHTTP struct {
	slot             identityattempt.Slot
	client           http.Client
	protectionBypass string
	now              func() time.Time
}

func (c *Client) Identity(slot identityattempt.Slot) (IdentityTransport, error) {
	if c == nil || c.baseURL == nil || c.http == nil || slot.Validate() != nil {
		return nil, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	base, err := identity.ParseControlBaseURL(c.baseURL.String())
	if err != nil || !base.Equal(slot.ControlBase()) {
		return nil, identityTransportFailure("IDENTITY_CONTEXT_CHANGED")
	}
	client := *c.http
	// A fresh HTTP/1 connection also avoids net/http's transparent replay on
	// reused connections or HTTP/2 stream refusal. Custom RoundTrippers are
	// explicit dependencies and receive exactly one RoundTrip invocation.
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if actual, ok := transport.(*http.Transport); ok {
		isolated := actual.Clone()
		isolated.DisableKeepAlives = true
		isolated.ForceAttemptHTTP2 = false
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		isolated.Protocols = protocols
		// Clone can inherit an already installed h2 handler and ALPN list.
		isolated.TLSNextProto = nil
		if isolated.TLSClientConfig != nil {
			isolated.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
		client.Transport = isolated
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// Identity never uses a caller cookie jar or follows a changed destination.
	client.Jar = nil
	return &identityHTTP{slot: slot, client: client, protectionBypass: c.protectionBypass, now: time.Now}, nil
}

// A timer notification can lag its logical deadline. Check both at each phase.
func (c *identityHTTP) callCurrent(ctx context.Context) bool {
	if c == nil || c.now == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, bounded := ctx.Deadline()
	return !bounded || c.now().Before(deadline)
}

// request completes the one HTTP attempt and checked body closure synchronously.
// The limit is an availability policy, not a maximum accepted identity schema.
func (c *identityHTTP) request(ctx context.Context, credential CredentialRequest, action string, body any, result any) error {
	if c == nil || c.slot.Validate() != nil || ctx == nil || credential.AccessToken == "" || strings.ContainsAny(credential.AccessToken, "\r\n") {
		return identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	query := url.Values{"action": {action}, "environment": {c.slot.Environment()}}
	endpoint, err := c.slot.ControlBase().Endpoint([]string{"v1", "projects", c.slot.ProjectSlug(), "identity"}, query)
	if err != nil {
		return identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	method := http.MethodPost
	var data []byte
	if action == "current" {
		if body != nil {
			return identityTransportFailure("IDENTITY_INPUT_INVALID")
		}
		method = http.MethodGet
	} else {
		data, err = json.Marshal(body)
		if err != nil || len(data) > identityRequestLimit {
			return identityTransportFailure("IDENTITY_INPUT_INVALID")
		}
	}
	callContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(callContext, method, endpoint, bytes.NewReader(data))
	if err != nil {
		return identityTransportFailure("IDENTITY_UNAVAILABLE")
	}
	// No identity request supplies rewind or idempotency authority to a transport.
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential.AccessToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.protectionBypass != "" {
		request.Header.Set("x-vercel-protection-bypass", c.protectionBypass)
	}
	if !c.callCurrent(callContext) {
		return identityTransportFailure("IDENTITY_UNAVAILABLE")
	}
	response, err := c.client.Do(request)
	if err != nil {
		// A response returned with an error is not a usable receipt.
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return identityTransportFailure("IDENTITY_UNAVAILABLE")
	}
	if response == nil || response.Body == nil {
		return identityTransportFailure("IDENTITY_UNAVAILABLE")
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, identityResponseLimit+1))
	closeErr := response.Body.Close()
	if closeErr != nil || readErr != nil || !c.callCurrent(callContext) {
		return identityTransportFailure("IDENTITY_UNAVAILABLE")
	}
	if len(data) > identityResponseLimit {
		return identityTransportFailure("IDENTITY_RESPONSE_TOO_LARGE")
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(data, &failure) == nil {
			if allowed, ok := identityTransportFailures[failure.Code]; ok &&
				failure.Code != "IDENTITY_RESPONSE_TOO_LARGE" && allowed.status == response.StatusCode {
				return identityTransportFailure(failure.Code)
			}
		}
		return identityTransportFailure("IDENTITY_UNAVAILABLE")
	}
	// Each complete receiver owns recursive closure, duplicate keys and EOF.
	if result == nil || json.Unmarshal(data, result) != nil {
		return identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	if !c.callCurrent(callContext) {
		return identityTransportFailure("IDENTITY_UNAVAILABLE")
	}
	return nil
}

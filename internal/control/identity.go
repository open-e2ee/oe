package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/open-e2ee/oe/internal/identity"
)

var identityFailures = map[string]struct {
	status  int
	message string
}{
	"AUTHENTICATION_REQUIRED":        {401, "Run oe auth login first."},
	"INVALID_SESSION":                {401, "Run oe auth login again."},
	"ORGANIZATION_REQUIRED":          {409, "Select an Organization with oe org switch."},
	"PROJECT_NOT_FOUND":              {404, "Relay project not found."},
	"ENVIRONMENT_NOT_FOUND":          {404, "Relay environment not found."},
	"IMPERSONATED_SESSION":           {403, "This session cannot perform the check."},
	"AUTHORITY_UNAVAILABLE":          {503, "Current resource authority is unavailable."},
	"IDENTITY_CHECK_INVALID":         {400, "The identity check input is invalid."},
	"IDENTITY_PROFILE_UNSUPPORTED":   {400, "This identity profile is not supported by this check."},
	"IDENTITY_ASSERTION_INVALID":     {400, "The test assertion is invalid. Request a fresh assertion and check the public profile."},
	"IDENTITY_CHECK_UNAVAILABLE":     {503, "The identity check is unavailable."},
	"DEPLOYMENT_PROTECTION_REQUIRED": {401, "Vercel deployment protection blocked the identity check. Set OE_PROTECTION_BYPASS to a valid bypass and retry."},
}

func identityFailure(code string) error {
	v, ok := identityFailures[code]
	if !ok {
		code = "IDENTITY_CHECK_UNAVAILABLE"
		v = identityFailures[code]
	}
	return &APIError{Code: code, Status: v.status, Message: v.message}
}

// CheckIdentity has one bounded attempt and never exposes arbitrary error text.
func (c *Client) CheckIdentity(ctx context.Context, credential CredentialRequest, project, environment string, draft identity.Draft) (identity.Check, error) {
	var result identity.Check
	if (environment != "sandbox" && environment != "production") ||
		(draft.Target.Mode != "device-owned" && draft.Target.Mode != "custom-token" && draft.Target.Mode != "provider-bound") ||
		(draft.Target.Mode == "device-owned" && draft.Assertion != "") ||
		(draft.Target.Mode != "device-owned" && (draft.Assertion == "" || len(draft.Assertion) > 65_536)) {
		return result, identityFailure("IDENTITY_CHECK_INVALID")
	}
	body, err := json.Marshal(draft)
	if err != nil || len(body) > 100_000 {
		return result, identityFailure("IDENTITY_CHECK_INVALID")
	}
	u := *c.baseURL
	u.Path = path.Join(u.Path, projectPath(project, "identity/check"))
	u.RawQuery = url.Values{"environment": {environment}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return result, identityFailure("IDENTITY_CHECK_UNAVAILABLE")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential.AccessToken)
	if c.protectionBypass != "" {
		request.Header.Set("x-vercel-protection-bypass", c.protectionBypass)
	}
	if c.cliVersion != "" {
		request.Header.Set("OpenE2EE-CLI-Version", c.cliVersion)
	}
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return result, identityFailure("IDENTITY_CHECK_UNAVAILABLE")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16_385))
	if err != nil || len(data) > 16_384 {
		return result, identityFailure("IDENTITY_CHECK_UNAVAILABLE")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure apiError
		if json.Unmarshal(data, &failure) == nil {
			if failure.deploymentProtection(response.StatusCode) {
				return result, identityFailure("DEPLOYMENT_PROTECTION_REQUIRED")
			}
			if allowed, ok := identityFailures[failure.Code]; ok && allowed.status == response.StatusCode {
				return result, identityFailure(failure.Code)
			}
		}
		return result, identityFailure("IDENTITY_CHECK_UNAVAILABLE")
	}
	if json.Unmarshal(data, &result) != nil || !result.Matches(draft.Target, environment) {
		return identity.Check{}, identityFailure("IDENTITY_CHECK_UNAVAILABLE")
	}
	return result, nil
}

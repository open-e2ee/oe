package control

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type Client struct {
	baseURL          *url.URL
	http             *http.Client
	protectionBypass string
}

type apiError struct {
	Code            string          `json:"code"`
	Message         string          `json:"message"`
	Error           string          `json:"error"`
	CanAccept       bool            `json:"canAccept"`
	Documents       []TermsDocument `json:"documents"`
	BillingSetupURL string          `json:"billingSetupUrl"`
}

type authConfiguration struct {
	ClientID                    string `json:"clientId"`
	DeviceAuthorizationEndpoint string `json:"deviceAuthorizationEndpoint"`
	SchemaVersion               int    `json:"schemaVersion"`
	TokenEndpoint               string `json:"tokenEndpoint"`
}

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
}

type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// oauthErrorResponse is a WorkOS refusal. Error is the OAuth error code.
// WorkOS puts some authentication codes in Code instead, and gives
// AuthKitRedirectURL when the person must sign in on the hosted page.
type oauthErrorResponse struct {
	Error              string `json:"error"`
	Code               string `json:"code"`
	AuthKitRedirectURL string `json:"authkit_redirect_url"`
}

// signInReasons are the WorkOS codes that refuse to move a session to an
// organization until the person signs in to it on the hosted page.
var signInReasons = map[string]bool{
	"sso_required": true, "mfa_enrollment": true, "organization_authentication_methods_required": true,
}

// signInReason gives the reason of a refusal that needs a new sign-in, or ""
// for any other refusal.
func (failure oauthErrorResponse) signInReason() string {
	for _, code := range []string{failure.Error, failure.Code} {
		if signInReasons[code] {
			return code
		}
	}
	if failure.AuthKitRedirectURL != "" {
		return cmp.Or(failure.Code, failure.Error, "authkit_redirect_url")
	}
	return ""
}

var (
	errAuthorizationPending = errors.New("authorization pending")
	errSlowDown             = errors.New("authorization polling must slow down")
	ErrSessionExpired       = errors.New("WorkOS session expired")
	// ErrAuthorizationExpired is a device code that expired before a person
	// approved it.
	ErrAuthorizationExpired = errors.New("browser authorization expired")
)

// ErrOrganizationsNotAvailable is a control API that does not list
// organizations, because it is older than the organization commands.
var ErrOrganizationsNotAvailable = errors.New("the control API does not list organizations")

// SignInRequiredError is a WorkOS refusal to move a session to an
// organization until the person signs in to that organization on the hosted
// page, for example with SSO or after an MFA enrollment. Reason is the WorkOS
// code.
type SignInRequiredError struct {
	Reason string
}

func (e *SignInRequiredError) Error() string {
	return "WorkOS requires a new sign-in for the organization (" + e.Reason + ")"
}

type oauthRequestError struct {
	status    int
	transient bool
}

func (e *oauthRequestError) Error() string {
	if e.status == 0 {
		return "authentication service request failed"
	}
	return fmt.Sprintf("authentication service returned status %d", e.status)
}

func New(baseURL string, client *http.Client) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid control URL %q", baseURL)
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{baseURL: parsed, http: client}, nil
}

func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/health", CredentialRequest{}, nil, nil)
}

func (c *Client) StartAuthorization(ctx context.Context, request AuthorizationRequest) (Authorization, error) {
	var configuration authConfiguration
	if err := c.do(ctx, http.MethodGet, "/v1/auth/configuration", CredentialRequest{}, nil, &configuration); err != nil {
		return Authorization{}, err
	}
	if err := c.validateAuthConfiguration(configuration); err != nil {
		return Authorization{}, err
	}
	var response deviceAuthorizationResponse
	err := c.doForm(ctx, configuration.DeviceAuthorizationEndpoint, url.Values{
		"client_id": {configuration.ClientID},
	}, &response)
	if err != nil {
		return Authorization{}, err
	}
	verificationURL := response.VerificationURIComplete
	if verificationURL == "" {
		verificationURL = response.VerificationURI
	}
	if response.DeviceCode == "" || response.UserCode == "" || response.ExpiresIn < 1 || verificationURL == "" {
		return Authorization{}, errors.New("WorkOS returned an incomplete device authorization")
	}
	for _, candidate := range []string{response.VerificationURIComplete, response.VerificationURI} {
		if candidate != "" && !validVerificationURL(candidate) {
			return Authorization{}, errors.New("WorkOS returned an invalid verification URL")
		}
	}
	return Authorization{
		CodeInURL: response.VerificationURIComplete != "",
		ClientID:  configuration.ClientID, DeviceCode: response.DeviceCode,
		ExpiresInSeconds: response.ExpiresIn, IntervalSeconds: response.Interval,
		TokenEndpoint: configuration.TokenEndpoint, UserCode: response.UserCode,
		VerificationURL: verificationURL, BareVerificationURL: response.VerificationURI,
	}, nil
}

// validVerificationURL accepts only an HTTPS page with a host and no user
// information, because the CLI opens it and shows it to the person.
func validVerificationURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}

func (c *Client) PollAuthorization(ctx context.Context, authorization Authorization) (Token, error) {
	if authorization.ClientID == "" || authorization.DeviceCode == "" || authorization.TokenEndpoint == "" {
		return Token{}, errors.New("the device authorization is incomplete")
	}
	var response oauthTokenResponse
	err := c.doForm(ctx, authorization.TokenEndpoint, url.Values{
		"client_id":   {authorization.ClientID},
		"device_code": {authorization.DeviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}, &response)
	if errors.Is(err, errAuthorizationPending) {
		return Token{Pending: true}, nil
	}
	if errors.Is(err, errSlowDown) {
		return Token{
			Pending:           true,
			RetryAfterSeconds: max(authorization.IntervalSeconds+5, 5),
		}, nil
	}
	if err != nil {
		return Token{}, sanitizeCredentialError(err, authorization.DeviceCode)
	}
	return token(response)
}

// RefreshAuthorization trades refreshToken for a new token pair. With an
// organizationID, the refresh grant also moves the session to that
// organization. The form carries organization_id only when it is set.
func (c *Client) RefreshAuthorization(ctx context.Context, refreshToken, organizationID string) (Token, error) {
	var configuration authConfiguration
	if err := c.do(ctx, http.MethodGet, "/v1/auth/configuration", CredentialRequest{}, nil, &configuration); err != nil {
		return Token{}, err
	}
	if err := c.validateAuthConfiguration(configuration); err != nil {
		return Token{}, err
	}
	if refreshToken == "" {
		return Token{}, errors.New("the refresh credential is empty")
	}
	form := url.Values{
		"client_id":     {configuration.ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	if organizationID != "" {
		form.Set("organization_id", organizationID)
	}
	for attempt := 0; attempt < 3; attempt++ {
		var response oauthTokenResponse
		err := c.doForm(ctx, configuration.TokenEndpoint, form, &response)
		if err == nil {
			return token(response)
		}
		var requestError *oauthRequestError
		if !errors.As(err, &requestError) || !requestError.transient {
			return Token{}, sanitizeCredentialError(err, refreshToken)
		}
		if attempt == 2 {
			return Token{}, sanitizeCredentialError(err, refreshToken)
		}
		delay := time.Duration(250*(1<<attempt)) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Token{}, ctx.Err()
		case <-timer.C:
		}
	}
	panic("unreachable")
}

func (c *Client) validateAuthConfiguration(configuration authConfiguration) error {
	if configuration.SchemaVersion != 1 || !strings.HasPrefix(configuration.ClientID, "client_") {
		return errors.New("the CLI authentication configuration is invalid")
	}
	for value, expectedPath := range map[string]string{
		configuration.DeviceAuthorizationEndpoint: "/user_management/authorize/device",
		configuration.TokenEndpoint:               "/user_management/authenticate",
	} {
		parsed, err := url.Parse(value)
		if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != expectedPath {
			return errors.New("the CLI authentication configuration is invalid")
		}
		production := parsed.Scheme == "https" && parsed.Host == "api.workos.com"
		loopback := isLoopback(c.baseURL.Hostname()) && parsed.Scheme == c.baseURL.Scheme && parsed.Host == c.baseURL.Host
		if !production && !loopback {
			return errors.New("the CLI authentication configuration is invalid")
		}
	}
	return nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (c *Client) doForm(ctx context.Context, endpoint string, form url.Values, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.http.Do(request)
	if err != nil {
		return &oauthRequestError{transient: true}
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 1<<20)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure oauthErrorResponse
		_ = json.NewDecoder(limited).Decode(&failure)
		if reason := failure.signInReason(); reason != "" {
			return &SignInRequiredError{Reason: reason}
		}
		switch failure.Error {
		case "authorization_pending":
			return errAuthorizationPending
		case "slow_down":
			return errSlowDown
		case "access_denied":
			return errors.New("browser authorization was denied")
		case "expired_token":
			return ErrAuthorizationExpired
		case "invalid_grant":
			return ErrSessionExpired
		default:
			return &oauthRequestError{
				status: response.StatusCode,
				transient: response.StatusCode == http.StatusRequestTimeout ||
					response.StatusCode == http.StatusTooManyRequests ||
					response.StatusCode >= 500,
			}
		}
	}
	if err := json.NewDecoder(limited).Decode(output); err != nil {
		return fmt.Errorf("decode authentication response: %w", err)
	}
	return nil
}

func token(response oauthTokenResponse) (Token, error) {
	if response.AccessToken == "" || response.RefreshToken == "" {
		return Token{}, errors.New("WorkOS returned an incomplete session")
	}
	expiresAt, err := jwtExpiration(response.AccessToken)
	if err != nil {
		return Token{}, err
	}
	return Token{
		AccessToken: response.AccessToken, ExpiresAt: expiresAt,
		RefreshToken: response.RefreshToken,
	}, nil
}

func jwtExpiration(value string) (string, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return "", errors.New("WorkOS returned an invalid access token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("WorkOS returned an invalid access token")
	}
	var claims struct {
		ExpiresAt int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.ExpiresAt < 1 {
		return "", errors.New("WorkOS returned an invalid access token")
	}
	return time.Unix(claims.ExpiresAt, 0).UTC().Format(time.RFC3339), nil
}

func (c *Client) BootstrapSandbox(ctx context.Context, credential CredentialRequest, request BootstrapRequest) (Bootstrap, error) {
	var response Bootstrap
	err := c.do(ctx, http.MethodPost, "/v1/projects/bootstrap", credential, request, &response)
	return response, err
}

func (c *Client) Activation(ctx context.Context, credential CredentialRequest, project string) (Activation, error) {
	var response Activation
	err := c.do(ctx, http.MethodGet, projectPath(project, "activation"), credential, nil, &response)
	return response, err
}

func (c *Client) Plan(ctx context.Context, credential CredentialRequest, request PlanRequest) (Plan, error) {
	var response Plan
	err := c.do(ctx, http.MethodPost, projectPath(request.ProjectSlug, "deploys/plan"), credential, request, &response)
	return response, err
}

func (c *Client) Deploy(ctx context.Context, credential CredentialRequest, request DeployRequest) (Deployment, error) {
	var response Deployment
	err := c.do(ctx, http.MethodPost, "/v1/deploys", credential, request, &response)
	return response, err
}

func (c *Client) GetProject(ctx context.Context, credential CredentialRequest, project string) (Project, error) {
	var response Project
	err := c.do(ctx, http.MethodGet, projectPath(project, ""), credential, nil, &response)
	return response, err
}

func (c *Client) ListProjects(ctx context.Context, credential CredentialRequest) ([]ProjectSummary, error) {
	response := []ProjectSummary{}
	err := c.do(ctx, http.MethodGet, "/v1/projects", credential, nil, &response)
	return response, err
}

func (c *Client) Notifications(ctx context.Context, credential CredentialRequest, project, environment string) (NotificationConfiguration, error) {
	var response NotificationConfiguration
	endpoint := projectPath(project, "notifications") + "?environment=" + url.QueryEscape(environment)
	err := c.do(ctx, http.MethodGet, endpoint, credential, nil, &response)
	return response, err
}

func (c *Client) ConfigureNotifications(ctx context.Context, credential CredentialRequest, project string, request NotificationConfigurationRequest) (NotificationConfiguration, error) {
	var response NotificationConfiguration
	err := c.do(ctx, http.MethodPost, projectPath(project, "notifications"), credential, request, &response)
	return response, err
}

func (c *Client) Terms(ctx context.Context, credential CredentialRequest) (Terms, error) {
	var response Terms
	if err := c.do(ctx, http.MethodGet, "/v1/terms", credential, nil, &response); err != nil {
		return Terms{}, err
	}
	return response, validateTerms(response)
}

func (c *Client) AcceptTerms(ctx context.Context, credential CredentialRequest, request TermsAcceptanceRequest) (TermsAcceptance, error) {
	var response TermsAcceptance
	if err := c.do(ctx, http.MethodPost, "/v1/terms/acceptance", credential, request, &response); err != nil {
		return TermsAcceptance{}, err
	}
	return response, validateTerms(response.Terms)
}

// Session reads the identity behind the access token: the person, the
// organization, the role, and the agent registration of an agent session.
func (c *Client) Session(ctx context.Context, credential CredentialRequest) (Session, error) {
	var response Session
	if err := c.do(ctx, http.MethodGet, "/v1/auth/session", credential, nil, &response); err != nil {
		return Session{}, err
	}
	if err := validateSession(response); err != nil {
		return Session{}, err
	}
	return response, nil
}

// ListOrganizations reads the organizations of the person and the
// organization of the session. A control API without the list answers 404,
// which gives ErrOrganizationsNotAvailable.
func (c *Client) ListOrganizations(ctx context.Context, credential CredentialRequest) (OrganizationList, error) {
	var response OrganizationList
	err := c.do(ctx, http.MethodGet, "/v1/organizations", credential, nil, &response)
	if refusal, ok := errors.AsType[*APIError](err); ok && refusal.Status == http.StatusNotFound {
		return OrganizationList{}, fmt.Errorf("%w: %w", ErrOrganizationsNotAvailable, err)
	}
	if err != nil {
		return OrganizationList{}, err
	}
	if err := validateOrganizations(response); err != nil {
		return OrganizationList{}, err
	}
	if response.Organizations == nil {
		response.Organizations = []Organization{}
	}
	return response, nil
}

func validateOrganizations(list OrganizationList) error {
	if list.SchemaVersion != 1 {
		return fmt.Errorf("the control API answered an unknown organization list schema version %d", list.SchemaVersion)
	}
	for _, organization := range list.Organizations {
		if organization.ID == "" || organization.Name == "" {
			return errors.New("the control API answered an incomplete organization list")
		}
	}
	return nil
}

func validateSession(session Session) error {
	if session.SchemaVersion != 1 {
		return fmt.Errorf("the control API answered an unknown session schema version %d", session.SchemaVersion)
	}
	if session.User.ID == "" || session.User.Email == "" || session.Organization.ID == "" || session.Organization.Name == "" ||
		(session.Agent != nil && session.Agent.RegistrationID == "") {
		return errors.New("the control API answered an incomplete session")
	}
	return nil
}

func validateTerms(terms Terms) error {
	if terms.State != TermsAccepted && terms.State != TermsRequired {
		return fmt.Errorf("the control API answered an unknown terms state %q", terms.State)
	}
	return nil
}

// SetProtectionBypass sets the secret for control requests. Call it before use.
func (c *Client) SetProtectionBypass(value string) {
	c.protectionBypass = strings.TrimSpace(value)
}

func (c *Client) do(ctx context.Context, method, endpoint string, credential CredentialRequest, body, output any) (err error) {
	defer func() {
		err = sanitizeCredentialError(err, credential.AccessToken, c.protectionBypass)
	}()
	httpClient := *c.http
	httpClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != c.baseURL.Scheme || request.URL.Host != c.baseURL.Host {
			request.Header.Del("x-vercel-protection-bypass")
		}
		if c.http.CheckRedirect != nil {
			return c.http.CheckRedirect(request, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	encoded, err := encodeBody(body)
	if err != nil {
		return err
	}
	retryable := method != http.MethodPost || credential.OperationID != ""
	for attempt := 0; attempt < 3; attempt++ {
		requestURL := *c.baseURL
		endpointPath, rawQuery, _ := strings.Cut(endpoint, "?")
		requestURL.Path = path.Join(strings.TrimSuffix(c.baseURL.Path, "/"), endpointPath)
		requestURL.RawQuery = rawQuery
		request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(encoded))
		if err != nil {
			return err
		}
		request.Header.Set("Accept", "application/json")
		if c.protectionBypass != "" {
			request.Header.Set("x-vercel-protection-bypass", c.protectionBypass)
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if credential.AccessToken != "" {
			request.Header.Set("Authorization", "Bearer "+credential.AccessToken)
		}
		if credential.OperationID != "" {
			request.Header.Set("Idempotency-Key", credential.OperationID)
		}
		response, err := httpClient.Do(request)
		if err != nil {
			if attempt < 2 && retryable {
				continue
			}
			return fmt.Errorf("control request failed: %w", err)
		}
		err = decodeResponse(response, output)
		response.Body.Close()
		if err == nil {
			return nil
		}
		if apiError, ok := errors.AsType[*APIError](err); attempt < 2 && retryable && ok && apiError.retryable() {
			continue
		}
		return err
	}
	return errors.New("control request exhausted retries")
}

func sanitizeCredentialError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	redact := func(value string) string {
		for _, secret := range secrets {
			if secret != "" {
				value = strings.ReplaceAll(value, secret, "[redacted]")
			}
		}
		return value
	}
	cause := err
	if refusal, ok := errors.AsType[*APIError](err); ok {
		copy := *refusal
		copy.Code = redact(copy.Code)
		copy.Message = redact(copy.Message)
		copy.BillingSetupURL = redact(copy.BillingSetupURL)
		copy.Documents = append([]TermsDocument(nil), copy.Documents...)
		for i := range copy.Documents {
			copy.Documents[i].Name = redact(copy.Documents[i].Name)
			copy.Documents[i].URL = redact(copy.Documents[i].URL)
			copy.Documents[i].Version = redact(copy.Documents[i].Version)
		}
		cause = &copy
	}
	return &sanitizedError{cause: cause, message: redact(err.Error())}
}

type sanitizedError struct {
	cause   error
	message string
}

func (e *sanitizedError) Error() string { return e.message }
func (e *sanitizedError) Unwrap() error { return e.cause }

// APIError is a control API refusal. Code is the stable value a caller
// switches on; the console omits it for some refusals. A TERMS_REQUIRED
// refusal also carries CanAccept and the Documents to accept. A CARD_REQUIRED
// refusal carries the BillingSetupURL where a person adds the card.
type APIError struct {
	Status          int
	Code            string
	Message         string
	CanAccept       bool
	Documents       []TermsDocument
	BillingSetupURL string
}

func (e *APIError) Error() string { return e.Message }

func (e *APIError) retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

func decodeResponse(response *http.Response, output any) error {
	limited := io.LimitReader(response.Body, 1<<20)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var problem apiError
		_ = json.NewDecoder(limited).Decode(&problem)
		message := strings.TrimSpace(cmp.Or(problem.Message, problem.Error))
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return &APIError{
			Status: response.StatusCode, Code: problem.Code, Message: message,
			CanAccept: problem.CanAccept, Documents: problem.Documents,
			BillingSetupURL: problem.BillingSetupURL,
		}
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, limited)
		return nil
	}
	if err := json.NewDecoder(limited).Decode(output); err != nil {
		return fmt.Errorf("decode control response: %w", err)
	}
	return nil
}

func encodeBody(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode control request: %w", err)
	}
	return encoded, nil
}

func projectPath(project, suffix string) string {
	base := "/v1/projects/" + url.PathEscape(project)
	if suffix == "" {
		return base
	}
	return base + "/" + suffix
}

package control

import "context"

type API interface {
	Health(context.Context) error
	StartAuthorization(context.Context, AuthorizationRequest) (Authorization, error)
	PollAuthorization(context.Context, Authorization) (Token, error)
	RefreshAuthorization(context.Context, string) (Token, error)
	BootstrapSandbox(context.Context, CredentialRequest, BootstrapRequest) (Bootstrap, error)
	Activation(context.Context, CredentialRequest, string) (Activation, error)
	Plan(context.Context, CredentialRequest, PlanRequest) (Plan, error)
	Deploy(context.Context, CredentialRequest, DeployRequest) (Deployment, error)
	GetProject(context.Context, CredentialRequest, string) (Project, error)
	ListProjects(context.Context, CredentialRequest) ([]ProjectSummary, error)
	Notifications(context.Context, CredentialRequest, string, string) (NotificationConfiguration, error)
	ConfigureNotifications(context.Context, CredentialRequest, string, NotificationConfigurationRequest) (NotificationConfiguration, error)
	Terms(context.Context, CredentialRequest) (Terms, error)
	AcceptTerms(context.Context, CredentialRequest, TermsAcceptanceRequest) (TermsAcceptance, error)
	Session(context.Context, CredentialRequest) (Session, error)
}

type CredentialRequest struct {
	AccessToken string
	OperationID string
}

type AuthorizationRequest struct{}

type Authorization struct {
	ClientID         string `json:"-"`
	DeviceCode       string `json:"-"`
	ExpiresInSeconds int    `json:"-"`
	IntervalSeconds  int    `json:"intervalSeconds"`
	TokenEndpoint    string `json:"-"`
	UserCode         string `json:"userCode"`
	VerificationURL  string `json:"verificationUrl"`
	// BareVerificationURL is the page without the code, where a person on
	// another device types the code. It is empty when WorkOS gives none.
	BareVerificationURL string `json:"bareVerificationUrl"`
	// CodeInURL is true when VerificationURL already carries the user code, so
	// the page asks the person to confirm the code instead of typing it.
	CodeInURL bool `json:"-"`
}

type Token struct {
	Pending           bool   `json:"pending"`
	AccessToken       string `json:"accessToken,omitempty"`
	ExpiresAt         string `json:"expiresAt,omitempty"`
	RefreshToken      string `json:"refreshToken,omitempty"`
	RetryAfterSeconds int    `json:"-"`
}

// BootstrapRequest creates the project with its Sandbox environment when the
// organization has no project with the slug. Name is the display name.
type BootstrapRequest struct {
	Name        string             `json:"name,omitempty"`
	Policy      RelayPolicyRequest `json:"policy"`
	ProjectSlug string             `json:"project"`
	Writer      string             `json:"writer"`
}

// Bootstrap is the answer to a BootstrapRequest. Created is false when the
// project existed, and then the answer holds no Sandbox connection.
type Bootstrap struct {
	Created         bool   `json:"created"`
	ProjectID       string `json:"projectId"`
	ProjectSlug     string `json:"project"`
	Writer          string `json:"writer"`
	Revision        string `json:"revision"`
	SandboxRelayURL string `json:"sandboxRelayUrl"`
	Environment     string `json:"environment"`
}

type Activation struct {
	FirstDevice       bool `json:"firstDevice"`
	FirstAcknowledged bool `json:"firstAcknowledged"`
}

type PlanRequest struct {
	Environment string             `json:"environment"`
	Policy      RelayPolicyRequest `json:"policy"`
	ProjectSlug string             `json:"project"`
	Writer      string             `json:"writer"`
}

// RelayPolicyRequest is the Relay policy of a plan or a deploy. The control
// API owns the wire name deliveryTtlSeconds. The CLI calls the same value
// delivery retention, as the config does.
type RelayPolicyRequest struct {
	AttachmentRetentionSeconds int `json:"attachmentRetentionSeconds"`
	DeliveryRetentionSeconds   int `json:"deliveryTtlSeconds"`
}

type Change struct {
	Path   string `json:"path"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

type Plan struct {
	ID               string   `json:"id"`
	ProjectSlug      string   `json:"project"`
	Environment      string   `json:"environment"`
	ExpectedRevision string   `json:"expectedRevision"`
	Changes          []Change `json:"changes"`
	BillingReady     bool     `json:"billingReady"`
	BillingSetupURL  string   `json:"billingSetupUrl,omitempty"`
}

// DeployRequest applies a plan to the environment that the plan names.
type DeployRequest struct {
	Environment      string             `json:"environment"`
	ExpectedRevision string             `json:"expectedRevision"`
	PlanID           string             `json:"planId"`
	Policy           RelayPolicyRequest `json:"policy"`
	ProjectSlug      string             `json:"project"`
	Writer           string             `json:"writer"`
}

type Deployment struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Status   string `json:"status"`
	RelayURL string `json:"relayUrl"`
}

type Project struct {
	Sandbox    *ProjectEnvironment `json:"sandbox,omitempty"`
	Production *ProjectEnvironment `json:"production,omitempty"`
	Slug       string              `json:"slug"`
	Writer     string              `json:"writer"`
}

// ProjectEnvironment is one environment of a project read. The Production
// read is always present: State is "active", "available", or "inactive", and
// BlockedBy names the first gate that stops activation. CanActivate and
// CardOnFile are set on Production only. Only an active environment has a
// RelayURL and the policy fields.
type ProjectEnvironment struct {
	AttachmentRetentionSeconds int    `json:"attachmentRetentionSeconds"`
	DeliveryRetentionSeconds   int    `json:"deliveryTtlSeconds"`
	RelayURL                   string `json:"relayUrl"`
	Revision                   string `json:"revision"`
	State                      string `json:"state,omitempty"`
	BlockedBy                  string `json:"blockedBy,omitempty"`
	CanActivate                bool   `json:"canActivate,omitempty"`
	CardOnFile                 bool   `json:"cardOnFile,omitempty"`
}

// Production states and the gates that stop an activation, in the order that
// the console checks them.
const (
	ProductionActive    = "active"
	ProductionAvailable = "available"
	ProductionInactive  = "inactive"

	BlockedByBillingPermission = "billing_permission"
	BlockedByTerms             = "terms"
	BlockedByFreeProjectLimit  = "free_project_limit"
	BlockedByCard              = "card"
)

// ProjectSummary is one project in the list of the projects that the caller
// can read.
type ProjectSummary struct {
	Slug       string             `json:"slug"`
	Name       string             `json:"name"`
	Product    string             `json:"product"`
	Production ProductionStanding `json:"production"`
}

type ProductionStanding struct {
	State string `json:"state"`
}

type NotificationProfile string

const (
	NotificationBackgroundOnly NotificationProfile = "background-only"
	NotificationVisibleAlert   NotificationProfile = "visible-alert"
	NotificationNSEVisible     NotificationProfile = "nse-visible"
)

type NotificationConfiguration struct {
	AllowedProfiles      []NotificationProfile `json:"allowedProfiles"`
	ConfigurationVersion int                   `json:"configurationVersion"`
	Environment          string                `json:"environment"`
	Providers            []string              `json:"providers"`
}

type NotificationConfigurationRequest struct {
	AllowedProfiles              []NotificationProfile `json:"allowedProfiles"`
	Environment                  string                `json:"environment"`
	ExpectedConfigurationVersion int                   `json:"expectedConfigurationVersion"`
}

const (
	TermsAccepted = "accepted"
	TermsRequired = "required"
)

// Terms is the terms standing of the caller's organization. One acceptance
// covers every document, and CanAccept reports whether the caller may give it.
type Terms struct {
	State      string          `json:"state"`
	CanAccept  bool            `json:"canAccept"`
	Documents  []TermsDocument `json:"documents"`
	AcceptedAt *string         `json:"acceptedAt"`
}

type TermsDocument struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Version string `json:"version"`
}

// TermsAcceptanceRequest is the act of acceptance only. The server records the
// document versions and the time. AgentName is the detected coding agent, and
// only an agent actor has one.
type TermsAcceptanceRequest struct {
	Actor     string `json:"actor"`
	AgentName string `json:"agentName,omitempty"`
}

// TermsAcceptance is the standing after an acceptance. Changed is false when
// the organization had accepted already, so nothing was recorded.
type TermsAcceptance struct {
	Terms
	Changed bool `json:"changed"`
}

// Session is the identity behind an access token: the person, the
// organization, and the role in it. Agent is set when an agent registration
// holds the session for the person.
type Session struct {
	SchemaVersion int                 `json:"schemaVersion"`
	User          SessionUser         `json:"user"`
	Organization  SessionOrganization `json:"organization"`
	Role          string              `json:"role"`
	Agent         *SessionAgent       `json:"agent"`
}

// SessionUser is the person of a session. Name is empty when the person has
// none.
type SessionUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type SessionOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SessionAgent struct {
	RegistrationID string `json:"registrationId"`
}

package app

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
	"github.com/open-e2ee/oe/internal/output"
)

const acceptTermsCommand = "oe auth login --accept-terms"

func (r *runner) auth(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("auth", "name an auth command: login, status, or logout")
	}
	switch args[0] {
	case "login":
		return r.authLogin(ctx, args[1:])
	case "status":
		return r.authStatus(ctx, args[1:])
	case "logout":
		return r.authLogout(args[1:])
	default:
		return usageError("auth", fmt.Sprintf("unknown auth command %q", args[0]))
	}
}

// authLogin logs in with the device flow, then runs the terms step. With
// --accept-terms and a valid session, or with OE_ACCESS_TOKEN, it starts no
// device flow. A terms state that stays required is not a failure: the login
// succeeded, and next names the acceptance when the caller may give it. With
// accepted terms, next names the setup step of the directory. A person at a
// terminal who logged in, in an app directory with no config, chooses to
// create a project, link one, or skip.
func (r *runner) authLogin(ctx context.Context, args []string) error {
	flags := newFlags("auth login")
	timeout := flags.Duration("timeout", 5*time.Minute, "login timeout")
	acceptTerms := flags.Bool("accept-terms", false, "accept the OpenE2EE terms for the organization")
	if err := parseFlags(flags, "auth", args); err != nil {
		return err
	}
	// A login that cannot wait never succeeds, so it is a usage error and not
	// the temporary LOGIN_TIMED_OUT.
	if *timeout <= 0 {
		return usageError("auth", "--timeout must be positive")
	}
	session, loggedIn, err := r.loginSession(ctx, *timeout, *acceptTerms)
	if err != nil {
		return err
	}
	request := control.CredentialRequest{AccessToken: session.AccessToken}
	identity, err := r.api.Session(ctx, request)
	if err != nil {
		return err
	}
	terms, err := r.api.Terms(ctx, request)
	if err != nil {
		return err
	}
	data := sessionData(identity, session.Source)
	organization := identity.Organization.Name
	accepting := *acceptTerms && terms.State == control.TermsRequired
	if !*acceptTerms && terms.State == control.TermsRequired && terms.CanAccept && r.canPrompt() {
		accepting, err = r.askTerms(organization, terms.Documents)
		if err != nil {
			return err
		}
	}
	changed := false
	if accepting {
		accepted, err := r.api.AcceptTerms(ctx, request, r.termsActor(*acceptTerms))
		if err != nil {
			return err
		}
		terms, changed = accepted.Terms, accepted.Changed
	}
	if *acceptTerms || accepting {
		data["changed"] = changed
	}
	data["terms"] = terms.State
	data["canAccept"] = terms.CanAccept

	message := []string{signedIn(identity)}
	if session.Source == "environment" {
		message = append(message, "Using the scoped CI credential from OE_ACCESS_TOKEN. It was not stored.")
	}
	next := ""
	switch {
	case terms.State == control.TermsAccepted && changed:
		message = append(message, organization+" accepted the OpenE2EE terms.")
		next = setupNext(r.directory)
	case terms.State == control.TermsAccepted:
		message = append(message, organization+" has accepted the OpenE2EE terms.")
		next = setupNext(r.directory)
	case terms.CanAccept:
		message = append(message, organization+" has not accepted the OpenE2EE terms.")
		data["documents"] = termsDocuments(terms.Documents)
		next = acceptTermsCommand
	default:
		message = append(message, organization+" has not accepted the OpenE2EE terms. An administrator of "+
			organization+" must accept them, in the console or with "+acceptTermsCommand+".")
		data["documents"] = termsDocuments(terms.Documents)
	}
	text := strings.Join(message, " ")
	if r.out.Mode() == output.Text && terms.State == control.TermsRequired {
		text += documentList(terms.Documents)
	}
	if loggedIn && next == "oe new" && r.mode == output.Text && r.canPrompt() {
		return r.offerSetup(ctx, text, data)
	}
	return r.out.SuccessNext("auth login", text, next, data)
}

// setupNext is the setup command for directory after a login. In a directory
// that a config sets up, it is oe doctor when the Sandbox Relay connection is
// in .env.local, because the setup is done, and oe link when the connection is
// not there. It is oe new in a directory that holds the package.json of an
// app, and nothing otherwise. oe doctor also reports a connection that it
// cannot read.
func setupNext(directory string) string {
	if path, err := config.Find(directory); err == nil {
		root := filepath.Dir(path)
		connection, err := envfile.Detect(root, "")
		if err != nil {
			return "oe doctor"
		}
		local, err := envfile.Read(filepath.Join(root, environmentFiles["sandbox"]), connection.Variable)
		if err != nil || local != "" {
			return "oe doctor"
		}
		return "oe link"
	}
	if _, err := os.Stat(filepath.Join(directory, "package.json")); err == nil {
		return "oe new"
	}
	return ""
}

// offerSetup shows the login, then asks the person to create a project, link
// one, or skip. A create or a link is the oe new or oe link of the run, and a
// failure names that command, because the login stays done. Any other answer
// skips.
func (r *runner) offerSetup(ctx context.Context, login string, data map[string]any) error {
	if err := r.out.Progress("auth login", login, nil); err != nil {
		return err
	}
	create := "Create a new project"
	if len(products) == 1 {
		create = "Create a new " + products[0] + " project"
	}
	fmt.Fprintf(r.errOut, "What do you want to do in this directory?\n  1. %s (oe new)\n  2. Link an existing project (oe link)\n  3. Skip\nChoose [1-3]: ", create)
	answer, err := bufio.NewReader(r.in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "1", "create":
		if err := r.new(ctx, nil); err != nil {
			return classify(err, "oe new", r.environment)
		}
		return nil
	case "2", "link":
		if err := r.link(ctx, nil); err != nil {
			return classify(err, "oe link", r.environment)
		}
		return nil
	}
	return r.out.SuccessNext("auth login", "Run oe new to create a project in this directory, or oe link to link a project that exists.", "oe new", data)
}

// loginSession returns the session for the terms step, and reports whether
// this run logged in. OE_ACCESS_TOKEN is never replaced by a login. With
// acceptTerms, a stored session that is still valid is used as it is.
func (r *runner) loginSession(ctx context.Context, timeout time.Duration, acceptTerms bool) (credential.Credential, bool, error) {
	if acceptTerms || r.getenv("OE_ACCESS_TOKEN") != "" {
		value, err := r.access(ctx, "", false)
		if err == nil {
			return value, false, nil
		}
		if failure, ok := errors.AsType[*problem](err); !ok || failure.exit != exitAuthentication {
			return credential.Credential{}, false, err
		}
	}
	value, err := r.interactiveLogin(ctx, timeout, r.announcePending)
	return value, err == nil, err
}

// announcePending shows the device flow of oe auth login as a pending event.
// Under an agent it is the first of two JSON documents, so the agent can hand
// the URL and the code to the person while the CLI polls. action.url is the
// page to open; data.bareVerificationUrl is the page for another device.
func (r *runner) announcePending(authorization control.Authorization) {
	message := "A person must approve this device."
	if r.out.Mode() == output.Text {
		message = loginPrompt(authorization)
	}
	data := map[string]any{"userCode": authorization.UserCode, "expiresInSeconds": authorization.ExpiresInSeconds}
	if authorization.BareVerificationURL != "" {
		data["bareVerificationUrl"] = authorization.BareVerificationURL
	}
	_ = r.out.Pending("auth login", message, output.Action{
		Kind: "browser", URL: authorization.VerificationURL, Reason: "login",
	}, data)
}

// askTerms is the one terms prompt for a person at a terminal. It lists each
// document with its URL.
func (r *runner) askTerms(organization string, documents []control.TermsDocument) (bool, error) {
	fmt.Fprint(r.errOut, "The OpenE2EE terms:"+documentList(documents)+"\n")
	return askConfirmation(r.in, r.errOut, "Accept these terms for "+organization+"?")
}

// termsActor is the acceptance request. --accept-terms under an agent records
// the agent and the name that AD5 detection gives; a prompt answer is always
// a person.
func (r *runner) termsActor(flag bool) control.TermsAcceptanceRequest {
	if flag && r.underAgent {
		return control.TermsAcceptanceRequest{Actor: "agent", AgentName: r.harness.ID}
	}
	return control.TermsAcceptanceRequest{Actor: "person"}
}

// authStatus reads the identity of the session and the terms state of its
// organization. Both reads also check the session with the control API. The
// text names the person, the organization, and the store; the IDs and the
// role are in the data only.
func (r *runner) authStatus(ctx context.Context, args []string) error {
	if err := parseFlags(newFlags("auth status"), "auth", args); err != nil {
		return err
	}
	session, err := r.access(ctx, "", false)
	if err != nil {
		return err
	}
	request := control.CredentialRequest{AccessToken: session.AccessToken}
	identity, err := r.api.Session(ctx, request)
	if err != nil {
		return err
	}
	terms, err := r.api.Terms(ctx, request)
	if err != nil {
		return err
	}
	data := sessionData(identity, session.Source)
	data["terms"] = terms.State
	data["canAccept"] = terms.CanAccept

	message := signedIn(identity)
	if label := credential.LocationOf(session.Source).Label; label != "" {
		message += " (" + label + ")"
	}
	if terms.State == control.TermsAccepted {
		message += "\n" + identity.Organization.Name + " has accepted the OpenE2EE terms."
	} else {
		message += "\n" + identity.Organization.Name + " has not accepted the OpenE2EE terms."
	}
	return r.out.Success("auth status", message, data)
}

// signedIn names the person of a session, and the agent that holds it for
// the person, in the organization. It shows no ID.
func signedIn(session control.Session) string {
	person := session.User.Email
	if session.User.Name != "" {
		person = session.User.Name + " (" + session.User.Email + ")"
	}
	if session.Agent != nil {
		person = "an agent for " + person
	}
	// An organization name such as "Acme Inc." already ends the sentence.
	return strings.TrimSuffix("Signed in as "+person+" in "+session.Organization.Name, ".") + "."
}

// sessionData is the identity part of a result: the IDs, the names, the role,
// the agent registration, and where the credential comes from. A name or a
// role that the session lacks is null.
func sessionData(session control.Session, source string) map[string]any {
	data := map[string]any{
		"user": session.User.ID, "email": session.User.Email, "userName": nullable(session.User.Name),
		"organization": map[string]any{"id": session.Organization.ID}, "organizationName": session.Organization.Name,
		"role": nullable(session.Role), "source": source, "store": credential.LocationOf(source).Key,
	}
	if session.Agent != nil {
		data["agent"] = map[string]any{"registrationId": session.Agent.RegistrationID}
	}
	return data
}

// nullable is nil for an empty value, so JSON shows null.
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (r *runner) authLogout(args []string) error {
	if err := parseFlags(newFlags("auth logout"), "auth", args); err != nil {
		return err
	}
	profile, err := credential.Profile(r.controlURL)
	if err != nil {
		return err
	}
	if err := r.store.Delete(profile); err != nil {
		return err
	}
	message := "Logged out. The OS keychain holds no session for " + profile + "."
	environment := r.getenv("OE_ACCESS_TOKEN") != ""
	if environment {
		message += " OE_ACCESS_TOKEN is still set, so later commands still use it."
	}
	return r.out.Success("auth logout", message, map[string]any{"profile": profile, "environmentCredential": environment})
}

// sessionClaims are the claims of a WorkOS access token that oe new reads
// without a request. The control API verifies the token; the CLI decodes the
// claims only to key an operation and to report the organization ID. A token
// that is not a JWT has none.
type sessionClaims struct {
	Organization string `json:"org_id"`
}

func sessionClaimsOf(token string) sessionClaims {
	var claims sessionClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return sessionClaims{}
	}
	return claims
}

// termsDocuments is never nil, so JSON shows an empty list, not null.
func termsDocuments(documents []control.TermsDocument) []control.TermsDocument {
	if documents == nil {
		return []control.TermsDocument{}
	}
	return documents
}

// documentList gives each document on its own indented line.
func documentList(documents []control.TermsDocument) string {
	var text strings.Builder
	for _, document := range documents {
		fmt.Fprintf(&text, "\n  %s: %s", document.Name, document.URL)
	}
	return text.String()
}

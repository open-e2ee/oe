package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
)

func (r *runner) identity(ctx context.Context, args []string) error {
	invalid := func(message string) error { return usageError("identity", message) }
	if len(args) == 0 || args[0] != "check" {
		return invalid("use oe identity check with a public profile file")
	}
	flags := newFlags("identity check")
	profilePath := flags.String("profile", "", "public identity profile JSON file")
	assertionStdin := flags.Bool("assertion-stdin", false, "send a transient test assertion from standard input to Console")
	if parseFlags(flags, "identity", args[1:]) != nil || *profilePath == "" || flags.NArg() != 0 {
		return invalid("identity check requires --profile and accepts no positional values or assertion arguments")
	}
	p, err := identity.Load(*profilePath)
	if errors.Is(err, identity.ErrUnsupported) {
		return &problem{code: "IDENTITY_PROFILE_UNSUPPORTED", message: identity.ErrUnsupported.Error(), next: "oe help identity", exit: exitUsage}
	}
	if err != nil {
		return &problem{code: "IDENTITY_CHECK_INVALID", message: "The public identity profile could not be read or is invalid.", next: "oe help identity", exit: exitUsage}
	}
	if p.Mode == "device-owned" && *assertionStdin {
		return invalid("device-owned identity forbids --assertion-stdin and uses no backend assertion")
	}
	if p.Mode != "device-owned" && !*assertionStdin {
		return invalid("external identity requires --assertion-stdin; the transient assertion is sent to the authenticated Console verifier")
	}
	_, configuration, err := r.loadConfig()
	if err != nil {
		return &problem{code: "IDENTITY_CHECK_INVALID", message: "A valid project configuration is required. Use oe link for an existing project.", next: "oe help identity", exit: exitUsage}
	}
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return identityCommandFailure(err)
	}
	draft := identity.Draft{Target: p}
	if *assertionStdin {
		data, err := io.ReadAll(io.LimitReader(r.in, 65_537))
		if err != nil || len(data) > 65_536 {
			return &problem{code: "IDENTITY_CHECK_INVALID", message: "The assertion input is invalid or exceeds 65,536 bytes.", next: "oe help identity", exit: exitUsage}
		}
		draft.Assertion = strings.TrimSpace(string(data))
		if draft.Assertion == "" {
			return invalid("supply a fresh assertion on standard input")
		}
	}
	result, err := r.api.CheckIdentity(ctx, control.CredentialRequest{AccessToken: access.AccessToken}, configuration.Project, r.environment, draft)
	if err != nil {
		return identityCommandFailure(err)
	}
	if !result.Matches(p, r.environment) {
		return identityCommandFailure(nil)
	}
	message := "Accepted at check time against the draft profile. This does not establish current validity. Installed configuration, device admission, member binding, exchange and lifecycle remain unverified."
	if result.ExpiresAt != nil {
		message += fmt.Sprintf(" Signed expiry: %d Unix seconds.", *result.ExpiresAt)
	}
	if result.State == "not_applicable" {
		message = "Device-owned identity uses no backend assertion. Installed configuration, device admission, member binding, exchange and lifecycle remain unverified."
	}
	return r.out.Success("identity check", message, result.Data())
}

func identityCommandFailure(err error) error {
	if failure, ok := errors.AsType[*control.APIError](err); ok {
		code, message, next, exit := "IDENTITY_CHECK_UNAVAILABLE", "The identity check is unavailable.", "oe help identity", exitFailure
		switch failure.Code {
		case "AUTHENTICATION_REQUIRED", "INVALID_SESSION":
			code, message, next, exit = failure.Code, "Run oe auth login to check identity.", "oe auth login", exitAuthentication
		case "ORGANIZATION_REQUIRED":
			code, message, next = failure.Code, "Select an Organization with oe org switch.", "oe org switch"
		case "PROJECT_NOT_FOUND", "ENVIRONMENT_NOT_FOUND":
			code, message = failure.Code, "The addressed Relay resource is unavailable."
		case "IDENTITY_CHECK_INVALID", "IDENTITY_PROFILE_UNSUPPORTED", "IDENTITY_ASSERTION_INVALID":
			code, message = failure.Code, "The draft identity check was refused. Check the public profile and use a fresh external assertion."
		case "IMPERSONATED_SESSION":
			code, message = failure.Code, "This session cannot perform the identity check."
		case "AUTHORITY_UNAVAILABLE", "IDENTITY_CHECK_UNAVAILABLE":
			code, exit = failure.Code, exitTemporary
		}
		return &problem{code: code, message: message, next: next, exit: exit}
	}
	if failure, ok := errors.AsType[*problem](err); ok && (failure.exit == exitAuthentication || failure.code == "SCOPE_REQUIRED") {
		return &problem{code: "AUTHENTICATION_REQUIRED", message: "A current session with project read access is required.", next: "oe auth login", exit: exitAuthentication}
	}
	return &problem{code: "IDENTITY_CHECK_UNAVAILABLE", message: "The identity check is unavailable.", next: "oe help identity", exit: exitTemporary}
}

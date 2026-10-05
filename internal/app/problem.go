package app

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/output"
)

// problem is a command failure with a stable code, the exit status that the
// code implies, and the command that moves the caller forward.
type problem struct {
	code    string
	message string
	next    string
	exit    int
	data    map[string]any
	cause   error

	// actionURL is a page that a person must open to move forward, and
	// actionReason says why. A reason makes the action a browser step.
	actionURL    string
	actionReason string
}

func (p *problem) Error() string { return p.message }
func (p *problem) Unwrap() error { return p.cause }

func usageError(command, message string) error {
	next := "oe help"
	if _, ok := lookupCommand(command); ok {
		next += " " + command
	}
	return &problem{code: "USAGE_ERROR", message: message, next: next, exit: exitUsage}
}

func unknownCommand(name string) error {
	if verb, ok := authVerbs[name]; ok {
		return &problem{
			code: "USAGE_ERROR", exit: exitUsage, next: "oe auth " + verb,
			message: fmt.Sprintf("oe has no %s command; oe auth %s is the command", name, verb),
		}
	}
	return &problem{code: "USAGE_ERROR", message: fmt.Sprintf("unknown command %q", name), next: "oe help", exit: exitUsage}
}

// authVerbs maps a top-level command that other CLIs use for a session to the
// oe auth command that does the same work.
var authVerbs = map[string]string{"login": "login", "logout": "logout", "whoami": "status"}

func loginRequired(code, message string, cause error) error {
	return &problem{code: code, message: message, next: "oe auth login", exit: exitAuthentication, cause: cause}
}

// classify gives every error that reaches Run a code and an exit status. A
// control API refusal keeps the code that the console sent. A temporary failure
// exits 6, and its next is the command line of the run. A terms, card, or Free
// plan refusal exits 5: a person must act. environment is the environment of
// the run.
func classify(err error, commandLine, environment string) *problem {
	if known, ok := errors.AsType[*problem](err); ok {
		if known.exit == exitTemporary && known.next == "" {
			known.next = commandLine
		}
		return known
	}
	if failure, ok := errors.AsType[*config.Error](err); ok {
		result := &problem{code: failure.Code, message: err.Error(), next: commandLine, exit: exitFailure, data: failure.Data, cause: err}
		switch failure.Code {
		case "NODE_REQUIRED":
			result.exit, result.actionURL = exitPersonAction, "https://nodejs.org/en/download"
		case "CONFIG_EDIT_REQUIRED":
			result.exit = exitPersonAction
		case "CONFIG_INVALID":
			// The same command fails again until the file changes, so no
			// command moves the caller forward. error names the fields.
			result.next = ""
		}
		return result
	}
	if refusal, ok := errors.AsType[*control.APIError](err); ok {
		result := &problem{code: cmp.Or(refusal.Code, "CONTROL_ERROR"), message: err.Error(), exit: exitFailure, cause: err}
		switch {
		case refusal.Status == http.StatusUnauthorized || refusal.Code == "AUTHENTICATION_REQUIRED" || refusal.Code == "INVALID_SESSION":
			result.code = cmp.Or(refusal.Code, "AUTHENTICATION_REQUIRED")
			result.next = "oe auth login"
			result.exit = exitAuthentication
		case refusal.Code == "ORGANIZATION_REQUIRED":
			result.next = "oe auth login"
		case refusal.Code == "TERMS_REQUIRED":
			result.exit = exitPersonAction
			result.data = map[string]any{
				"canAccept": refusal.CanAccept, "documents": termsDocuments(refusal.Documents),
				"retry": commandLine,
			}
			if refusal.CanAccept {
				result.next = "oe auth login --accept-terms"
			}
		case refusal.Code == "TERMS_PERMISSION_REQUIRED":
			result.exit = exitPersonAction
		case refusal.Code == "CARD_REQUIRED":
			result.exit, result.next = exitPersonAction, commandLine
			result.actionURL, result.actionReason = refusal.BillingSetupURL, "card"
		case refusal.Code == "FREE_PROJECT_LIMIT":
			result.exit = exitPersonAction
		case refusal.Code == "ENVIRONMENT_NOT_FOUND" && environment == "sandbox":
			// Every project has Sandbox, so the session cannot read this project.
			result.next = "oe auth status"
		case refusal.Code == "AUTHORITY_UNAVAILABLE", refusal.Status == http.StatusTooManyRequests,
			refusal.Status == http.StatusBadGateway, refusal.Status == http.StatusServiceUnavailable,
			refusal.Status == http.StatusGatewayTimeout:
			result.next = commandLine
			result.exit = exitTemporary
		}
		return result
	}
	if _, ok := errors.AsType[*url.Error](err); ok {
		return &problem{code: "CONTROL_UNAVAILABLE", message: err.Error(), next: commandLine, exit: exitTemporary, cause: err}
	}
	return &problem{code: "COMMAND_FAILED", message: err.Error(), exit: exitFailure, cause: err}
}

// environmentTokenFailure is the failure of a run whose credential came from
// OE_ACCESS_TOKEN. A login never replaces OE_ACCESS_TOKEN, so a failure that
// names oe auth login would send the caller back to the same failure. A
// refused token gets its own code and names the variable. Any other failure
// that names oe auth login loses that next and says how to change the token.
func environmentTokenFailure(err error, commandLine, environment string) *problem {
	failure := classify(err, commandLine, environment)
	switch {
	case failure.exit == exitAuthentication:
		return &problem{
			code: "ACCESS_TOKEN_INVALID", exit: exitAuthentication, cause: err, data: failure.data,
			message: "the control API refused the token in OE_ACCESS_TOKEN, and a login never replaces it; " + replaceAccessToken,
		}
	case failure.next == "oe auth login":
		failure.next = ""
		failure.message += "; the credential comes from OE_ACCESS_TOKEN, and a login never replaces it; " + replaceAccessToken
	}
	return failure
}

const replaceAccessToken = "set OE_ACCESS_TOKEN to a new token, or unset OE_ACCESS_TOKEN and run oe auth login"

// commandLine writes args as one oe command line for a POSIX shell. It quotes
// each argument that holds a character outside a safe set.
func commandLine(args []string) string {
	words := []string{"oe"}
	for _, argument := range args {
		if argument != "" && strings.Trim(argument, shellSafe) == "" {
			words = append(words, argument)
			continue
		}
		words = append(words, "'"+strings.ReplaceAll(argument, "'", `'\''`)+"'")
	}
	return strings.Join(words, " ")
}

const shellSafe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-"

func (p *problem) output() output.Problem {
	action := output.Action{URL: p.actionURL}
	if p.actionReason != "" {
		action.Kind, action.Reason = "browser", p.actionReason
	}
	return output.Problem{Message: p.message, Code: p.code, Next: p.next, Action: action, Data: p.data}
}

package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
)

func (r *runner) doctor(ctx context.Context, args []string) error {
	flags := newFlags("doctor")
	wait := flags.Bool("wait", false, "wait for the first acknowledged message")
	timeout := flags.Duration("timeout", 30*time.Minute, "first acknowledgement timeout")
	if err := parseFlags(flags, "doctor", args); err != nil {
		return err
	}
	timeoutSet := false
	flags.Visit(func(set *flag.Flag) { timeoutSet = timeoutSet || set.Name == "timeout" })
	switch {
	case timeoutSet && !*wait:
		return usageError("doctor", "--timeout needs --wait")
	case *timeout <= 0:
		return usageError("doctor", "--timeout must be positive")
	case *wait && r.environment != "sandbox":
		// The control API reports activation for Sandbox only.
		return usageError("doctor", "--wait needs --env sandbox")
	}
	// The relay and relayOrigin keys are deprecated copies of signalRelay and
	// signalRelayOrigin. v7.0.0 removes them.
	checks := map[string]any{"config": "ok", "control": "ok", "credential": "ok", "signalRelay": "ok", "relay": "ok", "telemetry": "disabled"}
	path, value, err := r.loadConfig()
	if err != nil {
		return fmt.Errorf("doctor found a problem: %w", err)
	}
	if value.Format == config.FormatV2 {
		r.warn(configFormatWarning)
	}
	connection, err := envfile.Detect(filepath.Dir(path), "")
	if err != nil {
		return fmt.Errorf("doctor found a problem: %w", err)
	}
	environmentFile := environmentFiles[r.environment]
	local, deprecated, err := envfile.ReadConnection(filepath.Join(filepath.Dir(path), environmentFile), connection)
	if err != nil {
		return fmt.Errorf("doctor found a problem: %w", err)
	}
	if deprecated {
		r.warn(envfile.DeprecationWarning(environmentFile, connection, true))
	}
	// The config sets up the directory, so oe new refuses it. oe link writes
	// the env file of each active environment, and every project has an
	// active Sandbox, so a missing Sandbox connection needs no read.
	if local == "" && r.environment == "sandbox" {
		return connectionMissing(r.environment, environmentFile, "oe link")
	}
	if err := r.api.Health(ctx); err != nil {
		return fmt.Errorf("doctor found a problem: control API: %w", err)
	}
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return fmt.Errorf("doctor found a problem: credential: %w", err)
	}
	project, err := r.getProject(ctx, access, value.Project)
	if err != nil {
		return fmt.Errorf("doctor found a problem: project authority: %w", err)
	}
	expected := ""
	if environment := environmentOf(project, r.environment); environment != nil {
		expected = environment.SignalProtocolRelayURL
	}
	if local == "" {
		// oe link writes the env file of an active Production. The step that
		// activates Production depends on the config and the writer mode.
		if expected == "" {
			next, step := r.productionActivation(value.Project, project.Writer)
			failure := connectionMissing(r.environment, environmentFile, next)
			failure.message += "; " + step
			return failure
		}
		return connectionMissing(r.environment, environmentFile, "oe link")
	}
	if expected == "" {
		return r.environmentNotActive(value.Project, project.Writer, r.environment)
	}
	if expected != local {
		return &problem{
			code: "SIGNAL_RELAY_CONNECTION_STALE", exit: exitFailure, next: "oe link",
			message: fmt.Sprintf("doctor found a problem: the local %s OpenE2EE Signal Protocol Relay connection is stale or belongs to another project", r.environment),
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, local, nil)
	if err != nil {
		return fmt.Errorf("doctor found a problem: the OpenE2EE Signal Protocol Relay connection is invalid")
	}
	request.Header.Set("Accept", "application/json")
	response, err := r.http.Do(request)
	if err != nil {
		return fmt.Errorf("doctor found a problem: the OpenE2EE Signal Protocol Relay connection is unreachable")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("doctor found a problem: the OpenE2EE Signal Protocol Relay connection returned status %d", response.StatusCode)
	}
	origin, _ := url.Parse(local)
	checks["project"] = value.Project
	checks["environment"] = r.environment
	checks["configurationSource"] = environmentFile
	checks["signalRelayOrigin"] = origin.Scheme + "://" + origin.Host
	checks["relayOrigin"] = checks["signalRelayOrigin"]
	if !*wait {
		return r.out.Success("doctor", "All checks passed. CLI telemetry is disabled.", checks)
	}
	_ = r.out.Progress("doctor", "All checks passed. Waiting for the first acknowledged message.", checks)
	if err := r.waitForFirstMessage(ctx, access, value.Project, *timeout); err != nil {
		return err
	}
	checks["firstDevice"] = true
	checks["firstAcknowledged"] = true
	return r.out.Success("doctor", "All checks passed, and the first managed message was acknowledged.", checks)
}

// configFormatWarning tells a project whose config file uses the deprecated
// relay key to rename it.
const configFormatWarning = "warning: " + config.Filename + " uses the deprecated relay and relayReceipts keys; " +
	"rename them to signalRelay and signalRelayReceipts. oe " + config.FormatV2RemovalRelease + " stops reading the old keys."

// connectionMissing is a doctor run whose env file has no Relay connection
// for environment. next is the command that writes the connection.
func connectionMissing(environment, environmentFile, next string) *problem {
	return &problem{
		code: "SIGNAL_RELAY_CONNECTION_MISSING", exit: exitFailure, next: next,
		message: fmt.Sprintf("doctor found a problem: the %s OpenE2EE Signal Protocol Relay connection is not in %s", environment, environmentFile),
	}
}

// waitForFirstMessage polls the Sandbox activation of project until a device
// connected and a managed message was acknowledged. Only an acknowledgment
// that the wait sees happen counts: the control API reports whether the first
// managed message was ever acknowledged, with no time, so the first read is
// the baseline. A project whose first message was acknowledged before the wait
// started can show no new acknowledgment, and the wait fails at once instead of
// reporting old evidence. It refreshes a session that expires during the wait.
func (r *runner) waitForFirstMessage(ctx context.Context, access credential.Credential, project string, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for baseline := true; ; baseline = false {
		if access.Source != "environment" && access.RefreshToken != "" && credentialNeedsRefresh(access, r.now()) {
			refreshed, err := r.access(waitCtx, "", false)
			if err != nil {
				return firstMessageTimeout(ctx, waitCtx, timeout, err)
			}
			access = refreshed
		}
		state, err := r.api.Activation(waitCtx, control.CredentialRequest{AccessToken: access.AccessToken}, project)
		if err != nil {
			return firstMessageTimeout(ctx, waitCtx, timeout, err)
		}
		switch {
		case baseline && state.FirstAcknowledged:
			return &problem{
				code: "FIRST_MESSAGE_ALREADY_ACKNOWLEDGED", exit: exitFailure, next: "oe doctor",
				data: map[string]any{"project": project, "firstDevice": state.FirstDevice, "firstAcknowledged": true},
				message: fmt.Sprintf("the first managed message of project %s was acknowledged before this wait started, "+
					"and the control API reports only that first acknowledgment, so oe doctor --wait cannot see a new message; "+
					"run oe doctor to check the OpenE2EE Signal Protocol Relay connection", project),
			}
		case state.FirstDevice && state.FirstAcknowledged:
			return nil
		}
		if err := r.sleep(waitCtx, 2*time.Second); err != nil {
			return firstMessageTimeout(ctx, waitCtx, timeout, err)
		}
	}
}

// firstMessageTimeout gives the end of the wait its own code. The wait ends
// when waitCtx reaches its deadline while the run itself goes on. That
// failure is temporary, so classify names the same command as next. Any other
// failure stays as it is.
func firstMessageTimeout(ctx, waitCtx context.Context, timeout time.Duration, err error) error {
	if ctx.Err() != nil || !(errors.Is(err, context.DeadlineExceeded) || errors.Is(waitCtx.Err(), context.DeadlineExceeded)) {
		return err
	}
	return &problem{
		code: "FIRST_MESSAGE_TIMED_OUT", exit: exitTemporary, cause: err,
		message: fmt.Sprintf("no managed message was acknowledged within %s; send a message from the app, then run the command again", timeout),
	}
}

package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/output"
)

func (r *runner) org(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("org", "name an org command: list or switch")
	}
	switch args[0] {
	case "list":
		if err := parseFlags(newFlags("org list"), "org", args[1:]); err != nil {
			return err
		}
		return r.orgList(ctx)
	case "switch":
		flags := newFlags("org switch")
		if err := parseArguments(flags, "org", args[1:]); err != nil {
			return err
		}
		if flags.NArg() > 1 {
			return usageError("org", "oe org switch takes at most one ORG")
		}
		return r.orgSwitch(ctx, flags.Arg(0))
	default:
		return usageError("org", fmt.Sprintf("unknown org command %q", args[0]))
	}
}

// orgList prints the organizations of the person, with a marker on the
// organization of the session. The text shows no ID; the data has the IDs.
func (r *runner) orgList(ctx context.Context) error {
	value, err := r.access(ctx, "", false)
	if err != nil {
		return err
	}
	list, err := r.organizations(ctx, value)
	if err != nil {
		return err
	}
	data := organizationListData(list)
	if len(list.Organizations) == 0 {
		return r.out.Success("org list", "This account belongs to no organization.", data)
	}
	message := organizationTable(list)
	if list.Current == "" {
		return r.out.SuccessNext("org list", message+"\nThe session has no organization. Run oe org switch to choose one.", "oe org switch", data)
	}
	return r.out.Success("org list", message, data)
}

// orgSwitch moves the stored session to the organization that argument names
// by ID or by a unique name. Without argument, a person at a terminal chooses
// one; any other caller must name it.
func (r *runner) orgSwitch(ctx context.Context, argument string) error {
	value, err := r.access(ctx, "", false)
	if err != nil {
		return err
	}
	if value.Source == "environment" {
		return &problem{
			code: "USAGE_ERROR", exit: exitUsage,
			message: "the session comes from OE_ACCESS_TOKEN, which a switch never replaces; unset OE_ACCESS_TOKEN to switch",
		}
	}
	list, err := r.organizations(ctx, value)
	if err != nil {
		return err
	}
	if current, ok := organizationByID(list, list.Current); ok && current.Switchable != nil && !*current.Switchable {
		return &problem{
			code: "USAGE_ERROR", exit: exitUsage, data: organizationListData(list),
			message: "an agent session belongs to one organization; it cannot switch to another",
		}
	}
	var target control.Organization
	if argument == "" {
		chosen, keep, err := r.pickOrganization(list)
		if err != nil {
			return err
		}
		if keep {
			return r.alreadyInOrganization(list, chosen)
		}
		target = chosen
	} else if target, err = resolveOrganization(list, argument); err != nil {
		return err
	}
	if target.ID == list.Current {
		return r.alreadyInOrganization(list, target)
	}
	profile, err := credential.Profile(r.controlURL)
	if err != nil {
		return err
	}
	_, identity, err := r.switchOrganization(ctx, profile, value, list, target)
	if err != nil {
		return err
	}
	previous, hadPrevious := organizationByID(list, list.Current)
	message := "Switched to " + identity.Organization.Name
	data := map[string]any{
		"changed":      true,
		"organization": map[string]any{"id": identity.Organization.ID, "name": identity.Organization.Name, "role": nullable(identity.Role)},
		"previous":     nil,
	}
	if hadPrevious {
		message = "Switched from " + previous.Name + " to " + identity.Organization.Name
		data["previous"] = map[string]any{"id": previous.ID, "name": previous.Name}
	}
	// An organization name such as "Acme Inc." already ends the sentence.
	return r.out.SuccessNext("org switch", strings.TrimSuffix(message, ".")+".", "oe project list", data)
}

// switchOrganization refreshes value into target, stores the rotated pair,
// and confirms the organization of the new session. It returns the new
// credential and its session. The refresh spends the
// old refresh token, so the one store.Set comes before the confirmation:
// a failed confirmation still leaves a live session in the store. A WorkOS
// demand for a new sign-in changes nothing.
func (r *runner) switchOrganization(ctx context.Context, profile string, value credential.Credential, list control.OrganizationList, target control.Organization) (credential.Credential, control.Session, error) {
	login := commandLine([]string{"auth", "login", "--organization", organizationArgument(list, target)})
	if value.RefreshToken == "" {
		return credential.Credential{}, control.Session{}, &problem{
			code: "AUTHENTICATION_REQUIRED", exit: exitAuthentication, next: login,
			message: "the stored session has no refresh token, so it cannot switch the organization; run " + login,
		}
	}
	token, err := r.api.RefreshAuthorization(ctx, value.RefreshToken, target.ID)
	if signIn, ok := errors.AsType[*control.SignInRequiredError](err); ok {
		return credential.Credential{}, control.Session{}, &problem{
			code: "ORGANIZATION_SIGN_IN_REQUIRED", exit: exitPersonAction, next: login, cause: err,
			data: map[string]any{"organization": organizationEntry(target, list.Current), "reason": signIn.Reason},
			message: fmt.Sprintf("%s requires a new sign-in (%s); run %s and finish the sign-in in the browser; the stored session did not change",
				target.Name, signIn.Reason, login),
		}
	}
	if errors.Is(err, control.ErrSessionExpired) {
		return credential.Credential{}, control.Session{}, &problem{
			code: "SESSION_EXPIRED", exit: exitAuthentication, next: login, cause: err,
			message: "the WorkOS session expired; run " + login,
		}
	}
	if err != nil {
		return credential.Credential{}, control.Session{}, fmt.Errorf("switch to the organization %s: %w", target.Name, err)
	}
	switched := credential.Credential{
		AccessToken: token.AccessToken, ExpiresAt: token.ExpiresAt,
		RefreshToken: token.RefreshToken, Source: "keychain",
		ProtectionBypass: value.ProtectionBypass,
	}
	if err := r.store.Set(profile, switched); err != nil {
		return credential.Credential{}, control.Session{}, err
	}
	identity, err := r.api.Session(ctx, control.CredentialRequest{AccessToken: switched.AccessToken})
	if err != nil {
		return credential.Credential{}, control.Session{}, err
	}
	if identity.Organization.ID != target.ID {
		return credential.Credential{}, control.Session{}, &problem{
			code: "ORGANIZATION_SWITCH_FAILED", exit: exitFailure, next: "oe org list",
			data: map[string]any{
				"requested":    organizationEntry(target, list.Current),
				"organization": map[string]any{"id": identity.Organization.ID, "name": identity.Organization.Name},
			},
			message: fmt.Sprintf("WorkOS did not move the session to %s; the stored session is in %s", target.Name, identity.Organization.Name),
		}
	}
	return switched, identity, nil
}

// alreadyInOrganization is the result of a switch to the organization of the
// session: it changes nothing.
func (r *runner) alreadyInOrganization(list control.OrganizationList, current control.Organization) error {
	return r.out.SuccessNext("org switch", strings.TrimSuffix("The session is already in "+current.Name, ".")+".", "oe project list", map[string]any{
		"changed":      false,
		"organization": map[string]any{"id": current.ID, "name": current.Name, "role": nullable(current.Role)},
		"previous":     map[string]any{"id": current.ID, "name": current.Name},
	})
}

// pickOrganization asks a person at a terminal to choose an organization.
// Enter keeps the organization of the session, and keep is then true. Any
// other caller gets USAGE_ERROR with the list in data.
func (r *runner) pickOrganization(list control.OrganizationList) (control.Organization, bool, error) {
	if r.mode != output.Text || !r.canPrompt() {
		failure := usageError("org", "name the organization to switch to: oe org switch ORG").(*problem)
		failure.data = organizationListData(list)
		return control.Organization{}, false, failure
	}
	if len(list.Organizations) == 0 {
		return control.Organization{}, false, usageError("org", "this account belongs to no organization")
	}
	current, hasCurrent := organizationByID(list, list.Current)
	for index, organization := range list.Organizations {
		marker := ""
		if organization.ID == list.Current {
			marker = " (current)"
		}
		fmt.Fprintf(r.errOut, "  %d. %s%s\n", index+1, organization.Name, marker)
	}
	prompt := fmt.Sprintf("Switch to which organization? [1-%d] ", len(list.Organizations))
	if hasCurrent {
		prompt = fmt.Sprintf("Switch to which organization? [1-%d, Enter keeps %s] ", len(list.Organizations), current.Name)
	}
	fmt.Fprint(r.errOut, prompt)
	answer, err := bufio.NewReader(r.in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return control.Organization{}, false, err
	}
	answer = strings.TrimSpace(answer)
	if answer == "" && hasCurrent {
		return current, true, nil
	}
	choice, err := strconv.Atoi(answer)
	if err != nil || choice < 1 || choice > len(list.Organizations) {
		failure := usageError("org", "no organization was chosen").(*problem)
		failure.data = organizationListData(list)
		return control.Organization{}, false, failure
	}
	return list.Organizations[choice-1], false, nil
}

// resolveOrganization finds the organization that argument names: an ID, else
// a name without regard to case that only one organization has. An unknown,
// ambiguous, or non-member argument is a USAGE_ERROR with the candidates in
// data.
func resolveOrganization(list control.OrganizationList, argument string) (control.Organization, error) {
	if organization, ok := organizationByID(list, argument); ok {
		return organization, nil
	}
	var matches []control.Organization
	for _, organization := range list.Organizations {
		if strings.EqualFold(organization.Name, argument) {
			matches = append(matches, organization)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return control.Organization{}, &problem{
			code: "USAGE_ERROR", exit: exitUsage, next: "oe org list",
			data:    map[string]any{"organization": argument, "candidates": organizationEntries(list.Organizations, list.Current)},
			message: fmt.Sprintf("this account is not a member of an organization with the name or ID %q; oe org list shows its organizations", argument),
		}
	default:
		ids := make([]string, 0, len(matches))
		for _, match := range matches {
			ids = append(ids, match.ID)
		}
		return control.Organization{}, &problem{
			code: "USAGE_ERROR", exit: exitUsage, next: "oe org list",
			data: map[string]any{"organization": argument, "candidates": organizationEntries(matches, list.Current)},
			message: fmt.Sprintf("%d organizations have the name %q; name one by ID: %s",
				len(matches), argument, strings.Join(ids, ", ")),
		}
	}
}

// organizations reads the organization list. A control API that does not
// list organizations needs an update before the org commands can run.
func (r *runner) organizations(ctx context.Context, value credential.Credential) (control.OrganizationList, error) {
	list, err := r.api.ListOrganizations(ctx, control.CredentialRequest{AccessToken: value.AccessToken})
	if errors.Is(err, control.ErrOrganizationsNotAvailable) {
		return list, &problem{
			code: "CONTROL_UPDATE_REQUIRED", exit: exitFailure, cause: err,
			message: "update required: the control API at " + r.controlURL + " does not list organizations yet, so oe org cannot run",
		}
	}
	return list, err
}

func organizationByID(list control.OrganizationList, id string) (control.Organization, bool) {
	if id == "" {
		return control.Organization{}, false
	}
	for _, organization := range list.Organizations {
		if organization.ID == id {
			return organization, true
		}
	}
	return control.Organization{}, false
}

// organizationArgument names target on a command line: its name when no
// other organization of the list has that name, else its ID.
func organizationArgument(list control.OrganizationList, target control.Organization) string {
	count := 0
	for _, organization := range list.Organizations {
		if strings.EqualFold(organization.Name, target.Name) {
			count++
		}
	}
	if count == 1 {
		return target.Name
	}
	return target.ID
}

// organizationTable gives one line for each organization: a marker on the
// organization of the session, the name, and the role.
func organizationTable(list control.OrganizationList) string {
	var text strings.Builder
	table := tabwriter.NewWriter(&text, 0, 0, 2, ' ', 0)
	for _, organization := range list.Organizations {
		marker := " "
		if organization.ID == list.Current {
			marker = "*"
		}
		fmt.Fprintf(table, "%s %s\t%s\n", marker, organization.Name, organization.Role)
	}
	table.Flush()
	lines := strings.Split(strings.TrimSuffix(text.String(), "\n"), "\n")
	for index, line := range lines {
		lines[index] = strings.TrimRight(line, " ")
	}
	return strings.Join(lines, "\n")
}

// organizationSummary names each organization with the role of the person
// and a marker on the organization of the session, such as "Acme Inc.
// (admin, current), Beta LLC (member)".
func organizationSummary(list control.OrganizationList) string {
	parts := make([]string, 0, len(list.Organizations))
	for _, organization := range list.Organizations {
		var notes []string
		if organization.Role != "" {
			notes = append(notes, organization.Role)
		}
		if organization.ID == list.Current {
			notes = append(notes, "current")
		}
		part := organization.Name
		if len(notes) > 0 {
			part += " (" + strings.Join(notes, ", ") + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

// organizationListData is the data of a list: the ID of the organization of
// the session, or null, and each organization.
func organizationListData(list control.OrganizationList) map[string]any {
	return map[string]any{
		"current":       nullable(list.Current),
		"organizations": organizationEntries(list.Organizations, list.Current),
	}
}

// organizationEntries is never nil, so JSON shows an empty list, not null.
func organizationEntries(organizations []control.Organization, current string) []map[string]any {
	entries := make([]map[string]any, 0, len(organizations))
	for _, organization := range organizations {
		entries = append(entries, organizationEntry(organization, current))
	}
	return entries
}

// organizationEntry is one organization in data. switchable is true when the
// control API does not say.
func organizationEntry(organization control.Organization, current string) map[string]any {
	switchable := organization.Switchable == nil || *organization.Switchable
	return map[string]any{
		"id": organization.ID, "name": organization.Name, "role": nullable(organization.Role),
		"current": organization.ID == current, "switchable": switchable,
	}
}

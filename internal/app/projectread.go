package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
)

// maxSlugLength is the longest project slug that the control API accepts.
const maxSlugLength = 63

// reportURL is the page where a person reports a defect of oe or of the
// service that it reads.
const reportURL = "https://github.com/open-e2ee/oe/issues"

// validSlug reports whether value is a project slug: lowercase letters,
// digits, and single hyphens, at most maxSlugLength long.
func validSlug(value string) bool {
	return value != "" && slug(value) == value && len(value) <= maxSlugLength
}

// readProject reads project with a session that can read projects.
func (r *runner) readProject(ctx context.Context, project string) (control.Project, error) {
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return control.Project{}, err
	}
	return r.getProject(ctx, access, project)
}

// getProject reads project and gives each failure to find it a code and the
// command that lists the projects. A value that is not a slug fails before
// the read with PROJECT_INVALID. The control API refuses a project that the
// session cannot read with PROJECT_NOT_FOUND. It refuses a slug that it
// cannot read for another reason with CONTROL_CONFLICT, so the project list
// tells the two cases apart: a project that is not in the list is not found.
// The control API also uses CONTROL_CONFLICT for a project that it is
// deleting or that cannot take a request yet, and the code does not tell
// those apart from a record that the service holds in an inconsistent state.
// So a listed project that the read refuses keeps its code, its message says
// to report the refusal only when a retry gets it again, and its action names
// the page where a person reports it. No oe command repairs such a record.
func (r *runner) getProject(ctx context.Context, access credential.Credential, project string) (control.Project, error) {
	if !validSlug(project) {
		return control.Project{}, &problem{
			code: "PROJECT_INVALID", exit: exitUsage, next: "oe project list", data: map[string]any{"project": project},
			message: fmt.Sprintf("%q is not a project slug; a slug has at most %d lowercase letters, digits, and single hyphens", project, maxSlugLength),
		}
	}
	request := control.CredentialRequest{AccessToken: access.AccessToken}
	value, err := r.api.GetProject(ctx, request, project)
	refusal, ok := errors.AsType[*control.APIError](err)
	if !ok || (refusal.Code != "PROJECT_NOT_FOUND" && refusal.Code != "CONTROL_CONFLICT") {
		return value, err
	}
	notFound := &problem{
		code: "PROJECT_NOT_FOUND", exit: exitFailure, next: "oe project list", cause: err, data: map[string]any{"project": project},
		message: fmt.Sprintf("project %s was not found, or this account has no access to it", project),
	}
	if refusal.Code == "PROJECT_NOT_FOUND" {
		return control.Project{}, notFound
	}
	projects, listErr := r.api.ListProjects(ctx, request)
	if listErr != nil {
		return control.Project{}, err
	}
	for _, listed := range projects {
		if listed.Slug == project {
			return control.Project{}, &problem{
				code: refusal.Code, exit: exitFailure, cause: err,
				actionURL: reportURL, actionReason: "report",
				data: map[string]any{"project": project, "listed": true},
				message: fmt.Sprintf("project %s is in the project list, but the control API refused to read it (%s); "+
					"when a retry gets the same refusal, the service holds an inconsistent record of the project that no oe command repairs, "+
					"so report the project slug and this error at %s", project, strings.TrimSuffix(refusal.Message, "."), reportURL),
			}
		}
	}
	return control.Project{}, notFound
}

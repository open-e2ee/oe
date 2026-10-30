package app

import (
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/control"
)

func TestPublicIdentityInactiveProductionReportsActivationPrerequisite(t *testing.T) {
	for _, test := range []struct {
		name       string
		production *control.ProjectEnvironment
		writer     string
		noSection  bool
		next       string
		message    string
	}{
		{"absent", nil, "config", false, "oe config push", "run oe config push"},
		{"inactive", &control.ProjectEnvironment{State: control.ProductionInactive}, "config", false, "oe config push", "run oe config push"},
		{"available", &control.ProjectEnvironment{State: control.ProductionAvailable}, "config", false, "oe config push", "run oe config push"},
		{"console-writer", &control.ProjectEnvironment{State: control.ProductionInactive}, "console", false, "", "activate Production on the plan page"},
		{"missing-section", &control.ProjectEnvironment{State: control.ProductionInactive}, "config", true, "", "add production: {} under environments"},
	} {
		commands := []string{"current", "select"}
		if test.noSection {
			// Selection requires a declared identity before it reads the project.
			commands = []string{"current"}
		}
		for _, command := range commands {
			t.Run(test.name+"/"+command, func(t *testing.T) {
				f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
				f.project.Production, f.project.Writer = test.production, test.writer
				if test.noSection {
					f.dependencies.WorkingDir = noProductionProject(t, "sample")
				}
				args := []string{"identity", command, "--env", "production"}
				if command == "select" {
					args = append(args, "--dry-run")
				}
				exit, out, stderr := f.run(t, args...)
				failure := decodeEvent(t, []byte(out))
				if exit != exitFailure || stderr != "" || failure.Code != "ENVIRONMENT_NOT_ACTIVE" || failure.Next != test.next ||
					!strings.Contains(failure.Error, "production environment of project sample is not active") || !strings.Contains(failure.Error, test.message) {
					t.Fatal("inactive Production did not report its prerequisite", exit, out, stderr)
				}
				if strings.Contains(out, "retained attempt") || f.count("current") != 0 || f.count("preview") != 0 ||
					f.count("/v1/auth/session") != 1 || f.count("/v1/projects/sample") != 1 {
					t.Fatal("inactive Production reached identity transport or invented an attempt", out)
				}
				f.requireNoMutation(t)
			})
		}
	}
}

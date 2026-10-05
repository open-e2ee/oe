package app

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/envfile"
	"github.com/open-e2ee/oe/internal/projectlock"
)

// products are the products that oe new sets up. Without a product argument,
// oe new takes the only one.
var products = []string{"signal-relay"}

// cliPackage is the npm package of the CLI. oe new adds it to the
// devDependencies of the app, because open-e2ee.config.ts imports its config
// types.
const cliPackage = "@open-e2ee/oe"

// newFiles are the files that oe new writes, in the order of the report.
var newFiles = []string{config.Filename, ".env.local", ".gitignore", "package.json"}

// newFileChange is one file that oe new creates or updates.
type newFileChange struct {
	Path   string `json:"path"`
	Change string `json:"change"`
}

// new creates the project and its Sandbox environment with one
// create-if-absent call, then writes the config, the Relay connection, and
// the devDependency. A refusal writes nothing. The operation ID comes from the
// organization, the project, and the directory, so a retry of the same run
// replays the call.
func (r *runner) new(ctx context.Context, args []string) error {
	flags := newFlags("new")
	projectFlag := flags.String("project", "", "project slug")
	name := flags.String("name", "", "project display name")
	variable := flags.String("env-var", "", "Relay connection variable")
	dryRun := flags.Bool("dry-run", false, "show the changes and make none")
	if err := parseArguments(flags, "new", args); err != nil {
		return err
	}
	named := ""
	if flags.NArg() > 0 {
		named = flags.Arg(0)
		if err := parseFlags(flags, "new", flags.Args()[1:]); err != nil {
			return err
		}
	}
	if r.environment != "sandbox" {
		return &problem{
			code: "USAGE_ERROR", message: "oe new creates the Sandbox environment; use oe config push for Production",
			next: "oe new", exit: exitUsage,
		}
	}
	directory, err := filepath.Abs(r.directory)
	if err != nil {
		return err
	}
	if err := alreadySetUp(directory); err != nil {
		return err
	}
	product, err := r.newProduct(named)
	if err != nil {
		return err
	}
	project, err := newProject(*projectFlag, directory)
	if err != nil {
		return err
	}
	connection, err := envfile.Detect(directory, *variable)
	if err != nil {
		if *variable != "" {
			return usageError("new", "--env-var: "+err.Error())
		}
		return err
	}
	manifest, err := manifestWithCLI(directory)
	if err != nil {
		return err
	}
	value := config.New(project)
	value.Product = product
	value.Environments.Production = nil
	policy, err := controlPolicy(value, "sandbox")
	if err != nil {
		return err
	}
	data := map[string]any{
		"product": product, "project": project,
		"connection": connectionData(connection),
	}
	install := ""
	if manifest.exists {
		install = installCommand(directory)
		data["install"] = install
	}

	if *dryRun {
		data["dryRun"], data["changed"] = true, false
		data["files"] = plannedChanges(directory, manifest)
		rerun := []string{"new"}
		if named != "" {
			rerun = append(rerun, named)
		}
		rerun = append(rerun, "--project", project)
		if *name != "" {
			rerun = append(rerun, "--name", *name)
		}
		if *variable != "" {
			rerun = append(rerun, "--env-var", *variable)
		}
		return r.out.SuccessNext("new", fmt.Sprintf("oe new would create project %s with its Sandbox environment and write %s and .env.local. Nothing was changed.", project, config.Filename), commandLine(rerun), data)
	}

	access, err := r.access(ctx, "project:write", r.canPrompt())
	if err != nil {
		return err
	}
	claims := sessionClaimsOf(access.AccessToken)
	if claims.Organization != "" {
		data["organization"] = map[string]any{"id": claims.Organization}
	}
	credentials := control.CredentialRequest{
		AccessToken: access.AccessToken,
		OperationID: newOperationID(r.getenv, claims.Organization, project, directory),
	}
	request := control.BootstrapRequest{Policy: policy, ProjectSlug: project, Writer: "config", Name: *name}
	bootstrap, err := r.api.BootstrapSandbox(ctx, credentials, request)
	if refusal, ok := errors.AsType[*control.APIError](err); ok && refusal.Code == "TERMS_REQUIRED" && refusal.CanAccept && r.canPrompt() {
		identity, sessionErr := r.api.Session(ctx, control.CredentialRequest{AccessToken: access.AccessToken})
		if sessionErr != nil {
			return sessionErr
		}
		accepted, askErr := r.askTerms(identity.Organization.Name, refusal.Documents)
		if askErr != nil {
			return askErr
		}
		if !accepted {
			return err
		}
		if _, err := r.api.AcceptTerms(ctx, control.CredentialRequest{AccessToken: access.AccessToken}, r.termsActor(false)); err != nil {
			return err
		}
		// The console records the operation only after the terms check, so the
		// same operation ID creates the project now.
		bootstrap, err = r.api.BootstrapSandbox(ctx, credentials, request)
	}
	if refusal, ok := errors.AsType[*control.APIError](err); ok && refusal.Code == "PROJECT_NOT_FOUND" {
		return &problem{
			code: "PROJECT_NOT_FOUND", exit: exitFailure, next: "oe new --project " + project + "-2", cause: err,
			message: fmt.Sprintf("This account cannot create a project named %s. Choose another name.", project),
		}
	}
	if err != nil {
		return err
	}
	if !bootstrap.Created {
		return &problem{
			code: "PROJECT_EXISTS", exit: exitUsage, next: "oe new --project " + project + "-2",
			message: fmt.Sprintf("Project %s already exists in your organization. To use the existing project, run oe link %s.",
				project, project),
			data: map[string]any{"project": project},
		}
	}
	if bootstrap.Writer != "config" || bootstrap.ProjectSlug != project || bootstrap.Environment != "sandbox" {
		return errors.New("control API returned a bootstrap for a different project, writer, or environment")
	}
	if bootstrap.SandboxRelayURL == "" {
		return errors.New("control API returned an incomplete sandbox Relay connection")
	}

	files, err := writeNewProject(ctx, directory, value, connection.Variable, bootstrap.SandboxRelayURL)
	if err != nil {
		return err
	}
	data["environments"] = map[string]any{"sandbox": map[string]any{"state": "active", "revision": bootstrap.Revision}}
	data["files"], data["changed"] = files, true
	message := fmt.Sprintf("Created project %s with its Sandbox environment, and wrote %s and .env.local.", project, config.Filename)
	if install != "" {
		message += fmt.Sprintf(" Run %s to install %s.", install, cliPackage)
	}
	message += r.agentSetupHint(directory)
	return r.out.SuccessNext("new", message, "oe doctor --wait", data)
}

// writeNewProject writes the files of a created project under the project
// lock and reports each file that changed. The config is last, so a run that
// stops early leaves no config and its retry replays the operation.
func writeNewProject(ctx context.Context, directory string, value config.Config, variable, relayURL string) ([]newFileChange, error) {
	lock, err := projectlock.Acquire(ctx, directory)
	if err != nil {
		return nil, err
	}
	defer lock.Release()
	if err := alreadySetUp(directory); err != nil {
		return nil, err
	}
	before := make(map[string][]byte, len(newFiles))
	for _, file := range newFiles {
		contents, err := os.ReadFile(filepath.Join(directory, file))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		before[file] = contents
	}
	manifest, err := manifestWithCLI(directory)
	if err != nil {
		return nil, err
	}
	if err := writeRelayEnvironment(directory, ".env.local", variable, relayURL); err != nil {
		return nil, err
	}
	if err := ensureIgnored(directory, projectlock.Filename); err != nil {
		return nil, err
	}
	if manifest.edited != nil {
		if err := writePublicFile(filepath.Join(directory, "package.json"), manifest.edited); err != nil {
			return nil, err
		}
	}
	if err := config.Create(filepath.Join(directory, config.Filename), value); err != nil {
		return nil, err
	}
	files := []newFileChange{}
	for _, file := range newFiles {
		contents, err := os.ReadFile(filepath.Join(directory, file))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		switch {
		case before[file] == nil:
			files = append(files, newFileChange{file, "created"})
		case !bytes.Equal(before[file], contents):
			files = append(files, newFileChange{file, "updated"})
		}
	}
	return files, nil
}

// plannedChanges gives the files that oe new would write, without the Relay
// connection URL that only the control API gives.
func plannedChanges(directory string, manifest manifestChange) []newFileChange {
	change := func(file string) string {
		if _, err := os.Stat(filepath.Join(directory, file)); err == nil {
			return "updated"
		}
		return "created"
	}
	files := []newFileChange{{config.Filename, "created"}, {".env.local", change(".env.local")}}
	ignored, _ := os.ReadFile(filepath.Join(directory, ".gitignore"))
	lines := strings.Split(string(ignored), "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	if !slices.Contains(lines, ".env.local") || !slices.Contains(lines, projectlock.Filename) {
		files = append(files, newFileChange{".gitignore", change(".gitignore")})
	}
	if manifest.edited != nil {
		files = append(files, newFileChange{"package.json", "updated"})
	}
	return files
}

// alreadySetUp refuses a directory that a config sets up, in the directory or
// a parent. oe link connects such a directory to its project.
func alreadySetUp(directory string) error {
	path, err := config.Find(directory)
	if err != nil {
		return nil
	}
	data := map[string]any{"config": path}
	if value, err := config.Load(path); err == nil {
		data["project"] = value.Project
	}
	return &problem{
		code: "ALREADY_SET_UP", exit: exitUsage, next: "oe link", data: data,
		message: path + " already sets up this directory. To connect it to its project, run oe link.",
	}
}

// newProduct gives the named product, or the only product. With more than one
// product, a person picks one and any other caller must name one.
func (r *runner) newProduct(named string) (string, error) {
	if named != "" {
		if !slices.Contains(products, named) {
			return "", &problem{
				code: "USAGE_ERROR", exit: exitUsage, next: "oe help new",
				message: fmt.Sprintf("unknown product %q; the products are %s", named, strings.Join(products, ", ")),
				data:    map[string]any{"choices": products},
			}
		}
		return named, nil
	}
	if len(products) == 1 {
		return products[0], nil
	}
	required := &problem{
		code: "PRODUCT_REQUIRED", exit: exitUsage, next: "oe new " + products[0],
		message: "name the product: " + strings.Join(products, ", "),
		data:    map[string]any{"choices": products},
	}
	if !r.canPrompt() {
		return "", required
	}
	fmt.Fprintln(r.errOut, "Products:")
	for index, product := range products {
		fmt.Fprintf(r.errOut, "  %d. %s\n", index+1, product)
	}
	fmt.Fprint(r.errOut, "Product: ")
	answer, err := bufio.NewReader(r.in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	answer = strings.TrimSpace(answer)
	for index, product := range products {
		if answer == product || answer == strconv.Itoa(index+1) {
			return product, nil
		}
	}
	return "", required
}

// newProject gives the project slug from --project, else from the name of the
// directory.
func newProject(flag, directory string) (string, error) {
	if flag != "" {
		if slug(flag) != flag {
			return "", &problem{
				code: "PROJECT_INVALID", exit: exitUsage, next: "oe new --project " + cmp.Or(slug(flag), "my-app"),
				message: fmt.Sprintf("--project %q is not a project slug; use lowercase letters, digits, and single hyphens", flag),
			}
		}
		return flag, nil
	}
	if project := slug(filepath.Base(directory)); project != "" {
		return project, nil
	}
	return "", &problem{
		code: "PROJECT_REQUIRED", exit: exitUsage, next: "oe new --project my-app",
		message: "the directory name gives no project slug; name the project with --project",
	}
}

// newOperationID is the idempotency key of the create call. OE_OPERATION_ID
// overrides it.
func newOperationID(getenv func(string) string, organization, project, directory string) string {
	if supplied := strings.TrimSpace(getenv("OE_OPERATION_ID")); supplied != "" {
		return supplied
	}
	sum := sha256.Sum256([]byte(organization + "\x00" + project + "\x00" + directory))
	return "oe_new_" + hex.EncodeToString(sum[:])
}

func connectionData(connection envfile.Connection) map[string]any {
	data := map[string]any{"file": ".env.local", "variable": connection.Variable}
	if connection.Framework != "" {
		data["framework"] = connection.Framework
	}
	return data
}

// manifestChange is the package.json of the app. edited is the new file, or
// nil when package.json already names the CLI or does not exist.
type manifestChange struct {
	exists bool
	edited []byte
}

func manifestWithCLI(directory string) (manifestChange, error) {
	path := filepath.Join(directory, "package.json")
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return manifestChange{}, nil
	}
	if err != nil {
		return manifestChange{}, fmt.Errorf("read %s: %w", path, err)
	}
	edited, err := addDevDependency(contents, cliPackage, Version)
	if err != nil {
		return manifestChange{}, fmt.Errorf("read %s: %w", path, err)
	}
	return manifestChange{exists: true, edited: edited}, nil
}

// member is one member of a JSON object, in the order of the source.
type member struct {
	key   string
	value json.RawMessage
}

// addDevDependency adds name at version to the devDependencies of a
// package.json. It keeps the order of the members and the indent of the file,
// and puts name in sorted order, as npm does. It returns nil when name is
// already a dependency of any kind.
func addDevDependency(contents []byte, name, version string) ([]byte, error) {
	source := bytes.TrimPrefix(contents, []byte("\xef\xbb\xbf"))
	root, err := objectMembers(source)
	if err != nil {
		return nil, err
	}
	var devDependencies []member
	at := -1
	for index, field := range root {
		switch field.key {
		case "dependencies", "devDependencies", "peerDependencies", "optionalDependencies":
			dependencies, err := objectMembers(field.value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", field.key, err)
			}
			if slices.ContainsFunc(dependencies, func(dependency member) bool { return dependency.key == name }) {
				return nil, nil
			}
			if field.key == "devDependencies" {
				devDependencies, at = dependencies, index
			}
		}
	}
	added := member{name, jsonString(version)}
	position, _ := slices.BinarySearchFunc(devDependencies, name, func(dependency member, target string) int {
		return strings.Compare(dependency.key, target)
	})
	devDependencies = slices.Insert(devDependencies, position, added)
	object, err := encodeMembers(devDependencies)
	if err != nil {
		return nil, err
	}
	if at < 0 {
		root = append(root, member{"devDependencies", object})
	} else {
		root[at].value = object
	}
	compact, err := encodeMembers(root)
	if err != nil {
		return nil, err
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, compact, "", indentOf(source)); err != nil {
		return nil, err
	}
	if bytes.HasSuffix(source, []byte("\n")) {
		indented.WriteByte('\n')
	}
	return indented.Bytes(), nil
}

// objectMembers decodes a JSON object into its members in source order.
func objectMembers(source []byte) ([]member, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("the value is not a JSON object")
	}
	var members []member
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, _ := token.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		members = append(members, member{key, value})
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err == nil {
		return nil, errors.New("the file holds more than one JSON value")
	}
	return members, nil
}

func encodeMembers(members []member) (json.RawMessage, error) {
	var object bytes.Buffer
	object.WriteByte('{')
	for index, field := range members {
		if index > 0 {
			object.WriteByte(',')
		}
		object.Write(jsonString(field.key))
		object.WriteByte(':')
		if err := json.Compact(&object, field.value); err != nil {
			return nil, err
		}
	}
	object.WriteByte('}')
	return object.Bytes(), nil
}

// jsonString encodes value as a JSON string without HTML escapes, as
// JSON.stringify does.
func jsonString(value string) []byte {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
}

// indentOf gives the indent of the first indented line, or two spaces.
func indentOf(source []byte) string {
	for _, line := range strings.Split(string(source), "\n")[1:] {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed != "" && len(trimmed) < len(line) {
			return line[:len(line)-len(trimmed)]
		}
	}
	return "  "
}

// installCommand names the install command of the package manager that the
// lockfile of the app names, else npm.
func installCommand(directory string) string {
	for _, manager := range []struct{ lockfile, command string }{
		{"pnpm-lock.yaml", "pnpm install"},
		{"yarn.lock", "yarn install"},
		{"bun.lock", "bun install"},
		{"bun.lockb", "bun install"},
	} {
		if _, err := os.Stat(filepath.Join(directory, manager.lockfile)); err == nil {
			return manager.command
		}
	}
	return "npm install"
}

// retired answers a command that oe new and oe link replace. A directory that
// a config sets up gets oe link, and any other directory gets oe new.
func (r *runner) retired(command string) error {
	if path, err := config.Find(r.directory); err == nil {
		return &problem{
			code: "USAGE_ERROR", exit: exitUsage, next: "oe link",
			message: fmt.Sprintf("oe has no %s command. %s already sets up this directory; oe link connects it to its project.", command, path),
		}
	}
	return &problem{
		code: "USAGE_ERROR", exit: exitUsage, next: "oe new",
		message: fmt.Sprintf("oe has no %s command. oe new creates a project and its Sandbox environment.", command),
	}
}

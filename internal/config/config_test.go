package config

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const header = "// Public service policy. Do not put secrets in this file.\n" +
	"import { defineConfig } from \"@open-e2ee/oe/config\";\n\n"

const sample = header + `export default defineConfig({
  product: "signal-relay",
  project: "secure-chat",
  relay: {
    deliveryRetention: "30d",
    attachmentRetention: "30d",
  },
  environments: {
    sandbox: {
      relay: { deliveryRetention: "1d", attachmentRetention: "1d" },
    },
  },
});
`

// writeConfig writes contents as the config file of a new project directory.
func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), Filename)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireCode(t *testing.T, err error, code string) *Error {
	t.Helper()
	failure, ok := errors.AsType[*Error](err)
	if !ok || failure.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	return failure
}

func fieldErrors(t *testing.T, failure *Error) []FieldError {
	t.Helper()
	fields, ok := failure.Data["errors"].([]FieldError)
	if !ok || len(fields) == 0 {
		t.Fatalf("no field errors in %#v", failure.Data)
	}
	return fields
}

func requireFieldError(t *testing.T, failure *Error, path, fragment string) {
	t.Helper()
	for _, field := range fieldErrors(t, failure) {
		if field.Path == path && strings.Contains(field.Message, fragment) {
			return
		}
	}
	t.Fatalf("no error at %s with %q in %#v", path, fragment, failure.Data["errors"])
}

func requireFile(t *testing.T, path, want string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != want {
		t.Fatalf("file changed unexpectedly\nwant:\n%s\ngot:\n%s", want, contents)
	}
}

// fakeNode puts runtime on PATH under the name node.
func fakeNode(t *testing.T, runtimeName string) {
	t.Helper()
	target, err := exec.LookPath(runtimeName)
	if err != nil {
		t.Skipf("%s is not installed", runtimeName)
	}
	if runtime.GOOS == "windows" {
		t.Skip("a symbolic link named node needs developer mode on Windows")
	}
	directory := t.TempDir()
	if err := os.Symlink(target, filepath.Join(directory, "node")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
}

// preload runs source in node before the loader, through NODE_OPTIONS. The
// quotes are percent-encoded, because NODE_OPTIONS parsing removes them.
func preload(t *testing.T, source string) {
	t.Helper()
	t.Setenv("NODE_OPTIONS", "--import=data:text/javascript,"+strings.ReplaceAll(source, `"`, "%22"))
}

func TestLoadEvaluatesTheDefaultExport(t *testing.T) {
	path := writeConfig(t, header+`type Retention = "1d" | "7d" | "30d";
const sandboxRetention: Retention = "1d";

console.log("output from the config file does not reach stdout");

export default defineConfig({
  product: "signal-relay",
  project: "secure-chat",
  relay: {
    deliveryRetention: "30d",
    attachmentRetention: "7d" as const,
  },
  environments: {
    sandbox: {
      relay: { deliveryRetention: sandboxRetention },
    },
    production: {},
  },
});
`)
	value, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Product: "signal-relay",
		Project: "secure-chat",
		Relay:   RelayPolicy{DeliveryRetention: "30d", AttachmentRetention: "7d", RelayReceipts: true},
		Environments: Environments{
			Sandbox:    Environment{Relay: &RelayOverride{DeliveryRetention: "1d"}},
			Production: &Environment{},
		},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("want %#v, got %#v", want, value)
	}
	policy, err := value.RelayPolicyFor("sandbox")
	if err != nil || policy != (RelayPolicy{DeliveryRetention: "1d", AttachmentRetention: "7d", RelayReceipts: true}) {
		t.Fatalf("the Sandbox override must merge field by field: %#v, %v", policy, err)
	}
}

func TestLoadWorksWithoutNodeModules(t *testing.T) {
	path := writeConfig(t, sample)
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		if _, err := os.Stat(filepath.Join(directory, "node_modules")); err == nil {
			t.Fatalf("%s has node_modules, so the test proves nothing", directory)
		}
		if filepath.Dir(directory) == directory {
			break
		}
	}
	value, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.Project != "secure-chat" {
		t.Fatalf("unexpected config: %#v", value)
	}
}

func TestLoadWorksUnderCommonJSPackage(t *testing.T) {
	for name, manifest := range map[string]string{
		"commonjs":     `{"type": "commonjs"}`,
		"module":       `{"type": "module"}`,
		"no type":      `{"name": "secure-chat"}`,
		"no manifest":  "",
		"with require": `{"type": "commonjs", "dependencies": {"next": "16.0.0"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, sample)
			if manifest != "" {
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), "package.json"), []byte(manifest), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Load(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoadAllowsComputedValues(t *testing.T) {
	path := writeConfig(t, header+`const days = 7;
const shared = { deliveryRetention: "7d", attachmentRetention: "30d" } as const;
const name = (parts: string[]) => parts.join("-");

export default defineConfig({
  product: "signal-relay",
  project: name(["secure", "chat"]),
  relay: { ...shared },
  environments: {
    sandbox: { relay: { attachmentRetention: `+"`${days}d`"+` } },
    ...(days > 1 ? { production: {} } : {}),
  },
});
`)
	value, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.Project != "secure-chat" || value.Relay.DeliveryRetention != "7d" || value.Environments.Sandbox.Relay.AttachmentRetention != "7d" || value.Environments.Production == nil {
		t.Fatalf("unexpected config: %#v", value)
	}
}

func TestLoadRefusesOldNode(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		path := writeConfig(t, sample)
		t.Setenv("PATH", t.TempDir())
		failure := requireCode(t, loadError(path), "NODE_REQUIRED")
		if !strings.Contains(failure.Message, "Node.js 22.18 or later") {
			t.Fatalf("unexpected message: %s", failure.Message)
		}
	})
	for name, version := range map[string]string{"22.17": "22.17.0", "20": "20.20.2", "23.5": "23.5.0"} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, sample)
			preload(t, `Object.defineProperty(process.versions,"node",{value:"`+version+`"})`)
			failure := requireCode(t, loadError(path), "NODE_REQUIRED")
			if !strings.Contains(failure.Message, "Node.js 22.18 or later") || !strings.Contains(failure.Message, version) {
				t.Fatalf("unexpected message: %s", failure.Message)
			}
		})
	}
	t.Run("type stripping off", func(t *testing.T) {
		path := writeConfig(t, sample)
		t.Setenv("NODE_OPTIONS", "--no-experimental-strip-types")
		requireCode(t, loadError(path), "NODE_REQUIRED")
	})
}

func TestLoadRefusesBun(t *testing.T) {
	for name, source := range map[string]string{
		"bun":  `Object.defineProperty(process.versions,"bun",{value:"1.3.12"})`,
		"deno": `Object.defineProperty(process.versions,"deno",{value:"2.9.5"})`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, sample)
			preload(t, source)
			failure := requireCode(t, loadError(path), "NODE_REQUIRED")
			if !strings.Contains(strings.ToLower(failure.Message), name) {
				t.Fatalf("the message must name the runtime: %s", failure.Message)
			}
		})
	}
	for _, name := range []string{"bun", "deno"} {
		t.Run("real "+name, func(t *testing.T) {
			path := writeConfig(t, sample)
			fakeNode(t, name)
			requireCode(t, loadError(path), "NODE_REQUIRED")
		})
	}
}

func TestLoadRejectsNonJSONValue(t *testing.T) {
	for name, test := range map[string]struct{ source, fragment string }{
		"no default export": {`export const config = {};`, "no default export"},
		"undefined":         {`export default undefined;`, "undefined"},
		"function":          {`export default defineConfig({ product: "signal-relay", project: () => "chat" });`, "project"},
		"not finite":        {`export default { product: "signal-relay", project: "chat", relay: { deliveryRetention: NaN } };`, "relay.deliveryRetention"},
		"bigint":            {`export default { project: 1n };`, "project"},
		"date":              {`export default { project: new Date(0) };`, "project"},
		"map":               {`export default { environments: new Map() };`, "environments"},
		"symbol":            {`export default { project: Symbol("chat") };`, "project"},
		"sparse array":      {`export default { project: [1, , 3] };`, "project"},
		"cycle":             {`const value: any = { product: "signal-relay" }; value.relay = value; export default value;`, "relay"},
		"throws":            {`throw new Error("config exploded");`, "config exploded"},
		"syntax":            {`export default {`, Filename},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, header+test.source+"\n")
			failure := requireCode(t, loadError(path), "CONFIG_INVALID")
			if !strings.Contains(failure.Message, test.fragment) {
				t.Fatalf("the message must name %q: %s", test.fragment, failure.Message)
			}
		})
	}
}

func TestReadRequiresProductAndProject(t *testing.T) {
	for _, field := range []string{"product", "project"} {
		t.Run(field, func(t *testing.T) {
			var kept []string
			for _, line := range strings.Split(sample, "\n") {
				if !strings.HasPrefix(line, "  "+field+":") {
					kept = append(kept, line)
				}
			}
			path := writeConfig(t, strings.Join(kept, "\n"))
			failure := requireCode(t, loadError(path), "CONFIG_INVALID")
			requireFieldError(t, failure, field, "required")
		})
	}
	t.Run("unknown product", func(t *testing.T) {
		path := writeConfig(t, strings.Replace(sample, `"signal-relay"`, `"mls"`, 1))
		requireFieldError(t, requireCode(t, loadError(path), "CONFIG_INVALID"), "product", "signal-relay")
	})
	t.Run("project slug", func(t *testing.T) {
		path := writeConfig(t, strings.Replace(sample, `"secure-chat"`, `"Secure--Chat"`, 1))
		requireFieldError(t, requireCode(t, loadError(path), "CONFIG_INVALID"), "project", "")
	})
}

func TestProductionSectionIsOptional(t *testing.T) {
	value, err := Load(writeConfig(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	if value.Environments.Production != nil {
		t.Fatalf("no Production section was written: %#v", value.Environments.Production)
	}
	if _, err := value.RelayPolicyFor("production"); err == nil || !strings.Contains(err.Error(), "environments.production") {
		t.Fatalf("a missing Production section must be named: %v", err)
	}
	withProduction := strings.Replace(sample, "\n  },\n});", "\n    production: {},\n  },\n});", 1)
	value, err = Load(writeConfig(t, withProduction))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := value.RelayPolicyFor("production")
	if err != nil || policy != value.Relay {
		t.Fatalf("an empty Production section takes the shared policy: %#v, %v", policy, err)
	}
	withoutSandbox := strings.Replace(sample, `      relay: { deliveryRetention: "1d", attachmentRetention: "1d" },`, "", 1)
	withoutSandbox = strings.Replace(withoutSandbox, "    sandbox: {\n\n    },\n", "", 1)
	failure := requireCode(t, loadError(writeConfig(t, withoutSandbox)), "CONFIG_INVALID")
	requireFieldError(t, failure, "environments.sandbox", "required")
}

func TestRelayReceiptsDefaultsOnAndMergesPerEnvironment(t *testing.T) {
	const shared = "    attachmentRetention: \"30d\",\n  },"
	const sandbox = `relay: { deliveryRetention: "1d", attachmentRetention: "1d" },`
	const production = "    production: {},\n"
	for _, test := range []struct {
		name                string
		edits               [][2]string
		shared              bool
		sandbox, production bool
	}{
		{"absent", nil, true, true, true},
		{"shared on", [][2]string{{shared, "    attachmentRetention: \"30d\",\n    relayReceipts: true,\n  },"}}, true, true, true},
		{"shared off", [][2]string{{shared, "    attachmentRetention: \"30d\",\n    relayReceipts: false,\n  },"}}, false, false, false},
		{
			"sandbox override off",
			[][2]string{{sandbox, `relay: { deliveryRetention: "1d", attachmentRetention: "1d", relayReceipts: false },`}},
			true, false, true,
		},
		{
			"production override off",
			[][2]string{{production, "    production: { relay: { relayReceipts: false } },\n"}},
			true, true, false,
		},
		{
			"override on over shared off",
			[][2]string{
				{shared, "    attachmentRetention: \"30d\",\n    relayReceipts: false,\n  },"},
				{sandbox, `relay: { deliveryRetention: "1d", attachmentRetention: "1d", relayReceipts: true },`},
			},
			false, true, false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := strings.Replace(sample, "\n  },\n});", "\n"+production+"  },\n});", 1)
			for _, edit := range test.edits {
				if !strings.Contains(source, edit[0]) {
					t.Fatalf("the source has no %q", edit[0])
				}
				source = strings.Replace(source, edit[0], edit[1], 1)
			}
			value, err := Load(writeConfig(t, source))
			if err != nil {
				t.Fatal(err)
			}
			if value.Relay.RelayReceipts != test.shared {
				t.Fatalf("the shared relayReceipts is %v, want %v", value.Relay.RelayReceipts, test.shared)
			}
			for environment, want := range map[string]bool{"sandbox": test.sandbox, "production": test.production} {
				policy, err := value.RelayPolicyFor(environment)
				if err != nil || policy.RelayReceipts != want {
					t.Fatalf("the %s policy is %#v (%v), want relayReceipts %v", environment, policy, err, want)
				}
			}
		})
	}
	if !New("secure-chat").Relay.RelayReceipts {
		t.Fatal("a new config must turn Relay delivery receipts on")
	}
}

func TestSchemaErrorNamesThePropertyPath(t *testing.T) {
	for name, test := range map[string]struct{ from, to, path, fragment string }{
		"enum": {
			`relay: { deliveryRetention: "1d"`, `relay: { deliveryRetention: "2d"`,
			"environments.sandbox.relay.deliveryRetention", "1h",
		},
		"unknown field": {
			`project: "secure-chat",`, `project: "secure-chat", writer: "config",`,
			"writer", "not allowed",
		},
		"unknown environment": {
			"    sandbox: {", "    staging: {},\n    sandbox: {",
			"environments.staging", "not allowed",
		},
		"type": {
			`deliveryRetention: "30d",`, `deliveryRetention: 30,`,
			"relay.deliveryRetention", "",
		},
		"relayReceipts type": {
			`attachmentRetention: "30d",`, `attachmentRetention: "30d", relayReceipts: "on",`,
			"relay.relayReceipts", "",
		},
		"relayReceipts override type": {
			`relay: { deliveryRetention: "1d"`, `relay: { relayReceipts: 0, deliveryRetention: "1d"`,
			"environments.sandbox.relay.relayReceipts", "",
		},
		"managed maximum": {
			`relay: { deliveryRetention: "1d", attachmentRetention: "1d" }`, `relay: { attachmentRetention: "1d" }`,
			"environments.sandbox.relay.deliveryRetention", "7d",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(sample, test.from) {
				t.Fatalf("the sample has no %q", test.from)
			}
			path := writeConfig(t, strings.Replace(sample, test.from, test.to, 1))
			failure := requireCode(t, loadError(path), "CONFIG_INVALID")
			requireFieldError(t, failure, test.path, test.fragment)
			if !strings.Contains(failure.Message, test.path) {
				t.Fatalf("the message must name %s: %s", test.path, failure.Message)
			}
		})
	}
}

const ordered = "// Public service policy. Do not put secrets in this file.\n" +
	"import { defineConfig } from \"@open-e2ee/oe/config\";\n" +
	"\n" +
	"/* The keys are in a custom order. */\n" +
	"export default defineConfig({\n" +
	"  // Sandbox first.\n" +
	"  environments: {\n" +
	"    sandbox: {}, // Sandbox uses the shared policy.\n" +
	"  },\n" +
	"  relay: {\n" +
	"    attachmentRetention: \"7d\", // attachments\n" +
	"    deliveryRetention: \"7d\",\n" +
	"  },\n" +
	"  project: \"secure-chat\", /* the slug */\n" +
	"  product: \"signal-relay\",\n" +
	"} satisfies Record<string, unknown>);\n"

func crlf(value string) string { return strings.ReplaceAll(value, "\n", "\r\n") }

func TestEditKeepsCommentsAndOrder(t *testing.T) {
	for name, newline := range map[string]func(string) string{"LF": func(value string) string { return value }, "CRLF": crlf} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, newline(ordered))
			if err := Edit(path, Change{Path: []string{"project"}, Value: "renamed-chat"}); err != nil {
				t.Fatal(err)
			}
			requireFile(t, path, newline(strings.Replace(ordered, `"secure-chat"`, `"renamed-chat"`, 1)))
			value, err := Load(path)
			if err != nil || value.Project != "renamed-chat" {
				t.Fatalf("the edited file must load: %#v, %v", value, err)
			}
		})
	}
}

func TestEditChangesOnlyTheNamedPath(t *testing.T) {
	source := header + `export default defineConfig({
  product: 'signal-relay',
  project: 'secure-chat',
  relay: { deliveryRetention: '1d', attachmentRetention: '1d' },
  environments: {
    sandbox: {
      relay: { deliveryRetention: '1d', attachmentRetention: '1d' },
    },
  },
});
`
	path := writeConfig(t, source)
	if err := Edit(path, Change{Path: []string{"environments", "sandbox", "relay", "attachmentRetention"}, Value: "3d"}); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(source, `attachmentRetention: '1d' },
    },`, `attachmentRetention: '3d' },
    },`, 1)
	if want == source {
		t.Fatal("the expected file must differ from the source")
	}
	requireFile(t, path, want)
	if err := Edit(path, Change{Path: []string{"environments", "sandbox", "relay", "attachmentRetention"}, Value: "3d"}); err != nil {
		t.Fatal(err)
	}
	requireFile(t, path, want)
}

func TestEditAddsAMissingSection(t *testing.T) {
	for name, test := range map[string]struct {
		source, want string
		change       Change
	}{
		"section after a trailing comment": {
			source: ordered,
			change: Change{Path: []string{"environments", "production"}, Value: map[string]any{}},
			want: strings.Replace(ordered, "    sandbox: {}, // Sandbox uses the shared policy.\n",
				"    sandbox: {}, // Sandbox uses the shared policy.\n    production: {},\n", 1),
		},
		"field in an empty section": {
			source: ordered,
			change: Change{Path: []string{"environments", "sandbox", "relay", "deliveryRetention"}, Value: "3d"},
			want: strings.Replace(ordered, "    sandbox: {}, // Sandbox uses the shared policy.\n",
				"    sandbox: {\n      relay: {\n        deliveryRetention: \"3d\",\n      },\n    }, // Sandbox uses the shared policy.\n", 1),
		},
		"section with fields": {
			source: sample,
			change: Change{Path: []string{"environments", "production"}, Value: map[string]any{"relay": map[string]any{"deliveryRetention": "7d"}}},
			want: strings.Replace(sample, "      relay: { deliveryRetention: \"1d\", attachmentRetention: \"1d\" },\n    },\n",
				"      relay: { deliveryRetention: \"1d\", attachmentRetention: \"1d\" },\n    },\n    production: {\n      relay: {\n        deliveryRetention: \"7d\",\n      },\n    },\n", 1),
		},
		"no trailing commas": {
			source: header + "export default {\n  product: \"signal-relay\",\n  project: \"secure-chat\",\n  relay: { deliveryRetention: \"7d\", attachmentRetention: \"7d\" },\n  environments: {\n    sandbox: {} // note\n  }\n}\n",
			change: Change{Path: []string{"environments", "production"}, Value: map[string]any{}},
			want:   header + "export default {\n  product: \"signal-relay\",\n  project: \"secure-chat\",\n  relay: { deliveryRetention: \"7d\", attachmentRetention: \"7d\" },\n  environments: {\n    sandbox: {}, // note\n    production: {}\n  }\n}\n",
		},
		"field in a one-line object": {
			source: strings.Replace(sample, `relay: { deliveryRetention: "1d", attachmentRetention: "1d" }`, `relay: { deliveryRetention: "1d" }`, 1),
			change: Change{Path: []string{"environments", "sandbox", "relay"}, Value: map[string]any{"deliveryRetention": "3d", "attachmentRetention": "1d"}},
			want:   strings.Replace(sample, `deliveryRetention: "1d", attachmentRetention: "1d"`, `deliveryRetention: "3d", attachmentRetention: "1d"`, 1),
		},
	} {
		for newlineName, newline := range map[string]func(string) string{"LF": func(value string) string { return value }, "CRLF": crlf} {
			t.Run(name+" "+newlineName, func(t *testing.T) {
				path := writeConfig(t, newline(test.source))
				if err := Edit(path, test.change); err != nil {
					t.Fatal(err)
				}
				requireFile(t, path, newline(test.want))
			})
		}
	}
}

func TestEditOfAComputedValueWritesNothingAndReturnsTheEdit(t *testing.T) {
	for name, test := range map[string]struct {
		from, to, expression string
		change               Change
	}{
		"variable": {
			`project: "secure-chat",`, `project: slug,`, "slug",
			Change{Path: []string{"project"}, Value: "renamed-chat"},
		},
		"call": {
			`attachmentRetention: "1d" }`, `attachmentRetention: pick("1d") }`, `pick("1d")`,
			Change{Path: []string{"environments", "sandbox", "relay", "attachmentRetention"}, Value: "3d"},
		},
		"conditional": {
			`project: "secure-chat",`, `project: process.env.CI ? "ci-chat" : "secure-chat",`, `process.env.CI ? "ci-chat" : "secure-chat"`,
			Change{Path: []string{"project"}, Value: "renamed-chat"},
		},
		"spread": {
			`relay: { deliveryRetention: "1d", attachmentRetention: "1d" },`, `...base,`, "...base",
			Change{Path: []string{"environments", "sandbox", "relay", "attachmentRetention"}, Value: "3d"},
		},
		"value before a spread": {
			`relay: { deliveryRetention: "1d", attachmentRetention: "1d" },`, `relay: { attachmentRetention: "1d", ...base.relay },`, "...base.relay",
			Change{Path: []string{"environments", "sandbox", "relay", "attachmentRetention"}, Value: "3d"},
		},
		"template": {
			`project: "secure-chat",`, "project: `${slug}`,", "`${slug}`",
			Change{Path: []string{"project"}, Value: "renamed-chat"},
		},
		"variable section": {
			"    sandbox: {\n      relay: { deliveryRetention: \"1d\", attachmentRetention: \"1d\" },\n    },", "    sandbox: base,", "base",
			Change{Path: []string{"environments", "sandbox", "relay", "attachmentRetention"}, Value: "3d"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(sample, test.from) {
				t.Fatalf("the sample has no %q", test.from)
			}
			source := strings.Replace(strings.Replace(sample, test.from, test.to, 1), "export default", `const slug = "secure-chat";
const pick = (value: string) => value;
const base = { relay: { deliveryRetention: "1d", attachmentRetention: "1d" } } as const;

export default`, 1)
			path := writeConfig(t, source)
			if _, err := Load(path); err != nil {
				t.Fatalf("the computed file must load: %v", err)
			}
			failure := requireCode(t, Edit(path, test.change), "CONFIG_EDIT_REQUIRED")
			want := ManualEdit{
				File: path, Path: strings.Join(test.change.Path, "."),
				CurrentExpression: test.expression, NewValue: test.change.Value,
			}
			if edits, ok := failure.Data["edits"].([]ManualEdit); !ok || !reflect.DeepEqual(edits, []ManualEdit{want}) {
				t.Fatalf("want %#v, got %#v", want, failure.Data["edits"])
			}
			requireFile(t, path, source)
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatalf("an edit that writes nothing leaves no file behind: %v, %v", entries, err)
			}
		})
	}
}

func TestEditReturnsEveryComputedValue(t *testing.T) {
	source := strings.Replace(strings.Replace(sample,
		`project: "secure-chat",`, `project: ["secure", "chat"].join("-"),`, 1),
		`relay: { deliveryRetention: "1d", attachmentRetention: "1d" },`,
		`relay: { deliveryRetention: short, attachmentRetention: short },`, 1)
	source = strings.Replace(source, "export default", "const short = \"1d\";\n\nexport default", 1)
	path := writeConfig(t, source)
	changes := []Change{
		{Path: []string{"project"}, Value: "renamed-chat"},
		{Path: []string{"relay", "deliveryRetention"}, Value: "7d"},
		{Path: []string{"environments", "sandbox", "relay"}, Value: map[string]any{"deliveryRetention": "3d", "attachmentRetention": "12h"}},
	}
	want := []ManualEdit{
		{File: path, Path: "project", CurrentExpression: `["secure", "chat"].join("-")`, NewValue: "renamed-chat"},
		{File: path, Path: "environments.sandbox.relay.deliveryRetention", CurrentExpression: "short", NewValue: "3d"},
		{File: path, Path: "environments.sandbox.relay.attachmentRetention", CurrentExpression: "short", NewValue: "12h"},
	}
	for name, check := range map[string]func(string, ...Change) error{"Edit": Edit, "CheckEdit": CheckEdit} {
		failure := requireCode(t, check(path, changes...), "CONFIG_EDIT_REQUIRED")
		edits, _ := failure.Data["edits"].([]ManualEdit)
		sortEdits := func(edits []ManualEdit) []ManualEdit {
			edits = slices.Clone(edits)
			slices.SortFunc(edits, func(a, b ManualEdit) int { return strings.Compare(a.Path, b.Path) })
			return edits
		}
		if !reflect.DeepEqual(sortEdits(edits), sortEdits(want)) {
			t.Fatalf("%s: want %#v, got %#v", name, want, failure.Data["edits"])
		}
		for _, edit := range want {
			if !strings.Contains(failure.Message, edit.Path) {
				t.Fatalf("%s: the message does not name %s: %s", name, edit.Path, failure.Message)
			}
		}
		requireFile(t, path, source)
		if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
			t.Fatalf("%s: an edit that writes nothing leaves no file behind: %v, %v", name, entries, err)
		}
	}
}

func TestCheckEditWritesNothing(t *testing.T) {
	path := writeConfig(t, sample)
	if err := CheckEdit(path, Change{Path: []string{"relay", "deliveryRetention"}, Value: "7d"}); err != nil {
		t.Fatal(err)
	}
	requireFile(t, path, sample)
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("CheckEdit left a file behind: %v, %v", entries, err)
	}
}

func TestApplyGivesTheValueThatEditWrites(t *testing.T) {
	value := New("secure-chat")
	value.Environments.Production = nil
	path := filepath.Join(t.TempDir(), Filename)
	if err := Create(path, value); err != nil {
		t.Fatal(err)
	}
	changes := []Change{
		{Path: []string{"environments", "sandbox", "relay", "deliveryRetention"}, Value: "3d"},
		{Path: []string{"environments", "production"}, Value: map[string]any{}},
		{Path: []string{"environments", "production", "relay", "attachmentRetention"}, Value: "7d"},
		{Path: []string{"environments", "production", "relay", "relayReceipts"}, Value: false},
	}
	applied, err := Apply(value, changes...)
	if err != nil {
		t.Fatal(err)
	}
	if err := Edit(path, changes...); err != nil {
		t.Fatal(err)
	}
	edited, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(applied, edited) {
		t.Fatalf("Apply gave %#v, Edit wrote %#v", applied, edited)
	}
	if applied.Environments.Production == nil || applied.Environments.Sandbox.Relay.DeliveryRetention != "3d" ||
		applied.Environments.Production.Relay.RelayReceipts == nil || *applied.Environments.Production.Relay.RelayReceipts {
		t.Fatalf("Apply did not apply the changes: %#v", applied)
	}
}

func TestRetentionIsTheInverseOfRetentionSeconds(t *testing.T) {
	for value := range retentionSeconds {
		seconds, err := RetentionSeconds(value)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := Retention(seconds); err != nil || got != value {
			t.Fatalf("Retention(%d) = %q, %v, want %q", seconds, got, err, value)
		}
	}
	if _, err := Retention(90_000); err == nil {
		t.Fatal("Retention accepted a length that is not a retention value")
	}
}

func TestCreateWritesALoadableFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "project", "nested")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(directory), Filename)
	if err := Create(path, New("secure-chat")); err != nil {
		t.Fatal(err)
	}
	found, err := Find(directory)
	if err != nil || found != path {
		t.Fatalf("want %s, got %s, %v", path, found, err)
	}
	value, err := Load(found)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, New("secure-chat")) {
		t.Fatalf("want %#v, got %#v", New("secure-chat"), value)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(contents), "// Public service policy. Do not put secrets in this file.\n") ||
		!strings.Contains(string(contents), "import { defineConfig } from \"@open-e2ee/oe/config\";") {
		t.Fatalf("unexpected file:\n%s", contents)
	}
}

func loadError(path string) error {
	_, err := Load(path)
	return err
}

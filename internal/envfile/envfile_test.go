package envfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const signalRelayURL = "https://sandbox.relay.open-e2ee.dev/signal/v1/connection/pk_sandbox_public"

// The rows match managedSignalProtocolRelayFrameworkConnections in the
// console's src/lib/managed-signal-relay-setup-guidance.ts.
func TestVariableFollowsTheFrameworkInPackageJSON(t *testing.T) {
	for _, test := range []struct {
		name, manifest, override string
		want                     Connection
	}{
		{"next", `{"dependencies":{"next":"16.0.0","react":"19.0.0"}}`, "", Connection{"Next.js", "NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL"}},
		{"vite", `{"devDependencies":{"vite":"7.0.0"}}`, "", Connection{"Vite", "VITE_OPEN_E2EE_SIGNAL_RELAY_URL", "VITE_OPEN_E2EE_RELAY_URL"}},
		{"expo", `{"dependencies":{"expo":"55.0.0","react-native":"0.83.0"}}`, "", Connection{"Expo", "EXPO_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", "EXPO_PUBLIC_OPEN_E2EE_RELAY_URL"}},
		{"anything else", `{"dependencies":{"express":"5.0.0"}}`, "", Connection{"", "OPEN_E2EE_SIGNAL_RELAY_URL", "OPEN_E2EE_RELAY_URL"}},
		{"no package.json", "", "", Connection{"", "OPEN_E2EE_SIGNAL_RELAY_URL", "OPEN_E2EE_RELAY_URL"}},
		{"next before vite", `{"dependencies":{"next":"16.0.0"},"devDependencies":{"vite":"7.0.0"}}`, "", Connection{"Next.js", "NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL"}},
		{"expo before vite", `{"dependencies":{"expo":"55.0.0"},"devDependencies":{"vite":"7.0.0"}}`, "", Connection{"Expo", "EXPO_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", "EXPO_PUBLIC_OPEN_E2EE_RELAY_URL"}},
		{"byte order mark", "\xef\xbb\xbf" + `{"dependencies":{"next":"16.0.0"}}`, "", Connection{"Next.js", "NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL"}},
		{"override", `{"dependencies":{"next":"16.0.0"}}`, "SIGNAL_RELAY_URL", Connection{"", "SIGNAL_RELAY_URL", ""}},
		{"override skips package.json", `{not json`, "SIGNAL_RELAY_URL", Connection{"", "SIGNAL_RELAY_URL", ""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if test.manifest != "" {
				if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(test.manifest), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Detect(directory, test.override)
			if err != nil || got != test.want {
				t.Fatalf("Detect = %#v, %v; want %#v", got, err, test.want)
			}
		})
	}
}

func TestDetectRefusesAnInvalidManifestOrOverride(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"dependencies":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := Detect(directory, ""); err == nil {
		t.Fatalf("a malformed package.json chose %#v", got)
	}
	for _, override := range []string{"1SIGNAL_RELAY", "SIGNAL_RELAY-URL", "SIGNAL_RELAY URL", "SIGNAL_RELAY=URL"} {
		if got, err := Detect(t.TempDir(), override); err == nil {
			t.Fatalf("the override %q chose %#v", override, got)
		}
	}
}

func TestWriteKeepsOtherLines(t *testing.T) {
	for _, test := range []struct{ name, before, after string }{
		{
			"append after comments and blank lines",
			"\n# Database\nDATABASE_URL=postgres://localhost/app\n\n# Keys\nAPI_KEY=secret\n\n",
			"\n# Database\nDATABASE_URL=postgres://localhost/app\n\n# Keys\nAPI_KEY=secret\n\n" +
				configuredComment + "\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=" + signalRelayURL + "\n",
		},
		{
			"no final line break",
			"API_KEY=secret",
			"API_KEY=secret\n" + configuredComment + "\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=" + signalRelayURL + "\n",
		},
		{
			"replace in place",
			"A=1\n" + configuredComment + "\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=https://old.example\n# after\nB=2",
			"A=1\n" + configuredComment + "\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=" + signalRelayURL + "\n# after\nB=2",
		},
		{"new file", "", configuredComment + "\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=" + signalRelayURL + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".env.local")
			if test.before != "" {
				if err := os.WriteFile(path, []byte(test.before), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			expectWrite(t, path, "NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", signalRelayURL, test.after)
		})
	}
}

func TestWriteReplacesOnlyTheSignalProtocolRelayVariable(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	before := "OPEN_E2EE_SIGNAL_RELAY_URL=https://server.example\n" +
		"NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL_BACKUP=https://backup.example\n" +
		"# NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=https://commented.example\n" +
		"  NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL = https://first.example # old\n" +
		"KEEP=1\n" +
		"NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL: https://colon.example\n" +
		"NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=https://last.example\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	expectWrite(t, path, "NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", signalRelayURL,
		"OPEN_E2EE_SIGNAL_RELAY_URL=https://server.example\n"+
			"NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL_BACKUP=https://backup.example\n"+
			"# NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=https://commented.example\n"+
			configuredComment+"\n"+
			"NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL="+signalRelayURL+"\n"+
			"KEEP=1\n")
}

// A quoted value of the target variable is replaced whole, also when it spans
// lines. A line inside another variable's quoted value is never an
// assignment, and a quote that never closes quotes nothing.
func TestWriteReplacesAQuotedValue(t *testing.T) {
	for _, test := range []struct{ name, before, after string }{
		{
			"double quotes",
			`SIGNAL_RELAY="https://old.example" # comment` + "\nB=2\n",
			configuredComment + "\nSIGNAL_RELAY=" + signalRelayURL + "\nB=2\n",
		},
		{
			"single quotes",
			"SIGNAL_RELAY='https://old.example'\n",
			configuredComment + "\nSIGNAL_RELAY=" + signalRelayURL + "\n",
		},
		{
			"multi-line value of the target variable",
			"A=1\nSIGNAL_RELAY=\"https://old.example\nsecond line\"\nB=2\n",
			"A=1\n" + configuredComment + "\nSIGNAL_RELAY=" + signalRelayURL + "\nB=2\n",
		},
		{
			"assignment inside another quoted value",
			"CERT=\"-----BEGIN-----\nSIGNAL_RELAY=https://inside.example\n\\\" escaped\n-----END-----\"\n",
			"CERT=\"-----BEGIN-----\nSIGNAL_RELAY=https://inside.example\n\\\" escaped\n-----END-----\"\n" +
				configuredComment + "\nSIGNAL_RELAY=" + signalRelayURL + "\n",
		},
		{
			"unclosed quote",
			"SIGNAL_RELAY=\"https://old.example\nB=2\n",
			configuredComment + "\nSIGNAL_RELAY=" + signalRelayURL + "\nB=2\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".env.local")
			if err := os.WriteFile(path, []byte(test.before), 0o644); err != nil {
				t.Fatal(err)
			}
			expectWrite(t, path, "SIGNAL_RELAY", signalRelayURL, test.after)
		})
	}
}

func TestWriteKeepsTheExportPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(path, []byte("export A=1\nexport\tSIGNAL_RELAY=https://old.example\nexported=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectWrite(t, path, "SIGNAL_RELAY", signalRelayURL, "export A=1\n"+configuredComment+"\nexport SIGNAL_RELAY="+signalRelayURL+"\nexported=2\n")
}

func TestWriteKeepsCRLFLineEndings(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(path, []byte("A=1\r\n\r\nSIGNAL_RELAY=https://old.example\r\nB=2\nC=3"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectWrite(t, path, "SIGNAL_RELAY", signalRelayURL, "A=1\r\n\r\n"+configuredComment+"\r\nSIGNAL_RELAY="+signalRelayURL+"\r\nB=2\nC=3")

	appended := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(appended, []byte("A=1\r\nB=2"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectWrite(t, appended, "SIGNAL_RELAY", signalRelayURL, "A=1\r\nB=2\r\n"+configuredComment+"\r\nSIGNAL_RELAY="+signalRelayURL+"\r\n")
}

func TestWriteRecordsAnEnvironmentWithNoConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.production.local")
	if err := os.WriteFile(path, []byte("A=1\n"+configuredComment+"\nSIGNAL_RELAY="+signalRelayURL+"\nB=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectWrite(t, path, "SIGNAL_RELAY", "", "A=1\n"+unconfiguredComment+"\nB=2\n")
	expectWrite(t, path, "SIGNAL_RELAY", signalRelayURL, "A=1\n"+configuredComment+"\nSIGNAL_RELAY="+signalRelayURL+"\nB=2\n")
}

func TestWriteRefusesAValueThatAnEnvFileChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	for _, value := range []string{"https://a.example/#x", "https://a.example/ x", "https://a.example/$X", "https://a.example/\"", "https://a.example/\nB=2"} {
		if _, err := Write(path, Connection{Variable: "SIGNAL_RELAY"}, value); err == nil {
			t.Fatalf("Write accepted %q", value)
		}
	}
	if _, err := Write(path, Connection{Variable: "SIGNAL_RELAY-URL"}, signalRelayURL); err == nil {
		t.Fatal("Write accepted an invalid variable name")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a refused write created the file: %v", err)
	}
}

func TestWriteKeepsTheFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX permission bits")
	}
	path := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(path, []byte("API_KEY=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(path, Connection{Variable: "SIGNAL_RELAY"}, signalRelayURL); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the write changed the permissions of a file with a secret: %v %v", info.Mode(), err)
	}
	created := filepath.Join(t.TempDir(), ".env.local")
	if _, err := Write(created, Connection{Variable: "SIGNAL_RELAY"}, signalRelayURL); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(created); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("a new file is not 0644: %v %v", info.Mode(), err)
	}
}

func TestWriteFollowsASymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "shared.env")
	if err := os.WriteFile(target, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, ".env.local")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	expectWrite(t, link, "SIGNAL_RELAY", signalRelayURL, "A=1\n"+configuredComment+"\nSIGNAL_RELAY="+signalRelayURL+"\n")
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the write replaced the symlink: %v", err)
	}
}

// expectWrite writes twice and checks that the second write changes nothing.
func expectWrite(t *testing.T, path, variable, value, want string) {
	t.Helper()
	expectConnectionWrite(t, path, Connection{Variable: variable}, value, want, false)
}

// expectConnectionWrite writes twice, so the second write proves that the
// first one is stable.
func expectConnectionWrite(t *testing.T, path string, connection Connection, value, want string, wantDeprecated bool) {
	t.Helper()
	for range 2 {
		deprecated, err := Write(path, connection, value)
		if err != nil {
			t.Fatal(err)
		}
		if deprecated != wantDeprecated {
			t.Fatalf("Write reported deprecated=%t; want %t", deprecated, wantDeprecated)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("file =\n%q\nwant\n%q", got, want)
		}
	}
}

func TestReadReturnsTheLastAssignment(t *testing.T) {
	directory := t.TempDir()
	if value, err := Read(filepath.Join(directory, ".env.local"), "SIGNAL_RELAY"); err != nil || value != "" {
		t.Fatalf("a missing file has no value: %q, %v", value, err)
	}
	for name, test := range map[string]struct{ contents, want string }{
		"written":   {"A=1\r\n" + configuredComment + "\r\nSIGNAL_RELAY=" + signalRelayURL + "\r\n", signalRelayURL},
		"last wins": {"SIGNAL_RELAY=https://old.example\nexport SIGNAL_RELAY: " + signalRelayURL + "\n", signalRelayURL},
		"quoted":    {"SIGNAL_RELAY=\"" + signalRelayURL + "\" # comment\n", signalRelayURL},
		"comment":   {"SIGNAL_RELAY=" + signalRelayURL + " # comment\n", signalRelayURL},
		"multiline": {"KEY=\"a\nSIGNAL_RELAY=https://inside.example\n\"\nB=2\n", ""},
		"other key": {"SIGNAL_RELAY_URL=" + signalRelayURL + "\n", ""},
		"no value":  {unconfiguredComment + "\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".env.local")
			if err := os.WriteFile(path, []byte(test.contents), 0o644); err != nil {
				t.Fatal(err)
			}
			if value, err := Read(path, "SIGNAL_RELAY"); err != nil || value != test.want {
				t.Fatalf("want %q, got %q, %v", test.want, value, err)
			}
		})
	}
}

var nextConnection = Connection{"Next.js", "NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL", "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL"}

// A file that an earlier oe wrote keeps its deprecated line, with the same
// URL as the current line, so an app that still reads the deprecated name
// never gets a stale connection.
func TestWriteKeepsADeprecatedLineCurrent(t *testing.T) {
	for _, test := range []struct{ name, before, after string }{
		{
			"file from an earlier oe",
			"A=1\n" + configuredComment + "\nNEXT_PUBLIC_OPEN_E2EE_RELAY_URL=https://old.example\nB=2\n",
			"A=1\n" + configuredComment + "\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=" + signalRelayURL + "\nNEXT_PUBLIC_OPEN_E2EE_RELAY_URL=" + signalRelayURL + "\nB=2\n",
		},
		{
			"both lines with an export prefix on the deprecated one",
			"NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=https://old.example\nKEEP=1\nexport NEXT_PUBLIC_OPEN_E2EE_RELAY_URL=\"https://old.example\"\n",
			configuredComment + "\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=" + signalRelayURL + "\nexport NEXT_PUBLIC_OPEN_E2EE_RELAY_URL=" + signalRelayURL + "\nKEEP=1\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".env.local")
			if err := os.WriteFile(path, []byte(test.before), 0o644); err != nil {
				t.Fatal(err)
			}
			expectConnectionWrite(t, path, nextConnection, signalRelayURL, test.after, true)
		})
	}
}

func TestWriteNeverAddsADeprecatedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(path, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectConnectionWrite(t, path, nextConnection, signalRelayURL,
		"A=1\n"+configuredComment+"\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL="+signalRelayURL+"\n", false)
}

func TestWriteWithoutAConnectionRemovesTheDeprecatedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.production.local")
	before := "A=1\n" + configuredComment + "\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=https://old.example\nNEXT_PUBLIC_OPEN_E2EE_RELAY_URL=https://old.example\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	if deprecated, err := Write(path, nextConnection, ""); err != nil || !deprecated {
		t.Fatalf("Write = %t, %v; want the deprecated line reported", deprecated, err)
	}
	expectConnectionWrite(t, path, nextConnection, "", "A=1\n"+unconfiguredComment+"\n", false)
}

// An override names one variable, so a write leaves every other line alone.
func TestWriteWithAnOverrideLeavesTheDeprecatedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(path, []byte("OPEN_E2EE_RELAY_URL=https://old.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectConnectionWrite(t, path, Connection{Variable: "SIGNAL_RELAY"}, signalRelayURL,
		"OPEN_E2EE_RELAY_URL=https://old.example\n"+configuredComment+"\nSIGNAL_RELAY="+signalRelayURL+"\n", false)
}

func TestReadConnectionReadsTheCurrentNameFirst(t *testing.T) {
	for _, test := range []struct {
		name, contents string
		connection     Connection
		want           string
		wantDeprecated bool
	}{
		{"current name", "NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=https://new.example\n", nextConnection, "https://new.example", false},
		{"deprecated name", "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL=https://old.example\n", nextConnection, "https://old.example", true},
		{"both names", "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL=https://old.example\nNEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=https://new.example\n", nextConnection, "https://new.example", false},
		{"empty current name", "NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL=\nNEXT_PUBLIC_OPEN_E2EE_RELAY_URL=https://old.example\n", nextConnection, "https://old.example", true},
		{"neither name", "A=1\n", nextConnection, "", false},
		{"override", "OPEN_E2EE_RELAY_URL=https://old.example\n", Connection{Variable: "SIGNAL_RELAY"}, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".env.local")
			if err := os.WriteFile(path, []byte(test.contents), 0o644); err != nil {
				t.Fatal(err)
			}
			value, deprecated, err := ReadConnection(path, test.connection)
			if err != nil || value != test.want || deprecated != test.wantDeprecated {
				t.Fatalf("ReadConnection = %q, %t, %v; want %q, %t", value, deprecated, err, test.want, test.wantDeprecated)
			}
		})
	}
}

func TestDeprecationWarningNamesBothVariablesAndTheRemovalRelease(t *testing.T) {
	read := DeprecationWarning(".env.local", nextConnection, true)
	if read != "warning: .env.local assigns NEXT_PUBLIC_OPEN_E2EE_RELAY_URL, which is deprecated. Run oe link to write NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL. Read NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL in the app. oe v7.0.0 stops reading and writing NEXT_PUBLIC_OPEN_E2EE_RELAY_URL." {
		t.Fatalf("read warning = %q", read)
	}
	kept := DeprecationWarning(".env.local", nextConnection, false)
	if kept != "warning: .env.local assigns NEXT_PUBLIC_OPEN_E2EE_RELAY_URL, which is deprecated. oe keeps it current. Read NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL in the app. oe v7.0.0 stops reading and writing NEXT_PUBLIC_OPEN_E2EE_RELAY_URL." {
		t.Fatalf("kept warning = %q", kept)
	}
}

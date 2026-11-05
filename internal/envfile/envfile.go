// Package envfile owns the connection env files, .env.local and
// .env.production.local. It chooses the variable that the app's framework
// reads, and it replaces only the CLI's own lines in a file.
//
// The files use the dotenv format that Next.js, Vite, and Expo load. A line
// is an assignment when it is "KEY=value" or "KEY: value", with optional
// leading whitespace and an optional "export " prefix. A value that starts
// with a quote continues to the matching quote, also on a later line.
package envfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// DefaultVariable holds the connection when package.json names no framework
// that needs a prefix.
const DefaultVariable = "OPEN_E2EE_RELAY_URL"

const (
	configuredComment   = "# Public Signal Protocol Relay connection. This is not a credential."
	unconfiguredComment = "# Signal Protocol Relay connection is not configured for this environment."
)

// frameworks maps a package.json dependency to the variable that the
// framework exposes to client code. The names match the console mapping in
// src/lib/managed-signal-relay-setup-guidance.ts. The order is the precedence:
// other frameworks and their test tools can also depend on vite, so vite is
// last.
var frameworks = []struct{ dependency, framework, variable string }{
	{"next", "Next.js", "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL"},
	{"expo", "Expo", "EXPO_PUBLIC_OPEN_E2EE_RELAY_URL"},
	{"vite", "Vite", "VITE_OPEN_E2EE_RELAY_URL"},
}

var variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Connection names the variable that holds the Relay connection URL.
// Framework is the framework that chose the variable. It is empty when an
// override chose the variable or package.json names no known framework.
type Connection struct {
	Framework string
	Variable  string
}

// Detect chooses the variable for the app in directory from the dependencies
// and devDependencies in its package.json. A non-empty override wins, and
// Detect then does not read package.json. A directory with no package.json
// gets DefaultVariable.
func Detect(directory, override string) (Connection, error) {
	if override != "" {
		if !variableName.MatchString(override) {
			return Connection{}, fmt.Errorf("%q is not an environment variable name", override)
		}
		return Connection{Variable: override}, nil
	}
	path := filepath.Join(directory, "package.json")
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Connection{Variable: DefaultVariable}, nil
	}
	if err != nil {
		return Connection{}, fmt.Errorf("read %s: %w", path, err)
	}
	var manifest struct {
		Dependencies    map[string]json.RawMessage `json:"dependencies"`
		DevDependencies map[string]json.RawMessage `json:"devDependencies"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(contents, []byte("\xef\xbb\xbf")), &manifest); err != nil {
		return Connection{}, fmt.Errorf("read %s: %w", path, err)
	}
	for _, candidate := range frameworks {
		_, dependency := manifest.Dependencies[candidate.dependency]
		_, devDependency := manifest.DevDependencies[candidate.dependency]
		if dependency || devDependency {
			return Connection{Framework: candidate.framework, Variable: candidate.variable}, nil
		}
	}
	return Connection{Variable: DefaultVariable}, nil
}

// line is one line of an env file. ending is "\n", "\r\n", or "" for a last
// line with no line break.
type line struct {
	text, ending string
}

// Write sets variable to signalRelayURL in the env file at path. An empty signalRelayURL
// removes the variable and writes a comment that the environment has no
// connection.
//
// The CLI owns its comment lines and every assignment of variable. Write
// removes them and puts one new block where the first of them was, or at
// the end of the file. It keeps an "export " prefix from the first
// assignment. It keeps every other line, and the line break of each line,
// byte for byte. New lines use the line break of the first line. The file
// keeps its permissions, and a new file gets 0644, because the connection is
// public.
func Write(path, variable, signalRelayURL string) error {
	if !variableName.MatchString(variable) {
		return fmt.Errorf("%q is not an environment variable name", variable)
	}
	if strings.ContainsFunc(signalRelayURL, func(character rune) bool {
		return character <= ' ' || character == 0x7f || strings.ContainsRune("\"#$'\\`", character)
	}) {
		return fmt.Errorf("the OpenE2EE Signal Protocol Relay connection URL for %s has a character that an env file changes", variable)
	}
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
	}
	mode := os.FileMode(0o644)
	contents, err := os.ReadFile(path)
	switch {
	case err == nil:
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		mode = info.Mode().Perm()
	case !errors.Is(err, os.ErrNotExist):
		return err
	}

	lines := split(string(contents))
	newline := "\n"
	if len(lines) > 0 && lines[0].ending == "\r\n" {
		newline = "\r\n"
	}
	output := make([]line, 0, len(lines)+2)
	block, assigned, exported := -1, false, false
	for index := 0; index < len(lines); index++ {
		key, value, export, isAssignment := assignment(lines[index].text)
		end := index
		if isAssignment {
			end = valueEnd(lines, index, value)
		}
		owned := lines[index].text == configuredComment || lines[index].text == unconfiguredComment || (isAssignment && key == variable)
		if !owned {
			output = append(output, lines[index:end+1]...)
			index = end
			continue
		}
		if block < 0 {
			block = len(output)
		}
		if isAssignment && key == variable && !assigned {
			assigned, exported = true, export
		}
		index = end
	}

	var replacement []line
	if signalRelayURL == "" {
		replacement = []line{{unconfiguredComment, newline}}
	} else {
		prefix := ""
		if exported {
			prefix = "export "
		}
		replacement = []line{{configuredComment, newline}, {prefix + variable + "=" + signalRelayURL, newline}}
	}
	if block < 0 {
		if last := len(output) - 1; last >= 0 && output[last].ending == "" {
			output[last].ending = newline
		}
		block = len(output)
	}
	output = slices.Insert(output, block, replacement...)

	var result strings.Builder
	for _, current := range output {
		result.WriteString(current.text)
		result.WriteString(current.ending)
	}
	if contents != nil && result.String() == string(contents) {
		return nil
	}
	return writeAtomic(path, []byte(result.String()), mode)
}

// Read returns the value of the last assignment of variable in the env file at
// path. It removes the quotes of a quoted value, and the comment after an
// unquoted value. A missing file or variable gives "".
func Read(path, variable string) (string, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	lines := split(string(contents))
	result := ""
	for index := 0; index < len(lines); index++ {
		key, value, _, isAssignment := assignment(lines[index].text)
		if !isAssignment {
			continue
		}
		end := valueEnd(lines, index, value)
		if key == variable {
			result = unquote(lines, index, end, value)
		}
		index = end
	}
	return result, nil
}

// unquote returns the value of the assignment on lines[start:end+1], whose
// text after the separator on the first line is value.
func unquote(lines []line, start, end int, value string) string {
	if value != "" && strings.ContainsRune("\"'`", rune(value[0])) && (end > start || closes(value[1:], value[0])) {
		text := value
		for index := start + 1; index <= end; index++ {
			text += "\n" + lines[index].text
		}
		quote := text[0]
		for index := 1; index < len(text); index++ {
			switch text[index] {
			case '\\':
				index++
			case quote:
				return text[1:index]
			}
		}
	}
	if comment := strings.Index(value, " #"); comment >= 0 {
		value = value[:comment]
	}
	return strings.TrimRight(value, " \t")
}

func split(contents string) []line {
	var lines []line
	for contents != "" {
		text, rest, found := strings.Cut(contents, "\n")
		ending := ""
		if found {
			ending = "\n"
			if trimmed, crlf := strings.CutSuffix(text, "\r"); crlf {
				text, ending = trimmed, "\r\n"
			}
		}
		lines = append(lines, line{text, ending})
		contents = rest
	}
	return lines
}

// assignment parses an assignment line and returns its key, the value text
// after the separator, and whether it has an "export " prefix.
func assignment(text string) (key, value string, exported, ok bool) {
	rest := strings.TrimLeft(text, " \t")
	if after, found := strings.CutPrefix(rest, "export"); found && after != strings.TrimLeft(after, " \t") {
		rest, exported = strings.TrimLeft(after, " \t"), true
	}
	length := strings.IndexFunc(rest, func(character rune) bool {
		return !(character == '_' || character == '.' || character == '-' ||
			(character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9'))
	})
	if length <= 0 {
		return "", "", false, false
	}
	key, rest = rest[:length], strings.TrimLeft(rest[length:], " \t")
	switch {
	case strings.HasPrefix(rest, "="):
		rest = rest[1:]
	case strings.HasPrefix(rest, ":") && strings.TrimLeft(rest[1:], " \t") != rest[1:]:
		rest = rest[1:]
	default:
		return "", "", false, false
	}
	return key, strings.TrimLeft(rest, " \t"), exported, true
}

// valueEnd returns the index of the last line of the assignment that starts
// at lines[start]. A quoted value runs to its closing quote. A quote that
// never closes does not start a quoted value, as in dotenv.
func valueEnd(lines []line, start int, value string) int {
	if value == "" || !strings.ContainsRune("\"'`", rune(value[0])) {
		return start
	}
	quote := value[0]
	if closes(value[1:], quote) {
		return start
	}
	for index := start + 1; index < len(lines); index++ {
		if closes(lines[index].text, quote) {
			return index
		}
	}
	return start
}

// closes reports whether text holds quote with no backslash before it.
func closes(text string, quote byte) bool {
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '\\':
			index++
		case quote:
			return true
		}
	}
	return false
}

func writeAtomic(path string, contents []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".open-e2ee-environment-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

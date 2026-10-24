package identity

import (
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	whatwg "github.com/nationallibraryofnorway/whatwg-url/url"
)

var ErrControlBaseURL = errors.New("The control API address is invalid.")

// ControlBaseURL retains the complete canonical API prefix. It grants no authority.
type ControlBaseURL struct{ value string }

// ParseControlBaseURL accepts user input. JSON decoding requires canonical text.
func ParseControlBaseURL(raw string) (ControlBaseURL, error) {
	if !utf8.ValidString(raw) || strings.ContainsAny(raw, "\\#") || forbiddenURLRunes(raw, true) {
		return ControlBaseURL{}, ErrControlBaseURL
	}
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 1 {
		return ControlBaseURL{}, ErrControlBaseURL
	}
	scheme := strings.ToLower(raw[:schemeEnd])
	if scheme != "https" && scheme != "http" {
		return ControlBaseURL{}, ErrControlBaseURL
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, scheme) || parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(parsed.Host, "%") || strings.HasSuffix(parsed.Host, ":") {
		return ControlBaseURL{}, ErrControlBaseURL
	}
	if port := parsed.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ControlBaseURL{}, ErrControlBaseURL
		}
	}
	hostname := strings.ToLower(parsed.Hostname())
	if scheme == "http" && hostname != "localhost" && hostname != "127.0.0.1" && hostname != "::1" {
		return ControlBaseURL{}, ErrControlBaseURL
	}
	// The maintained parser owns IDNA, host case, IP spelling and default ports.
	authority, err := whatwg.Parse(scheme + "://" + parsed.Host)
	if err != nil || authority.Host() == "" || authority.Username() != "" || authority.Password() != "" {
		return ControlBaseURL{}, ErrControlBaseURL
	}
	if _, err := netip.ParseAddr(strings.Trim(authority.Hostname(), "[]")); err == nil {
		if original, err := netip.ParseAddr(hostname); err != nil || original.Zone() != "" {
			return ControlBaseURL{}, ErrControlBaseURL
		}
	}
	if !utf8.ValidString(parsed.Path) || forbiddenURLRunes(parsed.Path, false) {
		return ControlBaseURL{}, ErrControlBaseURL
	}
	for segment := range strings.SplitSeq(parsed.EscapedPath(), "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || strings.ContainsAny(decoded, "/\\%") || ((decoded == "." || decoded == "..") && decoded != segment) {
			return ControlBaseURL{}, ErrControlBaseURL
		}
	}
	prefix := path.Clean(parsed.Path)
	if prefix == "." || prefix == "/" {
		prefix = ""
	}
	canonical := (&url.URL{Scheme: scheme, Host: authority.Host(), Path: prefix}).String()
	return ControlBaseURL{value: canonical}, nil
}

func forbiddenURLRunes(value string, spaces bool) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) || spaces && unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func (v ControlBaseURL) String() string { return v.value }

func (v ControlBaseURL) Validate() error {
	parsed, err := ParseControlBaseURL(v.value)
	if err != nil || parsed.value != v.value {
		return ErrControlBaseURL
	}
	return nil
}

func (v ControlBaseURL) Equal(other ControlBaseURL) bool {
	return v.Validate() == nil && other.Validate() == nil && v.value == other.value
}

func (v ControlBaseURL) MarshalJSON() ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrControlBaseURL
	}
	return json.Marshal(v.value)
}

func (v *ControlBaseURL) UnmarshalJSON(data []byte) error {
	if v == nil {
		return ErrControlBaseURL
	}
	var text ContractText
	if text.UnmarshalJSON(data) != nil {
		return ErrControlBaseURL
	}
	raw, scalar := text.ScalarString()
	if !scalar {
		return ErrControlBaseURL
	}
	parsed, err := ParseControlBaseURL(raw)
	if err != nil || parsed.value != raw {
		return ErrControlBaseURL
	}
	*v = parsed
	return nil
}

// Endpoint composes route segments below the API prefix. It performs no I/O.
func (v ControlBaseURL) Endpoint(segments []string, query url.Values) (string, error) {
	if v.Validate() != nil || len(segments) == 0 {
		return "", ErrControlBaseURL
	}
	parsed, err := url.Parse(v.value)
	if err != nil {
		return "", ErrControlBaseURL
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || !utf8.ValidString(segment) || forbiddenURLRunes(segment, false) || strings.ContainsAny(segment, "/\\%") {
			return "", ErrControlBaseURL
		}
		parsed.Path += "/" + segment
	}
	for key, values := range query {
		if !utf8.ValidString(key) {
			return "", ErrControlBaseURL
		}
		for _, value := range values {
			if !utf8.ValidString(value) {
				return "", ErrControlBaseURL
			}
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

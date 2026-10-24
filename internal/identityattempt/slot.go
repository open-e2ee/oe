package identityattempt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"unicode/utf8"

	"github.com/open-e2ee/oe/internal/identity"
)

var ErrSlot = errors.New("The identity attempt slot is invalid.")

type Kind string

const (
	Selection Kind = "selection"
	KeysOnly  Kind = "keys-only"
	Lifecycle Kind = "lifecycle"
)

const slotDomain = "open-e2ee.identity-attempt-slot"

var projectSlug = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Slot is public local association. Its constructor does not verify server authority.
type Slot struct {
	base         identity.ControlBaseURL
	organization string
	project      string
	environment  string
	kind         Kind
}

// NewSlot consumes the Organization and project already checked by the caller.
func NewSlot(base identity.ControlBaseURL, organization, project, environment string, kind Kind) (Slot, error) {
	value := Slot{base: base, organization: organization, project: project, environment: environment, kind: kind}
	if value.Validate() != nil {
		return Slot{}, ErrSlot
	}
	return value, nil
}

func (v Slot) Validate() error {
	if v.base.Validate() != nil || v.organization == "" || !utf8.ValidString(v.organization) || len(v.project) > 63 || !projectSlug.MatchString(v.project) || v.environment != "sandbox" && v.environment != "production" || v.kind != Selection && v.kind != KeysOnly && v.kind != Lifecycle {
		return ErrSlot
	}
	return nil
}

func (v Slot) ControlBase() identity.ControlBaseURL { return v.base }
func (v Slot) OrganizationID() string               { return v.organization }
func (v Slot) ProjectSlug() string                  { return v.project }
func (v Slot) Environment() string                  { return v.environment }
func (v Slot) Kind() Kind                           { return v.kind }

func (v Slot) Equal(other Slot) bool {
	return v.Validate() == nil && other.Validate() == nil && v == other
}

func (v Slot) MarshalJSON() ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrSlot
	}
	return json.Marshal([7]any{slotDomain, 1, v.base, v.organization, v.project, v.environment, v.kind})
}

func slotText(data []byte) (string, error) {
	var value identity.ContractText
	if value.UnmarshalJSON(data) != nil {
		return "", ErrSlot
	}
	text, scalar := value.ScalarString()
	if !scalar {
		return "", ErrSlot
	}
	return text, nil
}

func (v *Slot) UnmarshalJSON(data []byte) error {
	if v == nil || !utf8.Valid(data) || !json.Valid(data) {
		return ErrSlot
	}
	// Raw members stay private to this fixed array decoder. No policy DTO escapes.
	var fields []json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 7 || !bytes.Equal(bytes.TrimSpace(fields[1]), []byte("1")) {
		return ErrSlot
	}
	domain, err := slotText(fields[0])
	if err != nil || domain != slotDomain {
		return ErrSlot
	}
	var base identity.ControlBaseURL
	if base.UnmarshalJSON(fields[2]) != nil {
		return ErrSlot
	}
	values := [4]string{}
	for i := range values {
		values[i], err = slotText(fields[i+3])
		if err != nil {
			return ErrSlot
		}
	}
	candidate, err := NewSlot(base, values[0], values[1], values[2], Kind(values[3]))
	if err != nil {
		return ErrSlot
	}
	*v = candidate
	return nil
}

// EncodeSlot emits the versioned compact array without a final newline.
func EncodeSlot(value Slot) ([]byte, error) { return value.MarshalJSON() }

func DecodeSlot(data []byte) (Slot, error) {
	var value Slot
	if value.UnmarshalJSON(data) != nil {
		return Slot{}, ErrSlot
	}
	return value, nil
}

// FilenameStem supplies only a digest. It creates no path or file.
func (v Slot) FilenameStem() (string, error) {
	encoded, err := EncodeSlot(v)
	if err != nil {
		return "", ErrSlot
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

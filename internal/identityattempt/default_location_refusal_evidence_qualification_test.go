//go:build identity_default_qualification

package identityattempt

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
)

const refusalFramePrefix = "default-refusal-observation "
const refusalRecordLimit = 4096
const refusalRecordsLimit = 1024
const refusalPayloadLimit = 1048576
const refusalFramedLimit = 2097152
const refusalFinalBytes = 65536
const refusalFinalRecords = 64
const refusalDescriptorLimit = 65536

var errRefusalBound = errors.New("refusal evidence bound reached")
var errRefusalShape = errors.New("refusal descriptor shape invalid")

type refusalNativeError struct {
	Present   bool    `json:"present"`
	Type      string  `json:"type,omitempty"`
	StoreCode string  `json:"storeCode,omitempty"`
	Win32Code *uint32 `json:"win32Code,omitempty"`
}

func refusalErrorRecord(err error) refusalNativeError {
	if err == nil {
		return refusalNativeError{}
	}
	result := refusalNativeError{Present: true, Type: fmt.Sprintf("%T", err)}
	if len(result.Type) > 128 {
		result.Type = "TYPE_BOUND_REACHED"
	}
	if native, ok := errors.AsType[syscall.Errno](err); ok {
		result.Win32Code = new(uint32(native))
	}
	if store, ok := errors.AsType[*Failure](err); ok {
		result.StoreCode = store.Code()
	}
	return result
}

type refusalBudget struct {
	Records         int    `json:"records"`
	Payload         int    `json:"payloadBytes"`
	Framed          int    `json:"framedBytes"`
	DescriptorBytes [2]int `json:"descriptorBytesByPhase"`
	ACEs            [2]int `json:"acesByPhase"`
}

func (b *refusalBudget) frame(value any, terminal bool) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	records, payload := refusalRecordsLimit, refusalPayloadLimit
	if !terminal {
		records -= refusalFinalRecords
		payload -= refusalFinalBytes
	}
	framed := len(refusalFramePrefix) + len(data) + 1
	if len(data) > refusalRecordLimit || b.Records >= records || len(data) > payload-b.Payload || framed > refusalFramedLimit-b.Framed {
		return nil, errRefusalBound
	}
	b.Records++
	b.Payload += len(data)
	b.Framed += framed
	return append(append([]byte(refusalFramePrefix), data...), '\n'), nil
}

func (b *refusalBudget) snapshot(phase, size, aces int) error {
	if phase < 0 || phase > 1 || size < 20 || size > refusalDescriptorLimit || aces < 0 || aces > 128 {
		return errRefusalBound
	}
	if size > 65536-b.DescriptorBytes[phase] || aces > 256-b.ACEs[phase] {
		return errRefusalBound
	}
	b.DescriptorBytes[phase] += size
	b.ACEs[phase] += aces
	return nil
}

func refusalHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func refusalPathBound(path string) error {
	if len(path) > 4096 || !utf8.ValidString(path) || strings.IndexByte(path, 0) >= 0 {
		return errRefusalBound
	}
	units := 1
	for _, value := range path {
		units += utf16.RuneLen(value)
		if units > 1024 {
			return errRefusalBound
		}
	}
	return nil
}

type refusalACE struct {
	Index  int     `json:"index"`
	Type   byte    `json:"type"`
	Flags  byte    `json:"flags"`
	Size   uint16  `json:"size"`
	SHA256 string  `json:"sha256"`
	Mask   *uint32 `json:"mask,omitempty"`
	SID    string  `json:"sid,omitempty"`
}

type refusalDescriptor struct {
	Revision       byte         `json:"revision"`
	Control        uint16       `json:"control"`
	OwnerPresent   bool         `json:"ownerPresent"`
	OwnerDefaulted bool         `json:"ownerDefaulted"`
	Owner          string       `json:"owner,omitempty"`
	DACLPresent    bool         `json:"daclPresent"`
	DACLDefaulted  bool         `json:"daclDefaulted"`
	DACLNull       bool         `json:"daclNull"`
	DACLRevision   byte         `json:"daclRevision"`
	DACLSize       uint16       `json:"daclSize"`
	ACECount       uint16       `json:"aceCount"`
	ACEs           []refusalACE `json:"-"`
}

func refusalSpan(data []byte, offset, size uint32) ([]byte, error) {
	if len(data) > refusalDescriptorLimit || offset > uint32(len(data)) || size > uint32(len(data))-offset {
		return nil, errRefusalShape
	}
	return data[int(offset):int(offset+size)], nil
}

func refusalSID(data []byte, offset, end uint32, step func() error) (string, uint32, error) {
	if end > uint32(len(data)) || offset > end || end-offset < 8 {
		return "", 0, errRefusalShape
	}
	header, err := refusalSpan(data, offset, 8)
	if err != nil || header[0] != 1 || header[1] > 15 {
		return "", 0, errRefusalShape
	}
	size := uint32(8) + uint32(header[1])*4
	if size > end-offset {
		return "", 0, errRefusalShape
	}
	var authority uint64
	for _, octet := range header[2:8] {
		if step != nil {
			if err := step(); err != nil {
				return "", 0, err
			}
		}
		authority = authority<<8 | uint64(octet)
	}
	text := fmt.Sprintf("S-1-%d", authority)
	for index := range int(header[1]) {
		if step != nil {
			if err := step(); err != nil {
				return "", 0, err
			}
		}
		part, err := refusalSpan(data, offset+8+uint32(index)*4, 4)
		if err != nil {
			return "", 0, err
		}
		text += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(part))
	}
	return text, size, nil
}

// This decoder checks public structure spans. It makes no access-policy decision.
func refusalDecode(data []byte, step func() error) (refusalDescriptor, error) {
	var result refusalDescriptor
	if len(data) < 20 || len(data) > refusalDescriptorLimit || data[0] != 1 {
		return result, errRefusalShape
	}
	result.Revision = data[0]
	result.Control = binary.LittleEndian.Uint16(data[2:4])
	if result.Control&0x8000 == 0 {
		return result, errRefusalShape
	}
	result.OwnerDefaulted = result.Control&1 != 0
	result.DACLPresent = result.Control&4 != 0
	result.DACLDefaulted = result.Control&8 != 0
	owner := binary.LittleEndian.Uint32(data[4:8])
	dacl := binary.LittleEndian.Uint32(data[16:20])
	var ownerSize uint32
	if owner != 0 {
		if owner < 20 || owner%4 != 0 {
			return result, errRefusalShape
		}
		var err error
		result.Owner, ownerSize, err = refusalSID(data, owner, uint32(len(data)), step)
		if err != nil {
			return result, err
		}
		result.OwnerPresent = true
	}
	result.DACLNull = dacl == 0
	if dacl == 0 {
		return result, nil
	}
	if dacl < 20 || dacl%4 != 0 {
		return result, errRefusalShape
	}
	header, err := refusalSpan(data, dacl, 8)
	if err != nil {
		return result, err
	}
	result.DACLRevision = header[0]
	result.DACLSize = binary.LittleEndian.Uint16(header[2:4])
	result.ACECount = binary.LittleEndian.Uint16(header[4:6])
	if result.DACLSize < 8 || result.ACECount > 128 {
		return result, errRefusalBound
	}
	acl, err := refusalSpan(data, dacl, uint32(result.DACLSize))
	if err != nil {
		return result, err
	}
	end := dacl + uint32(len(acl))
	if owner != 0 && owner < end && dacl < owner+ownerSize {
		return result, errRefusalShape
	}
	cursor := dacl + 8
	for index := range int(result.ACECount) {
		if step != nil {
			if err := step(); err != nil {
				return result, err
			}
		}
		if cursor > end || end-cursor < 4 {
			return result, errRefusalShape
		}
		h, err := refusalSpan(data, cursor, 4)
		if err != nil {
			return result, err
		}
		size := binary.LittleEndian.Uint16(h[2:4])
		if size < 4 || size%4 != 0 || uint32(size) > end-cursor {
			return result, errRefusalShape
		}
		raw, err := refusalSpan(data, cursor, uint32(size))
		if err != nil {
			return result, err
		}
		ace := refusalACE{Index: index, Type: h[0], Flags: h[1], Size: size, SHA256: refusalHash(raw)}
		if ace.Type == 0 || ace.Type == 1 {
			if size < 16 {
				return result, errRefusalShape
			}
			mask := binary.LittleEndian.Uint32(raw[4:8])
			ace.Mask = new(mask)
			var sidSize uint32
			ace.SID, sidSize, err = refusalSID(data, cursor+8, cursor+uint32(size), step)
			if err != nil {
				return result, err
			}
			if sidSize+8 != uint32(size) {
				return result, errRefusalShape
			}
		}
		result.ACEs = append(result.ACEs, ace)
		cursor += uint32(size)
	}
	return result, nil
}

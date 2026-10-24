package identityattempt

import (
	"encoding/binary"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// ABI declarations come from the pinned Apple macOS15.5 SDK headers.
// No implementation, comments or test bodies derive from the AGPL exemplar.
const (
	aclResponseCapacity = 4096
	aclExtendedSecurity = uint32(0x00400000)
	aclFullSize         = uint32(4)
	aclSecurityMagic    = uint32(0x012cc16d)
	aclEntryLimit       = uint32(128)
	aclAncestorRead     = uint32(1<<1 | 1<<3 | 1<<7 | 1<<9 | 1<<11 | 1<<20)
)

type aclRequest struct {
	maps                                  uint16
	reserved                              uint16
	common, volume, directory, file, fork uint32
}

type aclLibrary struct {
	attributes func(int32, unsafe.Pointer, unsafe.Pointer, uintptr, uint32) int32
	uuid       func(uint32, unsafe.Pointer) int32
}

type aclEntry struct {
	principal     [16]byte
	flags, rights uint32
}

var loadACL = sync.OnceValues(func() (aclLibrary, error) {
	var result aclLibrary
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" || unsafe.Sizeof(aclRequest{}) != 24 || unsafe.Sizeof(uintptr(0)) != 8 {
		return result, ErrUnsafe
	}
	library, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return result, ErrUnsafe
	}
	fail := func() (aclLibrary, error) {
		if purego.Dlclose(library) != nil {
			return aclLibrary{}, combine(ErrUnsafe, ErrRelease)
		}
		return aclLibrary{}, ErrUnsafe
	}
	attributes, err := purego.Dlsym(library, "fgetattrlist")
	if err != nil {
		return fail()
	}
	membership, err := purego.Dlsym(library, "mbr_uid_to_uuid")
	if err != nil {
		return fail()
	}
	purego.RegisterFunc(&result.attributes, attributes)
	purego.RegisterFunc(&result.uuid, membership)
	// The process retains this one library reference while the pointers remain live.
	return result, nil
})

func init() {
	unixACLReceiver = inspectDarwinACL
	unixMountReceiver = inspectDarwinMount
}

func inspectDarwinMount(file *os.File) error {
	var info unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &info) != nil {
		return ErrUnsafe
	}
	var name []byte
	for _, value := range info.Fstypename {
		if value == 0 {
			break
		}
		name = append(name, byte(value))
	}
	switch string(name) {
	case "nfs", "smbfs", "webdav", "autofs":
		return ErrUnsafe
	}
	return nil
}

func inspectDarwinACL(file *os.File, managed bool) error {
	if file == nil || file.Fd() > 1<<31-1 {
		return ErrUnsafe
	}
	var before unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil {
		return ErrUnsafe
	}
	api, err := loadACL()
	if err != nil {
		return err
	}
	request := aclRequest{maps: 5, common: aclExtendedSecurity}
	var response [aclResponseCapacity]byte
	if api.attributes(int32(file.Fd()), unsafe.Pointer(&request), unsafe.Pointer(&response[0]), uintptr(len(response)), aclFullSize) != 0 {
		return ErrUnsafe
	}
	runtime.KeepAlive(file)
	entries, err := parseACLResponse(response[:])
	if err != nil {
		return err
	}
	var after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Uid != after.Uid || before.Mode != after.Mode {
		return ErrChanged
	}
	if len(entries) == 0 {
		return nil
	}
	owner, err := aclUUID(api, before.Uid)
	if err != nil {
		return err
	}
	trusted := [][16]byte{owner}
	if !managed {
		trusted = nil
		for _, uid := range []uint32{0, uint32(os.Geteuid())} {
			id, err := aclUUID(api, uid)
			if err != nil {
				return err
			}
			trusted = append(trusted, id)
		}
	}
	return checkACLGrants(entries, managed, trusted)
}

func aclUUID(api aclLibrary, uid uint32) ([16]byte, error) {
	var id [16]byte
	if api.uuid(uid, unsafe.Pointer(&id[0])) != 0 || id == [16]byte{} {
		return [16]byte{}, ErrUnsafe
	}
	return id, nil
}

// parseACLResponse accepts only the complete supported native layout.
// Buffer offsets are signed; all arithmetic precedes slicing and allocation.
func parseACLResponse(buffer []byte) ([]aclEntry, error) {
	if len(buffer) < 12 {
		return nil, ErrUnsafe
	}
	u32 := func(offset int) uint32 { return binary.LittleEndian.Uint32(buffer[offset : offset+4]) }
	total := uint64(u32(0))
	displacement := int64(int32(u32(4)))
	length := uint64(u32(8))
	if total < 12 || total > uint64(len(buffer)) || total > aclResponseCapacity {
		return nil, ErrUnsafe
	}
	if length == 0 {
		if total != 12 || displacement != 0 && displacement != 8 {
			return nil, ErrUnsafe
		}
		return nil, nil
	}
	if displacement < 8 {
		return nil, ErrUnsafe
	}
	start := uint64(4 + displacement)
	if start > total || length > total-start || start+length != total || length < 44 {
		return nil, ErrUnsafe
	}
	payload := buffer[int(start):int(total)]
	if binary.LittleEndian.Uint32(payload[:4]) != aclSecurityMagic {
		return nil, ErrUnsafe
	}
	count := binary.LittleEndian.Uint32(payload[36:40])
	flags := binary.LittleEndian.Uint32(payload[40:44])
	if flags & ^uint32(0x00030000) != 0 {
		return nil, ErrUnsafe
	}
	if count == ^uint32(0) {
		count = 0
	}
	if count > aclEntryLimit || uint64(len(payload)) != 44+uint64(count)*24 {
		return nil, ErrUnsafe
	}
	result := make([]aclEntry, 0, count)
	for offset := 44; offset < len(payload); offset += 24 {
		var entry aclEntry
		copy(entry.principal[:], payload[offset:offset+16])
		entry.flags = binary.LittleEndian.Uint32(payload[offset+16 : offset+20])
		entry.rights = binary.LittleEndian.Uint32(payload[offset+20 : offset+24])
		kind := entry.flags & 15
		if kind != 1 && kind != 2 || entry.flags & ^uint32(0x1ff) != 0 {
			return nil, ErrUnsafe
		}
		result = append(result, entry)
	}
	return result, nil
}

func checkACLGrants(entries []aclEntry, managed bool, trusted [][16]byte) error {
	for _, entry := range entries {
		if entry.flags&15 == 2 || entry.rights == 0 {
			continue
		}
		if !managed && entry.rights & ^aclAncestorRead == 0 {
			continue
		}
		allowed := false
		for _, principal := range trusted {
			if entry.principal == principal {
				allowed = true
			}
		}
		if !allowed {
			return ErrUnsafe
		}
	}
	return nil
}

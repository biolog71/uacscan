// Package fileattr renders Linux file attributes the way the command line
// tools do, so that artifacts which pipe find(1) output through getcap or
// lsattr can be reproduced without running either.
package fileattr

import (
	"encoding/binary"
	"errors"
	"sort"
	"strings"
)

// The on-disk layout of security.capability, from linux/capability.h:
//
//	struct vfs_cap_data {
//	        __le32 magic_etc;
//	        struct { __le32 permitted, inheritable; } data[VFS_CAP_U32];
//	};
//
// Revision 3 appends a rootid for user namespaces but is otherwise identical.
const (
	vfsCapRevisionMask   = 0xFF000000
	vfsCapRevision1      = 0x01000000
	vfsCapRevision2      = 0x02000000
	vfsCapRevision3      = 0x03000000
	vfsCapFlagsEffective = 0x000001
)

// ErrNoCapabilities reports an attribute that is absent or unusable.
var ErrNoCapabilities = errors.New("no file capabilities")

// capNames maps capability numbers to the names getcap prints. The list is a
// kernel ABI: numbers are never reused, so an unknown high number simply means
// a capability newer than this table.
var capNames = []string{
	"cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner",
	"cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid",
	"cap_setpcap", "cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast",
	"cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
	"cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
	"cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
	"cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod",
	"cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap",
	"cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
	"cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf",
	"cap_checkpoint_restore",
}

// CapabilityName returns the name for a capability number.
func CapabilityName(n int) string {
	if n >= 0 && n < len(capNames) {
		return capNames[n]
	}
	// Unknown numbers are printed numerically, as libcap does.
	return "cap_" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Capabilities decodes a security.capability attribute into the text getcap
// prints after the file name, for example "cap_net_raw=ep".
//
// Capabilities sharing a flag set are grouped, and the flags are spelled in
// libcap's order: effective, inheritable, permitted.
func Capabilities(attr []byte) (string, error) {
	if len(attr) < 8 {
		return "", ErrNoCapabilities
	}
	magic := binary.LittleEndian.Uint32(attr[0:4])
	effective := magic&vfsCapFlagsEffective != 0

	var words int
	switch magic & vfsCapRevisionMask {
	case vfsCapRevision1:
		words = 1
	case vfsCapRevision2, vfsCapRevision3:
		words = 2
	default:
		return "", ErrNoCapabilities
	}
	if len(attr) < 4+8*words {
		return "", ErrNoCapabilities
	}

	var permitted, inheritable uint64
	for i := 0; i < words; i++ {
		p := uint64(binary.LittleEndian.Uint32(attr[4+i*8 : 8+i*8]))
		inh := uint64(binary.LittleEndian.Uint32(attr[8+i*8 : 12+i*8]))
		permitted |= p << (32 * i)
		inheritable |= inh << (32 * i)
	}
	if permitted == 0 && inheritable == 0 {
		return "", ErrNoCapabilities
	}

	// Group by flag set so that capabilities sharing one are printed together,
	// which is what libcap's cap_to_text does.
	groups := map[string][]string{}
	for n := 0; n < 64; n++ {
		bit := uint64(1) << n
		inP := permitted&bit != 0
		inI := inheritable&bit != 0
		if !inP && !inI {
			continue
		}
		var flags strings.Builder
		if effective && inP {
			flags.WriteByte('e')
		}
		if inI {
			flags.WriteByte('i')
		}
		if inP {
			flags.WriteByte('p')
		}
		key := flags.String()
		groups[key] = append(groups[key], CapabilityName(n))
	}
	if len(groups) == 0 {
		return "", ErrNoCapabilities
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, strings.Join(groups[k], ",")+"="+k)
	}
	return strings.Join(parts, " "), nil
}

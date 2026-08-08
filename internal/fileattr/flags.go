package fileattr

// Attribute flag bits, from linux/fs.h. These are a stable kernel ABI.
const (
	FlagSecRM       = 0x00000001 // s
	FlagUnrm        = 0x00000002 // u
	FlagCompr       = 0x00000004 // c
	FlagSync        = 0x00000008 // S
	FlagImmutable   = 0x00000010 // i
	FlagAppend      = 0x00000020 // a
	FlagNoDump      = 0x00000040 // d
	FlagNoAtime     = 0x00000080 // A
	FlagNoCompr     = 0x00000400 // m
	FlagEncrypt     = 0x00000800 // E
	FlagIndex       = 0x00001000 // I
	FlagJournalData = 0x00004000 // j
	FlagNoTail      = 0x00008000 // t
	FlagDirSync     = 0x00010000 // D
	FlagTopDir      = 0x00020000 // T
	FlagExtents     = 0x00080000 // e
	FlagVerity      = 0x00100000 // V
	FlagNoCOW       = 0x00800000 // C
	FlagDAX         = 0x02000000 // x
	FlagInlineData  = 0x10000000 // N
	FlagProjInherit = 0x20000000 // P
	FlagCasefold    = 0x40000000 // F
)

// flagOrder is e2fsprogs' flags_array from lib/e2p/pf.c, which fixes both the
// characters and their positions in lsattr's output.
//
// The order is not guessable and not alphabetical, so it was derived by
// measurement rather than from memory: setting individual flags on real files
// and reading back where lsattr placed each character. That pinned d at index
// 6, A at 7, e at 14 and the total width at 22, which the sequence below
// reproduces. A different e2fsprogs release may add entries and shift the tail.
var flagOrder = []struct {
	bit  uint32
	char byte
}{
	{FlagSecRM, 's'},
	{FlagUnrm, 'u'},
	{FlagSync, 'S'},
	{FlagDirSync, 'D'},
	{FlagImmutable, 'i'},
	{FlagAppend, 'a'},
	{FlagNoDump, 'd'},
	{FlagNoAtime, 'A'},
	{FlagCompr, 'c'},
	{FlagEncrypt, 'E'},
	{FlagJournalData, 'j'},
	{FlagIndex, 'I'},
	{FlagNoTail, 't'},
	{FlagTopDir, 'T'},
	{FlagExtents, 'e'},
	{FlagVerity, 'V'},
	{FlagNoCOW, 'C'},
	{FlagDAX, 'x'},
	{FlagCasefold, 'F'},
	{FlagInlineData, 'N'},
	{FlagProjInherit, 'P'},
	{FlagNoCompr, 'm'},
}

// FlagString renders attribute flags the way lsattr's default listing does: one
// column per known flag, a dash where it is unset.
func FlagString(flags uint32) string {
	out := make([]byte, len(flagOrder))
	for i, f := range flagOrder {
		if flags&f.bit != 0 {
			out[i] = f.char
		} else {
			out[i] = '-'
		}
	}
	return string(out)
}

// IsImmutable reports whether the immutable bit is set.
func IsImmutable(flags uint32) bool { return flags&FlagImmutable != 0 }

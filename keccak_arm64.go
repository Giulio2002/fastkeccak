//go:build arm64 && !purego

package keccak

import (
	"encoding/binary"
	"runtime"

	"golang.org/x/sys/cpu"
)

// Apple Silicon always has Armv8.2-A SHA3 extensions (VEOR3, VRAX1, VXAR, VBCAX).
// On other ARM64 platforms, detect at runtime via CPU feature flags.
// When SHA3 is unavailable, falls back to x/crypto/sha3.
func init() {
	useASM = runtime.GOOS == "darwin" || runtime.GOOS == "ios" || cpu.ARM64.HasSHA3
}

// keccakF1600Sha3 permutes state. When buf != nil, it first XORs rate bytes
// of buf into state, saving one full memory pass.
//
//go:noescape
func keccakF1600Sha3(a *[200]byte, buf *byte)

func keccakF1600(a *[200]byte) {
	keccakF1600Sha3(a, nil)
}

func xorAndPermute(state *[200]byte, buf *byte) {
	keccakF1600Sha3(state, buf)
}

// keccakF1600Sha3x2 XORs one rate-sized block of each message into the two
// interleaved states in st (lane i of message 0 in st[2i], message 1 in
// st[2i+1]) and permutes both simultaneously: the second state rides in the
// otherwise-unused upper 64-bit halves of the vector registers.
//
//go:noescape
func keccakF1600Sha3x2(st *[50]uint64, buf0, buf1 *byte)

// haveSum256Pair reports that this platform has a fused two-message kernel.
const haveSum256Pair = true

// sum256Pair computes the Keccak-256 digests of two independent inputs,
// sharing the permutation while both still have full blocks left.
func sum256Pair(a, b []byte) ([32]byte, [32]byte) {
	var st [50]uint64
	for len(a) >= rate && len(b) >= rate {
		keccakF1600Sha3x2(&st, &a[0], &b[0])
		a, b = a[rate:], b[rate:]
	}

	if len(a) < rate && len(b) < rate {
		// Both tails fit in one padded block each: fuse the final
		// permutation too. This makes pairing profitable even for inputs
		// shorter than one block (two messages, one permutation).
		var ta, tb [rate]byte
		copy(ta[:], a)
		ta[len(a)] = 0x01
		ta[rate-1] |= 0x80
		copy(tb[:], b)
		tb[len(b)] = 0x01
		tb[rate-1] |= 0x80
		keccakF1600Sha3x2(&st, &ta[0], &tb[0])

		var da, db [32]byte
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(da[i*8:], st[2*i])
			binary.LittleEndian.PutUint64(db[i*8:], st[2*i+1])
		}
		return da, db
	}

	// Lengths differ by more than a block: de-interleave and finish each
	// message individually.
	var sa, sb [200]byte
	for i := 0; i < 25; i++ {
		binary.LittleEndian.PutUint64(sa[i*8:], st[2*i])
		binary.LittleEndian.PutUint64(sb[i*8:], st[2*i+1])
	}
	return finishTail(&sa, a), finishTail(&sb, b)
}

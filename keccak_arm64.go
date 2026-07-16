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
	if useASM {
		batchKernel = sum256PairBatch
	}
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

// keccakF1600Sha3x2 absorbs and permutes `blocks` consecutive rate-sized
// blocks of each message into the two interleaved states in st (lane i of
// message 0 in st[2i], message 1 in st[2i+1]). Both states ride the same
// instruction stream: the second message occupies the otherwise-unused upper
// 64-bit halves of the vector registers, and the state stays
// register-resident across all blocks.
//
//go:noescape
func keccakF1600Sha3x2(st *[50]uint64, buf0, buf1 *byte, blocks int)

// sum256PairBatch hashes adjacent input pairs with the two-message kernel,
// returning how many inputs it consumed (the largest even prefix).
func sum256PairBatch(dst [][32]byte, inputs [][]byte) int {
	i := 0
	for ; i+1 < len(inputs); i += 2 {
		dst[i], dst[i+1] = sum256Pair(inputs[i], inputs[i+1])
	}
	return i
}

// sum256Pair computes the Keccak-256 digests of two independent inputs,
// sharing the permutation while both still have full blocks left.
func sum256Pair(a, b []byte) ([32]byte, [32]byte) {
	if (len(a) >= rate) != (len(b) >= rate) {
		// No shared full blocks and no shared final block — nothing to
		// fuse; plain hashing avoids the pair-state setup entirely.
		return Sum256(a), Sum256(b)
	}

	var st [50]uint64
	if blocks := min(len(a), len(b)) / rate; blocks > 0 {
		keccakF1600Sha3x2(&st, &a[0], &b[0], blocks)
		a, b = a[blocks*rate:], b[blocks*rate:]
	}

	if len(a) < rate && len(b) < rate {
		// Both tails fit in one padded block each: fuse the final
		// permutation too. This makes pairing profitable even for inputs
		// shorter than one block (two messages, one permutation).
		var ta, tb [rate]byte
		padBlock(&ta, a)
		padBlock(&tb, b)
		keccakF1600Sha3x2(&st, &ta[0], &tb[0], 1)

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

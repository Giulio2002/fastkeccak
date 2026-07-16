// Package keccak provides Keccak-256 hashing with platform-specific acceleration.
package keccak

import "hash"

// KeccakState wraps the keccak hasher. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

const rate = 136 // sponge rate for Keccak-256: (1600 - 2*256) / 8

var _ KeccakState = (*Hasher)(nil)

func NewFastKeccak() *Hasher {
	return &Hasher{}
}

// batchKernel, when non-nil, hashes some prefix of inputs into dst and
// returns how many inputs it consumed. Platform init registers it when a
// multi-message SIMD kernel is available; the hook is width-agnostic so a
// kernel of any lane count fits without touching Sum256Batch.
var batchKernel func(dst [][32]byte, inputs [][]byte) int

// Sum256Batch computes the Keccak-256 digest of each input into the
// corresponding element of dst. It panics if dst is shorter than inputs.
//
// Where a multi-message SIMD kernel is available (arm64 with SHA3
// extensions), independent inputs are hashed in lockstep, roughly doubling
// throughput; similar-length inputs batch fastest. Elsewhere it is
// equivalent to calling Sum256 in a loop.
func Sum256Batch(dst [][32]byte, inputs [][]byte) {
	if len(dst) < len(inputs) {
		panic("keccak: Sum256Batch dst shorter than inputs")
	}
	i := 0
	if batchKernel != nil {
		i = batchKernel(dst, inputs)
	}
	for ; i < len(inputs); i++ {
		dst[i] = Sum256(inputs[i])
	}
}

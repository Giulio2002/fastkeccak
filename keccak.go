// Package keccak provides Keccak-256 hashing with platform-specific acceleration.
package keccak

// The amd64 BMI2 permutation is generated; keep the .s file in sync by
// running `go generate` (checked in CI). The generator emits unaligned
// assembly, so asmfmt runs over its output — the committed .s must satisfy
// the asmfmt check like any hand-written one. Pinned, and fetched by
// `go run pkg@version`, which does not touch go.mod.
//go:generate go run gen_keccakf_bmi2.go
//go:generate go run github.com/klauspost/asmfmt/cmd/asmfmt@v1.3.2 -w keccakf_amd64_bmi2.s

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

// NewFastKeccak returns a new Keccak-256 hasher. The zero value of Hasher is
// equally usable and avoids the allocation.
func NewFastKeccak() *Hasher {
	return &Hasher{}
}

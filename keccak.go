// Package keccak provides Keccak-256 hashing with platform-specific acceleration.
package keccak

// The amd64 BMI2 permutation is generated; keep the .s file in sync by
// running `go generate` (checked in CI).
//go:generate go run gen_keccakf_bmi2.go

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

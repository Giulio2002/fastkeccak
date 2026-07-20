// Package keccak provides Keccak-256 hashing with platform-specific acceleration.
package keccak

// The amd64 BMI2 permutation is generated; keep the .s file in sync by
// running `go generate` (checked in CI).
//go:generate go run gen_keccakf_bmi2.go

import (
	"encoding"
	"errors"
	"hash"
	"slices"

	"golang.org/x/crypto/sha3"
)

// KeccakState wraps the keccak hasher. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

const rate = 136 // sponge rate for Keccak-256: (1600 - 2*256) / 8

var (
	_ KeccakState                = (*Hasher)(nil)
	_ encoding.BinaryMarshaler   = (*Hasher)(nil)
	_ encoding.BinaryAppender    = (*Hasher)(nil)
	_ encoding.BinaryUnmarshaler = (*Hasher)(nil)
)

// NewFastKeccak returns a new Keccak-256 hasher. The zero value of Hasher is
// equally usable and avoids the allocation.
func NewFastKeccak() *Hasher {
	return &Hasher{}
}

// Canonical marshaled-state format, identical no matter which implementation
// (native assembly or the x/crypto/sha3 fallback) produced it — the active
// implementation is a runtime CPU-feature decision, so the encoding must not
// depend on it:
//
//	magic (4) || state (200) || flags (1) || pos (1)
//
// state always has any partially absorbed input already XORed in; flags bit 0
// is the sponge direction (0 = absorbing, 1 = squeezing); pos is the byte
// position within the current block (absorb offset or squeeze read offset).
const (
	marshalMagic  = "fk1\x01"
	marshaledSize = len(marshalMagic) + 200 + 1 + 1
)

var errInvalidState = errors.New("keccak: invalid hash state")

// appendState appends the canonical encoding of a sponge state.
func appendState(b []byte, state *[200]byte, squeezing bool, pos int) []byte {
	b = slices.Grow(b, marshaledSize)
	b = append(b, marshalMagic...)
	b = append(b, state[:]...)
	var flags byte
	if squeezing {
		flags = 1
	}
	return append(b, flags, byte(pos))
}

// parseState validates and decodes a canonical encoding.
//
// pos == rate is valid only while squeezing: the x/crypto implementation
// permutes lazily on the next Read, so a state squeezed to an exact block
// boundary persists with pos == rate. The native decoder normalizes it by
// permuting eagerly.
func parseState(data []byte) (state [200]byte, squeezing bool, pos int, err error) {
	if len(data) != marshaledSize || string(data[:len(marshalMagic)]) != marshalMagic {
		return state, false, 0, errInvalidState
	}
	payload := data[len(marshalMagic):]
	flags, posByte := payload[200], int(payload[201])
	squeezing = flags == 1
	if flags > 1 || posByte > rate || (!squeezing && posByte == rate) {
		return state, false, 0, errInvalidState
	}
	copy(state[:], payload[:200])
	return state, squeezing, posByte, nil
}

// x/crypto/sha3's own stable marshal layout for legacy Keccak
// (sha3/legacy_hash.go): magic || rate || state || n || direction.
const (
	xcMagic = "sha\x0b"
	xcSize  = len(xcMagic) + 1 + 200 + 1 + 1
)

var errXCFormat = errors.New("keccak: unexpected x/crypto/sha3 state format")

// xcAppendState re-encodes a wrapped x/crypto/sha3 hasher's state in the
// canonical format. x/crypto keeps partial input XORed into the state with n
// as the block offset, which matches the canonical layout directly.
func xcAppendState(b []byte, xc KeccakState) ([]byte, error) {
	m, ok := xc.(encoding.BinaryMarshaler)
	if !ok {
		return nil, errXCFormat
	}
	enc, err := m.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(enc) != xcSize || string(enc[:len(xcMagic)]) != xcMagic || int(enc[4]) != rate {
		return nil, errXCFormat
	}
	var state [200]byte
	copy(state[:], enc[5:205])
	return appendState(b, &state, enc[206] == 1, int(enc[205])), nil
}

// xcFromState builds a wrapped x/crypto/sha3 hasher holding the given
// canonical sponge state.
func xcFromState(state *[200]byte, squeezing bool, pos int) (KeccakState, error) {
	blob := make([]byte, 0, xcSize)
	blob = append(blob, xcMagic...)
	blob = append(blob, byte(rate))
	blob = append(blob, state[:]...)
	var dir byte
	if squeezing {
		dir = 1
	}
	blob = append(blob, byte(pos), dir)

	st, ok := sha3.NewLegacyKeccak256().(KeccakState)
	if !ok {
		return nil, errXCFormat
	}
	u, ok := st.(encoding.BinaryUnmarshaler)
	if !ok {
		return nil, errXCFormat
	}
	if err := u.UnmarshalBinary(blob); err != nil {
		return nil, err
	}
	return st, nil
}

// cloneXC deep-copies a wrapped x/crypto/sha3 hasher via a marshal round-trip.
func cloneXC(xc KeccakState) (KeccakState, error) {
	m, ok := xc.(encoding.BinaryMarshaler)
	if !ok {
		return nil, errXCFormat
	}
	enc, err := m.MarshalBinary()
	if err != nil {
		return nil, err
	}
	st, ok := sha3.NewLegacyKeccak256().(KeccakState)
	if !ok {
		return nil, errXCFormat
	}
	u, ok := st.(encoding.BinaryUnmarshaler)
	if !ok {
		return nil, errXCFormat
	}
	if err := u.UnmarshalBinary(enc); err != nil {
		return nil, err
	}
	return st, nil
}

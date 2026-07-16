// Package keccak provides Keccak-256 hashing with platform-specific acceleration.
package keccak

import (
	"encoding"
	"errors"
	"hash"

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

func NewFastKeccak() *Hasher {
	return &Hasher{}
}

// Marshaled-state format identifiers. The two implementations (native asm
// sponge and wrapped x/crypto/sha3) use different encodings; the prefix makes
// a mismatch a clear error instead of silent corruption.
const (
	marshalMagicNative = "fk1n" // native asm sponge
	marshalMagicXC     = "fk1x" // wrapped x/crypto/sha3 state
)

var (
	errInvalidState = errors.New("keccak: invalid hash state")
	errNativeState  = errors.New("keccak: state was marshaled by the native implementation; this build uses the x/crypto/sha3 fallback")
	errXCState      = errors.New("keccak: state was marshaled by the x/crypto/sha3 fallback; this build uses the native implementation")
)

// marshalXC appends the marshaled state of a wrapped x/crypto/sha3 hasher,
// prefixed with marshalMagicXC.
func marshalXC(b []byte, xc KeccakState) ([]byte, error) {
	b = append(b, marshalMagicXC...)
	if a, ok := xc.(encoding.BinaryAppender); ok {
		return a.AppendBinary(b)
	}
	m, ok := xc.(encoding.BinaryMarshaler)
	if !ok {
		return nil, errors.New("keccak: underlying sha3 state does not support binary marshaling")
	}
	enc, err := m.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(b, enc...), nil
}

// unmarshalXC restores a wrapped x/crypto/sha3 hasher from a payload produced
// by marshalXC (without the magic prefix).
func unmarshalXC(payload []byte) (KeccakState, error) {
	st := sha3.NewLegacyKeccak256().(KeccakState)
	u, ok := st.(encoding.BinaryUnmarshaler)
	if !ok {
		return nil, errors.New("keccak: underlying sha3 state does not support binary unmarshaling")
	}
	if err := u.UnmarshalBinary(payload); err != nil {
		return nil, err
	}
	return st, nil
}

// cloneXC deep-copies a wrapped x/crypto/sha3 hasher via a marshal round-trip.
func cloneXC(xc KeccakState) (KeccakState, error) {
	enc, err := marshalXC(nil, xc)
	if err != nil {
		return nil, err
	}
	return unmarshalXC(enc[len(marshalMagicXC):])
}

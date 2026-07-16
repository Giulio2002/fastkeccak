//go:build (!arm64 && !amd64) || purego

package keccak

import (
	"golang.org/x/crypto/sha3"
)

// Sum256 computes the Keccak-256 hash of data.
// On non-arm64 platforms, delegates to x/crypto/sha3.NewLegacyKeccak256().
func Sum256(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Hasher is a streaming Keccak-256 hasher wrapping x/crypto/sha3.
type Hasher struct {
	h KeccakState
}

func (h *Hasher) init() {
	if h.h == nil {
		h.h = sha3.NewLegacyKeccak256().(KeccakState)
	}
}

// Reset resets the hasher to its initial state.
func (h *Hasher) Reset() {
	h.init()
	h.h.Reset()
}

// Write absorbs data into the hasher.
// Panics if called after Read.
func (h *Hasher) Write(p []byte) (int, error) {
	h.init()
	return h.h.Write(p)
}

// Sum256 finalizes and returns the 32-byte Keccak-256 digest.
// Does not modify the hasher state.
func (h *Hasher) Sum256() [32]byte {
	h.init()
	var out [32]byte
	h.h.Sum(out[:0])
	return out
}

// Sum appends the current Keccak-256 digest to b and returns the resulting slice.
// Does not modify the hasher state.
func (h *Hasher) Sum(b []byte) []byte {
	h.init()
	return h.h.Sum(b)
}

// Size returns the number of bytes Sum will produce (32).
func (h *Hasher) Size() int { return 32 }

// BlockSize returns the sponge rate in bytes (136).
func (h *Hasher) BlockSize() int { return rate }

// Read squeezes an arbitrary number of bytes from the sponge.
// On the first call, it pads and permutes, transitioning from absorbing to squeezing.
// Subsequent calls to Write will panic. It never returns an error.
func (h *Hasher) Read(out []byte) (int, error) {
	h.init()
	return h.h.Read(out)
}

// Clone returns a copy of the hasher in its current state. The copy and the
// original evolve independently.
func (h *Hasher) Clone() (*Hasher, error) {
	if h.h == nil {
		return &Hasher{}, nil
	}
	c, err := cloneXC(h.h)
	if err != nil {
		return nil, err
	}
	return &Hasher{h: c}, nil
}

// MarshalBinary implements encoding.BinaryMarshaler. The encoding is
// canonical: the same logical state marshals to the same bytes regardless of
// platform or active implementation, and can be restored anywhere.
func (h *Hasher) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize))
}

// AppendBinary implements encoding.BinaryAppender.
func (h *Hasher) AppendBinary(b []byte) ([]byte, error) {
	if h.h == nil {
		// A zero-value hasher is the canonical zero state; avoid allocating
		// (and retaining) a backing state just to encode it.
		var zero [200]byte
		return appendState(b, &zero, false, 0), nil
	}
	return xcAppendState(b, h.h)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (h *Hasher) UnmarshalBinary(data []byte) error {
	state, squeezing, pos, err := parseState(data)
	if err != nil {
		return err
	}
	st, err := xcFromState(&state, squeezing, pos)
	if err != nil {
		return err
	}
	h.h = st
	return nil
}

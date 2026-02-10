// Package keccak provides Keccak-256 hashing with platform-specific acceleration.
//
// On Apple Silicon (arm64/darwin), uses NEON SHA3 extensions (VEOR3, VRAX1, VXAR, VBCAX).
// On amd64, uses an unrolled permutation with complementing lanes optimization.
// Falls back to a pure-Go implementation on other platforms or with the purego build tag.
//
// Go 1.25's stdlib crypto/sha3 only exposes SHA-3 (domain 0x06), not Keccak-256
// (domain 0x01). And x/crypto/sha3.NewLegacyKeccak256() uses a pure-Go permutation
// with zero assembly on any platform. This package bridges the gap by using the
// same assembly from Go's stdlib for the keccak-f[1600] permutation.
package keccak

import "unsafe"

const (
	// rate is the sponge rate for Keccak-256: (1600 - 2*256) / 8 = 136 bytes.
	rate = 136
)

// Sum256 computes the Keccak-256 hash of data. Zero heap allocations.
func Sum256(data []byte) [32]byte {
	var state [200]byte

	// Absorb full blocks.
	for len(data) >= rate {
		xorIn(&state, data[:rate])
		keccakF1600(&state)
		data = data[rate:]
	}

	// Absorb remaining bytes + Keccak padding.
	// Keccak uses domain separator 0x01 (NOT SHA-3's 0x06).
	xorIn(&state, data)
	state[len(data)] ^= 0x01
	// pad10*1 end bit.
	state[rate-1] ^= 0x80
	keccakF1600(&state)

	// Squeeze 32 bytes.
	return [32]byte(state[:32])
}

// Hasher is a streaming Keccak-256 hasher. Designed for stack allocation.
type Hasher struct {
	state    [200]byte
	buf      [rate]byte
	absorbed int
}

// Reset resets the hasher to its initial state.
func (h *Hasher) Reset() {
	h.state = [200]byte{}
	h.absorbed = 0
}

// Write absorbs data into the hasher.
func (h *Hasher) Write(p []byte) {
	if h.absorbed > 0 {
		n := copy(h.buf[h.absorbed:rate], p)
		h.absorbed += n
		p = p[n:]
		if h.absorbed == rate {
			xorIn(&h.state, h.buf[:])
			keccakF1600(&h.state)
			h.absorbed = 0
		}
	}

	for len(p) >= rate {
		xorIn(&h.state, p[:rate])
		keccakF1600(&h.state)
		p = p[rate:]
	}

	if len(p) > 0 {
		h.absorbed = copy(h.buf[:], p)
	}
}

// Sum256 finalizes and returns the 32-byte Keccak-256 digest.
// Does not modify the hasher state.
func (h *Hasher) Sum256() [32]byte {
	state := h.state
	xorIn(&state, h.buf[:h.absorbed])
	state[h.absorbed] ^= 0x01
	state[rate-1] ^= 0x80
	keccakF1600(&state)
	return [32]byte(state[:32])
}

// xorIn XORs data into the beginning of state.
// Uses uint64 operations for the bulk of the data (8x fewer ops than byte-by-byte).
func xorIn(state *[200]byte, data []byte) {
	// XOR 8 bytes at a time using little-endian uint64 reads.
	n := len(data) >> 3
	stateU64 := (*[25]uint64)(unsafe.Pointer(state))
	for i := 0; i < n; i++ {
		stateU64[i] ^= le64(data[8*i:])
	}
	// Handle remaining bytes (< 8).
	for i := n << 3; i < len(data); i++ {
		state[i] ^= data[i]
	}
}

// le64 reads a little-endian uint64 from at least 8 bytes.
func le64(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

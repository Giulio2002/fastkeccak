//go:build amd64 && !purego

package keccak

//go:noescape
func keccakF1600(a *[200]byte)

//go:noescape
func xorAndPermute(state *[200]byte, buf *byte)

// Sum256 computes the Keccak-256 hash of data. Zero heap allocations.
func Sum256(data []byte) [32]byte { return sum256Sponge(data) }

// Hasher is a streaming Keccak-256 hasher. Designed for stack allocation.
type Hasher struct{ sponge }

// Sum256Reset finalizes and returns the 32-byte Keccak-256 digest, then resets
// the hasher. Faster than Sum256 followed by Reset because it avoids copying
// the internal state.
func (h *Hasher) Sum256Reset() [32]byte {
	return h.sponge.sum256AndReset()
}

//go:build arm64 && !purego

package keccak

import (
	"hash"
	"io"
	"runtime"
	"unsafe"

	"golang.org/x/crypto/sha3"
	"golang.org/x/sys/cpu"
)

// Apple Silicon always has Armv8.2-A SHA3 extensions (VEOR3, VRAX1, VXAR, VBCAX).
// On other ARM64 platforms, detect at runtime via CPU feature flags.
// When SHA3 is unavailable, falls back to x/crypto/sha3.
var useSHA3 = runtime.GOOS == "darwin" || runtime.GOOS == "ios" || cpu.ARM64.HasSHA3

//go:noescape
func keccakF1600NEON(a *[200]byte)

// Sum256 computes the Keccak-256 hash of data. Zero heap allocations when SHA3 is available.
func Sum256(data []byte) [32]byte {
	if !useSHA3 {
		return sum256XCrypto(data)
	}

	var state [200]byte

	for len(data) >= rate {
		xorIn(&state, data[:rate])
		keccakF1600NEON(&state)
		data = data[rate:]
	}

	xorIn(&state, data)
	state[len(data)] ^= 0x01
	state[rate-1] ^= 0x80
	keccakF1600NEON(&state)

	return [32]byte(state[:32])
}

func sum256XCrypto(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Hasher is a streaming Keccak-256 hasher.
// Uses NEON SHA3 assembly when available, x/crypto/sha3 otherwise.
type Hasher struct {
	// NEON sponge state
	state     [200]byte
	buf       [rate]byte
	absorbed  int
	squeezing bool
	readIdx   int // index into buf for next Read byte
	// x/crypto fallback
	xc hash.Hash
}

// Reset resets the hasher to its initial state.
func (h *Hasher) Reset() {
	if useSHA3 {
		h.state = [200]byte{}
		h.absorbed = 0
		h.squeezing = false
		h.readIdx = 0
	} else {
		if h.xc == nil {
			h.xc = sha3.NewLegacyKeccak256()
		} else {
			h.xc.Reset()
		}
	}
}

// Write absorbs data into the hasher.
// Panics if called after Read.
func (h *Hasher) Write(p []byte) {
	if h.squeezing {
		panic("keccak: Write after Read")
	}
	if !useSHA3 {
		if h.xc == nil {
			h.xc = sha3.NewLegacyKeccak256()
		}
		h.xc.Write(p)
		return
	}

	if h.absorbed > 0 {
		n := copy(h.buf[h.absorbed:rate], p)
		h.absorbed += n
		p = p[n:]
		if h.absorbed == rate {
			xorIn(&h.state, h.buf[:])
			keccakF1600NEON(&h.state)
			h.absorbed = 0
		}
	}

	for len(p) >= rate {
		xorIn(&h.state, p[:rate])
		keccakF1600NEON(&h.state)
		p = p[rate:]
	}

	if len(p) > 0 {
		h.absorbed = copy(h.buf[:], p)
	}
}

// Sum256 finalizes and returns the 32-byte Keccak-256 digest.
// Does not modify the hasher state.
func (h *Hasher) Sum256() [32]byte {
	if !useSHA3 {
		if h.xc == nil {
			return Sum256(nil)
		}
		var out [32]byte
		h.xc.Sum(out[:0])
		return out
	}

	state := h.state
	xorIn(&state, h.buf[:h.absorbed])
	state[h.absorbed] ^= 0x01
	state[rate-1] ^= 0x80
	keccakF1600NEON(&state)
	return [32]byte(state[:32])
}

// Read squeezes an arbitrary number of bytes from the sponge.
// On the first call, it pads and permutes, transitioning from absorbing to squeezing.
// Subsequent calls to Write will panic. It never returns an error.
func (h *Hasher) Read(out []byte) (int, error) {
	if !useSHA3 {
		if h.xc == nil {
			h.xc = sha3.NewLegacyKeccak256()
		}
		return h.xc.(io.Reader).Read(out)
	}

	if !h.squeezing {
		h.padAndSqueeze()
	}

	n := len(out)
	for len(out) > 0 {
		x := copy(out, h.buf[h.readIdx:rate])
		h.readIdx += x
		out = out[x:]
		if h.readIdx == rate {
			keccakF1600NEON(&h.state)
			copy(h.buf[:], h.state[:rate])
			h.readIdx = 0
		}
	}
	return n, nil
}

func (h *Hasher) padAndSqueeze() {
	xorIn(&h.state, h.buf[:h.absorbed])
	h.state[h.absorbed] ^= 0x01
	h.state[rate-1] ^= 0x80
	keccakF1600NEON(&h.state)
	copy(h.buf[:], h.state[:rate])
	h.squeezing = true
	h.readIdx = 0
}

func xorIn(state *[200]byte, data []byte) {
	n := len(data) >> 3
	stateU64 := (*[25]uint64)(unsafe.Pointer(state))
	for i := 0; i < n; i++ {
		stateU64[i] ^= le64(data[8*i:])
	}
	for i := n << 3; i < len(data); i++ {
		state[i] ^= data[i]
	}
}

func le64(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

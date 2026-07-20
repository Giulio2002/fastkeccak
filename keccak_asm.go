//go:build (amd64 || arm64) && !purego

package keccak

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// useASM is set by platform-specific init to indicate hardware acceleration is available.
// When false, Sum256 and Hasher fall back to x/crypto/sha3.
var useASM bool

// sponge is the core Keccak-256 sponge state used by native (asm) implementations.
type sponge struct {
	state     [200]byte
	buf       [rate]byte
	absorbed  int
	squeezing bool
	readIdx   int // index into state for next Read byte
}

// Reset resets the sponge to its initial state.
func (s *sponge) Reset() {
	s.state = [200]byte{}
	s.absorbed = 0
	s.squeezing = false
	s.readIdx = 0
}

// Write absorbs data into the sponge.
// Panics if called after Read.
func (s *sponge) Write(p []byte) (int, error) {
	if s.squeezing {
		panic("keccak: Write after Read")
	}
	n := len(p)
	if s.absorbed > 0 {
		x := copy(s.buf[s.absorbed:rate], p)
		s.absorbed += x
		p = p[x:]
		if s.absorbed == rate {
			xorAndPermute(&s.state, &s.buf[0])
			s.absorbed = 0
		}
	}

	for len(p) >= rate {
		xorAndPermute(&s.state, &p[0])
		p = p[rate:]
	}

	if len(p) > 0 {
		s.absorbed = copy(s.buf[:], p)
	}
	return n, nil
}

// Sum256 finalizes and returns the 32-byte Keccak-256 digest.
// Does not modify the sponge state.
// Panics if called after Read.
func (s *sponge) Sum256() [32]byte {
	if s.squeezing {
		panic("keccak: Sum after Read")
	}
	state := s.state
	xorIn(&state, s.buf[:s.absorbed])
	state[s.absorbed] ^= 0x01
	state[rate-1] ^= 0x80
	keccakF1600(&state)
	return [32]byte(state[:32])
}

// Sum appends the current Keccak-256 digest to b and returns the resulting slice.
// Does not modify the sponge state.
func (s *sponge) Sum(b []byte) []byte {
	d := s.Sum256()
	return append(b, d[:]...)
}

// Size returns the number of bytes Sum will produce (32).
func (s *sponge) Size() int { return 32 }

// BlockSize returns the sponge rate in bytes (136).
func (s *sponge) BlockSize() int { return rate }

// Read squeezes an arbitrary number of bytes from the sponge.
// On the first call, it pads and permutes, transitioning from absorbing to squeezing.
// Subsequent calls to Write will panic. It never returns an error.
func (s *sponge) Read(out []byte) (int, error) {
	if !s.squeezing {
		s.padAndSqueeze()
	}

	n := len(out)
	for len(out) > 0 {
		x := copy(out, s.state[s.readIdx:rate])
		s.readIdx += x
		out = out[x:]
		if s.readIdx == rate {
			keccakF1600(&s.state)
			s.readIdx = 0
		}
	}
	return n, nil
}

func (s *sponge) padAndSqueeze() {
	xorIn(&s.state, s.buf[:s.absorbed])
	s.state[s.absorbed] ^= 0x01
	s.state[rate-1] ^= 0x80
	keccakF1600(&s.state)
	s.absorbed = 0
	s.squeezing = true
	s.readIdx = 0
}

// sum256Sponge computes Keccak-256 in one shot using the assembly permutation.
func sum256Sponge(data []byte) [32]byte {
	var state [200]byte

	for len(data) >= rate {
		xorAndPermute(&state, &data[0])
		data = data[rate:]
	}

	xorIn(&state, data)
	state[len(data)] ^= 0x01
	state[rate-1] ^= 0x80
	keccakF1600(&state)

	return [32]byte(state[:32])
}

// Sum256 computes the Keccak-256 hash of data. Zero heap allocations when hardware
// acceleration is available.
func Sum256(data []byte) [32]byte {
	if !useASM {
		return sum256XCrypto(data)
	}
	return sum256Sponge(data)
}

func sum256XCrypto(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Hasher is a streaming Keccak-256 hasher.
// Uses platform assembly when available, x/crypto/sha3 otherwise.
type Hasher struct {
	sponge
	xc KeccakState // x/crypto fallback
}

// Reset resets the hasher to its initial state.
func (h *Hasher) Reset() {
	if useASM {
		h.sponge.Reset()
	} else {
		if h.xc == nil {
			h.xc = sha3.NewLegacyKeccak256().(KeccakState)
		} else {
			h.xc.Reset()
		}
	}
}

// Write absorbs data into the hasher.
// Panics if called after Read.
func (h *Hasher) Write(p []byte) (int, error) {
	if !useASM {
		if h.xc == nil {
			h.xc = sha3.NewLegacyKeccak256().(KeccakState)
		}
		return h.xc.Write(p)
	}
	return h.sponge.Write(p)
}

// Sum256 finalizes and returns the 32-byte Keccak-256 digest.
// Does not modify the hasher state.
func (h *Hasher) Sum256() [32]byte {
	if !useASM {
		if h.xc == nil {
			return Sum256(nil)
		}
		var out [32]byte
		h.xc.Sum(out[:0])
		return out
	}
	return h.sponge.Sum256()
}

// Sum appends the current Keccak-256 digest to b and returns the resulting slice.
// Does not modify the hasher state.
func (h *Hasher) Sum(b []byte) []byte {
	if !useASM {
		if h.xc == nil {
			d := Sum256(nil)
			return append(b, d[:]...)
		}
		return h.xc.Sum(b)
	}
	return h.sponge.Sum(b)
}

// Read squeezes an arbitrary number of bytes from the sponge.
// On the first call, it pads and permutes, transitioning from absorbing to squeezing.
// Subsequent calls to Write will panic. It never returns an error.
func (h *Hasher) Read(out []byte) (int, error) {
	if !useASM {
		if h.xc == nil {
			h.xc = sha3.NewLegacyKeccak256().(KeccakState)
		}
		return h.xc.Read(out)
	}
	return h.sponge.Read(out)
}

// Clone returns a copy of the hasher in its current state. The copy and the
// original evolve independently.
func (h *Hasher) Clone() (*Hasher, error) {
	if useASM {
		return &Hasher{sponge: h.sponge}, nil
	}
	if h.xc == nil {
		return &Hasher{}, nil
	}
	xc, err := cloneXC(h.xc)
	if err != nil {
		return nil, err
	}
	return &Hasher{xc: xc}, nil
}

// MarshalBinary implements encoding.BinaryMarshaler. The encoding is
// canonical: the same logical state marshals to the same bytes regardless of
// platform or active implementation, and can be restored anywhere.
func (h *Hasher) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize))
}

// AppendBinary implements encoding.BinaryAppender.
func (h *Hasher) AppendBinary(b []byte) ([]byte, error) {
	if !useASM {
		if h.xc == nil {
			// A zero-value hasher is the canonical zero state; avoid
			// allocating (and retaining) a fallback state just to encode it.
			var zero [200]byte
			return appendState(b, &zero, false, 0), nil
		}
		return xcAppendState(b, h.xc)
	}
	s := &h.sponge
	if s.squeezing {
		return appendState(b, &s.state, true, s.readIdx), nil
	}
	// Canonical form keeps partial input XORed into the state.
	state := s.state
	xorIn(&state, s.buf[:s.absorbed])
	return appendState(b, &state, false, s.absorbed), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (h *Hasher) UnmarshalBinary(data []byte) error {
	state, squeezing, pos, err := parseState(data)
	if err != nil {
		return err
	}
	if !useASM {
		xc, err := xcFromState(&state, squeezing, pos)
		if err != nil {
			return err
		}
		h.xc = xc
		return nil
	}
	// Partial input is already XORed into state, so buf stays zero: absorbing
	// XORs buf into state at finalization, and XORing zeroes is a no-op.
	s := sponge{state: state}
	if squeezing {
		if pos == rate {
			// Block-boundary state from the lazy fallback implementation;
			// the native sponge permutes eagerly.
			keccakF1600(&s.state)
			pos = 0
		}
		s.squeezing, s.readIdx = true, pos
	} else {
		s.absorbed = pos
	}
	h.sponge = s
	return nil
}

// xorIn XORs data into the first len(data) bytes of state using uint64 loads.
func xorIn(state *[200]byte, data []byte) {
	for i := 0; i+8 <= len(data); i += 8 {
		v := binary.LittleEndian.Uint64(state[i:]) ^ binary.LittleEndian.Uint64(data[i:])
		binary.LittleEndian.PutUint64(state[i:], v)
	}
	for i := len(data) &^ 7; i < len(data); i++ {
		state[i] ^= data[i]
	}
}

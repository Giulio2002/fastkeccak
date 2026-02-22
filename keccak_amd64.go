//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func keccakF1600(a *[200]byte)

// Sum256 computes the Keccak-256 hash of data. Zero heap allocations.
func Sum256(data []byte) [32]byte {
	var state [200]byte

	for len(data) >= rate {
		xorIn(&state, data[:rate])
		keccakF1600(&state)
		data = data[rate:]
	}

	xorIn(&state, data)
	state[len(data)] ^= 0x01
	state[rate-1] ^= 0x80
	keccakF1600(&state)

	return [32]byte(state[:32])
}

// Hasher is a streaming Keccak-256 hasher. Designed for stack allocation.
type Hasher struct {
	state     [200]byte
	buf       [rate]byte
	absorbed  int
	squeezing bool
	readIdx   int // index into buf for next Read byte
}

// Reset resets the hasher to its initial state.
func (h *Hasher) Reset() {
	h.state = [200]byte{}
	h.absorbed = 0
	h.squeezing = false
	h.readIdx = 0
}

// Write absorbs data into the hasher.
// Panics if called after Read.
func (h *Hasher) Write(p []byte) {
	if h.squeezing {
		panic("keccak: Write after Read")
	}
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

// Read squeezes an arbitrary number of bytes from the sponge.
// On the first call, it pads and permutes, transitioning from absorbing to squeezing.
// Subsequent calls to Write will panic. It never returns an error.
func (h *Hasher) Read(out []byte) (int, error) {
	if !h.squeezing {
		h.padAndSqueeze()
	}

	n := len(out)
	for len(out) > 0 {
		x := copy(out, h.buf[h.readIdx:rate])
		h.readIdx += x
		out = out[x:]
		if h.readIdx == rate {
			keccakF1600(&h.state)
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
	keccakF1600(&h.state)
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

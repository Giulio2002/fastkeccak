//go:build (amd64 || arm64) && !purego

package keccak

import (
	"math/rand"
	"testing"
)

// TestXorAndPermute verifies the fused XOR+permute assembly entry point
// against the composition of its two parts (xorIn + keccakF1600). The fused
// path is otherwise only covered indirectly through digest comparisons.
func TestXorAndPermute(t *testing.T) {
	if !useASM {
		t.Skip("hardware acceleration unavailable on this CPU")
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		var a, b [200]byte
		var buf [rate]byte
		rng.Read(a[:])
		rng.Read(buf[:])
		b = a

		xorAndPermute(&a, &buf[0])

		xorIn(&b, buf[:])
		keccakF1600(&b)

		if a != b {
			t.Fatalf("iteration %d: xorAndPermute diverges from xorIn+keccakF1600\ngot:  %x\nwant: %x", i, a, b)
		}
	}
}

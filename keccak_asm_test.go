//go:build (amd64 || arm64) && !purego

package keccak

import (
	"bytes"
	"math/rand"
	"strconv"
	"testing"

	"golang.org/x/crypto/sha3"
)

// TestXorAndPermute verifies the fused XOR+permute assembly entry point
// against the composition of its two parts (xorIn + keccakF1600). The fused
// path is otherwise only covered indirectly through digest comparisons.
func TestXorAndPermute(t *testing.T) {
	if !useASM {
		t.Skip("hardware acceleration unavailable on this CPU")
	}
	// The permutation has no data-dependent branches, so a divergence shows
	// on essentially any random state; more iterations add no assurance.
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 128; i++ {
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

// TestSpongeReadDefersBoundaryPermutation covers Read(rate) followed by
// Read(k): the only sequence where moving the block permutation to the read
// that needs it can change the output. TestReadMatchesXCrypto reads once per
// hasher and TestReadMultipleCalls chunks by 37, so neither lands a call
// boundary on rate.
func TestSpongeReadDefersBoundaryPermutation(t *testing.T) {
	if !useASM {
		t.Skip("hardware acceleration unavailable on this CPU")
	}
	const input = "input"
	for _, k := range []int{1, 7, rate - 1, rate, rate + 1} {
		t.Run(strconv.Itoa(k), func(t *testing.T) {
			ref := sha3.NewLegacyKeccak256().(KeccakState)
			ref.Write([]byte(input))
			want := make([]byte, rate+k)
			ref.Read(want)

			var s sponge
			s.Write([]byte(input))
			got := make([]byte, rate+k)
			s.Read(got[:rate])
			if s.readIdx != rate {
				t.Fatalf("read index after one full block = %d, want %d", s.readIdx, rate)
			}
			s.Read(got[rate:])

			if !bytes.Equal(got, want) {
				t.Fatalf("Read(%d)+Read(%d) = %x, want %x", rate, k, got, want)
			}
		})
	}
}

func BenchmarkSpongeRead(b *testing.B) {
	if !useASM {
		b.Skip("hardware acceleration unavailable on this CPU")
	}
	for _, size := range []int{rate - 1, rate, rate + 1} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			out := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				var h sponge
				h.Write([]byte("input"))
				h.Read(out)
			}
		})
	}
}

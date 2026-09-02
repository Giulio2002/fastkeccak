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

// backendDigests carries the digest each size produced on the first backend
// benchmarked, so the second one is checked against it rather than only
// timed.
var backendDigests = map[int][32]byte{}

// BenchmarkBackends compares the assembly backend against the x/crypto
// fallback on the same CPU, to answer whether the assembly is actually
// faster on this core. It flips useASM, so it must not run in parallel with
// anything else in the package.
func BenchmarkBackends(b *testing.B) {
	restore := useASM
	defer func() { useASM = restore }()

	if hasASM {
		b.Run("ASM", func(b *testing.B) { benchmarkBackend(b, true) })
	}
	b.Run("XCrypto", func(b *testing.B) { benchmarkBackend(b, false) })
}

func benchmarkBackend(b *testing.B, native bool) {
	for _, size := range benchSizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i)
		}

		b.Run(benchName(size), func(b *testing.B) {
			useASM = native
			var h Hasher
			// Warm up outside the timer: with useASM false the first Reset
			// lazily builds the x/crypto hasher, and that one allocation
			// would otherwise be reported as a per-op cost.
			h.Reset()
			var out [32]byte
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				h.Reset()
				h.Write(data)
				h.Read(out[:])
			}
			if want, ok := backendDigests[size]; ok && out != want {
				b.Fatalf("backend digest for %d bytes = %x, other backend gave %x", size, out, want)
			}
			backendDigests[size] = out
		})
	}
}

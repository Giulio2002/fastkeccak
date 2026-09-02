//go:build (amd64 || arm64) && !purego

package keccak

import (
	"math/rand"
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

func xcDigest(state KeccakState) [32]byte {
	var out [32]byte
	state.Sum(out[:0])
	return out
}

// TestHasherCloneFallbackState covers Clone on a receiver whose state lives in
// the x/crypto fallback while the package dispatches to assembly. Building the
// receiver directly keeps the test off the useASM global, which is only safe
// to write while nothing else in the package runs concurrently.
func TestHasherCloneFallbackState(t *testing.T) {
	const prefix = "shared prefix"
	var original Hasher
	original.xc = sha3.NewLegacyKeccak256().(KeccakState)
	original.xc.Write([]byte(prefix))

	clone, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	original.xc.Write([]byte(" original"))
	clone.xc.Write([]byte(" clone"))

	if got, want := xcDigest(original.xc), Sum256([]byte(prefix+" original")); got != want {
		t.Fatalf("original digest = %x, want %x", got, want)
	}
	if got, want := xcDigest(clone.xc), Sum256([]byte(prefix+" clone")); got != want {
		t.Fatalf("clone digest = %x, want %x", got, want)
	}
}

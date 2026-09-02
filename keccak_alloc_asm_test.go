//go:build (amd64 || arm64) && !purego

package keccak

import "testing"

// TestAsmSum256ZeroAllocs pins the library's headline property: on the
// assembly path Sum256 squeezes out of a copy of the sponge state, so it must
// not allocate at all.
func TestAsmSum256ZeroAllocs(t *testing.T) {
	if !useASM {
		t.Skip("hardware acceleration unavailable on this CPU")
	}
	var h Hasher
	h.Write([]byte("allocation test"))
	h.Sum256()
	if allocs := testing.AllocsPerRun(1000, func() {
		benchmarkDigest = h.Sum256()
	}); allocs != 0 {
		t.Fatalf("Hasher.Sum256 allocations = %v, want 0", allocs)
	}
}

func TestFallbackHasherSum256Allocs(t *testing.T) {
	old := useASM
	useASM = false
	t.Cleanup(func() { useASM = old })

	testHasherSum256Allocs(t)
}

func BenchmarkFallbackHasherSum256(b *testing.B) {
	old := useASM
	useASM = false
	b.Cleanup(func() { useASM = old })

	benchmarkHasherSum256(b)
}

package keccak

import "testing"

var benchmarkDigest [32]byte

func testHasherSum256Allocs(t *testing.T) {
	t.Helper()

	var h Hasher
	h.Write([]byte("allocation test"))
	h.Sum256()

	allocs := testing.AllocsPerRun(1000, func() {
		benchmarkDigest = h.Sum256()
	})
	if allocs != 0 {
		t.Fatalf("Hasher.Sum256 allocations = %v, want 0", allocs)
	}
}

func TestHasherSum256Allocs(t *testing.T) {
	testHasherSum256Allocs(t)
}

func benchmarkHasherSum256(b *testing.B) {
	var h Hasher
	h.Write([]byte("allocation benchmark"))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkDigest = h.Sum256()
	}
}

func BenchmarkHasherSum256(b *testing.B) {
	benchmarkHasherSum256(b)
}

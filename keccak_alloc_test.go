package keccak

import "testing"

var benchmarkDigest [32]byte

func testHasherSum256Allocs(t *testing.T) {
	t.Helper()

	input := []byte("allocation test")

	// A Hasher forced onto the heap costs exactly what one allocated there
	// to begin with costs, so comparing the two needs no per-platform
	// constant. Holding the digest buffer in Hasher, rather than in a local,
	// makes these equal.
	stack := testing.AllocsPerRun(1000, func() {
		var h Hasher
		h.Write(input)
		benchmarkDigest = h.Sum256()
	})
	heap := testing.AllocsPerRun(1000, func() {
		h := heapHasher()
		h.Write(input)
		benchmarkDigest = h.Sum256()
	})
	if stack >= heap {
		t.Fatalf("stack-allocated Hasher costs %v allocations against %v for a heap-allocated one: the Hasher is escaping", stack, heap)
	}
}

// heapHasher keeps the baseline honest: inlined, NewFastKeccak's result does
// not escape the closure either and the compiler stack-allocates it too.
//
//go:noinline
func heapHasher() *Hasher { return &Hasher{} }

func TestHasherSum256Allocs(t *testing.T) {
	testHasherSum256Allocs(t)
}

func benchmarkHasherSum256(b *testing.B) {
	var h Hasher
	h.Write([]byte("allocation benchmark"))
	b.ReportAllocs()
	for b.Loop() {
		benchmarkDigest = h.Sum256()
	}
}

func BenchmarkHasherSum256(b *testing.B) {
	benchmarkHasherSum256(b)
}

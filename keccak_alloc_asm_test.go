//go:build (amd64 || arm64) && !purego

package keccak

import "testing"

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

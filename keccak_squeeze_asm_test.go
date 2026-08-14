//go:build (amd64 || arm64) && !purego

package keccak

import (
	"strconv"
	"testing"
)

func TestSpongeReadDefersBoundaryPermutation(t *testing.T) {
	var h sponge
	h.Write([]byte("input"))
	h.Read(make([]byte, rate))

	if h.readIdx != rate {
		t.Fatalf("read index after one full block = %d, want %d", h.readIdx, rate)
	}

	var next [1]byte
	h.Read(next[:])
	if h.readIdx != 1 {
		t.Fatalf("read index after next byte = %d, want 1", h.readIdx)
	}
}

func BenchmarkSpongeRead(b *testing.B) {
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

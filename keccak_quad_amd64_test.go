//go:build amd64 && !purego

package keccak

import (
	"fmt"
	"testing"
)

// TestSum256Quad exercises the 4-way AVX2 kernel across block boundaries and
// mixed lengths, comparing every digest against the scalar path. Skips on
// CPUs without AVX2 (note: Rosetta 2 does not report AVX2, so this runs on
// real amd64 hardware only — CI's ubuntu runners cover it).
func TestSum256Quad(t *testing.T) {
	if batchKernel == nil {
		t.Skip("4-way batch kernel unavailable on this CPU")
	}
	mk := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*13 + n)
		}
		return b
	}
	cases := [][4]int{
		{0, 0, 0, 0},
		{32, 32, 32, 32},
		{135, 136, 137, 271},
		{136, 136, 136, 136},
		{272, 271, 273, 270},
		{0, 500, 32, 1000}, // mixed: falls back to scalar per message
		{1000, 999, 998, 997},
	}
	for _, lens := range cases {
		t.Run(fmt.Sprint(lens), func(t *testing.T) {
			var inputs [4][]byte
			for i, n := range lens {
				inputs[i] = mk(n)
			}
			d0, d1, d2, d3 := sum256Quad(inputs[0], inputs[1], inputs[2], inputs[3])
			for i, got := range [][32]byte{d0, d1, d2, d3} {
				if want := Sum256(inputs[i]); got != want {
					t.Fatalf("input %d (len %d): %x, want %x", i, lens[i], got, want)
				}
			}
		})
	}
}

func FuzzSum256Quad(f *testing.F) {
	f.Add([]byte(nil), []byte("a"), make([]byte, rate), make([]byte, rate*2+7))
	f.Fuzz(func(t *testing.T, a, b, c, d []byte) {
		if batchKernel == nil {
			t.Skip("4-way batch kernel unavailable on this CPU")
		}
		d0, d1, d2, d3 := sum256Quad(a, b, c, d)
		for i, in := range [][]byte{a, b, c, d} {
			if want := Sum256(in); [][32]byte{d0, d1, d2, d3}[i] != want {
				t.Fatalf("input %d (len %d) mismatch", i, len(in))
			}
		}
	})
}

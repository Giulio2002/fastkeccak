//go:build amd64 && !purego

package keccak

import (
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"
)

// TestSum256Oct exercises the 8-way AVX-512 kernel across block boundaries
// and mixed lengths, comparing every digest against the scalar path. Skips
// on CPUs without AVX-512F (GitHub's ubuntu runners are a hardware lottery
// here — Intel runners have it, some AMD ones don't; the test is a no-op
// where it can't run).
func TestSum256Oct(t *testing.T) {
	if !useASM || !cpu.X86.HasAVX512F {
		t.Skip("8-way batch kernel unavailable on this CPU")
	}
	mk := func(n, seed int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*11 + seed)
		}
		return b
	}
	cases := [][8]int{
		{0, 0, 0, 0, 0, 0, 0, 0},
		{32, 32, 32, 32, 32, 32, 32, 32},
		{135, 136, 137, 271, 272, 273, 400, 500},
		{136, 136, 136, 136, 136, 136, 136, 136},
		{0, 500, 32, 1000, 7, 136, 0, 272}, // mixed: scalar fallback
		{1000, 999, 998, 997, 996, 995, 994, 993},
	}
	for _, lens := range cases {
		t.Run(fmt.Sprint(lens), func(t *testing.T) {
			inputs := make([][]byte, 8)
			for i, n := range lens {
				inputs[i] = mk(n, i)
			}
			dst := make([][32]byte, 8)
			sum256Oct(dst, inputs)
			for i, in := range inputs {
				if want := Sum256(in); dst[i] != want {
					t.Fatalf("input %d (len %d): %x, want %x", i, len(in), dst[i], want)
				}
			}
			// The driver must not mutate the caller's slice headers.
			for i, n := range lens {
				if len(inputs[i]) != n {
					t.Fatalf("input %d mutated: len %d, want %d", i, len(inputs[i]), n)
				}
			}
		})
	}
}

func FuzzSum256Oct(f *testing.F) {
	f.Add([]byte(nil), []byte("a"), make([]byte, rate), make([]byte, rate*2+7))
	f.Fuzz(func(t *testing.T, a, b, c, d []byte) {
		if !useASM || !cpu.X86.HasAVX512F {
			t.Skip("8-way batch kernel unavailable on this CPU")
		}
		inputs := [][]byte{a, b, c, d, d, c, b, a}
		dst := make([][32]byte, 8)
		sum256Oct(dst, inputs)
		for i, in := range inputs {
			if want := Sum256(in); dst[i] != want {
				t.Fatalf("input %d (len %d) mismatch", i, len(in))
			}
		}
	})
}

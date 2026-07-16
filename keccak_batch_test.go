package keccak

import (
	"fmt"
	"testing"
)

func TestSum256Batch(t *testing.T) {
	mk := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*11 + n)
		}
		return b
	}

	// Length combinations around block boundaries, equal and unequal pairs,
	// odd counts, and empty inputs.
	cases := [][]int{
		{},
		{0},
		{1},
		{32, 32},
		{0, 300},
		{135, 136},
		{136, 136},
		{137, 135},
		{272, 272},
		{271, 273},
		{500, 32, 136},
		{0, 1, 135, 136, 137, 271, 272, 273, 1000},
	}
	for _, lens := range cases {
		t.Run(fmt.Sprint(lens), func(t *testing.T) {
			inputs := make([][]byte, len(lens))
			for i, n := range lens {
				inputs[i] = mk(n)
			}
			dst := make([][32]byte, len(inputs))
			Sum256Batch(dst, inputs)
			for i, in := range inputs {
				if want := Sum256(in); dst[i] != want {
					t.Fatalf("input %d (len %d): %x, want %x", i, len(in), dst[i], want)
				}
			}
		})
	}
}

func TestSum256BatchDstTooShort(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when dst is shorter than inputs")
		}
	}()
	Sum256Batch(make([][32]byte, 1), make([][]byte, 2))
}

func FuzzSum256Batch(f *testing.F) {
	f.Add([]byte(nil), []byte("hello"))
	f.Add(make([]byte, rate), make([]byte, rate))
	f.Add(make([]byte, rate*2+1), make([]byte, 17))

	f.Fuzz(func(t *testing.T, a, b []byte) {
		dst := make([][32]byte, 2)
		Sum256Batch(dst, [][]byte{a, b})
		if want := Sum256(a); dst[0] != want {
			t.Fatalf("a (len %d): %x, want %x", len(a), dst[0], want)
		}
		if want := Sum256(b); dst[1] != want {
			t.Fatalf("b (len %d): %x, want %x", len(b), dst[1], want)
		}
	})
}

func BenchmarkSum256Batch(b *testing.B) {
	for _, size := range []int{32, 136, 1024, 4096} {
		const n = 64
		inputs := make([][]byte, n)
		for i := range inputs {
			inputs[i] = make([]byte, size)
			for j := range inputs[i] {
				inputs[i][j] = byte(i + j)
			}
		}
		dst := make([][32]byte, n)

		b.Run(fmt.Sprintf("batch/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size * n))
			b.ReportAllocs()
			for b.Loop() {
				Sum256Batch(dst, inputs)
			}
		})
		b.Run(fmt.Sprintf("sequential/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size * n))
			b.ReportAllocs()
			for b.Loop() {
				for i, in := range inputs {
					dst[i] = Sum256(in)
				}
			}
		})
	}
}

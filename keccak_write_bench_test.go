package keccak

import (
	"strconv"
	"testing"
)

func BenchmarkHasherOneByteWrites(b *testing.B) {
	for _, size := range []int{32, 128, 256} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			data := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				var h Hasher
				for i := range data {
					h.Write(data[i : i+1])
				}
				h.Sum256()
			}
		})
	}
}

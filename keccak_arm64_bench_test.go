//go:build arm64 && !purego

package keccak

import (
	"strconv"
	"testing"
)

var arm64BackendDigest [32]byte

func BenchmarkARM64Backends(b *testing.B) {
	nativeAvailable := useASM
	defer func() { useASM = nativeAvailable }()

	if nativeAvailable {
		b.Run("SHA3", func(b *testing.B) {
			benchmarkARM64Backend(b, true)
		})
	}
	b.Run("XCrypto", func(b *testing.B) {
		benchmarkARM64Backend(b, false)
	})
}

func benchmarkARM64Backend(b *testing.B, native bool) {
	for _, size := range []int{32, 128, 256, 1024, 4096, 500 * 1024} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i)
		}

		b.Run(strconv.Itoa(size), func(b *testing.B) {
			useASM = native
			var h Hasher
			h.Reset()
			var out [32]byte
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				h.Reset()
				h.Write(data)
				h.Read(out[:])
				arm64BackendDigest = out
			}
		})
	}
}

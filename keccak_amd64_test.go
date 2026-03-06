//go:build amd64 && !purego

package keccak

import "testing"

func BenchmarkKeccakF1600(b *testing.B) {
	var state [200]byte
	b.ReportAllocs()
	for b.Loop() {
		keccakF1600(&state)
	}
}

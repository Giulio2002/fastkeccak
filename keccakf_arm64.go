//go:build arm64 && !purego

package keccak

import "runtime"

// Apple Silicon always has Armv8.2-A SHA3 extensions (VEOR3, VRAX1, VXAR, VBCAX).
// On non-Apple ARM64, these instructions are apparently slower than pure Go
// (per Go stdlib comment in crypto/internal/fips140/sha3/sha3_arm64.go).
var useSHA3 = runtime.GOOS == "darwin"

//go:noescape
func keccakF1600NEON(a *[200]byte)

func keccakF1600(a *[200]byte) {
	if useSHA3 {
		keccakF1600NEON(a)
	} else {
		keccakF1600Generic(a)
	}
}

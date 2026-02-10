//go:build amd64 && !purego

package keccak

// keccakF1600 is the Keccak-f[1600] permutation using an unrolled implementation
// with complementing lanes optimization. From Go stdlib crypto/internal/fips140/sha3.
//
//go:noescape
func keccakF1600(a *[200]byte)

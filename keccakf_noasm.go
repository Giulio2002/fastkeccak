//go:build purego || (!arm64 && !amd64)

package keccak

func keccakF1600(a *[200]byte) {
	keccakF1600Generic(a)
}

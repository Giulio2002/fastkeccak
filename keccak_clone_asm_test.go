//go:build (amd64 || arm64) && !purego

package keccak

import "testing"

func TestHasherCloneRuntimeFallback(t *testing.T) {
	old := useASM
	useASM = false
	t.Cleanup(func() { useASM = old })

	testHasherClone(t)
}

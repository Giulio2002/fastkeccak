//go:build arm64 && !purego

package keccak

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// All arm64 macOS machines (M1+) have the Armv8.2-A SHA3 extensions
// (VEOR3, VRAX1, VXAR, VBCAX). On other ARM64 platforms, detect at runtime
// via CPU feature flags. When SHA3 is unavailable, falls back to x/crypto/sha3.
//
// iOS is deliberately excluded: x/sys/cpu performs no feature detection on
// Darwin-family systems, and A12 and older chips (iPhone XS/XR, iPad 8, ...)
// lack FEAT_SHA3 — it first shipped in the A13. The Go standard library
// likewise leaves iOS without CPU feature detection (its darwin sysctl
// probing in internal/cpu is build-tagged `darwin && !ios`), so its SHA3
// assembly never runs on iOS either.
// hasASM is the CPU probe, recorded once. useASM is the dispatch flag and
// benchmarks flip it, so anything asking "can this CPU run the assembly?"
// must read hasASM.
var hasASM = runtime.GOOS == "darwin" || cpu.ARM64.HasSHA3

func init() {
	useASM = hasASM
}

// keccakF1600Sha3 permutes state. When buf != nil, it first XORs rate bytes
// of buf into state, saving one full memory pass.
//
//go:noescape
func keccakF1600Sha3(a *[200]byte, buf *byte)

func keccakF1600(a *[200]byte) {
	keccakF1600Sha3(a, nil)
}

func xorAndPermute(state *[200]byte, buf *byte) {
	keccakF1600Sha3(state, buf)
}

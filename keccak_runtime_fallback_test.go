//go:build (amd64 || arm64) && !purego

package keccak

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

func forceRuntimeFallback(t *testing.T) {
	t.Helper()
	old := useASM
	useASM = false
	t.Cleanup(func() { useASM = old })
}

func TestRuntimeFallbackMatchesXCrypto(t *testing.T) {
	forceRuntimeFallback(t)

	for _, size := range []int{0, 1, rate - 1, rate, rate + 1, 2 * rate, 500} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i*17 + size)
			}

			ref := sha3.NewLegacyKeccak256()
			ref.Write(data)
			var want [32]byte
			copy(want[:], ref.Sum(nil))

			if got := Sum256(data); got != want {
				t.Fatalf("Sum256 = %x, want %x", got, want)
			}

			var h Hasher
			for rest := data; len(rest) > 0; {
				n := min(37, len(rest))
				h.Write(rest[:n])
				rest = rest[n:]
			}
			if size > 0 && h.xc == nil {
				t.Fatal("Write did not materialize the x/crypto state, so the fallback branch never ran")
			}
			if got := h.Sum256(); got != want {
				t.Fatalf("Hasher.Sum256 = %x, want %x", got, want)
			}
			if got := h.Sum([]byte("prefix")); !bytes.Equal(got, append([]byte("prefix"), want[:]...)) {
				t.Fatalf("Hasher.Sum = %x, want prefix followed by %x", got, want)
			}

			gotStream := make([]byte, 300)
			h.Read(gotStream)
			wantStream := make([]byte, len(gotStream))
			ref.(KeccakState).Read(wantStream)
			if !bytes.Equal(gotStream, wantStream) {
				t.Fatal("Hasher.Read differs from x/crypto")
			}

			h.Reset()
			h.Write(data)
			if got := h.Sum256(); got != want {
				t.Fatalf("Hasher after Reset = %x, want %x", got, want)
			}

			var fresh Hasher
			fresh.Reset()
			fresh.Write(data)
			if got := fresh.Sum256(); got != want {
				t.Fatalf("Reset on a zero value = %x, want %x", got, want)
			}
		})
	}
}

func TestRuntimeFallbackZeroValue(t *testing.T) {
	forceRuntimeFallback(t)

	ref := sha3.NewLegacyKeccak256()
	var want [32]byte
	copy(want[:], ref.Sum(nil))

	var h Hasher
	if got := h.Sum256(); got != want {
		t.Fatalf("zero-value Sum256 = %x, want %x", got, want)
	}
	if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
		t.Fatalf("zero-value Sum = %x, want %x", got, want)
	}

	gotStream := make([]byte, 200)
	h.Read(gotStream)
	wantStream := make([]byte, len(gotStream))
	ref.(KeccakState).Read(wantStream)
	if !bytes.Equal(gotStream, wantStream) {
		t.Fatal("zero-value Read differs from x/crypto")
	}
}

func TestRuntimeFallbackWriteAfterReadPanics(t *testing.T) {
	forceRuntimeFallback(t)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on Write after Read")
		}
		// The sponge panics "keccak: Write after Read" for the same misuse,
		// so match the x/crypto prefix: otherwise this passes even when the
		// fallback is not the code under test.
		if s, ok := r.(string); !ok || !strings.Contains(s, "sha3: Write after Read") {
			t.Fatalf("recovered %v, want x/crypto's Write-after-Read panic", r)
		}
	}()

	var h Hasher
	h.Write([]byte("seed"))
	h.Read(make([]byte, 1))
	h.Write([]byte("data"))
}

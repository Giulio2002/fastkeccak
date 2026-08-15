//go:build (amd64 || arm64) && !purego

package keccak

import (
	"bytes"
	"slices"
	"testing"
)

// forceFallback routes the package through the x/crypto fallback arms of
// keccak_asm.go for the duration of a test. Those arms are compiled into
// every binary and taken at runtime on CPUs without BMI2 / SHA3 extensions
// (old Xeons, Graviton 2, ...), but no CI platform selects them naturally —
// purego builds compile keccak_default.go instead, which is different code.
// Tests using this must not call t.Parallel.
func forceFallback(t *testing.T) {
	t.Helper()
	old := useASM
	useASM = false
	t.Cleanup(func() { useASM = old })
}

// asFallback runs fn with the package routed through the x/crypto fallback,
// restoring whichever implementation was selected before. Unlike
// forceFallback it is scoped to a single call rather than a whole test, so
// one test can cross between implementations. t.Fatalf inside fn still runs
// the restore, since Goexit unwinds defers.
func asFallback(fn func()) {
	old := useASM
	useASM = false
	defer func() { useASM = old }()
	fn()
}

var fallbackLens = []int{0, 1, 32, 135, 136, 137, 271, 272, 300}

func fallbackData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*17 + n)
	}
	return b
}

// TestFallbackMatchesNative captures digests and squeeze streams from the
// active implementation, then re-runs everything through the fallback arms.
func TestFallbackMatchesNative(t *testing.T) {
	type captured struct {
		data   []byte
		digest [32]byte
		stream []byte
	}
	var want []captured
	for _, n := range fallbackLens {
		data := fallbackData(n)
		digest := Sum256(data)
		var h Hasher
		h.Write(data)
		if got := h.Sum(nil); !bytes.Equal(got, digest[:]) {
			t.Fatalf("len %d: native Sum = %x, want %x", n, got, digest)
		}
		stream := make([]byte, 300)
		h.Read(stream)
		want = append(want, captured{data, digest, stream})
	}

	forceFallback(t)

	for _, w := range want {
		if got := Sum256(w.data); got != w.digest {
			t.Fatalf("len %d: fallback Sum256 = %x, want %x", len(w.data), got, w.digest)
		}

		// Streaming in uneven chunks, then non-destructive Sum/Sum256.
		var h Hasher
		for rest := w.data; len(rest) > 0; {
			n := min(37, len(rest))
			h.Write(rest[:n])
			rest = rest[n:]
		}
		if got := h.Sum256(); got != w.digest {
			t.Fatalf("len %d: fallback Hasher.Sum256 = %x, want %x", len(w.data), got, w.digest)
		}
		if got := h.Sum([]byte("prefix")); !bytes.Equal(got, append([]byte("prefix"), w.digest[:]...)) {
			t.Fatalf("len %d: fallback Sum append mismatch", len(w.data))
		}

		// Squeezing.
		stream := make([]byte, 300)
		h.Read(stream)
		if !bytes.Equal(stream, w.stream) {
			t.Fatalf("len %d: fallback Read stream diverged", len(w.data))
		}

		// Reset and reuse.
		h.Reset()
		h.Write(w.data)
		if got := h.Sum256(); got != w.digest {
			t.Fatalf("len %d: fallback after Reset = %x, want %x", len(w.data), got, w.digest)
		}
	}
}

// TestFallbackCloneAndMarshal exercises the fallback arms of Clone and the
// binary marshaling round-trip, mid-absorb and mid-squeeze.
func TestFallbackCloneAndMarshal(t *testing.T) {
	forceFallback(t)

	prefix, suffix := fallbackData(150), fallbackData(41)
	whole := Sum256(slices.Concat(prefix, suffix))

	var h Hasher
	h.Write(prefix)

	c, err := h.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	c.Write(suffix)
	if got := c.Sum256(); got != whole {
		t.Fatalf("fallback clone: %x, want %x", got, whole)
	}

	enc, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var restored Hasher
	if err := restored.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	restored.Write(suffix)
	if got := restored.Sum256(); got != whole {
		t.Fatalf("fallback marshal round-trip: %x, want %x", got, whole)
	}

	// Mid-squeeze round-trip, including the lazy block-boundary state
	// (pos == rate) that only the fallback implementation produces.
	for _, pre := range []int{0, 50, rate} {
		var s Hasher
		s.Write(prefix)
		s.Read(make([]byte, pre))
		enc, err := s.MarshalBinary()
		if err != nil {
			t.Fatalf("pre %d: MarshalBinary: %v", pre, err)
		}
		var r Hasher
		if err := r.UnmarshalBinary(enc); err != nil {
			t.Fatalf("pre %d: UnmarshalBinary: %v", pre, err)
		}
		a, b := make([]byte, 200), make([]byte, 200)
		s.Read(a)
		r.Read(b)
		if !bytes.Equal(a, b) {
			t.Fatalf("pre %d: fallback mid-squeeze round-trip diverged", pre)
		}
	}

	// Zero-value hasher marshals without a backing state.
	var zero Hasher
	encZero, err := zero.MarshalBinary()
	if err != nil {
		t.Fatalf("zero MarshalBinary: %v", err)
	}
	var zr Hasher
	if err := zr.UnmarshalBinary(encZero); err != nil {
		t.Fatalf("zero UnmarshalBinary: %v", err)
	}
	if got, want := zr.Sum256(), Sum256(nil); got != want {
		t.Fatalf("zero round-trip: %x, want %x", got, want)
	}
}

// TestCrossImplementationMarshal proves the canonical format is portable
// between the native and fallback implementations in-process, in both
// directions — the scenario that motivated the single-format design (the
// same binary picks its implementation per host CPU).
func TestCrossImplementationMarshal(t *testing.T) {
	if !useASM {
		t.Skip("native implementation unavailable on this CPU")
	}
	data, suffix := fallbackData(200), fallbackData(77)
	whole := Sum256(slices.Concat(data, suffix))

	// Native → fallback.
	var n Hasher
	n.Write(data)
	encNative, err := n.MarshalBinary()
	if err != nil {
		t.Fatalf("native MarshalBinary: %v", err)
	}
	asFallback(func() {
		var f Hasher
		if err := f.UnmarshalBinary(encNative); err != nil {
			t.Fatalf("fallback UnmarshalBinary(native enc): %v", err)
		}
		f.Write(suffix)
		if got := f.Sum256(); got != whole {
			t.Fatalf("native->fallback: %x, want %x", got, whole)
		}
	})

	// Fallback → native.
	var encFallback []byte
	asFallback(func() {
		var f Hasher
		f.Write(data)
		var err error
		encFallback, err = f.MarshalBinary()
		if err != nil {
			t.Fatalf("fallback MarshalBinary: %v", err)
		}
	})
	var n2 Hasher
	if err := n2.UnmarshalBinary(encFallback); err != nil {
		t.Fatalf("native UnmarshalBinary(fallback enc): %v", err)
	}
	n2.Write(suffix)
	if got := n2.Sum256(); got != whole {
		t.Fatalf("fallback->native: %x, want %x", got, whole)
	}

	// The two encodings of the same logical state are byte-identical.
	if !bytes.Equal(encNative, encFallback) {
		t.Fatalf("encodings differ between implementations:\nnative:   %x\nfallback: %x", encNative, encFallback)
	}
}

// TestCrossImplementationEncodingsMatch checks the byte-identity claim across
// the state space, not just one absorbing state: every reachable kind of
// position, on both sides of the absorb/squeeze switch.
//
// The interesting entries are the block-boundary ones. Absorbing permutes
// eagerly on a filled block and squeezing permutes lazily on the next Read, so
// a squeeze that stops exactly at a boundary is the one state that two sponges
// can hold in two different-looking but equivalent forms (pre-permute at
// pos == rate, or post-permute at pos == 0). Both implementations squeeze
// lazily so that it always encodes the first way.
func TestCrossImplementationEncodingsMatch(t *testing.T) {
	if !useASM {
		t.Skip("native implementation unavailable on this CPU")
	}
	data := fallbackData(200)

	for _, tc := range []struct {
		name  string
		drive func(h *Hasher)
	}{
		{"zero value", func(*Hasher) {}},
		{"absorbing, partial block", func(h *Hasher) { h.Write(data[:50]) }},
		{"absorbing, exact block", func(h *Hasher) { h.Write(data[:rate]) }},
		{"absorbing, past a block", func(h *Hasher) { h.Write(data) }},
		{"squeezing, nothing read", func(h *Hasher) { h.Write(data); h.Read(nil) }},
		{"squeezing, partial block", func(h *Hasher) { h.Write(data); h.Read(make([]byte, 50)) }},
		{"squeezing, exact block", func(h *Hasher) { h.Write(data); h.Read(make([]byte, rate)) }},
		{"squeezing, two blocks", func(h *Hasher) { h.Write(data); h.Read(make([]byte, 2*rate)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// What the state is worth: the next 300 squeezed bytes.
			var ref Hasher
			tc.drive(&ref)
			want := make([]byte, 300)
			ref.Read(want)

			encode := func(h *Hasher) []byte {
				tc.drive(h)
				enc, err := h.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				return enc
			}
			var n Hasher
			encNative := encode(&n)
			var encFallback []byte
			asFallback(func() {
				var f Hasher
				encFallback = encode(&f)
			})
			if !bytes.Equal(encNative, encFallback) {
				t.Fatalf("encodings differ:\nnative:   %x\nfallback: %x", encNative, encFallback)
			}

			// Each implementation restores the other's encoding to a sponge
			// that produces the same output.
			check := func(who string, h *Hasher, enc []byte) {
				if err := h.UnmarshalBinary(enc); err != nil {
					t.Fatalf("%s UnmarshalBinary: %v", who, err)
				}
				got := make([]byte, len(want))
				h.Read(got)
				if !bytes.Equal(got, want) {
					t.Fatalf("%s squeezed a different stream after restore", who)
				}
			}
			var toNative Hasher
			check("native<-fallback", &toNative, encFallback)
			asFallback(func() {
				var toFallback Hasher
				check("fallback<-native", &toFallback, encNative)
			})
		})
	}
}

// TestFallbackHasherShape re-runs the implementation-independent surface
// through the fallback arms, where the panic comes out of x/crypto rather
// than the native sponge.
func TestFallbackHasherShape(t *testing.T) {
	forceFallback(t)
	checkHasherShape(t)
}

// The fallback pays two allocations to marshal, against one on the native
// path, because it re-encodes x/crypto's own MarshalBinary result. Routing
// x/crypto straight into the caller's buffer would remove that, at the cost
// of making the buffer escape on both paths, so the difference stands.
func TestMarshalAllocsPerPath(t *testing.T) {
	if useASM {
		if marshal, appendBuf := measureMarshalAllocs(t); marshal != 1 || appendBuf != 0 {
			t.Errorf("native allocs = %v marshal / %v append, want 1 / 0", marshal, appendBuf)
		}
	}
	asFallback(func() {
		if marshal, appendBuf := measureMarshalAllocs(t); marshal != 2 || appendBuf != 1 {
			t.Errorf("fallback allocs = %v marshal / %v append, want 2 / 1", marshal, appendBuf)
		}
	})
}

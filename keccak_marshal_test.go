package keccak

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"
)

func TestCloneIndependent(t *testing.T) {
	prefix := make([]byte, 100)
	for i := range prefix {
		prefix[i] = byte(i * 3)
	}
	suffixA := []byte("suffix-A")
	suffixB := []byte("suffix-B, and a longer one at that")

	var h Hasher
	h.Write(prefix)
	c, err := h.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}

	h.Write(suffixA)
	c.Write(suffixB)

	if got, want := h.Sum256(), Sum256(slices.Concat(prefix, suffixA)); got != want {
		t.Fatalf("original after clone: %x, want %x", got, want)
	}
	if got, want := c.Sum256(), Sum256(slices.Concat(prefix, suffixB)); got != want {
		t.Fatalf("clone: %x, want %x", got, want)
	}
}

func TestClonePrefixFork(t *testing.T) {
	// The motivating pattern: absorb a shared prefix once, fork per suffix.
	prefix := make([]byte, rate*2+17) // spans block boundaries
	for i := range prefix {
		prefix[i] = byte(i)
	}
	var base Hasher
	base.Write(prefix)

	for i := 0; i < 5; i++ {
		suffix := bytes.Repeat([]byte{byte(i + 1)}, i*40)
		c, err := base.Clone()
		if err != nil {
			t.Fatalf("Clone: %v", err)
		}
		c.Write(suffix)
		if got, want := c.Sum256(), Sum256(slices.Concat(prefix, suffix)); got != want {
			t.Fatalf("fork %d: %x, want %x", i, got, want)
		}
	}
	// base must be unaffected.
	if got, want := base.Sum256(), Sum256(prefix); got != want {
		t.Fatalf("base after forks: %x, want %x", got, want)
	}
}

func TestCloneMidSqueeze(t *testing.T) {
	var h Hasher
	h.Write([]byte("squeeze me"))
	first := make([]byte, 50)
	h.Read(first)

	c, err := h.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	a := make([]byte, 100)
	b := make([]byte, 100)
	h.Read(a)
	c.Read(b)
	if !bytes.Equal(a, b) {
		t.Fatalf("clone diverged mid-squeeze:\ngot:  %x\nwant: %x", b, a)
	}
}

func TestCloneZeroValue(t *testing.T) {
	var h Hasher
	c, err := h.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	c.Write([]byte("hello"))
	if got, want := c.Sum256(), Sum256([]byte("hello")); got != want {
		t.Fatalf("clone of zero value: %x, want %x", got, want)
	}
	if got, want := h.Sum256(), Sum256(nil); got != want {
		t.Fatalf("zero value after clone: %x, want %x", got, want)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	data := make([]byte, rate*2+50)
	for i := range data {
		data[i] = byte(i * 7)
	}
	// Split points around block boundaries.
	for _, split := range []int{0, 1, 17, rate - 1, rate, rate + 1, 2 * rate, len(data)} {
		var h Hasher
		h.Write(data[:split])
		enc, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("split %d: MarshalBinary: %v", split, err)
		}

		var restored Hasher
		if err := restored.UnmarshalBinary(enc); err != nil {
			t.Fatalf("split %d: UnmarshalBinary: %v", split, err)
		}
		restored.Write(data[split:])
		if got, want := restored.Sum256(), Sum256(data); got != want {
			t.Fatalf("split %d: %x, want %x", split, got, want)
		}
	}
}

func TestMarshalRoundTripMidSqueeze(t *testing.T) {
	for _, pre := range []int{0, 1, 50, rate - 1, rate, 200} {
		var h Hasher
		h.Write([]byte("marshal mid squeeze"))
		skip := make([]byte, pre)
		h.Read(skip)

		enc, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("pre %d: MarshalBinary: %v", pre, err)
		}
		var restored Hasher
		if err := restored.UnmarshalBinary(enc); err != nil {
			t.Fatalf("pre %d: UnmarshalBinary: %v", pre, err)
		}

		a := make([]byte, 300)
		b := make([]byte, 300)
		h.Read(a)
		restored.Read(b)
		if !bytes.Equal(a, b) {
			t.Fatalf("pre %d: restored squeeze diverged:\ngot:  %x\nwant: %x", pre, b, a)
		}
	}
}

func TestAppendBinary(t *testing.T) {
	var h Hasher
	h.Write([]byte("append"))
	prefix := []byte("existing")
	enc, err := h.AppendBinary(append([]byte(nil), prefix...))
	if err != nil {
		t.Fatalf("AppendBinary: %v", err)
	}
	if !bytes.HasPrefix(enc, prefix) {
		t.Fatalf("AppendBinary did not preserve prefix")
	}
	var restored Hasher
	if err := restored.UnmarshalBinary(enc[len(prefix):]); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if got, want := restored.Sum256(), h.Sum256(); got != want {
		t.Fatalf("restored: %x, want %x", got, want)
	}
}

// TestMarshalDoesNotMutate checks that marshaling is a read of the hasher, not
// a step in its lifecycle: encoding must be repeatable and must not disturb the
// digest or the squeeze stream. The native absorbing path is the one at risk,
// since it has to fold buffered input into a copy of the state.
func TestMarshalDoesNotMutate(t *testing.T) {
	for _, n := range []int{0, 1, 50, rate, rate + 7, 2*rate + 1} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i * 11)
		}
		var h Hasher
		h.Write(data)

		first, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("n=%d: MarshalBinary: %v", n, err)
		}
		second, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("n=%d: MarshalBinary (again): %v", n, err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("n=%d: marshaling twice gave different bytes", n)
		}
		if got, want := h.Sum256(), Sum256(data); got != want {
			t.Fatalf("n=%d: digest after marshal = %x, want %x", n, got, want)
		}

		// Same again, mid-squeeze.
		var s Hasher
		s.Write(data)
		s.Read(make([]byte, rate)) // stops on a block boundary
		if first, err = s.MarshalBinary(); err != nil {
			t.Fatalf("n=%d: mid-squeeze MarshalBinary: %v", n, err)
		}
		if second, err = s.MarshalBinary(); err != nil {
			t.Fatalf("n=%d: mid-squeeze MarshalBinary (again): %v", n, err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("n=%d: mid-squeeze marshaling twice gave different bytes", n)
		}

		var restored Hasher
		if err := restored.UnmarshalBinary(second); err != nil {
			t.Fatalf("n=%d: UnmarshalBinary: %v", n, err)
		}
		got, want := make([]byte, 200), make([]byte, 200)
		s.Read(want)
		restored.Read(got)
		if !bytes.Equal(got, want) {
			t.Fatalf("n=%d: squeeze diverged after marshaling the source twice", n)
		}
	}
}

// FuzzUnmarshalBinary checks the two properties that matter for a decoder fed
// persisted bytes from disk: it never panics, and whatever it accepts it
// re-encodes exactly. The format carries no redundancy and no
// implementation-specific normalization, so accept-then-marshal is the
// identity — if that ever stops holding, two hosts can disagree about the
// bytes for one state.
func FuzzUnmarshalBinary(f *testing.F) {
	seed := func(drive func(h *Hasher)) {
		var h Hasher
		drive(&h)
		enc, err := h.MarshalBinary()
		if err != nil {
			f.Fatalf("seed MarshalBinary: %v", err)
		}
		f.Add(enc)
	}
	seed(func(*Hasher) {})
	seed(func(h *Hasher) { h.Write([]byte("seed")) })
	seed(func(h *Hasher) { h.Write(make([]byte, rate-1)) })
	seed(func(h *Hasher) { h.Write(make([]byte, rate)) })
	seed(func(h *Hasher) { h.Write([]byte("seed")); h.Read(make([]byte, 7)) })
	seed(func(h *Hasher) { h.Write([]byte("seed")); h.Read(make([]byte, rate)) })
	f.Add([]byte(nil))
	f.Add([]byte(marshalMagic))

	f.Fuzz(func(t *testing.T, data []byte) {
		var h Hasher
		if err := h.UnmarshalBinary(data); err != nil {
			return // rejected inputs only have to not panic
		}
		enc, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary after accepting %x: %v", data, err)
		}
		if !bytes.Equal(enc, data) {
			t.Fatalf("re-encode changed the bytes:\n in: %x\nout: %x", data, enc)
		}
		// An accepted state must also be usable.
		h.Read(make([]byte, 300))
	})
}

// badState is a KeccakState that does not implement encoding.BinaryMarshaler,
// so xcAppendState takes its error path.
type badState struct{ KeccakState }

// TestAppendBinaryErrorKeepsPrefix checks the encoding.BinaryAppender contract:
// on error the input slice is returned unchanged, not dropped.
func TestAppendBinaryErrorKeepsPrefix(t *testing.T) {
	prefix := []byte("existing")
	b := append([]byte(nil), prefix...)
	got, err := xcAppendState(b, badState{})
	if err == nil {
		t.Fatal("expected an error from a state without BinaryMarshaler")
	}
	if !bytes.Equal(got, prefix) {
		t.Fatalf("prefix dropped on error: got %q, want %q", got, prefix)
	}
}

func TestUnmarshalErrors(t *testing.T) {
	var h Hasher
	h.Write([]byte("valid"))
	enc, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	flagsOff, posOff := len(marshalMagic)+200, len(marshalMagic)+201
	mutate := func(off int, v byte) []byte {
		bad := slices.Clone(enc)
		bad[off] = v
		return bad
	}
	for name, bad := range map[string][]byte{
		"nil":                         nil,
		"empty":                       {},
		"short":                       []byte("fk"),
		"bad magic":                   slices.Concat([]byte("nope"), enc[4:]),
		"magic only":                  []byte(marshalMagic),
		"truncated":                   enc[:len(enc)-1],
		"trailing":                    append(slices.Clone(enc), 0),
		"bad flags":                   mutate(flagsOff, 2),
		"pos == rate while absorbing": mutate(posOff, rate),
		"pos > rate":                  mutate(posOff, 255),
	} {
		var restored Hasher
		if err := restored.UnmarshalBinary(bad); err == nil {
			t.Fatalf("UnmarshalBinary(%s) = nil, want error", name)
		}
	}
}

// TestMarshalCanonicalBytes pins the wire format: the same logical state must
// marshal to the same bytes on every platform and implementation (the CI
// matrix runs this on native asm builds and the purego fallback). If this
// test needs updating, the format changed — bump the magic version.
func TestMarshalCanonicalBytes(t *testing.T) {
	sum := func(b []byte) string {
		d := Sum256(b)
		return hex.EncodeToString(d[:])
	}

	var h Hasher
	enc, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if got, want := hex.EncodeToString(enc[:8]), "666b310100000000"; got != want {
		t.Fatalf("zero-state prefix = %s, want %s", got, want)
	}
	if len(enc) != marshaledSize {
		t.Fatalf("len = %d, want %d", len(enc), marshaledSize)
	}
	// Digest of the full encoding is a compact cross-platform fingerprint.
	if got, want := sum(enc), "7fe3c540ad846c71039a3ea6100496db5662e71e07178342bc638b301e523b1e"; got != want {
		t.Fatalf("zero-state encoding fingerprint = %s, want %s", got, want)
	}

	h.Write([]byte("canonical wire format"))
	enc, err = h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if got, want := sum(enc), "447df4c4591c5cdca00f3b7248d5d3981d631067ca533f166ec5f01a0c019d00"; got != want {
		t.Fatalf("absorbing encoding fingerprint = %s, want %s", got, want)
	}

	h.Read(make([]byte, 50))
	enc, err = h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if got, want := sum(enc), "e0ae1516f534144ab2658af9050963ee3a65c4780d5bff5a31c58de5aa9a2fae"; got != want {
		t.Fatalf("squeezing encoding fingerprint = %s, want %s", got, want)
	}
}

// measureMarshalAllocs reports what MarshalBinary and a pre-sized AppendBinary
// cost on whichever implementation is active. The encoded slice is kept live:
// dropping it lets escape analysis fold the buffer onto the stack, and the
// measurement then reads a misleading 0.
func measureMarshalAllocs(t *testing.T) (marshal, appendBuf float64) {
	t.Helper()
	var h Hasher
	h.Write([]byte("partially absorbed input"))

	var (
		enc []byte
		err error
	)
	marshal = testing.AllocsPerRun(100, func() {
		enc, err = h.MarshalBinary()
	})
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(enc) != marshaledSize {
		t.Fatalf("MarshalBinary len = %d, want %d", len(enc), marshaledSize)
	}

	buf := make([]byte, 0, marshaledSize)
	appendBuf = testing.AllocsPerRun(100, func() {
		enc, err = h.AppendBinary(buf)
	})
	if err != nil {
		t.Fatalf("AppendBinary: %v", err)
	}
	if len(enc) != marshaledSize {
		t.Fatalf("AppendBinary len = %d, want %d", len(enc), marshaledSize)
	}
	return marshal, appendBuf
}

// Supplying a buffer must save exactly the one allocation MarshalBinary makes
// for it, on every implementation.
func TestAppendBinarySavesOneAlloc(t *testing.T) {
	marshal, appendBuf := measureMarshalAllocs(t)
	if marshal-appendBuf != 1 {
		t.Errorf("supplying a buffer saved %v allocations, want 1 (MarshalBinary %v, AppendBinary %v)",
			marshal-appendBuf, marshal, appendBuf)
	}
}

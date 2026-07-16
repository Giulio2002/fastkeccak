package keccak

import (
	"bytes"
	"testing"
)

// concat returns a+b in a fresh slice (no aliasing surprises).
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

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

	if got, want := h.Sum256(), Sum256(concat(prefix, suffixA)); got != want {
		t.Fatalf("original after clone: %x, want %x", got, want)
	}
	if got, want := c.Sum256(), Sum256(concat(prefix, suffixB)); got != want {
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
		if got, want := c.Sum256(), Sum256(concat(prefix, suffix)); got != want {
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

func TestUnmarshalErrors(t *testing.T) {
	var h Hasher
	for _, bad := range [][]byte{
		nil,
		{},
		[]byte("fk"),
		[]byte("nope"),
		[]byte("fk1?garbage"),
		[]byte(marshalMagicNative), // truncated payloads
		[]byte(marshalMagicXC),
	} {
		if err := h.UnmarshalBinary(bad); err == nil {
			t.Fatalf("UnmarshalBinary(%q) = nil, want error", bad)
		}
	}

	// A valid encoding must not be accepted after tampering with its length.
	h.Write([]byte("valid"))
	enc, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var restored Hasher
	if err := restored.UnmarshalBinary(enc[:len(enc)-1]); err == nil {
		t.Fatal("UnmarshalBinary(truncated) = nil, want error")
	}
}

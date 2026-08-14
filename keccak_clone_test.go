package keccak

import (
	"bytes"
	"testing"
)

func testHasherClone(t *testing.T) {
	t.Helper()

	var zero Hasher
	zeroClone, err := zero.Clone()
	if err != nil {
		t.Fatalf("Clone zero value: %v", err)
	}
	if got, want := zeroClone.Sum256(), Sum256(nil); got != want {
		t.Fatalf("zero-value clone digest = %x, want %x", got, want)
	}

	prefix := []byte("shared prefix")
	var original Hasher
	original.Write(prefix)

	clone, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	original.Write([]byte(" original"))
	clone.Write([]byte(" clone"))

	if got, want := original.Sum256(), Sum256(append(bytes.Clone(prefix), " original"...)); got != want {
		t.Fatalf("original digest = %x, want %x", got, want)
	}
	if got, want := clone.Sum256(), Sum256(append(bytes.Clone(prefix), " clone"...)); got != want {
		t.Fatalf("clone digest = %x, want %x", got, want)
	}

	var squeezing Hasher
	squeezing.Write(prefix)
	squeezing.Read(make([]byte, 17))
	squeezingClone, err := squeezing.Clone()
	if err != nil {
		t.Fatalf("Clone while squeezing: %v", err)
	}
	want := make([]byte, 200)
	got := make([]byte, len(want))
	squeezing.Read(want)
	squeezingClone.Read(got)
	if !bytes.Equal(got, want) {
		t.Fatal("clone did not preserve an independent squeeze position")
	}
}

func TestHasherClone(t *testing.T) {
	testHasherClone(t)
}

package keccak

import (
	"math/rand"
	"testing"
)

// FuzzWriteChunks feeds the same input through Write in randomly sized
// chunks and checks the digest matches the one-shot Sum256. The streaming
// buffer/refill logic around block boundaries is where chunking bugs hide.
func FuzzWriteChunks(f *testing.F) {
	f.Add([]byte("hello"), uint64(1))
	f.Add(make([]byte, rate), uint64(2))
	f.Add(make([]byte, rate*3+7), uint64(42))

	f.Fuzz(func(t *testing.T, data []byte, seed uint64) {
		want := Sum256(data)

		rng := rand.New(rand.NewSource(int64(seed)))
		var h Hasher
		rest := data
		for len(rest) > 0 {
			n := 1 + rng.Intn(len(rest))
			h.Write(rest[:n])
			rest = rest[n:]
		}
		if got := h.Sum256(); got != want {
			t.Fatalf("chunked write (seed %d) = %x, want %x", seed, got, want)
		}
	})
}

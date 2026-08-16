//go:build (amd64 || arm64) && !purego

package keccak

import (
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestXorAndPermute verifies the fused XOR+permute assembly entry point
// against the composition of its two parts (xorIn + keccakF1600). The fused
// path is otherwise only covered indirectly through digest comparisons.
func TestXorAndPermute(t *testing.T) {
	if !useASM {
		t.Skip("hardware acceleration unavailable on this CPU")
	}
	// The permutation has no data-dependent branches, so a divergence shows
	// on essentially any random state; more iterations add no assurance.
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 128; i++ {
		var a, b [200]byte
		var buf [rate]byte
		rng.Read(a[:])
		rng.Read(buf[:])
		b = a

		xorAndPermute(&a, &buf[0])

		xorIn(&b, buf[:])
		keccakF1600(&b)

		if a != b {
			t.Fatalf("iteration %d: xorAndPermute diverges from xorIn+keccakF1600\ngot:  %x\nwant: %x", i, a, b)
		}
	}
}

// The permutation kernel's stack-growth check is the only preemption point in
// the absorb and squeeze loops: those loops call nothing else, and assembly is
// never async-preemptible (runtime/preempt.go, isAsyncSafePoint rejects any
// FuncFlagAsm frame). Two ways to lose it:
//
//	NOSPLIT                  drops the check whatever the frame size
//	a frame under 128 bytes  makes the assembler mark a leaf NOSPLIT itself
//	                         (abi.StackSmall, obj6.go/obj7.go)
//
// Either one lets a single large Sum256 or Write hold every P in
// stop-the-world for the length of the hash.
var kernelTEXT = regexp.MustCompile(`^TEXT\s+·(keccakF1600\w*)\(SB\),\s*(?:([A-Z0-9|+]+),\s*)?\$(\d+)-\d+`)

func TestKernelKeepsStackCheck(t *testing.T) {
	files, err := filepath.Glob("*.s")
	if err != nil || len(files) == 0 {
		t.Fatalf("no assembly files found: %v", err)
	}
	found := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			m := kernelTEXT.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			found++
			name, flags, frame := m[1], m[2], m[3]
			where := f + ":" + strconv.Itoa(i+1)
			if strings.Contains(flags, "NOSPLIT") {
				t.Errorf("%s: %s is NOSPLIT, which drops the stack-growth check. "+
					"That check is the only preemption point in the block loops calling it; "+
					"without it a large Sum256 blocks every stop-the-world for the whole hash.",
					where, name)
			}
			if n, _ := strconv.Atoi(frame); n < 128 {
				t.Errorf("%s: %s has a %d-byte frame, under abi.StackSmall (128). The "+
					"assembler marks a leaf that small NOSPLIT itself, which drops the "+
					"stack-growth check. Keep the frame at 128 bytes or more.", where, name, n)
			}
		}
	}
	if found == 0 {
		t.Fatal("no keccakF1600 TEXT directive matched; was the kernel renamed?")
	}
}

func stopTheWorldHistogram() []uint64 {
	s := []metrics.Sample{{Name: "/sched/pauses/stopping/gc:seconds"}}
	metrics.Read(s)
	h := s[0].Value.Float64Histogram()
	out := make([]uint64, len(h.Counts))
	copy(out, h.Counts)
	return out
}

// maxStopTheWorldSince reports the largest stop-the-world stopping pause
// recorded since the given histogram snapshot.
func maxStopTheWorldSince(before []uint64) time.Duration {
	s := []metrics.Sample{{Name: "/sched/pauses/stopping/gc:seconds"}}
	metrics.Read(s)
	h := s[0].Value.Float64Histogram()
	var worst float64
	for i := range h.Counts {
		if h.Counts[i] > before[i] {
			worst = h.Buckets[i+1]
		}
	}
	return time.Duration(worst * float64(time.Second))
}

// pauseWhileHashing hashes buf a few times under GC pressure and reports the
// worst stop-the-world stopping pause the runtime recorded.
func pauseWhileHashing(buf []byte) time.Duration {
	var garbage []byte
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { // keep asking for a stop-the-world
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			garbage = make([]byte, 1<<20)
			runtime.GC()
			time.Sleep(time.Millisecond)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	before := stopTheWorldHistogram()
	for range 4 {
		Sum256(buf)
	}
	time.Sleep(300 * time.Millisecond) // let a blocked stop-the-world finish and be recorded

	got := maxStopTheWorldSince(before)
	close(stop)
	<-done
	_ = garbage
	return got
}

// TestSTWPauseWhileHashing measures the property the TEXT flags only imply: how
// long the runtime waits for a hashing goroutine to yield.
//
// The budget is relative to the same hash computed through the pure-Go fallback,
// which always has a preemption point, so a slow or noisy machine moves both
// numbers together and only a real regression separates them.
func TestSTWPauseWhileHashing(t *testing.T) {
	if testing.Short() {
		t.Skip("hashes 32 MiB")
	}
	if !useASM {
		t.Skip("hardware acceleration unavailable on this CPU")
	}
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("needs GOMAXPROCS >= 2 to observe a stopping pause")
	}

	buf := make([]byte, 32<<20)

	useASM = false // same call, preemptible implementation
	floor := pauseWhileHashing(buf)
	useASM = true
	got := pauseWhileHashing(buf)

	t.Logf("max GC stop-the-world stopping pause: assembly %v, pure Go %v", got, floor)

	// Healthy is microseconds either way; a missing preemption point is tens of
	// milliseconds, which is orders above both the floor and the absolute bound.
	if got > 5*time.Millisecond && got > 4*floor {
		t.Fatalf("assembly path stalls the world for %v against %v for the pure-Go path: "+
			"the block loop has no preemption point", got, floor)
	}
}

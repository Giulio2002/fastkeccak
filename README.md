# fastkeccak

Fast Keccak-256 for Go with platform-specific assembly, and zero allocations on the accelerated paths.

Go's `crypto/sha3` only exposes SHA-3 (domain `0x06`), not Keccak-256 (domain `0x01`).
`x/crypto/sha3.NewLegacyKeccak256()` provides Keccak-256 but uses a pure-Go permutation on all platforms.
This package uses assembly-optimized keccak-f[1600] permutations instead:

- **arm64 (Apple Silicon, and any CPU with the Armv8.2-A SHA3 extensions, FEAT_SHA3):** EOR3/RAX1/XAR/BCAX vector instructions — spelled `VEOR3`/`VRAX1`/`VXAR`/`VBCAX` in the Go assembler — with the block XOR fused into the permutation
- **amd64 (requires BMI1/BMI2, e.g. Intel Haswell or AMD Excavator and newer):** fully unrolled permutation using RORX/ANDN, with the block XOR fused into the permutation
- **Fallback (other platforms, older CPUs, or the `purego` build tag):** delegates to `x/crypto/sha3`, which allocates

On amd64 and non-Darwin arm64 the choice between assembly and fallback is made
at startup from CPU feature detection, so one binary can take different paths
on different hosts. On darwin/arm64 the assembly is assumed rather than probed,
and the `purego` tag or an unsupported GOARCH selects the fallback at build
time.

## Install

```bash
go get github.com/erigontech/fastkeccak
```

## Usage

```go
import keccak "github.com/erigontech/fastkeccak"

// One-shot
digest := keccak.Sum256(data)

// Streaming; the zero value is ready to use
var h keccak.Hasher
h.Write(part1)
h.Write(part2)
sum := h.Sum256()
```

## Benchmarks

`Sum256` vs `x/crypto/sha3.NewLegacyKeccak256`, medians via benchstat. The two
kernels are not equally far ahead of x/crypto, so both architectures are listed.

Apple M4 Max (arm64, Armv8.2-A SHA3 extensions), Go 1.26.5, `-count=6`:

| Size | fastkeccak | x/crypto/sha3 | Speedup |
|--------|------------------------|------------------------|---------|
| 32 B | 123.5 ns/op (259 MB/s) | 242.3 ns/op (132 MB/s) | **2.0x** |
| 128 B | 129.9 ns/op (985 MB/s) | 245.9 ns/op (521 MB/s) | **1.9x** |
| 256 B | 250.0 ns/op (1024 MB/s) | 472.1 ns/op (542 MB/s) | **1.9x** |
| 1 KB | 1.015 us/op (1009 MB/s) | 1.835 us/op (558 MB/s) | **1.8x** |
| 4 KB | 3.928 us/op (1043 MB/s) | 7.108 us/op (576 MB/s) | **1.8x** |
| 500 KB | 479.3 us/op (1068 MB/s) | 852.1 us/op (601 MB/s) | **1.8x** |

AMD EPYC 4344P (amd64, Zen 4, BMI1/BMI2), Linux, Go 1.26.6, `-count=10`.
x/crypto here reuses the digest buffer, so no allocation is charged to it:

| Size | fastkeccak | x/crypto/sha3 | Speedup |
|--------|------------------------|------------------------|---------|
| 32 B | 203.5 ns/op (157 MB/s) | 244.3 ns/op (131 MB/s) | **1.20x** |
| 128 B | 209.8 ns/op (610 MB/s) | 241.4 ns/op (530 MB/s) | **1.15x** |
| 256 B | 473.4 ns/op (541 MB/s) | 468.4 ns/op (547 MB/s) | 0.99x |
| 1 KB | 1.772 us/op (578 MB/s) | 1.815 us/op (564 MB/s) | **1.02x** |
| 4 KB | 6.186 us/op (662 MB/s) | 6.988 us/op (586 MB/s) | **1.13x** |
| 500 KB | 724.9 us/op (706 MB/s) | 845.0 us/op (606 MB/s) | **1.17x** |

The BMI2 kernel wins by a much smaller margin than the arm64 one, and at 256 B
it is a shade slower than x/crypto — reproducible across runs, not noise. Treat
the arm64 numbers as the best case rather than as what amd64 delivers.

The arm64 table above still compares `Sum256` against `x/crypto`'s `Sum(nil)`,
which charges x/crypto one 32 B allocation per call, so its speedups are
slightly flattering; it needs regenerating against the reused-buffer shape.

`Sum256` returns an array and so cannot allocate. x/crypto returns a slice, but
only allocates when the caller passes `nil` — `h.Sum(buf[:0])` is allocation
free too, on both architectures. The zero-allocation property is an API
difference, not a permanent x/crypto cost.

`go test -run=^$ -bench='FasterKeccak$|XCrypto$'` reproduces the arm64 table.
The amd64 x/crypto column came from a local variant of `BenchmarkXCrypto` ending
in `out = [32]byte(h.Sum(out[:0]))` instead of `h.Sum(nil)`; the repository has
no reused-buffer benchmark yet.

## Testing

```bash
go test ./...

# The fallback path (x/crypto/sha3) rather than the assembly
go test -tags purego ./...

# Assembly is validated against the Go declarations by vet's asmdecl.
# vet only sees the assembly for the target GOARCH, so run it per arch.
GOARCH=amd64 go vet ./...
GOARCH=arm64 go vet ./...

# Fuzz against the x/crypto reference
go test -run=^$ -fuzz FuzzSum256 -fuzztime 30s
```

CI runs the suite on real amd64 and arm64 hardware — emulation is not a
substitute, since Rosetta 2 does not report BMI2 and would silently exercise
the fallback instead of the assembly.

Authors: Giulio Rebuffo

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

AMD EPYC 4344P (amd64, Zen 4, BMI1/BMI2), Linux, Go 1.26.6, `-count=10`:

| Size | fastkeccak | x/crypto/sha3 | Speedup |
|--------|------------------------|------------------------|---------|
| 32 B | 203.2 ns/op (157 MB/s) | 256.7 ns/op (125 MB/s) | **1.26x** |
| 128 B | 209.6 ns/op (611 MB/s) | 254.9 ns/op (502 MB/s) | **1.22x** |
| 256 B | 490.4 ns/op (522 MB/s) | 483.1 ns/op (530 MB/s) | 0.99x |
| 1 KB | 1.771 us/op (578 MB/s) | 1.832 us/op (559 MB/s) | **1.03x** |
| 4 KB | 6.178 us/op (663 MB/s) | 7.013 us/op (584 MB/s) | **1.14x** |
| 500 KB | 723.4 us/op (708 MB/s) | 845.8 us/op (605 MB/s) | **1.17x** |

The BMI2 kernel wins by a much smaller margin than the arm64 one, and at 256 B
it is about 1.5% slower than x/crypto — reproducible across runs, not noise.
Treat the arm64 numbers as the best case rather than as what amd64 delivers.

Zero allocations across all sizes on both; x/crypto allocates 32 B/op (1 alloc)
for the digest. Reproduce with `go test -run=^$ -bench='FasterKeccak$|XCrypto$'`.

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

# fastkeccak

Fast Keccak-256 for Go with platform-specific assembly, and zero allocations on the accelerated paths.

Go's `crypto/sha3` only exposes SHA-3 (domain `0x06`), not Keccak-256 (domain `0x01`).
`x/crypto/sha3.NewLegacyKeccak256()` provides Keccak-256 but uses a pure-Go permutation on all platforms.
This package uses assembly-optimized keccak-f[1600] permutations instead:

- **arm64 (Apple Silicon, and any CPU with the Armv8.2-A SHA3 extensions, FEAT_SHA3):** EOR3/RAX1/XAR/BCAX vector instructions — spelled `VEOR3`/`VRAX1`/`VXAR`/`VBCAX` in the Go assembler — with the block XOR fused into the permutation
- **amd64 (requires BMI1/BMI2, e.g. Intel Haswell or AMD Excavator and newer):** fully unrolled permutation using RORX/ANDN, with the block XOR fused into the permutation
- **Fallback (other platforms, older CPUs, or the `purego` build tag):** delegates to `x/crypto/sha3`, which allocates

Which of the three runs is decided at startup from CPU feature detection, so
one binary can take different paths on different hosts.

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

`Sum256` vs `x/crypto/sha3.NewLegacyKeccak256`, Apple M4 Max (arm64, SHA3
extensions), Go 1.26.5, `-count=6`, medians via benchstat:

| Size | fastkeccak | x/crypto/sha3 | Speedup |
|--------|------------------------|------------------------|---------|
| 32 B | 123.5 ns/op (259 MB/s) | 242.3 ns/op (132 MB/s) | **2.0x** |
| 128 B | 129.9 ns/op (985 MB/s) | 245.9 ns/op (521 MB/s) | **1.9x** |
| 256 B | 250.0 ns/op (1024 MB/s) | 472.1 ns/op (542 MB/s) | **1.9x** |
| 1 KB | 1.015 us/op (1009 MB/s) | 1.835 us/op (558 MB/s) | **1.8x** |
| 4 KB | 3.928 us/op (1043 MB/s) | 7.108 us/op (576 MB/s) | **1.8x** |
| 500 KB | 479.3 us/op (1068 MB/s) | 852.1 us/op (601 MB/s) | **1.8x** |

Zero allocations across all sizes; x/crypto allocates 32 B/op (1 alloc) for
the digest. Reproduce with `go test -run=^$ -bench='FasterKeccak$|XCrypto$'`.

## Testing

```bash
go test ./...

# The fallback path (x/crypto/sha3) rather than the assembly
go test -tags purego ./...

# Assembly is validated against the Go declarations by vet's asmdecl
go vet ./...

# Fuzz against the x/crypto reference
go test -run=^$ -fuzz FuzzSum256 -fuzztime 30s
```

CI runs the suite on real amd64 and arm64 hardware — emulation is not a
substitute, since Rosetta 2 does not report BMI2 and would silently exercise
the fallback instead of the assembly.

Authors: Giulio Rebuffo

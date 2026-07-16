# fastkeccak

Fast, zero-allocation Keccak-256 for Go with platform-specific assembly.

Go's `crypto/sha3` only exposes SHA-3 (domain `0x06`), not Keccak-256 (domain `0x01`).
`x/crypto/sha3.NewLegacyKeccak256()` provides Keccak-256 but uses a pure-Go permutation on all platforms.
This package uses assembly-optimized keccak-f[1600] permutations instead:

- **arm64 (Apple Silicon, and any CPU with the Armv8.2-A SHA3 extensions, FEAT_SHA3):** EOR3/RAX1/XAR/BCAX vector instructions, with the block XOR fused into the permutation
- **amd64 (requires BMI1/BMI2, e.g. Intel Haswell or AMD Excavator and newer):** fully unrolled permutation using RORX/ANDN, with the block XOR fused into the permutation
- **Fallback (other platforms, older CPUs, or the `purego` build tag):** delegates to `x/crypto/sha3`

## Usage

```go
import keccak "github.com/erigontech/fastkeccak"

// One-shot
digest := keccak.Sum256(data)

// Streaming (zero allocs, stack-allocated)
var h keccak.Hasher
h.Write(part1)
h.Write(part2)
digest2 := h.Sum256()
```

## Benchmarks

### fastkeccak vs x/crypto/sha3

| Size | fastkeccak | x/crypto/sha3 | Speedup |
|------|--------------|----------|---------|
| 32 B | 116.4 ns/op (275 MB/s) | 244.8 ns/op (131 MB/s) | **2.1x** |
| 128 B | 121.8 ns/op (1051 MB/s) | 244.1 ns/op (524 MB/s) | **2.0x** |
| 256 B | 247.1 ns/op (1036 MB/s) | 467.7 ns/op (547 MB/s) | **1.9x** |
| 1 KB | 988.9 ns/op (1035 MB/s) | 1801 ns/op (569 MB/s) | **1.8x** |
| 4 KB | 3857 ns/op (1062 MB/s) | 6896 ns/op (594 MB/s) | **1.8x** |
| 500 KB | 485.6 us/op (1054 MB/s) | 836.8 us/op (612 MB/s) | **1.7x** |

Zero allocations across all sizes (x/crypto allocates 32 B/op).

## Testing

```bash
go test -v ./...

# Fuzz against x/crypto reference
go test -fuzz FuzzSum256 -fuzztime 30s
```

Authors: Giulio Rebuffo

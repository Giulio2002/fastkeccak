# faster_keccak

Fast, zero-allocation Keccak-256 for Go with platform-specific assembly.

Go's `crypto/sha3` only exposes SHA-3 (domain `0x06`), not Keccak-256 (domain `0x01`).
`x/crypto/sha3.NewLegacyKeccak256()` provides Keccak-256 but uses a pure-Go permutation on all platforms.
This package uses assembly-optimized keccak-f[1600] permutations instead:

- **arm64 (Apple Silicon):** NEON SHA3 extensions (EOR3, RAX1, XAR, BCAX)
- **amd64:** Unrolled permutation with complementing lanes optimization
- **Fallback:** Pure-Go implementation (or with `purego` build tag)

## Usage

```go
import "github.com/Giulio2002/faster_keccak"

// One-shot
digest := keccak.Sum256(data)

// Streaming (zero allocs, stack-allocated)
var h keccak.Hasher
h.Write(part1)
h.Write(part2)
digest := h.Sum256()
```

## Benchmarks

Apple M4, `go1.25.5 darwin/arm64`:

### faster_keccak vs x/crypto/sha3

| Size | faster_keccak | x/crypto | Speedup |
|------|--------------|----------|---------|
| 32 B | 116.4 ns/op (275 MB/s) | 244.8 ns/op (131 MB/s) | **2.1x** |
| 128 B | 121.8 ns/op (1051 MB/s) | 244.1 ns/op (524 MB/s) | **2.0x** |
| 256 B | 247.1 ns/op (1036 MB/s) | 467.7 ns/op (547 MB/s) | **1.9x** |
| 1 KB | 988.9 ns/op (1035 MB/s) | 1801 ns/op (569 MB/s) | **1.8x** |
| 4 KB | 3857 ns/op (1062 MB/s) | 6896 ns/op (594 MB/s) | **1.8x** |
| 500 KB | 485.6 us/op (1054 MB/s) | 836.8 us/op (612 MB/s) | **1.7x** |

Zero allocations across all sizes (x/crypto allocates 32 B/op).

on x86_64, nothing changes, the two are equal!

## Testing

```bash
go test -v ./...

# Fuzz against x/crypto reference
go test -fuzz FuzzSum256 -fuzztime 30s
```

# fastkeccak

Fast Keccak-256 for Go with platform-specific assembly.

Keccak-256 uses domain byte `0x01`, while SHA3-256 uses `0x06`. Go's
`crypto/sha3` package provides SHA-3, and `golang.org/x/crypto/sha3` provides
the legacy Keccak variant used by Ethereum.

fastkeccak selects an implementation for the current platform:

- **arm64:** Armv8.2-A SHA3 assembly selected by OS and CPU feature checks
- **amd64:** BMI1/BMI2 assembly when the CPU reports support
- **fallback:** `golang.org/x/crypto/sha3` on other CPUs and platforms, or
  when built with the `purego` tag

## Install

```bash
go get github.com/erigontech/fastkeccak
```

## Usage

```go
import "github.com/erigontech/fastkeccak"

// One-shot
sum := keccak.Sum256(data)

// Streaming
var h keccak.Hasher
h.Write(part1)
h.Write(part2)
streamSum := h.Sum256()
```

## Benchmarks

Performance depends on the CPU, operating system, and Go version. Run the
benchmarks on the target system:

```bash
go test -run '^$' -bench . -benchmem
```

Compare benchmarks with the same one-shot or streaming call shape. Supplying
`nil` to `hash.Hash.Sum` asks it to allocate an output slice and should not be
used to infer whether the hash implementation itself allocates.

## Testing

```bash
go test -v ./...

# Fuzz against x/crypto reference
go test -fuzz FuzzSum256 -fuzztime 30s
```

Authors: Giulio Rebuffo

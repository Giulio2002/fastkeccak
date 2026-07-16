//go:build amd64 && !purego

//go:generate go run gen_keccakf_x4_avx2.go

package keccak

import (
	"encoding/binary"

	"golang.org/x/sys/cpu"
)

func init() {
	useASM = cpu.X86.HasBMI1 && cpu.X86.HasBMI2
	// The batch kernel needs AVX2; its tail handling reuses the BMI2 kernel.
	if useASM && cpu.X86.HasAVX2 {
		batchKernel = sum256QuadBatch
	}
}

// keccakF1600BMI2 permutes state. When buf != nil, it first XORs rate bytes
// of buf into state, saving one full memory pass.
//
//go:noescape
func keccakF1600BMI2(a *[200]byte, buf *byte)

func keccakF1600(a *[200]byte) {
	keccakF1600BMI2(a, nil)
}

func xorAndPermute(state *[200]byte, buf *byte) {
	keccakF1600BMI2(state, buf)
}

// keccakF1600AVX2x4 absorbs and permutes `blocks` consecutive rate-sized
// blocks of four independent messages into four interleaved states (lane i
// of message j in st[4i+j] — one message per 64-bit lane of a 256-bit
// register row). Buffer pointers advance internally.
//
//go:noescape
func keccakF1600AVX2x4(st *[100]uint64, b0, b1, b2, b3 *byte, blocks int)

// sum256QuadBatch hashes groups of four inputs with the 4-way AVX2 kernel,
// returning how many inputs it consumed (the largest multiple-of-4 prefix).
func sum256QuadBatch(dst [][32]byte, inputs [][]byte) int {
	i := 0
	for ; i+3 < len(inputs); i += 4 {
		dst[i], dst[i+1], dst[i+2], dst[i+3] =
			sum256Quad(inputs[i], inputs[i+1], inputs[i+2], inputs[i+3])
	}
	return i
}

// sum256Quad computes the Keccak-256 digests of four independent inputs,
// sharing the permutation while all four still have full blocks left.
func sum256Quad(a, b, c, d []byte) ([32]byte, [32]byte, [32]byte, [32]byte) {
	nFull := 0
	for _, m := range [4][]byte{a, b, c, d} {
		if len(m) >= rate {
			nFull++
		}
	}
	if nFull != 0 && nFull != 4 {
		// Mixed: some messages have no full blocks, so there is little or
		// no shared work — plain hashing avoids the quad-state setup.
		return Sum256(a), Sum256(b), Sum256(c), Sum256(d)
	}

	var st [100]uint64
	if blocks := min(len(a), len(b), len(c), len(d)) / rate; blocks > 0 {
		keccakF1600AVX2x4(&st, &a[0], &b[0], &c[0], &d[0], blocks)
		a, b, c, d = a[blocks*rate:], b[blocks*rate:], c[blocks*rate:], d[blocks*rate:]
	}

	if len(a) < rate && len(b) < rate && len(c) < rate && len(d) < rate {
		// All tails fit in one padded block each: fuse the final
		// permutation too (four messages, one permutation).
		var ta, tb, tc, td [rate]byte
		padBlock(&ta, a)
		padBlock(&tb, b)
		padBlock(&tc, c)
		padBlock(&td, d)
		keccakF1600AVX2x4(&st, &ta[0], &tb[0], &tc[0], &td[0], 1)

		var da, db, dc, dd [32]byte
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(da[i*8:], st[4*i])
			binary.LittleEndian.PutUint64(db[i*8:], st[4*i+1])
			binary.LittleEndian.PutUint64(dc[i*8:], st[4*i+2])
			binary.LittleEndian.PutUint64(dd[i*8:], st[4*i+3])
		}
		return da, db, dc, dd
	}

	// Tail lengths straddle a block boundary: de-interleave and finish each
	// message individually.
	var sa, sb, sc, sd [200]byte
	for i := 0; i < 25; i++ {
		binary.LittleEndian.PutUint64(sa[i*8:], st[4*i])
		binary.LittleEndian.PutUint64(sb[i*8:], st[4*i+1])
		binary.LittleEndian.PutUint64(sc[i*8:], st[4*i+2])
		binary.LittleEndian.PutUint64(sd[i*8:], st[4*i+3])
	}
	return finishTail(&sa, a), finishTail(&sb, b), finishTail(&sc, c), finishTail(&sd, d)
}

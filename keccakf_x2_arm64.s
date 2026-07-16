// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// func keccakF1600Sha3x2(st *[50]uint64, buf0, buf1 *byte, blocks int)
//
// Absorbs and permutes `blocks` consecutive rate-sized blocks of two
// independent messages into two interleaved Keccak-1600 states: lane i of
// message 0 lives in st[2i], of message 1 in st[2i+1], i.e. the low and high
// 64-bit halves of one vector register. The shared round body (see
// keccakf_rounds_arm64.h) operates elementwise on both halves, so the second
// message rides in the otherwise-unused upper halves for free, and the state
// stays register-resident across all blocks.
TEXT ·keccakF1600Sha3x2(SB), NOSPLIT, $0-32
	MOVD	st+0(FP), R0
	MOVD	buf0+8(FP), R3
	MOVD	buf1+16(FP), R4
	MOVD	blocks+24(FP), R5

	// Load interleaved state: one 128-bit register per lane pair.
	VLD1.P	64(R0), [V0.D2, V1.D2, V2.D2, V3.D2]
	VLD1.P	64(R0), [V4.D2, V5.D2, V6.D2, V7.D2]
	VLD1.P	64(R0), [V8.D2, V9.D2, V10.D2, V11.D2]
	VLD1.P	64(R0), [V12.D2, V13.D2, V14.D2, V15.D2]
	VLD1.P	64(R0), [V16.D2, V17.D2, V18.D2, V19.D2]
	VLD1.P	64(R0), [V20.D2, V21.D2, V22.D2, V23.D2]
	VLD1	(R0), [V24.D2]
	SUB	$384, R0, R0

	// Defensive: blocks <= 0 stores the state back unchanged instead of
	// underflowing the do-while counter (callers always pass blocks >= 1).
	CMP	$1, R5
	BLT	store

block_loop:
	MOVD	$round_consts<>(SB), R1
	MOVD	$24, R2 // counter for loop

	// XOR one rate-sized block of each message into its half of the state.
	// Per iteration: V25 = buf0 lanes (i, i+1), V26 = buf1 lanes (i, i+1);
	// ZIP1/ZIP2 regroup them into per-lane (msg0, msg1) pairs.
	VLD1.P	16(R3), [V25.D2]
	VLD1.P	16(R4), [V26.D2]
	VZIP1	V26.D2, V25.D2, V27.D2
	VZIP2	V26.D2, V25.D2, V28.D2
	VEOR	V27.B16, V0.B16, V0.B16
	VEOR	V28.B16, V1.B16, V1.B16

	VLD1.P	16(R3), [V25.D2]
	VLD1.P	16(R4), [V26.D2]
	VZIP1	V26.D2, V25.D2, V27.D2
	VZIP2	V26.D2, V25.D2, V28.D2
	VEOR	V27.B16, V2.B16, V2.B16
	VEOR	V28.B16, V3.B16, V3.B16

	VLD1.P	16(R3), [V25.D2]
	VLD1.P	16(R4), [V26.D2]
	VZIP1	V26.D2, V25.D2, V27.D2
	VZIP2	V26.D2, V25.D2, V28.D2
	VEOR	V27.B16, V4.B16, V4.B16
	VEOR	V28.B16, V5.B16, V5.B16

	VLD1.P	16(R3), [V25.D2]
	VLD1.P	16(R4), [V26.D2]
	VZIP1	V26.D2, V25.D2, V27.D2
	VZIP2	V26.D2, V25.D2, V28.D2
	VEOR	V27.B16, V6.B16, V6.B16
	VEOR	V28.B16, V7.B16, V7.B16

	VLD1.P	16(R3), [V25.D2]
	VLD1.P	16(R4), [V26.D2]
	VZIP1	V26.D2, V25.D2, V27.D2
	VZIP2	V26.D2, V25.D2, V28.D2
	VEOR	V27.B16, V8.B16, V8.B16
	VEOR	V28.B16, V9.B16, V9.B16

	VLD1.P	16(R3), [V25.D2]
	VLD1.P	16(R4), [V26.D2]
	VZIP1	V26.D2, V25.D2, V27.D2
	VZIP2	V26.D2, V25.D2, V28.D2
	VEOR	V27.B16, V10.B16, V10.B16
	VEOR	V28.B16, V11.B16, V11.B16

	VLD1.P	16(R3), [V25.D2]
	VLD1.P	16(R4), [V26.D2]
	VZIP1	V26.D2, V25.D2, V27.D2
	VZIP2	V26.D2, V25.D2, V28.D2
	VEOR	V27.B16, V12.B16, V12.B16
	VEOR	V28.B16, V13.B16, V13.B16

	VLD1.P	16(R3), [V25.D2]
	VLD1.P	16(R4), [V26.D2]
	VZIP1	V26.D2, V25.D2, V27.D2
	VZIP2	V26.D2, V25.D2, V28.D2
	VEOR	V27.B16, V14.B16, V14.B16
	VEOR	V28.B16, V15.B16, V15.B16

	// Lane 16: last data lane (8 bytes of each buf at offset 128).
	// Post-increment so R3/R4 point at the next block for the loop.
	VLD1.P	8(R3), [V25.D1]
	VLD1.P	8(R4), [V26.D1]
	VZIP1	V26.D2, V25.D2, V27.D2
	VEOR	V27.B16, V16.B16, V16.B16

#include "keccakf_rounds_arm64.h"

	SUB	$1, R5, R5
	CBNZ	R5, block_loop

store:
	VST1.P	[V0.D2, V1.D2, V2.D2, V3.D2], 64(R0)
	VST1.P	[V4.D2, V5.D2, V6.D2, V7.D2], 64(R0)
	VST1.P	[V8.D2, V9.D2, V10.D2, V11.D2], 64(R0)
	VST1.P	[V12.D2, V13.D2, V14.D2, V15.D2], 64(R0)
	VST1.P	[V16.D2, V17.D2, V18.D2, V19.D2], 64(R0)
	VST1.P	[V20.D2, V21.D2, V22.D2, V23.D2], 64(R0)
	VST1	[V24.D2], (R0)

	RET

#include "keccakf_rc_arm64.h"

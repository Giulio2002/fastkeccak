// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"

// func keccakF1600Sha3(a *[200]byte, buf *byte)
// When buf != nil, XORs rate bytes into state before permuting.
// When buf == nil, just permutes.
TEXT ·keccakF1600Sha3(SB), $200-16
	MOVD	a+0(FP), R0
	MOVD	buf+8(FP), R3
	MOVD	$round_consts<>(SB), R1
	MOVD	$24, R2 // counter for loop

	CBZ	R3, load_state

	// XOR path: load state and XOR with buf (17 lanes = 136 bytes)
	VLD1.P	16(R0), [V0.D1, V1.D1]
	VLD1.P	16(R3), [V25.D1, V26.D1]
	VEOR	V25.B16, V0.B16, V0.B16
	VEOR	V26.B16, V1.B16, V1.B16

	VLD1.P	16(R0), [V2.D1, V3.D1]
	VLD1.P	16(R3), [V25.D1, V26.D1]
	VEOR	V25.B16, V2.B16, V2.B16
	VEOR	V26.B16, V3.B16, V3.B16

	VLD1.P	16(R0), [V4.D1, V5.D1]
	VLD1.P	16(R3), [V25.D1, V26.D1]
	VEOR	V25.B16, V4.B16, V4.B16
	VEOR	V26.B16, V5.B16, V5.B16

	VLD1.P	16(R0), [V6.D1, V7.D1]
	VLD1.P	16(R3), [V25.D1, V26.D1]
	VEOR	V25.B16, V6.B16, V6.B16
	VEOR	V26.B16, V7.B16, V7.B16

	VLD1.P	16(R0), [V8.D1, V9.D1]
	VLD1.P	16(R3), [V25.D1, V26.D1]
	VEOR	V25.B16, V8.B16, V8.B16
	VEOR	V26.B16, V9.B16, V9.B16

	VLD1.P	16(R0), [V10.D1, V11.D1]
	VLD1.P	16(R3), [V25.D1, V26.D1]
	VEOR	V25.B16, V10.B16, V10.B16
	VEOR	V26.B16, V11.B16, V11.B16

	VLD1.P	16(R0), [V12.D1, V13.D1]
	VLD1.P	16(R3), [V25.D1, V26.D1]
	VEOR	V25.B16, V12.B16, V12.B16
	VEOR	V26.B16, V13.B16, V13.B16

	VLD1.P	16(R0), [V14.D1, V15.D1]
	VLD1.P	16(R3), [V25.D1, V26.D1]
	VEOR	V25.B16, V14.B16, V14.B16
	VEOR	V26.B16, V15.B16, V15.B16

	// Lane 16: last data lane (8 bytes at buf offset 128)
	VLD1.P	16(R0), [V16.D1, V17.D1]
	VLD1	(R3), [V25.D1]
	VEOR	V25.B16, V16.B16, V16.B16

	// Remaining state lanes 18-24 (no data to XOR)
	VLD1.P	16(R0), [V18.D1, V19.D1]
	VLD1.P	16(R0), [V20.D1, V21.D1]
	VLD1.P	16(R0), [V22.D1, V23.D1]
	VLD1	(R0), [V24.D1]

	SUB	$192, R0, R0
	B	rounds

load_state:
	VLD1.P	16(R0), [V0.D1, V1.D1]
	VLD1.P	16(R0), [V2.D1, V3.D1]
	VLD1.P	16(R0), [V4.D1, V5.D1]
	VLD1.P	16(R0), [V6.D1, V7.D1]
	VLD1.P	16(R0), [V8.D1, V9.D1]
	VLD1.P	16(R0), [V10.D1, V11.D1]
	VLD1.P	16(R0), [V12.D1, V13.D1]
	VLD1.P	16(R0), [V14.D1, V15.D1]
	VLD1.P	16(R0), [V16.D1, V17.D1]
	VLD1.P	16(R0), [V18.D1, V19.D1]
	VLD1.P	16(R0), [V20.D1, V21.D1]
	VLD1.P	16(R0), [V22.D1, V23.D1]
	VLD1	(R0), [V24.D1]

	SUB	$192, R0, R0

#include "keccakf_rounds_arm64.h"

	VST1.P	[V0.D1, V1.D1], 16(R0)
	VST1.P	[V2.D1, V3.D1], 16(R0)
	VST1.P	[V4.D1, V5.D1], 16(R0)
	VST1.P	[V6.D1, V7.D1], 16(R0)
	VST1.P	[V8.D1, V9.D1], 16(R0)
	VST1.P	[V10.D1, V11.D1], 16(R0)
	VST1.P	[V12.D1, V13.D1], 16(R0)
	VST1.P	[V14.D1, V15.D1], 16(R0)
	VST1.P	[V16.D1, V17.D1], 16(R0)
	VST1.P	[V18.D1, V19.D1], 16(R0)
	VST1.P	[V20.D1, V21.D1], 16(R0)
	VST1.P	[V22.D1, V23.D1], 16(R0)
	VST1	[V24.D1], (R0)

	RET

#include "keccakf_rc_arm64.h"

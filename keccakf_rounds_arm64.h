// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The 24-round Keccak-f[1600] body shared by the single-message kernel
// (keccakf_arm64.s) and the two-message interleaved kernel
// (keccakf_x2_arm64.s). Every instruction operates elementwise on both
// 64-bit halves of the vector registers, so the same text permutes one state
// held in the low halves, or two independent states held in the low/high
// halves.
//
// Contract at #include site:
//   V0-V24  state lane(s) 0-24
//   R1      &round_consts<> (advances through the table)
//   R2      24 (round counter, reaches 0)
// Clobbers V25-V31, R1, R2. Include keccakf_rc_arm64.h at file scope for the
// round_consts<> table.

rounds:
	// theta
	VEOR3	 V20.B16, V15.B16, V10.B16, V25.B16
	VEOR3	 V21.B16, V16.B16, V11.B16, V26.B16
	VEOR3	 V22.B16, V17.B16, V12.B16, V27.B16
	VEOR3	 V23.B16, V18.B16, V13.B16, V28.B16
	VEOR3	 V24.B16, V19.B16, V14.B16, V29.B16
	VEOR3	 V25.B16, V5.B16, V0.B16, V25.B16
	VEOR3	 V26.B16, V6.B16, V1.B16, V26.B16
	VEOR3	 V27.B16, V7.B16, V2.B16, V27.B16
	VEOR3	 V28.B16, V8.B16, V3.B16, V28.B16
	VEOR3	 V29.B16, V9.B16, V4.B16, V29.B16

	VRAX1	V27.D2, V25.D2, V30.D2
	VRAX1	V28.D2, V26.D2, V31.D2
	VRAX1	V29.D2, V27.D2, V27.D2
	VRAX1	V25.D2, V28.D2, V28.D2
	VRAX1	V26.D2, V29.D2, V29.D2

	// theta and rho and Pi
	VEOR	V29.B16, V0.B16, V0.B16

	VXAR	$63, V30.D2, V1.D2, V25.D2

	VXAR	$20, V30.D2, V6.D2, V1.D2
	VXAR	$44, V28.D2, V9.D2, V6.D2
	VXAR	$3, V31.D2, V22.D2, V9.D2
	VXAR	$25, V28.D2, V14.D2, V22.D2
	VXAR	$46, V29.D2, V20.D2, V14.D2

	VXAR	$2, V31.D2, V2.D2, V26.D2

	VXAR	$21, V31.D2, V12.D2, V2.D2
	VXAR	$39, V27.D2, V13.D2, V12.D2
	VXAR	$56, V28.D2, V19.D2, V13.D2
	VXAR	$8, V27.D2, V23.D2, V19.D2
	VXAR	$23, V29.D2, V15.D2, V23.D2

	VXAR	$37, V28.D2, V4.D2, V15.D2

	VXAR	$50, V28.D2, V24.D2, V28.D2
	VXAR	$62, V30.D2, V21.D2, V24.D2
	VXAR	$9, V27.D2, V8.D2, V8.D2
	VXAR	$19, V30.D2, V16.D2, V4.D2
	VXAR	$28, V29.D2, V5.D2, V16.D2

	VXAR	$36, V27.D2, V3.D2, V5.D2

	VXAR	$43, V27.D2, V18.D2, V27.D2
	VXAR	$49, V31.D2, V17.D2, V3.D2
	VXAR	$54, V30.D2, V11.D2, V30.D2
	VXAR	$58, V31.D2, V7.D2, V31.D2
	VXAR	$61, V29.D2, V10.D2, V29.D2

	// chi and iota
	VBCAX	V8.B16, V22.B16, V26.B16, V20.B16
	VBCAX	V22.B16, V23.B16, V8.B16, V21.B16
	VBCAX	V23.B16, V24.B16, V22.B16, V22.B16
	VBCAX	V24.B16, V26.B16, V23.B16, V23.B16
	VBCAX	V26.B16, V8.B16, V24.B16, V24.B16

	VLD1R.P	8(R1), [V26.D2]

	VBCAX	V3.B16, V19.B16, V30.B16, V17.B16
	VBCAX	V19.B16, V15.B16, V3.B16, V18.B16
	VBCAX	V15.B16, V16.B16, V19.B16, V19.B16
	VBCAX	V16.B16, V30.B16, V15.B16, V15.B16
	VBCAX	V30.B16, V3.B16, V16.B16, V16.B16

	VBCAX	V31.B16, V12.B16, V25.B16, V10.B16
	VBCAX	V12.B16, V13.B16, V31.B16, V11.B16
	VBCAX	V13.B16, V14.B16, V12.B16, V12.B16
	VBCAX	V14.B16, V25.B16, V13.B16, V13.B16
	VBCAX	V25.B16, V31.B16, V14.B16, V14.B16

	VBCAX	V4.B16, V9.B16, V29.B16, V7.B16
	VBCAX	V9.B16, V5.B16, V4.B16, V8.B16
	VBCAX	V5.B16, V6.B16, V9.B16, V9.B16
	VBCAX	V6.B16, V29.B16, V5.B16, V5.B16
	VBCAX	V29.B16, V4.B16, V6.B16, V6.B16

	VBCAX	V28.B16, V0.B16, V27.B16, V3.B16
	VBCAX	V0.B16, V1.B16, V28.B16, V4.B16

	VBCAX	V1.B16, V2.B16, V0.B16, V0.B16  // iota (chi part)

	VBCAX	V2.B16, V27.B16, V1.B16, V1.B16
	VBCAX	V27.B16, V28.B16, V2.B16, V2.B16

	VEOR	V26.B16, V0.B16, V0.B16 // iota

	SUB		$1, R2, R2
	CBNZ	R2, rounds

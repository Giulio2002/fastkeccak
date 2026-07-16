// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Keccak-f[1600] iota round constants, consumed by the round body in
// keccakf_rounds_arm64.h. round_consts<> is file-static, so each including
// .s file gets its own identical copy — the source of truth stays here.

DATA	round_consts<>+0x00(SB)/8, $0x0000000000000001
DATA	round_consts<>+0x08(SB)/8, $0x0000000000008082
DATA	round_consts<>+0x10(SB)/8, $0x800000000000808a
DATA	round_consts<>+0x18(SB)/8, $0x8000000080008000
DATA	round_consts<>+0x20(SB)/8, $0x000000000000808b
DATA	round_consts<>+0x28(SB)/8, $0x0000000080000001
DATA	round_consts<>+0x30(SB)/8, $0x8000000080008081
DATA	round_consts<>+0x38(SB)/8, $0x8000000000008009
DATA	round_consts<>+0x40(SB)/8, $0x000000000000008a
DATA	round_consts<>+0x48(SB)/8, $0x0000000000000088
DATA	round_consts<>+0x50(SB)/8, $0x0000000080008009
DATA	round_consts<>+0x58(SB)/8, $0x000000008000000a
DATA	round_consts<>+0x60(SB)/8, $0x000000008000808b
DATA	round_consts<>+0x68(SB)/8, $0x800000000000008b
DATA	round_consts<>+0x70(SB)/8, $0x8000000000008089
DATA	round_consts<>+0x78(SB)/8, $0x8000000000008003
DATA	round_consts<>+0x80(SB)/8, $0x8000000000008002
DATA	round_consts<>+0x88(SB)/8, $0x8000000000000080
DATA	round_consts<>+0x90(SB)/8, $0x000000000000800a
DATA	round_consts<>+0x98(SB)/8, $0x800000008000000a
DATA	round_consts<>+0xA0(SB)/8, $0x8000000080008081
DATA	round_consts<>+0xA8(SB)/8, $0x8000000000008080
DATA	round_consts<>+0xB0(SB)/8, $0x0000000080000001
DATA	round_consts<>+0xB8(SB)/8, $0x8000000080008008
GLOBL	round_consts<>(SB), NOPTR|RODATA, $192

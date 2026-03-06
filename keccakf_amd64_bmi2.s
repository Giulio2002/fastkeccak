//go:build !purego

#include "textflag.h"

// BMI2-optimized Keccak-f[1600] permutation.
// Uses RORXQ (non-destructive 3-operand rotate) for rho/theta steps
// and ANDNQ (BMI1, always present with BMI2) for the chi step.
//
// func keccakF1600(a *[200]byte)
TEXT ·keccakF1600(SB), $200-8
	MOVQ a+0(FP), DI
	LEAQ round_consts_bmi2<>(SB), R15
	MOVQ $24, R14

round_loop:
	// === Theta: compute column parities C[0..4] ===
	// C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20]
	MOVQ 0(DI), AX
	XORQ 40(DI), AX
	XORQ 80(DI), AX
	XORQ 120(DI), AX
	XORQ 160(DI), AX       // C0

	MOVQ 8(DI), BX
	XORQ 48(DI), BX
	XORQ 88(DI), BX
	XORQ 128(DI), BX
	XORQ 168(DI), BX       // C1

	MOVQ 16(DI), CX
	XORQ 56(DI), CX
	XORQ 96(DI), CX
	XORQ 136(DI), CX
	XORQ 176(DI), CX       // C2

	MOVQ 24(DI), DX
	XORQ 64(DI), DX
	XORQ 104(DI), DX
	XORQ 144(DI), DX
	XORQ 184(DI), DX       // C3

	MOVQ 32(DI), SI
	XORQ 72(DI), SI
	XORQ 112(DI), SI
	XORQ 152(DI), SI
	XORQ 192(DI), SI       // C4

	// === Theta: compute D[0..4] using RORXQ ===
	// D[x] = C[(x+4)%5] ^ ROL(C[(x+1)%5], 1)
	// ROL(v, 1) = ROR(v, 63)
	RORXQ $63, BX, R8
	XORQ  SI, R8           // D0 = R8

	RORXQ $63, CX, R9
	XORQ  AX, R9           // D1 = R9

	RORXQ $63, DX, R10
	XORQ  BX, R10          // D2 = R10

	RORXQ $63, SI, R11
	XORQ  CX, R11          // D3 = R11

	RORXQ $63, AX, R12
	XORQ  DX, R12          // D4 = R12

	// === Theta + Rho + Pi (combined) ===
	// For each source lane s: load A[s], XOR D[s%5], rotate, store to B[pi(s)] on stack.
	// D0=R8, D1=R9, D2=R10, D3=R11, D4=R12

	// s=0 -> B[0], D0, no rotation
	MOVQ  0(DI), AX
	XORQ  R8, AX
	MOVQ  AX, 0(SP)

	// s=1 -> B[10], D1, ROL 1 = ROR 63
	MOVQ  8(DI), AX
	XORQ  R9, AX
	RORXQ $63, AX, AX
	MOVQ  AX, 80(SP)

	// s=2 -> B[20], D2, ROL 62 = ROR 2
	MOVQ  16(DI), AX
	XORQ  R10, AX
	RORXQ $2, AX, AX
	MOVQ  AX, 160(SP)

	// s=3 -> B[5], D3, ROL 28 = ROR 36
	MOVQ  24(DI), AX
	XORQ  R11, AX
	RORXQ $36, AX, AX
	MOVQ  AX, 40(SP)

	// s=4 -> B[15], D4, ROL 27 = ROR 37
	MOVQ  32(DI), AX
	XORQ  R12, AX
	RORXQ $37, AX, AX
	MOVQ  AX, 120(SP)

	// s=5 -> B[16], D0, ROL 36 = ROR 28
	MOVQ  40(DI), AX
	XORQ  R8, AX
	RORXQ $28, AX, AX
	MOVQ  AX, 128(SP)

	// s=6 -> B[1], D1, ROL 44 = ROR 20
	MOVQ  48(DI), AX
	XORQ  R9, AX
	RORXQ $20, AX, AX
	MOVQ  AX, 8(SP)

	// s=7 -> B[11], D2, ROL 6 = ROR 58
	MOVQ  56(DI), AX
	XORQ  R10, AX
	RORXQ $58, AX, AX
	MOVQ  AX, 88(SP)

	// s=8 -> B[21], D3, ROL 55 = ROR 9
	MOVQ  64(DI), AX
	XORQ  R11, AX
	RORXQ $9, AX, AX
	MOVQ  AX, 168(SP)

	// s=9 -> B[6], D4, ROL 20 = ROR 44
	MOVQ  72(DI), AX
	XORQ  R12, AX
	RORXQ $44, AX, AX
	MOVQ  AX, 48(SP)

	// s=10 -> B[7], D0, ROL 3 = ROR 61
	MOVQ  80(DI), AX
	XORQ  R8, AX
	RORXQ $61, AX, AX
	MOVQ  AX, 56(SP)

	// s=11 -> B[17], D1, ROL 10 = ROR 54
	MOVQ  88(DI), AX
	XORQ  R9, AX
	RORXQ $54, AX, AX
	MOVQ  AX, 136(SP)

	// s=12 -> B[2], D2, ROL 43 = ROR 21
	MOVQ  96(DI), AX
	XORQ  R10, AX
	RORXQ $21, AX, AX
	MOVQ  AX, 16(SP)

	// s=13 -> B[12], D3, ROL 25 = ROR 39
	MOVQ  104(DI), AX
	XORQ  R11, AX
	RORXQ $39, AX, AX
	MOVQ  AX, 96(SP)

	// s=14 -> B[22], D4, ROL 39 = ROR 25
	MOVQ  112(DI), AX
	XORQ  R12, AX
	RORXQ $25, AX, AX
	MOVQ  AX, 176(SP)

	// s=15 -> B[23], D0, ROL 41 = ROR 23
	MOVQ  120(DI), AX
	XORQ  R8, AX
	RORXQ $23, AX, AX
	MOVQ  AX, 184(SP)

	// s=16 -> B[8], D1, ROL 45 = ROR 19
	MOVQ  128(DI), AX
	XORQ  R9, AX
	RORXQ $19, AX, AX
	MOVQ  AX, 64(SP)

	// s=17 -> B[18], D2, ROL 15 = ROR 49
	MOVQ  136(DI), AX
	XORQ  R10, AX
	RORXQ $49, AX, AX
	MOVQ  AX, 144(SP)

	// s=18 -> B[3], D3, ROL 21 = ROR 43
	MOVQ  144(DI), AX
	XORQ  R11, AX
	RORXQ $43, AX, AX
	MOVQ  AX, 24(SP)

	// s=19 -> B[13], D4, ROL 8 = ROR 56
	MOVQ  152(DI), AX
	XORQ  R12, AX
	RORXQ $56, AX, AX
	MOVQ  AX, 104(SP)

	// s=20 -> B[14], D0, ROL 18 = ROR 46
	MOVQ  160(DI), AX
	XORQ  R8, AX
	RORXQ $46, AX, AX
	MOVQ  AX, 112(SP)

	// s=21 -> B[24], D1, ROL 2 = ROR 62
	MOVQ  168(DI), AX
	XORQ  R9, AX
	RORXQ $62, AX, AX
	MOVQ  AX, 192(SP)

	// s=22 -> B[9], D2, ROL 61 = ROR 3
	MOVQ  176(DI), AX
	XORQ  R10, AX
	RORXQ $3, AX, AX
	MOVQ  AX, 72(SP)

	// s=23 -> B[19], D3, ROL 56 = ROR 8
	MOVQ  184(DI), AX
	XORQ  R11, AX
	RORXQ $8, AX, AX
	MOVQ  AX, 152(SP)

	// s=24 -> B[4], D4, ROL 14 = ROR 50
	MOVQ  192(DI), AX
	XORQ  R12, AX
	RORXQ $50, AX, AX
	MOVQ  AX, 32(SP)

	// === Chi (using ANDNQ) + Iota ===
	// Chi: A'[x+5y] = B[x+5y] ^ (~B[(x+1)%5+5y] & B[(x+2)%5+5y])
	// ANDNQ src, mask, dst => dst = ~mask & src

	// Row 0: B[0..4] -> A[0..4]
	MOVQ  0(SP), AX
	MOVQ  8(SP), BX
	MOVQ  16(SP), CX
	MOVQ  24(SP), DX
	MOVQ  32(SP), SI

	ANDNQ CX, BX, R8       // ~B[1] & B[2]
	XORQ  AX, R8           // B[0] ^ (~B[1] & B[2])
	XORQ  0(R15), R8       // iota: XOR round constant
	MOVQ  R8, 0(DI)

	ANDNQ DX, CX, R8       // ~B[2] & B[3]
	XORQ  BX, R8
	MOVQ  R8, 8(DI)

	ANDNQ SI, DX, R8       // ~B[3] & B[4]
	XORQ  CX, R8
	MOVQ  R8, 16(DI)

	ANDNQ AX, SI, R8       // ~B[4] & B[0]
	XORQ  DX, R8
	MOVQ  R8, 24(DI)

	ANDNQ BX, AX, R8       // ~B[0] & B[1]
	XORQ  SI, R8
	MOVQ  R8, 32(DI)

	// Row 1: B[5..9] -> A[5..9]
	MOVQ  40(SP), AX
	MOVQ  48(SP), BX
	MOVQ  56(SP), CX
	MOVQ  64(SP), DX
	MOVQ  72(SP), SI

	ANDNQ CX, BX, R8
	XORQ  AX, R8
	MOVQ  R8, 40(DI)

	ANDNQ DX, CX, R8
	XORQ  BX, R8
	MOVQ  R8, 48(DI)

	ANDNQ SI, DX, R8
	XORQ  CX, R8
	MOVQ  R8, 56(DI)

	ANDNQ AX, SI, R8
	XORQ  DX, R8
	MOVQ  R8, 64(DI)

	ANDNQ BX, AX, R8
	XORQ  SI, R8
	MOVQ  R8, 72(DI)

	// Row 2: B[10..14] -> A[10..14]
	MOVQ  80(SP), AX
	MOVQ  88(SP), BX
	MOVQ  96(SP), CX
	MOVQ  104(SP), DX
	MOVQ  112(SP), SI

	ANDNQ CX, BX, R8
	XORQ  AX, R8
	MOVQ  R8, 80(DI)

	ANDNQ DX, CX, R8
	XORQ  BX, R8
	MOVQ  R8, 88(DI)

	ANDNQ SI, DX, R8
	XORQ  CX, R8
	MOVQ  R8, 96(DI)

	ANDNQ AX, SI, R8
	XORQ  DX, R8
	MOVQ  R8, 104(DI)

	ANDNQ BX, AX, R8
	XORQ  SI, R8
	MOVQ  R8, 112(DI)

	// Row 3: B[15..19] -> A[15..19]
	MOVQ  120(SP), AX
	MOVQ  128(SP), BX
	MOVQ  136(SP), CX
	MOVQ  144(SP), DX
	MOVQ  152(SP), SI

	ANDNQ CX, BX, R8
	XORQ  AX, R8
	MOVQ  R8, 120(DI)

	ANDNQ DX, CX, R8
	XORQ  BX, R8
	MOVQ  R8, 128(DI)

	ANDNQ SI, DX, R8
	XORQ  CX, R8
	MOVQ  R8, 136(DI)

	ANDNQ AX, SI, R8
	XORQ  DX, R8
	MOVQ  R8, 144(DI)

	ANDNQ BX, AX, R8
	XORQ  SI, R8
	MOVQ  R8, 152(DI)

	// Row 4: B[20..24] -> A[20..24]
	MOVQ  160(SP), AX
	MOVQ  168(SP), BX
	MOVQ  176(SP), CX
	MOVQ  184(SP), DX
	MOVQ  192(SP), SI

	ANDNQ CX, BX, R8
	XORQ  AX, R8
	MOVQ  R8, 160(DI)

	ANDNQ DX, CX, R8
	XORQ  BX, R8
	MOVQ  R8, 168(DI)

	ANDNQ SI, DX, R8
	XORQ  CX, R8
	MOVQ  R8, 176(DI)

	ANDNQ AX, SI, R8
	XORQ  DX, R8
	MOVQ  R8, 184(DI)

	ANDNQ BX, AX, R8
	XORQ  SI, R8
	MOVQ  R8, 192(DI)

	// Advance round constant pointer and loop
	ADDQ $8, R15
	SUBQ $1, R14
	JNZ  round_loop

	RET

// Round constants for Keccak-f[1600]
DATA round_consts_bmi2<>+0x00(SB)/8, $0x0000000000000001
DATA round_consts_bmi2<>+0x08(SB)/8, $0x0000000000008082
DATA round_consts_bmi2<>+0x10(SB)/8, $0x800000000000808a
DATA round_consts_bmi2<>+0x18(SB)/8, $0x8000000080008000
DATA round_consts_bmi2<>+0x20(SB)/8, $0x000000000000808b
DATA round_consts_bmi2<>+0x28(SB)/8, $0x0000000080000001
DATA round_consts_bmi2<>+0x30(SB)/8, $0x8000000080008081
DATA round_consts_bmi2<>+0x38(SB)/8, $0x8000000000008009
DATA round_consts_bmi2<>+0x40(SB)/8, $0x000000000000008a
DATA round_consts_bmi2<>+0x48(SB)/8, $0x0000000000000088
DATA round_consts_bmi2<>+0x50(SB)/8, $0x0000000080008009
DATA round_consts_bmi2<>+0x58(SB)/8, $0x000000008000000a
DATA round_consts_bmi2<>+0x60(SB)/8, $0x000000008000808b
DATA round_consts_bmi2<>+0x68(SB)/8, $0x800000000000008b
DATA round_consts_bmi2<>+0x70(SB)/8, $0x8000000000008089
DATA round_consts_bmi2<>+0x78(SB)/8, $0x8000000000008003
DATA round_consts_bmi2<>+0x80(SB)/8, $0x8000000000008002
DATA round_consts_bmi2<>+0x88(SB)/8, $0x8000000000000080
DATA round_consts_bmi2<>+0x90(SB)/8, $0x000000000000800a
DATA round_consts_bmi2<>+0x98(SB)/8, $0x800000008000000a
DATA round_consts_bmi2<>+0xA0(SB)/8, $0x8000000080008081
DATA round_consts_bmi2<>+0xA8(SB)/8, $0x8000000000008080
DATA round_consts_bmi2<>+0xB0(SB)/8, $0x0000000080000001
DATA round_consts_bmi2<>+0xB8(SB)/8, $0x8000000080008008
GLOBL round_consts_bmi2<>(SB), NOPTR|RODATA, $192

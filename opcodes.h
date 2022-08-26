#pragma once

// Reference: https://bpf.wtf/sol-0x03-isa/

// Legacy Load/Store class
#define BPF_OPC_LDDW 0x18
#define BPF_OPC_LDABSB 0x30
#define BPF_OPC_LDABSH 0x28
#define BPF_OPC_LDABSW 0x20
#define BPF_OPC_LDABSDW 0x38
#define BPF_OPC_LDINDB 0x50
#define BPF_OPC_LDINDH 0x48
#define BPF_OPC_LDINDW 0x40
#define BPF_OPC_LDINDDW 0x58

// Load/Store class
#define BPF_OPC_LDXB 0x71
#define BPF_OPC_LDXH 0x69
#define BPF_OPC_LDXW 0x61
#define BPF_OPC_LDXDW 0x79
#define BPF_OPC_STB 0x72
#define BPF_OPC_STH 0x6a
#define BPF_OPC_STW 0x62
#define BPF_OPC_STDW 0x7a
#define BPF_OPC_STXB 0x73
#define BPF_OPC_STXH 0x6b
#define BPF_OPC_STXW 0x63
#define BPF_OPC_STXDW 0x7b

// ALU64 class
#define BPF_OPC_ADD64_IMM 0x07
#define BPF_OPC_ADD64_REG 0x0f
#define BPF_OPC_SUB64_IMM 0x17
#define BPF_OPC_SUB64_REG 0x1f
#define BPF_OPC_MUL64_IMM 0x27
#define BPF_OPC_MUL64_REG 0x2f
#define BPF_OPC_DIV64_IMM 0x37
#define BPF_OPC_DIV64_REG 0x3f
#define BPF_OPC_OR64_IMM 0x47
#define BPF_OPC_OR64_REG 0x4f
#define BPF_OPC_AND64_IMM 0x57
#define BPF_OPC_AND64_REG 0x5f
#define BPF_OPC_LSH64_IMM 0x67
#define BPF_OPC_LSH64_REG 0x6f
#define BPF_OPC_RSH64_IMM 0x77
#define BPF_OPC_RSH64_REG 0x7f
#define BPF_OPC_NEG64_IMM 0x87
#define BPF_OPC_MOD64_IMM 0x97
#define BPF_OPC_MOD64_REG 0x9f
#define BPF_OPC_XOR64_IMM 0xa7
#define BPF_OPC_XOR64_REG 0xaf
#define BPF_OPC_MOV64_IMM 0xb7
#define BPF_OPC_MOV64_REG 0xbf
#define BPF_OPC_ARSH64_IMM 0xc7
#define BPF_OPC_ARSH64_REG 0xcf
#define BPF_OPC_SDIV64_IMM 0xe7
#define BPF_OPC_SDIV64_REG 0xef

// ALU32 class
#define BPF_OPC_ADD32_IMM 0x04
#define BPF_OPC_ADD32_REG 0x0c
#define BPF_OPC_SUB32_IMM 0x14
#define BPF_OPC_SUB32_REG 0x1c
#define BPF_OPC_MUL32_IMM 0x24
#define BPF_OPC_MUL32_REG 0x2c
#define BPF_OPC_DIV32_IMM 0x34
#define BPF_OPC_DIV32_REG 0x3c
#define BPF_OPC_OR32_IMM 0x44
#define BPF_OPC_OR32_REG 0x4c
#define BPF_OPC_AND32_IMM 0x54
#define BPF_OPC_AND32_REG 0x5c
#define BPF_OPC_LSH32_IMM 0x64
#define BPF_OPC_LSH32_REG 0x6c
#define BPF_OPC_RSH32_IMM 0x74
#define BPF_OPC_RSH32_REG 0x7c
#define BPF_OPC_NEG32_IMM 0x84
#define BPF_OPC_MOD32_IMM 0x94
#define BPF_OPC_MOD32_REG 0x9c
#define BPF_OPC_XOR32_IMM 0xa4
#define BPF_OPC_XOR32_REG 0xac
#define BPF_OPC_MOV32_IMM 0xb4
#define BPF_OPC_MOV32_REG 0xbc

// Endian ALU extension
#define BPF_OPC_LE 0xd4
#define BPF_OPC_BE 0xdc

// Jump class
#define BPF_OPC_JA 0x05
#define BPF_OPC_JEQ_IMM 0x15
#define BPF_OPC_JEQ_REG 0x1d
#define BPF_OPC_JGT_IMM 0x25
#define BPF_OPC_JGT_REG 0x2d
#define BPF_OPC_JGE_IMM 0x35
#define BPF_OPC_JGE_REG 0x3d
#define BPF_OPC_JSET_IMM 0x45
#define BPF_OPC_JSET_REG 0x4d
#define BPF_OPC_JNE_IMM 0x55
#define BPF_OPC_JNE_REG 0x5d
#define BPF_OPC_JSGT_IMM 0x65
#define BPF_OPC_JSGT_REG 0x6d
#define BPF_OPC_JSGE_IMM 0x75
#define BPF_OPC_JSGE_REG 0x7d
#define BPF_OPC_JLT_IMM 0xa5
#define BPF_OPC_JLT_REG 0xad
#define BPF_OPC_JLE_IMM 0xb5
#define BPF_OPC_JLE_REG 0xbd
#define BPF_OPC_JSLT_IMM 0xc5
#define BPF_OPC_JSLT_REG 0xcd
#define BPF_OPC_JSLE_IMM 0xd5
#define BPF_OPC_JSLE_REG 0xdd

// Call class
#define BPF_OPC_CALL 0x85
#define BPF_OPC_CALLX 0x8d
#define BPF_OPC_EXIT 0x95

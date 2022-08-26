#pragma once

#include <capstone/bpf.h>
#include <capstone/capstone.h>
#include "util.h"

//*****************************************************************************
// structs and types
//*****************************************************************************
enum bpf_status_t {
    STATUS_ERROR_UNSPEC = -1,
    STATUS_SUCCESS = 0,
    STATUS_UNDEF_INSTR
};

/* operand type */
enum operand_type_t { REG,
    VAL,
    LABEL };

struct decomp_request {
    uint8_t* data;
    int size;
    uint32_t addr;
    bool lil_end;
};

struct decomp_result {
    /* actual capstone handle used, in case caller wants to do extra stuff
            (this can be one of two handles opened for BE or LE disassembling) */
    csh handle;

    bpf_status_t status;

    cs_insn insn;
    cs_detail detail;
};

//*****************************************************************************
// function prototypes
//*****************************************************************************
extern "C" int ebpf_init(void);
extern "C" void ebpf_release(void);
extern "C" bool ebpf_decompose(
    const uint8_t* data, int size, uint64_t addr,
    bool lil_end, struct decomp_result* result);
extern "C" int ebpf_disassemble(
    struct decomp_result*, char* buf, size_t len);
extern "C" const char* ebpf_reg_to_str(uint32_t rid);

static inline int16_t Int16SignExtend(uint32_t x)
{
    int16_t ret;
    if (x < 0x8000) {
        ret = (int16_t)x;
    } else {
        ret = (int16_t)(0x10000 - x);
    }
    return ret;
}

static inline uint64_t JumpDest(const uint8_t* data, uint64_t addr, bool le)
{
    uint16_t raw = *(const uint16_t *)(data + 2);
    if (!le)
        raw = bswap16(raw);
    int16_t off = (int16_t)raw;
    return addr + (int64_t)off * 8 + 8;
}

static inline uint64_t JumpDest(struct cs_bpf_op* op, uint64_t addr)
{
    int64_t off = Int16SignExtend(op->off);
    return addr + (int64_t)off * 8 + 8;
}

static inline uint64_t CallDest(const uint8_t* data, uint64_t addr, bool le)
{
    uint32_t raw = *(const uint32_t *)(data + 4);
    if (!le)
        raw = bswap32(raw);
    int64_t off = (int32_t)raw;
    return addr + (int64_t)off * 8 + 8;
}

static inline uint64_t CallDest(struct cs_bpf_op* op, uint64_t addr)
{
    int64_t off = (int32_t)op->imm;
    return addr + (int64_t)off * 8 + 8;
}

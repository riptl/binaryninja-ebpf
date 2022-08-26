#pragma once

#include <capstone/bpf.h>
#include <capstone/capstone.h>

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
extern "C" int ebpf_decompose(
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

static inline uint64_t JumpDest(const uint8_t *data, uint64_t addr, bool le) {
    // TODO endianness
    int16_t off;
    if (le)
        off = (int16_t)((uint16_t)data[2] | (uint16_t)data[3] << 8);
    else
        off = (int16_t)((uint16_t)data[3] | (uint16_t)data[2] << 8);
    return addr + (int64_t)off * 8 + 8;
}

static inline uint64_t JumpDest(struct cs_bpf_op* op, uint64_t addr)
{
    uint64_t base = addr + 8;
    int16_t off = Int16SignExtend(op->off);
    int64_t offset = (int64_t)(off)*8;
    return (uint64_t)((int64_t)base + offset);
}

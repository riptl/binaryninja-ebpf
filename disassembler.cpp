#include "disassembler.h"

#include <binaryninjaapi.h>

#include <cstring>

thread_local csh handle_lil = 0;
thread_local csh handle_big = 0;

extern "C" int
ebpf_init(void)
{
    int rc = -1;

    if (handle_lil || handle_big) {
        goto beach;
    }

    if (cs_open(CS_ARCH_BPF, (cs_mode)(CS_MODE_BIG_ENDIAN | CS_MODE_BPF_EXTENDED), &handle_big) != CS_ERR_OK) {
        goto beach;
    }
    if (cs_open(CS_ARCH_BPF, (cs_mode)(CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_EXTENDED), &handle_lil) != CS_ERR_OK) {
        goto beach;
    }

    cs_option(handle_big, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle_lil, CS_OPT_DETAIL, CS_OPT_ON);

    rc = 0;
beach:
    if (rc) {
        ebpf_release();
    }
    return rc;
}

extern "C" void
ebpf_release(void)
{
    if (handle_lil) {
        cs_close(&handle_lil);
        handle_lil = 0;
    }

    if (handle_big) {
        cs_close(&handle_big);
        handle_big = 0;
    }
}

extern "C" int
ebpf_decompose(const uint8_t* data,
    int size,
    uint64_t addr,
    bool lil_end,
    struct decomp_result* res)
{
    if (!handle_lil) {
        ebpf_init();
    }

    csh handle;
    cs_insn* insn = 0;

    handle = handle_big;
    if (lil_end)
        handle = handle_lil;
    res->handle = handle;

    size_t n = cs_disasm(handle, data, size, addr, 1, &insn);
    if (n != 1) {
        goto beach;
    }

    res->status = STATUS_SUCCESS;

    memcpy(&(res->insn), insn, sizeof(cs_insn));
    memcpy(&(res->detail), insn->detail, sizeof(cs_detail));

beach:
    if (insn) {
        cs_free(insn, 1);
        insn = 0;
    }
    return 0;
}

extern "C" int
ebpf_disassemble(struct decomp_result* res, char* buf, size_t len)
{
    int rc = -1;

    if (len < strlen(res->insn.mnemonic) + strlen(res->insn.op_str) + 2) {
        goto beach;
    }

    std::strncpy(buf, res->insn.mnemonic, len);
    std::strncat(buf, " ", len);
    std::strncat(buf, res->insn.op_str, len);
    buf[len - 1] = 0;

    rc = 0;
beach:
    return rc;
}

extern "C" const char*
ebpf_reg_to_str(uint32_t rid)
{
    if (!handle_lil) {
        ebpf_init();
    }
    return cs_reg_name(handle_lil, rid);
}

#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
using namespace BinaryNinja;

#include <capstone/capstone.h>

#include "disassembler.h"

bool GetLowLevelILForPPCInstruction(Architecture* arch, LowLevelILFunction& il,
    const uint8_t* data, uint64_t addr, decomp_result* res, bool le)
{
    struct cs_insn* insn = &(res->insn);
    struct cs_detail* detail = &(res->detail);
    struct cs_bpf* bpf = &(detail->bpf);

    switch (insn->id) {
    }
}

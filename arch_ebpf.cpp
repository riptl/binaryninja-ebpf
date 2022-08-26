#include <cstring>

#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
using namespace BinaryNinja;

#include <capstone/bpf.h>
#include <capstone/capstone.h>

#include "disassembler.h"
#include "il.h"
#include "opcodes.h"

enum ElfBpfRelocationType {
    R_BPF_NONE = 0,
    R_BPF_64_64 = 1,
    R_BPF_64_ABS64 = 2,
    R_BPF_64_ABS32 = 3,
    R_BPF_64_NODYLD32 = 4,
    R_BPF_64_RELATIVE = 8,
    R_BPF_64_32 = 10,
};

static const char*
GetRelocationString(ElfBpfRelocationType relocType)
{
    static std::map<ElfBpfRelocationType, const char*> relocTable = {
        { R_BPF_NONE, "R_BPF_NONE" },
        { R_BPF_64_64, "R_BPF_64_64" },
        { R_BPF_64_ABS64, "R_BPF_64_ABS64" },
        { R_BPF_64_ABS32, "R_BPF_64_ABS32" },
        { R_BPF_64_NODYLD32, "R_BPF_64_NODYLD32" },
        { R_BPF_64_RELATIVE, "R_BPF_64_RELATIVE" },
        { R_BPF_64_32, "R_BPF_64_32" },
    };
    if (relocTable.count(relocType))
        return relocTable.at(relocType);
    return "Unknown eBPF relocation";
}

static void WriteNop(uint8_t* data)
{
    data[0] = BPF_OPC_XOR64_REG;
    memset(data + 1, 0, 7);
}

static bool IsBranch(const uint8_t* data)
{
    return (data[0] & 0x7) == 0x5;
}

static bool IsLongIns(const uint8_t* data)
{
    return data[0] == BPF_OPC_LDDW;
}

static int16_t GetOffset(uint32_t x)
{
    int16_t ret;
    if (x < 0x8000) {
        ret = (int16_t)x;
    } else {
        ret = (int16_t)(0x10000 - x);
    }
    return ret;
}

class EBPFArchitecture : public Architecture {
private:
    BNEndianness endian;

    BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size)
    {
        BNRegisterInfo result;
        result.fullWidthRegister = fullWidthReg;
        result.offset = offset;
        result.size = size;
        result.extend = NoExtend;
        return result;
    }

public:
    EBPFArchitecture(const char* name, BNEndianness endian_)
        : Architecture(name)
    {
        endian = endian_;
    }

    virtual BNEndianness GetEndianness() const override { return endian; }

    virtual size_t GetAddressSize() const override { return 8; }

    virtual size_t GetDefaultIntegerSize() const override { return 8; }

    virtual size_t GetInstructionAlignment() const override { return 8; }

    virtual size_t GetMaxInstructionLength() const override { return 16; }

    virtual bool GetInstructionInfo(const uint8_t* data,
        uint64_t addr,
        size_t maxLen,
        InstructionInfo& result) override
    {
        struct decomp_result res;
        struct cs_insn* insn = &(res.insn);

        if (maxLen < 4) {
            return false;
        }
        if (ebpf_decompose(data, 16, addr, endian == LittleEndian, &res)) {
            goto beach;
        }

        switch (insn->id) {
        case BPF_INS_JMP:
            result.AddBranch(UnconditionalBranch, JumpDest(data, addr, endian == LittleEndian));
            break;
        case BPF_INS_JEQ:
        case BPF_INS_JGT:
        case BPF_INS_JGE:
        case BPF_INS_JSET:
        case BPF_INS_JNE:
        case BPF_INS_JSGT:
        case BPF_INS_JSGE:
        case BPF_INS_JLT:
        case BPF_INS_JLE:
        case BPF_INS_JSLT:
        case BPF_INS_JSLE:
            result.AddBranch(TrueBranch, JumpDest(data, addr, endian == LittleEndian));
            result.AddBranch(FalseBranch, addr + 8);
            break;
        case BPF_INS_CALL:
            if (data[1] & 0xF0 == 0x10) {
                result.AddBranch(CallDestination, JumpDest(data, addr, endian == LittleEndian));
            } else {
                result.AddBranch(SystemCall);
            }
            break;
        case BPF_INS_CALLX:
            result.AddBranch(UnresolvedBranch);
            break;
        case BPF_INS_EXIT:
            result.AddBranch(FunctionReturn);
            break;
        }

        result.length = 8;
    beach:
        return true;
    }

    virtual bool GetInstructionText(const uint8_t* data,
        uint64_t addr,
        size_t& len,
        std::vector<InstructionTextToken>& result) override
    {
        bool rc = false;
        struct decomp_result res;
        struct cs_insn* insn = &(res.insn);
        struct cs_detail* detail = &(res.detail);
        struct cs_bpf* bpf = &(detail->bpf);
        char buf[32];
        size_t strlenMnem;

        if (len < 8) {
            goto beach;
        }
        if (ebpf_decompose(data, 16, addr, endian == LittleEndian, &res)) {
            goto beach;
        }

        /* mnemonic */
        result.emplace_back(InstructionToken, insn->mnemonic);

        /* padding between mnemonic and operands */
        memset(buf, ' ', 8);
        strlenMnem = strlen(insn->mnemonic);
        if (strlenMnem < 8)
            buf[8 - strlenMnem] = '\0';
        else
            buf[1] = '\0';
        result.emplace_back(TextToken, buf);

        if (insn->id == BPF_INS_CALL) {
            std::sprintf(buf, "%#lx", bpf->operands[0].imm);
            result.emplace_back(PossibleAddressToken, buf, bpf->operands[0].imm, 8);
            len = 8;
            return true;
        }

        /* operands */
        for (int i = 0; i < bpf->op_count; ++i) {
            struct cs_bpf_op* op = &(bpf->operands[i]);
            int16_t disp;

            switch (op->type) {
            case BPF_OP_REG:
                result.emplace_back(RegisterToken, GetRegisterName(op->reg));
                break;
            case BPF_OP_IMM:
                // TODO special snowflake insn
                std::sprintf(buf, "%#lx", op->imm);
                result.emplace_back(IntegerToken, buf, op->imm, 8);
                break;
            case BPF_OP_OFF:
                disp = GetOffset(op->off);
                if (disp >= 0) {
                    std::sprintf(buf, "+%#x", disp);
                } else {
                    std::sprintf(buf, "-%#x", -disp);
                }
                result.emplace_back(CodeRelativeAddressToken, buf, disp, 2);
                break;
            case BPF_OP_MEM:
                result.emplace_back(TextToken, "[");
                result.emplace_back(RegisterToken, GetRegisterName(op->mem.base));
                disp = GetOffset(op->mem.disp);
                if (disp >= 0) {
                    std::sprintf(buf, "+%#x", disp);
                } else {
                    std::sprintf(buf, "-%#x", -disp);
                }
                result.emplace_back(IntegerToken, buf, disp, 2);

                result.emplace_back(TextToken, "]");
                break;
            default:
                std::sprintf(buf, "unknown (%d)", op->type);
                result.emplace_back(TextToken, buf);
                break;
            }

            if (i < bpf->op_count - 1) {
                result.emplace_back(OperandSeparatorToken, ", ");
            }
        }

        rc = true;
        if (data[0] == BPF_OPC_LDDW) {
            len = 16;
        } else {
            len = 8;
        }
    beach:
        return rc;
    }

    virtual bool GetInstructionLowLevelIL(const uint8_t* data,
        uint64_t addr,
        size_t& len,
        LowLevelILFunction& il) override
    {
        bool rc = false;
        struct decomp_result res;

        if (len < 8) {
            goto beach;
        }
        if (ebpf_decompose(data, len, addr, endian == LittleEndian, &res)) {
            il.AddInstruction(il.Undefined());
            goto beach;
        }

        rc = GetLowLevelILForBPFInstruction(this, il, data, addr, &res, endian == LittleEndian);
        len = 8;

    beach:
        return rc;
    }

    virtual size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
        uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override
    {
        return 0;
    }

    virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override
    {
        return il.Unimplemented();
    }

    virtual std::string GetRegisterName(uint32_t regId) override
    {
        const char* result = ebpf_reg_to_str(regId);
        if (result == NULL) {
            result = "unknown";
        }
        return result;
    }

    virtual std::vector<uint32_t> GetAllFlags() override
    {
        return {};
    }

    virtual std::string GetFlagName(uint32_t flag) override
    {
        return "ERR_FLAG_NAME";
    }

    virtual std::vector<uint32_t> GetAllFlagWriteTypes() override
    {
        return {};
    }

    virtual std::string GetFlagWriteTypeName(uint32_t writeType) override
    {
        return "invalid";
    }

    virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override
    {
        return {};
    }

    virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override
    {
        return IL_FLAGCLASS_NONE;
    }

    virtual std::vector<uint32_t> GetAllSemanticFlagClasses() override
    {
        return {};
    }

    virtual std::string GetSemanticFlagClassName(uint32_t semClass) override
    {
        return "";
    }

    virtual std::vector<uint32_t> GetAllSemanticFlagGroups() override
    {
        return {};
    }

    virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override
    {
        return "";
    }

    virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override
    {
        return {};
    }

    virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup) override
    {
        return {};
    }

    virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass) override
    {
        return ZeroFlagRole;
    }

    virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t) override
    {
        return {};
    }

    virtual std::vector<uint32_t> GetFullWidthRegisters() override
    {
        return {
            BPF_REG_R0,
            BPF_REG_R1,
            BPF_REG_R2,
            BPF_REG_R3,
            BPF_REG_R4,
            BPF_REG_R5,
            BPF_REG_R6,
            BPF_REG_R7,
            BPF_REG_R8,
            BPF_REG_R9,
            BPF_REG_R10,
            // BPF_REG_R11
        };
    }

    virtual std::vector<uint32_t> GetAllRegisters() override
    {
        return {
            BPF_REG_R0,
            BPF_REG_R1,
            BPF_REG_R2,
            BPF_REG_R3,
            BPF_REG_R4,
            BPF_REG_R5,
            BPF_REG_R6,
            BPF_REG_R7,
            BPF_REG_R8,
            BPF_REG_R9,
            BPF_REG_R10,
            // BPF_REG_R11
        };
    }

    virtual std::vector<uint32_t> GetGlobalRegisters() override
    {
        return {};
    }

    virtual BNRegisterInfo GetRegisterInfo(uint32_t regId) override
    {
        switch (regId) {
        case BPF_REG_R0:
        case BPF_REG_R1:
        case BPF_REG_R2:
        case BPF_REG_R3:
        case BPF_REG_R4:
        case BPF_REG_R5:
        case BPF_REG_R6:
        case BPF_REG_R7:
        case BPF_REG_R8:
        case BPF_REG_R9:
        case BPF_REG_R10:
            return RegisterInfo(regId, 0, 8);
        default:
            return RegisterInfo(0, 0, 0);
        }
    }

    virtual uint32_t GetStackPointerRegister() override
    {
        // R11 but Capstone doesn't support that yet
        return 0;
    }

    virtual uint32_t GetLinkRegister() override
    {
        return 0;
    }

    /*************************************************************************/

    virtual bool CanAssemble() override
    {
        return false;
    }

    virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors) override
    {
        return false;
    }

    /*************************************************************************/

    virtual bool IsNeverBranchPatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
        return false;
    }

    virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
        if (len < 8) {
            return false;
        }
        return IsBranch(data);
    }

    virtual bool IsInvertBranchPatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
        if (len < 8) {
            return false;
        }
        return IsBranch(data) && data[0] != BPF_OPC_JSET_IMM && data[0] != BPF_OPC_JSET_REG;
    }

    virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
        return false;
    }

    virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
        return false;
    }

    /*************************************************************************/

    virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
    {
        if (len < 8) {
            return false;
        }
        if (IsLongIns(data) && len >= 16) {
            WriteNop(data + 8);
        }
        WriteNop(data);
        return true;
    }

    virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
    {
        if (len < 8 || !IsBranch(data)) {
            return false;
        }
        data[0] = BPF_OPC_JA;
        data[1] = 0;
        return true;
    }

    virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
    {
        if (len < 8 || !IsBranch(data)) {
            return false;
        }
        uint8_t new_opc = data[0] & 0x0F;
        switch (data[0] >> 4) {
        case 0x0: // JA
            WriteNop(data);
            break;
        case 0x1: // JEQ
        case 0x5: // JNE
            new_opc |= (new_opc ^ 0x40);
            break;
        case 0x2: // JGT
            new_opc |= 0xb0; // JLE
            break;
        case 0x3: // JGE
            new_opc |= 0xa0; // JLT
            break;
        case 0x6: // JSGT
            new_opc |= 0xd0; // JSLE
            break;
        case 0x7: // JSGE
            new_opc |= 0xc0; // JLT
            break;
        case 0xa: // JLT
            new_opc |= 0x70; // JSGE
            break;
        case 0xb: // JLE
            new_opc |= 0x20; // JGT
            break;
        case 0xc: // JSLT
            new_opc |= 0x70; // JSGE
            break;
        case 0xd: // JSLE
            new_opc |= 0x60; // JSGT
            break;
        default:
            // JSET cannot be inverted
            return false;
        }
        return true;
    }

    virtual bool SkipAndReturnValue(uint8_t* data,
        uint64_t addr,
        size_t len,
        uint64_t value) override
    {
        return false;
    }
};

class EBPFElfRelocationHandler : public RelocationHandler {
public:
    virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
    {
        auto info = reloc->GetInfo();
        switch (info.nativeType) {
        case R_BPF_64_64:
            break;
        case R_BPF_64_ABS64:
            break;
        case R_BPF_64_ABS32:
            break;
        case R_BPF_64_NODYLD32:
            break;
        case R_BPF_64_RELATIVE:
            break;
        case R_BPF_64_32:
            break;
        default:
            return false;
        }
        return true;
    }

    virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result) override
    {
        std::set<uint64_t> relocTypes;
        for (auto& reloc : result) {
            switch (reloc.nativeType) {
                // TODO
            }
        }
        return true;
    }
};

class SolanaCallingConvention : public CallingConvention {
public:
    SolanaCallingConvention(Architecture* arch)
        : CallingConvention(arch, "solana")
    {
    }

    virtual std::vector<uint32_t> GetIntegerArgumentRegisters() override
    {
        return {
            BPF_REG_R1,
            BPF_REG_R2,
            BPF_REG_R3,
            BPF_REG_R4,
            BPF_REG_R5,
        };
    }

    virtual std::vector<uint32_t> GetCallerSavedRegisters() override
    {
        return {};
    }

    virtual std::vector<uint32_t> GetCalleeSavedRegisters() override
    {
        return {
            BPF_REG_R6,
            BPF_REG_R7,
            BPF_REG_R8,
            BPF_REG_R9,
        };
    }

    virtual uint32_t GetIntegerReturnValueRegister() override
    {
        return PPC_REG_R0;
    }
};

extern "C" {
BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN bool CorePluginInit()
{
    Architecture* ebpf_be = new EBPFArchitecture("ebpf_be", BigEndian);
    Architecture::Register(ebpf_be);

    Architecture* ebpf_le = new EBPFArchitecture("ebpf_le", LittleEndian);
    Architecture::Register(ebpf_le);

#define EM_BPF 247
    BinaryViewType::RegisterArchitecture(
        "ELF",
        EM_BPF,
        BigEndian,
        ebpf_be);

    BinaryViewType::RegisterArchitecture(
        "ELF",
        EM_BPF,
        LittleEndian,
        ebpf_le);

    Ref<CallingConvention> conv;
    conv = new SolanaCallingConvention(ebpf_be);
    ebpf_be->RegisterCallingConvention(conv);
    ebpf_be->SetDefaultCallingConvention(conv);
    conv = new SolanaCallingConvention(ebpf_le);
    ebpf_le->RegisterCallingConvention(conv);
    ebpf_le->SetDefaultCallingConvention(conv);

    return true;
}
}

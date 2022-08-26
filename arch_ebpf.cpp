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

        if (maxLen < 8) {
            return false;
        }
        if (!ebpf_decompose(data, 16, addr, endian == LittleEndian, &res)) {
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
            result.AddBranch(CallDestination, CallDest(data, addr, endian == LittleEndian));
            break;
        case BPF_INS_SYSCALL:
            result.AddBranch(SystemCall);
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
        size_t strlenMnem;

        char buf[256];
#define FMT_I64(x)                                          \
    do {                                                    \
        if ((x) >= 0)                                       \
            std::snprintf(buf, sizeof(buf), "+%#lx", (x));  \
        else                                                \
            std::snprintf(buf, sizeof(buf), "-%#lx", -(x)); \
    } while (0)

        if (len < 8) {
            goto beach;
        }
        if (!ebpf_decompose(data, 16, addr, endian == LittleEndian, &res)) {
            goto beach;
        }

        /* mnemonic */
        result.emplace_back(InstructionToken, insn->mnemonic);

        /* padding between mnemonic and operands */
        result.emplace_back(TextToken, std::string(10 - strlen(insn->mnemonic), ' '));

        if (insn->id == BPF_INS_CALL) {
            int64_t off = (int32_t)bpf->operands[0].imm;
            off = off * 8 + 8;
            FMT_I64(off);
            result.emplace_back(PossibleAddressToken, buf, bpf->operands[0].imm, 8);
            len = 8;
            return true;
        }

        /* operands */
        for (int i = 0; i < bpf->op_count; ++i) {
            struct cs_bpf_op* op = &(bpf->operands[i]);
            int64_t val;

            switch (op->type) {
            case BPF_OP_REG:
                result.emplace_back(RegisterToken, GetRegisterName(op->reg));
                break;
            case BPF_OP_IMM:
                val = (int32_t)bpf->operands[0].imm;
                FMT_I64(val);
                result.emplace_back(IntegerToken, buf, op->imm, 8);
                break;
            case BPF_OP_OFF:
                val = Int16SignExtend(op->off);
                FMT_I64(val);
                result.emplace_back(CodeRelativeAddressToken, buf, val, 2);
                break;
            case BPF_OP_MEM:
                result.emplace_back(TextToken, "[");

                result.emplace_back(RegisterToken, GetRegisterName(op->mem.base));
                val = Int16SignExtend(op->mem.disp) * 8 + 8;
                FMT_I64(val);
                result.emplace_back(IntegerToken, buf, val, 2);

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
        if (IsLongIns(data)) {
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
        if (!ebpf_decompose(data, len, addr, endian == LittleEndian, &res)) {
            il.AddInstruction(il.Undefined());
            goto beach;
        }

        rc = GetLowLevelILForBPFInstruction(this, il, data, addr, &res, endian == LittleEndian);
        if (IsLongIns(data)) {
            len = 16;
        } else {
            len = 8;
        }

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
        return BPF_REG_R0;
    }
};

class EbpfElfRelocationHandler : public RelocationHandler {
public:
    virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
    {
        auto info = reloc->GetInfo();
        uint64_t* dest64 = (uint64_t*)dest;
        uint32_t* dest32 = (uint32_t*)dest;
        uint16_t* dest16 = (uint16_t*)dest;
        auto swap64 = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian) ? x : bswap64(x); };
        auto swap32 = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian) ? x : bswap32(x); };
        auto swap16 = [&arch](uint16_t x) { return (arch->GetEndianness() == LittleEndian) ? x : bswap16(x); };
        uint64_t target = reloc->GetTarget();
        std::vector<Ref<Section>> sections;
        uint64_t rela_src;
        switch (info.nativeType) {
        case R_BPF_64_64:
            dest32[1] = swap32((uint32_t)((target + info.addend) & 0xffffffff));
            dest32[3] = swap32((uint32_t)((target + info.addend) >> 32));
            break;
        case R_BPF_64_ABS64:
            dest64[0] = swap64(target + info.addend);
            break;
        case R_BPF_64_ABS32:
        case R_BPF_64_NODYLD32:
            dest64[0] = swap32((uint32_t)(target + info.addend));
            break;
        case R_BPF_64_RELATIVE:
            // Super weird reloc
            sections = view->GetSectionsAt(reloc->GetAddress());
            if (!sections.empty() && sections[0]->GetName() == ".text") {
                rela_src = 0;
                rela_src = swap32(dest32[1]) | ((uint64_t)(swap32(dest32[3])) << 32);
                // wtf?
                if (rela_src < 0x100000000) {
                    rela_src += 0x100000000;
                }
                dest32[1] = swap32((uint32_t)((rela_src)&0xffffffff));
                dest32[3] = swap32((uint32_t)((rela_src) >> 32));
            } else {
                // i give up
            }
            sections.clear();
            break;
        case R_BPF_64_32:
            // TODO This isn't documented as pc-rel, but BPF_INS_CALL takes pc-rel immediate
            dest32[1] = swap32((uint32_t)((target + info.addend - reloc->GetAddress()) / 8 - 1));
            break;
        }
        return true;
    }

    virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result) override
    {
        std::set<uint64_t> relocTypes;
        for (auto& reloc : result) {
            reloc.type = StandardRelocationType;
            reloc.size = 8;
            reloc.pcRelative = false;
            reloc.dataRelocation = false;
            switch (reloc.nativeType) {
            case R_BPF_NONE:
                reloc.type = IgnoredRelocation;
                break;
            case R_BPF_64_64:
                break;
            case R_BPF_64_ABS64:
                reloc.dataRelocation = true;
                break;
            case R_BPF_64_ABS32:
            case R_BPF_64_NODYLD32:
                reloc.dataRelocation = true;
                reloc.size = 4;
                break;
            case R_BPF_64_RELATIVE:
                reloc.pcRelative = true; // not really??
                break;
            case R_BPF_64_32:
                reloc.size = 4;
                break;
            default:
                reloc.type = UnhandledRelocation;
                relocTypes.insert(reloc.nativeType);
                break;
            }
        }
        for (auto& reloc : relocTypes)
            LogWarn("Unsupported ELF relocation type: %s", GetRelocationString((ElfBpfRelocationType)reloc));
        return true;
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

    ebpf_le->RegisterRelocationHandler("ELF", new EbpfElfRelocationHandler());
    ebpf_be->RegisterRelocationHandler("ELF", new EbpfElfRelocationHandler());

    return true;
}
}

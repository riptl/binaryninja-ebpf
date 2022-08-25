#include <binaryninjaapi.h>

#include "lowlevelilinstruction.h"
using namespace BinaryNinja;

#include <capstone/bpf.h>

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

class EBPFArchitecture : public Architecture {
private:
    BNEndianness endian;

public:
    EBPFArchitecture(const char* name, BNEndianness endian_)
        : Architecture(name)
    {
        endian = endian_;
    }

    virtual BNEndianness GetEndianness() const override { return endian; }

    virtual size_t GetAddressSize() const override { return 4; }

    virtual size_t GetDefaultIntegerSize() const override { return 8; }

    virtual size_t GetInstructionAlignment() const override { return 8; }

    virtual size_t GetMaxInstructionLength() const override { return 16; }

    virtual bool GetInstructionInfo(const uint8_t* data,
        uint64_t addr,
        size_t maxLen,
        InstructionInfo& result) override
    {
        return false;
    }

    virtual bool GetInstructionText(const uint8_t* data,
        uint64_t addr,
        size_t& len,
        std::vector<InstructionTextToken>& result) override
    {
        return false;
    }

    virtual bool GetInstructionLowLevelIL(const uint8_t* data,
        uint64_t addr,
        size_t& len,
        LowLevelILFunction& il) override
    {
        return false;
    }

    virtual std::string GetRegisterName(uint32_t regId) override { }

    virtual std::vector<uint32_t> GetFullWidthRegisters() override
    {
        return std::vector<uint32_t> {

        };
    }

    virtual std::vector<uint32_t> GetAllRegisters() override
    {
        std::vector<uint32_t> result = {};
        return result;
    }

    virtual std::vector<uint32_t> GetGlobalRegisters() override
    {
        return std::vector<uint32_t> {};
    }

    virtual BNRegisterInfo GetRegisterInfo(uint32_t regId) override
    {
        switch (regId) {
        }
    }

    /*************************************************************************/

    virtual bool IsNeverBranchPatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
    }

    virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
    }

    virtual bool IsInvertBranchPatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
    }

    virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
    }

    virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data,
        uint64_t addr,
        size_t len) override
    {
    }

    /*************************************************************************/

    virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override { }

    virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
    {
    }

    virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
    {
    }

    virtual bool SkipAndReturnValue(uint8_t* data,
        uint64_t addr,
        size_t len,
        uint64_t value) override
    {
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

extern "C" {
BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN bool CorePluginInit()
{
    Architecture* ebpf_be = new EBPFArchitecture("ebpf_be", BigEndian);
    Architecture* ebpf_le = new EBPFArchitecture("ebpf_le", LittleEndian);

    #define EM_BPF 247
    BinaryViewType::RegisterArchitecture(
        "ELF",
        EM_BPF,
        BigEndian,
        ebpf_be);

    BinaryViewType::RegisterArchitecture(
        "ELF",
        EM_BPF,
        BigEndian,
        ebpf_be);

    return true;
}
}

#include <capstone/bpf.h>
#include <capstone/capstone.h>

//*****************************************************************************
// structs and types
//*****************************************************************************
enum ppc_status_t {
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

    ppc_status_t status;

    cs_insn insn;
    cs_detail detail;
};

//*****************************************************************************
// function prototypes
//*****************************************************************************
extern "C" int ebpf_init(void);
extern "C" void ebpf_release(void);
extern "C" int ebpf_decompose(
    const uint8_t* data, int size, uint32_t addr,
    bool lil_end, struct decomp_result* result);
extern "C" int ebpf_disassemble(
    struct decomp_result*, char* buf, size_t len);
extern "C" const char* ebpf_reg_to_str(uint32_t rid);

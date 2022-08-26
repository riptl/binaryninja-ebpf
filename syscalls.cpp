#include "syscalls.h"

// Reference: https://bpf.wtf/sol-0x04-syscalls/

std::map<uint32_t, const char*> SbfSyscalls = {
    { 0xb6fc1a11, "abort" },
    { 0x686093bb, "sol_panic_" },
    { 0x207559bd, "sol_log_" },
    { 0x5c2a3178, "sol_log_64_" },
    { 0x52ba5096, "sol_log_compute_units_" },
    { 0x7ef088ca, "sol_log_pubkey" },
    { 0x9377323c, "sol_create_program_address" },
    { 0x48504a38, "sol_try_find_program_address" },
    { 0x11f49d86, "sol_sha256" },
    { 0xd7793abb, "sol_keccak256" },
    { 0x17e40350, "sol_secp256k1_recover" },
    { 0x174c5122, "sol_blake3" },
    { 0xaa2607ca, "sol_curve_validate_point" },
    { 0xdd1c41a6, "sol_curve_group_op" },
    { 0xd56b5fe9, "sol_get_clock_sysvar" },
    { 0x23a29a61, "sol_get_epoch_schedule_sysvar" },
    { 0x3b97b73c, "sol_get_fees_sysvar" },
    { 0xbf7188f6, "sol_get_rent_sysvar" },
    { 0x717cc4a3, "sol_memcpy_" },
    { 0x434371f8, "sol_memmove_" },
    { 0x5fdcde31, "sol_memcmp_" },
    { 0x3770fb22, "sol_memset_" },
    { 0xa22b9c85, "sol_invoke_signed_c" },
    { 0xd7449092, "sol_invoke_signed_rust" },
    { 0x83f00e8f, "sol_alloc_free_" },
    { 0xa226d3eb, "sol_set_return_data" },
    { 0x5d2245e4, "sol_get_return_data" },
    { 0x7317b434, "sol_log_data" },
    { 0xadb8efc8, "sol_get_processed_sibling_instruction" },
    { 0x85532d94, "sol_get_stack_height" }
};

#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
using namespace BinaryNinja;

#include <capstone/capstone.h>

#include "disassembler.h"
#include "il.h"

static ExprId operToIL(LowLevelILFunction& il, struct cs_bpf_op* op)
{
    ExprId res;
    if (!op) {
        return il.Unimplemented();
    }

    switch (op->type) {
    case BPF_OP_REG:
        res = il.Register(8, op->reg);
        break;
    case BPF_OP_IMM:
        res = il.Const(8, (int32_t)op->imm);
        break;
    case BPF_OP_MEM:
        res = il.Add(8, il.Register(8, op->mem.base), il.Const(8, (int64_t)Int16SignExtend(op->mem.disp)));
        break;
    default:
        res = il.Unimplemented();
        break;
    }
    return res;
}

static ExprId JumpAlways(
    Architecture* arch,
    LowLevelILFunction& il,
    uint64_t target)
{
    BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);
    if (label)
        return il.Goto(*label);
    else
        return il.Jump(il.ConstPointer(8, target));
}

static void _JumpConditional(
    Architecture* arch,
    LowLevelILFunction& il,
    uint64_t t,
    uint64_t f,
    ExprId condition)
{
    BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
    BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);

    if (trueLabel && falseLabel) {
        il.AddInstruction(il.If(condition, *trueLabel, *falseLabel));
        return;
    }

    LowLevelILLabel trueCode, falseCode;
    if (trueLabel) {
        il.AddInstruction(il.If(condition, *trueLabel, falseCode));
        il.MarkLabel(falseCode);
        il.AddInstruction(il.Jump(il.ConstPointer(8, f)));
        return;
    }
    if (falseLabel) {
        il.AddInstruction(il.If(condition, trueCode, *falseLabel));
        il.MarkLabel(trueCode);
        il.AddInstruction(il.Jump(il.ConstPointer(8, t)));
        return;
    }

    il.AddInstruction(il.If(condition, trueCode, falseCode));
    il.MarkLabel(trueCode);
    il.AddInstruction(il.Jump(il.ConstPointer(8, t)));
    il.MarkLabel(falseCode);
    il.AddInstruction(il.Jump(il.ConstPointer(8, f)));
}

static void JumpConditional(
    Architecture* arch,
    LowLevelILFunction& il,
    uint64_t addr,
    struct cs_bpf_op* op,
    ExprId condition)
{
    uint64_t t = JumpDest(op, addr);
    uint64_t f = addr + 8;
    _JumpConditional(arch, il, t, f, condition);
}

extern thread_local csh handle_lil;

bool GetLowLevelILForBPFInstruction(Architecture* arch, LowLevelILFunction& il,
    const uint8_t* data, uint64_t addr, decomp_result* res, bool le)
{
    struct cs_insn* insn = &(res->insn);
    struct cs_detail* detail = &(res->detail);
    struct cs_bpf* bpf = &(detail->bpf);

    // clang-format off
    /* create convenient access to instruction operands */
    cs_bpf_op *oper0 = NULL, *oper1 = NULL, *oper2 = NULL, *oper3 = NULL, *oper4 = NULL;
    #define REQUIRE1OP if(!oper0) goto ReturnUnimpl;
	#define REQUIRE2OPS if(!oper0 || !oper1) goto ReturnUnimpl;
	#define REQUIRE3OPS if(!oper0 || !oper1 || !oper2) goto ReturnUnimpl;
	#define REQUIRE4OPS if(!oper0 || !oper1 || !oper2 || !oper3) goto ReturnUnimpl;
	#define REQUIRE5OPS if(!oper0 || !oper1 || !oper2 || !oper3 || !oper4) goto ReturnUnimpl;
	switch(bpf->op_count) {
		default:
		case 5: oper4 = &(bpf->operands[4]);
		case 4: oper3 = &(bpf->operands[3]);
		case 3: oper2 = &(bpf->operands[2]);
		case 2: oper1 = &(bpf->operands[1]);
		case 1: oper0 = &(bpf->operands[0]);
		case 0: break;
	}
    // clang-format on

    // printf("id=%s\n", cs_insn_name(handle_lil, insn->id));
    // fflush(stdout);

    ExprId ei0, ei1, ei2;
    switch (insn->id) {
    // Legacy load/store class
    case BPF_INS_LDDW:
        REQUIRE2OPS
        ei0 = il.SetRegister(8, oper0->reg, operToIL(il, oper1));
        il.AddInstruction(ei0);
        break;
    // Load/Store class
    case BPF_INS_LDXB:
        REQUIRE2OPS
        ei0 = il.Load(8, operToIL(il, oper1));
        ei0 = il.LowPart(1, ei0);
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_LDXH:
        REQUIRE2OPS
        ei0 = il.Load(8, operToIL(il, oper1));
        ei0 = il.LowPart(2, ei0);
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_LDXW:
        REQUIRE2OPS
        ei0 = il.Load(8, operToIL(il, oper1));
        ei0 = il.LowPart(4, ei0);
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_LDXDW:
        REQUIRE2OPS
        ei0 = il.Load(8, operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_STXB:
        REQUIRE2OPS
        ei0 = il.LowPart(1, operToIL(il, oper1));
        ei0 = il.Store(8, operToIL(il, oper0), ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_STXH:
        REQUIRE2OPS
        ei0 = il.LowPart(2, operToIL(il, oper1));
        ei0 = il.Store(8, operToIL(il, oper0), ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_STXW:
        REQUIRE2OPS
        ei0 = il.LowPart(4, operToIL(il, oper1));
        ei0 = il.Store(8, operToIL(il, oper0), ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_STXDW:
        REQUIRE2OPS
        ei0 = il.Store(8, operToIL(il, oper0), operToIL(il, oper1));
        il.AddInstruction(ei0);
        break;
    // ALU64 class
    case BPF_INS_ADD64:
        REQUIRE2OPS
        ei0 = il.Add(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_SUB64:
        REQUIRE2OPS
        ei0 = il.Sub(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_MUL64:
        REQUIRE2OPS
        ei0 = il.Mult(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_DIV64:
        REQUIRE2OPS
        ei0 = il.DivUnsigned(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_OR64:
        REQUIRE2OPS
        ei0 = il.Or(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_AND64:
        REQUIRE2OPS
        ei0 = il.And(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_LSH64:
        REQUIRE2OPS
        ei0 = il.ShiftLeft(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_RSH64:
        REQUIRE2OPS
        ei0 = il.LogicalShiftRight(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_NEG64:
        REQUIRE1OP
        ei0 = il.Neg(8, operToIL(il, oper0));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_MOD64:
        REQUIRE2OPS
        ei0 = il.ModUnsigned(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_XOR64:
        REQUIRE2OPS
        ei0 = il.Xor(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_MOV64:
        REQUIRE2OPS
        ei0 = il.SetRegister(8, oper0->reg, operToIL(il, oper1));
        il.AddInstruction(ei0);
        break;
    case BPF_INS_ARSH64:
        REQUIRE2OPS
        ei0 = il.ArithShiftRight(8, operToIL(il, oper0), operToIL(il, oper1));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    // ALU32 class
    case BPF_INS_ADD:
        REQUIRE2OPS
        ei0 = il.Add(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_SUB:
        REQUIRE2OPS
        ei0 = il.Sub(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_MUL:
        REQUIRE2OPS
        ei0 = il.Mult(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_DIV:
        REQUIRE2OPS
        ei0 = il.DivUnsigned(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_OR:
        REQUIRE2OPS
        ei0 = il.Or(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_AND:
        REQUIRE2OPS
        ei0 = il.And(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_LSH:
        REQUIRE2OPS
        ei0 = il.ShiftLeft(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_RSH:
        REQUIRE2OPS
        ei0 = il.LogicalShiftRight(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_NEG:
        REQUIRE1OP
        ei0 = il.Neg(4, il.LowPart(4, operToIL(il, oper0)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_MOD:
        REQUIRE2OPS
        ei0 = il.ModUnsigned(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_XOR:
        REQUIRE2OPS
        ei0 = il.Xor(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    case BPF_INS_MOV:
        REQUIRE2OPS
        ei0 = il.SetRegister(8, oper0->reg, il.LowPart(4, operToIL(il, oper1)));
        il.AddInstruction(ei0);
        break;
    case BPF_INS_ARSH:
        REQUIRE2OPS
        ei0 = il.ArithShiftRight(4, il.LowPart(4, operToIL(il, oper0)), il.LowPart(4, operToIL(il, oper1)));
        ei0 = il.SetRegister(8, oper0->reg, ei0);
        il.AddInstruction(ei0);
        break;
    // ALU extension class
    case BPF_INS_LE16:
    case BPF_INS_BE16:
        REQUIRE1OP
        if ((insn->id == BPF_INS_LE16) == le) {
            ei0 = il.LowPart(2, operToIL(il, oper0));
        } else {
            ei0 = il.RotateLeft(2, il.LowPart(2, operToIL(il, oper0)), il.Const(2, 8));
        }
        il.AddInstruction(il.SetRegister(8, oper0->reg, ei0));
        break;
    case BPF_INS_LE32:
    case BPF_INS_BE32:
        REQUIRE1OP
        if ((insn->id == BPF_INS_LE32) == le) {
            ei0 = il.LowPart(2, operToIL(il, oper0));
        } else {
            ei1 = operToIL(il, oper0);
            // clang-format off
            // dst  = (( src        & 0xff) << 24)
            ei0 =               il.ShiftLeft(4, il.LowPart(1,                         ei1),                   il.Const(8, 24));
            // dst |= (((src >>  8) & 0xff) << 16)
            ei0 = il.Or(4, ei0, il.ShiftLeft(4, il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(4,  8))), il.Const(4, 16)));
            // dst |= (((src >> 16) & 0xff) <<  8)
            ei0 = il.Or(4, ei0, il.ShiftLeft(4, il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(4, 16))), il.Const(4,  8)));
            // dst |=  ((src >> 24) & 0xff)
            ei0 = il.Or(4, ei0,                 il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(4, 24))));
            // clang-format on
        }
        il.AddInstruction(il.SetRegister(8, oper0->reg, ei0));
        break;
    case BPF_INS_LE64:
    case BPF_INS_BE64:
        REQUIRE1OP
        if ((insn->id == BPF_INS_LE16) == le) {
            il.AddInstruction(il.Nop());
        } else {
            ei1 = operToIL(il, oper0);
            // clang-format off
            // dst  = (( src        & 0xff) << 56)
            ei0 =               il.ShiftLeft(8, il.LowPart(1,                         ei1),                   il.Const(8, 56));
            // dst |= (((src >>  8) & 0xff) << 48)
            ei0 = il.Or(8, ei0, il.ShiftLeft(8, il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(8,  8))), il.Const(8, 48)));
            // dst |= (((src >> 16) & 0xff) << 40)
            ei0 = il.Or(8, ei0, il.ShiftLeft(8, il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(8, 16))), il.Const(8, 40)));
            // dst |= (((src >> 24) & 0xff) << 32)
            ei0 = il.Or(8, ei0, il.ShiftLeft(8, il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(8, 24))), il.Const(8, 32)));
            // dst |= (((src >> 32) & 0xff) << 24)
            ei0 = il.Or(8, ei0, il.ShiftLeft(8, il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(8, 32))), il.Const(8, 24)));
            // dst |= (((src >> 40) & 0xff) << 16)
            ei0 = il.Or(8, ei0, il.ShiftLeft(8, il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(8, 40))), il.Const(8, 16)));
            // dst |= (((src >> 48) & 0xff) <<  8)
            ei0 = il.Or(8, ei0, il.ShiftLeft(8, il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(8, 48))), il.Const(8,  8)));
            // dst |=  ((src >> 56) & 0xff)
            ei0 = il.Or(8, ei0,                 il.LowPart(1, il.LogicalShiftRight(4, ei1, il.Const(8, 56))));
            // clang-format on
            il.AddInstruction(il.SetRegister(8, oper0->reg, ei0));
        }
        break;
    // Jump class
    case BPF_INS_JMP:
        REQUIRE1OP
        il.AddInstruction(JumpAlways(arch, il, JumpDest(oper0, addr)));
        break;
    case BPF_INS_JEQ:
        REQUIRE2OPS
        ei0 = il.CompareEqual(8, operToIL(il, oper0), operToIL(il, oper1));
        JumpConditional(arch, il, addr, oper2, ei0);
        break;
    case BPF_INS_JGT:
        REQUIRE2OPS
        ei0 = il.CompareUnsignedGreaterThan(8, operToIL(il, oper0), operToIL(il, oper1));
        JumpConditional(arch, il, addr, oper2, ei0);
        break;
    case BPF_INS_JGE:
        REQUIRE2OPS
        ei0 = il.CompareUnsignedGreaterEqual(8, operToIL(il, oper0), operToIL(il, oper1));
        JumpConditional(arch, il, addr, oper2, ei0);
        break;
    case BPF_INS_JNE:
        REQUIRE2OPS
        ei0 = il.CompareNotEqual(8, operToIL(il, oper0), operToIL(il, oper1));
        JumpConditional(arch, il, addr, oper2, ei0);
        break;
    case BPF_INS_JSGT:
        REQUIRE2OPS
        ei0 = il.CompareSignedGreaterThan(8, operToIL(il, oper0), operToIL(il, oper1));
        JumpConditional(arch, il, addr, oper2, ei0);
        break;
    case BPF_INS_JSGE:
        REQUIRE2OPS
        ei0 = il.CompareSignedGreaterEqual(8, operToIL(il, oper0), operToIL(il, oper1));
        JumpConditional(arch, il, addr, oper2, ei0);
        break;
    // Call class
    case BPF_INS_CALL:
        REQUIRE1OP
        if ((data[1] & 0xF0) == 0x10) {
            ei0 = il.ConstPointer(8, CallDest(oper0, addr));
            ei0 = il.Call(ei0);
        } else {
            ei0 = il.SystemCall();
        }
        il.AddInstruction(ei0);
        break;
    case BPF_INS_CALLX:
        REQUIRE1OP
        ei0 = il.Call(operToIL(il, oper0));
        il.AddInstruction(ei0);
        break;
    case BPF_INS_EXIT:
        il.AddInstruction(il.Return(il.Const(1, 1)));
        break;
    ReturnUnimpl:
    default:
        il.AddInstruction(il.Unimplemented());
        break;
    }

    return true;
}

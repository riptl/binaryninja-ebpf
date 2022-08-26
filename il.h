#pragma once

#define IL_FLAGCLASS_NONE 0

bool GetLowLevelILForBPFInstruction(Architecture* arch, LowLevelILFunction& il, const uint8_t* data, uint64_t addr, decomp_result* res, bool le);

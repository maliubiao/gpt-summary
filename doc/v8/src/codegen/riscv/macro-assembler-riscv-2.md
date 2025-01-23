Response: The user wants a summary of the provided C++ code snippet, which is part 3 of 5 of the `macro-assembler-riscv.cc` file. The goal is to understand its functionalities and if related to JavaScript, to provide illustrative examples.

Based on the content of this part, it mainly focuses on:

1. **Floating-point operations:**  Loading, storing, and manipulating floating-point numbers (both single and double precision).
2. **Comparisons:** Implementing various integer comparison operations (signed and unsigned).
3. **Bit manipulation:** Providing instructions for counting leading/trailing zeros and set bits.
4. **Conditional execution:**  Instructions for conditionally setting a register to zero.
5. **Function calls and jumps:** Implementing different branching and linking instructions, including calls to C functions and built-in functions.
6. **Stack manipulation:** Instructions for pushing and popping values onto the stack.
7. **Exception handling:**  Functions for managing stack handlers.
8. **JavaScript invocation:**  Helper functions for invoking JavaScript functions, including stack overflow checks and debugging hooks.
9. **WebAssembly (Wasm) support:** Beginning to introduce Vector instructions (RVV).

The relation to JavaScript comes from the fact that this `MacroAssembler` is used by V8 (the JavaScript engine) to generate machine code. Many of these operations are fundamental to implementing JavaScript's semantics, especially in areas like arithmetic, comparisons, function calls, and interactions with the underlying system.

I will now construct the summary and JavaScript examples based on these observations.
```cpp
 Operand(-8));
  StoreDouble(dst, MemOperand(sp, 0));
  Sw(src_high, MemOperand(sp, 4));
  LoadDouble(dst, MemOperand(sp, 0));
  Add32(sp, sp, Operand(8));
#endif
}

void MacroAssembler::InsertLowWordF64(FPURegister dst, Register src_low) {
#if V8_TARGET_ARCH_RISCV64
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);

  DCHECK(src_low != scratch && src_low != scratch2);
  fmv_x_d(scratch, dst);
  slli(scratch2, src_low, 32);
  srli(scratch2, scratch2, 32);
  srli(scratch, scratch, 32);
  slli(scratch, scratch, 32);
  or_(scratch, scratch, scratch2);
  fmv_d_x(dst, scratch);
#elif V8_TARGET_ARCH_RISCV32
  BlockTrampolinePoolScope block_trampoline_pool(this);
  AddWord(sp, sp, Operand(-8));
  StoreDouble(dst, MemOperand(sp, 0));
  Sw(src_low, MemOperand(sp, 0));
  LoadDouble(dst, MemOperand(sp, 0));
  AddWord(sp, sp, Operand(8));
#endif
}

void MacroAssembler::LoadFPRImmediate(FPURegister dst, uint32_t src) {
  ASM_CODE_COMMENT(this);
  // Handle special values first.
  if (src == base::bit_cast<uint32_t>(0.0f) && has_single_zero_reg_set_) {
    if (dst != kSingleRegZero) fmv_s(dst, kSingleRegZero);
  } else if (src == base::bit_cast<uint32_t>(-0.0f) &&
             has_single_zero_reg_set_) {
    Neg_s(dst, kSingleRegZero);
  } else {
    if (dst == kSingleRegZero) {
      DCHECK(src == base::bit_cast<uint32_t>(0.0f));
      fcvt_s_w(dst, zero_reg);
      has_single_zero_reg_set_ = true;
    } else {
      if (src == base::bit_cast<uint32_t>(0.0f)) {
        fcvt_s_w(dst, zero_reg);
      } else {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        li(scratch, Operand(static_cast<int32_t>(src)));
        fmv_w_x(dst, scratch);
      }
    }
  }
}

void MacroAssembler::LoadFPRImmediate(FPURegister dst, uint64_t src) {
  ASM_CODE_COMMENT(this);
  // Handle special values first.
  if (src == base::bit_cast<uint64_t>(0.0) && has_double_zero_reg_set_) {
    if (dst != kDoubleRegZero) fmv_d(dst, kDoubleRegZero);
  } else if (src == base::bit_cast<uint64_t>(-0.0) &&
             has_double_zero_reg_set_) {
    Neg_d(dst, kDoubleRegZero);
  } else {
#if V8_TARGET_ARCH_RISCV64
    if (dst == kDoubleRegZero) {
      DCHECK(src == base::bit_cast<uint64_t>(0.0));
      fcvt_d_l(dst, zero_reg);
      has_double_zero_reg_set_ = true;
    } else {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      if (src == base::bit_cast<uint64_t>(0.0)) {
        fcvt_d_l(dst, zero_reg);
      } else {
        li(scratch, Operand(src));
        fmv_d_x(dst, scratch);
      }
    }
#elif V8_TARGET_ARCH_RISCV32
    if (dst == kDoubleRegZero) {
      DCHECK(src == base::bit_cast<uint64_t>(0.0));
      fcvt_d_w(dst, zero_reg);
      has_double_zero_reg_set_ = true;
    } else {
      // Todo: need to clear the stack content?
      if (src == base::bit_cast<uint64_t>(0.0)) {
        fcvt_d_w(dst, zero_reg);
      } else {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        uint32_t low_32 = src & 0xffffffffull;
        uint32_t up_32 = src >> 32;
        AddWord(sp, sp, Operand(-8));
        li(scratch, Operand(static_cast<int32_t>(low_32)));
        Sw(scratch, MemOperand(sp, 0));
        li(scratch, Operand(static_cast<int32_t>(up_32)));
        Sw(scratch, MemOperand(sp, 4));
        LoadDouble(dst, MemOperand(sp, 0));
        AddWord(sp, sp, Operand(8));
      }
    }
#endif
  }
}

void MacroAssembler::CompareI(Register rd, Register rs, const Operand& rt,
                              Condition cond) {
  switch (cond) {
    case eq:
      Seq(rd, rs, rt);
      break;
    case ne:
      Sne(rd, rs, rt);
      break;

    // Signed comparison.
    case greater:
      Sgt(rd, rs, rt);
      break;
    case greater_equal:
      Sge(rd, rs, rt);  // rs >= rt
      break;
    case less:
      Slt(rd, rs, rt);  // rs < rt
      break;
    case less_equal:
      Sle(rd, rs, rt);  // rs <= rt
      break;

    // Unsigned comparison.
    case Ugreater:
      Sgtu(rd, rs, rt);  // rs > rt
      break;
    case Ugreater_equal:
      Sgeu(rd, rs, rt);  // rs >= rt
      break;
    case Uless:
      Sltu(rd, rs, rt);  // rs < rt
      break;
    case Uless_equal:
      Sleu(rd, rs, rt);  // rs <= rt
      break;
    case cc_always:
      UNREACHABLE();
    default:
      UNREACHABLE();
  }
}

// dest <- (condition != 0 ? zero : dest)
void MacroAssembler::LoadZeroIfConditionNotZero(Register dest,
                                                Register condition) {
  if (CpuFeatures::IsSupported(ZICOND)) {
    czero_nez(dest, dest, condition);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    seqz(scratch, condition);
    // neg + and may be more efficient than mul(dest, dest, scratch)
    neg(scratch, scratch);  // 0 is still 0, 1 becomes all 1s
    and_(dest, dest, scratch);
  }
}

// dest <- (condition == 0 ? 0 : dest)
void MacroAssembler::LoadZeroIfConditionZero(Register dest,
                                             Register condition) {
  if (CpuFeatures::IsSupported(ZICOND)) {
    czero_eqz(dest, dest, condition);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    snez(scratch, condition);
    //  neg + and may be more efficient than mul(dest, dest, scratch);
    neg(scratch, scratch);  // 0 is still 0, 1 becomes all 1s
    and_(dest, dest, scratch);
  }
}

void MacroAssembler::Clz32(Register rd, Register xx) {
  if (CpuFeatures::IsSupported(ZBB)) {
#if V8_TARGET_ARCH_RISCV64
    clzw(rd, xx);
#else
    clz(rd, xx);
#endif
  } else {
    // 32 bit unsigned in lower word: count number of leading zeros.
    //  int n = 32;
    //  unsigned y;

    //  y = x >>16; if (y != 0) { n = n -16; x = y; }
    //  y = x >> 8; if (y != 0) { n = n - 8; x = y; }
    //  y = x >> 4; if (y != 0) { n = n - 4; x = y; }
    //  y = x >> 2; if (y != 0) { n = n - 2; x = y; }
    //  y = x >> 1; if (y != 0) {rd = n - 2; return;}
    //  rd = n - x;

    Label L0, L1, L2, L3, L4;
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Register x = rd;
    Register y = temps.Acquire();
    Register n = temps.Acquire();
    DCHECK(xx != y && xx != n);
    Move(x, xx);
    li(n, Operand(32));
#if V8_TARGET_ARCH_RISCV64
    srliw(y, x, 16);
    BranchShort(&L0, eq, y, Operand(zero_reg));
    Move(x, y);
    addiw(n, n, -16);
    bind(&L0);
    srliw(y, x, 8);
    BranchShort(&L1, eq, y, Operand(zero_reg));
    addiw(n, n, -8);
    Move(x, y);
    bind(&L1);
    srliw(y, x, 4);
    BranchShort(&L2, eq, y, Operand(zero_reg));
    addiw(n, n, -4);
    Move(x, y);
    bind(&L2);
    srliw(y, x, 2);
    BranchShort(&L3, eq, y, Operand(zero_reg));
    addiw(n, n, -2);
    Move(x, y);
    bind(&L3);
    srliw(y, x, 1);
    subw(rd, n, x);
    BranchShort(&L4, eq, y, Operand(zero_reg));
    addiw(rd, n, -2);
    bind(&L4);
#elif V8_TARGET_ARCH_RISCV32
    srli(y, x, 16);
    BranchShort(&L0, eq, y, Operand(zero_reg));
    Move(x, y);
    addi(n, n, -16);
    bind(&L0);
    srli(y, x, 8);
    BranchShort(&L1, eq, y, Operand(zero_reg));
    addi(n, n, -8);
    Move(x, y);
    bind(&L1);
    srli(y, x, 4);
    BranchShort(&L2, eq, y, Operand(zero_reg));
    addi(n, n, -4);
    Move(x, y);
    bind(&L2);
    srli(y, x, 2);
    BranchShort(&L3, eq, y, Operand(zero_reg));
    addi(n, n, -2);
    Move(x, y);
    bind(&L3);
    srli(y, x, 1);
    sub(rd, n, x);
    BranchShort(&L4, eq, y, Operand(zero_reg));
    addi(rd, n, -2);
    bind(&L4);
#endif
  }
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Clz64(Register rd, Register xx) {
  if (CpuFeatures::IsSupported(ZBB)) {
    clz(rd, xx);
  } else {
    // 64 bit: count number of leading zeros.
    //  int n = 64;
    //  unsigned y;

    //  y = x >>32; if (y != 0) { n = n - 32; x = y; }
    //  y = x >>16; if (y != 0) { n = n - 16; x = y; }
    //  y = x >> 8; if (y != 0) { n = n - 8; x = y; }
    //  y = x >> 4; if (y != 0) { n = n - 4; x = y; }
    //  y = x >> 2; if (y != 0) { n = n - 2; x = y; }
    //  y = x >> 1; if (y != 0) {rd = n - 2; return;}
    //  rd = n - x;

    Label L0, L1, L2, L3, L4, L5;
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Register x = rd;
    Register y = temps.Acquire();
    Register n = temps.Acquire();
    DCHECK(xx != y && xx != n);
    Move(x, xx);
    li(n, Operand(64));
    srli(y, x, 32);
    BranchShort(&L0, eq, y, Operand(zero_reg));
    addiw(n, n, -32);
    Move(x, y);
    bind(&L0);
    srli(y, x, 16);
    BranchShort(&L1, eq, y, Operand(zero_reg));
    addiw(n, n, -16);
    Move(x, y);
    bind(&L1);
    srli(y, x, 8);
    BranchShort(&L2, eq, y, Operand(zero_reg));
    addiw(n, n, -8);
    Move(x, y);
    bind(&L2);
    srli(y, x, 4);
    BranchShort(&L3, eq, y, Operand(zero_reg));
    addiw(n, n, -4);
    Move(x, y);
    bind(&L3);
    srli(y, x, 2);
    BranchShort(&L4, eq, y, Operand(zero_reg));
    addiw(n, n, -2);
    Move(x, y);
    bind(&L4);
    srli(y, x, 1);
    subw(rd, n, x);
    BranchShort(&L5, eq, y, Operand(zero_reg));
    addiw(rd, n, -2);
    bind(&L5);
  }
}
#endif
void MacroAssembler::Ctz32(Register rd, Register rs) {
  if (CpuFeatures::IsSupported(ZBB)) {
#if V8_TARGET_ARCH_RISCV64
    ctzw(rd, rs);
#else
    ctz(rd, rs);
#endif
  } else {
    // Convert trailing zeroes to trailing ones, and bits to their left
    // to zeroes.

    BlockTrampolinePoolScope block_trampoline_pool(this);
    {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      AddWord(scratch, rs, -1);
      Xor(rd, scratch, rs);
      And(rd, rd, scratch);
      // Count number of leading zeroes.
    }
    Clz32(rd, rd);
    {
      // Subtract number of leading zeroes from 32 to get number of trailing
      // ones. Remember that the trailing ones were formerly trailing zeroes.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, 32);
      Sub32(rd, scratch, rd);
    }
  }
}
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Ctz64(Register rd, Register rs) {
  if (CpuFeatures::IsSupported(ZBB)) {
    ctz(rd, rs);
  } else {
    // Convert trailing zeroes to trailing ones, and bits to their left
    // to zeroes.
    BlockTrampolinePoolScope block_trampoline_pool(this);
    {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      AddWord(scratch, rs, -1);
      Xor(rd, scratch, rs);
      And(rd, rd, scratch);
      // Count number of leading zeroes.
    }
    Clz64(rd, rd);
    {
      // Subtract number of leading zeroes from 64 to get number of trailing
      // ones. Remember that the trailing ones were formerly trailing zeroes.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, 64);
      SubWord(rd, scratch, rd);
    }
  }
}
#endif
void MacroAssembler::Popcnt32(Register rd, Register rs, Register scratch) {
  if (CpuFeatures::IsSupported(ZBB)) {
#if V8_TARGET_ARCH_RISCV64
    cpopw(rd, rs);
#else
    cpop(rd, rs);
#endif
  } else {
    DCHECK_NE(scratch, rs);
    DCHECK_NE(scratch, rd);
    // https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
    //
    // A generalization of the best bit counting method to integers of
    // bit-widths up to 128 (parameterized by type T) is this:
    //
    // v = v - ((v >> 1) & (T)~(T)0/3);                           // temp
    // v = (v & (T)~(T)0/15*3) + ((v >> 2) & (T)~(T)0/15*3);      // temp
    // v = (v + (v >> 4)) & (T)~(T)0/255*15;                      // temp
    // c = (T)(v * ((T)~(T)0/255)) >> (sizeof(T) - 1) * BITS_PER_BYTE; //count
    //
    // There are algorithms which are faster in the cases where very few
    // bits are set but the algorithm here attempts to minimize the total
    // number of instructions executed even when a large number of bits
    // are set.
    // The number of instruction is 20.
    // uint32_t B0 = 0x55555555;     // (T)~(T)0/3
    // uint32_t B1 = 0x33333333;     // (T)~(T)0/15*3
    // uint32_t B2 = 0x0F0F0F0F;     // (T)~(T)0/255*15
    // uint32_t value = 0x01010101;  // (T)~(T)0/255

    uint32_t shift = 24;
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Register scratch2 = temps.Acquire();
    Register value = temps.Acquire();
    DCHECK((rd != value) && (rs != value));
    li(value, 0x01010101);     // value = 0x01010101;
    li(scratch2, 0x55555555);  // B0 = 0x55555555;
    Srl32(scratch, rs, 1);
    And(scratch, scratch, scratch2);
    Sub32(scratch, rs, scratch);
    li(scratch2, 0x33333333);  // B1 = 0x33333333;
    slli(rd, scratch2, 4);
    or_(scratch2, scratch2, rd);
    And(rd, scratch, scratch2);
    Srl32(scratch, scratch, 2);
    And(scratch, scratch, scratch2);
    Add32(scratch, rd, scratch);
    Srl32(rd, scratch, 4);
    Add32(rd, rd, scratch);
    li(scratch2, 0xF);
    Mul32(scratch2, value, scratch2);  // B2 = 0x0F0F0F0F;
    And(rd, rd, scratch2);
    Mul32(rd, rd, value);
    Srl32(rd, rd, shift);
  }
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Popcnt64(Register rd, Register rs, Register scratch) {
  if (CpuFeatures::IsSupported(ZBB)) {
    cpop(rd, rs);
  } else {
    DCHECK_NE(scratch, rs);
    DCHECK_NE(scratch, rd);
    // uint64_t B0 = 0x5555555555555555l;     // (T)~(T)0/3
    // uint64_t B1 = 0x3333333333333333l;     // (T)~(T)0/15*3
    // uint64_t B2 = 0x0F0F0F0F0F0F0F0Fl;     // (T)~(T)0/255*15
    // uint64_t value = 0x0101010101010101l;  // (T)~(T)0/255
    // uint64_t shift = 24;                   // (sizeof(T) - 1) * BITS_PER_BYTE
    uint64_t shift = 24;
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Register scratch2 = temps.Acquire();
    Register value = temps.Acquire();
    DCHECK((rd != value) && (rs != value));
    li(value, 0x1111111111111111l);  // value = 0x1111111111111111l;
    li(scratch2, 5);
    Mul64(scratch2, value, scratch2);  // B0 = 0x5555555555555555l;
    Srl64(scratch, rs, 1);
    And(scratch, scratch, scratch2);
    SubWord(scratch, rs, scratch);
    li(scratch2, 3);
    Mul64(scratch2, value, scratch2);  // B1 = 0x3333333333333333l;
    And(rd, scratch, scratch2);
    Srl64(scratch, scratch, 2);
    And(scratch, scratch, scratch2);
    AddWord(scratch, rd, scratch);
    Srl64(rd, scratch, 4);
    AddWord(rd, rd, scratch);
    li(scratch2, 0xF);
    li(value, 0x0101010101010101l);    // value = 0x0101010101010101l;
    Mul64(scratch2, value, scratch2);  // B2 = 0x0F0F0F0F0F0F0F0Fl;
    And(rd, rd, scratch2);
    Mul64(rd, rd, value);
    srli(rd, rd, 32 + shift);
  }
}
#endif
void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DoubleRegister double_input,
                                                Label* done) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  // if scratch == 1, exception happens during truncation
  Trunc_w_d(result, double_input, scratch);
  // If we had no exceptions (i.e., scratch==1) we are done.
  Branch(done, eq, scratch, Operand(1));
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode) {
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub
  // instead.
  push(ra);
  SubWord(sp, sp, Operand(kDoubleSize));  // Put input on stack.
  fsd(double_input, sp, 0);
#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }
  LoadWord(result, MemOperand(sp, 0));

  AddWord(sp, sp, Operand(kDoubleSize));
  pop(ra);

  bind(&done);
}

// BRANCH_ARGS_CHECK checks that conditional jump arguments are correct.
#define BRANCH_ARGS_CHECK(cond, rs, rt)                                  \
  DCHECK((cond == cc_always && rs == zero_reg && rt.rm() == zero_reg) || \
         (cond != cc_always && (rs != zero_reg || rt.rm() != zero_reg)))

void MacroAssembler::Branch(int32_t offset) {
  DCHECK(is_int21(offset));
  BranchShort(offset);
}

void MacroAssembler::Branch(int32_t offset, Condition cond, Register rs,
                            const Operand& rt, Label::Distance distance) {
  bool is_near = BranchShortCheck(offset, nullptr, cond, rs, rt);
  DCHECK(is_near);
  USE(is_near);
}

void MacroAssembler::Branch(Label* L) {
  if (L->is_bound()) {
    if (is_near(L)) {
      BranchShort(L);
    } else {
      BranchLong(L);
    }
  } else {
    if (is_trampoline_emitted()) {
      BranchLong(L);
    } else {
      BranchShort(L);
    }
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rs,
                            const Operand& rt, Label::Distance distance) {
  if (L->is_bound()) {
    if (!BranchShortCheck(0, L, cond, rs, rt)) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rs, rt);
        BranchLong(L);
        bind(&skip);
      } else {
        BranchLong(L);
        EmitConstPoolWithJumpIfNeeded();
      }
    }
  } else {
    if (is_trampoline_emitted() && distance == Label::Distance::kFar) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rs, rt);
        BranchLong(L);
        bind(&skip);
      } else {
        BranchLong(L);
        EmitConstPoolWithJumpIfNeeded();
      }
    } else {
      BranchShort(L, cond, rs, rt);
    }
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rs,
                            RootIndex index, Label::Distance distance) {
  UseScratchRegisterScope temps(this);
  Register right = temps.Acquire();
  if (COMPRESS_POINTERS_BOOL) {
    Register left = rs;
    if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
        is_int12(ReadOnlyRootPtr(index))) {
      left = temps.Acquire();
      Sll32(left, rs, 0);
    }
    LoadTaggedRoot(right, index);
    Branch(L, cond, left, Operand(right));
  } else {
    LoadRoot(right, index);
    Branch(L, cond, rs, Operand(right));
  }
}

void MacroAssembler::CompareTaggedAndBranch(Label* label, Condition cond,
                                            Register r1, const Operand& r2,
                                            bool need_link) {
  if (COMPRESS_POINTERS_BOOL) {
    UseScratchRegisterScope temps(this);
    Register scratch0 = temps.Acquire();
    Sll32(scratch0, r1, 0);
    if (IsZero(r2)) {
      Branch(label, cond, scratch0, Operand(zero_reg));
    } else {
      Register scratch1 = temps.Acquire();
      if (r2.is_reg()) {
        Sll32(scratch1, r2.rm(), 0);
      } else {
        li(scratch1, r2);
        Sll32(scratch1, scratch1, 0);
      }
      Branch(label, cond, scratch0, Operand(scratch1));
    }
  } else {
    Branch(label, cond, r1, r2);
  }
}

void MacroAssembler::BranchShortHelper(int32_t offset, Label* L) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset21);
  j(offset);
}

void MacroAssembler::BranchShort(int32_t offset) {
  DCHECK(is_int21(offset));
  BranchShortHelper(offset, nullptr);
}

void MacroAssembler::BranchShort(Label* L) { BranchShortHelper(0, L); }

int32_t MacroAssembler::GetOffset(int32_t offset, Label* L, OffsetSize bits) {
  if (L) {
    offset = branch_offset_helper(L, bits);
  } else {
    DCHECK(is_intn(offset, bits));
  }
  return offset;
}

Register MacroAssembler::GetRtAsRegisterHelper(const Operand& rt,
                                               Register scratch) {
  Register r2 = no_reg;
  if (rt.is_reg()) {
    r2 = rt.rm();
  } else {
    r2 = scratch;
    li(r2, rt);
  }

  return r2;
}

bool MacroAssembler::CalculateOffset(Label* L, int32_t* offset,
                                     OffsetSize bits) {
  if (!is_near(L, bits)) return false;
  *offset = GetOffset(*offset, L, bits);
  return true;
}

bool MacroAssembler::CalculateOffset(Label* L, int32_t* offset, OffsetSize bits,
                                     Register* scratch, const Operand& rt) {
  if (!is_near(L, bits)) return false;
  *scratch = GetRtAsRegisterHelper(rt, *scratch);
  
### 提示词
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```
Operand(-8));
  StoreDouble(dst, MemOperand(sp, 0));
  Sw(src_high, MemOperand(sp, 4));
  LoadDouble(dst, MemOperand(sp, 0));
  Add32(sp, sp, Operand(8));
#endif
}

void MacroAssembler::InsertLowWordF64(FPURegister dst, Register src_low) {
#if V8_TARGET_ARCH_RISCV64
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);

  DCHECK(src_low != scratch && src_low != scratch2);
  fmv_x_d(scratch, dst);
  slli(scratch2, src_low, 32);
  srli(scratch2, scratch2, 32);
  srli(scratch, scratch, 32);
  slli(scratch, scratch, 32);
  or_(scratch, scratch, scratch2);
  fmv_d_x(dst, scratch);
#elif V8_TARGET_ARCH_RISCV32
  BlockTrampolinePoolScope block_trampoline_pool(this);
  AddWord(sp, sp, Operand(-8));
  StoreDouble(dst, MemOperand(sp, 0));
  Sw(src_low, MemOperand(sp, 0));
  LoadDouble(dst, MemOperand(sp, 0));
  AddWord(sp, sp, Operand(8));
#endif
}

void MacroAssembler::LoadFPRImmediate(FPURegister dst, uint32_t src) {
  ASM_CODE_COMMENT(this);
  // Handle special values first.
  if (src == base::bit_cast<uint32_t>(0.0f) && has_single_zero_reg_set_) {
    if (dst != kSingleRegZero) fmv_s(dst, kSingleRegZero);
  } else if (src == base::bit_cast<uint32_t>(-0.0f) &&
             has_single_zero_reg_set_) {
    Neg_s(dst, kSingleRegZero);
  } else {
    if (dst == kSingleRegZero) {
      DCHECK(src == base::bit_cast<uint32_t>(0.0f));
      fcvt_s_w(dst, zero_reg);
      has_single_zero_reg_set_ = true;
    } else {
      if (src == base::bit_cast<uint32_t>(0.0f)) {
        fcvt_s_w(dst, zero_reg);
      } else {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        li(scratch, Operand(static_cast<int32_t>(src)));
        fmv_w_x(dst, scratch);
      }
    }
  }
}

void MacroAssembler::LoadFPRImmediate(FPURegister dst, uint64_t src) {
  ASM_CODE_COMMENT(this);
  // Handle special values first.
  if (src == base::bit_cast<uint64_t>(0.0) && has_double_zero_reg_set_) {
    if (dst != kDoubleRegZero) fmv_d(dst, kDoubleRegZero);
  } else if (src == base::bit_cast<uint64_t>(-0.0) &&
             has_double_zero_reg_set_) {
    Neg_d(dst, kDoubleRegZero);
  } else {
#if V8_TARGET_ARCH_RISCV64
    if (dst == kDoubleRegZero) {
      DCHECK(src == base::bit_cast<uint64_t>(0.0));
      fcvt_d_l(dst, zero_reg);
      has_double_zero_reg_set_ = true;
    } else {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      if (src == base::bit_cast<uint64_t>(0.0)) {
        fcvt_d_l(dst, zero_reg);
      } else {
        li(scratch, Operand(src));
        fmv_d_x(dst, scratch);
      }
    }
#elif V8_TARGET_ARCH_RISCV32
    if (dst == kDoubleRegZero) {
      DCHECK(src == base::bit_cast<uint64_t>(0.0));
      fcvt_d_w(dst, zero_reg);
      has_double_zero_reg_set_ = true;
    } else {
      // Todo: need to clear the stack content?
      if (src == base::bit_cast<uint64_t>(0.0)) {
        fcvt_d_w(dst, zero_reg);
      } else {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        uint32_t low_32 = src & 0xffffffffull;
        uint32_t up_32 = src >> 32;
        AddWord(sp, sp, Operand(-8));
        li(scratch, Operand(static_cast<int32_t>(low_32)));
        Sw(scratch, MemOperand(sp, 0));
        li(scratch, Operand(static_cast<int32_t>(up_32)));
        Sw(scratch, MemOperand(sp, 4));
        LoadDouble(dst, MemOperand(sp, 0));
        AddWord(sp, sp, Operand(8));
      }
    }
#endif
  }
}

void MacroAssembler::CompareI(Register rd, Register rs, const Operand& rt,
                              Condition cond) {
  switch (cond) {
    case eq:
      Seq(rd, rs, rt);
      break;
    case ne:
      Sne(rd, rs, rt);
      break;

    // Signed comparison.
    case greater:
      Sgt(rd, rs, rt);
      break;
    case greater_equal:
      Sge(rd, rs, rt);  // rs >= rt
      break;
    case less:
      Slt(rd, rs, rt);  // rs < rt
      break;
    case less_equal:
      Sle(rd, rs, rt);  // rs <= rt
      break;

    // Unsigned comparison.
    case Ugreater:
      Sgtu(rd, rs, rt);  // rs > rt
      break;
    case Ugreater_equal:
      Sgeu(rd, rs, rt);  // rs >= rt
      break;
    case Uless:
      Sltu(rd, rs, rt);  // rs < rt
      break;
    case Uless_equal:
      Sleu(rd, rs, rt);  // rs <= rt
      break;
    case cc_always:
      UNREACHABLE();
    default:
      UNREACHABLE();
  }
}

// dest <- (condition != 0 ? zero : dest)
void MacroAssembler::LoadZeroIfConditionNotZero(Register dest,
                                                Register condition) {
  if (CpuFeatures::IsSupported(ZICOND)) {
    czero_nez(dest, dest, condition);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    seqz(scratch, condition);
    // neg + and may be more efficient than mul(dest, dest, scratch)
    neg(scratch, scratch);  // 0 is still 0, 1 becomes all 1s
    and_(dest, dest, scratch);
  }
}

// dest <- (condition == 0 ? 0 : dest)
void MacroAssembler::LoadZeroIfConditionZero(Register dest,
                                             Register condition) {
  if (CpuFeatures::IsSupported(ZICOND)) {
    czero_eqz(dest, dest, condition);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    snez(scratch, condition);
    //  neg + and may be more efficient than mul(dest, dest, scratch);
    neg(scratch, scratch);  // 0 is still 0, 1 becomes all 1s
    and_(dest, dest, scratch);
  }
}

void MacroAssembler::Clz32(Register rd, Register xx) {
  if (CpuFeatures::IsSupported(ZBB)) {
#if V8_TARGET_ARCH_RISCV64
    clzw(rd, xx);
#else
    clz(rd, xx);
#endif
  } else {
    // 32 bit unsigned in lower word: count number of leading zeros.
    //  int n = 32;
    //  unsigned y;

    //  y = x >>16; if (y != 0) { n = n -16; x = y; }
    //  y = x >> 8; if (y != 0) { n = n - 8; x = y; }
    //  y = x >> 4; if (y != 0) { n = n - 4; x = y; }
    //  y = x >> 2; if (y != 0) { n = n - 2; x = y; }
    //  y = x >> 1; if (y != 0) {rd = n - 2; return;}
    //  rd = n - x;

    Label L0, L1, L2, L3, L4;
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Register x = rd;
    Register y = temps.Acquire();
    Register n = temps.Acquire();
    DCHECK(xx != y && xx != n);
    Move(x, xx);
    li(n, Operand(32));
#if V8_TARGET_ARCH_RISCV64
    srliw(y, x, 16);
    BranchShort(&L0, eq, y, Operand(zero_reg));
    Move(x, y);
    addiw(n, n, -16);
    bind(&L0);
    srliw(y, x, 8);
    BranchShort(&L1, eq, y, Operand(zero_reg));
    addiw(n, n, -8);
    Move(x, y);
    bind(&L1);
    srliw(y, x, 4);
    BranchShort(&L2, eq, y, Operand(zero_reg));
    addiw(n, n, -4);
    Move(x, y);
    bind(&L2);
    srliw(y, x, 2);
    BranchShort(&L3, eq, y, Operand(zero_reg));
    addiw(n, n, -2);
    Move(x, y);
    bind(&L3);
    srliw(y, x, 1);
    subw(rd, n, x);
    BranchShort(&L4, eq, y, Operand(zero_reg));
    addiw(rd, n, -2);
    bind(&L4);
#elif V8_TARGET_ARCH_RISCV32
    srli(y, x, 16);
    BranchShort(&L0, eq, y, Operand(zero_reg));
    Move(x, y);
    addi(n, n, -16);
    bind(&L0);
    srli(y, x, 8);
    BranchShort(&L1, eq, y, Operand(zero_reg));
    addi(n, n, -8);
    Move(x, y);
    bind(&L1);
    srli(y, x, 4);
    BranchShort(&L2, eq, y, Operand(zero_reg));
    addi(n, n, -4);
    Move(x, y);
    bind(&L2);
    srli(y, x, 2);
    BranchShort(&L3, eq, y, Operand(zero_reg));
    addi(n, n, -2);
    Move(x, y);
    bind(&L3);
    srli(y, x, 1);
    sub(rd, n, x);
    BranchShort(&L4, eq, y, Operand(zero_reg));
    addi(rd, n, -2);
    bind(&L4);
#endif
  }
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Clz64(Register rd, Register xx) {
  if (CpuFeatures::IsSupported(ZBB)) {
    clz(rd, xx);
  } else {
    // 64 bit: count number of leading zeros.
    //  int n = 64;
    //  unsigned y;

    //  y = x >>32; if (y != 0) { n = n - 32; x = y; }
    //  y = x >>16; if (y != 0) { n = n - 16; x = y; }
    //  y = x >> 8; if (y != 0) { n = n - 8; x = y; }
    //  y = x >> 4; if (y != 0) { n = n - 4; x = y; }
    //  y = x >> 2; if (y != 0) { n = n - 2; x = y; }
    //  y = x >> 1; if (y != 0) {rd = n - 2; return;}
    //  rd = n - x;

    Label L0, L1, L2, L3, L4, L5;
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Register x = rd;
    Register y = temps.Acquire();
    Register n = temps.Acquire();
    DCHECK(xx != y && xx != n);
    Move(x, xx);
    li(n, Operand(64));
    srli(y, x, 32);
    BranchShort(&L0, eq, y, Operand(zero_reg));
    addiw(n, n, -32);
    Move(x, y);
    bind(&L0);
    srli(y, x, 16);
    BranchShort(&L1, eq, y, Operand(zero_reg));
    addiw(n, n, -16);
    Move(x, y);
    bind(&L1);
    srli(y, x, 8);
    BranchShort(&L2, eq, y, Operand(zero_reg));
    addiw(n, n, -8);
    Move(x, y);
    bind(&L2);
    srli(y, x, 4);
    BranchShort(&L3, eq, y, Operand(zero_reg));
    addiw(n, n, -4);
    Move(x, y);
    bind(&L3);
    srli(y, x, 2);
    BranchShort(&L4, eq, y, Operand(zero_reg));
    addiw(n, n, -2);
    Move(x, y);
    bind(&L4);
    srli(y, x, 1);
    subw(rd, n, x);
    BranchShort(&L5, eq, y, Operand(zero_reg));
    addiw(rd, n, -2);
    bind(&L5);
  }
}
#endif
void MacroAssembler::Ctz32(Register rd, Register rs) {
  if (CpuFeatures::IsSupported(ZBB)) {
#if V8_TARGET_ARCH_RISCV64
    ctzw(rd, rs);
#else
    ctz(rd, rs);
#endif
  } else {
    // Convert trailing zeroes to trailing ones, and bits to their left
    // to zeroes.

    BlockTrampolinePoolScope block_trampoline_pool(this);
    {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      AddWord(scratch, rs, -1);
      Xor(rd, scratch, rs);
      And(rd, rd, scratch);
      // Count number of leading zeroes.
    }
    Clz32(rd, rd);
    {
      // Subtract number of leading zeroes from 32 to get number of trailing
      // ones. Remember that the trailing ones were formerly trailing zeroes.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, 32);
      Sub32(rd, scratch, rd);
    }
  }
}
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Ctz64(Register rd, Register rs) {
  if (CpuFeatures::IsSupported(ZBB)) {
    ctz(rd, rs);
  } else {
    // Convert trailing zeroes to trailing ones, and bits to their left
    // to zeroes.
    BlockTrampolinePoolScope block_trampoline_pool(this);
    {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      AddWord(scratch, rs, -1);
      Xor(rd, scratch, rs);
      And(rd, rd, scratch);
      // Count number of leading zeroes.
    }
    Clz64(rd, rd);
    {
      // Subtract number of leading zeroes from 64 to get number of trailing
      // ones. Remember that the trailing ones were formerly trailing zeroes.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, 64);
      SubWord(rd, scratch, rd);
    }
  }
}
#endif
void MacroAssembler::Popcnt32(Register rd, Register rs, Register scratch) {
  if (CpuFeatures::IsSupported(ZBB)) {
#if V8_TARGET_ARCH_RISCV64
    cpopw(rd, rs);
#else
    cpop(rd, rs);
#endif
  } else {
    DCHECK_NE(scratch, rs);
    DCHECK_NE(scratch, rd);
    // https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
    //
    // A generalization of the best bit counting method to integers of
    // bit-widths up to 128 (parameterized by type T) is this:
    //
    // v = v - ((v >> 1) & (T)~(T)0/3);                           // temp
    // v = (v & (T)~(T)0/15*3) + ((v >> 2) & (T)~(T)0/15*3);      // temp
    // v = (v + (v >> 4)) & (T)~(T)0/255*15;                      // temp
    // c = (T)(v * ((T)~(T)0/255)) >> (sizeof(T) - 1) * BITS_PER_BYTE; //count
    //
    // There are algorithms which are faster in the cases where very few
    // bits are set but the algorithm here attempts to minimize the total
    // number of instructions executed even when a large number of bits
    // are set.
    // The number of instruction is 20.
    // uint32_t B0 = 0x55555555;     // (T)~(T)0/3
    // uint32_t B1 = 0x33333333;     // (T)~(T)0/15*3
    // uint32_t B2 = 0x0F0F0F0F;     // (T)~(T)0/255*15
    // uint32_t value = 0x01010101;  // (T)~(T)0/255

    uint32_t shift = 24;
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Register scratch2 = temps.Acquire();
    Register value = temps.Acquire();
    DCHECK((rd != value) && (rs != value));
    li(value, 0x01010101);     // value = 0x01010101;
    li(scratch2, 0x55555555);  // B0 = 0x55555555;
    Srl32(scratch, rs, 1);
    And(scratch, scratch, scratch2);
    Sub32(scratch, rs, scratch);
    li(scratch2, 0x33333333);  // B1 = 0x33333333;
    slli(rd, scratch2, 4);
    or_(scratch2, scratch2, rd);
    And(rd, scratch, scratch2);
    Srl32(scratch, scratch, 2);
    And(scratch, scratch, scratch2);
    Add32(scratch, rd, scratch);
    Srl32(rd, scratch, 4);
    Add32(rd, rd, scratch);
    li(scratch2, 0xF);
    Mul32(scratch2, value, scratch2);  // B2 = 0x0F0F0F0F;
    And(rd, rd, scratch2);
    Mul32(rd, rd, value);
    Srl32(rd, rd, shift);
  }
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Popcnt64(Register rd, Register rs, Register scratch) {
  if (CpuFeatures::IsSupported(ZBB)) {
    cpop(rd, rs);
  } else {
    DCHECK_NE(scratch, rs);
    DCHECK_NE(scratch, rd);
    // uint64_t B0 = 0x5555555555555555l;     // (T)~(T)0/3
    // uint64_t B1 = 0x3333333333333333l;     // (T)~(T)0/15*3
    // uint64_t B2 = 0x0F0F0F0F0F0F0F0Fl;     // (T)~(T)0/255*15
    // uint64_t value = 0x0101010101010101l;  // (T)~(T)0/255
    // uint64_t shift = 24;                   // (sizeof(T) - 1) * BITS_PER_BYTE
    uint64_t shift = 24;
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Register scratch2 = temps.Acquire();
    Register value = temps.Acquire();
    DCHECK((rd != value) && (rs != value));
    li(value, 0x1111111111111111l);  // value = 0x1111111111111111l;
    li(scratch2, 5);
    Mul64(scratch2, value, scratch2);  // B0 = 0x5555555555555555l;
    Srl64(scratch, rs, 1);
    And(scratch, scratch, scratch2);
    SubWord(scratch, rs, scratch);
    li(scratch2, 3);
    Mul64(scratch2, value, scratch2);  // B1 = 0x3333333333333333l;
    And(rd, scratch, scratch2);
    Srl64(scratch, scratch, 2);
    And(scratch, scratch, scratch2);
    AddWord(scratch, rd, scratch);
    Srl64(rd, scratch, 4);
    AddWord(rd, rd, scratch);
    li(scratch2, 0xF);
    li(value, 0x0101010101010101l);    // value = 0x0101010101010101l;
    Mul64(scratch2, value, scratch2);  // B2 = 0x0F0F0F0F0F0F0F0Fl;
    And(rd, rd, scratch2);
    Mul64(rd, rd, value);
    srli(rd, rd, 32 + shift);
  }
}
#endif
void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DoubleRegister double_input,
                                                Label* done) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  // if scratch == 1, exception happens during truncation
  Trunc_w_d(result, double_input, scratch);
  // If we had no exceptions (i.e., scratch==1) we are done.
  Branch(done, eq, scratch, Operand(1));
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode) {
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub
  // instead.
  push(ra);
  SubWord(sp, sp, Operand(kDoubleSize));  // Put input on stack.
  fsd(double_input, sp, 0);
#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }
  LoadWord(result, MemOperand(sp, 0));

  AddWord(sp, sp, Operand(kDoubleSize));
  pop(ra);

  bind(&done);
}

// BRANCH_ARGS_CHECK checks that conditional jump arguments are correct.
#define BRANCH_ARGS_CHECK(cond, rs, rt)                                  \
  DCHECK((cond == cc_always && rs == zero_reg && rt.rm() == zero_reg) || \
         (cond != cc_always && (rs != zero_reg || rt.rm() != zero_reg)))

void MacroAssembler::Branch(int32_t offset) {
  DCHECK(is_int21(offset));
  BranchShort(offset);
}

void MacroAssembler::Branch(int32_t offset, Condition cond, Register rs,
                            const Operand& rt, Label::Distance distance) {
  bool is_near = BranchShortCheck(offset, nullptr, cond, rs, rt);
  DCHECK(is_near);
  USE(is_near);
}

void MacroAssembler::Branch(Label* L) {
  if (L->is_bound()) {
    if (is_near(L)) {
      BranchShort(L);
    } else {
      BranchLong(L);
    }
  } else {
    if (is_trampoline_emitted()) {
      BranchLong(L);
    } else {
      BranchShort(L);
    }
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rs,
                            const Operand& rt, Label::Distance distance) {
  if (L->is_bound()) {
    if (!BranchShortCheck(0, L, cond, rs, rt)) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rs, rt);
        BranchLong(L);
        bind(&skip);
      } else {
        BranchLong(L);
        EmitConstPoolWithJumpIfNeeded();
      }
    }
  } else {
    if (is_trampoline_emitted() && distance == Label::Distance::kFar) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rs, rt);
        BranchLong(L);
        bind(&skip);
      } else {
        BranchLong(L);
        EmitConstPoolWithJumpIfNeeded();
      }
    } else {
      BranchShort(L, cond, rs, rt);
    }
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rs,
                            RootIndex index, Label::Distance distance) {
  UseScratchRegisterScope temps(this);
  Register right = temps.Acquire();
  if (COMPRESS_POINTERS_BOOL) {
    Register left = rs;
    if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
        is_int12(ReadOnlyRootPtr(index))) {
      left = temps.Acquire();
      Sll32(left, rs, 0);
    }
    LoadTaggedRoot(right, index);
    Branch(L, cond, left, Operand(right));
  } else {
    LoadRoot(right, index);
    Branch(L, cond, rs, Operand(right));
  }
}

void MacroAssembler::CompareTaggedAndBranch(Label* label, Condition cond,
                                            Register r1, const Operand& r2,
                                            bool need_link) {
  if (COMPRESS_POINTERS_BOOL) {
    UseScratchRegisterScope temps(this);
    Register scratch0 = temps.Acquire();
    Sll32(scratch0, r1, 0);
    if (IsZero(r2)) {
      Branch(label, cond, scratch0, Operand(zero_reg));
    } else {
      Register scratch1 = temps.Acquire();
      if (r2.is_reg()) {
        Sll32(scratch1, r2.rm(), 0);
      } else {
        li(scratch1, r2);
        Sll32(scratch1, scratch1, 0);
      }
      Branch(label, cond, scratch0, Operand(scratch1));
    }
  } else {
    Branch(label, cond, r1, r2);
  }
}

void MacroAssembler::BranchShortHelper(int32_t offset, Label* L) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset21);
  j(offset);
}

void MacroAssembler::BranchShort(int32_t offset) {
  DCHECK(is_int21(offset));
  BranchShortHelper(offset, nullptr);
}

void MacroAssembler::BranchShort(Label* L) { BranchShortHelper(0, L); }

int32_t MacroAssembler::GetOffset(int32_t offset, Label* L, OffsetSize bits) {
  if (L) {
    offset = branch_offset_helper(L, bits);
  } else {
    DCHECK(is_intn(offset, bits));
  }
  return offset;
}

Register MacroAssembler::GetRtAsRegisterHelper(const Operand& rt,
                                               Register scratch) {
  Register r2 = no_reg;
  if (rt.is_reg()) {
    r2 = rt.rm();
  } else {
    r2 = scratch;
    li(r2, rt);
  }

  return r2;
}

bool MacroAssembler::CalculateOffset(Label* L, int32_t* offset,
                                     OffsetSize bits) {
  if (!is_near(L, bits)) return false;
  *offset = GetOffset(*offset, L, bits);
  return true;
}

bool MacroAssembler::CalculateOffset(Label* L, int32_t* offset, OffsetSize bits,
                                     Register* scratch, const Operand& rt) {
  if (!is_near(L, bits)) return false;
  *scratch = GetRtAsRegisterHelper(rt, *scratch);
  *offset = GetOffset(*offset, L, bits);
  return true;
}

bool MacroAssembler::BranchShortHelper(int32_t offset, Label* L, Condition cond,
                                       Register rs, const Operand& rt) {
  DCHECK(L == nullptr || offset == 0);
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = no_reg;
  if (!rt.is_reg()) {
    if (rt.immediate() == 0) {
      scratch = zero_reg;
    } else {
      scratch = temps.Acquire();
      li(scratch, rt);
    }
  } else {
    scratch = rt.rm();
  }
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    switch (cond) {
      case cc_always:
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
        j(offset);
        EmitConstPoolWithJumpIfNeeded();
        break;
      case eq:
        // rs == rt
        if (rt.is_reg() && rs == rt.rm()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          j(offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          beq(rs, scratch, offset);
        }
        break;
      case ne:
        // rs != rt
        if (rt.is_reg() && rs == rt.rm()) {
          break;  // No code needs to be emitted
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          bne(rs, scratch, offset);
        }
        break;

      // Signed comparison.
      case greater:
        // rs > rt
        if (rt.is_reg() && rs == rt.rm()) {
          break;  // No code needs to be emitted.
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          bgt(rs, scratch, offset);
        }
        break;
      case greater_equal:
        // rs >= rt
        if (rt.is_reg() && rs == rt.rm()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          j(offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          bge(rs, scratch, offset);
        }
        break;
      case less:
        // rs < rt
        if (rt.is_reg() && rs == rt.rm()) {
          break;  // No code needs to be emitted.
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          blt(rs, scratch, offset);
        }
        break;
      case less_equal:
        // rs <= rt
        if (rt.is_reg() && rs == rt.rm()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          j(offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          ble(rs, scratch, offset);
        }
        break;

      // Unsigned comparison.
      case Ugreater:
        // rs > rt
        if (rt.is_reg() && rs == rt.rm()) {
          break;  // No code needs to be emitted.
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          bgtu(rs, scratch, offset);
        }
        break;
      case Ugreater_equal:
        // rs >= rt
        if (rt.is_reg() && rs == rt.rm()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          j(offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          bgeu(rs, scratch, offset);
        }
        break;
      case Uless:
        // rs < rt
        if (rt.is_reg() && rs == rt.rm()) {
          break;  // No code needs to be emitted.
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          bltu(rs, scratch, offset);
        }
        break;
      case Uless_equal:
        // rs <= rt
        if (rt.is_reg() && rs == rt.rm()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          j(offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
          bleu(rs, scratch, offset);
        }
        break;
      case Condition::overflow:
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
        bnez(rs, offset);
        break;
      case Condition::no_overflow:
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset13)) return false;
        beqz(rs, offset);
        break;
      default:
        UNREACHABLE();
    }
  }

  CheckTrampolinePoolQuick(1);
  return true;
}

bool MacroAssembler::BranchShortCheck(int32_t offset, Label* L, Condition cond,
                                      Register rs, const Operand& rt) {
  BRANCH_ARGS_CHECK(cond, rs, rt);

  if (!L) {
    DCHECK(is_int13(offset));
    return BranchShortHelper(offset, nullptr, cond, rs, rt);
  } else {
    DCHECK_EQ(offset, 0);
    return BranchShortHelper(0, L, cond, rs, rt);
  }
}

void MacroAssembler::BranchShort(int32_t offset, Condition cond, Register rs,
                                 const Operand& rt) {
  BranchShortCheck(offset, nullptr, cond, rs, rt);
}

void MacroAssembler::BranchShort(Label* L, Condition cond, Register rs,
                                 const Operand& rt) {
  BranchShortCheck(0, L, cond, rs, rt);
}

void MacroAssembler::BranchAndLink(int32_t offset) {
  BranchAndLinkShort(offset);
}

void MacroAssembler::BranchAndLink(int32_t offset, Condition cond, Register rs,
                                   const Operand& rt) {
  bool is_near = BranchAndLinkShortCheck(offset, nullptr, cond, rs, rt);
  DCHECK(is_near);
  USE(is_near);
}

void MacroAssembler::BranchAndLink(Label* L) {
  if (L->is_bound()) {
    if (is_near(L)) {
      BranchAndLinkShort(L);
    } else {
      BranchAndLinkLong(L);
    }
  } else {
    if (is_trampoline_emitted()) {
      BranchAndLinkLong(L);
    } else {
      BranchAndLinkShort(L);
    }
  }
}

void MacroAssembler::BranchAndLink(Label* L, Condition cond, Register rs,
                                   const Operand& rt) {
  if (L->is_bound()) {
    if (!BranchAndLinkShortCheck(0, L, cond, rs, rt)) {
      Label skip;
      Condition neg_cond = NegateCondition(cond);
      BranchShort(&skip, neg_cond, rs, rt);
      BranchAndLinkLong(L);
      bind(&skip);
    }
  } else {
    if (is_trampoline_emitted()) {
      Label skip;
      Condition neg_cond = NegateCondition(cond);
      BranchShort(&skip, neg_cond, rs, rt);
      BranchAndLinkLong(L);
      bind(&skip);
    } else {
      BranchAndLinkShortCheck(0, L, cond, rs, rt);
    }
  }
}

void MacroAssembler::BranchAndLinkShortHelper(int32_t offset, Label* L) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset21);
  jal(offset);
}

void MacroAssembler::BranchAndLinkShort(int32_t offset) {
  DCHECK(is_int21(offset));
  BranchAndLinkShortHelper(offset, nullptr);
}

void MacroAssembler::BranchAndLinkShort(Label* L) {
  BranchAndLinkShortHelper(0, L);
}

// Pre r6 we need to use a bgezal or bltzal, but they can't be used directly
// with the slt instructions. We could use sub or add instead but we would miss
// overflow cases, so we keep slt and add an intermediate third instruction.
bool MacroAssembler::BranchAndLinkShortHelper(int32_t offset, Label* L,
                                              Condition cond, Register rs,
                                              const Operand& rt) {
  DCHECK(L == nullptr || offset == 0);
  if (!is_near(L, OffsetSize::kOffset21)) return false;

  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);

  if (cond == cc_always) {
    offset = GetOffset(offset, L, OffsetSize::kOffset21);
    jal(offset);
  } else {
    Branch(kInstrSize * 2, NegateCondition(cond), rs,
           Operand(GetRtAsRegisterHelper(rt, scratch)));
    offset = GetOffset(offset, L, OffsetSize::kOffset21);
    jal(offset);
  }

  return true;
}

bool MacroAssembler::BranchAndLinkShortCheck(int32_t offset, Label* L,
                                             Condition cond, Register rs,
                                             const Operand& rt) {
  BRANCH_ARGS_CHECK(cond, rs, rt);

  if (!L) {
    DCHECK(is_int21(offset));
    return BranchAndLinkShortHelper(offset, nullptr, cond, rs, rt);
  } else {
    DCHECK_EQ(offset, 0);
    return BranchAndLinkShortHelper(0, L, cond, rs, rt);
  }
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(destination,
                  FieldMemOperand(destination, FixedArray::OffsetOfElementAt(
                                                   constant_index)));
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  LoadWord(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  StoreWord(value, MemOperand(kRootRegister, offset));
}

MemOperand MacroAssembler::ExternalReferenceAsOperand(
    ExternalReference reference, Register scratch) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      return MemOperand(kRootRegister, reference.offset_from_root_register());
    }
    if (options().enable_root_relative_access) {
      int64_t offset =
          RootRegisterOffsetForExternalReference(isolate(), reference);
      if (is_int32(offset)) {
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      }
    }
    if (root_array_available_ && options().isolate_independent_code) {
      if (IsAddressableThroughRootRegister(isolate(), reference)) {
        // Some external references can be efficiently loaded as an offset from
        // kRootRegister.
        intptr_t offset =
            RootRegisterOffsetForExternalReference(isolate(), reference);
        CHECK(is_int32(offset));
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      } else {
        // Otherwise, do a memory load from the external reference table.
        DCHECK(scratch.is_valid());
        LoadWord(scratch,
                 MemOperand(kRootRegister,
                            RootRegisterOffsetForExternalReferenceTableEntry(
                                isolate(), reference)));
        return MemOperand(scratch, 0);
      }
    }
  }
  DCHECK(scratch.is_valid());
  li(scratch, reference);
  return MemOperand(scratch, 0);
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    Move(destination, kRootRegister);
  } else {
    AddWord(destination, kRootRegister, Operand(offset));
  }
}

void MacroAssembler::Jump(Register target, Condition cond, Register rs,
                          const Operand& rt) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (cond == cc_always) {
    jr(target);
    ForceConstantPoolEmissionWithoutJump();
  } else {
    BRANCH_ARGS_CHECK(cond, rs, rt);
    Branch(kInstrSize * 2, NegateCondition(cond), rs, rt);
    jr(target);
  }
}

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond, Register rs, const Operand& rt) {
  Label skip;
  if (cond != cc_always) {
    Branch(&skip, NegateCondition(cond), rs, rt);
  }
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    li(t6, Operand(target, rmode));
    Jump(t6, al, zero_reg, Operand(zero_reg));
    EmitConstPoolWithJumpIfNeeded();
    bind(&skip);
  }
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode, Condition cond,
                          Register rs, const Operand& rt) {
  DCHECK(!RelocInfo::IsCodeTarget(rmode));
  Jump(static_cast<intptr_t>(target), rmode, cond, rs, rt);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, Register rs, const Operand& rt) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    // Inline the trampoline.
    Label skip;
    if (cond != al) Branch(&skip, NegateCondition(cond), rs, rt);
    TailCallBuiltin(builtin);
    bind(&skip);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  if (CanUseNearCallOrJump(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(code);
    DCHECK(is_int32(index));
    Label skip;
    if (cond != al) Branch(&skip, NegateCondition(cond), rs, rt);
    RecordRelocInfo(RelocInfo::RELATIVE_CODE_TARGET,
                    static_cast<int32_t>(index));
    GenPCRelativeJump(t6, static_cast<int32_t>(index));
    bind(&skip);
  } else {
    Jump(code.address(), rmode, cond);
  }
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  li(t6, reference);
  Jump(t6);
}

// Note: To call gcc-compiled C code on riscv64, you must call through t6.
void MacroAssembler::Call(Register target, Condition cond, Register rs,
                          const Operand& rt) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (cond == cc_always) {
    jalr(ra, target, 0);
  } else {
    BRANCH_ARGS_CHECK(cond, rs, rt);
    Branch(kInstrSize * 2, NegateCondition(cond), rs, rt);
    jalr(ra, target, 0);
  }
}

void MacroAssembler::CompareTaggedRootAndBranch(const Register& obj,
                                                RootIndex index, Condition cc,
                                                Label* target) {
  ASM_CODE_COMMENT(this);
  AssertSmiOrHeapObjectInMainCompressionCage(obj);
  UseScratchRegisterScope temps(this);
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index)) {
    CompareTaggedAndBranch(target, cc, obj, Operand(ReadOnlyRootPtr(index)));
    return;
  }
  // Some smi roots contain system pointer size values like stack limits.
  DCHECK(base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                         RootIndex::kLastStrongOrReadOnlyRoot));
  Register temp = temps.Acquire();
  DCHECK(!AreAliased(obj, temp));
  LoadRoot(temp, index);
  CompareTaggedAndBranch(target, cc, obj, Operand(temp));
}
// Compare the object in a register to a value from the root list.
void MacroAssembler::CompareRootAndBranch(const Register& obj, RootIndex index,
                                          Condition cc, Label* target,
                                          ComparisonMode mode) {
  ASM_CODE_COMMENT(this);
  if (mode == ComparisonMode::kFullPointer ||
      !base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                       RootIndex::kLastStrongOrReadOnlyRoot)) {
    // Some smi roots contain system pointer size values like stack limits.
    UseScratchRegisterScope temps(this);
    Register temp = temps.Acquire();
    DCHECK(!AreAliased(obj, temp));
    LoadRoot(temp, index);
    Branch(target, cc, obj, Operand(temp));
    return;
  }
  CompareTaggedRootAndBranch(obj, index, cc, target);
}
#if V8_TARGET_ARCH_RISCV64
// Compare the tagged object in a register to a value from the root list
// and put 0 into result if equal or 1 otherwise.
void MacroAssembler::CompareTaggedRoot(const Register& with, RootIndex index,
                                       const Register& result) {
  ASM_CODE_COMMENT(this);
  AssertSmiOrHeapObjectInMainCompressionCage(with);
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index)) {
    Li(result, ReadOnlyRootPtr(index));
    MacroAssembler::CmpTagged(result, with, result);
    return;
  }
  // Some smi roots contain system pointer size values like stack limits.
  DCHECK(base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                         RootIndex::kLastStrongOrReadOnlyRoot));
  LoadRoot(result, index);
  MacroAssembler::CmpTagged(result, with, result);
}

void MacroAssembler::CompareRoot(const Register& obj, RootIndex index,
                                 const Register& result, ComparisonMode mode) {
  ASM_CODE_COMMENT(this);
  if (mode == ComparisonMode::kFullPointer ||
      !base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                       RootIndex::kLastStrongOrReadOnlyRoot)) {
    // Some smi roots contain system pointer size values like stack limits.
    UseScratchRegisterScope temps(this);
    Register temp = temps.Acquire();
    DCHECK(!AreAliased(obj, temp));
    LoadRoot(temp, index);
    CompareI(result, obj, Operand(temp),
             Condition::ne);  // result is 0 if equal or 1 otherwise
    return;
  }
  // FIXME: check that 0/1 in result is expected for all CompareRoot callers
  CompareTaggedRoot(obj, index, result);
}
#endif

void MacroAssembler::JumpIfIsInRange(Register value, unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  if (lower_limit != 0) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    SubWord(scratch, value, Operand(lower_limit));
    Branch(on_in_range, Uless_equal, scratch,
           Operand(higher_limit - lower_limit));
  } else {
    Branch(on_in_range, Uless_equal, value,
           Operand(higher_limit - lower_limit));
  }
}

// The calculated offset is either:
// * the 'target' input unmodified if this is a Wasm call, or
// * the offset of the target from the current PC, in instructions, for any
//   other type of call.
int64_t MacroAssembler::CalculateTargetOffset(Address target,
                                              RelocInfo::Mode rmode,
                                              uint8_t* pc) {
  int64_t offset = static_cast<int64_t>(target);
  if (rmode == RelocInfo::WASM_CALL || rmode == RelocInfo::WASM_STUB_CALL) {
    // The target of WebAssembly calls is still an index instead of an actual
    // address at this point, and needs to be encoded as-is.
    return offset;
  }
  offset -= reinterpret_cast<int64_t>(pc);
  DCHECK_EQ(offset % kInstrSize, 0);
  return offset;
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode, Condition cond,
                          Register rs, const Operand& rt) {
  ASM_CODE_COMMENT(this);
  if (CanUseNearCallOrJump(rmode)) {
    int64_t offset = CalculateTargetOffset(target, rmode, pc_);
    DCHECK(is_int32(offset));
    near_call(static_cast<int>(offset), rmode);
  } else {
    li(t6, Operand(static_cast<intptr_t>(target), rmode), ADDRESS_LOAD);
    Call(t6, cond, rs, rt);
  }
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, Register rs, const Operand& rt) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    // Inline the trampoline.
    CHECK_EQ(cond, Condition::al);  // Implement if necessary.
    CallBuiltin(builtin);
    return;
  }

  DCHECK(RelocInfo::IsCodeTarget(rmode));

  if (CanUseNearCallOrJump(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(code);
    DCHECK(is_int32(index));
    Label skip;
    if (cond != al) Branch(&skip, NegateCondition(cond), rs, rt);
    RecordRelocInfo(RelocInfo::RELATIVE_CODE_TARGET,
                    static_cast<int32_t>(index));
    GenPCRelativeJumpAndLink(t6, static_cast<int32_t>(index));
    bind(&skip);
  } else {
    Call(code.address(), rmode);
  }
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
#if V8_TARGET_ARCH_RISCV64
  static_assert(kSystemPointerSize == 8);
#elif V8_TARGET_ARCH_RISCV32
  static_assert(kSystemPointerSize == 4);
#endif
  static_assert(kSmiTagSize == 1);
  static_assert(kSmiTag == 0);

  // The builtin register contains the builtin index as a Smi.
  SmiUntag(target, builtin_index);
  CalcScaledAddress(target, kRootRegister, target, kSystemPointerSizeLog2);
  LoadWord(target,
           MemOperand(target, IsolateData::builtin_entry_table_offset()));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}

void MacroAssembler::CallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(t6, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(t6);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      near_call(static_cast<int>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, t6);
      Call(t6);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        EmbeddedObjectIndex index = AddEmbeddedObject(code);
        DCHECK(is_int32(index));
        RecordRelocInfo(RelocInfo::RELATIVE_CODE_TARGET,
                        static_cast<int32_t>(index));
        GenPCRelativeJumpAndLink(t6, static_cast<int32_t>(index));
      } else {
        LoadEntryFromBuiltin(builtin, t6);
        Call(t6);
      }
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond,
                                     Register type, Operand range) {
  Label done;
  Branch(&done, NegateCondition(cond), type, range);
  TailCallBuiltin(builtin);
  bind(&done);
}

void MacroAssembler::TailCallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(t6, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Jump(t6);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      near_jump(static_cast<int>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, t6);
      Jump(t6);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        EmbeddedObjectIndex index = AddEmbeddedObject(code);
        DCHECK(is_int32(index));
        RecordRelocInfo(RelocInfo::RELATIVE_CODE_TARGET,
                        static_cast<int32_t>(index));
        GenPCRelativeJump(t6, static_cast<int32_t>(index));
      } else {
        LoadEntryFromBuiltin(builtin, t6);
        Jump(t6);
      }
      break;
    }
  }
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  LoadWord(destination, EntryFromBuiltinAsOperand(builtin));
}

MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::PatchAndJump(Address target) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  auipc(scratch, 0);  // Load PC into scratch
  LoadWord(t6, MemOperand(scratch, kInstrSize * 4));
  jr(t6);
  nop();  // For alignment
#if V8_TARGET_ARCH_RISCV64
  DCHECK_EQ(reinterpret_cast<uint64_t>(pc_) % 8, 0);
#elif V8_TARGET_ARCH_RISCV32
  DCHECK_EQ(reinterpret_cast<uint32_t>(pc_) % 4, 0);
#endif
  *reinterpret_cast<uintptr_t*>(pc_) = target;  // pc_ should be align.
  pc_ += sizeof(uintptr_t);
}

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.
  //
  // Compute the return address in lr to return to after the jump below. The
  // pc is already at '+ 8' from the current instruction; but return is after
  // three instructions, so add another 4 to pc to get the return address.
  //
  Assembler::BlockTrampolinePoolScope block_trampoline_pool(this);
  int kNumInstructionsToJump = 5;
  if (v8_flags.riscv_c_extension) kNumInstructionsToJump = 4;
  Label find_ra;
  // Adjust the value in ra to point to the correct return location, one
  // instruction past the real call into C code (the jalr(t6)), and push it.
  // This is the return address of the exit frame.
  auipc(ra, 0);  // Set ra the current PC
  bind(&find_ra);
  addi(ra, ra,
       (kNumInstructionsToJump + 1) *
           kInstrSize);  // Set ra to insn after the call

  // This spot was reserved in EnterExitFrame.
  StoreWord(ra, MemOperand(sp));
  addi(sp, sp, -kCArgsSlotsSize);
  // Stack is still aligned.

  // Call the C routine.
  Mv(t6,
     target);  // Function pointer to t6 to conform to ABI for PIC.
  jalr(t6);
  // Make sure the stored 'ra' points to this position.
  DCHECK_EQ(kNumInstructionsToJump, InstructionsGeneratedSince(&find_ra));
}

void MacroAssembler::Ret(Condition cond, Register rs, const Operand& rt) {
  Jump(ra, cond, rs, rt);
  if (cond == al) {
    ForceConstantPoolEmissionWithoutJump();
  }
}

void MacroAssembler::BranchLong(Label* L) {
  // Generate position independent long branch.
  BlockTrampolinePoolScope block_trampoline_pool(this);
  int32_t imm;
  imm = branch_long_offset(L);
  if (L->is_bound() && is_intn(imm, Assembler::kJumpOffsetBits) &&
      (imm & 1) == 0) {
    j(imm);
    nop();
    EmitConstPoolWithJumpIfNeeded();
    return;
  }
  GenPCRelativeJump(t6, imm);
  EmitConstPoolWithJumpIfNeeded();
}

void MacroAssembler::BranchAndLinkLong(Label* L) {
  // Generate position independent long branch and link.
  BlockTrampolinePoolScope block_trampoline_pool(this);
  int32_t imm;
  imm = branch_long_offset(L);
  if (L->is_bound() && is_intn(imm, Assembler::kJumpOffsetBits) &&
      (imm & 1) == 0) {
    jal(t6, imm);
    nop();
    return;
  }
  GenPCRelativeJumpAndLink(t6, imm);
}

void MacroAssembler::DropAndRet(int drop) {
  AddWord(sp, sp, drop * kSystemPointerSize);
  Ret();
}

void MacroAssembler::DropAndRet(int drop, Condition cond, Register r1,
                                const Operand& r2) {
  // Both Drop and Ret need to be conditional.
  Label skip;
  if (cond != cc_always) {
    Branch(&skip, NegateCondition(cond), r1, r2);
  }

  Drop(drop);
  Ret();

  if (cond != cc_always) {
    bind(&skip);
  }
}

void MacroAssembler::Drop(int count, Condition cond, Register reg,
                          const Operand& op) {
  if (count <= 0) {
    return;
  }

  Label skip;

  if (cond != al) {
    Branch(&skip, NegateCondition(cond), reg, op);
  }

  AddWord(sp, sp, Operand(count * kSystemPointerSize));

  if (cond != al) {
    bind(&skip);
  }
}

void MacroAssembler::Swap(Register reg1, Register reg2, Register scratch) {
  if (scratch == no_reg) {
    Xor(reg1, reg1, Operand(reg2));
    Xor(reg2, reg2, Operand(reg1));
    Xor(reg1, reg1, Operand(reg2));
  } else {
    Mv(scratch, reg1);
    Mv(reg1, reg2);
    Mv(reg2, scratch);
  }
}

void MacroAssembler::Call(Label* target) { BranchAndLink(target); }

void MacroAssembler::LoadAddress(Register dst, Label* target,
                                 RelocInfo::Mode rmode) {
  int32_t offset;
  if (CalculateOffset(target, &offset, OffsetSize::kOffset32)) {
    CHECK(is_int32(offset + 0x800));
    int32_t Hi20 = (((int32_t)offset + 0x800) >> 12);
    int32_t Lo12 = (int32_t)offset << 20 >> 20;
    BlockTrampolinePoolScope block_trampoline_pool(this);
    auipc(dst, Hi20);
    addi(dst, dst, Lo12);
  } else {
    uintptr_t address = jump_address(target);
    li(dst, Operand(address, rmode), ADDRESS_LOAD);
  }
}

void MacroAssembler::Switch(Register scratch, Register value,
                            int case_value_base, Label** labels,
                            int num_labels) {
  Register table = scratch;
  Label fallthrough, jump_table;
  if (case_value_base != 0) {
    SubWord(value, value, Operand(case_value_base));
  }
  Branch(&fallthrough, Condition::Ugreater_equal, value, Operand(num_labels));
  LoadAddress(table, &jump_table);
  CalcScaledAddress(table, table, value, kSystemPointerSizeLog2);
  LoadWord(table, MemOperand(table, 0));
  Jump(table);
  // Calculate label area size and let MASM know that it will be impossible to
  // create the trampoline within the range. That forces MASM to create the
  // trampoline right here if necessary, i.e. if label area is too large and
  // all unbound forward branches cannot be bound over it. Use nop() because the
  // trampoline cannot be emitted right after Jump().
  nop();
  static constexpr int mask = kInstrSize - 1;
  int aligned_label_area_size = num_labels * kUIntptrSize + kSystemPointerSize;
  int instructions_per_label_area =
      ((aligned_label_area_size + mask) & ~mask) >> kInstrSizeLog2;
  BlockTrampolinePoolFor(instructions_per_label_area);
  // Emit the jump table inline, under the assumption that it's not too big.
  Align(kSystemPointerSize);
  bind(&jump_table);
  for (int i = 0; i < num_labels; ++i) {
    dd(labels[i]);
  }
  bind(&fallthrough);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(smi));
  push(scratch);
}

void MacroAssembler::Push(Tagged<TaggedIndex> index) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(static_cast<uint32_t>(index.ptr())));
  push(scratch);
}

void MacroAssembler::PushArray(Register array, Register size,
                               PushArrayOrder order) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    Mv(scratch, zero_reg);
    jmp(&entry);
    bind(&loop);
    CalcScaledAddress(scratch2, array, scratch, kSystemPointerSizeLog2);
    LoadWord(scratch2, MemOperand(scratch2));
    push(scratch2);
    AddWord(scratch, scratch, Operand(1));
    bind(&entry);
    Branch(&loop, less, scratch, Operand(size));
  } else {
    Mv(scratch, size);
    jmp(&entry);
    bind(&loop);
    CalcScaledAddress(scratch2, array, scratch, kSystemPointerSizeLog2);
    LoadWord(scratch2, MemOperand(scratch2));
    push(scratch2);
    bind(&entry);
    AddWord(scratch, scratch, Operand(-1));
    Branch(&loop, greater_equal, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::Push(Handle<HeapObject> handle) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(handle));
  push(scratch);
}

// ---------------------------------------------------------------------------
// Exception handling.

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize);

  Push(Smi::zero());  // Padding.

  // Link the current handler as the next handler.
  UseScratchRegisterScope temps(this);
  Register handler_address = temps.Acquire();
  li(handler_address,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  Register handler = temps.Acquire();
  LoadWord(handler, MemOperand(handler_address));
  push(handler);

  // Set this new handler as the current one.
  StoreWord(sp, MemOperand(handler_address));
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kNextOffset == 0);
  pop(a1);
  AddWord(sp, sp,
          Operand(static_cast<intptr_t>(StackHandlerConstants::kSize -
                                        kSystemPointerSize)));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  StoreWord(a1, MemOperand(scratch));
}

void MacroAssembler::FPUCanonicalizeNaN(const DoubleRegister dst,
                                        const DoubleRegister src) {
  // Subtracting 0.0 preserves all inputs except for signalling NaNs, which
  // become quiet NaNs. We use fsub rather than fadd because fsub preserves -0.0
  // inputs: -0.0 + 0.0 = 0.0, but -0.0 - 0.0 = -0.0.
  if (!IsDoubleZeroRegSet()) {
    LoadFPRImmediate(kDoubleRegZero, 0.0);
  }
  fsub_d(dst, src, kDoubleRegZero);
}

void MacroAssembler::MovFromFloatResult(const DoubleRegister dst) {
  Move(dst, fa0);  // Reg fa0 is FP return value.
}

void MacroAssembler::MovFromFloatParameter(const DoubleRegister dst) {
  Move(dst, fa0);  // Reg fa0 is FP first argument value.
}

void MacroAssembler::MovToFloatParameter(DoubleRegister src) { Move(fa0, src); }

void MacroAssembler::MovToFloatResult(DoubleRegister src) { Move(fa0, src); }

void MacroAssembler::MovToFloatParameters(DoubleRegister src1,
                                          DoubleRegister src2) {
  const DoubleRegister fparg2 = fa1;
  if (src2 == fa0) {
    DCHECK(src1 != fparg2);
    Move(fparg2, src2);
    Move(fa0, src1);
  } else {
    Move(fa0, src1);
    Move(fparg2, src2);
  }
}

// -----------------------------------------------------------------------------
// JavaScript invokes.

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();
  LoadWord(destination,
           MemOperand(kRootRegister, static_cast<int32_t>(offset)));
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch1,
                                        Register scratch2,
                                        Label* stack_overflow, Label* done) {
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  DCHECK(stack_overflow != nullptr || done != nullptr);
  LoadStackLimit(scratch1, StackLimitKind::kRealStackLimit);
  // Make scratch1 the space we have left. The stack might already be overflowed
  // here which will cause scratch1 to become negative.
  SubWord(scratch1, sp, scratch1);
  // Check if the arguments will overflow the stack.
  SllWord(scratch2, num_args, kSystemPointerSizeLog2);
  // Signed comparison.
  if (stack_overflow != nullptr) {
    Branch(stack_overflow, le, scratch1, Operand(scratch2));
  } else if (done != nullptr) {
    Branch(done, gt, scratch1, Operand(scratch2));
  } else {
    UNREACHABLE();
  }
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  Label regular_invoke;

  //  a0: actual arguments count
  //  a1: function (passed through to callee)
  //  a2: expected arguments count

  DCHECK_EQ(actual_parameter_count, a0);
  DCHECK_EQ(expected_parameter_count, a2);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  SubWord(expected_parameter_count, expected_parameter_count,
          actual_parameter_count);
  Branch(&regular_invoke, le, expected_parameter_count, Operand(zero_reg));

  Label stack_overflow;
  {
    UseScratchRegisterScope temps(this);
    StackOverflowCheck(expected_parameter_count, temps.Acquire(),
                       temps.Acquire(), &stack_overflow);
  }
  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy;
    Register src = a6, dest = a7;
    Move(src, sp);
    SllWord(t0, expected_parameter_count, kSystemPointerSizeLog2);
    SubWord(sp, sp, Operand(t0));
    // Update stack pointer.
    Move(dest, sp);
    Move(t0, actual_parameter_count);
    bind(&copy);
    LoadWord(t1, MemOperand(src, 0));
    StoreWord(t1, MemOperand(dest, 0));
    SubWord(t0, t0, Operand(1));
    AddWord(src, src, Operand(kSystemPointerSize));
    AddWord(dest, dest, Operand(kSystemPointerSize));
    Branch(&copy, gt, t0, Operand(zero_reg));
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(t0, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    StoreWord(t0, MemOperand(a7, 0));
    SubWord(expected_parameter_count, expected_parameter_count, Operand(1));
    AddWord(a7, a7, Operand(kSystemPointerSize));
    Branch(&loop, gt, expected_parameter_count, Operand(zero_reg));
  }
  Branch(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    break_(0xCC);
  }
  bind(&regular_invoke);
}

void MacroAssembler::CheckDebugHook(Register fun, Register new_target,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count) {
  Label skip_hook;
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch,
       ExternalReference::debug_hook_on_function_call_address(isolate()));
    Lb(scratch, MemOperand(scratch));
    Branch(&skip_hook, eq, scratch, Operand(zero_reg));
  }
  {
    // Load receiver to pass it later to DebugOnFunctionCall hook.
    UseScratchRegisterScope temps(this);
    Register receiver = temps.Acquire();
    LoadReceiver(receiver);

    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    SmiTag(expected_parameter_count);
    Push(expected_parameter_count);

    SmiTag(actual_parameter_count);
    Push(actual_parameter_count);

    if (new_target.is_valid()) {
      Push(new_target);
    }
    Push(fun);
    Push(fun);
    Push(receiver);
    CallRuntime(Runtime::kDebugOnFunctionCall);
    Pop(fun);
    if (new_target.is_valid()) {
      Pop(new_target);
    }

    Pop(actual_parameter_count);
    SmiUntag(actual_parameter_count);

    Pop(expected_parameter_count);
    SmiUntag(expected_parameter_count);
  }
  bind(&skip_hook);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, a1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == a3);

  // On function call, call into the debugger if necessary.
  CheckDebugHook(function, new_target, expected_parameter_count,
                 actual_parameter_count);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(a3, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }

  // Continue here if InvokePrologue does handle the invocation due to
  // mismatched parameter counts.
  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);
  Register expected_parameter_count = a2;
  {
    UseScratchRegisterScope temps(this);
    Register temp_reg = temps.Acquire();
    LoadTaggedField(
        temp_reg,
        FieldMemOperand(function, JSFunction::kSharedFunctionInfoOffset));
    LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));
    // The argument count is stored as uint16_t
    Lhu(expected_parameter_count,
        FieldMemOperand(temp_reg,
                        SharedFunctionInfo::kFormalParameterCountOffset));
  }
  InvokeFunctionCode(function, new_target, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);

  // Get the function and setup the context.
  LoadTaggedField(cp, FieldMemOperand(a1, JSFunction::kContextOffset));

  InvokeFunctionCode(a1, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}

// ---------------------------------------------------------------------------
// Support functions.

void MacroAssembler::GetObjectType(Register object, Register map,
                                   Register type_reg) {
  LoadMap(map, object);
  Lhu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
}

void MacroAssembler::GetInstanceTypeRange(Register map, Register type_reg,
                                          InstanceType lower_limit,
                                          Register range) {
  Lhu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  SubWord(range, type_reg, Operand(lower_limit));
}
//------------------------------------------------------------------------------
// Wasm
void MacroAssembler::WasmRvvEq(VRegister dst, VRegister lhs, VRegister rhs,
                               VSew sew, Vlmul lmul) {
  VU.set(kScratchReg, sew, lmul);
  vmseq_vv(v0, lhs, rhs);
  li(kScratchReg, -1);
  vmv_vx(dst, zero_reg);
  vmerge_vx(dst, kScratchReg, dst);
}

void MacroAssembler::WasmRvvNe(VRegister dst, VRegister lhs, VRegister rhs,
                               VSew sew, Vlmul lmul) {
  VU.set(kScratchReg, sew, lmul);
  vmsne_vv(v0, lhs, rhs);
  li(kScratchReg, -1);
  vmv_vx(dst, zero_reg);
  vmerge_vx(dst, kScratchReg, dst);
}

void MacroAssembler::WasmRvvGeS(VRegister dst, VRegister lhs, VRegister rhs,
                                VSew sew, Vlmul lmul) {
  VU.set(kScratchReg, sew, lmul);
  vmsle_vv(v0, rhs, lhs);
  li(kScratchReg, -1);
  vmv_vx(dst, zero_reg);
  vmerge_vx(dst, kScratchReg, dst);
}

void MacroAssembler::WasmRvvGeU(VRegister dst, VRegister lhs, VRegister rhs,
                                VSew sew, Vlmul lmul) {
  VU.set(kScratchReg, sew, lmul);
  vmsleu_vv(v0, rhs, lhs);
  li(kScratchReg, -1);
  vmv_vx(dst, zero_reg);
  vmerge_vx(dst, kScratchReg, dst);
}

void MacroAssembler::WasmRvvGtS(VRegister dst, VRegister lhs, VRegister rhs,
                                VSew sew, Vlmul lmul) {
  VU.set(kScratchReg, sew, lmul);
  vmslt_vv(v0, rhs, lhs);
  li(kScratchReg, -1);
  vmv_vx(dst, zero_reg);
  vmerge_vx(dst, kScratchReg, dst);
}

void MacroAssembler::WasmRvvGtU(VRegister dst, VRegister lhs, VRegister rhs,
                                VSew sew, Vlmul lmul) {
  VU.set(kScratchReg, sew, lmul);
  vmsltu_vv(v0, rhs, lhs);
  li(kScratchReg, -1);
  vmv_vx(dst, zero_reg);
  vmerge_vx(dst, kScratchReg, dst);
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::WasmRvvS128const(VRegister dst, const uint8_t imms[16]) {
  uint64_t vals[2];
  memcpy(vals, imms, sizeof(vals));
  VU.set(kScratchReg, E64, m1);
  li(kScratchReg, vals[1]);
  vmv_sx(kSimd128ScratchReg, kScratchReg);
  vslideup_vi(dst, kSimd128ScratchR
```
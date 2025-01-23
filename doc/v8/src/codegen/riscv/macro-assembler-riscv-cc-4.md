Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/riscv/macro-assembler-riscv.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename and the content clearly indicate that this file is part of V8's code generation for the RISC-V architecture. It deals with low-level assembly instructions and provides an abstraction layer (`MacroAssembler`) for generating machine code.

2. **Analyze Key Functionalities by Code Sections:**  Go through the code snippets and group related functions. Look for patterns and common themes.

3. **Focus on Public Interface:** The `MacroAssembler` class provides a public interface for code generation. The functions within the snippet are likely part of this interface.

4. **Relate to JavaScript (if applicable):**  Consider how these low-level operations relate to higher-level JavaScript concepts. This often involves understanding how V8 represents data and executes code.

5. **Look for Conditional Compilation (`#if`)**: The presence of `#if V8_TARGET_ARCH_RISCV64` and `#elif V8_TARGET_ARCH_RISCV32` indicates that the code handles both 32-bit and 64-bit RISC-V architectures, with some platform-specific implementations.

6. **Identify Common Programming Errors:**  Think about scenarios where developers might misuse these low-level operations or how errors could manifest.

7. **Consider the "Part 5 of 9" Context:**  This suggests that this file is a larger piece, and this snippet focuses on a specific set of functionalities within the `MacroAssembler`.

8. **Address Specific Instructions in the Prompt:** The prompt specifically asks about `.tq` files (Torque) and to provide JavaScript examples if applicable.

**Pre-computation and Pre-analysis:**

* **`.tq` Files:** Remember that `.tq` files in V8 are related to Torque, a domain-specific language for generating C++ code, especially for built-in functions and runtime code. The prompt provides a direct condition for this.
* **JavaScript and Low-Level Code:**  Understand that the `MacroAssembler` is used internally by V8's compiler to translate JavaScript code into machine code. Specific operations like loading/storing values, performing arithmetic, and control flow have direct counterparts in assembly.
* **Common Programming Errors in Assembly:** Think about things like incorrect register usage, stack imbalances, and logic errors in conditional branches.

**Step-by-step thought process for summarizing the functionality:**

* **Initial Observation:** The code deals with manipulating data in registers and memory, specifically focusing on floating-point numbers (doubles and floats).
* **`InsertHighWordF64` and `InsertLowWordF64`:** These functions clearly deal with inserting the high and low 32-bit words into a 64-bit floating-point register. This is necessary because RISC-V has separate instructions for moving data between integer and floating-point registers. The code uses stack or temporary registers to achieve this.
* **`LoadFPRImmediate`:** This function focuses on loading immediate (constant) values into floating-point registers. It handles special cases like zero and negative zero efficiently. The conditional compilation shows different approaches for 32-bit and 64-bit architectures.
* **`CompareI`:**  This function implements various integer comparison operations and sets a destination register based on the comparison result. It maps high-level comparison conditions (`eq`, `ne`, `greater`, etc.) to RISC-V instructions.
* **`LoadZeroIfConditionNotZero` and `LoadZeroIfConditionZero`:** These functions conditionally load zero into a register based on whether another register is non-zero or zero. They demonstrate different implementations depending on the availability of the ZICOND extension.
* **`Clz32` and `Clz64`:** These functions calculate the number of leading zeros in a 32-bit or 64-bit value. Again, it shows optimized implementations if the ZBB extension is available, and fallback implementations using bitwise operations and branches.
* **`Ctz32` and `Ctz64`:** These functions calculate the number of trailing zeros. They cleverly reuse the `Clz` functionality after transforming the input.
* **`Popcnt32` and `Popcnt64`:** These functions count the number of set bits (population count). The code implements a standard bit manipulation algorithm, with different constants for 32-bit and 64-bit versions.
* **`TryInlineTruncateDoubleToI` and `TruncateDoubleToI`:** These functions convert a double-precision floating-point number to an integer. It first attempts an inline version and falls back to calling a runtime stub if the inline version fails (e.g., due to out-of-range values).
* **`Branch` and `BranchAndLink`:** These are fundamental control flow instructions. The code handles both short and long branches (to deal with larger code offsets), and conditional branches. The `BranchAndLink` versions also save the return address for function calls.
* **`LoadFromConstantsTable` and `LoadRootRelative`, `StoreRootRelative`:** These functions deal with accessing data stored in the V8 runtime's constant pool and root table. This is essential for accessing frequently used values and objects.
* **`ExternalReferenceAsOperand`:** This function handles the conversion of external references (pointers to data outside the current code) into memory operands, potentially using a root register for optimization.
* **`Jump`:**  Implements unconditional jumps, potentially with conditions. It shows how to jump to a register value, an absolute address, or a code object.

**Final Refinement:** Organize the identified functionalities into logical groups and write a concise summary, addressing all points in the user's prompt.
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
### 提示词
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共9部分，请归纳一下它的功能
```

### 源代码
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
```
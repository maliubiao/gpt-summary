Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is part of the V8 JavaScript engine and implements a RISC-V macro assembler.

My plan is to:
1. Identify the main purpose of the code.
2. List the key operations and instructions implemented.
3. Check if the code snippet relates to JavaScript functionality and provide an example if it does.
4. Look for code logic and provide an example with input and output.
5. Identify potential user programming errors related to this code.
6. Check if the file extension would be `.tq` and if it would be related to Torque.
7. Finally, summarize the functionality of the provided part of the code.
这是V8 JavaScript引擎中RISC-V架构的宏汇编器实现的一部分。

**功能列举:**

该代码片段主要实现了以下功能：

1. **算术运算指令:** 提供了加法 (`AddWord`, `Add64`, `Add32`) 和减法 (`SubWord`, `Sub64`, `Sub32`) 操作，支持寄存器与寄存器、寄存器与立即数的不同操作数形式。同时考虑了RISC-V C扩展指令集以优化代码大小和性能。
2. **乘法指令:** 提供了32位和64位的乘法操作 (`Mul32`, `Mulh32`, `Mulhu32`, `Mul64`, `Mulh64`, `Mulhu64`)。
3. **除法和取模指令:** 提供了32位和64位的除法 (`Div32`, `Div64`, `Divu32`, `Divu64`) 和取模 (`Mod32`, `Mod64`, `Modu32`, `Modu64`) 操作。
4. **逻辑运算指令:** 实现了与 (`And`)、或 (`Or`)、异或 (`Xor`)、或非 (`Nor`) 等逻辑运算。
5. **比较指令:** 提供了各种比较指令，如等于 (`Seq`, `Seqz`)、不等于 (`Sne`, `Snez`)、小于 (`Slt`, `Sltu`)、小于等于 (`Sle`, `Sleu`)、大于等于 (`Sge`, `Sgeu`)、大于 (`Sgt`, `Sgtu`)。
6. **移位指令:** 实现了左移 (`SllWord`, `Sll32`, `Sll64`)、算术右移 (`SraWord`, `Sra32`, `Sra64`) 和逻辑右移 (`SrlWord`, `Srl32`, `Srl64`)。对于RISC-V64架构，还提供了循环右移 (`Ror`, `Dror`) 操作。
7. **加载立即数指令:** 提供了加载立即数的便捷指令 `Li`，它会根据立即数的大小和C扩展是否启用选择合适的指令。
8. **移动指令:** 提供了寄存器移动指令 `Mv`，同样考虑了C扩展。
9. **计算缩放地址:** 提供了 `CalcScaledAddress` 函数，用于计算基于寄存器和缩放因子的内存地址。
10. **字节序转换:** 提供了 `ByteSwap` 函数，用于进行字节序转换，针对RISC-V64和RISC-V32架构有不同的实现，并考虑了Zbb扩展。

**关于 .tq 结尾:**

如果 `v8/src/codegen/riscv/macro-assembler-riscv.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。 Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的汇编代码。 但根据提供的信息，该文件以 `.cc` 结尾，所以它是 C++ 源代码。

**与 JavaScript 的关系 (示例):**

宏汇编器生成的汇编代码最终会执行 JavaScript 代码。例如，一个简单的 JavaScript 加法操作 `a + b`：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3);
```

V8 编译这段 JavaScript 代码时，`MacroAssembler::AddWord` 或 `MacroAssembler::Add64` (取决于 `a` 和 `b` 的类型)  这样的函数会被调用，生成相应的 RISC-V 加法汇编指令，将 `a` 和 `b` 的值加载到寄存器中，执行加法，并将结果存储起来。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `MacroAssembler::AddWord(rd, rs, Operand(10))`，其中 `rd` 和 `rs` 是 RISC-V 寄存器，例如 `x10` 和 `x11`。

* **假设输入:** `rd = x10`, `rs = x11`, `rt = Operand(10)`
* **代码逻辑:**  因为 `rt` 是立即数 10，且在 `is_int12` 的范围内，代码会执行 `addi(rd, rs, 10)`。
* **假设输出:** 生成的汇编指令会将寄存器 `x11` 的值加上 10，并将结果存储到寄存器 `x10` 中。

**用户常见的编程错误 (举例):**

一个常见的编程错误是在使用立即数时超出指令支持的范围。例如，`addi` 指令的立即数是 12 位有符号数。如果用户尝试使用超出这个范围的立即数，例如 `Operand(0xFFFFFFFF)`，那么 `MacroAssembler::AddWord` 函数会使用 `li` 指令将立即数加载到临时寄存器，然后再进行加法操作。 但是，如果用户直接假设可以使用超出范围的立即数，可能会导致生成的汇编代码不正确或效率低下。

**归纳功能 (第2部分):**

这部分代码主要专注于实现 RISC-V 架构的基本算术、逻辑、比较和移位运算的宏指令。它提供了用于生成这些指令的 C++ 接口，并考虑了代码大小优化（通过 RISC-V C 扩展）和不同操作数类型的处理。此外，还包含了加载立即数、移动寄存器以及字节序转换等辅助功能。 这些宏指令是构建更高级抽象的基础，用于在 V8 引擎中生成执行 JavaScript 代码所需的机器码。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共9部分，请归纳一下它的功能

"""
cratch);
      }
    }
  }
}

void MacroAssembler::AddWord(Register rd, Register rs, const Operand& rt) {
  Add64(rd, rs, rt);
}

void MacroAssembler::SubWord(Register rd, Register rs, const Operand& rt) {
  Sub64(rd, rs, rt);
}

void MacroAssembler::Sub64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_sub(rd, rt.rm());
    } else {
      sub(rd, rs, rt.rm());
    }
  } else if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
             (rd != zero_reg) && is_int6(-rt.immediate()) &&
             (rt.immediate() != 0) && !MustUseReg(rt.rmode())) {
    c_addi(rd,
           static_cast<int8_t>(
               -rt.immediate()));  // No c_subi instr, use c_addi(x, y, -imm).

  } else if (v8_flags.riscv_c_extension && is_int10(-rt.immediate()) &&
             (rt.immediate() != 0) && ((rt.immediate() & 0xf) == 0) &&
             (rd.code() == rs.code()) && (rd == sp) &&
             !MustUseReg(rt.rmode())) {
    c_addi16sp(static_cast<int16_t>(-rt.immediate()));
  } else if (is_int12(-rt.immediate()) && !MustUseReg(rt.rmode())) {
    addi(rd, rs,
         static_cast<int32_t>(
             -rt.immediate()));  // No subi instr, use addi(x, y, -imm).
  } else if ((-4096 <= -rt.immediate() && -rt.immediate() <= -2049) ||
             (2048 <= -rt.immediate() && -rt.immediate() <= 4094)) {
    addi(rd, rs, -rt.immediate() / 2);
    addi(rd, rd, -rt.immediate() - (-rt.immediate() / 2));
  } else {
    int li_count = InstrCountForLi64Bit(rt.immediate());
    int li_neg_count = InstrCountForLi64Bit(-rt.immediate());
    if (li_neg_count < li_count && !MustUseReg(rt.rmode())) {
      // Use load -imm and add when loading -imm generates one instruction.
      DCHECK(rt.immediate() != std::numeric_limits<int32_t>::min());
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(-rt.immediate()));
      add(rd, rs, scratch);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, rt);
      sub(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Add64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        (rt.rm() != zero_reg) && (rs != zero_reg)) {
      c_add(rd, rt.rm());
    } else {
      add(rd, rs, rt.rm());
    }
  } else {
    if (v8_flags.riscv_c_extension && is_int6(rt.immediate()) &&
        (rd.code() == rs.code()) && (rd != zero_reg) && (rt.immediate() != 0) &&
        !MustUseReg(rt.rmode())) {
      c_addi(rd, static_cast<int8_t>(rt.immediate()));
    } else if (v8_flags.riscv_c_extension && is_int10(rt.immediate()) &&
               (rt.immediate() != 0) && ((rt.immediate() & 0xf) == 0) &&
               (rd.code() == rs.code()) && (rd == sp) &&
               !MustUseReg(rt.rmode())) {
      c_addi16sp(static_cast<int16_t>(rt.immediate()));
    } else if (v8_flags.riscv_c_extension &&
               ((rd.code() & 0b11000) == 0b01000) && (rs == sp) &&
               is_uint10(rt.immediate()) && (rt.immediate() != 0) &&
               !MustUseReg(rt.rmode())) {
      c_addi4spn(rd, static_cast<uint16_t>(rt.immediate()));
    } else if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      addi(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else if ((-4096 <= rt.immediate() && rt.immediate() <= -2049) ||
               (2048 <= rt.immediate() && rt.immediate() <= 4094)) {
      addi(rd, rs, rt.immediate() / 2);
      addi(rd, rd, rt.immediate() - (rt.immediate() / 2));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      BlockTrampolinePoolScope block_trampoline_pool(this);
      li(scratch, rt);
      add(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Mul32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mulw(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulw(rd, rs, scratch);
  }
}

void MacroAssembler::Mulh32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mul(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mul(rd, rs, scratch);
  }
  srai(rd, rd, 32);
}

void MacroAssembler::Mulhu32(Register rd, Register rs, const Operand& rt,
                             Register rsz, Register rtz) {
  slli(rsz, rs, 32);
  if (rt.is_reg()) {
    slli(rtz, rt.rm(), 32);
  } else {
    Li(rtz, rt.immediate() << 32);
  }
  mulhu(rd, rsz, rtz);
  srai(rd, rd, 32);
}

void MacroAssembler::Mul64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mul(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mul(rd, rs, scratch);
  }
}

void MacroAssembler::Mulh64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mulh(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulh(rd, rs, scratch);
  }
}

void MacroAssembler::Mulhu64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mulhu(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulhu(rd, rs, scratch);
  }
}

void MacroAssembler::Div32(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    divw(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    divw(res, rs, scratch);
  }
}

void MacroAssembler::Mod32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    remw(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    remw(rd, rs, scratch);
  }
}

void MacroAssembler::Modu32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    remuw(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    remuw(rd, rs, scratch);
  }
}

void MacroAssembler::Div64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    div(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    div(rd, rs, scratch);
  }
}

void MacroAssembler::Divu32(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    divuw(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    divuw(res, rs, scratch);
  }
}

void MacroAssembler::Divu64(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    divu(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    divu(res, rs, scratch);
  }
}

void MacroAssembler::Mod64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    rem(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    rem(rd, rs, scratch);
  }
}

void MacroAssembler::Modu64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    remu(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    remu(rd, rs, scratch);
  }
}
#elif V8_TARGET_ARCH_RISCV32
void MacroAssembler::AddWord(Register rd, Register rs, const Operand& rt) {
  Add32(rd, rs, rt);
}

void MacroAssembler::Add32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        (rt.rm() != zero_reg) && (rs != zero_reg)) {
      c_add(rd, rt.rm());
    } else {
      add(rd, rs, rt.rm());
    }
  } else {
    if (v8_flags.riscv_c_extension && is_int6(rt.immediate()) &&
        (rd.code() == rs.code()) && (rd != zero_reg) && (rt.immediate() != 0) &&
        !MustUseReg(rt.rmode())) {
      c_addi(rd, static_cast<int8_t>(rt.immediate()));
    } else if (v8_flags.riscv_c_extension && is_int10(rt.immediate()) &&
               (rt.immediate() != 0) && ((rt.immediate() & 0xf) == 0) &&
               (rd.code() == rs.code()) && (rd == sp) &&
               !MustUseReg(rt.rmode())) {
      c_addi16sp(static_cast<int16_t>(rt.immediate()));
    } else if (v8_flags.riscv_c_extension &&
               ((rd.code() & 0b11000) == 0b01000) && (rs == sp) &&
               is_uint10(rt.immediate()) && (rt.immediate() != 0) &&
               !MustUseReg(rt.rmode())) {
      c_addi4spn(rd, static_cast<uint16_t>(rt.immediate()));
    } else if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      addi(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else if ((-4096 <= rt.immediate() && rt.immediate() <= -2049) ||
               (2048 <= rt.immediate() && rt.immediate() <= 4094)) {
      addi(rd, rs, rt.immediate() / 2);
      addi(rd, rd, rt.immediate() - (rt.immediate() / 2));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      BlockTrampolinePoolScope block_trampoline_pool(this);
      li(scratch, rt);
      add(rd, rs, scratch);
    }
  }
}

void MacroAssembler::SubWord(Register rd, Register rs, const Operand& rt) {
  Sub32(rd, rs, rt);
}

void MacroAssembler::Sub32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_sub(rd, rt.rm());
    } else {
      sub(rd, rs, rt.rm());
    }
  } else if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
             (rd != zero_reg) && is_int6(-rt.immediate()) &&
             (rt.immediate() != 0) && !MustUseReg(rt.rmode())) {
    c_addi(rd,
           static_cast<int8_t>(
               -rt.immediate()));  // No c_subi instr, use c_addi(x, y, -imm).

  } else if (v8_flags.riscv_c_extension && is_int10(-rt.immediate()) &&
             (rt.immediate() != 0) && ((rt.immediate() & 0xf) == 0) &&
             (rd.code() == rs.code()) && (rd == sp) &&
             !MustUseReg(rt.rmode())) {
    c_addi16sp(static_cast<int16_t>(-rt.immediate()));
  } else if (is_int12(-rt.immediate()) && !MustUseReg(rt.rmode())) {
    addi(rd, rs,
         static_cast<int32_t>(
             -rt.immediate()));  // No subi instr, use addi(x, y, -imm).
  } else if ((-4096 <= -rt.immediate() && -rt.immediate() <= -2049) ||
             (2048 <= -rt.immediate() && -rt.immediate() <= 4094)) {
    addi(rd, rs, -rt.immediate() / 2);
    addi(rd, rd, -rt.immediate() - (-rt.immediate() / 2));
  } else {
    // RV32G todo: imm64 or imm32 here
    int li_count = InstrCountForLi64Bit(rt.immediate());
    int li_neg_count = InstrCountForLi64Bit(-rt.immediate());
    if (li_neg_count < li_count && !MustUseReg(rt.rmode())) {
      // Use load -imm and add when loading -imm generates one instruction.
      DCHECK(rt.immediate() != std::numeric_limits<int32_t>::min());
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(-rt.immediate()));
      add(rd, rs, scratch);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, rt);
      sub(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Mul32(Register rd, Register rs, const Operand& rt) {
  Mul(rd, rs, rt);
}

void MacroAssembler::Mul(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mul(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mul(rd, rs, scratch);
  }
}

void MacroAssembler::Mulh(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mulh(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulh(rd, rs, scratch);
  }
}

void MacroAssembler::Mulhu(Register rd, Register rs, const Operand& rt,
                           Register rsz, Register rtz) {
  if (rt.is_reg()) {
    mulhu(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    mulhu(rd, rs, scratch);
  }
}

void MacroAssembler::Div(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    div(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    div(res, rs, scratch);
  }
}

void MacroAssembler::Mod(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    rem(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    rem(rd, rs, scratch);
  }
}

void MacroAssembler::Modu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    remu(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    remu(rd, rs, scratch);
  }
}

void MacroAssembler::Divu(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    divu(res, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Li(scratch, rt.immediate());
    divu(res, rs, scratch);
  }
}

#endif

void MacroAssembler::And(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_and(rd, rt.rm());
    } else {
      and_(rd, rs, rt.rm());
    }
  } else {
    if (v8_flags.riscv_c_extension && is_int6(rt.immediate()) &&
        !MustUseReg(rt.rmode()) && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000)) {
      c_andi(rd, static_cast<int8_t>(rt.immediate()));
    } else if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      andi(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      Li(scratch, rt.immediate());
      and_(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Or(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_or(rd, rt.rm());
    } else {
      or_(rd, rs, rt.rm());
    }
  } else {
    if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      ori(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      Li(scratch, rt.immediate());
      or_(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Xor(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        ((rd.code() & 0b11000) == 0b01000) &&
        ((rt.rm().code() & 0b11000) == 0b01000)) {
      c_xor(rd, rt.rm());
    } else {
      xor_(rd, rs, rt.rm());
    }
  } else {
    if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      xori(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      Li(scratch, rt.immediate());
      xor_(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Nor(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    or_(rd, rs, rt.rm());
    not_(rd, rd);
  } else {
    Or(rd, rs, rt);
    not_(rd, rd);
  }
}

void MacroAssembler::Neg(Register rs, const Operand& rt) {
  DCHECK(rt.is_reg());
  neg(rs, rt.rm());
}

void MacroAssembler::Seqz(Register rd, const Operand& rt) {
  if (rt.is_reg()) {
    seqz(rd, rt.rm());
  } else {
    li(rd, rt.immediate() == 0);
  }
}

void MacroAssembler::Snez(Register rd, const Operand& rt) {
  if (rt.is_reg()) {
    snez(rd, rt.rm());
  } else {
    li(rd, rt.immediate() != 0);
  }
}

void MacroAssembler::Seq(Register rd, Register rs, const Operand& rt) {
  if (rs == zero_reg) {
    Seqz(rd, rt);
  } else if (IsZero(rt)) {
    seqz(rd, rs);
  } else {
    SubWord(rd, rs, rt);
    seqz(rd, rd);
  }
}

void MacroAssembler::Sne(Register rd, Register rs, const Operand& rt) {
  if (rs == zero_reg) {
    Snez(rd, rt);
  } else if (IsZero(rt)) {
    snez(rd, rs);
  } else {
    SubWord(rd, rs, rt);
    snez(rd, rd);
  }
}

void MacroAssembler::Slt(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    slt(rd, rs, rt.rm());
  } else {
    if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      slti(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Li(scratch, rt.immediate());
      slt(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Sltu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sltu(rd, rs, rt.rm());
  } else {
    if (is_int12(rt.immediate()) && !MustUseReg(rt.rmode())) {
      sltiu(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Li(scratch, rt.immediate());
      sltu(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Sle(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    slt(rd, rt.rm(), rs);
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Li(scratch, rt.immediate());
    slt(rd, scratch, rs);
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sleu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sltu(rd, rt.rm(), rs);
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Li(scratch, rt.immediate());
    sltu(rd, scratch, rs);
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sge(Register rd, Register rs, const Operand& rt) {
  Slt(rd, rs, rt);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgeu(Register rd, Register rs, const Operand& rt) {
  Sltu(rd, rs, rt);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgt(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    slt(rd, rt.rm(), rs);
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Li(scratch, rt.immediate());
    slt(rd, scratch, rs);
  }
}

void MacroAssembler::Sgtu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sltu(rd, rt.rm(), rs);
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Li(scratch, rt.immediate());
    sltu(rd, scratch, rs);
  }
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Sll32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sllw(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    slliw(rd, rs, shamt);
  }
}

void MacroAssembler::Sra32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sraw(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    sraiw(rd, rs, shamt);
  }
}

void MacroAssembler::Srl32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    srlw(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srliw(rd, rs, shamt);
  }
}

void MacroAssembler::SraWord(Register rd, Register rs, const Operand& rt) {
  Sra64(rd, rs, rt);
}

void MacroAssembler::Sra64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sra(rd, rs, rt.rm());
  } else if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
             ((rd.code() & 0b11000) == 0b01000) && is_int6(rt.immediate())) {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    c_srai(rd, shamt);
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srai(rd, rs, shamt);
  }
}

void MacroAssembler::SrlWord(Register rd, Register rs, const Operand& rt) {
  Srl64(rd, rs, rt);
}

void MacroAssembler::Srl64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    srl(rd, rs, rt.rm());
  } else if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
             ((rd.code() & 0b11000) == 0b01000) && is_int6(rt.immediate())) {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    c_srli(rd, shamt);
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srli(rd, rs, shamt);
  }
}

void MacroAssembler::SllWord(Register rd, Register rs, const Operand& rt) {
  Sll64(rd, rs, rt);
}

void MacroAssembler::Sll64(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sll(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    if (v8_flags.riscv_c_extension && (rd.code() == rs.code()) &&
        (rd != zero_reg) && (shamt != 0) && is_uint6(shamt)) {
      c_slli(rd, shamt);
    } else {
      slli(rd, rs, shamt);
    }
  }
}

void MacroAssembler::Ror(Register rd, Register rs, const Operand& rt) {
  if (CpuFeatures::IsSupported(ZBB)) {
    if (rt.is_reg()) {
      rorw(rd, rs, rt.rm());
    } else {
      int64_t ror_value = rt.immediate() % 32;
      if (ror_value < 0) {
        ror_value += 32;
      }
      roriw(rd, rs, ror_value);
    }
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (rt.is_reg()) {
    negw(scratch, rt.rm());
    sllw(scratch, rs, scratch);
    srlw(rd, rs, rt.rm());
    or_(rd, scratch, rd);
    sext_w(rd, rd);
  } else {
    int64_t ror_value = rt.immediate() % 32;
    if (ror_value == 0) {
      Mv(rd, rs);
      return;
    } else if (ror_value < 0) {
      ror_value += 32;
    }
    srliw(scratch, rs, ror_value);
    slliw(rd, rs, 32 - ror_value);
    or_(rd, scratch, rd);
    sext_w(rd, rd);
  }
}

void MacroAssembler::Dror(Register rd, Register rs, const Operand& rt) {
  if (CpuFeatures::IsSupported(ZBB)) {
    if (rt.is_reg()) {
      ror(rd, rs, rt.rm());
    } else {
      int64_t dror_value = rt.immediate() % 64;
      if (dror_value < 0) {
        dror_value += 64;
      }
      rori(rd, rs, dror_value);
    }
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (rt.is_reg()) {
    negw(scratch, rt.rm());
    sll(scratch, rs, scratch);
    srl(rd, rs, rt.rm());
    or_(rd, scratch, rd);
  } else {
    int64_t dror_value = rt.immediate() % 64;
    if (dror_value == 0) {
      Mv(rd, rs);
      return;
    } else if (dror_value < 0) {
      dror_value += 64;
    }
    srli(scratch, rs, dror_value);
    slli(rd, rs, 64 - dror_value);
    or_(rd, scratch, rd);
  }
}
#elif V8_TARGET_ARCH_RISCV32
void MacroAssembler::SllWord(Register rd, Register rs, const Operand& rt) {
  Sll32(rd, rs, rt);
}

void MacroAssembler::Sll32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sll(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    slli(rd, rs, shamt);
  }
}

void MacroAssembler::SraWord(Register rd, Register rs, const Operand& rt) {
  Sra32(rd, rs, rt);
}

void MacroAssembler::Sra32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sra(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srai(rd, rs, shamt);
  }
}

void MacroAssembler::SrlWord(Register rd, Register rs, const Operand& rt) {
  Srl32(rd, rs, rt);
}

void MacroAssembler::Srl32(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    srl(rd, rs, rt.rm());
  } else {
    uint8_t shamt = static_cast<uint8_t>(rt.immediate());
    srli(rd, rs, shamt);
  }
}

void MacroAssembler::Ror(Register rd, Register rs, const Operand& rt) {
  if (CpuFeatures::IsSupported(ZBB)) {
    if (rt.is_reg()) {
      ror(rd, rs, rt.rm());
    } else {
      int32_t ror_value = rt.immediate() % 32;
      if (ror_value < 0) {
        ror_value += 32;
      }
      rori(rd, rs, ror_value);
    }
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (rt.is_reg()) {
    neg(scratch, rt.rm());
    sll(scratch, rs, scratch);
    srl(rd, rs, rt.rm());
    or_(rd, scratch, rd);
  } else {
    int32_t ror_value = rt.immediate() % 32;
    if (ror_value == 0) {
      Mv(rd, rs);
      return;
    } else if (ror_value < 0) {
      ror_value += 32;
    }
    srli(scratch, rs, ror_value);
    slli(rd, rs, 32 - ror_value);
    or_(rd, scratch, rd);
  }
}
#endif

void MacroAssembler::Li(Register rd, intptr_t imm) {
  if (v8_flags.riscv_c_extension && (rd != zero_reg) && is_int6(imm)) {
    c_li(rd, imm);
  } else {
    RV_li(rd, imm);
  }
}

void MacroAssembler::Mv(Register rd, const Operand& rt) {
  if (v8_flags.riscv_c_extension && (rd != zero_reg) && (rt.rm() != zero_reg)) {
    c_mv(rd, rt.rm());
  } else {
    mv(rd, rt.rm());
  }
}

void MacroAssembler::CalcScaledAddress(Register rd, Register rt, Register rs,
                                       uint8_t sa) {
  DCHECK(sa >= 1 && sa <= 31);
  if (CpuFeatures::IsSupported(ZBA)) {
    switch (sa) {
      case 1:
        sh1add(rd, rs, rt);
        return;
      case 2:
        sh2add(rd, rs, rt);
        return;
      case 3:
        sh3add(rd, rs, rt);
        return;
      default:
        break;
    }
  }
  UseScratchRegisterScope temps(this);
  Register tmp = rd == rt ? temps.Acquire() : rd;
  DCHECK(tmp != rt);
  slli(tmp, rs, sa);
  AddWord(rd, rt, tmp);
  return;
}

// ------------Pseudo-instructions-------------
// Change endianness

template <int NBYTES>
void MacroAssembler::ReverseBytesHelper(Register rd, Register rs, Register tmp1,
                                        Register tmp2) {
  DCHECK(tmp1 != tmp2);
  DCHECK((rs != tmp1) && (rs != tmp2));
  DCHECK((rd != tmp1) && (rd != tmp2));

  // ByteMask - maximum value, held in byte
  constexpr int ByteMask = (1 << kBitsPerByte) - 1;
  // tmp1 = rs[0]; take least byte
  // tmp1 = tmp1 << kBitsPerByte;
  // for (nbyte = 1; nbyte < NBYTES - 1; nbyte++) {
  //   tmp2 = rs[nbyte]; take n`th byte
  //   tmp1 = (tmp2 | tmp1) << kBitsPerByte; add n`th source byte to tmp1
  // }
  // rd[0] = rs[NBYTES-1]; take upper byte
  // rd[NBYTES-1 : 1] = tmp1[NBYTES-1 : 1]; fill other bytes
  andi(tmp1, rs, ByteMask);
  slli(tmp1, tmp1, kBitsPerByte);
  for (int nbyte = 1; nbyte < NBYTES - 1; nbyte++) {
    srli(tmp2, rs, nbyte * kBitsPerByte);
    andi(tmp2, tmp2, ByteMask);
    or_(tmp1, tmp1, tmp2);
    slli(tmp1, tmp1, kBitsPerByte);
  }
  srli(rd, rs, (NBYTES - 1) * kBitsPerByte);
  andi(rd, rd, ByteMask);
  or_(rd, tmp1, rd);
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::ByteSwap(Register rd, Register rs, int operand_size,
                              Register scratch) {
  DCHECK(operand_size == 4 || operand_size == 8);
  if (CpuFeatures::IsSupported(ZBB)) {
    rev8(rd, rs);
    if (operand_size == 4) {
      srai(rd, rd, 32);
    }
    return;
  }
  DCHECK_NE(scratch, rs);
  DCHECK_NE(scratch, rd);
  if (operand_size == 4) {
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    DCHECK((rd != t6) && (rs != t6));
    Register x0 = temps.Acquire();
    Register x1 = temps.Acquire();
    if (scratch == no_reg) {
      ReverseBytesHelper<8>(rd, rs, x0, x1);
      srai(rd, rd, 32);
    } else {
      // Uint32_t x1 = 0x00FF00FF;
      // x0 = (x0 << 16 | x0 >> 16);
      // x0 = (((x0 & x1) << 8)  | ((x0 & (x1 << 8)) >> 8));
      Register x2 = scratch;
      li(x1, 0x00FF00FF);
      slliw(x0, rs, 16);
      srliw(rd, rs, 16);
      or_(x0, rd, x0);   // x0 <- x0 << 16 | x0 >> 16
      and_(x2, x0, x1);  // x2 <- x0 & 0x00FF00FF
      slliw(x2, x2, 8);  // x2 <- (x0 & x1) << 8
      slliw(x1, x1, 8);  // x1 <- 0xFF00FF00
      and_(rd, x0, x1);  // x0 & 0xFF00FF00
      srliw(rd, rd, 8);
      or_(rd, rd, x2);  // (((x0 & x1) << 8)  | ((x0 & (x1 << 8)) >> 8))
    }
  } else {
    UseScratchRegisterScope temps(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    DCHECK((rd != t6) && (rs != t6));
    Register x0 = temps.Acquire();
    Register x1 = temps.Acquire();
    if (scratch == no_reg) {
      ReverseBytesHelper<8>(rd, rs, x0, x1);
    } else {
      // uinx24_t x1 = 0x0000FFFF0000FFFFl;
      // uinx24_t x1 = 0x00FF00FF00FF00FFl;
      // x0 = (x0 << 32 | x0 >> 32);
      // x0 = (x0 & x1) << 16 | (x0 & (x1 << 16)) >> 16;
      // x0 = (x0 & x1) << 8  | (x0 & (x1 << 8)) >> 8;
      Register x2 = scratch;
      li(x1, 0x0000FFFF0000FFFFl);
      slli(x0, rs, 32);
      srli(rd, rs, 32);
      or_(x0, rd, x0);   // x0 <- x0 << 32 | x0 >> 32
      and_(x2, x0, x1);  // x2 <- x0 & 0x0000FFFF0000FFFF
      slli(x2, x2, 16);  // x2 <- (x0 & 0x0000FFFF0000FFFF) << 16
      slli(x1, x1, 16);  // x1 <- 0xFFFF0000FFFF0000
      and_(rd, x0, x1);  // rd <- x0 & 0xFFFF0000FFFF0000
      srli(rd, rd, 16);  // rd <- x0 & (x1 << 16)) >> 16
      or_(x0, rd, x2);   // (x0 & x1) << 16 | (x0 & (x1 << 16)) >> 16;
      li(x1, 0x00FF00FF00FF00FFl);
      and_(x2, x0, x1);  // x2 <- x0 & 0x00FF00FF00FF00FF
      slli(x2, x2, 8);   // x2 <- (x0 & x1) << 8
      slli(x1, x1, 8);   // x1 <- 0xFF00FF00FF00FF00
      and_(rd, x0, x1);
      srli(rd, rd, 8);  // rd <- (x0 & (x1 << 8)) >> 8
      or_(rd, rd, x2);  // (((x0 & x1) << 8)  | ((x0 & (x1 << 8)) >> 8))
    }
  }
}

#elif V8_TARGET_ARCH_RISCV32
void MacroAssembler::ByteSwap(Register rd, Register rs, int operand_size,
                              Register scratch) {
  if (CpuFeatures::IsSupported(ZBB)) {
    rev8(rd, rs);
    return;
  }
  DCHECK_NE(scratch, rs);
  DCHECK_NE(scratch, rd);
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK((rd != t6) && (rs != t6));
  Register x0 = temps.Acquire();
  Register x1 = temps.Acquire();
  if (scratch == no_reg) {
    ReverseBytesHelper<4>(rd, rs, x0, x1);
  } else {
    // Uint32_t x1 = 0x00FF00FF;
    // x0 = (x0 << 16 | x0 >> 16);
    // x0 = (((x0 & x1) << 8)  | ((x0 & (x1 << 8)) >> 8));
    Register x2 = scratch;
    li(x1, 0x00FF00FF);
    slli(x0, rs, 16);
    srli(rd, rs, 16);
    or_(x0, rd, x0);   // x0 <- x0 << 16 | x0 >> 16
    and_(x2, x0, x1);  // x2 <- x0 & 0x00FF00FF
    slli(x2, x2, 8);   // x2 <- (x0 & x1) << 8
 
"""


```
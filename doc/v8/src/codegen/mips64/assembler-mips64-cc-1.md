Response:
The user wants a summary of the functionality of the provided C++ code snippet. This snippet is a part of the `Assembler` class for the MIPS64 architecture in V8.

Here's a breakdown of the code's functionalities:

1. **Label Management:**  The code deals with labels, which are placeholders for memory addresses. It allows binding labels to specific positions, checking if a label is bound, and linking to labels.

2. **Instruction Emission:** The code provides methods to generate and emit MIPS64 instructions. These methods take opcodes, registers, and immediate values as arguments and construct the corresponding machine code.

3. **Branching and Jumping:** The code includes functions for generating various branch and jump instructions, handling short and long jumps, and managing the delay slots associated with these instructions.

4. **Trampoline Management:** To handle long jumps that are out of the immediate reach of a branch instruction, the code implements a trampoline mechanism. It allocates and manages trampoline entries in the code buffer.

5. **Relocation Information:** The code considers relocation, where addresses might need to be adjusted after the initial code generation. The `MustUseReg` function hints at handling relocatable values.

6. **MSA (MIPS SIMD Architecture) Support:**  The code includes methods to generate instructions for the MSA extension, handling different data types and operations.

7. **Instruction Formatting:** Helper functions like `GenInstrRegister` and `GenInstrImmediate` are used to format instructions based on their type and operands.

Based on this analysis, I can now formulate a summary of the code's functions.
这是 `v8/src/codegen/mips64/assembler-mips64.cc` 文件的代码片段，它主要负责以下功能：

**核心功能：**

1. **标签 (Label) 管理:**
   -  提供了创建、绑定、查询和操作代码标签的功能。标签用于表示代码中的特定位置，常用于跳转和分支指令。
   -  可以判断标签是否已绑定 (`is_bound`) 或已链接 (`is_linked`)。
   -  可以绑定标签到一个特定的代码偏移量 (`bind_to`, `bind`)。
   -  可以遍历链接的标签 (`next`)。
   -  可以判断当前指令位置与标签位置的距离是否在短跳转范围内 (`is_near`, `is_near_branch`)。

2. **指令生成与发射 (Instruction Generation and Emission):**
   -  提供了多种 `GenInstr...` 函数，用于生成不同类型的 MIPS64 指令。
   -  这些函数接收操作码 (opcode)、寄存器、立即数等参数，并将它们编码成机器指令。
   -  支持通用寄存器操作、浮点寄存器操作以及 MSA (MIPS SIMD Architecture) 指令的生成。
   -  `emit` 函数负责将生成的指令写入到代码缓冲区中。

3. **分支与跳转指令 (Branch and Jump Instructions):**
   -  实现了各种条件分支指令 (如 `beq`, `bne`, `bgez`, `bltz` 等) 和无条件跳转指令 (`j`, `jal`, `jr`, `jalr`)。
   -  考虑了 MIPS64 R6 架构引入的新分支指令和紧凑分支指令。
   -  `BranchOffset` 函数用于计算分支指令的偏移量范围。

4. **跳转目标管理 (Jump Target Management):**
   -  `jump_address`, `jump_offset`, `branch_long_offset`, `branch_offset_helper` 等函数用于计算跳转目标地址或偏移量。
   -  这些函数会处理标签是否已经绑定，以及如何链接未绑定的标签。

5. **Trampoline (跳板) 机制:**
   -  当跳转目标距离过远，超出直接分支指令的范围时，会使用 trampoline。
   -  `get_trampoline_entry` 函数用于获取空闲的 trampoline 条目。
   -  代码中会检查是否需要使用 trampoline，并在必要时将短跳转指令指向 trampoline，trampoline 中包含跳转到最终目标的指令。

6. **MSA 指令支持 (MSA Instruction Support):**
   -  提供了一系列 `GenInstrMsa...` 函数，用于生成 MSA 相关的指令，支持向量和标量操作。

**与 JavaScript 的关系 (假设 `v8/src/codegen/mips64/assembler-mips64.cc` 与 JavaScript 功能有关):**

`v8/src/codegen/mips64/assembler-mips64.cc` 文件是 V8 JavaScript 引擎的一部分，负责将 JavaScript 代码编译成 MIPS64 架构的机器码。

例如，当 V8 编译一个包含 `if` 语句的 JavaScript 函数时，`assembler-mips64.cc` 中的分支指令生成功能会被使用：

```javascript
function myFunction(x) {
  if (x > 10) {
    return "greater than 10";
  } else {
    return "less than or equal to 10";
  }
}
```

V8 编译器可能会生成类似以下的 MIPS64 汇编代码（简化示例）：

```assembly
  // ... 一些代码 ...
  lw  t0, [sp + offset_of_x]  // 将 x 的值加载到寄存器 t0
  li  t1, 10                 // 将立即数 10 加载到寄存器 t1
  ble t0, t1, else_branch     // 如果 t0 <= t1，则跳转到 else_branch 标签
  // ... x > 10 的代码 ...
  li  v0, address_of_string_greater  // 将字符串 "greater than 10" 的地址加载到 v0
  j   end_of_if                 // 跳转到 end_of_if 标签
else_branch:
  // ... x <= 10 的代码 ...
  li  v0, address_of_string_less_equal // 将字符串 "less than or equal to 10" 的地址加载到 v0
end_of_if:
  // ... 后续代码 ...
```

在生成上述汇编代码的过程中，`assembler-mips64.cc` 中的 `ble` (小于等于跳转) 和 `j` (无条件跳转) 指令生成函数会被调用。标签 `else_branch` 和 `end_of_if` 会被创建和绑定。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个标签 `myLabel` 尚未绑定，并且我们执行以下代码：

**输入:**

- `L`: 指向 `myLabel` 的指针，`myLabel->is_linked()` 为 false。
- 调用 `Assembler::jump_offset(myLabel)`

**输出:**

- `myLabel->is_linked()` 将变为 true。
- `myLabel` 将链接到当前的程序计数器偏移量 (`pc_offset()`).
- 函数返回 `kEndOfJumpChain`。

**解释:**

由于 `myLabel` 未绑定且未链接，`jump_offset` 函数会将其链接到当前的指令位置，并返回一个特殊值 `kEndOfJumpChain`，表示这是链接链的末尾，需要在后续处理中被回填真正的偏移量。

**用户常见的编程错误 (如果涉及):**

虽然 `assembler-mips64.cc` 不是用户直接编写的代码，但使用汇编语言编程时常见的错误包括：

1. **跳转目标超出范围:** 尝试跳转到超出当前指令 +/- 32KB 范围的位置，而没有正确处理 trampoline 或长跳转指令。
2. **延迟槽指令错误:** 在分支或跳转指令的延迟槽中放置了不合适的指令，导致程序行为异常。MIPS 架构的分支和跳转指令后通常有一个延迟槽，该槽中的指令会在分支或跳转发生前执行。
3. **寄存器使用冲突:** 在没有保存和恢复的情况下，错误地覆盖了重要寄存器的值。

**本代码片段的功能归纳:**

这个代码片段是 V8 引擎中 MIPS64 架构汇编器的核心部分，负责 **管理代码标签、生成和发射 MIPS64 机器指令 (包括普通指令和 MSA 指令)、处理分支和跳转逻辑、以及实现长跳转的 trampoline 机制**。它是将 JavaScript 代码转换为可执行机器码的关键组件。

### 提示词
```
这是目录为v8/src/codegen/mips64/assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
intF("unused label\n");
  } else if (L->is_bound()) {
    PrintF("bound label to %d\n", L->pos());
  } else if (L->is_linked()) {
    Label l;
    l.link_to(L->pos());
    PrintF("unbound label");
    while (l.is_linked()) {
      PrintF("@ %d ", l.pos());
      Instr instr = instr_at(l.pos());
      if ((instr & ~kImm16Mask) == 0) {
        PrintF("value\n");
      } else {
        PrintF("%d\n", instr);
      }
      next(&l, is_internal_reference(&l));
    }
  } else {
    PrintF("label in inconsistent state (pos = %d)\n", L->pos_);
  }
}

void Assembler::bind_to(Label* L, int pos) {
  DCHECK(0 <= pos && pos <= pc_offset());  // Must have valid binding position.
  int trampoline_pos = kInvalidSlotPos;
  bool is_internal = false;
  if (L->is_linked() && !trampoline_emitted_) {
    unbound_labels_count_--;
    if (!is_internal_reference(L)) {
      next_buffer_check_ += kTrampolineSlotsSize;
    }
  }

  while (L->is_linked()) {
    int fixup_pos = L->pos();
    int dist = pos - fixup_pos;
    is_internal = is_internal_reference(L);
    next(L, is_internal);  // Call next before overwriting link with target at
                           // fixup_pos.
    Instr instr = instr_at(fixup_pos);
    if (is_internal) {
      target_at_put(fixup_pos, pos, is_internal);
    } else {
      if (IsBranch(instr)) {
        int branch_offset = BranchOffset(instr);
        if (dist > branch_offset) {
          if (trampoline_pos == kInvalidSlotPos) {
            trampoline_pos = get_trampoline_entry(fixup_pos);
            CHECK_NE(trampoline_pos, kInvalidSlotPos);
          }
          CHECK((trampoline_pos - fixup_pos) <= branch_offset);
          target_at_put(fixup_pos, trampoline_pos, false);
          fixup_pos = trampoline_pos;
        }
        target_at_put(fixup_pos, pos, false);
      } else {
        DCHECK(IsJ(instr) || IsJal(instr) || IsLui(instr) ||
               IsEmittedConstant(instr) || IsMov(instr, t8, ra));
        target_at_put(fixup_pos, pos, false);
      }
    }
  }
  L->bind_to(pos);

  // Keep track of the last bound label so we don't eliminate any instructions
  // before a bound label.
  if (pos > last_bound_pos_) last_bound_pos_ = pos;
}

void Assembler::bind(Label* L) {
  DCHECK(!L->is_bound());  // Label can only be bound once.
  bind_to(L, pc_offset());
}

void Assembler::next(Label* L, bool is_internal) {
  DCHECK(L->is_linked());
  int link = target_at(L->pos(), is_internal);
  if (link == kEndOfChain) {
    L->Unuse();
  } else {
    DCHECK_GE(link, 0);
    L->link_to(link);
  }
}

bool Assembler::is_near(Label* L) {
  DCHECK(L->is_bound());
  return pc_offset() - L->pos() < kMaxBranchOffset - 4 * kInstrSize;
}

bool Assembler::is_near(Label* L, OffsetSize bits) {
  if (L == nullptr || !L->is_bound()) return true;
  return ((pc_offset() - L->pos()) <
          (1 << (bits + 2 - 1)) - 1 - 5 * kInstrSize);
}

bool Assembler::is_near_branch(Label* L) {
  DCHECK(L->is_bound());
  return kArchVariant == kMips64r6 ? is_near_r6(L) : is_near_pre_r6(L);
}

int Assembler::BranchOffset(Instr instr) {
  // At pre-R6 and for other R6 branches the offset is 16 bits.
  int bits = OffsetSize::kOffset16;

  if (kArchVariant == kMips64r6) {
    uint32_t opcode = GetOpcodeField(instr);
    switch (opcode) {
      // Checks BC or BALC.
      case BC:
      case BALC:
        bits = OffsetSize::kOffset26;
        break;

      // Checks BEQZC or BNEZC.
      case POP66:
      case POP76:
        if (GetRsField(instr) != 0) bits = OffsetSize::kOffset21;
        break;
      default:
        break;
    }
  }

  return (1 << (bits + 2 - 1)) - 1;
}

// We have to use a temporary register for things that can be relocated even
// if they can be encoded in the MIPS's 16 bits of immediate-offset instruction
// space.  There is no guarantee that the relocated location can be similarly
// encoded.
bool Assembler::MustUseReg(RelocInfo::Mode rmode) {
  return !RelocInfo::IsNoInfo(rmode);
}

void Assembler::GenInstrRegister(Opcode opcode, Register rs, Register rt,
                                 Register rd, uint16_t sa,
                                 SecondaryField func) {
  DCHECK(rd.is_valid() && rs.is_valid() && rt.is_valid() && is_uint5(sa));
  Instr instr = opcode | (rs.code() << kRsShift) | (rt.code() << kRtShift) |
                (rd.code() << kRdShift) | (sa << kSaShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, Register rs, Register rt,
                                 uint16_t msb, uint16_t lsb,
                                 SecondaryField func) {
  DCHECK(rs.is_valid() && rt.is_valid() && is_uint5(msb) && is_uint5(lsb));
  Instr instr = opcode | (rs.code() << kRsShift) | (rt.code() << kRtShift) |
                (msb << kRdShift) | (lsb << kSaShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, SecondaryField fmt,
                                 FPURegister ft, FPURegister fs, FPURegister fd,
                                 SecondaryField func) {
  DCHECK(fd.is_valid() && fs.is_valid() && ft.is_valid());
  Instr instr = opcode | fmt | (ft.code() << kFtShift) |
                (fs.code() << kFsShift) | (fd.code() << kFdShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, FPURegister fr, FPURegister ft,
                                 FPURegister fs, FPURegister fd,
                                 SecondaryField func) {
  DCHECK(fd.is_valid() && fr.is_valid() && fs.is_valid() && ft.is_valid());
  Instr instr = opcode | (fr.code() << kFrShift) | (ft.code() << kFtShift) |
                (fs.code() << kFsShift) | (fd.code() << kFdShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, SecondaryField fmt, Register rt,
                                 FPURegister fs, FPURegister fd,
                                 SecondaryField func) {
  DCHECK(fd.is_valid() && fs.is_valid() && rt.is_valid());
  Instr instr = opcode | fmt | (rt.code() << kRtShift) |
                (fs.code() << kFsShift) | (fd.code() << kFdShift) | func;
  emit(instr);
}

void Assembler::GenInstrRegister(Opcode opcode, SecondaryField fmt, Register rt,
                                 FPUControlRegister fs, SecondaryField func) {
  DCHECK(fs.is_valid() && rt.is_valid());
  Instr instr =
      opcode | fmt | (rt.code() << kRtShift) | (fs.code() << kFsShift) | func;
  emit(instr);
}

// Instructions with immediate value.
// Registers are in the order of the instruction encoding, from left to right.
void Assembler::GenInstrImmediate(Opcode opcode, Register rs, Register rt,
                                  int32_t j,
                                  CompactBranchType is_compact_branch) {
  DCHECK(rs.is_valid() && rt.is_valid() && (is_int16(j) || is_uint16(j)));
  Instr instr = opcode | (rs.code() << kRsShift) | (rt.code() << kRtShift) |
                (j & kImm16Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register base, Register rt,
                                  int32_t offset9, int bit6,
                                  SecondaryField func) {
  DCHECK(base.is_valid() && rt.is_valid() && is_int9(offset9) &&
         is_uint1(bit6));
  Instr instr = opcode | (base.code() << kBaseShift) | (rt.code() << kRtShift) |
                ((offset9 << kImm9Shift) & kImm9Mask) | bit6 << kBit6Shift |
                func;
  emit(instr);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register rs, SecondaryField SF,
                                  int32_t j,
                                  CompactBranchType is_compact_branch) {
  DCHECK(rs.is_valid() && (is_int16(j) || is_uint16(j)));
  Instr instr = opcode | (rs.code() << kRsShift) | SF | (j & kImm16Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register rs, FPURegister ft,
                                  int32_t j,
                                  CompactBranchType is_compact_branch) {
  DCHECK(rs.is_valid() && ft.is_valid() && (is_int16(j) || is_uint16(j)));
  Instr instr = opcode | (rs.code() << kRsShift) | (ft.code() << kFtShift) |
                (j & kImm16Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register rs, int32_t offset21,
                                  CompactBranchType is_compact_branch) {
  DCHECK(rs.is_valid() && (is_int21(offset21)));
  Instr instr = opcode | (rs.code() << kRsShift) | (offset21 & kImm21Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrImmediate(Opcode opcode, Register rs,
                                  uint32_t offset21) {
  DCHECK(rs.is_valid() && (is_uint21(offset21)));
  Instr instr = opcode | (rs.code() << kRsShift) | (offset21 & kImm21Mask);
  emit(instr);
}

void Assembler::GenInstrImmediate(Opcode opcode, int32_t offset26,
                                  CompactBranchType is_compact_branch) {
  DCHECK(is_int26(offset26));
  Instr instr = opcode | (offset26 & kImm26Mask);
  emit(instr, is_compact_branch);
}

void Assembler::GenInstrJump(Opcode opcode, uint32_t address) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(is_uint26(address));
  Instr instr = opcode | address;
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

// MSA instructions
void Assembler::GenInstrMsaI8(SecondaryField operation, uint32_t imm8,
                              MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid() && is_uint8(imm8));
  Instr instr = MSA | operation | ((imm8 & kImm8Mask) << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsaI5(SecondaryField operation, SecondaryField df,
                              int32_t imm5, MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid());
  DCHECK((operation == MAXI_S) || (operation == MINI_S) ||
                 (operation == CEQI) || (operation == CLTI_S) ||
                 (operation == CLEI_S)
             ? is_int5(imm5)
             : is_uint5(imm5));
  Instr instr = MSA | operation | df | ((imm5 & kImm5Mask) << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsaBit(SecondaryField operation, SecondaryField df,
                               uint32_t m, MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid() && is_valid_msa_df_m(df, m));
  Instr instr = MSA | operation | df | (m << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsaI10(SecondaryField operation, SecondaryField df,
                               int32_t imm10, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(wd.is_valid() && is_int10(imm10));
  Instr instr = MSA | operation | df | ((imm10 & kImm10Mask) << kWsShift) |
                (wd.code() << kWdShift);
  emit(instr);
}

template <typename RegType>
void Assembler::GenInstrMsa3R(SecondaryField operation, SecondaryField df,
                              RegType t, MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(t.is_valid() && ws.is_valid() && wd.is_valid());
  Instr instr = MSA | operation | df | (t.code() << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

template <typename DstType, typename SrcType>
void Assembler::GenInstrMsaElm(SecondaryField operation, SecondaryField df,
                               uint32_t n, SrcType src, DstType dst) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(src.is_valid() && dst.is_valid() && is_valid_msa_df_n(df, n));
  Instr instr = MSA | operation | df | (n << kWtShift) |
                (src.code() << kWsShift) | (dst.code() << kWdShift) |
                MSA_ELM_MINOR;
  emit(instr);
}

void Assembler::GenInstrMsa3RF(SecondaryField operation, uint32_t df,
                               MSARegister wt, MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(wt.is_valid() && ws.is_valid() && wd.is_valid());
  DCHECK_LT(df, 2);
  Instr instr = MSA | operation | (df << 21) | (wt.code() << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsaVec(SecondaryField operation, MSARegister wt,
                               MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(wt.is_valid() && ws.is_valid() && wd.is_valid());
  Instr instr = MSA | operation | (wt.code() << kWtShift) |
                (ws.code() << kWsShift) | (wd.code() << kWdShift) |
                MSA_VEC_2R_2RF_MINOR;
  emit(instr);
}

void Assembler::GenInstrMsaMI10(SecondaryField operation, int32_t s10,
                                Register rs, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(rs.is_valid() && wd.is_valid() && is_int10(s10));
  Instr instr = MSA | operation | ((s10 & kImm10Mask) << kWtShift) |
                (rs.code() << kWsShift) | (wd.code() << kWdShift);
  emit(instr);
}

void Assembler::GenInstrMsa2R(SecondaryField operation, SecondaryField df,
                              MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid());
  Instr instr = MSA | MSA_2R_FORMAT | operation | df | (ws.code() << kWsShift) |
                (wd.code() << kWdShift) | MSA_VEC_2R_2RF_MINOR;
  emit(instr);
}

void Assembler::GenInstrMsa2RF(SecondaryField operation, SecondaryField df,
                               MSARegister ws, MSARegister wd) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid());
  Instr instr = MSA | MSA_2RF_FORMAT | operation | df |
                (ws.code() << kWsShift) | (wd.code() << kWdShift) |
                MSA_VEC_2R_2RF_MINOR;
  emit(instr);
}

void Assembler::GenInstrMsaBranch(SecondaryField operation, MSARegister wt,
                                  int32_t offset16) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(wt.is_valid() && is_int16(offset16));
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Instr instr =
      COP1 | operation | (wt.code() << kWtShift) | (offset16 & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

// Returns the next free trampoline entry.
int32_t Assembler::get_trampoline_entry(int32_t pos) {
  int32_t trampoline_entry = kInvalidSlotPos;
  if (!internal_trampoline_exception_) {
    if (trampoline_.start() > pos) {
      trampoline_entry = trampoline_.take_slot();
    }

    if (kInvalidSlotPos == trampoline_entry) {
      internal_trampoline_exception_ = true;
    }
  }
  return trampoline_entry;
}

uint64_t Assembler::jump_address(Label* L) {
  int64_t target_pos;
  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      L->link_to(pc_offset());
    } else {
      L->link_to(pc_offset());
      return kEndOfJumpChain;
    }
  }
  uint64_t imm = reinterpret_cast<uint64_t>(buffer_start_) + target_pos;
  DCHECK_EQ(imm & 3, 0);

  return imm;
}

uint64_t Assembler::jump_offset(Label* L) {
  int64_t target_pos;
  int32_t pad = IsPrevInstrCompactBranch() ? kInstrSize : 0;

  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      L->link_to(pc_offset() + pad);
    } else {
      L->link_to(pc_offset() + pad);
      return kEndOfJumpChain;
    }
  }
  int64_t imm = target_pos - (pc_offset() + pad);
  DCHECK_EQ(imm & 3, 0);

  return static_cast<uint64_t>(imm);
}

uint64_t Assembler::branch_long_offset(Label* L) {
  int64_t target_pos;

  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      L->link_to(pc_offset());
    } else {
      L->link_to(pc_offset());
      return kEndOfJumpChain;
    }
  }
  int64_t offset = target_pos - (pc_offset() + kLongBranchPCOffset);
  DCHECK_EQ(offset & 3, 0);

  return static_cast<uint64_t>(offset);
}

int32_t Assembler::branch_offset_helper(Label* L, OffsetSize bits) {
  int32_t target_pos;
  int32_t pad = IsPrevInstrCompactBranch() ? kInstrSize : 0;

  if (L->is_bound()) {
    target_pos = L->pos();
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();
      L->link_to(pc_offset() + pad);
    } else {
      L->link_to(pc_offset() + pad);
      if (!trampoline_emitted_) {
        unbound_labels_count_++;
        next_buffer_check_ -= kTrampolineSlotsSize;
      }
      return kEndOfChain;
    }
  }

  int32_t offset = target_pos - (pc_offset() + kBranchPCOffset + pad);
  DCHECK(is_intn(offset, bits + 2));
  DCHECK_EQ(offset & 3, 0);

  return offset;
}

void Assembler::label_at_put(Label* L, int at_offset) {
  int target_pos;
  if (L->is_bound()) {
    target_pos = L->pos();
    instr_at_put(at_offset, target_pos + (InstructionStream::kHeaderSize -
                                          kHeapObjectTag));
  } else {
    if (L->is_linked()) {
      target_pos = L->pos();  // L's link.
      int32_t imm18 = target_pos - at_offset;
      DCHECK_EQ(imm18 & 3, 0);
      int32_t imm16 = imm18 >> 2;
      DCHECK(is_int16(imm16));
      instr_at_put(at_offset, (imm16 & kImm16Mask));
    } else {
      target_pos = kEndOfChain;
      instr_at_put(at_offset, 0);
      if (!trampoline_emitted_) {
        unbound_labels_count_++;
        next_buffer_check_ -= kTrampolineSlotsSize;
      }
    }
    L->link_to(at_offset);
  }
}

//------- Branch and jump instructions --------

void Assembler::b(int16_t offset) { beq(zero_reg, zero_reg, offset); }

void Assembler::bal(int16_t offset) { bgezal(zero_reg, offset); }

void Assembler::bc(int32_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrImmediate(BC, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::balc(int32_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrImmediate(BALC, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::beq(Register rs, Register rt, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(BEQ, rs, rt, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bgez(Register rs, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BGEZ, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bgezc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  GenInstrImmediate(BLEZL, rt, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgeuc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rt != zero_reg);
  DCHECK(rs.code() != rt.code());
  GenInstrImmediate(BLEZ, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgec(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rt != zero_reg);
  DCHECK(rs.code() != rt.code());
  GenInstrImmediate(BLEZL, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgezal(Register rs, int16_t offset) {
  DCHECK(kArchVariant != kMips64r6 || rs == zero_reg);
  DCHECK(rs != ra);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BGEZAL, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bgtz(Register rs, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(BGTZ, rs, zero_reg, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bgtzc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  GenInstrImmediate(BGTZL, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::blez(Register rs, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(BLEZ, rs, zero_reg, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::blezc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  GenInstrImmediate(BLEZL, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bltzc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  GenInstrImmediate(BGTZL, rt, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bltuc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rt != zero_reg);
  DCHECK(rs.code() != rt.code());
  GenInstrImmediate(BGTZ, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bltc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rt != zero_reg);
  DCHECK(rs.code() != rt.code());
  GenInstrImmediate(BGTZL, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bltz(Register rs, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BLTZ, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bltzal(Register rs, int16_t offset) {
  DCHECK(kArchVariant != kMips64r6 || rs == zero_reg);
  DCHECK(rs != ra);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BLTZAL, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bne(Register rs, Register rt, int16_t offset) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(BNE, rs, rt, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bovc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  if (rs.code() >= rt.code()) {
    GenInstrImmediate(ADDI, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
  } else {
    GenInstrImmediate(ADDI, rt, rs, offset, CompactBranchType::COMPACT_BRANCH);
  }
}

void Assembler::bnvc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  if (rs.code() >= rt.code()) {
    GenInstrImmediate(DADDI, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
  } else {
    GenInstrImmediate(DADDI, rt, rs, offset, CompactBranchType::COMPACT_BRANCH);
  }
}

void Assembler::blezalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(BLEZ, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgezalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(BLEZ, rt, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgezall(Register rs, int16_t offset) {
  DCHECK_NE(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  DCHECK(rs != ra);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrImmediate(REGIMM, rs, BGEZALL, offset);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bltzalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(BGTZ, rt, rt, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bgtzalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(BGTZ, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::beqzalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(ADDI, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bnezalc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rt != zero_reg);
  DCHECK(rt != ra);
  GenInstrImmediate(DADDI, zero_reg, rt, offset,
                    CompactBranchType::COMPACT_BRANCH);
}

void Assembler::beqc(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.code() != rt.code() && rs.code() != 0 && rt.code() != 0);
  if (rs.code() < rt.code()) {
    GenInstrImmediate(ADDI, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
  } else {
    GenInstrImmediate(ADDI, rt, rs, offset, CompactBranchType::COMPACT_BRANCH);
  }
}

void Assembler::beqzc(Register rs, int32_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  GenInstrImmediate(POP66, rs, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::bnec(Register rs, Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs.code() != rt.code() && rs.code() != 0 && rt.code() != 0);
  if (rs.code() < rt.code()) {
    GenInstrImmediate(DADDI, rs, rt, offset, CompactBranchType::COMPACT_BRANCH);
  } else {
    GenInstrImmediate(DADDI, rt, rs, offset, CompactBranchType::COMPACT_BRANCH);
  }
}

void Assembler::bnezc(Register rs, int32_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(rs != zero_reg);
  GenInstrImmediate(POP76, rs, offset, CompactBranchType::COMPACT_BRANCH);
}

void Assembler::j(int64_t target) {
  // Deprecated. Use PC-relative jumps instead.
  UNREACHABLE();
}

void Assembler::j(Label* target) {
  // Deprecated. Use PC-relative jumps instead.
  UNREACHABLE();
}

void Assembler::jal(Label* target) {
  // Deprecated. Use PC-relative jumps instead.
  UNREACHABLE();
}

void Assembler::jal(int64_t target) {
  // Deprecated. Use PC-relative jumps instead.
  UNREACHABLE();
}

void Assembler::jr(Register rs) {
  if (kArchVariant != kMips64r6) {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    GenInstrRegister(SPECIAL, rs, zero_reg, zero_reg, 0, JR);
    BlockTrampolinePoolFor(1);  // For associated delay slot.
  } else {
    jalr(rs, zero_reg);
  }
}

void Assembler::jalr(Register rs, Register rd) {
  DCHECK(rs.code() != rd.code());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  GenInstrRegister(SPECIAL, rs, zero_reg, rd, 0, JALR);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::jic(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrImmediate(POP66, zero_reg, rt, offset);
}

void Assembler::jialc(Register rt, int16_t offset) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrImmediate(POP76, zero_reg, rt, offset);
}

// -------Data-processing-instructions---------

// Arithmetic.

void Assembler::addu(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, ADDU);
}

void Assembler::addiu(Register rd, Register rs, int32_t j) {
  GenInstrImmediate(ADDIU, rs, rd, j);
}

void Assembler::subu(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SUBU);
}

void Assembler::mul(Register rd, Register rs, Register rt) {
  if (kArchVariant == kMips64r6) {
    GenInstrRegister(SPECIAL, rs, rt, rd, MUL_OP, MUL_MUH);
  } else {
    GenInstrRegister(SPECIAL2, rs, rt, rd, 0, MUL);
  }
}

void Assembler::muh(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUH_OP, MUL_MUH);
}

void Assembler::mulu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUL_OP, MUL_MUH_U);
}

void Assembler::muhu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUH_OP, MUL_MUH_U);
}

void Assembler::dmul(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUL_OP, D_MUL_MUH);
}

void Assembler::dmuh(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUH_OP, D_MUL_MUH);
}

void Assembler::dmulu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUL_OP, D_MUL_MUH_U);
}

void Assembler::dmuhu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MUH_OP, D_MUL_MUH_U);
}

void Assembler::mult(Register rs, Register rt) {
  DCHECK_NE(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, MULT);
}

void Assembler::multu(Register rs, Register rt) {
  DCHECK_NE(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, MULTU);
}

void Assembler::daddiu(Register rd, Register rs, int32_t j) {
  GenInstrImmediate(DADDIU, rs, rd, j);
}

void Assembler::div(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DIV);
}

void Assembler::div(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, DIV_OP, DIV_MOD);
}

void Assembler::mod(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MOD_OP, DIV_MOD);
}

void Assembler::divu(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DIVU);
}

void Assembler::divu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, DIV_OP, DIV_MOD_U);
}

void Assembler::modu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MOD_OP, DIV_MOD_U);
}

void Assembler::daddu(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, DADDU);
}

void Assembler::dsubu(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, DSUBU);
}

void Assembler::dmult(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DMULT);
}

void Assembler::dmultu(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DMULTU);
}

void Assembler::ddiv(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DDIV);
}

void Assembler::ddiv(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, DIV_OP, D_DIV_MOD);
}

void Assembler::dmod(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MOD_OP, D_DIV_MOD);
}

void Assembler::ddivu(Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, zero_reg, 0, DDIVU);
}

void Assembler::ddivu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, DIV_OP, D_DIV_MOD_U);
}

void Assembler::dmodu(Register rd, Register rs, Register rt) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(SPECIAL, rs, rt, rd, MOD_OP, D_DIV_MOD_U);
}

// Logical.

void Assembler::and_(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, AND);
}

void Assembler::andi(Register rt, Register rs, int32_t j) {
  DCHECK(is_uint16(j));
  GenInstrImmediate(ANDI, rs, rt, j);
}

void Assembler::or_(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, OR);
}

void Assembler::ori(Register rt, Register rs, int32_t j) {
  DCHECK(is_uint16(j));
  GenInstrImmediate(ORI, rs, rt, j);
}

void Assembler::xor_(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, XOR);
}

void Assembler::xori(Register rt, Register rs, int32_t j) {
  DCHECK(is_uint16(j));
  GenInstrImmediate(XORI, rs, rt, j);
}

void Assembler::nor(Register rd, Register rs, Register rt) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, NOR);
}

// Shifts.
void Assembler::sll(Register rd, Register rt, uint16_t sa,
                    bool coming_from_nop) {
  // Don't allow nop instructions in the form sll zero_reg, zero_reg to be
  // generated using the sll instruction. They must be generated using
  // nop(int/NopMarkerTypes).
  DCHECK(coming_from_nop || (rd != zero_reg && rt != zero_reg));
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, SLL);
}

void Assembler::sllv(Register rd, Register rt, Register rs) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SLLV);
}

void Assembler::srl(Register rd, Register rt, uint16_t sa) {
  GenInstrRegister(SPECIAL, zero_reg, rt, rd, sa & 0x1F, SRL);
}

void Assembler::srlv(Register rd, Register rt, Register rs) {
  GenInstrRegister(SPECIAL, rs, rt, rd, 0, SRLV);
}

void Assembler::sra(Register rd, Register rt, uint16_t sa) {
  GenInstrReg
```
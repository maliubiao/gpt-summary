Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/loong64/macro-assembler-loong64.cc`.

Here's a breakdown of how to approach this:

1. **Identify the file's purpose:** The name "macro-assembler-loong64.cc" strongly suggests it's responsible for generating low-level assembly instructions for the LoongArch64 architecture within the V8 JavaScript engine. "MacroAssembler" indicates it provides higher-level abstractions over raw assembly.

2. **Analyze the function names and their arguments:**  The function names are generally descriptive, hinting at their operations. Look for patterns related to:
    * **Comparison:**  Functions like `CompareIsNanF`, `CompareWord`, `CompareTaggedAndBranch`, `CompareRootAndBranch`.
    * **Branching/Jumping:**  Functions like `BranchTrueShortF`, `BranchFalseF`, `Branch`, `Jump`, `Call`.
    * **Data Movement:** Functions like `FmoveLow`, `Move`, `Movz`, `Movn`, `LoadZeroIfConditionNotZero`, `LoadFromConstantsTable`, `LoadRootRelative`, `StoreRootRelative`.
    * **Bit Manipulation:** Functions like `Clz_w`, `Ctz_d`, `Popcnt_w`, `ExtractBits`, `InsertBits`.
    * **Floating-Point Operations:** Functions dealing with `FPURegister`.
    * **Conversions:** `TryInlineTruncateDoubleToI`, `TruncateDoubleToI`.
    * **Address/Offset Calculation:** `GetOffset`, `LoadLabelRelative`.

3. **Look for common assembly concepts:** The code uses terms like "registers" (e.g., `Register`, `FPURegister`, `CFRegister`), "labels", "operands", "conditions", which are fundamental to assembly programming.

4. **Consider the context within V8:**  This code is part of a JavaScript engine. Therefore, some functions might be related to:
    * **Tagged Values:**  Functions like `CompareTaggedAndBranch` suggest the handling of JavaScript's tagged representation of values.
    * **Roots Table:** Functions like `LoadRoot`, `LoadRootRelative` indicate interaction with V8's roots table, which stores important internal objects and values.
    * **Builtins:** Functions like `CallBuiltin`, `TailCallBuiltin`, `LoadEntryFromBuiltinIndex` relate to calling pre-compiled code for common JavaScript operations.
    * **Stack Management:** Although not explicitly present in this snippet, macro assemblers often deal with stack operations.

5. **Address the specific questions from the user:**
    * **`.tq` extension:** The code doesn't end in `.tq`, so it's C++ not Torque.
    * **JavaScript relation:**  Identify functions that seem to directly implement or support JavaScript features (e.g., type checking, function calls). Provide examples where applicable.
    * **Code logic and examples:**  For functions with clear logical operations (like bit manipulation), provide hypothetical inputs and outputs.
    * **Common programming errors:** Think about how misuse of these low-level operations could lead to errors (e.g., incorrect register usage, miscalculation of offsets).

6. **Synthesize a summary:** Combine the observations to create a concise overview of the file's role.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on individual instruction mnemonics.
* **Correction:**  Shift focus to the higher-level functionality provided by the macro assembler functions. The mnemonics are implementation details.
* **Initial thought:**  Try to understand every single line of code.
* **Correction:**  Focus on the function signatures and names to grasp the overall purpose of each function. Details can be skipped for a summary.
* **Initial thought:**  Overlook the V8 context.
* **Correction:**  Remember that this code is part of a larger system and consider how it fits into the execution of JavaScript code. Pay attention to terms like "Tagged", "Root", and "Builtin".
这是 `v8/src/codegen/loong64/macro-assembler-loong64.cc` 文件的第三部分代码，其主要功能是为 LoongArch64 架构的 V8 引擎提供宏汇编器 (MacroAssembler) 的实现。宏汇编器提供了一系列高级的接口，用于生成底层的汇编指令，简化了代码生成过程。

**以下是这段代码的主要功能归纳：**

1. **浮点数比较和分支:**
   - `CompareIsNanF`:  比较浮点数是否为 NaN (Not a Number)。
   - `BranchTrueShortF`, `BranchFalseShortF`, `BranchTrueF`, `BranchFalseF`:  基于浮点数比较结果（存储在条件标志寄存器 CFRegister 中）进行条件跳转。提供了短跳转和长跳转两种方式，以优化代码大小和性能。

2. **浮点数寄存器操作:**
   - `FmoveLow`: 将通用寄存器的低位数据移动到浮点寄存器。
   - `Move(FPURegister dst, uint32_t src)`: 将 32 位立即数移动到浮点寄存器。
   - `Move(FPURegister dst, uint64_t src)`: 将 64 位立即数移动到浮点寄存器，并处理特殊值（如正零和负零）。

3. **通用寄存器条件移动:**
   - `Movz`:  条件移动，当条件寄存器为零时移动。
   - `Movn`:  条件移动，当条件寄存器非零时移动。
   - `LoadZeroIfConditionNotZero`:  如果条件寄存器非零，则将目标寄存器设置为零。
   - `LoadZeroIfConditionZero`: 如果条件寄存器为零，则将目标寄存器设置为零。
   - `LoadZeroIfFPUCondition`: 如果 FPU 条件标志为真，则将目标寄存器设置为零。
   - `LoadZeroIfNotFPUCondition`: 如果 FPU 条件标志为假，则将目标寄存器设置为零。

4. **位操作:**
   - `Clz_w`, `Clz_d`: 计算前导零的个数（32 位和 64 位）。
   - `Ctz_w`, `Ctz_d`: 计算尾部零的个数（32 位和 64 位）。
   - `Popcnt_w`, `Popcnt_d`: 计算二进制表示中 1 的个数（32 位和 64 位）。这里使用了一种通用的位计数算法。
   - `ExtractBits`: 从源寄存器提取指定位置和大小的位，并可以选择进行符号扩展。
   - `InsertBits`: 将源寄存器的低位插入到目标寄存器的指定位置。

5. **浮点数到整数的截断:**
   - `TryInlineTruncateDoubleToI`: 尝试内联将双精度浮点数截断为整数。
   - `TruncateDoubleToI`: 将双精度浮点数截断为整数。如果内联版本失败，则调用运行时 Stub。

6. **通用寄存器比较:**
   - `CompareWord`:  比较两个通用寄存器的值，并将比较结果（0 或 1）存储到目标寄存器中。支持多种比较条件（等于、不等于、小于、大于等）。

7. **无条件和条件分支:**
   - `Branch(Label* L, bool need_link)`: 无条件跳转到指定标签。可以选择是否保存返回地址（用于函数调用）。
   - `Branch(Label* L, Condition cond, Register rj, const Operand& rk, bool need_link)`:  根据通用寄存器的条件比较结果进行条件跳转。提供了多种优化，包括短跳转和长跳转，以及对立即数 0 的特殊处理。
   - `Branch(Label* L, Condition cond, Register rj, RootIndex index, bool need_sign_extend)`: 将寄存器的值与 Root 表中的值进行比较并进行条件跳转。

8. **标签和偏移量计算:**
   - `GetOffset`: 计算从当前位置到指定标签的偏移量。

9. **辅助函数:**
   - `GetRkAsRegisterHelper`:  获取操作数 `rk` 的寄存器表示，如果 `rk` 是立即数，则使用临时寄存器加载。
   - `BranchShortOrFallback`:  尝试生成短跳转指令，如果无法生成，则返回 `false`，由调用者处理长跳转或跳板。
   - `BranchShort`: 生成短跳转指令，并断言生成成功。

10. **带标签比较和分支:**
    - `CompareTaggedAndBranch`: 比较带标签的值并进行分支，考虑了指针压缩的情况。

11. **加载标签相对地址:**
    - `LoadLabelRelative`: 将标签的地址加载到寄存器中。

12. **加载常量表中的值:**
    - `LoadFromConstantsTable`: 从常量表中加载指定索引的值到寄存器中。

13. **加载和存储根表相对地址:**
    - `LoadRootRelative`: 从 Root 表中加载指定偏移量的值到寄存器。
    - `StoreRootRelative`: 将寄存器的值存储到 Root 表中的指定偏移量。

14. **加载根寄存器偏移量:**
    - `LoadRootRegisterOffset`: 将根寄存器加上偏移量后的地址加载到目标寄存器。

15. **外部引用操作数:**
    - `ExternalReferenceAsOperand`: 将外部引用转换为内存操作数，并根据不同的配置选择最佳的加载方式，例如直接从 Root 寄存器偏移加载或通过外部引用表加载。

16. **调用偏移量判断:**
    - `IsNearCallOffset`: 判断给定的偏移量是否是近调用的有效偏移量。

17. **计算目标偏移量:**
    - `CalculateTargetOffset`: 计算调用目标的偏移量，区分 WebAssembly 调用和普通调用。

18. **跳转指令:**
    - `Jump(Register target, Condition cond, Register rj, const Operand& rk)`: 跳转到寄存器指定的地址。
    - `Jump(intptr_t target, RelocInfo::Mode rmode, Condition cond, Register rj, const Operand& rk)`: 跳转到绝对地址，并指定重定位信息。
    - `Jump(Address target, RelocInfo::Mode rmode, Condition cond, Register rj, const Operand& rk)`: 跳转到绝对地址。
    - `Jump(Handle<Code> code, RelocInfo::Mode rmode, Condition cond, Register rj, const Operand& rk)`: 跳转到 Code 对象的入口地址。
    - `Jump(const ExternalReference& reference)`: 跳转到外部引用的地址。

19. **调用指令:**
    - `Call(Register target, Condition cond, Register rj, const Operand& rk)`: 调用寄存器指定的地址，保存返回地址。
    - `CompareTaggedRootAndBranch`: 比较带标签的值与 Root 表中的值，并进行条件跳转。
    - `CompareRootAndBranch`: 比较寄存器中的值与 Root 表中的值，并进行条件跳转。
    - `JumpIfIsInRange`: 如果寄存器的值在指定范围内，则跳转。
    - `Call(Address target, RelocInfo::Mode rmode, Condition cond, Register rj, const Operand& rk)`: 调用绝对地址，并指定重定位信息。
    - `Call(Handle<Code> code, RelocInfo::Mode rmode, Condition cond, Register rj, const Operand& rk)`: 调用 Code 对象的入口地址。

20. **加载内置函数入口地址:**
    - `LoadEntryFromBuiltinIndex`: 根据内置函数的索引加载其入口地址。

**关于你的问题：**

* **`.tq` 结尾:** 该文件以 `.cc` 结尾，因此是 C++ 源代码，不是 v8 Torque 源代码。

* **与 Javascript 的关系:**  这段代码直接负责生成执行 Javascript 代码的机器码。例如：
    ```javascript
    function compare(a, b) {
      if (a > b) {
        return 1;
      } else {
        return 0;
      }
    }
    ```
    当 V8 编译这段 Javascript 代码时，`MacroAssembler` 中的 `CompareWord` 和 `Branch` 等函数会被用来生成比较 `a` 和 `b` 并根据比较结果跳转的汇编指令。又如，当 Javascript 代码中进行浮点数运算时，相关的浮点数比较和移动指令生成也会使用到这里的函数。

* **代码逻辑推理:**  以 `Popcnt_w` (计算 32 位整数中 1 的个数) 为例：
    **假设输入:**  寄存器 `rj` 的值为 `0b01101001` (十进制 105)。
    **输出:**  寄存器 `rd` 的值将为 `4`，因为 `01101001` 中有四个 1。
    这段代码实现了一个经典的并行位计数算法。

* **用户常见的编程错误:**  直接使用 `MacroAssembler` 通常是 V8 引擎的开发者或高级使用者才会做的事情。但即使在这种情况下，也可能出现以下错误：
    * **寄存器分配错误:**  错误地使用了已经被占用的寄存器，导致数据被覆盖。
    * **偏移量计算错误:** 在内存访问或跳转时，计算了错误的偏移量，导致访问到错误的内存地址或跳转到错误的代码位置。例如，在 `LoadRootRelative` 中，如果 `offset` 计算错误，可能会读取到错误的根对象。
    * **条件码使用错误:** 在条件分支指令中使用了错误的条件码，导致程序执行流程错误。
    * **不了解指令的副作用:**  某些指令除了完成主要功能外，还可能修改某些寄存器的值，如果不了解这些副作用，可能会导致难以调试的错误。

**总结:**

`v8/src/codegen/loong64/macro-assembler-loong64.cc` 的这段代码是 LoongArch64 架构 V8 引擎的核心组成部分，它提供了一组用于生成汇编指令的高级接口，涵盖了浮点数操作、通用寄存器操作、位操作、条件分支、内存访问、函数调用等多个方面。它是 V8 将 Javascript 代码转换为可执行机器码的关键工具。

Prompt: 
```
这是目录为v8/src/codegen/loong64/macro-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/loong64/macro-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
_cond_d(cc, cmp1, cmp2, cd);
  }
}

void MacroAssembler::CompareIsNanF(FPURegister cmp1, FPURegister cmp2,
                                   CFRegister cd, bool f32) {
  CompareF(cmp1, cmp2, CUN, cd, f32);
}

void MacroAssembler::BranchTrueShortF(Label* target, CFRegister cj) {
  bcnez(cj, target);
}

void MacroAssembler::BranchFalseShortF(Label* target, CFRegister cj) {
  bceqz(cj, target);
}

void MacroAssembler::BranchTrueF(Label* target, CFRegister cj) {
  // TODO(yuyin): can be optimzed
  bool long_branch = target->is_bound()
                         ? !is_near(target, OffsetSize::kOffset21)
                         : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchFalseShortF(&skip, cj);
    Branch(target);
    bind(&skip);
  } else {
    BranchTrueShortF(target, cj);
  }
}

void MacroAssembler::BranchFalseF(Label* target, CFRegister cj) {
  bool long_branch = target->is_bound()
                         ? !is_near(target, OffsetSize::kOffset21)
                         : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchTrueShortF(&skip, cj);
    Branch(target);
    bind(&skip);
  } else {
    BranchFalseShortF(target, cj);
  }
}

void MacroAssembler::FmoveLow(FPURegister dst, Register src_low) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  DCHECK(src_low != scratch);
  movfrh2gr_s(scratch, dst);
  movgr2fr_w(dst, src_low);
  movgr2frh_w(dst, scratch);
}

void MacroAssembler::Move(FPURegister dst, uint32_t src) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(static_cast<int32_t>(src)));
  movgr2fr_w(dst, scratch);
}

void MacroAssembler::Move(FPURegister dst, uint64_t src) {
  // Handle special values first.
  if (src == base::bit_cast<uint64_t>(0.0) && has_double_zero_reg_set_) {
    fmov_d(dst, kDoubleRegZero);
  } else if (src == base::bit_cast<uint64_t>(-0.0) &&
             has_double_zero_reg_set_) {
    Neg_d(dst, kDoubleRegZero);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, Operand(static_cast<int64_t>(src)));
    movgr2fr_d(dst, scratch);
    if (dst == kDoubleRegZero) has_double_zero_reg_set_ = true;
  }
}

void MacroAssembler::Movz(Register rd, Register rj, Register rk) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  masknez(scratch, rj, rk);
  maskeqz(rd, rd, rk);
  or_(rd, rd, scratch);
}

void MacroAssembler::Movn(Register rd, Register rj, Register rk) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  maskeqz(scratch, rj, rk);
  masknez(rd, rd, rk);
  or_(rd, rd, scratch);
}

void MacroAssembler::LoadZeroIfConditionNotZero(Register dest,
                                                Register condition) {
  masknez(dest, dest, condition);
}

void MacroAssembler::LoadZeroIfConditionZero(Register dest,
                                             Register condition) {
  maskeqz(dest, dest, condition);
}

void MacroAssembler::LoadZeroIfFPUCondition(Register dest, CFRegister cc) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  movcf2gr(scratch, cc);
  LoadZeroIfConditionNotZero(dest, scratch);
}

void MacroAssembler::LoadZeroIfNotFPUCondition(Register dest, CFRegister cc) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  movcf2gr(scratch, cc);
  LoadZeroIfConditionZero(dest, scratch);
}

void MacroAssembler::Clz_w(Register rd, Register rj) { clz_w(rd, rj); }

void MacroAssembler::Clz_d(Register rd, Register rj) { clz_d(rd, rj); }

void MacroAssembler::Ctz_w(Register rd, Register rj) { ctz_w(rd, rj); }

void MacroAssembler::Ctz_d(Register rd, Register rj) { ctz_d(rd, rj); }

// TODO(LOONG_dev): Optimize like arm64, use simd instruction
void MacroAssembler::Popcnt_w(Register rd, Register rj) {
  ASM_CODE_COMMENT(this);
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
  int32_t B0 = 0x55555555;     // (T)~(T)0/3
  int32_t B1 = 0x33333333;     // (T)~(T)0/15*3
  int32_t B2 = 0x0F0F0F0F;     // (T)~(T)0/255*15
  int32_t value = 0x01010101;  // (T)~(T)0/255
  uint32_t shift = 24;         // (sizeof(T) - 1) * BITS_PER_BYTE

  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();
  Register scratch2 = t8;
  srli_w(scratch, rj, 1);
  li(scratch2, B0);
  And(scratch, scratch, scratch2);
  Sub_w(scratch, rj, scratch);
  li(scratch2, B1);
  And(rd, scratch, scratch2);
  srli_w(scratch, scratch, 2);
  And(scratch, scratch, scratch2);
  Add_w(scratch, rd, scratch);
  srli_w(rd, scratch, 4);
  Add_w(rd, rd, scratch);
  li(scratch2, B2);
  And(rd, rd, scratch2);
  li(scratch, value);
  Mul_w(rd, rd, scratch);
  srli_w(rd, rd, shift);
}

void MacroAssembler::Popcnt_d(Register rd, Register rj) {
  ASM_CODE_COMMENT(this);
  int64_t B0 = 0x5555555555555555l;     // (T)~(T)0/3
  int64_t B1 = 0x3333333333333333l;     // (T)~(T)0/15*3
  int64_t B2 = 0x0F0F0F0F0F0F0F0Fl;     // (T)~(T)0/255*15
  int64_t value = 0x0101010101010101l;  // (T)~(T)0/255
  uint32_t shift = 56;                  // (sizeof(T) - 1) * BITS_PER_BYTE

  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();
  Register scratch2 = t8;
  srli_d(scratch, rj, 1);
  li(scratch2, B0);
  And(scratch, scratch, scratch2);
  Sub_d(scratch, rj, scratch);
  li(scratch2, B1);
  And(rd, scratch, scratch2);
  srli_d(scratch, scratch, 2);
  And(scratch, scratch, scratch2);
  Add_d(scratch, rd, scratch);
  srli_d(rd, scratch, 4);
  Add_d(rd, rd, scratch);
  li(scratch2, B2);
  And(rd, rd, scratch2);
  li(scratch, value);
  Mul_d(rd, rd, scratch);
  srli_d(rd, rd, shift);
}

void MacroAssembler::ExtractBits(Register dest, Register source, Register pos,
                                 int size, bool sign_extend) {
  sra_d(dest, source, pos);
  bstrpick_d(dest, dest, size - 1, 0);
  if (sign_extend) {
    switch (size) {
      case 8:
        ext_w_b(dest, dest);
        break;
      case 16:
        ext_w_h(dest, dest);
        break;
      case 32:
        // sign-extend word
        slli_w(dest, dest, 0);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void MacroAssembler::InsertBits(Register dest, Register source, Register pos,
                                int size) {
  Rotr_d(dest, dest, pos);
  bstrins_d(dest, source, size - 1, 0);
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Sub_d(scratch, zero_reg, pos);
    Rotr_d(dest, dest, scratch);
  }
}

void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DoubleRegister double_input,
                                                Label* done) {
  DoubleRegister single_scratch = kScratchDoubleReg;
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();

  ftintrz_l_d(single_scratch, double_input);
  movfr2gr_d(scratch2, single_scratch);
  li(scratch, 1L << 63);
  Xor(scratch, scratch, scratch2);
  rotri_d(scratch2, scratch, 1);
  movfr2gr_s(result, single_scratch);
  Branch(done, ne, scratch, Operand(scratch2));
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode) {
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  Sub_d(sp, sp,
        Operand(kDoubleSize + kSystemPointerSize));  // Put input on stack.
  St_d(ra, MemOperand(sp, kSystemPointerSize));
  Fst_d(double_input, MemOperand(sp, 0));

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

  Pop(ra, result);
  bind(&done);
}

void MacroAssembler::CompareWord(Condition cond, Register dst, Register lhs,
                                 const Operand& rhs) {
  switch (cond) {
    case eq:
    case ne: {
      if (rhs.IsImmediate()) {
        if (rhs.immediate() == 0) {
          if (cond == eq) {
            Sltu(dst, lhs, 1);
          } else {
            Sltu(dst, zero_reg, lhs);
          }
        } else if (is_int12(-rhs.immediate())) {
          Add_d(dst, lhs, Operand(-rhs.immediate()));
          if (cond == eq) {
            Sltu(dst, dst, 1);
          } else {
            Sltu(dst, zero_reg, dst);
          }
        } else {
          Xor(dst, lhs, rhs);
          if (cond == eq) {
            Sltu(dst, dst, 1);
          } else {
            Sltu(dst, zero_reg, dst);
          }
        }
      } else {
        Xor(dst, lhs, rhs);
        if (cond == eq) {
          Sltu(dst, dst, 1);
        } else {
          Sltu(dst, zero_reg, dst);
        }
      }
      break;
    }
    case lt:
      Slt(dst, lhs, rhs);
      break;
    case gt:
      Sgt(dst, lhs, rhs);
      break;
    case le:
      Sle(dst, lhs, rhs);
      break;
    case ge:
      Sge(dst, lhs, rhs);
      break;
    case lo:
      Sltu(dst, lhs, rhs);
      break;
    case hs:
      Sgeu(dst, lhs, rhs);
      break;
    case hi:
      Sgtu(dst, lhs, rhs);
      break;
    case ls:
      Sleu(dst, lhs, rhs);
      break;
    default:
      UNREACHABLE();
  }
}

// BRANCH_ARGS_CHECK checks that conditional jump arguments are correct.
#define BRANCH_ARGS_CHECK(cond, rj, rk)                                  \
  DCHECK((cond == cc_always && rj == zero_reg && rk.rm() == zero_reg) || \
         (cond != cc_always && (rj != zero_reg || rk.rm() != zero_reg)))

void MacroAssembler::Branch(Label* L, bool need_link) {
  int offset = GetOffset(L, OffsetSize::kOffset26);
  if (need_link) {
    bl(offset);
  } else {
    b(offset);
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rj,
                            const Operand& rk, bool need_link) {
  if (L->is_bound()) {
    BRANCH_ARGS_CHECK(cond, rj, rk);
    if (!BranchShortOrFallback(L, cond, rj, rk, need_link)) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rj, rk, need_link);
        Branch(L, need_link);
        bind(&skip);
      } else {
        Branch(L);
      }
    }
  } else {
    if (is_trampoline_emitted()) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rj, rk, need_link);
        Branch(L, need_link);
        bind(&skip);
      } else {
        Branch(L);
      }
    } else {
      BranchShort(L, cond, rj, rk, need_link);
    }
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rj,
                            RootIndex index, bool need_sign_extend) {
  UseScratchRegisterScope temps(this);
  Register right = temps.Acquire();
  if (COMPRESS_POINTERS_BOOL) {
    Register left = rj;
    if (need_sign_extend) {
      left = temps.hasAvailable() ? temps.Acquire() : t8;
      slli_w(left, rj, 0);
    }
    LoadTaggedRoot(right, index);
    Branch(L, cond, left, Operand(right));
  } else {
    LoadRoot(right, index);
    Branch(L, cond, rj, Operand(right));
  }
}

int32_t MacroAssembler::GetOffset(Label* L, OffsetSize bits) {
  return branch_offset_helper(L, bits) >> 2;
}

Register MacroAssembler::GetRkAsRegisterHelper(const Operand& rk,
                                               Register scratch) {
  Register r2 = no_reg;
  if (rk.is_reg()) {
    r2 = rk.rm();
  } else {
    r2 = scratch;
    li(r2, rk);
  }

  return r2;
}

bool MacroAssembler::BranchShortOrFallback(Label* L, Condition cond,
                                           Register rj, const Operand& rk,
                                           bool need_link) {
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
  DCHECK_NE(rj, zero_reg);

  // Be careful to always use shifted_branch_offset only just before the
  // branch instruction, as the location will be remember for patching the
  // target.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    int offset = 0;
    switch (cond) {
      case cc_always:
        if (L->is_bound() && !is_near(L, OffsetSize::kOffset26)) return false;
        offset = GetOffset(L, OffsetSize::kOffset26);
        if (need_link) {
          bl(offset);
        } else {
          b(offset);
        }
        break;
      case eq:
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          // beq is used here to make the code patchable. Otherwise b should
          // be used which has no condition field so is not patchable.
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset16);
          beq(rj, rj, offset);
        } else if (IsZero(rk)) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset21)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset21);
          beqz(rj, offset);
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          // We don't want any other register but scratch clobbered.
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          offset = GetOffset(L, OffsetSize::kOffset16);
          beq(rj, sc, offset);
        }
        break;
      case ne:
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          // bne is used here to make the code patchable. Otherwise we
          // should not generate any instruction.
          offset = GetOffset(L, OffsetSize::kOffset16);
          bne(rj, rj, offset);
        } else if (IsZero(rk)) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset21)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset21);
          bnez(rj, offset);
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          // We don't want any other register but scratch clobbered.
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          offset = GetOffset(L, OffsetSize::kOffset16);
          bne(rj, sc, offset);
        }
        break;

      // Signed comparison.
      case greater:
        // rj > rk
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          // No code needs to be emitted.
        } else if (IsZero(rk)) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset16);
          blt(zero_reg, rj, offset);
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          DCHECK(rj != sc);
          offset = GetOffset(L, OffsetSize::kOffset16);
          blt(sc, rj, offset);
        }
        break;
      case greater_equal:
        // rj >= rk
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset26)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset26);
          b(offset);
        } else if (IsZero(rk)) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset16);
          bge(rj, zero_reg, offset);
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          DCHECK(rj != sc);
          offset = GetOffset(L, OffsetSize::kOffset16);
          bge(rj, sc, offset);
        }
        break;
      case less:
        // rj < rk
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          // No code needs to be emitted.
        } else if (IsZero(rk)) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset16);
          blt(rj, zero_reg, offset);
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          DCHECK(rj != sc);
          offset = GetOffset(L, OffsetSize::kOffset16);
          blt(rj, sc, offset);
        }
        break;
      case less_equal:
        // rj <= rk
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset26)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset26);
          b(offset);
        } else if (IsZero(rk)) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset16);
          bge(zero_reg, rj, offset);
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          DCHECK(rj != sc);
          offset = GetOffset(L, OffsetSize::kOffset16);
          bge(sc, rj, offset);
        }
        break;

      // Unsigned comparison.
      case Ugreater:
        // rj > rk
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          // No code needs to be emitted.
        } else if (IsZero(rk)) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset26)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset26);
          bnez(rj, offset);
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          DCHECK(rj != sc);
          offset = GetOffset(L, OffsetSize::kOffset16);
          bltu(sc, rj, offset);
        }
        break;
      case Ugreater_equal:
        // rj >= rk
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset26)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset26);
          b(offset);
        } else if (IsZero(rk)) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset26)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset26);
          b(offset);
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          DCHECK(rj != sc);
          offset = GetOffset(L, OffsetSize::kOffset16);
          bgeu(rj, sc, offset);
        }
        break;
      case Uless:
        // rj < rk
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          // No code needs to be emitted.
        } else if (IsZero(rk)) {
          // No code needs to be emitted.
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          DCHECK(rj != sc);
          offset = GetOffset(L, OffsetSize::kOffset16);
          bltu(rj, sc, offset);
        }
        break;
      case Uless_equal:
        // rj <= rk
        if (rk.is_reg() && rj.code() == rk.rm().code()) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset26)) return false;
          if (need_link) pcaddi(ra, 2);
          offset = GetOffset(L, OffsetSize::kOffset26);
          b(offset);
        } else if (IsZero(rk)) {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset21)) return false;
          if (need_link) pcaddi(ra, 2);
          beqz(rj, L);
        } else {
          if (L->is_bound() && !is_near(L, OffsetSize::kOffset16)) return false;
          if (need_link) pcaddi(ra, 2);
          Register sc = GetRkAsRegisterHelper(rk, scratch);
          DCHECK(rj != sc);
          offset = GetOffset(L, OffsetSize::kOffset16);
          bgeu(sc, rj, offset);
        }
        break;
      default:
        UNREACHABLE();
    }
  }
  return true;
}

void MacroAssembler::BranchShort(Label* L, Condition cond, Register rj,
                                 const Operand& rk, bool need_link) {
  BRANCH_ARGS_CHECK(cond, rj, rk);
  bool result = BranchShortOrFallback(L, cond, rj, rk, need_link);
  DCHECK(result);
  USE(result);
}

void MacroAssembler::CompareTaggedAndBranch(Label* label, Condition cond,
                                            Register r1, const Operand& r2,
                                            bool need_link) {
  if (COMPRESS_POINTERS_BOOL) {
    UseScratchRegisterScope temps(this);
    Register scratch0 = temps.Acquire();
    slli_w(scratch0, r1, 0);
    if (IsZero(r2)) {
      Branch(label, cond, scratch0, Operand(zero_reg), need_link);
    } else {
      Register scratch1 = temps.hasAvailable() ? temps.Acquire() : t8;
      if (r2.is_reg()) {
        slli_w(scratch1, r2.rm(), 0);
      } else {
        li(scratch1, r2);
      }
      Branch(label, cond, scratch0, Operand(scratch1), need_link);
    }
  } else {
    Branch(label, cond, r1, r2, need_link);
  }
}

void MacroAssembler::LoadLabelRelative(Register dest, Label* target) {
  ASM_CODE_COMMENT(this);
  // pcaddi could handle 22-bit pc offset.
  int32_t offset = branch_offset_helper(target, OffsetSize::kOffset20);
  DCHECK(is_int22(offset));
  pcaddi(dest, offset >> 2);
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  ASM_CODE_COMMENT(this);
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(destination,
                  FieldMemOperand(destination, FixedArray::OffsetOfElementAt(
                                                   constant_index)));
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  Ld_d(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  St_d(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    Move(destination, kRootRegister);
  } else {
    Add_d(destination, kRootRegister, Operand(offset));
  }
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
    if (options().isolate_independent_code) {
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
        Ld_d(scratch,
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

bool MacroAssembler::IsNearCallOffset(int64_t offset) {
  return is_int28(offset);
}

// The calculated offset is either:
// * the 'target' input unmodified if this is a Wasm call, or
// * the offset of the target from the current PC, in instructions, for any
//   other type of call.
// static
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

void MacroAssembler::Jump(Register target, Condition cond, Register rj,
                          const Operand& rk) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (cond == cc_always) {
    jirl(zero_reg, target, 0);
  } else {
    BRANCH_ARGS_CHECK(cond, rj, rk);
    Label skip;
    Branch(&skip, NegateCondition(cond), rj, rk);
    jirl(zero_reg, target, 0);
    bind(&skip);
  }
}

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond, Register rj, const Operand& rk) {
  Label skip;
  if (cond != cc_always) {
    Branch(&skip, NegateCondition(cond), rj, rk);
  }
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    li(t7, Operand(target, rmode));
    jirl(zero_reg, t7, 0);
    bind(&skip);
  }
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode, Condition cond,
                          Register rj, const Operand& rk) {
  Jump(static_cast<intptr_t>(target), rmode, cond, rj, rk);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, Register rj, const Operand& rk) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Label skip;
  if (cond != cc_always) {
    BranchShort(&skip, NegateCondition(cond), rj, rk);
  }

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    TailCallBuiltin(builtin);
    bind(&skip);
    return;
  }

  int32_t target_index = AddCodeTarget(code);
  Jump(static_cast<Address>(target_index), rmode, cc_always, rj, rk);
  bind(&skip);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  li(t7, reference);
  Jump(t7);
}

// Note: To call gcc-compiled C code on loonarch, you must call through t[0-8].
void MacroAssembler::Call(Register target, Condition cond, Register rj,
                          const Operand& rk) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (cond == cc_always) {
    jirl(ra, target, 0);
  } else {
    BRANCH_ARGS_CHECK(cond, rj, rk);
    Label skip;
    Branch(&skip, NegateCondition(cond), rj, rk);
    jirl(ra, target, 0);
    bind(&skip);
  }
  set_pc_for_safepoint();
}

void MacroAssembler::CompareTaggedRootAndBranch(const Register& obj,
                                                RootIndex index, Condition cc,
                                                Label* target) {
  ASM_CODE_COMMENT(this);
  // AssertSmiOrHeapObjectInMainCompressionCage(obj);
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

void MacroAssembler::JumpIfIsInRange(Register value, unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  ASM_CODE_COMMENT(this);
  if (lower_limit != 0) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Sub_d(scratch, value, Operand(lower_limit));
    Branch(on_in_range, ls, scratch, Operand(higher_limit - lower_limit));
  } else {
    Branch(on_in_range, ls, value, Operand(higher_limit - lower_limit));
  }
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode, Condition cond,
                          Register rj, const Operand& rk) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Label skip;
  if (cond != cc_always) {
    BranchShort(&skip, NegateCondition(cond), rj, rk);
  }
  intptr_t offset_diff = target - pc_offset();
  if (RelocInfo::IsNoInfo(rmode) && is_int28(offset_diff)) {
    bl(offset_diff >> 2);
  } else if (RelocInfo::IsNoInfo(rmode) && is_int38(offset_diff)) {
    pcaddu18i(t7, static_cast<int32_t>(offset_diff) >> 18);
    jirl(ra, t7, (offset_diff & 0x3ffff) >> 2);
  } else {
    li(t7, Operand(static_cast<int64_t>(target), rmode), ADDRESS_LOAD);
    Call(t7, cc_always, rj, rk);
  }
  bind(&skip);
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, Register rj, const Operand& rk) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }

  DCHECK(RelocInfo::IsCodeTarget(rmode));
  int32_t target_index = AddCodeTarget(code);
  Call(static_cast<Address>(target_index), rmode, cond, rj, rk);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  ASM_CODE_COMMENT(this);
  static_assert(kSystemPointerSize == 8);
  static_assert(kSmiTagSize == 1);
  static_assert(kSmiTag == 0);

  // The builtin_index register contains the builtin index as a Smi.
  SmiUntag(target, builtin_index);
  Alsl_d(target, target, kRootRegister, kSystemPointerSizeLog2, t7);
  Ld_d(target, MemOperan
"""


```
Response: The user is asking for a summary of the functionality of the provided C++ code snippet. This is the second part of a three-part series. The code appears to be part of a macro assembler for the LoongArch64 architecture within the V8 JavaScript engine.

I need to analyze the provided code and identify the key operations and abstractions it implements. Since it's part 2 of 3, it likely builds upon the functionalities of part 1 and provides a distinct set of capabilities. The code includes functions related to:

- **Floating-point comparisons and branching:** `CompareIsNanF`, `BranchTrueShortF`, `BranchFalseShortF`, `BranchTrueF`, `BranchFalseF`.
- **Floating-point moves:** `FmoveLow`, `Move` (for both immediate and register sources).
- **Conditional moves:** `Movz`, `Movn`, `LoadZeroIfConditionNotZero`, `LoadZeroIfConditionZero`, `LoadZeroIfFPUCondition`, `LoadZeroIfNotFPUCondition`.
- **Bit manipulation:** `Clz_w`, `Clz_d`, `Ctz_w`, `Ctz_d`, `Popcnt_w`, `Popcnt_d`, `ExtractBits`, `InsertBits`.
- **Floating-point conversion:** `TryInlineTruncateDoubleToI`, `TruncateDoubleToI`.
- **Integer comparisons:** `CompareWord`.
- **Unconditional and conditional branching:** `Branch`, `BranchShort`, `CompareTaggedAndBranch`.
- **Loading constants and addresses:** `LoadLabelRelative`, `LoadFromConstantsTable`, `LoadRootRelative`, `StoreRootRelative`, `LoadRootRegisterOffset`, `ExternalReferenceAsOperand`.
- **Jumps and calls:** `Jump`, `Call`, `TailCallBuiltin`, `StoreReturnAddressAndCall`, `CallBuiltinByIndex`, `CallBuiltin`.
- **Stack manipulation:** `DropArguments`, `DropArgumentsAndPushNewReceiver`, `Ret`, `Drop`, `Swap`, `Push`, `PushArray`.
- **Exception handling:** `PushStackHandler`, `PopStackHandler`, `FPUCanonicalizeNaN`.
- **JavaScript invocation:** `LoadStackLimit`, `StackOverflowCheck`, `TestCodeIsMarkedForDeoptimizationAndJump`, `InvokePrologue`, `CallDebugOnFunctionCall`, `InvokeFunctionCode`, `InvokeFunctionWithNewTarget`, `InvokeFunction`.
- **Object type checks:** `GetObjectType`, `GetInstanceTypeRange`.
- **Runtime calls:** `AddOverflow_d`, `SubOverflow_d`, `MulOverflow_w`, `MulOverflow_d`, `CallRuntime`, `TailCallRuntime`, `JumpToExternalReference`, `LoadWeakValue`, `EmitIncrementCounter`, `EmitDecrementCounter`.
- **Debugging and assertions:** `Trap`, `DebugBreak`, `Check`, `SbxCheck`, `Abort`.
- **Memory access:** `LoadMap`, `LoadCompressedMap`, `LoadFeedbackVector`, `LoadNativeContextSlot`.
- **Frame management:** `StubPrologue`, `Prologue`, `EnterFrame`, `LeaveFrame`.

Considering this is part 2, I should focus on the functionalities specifically present in this segment and how they relate to the broader goal of a macro assembler for JavaScript execution. The presence of `InvokeFunction` and related functions suggests this part deals with the mechanics of calling JavaScript functions. The floating-point and bit manipulation instructions indicate support for numerical operations. The branching and comparison instructions are crucial for control flow.

The relation to JavaScript is evident in functions like `InvokeFunction`, `CallRuntime`, and the handling of tagged values. I can provide simple JavaScript examples to illustrate how some of these low-level operations might be used in the execution of JavaScript code.
这是 `v8/src/codegen/loong64/macro-assembler-loong64.cc` 文件中宏汇编器（MacroAssembler）实现的一部分，专门针对 LoongArch64 架构。这部分代码主要负责以下功能：

**1. 浮点运算和比较相关的宏指令:**

- 提供了用于比较浮点数是否为 NaN (`CompareIsNanF`) 的宏指令。
- 提供了基于浮点比较结果进行短跳转 (`BranchTrueShortF`, `BranchFalseShortF`) 和长跳转 (`BranchTrueF`, `BranchFalseF`) 的宏指令。

**2. 浮点寄存器操作的宏指令:**

- 提供了在浮点寄存器和通用寄存器之间移动低位数据的宏指令 (`FmoveLow`).
- 提供了将 32 位和 64 位立即数加载到浮点寄存器的宏指令 (`Move`).

**3. 基于条件码进行条件移动的宏指令:**

- 提供了基于通用寄存器的零/非零状态进行条件移动的宏指令 (`Movz`, `Movn`).
- 提供了基于通用寄存器的零/非零状态加载零值的宏指令 (`LoadZeroIfConditionNotZero`, `LoadZeroIfConditionZero`).
- 提供了基于浮点条件码寄存器的状态加载零值的宏指令 (`LoadZeroIfFPUCondition`, `LoadZeroIfNotFPUCondition`).

**4. 位操作相关的宏指令:**

- 提供了计算前导零个数 (`Clz_w`, `Clz_d`) 和尾部零个数 (`Ctz_w`, `Ctz_d`) 的宏指令。
- 提供了计算字或双字中置位比特数的宏指令 (`Popcnt_w`, `Popcnt_d`)。
- 提供了提取 (`ExtractBits`) 和插入 (`InsertBits`) 位段的宏指令。

**5. 浮点数到整数转换的宏指令:**

- 提供了尝试内联将双精度浮点数截断为整数的宏指令 (`TryInlineTruncateDoubleToI`)，如果无法内联则回退到调用 Stub。
- 提供了将双精度浮点数截断为整数的宏指令 (`TruncateDoubleToI`)，它会根据情况选择内联或调用运行时 Stub。

**6. 整数比较相关的宏指令:**

- 提供了比较两个操作数大小的宏指令 (`CompareWord`)，并根据比较结果设置目标寄存器。

**7. 分支跳转相关的宏指令:**

- 提供了无条件和有条件跳转的宏指令 (`Branch`)，支持长跳转和短跳转的优化。
- 提供了根据标记对象进行比较并跳转的宏指令 (`CompareTaggedAndBranch`)，考虑了指针压缩的情况。
- 提供了短跳转的宏指令 (`BranchShort`)。

**8. 加载常量和地址的宏指令:**

- 提供了加载相对于标签地址的宏指令 (`LoadLabelRelative`).
- 提供了从常量表加载值的宏指令 (`LoadFromConstantsTable`).
- 提供了加载和存储相对于 Root Register 的值的宏指令 (`LoadRootRelative`, `StoreRootRelative`).
- 提供了加载 Root Register 加上偏移量的地址的宏指令 (`LoadRootRegisterOffset`).
- 提供了将外部引用作为操作数使用的宏指令 (`ExternalReferenceAsOperand`)，会根据不同的情况选择最优的加载方式。

**9. 函数调用和跳转相关的宏指令:**

- 提供了无条件和有条件跳转到指定寄存器地址的宏指令 (`Jump`).
- 提供了无条件和有条件调用指定寄存器地址的函数的宏指令 (`Call`).
- 提供了尾调用内置函数的宏指令 (`TailCallBuiltin`).
- 提供了存储返回地址并调用目标地址的宏指令 (`StoreReturnAddressAndCall`)，常用于调用 C 函数。
- 提供了通过索引调用内置函数的宏指令 (`CallBuiltinByIndex`).
- 提供了调用内置函数的宏指令 (`CallBuiltin`)，根据编译选项选择不同的调用方式。

**10. 栈操作相关的宏指令:**

- 提供了丢弃栈上指定数量参数的宏指令 (`DropArguments`).
- 提供了丢弃参数并压入新的接收者的宏指令 (`DropArgumentsAndPushNewReceiver`).
- 提供了返回指令 (`Ret`).
- 提供了有条件丢弃栈上指定数量数据的宏指令 (`Drop`).
- 提供了交换两个寄存器值的宏指令 (`Swap`).
- 提供了调用标签位置的宏指令 (`Call`).
- 提供了压入立即数（Smi 或 HeapObject）到栈上的宏指令 (`Push`).
- 提供了将数组内容压入栈的宏指令 (`PushArray`)，支持正序和逆序压栈。

**11. 异常处理相关的宏指令:**

- 提供了压入和弹出栈处理器的宏指令 (`PushStackHandler`, `PopStackHandler`).
- 提供了将浮点数 NaN 规范化的宏指令 (`FPUCanonicalizeNaN`).

**12. JavaScript 调用相关的宏指令:**

- 提供了加载栈限制的宏指令 (`LoadStackLimit`).
- 提供了进行栈溢出检查的宏指令 (`StackOverflowCheck`).
- 提供了检查代码是否被标记为需要反优化的宏指令 (`TestCodeIsMarkedForDeoptimizationAndJump`).
- 提供了函数调用的序言处理宏指令 (`InvokePrologue`)，处理参数数量不匹配的情况。
- 提供了在函数调用时调用调试钩子的宏指令 (`CallDebugOnFunctionCall`).
- 提供了调用 JavaScript 函数的宏指令 (`InvokeFunction`, `InvokeFunctionWithNewTarget`, `InvokeFunctionCode`)，处理不同的调用场景（普通调用、带 `new.target` 的调用）和参数适配模式。

**13. 类型检查相关的宏指令:**

- 提供了获取对象类型的宏指令 (`GetObjectType`).
- 提供了获取实例类型范围的宏指令 (`GetInstanceTypeRange`).

**14. 运行时调用的宏指令:**

- 提供了带有溢出检测的加法和减法宏指令 (`AddOverflow_d`, `SubOverflow_d`).
- 提供了带有溢出检测的乘法宏指令 (`MulOverflow_w`, `MulOverflow_d`).
- 提供了调用运行时函数的宏指令 (`CallRuntime`).
- 提供了尾调用运行时函数的宏指令 (`TailCallRuntime`).
- 提供了跳转到外部引用的宏指令 (`JumpToExternalReference`).
- 提供了加载弱引用的值的宏指令 (`LoadWeakValue`)，如果弱引用被清除则跳转到指定标签。
- 提供了发射递增和递减计数器的宏指令 (`EmitIncrementCounter`, `EmitDecrementCounter`).

**15. 调试和断言相关的宏指令:**

- 提供了触发陷阱和断点的宏指令 (`Trap`, `DebugBreak`).
- 提供了进行条件检查并在条件不满足时中止程序的宏指令 (`Check`, `SbxCheck`, `Abort`).

**16. 内存访问相关的宏指令:**

- 提供了加载对象 Map 的宏指令 (`LoadMap`).
- 提供了加载压缩 Map 的宏指令 (`LoadCompressedMap`).
- 提供了加载反馈向量的宏指令 (`LoadFeedbackVector`).
- 提供了加载 NativeContext 插槽的宏指令 (`LoadNativeContextSlot`).

**17. 帧管理相关的宏指令:**

- 提供了 Stub 序言的宏指令 (`StubPrologue`).
- 提供了标准帧序言的宏指令 (`Prologue`).
- 提供了进入和离开帧的宏指令 (`EnterFrame`, `LeaveFrame`).

**与 JavaScript 的关系：**

这部分宏汇编代码是 V8 引擎执行 JavaScript 代码的关键组成部分。许多宏指令直接对应了 JavaScript 的运行时行为，例如：

- **函数调用 (`InvokeFunction` 等):**  JavaScript 中的函数调用需要设置调用栈、传递参数、执行函数体等，这些操作在底层就需要通过类似 `InvokeFunction` 这样的宏指令来实现。
- **类型检查 (`GetObjectType` 等):** JavaScript 是动态类型语言，运行时需要进行类型检查，例如判断一个对象是否为特定类型，这些可以通过加载对象的 Map 并检查其类型信息来实现。
- **算术运算 (`AddOverflow_d` 等):** JavaScript 中的数值运算，例如加法、减法，需要考虑溢出等情况，这些宏指令提供了底层的溢出检测机制。
- **异常处理 (`PushStackHandler` 等):** JavaScript 中的 `try...catch` 机制需要底层的栈处理器管理，这些宏指令用于管理异常处理上下文。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 引擎执行这段 JavaScript 代码时，`InvokeFunction` 相关的宏指令会被用来调用 `add` 函数。在 `add` 函数内部，`AddOverflow_d` 这样的宏指令可能会被用来执行底层的加法运算，并检查是否发生溢出。

再比如，对于类型检查：

```javascript
function isNumber(obj) {
  return typeof obj === 'number';
}

isNumber(123);
```

在执行 `isNumber` 函数时，`GetObjectType` 这样的宏指令会被用来获取 `obj` 的类型信息，以便进行比较。

总而言之，这部分 `macro-assembler-loong64.cc` 代码提供了在 LoongArch64 架构上执行 JavaScript 代码所需的底层指令抽象，它将高级的 JavaScript 概念映射到具体的机器指令，是 V8 引擎实现跨平台能力的关键。

Prompt: 
```
这是目录为v8/src/codegen/loong64/macro-assembler-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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
  Ld_d(target, MemOperand(target, IsolateData::builtin_entry_table_offset()));
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  Ld_d(destination, EntryFromBuiltinAsOperand(builtin));
}
MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  ASM_CODE_COMMENT(this);
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}

void MacroAssembler::CallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  UseScratchRegisterScope temps(this);
  Register temp = temps.Acquire();
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(temp);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative: {
      RecordRelocInfo(RelocInfo::NEAR_BUILTIN_ENTRY);
      bl(static_cast<int>(builtin));
      set_pc_for_safepoint();
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Call(temp);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        RecordRelocInfo(RelocInfo::RELATIVE_CODE_TARGET);
        bl(code_target_index);
        set_pc_for_safepoint();
      } else {
        LoadEntryFromBuiltin(builtin, temp);
        Call(temp);
      }
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond,
                                     Register type, Operand range) {
  if (cond != cc_always) {
    Label done;
    Branch(&done, NegateCondition(cond), type, range);
    TailCallBuiltin(builtin);
    bind(&done);
  } else {
    TailCallBuiltin(builtin);
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  UseScratchRegisterScope temps(this);
  Register temp = temps.Acquire();

  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Jump(temp);
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Jump(temp);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative: {
      RecordRelocInfo(RelocInfo::NEAR_BUILTIN_ENTRY);
      b(static_cast<int>(builtin));
      set_pc_for_safepoint();
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        RecordRelocInfo(RelocInfo::RELATIVE_CODE_TARGET);
        b(code_target_index);
      } else {
        LoadEntryFromBuiltin(builtin, temp);
        Jump(temp);
      }
      break;
    }
  }
}

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  ASM_CODE_COMMENT(this);
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

  Assembler::BlockTrampolinePoolScope block_trampoline_pool(this);
  static constexpr int kNumInstructionsToJump = 2;
  Label find_ra;
  // Adjust the value in ra to point to the correct return location, 2nd
  // instruction past the real call into C code (the jirl)), and push it.
  // This is the return address of the exit frame.
  pcaddi(ra, kNumInstructionsToJump + 1);
  bind(&find_ra);

  // This spot was reserved in EnterExitFrame.
  St_d(ra, MemOperand(sp, 0));
  // Stack is still aligned.

  // TODO(LOONG_dev): can be jirl target? a0 -- a7?
  jirl(zero_reg, target, 0);
  // Make sure the stored 'ra' points to this position.
  DCHECK_EQ(kNumInstructionsToJump, InstructionsGeneratedSince(&find_ra));
}

void MacroAssembler::DropArguments(Register count) {
  Alsl_d(sp, count, sp, kSystemPointerSizeLog2);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  Push(receiver);
}

void MacroAssembler::Ret(Condition cond, Register rj, const Operand& rk) {
  Jump(ra, cond, rj, rk);
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

  Add_d(sp, sp, Operand(count * kSystemPointerSize));

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
    mov(scratch, reg1);
    mov(reg1, reg2);
    mov(reg2, scratch);
  }
}

void MacroAssembler::Call(Label* target) { Branch(target, true); }

void MacroAssembler::Push(Tagged<Smi> smi) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(smi));
  Push(scratch);
}

void MacroAssembler::Push(Handle<HeapObject> handle) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(handle));
  Push(scratch);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               Register scratch2, PushArrayOrder order) {
  DCHECK(!AreAliased(array, size, scratch, scratch2));
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    mov(scratch, zero_reg);
    jmp(&entry);
    bind(&loop);
    Alsl_d(scratch2, scratch, array, kSystemPointerSizeLog2, t7);
    Ld_d(scratch2, MemOperand(scratch2, 0));
    Push(scratch2);
    Add_d(scratch, scratch, Operand(1));
    bind(&entry);
    Branch(&loop, less, scratch, Operand(size));
  } else {
    mov(scratch, size);
    jmp(&entry);
    bind(&loop);
    Alsl_d(scratch2, scratch, array, kSystemPointerSizeLog2, t7);
    Ld_d(scratch2, MemOperand(scratch2, 0));
    Push(scratch2);
    bind(&entry);
    Add_d(scratch, scratch, Operand(-1));
    Branch(&loop, greater_equal, scratch, Operand(zero_reg));
  }
}

// ---------------------------------------------------------------------------
// Exception handling.

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize);

  Push(Smi::zero());  // Padding.

  // Link the current handler as the next handler.
  li(t2,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  Ld_d(t1, MemOperand(t2, 0));
  Push(t1);

  // Set this new handler as the current one.
  St_d(sp, MemOperand(t2, 0));
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kNextOffset == 0);
  Pop(a1);
  Add_d(sp, sp,
        Operand(static_cast<int64_t>(StackHandlerConstants::kSize -
                                     kSystemPointerSize)));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  St_d(a1, MemOperand(scratch, 0));
}

void MacroAssembler::FPUCanonicalizeNaN(const DoubleRegister dst,
                                        const DoubleRegister src) {
  fsub_d(dst, src, kDoubleRegZero);
}

// -----------------------------------------------------------------------------
// JavaScript invokes.

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();

  Ld_d(destination, MemOperand(kRootRegister, static_cast<int32_t>(offset)));
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch1,
                                        Register scratch2,
                                        Label* stack_overflow) {
  ASM_CODE_COMMENT(this);
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.

  LoadStackLimit(scratch1, StackLimitKind::kRealStackLimit);
  // Make scratch1 the space we have left. The stack might already be overflowed
  // here which will cause scratch1 to become negative.
  sub_d(scratch1, sp, scratch1);
  // Check if the arguments will overflow the stack.
  slli_d(scratch2, num_args, kSystemPointerSizeLog2);
  // Signed comparison.
  Branch(stack_overflow, le, scratch1, Operand(scratch2));
}

void MacroAssembler::TestCodeIsMarkedForDeoptimizationAndJump(
    Register code_data_container, Register scratch, Condition cond,
    Label* target) {
  Ld_wu(scratch, FieldMemOperand(code_data_container, Code::kFlagsOffset));
  And(scratch, scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
  Branch(target, cond, scratch, Operand(zero_reg));
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  Label regular_invoke;

  //  a0: actual arguments count
  //  a1: function (passed through to callee)
  //  a2: expected arguments count

  DCHECK_EQ(actual_parameter_count, a0);
  DCHECK_EQ(expected_parameter_count, a2);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  sub_d(expected_parameter_count, expected_parameter_count,
        actual_parameter_count);
  Branch(&regular_invoke, le, expected_parameter_count, Operand(zero_reg));

  Label stack_overflow;
  StackOverflowCheck(expected_parameter_count, t0, t1, &stack_overflow);
  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy;
    Register src = a6, dest = a7;
    mov(src, sp);
    slli_d(t0, expected_parameter_count, kSystemPointerSizeLog2);
    Sub_d(sp, sp, Operand(t0));
    // Update stack pointer.
    mov(dest, sp);
    mov(t0, actual_parameter_count);
    bind(&copy);
    Ld_d(t1, MemOperand(src, 0));
    St_d(t1, MemOperand(dest, 0));
    Sub_d(t0, t0, Operand(1));
    Add_d(src, src, Operand(kSystemPointerSize));
    Add_d(dest, dest, Operand(kSystemPointerSize));
    Branch(&copy, gt, t0, Operand(zero_reg));
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(t0, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    St_d(t0, MemOperand(a7, 0));
    Sub_d(expected_parameter_count, expected_parameter_count, Operand(1));
    Add_d(a7, a7, Operand(kSystemPointerSize));
    Branch(&loop, gt, expected_parameter_count, Operand(zero_reg));
  }
  b(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    break_(0xCC);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CallDebugOnFunctionCall(
    Register fun, Register new_target,
    Register expected_parameter_count_or_dispatch_handle,
    Register actual_parameter_count) {
  DCHECK(!AreAliased(t0, fun, new_target,
                     expected_parameter_count_or_dispatch_handle,
                     actual_parameter_count));
  // Load receiver to pass it later to DebugOnFunctionCall hook.
  LoadReceiver(t0);
  FrameScope frame(
      this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

  SmiTag(expected_parameter_count_or_dispatch_handle);
  SmiTag(actual_parameter_count);
  Push(expected_parameter_count_or_dispatch_handle, actual_parameter_count);

  if (new_target.is_valid()) {
    Push(new_target);
  }
  Push(fun, fun, t0);
  CallRuntime(Runtime::kDebugOnFunctionCall);
  Pop(fun);
  if (new_target.is_valid()) {
    Pop(new_target);
  }

  Pop(expected_parameter_count_or_dispatch_handle, actual_parameter_count);
  SmiUntag(actual_parameter_count);
  SmiUntag(expected_parameter_count_or_dispatch_handle);
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::InvokeFunction(
    Register function, Register actual_parameter_count, InvokeType type,
    ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, a1);

  // Set up the context.
  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, no_reg, actual_parameter_count, type,
                     argument_adaption_mode);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, a1);

  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, new_target, actual_parameter_count, type);
}

void MacroAssembler::InvokeFunctionCode(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type, ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, a1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == a3);

  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Ld_w(dispatch_handle,
       FieldMemOperand(function, JSFunction::kDispatchHandleOffset));

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    li(t0, ExternalReference::debug_hook_on_function_call_address(isolate()));
    Ld_b(t0, MemOperand(t0, 0));
    BranchShort(&debug_hook, ne, t0, Operand(zero_reg));
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(a3, RootIndex::kUndefinedValue);
  }

  Register scratch = s1;
  if (argument_adaption_mode == ArgumentAdaptionMode::kAdapt) {
    Register expected_parameter_count = a2;
    LoadParameterCountFromJSDispatchTable(expected_parameter_count,
                                          dispatch_handle, scratch);
    InvokePrologue(expected_parameter_count, actual_parameter_count, type);
  }

  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  LoadEntrypointFromJSDispatchTable(kJavaScriptCallCodeStartRegister,
                                    dispatch_handle, scratch);
  switch (type) {
    case InvokeType::kCall:
      Call(kJavaScriptCallCodeStartRegister);
      break;
    case InvokeType::kJump:
      Jump(kJavaScriptCallCodeStartRegister);
      break;
  }
  Label done;
  Branch(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, dispatch_handle,
                          actual_parameter_count);
  Branch(&continue_after_hook);

  bind(&done);
}
#else
void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, a1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == a3);

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    li(t0, ExternalReference::debug_hook_on_function_call_address(isolate()));
    Ld_b(t0, MemOperand(t0, 0));
    BranchShort(&debug_hook, ne, t0, Operand(zero_reg));
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(a3, RootIndex::kUndefinedValue);
  }

  InvokePrologue(expected_parameter_count, actual_parameter_count, type);

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

  Label done;
  Branch(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, expected_parameter_count,
                          actual_parameter_count);
  Branch(&continue_after_hook);

  // Continue here if InvokePrologue does handle the invocation due to
  // mismatched parameter counts.
  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);
  Register expected_parameter_count = a2;
  Register temp_reg = t0;
  LoadTaggedField(temp_reg,
                  FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  LoadTaggedField(cp, FieldMemOperand(a1, JSFunction::kContextOffset));
  // The argument count is stored as uint16_t
  Ld_hu(expected_parameter_count,
        FieldMemOperand(temp_reg,
                        SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(a1, new_target, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);

  // Get the function and setup the context.
  LoadTaggedField(cp, FieldMemOperand(a1, JSFunction::kContextOffset));

  InvokeFunctionCode(a1, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}
#endif  // V8_ENABLE_LEAPTIERING

// ---------------------------------------------------------------------------
// Support functions.

void MacroAssembler::GetObjectType(Register object, Register map,
                                   Register type_reg) {
  LoadMap(map, object);
  Ld_hu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
}

void MacroAssembler::GetInstanceTypeRange(Register map, Register type_reg,
                                          InstanceType lower_limit,
                                          Register range) {
  Ld_hu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  if (lower_limit != 0 || type_reg != range) {
    Sub_d(range, type_reg, Operand(lower_limit));
  }
}

// -----------------------------------------------------------------------------
// Runtime calls.

void MacroAssembler::AddOverflow_d(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Register right_reg = no_reg;
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    add_d(scratch2, left, right_reg);
    xor_(overflow, scratch2, left);
    xor_(scratch, scratch2, right_reg);
    and_(overflow, overflow, scratch);
    mov(dst, scratch2);
  } else {
    add_d(dst, left, right_reg);
    xor_(overflow, dst, left);
    xor_(scratch, dst, right_reg);
    and_(overflow, overflow, scratch);
  }
}

void MacroAssembler::SubOverflow_d(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Register right_reg = no_reg;
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Sub_d(scratch2, left, right_reg);
    xor_(overflow, left, scratch2);
    xor_(scratch, left, right_reg);
    and_(overflow, overflow, scratch);
    mov(dst, scratch2);
  } else {
    sub_d(dst, left, right_reg);
    xor_(overflow, left, dst);
    xor_(scratch, left, right_reg);
    and_(overflow, overflow, scratch);
  }
}

void MacroAssembler::MulOverflow_w(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Register right_reg = no_reg;
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Mul_w(scratch2, left, right_reg);
    Mulh_w(overflow, left, right_reg);
    mov(dst, scratch2);
  } else {
    Mul_w(dst, left, right_reg);
    Mulh_w(overflow, left, right_reg);
  }

  srai_d(scratch2, dst, 32);
  xor_(overflow, overflow, scratch2);
}

void MacroAssembler::MulOverflow_d(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Register right_reg = no_reg;
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Mul_d(scratch2, left, right_reg);
    Mulh_d(overflow, left, right_reg);
    mov(dst, scratch2);
  } else {
    Mul_d(dst, left, right_reg);
    Mulh_d(overflow, left, right_reg);
  }

  srai_d(scratch2, dst, 63);
  xor_(overflow, overflow, scratch2);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // All parameters are on the stack. v0 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  PrepareCEntryArgs(num_arguments);
  PrepareCEntryFunction(ExternalReference::Create(f));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    PrepareCEntryArgs(function->nargs);
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  PrepareCEntryFunction(builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  CompareTaggedAndBranch(target_if_cleared, eq, in,
                         Operand(kClearedWeakHeapObjectLower32));
  And(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    li(scratch2, ExternalReference::Create(counter));
    Ld_w(scratch1, MemOperand(scratch2, 0));
    Add_w(scratch1, scratch1, Operand(value));
    St_w(scratch1, MemOperand(scratch2, 0));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    li(scratch2, ExternalReference::Create(counter));
    Ld_w(scratch1, MemOperand(scratch2, 0));
    Sub_w(scratch1, scratch1, Operand(value));
    St_w(scratch1, MemOperand(scratch2, 0));
  }
}

// -----------------------------------------------------------------------------
// Debugging.

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::Check(Condition cc, AbortReason reason, Register rj,
                           Operand rk) {
  Label L;
  Branch(&L, cc, rj, rk);
  Abort(reason);
  // Will not return here.
  bind(&L);
}

void MacroAssembler::SbxCheck(Condition cc, AbortReason reason, Register rj,
                              Operand rk) {
  Check(cc, reason, rj, rk);
}

void MacroAssembler::Abort(AbortReason reason) {
  Label abort_start;
  bind(&abort_start);
  if (v8_flags.code_comments) {
    const char* msg = GetAbortReason(reason);
    RecordComment("Abort message: ");
    RecordComment(msg);
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    stop();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    PrepareCallCFunction(1, a0);
    li(a0, Operand(static_cast<int>(reason)));
    li(a1, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(a1);
    return;
  }

  Move(a0, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      LoadEntryFromBuiltin(Builtin::kAbort, t7);
      Call(t7);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }

  // Will not return here.
  if (is_trampoline_pool_blocked()) {
    // If the calling code cares about the exact number of
    // instructions generated, we insert padding here to keep the size
    // of the Abort macro constant.
    // Currently in debug mode with debug_code enabled the number of
    // generated instructions is 10, so we use this as a maximum value.
    static const int kExpectedAbortInstructions = 10;
    int abort_instructions = InstructionsGeneratedSince(&abort_start);
    DCHECK_LE(abort_instructions, kExpectedAbortInstructions);
    while (abort_instructions++ < kExpectedAbortInstructions) {
      nop();
    }
  }
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  LoadTaggedField(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadCompressedMap(Register dst, Register object) {
  ASM_CODE_COMMENT(this);
  Ld_w(dst, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;
  // Load the feedback vector from the closure.
  LoadTaggedField(dst,
                  FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  LoadTaggedField(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  LoadTaggedField(scratch, FieldMemOperand(dst, HeapObject::kMapOffset));
  Ld_hu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Branch(&done, eq, scratch, Operand(FEEDBACK_VECTOR_TYPE));

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  Branch(fbv_undef);

  bind(&done);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  LoadTaggedField(
      dst, FieldMemOperand(
               dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(StackFrame::TypeToMarker(type)));
  PushCommonFrame(scratch);
}

void MacroAssembler::Prologue() { PushStandardFrame(a1); }

void MacroAssembler::EnterFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Push(ra, fp);
  Move(fp, sp);
  if (!StackFrame::IsJavaScript(type)) {
    li(kScratchReg, Operand(StackFrame::TypeToMarker(type)));
    Push(kScratchReg);
  }
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM || type == StackFrame::WASM_LIFTOFF_SETUP) {
    Push(kWasmImplicitArgRegister);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
}

void MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  addi_d(sp, fp, 2 * kSystemPointerSize);
  Ld_d(ra, MemOperand(fp, 1 * kSystemPoin
"""


```
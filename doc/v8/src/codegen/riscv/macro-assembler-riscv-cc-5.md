Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/riscv/macro-assembler-riscv.cc`.

Here's a breakdown of the code and its purpose:

1. **MacroAssembler Class:** The code is part of the `MacroAssembler` class, which is responsible for generating machine code instructions. It provides a higher-level abstraction over raw assembly instructions.

2. **RISC-V Architecture:** The code specifically targets the RISC-V architecture, evident from the file path and the use of RISC-V specific instructions (e.g., `jalr`, `auipc`, `addi`, `vmsle_vv`).

3. **Code Generation:** The functions within the `MacroAssembler` class generate sequences of RISC-V instructions to perform various operations.

4. **Calling Conventions:** The code handles different calling conventions, including calls to C functions, JavaScript functions, and built-in functions.

5. **Branching and Jumping:** Functions like `Jump`, `Call`, `Branch`, and their variations handle control flow within the generated code.

6. **Root Table Access:**  The code interacts with the V8 root table (a table of important values) using functions like `LoadRoot` and `CompareRoot`.

7. **Stack Management:** Functions like `Push`, `Pop`, `Drop`, and `PushStackHandler` manage the call stack.

8. **Exception Handling:**  The `PushStackHandler` and `PopStackHandler` functions are part of V8's exception handling mechanism.

9. **Floating-Point Operations:** Functions with `FPU` in their name handle floating-point operations.

10. **JavaScript Invocation:**  Functions like `InvokeFunctionCode` and `InvokeFunction` handle calls to JavaScript functions, including argument setup and stack management.

11. **Debugging Support:**  The `CheckDebugHook` function integrates with V8's debugging features.

12. **Wasm Support:** The `WasmRvv...` functions indicate support for WebAssembly's vector instructions (RVV extension).

Now, let's address the specific questions:

*   **.tq extension:** The code snippet is C++, not Torque.
*   **Relationship to Javascript:** Many functions, especially those related to `InvokeFunction`, directly facilitate the execution of JavaScript code.
*   **Code Logic Reasoning:** The conditional branching and function calls based on conditions or builtin status involve logic.
*   **User Programming Errors:** Incorrect stack management or calling conventions are potential errors.

Finally, I need to summarize the functionality based on this specific part (part 6) of the file.
这是 `v8/src/codegen/riscv/macro-assembler-riscv.cc` 文件的一部分，它定义了 `MacroAssembler` 类中用于生成 RISC-V 汇编指令的各种方法。这部分代码主要关注**控制流指令**（如跳转、调用、返回）以及与**函数调用**相关的操作，包括调用 JavaScript 函数、内置函数和 C++ 函数。它还涉及**条件执行**、**栈操作**、**异常处理**、**浮点数操作**、**调试支持**以及对 **WebAssembly (Wasm)** 的部分支持。

**功能归纳 (第 6 部分):**

这部分 `MacroAssembler` 的代码主要提供了以下功能：

1. **无条件和条件跳转 (Jump):** 允许在代码中无条件或根据条件跳转到指定的地址、标签或代码对象。
2. **无条件和条件调用 (Call):** 允许调用指定的地址、标签、代码对象或内置函数，并保存返回地址。
3. **尾调用 (TailCallBuiltin):**  优化后的调用，在调用前清理当前栈帧，适用于调用后立即返回的情况。
4. **调用内置函数 (CallBuiltin, CallBuiltinByIndex):**  提供多种方式调用 V8 的内置函数，包括直接调用、通过索引调用等，并考虑了性能优化和快照创建的场景。
5. **加载内置函数入口地址 (LoadEntryFromBuiltin, LoadEntryFromBuiltinIndex):** 用于获取内置函数的实际执行地址。
6. **存储返回地址并调用 C 函数 (StoreReturnAddressAndCall):**  处理从 JavaScript 代码调用 C++ 代码的场景，包括设置返回地址和栈。
7. **返回指令 (Ret):**  从函数调用中返回。
8. **长跳转和长调用 (BranchLong, BranchAndLinkLong):**  处理超出普通跳转指令范围的情况。
9. **栈操作 (DropAndRet, Drop, PushArray, Push, PopStackHandler):**  提供操作栈的方法，包括弹出数据、压入数据、丢弃栈帧等，以及用于异常处理的栈处理器的管理。
10. **交换寄存器值 (Swap):**  交换两个寄存器中的值。
11. **加载地址 (LoadAddress):**  将标签的地址加载到寄存器中。
12. **Switch 语句支持 (Switch):**  生成实现 switch 语句的汇编代码。
13. **浮点数操作 (FPUCanonicalizeNaN, MovFromFloatResult, 等):** 提供处理浮点数的操作，如 NaN 规范化、参数和返回值传递。
14. **加载栈限制 (LoadStackLimit):**  加载当前的栈顶限制，用于栈溢出检查。
15. **栈溢出检查 (StackOverflowCheck):**  在函数调用前检查是否会发生栈溢出。
16. **JavaScript 函数调用序言 (InvokePrologue):**  处理 JavaScript 函数调用前的参数调整，处理参数过多或过少的情况。
17. **调试钩子检查 (CheckDebugHook):**  在函数调用时检查是否需要触发调试钩子。
18. **调用 JavaScript 函数 (InvokeFunctionCode, InvokeFunctionWithNewTarget, InvokeFunction):**  生成调用 JavaScript 函数的代码，包括处理 `new.target` 和上下文。
19. **获取对象类型 (GetObjectType, GetInstanceTypeRange):**  用于获取对象的类型信息。
20. **WebAssembly RVV 指令支持 (WasmRvvEq, WasmRvvNe, 等):**  为 WebAssembly 的 RISC-V 向量扩展指令提供支持，用于生成向量比较操作的指令。

**关于问题：**

*   **`.tq` 结尾：**  `v8/src/codegen/riscv/macro-assembler-riscv.cc` 以 `.cc` 结尾，因此它是 **C++** 源代码，而不是 Torque 源代码。
*   **与 Javascript 的关系：**  `macro-assembler-riscv.cc` 的核心功能是生成执行 JavaScript 代码所需的机器码。例如，`InvokeFunction` 系列的函数就直接负责生成调用 JavaScript 函数的指令序列。

    ```javascript
    function myFunction(a, b) {
      return a + b;
    }

    myFunction(1, 2); // 这行 JavaScript 代码的执行会涉及到 `InvokeFunction` 相关的汇编代码生成
    ```

    当 V8 执行 `myFunction(1, 2)` 时，`MacroAssembler` 会生成相应的 RISC-V 汇编指令，包括参数准备、函数地址加载、跳转到函数入口等操作。`InvokeFunction` 等函数会处理诸如获取函数代码、设置上下文、传递参数等底层细节。

*   **代码逻辑推理：**

    **假设输入：**
    *   `cond` 为 `eq` (等于)
    *   `rs` 寄存器中的值为 10
    *   `rt` 操作数的值为 10
    *   `code` 是一个指向内置函数 `Builtin::kAdd` 的 `Handle<Code>`

    **输出：**
    由于条件 `eq` 为真 (10 等于 10)，`TailCallBuiltin(builtin)` 将被执行，生成尾调用内置函数 `Builtin::kAdd` 的汇编指令。如果条件为假，则会跳过尾调用。

*   **用户常见的编程错误：**  虽然 `macro-assembler-riscv.cc` 是 V8 内部的代码，但其功能与用户编写 JavaScript 代码的方式息息相关。一个常见的编程错误可能会导致这里生成的代码执行出错，例如：

    *   **栈溢出：**  如果 JavaScript 代码中存在无限递归调用，最终会导致 `StackOverflowCheck` 失败，并调用 `Runtime::kThrowStackOverflow` 抛出错误。

        ```javascript
        function recursiveFunction() {
          recursiveFunction(); // 无限递归
        }

        recursiveFunction(); // 这将导致栈溢出
        ```

    *   **类型错误：**  如果 JavaScript 代码的操作期望某种类型的对象，但实际传入了错误的类型，可能会导致 V8 内部生成的指令访问非法内存或执行错误的操作。

*   **总结：** 这部分 `v8/src/codegen/riscv/macro-assembler-riscv.cc` 代码是 V8 引擎 RISC-V 架构代码生成的核心部分，专注于生成控制流和函数调用相关的汇编指令，为 JavaScript 代码的执行提供底层的机器码支持，并涉及到与内置函数、C++ 代码以及 WebAssembly 的交互。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共9部分，请归纳一下它的功能

"""
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
"""


```
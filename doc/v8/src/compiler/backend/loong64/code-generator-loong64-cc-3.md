Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's backend compiler for the LoongArch64 architecture.

I need to:
1. **Identify the main purpose of the code:** It's a code generator for LoongArch64.
2. **List key functionalities based on the code:**  Look for function names and their actions. Keywords like `Assemble`, `Push`, `Pop`, `Move`, `Return`, `Frame` are important.
3. **Address specific points raised in the prompt:**
    - Check for `.tq` extension (it's `.cc`, so it's not Torque).
    - Explain the relationship to JavaScript (it translates optimized JavaScript code to machine code).
    - Provide JavaScript examples (illustrating concepts like function calls, stack frames).
    - Provide code logic reasoning with input/output (demonstrating how instructions are generated for certain operations).
    - Highlight common programming errors related to the functionality (e.g., stack overflow).
4. **Summarize the overall function** as the final step (as requested by "这是第4部分，共4部分").

Based on the function names and code structure, the main responsibilities of this code involve:
- Managing the function call stack (frame setup, return).
- Moving data between registers and memory (including stack).
- Implementing control flow (switch statements, jumps).
- Handling deoptimization.
- Supporting WebAssembly (Wasm).
这是V8 JavaScript引擎中为LoongArch64架构生成机器码的代码生成器的实现。它负责将中间表示（IR）指令转换为可以在LoongArch64处理器上执行的实际机器指令。

以下是代码片段中展示的一些关键功能：

1. **`AssembleSwitch()`**:  为 `switch` 语句生成机器码。它使用一个查找表来高效地跳转到与 `switch` 语句的 `case` 值匹配的代码块。
2. **`AssembleArchSelect()`**:  (未实现) 本应根据条件选择不同的代码路径，可能用于实现条件赋值或条件执行。
3. **`FinishFrame()`**:  在函数调用的末尾执行清理帧的操作，例如保存和恢复被调用者保存的寄存器。
4. **`AssembleConstructFrame()`**:  在函数调用开始时构建栈帧。这包括分配局部变量的空间、保存返回地址和帧指针，以及保存被调用者保存的寄存器。这段代码还处理了WebAssembly函数的栈帧构建，并包含了栈溢出检查。
5. **`AssembleReturn()`**:  生成函数返回的机器码。这包括恢复被调用者保存的寄存器、调整栈指针并跳转回调用者。它还处理了与WebAssembly相关的特定返回逻辑。
6. **`FinishCode()`**:  在代码生成过程的最后执行必要的清理工作。
7. **`PrepareForDeoptimizationExits()`**:  为反优化出口做准备。反优化是将优化后的代码执行过程回退到未优化代码的过程。
8. **`Push()`**:  将数据压入栈中。它处理不同类型的操作数（寄存器、栈槽）。
9. **`Pop()`**:  从栈中弹出数据到指定的目标位置。
10. **`PopTempStackSlots()`**: 清理临时使用的栈空间。
11. **`MoveToTempLocation()`**:  将一个操作数的值移动到一个临时位置，通常用于解决指令之间的依赖关系或为复杂操作腾出寄存器。
12. **`MoveTempLocationTo()`**:  将之前移动到临时位置的值移动到最终的目标位置。
13. **`SetPendingMove()`**:  记录待处理的移动操作，可能用于优化寄存器分配或指令调度。
14. **`AssembleMove()`**:  生成将数据从一个位置移动到另一个位置的机器码。它支持寄存器、栈槽和常量之间的移动。
15. **`AssembleSwap()`**:  生成交换两个操作数值的机器码。
16. **`AssembleJumpTable()`**: (未实现)  本应生成跳转表的机器码，用于实现更复杂的控制流结构。

**关于代码的性质：**

`v8/src/compiler/backend/loong64/code-generator-loong64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码**，而不是 Torque 源代码。

**与 JavaScript 的功能关系和 JavaScript 示例：**

这个代码生成器的核心功能是将高级的 JavaScript 代码（经过编译器的优化）转换为底层的 LoongArch64 汇编指令。每当你执行一个 JavaScript 函数时，V8 的编译器（TurboFan 或 Crankshaft）会将该函数编译成机器码，而 `code-generator-loong64.cc`  就参与了这个过程。

例如，考虑以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 执行 `add(5, 10)` 时，编译器会生成类似于以下步骤的机器码（简化表示，实际会更复杂）：

1. **构建栈帧 (`AssembleConstructFrame`)**: 为 `add` 函数创建一个栈帧，用于存储局部变量和参数。
2. **加载参数**: 将参数 `5` 和 `10` 从它们所在的位置（可能在寄存器或调用者的栈帧中）加载到寄存器中。
3. **执行加法操作**: 生成加法指令，将两个参数寄存器中的值相加。
4. **存储结果**: 将加法结果存储到指定的寄存器或栈槽中。
5. **返回 (`AssembleReturn`)**:  生成返回指令，将结果放回调用者期望的位置，并清理 `add` 函数的栈帧。

再例如，一个包含 `switch` 语句的 JavaScript 函数：

```javascript
function handleCase(value) {
  switch (value) {
    case 1:
      return "one";
    case 5:
      return "five";
    case 10:
      return "ten";
    default:
      return "other";
  }
}

handleCase(5);
```

`AssembleSwitch()` 函数会被用来生成高效的机器码，可能创建一个查找表，根据 `value` 的值直接跳转到对应的 `case` 代码块。

**代码逻辑推理（假设输入与输出）：**

假设我们有一个简单的指令，要求将一个寄存器 `r1` 的值移动到另一个寄存器 `r2`。

**输入 (Instruction):**  一个表示移动操作的 `Instruction` 对象，其中源操作数为寄存器 `r1`，目标操作数为寄存器 `r2`。

**代码片段：**

```c++
void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  Loong64OperandConverter g(this, nullptr);
  if (source->IsRegister()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      __ mov(g.ToRegister(destination), src);
    } else {
      __ St_d(src, g.ToMemOperand(destination));
    }
  }
  // ... 其他情况 ...
}
```

**推理：**

1. `source->IsRegister()` 为真，因为源操作数是寄存器。
2. `destination->IsRegister()` 为真，因为目标操作数也是寄存器。
3. `g.ToRegister(source)` 将 `InstructionOperand` 转换为 LoongArch64 的 `Register` 对象，代表 `r1`。
4. `g.ToRegister(destination)` 将 `InstructionOperand` 转换为 LoongArch64 的 `Register` 对象，代表 `r2`。
5. `__ mov(g.ToRegister(destination), src);`  会生成 LoongArch64 的 `mov` 指令，将 `r1` 的内容移动到 `r2`。

**输出 (机器码):**  LoongArch64 汇编指令 `mov r2, r1` (实际的寄存器编号可能会有所不同)。

**用户常见的编程错误：**

涉及到栈操作的代码（如 `Push`, `Pop`, `AssembleConstructFrame`, `AssembleReturn`）容易引发与栈相关的错误：

1. **栈溢出**:  如果程序分配的栈空间不足以容纳局部变量、函数调用信息等，就会发生栈溢出。WebAssembly 的栈溢出检查 (`if (info()->IsWasm() && required_slots * kSystemPointerSize > 4 * KB)`) 就是为了防止这种情况。

   **JavaScript 示例 (可能导致栈溢出的递归):**
   ```javascript
   function recursiveFunction() {
     recursiveFunction(); // 无终止条件的递归
   }
   recursiveFunction(); // 会导致栈溢出
   ```

2. **栈下溢**:  尝试从空栈中弹出数据，这通常是由于 `push` 和 `pop` 操作不匹配造成的。

3. **访问已释放的栈空间**:  在函数返回后，尝试访问其栈帧中的数据。

4. **不正确的栈指针操作**:  手动修改栈指针（`sp`）时，如果计算错误，可能导致栈损坏。

**总结 `code-generator-loong64.cc` 的功能 (作为第4部分):**

作为V8编译器的最后阶段之一，`v8/src/compiler/backend/loong64/code-generator-loong64.cc` 的主要功能是 **将高级的、平台无关的中间表示（IR）指令翻译成可以在 LoongArch64 架构上执行的本地机器代码**。它负责处理函数调用约定、栈帧管理、数据移动、控制流以及其他与目标架构相关的细节。这个代码生成器是 V8 引擎将 JavaScript 代码高效地运行在 LoongArch64 硬件上的关键组成部分。它确保了生成的机器码能够正确地执行 JavaScript 语义，并尽可能地优化性能。

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/code-generator-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/loong64/code-generator-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
 __ slli_w(scratch, input, 0);
  __ Branch(GetLabel(i.InputRpo(1)), hs, scratch, Operand(case_count));
  __ GenerateSwitchTable(scratch, case_count, [&i, this](size_t index) {
    return GetLabel(i.InputRpo(index + 2));
  });
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  UNIMPLEMENTED();
}

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fpu.is_empty()) {
    int count = saves_fpu.Count();
    DCHECK_EQ(kNumCalleeSavedFPU, count);
    frame->AllocateSavedCalleeRegisterSlots(count *
                                            (kDoubleSize / kSystemPointerSize));
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    int count = saves.Count();
    frame->AllocateSavedCalleeRegisterSlots(count);
  }
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  if (frame_access_state()->has_frame()) {
    if (call_descriptor->IsCFunctionCall()) {
#if V8_ENABLE_WEBASSEMBLY
      if (info()->GetOutputStackFrameType() == StackFrame::C_WASM_ENTRY) {
        __ StubPrologue(StackFrame::C_WASM_ENTRY);
        // Reserve stack space for saving the c_entry_fp later.
        __ Sub_d(sp, sp, Operand(kSystemPointerSize));
#else
      // For balance.
      if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
      } else {
        __ Push(ra, fp);
        __ mov(fp, sp);
      }
    } else if (call_descriptor->IsJSFunctionCall()) {
      __ Prologue();
    } else {
      __ StubPrologue(info()->GetOutputStackFrameType());
#if V8_ENABLE_WEBASSEMBLY
      if (call_descriptor->IsWasmFunctionCall() ||
          call_descriptor->IsWasmImportWrapper() ||
          call_descriptor->IsWasmCapiFunction()) {
        // For import wrappers and C-API functions, this stack slot is only used
        // for printing stack traces in V8. Also, it holds a WasmImportData
        // instead of the trusted instance data, which is taken care of in the
        // frames accessors.
        __ Push(kWasmImplicitArgRegister);
      }
      if (call_descriptor->IsWasmCapiFunction()) {
        // Reserve space for saving the PC later.
        __ Sub_d(sp, sp, Operand(kSystemPointerSize));
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }
  }

  int required_slots =
      frame()->GetTotalFrameSlotCount() - frame()->GetFixedSlotCount();

  if (info()->is_osr()) {
    // TurboFan OSR-compiled functions cannot be entered directly.
    __ Abort(AbortReason::kShouldNotDirectlyEnterOsrFunction);

    // Unoptimized code jumps directly to this entrypoint while the unoptimized
    // frame is still on the stack. Optimized code uses OSR values directly from
    // the unoptimized frame. Thus, all that needs to be done is to allocate the
    // remaining stack slots.
    __ RecordComment("-- OSR entrypoint --");
    osr_pc_offset_ = __ pc_offset();
    required_slots -= osr_helper()->UnoptimizedFrameSlots();
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();

  if (required_slots > 0) {
    DCHECK(frame_access_state()->has_frame());
#if V8_ENABLE_WEBASSEMBLY
    if (info()->IsWasm() && required_slots * kSystemPointerSize > 4 * KB) {
      // For WebAssembly functions with big frames we have to do the stack
      // overflow check before we construct the frame. Otherwise we may not
      // have enough space on the stack to call the runtime for the stack
      // overflow.
      Label done;

      // If the frame is bigger than the stack, we throw the stack overflow
      // exception unconditionally. Thereby we can avoid the integer overflow
      // check in the condition code.
      if (required_slots * kSystemPointerSize < v8_flags.stack_size * KB) {
        UseScratchRegisterScope temps(masm());
        Register stack_limit = temps.Acquire();
        __ LoadStackLimit(stack_limit,
                          MacroAssembler::StackLimitKind::kRealStackLimit);
        __ Add_d(stack_limit, stack_limit,
                 Operand(required_slots * kSystemPointerSize));
        __ Branch(&done, uge, sp, Operand(stack_limit));
      }

      if (v8_flags.experimental_wasm_growable_stacks) {
        RegList regs_to_save;
        regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
        regs_to_save.set(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister());

        for (auto reg : wasm::kGpParamRegisters) regs_to_save.set(reg);
        __ MultiPush(regs_to_save);
        __ li(WasmHandleStackOverflowDescriptor::GapRegister(),
              required_slots * kSystemPointerSize);
        __ Add_d(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister(), fp,
            Operand(call_descriptor->ParameterSlotCount() * kSystemPointerSize +
                    CommonFrameConstants::kFixedFrameSizeAboveFp));
        __ CallBuiltin(Builtin::kWasmHandleStackOverflow);
        __ MultiPop(regs_to_save);
      } else {
        __ Call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
                RelocInfo::WASM_STUB_CALL);
        // The call does not return, hence we can ignore any references and just
        // define an empty safepoint.
        ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
        RecordSafepoint(reference_map);
        if (v8_flags.debug_code) {
          __ stop();
        }
      }

      __ bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  const int returns = frame()->GetReturnSlotCount();

  // Skip callee-saved and return slots, which are pushed below.
  required_slots -= saves.Count();
  required_slots -= saves_fpu.Count();
  required_slots -= returns;
  if (required_slots > 0) {
    __ Sub_d(sp, sp, Operand(required_slots * kSystemPointerSize));
  }

  if (!saves_fpu.is_empty()) {
    // Save callee-saved FPU registers.
    __ MultiPushFPU(saves_fpu);
    DCHECK_EQ(kNumCalleeSavedFPU, saves_fpu.Count());
  }

  if (!saves.is_empty()) {
    // Save callee-saved registers.
    __ MultiPush(saves);
  }

  if (returns != 0) {
    // Create space for returns.
    __ Sub_d(sp, sp, Operand(returns * kSystemPointerSize));
  }

  for (int spill_slot : frame()->tagged_slots()) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
    DCHECK(offset.from_frame_pointer());
    __ St_d(zero_reg, MemOperand(fp, offset.offset()));
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = frame()->GetReturnSlotCount();
  if (returns != 0) {
    __ Add_d(sp, sp, Operand(returns * kSystemPointerSize));
  }

  // Restore GP registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    __ MultiPop(saves);
  }

  // Restore FPU registers.
  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fpu.is_empty()) {
    __ MultiPopFPU(saves_fpu);
  }

  Loong64OperandConverter g(this, nullptr);

  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue,
                g.ToRegister(additional_pop_count),
                Operand(static_cast<int64_t>(0)));
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  if (call_descriptor->IsWasmFunctionCall() &&
      v8_flags.experimental_wasm_growable_stacks) {
    Label done;
    {
      UseScratchRegisterScope temps{masm()};
      Register scratch = temps.Acquire();
      __ Ld_d(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
      __ BranchShort(
          &done, ne, scratch,
          Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
    }
    RegList regs_to_save;
    for (auto reg : wasm::kGpReturnRegisters) regs_to_save.set(reg);
    __ MultiPush(regs_to_save);
    __ li(kCArgRegs[0], ExternalReference::isolate_address());
    {
      UseScratchRegisterScope temps{masm()};
      Register scratch = temps.Acquire();
      __ PrepareCallCFunction(1, scratch);
    }
    __ CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
    __ mov(fp, kReturnRegister0);
    __ MultiPop(regs_to_save);
    __ bind(&done);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.
  const bool drop_jsargs = frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall() &&
                           parameter_slots != 0;

  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    // Canonicalize JSFunction return sites for now unless they have an variable
    // number of stack slot pops.
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ Branch(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count
      __ Ld_d(t0, MemOperand(fp, StandardFrameConstants::kArgCOffset));
    }
    AssembleDeconstructFrame();
  }
  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver). This
    // number of arguments is given by max(1 + argc_reg, parameter_count).
    if (parameter_slots > 1) {
      __ li(t1, parameter_slots);
      __ slt(t2, t0, t1);
      __ Movn(t0, t1, t2);
    }
    __ Alsl_d(sp, t0, sp, kSystemPointerSizeLog2);
  } else if (additional_pop_count->IsImmediate()) {
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    __ Drop(parameter_slots + additional_count);
  } else {
    Register pop_reg = g.ToRegister(additional_pop_count);
    __ Drop(parameter_slots);
    __ Alsl_d(sp, pop_reg, sp, kSystemPointerSizeLog2);
  }
  __ Ret();
}

void CodeGenerator::FinishCode() {}

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  Loong64OperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ Push(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ Ld_d(scratch, g.ToMemOperand(source));
    __ Push(scratch);
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ Sub_d(sp, sp, Operand(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  Loong64OperandConverter g(this, nullptr);
  int dropped_slots = ElementSizeInPointers(rep);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Pop(g.ToRegister(dest));
  } else if (dest->IsStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ Pop(scratch);
    __ St_d(scratch, g.ToMemOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Add_d(sp, sp, Operand(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ Add_d(sp, sp, Operand(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  DCHECK(!source->IsImmediate());
  move_cycle_.temps.emplace(masm());
  auto& temps = *move_cycle_.temps;
  // Temporarily exclude the reserved scratch registers while we pick one to
  // resolve the move cycle. Re-include them immediately afterwards as they
  // might be needed for the move to the temp location.
  temps.Exclude(move_cycle_.scratch_regs);
  temps.ExcludeFp(move_cycle_.scratch_fpregs);
  if (!IsFloatingPoint(rep)) {
    if (temps.hasAvailable()) {
      Register scratch = move_cycle_.temps->Acquire();
      move_cycle_.scratch_reg.emplace(scratch);
    } else if (temps.hasAvailableFp()) {
      // Try to use an FP register if no GP register is available for non-FP
      // moves.
      FPURegister scratch = move_cycle_.temps->AcquireFp();
      move_cycle_.scratch_fpreg.emplace(scratch);
    }
  } else {
    DCHECK(temps.hasAvailableFp());
    FPURegister scratch = move_cycle_.temps->AcquireFp();
    move_cycle_.scratch_fpreg.emplace(scratch);
  }
  temps.Include(move_cycle_.scratch_regs);
  temps.IncludeFp(move_cycle_.scratch_fpregs);
  if (move_cycle_.scratch_reg.has_value()) {
    // A scratch register is available for this rep.
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(source, &scratch);
  } else if (move_cycle_.scratch_fpreg.has_value()) {
    // A scratch fp register is available for this rep.
    if (!IsFloatingPoint(rep)) {
      AllocatedOperand scratch(LocationOperand::REGISTER,
                               MachineRepresentation::kFloat64,
                               move_cycle_.scratch_fpreg->code());
      Loong64OperandConverter g(this, nullptr);
      if (source->IsStackSlot()) {
        __ Fld_d(g.ToDoubleRegister(&scratch), g.ToMemOperand(source));
      } else {
        DCHECK(source->IsRegister());
        __ movgr2fr_d(g.ToDoubleRegister(&scratch), g.ToRegister(source));
      }
    } else {
      AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                               move_cycle_.scratch_fpreg->code());
      AssembleMove(source, &scratch);
    }
  } else {
    // The scratch registers are blocked by pending moves. Use the stack
    // instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  if (move_cycle_.scratch_reg.has_value()) {
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(&scratch, dest);
  } else if (move_cycle_.scratch_fpreg.has_value()) {
    if (!IsFloatingPoint(rep)) {
      // We used a DoubleRegister to move a non-FP operand, change the
      // representation to correctly interpret the InstructionOperand's code.
      AllocatedOperand scratch(LocationOperand::REGISTER,
                               MachineRepresentation::kFloat64,
                               move_cycle_.scratch_fpreg->code());
      Loong64OperandConverter g(this, nullptr);
      if (dest->IsStackSlot()) {
        __ Fst_d(g.ToDoubleRegister(&scratch), g.ToMemOperand(dest));
      } else {
        DCHECK(dest->IsRegister());
        __ movfr2gr_d(g.ToRegister(dest), g.ToDoubleRegister(&scratch));
      }
    } else {
      AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                               move_cycle_.scratch_fpreg->code());
      AssembleMove(&scratch, dest);
    }
  } else {
    Pop(dest, rep);
  }
  // Restore the default state to release the {UseScratchRegisterScope} and to
  // prepare for the next cycle.
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  InstructionOperand* src = &move->source();
  InstructionOperand* dst = &move->destination();
  UseScratchRegisterScope temps(masm());
  if (src->IsConstant() || (src->IsStackSlot() && dst->IsStackSlot())) {
    Register temp = temps.Acquire();
    move_cycle_.scratch_regs.set(temp);
  }
  if (src->IsAnyStackSlot() || dst->IsAnyStackSlot()) {
    Loong64OperandConverter g(this, nullptr);
    bool src_need_scratch = false;
    bool dst_need_scratch = false;
    if (src->IsStackSlot()) {
      // Doubleword load/store
      MemOperand src_mem = g.ToMemOperand(src);
      src_need_scratch =
          (!is_int16(src_mem.offset()) || (src_mem.offset() & 0b11) != 0) &&
          (!is_int12(src_mem.offset()) && !src_mem.hasIndexReg());
    } else if (src->IsFPStackSlot()) {
      // DoubleWord float-pointing load/store.
      MemOperand src_mem = g.ToMemOperand(src);
      src_need_scratch = !is_int12(src_mem.offset()) && !src_mem.hasIndexReg();
    }
    if (dst->IsStackSlot()) {
      // Doubleword load/store
      MemOperand dst_mem = g.ToMemOperand(dst);
      dst_need_scratch =
          (!is_int16(dst_mem.offset()) || (dst_mem.offset() & 0b11) != 0) &&
          (!is_int12(dst_mem.offset()) && !dst_mem.hasIndexReg());
    } else if (dst->IsFPStackSlot()) {
      // DoubleWord float-pointing load/store.
      MemOperand dst_mem = g.ToMemOperand(dst);
      dst_need_scratch = !is_int12(dst_mem.offset()) && !dst_mem.hasIndexReg();
    }
    if (src_need_scratch || dst_need_scratch) {
      Register temp = temps.Acquire();
      move_cycle_.scratch_regs.set(temp);
    }
  }
}

namespace {

bool Is32BitOperand(InstructionOperand* operand) {
  DCHECK(operand->IsStackSlot() || operand->IsRegister());
  MachineRepresentation mr = LocationOperand::cast(operand)->representation();
  return mr == MachineRepresentation::kWord32 ||
         mr == MachineRepresentation::kCompressed ||
         mr == MachineRepresentation::kCompressedPointer;
}

// When we need only 32 bits, move only 32 bits, otherwise the destination
// register' upper 32 bits may contain dirty data.
bool Use32BitMove(InstructionOperand* source, InstructionOperand* destination) {
  return Is32BitOperand(source) && Is32BitOperand(destination);
}

}  // namespace

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  Loong64OperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  if (source->IsRegister()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      __ mov(g.ToRegister(destination), src);
    } else {
      __ St_d(src, g.ToMemOperand(destination));
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    MemOperand src = g.ToMemOperand(source);
    if (destination->IsRegister()) {
      if (Use32BitMove(source, destination)) {
        __ Ld_w(g.ToRegister(destination), src);
      } else {
        __ Ld_d(g.ToRegister(destination), src);
      }
    } else {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ Ld_d(scratch, src);
      __ St_d(scratch, g.ToMemOperand(destination));
    }
  } else if (source->IsConstant()) {
    Constant src = g.ToConstant(source);
    if (destination->IsRegister() || destination->IsStackSlot()) {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      Register dst =
          destination->IsRegister() ? g.ToRegister(destination) : scratch;
      switch (src.type()) {
        case Constant::kInt32:
          __ li(dst, Operand(src.ToInt32(), src.rmode()));
          break;
        case Constant::kFloat32:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat32()));
          break;
        case Constant::kInt64:
          __ li(dst, Operand(src.ToInt64(), src.rmode()));
          break;
        case Constant::kFloat64:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat64().value()));
          break;
        case Constant::kExternalReference:
          __ li(dst, src.ToExternalReference());
          break;
        case Constant::kHeapObject: {
          Handle<HeapObject> src_object = src.ToHeapObject();
          RootIndex index;
          if (IsMaterializableFromRoot(src_object, &index)) {
            __ LoadRoot(dst, index);
          } else {
            __ li(dst, src_object);
          }
          break;
        }
        case Constant::kCompressedHeapObject: {
          Handle<HeapObject> src_object = src.ToHeapObject();
          RootIndex index;
          if (IsMaterializableFromRoot(src_object, &index)) {
            __ LoadTaggedRoot(dst, index);
          } else {
            __ li(dst, src_object, RelocInfo::COMPRESSED_EMBEDDED_OBJECT);
          }
          break;
        }
        case Constant::kRpoNumber:
          UNREACHABLE();  // TODO(titzer): loading RPO numbers on LOONG64.
      }
      if (destination->IsStackSlot()) __ St_d(dst, g.ToMemOperand(destination));
    } else if (src.type() == Constant::kFloat32) {
      if (destination->IsFPStackSlot()) {
        MemOperand dst = g.ToMemOperand(destination);
        if (base::bit_cast<int32_t>(src.ToFloat32()) == 0) {
          __ St_d(zero_reg, dst);
        } else {
          UseScratchRegisterScope temps(masm());
          Register scratch = temps.Acquire();
          __ li(scratch, Operand(base::bit_cast<int32_t>(src.ToFloat32())));
          __ St_d(scratch, dst);
        }
      } else {
        DCHECK(destination->IsFPRegister());
        FloatRegister dst = g.ToSingleRegister(destination);
        __ Move(dst, src.ToFloat32());
      }
    } else {
      DCHECK_EQ(Constant::kFloat64, src.type());
      DoubleRegister dst = destination->IsFPRegister()
                               ? g.ToDoubleRegister(destination)
                               : kScratchDoubleReg;
      __ Move(dst, src.ToFloat64().value());
      if (destination->IsFPStackSlot()) {
        __ Fst_d(dst, g.ToMemOperand(destination));
      }
    }
  } else if (source->IsFPRegister()) {
    FPURegister src = g.ToDoubleRegister(source);
    if (destination->IsFPRegister()) {
      FPURegister dst = g.ToDoubleRegister(destination);
      __ Move(dst, src);
    } else {
      DCHECK(destination->IsFPStackSlot());
      __ Fst_d(src, g.ToMemOperand(destination));
    }
  } else if (source->IsFPStackSlot()) {
    DCHECK(destination->IsFPRegister() || destination->IsFPStackSlot());
    MemOperand src = g.ToMemOperand(source);
    if (destination->IsFPRegister()) {
      __ Fld_d(g.ToDoubleRegister(destination), src);
    } else {
      DCHECK(destination->IsFPStackSlot());
      FPURegister temp = kScratchDoubleReg;
      __ Fld_d(temp, src);
      __ Fst_d(temp, g.ToMemOperand(destination));
    }
  } else {
    UNREACHABLE();
  }
}

void CodeGenerator::AssembleSwap(InstructionOperand* source,
                                 InstructionOperand* destination) {
  Loong64OperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  if (source->IsRegister()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    // Register-register.
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      Register dst = g.ToRegister(destination);
      __ Move(scratch, src);
      __ Move(src, dst);
      __ Move(dst, scratch);
    } else {
      DCHECK(destination->IsStackSlot());
      MemOperand dst = g.ToMemOperand(destination);
      __ mov(scratch, src);
      __ Ld_d(src, dst);
      __ St_d(scratch, dst);
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsStackSlot());
    // TODO(LOONG_dev): LOONG64 Optimize scratch registers usage
    // Since the Ld instruction may need a scratch reg,
    // we should not use both of the two scratch registers in
    // UseScratchRegisterScope here.
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    FPURegister scratch_d = kScratchDoubleReg;
    MemOperand src = g.ToMemOperand(source);
    MemOperand dst = g.ToMemOperand(destination);
    __ Ld_d(scratch, src);
    __ Fld_d(scratch_d, dst);
    __ St_d(scratch, dst);
    __ Fst_d(scratch_d, src);
  } else if (source->IsFPRegister()) {
    FPURegister scratch_d = kScratchDoubleReg;
    FPURegister src = g.ToDoubleRegister(source);
    if (destination->IsFPRegister()) {
      FPURegister dst = g.ToDoubleRegister(destination);
      __ Move(scratch_d, src);
      __ Move(src, dst);
      __ Move(dst, scratch_d);
    } else {
      DCHECK(destination->IsFPStackSlot());
      MemOperand dst = g.ToMemOperand(destination);
      __ Move(scratch_d, src);
      __ Fld_d(src, dst);
      __ Fst_d(scratch_d, dst);
    }
  } else if (source->IsFPStackSlot()) {
    DCHECK(destination->IsFPStackSlot());
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    FPURegister scratch_d = kScratchDoubleReg;
    MemOperand src = g.ToMemOperand(source);
    MemOperand dst = g.ToMemOperand(destination);
    __ Fld_d(scratch_d, src);
    __ Ld_d(scratch, dst);
    __ Fst_d(scratch_d, dst);
    __ St_d(scratch, src);
  } else {
    // No other combinations are possible.
    UNREACHABLE();
  }
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
  // On 64-bit LOONG64 we emit the jump tables inline.
  UNREACHABLE();
}

#undef ASSEMBLE_ATOMIC_LOAD_INTEGER
#undef ASSEMBLE_ATOMIC_STORE_INTEGER
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC_BINOP_EXT
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP

#undef TRACE
#undef __

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```
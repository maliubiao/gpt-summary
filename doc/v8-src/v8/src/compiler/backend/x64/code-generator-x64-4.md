Response: The user wants a summary of the functionality of the C++ code provided. The code is part of the V8 JavaScript engine and specifically deals with code generation for the x64 architecture. Since this is part 5 of 5, it likely covers the final stages of code generation, including control flow, frame setup, returns, moves, and jumps.

I should break down the code snippets and identify the core actions performed by each function. Then, I will synthesize a concise summary of the file's overall purpose. Finally, I will try to illustrate its connection to JavaScript with an example.
```javascript
// 这是一个代码生成器的部分实现，负责将中间表示（IR）指令转换为 x64 汇编代码。
// 它处理控制流操作（例如分支、跳转、条件跳转）、函数调用和返回、
// 以及数据移动和操作。

// 与 JavaScript 的关系在于，V8 编译 JavaScript 代码的流程中，
// CodeGeneratorX64 会被用来生成最终可以在 x64 架构上执行的机器码。

// 举例来说，JavaScript 中的一个简单的 if 语句：
function example(x) {
  if (x > 10) {
    return "greater";
  } else {
    return "not greater";
  }
}

// 在 V8 的编译过程中，这个 if 语句会被转换为一系列的 IR 指令。
// CodeGeneratorX64 中的 AssembleArchBranch 函数（或者类似的函数）
// 会将这些 IR 指令转换为 x64 的条件跳转指令，例如：

// 假设 IR 中表示 x > 10 的比较结果保存在某个标志位中
// 以及 "greater" 和 "not greater" 的返回值地址已经确定

// AssembleArchBranch 可能会生成如下的汇编代码：
// 比较 x 和 10
// ...
// 如果标志位指示 x > 10，则跳转到 "greater" 的代码块
// jg <label_greater>
// 否则，继续执行 "not greater" 的代码块

// AssembleArchReturn 函数会生成返回指令，将结果返回给调用者。

// AssembleMove 函数则负责将数据从一个位置移动到另一个位置，
// 例如将计算结果存储到寄存器或栈上。

// 总而言之，这个文件中的代码是将高级的 JavaScript 逻辑
// 转换为低级的、可以直接在 CPU 上运行的指令的关键部分。
```

这是 `v8/src/compiler/backend/x64/code-generator-x64.cc` 源代码文件的最后一部分，主要负责完成以下功能：

1. **分支指令的汇编 (AssembleArchBranch, AssembleArchDeoptBranch, AssembleArchTrap):**  根据 IR 指令中的条件生成相应的 x64 分支指令（例如 `jmp`，`jcc`）。它会考虑 CPU 特性（例如 `INTEL_JCC_ERRATUM_MITIGATION`）来生成优化的分支代码。`AssembleArchDeoptBranch` 专门处理需要进行反优化的分支。 `AssembleArchTrap` 用于 WebAssembly 中的 trap 操作。

2. **布尔值生成的汇编 (AssembleArchBoolean):**  根据条件码生成布尔值（0 或 1）并存储到指定寄存器中。

3. **条件选择的汇编 (AssembleArchSelect):**  根据条件码，从两个输入中选择一个作为输出。这对应于 CMOV 指令。

4. **Switch 语句的汇编 (AssembleArchBinarySearchSwitch, AssembleArchTableSwitch):**  将高级的 switch 语句转换为 x64 的跳转指令序列。`AssembleArchBinarySearchSwitch` 使用二分查找优化大型 switch 语句，而 `AssembleArchTableSwitch` 使用跳转表来实现高效跳转。

5. **函数帧的构建和销毁 (FinishFrame, AssembleConstructFrame, AssembleDeconstructFrame, AssembleReturn):**  负责生成函数调用时的栈帧设置代码（例如保存寄存器，分配局部变量空间）和函数返回时的栈帧清理代码（恢复寄存器，释放栈空间）。`AssembleReturn` 处理函数返回，包括恢复寄存器和跳转到返回地址。 对于 JavaScript 函数调用，还会处理参数的弹出。

6. **代码结束处理 (FinishCode):**  执行代码生成完成后的清理工作，例如修补常量池。

7. **反优化出口准备 (PrepareForDeoptimizationExits):**  为代码的反优化出口做准备。

8. **栈访问计数 (IncrementStackAccessCounter):**  用于调试和性能分析，记录栈的访问次数。

9. **临时栈空间管理 (Push, Pop, PopTempStackSlots):**  提供操作栈的辅助函数，用于在代码生成过程中临时存储数据。

10. **数据移动 (AssembleMove, AssembleSwap, MoveToTempLocation, MoveTempLocationTo, SetPendingMove):**  生成 x64 的数据移动指令 (`mov`, `movsd`, `movaps` 等)，用于在寄存器、内存之间传递数据。 `AssembleSwap` 用于交换两个操作数的值。 提供了临时位置存储和恢复的机制。

11. **跳转表生成 (AssembleJumpTable):**  生成跳转表数据，用于 `AssembleArchTableSwitch`。对于内置函数，跳转表存储的是目标地址与表地址的偏移量，以实现位置无关性。

**与 JavaScript 的关系:**

这个文件是 V8 编译器后端的一部分，直接将 TurboFan 优化器生成的中间代码转换为可以在 x64 架构上执行的机器码。JavaScript 代码经过解析、编译优化后，最终会通过 `CodeGeneratorX64` 生成汇编指令。

**JavaScript 举例:**

考虑以下 JavaScript 代码：

```javascript
function foo(x) {
  if (x > 10) {
    return x * 2;
  } else {
    return x + 5;
  }
}
```

当 V8 编译这个函数时，`CodeGeneratorX64` 中的相关函数会执行以下操作：

* **`AssembleArchBranch`:** 将 `if (x > 10)` 转换为一个比较指令和一个条件跳转指令。例如，比较 `x` 和 `10`，如果大于则跳转到 `return x * 2;` 的代码块。
* **`AssembleMove`:** 将 `x` 的值加载到寄存器中，并将常量 `2` 或 `5` 加载到另一个寄存器中。
* **`AssembleArchBoolean` (如果需要):**  如果需要将比较结果显式地存储为布尔值，则会使用此函数。
* **`AssembleReturn`:** 将计算结果存储到返回寄存器，并生成返回指令。
* **`AssembleConstructFrame`:**  在函数入口处分配栈帧，可能用于保存局部变量或寄存器。
* **`AssembleDeconstructFrame`:** 在函数返回前清理栈帧。

对于一个 `switch` 语句的例子：

```javascript
function bar(y) {
  switch (y) {
    case 1: return "one";
    case 5: return "five";
    case 10: return "ten";
    default: return "other";
  }
}
```

`CodeGeneratorX64` 中的 `AssembleArchTableSwitch` 或 `AssembleArchBinarySearchSwitch` 会根据 case 的数量选择合适的方式生成跳转代码，直接跳转到对应 case 的代码块。

总之，`code-generator-x64.cc` (第 5 部分) 的功能是 V8 引擎将高级 JavaScript 代码转化为可在 x64 处理器上执行的低级机器指令的关键组成部分，涵盖了控制流、函数调用、数据操作等核心方面。

Prompt: 
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共5部分，请归纳一下它的功能

"""
es branches after this instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  Label::Distance flabel_distance =
      branch->fallthru ? Label::kNear : Label::kFar;
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;
  if (CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION)) {
    if (branch->condition == kUnorderedEqual) {
      __ aligned_j(FlagsConditionToCondition(kIsNaN), flabel, flabel_distance);
    } else if (branch->condition == kUnorderedNotEqual) {
      __ aligned_j(FlagsConditionToCondition(kIsNaN), tlabel);
    }
    __ aligned_j(FlagsConditionToCondition(branch->condition), tlabel);
    if (!branch->fallthru) {
      __ aligned_jmp(flabel, flabel_distance);
    }
  } else {
    if (branch->condition == kUnorderedEqual) {
      __ j(FlagsConditionToCondition(kIsNaN), flabel, flabel_distance);
    } else if (branch->condition == kUnorderedNotEqual) {
      __ j(FlagsConditionToCondition(kIsNaN), tlabel);
    }
    __ j(FlagsConditionToCondition(branch->condition), tlabel);
    if (!branch->fallthru) {
      __ jmp(flabel, flabel_distance);
    }
  }
}

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  Label::Distance flabel_distance =
      branch->fallthru ? Label::kNear : Label::kFar;
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;
  Label nodeopt;
  if (CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION)) {
    if (branch->condition == kUnorderedEqual) {
      __ aligned_j(FlagsConditionToCondition(kIsNaN), flabel, flabel_distance);
    } else if (branch->condition == kUnorderedNotEqual) {
      __ aligned_j(FlagsConditionToCondition(kIsNaN), tlabel);
    }
    __ aligned_j(FlagsConditionToCondition(branch->condition), tlabel);
  } else {
    if (branch->condition == kUnorderedEqual) {
      __ j(FlagsConditionToCondition(kIsNaN), flabel, flabel_distance);
    } else if (branch->condition == kUnorderedNotEqual) {
      __ j(FlagsConditionToCondition(kIsNaN), tlabel);
    }
    __ j(FlagsConditionToCondition(branch->condition), tlabel);
  }

  if (v8_flags.deopt_every_n_times > 0) {
    if (isolate() != nullptr) {
      ExternalReference counter =
          ExternalReference::stress_deopt_count(isolate());

      __ pushfq();
      __ pushq(rax);
      __ load_rax(counter);
      __ decl(rax);
      __ j(not_zero, &nodeopt, Label::kNear);

      __ Move(rax, v8_flags.deopt_every_n_times);
      __ store_rax(counter);
      __ popq(rax);
      __ popfq();
      __ jmp(tlabel);

      __ bind(&nodeopt);
      __ store_rax(counter);
      __ popq(rax);
      __ popfq();
    } else {
#if V8_ENABLE_WEBASSEMBLY
      CHECK(v8_flags.wasm_deopt);
      CHECK(IsWasm());
      __ pushfq();
      __ pushq(rax);
      __ pushq(rbx);
      // Load the address of the counter into rbx.
      __ movq(rbx, Operand(rbp, WasmFrameConstants::kWasmInstanceDataOffset));
      __ movq(
          rbx,
          Operand(rbx, WasmTrustedInstanceData::kStressDeoptCounterOffset - 1));
      // Load the counter into rax and decrement it.
      __ movq(rax, Operand(rbx, 0));
      __ decl(rax);
      __ j(not_zero, &nodeopt, Label::kNear);
      // The counter is zero, reset counter.
      __ Move(rax, v8_flags.deopt_every_n_times);
      __ movq(Operand(rbx, 0), rax);
      // Restore registers and jump to deopt label.
      __ popq(rbx);
      __ popq(rax);
      __ popfq();
      __ jmp(tlabel);
      // Write back counter and restore registers.
      __ bind(&nodeopt);
      __ movq(Operand(rbx, 0), rax);
      __ popq(rbx);
      __ popq(rax);
      __ popfq();
#else
      UNREACHABLE();
#endif
    }
  }

  if (!branch->fallthru) {
    if (CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION)) {
      __ aligned_jmp(flabel, flabel_distance);
    } else {
      __ jmp(flabel, flabel_distance);
    }
  }
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ jmp(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  auto ool = zone()->New<WasmOutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  Label end;
  if (condition == kUnorderedEqual) {
    __ j(FlagsConditionToCondition(kIsNaN), &end, Label::kNear);
  } else if (condition == kUnorderedNotEqual) {
    __ j(FlagsConditionToCondition(kIsNaN), tlabel);
  }
  __ j(FlagsConditionToCondition(condition), tlabel);
  __ bind(&end);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after this instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  X64OperandConverter i(this, instr);
  Label done;

  // Materialize a full 64-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  Label check;
  DCHECK_NE(0u, instr->OutputCount());
  Register reg = i.OutputRegister(instr->OutputCount() - 1);
  if (condition == kUnorderedEqual) {
    __ j(parity_odd, &check, Label::kNear);
    __ Move(reg, 0);
    __ jmp(&done, Label::kNear);
  } else if (condition == kUnorderedNotEqual) {
    __ j(parity_odd, &check, Label::kNear);
    __ Move(reg, 1);
    __ jmp(&done, Label::kNear);
  }
  __ bind(&check);
  __ setcc(FlagsConditionToCondition(condition), reg);
  if (!ShouldClearOutputRegisterBeforeInstruction(this, instr)) {
    __ movzxbl(reg, reg);
  }
  __ bind(&done);
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitchRange(
    Register input, RpoNumber def_block, std::pair<int32_t, Label*>* begin,
    std::pair<int32_t, Label*>* end, std::optional<int32_t>& last_cmp_value) {
  if (end - begin < kBinarySearchSwitchMinimalCases) {
    if (last_cmp_value && *last_cmp_value == begin->first) {
      // No need to do another repeat cmp.
      masm()->j(equal, begin->second);
      ++begin;
    }

    while (begin != end) {
      masm()->JumpIfEqual(input, begin->first, begin->second);
      ++begin;
    }
    AssembleArchJumpRegardlessOfAssemblyOrder(def_block);
    return;
  }
  auto middle = begin + (end - begin) / 2;
  Label less_label;
  masm()->JumpIfLessThan(input, middle->first, &less_label);
  last_cmp_value = middle->first;
  AssembleArchBinarySearchSwitchRange(input, def_block, middle, end,
                                      last_cmp_value);
  masm()->bind(&less_label);
  AssembleArchBinarySearchSwitchRange(input, def_block, begin, middle,
                                      last_cmp_value);
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  X64OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  std::optional<int32_t> last_cmp_value;
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size(),
                                      last_cmp_value);
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  X64OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  int32_t const case_count = static_cast<int32_t>(instr->InputCount() - 2);
  base::Vector<Label*> cases = zone()->AllocateVector<Label*>(case_count);
  for (int32_t index = 0; index < case_count; ++index) {
    cases[index] = GetLabel(i.InputRpo(index + 2));
  }
  Label* const table = AddJumpTable(cases);
  __ cmpl(input, Immediate(case_count));
  __ j(above_equal, GetLabel(i.InputRpo(1)));
  __ leaq(kScratchRegister, Operand(table));

  if (V8_UNLIKELY(Builtins::IsBuiltinId(masm_.builtin()))) {
    // For builtins, the value in the table is 'target_address - table_address'
    // (4 bytes) Load the value in the table with index.
    // value = [table +index*4]
    __ movsxlq(input, Operand(kScratchRegister, input, times_4, 0));
    // Calculate the absolute address of target:
    // target = table + (target - table)
    __ addq(input, kScratchRegister);
    // Jump to the target.

    // Add the notrack prefix to disable landing pad enforcement.
    __ jmp(input, /*notrack=*/true);
  } else {
    // For non builtins, the value in the table is 'target_address' (8 bytes)
    // jmp [table + index*8]
    __ jmp(Operand(kScratchRegister, input, times_8, 0), /*notrack=*/true);
  }
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  X64OperandConverter i(this, instr);
  MachineRepresentation rep =
      LocationOperand::cast(instr->OutputAt(0))->representation();
  Condition cc = FlagsConditionToCondition(condition);
  DCHECK_EQ(i.OutputRegister(), i.InputRegister(instr->InputCount() - 2));
  size_t last_input = instr->InputCount() - 1;
  // kUnorderedNotEqual can be implemented more efficiently than
  // kUnorderedEqual. As the OR of two flags, it can be done with just two
  // cmovs. If the condition was originally a kUnorderedEqual, expect the
  // instruction selector to have inverted it and swapped the input.
  DCHECK_NE(condition, kUnorderedEqual);
  if (rep == MachineRepresentation::kWord32) {
    if (HasRegisterInput(instr, last_input)) {
      __ cmovl(cc, i.OutputRegister(), i.InputRegister(last_input));
      if (condition == kUnorderedNotEqual) {
        __ cmovl(parity_even, i.OutputRegister(), i.InputRegister(last_input));
      }
    } else {
      __ cmovl(cc, i.OutputRegister(), i.InputOperand(last_input));
      if (condition == kUnorderedNotEqual) {
        __ cmovl(parity_even, i.OutputRegister(), i.InputOperand(last_input));
      }
    }
  } else {
    DCHECK_EQ(rep, MachineRepresentation::kWord64);
    if (HasRegisterInput(instr, last_input)) {
      __ cmovq(cc, i.OutputRegister(), i.InputRegister(last_input));
      if (condition == kUnorderedNotEqual) {
        __ cmovq(parity_even, i.OutputRegister(), i.InputRegister(last_input));
      }
    } else {
      __ cmovq(cc, i.OutputRegister(), i.InputOperand(last_input));
      if (condition == kUnorderedNotEqual) {
        __ cmovq(parity_even, i.OutputRegister(), i.InputOperand(last_input));
      }
    }
  }
}

namespace {

static const int kQuadWordSize = 16;

}  // namespace

void CodeGenerator::FinishFrame(Frame* frame) {
  CallDescriptor* call_descriptor = linkage()->GetIncomingDescriptor();

  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fp.is_empty()) {  // Save callee-saved XMM registers.
    frame->AlignSavedCalleeRegisterSlots();
    const uint32_t saves_fp_count = saves_fp.Count();
    frame->AllocateSavedCalleeRegisterSlots(
        saves_fp_count * (kQuadWordSize / kSystemPointerSize));
  }
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {  // Save callee-saved registers.
    frame->AllocateSavedCalleeRegisterSlots(saves.Count());
  }
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  if (frame_access_state()->has_frame()) {
    int pc_base = __ pc_offset();

    if (call_descriptor->IsCFunctionCall()) {
      __ pushq(rbp);
      __ movq(rbp, rsp);
#if V8_ENABLE_WEBASSEMBLY
      if (info()->GetOutputStackFrameType() == StackFrame::C_WASM_ENTRY) {
        __ Push(Immediate(StackFrame::TypeToMarker(StackFrame::C_WASM_ENTRY)));
        // Reserve stack space for saving the c_entry_fp later.
        __ AllocateStackSpace(kSystemPointerSize);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
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
        __ pushq(kWasmImplicitArgRegister);
      }
      if (call_descriptor->IsWasmCapiFunction()) {
        // Reserve space for saving the PC later.
        __ AllocateStackSpace(kSystemPointerSize);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }

    unwinding_info_writer_.MarkFrameConstructed(pc_base);
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
    required_slots -= static_cast<int>(osr_helper()->UnoptimizedFrameSlots());
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();

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
        __ movq(kScratchRegister,
                __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
        __ addq(kScratchRegister,
                Immediate(required_slots * kSystemPointerSize));
        __ cmpq(rsp, kScratchRegister);
        __ j(above_equal, &done, Label::kNear);
      }

      if (v8_flags.experimental_wasm_growable_stacks) {
        RegList regs_to_save;
        regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
        regs_to_save.set(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister());
        for (auto reg : wasm::kGpParamRegisters) regs_to_save.set(reg);
        __ PushAll(regs_to_save);
        __ movq(WasmHandleStackOverflowDescriptor::GapRegister(),
                Immediate(required_slots * kSystemPointerSize));
        __ movq(WasmHandleStackOverflowDescriptor::FrameBaseRegister(), rbp);
        __ addq(WasmHandleStackOverflowDescriptor::FrameBaseRegister(),
                Immediate(static_cast<int32_t>(
                    call_descriptor->ParameterSlotCount() * kSystemPointerSize +
                    CommonFrameConstants::kFixedFrameSizeAboveFp)));
        __ CallBuiltin(Builtin::kWasmHandleStackOverflow);
        __ PopAll(regs_to_save);
      } else {
        __ near_call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
                     RelocInfo::WASM_STUB_CALL);
        // The call does not return, hence we can ignore any references and just
        // define an empty safepoint.
        ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
        RecordSafepoint(reference_map);
        __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
      }
      __ bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    // Skip callee-saved and return slots, which are created below.
    required_slots -= saves.Count();
    required_slots -= saves_fp.Count() * (kQuadWordSize / kSystemPointerSize);
    required_slots -= frame()->GetReturnSlotCount();
    if (required_slots > 0) {
      __ AllocateStackSpace(required_slots * kSystemPointerSize);
    }
  }

  if (!saves_fp.is_empty()) {  // Save callee-saved XMM registers.
    const uint32_t saves_fp_count = saves_fp.Count();
    const int stack_size = saves_fp_count * kQuadWordSize;
    // Adjust the stack pointer.
    __ AllocateStackSpace(stack_size);
    // Store the registers on the stack.
    int slot_idx = 0;
    for (XMMRegister reg : saves_fp) {
      __ Movdqu(Operand(rsp, kQuadWordSize * slot_idx), reg);
      slot_idx++;
    }
  }

  if (!saves.is_empty()) {  // Save callee-saved registers.
    for (Register reg : base::Reversed(saves)) {
      __ pushq(reg);
    }
  }

  // Allocate return slots (located after callee-saved).
  if (frame()->GetReturnSlotCount() > 0) {
    __ AllocateStackSpace(frame()->GetReturnSlotCount() * kSystemPointerSize);
  }

  for (int spill_slot : frame()->tagged_slots()) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
    DCHECK(offset.from_frame_pointer());
    __ movq(Operand(rbp, offset.offset()), Immediate(0));
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  // Restore registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    const int returns = frame()->GetReturnSlotCount();
    if (returns != 0) {
      __ addq(rsp, Immediate(returns * kSystemPointerSize));
    }
    for (Register reg : saves) {
      __ popq(reg);
    }
  }
  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fp.is_empty()) {
    const uint32_t saves_fp_count = saves_fp.Count();
    const int stack_size = saves_fp_count * kQuadWordSize;
    // Load the registers from the stack.
    int slot_idx = 0;
    for (XMMRegister reg : saves_fp) {
      __ Movdqu(reg, Operand(rsp, kQuadWordSize * slot_idx));
      slot_idx++;
    }
    // Adjust the stack pointer.
    __ addq(rsp, Immediate(stack_size));
  }

  unwinding_info_writer_.MarkBlockWillExit();

  X64OperandConverter g(this, nullptr);
  int parameter_slots = static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ cmpq(g.ToRegister(additional_pop_count), Immediate(0));
      __ Assert(equal, AbortReason::kUnexpectedAdditionalPopValue);
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  if (call_descriptor->IsWasmFunctionCall() &&
      v8_flags.experimental_wasm_growable_stacks) {
    __ movq(kScratchRegister,
            MemOperand(rbp, TypedFrameConstants::kFrameTypeOffset));
    __ cmpq(
        kScratchRegister,
        Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
    Label done;
    __ j(not_equal, &done);
    RegList regs_to_save;
    for (auto reg : wasm::kGpReturnRegisters) regs_to_save.set(reg);
    __ PushAll(regs_to_save);
    __ PrepareCallCFunction(1);
    __ LoadAddress(kCArgRegs[0], ExternalReference::isolate_address());
    __ CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
    // Restore old FP. We don't need to restore old SP explicitly, because
    // it will be restored from FP inside of AssembleDeconstructFrame.
    __ movq(rbp, kReturnRegister0);
    __ PopAll(regs_to_save);
    __ bind(&done);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  Register argc_reg = rcx;
  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.
  const bool drop_jsargs = parameter_slots != 0 &&
                           frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall();
  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      // Canonicalize JSFunction return sites for now.
      if (return_label_.is_bound()) {
        // Emit a far jump here can't save code size but may bring some
        // regression, so we just forward when it is a near jump.
        const bool is_near_jump = is_int8(return_label_.pos() - __ pc_offset());
        if (drop_jsargs || is_near_jump) {
          __ jmp(&return_label_);
          return;
        }
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count.
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
      __ movq(argc_reg, Operand(rbp, StandardFrameConstants::kArgCOffset));
    }
    AssembleDeconstructFrame();
  }

  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver).
    // The number of arguments without the receiver is
    // max(argc_reg, parameter_slots-1), and the receiver is added in
    // DropArguments().
    Label mismatch_return;
    Register scratch_reg = r10;
    DCHECK_NE(argc_reg, scratch_reg);
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(scratch_reg));
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    __ cmpq(argc_reg, Immediate(parameter_slots));
    __ j(greater, &mismatch_return, Label::kNear);
    __ Ret(parameter_slots * kSystemPointerSize, scratch_reg);
    __ bind(&mismatch_return);
    __ DropArguments(argc_reg, scratch_reg);
    // We use a return instead of a jump for better return address prediction.
    __ Ret();
  } else if (additional_pop_count->IsImmediate()) {
    Register scratch_reg = r10;
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(scratch_reg));
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    size_t pop_size = (parameter_slots + additional_count) * kSystemPointerSize;
    CHECK_LE(pop_size, static_cast<size_t>(std::numeric_limits<int>::max()));
    __ Ret(static_cast<int>(pop_size), scratch_reg);
  } else {
    Register pop_reg = g.ToRegister(additional_pop_count);
    Register scratch_reg = pop_reg == r10 ? rcx : r10;
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(scratch_reg));
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(pop_reg));
    int pop_size = static_cast<int>(parameter_slots * kSystemPointerSize);
    __ PopReturnAddressTo(scratch_reg);
    __ leaq(rsp, Operand(rsp, pop_reg, times_system_pointer_size,
                         static_cast<int>(pop_size)));
    __ PushReturnAddressFrom(scratch_reg);
    __ Ret();
  }
}

void CodeGenerator::FinishCode() { masm()->PatchConstPool(); }

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {}

void CodeGenerator::IncrementStackAccessCounter(
    InstructionOperand* source, InstructionOperand* destination) {
  DCHECK(v8_flags.trace_turbo_stack_accesses);
  if (!info()->IsOptimizing()) {
#if V8_ENABLE_WEBASSEMBLY
    if (!info()->IsWasm()) return;
#else
    return;
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  DCHECK_NOT_NULL(debug_name_);
  auto IncrementCounter = [&](ExternalReference counter) {
    __ incl(__ ExternalReferenceAsOperand(counter));
  };
  if (source->IsAnyStackSlot()) {
    IncrementCounter(
        ExternalReference::address_of_load_from_stack_count(debug_name_));
  }
  if (destination->IsAnyStackSlot()) {
    IncrementCounter(
        ExternalReference::address_of_store_to_stack_count(debug_name_));
  }
}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  X64OperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ pushq(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot() || source->IsFloatStackSlot() ||
             source->IsDoubleStackSlot()) {
    __ pushq(g.ToOperand(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for xmm registers / 128-bit memory operands. Bump
    // the stack pointer and assemble the move.
    __ subq(rsp, Immediate(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  X64OperandConverter g(this, nullptr);
  int dropped_slots = ElementSizeInPointers(rep);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ popq(g.ToRegister(dest));
  } else if (dest->IsStackSlot() || dest->IsFloatStackSlot() ||
             dest->IsDoubleStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ popq(g.ToOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ addq(rsp, Immediate(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ addq(rsp, Immediate(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  DCHECK(!source->IsImmediate());
  if ((IsFloatingPoint(rep) &&
       !move_cycle_.pending_double_scratch_register_use) ||
      (!IsFloatingPoint(rep) && !move_cycle_.pending_scratch_register_use)) {
    // The scratch register for this rep is available.
    int scratch_reg_code = !IsFloatingPoint(rep) ? kScratchRegister.code()
                                                 : kScratchDoubleReg.code();
    AllocatedOperand scratch(LocationOperand::REGISTER, rep, scratch_reg_code);
    AssembleMove(source, &scratch);
  } else {
    // The scratch register is blocked by pending moves. Use the stack instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  if ((IsFloatingPoint(rep) &&
       !move_cycle_.pending_double_scratch_register_use) ||
      (!IsFloatingPoint(rep) && !move_cycle_.pending_scratch_register_use)) {
    int scratch_reg_code = !IsFloatingPoint(rep) ? kScratchRegister.code()
                                                 : kScratchDoubleReg.code();
    AllocatedOperand scratch(LocationOperand::REGISTER, rep, scratch_reg_code);
    AssembleMove(&scratch, dest);
  } else {
    Pop(dest, rep);
  }
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  MoveType::Type move_type =
      MoveType::InferMove(&move->source(), &move->destination());
  if (move_type == MoveType::kConstantToStack) {
    X64OperandConverter g(this, nullptr);
    Constant src = g.ToConstant(&move->source());
    if (move->destination().IsStackSlot() &&
        (!RelocInfo::IsNoInfo(src.rmode()) ||
         (src.type() != Constant::kInt32 && src.type() != Constant::kInt64))) {
      move_cycle_.pending_scratch_register_use = true;
    }
  } else if (move_type == MoveType::kStackToStack) {
    if (move->source().IsFPLocationOperand()) {
      move_cycle_.pending_double_scratch_register_use = true;
    } else {
      move_cycle_.pending_scratch_register_use = true;
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

// When we need only 32 bits, move only 32 bits. Benefits:
// - Save a byte here and there (depending on the destination
//   register; "movl eax, ..." is smaller than "movq rax, ...").
// - Safeguard against accidental decompression of compressed slots.
// We must check both {source} and {destination} to be 32-bit values,
// because treating 32-bit sources as 64-bit values can be perfectly
// fine as a result of virtual register renaming (to avoid redundant
// explicit zero-extensions that also happen implicitly).
bool Use32BitMove(InstructionOperand* source, InstructionOperand* destination) {
  return Is32BitOperand(source) && Is32BitOperand(destination);
}

}  // namespace

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  X64OperandConverter g(this, nullptr);
  // Helper function to write the given constant to the dst register.
  // If a move type needs the scratch register, this also needs to be recorded
  // in {SetPendingMove} to avoid conflicts with the gap resolver.
  auto MoveConstantToRegister = [&](Register dst, Constant src) {
    switch (src.type()) {
      case Constant::kInt32: {
        int32_t value = src.ToInt32();
        if (value == 0 && RelocInfo::IsNoInfo(src.rmode())) {
          __ xorl(dst, dst);
        } else {
          __ movl(dst, Immediate(value, src.rmode()));
        }
        break;
      }
      case Constant::kInt64:
        if (RelocInfo::IsNoInfo(src.rmode())) {
          __ Move(dst, src.ToInt64());
        } else {
          __ movq(dst, Immediate64(src.ToInt64(), src.rmode()));
        }
        break;
      case Constant::kFloat32:
        __ MoveNumber(dst, src.ToFloat32());
        break;
      case Constant::kFloat64:
        __ MoveNumber(dst, src.ToFloat64().value());
        break;
      case Constant::kExternalReference:
        __ Move(dst, src.ToExternalReference());
        break;
      case Constant::kHeapObject: {
        Handle<HeapObject> src_object = src.ToHeapObject();
        RootIndex index;
        if (IsMaterializableFromRoot(src_object, &index)) {
          __ LoadRoot(dst, index);
        } else {
          __ Move(dst, src_object);
        }
        break;
      }
      case Constant::kCompressedHeapObject: {
        Handle<HeapObject> src_object = src.ToHeapObject();
        RootIndex index;
        if (IsMaterializableFromRoot(src_object, &index)) {
          __ LoadTaggedRoot(dst, index);
        } else {
          __ Move(dst, src_object, RelocInfo::COMPRESSED_EMBEDDED_OBJECT);
        }
        break;
      }
      case Constant::kRpoNumber:
        UNREACHABLE();  // TODO(dcarney): load of labels on x64.
    }
  };
  // Helper function to write the given constant to the stack.
  auto MoveConstantToSlot = [&](Operand dst, Constant src) {
    if (RelocInfo::IsNoInfo(src.rmode())) {
      switch (src.type()) {
        case Constant::kInt32:
          __ Move(dst, src.ToInt32());
          return;
        case Constant::kInt64:
          __ Move(dst, src.ToInt64());
          return;
        default:
          break;
      }
    }
    MoveConstantToRegister(kScratchRegister, src);
    __ movq(dst, kScratchRegister);
  };

  if (v8_flags.trace_turbo_stack_accesses) {
    IncrementStackAccessCounter(source, destination);
  }

  // Dispatch on the source and destination operand kinds.
  switch (MoveType::InferMove(source, destination)) {
    case MoveType::kRegisterToRegister:
      if (source->IsRegister()) {
        DCHECK(destination->IsRegister());
        if (Use32BitMove(source, destination)) {
          __ movl(g.ToRegister(destination), g.ToRegister(source));
        } else {
          __ movq(g.ToRegister(destination), g.ToRegister(source));
        }
      } else {
        DCHECK(source->IsFPRegister());
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kSimd256) {
          CpuFeatureScope avx_scope(masm(), AVX);
          // Whether the ymm source should be used as a xmm.
          if (source->IsSimd256Register() && destination->IsSimd128Register()) {
            __ vmovapd(g.ToSimd128Register(destination),
                       g.ToSimd128Register(source));
          } else {
            __ vmovapd(g.ToSimd256Register(destination),
                       g.ToSimd256Register(source));
          }
        } else {
          __ Movapd(g.ToDoubleRegister(destination),
                    g.ToDoubleRegister(source));
        }
      }
      return;
    case MoveType::kRegisterToStack: {
      Operand dst = g.ToOperand(destination);
      if (source->IsRegister()) {
        __ movq(dst, g.ToRegister(source));
      } else {
        DCHECK(source->IsFPRegister());
        XMMRegister src = g.ToDoubleRegister(source);
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kSimd128) {
          __ Movups(dst, src);
        } else if (rep == MachineRepresentation::kSimd256) {
          CpuFeatureScope avx_scope(masm(), AVX);
          // Whether the ymm source should be used as a xmm.
          if (source->IsSimd256Register() &&
              destination->IsSimd128StackSlot()) {
            __ vmovups(dst, g.ToSimd128Register(source));
          } else {
            __ vmovups(dst, g.ToSimd256Register(source));
          }
        } else {
          __ Movsd(dst, src);
        }
      }
      return;
    }
    case MoveType::kStackToRegister: {
      Operand src = g.ToOperand(source);
      if (source->IsStackSlot()) {
        if (Use32BitMove(source, destination)) {
          __ movl(g.ToRegister(destination), src);
        } else {
          __ movq(g.ToRegister(destination), src);
        }
      } else {
        DCHECK(source->IsFPStackSlot());
        XMMRegister dst = g.ToDoubleRegister(destination);
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kSimd128) {
          __ Movups(dst, src);
        } else if (rep == MachineRepresentation::kSimd256) {
          CpuFeatureScope avx_scope(masm(), AVX);
          if (source->IsSimd256StackSlot() &&
              destination->IsSimd128Register()) {
            __ vmovups(g.ToSimd128Register(destination), src);
          } else {
            __ vmovups(g.ToSimd256Register(destination), src);
          }
        } else {
          __ Movsd(dst, src);
        }
      }
      return;
    }
    case MoveType::kStackToStack: {
      Operand src = g.ToOperand(source);
      Operand dst = g.ToOperand(destination);
      if (source->IsStackSlot()) {
        // Spill on demand to use a temporary register for memory-to-memory
        // moves.
        if (Use32BitMove(source, destination)) {
          __ movl(kScratchRegister, src);
        } else {
          __ movq(kScratchRegister, src);
        }
        // Always write the full 64-bit to avoid leaving stale bits in the upper
        // 32-bit on the stack.
        __ movq(dst, kScratchRegister);
      } else {
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kSimd128) {
          __ Movups(kScratchDoubleReg, src);
          __ Movups(dst, kScratchDoubleReg);
        } else if (rep == MachineRepresentation::kSimd256) {
          CpuFeatureScope avx_scope(masm(), AVX);
          if (source->IsSimd256StackSlot() &&
              destination->IsSimd128StackSlot()) {
            __ vmovups(kScratchDoubleReg, src);
            __ vmovups(dst, kScratchDoubleReg);
          } else {
            __ vmovups(kScratchSimd256Reg, src);
            __ vmovups(dst, kScratchSimd256Reg);
          }
        } else {
          __ Movsd(kScratchDoubleReg, src);
          __ Movsd(dst, kScratchDoubleReg);
        }
      }
      return;
    }
    case MoveType::kConstantToRegister: {
      Constant src = g.ToConstant(source);
      if (destination->IsRegister()) {
        MoveConstantToRegister(g.ToRegister(destination), src);
      } else {
        DCHECK(destination->IsFPRegister());
        XMMRegister dst = g.ToDoubleRegister(destination);
        if (src.type() == Constant::kFloat32) {
          // TODO(turbofan): Can we do better here?
          __ Move(dst, base::bit_cast<uint32_t>(src.ToFloat32()));
        } else {
          DCHECK_EQ(src.type(), Constant::kFloat64);
          __ Move(dst, src.ToFloat64().AsUint64());
        }
      }
      return;
    }
    case MoveType::kConstantToStack: {
      Constant src = g.ToConstant(source);
      Operand dst = g.ToOperand(destination);
      if (destination->IsStackSlot()) {
        MoveConstantToSlot(dst, src);
      } else {
        DCHECK(destination->IsFPStackSlot());
        if (src.type() == Constant::kFloat32) {
          __ movl(dst, Immediate(base::bit_cast<uint32_t>(src.ToFloat32())));
        } else {
          DCHECK_EQ(src.type(), Constant::kFloat64);
          __ Move(dst, src.ToFloat64().AsUint64());
        }
      }
      return;
    }
  }
  UNREACHABLE();
}

void CodeGenerator::AssembleSwap(InstructionOperand* source,
                                 InstructionOperand* destination) {
  if (v8_flags.trace_turbo_stack_accesses) {
    IncrementStackAccessCounter(source, destination);
    IncrementStackAccessCounter(destination, source);
  }

  X64OperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  switch (MoveType::InferSwap(source, destination)) {
    case MoveType::kRegisterToRegister: {
      if (source->IsRegister()) {
        Register src = g.ToRegister(source);
        Register dst = g.ToRegister(destination);
        if (Use32BitMove(source, destination)) {
          __ movl(kScratchRegister, src);
          __ movl(src, dst);
          __ movl(dst, kScratchRegister);
        } else {
          __ movq(kScratchRegister, src);
          __ movq(src, dst);
          __ movq(dst, kScratchRegister);
        }
      } else {
        DCHECK(source->IsFPRegister());
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kSimd256) {
          YMMRegister src = g.ToSimd256Register(source);
          YMMRegister dst = g.ToSimd256Register(destination);
          CpuFeatureScope avx_scope(masm(), AVX);
          __ vmovapd(kScratchSimd256Reg, src);
          __ vmovapd(src, dst);
          __ vmovapd(dst, kScratchSimd256Reg);

        } else {
          XMMRegister src = g.ToDoubleRegister(source);
          XMMRegister dst = g.ToDoubleRegister(destination);
          __ Movapd(kScratchDoubleReg, src);
          __ Movapd(src, dst);
          __ Movapd(dst, kScratchDoubleReg);
        }
      }
      return;
    }
    case MoveType::kRegisterToStack: {
      if (source->IsRegister()) {
        Register src = g.ToRegister(source);
        Operand dst = g.ToOperand(destination);
        __ movq(kScratchRegister, src);
        __ movq(src, dst);
        __ movq(dst, kScratchRegister);
      } else {
        DCHECK(source->IsFPRegister());
        Operand dst = g.ToOperand(destination);
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kSimd128) {
          XMMRegister src = g.ToDoubleRegister(source);
          __ Movups(kScratchDoubleReg, src);
          __ Movups(src, dst);
          __ Movups(dst, kScratchDoubleReg);
        } else if (rep == MachineRepresentation::kSimd256) {
          YMMRegister src = g.ToSimd256Register(source);
          CpuFeatureScope avx_scope(masm(), AVX);
          __ vmovups(kScratchSimd256Reg, src);
          __ vmovups(src, dst);
          __ vmovups(dst, kScratchSimd256Reg);
        } else {
          XMMRegister src = g.ToDoubleRegister(source);
          __ Movsd(kScratchDoubleReg, src);
          __ Movsd(src, dst);
          __ Movsd(dst, kScratchDoubleReg);
        }
      }
      return;
    }
    case MoveType::kStackToStack: {
      Operand src = g.ToOperand(source);
      Operand dst = g.ToOperand(destination);
      MachineRepresentation rep =
          LocationOperand::cast(source)->representation();
      if (rep == MachineRepresentation::kSimd128) {
        // Without AVX, misaligned reads and writes will trap. Move using the
        // stack, in two parts.
        // The XOR trick can be used if AVX is supported, but it needs more
        // instructions, and may introduce performance penalty if the memory
        // reference splits a cache line.
        __ movups(kScratchDoubleReg, dst);  // Save dst in scratch register.
        __ pushq(src);  // Then use stack to copy src to destination.
        unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                         kSystemPointerSize);
        __ popq(dst);
        unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                         -kSystemPointerSize);
        __ pushq(g.ToOperand(source, kSystemPointerSize));
        unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                         kSystemPointerSize);
        __ popq(g.ToOperand(destination, kSystemPointerSize));
        unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                         -kSystemPointerSize);
        __ movups(src, kScratchDoubleReg);
      } else if (rep == MachineRepresentation::kSimd256) {
        // Use the XOR trick to swap without a temporary. The xorps may read
        // from unaligned address, causing a slowdown, but swaps
        // between slots should be rare.
        __ vmovups(kScratchSimd256Reg, src);
        __ vxorps(kScratchSimd256Reg, kScratchSimd256Reg,
                  dst);  // scratch contains src ^ dst.
        __ vmovups(src, kScratchSimd256Reg);
        __ vxorps(kScratchSimd256Reg, kScratchSimd256Reg,
                  dst);  // scratch contains src.
        __ vmovups(dst, kScratchSimd256Reg);
        __ vxorps(kScratchSimd256Reg, kScratchSimd256Reg,
                  src);  // scratch contains dst.
        __ vmovups(src, kScratchSimd256Reg);
      } else {
        Register tmp = kScratchRegister;
        __ movq(tmp, dst);
        __ pushq(src);  // Then use stack to copy src to destination.
        unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                         kSystemPointerSize);
        __ popq(dst);
        unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                         -kSystemPointerSize);
        __ movq(src, tmp);
      }
      return;
    }
    default:
      UNREACHABLE();
  }
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
#ifdef V8_ENABLE_BUILTIN_JUMP_TABLE_SWITCH
  // For builtins, the value in table is `target_address - table_address`.
  // The reason is that the builtins code position may be changed so the table
  // value should be position independent.
  if (V8_UNLIKELY(Builtins::IsBuiltinId(masm_.builtin()))) {
    int table_pos = __ pc_offset();

    for (auto* target : targets) {
      __ WriteBuiltinJumpTableEntry(target, table_pos);
    }
    return;
  }

#endif  // V8_ENABLE_BUILTIN_JUMP_TABLE_SWITCH

  // For non-builtins, the value in table is just the target absolute address,
  // it's position dependent.
  for (size_t index = 0; index < targets.size(); ++index) {
    __ dq(targets[index]);
  }
}

#undef __

}  // namespace v8::internal::compiler

"""


```
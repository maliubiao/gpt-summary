Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/x64/code-generator-x64.cc`. They've also given specific constraints and questions related to V8, Torque, JavaScript, code logic, and common programming errors. This is the 9th of 10 parts, so a summary of its function is expected.

Here's a breakdown of the thought process to address each of the user's requests:

1. **Identify the core purpose:** The code clearly deals with generating x64 assembly instructions based on higher-level instructions (likely from the V8 compiler's intermediate representation). The function names like `AssembleArchBranch`, `AssembleArchDeoptBranch`, `AssembleArchBoolean`, etc., strongly suggest this.

2. **List the functionalities:** Go through each function in the snippet and describe what it does in terms of assembly generation:
    * `AssembleArchBranch`: Generates conditional branch instructions. It handles a specific mitigation for Intel JCC erratum and different branch conditions, including unordered comparisons (NaN checks).
    * `AssembleArchDeoptBranch`: Generates conditional branch instructions that can trigger deoptimization. It includes logic for `v8_flags.deopt_every_n_times` to force deoptimizations for testing purposes. It also has WebAssembly specific logic.
    * `AssembleArchJumpRegardlessOfAssemblyOrder`: Generates an unconditional jump.
    * `AssembleArchTrap`: Generates a trap instruction, primarily for WebAssembly.
    * `AssembleArchBoolean`: Generates code to materialize boolean values (0 or 1) based on flag conditions.
    * `AssembleArchConditionalBoolean`, `AssembleArchConditionalBranch`:  These functions contain `UNREACHABLE()`, indicating they are not currently used or implemented for this architecture in this context.
    * `AssembleArchBinarySearchSwitchRange`, `AssembleArchBinarySearchSwitch`: Generate code for efficient switch statements using binary search.
    * `AssembleArchTableSwitch`: Generates code for jump tables, used for dense switch statements. It handles differences between built-in and non-built-in code.
    * `AssembleArchSelect`: Generates code for conditional moves (cmov) based on flags.
    * `FinishFrame`:  Allocates space for saved callee registers and other frame data.
    * `AssembleConstructFrame`: Generates the prologue of a function, setting up the stack frame. Handles OSR entry points and potential stack overflow checks for WebAssembly.
    * `AssembleReturn`: Generates the epilogue of a function, restoring registers and returning. Handles dropping arguments for JavaScript functions and special logic for WebAssembly growable stacks.
    * `FinishCode`:  Performs post-assembly tasks like patching the constant pool.
    * `PrepareForDeoptimizationExits`:  Empty function in this snippet.
    * `IncrementStackAccessCounter`:  Increments counters for tracing stack accesses (only active in debug builds and optimization).
    * `Push`, `Pop`: Helper functions to manipulate the stack, managing stack pointer adjustments.
    * `PopTempStackSlots`: Cleans up temporary stack allocations.
    * `MoveToTempLocation`, `MoveTempLocationTo`: Helper functions for moving data to temporary locations (registers or stack) to avoid conflicts.
    * `SetPendingMove`: Tracks pending moves to manage register usage.
    * `AssembleMove`: Generates move instructions, handling different operand types (registers, memory, constants). It includes optimizations for 32-bit moves.

3. **Check for Torque:** The code does *not* end with `.tq`. Therefore, it's not a Torque source file.

4. **Relate to JavaScript:**  The code is directly involved in compiling JavaScript. The branching, deoptimization, and function call/return mechanisms are fundamental to how JavaScript execution is managed by V8. Provide a simple JavaScript `if` statement as an example to illustrate how a high-level conditional would be translated into branch instructions by this code.

5. **Provide code logic examples:**
    * For `AssembleArchBranch`, illustrate how different conditions map to different assembly instructions and how the `fallthru` flag affects the generated code. Provide sample inputs (instruction details, branch info) and the expected assembly output.
    * For `AssembleArchDeoptBranch`, highlight the additional logic for the `deopt_every_n_times` flag and how it forces deoptimization.

6. **Illustrate common programming errors:**  Focus on errors related to the concepts in the code:
    * Incorrect conditional logic leading to wrong branches.
    * Stack corruption due to incorrect stack pointer management (though the code itself *prevents* this if used correctly by the compiler).
    * Deoptimization loops if deoptimization conditions are not handled properly.

7. **Summarize the functionality (as the 9th of 10 parts):**  Emphasize that this part of the `code-generator-x64.cc` is responsible for generating the core control flow and data manipulation assembly instructions for the x64 architecture. It handles branching, function calls/returns, stack management, and various optimizations. It's a crucial component in the code generation pipeline.

8. **Review and refine:** Ensure the explanations are clear, concise, and accurate. Check for any inconsistencies or missing information. For example, ensure that the explanation of `kUnorderedEqual` and `kUnorderedNotEqual` refers to NaN checks, which is evident in the code. Also, double-check the handling of the Intel JCC erratum mitigation.
这是 `v8/src/compiler/backend/x64/code-generator-x64.cc` 源代码的第 9 部分，主要负责生成 x64 架构的汇编代码，特别是关于**控制流**、**函数帧管理**和**数据移动**相关的指令。

以下是其功能的详细列表：

1. **生成条件分支指令 (`AssembleArchBranch`)**:
   - 根据指令 (`instr`) 和分支信息 (`branch`) 生成条件跳转指令。
   - 处理 `fallthru` (是否顺序执行) 的情况，决定使用近跳转 (`kNear`) 还是远跳转 (`kFar`)。
   - 特殊处理 `kUnorderedEqual` 和 `kUnorderedNotEqual` 条件，这些通常与浮点数 NaN 的比较有关。
   - 如果 CPU 支持 `INTEL_JCC_ERRATUM_MITIGATION`，会生成带有对齐前缀的跳转指令，以规避 Intel 处理器的 JCC 指令的勘误。

2. **生成用于反优化的条件分支指令 (`AssembleArchDeoptBranch`)**:
   - 类似于 `AssembleArchBranch`，但用于在特定条件下触发反优化流程。
   - 包含基于 `v8_flags.deopt_every_n_times` 的压力测试逻辑，可以强制每隔 N 次执行就进行反优化，用于测试目的。
   - 针对 WebAssembly 场景有特定的反优化处理逻辑。

3. **生成无条件跳转指令 (`AssembleArchJumpRegardlessOfAssemblyOrder`)**:
   -  简单地跳转到指定的标签。

4. **生成 Trap 指令 (针对 WebAssembly) (`AssembleArchTrap`)**:
   -  根据条件生成 trap 指令，用于在 WebAssembly 代码中触发异常或错误处理。

5. **生成布尔值物化指令 (`AssembleArchBoolean`)**:
   -  根据条件标志 (`condition`) 将寄存器设置为 0 或 1。
   -  处理 `kUnorderedEqual` 和 `kUnorderedNotEqual` 条件，与 NaN 的判断相关。

6. **`AssembleArchConditionalBoolean` 和 `AssembleArchConditionalBranch`**:
   -  目前包含 `UNREACHABLE()`，表示这部分功能在这个架构中可能未实现或不使用。

7. **生成二分查找 Switch 语句的指令 (`AssembleArchBinarySearchSwitchRange`, `AssembleArchBinarySearchSwitch`)**:
   -  为了高效地处理大量的 case，使用二分查找的方式生成跳转指令。
   -  `AssembleArchBinarySearchSwitchRange` 是递归辅助函数。

8. **生成跳转表 Switch 语句的指令 (`AssembleArchTableSwitch`)**:
   -  用于处理 case 数量较多且连续的情况。
   -  生成比较指令，判断索引是否在范围内，然后通过跳转表进行跳转。
   -  区分内置函数和普通函数的跳转表条目结构。

9. **生成条件选择指令 (`AssembleArchSelect`)**:
   -  根据条件标志 (`condition`) 选择不同的输入值写入输出寄存器。
   -  使用 `cmov` 指令实现条件移动。
   -  针对 `kUnorderedNotEqual` 有特殊的优化处理。

10. **完成函数帧的布局 (`FinishFrame`)**:
    - 计算并分配需要保存的 callee-saved 寄存器的空间。

11. **生成函数帧的构建代码 (`AssembleConstructFrame`)**:
    - 生成函数序言 (prologue)，包括保存帧指针、分配局部变量空间等。
    - 处理 C 函数调用、JS 函数调用和 Stub 调用的不同序言。
    - 处理 On-Stack Replacement (OSR) 的入口点。
    - 为 WebAssembly 函数进行栈溢出检查。
    - 保存 callee-saved 寄存器。

12. **生成函数返回代码 (`AssembleReturn`)**:
    - 生成函数尾声 (epilogue)，包括恢复 callee-saved 寄存器、调整栈指针等。
    - 处理 C 函数调用和 JS 函数调用的不同尾声。
    - 处理需要弹出参数的情况。
    - 针对 WebAssembly 的 growable stacks 有特殊处理。

13. **完成代码生成 (`FinishCode`)**:
    - 执行代码生成的最后步骤，例如修补常量池。

14. **准备反优化出口 (`PrepareForDeoptimizationExits`)**:
    - 在此代码片段中为空函数，但其目的是为反优化出口做准备。

15. **增加栈访问计数器 (`IncrementStackAccessCounter`)**:
    - 用于在调试模式下跟踪栈的访问情况。

16. **栈操作辅助函数 (`Push`, `Pop`, `PopTempStackSlots`)**:
    - `Push`: 将数据压入栈中。
    - `Pop`: 从栈中弹出数据。
    - `PopTempStackSlots`: 弹出临时使用的栈空间。

17. **临时数据移动辅助函数 (`MoveToTempLocation`, `MoveTempLocationTo`)**:
    - 用于将数据移动到临时位置（寄存器或栈），避免寄存器冲突。

18. **设置待处理的移动操作 (`SetPendingMove`)**:
    - 用于跟踪待处理的移动操作，以便更好地管理寄存器分配。

19. **生成数据移动指令 (`AssembleMove`)**:
    - 根据源操作数和目标操作数的类型生成不同的 `mov` 指令。
    - 处理寄存器到寄存器、寄存器到内存、内存到寄存器、常量到寄存器、常量到内存等各种情况。
    - 针对 32 位操作数有优化。

**关于问题：**

* **`.tq` 结尾：**  `v8/src/compiler/backend/x64/code-generator-x64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码**，而不是 V8 Torque 源代码。

* **与 JavaScript 的关系：** 这个文件是 V8 编译器后端的一部分，负责将中间表示的指令翻译成目标机器 (x64) 的汇编代码。JavaScript 代码经过 V8 的解析、优化等步骤后，最终会通过这个文件生成可执行的机器码。

   **JavaScript 示例：**

   ```javascript
   function compare(a, b) {
     if (a > b) {
       return 1;
     } else {
       return -1;
     }
   }
   ```

   当 V8 编译 `compare` 函数时，`if (a > b)` 这个条件判断就可能涉及到 `AssembleArchBranch` 函数的调用，根据比较结果生成跳转到 `return 1;` 或 `return -1;` 代码块的指令。

* **代码逻辑推理：**

   **假设输入 `AssembleArchBranch`:**
   - `instr`:  表示一个比较指令，例如比较寄存器 `rax` 和 `rbx`。
   - `branch`:
     - `condition`: `kGreaterThan` (大于)
     - `true_label`: 指向 `return 1;` 代码块的标签。
     - `false_label`: 指向 `return -1;` 代码块的标签。
     - `fallthru`: `false` (不顺序执行)。

   **预期输出的汇编代码 (简化):**
   ```assembly
   cmpq rax, rbx   ; 假设的比较指令
   jg  [true_label地址] ; 如果大于则跳转到 true_label
   jmp [false_label地址] ; 否则跳转到 false_label
   ```

* **用户常见的编程错误：**

   1. **错误的条件判断：**  在 JavaScript 中编写了逻辑错误的条件语句，例如使用了错误的比较运算符，导致 `AssembleArchBranch` 生成了不符合预期的跳转指令。

      ```javascript
      // 错误地使用了 <=，本意是 >
      if (a <= b) {
        // ...
      }
      ```

   2. **栈溢出：** 虽然 `AssembleConstructFrame` 中有栈溢出检查，但如果 JavaScript 代码中存在无限递归或者创建了过多的局部变量，仍然可能导致栈溢出。

      ```javascript
      function recursiveFunction() {
        recursiveFunction(); // 无终止条件的递归
      }
      recursiveFunction();
      ```

   3. **Deoptimization 导致的性能问题：**  如果代码触发了频繁的反优化，可能会导致性能下降。这可能与 V8 的优化假设不符，或者代码中存在一些导致类型不稳定等问题。`AssembleArchDeoptBranch` 生成的反优化分支就是为了处理这些情况。

* **功能归纳 (第 9 部分)：**  作为代码生成器的第 9 部分，这个文件主要负责将编译器的中间表示翻译成具体的 x64 汇编指令，涵盖了程序执行的控制流（分支、跳转、switch）、函数调用的栈帧管理（构建、返回）以及数据的移动操作。它是生成高效机器码的关键环节，连接了高级的中间表示和底层的机器指令。它确保了 JavaScript 代码能够在 x64 架构上正确且尽可能高效地运行。

Prompt: 
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/code-generator-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共10部分，请归纳一下它的功能

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
          __ movl(g.ToRegister(desti
"""


```
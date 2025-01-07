Response:
Let's break down the thought process for analyzing this V8 code generator snippet.

1. **Understanding the Context:** The first crucial step is recognizing the file path: `v8/src/compiler/backend/s390/code-generator-s390.cc`. This tells us several key things:
    * **Language:** It's a `.cc` file, meaning it's C++ code. The prompt also explicitly states it's V8 source.
    * **Component:** It resides in the `compiler/backend` directory, indicating it's part of the code generation pipeline. More specifically, it's in the `s390` subdirectory, which points to code generation for the IBM System/390 architecture.
    * **Purpose:** The filename `code-generator-s390.cc` clearly suggests its main function: generating machine code for the S390 architecture.

2. **Initial Code Scan (High-Level):**  Quickly skim through the code, looking for keywords and structural elements:
    * **`case` statements:** These often indicate a dispatch mechanism based on opcodes or instruction types. The presence of `kS390_...` strongly suggests it's handling specific S390 instructions.
    * **`__` (double underscore):** This is a common convention in V8 for accessing the assembler. It's a strong indicator of code emission. Seeing methods like `__ StoreTaggedField`, `__ DecompressTagged`, `__ b` (branch), `__ mov`, etc., confirms the code generation aspect.
    * **Method names:**  `AssembleArch...`, `FinishFrame`, `AssembleConstructFrame`, `AssembleReturn`, `AssembleMove`, `AssembleSwap`, etc.,  reveal the different stages and tasks involved in code generation.
    * **`Instruction* instr`:** This argument is common in the assembly methods, indicating they operate on a higher-level representation of an instruction.
    * **`BranchInfo* branch`:** Suggests handling of control flow.
    * **`OutOfLineCode`:** Points to handling of less common or complex scenarios, like traps.
    * **WebAssembly (`V8_ENABLE_WEBASSEMBLY`):** Indicates support for WebAssembly compilation.

3. **Dissecting Key Sections:** Focus on the most prominent code blocks:

    * **`AssembleArchInstruction`:**  This is a central dispatch function. The `switch` statement based on `instr->arch_opcode()` is the core logic for translating intermediate representation (IR) instructions to S390 assembly. Analyze some of the `case` blocks to understand what kind of S390 instructions are being handled (e.g., storing lanes of SIMD vectors, storing compressed tagged values, loading and decompressing tagged values).

    * **`AssembleArchBranch`:**  Handles conditional branching based on flags and instruction types. Notice the specific handling of floating-point comparisons (`kS390_CmpFloat`, `kS390_CmpDouble`) and the `bunordered` instruction.

    * **Frame Management (`FinishFrame`, `AssembleConstructFrame`, `AssembleReturn`):**  These methods deal with setting up and tearing down function call frames, saving and restoring registers, and allocating stack space. Pay attention to the handling of callee-saved registers and the potential for stack overflow checks in WebAssembly.

    * **Move and Swap Operations (`AssembleMove`, `AssembleSwap`):** These are fundamental operations. Observe how different data types (registers, stack slots, constants, floating-point values, SIMD vectors) are moved and swapped. Note the use of scratch registers.

4. **Answering the Specific Questions:** Now, address the prompt's requirements systematically:

    * **Functionality:** Based on the dissected sections, summarize the key responsibilities: translating IR to S390 assembly, handling various instructions, managing the call frame, and supporting features like WebAssembly traps.

    * **`.tq` extension:** Explicitly state that the `.cc` extension indicates C++ and not Torque.

    * **Relationship to JavaScript (with examples):**  The key is to connect the low-level operations to higher-level JavaScript concepts. Think about how these assembly instructions are used to implement:
        * Variable assignment (using `AssembleMove`).
        * Object property access (using store/load tagged instructions).
        * Arithmetic operations (although this snippet doesn't show the core arithmetic logic directly, it sets up the framework).
        * Control flow (using `AssembleArchBranch`).

    * **Code Logic Inference (with examples):** Choose a simpler `case` within `AssembleArchInstruction`, like `kS390_StoreCompressTagged`, and provide a concrete input (register and memory location) and describe the expected assembly output.

    * **Common Programming Errors:**  Relate the code generation to potential errors a JavaScript programmer might make. For instance, incorrect type assumptions could lead to issues with tagged value compression/decompression, or memory access errors could relate to how the code generator handles memory operands. Stack overflows are also relevant, especially in the context of `AssembleConstructFrame`.

    * **归纳功能 (Summarize functionality):**  Reiterate the main purpose in concise terms, emphasizing its role in the V8 compilation pipeline for the S390 architecture.

5. **Refinement and Clarity:** Review the answers for accuracy, clarity, and completeness. Ensure the examples are easy to understand and directly illustrate the concepts. Use precise language when describing technical details.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just handles individual instructions."  **Correction:**  Realize it's more than that. It also manages the function call frame, which is essential for correct execution.
* **Initial thought:** "Just list all the `case` statements as features." **Correction:** Group related functionalities (like SIMD operations, tagged value handling, branching) for a more structured explanation.
* **Initial thought:** "The JavaScript examples need to show the exact assembly." **Correction:** Focus on the *concept* the assembly implements rather than trying to reverse-engineer the exact generated code (which can be complex and vary). The goal is to illustrate the *connection* to JavaScript behavior.

By following these steps, you can effectively analyze and explain the functionality of a complex code snippet like this V8 code generator.
这是v8/src/compiler/backend/s390/code-generator-s390.cc的第5部分，也是最后一部分。综合前面四个部分的内容，这个文件的主要功能是 **为 IBM System/390 架构生成机器代码**。 它负责将 TurboFan 编译器生成的中间表示（IR）指令转换为实际的 S390 汇编指令。

**归纳一下它的功能，主要体现在以下几个方面：**

1. **处理各种 S390 特定的指令:**  这部分代码继续处理 `AssembleArchInstruction` 函数中的各种 `case` 分支，这些分支对应着特定的 S390 架构指令。例如：
    * `kS390_S128StoreLane`:  存储 SIMD 寄存器的特定 Lane。
    * `kS390_StoreCompressTagged`: 存储压缩的标记指针。
    * `kS390_LoadDecompressTaggedSigned` 和 `kS390_LoadDecompressTagged`: 加载并解压缩标记指针。

2. **实现分支和跳转:** `AssembleArchBranch` 函数根据指令和条件生成相应的分支指令。它还处理浮点数比较的特殊情况，检查 NaN（unordered）。

3. **处理 Deoptimization 分支:** `AssembleArchDeoptBranch`  处理当优化代码需要回退到未优化代码时的分支。

4. **实现无条件跳转:** `AssembleArchJumpRegardlessOfAssemblyOrder` 生成无条件跳转指令。

5. **支持 WebAssembly Trap:**  `AssembleArchTrap` 函数在 WebAssembly 代码中生成陷阱指令，用于处理错误或异常情况。

6. **生成布尔值:** `AssembleArchBoolean` 函数根据条件码生成表示布尔值的 0 或 1。

7. **实现条件分支和条件布尔值生成:**  虽然 `AssembleArchConditionalBoolean` 和 `AssembleArchConditionalBranch` 中是 `UNREACHABLE()`，但这可能表示在 S390 架构上，这些功能是通过其他方式实现的，或者当前的 IR 不会生成这些类型的指令。

8. **实现 Switch 语句:**
    * `AssembleArchBinarySearchSwitch`:  生成二分查找的 switch 语句代码。
    * `AssembleArchTableSwitch`: 生成基于跳转表的 switch 语句代码。

9. **实现 Select 指令:** `AssembleArchSelect`  目前是 `UNIMPLEMENTED()`，表示 S390 架构的 select 指令尚未实现。

10. **管理函数帧 (Frame):**
    * `FinishFrame`:  在函数帧布局完成后进行最后的处理，例如保存 Callee-saved 寄存器。
    * `AssembleConstructFrame`:  生成构造函数帧的代码，包括分配栈空间、保存寄存器等。
    * `AssembleReturn`: 生成函数返回的代码，包括恢复寄存器、弹出栈空间等。

11. **完成代码生成:** `FinishCode` 在代码生成过程结束时执行清理工作。

12. **处理 Deoptimization 出口:** `PrepareForDeoptimizationExits`  为 Deoptimization 出口做准备。

13. **实现栈操作 (Push 和 Pop):**  `Push` 和 `Pop` 函数分别用于将数据压入和弹出栈。

14. **处理临时栈槽:** `PopTempStackSlots` 用于清理临时使用的栈空间。

15. **实现临时位置的移动:** `MoveToTempLocation` 和 `MoveTempLocationTo`  用于在代码生成过程中将数据移动到临时位置（寄存器或栈上）。

16. **设置待处理的 Move 操作:** `SetPendingMove` 记录待处理的移动操作，用于优化移动指令的生成。

17. **实现 Move 指令:** `AssembleMove`  生成各种类型的 Move 指令，包括寄存器到寄存器、寄存器到内存、常量到寄存器/内存等。它还处理浮点数和 SIMD 向量的移动。

18. **实现 Swap 指令:** `AssembleSwap` 生成交换两个操作数内容的指令，支持寄存器、栈槽以及浮点数和 SIMD 寄存器。

19. **生成跳转表:** `AssembleJumpTable`  生成 switch 语句使用的跳转表。

**关于 .tq 结尾：**

代码注释中已经明确指出，如果文件以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码。由于 `v8/src/compiler/backend/s390/code-generator-s390.cc` 的结尾是 `.cc`，因此它是一个 **C++ 源代码**，而不是 Torque 源代码。

**与 JavaScript 的功能关系及示例：**

这个文件生成的机器代码是 JavaScript 代码在 S390 架构上执行的基础。许多 JavaScript 的操作最终会通过 TurboFan 编译成这里生成的机器码。

例如：

* **变量赋值:**  JavaScript 中的 `let x = 10;`  可能会被编译成使用 `AssembleMove` 将常量 10 移动到代表变量 `x` 的寄存器或栈槽。
* **对象属性访问:**  JavaScript 中的 `obj.property`  可能涉及加载对象的属性，这可能使用到 `kS390_LoadTaggedField` 或类似的指令来加载标记指针。
* **算术运算:**  JavaScript 中的 `a + b`  会生成相应的加法指令，例如 `kS390_Add64`，并使用 `AssembleMove` 将操作数加载到寄存器中，并将结果存储回去。
* **函数调用:**  JavaScript 函数的调用和返回涉及到函数帧的构建和销毁，这部分代码由 `AssembleConstructFrame` 和 `AssembleReturn` 处理。
* **控制流:**  JavaScript 的 `if` 语句和循环会被编译成使用 `AssembleArchBranch` 生成的条件分支指令。

**代码逻辑推理示例：**

**假设输入：**

一个 IR 指令 `instr`，其 `arch_opcode` 为 `kS390_StoreCompressTagged`，输入操作数 `i.InputRegister(0)` 代表要存储的值的寄存器 (例如 `r3`)，内存操作数 `i.MemoryOperand()` 代表要存储的内存地址 (例如 `MemOperand(r2, 8)`)。

**预期输出：**

`AssembleArchInstruction` 函数的 `case kS390_StoreCompressTagged` 分支会被执行，最终会生成 S390 汇编指令来将 `r3` 中的值（假设是一个标记指针）压缩后存储到 `r2 + 8` 的内存地址。具体生成的汇编指令可能类似于：

```assembly
stg r3, 8(r2)  // 假设 StoreTaggedField 最终生成的是 stg 指令
```

（实际生成的指令可能更复杂，涉及到辅助寄存器 `r1`）。

**用户常见的编程错误示例：**

虽然这个文件是编译器内部的代码，但它处理的逻辑与一些常见的 JavaScript 编程错误间接相关：

* **类型错误:** 如果 JavaScript 代码中存在类型不匹配，例如尝试将一个非对象的值当作对象访问属性，编译器可能会生成尝试解压缩标记指针的代码。如果该指针实际上没有被标记，那么在 `kS390_LoadDecompressTagged` 阶段可能会出现问题，尽管这不是用户直接能看到的错误，但它反映了底层对类型处理的需求。
* **栈溢出:**  如果 JavaScript 代码导致过深的函数调用栈，最终会导致 `AssembleConstructFrame` 中分配过多栈空间，超出系统限制，从而发生栈溢出错误。虽然这里的代码尝试进行栈溢出检查，但用户编写的递归过深的函数仍然可能触发。

**总结:**

`v8/src/compiler/backend/s390/code-generator-s390.cc` 是 V8 编译器中至关重要的一个组件，它专注于将高级的中间表示转换为可以在 IBM System/390 架构上运行的底层机器代码。它处理各种指令、管理函数调用栈、并支持 WebAssembly 等特性。尽管用户无法直接操作这些代码，但它却是 JavaScript 代码高效执行的基石。

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/code-generator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/code-generator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能

"""
ore32Lane: {
      STORE_LANE(32, 3 - i.InputUint8(1));
      break;
    }
    case kS390_S128Store64Lane: {
      STORE_LANE(64, 1 - i.InputUint8(1));
      break;
    }
#undef STORE_LANE
    case kS390_StoreCompressTagged: {
      CHECK(!instr->HasOutput());
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode, &index);
      Register value = i.InputRegister(index);
      __ StoreTaggedField(value, operand, r1);
      break;
    }
    case kS390_LoadDecompressTaggedSigned: {
      CHECK(instr->HasOutput());
      __ DecompressTaggedSigned(i.OutputRegister(), i.MemoryOperand());
      break;
    }
    case kS390_LoadDecompressTagged: {
      CHECK(instr->HasOutput());
      __ DecompressTagged(i.OutputRegister(), i.MemoryOperand());
      break;
    }
    default:
      UNREACHABLE();
  }
  return kSuccess;
}

// Assembles branches after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  S390OperandConverter i(this, instr);
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;
  ArchOpcode op = instr->arch_opcode();
  FlagsCondition condition = branch->condition;

  Condition cond = FlagsConditionToCondition(condition, op);
  if (op == kS390_CmpFloat || op == kS390_CmpDouble) {
    // check for unordered if necessary
    // Branching to flabel/tlabel according to what's expected by tests
    if (cond == le || cond == eq || cond == lt) {
      __ bunordered(flabel);
    } else if (cond == gt || cond == ne || cond == ge) {
      __ bunordered(tlabel);
    }
  }
  __ b(cond, tlabel);
  if (!branch->fallthru) __ b(flabel);  // no fallthru to flabel.
}

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ b(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  class OutOfLineTrap final : public OutOfLineCode {
   public:
    OutOfLineTrap(CodeGenerator* gen, Instruction* instr)
        : OutOfLineCode(gen), instr_(instr), gen_(gen) {}

    void Generate() final {
      S390OperandConverter i(gen_, instr_);
      TrapId trap_id =
          static_cast<TrapId>(i.InputInt32(instr_->InputCount() - 1));
      GenerateCallToTrap(trap_id);
    }

   private:
    void GenerateCallToTrap(TrapId trap_id) {
      gen_->AssembleSourcePosition(instr_);
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ Call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
      ReferenceMap* reference_map =
          gen_->zone()->New<ReferenceMap>(gen_->zone());
      gen_->RecordSafepoint(reference_map);
      if (v8_flags.debug_code) {
        __ stop();
      }
    }

    Instruction* instr_;
    CodeGenerator* gen_;
  };
  auto ool = zone()->New<OutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  Label end;

  ArchOpcode op = instr->arch_opcode();
  Condition cond = FlagsConditionToCondition(condition, op);
  if (op == kS390_CmpFloat || op == kS390_CmpDouble) {
    // check for unordered if necessary
    if (cond == le || cond == eq || cond == lt) {
      __ bunordered(&end);
    } else if (cond == gt || cond == ne || cond == ge) {
      __ bunordered(tlabel);
    }
  }
  __ b(cond, tlabel);
  __ bind(&end);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  S390OperandConverter i(this, instr);
  ArchOpcode op = instr->arch_opcode();
  bool check_unordered = (op == kS390_CmpDouble || op == kS390_CmpFloat);

  // Overflow checked for add/sub only.
  DCHECK((condition != kOverflow && condition != kNotOverflow) ||
         (op == kS390_Add32 || op == kS390_Add64 || op == kS390_Sub32 ||
          op == kS390_Sub64 || op == kS390_Mul32 ||
          op == kS390_Mul64WithOverflow));

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Register reg = i.OutputRegister(instr->OutputCount() - 1);
  Condition cond = FlagsConditionToCondition(condition, op);
  Label done;
  if (check_unordered) {
    __ mov(reg, (cond == eq || cond == le || cond == lt) ? Operand::Zero()
                                                         : Operand(1));
    __ bunordered(&done);
  }

  // TODO(john.yan): use load imm high on condition here
  __ mov(reg, Operand::Zero());
  __ mov(kScratchReg, Operand(1));
  // locr is sufficient since reg's upper 32 is guarrantee to be 0
  __ locr(cond, reg, kScratchReg);
  __ bind(&done);
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  S390OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  S390OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  int32_t const case_count = static_cast<int32_t>(instr->InputCount() - 2);
  base::Vector<Label*> cases = zone()->AllocateVector<Label*>(case_count);
  for (int32_t index = 0; index < case_count; ++index) {
    cases[index] = GetLabel(i.InputRpo(index + 2));
  }
  Label* const table = AddJumpTable(cases);
  __ CmpU64(input, Operand(case_count));
  __ bge(GetLabel(i.InputRpo(1)));
  __ larl(kScratchReg, table);
  __ ShiftLeftU64(r1, input, Operand(kSystemPointerSizeLog2));
  __ LoadU64(kScratchReg, MemOperand(kScratchReg, r1));
  __ Jump(kScratchReg);
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  UNIMPLEMENTED();
}

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  const DoubleRegList double_saves = call_descriptor->CalleeSavedFPRegisters();

  // Save callee-saved Double registers.
  if (!double_saves.is_empty()) {
    frame->AlignSavedCalleeRegisterSlots();
    DCHECK_EQ(kNumCalleeSavedDoubles, double_saves.Count());
    frame->AllocateSavedCalleeRegisterSlots(kNumCalleeSavedDoubles *
                                            (kDoubleSize / kSystemPointerSize));
  }
  // Save callee-saved registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    // register save area does not include the fp or constant pool pointer.
    const int num_saves = kNumCalleeSaved - 1;
    frame->AllocateSavedCalleeRegisterSlots(num_saves);
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
        __ lay(sp, MemOperand(sp, -kSystemPointerSize));
#else
      // For balance.
      if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
      } else {
        __ Push(r14, fp);
        __ mov(fp, sp);
      }
    } else if (call_descriptor->IsJSFunctionCall()) {
      __ Prologue(ip);
    } else {
      StackFrame::Type type = info()->GetOutputStackFrameType();
      // TODO(mbrandy): Detect cases where ip is the entrypoint (for
      // efficient initialization of the constant pool pointer register).
      __ StubPrologue(type);
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
        __ lay(sp, MemOperand(sp, -kSystemPointerSize));
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }
    unwinding_info_writer_.MarkFrameConstructed(__ pc_offset());
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

  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();
  const RegList saves = call_descriptor->CalleeSavedRegisters();

  if (required_slots > 0) {
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
        Register stack_limit = r1;
        __ LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
        __ AddS64(stack_limit, stack_limit,
                  Operand(required_slots * kSystemPointerSize));
        __ CmpU64(sp, stack_limit);
        __ bge(&done);
      }

      __ Call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
              RelocInfo::WASM_STUB_CALL);
      // The call does not return, hence we can ignore any references and just
      // define an empty safepoint.
      ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
      RecordSafepoint(reference_map);
      if (v8_flags.debug_code) __ stop();

      __ bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    // Skip callee-saved and return slots, which are pushed below.
    required_slots -= saves.Count();
    required_slots -= frame()->GetReturnSlotCount();
    required_slots -= (kDoubleSize / kSystemPointerSize) * saves_fp.Count();
    __ lay(sp, MemOperand(sp, -required_slots * kSystemPointerSize));
  }

  // Save callee-saved Double registers.
  if (!saves_fp.is_empty()) {
    __ MultiPushDoubles(saves_fp);
    DCHECK_EQ(kNumCalleeSavedDoubles, saves_fp.Count());
  }

  // Save callee-saved registers.
  if (!saves.is_empty()) {
    __ MultiPush(saves);
    // register save area does not include the fp or constant pool pointer.
  }

  const int returns = frame()->GetReturnSlotCount();
  // Create space for returns.
  __ AllocateStackSpace(returns * kSystemPointerSize);

  if (!frame()->tagged_slots().IsEmpty()) {
    __ mov(kScratchReg, Operand(0));
    for (int spill_slot : frame()->tagged_slots()) {
      FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
      DCHECK(offset.from_frame_pointer());
      __ StoreU64(kScratchReg, MemOperand(fp, offset.offset()));
    }
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = frame()->GetReturnSlotCount();
  if (returns != 0) {
    // Create space for returns.
    __ lay(sp, MemOperand(sp, returns * kSystemPointerSize));
  }

  // Restore registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    __ MultiPop(saves);
  }

  // Restore double registers.
  const DoubleRegList double_saves = call_descriptor->CalleeSavedFPRegisters();
  if (!double_saves.is_empty()) {
    __ MultiPopDoubles(double_saves);
  }

  unwinding_info_writer_.MarkBlockWillExit();

  S390OperandConverter g(this, nullptr);
  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ CmpS64(g.ToRegister(additional_pop_count), Operand(0));
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue);
    }
  }

  Register argc_reg = r5;
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
    // Canonicalize JSFunction return sites for now unless they have an variable
    // number of stack slot pops
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ b(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count.
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
      __ LoadU64(argc_reg, MemOperand(fp, StandardFrameConstants::kArgCOffset));
    }
    AssembleDeconstructFrame();
  }

  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver).
    // The number of arguments without the receiver is
    // max(argc_reg, parameter_slots-1), and the receiver is added in
    // DropArguments().
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    if (parameter_slots > 1) {
      Label skip;
      __ CmpS64(argc_reg, Operand(parameter_slots));
      __ bgt(&skip);
      __ mov(argc_reg, Operand(parameter_slots));
      __ bind(&skip);
    }
    __ DropArguments(argc_reg);
  } else if (additional_pop_count->IsImmediate()) {
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    __ Drop(parameter_slots + additional_count);
  } else if (parameter_slots == 0) {
    __ Drop(g.ToRegister(additional_pop_count));
  } else {
    // {additional_pop_count} is guaranteed to be zero if {parameter_slots !=
    // 0}. Check RawMachineAssembler::PopAndReturn.
    __ Drop(parameter_slots);
  }
  __ Ret();
}

void CodeGenerator::FinishCode() {}

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  S390OperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsFloatStackSlot() || source->IsDoubleStackSlot()) {
    __ LoadU64(r1, g.ToMemOperand(source));
    __ Push(r1);
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // Bump the stack pointer and assemble the move.
    __ lay(sp, MemOperand(sp, -(new_slots * kSystemPointerSize)));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  int dropped_slots = ElementSizeInPointers(rep);
  S390OperandConverter g(this, nullptr);
  if (dest->IsFloatStackSlot() || dest->IsDoubleStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Pop(r1);
    __ StoreU64(r1, g.ToMemOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ lay(sp, MemOperand(sp, dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ lay(sp, MemOperand(sp, temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  if (!IsFloatingPoint(rep) ||
      ((IsFloatingPoint(rep) &&
        !move_cycle_.pending_double_scratch_register_use))) {
    // The scratch register for this rep is available.
    int scratch_reg_code =
        !IsFloatingPoint(rep) ? kScratchReg.code() : kScratchDoubleReg.code();
    AllocatedOperand scratch(LocationOperand::REGISTER, rep, scratch_reg_code);
    DCHECK(!AreAliased(kScratchReg, r0, r1));
    AssembleMove(source, &scratch);
  } else {
    // The scratch register is blocked by pending moves. Use the stack instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  if (!IsFloatingPoint(rep) ||
      ((IsFloatingPoint(rep) &&
        !move_cycle_.pending_double_scratch_register_use))) {
    int scratch_reg_code =
        !IsFloatingPoint(rep) ? kScratchReg.code() : kScratchDoubleReg.code();
    AllocatedOperand scratch(LocationOperand::REGISTER, rep, scratch_reg_code);
    DCHECK(!AreAliased(kScratchReg, r0, r1));
    AssembleMove(&scratch, dest);
  } else {
    Pop(dest, rep);
  }
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  if ((move->source().IsConstant() || move->source().IsFPStackSlot()) &&
      !move->destination().IsFPRegister()) {
    move_cycle_.pending_double_scratch_register_use = true;
  }
}

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  S390OperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  // If a move type needs the scratch register, this also needs to be recorded
  // in {SetPendingMove} to avoid conflicts with the gap resolver.
  if (source->IsRegister()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      __ Move(g.ToRegister(destination), src);
    } else {
      __ StoreU64(src, g.ToMemOperand(destination));
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    MemOperand src = g.ToMemOperand(source);
    if (destination->IsRegister()) {
      __ LoadU64(g.ToRegister(destination), src);
    } else {
      Register temp = r1;
      __ LoadU64(temp, src, r0);
      __ StoreU64(temp, g.ToMemOperand(destination));
    }
  } else if (source->IsConstant()) {
    Constant src = g.ToConstant(source);
    if (destination->IsRegister() || destination->IsStackSlot()) {
      Register dst = destination->IsRegister() ? g.ToRegister(destination) : r1;
      switch (src.type()) {
        case Constant::kInt32:
          __ mov(dst, Operand(src.ToInt32(), src.rmode()));
          break;
        case Constant::kInt64:
          __ mov(dst, Operand(src.ToInt64(), src.rmode()));
          break;
        case Constant::kFloat32:
          __ mov(dst, Operand::EmbeddedNumber(src.ToFloat32()));
          break;
        case Constant::kFloat64:
          __ mov(dst, Operand::EmbeddedNumber(src.ToFloat64().value()));
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
          UNREACHABLE();  // TODO(dcarney): loading RPO constants on S390.
      }
      if (destination->IsStackSlot()) {
        __ StoreU64(dst, g.ToMemOperand(destination), r0);
      }
    } else {
      DoubleRegister dst = destination->IsFPRegister()
                               ? g.ToDoubleRegister(destination)
                               : kScratchDoubleReg;
      double value = (src.type() == Constant::kFloat32)
                         ? src.ToFloat32()
                         : src.ToFloat64().value();
      if (src.type() == Constant::kFloat32) {
        __ LoadF32<float>(dst, src.ToFloat32(), r1);
      } else {
        __ LoadF64<double>(dst, value, r1);
      }

      if (destination->IsFloatStackSlot()) {
        __ StoreF32(dst, g.ToMemOperand(destination));
      } else if (destination->IsDoubleStackSlot()) {
        __ StoreF64(dst, g.ToMemOperand(destination));
      }
    }
  } else if (source->IsFPRegister()) {
    MachineRepresentation rep = LocationOperand::cast(source)->representation();
    if (rep == MachineRepresentation::kSimd128) {
      if (destination->IsSimd128Register()) {
        __ vlr(g.ToSimd128Register(destination), g.ToSimd128Register(source),
               Condition(0), Condition(0), Condition(0));
      } else {
        DCHECK(destination->IsSimd128StackSlot());
        __ StoreV128(g.ToSimd128Register(source), g.ToMemOperand(destination),
                     r1);
      }
    } else {
      DoubleRegister src = g.ToDoubleRegister(source);
      if (destination->IsFPRegister()) {
        DoubleRegister dst = g.ToDoubleRegister(destination);
        __ Move(dst, src);
      } else {
        DCHECK(destination->IsFPStackSlot());
        LocationOperand* op = LocationOperand::cast(source);
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ StoreF64(src, g.ToMemOperand(destination));
        } else {
          __ StoreF32(src, g.ToMemOperand(destination));
        }
      }
    }
  } else if (source->IsFPStackSlot()) {
    DCHECK(destination->IsFPRegister() || destination->IsFPStackSlot());
    MemOperand src = g.ToMemOperand(source);
    if (destination->IsFPRegister()) {
      LocationOperand* op = LocationOperand::cast(source);
      if (op->representation() == MachineRepresentation::kFloat64) {
        __ LoadF64(g.ToDoubleRegister(destination), src);
      } else if (op->representation() == MachineRepresentation::kFloat32) {
        __ LoadF32(g.ToDoubleRegister(destination), src);
      } else {
        DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
        __ LoadV128(g.ToSimd128Register(destination), g.ToMemOperand(source),
                    r1);
      }
    } else {
      LocationOperand* op = LocationOperand::cast(source);
      DoubleRegister temp = kScratchDoubleReg;
      if (op->representation() == MachineRepresentation::kFloat64) {
        __ LoadF64(temp, src);
        __ StoreF64(temp, g.ToMemOperand(destination));
      } else if (op->representation() == MachineRepresentation::kFloat32) {
        __ LoadF32(temp, src);
        __ StoreF32(temp, g.ToMemOperand(destination));
      } else {
        DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
        __ LoadV128(kScratchDoubleReg, g.ToMemOperand(source), r1);
        __ StoreV128(kScratchDoubleReg, g.ToMemOperand(destination), r1);
      }
    }
  } else {
    UNREACHABLE();
  }
}

// Swaping contents in source and destination.
// source and destination could be:
//   Register,
//   FloatRegister,
//   DoubleRegister,
//   StackSlot,
//   FloatStackSlot,
//   or DoubleStackSlot
void CodeGenerator::AssembleSwap(InstructionOperand* source,
                                 InstructionOperand* destination) {
  S390OperandConverter g(this, nullptr);
  if (source->IsRegister()) {
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      __ SwapP(src, g.ToRegister(destination), kScratchReg);
    } else {
      DCHECK(destination->IsStackSlot());
      __ SwapP(src, g.ToMemOperand(destination), kScratchReg);
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsStackSlot());
    __ SwapP(g.ToMemOperand(source), g.ToMemOperand(destination), kScratchReg,
             r0);
  } else if (source->IsFloatRegister()) {
    DoubleRegister src = g.ToDoubleRegister(source);
    if (destination->IsFloatRegister()) {
      __ SwapFloat32(src, g.ToDoubleRegister(destination), kScratchDoubleReg);
    } else {
      DCHECK(destination->IsFloatStackSlot());
      __ SwapFloat32(src, g.ToMemOperand(destination), kScratchDoubleReg);
    }
  } else if (source->IsDoubleRegister()) {
    DoubleRegister src = g.ToDoubleRegister(source);
    if (destination->IsDoubleRegister()) {
      __ SwapDouble(src, g.ToDoubleRegister(destination), kScratchDoubleReg);
    } else {
      DCHECK(destination->IsDoubleStackSlot());
      __ SwapDouble(src, g.ToMemOperand(destination), kScratchDoubleReg);
    }
  } else if (source->IsFloatStackSlot()) {
    DCHECK(destination->IsFloatStackSlot());
    __ SwapFloat32(g.ToMemOperand(source), g.ToMemOperand(destination),
                   kScratchDoubleReg);
  } else if (source->IsDoubleStackSlot()) {
    DCHECK(destination->IsDoubleStackSlot());
    __ SwapDouble(g.ToMemOperand(source), g.ToMemOperand(destination),
                  kScratchDoubleReg);
  } else if (source->IsSimd128Register()) {
    Simd128Register src = g.ToSimd128Register(source);
    if (destination->IsSimd128Register()) {
      __ SwapSimd128(src, g.ToSimd128Register(destination), kScratchDoubleReg);
    } else {
      DCHECK(destination->IsSimd128StackSlot());
      __ SwapSimd128(src, g.ToMemOperand(destination), kScratchDoubleReg);
    }
  } else if (source->IsSimd128StackSlot()) {
    DCHECK(destination->IsSimd128StackSlot());
    __ SwapSimd128(g.ToMemOperand(source), g.ToMemOperand(destination),
                   kScratchDoubleReg);
  } else {
    UNREACHABLE();
  }
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
  for (auto target : targets) {
    __ emit_label_addr(target);
  }
}

#undef __

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```
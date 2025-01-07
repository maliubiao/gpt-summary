Response: The user wants a summary of the functionality of the provided C++ code snippet, which is the third part of a larger file. The file seems to be related to code generation for the S390 architecture within the V8 JavaScript engine. I need to go through the code and identify the key actions and operations being performed. I should also identify any connections to JavaScript concepts and illustrate these with JavaScript examples.

Here's a breakdown of the code's functionality:

1. **Memory Operations:** It handles storing and loading data to/from memory, including tagged values (used for representing JavaScript objects and values). It includes specific operations for compressed tagged values and lane-based SIMD stores.
2. **Branching and Control Flow:** It implements conditional and unconditional branches, including branches based on floating-point comparisons and handling of unordered results. It also handles trapping for WebAssembly.
3. **Boolean Materialization:** It generates code to represent boolean results (true/false) as integer values (1/0) in registers.
4. **Switch Statements:** It supports both binary search and table switch implementations for efficient multi-way branching.
5. **Frame Management:** It includes functions for setting up and tearing down stack frames, handling callee-saved registers, and allocating stack space. It also has specific logic for WebAssembly function calls and stack overflow checks.
6. **Return Statements:** It generates code for returning from functions, including handling argument popping and deconstructing stack frames.
7. **Stack Operations (Push/Pop):**  It provides functions for pushing and popping values onto and off the stack.
8. **Moving Data:** It implements logic for moving data between registers, stack slots, and constants, including handling floating-point values and SIMD registers. It also includes a mechanism to manage scratch registers to avoid conflicts during complex move sequences.
9. **Swapping Data:** It provides functionality to swap the contents of two operands, which can be registers, stack slots, or floating-point registers/slots.
10. **Jump Tables:** It generates the actual data for jump tables.

Now, let's consider the relationship to JavaScript. The code generator is responsible for translating JavaScript code into machine code that the S390 processor can execute.

*   **Tagged Values:**  JavaScript uses tagged pointers to represent different types of values. The `StoreCompressTagged`, `LoadDecompressTaggedSigned`, and `LoadDecompressTagged` operations are directly related to how JavaScript values are stored in memory.
*   **Control Flow:**  JavaScript's `if`, `else`, `switch`, and loop constructs are translated into conditional and unconditional branches in the generated machine code.
*   **Function Calls:**  JavaScript function calls involve setting up stack frames, saving registers, and passing arguments. The `AssembleConstructFrame` and `AssembleReturn` functions handle these tasks.
*   **Data Types:** JavaScript has various data types (numbers, strings, objects, etc.). The code generator needs to handle the different representations of these types in memory and registers. The floating-point and SIMD operations are used for JavaScript's Number type and potentially for future SIMD features.
*   **WebAssembly:** The code includes specific logic for WebAssembly, as V8 can execute WebAssembly code. The trap mechanism and specialized function call setup are examples of this.
这个C++源代码文件（`code-generator-s390.cc`的第三部分）是V8 JavaScript引擎中用于将中间代码（IR）转换成S390架构机器码的组件。它包含了实现各种S390指令的汇编逻辑，并处理了与JavaScript执行相关的特定功能。

以下是其主要功能的归纳：

1. **指令汇编:** 实现了各种S390架构的指令的汇编逻辑，例如存储、加载、比较、分支、跳转等。这些指令对应着V8中间表示（IR）中的各种操作。
2. **内存操作:**  处理内存的存储和加载操作，包括对特定大小（例如32位、64位、128位）的数据进行操作，以及处理SIMD指令的lane操作。
3. **Tagged 值处理:**  包含处理JavaScript中Tagged值的特殊指令，例如压缩和解压缩Tagged值，用于高效地存储和加载JavaScript对象和值。
4. **条件分支:**  实现了基于各种条件码（例如相等、不等、大于、小于等）的条件分支指令，这些条件码通常由之前的比较指令设置。它还处理了浮点数比较中可能出现的“无序”情况。
5. **WebAssembly支持:**  包含对WebAssembly陷阱（trap）的处理逻辑，用于在WebAssembly代码执行过程中发生错误时中断执行。
6. **布尔值物化:**  实现了将条件码的值（真或假）物化为寄存器中的整数值（通常是1或0）的操作。
7. **Switch 语句:**  提供了组装二分查找和跳转表两种形式的Switch语句的逻辑，用于优化多路分支。
8. **帧管理:**  实现了函数调用和返回时的帧（stack frame）的创建和销毁，包括保存和恢复寄存器。
9. **函数调用和返回:**  实现了函数返回的逻辑，包括恢复寄存器、调整栈指针以及处理参数的弹出。
10. **数据移动:**  实现了各种数据移动操作，包括在寄存器之间、寄存器和内存之间、以及加载常量到寄存器或内存中。它还处理了浮点数和SIMD寄存器的数据移动。
11. **数据交换:**  实现了交换两个操作数内容的指令，可以交换寄存器、内存位置、浮点寄存器等。
12. **跳转表生成:**  生成跳转表的数据部分，用于实现table switch。
13. **临时位置管理:**  提供了一种机制来使用临时寄存器或栈空间来辅助完成一些复杂的操作，例如数据移动。

**与 JavaScript 功能的关系以及 JavaScript 示例：**

这个代码生成器的核心任务是将 JavaScript 代码转换为机器码，因此它与 JavaScript 的各种功能都有着密切的关系。以下是一些例子：

*   **变量存储和加载:** JavaScript 中的变量需要存储在内存中。`kS390_StoreCompressTagged` 和 `kS390_LoadDecompressTagged` 等指令就用于处理 JavaScript 变量的存储和加载。例如：

    ```javascript
    let x = 10; // 存储数值 10
    let y = x;  // 加载变量 x 的值
    ```

*   **条件语句:** JavaScript 的 `if` 语句会被翻译成条件分支指令。例如：

    ```javascript
    let a = 5;
    if (a > 0) {
      console.log("a is positive");
    }
    ```
    这会用到诸如 `kS390_CmpS64`（比较）和 `b(gt, tlabel)`（大于时跳转）之类的指令。

*   **循环语句:** JavaScript 的 `for` 或 `while` 循环也会用到条件分支和跳转指令。例如：

    ```javascript
    for (let i = 0; i < 5; i++) {
      console.log(i);
    }
    ```
    这会涉及比较 `i` 和 `5`，并在条件满足时跳转回循环开始的代码。

*   **函数调用:** JavaScript 函数的调用需要创建栈帧，保存寄存器。`AssembleConstructFrame` 负责这部分工作。例如：

    ```javascript
    function add(a, b) {
      return a + b;
    }
    let result = add(2, 3);
    ```
    调用 `add` 函数时，会执行帧的创建和参数的传递。

*   **Switch 语句:** JavaScript 的 `switch` 语句可以使用二分查找或跳转表进行优化，这对应于 `AssembleArchBinarySearchSwitch` 和 `AssembleArchTableSwitch` 的功能。例如：

    ```javascript
    let fruit = "apple";
    switch (fruit) {
      case "banana":
        console.log("It's a banana");
        break;
      case "apple":
        console.log("It's an apple");
        break;
      default:
        console.log("It's some other fruit");
    }
    ```

*   **WebAssembly 互操作:** 如果 JavaScript 代码调用 WebAssembly 模块，或者 WebAssembly 调用 JavaScript 函数，那么相关的陷阱处理逻辑可能会被用到。

总而言之，这个代码文件的核心功能是将高级的、平台无关的 JavaScript 代码（或其中间表示）转换为可以在 S390 架构上执行的低级机器指令。它是 V8 引擎将 JavaScript 动态性转化为高效机器码的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/code-generator-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

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
Response: The user wants to understand the functionality of a C++ source code file related to V8's ARM code generator, specifically the third part of the file.

The code snippet focuses on assembling specific ARM instructions for various operations, especially atomic operations, branches, deoptimization, boolean materialization, switches, frame construction, returns, moves, swaps, and jump tables.

To summarize the functionality, I will categorize the operations handled in this part of the code.

For the Javascript part, I will identify operations that directly correspond to Javascript features and provide examples.
这个C++源代码文件（`v8/src/compiler/backend/arm/code-generator-arm.cc`）的第3部分，主要负责将高级中间表示（HIR）的指令转换为底层的ARM汇编代码。它实现了代码生成器的部分功能，专注于以下几个方面：

**1. 原子操作的汇编生成:**

*   针对不同的数据类型（8位、16位、32位，有符号和无符号），生成原子比较交换指令 (`kAtomicCompareExchange...`)。
*   针对不同的数据类型，生成原子二元操作指令 (`kAtomicAdd...`, `kAtomicSub...`, `kAtomicAnd...`, `kAtomicOr...`, `kAtomicXor...`)。
*   生成原子加载/存储一对字 (`kArmWord32AtomicPairLoad`, `kArmWord32AtomicPairStore`) 的指令。
*   生成原子算术和逻辑二元操作一对字 (`kArmWord32AtomicPairAdd`, `kArmWord32AtomicPairSub`, `kArmWord32AtomicPairAnd`, `kArmWord32AtomicPairOr`, `kArmWord32AtomicPairXor`) 的指令。
*   生成原子交换一对字 (`kArmWord32AtomicPairExchange`) 的指令。
*   生成原子比较交换一对字 (`kArmWord32AtomicPairCompareExchange`) 的指令。

**2. 控制流操作的汇编生成:**

*   生成条件分支指令 (`AssembleArchBranch`)。
*   生成去优化分支指令 (`AssembleArchDeoptBranch`)。
*   生成无条件跳转指令 (`AssembleArchJumpRegardlessOfAssemblyOrder`)。
*   生成 WebAssembly trap 指令 (`AssembleArchTrap`)。
*   生成布尔值物化指令 (`AssembleArchBoolean`)，根据条件将寄存器设置为 0 或 1。
*   生成二分查找开关语句的指令 (`AssembleArchBinarySearchSwitch`)。
*   生成跳转表开关语句的指令 (`AssembleArchTableSwitch`)。

**3. 函数调用和返回相关的汇编生成:**

*   完成函数帧的布局 (`FinishFrame`)，包括保存的寄存器等。
*   生成构造函数帧的代码 (`AssembleConstructFrame`)，包括保存返回地址、帧指针，以及为局部变量分配空间。
*   生成函数返回的代码 (`AssembleReturn`)，包括恢复寄存器、调整栈指针和执行 `ret` 指令。

**4. 数据移动操作的汇编生成:**

*   生成各种数据移动指令 (`AssembleMove`)，包括寄存器到寄存器、寄存器到栈、栈到寄存器、栈到栈、常量到寄存器、常量到栈等不同类型的移动。
*   实现栈的 `push` 和 `pop` 操作。
*   处理临时变量的移动 (`MoveToTempLocation`, `MoveTempLocationTo`)，用于解决复杂的寄存器分配场景。
*   设置待处理的移动操作 (`SetPendingMove`)，用于优化移动指令的生成。
*   生成数据交换指令 (`AssembleSwap`)，用于交换寄存器或内存中的值。

**5. 其他:**

*   生成跳转表 (`AssembleJumpTable`) (但代码中指出在 32 位 ARM 上会内联，因此这里实际上是 UNREACHABLE)。
*   在代码生成结束时执行必要的清理工作 (`FinishCode`)。
*   为去优化出口准备工作 (`PrepareForDeoptimizationExits`)。

**与 JavaScript 的关系和示例:**

这段代码是 V8 引擎将 JavaScript 代码编译成机器码的关键部分。  当 JavaScript 代码执行到需要进行原子操作、条件判断、函数调用、数据赋值等操作时，V8 的编译器会生成相应的中间表示指令，然后由 `code-generator-arm.cc` 中的代码将其转换为实际的 ARM 汇编指令。

**JavaScript 原子操作示例:**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
const arr = new Int32Array(sab);

Atomics.add(arr, 0, 5); // 对应 kAtomicAddWord32
Atomics.compareExchange(arr, 1, 0, 10); // 对应 kAtomicCompareExchangeWord32
```

**JavaScript 控制流示例:**

```javascript
let x = 10;
if (x > 5) { // 对应 AssembleArchBranch (根据比较结果生成条件分支)
  console.log("x is greater than 5");
}

function myFunction(a, b) { // 对应 AssembleConstructFrame (创建函数帧) 和 AssembleReturn (函数返回)
  return a + b;
}

switch (x) { // 对应 AssembleArchTableSwitch 或 AssembleArchBinarySearchSwitch (生成跳转表或二分查找分支)
  case 1:
    console.log("x is 1");
    break;
  case 10:
    console.log("x is 10");
    break;
  default:
    console.log("x is something else");
}
```

**JavaScript 数据移动示例:**

```javascript
let a = 5; // 对应 AssembleMove (将常量 5 移动到变量 a 对应的内存或寄存器)
let b = a; // 对应 AssembleMove (将变量 a 的值移动到变量 b 对应的内存或寄存器)

function swap(arr, i, j) { // 对应 AssembleSwap (交换数组元素)
  [arr[i], arr[j]] = [arr[j], arr[i]];
}
```

总而言之， `code-generator-arm.cc` 的这一部分是 V8 引擎将 JavaScript 的高级语义转换为底层 ARM 机器指令的关键桥梁，它直接影响着 JavaScript 代码在 ARM 架构上的执行效率和正确性。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm/code-generator-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
changeUint16:
      __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));
      __ uxth(i.TempRegister(2), i.InputRegister(2));
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(ldrexh, strexh,
                                               i.TempRegister(2));
      break;
    case kAtomicCompareExchangeWord32:
      __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(ldrex, strex,
                                               i.InputRegister(2));
      break;
#define ATOMIC_BINOP_CASE(op, inst)                    \
  case kAtomic##op##Int8:                              \
    ASSEMBLE_ATOMIC_BINOP(ldrexb, strexb, inst);       \
    __ sxtb(i.OutputRegister(0), i.OutputRegister(0)); \
    break;                                             \
  case kAtomic##op##Uint8:                             \
    ASSEMBLE_ATOMIC_BINOP(ldrexb, strexb, inst);       \
    break;                                             \
  case kAtomic##op##Int16:                             \
    ASSEMBLE_ATOMIC_BINOP(ldrexh, strexh, inst);       \
    __ sxth(i.OutputRegister(0), i.OutputRegister(0)); \
    break;                                             \
  case kAtomic##op##Uint16:                            \
    ASSEMBLE_ATOMIC_BINOP(ldrexh, strexh, inst);       \
    break;                                             \
  case kAtomic##op##Word32:                            \
    ASSEMBLE_ATOMIC_BINOP(ldrex, strex, inst);         \
    break;
      ATOMIC_BINOP_CASE(Add, add)
      ATOMIC_BINOP_CASE(Sub, sub)
      ATOMIC_BINOP_CASE(And, and_)
      ATOMIC_BINOP_CASE(Or, orr)
      ATOMIC_BINOP_CASE(Xor, eor)
#undef ATOMIC_BINOP_CASE
    case kArmWord32AtomicPairLoad: {
      if (instr->OutputCount() == 2) {
        DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r0, r1));
        __ add(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
        __ ldrexd(r0, r1, i.TempRegister(0));
        __ dmb(ISH);
      } else {
        // A special case of this instruction: even though this is a pair load,
        // we only need one of the two words. We emit a normal atomic load.
        DCHECK_EQ(instr->OutputCount(), 1);
        Register base = i.InputRegister(0);
        Register offset = i.InputRegister(1);
        DCHECK(instr->InputAt(2)->IsImmediate());
        int32_t offset_imm = i.InputInt32(2);
        if (offset_imm != 0) {
          Register temp = i.TempRegister(0);
          __ add(temp, offset, Operand(offset_imm));
          offset = temp;
        }
        __ ldr(i.OutputRegister(), MemOperand(base, offset));
        __ dmb(ISH);
      }
      break;
    }
    case kArmWord32AtomicPairStore: {
      Label store;
      Register base = i.InputRegister(0);
      Register offset = i.InputRegister(1);
      Register value_low = i.InputRegister(2);
      Register value_high = i.InputRegister(3);
      Register actual_addr = i.TempRegister(0);
      // The {ldrexd} instruction needs two temp registers. We do not need the
      // result of {ldrexd}, but {strexd} likely fails without the {ldrexd}.
      Register tmp1 = i.TempRegister(1);
      Register tmp2 = i.TempRegister(2);
      // Reuse one of the temp registers for the result of {strexd}.
      Register store_result = tmp1;
      __ add(actual_addr, base, offset);
      __ dmb(ISH);
      __ bind(&store);
      // Add this {ldrexd} instruction here so that {strexd} below can succeed.
      // We don't need the result of {ldrexd} itself.
      __ ldrexd(tmp1, tmp2, actual_addr);
      __ strexd(store_result, value_low, value_high, actual_addr);
      __ cmp(store_result, Operand(0));
      __ b(ne, &store);
      __ dmb(ISH);
      break;
    }
#define ATOMIC_ARITH_BINOP_CASE(op, instr1, instr2)           \
  case kArmWord32AtomicPair##op: {                            \
    DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r2, r3)); \
    ASSEMBLE_ATOMIC64_ARITH_BINOP(instr1, instr2);            \
    break;                                                    \
  }
      ATOMIC_ARITH_BINOP_CASE(Add, add, adc)
      ATOMIC_ARITH_BINOP_CASE(Sub, sub, sbc)
#undef ATOMIC_ARITH_BINOP_CASE
#define ATOMIC_LOGIC_BINOP_CASE(op, instr1)                   \
  case kArmWord32AtomicPair##op: {                            \
    DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r2, r3)); \
    ASSEMBLE_ATOMIC64_LOGIC_BINOP(instr1);                    \
    break;                                                    \
  }
      ATOMIC_LOGIC_BINOP_CASE(And, and_)
      ATOMIC_LOGIC_BINOP_CASE(Or, orr)
      ATOMIC_LOGIC_BINOP_CASE(Xor, eor)
#undef ATOMIC_LOGIC_BINOP_CASE
    case kArmWord32AtomicPairExchange: {
      DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r6, r7));
      Label exchange;
      __ add(i.TempRegister(0), i.InputRegister(2), i.InputRegister(3));
      __ dmb(ISH);
      __ bind(&exchange);
      __ ldrexd(r6, r7, i.TempRegister(0));
      __ strexd(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1),
                i.TempRegister(0));
      __ teq(i.TempRegister(1), Operand(0));
      __ b(ne, &exchange);
      __ dmb(ISH);
      break;
    }
    case kArmWord32AtomicPairCompareExchange: {
      DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r2, r3));
      __ add(i.TempRegister(0), i.InputRegister(4), i.InputRegister(5));
      Label compareExchange;
      Label exit;
      __ dmb(ISH);
      __ bind(&compareExchange);
      __ ldrexd(r2, r3, i.TempRegister(0));
      __ teq(i.InputRegister(0), Operand(r2));
      __ b(ne, &exit);
      __ teq(i.InputRegister(1), Operand(r3));
      __ b(ne, &exit);
      __ strexd(i.TempRegister(1), i.InputRegister(2), i.InputRegister(3),
                i.TempRegister(0));
      __ teq(i.TempRegister(1), Operand(0));
      __ b(ne, &compareExchange);
      __ bind(&exit);
      __ dmb(ISH);
      break;
    }
#undef ASSEMBLE_ATOMIC_LOAD_INTEGER
#undef ASSEMBLE_ATOMIC_STORE_INTEGER
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC64_ARITH_BINOP
#undef ASSEMBLE_ATOMIC64_LOGIC_BINOP
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP
#undef ASSEMBLE_NEON_NARROWING_OP
#undef ASSEMBLE_SIMD_SHIFT_LEFT
#undef ASSEMBLE_SIMD_SHIFT_RIGHT
  }
  return kSuccess;
}

// Assembles branches after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  ArmOperandConverter i(this, instr);
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;
  Condition cc = FlagsConditionToCondition(branch->condition);
  __ b(cc, tlabel);
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
      ArmOperandConverter i(gen_, instr_);
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
  Condition cc = FlagsConditionToCondition(condition);
  __ b(cc, tlabel);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  ArmOperandConverter i(this, instr);

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Register reg = i.OutputRegister(instr->OutputCount() - 1);
  Condition cc = FlagsConditionToCondition(condition);
  __ mov(reg, Operand(0));
  __ mov(reg, Operand(1), LeaveCC, cc);
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  ArmOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  ArmOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  size_t const case_count = instr->InputCount() - 2;
  // This {cmp} might still emit a constant pool entry.
  __ cmp(input, Operand(case_count));
  // Ensure to emit the constant pool first if necessary.
  __ CheckConstPool(true, true);
  __ BlockConstPoolFor(case_count + 2);
  __ add(pc, pc, Operand(input, LSL, 2), LeaveCC, lo);
  __ b(GetLabel(i.InputRpo(1)));
  for (size_t index = 0; index < case_count; ++index) {
    __ b(GetLabel(i.InputRpo(index + 2)));
  }
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  UNIMPLEMENTED();
}

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fp.is_empty()) {
    frame->AlignSavedCalleeRegisterSlots();
  }

  if (!saves_fp.is_empty()) {
    // Save callee-saved FP registers.
    static_assert(DwVfpRegister::kNumRegisters == 32);
    uint32_t last = base::bits::CountLeadingZeros32(saves_fp.bits()) - 1;
    uint32_t first = base::bits::CountTrailingZeros32(saves_fp.bits());
    DCHECK_EQ((last - first + 1), saves_fp.Count());
    frame->AllocateSavedCalleeRegisterSlots((last - first + 1) *
                                            (kDoubleSize / kSystemPointerSize));
  }
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    // Save callee-saved registers.
    frame->AllocateSavedCalleeRegisterSlots(saves.Count());
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
        __ AllocateStackSpace(kSystemPointerSize);
#else
      // For balance.
      if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
      } else {
        __ Push(lr, fp);
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
        __ AllocateStackSpace(kSystemPointerSize);
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
        UseScratchRegisterScope temps(masm());
        Register stack_limit = temps.Acquire();
        __ LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
        __ add(stack_limit, stack_limit,
               Operand(required_slots * kSystemPointerSize));
        __ cmp(sp, stack_limit);
        __ b(cs, &done);
      }

      if (v8_flags.experimental_wasm_growable_stacks) {
        RegList regs_to_save;
        regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
        regs_to_save.set(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister());
        for (auto reg : wasm::kGpParamRegisters) regs_to_save.set(reg);
        __ stm(db_w, sp, regs_to_save);
        __ mov(WasmHandleStackOverflowDescriptor::GapRegister(),
               Operand(required_slots * kSystemPointerSize));
        __ add(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister(), fp,
            Operand(call_descriptor->ParameterSlotCount() * kSystemPointerSize +
                    CommonFrameConstants::kFixedFrameSizeAboveFp));
        __ CallBuiltin(Builtin::kWasmHandleStackOverflow);
        __ ldm(ia_w, sp, regs_to_save);
      } else {
        __ Call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
                RelocInfo::WASM_STUB_CALL);
        // The call does not return, hence we can ignore any references and just
        // define an empty safepoint.
        ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
        RecordSafepoint(reference_map);
        if (v8_flags.debug_code) __ stop();
      }

      __ bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    // Skip callee-saved and return slots, which are pushed below.
    required_slots -= saves.Count();
    required_slots -= frame()->GetReturnSlotCount();
    required_slots -= 2 * saves_fp.Count();
    if (required_slots > 0) {
      __ AllocateStackSpace(required_slots * kSystemPointerSize);
    }
  }

  if (!saves_fp.is_empty()) {
    // Save callee-saved FP registers.
    static_assert(DwVfpRegister::kNumRegisters == 32);
    __ vstm(db_w, sp, saves_fp.first(), saves_fp.last());
  }

  if (!saves.is_empty()) {
    // Save callee-saved registers.
    __ stm(db_w, sp, saves);
  }

  const int returns = frame()->GetReturnSlotCount();
  // Create space for returns.
  __ AllocateStackSpace(returns * kSystemPointerSize);

  if (!frame()->tagged_slots().IsEmpty()) {
    UseScratchRegisterScope temps(masm());
    Register zero = temps.Acquire();
    __ mov(zero, Operand(0));
    for (int spill_slot : frame()->tagged_slots()) {
      FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
      DCHECK(offset.from_frame_pointer());
      __ str(zero, MemOperand(fp, offset.offset()));
    }
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = frame()->GetReturnSlotCount();
  if (returns != 0) {
    // Free space of returns.
    __ add(sp, sp, Operand(returns * kSystemPointerSize));
  }

  // Restore registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    __ ldm(ia_w, sp, saves);
  }

  // Restore FP registers.
  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fp.is_empty()) {
    static_assert(DwVfpRegister::kNumRegisters == 32);
    __ vldm(ia_w, sp, saves_fp.first(), saves_fp.last());
  }

  unwinding_info_writer_.MarkBlockWillExit();

  ArmOperandConverter g(this, nullptr);
  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());

  // {additional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ cmp(g.ToRegister(additional_pop_count), Operand(0));
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue);
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  if (call_descriptor->IsWasmFunctionCall() &&
      v8_flags.experimental_wasm_growable_stacks) {
    {
      UseScratchRegisterScope temps{masm()};
      Register scratch = temps.Acquire();
      __ ldr(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
      __ cmp(scratch,
             Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
    }
    Label done;
    __ b(&done, ne);
    RegList regs_to_save;
    for (auto reg : wasm::kGpReturnRegisters) regs_to_save.set(reg);
    __ stm(db_w, sp, regs_to_save);
    __ Move(kCArgRegs[0], ExternalReference::isolate_address());
    __ PrepareCallCFunction(1);
    __ CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
    // Restore old FP. We don't need to restore old SP explicitly, because
    // it will be restored from FP in LeaveFrame before return.
    __ mov(fp, kReturnRegister0);
    __ ldm(ia_w, sp, regs_to_save);
    __ bind(&done);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  Register argc_reg = r3;
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
    // number of stack slot pops.
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
      __ ldr(argc_reg, MemOperand(fp, StandardFrameConstants::kArgCOffset));
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
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
      __ cmp(argc_reg, Operand(parameter_slots));
      __ mov(argc_reg, Operand(parameter_slots), LeaveCC, lt);
    }
    __ DropArguments(argc_reg);
  } else if (additional_pop_count->IsImmediate()) {
    DCHECK_EQ(Constant::kInt32, g.ToConstant(additional_pop_count).type());
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

void CodeGenerator::FinishCode() { __ CheckConstPool(true, false); }

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {
  __ CheckConstPool(true, false);
}

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  ArmOperandConverter g(this, nullptr);
  // Helper function to write the given constant to the dst register.
  auto MoveConstantToRegister = [&](Register dst, Constant src) {
    if (src.type() == Constant::kHeapObject) {
      Handle<HeapObject> src_object = src.ToHeapObject();
      RootIndex index;
      if (IsMaterializableFromRoot(src_object, &index)) {
        __ LoadRoot(dst, index);
      } else {
        __ Move(dst, src_object);
      }
    } else if (src.type() == Constant::kExternalReference) {
      __ Move(dst, src.ToExternalReference());
    } else {
      __ mov(dst, g.ToImmediate(source));
    }
  };
  switch (MoveType::InferMove(source, destination)) {
    case MoveType::kRegisterToRegister:
      if (source->IsRegister()) {
        __ mov(g.ToRegister(destination), g.ToRegister(source));
      } else if (source->IsFloatRegister()) {
        DCHECK(destination->IsFloatRegister());
        // GapResolver may give us reg codes that don't map to actual
        // s-registers. Generate code to work around those cases.
        int src_code = LocationOperand::cast(source)->register_code();
        int dst_code = LocationOperand::cast(destination)->register_code();
        __ VmovExtended(dst_code, src_code);
      } else if (source->IsDoubleRegister()) {
        __ Move(g.ToDoubleRegister(destination), g.ToDoubleRegister(source));
      } else {
        __ Move(g.ToSimd128Register(destination), g.ToSimd128Register(source));
      }
      return;
    case MoveType::kRegisterToStack: {
      MemOperand dst = g.ToMemOperand(destination);
      if (source->IsRegister()) {
        __ str(g.ToRegister(source), dst);
      } else if (source->IsFloatRegister()) {
        // GapResolver may give us reg codes that don't map to actual
        // s-registers. Generate code to work around those cases.
        int src_code = LocationOperand::cast(source)->register_code();
        __ VmovExtended(dst, src_code);
      } else if (source->IsDoubleRegister()) {
        __ vstr(g.ToDoubleRegister(source), dst);
      } else {
        UseScratchRegisterScope temps(masm());
        Register temp = temps.Acquire();
        QwNeonRegister src = g.ToSimd128Register(source);
        __ add(temp, dst.rn(), Operand(dst.offset()));
        __ vst1(Neon8, NeonListOperand(src.low(), 2), NeonMemOperand(temp));
      }
      return;
    }
    case MoveType::kStackToRegister: {
      MemOperand src = g.ToMemOperand(source);
      if (source->IsStackSlot()) {
        __ ldr(g.ToRegister(destination), src);
      } else if (source->IsFloatStackSlot()) {
        DCHECK(destination->IsFloatRegister());
        // GapResolver may give us reg codes that don't map to actual
        // s-registers. Generate code to work around those cases.
        int dst_code = LocationOperand::cast(destination)->register_code();
        __ VmovExtended(dst_code, src);
      } else if (source->IsDoubleStackSlot()) {
        __ vldr(g.ToDoubleRegister(destination), src);
      } else {
        UseScratchRegisterScope temps(masm());
        Register temp = temps.Acquire();
        QwNeonRegister dst = g.ToSimd128Register(destination);
        __ add(temp, src.rn(), Operand(src.offset()));
        __ vld1(Neon8, NeonListOperand(dst.low(), 2), NeonMemOperand(temp));
      }
      return;
    }
    case MoveType::kStackToStack: {
      MemOperand src = g.ToMemOperand(source);
      MemOperand dst = g.ToMemOperand(destination);
      UseScratchRegisterScope temps(masm());
      if (source->IsStackSlot() || source->IsFloatStackSlot()) {
        SwVfpRegister temp = temps.AcquireS();
        __ vldr(temp, src);
        __ vstr(temp, dst);
      } else if (source->IsDoubleStackSlot()) {
        DwVfpRegister temp = temps.AcquireD();
        __ vldr(temp, src);
        __ vstr(temp, dst);
      } else {
        DCHECK(source->IsSimd128StackSlot());
        Register temp = temps.Acquire();
        QwNeonRegister temp_q = temps.AcquireQ();
        __ add(temp, src.rn(), Operand(src.offset()));
        __ vld1(Neon8, NeonListOperand(temp_q.low(), 2), NeonMemOperand(temp));
        __ add(temp, dst.rn(), Operand(dst.offset()));
        __ vst1(Neon8, NeonListOperand(temp_q.low(), 2), NeonMemOperand(temp));
      }
      return;
    }
    case MoveType::kConstantToRegister: {
      Constant src = g.ToConstant(source);
      if (destination->IsRegister()) {
        MoveConstantToRegister(g.ToRegister(destination), src);
      } else if (destination->IsFloatRegister()) {
        __ vmov(g.ToFloatRegister(destination),
                Float32::FromBits(src.ToFloat32AsInt()));
      } else {
        // TODO(arm): Look into optimizing this further if possible. Supporting
        // the NEON version of VMOV may help.
        __ vmov(g.ToDoubleRegister(destination), src.ToFloat64());
      }
      return;
    }
    case MoveType::kConstantToStack: {
      Constant src = g.ToConstant(source);
      MemOperand dst = g.ToMemOperand(destination);
      if (destination->IsStackSlot()) {
        UseScratchRegisterScope temps(masm());
        // Acquire a S register instead of a general purpose register in case
        // `vstr` needs one to compute the address of `dst`.
        SwVfpRegister s_temp = temps.AcquireS();
        {
          // TODO(arm): This sequence could be optimized further if necessary by
          // writing the constant directly into `s_temp`.
          UseScratchRegisterScope temps(masm());
          Register temp = temps.Acquire();
          MoveConstantToRegister(temp, src);
          __ vmov(s_temp, temp);
        }
        __ vstr(s_temp, dst);
      } else if (destination->IsFloatStackSlot()) {
        UseScratchRegisterScope temps(masm());
        SwVfpRegister temp = temps.AcquireS();
        __ vmov(temp, Float32::FromBits(src.ToFloat32AsInt()));
        __ vstr(temp, dst);
      } else {
        DCHECK(destination->IsDoubleStackSlot());
        UseScratchRegisterScope temps(masm());
        DwVfpRegister temp = temps.AcquireD();
        // TODO(arm): Look into optimizing this further if possible. Supporting
        // the NEON version of VMOV may help.
        __ vmov(temp, src.ToFloat64());
        __ vstr(temp, g.ToMemOperand(destination));
      }
      return;
    }
  }
  UNREACHABLE();
}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  ArmOperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ push(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ ldr(scratch, g.ToMemOperand(source));
    __ push(scratch);
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ sub(sp, sp, Operand(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  int dropped_slots = ElementSizeInPointers(rep);
  ArmOperandConverter g(this, nullptr);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ pop(g.ToRegister(dest));
  } else if (dest->IsStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ pop(scratch);
    __ str(scratch, g.ToMemOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ add(sp, sp, Operand(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ add(sp, sp, Operand(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  move_cycle_.temps.emplace(masm());
  auto& temps = *move_cycle_.temps;
  // Temporarily exclude the reserved scratch registers while we pick a
  // location to resolve the cycle. Re-include them immediately afterwards so
  // that they are available to assemble the move.
  temps.Exclude(move_cycle_.scratch_v_reglist);
  int reg_code = -1;
  if ((!IsFloatingPoint(rep) || rep == MachineRepresentation::kFloat32) &&
      temps.CanAcquireS()) {
    reg_code = temps.AcquireS().code();
  } else if (rep == MachineRepresentation::kFloat64 && temps.CanAcquireD()) {
    reg_code = temps.AcquireD().code();
  } else if (rep == MachineRepresentation::kSimd128 && temps.CanAcquireQ()) {
    reg_code = temps.AcquireQ().code();
  }
  temps.Include(move_cycle_.scratch_v_reglist);
  if (reg_code != -1) {
    // A scratch register is available for this rep.
    move_cycle_.scratch_reg_code = reg_code;
    if (IsFloatingPoint(rep)) {
      AllocatedOperand scratch(LocationOperand::REGISTER, rep, reg_code);
      AssembleMove(source, &scratch);
    } else {
      AllocatedOperand scratch(LocationOperand::REGISTER,
                               MachineRepresentation::kFloat32, reg_code);
      ArmOperandConverter g(this, nullptr);
      if (source->IsStackSlot()) {
        __ vldr(g.ToFloatRegister(&scratch), g.ToMemOperand(source));
      } else {
        DCHECK(source->IsRegister());
        __ vmov(g.ToFloatRegister(&scratch), g.ToRegister(source));
      }
    }
  } else {
    // The scratch registers are blocked by pending moves. Use the stack
    // instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  int scratch_reg_code = move_cycle_.scratch_reg_code;
  DCHECK(move_cycle_.temps.has_value());
  if (scratch_reg_code != -1) {
    if (IsFloatingPoint(rep)) {
      AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                               scratch_reg_code);
      AssembleMove(&scratch, dest);
    } else {
      AllocatedOperand scratch(LocationOperand::REGISTER,
                               MachineRepresentation::kFloat32,
                               scratch_reg_code);
      ArmOperandConverter g(this, nullptr);
      if (dest->IsStackSlot()) {
        __ vstr(g.ToFloatRegister(&scratch), g.ToMemOperand(dest));
      } else {
        DCHECK(dest->IsRegister());
        __ vmov(g.ToRegister(dest), g.ToFloatRegister(&scratch));
      }
    }
  } else {
    Pop(dest, rep);
  }
  // Restore the default state to release the {UseScratchRegisterScope} and to
  // prepare for the next cycle.
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  InstructionOperand& source = move->source();
  InstructionOperand& destination = move->destination();
  MoveType::Type move_type =
      MoveType::InferMove(&move->source(), &move->destination());
  UseScratchRegisterScope temps(masm());
  if (move_type == MoveType::kStackToStack) {
    if (source.IsStackSlot() || source.IsFloatStackSlot()) {
      SwVfpRegister temp = temps.AcquireS();
      move_cycle_.scratch_v_reglist |= temp.ToVfpRegList();
    } else if (source.IsDoubleStackSlot()) {
      DwVfpRegister temp = temps.AcquireD();
      move_cycle_.scratch_v_reglist |= temp.ToVfpRegList();
    } else {
      QwNeonRegister temp = temps.AcquireQ();
      move_cycle_.scratch_v_reglist |= temp.ToVfpRegList();
    }
    return;
  } else if (move_type == MoveType::kConstantToStack) {
    if (destination.IsStackSlot()) {
      // Acquire a S register instead of a general purpose register in case
      // `vstr` needs one to compute the address of `dst`.
      SwVfpRegister s_temp = temps.AcquireS();
      move_cycle_.scratch_v_reglist |= s_temp.ToVfpRegList();
    } else if (destination.IsFloatStackSlot()) {
      SwVfpRegister temp = temps.AcquireS();
      move_cycle_.scratch_v_reglist |= temp.ToVfpRegList();
    } else {
      DwVfpRegister temp = temps.AcquireD();
      move_cycle_.scratch_v_reglist |= temp.ToVfpRegList();
    }
  }
}

void CodeGenerator::AssembleSwap(InstructionOperand* source,
                                 InstructionOperand* destination) {
  ArmOperandConverter g(this, nullptr);
  switch (MoveType::InferSwap(source, destination)) {
    case MoveType::kRegisterToRegister:
      if (source->IsRegister()) {
        __ Swap(g.ToRegister(source), g.ToRegister(destination));
      } else if (source->IsFloatRegister()) {
        DCHECK(destination->IsFloatRegister());
        // GapResolver may give us reg codes that don't map to actual
        // s-registers. Generate code to work around those cases.
        UseScratchRegisterScope temps(masm());
        LowDwVfpRegister temp = temps.AcquireLowD();
        int src_code = LocationOperand::cast(source)->register_code();
        int dst_code = LocationOperand::cast(destination)->register_code();
        __ VmovExtended(temp.low().code(), src_code);
        __ VmovExtended(src_code, dst_code);
        __ VmovExtended(dst_code, temp.low().code());
      } else if (source->IsDoubleRegister()) {
        __ Swap(g.ToDoubleRegister(source), g.ToDoubleRegister(destination));
      } else {
        __ Swap(g.ToSimd128Register(source), g.ToSimd128Register(destination));
      }
      return;
    case MoveType::kRegisterToStack: {
      MemOperand dst = g.ToMemOperand(destination);
      if (source->IsRegister()) {
        Register src = g.ToRegister(source);
        UseScratchRegisterScope temps(masm());
        SwVfpRegister temp = temps.AcquireS();
        __ vmov(temp, src);
        __ ldr(src, dst);
        __ vstr(temp, dst);
      } else if (source->IsFloatRegister()) {
        int src_code = LocationOperand::cast(source)->register_code();
        UseScratchRegisterScope temps(masm());
        LowDwVfpRegister temp = temps.AcquireLowD();
        __ VmovExtended(temp.low().code(), src_code);
        __ VmovExtended(src_code, dst);
        __ vstr(temp.low(), dst);
      } else if (source->IsDoubleRegister()) {
        UseScratchRegisterScope temps(masm());
        DwVfpRegister temp = temps.AcquireD();
        DwVfpRegister src = g.ToDoubleRegister(source);
        __ Move(temp, src);
        __ vldr(src, dst);
        __ vstr(temp, dst);
      } else {
        QwNeonRegister src = g.ToSimd128Register(source);
        UseScratchRegisterScope temps(masm());
        Register temp = temps.Acquire();
        QwNeonRegister temp_q = temps.AcquireQ();
        __ Move(temp_q, src);
        __ add(temp, dst.rn(), Operand(dst.offset()));
        __ vld1(Neon8, NeonListOperand(src.low(), 2), NeonMemOperand(temp));
        __ vst1(Neon8, NeonListOperand(temp_q.low(), 2), NeonMemOperand(temp));
      }
      return;
    }
    case MoveType::kStackToStack: {
      MemOperand src = g.ToMemOperand(source);
      MemOperand dst = g.ToMemOperand(destination);
      if (source->IsStackSlot() || source->IsFloatStackSlot()) {
        UseScratchRegisterScope temps(masm());
        SwVfpRegister temp_0 = temps.AcquireS();
        SwVfpRegister temp_1 = temps.AcquireS();
        __ vldr(temp_0, dst);
        __ vldr(temp_1, src);
        __ vstr(temp_0, src);
        __ vstr(temp_1, dst);
      } else if (source->IsDoubleStackSlot()) {
        UseScratchRegisterScope temps(masm());
        LowDwVfpRegister temp = temps.AcquireLowD();
        if (temps.CanAcquireD()) {
          DwVfpRegister temp_0 = temp;
          DwVfpRegister temp_1 = temps.AcquireD();
          __ vldr(temp_0, dst);
          __ vldr(temp_1, src);
          __ vstr(temp_0, src);
          __ vstr(temp_1, dst);
        } else {
          // We only have a single D register available. However, we can split
          // it into 2 S registers and swap the slots 32 bits at a time.
          MemOperand src0 = src;
          MemOperand dst0 = dst;
          MemOperand src1(src.rn(), src.offset() + kFloatSize);
          MemOperand dst1(dst.rn(), dst.offset() + kFloatSize);
          SwVfpRegister temp_0 = temp.low();
          SwVfpRegister temp_1 = temp.high();
          __ vldr(temp_0, dst0);
          __ vldr(temp_1, src0);
          __ vstr(temp_0, src0);
          __ vstr(temp_1, dst0);
          __ vldr(temp_0, dst1);
          __ vldr(temp_1, src1);
          __ vstr(temp_0, src1);
          __ vstr(temp_1, dst1);
        }
      } else {
        DCHECK(source->IsSimd128StackSlot());
        MemOperand src0 = src;
        MemOperand dst0 = dst;
        MemOperand src1(src.rn(), src.offset() + kDoubleSize);
        MemOperand dst1(dst.rn(), dst.offset() + kDoubleSize);
        UseScratchRegisterScope temps(masm());
        DwVfpRegister temp_0 = temps.AcquireD();
        DwVfpRegister temp_1 = temps.AcquireD();
        __ vldr(temp_0, dst0);
        __ vldr(temp_1, src0);
        __ vstr(temp_0, src0);
        __ vstr(temp_1, dst0);
        __ vldr(temp_0, dst1);
        __ vldr(temp_1, src1);
        __ vstr(temp_0, src1);
        __ vstr(temp_1, dst1);
      }
      return;
    }
    default:
      UNREACHABLE();
  }
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
  // On 32-bit ARM we emit the jump tables inline.
  UNREACHABLE();
}

#undef __

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```
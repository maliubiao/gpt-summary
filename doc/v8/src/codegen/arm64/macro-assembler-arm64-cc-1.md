Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/arm64/macro-assembler-arm64.cc`. This is the second part of a larger file, and I need to consider that context. The user has provided some keywords to help guide my explanation:

1. **Functionality Listing:** I need to list the operations this code performs.
2. **Torque Source:** I need to check if the filename ends in `.tq`. If so, it's a Torque source.
3. **JavaScript Relationship:** If the code relates to JavaScript, provide a JavaScript example.
4. **Code Logic Inference:** For code with clear logic, provide assumed input and output.
5. **Common Programming Errors:**  Point out any common errors the code might help prevent or be related to.
6. **Part 2 Summary:** Provide a concise summary of the functionality of this specific section.

Let's break down the code and address each point.

* **Load/Store Instructions:** The code defines `LoadStoreMacro` and `LoadStorePairMacro`. These functions handle loading and storing data to and from memory, considering different addressing modes (immediate offset, register offset, pre/post-indexing) and immediate offset ranges.
* **Address Calculation:** The `Adr` function calculates the address of a label, potentially using a "far" addressing mode if the label is too far away for a direct instruction.
* **Branching:** The `B` functions handle conditional and unconditional branching. `Tbnz`, `Tbz`, `Cbnz`, and `Cbz` implement test-and-branch and compare-and-branch instructions.
* **Arithmetic Operations:**  The `Abs` function calculates the absolute value of a register.
* **Switch Statement:** The `Switch` function implements a switch statement using a jump table.
* **Stack Operations:** The code provides abstracted stack operations like `Push` and `Pop` for multiple registers, along with helper functions `PushHelper` and `PopHelper`. `PushMultipleTimes` handles pushing the same register multiple times. `PokePair` and `PeekPair` provide direct access to stack slots.
* **Callee-Saved Registers:** `PushCalleeSavedRegisters` and `PopCalleeSavedRegisters` manage saving and restoring registers according to the calling convention.
* **Tail Calls and Optimization:** The `TailCallOptimizedCodeSlot` (disabled in the provided snippet due to `V8_ENABLE_LEAPTIERING`), `ReplaceClosureCodeWithOptimizedCode`, and `GenerateTailCallToReturnedCode` functions are involved in optimizing function calls.
* **Feedback Vectors:** The code includes functions like `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing` and `OptimizeCodeOrTailCallOptimizedCodeSlot` for dealing with feedback vectors used in optimization.
* **Smi Checking:**  The `CheckSmi` function checks if a value is a Small Integer (Smi).
* **Assertions:** A large section of the code is dedicated to `Assert...` functions, which are used for debugging and verifying the state of the program during development.
* **Memory Copying:** The `CopySlots` and `CopyDoubleWords` functions are for efficiently copying data in memory.
* **Slot Addressing:** The `SlotAddress` function calculates the address of a stack slot.
* **NaN Canonicalization:**  `CanonicalizeNaN` converts NaN values to a canonical representation.

Now, let's address the specific points:

1. **Functionality Listing:** Already done above.
2. **Torque Source:** The filename ends in `.cc`, not `.tq`, so it's a standard C++ source file.
3. **JavaScript Relationship:** Many functions here are directly related to how JavaScript code is executed and optimized within V8. Stack operations, function calls, and object manipulation are core to JavaScript execution.
4. **Code Logic Inference:**  For example, in `Abs`: if `rm` is the minimum representable negative number, `Cneg` will set the overflow flag (`vs`). The conditional branch will then jump to `is_not_representable`.
5. **Common Programming Errors:** The `AssertSpAligned` function helps catch a common ARM64 error: incorrect stack pointer alignment.
6. **Part 2 Summary:** This section of `macro-assembler-arm64.cc` provides implementations for various high-level assembly instructions (macros) used for common tasks like memory access, branching, stack manipulation, function calls, and runtime interaction within the V8 JavaScript engine on ARM64 architecture. It also includes debugging assertions to help catch errors during development.

Planning complete. I will now generate the response.

```cpp
    // Load/stores with immediate offset addressing should have been handled by
    // the caller.
    DCHECK(!IsImmLSScaled(offset, CalcLSDataSizeLog2(op)) && !is_imm_unscaled);
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireSameSizeAs(addr.base());
    Mov(temp, offset);
    LoadStore(rt, MemOperand(addr.base(), temp), op);
  } else if (addr.IsPostIndex()) {
    // Post-index beyond unscaled addressing range.
    DCHECK(!is_imm_unscaled);
    LoadStore(rt, MemOperand(addr.base()), op);
    add(addr.base(), addr.base(), offset);
  } else {
    // Pre-index beyond unscaled addressing range.
    DCHECK(!is_imm_unscaled && addr.IsPreIndex());
    add(addr.base(), addr.base(), offset);
    LoadStore(rt, MemOperand(addr.base()), op);
  }
}

void MacroAssembler::LoadStorePairMacro(const CPURegister& rt,
                                        const CPURegister& rt2,
                                        const MemOperand& addr,
                                        LoadStorePairOp op) {
  if (addr.IsRegisterOffset()) {
    UseScratchRegisterScope temps(this);
    Register base = addr.base();
    Register temp = temps.AcquireSameSizeAs(base);
    Add(temp, base, addr.regoffset());
    LoadStorePair(rt, rt2, MemOperand(temp), op);
    return;
  }

  int64_t offset = addr.offset();
  unsigned size = CalcLSPairDataSize(op);

  // Check if the offset fits in the immediate field of the appropriate
  // instruction. If not, emit two instructions to perform the operation.
  if (IsImmLSPair(offset, size)) {
    // Encodable in one load/store pair instruction.
    LoadStorePair(rt, rt2, addr, op);
  } else {
    Register base = addr.base();
    if (addr.IsImmediateOffset()) {
      UseScratchRegisterScope temps(this);
      Register temp = temps.AcquireSameSizeAs(base);
      Add(temp, base, offset);
      LoadStorePair(rt, rt2, MemOperand(temp), op);
    } else if (addr.IsPostIndex()) {
      LoadStorePair(rt, rt2, MemOperand(base()), op);
      Add(base, base, offset);
    } else {
      DCHECK(addr.IsPreIndex());
      Add(base, base, offset);
      LoadStorePair(rt, rt2, MemOperand(base()), op);
    }
  }
}

void MacroAssembler::Adr(const Register& rd, Label* label, AdrHint hint) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());

  if (hint == kAdrNear) {
    adr(rd, label);
    return;
  }

  DCHECK_EQ(hint, kAdrFar);
  if (label->is_bound()) {
    int label_offset = label->pos() - pc_offset();
    if (Instruction::IsValidPCRelOffset(label_offset)) {
      adr(rd, label);
    } else {
      DCHECK_LE(label_offset, 0);
      int min_adr_offset = -(1 << (Instruction::ImmPCRelRangeBitwidth - 1));
      adr(rd, min_adr_offset);
      Add(rd, rd, label_offset - min_adr_offset);
    }
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.AcquireX();

    InstructionAccurateScope scope(this,
                                   PatchingAssembler::kAdrFarPatchableNInstrs);
    adr(rd, label);
    for (int i = 0; i < PatchingAssembler::kAdrFarPatchableNNops; ++i) {
      nop(ADR_FAR_NOP);
    }
    movz(scratch, 0);
  }
}

void MacroAssembler::B(Label* label, BranchType type, Register reg, int bit) {
  DCHECK((reg == NoReg || type >= kBranchTypeFirstUsingReg) &&
         (bit == -1 || type >= kBranchTypeFirstUsingBit));
  if (kBranchTypeFirstCondition <= type && type <= kBranchTypeLastCondition) {
    B(static_cast<Condition>(type), label);
  } else {
    switch (type) {
      case always:
        B(label);
        break;
      case never:
        break;
      case reg_zero:
        Cbz(reg, label);
        break;
      case reg_not_zero:
        Cbnz(reg, label);
        break;
      case reg_bit_clear:
        Tbz(reg, bit, label);
        break;
      case reg_bit_set:
        Tbnz(reg, bit, label);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void MacroAssembler::B(Label* label, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK((cond != al) && (cond != nv));

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<CondBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    b(&done, NegateCondition(cond));
    B(label);
    bind(&done);
  } else {
    b(label, cond);
  }
}

void MacroAssembler::Tbnz(const Register& rt, unsigned bit_pos, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<TestBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    tbz(rt, bit_pos, &done);
    B(label);
    bind(&done);
  } else {
    tbnz(rt, bit_pos, label);
  }
}

void MacroAssembler::Tbz(const Register& rt, unsigned bit_pos, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<TestBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    tbnz(rt, bit_pos, &done);
    B(label);
    bind(&done);
  } else {
    tbz(rt, bit_pos, label);
  }
}

void MacroAssembler::Cbnz(const Register& rt, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<CompareBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    cbz(rt, &done);
    B(label);
    bind(&done);
  } else {
    cbnz(rt, label);
  }
}

void MacroAssembler::Cbz(const Register& rt, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<CompareBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    cbnz(rt, &done);
    B(label);
    bind(&done);
  } else {
    cbz(rt, label);
  }
}

// Pseudo-instructions.

void MacroAssembler::Abs(const Register& rd, const Register& rm,
                         Label* is_not_representable, Label* is_representable) {
  DCHECK(allow_macro_instructions());
  DCHECK(AreSameSizeAndType(rd, rm));

  Cmp(rm, 1);
  Cneg(rd, rm, lt);

  // If the comparison sets the v flag, the input was the smallest value
  // representable by rm, and the mathematical result of abs(rm) is not
  // representable using two's complement.
  if ((is_not_representable != nullptr) && (is_representable != nullptr)) {
    B(is_not_representable, vs);
    B(is_representable);
  } else if (is_not_representable != nullptr) {
    B(is_not_representable, vs);
  } else if (is_representable != nullptr) {
    B(is_representable, vc);
  }
}

void MacroAssembler::Switch(Register scratch, Register value,
                            int case_value_base, Label** labels,
                            int num_labels) {
  Register table = scratch;
  Label fallthrough, jump_table;
  if (case_value_base != 0) {
    Sub(value, value, case_value_base);
  }
  Cmp(value, Immediate(num_labels));
  B(&fallthrough, hs);
  Adr(table, &jump_table);
  Ldr(table, MemOperand(table, value, LSL, kSystemPointerSizeLog2));
  Br(table);
  // Emit the jump table inline, under the assumption that it's not too big.
  // Make sure there are no veneer pool entries in the middle of the table.
  const int jump_table_size = num_labels * kSystemPointerSize;
  CheckVeneerPool(false, false, jump_table_size);
  BlockPoolsScope no_pool_inbetween(this, jump_table_size);
  Align(kSystemPointerSize);
  bind(&jump_table);
  for (int i = 0; i < num_labels; ++i) {
    dcptr(labels[i]);
  }
  bind(&fallthrough);
}

// Abstracted stack operations.

void MacroAssembler::Push(const CPURegister& src0, const CPURegister& src1,
                          const CPURegister& src2, const CPURegister& src3,
                          const CPURegister& src4, const CPURegister& src5,
                          const CPURegister& src6, const CPURegister& src7) {
  DCHECK(AreSameSizeAndType(src0, src1, src2, src3, src4, src5, src6, src7));

  int count = 5 + src5.is_valid() + src6.is_valid() + src6.is_valid();
  int size = src0.SizeInBytes();
  DCHECK_EQ(0, (size * count) % 16);

  PushHelper(4, size, src0, src1, src2, src3);
  PushHelper(count - 4, size, src4, src5, src6, src7);
}

void MacroAssembler::Pop(const CPURegister& dst0, const CPURegister& dst1,
                         const CPURegister& dst2, const CPURegister& dst3,
                         const CPURegister& dst4, const CPURegister& dst5,
                         const CPURegister& dst6, const CPURegister& dst7) {
  // It is not valid to pop into the same register more than once in one
  // instruction, not even into the zero register.
  DCHECK(!AreAliased(dst0, dst1, dst2, dst3, dst4, dst5, dst6, dst7));
  DCHECK(AreSameSizeAndType(dst0, dst1, dst2, dst3, dst4, dst5, dst6, dst7));
  DCHECK(dst0.is_valid());

  int count = 5 + dst5.is_valid() + dst6.is_valid() + dst7.is_valid();
  int size = dst0.SizeInBytes();
  DCHECK_EQ(0, (size * count) % 16);

  PopHelper(4, size, dst0, dst1, dst2, dst3);
  PopHelper(count - 4, size, dst4, dst5, dst6, dst7);
}

void MacroAssembler::PushMultipleTimes(CPURegister src, Register count) {
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireSameSizeAs(count);

  Label loop, leftover2, leftover1, done;

  Subs(temp, count, 4);
  B(mi, &leftover2);

  // Push groups of four first.
  Bind(&loop);
  Subs(temp, temp, 4);
  PushHelper(4, src.SizeInBytes(), src, src, src, src);
  B(pl, &loop);

  // Push groups of two.
  Bind(&leftover2);
  Tbz(count, 1, &leftover1);
  PushHelper(2, src.SizeInBytes(), src, src, NoReg, NoReg);

  // Push the last one (if required).
  Bind(&leftover1);
  Tbz(count, 0, &done);
  PushHelper(1, src.SizeInBytes(), src, NoReg, NoReg, NoReg);

  Bind(&done);
}

void MacroAssembler::PushHelper(int count, int size, const CPURegister& src0,
                                const CPURegister& src1,
                                const CPURegister& src2,
                                const CPURegister& src3) {
  // Ensure that we don't unintentially modify scratch or debug registers.
  InstructionAccurateScope scope(this);

  DCHECK(AreSameSizeAndType(src0, src1, src2, src3));
  DCHECK(size == src0.SizeInBytes());

  // When pushing multiple registers, the store order is chosen such that
  // Push(a, b) is equivalent to Push(a) followed by Push(b).
  switch (count) {
    case 1:
      DCHECK(src1.IsNone() && src2.IsNone() && src3.IsNone());
      str(src0, MemOperand(sp, -1 * size, PreIndex));
      break;
    case 2:
      DCHECK(src2.IsNone() && src3.IsNone());
      stp(src1, src0, MemOperand(sp, -2 * size, PreIndex));
      break;
    case 3:
      DCHECK(src3.IsNone());
      stp(src2, src1, MemOperand(sp, -3 * size, PreIndex));
      str(src0, MemOperand(sp, 2 * size));
      break;
    case 4:
      // Skip over 4 * size, then fill in the gap. This allows four W registers
      // to be pushed using sp, whilst maintaining 16-byte alignment for sp
      // at all times.
      stp(src3, src2, MemOperand(sp, -4 * size, PreIndex));
      stp(src1, src0, MemOperand(sp, 2 * size));
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::PopHelper(int count, int size, const CPURegister& dst0,
                               const CPURegister& dst1, const CPURegister& dst2,
                               const CPURegister& dst3) {
  // Ensure that we don't unintentially modify scratch or debug registers.
  InstructionAccurateScope scope(this);

  DCHECK(AreSameSizeAndType(dst0, dst1, dst2, dst3));
  DCHECK(size == dst0.SizeInBytes());

  // When popping multiple registers, the load order is chosen such that
  // Pop(a, b) is equivalent to Pop(a) followed by Pop(b).
  switch (count) {
    case 1:
      DCHECK(dst1.IsNone() && dst2.IsNone() && dst3.IsNone());
      ldr(dst0, MemOperand(sp, 1 * size, PostIndex));
      break;
    case 2:
      DCHECK(dst2.IsNone() && dst3.IsNone());
      ldp(dst0, dst1, MemOperand(sp, 2 * size, PostIndex));
      break;
    case 3:
      DCHECK(dst3.IsNone());
      ldr(dst2, MemOperand(sp, 2 * size));
      ldp(dst0, dst1, MemOperand(sp, 3 * size, PostIndex));
      break;
    case 4:
      // Load the higher addresses first, then load the lower addresses and
      // skip the whole block in the second instruction. This allows four W
      // registers to be popped using sp, whilst maintaining 16-byte alignment
      // for sp at all times.
      ldp(dst2, dst3, MemOperand(sp, 2 * size));
      ldp(dst0, dst1, MemOperand(sp, 4 * size, PostIndex));
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::PokePair(const CPURegister& src1, const CPURegister& src2,
                              int offset) {
  DCHECK(AreSameSizeAndType(src1, src2));
  DCHECK((offset >= 0) && ((offset % src1.SizeInBytes()) == 0));
  Stp(src1, src2, MemOperand(sp, offset));
}

void MacroAssembler::PeekPair(const CPURegister& dst1, const CPURegister& dst2,
                              int offset) {
  DCHECK(AreSameSizeAndType(dst1, dst2));
  DCHECK((offset >= 0) && ((offset % dst1.SizeInBytes()) == 0));
  Ldp(dst1, dst2, MemOperand(sp, offset));
}

void MacroAssembler::PushCalleeSavedRegisters() {
  ASM_CODE_COMMENT(this);
  // Ensure that the macro-assembler doesn't use any scratch registers.
  InstructionAccurateScope scope(this);

  MemOperand tos(sp, -2 * static_cast<int>(kXRegSize), PreIndex);

  stp(d14, d15, tos);
  stp(d12, d13, tos);
  stp(d10, d11, tos);
  stp(d8, d9, tos);

  stp(x27, x28, tos);
  stp(x25, x26, tos);
  stp(x23, x24, tos);
  stp(x21, x22, tos);
  stp(x19, x20, tos);

  static_assert(
      EntryFrameConstants::kCalleeSavedRegisterBytesPushedBeforeFpLrPair ==
      18 * kSystemPointerSize);

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
    // Use the stack pointer's value immediately before pushing the LR as the
    // context for signing it. This is what the StackFrameIterator expects.
    pacibsp();
#endif

    stp(x29, x30, tos);  // fp, lr

    static_assert(
        EntryFrameConstants::kCalleeSavedRegisterBytesPushedAfterFpLrPair == 0);
}

void MacroAssembler::PopCalleeSavedRegisters() {
  ASM_CODE_COMMENT(this);
  // Ensure that the macro-assembler doesn't use any scratch registers.
  InstructionAccurateScope scope(this);

  MemOperand tos(sp, 2 * kXRegSize, PostIndex);

  ldp(x29, x30, tos);  // fp, lr

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  // The context (stack pointer value) for authenticating the LR here must
  // match the one used for signing it (see `PushCalleeSavedRegisters`).
  autibsp();
#endif

    ldp(x19, x20, tos);
    ldp(x21, x22, tos);
    ldp(x23, x24, tos);
    ldp(x25, x26, tos);
    ldp(x27, x28, tos);

    ldp(d8, d9, tos);
    ldp(d10, d11, tos);
    ldp(d12, d13, tos);
    ldp(d14, d15, tos);
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
// Only used when leaptiering is disabled.
void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry,
                               Register scratch) {
  // ----------- S t a t e -------------
  //  -- x0 : actual argument count
  //  -- x3 : new target (preserved for callee if needed, and caller)
  //  -- x1 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  ASM_CODE_COMMENT(masm);
  DCHECK(!AreAliased(x1, x3, optimized_code_entry, scratch));

  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  __ AssertCode(optimized_code_entry);
  __ JumpIfCodeIsMarkedForDeoptimization(optimized_code_entry, scratch,
                                         &heal_optimized_code_slot);

  // Optimized code is good, get it into the closure and link the closure into
  // the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, x1);
  static_assert(kJavaScriptCallCodeStartRegister == x2, "ABI mismatch");
  __ Move(x2, optimized_code_entry);
  __ JumpCodeObject(x2, kJSEntrypointTag);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}
#endif  // V8_ENABLE_LEAPTIERING

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, scratch, scratch, FEEDBACK_CELL_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, scratch, scratch, FEEDBACK_VECTOR_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(optimized_code, closure));

#ifdef V8_ENABLE_LEAPTIERING
  UNREACHABLE();
#else
  // Store code entry in the closure.
  AssertCode(optimized_code);
  StoreCodePointerField(optimized_code,
                        FieldMemOperand(closure, JSFunction::kCodeOffset));
  RecordWriteField(closure, JSFunction::kCodeOffset, optimized_code,
                   kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   ReadOnlyCheck::kOmit, SlotDescriptor::ForCodePointerSlot());
#endif  // V8_ENABLE_LEAPTIERING
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  ASM_CODE_COMMENT(this);
  // ----------- S t a t e -------------
  //  -- x0 : actual argument count (preserved for callee)
  //  -- x1 : target function (preserved for callee)
  //  -- x3 : new target (preserved for callee)
  //  -- x4 : dispatch handle (preserved for callee)
  // -----------------------------------
  {
    FrameScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target, the actual
    // argument count, and the dispatch handle.
    Register lastreg = V8_ENABLE_LEAPTIERING_BOOL
                           ? kJavaScriptCallDispatchHandleRegister
                           : padreg;
    SmiTag(kJavaScriptCallArgCountRegister);
    // No need to SmiTag the dispatch handle as it always looks like a Smi.
    static_assert(kJSDispatchHandleShift > 0);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister, lastreg);
    // Push another copy as a parameter to the runtime call.
    PushArgument(kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    Mov(x2, x0);

    // Restore target function, new target, actual argument count, and dispatch
    // handle.
    Pop(lastreg, kJavaScriptCallArgCountRegister,
        kJavaScriptCallNewTargetRegister, kJavaScriptCallTargetRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }

  static_assert(kJavaScriptCallCodeStartRegister == x2, "ABI mismatch");
  JumpCodeObject(x2, kJSEntrypointTag);
}

#ifndef V8_ENABLE_LEAPTIERING

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
Condition MacroAssembler::LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  uint32_t flag_mask =
      FeedbackVector::FlagMaskForNeedsProcessingCheckFrom(current_code_kind);
  Ldrh(flags, FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  Tst(flags, flag_mask);
  return ne;
}

void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  B(LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(flags, feedback_vector,
                                                     current_code_kind),
    flags_need_processing);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, Register feedback_vector) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available.
  TestAndBranchIfAllClear(flags,
                          FeedbackVector::kFlagsTieringStateIsAnyRequested,
                          &maybe_needs_logging);
  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  TestAndBranchIfAllClear(flags, FeedbackVector::LogNextExecutionBit::kMask,
                          &maybe_has_optimized_code);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  // This tiering logic is only needed if leaptiering is disabled. Otherwise
  // we'll automatically tier up through the dispatch table.
  Register optimized_code_entry = x7;
  LoadTaggedField(optimized_code_entry,
                  FieldMemOperand(feedback_vector,
                                  FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry, x4);
}

#endif  // !V8_ENABLE_LEAPTIERING

Condition MacroAssembler::CheckSmi(Register object) {
  static_assert(kSmiTag == 0);
  Tst(object, kSmiTagMask);
  return eq;
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertSpAligned() {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  HardAbortScope hard_abort(this);  // Avoid calls to Abort.
  // Arm64 requires the stack pointer to be 16-byte aligned prior to address
  // calculation.
  UseScratchRegisterScope scope(this);
  Register temp = scope.AcquireX();
  Mov(temp, sp);
  Tst(temp, 15);
  Check(eq, AbortReason::kUnexpectedStackPointer);
}

void MacroAssembler::AssertFPCRState(Register fpcr) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Label unexpected_mode, done;
  UseScratchRegisterScope temps(this);
  if (fpcr.IsNone()) {
    fpcr = temps.AcquireX();
    Mrs(fpcr, FPCR);
  }

  // Settings left to their default values:
  //   - Assert that flush
### 提示词
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Load/stores with immediate offset addressing should have been handled by
    // the caller.
    DCHECK(!IsImmLSScaled(offset, CalcLSDataSizeLog2(op)) && !is_imm_unscaled);
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireSameSizeAs(addr.base());
    Mov(temp, offset);
    LoadStore(rt, MemOperand(addr.base(), temp), op);
  } else if (addr.IsPostIndex()) {
    // Post-index beyond unscaled addressing range.
    DCHECK(!is_imm_unscaled);
    LoadStore(rt, MemOperand(addr.base()), op);
    add(addr.base(), addr.base(), offset);
  } else {
    // Pre-index beyond unscaled addressing range.
    DCHECK(!is_imm_unscaled && addr.IsPreIndex());
    add(addr.base(), addr.base(), offset);
    LoadStore(rt, MemOperand(addr.base()), op);
  }
}

void MacroAssembler::LoadStorePairMacro(const CPURegister& rt,
                                        const CPURegister& rt2,
                                        const MemOperand& addr,
                                        LoadStorePairOp op) {
  if (addr.IsRegisterOffset()) {
    UseScratchRegisterScope temps(this);
    Register base = addr.base();
    Register temp = temps.AcquireSameSizeAs(base);
    Add(temp, base, addr.regoffset());
    LoadStorePair(rt, rt2, MemOperand(temp), op);
    return;
  }

  int64_t offset = addr.offset();
  unsigned size = CalcLSPairDataSize(op);

  // Check if the offset fits in the immediate field of the appropriate
  // instruction. If not, emit two instructions to perform the operation.
  if (IsImmLSPair(offset, size)) {
    // Encodable in one load/store pair instruction.
    LoadStorePair(rt, rt2, addr, op);
  } else {
    Register base = addr.base();
    if (addr.IsImmediateOffset()) {
      UseScratchRegisterScope temps(this);
      Register temp = temps.AcquireSameSizeAs(base);
      Add(temp, base, offset);
      LoadStorePair(rt, rt2, MemOperand(temp), op);
    } else if (addr.IsPostIndex()) {
      LoadStorePair(rt, rt2, MemOperand(base), op);
      Add(base, base, offset);
    } else {
      DCHECK(addr.IsPreIndex());
      Add(base, base, offset);
      LoadStorePair(rt, rt2, MemOperand(base), op);
    }
  }
}

void MacroAssembler::Adr(const Register& rd, Label* label, AdrHint hint) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());

  if (hint == kAdrNear) {
    adr(rd, label);
    return;
  }

  DCHECK_EQ(hint, kAdrFar);
  if (label->is_bound()) {
    int label_offset = label->pos() - pc_offset();
    if (Instruction::IsValidPCRelOffset(label_offset)) {
      adr(rd, label);
    } else {
      DCHECK_LE(label_offset, 0);
      int min_adr_offset = -(1 << (Instruction::ImmPCRelRangeBitwidth - 1));
      adr(rd, min_adr_offset);
      Add(rd, rd, label_offset - min_adr_offset);
    }
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.AcquireX();

    InstructionAccurateScope scope(this,
                                   PatchingAssembler::kAdrFarPatchableNInstrs);
    adr(rd, label);
    for (int i = 0; i < PatchingAssembler::kAdrFarPatchableNNops; ++i) {
      nop(ADR_FAR_NOP);
    }
    movz(scratch, 0);
  }
}

void MacroAssembler::B(Label* label, BranchType type, Register reg, int bit) {
  DCHECK((reg == NoReg || type >= kBranchTypeFirstUsingReg) &&
         (bit == -1 || type >= kBranchTypeFirstUsingBit));
  if (kBranchTypeFirstCondition <= type && type <= kBranchTypeLastCondition) {
    B(static_cast<Condition>(type), label);
  } else {
    switch (type) {
      case always:
        B(label);
        break;
      case never:
        break;
      case reg_zero:
        Cbz(reg, label);
        break;
      case reg_not_zero:
        Cbnz(reg, label);
        break;
      case reg_bit_clear:
        Tbz(reg, bit, label);
        break;
      case reg_bit_set:
        Tbnz(reg, bit, label);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void MacroAssembler::B(Label* label, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK((cond != al) && (cond != nv));

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<CondBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    b(&done, NegateCondition(cond));
    B(label);
    bind(&done);
  } else {
    b(label, cond);
  }
}

void MacroAssembler::Tbnz(const Register& rt, unsigned bit_pos, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<TestBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    tbz(rt, bit_pos, &done);
    B(label);
    bind(&done);
  } else {
    tbnz(rt, bit_pos, label);
  }
}

void MacroAssembler::Tbz(const Register& rt, unsigned bit_pos, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<TestBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    tbnz(rt, bit_pos, &done);
    B(label);
    bind(&done);
  } else {
    tbz(rt, bit_pos, label);
  }
}

void MacroAssembler::Cbnz(const Register& rt, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<CompareBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    cbz(rt, &done);
    B(label);
    bind(&done);
  } else {
    cbnz(rt, label);
  }
}

void MacroAssembler::Cbz(const Register& rt, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<CompareBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    cbnz(rt, &done);
    B(label);
    bind(&done);
  } else {
    cbz(rt, label);
  }
}

// Pseudo-instructions.

void MacroAssembler::Abs(const Register& rd, const Register& rm,
                         Label* is_not_representable, Label* is_representable) {
  DCHECK(allow_macro_instructions());
  DCHECK(AreSameSizeAndType(rd, rm));

  Cmp(rm, 1);
  Cneg(rd, rm, lt);

  // If the comparison sets the v flag, the input was the smallest value
  // representable by rm, and the mathematical result of abs(rm) is not
  // representable using two's complement.
  if ((is_not_representable != nullptr) && (is_representable != nullptr)) {
    B(is_not_representable, vs);
    B(is_representable);
  } else if (is_not_representable != nullptr) {
    B(is_not_representable, vs);
  } else if (is_representable != nullptr) {
    B(is_representable, vc);
  }
}

void MacroAssembler::Switch(Register scratch, Register value,
                            int case_value_base, Label** labels,
                            int num_labels) {
  Register table = scratch;
  Label fallthrough, jump_table;
  if (case_value_base != 0) {
    Sub(value, value, case_value_base);
  }
  Cmp(value, Immediate(num_labels));
  B(&fallthrough, hs);
  Adr(table, &jump_table);
  Ldr(table, MemOperand(table, value, LSL, kSystemPointerSizeLog2));
  Br(table);
  // Emit the jump table inline, under the assumption that it's not too big.
  // Make sure there are no veneer pool entries in the middle of the table.
  const int jump_table_size = num_labels * kSystemPointerSize;
  CheckVeneerPool(false, false, jump_table_size);
  BlockPoolsScope no_pool_inbetween(this, jump_table_size);
  Align(kSystemPointerSize);
  bind(&jump_table);
  for (int i = 0; i < num_labels; ++i) {
    dcptr(labels[i]);
  }
  bind(&fallthrough);
}

// Abstracted stack operations.

void MacroAssembler::Push(const CPURegister& src0, const CPURegister& src1,
                          const CPURegister& src2, const CPURegister& src3,
                          const CPURegister& src4, const CPURegister& src5,
                          const CPURegister& src6, const CPURegister& src7) {
  DCHECK(AreSameSizeAndType(src0, src1, src2, src3, src4, src5, src6, src7));

  int count = 5 + src5.is_valid() + src6.is_valid() + src6.is_valid();
  int size = src0.SizeInBytes();
  DCHECK_EQ(0, (size * count) % 16);

  PushHelper(4, size, src0, src1, src2, src3);
  PushHelper(count - 4, size, src4, src5, src6, src7);
}

void MacroAssembler::Pop(const CPURegister& dst0, const CPURegister& dst1,
                         const CPURegister& dst2, const CPURegister& dst3,
                         const CPURegister& dst4, const CPURegister& dst5,
                         const CPURegister& dst6, const CPURegister& dst7) {
  // It is not valid to pop into the same register more than once in one
  // instruction, not even into the zero register.
  DCHECK(!AreAliased(dst0, dst1, dst2, dst3, dst4, dst5, dst6, dst7));
  DCHECK(AreSameSizeAndType(dst0, dst1, dst2, dst3, dst4, dst5, dst6, dst7));
  DCHECK(dst0.is_valid());

  int count = 5 + dst5.is_valid() + dst6.is_valid() + dst7.is_valid();
  int size = dst0.SizeInBytes();
  DCHECK_EQ(0, (size * count) % 16);

  PopHelper(4, size, dst0, dst1, dst2, dst3);
  PopHelper(count - 4, size, dst4, dst5, dst6, dst7);
}

void MacroAssembler::PushMultipleTimes(CPURegister src, Register count) {
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireSameSizeAs(count);

  Label loop, leftover2, leftover1, done;

  Subs(temp, count, 4);
  B(mi, &leftover2);

  // Push groups of four first.
  Bind(&loop);
  Subs(temp, temp, 4);
  PushHelper(4, src.SizeInBytes(), src, src, src, src);
  B(pl, &loop);

  // Push groups of two.
  Bind(&leftover2);
  Tbz(count, 1, &leftover1);
  PushHelper(2, src.SizeInBytes(), src, src, NoReg, NoReg);

  // Push the last one (if required).
  Bind(&leftover1);
  Tbz(count, 0, &done);
  PushHelper(1, src.SizeInBytes(), src, NoReg, NoReg, NoReg);

  Bind(&done);
}

void MacroAssembler::PushHelper(int count, int size, const CPURegister& src0,
                                const CPURegister& src1,
                                const CPURegister& src2,
                                const CPURegister& src3) {
  // Ensure that we don't unintentially modify scratch or debug registers.
  InstructionAccurateScope scope(this);

  DCHECK(AreSameSizeAndType(src0, src1, src2, src3));
  DCHECK(size == src0.SizeInBytes());

  // When pushing multiple registers, the store order is chosen such that
  // Push(a, b) is equivalent to Push(a) followed by Push(b).
  switch (count) {
    case 1:
      DCHECK(src1.IsNone() && src2.IsNone() && src3.IsNone());
      str(src0, MemOperand(sp, -1 * size, PreIndex));
      break;
    case 2:
      DCHECK(src2.IsNone() && src3.IsNone());
      stp(src1, src0, MemOperand(sp, -2 * size, PreIndex));
      break;
    case 3:
      DCHECK(src3.IsNone());
      stp(src2, src1, MemOperand(sp, -3 * size, PreIndex));
      str(src0, MemOperand(sp, 2 * size));
      break;
    case 4:
      // Skip over 4 * size, then fill in the gap. This allows four W registers
      // to be pushed using sp, whilst maintaining 16-byte alignment for sp
      // at all times.
      stp(src3, src2, MemOperand(sp, -4 * size, PreIndex));
      stp(src1, src0, MemOperand(sp, 2 * size));
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::PopHelper(int count, int size, const CPURegister& dst0,
                               const CPURegister& dst1, const CPURegister& dst2,
                               const CPURegister& dst3) {
  // Ensure that we don't unintentially modify scratch or debug registers.
  InstructionAccurateScope scope(this);

  DCHECK(AreSameSizeAndType(dst0, dst1, dst2, dst3));
  DCHECK(size == dst0.SizeInBytes());

  // When popping multiple registers, the load order is chosen such that
  // Pop(a, b) is equivalent to Pop(a) followed by Pop(b).
  switch (count) {
    case 1:
      DCHECK(dst1.IsNone() && dst2.IsNone() && dst3.IsNone());
      ldr(dst0, MemOperand(sp, 1 * size, PostIndex));
      break;
    case 2:
      DCHECK(dst2.IsNone() && dst3.IsNone());
      ldp(dst0, dst1, MemOperand(sp, 2 * size, PostIndex));
      break;
    case 3:
      DCHECK(dst3.IsNone());
      ldr(dst2, MemOperand(sp, 2 * size));
      ldp(dst0, dst1, MemOperand(sp, 3 * size, PostIndex));
      break;
    case 4:
      // Load the higher addresses first, then load the lower addresses and
      // skip the whole block in the second instruction. This allows four W
      // registers to be popped using sp, whilst maintaining 16-byte alignment
      // for sp at all times.
      ldp(dst2, dst3, MemOperand(sp, 2 * size));
      ldp(dst0, dst1, MemOperand(sp, 4 * size, PostIndex));
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::PokePair(const CPURegister& src1, const CPURegister& src2,
                              int offset) {
  DCHECK(AreSameSizeAndType(src1, src2));
  DCHECK((offset >= 0) && ((offset % src1.SizeInBytes()) == 0));
  Stp(src1, src2, MemOperand(sp, offset));
}

void MacroAssembler::PeekPair(const CPURegister& dst1, const CPURegister& dst2,
                              int offset) {
  DCHECK(AreSameSizeAndType(dst1, dst2));
  DCHECK((offset >= 0) && ((offset % dst1.SizeInBytes()) == 0));
  Ldp(dst1, dst2, MemOperand(sp, offset));
}

void MacroAssembler::PushCalleeSavedRegisters() {
  ASM_CODE_COMMENT(this);
  // Ensure that the macro-assembler doesn't use any scratch registers.
  InstructionAccurateScope scope(this);

  MemOperand tos(sp, -2 * static_cast<int>(kXRegSize), PreIndex);

  stp(d14, d15, tos);
  stp(d12, d13, tos);
  stp(d10, d11, tos);
  stp(d8, d9, tos);

  stp(x27, x28, tos);
  stp(x25, x26, tos);
  stp(x23, x24, tos);
  stp(x21, x22, tos);
  stp(x19, x20, tos);

  static_assert(
      EntryFrameConstants::kCalleeSavedRegisterBytesPushedBeforeFpLrPair ==
      18 * kSystemPointerSize);

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
    // Use the stack pointer's value immediately before pushing the LR as the
    // context for signing it. This is what the StackFrameIterator expects.
    pacibsp();
#endif

    stp(x29, x30, tos);  // fp, lr

    static_assert(
        EntryFrameConstants::kCalleeSavedRegisterBytesPushedAfterFpLrPair == 0);
}

void MacroAssembler::PopCalleeSavedRegisters() {
  ASM_CODE_COMMENT(this);
  // Ensure that the macro-assembler doesn't use any scratch registers.
  InstructionAccurateScope scope(this);

  MemOperand tos(sp, 2 * kXRegSize, PostIndex);

  ldp(x29, x30, tos);  // fp, lr

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  // The context (stack pointer value) for authenticating the LR here must
  // match the one used for signing it (see `PushCalleeSavedRegisters`).
  autibsp();
#endif

    ldp(x19, x20, tos);
    ldp(x21, x22, tos);
    ldp(x23, x24, tos);
    ldp(x25, x26, tos);
    ldp(x27, x28, tos);

    ldp(d8, d9, tos);
    ldp(d10, d11, tos);
    ldp(d12, d13, tos);
    ldp(d14, d15, tos);
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
// Only used when leaptiering is disabled.
void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry,
                               Register scratch) {
  // ----------- S t a t e -------------
  //  -- x0 : actual argument count
  //  -- x3 : new target (preserved for callee if needed, and caller)
  //  -- x1 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  ASM_CODE_COMMENT(masm);
  DCHECK(!AreAliased(x1, x3, optimized_code_entry, scratch));

  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  __ AssertCode(optimized_code_entry);
  __ JumpIfCodeIsMarkedForDeoptimization(optimized_code_entry, scratch,
                                         &heal_optimized_code_slot);

  // Optimized code is good, get it into the closure and link the closure into
  // the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, x1);
  static_assert(kJavaScriptCallCodeStartRegister == x2, "ABI mismatch");
  __ Move(x2, optimized_code_entry);
  __ JumpCodeObject(x2, kJSEntrypointTag);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}
#endif  // V8_ENABLE_LEAPTIERING

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, scratch, scratch, FEEDBACK_CELL_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, scratch, scratch, FEEDBACK_VECTOR_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(optimized_code, closure));

#ifdef V8_ENABLE_LEAPTIERING
  UNREACHABLE();
#else
  // Store code entry in the closure.
  AssertCode(optimized_code);
  StoreCodePointerField(optimized_code,
                        FieldMemOperand(closure, JSFunction::kCodeOffset));
  RecordWriteField(closure, JSFunction::kCodeOffset, optimized_code,
                   kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   ReadOnlyCheck::kOmit, SlotDescriptor::ForCodePointerSlot());
#endif  // V8_ENABLE_LEAPTIERING
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  ASM_CODE_COMMENT(this);
  // ----------- S t a t e -------------
  //  -- x0 : actual argument count (preserved for callee)
  //  -- x1 : target function (preserved for callee)
  //  -- x3 : new target (preserved for callee)
  //  -- x4 : dispatch handle (preserved for callee)
  // -----------------------------------
  {
    FrameScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target, the actual
    // argument count, and the dispatch handle.
    Register lastreg = V8_ENABLE_LEAPTIERING_BOOL
                           ? kJavaScriptCallDispatchHandleRegister
                           : padreg;
    SmiTag(kJavaScriptCallArgCountRegister);
    // No need to SmiTag the dispatch handle as it always looks like a Smi.
    static_assert(kJSDispatchHandleShift > 0);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister, lastreg);
    // Push another copy as a parameter to the runtime call.
    PushArgument(kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    Mov(x2, x0);

    // Restore target function, new target, actual argument count, and dispatch
    // handle.
    Pop(lastreg, kJavaScriptCallArgCountRegister,
        kJavaScriptCallNewTargetRegister, kJavaScriptCallTargetRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }

  static_assert(kJavaScriptCallCodeStartRegister == x2, "ABI mismatch");
  JumpCodeObject(x2, kJSEntrypointTag);
}

#ifndef V8_ENABLE_LEAPTIERING

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
Condition MacroAssembler::LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  uint32_t flag_mask =
      FeedbackVector::FlagMaskForNeedsProcessingCheckFrom(current_code_kind);
  Ldrh(flags, FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  Tst(flags, flag_mask);
  return ne;
}

void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  B(LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(flags, feedback_vector,
                                                     current_code_kind),
    flags_need_processing);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, Register feedback_vector) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available.
  TestAndBranchIfAllClear(flags,
                          FeedbackVector::kFlagsTieringStateIsAnyRequested,
                          &maybe_needs_logging);
  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  TestAndBranchIfAllClear(flags, FeedbackVector::LogNextExecutionBit::kMask,
                          &maybe_has_optimized_code);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  // This tiering logic is only needed if leaptiering is disabled. Otherwise
  // we'll automatically tier up through the dispatch table.
  Register optimized_code_entry = x7;
  LoadTaggedField(optimized_code_entry,
                  FieldMemOperand(feedback_vector,
                                  FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry, x4);
}

#endif  // !V8_ENABLE_LEAPTIERING

Condition MacroAssembler::CheckSmi(Register object) {
  static_assert(kSmiTag == 0);
  Tst(object, kSmiTagMask);
  return eq;
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertSpAligned() {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  HardAbortScope hard_abort(this);  // Avoid calls to Abort.
  // Arm64 requires the stack pointer to be 16-byte aligned prior to address
  // calculation.
  UseScratchRegisterScope scope(this);
  Register temp = scope.AcquireX();
  Mov(temp, sp);
  Tst(temp, 15);
  Check(eq, AbortReason::kUnexpectedStackPointer);
}

void MacroAssembler::AssertFPCRState(Register fpcr) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Label unexpected_mode, done;
  UseScratchRegisterScope temps(this);
  if (fpcr.IsNone()) {
    fpcr = temps.AcquireX();
    Mrs(fpcr, FPCR);
  }

  // Settings left to their default values:
  //   - Assert that flush-to-zero is not set.
  Tbnz(fpcr, FZ_offset, &unexpected_mode);
  //   - Assert that the rounding mode is nearest-with-ties-to-even.
  static_assert(FPTieEven == 0);
  Tst(fpcr, RMode_mask);
  B(eq, &done);

  Bind(&unexpected_mode);
  Abort(AbortReason::kUnexpectedFPCRMode);

  Bind(&done);
}

void MacroAssembler::AssertSmi(Register object, AbortReason reason) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  Tst(object, kSmiTagMask);
  Check(eq, reason);
}

void MacroAssembler::AssertNotSmi(Register object, AbortReason reason) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  Tst(object, kSmiTagMask);
  Check(ne, reason);
}

void MacroAssembler::AssertZeroExtended(Register int32_register) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Tst(int32_register.X(), kMaxUInt32);
  Check(ls, AbortReason::k32BitValueInRegisterIsNotZeroExtended);
}

void MacroAssembler::AssertMap(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsNotAMap);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();

  IsObjectType(object, temp, temp, MAP_TYPE);
  Check(eq, AbortReason::kOperandIsNotAMap);
}

void MacroAssembler::AssertCode(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsNotACode);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();

  IsObjectType(object, temp, temp, CODE_TYPE);
  Check(eq, AbortReason::kOperandIsNotACode);
}

void MacroAssembler::AssertConstructor(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAConstructor);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();

  LoadMap(temp, object);
  Ldrb(temp, FieldMemOperand(temp, Map::kBitFieldOffset));
  Tst(temp, Operand(Map::Bits1::IsConstructorBit::kMask));

  Check(ne, AbortReason::kOperandIsNotAConstructor);
}

void MacroAssembler::AssertFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAFunction);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  LoadMap(temp, object);
  CompareInstanceTypeRange(temp, temp, FIRST_JS_FUNCTION_TYPE,
                           LAST_JS_FUNCTION_TYPE);
  Check(ls, AbortReason::kOperandIsNotAFunction);
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAFunction);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  LoadMap(temp, object);
  CompareInstanceTypeRange(temp, temp, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                           LAST_CALLABLE_JS_FUNCTION_TYPE);
  Check(ls, AbortReason::kOperandIsNotACallableFunction);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotABoundFunction);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();

  IsObjectType(object, temp, temp, JS_BOUND_FUNCTION_TYPE);
  Check(eq, AbortReason::kOperandIsNotABoundFunction);
}

void MacroAssembler::AssertSmiOrHeapObjectInMainCompressionCage(
    Register object) {
  if (!PointerCompressionIsEnabled()) return;
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  // We may not have any scratch registers so we preserve our input register.
  Push(object, xzr);
  Label ok;
  B(&ok, CheckSmi(object));
  Mov(object, Operand(object, LSR, 32));
  // Either the value is now equal to the right-shifted pointer compression
  // cage base or it's zero if we got a compressed pointer register as input.
  Cmp(object, 0);
  B(kEqual, &ok);
  Cmp(object, Operand(kPtrComprCageBaseRegister, LSR, 32));
  Check(kEqual, AbortReason::kObjectNotTagged);
  bind(&ok);
  Pop(xzr, object);
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAGeneratorObject);

  // Load map
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  LoadMap(temp, object);

  // Load instance type and check if JSGeneratorObject
  CompareInstanceTypeRange(temp, temp, FIRST_JS_GENERATOR_OBJECT_TYPE,
                           LAST_JS_GENERATOR_OBJECT_TYPE);
  // Restore generator object to register and perform assertion
  Check(ls, AbortReason::kOperandIsNotAGeneratorObject);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Label done_checking;
  AssertNotSmi(object);
  JumpIfRoot(object, RootIndex::kUndefinedValue, &done_checking);
  LoadMap(scratch, object);
  CompareInstanceType(scratch, scratch, ALLOCATION_SITE_TYPE);
  Assert(eq, AbortReason::kExpectedUndefinedOrCell);
  Bind(&done_checking);
}

void MacroAssembler::AssertPositiveOrZero(Register value) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Label done;
  int sign_bit = value.Is64Bits() ? kXSignBit : kWSignBit;
  Tbz(value, sign_bit, &done);
  Abort(AbortReason::kUnexpectedNegativeValue);
  Bind(&done);
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 Register tmp, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp, tmp));
  Label ok;

  JumpIfSmi(object, &ok);

  LoadMap(map_tmp, object);
  CompareInstanceType(map_tmp, tmp, LAST_NAME_TYPE);
  B(kUnsignedLessThanEqual, &ok);

  CompareInstanceType(map_tmp, tmp, FIRST_JS_RECEIVER_TYPE);
  B(kUnsignedGreaterThanEqual, &ok);

  CompareRoot(map_tmp, RootIndex::kHeapNumberMap);
  B(kEqual, &ok);

  CompareRoot(map_tmp, RootIndex::kBigIntMap);
  B(kEqual, &ok);

  CompareRoot(object, RootIndex::kUndefinedValue);
  B(kEqual, &ok);

  CompareRoot(object, RootIndex::kTrueValue);
  B(kEqual, &ok);

  CompareRoot(object, RootIndex::kFalseValue);
  B(kEqual, &ok);

  CompareRoot(object, RootIndex::kNullValue);
  B(kEqual, &ok);

  Abort(abort_reason);

  bind(&ok);
}

void MacroAssembler::Assert(Condition cond, AbortReason reason) {
  if (v8_flags.debug_code) {
    Check(cond, reason);
  }
}

void MacroAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::CopySlots(int dst, Register src, Register slot_count) {
  DCHECK(!src.IsZero());
  UseScratchRegisterScope scope(this);
  Register dst_reg = scope.AcquireX();
  SlotAddress(dst_reg, dst);
  SlotAddress(src, src);
  CopyDoubleWords(dst_reg, src, slot_count);
}

void MacroAssembler::CopySlots(Register dst, Register src,
                               Register slot_count) {
  DCHECK(!dst.IsZero() && !src.IsZero());
  SlotAddress(dst, dst);
  SlotAddress(src, src);
  CopyDoubleWords(dst, src, slot_count);
}

void MacroAssembler::CopyDoubleWords(Register dst, Register src, Register count,
                                     CopyDoubleWordsMode mode) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(dst, src, count));

  if (v8_flags.debug_code) {
    Register pointer1 = dst;
    Register pointer2 = src;
    if (mode == kSrcLessThanDst) {
      pointer1 = src;
      pointer2 = dst;
    }
    // Copy requires pointer1 < pointer2 || (pointer1 - pointer2) >= count.
    Label pointer1_below_pointer2;
    Subs(pointer1, pointer1, pointer2);
    B(lt, &pointer1_below_pointer2);
    Cmp(pointer1, count);
    Check(ge, AbortReason::kOffsetOutOfRange);
    Bind(&pointer1_below_pointer2);
    Add(pointer1, pointer1, pointer2);
  }
  static_assert(kSystemPointerSize == kDRegSize,
                "pointers must be the same size as doubles");

  if (mode == kDstLessThanSrcAndReverse) {
    Add(src, src, Operand(count, LSL, kSystemPointerSizeLog2));
    Sub(src, src, kSystemPointerSize);
  }

  int src_direction = (mode == kDstLessThanSrc) ? 1 : -1;
  int dst_direction = (mode == kSrcLessThanDst) ? -1 : 1;

  UseScratchRegisterScope scope(this);
  VRegister temp0 = scope.AcquireD();
  VRegister temp1 = scope.AcquireD();

  Label pairs, loop, done;

  Tbz(count, 0, &pairs);
  Ldr(temp0, MemOperand(src, src_direction * kSystemPointerSize, PostIndex));
  Sub(count, count, 1);
  Str(temp0, MemOperand(dst, dst_direction * kSystemPointerSize, PostIndex));

  Bind(&pairs);
  if (mode == kSrcLessThanDst) {
    // Adjust pointers for post-index ldp/stp with negative offset:
    Sub(dst, dst, kSystemPointerSize);
    Sub(src, src, kSystemPointerSize);
  } else if (mode == kDstLessThanSrcAndReverse) {
    Sub(src, src, kSystemPointerSize);
  }
  Bind(&loop);
  Cbz(count, &done);
  Ldp(temp0, temp1,
      MemOperand(src, 2 * src_direction * kSystemPointerSize, PostIndex));
  Sub(count, count, 2);
  if (mode == kDstLessThanSrcAndReverse) {
    Stp(temp1, temp0,
        MemOperand(dst, 2 * dst_direction * kSystemPointerSize, PostIndex));
  } else {
    Stp(temp0, temp1,
        MemOperand(dst, 2 * dst_direction * kSystemPointerSize, PostIndex));
  }
  B(&loop);

  // TODO(all): large copies may benefit from using temporary Q registers
  // to copy four double words per iteration.

  Bind(&done);
}

void MacroAssembler::SlotAddress(Register dst, int slot_offset) {
  Add(dst, sp, slot_offset << kSystemPointerSizeLog2);
}

void MacroAssembler::SlotAddress(Register dst, Register slot_offset) {
  Add(dst, sp, Operand(slot_offset, LSL, kSystemPointerSizeLog2));
}

void MacroAssembler::CanonicalizeNaN(const VRegister& dst,
                                     const VRegister& src) {
  AssertFPCRState();

  // Subtra
```
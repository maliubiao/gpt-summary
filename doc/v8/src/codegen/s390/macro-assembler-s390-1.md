Response: The user wants a summary of the C++ source code file `v8/src/codegen/s390/macro-assembler-s390.cc`.
This is the second part of a four-part summary request.
Therefore, I should focus on the functionality present in the provided code snippet and avoid repeating information that might have been covered in the first part or that will be covered in the subsequent parts.

The code snippet contains a significant portion of the `MacroAssembler` class implementation for the s390 architecture in V8. It deals with low-level code generation, including:

- **Optimized code handling:** Functions like `TailCallOptimizedCodeSlot` and `ReplaceClosureCodeWithOptimizedCode` are responsible for managing the execution of optimized JavaScript code.
- **Runtime calls:**  Functions like `CallRuntime` and `TailCallRuntime` facilitate calling into the V8 runtime system.
- **Feedback vector processing:**  Functions like `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing` and `OptimizeCodeOrTailCallOptimizedCodeSlot` handle the logic for tiered compilation based on feedback.
- **Debugging assertions:**  Various `Assert...` functions are used for runtime checks in debug builds.
- **C function calls:** Functions like `PrepareCallCFunction` and `CallCFunction` are used to call external C functions.
- **Low-level assembly instructions:** A large number of methods wrap s390 assembly instructions for various operations (arithmetic, logical, memory access, comparisons, branches).

Given this is part 2, I should consider what might have been in part 1. Part 1 likely covered basic setup and potentially some initial instruction wrappers. Parts 3 and 4 will likely cover more specialized instructions or features.

My summary should focus on the core functionalities exposed in *this* part of the code.
这个C++源代码文件（`v8/src/codegen/s390/macro-assembler-s390.cc`）的第2部分主要负责以下功能：

1. **处理优化的代码调用:**  它包含了用于处理尾调用优化代码槽的逻辑 (`TailCallOptimizedCodeSlot`)。这个函数负责检查是否可以跳转到函数的优化版本，如果优化代码可用且未被标记为反优化，则会执行跳转。

2. **替换闭包代码为优化代码:**  `ReplaceClosureCodeWithOptimizedCode` 函数用于将一个函数的闭包中的代码指针替换为优化后的代码。这使得后续对该函数的调用可以直接执行优化后的版本。

3. **生成返回到运行时代码的尾调用:** `GenerateTailCallToReturnedCode` 函数用于生成一个尾调用指令序列，该指令序列会调用 V8 运行时系统的特定函数。这通常用于处理一些需要运行时支持的操作，例如编译优化代码。

4. **检查反馈向量并判断是否需要处理:**  `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing` 和 `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing` 函数用于从反馈向量中加载标志位，并根据这些标志位判断是否需要进行进一步的处理，例如触发优化或记录执行信息。

5. **根据反馈向量优化代码或尾调用优化代码槽:** `OptimizeCodeOrTailCallOptimizedCodeSlot` 函数基于反馈向量的标志来决定是否应该编译优化代码、记录函数执行信息或者尾调用到已存在的优化代码槽。

6. **调用运行时函数:** `CallRuntime` 函数用于生成调用 V8 运行时函数的代码。它负责设置参数并将控制权转移到运行时系统。

7. **尾调用运行时函数:** `TailCallRuntime` 函数用于生成尾调用 V8 运行时函数的代码，优化了栈的使用。

8. **跳转到外部引用:** `JumpToExternalReference` 函数用于跳转到指定的外部代码地址，常用于调用内置函数。

9. **加载弱引用值:** `LoadWeakValue` 函数用于加载弱引用，如果弱引用已被清除，则跳转到指定的目标地址。

10. **发射计数器增减指令:** `EmitIncrementCounter` 和 `EmitDecrementCounter` 用于生成增加或减少性能计数器的指令。

11. **断言:**  `Check` 和 `Abort` 函数用于在开发和调试阶段进行条件检查，并在条件不满足时中止程序执行。`AssertFeedbackCell`, `AssertFeedbackVector` 等用于断言对象的类型。

12. **加载对象 Map:** `LoadCompressedMap` 和 `LoadMap` 函数用于加载对象的 Map（描述对象结构和类型的元数据）。

13. **加载反馈向量:** `LoadFeedbackVector` 函数用于从闭包中加载反馈向量。

14. **加载 Native Context Slot:** `LoadNativeContextSlot` 函数用于加载 Native Context 中的特定槽位。

15. **提供各种断言宏:**  在 `V8_ENABLE_DEBUG_CODE` 宏定义下，提供了大量的 `Assert...` 函数用于在调试模式下检查各种条件，例如对象是否为 Smi、Map、函数等。

16. **计算栈上传递的字数:** `CalculateStackPassedWords` 函数用于计算通过栈传递给 C 函数的参数数量。

17. **准备调用 C 函数:** `PrepareCallCFunction` 函数用于在调用 C 函数之前进行栈的设置和参数的准备。

18. **调用 C 函数:** `CallCFunction` 函数用于生成调用外部 C 函数的代码，包括处理参数传递和栈帧管理。

19. **检查内存页标志:** `CheckPageFlag` 函数用于检查给定内存地址所在页面的标志位。

20. **获取不与其他寄存器冲突的寄存器:** `GetRegisterThatIsNotOneOf` 函数用于获取一个不与指定寄存器列表中的寄存器冲突的可用寄存器。

21. **大量的汇编指令封装:** 提供了大量的 `mov`, `MulS32`, `MulHighS32`, `DivS32`, `ModS32`, `AddS32`, `SubS32`, `And`, `Or`, `Xor`, `CmpS32`, `LoadU64`, `StoreU64` 等函数，用于生成各种 s390 架构的汇编指令。 这些函数通常会根据操作数类型和立即数的大小选择最优的指令。

**与 Javascript 的关系 (示例):**

此部分代码与 JavaScript 的执行性能优化密切相关。例如，当 JavaScript 引擎尝试优化一个函数时，`TailCallOptimizedCodeSlot` 和 `ReplaceClosureCodeWithOptimizedCode` 就发挥作用了。

假设有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

function calculate(x) {
  return add(x, 5);
}

console.log(calculate(10));
```

当 `calculate` 函数被多次调用时，V8 引擎可能会对其进行优化。

1. **反馈收集:**  在未优化的执行过程中，V8 会收集关于 `add` 函数调用情况的反馈信息，例如参数类型。这些信息存储在与 `add` 函数关联的**反馈向量**中。

2. **触发优化:** 当反馈信息表明 `add` 函数值得优化时，引擎可能会决定编译 `add` 函数的优化版本。此时，`OptimizeCodeOrTailCallOptimizedCodeSlot` 可能会被调用，并根据反馈向量的标志来决定触发优化编译。

3. **替换代码:** 优化后的 `add` 函数的代码会被生成。 `ReplaceClosureCodeWithOptimizedCode` 函数会被调用，将 `add` 函数的闭包中指向未优化代码的指针替换为指向优化代码的指针。

4. **尾调用优化:** 如果 `calculate` 函数的优化版本也生成了，并且它对 `add` 的调用是尾调用，那么 `TailCallOptimizedCodeSlot` 就有可能被使用。当执行到 `calculate` 中调用 `add` 的地方时，引擎会检查 `add` 的优化代码槽。如果优化代码可用，引擎会执行一个**尾调用**，直接跳转到优化后的 `add` 函数，而不需要额外的栈帧，从而提高性能。

5. **运行时支持:** 如果在优化的过程中需要进行一些底层的操作，例如分配内存或者进行类型转换，`CallRuntime` 或 `TailCallRuntime` 函数会被用来调用 V8 运行时系统的相关函数。

总而言之，此部分代码是 V8 JavaScript 引擎在 s390 架构上进行代码生成和优化的核心组成部分，它直接影响着 JavaScript 代码的执行效率。

Prompt: 
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
);
  beq(done);
}

namespace {

void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry,
                               Register scratch) {
  // ----------- S t a t e -------------
  //  -- r2 : actual argument count
  //  -- r5 : new target (preserved for callee if needed, and caller)
  //  -- r3 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  DCHECK(!AreAliased(r3, r5, optimized_code_entry, scratch));

  Register closure = r3;
  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadTaggedField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  {
    __ TestCodeIsMarkedForDeoptimization(optimized_code_entry, scratch);
    __ bne(&heal_optimized_code_slot);
  }

  // Optimized code is good, get it into the closure and link the closure
  // into the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, closure, scratch,
                                         r7);
  static_assert(kJavaScriptCallCodeStartRegister == r4, "ABI mismatch");
  __ LoadCodeInstructionStart(r4, optimized_code_entry);
  __ Jump(r4);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}

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
void MacroAssembler::AssertFeedbackVector(Register object) {
  if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    CompareObjectType(object, scratch, scratch, FEEDBACK_VECTOR_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

// Optimized code is good, get it into the closure and link the closure
// into the optimized functions list, then tail call the optimized code.
void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure, Register scratch1,
    Register slot_address) {
  DCHECK(!AreAliased(optimized_code, closure, scratch1, slot_address));
  DCHECK_EQ(closure, kJSFunctionRegister);
  DCHECK(!AreAliased(optimized_code, closure));
  // Store code entry in the closure.
  StoreTaggedField(optimized_code,
                   FieldMemOperand(closure, JSFunction::kCodeOffset), r0);
  // Write barrier clobbers scratch1 below.
  Register value = scratch1;
  mov(value, optimized_code);

  RecordWriteField(closure, JSFunction::kCodeOffset, value, slot_address,
                   kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore,
                   SmiCheck::kOmit);
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  // ----------- S t a t e -------------
  //  -- r2 : actual argument count
  //  -- r3 : target function (preserved for callee)
  //  -- r5 : new target (preserved for callee)
  // -----------------------------------
  {
    FrameAndConstantPoolScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target and the actual
    // argument count.
    // Push function as parameter to the runtime call.
    SmiTag(kJavaScriptCallArgCountRegister);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister, kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    mov(r4, r2);

    // Restore target function, new target and actual argument count.
    Pop(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
        kJavaScriptCallArgCountRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }
  static_assert(kJavaScriptCallCodeStartRegister == r4, "ABI mismatch");
  JumpCodeObject(r4);
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
Condition MacroAssembler::LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  LoadU16(flags,
          FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  uint32_t kFlagsMask = FeedbackVector::kFlagsTieringStateIsAnyRequested |
                        FeedbackVector::kFlagsMaybeHasTurbofanCode |
                        FeedbackVector::kFlagsLogNextExecution;
  if (current_code_kind != CodeKind::MAGLEV) {
    kFlagsMask |= FeedbackVector::kFlagsMaybeHasMaglevCode;
  }
  CHECK(is_uint16(kFlagsMask));
  tmll(flags, Operand(kFlagsMask));
  return Condition(7);
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  b(LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(flags, feedback_vector,
                                                     current_code_kind),
    flags_need_processing);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, Register feedback_vector) {
  DCHECK(!AreAliased(flags, feedback_vector));
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available
  TestBitMask(flags, FeedbackVector::kFlagsTieringStateIsAnyRequested, r0);
  beq(&maybe_needs_logging);

  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  TestBitMask(flags, FeedbackVector::LogNextExecutionBit::kMask, r0);
  beq(&maybe_has_optimized_code);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = flags;
  LoadTaggedField(optimized_code_entry,
                  FieldMemOperand(feedback_vector,
                                  FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry, r1);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  // All parameters are on the stack.  r2 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  mov(r2, Operand(num_arguments));
  Move(r3, ExternalReference::Create(f));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    mov(r2, Operand(function->nargs));
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  Move(r3, builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  CmpS32(in, Operand(kClearedWeakHeapObjectLower32));
  beq(target_if_cleared);

  AndP(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK(value > 0 && is_int8(value));
  if (v8_flags.native_code_counters && counter->Enabled()) {
    Move(scratch2, ExternalReference::Create(counter));
    // @TODO(john.yan): can be optimized by asi()
    LoadS32(scratch1, MemOperand(scratch2));
    AddS64(scratch1, Operand(value));
    StoreU32(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK(value > 0 && is_int8(value));
  if (v8_flags.native_code_counters && counter->Enabled()) {
    Move(scratch2, ExternalReference::Create(counter));
    // @TODO(john.yan): can be optimized by asi()
    LoadS32(scratch1, MemOperand(scratch2));
    AddS64(scratch1, Operand(-value));
    StoreU32(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::Check(Condition cond, AbortReason reason, CRegister cr) {
  Label L;
  b(to_condition(cond), &L);
  Abort(reason);
  // will not return here
  bind(&L);
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
    lgfi(r2, Operand(static_cast<int>(reason)));
    PrepareCallCFunction(1, 0, r3);
#if V8_OS_ZOS
    CallCFunction(ExternalReference::abort_with_reason(), 1, 0);
#else
    Move(r3, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(r3);
#endif
    return;
  }

  LoadSmiLiteral(r3, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      LoadEntryFromBuiltin(Builtin::kAbort, ip);
      Call(ip);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }
  // will not return here
}

void MacroAssembler::LoadCompressedMap(Register destination, Register object) {
  CHECK(COMPRESS_POINTERS_BOOL);
  LoadU32(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  LoadTaggedField(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;

  // Load the feedback vector from the closure.
  LoadTaggedField(dst,
                  FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  LoadTaggedField(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  IsObjectType(dst, scratch, scratch, FEEDBACK_VECTOR_TYPE);
  b(eq, &done);

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  b(fbv_undef);

  bind(&done);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  LoadTaggedField(
      dst, FieldMemOperand(
               dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)));
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::Assert(Condition cond, AbortReason reason, CRegister cr) {
  if (v8_flags.debug_code) Check(cond, reason, cr);
}

void MacroAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}

void MacroAssembler::AssertZeroExtended(Register int32_register) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  mov(r0, Operand(kMaxUInt32));
  CmpS64(int32_register, r0);
  Check(le, AbortReason::k32BitValueInRegisterIsNotZeroExtended);
}

void MacroAssembler::AssertMap(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  TestIfSmi(object);
  Check(ne, AbortReason::kOperandIsNotAMap);
  Push(object);
  LoadMap(object, object);
  CompareInstanceType(object, object, MAP_TYPE);
  Pop(object);
  Check(eq, AbortReason::kOperandIsNotAMap);
}

void MacroAssembler::AssertNotSmi(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(ne, AbortReason::kOperandIsASmi, cr0);
  }
}

void MacroAssembler::AssertSmi(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(eq, AbortReason::kOperandIsNotASmi, cr0);
  }
}

void MacroAssembler::AssertConstructor(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor);
    LoadMap(scratch, object);
    tm(FieldMemOperand(scratch, Map::kBitFieldOffset),
       Operand(Map::Bits1::IsConstructorBit::kMask));
    Check(ne, AbortReason::kOperandIsNotAConstructor);
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, cr0);
    push(object);
    LoadMap(object, object);
    CompareInstanceTypeRange(object, object, object, FIRST_JS_FUNCTION_TYPE,
                             LAST_JS_FUNCTION_TYPE);
    pop(object);
    Check(le, AbortReason::kOperandIsNotAFunction);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  TestIfSmi(object);
  Check(ne, AbortReason::kOperandIsASmiAndNotAFunction);
  push(object);
  LoadMap(object, object);
  CompareInstanceTypeRange(object, object, object,
                           FIRST_CALLABLE_JS_FUNCTION_TYPE,
                           LAST_CALLABLE_JS_FUNCTION_TYPE);
  pop(object);
  Check(le, AbortReason::kOperandIsNotACallableFunction);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, cr0);
    push(object);
    IsObjectType(object, object, object, JS_BOUND_FUNCTION_TYPE);
    pop(object);
    Check(eq, AbortReason::kOperandIsNotABoundFunction);
  }
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  TestIfSmi(object);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, cr0);

  // Load map
  Register map = object;
  push(object);
  LoadMap(map, object);

  // Check if JSGeneratorObject
  Register scratch = object;
  CompareInstanceTypeRange(map, scratch, scratch,
                           FIRST_JS_GENERATOR_OBJECT_TYPE,
                           LAST_JS_GENERATOR_OBJECT_TYPE);
  // Restore generator object to register and perform assertion
  pop(object);
  Check(le, AbortReason::kOperandIsNotAGeneratorObject);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    Label done_checking;
    AssertNotSmi(object);
    CompareRoot(object, RootIndex::kUndefinedValue);
    beq(&done_checking, Label::kNear);
    LoadMap(scratch, object);
    CompareInstanceType(scratch, scratch, ALLOCATION_SITE_TYPE);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell);
    bind(&done_checking);
  }
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
  ble(&ok);

  CompareInstanceType(map_tmp, tmp, FIRST_JS_RECEIVER_TYPE);
  bge(&ok);

  CompareRoot(map_tmp, RootIndex::kHeapNumberMap);
  beq(&ok);

  CompareRoot(map_tmp, RootIndex::kBigIntMap);
  beq(&ok);

  CompareRoot(object, RootIndex::kUndefinedValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kTrueValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kFalseValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kNullValue);
  beq(&ok);

  Abort(abort_reason);

  bind(&ok);
}

#endif  // V8_ENABLE_DEBUG_CODE

int MacroAssembler::CalculateStackPassedWords(int num_reg_arguments,
                                              int num_double_arguments) {
  int stack_passed_words = 0;
  if (num_double_arguments > DoubleRegister::kNumRegisters) {
    stack_passed_words +=
        2 * (num_double_arguments - DoubleRegister::kNumRegisters);
  }
  // Up to five simple arguments are passed in registers r2..r6
  if (num_reg_arguments > kRegisterPassedArguments) {
    stack_passed_words += num_reg_arguments - kRegisterPassedArguments;
  }
  return stack_passed_words;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  int frame_alignment = ActivationFrameAlignment();
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  int stack_space = kNumRequiredStackFrameSlots;
  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for stack arguments
    // -- preserving original value of sp.
    mov(scratch, sp);
    lay(sp, MemOperand(sp, -(stack_passed_arguments + 1) * kSystemPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    ClearRightImm(sp, sp,
                  Operand(base::bits::WhichPowerOfTwo(frame_alignment)));
    StoreU64(scratch,
             MemOperand(sp, (stack_passed_arguments)*kSystemPointerSize));
  } else {
    stack_space += stack_passed_arguments;
  }
  lay(sp, MemOperand(sp, (-stack_space) * kSystemPointerSize));
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

void MacroAssembler::MovToFloatParameter(DoubleRegister src) { Move(d0, src); }

void MacroAssembler::MovToFloatResult(DoubleRegister src) { Move(d0, src); }

void MacroAssembler::MovToFloatParameters(DoubleRegister src1,
                                          DoubleRegister src2) {
  if (src2 == d0) {
    DCHECK(src1 != d2);
    Move(d2, src2);
    Move(d0, src1);
  } else {
    Move(d0, src1);
    Move(d2, src2);
  }
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor,
                                  Label* return_label) {
  Move(ip, function);
  return CallCFunction(ip, num_reg_arguments, num_double_arguments,
                       set_isolate_data_slots, has_function_descriptor,
                       return_label);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor,
                                  Label* return_label) {
  ASM_CODE_COMMENT(this);
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());

#if V8_OS_ZOS
  // Shuffle input arguments
  mov(r1, r2);
  mov(r2, r3);
  mov(r3, r4);

  // XPLINK treats r7 as voliatile return register, but r14 as preserved
  // Since Linux is the other way around, perserve r7 value in r14 across
  // the call.
  mov(r14, r7);

  // XPLINK linkage requires args in r5,r6,r7,r8,r9 to be passed on the stack.
  // However, for DirectAPI C calls, there may not be stack slots
  // for these 4th and 5th parameters if num_reg_arguments are less
  // than 3.  In that case, we need to still preserve r5/r6 into
  // register save area, as they are considered volatile in XPLINK.
  if (num_reg_arguments == 4) {
    StoreU64(r5, MemOperand(sp, 19 * kSystemPointerSize));
    StoreU64(r6, MemOperand(sp, 6 * kSystemPointerSize));
  } else if (num_reg_arguments >= 5) {
    // Save original r5 - r6  to Stack, r7 - r9 already saved to Stack
    StoreMultipleP(r5, r6, MemOperand(sp, 19 * kSystemPointerSize));
  } else {
    StoreMultipleP(r5, r6, MemOperand(sp, 5 * kSystemPointerSize));
  }
#endif

  Label get_pc;

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // Save the frame pointer and PC so that the stack layout remains iterable,
    // even without an ExitFrame which normally exists between JS and C frames.
    // See x64 code for reasoning about how to address the isolate data fields.
    larl(r0, &get_pc);
    CHECK(root_array_available());
    StoreU64(r0,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
    StoreU64(fp,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

#if V8_OS_ZOS
  // Set up the system stack pointer with the XPLINK bias.
  lay(r4, MemOperand(sp, -kStackPointerBias));

  Register dest = function;
  if (has_function_descriptor) {
    LoadMultipleP(r5, r6, MemOperand(function));
    dest = r6;
  }
#else
  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  Register dest = function;
  if (ABI_CALL_VIA_IP) {
    Move(ip, function);
    dest = ip;
  }
#endif

#if V8_OS_ZOS
  if (has_function_descriptor) {
    // Branch to target via indirect branch
    basr(r7, dest);
    nop(BASR_CALL_TYPE_NOP);
  } else {
    basr(r7, dest);
  }

  // Restore r5-r9 from the appropriate stack locations (see notes above).
  if (num_reg_arguments == 4) {
    LoadU64(r5, MemOperand(sp, 19 * kSystemPointerSize));
    LoadU64(r6, MemOperand(sp, 6 * kSystemPointerSize));
  } else if (num_reg_arguments >= 5) {
    LoadMultipleP(r5, r6, MemOperand(sp, 19 * kSystemPointerSize));
  } else {
    LoadMultipleP(r5, r6, MemOperand(sp, 5 * kSystemPointerSize));
  }

  // Restore original r7
  mov(r7, r14);

  // Shuffle the result
  mov(r2, r3);
#else
  Call(dest);
#endif

  int call_pc_offset = pc_offset();
  bind(&get_pc);
  if (return_label) bind(return_label);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    Register zero_scratch = r0;
    lghi(zero_scratch, Operand::Zero());

    StoreU64(zero_scratch,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  int stack_space = kNumRequiredStackFrameSlots + stack_passed_arguments;
  if (ActivationFrameAlignment() > kSystemPointerSize) {
    // Load the original stack pointer (pre-alignment) from the stack
    LoadU64(sp, MemOperand(sp, stack_space * kSystemPointerSize));
  } else {
    la(sp, MemOperand(sp, stack_space * kSystemPointerSize));
  }

  return call_pc_offset;
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor,
                                  Label* return_label) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       has_function_descriptor, return_label);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor,
                                  Label* return_label) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       has_function_descriptor, return_label);
}

void MacroAssembler::CheckPageFlag(
    Register object,
    Register scratch,  // scratch may be same register as object
    int mask, Condition cc, Label* condition_met) {
  DCHECK(cc == ne || cc == eq);
  ClearRightImm(scratch, object, Operand(kPageSizeBits));

  if (base::bits::IsPowerOfTwo(mask)) {
    // If it's a power of two, we can use Test-Under-Mask Memory-Imm form
    // which allows testing of a single byte in memory.
    int32_t byte_offset = 4;
    uint32_t shifted_mask = mask;
    // Determine the byte offset to be tested
    if (mask <= 0x80) {
      byte_offset = kSystemPointerSize - 1;
    } else if (mask < 0x8000) {
      byte_offset = kSystemPointerSize - 2;
      shifted_mask = mask >> 8;
    } else if (mask < 0x800000) {
      byte_offset = kSystemPointerSize - 3;
      shifted_mask = mask >> 16;
    } else {
      byte_offset = kSystemPointerSize - 4;
      shifted_mask = mask >> 24;
    }
#if V8_TARGET_LITTLE_ENDIAN
    // Reverse the byte_offset if emulating on little endian platform
    byte_offset = kSystemPointerSize - byte_offset - 1;
#endif
    tm(MemOperand(scratch, MemoryChunk::FlagsOffset() + byte_offset),
       Operand(shifted_mask));
  } else {
    LoadU64(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
    AndP(r0, scratch, Operand(mask));
  }
  // Should be okay to remove rc

  if (cc == ne) {
    bne(condition_met);
  }
  if (cc == eq) {
    beq(condition_met);
  }
}

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2, Register reg3,
                                   Register reg4, Register reg5,
                                   Register reg6) {
  RegList regs = {reg1, reg2, reg3, reg4, reg5, reg6};

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    Register candidate = Register::from_code(code);
    if (regs.has(candidate)) continue;
    return candidate;
  }
  UNREACHABLE();
}

void MacroAssembler::mov(Register dst, Register src) { lgr(dst, src); }

void MacroAssembler::mov(Register dst, const Operand& src) {
  int64_t value = 0;

  if (src.is_heap_number_request()) {
    RequestHeapNumber(src.heap_number_request());
  } else {
    value = src.immediate();
  }

  if (src.rmode() != RelocInfo::NO_INFO) {
    // some form of relocation needed
    RecordRelocInfo(src.rmode(), value);
  }

  int32_t hi_32 = static_cast<int32_t>(value >> 32);
  int32_t lo_32 = static_cast<int32_t>(value);

  if (src.rmode() == RelocInfo::NO_INFO) {
    if (hi_32 == 0) {
      if (is_uint16(lo_32)) {
        llill(dst, Operand(lo_32));
        return;
      }
      llilf(dst, Operand(lo_32));
      return;
    } else if (lo_32 == 0) {
      if (is_uint16(hi_32)) {
        llihl(dst, Operand(hi_32));
        return;
      }
      llihf(dst, Operand(hi_32));
      return;
    } else if (is_int16(value)) {
      lghi(dst, Operand(value));
      return;
    } else if (is_int32(value)) {
      lgfi(dst, Operand(value));
      return;
    }
  } else if (src.rmode() == RelocInfo::WASM_CANONICAL_SIG_ID) {
    CHECK(is_int32(value));
    // If this is changed then also change `uint32_constant_at` and
    // `set_uint32_constant_at`.
    lgfi(dst, Operand(value));
    return;
  }

  iihf(dst, Operand(hi_32));
  iilf(dst, Operand(lo_32));
}

void MacroAssembler::MulS32(Register dst, const MemOperand& src1) {
  if (is_uint12(src1.offset())) {
    ms(dst, src1);
  } else if (is_int20(src1.offset())) {
    msy(dst, src1);
  } else {
    UNIMPLEMENTED();
  }
}

void MacroAssembler::MulS32(Register dst, Register src1) { msr(dst, src1); }

void MacroAssembler::MulS32(Register dst, const Operand& src1) {
  msfi(dst, src1);
}

#define Generate_MulHigh32(instr) \
  {                               \
    lgfr(dst, src1);              \
    instr(dst, src2);             \
    srlg(dst, dst, Operand(32));  \
  }

void MacroAssembler::MulHighS32(Register dst, Register src1,
                                const MemOperand& src2) {
  Generate_MulHigh32(msgf);
}

void MacroAssembler::MulHighS32(Register dst, Register src1, Register src2) {
  if (dst == src2) {
    std::swap(src1, src2);
  }
  Generate_MulHigh32(msgfr);
}

void MacroAssembler::MulHighS32(Register dst, Register src1,
                                const Operand& src2) {
  Generate_MulHigh32(msgfi);
}

#undef Generate_MulHigh32

#define Generate_MulHighU32(instr) \
  {                                \
    lr(r1, src1);                  \
    instr(r0, src2);               \
    LoadU32(dst, r0);              \
  }

void MacroAssembler::MulHighU32(Register dst, Register src1,
                                const MemOperand& src2) {
  Generate_MulHighU32(ml);
}

void MacroAssembler::MulHighU32(Register dst, Register src1, Register src2) {
  Generate_MulHighU32(mlr);
}

void MacroAssembler::MulHighU32(Register dst, Register src1,
                                const Operand& src2) {
  USE(dst);
  USE(src1);
  USE(src2);
  UNREACHABLE();
}

#undef Generate_MulHighU32

#define Generate_Mul32WithOverflowIfCCUnequal(instr) \
  {                                                  \
    lgfr(dst, src1);                                 \
    instr(dst, src2);                                \
    cgfr(dst, dst);                                  \
  }

void MacroAssembler::Mul32WithOverflowIfCCUnequal(Register dst, Register src1,
                                                  const MemOperand& src2) {
  Register result = dst;
  if (src2.rx() == dst || src2.rb() == dst) dst = r0;
  Generate_Mul32WithOverflowIfCCUnequal(msgf);
  if (result != dst) llgfr(result, dst);
}

void MacroAssembler::Mul32WithOverflowIfCCUnequal(Register dst, Register src1,
                                                  Register src2) {
  if (dst == src2) {
    std::swap(src1, src2);
  }
  Generate_Mul32WithOverflowIfCCUnequal(msgfr);
}

void MacroAssembler::Mul32WithOverflowIfCCUnequal(Register dst, Register src1,
                                                  const Operand& src2) {
  Generate_Mul32WithOverflowIfCCUnequal(msgfi);
}

#undef Generate_Mul32WithOverflowIfCCUnequal

#define Generate_Div32(instr) \
  {                           \
    lgfr(r1, src1);           \
    instr(r0, src2);          \
    LoadU32(dst, r1);         \
  }

void MacroAssembler::DivS32(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_Div32(dsgf);
}

void MacroAssembler::DivS32(Register dst, Register src1, Register src2) {
  Generate_Div32(dsgfr);
}

#undef Generate_Div32

#define Generate_DivU32(instr) \
  {                            \
    lr(r0, src1);              \
    srdl(r0, Operand(32));     \
    instr(r0, src2);           \
    LoadU32(dst, r1);          \
  }

void MacroAssembler::DivU32(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_DivU32(dl);
}

void MacroAssembler::DivU32(Register dst, Register src1, Register src2) {
  Generate_DivU32(dlr);
}

#undef Generate_DivU32

#define Generate_Div64(instr) \
  {                           \
    lgr(r1, src1);            \
    instr(r0, src2);          \
    lgr(dst, r1);             \
  }

void MacroAssembler::DivS64(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_Div64(dsg);
}

void MacroAssembler::DivS64(Register dst, Register src1, Register src2) {
  Generate_Div64(dsgr);
}

#undef Generate_Div64

#define Generate_DivU64(instr) \
  {                            \
    lgr(r1, src1);             \
    lghi(r0, Operand::Zero()); \
    instr(r0, src2);           \
    lgr(dst, r1);              \
  }

void MacroAssembler::DivU64(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_DivU64(dlg);
}

void MacroAssembler::DivU64(Register dst, Register src1, Register src2) {
  Generate_DivU64(dlgr);
}

#undef Generate_DivU64

#define Generate_Mod32(instr) \
  {                           \
    lgfr(r1, src1);           \
    instr(r0, src2);          \
    LoadU32(dst, r0);         \
  }

void MacroAssembler::ModS32(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_Mod32(dsgf);
}

void MacroAssembler::ModS32(Register dst, Register src1, Register src2) {
  Generate_Mod32(dsgfr);
}

#undef Generate_Mod32

#define Generate_ModU32(instr) \
  {                            \
    lr(r0, src1);              \
    srdl(r0, Operand(32));     \
    instr(r0, src2);           \
    LoadU32(dst, r0);          \
  }

void MacroAssembler::ModU32(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_ModU32(dl);
}

void MacroAssembler::ModU32(Register dst, Register src1, Register src2) {
  Generate_ModU32(dlr);
}

#undef Generate_ModU32

#define Generate_Mod64(instr) \
  {                           \
    lgr(r1, src1);            \
    instr(r0, src2);          \
    lgr(dst, r0);             \
  }

void MacroAssembler::ModS64(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_Mod64(dsg);
}

void MacroAssembler::ModS64(Register dst, Register src1, Register src2) {
  Generate_Mod64(dsgr);
}

#undef Generate_Mod64

#define Generate_ModU64(instr) \
  {                            \
    lgr(r1, src1);             \
    lghi(r0, Operand::Zero()); \
    instr(r0, src2);           \
    lgr(dst, r0);              \
  }

void MacroAssembler::ModU64(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_ModU64(dlg);
}

void MacroAssembler::ModU64(Register dst, Register src1, Register src2) {
  Generate_ModU64(dlgr);
}

#undef Generate_ModU64

void MacroAssembler::MulS64(Register dst, const Operand& opnd) {
  msgfi(dst, opnd);
}

void MacroAssembler::MulS64(Register dst, Register src) { msgr(dst, src); }

void MacroAssembler::MulS64(Register dst, const MemOperand& opnd) {
  msg(dst, opnd);
}

void MacroAssembler::MulHighS64(Register dst, Register src1, Register src2) {
  if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
    mgrk(r0, src1, src2);
    lgr(dst, r0);
  } else {
    SaveFPRegsMode fp_mode = SaveFPRegsMode::kSave;
    PushCallerSaved(fp_mode, ip);
    Push(src1, src2);
    Pop(r2, r3);
    {
      FrameScope scope(this, StackFrame::INTERNAL);
      PrepareCallCFunction(2, 0, r0);
      CallCFunction(ExternalReference::int64_mul_high_function(), 2, 0);
    }
    mov(r0, r2);
    PopCallerSaved(fp_mode, ip);
    mov(dst, r0);
  }
}

void MacroAssembler::MulHighS64(Register dst, Register src1,
                                const MemOperand& src2) {
  // TODO(v8): implement this.
  UNIMPLEMENTED();
}

void MacroAssembler::MulHighU64(Register dst, Register src1, Register src2) {
  lgr(r1, src1);
  mlgr(r0, src2);
  lgr(dst, r0);
}

void MacroAssembler::MulHighU64(Register dst, Register src1,
                                const MemOperand& src2) {
  // TODO(v8): implement this.
  UNIMPLEMENTED();
}

void MacroAssembler::Sqrt(DoubleRegister result, DoubleRegister input) {
  sqdbr(result, input);
}
void MacroAssembler::Sqrt(DoubleRegister result, const MemOperand& input) {
  if (is_uint12(input.offset())) {
    sqdb(result, input);
  } else {
    ldy(result, input);
    sqdbr(result, result);
  }
}
//----------------------------------------------------------------------------
//  Add Instructions
//----------------------------------------------------------------------------

// Add 32-bit (Register dst = Register dst + Immediate opnd)
void MacroAssembler::AddS32(Register dst, const Operand& opnd) {
  if (is_int16(opnd.immediate()))
    ahi(dst, opnd);
  else
    afi(dst, opnd);
}

// Add Pointer Size (Register dst = Register dst + Immediate opnd)
void MacroAssembler::AddS64(Register dst, const Operand& opnd) {
  if (is_int16(opnd.immediate()))
    aghi(dst, opnd);
  else
    agfi(dst, opnd);
}

void MacroAssembler::AddS32(Register dst, Register src, int32_t opnd) {
  AddS32(dst, src, Operand(opnd));
}

// Add 32-bit (Register dst = Register src + Immediate opnd)
void MacroAssembler::AddS32(Register dst, Register src, const Operand& opnd) {
  if (dst != src) {
    if (CpuFeatures::IsSupported(DISTINCT_OPS) && is_int16(opnd.immediate())) {
      ahik(dst, src, opnd);
      return;
    }
    lr(dst, src);
  }
  AddS32(dst, opnd);
}

void MacroAssembler::AddS64(Register dst, Register src, int32_t opnd) {
  AddS64(dst, src, Operand(opnd));
}

// Add Pointer Size (Register dst = Register src + Immediate opnd)
void MacroAssembler::AddS64(Register dst, Register src, const Operand& opnd) {
  if (dst != src) {
    if (CpuFeatures::IsSupported(DISTINCT_OPS) && is_int16(opnd.immediate())) {
      aghik(dst, src, opnd);
      return;
    }
    mov(dst, src);
  }
  AddS64(dst, opnd);
}

// Add 32-bit (Register dst = Register dst + Register src)
void MacroAssembler::AddS32(Register dst, Register src) { ar(dst, src); }

// Add Pointer Size (Register dst = Register dst + Register src)
void MacroAssembler::AddS64(Register dst, Register src) { agr(dst, src); }

// Add 32-bit (Register dst = Register src1 + Register src2)
void MacroAssembler::AddS32(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate AR/AGR, over the non clobbering ARK/AGRK
    // as AR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      ark(dst, src1, src2);
      return;
    } else {
      lr(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  ar(dst, src2);
}

// Add Pointer Size (Register dst = Register src1 + Register src2)
void MacroAssembler::AddS64(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate AR/AGR, over the non clobbering ARK/AGRK
    // as AR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      agrk(dst, src1, src2);
      return;
    } else {
      mov(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  agr(dst, src2);
}

// Add 32-bit (Register-Memory)
void MacroAssembler::AddS32(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    a(dst, opnd);
  else
    ay(dst, opnd);
}

// Add Pointer Size (Register-Memory)
void MacroAssembler::AddS64(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  ag(dst, opnd);
}

// Add 32-bit (Memory - Immediate)
void MacroAssembler::AddS32(const MemOperand& opnd, const Operand& imm) {
  DCHECK(is_int8(imm.immediate()));
  DCHECK(is_int20(opnd.offset()));
  DCHECK(CpuFeatures::IsSupported(GENERAL_INSTR_EXT));
  asi(opnd, imm);
}

// Add Pointer-sized (Memory - Immediate)
void MacroAssembler::AddS64(const MemOperand& opnd, const Operand& imm) {
  DCHECK(is_int8(imm.immediate()));
  DCHECK(is_int20(opnd.offset()));
  DCHECK(CpuFeatures::IsSupported(GENERAL_INSTR_EXT));
  agsi(opnd, imm);
}

//----------------------------------------------------------------------------
//  Add Logical Instructions
//----------------------------------------------------------------------------

// Add Logical 32-bit (Register dst = Register src1 + Register src2)
void MacroAssembler::AddU32(Register dst, Register src1, Register src2) {
  if (dst != src2 && dst != src1) {
    lr(dst, src1);
    alr(dst, src2);
  } else if (dst != src2) {
    // dst == src1
    DCHECK(dst == src1);
    alr(dst, src2);
  } else {
    // dst == src2
    DCHECK(dst == src2);
    alr(dst, src1);
  }
}

// Add Logical 32-bit (Register dst = Register dst + Immediate opnd)
void MacroAssembler::AddU32(Register dst, const Operand& imm) {
  alfi(dst, imm);
}

// Add Logical Pointer Size (Register dst = Register dst + Immediate opnd)
void MacroAssembler::AddU64(Register dst, const Operand& imm) {
  algfi(dst, imm);
}

void MacroAssembler::AddU64(Register dst, Register src1, Register src2) {
  if (dst != src2 && dst != src1) {
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      algrk(dst, src1, src2);
    } else {
      lgr(dst, src1);
      algr(dst, src2);
    }
  } else if (dst != src2) {
    // dst == src1
    DCHECK(dst == src1);
    algr(dst, src2);
  } else {
    // dst == src2
    DCHECK(dst == src2);
    algr(dst, src1);
  }
}

// Add Logical 32-bit (Register-Memory)
void MacroAssembler::AddU32(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    al_z(dst, opnd);
  else
    aly(dst, opnd);
}

// Add Logical Pointer Size (Register-Memory)
void MacroAssembler::AddU64(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  alg(dst, opnd);
}

//----------------------------------------------------------------------------
//  Subtract Instructions
//----------------------------------------------------------------------------

// Subtract Logical 32-bit (Register dst = Register src1 - Register src2)
void MacroAssembler::SubU32(Register dst, Register src1, Register src2) {
  if (dst != src2 && dst != src1) {
    lr(dst, src1);
    slr(dst, src2);
  } else if (dst != src2) {
    // dst == src1
    DCHECK(dst == src1);
    slr(dst, src2);
  } else {
    // dst == src2
    DCHECK(dst == src2);
    lr(r0, dst);
    SubU32(dst, src1, r0);
  }
}

// Subtract 32-bit (Register dst = Register dst - Immediate opnd)
void MacroAssembler::SubS32(Register dst, const Operand& imm) {
  AddS32(dst, Operand(-(imm.immediate())));
}

// Subtract Pointer Size (Register dst = Register dst - Immediate opnd)
void MacroAssembler::SubS64(Register dst, const Operand& imm) {
  AddS64(dst, Operand(-(imm.immediate())));
}

void MacroAssembler::SubS32(Register dst, Register src, int32_t imm) {
  SubS32(dst, src, Operand(imm));
}

// Subtract 32-bit (Register dst = Register src - Immediate opnd)
void MacroAssembler::SubS32(Register dst, Register src, const Operand& imm) {
  AddS32(dst, src, Operand(-(imm.immediate())));
}

void MacroAssembler::SubS64(Register dst, Register src, int32_t imm) {
  SubS64(dst, src, Operand(imm));
}

// Subtract Pointer Sized (Register dst = Register src - Immediate opnd)
void MacroAssembler::SubS64(Register dst, Register src, const Operand& imm) {
  AddS64(dst, src, Operand(-(imm.immediate())));
}

// Subtract 32-bit (Register dst = Register dst - Register src)
void MacroAssembler::SubS32(Register dst, Register src) { sr(dst, src); }

// Subtract Pointer Size (Register dst = Register dst - Register src)
void MacroAssembler::SubS64(Register dst, Register src) { sgr(dst, src); }

// Subtract 32-bit (Register = Register - Register)
void MacroAssembler::SubS32(Register dst, Register src1, Register src2) {
  // Use non-clobbering version if possible
  if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    srk(dst, src1, src2);
    return;
  }
  if (dst != src1 && dst != src2) lr(dst, src1);
  // In scenario where we have dst = src - dst, we need to swap and negate
  if (dst != src1 && dst == src2) {
    Label done;
    lcr(dst, dst);  // dst = -dst
    b(overflow, &done);
    ar(dst, src1);  // dst = dst + src
    bind(&done);
  } else {
    sr(dst, src2);
  }
}

// Subtract Pointer Sized (Register = Register - Register)
void MacroAssembler::SubS64(Register dst, Register src1, Register src2) {
  // Use non-clobbering version if possible
  if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    sgrk(dst, src1, src2);
    return;
  }
  if (dst != src1 && dst != src2) mov(dst, src1);
  // In scenario where we have dst = src - dst, we need to swap and negate
  if (dst != src1 && dst == src2) {
    Label done;
    lcgr(dst, dst);  // dst = -dst
    b(overflow, &done);
    AddS64(dst, src1);  // dst = dst + src
    bind(&done);
  } else {
    SubS64(dst, src2);
  }
}

// Subtract 32-bit (Register-Memory)
void MacroAssembler::SubS32(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    s(dst, opnd);
  else
    sy(dst, opnd);
}

// Subtract Pointer Sized (Register - Memory)
void MacroAssembler::SubS64(Register dst, const MemOperand& opnd) {
  sg(dst, opnd);
}

void MacroAssembler::MovIntToFloat(DoubleRegister dst, Register src) {
  sllg(r0, src, Operand(32));
  ldgr(dst, r0);
}

void MacroAssembler::MovFloatToInt(Register dst, DoubleRegister src) {
  lgdr(dst, src);
  srlg(dst, dst, Operand(32));
}

// Load And Subtract 32-bit (similar to laa/lan/lao/lax)
void MacroAssembler::LoadAndSub32(Register dst, Register src,
                                  const MemOperand& opnd) {
  lcr(dst, src);
  laa(dst, dst, opnd);
}

void MacroAssembler::LoadAndSub64(Register dst, Register src,
                                  const MemOperand& opnd) {
  lcgr(dst, src);
  laag(dst, dst, opnd);
}

//----------------------------------------------------------------------------
//  Subtract Logical Instructions
//----------------------------------------------------------------------------

// Subtract Logical 32-bit (Register - Memory)
void MacroAssembler::SubU32(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    sl(dst, opnd);
  else
    sly(dst, opnd);
}

// Subtract Logical Pointer Sized (Register - Memory)
void MacroAssembler::SubU64(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  slgf(dst, opnd);
}

//----------------------------------------------------------------------------
//  Bitwise Operations
//----------------------------------------------------------------------------

// AND 32-bit - dst = dst & src
void MacroAssembler::And(Register dst, Register src) { nr(dst, src); }

// AND Pointer Size - dst = dst & src
void MacroAssembler::AndP(Register dst, Register src) { ngr(dst, src); }

// Non-clobbering AND 32-bit - dst = src1 & src1
void MacroAssembler::And(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      nrk(dst, src1, src2);
      return;
    } else {
      lr(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  And(dst, src2);
}

// Non-clobbering AND pointer size - dst = src1 & src1
void MacroAssembler::AndP(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      ngrk(dst, src1, src2);
      return;
    } else {
      mov(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  AndP(dst, src2);
}

// AND 32-bit (Reg - Mem)
void MacroAssembler::And(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    n(dst, opnd);
  else
    ny(dst, opnd);
}

// AND Pointer Size (Reg - Mem)
void MacroAssembler::AndP(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  ng(dst, opnd);
}

// AND 32-bit - dst = dst & imm
void MacroAssembler::And(Register dst, const Operand& opnd) { nilf(dst, opnd); }

// AND Pointer Size - dst = dst & imm
void MacroAssembler::AndP(Register dst, const Operand& opnd) {
  intptr_t value = opnd.immediate();
  if (value >> 32 != -1) {
    // this may not work b/c condition code won't be set correctly
    nihf(dst, Operand(value >> 32));
  }
  nilf(dst, Operand(value & 0xFFFFFFFF));
}

// AND 32-bit - dst = src & imm
void MacroAssembler::And(Register dst, Register src, const Operand& opnd) {
  if (dst != src) lr(dst, src);
  nilf(dst, opnd);
}

// AND Pointer Size - dst = src & imm
void MacroAssembler::AndP(Register dst, Register src, const Operand& opnd) {
  // Try to exploit RISBG first
  intptr_t value = opnd.immediate();
  if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
    intptr_t shifted_value = value;
    int trailing_zeros = 0;

    // We start checking how many trailing zeros are left at the end.
    while ((0 != shifted_value) && (0 == (shifted_value & 1))) {
      trailing_zeros++;
      shifted_value >>= 1;
    }

    // If temp (value with right-most set of zeros shifted out) is 1 less
    // than power of 2, we have consecutive bits of 1.
    // Special case: If shift_value is zero, we cannot use RISBG, as it requires
    //               selection of at least 1 bit.
    if ((0 != shifted_value) && base::bits::IsPowerOfTwo(shifted_value + 1)) {
      int startBit =
          base::bits::CountLeadingZeros64(shifted_value) - trailing_zeros;
      int endBit = 63 - trailing_zeros;
      // Start: startBit, End: endBit, Shift = 0, true = zero unselected bits.
      RotateInsertSelectBits(dst, src, Operand(startBit), Operand(endBit),
                             Operand::Zero(), true);
      return;
    } else if (-1 == shifted_value) {
      // A Special case in which all top bits up to MSB are 1's.  In this case,
      // we can set startBit to be 0.
      int endBit = 63 - trailing_zeros;
      RotateInsertSelectBits(dst, src, Operand::Zero(), Operand(endBit),
                             Operand::Zero(), true);
      return;
    }
  }

  // If we are &'ing zero, we can just whack the dst register and skip copy
  if (dst != src && (0 != value)) mov(dst, src);
  AndP(dst, opnd);
}

// OR 32-bit - dst = dst & src
void MacroAssembler::Or(Register dst, Register src) { or_z(dst, src); }

// OR Pointer Size - dst = dst & src
void MacroAssembler::OrP(Register dst, Register src) { ogr(dst, src); }

// Non-clobbering OR 32-bit - dst = src1 & src1
void MacroAssembler::Or(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      ork(dst, src1, src2);
      return;
    } else {
      lr(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  Or(dst, src2);
}

// Non-clobbering OR pointer size - dst = src1 & src1
void MacroAssembler::OrP(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      ogrk(dst, src1, src2);
      return;
    } else {
      mov(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  OrP(dst, src2);
}

// OR 32-bit (Reg - Mem)
void MacroAssembler::Or(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    o(dst, opnd);
  else
    oy(dst, opnd);
}

// OR Pointer Size (Reg - Mem)
void MacroAssembler::OrP(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  og(dst, opnd);
}

// OR 32-bit - dst = dst & imm
void MacroAssembler::Or(Register dst, const Operand& opnd) { oilf(dst, opnd); }

// OR Pointer Size - dst = dst & imm
void MacroAssembler::OrP(Register dst, const Operand& opnd) {
  intptr_t value = opnd.immediate();
  if (value >> 32 != 0) {
    // this may not work b/c condition code won't be set correctly
    oihf(dst, Operand(value >> 32));
  }
  oilf(dst, Operand(value & 0xFFFFFFFF));
}

// OR 32-bit - dst = src & imm
void MacroAssembler::Or(Register dst, Register src, const Operand& opnd) {
  if (dst != src) lr(dst, src);
  oilf(dst, opnd);
}

// OR Pointer Size - dst = src & imm
void MacroAssembler::OrP(Register dst, Register src, const Operand& opnd) {
  if (dst != src) mov(dst, src);
  OrP(dst, opnd);
}

// XOR 32-bit - dst = dst & src
void MacroAssembler::Xor(Register dst, Register src) { xr(dst, src); }

// XOR Pointer Size - dst = dst & src
void MacroAssembler::XorP(Register dst, Register src) { xgr(dst, src); }

// Non-clobbering XOR 32-bit - dst = src1 & src1
void MacroAssembler::Xor(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      xrk(dst, src1, src2);
      return;
    } else {
      lr(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  Xor(dst, src2);
}

// Non-clobbering XOR pointer size - dst = src1 & src1
void MacroAssembler::XorP(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      xgrk(dst, src1, src2);
      return;
    } else {
      mov(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  XorP(dst, src2);
}

// XOR 32-bit (Reg - Mem)
void MacroAssembler::Xor(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    x(dst, opnd);
  else
    xy(dst, opnd);
}

// XOR Pointer Size (Reg - Mem)
void MacroAssembler::XorP(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  xg(dst, opnd);
}

// XOR 32-bit - dst = dst & imm
void MacroAssembler::Xor(Register dst, const Operand& opnd) { xilf(dst, opnd); }

// XOR Pointer Size - dst = dst & imm
void MacroAssembler::XorP(Register dst, const Operand& opnd) {
  intptr_t value = opnd.immediate();
  xihf(dst, Operand(value >> 32));
  xilf(dst, Operand(value & 0xFFFFFFFF));
}

// XOR 32-bit - dst = src & imm
void MacroAssembler::Xor(Register dst, Register src, const Operand& opnd) {
  if (dst != src) lr(dst, src);
  xilf(dst, opnd);
}

// XOR Pointer Size - dst = src & imm
void MacroAssembler::XorP(Register dst, Register src, const Operand& opnd) {
  if (dst != src) mov(dst, src);
  XorP(dst, opnd);
}

void MacroAssembler::Not32(Register dst, Register src) {
  if (src != no_reg && src != dst) lr(dst, src);
  xilf(dst, Operand(0xFFFFFFFF));
}

void MacroAssembler::Not64(Register dst, Register src) {
  if (src != no_reg && src != dst) lgr(dst, src);
  xihf(dst, Operand(0xFFFFFFFF));
  xilf(dst, Operand(0xFFFFFFFF));
}

void MacroAssembler::NotP(Register dst, Register src) {
  Not64(dst, src);
}

void MacroAssembler::LoadPositiveP(Register result, Register input) {
  lpgr(result, input);
}

void MacroAssembler::LoadPositive32(Register result, Register input) {
  lpr(result, input);
  lgfr(result, result);
}

//-----------------------------------------------------------------------------
//  Compare Helpers
//-----------------------------------------------------------------------------

// Compare 32-bit Register vs Register
void MacroAssembler::CmpS32(Register src1, Register src2) { cr_z(src1, src2); }

// Compare Pointer Sized Register vs Register
void MacroAssembler::CmpS64(Register src1, Register src2) { cgr(src1, src2); }

// Compare 32-bit Register vs Immediate
// This helper will set up proper relocation entries if required.
void MacroAssembler::CmpS32(Register dst, const Operand& opnd) {
  if (opnd.rmode() == RelocInfo::NO_INFO) {
    intptr_t value = opnd.immediate();
    if (is_int16(value))
      chi(dst, opnd);
    else
      cfi(dst, opnd);
  } else {
    // Need to generate relocation record here
    RecordRelocInfo(opnd.rmode(), opnd.immediate());
    cfi(dst, opnd);
  }
}

// Compare Pointer Sized  Register vs Immediate
// This helper will set up proper relocation entries if required.
void MacroAssembler::CmpS64(Register dst, const Operand& opnd) {
  if (opnd.rmode() == RelocInfo::NO_INFO) {
    cgfi(dst, opnd);
  } else {
    mov(r0, opnd);  // Need to generate 64-bit relocation
    cgr(dst, r0);
  }
}

// Compare 32-bit Register vs Memory
void MacroAssembler::CmpS32(Register dst, const MemOperand& opnd) {
  // make sure offset is within 20 bit range
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    c(dst, opnd);
  else
    cy(dst, opnd);
}

// Compare Pointer Size Register vs Memory
void MacroAssembler::CmpS64(Register dst, const MemOperand& opnd) {
  // make sure offset is within 20 bit range
  DCHECK(is_int20(opnd.offset()));
  cg(dst, opnd);
}

void MacroAssembler::CmpF32(DoubleRegister src1, DoubleRegister src2) {
  cebr(src1, src2);
}

void MacroAssembler::CmpF64(DoubleRegister src1, DoubleRegister src2) {
  cdbr(src1, src2);
}

void MacroAssembler::CmpF32(DoubleRegister src1, const MemOperand& src2) {
  DCHECK(is_int12(src2.offset()));
  ceb(src1, src2);
}

void MacroAssembler::CmpF64(DoubleRegister src1, const MemOperand& src2) {
  DCHECK(is_int12(src2.offset()));
  cdb(src1, src2);
}

// Using cs or scy based on the offset
void MacroAssembler::CmpAndSwap(Register old_val, Register new_val,
                                const MemOperand& opnd) {
  if (is_uint12(opnd.offset())) {
    cs(old_val, new_val, opnd);
  } else {
    csy(old_val, new_val, opnd);
  }
}

void MacroAssembler::CmpAndSwap64(Register old_val, Register new_val,
                                  const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  csg(old_val, new_val, opnd);
}

//-----------------------------------------------------------------------------
// Compare Logical Helpers
//-----------------------------------------------------------------------------

// Compare Logical 32-bit Register vs Register
void MacroAssembler::CmpU32(Register dst, Register src) { clr(dst, src); }

// Compare Logical Pointer Sized Register vs Register
void MacroAssembler::CmpU64(Register dst, Register src) {
  clgr(dst, src);
}

// Compare Logical 32-bit Register vs Immediate
void MacroAssembler::CmpU32(Register dst, const Operand& opnd) {
  clfi(dst, opnd);
}

// Compare Logical Pointer Sized Register vs Immediate
void MacroAssembler::CmpU64(Register dst, const Operand& opnd) {
  DCHECK_EQ(static_cast<uint32_t>(opnd.immediate() >> 32), 0);
  clgfi(dst, opnd);
}

// Compare Logical 32-bit Register vs Memory
void MacroAssembler::CmpU32(Register dst, const MemOperand& opnd) {
  // make sure offset is within 20 bit range
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    cl(dst, opnd);
  else
    cly(dst, opnd);
}

// Compare Logical Pointer Sized Register vs Memory
void MacroAssembler::CmpU64(Register dst, const MemOperand& opnd) {
  // make sure offset is within 20 bit range
  DCHECK(is_int20(opnd.offset()));
  clg(dst, opnd);
}

void MacroAssembler::Branch(Condition c, const Operand& opnd) {
  intptr_t value = opnd.immediate();
  if (is_int16(value))
    brc(c, opnd);
  else
    brcl(c, opnd);
}

// Branch On Count.  Decrement R1, and branch if R1 != 0.
void MacroAssembler::BranchOnCount(Register r1, Label* l) {
  int32_t offset = branch_offset(l);
  if (is_int16(offset)) {
    brctg(r1, Operand(offset));
  } else {
    AddS64(r1, Operand(-1));
    Branch(ne, Operand(offset));
  }
}

void MacroAssembler::LoadSmiLiteral(Register dst, Tagged<Smi> smi) {
  intptr_t value = static_cast<intptr_t>(smi.ptr());
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  llilf(dst, Operand(value));
#else
  DCHECK_EQ(value & 0xFFFFFFFF, 0);
  // The smi value is loaded in upper 32-bits.  Lower 32-bit are zeros.
  llihf(dst, Operand(value >> 32));
#endif
}

void MacroAssembler::CmpSmiLiteral(Register src1, Tagged<Smi> smi,
                                   Register scratch) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  // CFI takes 32-bit immediate.
  cfi(src1, Operand(smi));
#else
  if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    cih(src1, Operand(static_cast<intptr_t>(smi.ptr()) >> 32));
  } else {
    LoadSmiLiteral(scratch, smi);
    cgr(src1, scratch);
  }
#endif
}

void MacroAssembler::LoadU64(Register dst, const MemOperand& mem,
                             Register scratch) {
  int offset = mem.offset();

  MemOperand src = mem;
  if (!is_int20(offset)) {
    DCHECK(scratch != no_reg && scratch != r0 && mem.rx() == r0);
    DCHECK(scratch != mem.rb());
    mov(scratch, Operand(offset));
    src = MemOperand(mem.rb(), scratch);
  }
  lg(dst, src);
}

// Store a "pointer" sized value to the memory location
void MacroAssembler::StoreU64(Register src, const MemOperand& mem,
                              Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    stg(src, MemOperand(mem.rb(), scratch));
  } else {
    stg(src, mem);
  }
}

// Store a "pointer" sized constant to the memory location
void MacroAssembler::StoreU64(const MemOperand& mem, const Operand& opnd,
                              Register scratch) {
  // Relocations not supported
  DCHECK_EQ(opnd.rmode(), RelocInfo::NO_INFO);

  // Try to use MVGHI/MVHI
  if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT) && is_uint12(mem.offset()) &&
      mem.getIndexRegister() == r0 && is_int16(opnd.immediate())) {
    mvghi(mem, opnd);
  } else {
    mov(scratch, opnd);
    StoreU64(scratch, mem);
  }
}

void MacroAssembler::LoadMultipleP(Register dst1, Register dst2,
                                   const MemOperand& mem) {
  DCHECK(is_int20(mem.offset()));
  lmg(dst1, dst2, mem);
}

void MacroAssembler::StoreMultipleP(Register src1, Register src2,
                                    const MemOperand& mem) {
  DCHECK(is_int20(mem.offset()));
  stmg(src1, src2, mem);
}

void MacroAssembler::LoadMultipleW(Register dst1, Register dst2,
                                   const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    lm(dst1, dst2, mem);
  } else {
    DCHECK(is_int20(mem.offset()));
    lmy(dst1, dst2, mem);
  }
}

void MacroAssembler::StoreMultipleW(Register src1, Register src2,
                                    const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    stm(src1, src2, mem);
  } else {
    DCHECK(is_int20(mem.offset()));
    stmy(src1, src2, mem);
  }
}

// Load 32-bits and sign extend if necessary.
void MacroAssembler::LoadS32(Register dst, Register src) {
  lgfr(dst, src);
}

// Load 32-bits and sign extend if necessary.
void MacroAssembler::LoadS32(Register dst, const MemOperand& mem,
                             Register scratch) {
  int offset = mem.offset();

  if (!is_int20(offset)) {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    lgf(dst, MemOperand(mem.rb(), scratch));
  } else {
    lgf(dst, mem);
  }
}

// Load 32-bits and zero extend if necessary.
void MacroAssembler::LoadU32(Register dst, Register src) {
  llgfr(dst, src);
}

// Variable length depending on whether offset fits into immediate field
// MemOperand of RX or RXY format
void MacroAssembler::LoadU32(Register dst, const MemOperand& mem,
                             Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (is_int20(offset)) {
    llgf(dst, mem);
  } else if (scratch != no_reg) {
    // Materialize offset into scratch register.
    mov(scratch, Operand(offset));
    llgf(dst, MemOperand(base, scratch));
  } else {
    DCHECK(false);
  }
}

void MacroAssembler::LoadU16(Register dst, const MemOperand& mem) {
  // TODO(s390x): Add scratch reg
  llgh(dst, mem);
}

void MacroAssembler::LoadU16(Register dst, Register src) {
  llghr(dst, src);
}

void MacroAssembler::LoadS8(Register dst, const MemOperand& mem) {
  // TODO(s390x): Add scratch reg
  lgb(dst, mem);
}

void MacroAssembler::LoadS8(Register dst, Register src) {
  lgbr(dst, src);
}

void MacroAssembler::LoadU8(Register dst, const MemOperand& mem) {
  // TODO(s390x): Add scratch reg
  llgc(dst, mem);
}

void MacroAssembler::LoadU8(Register dst, Register src) {
  llgcr(dst, src);
}

#ifdef V8_TARGET_BIG_ENDIAN
void MacroAssembler::LoadU64LE(Register dst, const MemOperand& mem,
                               Register scratch) {
  lrvg(dst, mem);
}

void MacroAssembler::LoadS32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  lrv(dst, opnd);
  L
"""


```
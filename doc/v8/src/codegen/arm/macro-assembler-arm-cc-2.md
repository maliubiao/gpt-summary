Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8's `macro-assembler-arm.cc` file. I need to analyze the code and identify its main purposes and the operations it performs.

Here's a breakdown of the code's functionalities:

1. **Range Check:**  `mpIfIsInRange` checks if a register value falls within a given range.
2. **Double to Integer Conversion:** `TryInlineTruncateDoubleToI` and `TruncateDoubleToI` attempt to efficiently convert a double-precision floating-point number to an integer. If the inline conversion fails (due to potential saturation), it falls back to calling a runtime stub.
3. **Optimized Code Handling:** The anonymous namespace function `TailCallOptimizedCodeSlot` deals with tail-calling optimized code. It checks if optimized code is available, handles deoptimization scenarios, and performs the tail call.
4. **Assertions (Debug Mode):**  Several `Assert...` functions are present, used for debugging purposes to verify the types and states of objects.
5. **Code Replacement:** `ReplaceClosureCodeWithOptimizedCode` updates a function's closure to point to optimized code.
6. **Tail Calls to Runtime:** `GenerateTailCallToReturnedCode` executes a tail call to a V8 runtime function.
7. **Feedback Vector Processing:** `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing`, `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing`, and `OptimizeCodeOrTailCallOptimizedCodeSlot` handle the loading and checking of flags within a feedback vector, used for triggering optimization or logging.
8. **Runtime Calls:** `CallRuntime` and `TailCallRuntime` facilitate calls to V8 runtime functions.
9. **External Calls:** `JumpToExternalReference` handles jumps to external (non-V8) code.
10. **Weak References:** `LoadWeakValue` deals with loading weak references, jumping to a target if the reference is cleared.
11. **Counters:** `EmitIncrementCounter` and `EmitDecrementCounter` manage incrementing and decrementing internal performance counters.
12. **Basic Checks and Aborts:** `Check` and `Abort` provide mechanisms for asserting conditions and terminating execution upon failure.
13. **Object Property Access:** `LoadMap` and `LoadFeedbackVector` are used to load object metadata and feedback information.
14. **Context and Global Object Access:** `LoadGlobalProxy` and `LoadNativeContextSlot` are used to access the global proxy object and slots within the native context.
15. **Root Register Initialization:** `InitializeRootRegister` sets up a key register pointing to the isolate's root.
16. **Smi Handling:**  Functions like `SmiTag`, `SmiTst`, `JumpIfSmi`, and `JumpIfNotSmi` are used for efficiently working with Small Integers (Smis).
17. **Floating-Point Register Handling:** `CheckFor32DRegs`, `SaveFPRegs`, `RestoreFPRegs`, `SaveFPRegsToHeap`, and `RestoreFPRegsFromHeap` manage saving and restoring floating-point registers, potentially for function calls or context switching.
18. **Floating-Point Min/Max:** `FloatMaxHelper`, `FloatMinHelper`, and their out-of-line counterparts implement efficient floating-point minimum and maximum operations, handling NaN and zero cases.
19. **C Function Calls:** `PrepareCallCFunction`, `MovToFloatParameter`, `MovToFloatResult`, `MovToFloatParameters`, and `CallCFunction` provide mechanisms for calling C functions from generated code, managing argument passing and stack setup.

Considering this is part 3 of 4, I should focus on summarizing the functionality covered in this specific snippet, while keeping in mind the broader context of a macro assembler.
```
功能列表:
1. **范围检查:** `mpIfIsInRange` 函数用于检查一个寄存器中的值是否在给定的上下限之间，如果在范围内则跳转到指定的标签。
2. **Double 类型到整数的快速转换尝试:** `TryInlineTruncateDoubleToI` 尝试内联地将一个 double 类型的浮点数截断转换为整数。如果转换成功，则跳转到 `done` 标签。
3. **Double 类型到整数的转换 (带运行时回调):** `TruncateDoubleToI` 函数封装了 double 到整数的转换逻辑。它首先尝试 `TryInlineTruncateDoubleToI` 进行快速转换，如果失败则调用运行时 (runtime) 的 `DoubleToI` 函数进行处理。
4. **优化的代码槽尾调用:** 匿名命名空间中的 `TailCallOptimizedCodeSlot` 函数处理尾调用到优化的代码。它会检查优化的代码是否存在且未被标记为反优化，如果条件满足则替换当前闭包的代码并跳转到优化后的代码。如果优化的代码槽为空或已被标记为反优化，则调用运行时函数 `HealOptimizedCodeSlot`。
5. **断言 (Debug 代码):**  `AssertFeedbackCell` 和 `AssertFeedbackVector` 函数（在 `V8_ENABLE_DEBUG_CODE` 宏定义下）用于在调试模式下断言某个对象分别是 Feedback Cell 或 Feedback Vector 类型。
6. **替换闭包代码为优化后的代码:** `ReplaceClosureCodeWithOptimizedCode` 函数将一个闭包 (JSFunction) 的代码指针替换为指向优化后代码的指针。
7. **尾调用到运行时:** `GenerateTailCallToReturnedCode` 函数用于生成一个到运行时函数的尾调用。它会将必要的参数压栈，调用运行时函数，然后跳转到返回的代码对象。
8. **加载并检查 Feedback Vector 标志位:** `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing` 函数加载 Feedback Vector 中的标志位，并检查是否需要进一步处理 (例如优化或日志记录)。它返回一个条件码，指示是否需要处理。
9. **加载 Feedback Vector 标志位并根据需要跳转:** `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing` 函数加载 Feedback Vector 的标志位，并根据标志位的值跳转到指定的标签 `flags_need_processing`。
10. **优化代码或尾调用优化代码槽:** `OptimizeCodeOrTailCallOptimizedCodeSlot` 函数根据 Feedback Vector 的标志位，决定是调用运行时进行代码优化，还是进行尾调用到已有的优化代码槽。
11. **调用运行时函数:** `CallRuntime` 函数用于调用一个 V8 的运行时函数。它会将参数准备好，并调用相应的 C++ 入口点。
12. **尾调用运行时函数:** `TailCallRuntime` 函数用于执行到运行时函数的尾调用。
13. **跳转到外部引用:** `JumpToExternalReference` 函数用于跳转到外部 (非 V8 代码) 的地址。
14. **加载弱引用值:** `LoadWeakValue` 函数用于加载一个弱引用的值。如果弱引用已被清除，则跳转到指定的目标标签。
15. **发射增加计数器指令:** `EmitIncrementCounter` 函数用于在启用了本地代码计数器的情况下，增加一个指定的统计计数器的值。
16. **发射减少计数器指令:** `EmitDecrementCounter` 函数用于在启用了本地代码计数器的情况下，减少一个指定的统计计数器的值。
17. **断言 (Debug 代码):** `Assert`, `AssertUnreachable`, `AssertNotSmi`, `AssertSmi`, `AssertMap`, `AssertConstructor`, `AssertFunction`, `AssertCallableFunction`, `AssertBoundFunction`, `AssertGeneratorObject`, `AssertUndefinedOrAllocationSite`, `AssertJSAny` 等一系列 `Assert` 函数用于在调试模式下进行各种类型和状态的断言检查。
18. **检查条件并中止:** `Check` 函数在给定条件不满足时调用 `Abort` 函数。
19. **中止执行:** `Abort` 函数用于中止代码执行，通常是由于断言失败或其他严重错误。
20. **加载 Map 对象:** `LoadMap` 函数用于加载一个对象的 Map 属性。
21. **加载 Feedback Vector:** `LoadFeedbackVector` 函数用于从闭包中加载 Feedback Vector。如果 Feedback Vector 无效，则加载 undefined 并跳转到指定标签。
22. **加载全局 Proxy 对象:** `LoadGlobalProxy` 函数用于加载全局 Proxy 对象。
23. **加载 Native Context 槽位:** `LoadNativeContextSlot` 函数用于加载 Native Context 中的指定槽位的值。
24. **初始化 Root 寄存器:** `InitializeRootRegister` 函数用于初始化 Root 寄存器，使其指向当前 Isolate 的根。
25. **Smi 标记:** `SmiTag` 函数用于将一个整数值标记为 Smi (Small Integer)。
26. **Smi 测试:** `SmiTst` 函数用于测试一个值是否是 Smi。
27. **跳转如果为 Smi:** `JumpIfSmi` 函数用于在给定值为 Smi 时跳转到指定标签。
28. **跳转如果相等:** `JumpIfEqual` 函数用于在两个值相等时跳转。
29. **跳转如果小于:** `JumpIfLessThan` 函数用于在第一个值小于第二个值时跳转。
30. **跳转如果不为 Smi:** `JumpIfNotSmi` 函数用于在给定值不是 Smi 时跳转到指定标签。
31. **检查 32 位 D 寄存器支持:** `CheckFor32DRegs` 函数检查 CPU 是否支持 32 个双精度浮点寄存器。
32. **保存浮点寄存器:** `SaveFPRegs` 函数将所有的浮点寄存器 (d0-d31) 保存到栈上。
33. **恢复浮点寄存器:** `RestoreFPRegs` 函数从栈上恢复所有的浮点寄存器 (d0-d31)。
34. **保存浮点寄存器到堆:** `SaveFPRegsToHeap` 函数将所有的浮点寄存器保存到堆内存中。
35. **从堆恢复浮点寄存器:** `RestoreFPRegsFromHeap` 函数从堆内存中恢复所有的浮点寄存器。
36. **浮点数最大值辅助函数:** `FloatMaxHelper` 函数用于计算两个浮点数的最大值，并处理 NaN 的情况。它有内联和外联 (out-of-line) 两种实现。
37. **浮点数最小值辅助函数:** `FloatMinHelper` 函数用于计算两个浮点数的最小值，并处理 NaN 和 +/-0 的情况。它也有内联和外联两种实现。
38. **浮点数最大值外联辅助函数:** `FloatMaxOutOfLineHelper` 函数处理 `FloatMaxHelper` 中需要外联处理的情况，主要是处理 NaN。
39. **浮点数最小值外联辅助函数:** `FloatMinOutOfLineHelper` 函数处理 `FloatMinHelper` 中需要外联处理的情况，主要是处理 NaN 和 +/-0。
40. **特定类型的浮点数最大值/最小值函数:** `FloatMax` 和 `FloatMin` 函数针对 `SwVfpRegister` (单精度) 和 `DwVfpRegister` (双精度) 提供了计算最大值和最小值的接口，并处理了需要跳转到外联代码的情况。
41. **计算通过栈传递的字数:** `CalculateStackPassedWords` 函数根据寄存器参数和双精度浮点参数的数量，计算通过栈传递的字数，这取决于 ARM 的调用约定 (硬浮点或软浮点)。
42. **准备调用 C 函数:** `PrepareCallCFunction` 函数为调用 C 函数做准备，包括栈对齐和分配栈空间以传递参数。
43. **将值移动到浮点参数寄存器:** `MovToFloatParameter` 函数将一个双精度浮点寄存器的值移动到用于传递浮点参数的寄存器 (d0)，在软浮点调用约定中需要将双字移动到 r0 和 r1。
44. **将值移动到浮点结果寄存器:** `MovToFloatResult` 函数与 `MovToFloatParameter` 类似，用于将浮点结果移动到指定的寄存器。
45. **将值移动到多个浮点参数寄存器:** `MovToFloatParameters` 函数将两个双精度浮点寄存器的值移动到用于传递浮点参数的寄存器 (d0 和 d1)。
46. **调用 C 函数:** `CallCFunction` 函数用于调用 C 函数，包括设置参数、调用函数本身以及处理返回后的栈。它支持设置 Isolate 数据槽位。

根据你提供的代码片段，我们可以归纳一下 `v8/src/codegen/arm/macro-assembler-arm.cc` (第 3 部分) 的功能：

**归纳:**

这部分代码主要提供了 **ARM 架构下用于生成机器码的宏汇编器 (MacroAssembler) 的核心功能**，专注于：

* **数值类型转换和比较:**  实现了 Double 到 Integer 的转换，以及数值范围的比较。
* **函数调用和优化:**  提供了调用运行时函数和 C 函数的机制，并包含了处理优化代码尾调用的逻辑，这是 V8 优化管道的关键部分。
* **反馈向量处理:** 包含了加载和检查反馈向量标志位的功能，用于驱动代码的优化和分层编译。
* **低级代码操作:**  提供了加载、存储、比较、跳转等基本指令的封装，以及对 Smi 类型的特殊处理。
* **浮点运算支持:**  包含了浮点寄存器的保存和恢复，以及浮点数最大值和最小值的计算，并考虑了 NaN 和零的特殊情况。
* **调试和断言:**  集成了大量的断言宏，用于在开发和调试过程中检查代码的正确性。
* **底层系统交互:**  提供了与 V8 运行时系统交互 (通过 `CallRuntime`) 以及调用外部 C 函数的能力。

总而言之，这部分代码是 ARM 架构宏汇编器的核心组成部分，提供了构建 V8 引擎在 ARM 平台上运行所需的各种底层指令和操作。它体现了 V8 为了实现高性能所进行的精细化控制，包括内联优化、运行时回调和对特定硬件特性的利用。
```
Prompt: 
```
这是目录为v8/src/codegen/arm/macro-assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm/macro-assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
mpIfIsInRange(Register value, Register scratch,
                                     unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  ASM_CODE_COMMENT(this);
  CompareRange(value, scratch, lower_limit, higher_limit);
  b(ls, on_in_range);
}

void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DwVfpRegister double_input,
                                                Label* done) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  SwVfpRegister single_scratch = SwVfpRegister::no_reg();
  if (temps.CanAcquireVfp<SwVfpRegister>()) {
    single_scratch = temps.AcquireS();
  } else {
    // Re-use the input as a scratch register. However, we can only do this if
    // the input register is d0-d15 as there are no s32+ registers.
    DCHECK_LT(double_input.code(), LowDwVfpRegister::kNumRegisters);
    LowDwVfpRegister double_scratch =
        LowDwVfpRegister::from_code(double_input.code());
    single_scratch = double_scratch.low();
  }
  vcvt_s32_f64(single_scratch, double_input);
  vmov(result, single_scratch);

  Register scratch = temps.Acquire();
  // If result is not saturated (0x7FFFFFFF or 0x80000000), we are done.
  sub(scratch, result, Operand(1));
  cmp(scratch, Operand(0x7FFFFFFE));
  b(lt, done);
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DwVfpRegister double_input,
                                       StubCallMode stub_mode) {
  ASM_CODE_COMMENT(this);
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  push(lr);
  AllocateStackSpace(kDoubleSize);  // Put input on stack.
  vstr(double_input, MemOperand(sp, 0));

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
  ldr(result, MemOperand(sp, 0));

  add(sp, sp, Operand(kDoubleSize));
  pop(lr);

  bind(&done);
}

namespace {

void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry,
                               Register scratch) {
  // ----------- S t a t e -------------
  //  -- r0 : actual argument count
  //  -- r3 : new target (preserved for callee if needed, and caller)
  //  -- r1 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  DCHECK(!AreAliased(r1, r3, optimized_code_entry, scratch));

  Register closure = r1;
  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ ldr(optimized_code_entry,
         FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  {
    UseScratchRegisterScope temps(masm);
    __ TestCodeIsMarkedForDeoptimization(optimized_code_entry, temps.Acquire());
    __ b(ne, &heal_optimized_code_slot);
  }

  // Optimized code is good, get it into the closure and link the closure
  // into the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, closure);
  static_assert(kJavaScriptCallCodeStartRegister == r2, "ABI mismatch");
  __ LoadCodeInstructionStart(r2, optimized_code_entry);
  __ Jump(r2);

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
    CompareObjectType(object, scratch, scratch, FEEDBACK_CELL_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    CompareObjectType(object, scratch, scratch, FEEDBACK_VECTOR_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(optimized_code, closure));
  // Store code entry in the closure.
  str(optimized_code, FieldMemOperand(closure, JSFunction::kCodeOffset));
  RecordWriteField(closure, JSFunction::kCodeOffset, optimized_code,
                   kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore,
                   SmiCheck::kOmit);
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  // ----------- S t a t e -------------
  //  -- r0 : actual argument count
  //  -- r1 : target function (preserved for callee)
  //  -- r3 : new target (preserved for callee)
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
    mov(r2, r0);

    // Restore target function, new target and actual argument count.
    Pop(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
        kJavaScriptCallArgCountRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }
  static_assert(kJavaScriptCallCodeStartRegister == r2, "ABI mismatch");
  JumpCodeObject(r2);
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
Condition MacroAssembler::LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  ldrh(flags, FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  uint32_t kFlagsMask = FeedbackVector::kFlagsTieringStateIsAnyRequested |
                        FeedbackVector::kFlagsMaybeHasTurbofanCode |
                        FeedbackVector::kFlagsLogNextExecution;
  if (current_code_kind != CodeKind::MAGLEV) {
    kFlagsMask |= FeedbackVector::kFlagsMaybeHasMaglevCode;
  }
  tst(flags, Operand(kFlagsMask));
  return ne;
}

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
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available.
  tst(flags, Operand(FeedbackVector::kFlagsTieringStateIsAnyRequested));
  b(eq, &maybe_needs_logging);
  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  tst(flags, Operand(FeedbackVector::LogNextExecutionBit::kMask));
  b(eq, &maybe_has_optimized_code);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = flags;
  ldr(optimized_code_entry,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry, r6);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // All parameters are on the stack.  r0 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  mov(r0, Operand(num_arguments));
  Move(r1, ExternalReference::Create(f));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    // TODO(1236192): Most runtime routines don't need the number of
    // arguments passed in because it is constant. At some point we
    // should remove this need and make the runtime routine entry code
    // smarter.
    mov(r0, Operand(function->nargs));
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
#if defined(__thumb__)
  // Thumb mode builtin.
  DCHECK_EQ(builtin.address() & 1, 1);
#endif
  Move(r1, builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  cmp(in, Operand(kClearedWeakHeapObjectLower32));
  b(eq, target_if_cleared);

  and_(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    Move(scratch2, ExternalReference::Create(counter));
    ldr(scratch1, MemOperand(scratch2));
    add(scratch1, scratch1, Operand(value));
    str(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    Move(scratch2, ExternalReference::Create(counter));
    ldr(scratch1, MemOperand(scratch2));
    sub(scratch1, scratch1, Operand(value));
    str(scratch1, MemOperand(scratch2));
  }
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::Assert(Condition cond, AbortReason reason) {
  if (v8_flags.debug_code) Check(cond, reason);
}

void MacroAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}

void MacroAssembler::AssertNotSmi(Register object, AbortReason reason) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  tst(object, Operand(kSmiTagMask));
  Check(ne, reason);
}

void MacroAssembler::AssertSmi(Register object, AbortReason reason) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  tst(object, Operand(kSmiTagMask));
  Check(eq, reason);
}

void MacroAssembler::AssertMap(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsNotAMap);

  UseScratchRegisterScope temps(this);
  Register temp = temps.Acquire();

  CompareObjectType(object, temp, temp, MAP_TYPE);
  Check(eq, AbortReason::kOperandIsNotAMap);
}

void MacroAssembler::AssertConstructor(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  tst(object, Operand(kSmiTagMask));
  Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor);
  push(object);
  LoadMap(object, object);
  ldrb(object, FieldMemOperand(object, Map::kBitFieldOffset));
  tst(object, Operand(Map::Bits1::IsConstructorBit::kMask));
  pop(object);
  Check(ne, AbortReason::kOperandIsNotAConstructor);
}

void MacroAssembler::AssertFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  tst(object, Operand(kSmiTagMask));
  Check(ne, AbortReason::kOperandIsASmiAndNotAFunction);
  push(object);
  LoadMap(object, object);
  CompareInstanceTypeRange(object, object, object, FIRST_JS_FUNCTION_TYPE,
                           LAST_JS_FUNCTION_TYPE);
  pop(object);
  Check(ls, AbortReason::kOperandIsNotAFunction);
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  tst(object, Operand(kSmiTagMask));
  Check(ne, AbortReason::kOperandIsASmiAndNotAFunction);
  push(object);
  LoadMap(object, object);
  CompareInstanceTypeRange(object, object, object,
                           FIRST_CALLABLE_JS_FUNCTION_TYPE,
                           LAST_CALLABLE_JS_FUNCTION_TYPE);
  pop(object);
  Check(ls, AbortReason::kOperandIsNotACallableFunction);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  tst(object, Operand(kSmiTagMask));
  Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction);
  push(object);
  CompareObjectType(object, object, object, JS_BOUND_FUNCTION_TYPE);
  pop(object);
  Check(eq, AbortReason::kOperandIsNotABoundFunction);
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  tst(object, Operand(kSmiTagMask));
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject);

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
  Check(ls, AbortReason::kOperandIsNotAGeneratorObject);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Label done_checking;
  AssertNotSmi(object);
  CompareRoot(object, RootIndex::kUndefinedValue);
  b(eq, &done_checking);
  LoadMap(scratch, object);
  CompareInstanceType(scratch, scratch, ALLOCATION_SITE_TYPE);
  Assert(eq, AbortReason::kExpectedUndefinedOrCell);
  bind(&done_checking);
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
  b(kUnsignedLessThanEqual, &ok);

  CompareInstanceType(map_tmp, tmp, FIRST_JS_RECEIVER_TYPE);
  b(kUnsignedGreaterThanEqual, &ok);

  CompareRoot(map_tmp, RootIndex::kHeapNumberMap);
  b(kEqual, &ok);

  CompareRoot(map_tmp, RootIndex::kBigIntMap);
  b(kEqual, &ok);

  CompareRoot(object, RootIndex::kUndefinedValue);
  b(kEqual, &ok);

  CompareRoot(object, RootIndex::kTrueValue);
  b(kEqual, &ok);

  CompareRoot(object, RootIndex::kFalseValue);
  b(kEqual, &ok);

  CompareRoot(object, RootIndex::kNullValue);
  b(kEqual, &ok);

  Abort(abort_reason);

  bind(&ok);
}

#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::Check(Condition cond, AbortReason reason) {
  Label L;
  b(cond, &L);
  Abort(reason);
  // will not return here
  bind(&L);
}

void MacroAssembler::Abort(AbortReason reason) {
  ASM_CODE_COMMENT(this);
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
    Move32BitImmediate(r0, Operand(static_cast<int>(reason)));
    PrepareCallCFunction(1, 0, r1);
    Move(r1, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(r1);
    return;
  }

  Move(r1, Smi::FromInt(static_cast<int>(reason)));

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

void MacroAssembler::LoadMap(Register destination, Register object) {
  ldr(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;

  // Load the feedback vector from the closure.
  ldr(dst, FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  ldr(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  ldr(scratch, FieldMemOperand(dst, HeapObject::kMapOffset));
  ldrh(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  cmp(scratch, Operand(FEEDBACK_VECTOR_TYPE));
  b(eq, &done);

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  b(fbv_undef);

  bind(&done);
}

void MacroAssembler::LoadGlobalProxy(Register dst) {
  ASM_CODE_COMMENT(this);
  LoadNativeContextSlot(dst, Context::GLOBAL_PROXY_INDEX);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  ASM_CODE_COMMENT(this);
  LoadMap(dst, cp);
  ldr(dst, FieldMemOperand(
               dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  ldr(dst, MemOperand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::InitializeRootRegister() {
  ASM_CODE_COMMENT(this);
  ExternalReference isolate_root = ExternalReference::isolate_root(isolate());
  mov(kRootRegister, Operand(isolate_root));
}

void MacroAssembler::SmiTag(Register reg, SBit s) {
  add(reg, reg, Operand(reg), s);
}

void MacroAssembler::SmiTag(Register dst, Register src, SBit s) {
  add(dst, src, Operand(src), s);
}

void MacroAssembler::SmiTst(Register value) {
  tst(value, Operand(kSmiTagMask));
}

void MacroAssembler::JumpIfSmi(Register value, Label* smi_label) {
  tst(value, Operand(kSmiTagMask));
  b(eq, smi_label);
}

void MacroAssembler::JumpIfEqual(Register x, int32_t y, Label* dest) {
  cmp(x, Operand(y));
  b(eq, dest);
}

void MacroAssembler::JumpIfLessThan(Register x, int32_t y, Label* dest) {
  cmp(x, Operand(y));
  b(lt, dest);
}

void MacroAssembler::JumpIfNotSmi(Register value, Label* not_smi_label) {
  tst(value, Operand(kSmiTagMask));
  b(ne, not_smi_label);
}

void MacroAssembler::CheckFor32DRegs(Register scratch) {
  ASM_CODE_COMMENT(this);
  Move(scratch, ExternalReference::cpu_features());
  ldr(scratch, MemOperand(scratch));
  tst(scratch, Operand(1u << VFP32DREGS));
}

void MacroAssembler::SaveFPRegs(Register location, Register scratch) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope scope(this, VFP32DREGS, CpuFeatureScope::kDontCheckSupported);
  CheckFor32DRegs(scratch);
  vstm(db_w, location, d16, d31, ne);
  sub(location, location, Operand(16 * kDoubleSize), LeaveCC, eq);
  vstm(db_w, location, d0, d15);
}

void MacroAssembler::RestoreFPRegs(Register location, Register scratch) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope scope(this, VFP32DREGS, CpuFeatureScope::kDontCheckSupported);
  CheckFor32DRegs(scratch);
  vldm(ia_w, location, d0, d15);
  vldm(ia_w, location, d16, d31, ne);
  add(location, location, Operand(16 * kDoubleSize), LeaveCC, eq);
}

void MacroAssembler::SaveFPRegsToHeap(Register location, Register scratch) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope scope(this, VFP32DREGS, CpuFeatureScope::kDontCheckSupported);
  CheckFor32DRegs(scratch);
  vstm(ia_w, location, d0, d15);
  vstm(ia_w, location, d16, d31, ne);
  add(location, location, Operand(16 * kDoubleSize), LeaveCC, eq);
}

void MacroAssembler::RestoreFPRegsFromHeap(Register location,
                                           Register scratch) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope scope(this, VFP32DREGS, CpuFeatureScope::kDontCheckSupported);
  CheckFor32DRegs(scratch);
  vldm(ia_w, location, d0, d15);
  vldm(ia_w, location, d16, d31, ne);
  add(location, location, Operand(16 * kDoubleSize), LeaveCC, eq);
}

template <typename T>
void MacroAssembler::FloatMaxHelper(T result, T left, T right,
                                    Label* out_of_line) {
  // This trivial case is caught sooner, so that the out-of-line code can be
  // completely avoided.
  DCHECK(left != right);

  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    VFPCompareAndSetFlags(left, right);
    b(vs, out_of_line);
    vmaxnm(result, left, right);
  } else {
    Label done;
    VFPCompareAndSetFlags(left, right);
    b(vs, out_of_line);
    // Avoid a conditional instruction if the result register is unique.
    bool aliased_result_reg = result == left || result == right;
    Move(result, right, aliased_result_reg ? mi : al);
    Move(result, left, gt);
    b(ne, &done);
    // Left and right are equal, but check for +/-0.
    VFPCompareAndSetFlags(left, 0.0);
    b(eq, out_of_line);
    // The arguments are equal and not zero, so it doesn't matter which input we
    // pick. We have already moved one input into the result (if it didn't
    // already alias) so there's nothing more to do.
    bind(&done);
  }
}

template <typename T>
void MacroAssembler::FloatMaxOutOfLineHelper(T result, T left, T right) {
  DCHECK(left != right);

  // ARMv8: At least one of left and right is a NaN.
  // Anything else: At least one of left and right is a NaN, or both left and
  // right are zeroes with unknown sign.

  // If left and right are +/-0, select the one with the most positive sign.
  // If left or right are NaN, vadd propagates the appropriate one.
  vadd(result, left, right);
}

template <typename T>
void MacroAssembler::FloatMinHelper(T result, T left, T right,
                                    Label* out_of_line) {
  // This trivial case is caught sooner, so that the out-of-line code can be
  // completely avoided.
  DCHECK(left != right);

  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    VFPCompareAndSetFlags(left, right);
    b(vs, out_of_line);
    vminnm(result, left, right);
  } else {
    Label done;
    VFPCompareAndSetFlags(left, right);
    b(vs, out_of_line);
    // Avoid a conditional instruction if the result register is unique.
    bool aliased_result_reg = result == left || result == right;
    Move(result, left, aliased_result_reg ? mi : al);
    Move(result, right, gt);
    b(ne, &done);
    // Left and right are equal, but check for +/-0.
    VFPCompareAndSetFlags(left, 0.0);
    // If the arguments are equal and not zero, it doesn't matter which input we
    // pick. We have already moved one input into the result (if it didn't
    // already alias) so there's nothing more to do.
    b(ne, &done);
    // At this point, both left and right are either 0 or -0.
    // We could use a single 'vorr' instruction here if we had NEON support.
    // The algorithm used is -((-L) + (-R)), which is most efficiently expressed
    // as -((-L) - R).
    if (left == result) {
      DCHECK(right != result);
      vneg(result, left);
      vsub(result, result, right);
      vneg(result, result);
    } else {
      DCHECK(left != result);
      vneg(result, right);
      vsub(result, result, left);
      vneg(result, result);
    }
    bind(&done);
  }
}

template <typename T>
void MacroAssembler::FloatMinOutOfLineHelper(T result, T left, T right) {
  DCHECK(left != right);

  // At least one of left and right is a NaN. Use vadd to propagate the NaN
  // appropriately. +/-0 is handled inline.
  vadd(result, left, right);
}

void MacroAssembler::FloatMax(SwVfpRegister result, SwVfpRegister left,
                              SwVfpRegister right, Label* out_of_line) {
  FloatMaxHelper(result, left, right, out_of_line);
}

void MacroAssembler::FloatMin(SwVfpRegister result, SwVfpRegister left,
                              SwVfpRegister right, Label* out_of_line) {
  FloatMinHelper(result, left, right, out_of_line);
}

void MacroAssembler::FloatMax(DwVfpRegister result, DwVfpRegister left,
                              DwVfpRegister right, Label* out_of_line) {
  FloatMaxHelper(result, left, right, out_of_line);
}

void MacroAssembler::FloatMin(DwVfpRegister result, DwVfpRegister left,
                              DwVfpRegister right, Label* out_of_line) {
  FloatMinHelper(result, left, right, out_of_line);
}

void MacroAssembler::FloatMaxOutOfLine(SwVfpRegister result, SwVfpRegister left,
                                       SwVfpRegister right) {
  FloatMaxOutOfLineHelper(result, left, right);
}

void MacroAssembler::FloatMinOutOfLine(SwVfpRegister result, SwVfpRegister left,
                                       SwVfpRegister right) {
  FloatMinOutOfLineHelper(result, left, right);
}

void MacroAssembler::FloatMaxOutOfLine(DwVfpRegister result, DwVfpRegister left,
                                       DwVfpRegister right) {
  FloatMaxOutOfLineHelper(result, left, right);
}

void MacroAssembler::FloatMinOutOfLine(DwVfpRegister result, DwVfpRegister left,
                                       DwVfpRegister right) {
  FloatMinOutOfLineHelper(result, left, right);
}

int MacroAssembler::CalculateStackPassedWords(int num_reg_arguments,
                                              int num_double_arguments) {
  int stack_passed_words = 0;
  if (use_eabi_hardfloat()) {
    // In the hard floating point calling convention, we can use the first 8
    // registers to pass doubles.
    if (num_double_arguments > kDoubleRegisterPassedArguments) {
      stack_passed_words +=
          2 * (num_double_arguments - kDoubleRegisterPassedArguments);
    }
  } else {
    // In the soft floating point calling convention, every double
    // argument is passed using two registers.
    num_reg_arguments += 2 * num_double_arguments;
  }
  // Up to four simple arguments are passed in registers r0..r3.
  if (num_reg_arguments > kRegisterPassedArguments) {
    stack_passed_words += num_reg_arguments - kRegisterPassedArguments;
  }
  return stack_passed_words;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = ActivationFrameAlignment();
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  if (frame_alignment > kPointerSize) {
    UseScratchRegisterScope temps(this);
    if (!scratch.is_valid()) scratch = temps.Acquire();
    // Make stack end at alignment and make room for num_arguments - 4 words
    // and the original value of sp.
    mov(scratch, sp);
    AllocateStackSpace((stack_passed_arguments + 1) * kPointerSize);
    EnforceStackAlignment();
    str(scratch, MemOperand(sp, stack_passed_arguments * kPointerSize));
  } else if (stack_passed_arguments > 0) {
    AllocateStackSpace(stack_passed_arguments * kPointerSize);
  }
}

void MacroAssembler::MovToFloatParameter(DwVfpRegister src) {
  DCHECK(src == d0);
  if (!use_eabi_hardfloat()) {
    vmov(r0, r1, src);
  }
}

// On ARM this is just a synonym to make the purpose clear.
void MacroAssembler::MovToFloatResult(DwVfpRegister src) {
  MovToFloatParameter(src);
}

void MacroAssembler::MovToFloatParameters(DwVfpRegister src1,
                                          DwVfpRegister src2) {
  DCHECK(src1 == d0);
  DCHECK(src2 == d1);
  if (!use_eabi_hardfloat()) {
    vmov(r0, r1, src1);
    vmov(r2, r3, src2);
  }
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_label) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, function);
  return CallCFunction(scratch, num_reg_arguments, num_double_arguments,
                       set_isolate_data_slots, return_label);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_label) {
  ASM_CODE_COMMENT(this);
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());
  // Make sure that the stack is aligned before calling a C function unless
  // running in the simulator. The simulator has its own alignment check which
  // provides more information.
#if V8_HOST_ARCH_ARM
  if (v8_flags.debug_code) {
    int frame_alignment = base::OS::ActivationFrameAlignment();
    int frame_alignment_mask = frame_alignment - 1;
    if (frame_alignment > kPointerSize) {
      ASM_CODE_COMMENT_STRING(this, "Check stack alignment");
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      Label alignment_as_expected;
      tst(sp, Operand(frame_alignment_mask));
      b(eq, &alignment_as_expected);
      // Don't use Check here, as it will call Runtime_Abort possibly
      // re-entering here.
      stop();
      bind(&alignment_as_expected);
    }
  }
#endif

  Label get_pc;

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    Register pc_scratch = r5;
    Push(pc_scratch);
    GetLabelAddress(pc_scratch, &get_pc);

    // Save the frame pointer and PC so that the stack layout remains iterable,
    // even without an ExitFrame which normally exists between JS and C frames.
    CHECK(root_array_available());
    str(pc_scratch,
        ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
    str(fp, ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));

    Pop(pc_scratch);
  }

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  Call(function);
  int call_pc_offset = pc_offset();
  bind(&get_pc);
  if (return_label) bind(return_label);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    Register zero_scratch = r5;
    Push(zero_scratch);
    mov(zero_scratch, Operand::Zero());

    str(zero_scratch,
        ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));

    Pop(zero_scratch);
  }

  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  if (ActivationFrameAlignment() > kPointerSize) {
    ldr(sp, MemOperand(sp, stack_passed_arguments * kPointerSize));
  } else {
    add(sp
"""


```
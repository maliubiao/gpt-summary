Response: The user wants a summary of the C++ source code file `v8/src/codegen/arm/macro-assembler-arm.cc`. This is the second part of the file. I need to understand the functionalities implemented in this part and relate them to JavaScript execution if possible.

Based on the code snippets, here's a breakdown of the functionalities:

*   **Range Check:** `mpIfIsInRange` checks if a register value falls within a given range.
*   **Double to Integer Conversion:** `TryInlineTruncateDoubleToI` attempts to inline the conversion of a double-precision floating-point number to an integer. `TruncateDoubleToI` handles the full conversion, potentially calling a runtime stub if the inline version fails.
*   **Optimized Code Handling:** `TailCallOptimizedCodeSlot` manages tail calls to optimized code, handling cases where the optimized code slot is cleared or marked for deoptimization. `ReplaceClosureCodeWithOptimizedCode` updates a closure object with a pointer to optimized code.
*   **Tail Calls to Runtime:** `GenerateTailCallToReturnedCode` performs a tail call to a runtime function.
*   **Feedback Vector Processing:** `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing` and `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing` check flags in a feedback vector to determine if further processing is required (e.g., for optimization). `OptimizeCodeOrTailCallOptimizedCodeSlot` orchestrates the process of potentially optimizing code or tail-calling existing optimized code based on feedback vector flags.
*   **Runtime Calls:** `CallRuntime` and `TailCallRuntime` provide mechanisms to call runtime functions. `JumpToExternalReference` facilitates jumps to external C++ functions.
*   **Weak Value Handling:** `LoadWeakValue` loads a weak reference, branching if the reference is cleared.
*   **Counters:** `EmitIncrementCounter` and `EmitDecrementCounter` manage performance counters.
*   **Assertions:** The `Assert*` family of functions are used for debugging and verifying runtime conditions.
*   **Generic Checks and Aborts:** `Check` and `Abort` handle error conditions.
*   **Object Property Loading:** `LoadMap` and `LoadFeedbackVector` load specific properties from JavaScript objects. `LoadGlobalProxy` and `LoadNativeContextSlot` load global objects.
*   **Root Register Initialization:** `InitializeRootRegister` sets up a register to point to the isolate's root object.
*   **Smi Handling:** `SmiTag`, `SmiTst`, `JumpIfSmi`, and `JumpIfNotSmi` deal with Smis (small integers), a common V8 optimization.
*   **Floating-Point Register Handling:** `CheckFor32DRegs`, `SaveFPRegs`, `RestoreFPRegs`, `SaveFPRegsToHeap`, and `RestoreFPRegsFromHeap` manage saving and restoring floating-point registers.
*   **Floating-Point Math Helpers:** `FloatMaxHelper`, `FloatMinHelper`, `FloatMaxOutOfLineHelper`, and `FloatMinOutOfLineHelper` provide optimized implementations for `Math.max` and `Math.min`.
*   **C Function Call Preparation:** `CalculateStackPassedWords` and `PrepareCallCFunction` handle the setup for calling C++ functions. `MovToFloatParameter`, `MovToFloatResult`, and `MovToFloatParameters` manage moving floating-point values as parameters. `CallCFunction` handles the actual call.
*   **Page Flag Checks:** `CheckPageFlag` checks flags associated with memory pages.
*   **Register Allocation Helper:** `GetRegisterThatIsNotOneOf` assists in finding an unused register.
*   **Code Address Computation:** `ComputeCodeStartAddress` calculates the starting address of the current code object.
*   **Deoptimization Handling:** `BailoutIfDeoptimized` checks if the current code is marked for deoptimization. `CallForDeoptimization` initiates the deoptimization process.
*   **Traps and Debug Breaks:** `Trap` and `DebugBreak` are used for debugging.
*   **SIMD Operations (I64x2 and F64x2):**  Functions like `I64x2BitMask`, `I64x2Eq`, `F64x2ConvertLowI32x4S`, etc., implement SIMD (Single Instruction, Multiple Data) operations for 64-bit integer and 64-bit floating-point vectors.
*   **Switch Statement Implementation:** `Switch` provides an efficient way to implement switch statements.
*   **Optimized Code Loading:** `JumpIfCodeIsMarkedForDeoptimization`, `JumpIfCodeIsTurbofanned`, and `TryLoadOptimizedOsrCode` deal with loading and checking optimized code during execution.
*   **Calling API Functions:** `CallApiFunctionAndReturn` handles calling JavaScript API functions from within generated code, including managing handle scopes and exception propagation.
这是 `v8/src/codegen/arm/macro-assembler-arm.cc` 文件的第二部分，它延续了第一部分的功能，主要负责提供 ARM 架构特定的汇编指令的抽象和封装，用于在 V8 引擎中动态生成机器码。  它与 JavaScript 的功能密切相关，因为它生成的机器码直接执行 JavaScript 代码。

以下是这部分代码的主要功能归纳：

**1. 类型转换和数值处理：**

*   **`mpIfIsInRange`**:  生成汇编代码，检查一个寄存器中的值是否在给定的范围内，如果满足条件则跳转到指定的标签。
*   **`TryInlineTruncateDoubleToI`**: 尝试内联将双精度浮点数转换为整数的汇编代码，如果成功则跳转到完成标签。
*   **`TruncateDoubleToI`**:  将双精度浮点数转换为整数，如果内联失败，则调用运行时 stub 函数来完成转换。

**2. 优化代码的调用和管理：**

*   **`TailCallOptimizedCodeSlot`**: 生成汇编代码，用于尾调用到优化后的代码。它会检查优化后的代码是否可用，是否被标记为 deopt 等。
*   **`ReplaceClosureCodeWithOptimizedCode`**:  更新闭包对象中的代码指针，指向优化后的代码。
*   **`GenerateTailCallToReturnedCode`**:  生成汇编代码，用于尾调用到由运行时函数返回的代码。
*   **`LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing` 和 `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing`**:  检查反馈向量中的标志，判断是否需要进行优化处理。
*   **`OptimizeCodeOrTailCallOptimizedCodeSlot`**:  根据反馈向量的标志，决定是否进行代码优化或尾调用到已有的优化代码。
*   **`TryLoadOptimizedOsrCode`**: 尝试加载用于 On-Stack Replacement (OSR) 的优化代码。

**3. 运行时函数的调用：**

*   **`CallRuntime`**: 生成汇编代码来调用 V8 的运行时 (Runtime) 函数。
*   **`TailCallRuntime`**: 生成汇编代码来尾调用 V8 的运行时函数。
*   **`JumpToExternalReference`**:  生成汇编代码来跳转到外部 C++ 函数。

**4. 弱引用处理：**

*   **`LoadWeakValue`**:  加载一个弱引用，如果引用的对象已经被回收，则跳转到指定的标签。

**5. 性能计数器：**

*   **`EmitIncrementCounter` 和 `EmitDecrementCounter`**:  用于增加或减少性能计数器的值。

**6. 断言和检查：**

*   一系列 `Assert*` 函数（例如 `AssertNotSmi`, `AssertMap`, `AssertFunction` 等）：用于在调试模式下进行各种运行时断言，检查代码执行的假设是否成立。
*   **`Check`**:  生成汇编代码，根据条件跳转，如果不满足条件则触发 `Abort`。
*   **`Abort`**:  生成汇编代码，用于终止程序执行并报告错误原因。

**7. 对象属性的加载：**

*   **`LoadMap`**: 加载对象的 Map 属性。
*   **`LoadFeedbackVector`**: 加载闭包的反馈向量。
*   **`LoadGlobalProxy`**: 加载全局代理对象。
*   **`LoadNativeContextSlot`**: 加载 Native Context 中的特定槽位。

**8. 寄存器操作和状态管理：**

*   **`InitializeRootRegister`**: 初始化根寄存器，指向 Isolate 的根对象。
*   **`SmiTag` 系列函数**:  用于将整数转换为 Smi (Small Integer)。
*   **`SmiTst`**:  测试一个值是否是 Smi。
*   **`JumpIfSmi` 和 `JumpIfNotSmi`**: 根据是否是 Smi 进行跳转。
*   **`CheckFor32DRegs`**: 检查 CPU 是否支持 32 个双精度浮点寄存器。
*   **`SaveFPRegs` 系列和 `RestoreFPRegs` 系列函数**:  用于保存和恢复浮点寄存器的状态。

**9. 浮点数操作辅助函数：**

*   **`FloatMaxHelper`, `FloatMinHelper`, `FloatMaxOutOfLineHelper`, `FloatMinOutOfLineHelper`**:  提供高效的 `Math.max` 和 `Math.min` 的实现，处理 NaN 和正负零的情况。

**10. C 函数调用相关：**

*   **`CalculateStackPassedWords`**: 计算传递给 C 函数的参数在栈上占用的字数。
*   **`PrepareCallCFunction`**:  为调用 C 函数准备栈空间。
*   **`MovToFloatParameter`, `MovToFloatResult`, `MovToFloatParameters`**:  将浮点数移动到参数寄存器或结果寄存器中。
*   **`CallCFunction`**:  生成汇编代码来调用 C 函数。

**11. 其他辅助功能：**

*   **`CheckPageFlag`**: 检查内存页的标志位。
*   **`GetRegisterThatIsNotOneOf`**:  获取一个不属于指定寄存器列表的寄存器。
*   **`ComputeCodeStartAddress`**: 计算当前代码对象的起始地址。
*   **`BailoutIfDeoptimized`**:  如果代码被标记为需要反优化，则跳转到反优化入口。
*   **`CallForDeoptimization`**: 生成汇编代码来执行反优化过程。
*   **`Trap` 和 `DebugBreak`**:  用于触发断点或异常。
*   **SIMD (向量化) 指令**:  提供了一系列用于操作 64 位整数向量 (`I64x2*`) 和 64 位浮点数向量 (`F64x2*`) 的汇编指令封装，用于加速并行计算。
*   **`Switch`**:  生成高效的 `switch` 语句的汇编代码实现。
*   **`JumpIfCodeIsMarkedForDeoptimization` 和 `JumpIfCodeIsTurbofanned`**: 检查代码对象是否被标记为需要反优化或已经被 TurboFan 优化。
*   **`CallApiFunctionAndReturn`**:  用于调用 JavaScript API 函数，并处理 HandleScope 和异常。

**与 JavaScript 的关系：**

这个文件中的代码是 V8 引擎将 JavaScript 代码转换为可执行机器码的关键部分。 例如：

*   **类型转换**: 当 JavaScript 中进行数字类型转换（如 `Number(value)` 或位运算）时，`TryInlineTruncateDoubleToI` 或 `TruncateDoubleToI` 等函数生成的机器码会被执行。

    ```javascript
    let floatValue = 3.14;
    let intValue = Math.trunc(floatValue); // 或 floatValue | 0
    ```

*   **函数调用和优化**: 当 JavaScript 函数被调用时，`TailCallOptimizedCodeSlot` 和相关的函数负责调用未优化的代码、已经优化的代码，或者触发代码优化。

    ```javascript
    function myFunction(x) {
      return x * 2;
    }

    myFunction(5); // 可能会触发代码优化，后续调用会走优化后的路径
    ```

*   **运行时调用**: 当 JavaScript 代码需要执行一些底层操作（例如创建对象、访问原型链等）时，会调用 V8 的运行时函数，这通过 `CallRuntime` 或 `TailCallRuntime` 生成的机器码来实现。

    ```javascript
    let obj = {}; // 内部会调用运行时函数来创建对象
    ```

*   **性能计数器和断言**: 虽然这些功能在 JavaScript 代码中不可见，但它们在 V8 引擎的开发和调试过程中至关重要，用于性能分析和代码正确性验证。

*   **SIMD 操作**: 当 JavaScript 使用 SIMD API (`Float64x2`, `Int32x4` 等) 进行向量化计算时，`I64x2BitMask`, `F64x2ConvertLowI32x4S` 等函数生成的机器码会被调用。

    ```javascript
    let a = Float64x2(1.0, 2.0);
    let b = Float64x2(3.0, 4.0);
    let sum = Float64x2.add(a, b);
    ```

总而言之，`macro-assembler-arm.cc` 的这部分代码定义了用于生成 ARM 架构机器码的各种构建块，这些机器码直接执行 JavaScript 代码，并负责处理类型转换、函数调用、性能优化、错误处理等关键任务，是 V8 引擎实现 JavaScript 执行的核心组成部分。

Prompt: 
```
这是目录为v8/src/codegen/arm/macro-assembler-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

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
    add(sp, sp, Operand(stack_passed_arguments * kPointerSize));
  }

  return call_pc_offset;
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_label) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_label);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_label) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_label);
}

void MacroAssembler::CheckPageFlag(Register object, int mask, Condition cc,
                                   Label* condition_met) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  DCHECK(!AreAliased(object, scratch));
  DCHECK(cc == eq || cc == ne);
  Bfc(scratch, object, 0, kPageSizeBits);
  ldr(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  tst(scratch, Operand(mask));
  b(cc, condition_met);
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

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  ASM_CODE_COMMENT(this);
  // We can use the register pc - 8 for the address of the current instruction.
  sub(dst, pc, Operand(pc_offset() + Instruction::kPcLoadDelta));
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized() {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  ldr(scratch, MemOperand(kJavaScriptCallCodeStartRegister, offset));
  ldr(scratch, FieldMemOperand(scratch, Code::kFlagsOffset));
  tst(scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
  TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne);
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);

  // All constants should have been emitted prior to deoptimization exit
  // emission. See PrepareForDeoptimizationExits.
  DCHECK(!has_pending_constants());
  BlockConstPoolScope block_const_pool(this);

  CHECK_LE(target, Builtins::kLastTier0);
  ldr(ip,
      MemOperand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(target)));
  Call(ip);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);

  // The above code must not emit constants either.
  DCHECK(!has_pending_constants());
}

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::I64x2BitMask(Register dst, QwNeonRegister src) {
  UseScratchRegisterScope temps(this);
  QwNeonRegister tmp1 = temps.AcquireQ();
  Register tmp = temps.Acquire();

  vshr(NeonU64, tmp1, src, 63);
  vmov(NeonU32, dst, tmp1.low(), 0);
  vmov(NeonU32, tmp, tmp1.high(), 0);
  add(dst, dst, Operand(tmp, LSL, 1));
}

void MacroAssembler::I64x2Eq(QwNeonRegister dst, QwNeonRegister src1,
                             QwNeonRegister src2) {
  UseScratchRegisterScope temps(this);
  Simd128Register scratch = temps.AcquireQ();
  vceq(Neon32, dst, src1, src2);
  vrev64(Neon32, scratch, dst);
  vand(dst, dst, scratch);
}

void MacroAssembler::I64x2Ne(QwNeonRegister dst, QwNeonRegister src1,
                             QwNeonRegister src2) {
  UseScratchRegisterScope temps(this);
  Simd128Register tmp = temps.AcquireQ();
  vceq(Neon32, dst, src1, src2);
  vrev64(Neon32, tmp, dst);
  vmvn(dst, dst);
  vorn(dst, dst, tmp);
}

void MacroAssembler::I64x2GtS(QwNeonRegister dst, QwNeonRegister src1,
                              QwNeonRegister src2) {
  ASM_CODE_COMMENT(this);
  vqsub(NeonS64, dst, src2, src1);
  vshr(NeonS64, dst, dst, 63);
}

void MacroAssembler::I64x2GeS(QwNeonRegister dst, QwNeonRegister src1,
                              QwNeonRegister src2) {
  ASM_CODE_COMMENT(this);
  vqsub(NeonS64, dst, src1, src2);
  vshr(NeonS64, dst, dst, 63);
  vmvn(dst, dst);
}

void MacroAssembler::I64x2AllTrue(Register dst, QwNeonRegister src) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  QwNeonRegister tmp = temps.AcquireQ();
  // src = | a | b | c | d |
  // tmp = | max(a,b) | max(c,d) | ...
  vpmax(NeonU32, tmp.low(), src.low(), src.high());
  // tmp = | max(a,b) == 0 | max(c,d) == 0 | ...
  vceq(Neon32, tmp, tmp, 0);
  // tmp = | max(a,b) == 0 or max(c,d) == 0 | ...
  vpmax(NeonU32, tmp.low(), tmp.low(), tmp.low());
  // dst = (max(a,b) == 0 || max(c,d) == 0)
  // dst will either be -1 or 0.
  vmov(NeonS32, dst, tmp.low(), 0);
  // dst = !dst (-1 -> 0, 0 -> 1)
  add(dst, dst, Operand(1));
  // This works because:
  // !dst
  // = !(max(a,b) == 0 || max(c,d) == 0)
  // = max(a,b) != 0 && max(c,d) != 0
  // = (a != 0 || b != 0) && (c != 0 || d != 0)
  // = defintion of i64x2.all_true.
}

void MacroAssembler::I64x2Abs(QwNeonRegister dst, QwNeonRegister src) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Simd128Register tmp = temps.AcquireQ();
  vshr(NeonS64, tmp, src, 63);
  veor(dst, src, tmp);
  vsub(Neon64, dst, dst, tmp);
}

namespace {
using AssemblerFunc = void (Assembler::*)(DwVfpRegister, SwVfpRegister,
                                          VFPConversionMode, const Condition);
// Helper function for f64x2 convert low instructions.
// This ensures that we do not overwrite src, if dst == src.
void F64x2ConvertLowHelper(Assembler* assm, QwNeonRegister dst,
                           QwNeonRegister src, AssemblerFunc convert_fn) {
  LowDwVfpRegister src_d = LowDwVfpRegister::from_code(src.low().code());
  UseScratchRegisterScope temps(assm);
  if (dst == src) {
    LowDwVfpRegister tmp = temps.AcquireLowD();
    assm->vmov(tmp, src_d);
    src_d = tmp;
  }
  // Default arguments are not part of the function type
  (assm->*convert_fn)(dst.low(), src_d.low(), kDefaultRoundToZero, al);
  (assm->*convert_fn)(dst.high(), src_d.high(), kDefaultRoundToZero, al);
}
}  // namespace

void MacroAssembler::F64x2ConvertLowI32x4S(QwNeonRegister dst,
                                           QwNeonRegister src) {
  F64x2ConvertLowHelper(this, dst, src, &Assembler::vcvt_f64_s32);
}

void MacroAssembler::F64x2ConvertLowI32x4U(QwNeonRegister dst,
                                           QwNeonRegister src) {
  F64x2ConvertLowHelper(this, dst, src, &Assembler::vcvt_f64_u32);
}

void MacroAssembler::F64x2PromoteLowF32x4(QwNeonRegister dst,
                                          QwNeonRegister src) {
  F64x2ConvertLowHelper(this, dst, src, &Assembler::vcvt_f64_f32);
}

void MacroAssembler::Switch(Register scratch, Register value,
                            int case_value_base, Label** labels,
                            int num_labels) {
  Label fallthrough;
  if (case_value_base != 0) {
    sub(value, value, Operand(case_value_base));
  }
  // This {cmp} might still emit a constant pool entry.
  cmp(value, Operand(num_labels));
  // Ensure to emit the constant pool first if necessary.
  CheckConstPool(true, true);
  BlockConstPoolFor(num_labels + 2);
  add(pc, pc, Operand(value, LSL, 2), LeaveCC, lo);
  b(&fallthrough);
  for (int i = 0; i < num_labels; ++i) {
    b(labels[i]);
  }
  bind(&fallthrough);
}

void MacroAssembler::JumpIfCodeIsMarkedForDeoptimization(
    Register code, Register scratch, Label* if_marked_for_deoptimization) {
  ldr(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  tst(scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
  b(if_marked_for_deoptimization, ne);
}

void MacroAssembler::JumpIfCodeIsTurbofanned(Register code, Register scratch,
                                             Label* if_turbofanned) {
  ldr(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  tst(scratch, Operand(1 << Code::kIsTurbofannedBit));
  b(if_turbofanned, ne);
}

void MacroAssembler::TryLoadOptimizedOsrCode(Register scratch_and_result,
                                             CodeKind min_opt_level,
                                             Register feedback_vector,
                                             FeedbackSlot slot,
                                             Label* on_result,
                                             Label::Distance) {
  Label fallthrough, clear_slot;
  LoadTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));
  LoadWeakValue(scratch_and_result, scratch_and_result, &fallthrough);

  // Is it marked_for_deoptimization? If yes, clear the slot.
  {
    UseScratchRegisterScope temps(this);

    // The entry references a CodeWrapper object. Unwrap it now.
    ldr(scratch_and_result,
        FieldMemOperand(scratch_and_result, CodeWrapper::kCodeOffset));

    Register temp = temps.Acquire();
    JumpIfCodeIsMarkedForDeoptimization(scratch_and_result, temp, &clear_slot);
    if (min_opt_level == CodeKind::TURBOFAN_JS) {
      JumpIfCodeIsTurbofanned(scratch_and_result, temp, on_result);
      b(&fallthrough);
    } else {
      b(on_result);
    }
  }

  bind(&clear_slot);
  Move(scratch_and_result, ClearedValue());
  StoreTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));

  bind(&fallthrough);
  Move(scratch_and_result, Operand(0));
}

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for the fast call).
void CallApiFunctionAndReturn(MacroAssembler* masm, bool with_profiling,
                              Register function_address,
                              ExternalReference thunk_ref, Register thunk_arg,
                              int slots_to_drop_on_return,
                              MemOperand* argc_operand,
                              MemOperand return_value_operand) {
  ASM_CODE_COMMENT(masm);

  using ER = ExternalReference;

  Isolate* isolate = masm->isolate();
  MemOperand next_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_next_address(isolate), no_reg);
  MemOperand limit_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_limit_address(isolate), no_reg);
  MemOperand level_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_level_address(isolate), no_reg);

  Register return_value = r0;
  Register scratch = r8;
  Register scratch2 = r9;

  // Allocate HandleScope in callee-saved registers.
  // We will need to restore the HandleScope after the call to the API function,
  // by allocating it in callee-saved registers it'll be preserved by C code.
  Register prev_next_address_reg = r4;
  Register prev_limit_reg = r5;
  Register prev_level_reg = r6;

  // C arguments (kCArgRegs[0/1]) are expected to be initialized outside, so
  // this function must not corrupt them (return_value overlaps with
  // kCArgRegs[0] but that's ok because we start using it only after the C
  // call).
  DCHECK(!AreAliased(kCArgRegs[0], kCArgRegs[1],  // C args
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  // function_address and thunk_arg might overlap but this function must not
  // corrupted them until the call is made (i.e. overlap with return_value is
  // fine).
  DCHECK(!AreAliased(function_address,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  DCHECK(!AreAliased(thunk_arg,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Allocate HandleScope in callee-save registers.");
    __ ldr(prev_next_address_reg, next_mem_op);
    __ ldr(prev_limit_reg, limit_mem_op);
    __ ldr(prev_level_reg, level_mem_op);
    __ add(scratch, prev_level_reg, Operand(1));
    __ str(scratch, level_mem_op);
  }

  Label profiler_or_side_effects_check_enabled, done_api_call;
  if (with_profiling) {
    __ RecordComment("Check if profiler or side effects check is enabled");
    __ ldrb(scratch,
            __ ExternalReferenceAsOperand(IsolateFieldId::kExecutionMode));
    __ cmp(scratch, Operand(0));
    __ b(ne, &profiler_or_side_effects_check_enabled);
#ifdef V8_RUNTIME_CALL_STATS
    __ RecordComment("Check if RCS is enabled");
    __ Move(scratch, ER::address_of_runtime_stats_flag());
    __ ldr(scratch, MemOperand(scratch, 0));
    __ cmp(scratch, Operand(0));
    __ b(ne, &profiler_or_side_effects_check_enabled);
#endif  // V8_RUNTIME_CALL_STATS
  }

  __ RecordComment("Call the api function directly.");
  __ StoreReturnAddressAndCall(function_address);
  __ bind(&done_api_call);

  Label propagate_exception;
  Label delete_allocated_handles;
  Label leave_exit_frame;

  __ RecordComment("Load the value from ReturnValue");
  __ ldr(return_value, return_value_operand);

  {
    ASM_CODE_COMMENT_STRING(
        masm,
        "No more valid handles (the result handle was the last one)."
        "Restore previous handle scope.");
    __ str(prev_next_address_reg, next_mem_op);
    if (v8_flags.debug_code) {
      __ ldr(scratch, level_mem_op);
      __ sub(scratch, scratch, Operand(1));
      __ cmp(scratch, prev_level_reg);
      __ Check(eq, AbortReason::kUnexpectedLevelAfterReturnFromApiCall);
    }
    __ str(prev_level_reg, level_mem_op);
    __ ldr(scratch, limit_mem_op);
    __ cmp(scratch, prev_limit_reg);
    __ b(ne, &delete_allocated_handles);
  }

  __ RecordComment("Leave the API exit frame.");
  __ bind(&leave_exit_frame);

  Register argc_reg = prev_limit_reg;
  if (argc_operand != nullptr) {
    // Load the number of stack slots to drop before LeaveExitFrame modifies sp.
    __ ldr(argc_reg, *argc_operand);
  }
  __ LeaveExitFrame(scratch);

  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Check if the function scheduled an exception.");
    __ LoadRoot(scratch, RootIndex::kTheHoleValue);
    __ ldr(scratch2, __ ExternalReferenceAsOperand(
                         ER::exception_address(isolate), no_reg));
    __ cmp(scratch, scratch2);
    __ b(ne, &propagate_exception);
  }

  __ AssertJSAny(return_value, scratch, scratch2,
                 AbortReason::kAPICallReturnedInvalidObject);

  if (argc_operand == nullptr) {
    DCHECK_NE(slots_to_drop_on_return, 0);
    __ add(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));

  } else {
    // {argc_operand} was loaded into {argc_reg} above.
    __ add(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));
    __ add(sp, sp, Operand(argc_reg, LSL, kSystemPointerSizeLog2));
  }

  __ mov(pc, lr);

  if (with_profiling) {
    ASM_CODE_COMMENT_STRING(masm, "Call the api function via thunk wrapper.");
    __ bind(&profiler_or_side_effects_check_enabled);
    // Additional parameter is the address of the actual callback function.
    if (thunk_arg.is_valid()) {
      MemOperand thunk_arg_mem_op = __ ExternalReferenceAsOperand(
          IsolateFieldId::kApiCallbackThunkArgument);
      __ str(thunk_arg, thunk_arg_mem_op);
    }
    __ Move(scratch, thunk_ref);
    __ StoreReturnAddressAndCall(scratch);
    __ b(&done_api_call);
  }

  __ RecordComment("An exception was thrown. Propagate it.");
  __ bind(&propagate_exception);
  __ TailCallRuntime(Runtime::kPropagateException);
  {
    ASM_CODE_COMMENT_STRING(
        masm, "HandleScope limit has changed. Delete allocated extensions.");
    __ bind(&delete_allocated_handles);
    __ str(prev_limit_reg, limit_mem_op);
    // Save the return value in a callee-save register.
    Register saved_result = prev_limit_reg;
    __ mov(saved_result, return_value);
    __ PrepareCallCFunction(1);
    __ Move(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::delete_handle_scope_extensions(), 1);
    __ mov(return_value, saved_result);
    __ jmp(&leave_exit_frame);
  }
}

}  // namespace internal
}  // namespace v8

#undef __

#endif  // V8_TARGET_ARCH_ARM

"""


```
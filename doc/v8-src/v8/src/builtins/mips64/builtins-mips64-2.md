Response: The user wants to understand the functionality of the C++ code provided, which is part of the V8 JavaScript engine specifically for the MIPS64 architecture. The request is split into three parts, and this is the third part. Since this is the final part, I need to synthesize the understanding from all parts.

**Part 1 and 2 Analysis (Implicit from the structure of the request):**

It's likely that the previous parts covered:

*   **Entry points for JavaScript calls into C++:** This would involve setting up the stack frame and calling the appropriate C++ function.
*   **Handling different types of JavaScript calls:**  Potentially related to regular function calls, constructor calls, and calls with a specific number of arguments.
*   **Possibly some basic built-in functions:** Implementations of fundamental JavaScript operations.

**Part 3 Analysis (Focusing on the provided code):**

This part primarily deals with:

*   **Deoptimization:** The process of moving execution from optimized (compiled) code back to the interpreter.
*   **Baseline code execution:**  A less optimized, but faster than the interpreter, version of JavaScript code.
*   **Interpreter entry:**  How to start executing JavaScript code in the interpreter.

**Connecting to JavaScript:**

The key is to understand how these low-level C++ functions facilitate the execution of JavaScript. Deoptimization happens when the engine detects that the optimized code might be producing incorrect results due to assumptions made during compilation. Baseline code provides a middle ground for performance. The interpreter is the fallback for all JavaScript execution.

**High-Level Plan:**

1. Summarize the core functionalities present in this part of the code.
2. Explain how these functionalities relate to JavaScript execution.
3. Provide JavaScript examples to illustrate the concepts.
这是 `v8/src/builtins/mips64/builtins-mips64.cc` 文件的第三部分，它主要包含了以下功能：

**1. Deoptimization Entry (Generate_DeoptimizationEntry):**

*   **功能:**  处理从优化后的机器码（例如 TurboFan 生成的代码）返回到解释器执行的过程。当优化后的代码由于某些原因（例如类型推断失败）无法继续执行时，就需要进行反优化。这个函数负责保存当前机器状态（寄存器、栈等），创建一个 `Deoptimizer` 对象，并计算出返回到解释器时需要恢复的状态。
*   **与 JavaScript 的关系:**  当 JavaScript 代码被 V8 的优化编译器优化后，执行速度会更快。但是，如果运行时的实际类型与编译时假设的类型不符，或者发生了其他需要回到解释器执行的情况，就会触发反优化。这个过程对用户是透明的，但它是保证 JavaScript 代码正确执行的重要机制。

**2. Eager 和 Lazy Deoptimization Entry (Generate_DeoptimizationEntry_Eager, Generate_DeoptimizationEntry_Lazy):**

*   **功能:**  这是 `Generate_DeoptimizationEntry` 的两个入口点，区分了两种反优化的时机：
    *   `Generate_DeoptimizationEntry_Eager`:  立即进行反优化。
    *   `Generate_DeoptimizationEntry_Lazy`:  在稍后的某个时间点进行反优化。
*   **与 JavaScript 的关系:**  无论是哪种反优化，最终的目的都是回到解释器执行 JavaScript 代码，以保证程序的正确性。

**3. Baseline 或 Interpreter Entry (Generate_BaselineOrInterpreterEntry):**

*   **功能:**  决定如何开始执行一个 JavaScript 函数。它会检查是否存在 baseline 代码（一种比解释器快但不如优化代码快的中间表示），如果存在就跳转到 baseline 代码执行，否则就进入解释器执行。
*   **与 JavaScript 的关系:**  当 V8 首次遇到一个 JavaScript 函数时，通常会先在解释器中执行。如果该函数被频繁调用，V8 可能会为其生成 baseline 代码或更优化的代码。这个函数就是决定在函数调用时，选择使用哪种执行方式的入口点。

**4. Interpreter On-Stack Replacement (OSR) 到 Baseline (Generate_InterpreterOnStackReplacement_ToBaseline):**

*   **功能:**  当一个正在解释器中执行的循环变得“热”时，V8 可以在不退出函数执行的情况下，将其替换为 baseline 代码继续执行。这个过程称为 On-Stack Replacement (OSR)。这个函数是 OSR 到 baseline 代码的入口点。
*   **与 JavaScript 的关系:**  OSR 是一种优化技术，允许 V8 在运行时动态地将解释执行的代码升级到更快的 baseline 代码，从而提高性能。

**5. Restart Frame Trampoline (Generate_RestartFrameTrampoline):**

*   **功能:**  当需要“重启”一个帧时使用。这通常发生在例如调试或者执行 generator 函数的场景中。它会清理当前的帧，然后重新调用对应的 JavaScript 函数。
*   **与 JavaScript 的关系:**  这个函数与 JavaScript 的执行流程控制有关，特别是在处理中断或需要重新执行函数的情况。

**JavaScript 示例:**

以下 JavaScript 例子可以帮助理解反优化和 baseline 代码的概念：

```javascript
function add(a, b) {
  return a + b;
}

// 第一次调用，可能在解释器中执行
add(1, 2);

// 多次调用后，V8 可能会生成 baseline 代码或者更优化的代码
for (let i = 0; i < 10000; i++) {
  add(i, i + 1);
}

// 之后如果传入了不同类型的参数，可能会触发反优化
add("hello", "world"); // 假设优化后的代码只针对数字做了优化
```

**解释:**

1. 最初，`add(1, 2)` 可能在解释器中执行。
2. 随着 `add` 函数被多次调用，V8 会分析其行为，如果它总是接收数字参数，可能会生成 baseline 代码或者更优化的机器码，这样后续的 `add(i, i + 1)` 执行速度会更快。
3. 但是，当调用 `add("hello", "world")` 时，由于参数类型发生了变化（从数字变为字符串），之前优化后的代码可能无法处理这种情况，这时就会触发反优化，程序会回到解释器执行。`Generate_DeoptimizationEntry` 系列的函数就负责处理这个过程。
4. `Generate_BaselineOrInterpreterEntry` 会在函数首次被调用或反优化后决定是否可以使用 baseline 代码或回退到解释器。
5. 如果在一个正在执行的循环中，V8 决定使用 baseline 代码，`Generate_InterpreterOnStackReplacement_ToBaseline` 就会被调用。

总而言之，这部分代码是 V8 引擎中处理代码优化、反优化以及不同执行模式切换的关键组成部分，它保证了 JavaScript 代码在各种情况下的正确执行，并尽可能地提高性能。

Prompt: 
```
这是目录为v8/src/builtins/mips64/builtins-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
alling convention. Callers use
  // EnterExitFrame/LeaveExitFrame so they handle stack restoring and we don't
  // have to do that here. Any caller must drop kCArgsSlotsSize stack space
  // after the call.
  __ daddiu(sp, sp, -kCArgsSlotsSize);

  __ Sd(ra, MemOperand(sp, kCArgsSlotsSize));  // Store the return address.
  __ Call(t9);                                 // Call the C++ function.
  __ Ld(t9, MemOperand(sp, kCArgsSlotsSize));  // Return to calling code.

  if (v8_flags.debug_code && v8_flags.enable_slow_asserts) {
    // In case of an error the return address may point to a memory area
    // filled with kZapValue by the GC. Dereference the address and check for
    // this.
    __ Uld(a4, MemOperand(t9));
    __ Assert(ne, AbortReason::kReceivedInvalidReturnAddress, a4,
              Operand(reinterpret_cast<uint64_t>(kZapValue)));
  }

  __ Jump(t9);
}

namespace {

// This code tries to be close to ia32 code so that any changes can be
// easily ported.
void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // Unlike on ARM we don't save all the registers, just the useful ones.
  // For the rest, there are gaps on the stack, so the offsets remain the same.
  const int kNumberOfRegisters = Register::kNumRegisters;

  RegList restored_regs = kJSCallerSaved | kCalleeSaved;
  RegList saved_regs = restored_regs | sp | ra;

  const int kMSARegsSize = kSimd128Size * MSARegister::kNumRegisters;

  // Save all allocatable simd128 / double registers before messing with them.
  __ Dsubu(sp, sp, Operand(kMSARegsSize));
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  {
    // Check if machine has simd support, if so save vector registers.
    // If not then save double registers.
    Label no_simd, done;
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();

    __ li(scratch, ExternalReference::supports_wasm_simd_128_address());
    // If > 0 then simd is available.
    __ Lbu(scratch, MemOperand(scratch));
    __ Branch(&no_simd, le, scratch, Operand(zero_reg));

    CpuFeatureScope msa_scope(
        masm, MIPS_SIMD, CpuFeatureScope::CheckPolicy::kDontCheckSupported);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int offset = code * kSimd128Size;
      const MSARegister fpu_reg = MSARegister::from_code(code);
      __ st_d(fpu_reg, MemOperand(sp, offset));
    }
    __ Branch(&done);

    __ bind(&no_simd);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int offset = code * kSimd128Size;
      const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
      __ Sdc1(fpu_reg, MemOperand(sp, offset));
    }

    __ bind(&done);
  }

  // Push saved_regs (needed to populate FrameDescription::registers_).
  // Leave gaps for other registers.
  __ Dsubu(sp, sp, kNumberOfRegisters * kSystemPointerSize);
  for (int16_t i = kNumberOfRegisters - 1; i >= 0; i--) {
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ Sd(ToRegister(i), MemOperand(sp, kSystemPointerSize * i));
    }
  }

  __ li(a2,
        ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate));
  __ Sd(fp, MemOperand(a2));

  const int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kSystemPointerSize) + kMSARegsSize;

  // Get the address of the location in the code object (a2) (return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register a3.
  __ mov(a2, ra);
  __ Daddu(a3, sp, Operand(kSavedRegistersAreaSize));

  __ Dsubu(a3, fp, a3);

  // Allocate a new deoptimizer object.
  __ PrepareCallCFunction(5, a4);
  // Pass six arguments, according to n64 ABI.
  __ mov(a0, zero_reg);
  Label context_check;
  __ Ld(a1, MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(a1, &context_check);
  __ Ld(a0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ li(a1, Operand(static_cast<int>(deopt_kind)));
  // a2: code address or 0 already loaded.
  // a3: already has fp-to-sp delta.
  __ li(a4, ExternalReference::isolate_address());

  // Call Deoptimizer::New().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register v0 and get the input
  // frame descriptor pointer to a1 (deoptimizer->input_);
  // Move deopt-obj to a0 for call to Deoptimizer::ComputeOutputFrames() below.
  __ mov(a0, v0);
  __ Ld(a1, MemOperand(v0, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_[kNumRegisters].
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ Ld(a2, MemOperand(sp, i * kSystemPointerSize));
      __ Sd(a2, MemOperand(a1, offset));
    } else if (v8_flags.debug_code) {
      __ li(a2, kDebugZapValue);
      __ Sd(a2, MemOperand(a1, offset));
    }
  }

  // Copy simd128 / double registers to the input frame.
  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  {
    // Check if machine has simd support, if so copy vector registers.
    // If not then copy double registers.
    Label no_simd, done;
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();

    __ li(scratch, ExternalReference::supports_wasm_simd_128_address());
    // If > 0 then simd is available.
    __ Lbu(scratch, MemOperand(scratch));
    __ Branch(&no_simd, le, scratch, Operand(zero_reg));

    CpuFeatureScope msa_scope(
        masm, MIPS_SIMD, CpuFeatureScope::CheckPolicy::kDontCheckSupported);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int dst_offset = code * kSimd128Size + simd128_regs_offset;
      int src_offset =
          code * kSimd128Size + kNumberOfRegisters * kSystemPointerSize;
      __ ld_d(w0, MemOperand(sp, src_offset));
      __ st_d(w0, MemOperand(a1, dst_offset));
    }
    __ Branch(&done);

    __ bind(&no_simd);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int dst_offset = code * kSimd128Size + simd128_regs_offset;
      int src_offset =
          code * kSimd128Size + kNumberOfRegisters * kSystemPointerSize;
      __ Ldc1(f0, MemOperand(sp, src_offset));
      __ Sdc1(f0, MemOperand(a1, dst_offset));
    }

    __ bind(&done);
  }

  // Remove the saved registers from the stack.
  __ Daddu(sp, sp, Operand(kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register a2; that is
  // the first stack slot not part of the input frame.
  __ Ld(a2, MemOperand(a1, FrameDescription::frame_size_offset()));
  __ Daddu(a2, a2, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ Daddu(a3, a1, Operand(FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ BranchShort(&pop_loop_header);
  __ bind(&pop_loop);
  __ pop(a4);
  __ Sd(a4, MemOperand(a3, 0));
  __ daddiu(a3, a3, sizeof(uint64_t));
  __ bind(&pop_loop_header);
  __ BranchShort(&pop_loop, ne, a2, Operand(sp));
  // Compute the output frame in the deoptimizer.
  __ push(a0);  // Preserve deoptimizer object across call.
  // a0: deoptimizer object; a1: scratch.
  __ PrepareCallCFunction(1, a1);
  // Call Deoptimizer::ComputeOutputFrames().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ pop(a0);  // Restore deoptimizer object (class Deoptimizer).

  __ Ld(sp, MemOperand(a0, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: a4 = current "FrameDescription** output_",
  // a1 = one past the last FrameDescription**.
  __ Lw(a1, MemOperand(a0, Deoptimizer::output_count_offset()));
  __ Ld(a4, MemOperand(a0, Deoptimizer::output_offset()));  // a4 is output_.
  __ Dlsa(a1, a4, a1, kSystemPointerSizeLog2);
  __ BranchShort(&outer_loop_header);

  __ bind(&outer_push_loop);
  Register current_frame = a2;
  Register frame_size = a3;
  __ Ld(current_frame, MemOperand(a4, 0));
  __ Ld(frame_size,
        MemOperand(current_frame, FrameDescription::frame_size_offset()));
  __ BranchShort(&inner_loop_header);

  __ bind(&inner_push_loop);
  __ Dsubu(frame_size, frame_size, Operand(sizeof(uint64_t)));
  __ Daddu(a6, current_frame, Operand(frame_size));
  __ Ld(a7, MemOperand(a6, FrameDescription::frame_content_offset()));
  __ push(a7);

  __ bind(&inner_loop_header);
  __ BranchShort(&inner_push_loop, ne, frame_size, Operand(zero_reg));

  __ Daddu(a4, a4, Operand(kSystemPointerSize));

  __ bind(&outer_loop_header);
  __ BranchShort(&outer_push_loop, lt, a4, Operand(a1));

  {
    // Check if machine has simd support, if so restore vector registers.
    // If not then restore double registers.
    Label no_simd, done;
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();

    __ li(scratch, ExternalReference::supports_wasm_simd_128_address());
    // If > 0 then simd is available.
    __ Lbu(scratch, MemOperand(scratch));
    __ Branch(&no_simd, le, scratch, Operand(zero_reg));

    CpuFeatureScope msa_scope(
        masm, MIPS_SIMD, CpuFeatureScope::CheckPolicy::kDontCheckSupported);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int src_offset = code * kSimd128Size + simd128_regs_offset;
      const MSARegister fpu_reg = MSARegister::from_code(code);
      __ ld_d(fpu_reg, MemOperand(current_frame, src_offset));
    }
    __ Branch(&done);

    __ bind(&no_simd);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int src_offset = code * kSimd128Size + simd128_regs_offset;
      const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
      __ Ldc1(fpu_reg, MemOperand(current_frame, src_offset));
    }

    __ bind(&done);
  }

  // Push pc and continuation from the last output frame.
  __ Ld(a6, MemOperand(current_frame, FrameDescription::pc_offset()));
  __ push(a6);
  __ Ld(a6, MemOperand(current_frame, FrameDescription::continuation_offset()));
  __ push(a6);

  // Technically restoring 'at' should work unless zero_reg is also restored
  // but it's safer to check for this.
  DCHECK(!(restored_regs.has(at)));
  // Restore the registers from the last output frame.
  __ mov(at, current_frame);
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((restored_regs.bits() & (1 << i)) != 0) {
      __ Ld(ToRegister(i), MemOperand(at, offset));
    }
  }

  // If the continuation is non-zero (JavaScript), branch to the continuation.
  // For Wasm just return to the pc from the last output frame in the lr
  // register.
  Label end;
  __ pop(at);  // Get continuation, leave pc on stack.
  __ pop(ra);
  __ Branch(&end, eq, at, Operand(zero_reg));
  __ Jump(at);

  __ bind(&end);
  __ Jump(ra);
}

}  // namespace

void Builtins::Generate_DeoptimizationEntry_Eager(MacroAssembler* masm) {
  Generate_DeoptimizationEntry(masm, DeoptimizeKind::kEager);
}

void Builtins::Generate_DeoptimizationEntry_Lazy(MacroAssembler* masm) {
  Generate_DeoptimizationEntry(masm, DeoptimizeKind::kLazy);
}

namespace {

// Restarts execution either at the current or next (in execution order)
// bytecode. If there is baseline code on the shared function info, converts an
// interpreter frame into a baseline frame and continues execution in baseline
// code. Otherwise execution continues with bytecode.
void Generate_BaselineOrInterpreterEntry(MacroAssembler* masm,
                                         bool next_bytecode,
                                         bool is_osr = false) {
  Label start;
  __ bind(&start);

  // Get function from the frame.
  Register closure = a1;
  __ Ld(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = s1;
  __ Ld(code_obj,
        FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj);
  }

  __ Ld(code_obj,
        FieldMemOperand(code_obj,
                        SharedFunctionInfo::kTrustedFunctionDataOffset));

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ GetObjectType(code_obj, t2, t2);
    __ Branch(&start_with_baseline, eq, t2, Operand(CODE_TYPE));

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ GetObjectType(code_obj, t2, t2);
    __ Assert(eq, AbortReason::kExpectedBaselineData, t2, Operand(CODE_TYPE));
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, t2);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = a2;
  Register feedback_vector = t8;
  __ Ld(feedback_cell,
        FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ Ld(feedback_vector,
        FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ GetObjectType(feedback_vector, t2, t2);
  __ Branch(&install_baseline_code, ne, t2, Operand(FEEDBACK_VECTOR_TYPE));

  // Save BytecodeOffset from the stack frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  // Replace BytecodeOffset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ Sd(feedback_cell,
        MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ Sd(feedback_vector,
        MemOperand(fp, InterpreterFrameConstants::kFeedbackVectorFromFp));
  feedback_vector = no_reg;

  // Compute baseline pc for bytecode offset.
  ExternalReference get_baseline_pc_extref;
  if (next_bytecode || is_osr) {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_next_executed_bytecode();
  } else {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_bytecode_offset();
  }

  Register get_baseline_pc = a3;
  __ li(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ Branch(&function_entry_bytecode, eq, kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                      kFunctionEntryBytecodeOffset));
  }

  __ Dsubu(kInterpreterBytecodeOffsetRegister,
           kInterpreterBytecodeOffsetRegister,
           (BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ Ld(kInterpreterBytecodeArrayRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
  __ Push(kInterpreterAccumulatorRegister);
  {
    __ Move(kCArgRegs[0], code_obj);
    __ Move(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ Move(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PrepareCallCFunction(3, 0, a4);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ LoadCodeInstructionStart(code_obj, code_obj, kJSEntrypointTag);
  __ Daddu(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    // TODO(liuyu): Remove Ld as arm64 after register reallocation.
    __ Ld(kInterpreterBytecodeArrayRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
    Generate_OSREntry(masm, code_obj);
  } else {
    __ Jump(code_obj);
  }
  __ Trap();  // Unreachable.

  if (!is_osr) {
    __ bind(&function_entry_bytecode);
    // If the bytecode offset is kFunctionEntryOffset, get the start address of
    // the first bytecode.
    __ mov(kInterpreterBytecodeOffsetRegister, zero_reg);
    if (next_bytecode) {
      __ li(get_baseline_pc,
            ExternalReference::baseline_pc_for_bytecode_offset());
    }
    __ Branch(&valid_bytecode_offset);
  }

  __ bind(&install_baseline_code);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(kInterpreterAccumulatorRegister);
    __ Push(closure);
    __ CallRuntime(Runtime::kInstallBaselineCode, 1);
    __ Pop(kInterpreterAccumulatorRegister);
  }
  // Retry from the start after installing baseline code.
  __ Branch(&start);
}

}  // namespace

void Builtins::Generate_BaselineOrInterpreterEnterAtBytecode(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, false);
}

void Builtins::Generate_BaselineOrInterpreterEnterAtNextBytecode(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, true);
}

void Builtins::Generate_InterpreterOnStackReplacement_ToBaseline(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, false, true);
}

void Builtins::Generate_RestartFrameTrampoline(MacroAssembler* masm) {
  // Frame is being dropped:
  // - Look up current function on the frame.
  // - Leave the frame.
  // - Restart the frame by calling the function.

  __ Ld(a1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ Ld(a0, MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // Pop return address and frame.
  __ LeaveFrame(StackFrame::INTERPRETED);

  __ li(a2, Operand(kDontAdaptArgumentsSentinel));

  __ InvokeFunction(a1, a2, a0, InvokeType::kJump);
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_MIPS64

"""


```
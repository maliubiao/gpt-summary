Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `builtins-arm64.cc` file. I need to analyze the code and provide a summary of its functions. The decomposed instructions are:

1. **List the functions of the code:** I need to identify the different functions defined in the code and explain what each function does.
2. **Check for Torque source:** Determine if the filename ends with `.tq`. If so, state that it's a Torque source.
3. **Relate to JavaScript:** If any function is related to JavaScript functionality, provide a JavaScript example to illustrate the connection.
4. **Provide code logic inference with examples:** For functions involving code logic, create hypothetical inputs and expected outputs to demonstrate the function's behavior.
5. **Identify common programming errors:** Point out potential programming mistakes that the code helps to handle or prevent.
6. **Summarize the overall functionality:**  Provide a concise overview of the purpose of this code snippet within V8.
7. **Acknowledge part number:** Note that this is part 7 of 7.

Based on the code, the main functionalities are related to *deoptimization* and *entering baseline or interpreter code*.
```cpp
// Saved on the stack above core registers.
  const int kSimd128RegistersOffset = saved_registers.Count() * kXRegSize;

  Register code_object = x2;
  Register fp_to_sp = x3;
  // Get the address of the location in the code object. This is the return
  // address for lazy deoptimization.
  __ Mov(code_object, lr);
  // Compute the fp-to-sp delta.
  __ Add(fp_to_sp, sp, kSavedRegistersAreaSize);
  __ Sub(fp_to_sp, fp, fp_to_sp);

  // Allocate a new deoptimizer object.
  __ Ldr(x1, MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));

  // Ensure we can safely load from below fp.
  DCHECK_GT(kSavedRegistersAreaSize, -StandardFrameConstants::kFunctionOffset);
  __ Ldr(x0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // If x1 is a smi, zero x0.
  __ Tst(x1, kSmiTagMask);
  __ CzeroX(x0, eq);

  __ Mov(x1, static_cast<int>(deopt_kind));
  // Following arguments are already loaded:
  //  - x2: code object address
  //  - x3: fp-to-sp delta
  __ Mov(x4, ExternalReference::isolate_address());

  {
    // Call Deoptimizer::New().
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register x0.
  Register deoptimizer = x0;

  // Get the input frame descriptor pointer.
  __ Ldr(x1, MemOperand(deoptimizer, Deoptimizer::input_offset()));

  // Copy core registers into the input frame.
  CopyRegListToFrame(masm, x1, FrameDescription::registers_offset(),
                     saved_registers, x2, x3);

  // Copy simd128 / double registers to the input frame.
  CopyRegListToFrame(masm, x1, FrameDescription::simd128_registers_offset(),
                     saved_simd128_registers, q2, q3, kSimd128RegistersOffset);

  // Mark the stack as not iterable for the CPU profiler which won't be able to
  // walk the stack without the return address.
  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.AcquireX();
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ strb(xzr, MemOperand(is_iterable));
  }

  // Remove the saved registers from the stack.
  DCHECK_EQ(kSavedRegistersAreaSize % kXRegSize, 0);
  __ Drop(kSavedRegistersAreaSize / kXRegSize);

  // Compute a pointer to the unwinding limit in register x2; that is
  // the first stack slot not part of the input frame.
  Register unwind_limit = x2;
  __ Ldr(unwind_limit, MemOperand(x1, FrameDescription::frame_size_offset()));

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ Add(x3, x1, FrameDescription::frame_content_offset());
  __ SlotAddress(x1, 0);
  __ Lsr(unwind_limit, unwind_limit, kSystemPointerSizeLog2);
  __ Mov(x5, unwind_limit);
  __ CopyDoubleWords(x3, x1, x5);
  // Since {unwind_limit} is the frame size up to the parameter count, we might
  // end up with an unaligned stack pointer. This is later recovered when
  // setting the stack pointer to {caller_frame_top_offset}.
  __ Bic(unwind_limit, unwind_limit, 1);
  __ Drop(unwind_limit);

  // Compute the output frame in the deoptimizer.
  __ Push(padreg, x0);  // Preserve deoptimizer object across call.
  {
    // Call Deoptimizer::ComputeOutputFrames().
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ Pop(x4, padreg);  // Restore deoptimizer object (class Deoptimizer).

  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Ldr(scratch, MemOperand(x4, Deoptimizer::caller_frame_top_offset()));
    __ Mov(sp, scratch);
  }

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, outer_loop_header;
  __ Ldrsw(x1, MemOperand(x4, Deoptimizer::output_count_offset()));
  __ Ldr(x0, MemOperand(x4, Deoptimizer::output_offset()));
  __ Add(x1, x0, Operand(x1, LSL, kSystemPointerSizeLog2));
  __ B(&outer_loop_header);

  __ Bind(&outer_push_loop);
  Register current_frame = x2;
  Register frame_size = x3;
  __ Ldr(current_frame, MemOperand(x0, kSystemPointerSize, PostIndex));
  __ Ldr(x3, MemOperand(current_frame, FrameDescription::frame_size_offset()));
  __ Lsr(frame_size, x3, kSystemPointerSizeLog2);
  __ Claim(frame_size, kXRegSize, /*assume_sp_aligned=*/false);

  __ Add(x7, current_frame, FrameDescription::frame_content_offset());
  __ SlotAddress(x6, 0);
  __ CopyDoubleWords(x6, x7, frame_size);

  __ Bind(&outer_loop_header);
  __ Cmp(x0, x1);
  __ B(lt, &outer_push_loop);

  RestoreRegList(masm, saved_simd128_registers, current_frame,
                 FrameDescription::simd128_registers_offset());

  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.AcquireX();
    Register one = x4;
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ Mov(one, Operand(1));
    __ strb(one, MemOperand(is_iterable));
  }

  // TODO(all): ARM copies a lot (if not all) of the last output frame onto the
  // stack, then pops it all into registers. Here, we try to load it directly
  // into the relevant registers. Is this correct? If so, we should improve the
  // ARM code.

  // Restore registers from the last output frame.
  // Note that lr is not in the list of saved_registers and will be restored
  // later. We can use it to hold the address of last output frame while
  // reloading the other registers.
  DCHECK(!saved_registers.IncludesAliasOf(lr));
  Register last_output_frame = lr;
  __ Mov(last_output_frame, current_frame);

  RestoreRegList(masm, saved_registers, last_output_frame,
                 FrameDescription::registers_offset());

  UseScratchRegisterScope temps(masm);
  temps.Exclude(x17);
  Register continuation = x17;
  __ Ldr(continuation, MemOperand(last_output_frame,
                                  FrameDescription::continuation_offset()));
  __ Ldr(lr, MemOperand(last_output_frame, FrameDescription::pc_offset()));
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  __ Autibsp();
#endif
  // If the continuation is non-zero (JavaScript), branch to the continuation.
  // For Wasm just return to the pc from the last output frame in the lr
  // register.
  Label end;
  __ CompareAndBranch(continuation, 0, eq, &end);
  __ Br(continuation);
  __ Bind(&end);
  __ Ret();
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
  Register closure = x1;
  __ Ldr(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = x22;
  __ LoadTaggedField(
      code_obj,
      FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj);
  }

  __ LoadTrustedPointerField(
      code_obj,
      FieldMemOperand(code_obj, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ IsObjectType(code_obj, x3, x3, CODE_TYPE);
    __ B(eq, &start_with_baseline);

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ IsObjectType(code_obj, x3, x3, CODE_TYPE);
    __ Assert(eq, AbortReason::kExpectedBaselineData);
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, x3);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = x2;
  Register feedback_vector = x15;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ IsObjectType(feedback_vector, x3, x3, FEEDBACK_VECTOR_TYPE);
  __ B(ne, &install_baseline_code);

  // Save BytecodeOffset from the stack frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ Str(feedback_cell,
         MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ Str(feedback_vector,
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
  Register get_baseline_pc = x3;
  __ Mov(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ cmp(kInterpreterBytecodeOffsetRegister,
           Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                   kFunctionEntryBytecodeOffset));
    __ B(eq, &function_entry_bytecode);
  }

  __ Sub(kInterpreterBytecodeOffsetRegister, kInterpreterBytecodeOffsetRegister,
         (BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
  __ Push(padreg, kInterpreterAccumulatorRegister);
  {
    __ Mov(kCArgRegs[0], code_obj);
    __ Mov(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ Mov(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ LoadCodeInstructionStart(code_obj, code_obj, kJSEntrypointTag);
  __ Add(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister, padreg);

  if (is_osr) {
    Generate_OSREntry(masm, code_obj);
  } else {
    __ Jump(code_obj);
  }
  __ Trap();  // Unreachable.

  if (!is_osr) {
    __ bind(&function_entry_bytecode);
    // If the bytecode offset is kFunctionEntryOffset, get the start address of
    // the first bytecode.
    __ Mov(kInterpreterBytecodeOffsetRegister, Operand(0));
    if (next_bytecode) {
      __ Mov(get_baseline_pc,
             ExternalReference::baseline_pc_for_bytecode_offset());
    }
    __ B(&valid_bytecode_offset);
  }

  __ bind(&install_baseline_code);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(padreg, kInterpreterAccumulatorRegister);
    __ PushArgument(closure);
    __ CallRuntime(Runtime::kInstallBaselineCode, 1);
    __ Pop(kInterpreterAccumulatorRegister, padreg);
  }
  // Retry from the start after installing baseline code.
  __ B(&start);
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

  __ Ldr(x1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ ldr(x0, MemOperand(fp, StandardFrameConstants::kArgCOffset));

  __ LeaveFrame(StackFrame::INTERPRETED);

  // The arguments are already in the stack (including any necessary padding),
  // we should not try to massage the arguments again.
#ifdef V8_ENABLE_LEAPTIERING
  __ InvokeFunction(x1, x0, InvokeType::kJump,
                    ArgumentAdaptionMode::kDontAdapt);
#else
  __ Mov(x2, kDontAdaptArgumentsSentinel);
  __ InvokeFunction(x1, x2, x0, InvokeType::kJump);
#endif
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_ARM
```

### 功能列表:

1. **`Generate_DeoptimizationEntry`**: This function (and its specializations) handles the process of deoptimizing code. When the optimized (e.g., TurboFan-compiled) code makes assumptions that are no longer valid, it needs to revert to a less optimized version (interpreter or baseline). This function sets up the necessary steps to transition back, including:
    *   Saving the current state (registers, stack).
    *   Creating a `Deoptimizer` object to manage the process.
    *   Copying the frame information.
    *   Unwinding the stack.
    *   Computing the new output frame.
    *   Restoring the state and jumping to the continuation point.
2. **`Generate_DeoptimizationEntry_Eager`**: A specific entry point for deoptimization that occurs immediately (eagerly).
3. **`Generate_DeoptimizationEntry_Lazy`**: A specific entry point for deoptimization that occurs when the result of an operation is needed (lazily).
4. **`Generate_BaselineOrInterpreterEntry`**: This function handles the entry into either baseline code (a minimally optimized version) or the interpreter. It checks if baseline code exists for a function and transitions to it if available. Otherwise, it enters the interpreter. This function also handles On-Stack Replacement (OSR), where an interpreter frame is replaced with a baseline frame during execution.
5. **`Generate_BaselineOrInterpreterEnterAtBytecode`**:  An entry point for `Generate_BaselineOrInterpreterEntry` that starts execution at the current bytecode.
6. **`Generate_BaselineOrInterpreterEnterAtNextBytecode`**: An entry point for `Generate_BaselineOrInterpreterEntry` that starts execution at the next bytecode.
7. **`Generate_InterpreterOnStackReplacement_ToBaseline`**:  An entry point for `Generate_BaselineOrInterpreterEntry` specifically for transitioning from the interpreter to baseline code during OSR.
8. **`Generate_RestartFrameTrampoline`**: This function is called when an interpreted frame needs to be restarted. It retrieves the function and argument count from the frame, leaves the current frame, and then calls the function again, effectively restarting its execution.

### Torque 源代码:

The filename `v8/src/builtins/arm64/builtins-arm64.cc` does **not** end with `.tq`. Therefore, it is **not** a V8 Torque source file. It's a C++ source file containing assembly code generated using V8's MacroAssembler.

### 与 JavaScript 功能的关系及示例:

The functions in this file are directly related to how JavaScript code is executed and optimized in V8.

*   **Deoptimization**: This is triggered when the runtime conditions invalidate optimizations made by the compiler. For example, if a function was optimized assuming a certain object property type, and later that property's type changes, deoptimization occurs.

    ```javascript
    function add(a, b) {
      return a + b;
    }

    // Initially, V8 might optimize 'add' assuming a and b are numbers.
    add(1, 2);

    // Later, if the function is called with non-numbers, it might trigger deoptimization.
    add("hello", "world");
    ```

*   **Baseline/Interpreter Entry**: When a JavaScript function is first called, it's typically executed by the interpreter. As the function is called more often, V8 might compile it to baseline code for better performance.

    ```javascript
    function countTo(n) {
      let count = 0;
      for (let i = 0; i < n; i++) {
        count++;
      }
      return count;
    }

    // Initially executed by the interpreter.
    countTo(5);
    // After multiple calls, V8 might compile it to baseline code.
    countTo(1000);
    ```

*   **On-Stack Replacement (OSR)**:  This allows V8 to transition from executing an interpreted function to a compiled version (like baseline) while the function is already on the stack (e.g., in a long-running loop).

    ```javascript
    function longRunningLoop(n) {
      let sum = 0;
      for (let i = 0; i < n; i++) {
        sum += i;
      }
      return sum;
    }

    // Initially executed by the interpreter. During the loop, V8 might perform OSR
    // to baseline or further optimized code.
    longRunningLoop(10000);
    ```

*   **Restarting Frames**: This can happen in scenarios involving generators or async functions where execution is paused and then resumed.

    ```javascript
    function* myGenerator() {
      yield 1;
      yield 2;
    }

    const gen = myGenerator();
    console.log(gen.next()); // { value: 1, done: false }
    // The frame is potentially "restarted" when the next value is requested.
    console.log(gen.next()); // { value: 2, done: false }
    ```

### 代码逻辑推理示例:

Let's focus on a simplified view of the `Generate_DeoptimizationEntry` function.

**Hypothetical Input (Deoptimization):**

*   Optimized function `foo` is currently executing.
*   A deoptimization condition is met (e.g., type mismatch).
*   The current state includes the values of CPU registers and the stack frame.
*   `deopt_kind` is set to `kEager`.

**Expected Output:**

1. The current register values are saved onto the stack.
2. A `Deoptimizer` object is created, containing information about the deoptimization.
3. The stack is unwound to the point before the optimized call.
4. A new, unoptimized frame is constructed on the stack.
5. Execution resumes in the unoptimized version of `foo` (or the interpreter).

**Simplified Logic Flow:**

1. Save registers.
2. Create `Deoptimizer`.
3. Copy frame data to `Deoptimizer`.
4. Unwind stack.
5. Compute output frame.
6. Replace current frame with the output frame.
7. Restore registers.
8. Jump to the continuation point.

### 用户常见的编程错误:

The deoptimization mechanisms often come into play due to programming practices that make code harder to optimize or that violate assumptions made by the optimizing compiler. Examples include:

1. **Type instability:**  Consistently using variables with the same data type allows for better optimization. Changing the type of a variable frequently can lead to deoptimization.

    ```javascript
    function process(input) {
      let result = 0;
      if (typeof input === 'number') {
        result = input * 2;
      } else if (typeof input === 'string') {
        result = input.length;
      }
      return result;
    }

    process(5);   // Optimized for number
    process("abc"); // Might trigger deoptimization as the type changed
    ```

2. **Hidden classes/property changes:** V8 optimizes object property access based on the object's "shape" (hidden class). Dynamically adding or deleting properties can change the hidden class and lead to deoptimization.

    ```javascript
    function Point(x, y) {
      this.x = x;
      this.y = y;
    }

    const p1 = new Point(1, 2); // V8 optimizes based on the initial shape
    const p2 = new Point(3, 4);
    p2.z = 5; // Adding a property changes the shape of p2
    ```

3. **Using `arguments` object:** The `arguments` object inhibits certain optimizations. Rest parameters are generally preferred.

    ```javascript
    function sumArguments() {
      let sum = 0;
      for (let i = 0; i < arguments.length; i++) {
        sum += arguments[i];
      }
      return sum;
    }
    ```

### 功能归纳:

This part of `builtins-arm64.cc` provides the low-level assembly code for handling two crucial aspects of V8's execution on ARM64 architecture: **deoptimization** and transitioning between **interpreter and baseline code**. It ensures that the JavaScript engine can gracefully revert from optimized code when necessary and efficiently switch to more optimized versions as code becomes "hot". The code manages the stack frame manipulation, register saving/restoring, and calling into the C++ runtime to handle these transitions. This is essential for the dynamic nature of JavaScript and V8's optimization strategy.

This is part 7 of 7, implying this is likely the final segment covering a specific area of V8 builtins for ARM64. This specific part focuses on the runtime mechanics of adapting to changing execution conditions and moving between different levels of code optimization.

Prompt: 
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm64/builtins-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共7部分，请归纳一下它的功能

"""
aved on the stack above core registers.
  const int kSimd128RegistersOffset = saved_registers.Count() * kXRegSize;

  Register code_object = x2;
  Register fp_to_sp = x3;
  // Get the address of the location in the code object. This is the return
  // address for lazy deoptimization.
  __ Mov(code_object, lr);
  // Compute the fp-to-sp delta.
  __ Add(fp_to_sp, sp, kSavedRegistersAreaSize);
  __ Sub(fp_to_sp, fp, fp_to_sp);

  // Allocate a new deoptimizer object.
  __ Ldr(x1, MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));

  // Ensure we can safely load from below fp.
  DCHECK_GT(kSavedRegistersAreaSize, -StandardFrameConstants::kFunctionOffset);
  __ Ldr(x0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // If x1 is a smi, zero x0.
  __ Tst(x1, kSmiTagMask);
  __ CzeroX(x0, eq);

  __ Mov(x1, static_cast<int>(deopt_kind));
  // Following arguments are already loaded:
  //  - x2: code object address
  //  - x3: fp-to-sp delta
  __ Mov(x4, ExternalReference::isolate_address());

  {
    // Call Deoptimizer::New().
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register x0.
  Register deoptimizer = x0;

  // Get the input frame descriptor pointer.
  __ Ldr(x1, MemOperand(deoptimizer, Deoptimizer::input_offset()));

  // Copy core registers into the input frame.
  CopyRegListToFrame(masm, x1, FrameDescription::registers_offset(),
                     saved_registers, x2, x3);

  // Copy simd128 / double registers to the input frame.
  CopyRegListToFrame(masm, x1, FrameDescription::simd128_registers_offset(),
                     saved_simd128_registers, q2, q3, kSimd128RegistersOffset);

  // Mark the stack as not iterable for the CPU profiler which won't be able to
  // walk the stack without the return address.
  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.AcquireX();
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ strb(xzr, MemOperand(is_iterable));
  }

  // Remove the saved registers from the stack.
  DCHECK_EQ(kSavedRegistersAreaSize % kXRegSize, 0);
  __ Drop(kSavedRegistersAreaSize / kXRegSize);

  // Compute a pointer to the unwinding limit in register x2; that is
  // the first stack slot not part of the input frame.
  Register unwind_limit = x2;
  __ Ldr(unwind_limit, MemOperand(x1, FrameDescription::frame_size_offset()));

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ Add(x3, x1, FrameDescription::frame_content_offset());
  __ SlotAddress(x1, 0);
  __ Lsr(unwind_limit, unwind_limit, kSystemPointerSizeLog2);
  __ Mov(x5, unwind_limit);
  __ CopyDoubleWords(x3, x1, x5);
  // Since {unwind_limit} is the frame size up to the parameter count, we might
  // end up with an unaligned stack pointer. This is later recovered when
  // setting the stack pointer to {caller_frame_top_offset}.
  __ Bic(unwind_limit, unwind_limit, 1);
  __ Drop(unwind_limit);

  // Compute the output frame in the deoptimizer.
  __ Push(padreg, x0);  // Preserve deoptimizer object across call.
  {
    // Call Deoptimizer::ComputeOutputFrames().
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ Pop(x4, padreg);  // Restore deoptimizer object (class Deoptimizer).

  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Ldr(scratch, MemOperand(x4, Deoptimizer::caller_frame_top_offset()));
    __ Mov(sp, scratch);
  }

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, outer_loop_header;
  __ Ldrsw(x1, MemOperand(x4, Deoptimizer::output_count_offset()));
  __ Ldr(x0, MemOperand(x4, Deoptimizer::output_offset()));
  __ Add(x1, x0, Operand(x1, LSL, kSystemPointerSizeLog2));
  __ B(&outer_loop_header);

  __ Bind(&outer_push_loop);
  Register current_frame = x2;
  Register frame_size = x3;
  __ Ldr(current_frame, MemOperand(x0, kSystemPointerSize, PostIndex));
  __ Ldr(x3, MemOperand(current_frame, FrameDescription::frame_size_offset()));
  __ Lsr(frame_size, x3, kSystemPointerSizeLog2);
  __ Claim(frame_size, kXRegSize, /*assume_sp_aligned=*/false);

  __ Add(x7, current_frame, FrameDescription::frame_content_offset());
  __ SlotAddress(x6, 0);
  __ CopyDoubleWords(x6, x7, frame_size);

  __ Bind(&outer_loop_header);
  __ Cmp(x0, x1);
  __ B(lt, &outer_push_loop);

  RestoreRegList(masm, saved_simd128_registers, current_frame,
                 FrameDescription::simd128_registers_offset());

  {
    UseScratchRegisterScope temps(masm);
    Register is_iterable = temps.AcquireX();
    Register one = x4;
    __ LoadIsolateField(is_iterable, IsolateFieldId::kStackIsIterable);
    __ Mov(one, Operand(1));
    __ strb(one, MemOperand(is_iterable));
  }

  // TODO(all): ARM copies a lot (if not all) of the last output frame onto the
  // stack, then pops it all into registers. Here, we try to load it directly
  // into the relevant registers. Is this correct? If so, we should improve the
  // ARM code.

  // Restore registers from the last output frame.
  // Note that lr is not in the list of saved_registers and will be restored
  // later. We can use it to hold the address of last output frame while
  // reloading the other registers.
  DCHECK(!saved_registers.IncludesAliasOf(lr));
  Register last_output_frame = lr;
  __ Mov(last_output_frame, current_frame);

  RestoreRegList(masm, saved_registers, last_output_frame,
                 FrameDescription::registers_offset());

  UseScratchRegisterScope temps(masm);
  temps.Exclude(x17);
  Register continuation = x17;
  __ Ldr(continuation, MemOperand(last_output_frame,
                                  FrameDescription::continuation_offset()));
  __ Ldr(lr, MemOperand(last_output_frame, FrameDescription::pc_offset()));
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  __ Autibsp();
#endif
  // If the continuation is non-zero (JavaScript), branch to the continuation.
  // For Wasm just return to the pc from the last output frame in the lr
  // register.
  Label end;
  __ CompareAndBranch(continuation, 0, eq, &end);
  __ Br(continuation);
  __ Bind(&end);
  __ Ret();
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
  Register closure = x1;
  __ Ldr(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = x22;
  __ LoadTaggedField(
      code_obj,
      FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj);
  }

  __ LoadTrustedPointerField(
      code_obj,
      FieldMemOperand(code_obj, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ IsObjectType(code_obj, x3, x3, CODE_TYPE);
    __ B(eq, &start_with_baseline);

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ IsObjectType(code_obj, x3, x3, CODE_TYPE);
    __ Assert(eq, AbortReason::kExpectedBaselineData);
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, x3);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = x2;
  Register feedback_vector = x15;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ IsObjectType(feedback_vector, x3, x3, FEEDBACK_VECTOR_TYPE);
  __ B(ne, &install_baseline_code);

  // Save BytecodeOffset from the stack frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ Str(feedback_cell,
         MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ Str(feedback_vector,
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
  Register get_baseline_pc = x3;
  __ Mov(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ cmp(kInterpreterBytecodeOffsetRegister,
           Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                   kFunctionEntryBytecodeOffset));
    __ B(eq, &function_entry_bytecode);
  }

  __ Sub(kInterpreterBytecodeOffsetRegister, kInterpreterBytecodeOffsetRegister,
         (BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
  __ Push(padreg, kInterpreterAccumulatorRegister);
  {
    __ Mov(kCArgRegs[0], code_obj);
    __ Mov(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ Mov(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ LoadCodeInstructionStart(code_obj, code_obj, kJSEntrypointTag);
  __ Add(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister, padreg);

  if (is_osr) {
    Generate_OSREntry(masm, code_obj);
  } else {
    __ Jump(code_obj);
  }
  __ Trap();  // Unreachable.

  if (!is_osr) {
    __ bind(&function_entry_bytecode);
    // If the bytecode offset is kFunctionEntryOffset, get the start address of
    // the first bytecode.
    __ Mov(kInterpreterBytecodeOffsetRegister, Operand(0));
    if (next_bytecode) {
      __ Mov(get_baseline_pc,
             ExternalReference::baseline_pc_for_bytecode_offset());
    }
    __ B(&valid_bytecode_offset);
  }

  __ bind(&install_baseline_code);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(padreg, kInterpreterAccumulatorRegister);
    __ PushArgument(closure);
    __ CallRuntime(Runtime::kInstallBaselineCode, 1);
    __ Pop(kInterpreterAccumulatorRegister, padreg);
  }
  // Retry from the start after installing baseline code.
  __ B(&start);
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

  __ Ldr(x1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ ldr(x0, MemOperand(fp, StandardFrameConstants::kArgCOffset));

  __ LeaveFrame(StackFrame::INTERPRETED);

  // The arguments are already in the stack (including any necessary padding),
  // we should not try to massage the arguments again.
#ifdef V8_ENABLE_LEAPTIERING
  __ InvokeFunction(x1, x0, InvokeType::kJump,
                    ArgumentAdaptionMode::kDontAdapt);
#else
  __ Mov(x2, kDontAdaptArgumentsSentinel);
  __ InvokeFunction(x1, x2, x0, InvokeType::kJump);
#endif
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_ARM

"""


```
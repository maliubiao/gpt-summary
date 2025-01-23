Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `macro-assembler-mips64.cc` file. I need to go through each function and explain its purpose within the context of code generation for the MIPS64 architecture in V8. I also need to address the specific points in the prompt about `.tq` files, JavaScript relevance with examples, logical reasoning with input/output, common programming errors, and finally, summarize the overall functionality of this part of the file.

Here's a breakdown of the functions and their roles:

1. **`void MacroAssembler::InvokeRuntime(Runtime::FunctionId fid)`**: This function seems to prepare arguments for and call a V8 runtime function identified by `fid`.
2. **`void MacroAssembler::JumpToExternalReference(...)`**:  This function looks like it sets up a call to an external function or builtin within V8.
3. **`void MacroAssembler::LoadWeakValue(...)`**: This appears to handle loading values from weak references, checking if the reference is still valid.
4. **`void MacroAssembler::EmitIncrementCounter(...)`** and **`void MacroAssembler::EmitDecrementCounter(...)`**: These functions are for incrementing and decrementing performance counters.
5. **Debugging Functions (`Trap`, `DebugBreak`, `Check`, `Abort`)**: These are utilities for debugging and handling errors during code execution.
6. **`void MacroAssembler::LoadMap(...)`**: This function loads the map (metadata) of a HeapObject.
7. **`void MacroAssembler::LoadFeedbackVector(...)`**: This function retrieves the feedback vector associated with a JSFunction.
8. **`void MacroAssembler::LoadNativeContextSlot(...)`**: This function accesses slots within the native context.
9. **Stack Frame Management Functions (`StubPrologue`, `Prologue`, `EnterFrame`, `LeaveFrame`, `EnterExitFrame`, `LeaveExitFrame`)**: These functions handle the setup and teardown of different types of stack frames.
10. **`int MacroAssembler::ActivationFrameAlignment()`**: This function determines the required alignment for stack frames.
11. **Smi Handling Functions (`SmiUntag`, `JumpIfSmi`, `JumpIfNotSmi`)**: These functions deal with tagged small integers (Smis).
12. **Assertion Functions (`Assert`, `AssertJSAny`, `AssertNotSmi`, `AssertSmi`, `AssertStackIsAligned`, `AssertConstructor`, `AssertFunction`, `AssertCallableFunction`, `AssertBoundFunction`, `AssertGeneratorObject`, `AssertUndefinedOrAllocationSite`)**: These are for runtime checks and debugging.
13. **Floating-Point Max/Min Functions (`Float32Max`, `Float32MaxOutOfLine`, `Float32Min`, `Float32MinOutOfLine`, `Float64Max`, `Float64MaxOutOfLine`, `Float64Min`, `Float64MinOutOfLine`)**: These functions implement the maximum and minimum operations for single and double-precision floating-point numbers.
14. **`int MacroAssembler::CalculateStackPassedWords(...)`**: This calculates the number of words passed on the stack for C function calls.
15. **C Function Call Preparation and Execution Functions (`PrepareCallCFunction`, `CallCFunction`, `CallCFunctionHelper`)**: These functions handle setting up and calling C functions.
16. **`void MacroAssembler::CheckPageFlag(...)`**: This function checks flags associated with memory pages.
17. **`Register GetRegisterThatIsNotOneOf(...)`**: This utility function finds an available register that is not in a given list.
18. **`void MacroAssembler::ComputeCodeStartAddress(...)`**: This function calculates the start address of the generated code.
19. **Deoptimization Related Function (`CallForDeoptimization`)**: This function handles calls when deoptimization is needed.
20. **Code Object Related Functions (`LoadCodeInstructionStart`, `CallCodeObject`, `JumpCodeObject`)**: These functions deal with loading and executing code objects.
21. **`void MacroAssembler::CallJSFunction(...)`**: This function appears to handle calling JavaScript functions.

Now, I'll formulate the response by grouping these functionalities and addressing all the requirements from the prompt.
The provided code snippet is a portion of `v8/src/codegen/mips64/macro-assembler-mips64.cc`, which is a core component of the V8 JavaScript engine. This file defines the `MacroAssembler` class for the MIPS64 architecture. The `MacroAssembler` provides a high-level interface for generating machine code instructions. It offers a set of methods that correspond to common assembly language instructions and higher-level operations needed by the V8 engine.

Here's a breakdown of the functionalities in this specific snippet:

**Core Functionalities:**

1. **Runtime Function Invocation:** The `InvokeRuntime` function facilitates calling V8's built-in runtime functions. It prepares the arguments and jumps to the appropriate entry point.
2. **External Reference Calls:** The `JumpToExternalReference` function enables calling external C++ functions or built-ins by jumping to their memory addresses. It handles setting up the necessary C entry frame.
3. **Weak Value Handling:** `LoadWeakValue` deals with loading values from weak references. It checks if the referenced object is still alive and branches accordingly.
4. **Performance Counters:** `EmitIncrementCounter` and `EmitDecrementCounter` provide a mechanism to increment and decrement internal performance counters, used for profiling and statistics gathering.
5. **Debugging and Error Handling:** Functions like `Trap`, `DebugBreak`, `Check`, and `Abort` are crucial for debugging the generated code and handling unexpected conditions or errors. `Check` conditionally triggers an `Abort` if a specified condition is not met. `Abort` halts execution and reports an error reason.
6. **Object Property Access:** `LoadMap` is used to retrieve the "map" of a JavaScript object, which contains metadata about its structure and type.
7. **Feedback Vector Management:** `LoadFeedbackVector` loads the feedback vector associated with a JavaScript function. Feedback vectors are used for optimizing subsequent calls to the function.
8. **Native Context Access:** `LoadNativeContextSlot` allows accessing specific slots within the native context, which holds global objects and information.
9. **Stack Frame Management:** The functions `StubPrologue`, `Prologue`, `EnterFrame`, `LeaveFrame`, `EnterExitFrame`, and `LeaveExitFrame` are responsible for setting up and tearing down different types of stack frames. Stack frames are used to manage function calls and local variables. `EnterExitFrame` and `LeaveExitFrame` are specifically used when transitioning between JavaScript and C++ code.
10. **Stack Alignment:** `ActivationFrameAlignment` determines the required alignment for stack frames on the MIPS64 architecture.
11. **Smi (Small Integer) Handling:** `SmiUntag`, `JumpIfSmi`, and `JumpIfNotSmi` provide optimized ways to work with small integers, which are a common data type in JavaScript. `SmiUntag` converts a Smi to its integer representation. `JumpIfSmi` and `JumpIfNotSmi` conditionally branch based on whether a value is a Smi.
12. **Assertions (Debug Checks):** The `Assert...` family of functions are used extensively in debug builds to verify assumptions about the state of the program. They help catch programming errors early.
13. **Floating-Point Max/Min Operations:** `Float32Max`, `Float32Min`, `Float64Max`, and `Float64Min` implement the maximum and minimum operations for single and double-precision floating-point numbers, handling NaN cases. The "OutOfLine" versions are likely fallbacks for edge cases or when the direct instruction isn't available or efficient.
14. **C Function Call Preparation:** `PrepareCallCFunction` sets up the stack and registers before calling a C function, ensuring proper argument passing according to the ABI.
15. **C Function Call Execution:** `CallCFunction` and `CallCFunctionHelper` perform the actual call to a C function, either by directly jumping to the function's address or through an external reference. They also handle stack adjustments after the call.
16. **Memory Page Flag Checks:** `CheckPageFlag` checks specific flags associated with memory pages, likely used for memory management or security purposes.
17. **Register Allocation Hint:** `GetRegisterThatIsNotOneOf` is a helper function to find a register that is not already in use, aiding in register allocation.
18. **Code Start Address Calculation:** `ComputeCodeStartAddress` calculates the starting address of the currently generated code.
19. **Deoptimization Support:** `CallForDeoptimization` is involved in the process of deoptimizing code, which happens when the runtime detects that previously optimized code is no longer performing optimally.
20. **Code Object Handling:** `LoadCodeInstructionStart`, `CallCodeObject`, and `JumpCodeObject` are used to load the starting address of executable code within a `Code` object and then either call or jump to that code.
21. **JavaScript Function Calls:** `CallJSFunction` handles the invocation of JavaScript functions.

**Is it a Torque file?**

The code snippet you provided is in `.cc` format, indicating it's a C++ source file, not a Torque (`.tq`) file. Torque is V8's domain-specific language for generating built-in functions, and its syntax is different from C++.

**Relationship to JavaScript and Examples:**

Many of these functions directly support the execution of JavaScript code. Here are some examples illustrating the connection:

*   **`InvokeRuntime(Runtime::kAdd)`**: When JavaScript code performs an addition, and the operands are not simple enough for inline addition, V8 might call the `Runtime::kAdd` runtime function using `InvokeRuntime`.
    ```javascript
    function add(a, b) {
      return a + b;
    }
    add(1e300, 1e300); // Might trigger a runtime call for large numbers
    ```
*   **`LoadMap(destination, object)`**:  When V8 needs to know the type and structure of a JavaScript object, it uses `LoadMap`.
    ```javascript
    const obj = { x: 1 };
    // Internally, V8 will load the 'map' of 'obj' to understand its properties.
    ```
*   **`AssertNotSmi(object)`**:  During development or in debug builds, V8 might use assertions to ensure a value expected to be a JavaScript object (and not a Smi) indeed is.
    ```javascript
    function processObject(obj) {
      // V8 might have an internal check that 'obj' is not a Smi here in debug mode.
      console.log(obj.x);
    }
    processObject({ x: 1 });
    ```
*   **`Float64Max(dst, src1, src2, out_of_line)`**: The `Math.max()` function in JavaScript can utilize the `Float64Max` instruction.
    ```javascript
    Math.max(3.14, 2.71);
    ```
*   **`CallJSFunction(function_object)`**: When a JavaScript function is called, the `CallJSFunction` function in the macro assembler is used to execute its code.
    ```javascript
    function greet(name) {
      console.log('Hello, ' + name);
    }
    greet('World'); // This triggers a CallJSFunction internally.
    ```

**Code Logic Inference with Assumptions:**

Let's consider the `LoadWeakValue` function:

```c++
void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  Branch(target_if_cleared, eq, in, Operand(kClearedWeakHeapObjectLower32));

  And(out, in, Operand(~kWeakHeapObjectMask));
}
```

*   **Assumption:** `in` register holds a weak reference to a HeapObject. `kClearedWeakHeapObjectLower32` is a constant representing the lower 32 bits of a cleared weak reference. `kWeakHeapObjectMask` is a mask used to clear the weak tag bits.
*   **Input:**  Let's say the `in` register contains the value `0xABCDE001`, and `kClearedWeakHeapObjectLower32` is `0x00000001`. The `target_if_cleared` label points to some error handling code.
*   **Logic:**
    1. The `Branch` instruction checks if the value in `in` is equal to `kClearedWeakHeapObjectLower32`. In this case, `0xABCDE001` is not equal to `0x00000001`.
    2. Since the branch condition is false, the execution continues to the `And` instruction.
    3. The `And` instruction performs a bitwise AND operation between the value in `in` (`0xABCDE001`) and the bitwise NOT of `kWeakHeapObjectMask`. Assuming `kWeakHeapObjectMask` is `0x00000001`, then `~kWeakHeapObjectMask` is `0xFFFFFFFE`.
    4. The result of `0xABCDE001 & 0xFFFFFFFE` is `0xABCDE000`.
    5. This result is stored in the `out` register.
*   **Output:** The `out` register will contain the unmasked value of the weak reference (assuming it wasn't cleared). If the weak reference was cleared (i.e., `in` was equal to `kClearedWeakHeapObjectLower32`), the code would have branched to `target_if_cleared`.

**Common Programming Errors:**

*   **Incorrect Stack Frame Management:**  Manually managing stack frames is error-prone. For example, forgetting to `LeaveFrame` after an `EnterFrame` can lead to stack corruption and crashes.
    ```c++
    void MyFunction(MacroAssembler* masm) {
      masm->EnterFrame(StackFrame::JAVA_SCRIPT);
      // ... some code ...
      // Error: Forgetting to call masm->LeaveFrame(StackFrame::JAVA_SCRIPT);
      masm->Ret();
    }
    ```
*   **Incorrect Argument Passing to C Functions:**  Providing the wrong number or type of arguments when calling a C function using `PrepareCallCFunction` and `CallCFunction` can lead to crashes or unexpected behavior. The MIPS ABI dictates how arguments are passed in registers and on the stack.
    ```c++
    // C function expects two integer arguments
    // int c_function(int a, int b);

    void CallCFuncIncorrectly(MacroAssembler* masm) {
      masm->PrepareCallCFunction(1, t0); // Incorrect: Preparing for 1 reg arg
      masm->li(a0, Operand(10));
      masm->li(a1, Operand(20));
      masm->CallCFunction(ExternalReference::ForCppFunction(c_function), 1); // Incorrect: Telling CallCFunction there's 1 arg
    }
    ```
*   **Register Allocation Conflicts:**  Using the same register for multiple purposes without saving and restoring its value can lead to data corruption. The `UseScratchRegisterScope` helps mitigate this, but manual register usage requires careful planning.

**Summary of Functionality (Part 6 of 7):**

This part of `macro-assembler-mips64.cc` focuses on providing a diverse set of low-level code generation primitives for the MIPS64 architecture within the V8 engine. It includes functionalities for:

*   **Interacting with the V8 runtime and external C++ code.**
*   **Handling weak references and performance monitoring.**
*   **Debugging and error handling during code execution.**
*   **Accessing object properties and metadata.**
*   **Managing stack frames for function calls.**
*   **Optimized handling of small integers.**
*   **Runtime assertions for verifying code correctness.**
*   **Implementing basic arithmetic operations for floating-point numbers.**
*   **Preparing for and executing calls to C functions.**
*   **Working with memory pages and code objects.**
*   **Supporting code deoptimization.**
*   **Calling JavaScript functions.**

Essentially, it lays down fundamental building blocks that higher-level parts of the V8 compiler utilize to generate efficient machine code for executing JavaScript.

### 提示词
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
t Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    PrepareCEntryArgs(function->nargs);
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  PrepareCEntryFunction(builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  Branch(target_if_cleared, eq, in, Operand(kClearedWeakHeapObjectLower32));

  And(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    li(scratch2, ExternalReference::Create(counter));
    Lw(scratch1, MemOperand(scratch2));
    Addu(scratch1, scratch1, Operand(value));
    Sw(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    li(scratch2, ExternalReference::Create(counter));
    Lw(scratch1, MemOperand(scratch2));
    Subu(scratch1, scratch1, Operand(value));
    Sw(scratch1, MemOperand(scratch2));
  }
}

// -----------------------------------------------------------------------------
// Debugging.

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::Check(Condition cc, AbortReason reason, Register rs,
                           Operand rt) {
  Label L;
  Branch(&L, cc, rs, rt);
  Abort(reason);
  // Will not return here.
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
    PrepareCallCFunction(1, a0);
    li(a0, Operand(static_cast<int>(reason)));
    li(a1, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(a1);
    return;
  }

  Move(a0, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      LoadEntryFromBuiltin(Builtin::kAbort, t9);
      Call(t9);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }
  // Will not return here.
  if (is_trampoline_pool_blocked()) {
    // If the calling code cares about the exact number of
    // instructions generated, we insert padding here to keep the size
    // of the Abort macro constant.
    // Currently in debug mode with debug_code enabled the number of
    // generated instructions is 10, so we use this as a maximum value.
    static const int kExpectedAbortInstructions = 10;
    int abort_instructions = InstructionsGeneratedSince(&abort_start);
    DCHECK_LE(abort_instructions, kExpectedAbortInstructions);
    while (abort_instructions++ < kExpectedAbortInstructions) {
      nop();
    }
  }
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  Ld(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;
  // Load the feedback vector from the closure.
  Ld(dst, FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  Ld(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  Ld(scratch, FieldMemOperand(dst, HeapObject::kMapOffset));
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Branch(&done, eq, scratch, Operand(FEEDBACK_VECTOR_TYPE));

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  Branch(fbv_undef);

  bind(&done);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  Ld(dst,
     FieldMemOperand(dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  Ld(dst, MemOperand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(StackFrame::TypeToMarker(type)));
  PushCommonFrame(scratch);
}

void MacroAssembler::Prologue() { PushStandardFrame(a1); }

void MacroAssembler::EnterFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Push(ra, fp);
  Move(fp, sp);
  if (!StackFrame::IsJavaScript(type)) {
    li(kScratchReg, Operand(StackFrame::TypeToMarker(type)));
    Push(kScratchReg);
  }
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM || type == StackFrame::WASM_LIFTOFF_SETUP) {
    Push(kWasmImplicitArgRegister);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
}

void MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  daddiu(sp, fp, 2 * kPointerSize);
  Ld(ra, MemOperand(fp, 1 * kPointerSize));
  Ld(fp, MemOperand(fp, 0 * kPointerSize));
}

void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  using ER = ExternalReference;

  // Set up the frame structure on the stack.
  static_assert(2 * kPointerSize == ExitFrameConstants::kCallerSPDisplacement);
  static_assert(1 * kPointerSize == ExitFrameConstants::kCallerPCOffset);
  static_assert(0 * kPointerSize == ExitFrameConstants::kCallerFPOffset);

  // This is how the stack will look:
  // fp + 2 (==kCallerSPDisplacement) - old stack's end
  // [fp + 1 (==kCallerPCOffset)] - saved old ra
  // [fp + 0 (==kCallerFPOffset)] - saved old fp
  // [fp - 1 frame_type Smi
  // [fp - 2 (==kSPOffset)] - sp of the called function
  // fp - (2 + stack_space + alignment) == sp == [fp - kSPOffset] - top of the
  //   new stack (will contain saved ra)

  // Save registers and reserve room for saved entry sp.
  daddiu(sp, sp, -2 * kPointerSize - ExitFrameConstants::kFixedFrameSizeFromFp);
  Sd(ra, MemOperand(sp, 3 * kPointerSize));
  Sd(fp, MemOperand(sp, 2 * kPointerSize));
  li(scratch, Operand(StackFrame::TypeToMarker(frame_type)));
  Sd(scratch, MemOperand(sp, 1 * kPointerSize));

  // Set up new frame pointer.
  daddiu(fp, sp, ExitFrameConstants::kFixedFrameSizeFromFp);

  if (v8_flags.debug_code) {
    Sd(zero_reg, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  Sd(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  Sd(cp, ExternalReferenceAsOperand(context_address, no_reg));

  const int frame_alignment = MacroAssembler::ActivationFrameAlignment();

  // Reserve place for the return address, stack space and align the frame
  // preparing for calling the runtime function.
  DCHECK_GE(stack_space, 0);
  Dsubu(sp, sp, Operand((stack_space + 1) * kPointerSize));
  if (frame_alignment > 0) {
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));  // Align stack.
  }

  // Set the exit frame sp value to point just before the return address
  // location.
  daddiu(scratch, sp, kPointerSize);
  Sd(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);

  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  Ld(cp, ExternalReferenceAsOperand(context_address, no_reg));

  if (v8_flags.debug_code) {
    li(scratch, Operand(Context::kInvalidContext));
    Sd(scratch, ExternalReferenceAsOperand(context_address, no_reg));
  }

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  Sd(zero_reg, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Pop the arguments, restore registers, and return.
  mov(sp, fp);  // Respect ABI stack constraint.
  Ld(fp, MemOperand(sp, ExitFrameConstants::kCallerFPOffset));
  Ld(ra, MemOperand(sp, ExitFrameConstants::kCallerPCOffset));

  daddiu(sp, sp, 2 * kPointerSize);
}

int MacroAssembler::ActivationFrameAlignment() {
#if V8_HOST_ARCH_MIPS || V8_HOST_ARCH_MIPS64
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one Mips
  // platform for another Mips platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else   // V8_HOST_ARCH_MIPS
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif  // V8_HOST_ARCH_MIPS
}

void MacroAssembler::SmiUntag(Register dst, const MemOperand& src) {
  if (SmiValuesAre32Bits()) {
    Lw(dst, MemOperand(src.rm(), SmiWordOffset(src.offset())));
  } else {
    DCHECK(SmiValuesAre31Bits());
    Lw(dst, src);
    SmiUntag(dst);
  }
}

void MacroAssembler::JumpIfSmi(Register value, Label* smi_label,
                               BranchDelaySlot bd) {
  DCHECK_EQ(0, kSmiTag);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  andi(scratch, value, kSmiTagMask);
  Branch(bd, smi_label, eq, scratch, Operand(zero_reg));
}

void MacroAssembler::JumpIfNotSmi(Register value, Label* not_smi_label,
                                  BranchDelaySlot bd) {
  DCHECK_EQ(0, kSmiTag);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  andi(scratch, value, kSmiTagMask);
  Branch(bd, not_smi_label, ne, scratch, Operand(zero_reg));
}

#ifdef V8_ENABLE_DEBUG_CODE

void MacroAssembler::Assert(Condition cc, AbortReason reason, Register rs,
                            Operand rt) {
  if (v8_flags.debug_code) Check(cc, reason, rs, rt);
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 Register tmp, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp, tmp));
  Label ok;

  JumpIfSmi(object, &ok);

  GetObjectType(object, map_tmp, tmp);

  Branch(&ok, kUnsignedLessThanEqual, tmp, Operand(LAST_NAME_TYPE));

  Branch(&ok, kUnsignedGreaterThanEqual, tmp, Operand(FIRST_JS_RECEIVER_TYPE));

  Branch(&ok, kEqual, map_tmp, RootIndex::kHeapNumberMap);

  Branch(&ok, kEqual, map_tmp, RootIndex::kBigIntMap);

  Branch(&ok, kEqual, object, RootIndex::kUndefinedValue);

  Branch(&ok, kEqual, object, RootIndex::kTrueValue);

  Branch(&ok, kEqual, object, RootIndex::kFalseValue);

  Branch(&ok, kEqual, object, RootIndex::kNullValue);

  Abort(abort_reason);
  bind(&ok);
}

void MacroAssembler::AssertNotSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    static_assert(kSmiTag == 0);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    andi(scratch, object, kSmiTagMask);
    Check(ne, AbortReason::kOperandIsASmi, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::AssertSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    static_assert(kSmiTag == 0);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    andi(scratch, object, kSmiTagMask);
    Check(eq, AbortReason::kOperandIsASmi, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::AssertStackIsAligned() {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    const int frame_alignment = ActivationFrameAlignment();
    const int frame_alignment_mask = frame_alignment - 1;

    if (frame_alignment > kPointerSize) {
      Label alignment_as_expected;
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        andi(scratch, sp, frame_alignment_mask);
        Branch(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort re-entering here.
      stop();
      bind(&alignment_as_expected);
    }
  }
}

void MacroAssembler::AssertConstructor(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor, t8,
          Operand(zero_reg));

    LoadMap(t8, object);
    Lbu(t8, FieldMemOperand(t8, Map::kBitFieldOffset));
    And(t8, t8, Operand(Map::Bits1::IsConstructorBit::kMask));
    Check(ne, AbortReason::kOperandIsNotAConstructor, t8, Operand(zero_reg));
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, t8,
          Operand(zero_reg));
    push(object);
    LoadMap(object, object);
    GetInstanceTypeRange(object, object, FIRST_JS_FUNCTION_TYPE, t8);
    Check(ls, AbortReason::kOperandIsNotAFunction, t8,
          Operand(LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));
    pop(object);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, t8,
          Operand(zero_reg));
    push(object);
    LoadMap(object, object);
    GetInstanceTypeRange(object, object, FIRST_CALLABLE_JS_FUNCTION_TYPE, t8);
    Check(ls, AbortReason::kOperandIsNotACallableFunction, t8,
          Operand(LAST_CALLABLE_JS_FUNCTION_TYPE -
                  FIRST_CALLABLE_JS_FUNCTION_TYPE));
    pop(object);
  }
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, t8,
          Operand(zero_reg));
    GetObjectType(object, t8, t8);
    Check(eq, AbortReason::kOperandIsNotABoundFunction, t8,
          Operand(JS_BOUND_FUNCTION_TYPE));
  }
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  static_assert(kSmiTag == 0);
  SmiTst(object, t8);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, t8,
        Operand(zero_reg));
  GetObjectType(object, t8, t8);
  Dsubu(t8, t8, Operand(FIRST_JS_GENERATOR_OBJECT_TYPE));
  Check(
      ls, AbortReason::kOperandIsNotAGeneratorObject, t8,
      Operand(LAST_JS_GENERATOR_OBJECT_TYPE - FIRST_JS_GENERATOR_OBJECT_TYPE));
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    Label done_checking;
    AssertNotSmi(object);
    LoadRoot(scratch, RootIndex::kUndefinedValue);
    Branch(&done_checking, eq, object, Operand(scratch));
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell, scratch,
           Operand(ALLOCATION_SITE_TYPE));
    bind(&done_checking);
  }
}

#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::Float32Max(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_s(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF32(src1, src2);
  BranchTrueF(out_of_line);

  if (kArchVariant >= kMips64r6) {
    max_s(dst, src1, src2);
  } else {
    Label return_left, return_right, done;

    CompareF32(OLT, src1, src2);
    BranchTrueShortF(&return_right);
    CompareF32(OLT, src2, src1);
    BranchTrueShortF(&return_left);

    // Operands are equal, but check for +/-0.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      mfc1(t8, src1);
      dsll32(t8, t8, 0);
      Branch(&return_left, eq, t8, Operand(zero_reg));
      Branch(&return_right);
    }

    bind(&return_right);
    if (src2 != dst) {
      Move_s(dst, src2);
    }
    Branch(&done);

    bind(&return_left);
    if (src1 != dst) {
      Move_s(dst, src1);
    }

    bind(&done);
  }
}

void MacroAssembler::Float32MaxOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  add_s(dst, src1, src2);
}

void MacroAssembler::Float32Min(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_s(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF32(src1, src2);
  BranchTrueF(out_of_line);

  if (kArchVariant >= kMips64r6) {
    min_s(dst, src1, src2);
  } else {
    Label return_left, return_right, done;

    CompareF32(OLT, src1, src2);
    BranchTrueShortF(&return_left);
    CompareF32(OLT, src2, src1);
    BranchTrueShortF(&return_right);

    // Left equals right => check for -0.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      mfc1(t8, src1);
      dsll32(t8, t8, 0);
      Branch(&return_right, eq, t8, Operand(zero_reg));
      Branch(&return_left);
    }

    bind(&return_right);
    if (src2 != dst) {
      Move_s(dst, src2);
    }
    Branch(&done);

    bind(&return_left);
    if (src1 != dst) {
      Move_s(dst, src1);
    }

    bind(&done);
  }
}

void MacroAssembler::Float32MinOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  add_s(dst, src1, src2);
}

void MacroAssembler::Float64Max(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_d(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF64(src1, src2);
  BranchTrueF(out_of_line);

  if (kArchVariant >= kMips64r6) {
    max_d(dst, src1, src2);
  } else {
    Label return_left, return_right, done;

    CompareF64(OLT, src1, src2);
    BranchTrueShortF(&return_right);
    CompareF64(OLT, src2, src1);
    BranchTrueShortF(&return_left);

    // Left equals right => check for -0.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      dmfc1(t8, src1);
      Branch(&return_left, eq, t8, Operand(zero_reg));
      Branch(&return_right);
    }

    bind(&return_right);
    if (src2 != dst) {
      Move_d(dst, src2);
    }
    Branch(&done);

    bind(&return_left);
    if (src1 != dst) {
      Move_d(dst, src1);
    }

    bind(&done);
  }
}

void MacroAssembler::Float64MaxOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  add_d(dst, src1, src2);
}

void MacroAssembler::Float64Min(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_d(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF64(src1, src2);
  BranchTrueF(out_of_line);

  if (kArchVariant >= kMips64r6) {
    min_d(dst, src1, src2);
  } else {
    Label return_left, return_right, done;

    CompareF64(OLT, src1, src2);
    BranchTrueShortF(&return_left);
    CompareF64(OLT, src2, src1);
    BranchTrueShortF(&return_right);

    // Left equals right => check for -0.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      dmfc1(t8, src1);
      Branch(&return_right, eq, t8, Operand(zero_reg));
      Branch(&return_left);
    }

    bind(&return_right);
    if (src2 != dst) {
      Move_d(dst, src2);
    }
    Branch(&done);

    bind(&return_left);
    if (src1 != dst) {
      Move_d(dst, src1);
    }

    bind(&done);
  }
}

void MacroAssembler::Float64MinOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  add_d(dst, src1, src2);
}

int MacroAssembler::CalculateStackPassedWords(int num_reg_arguments,
                                              int num_double_arguments) {
  int stack_passed_words = 0;
  int num_args = num_reg_arguments + num_double_arguments;

  // Up to eight arguments are passed in FPURegisters and GPRegisters.
  if (num_args > kRegisterPassedArguments) {
    stack_passed_words = num_args - kRegisterPassedArguments;
  }
  stack_passed_words += kCArgSlotCount;
  return stack_passed_words;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = ActivationFrameAlignment();

  // n64: Up to eight simple arguments in a0..a3, a4..a7, No argument slots.
  // O32: Up to four simple arguments are passed in registers a0..a3.
  // Those four arguments must have reserved argument slots on the stack for
  // mips, even though those argument slots are not normally used.
  // Both ABIs: Remaining arguments are pushed on the stack, above (higher
  // address than) the (O32) argument slots. (arg slot calculation handled by
  // CalculateStackPassedWords()).
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  if (frame_alignment > kPointerSize) {
    // Make stack end at alignment and make room for num_arguments - 4 words
    // and the original value of sp.
    mov(scratch, sp);
    Dsubu(sp, sp, Operand((stack_passed_arguments + 1) * kPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));
    Sd(scratch, MemOperand(sp, stack_passed_arguments * kPointerSize));
  } else {
    Dsubu(sp, sp, Operand(stack_passed_arguments * kPointerSize));
  }
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  li(t9, function);
  return CallCFunctionHelper(t9, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
  return CallCFunctionHelper(function, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunctionHelper(
    Register function, int num_reg_arguments, int num_double_arguments,
    SetIsolateDataSlots set_isolate_data_slots, Label* return_location) {
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());

  Label get_pc;

  // Make sure that the stack is aligned before calling a C function unless
  // running in the simulator. The simulator has its own alignment check which
  // provides more information.
  // The argument stots are presumed to have been set up by
  // PrepareCallCFunction. The C function must be called via t9, for mips ABI.

#if V8_HOST_ARCH_MIPS || V8_HOST_ARCH_MIPS64
  if (v8_flags.debug_code) {
    int frame_alignment = base::OS::ActivationFrameAlignment();
    int frame_alignment_mask = frame_alignment - 1;
    if (frame_alignment > kPointerSize) {
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      Label alignment_as_expected;
      {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        And(scratch, sp, Operand(frame_alignment_mask));
        Branch(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort possibly
      // re-entering here.
      stop();
      bind(&alignment_as_expected);
    }
  }
#endif  // V8_HOST_ARCH_MIPS

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      if (function != t9) {
        mov(t9, function);
        function = t9;
      }

      // Save the frame pointer and PC so that the stack layout remains
      // iterable, even without an ExitFrame which normally exists between JS
      // and C frames. 't' registers are caller-saved so this is safe as a
      // scratch register.
      Register pc_scratch = t1;
      DCHECK(!AreAliased(pc_scratch, function));
      CHECK(root_array_available());

      LoadAddressPCRelative(pc_scratch, &get_pc);

      Sd(pc_scratch,
         ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
      Sd(fp, ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }

    Call(function);
    int call_pc_offset = pc_offset();
    bind(&get_pc);

    if (return_location) bind(return_location);

    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      // We don't unset the PC; the FP is the source of truth.
      Sd(zero_reg,
         ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }

    int stack_passed_arguments =
        CalculateStackPassedWords(num_reg_arguments, num_double_arguments);

    if (base::OS::ActivationFrameAlignment() > kPointerSize) {
      Ld(sp, MemOperand(sp, stack_passed_arguments * kPointerSize));
    } else {
      Daddu(sp, sp, Operand(stack_passed_arguments * kPointerSize));
    }

    set_pc_for_safepoint();

    return call_pc_offset;
  }
}

#undef BRANCH_ARGS_CHECK

void MacroAssembler::CheckPageFlag(Register object, Register scratch, int mask,
                                   Condition cc, Label* condition_met) {
  ASM_CODE_COMMENT(this);
  And(scratch, object, Operand(~MemoryChunk::GetAlignmentMaskForAssembler()));
  Ld(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  And(scratch, scratch, Operand(mask));
  Branch(condition_met, cc, scratch, Operand(zero_reg));
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
  // This push on ra and the pop below together ensure that we restore the
  // register ra, which is needed while computing the code start address.
  push(ra);

  // The nal instruction puts the address of the current instruction into
  // the return address (ra) register, which we can use later on.
  if (kArchVariant == kMips64r6) {
    addiupc(ra, 1);
  } else {
    nal();
    nop();
  }
  int pc = pc_offset();
  li(dst, Operand(pc));
  Dsubu(dst, ra, dst);

  pop(ra);  // Restore ra
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ld(t9,
     MemOperand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(target)));
  Call(t9);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::LoadCodeInstructionStart(
    Register destination, Register code_data_container_object,
    CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  Ld(destination, FieldMemOperand(code_data_container_object,
                                  Code::kInstructionStartOffset));
}

void MacroAssembler::CallCodeObject(Register code_data_container_object,
                                    CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_data_container_object,
                           code_data_container_object, tag);
  Call(code_data_container_object);
}

void MacroAssembler::JumpCodeObject(Register code_data_container_object,
                                    CodeEntrypointTag tag, JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_data_container_object,
                           code_data_container_object, tag);
  Jump(code_data_container_object);
}

void MacroAssembler::CallJSFunction(Register function_object) {
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  LoadCodeEntrypointFromJSDispatchTable(
      code,
      FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  Call(code);
#else
  Ld(code, FieldMemOperand(func
```
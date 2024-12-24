Response: The user wants me to summarize the functionality of a C++ source code file for the V8 JavaScript engine, specifically the `builtins-riscv.cc` file. This is the third of three parts.

I need to identify the main functions and their purpose. Since this is the third part, it's likely to contain code related to deoptimization, baseline/interpreter transitions, API callbacks, and possibly other architecture-specific built-in functions for the RISC-V architecture.

If there's a connection to JavaScript functionality, I need to illustrate it with a JavaScript example. This will likely involve concepts like function calls, error handling, and performance optimizations.

Here's a plan:
1. Go through the provided code snippets function by function.
2. Summarize the core functionality of each function.
3. Identify functions that directly relate to JavaScript execution or optimization.
4. For those related functions, create a simple JavaScript example that demonstrates the underlying mechanism.
This C++ code file, `builtins-riscv.cc`, part 3 of 3, for the V8 JavaScript engine on the RISC-V architecture, primarily focuses on the following functionalities:

**1. Handling Transitions between JavaScript and WebAssembly (Wasm):**

*   **`Generate_JSToWasmWrapperAsm`**:  Generates code for a wrapper function that facilitates calling WebAssembly functions from JavaScript. It sets up the necessary stack frame, copies arguments, and calls the WebAssembly function.
*   **`Generate_WasmReturnPromiseOnSuspendAsm`**:  Similar to the above, but specifically for WebAssembly functions that return a Promise. It handles the stack switching required for asynchronous operations in Wasm.
*   **`Generate_JSToWasmStressSwitchStacksAsm`**:  A variant for stress testing stack switching during JavaScript to WebAssembly calls.

**2. Implementing API Callbacks:**

*   **`Generate_CallApiCallbackImpl`**: Generates code to handle calls to native JavaScript functions exposed through the V8 C++ API. This involves setting up the `FunctionCallbackInfo` object with arguments, the receiver, and other necessary information before calling the native function.
*   **`Generate_CallApiGetter`**:  Generates code for calling native getter functions defined through the V8 API. It sets up the `PropertyCallbackInfo` object and calls the native getter.

**3. Supporting Deoptimization:**

*   **`Generate_DeoptimizationEntry_Eager` and `Generate_DeoptimizationEntry_Lazy`**: These functions generate code that serves as the entry point when code needs to be deoptimized (reverted to a less optimized state, like the interpreter). This happens when assumptions made by the optimizing compiler are invalidated. The code saves the necessary registers and state, creates a deoptimizer object, and then reconstructs the frame.

**4. Managing Transitions between Baseline and Interpreter Code:**

*   **`Generate_BaselineOrInterpreterEnterAtBytecode` and `Generate_BaselineOrInterpreterEnterAtNextBytecode`**: These functions handle entering either the baseline compiler's output or the interpreter. They check if baseline code is available for a function and, if so, transition to it. Otherwise, they enter the interpreter.
*   **`Generate_InterpreterOnStackReplacement_ToBaseline`**: This function handles the on-stack replacement (OSR) from interpreter code to baseline code while the function is already executing.

**5. Restarting Frames:**

*   **`Generate_RestartFrameTrampoline`**:  Generates code for a trampoline that is used when a function's frame needs to be restarted. This typically occurs after a deoptimization.

**6. Direct C Function Calls:**

*   **`Generate_DirectCEntry`**: Provides a mechanism for JavaScript code to directly call C++ functions in a way that is safe even if a garbage collection occurs during the call.

**Relationship to JavaScript and Examples:**

Many of these built-ins are crucial for the interaction between JavaScript and lower-level engine components. Here are a few examples illustrating their connection to JavaScript:

**a) JavaScript to WebAssembly Calls (`Generate_JSToWasmWrapperAsm`):**

```javascript
// Assume you have a WebAssembly module loaded and an instance created
const wasmInstance = // ... your WebAssembly instance
const addFunction = wasmInstance.exports.add;

const result = addFunction(5, 10);
console.log(result); // Output: 15 (if the Wasm function adds two numbers)
```

When you call `addFunction` in JavaScript, V8 uses the generated wrapper code (from `Generate_JSToWasmWrapperAsm`) to:

1. Set up the correct calling convention for the RISC-V architecture.
2. Convert JavaScript arguments (5 and 10) to the appropriate Wasm types.
3. Call the actual WebAssembly `add` function.
4. Convert the Wasm return value back to a JavaScript value.

**b) API Callbacks (`Generate_CallApiCallbackImpl`):**

```javascript
function greet(name) {
  console.log("Hello, " + name + "!");
}

// In a C++ V8 embedding:
v8::Local<v8::FunctionTemplate> tpl = v8::FunctionTemplate::New(isolate, greet);
// ... (setting up the object template and properties)
```

When JavaScript code calls a function created using a `FunctionTemplate` (like the `greet` function above), V8 uses the code generated by `Generate_CallApiCallbackImpl` to:

1. Create a `FunctionCallbackInfo` object containing details about the call (arguments, receiver, etc.).
2. Call the native C++ function (`greet` in this case).

**c) Deoptimization (`Generate_DeoptimizationEntry_Eager`):**

```javascript
function potentiallyUnstableFunction(x) {
  // Initially, V8 might optimize this assuming 'x' is always a number
  return x + 1;
}

potentiallyUnstableFunction(5); // V8 might optimize based on this call

potentiallyUnstableFunction("hello"); // If 'x' becomes a string, the optimization is invalid
```

If `potentiallyUnstableFunction` is initially optimized assuming `x` is always a number, but then it's called with a string, V8 will trigger a deoptimization. The `Generate_DeoptimizationEntry_Eager` code will be executed to:

1. Safely unwind the optimized stack frame.
2. Revert the function to its unoptimized state (likely running in the interpreter).
3. Restart execution from the point where the deoptimization occurred.

**d) Baseline/Interpreter Transitions (`Generate_BaselineOrInterpreterEnterAtBytecode`):**

```javascript
function frequentlyCalledFunction() {
  let sum = 0;
  for (let i = 0; i < 1000; i++) {
    sum += i;
  }
  return sum;
}

// After being called a few times, V8 might compile this function to baseline code
let result = frequentlyCalledFunction();
```

Initially, `frequentlyCalledFunction` might run in the interpreter. After V8 detects it's called frequently, it might compile it to baseline code (a less optimized compiled version). The `Generate_BaselineOrInterpreterEnterAtBytecode` built-in is involved in the transition from the interpreter to the baseline code when the function is called.

In summary, this part of the `builtins-riscv.cc` file is crucial for managing various transitions and interactions within the V8 engine on the RISC-V architecture, directly impacting how JavaScript code interacts with WebAssembly and native C++ code, and how the engine optimizes and handles errors during execution.

Prompt: 
```
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
gister jmpbuf, Register tmp) {
#ifdef V8_TARGET_ARCH_RISCV64
  if (masm->options().enable_simulator_code) {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(kSimulatorBreakArgument);
    __ LoadWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
    __ LoadWord(kSimulatorBreakArgument,
                MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset));
    __ mv(sp, tmp);
    __ break_(kExceptionIsSwitchStackLimit);
  } else {
    __ LoadWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
    __ mv(sp, tmp);
  }
#endif
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Label* pc,
                    Register tmp) {
  ASM_CODE_COMMENT(masm);
  __ mv(tmp, sp);
  __ StoreWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  __ StoreWord(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  __ LoadStackLimit(tmp, StackLimitKind::kRealStackLimit);
  __ StoreWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset));
  __ LoadAddress(tmp, pc);
  __ StoreWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    Register tmp, wasm::JumpBuffer::StackState expected_state) {
  ASM_CODE_COMMENT(masm);
  SwitchStackPointerAndSimulatorStackLimit(masm, jmpbuf, tmp);
  __ LoadWord(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  SwitchStackState(masm, jmpbuf, tmp, expected_state, wasm::JumpBuffer::Active);
  if (load_pc) {
    __ LoadWord(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
    __ Jump(tmp);
  }
  // The stack limit in StackGuard is set separately under the ExecutionAccess
  // lock.
}
// Updates the stack limit to match the new active stack.
// Pass the {finished_continuation} argument to indicate that the stack that we
// are switching from has returned, and in this case return its memory to the
// stack pool.
void SwitchStacks(MacroAssembler* masm, Register finished_continuation,
                  Register tmp) {
  ASM_CODE_COMMENT(masm);
  using ER = ExternalReference;
  if (finished_continuation != no_reg) {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ li(kCArgRegs[0], ExternalReference::isolate_address(masm->isolate()));
    __ mv(kCArgRegs[1], finished_continuation);
    __ PrepareCallCFunction(2, tmp);
    __ CallCFunction(ER::wasm_return_switch(), 2);
  } else {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ li(kCArgRegs[0], ER::isolate_address(masm->isolate()));
    __ PrepareCallCFunction(1, tmp);
    __ CallCFunction(ER::wasm_sync_stack_limit(), 1);
  }
}

void ReloadParentContinuation(MacroAssembler* masm, Register return_reg,
                              Register return_value, Register context,
                              Register tmp1, Register tmp2, Register tmp3) {
  ASM_CODE_COMMENT(masm);
  Register active_continuation = tmp1;
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);

  // Set a null pointer in the jump buffer's SP slot to indicate to the stack
  // frame iterator that this stack is empty.
  Register jmpbuf = tmp2;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  __ StoreWord(zero_reg, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    SwitchStackState(masm, jmpbuf, scratch, wasm::JumpBuffer::Active,
                     wasm::JumpBuffer::Retired);
  }
  Register parent = tmp2;
  __ LoadTaggedField(parent,
                     FieldMemOperand(active_continuation,
                                     WasmContinuationObject::kParentOffset));

  // Update active continuation root.
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ StoreWord(parent, MemOperand(kRootRegister, active_continuation_offset));
  jmpbuf = parent;
  __ LoadExternalPointerField(
      jmpbuf, FieldMemOperand(parent, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);

  // Switch stack!
  LoadJumpBuffer(masm, jmpbuf, false, tmp3, wasm::JumpBuffer::Inactive);

  __ Push(return_reg, return_value, context);
  SwitchStacks(masm, active_continuation, tmp3);
  __ Pop(return_reg, return_value, context);
}

void RestoreParentSuspender(MacroAssembler* masm, Register tmp1,
                            Register tmp2) {
  ASM_CODE_COMMENT(masm);
  Register suspender = tmp1;
  __ LoadRoot(suspender, RootIndex::kActiveSuspender);
  MemOperand state_loc =
      FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset);
  __ Move(tmp2, Smi::FromInt(WasmSuspenderObject::kInactive));
  __ StoreTaggedField(tmp2, state_loc);
  __ LoadTaggedField(
      suspender,
      FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  Label undefined;
  __ CompareRootAndBranch(suspender, RootIndex::kUndefinedValue, eq,
                          &undefined);
  if (v8_flags.debug_code) {
    // Check that the parent suspender is active.
    Label parent_inactive;
    Register state = tmp2;
    __ SmiUntag(state, state_loc);
    __ Branch(&parent_inactive, eq, state,
              Operand(WasmSuspenderObject::kActive));
    __ Trap();
    __ bind(&parent_inactive);
  }
  __ Move(tmp2, Smi::FromInt(WasmSuspenderObject::kActive));
  __ StoreTaggedField(tmp2, state_loc);
  __ bind(&undefined);
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ StoreWord(suspender, MemOperand(kRootRegister, active_suspender_offset));
}

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  ASM_CODE_COMMENT(masm);
  __ StoreWord(zero_reg,
               MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
  __ StoreWord(zero_reg,
               MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
}

void LoadTargetJumpBuffer(MacroAssembler* masm, Register target_continuation,
                          Register tmp,
                          wasm::JumpBuffer::StackState expected_state) {
  ASM_CODE_COMMENT(masm);
  Register target_jmpbuf = target_continuation;
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldMemOperand(target_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  __ StoreWord(
      zero_reg,
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  // Switch stack!
  LoadJumpBuffer(masm, target_jmpbuf, false, tmp, expected_state);
}
}  // namespace

void Builtins::Generate_WasmSuspend(MacroAssembler* masm) {
  // Set up the stackframe.
  __ EnterFrame(StackFrame::STACK_SWITCH);

  Register suspender = a0;  //  DEFINE_PINNED(suspender, x0);
  // Register context = kContextRegister; //  DEFINE_PINNED(context,
  // kContextRegister);

  __ SubWord(
      sp, sp,
      Operand(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize));
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  // -------------------------------------------
  // Save current state in active jump buffer.
  // -------------------------------------------
  Label resume;
  Register continuation = kScratchReg;  //  DEFINE_REG(continuation);
  __ LoadRoot(continuation, RootIndex::kActiveContinuation);
  Register jmpbuf = kScratchReg2;  //  DEFINE_REG(jmpbuf);
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(continuation, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  FillJumpBuffer(masm, jmpbuf, &resume, scratch);
  SwitchStackState(masm, jmpbuf, scratch, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Suspended);
  __ Move(scratch, Smi::FromInt(WasmSuspenderObject::kSuspended));
  __ StoreTaggedField(
      scratch, FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  temps.Include(scratch);
  scratch = no_reg;

  Register suspender_continuation = temps.Acquire();
  __ LoadTaggedField(
      suspender_continuation,
      FieldMemOperand(suspender, WasmSuspenderObject::kContinuationOffset));
  if (v8_flags.debug_code) {
    // -------------------------------------------
    // Check that the suspender's continuation is the active continuation.
    // -------------------------------------------
    // TODO(thibaudm): Once we add core stack-switching instructions, this
    // check will not hold anymore: it's possible that the active continuation
    // changed (due to an internal switch), so we have to update the suspender.
    Label ok;
    __ Branch(&ok, eq, suspender_continuation, Operand(continuation));
    __ Trap();
    __ bind(&ok);
  }
  continuation = no_reg;
  // -------------------------------------------
  // Update roots.
  // -------------------------------------------
  Register caller = kScratchReg;  //   DEFINE_REG(caller);
  __ LoadTaggedField(caller,
                     FieldMemOperand(suspender_continuation,
                                     WasmContinuationObject::kParentOffset));
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ StoreWord(caller, MemOperand(kRootRegister, active_continuation_offset));

  temps.Include(suspender_continuation);
  suspender_continuation = no_reg;

  Register parent = temps.Acquire();
  __ LoadTaggedField(
      parent, FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ StoreWord(parent, MemOperand(kRootRegister, active_suspender_offset));
  temps.Include(parent);
  parent = no_reg;
  // -------------------------------------------
  // Load jump buffer.
  // -------------------------------------------
  __ Push(caller, suspender);
  SwitchStacks(masm, no_reg, caller);
  __ Pop(caller, suspender);
  __ LoadExternalPointerField(
      jmpbuf, FieldMemOperand(caller, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  __ LoadTaggedField(
      kReturnRegister0,
      FieldMemOperand(suspender, WasmSuspenderObject::kPromiseOffset));
  MemOperand GCScanSlotPlace =
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ StoreWord(zero_reg, GCScanSlotPlace);
  scratch = temps.Acquire();

  LoadJumpBuffer(masm, jmpbuf, true, scratch, wasm::JumpBuffer::Inactive);
  __ Trap();
  __ bind(&resume);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  __ Ret();
}


namespace {
// Resume the suspender stored in the closure. We generate two variants of this
// builtin: the onFulfilled variant resumes execution at the saved PC and
// forwards the value, the onRejected variant throws the value.
#define FREE_REG(x) \
  temps.Include(x); \
  x = no_reg;

void Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume) {
  UseScratchRegisterScope temps(masm);
  temps.Include(t1, t2);
  __ EnterFrame(StackFrame::STACK_SWITCH);

  Register closure = kJSFunctionRegister;  //  DEFINE_PINNED(closure,
                                           //  kJSFunctionRegister);  // x1

  __ SubWord(
      sp, sp,
      Operand(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize));
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  // -------------------------------------------
  // Load suspender from closure.
  // -------------------------------------------
  Register sfi = temps.Acquire();
  __ LoadTaggedField(
      sfi,
      MemOperand(
          closure,
          wasm::ObjectAccess::SharedFunctionInfoOffsetInTaggedJSFunction()));
  closure = no_reg;
  // Suspender should be ObjectRegister register to be used in
  // RecordWriteField calls later.
  Register suspender = WriteBarrierDescriptor::ObjectRegister();
  Register resume_data = temps.Acquire();
  __ LoadTaggedField(
      resume_data,
      FieldMemOperand(sfi, SharedFunctionInfo::kUntrustedFunctionDataOffset));
  // The write barrier uses a fixed register for the host object (rdi). The next
  // barrier is on the suspender, so load it in rdi directly.
  __ LoadTaggedField(
      suspender,
      FieldMemOperand(resume_data, WasmResumeData::kSuspenderOffset));
  FREE_REG(resume_data);
  FREE_REG(sfi);
  // Check the suspender state.
  Label suspender_is_suspended;
  Register state = temps.Acquire();
  __ SmiUntag(state,
              FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ Branch(&suspender_is_suspended, eq, state,
            Operand(WasmSuspenderObject::kSuspended));
  __ Trap();

  __ bind(&suspender_is_suspended);
  FREE_REG(state);
  // -------------------------------------------
  // Save current state.
  // -------------------------------------------
  Label suspend;
  Register active_continuation = temps.Acquire();
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);
  Register current_jmpbuf = temps.Acquire();
  Register scratch = temps.Acquire();

  __ LoadExternalPointerField(
      current_jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  FillJumpBuffer(masm, current_jmpbuf, &suspend, scratch);
  SwitchStackState(masm, current_jmpbuf, scratch, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Inactive);
  FREE_REG(current_jmpbuf);
  // -------------------------------------------
  // Set the suspender and continuation parents and update the roots
  // -------------------------------------------
  Register active_suspender = kScratchReg;
  __ LoadRoot(active_suspender, RootIndex::kActiveSuspender);
  __ StoreTaggedField(
      active_suspender,
      FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  __ RecordWriteField(suspender, WasmSuspenderObject::kParentOffset,
                      active_suspender, kRAHasBeenSaved,
                      SaveFPRegsMode::kIgnore);
  active_suspender = no_reg;

  __ Move(scratch, Smi::FromInt(WasmSuspenderObject::kActive));
  __ StoreTaggedField(
      scratch, FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ StoreWord(suspender, MemOperand(kRootRegister, active_suspender_offset));

  // Next line we are going to load a field from suspender, but we have to use
  // the same register for target_continuation to use it in RecordWriteField.
  // So, free suspender here to use pinned reg, but load from it next line.
  suspender = no_reg;
  Register target_continuation = WriteBarrierDescriptor::ObjectRegister();
  suspender = target_continuation;
  __ LoadTaggedField(
      target_continuation,
      FieldMemOperand(suspender, WasmSuspenderObject::kContinuationOffset));
  suspender = no_reg;

  __ StoreTaggedField(active_continuation,
                      FieldMemOperand(target_continuation,
                                      WasmContinuationObject::kParentOffset));
  __ RecordWriteField(
      target_continuation, WasmContinuationObject::kParentOffset,
      active_continuation, kRAHasBeenSaved, SaveFPRegsMode::kIgnore);
  FREE_REG(active_continuation);
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ StoreWord(target_continuation,
               MemOperand(kRootRegister, active_continuation_offset));

  __ Push(target_continuation);
  SwitchStacks(masm, no_reg, scratch);
  __ Pop(target_continuation);

  // -------------------------------------------
  // Load state from target jmpbuf (longjmp).
  // -------------------------------------------
  Register target_jmpbuf = temps.Acquire();
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldMemOperand(target_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  // Move resolved value to return register.
  __ LoadWord(kReturnRegister0, MemOperand(fp, 3 * kSystemPointerSize));
  MemOperand GCScanSlotPlace =
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ StoreWord(zero_reg, GCScanSlotPlace);
  if (on_resume == wasm::OnResume::kThrow) {
    // Switch to the continuation's stack without restoring the PC.
    LoadJumpBuffer(masm, target_jmpbuf, false, scratch,
                   wasm::JumpBuffer::Suspended);
    // Pop this frame now. The unwinder expects that the first STACK_SWITCH
    // frame is the outermost one.
    __ LeaveFrame(StackFrame::STACK_SWITCH);
    // Forward the onRejected value to kThrow.
    __ Push(kReturnRegister0);
    __ CallRuntime(Runtime::kThrow);
  } else {
    // Resume the continuation normally.
    LoadJumpBuffer(masm, target_jmpbuf, true, scratch,
                   wasm::JumpBuffer::Suspended);
  }
  __ Trap();
  __ bind(&suspend);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  // Pop receiver + parameter.
  // __ DropArguments(2);
  __ AddWord(sp, sp, Operand(2 * kSystemPointerSize));
  __ Ret();
}
}  // namespace

void Builtins::Generate_WasmResume(MacroAssembler* masm) {
  Generate_WasmResumeHelper(masm, wasm::OnResume::kContinue);
}

void Builtins::Generate_WasmReject(MacroAssembler* masm) {
  Generate_WasmResumeHelper(masm, wasm::OnResume::kThrow);
}

void Builtins::Generate_WasmOnStackReplace(MacroAssembler* masm) {
  // Only needed on x64.
  __ Trap();
}

namespace {

void SaveState(MacroAssembler* masm, Register active_continuation, Register tmp,
               Label* suspend) {
  ASM_CODE_COMMENT(masm);
  Register jmpbuf = tmp;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  FillJumpBuffer(masm, jmpbuf, suspend, scratch);
}

void SwitchToAllocatedStack(MacroAssembler* masm, Register wasm_instance,
                            Register wrapper_buffer, Register original_fp,
                            Register new_wrapper_buffer, Label* suspend) {
  ASM_CODE_COMMENT(masm);
  UseScratchRegisterScope temps(masm);

  ResetStackSwitchFrameStackSlots(masm);
  Register scratch = temps.Acquire();
  Register target_continuation = temps.Acquire();
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  Register parent_continuation = temps.Acquire();
  __ LoadTaggedField(parent_continuation,
                     FieldMemOperand(target_continuation,
                                     WasmContinuationObject::kParentOffset));
  SaveState(masm, parent_continuation, scratch, suspend);
  __ Push(wasm_instance, wrapper_buffer);
  SwitchStacks(masm, no_reg, scratch);
  __ Pop(wasm_instance, wrapper_buffer);
  FREE_REG(parent_continuation);
  // Save the old stack's fp in x9, and use it to access the parameters in
  // the parent frame.
  __ mv(original_fp, fp);
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  LoadTargetJumpBuffer(masm, target_continuation, scratch,
                       wasm::JumpBuffer::Suspended);
  FREE_REG(target_continuation);
  // Push the loaded fp. We know it is null, because there is no frame yet,
  // so we could also push 0 directly. In any case we need to push it,
  // because this marks the base of the stack segment for
  // the stack frame iterator.
  __ EnterFrame(StackFrame::STACK_SWITCH);
  int stack_space =
      RoundUp(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize +
                  JSToWasmWrapperFrameConstants::kWrapperBufferSize,
              16);
  __ SubWord(sp, sp, Operand(stack_space));
  __ mv(new_wrapper_buffer, sp);
  // Copy data needed for return handling from old wrapper buffer to new one.
  // kWrapperBufferRefReturnCount will be copied too, because 8 bytes are copied
  // at the same time.
  static_assert(JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount ==
                JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount + 4);
  __ LoadWord(
      scratch,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ StoreWord(
      scratch,
      MemOperand(new_wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ LoadWord(
      scratch,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
  __ StoreWord(
      scratch,
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
}

// Loads the context field of the WasmTrustedInstanceData or WasmImportData
// depending on the data's type, and places the result in the input register.
void GetContextFromImplicitArg(MacroAssembler* masm, Register data,
                               Register scratch) {
  __ LoadTaggedField(scratch, FieldMemOperand(data, HeapObject::kMapOffset));
  Label instance;
  Label end;
  __ GetInstanceTypeRange(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE,
                          scratch);
  // __ CompareInstanceType(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  __ Branch(&instance, eq, scratch, Operand(zero_reg));
  __ LoadTaggedField(
      data, FieldMemOperand(data, WasmImportData::kNativeContextOffset));
  __ Branch(&end);
  __ bind(&instance);
  __ LoadTaggedField(
      data,
      FieldMemOperand(data, WasmTrustedInstanceData::kNativeContextOffset));
  __ bind(&end);
}

void SwitchBackAndReturnPromise(MacroAssembler* masm, wasm::Promise mode,
                                Label* return_promise) {
  UseScratchRegisterScope temps(masm);
  // The return value of the wasm function becomes the parameter of the
  // FulfillPromise builtin, and the promise is the return value of this
  // wrapper.
  static const Builtin_FulfillPromise_InterfaceDescriptor desc;
  Register promise = desc.GetRegisterParameter(0);
  Register return_value = desc.GetRegisterParameter(1);
  Register tmp = kScratchReg;
  Register tmp2 = kScratchReg2;
  Register tmp3 = temps.Acquire();
  if (mode == wasm::kPromise) {
    __ Move(return_value, kReturnRegister0);
    __ LoadRoot(promise, RootIndex::kActiveSuspender);
    __ LoadTaggedField(
        promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));
  }
  __ LoadWord(kContextRegister,
              MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  GetContextFromImplicitArg(masm, kContextRegister, tmp);

  ReloadParentContinuation(masm, promise, return_value, kContextRegister, tmp,
                           tmp2, tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  if (mode == wasm::kPromise) {
    __ li(tmp, 1);
    __ StoreWord(
        tmp, MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
    __ Push(promise);
    __ CallBuiltin(Builtin::kFulfillPromise);
    __ Pop(promise);
  }
  tmp = no_reg;
  tmp2 = no_reg;
  __ bind(return_promise);
}

void GenerateExceptionHandlingLandingPad(MacroAssembler* masm,
                                         Label* return_promise) {
  static const Builtin_RejectPromise_InterfaceDescriptor desc;
  Register promise = desc.GetRegisterParameter(0);
  Register reason = desc.GetRegisterParameter(1);
  Register debug_event = desc.GetRegisterParameter(2);
  int catch_handler = __ pc_offset();
  {
    UseScratchRegisterScope temps(masm);
    Register thread_in_wasm_flag_addr = temps.Acquire();
    // Unset thread_in_wasm_flag.
    __ LoadWord(thread_in_wasm_flag_addr,
                MemOperand(kRootRegister,
                           Isolate::thread_in_wasm_flag_address_offset()));
    __ StoreWord(zero_reg, MemOperand(thread_in_wasm_flag_addr, 0));
  }
  // The exception becomes the parameter of the RejectPromise builtin, and the
  // promise is the return value of this wrapper.
  __ mv(reason, kReturnRegister0);
  __ LoadRoot(promise, RootIndex::kActiveSuspender);
  __ LoadTaggedField(
      promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));

  __ LoadWord(kContextRegister,
              MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  Register tmp = kScratchReg;
  Register tmp2 = kScratchReg2;
  UseScratchRegisterScope temps(masm);
  Register tmp3 = temps.Acquire();
  GetContextFromImplicitArg(masm, kContextRegister, tmp);
  ReloadParentContinuation(masm, promise, reason, kContextRegister, tmp, tmp2,
                           tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  __ li(tmp, 1);
  __ StoreWord(
      tmp, MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  tmp = no_reg;
  tmp2 = no_reg;
  temps.Include(tmp3);
  tmp3 = no_reg;
  __ Push(promise);
  __ LoadRoot(debug_event, RootIndex::kTrueValue);
  __ CallBuiltin(Builtin::kRejectPromise);
  __ Pop(promise);

  // Run the rest of the wrapper normally (deconstruct the frame, ...).
  __ jmp(return_promise);

  masm->isolate()->builtins()->SetJSPIPromptHandlerOffset(catch_handler);
}

void JSToWasmWrapperHelper(MacroAssembler* masm, wasm::Promise mode) {
  bool stack_switch = mode == wasm::kPromise || mode == wasm::kStressSwitch;
  __ EnterFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);

  __ SubWord(
      sp, sp,
      Operand(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize));

  // Load the implicit argument (instance data or import data) from the frame.
  Register implicit_arg = kWasmImplicitArgRegister;
  __ LoadWord(
      implicit_arg,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));

  Register wrapper_buffer =
      WasmJSToWasmWrapperDescriptor::WrapperBufferRegister();
  Label suspend;
  Register original_fp = kScratchReg;
  Register new_wrapper_buffer = kScratchReg2;
  if (stack_switch) {
    SwitchToAllocatedStack(masm, implicit_arg, wrapper_buffer, original_fp,
                           new_wrapper_buffer, &suspend);
  } else {
    original_fp = fp;
    new_wrapper_buffer = wrapper_buffer;
  }

  {
    __ StoreWord(
        new_wrapper_buffer,
        MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));
    if (stack_switch) {
      __ StoreWord(
          implicit_arg,
          MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
      UseScratchRegisterScope temps(masm);
      Register scratch = temps.Acquire();
      __ LoadWord(
          scratch,
          MemOperand(original_fp,
                     JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
      __ StoreWord(
          scratch,
          MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    }
  }
  {
    UseScratchRegisterScope temps(masm);
    Register result_size = temps.Acquire();
    __ LoadWord(
        result_size,
        MemOperand(wrapper_buffer, JSToWasmWrapperFrameConstants::
                                       kWrapperBufferStackReturnBufferSize));
    // // The `result_size` is the number of slots needed on the stack to store
    // the
    // // return values of the wasm function. If `result_size` is an odd number,
    // we
    // // have to add `1` to preserve stack pointer alignment.
    // __ AddWord(result_size, result_size, 1);
    // __ Bic(result_size, result_size, 1);
    __ SllWord(result_size, result_size, kSystemPointerSizeLog2);
    __ SubWord(sp, sp, Operand(result_size));
  }
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ mv(scratch, sp);
    __ StoreWord(scratch, MemOperand(new_wrapper_buffer,
                                     JSToWasmWrapperFrameConstants::
                                         kWrapperBufferStackReturnBufferStart));
  }
  original_fp = no_reg;
  new_wrapper_buffer = no_reg;

  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;

  {
    UseScratchRegisterScope temps(masm);
    Register params_start = temps.Acquire();
    __ LoadWord(
        params_start,
        MemOperand(wrapper_buffer,
                   JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
    {
      // Push stack parameters on the stack.
      UseScratchRegisterScope temps(masm);
      Register params_end = kScratchReg;
      __ LoadWord(
          params_end,
          MemOperand(wrapper_buffer,
                     JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));
      Register last_stack_param = kScratchReg2;

      __ AddWord(last_stack_param, params_start, Operand(stack_params_offset));
      Label loop_start;
      __ bind(&loop_start);

      Label finish_stack_params;
      __ Branch(&finish_stack_params, ge, last_stack_param,
                Operand(params_end));

      // Push parameter
      {
        UseScratchRegisterScope temps(masm);
        Register scratch = temps.Acquire();
        __ SubWord(params_end, params_end, Operand(kSystemPointerSize));
        __ LoadWord(scratch, MemOperand(params_end, 0));
        __ Push(scratch);
      }
      __ Branch(&loop_start);

      __ bind(&finish_stack_params);
    }
    int next_offset = 0;
    for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); ++i) {
      // Check that {params_start} does not overlap with any of the parameter
      // registers, so that we don't overwrite it by accident with the loads
      // below.
      DCHECK_NE(params_start, wasm::kGpParamRegisters[i]);
      __ LoadWord(wasm::kGpParamRegisters[i],
                  MemOperand(params_start, next_offset));
      next_offset += kSystemPointerSize;
    }

    for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); ++i) {
      __ LoadDouble(wasm::kFpParamRegisters[i],
                    MemOperand(params_start, next_offset));
      next_offset += kDoubleSize;
    }
    DCHECK_EQ(next_offset, stack_params_offset);
  }

  {
    UseScratchRegisterScope temps(masm);
    Register thread_in_wasm_flag_addr = temps.Acquire();
    __ LoadWord(thread_in_wasm_flag_addr,
                MemOperand(kRootRegister,
                           Isolate::thread_in_wasm_flag_address_offset()));
    Register scratch = temps.Acquire();
    __ li(scratch, 1);
    __ Sw(scratch, MemOperand(thread_in_wasm_flag_addr, 0));
  }
  __ StoreWord(
      zero_reg,
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register call_target = temps.Acquire();
    __ LoadWord(
        call_target,
        MemOperand(wrapper_buffer,
                   JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));
    __ Call(call_target);
  }
  {
    UseScratchRegisterScope temps(masm);
    Register thread_in_wasm_flag_addr = temps.Acquire();
    __ LoadWord(thread_in_wasm_flag_addr,
                MemOperand(kRootRegister,
                           Isolate::thread_in_wasm_flag_address_offset()));
    __ Sw(zero_reg, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  wrapper_buffer = a2;
  __ LoadWord(
      wrapper_buffer,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  __ StoreDouble(
      wasm::kFpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1));
  __ StoreDouble(
      wasm::kFpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ StoreWord(
      wasm::kGpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ StoreWord(
      wasm::kGpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));
  // Call the return value builtin with
  // x0: wasm instance.
  // x1: the result JSArray for multi-return.
  // x2: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ LoadWord(a1,
                MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    __ LoadWord(a0,
                MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ LoadWord(
        a1,
        MemOperand(fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
    __ LoadWord(
        a0, MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  }
  {
    UseScratchRegisterScope temps(masm);
    GetContextFromImplicitArg(masm, a0, temps.Acquire());
  }
  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  Label return_promise;
  if (stack_switch) {
    SwitchBackAndReturnPromise(masm, mode, &return_promise);
  }
  __ bind(&suspend);

  __ LeaveFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);
  // Despite returning to the different location for regular and stack switching
  // versions, incoming argument count matches both cases:
  // instance and result array without suspend or
  // or promise resolve/reject params for callback.
  constexpr int64_t stack_arguments_in = 2;
  // __ DropArguments(stack_arguments_in);
  __ AddWord(sp, sp, Operand(stack_arguments_in * kSystemPointerSize));
  __ Ret();

  // Catch handler for the stack-switching wrapper: reject the promise with the
  // thrown exception.
  if (mode == wasm::kPromise) {
    GenerateExceptionHandlingLandingPad(masm, &return_promise);
  }
}
}  // namespace

void Builtins::Generate_JSToWasmWrapperAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kNoPromise);
}
void Builtins::Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  temps.Include(t1, t2);
  DCHECK(!AreAliased(WasmJSToWasmWrapperDescriptor::WrapperBufferRegister(), t1,
                     t2));
  JSToWasmWrapperHelper(masm, wasm::kPromise);
}
void Builtins::Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  temps.Include(t1, t2);
  DCHECK(!AreAliased(WasmJSToWasmWrapperDescriptor::WrapperBufferRegister(), t1,
                     t2));
  JSToWasmWrapperHelper(masm, wasm::kStressSwitch);
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- a1                  : api function address
  // Both modes:
  //  -- a2                  : arguments count
  //  -- a3                  : FunctionTemplateInfo
  //  -- a0                  : holder
  //  -- cp                  : context
  //  -- sp[0]               : receiver
  //  -- sp[8]               : first argument
  //  -- ...
  //  -- sp[(argc) * 8]      : last argument
  // -----------------------------------
  Register function_callback_info_arg = kCArgRegs[0];

  Register api_function_address = no_reg;
  Register argc = no_reg;
  Register func_templ = no_reg;
  Register holder = no_reg;
  Register topmost_script_having_context = no_reg;
  Register scratch = t0;

  switch (mode) {
    case CallApiCallbackMode::kGeneric:
      topmost_script_having_context = CallApiCallbackGenericDescriptor::
          TopmostScriptHavingContextRegister();
      argc = CallApiCallbackGenericDescriptor::ActualArgumentsCountRegister();
      func_templ =
          CallApiCallbackGenericDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackGenericDescriptor::HolderRegister();
      break;

    case CallApiCallbackMode::kOptimizedNoProfiling:
    case CallApiCallbackMode::kOptimized:
      // Caller context is always equal to current context because we don't
      // inline Api calls cross-context.
      topmost_script_having_context = kContextRegister;
      api_function_address =
          CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister();
      argc = CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister();
      func_templ =
          CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackOptimizedDescriptor::HolderRegister();
      break;
  }
  DCHECK(!AreAliased(api_function_address, topmost_script_having_context, argc,
                     holder, func_templ, scratch));

  using FCA = FunctionCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiCallbackExitFrameConstants;

  static_assert(FCA::kArgsLength == 6);
  static_assert(FCA::kNewTargetIndex == 5);
  static_assert(FCA::kTargetIndex == 4);
  static_assert(FCA::kReturnValueIndex == 3);
  static_assert(FCA::kContextIndex == 2);
  static_assert(FCA::kIsolateIndex == 1);
  static_assert(FCA::kHolderIndex == 0);

  // Set up FunctionCallbackInfo's implicit_args on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kData
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[6 * kSystemPointerSize]:            <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);
  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }
  // Reserve space on the stack.
  static constexpr int kStackSize = FCA::kArgsLength;
  static_assert(kStackSize % 2 == 0);
  __ SubWord(sp, sp, Operand(kStackSize * kSystemPointerSize));

  // kHolder.
  __ StoreWord(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ li(scratch, ER::isolate_address());
  __ StoreWord(scratch,
               MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext
  __ StoreWord(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ StoreWord(scratch,
               MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ StoreWord(func_templ,
               MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ StoreWord(scratch,
               MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  if (mode == CallApiCallbackMode::kGeneric) {
    __ LoadExternalPointerField(
        api_function_address,
        FieldMemOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset),
        kFunctionTemplateInfoCallbackTag);
  }

  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_CALLBACK_EXIT);
  MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ StoreWord(argc, argc_operand);
    // FunctionCallbackInfo::implicit_args_.
    __ AddWord(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ StoreWord(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));
    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ AddWord(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ StoreWord(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }
  __ RecordComment("v8::FunctionCallback's argument");
  __ AddWord(function_callback_info_arg, fp,
             Operand(FC::kFunctionCallbackInfoOffset));
  DCHECK(!AreAliased(api_function_address, function_callback_info_arg));
  ExternalReference thunk_ref = ER::invoke_function_callback(mode);
  Register no_thunk_arg = no_reg;
  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kFunctionCallbackInfoArgsLength + kJSArgcReceiverSlots;
  const bool with_profiling =
      mode != CallApiCallbackMode::kOptimizedNoProfiling;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, no_thunk_arg, kSlotsToDropOnReturn,
                           &argc_operand, return_value_operand);
}

void Builtins::Generate_CallApiGetter(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- cp                  : context
  //  -- a1                  : receiver
  //  -- a3                  : accessor info
  //  -- a0                  : holder
  // -----------------------------------

  Register name_arg = kCArgRegs[0];
  Register property_callback_info_arg = kCArgRegs[1];

  Register api_function_address = kCArgRegs[2];

  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = a4;
  DCHECK(!AreAliased(receiver, holder, callback, scratch));

  // Build v8::PropertyCallbackInfo::args_ array on the stack and push property
  // name below the exit frame to make GC aware of them.
  using PCA = PropertyCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiAccessorExitFrameConstants;
  static_assert(PCA::kPropertyKeyIndex == 0);
  static_assert(PCA::kShouldThrowOnErrorIndex == 1);
  static_assert(PCA::kHolderIndex == 2);
  static_assert(PCA::kIsolateIndex == 3);
  static_assert(PCA::kHolderV2Index == 4);
  static_assert(PCA::kReturnValueIndex == 5);
  static_assert(PCA::kDataIndex == 6);
  static_assert(PCA::kThisIndex == 7);
  static_assert(PCA::kArgsLength == 8);
  // Set up v8::PropertyCallbackInfo's (PCI) args_ on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: name                      <= PCI::args_
  //   sp[1 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   sp[2 * kSystemPointerSize]: kHolderIndex
  //   sp[3 * kSystemPointerSize]: kIsolateIndex
  //   sp[4 * kSystemPointerSize]: kHolderV2Index
  //   sp[5 * kSystemPointerSize]: kReturnValueIndex
  //   sp[6 * kSystemPointerSize]: kDataIndex
  //   sp[7 * kSystemPointerSize]: kThisIndex / receiver
  __ SubWord(sp, sp, (PCA::kArgsLength)*kSystemPointerSize);
  __ StoreWord(receiver, MemOperand(sp, (PCA::kThisIndex)*kSystemPointerSize));
  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kDataOffset));
  __ StoreWord(scratch, MemOperand(sp, (PCA::kDataIndex)*kSystemPointerSize));
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ StoreWord(scratch,
               MemOperand(sp, (PCA::kReturnValueIndex)*kSystemPointerSize));
  __ StoreWord(zero_reg,
               MemOperand(sp, (PCA::kHolderV2Index)*kSystemPointerSize));
  __ li(scratch, ER::isolate_address());
  __ StoreWord(scratch,
               MemOperand(sp, (PCA::kIsolateIndex)*kSystemPointerSize));
  __ StoreWord(holder, MemOperand(sp, (PCA::kHolderIndex)*kSystemPointerSize));
  // should_throw_on_error -> false
  DCHECK_EQ(0, Smi::zero().ptr());
  __ StoreWord(
      zero_reg,
      MemOperand(sp, (PCA::kShouldThrowOnErrorIndex)*kSystemPointerSize));
  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kNameOffset));
  __ StoreWord(scratch, MemOperand(sp, 0 * kSystemPointerSize));

  __ RecordComment("Load api_function_address");
  __ LoadExternalPointerField(
      api_function_address,
      FieldMemOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset),
      kAccessorInfoGetterTag);

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_ACCESSOR_EXIT);
  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  __ AddWord(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));
  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name_arg,
                     callback, scratch));
#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  // |name_arg| is already initialized above.
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ mv(name_arg, property_callback_info_arg);
#endif

  ExternalReference thunk_ref = ER::invoke_accessor_getter_callback();
  // Pass AccessorInfo to thunk wrapper in case profiler or side-effect
  // checking is enabled.
  Register thunk_arg = callback;

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kPropertyCallbackInfoArgsLength;
  MemOperand* const kUseStackSpaceConstant = nullptr;

  const bool with_profiling = true;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, thunk_arg, kSlotsToDropOnReturn,
                           kUseStackSpaceConstant, return_value_operand);
}

void Builtins::Generate_DirectCEntry(MacroAssembler* masm) {
  // The sole purpose of DirectCEntry is for movable callers (e.g. any general
  // purpose InstructionStream object) to be able to call into C functions that
  // may trigger GC and thus move the caller.
  //
  // DirectCEntry places the return address on the stack (updated by the GC),
  // making the call GC safe. The irregexp backend relies on this.

  // Make place for arguments to fit C calling convention. Callers use
  // EnterExitFrame/LeaveExitFrame so they handle stack restoring and we don't
  // have to do that here. Any caller must drop kCArgsSlotsSize stack space
  // after the call.
  __ AddWord(sp, sp, -kCArgsSlotsSize);

  __ StoreWord(ra,
               MemOperand(sp, kCArgsSlotsSize));  // Store the return address.
  __ Call(t6);                                    // Call the C++ function.
  __ LoadWord(t6, MemOperand(sp, kCArgsSlotsSize));  // Return to calling code.

  if (v8_flags.debug_code && v8_flags.enable_slow_asserts) {
    // In case of an error the return address may point to a memory area
    // filled with kZapValue by the GC. Dereference the address and check for
    // this.
    __ Uld(a4, MemOperand(t6));
    __ Assert(ne, AbortReason::kReceivedInvalidReturnAddress, a4,
              Operand(kZapValue));
  }

  __ Jump(t6);
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

  const int kDoubleRegsSize = kDoubleSize * DoubleRegister::kNumRegisters;

  // Save all double FPU registers before messing with them.
  __ SubWord(sp, sp, Operand(kDoubleRegsSize));
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
    int offset = code * kDoubleSize;
    __ StoreDouble(fpu_reg, MemOperand(sp, offset));
  }

  // Push saved_regs (needed to populate FrameDescription::registers_).
  // Leave gaps for other registers.
  __ SubWord(sp, sp, kNumberOfRegisters * kSystemPointerSize);
  for (int16_t i = kNumberOfRegisters - 1; i >= 0; i--) {
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ StoreWord(ToRegister(i), MemOperand(sp, kSystemPointerSize * i));
    }
  }

  __ li(a2,
        ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate));
  __ StoreWord(fp, MemOperand(a2));

  const int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kSystemPointerSize) + kDoubleRegsSize;

  // Get the address of the location in the code object (a2) (return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register a4.
  __ Move(a2, ra);
  __ AddWord(a3, sp, Operand(kSavedRegistersAreaSize));

  __ SubWord(a3, fp, a3);

  // Allocate a new deoptimizer object.
  __ PrepareCallCFunction(5, a4);
  // Pass five arguments, according to n64 ABI.
  __ Move(a0, zero_reg);
  Label context_check;
  __ LoadWord(a1,
              MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(a1, &context_check);
  __ LoadWord(a0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ li(a1, Operand(static_cast<int64_t>(deopt_kind)));
  // a2: code object address
  // a3: fp-to-sp delta
  __ li(a4, ExternalReference::isolate_address());

  // Call Deoptimizer::New().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register a0 and get the input
  // frame descriptor pointer to a1 (deoptimizer->input_);
  __ LoadWord(a1, MemOperand(a0, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_[kNumRegisters].
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ LoadWord(a2, MemOperand(sp, i * kSystemPointerSize));
      __ StoreWord(a2, MemOperand(a1, offset));
    } else if (v8_flags.debug_code) {
      __ li(a2, kDebugZapValue);
      __ StoreWord(a2, MemOperand(a1, offset));
    }
  }

  int double_regs_offset = FrameDescription::double_registers_offset();
  // int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  //  Copy FPU registers to
  //  double_registers_[DoubleRegister::kNumAllocatableRegisters]
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    int dst_offset = code * kDoubleSize + double_regs_offset;
    int src_offset =
        code * kDoubleSize + kNumberOfRegisters * kSystemPointerSize;
    __ LoadDouble(ft0, MemOperand(sp, src_offset));
    __ StoreDouble(ft0, MemOperand(a1, dst_offset));
  }
  // TODO(riscv): Add Simd128 copy

  // Remove the saved registers from the stack.
  __ AddWord(sp, sp, Operand(kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register a2; that is
  // the first stack slot not part of the input frame.
  __ LoadWord(a2, MemOperand(a1, FrameDescription::frame_size_offset()));
  __ AddWord(a2, a2, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ AddWord(a3, a1, Operand(FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ BranchShort(&pop_loop_header);
  __ bind(&pop_loop);
  __ pop(a4);
  __ StoreWord(a4, MemOperand(a3, 0));
  __ AddWord(a3, a3, kSystemPointerSize);
  __ bind(&pop_loop_header);
  __ Branch(&pop_loop, ne, a2, Operand(sp), Label::Distance::kNear);
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

  __ LoadWord(sp, MemOperand(a0, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: a4 = current "FrameDescription** output_",
  // a1 = one past the last FrameDescription**.
  __ Lw(a1, MemOperand(a0, Deoptimizer::output_count_offset()));
  __ LoadWord(a4,
              MemOperand(a0, Deoptimizer::output_offset()));  // a4 is output_.
  __ CalcScaledAddress(a1, a4, a1, kSystemPointerSizeLog2);
  __ BranchShort(&outer_loop_header);
  __ bind(&outer_push_loop);
  // Inner loop state: a2 = current FrameDescription*, a3 = loop index.
  __ LoadWord(a2, MemOperand(a4, 0));  // output_[ix]
  __ LoadWord(a3, MemOperand(a2, FrameDescription::frame_size_offset()));
  __ BranchShort(&inner_loop_header);
  __ bind(&inner_push_loop);
  __ SubWord(a3, a3, Operand(kSystemPointerSize));
  __ AddWord(a6, a2, Operand(a3));
  __ LoadWord(a7, MemOperand(a6, FrameDescription::frame_content_offset()));
  __ push(a7);
  __ bind(&inner_loop_header);
  __ Branch(&inner_push_loop, ne, a3, Operand(zero_reg));

  __ AddWord(a4, a4, Operand(kSystemPointerSize));
  __ bind(&outer_loop_header);
  __ Branch(&outer_push_loop, lt, a4, Operand(a1));

  __ LoadWord(a1, MemOperand(a0, Deoptimizer::input_offset()));
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
    int src_offset = code * kDoubleSize + double_regs_offset;
    __ LoadDouble(fpu_reg, MemOperand(a1, src_offset));
  }

  // Push pc and continuation from the last output frame.
  __ LoadWord(a6, MemOperand(a2, FrameDescription::pc_offset()));
  __ push(a6);
  __ LoadWord(a6, MemOperand(a2, FrameDescription::continuation_offset()));
  __ push(a6);

  // Technically restoring 't3' should work unless zero_reg is also restored
  // but it's safer to check for this.
  DCHECK(!(restored_regs.has(t3)));
  // Restore the registers from the last output frame.
  __ Move(t3, a2);
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((restored_regs.bits() & (1 << i)) != 0) {
      __ LoadWord(ToRegister(i), MemOperand(t3, offset));
    }
  }

  __ pop(t6);  // Get continuation, leave pc on stack.
  __ pop(ra);
  Label end;
  __ Branch(&end, eq, t6, Operand(zero_reg));
  __ Jump(t6);
  __ bind(&end);
  __ Ret();
  __ stop();
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
  __ LoadWord(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = s1;
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
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ GetObjectType(code_obj, scratch, scratch);
    __ Branch(&start_with_baseline, eq, scratch, Operand(CODE_TYPE));

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ GetObjectType(code_obj, scratch, scratch);
    __ Assert(eq, AbortReason::kExpectedBaselineData, scratch,
              Operand(CODE_TYPE));
  }
  if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    AssertCodeIsBaseline(masm, code_obj, scratch);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = a2;
  Register feedback_vector = t4;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  {
    UseScratchRegisterScope temps(masm);
    Register type = temps.Acquire();
    __ GetObjectType(feedback_vector, type, type);
    __ Branch(&install_baseline_code, ne, type, Operand(FEEDBACK_VECTOR_TYPE));
  }
  // Save BytecodeOffset from the stack frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ StoreWord(feedback_cell,
               MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ StoreWord(
      feedback_vector,
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

  __ SubWord(kInterpreterBytecodeOffsetRegister,
             kInterpreterBytecodeOffsetRegister,
             (BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ LoadWord(kInterpreterBytecodeArrayRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
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
  __ AddWord(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    // Reset the OSR loop nesting depth to disarm back edges.
    // TODO(pthier): Separate baseline Sparkplug from TF arming and don't disarm
    // Sparkplug here.
    __ LoadWord(
        kInterpreterBytecodeArrayRegister,
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
    __ li(kInterpreterBytecodeOffsetRegister, Operand(0));
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

  __ LoadWord(a1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadWord(a0, MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // Pop return address and frame.
  __ LeaveFrame(StackFrame::INTERPRETED);

  __ li(a2, Operand(kDontAdaptArgumentsSentinel));

  __ InvokeFunction(a1, a2, a0, InvokeType::kJump);
}

#undef __

}  // namespace internal
}  // namespace v8

"""


```
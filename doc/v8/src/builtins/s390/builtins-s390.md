Response: The user wants a summary of the C++ source code file `builtins-s390.cc`.
The goal is to understand its functionality and, if it relates to JavaScript, illustrate it with JavaScript examples.

**Thinking Process:**

1. **High-Level Overview:**  The file is located in `v8/src/builtins/s390/`. This suggests it contains architecture-specific (s390) implementations of built-in functions for the V8 JavaScript engine.

2. **Key Components:** Scan the code for important classes, functions, and macros. Notice the usage of `MacroAssembler`, `Builtins`, and various `Generate_` prefixed functions. These strongly indicate that the file is responsible for generating machine code for specific built-in functionalities.

3. **Specific Built-ins:** Look for function names that resemble common JavaScript concepts or built-in methods. Examples include `Adaptor`, `JSConstructStubGeneric`, `ResumeGeneratorTrampoline`, `JSEntry`, `InterpreterEntryTrampoline`, `BaselineOutOfLinePrologue`, `InterpreterPushArgsThenCallImpl`, etc. These are low-level implementations of how JavaScript constructs are handled.

4. **Relationship to JavaScript:** The presence of functions like `JSConstructStubGeneric` (for `new` operator), `ResumeGeneratorTrampoline` (for `yield` and `async`/`await`), and `InterpreterEntryTrampoline` (for function calls) clearly demonstrates the connection to JavaScript.

5. **Code Generation:** The `MacroAssembler` class is central. It's used to emit assembly instructions (likely for the s390 architecture). The `Generate_` prefixes confirm that these functions are responsible for code generation.

6. **Interpreter and Baseline:** The code mentions both "Interpreter" and "Baseline". This points to V8's tiered compilation approach. The interpreter executes code initially, and the baseline compiler generates optimized code for frequently executed parts.

7. **OSREntry:** The `Generate_OSREntry` function hints at On-Stack Replacement, a technique where the engine switches from interpreted or baseline code to more optimized code while a function is still running.

8. **Stack Frames:**  References to `StackFrame` and its constants (like `kFunctionOffset`, `kBytecodeOffsetFromFp`) indicate that the code manipulates the call stack, essential for function execution.

9. **Error Handling:** Calls to `Runtime::kThrowStackOverflow` suggest handling of common runtime errors.

10. **JavaScript Examples (Conceptual):**  While the C++ code deals with the low-level details, think about the corresponding JavaScript operations.
    * `JSConstructStubGeneric` relates to using the `new` keyword.
    * `ResumeGeneratorTrampoline` relates to `yield` within generators or the asynchronous nature of `async/await`.
    * `InterpreterEntryTrampoline` is the entry point for regular function calls.

11. **Structure of the File:** The code is organized into namespaces (`v8::internal`) and helper functions. The `Builtins` class seems to be the central point for registering or managing these generated code snippets.

**Drafting the Summary (Iterative Refinement):**

* **Initial thought:** "This file contains s390 architecture-specific built-in functions for V8."

* **Adding details:** "This C++ file implements built-in JavaScript functionalities for the s390 architecture within the V8 engine. It uses `MacroAssembler` to generate assembly code for common operations like function calls, constructor calls, and generator resumption."

* **Connecting to JavaScript:** "This file defines low-level implementations for core JavaScript features. For instance, it handles how the `new` keyword creates objects (`Generate_JSConstructStubGeneric`) and how generator functions are resumed using `yield` (`Generate_ResumeGeneratorTrampoline`)."

* **Illustrating with JavaScript:** "For example, when you use the `new` keyword in JavaScript like `new MyClass()`, the logic within a function similar to `Generate_JSConstructStubGeneric` is executed at the machine code level. Similarly, when a generator function encounters a `yield` statement, functions like `Generate_ResumeGeneratorTrampoline` manage the suspension and subsequent resumption of the generator's execution."

* **Incorporating interpreter/baseline:** "The file also includes code related to V8's tiered compilation, managing the transition between the interpreter (`Generate_InterpreterEntryTrampoline`) and baseline compiler (`Generate_BaselineOutOfLinePrologue`)."

* **Final Polish:** Ensure the summary is concise, accurate, and addresses all key aspects of the code.

This step-by-step analysis leads to the desired summary by breaking down the complex C++ code into understandable concepts and linking them to familiar JavaScript features.
This C++ source code file, located at `v8/src/builtins/s390/builtins-s390.cc`, is the first of three parts that define the **architecture-specific (s390) implementations of built-in JavaScript functions** for the V8 JavaScript engine.

Here's a breakdown of its functionalities based on the provided code:

**Core Functionalities:**

* **Code Generation for Built-ins:** The primary function of this file is to generate machine code (specifically for the s390 architecture) for various built-in JavaScript functions and operations. This is evident from the numerous functions prefixed with `Generate_`, which take a `MacroAssembler` as input. The `MacroAssembler` is used to emit assembly instructions.
* **Handling Function Calls:**  It contains code for different ways JavaScript functions are called, including:
    * **Adaptors:**  Used as intermediaries for calling functions with a specific signature.
    * **Construct Calls (`new` keyword):**  Implementations for how constructor functions are invoked (`Generate_JSConstructStubGeneric`, `Generate_JSBuiltinsConstructStub`).
    * **Regular Calls:**  Entry points and setup for calling JavaScript functions (`Generate_JSEntry`, `Generate_JSEntryTrampoline`, `Generate_InterpreterEntryTrampoline`).
    * **Tail Calls:** Optimizations for function calls where the last action is another function call.
* **Generator Function Support:** It includes logic for resuming generator functions (`Generate_ResumeGeneratorTrampoline`). This is crucial for implementing `yield` and `async/await`.
* **Interpreter Integration:**  The code has significant parts dedicated to the V8 interpreter, including:
    * **Entry and Exit:** Setting up and tearing down interpreter frames (`Generate_InterpreterEntryTrampoline`, `LeaveInterpreterFrame`).
    * **Bytecode Handling:**  Advancing through bytecode instructions (`AdvanceBytecodeOffsetOrReturn`).
    * **Argument Handling:** Pushing arguments onto the stack for interpreter calls (`GenerateInterpreterPushArgs`, `Generate_InterpreterPushArgsThenCallImpl`, `Generate_InterpreterPushArgsThenConstructImpl`).
* **Baseline Compilation Support:** It includes code related to V8's baseline compiler, a lightweight optimizing compiler:
    * **Prologue and Deoptimization:** Logic for the initial setup and handling deoptimization from baseline code (`Generate_BaselineOutOfLinePrologue`, `Generate_BaselineOutOfLinePrologueDeopt`).
* **On-Stack Replacement (OSR):**  Functions like `Generate_OSREntry` and `OnStackReplacement` handle the process of transitioning from less optimized (interpreter or baseline) code to more optimized code while a function is running.
* **Stack Management:**  The code directly manipulates the stack, pushing and popping values, setting up frames, and performing stack overflow checks.
* **Debugging Support:**  There are checks and hooks for debugging, especially for stepping through code.
* **Tiering:** The presence of code for both interpreter and baseline suggests this file is involved in V8's tiered compilation system, where code starts in the interpreter and can be promoted to baseline or optimized code.
* **Feedback Vector Handling:**  The code interacts with feedback vectors, which store information about the execution of functions to guide optimization.

**Relationship to JavaScript (with JavaScript examples):**

This C++ code directly implements the underlying mechanics of how JavaScript code is executed on the s390 architecture. Here are some examples:

1. **Function Calls:**
   ```javascript
   function myFunction(a, b) {
     return a + b;
   }
   myFunction(1, 2);
   ```
   The `Generate_InterpreterEntryTrampoline` or `Generate_JSEntryTrampoline` (depending on the optimization level) in this C++ file would be responsible for setting up the stack frame, passing arguments (1 and 2), and jumping to the machine code representing the `myFunction`'s logic.

2. **Constructor Calls (`new` keyword):**
   ```javascript
   class MyClass {
     constructor(value) {
       this.myValue = value;
     }
   }
   const instance = new MyClass(5);
   ```
   The `Generate_JSConstructStubGeneric` function in the C++ would handle the allocation of memory for the `MyClass` instance, calling the `constructor`, and setting up the prototype chain.

3. **Generator Functions:**
   ```javascript
   function* myGenerator() {
     yield 1;
     yield 2;
   }
   const gen = myGenerator();
   gen.next(); // { value: 1, done: false }
   gen.next(); // { value: 2, done: false }
   ```
   The `Generate_ResumeGeneratorTrampoline` function in the C++ is invoked when `gen.next()` is called. It manages the state of the generator, allowing it to resume execution from where it left off at the `yield` statement.

4. **Stack Overflow:**
   ```javascript
   function recursiveFunction() {
     recursiveFunction();
   }
   recursiveFunction(); // This will eventually cause a stack overflow.
   ```
   The stack overflow checks performed in the C++ code (like the calls to `Runtime::kThrowStackOverflow`) are the mechanisms that detect when the JavaScript call stack exceeds its limits, leading to the `RangeError: Maximum call stack size exceeded` error in JavaScript.

**In essence, this file provides the low-level "engine" that makes JavaScript code run on s390 systems. It translates high-level JavaScript constructs into the concrete machine instructions that the processor understands.**

### 提示词
```
这是目录为v8/src/builtins/s390/builtins-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_S390X

#include "src/api/api-arguments.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
// For interpreter_entry_return_pc_offset. TODO(jkummerow): Drop.
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/register-configuration.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/heap/heap-inl.h"
#include "src/logging/counters.h"
#include "src/objects/cell.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-generator.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/baseline/liftoff-assembler-defs.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)

namespace {

static void AssertCodeIsBaseline(MacroAssembler* masm, Register code,
                                 Register scratch) {
  DCHECK(!AreAliased(code, scratch));
  // Verify that the code kind is baseline code via the CodeKind.
  __ LoadU32(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ CmpS64(scratch, Operand(static_cast<int>(CodeKind::BASELINE)));
  __ Assert(eq, AbortReason::kExpectedBaselineData);
}

static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  USE(GetSharedFunctionInfoBytecodeOrBaseline);
  ASM_CODE_COMMENT(masm);
  Label done;

  Register data = bytecode;
  __ LoadTaggedField(
      data,
      FieldMemOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset));

  __ LoadMap(scratch1, data);
  __ LoadU16(scratch1, FieldMemOperand(scratch1, Map::kInstanceTypeOffset));

#ifndef V8_JITLESS
  __ CmpS32(scratch1, Operand(CODE_TYPE));
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ b(ne, &not_baseline);
    AssertCodeIsBaseline(masm, data, scratch1);
    __ beq(is_baseline);
    __ bind(&not_baseline);
  } else {
    __ beq(is_baseline);
  }
#endif  // !V8_JITLESS

  __ CmpS32(scratch1, Operand(BYTECODE_ARRAY_TYPE));
  __ b(eq, &done);

  __ CmpS32(scratch1, Operand(INTERPRETER_DATA_TYPE));
  __ b(ne, is_unavailable);
  __ LoadTaggedField(
      data, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset));

  __ bind(&done);
}

void Generate_OSREntry(MacroAssembler* masm, Register entry_address,
                       Operand offset) {
  if (!offset.is_reg() && is_int20(offset.immediate())) {
    __ lay(r14, MemOperand(entry_address, offset.immediate()));
  } else {
    DCHECK(offset.is_reg());
    __ AddS64(r14, entry_address, offset.rm());
  }

  // "return" to the OSR entry point of the function.
  __ Ret();
}

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi,
                                Register scratch) {
  DCHECK(!AreAliased(sfi, scratch));
  __ mov(scratch, Operand(0));
  __ StoreU16(scratch, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset),
              no_reg);
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function,
                        Register scratch1, Register scratch2) {
  __ LoadTaggedField(
      scratch1,
      FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, scratch1, scratch2);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  DCHECK(!AreAliased(feedback_vector, scratch));
  __ LoadU8(scratch,
            FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ AndP(scratch, scratch, Operand(~FeedbackVector::OsrUrgencyBits::kMask));
  __ StoreU8(scratch,
             FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
}

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
  Register closure = r3;
  __ LoadU64(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = r8;
  __ LoadTaggedField(
      code_obj,
      FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj, r5);
  }

  __ LoadTaggedField(
      code_obj, FieldMemOperand(
                    code_obj, SharedFunctionInfo::kTrustedFunctionDataOffset));

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ CompareObjectType(code_obj, r5, r5, CODE_TYPE);
    __ b(eq, &start_with_baseline);

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ CompareObjectType(code_obj, r5, r5, CODE_TYPE);
    __ Assert(eq, AbortReason::kExpectedBaselineData);
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, r5);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = r4;
  Register feedback_vector = r1;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ CompareObjectType(feedback_vector, r5, r5, FEEDBACK_VECTOR_TYPE);
  __ b(ne, &install_baseline_code);

  // Save BytecodeOffset from the stack frame.
  __ LoadU64(kInterpreterBytecodeOffsetRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ StoreU64(feedback_cell,
              MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ StoreU64(feedback_vector,
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
  Register get_baseline_pc = r5;
  __ Move(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ CmpS64(kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                      kFunctionEntryBytecodeOffset));
    __ b(eq, &function_entry_bytecode);
  }

  __ SubS64(kInterpreterBytecodeOffsetRegister,
            kInterpreterBytecodeOffsetRegister,
            Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
  __ Push(kInterpreterAccumulatorRegister);
  {
    __ mov(kCArgRegs[0], code_obj);
    __ mov(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ mov(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PrepareCallCFunction(3, 0, r1);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ LoadCodeInstructionStart(code_obj, code_obj);
  __ AddS64(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    // TODO(pthier): Separate baseline Sparkplug from TF arming and don't
    // disarm Sparkplug here.
    Generate_OSREntry(masm, code_obj, Operand(0));
  } else {
    __ Jump(code_obj);
  }
  __ Trap();  // Unreachable.

  if (!is_osr) {
    __ bind(&function_entry_bytecode);
    // If the bytecode offset is kFunctionEntryOffset, get the start address of
    // the first bytecode.
    __ mov(kInterpreterBytecodeOffsetRegister, Operand(0));
    if (next_bytecode) {
      __ Move(get_baseline_pc,
              ExternalReference::baseline_pc_for_bytecode_offset());
    }
    __ b(&valid_bytecode_offset);
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
  __ b(&start);
}

enum class OsrSourceTier {
  kInterpreter,
  kBaseline,
};

void OnStackReplacement(MacroAssembler* masm, OsrSourceTier source,
                        Register maybe_target_code) {
  Label jump_to_optimized_code;
  {
    // If maybe_target_code is not null, no need to call into runtime. A
    // precondition here is: if maybe_target_code is an InstructionStream
    // object, it must NOT be marked_for_deoptimization (callers must ensure
    // this).
    __ CmpSmiLiteral(maybe_target_code, Smi::zero(), r0);
    __ bne(&jump_to_optimized_code);
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ CmpSmiLiteral(r2, Smi::zero(), r0);
  __ bne(&jump_to_optimized_code);
  __ Ret();

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, r2);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ Move(r3, ExternalReference::address_of_log_or_trace_osr());
    __ LoadU8(r3, MemOperand(r3));
    __ tmll(r3, Operand(0xFF));  // Mask to the LSB.
    __ beq(&next);

    {
      FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
      __ Push(r2);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(r2);
    }

    __ bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame. This is the case then OSR is triggered from bytecode.
    __ LeaveFrame(StackFrame::STUB);
  }

  // Load deoptimization data from the code object.
  // <deopt_data> = <code>[#deoptimization_data_offset]
  __ LoadTaggedField(
      r3,
      FieldMemOperand(r2, Code::kDeoptimizationDataOrInterpreterDataOffset));

  // Load the OSR entrypoint offset from the deoptimization data.
  // <osr_offset> = <deopt_data>[#header_size + #osr_pc_offset]
  __ SmiUntagField(
      r3, FieldMemOperand(r3, FixedArray::OffsetOfElementAt(
                                  DeoptimizationData::kOsrPcOffsetIndex)));

  __ LoadCodeInstructionStart(r2, r2);

  // Compute the target address = code_entry + osr_offset
  // <entry_addr> = <code_entry> + <osr_offset>
  Generate_OSREntry(masm, r2, Operand(r3));
}

}  // namespace

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
  __ Move(kJavaScriptCallExtraArg1Register, ExternalReference::Create(address));
  __ TailCallBuiltin(
      Builtins::AdaptorWithBuiltinExitFrame(formal_parameter_count));
}

namespace {

enum class ArgumentsElementType {
  kRaw,    // Push arguments as they are.
  kHandle  // Dereference arguments before pushing.
};

void Generate_PushArguments(MacroAssembler* masm, Register array, Register argc,
                            Register scratch,
                            ArgumentsElementType element_type) {
  DCHECK(!AreAliased(array, argc, scratch));
  Register counter = scratch;
  Register value = ip;
  Label loop, entry;
  __ SubS64(counter, argc, Operand(kJSArgcReceiverSlots));
  __ b(&entry);
  __ bind(&loop);
  __ ShiftLeftU64(value, counter, Operand(kSystemPointerSizeLog2));
  __ LoadU64(value, MemOperand(array, value));
  if (element_type == ArgumentsElementType::kHandle) {
    __ LoadU64(value, MemOperand(value));
  }
  __ push(value);
  __ bind(&entry);
  __ SubS64(counter, counter, Operand(1));
  __ bge(&loop);
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2     : number of arguments
  //  -- r3     : constructor function
  //  -- r5     : new target
  //  -- cp     : context
  //  -- lr     : return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  Register scratch = r4;
  Label stack_overflow;

  __ StackOverflowCheck(r2, scratch, &stack_overflow);

  // Enter a construct frame.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.
    __ Push(cp, r2);

    // TODO(victorgomes): When the arguments adaptor is completely removed, we
    // should get the formal parameter count and copy the arguments in its
    // correct position (including any undefined), instead of delaying this to
    // InvokeFunction.

    // Set up pointer to first argument (skip receiver).
    __ la(r6, MemOperand(fp, StandardFrameConstants::kCallerSPOffset +
                                 kSystemPointerSize));
    // Copy arguments and receiver to the expression stack.
    // r6: Pointer to start of arguments.
    // r2: Number of arguments.
    Generate_PushArguments(masm, r6, r2, r1, ArgumentsElementType::kRaw);

    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // r2: number of arguments
    // r3: constructor function
    // r5: new target

    __ InvokeFunctionWithNewTarget(r3, r5, r2, InvokeType::kCall);

    // Restore context from the frame.
    __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ LoadU64(scratch, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

    // Leave construct frame.
  }
  // Remove caller arguments from the stack and return.
  __ DropArguments(scratch);
  __ Ret();

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ bkpt(0);  // Unreachable code.
  }
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  --      r2: number of arguments (untagged)
  //  --      r3: constructor function
  //  --      r5: new target
  //  --      cp: context
  //  --      lr: return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  FrameScope scope(masm, StackFrame::MANUAL);
  // Enter a construct frame.
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;
  __ EnterFrame(StackFrame::CONSTRUCT);

  // Preserve the incoming parameters on the stack.
  __ Push(cp, r2, r3);
  __ PushRoot(RootIndex::kUndefinedValue);
  __ Push(r5);

  // ----------- S t a t e -------------
  //  --        sp[0*kSystemPointerSize]: new target
  //  --        sp[1*kSystemPointerSize]: padding
  //  -- r3 and sp[2*kSystemPointerSize]: constructor function
  //  --        sp[3*kSystemPointerSize]: number of arguments
  //  --        sp[4*kSystemPointerSize]: context
  // -----------------------------------

  __ LoadTaggedField(
      r6, FieldMemOperand(r3, JSFunction::kSharedFunctionInfoOffset));
  __ LoadU32(r6, FieldMemOperand(r6, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(r6);
  __ JumpIfIsInRange(
      r6, r6, static_cast<uint8_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint8_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);
  __ b(&post_instantiation_deopt_entry);

  // Else: use TheHoleValue as receiver for constructor call
  __ bind(&not_create_implicit_receiver);
  __ LoadRoot(r2, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  --                          r2: receiver
  //  -- Slot 4 / sp[0*kSystemPointerSize]: new target
  //  -- Slot 3 / sp[1*kSystemPointerSize]: padding
  //  -- Slot 2 / sp[2*kSystemPointerSize]: constructor function
  //  -- Slot 1 / sp[3*kSystemPointerSize]: number of arguments
  //  -- Slot 0 / sp[4*kSystemPointerSize]: context
  // -----------------------------------
  // Deoptimizer enters here.
  masm->isolate()->heap()->SetConstructStubCreateDeoptPCOffset(
      masm->pc_offset());
  __ bind(&post_instantiation_deopt_entry);

  // Restore new target.
  __ Pop(r5);

  // Push the allocated receiver to the stack.
  __ Push(r2);
  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in r6
  // since r0 needs to store the number of arguments before
  // InvokingFunction.
  __ mov(r8, r2);

  // Set up pointer to first argument (skip receiver).
  __ la(r6, MemOperand(fp, StandardFrameConstants::kCallerSPOffset +
                               kSystemPointerSize));

  // ----------- S t a t e -------------
  //  --                 r5: new target
  //  -- sp[0*kSystemPointerSize]: implicit receiver
  //  -- sp[1*kSystemPointerSize]: implicit receiver
  //  -- sp[2*kSystemPointerSize]: padding
  //  -- sp[3*kSystemPointerSize]: constructor function
  //  -- sp[4*kSystemPointerSize]: number of arguments
  //  -- sp[5*kSystemPointerSize]: context
  // -----------------------------------

  // Restore constructor function and argument count.
  __ LoadU64(r3, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ LoadU64(r2, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  Label stack_overflow;
  __ StackOverflowCheck(r2, r7, &stack_overflow);

  // Copy arguments and receiver to the expression stack.
  // r6: Pointer to start of argument.
  // r2: Number of arguments.
  Generate_PushArguments(masm, r6, r2, r1, ArgumentsElementType::kRaw);

  // Push implicit receiver.
  __ Push(r8);

  // Call the function.
  __ InvokeFunctionWithNewTarget(r3, r5, r2, InvokeType::kCall);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(r2, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ LoadU64(r2, MemOperand(sp));
  __ JumpIfRoot(r2, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore arguments count from the frame.
  __ LoadU64(r3, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(r3);
  __ Ret();

  __ bind(&check_receiver);
  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(r2, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CompareObjectType(r2, r6, r6, FIRST_JS_RECEIVER_TYPE);
  __ bge(&leave_and_return);
  __ b(&use_receiver);

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ bkpt(0);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ LoadU64(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ bkpt(0);
}

void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the value to pass to the generator
  //  -- r3 : the JSGeneratorObject to resume
  //  -- lr : return address
  // -----------------------------------
  // Store input value into generator object.
  __ StoreTaggedField(
      r2, FieldMemOperand(r3, JSGeneratorObject::kInputOrDebugPosOffset), r0);
  __ RecordWriteField(r3, JSGeneratorObject::kInputOrDebugPosOffset, r2, r5,
                      kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that r3 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(r3);

  // Load suspended function and context.
  __ LoadTaggedField(r6,
                     FieldMemOperand(r3, JSGeneratorObject::kFunctionOffset));
  __ LoadTaggedField(cp, FieldMemOperand(r6, JSFunction::kContextOffset));

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  Register scratch = r7;

  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ Move(scratch, debug_hook);
  __ LoadS8(scratch, MemOperand(scratch));
  __ CmpSmiLiteral(scratch, Smi::zero(), r0);
  __ bne(&prepare_step_in_if_stepping);

  // Flood function if we need to continue stepping in the suspended generator.

  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());

  __ Move(scratch, debug_suspended_generator);
  __ LoadU64(scratch, MemOperand(scratch));
  __ CmpS64(scratch, r3);
  __ beq(&prepare_step_in_suspended_generator);
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadU64(scratch,
             __ StackLimitAsMemOperand(StackLimitKind::kRealStackLimit));
  __ CmpU64(sp, scratch);
  __ blt(&stack_overflow);

  // ----------- S t a t e -------------
  //  -- r3    : the JSGeneratorObject to resume
  //  -- r6    : generator function
  //  -- cp    : generator context
  //  -- lr    : return address
  // -----------------------------------

  // Copy the function arguments from the generator object's register file.
  __ LoadTaggedField(
      r5, FieldMemOperand(r6, JSFunction::kSharedFunctionInfoOffset));
  __ LoadU16(
      r5, FieldMemOperand(r5, SharedFunctionInfo::kFormalParameterCountOffset));
  __ SubS64(r5, r5, Operand(kJSArgcReceiverSlots));
  __ LoadTaggedField(
      r4,
      FieldMemOperand(r3, JSGeneratorObject::kParametersAndRegistersOffset));
  {
    Label done_loop, loop;
    __ bind(&loop);
    __ SubS64(r5, r5, Operand(1));
    __ blt(&done_loop);
    __ ShiftLeftU64(r1, r5, Operand(kTaggedSizeLog2));
    __ la(scratch, MemOperand(r4, r1));
    __ LoadTaggedField(
        scratch, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
    __ Push(scratch);
    __ b(&loop);
    __ bind(&done_loop);

    // Push receiver.
    __ LoadTaggedField(scratch,
                       FieldMemOperand(r3, JSGeneratorObject::kReceiverOffset));
    __ Push(scratch);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label is_baseline, is_unavailable, ok;
    __ LoadTaggedField(
        r5, FieldMemOperand(r6, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, r5, r5, ip, &is_baseline,
                                            &is_unavailable);
    __ jmp(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ CompareObjectType(r5, r5, r5, CODE_TYPE);
    __ Assert(eq, AbortReason::kMissingBytecodeArray);

    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ LoadTaggedField(
        r2, FieldMemOperand(r6, JSFunction::kSharedFunctionInfoOffset));
    __ LoadS16(r2, FieldMemOperand(
                       r2, SharedFunctionInfo::kFormalParameterCountOffset));
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ mov(r5, r3);
    __ mov(r3, r6);
    __ JumpJSFunction(r3);
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r3, r6);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(r3);
    __ LoadTaggedField(r6,
                       FieldMemOperand(r3, JSGeneratorObject::kFunctionOffset));
  }
  __ b(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(r3);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(r3);
    __ LoadTaggedField(r6,
                       FieldMemOperand(r3, JSGeneratorObject::kFunctionOffset));
  }
  __ b(&stepping_prepared);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ bkpt(0);  // This should be unreachable.
  }
}

void Builtins::Generate_ConstructedNonConstructable(MacroAssembler* masm) {
  FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
  __ push(r3);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
  __ Trap();  // Unreachable.
}

namespace {

constexpr int kPushedStackSpace =
    (kNumCalleeSaved + 2) * kSystemPointerSize +
    kNumCalleeSavedDoubles * kDoubleSize + 7 * kSystemPointerSize +
    EntryFrameConstants::kNextFastCallFramePCOffset - kSystemPointerSize;

// Called with the native C calling convention. The corresponding function
// signature is either:
//
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, Address new_target, Address target,
//       Address receiver, intptr_t argc, Address** args)>;
// or
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, MicrotaskQueue* microtask_queue)>;
void Generate_JSEntryVariant(MacroAssembler* masm, StackFrame::Type type,
                             Builtin entry_trampoline) {
  // The register state is either:
  //   r2:                             root register value
  //   r3:                             code entry
  //   r4:                             function
  //   r5:                             receiver
  //   r6:                             argc
  //   [sp + 20 * kSystemPointerSize]: argv
  // or
  //   r2: root_register_value
  //   r3: microtask_queue

  Label invoke, handler_entry, exit;

#if V8_OS_ZOS
  const int stack_space = 12 * kSystemPointerSize;

  // Store r4 - r15 to Stack
  __ StoreMultipleP(r4, sp, MemOperand(r4, kStackPointerBias - stack_space));
  // Grow stack
  __ lay(r4, MemOperand(r4, -stack_space));

  // Shuffle input XPLINK register arguments to match LoZ
  __ mov(sp, r4);
  __ mov(r4, r3);
  __ mov(r3, r2);
  __ mov(r2, r1);

  // Load args 4 and 5 from XPLINK extra frame slots in r5 and r6
  __ LoadMultipleP(
      r5, r6,
      MemOperand(sp, kStackPointerBias +
                         kXPLINKStackFrameExtraParamSlot * kSystemPointerSize +
                         stack_space));

  // Load arg 6 from XPLINK extra arg slot
  __ LoadU64(r0, MemOperand(sp, kStackPointerBias +
                                    kXPLINKStackFrameExtraParamSlot *
                                        kSystemPointerSize +
                                    stack_space + 2 * kSystemPointerSize));

  // Store arg 6 to expected LoZ save area
  __ StoreU64(r0, MemOperand(sp, kCalleeRegisterSaveAreaSize));
#endif

  int pushed_stack_space = 0;
  {
    NoRootArrayScope no_root_array(masm);

    // saving floating point registers
    // 64bit ABI requires f8 to f15 be saved
    // http://refspecs.linuxbase.org/ELF/zSeries/lzsabi0_zSeries.html
    __ lay(sp, MemOperand(sp, -8 * kDoubleSize));
    __ std(d8, MemOperand(sp));
    __ std(d9, MemOperand(sp, 1 * kDoubleSize));
    __ std(d10, MemOperand(sp, 2 * kDoubleSize));
    __ std(d11, MemOperand(sp, 3 * kDoubleSize));
    __ std(d12, MemOperand(sp, 4 * kDoubleSize));
    __ std(d13, MemOperand(sp, 5 * kDoubleSize));
    __ std(d14, MemOperand(sp, 6 * kDoubleSize));
    __ std(d15, MemOperand(sp, 7 * kDoubleSize));
    pushed_stack_space += kNumCalleeSavedDoubles * kDoubleSize;

    // zLinux ABI
    //    Incoming parameters:
    //          r2: root register value
    //          r3: code entry
    //          r4: function
    //          r5: receiver
    //          r6: argc
    // [sp + 20 * kSystemPointerSize]: argv
    //    Requires us to save the callee-preserved registers r6-r13
    //    General convention is to also save r14 (return addr) and
    //    sp/r15 as well in a single STM/STMG
    __ lay(sp, MemOperand(sp, -10 * kSystemPointerSize));
    __ StoreMultipleP(r6, sp, MemOperand(sp, 0));
    pushed_stack_space += (kNumCalleeSaved + 2) * kSystemPointerSize;

    // Initialize the root register.
    // C calling convention. The first argument is passed in r2.
    __ mov(kRootRegister, r2);
  }

  // Push a frame with special values setup to mark it as an entry frame.
  //   Bad FP (-1)
  //   SMI Marker
  //   SMI Marker
  //   kCEntryFPAddress
  //   Frame type
  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  pushed_stack_space += 7 * kSystemPointerSize;

  // Push a bad frame pointer to fail if it is used.
  __ mov(r0, Operand(-1));
  __ push(r0);

  __ mov(r0, Operand(StackFrame::TypeToMarker(type)));
  __ push(r0);
  __ push(r0);

  __ mov(r0, Operand::Zero());
  __ Move(ip, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                        masm->isolate()));
  __ LoadU64(r9, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r9);

  __ LoadIsolateField(ip, IsolateFieldId::kFastCCallCallerFP);
  __ LoadU64(r9, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r9);

  __ LoadIsolateField(ip, IsolateFieldId::kFastCCallCallerPC);
  __ LoadU64(r9, MemOperand(ip));
  __ StoreU64(r0, MemOperand(ip));
  __ push(r9);

#ifdef V8_COMPRESS_POINTERS_IN_SHARED_CAGE
  // Initialize the pointer cage base register.
  __ LoadRootRelative(kPtrComprCageBaseRegister,
                      IsolateData::cage_base_offset());
#endif

  Register scrach = r8;

  // Set up frame pointer for the frame to be pushed.
  __ lay(fp, MemOperand(sp, -EntryFrameConstants::kNextFastCallFramePCOffset));
  pushed_stack_space +=
      EntryFrameConstants::kNextFastCallFramePCOffset - kSystemPointerSize;

  // If this is the outermost JS call, set js_entry_sp value.
  Label non_outermost_js;
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ Move(r7, js_entry_sp);
  __ LoadAndTestP(scrach, MemOperand(r7));
  __ bne(&non_outermost_js, Label::kNear);
  __ StoreU64(fp, MemOperand(r7));
  __ mov(scrach, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  Label cont;
  __ b(&cont, Label::kNear);
  __ bind(&non_outermost_js);
  __ mov(scrach, Operand(StackFrame::INNER_JSENTRY_FRAME));

  __ bind(&cont);
  __ push(scrach);  // frame-type

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ b(&invoke, Label::kNear);

  __ bind(&handler_entry);

  // Store the current pc as the handler offset. It's used later to create the
  // handler table.
  masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

  // Caught exception: Store result (exception) in the exception
  // field in the JSEnv and return a failure sentinel.  Coming in here the
  // fp will be invalid because the PushStackHandler below sets it to 0 to
  // signal the existence of the JSEntry frame.
  __ Move(scrach, ExternalReference::Create(IsolateAddressId::kExceptionAddress,
                                            masm->isolate()));

  __ StoreU64(r2, MemOperand(scrach));
  __ LoadRoot(r2, RootIndex::kException);
  __ b(&exit, Label::kNear);

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  // Must preserve r2-r6.
  __ PushStackHandler();
  // If an exception not caught by another handler occurs, this handler
  // returns control to the code after the b(&invoke) above, which
  // restores all kCalleeSaved registers (including cp and fp) to their
  // saved values before returning a failure to C.

  // Invoke the function by calling through JS entry trampoline builtin.
  // Notice that we cannot store a reference to the trampoline code directly in
  // this stub, because runtime stubs are not traversed when doing GC.

  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  USE(pushed_stack_space);
  DCHECK_EQ(kPushedStackSpace, pushed_stack_space);
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();
  __ bind(&exit);  // r2 holds result

  // Check if the current stack frame is marked as the outermost JS frame.
  Label non_outermost_js_2;
  __ pop(r7);
  __ CmpS64(r7, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ bne(&non_outermost_js_2, Label::kNear);
  __ mov(scrach, Operand::Zero());
  __ Move(r7, js_entry_sp);
  __ StoreU64(scrach, MemOperand(r7));
  __ bind(&non_outermost_js_2);

  // Restore the top frame descriptors from the stack.
  __ pop(r5);
  __ LoadIsolateField(scrach, IsolateFieldId::kFastCCallCallerPC);
  __ StoreU64(r5, MemOperand(scrach));

  __ pop(r5);
  __ LoadIsolateField(scrach, IsolateFieldId::kFastCCallCallerFP);
  __ StoreU64(r5, MemOperand(scrach));

  __ pop(r5);
  __ Move(scrach, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                            masm->isolate()));
  __ StoreU64(r5, MemOperand(scrach));

  // Reset the stack to the callee saved registers.
  __ lay(sp, MemOperand(sp, -EntryFrameConstants::kNextExitFrameFPOffset));

  // Reload callee-saved preserved regs, return address reg (r14) and sp
  __ LoadMultipleP(r6, sp, MemOperand(sp, 0));
  __ la(sp, MemOperand(sp, 10 * kSystemPointerSize));

  // 64bit ABI requires f8 to f15 be saved
  __ ld(d8, MemOperand(sp));
  __ ld(d9, MemOperand(sp, 1 * kDoubleSize));
  __ ld(d10, MemOperand(sp, 2 * kDoubleSize));
  __ ld(d11, MemOperand(sp, 3 * kDoubleSize));
  __ ld(d12, MemOperand(sp, 4 * kDoubleSize));
  __ ld(d13, MemOperand(sp, 5 * kDoubleSize));
  __ ld(d14, MemOperand(sp, 6 * kDoubleSize));
  __ ld(d15, MemOperand(sp, 7 * kDoubleSize));
  __ la(sp, MemOperand(sp, 8 * kDoubleSize));

#if V8_OS_ZOS
  // On z/OS, the return register is r3
  __ mov(r3, r2);
  // Restore r4 - r15 from Stack
  __ LoadMultipleP(r4, sp, MemOperand(sp, kStackPointerBias));
  __ b(r7);
#else
  __ b(r14);
#endif
}

}  // namespace

void Builtins::Generate_JSEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::ENTRY, Builtin::kJSEntryTrampoline);
}

void Builtins::Generate_JSConstructEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::CONSTRUCT_ENTRY,
                          Builtin::kJSConstructEntryTrampoline);
}

void Builtins::Generate_JSRunMicrotasksEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::ENTRY,
                          Builtin::kRunMicrotasksTrampoline);
}

static void Generate_JSEntryTrampolineHelper(MacroAssembler* masm,
                                             bool is_construct) {
  // Called from Generate_JS_Entry
  // r3: new.target
  // r4: function
  // r5: receiver
  // r6: argc
  // [fp + kPushedStackSpace + 20 * kSystemPointerSize]: argv
  // r0,r2,r7-r8, cp may be clobbered

  __ mov(r2, r6);
  // Load argv from the stack.
  __ LoadU64(
      r6, MemOperand(fp, kPushedStackSpace + EntryFrameConstants::kArgvOffset));

  // r2: argc
  // r3: new.target
  // r4: function
  // r5: receiver
  // r6: argv

  // Enter an internal frame.
  {
    // FrameScope ends up calling MacroAssembler::EnterFrame here
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ Move(cp, context_address);
    __ LoadU64(cp, MemOperand(cp));

    // Push the function
    __ Push(r4);

    // Check if we have enough stack space to push all arguments.
    Label enough_stack_space, stack_overflow;
    __ mov(r7, r2);
    __ StackOverflowCheck(r7, r1, &stack_overflow);
    __ b(&enough_stack_space);
    __ bind(&stack_overflow);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);

    __ bind(&enough_stack_space);

    // Copy arguments to the stack from argv to sp.
    // The arguments are actually placed in reverse order on sp
    // compared to argv (i.e. arg1 is highest memory in sp).
    // r2: argc
    // r3: function
    // r5: new.target
    // r6: argv, i.e. points to first arg
    // r7: scratch reg to hold scaled argc
    // r8: scratch reg to hold arg handle
    Generate_PushArguments(masm, r6, r2, r1, ArgumentsElementType::kHandle);

    // Push the receiver.
    __ Push(r5);

    // Setup new.target, argc and function.
    __ mov(r5, r3);
    __ mov(r3, r4);
    // r2: argc
    // r3: function
    // r5: new.target

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    __ LoadRoot(r4, RootIndex::kUndefinedValue);
    __ mov(r6, r4);
    __ mov(r7, r6);
    __ mov(r8, r6);

    // Invoke the code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Exit the JS frame and remove the parameters (except function), and
    // return.
  }
  __ b(r14);

  // r2: result
}

void Builtins::Generate_JSEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, false);
}

void Builtins::Generate_JSConstructEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, true);
}

void Builtins::Generate_RunMicrotasksTrampoline(MacroAssembler* masm) {
  // This expects two C++ function parameters passed by Invoke() in
  // execution.cc.
  //   r2: root_register_value
  //   r3: microtask_queue

  __ mov(RunMicrotasksDescriptor::MicrotaskQueueRegister(), r3);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  Register params_size = scratch1;
  // Get the size of the formal parameters + receiver (in bytes).
  __ LoadU64(params_size,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadU16(params_size,
             FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ LoadU64(actual_params_size,
             MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  Label corrected_args_count;
  __ CmpS64(params_size, actual_params_size);
  __ bge(&corrected_args_count);
  __ mov(params_size, actual_params_size);
  __ bind(&corrected_args_count);

  // Leave the frame (also dropping the register file).
  __ LeaveFrame(StackFrame::INTERPRETED);

  __ DropArguments(params_size);
}

// Advance the current bytecode offset. This simulates what all bytecode
// handlers do upon completion of the underlying operation. Will bail out to a
// label if the bytecode (without prefix) is a return bytecode. Will not advance
// the bytecode offset if the current bytecode is a JumpLoop, instead just
// re-executing the JumpLoop to jump to the correct bytecode.
static void AdvanceBytecodeOffsetOrReturn(MacroAssembler* masm,
                                          Register bytecode_array,
                                          Register bytecode_offset,
                                          Register bytecode, Register scratch1,
                                          Register scratch2, Label* if_return) {
  Register bytecode_size_table = scratch1;
  Register scratch3 = bytecode;

  // The bytecode offset value will be increased by one in wide and extra wide
  // cases. In the case of having a wide or extra wide JumpLoop bytecode, we
  // will restore the original bytecode. In order to simplify the code, we have
  // a backup of it.
  Register original_bytecode_offset = scratch2;
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode_size_table,
                     bytecode, original_bytecode_offset));
  __ Move(bytecode_size_table,
          ExternalReference::bytecode_size_table_address());
  __ Move(original_bytecode_offset, bytecode_offset);

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ CmpS64(bytecode, Operand(0x3));
  __ bgt(&process_bytecode);
  __ tmll(bytecode, Operand(0x1));
  __ bne(&extra_wide);

  // Load the next bytecode and update table to the wide scaled table.
  __ AddS64(bytecode_offset, bytecode_offset, Operand(1));
  __ LoadU8(bytecode, MemOperand(bytecode_array, bytecode_offset));
  __ AddS64(bytecode_size_table, bytecode_size_table,
            Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ b(&process_bytecode);

  __ bind(&extra_wide);
  // Load the next bytecode and update table to the extra wide scaled table.
  __ AddS64(bytecode_offset, bytecode_offset, Operand(1));
  __ LoadU8(bytecode, MemOperand(bytecode_array, bytecode_offset));
  __ AddS64(bytecode_size_table, bytecode_size_table,
            Operand(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  // Load the size of the current bytecode.
  __ bind(&process_bytecode);

  // Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)                                             \
  __ CmpS64(bytecode,                                                   \
            Operand(static_cast<int>(interpreter::Bytecode::k##NAME))); \
  __ beq(if_return);
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ CmpS64(bytecode,
            Operand(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ bne(&not_jump_loop);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ b(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ LoadU8(scratch3, MemOperand(bytecode_size_table, bytecode));
  __ AddS64(bytecode_offset, bytecode_offset, scratch3);

  __ bind(&end);
}

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  // UseScratchRegisterScope temps(masm);
  // Need a few extra registers
  // temps.Include(r8, r9);

  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  Register feedback_cell = r6;
  Register feedback_vector = ip;
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  __ AssertFeedbackVector(feedback_vector, r1);

  // Check for an tiering state.
  Label flags_need_processing;
  Register flags = r8;
  {
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
  }

  {
    UseScratchRegisterScope temps(masm);
    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, r1);
  }

  // Increment invocation count for the function.
  {
    Register invocation_count = r1;
    __ LoadU32(invocation_count,
               FieldMemOperand(feedback_vector,
                               FeedbackVector::kInvocationCountOffset));
    __ AddU32(invocation_count, Operand(1));
    __ StoreU32(invocation_count,
                FieldMemOperand(feedback_vector,
                                FeedbackVector::kInvocationCountOffset));
  }

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  {
    ASM_CODE_COMMENT_STRING(masm, "Frame Setup");
    // Normally the first thing we'd do here is Push(lr, fp), but we already
    // entered the frame in BaselineCompiler::Prologue, as we had to use the
    // value lr before the call to this BaselineOutOfLinePrologue builtin.

    Register callee_context = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kCalleeContext);
    Register callee_js_function = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kClosure);
    ResetJSFunctionAge(masm, callee_js_function, r1, r0);
    __ Push(callee_context, callee_js_function);
    DCHECK_EQ(callee_js_function, kJavaScriptCallTargetRegister);
    DCHECK_EQ(callee_js_function, kJSFunctionRegister);

    Register argc = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kJavaScriptCallArgCount);
    // We'll use the bytecode for both code age/OSR resetting, and pushing onto
    // the frame, so load it into a register.
    Register bytecodeArray = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kInterpreterBytecodeArray);

    __ Push(argc, bytecodeArray);

    if (v8_flags.debug_code) {
      Register scratch = r1;
      __ CompareObjectType(feedback_vector, scratch, scratch,
                           FEEDBACK_VECTOR_TYPE);
      __ Assert(eq, AbortReason::kExpectedFeedbackVector);
    }
    __ Push(feedback_cell);
    __ Push(feedback_vector);
  }

  Label call_stack_guard;
  Register frame_size = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kStackFrameSize);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt check");
    // Stack check. This folds the checks for both the interrupt stack limit
    // check and the real stack limit into one by just checking for the
    // interrupt limit. The interrupt limit is either equal to the real stack
    // limit or tighter. By ensuring we have space until that limit after
    // building the frame we can quickly precheck both at once.

    Register sp_minus_frame_size = r1;
    Register interrupt_limit = r0;
    __ SubS64(sp_minus_frame_size, sp, frame_size);
    __ LoadStackLimit(interrupt_limit, StackLimitKind::kInterruptStackLimit);
    __ CmpU64(sp_minus_frame_size, interrupt_limit);
    __ blt(&call_stack_guard);
  }

  // Do "fast" return to the caller pc in lr.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");

    // Drop the frame created by the baseline call.
    __ Pop(r14, fp);
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
    __ Trap();
  }

  __ bind(&call_stack_guard);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt call");
    FrameScope frame_scope(masm, StackFrame::INTERNAL);
    // Save incoming new target or generator
    __ Push(kJavaScriptCallNewTargetRegister);
    __ SmiTag(frame_size);
    __ Push(frame_size);
    __ CallRuntime(Runtime::kStackGuardWithGap);
    __ Pop(kJavaScriptCallNewTargetRegister);
  }

  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop the feedback vector, the bytecode offset (was the feedback vector but
  // got replaced during deopt) and bytecode array.
  __ Drop(3);

  // Context, closure, argc.
  __ Pop(kContextRegister, kJavaScriptCallTargetRegister,
         kJavaScriptCallArgCountRegister);

  // Drop frame pointer
  __ LeaveFrame(StackFrame::BASELINE);

  // Enter the interpreter.
  __ TailCallBuiltin(Builtin::kInterpreterEntryTrampoline);
}

// Generate code for entering a JS function with the interpreter.
// On entry to the function the receiver and arguments have been pushed on the
// stack left to right.
//
// The live registers are:
//   o r2: actual argument count
//   o r3: the JS function object being called.
//   o r5: the incoming new target or generator object
//   o cp: our context
//   o pp: the caller's constant pool pointer (if enabled)
//   o fp: the caller's frame pointer
//   o sp: stack pointer
//   o lr: return address
//
// The function builds an interpreter frame.  See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = r3;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  __ LoadTaggedField(
      r6, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, r6, ip);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(masm, r6,
                                          kInterpreterBytecodeArrayRegister, ip,
                                          &is_baseline, &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = r4;
  __ LoadFeedbackVector(feedback_vector, closure, r6, &push_stack_frame);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count.

  Register flags = r6;
  Label flags_need_processing;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);

    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, r1);

  // Increment invocation count for the function.
  __ LoadS32(r1, FieldMemOperand(feedback_vector,
                                 FeedbackVector::kInvocationCountOffset));
  __ AddS64(r1, r1, Operand(1));
  __ StoreU32(r1, FieldMemOperand(feedback_vector,
                                  FeedbackVector::kInvocationCountOffset));

  // Open a frame scope to indicate that there is a frame on the stack.  The
  // MANUAL indicates that the scope shouldn't actually generate code to set up
  // the frame (that is done below).

#else
  // Note: By omitting the above code in jitless mode we also disable:
  // - kFlagsLogNextExecution: only used for logging/profiling; and
  // - kInvocationCountOffset: only used for tiering heuristics and code
  //   coverage.
#endif  // !V8_JITLESS

  __ bind(&push_stack_frame);
  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ PushStandardFrame(closure);

  // Load the initial bytecode offset.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Push bytecode array and Smi tagged bytecode array offset.
  __ SmiTag(r0, kInterpreterBytecodeOffsetRegister);
  __ Push(kInterpreterBytecodeArrayRegister, r0, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size (word) from the BytecodeArray object.
    __ LoadU32(r4, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                                   BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ SubS64(r8, sp, r4);
    __ CmpU64(r8, __ StackLimitAsMemOperand(StackLimitKind::kRealStackLimit));
    __ blt(&stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    Label loop, no_args;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ ShiftRightU64(r4, r4, Operand(kSystemPointerSizeLog2));
    __ LoadAndTestP(r4, r4);
    __ beq(&no_args);
    __ mov(r1, r4);
    __ bind(&loop);
    __ push(kInterpreterAccumulatorRegister);
    __ SubS64(r1, Operand(1));
    __ bne(&loop);
    __ bind(&no_args);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in r5.
  Label no_incoming_new_target_or_generator_register;
  __ LoadS32(r8,
             FieldMemOperand(
                 kInterpreterBytecodeArrayRegister,
                 BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ CmpS64(r8, Operand::Zero());
  __ beq(&no_incoming_new_target_or_generator_register);
  __ ShiftLeftU64(r8, r8, Operand(kSystemPointerSizeLog2));
  __ StoreU64(r5, MemOperand(fp, r8));
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadU64(r0,
             __ StackLimitAsMemOperand(StackLimitKind::kInterruptStackLimit));
  __ CmpU64(sp, r0);
  __ blt(&stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  __ LoadU8(r5, MemOperand(kInterpreterBytecodeArrayRegister,
                           kInterpreterBytecodeOffsetRegister));
  __ ShiftLeftU64(r5, r5, Operand(kSystemPointerSizeLog2));
  __ LoadU64(kJavaScriptCallCodeStartRegister,
             MemOperand(kInterpreterDispatchTableRegister, r5));
  __ Call(kJavaScriptCallCodeStartRegister);

  __ RecordComment("--- InterpreterEntryReturnPC point ---");
  if (mode == InterpreterEntryTrampolineMode::kDefault) {
    masm->isolate()->heap()->SetInterpreterEntryReturnPCOffset(
        masm->pc_offset());
  } else {
    DCHECK_EQ(mode, InterpreterEntryTrampolineMode::kForProfiling);
    // Both versions must be the same up to this point otherwise the builtins
    // will not be interchangable.
    CHECK_EQ(
        masm->isolate()->heap()->interpreter_entry_return_pc_offset().value(),
        masm->pc_offset());
  }

  // Any returns to the entry trampoline are either due to the return bytecode
  // or the interpreter tail calling a builtin and then a dispatch.

  // Get bytecode array and bytecode offset from the stack frame.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadU64(kInterpreterBytecodeOffsetRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ LoadU8(r3, MemOperand(kInterpreterBytecodeArrayRegister,
                           kInterpreterBytecodeOffsetRegister));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, r3, r4, r5,
                                &do_return);
  __ b(&do_dispatch);

  __ bind(&do_return);
  // The return value is in r2.
  LeaveInterpreterFrame(masm, r4, r6);
  __ Ret();

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                              kFunctionEntryBytecodeOffset)));
  __ StoreU64(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(r0, kInterpreterBytecodeOffsetRegister);
  __ StoreU64(r0,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);

  __ bind(&is_baseline);
  {
    // Load the feedback vector from the closure.
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
    __ LoadTaggedField(
        feedback_vector,
        FieldMemOperand(feedback_vector, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ LoadTaggedField(
        ip, FieldMemOperand(feedback_vector, HeapObject::kMapOffset));
    __ LoadU16(ip, FieldMemOperand(ip, Map::kInstanceTypeOffset));
    __ CmpS32(ip, Operand(FEEDBACK_VECTOR_TYPE));
    __ b(ne, &install_baseline_code);

    // Check for an tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

#ifndef V8_ENABLE_LEAPTIERING
    // TODO(olivf, 42204201): This fastcase is difficult to support with the
    // sandbox as it requires getting write access to the dispatch table. See
    // `JSFunction::UpdateCode`. We might want to remove it for all
    // configurations as it does not seem to be performance sensitive.

    // Load the baseline code into the closure.
    __ mov(r4, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == r4, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(r4, closure, ip, r1);
    __ JumpCodeObject(r4);

#endif  // V8_ENABLE_LEAPTIERING

    __ bind(&install_baseline_code);
    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&compile_lazy);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ bkpt(0);  // Should not return.
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm, Register num_args,
                                        Register start_address,
                                        Register scratch) {
  ASM_CODE_COMMENT(masm);
  __ SubS64(scratch, num_args, Operand(1));
  __ ShiftLeftU64(scratch, scratch, Operand(kSystemPointerSizeLog2));
  __ SubS64(start_address, start_address, scratch);
  // Push the arguments.
  __ PushArray(start_address, num_args, r1, scratch,
               MacroAssembler::PushArrayOrder::kReverse);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r4 : the address of the first argument to be pushed. Subsequent
  //          arguments should be consecutive above this, in the same order as
  //          they are to be pushed onto the stack.
  //  -- r3 : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ SubS64(r2, r2, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ SubS64(r5, r2, Operand(kJSArgcReceiverSlots));
  } else {
    __ mov(r5, r2);
  }

  __ StackOverflowCheck(r5, ip, &stack_overflow);

  // Push the arguments.
  GenerateInterpreterPushArgs(masm, r5, r4, r6);

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r2.
    // r2 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ LoadU64(r4, MemOperand(r4, -kSystemPointerSize));
  }

  // Call the target.
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ TailCallBuiltin(Builtin::kCallWithSpread);
  } else {
    __ TailCallBuiltin(Builtins::Call(receiver_mode));
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable Code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  // -- r2 : argument count
  // -- r5 : new target
  // -- r3 : constructor to call
  // -- r4 : allocation site feedback if available, undefined otherwise.
  // -- r6 : address of the first argument
  // -----------------------------------
  Label stack_overflow;
  __ StackOverflowCheck(r2, ip, &stack_overflow);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ SubS64(r2, r2, Operand(1));
  }

  Register argc_without_receiver = ip;
  __ SubS64(argc_without_receiver, r2, Operand(kJSArgcReceiverSlots));
  // Push the arguments. r4 and r5 will be modified.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r6, r7);

  // Push a slot for the receiver to be constructed.
  __ mov(r0, Operand::Zero());
  __ push(r0);

  if (mode == InterpreterPushArgsMode::kWithFi
```
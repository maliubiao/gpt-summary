Response:
Let's break down the thought process for analyzing the given C++ code snippet.

**1. Initial Skim and Keyword Spotting:**

The first step is to quickly scan the code, looking for recognizable keywords and patterns. This helps to get a general sense of what the code is doing. Some of the immediately noticeable elements are:

* `#if V8_TARGET_ARCH_LOONG64`: This strongly suggests architecture-specific code, targeting the LoongArch 64-bit architecture.
* `#include`:  Indicates inclusion of various V8 header files. These filenames hint at different areas of V8 (API, builtins, codegen, debugging, deoptimization, execution, heap, objects, runtime, wasm).
* `namespace v8 { namespace internal {`:  Confirms this is internal V8 code.
* `Builtins::Generate_...`: This is a very strong signal that the code is generating machine code for built-in JavaScript functions.
* `MacroAssembler`:  This class is the core tool for generating assembly instructions within V8.
* `FrameScope`:  Deals with setting up and tearing down stack frames.
* `Push`, `Pop`, `Ld_d`, `St_d`, `Add_d`, `Sub_d`, `Branch`, `CallBuiltin`, `CallRuntime`: These are assembly instruction mnemonics (or abstractions of them via the `MacroAssembler`).
* Comments like `// ----------- S t a t e -------------` and  `// Registers:`: These describe the register and stack state at different points in the generated code, which is crucial for understanding the logic.
* Specific builtin names like `Builtins::Adaptor`, `Builtins::JSConstructStubGeneric`, `Builtins::ResumeGeneratorTrampoline`, `Builtins::JSEntry`, etc.: These point to different built-in functionalities.

**2. Understanding the Core Functionality (Based on `Generate_` prefixes):**

The prevalence of `Generate_` strongly indicates code generation. The names of the functions after `Generate_` suggest different built-in functions or code stubs being created.

* `Adaptor`:  Likely an intermediary to adapt calls.
* `PushArguments`:  A utility function for pushing arguments onto the stack.
* `JSBuiltinsConstructStubHelper`, `JSConstructStubGeneric`, `JSBuiltinsConstructStub`:  Related to the `new` operator and constructor calls in JavaScript.
* `ResumeGeneratorTrampoline`:  Specifically for handling the resumption of JavaScript generator functions.
* `ConstructedNonConstructable`:  Deals with errors when trying to construct non-constructable objects.
* `CheckStackOverflow`:  A safety check to prevent stack exhaustion.
* `JSEntryVariant`, `JSEntry`, `JSConstructEntry`, `JSRunMicrotasksEntry`, `JSEntryTrampoline`, `JSConstructEntryTrampoline`, `RunMicrotasksTrampoline`:  These all seem to be related to the entry points into JavaScript execution from native code.
* `LeaveInterpreterFrame`:  Part of the process of exiting the V8 interpreter.
* `AdvanceBytecodeOffsetOrReturn`:  Logic for moving through bytecode instructions in the interpreter.

**3. Connecting to JavaScript Concepts:**

Based on the function names and the overall context of V8, we can start to relate these code generation functions to JavaScript features:

* **Constructors (`new`):**  The `JSConstructStub` family directly relates to how JavaScript's `new` operator works, including handling inheritance (`DerivedConstructor`), implicit receiver creation, and calling the constructor function.
* **Generators (`function*`):**  `ResumeGeneratorTrampoline` is clearly for the `next()` method and the internal mechanics of generators.
* **Function Calls:**  `JSEntry` and its variants handle the transition from native code (like browser APIs) to JavaScript functions. The trampoline functions are likely the low-level entry points.
* **Stack Management:**  `CheckStackOverflow` is a fundamental part of preventing runtime errors in any language with a call stack.
* **Error Handling:** `ConstructedNonConstructable` handles specific error scenarios.
* **Bytecode Interpretation:** `LeaveInterpreterFrame` and `AdvanceBytecodeOffsetOrReturn` are directly related to how V8's interpreter executes JavaScript bytecode.

**4. Analyzing Specific Code Blocks (Examples):**

Let's look at a few snippets in more detail:

* **`Generate_Adaptor`:**  It loads an address into a register and then does a `TailCallBuiltin`. This suggests it's a simple forwarding mechanism. The comment mentioning `Builtins::AdaptorWithBuiltinExitFrame` reinforces this.

* **`Generate_PushArguments`:** The loop and the memory access instructions (`Ld_d`, `Push`) clearly indicate that it's iterating through an array and pushing elements onto the stack. The `ArgumentsElementType` enum suggests different ways of handling the elements (raw or dereferenced as handles).

* **`Generate_JSConstructStubGeneric`:**  The setting up of a `CONSTRUCT` frame, the checks for `DerivedConstructor`, the call to `Builtin::kFastNewObject`, and the `InvokeFunctionWithNewTarget` all strongly point to the implementation of the `new` operator.

* **`Generate_ResumeGeneratorTrampoline`:** The storing of the input value, loading the function and context, and the final `JumpJSFunction` with the generator object as `new.target` perfectly match the semantics of resuming a generator.

* **`Generate_JSEntryVariant`:** The saving of registers, setting up the stack frame, handling exceptions (`handler_entry`), and calling the entry trampoline are the essential steps for entering JavaScript execution.

**5. Considering Edge Cases and Potential Errors:**

* **Stack Overflow:** The `Generate_CheckStackOverflow` function highlights a common programming error: exceeding the available stack space, especially with recursive calls or large numbers of arguments.

* **Incorrect Constructor Usage:**  `Generate_ConstructedNonConstructable` addresses the error of trying to use `new` on a function that isn't a constructor.

**6. Inferring Torque (based on the hint):**

The prompt mentions that if the filename ends in `.tq`, it's Torque. Since this file is `.cc`, it's C++. However, the prompt provides context about Torque. If this *were* a `.tq` file, it would be a higher-level language for defining built-ins, which then gets translated into C++ (and eventually assembly).

**7. Structuring the Explanation:**

Finally, organize the findings into a clear and structured explanation, covering the points requested in the prompt:

* **Overall Function:** Start with a high-level summary.
* **Relationship to JavaScript:** Explain how the C++ code implements JavaScript features.
* **JavaScript Examples:** Provide concrete examples to illustrate the connection.
* **Code Logic/Assumptions:** Explain specific code blocks with hypothetical inputs and outputs.
* **Common Errors:**  Give examples of programming errors this code helps prevent or handle.
* **Torque Mention:** Address the `.tq` filename possibility and its implications.

By following these steps, we can systematically analyze the given C++ code and arrive at a comprehensive understanding of its purpose and functionality within the V8 JavaScript engine.
This is the first part of the `v8/src/builtins/loong64/builtins-loong64.cc` file, which contains architecture-specific (LoongArch 64-bit) implementations of built-in JavaScript functions for the V8 engine.

Here's a breakdown of its functionality:

**Overall Function:**

This file provides the assembly code implementations for various built-in JavaScript functions and runtime functionalities specifically optimized for the LoongArch 64-bit architecture. It handles tasks like function calls, constructor calls, generator resumption, stack management, and entry/exit points for JavaScript execution.

**Key Functionalities Covered in this Part:**

1. **Function Adaptor (`Generate_Adaptor`):**
   - Provides a mechanism to transition from generic built-in function calls to specific C++ function implementations.
   - It sets up an external reference to the target C++ function's address and then performs a tail call to a generic adaptor built-in.

2. **Argument Handling (`Generate_PushArguments`):**
   - A helper function to efficiently push arguments onto the stack from an array-like structure.
   - It can handle pushing raw argument values or dereferencing handles (pointers to objects).

3. **Constructor Stubs (`Generate_JSBuiltinsConstructStubHelper`, `Generate_JSConstructStubGeneric`, `Generate_JSBuiltinsConstructStub`):**
   - Implements the logic for calling JavaScript constructors (`new` keyword).
   - `JSConstructStubGeneric` handles both ES5 constructor functions and ES6 class constructors.
   - It involves:
     - Setting up a construct frame on the stack.
     - Allocating a new receiver object (unless it's a derived class constructor).
     - Copying arguments to the stack.
     - Calling the constructor function.
     - Handling the return value (checking if it's an object).

4. **Generator Resumption (`Generate_ResumeGeneratorTrampoline`):**
   - Handles the process of resuming a suspended JavaScript generator function.
   - It involves:
     - Storing the input value into the generator object.
     - Loading the generator's function and context.
     - Checking for stack overflow.
     - Pushing arguments onto the stack (using "holes" as placeholders).
     - Jumping to the generator function's code (either in the interpreter or TurboFan).

5. **Handling Non-Constructable Calls (`Generate_ConstructedNonConstructable`):**
   - Provides an error handler when the `new` operator is used on a non-constructable function.

6. **Stack Overflow Checks (`Generate_CheckStackOverflow`):**
   - A utility function to check if there's enough stack space before making function calls, preventing stack overflow errors.

7. **JavaScript Entry Points (`Generate_JSEntryVariant`, `Generate_JSEntry`, `Generate_JSConstructEntry`, `Generate_JSRunMicrotasksEntry`, `Generate_JSEntryTrampoline`, `Generate_JSConstructEntryTrampoline`, `Generate_RunMicrotasksTrampoline`):**
   - Defines the entry points from native C++ code into JavaScript execution.
   - `JSEntryVariant` is a general helper.
   - `JSEntry` is the standard entry point for function calls.
   - `JSConstructEntry` is the entry point for constructor calls.
   - `JSRunMicrotasksEntry` is for running microtasks.
   - Trampoline functions (`JSEntryTrampoline`, `JSConstructEntryTrampoline`) act as low-level entry points that set up the necessary environment before calling the actual JavaScript function.

8. **Interpreter Frame Management (`LeaveInterpreterFrame`):**
   - Handles the process of exiting an interpreter frame, cleaning up the stack.

9. **Bytecode Offset Advancement (`AdvanceBytecodeOffsetOrReturn`):**
   - A utility function used within the interpreter to move to the next bytecode instruction or return from the function.

**Regarding `.tq` files and JavaScript relationship:**

- The prompt correctly states that if the file ended in `.tq`, it would be a **Torque** source file. Torque is a domain-specific language used within V8 to define built-in functions in a more declarative and type-safe way. Torque code is then compiled into C++ code (like the current file).
- Since `builtins-loong64.cc` is a `.cc` file, it contains the **generated C++ code** that implements the built-ins. This C++ code directly interacts with the V8 engine's internals, including the `MacroAssembler` to generate assembly instructions.

**JavaScript Examples (Illustrating Relationships):**

1. **Constructor Stubs (`Generate_JSConstructStubGeneric`):**
   ```javascript
   function MyClass(value) {
     this.value = value;
   }
   const instance = new MyClass(10); // This call would involve the construct stubs.
   ```

2. **Generator Resumption (`Generate_ResumeGeneratorTrampoline`):**
   ```javascript
   function* myGenerator() {
     yield 1;
     yield 2;
   }
   const gen = myGenerator();
   gen.next(); // First call
   gen.next(5); // Second call, passing a value (handled by the trampoline).
   ```

3. **JavaScript Entry Points (`Generate_JSEntry`):**
   ```javascript
   function myFunction(a, b) {
     return a + b;
   }
   myFunction(5, 3); // This function call would go through a JSEntry point.

   // Example with a constructor
   class AnotherClass {}
   new AnotherClass(); // This would go through a JSConstructEntry point.

   async function myAsyncFunction() {
     await Promise.resolve();
   }
   myAsyncFunction(); // Might involve specific entry points for async functions.
   ```

**Code Logic Inference (Example: `Generate_PushArguments`):**

**Assumption:** `array` points to the start of an array-like structure on the stack or in memory, `argc` holds the number of arguments (including the receiver), and elements need to be pushed onto the stack.

**Input:**
- `array`: A register holding the memory address of the first argument.
- `argc`: A register holding the integer value `n + 1` (where `n` is the number of actual arguments).
- `kJSArgcReceiverSlots`: A constant representing the number of slots for the receiver (usually 1).

**Output:**
- The `n` arguments (excluding the receiver) will be pushed onto the stack in reverse order.

**Logic:**
1. `scratch` is initialized to `argc - kJSArgcReceiverSlots`, representing the index of the last actual argument.
2. The loop iterates from the last argument down to the first.
3. Inside the loop:
   - `scratch2` calculates the memory address of the current argument using `array` and the current index `scratch`.
   - If `element_type` is `kHandle`, the value at that address is loaded, and then the value pointed to by that loaded value is pushed (dereferencing the handle).
   - If `element_type` is `kRaw`, the value at that address is directly pushed.
4. The loop continues until all arguments are pushed.

**User Common Programming Errors (Related to this code):**

1. **Stack Overflow:**  Calling functions recursively without a proper base case or with a very large number of arguments can lead to stack overflow. The `Generate_CheckStackOverflow` function attempts to prevent this, but excessive recursion can still cause issues.

   ```javascript
   function recursiveFunction(n) {
     if (n <= 0) {
       return;
     }
     recursiveFunction(n - 1); // Potential stack overflow if n is too large
   }
   recursiveFunction(10000); // Might cause a stack overflow
   ```

2. **Incorrect `this` binding in Constructors:** If a constructor doesn't properly initialize `this` or returns a non-object, it can lead to unexpected behavior. The constructor stubs handle the creation of the initial `this` object.

   ```javascript
   function BadConstructor() {
     // Forgetting to initialize properties on 'this'
     return 5; // Returning a primitive will be ignored in favor of the created 'this'
   }
   const badInstance = new BadConstructor();
   console.log(typeof badInstance); // Output: "object" (though the return was a number)
   ```

3. **Calling Non-Constructable Functions with `new`:**  Trying to use the `new` keyword with a regular function (not designed to be a constructor) will result in an error handled by `Generate_ConstructedNonConstructable`.

   ```javascript
   function regularFunction() {
     return 10;
   }
   // new regularFunction(); // This will throw a TypeError: regularFunction is not a constructor
   ```

**Summary of Part 1 Functionality:**

The first part of `v8/src/builtins/loong64/builtins-loong64.cc` lays the foundation for executing JavaScript code on the LoongArch 64-bit architecture. It provides essential low-level mechanisms for function calls (both regular and constructor calls), generator management, stack safety, and entry points into the JavaScript runtime. It's a crucial component for bridging the gap between the V8 engine's C++ core and the execution of JavaScript code.

Prompt: 
```
这是目录为v8/src/builtins/loong64/builtins-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/loong64/builtins-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_LOONG64

#include "src/api/api-arguments.h"
#include "src/builtins/builtins-descriptors.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/logging/counters.h"
// For interpreter_entry_return_pc_offset. TODO(jkummerow): Drop.
#include "src/codegen/loong64/constants-loong64.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/register-configuration.h"
#include "src/heap/heap-inl.h"
#include "src/objects/cell.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-generator.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/baseline/liftoff-assembler-defs.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
  __ li(kJavaScriptCallExtraArg1Register, ExternalReference::Create(address));
  __ TailCallBuiltin(
      Builtins::AdaptorWithBuiltinExitFrame(formal_parameter_count));
}

namespace {

enum class ArgumentsElementType {
  kRaw,    // Push arguments as they are.
  kHandle  // Dereference arguments before pushing.
};

void Generate_PushArguments(MacroAssembler* masm, Register array, Register argc,
                            Register scratch, Register scratch2,
                            ArgumentsElementType element_type) {
  DCHECK(!AreAliased(array, argc, scratch));
  Label loop, entry;
  __ Sub_d(scratch, argc, Operand(kJSArgcReceiverSlots));
  __ Branch(&entry);
  __ bind(&loop);
  __ Alsl_d(scratch2, scratch, array, kSystemPointerSizeLog2, t7);
  __ Ld_d(scratch2, MemOperand(scratch2, 0));
  if (element_type == ArgumentsElementType::kHandle) {
    __ Ld_d(scratch2, MemOperand(scratch2, 0));
  }
  __ Push(scratch2);
  __ bind(&entry);
  __ Add_d(scratch, scratch, Operand(-1));
  __ Branch(&loop, greater_equal, scratch, Operand(zero_reg));
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0     : number of arguments
  //  -- a1     : constructor function
  //  -- a3     : new target
  //  -- cp     : context
  //  -- ra     : return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  // Enter a construct frame.
  {
    FrameScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.
    __ Push(cp, a0);

    // Set up pointer to first argument (skip receiver).
    __ Add_d(
        t2, fp,
        Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));
    // Copy arguments and receiver to the expression stack.
    // t2: Pointer to start of arguments.
    // a0: Number of arguments.
    Generate_PushArguments(masm, t2, a0, t3, t0, ArgumentsElementType::kRaw);
    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // a0: number of arguments (untagged)
    // a1: constructor function
    // a3: new target
    __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);

    // Restore context from the frame.
    __ Ld_d(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ Ld_d(t3, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
    // Leave construct frame.
  }

  // Remove caller arguments from the stack and return.
  __ DropArguments(t3);
  __ Ret();
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  --      a0: number of arguments (untagged)
  //  --      a1: constructor function
  //  --      a3: new target
  //  --      cp: context
  //  --      ra: return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;
  __ EnterFrame(StackFrame::CONSTRUCT);

  // Preserve the incoming parameters on the stack.
  __ Push(cp, a0, a1);
  __ PushRoot(RootIndex::kUndefinedValue);
  __ Push(a3);

  // ----------- S t a t e -------------
  //  --        sp[0*kSystemPointerSize]: new target
  //  --        sp[1*kSystemPointerSize]: padding
  //  -- a1 and sp[2*kSystemPointerSize]: constructor function
  //  --        sp[3*kSystemPointerSize]: number of arguments
  //  --        sp[4*kSystemPointerSize]: context
  // -----------------------------------

  __ LoadTaggedField(
      t2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ Ld_wu(t2, FieldMemOperand(t2, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(t2);
  __ JumpIfIsInRange(
      t2, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);

  // If not derived class constructor: Allocate the new receiver object.
  __ CallBuiltin(Builtin::kFastNewObject);
  __ Branch(&post_instantiation_deopt_entry);

  // Else: use TheHoleValue as receiver for constructor call
  __ bind(&not_create_implicit_receiver);
  __ LoadRoot(a0, RootIndex::kTheHoleValue);

  // ----------- S t a t e -------------
  //  --                          a0: receiver
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
  __ Pop(a3);

  // Push the allocated receiver to the stack.
  __ Push(a0);

  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in a6
  // since a0 will store the return value of callRuntime.
  __ mov(a6, a0);

  // Set up pointer to last argument.
  __ Add_d(
      t2, fp,
      Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));

  // ----------- S t a t e -------------
  //  --                 r3: new target
  //  -- sp[0*kSystemPointerSize]: implicit receiver
  //  -- sp[1*kSystemPointerSize]: implicit receiver
  //  -- sp[2*kSystemPointerSize]: padding
  //  -- sp[3*kSystemPointerSize]: constructor function
  //  -- sp[4*kSystemPointerSize]: number of arguments
  //  -- sp[5*kSystemPointerSize]: context
  // -----------------------------------

  // Restore constructor function and argument count.
  __ Ld_d(a1, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ Ld_d(a0, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  Label stack_overflow;
  __ StackOverflowCheck(a0, t0, t1, &stack_overflow);

  // TODO(victorgomes): When the arguments adaptor is completely removed, we
  // should get the formal parameter count and copy the arguments in its
  // correct position (including any undefined), instead of delaying this to
  // InvokeFunction.

  // Copy arguments and receiver to the expression stack.
  // t2: Pointer to start of argument.
  // a0: Number of arguments.
  Generate_PushArguments(masm, t2, a0, t0, t1, ArgumentsElementType::kRaw);
  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments,
  __ Push(a6);

  // Call the function.
  __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(a0, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ Ld_d(a0, MemOperand(sp, 0 * kSystemPointerSize));
  __ JumpIfRoot(a0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore arguments count from the frame.
  __ Ld_d(a1, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(a1);
  __ Ret();

  __ bind(&check_receiver);
  __ JumpIfSmi(a0, &use_receiver);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(a0, t2, &leave_and_return);
  __ Branch(&use_receiver);

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ Ld_d(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ break_(0xCC);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ Ld_d(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ break_(0xCC);
}

void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

static void AssertCodeIsBaseline(MacroAssembler* masm, Register code,
                                 Register scratch) {
  DCHECK(!AreAliased(code, scratch));
  // Verify that the code kind is baseline code via the CodeKind.
  __ Ld_d(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ Assert(eq, AbortReason::kExpectedBaselineData, scratch,
            Operand(static_cast<int>(CodeKind::BASELINE)));
}

// TODO(v8:11429): Add a path for "not_compiled" and unify the two uses under
// the more general dispatch.
static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  DCHECK(!AreAliased(bytecode, scratch1));
  ASM_CODE_COMMENT(masm);
  Label done;

  Register data = bytecode;
  __ LoadTrustedPointerField(
      data,
      FieldMemOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);

  __ GetObjectType(data, scratch1, scratch1);

#ifndef V8_JITLESS
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ Branch(&not_baseline, ne, scratch1, Operand(CODE_TYPE));
    AssertCodeIsBaseline(masm, data, scratch1);
    __ Branch(is_baseline);
    __ bind(&not_baseline);
  } else {
    __ Branch(is_baseline, eq, scratch1, Operand(CODE_TYPE));
  }
#endif  // !V8_JITLESS

  __ Branch(&done, ne, scratch1, Operand(INTERPRETER_DATA_TYPE));
  __ LoadProtectedPointerField(
      bytecode, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset));

  __ bind(&done);

  __ GetObjectType(bytecode, scratch1, scratch1);
  __ Branch(is_unavailable, ne, scratch1, Operand(BYTECODE_ARRAY_TYPE));
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the value to pass to the generator
  //  -- a1 : the JSGeneratorObject to resume
  //  -- ra : return address
  // -----------------------------------
  // Store input value into generator object.
  __ StoreTaggedField(
      a0, FieldMemOperand(a1, JSGeneratorObject::kInputOrDebugPosOffset));
  __ RecordWriteField(a1, JSGeneratorObject::kInputOrDebugPosOffset, a0,
                      kRAHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that a1 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(a1);

  // Load suspended function and context.
  __ LoadTaggedField(a4,
                     FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ LoadTaggedField(cp, FieldMemOperand(a4, JSFunction::kContextOffset));

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ li(a5, debug_hook);
  __ Ld_b(a5, MemOperand(a5, 0));
  __ Branch(&prepare_step_in_if_stepping, ne, a5, Operand(zero_reg));

  // Flood function if we need to continue stepping in the suspended generator.
  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());
  __ li(a5, debug_suspended_generator);
  __ Ld_d(a5, MemOperand(a5, 0));
  __ Branch(&prepare_step_in_suspended_generator, eq, a1, Operand(a5));
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadStackLimit(kScratchReg,
                    MacroAssembler::StackLimitKind::kRealStackLimit);
  __ Branch(&stack_overflow, lo, sp, Operand(kScratchReg));

  // ----------- S t a t e -------------
  //  -- a1    : the JSGeneratorObject to resume
  //  -- a4    : generator function
  //  -- cp    : generator context
  //  -- ra    : return address
  // -----------------------------------

  // Push holes for arguments to generator function. Since the parser forced
  // context allocation for any variables in generators, the actual argument
  // values have already been copied into the context and these dummy values
  // will never be used.
  __ LoadTaggedField(
      a3, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
  __ Ld_hu(
      a3, FieldMemOperand(a3, SharedFunctionInfo::kFormalParameterCountOffset));
  __ Sub_d(a3, a3, Operand(kJSArgcReceiverSlots));
  __ LoadTaggedField(
      t1,
      FieldMemOperand(a1, JSGeneratorObject::kParametersAndRegistersOffset));
  {
    Label done_loop, loop;
    __ bind(&loop);
    __ Sub_d(a3, a3, Operand(1));
    __ Branch(&done_loop, lt, a3, Operand(zero_reg));
    __ Alsl_d(kScratchReg, a3, t1, kTaggedSizeLog2, t7);
    __ LoadTaggedField(
        kScratchReg,
        FieldMemOperand(kScratchReg, OFFSET_OF_DATA_START(FixedArray)));
    __ Push(kScratchReg);
    __ Branch(&loop);
    __ bind(&done_loop);
    // Push receiver.
    __ LoadTaggedField(kScratchReg,
                       FieldMemOperand(a1, JSGeneratorObject::kReceiverOffset));
    __ Push(kScratchReg);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label ok, is_baseline, is_unavailable;
    Register sfi = a3;
    Register bytecode = a3;
    __ LoadTaggedField(
        sfi, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, sfi, bytecode, t5,
                                            &is_baseline, &is_unavailable);
    __ Branch(&ok);

    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);

    __ bind(&is_baseline);
    __ GetObjectType(a3, a3, bytecode);
    __ Assert(eq, AbortReason::kMissingBytecodeArray, bytecode,
              Operand(CODE_TYPE));
    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    // TODO(40931165): use parameter count from JSDispatchTable and validate
    // that it matches the number of values in the JSGeneratorObject.
    __ LoadTaggedField(
        a0, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
    __ Ld_hu(a0, FieldMemOperand(
                     a0, SharedFunctionInfo::kFormalParameterCountOffset));
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ Move(a3, a1);
    __ Move(a1, a4);
    __ JumpJSFunction(a1);
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(a1, a4);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(a1);
  }
  __ LoadTaggedField(a4,
                     FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ Branch(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(a1);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(a1);
  }
  __ LoadTaggedField(a4,
                     FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ Branch(&stepping_prepared);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ break_(0xCC);  // This should be unreachable.
  }
}

void Builtins::Generate_ConstructedNonConstructable(MacroAssembler* masm) {
  FrameScope scope(masm, StackFrame::INTERNAL);
  __ Push(a1);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
}

// Clobbers scratch1 and scratch2; preserves all other registers.
static void Generate_CheckStackOverflow(MacroAssembler* masm, Register argc,
                                        Register scratch1, Register scratch2) {
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  Label okay;
  __ LoadStackLimit(scratch1, MacroAssembler::StackLimitKind::kRealStackLimit);
  // Make a2 the space we have left. The stack might already be overflowed
  // here which will cause r2 to become negative.
  __ sub_d(scratch1, sp, scratch1);
  // Check if the arguments will overflow the stack.
  __ slli_d(scratch2, argc, kSystemPointerSizeLog2);
  __ Branch(&okay, gt, scratch1, Operand(scratch2));  // Signed comparison.

  // Out of stack space.
  __ CallRuntime(Runtime::kThrowStackOverflow);

  __ bind(&okay);
}

namespace {

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
  Label invoke, handler_entry, exit;

  {
    NoRootArrayScope no_root_array(masm);

    // Registers:
    //  either
    //   a0: root register value
    //   a1: entry address
    //   a2: function
    //   a3: receiver
    //   a4: argc
    //   a5: argv
    //  or
    //   a0: root register value
    //   a1: microtask_queue

    // Save callee saved registers on the stack.
    __ MultiPush(kCalleeSaved | ra);

    // Save callee-saved FPU registers.
    __ MultiPushFPU(kCalleeSavedFPU);
    // Set up the reserved register for 0.0.
    __ Move(kDoubleRegZero, 0.0);

    // Initialize the root register.
    // C calling convention. The first argument is passed in a0.
    __ mov(kRootRegister, a0);

#ifdef V8_COMPRESS_POINTERS
    // Initialize the pointer cage base register.
    __ LoadRootRelative(kPtrComprCageBaseRegister,
                        IsolateData::cage_base_offset());
#endif
  }

  // a1: entry address
  // a2: function
  // a3: receiver
  // a4: argc
  // a5: argv

  // We build an EntryFrame.
  __ li(s1, Operand(-1));  // Push a bad frame pointer to fail if it is used.
  __ li(s2, Operand(StackFrame::TypeToMarker(type)));
  __ li(s3, Operand(StackFrame::TypeToMarker(type)));
  ExternalReference c_entry_fp = ExternalReference::Create(
      IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ li(s5, c_entry_fp);
  __ Ld_d(s4, MemOperand(s5, 0));
  __ Push(s1, s2, s3, s4);

  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  __ St_d(zero_reg, MemOperand(s5, 0));

  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerFP);
  __ Ld_d(s2, MemOperand(s1, 0));
  __ St_d(zero_reg, MemOperand(s1, 0));
  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerPC);
  __ Ld_d(s3, MemOperand(s1, 0));
  __ St_d(zero_reg, MemOperand(s1, 0));
  __ Push(s2, s3);

  // Set up frame pointer for the frame to be pushed.
  __ addi_d(fp, sp, -EntryFrameConstants::kNextFastCallFramePCOffset);

  // Registers:
  //  either
  //   a1: entry address
  //   a2: function
  //   a3: receiver
  //   a4: argc
  //   a5: argv
  //  or
  //   a1: microtask_queue
  //
  // Stack:
  // fast api call pc   |
  // fast api call fp   |
  // C entry FP         |
  // function slot      | entry frame
  // context slot       |
  // bad fp (0xFF...F)  |
  // callee saved registers + ra

  // If this is the outermost JS call, set js_entry_sp value.
  Label non_outermost_js;
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ li(s1, js_entry_sp);
  __ Ld_d(s2, MemOperand(s1, 0));
  __ Branch(&non_outermost_js, ne, s2, Operand(zero_reg));
  __ St_d(fp, MemOperand(s1, 0));
  __ li(s3, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  Label cont;
  __ b(&cont);
  __ nop();  // Branch delay slot nop.
  __ bind(&non_outermost_js);
  __ li(s3, Operand(StackFrame::INNER_JSENTRY_FRAME));
  __ bind(&cont);
  __ Push(s3);

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ jmp(&invoke);
  __ bind(&handler_entry);

  // Store the current pc as the handler offset. It's used later to create the
  // handler table.
  masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

  // Caught exception: Store result (exception) in the exception
  // field in the JSEnv and return a failure sentinel.  Coming in here the
  // fp will be invalid because the PushStackHandler below sets it to 0 to
  // signal the existence of the JSEntry frame.
  __ li(s1, ExternalReference::Create(IsolateAddressId::kExceptionAddress,
                                      masm->isolate()));
  __ St_d(a0,
          MemOperand(s1, 0));  // We come back from 'invoke'. result is in a0.
  __ LoadRoot(a0, RootIndex::kException);
  __ b(&exit);  // b exposes branch delay slot.
  __ nop();     // Branch delay slot nop.

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  __ PushStackHandler();
  // If an exception not caught by another handler occurs, this handler
  // returns control to the code after the bal(&invoke) above, which
  // restores all kCalleeSaved registers (including cp and fp) to their
  // saved values before returning a failure to C.
  //
  // Registers:
  //  either
  //   a0: root register value
  //   a1: entry address
  //   a2: function
  //   a3: receiver
  //   a4: argc
  //   a5: argv
  //  or
  //   a0: root register value
  //   a1: microtask_queue
  //
  // Stack:
  // handler frame
  // entry frame
  // fast api call pc
  // fast api call fp
  // C entry FP
  // function slot
  // context slot
  // bad fp (0xFF...F)
  // callee saved registers + ra

  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();

  __ bind(&exit);  // a0 holds result
  // Check if the current stack frame is marked as the outermost JS frame.
  Label non_outermost_js_2;
  __ Pop(a5);
  __ Branch(&non_outermost_js_2, ne, a5,
            Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  __ li(a5, js_entry_sp);
  __ St_d(zero_reg, MemOperand(a5, 0));
  __ bind(&non_outermost_js_2);

  // Restore the top frame descriptors from the stack.
  __ Pop(a4, a5);
  __ LoadIsolateField(a6, IsolateFieldId::kFastCCallCallerFP);
  __ St_d(a4, MemOperand(a6, 0));
  __ LoadIsolateField(a6, IsolateFieldId::kFastCCallCallerPC);
  __ St_d(a5, MemOperand(a6, 0));

  __ Pop(a5);
  __ li(a4, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                      masm->isolate()));
  __ St_d(a5, MemOperand(a4, 0));

  // Reset the stack to the callee saved registers.
  __ addi_d(sp, sp, -EntryFrameConstants::kNextExitFrameFPOffset);

  // Restore callee-saved fpu registers.
  __ MultiPopFPU(kCalleeSavedFPU);

  // Restore callee saved registers from the stack.
  __ MultiPop(kCalleeSaved | ra);
  // Return.
  __ Jump(ra);
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
  // ----------- S t a t e -------------
  //  -- a1: new.target
  //  -- a2: function
  //  -- a3: receiver_pointer
  //  -- a4: argc
  //  -- a5: argv
  // -----------------------------------

  // Enter an internal frame.
  {
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ li(cp, context_address);
    __ Ld_d(cp, MemOperand(cp, 0));

    // Push the function and the receiver onto the stack.
    __ Push(a2);

    // Check if we have enough stack space to push all arguments.
    __ mov(a6, a4);
    Generate_CheckStackOverflow(masm, a6, a0, s2);

    // Copy arguments to the stack.
    // a4: argc
    // a5: argv, i.e. points to first arg
    Generate_PushArguments(masm, a5, a4, s1, s2, ArgumentsElementType::kHandle);

    // Push the receive.
    __ Push(a3);

    // a0: argc
    // a1: function
    // a3: new.target
    __ mov(a3, a1);
    __ mov(a1, a2);
    __ mov(a0, a4);

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    __ LoadRoot(a4, RootIndex::kUndefinedValue);
    __ mov(a5, a4);
    __ mov(s1, a4);
    __ mov(s2, a4);
    __ mov(s3, a4);
    __ mov(s4, a4);
    __ mov(s5, a4);
#ifndef V8_COMPRESS_POINTERS
    __ mov(s8, a4);
#endif
    // s6 holds the root address. Do not clobber.
    // s7 is cp. Do not init.
    // s8 is pointer cage base register (kPointerCageBaseRegister).

    // Invoke the code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Leave internal frame.
  }
  __ Jump(ra);
}

void Builtins::Generate_JSEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, false);
}

void Builtins::Generate_JSConstructEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, true);
}

void Builtins::Generate_RunMicrotasksTrampoline(MacroAssembler* masm) {
  // a1: microtask_queue
  __ mov(RunMicrotasksDescriptor::MicrotaskQueueRegister(), a1);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  Register params_size = scratch1;

  // Get the size of the formal parameters + receiver (in bytes).
  __ Ld_d(params_size,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Ld_hu(params_size,
           FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ Ld_d(actual_params_size,
          MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  __ slt(t2, params_size, actual_params_size);
  __ Movn(params_size, actual_params_size, t2);

  // Leave the frame (also dropping the register file).
  __ LeaveFrame(StackFrame::INTERPRETED);

  // Drop arguments.
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
                                          Register scratch2, Register scratch3,
                                          Label* if_return) {
  Register bytecode_size_table = scratch1;

  // The bytecode offset value will be increased by one in wide and extra wide
  // cases. In the case of having a wide or extra wide JumpLoop bytecode, we
  // will restore the original bytecode. In order to simplify the code, we have
  // a backup of it.
  Register original_bytecode_offset = scratch3;
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode,
                     bytecode_size_table, original_bytecode_offset));
  __ Move(original_bytecode_offset, bytecode_offset);
  __ li(bytecode_size_table, ExternalReference::bytecode_size_table_address());

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
                static_cast<int>(interpreter::Bytecode::kDebugBreakExtraWide));
  __ Branch(&process_bytecode, hi, bytecode, Operand(3));
  __ And(scratch2, bytecode, Operand(1));
  __ Branch(&extra_wide, ne, scratch2, Operand(zero_reg));

  // Load the next bytecode and update table to the wide scaled table.
  __ Add_d(bytecode_offset, bytecode_offset, Operand(1));
  __ Add_d(scratch2, bytecode_array, bytecode_offset);
  __ Ld_bu(bytecode, MemOperand(scratch2, 0));
  __ Add_d(bytecode_size_table, bytecode_size_table,
           Operand(kByteSize * interpreter::Bytecodes::kBytecodeCount));
  __ jmp(&process_bytecode);

  __ bind(&extra_wide);
  // Load the next bytecode and update table to the extra wide scaled table.
  __ Add_d(bytecode_offset, bytecode_offset, Operand(1));
  __ Add_d(scratch2, bytecode_array, bytecode_offset);
  __ Ld_bu(bytecode, MemOperand(scratch2, 0));
  __ Add_d(bytecode_size_table, bytecode_size_table,
           Operand(2 * kByteSize * interpreter::Bytecodes::kBytecodeCount));

  __ bind(&process_bytecode);

// Bailout to the return label if this is a return bytecode.
#define JUMP_IF_EQUAL(NAME)          \
  __ Branch(if_return, eq, bytecode, \
            Operand(static_cast<int>(interpreter::Bytecode::k##NAME)));
  RETURN_BYTECODE_LIST(JU
"""


```
Response:
Let's break down the request and the provided C++ code snippet.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the `builtins-loong64.cc` file, assuming it's part of the V8 JavaScript engine. It also touches upon Torque (`.tq`) files, JavaScript relevance, code logic, and common programming errors. Crucially, it specifies this is part 6 of 6, implying a summarizing requirement.

**2. Initial Code Scan and High-Level Recognition:**

A quick scan of the code reveals the following:

* **Assembly Instructions:**  The code heavily uses `__` followed by mnemonics like `St_d`, `Ld_d`, `Call`, `Jump`, etc. This strongly suggests it's assembly code generation within C++. The `MacroAssembler` class confirms this.
* **`Builtins::Generate_...` Functions:** The file contains numerous functions named `Generate_...`, indicating it's responsible for generating code for specific built-in operations in V8.
* **LOONG64 Specific:** The file path `v8/src/builtins/loong64/` clearly indicates architecture-specific code for the LOONG64 processor architecture.
* **References to V8 Internals:**  Terms like `Isolate`, `Context`, `FunctionCallbackInfo`, `PropertyCallbackInfo`, `Deoptimizer`, `InterpreterFrameConstants`, `BaselineFrameConstants`, `SharedFunctionInfo`, `FeedbackVector`, etc., are all key V8 internal concepts. This further confirms its role in implementing core JavaScript functionality.
* **API Calls:** There are calls to C++ functions (e.g., `CallCFunction`) and interactions with the V8 API.

**3. Deconstructing Individual `Generate_...` Functions:**

Now, let's analyze what each function appears to be doing:

* **`Generate_CallApiCallback`:**  Deals with calling JavaScript functions from C++ (API callbacks). It sets up the necessary arguments on the stack, including `holder`, `isolate`, `context`, `returnValue`, `target`, and `newTarget`. It handles both generic and optimized callbacks.
* **`Generate_CallApiGetter`:** Handles calls to JavaScript getter functions defined in C++. It sets up `PropertyCallbackInfo` arguments on the stack, such as the property `name`, `holder`, `isolate`, `receiver`, etc.
* **`Generate_DirectCEntry`:** Provides a safe way to call C++ functions from generated code that might trigger garbage collection. It ensures the return address is on the stack so it can be updated if the calling code moves.
* **`Generate_DeoptimizationEntry` (Eager and Lazy):** Implements the process of deoptimizing code. This happens when the optimized code makes assumptions that are no longer valid. It saves register states, allocates a `Deoptimizer` object, copies frame information, and transitions back to a less optimized state (interpreter or baseline). The "Eager" and "Lazy" variants likely differ in when the deoptimization occurs.
* **`Generate_BaselineOrInterpreterEntry`:**  Manages the transition from interpreted bytecode execution to baseline compiled code (a less optimized form of machine code). It checks if baseline code is available and, if so, jumps to it. It also handles the case where baseline code needs to be installed.
* **`Generate_InterpreterOnStackReplacement_ToBaseline`:** A specific case of the previous function, used for On-Stack Replacement (OSR), where a long-running interpreted function is upgraded to baseline code while it's still running.
* **`Generate_RestartFrameTrampoline`:**  Provides a mechanism to restart the execution of the current interpreted frame, typically after some event that requires the frame to be re-evaluated.

**4. Addressing Specific Request Points:**

* **Functionality Listing:** The above breakdown of each `Generate_...` function directly addresses this.
* **Torque (`.tq`) Files:** The code mentions `onTemplateInfoRegister()`, which is highly characteristic of Torque-generated built-ins. So, the initial hypothesis is likely correct.
* **JavaScript Relationship and Examples:** The functions directly implement how JavaScript interacts with C++ code (API callbacks, getters) and how V8 manages different execution tiers (interpreter, baseline, optimized). JavaScript examples become straightforward (see the "Self-Correction/Refinement" section).
* **Code Logic Reasoning:**  For `CallApiCallback` and `CallApiGetter`, we can infer the stack layout based on the `static_assert` statements and the `__ St_d` (store double-word) instructions. Assumptions about input registers and the resulting stack state can be made.
* **Common Programming Errors:** The `DirectCEntry` function implicitly addresses errors related to GC moving code. Deoptimization is triggered by incorrect assumptions or runtime conditions, which can be seen as a form of "error" in the optimized code's assumptions.
* **Part 6 of 6 - Summarization:** The file contains the LOONG64 architecture-specific implementations of several key built-in functions in V8. These functions handle interactions between JavaScript and C++, manage code optimization and deoptimization, and provide a safe way to call C++ code. It's a crucial low-level component for the LOONG64 port of V8.

**5. Self-Correction/Refinement During the Thought Process:**

* **Initial Assumption about Assembly:** While it's assembly *generation*, the code is C++. This nuance is important.
* **JavaScript Examples:**  Initially, I might have struggled with precise JavaScript examples. However, thinking about API callbacks (`v8::FunctionTemplate`, `v8::Accessor`) and the concept of optimization/deoptimization (though not directly controllable by JS) clarifies how these built-ins are used.
* **Code Logic Detail:**  The stack layout in `CallApiCallback` and `CallApiGetter` is quite detailed. I needed to carefully examine the `static_assert` statements and the store instructions to reconstruct the argument order.
* **Error Handling:** While not explicit error *handling* code, the deoptimization logic is a response to a kind of runtime error (invalidated optimization assumptions).

By following this structured approach—scanning, deconstructing, connecting to the request, and refining—I could arrive at a comprehensive understanding of the `builtins-loong64.cc` file.
This C++ source code file, `v8/src/builtins/loong64/builtins-loong64.cc`, is a crucial part of the V8 JavaScript engine specifically designed for the **LOONG64 architecture**. It defines and implements a collection of **built-in functions** that are fundamental to the execution of JavaScript code within V8 on this architecture.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Implementing API Callbacks:**
   - The `Generate_CallApiCallback` function handles the transition from C++ code (where V8 internals reside) to JavaScript functions defined through the V8 API (using `v8::FunctionTemplate`, etc.).
   - It sets up the necessary stack frame and arguments required by the JavaScript function, including the `holder`, `isolate`, `context`, `receiver`, and arguments.
   - It supports both generic and optimized API callbacks, potentially using different call paths for performance.

2. **Implementing API Getters:**
   - The `Generate_CallApiGetter` function is responsible for invoking JavaScript getter functions defined through the V8 API (`v8::Accessor`).
   - It prepares the `v8::PropertyCallbackInfo` object on the stack, providing information like the property name, holder object, and receiver to the JavaScript getter function.

3. **Direct C++ Function Calls:**
   - `Generate_DirectCEntry` provides a mechanism for directly calling C++ functions from generated code. This is essential for operations that might trigger garbage collection (GC), as it ensures the return address is safely stored on the stack and can be updated by the GC if the calling code moves in memory.

4. **Handling Deoptimization:**
   - `Generate_DeoptimizationEntry_Eager` and `Generate_DeoptimizationEntry_Lazy` implement the deoptimization process. This is triggered when the assumptions made by optimized code (compiled by TurboFan) are invalidated at runtime.
   - These functions save the current register state, reconstruct the stack frame, and transition execution back to either the interpreter or baseline compiler, ensuring correct execution even when optimizations are no longer valid.
   - "Eager" deoptimization happens immediately, while "Lazy" deoptimization occurs at a later, more convenient point.

5. **Entry Points for Baseline and Interpreter:**
   - `Generate_BaselineOrInterpreterEnterAtBytecode` and `Generate_BaselineOrInterpreterEnterAtNextBytecode` define the entry points when execution begins in either the interpreter or the baseline compiler.
   - They check if baseline code exists for a function and, if so, jump to it. Otherwise, they fall back to the interpreter.
   - They manage the transition from an interpreted frame to a baseline frame.

6. **On-Stack Replacement (OSR):**
   - `Generate_InterpreterOnStackReplacement_ToBaseline` handles the process of upgrading a long-running interpreted function to its baseline compiled version while it's still executing. This improves performance for hot functions.

7. **Restarting Frames:**
   - `Generate_RestartFrameTrampoline` allows restarting the execution of the current JavaScript function's frame. This is often used in scenarios where changes require the frame's state to be re-evaluated.

**Is it a Torque file?**

The code snippet includes `onTemplateInfoRegister()`, which is a strong indicator that **this file likely incorporates or interacts with code generated by Torque**. Torque is V8's domain-specific language for defining built-in functions. While the provided snippet is C++, it's highly probable that some parts of the logic or the definitions of the built-ins it implements are specified in Torque (`.tq`) files. The C++ code then serves as the "backend" implementation for the Torque-defined logic.

**Relationship with JavaScript and Examples:**

These built-in functions are the low-level machinery that makes JavaScript execution possible within V8. They are not directly called by JavaScript code, but they are invoked by the V8 engine when certain JavaScript operations are performed.

**Examples:**

* **API Callbacks:** When you define a native function in C++ and expose it to JavaScript using `v8::FunctionTemplate`, the `Generate_CallApiCallback` function is responsible for setting up the call when that JavaScript function is invoked.

   ```javascript
   // C++ code (simplified)
   v8::Local<v8::FunctionTemplate> tpl = v8::FunctionTemplate::New(isolate, MyNativeFunction);
   // ... expose tpl to JavaScript ...

   // JavaScript code
   myNativeFunction(); // This will eventually lead to Generate_CallApiCallback
   ```

* **API Getters:** When you define a getter for a JavaScript object in C++, `Generate_CallApiGetter` is invoked when JavaScript code tries to access that property.

   ```javascript
   // C++ code (simplified)
   v8::AccessorGetterCallback getter = MyGetter;
   tpl->SetAccessor(v8::String::NewFromUtf8Literal(isolate, "myProperty"), getter);

   // JavaScript code
   console.log(myObject.myProperty); // This will eventually lead to Generate_CallApiGetter
   ```

* **Deoptimization:** While you can't directly trigger deoptimization in JavaScript, certain coding patterns or runtime conditions can cause V8 to deoptimize code.

   ```javascript
   function potentiallyOptimizedFunction(x) {
       if (typeof x === 'number') {
           return x * 2;
       } else {
           // If the type of x changes unexpectedly, the optimized code might be invalid
           return x + " is not a number";
       }
   }

   potentiallyOptimizedFunction(5); // V8 might optimize for number input
   potentiallyOptimizedFunction("hello"); // This could trigger deoptimization
   ```

**Code Logic Reasoning (Example: `Generate_CallApiCallback`)**

**Assumption:**  A JavaScript function, defined as a native function via the V8 API, is being called from C++.

**Input:**
- `api_function_address`: The memory address of the C++ function to be called.
- `topmost_script_having_context`: Information about the script context.
- `argc`: The number of arguments passed to the JavaScript function.
- `holder`: The object on which the function was called (the `this` value).
- `func_templ`: The `FunctionTemplateInfo` associated with the function.

**Output (Conceptual Stack Layout):**
The function sets up a specific layout on the stack to be compatible with how JavaScript functions expect arguments and context. Key elements pushed onto the stack include (as commented in the code):

```
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kData
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
```

The code stores these values in specific memory locations relative to the stack pointer (`sp`). It also takes care of setting up the `FunctionCallbackInfo` object, which is the primary way C++ code interacts with the JavaScript function call.

**Common Programming Errors (Related to these built-ins):**

While developers don't directly write code in this file, understanding its purpose helps in avoiding errors when interacting with the V8 API:

1. **Incorrectly Defining Native Functions:**  Errors in the C++ implementation of native functions (passed to `v8::FunctionTemplate`) can lead to crashes or unexpected behavior. For example, not handling arguments correctly or leaking memory.

2. **Mismatched API Usage:** Incorrectly setting up accessors (`v8::Accessor`) or interceptors can lead to issues when JavaScript code tries to access or modify object properties.

3. **Performance Issues Due to Deoptimization:** While not strictly an error, writing JavaScript code that frequently causes deoptimization can significantly impact performance. Understanding the reasons for deoptimization helps in writing more performant code. For instance, relying on dynamic types excessively might hinder optimization.

**归纳一下它的功能 (Summary of its Functionality):**

This `builtins-loong64.cc` file provides the **LOONG64 architecture-specific implementations of essential built-in functions for the V8 JavaScript engine.** It acts as a bridge between the C++ internals of V8 and the execution of JavaScript code. Its responsibilities include:

- Facilitating calls between C++ and JavaScript (API callbacks and getters).
- Providing a safe mechanism for calling C++ functions that might trigger garbage collection.
- Managing the deoptimization process, ensuring correct execution when optimized code becomes invalid.
- Defining entry points for executing JavaScript in the interpreter and baseline compiler.
- Implementing on-stack replacement for performance optimization.
- Enabling the restarting of JavaScript execution frames.

Essentially, this file contains the low-level, architecture-aware code that enables V8 to execute JavaScript efficiently on LOONG64 processors. It works in conjunction with higher-level components like the interpreter, compilers (TurboFan, Crankshaft), and the V8 API.

Prompt: 
```
这是目录为v8/src/builtins/loong64/builtins-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/loong64/builtins-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
onTemplateInfoRegister();
      holder = CallApiCallbackOptimizedDescriptor::HolderRegister();
      break;
  }
  DCHECK(!AreAliased(api_function_address, topmost_script_having_context, argc,
                     holder, scratch));

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
  //
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kData
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[6 * kSystemPointerSize]:           <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);
  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  // Reserve space on the stack.
  __ Sub_d(sp, sp, Operand(FCA::kArgsLength * kSystemPointerSize));

  // kHolder.
  __ St_d(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ li(scratch, ER::isolate_address());
  __ St_d(scratch, MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext.
  __ St_d(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue.
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ St_d(scratch, MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ St_d(func_templ, MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ St_d(scratch, MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

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
    ASM_CODE_COMMENT_STRING(masm, "Initialize FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ St_d(argc, argc_operand);

    // FunctionCallbackInfo::implicit_args_.
    __ Add_d(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ St_d(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ Add_d(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ St_d(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  // function_callback_info_arg = v8::FunctionCallbackInfo&
  __ Add_d(function_callback_info_arg, fp,
           Operand(FC::kFunctionCallbackInfoOffset));

  DCHECK(
      !AreAliased(api_function_address, scratch, function_callback_info_arg));

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

  Register api_function_address = a2;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = a4;
  Register undef = a5;
  Register scratch2 = a6;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, undef, scratch2));

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
  //   sp[0 * kSystemPointerSize]: name                       <= PCI:args_
  //   sp[1 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   sp[2 * kSystemPointerSize]: kHolderIndex
  //   sp[3 * kSystemPointerSize]: kIsolateIndex
  //   sp[4 * kSystemPointerSize]: kHolderV2Index
  //   sp[5 * kSystemPointerSize]: kReturnValueIndex
  //   sp[6 * kSystemPointerSize]: kDataIndex
  //   sp[7 * kSystemPointerSize]: kThisIndex / receiver

  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kDataOffset));
  __ LoadRoot(undef, RootIndex::kUndefinedValue);
  __ li(scratch2, ER::isolate_address());
  Register holderV2 = zero_reg;
  __ Push(receiver, scratch,  // kThisIndex, kDataIndex
          undef, holderV2);   // kReturnValueIndex, kHolderV2Index
  __ Push(scratch2, holder);  // kIsolateIndex, kHolderIndex

  // |name_arg| clashes with |holder|, so we need to push holder first.
  __ LoadTaggedField(name_arg,
                     FieldMemOperand(callback, AccessorInfo::kNameOffset));
  static_assert(kDontThrow == 0);
  Register should_throw_on_error =
      zero_reg;  // should_throw_on_error -> kDontThrow
  __ Push(should_throw_on_error, name_arg);

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
  __ Add_d(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));

  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name_arg,
                     callback, scratch, scratch2));

#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  // |name_arg| is already initialized above.
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ mov(name_arg, property_callback_info_arg);
#endif

  ER thunk_ref = ER::invoke_accessor_getter_callback();
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

  __ St_d(ra, MemOperand(sp, 0));  // Store the return address.
  __ Call(t7);                     // Call the C++ function.
  __ Ld_d(ra, MemOperand(sp, 0));  // Return to calling code.

  // TODO(LOONG_dev): LOONG64 Check this assert.
  if (v8_flags.debug_code && v8_flags.enable_slow_asserts) {
    // In case of an error the return address may point to a memory area
    // filled with kZapValue by the GC. Dereference the address and check for
    // this.
    __ Ld_d(a4, MemOperand(ra, 0));
    __ Assert(ne, AbortReason::kReceivedInvalidReturnAddress, a4,
              Operand(reinterpret_cast<uint64_t>(kZapValue)));
  }

  __ Jump(ra);
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

  const int kSimd128RegsSize = kSimd128Size * Simd128Register::kNumRegisters;

  // Save all allocatable simd128 / double registers before messing with them.
  // TODO(loong64): Add simd support here.
  __ Sub_d(sp, sp, Operand(kSimd128RegsSize));
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_double_registers(); ++i) {
    int code = config->GetAllocatableDoubleCode(i);
    const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
    int offset = code * kSimd128Size;
    __ Fst_d(fpu_reg, MemOperand(sp, offset));
  }

  // Push saved_regs (needed to populate FrameDescription::registers_).
  // Leave gaps for other registers.
  __ Sub_d(sp, sp, kNumberOfRegisters * kSystemPointerSize);
  for (int16_t i = kNumberOfRegisters - 1; i >= 0; i--) {
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ St_d(ToRegister(i), MemOperand(sp, kSystemPointerSize * i));
    }
  }

  __ li(a2,
        ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate));
  __ St_d(fp, MemOperand(a2, 0));

  const int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kSystemPointerSize) + kSimd128RegsSize;

  // Get the address of the location in the code object (a2) (return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register a3.
  __ mov(a2, ra);
  __ Add_d(a3, sp, Operand(kSavedRegistersAreaSize));

  __ sub_d(a3, fp, a3);

  // Allocate a new deoptimizer object.
  __ PrepareCallCFunction(5, a4);
  // Pass six arguments, according to n64 ABI.
  __ mov(a0, zero_reg);
  Label context_check;
  __ Ld_d(a1, MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(a1, &context_check);
  __ Ld_d(a0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
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

  // Preserve "deoptimizer" object in register a0 and get the input
  // frame descriptor pointer to a1 (deoptimizer->input_);
  // Move deopt-obj to a0 for call to Deoptimizer::ComputeOutputFrames() below.
  __ Ld_d(a1, MemOperand(a0, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_[kNumRegisters].
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ Ld_d(a2, MemOperand(sp, i * kSystemPointerSize));
      __ St_d(a2, MemOperand(a1, offset));
    } else if (v8_flags.debug_code) {
      __ li(a2, Operand(kDebugZapValue));
      __ St_d(a2, MemOperand(a1, offset));
    }
  }

  // Copy simd128 / double registers to the input frame.
  // TODO(loong64): Add simd support here.
  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
    int code = config->GetAllocatableSimd128Code(i);
    int dst_offset = code * kSimd128Size + simd128_regs_offset;
    int src_offset =
        code * kSimd128Size + kNumberOfRegisters * kSystemPointerSize;
    __ Fld_d(f0, MemOperand(sp, src_offset));
    __ Fst_d(f0, MemOperand(a1, dst_offset));
  }

  // Remove the saved registers from the stack.
  __ Add_d(sp, sp, Operand(kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register a2; that is
  // the first stack slot not part of the input frame.
  __ Ld_d(a2, MemOperand(a1, FrameDescription::frame_size_offset()));
  __ add_d(a2, a2, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ Add_d(a3, a1, Operand(FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ Branch(&pop_loop_header);
  __ bind(&pop_loop);
  __ Pop(a4);
  __ St_d(a4, MemOperand(a3, 0));
  __ addi_d(a3, a3, sizeof(uint64_t));
  __ bind(&pop_loop_header);
  __ BranchShort(&pop_loop, ne, a2, Operand(sp));
  // Compute the output frame in the deoptimizer.
  __ Push(a0);  // Preserve deoptimizer object across call.
  // a0: deoptimizer object; a1: scratch.
  __ PrepareCallCFunction(1, a1);
  // Call Deoptimizer::ComputeOutputFrames().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ Pop(a0);  // Restore deoptimizer object (class Deoptimizer).

  __ Ld_d(sp, MemOperand(a0, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: a4 = current "FrameDescription** output_",
  // a1 = one past the last FrameDescription**.
  __ Ld_w(a1, MemOperand(a0, Deoptimizer::output_count_offset()));
  __ Ld_d(a4, MemOperand(a0, Deoptimizer::output_offset()));  // a4 is output_.
  __ Alsl_d(a1, a1, a4, kSystemPointerSizeLog2);
  __ Branch(&outer_loop_header);

  __ bind(&outer_push_loop);
  Register current_frame = a2;
  Register frame_size = a3;
  __ Ld_d(current_frame, MemOperand(a4, 0));
  __ Ld_d(frame_size,
          MemOperand(current_frame, FrameDescription::frame_size_offset()));
  __ Branch(&inner_loop_header);

  __ bind(&inner_push_loop);
  __ Sub_d(frame_size, frame_size, Operand(sizeof(uint64_t)));
  __ Add_d(a6, current_frame, Operand(frame_size));
  __ Ld_d(a7, MemOperand(a6, FrameDescription::frame_content_offset()));
  __ Push(a7);

  __ bind(&inner_loop_header);
  __ BranchShort(&inner_push_loop, ne, frame_size, Operand(zero_reg));

  __ Add_d(a4, a4, Operand(kSystemPointerSize));

  __ bind(&outer_loop_header);
  __ BranchShort(&outer_push_loop, lt, a4, Operand(a1));

  // TODO(loong64): Add simd support here.
  for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
    int code = config->GetAllocatableSimd128Code(i);
    const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
    int src_offset = code * kSimd128Size + simd128_regs_offset;
    __ Fld_d(fpu_reg, MemOperand(current_frame, src_offset));
  }

  // Push pc and continuation from the last output frame.
  __ Ld_d(a6, MemOperand(current_frame, FrameDescription::pc_offset()));
  __ Push(a6);
  __ Ld_d(a6,
          MemOperand(current_frame, FrameDescription::continuation_offset()));
  __ Push(a6);

  // Technically restoring 'at' should work unless zero_reg is also restored
  // but it's safer to check for this.
  DCHECK(!(restored_regs.has(t7)));
  // Restore the registers from the last output frame.
  __ mov(t7, current_frame);
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((restored_regs.bits() & (1 << i)) != 0) {
      __ Ld_d(ToRegister(i), MemOperand(t7, offset));
    }
  }

  // If the continuation is non-zero (JavaScript), branch to the continuation.
  // For Wasm just return to the pc from the last output frame in the lr
  // register.
  Label end;
  __ Pop(t7);  // Get continuation, leave pc on stack.
  __ Pop(ra);
  __ BranchShort(&end, eq, t7, Operand(zero_reg));
  __ Jump(t7);
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
  __ Ld_d(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

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
    __ JumpIfObjectType(&start_with_baseline, eq, code_obj, CODE_TYPE, t2);

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
  __ LoadTaggedField(feedback_cell,
                     FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(
      feedback_vector,
      FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ JumpIfObjectType(&install_baseline_code, ne, feedback_vector,
                      FEEDBACK_VECTOR_TYPE, t2);

  // Save BytecodeOffset from the stack frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  // Replace bytecode offset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ St_d(feedback_cell,
          MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ St_d(feedback_vector,
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

  __ Sub_d(kInterpreterBytecodeOffsetRegister,
           kInterpreterBytecodeOffsetRegister,
           (BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ Ld_d(kInterpreterBytecodeArrayRegister,
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
  __ Add_d(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    // TODO(liuyu): Remove Ld as arm64 after register reallocation.
    __ Ld_d(kInterpreterBytecodeArrayRegister,
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
  // Restart the current frame:
  // - Look up current function on the frame.
  // - Leave the frame.
  // - Restart the frame by calling the function.

  __ Ld_d(a1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ Ld_d(a0, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ LeaveFrame(StackFrame::INTERPRETED);

  // The arguments are already in the stack (including any necessary padding),
  // we should not try to massage the arguments again.
#ifdef V8_ENABLE_LEAPTIERING
  __ InvokeFunction(a1, a0, InvokeType::kJump,
                    ArgumentAdaptionMode::kDontAdapt);
#else
  __ li(a2, Operand(kDontAdaptArgumentsSentinel));
  __ InvokeFunction(a1, a2, a0, InvokeType::kJump);
#endif
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_LOONG64

"""


```
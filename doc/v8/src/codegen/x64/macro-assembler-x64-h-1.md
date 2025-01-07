Response:
Let's break down the thought process for analyzing this C++ header file and generating the summary.

1. **Understand the Goal:** The request asks for a functional summary of `macro-assembler-x64.h`, including specific considerations like Torque, JavaScript relevance, code logic, and common errors. The fact it's part 2 suggests there's a prior part describing the basics.

2. **Initial Scan and Keyword Spotting:** Quickly read through the code, looking for recurring patterns and keywords. Terms like `Load`, `Store`, `JumpIf`, `Compare`, `Call`, `Push`, `Pop`, `RecordWrite`, `InvokeFunction`, `StackHandler`, `Runtime`, `Counter`, `StackLimit` immediately jump out. These suggest the core functionality is about manipulating data in registers, memory, and the stack, controlling program flow, interacting with the runtime, and handling system-level concerns. The "x64" in the filename confirms this is architecture-specific assembly generation.

3. **Categorize Functionality:**  Start grouping the functions based on their apparent purpose. This is an iterative process, and initial categories might be broad and then refined.

    * **Memory Access:**  Functions with `Load`, `Store`, `FieldOperand`, `ExitFrameStackSlotOperand` clearly deal with reading and writing memory. The variations (`SandboxedPointer`, `ExternalPointer`, `TrustedPointer`, `CodePointer`, `IndirectPointer`) suggest different memory management schemes, possibly related to security or optimization.
    * **Control Flow:**  `JumpIf`, `Compare`, `TestCodeIsMarkedForDeoptimization` are related to conditional execution and code state.
    * **Stack Manipulation:** `Push`, `Pop`, `Drop`, `DropUnderReturnAddress`, `PushStackHandler`, `PopStackHandler` are all about stack management.
    * **Function Calls:** `InvokeFunction`, `CallRuntime`, `TailCallRuntime`, `CallApiFunctionAndReturn` are related to calling different types of functions (JavaScript, runtime, API).
    * **Object/Type Checks:** `CmpObjectType`, `IsObjectType`, `JumpIfJSAnyIsNotPrimitive`, `Assert*` functions are about verifying the type and state of objects.
    * **GC Support:** `RecordWriteField`, `RecordWrite`, `EnterExitFrame`, `LeaveExitFrame` clearly deal with garbage collection.
    * **Debugging/Assertions:** The `Assert*` functions and `CallDebugOnFunctionCall` point to debugging and validation capabilities.
    * **Performance/Optimization:**  The `Tiering support` section, `TryLoadOptimizedOsrCode`, and functions related to feedback vectors suggest optimization strategies.
    * **External References:**  Functions dealing with `ExternalReference` likely handle interactions with code or data outside the V8 heap.
    * **Counters/Statistics:** `IncrementCounter`, `DecrementCounter` are for performance monitoring.
    * **Stack Limits:** `StackLimitAsOperand`, `StackOverflowCheck` handle potential stack overflow errors.
    * **Weak References:** `LoadWeakValue` deals with a specific type of reference.

4. **Address Specific Questions:**

    * **Torque:** The prompt specifically asks about `.tq`. Since the file is `.h`, it's not a Torque file. State this clearly.
    * **JavaScript Relevance:**  Many functions directly relate to JavaScript concepts (functions, objects, contexts, calls). Provide concrete JavaScript examples that would *implicitly* trigger the use of these assembly-level functions (e.g., accessing object properties, calling functions, using `instanceof`). Emphasize that developers don't directly use these functions.
    * **Code Logic and Assumptions:**  Choose a few functions with clear logic (`CompareRange`, `JumpIfRoot`) and provide simple examples of inputs and expected behavior. This demonstrates how the assembly code would work.
    * **Common Programming Errors:** Think about JavaScript errors that could relate to the assembly functions. Type errors (using a non-object where an object is expected), stack overflows (deep recursion), and incorrect function calls (wrong number of arguments) are good examples.

5. **Synthesize and Summarize:**  Based on the categorized functionality, write a concise summary. Start with a high-level description of the file's purpose (low-level code generation for x64). Then, elaborate on the major categories of functionality identified earlier. Reiterate that this is *part 2*, building upon the basics covered in part 1.

6. **Refine and Organize:** Review the summary for clarity, accuracy, and completeness. Ensure the language is appropriate for someone familiar with programming concepts but possibly not V8 internals. Use bullet points or numbered lists for better readability.

7. **Self-Correction/Refinement during the Process:**

    * **Initial Broad Categories:**  Realize that "Memory Access" could be further divided into different types of pointers (sandboxed, external, etc.).
    * **Connecting to JavaScript:** Initially, you might just list the JavaScript-related function names. Then, realize you need to explain *how* these relate to actual JavaScript code. Provide the illustrative examples.
    * **Overlapping Functionality:** Notice that some functions serve multiple purposes (e.g., `RecordWrite` is GC support but also involves memory access). Mention these overlaps where appropriate.
    * **Level of Detail:** Decide on the appropriate level of technical detail. Avoid getting bogged down in the specifics of x64 assembly instructions unless absolutely necessary to explain the function's purpose. Focus on the *what* and *why* rather than the *how*.

By following these steps, you can systematically analyze a complex C++ header file and generate a comprehensive and informative summary.
Based on the provided code snippet from `v8/src/codegen/x64/macro-assembler-x64.h`, here's a breakdown of its functionalities:

**Core Functionality: Low-Level Code Generation for x64 Architecture**

This header file defines the `MacroAssembler` class for the x64 architecture within the V8 JavaScript engine. Its primary function is to provide an interface for generating machine code instructions directly. Think of it as a more abstract way to write assembly code, offering higher-level methods that correspond to common assembly patterns needed by V8.

**Specific Functionalities (as evident in this part of the code):**

* **Sandboxed Pointers:**  Provides mechanisms for loading and storing pointers that are managed within a sandbox for security purposes. This involves special handling to ensure these pointers remain within allowed memory regions.
    * `LoadSandboxedPointerField`
    * `StoreSandboxedPointerField`
    * `LoadExternalPointerField`: Handles decoding of off-heap pointers when sandboxing is enabled.

* **Trusted Pointers:** Deals with pointers that are considered "trusted" and might be subject to indirection via a table when sandboxing is enabled.
    * `LoadTrustedPointerField`
    * `StoreTrustedPointerField`
    * `LoadCodePointerField`:  A specialized version of trusted pointers for referencing code objects.
    * `StoreCodePointerField`

* **Indirect Pointers:**  Specifically for handling pointers that always go through an indirection table when sandboxing is enabled.
    * `LoadIndirectPointerField`
    * `StoreIndirectPointerField`

* **Resolving Indirect Pointer Handles (Sandboxing):** When sandboxing is active, these functions retrieve the actual heap object or code object from a handle (an index into a table).
    * `ResolveIndirectPointerHandle`
    * `ResolveTrustedPointerHandle`
    * `ResolveCodePointerHandle`
    * `LoadCodeEntrypointViaCodePointer`:  Retrieves the entry point of a code object through a code pointer.

* **Leaptiering Support (Optimization):**  If the `V8_ENABLE_LEAPTIERING` flag is defined, it includes functions for accessing JavaScript dispatch tables, used in optimized code execution.
    * `LoadEntrypointFromJSDispatchTable`
    * `LoadParameterCountFromJSDispatchTable`
    * `LoadEntrypointAndParameterCountFromJSDispatchTable`

* **Protected Pointers:**  Handles loading values from memory locations that might have special protection mechanisms.
    * `LoadProtectedPointerField`

* **External References:** Provides efficient ways to load and store values from memory locations outside the V8 heap, often used for interacting with the operating system or other libraries.
    * `Load(Register destination, ExternalReference source)`
    * `Store(ExternalReference destination, Register source)`
    * `PushAddress(ExternalReference source)`

* **Root Array Operations:**  Allows interaction with the V8 root array, a collection of important, globally accessible objects.
    * `PushRoot(RootIndex index)`
    * `JumpIfRoot`
    * `JumpIfNotRoot`

* **Garbage Collection (GC) Support:** Includes functions to inform the garbage collector about pointer writes, which is crucial for maintaining memory safety.
    * `RecordWriteField`
    * `RecordWrite`
    * `EnterExitFrame`: Sets up a special stack frame for calls into non-JavaScript code (like C++ runtime functions).
    * `LeaveExitFrame`: Tears down the exit frame.

* **JavaScript Function Invocation:** Provides different ways to call JavaScript functions, potentially with optimizations like leaptiering.
    * `InvokeFunctionCode`
    * `InvokeFunction`
    * `CallDebugOnFunctionCall`:  Used for debugging during function calls.

* **Macro Instructions (Higher-Level Assembly Operations):** Offers convenience methods for common assembly sequences.
    * `Cmp`:  Compare operations.
    * `CompareRange`, `JumpIfIsInRange`:  Efficiently checks if a value falls within a range.
    * `Drop`, `DropUnderReturnAddress`:  Manipulating the stack pointer.
    * `PushQuad`, `PushImm32`, `Pop`, `PopQuad`:  Stack operations for pushing and popping data.

* **Object Type Checking:**  Provides functions to efficiently determine the type of an object.
    * `CmpObjectType`
    * `IsObjectType`
    * `IsObjectTypeInRange`
    * `JumpIfJSAnyIsNotPrimitive`, `JumpIfJSAnyIsPrimitive`: Checks if a value is a primitive type.
    * `CmpInstanceTypeRange`

* **Field Decoding:**  Provides a template function to extract specific bitfields from a value.
    * `DecodeField`

* **Code Object Inspection:**  Functions to check the state of code objects (e.g., if they are marked for deoptimization).
    * `TestCodeIsMarkedForDeoptimization`
    * `TestCodeIsTurbofanned`
    * `ClearedValue`: Returns a cleared value representation.

* **Tiering Support (Optimization Continued):**  Further functions related to the tiered compilation system, including assertions and mechanisms to replace code with optimized versions.
    * `AssertFeedbackCell`, `AssertFeedbackVector`
    * `ReplaceClosureCodeWithOptimizedCode`
    * `GenerateTailCallToReturnedCode`
    * `CheckFeedbackVectorFlagsNeedsProcessing`, `CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing` (without `V8_ENABLE_LEAPTIERING`)
    * `OptimizeCodeOrTailCallOptimizedCodeSlot`

* **Assertions (Debug Checks):** Includes `Assert*` functions that trigger errors in debug builds if certain conditions are not met. These are crucial for verifying assumptions during development.
    * `AssertConstructor`
    * `AssertFunction`
    * `AssertCallableFunction`
    * `AssertBoundFunction`
    * `AssertGeneratorObject`
    * `AssertUndefinedOrAllocationSite`
    * `AssertJSAny`

* **Exception Handling:**  Provides mechanisms for managing exceptions at the assembly level.
    * `PushStackHandler`: Sets up a new exception handler.
    * `PopStackHandler`: Removes an exception handler.

* **Context Management:** Functions for loading specific slots from the current JavaScript context.
    * `LoadGlobalProxy`
    * `LoadNativeContextSlot`

* **Optimized Code Loading:**  Attempts to load optimized code if available.
    * `TryLoadOptimizedOsrCode`

* **Runtime Calls:**  Provides a way to call built-in C++ runtime functions within V8.
    * `CallRuntime`
    * `TailCallRuntime`
    * `JumpToExternalReference`

* **Performance Counters:**  Functions for incrementing and decrementing performance counters.
    * `IncrementCounter`, `EmitIncrementCounter`
    * `DecrementCounter`, `EmitDecrementCounter`

* **Stack Limit Checks:**  Functions to check for stack overflow conditions.
    * `StackLimitAsOperand`
    * `StackOverflowCheck`

* **Weak References:**  Handles loading values from weak references, which can be cleared by the garbage collector.
    * `LoadWeakValue`

**Regarding the `.tq` extension:**

The code you provided is a `.h` file, a standard C++ header file. Therefore, it is **not** a v8 Torque source code file. Torque files use the `.tq` extension.

**Relationship to JavaScript (with examples):**

While JavaScript developers don't directly interact with `macro-assembler-x64.h`, its functionality is fundamental to how JavaScript code is executed by V8. Every JavaScript operation, from simple arithmetic to complex function calls and object manipulations, eventually gets translated into machine code instructions generated (at least in part) using classes like `MacroAssembler`.

Here are some JavaScript examples and how they might relate:

1. **Accessing Object Properties:**

   ```javascript
   const obj = { x: 10 };
   const value = obj.x;
   ```

   Internally, V8 will use `LoadField` or similar functions to load the value of the `x` property from the object's memory location. The `FieldOperand` would be used to calculate the correct memory address.

2. **Calling a Function:**

   ```javascript
   function add(a, b) {
     return a + b;
   }
   add(5, 3);
   ```

   The `InvokeFunction` or `InvokeFunctionCode` methods would be used to generate the assembly instructions for setting up the call stack, passing arguments, and jumping to the function's code.

3. **Checking Object Type:**

   ```javascript
   const arr = [1, 2, 3];
   if (arr instanceof Array) {
     console.log("It's an array!");
   }
   ```

   The `CmpObjectType` or `IsObjectType` functions would be involved in comparing the object's type information with the `Array` type.

4. **Garbage Collection:**

   While invisible to the JavaScript developer, every time you assign an object to a variable:

   ```javascript
   let myObject = {};
   ```

   V8 might use `RecordWrite` to inform the garbage collector about this pointer write, ensuring proper memory management.

**Code Logic Inference (with assumptions):**

Let's take the `CompareRange` function as an example:

**Assumption:** The `CompareRange` function checks if a value in a register is within a specified unsigned range (inclusive).

**Input:**
* `value` register contains the number `7`.
* `lower_limit` is `5`.
* `higher_limit` is `10`.

**Assembly Logic (Conceptual):**

```assembly
  mov  rax, value_register  // Move the value into rax
  cmp  rax, lower_limit     // Compare with the lower limit
  jb   outside_range       // Jump below if rax < lower_limit (CF=1)
  cmp  rax, higher_limit    // Compare with the higher limit
  ja   outside_range       // Jump above if rax > higher_limit (CF=0 and ZF=0)

  // If we reach here, the value is in range (CF=0 or ZF=1)
```

**Output/Flags:** The CPU flags would be set such that the "below or equal" condition (CF=1 or ZF=1) would be true, indicating the value is within the range.

**Common Programming Errors (related to underlying assembly):**

1. **Stack Overflow:**  Deeply recursive JavaScript functions can exhaust the call stack. This directly relates to the stack manipulation functions (`Push`, `Pop`) and stack limit checks (`StackOverflowCheck`). The assembly code generated needs to carefully manage the stack to prevent overflows.

   ```javascript
   function recurse() {
     recurse();
   }
   recurse(); // Likely to cause a stack overflow
   ```

2. **Type Errors:** Performing operations on values of the wrong type (e.g., trying to access a property on a primitive) might lead to assembly code that attempts invalid memory access. The type checking functions (`CmpObjectType`, etc.) are designed to prevent such issues at runtime within V8.

   ```javascript
   let num = 5;
   num.toString(); // Works
   num.x;        // Type error: Cannot read properties of null (or undefined)
   ```

3. **Incorrect Function Calls:** Calling functions with the wrong number of arguments or with arguments of incompatible types can lead to errors during the function invocation process, which is handled by functions like `InvokeFunction`.

   ```javascript
   function greet(name) {
     console.log("Hello, " + name);
   }
   greet(); // Error: Expected 1 argument, but got 0.
   ```

**Summary of Functionality (Part 2):**

This portion of `v8/src/codegen/x64/macro-assembler-x64.h` primarily focuses on providing an interface for generating low-level x64 assembly code related to:

* **Memory Management and Pointer Handling:**  Specifically dealing with different types of pointers like sandboxed, trusted, and indirect pointers, especially in the context of security sandboxing.
* **Optimized Code Execution:**  Supporting features like leaptiering and providing mechanisms for loading and invoking optimized code.
* **Interaction with the V8 Runtime:**  Facilitating calls to built-in C++ runtime functions and managing external references.
* **Garbage Collection Support:**  Notifying the garbage collector about pointer writes.
* **JavaScript Function Invocation:**  Providing the building blocks for calling JavaScript functions.
* **Type Checking and Assertions:**  Ensuring the integrity of objects and code execution through runtime checks.
* **Exception Handling:**  Setting up and managing exception handling at the assembly level.
* **Performance Monitoring:**  Providing tools for tracking performance metrics.
* **Stack Management and Stack Overflow Prevention.**

Essentially, it provides the low-level machinery necessary for V8 to securely and efficiently execute JavaScript code on x64 architectures. This part builds upon the fundamental assembly generation capabilities likely introduced in the first part of the file.

Prompt: 
```
这是目录为v8/src/codegen/x64/macro-assembler-x64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/macro-assembler-x64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
code and store a SandboxedPointer to the heap.
  void StoreSandboxedPointerField(Operand dst_field_operand, Register value);

  enum class IsolateRootLocation { kInScratchRegister, kInRootRegister };
  // Loads a field containing off-heap pointer and does necessary decoding
  // if sandboxed external pointers are enabled.
  void LoadExternalPointerField(Register destination, Operand field_operand,
                                ExternalPointerTag tag, Register scratch,
                                IsolateRootLocation isolateRootLocation =
                                    IsolateRootLocation::kInRootRegister);

  // Load a trusted pointer field.
  // When the sandbox is enabled, these are indirect pointers using the trusted
  // pointer table. Otherwise they are regular tagged fields.
  void LoadTrustedPointerField(Register destination, Operand field_operand,
                               IndirectPointerTag tag, Register scratch);
  // Store a trusted pointer field.
  void StoreTrustedPointerField(Operand dst_field_operand, Register value);

  // Load a code pointer field.
  // These are special versions of trusted pointers that, when the sandbox is
  // enabled, reference code objects through the code pointer table.
  void LoadCodePointerField(Register destination, Operand field_operand,
                            Register scratch) {
    LoadTrustedPointerField(destination, field_operand, kCodeIndirectPointerTag,
                            scratch);
  }
  // Store a code pointer field.
  void StoreCodePointerField(Operand dst_field_operand, Register value) {
    StoreTrustedPointerField(dst_field_operand, value);
  }

  // Load an indirect pointer field.
  // Only available when the sandbox is enabled, but always visible to avoid
  // having to place the #ifdefs into the caller.
  void LoadIndirectPointerField(Register destination, Operand field_operand,
                                IndirectPointerTag tag, Register scratch);

  // Store an indirect pointer field.
  // Only available when the sandbox is enabled, but always visible to avoid
  // having to place the #ifdefs into the caller.
  void StoreIndirectPointerField(Operand dst_field_operand, Register value);

#ifdef V8_ENABLE_SANDBOX
  // Retrieve the heap object referenced by the given indirect pointer handle,
  // which can either be a trusted pointer handle or a code pointer handle.
  void ResolveIndirectPointerHandle(Register destination, Register handle,
                                    IndirectPointerTag tag);

  // Retrieve the heap object referenced by the given trusted pointer handle.
  void ResolveTrustedPointerHandle(Register destination, Register handle,
                                   IndirectPointerTag tag);

  // Retrieve the Code object referenced by the given code pointer handle.
  void ResolveCodePointerHandle(Register destination, Register handle);

  // Load the pointer to a Code's entrypoint via a code pointer.
  // Only available when the sandbox is enabled as it requires the code pointer
  // table.
  void LoadCodeEntrypointViaCodePointer(Register destination,
                                        Operand field_operand,
                                        CodeEntrypointTag tag);
#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_LEAPTIERING
  void LoadEntrypointFromJSDispatchTable(Register destination,
                                         Register dispatch_handle);
  void LoadParameterCountFromJSDispatchTable(Register destination,
                                             Register dispatch_handle);
  void LoadEntrypointAndParameterCountFromJSDispatchTable(
      Register entrypoint, Register parameter_count, Register dispatch_handle);
#endif  // V8_ENABLE_LEAPTIERING

  void LoadProtectedPointerField(Register destination, Operand field_operand);

  // Loads and stores the value of an external reference.
  // Special case code for load and store to take advantage of
  // load_rax/store_rax if possible/necessary.
  // For other operations, just use:
  //   Operand operand = ExternalReferenceAsOperand(extref);
  //   operation(operand, ..);
  void Load(Register destination, ExternalReference source);
  void Store(ExternalReference destination, Register source);

  // Pushes the address of the external reference onto the stack.
  void PushAddress(ExternalReference source);

  // Operations on roots in the root-array.
  // Load a root value where the index (or part of it) is variable.
  // The variable_offset register is added to the fixed_offset value
  // to get the index into the root-array.
  void PushRoot(RootIndex index);

  // Compare the object in a register to a value and jump if they are equal.
  void JumpIfRoot(Register with, RootIndex index, Label* if_equal,
                  Label::Distance if_equal_distance = Label::kFar) {
    CompareRoot(with, index);
    j(equal, if_equal, if_equal_distance);
  }
  void JumpIfRoot(Operand with, RootIndex index, Label* if_equal,
                  Label::Distance if_equal_distance = Label::kFar) {
    CompareRoot(with, index);
    j(equal, if_equal, if_equal_distance);
  }

  // Compare the object in a register to a value and jump if they are not equal.
  void JumpIfNotRoot(Register with, RootIndex index, Label* if_not_equal,
                     Label::Distance if_not_equal_distance = Label::kFar) {
    CompareRoot(with, index);
    j(not_equal, if_not_equal, if_not_equal_distance);
  }
  void JumpIfNotRoot(Operand with, RootIndex index, Label* if_not_equal,
                     Label::Distance if_not_equal_distance = Label::kFar) {
    CompareRoot(with, index);
    j(not_equal, if_not_equal, if_not_equal_distance);
  }

  // ---------------------------------------------------------------------------
  // GC Support

  // Notify the garbage collector that we wrote a pointer into an object.
  // |object| is the object being stored into, |value| is the object being
  // stored.  value and scratch registers are clobbered by the operation.
  // The offset is the offset from the start of the object, not the offset from
  // the tagged HeapObject pointer.  For use with FieldOperand(reg, off).
  void RecordWriteField(
      Register object, int offset, Register value, Register slot_address,
      SaveFPRegsMode save_fp, SmiCheck smi_check = SmiCheck::kInline,
      ReadOnlyCheck ro_check = ReadOnlyCheck::kInline,
      SlotDescriptor slot = SlotDescriptor::ForDirectPointerSlot());

  // For page containing |object| mark region covering |address|
  // dirty. |object| is the object being stored into, |value| is the
  // object being stored. The address and value registers are clobbered by the
  // operation.  RecordWrite filters out smis so it does not update
  // the write barrier if the value is a smi.
  void RecordWrite(
      Register object, Register slot_address, Register value,
      SaveFPRegsMode save_fp, SmiCheck smi_check = SmiCheck::kInline,
      ReadOnlyCheck ro_check = ReadOnlyCheck::kInline,
      SlotDescriptor slot = SlotDescriptor::ForDirectPointerSlot());

  // Allocates an EXIT/BUILTIN_EXIT/API_CALLBACK_EXIT frame with given number
  // of slots in non-GCed area.
  void EnterExitFrame(int extra_slots, StackFrame::Type frame_type,
                      Register c_function);
  void LeaveExitFrame();

  // ---------------------------------------------------------------------------
  // JavaScript invokes

  // The way we invoke JSFunctions differs depending on whether leaptiering is
  // enabled. As such, these functions exist in two variants. In the future,
  // leaptiering will be used on all platforms. At that point, the
  // non-leaptiering variants will disappear.

#ifdef V8_ENABLE_LEAPTIERING
  // Invoke the JavaScript function code by either calling or jumping.
  void InvokeFunctionCode(Register function, Register new_target,
                          Register actual_parameter_count, InvokeType type,
                          ArgumentAdaptionMode argument_adaption_mode =
                              ArgumentAdaptionMode::kAdapt);

  // Invoke the JavaScript function in the given register. Changes the
  // current context to the context in the function before invoking.
  void InvokeFunction(Register function, Register new_target,
                      Register actual_parameter_count, InvokeType type,
                      ArgumentAdaptionMode argument_adaption_mode =
                          ArgumentAdaptionMode::kAdapt);
#else
  // Invoke the JavaScript function code by either calling or jumping.
  void InvokeFunctionCode(Register function, Register new_target,
                          Register expected_parameter_count,
                          Register actual_parameter_count, InvokeType type);

  // Invoke the JavaScript function in the given register. Changes the
  // current context to the context in the function before invoking.
  void InvokeFunction(Register function, Register new_target,
                      Register actual_parameter_count, InvokeType type);

  void InvokeFunction(Register function, Register new_target,
                      Register expected_parameter_count,
                      Register actual_parameter_count, InvokeType type);
#endif  // V8_ENABLE_LEAPTIERING

  // On function call, call into the debugger.
  void CallDebugOnFunctionCall(
      Register fun, Register new_target,
      Register expected_parameter_count_or_dispatch_handle,
      Register actual_parameter_count);

  // ---------------------------------------------------------------------------
  // Macro instructions.

  void Cmp(Register dst, Handle<Object> source);
  void Cmp(Operand dst, Handle<Object> source);

  // Checks if value is in range [lower_limit, higher_limit] using a single
  // comparison. Flags CF=1 or ZF=1 indicate the value is in the range
  // (condition below_equal).
  void CompareRange(Register value, unsigned lower_limit,
                    unsigned higher_limit);
  void JumpIfIsInRange(Register value, unsigned lower_limit,
                       unsigned higher_limit, Label* on_in_range,
                       Label::Distance near_jump = Label::kFar);

  // Emit code to discard a non-negative number of pointer-sized elements
  // from the stack, clobbering only the rsp register.
  void Drop(int stack_elements);
  // Emit code to discard a positive number of pointer-sized elements
  // from the stack under the return address which remains on the top,
  // clobbering the rsp register.
  void DropUnderReturnAddress(int stack_elements,
                              Register scratch = kScratchRegister);
  void PushQuad(Operand src);
  void PushImm32(int32_t imm32);
  void Pop(Register dst);
  void Pop(Operand dst);
  void PopQuad(Operand dst);

  // Compare object type for heap object.
  // Always use unsigned comparisons: above and below, not less and greater.
  // Incoming register is heap_object and outgoing register is map.
  // They may be the same register, and may be kScratchRegister.
  void CmpObjectType(Register heap_object, InstanceType type, Register map);
  // Variant of the above, which only guarantees to set the correct
  // equal/not_equal flag. Map might not be loaded.
  void IsObjectType(Register heap_object, InstanceType type, Register scratch);
  // Variant of the above, which compares against a type range rather than a
  // single type (lower_limit and higher_limit are inclusive).
  //
  // Always use unsigned comparisons: below for a positive result.
  void IsObjectTypeInRange(Register heap_object, InstanceType low,
                           InstanceType high, Register scratch);
#if V8_STATIC_ROOTS_BOOL
  // Fast variant which is guaranteed to not actually load the instance type
  // from the map.
  void IsObjectTypeFast(Register heap_object, InstanceType type,
                        Register compressed_map_scratch);
  void CompareInstanceTypeWithUniqueCompressedMap(Register map,
                                                  InstanceType type);
#endif  // V8_STATIC_ROOTS_BOOL

  // Fast check if the object is a js receiver type. Assumes only primitive
  // objects or js receivers are passed.
  void JumpIfJSAnyIsNotPrimitive(
      Register heap_object, Register scratch, Label* target,
      Label::Distance distance = Label::kFar,
      Condition condition = Condition::kUnsignedGreaterThanEqual);
  void JumpIfJSAnyIsPrimitive(Register heap_object, Register scratch,
                              Label* target,
                              Label::Distance distance = Label::kFar) {
    return JumpIfJSAnyIsNotPrimitive(heap_object, scratch, target, distance,
                                     Condition::kUnsignedLessThan);
  }

  // Compare instance type ranges for a map (low and high inclusive)
  // Always use unsigned comparisons: below_equal for a positive result.
  void CmpInstanceTypeRange(Register map, Register instance_type_out,
                            InstanceType low, InstanceType high);

  template <typename Field>
  void DecodeField(Register reg) {
    static const int shift = Field::kShift;
    static const int mask = Field::kMask >> Field::kShift;
    if (shift != 0) {
      shrq(reg, Immediate(shift));
    }
    andq(reg, Immediate(mask));
  }

  void TestCodeIsMarkedForDeoptimization(Register code);
  void TestCodeIsTurbofanned(Register code);
  Immediate ClearedValue() const;

  // Tiering support.
  void AssertFeedbackCell(Register object,
                          Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void AssertFeedbackVector(Register object,
                            Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void ReplaceClosureCodeWithOptimizedCode(Register optimized_code,
                                           Register closure, Register scratch1,
                                           Register slot_address);
  void GenerateTailCallToReturnedCode(Runtime::FunctionId function_id,
                                      JumpMode jump_mode = JumpMode::kJump);
#ifndef V8_ENABLE_LEAPTIERING
  Condition CheckFeedbackVectorFlagsNeedsProcessing(Register feedback_vector,
                                                    CodeKind current_code_kind);
  void CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      Register feedback_vector, CodeKind current_code_kind,
      Label* flags_need_processing);
  void OptimizeCodeOrTailCallOptimizedCodeSlot(Register feedback_vector,
                                               Register closure,
                                               JumpMode jump_mode);
  // For compatibility with other archs.
  void OptimizeCodeOrTailCallOptimizedCodeSlot(Register flags,
                                               Register feedback_vector) {
    OptimizeCodeOrTailCallOptimizedCodeSlot(
        feedback_vector, kJSFunctionRegister, JumpMode::kJump);
  }
#endif  // !V8_ENABLE_LEAPTIERING

  // Abort execution if argument is not a Constructor, enabled via --debug-code.
  void AssertConstructor(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSFunction, enabled via --debug-code.
  void AssertFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a callable JSFunction, enabled via
  // --debug-code.
  void AssertCallableFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSBoundFunction,
  // enabled via --debug-code.
  void AssertBoundFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSGeneratorObject (or subclass),
  // enabled via --debug-code.
  void AssertGeneratorObject(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not undefined or an AllocationSite, enabled
  // via --debug-code.
  void AssertUndefinedOrAllocationSite(Register object) NOOP_UNLESS_DEBUG_CODE;

  void AssertJSAny(Register object, Register map_tmp,
                   AbortReason abort_reason) NOOP_UNLESS_DEBUG_CODE;

  // ---------------------------------------------------------------------------
  // Exception handling

  // Push a new stack handler and link it into stack handler chain.
  void PushStackHandler();

  // Unlink the stack handler on top of the stack from the stack handler chain.
  void PopStackHandler();

  // ---------------------------------------------------------------------------
  // Support functions.

  // Load the global proxy from the current context.
  void LoadGlobalProxy(Register dst) {
    LoadNativeContextSlot(dst, Context::GLOBAL_PROXY_INDEX);
  }

  // Load the native context slot with the current index.
  void LoadNativeContextSlot(Register dst, int index);

  // Falls through and sets scratch_and_result to 0 on failure, jumps to
  // on_result on success.
  void TryLoadOptimizedOsrCode(Register scratch_and_result,
                               CodeKind min_opt_level, Register feedback_vector,
                               FeedbackSlot slot, Label* on_result,
                               Label::Distance distance);

  // ---------------------------------------------------------------------------
  // Runtime calls

  // Call a runtime routine.
  void CallRuntime(const Runtime::Function* f, int num_arguments);

  // Convenience function: Same as above, but takes the fid instead.
  void CallRuntime(Runtime::FunctionId fid) {
    const Runtime::Function* function = Runtime::FunctionForId(fid);
    CallRuntime(function, function->nargs);
  }

  // Convenience function: Same as above, but takes the fid instead.
  void CallRuntime(Runtime::FunctionId fid, int num_arguments) {
    CallRuntime(Runtime::FunctionForId(fid), num_arguments);
  }

  // Convenience function: tail call a runtime routine (jump)
  void TailCallRuntime(Runtime::FunctionId fid);

  // Jump to a runtime routines
  void JumpToExternalReference(const ExternalReference& ext,
                               bool builtin_exit_frame = false);

  // ---------------------------------------------------------------------------
  // StatsCounter support
  void IncrementCounter(StatsCounter* counter, int value) {
    if (!v8_flags.native_code_counters) return;
    EmitIncrementCounter(counter, value);
  }
  void EmitIncrementCounter(StatsCounter* counter, int value);
  void DecrementCounter(StatsCounter* counter, int value) {
    if (!v8_flags.native_code_counters) return;
    EmitDecrementCounter(counter, value);
  }
  void EmitDecrementCounter(StatsCounter* counter, int value);

  // ---------------------------------------------------------------------------
  // Stack limit utilities
  Operand StackLimitAsOperand(StackLimitKind kind);
  void StackOverflowCheck(
      Register num_args, Label* stack_overflow,
      Label::Distance stack_overflow_distance = Label::kFar);

  // ---------------------------------------------------------------------------
  // In-place weak references.
  void LoadWeakValue(Register in_out, Label* target_if_cleared);

 protected:
  static const int kSmiShift = kSmiTagSize + kSmiShiftSize;

  // Returns a register holding the smi value. The register MUST NOT be
  // modified. It may be the "smi 1 constant" register.
  Register GetSmiConstant(Tagged<Smi> value);

  // Drops arguments assuming that the return address was already popped.
  void DropArguments(Register count);

 private:
  // Helper functions for generating invokes.
  void InvokePrologue(Register expected_parameter_count,
                      Register actual_parameter_count, InvokeType type);

  DISALLOW_IMPLICIT_CONSTRUCTORS(MacroAssembler);
};

// -----------------------------------------------------------------------------
// Static helper functions.

// Generate an Operand for loading a field from an object.
inline Operand FieldOperand(Register object, int offset) {
  return Operand(object, offset - kHeapObjectTag);
}

// For compatibility with platform-independent code.
inline MemOperand FieldMemOperand(Register object, int offset) {
  return MemOperand(object, offset - kHeapObjectTag);
}

// Generate an Operand for loading a field from an object. Object pointer is a
// compressed pointer when pointer compression is enabled.
inline Operand FieldOperand(TaggedRegister object, int offset) {
  if (COMPRESS_POINTERS_BOOL) {
    return Operand(kPtrComprCageBaseRegister, object.reg(),
                   ScaleFactor::times_1, offset - kHeapObjectTag);
  } else {
    return Operand(object.reg(), offset - kHeapObjectTag);
  }
}

// Generate an Operand for loading an indexed field from an object.
inline Operand FieldOperand(Register object, Register index, ScaleFactor scale,
                            int offset) {
  return Operand(object, index, scale, offset - kHeapObjectTag);
}

// Provides access to exit frame stack space (not GC-ed).
inline Operand ExitFrameStackSlotOperand(int offset) {
#ifdef V8_TARGET_OS_WIN
  return Operand(rsp, offset + kWindowsHomeStackSlots * kSystemPointerSize);
#else
  return Operand(rsp, offset);
#endif
}

// Provides access to exit frame parameters (GC-ed).
inline Operand ExitFrameCallerStackSlotOperand(int index) {
  return Operand(rbp,
                 (BuiltinExitFrameConstants::kFixedSlotCountAboveFp + index) *
                     kSystemPointerSize);
}

struct MoveCycleState {
  // Whether a move in the cycle needs the scratch or double scratch register.
  bool pending_scratch_register_use = false;
  bool pending_double_scratch_register_use = false;
};

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
                              MemOperand return_value_operand);

#define ACCESS_MASM(masm) masm->

}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_X64_MACRO_ASSEMBLER_X64_H_

"""


```
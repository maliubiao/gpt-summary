Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/x64/macro-assembler-x64.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The filename `macro-assembler-x64.cc` strongly suggests this code is responsible for generating x64 assembly instructions. The `MacroAssembler` class is central to this.

2. **Categorize Functionality:**  Scan the code for common assembly operations and group them. Look for verbs like `Cmp`, `Jump`, `Push`, `Move`, `Call`, `Pop`, etc. This immediately reveals categories like:
    * Comparison operations (`Cmp`, `CompareRange`, `JumpIfIsInRange`)
    * Stack manipulation (`Push`, `Pop`, `Drop`)
    * Data movement (`Move`)
    * Control flow (`Jump`, `Call`, `Ret`)
    * Built-in function handling (`CallBuiltin`, `TailCallBuiltin`)
    * Code object manipulation (`LoadCodeInstructionStart`, `CallCodeObject`, `JumpCodeObject`)
    * JavaScript function calls (`CallJSFunction`, `JumpJSFunction`)
    * WebAssembly integration (`ResolveWasmCodePointer`, `CallWasmCodePointer`, `LoadWasmCodePointer`)
    * Low-level bit manipulation (`Lzcntl`, `Lzcntq`, `Tzcntq`, `Tzcntl`, `Popcntl`, `Popcntq`)
    * Stack frame management (`PushStackHandler`, `PopStackHandler`)
    * Type checking (`IsObjectType`, `IsObjectTypeInRange`, `CmpObjectType`, `CmpInstanceType`, `CmpInstanceTypeRange`)
    * Debug assertions (`AssertNotSmi`, `AssertSmi`, etc.)

3. **Address Specific User Queries:** Go through the user's specific questions:

    * **List the functions:** This is covered by the categorization above. Be more specific within each category.
    * **`.tq` extension:** State that it's not a Torque file because it doesn't end in `.tq`.
    * **Relationship to JavaScript:**  Look for functions that explicitly mention JavaScript (e.g., `CallJSFunction`, `JumpJSFunction`). Explain how these functions are used to execute JavaScript code by interacting with `JSFunction` objects. Provide a simple JavaScript example that demonstrates a function call, which would implicitly use these underlying mechanisms.
    * **Code logic/reasoning:** Choose a simple function with clear logic. `CompareRange` is a good candidate. Explain its purpose (checking if a value is within a range). Provide an example with clear input (value, lower limit, upper limit) and the expected output (whether the comparison flags would indicate the value is in range).
    * **Common programming errors:** Think about how the assembly instructions could be misused. Incorrect stack management (e.g., mismatched `Push` and `Pop`) is a classic error. Provide a C++-like example to illustrate this.
    * **Overall function (summarization):** Synthesize the categorized functions into a high-level summary. Emphasize that it's a low-level code generator for the x64 architecture, used by the V8 JavaScript engine.

4. **Structure the Answer:** Organize the information logically, using headings and bullet points for clarity.

5. **Refine and Elaborate:**  Review the generated answer for completeness and accuracy. Add details where necessary to make the explanations clearer. For example, when discussing JavaScript interaction, mention `JSFunction` objects and the concept of calling functions. For the programming error example, explain *why* the stack imbalance is a problem.

6. **Consider Edge Cases/Nuances:** While not explicitly asked, recognize that some functions have conditional compilation (`#ifdef`), indicating platform-specific behavior or feature flags. Briefly acknowledge this.

By following these steps, we can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
Based on the provided code snippet from `v8/src/codegen/x64/macro-assembler-x64.cc`, here's a breakdown of its functionality:

**Core Functionality: Low-Level Assembly Code Generation for x64 Architecture**

This code defines part of the `MacroAssembler` class for the x64 architecture in V8. The `MacroAssembler` provides a high-level C++ interface to generate raw x64 machine code instructions. It abstracts away the complexities of direct assembly coding, allowing V8's compiler and runtime to emit efficient machine code.

Here's a breakdown of the specific functionalities present in this snippet:

* **Comparison Operations:**
    * `Cmp(Operand dst, Smi source)`: Compares a destination operand with a Small Integer (Smi).
    * `Cmp(Operand dst, Handle<Object> source)`: Compares a destination operand with a Heap Object (potentially Smi or other object types). It handles different scenarios like Smi comparison, embedded objects, and isolate-independent code.
    * `CompareRange(Register value, unsigned lower_limit, unsigned higher_limit)`:  Efficiently checks if a register's value falls within a specified unsigned range.
    * `JumpIfIsInRange(...)`: Jumps to a target label if a register's value is within a given range.

* **Stack Manipulation:**
    * `Push(Handle<HeapObject> source)`: Pushes a Heap Object onto the stack.
    * `PushArray(...)`: Pushes the contents of an array onto the stack in either forward or reverse order.
    * `Drop(int stack_elements)`: Adjusts the stack pointer to effectively discard a specified number of stack elements.
    * `DropUnderReturnAddress(...)`: Drops stack elements while preserving the return address.
    * `DropArguments(...)`: Adjusts the stack pointer to discard function arguments.
    * `DropArgumentsAndPushNewReceiver(...)`: Drops arguments and pushes a new receiver object onto the stack.
    * `Push(Register src)`, `Push(Operand src)`, `PushQuad(Operand src)`, `Push(Immediate value)`, `PushImm32(int32_t imm32)`: Various forms of pushing data onto the stack.
    * `Pop(Register dst)`, `Pop(Operand dst)`, `PopQuad(Operand dst)`:  Pops data from the stack into a register or memory location.

* **Control Flow:**
    * `Jump(const ExternalReference& reference)`: Jumps to an external function address.
    * `Jump(Operand op)`, `Jump(Operand op, Condition cc)`: Unconditional and conditional jumps to a specified operand (usually a memory location containing the target address).
    * `Jump(Address destination, RelocInfo::Mode rmode)`, `Jump(Address destination, RelocInfo::Mode rmode, Condition cc)`: Jumps to a direct memory address.
    * `Jump(Handle<Code> code_object, RelocInfo::Mode rmode)`, `Jump(Handle<Code> code_object, RelocInfo::Mode rmode, Condition cc)`: Jumps to the entry point of a Code object (compiled JavaScript or built-in code). Handles tail calls to built-ins.
    * `Call(ExternalReference ext)`: Calls an external function.
    * `Call(Operand op)`: Calls a function at the address specified by the operand.
    * `Call(Address destination, RelocInfo::Mode rmode)`: Calls a function at a direct memory address.
    * `Call(Handle<Code> code_object, RelocInfo::Mode rmode)`: Calls a Code object.
    * `CallBuiltinByIndex(Register builtin_index)`: Calls a built-in function based on its index.
    * `CallBuiltin(Builtin builtin)`: Calls a specific built-in function.
    * `TailCallBuiltin(Builtin builtin)`, `TailCallBuiltin(Builtin builtin, Condition cc)`: Performs a tail call to a built-in function (optimizes function calls where the current function's stack frame is no longer needed).
    * `Ret()`, `Ret(int bytes_dropped, Register scratch)`: Returns from a function, optionally adjusting the stack pointer.

* **Data Movement:**
    * `Move(Register result, Handle<HeapObject> object, RelocInfo::Mode rmode)`: Moves a Heap Object into a register, handling different relocation modes (how addresses are adjusted during linking).
    * `Move(Operand dst, Handle<HeapObject> object, RelocInfo::Mode rmode)`: Moves a Heap Object to a memory location.

* **Code Object Interaction:**
    * `LoadCodeInstructionStart(...)`: Loads the starting address of the executable code within a Code object.
    * `CallCodeObject(...)`: Calls a Code object.
    * `JumpCodeObject(...)`: Jumps to a Code object.

* **JavaScript Function Calls:**
    * `CallJSFunction(...)`:  Specifically handles calling JavaScript functions, including dispatch handle lookup and parameter count checking (with LEAPTIERING enabled).
    * `JumpJSFunction(...)`: Jumps to a JavaScript function.

* **WebAssembly Integration:**
    * `ResolveWasmCodePointer(...)`: Resolves a WebAssembly code pointer from a table.
    * `CallWasmCodePointer(...)`: Calls a WebAssembly function using a resolved pointer.
    * `LoadWasmCodePointer(...)`: Loads a WebAssembly code pointer.

* **Low-Level Bit Manipulation (Potentially with CPU Feature Checks):**
    * `Lzcntl(...)`, `Lzcntq(...)`: Counts leading zeros in a register or memory location.
    * `Tzcntq(...)`, `Tzcntl(...)`: Counts trailing zeros in a register or memory location.
    * `Popcntl(...)`, `Popcntq(...)`: Counts the number of set bits (population count) in a register or memory location.

* **Stack Handler Management (Exception Handling):**
    * `PushStackHandler()`: Pushes a new stack handler onto the stack, used for exception handling.
    * `PopStackHandler()`: Removes the current stack handler from the stack.

* **Conditional Security Feature:**
    * `IncsspqIfSupported(...)`: Conditionally increments the shadow stack pointer if the CPU supports CET-SS (Control-flow Enforcement Technology Shadow Stack).

* **Type Checking:**
    * `CompareInstanceTypeWithUniqueCompressedMap(...)`: Compares the instance type of an object's map with a known unique map.
    * `IsObjectTypeFast(...)`: Quickly checks if an object is of a specific type using compressed maps.
    * `IsObjectType(...)`: Checks if a Heap Object is of a specific instance type.
    * `IsObjectTypeInRange(...)`: Checks if a Heap Object's type falls within a range of instance types.
    * `JumpIfJSAnyIsNotPrimitive(...)`: Jumps if a Heap Object is not a primitive value.
    * `CmpObjectType(...)`: Compares the instance type of a Heap Object.
    * `CmpInstanceType(...)`: Compares an instance type value.
    * `CmpInstanceTypeRange(...)`: Checks if an instance type falls within a range.

* **Code Object Status Checks:**
    * `TestCodeIsMarkedForDeoptimization(...)`: Checks if a Code object is marked for deoptimization (indicating a performance issue).
    * `TestCodeIsTurbofanned(...)`: Checks if a Code object was generated by the Turbofan optimizing compiler.

* **Utilities:**
    * `ClearedValue()`: Returns an immediate representing the cleared value.

* **Debug Assertions (when `v8_flags.debug_code` is enabled):**  These functions are used to verify assumptions and catch errors during development. Examples include:
    * `AssertNotSmi(...)`, `AssertSmi(...)`: Checks if a value is or is not a Small Integer.
    * `AssertZeroExtended(...)`: Checks if a register contains a zero-extended 32-bit value.
    * `AssertSignedBitOfSmiIsZero(...)`: Checks the signed bit of a Smi.
    * `AssertMap(...)`, `AssertCode(...)`: Checks if an object is a Map or Code object.
    * `AssertSmiOrHeapObjectInMainCompressionCage(...)`: Checks if an object is correctly tagged in a compressed pointer environment.
    * `AssertConstructor(...)`, `AssertFunction(...)`: Checks if an object is a constructor or a function.

**Is `v8/src/codegen/x64/macro-assembler-x64.cc` a Torque file?**

No, it is not a Torque file. The user's condition states that if a file in that directory ends with `.tq`, it's a Torque source file. This file ends with `.cc`, indicating it's a C++ source file.

**Relationship to JavaScript and Example:**

This code is fundamental to how V8 executes JavaScript. When V8 compiles JavaScript code, the `MacroAssembler` is used to generate the actual x64 machine code that the CPU will execute. Functions like `CallJSFunction` and `JumpJSFunction` directly interact with JavaScript function objects.

**JavaScript Example:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result); // Output: 8
```

When V8 executes this JavaScript code, the `add` function will be compiled into x64 machine code using the `MacroAssembler`. The `CallJSFunction` (or similar) functionality would be used when calling the `add` function. This involves:

1. **Loading the `add` function object.**
2. **Looking up the compiled code for `add`.**
3. **Setting up the arguments (5 and 3) on the stack.**
4. **Jumping to the entry point of the compiled code for `add`.**

**Code Logic Reasoning with Example:**

Let's take the `CompareRange` function:

```c++
void MacroAssembler::CompareRange(Register value, unsigned lower_limit,
                                  unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    leal(kScratchRegister, Operand(value, 0u - lower_limit));
    cmpl(kScratchRegister, Immediate(higher_limit - lower_limit));
  } else {
    cmpl(value, Immediate(higher_limit));
  }
}
```

**Assumptions:**

* `value`:  A register holding the unsigned integer to be checked.
* `lower_limit`: The lower bound of the range (inclusive).
* `higher_limit`: The upper bound of the range (exclusive).
* `kScratchRegister`: A temporary register available for use.

**Logic:**

The function efficiently checks if `lower_limit <= value < higher_limit`.

* **If `lower_limit` is not 0:**
    1. It calculates `value - lower_limit` and stores it in `kScratchRegister`. The `leal` instruction performs address calculation without actually accessing memory.
    2. It then compares `kScratchRegister` (which holds `value - lower_limit`) with `higher_limit - lower_limit`. If `value` is within the range, `value - lower_limit` will be less than `higher_limit - lower_limit`.
* **If `lower_limit` is 0:**
    1. It directly compares `value` with `higher_limit`.

**Example Input and Output:**

* **Input:** `value` contains `7`, `lower_limit` is `5`, `higher_limit` is `10`.
* **Output:**
    * Since `lower_limit` is not 0:
        * `kScratchRegister` will be loaded with `7 - 5 = 2`.
        * The comparison will be `cmp 2, Immediate(10 - 5)`, which is `cmp 2, Immediate(5)`.
        * The comparison flags will be set such that a subsequent "below" or "below or equal" jump would be taken.

**User Common Programming Errors:**

Using the `MacroAssembler` directly is rare for most JavaScript developers. However, V8 developers working on the compiler or runtime can make errors. Here's a common type of error related to stack manipulation:

**Example:** Incorrectly balancing the stack.

```c++
void MyIncorrectFunction(MacroAssembler* masm) {
  // ... some code ...
  masm->Push(rax);
  // ... some other code ...
  // Oops! Forgot to pop rax before returning.
  masm->Ret();
}
```

**Explanation:**

In this example, a value is pushed onto the stack using `Push(rax)`, but there's no corresponding `Pop` instruction before the `Ret()`. This leads to a stack imbalance. When the `Ret()` instruction is executed, it will pop the return address from the wrong location on the stack, leading to a crash or unpredictable behavior.

**Functionality Summary (Part 4 of 6):**

This portion of `macro-assembler-x64.cc` focuses on providing methods for:

* **Comparing values** (Smis, Heap Objects, and ranges).
* **Manipulating the stack** (pushing, popping, and dropping elements and arguments).
* **Controlling program flow** (unconditional and conditional jumps and calls to various types of functions: external, built-in, JavaScript, and WebAssembly).
* **Moving data** between registers and memory, especially handling Heap Objects.
* **Interacting with Code objects** (loading entry points, calling, and jumping).
* **Performing low-level bitwise operations.**
* **Managing stack handlers for exception handling.**
* **Performing type checks on Heap Objects.**
* **Including debug assertions to catch development errors.**

In essence, it's a collection of foundational building blocks for generating x64 assembly code within the V8 JavaScript engine, dealing with fundamental operations needed for executing JavaScript and other code.

### 提示词
```
这是目录为v8/src/codegen/x64/macro-assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/macro-assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ter, Cast<HeapObject>(source));
    cmp_tagged(dst, kScratchRegister);
  } else if (COMPRESS_POINTERS_BOOL) {
    EmbeddedObjectIndex index = AddEmbeddedObject(Cast<HeapObject>(source));
    DCHECK(is_uint32(index));
    cmpl(dst, Immediate(static_cast<int>(index),
                        RelocInfo::COMPRESSED_EMBEDDED_OBJECT));
  } else {
    movq(kScratchRegister,
         Immediate64(source.address(), RelocInfo::FULL_EMBEDDED_OBJECT));
    cmpq(dst, kScratchRegister);
  }
}

void MacroAssembler::Cmp(Operand dst, Handle<Object> source) {
  if (IsSmi(*source)) {
    Cmp(dst, Cast<Smi>(*source));
  } else if (root_array_available_ && options().isolate_independent_code) {
    // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
    // non-isolate-independent code. In many cases it might be cheaper than
    // embedding the relocatable value.
    // TODO(v8:9706): Fix-it! This load will always uncompress the value
    // even when we are loading a compressed embedded object.
    IndirectLoadConstant(kScratchRegister, Cast<HeapObject>(source));
    cmp_tagged(dst, kScratchRegister);
  } else if (COMPRESS_POINTERS_BOOL) {
    EmbeddedObjectIndex index = AddEmbeddedObject(Cast<HeapObject>(source));
    DCHECK(is_uint32(index));
    cmpl(dst, Immediate(static_cast<int>(index),
                        RelocInfo::COMPRESSED_EMBEDDED_OBJECT));
  } else {
    Move(kScratchRegister, Cast<HeapObject>(source),
         RelocInfo::FULL_EMBEDDED_OBJECT);
    cmp_tagged(dst, kScratchRegister);
  }
}

void MacroAssembler::CompareRange(Register value, unsigned lower_limit,
                                  unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    leal(kScratchRegister, Operand(value, 0u - lower_limit));
    cmpl(kScratchRegister, Immediate(higher_limit - lower_limit));
  } else {
    cmpl(value, Immediate(higher_limit));
  }
}

void MacroAssembler::JumpIfIsInRange(Register value, unsigned lower_limit,
                                     unsigned higher_limit, Label* on_in_range,
                                     Label::Distance near_jump) {
  CompareRange(value, lower_limit, higher_limit);
  j(below_equal, on_in_range, near_jump);
}

void MacroAssembler::Push(Handle<HeapObject> source) {
  Move(kScratchRegister, source);
  Push(kScratchRegister);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               PushArrayOrder order) {
  DCHECK(!AreAliased(array, size, scratch));
  Register counter = scratch;
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    Move(counter, 0);
    jmp(&entry);
    bind(&loop);
    Push(Operand(array, counter, times_system_pointer_size, 0));
    incq(counter);
    bind(&entry);
    cmpq(counter, size);
    j(less, &loop, Label::kNear);
  } else {
    movq(counter, size);
    jmp(&entry);
    bind(&loop);
    Push(Operand(array, counter, times_system_pointer_size, 0));
    bind(&entry);
    decq(counter);
    j(greater_equal, &loop, Label::kNear);
  }
}

void MacroAssembler::Move(Register result, Handle<HeapObject> object,
                          RelocInfo::Mode rmode) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    // TODO(v8:9706): Fix-it! This load will always uncompress the value
    // even when we are loading a compressed embedded object.
    IndirectLoadConstant(result, object);
  } else if (RelocInfo::IsCompressedEmbeddedObject(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(object);
    DCHECK(is_uint32(index));
    movl(result, Immediate(static_cast<int>(index), rmode));
  } else {
    DCHECK(RelocInfo::IsFullEmbeddedObject(rmode));
    movq(result, Immediate64(object.address(), rmode));
  }
}

void MacroAssembler::Move(Operand dst, Handle<HeapObject> object,
                          RelocInfo::Mode rmode) {
  Move(kScratchRegister, object, rmode);
  movq(dst, kScratchRegister);
}

void MacroAssembler::Drop(int stack_elements) {
  if (stack_elements > 0) {
    addq(rsp, Immediate(stack_elements * kSystemPointerSize));
  }
}

void MacroAssembler::DropUnderReturnAddress(int stack_elements,
                                            Register scratch) {
  DCHECK_GT(stack_elements, 0);
  if (stack_elements == 1) {
    popq(MemOperand(rsp, 0));
    return;
  }

  PopReturnAddressTo(scratch);
  Drop(stack_elements);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::DropArguments(Register count) {
  leaq(rsp, Operand(rsp, count, times_system_pointer_size, 0));
}

void MacroAssembler::DropArguments(Register count, Register scratch) {
  DCHECK(!AreAliased(count, scratch));
  PopReturnAddressTo(scratch);
  DropArguments(count);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver,
                                                     Register scratch) {
  DCHECK(!AreAliased(argc, receiver, scratch));
  PopReturnAddressTo(scratch);
  DropArguments(argc);
  Push(receiver);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Operand receiver,
                                                     Register scratch) {
  DCHECK(!AreAliased(argc, scratch));
  DCHECK(!receiver.AddressUsesRegister(scratch));
  PopReturnAddressTo(scratch);
  DropArguments(argc);
  Push(receiver);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::Push(Register src) { pushq(src); }

void MacroAssembler::Push(Operand src) { pushq(src); }

void MacroAssembler::PushQuad(Operand src) { pushq(src); }

void MacroAssembler::Push(Immediate value) { pushq(value); }

void MacroAssembler::PushImm32(int32_t imm32) { pushq_imm32(imm32); }

void MacroAssembler::Pop(Register dst) { popq(dst); }

void MacroAssembler::Pop(Operand dst) { popq(dst); }

void MacroAssembler::PopQuad(Operand dst) { popq(dst); }

void MacroAssembler::Jump(const ExternalReference& reference) {
  DCHECK(root_array_available());
  jmp(Operand(kRootRegister, RootRegisterOffsetForExternalReferenceTableEntry(
                                 isolate(), reference)));
}

void MacroAssembler::Jump(Operand op) { jmp(op); }

void MacroAssembler::Jump(Operand op, Condition cc) {
  Label skip;
  j(NegateCondition(cc), &skip, Label::kNear);
  Jump(op);
  bind(&skip);
}

void MacroAssembler::Jump(Address destination, RelocInfo::Mode rmode) {
  Move(kScratchRegister, destination, rmode);
  jmp(kScratchRegister);
}

void MacroAssembler::Jump(Address destination, RelocInfo::Mode rmode,
                          Condition cc) {
  Label skip;
  j(NegateCondition(cc), &skip, Label::kNear);
  Jump(destination, rmode);
  bind(&skip);
}

void MacroAssembler::Jump(Handle<Code> code_object, RelocInfo::Mode rmode) {
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code_object));
  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code_object, &builtin)) {
    TailCallBuiltin(builtin);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  jmp(code_object, rmode);
}

void MacroAssembler::Jump(Handle<Code> code_object, RelocInfo::Mode rmode,
                          Condition cc) {
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code_object));
  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code_object, &builtin)) {
    TailCallBuiltin(builtin, cc);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  j(cc, code_object, rmode);
}

void MacroAssembler::Call(ExternalReference ext) {
  LoadAddress(kScratchRegister, ext);
  call(kScratchRegister);
}

void MacroAssembler::Call(Operand op) {
  if (!CpuFeatures::IsSupported(INTEL_ATOM)) {
    call(op);
  } else {
    movq(kScratchRegister, op);
    call(kScratchRegister);
  }
}

void MacroAssembler::Call(Address destination, RelocInfo::Mode rmode) {
  Move(kScratchRegister, destination, rmode);
  call(kScratchRegister);
}

void MacroAssembler::Call(Handle<Code> code_object, RelocInfo::Mode rmode) {
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code_object));
  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code_object, &builtin)) {
    CallBuiltin(builtin);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  call(code_object, rmode);
}

Operand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  DCHECK(root_array_available());
  return Operand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(builtin));
}

Operand MacroAssembler::EntryFromBuiltinIndexAsOperand(Register builtin_index) {
  if (SmiValuesAre32Bits()) {
    // The builtin_index register contains the builtin index as a Smi.
    Move(kScratchRegister, builtin_index);  // Callee checks for equality.
    SmiUntagUnsigned(kScratchRegister);
    return Operand(kRootRegister, kScratchRegister, times_system_pointer_size,
                   IsolateData::builtin_entry_table_offset());
  } else {
    DCHECK(SmiValuesAre31Bits());

    // The builtin_index register contains the builtin index as a Smi.
    // Untagging is folded into the indexing operand below (we use
    // times_half_system_pointer_size since smis are already shifted by one).
    return Operand(kRootRegister, builtin_index, times_half_system_pointer_size,
                   IsolateData::builtin_entry_table_offset());
  }
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index) {
  Call(EntryFromBuiltinIndexAsOperand(builtin_index));
}

void MacroAssembler::CallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute:
      Call(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET);
      break;
    case BuiltinCallJumpMode::kPCRelative:
      near_call(static_cast<intptr_t>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect:
      Call(EntryFromBuiltinAsOperand(builtin));
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      call(code, RelocInfo::CODE_TARGET);
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute:
      Jump(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET);
      break;
    case BuiltinCallJumpMode::kPCRelative:
      near_jmp(static_cast<intptr_t>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect:
      Jump(EntryFromBuiltinAsOperand(builtin));
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      jmp(code, RelocInfo::CODE_TARGET);
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cc) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute:
      Jump(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET, cc);
      break;
    case BuiltinCallJumpMode::kPCRelative:
      near_j(cc, static_cast<intptr_t>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect:
      Jump(EntryFromBuiltinAsOperand(builtin), cc);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      j(cc, code, RelocInfo::CODE_TARGET);
      break;
    }
  }
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      destination, FieldOperand(code_object, Code::kSelfIndirectPointerOffset),
      tag);
#else
  movq(destination, FieldOperand(code_object, Code::kInstructionStartOffset));
#endif
}

void MacroAssembler::CallCodeObject(Register code_object,
                                    CodeEntrypointTag tag) {
  LoadCodeInstructionStart(code_object, code_object, tag);
  call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, CodeEntrypointTag tag,
                                    JumpMode jump_mode) {
  // TODO(saelo): can we avoid using this for JavaScript functions
  // (kJSEntrypointTag) and instead use a variant that ensures that the caller
  // and callee agree on the signature (i.e. parameter count)?
  LoadCodeInstructionStart(code_object, code_object, tag);
  switch (jump_mode) {
    case JumpMode::kJump:
      jmp(code_object);
      return;
    case JumpMode::kPushAndReturn:
      pushq(code_object);
      Ret();
      return;
  }
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
#if V8_ENABLE_LEAPTIERING
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  static_assert(kJavaScriptCallDispatchHandleRegister == r15, "ABI mismatch");
  movl(r15, FieldOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointAndParameterCountFromJSDispatchTable(rcx, rbx, r15);
  // Force a safe crash if the parameter count doesn't match.
  cmpl(rbx, Immediate(argument_count));
  SbxCheck(less_equal, AbortReason::kJSSignatureMismatch);
  call(rcx);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      rcx, FieldOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  call(rcx);
#else
  LoadTaggedField(rcx, FieldOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(rcx, kJSEntrypointTag);
#endif
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
#if V8_ENABLE_LEAPTIERING
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  static_assert(kJavaScriptCallDispatchHandleRegister == r15, "ABI mismatch");
  movl(r15, FieldOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointFromJSDispatchTable(rcx, r15);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  jmp(rcx);
  // This implementation is not currently used because callers usually need
  // to load both entry point and parameter count and then do something with
  // the latter before the actual call.
  // TODO(ishell): remove the above code once it's clear it's not needed.
  UNREACHABLE();
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      rcx, FieldOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  jmp(rcx);
#else
  LoadTaggedField(rcx, FieldOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(rcx, kJSEntrypointTag, jump_mode);
#endif
}

void MacroAssembler::ResolveWasmCodePointer(Register target) {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  ExternalReference global_jump_table =
      ExternalReference::wasm_code_pointer_table();
  Move(kScratchRegister, global_jump_table);
  static_assert(sizeof(wasm::WasmCodePointerTableEntry) == 8);
  movq(target, Operand(kScratchRegister, target, ScaleFactor::times_8, 0));
#endif
}

void MacroAssembler::CallWasmCodePointer(Register target,
                                         CallJumpMode call_jump_mode) {
  ResolveWasmCodePointer(target);
  if (call_jump_mode == CallJumpMode::kTailCall) {
    jmp(target);
  } else {
    call(target);
  }
}

void MacroAssembler::LoadWasmCodePointer(Register dst, Operand src) {
  if constexpr (V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL) {
    static_assert(!V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL ||
                  sizeof(WasmCodePointer) == 4);
    movl(dst, src);
  } else {
    static_assert(V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL ||
                  sizeof(WasmCodePointer) == 8);
    movq(dst, src);
  }
}

void MacroAssembler::PextrdPreSse41(Register dst, XMMRegister src,
                                    uint8_t imm8) {
  if (imm8 == 0) {
    Movd(dst, src);
    return;
  }
  DCHECK_EQ(1, imm8);
  movq(dst, src);
  shrq(dst, Immediate(32));
}

namespace {
template <typename Op>
void PinsrdPreSse41Helper(MacroAssembler* masm, XMMRegister dst, Op src,
                          uint8_t imm8, uint32_t* load_pc_offset) {
  masm->Movd(kScratchDoubleReg, src);
  if (load_pc_offset) *load_pc_offset = masm->pc_offset();
  if (imm8 == 1) {
    masm->punpckldq(dst, kScratchDoubleReg);
  } else {
    DCHECK_EQ(0, imm8);
    masm->Movss(dst, kScratchDoubleReg);
  }
}
}  // namespace

void MacroAssembler::PinsrdPreSse41(XMMRegister dst, Register src, uint8_t imm8,
                                    uint32_t* load_pc_offset) {
  PinsrdPreSse41Helper(this, dst, src, imm8, load_pc_offset);
}

void MacroAssembler::PinsrdPreSse41(XMMRegister dst, Operand src, uint8_t imm8,
                                    uint32_t* load_pc_offset) {
  PinsrdPreSse41Helper(this, dst, src, imm8, load_pc_offset);
}

void MacroAssembler::Pinsrq(XMMRegister dst, XMMRegister src1, Register src2,
                            uint8_t imm8, uint32_t* load_pc_offset) {
  PinsrHelper(this, &Assembler::vpinsrq, &Assembler::pinsrq, dst, src1, src2,
              imm8, load_pc_offset, {SSE4_1});
}

void MacroAssembler::Pinsrq(XMMRegister dst, XMMRegister src1, Operand src2,
                            uint8_t imm8, uint32_t* load_pc_offset) {
  PinsrHelper(this, &Assembler::vpinsrq, &Assembler::pinsrq, dst, src1, src2,
              imm8, load_pc_offset, {SSE4_1});
}

void MacroAssembler::Lzcntl(Register dst, Register src) {
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcntl(dst, src);
    return;
  }
  Label not_zero_src;
  bsrl(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 63);  // 63^31 == 32
  bind(&not_zero_src);
  xorl(dst, Immediate(31));  // for x in [0..31], 31^x == 31 - x
}

void MacroAssembler::Lzcntl(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcntl(dst, src);
    return;
  }
  Label not_zero_src;
  bsrl(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 63);  // 63^31 == 32
  bind(&not_zero_src);
  xorl(dst, Immediate(31));  // for x in [0..31], 31^x == 31 - x
}

void MacroAssembler::Lzcntq(Register dst, Register src) {
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcntq(dst, src);
    return;
  }
  Label not_zero_src;
  bsrq(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 127);  // 127^63 == 64
  bind(&not_zero_src);
  xorl(dst, Immediate(63));  // for x in [0..63], 63^x == 63 - x
}

void MacroAssembler::Lzcntq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcntq(dst, src);
    return;
  }
  Label not_zero_src;
  bsrq(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 127);  // 127^63 == 64
  bind(&not_zero_src);
  xorl(dst, Immediate(63));  // for x in [0..63], 63^x == 63 - x
}

void MacroAssembler::Tzcntq(Register dst, Register src) {
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcntq(dst, src);
    return;
  }
  Label not_zero_src;
  bsfq(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  // Define the result of tzcnt(0) separately, because bsf(0) is undefined.
  Move(dst, 64);
  bind(&not_zero_src);
}

void MacroAssembler::Tzcntq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcntq(dst, src);
    return;
  }
  Label not_zero_src;
  bsfq(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  // Define the result of tzcnt(0) separately, because bsf(0) is undefined.
  Move(dst, 64);
  bind(&not_zero_src);
}

void MacroAssembler::Tzcntl(Register dst, Register src) {
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcntl(dst, src);
    return;
  }
  Label not_zero_src;
  bsfl(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 32);  // The result of tzcnt is 32 if src = 0.
  bind(&not_zero_src);
}

void MacroAssembler::Tzcntl(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcntl(dst, src);
    return;
  }
  Label not_zero_src;
  bsfl(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 32);  // The result of tzcnt is 32 if src = 0.
  bind(&not_zero_src);
}

void MacroAssembler::Popcntl(Register dst, Register src) {
  if (CpuFeatures::IsSupported(POPCNT)) {
    CpuFeatureScope scope(this, POPCNT);
    popcntl(dst, src);
    return;
  }
  UNREACHABLE();
}

void MacroAssembler::Popcntl(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(POPCNT)) {
    CpuFeatureScope scope(this, POPCNT);
    popcntl(dst, src);
    return;
  }
  UNREACHABLE();
}

void MacroAssembler::Popcntq(Register dst, Register src) {
  if (CpuFeatures::IsSupported(POPCNT)) {
    CpuFeatureScope scope(this, POPCNT);
    popcntq(dst, src);
    return;
  }
  UNREACHABLE();
}

void MacroAssembler::Popcntq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(POPCNT)) {
    CpuFeatureScope scope(this, POPCNT);
    popcntq(dst, src);
    return;
  }
  UNREACHABLE();
}

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0);

  Push(Immediate(0));  // Padding.

  // Link the current handler as the next handler.
  ExternalReference handler_address =
      ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate());
  Push(ExternalReferenceAsOperand(handler_address));

  // Set this new handler as the current one.
  movq(ExternalReferenceAsOperand(handler_address), rsp);
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kNextOffset == 0);
  ExternalReference handler_address =
      ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate());
  Pop(ExternalReferenceAsOperand(handler_address));
  addq(rsp, Immediate(StackHandlerConstants::kSize - kSystemPointerSize));
}

void MacroAssembler::Ret() { ret(0); }

void MacroAssembler::Ret(int bytes_dropped, Register scratch) {
  if (is_uint16(bytes_dropped)) {
    ret(bytes_dropped);
  } else {
    PopReturnAddressTo(scratch);
    addq(rsp, Immediate(bytes_dropped));
    PushReturnAddressFrom(scratch);
    ret(0);
  }
}

void MacroAssembler::IncsspqIfSupported(Register number_of_words,
                                        Register scratch) {
  // Optimized code can validate at runtime whether the cpu supports the
  // incsspq instruction, so it shouldn't use this method.
  CHECK(isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK_NE(number_of_words, scratch);
  Label not_supported;
  ExternalReference supports_cetss =
      ExternalReference::supports_cetss_address();
  Operand supports_cetss_operand =
      ExternalReferenceAsOperand(supports_cetss, scratch);
  cmpb(supports_cetss_operand, Immediate(0));
  j(equal, &not_supported, Label::kNear);
  incsspq(number_of_words);
  bind(&not_supported);
}

#if V8_STATIC_ROOTS_BOOL
void MacroAssembler::CompareInstanceTypeWithUniqueCompressedMap(
    Register map, InstanceType type) {
  std::optional<RootIndex> expected =
      InstanceTypeChecker::UniqueMapOfInstanceType(type);
  CHECK(expected);
  Tagged_t expected_ptr = ReadOnlyRootPtr(*expected);
  cmp_tagged(map, Immediate(expected_ptr));
}

void MacroAssembler::IsObjectTypeFast(Register object, InstanceType type,
                                      Register compressed_map_scratch) {
  ASM_CODE_COMMENT(this);
  CHECK(InstanceTypeChecker::UniqueMapOfInstanceType(type));
  LoadCompressedMap(compressed_map_scratch, object);
  CompareInstanceTypeWithUniqueCompressedMap(compressed_map_scratch, type);
}
#endif  // V8_STATIC_ROOTS_BOOL

void MacroAssembler::IsObjectType(Register heap_object, InstanceType type,
                                  Register map) {
#if V8_STATIC_ROOTS_BOOL
  if (InstanceTypeChecker::UniqueMapOfInstanceType(type)) {
    LoadCompressedMap(map, heap_object);
    CompareInstanceTypeWithUniqueCompressedMap(map, type);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL
  CmpObjectType(heap_object, type, map);
}

void MacroAssembler::IsObjectTypeInRange(Register heap_object,
                                         InstanceType lower_limit,
                                         InstanceType higher_limit,
                                         Register scratch) {
  DCHECK_LT(lower_limit, higher_limit);
#if V8_STATIC_ROOTS_BOOL
  if (auto range = InstanceTypeChecker::UniqueMapRangeOfInstanceTypeRange(
          lower_limit, higher_limit)) {
    LoadCompressedMap(scratch, heap_object);
    CompareRange(scratch, range->first, range->second);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL
  LoadMap(scratch, heap_object);
  CmpInstanceTypeRange(scratch, scratch, lower_limit, higher_limit);
}

void MacroAssembler::JumpIfJSAnyIsNotPrimitive(Register heap_object,
                                               Register scratch, Label* target,
                                               Label::Distance distance,
                                               Condition cc) {
  CHECK(cc == Condition::kUnsignedLessThan ||
        cc == Condition::kUnsignedGreaterThanEqual);
  if (V8_STATIC_ROOTS_BOOL) {
#ifdef DEBUG
    Label ok;
    LoadMap(scratch, heap_object);
    CmpInstanceTypeRange(scratch, scratch, FIRST_JS_RECEIVER_TYPE,
                         LAST_JS_RECEIVER_TYPE);
    j(Condition::kUnsignedLessThanEqual, &ok, Label::Distance::kNear);
    LoadMap(scratch, heap_object);
    CmpInstanceTypeRange(scratch, scratch, FIRST_PRIMITIVE_HEAP_OBJECT_TYPE,
                         LAST_PRIMITIVE_HEAP_OBJECT_TYPE);
    j(Condition::kUnsignedLessThanEqual, &ok, Label::Distance::kNear);
    Abort(AbortReason::kInvalidReceiver);
    bind(&ok);
#endif  // DEBUG

    // All primitive object's maps are allocated at the start of the read only
    // heap. Thus JS_RECEIVER's must have maps with larger (compressed)
    // addresses.
    LoadCompressedMap(scratch, heap_object);
    cmp_tagged(scratch, Immediate(InstanceTypeChecker::kNonJsReceiverMapLimit));
  } else {
    static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
    CmpObjectType(heap_object, FIRST_JS_RECEIVER_TYPE, scratch);
  }
  j(cc, target, distance);
}

void MacroAssembler::CmpObjectType(Register heap_object, InstanceType type,
                                   Register map) {
  LoadMap(map, heap_object);
  CmpInstanceType(map, type);
}

void MacroAssembler::CmpInstanceType(Register map, InstanceType type) {
  cmpw(FieldOperand(map, Map::kInstanceTypeOffset), Immediate(type));
}

void MacroAssembler::CmpInstanceTypeRange(Register map,
                                          Register instance_type_out,
                                          InstanceType lower_limit,
                                          InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
  movzxwl(instance_type_out, FieldOperand(map, Map::kInstanceTypeOffset));
  CompareRange(instance_type_out, lower_limit, higher_limit);
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code) {
  const int kByteWithDeoptBitOffset = 0 * kByteSize;
  const int kByteWithDeoptBitOffsetInBits = kByteWithDeoptBitOffset * 8;
  static_assert(V8_TARGET_LITTLE_ENDIAN == 1);
  static_assert(FIELD_SIZE(Code::kFlagsOffset) * kBitsPerByte == 32);
  static_assert(Code::kMarkedForDeoptimizationBit >
                kByteWithDeoptBitOffsetInBits);
  testb(FieldOperand(code, Code::kFlagsOffset + kByteWithDeoptBitOffset),
        Immediate(1 << (Code::kMarkedForDeoptimizationBit -
                        kByteWithDeoptBitOffsetInBits)));
}

void MacroAssembler::TestCodeIsTurbofanned(Register code) {
  testl(FieldOperand(code, Code::kFlagsOffset),
        Immediate(1 << Code::kIsTurbofannedBit));
}

Immediate MacroAssembler::ClearedValue() const {
  return Immediate(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertNotSmi(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Condition is_smi = CheckSmi(object);
  Check(NegateCondition(is_smi), AbortReason::kOperandIsASmi);
}

void MacroAssembler::AssertSmi(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Condition is_smi = CheckSmi(object);
  Check(is_smi, AbortReason::kOperandIsNotASmi);
#ifdef ENABLE_SLOW_DCHECKS
  ClobberDecompressedSmiBits(object);
#endif
}

void MacroAssembler::AssertSmi(Operand object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Condition is_smi = CheckSmi(object);
  Check(is_smi, AbortReason::kOperandIsNotASmi);
}

void MacroAssembler::AssertZeroExtended(Register int32_register) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  DCHECK_NE(int32_register, kScratchRegister);
  movl(kScratchRegister, Immediate(kMaxUInt32));  // zero-extended
  cmpq(int32_register, kScratchRegister);
  Check(below_equal, AbortReason::k32BitValueInRegisterIsNotZeroExtended);
}

void MacroAssembler::AssertSignedBitOfSmiIsZero(Register smi_register) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  DCHECK(COMPRESS_POINTERS_BOOL);
  testl(smi_register, Immediate(int32_t{0x10000000}));
  Check(zero, AbortReason::kSignedBitOfSmiIsNotZero);
}

void MacroAssembler::AssertMap(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsNotAMap);
  Push(object);
  LoadMap(object, object);
  CmpInstanceType(object, MAP_TYPE);
  popq(object);
  Check(equal, AbortReason::kOperandIsNotAMap);
}

void MacroAssembler::AssertCode(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsNotACode);
  Push(object);
  LoadMap(object, object);
  CmpInstanceType(object, CODE_TYPE);
  popq(object);
  Check(equal, AbortReason::kOperandIsNotACode);
}

void MacroAssembler::AssertSmiOrHeapObjectInMainCompressionCage(
    Register object) {
  if (!PointerCompressionIsEnabled()) return;
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Label ok;
  // We may not have any scratch registers so we preserve our input register.
  pushq(object);
  j(CheckSmi(object), &ok);
  // Clear the lower 32 bits.
  shrq(object, Immediate(32));
  shlq(object, Immediate(32));
  // Either the value is now equal to the pointer compression cage base or it's
  // zero if we got a compressed pointer register as input.
  j(zero, &ok);
  cmpq(object, kPtrComprCageBaseRegister);
  Check(equal, AbortReason::kObjectNotTagged);
  bind(&ok);
  popq(object);
}

void MacroAssembler::AssertConstructor(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsASmiAndNotAConstructor);
  Push(object);
  LoadMap(object, object);
  testb(FieldOperand(object, Map::kBitFieldOffset),
        Immediate(Map::Bits1::IsConstructorBit::kMask));
  Pop(object);
  Check(not_zero, AbortReason::kOperandIsNotAConstructor);
}

void MacroAssembler::AssertFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortR
```
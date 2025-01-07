Response:
Let's break down the thought process to analyze the `macro-assembler-ia32.h` file.

**1. Initial Understanding and Context:**

The file name `macro-assembler-ia32.h` immediately suggests its purpose: it's a header file defining a macro assembler for the IA-32 (x86 32-bit) architecture. The "macro" part implies it provides higher-level abstractions over raw assembly instructions. The `v8/src/codegen/ia32/` path confirms it's part of the V8 JavaScript engine's code generation component, specifically for the IA-32 architecture.

**2. Examining the Includes:**

The `#include` directives are crucial for understanding dependencies and functionality:

* `<stdint.h>`: Standard integer types (e.g., `uintptr_t`).
* `"include/v8-internal.h"`:  V8's internal definitions. This is a strong indicator that this code is deeply embedded within the V8 engine.
* `"src/base/logging.h"`:  Logging facilities within V8.
* `"src/base/macros.h"`:  Common macros used throughout V8 (e.g., `DISALLOW_IMPLICIT_CONSTRUCTORS`).
* `"src/builtins/builtins.h"`: Definitions related to V8's built-in functions.
* `"src/codegen/assembler.h"`:  The base assembler class. This class likely provides the low-level assembly instruction emission. `MacroAssembler` builds upon this.
* `"src/codegen/bailout-reason.h"`: Enumerations for deoptimization reasons.
* `"src/codegen/cpu-features.h"`:  Mechanism to check for CPU capabilities.
* `"src/codegen/ia32/assembler-ia32.h"`: The IA-32 specific assembler (lower-level than `MacroAssembler`).
* `"src/codegen/ia32/register-ia32.h"`: Definitions for IA-32 registers.
* `"src/codegen/label.h"`:  Mechanism for defining and referencing code labels.
* `"src/codegen/macro-assembler-base.h"`:  A base class for macro assemblers, likely shared across architectures.
* `"src/codegen/reglist.h"`:  Data structures for managing lists of registers.
* `"src/codegen/reloc-info.h"`:  Information needed for relocating code (adjusting addresses).
* `"src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h"`: Hints at shared functionality between IA-32 and x64.
* `"src/common/globals.h"`: Global V8 settings and constants.
* `"src/execution/frame-constants.h"` and `"src/execution/frames.h"`: Definitions related to call frames and stack organization.
* `"src/handles/handles.h"`:  V8's garbage-collected pointer abstraction.
* `"src/objects/heap-object.h"` and `"src/objects/smi.h"`:  Definitions for V8's object model (heap objects and small integers).
* `"src/roots/roots.h"`:  Access to V8's "roots" – globally accessible objects.
* `"src/runtime/runtime.h"`:  Definitions for V8's runtime functions (implemented in C++).

**3. Analyzing the `MacroAssembler` Class:**

The core of the file is the `MacroAssembler` class definition. The `public` methods reveal its key functionalities. I'd go through each method group and infer their purpose:

* **Memory Access:**  Methods like `MemoryChunkHeaderFromObject`, `CheckPageFlag` deal with memory management and object properties.
* **Frame Management:** `EnterFrame`, `LeaveFrame`, `AllocateStackSpace` are essential for setting up and tearing down function call stacks.
* **Control Flow:** `Call`, `Jump`, `Ret`, conditional jumps (`JumpIfSmi`, `JumpIfEqual`, etc.), and label manipulation (`LoadLabelAddress`) are for directing the execution flow.
* **Data Movement:** `Move` (for registers, immediates, memory), `Push`, `Pop` are for manipulating data.
* **Built-in Functions:** `CallBuiltin`, `TailCallBuiltin`, `LoadEntryFromBuiltinIndex` interact with V8's pre-compiled built-in functions.
* **JavaScript Function Calls:** `CallJSFunction`, `JumpJSFunction`, `InvokeFunction` are critical for executing JavaScript code.
* **C++ Function Calls:** `PrepareCallCFunction`, `CallCFunction` allow calling back into the V8 C++ runtime.
* **Bit Manipulation:** `ShlPair`, `ShrPair`, `SarPair`, `Lzcnt`, `Tzcnt`, `Popcnt` provide bitwise operations.
* **Prologue/Epilogue:** `StubPrologue`, `Prologue` handle the standard function setup.
* **Argument Handling:** `DropArguments`, `DropArgumentsAndPushNewReceiver` manage function arguments on the stack.
* **Root Access:** `RootAsOperand`, `LoadRoot`, `CompareRoot` provide efficient access to global V8 objects.
* **Array Manipulation:** `PushArray` for pushing array elements onto the stack.
* **External References:** `ExternalReferenceAsOperand`, `LoadAddress` for interacting with addresses outside the generated code.
* **Floating-Point:** `Cvtsi2ss`, `Cvtsi2sd`, etc., for conversions between integer and floating-point types.
* **GC Support:** `RecordWriteField`, `RecordWrite`, `EnterExitFrame`, `LeaveExitFrame` are crucial for informing the garbage collector about memory modifications.
* **Global Object Access:** `LoadGlobalProxy`, `LoadNativeContextSlot`.
* **Object Type Checks:** `CmpObjectType`, `CmpInstanceType`, `CmpInstanceTypeRange`.
* **Smi Manipulation:** `SmiTag`, `SmiUntag`, `SmiCompare`.
* **Deoptimization:** `TestCodeIsMarkedForDeoptimization`, `ReplaceClosureCodeWithOptimizedCode`.
* **Tiering:**  Methods related to optimizing code execution.
* **Assertions:**  `Assert`, `Check`, `AssertSmi`, etc., for debugging and verifying assumptions.
* **Exception Handling:** `PushStackHandler`, `PopStackHandler`.
* **Runtime Calls:** `CallRuntime`, `TailCallRuntime`, `JumpToExternalReference`.
* **Utilities:** `Drop`, `LoadWeakValue`.
* **Stats Counters:** `IncrementCounter`, `DecrementCounter`.
* **Stack Limits:** `CompareStackLimit`, `StackOverflowCheck`.

**4. Identifying Javascript Relevance:**

Many of the methods directly relate to executing JavaScript: `CallJSFunction`, `InvokeFunction`, argument handling, object type checks, and interactions with built-in functions are all part of how V8 runs JavaScript code.

**5. Considering `.tq` Extension:**

The prompt asks about the `.tq` extension. Knowing that Torque is V8's type-safe dialect for writing built-ins and runtime code, I'd immediately recognize that if the file ended in `.tq`, it would be a Torque source file, not a C++ header.

**6. Code Logic and Examples:**

For methods with clear logic (e.g., `SmiUntag`, `SmiTag`), I could construct simple examples. For more complex methods, I'd focus on illustrating the *intent* or *scenario* where they'd be used.

**7. Common Programming Errors:**

I'd think about how someone using this macro assembler incorrectly might introduce bugs. Stack corruption (incorrect `AllocateStackSpace`, mismatched `Push`/`Pop`), incorrect argument passing to functions, and forgetting GC barriers (`RecordWrite`) are common issues.

**8. Structuring the Output:**

Finally, I'd organize the information into the requested categories: Functionality, `.tq` extension explanation, JavaScript examples, code logic examples, and common errors. This provides a comprehensive and well-structured answer.
This header file, `v8/src/codegen/ia32/macro-assembler-ia32.h`, defines the `MacroAssembler` class for the IA-32 (x86 32-bit) architecture within the V8 JavaScript engine. It provides a higher-level abstraction over the raw assembly instructions, making it easier to generate machine code for the IA-32 platform.

Here's a breakdown of its functionalities:

**Core Functionality:  Generating IA-32 Assembly Code**

The primary function of `MacroAssembler` is to generate sequences of IA-32 assembly instructions. It encapsulates common instruction patterns and operations, making code generation more efficient and less error-prone. It builds upon the lower-level `Assembler` class.

**Key Features and Functionality Areas:**

* **Register and Memory Manipulation:**
    * **`Move(Register dst, ...)`:**  Moves data between registers, immediate values, and memory locations.
    * **`Push(Register src)` / `Pop(Register dst)`:** Pushes values onto and pops values from the stack.
    * **`Operand` Class:**  Provides a way to represent memory operands (e.g., `Operand(ebp, offset)`).
    * **`FieldOperand`:**  Specifically for accessing fields within JavaScript objects in memory.

* **Control Flow:**
    * **`Call(Register reg)` / `Call(Label* target)`:**  Generates call instructions to registers or labeled code locations.
    * **`Jump(Register reg)` / `Jump(Label* target)`:** Generates jump instructions.
    * **Conditional Jumps (`j(Condition cc, Label* target)`):** Jumps based on the result of previous comparisons (e.g., `JumpIfSmi`, `JumpIfEqual`).
    * **`Ret()`:** Generates a return instruction.
    * **`Label` Class:**  Used to mark specific locations in the generated code for branching.

* **Stack Frame Management:**
    * **`EnterFrame(StackFrame::Type type)` / `LeaveFrame(StackFrame::Type type)`:**  Sets up and tears down function call stack frames.
    * **`AllocateStackSpace(int bytes)`:**  Allocates space on the stack.

* **Function Calls (JavaScript and C++):**
    * **`CallJSFunction(Register function_object, uint16_t argument_count)`:** Calls a JavaScript function.
    * **`CallBuiltin(Builtin builtin)`:** Calls a built-in V8 function.
    * **`CallCFunction(ExternalReference function, int num_arguments)`:** Calls a C++ function within V8.
    * **`PrepareCallCFunction`:** Prepares the stack for calling a C++ function.

* **Object and Smi (Small Integer) Handling:**
    * **`LoadMap(Register destination, Register object)`:** Loads the map (object type information) of an object.
    * **`SmiTag(Register reg)` / `SmiUntag(Register reg)`:** Converts between tagged and untagged Smi representations.
    * **`JumpIfSmi(Register value, Label* smi_label)` / `JumpIfNotSmi`:** Checks if a value is a Smi.

* **Garbage Collection (GC) Support:**
    * **`RecordWriteField(Register object, int offset, Register value, Register scratch, SaveFPRegsMode save_fp)`:**  Notifies the garbage collector about a pointer write to an object, crucial for maintaining memory safety.

* **Debugging and Assertions:**
    * **`Assert(Condition cc, AbortReason reason)` / `Check(Condition cc, AbortReason reason)`:**  Inserts assertions that will trigger an abort if the condition is false (used for debugging).
    * **`DebugBreak()`:**  Inserts a breakpoint for debugging.

* **Runtime Calls:**
    * **`CallRuntime(Runtime::FunctionId fid, int num_arguments)`:** Calls a V8 runtime function (implemented in C++).

* **Root Register Access:**
    * **`LoadRoot(Register destination, RootIndex index)`:** Loads a global "root" object into a register. Roots are fundamental V8 objects.

* **Floating-Point Operations:** Provides instructions for moving and converting floating-point values using XMM registers (e.g., `Cvtsi2ss`, `Cvtsi2sd`).

* **Tiering and Optimization:**
    * Methods related to feedback vectors and optimizing code execution (`AssertFeedbackCell`, `ReplaceClosureCodeWithOptimizedCode`).

* **Exception Handling:**
    * **`PushStackHandler` / `PopStackHandler`:** Manages stack handlers for exception handling.

**Is `v8/src/codegen/ia32/macro-assembler-ia32.h` a Torque Source File?**

No, the filename ends with `.h`, which is the standard extension for C++ header files. If it were a Torque source file, its name would typically end with `.tq`.

**Relationship with JavaScript and Examples:**

The `MacroAssembler` directly enables the execution of JavaScript code within V8. When V8 needs to compile JavaScript code into machine instructions for the IA-32 architecture, it uses the `MacroAssembler` to generate that code.

Here are some examples of how the functionalities in `macro-assembler-ia32.h` relate to JavaScript:

**1. Function Calls:**

When you call a JavaScript function, V8 internally uses the `MacroAssembler` to generate code that:

* Sets up a new stack frame (`EnterFrame`).
* Moves arguments to the correct locations on the stack or in registers.
* Calls the function's code (`CallJSFunction`).
* Handles the return value.
* Tears down the stack frame (`LeaveFrame`).

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

Internally, V8 would generate IA-32 assembly code using `MacroAssembler` to perform these steps. `CallJSFunction` is a key method for this.

**2. Object Property Access:**

Accessing properties of JavaScript objects involves:

* Loading the object's properties (often stored in a hidden class or dictionary).
* Performing lookups based on the property name.

The `MacroAssembler` provides `FieldOperand` to access object fields efficiently.

```javascript
const obj = { x: 10 };
console.log(obj.x);
```

The access to `obj.x` would involve generated IA-32 code that calculates the memory offset of the `x` property and loads its value using something like `mov eax, FieldOperand(object_register, offset_of_x)`.

**3. Garbage Collection:**

When you create objects in JavaScript:

```javascript
const myObject = {};
```

V8 allocates memory on the heap. If you then store a reference to another object within `myObject`:

```javascript
const anotherObject = { value: 20 };
myObject.ref = anotherObject;
```

The `MacroAssembler` would have been used during the assignment to `myObject.ref` to call `RecordWriteField` or `RecordWrite`. This informs the garbage collector that a pointer has been written, ensuring that `anotherObject` is not prematurely collected when `myObject` is still referencing it.

**4. Smi Operations:**

Operations on small integers (Smis) are often optimized:

```javascript
let count = 5;
count++;
```

The increment operation might involve `SmiTag` and `SmiUntag` if `count` is a Smi, or direct integer arithmetic instructions. The `MacroAssembler` provides methods for these Smi-specific operations.

**Code Logic Reasoning (Hypothetical Example):**

Let's consider the `JumpIfSmi` method.

**Hypothetical Input:**

* `value` register contains a value that could be a Smi or a HeapObject pointer.
* `smi_label` is a label marking a code location to jump to if `value` is a Smi.

**Code Logic in `JumpIfSmi`:**

```c++
  inline void JumpIfSmi(Register value, Label* smi_label,
                        Label::Distance distance = Label::kFar) {
    test(value, Immediate(kSmiTagMask)); // Test the least significant bit (Smi tag)
    j(zero, smi_label, distance);        // Jump if the zero flag is set (LSB is 0)
  }
```

**Explanation:**

1. **`test(value, Immediate(kSmiTagMask))`:**  The `kSmiTagMask` is a bitmask (likely `0x01`). The `test` instruction performs a bitwise AND between the `value` in the register and the mask, but it *only* sets the CPU flags (like the zero flag). It doesn't modify the operands. Smis in V8 have their least significant bit set to 0.
2. **`j(zero, smi_label, distance)`:** This is a conditional jump instruction. It checks the zero flag. If the zero flag is set (meaning the result of the `test` was 0, indicating the least significant bit of `value` was 0), then the execution jumps to the code location marked by `smi_label`.

**Hypothetical Output:**

* If the `value` register contained a Smi (e.g., `0x0000000A`), the `test` instruction would result in 0, the zero flag would be set, and the jump to `smi_label` would occur.
* If the `value` register contained a HeapObject pointer (e.g., `0x1234567B`), the `test` instruction would result in a non-zero value, the zero flag would not be set, and the jump would *not* occur.

**Common Programming Errors:**

Developers working with `MacroAssembler` (typically V8 engine developers) can make mistakes that lead to crashes or incorrect behavior. Some common errors include:

1. **Stack Corruption:**
   * **Incorrect `AllocateStackSpace`:** Allocating too little or too much stack space.
   * **Mismatched `Push` and `Pop`:** Pushing values onto the stack without popping them, or vice versa, leading to an incorrect stack pointer.

   ```c++
   // Incorrect: Pushing two registers but only popping one.
   masm->Push(eax);
   masm->Push(ebx);
   masm->Pop(eax);
   masm->Ret(); // Return address is now incorrect
   ```

2. **Register Allocation Errors:**
   * **Using a register that's expected to hold a specific value:**  Overwriting a register that the calling code relies on.
   * **Forgetting to save and restore registers when calling C++ functions:**  C++ calling conventions often require certain registers to be preserved.

3. **Incorrect Argument Passing:**
   * **Passing the wrong number of arguments to a function.**
   * **Putting arguments in the wrong order on the stack.**

4. **Forgetting Garbage Collection Barriers:**
   * When writing a pointer to a HeapObject into another HeapObject, failing to call `RecordWriteField` or `RecordWrite`. This can lead to the garbage collector incorrectly freeing the pointed-to object.

   ```c++
   // Assuming 'object' and 'value' are registers holding HeapObjects
   // Incorrect: Forgetting the write barrier
   masm->mov(FieldOperand(object, offset), value);
   ```

5. **Incorrectly Handling Smis:**
   * Performing arithmetic on tagged Smis without untagging them first.
   * Comparing a tagged Smi with an untagged integer.

6. **Control Flow Errors:**
   * Jumping to the wrong label.
   * Missing return instructions.
   * Incorrectly using conditional jumps.

These errors can be difficult to debug as they often manifest as crashes or subtle incorrect behavior that's hard to trace back to the generated assembly code. Thorough testing and careful understanding of the IA-32 architecture and V8's internal conventions are crucial.

Prompt: 
```
这是目录为v8/src/codegen/ia32/macro-assembler-ia32.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ia32/macro-assembler-ia32.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDED_FROM_MACRO_ASSEMBLER_H
#error This header must be included via macro-assembler.h
#endif

#ifndef V8_CODEGEN_IA32_MACRO_ASSEMBLER_IA32_H_
#define V8_CODEGEN_IA32_MACRO_ASSEMBLER_IA32_H_

#include <stdint.h>

#include "include/v8-internal.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/builtins/builtins.h"
#include "src/codegen/assembler.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/ia32/assembler-ia32.h"
#include "src/codegen/ia32/register-ia32.h"
#include "src/codegen/label.h"
#include "src/codegen/macro-assembler-base.h"
#include "src/codegen/reglist.h"
#include "src/codegen/reloc-info.h"
#include "src/codegen/shared-ia32-x64/macro-assembler-shared-ia32-x64.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/handles/handles.h"
#include "src/objects/heap-object.h"
#include "src/objects/smi.h"
#include "src/roots/roots.h"
#include "src/runtime/runtime.h"

namespace v8 {
namespace internal {

class InstructionStream;
class ExternalReference;
class StatsCounter;

// Convenience for platform-independent signatures.  We do not normally
// distinguish memory operands from other operands on ia32.
using MemOperand = Operand;

// TODO(victorgomes): Move definition to macro-assembler.h, once all other
// platforms are updated.
enum class StackLimitKind { kInterruptStackLimit, kRealStackLimit };

// Convenient class to access arguments below the stack pointer.
class StackArgumentsAccessor {
 public:
  // argc = the number of arguments not including the receiver.
  explicit StackArgumentsAccessor(Register argc) : argc_(argc) {
    DCHECK_NE(argc_, no_reg);
  }

  // Argument 0 is the receiver (despite argc not including the receiver).
  Operand operator[](int index) const { return GetArgumentOperand(index); }

  Operand GetArgumentOperand(int index) const;
  Operand GetReceiverOperand() const { return GetArgumentOperand(0); }

 private:
  const Register argc_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(StackArgumentsAccessor);
};

class V8_EXPORT_PRIVATE MacroAssembler
    : public SharedMacroAssembler<MacroAssembler> {
 public:
  using SharedMacroAssembler<MacroAssembler>::SharedMacroAssembler;

  void MemoryChunkHeaderFromObject(Register object, Register header);
  void CheckPageFlag(Register object, Register scratch, int mask, Condition cc,
                     Label* condition_met,
                     Label::Distance condition_met_distance = Label::kFar);

  // Activation support.
  void EnterFrame(StackFrame::Type type);
  void EnterFrame(StackFrame::Type type, bool load_constant_pool_pointer_reg) {
    // Out-of-line constant pool not implemented on ia32.
    UNREACHABLE();
  }
  void LeaveFrame(StackFrame::Type type);

// Allocate stack space of given size (i.e. decrement {esp} by the value
// stored in the given register, or by a constant). If you need to perform a
// stack check, do it before calling this function because this function may
// write into the newly allocated space. It may also overwrite the given
// register's value, in the version that takes a register.
#ifdef V8_OS_WIN
  void AllocateStackSpace(Register bytes_scratch);
  void AllocateStackSpace(int bytes);
#else
  void AllocateStackSpace(Register bytes) { sub(esp, bytes); }
  void AllocateStackSpace(int bytes) {
    DCHECK_GE(bytes, 0);
    if (bytes == 0) return;
    sub(esp, Immediate(bytes));
  }
#endif

  // Print a message to stdout and abort execution.
  void Abort(AbortReason reason);

  // Calls Abort(msg) if the condition cc is not satisfied.
  // Use --debug_code to enable.
  void Assert(Condition cc, AbortReason reason) NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but without condition.
  // Use --debug_code to enable.
  void AssertUnreachable(AbortReason reason) NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but always enabled.
  void Check(Condition cc, AbortReason reason);

  // Check that the stack is aligned.
  void CheckStackAlignment();

  // Align to natural boundary
  void AlignStackPointer();

  // Move a constant into a destination using the most efficient encoding.
  void Move(Register dst, int32_t x) {
    if (x == 0) {
      xor_(dst, dst);
    } else {
      mov(dst, Immediate(x));
    }
  }
  void Move(Register dst, const Immediate& src);
  void Move(Register dst, Tagged<Smi> src) { Move(dst, Immediate(src)); }
  void Move(Register dst, Handle<HeapObject> src);
  void Move(Register dst, Register src);
  void Move(Register dst, Operand src);
  void Move(Operand dst, const Immediate& src);

  // Move an immediate into an XMM register.
  void Move(XMMRegister dst, uint32_t src);
  void Move(XMMRegister dst, uint64_t src);
  void Move(XMMRegister dst, float src) {
    Move(dst, base::bit_cast<uint32_t>(src));
  }
  void Move(XMMRegister dst, double src) {
    Move(dst, base::bit_cast<uint64_t>(src));
  }

  Operand EntryFromBuiltinAsOperand(Builtin builtin);

  void Call(Register reg) { call(reg); }
  void Call(Operand op) { call(op); }
  void Call(Label* target) { call(target); }
  void Call(Handle<Code> code_object, RelocInfo::Mode rmode);

  // Load the builtin given by the Smi in |builtin_index| into |target|.
  void LoadEntryFromBuiltinIndex(Register builtin_index, Register target);
  void CallBuiltinByIndex(Register builtin_index, Register target);
  void CallBuiltin(Builtin builtin);
  void TailCallBuiltin(Builtin builtin);

  // Load the code entry point from the Code object.
  void LoadCodeInstructionStart(Register destination, Register code_object,
                                CodeEntrypointTag = kDefaultCodeEntrypointTag);
  void CallCodeObject(Register code_object);
  void JumpCodeObject(Register code_object,
                      JumpMode jump_mode = JumpMode::kJump);

  // Convenience functions to call/jmp to the code of a JSFunction object.
  void CallJSFunction(Register function_object, uint16_t argument_count);
  void JumpJSFunction(Register function_object,
                      JumpMode jump_mode = JumpMode::kJump);
  void ResolveWasmCodePointer(Register target);
  void CallWasmCodePointer(Register target,
                           CallJumpMode call_jump_mode = CallJumpMode::kCall);

  void Jump(const ExternalReference& reference);
  void Jump(Handle<Code> code_object, RelocInfo::Mode rmode);

  void LoadLabelAddress(Register dst, Label* lbl);

  void LoadMap(Register destination, Register object);

  void LoadFeedbackVector(Register dst, Register closure, Register scratch,
                          Label* fbv_undef, Label::Distance distance);

  void Trap();
  void DebugBreak();

  void CallForDeoptimization(Builtin target, int deopt_id, Label* exit,
                             DeoptimizeKind kind, Label* ret,
                             Label* jump_deoptimization_entry_label);

  // Jump the register contains a smi.
  inline void JumpIfSmi(Register value, Label* smi_label,
                        Label::Distance distance = Label::kFar) {
    test(value, Immediate(kSmiTagMask));
    j(zero, smi_label, distance);
  }
  // Jump if the operand is a smi.
  inline void JumpIfSmi(Operand value, Label* smi_label,
                        Label::Distance distance = Label::kFar) {
    test(value, Immediate(kSmiTagMask));
    j(zero, smi_label, distance);
  }

  void JumpIfEqual(Register a, int32_t b, Label* dest) {
    cmp(a, Immediate(b));
    j(equal, dest);
  }

  void JumpIfLessThan(Register a, int32_t b, Label* dest) {
    cmp(a, Immediate(b));
    j(less, dest);
  }

  void SmiUntag(Register reg) { sar(reg, kSmiTagSize); }
  void SmiUntag(Register output, Register value) {
    mov(output, value);
    SmiUntag(output);
  }

  void SmiToInt32(Register reg) { SmiUntag(reg); }

  // Before calling a C-function from generated code, align arguments on stack.
  // After aligning the frame, arguments must be stored in esp[0], esp[4],
  // etc., not pushed. The argument count assumes all arguments are word sized.
  // Some compilers/platforms require the stack to be aligned when calling
  // C++ code.
  // Needs a scratch register to do some arithmetic. This register will be
  // trashed.
  void PrepareCallCFunction(int num_arguments, Register scratch);

  // Calls a C function and cleans up the space for arguments allocated
  // by PrepareCallCFunction. The called function is not allowed to trigger a
  // garbage collection, since that might move the code and invalidate the
  // return address (unless this is somehow accounted for by the called
  // function).
  int CallCFunction(
      ExternalReference function, int num_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);
  int CallCFunction(
      Register function, int num_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);

  void ShlPair(Register high, Register low, uint8_t imm8);
  void ShlPair_cl(Register high, Register low);
  void ShrPair(Register high, Register low, uint8_t imm8);
  void ShrPair_cl(Register high, Register low);
  void SarPair(Register high, Register low, uint8_t imm8);
  void SarPair_cl(Register high, Register low);

  // Generates function and stub prologue code.
  void StubPrologue(StackFrame::Type type);
  void Prologue();

  // Helpers for argument handling
  void DropArguments(Register count, Register scratch);
  void DropArgumentsAndPushNewReceiver(Register argc, Register receiver,
                                       Register scratch);
  void DropArgumentsAndPushNewReceiver(Register argc, Operand receiver,
                                       Register scratch);

  void Lzcnt(Register dst, Register src) { Lzcnt(dst, Operand(src)); }
  void Lzcnt(Register dst, Operand src);

  void Tzcnt(Register dst, Register src) { Tzcnt(dst, Operand(src)); }
  void Tzcnt(Register dst, Operand src);

  void Popcnt(Register dst, Register src) { Popcnt(dst, Operand(src)); }
  void Popcnt(Register dst, Operand src);

  void PushReturnAddressFrom(Register src) { push(src); }
  void PopReturnAddressTo(Register dst) { pop(dst); }

  void PushReturnAddressFrom(XMMRegister src, Register scratch) {
    Push(src, scratch);
  }
  void PopReturnAddressTo(XMMRegister dst, Register scratch) {
    Pop(dst, scratch);
  }

  void Ret();

  // Root register utility functions.

  void InitializeRootRegister();

  Operand RootAsOperand(RootIndex index);
  void LoadRoot(Register destination, RootIndex index) final;

  // Indirect root-relative loads.
  void LoadFromConstantsTable(Register destination, int constant_index) final;
  void LoadRootRegisterOffset(Register destination, intptr_t offset) final;
  void LoadRootRelative(Register destination, int32_t offset) final;
  void StoreRootRelative(int32_t offset, Register value) final;

  void PushPC();

  enum class PushArrayOrder { kNormal, kReverse };
  // `array` points to the first element (the lowest address).
  // `array` and `size` are not modified.
  void PushArray(Register array, Register size, Register scratch,
                 PushArrayOrder order = PushArrayOrder::kNormal);

  // Operand pointing to an external reference.
  // May emit code to set up the scratch register. The operand is
  // only guaranteed to be correct as long as the scratch register
  // isn't changed.
  // If the operand is used more than once, use a scratch register
  // that is guaranteed not to be clobbered.
  Operand ExternalReferenceAsOperand(ExternalReference reference,
                                     Register scratch);
  Operand ExternalReferenceAsOperand(IsolateFieldId id) {
    return ExternalReferenceAsOperand(ExternalReference::Create(id), no_reg);
  }
  Operand ExternalReferenceAddressAsOperand(ExternalReference reference);
  Operand HeapObjectAsOperand(Handle<HeapObject> object);

  void LoadAddress(Register destination, ExternalReference source);

  void CompareRoot(Register with, RootIndex index);
  void CompareRoot(Register with, Register scratch, RootIndex index);

  // Return and drop arguments from stack, where the number of arguments
  // may be bigger than 2^16 - 1.  Requires a scratch register.
  void Ret(int bytes_dropped, Register scratch);

  void PextrdPreSse41(Register dst, XMMRegister src, uint8_t imm8);
  void PinsrdPreSse41(XMMRegister dst, Register src, uint8_t imm8,
                      uint32_t* load_pc_offset) {
    PinsrdPreSse41(dst, Operand(src), imm8, load_pc_offset);
  }
  void PinsrdPreSse41(XMMRegister dst, Operand src, uint8_t imm8,
                      uint32_t* load_pc_offset);

  // Expression support
  // cvtsi2sd instruction only writes to the low 64-bit of dst register, which
  // hinders register renaming and makes dependence chains longer. So we use
  // xorps to clear the dst register before cvtsi2sd to solve this issue.
  void Cvtsi2ss(XMMRegister dst, Register src) { Cvtsi2ss(dst, Operand(src)); }
  void Cvtsi2ss(XMMRegister dst, Operand src);
  void Cvtsi2sd(XMMRegister dst, Register src) { Cvtsi2sd(dst, Operand(src)); }
  void Cvtsi2sd(XMMRegister dst, Operand src);

  void Cvtui2ss(XMMRegister dst, Register src, Register tmp) {
    Cvtui2ss(dst, Operand(src), tmp);
  }
  void Cvtui2ss(XMMRegister dst, Operand src, Register tmp);
  void Cvttss2ui(Register dst, XMMRegister src, XMMRegister tmp) {
    Cvttss2ui(dst, Operand(src), tmp);
  }
  void Cvttss2ui(Register dst, Operand src, XMMRegister tmp);
  void Cvtui2sd(XMMRegister dst, Register src, Register scratch) {
    Cvtui2sd(dst, Operand(src), scratch);
  }
  void Cvtui2sd(XMMRegister dst, Operand src, Register scratch);
  void Cvttsd2ui(Register dst, XMMRegister src, XMMRegister tmp) {
    Cvttsd2ui(dst, Operand(src), tmp);
  }
  void Cvttsd2ui(Register dst, Operand src, XMMRegister tmp);

  void Push(Register src) { push(src); }
  void Push(Operand src) { push(src); }
  void Push(Immediate value);
  void Push(Handle<HeapObject> handle) { push(Immediate(handle)); }
  void Push(Tagged<Smi> smi) { Push(Immediate(smi)); }
  void Push(XMMRegister src, Register scratch) {
    movd(scratch, src);
    push(scratch);
  }

  void Pop(Register dst) { pop(dst); }
  void Pop(Operand dst) { pop(dst); }
  void Pop(XMMRegister dst, Register scratch) {
    pop(scratch);
    movd(dst, scratch);
  }

  void MaybeSaveRegisters(RegList registers);
  void MaybeRestoreRegisters(RegList registers);

  void CallEphemeronKeyBarrier(Register object, Register slot_address,
                               SaveFPRegsMode fp_mode);

  void CallRecordWriteStubSaveRegisters(
      Register object, Register slot_address, SaveFPRegsMode fp_mode,
      StubCallMode mode = StubCallMode::kCallBuiltinPointer);
  void CallRecordWriteStub(
      Register object, Register slot_address, SaveFPRegsMode fp_mode,
      StubCallMode mode = StubCallMode::kCallBuiltinPointer);

  // Calculate how much stack space (in bytes) are required to store caller
  // registers excluding those specified in the arguments.
  int RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                      Register exclusion = no_reg) const;

  // PushCallerSaved and PopCallerSaved do not arrange the registers in any
  // particular order so they are not useful for calls that can cause a GC.
  // The caller can exclude a register that does not need to be saved and
  // restored.

  // Push caller saved registers on the stack, and return the number of bytes
  // stack pointer is adjusted.
  int PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion = no_reg);
  // Restore caller saved registers from the stack, and return the number of
  // bytes stack pointer is adjusted.
  int PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion = no_reg);

  // Compute the start of the generated instruction stream from the current PC.
  // This is an alternative to embedding the {CodeObject} handle as a reference.
  void ComputeCodeStartAddress(Register dst);

  // Control-flow integrity:

  // Define a function entrypoint. This doesn't emit any code for this
  // architecture, as control-flow integrity is not supported for it.
  void CodeEntry() {}
  // Define an exception handler.
  void ExceptionHandler() {}
  // Define an exception handler and bind a label.
  void BindExceptionHandler(Label* label) { bind(label); }

  void PushRoot(RootIndex index);

  // Compare the object in a register to a value and jump if they are equal.
  void JumpIfRoot(Register with, RootIndex index, Label* if_equal,
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

  // Checks if value is in range [lower_limit, higher_limit] using a single
  // comparison. Flags CF=1 or ZF=1 indicate the value is in the range
  // (condition below_equal). It is valid, that |value| == |scratch| as far as
  // this function is concerned.
  void CompareRange(Register value, unsigned lower_limit, unsigned higher_limit,
                    Register scratch);
  void JumpIfIsInRange(Register value, unsigned lower_limit,
                       unsigned higher_limit, Register scratch,
                       Label* on_in_range,
                       Label::Distance near_jump = Label::kFar);

  // ---------------------------------------------------------------------------
  // GC Support
  // Notify the garbage collector that we wrote a pointer into an object.
  // |object| is the object being stored into, |value| is the object being
  // stored.  value and scratch registers are clobbered by the operation.
  // The offset is the offset from the start of the object, not the offset from
  // the tagged HeapObject pointer.  For use with FieldOperand(reg, off).
  void RecordWriteField(Register object, int offset, Register value,
                        Register scratch, SaveFPRegsMode save_fp,
                        SmiCheck smi_check = SmiCheck::kInline);

  // For page containing |object| mark region covering |address|
  // dirty. |object| is the object being stored into, |value| is the
  // object being stored. The address and value registers are clobbered by the
  // operation. RecordWrite filters out smis so it does not update the
  // write barrier if the value is a smi.
  void RecordWrite(Register object, Register address, Register value,
                   SaveFPRegsMode save_fp,
                   SmiCheck smi_check = SmiCheck::kInline);

  // Allocates an EXIT/BUILTIN_EXIT/API_CALLBACK_EXIT frame with given number
  // of slots in non-GCed area.
  void EnterExitFrame(int extra_slots, StackFrame::Type frame_type,
                      Register c_function);
  void LeaveExitFrame(Register scratch);

  // Load the global proxy from the current context.
  void LoadGlobalProxy(Register dst);

  // Load a value from the native context with a given index.
  void LoadNativeContextSlot(Register dst, int index);

  // ---------------------------------------------------------------------------
  // JavaScript invokes

  // Invoke the JavaScript function code by either calling or jumping.

  void InvokeFunctionCode(Register function, Register new_target,
                          Register expected_parameter_count,
                          Register actual_parameter_count, InvokeType type);

  // On function call, call into the debugger.
  // This may clobber ecx.
  void CallDebugOnFunctionCall(Register fun, Register new_target,
                               Register expected_parameter_count,
                               Register actual_parameter_count);

  // Invoke the JavaScript function in the given register. Changes the
  // current context to the context in the function before invoking.
  void InvokeFunction(Register function, Register new_target,
                      Register actual_parameter_count, InvokeType type);

  // Compare object type for heap object.
  // Incoming register is heap_object and outgoing register is map.
  void CmpObjectType(Register heap_object, InstanceType type, Register map);

  // Compare instance type for map.
  void CmpInstanceType(Register map, InstanceType type);

  // Compare instance type ranges for a map (lower_limit and higher_limit
  // inclusive).
  //
  // Always use unsigned comparisons: below_equal for a positive
  // result.
  void CmpInstanceTypeRange(Register map, Register instance_type_out,
                            Register scratch, InstanceType lower_limit,
                            InstanceType higher_limit);

  // Smi tagging support.
  void SmiTag(Register reg) {
    static_assert(kSmiTag == 0);
    static_assert(kSmiTagSize == 1);
    add(reg, reg);
  }

  // Simple comparison of smis.  Both sides must be known smis to use these,
  // otherwise use Cmp.
  void SmiCompare(Register smi1, Register smi2);
  void SmiCompare(Register dst, Tagged<Smi> src);
  void SmiCompare(Register dst, Operand src);
  void SmiCompare(Operand dst, Register src);
  void SmiCompare(Operand dst, Smi src);

  // Jump if register contain a non-smi.
  inline void JumpIfNotSmi(Register value, Label* not_smi_label,
                           Label::Distance distance = Label::kFar) {
    test(value, Immediate(kSmiTagMask));
    j(not_zero, not_smi_label, distance);
  }
  // Jump if the operand is not a smi.
  inline void JumpIfNotSmi(Operand value, Label* smi_label,
                           Label::Distance distance = Label::kFar) {
    test(value, Immediate(kSmiTagMask));
    j(not_zero, smi_label, distance);
  }

  template <typename Field>
  void DecodeField(Register reg) {
    static const int shift = Field::kShift;
    static const int mask = Field::kMask >> Field::kShift;
    if (shift != 0) {
      sar(reg, shift);
    }
    and_(reg, Immediate(mask));
  }

  void TestCodeIsMarkedForDeoptimization(Register code);
  Immediate ClearedValue() const;

  // Tiering support.
  void AssertFeedbackCell(Register object,
                          Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void AssertFeedbackVector(Register object,
                            Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void ReplaceClosureCodeWithOptimizedCode(Register optimized_code,
                                           Register closure, Register scratch1,
                                           Register slot_address);
  void GenerateTailCallToReturnedCode(Runtime::FunctionId function_id);
  void LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      Register flags, XMMRegister saved_feedback_vector,
      CodeKind current_code_kind, Label* flags_need_processing);
  void OptimizeCodeOrTailCallOptimizedCodeSlot(
      Register flags, XMMRegister saved_feedback_vector);

  // Abort execution if argument is not a smi, enabled via --debug-code.
  void AssertSmi(Register object) NOOP_UNLESS_DEBUG_CODE;
  void AssertSmi(Operand object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is a smi, enabled via --debug-code.
  void AssertNotSmi(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSFunction, enabled via --debug-code.
  void AssertFunction(Register object, Register scratch) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a callable JSFunction, enabled via
  // --debug-code.
  void AssertCallableFunction(Register object,
                              Register scratch) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a Constructor, enabled via --debug-code.
  void AssertConstructor(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSBoundFunction,
  // enabled via --debug-code.
  void AssertBoundFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSGeneratorObject (or subclass),
  // enabled via --debug-code.
  void AssertGeneratorObject(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not undefined or an AllocationSite, enabled
  // via --debug-code.
  void AssertUndefinedOrAllocationSite(Register object,
                                       Register scratch) NOOP_UNLESS_DEBUG_CODE;

  void AssertJSAny(Register object, Register map_tmp,
                   AbortReason abort_reason) NOOP_UNLESS_DEBUG_CODE;

  // ---------------------------------------------------------------------------
  // Exception handling

  // Push a new stack handler and link it into stack handler chain.
  void PushStackHandler(Register scratch);

  // Unlink the stack handler on top of the stack from the stack handler chain.
  void PopStackHandler(Register scratch);

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

  // Convenience function: tail call a runtime routine (jump).
  void TailCallRuntime(Runtime::FunctionId fid);

  // Jump to a runtime routine.
  void JumpToExternalReference(const ExternalReference& ext,
                               bool builtin_exit_frame = false);

  // ---------------------------------------------------------------------------
  // Utilities

  // Emit code to discard a non-negative number of pointer-sized elements
  // from the stack, clobbering only the esp register.
  void Drop(int element_count);

  // ---------------------------------------------------------------------------
  // In-place weak references.
  void LoadWeakValue(Register in_out, Label* target_if_cleared);

  // ---------------------------------------------------------------------------
  // StatsCounter support

  void IncrementCounter(StatsCounter* counter, int value, Register scratch) {
    if (!v8_flags.native_code_counters) return;
    EmitIncrementCounter(counter, value, scratch);
  }
  void EmitIncrementCounter(StatsCounter* counter, int value, Register scratch);
  void DecrementCounter(StatsCounter* counter, int value, Register scratch) {
    if (!v8_flags.native_code_counters) return;
    EmitDecrementCounter(counter, value, scratch);
  }
  void EmitDecrementCounter(StatsCounter* counter, int value, Register scratch);

  // ---------------------------------------------------------------------------
  // Stack limit utilities
  void CompareStackLimit(Register with, StackLimitKind kind);
  Operand StackLimitAsOperand(StackLimitKind kind);

  void StackOverflowCheck(Register num_args, Register scratch,
                          Label* stack_overflow, bool include_receiver = false);

 protected:
  // Drops arguments assuming that the return address was already popped.
  void DropArguments(Register count);

 private:
  // Helper functions for generating invokes.
  void InvokePrologue(Register expected_parameter_count,
                      Register actual_parameter_count, Label* done,
                      InvokeType type);

  DISALLOW_IMPLICIT_CONSTRUCTORS(MacroAssembler);
};

// -----------------------------------------------------------------------------
// Static helper functions.

// Generate an Operand for loading a field from an object.
inline Operand FieldOperand(Register object, int offset) {
  return Operand(object, offset - kHeapObjectTag);
}

// Generate an Operand for loading an indexed field from an object.
inline Operand FieldOperand(Register object, Register index, ScaleFactor scale,
                            int offset) {
  return Operand(object, index, scale, offset - kHeapObjectTag);
}

// Provides access to exit frame stack space (not GC-ed).
inline Operand ExitFrameStackSlotOperand(int offset) {
  return Operand(esp, offset);
}

// Provides access to exit frame parameters (GC-ed).
inline Operand ExitFrameCallerStackSlotOperand(int index) {
  return Operand(ebp,
                 (BuiltinExitFrameConstants::kFixedSlotCountAboveFp + index) *
                     kSystemPointerSize);
}

struct MoveCycleState {
  // Whether a move in the cycle needs the double scratch register.
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

#endif  // V8_CODEGEN_IA32_MACRO_ASSEMBLER_IA32_H_

"""

```
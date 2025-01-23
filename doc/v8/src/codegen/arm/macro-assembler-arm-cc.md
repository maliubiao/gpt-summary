Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Assessment & Obvious Clues:**

* **File Path:** `v8/src/codegen/arm/macro-assembler-arm.cc`. This immediately tells us a few key things:
    * **`v8`:**  It's part of the V8 JavaScript engine.
    * **`codegen`:**  This relates to code generation, the process of turning higher-level code into machine instructions.
    * **`arm`:**  The code is specific to the ARM architecture.
    * **`macro-assembler-arm.cc`:** This strongly suggests it's a *macro assembler*. Macro assemblers provide higher-level abstractions over raw assembly instructions, making code generation easier. The `.cc` extension confirms it's C++ code.
* **Copyright Notice:** Standard V8 copyright, confirming its origin.
* **Includes:** The included headers provide clues about the functionalities this file touches:
    * `<limits.h>`: Standard C library for numerical limits.
    * `"src/base/bits.h"`, `"src/base/division-by-constant.h"`, etc.:  V8 base library components, suggesting low-level operations, math, and utility functions.
    * `"src/builtins/builtins-inl.h"`: Interaction with V8's built-in functions (core JavaScript features implemented in native code).
    * `"src/codegen/assembler-inl.h"`, `"src/codegen/callable.h"`, etc.: Other V8 code generation components, indicating this file is part of a larger code generation system.
    * `"src/debug/debug.h"`:  Debugging support.
    * `"src/deoptimizer/deoptimizer.h"`: Handling deoptimization (going back from optimized to less-optimized code).
    * `"src/execution/frames-inl.h"`: Managing execution stacks.
    * `"src/heap/mutable-page-metadata.h"`:  Memory management (V8's heap).
    * `"src/init/bootstrapper.h"`: V8 initialization.
    * `"src/logging/counters.h"`: Performance tracking.
    * `"src/objects/objects-inl.h"`: V8's object model (how JavaScript objects are represented in memory).
    * `"src/runtime/runtime.h"`: V8 runtime functions (native functions callable from JavaScript).
    * `"src/snapshot/snapshot.h"`: Saving and loading V8's internal state.
* **`#if V8_TARGET_ARCH_ARM`:** This confirms the architecture-specific nature of the code.
* **`#define __ ACCESS_MASM(masm)`:** A common V8 macro for simplifying access to the `MacroAssembler` instance.
* **Namespace:** `namespace v8 { namespace internal { ... }}`:  Standard V8 namespacing.

**2. Analyzing Key Methods and Sections:**

* **`MacroAssembler::RequiredStackSizeForCallerSaved`:**  Deals with calculating the stack space needed to save caller-saved registers. This is fundamental for function calls.
* **`MacroAssembler::PushCallerSaved` and `MacroAssembler::PopCallerSaved`:**  These are the core functions for actually saving and restoring caller-saved registers. The `SaveFPRegsMode` parameter indicates it handles both general-purpose and floating-point registers.
* **`MacroAssembler::LoadFromConstantsTable`, `LoadRootRelative`, `StoreRootRelative`, `LoadRootRegisterOffset`:** These functions are about accessing V8's internal data structures, particularly the "roots table" which holds pointers to important objects. The variations likely deal with different ways of addressing these constants.
* **`MacroAssembler::ExternalReferenceAsOperand`:**  This is crucial for interacting with code outside the currently generated code (e.g., calling C++ functions or accessing global variables). The complexity suggests it handles different scenarios for external references.
* **`MacroAssembler::Jump`, `Call`, `TailCallBuiltin`:** These are the core control flow instructions, responsible for jumping to different parts of the code or calling functions. The different overloads handle various target types (registers, addresses, Code objects, builtins). The `RelocInfo::Mode` is important for how the target address is handled during linking.
* **`MacroAssembler::LoadEntryFromBuiltinIndex`, `CallBuiltinByIndex`, `LoadEntryFromBuiltin`, `CallBuiltin`:** These are specific to calling V8's built-in functions, which are highly optimized native implementations of core JavaScript functionality.
* **`MacroAssembler::CallJSFunction`, `JumpJSFunction`:**  Specifically for calling and jumping to JavaScript functions.
* **`MacroAssembler::RecordWriteField`, `RecordWrite`, `CallRecordWriteStub`:** These functions are related to V8's garbage collector's write barrier. This is a crucial mechanism for ensuring memory safety when objects are modified. The complexity arises from different optimization levels and the need to track object references.
* **`MacroAssembler::PushCommonFrame`, `PushStandardFrame`:**  Functions for setting up stack frames when entering functions. Different frame types have different layouts.
* **`MacroAssembler::VFPCanonicalizeNaN`:**  Handles the specific case of canonicalizing Not-a-Number (NaN) values in floating-point operations.

**3. Inferring Overall Functionality:**

By looking at the types of operations and the context of the file path, it becomes clear that `macro-assembler-arm.cc` is a core component of V8's code generation pipeline for the ARM architecture. It provides a set of *macros* (higher-level instructions) that simplify the process of emitting ARM assembly code. This includes:

* **Register Management:** Saving, restoring, and manipulating registers.
* **Memory Access:** Loading and storing data from various memory locations (constants table, root table, object fields, external references).
* **Control Flow:** Implementing jumps, calls (both direct and indirect), and returns.
* **Function Calls:**  Specifically handling calls to JavaScript functions, built-in functions, and external C++ functions.
* **Garbage Collection Support:** Implementing the write barrier.
* **Stack Frame Management:** Setting up and tearing down stack frames.
* **Floating-Point Operations:** Handling floating-point numbers and special cases like NaN.

**4. Addressing the Specific Questions:**

* **Functionality Listing:**  This follows directly from the analysis of the methods and overall purpose.
* **Torque Check:** Checking the file extension is straightforward.
* **JavaScript Relationship:** Identify methods related to calling JavaScript functions and built-ins. Provide a simple JavaScript example that would trigger the execution of such code (e.g., a function call).
* **Code Logic Inference:** Focus on methods with clear inputs and outputs (e.g., `PushCallerSaved`). Create simple scenarios to illustrate the function's behavior.
* **Common Programming Errors:** Think about what could go wrong when manually managing registers and memory. For example, forgetting to save/restore registers or miscalculating offsets.
* **Overall Function Summary:**  Synthesize the findings into a concise summary of the file's role.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "It's just an assembler."  **Correction:** It's a *macro* assembler, providing a higher level of abstraction.
* **Focusing too much on individual instructions:** **Correction:**  Group related functions to understand their broader purpose (e.g., all the `Load...` functions relate to accessing constants and roots).
* **Overlooking the "why":** **Correction:**  Consider the context within V8. Why is register saving needed? Why is there a write barrier? Understanding the "why" helps to grasp the importance of the code.
* **Being too technical:** **Correction:**  When explaining the JavaScript relationship, use simple, illustrative examples rather than diving into the intricacies of the V8 compiler.

By following this systematic approach, combining code inspection with an understanding of the V8 architecture and general code generation principles, we can effectively analyze and summarize the functionality of a complex source code file like `macro-assembler-arm.cc`.
This is the first part of an analysis of the V8 source code file `v8/src/codegen/arm/macro-assembler-arm.cc`. Let's break down its functionality based on the provided snippet.

**Core Functionality of `v8/src/codegen/arm/macro-assembler-arm.cc`:**

This file defines the `MacroAssembler` class for the ARM architecture within the V8 JavaScript engine. A `MacroAssembler` provides a higher-level interface for generating ARM assembly instructions. It abstracts away some of the complexities of directly writing assembly code, making it easier for V8's compiler to produce efficient machine code.

Here's a breakdown of the specific functionalities demonstrated in this part:

1. **Caller-Saved Register Management:**
   - `RequiredStackSizeForCallerSaved`: Calculates the amount of stack space needed to save caller-saved registers before a function call.
   - `PushCallerSaved`:  Pushes caller-saved registers onto the stack. This is crucial for adhering to the ARM calling convention, ensuring that a called function doesn't corrupt registers that the caller expects to preserve. It can also handle saving floating-point registers.
   - `PopCallerSaved`: Restores caller-saved registers from the stack after a function call returns.

2. **Accessing Constants and Roots:**
   - `LoadFromConstantsTable`: Loads a value from V8's constants table into a register. This table stores frequently used values.
   - `LoadRootRelative`: Loads a value from a location relative to the `kRootRegister`. The root register points to important V8 internal data structures.
   - `StoreRootRelative`: Stores a value to a location relative to the `kRootRegister`.
   - `LoadRootRegisterOffset`: Loads the address of a specific offset from the `kRootRegister` into a destination register.
   - `ExternalReferenceAsOperand`:  Converts an `ExternalReference` (a pointer to data outside the generated code) into a memory operand that can be used in assembly instructions. It handles different scenarios, including isolate-independent code and accessing fields within the isolate.

3. **Label and Address Management:**
   - `GetLabelAddress`: Obtains the address of a specific label within the generated code.
   - `Jump`: Implements unconditional and conditional jumps to different locations in the code. It handles jumps to registers, absolute addresses, and code objects.

4. **Function Calls:**
   - `Call`: Implements function calls to registers, absolute addresses, and code objects. It also handles calls to V8 built-in functions.
   - `TailCallBuiltin`: Implements tail calls to built-in functions, which are optimizations where the current stack frame can be reused.
   - `LoadEntryFromBuiltinIndex`, `CallBuiltinByIndex`, `LoadEntryFromBuiltin`, `CallBuiltin`:  Mechanisms for calling V8's built-in functions, which implement core JavaScript functionalities.
   - `CallCodeObject`, `JumpCodeObject`:  Call or jump to a specific code object (compiled JavaScript or bytecode).
   - `CallJSFunction`, `JumpJSFunction`: Specifically designed for calling and jumping to JavaScript functions.
   - `ResolveWasmCodePointer`, `CallWasmCodePointer`: Handles calls to WebAssembly code.
   - `StoreReturnAddressAndCall`:  Used for calling C functions from V8.

5. **Stack Manipulation:**
   - `Ret`: Implements a function return.
   - `Drop`: Removes a specified number of items from the stack.
   - `EnforceStackAlignment`: Ensures the stack pointer is aligned correctly, which is often required by the ARM architecture.

6. **Deoptimization Support:**
   - `TestCodeIsMarkedForDeoptimization`: Checks if a code object is marked for deoptimization.

7. **Constants and Special Values:**
   - `ClearedValue`: Provides an operand representing a cleared value.

8. **Pushing Data onto the Stack:**
   - `Push`: Pushes various types of data (handles, Smis, TaggedIndices) onto the stack.
   - `PushArray`: Pushes the elements of an array onto the stack.

9. **Moving Data:**
   - `Move`:  Copies data between registers, or loads immediate values or addresses into registers. It handles different data types like Smis, HeapObjects, and external references.
   - `MovePair`: Moves two pairs of registers simultaneously.
   - `Swap`: Swaps the contents of two registers.

10. **Arithmetic and Logical Operations:**
    - `Mls`: Multiply and subtract (if supported by the CPU).
    - `And`, `Ubfx`, `Sbfx`, `Bfc`:  Bitwise logical operations and bitfield extractions.

11. **Loading Roots:**
    - `LoadRoot`: Loads a specific root object from the root table into a register.

12. **Write Barrier Implementation (Garbage Collection):**
    - `RecordWriteField`, `RecordWrite`, `CallEphemeronKeyBarrier`, `CallRecordWriteStubSaveRegisters`, `CallRecordWriteStub`, `MoveObjectAndSlot`: These functions are crucial for V8's garbage collector. They ensure that the collector is aware of object references when an object field is modified, maintaining the integrity of the heap.

13. **Zeroing Memory:**
    - `Zero`: Writes zero to a specified memory location.

14. **Saving and Restoring Registers (General Purpose):**
    - `MaybeSaveRegisters`, `MaybeRestoreRegisters`: Conditionally save or restore a list of registers.

15. **Frame Management:**
    - `PushCommonFrame`, `PushStandardFrame`:  Set up stack frames when entering functions.

16. **Floating-Point Operations (Specific Example):**
    - `VFPCanonicalizeNaN`: Canonicalizes Not-a-Number (NaN) values in floating-point registers.

**Regarding `.tq` extension and JavaScript examples:**

- **`.tq` extension:** The provided code snippet is in `.cc`, not `.tq`. Therefore, it's a standard C++ source file. If `v8/src/codegen/arm/macro-assembler-arm.cc` *were* named `v8/src/codegen/arm/macro-assembler-arm.tq`, then it would be a Torque source file. Torque is V8's domain-specific language for generating built-in functions more safely and efficiently.

- **Relationship with JavaScript and Examples:**  `macro-assembler-arm.cc` is deeply related to JavaScript because it's responsible for generating the low-level machine code that executes JavaScript.

   **Example:** When you call a JavaScript function, the V8 engine (specifically the compiler and this `MacroAssembler`) will generate ARM instructions similar to what's implemented in `CallJSFunction`.

   ```javascript
   function myFunction(a, b) {
     return a + b;
   }

   myFunction(5, 10);
   ```

   When `myFunction` is called, the V8 compiler will use the `MacroAssembler` to generate code that:
   - Sets up a stack frame (`PushStandardFrame`).
   - Loads the arguments `a` and `b` into registers.
   - Performs the addition.
   - Returns the result (`Ret`).

   Similarly, built-in JavaScript functions like `Array.push()` or `console.log()` have highly optimized implementations that are often generated using the `MacroAssembler` (or potentially Torque, which then uses the assembler). The `CallBuiltin` methods facilitate calling these optimized implementations.

**Code Logic Inference (Example):**

**Assumption:** `sp` (stack pointer) initially points to memory address `0x1000`.

**Input:**
- `fp_mode` = `SaveFPRegsMode::kSave`
- `exclusion1` = `r0`
- `exclusion2` = `r1`
- `exclusion3` = `no_reg`

**Execution of `PushCallerSaved`:**

1. **`RegList exclusions = {exclusion1, exclusion2, exclusion3};`**: `exclusions` will contain `r0` and `r1`.
2. **`RegList list = (kCallerSaved | lr) - exclusions;`**: `kCallerSaved` typically includes registers like `r0`-`r3`, `r12`. `lr` (link register) is also included. After removing `r0` and `r1`, `list` might contain `r2`, `r3`, `r12`, and `lr`.
3. **`stm(db_w, sp, list);`**: This ARM instruction "store multiple decrement before write" will push the registers in `list` onto the stack. Assuming the registers are pushed in decreasing order, the stack might look like this (assuming `kPointerSize` is 4):
   - `0xFFFC`: value of `lr`
   - `0xFFF8`: value of `r12`
   - `0xFFF4`: value of `r3`
   - `0xFFF0`: value of `r2`
   - `sp` is now `0xFFEC`
4. **`SaveFPRegs(sp, lr);`**: If `fp_mode` is `kSave`, this will push all the floating-point registers onto the stack. The stack pointer will decrease further.

**Output:**
- The stack pointer `sp` will be lower than the initial `0x1000`.
- The values of the caller-saved registers (and potentially floating-point registers) will be stored on the stack.
- The function returns the total number of bytes pushed onto the stack.

**Common Programming Errors:**

- **Incorrectly calculating stack size:**  Forgetting to account for all the registers being saved can lead to stack overflow or memory corruption.
- **Mismatched `PushCallerSaved` and `PopCallerSaved`:** If you push registers but don't pop the same registers in the correct order, the stack will become corrupted, leading to unpredictable behavior and crashes.
- **Using incorrect offsets:** When accessing data relative to the root register or within objects, using the wrong offset can lead to reading or writing to the wrong memory locations.
- **Forgetting to save or restore link register (`lr`):**  The `lr` holds the return address. If it's not saved before a call and restored afterward, the function won't return correctly.
- **Incorrectly handling the write barrier:** Failing to call the write barrier when modifying object fields can lead to the garbage collector not tracking references correctly, resulting in premature garbage collection and crashes.

**Summary of Part 1 Functionality:**

The first part of `v8/src/codegen/arm/macro-assembler-arm.cc` lays the groundwork for generating ARM assembly code in V8. It provides fundamental building blocks for managing registers, accessing memory, controlling program flow (jumps and calls), and interacting with V8's internal structures and the garbage collector. It handles the essential tasks needed to translate higher-level operations into executable machine instructions for the ARM architecture.

### 提示词
```
这是目录为v8/src/codegen/arm/macro-assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm/macro-assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_ARM

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/base/numbers/double.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/external-reference-table.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/register.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/objects/objects-inl.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/arm/macro-assembler-arm.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion1,
                                                    Register exclusion2,
                                                    Register exclusion3) const {
  int bytes = 0;
  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = (kCallerSaved | lr) - exclusions;

  bytes += list.Count() * kPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += DwVfpRegister::kNumRegisters * DwVfpRegister::kSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                    Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = (kCallerSaved | lr) - exclusions;
  stm(db_w, sp, list);

  bytes += list.Count() * kPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    SaveFPRegs(sp, lr);
    bytes += DwVfpRegister::kNumRegisters * DwVfpRegister::kSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                   Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    RestoreFPRegs(sp, lr);
    bytes += DwVfpRegister::kNumRegisters * DwVfpRegister::kSizeInBytes;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = (kCallerSaved | lr) - exclusions;
  ldm(ia_w, sp, list);

  bytes += list.Count() * kPointerSize;

  return bytes;
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));

  const uint32_t offset = OFFSET_OF_DATA_START(FixedArray) +
                          constant_index * kPointerSize - kHeapObjectTag;

  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  ldr(destination, MemOperand(destination, offset));
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  ldr(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  str(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    Move(destination, kRootRegister);
  } else {
    add(destination, kRootRegister, Operand(offset));
  }
}

MemOperand MacroAssembler::ExternalReferenceAsOperand(
    ExternalReference reference, Register scratch) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      return MemOperand(kRootRegister, reference.offset_from_root_register());
    }
    if (options().enable_root_relative_access) {
      intptr_t offset =
          RootRegisterOffsetForExternalReference(isolate(), reference);
      if (is_int32(offset)) {
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      }
    }
    if (options().isolate_independent_code) {
      if (IsAddressableThroughRootRegister(isolate(), reference)) {
        // Some external references can be efficiently loaded as an offset from
        // kRootRegister.
        intptr_t offset =
            RootRegisterOffsetForExternalReference(isolate(), reference);
        CHECK(is_int32(offset));
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      } else {
        // Otherwise, do a memory load from the external reference table.
        ldr(scratch,
            MemOperand(kRootRegister,
                       RootRegisterOffsetForExternalReferenceTableEntry(
                           isolate(), reference)));
        return MemOperand(scratch, 0);
      }
    }
  }
  Move(scratch, reference);
  return MemOperand(scratch, 0);
}

void MacroAssembler::GetLabelAddress(Register dest, Label* target) {
  // This should be just a
  //    add(dest, pc, branch_offset(target));
  // but current implementation of Assembler::bind_to()/target_at_put() add
  // (InstructionStream::kHeaderSize - kHeapObjectTag) to a position of a label
  // in a "linked" state and thus making it usable only for mov_label_offset().
  // TODO(ishell): fix branch_offset() and re-implement
  // RegExpMacroAssemblerARM::PushBacktrack() without mov_label_offset().
  mov_label_offset(dest, target);
  // mov_label_offset computes offset of the |target| relative to the "current
  // InstructionStream object pointer" which is essentally pc_offset() of the
  // label added with (InstructionStream::kHeaderSize - kHeapObjectTag).
  // Compute "current InstructionStream object pointer" and add it to the
  // offset in |lr| register.
  int current_instr_code_object_relative_offset =
      pc_offset() + Instruction::kPcLoadDelta +
      (InstructionStream::kHeaderSize - kHeapObjectTag);
  add(dest, pc, dest);
  sub(dest, dest, Operand(current_instr_code_object_relative_offset));
}

void MacroAssembler::Jump(Register target, Condition cond) { bx(target, cond); }

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond) {
  mov(pc, Operand(target, rmode), LeaveCC, cond);
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(!RelocInfo::IsCodeTarget(rmode));
  Jump(static_cast<intptr_t>(target), rmode, cond);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    TailCallBuiltin(builtin, cond);
    return;
  }

  // 'code' is always generated ARM code, never THUMB code
  Jump(static_cast<intptr_t>(code.address()), rmode, cond);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, reference);
  Jump(scratch);
}

void MacroAssembler::Call(Register target, Condition cond) {
  // Block constant pool for the call instruction sequence.
  BlockConstPoolScope block_const_pool(this);
  blx(target, cond);
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode, Condition cond,
                          TargetAddressStorageMode mode,
                          bool check_constant_pool) {
  // Check if we have to emit the constant pool before we block it.
  if (check_constant_pool) MaybeCheckConstPool();
  // Block constant pool for the call instruction sequence.
  BlockConstPoolScope block_const_pool(this);

  bool old_predictable_code_size = predictable_code_size();
  if (mode == NEVER_INLINE_TARGET_ADDRESS) {
    set_predictable_code_size(true);
  }

  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.

  // Call sequence on V7 or later may be :
  //  movw  ip, #... @ call address low 16
  //  movt  ip, #... @ call address high 16
  //  blx   ip
  //                      @ return address
  // Or for pre-V7 or values that may be back-patched
  // to avoid ICache flushes:
  //  ldr   ip, [pc, #...] @ call address
  //  blx   ip
  //                      @ return address

  mov(ip, Operand(target, rmode));
  blx(ip, cond);

  if (mode == NEVER_INLINE_TARGET_ADDRESS) {
    set_predictable_code_size(old_predictable_code_size);
  }
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, TargetAddressStorageMode mode,
                          bool check_constant_pool) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }

  // 'code' is always generated ARM code, never THUMB code
  Call(code.address(), rmode, cond, mode);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  ASM_CODE_COMMENT(this);
  static_assert(kSystemPointerSize == 4);
  static_assert(kSmiShiftSize == 0);
  static_assert(kSmiTagSize == 1);
  static_assert(kSmiTag == 0);

  // The builtin_index register contains the builtin index as a Smi.
  mov(target,
      Operand(builtin_index, LSL, kSystemPointerSizeLog2 - kSmiTagSize));
  add(target, target, Operand(IsolateData::builtin_entry_table_offset()));
  ldr(target, MemOperand(kRootRegister, target));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  ASM_CODE_COMMENT(this);
  ldr(destination, EntryFromBuiltinAsOperand(builtin));
}

MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::CallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(ip, cond);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect:
      ldr(ip, EntryFromBuiltinAsOperand(builtin));
      Call(ip, cond);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        bl(code_target_index * kInstrSize, cond,
           RelocInfo::RELATIVE_CODE_TARGET);
      } else {
        ldr(ip, EntryFromBuiltinAsOperand(builtin));
        Call(ip, cond);
      }
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Jump(ip, cond);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect:
      ldr(ip, EntryFromBuiltinAsOperand(builtin));
      Jump(ip, cond);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        b(code_target_index * kInstrSize, cond,
          RelocInfo::RELATIVE_CODE_TARGET);
      } else {
        ldr(ip, EntryFromBuiltinAsOperand(builtin));
        Jump(ip, cond);
      }
      break;
    }
  }
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  ldr(destination, FieldMemOperand(code_object, Code::kInstructionStartOffset));
}

void MacroAssembler::CallCodeObject(Register code_object) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  DCHECK_WITH_MSG(!V8_ENABLE_LEAPTIERING_BOOL,
                  "argument_count is only used with Leaptiering");
  Register code = kJavaScriptCallCodeStartRegister;
  ldr(code, FieldMemOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(code);
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
  Register code = kJavaScriptCallCodeStartRegister;
  ldr(code, FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, jump_mode);
}

void MacroAssembler::ResolveWasmCodePointer(Register target) {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  ExternalReference global_jump_table =
      ExternalReference::wasm_code_pointer_table();
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, global_jump_table);
  static_assert(sizeof(wasm::WasmCodePointerTableEntry) == 4);
  ldr(target, MemOperand(scratch, target, LSL, 2));
#endif
}

void MacroAssembler::CallWasmCodePointer(Register target,
                                         CallJumpMode call_jump_mode) {
  ResolveWasmCodePointer(target);
  if (call_jump_mode == CallJumpMode::kTailCall) {
    Jump(target);
  } else {
    Call(target);
  }
}

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  ASM_CODE_COMMENT(this);
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

  // Compute the return address in lr to return to after the jump below. The pc
  // is already at '+ 8' from the current instruction; but return is after three
  // instructions, so add another 4 to pc to get the return address.
  Assembler::BlockConstPoolScope block_const_pool(this);
  add(lr, pc, Operand(4));
  str(lr, MemOperand(sp));
  Call(target);
}

void MacroAssembler::Ret(Condition cond) { bx(lr, cond); }

void MacroAssembler::Drop(int count, Condition cond) {
  if (count > 0) {
    add(sp, sp, Operand(count * kPointerSize), LeaveCC, cond);
  }
}

void MacroAssembler::Drop(Register count, Condition cond) {
  add(sp, sp, Operand(count, LSL, kPointerSizeLog2), LeaveCC, cond);
}

// Enforce alignment of sp.
void MacroAssembler::EnforceStackAlignment() {
  int frame_alignment = ActivationFrameAlignment();
  DCHECK(base::bits::IsPowerOfTwo(frame_alignment));

  uint32_t frame_alignment_mask = ~(static_cast<uint32_t>(frame_alignment) - 1);
  and_(sp, sp, Operand(frame_alignment_mask));
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code,
                                                       Register scratch) {
  ldr(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  tst(scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::Call(Label* target) { bl(target); }

void MacroAssembler::Push(Handle<HeapObject> handle) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  mov(scratch, Operand(handle));
  push(scratch);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  mov(scratch, Operand(smi));
  push(scratch);
}

void MacroAssembler::Push(Tagged<TaggedIndex> index) {
  // TaggedIndex is the same as Smi for 32 bit archs.
  Push(Smi::FromIntptr(index.value()));
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               PushArrayOrder order) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register counter = scratch;
  Register tmp = temps.Acquire();
  DCHECK(!AreAliased(array, size, counter, tmp));
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    mov(counter, Operand(0));
    b(&entry);
    bind(&loop);
    ldr(tmp, MemOperand(array, counter, LSL, kSystemPointerSizeLog2));
    push(tmp);
    add(counter, counter, Operand(1));
    bind(&entry);
    cmp(counter, size);
    b(lt, &loop);
  } else {
    mov(counter, size);
    b(&entry);
    bind(&loop);
    ldr(tmp, MemOperand(array, counter, LSL, kSystemPointerSizeLog2));
    push(tmp);
    bind(&entry);
    sub(counter, counter, Operand(1), SetCC);
    b(ge, &loop);
  }
}

void MacroAssembler::Move(Register dst, Tagged<Smi> smi) {
  mov(dst, Operand(smi));
}

void MacroAssembler::Move(Register dst, Handle<HeapObject> value) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    IndirectLoadConstant(dst, value);
    return;
  }
  mov(dst, Operand(value));
}

void MacroAssembler::Move(Register dst, ExternalReference reference) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      add(dst, kRootRegister, Operand(reference.offset_from_root_register()));
      return;
    }
    if (options().isolate_independent_code) {
      IndirectLoadExternalReference(dst, reference);
      return;
    }
  }

  // External references should not get created with IDs if
  // `!root_array_available()`.
  CHECK(!reference.IsIsolateFieldId());
  mov(dst, Operand(reference));
}

void MacroAssembler::LoadIsolateField(Register dst, IsolateFieldId id) {
  Move(dst, ExternalReference::Create(id));
}

void MacroAssembler::Move(Register dst, Register src, Condition cond) {
  if (dst != src) {
    mov(dst, src, LeaveCC, cond);
  }
}

void MacroAssembler::Move(SwVfpRegister dst, SwVfpRegister src,
                          Condition cond) {
  if (dst != src) {
    vmov(dst, src, cond);
  }
}

void MacroAssembler::Move(DwVfpRegister dst, DwVfpRegister src,
                          Condition cond) {
  if (dst != src) {
    vmov(dst, src, cond);
  }
}

void MacroAssembler::Move(QwNeonRegister dst, QwNeonRegister src) {
  if (dst != src) {
    vmov(dst, src);
  }
}

void MacroAssembler::MovePair(Register dst0, Register src0, Register dst1,
                              Register src1) {
  DCHECK_NE(dst0, dst1);
  if (dst0 != src1) {
    Move(dst0, src0);
    Move(dst1, src1);
  } else if (dst1 != src0) {
    // Swap the order of the moves to resolve the overlap.
    Move(dst1, src1);
    Move(dst0, src0);
  } else {
    // Worse case scenario, this is a swap.
    Swap(dst0, src0);
  }
}

void MacroAssembler::Swap(Register srcdst0, Register srcdst1) {
  DCHECK(srcdst0 != srcdst1);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  mov(scratch, srcdst0);
  mov(srcdst0, srcdst1);
  mov(srcdst1, scratch);
}

void MacroAssembler::Swap(DwVfpRegister srcdst0, DwVfpRegister srcdst1) {
  DCHECK(srcdst0 != srcdst1);
  DCHECK(VfpRegisterIsAvailable(srcdst0));
  DCHECK(VfpRegisterIsAvailable(srcdst1));

  if (CpuFeatures::IsSupported(NEON)) {
    vswp(srcdst0, srcdst1);
  } else {
    UseScratchRegisterScope temps(this);
    DwVfpRegister scratch = temps.AcquireD();
    vmov(scratch, srcdst0);
    vmov(srcdst0, srcdst1);
    vmov(srcdst1, scratch);
  }
}

void MacroAssembler::Swap(QwNeonRegister srcdst0, QwNeonRegister srcdst1) {
  DCHECK(srcdst0 != srcdst1);
  vswp(srcdst0, srcdst1);
}

void MacroAssembler::Mls(Register dst, Register src1, Register src2,
                         Register srcA, Condition cond) {
  if (CpuFeatures::IsSupported(ARMv7)) {
    CpuFeatureScope scope(this, ARMv7);
    mls(dst, src1, src2, srcA, cond);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(srcA != scratch);
    mul(scratch, src1, src2, LeaveCC, cond);
    sub(dst, srcA, scratch, LeaveCC, cond);
  }
}

void MacroAssembler::And(Register dst, Register src1, const Operand& src2,
                         Condition cond) {
  if (!src2.IsRegister() && !src2.MustOutputRelocInfo(this) &&
      src2.immediate() == 0) {
    mov(dst, Operand::Zero(), LeaveCC, cond);
  } else if (!(src2.InstructionsRequired(this) == 1) &&
             !src2.MustOutputRelocInfo(this) &&
             CpuFeatures::IsSupported(ARMv7) &&
             base::bits::IsPowerOfTwo(src2.immediate() + 1)) {
    CpuFeatureScope scope(this, ARMv7);
    ubfx(dst, src1, 0,
         base::bits::WhichPowerOfTwo(static_cast<uint32_t>(src2.immediate()) +
                                     1),
         cond);
  } else {
    and_(dst, src1, src2, LeaveCC, cond);
  }
}

void MacroAssembler::Ubfx(Register dst, Register src1, int lsb, int width,
                          Condition cond) {
  DCHECK_LT(lsb, 32);
  if (!CpuFeatures::IsSupported(ARMv7) || predictable_code_size()) {
    int mask = (1u << (width + lsb)) - 1u - ((1u << lsb) - 1u);
    and_(dst, src1, Operand(mask), LeaveCC, cond);
    if (lsb != 0) {
      mov(dst, Operand(dst, LSR, lsb), LeaveCC, cond);
    }
  } else {
    CpuFeatureScope scope(this, ARMv7);
    ubfx(dst, src1, lsb, width, cond);
  }
}

void MacroAssembler::Sbfx(Register dst, Register src1, int lsb, int width,
                          Condition cond) {
  DCHECK_LT(lsb, 32);
  if (!CpuFeatures::IsSupported(ARMv7) || predictable_code_size()) {
    int mask = (1 << (width + lsb)) - 1 - ((1 << lsb) - 1);
    and_(dst, src1, Operand(mask), LeaveCC, cond);
    int shift_up = 32 - lsb - width;
    int shift_down = lsb + shift_up;
    if (shift_up != 0) {
      mov(dst, Operand(dst, LSL, shift_up), LeaveCC, cond);
    }
    if (shift_down != 0) {
      mov(dst, Operand(dst, ASR, shift_down), LeaveCC, cond);
    }
  } else {
    CpuFeatureScope scope(this, ARMv7);
    sbfx(dst, src1, lsb, width, cond);
  }
}

void MacroAssembler::Bfc(Register dst, Register src, int lsb, int width,
                         Condition cond) {
  DCHECK_LT(lsb, 32);
  if (!CpuFeatures::IsSupported(ARMv7) || predictable_code_size()) {
    int mask = (1 << (width + lsb)) - 1 - ((1 << lsb) - 1);
    bic(dst, src, Operand(mask));
  } else {
    CpuFeatureScope scope(this, ARMv7);
    Move(dst, src, cond);
    bfc(dst, lsb, width, cond);
  }
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index,
                              Condition cond) {
  ldr(destination,
      MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)), cond);
}

void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value,
                                      LinkRegisterStatus lr_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check) {
  ASM_CODE_COMMENT(this);
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so so offset must be a multiple of kPointerSize.
  DCHECK(IsAligned(offset, kPointerSize));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    Label ok;
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(!AreAliased(object, value, scratch));
    add(scratch, object, Operand(offset - kHeapObjectTag));
    tst(scratch, Operand(kPointerSize - 1));
    b(eq, &ok);
    stop();
    bind(&ok);
  }

  RecordWrite(object, Operand(offset - kHeapObjectTag), value, lr_status,
              save_fp, SmiCheck::kOmit);

  bind(&done);
}

void MacroAssembler::Zero(const MemOperand& dest) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  mov(scratch, Operand::Zero());
  str(scratch, dest);
}
void MacroAssembler::Zero(const MemOperand& dest1, const MemOperand& dest2) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  mov(scratch, Operand::Zero());
  str(scratch, dest1);
  str(scratch, dest2);
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  stm(db_w, sp, registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  ldm(ia_w, sp, registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object, Operand offset,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();
  MoveObjectAndSlot(object_parameter, slot_address_parameter, object, offset);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Operand offset,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();
  MoveObjectAndSlot(object_parameter, slot_address_parameter, object, offset);

  CallRecordWriteStub(object_parameter, slot_address_parameter, fp_mode, mode);

  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStub(Register object, Register slot_address,
                                         SaveFPRegsMode fp_mode,
                                         StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    Call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode));
  }
}

void MacroAssembler::MoveObjectAndSlot(Register dst_object, Register dst_slot,
                                       Register object, Operand offset) {
  DCHECK_NE(dst_object, dst_slot);
  DCHECK(offset.IsRegister() || offset.IsImmediate());
  // If `offset` is a register, it cannot overlap with `object`.
  DCHECK_IMPLIES(offset.IsRegister(), offset.rm() != object);

  // If the slot register does not overlap with the object register, we can
  // overwrite it.
  if (dst_slot != object) {
    add(dst_slot, object, offset);
    Move(dst_object, object);
    return;
  }

  DCHECK_EQ(dst_slot, object);

  // If the destination object register does not overlap with the offset
  // register, we can overwrite it.
  if (!offset.IsRegister() || (offset.rm() != dst_object)) {
    Move(dst_object, dst_slot);
    add(dst_slot, dst_slot, offset);
    return;
  }

  DCHECK_EQ(dst_object, offset.rm());

  // We only have `dst_slot` and `dst_object` left as distinct registers so we
  // have to swap them. We write this as a add+sub sequence to avoid using a
  // scratch register.
  add(dst_slot, dst_slot, dst_object);
  sub(dst_object, dst_slot, dst_object);
}

// The register 'object' contains a heap object pointer. The heap object tag is
// shifted away. A scratch register also needs to be available.
void MacroAssembler::RecordWrite(Register object, Operand offset,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check) {
  DCHECK(!AreAliased(object, value));
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(!AreAliased(object, value, scratch));
    add(scratch, object, offset);
    ldr(scratch, MemOperand(scratch));
    cmp(scratch, value);
    Check(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite);
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  CheckPageFlag(value, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                &done);
  CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask, eq,
                &done);

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    push(lr);
  }

  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, value, slot_address));
  DCHECK(!offset.IsRegister());
  add(slot_address, object, offset);
  CallRecordWriteStub(object, slot_address, fp_mode);
  if (lr_status == kLRHasNotBeenSaved) {
    pop(lr);
  }

  if (v8_flags.debug_code) Move(slot_address, Operand(kZapValue));

  bind(&done);
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  ASM_CODE_COMMENT(this);
  if (marker_reg.is_valid()) {
    if (marker_reg.code() > fp.code()) {
      stm(db_w, sp, {fp, lr});
      mov(fp, Operand(sp));
      Push(marker_reg);
    } else {
      stm(db_w, sp, {marker_reg, fp, lr});
      add(fp, sp, Operand(kPointerSize));
    }
  } else {
    stm(db_w, sp, {fp, lr});
    mov(fp, sp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  ASM_CODE_COMMENT(this);
  DCHECK(!function_reg.is_valid() || function_reg.code() < cp.code());
  stm(db_w, sp, {function_reg, cp, fp, lr});
  int offset = -StandardFrameConstants::kContextOffset;
  offset += function_reg.is_valid() ? kPointerSize : 0;
  add(fp, sp, Operand(offset));
  Push(kJavaScriptCallArgCountRegister);
}

void MacroAssembler::VFPCanonicalizeNaN(const DwVfpRegister dst,
                                        const DwVfpRegister src,
                                        const Condition cond) {
  // Subtracting 0.0 preserves all inputs except for sig
```
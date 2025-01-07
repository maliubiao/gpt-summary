Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/ia32/macro-assembler-ia32.cc`.

Here's a breakdown of how to approach this:

1. **Identify the file's purpose:** The path suggests it's part of the code generation for the IA32 architecture in V8. The name "macro-assembler" indicates it provides higher-level abstractions over the underlying assembler.

2. **Analyze the includes:** The included headers reveal the components this file interacts with:
    - `v8-internal.h`: Core V8 definitions.
    - `src/base/...`: Basic utilities and platform abstraction.
    - `src/codegen/...`: Code generation related classes (assembler, bailout, code factory, etc.).
    - `src/objects/...`: V8 object model definitions.
    - `src/runtime/...`: Runtime functions.
    - `src/handles/...`: Handle management.
    - `src/heap/...`: Heap management.
    - `src/flags/...`: V8 flags.

3. **Examine key functionalities:** Scan the code for prominent methods and patterns:
    - **Root Register Handling:**  `InitializeRootRegister`, `LoadRoot`, `CompareRoot`, `PushRoot`. This suggests managing access to the V8 isolate's root object.
    - **Stack Argument Access:** `StackArgumentsAccessor`. Likely for accessing function arguments on the stack.
    - **External References:** `ExternalReferenceAsOperand`, `LoadAddress`. Indicates handling of references to external data or functions.
    - **Heap Object Operations:** `HeapObjectAsOperand`, `LoadMap`, `CmpObjectType`, `RecordWriteField`, `RecordWrite`. These are crucial for interacting with V8's object model and implementing garbage collection write barriers.
    - **Function Calls and Tail Calls:**  `GenerateTailCallToReturnedCode`, `TailCallOptimizedCodeSlot`, `CallRuntime`, `CallBuiltin`. Deals with calling functions, both within V8 and to external code.
    - **Optimization and Tiering:** `LoadFeedbackVector`, `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing`, `OptimizeCodeOrTailCallOptimizedCodeSlot`. Highlights mechanisms for optimizing JavaScript code execution.
    - **Register Saving/Restoring:** `PushCallerSaved`, `PopCallerSaved`. Important for maintaining register state during function calls.
    - **Type Assertions:** `AssertSmi`, `AssertHeapObject`, etc. Used for debugging and ensuring type safety in generated code.
    - **Floating-Point Operations:** `Cvtsi2ss`, `Cvtsi2sd`, etc. Shows support for converting between integer and floating-point representations.
    - **Bitwise Operations:** `ShlPair`, `ShrPair`, `SarPair`. Indicates low-level bit manipulation capabilities.

4. **Consider the "torque" aspect:** The prompt mentions `.tq` files. Since this file is `.cc`, it's not a Torque source file. This part of the prompt serves as a distractor or a check for understanding of V8's build system.

5. **JavaScript Relationship:** Many of the operations directly relate to JavaScript functionality. For instance, accessing arguments, calling functions, working with objects, and handling optimization are all fundamental to executing JavaScript code.

6. **Code Logic and Examples:** Focus on specific methods and illustrate their behavior with simple examples. For instance, `LoadRoot` loads a specific root object; `RecordWrite` implements a write barrier.

7. **Common Programming Errors:**  Relate the functionality to common pitfalls in lower-level programming, like incorrect register usage, stack management issues, and type errors.

8. **Summarize the Functionality:**  Combine the observations into a concise summary of the file's role.

**Self-Correction/Refinement:**

- Initially, I might focus too heavily on individual instructions. It's important to step back and see the bigger picture of the macro-assembler's purpose within the code generation pipeline.
- The "torque" comment needs to be addressed directly and clarified that it's not applicable to this file.
- When giving JavaScript examples, ensure they clearly relate to the C++ code's function. For example, object property access in JavaScript corresponds to field access in the C++ code.
-  The level of detail in the explanation should be balanced. Avoid getting bogged down in the specifics of every function, but provide enough information to convey the core responsibilities.
This C++ source file, `v8/src/codegen/ia32/macro-assembler-ia32.cc`, is a core component of the V8 JavaScript engine responsible for **generating machine code for the IA32 (x86 32-bit) architecture**. It provides a higher-level abstraction layer over the raw assembly instructions, making it easier for V8 developers to generate efficient and correct code.

Here's a breakdown of its key functionalities:

**1. Abstraction over Assembly Instructions:**

- It offers a set of C++ methods that correspond to common IA32 assembly instructions and higher-level operations. This allows developers to write code that is closer to the logic they want to implement without dealing with the intricacies of individual assembly opcodes.
- The `MacroAssembler` class inherits from `MacroAssemblerBase` and provides IA32-specific functionalities.
- The `__` macro within the file is used as a shorthand to access the `MacroAssembler` instance's methods.

**2. Accessing V8 Runtime Data:**

- **Root Register Management:** It manages the `kRootRegister`, which holds a pointer to the V8 isolate's root object. This provides a central access point to various V8 internal data structures. Methods like `InitializeRootRegister`, `LoadRoot`, `CompareRoot`, and `PushRoot` are used for this purpose.
- **External References:** It handles external references to functions or data outside the generated code. Methods like `ExternalReferenceAsOperand` and `LoadAddress` are used to load these references.
- **Constants Table:** It provides a way to load constants from the V8 constants table using `LoadFromConstantsTable`.

**3. Stack Manipulation:**

- **Argument Access:** The `StackArgumentsAccessor` class provides a way to access arguments passed on the stack to a function.
- **Caller-Saved Registers:** It provides methods `PushCallerSaved` and `PopCallerSaved` to save and restore registers that a calling function might need to preserve across a call.

**4. Heap Object Operations:**

- **Loading Object Information:** It includes functions to load the map (type information) of an object (`LoadMap`) and compare object types (`CmpObjectType`, `CmpInstanceType`).
- **Write Barrier:** It implements the write barrier, a crucial mechanism for the garbage collector. The `RecordWriteField` and `RecordWrite` methods ensure that when an object pointer is updated, the garbage collector is notified to maintain heap integrity.
- **Feedback Vectors:** It provides functions to load and manipulate feedback vectors, which are used for runtime optimization (`LoadFeedbackVector`, `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing`).

**5. Function Calls and Tail Calls:**

- It offers methods for generating regular function calls (`CallRuntime`, `CallBuiltin`) and optimized tail calls (`GenerateTailCallToReturnedCode`, `TailCallOptimizedCodeSlot`). Tail calls are important for optimizing certain function call patterns.

**6. Code Optimization and Tiering:**

- It includes logic to handle optimized code and the tiering of code (moving between different optimization levels). The `OptimizeCodeOrTailCallOptimizedCodeSlot` method checks for available optimized code and performs the appropriate action.

**7. Debugging and Assertions:**

- It includes assertion methods (`AssertSmi`, `AssertHeapObject`, etc.) that are used in debug builds to verify assumptions about the state of the program.

**8. Floating-Point and Bitwise Operations:**

- It provides methods for common floating-point conversions and arithmetic (`Cvtsi2ss`, `Cvtsi2sd`, etc.) and bitwise shift operations (`ShlPair`, `ShrPair`, `SarPair`).

**Regarding the `.tq` suffix:**

The statement "if v8/src/codegen/ia32/macro-assembler-ia32.cc以.tq结尾，那它是个v8 torque源代码" is **incorrect**. Files ending in `.tq` in the V8 codebase are indeed **Torque** source files. Torque is a domain-specific language used in V8 to generate efficient C++ code for built-in functions. Since `macro-assembler-ia32.cc` ends in `.cc`, it is a standard C++ source file.

**Relationship with JavaScript and Examples:**

This file is **directly related** to JavaScript functionality. It's responsible for generating the low-level instructions that execute JavaScript code. Many of its functions directly correspond to operations performed in JavaScript.

Here are some examples of how the C++ code relates to JavaScript:

* **Object Property Access:** When you access a property of an object in JavaScript (e.g., `obj.property`), the generated IA32 code using `macro-assembler-ia32.cc` might involve:
    - Loading the object's map using `LoadMap`.
    - Determining the offset of the property within the object.
    - Loading the property value using an appropriate memory access instruction.
    - If the property is being written, potentially calling `RecordWriteField` to ensure the write barrier is executed.

   ```javascript
   const obj = { x: 10 };
   const value = obj.x; // Accessing a property
   obj.y = 20;        // Setting a property
   ```

* **Function Calls:** When a JavaScript function is called, the generated IA32 code will use methods like `CallRuntime` or `CallBuiltin` (for built-in functions) to transfer control to the target function. It will also involve setting up the stack frame for the call.

   ```javascript
   function myFunction(a, b) {
       return a + b;
   }
   const result = myFunction(5, 3); // Calling a function
   ```

* **Garbage Collection:** The `RecordWrite` family of functions is essential for the garbage collector. When a pointer within a JavaScript object is updated, these functions ensure that the garbage collector is aware of the change, allowing it to track object references correctly and prevent memory leaks.

* **Optimization:** The logic involving feedback vectors and optimized code relates to how V8 optimizes frequently executed JavaScript code. The generated code might check the feedback vector to see if an optimized version of a function is available and then perform a tail call to that optimized code using `TailCallOptimizedCodeSlot`.

**Code Logic Inference (Hypothetical Example):**

Let's consider the `LoadRoot` function:

**Hypothetical Input:** `destination` = `eax`, `index` = `RootIndex::kUndefinedValue`

**Code Logic:**  The `LoadRoot` function checks if the root array is available. If it is, it calculates the offset of the `undefined` value within the root array and loads it into the `eax` register. If the root array is not available (in older V8 versions or specific configurations), it might load the `undefined` value from a fixed memory location or use other strategies.

**Hypothetical Output:** The `eax` register will contain the memory address of the `undefined` value in the V8 heap.

**Common Programming Errors (Related to this file's domain):**

While developers rarely directly edit this file, understanding its purpose helps in understanding potential errors in the V8 engine itself or in generated code:

* **Incorrect Register Usage:** If the code generation logic incorrectly allocates or uses registers, it can lead to data corruption or unexpected behavior. For example, accidentally overwriting a register that holds an important value.
* **Stack Corruption:** Errors in managing the stack (e.g., incorrect pushes or pops) can lead to crashes or unpredictable behavior. This could manifest if `PushCallerSaved` or `PopCallerSaved` are used incorrectly.
* **Write Barrier Failures:** If the write barrier is not correctly implemented or called, the garbage collector might not track object references accurately, leading to premature garbage collection and dangling pointers.
* **Type Errors:** If the generated code makes incorrect assumptions about the types of objects, it can lead to errors when accessing object properties or calling methods. The assertion methods in this file are designed to catch some of these errors during development.

**Summary of Functionality (Part 1):**

In essence, `v8/src/codegen/ia32/macro-assembler-ia32.cc` provides the building blocks for generating machine code for the IA32 architecture within the V8 JavaScript engine. It offers an abstraction layer over raw assembly, facilitating access to V8 runtime data, managing the stack, performing heap object operations (including the critical write barrier), handling function calls and optimizations, and incorporating debugging aids. It plays a crucial role in the execution of JavaScript code by translating high-level JavaScript constructs into low-level machine instructions that the processor can understand and execute.

Prompt: 
```
这是目录为v8/src/codegen/ia32/macro-assembler-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ia32/macro-assembler-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_IA32

#include <stdint.h>

#include "include/v8-internal.h"
#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/platform/platform.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/external-reference.h"
#include "src/codegen/ia32/assembler-ia32.h"
#include "src/codegen/ia32/register-ia32.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/label.h"
#include "src/codegen/macro-assembler-base.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register.h"
#include "src/codegen/reglist.h"
#include "src/codegen/reloc-info.h"
#include "src/common/globals.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-data.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/handles/handles-inl.h"
#include "src/handles/handles.h"
#include "src/heap/factory-inl.h"
#include "src/heap/factory.h"
#include "src/heap/memory-chunk-metadata.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/logging/counters.h"
#include "src/objects/code.h"
#include "src/objects/contexts.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-function.h"
#include "src/objects/map.h"
#include "src/objects/objects.h"
#include "src/objects/oddball.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/slots-inl.h"
#include "src/objects/smi.h"
#include "src/roots/roots-inl.h"
#include "src/roots/roots.h"
#include "src/runtime/runtime.h"
#include "src/utils/utils.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/ia32/macro-assembler-ia32.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

Operand StackArgumentsAccessor::GetArgumentOperand(int index) const {
  DCHECK_GE(index, 0);
  // arg[0] = esp + kPCOnStackSize;
  // arg[i] = arg[0] + i * kSystemPointerSize;
  return Operand(esp, kPCOnStackSize + index * kSystemPointerSize);
}

// -------------------------------------------------------------------------
// MacroAssembler implementation.

void MacroAssembler::InitializeRootRegister() {
  ASM_CODE_COMMENT(this);
  ExternalReference isolate_root = ExternalReference::isolate_root(isolate());
  Move(kRootRegister, Immediate(isolate_root));
}

Operand MacroAssembler::RootAsOperand(RootIndex index) {
  DCHECK(root_array_available());
  return Operand(kRootRegister, RootRegisterOffsetForRootIndex(index));
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (root_array_available()) {
    mov(destination, RootAsOperand(index));
    return;
  }

  if (RootsTable::IsImmortalImmovable(index)) {
    Handle<Object> object = isolate()->root_handle(index);
    if (IsSmi(*object)) {
      mov(destination, Immediate(Cast<Smi>(*object)));
      return;
    } else {
      DCHECK(IsHeapObject(*object));
      mov(destination, Cast<HeapObject>(object));
      return;
    }
  }

  ExternalReference isolate_root = ExternalReference::isolate_root(isolate());
  lea(destination,
      Operand(isolate_root.address(), RelocInfo::EXTERNAL_REFERENCE));
  mov(destination, Operand(destination, RootRegisterOffsetForRootIndex(index)));
}

void MacroAssembler::CompareRoot(Register with, Register scratch,
                                 RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (root_array_available()) {
    CompareRoot(with, index);
  } else {
    ExternalReference isolate_root = ExternalReference::isolate_root(isolate());
    lea(scratch,
        Operand(isolate_root.address(), RelocInfo::EXTERNAL_REFERENCE));
    cmp(with, Operand(scratch, RootRegisterOffsetForRootIndex(index)));
  }
}

void MacroAssembler::CompareRoot(Register with, RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (root_array_available()) {
    cmp(with, RootAsOperand(index));
    return;
  }

  DCHECK(RootsTable::IsImmortalImmovable(index));
  Handle<Object> object = isolate()->root_handle(index);
  if (IsHeapObject(*object)) {
    cmp(with, Cast<HeapObject>(object));
  } else {
    cmp(with, Immediate(Cast<Smi>(*object)));
  }
}

void MacroAssembler::PushRoot(RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (root_array_available()) {
    DCHECK(RootsTable::IsImmortalImmovable(index));
    push(RootAsOperand(index));
    return;
  }

  // TODO(v8:6666): Add a scratch register or remove all uses.
  DCHECK(RootsTable::IsImmortalImmovable(index));
  Handle<Object> object = isolate()->root_handle(index);
  if (IsHeapObject(*object)) {
    Push(Cast<HeapObject>(object));
  } else {
    Push(Cast<Smi>(*object));
  }
}

void MacroAssembler::CompareRange(Register value, unsigned lower_limit,
                                  unsigned higher_limit, Register scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    lea(scratch, Operand(value, 0u - lower_limit));
    cmp(scratch, Immediate(higher_limit - lower_limit));
  } else {
    cmp(value, Immediate(higher_limit));
  }
}

void MacroAssembler::JumpIfIsInRange(Register value, unsigned lower_limit,
                                     unsigned higher_limit, Register scratch,
                                     Label* on_in_range,
                                     Label::Distance near_jump) {
  CompareRange(value, lower_limit, higher_limit, scratch);
  j(below_equal, on_in_range, near_jump);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               PushArrayOrder order) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(array, size, scratch));
  Register counter = scratch;
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    mov(counter, 0);
    jmp(&entry);
    bind(&loop);
    Push(Operand(array, counter, times_system_pointer_size, 0));
    inc(counter);
    bind(&entry);
    cmp(counter, size);
    j(less, &loop, Label::kNear);
  } else {
    mov(counter, size);
    jmp(&entry);
    bind(&loop);
    Push(Operand(array, counter, times_system_pointer_size, 0));
    bind(&entry);
    dec(counter);
    j(greater_equal, &loop, Label::kNear);
  }
}

Operand MacroAssembler::ExternalReferenceAsOperand(ExternalReference reference,
                                                   Register scratch) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      return Operand(kRootRegister, reference.offset_from_root_register());
    }
    if (options().enable_root_relative_access) {
      intptr_t delta =
          RootRegisterOffsetForExternalReference(isolate(), reference);
      return Operand(kRootRegister, delta);
    }
    if (options().isolate_independent_code) {
      if (IsAddressableThroughRootRegister(isolate(), reference)) {
        // Some external references can be efficiently loaded as an offset from
        // kRootRegister.
        intptr_t offset =
            RootRegisterOffsetForExternalReference(isolate(), reference);
        return Operand(kRootRegister, offset);
      } else {
        // Otherwise, do a memory load from the external reference table.
        mov(scratch, Operand(kRootRegister,
                             RootRegisterOffsetForExternalReferenceTableEntry(
                                 isolate(), reference)));
        return Operand(scratch, 0);
      }
    }
  }
  Move(scratch, Immediate(reference));
  return Operand(scratch, 0);
}

// TODO(v8:6666): If possible, refactor into a platform-independent function in
// MacroAssembler.
Operand MacroAssembler::HeapObjectAsOperand(Handle<HeapObject> object) {
  DCHECK(root_array_available());

  Builtin builtin;
  RootIndex root_index;
  if (isolate()->roots_table().IsRootHandle(object, &root_index)) {
    return RootAsOperand(root_index);
  } else if (isolate()->builtins()->IsBuiltinHandle(object, &builtin)) {
    return Operand(kRootRegister, RootRegisterOffsetForBuiltin(builtin));
  } else if (object.is_identical_to(code_object_) &&
             Builtins::IsBuiltinId(maybe_builtin_)) {
    return Operand(kRootRegister, RootRegisterOffsetForBuiltin(maybe_builtin_));
  } else {
    // Objects in the constants table need an additional indirection, which
    // cannot be represented as a single Operand.
    UNREACHABLE();
  }
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  ASM_CODE_COMMENT(this);
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  mov(destination,
      FieldOperand(destination, FixedArray::OffsetOfElementAt(constant_index)));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  ASM_CODE_COMMENT(this);
  DCHECK(is_int32(offset));
  DCHECK(root_array_available());
  if (offset == 0) {
    mov(destination, kRootRegister);
  } else {
    lea(destination, Operand(kRootRegister, static_cast<int32_t>(offset)));
  }
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  mov(destination, Operand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  mov(Operand(kRootRegister, offset), value);
}

void MacroAssembler::LoadAddress(Register destination,
                                 ExternalReference source) {
  if (root_array_available()) {
    if (source.IsIsolateFieldId()) {
      lea(destination,
          Operand(kRootRegister, source.offset_from_root_register()));
      return;
    }
    if (options().isolate_independent_code) {
      IndirectLoadExternalReference(destination, source);
      return;
    }
  }
  // External references should not get created with IDs if
  // `!root_array_available()`.
  CHECK(!source.IsIsolateFieldId());
  mov(destination, Immediate(source));
}

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion) const {
  int bytes = 0;
  RegList saved_regs = kCallerSaved - exclusion;
  bytes += kSystemPointerSize * saved_regs.Count();

  if (fp_mode == SaveFPRegsMode::kSave) {
    // Count all XMM registers except XMM0.
    bytes += kStackSavedSavedFPSize * (XMMRegister::kNumRegisters - 1);
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode,
                                    Register exclusion) {
  ASM_CODE_COMMENT(this);
  // We don't allow a GC in a write barrier slow path so there is no need to
  // store the registers in any particular way, but we do have to store and
  // restore them.
  int bytes = 0;
  RegList saved_regs = kCallerSaved - exclusion;
  for (Register reg : saved_regs) {
    push(reg);
    bytes += kSystemPointerSize;
  }

  if (fp_mode == SaveFPRegsMode::kSave) {
    // Save all XMM registers except XMM0.
    const int delta = kStackSavedSavedFPSize * (XMMRegister::kNumRegisters - 1);
    AllocateStackSpace(delta);
    for (int i = XMMRegister::kNumRegisters - 1; i > 0; i--) {
      XMMRegister reg = XMMRegister::from_code(i);
#if V8_ENABLE_WEBASSEMBLY
      Movdqu(Operand(esp, (i - 1) * kStackSavedSavedFPSize), reg);
#else
      Movsd(Operand(esp, (i - 1) * kStackSavedSavedFPSize), reg);
#endif  // V8_ENABLE_WEBASSEMBLY
    }
    bytes += delta;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    // Restore all XMM registers except XMM0.
    const int delta = kStackSavedSavedFPSize * (XMMRegister::kNumRegisters - 1);
    for (int i = XMMRegister::kNumRegisters - 1; i > 0; i--) {
      XMMRegister reg = XMMRegister::from_code(i);
#if V8_ENABLE_WEBASSEMBLY
      Movdqu(reg, Operand(esp, (i - 1) * kStackSavedSavedFPSize));
#else
      Movsd(reg, Operand(esp, (i - 1) * kStackSavedSavedFPSize));
#endif  // V8_ENABLE_WEBASSEMBLY
    }
    add(esp, Immediate(delta));
    bytes += delta;
  }

  RegList saved_regs = kCallerSaved - exclusion;
  for (Register reg : base::Reversed(saved_regs)) {
    pop(reg);
    bytes += kSystemPointerSize;
  }

  return bytes;
}

void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, Register slot_address,
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
  // of the object, so so offset must be a multiple of kTaggedSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  lea(slot_address, FieldOperand(object, offset));
  if (v8_flags.debug_code) {
    Label ok;
    test_b(slot_address, Immediate(kTaggedSize - 1));
    j(zero, &ok, Label::kNear);
    int3();
    bind(&ok);
  }

  RecordWrite(object, slot_address, value, save_fp, SmiCheck::kOmit);

  bind(&done);

  // Clobber clobbered input registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(value, Immediate(base::bit_cast<int32_t>(kZapValue)));
    mov(slot_address, Immediate(base::bit_cast<int32_t>(kZapValue)));
  }
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  for (Register reg : registers) {
    push(reg);
  }
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  for (Register reg : base::Reversed(registers)) {
    pop(reg);
  }
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object,
                                             Register slot_address,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  push(object);
  push(slot_address);
  pop(slot_address_parameter);
  pop(object_parameter);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Register slot_address,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  push(object);
  push(slot_address);
  pop(slot_address_parameter);
  pop(object_parameter);

  CallRecordWriteStub(object_parameter, slot_address_parameter, fp_mode, mode);

  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStub(Register object, Register slot_address,
                                         SaveFPRegsMode fp_mode,
                                         StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  // Use CallRecordWriteStubSaveRegisters if the object and slot registers
  // need to be caller saved.
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    // Use {wasm_call} for direct Wasm call within a module.
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    wasm_call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode));
  }
}

void MacroAssembler::RecordWrite(Register object, Register slot_address,
                                 Register value, SaveFPRegsMode fp_mode,
                                 SmiCheck smi_check) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, value, slot_address));
  AssertNotSmi(object);

  if (v8_flags.disable_write_barriers) {
    return;
  }

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    Label ok;
    cmp(value, Operand(slot_address, 0));
    j(equal, &ok, Label::kNear);
    int3();
    bind(&ok);
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis and stores into young gen.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    // Skip barrier if writing a smi.
    JumpIfSmi(value, &done, Label::kNear);
  }

  CheckPageFlag(value,
                value,  // Used as scratch.
                MemoryChunk::kPointersToHereAreInterestingMask, zero, &done,
                Label::kNear);
  CheckPageFlag(object,
                value,  // Used as scratch.
                MemoryChunk::kPointersFromHereAreInterestingMask, zero, &done,
                Label::kNear);
  RecordComment("CheckPageFlag]");

  CallRecordWriteStub(object, slot_address, fp_mode);

  bind(&done);

  // Clobber clobbered registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Clobber slot_address and value");
    mov(slot_address, Immediate(base::bit_cast<int32_t>(kZapValue)));
    mov(value, Immediate(base::bit_cast<int32_t>(kZapValue)));
  }
}

void MacroAssembler::Cvtsi2ss(XMMRegister dst, Operand src) {
  xorps(dst, dst);
  cvtsi2ss(dst, src);
}

void MacroAssembler::Cvtsi2sd(XMMRegister dst, Operand src) {
  xorpd(dst, dst);
  cvtsi2sd(dst, src);
}

void MacroAssembler::Cvtui2ss(XMMRegister dst, Operand src, Register tmp) {
  Label done;
  Register src_reg = src.is_reg_only() ? src.reg() : tmp;
  if (src_reg == tmp) mov(tmp, src);
  cvtsi2ss(dst, src_reg);
  test(src_reg, src_reg);
  j(positive, &done, Label::kNear);

  // Compute {src/2 | (src&1)} (retain the LSB to avoid rounding errors).
  if (src_reg != tmp) mov(tmp, src_reg);
  shr(tmp, 1);
  // The LSB is shifted into CF. If it is set, set the LSB in {tmp}.
  Label msb_not_set;
  j(not_carry, &msb_not_set, Label::kNear);
  or_(tmp, Immediate(1));
  bind(&msb_not_set);
  cvtsi2ss(dst, tmp);
  addss(dst, dst);
  bind(&done);
}

void MacroAssembler::Cvttss2ui(Register dst, Operand src, XMMRegister tmp) {
  Label done;
  cvttss2si(dst, src);
  test(dst, dst);
  j(positive, &done);
  Move(tmp, static_cast<float>(INT32_MIN));
  addss(tmp, src);
  cvttss2si(dst, tmp);
  or_(dst, Immediate(0x80000000));
  bind(&done);
}

void MacroAssembler::Cvtui2sd(XMMRegister dst, Operand src, Register scratch) {
  Label done;
  cmp(src, Immediate(0));
  ExternalReference uint32_bias = ExternalReference::address_of_uint32_bias();
  Cvtsi2sd(dst, src);
  j(not_sign, &done, Label::kNear);
  addsd(dst, ExternalReferenceAsOperand(uint32_bias, scratch));
  bind(&done);
}

void MacroAssembler::Cvttsd2ui(Register dst, Operand src, XMMRegister tmp) {
  Move(tmp, -2147483648.0);
  addsd(tmp, src);
  cvttsd2si(dst, tmp);
  add(dst, Immediate(0x80000000));
}

void MacroAssembler::ShlPair(Register high, Register low, uint8_t shift) {
  DCHECK_GE(63, shift);
  if (shift >= 32) {
    mov(high, low);
    if (shift != 32) shl(high, shift - 32);
    xor_(low, low);
  } else {
    shld(high, low, shift);
    shl(low, shift);
  }
}

void MacroAssembler::ShlPair_cl(Register high, Register low) {
  ASM_CODE_COMMENT(this);
  shld_cl(high, low);
  shl_cl(low);
  Label done;
  test(ecx, Immediate(0x20));
  j(equal, &done, Label::kNear);
  mov(high, low);
  xor_(low, low);
  bind(&done);
}

void MacroAssembler::ShrPair(Register high, Register low, uint8_t shift) {
  DCHECK_GE(63, shift);
  if (shift >= 32) {
    mov(low, high);
    if (shift != 32) shr(low, shift - 32);
    xor_(high, high);
  } else {
    shrd(low, high, shift);
    shr(high, shift);
  }
}

void MacroAssembler::ShrPair_cl(Register high, Register low) {
  ASM_CODE_COMMENT(this);
  shrd_cl(low, high);
  shr_cl(high);
  Label done;
  test(ecx, Immediate(0x20));
  j(equal, &done, Label::kNear);
  mov(low, high);
  xor_(high, high);
  bind(&done);
}

void MacroAssembler::SarPair(Register high, Register low, uint8_t shift) {
  ASM_CODE_COMMENT(this);
  DCHECK_GE(63, shift);
  if (shift >= 32) {
    mov(low, high);
    if (shift != 32) sar(low, shift - 32);
    sar(high, 31);
  } else {
    shrd(low, high, shift);
    sar(high, shift);
  }
}

void MacroAssembler::SarPair_cl(Register high, Register low) {
  ASM_CODE_COMMENT(this);
  shrd_cl(low, high);
  sar_cl(high);
  Label done;
  test(ecx, Immediate(0x20));
  j(equal, &done, Label::kNear);
  mov(low, high);
  sar(high, 31);
  bind(&done);
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  mov(destination, FieldOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef,
                                        Label::Distance distance) {
  Label done;

  // Load the feedback vector from the closure.
  mov(dst, FieldOperand(closure, JSFunction::kFeedbackCellOffset));
  mov(dst, FieldOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  mov(scratch, FieldOperand(dst, HeapObject::kMapOffset));
  CmpInstanceType(scratch, FEEDBACK_VECTOR_TYPE);
  j(equal, &done, Label::kNear);

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  jmp(fbv_undef, distance);

  bind(&done);
}

void MacroAssembler::CmpObjectType(Register heap_object, InstanceType type,
                                   Register map) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, heap_object);
  CmpInstanceType(map, type);
}

void MacroAssembler::CmpInstanceType(Register map, InstanceType type) {
  cmpw(FieldOperand(map, Map::kInstanceTypeOffset), Immediate(type));
}

void MacroAssembler::CmpInstanceTypeRange(Register map,
                                          Register instance_type_out,
                                          Register scratch,
                                          InstanceType lower_limit,
                                          InstanceType higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  movzx_w(instance_type_out, FieldOperand(map, Map::kInstanceTypeOffset));
  CompareRange(instance_type_out, lower_limit, higher_limit, scratch);
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code) {
  test(FieldOperand(code, Code::kFlagsOffset),
       Immediate(1 << Code::kMarkedForDeoptimizationBit));
}

Immediate MacroAssembler::ClearedValue() const {
  return Immediate(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

namespace {

void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry) {
  // ----------- S t a t e -------------
  //  -- eax : actual argument count
  //  -- edx : new target (preserved for callee if needed, and caller)
  //  -- edi : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  ASM_CODE_COMMENT(masm);
  DCHECK(!AreAliased(edx, edi, optimized_code_entry));

  Register closure = edi;
  __ Push(eax);
  __ Push(edx);

  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ mov(optimized_code_entry,
         FieldOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, bailout to a
  // given label.
  __ TestCodeIsMarkedForDeoptimization(optimized_code_entry);
  __ j(not_zero, &heal_optimized_code_slot);

  // Optimized code is good, get it into the closure and link the closure
  // into the optimized functions list, then tail call the optimized code.
  __ Push(optimized_code_entry);
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, closure, edx,
                                         ecx);
  static_assert(kJavaScriptCallCodeStartRegister == ecx, "ABI mismatch");
  __ Pop(optimized_code_entry);
  __ LoadCodeInstructionStart(ecx, optimized_code_entry);
  __ Pop(edx);
  __ Pop(eax);
  __ jmp(ecx);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ Pop(edx);
  __ Pop(eax);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    CmpObjectType(object, FEEDBACK_CELL_TYPE, scratch);
    Assert(equal, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    CmpObjectType(object, FEEDBACK_VECTOR_TYPE, scratch);
    Assert(equal, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure, Register value,
    Register slot_address) {
  ASM_CODE_COMMENT(this);
  // Store the optimized code in the closure.
  mov(FieldOperand(closure, JSFunction::kCodeOffset), optimized_code);
  mov(value, optimized_code);  // Write barrier clobbers slot_address below.
  RecordWriteField(closure, JSFunction::kCodeOffset, value, slot_address,
                   SaveFPRegsMode::kIgnore, SmiCheck::kOmit);
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  // ----------- S t a t e -------------
  //  -- eax : actual argument count
  //  -- edx : new target (preserved for callee)
  //  -- edi : target function (preserved for callee)
  // -----------------------------------
  ASM_CODE_COMMENT(this);
  {
    FrameScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target and the actual
    // argument count.
    push(kJavaScriptCallTargetRegister);
    push(kJavaScriptCallNewTargetRegister);
    SmiTag(kJavaScriptCallArgCountRegister);
    push(kJavaScriptCallArgCountRegister);
    // Function is also the parameter to the runtime call.
    push(kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    mov(ecx, eax);

    // Restore target function, new target and actual argument count.
    pop(kJavaScriptCallArgCountRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
    pop(kJavaScriptCallNewTargetRegister);
    pop(kJavaScriptCallTargetRegister);
  }

  static_assert(kJavaScriptCallCodeStartRegister == ecx, "ABI mismatch");
  JumpCodeObject(ecx);
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
// Registers flags and feedback_vector must be aliased.
void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, XMMRegister saved_feedback_vector,
    CodeKind current_code_kind, Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  DCHECK(CodeKindCanTierUp(current_code_kind));
  Register feedback_vector = flags;

  // Store feedback_vector. We may need it if we need to load the optimize code
  // slot entry.
  movd(saved_feedback_vector, feedback_vector);
  mov_w(flags, FieldOperand(feedback_vector, FeedbackVector::kFlagsOffset));

  // Check if there is optimized code or a tiering state that needes to be
  // processed.
  uint32_t kFlagsMask = FeedbackVector::kFlagsTieringStateIsAnyRequested |
                        FeedbackVector::kFlagsMaybeHasTurbofanCode |
                        FeedbackVector::kFlagsLogNextExecution;
  if (current_code_kind != CodeKind::MAGLEV) {
    kFlagsMask |= FeedbackVector::kFlagsMaybeHasMaglevCode;
  }
  test_w(flags, Immediate(kFlagsMask));
  j(not_zero, flags_need_processing);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, XMMRegister saved_feedback_vector) {
  ASM_CODE_COMMENT(this);
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available.
  test(flags, Immediate(FeedbackVector::kFlagsTieringStateIsAnyRequested));
  j(zero, &maybe_needs_logging);

  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  test(flags, Immediate(FeedbackVector::LogNextExecutionBit::kMask));
  j(zero, &maybe_has_optimized_code);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = flags;
  Register feedback_vector = flags;
  movd(feedback_vector, saved_feedback_vector);  // Restore feedback vector.
  mov(optimized_code_entry,
      FieldOperand(feedback_vector, FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry);
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    test(object, Immediate(kSmiTagMask));
    Check(equal, AbortReason::kOperandIsNotASmi);
  }
}

void MacroAssembler::AssertSmi(Operand object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  test(object, Immediate(kSmiTagMask));
  Check(equal, AbortReason::kOperandIsNotASmi);
}

void MacroAssembler::AssertConstructor(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    test(object, Immediate(kSmiTagMask));
    Check(not_equal, AbortReason::kOperandIsASmiAndNotAConstructor);
    Push(object);
    LoadMap(object, object);
    test_b(FieldOperand(object, Map::kBitFieldOffset),
           Immediate(Map::Bits1::IsConstructorBit::kMask));
    Pop(object);
    Check(not_zero, AbortReason::kOperandIsNotAConstructor);
  }
}

void MacroAssembler::AssertFunction(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    test(object, Immediate(kSmiTagMask));
    Check(not_equal, AbortReason::kOperandIsASmiAndNotAFunction);
    Push(object);
    LoadMap(object, object);
    CmpInstanceTypeRange(object, scratch, scratch, FIRST_JS_FUNCTION_TYPE,
                         LAST_JS_FUNCTION_TYPE);
    Pop(object);
    Check(below_equal, AbortReason::kOperandIsNotAFunction);
  }
}

void MacroAssembler::AssertCallableFunction(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    test(object, Immediate(kSmiTagMask));
    Check(not_equal, AbortReason::kOperandIsASmiAndNotAFunction);
    Push(object);
    LoadMap(object, object);
    CmpInstanceTypeRange(object, scratch, scratch,
                         FIRST_CALLABLE_JS_FUNCTION_TYPE,
                         LAST_CALLABLE_JS_FUNCTION_TYPE);
    Pop(object);
    Check(below_equal, AbortReason::kOperandIsNotACallableFunction);
  }
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    test(object, Immediate(kSmiTagMask));
    Check(not_equal, AbortReason::kOperandIsASmiAndNotABoundFunction);
    Push(object);
    CmpObjectType(object, JS_BOUND_FUNCTION_TYPE, object);
    Pop(object);
    Check(equal, AbortReason::kOperandIsNotABoundFunction);
  }
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);

  test(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsASmiAndNotAGenerat
"""


```
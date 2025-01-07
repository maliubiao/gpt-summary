Response: My goal is to analyze the provided C++ code snippet and summarize its functionality, specifically focusing on its relation to JavaScript. Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file name `macro-assembler-loong64.cc` immediately suggests this code is related to low-level code generation for the LoongArch64 architecture. The term "macro-assembler" indicates it provides a higher-level abstraction over raw assembly instructions. It's likely part of a larger system that compiles or interprets code, and in the context of V8, that's JavaScript.

2. **Examine Key Includes:**  The included headers offer clues about the file's responsibilities.
    * `<limits.h>`: Standard library for numerical limits.
    * `src/base/bits.h`, `src/base/division-by-constant.h`:  Basic utilities, likely for bit manipulation and optimized division.
    * `src/builtins/builtins-inl.h`, `src/codegen/...`:  Strong indicators of code generation functionality within the V8 JavaScript engine. "Builtins" are pre-compiled JavaScript functions implemented in C++. "Codegen" clearly points to code generation.
    * `src/debug/debug.h`, `src/deoptimizer/deoptimizer.h`, `src/execution/frames-inl.h`:  Features related to debugging, deoptimization (going back from optimized code to simpler code), and call stack management.
    * `src/heap/...`, `src/objects/...`:  Interaction with V8's heap management and object representation.
    * `src/runtime/runtime.h`:  Calling into V8's runtime system for various operations.
    * `src/snapshot/snapshot.h`:  Dealing with snapshots of the heap for faster startup.

3. **Analyze Namespaces and Macros:**
    * `namespace v8 { namespace internal {`: This confirms it's part of the internal implementation of the V8 engine.
    * `#define __ ACCESS_MASM(masm)`: This macro likely simplifies access to the `MacroAssembler` object's methods within the current file.

4. **Skim Function Definitions for Patterns:** Look for common patterns and categories of functions:
    * **Stack Management:** `RequiredStackSizeForCallerSaved`, `PushCallerSaved`, `PopCallerSaved`, `PushCommonFrame`, `PushStandardFrame`. These functions handle managing the call stack, saving and restoring registers, which is essential for function calls.
    * **Root Loading:** `LoadRoot`, `LoadTaggedRoot`. These functions load predefined values (roots) from a global table.
    * **Write Barriers:** `RecordWriteField`, `RecordWrite`, `CallRecordWriteStub*`. These are crucial for garbage collection, ensuring the collector is aware of object references.
    * **Sandboxed Pointers:** `DecodeSandboxedPointer`, `LoadSandboxedPointerField`, `StoreSandboxedPointerField`. This suggests support for a sandboxed environment, likely for security.
    * **Indirect Pointers:** `LoadIndirectPointerField`, `StoreIndirectPointerField`, `ResolveIndirectPointerHandle`, `ResolveCodePointerHandle`, `ResolveTrustedPointerHandle`. This indicates a level of indirection in pointer access, potentially for security or code sharing.
    * **JS Dispatch Table:** `LoadEntrypointFromJSDispatchTable`, `LoadParameterCountFromJSDispatchTable`, `LoadEntrypointAndParameterCountFromJSDispatchTable`. This is a mechanism for efficient dispatch of JavaScript function calls, especially in optimized code.
    * **Register Manipulation:** Numerous functions like `Add_w`, `Sub_d`, `Mul_w`, `And`, `Or`, etc. These are wrappers or helpers around the actual LoongArch64 assembly instructions. They often handle immediate values and register allocation.
    * **Memory Access:** `Ld_b`, `St_w`, `Fld_d`, `Fst_s`, `Ll_w`, `Sc_d`. These functions provide ways to load and store data from memory, handling different data sizes.
    * **Floating-Point Operations:** Functions starting with `F` like `Fld_s`, `Fst_d`, `Fadd_d`, `Fsub_s`, `Ffint_d_uw`, `Ftintrz_l_d`, `RoundDouble`, etc. These are for handling floating-point numbers.
    * **Helper Functions:**  `MaybeSaveRegisters`, `MaybeRestoreRegisters`, `MoveObjectAndSlot`.

5. **Connect to JavaScript Functionality:** Based on the identified function categories, establish the link to JavaScript:
    * **Function Calls:**  The stack management functions are directly involved in how JavaScript functions are called and how their state is managed.
    * **Object Properties:** The write barrier functions are essential when updating properties of JavaScript objects. The sandboxed and indirect pointer functions also relate to how objects and their properties are accessed, potentially with security considerations.
    * **Garbage Collection:** Write barriers ensure the garbage collector can track live objects, preventing memory leaks.
    * **Optimized Code Execution:** The JS dispatch table functions are used in optimized code to quickly call JavaScript functions.
    * **Arithmetic and Logical Operations:** The register manipulation functions correspond to the basic operations performed on JavaScript numbers and other data types.
    * **Data Storage:** The memory access functions are used to read and write JavaScript values in memory.
    * **Number Representation:** The floating-point functions are used to handle JavaScript's Number type, which is based on double-precision floating-point.

6. **Construct the Summary:**  Synthesize the observations into a concise description of the file's functionality. Emphasize the core purpose (macro-assembler for LoongArch64), its role in V8, and the key functionalities it provides. Highlight the connection to JavaScript by mentioning how these low-level operations enable higher-level JavaScript features.

7. **Create a JavaScript Example (If Applicable):**  Choose a simple JavaScript code snippet that directly relates to the functionalities observed in the C++ code. In this case, object property assignment and function calls are good examples because they involve write barriers and stack management/dispatch.

8. **Review and Refine:** Ensure the summary is clear, accurate, and covers the main points. Check for any inconsistencies or areas where more detail could be added (without making the summary too long). For a "Part 1 of 3" request, focus on the foundational aspects and high-level overview. Subsequent parts might delve into more specific details.
This is the first part of the `macro-assembler-loong64.cc` file, which is a crucial component of the V8 JavaScript engine. Its primary function is to provide an **abstraction layer over the LoongArch64 assembly language**, making it easier for the V8 compiler to generate machine code for this architecture.

Here's a breakdown of its functionalities as seen in this first part:

* **Stack Frame Management:** It includes functions for managing the call stack, such as `RequiredStackSizeForCallerSaved`, `PushCallerSaved`, `PopCallerSaved`, `PushCommonFrame`, and `PushStandardFrame`. These functions handle saving and restoring registers and setting up the stack frame when calling functions. This is fundamental to how JavaScript function calls are implemented at the machine level.

* **Root Object Access:** Functions like `LoadRoot` and `LoadTaggedRoot` are responsible for loading well-known objects (roots) from the V8 heap into registers. These roots are essential for the runtime environment of JavaScript.

* **Write Barrier Implementation:**  The code contains functions related to the write barrier, such as `RecordWriteField`, `RecordWrite`, `CallRecordWriteStub`, and `CallEphemeronKeyBarrier`. The write barrier is a mechanism used by the garbage collector to track object references and ensure memory safety in JavaScript.

* **Sandboxed Pointer Handling:**  Functions like `DecodeSandboxedPointer`, `LoadSandboxedPointerField`, and `StoreSandboxedPointerField` suggest support for a sandboxed environment, likely for security purposes, by providing specific ways to handle memory addresses.

* **Indirect Pointer Handling:**  Functions like `LoadIndirectPointerField`, `StoreIndirectPointerField`, and their associated `Resolve*` functions indicate a mechanism for accessing memory locations indirectly. This can be used for various purposes, including security and code sharing.

* **JS Dispatch Table Access:**  Functions like `LoadEntrypointFromJSDispatchTable`, `LoadParameterCountFromJSDispatchTable`, and `LoadEntrypointAndParameterCountFromJSDispatchTable` are used for efficient dispatching of JavaScript function calls, particularly in optimized code.

* **Register Manipulation Macros:**  The file defines a large number of macros like `Add_w`, `Sub_d`, `Mul_w`, `And`, `Or`, etc. These are high-level instructions that map to one or more actual LoongArch64 assembly instructions. They simplify the process of performing common arithmetic and logical operations on registers.

* **Memory Access Macros:** It provides macros for loading and storing data of different sizes from memory, such as `Ld_b`, `St_w`, `Fld_d`, `Fst_s`, `Ll_w`, and `Sc_d`.

* **Immediate Value Loading (`li`):** The `li` function (load immediate) is crucial for loading constant values into registers. It handles various optimizations and relocation scenarios.

* **Multi-Register Push/Pop:** Functions like `MultiPush` and `MultiPop` allow efficient saving and restoring of multiple registers on the stack.

**Relationship to JavaScript:**

This file is deeply intertwined with the execution of JavaScript. Here's how some of the functionalities relate:

* **Function Calls:** When a JavaScript function is called, the stack management functions in this file are used to set up the necessary stack frame, save registers, and pass arguments.
* **Object Access:** When you access properties of JavaScript objects, the code generated using these functions performs the underlying memory accesses and potentially triggers write barriers if the object's state is modified.
* **Garbage Collection:** The write barrier mechanisms implemented here are fundamental for the V8 garbage collector to track object references and reclaim unused memory, preventing memory leaks in JavaScript applications.
* **Optimized Code:** The JS dispatch table functions are heavily used in V8's optimizing compilers (like TurboFan) to generate efficient code for calling JavaScript functions.
* **Arithmetic and Logical Operations:**  JavaScript code often involves arithmetic (addition, subtraction, multiplication, etc.) and logical operations. The register manipulation macros in this file are used to generate the assembly instructions that perform these operations on JavaScript numbers and other data types.

**JavaScript Example:**

```javascript
function add(a, b) {
  return a + b;
}

let obj = { x: 10 };
obj.y = 20;
```

**Explanation of the link:**

1. **`add(a, b)` function call:** When this function is called, the `PushCallerSaved`, `PushStandardFrame` (or similar), and eventually the function's code generated using the macros in this file will be executed. The return value will involve using stack management to restore state. The `a + b` operation will likely use `Add_w` or similar macros.

2. **`let obj = { x: 10 };`:** This creates a JavaScript object. The memory for this object will be allocated on the V8 heap, and the value `10` will be stored in the appropriate memory location.

3. **`obj.y = 20;`:** This assigns a new property `y` to the object. This operation will involve:
   * Calculating the memory location for the `y` property.
   * Storing the value `20` in that location using macros like `St_w`.
   * **Crucially, this assignment will trigger a write barrier.** The `RecordWriteField` or `RecordWrite` functions in this C++ file will be called to inform the garbage collector that the `obj` object now has a reference to the value `20` (if it's a heap object). This ensures the garbage collector doesn't prematurely collect `20` if `obj` is still reachable.

In essence, this `macro-assembler-loong64.cc` file provides the building blocks for translating JavaScript code into the low-level instructions that the LoongArch64 processor can understand and execute. It handles the intricacies of the architecture, allowing the higher layers of V8 to focus on the semantics of JavaScript.

Prompt: 
```
这是目录为v8/src/codegen/loong64/macro-assembler-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_LOONG64

#include <optional>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/external-reference-table.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register-configuration.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/objects/heap-number.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/loong64/macro-assembler-loong64.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

static inline bool IsZero(const Operand& rk) {
  if (rk.is_reg()) {
    return rk.rm() == zero_reg;
  } else {
    return rk.immediate() == 0;
  }
}

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion1,
                                                    Register exclusion2,
                                                    Register exclusion3) const {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                    Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                   Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kSystemPointerSize;

  return bytes;
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index) {
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      is_int12(ReadOnlyRootPtr(index))) {
    DecompressTagged(destination, ReadOnlyRootPtr(index));
    return;
  }
  // Many roots have addresses that are too large to fit into addition immediate
  // operands. Evidence suggests that the extra instruction for decompression
  // costs us more than the load.
  Ld_d(destination, MemOperand(s6, RootRegisterOffsetForRootIndex(index)));
}
void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      is_int12(ReadOnlyRootPtr(index))) {
    li(destination, (int32_t)ReadOnlyRootPtr(index));
    return;
  }
  Ld_w(destination, MemOperand(s6, RootRegisterOffsetForRootIndex(index)));
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  if (marker_reg.is_valid()) {
    Push(ra, fp, marker_reg);
    Add_d(fp, sp, Operand(kSystemPointerSize));
  } else {
    Push(ra, fp);
    mov(fp, sp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int offset = -StandardFrameConstants::kContextOffset;
  if (function_reg.is_valid()) {
    Push(ra, fp, cp, function_reg, kJavaScriptCallArgCountRegister);
    offset += 2 * kSystemPointerSize;
  } else {
    Push(ra, fp, cp, kJavaScriptCallArgCountRegister);
    offset += kSystemPointerSize;
  }
  Add_d(fp, sp, Operand(offset));
}

// Clobbers object, dst, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, RAStatus ra_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check, SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so offset must be a multiple of kPointerSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  if (v8_flags.debug_code) {
    Label ok;
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Add_d(scratch, object, offset - kHeapObjectTag);
    And(scratch, scratch, Operand(kTaggedSize - 1));
    Branch(&ok, eq, scratch, Operand(zero_reg));
    Abort(AbortReason::kUnalignedCellInWriteBarrier);
    bind(&ok);
  }

  RecordWrite(object, Operand(offset - kHeapObjectTag), value, ra_status,
              save_fp, SmiCheck::kOmit, slot);

  bind(&done);
}

void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  srli_d(value, value, kSandboxedPointerShift);
  Add_d(value, value, kPtrComprCageBaseRegister);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadSandboxedPointerField(Register destination,
                                               MemOperand field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  Ld_d(destination, field_operand);
  DecodeSandboxedPointer(destination);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::StoreSandboxedPointerField(Register value,
                                                MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Sub_d(scratch, value, kPtrComprCageBaseRegister);
  slli_d(scratch, scratch, kSandboxedPointerShift);
  St_d(scratch, dst_field_operand);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadExternalPointerField(Register destination,
                                              MemOperand field_operand,
                                              ExternalPointerTag tag,
                                              Register isolate_root) {
  DCHECK(!AreAliased(destination, isolate_root));
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  DCHECK(!IsSharedExternalPointerType(tag));
  UseScratchRegisterScope temps(this);
  Register external_table = temps.Acquire();
  if (isolate_root == no_reg) {
    DCHECK(root_array_available_);
    isolate_root = kRootRegister;
  }
  Ld_d(external_table,
       MemOperand(isolate_root,
                  IsolateData::external_pointer_table_offset() +
                      Internals::kExternalPointerTableBasePointerOffset));
  Ld_wu(destination, field_operand);
  srli_d(destination, destination, kExternalPointerIndexShift);
  slli_d(destination, destination, kExternalPointerTableEntrySizeLog2);
  Ld_d(destination, MemOperand(external_table, destination));
  // We need another scratch register for the 64-bit tag constant. Instead of
  // forcing the `And` to allocate a new temp register (which we may not have),
  // reuse the temp register that we used for the external pointer table base.
  Register tag_reg = external_table;
  li(tag_reg, Operand(~tag));
  And(destination, destination, tag_reg);
#else
  Ld_d(destination, field_operand);
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::LoadTrustedPointerField(Register destination,
                                             MemOperand field_operand,
                                             IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  LoadIndirectPointerField(destination, field_operand, tag);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::StoreTrustedPointerField(Register value,
                                              MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  StoreIndirectPointerField(value, dst_field_operand);
#else
  StoreTaggedField(value, dst_field_operand);
#endif
}

void MacroAssembler::LoadIndirectPointerField(Register destination,
                                              MemOperand field_operand,
                                              IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register handle = temps.hasAvailable() ? temps.Acquire() : t8;
  Ld_wu(handle, field_operand);

  ResolveIndirectPointerHandle(destination, handle, tag);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreIndirectPointerField(Register value,
                                               MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Ld_w(scratch, FieldMemOperand(
                    value, ExposedTrustedObject::kSelfIndirectPointerOffset));
  St_w(scratch, dst_field_operand);
#else
  UNREACHABLE();
#endif
}

#ifdef V8_ENABLE_SANDBOX
void MacroAssembler::ResolveIndirectPointerHandle(Register destination,
                                                  Register handle,
                                                  IndirectPointerTag tag) {
  // The tag implies which pointer table to use.
  if (tag == kUnknownIndirectPointerTag) {
    // In this case we have to rely on the handle marking to determine which
    // pointer table to use.
    Label is_trusted_pointer_handle, done;
    DCHECK(!AreAliased(destination, handle));
    And(destination, handle, kCodePointerHandleMarker);
    Branch(&is_trusted_pointer_handle, eq, destination, Operand(zero_reg));
    ResolveCodePointerHandle(destination, handle);
    Branch(&done);
    bind(&is_trusted_pointer_handle);
    ResolveTrustedPointerHandle(destination, handle,
                                kUnknownIndirectPointerTag);
    bind(&done);
  } else if (tag == kCodeIndirectPointerTag) {
    ResolveCodePointerHandle(destination, handle);
  } else {
    ResolveTrustedPointerHandle(destination, handle, tag);
  }
}

void MacroAssembler::ResolveTrustedPointerHandle(Register destination,
                                                 Register handle,
                                                 IndirectPointerTag tag) {
  DCHECK_NE(tag, kCodeIndirectPointerTag);
  DCHECK(!AreAliased(handle, destination));

  DCHECK(root_array_available_);
  Register table = destination;
  Ld_d(table,
       MemOperand(kRootRegister, IsolateData::trusted_pointer_table_offset()));
  srli_d(handle, handle, kTrustedPointerHandleShift);
  Alsl_d(destination, handle, table, kTrustedPointerTableEntrySizeLog2);
  Ld_d(destination, MemOperand(destination, 0));
  // Untag the pointer and remove the marking bit in one operation.
  Register tag_reg = handle;
  li(tag_reg, Operand(~(tag | kTrustedPointerTableMarkBit)));
  and_(destination, destination, tag_reg);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle) {
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  li(table, ExternalReference::code_pointer_table_address());
  srli_d(handle, handle, kCodePointerHandleShift);
  Alsl_d(destination, handle, table, kCodePointerTableEntrySizeLog2);
  Ld_d(destination,
       MemOperand(destination, kCodePointerTableEntryCodeObjectOffset));
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  Or(destination, destination, Operand(kHeapObjectTag));
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      MemOperand field_operand,
                                                      CodeEntrypointTag tag) {
  DCHECK_NE(tag, kInvalidEntrypointTag);
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, ExternalReference::code_pointer_table_address());
  Ld_wu(destination, field_operand);
  srli_d(destination, destination, kCodePointerHandleShift);
  slli_d(destination, destination, kCodePointerTableEntrySizeLog2);
  Ld_d(destination, MemOperand(scratch, destination));
  if (tag != 0) {
    li(scratch, Operand(tag));
    xor_(destination, destination, scratch);
  }
}
#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadEntrypointFromJSDispatchTable(Register destination,
                                                       Register dispatch_handle,
                                                       Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli_d(index, dispatch_handle, kJSDispatchHandleShift);
  slli_d(destination, index, kJSDispatchTableEntrySizeLog2);
  Add_d(scratch, scratch, destination);
  Ld_d(destination, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle, Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli_d(index, dispatch_handle, kJSDispatchHandleShift);
  slli_d(destination, index, kJSDispatchTableEntrySizeLog2);
  Add_d(scratch, scratch, destination);
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ld_hu(destination, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle,
    Register scratch) {
  DCHECK(!AreAliased(entrypoint, parameter_count, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = parameter_count;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli_d(index, dispatch_handle, kJSDispatchHandleShift);
  slli_d(parameter_count, index, kJSDispatchTableEntrySizeLog2);
  Add_d(scratch, scratch, parameter_count);
  Ld_d(entrypoint, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ld_hu(parameter_count,
        MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}
#endif

void MacroAssembler::LoadProtectedPointerField(Register destination,
                                               MemOperand field_operand) {
  DCHECK(root_array_available());
#ifdef V8_ENABLE_SANDBOX
  DecompressProtected(destination, field_operand);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
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

void MacroAssembler::CallIndirectPointerBarrier(Register object, Operand offset,
                                                SaveFPRegsMode fp_mode,
                                                IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  RegList registers =
      IndirectPointerWriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  MoveObjectAndSlot(
      IndirectPointerWriteBarrierDescriptor::ObjectRegister(),
      IndirectPointerWriteBarrierDescriptor::SlotAddressRegister(), object,
      offset);
  li(IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister(),
     Operand(tag));

  CallBuiltin(Builtins::IndirectPointerBarrier(fp_mode));
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
  // Use CallRecordWriteStubSaveRegisters if the object and slot registers
  // need to be caller saved.
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
  ASM_CODE_COMMENT(this);
  DCHECK_NE(dst_object, dst_slot);
  // If `offset` is a register, it cannot overlap with `object`.
  DCHECK_IMPLIES(!offset.IsImmediate(), offset.rm() != object);

  // If the slot register does not overlap with the object register, we can
  // overwrite it.
  if (dst_slot != object) {
    Add_d(dst_slot, object, offset);
    mov(dst_object, object);
    return;
  }

  DCHECK_EQ(dst_slot, object);

  // If the destination object register does not overlap with the offset
  // register, we can overwrite it.
  if (offset.IsImmediate() || (offset.rm() != dst_object)) {
    mov(dst_object, dst_slot);
    Add_d(dst_slot, dst_slot, offset);
    return;
  }

  DCHECK_EQ(dst_object, offset.rm());

  // We only have `dst_slot` and `dst_object` left as distinct registers so we
  // have to swap them. We write this as a add+sub sequence to avoid using a
  // scratch register.
  Add_d(dst_slot, dst_slot, dst_object);
  Sub_d(dst_object, dst_slot, dst_object);
}

// If lr_status is kLRHasBeenSaved, lr will be clobbered.
// TODO(LOONG_dev): LOONG64 Check this comment
// Clobbers object, address, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Operand offset,
                                 Register value, RAStatus ra_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check,
                                 SlotDescriptor slot) {
  DCHECK(!AreAliased(object, value));

  if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
    Add_d(scratch, object, offset);
    if (slot.contains_indirect_pointer()) {
      LoadIndirectPointerField(scratch, MemOperand(scratch, 0),
                               slot.indirect_pointer_tag());
    } else {
      DCHECK(slot.contains_direct_pointer());
      LoadTaggedField(scratch, MemOperand(scratch, 0));
    }
    Assert(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite, scratch,
           Operand(value));
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    DCHECK_EQ(0, kSmiTag);
    JumpIfSmi(value, &done);
  }

  CheckPageFlag(value, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                &done);

  CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask, eq,
                &done);

  // Record the actual write.
  if (ra_status == kRAHasNotBeenSaved) {
    Push(ra);
  }

  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, slot_address, value));
  if (slot.contains_direct_pointer()) {
    DCHECK(offset.IsImmediate());
    Add_d(slot_address, object, offset);
    CallRecordWriteStub(object, slot_address, fp_mode,
                        StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, offset, fp_mode,
                               slot.indirect_pointer_tag());
  }
  if (ra_status == kRAHasNotBeenSaved) {
    Pop(ra);
  }

  bind(&done);
}

// ---------------------------------------------------------------------------
// Instruction macros.

void MacroAssembler::Add_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    add_w(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      addi_w(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      li(scratch, rk);
      add_w(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Add_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    add_d(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      addi_d(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      DCHECK(rj != scratch);
      li(scratch, rk);
      add_d(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Sub_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sub_w(rd, rj, rk.rm());
  } else {
    DCHECK(is_int32(rk.immediate()));
    if (is_int12(-rk.immediate()) && !MustUseReg(rk.rmode())) {
      // No subi_w instr, use addi_w(x, y, -imm).
      addi_w(rd, rj, static_cast<int32_t>(-rk.immediate()));
    } else {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      if (-rk.immediate() >> 12 == 0 && !MustUseReg(rk.rmode())) {
        // Use load -imm and addu when loading -imm generates one instruction.
        li(scratch, -rk.immediate());
        add_w(rd, rj, scratch);
      } else {
        // li handles the relocation.
        li(scratch, rk);
        sub_w(rd, rj, scratch);
      }
    }
  }
}

void MacroAssembler::Sub_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sub_d(rd, rj, rk.rm());
  } else if (is_int12(-rk.immediate()) && !MustUseReg(rk.rmode())) {
    // No subi_d instr, use addi_d(x, y, -imm).
    addi_d(rd, rj, static_cast<int32_t>(-rk.immediate()));
  } else {
    DCHECK(rj != t7);
    int li_count = InstrCountForLi64Bit(rk.immediate());
    int li_neg_count = InstrCountForLi64Bit(-rk.immediate());
    if (li_neg_count < li_count && !MustUseReg(rk.rmode())) {
      // Use load -imm and add_d when loading -imm generates one instruction.
      DCHECK(rk.immediate() != std::numeric_limits<int32_t>::min());
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(-rk.immediate()));
      add_d(rd, rj, scratch);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, rk);
      sub_d(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Mul_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mul_w(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mul_w(rd, rj, scratch);
  }
}

void MacroAssembler::Mulh_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mulh_w(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mulh_w(rd, rj, scratch);
  }
}

void MacroAssembler::Mulh_wu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mulh_wu(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mulh_wu(rd, rj, scratch);
  }
}

void MacroAssembler::Mul_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mul_d(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mul_d(rd, rj, scratch);
  }
}

void MacroAssembler::Mulh_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mulh_d(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mulh_d(rd, rj, scratch);
  }
}

void MacroAssembler::Mulh_du(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mulh_du(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mulh_du(rd, rj, scratch);
  }
}

void MacroAssembler::Div_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    div_w(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    div_w(rd, rj, scratch);
  }
}

void MacroAssembler::Mod_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mod_w(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mod_w(rd, rj, scratch);
  }
}

void MacroAssembler::Mod_wu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mod_wu(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mod_wu(rd, rj, scratch);
  }
}

void MacroAssembler::Div_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    div_d(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    div_d(rd, rj, scratch);
  }
}

void MacroAssembler::Div_wu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    div_wu(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    div_wu(rd, rj, scratch);
  }
}

void MacroAssembler::Div_du(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    div_du(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    div_du(rd, rj, scratch);
  }
}

void MacroAssembler::Mod_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mod_d(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mod_d(rd, rj, scratch);
  }
}

void MacroAssembler::Mod_du(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mod_du(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mod_du(rd, rj, scratch);
  }
}

void MacroAssembler::And(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    and_(rd, rj, rk.rm());
  } else {
    if (is_uint12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      andi(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      li(scratch, rk);
      and_(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Or(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    or_(rd, rj, rk.rm());
  } else {
    if (is_uint12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      ori(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      li(scratch, rk);
      or_(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Xor(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    xor_(rd, rj, rk.rm());
  } else {
    if (is_uint12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      xori(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      li(scratch, rk);
      xor_(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Nor(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    nor(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    nor(rd, rj, scratch);
  }
}

void MacroAssembler::Andn(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    andn(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    andn(rd, rj, scratch);
  }
}

void MacroAssembler::Orn(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    orn(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    orn(rd, rj, scratch);
  }
}

void MacroAssembler::Neg(Register rj, const Operand& rk) {
  DCHECK(rk.is_reg());
  sub_d(rj, zero_reg, rk.rm());
}

void MacroAssembler::Slt(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    slt(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      slti(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      DCHECK(rj != scratch);
      li(scratch, rk);
      slt(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Sltu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sltu(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      sltui(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      DCHECK(rj != scratch);
      li(scratch, rk);
      sltu(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Sle(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    slt(rd, rk.rm(), rj);
  } else {
    if (rk.immediate() == 0 && !MustUseReg(rk.rmode())) {
      slt(rd, zero_reg, rj);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rj != scratch);
      li(scratch, rk);
      slt(rd, scratch, rj);
    }
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sleu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sltu(rd, rk.rm(), rj);
  } else {
    if (rk.immediate() == 0 && !MustUseReg(rk.rmode())) {
      sltu(rd, zero_reg, rj);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rj != scratch);
      li(scratch, rk);
      sltu(rd, scratch, rj);
    }
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sge(Register rd, Register rj, const Operand& rk) {
  Slt(rd, rj, rk);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgeu(Register rd, Register rj, const Operand& rk) {
  Sltu(rd, rj, rk);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgt(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    slt(rd, rk.rm(), rj);
  } else {
    if (rk.immediate() == 0 && !MustUseReg(rk.rmode())) {
      slt(rd, zero_reg, rj);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rj != scratch);
      li(scratch, rk);
      slt(rd, scratch, rj);
    }
  }
}

void MacroAssembler::Sgtu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sltu(rd, rk.rm(), rj);
  } else {
    if (rk.immediate() == 0 && !MustUseReg(rk.rmode())) {
      sltu(rd, zero_reg, rj);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rj != scratch);
      li(scratch, rk);
      sltu(rd, scratch, rj);
    }
  }
}

void MacroAssembler::Rotr_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    rotr_w(rd, rj, rk.rm());
  } else {
    int64_t ror_value = rk.immediate() % 32;
    if (ror_value < 0) {
      ror_value += 32;
    }
    rotri_w(rd, rj, ror_value);
  }
}

void MacroAssembler::Rotr_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    rotr_d(rd, rj, rk.rm());
  } else {
    int64_t dror_value = rk.immediate() % 64;
    if (dror_value < 0) dror_value += 64;
    rotri_d(rd, rj, dror_value);
  }
}

void MacroAssembler::Alsl_w(Register rd, Register rj, Register rk, uint8_t sa,
                            Register scratch) {
  DCHECK(sa >= 1 && sa <= 31);
  if (sa <= 4) {
    alsl_w(rd, rj, rk, sa);
  } else {
    Register tmp = rd == rk ? scratch : rd;
    DCHECK(tmp != rk);
    slli_w(tmp, rj, sa);
    add_w(rd, rk, tmp);
  }
}

void MacroAssembler::Alsl_d(Register rd, Register rj, Register rk, uint8_t sa,
                            Register scratch) {
  DCHECK(sa >= 1 && sa <= 63);
  if (sa <= 4) {
    alsl_d(rd, rj, rk, sa);
  } else {
    Register tmp = rd == rk ? scratch : rd;
    DCHECK(tmp != rk);
    slli_d(tmp, rj, sa);
    add_d(rd, rk, tmp);
  }
}

// ------------Pseudo-instructions-------------

// Change endianness
void MacroAssembler::ByteSwap(Register dest, Register src, int operand_size) {
  DCHECK(operand_size == 4 || operand_size == 8);
  if (operand_size == 4) {
    revb_2w(dest, src);
    slli_w(dest, dest, 0);
  } else {
    revb_d(dest, src);
  }
}

void MacroAssembler::Ld_b(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_b(rd, source.base(), source.index());
  } else {
    ld_b(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_bu(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_bu(rd, source.base(), source.index());
  } else {
    ld_bu(rd, source.base(), source.offset());
  }
}

void MacroAssembler::St_b(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    stx_b(rd, source.base(), source.index());
  } else {
    st_b(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_h(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_h(rd, source.base(), source.index());
  } else {
    ld_h(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_hu(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_hu(rd, source.base(), source.index());
  } else {
    ld_hu(rd, source.base(), source.offset());
  }
}

void MacroAssembler::St_h(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    stx_h(rd, source.base(), source.index());
  } else {
    st_h(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_w(Register rd, const MemOperand& rj) {
  MemOperand source = rj;

  if (!(source.hasIndexReg()) && is_int16(source.offset()) &&
      (source.offset() & 0b11) == 0) {
    ldptr_w(rd, source.base(), source.offset());
    return;
  }

  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_w(rd, source.base(), source.index());
  } else {
    ld_w(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_wu(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);

  if (source.hasIndexReg()) {
    ldx_wu(rd, source.base(), source.index());
  } else {
    ld_wu(rd, source.base(), source.offset());
  }
}

void MacroAssembler::St_w(Register rd, const MemOperand& rj) {
  MemOperand source = rj;

  if (!(source.hasIndexReg()) && is_int16(source.offset()) &&
      (source.offset() & 0b11) == 0) {
    stptr_w(rd, source.base(), source.offset());
    return;
  }

  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    stx_w(rd, source.base(), source.index());
  } else {
    st_w(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_d(Register rd, const MemOperand& rj) {
  MemOperand source = rj;

  if (!(source.hasIndexReg()) && is_int16(source.offset()) &&
      (source.offset() & 0b11) == 0) {
    ldptr_d(rd, source.base(), source.offset());
    return;
  }

  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_d(rd, source.base(), source.index());
  } else {
    ld_d(rd, source.base(), source.offset());
  }
}

void MacroAssembler::St_d(Register rd, const MemOperand& rj) {
  MemOperand source = rj;

  if (!(source.hasIndexReg()) && is_int16(source.offset()) &&
      (source.offset() & 0b11) == 0) {
    stptr_d(rd, source.base(), source.offset());
    return;
  }

  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    stx_d(rd, source.base(), source.index());
  } else {
    st_d(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Fld_s(FPURegister fd, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  if (tmp.hasIndexReg()) {
    fldx_s(fd, tmp.base(), tmp.index());
  } else {
    fld_s(fd, tmp.base(), tmp.offset());
  }
}

void MacroAssembler::Fst_s(FPURegister fs, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  if (tmp.hasIndexReg()) {
    fstx_s(fs, tmp.base(), tmp.index());
  } else {
    fst_s(fs, tmp.base(), tmp.offset());
  }
}

void MacroAssembler::Fld_d(FPURegister fd, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  if (tmp.hasIndexReg()) {
    fldx_d(fd, tmp.base(), tmp.index());
  } else {
    fld_d(fd, tmp.base(), tmp.offset());
  }
}

void MacroAssembler::Fst_d(FPURegister fs, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  if (tmp.hasIndexReg()) {
    fstx_d(fs, tmp.base(), tmp.index());
  } else {
    fst_d(fs, tmp.base(), tmp.offset());
  }
}

void MacroAssembler::Ll_w(Register rd, const MemOperand& rj) {
  DCHECK(!rj.hasIndexReg());
  bool is_one_instruction = is_int14(rj.offset());
  if (is_one_instruction) {
    ll_w(rd, rj.base(), rj.offset());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rj.offset());
    add_d(scratch, scratch, rj.base());
    ll_w(rd, scratch, 0);
  }
}

void MacroAssembler::Ll_d(Register rd, const MemOperand& rj) {
  DCHECK(!rj.hasIndexReg());
  bool is_one_instruction = is_int14(rj.offset());
  if (is_one_instruction) {
    ll_d(rd, rj.base(), rj.offset());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rj.offset());
    add_d(scratch, scratch, rj.base());
    ll_d(rd, scratch, 0);
  }
}

void MacroAssembler::Sc_w(Register rd, const MemOperand& rj) {
  DCHECK(!rj.hasIndexReg());
  bool is_one_instruction = is_int14(rj.offset());
  if (is_one_instruction) {
    sc_w(rd, rj.base(), rj.offset());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rj.offset());
    add_d(scratch, scratch, rj.base());
    sc_w(rd, scratch, 0);
  }
}

void MacroAssembler::Sc_d(Register rd, const MemOperand& rj) {
  DCHECK(!rj.hasIndexReg());
  bool is_one_instruction = is_int14(rj.offset());
  if (is_one_instruction) {
    sc_d(rd, rj.base(), rj.offset());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rj.offset());
    add_d(scratch, scratch, rj.base());
    sc_d(rd, scratch, 0);
  }
}

void MacroAssembler::li(Register dst, Handle<HeapObject> value,
                        RelocInfo::Mode rmode, LiFlags mode) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    IndirectLoadConstant(dst, value);
    return;
  }
  li(dst, Operand(value), mode);
}

void MacroAssembler::li(Register dst, ExternalReference reference,
                        LiFlags mode) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      Add_d(dst, kRootRegister, Operand(reference.offset_from_root_register()));
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
  li(dst, Operand(reference), mode);
}

static inline int InstrCountForLiLower32Bit(int64_t value) {
  if (is_int12(static_cast<int32_t>(value)) ||
      is_uint12(static_cast<int32_t>(value)) || !(value & kImm12Mask)) {
    return 1;
  } else {
    return 2;
  }
}

void MacroAssembler::LiLower32BitHelper(Register rd, Operand j) {
  if (is_int12(static_cast<int32_t>(j.immediate()))) {
    addi_d(rd, zero_reg, j.immediate());
  } else if (is_uint12(static_cast<int32_t>(j.immediate()))) {
    ori(rd, zero_reg, j.immediate() & kImm12Mask);
  } else {
    lu12i_w(rd, j.immediate() >> 12 & 0xfffff);
    if (j.immediate() & kImm12Mask) {
      ori(rd, rd, j.immediate() & kImm12Mask);
    }
  }
}

int MacroAssembler::InstrCountForLi64Bit(int64_t value) {
  if (is_int32(value)) {
    return InstrCountForLiLower32Bit(value);
  } else if (is_int52(value)) {
    return InstrCountForLiLower32Bit(value) + 1;
  } else if ((value & 0xffffffffL) == 0) {
    // 32 LSBs (Least Significant Bits) all set to zero.
    uint8_t tzc = base::bits::CountTrailingZeros32(value >> 32);
    uint8_t lzc = base::bits::CountLeadingZeros32(value >> 32);
    if (tzc >= 20) {
      return 1;
    } else if (tzc + lzc > 12) {
      return 2;
    } else {
      return 3;
    }
  } else {
    int64_t imm21 = (value >> 31) & 0x1fffffL;
    if (imm21 != 0x1fffffL && imm21 != 0) {
      return InstrCountForLiLower32Bit(value) + 2;
    } else {
      return InstrCountForLiLower32Bit(value) + 1;
    }
  }
  UNREACHABLE();
  return INT_MAX;
}

// All changes to if...else conditions here must be added to
// InstrCountForLi64Bit as well.
void MacroAssembler::li_optimized(Register rd, Operand j, LiFlags mode) {
  DCHECK(!j.is_reg());
  DCHECK(!MustUseReg(j.rmode()));
  DCHECK(mode == OPTIMIZE_SIZE);
  int64_t imm = j.immediate();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Normal load of an immediate value which does not need Relocation Info.
  if (is_int32(imm)) {
    LiLower32BitHelper(rd, j);
  } else if (is_int52(imm)) {
    LiLower32BitHelper(rd, j);
    lu32i_d(rd, imm >> 32 & 0xfffff);
  } else if ((imm & 0xffffffffL) == 0) {
    // 32 LSBs (Least Significant Bits) all set to zero.
    uint8_t tzc = base::bits::CountTrailingZeros32(imm >> 32);
    uint8_t lzc = base::bits::CountLeadingZeros32(imm >> 32);
    if (tzc >= 20) {
      lu52i_d(rd, zero_reg, imm >> 52 & kImm12Mask);
    } else if (tzc + lzc > 12) {
      int32_t mask = (1 << (32 - tzc)) - 1;
      lu12i_w(rd, imm >> (tzc + 32) & mask);
      slli_d(rd, rd, tzc + 20);
    } else {
      xor_(rd, rd, rd);
      lu32i_d(rd, imm >> 32 & 0xfffff);
      lu52i_d(rd, rd, imm >> 52 & kImm12Mask);
    }
  } else {
    int64_t imm21 = (imm >> 31) & 0x1fffffL;
    LiLower32BitHelper(rd, j);
    if (imm21 != 0x1fffffL && imm21 != 0) lu32i_d(rd, imm >> 32 & 0xfffff);
    lu52i_d(rd, rd, imm >> 52 & kImm12Mask);
  }
}

void MacroAssembler::li(Register rd, Operand j, LiFlags mode) {
  DCHECK(!j.is_reg());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (!MustUseReg(j.rmode()) && mode == OPTIMIZE_SIZE) {
    li_optimized(rd, j, mode);
  } else if (RelocInfo::IsCompressedEmbeddedObject(j.rmode())) {
    Handle<HeapObject> handle(reinterpret_cast<Address*>(j.immediate()));
    uint32_t immediate = AddEmbeddedObject(handle);
    RecordRelocInfo(j.rmode(), immediate);
    lu12i_w(rd, immediate >> 12 & 0xfffff);
    ori(rd, rd, immediate & kImm12Mask);
  } else if (MustUseReg(j.rmode())) {
    int64_t immediate;
    if (j.IsHeapNumberRequest()) {
      RequestHeapNumber(j.heap_number_request());
      immediate = 0;
    } else if (RelocInfo::IsFullEmbeddedObject(j.rmode())) {
      Handle<HeapObject> handle(reinterpret_cast<Address*>(j.immediate()));
      immediate = AddEmbeddedObject(handle);
    } else {
      immediate = j.immediate();
    }

    RecordRelocInfo(j.rmode(), immediate);
    lu12i_w(rd, immediate >> 12 & 0xfffff);
    ori(rd, rd, immediate & kImm12Mask);
    if (RelocInfo::IsWasmCanonicalSigId(j.rmode())) {
      // wasm_canonical_sig_id is 32-bit value.
      DCHECK(is_int32(immediate));
      return;
    }
    lu32i_d(rd, immediate >> 32 & 0xfffff);
  } else if (mode == ADDRESS_LOAD) {
    // We always need the same number of instructions as we may need to patch
    // this code to load another value which may need all 3 instructions.
    lu12i_w(rd, j.immediate() >> 12 & 0xfffff);
    ori(rd, rd, j.immediate() & kImm12Mask);
    lu32i_d(rd, j.immediate() >> 32 & 0xfffff);
  } else {  // mode == CONSTANT_SIZE - always emit the same instruction
            // sequence.
    lu12i_w(rd, j.immediate() >> 12 & 0xfffff);
    ori(rd, rd, j.immediate() & kImm12Mask);
    lu32i_d(rd, j.immediate() >> 32 & 0xfffff);
    lu52i_d(rd, rd, j.immediate() >> 52 & kImm12Mask);
  }
}

void MacroAssembler::LoadIsolateField(Register dst, IsolateFieldId id) {
  li(dst, ExternalReference::Create(id));
}

void MacroAssembler::MultiPush(RegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPush(RegList regs1, RegList regs2) {
  DCHECK((regs1 & regs2).is_empty());
  int16_t stack_offset = 0;

  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs1.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs2.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPush(RegList regs1, RegList regs2, RegList regs3) {
  DCHECK((regs1 & regs2).is_empty());
  DCHECK((regs1 & regs3).is_empty());
  DCHECK((regs2 & regs3).is_empty());
  int16_t stack_offset = 0;

  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs1.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs2.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs3.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPop(RegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPop(RegList regs1, RegList regs2) {
  DCHECK((regs1 & regs2).is_empty());
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs2.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs1.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPop(RegList regs1, RegList regs2, RegList regs3) {
  DCHECK((regs1 & regs2).is_empty());
  DCHECK((regs1 & regs3).is_empty());
  DCHECK((regs2 & regs3).is_empty());
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs3.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs2.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs1.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPushFPU(DoubleRegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kDoubleSize;

  Sub_d(sp, sp, Operand(stack_offset));
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kDoubleSize;
      Fst_d(FPURegister::from_code(i), MemOperand(sp, stack_offset));
    }
  }
}

void MacroAssembler::MultiPopFPU(DoubleRegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      Fld_d(FPURegister::from_code(i), MemOperand(sp, stack_offset));
      stack_offset += kDoubleSize;
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::Bstrpick_w(Register rk, Register rj, uint16_t msbw,
                                uint16_t lsbw) {
  DCHECK_LT(lsbw, msbw);
  DCHECK_LT(lsbw, 32);
  DCHECK_LT(msbw, 32);
  bstrpick_w(rk, rj, msbw, lsbw);
}

void MacroAssembler::Bstrpick_d(Register rk, Register rj, uint16_t msbw,
                                uint16_t lsbw) {
  DCHECK_LT(lsbw, msbw);
  DCHECK_LT(lsbw, 64);
  DCHECK_LT(msbw, 64);
  bstrpick_d(rk, rj, msbw, lsbw);
}

void MacroAssembler::Neg_s(FPURegister fd, FPURegister fj) { fneg_s(fd, fj); }

void MacroAssembler::Neg_d(FPURegister fd, FPURegister fj) { fneg_d(fd, fj); }

void MacroAssembler::Ffint_d_uw(FPURegister fd, FPURegister fj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  movfr2gr_s(t8, fj);
  Ffint_d_uw(fd, t8);
}

void MacroAssembler::Ffint_d_uw(FPURegister fd, Register rj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(rj != t7);

  Bstrpick_d(t7, rj, 31, 0);
  movgr2fr_d(fd, t7);
  ffint_d_l(fd, fd);
}

void MacroAssembler::Ffint_d_ul(FPURegister fd, FPURegister fj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  movfr2gr_d(t8, fj);
  Ffint_d_ul(fd, t8);
}

void MacroAssembler::Ffint_d_ul(FPURegister fd, Register rj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(rj != t7);

  Label msb_clear, conversion_done;

  Branch(&msb_clear, ge, rj, Operand(zero_reg));

  // Rj >= 2^63
  andi(t7, rj, 1);
  srli_d(rj, rj, 1);
  or_(t7, t7, rj);
  movgr2fr_d(fd, t7);
  ffint_d_l(fd, fd);
  fadd_d(fd, fd, fd);
  Branch(&conversion_done);

  bind(&msb_clear);
  // Rs < 2^63, we can do simple conversion.
  movgr2fr_d(fd, rj);
  ffint_d_l(fd, fd);

  bind(&conversion_done);
}

void MacroAssembler::Ffint_s_uw(FPURegister fd, FPURegister fj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  movfr2gr_d(t8, fj);
  Ffint_s_uw(fd, t8);
}

void MacroAssembler::Ffint_s_uw(FPURegister fd, Register rj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(rj != t7);

  bstrpick_d(t7, rj, 31, 0);
  movgr2fr_d(fd, t7);
  ffint_s_l(fd, fd);
}

void MacroAssembler::Ffint_s_ul(FPURegister fd, FPURegister fj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  movfr2gr_d(t8, fj);
  Ffint_s_ul(fd, t8);
}

void MacroAssembler::Ffint_s_ul(FPURegister fd, Register rj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(rj != t7);

  Label positive, conversion_done;

  Branch(&positive, ge, rj, Operand(zero_reg));

  // Rs >= 2^31.
  andi(t7, rj, 1);
  srli_d(rj, rj, 1);
  or_(t7, t7, rj);
  movgr2fr_d(fd, t7);
  ffint_s_l(fd, fd);
  fadd_s(fd, fd, fd);
  Branch(&conversion_done);

  bind(&positive);
  // Rs < 2^31, we can do simple conversion.
  movgr2fr_d(fd, rj);
  ffint_s_l(fd, fd);

  bind(&conversion_done);
}

void MacroAssembler::Ftintrne_l_d(FPURegister fd, FPURegister fj) {
  ftintrne_l_d(fd, fj);
}

void MacroAssembler::Ftintrm_l_d(FPURegister fd, FPURegister fj) {
  ftintrm_l_d(fd, fj);
}

void MacroAssembler::Ftintrp_l_d(FPURegister fd, FPURegister fj) {
  ftintrp_l_d(fd, fj);
}

void MacroAssembler::Ftintrz_l_d(FPURegister fd, FPURegister fj) {
  ftintrz_l_d(fd, fj);
}

void MacroAssembler::Ftintrz_l_ud(FPURegister fd, FPURegister fj,
                                  FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Load to GPR.
  movfr2gr_d(t8, fj);
  // Reset sign bit.
  {
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x7FFFFFFFFFFFFFFFl);
    and_(t8, t8, scratch1);
  }
  movgr2fr_d(scratch, t8);
  Ftintrz_l_d(fd, scratch);
}

void MacroAssembler::Ftintrz_uw_d(FPURegister fd, FPURegister fj,
                                  FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ftintrz_uw_d(t8, fj, scratch);
  movgr2fr_w(fd, t8);
}

void MacroAssembler::Ftintrz_uw_s(FPURegister fd, FPURegister fj,
                                  FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ftintrz_uw_s(t8, fj, scratch);
  movgr2fr_w(fd, t8);
}

void MacroAssembler::Ftintrz_ul_d(FPURegister fd, FPURegister fj,
                                  FPURegister scratch, Register result) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ftintrz_ul_d(t8, fj, scratch, result);
  movgr2fr_d(fd, t8);
}

void MacroAssembler::Ftintrz_ul_s(FPURegister fd, FPURegister fj,
                                  FPURegister scratch, Register result) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ftintrz_ul_s(t8, fj, scratch, result);
  movgr2fr_d(fd, t8);
}

void MacroAssembler::Ftintrz_w_d(FPURegister fd, FPURegister fj) {
  ftintrz_w_d(fd, fj);
}

void MacroAssembler::Ftintrne_w_d(FPURegister fd, FPURegister fj) {
  ftintrne_w_d(fd, fj);
}

void MacroAssembler::Ftintrm_w_d(FPURegister fd, FPURegister fj) {
  ftintrm_w_d(fd, fj);
}

void MacroAssembler::Ftintrp_w_d(FPURegister fd, FPURegister fj) {
  ftintrp_w_d(fd, fj);
}

void MacroAssembler::Ftintrz_uw_d(Register rd, FPURegister fj,
                                  FPURegister scratch) {
  DCHECK(fj != scratch);
  DCHECK(rd != t7);

  {
    // Load 2^32 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x41F0000000000000);
    movgr2fr_d(scratch, scratch1);
  }
  // Test if scratch > fd.
  // If fd < 2^32 we can convert it normally.
  Label simple_convert;
  CompareF64(fj, scratch, CULT);
  BranchTrueShortF(&simple_convert);

  // If fd > 2^32, the result should be UINT_32_MAX;
  Add_w(rd, zero_reg, -1);

  Label done;
  Branch(&done);
  // Simple conversion.
  bind(&simple_convert);
  // Double -> Int64 -> Uint32;
  ftintrz_l_d(scratch, fj);
  movfr2gr_s(rd, scratch);

  bind(&done);
}

void MacroAssembler::Ftintrz_uw_s(Register rd, FPURegister fj,
                                  FPURegister scratch) {
  DCHECK(fj != scratch);
  DCHECK(rd != t7);
  {
    // Load 2^32 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x4F800000);
    movgr2fr_w(scratch, scratch1);
  }
  // Test if scratch > fs.
  // If fs < 2^32 we can convert it normally.
  Label simple_convert;
  CompareF32(fj, scratch, CULT);
  BranchTrueShortF(&simple_convert);

  // If fd > 2^32, the result should be UINT_32_MAX;
  Add_w(rd, zero_reg, -1);

  Label done;
  Branch(&done);
  // Simple conversion.
  bind(&simple_convert);
  // Float -> Int64 -> Uint32;
  ftintrz_l_s(scratch, fj);
  movfr2gr_s(rd, scratch);

  bind(&done);
}

void MacroAssembler::Ftintrz_ul_d(Register rd, FPURegister fj,
                                  FPURegister scratch, Register result) {
  DCHECK(fj != scratch);
  DCHECK(result.is_valid() ? !AreAliased(rd, result, t7) : !AreAliased(rd, t7));

  Label simple_convert, done, fail;
  if (result.is_valid()) {
    mov(result, zero_reg);
    Move(scratch, -1.0);
    // If fd =< -1 or unordered, then the conversion fails.
    CompareF64(fj, scratch, CULE);
    BranchTrueShortF(&fail);
  }

  // Load 2^63 into scratch as its double representation.
  li(t7, 0x43E0000000000000);
  movgr2fr_d(scratch, t7);

  // Test if scratch > fs.
  // If fs < 2^63 or unordered we can convert it normally.
  CompareF64(fj, scratch, CULT);
  BranchTrueShortF(&simple_convert);

  // First we subtract 2^63 from fs, then trunc it to rd
  // and add 2^63 to rd.
  fsub_d(scratch, fj, scratch);
  ftintrz_l_d(scratch, scratch);
  movfr2gr_d(rd, scratch);
  Or(rd, rd, Operand(1UL << 63));
  Branch(&done);

  // Simple conversion.
  bind(&simple_convert);
  ftintrz_l_d(scratch, fj);
  movfr2gr_d(rd, scratch);

  bind(&done);
  if (result.is_valid()) {
    // Conversion is failed if the result is negative.
    {
      UseScratchRegisterScope temps(this);
      Register scratch1 = temps.Acquire();
      addi_d(scratch1, zero_reg, -1);
      srli_d(scratch1, scratch1, 1);  // Load 2^62.
      movfr2gr_d(result, scratch);
      xor_(result, result, scratch1);
    }
    Slt(result, zero_reg, result);
  }

  bind(&fail);
}

void MacroAssembler::Ftintrz_ul_s(Register rd, FPURegister fj,
                                  FPURegister scratch, Register result) {
  DCHECK(fj != scratch);
  DCHECK(result.is_valid() ? !AreAliased(rd, result, t7) : !AreAliased(rd, t7));

  Label simple_convert, done, fail;
  if (result.is_valid()) {
    mov(result, zero_reg);
    Move(scratch, -1.0f);
    // If fd =< -1 or unordered, then the conversion fails.
    CompareF32(fj, scratch, CULE);
    BranchTrueShortF(&fail);
  }

  {
    // Load 2^63 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x5F000000);
    movgr2fr_w(scratch, scratch1);
  }

  // Test if scratch > fs.
  // If fs < 2^63 or unordered, we can convert it normally.
  CompareF32(fj, scratch, CULT);
  BranchTrueShortF(&simple_convert);

  // First we subtract 2^63 from fs, then trunc it to rd
  // and add 2^63 to rd.
  fsub_s(scratch, fj, scratch);
  ftintrz_l_s(scratch, scratch);
  movfr2gr_d(rd, scratch);
  Or(rd, rd, Operand(1UL << 63));
  Branch(&done);

  // Simple conversion.
  bind(&simple_convert);
  ftintrz_l_s(scratch, fj);
  movfr2gr_d(rd, scratch);

  bind(&done);
  if (result.is_valid()) {
    // Conversion is failed if the result is negative or unordered.
    {
      UseScratchRegisterScope temps(this);
      Register scratch1 = temps.Acquire();
      addi_d(scratch1, zero_reg, -1);
      srli_d(scratch1, scratch1, 1);  // Load 2^62.
      movfr2gr_d(result, scratch);
      xor_(result, result, scratch1);
    }
    Slt(result, zero_reg, result);
  }

  bind(&fail);
}

void MacroAssembler::RoundDouble(FPURegister dst, FPURegister src,
                                 FPURoundingMode mode) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  movfcsr2gr(scratch);
  li(t7, Operand(mode));
  movgr2fcsr(t7);
  frint_d(dst, src);
  movgr2fcsr(scratch);
}

void MacroAssembler::Floor_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_floor);
}

void MacroAssembler::Ceil_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_ceil);
}

void MacroAssembler::Trunc_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_trunc);
}

void MacroAssembler::Round_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_round);
}

void MacroAssembler::RoundFloat(FPURegister dst, FPURegister src,
                                FPURoundingMode mode) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  movfcsr2gr(scratch);
  li(t7, Operand(mode));
  movgr2fcsr(t7);
  frint_s(dst, src);
  movgr2fcsr(scratch);
}

void MacroAssembler::Floor_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_floor);
}

void MacroAssembler::Ceil_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_ceil);
}

void MacroAssembler::Trunc_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_trunc);
}

void MacroAssembler::Round_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_round);
}

void MacroAssembler::CompareF(FPURegister cmp1, FPURegister cmp2,
                              FPUCondition cc, CFRegister cd, bool f32) {
  if (f32) {
    fcmp_cond_s(cc, cmp1, cmp2, cd);
  } else {
    fcmp
"""


```
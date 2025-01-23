Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/ppc/macro-assembler-ppc.cc`. They also have specific questions about how to identify Torque source files and how the code relates to JavaScript. Finally, they want a summary of the functionality of this first part of the file.

Here's a breakdown of the thinking process to answer the request:

1. **Identify the core purpose:** The filename `macro-assembler-ppc.cc` immediately suggests this code is about generating machine code instructions for the PowerPC architecture within the V8 JavaScript engine. The "macro-assembler" part implies it provides a higher-level abstraction over raw assembly instructions.

2. **Analyze the includes:** The included headers provide clues about the functionalities implemented:
    * `<assert.h>`, `<limits.h>`: Basic C utilities.
    * `src/base/bits.h`, `src/base/division-by-constant.h`: Low-level utilities.
    * `src/builtins/builtins-inl.h`:  Interaction with built-in JavaScript functions.
    * `src/codegen/*`:  Core code generation components like `Callable`, `CodeFactory`, `ExternalReferenceTable`, `InterfaceDescriptors`, `MacroAssembler`, `RegisterConfiguration`, `Register`.
    * `src/debug/debug.h`: Debugging support.
    * `src/deoptimizer/deoptimizer.h`: Handling deoptimization (returning to interpreted code).
    * `src/execution/frames-inl.h`:  Stack frame management.
    * `src/heap/*`:  Memory management within V8.
    * `src/init/bootstrapper.h`:  V8 initialization.
    * `src/logging/counters.h`: Performance counters.
    * `src/runtime/runtime.h`:  Interaction with the V8 runtime system.
    * `src/snapshot/snapshot.h`:  Saving and loading V8 state.

3. **Examine the code structure:** The code defines a `MacroAssembler` class within the `v8::internal` namespace, specifically for the PPC architecture. It contains methods for:
    * Managing caller-saved registers (pushing and popping).
    * Jumping to different code locations.
    * Loading and storing data from memory, including constants, roots, and object fields.
    * Calling functions (both regular and built-in).
    * Manipulating the stack.
    * Moving data between registers.
    * Handling tagged values (V8's representation of JavaScript values).
    * Dealing with sandboxed pointers (a security feature).
    * Implementing record writes (updating object properties with write barriers).

4. **Address the specific questions:**
    * **Torque source:**  The prompt provides the rule: `.tq` extension indicates a Torque source file. This is a straightforward check.
    * **Relationship to JavaScript:** The methods clearly relate to how V8 executes JavaScript. Operations like loading object fields, calling built-ins, and handling tagged values are fundamental to JavaScript execution. The example provided will focus on a simple operation like accessing an object property.
    * **Code logic reasoning:**  Pick a relatively simple method, like `LoadFromConstantsTable`, and illustrate its behavior with input and output.
    * **Common programming errors:**  Consider typical mistakes developers make that this code might help prevent or handle, such as incorrect memory access.

5. **Summarize the functionality of Part 1:**  Focus on the key responsibilities demonstrated in the code provided, which are primarily low-level code generation primitives for the PPC architecture within V8.

6. **Structure the answer:** Organize the information logically, starting with the core functionality, then addressing the specific questions, and finally providing the summary. Use clear and concise language. Use code blocks for the JavaScript example and the input/output scenario.

7. **Refine the answer:** Review the generated answer for accuracy, completeness, and clarity. Ensure all parts of the prompt are addressed. For example, initially, I might have missed the distinction between different `Call` methods (with `Code`, `Address`, `Builtin`). A review would catch this and allow for a more nuanced explanation. Similarly, ensuring the JavaScript example directly relates to the C++ code is important.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>  // For assert
#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_PPC64

#include <optional>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/builtins/builtins-inl.h"
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
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/ppc/macro-assembler-ppc.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

namespace {

// Simd and Floating Pointer registers are not shared. For WebAssembly we save
// both registers, If we are not running Wasm, we can get away with only saving
// FP registers.
#if V8_ENABLE_WEBASSEMBLY
constexpr int kStackSavedSavedFPSizeInBytes =
    (kNumCallerSavedDoubles * kSimd128Size) +
    (kNumCallerSavedDoubles * kDoubleSize);
#else
constexpr int kStackSavedSavedFPSizeInBytes =
    kNumCallerSavedDoubles * kDoubleSize;
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion1,
                                                    Register exclusion2,
                                                    Register exclusion3) const {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register scratch1,
                                    Register scratch2, Register exclusion1,
                                    Register exclusion2, Register exclusion3) {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushF64AndV128(kCallerSavedDoubles, kCallerSavedSimd128s, scratch1,
                        scratch2);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register scratch1,
                                   Register scratch2, Register exclusion1,
                                   Register exclusion2, Register exclusion3) {
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopF64AndV128(kCallerSavedDoubles, kCallerSavedSimd128s, scratch1,
                       scratch2);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kSystemPointerSize;

  return bytes;
}

void MacroAssembler::Jump(Register target) {
  mtctr(target);
  bctr();
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));

  DCHECK_NE(destination, r0);
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(destination,
                  FieldMemOperand(destination, FixedArray::OffsetOfElementAt(
                                                   constant_index)),
                  r0);
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  LoadU64(destination, MemOperand(kRootRegister, offset), r0);
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  StoreU64(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    mr(destination, kRootRegister);
  } else {
    AddS64(destination, kRootRegister, Operand(offset), destination);
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
        LoadU64(scratch,
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

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond, CRegister cr) {
  Label skip;

  if (cond != al) b(NegateCondition(cond), &skip, cr);

  mov(ip, Operand(target, rmode));
  mtctr(ip);
  bctr();

  bind(&skip);
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode, Condition cond,
                          CRegister cr) {
  DCHECK(!RelocInfo::IsCodeTarget(rmode));
  Jump(static_cast<intptr_t>(target), rmode, cond, cr);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, CRegister cr) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    TailCallBuiltin(builtin, cond, cr);
    return;
  }
  int32_t target_index = AddCodeTarget(code);
  Jump(static_cast<intptr_t>(target_index), rmode, cond, cr);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, reference);
  if (ABI_USES_FUNCTION_DESCRIPTORS) {
    // AIX uses a function descriptor. When calling C code be
    // aware of this descriptor and pick up values from it.
    LoadU64(ToRegister(ABI_TOC_REGISTER),
            MemOperand(scratch, kSystemPointerSize));
    LoadU64(scratch, MemOperand(scratch, 0));
  }
  Jump(scratch);
}

void MacroAssembler::Call(Register target) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // branch via link register and set LK bit for return point
  mtctr(target);
  bctrl();
}

void MacroAssembler::CallJSEntry(Register target) {
  CHECK(target == r5);
  Call(target);
}

int MacroAssembler::CallSizeNotPredictableCodeSize(Address target,
                                                   RelocInfo::Mode rmode,
                                                   Condition cond) {
  return (2 + kMovInstructionsNoConstantPool) * kInstrSize;
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode,
                          Condition cond) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(cond == al);

  // This can likely be optimized to make use of bc() with 24bit relative
  //
  // RecordRelocInfo(x.rmode_, x.immediate);
  // bc( BA, .... offset, LKset);
  //

  mov(ip, Operand(target, rmode));
  mtctr(ip);
  bctrl();
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin, cond);
    return;
  }
  int32_t target_index = AddCodeTarget(code);
  Call(static_cast<Address>(target_index), rmode, cond);
}

void MacroAssembler::CallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      Label skip;
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      if (cond != al) b(NegateCondition(cond), &skip);
      Call(ip);
      bind(&skip);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect: {
      Label skip;
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin), r0);
      if (cond != al) b(NegateCondition(cond), &skip);
      Call(ip);
      bind(&skip);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        Call(static_cast<Address>(code_target_index), RelocInfo::CODE_TARGET,
             cond);
      } else {
        Label skip;
        LoadU64(ip, EntryFromBuiltinAsOperand(builtin), r0);
        if (cond != al) b(NegateCondition(cond), &skip);
        Call(ip);
        bind(&skip);
      }
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond,
                                     CRegister cr) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      Label skip;
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      if (cond != al) b(NegateCondition(cond), &skip, cr);
      Jump(ip);
      bind(&skip);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect: {
      Label skip;
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
      if (cond != al) b(NegateCondition(cond), &skip, cr);
      Jump(ip);
      bind(&skip);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        Jump(static_cast<intptr_t>(code_target_index), RelocInfo::CODE_TARGET,
             cond, cr);
      } else {
        Label skip;
        LoadU64(ip, EntryFromBuiltinAsOperand(builtin), r0);
        if (cond != al) b(NegateCondition(cond), &skip, cr);
        Jump(ip);
        bind(&skip);
      }
      break;
    }
  }
}

void MacroAssembler::Drop(int count) {
  if (count > 0) {
    AddS64(sp, sp, Operand(count * kSystemPointerSize), r0);
  }
}

void MacroAssembler::Drop(Register count, Register scratch) {
  ShiftLeftU64(scratch, count, Operand(kSystemPointerSizeLog2));
  add(sp, sp, scratch);
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code,
                                                       Register scratch1,
                                                       Register scratch2) {
  LoadU32(scratch1, FieldMemOperand(code, Code::kFlagsOffset), scratch2);
  TestBit(scratch1, Code::kMarkedForDeoptimizationBit, scratch2);
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::Call(Label* target) { b(target, SetLK); }

void MacroAssembler::Push(Handle<HeapObject> handle) {
  mov(r0, Operand(handle));
  push(r0);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  mov(r0, Operand(smi));
  push(r0);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               Register scratch2, PushArrayOrder order) {
  Label loop, done;

  if (order == kNormal) {
    cmpi(size, Operand::Zero());
    beq(&done);
    ShiftLeftU64(scratch, size, Operand(kSystemPointerSizeLog2));
    add(scratch, array, scratch);
    mtctr(size);

    bind(&loop);
    LoadU64WithUpdate(scratch2, MemOperand(scratch, -kSystemPointerSize));
    StoreU64WithUpdate(scratch2, MemOperand(sp, -kSystemPointerSize));
    bdnz(&loop);

    bind(&done);
  } else {
    cmpi(size, Operand::Zero());
    beq(&done);

    mtctr(size);
    subi(scratch, array, Operand(kSystemPointerSize));

    bind(&loop);
    LoadU64WithUpdate(scratch2, MemOperand(scratch, kSystemPointerSize));
    StoreU64WithUpdate(scratch2, MemOperand(sp, -kSystemPointerSize));
    bdnz(&loop);
    bind(&done);
  }
}

void MacroAssembler::Move(Register dst, Handle<HeapObject> value,
                          RelocInfo::Mode rmode) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    IndirectLoadConstant(dst, value);
    return;
  } else if (RelocInfo::IsCompressedEmbeddedObject(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(value);
    DCHECK(is_uint32(index));
    mov(dst, Operand(static_cast<int>(index), rmode));
  } else {
    DCHECK(RelocInfo::IsFullEmbeddedObject(rmode));
    mov(dst, Operand(value.address(), rmode));
  }
}

void MacroAssembler::Move(Register dst, ExternalReference reference) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      AddS64(dst, kRootRegister,
             Operand(reference.offset_from_root_register()));
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
  DCHECK(cond == al);
  if (dst != src) {
    mr(dst, src);
  }
}

void MacroAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  if (dst != src) {
    fmr(dst, src);
  }
}

void MacroAssembler::MultiPush(RegList regs, Register location) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kSystemPointerSize;

  subi(location, location, Operand(stack_offset));
  for (int16_t i = Register::kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      StoreU64(ToRegister(i), MemOperand(location, stack_offset));
    }
  }
}

void MacroAssembler::MultiPop(RegList regs, Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < Register::kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      LoadU64(ToRegister(i), MemOperand(location, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  addi(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPushDoubles(DoubleRegList dregs, Register location) {
  int16_t num_to_push = dregs.Count();
  int16_t stack_offset = num_to_push * kDoubleSize;

  subi(location, location, Operand(stack_offset));
  for (int16_t i = DoubleRegister::kNumRegisters - 1; i >= 0; i--) {
    if ((dregs.bits() & (1 << i)) != 0) {
      DoubleRegister dreg = DoubleRegister::from_code(i);
      stack_offset -= kDoubleSize;
      stfd(dreg, MemOperand(location, stack_offset));
    }
  }
}

void MacroAssembler::MultiPushV128(Simd128RegList simd_regs, Register scratch,
                                   Register location) {
  int16_t num_to_push = simd_regs.Count();
  int16_t stack_offset = num_to_push * kSimd128Size;

  subi(location, location, Operand(stack_offset));
  for (int16_t i = Simd128Register::kNumRegisters - 1; i >= 0; i--) {
    if ((simd_regs.bits() & (1 << i)) != 0) {
      Simd128Register simd_reg = Simd128Register::from_code(i);
      stack_offset -= kSimd128Size;
      StoreSimd128(simd_reg, MemOperand(location, stack_offset), scratch);
    }
  }
}

void MacroAssembler::MultiPopDoubles(DoubleRegList dregs, Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < DoubleRegister::kNumRegisters; i++) {
    if ((dregs.bits() & (1 << i)) != 0) {
      DoubleRegister dreg = DoubleRegister::from_code(i);
      lfd(dreg, MemOperand(location, stack_offset));
      stack_offset += kDoubleSize;
    }
  }
  addi(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPopV128(Simd128RegList simd_regs, Register scratch,
                                  Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < Simd128Register::kNumRegisters; i++) {
    if ((simd_regs.bits() & (1 << i)) != 0) {
      Simd128Register simd_reg = Simd128Register::from_code(i);
      LoadSimd128(simd_reg, MemOperand(location, stack_offset), scratch);
      stack_offset += kSimd128Size;
    }
  }
  addi(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPushF64AndV128(DoubleRegList dregs,
                                         Simd128RegList simd_regs,
                                         Register scratch1, Register scratch2,
                                         Register location) {
  MultiPushDoubles(dregs);
#if V8_ENABLE_WEBASSEMBLY
  bool generating_bultins =
      isolate() && isolate()->IsGeneratingEmbeddedBuiltins();
  if (generating_bultins) {
    // V8 uses the same set of fp param registers as Simd param registers.
    // As these registers are two different sets on ppc we must make
    // sure to also save them when Simd is enabled.
    // Check the comments under crrev.com/c/2645694 for more details.
    Label push_empty_simd, simd_pushed;
    Move(scratch1, ExternalReference::supports_wasm_simd_128_address());
    LoadU8(scratch1, MemOperand(scratch1), scratch2);
    cmpi(scratch1, Operand::Zero());  // If > 0 then simd is available.
    ble(&push_empty_simd);
    MultiPushV128(simd_regs, scratch1);
    b(&simd_pushed);
    bind(&push_empty_simd);
    // We still need to allocate empty space on the stack even if we
    // are not pushing Simd registers (see kFixedFrameSizeFromFp).
    addi(sp, sp,
         Operand(-static_cast<int8_t>(simd_regs.Count()) * kSimd128Size));
    bind(&simd_pushed);
  } else {
    if (CpuFeatures::SupportsWasmSimd128()) {
      MultiPushV128(simd_regs, scratch1);
    } else {
      addi(sp, sp,
           Operand(-static_cast<int8_t>(simd_regs.Count()) * kSimd128Size));
    }
  }
#endif
}

void MacroAssembler::MultiPopF64AndV128(DoubleRegList dregs,
                                        Simd128RegList simd_regs,
                                        Register scratch1, Register scratch2,
                                        Register location) {
#if V8_ENABLE_WEBASSEMBLY
  bool generating_bultins =
      isolate() && isolate()->IsGeneratingEmbeddedBuiltins();
  if (generating_bultins) {
    Label pop_empty_simd, simd_popped;
    Move(scratch1, ExternalReference::supports_wasm_simd_128_address());
    LoadU8(scratch1, MemOperand(scratch1), scratch2);
    cmpi(scratch1, Operand::Zero());  // If > 0 then simd is available.
    ble(&pop_empty_simd);
    MultiPopV128(simd_regs, scratch1);
    b(&simd_popped);
    bind(&pop_empty_simd);
    addi(sp, sp,
         Operand(static_cast<int8_t>(simd_regs.Count()) * kSimd128Size));
    bind(&simd_popped);
  } else {
    if (CpuFeatures::SupportsWasmSimd128()) {
      MultiPopV128(simd_regs, scratch1);
    } else {
      addi(sp, sp,
           Operand(static_cast<int8_t>(simd_regs.Count()) * kSimd128Size));
    }
  }
#endif
  MultiPopDoubles(dregs);
}

void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (CanBeImmediate(index)) {
    mov(destination, Operand(ReadOnlyRootPtr(index), RelocInfo::Mode::NO_INFO));
    return;
  }
  LoadRoot(destination, index);
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index,
                              Condition cond) {
  DCHECK(cond == al);
  if (CanBeImmediate(index)) {
    DecompressTagged(destination, ReadOnlyRootPtr(index));
    return;
  }
  LoadU64(destination,
          MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)), r0);
}

void MacroAssembler::LoadTaggedField(const Register& destination,
                                     const MemOperand& field_operand,
                                     const Register& scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand);
  } else {
    LoadU64(destination, field_operand, scratch);
  }
}

void MacroAssembler::SmiUntag(Register dst, const MemOperand& src, RCBit rc,
                              Register scratch) {
  if (SmiValuesAre31Bits()) {
    LoadU32(dst, src, scratch);
  } else {
    LoadU64(dst, src, scratch);
  }

  SmiUntag(dst, rc);
}

void MacroAssembler::StoreTaggedField(const Register& value,
                                      const MemOperand& dst_field_operand,
                                      const Register& scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    RecordComment("[ StoreTagged");
    StoreU32(value, dst_field_operand, scratch);
    RecordComment("]");
  } else {
    StoreU64(value, dst_field_operand, scratch);
  }
}

void MacroAssembler::DecompressTaggedSigned(Register destination,
                                            Register src) {
  RecordComment("[ DecompressTaggedSigned");
  ZeroExtWord32(destination, src);
  RecordComment("]");
}

void MacroAssembler::DecompressTaggedSigned(Register destination,
                                            MemOperand field_operand) {
  RecordComment("[ DecompressTaggedSigned");
  LoadU32(destination, field_operand, r0);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(Register destination, Register source) {
  RecordComment("[ DecompressTagged");
  ZeroExtWord32(destination, source);
  add(destination, destination, kPtrComprCageBaseRegister);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(Register destination,
                                      MemOperand field_operand) {
  RecordComment("[ DecompressTagged");
  LoadU32(destination, field_operand, r0);
  add(destination, destination, kPtrComprCageBaseRegister);
  RecordComment("
### 提示词
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/macro-assembler-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>  // For assert
#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_PPC64

#include <optional>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/builtins/builtins-inl.h"
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
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/ppc/macro-assembler-ppc.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

namespace {

// Simd and Floating Pointer registers are not shared. For WebAssembly we save
// both registers, If we are not running Wasm, we can get away with only saving
// FP registers.
#if V8_ENABLE_WEBASSEMBLY
constexpr int kStackSavedSavedFPSizeInBytes =
    (kNumCallerSavedDoubles * kSimd128Size) +
    (kNumCallerSavedDoubles * kDoubleSize);
#else
constexpr int kStackSavedSavedFPSizeInBytes =
    kNumCallerSavedDoubles * kDoubleSize;
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion1,
                                                    Register exclusion2,
                                                    Register exclusion3) const {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register scratch1,
                                    Register scratch2, Register exclusion1,
                                    Register exclusion2, Register exclusion3) {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushF64AndV128(kCallerSavedDoubles, kCallerSavedSimd128s, scratch1,
                        scratch2);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register scratch1,
                                   Register scratch2, Register exclusion1,
                                   Register exclusion2, Register exclusion3) {
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopF64AndV128(kCallerSavedDoubles, kCallerSavedSimd128s, scratch1,
                       scratch2);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kSystemPointerSize;

  return bytes;
}

void MacroAssembler::Jump(Register target) {
  mtctr(target);
  bctr();
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));

  DCHECK_NE(destination, r0);
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(destination,
                  FieldMemOperand(destination, FixedArray::OffsetOfElementAt(
                                                   constant_index)),
                  r0);
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  LoadU64(destination, MemOperand(kRootRegister, offset), r0);
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  StoreU64(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    mr(destination, kRootRegister);
  } else {
    AddS64(destination, kRootRegister, Operand(offset), destination);
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
        LoadU64(scratch,
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

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond, CRegister cr) {
  Label skip;

  if (cond != al) b(NegateCondition(cond), &skip, cr);

  mov(ip, Operand(target, rmode));
  mtctr(ip);
  bctr();

  bind(&skip);
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode, Condition cond,
                          CRegister cr) {
  DCHECK(!RelocInfo::IsCodeTarget(rmode));
  Jump(static_cast<intptr_t>(target), rmode, cond, cr);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, CRegister cr) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    TailCallBuiltin(builtin, cond, cr);
    return;
  }
  int32_t target_index = AddCodeTarget(code);
  Jump(static_cast<intptr_t>(target_index), rmode, cond, cr);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, reference);
  if (ABI_USES_FUNCTION_DESCRIPTORS) {
    // AIX uses a function descriptor. When calling C code be
    // aware of this descriptor and pick up values from it.
    LoadU64(ToRegister(ABI_TOC_REGISTER),
            MemOperand(scratch, kSystemPointerSize));
    LoadU64(scratch, MemOperand(scratch, 0));
  }
  Jump(scratch);
}

void MacroAssembler::Call(Register target) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // branch via link register and set LK bit for return point
  mtctr(target);
  bctrl();
}

void MacroAssembler::CallJSEntry(Register target) {
  CHECK(target == r5);
  Call(target);
}

int MacroAssembler::CallSizeNotPredictableCodeSize(Address target,
                                                   RelocInfo::Mode rmode,
                                                   Condition cond) {
  return (2 + kMovInstructionsNoConstantPool) * kInstrSize;
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode,
                          Condition cond) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(cond == al);

  // This can likely be optimized to make use of bc() with 24bit relative
  //
  // RecordRelocInfo(x.rmode_, x.immediate);
  // bc( BA, .... offset, LKset);
  //

  mov(ip, Operand(target, rmode));
  mtctr(ip);
  bctrl();
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin, cond);
    return;
  }
  int32_t target_index = AddCodeTarget(code);
  Call(static_cast<Address>(target_index), rmode, cond);
}

void MacroAssembler::CallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      Label skip;
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      if (cond != al) b(NegateCondition(cond), &skip);
      Call(ip);
      bind(&skip);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect: {
      Label skip;
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin), r0);
      if (cond != al) b(NegateCondition(cond), &skip);
      Call(ip);
      bind(&skip);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        Call(static_cast<Address>(code_target_index), RelocInfo::CODE_TARGET,
             cond);
      } else {
        Label skip;
        LoadU64(ip, EntryFromBuiltinAsOperand(builtin), r0);
        if (cond != al) b(NegateCondition(cond), &skip);
        Call(ip);
        bind(&skip);
      }
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond,
                                     CRegister cr) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      Label skip;
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      if (cond != al) b(NegateCondition(cond), &skip, cr);
      Jump(ip);
      bind(&skip);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect: {
      Label skip;
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
      if (cond != al) b(NegateCondition(cond), &skip, cr);
      Jump(ip);
      bind(&skip);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        Jump(static_cast<intptr_t>(code_target_index), RelocInfo::CODE_TARGET,
             cond, cr);
      } else {
        Label skip;
        LoadU64(ip, EntryFromBuiltinAsOperand(builtin), r0);
        if (cond != al) b(NegateCondition(cond), &skip, cr);
        Jump(ip);
        bind(&skip);
      }
      break;
    }
  }
}

void MacroAssembler::Drop(int count) {
  if (count > 0) {
    AddS64(sp, sp, Operand(count * kSystemPointerSize), r0);
  }
}

void MacroAssembler::Drop(Register count, Register scratch) {
  ShiftLeftU64(scratch, count, Operand(kSystemPointerSizeLog2));
  add(sp, sp, scratch);
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code,
                                                       Register scratch1,
                                                       Register scratch2) {
  LoadU32(scratch1, FieldMemOperand(code, Code::kFlagsOffset), scratch2);
  TestBit(scratch1, Code::kMarkedForDeoptimizationBit, scratch2);
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::Call(Label* target) { b(target, SetLK); }

void MacroAssembler::Push(Handle<HeapObject> handle) {
  mov(r0, Operand(handle));
  push(r0);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  mov(r0, Operand(smi));
  push(r0);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               Register scratch2, PushArrayOrder order) {
  Label loop, done;

  if (order == kNormal) {
    cmpi(size, Operand::Zero());
    beq(&done);
    ShiftLeftU64(scratch, size, Operand(kSystemPointerSizeLog2));
    add(scratch, array, scratch);
    mtctr(size);

    bind(&loop);
    LoadU64WithUpdate(scratch2, MemOperand(scratch, -kSystemPointerSize));
    StoreU64WithUpdate(scratch2, MemOperand(sp, -kSystemPointerSize));
    bdnz(&loop);

    bind(&done);
  } else {
    cmpi(size, Operand::Zero());
    beq(&done);

    mtctr(size);
    subi(scratch, array, Operand(kSystemPointerSize));

    bind(&loop);
    LoadU64WithUpdate(scratch2, MemOperand(scratch, kSystemPointerSize));
    StoreU64WithUpdate(scratch2, MemOperand(sp, -kSystemPointerSize));
    bdnz(&loop);
    bind(&done);
  }
}

void MacroAssembler::Move(Register dst, Handle<HeapObject> value,
                          RelocInfo::Mode rmode) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    IndirectLoadConstant(dst, value);
    return;
  } else if (RelocInfo::IsCompressedEmbeddedObject(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(value);
    DCHECK(is_uint32(index));
    mov(dst, Operand(static_cast<int>(index), rmode));
  } else {
    DCHECK(RelocInfo::IsFullEmbeddedObject(rmode));
    mov(dst, Operand(value.address(), rmode));
  }
}

void MacroAssembler::Move(Register dst, ExternalReference reference) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      AddS64(dst, kRootRegister,
             Operand(reference.offset_from_root_register()));
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
  DCHECK(cond == al);
  if (dst != src) {
    mr(dst, src);
  }
}

void MacroAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  if (dst != src) {
    fmr(dst, src);
  }
}

void MacroAssembler::MultiPush(RegList regs, Register location) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kSystemPointerSize;

  subi(location, location, Operand(stack_offset));
  for (int16_t i = Register::kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      StoreU64(ToRegister(i), MemOperand(location, stack_offset));
    }
  }
}

void MacroAssembler::MultiPop(RegList regs, Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < Register::kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      LoadU64(ToRegister(i), MemOperand(location, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  addi(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPushDoubles(DoubleRegList dregs, Register location) {
  int16_t num_to_push = dregs.Count();
  int16_t stack_offset = num_to_push * kDoubleSize;

  subi(location, location, Operand(stack_offset));
  for (int16_t i = DoubleRegister::kNumRegisters - 1; i >= 0; i--) {
    if ((dregs.bits() & (1 << i)) != 0) {
      DoubleRegister dreg = DoubleRegister::from_code(i);
      stack_offset -= kDoubleSize;
      stfd(dreg, MemOperand(location, stack_offset));
    }
  }
}

void MacroAssembler::MultiPushV128(Simd128RegList simd_regs, Register scratch,
                                   Register location) {
  int16_t num_to_push = simd_regs.Count();
  int16_t stack_offset = num_to_push * kSimd128Size;

  subi(location, location, Operand(stack_offset));
  for (int16_t i = Simd128Register::kNumRegisters - 1; i >= 0; i--) {
    if ((simd_regs.bits() & (1 << i)) != 0) {
      Simd128Register simd_reg = Simd128Register::from_code(i);
      stack_offset -= kSimd128Size;
      StoreSimd128(simd_reg, MemOperand(location, stack_offset), scratch);
    }
  }
}

void MacroAssembler::MultiPopDoubles(DoubleRegList dregs, Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < DoubleRegister::kNumRegisters; i++) {
    if ((dregs.bits() & (1 << i)) != 0) {
      DoubleRegister dreg = DoubleRegister::from_code(i);
      lfd(dreg, MemOperand(location, stack_offset));
      stack_offset += kDoubleSize;
    }
  }
  addi(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPopV128(Simd128RegList simd_regs, Register scratch,
                                  Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < Simd128Register::kNumRegisters; i++) {
    if ((simd_regs.bits() & (1 << i)) != 0) {
      Simd128Register simd_reg = Simd128Register::from_code(i);
      LoadSimd128(simd_reg, MemOperand(location, stack_offset), scratch);
      stack_offset += kSimd128Size;
    }
  }
  addi(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPushF64AndV128(DoubleRegList dregs,
                                         Simd128RegList simd_regs,
                                         Register scratch1, Register scratch2,
                                         Register location) {
  MultiPushDoubles(dregs);
#if V8_ENABLE_WEBASSEMBLY
  bool generating_bultins =
      isolate() && isolate()->IsGeneratingEmbeddedBuiltins();
  if (generating_bultins) {
    // V8 uses the same set of fp param registers as Simd param registers.
    // As these registers are two different sets on ppc we must make
    // sure to also save them when Simd is enabled.
    // Check the comments under crrev.com/c/2645694 for more details.
    Label push_empty_simd, simd_pushed;
    Move(scratch1, ExternalReference::supports_wasm_simd_128_address());
    LoadU8(scratch1, MemOperand(scratch1), scratch2);
    cmpi(scratch1, Operand::Zero());  // If > 0 then simd is available.
    ble(&push_empty_simd);
    MultiPushV128(simd_regs, scratch1);
    b(&simd_pushed);
    bind(&push_empty_simd);
    // We still need to allocate empty space on the stack even if we
    // are not pushing Simd registers (see kFixedFrameSizeFromFp).
    addi(sp, sp,
         Operand(-static_cast<int8_t>(simd_regs.Count()) * kSimd128Size));
    bind(&simd_pushed);
  } else {
    if (CpuFeatures::SupportsWasmSimd128()) {
      MultiPushV128(simd_regs, scratch1);
    } else {
      addi(sp, sp,
           Operand(-static_cast<int8_t>(simd_regs.Count()) * kSimd128Size));
    }
  }
#endif
}

void MacroAssembler::MultiPopF64AndV128(DoubleRegList dregs,
                                        Simd128RegList simd_regs,
                                        Register scratch1, Register scratch2,
                                        Register location) {
#if V8_ENABLE_WEBASSEMBLY
  bool generating_bultins =
      isolate() && isolate()->IsGeneratingEmbeddedBuiltins();
  if (generating_bultins) {
    Label pop_empty_simd, simd_popped;
    Move(scratch1, ExternalReference::supports_wasm_simd_128_address());
    LoadU8(scratch1, MemOperand(scratch1), scratch2);
    cmpi(scratch1, Operand::Zero());  // If > 0 then simd is available.
    ble(&pop_empty_simd);
    MultiPopV128(simd_regs, scratch1);
    b(&simd_popped);
    bind(&pop_empty_simd);
    addi(sp, sp,
         Operand(static_cast<int8_t>(simd_regs.Count()) * kSimd128Size));
    bind(&simd_popped);
  } else {
    if (CpuFeatures::SupportsWasmSimd128()) {
      MultiPopV128(simd_regs, scratch1);
    } else {
      addi(sp, sp,
           Operand(static_cast<int8_t>(simd_regs.Count()) * kSimd128Size));
    }
  }
#endif
  MultiPopDoubles(dregs);
}

void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (CanBeImmediate(index)) {
    mov(destination, Operand(ReadOnlyRootPtr(index), RelocInfo::Mode::NO_INFO));
    return;
  }
  LoadRoot(destination, index);
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index,
                              Condition cond) {
  DCHECK(cond == al);
  if (CanBeImmediate(index)) {
    DecompressTagged(destination, ReadOnlyRootPtr(index));
    return;
  }
  LoadU64(destination,
          MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)), r0);
}

void MacroAssembler::LoadTaggedField(const Register& destination,
                                     const MemOperand& field_operand,
                                     const Register& scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand);
  } else {
    LoadU64(destination, field_operand, scratch);
  }
}

void MacroAssembler::SmiUntag(Register dst, const MemOperand& src, RCBit rc,
                              Register scratch) {
  if (SmiValuesAre31Bits()) {
    LoadU32(dst, src, scratch);
  } else {
    LoadU64(dst, src, scratch);
  }

  SmiUntag(dst, rc);
}

void MacroAssembler::StoreTaggedField(const Register& value,
                                      const MemOperand& dst_field_operand,
                                      const Register& scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    RecordComment("[ StoreTagged");
    StoreU32(value, dst_field_operand, scratch);
    RecordComment("]");
  } else {
    StoreU64(value, dst_field_operand, scratch);
  }
}

void MacroAssembler::DecompressTaggedSigned(Register destination,
                                            Register src) {
  RecordComment("[ DecompressTaggedSigned");
  ZeroExtWord32(destination, src);
  RecordComment("]");
}

void MacroAssembler::DecompressTaggedSigned(Register destination,
                                            MemOperand field_operand) {
  RecordComment("[ DecompressTaggedSigned");
  LoadU32(destination, field_operand, r0);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(Register destination, Register source) {
  RecordComment("[ DecompressTagged");
  ZeroExtWord32(destination, source);
  add(destination, destination, kPtrComprCageBaseRegister);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(Register destination,
                                      MemOperand field_operand) {
  RecordComment("[ DecompressTagged");
  LoadU32(destination, field_operand, r0);
  add(destination, destination, kPtrComprCageBaseRegister);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  AddS64(destination, kPtrComprCageBaseRegister,
         Operand(immediate, RelocInfo::Mode::NO_INFO));
}

void MacroAssembler::LoadTaggedSignedField(Register destination,
                                           MemOperand field_operand,
                                           Register scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destination, field_operand);
  } else {
    LoadU64(destination, field_operand, scratch);
  }
}

void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, Register slot_address,
                                      LinkRegisterStatus lr_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check, SlotDescriptor slot) {
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so so offset must be a multiple of kSystemPointerSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  AddS64(slot_address, object, Operand(offset - kHeapObjectTag), r0);
  if (v8_flags.debug_code) {
    Label ok;
    andi(r0, slot_address, Operand(kTaggedSize - 1));
    beq(&ok, cr0);
    stop();
    bind(&ok);
  }

  RecordWrite(object, slot_address, value, lr_status, save_fp, SmiCheck::kOmit,
              slot);

  bind(&done);

  // Clobber clobbered input registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(value, Operand(base::bit_cast<intptr_t>(kZapValue + 4)));
    mov(slot_address, Operand(base::bit_cast<intptr_t>(kZapValue + 8)));
  }
}

void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  ShiftRightU64(value, value, Operand(kSandboxedPointerShift));
  AddS64(value, value, kPtrComprCageBaseRegister);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadSandboxedPointerField(Register destination,
                                               const MemOperand& field_operand,
                                               Register scratch) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  LoadU64(destination, field_operand, scratch);
  DecodeSandboxedPointer(destination);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::StoreSandboxedPointerField(
    Register value, const MemOperand& dst_field_operand, Register scratch) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  UseScratchRegisterScope temps(this);
  Register scratch2 = temps.Acquire();
  DCHECK(!AreAliased(scratch, scratch2));
  SubS64(scratch2, value, kPtrComprCageBaseRegister);
  ShiftLeftU64(scratch2, scratch2, Operand(kSandboxedPointerShift));
  StoreU64(scratch2, dst_field_operand, scratch);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadExternalPointerField(Register destination,
                                              MemOperand field_operand,
                                              ExternalPointerTag tag,
                                              Register isolate_root,
                                              Register scratch) {
  DCHECK(!AreAliased(destination, isolate_root));
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  DCHECK(!IsSharedExternalPointerType(tag));
  UseScratchRegisterScope temps(this);
  Register external_table = temps.Acquire();
  DCHECK(!AreAliased(scratch, external_table));
  if (isolate_root == no_reg) {
    DCHECK(root_array_available_);
    isolate_root = kRootRegister;
  }
  LoadU64(external_table,
          MemOperand(isolate_root,
                     IsolateData::external_pointer_table_offset() +
                         Internals::kExternalPointerTableBasePointerOffset),
          scratch);
  LoadU32(destination, field_operand, scratch);
  ShiftRightU64(destination, destination, Operand(kExternalPointerIndexShift));
  ShiftLeftU64(destination, destination,
               Operand(kExternalPointerTableEntrySizeLog2));
  LoadU64(destination, MemOperand(external_table, destination), scratch);
  mov(scratch, Operand(~tag));
  AndU64(destination, destination, scratch);
#else
  LoadU64(destination, field_operand, scratch);
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::LoadTrustedPointerField(Register destination,
                                             MemOperand field_operand,
                                             IndirectPointerTag tag,
                                             Register scratch) {
#ifdef V8_ENABLE_SANDBOX
  LoadIndirectPointerField(destination, field_operand, tag, scratch);
#else
  LoadTaggedField(destination, field_operand, scratch);
#endif
}

void MacroAssembler::StoreTrustedPointerField(Register value,
                                              MemOperand dst_field_operand,
                                              Register scratch) {
#ifdef V8_ENABLE_SANDBOX
  StoreIndirectPointerField(value, dst_field_operand, scratch);
#else
  StoreTaggedField(value, dst_field_operand, scratch);
#endif
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
    CompareInstanceTypeRange(scratch, scratch, r0, FIRST_JS_RECEIVER_TYPE,
                             LAST_JS_RECEIVER_TYPE);
    ble(&ok);
    LoadMap(scratch, heap_object);
    CompareInstanceTypeRange(scratch, scratch, r0,
                             FIRST_PRIMITIVE_HEAP_OBJECT_TYPE,
                             LAST_PRIMITIVE_HEAP_OBJECT_TYPE);
    ble(&ok);
    Abort(AbortReason::kInvalidReceiver);
    bind(&ok);
#endif  // DEBUG

    // All primitive object's maps are allocated at the start of the read only
    // heap. Thus JS_RECEIVER's must have maps with larger (compressed)
    // addresses.
    UseScratchRegisterScope temps(this);
    Register scratch2 = temps.Acquire();
    DCHECK(!AreAliased(scratch2, scratch));
    LoadCompressedMap(scratch, heap_object, scratch2);
    mov(scratch2, Operand(InstanceTypeChecker::kNonJsReceiverMapLimit));
    CompareTagged(scratch, scratch2);
  } else {
    static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
    CompareObjectType(heap_object, scratch, scratch, FIRST_JS_RECEIVER_TYPE);
  }
  b(to_condition(cc), target);
}

void MacroAssembler::LoadIndirectPointerField(Register destination,
                                              MemOperand field_operand,
                                              IndirectPointerTag tag,
                                              Register scratch) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  Register handle = scratch;
  DCHECK(!AreAliased(handle, destination));
  LoadU32(handle, field_operand, scratch);
  ResolveIndirectPointerHandle(destination, handle, tag, scratch);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreIndirectPointerField(Register value,
                                               MemOperand dst_field_operand,
                                               Register scratch) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch2 = temps.Acquire();
  DCHECK(!AreAliased(scratch, scratch2));
  LoadU32(
      scratch2,
      FieldMemOperand(value, ExposedTrustedObject::kSelfIndirectPointerOffset),
      scratch);
  StoreU32(scratch2, dst_field_operand, scratch);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

#ifdef V8_ENABLE_SANDBOX
void MacroAssembler::ResolveIndirectPointerHandle(Register destination,
                                                  Register handle,
                                                  IndirectPointerTag tag,
                                                  Register scratch) {
  // Pointer resolution will fail in several paths if handle == ra
  DCHECK(!AreAliased(handle, r0));

  // The tag implies which pointer table to use.
  if (tag == kUnknownIndirectPointerTag) {
    // In this case we have to rely on the handle marking to determine which
    // pointer table to use.
    Label is_trusted_pointer_handle, done;
    mov(scratch, Operand(kCodePointerHandleMarke
```
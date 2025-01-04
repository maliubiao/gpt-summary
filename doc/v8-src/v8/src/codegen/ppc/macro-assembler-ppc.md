Response: The user wants a summary of the functionality of the C++ code provided in the file `v8/src/codegen/ppc/macro-assembler-ppc.cc`. The code is part of the V8 JavaScript engine and deals with code generation for the PowerPC 64-bit architecture.

Here's a breakdown of how to approach this:

1. **Identify Key Areas:** Scan the code for major functionalities and concepts. Look for keywords and function names that hint at the purpose of different code blocks. Keywords like `MacroAssembler`, `Jump`, `Call`, `Push`, `Pop`, `Load`, `Store`, `Register`, `StackFrame`, `Builtin`, `RecordWrite`, and comments will be helpful.

2. **Group Related Functionality:**  Group the identified areas into logical categories. For example, instructions related to function calls, stack manipulation, memory access, and interactions with the JavaScript runtime.

3. **Summarize Each Category:**  Briefly describe the purpose of each category. Focus on what the code is *doing* rather than the specific implementation details.

4. **Relate to JavaScript (if applicable):**  If a category has a direct connection to JavaScript features, provide a simple JavaScript example to illustrate the relationship. Think about how low-level assembly operations relate to high-level JavaScript concepts.

5. **Note the "Part 1 of 4" instruction:**  Acknowledge that this is only the first part and that the overall functionality may be broader.

**Mental Walkthrough of the Code:**

* **Includes:** The code includes various V8 headers, indicating it's a core part of the engine.
* **`MacroAssembler` Class:** This is the central class, responsible for generating machine code instructions.
* **Stack Management:**  Functions like `PushCallerSaved`, `PopCallerSaved`, `RequiredStackSizeForCallerSaved`, `Push`, `Pop`, `Drop` deal with managing the call stack, saving and restoring registers.
* **Control Flow:**  Functions like `Jump`, `Call`, `TailCallBuiltin` handle branching and calling other code sections.
* **Memory Access:**  Functions like `LoadFromConstantsTable`, `LoadRootRelative`, `StoreRootRelative`, `LoadTaggedField`, `StoreTaggedField` are about loading and storing data in memory, often interacting with V8's object model (tagged pointers).
* **External References:** The code interacts with external C++ functions and data through `ExternalReference`.
* **Builtins:** There are specific functions for calling and tail-calling built-in JavaScript functions.
* **Object Model Interaction:** Functions like `RecordWriteField` deal with writing to object properties and triggering write barriers (for garbage collection).
* **Frame Management:**  Functions like `PushCommonFrame`, `PushStandardFrame`, `EnterFrame`, `LeaveFrame`, `EnterExitFrame`, `LeaveExitFrame` are involved in setting up and tearing down call frames.
* **Type Checking:**  Functions like `IsObjectType` and related checks are used for verifying the type of JavaScript objects.
* **Floating-Point Operations:** Functions like `CanonicalizeNaN`, `ConvertIntToDouble`, `ConvertDoubleToInt64` handle conversions between different number representations.
* **Debugging:** The `CheckDebugHook` function suggests integration with debugging tools.

By grouping these observations and summarizing, we can arrive at a functional description of the code. The JavaScript examples should connect the low-level assembly operations to familiar JavaScript constructs.
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
                               
Prompt: 
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
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
    mov(scratch, Operand(kCodePointerHandleMarker));
    AndU64(scratch, handle, scratch, SetRC);
    beq(&is_trusted_pointer_handle, cr0);
    ResolveCodePointerHandle(destination, handle, scratch);
    b(&done);
    bind(&is_trusted_pointer_handle);
    ResolveTrustedPointerHandle(destination, handle, kUnknownIndirectPointerTag,
                                scratch);
    bind(&done);
  } else if (tag == kCodeIndirectPointerTag) {
    ResolveCodePointerHandle(destination, handle, scratch);
  } else {
    ResolveTrustedPointerHandle(destination, handle, tag, scratch);
  }
}

void MacroAssembler::ResolveTrustedPointerHandle(Register destination,
                                                 Register handle,
                                                 IndirectPointerTag tag,
                                                 Register scratch) {
  DCHECK_NE(tag, kCodeIndirectPointerTag);
  DCHECK(!AreAliased(handle, destination));

  CHECK(root_array_available_);
  Register table = destination;
  Move(table, ExternalReference::trusted_pointer_table_base_address(isolate()));
  ShiftRightU64(handle, handle, Operand(kTrustedPointerHandleShift));
  ShiftLeftU64(handle, handle, Operand(kTrustedPointerTableEntrySizeLog2));
  LoadU64(destination, MemOperand(table, handle), scratch);
  // The LSB is used as marking bit by the trusted pointer table, so here we
  // have to set it using a bitwise OR as it may or may not be set.
  mov(handle, Operand(kHeapObjectTag));
  OrU64(destination, destination, handle);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle,
                                              Register scratch) {
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  Move(table, ExternalReference::code_pointer_table_address());
  ShiftRightU64(handle, handle, Operand(kCodePointerHandleShift));
  ShiftLeftU64(handle, handle, Operand(kCodePointerTableEntrySizeLog2));
  AddS64(handle, table, handle);
  LoadU64(destination,
          MemOperand(handle, kCodePointerTableEntryCodeObjectOffset), scratch);
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  mov(handle, Operand(kHeapObjectTag));
  OrU64(destination, destination, handle);
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      MemOperand field_operand,
                                                      Register scratch) {
  ASM_CODE_COMMENT(this);

  // Due to register pressure, table is also used as a scratch register
  DCHECK(destination != r0);
  Register table = scratch;
  LoadU32(destination, field_operand, scratch);
  Move(table, ExternalReference::code_pointer_table_address());
  // TODO(tpearson): can the offset computation be done more efficiently?
  ShiftRightU64(destination, destination, Operand(kCodePointerHandleShift));
  ShiftLeftU64(destination, destination,
               Operand(kCodePointerTableEntrySizeLog2));
  LoadU64(destination, MemOperand(destination, table));
}
#endif  // V8_ENABLE_SANDBOX

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object,
                                             Register slot_address,
                                             SaveFPRegsMode fp_mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  // TODO(tpearson): The following is equivalent to
  // MovePair(slot_address_parameter, slot_address, object_parameter, object);
  // Implement with MoveObjectAndSlot()
  push(object);
  push(slot_address);
  pop(slot_address_parameter);
  pop(object_parameter);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallIndirectPointerBarrier(Register object,
                                                Register slot_address,
                                                SaveFPRegsMode fp_mode,
                                                IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      IndirectPointerWriteBarrierDescriptor::ComputeSavedRegisters(
          object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter =
      IndirectPointerWriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      IndirectPointerWriteBarrierDescriptor::SlotAddressRegister();
  Register tag_parameter =
      IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister();
  DCHECK(!AreAliased(object_parameter, slot_address_parameter, tag_parameter));

  // TODO(tpearson): The following is equivalent to
  // MovePair(slot_address_parameter, slot_address, object_parameter, object);
  // Implement with MoveObjectAndSlot()
  push(object);
  push(slot_address);
  pop(slot_address_parameter);
  pop(object_parameter);

  mov(tag_parameter, Operand(tag));

  CallBuiltin(Builtins::IndirectPointerBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Register slot_address,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
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
  // Use CallRecordWriteStubSaveRegisters if the object and slot registers
  // need to be caller saved.
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    // Use {near_call} for direct Wasm call within a module.
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    Call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode), al);
  }
}

// Will clobber 4 registers: object, address, scratch, ip.  The
// register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Register slot_address,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check,
                                 SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, value, slot_address));
  if (v8_flags.debug_code) {
    Register value_check = r0;
    // TODO(tpearson): Figure out why ScratchRegisterScope returns a
    // register that is aliased with one of our other in-use registers
    // For now, use r11 (kScratchReg in the code generator)
    Register scratch = r11;
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    DCHECK(!AreAliased(object, value, value_check, scratch));
    if (slot.contains_indirect_pointer()) {
      LoadIndirectPointerField(value_check, MemOperand(slot_address),
                               slot.indirect_pointer_tag(), scratch);
    } else {
      DCHECK(slot.contains_direct_pointer());
      LoadTaggedField(value_check, MemOperand(slot_address));
    }
    CmpS64(value_check, value);
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

  CheckPageFlag(value,
                value,  // Used as scratch.
                MemoryChunk::kPointersToHereAreInterestingMask, eq, &done);
  CheckPageFlag(object,
                value,  // Used as scratch.
                MemoryChunk::kPointersFromHereAreInterestingMask, eq, &done);

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    mflr(r0);
    push(r0);
  }
  if (slot.contains_direct_pointer()) {
    CallRecordWriteStubSaveRegisters(object, slot_address, fp_mode,
                                     StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, slot_address, fp_mode,
                               slot.indirect_pointer_tag());
  }
  if (lr_status == kLRHasNotBeenSaved) {
    pop(r0);
    mtlr(r0);
  }

  if (v8_flags.debug_code) mov(slot_address, Operand(kZapValue));

  bind(&done);

  // Clobber clobbered registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(slot_address, Operand(base::bit_cast<intptr_t>(kZapValue + 12)));
    mov(value, Operand(base::bit_cast<intptr_t>(kZapValue + 16)));
  }
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  int fp_delta = 0;
  mflr(r0);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    if (marker_reg.is_valid()) {
      Push(r0, fp, kConstantPoolRegister, marker_reg);
      fp_delta = 2;
    } else {
      Push(r0, fp, kConstantPoolRegister);
      fp_delta = 1;
    }
  } else {
    if (marker_reg.is_valid()) {
      Push(r0, fp, marker_reg);
      fp_delta = 1;
    } else {
      Push(r0, fp);
      fp_delta = 0;
    }
  }
  addi(fp, sp, Operand(fp_delta * kSystemPointerSize));
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int fp_delta = 0;
  mflr(r0);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    if (function_reg.is_valid()) {
      Push(r0, fp, kConstantPoolRegister, cp, function_reg);
      fp_delta = 3;
    } else {
      Push(r0, fp, kConstantPoolRegister, cp);
      fp_delta = 2;
    }
  } else {
    if (function_reg.is_valid()) {
      Push(r0, fp, cp, function_reg);
      fp_delta = 2;
    } else {
      Push(r0, fp, cp);
      fp_delta = 1;
    }
  }
  addi(fp, sp, Operand(fp_delta * kSystemPointerSize));
  Push(kJavaScriptCallArgCountRegister);
}

void MacroAssembler::RestoreFrameStateForTailCall() {
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    LoadU64(kConstantPoolRegister,
            MemOperand(fp, StandardFrameConstants::kConstantPoolOffset));
    set_constant_pool_available(false);
  }
  LoadU64(r0, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  LoadU64(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  mtlr(r0);
}

void MacroAssembler::CanonicalizeNaN(const DoubleRegister dst,
                                     const DoubleRegister src) {
  // Turn potential sNaN into qNaN.
  fsub(dst, src, kDoubleRegZero);
}

void MacroAssembler::ConvertIntToDouble(Register src, DoubleRegister dst) {
  MovIntToDouble(dst, src, r0);
  fcfid(dst, dst);
}

void MacroAssembler::ConvertUnsignedIntToDouble(Register src,
                                                DoubleRegister dst) {
  MovUnsignedIntToDouble(dst, src, r0);
  fcfid(dst, dst);
}

void MacroAssembler::ConvertIntToFloat(Register src, DoubleRegister dst) {
  MovIntToDouble(dst, src, r0);
  fcfids(dst, dst);
}

void MacroAssembler::ConvertUnsignedIntToFloat(Register src,
                                               DoubleRegister dst) {
  MovUnsignedIntToDouble(dst, src, r0);
  fcfids(dst, dst);
}

void MacroAssembler::ConvertInt64ToDouble(Register src,
                                          DoubleRegister double_dst) {
  MovInt64ToDouble(double_dst, src);
  fcfid(double_dst, double_dst);
}

void MacroAssembler::ConvertUnsignedInt64ToFloat(Register src,
                                                 DoubleRegister double_dst) {
  MovInt64ToDouble(double_dst, src);
  fcfidus(double_dst, double_dst);
}

void MacroAssembler::ConvertUnsignedInt64ToDouble(Register src,
                                                  DoubleRegister double_dst) {
  MovInt64ToDouble(double_dst, src);
  fcfidu(double_dst, double_dst);
}

void MacroAssembler::ConvertInt64ToFloat(Register src,
                                         DoubleRegister double_dst) {
  MovInt64ToDouble(double_dst, src);
  fcfids(double_dst, double_dst);
}

void MacroAssembler::ConvertDoubleToInt64(const DoubleRegister double_input,
                                          const Register dst,
                                          const DoubleRegister double_dst,
                                          FPRoundingMode rounding_mode) {
  if (rounding_mode == kRoundToZero) {
    fctidz(double_dst, double_input);
  } else {
    SetRoundingMode(rounding_mode);
    fctid(double_dst, double_input);
    ResetRoundingMode();
  }

  MovDoubleToInt64(
      dst, double_dst);
}

void MacroAssembler::ConvertDoubleToUnsignedInt64(
    const DoubleRegister double_input, const Register dst,
    const DoubleRegister double_dst, FPRoundingMode rounding_mode) {
  if (rounding_mode == kRoundToZero) {
    fctiduz(double_dst, double_input);
  } else {
    SetRoundingMode(rounding_mode);
    fctidu(double_dst, double_input);
    ResetRoundingMode();
  }

  MovDoubleToInt64(dst, double_dst);
}

void MacroAssembler::LoadConstantPoolPointerRegisterFromCodeTargetAddress(
    Register code_target_address, Register scratch1, Register scratch2) {
  // Builtins do not use the constant pool (see is_constant_pool_available).
  static_assert(InstructionStream::kOnHeapBodyIsContiguous);

#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      scratch2,
      FieldMemOperand(code_target_address, Code::kSelfIndirectPointerOffset),
      scratch1);
#else
  LoadU64(scratch2,
          FieldMemOperand(code_target_address, Code::kInstructionStartOffset),
          scratch1);
#endif
  LoadU32(scratch1,
          FieldMemOperand(code_target_address, Code::kInstructionSizeOffset),
          scratch1);
  add(scratch2, scratch1, scratch2);
  LoadU32(kConstantPoolRegister,
          FieldMemOperand(code_target_address, Code::kConstantPoolOffsetOffset),
          scratch1);
  add(kConstantPoolRegister, scratch2, kConstantPoolRegister);
}

void MacroAssembler::LoadPC(Register dst) {
  b(4, SetLK);
  mflr(dst);
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  mflr(r0);
  LoadPC(dst);
  subi(dst, dst, Operand(pc_offset() - kInstrSize));
  mtlr(r0);
}

void MacroAssembler::LoadConstantPoolPointerRegister() {
  //
  // Builtins do not use the constant pool (see is_constant_pool_available).
  static_assert(InstructionStream::kOnHeapBodyIsContiguous);

  LoadPC(kConstantPoolRegister);
  int32_t delta = -pc_offset() + 4;
  add_label_offset(kConstantPoolRegister, kConstantPoolRegister,
                   ConstantPoolPosition(), delta);
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  {
    ConstantPoolUnavailableScope constant_pool_unavailable(this);
    mov(r11, Operand(StackFrame::TypeToMarker(type)));
    PushCommonFrame(r11);
  }
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    LoadConstantPoolPointerRegister();
    set_constant_pool_available(true);
  }
}

void MacroAssembler::Prologue() {
  PushStandardFrame(r4);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    // base contains prologue address
    LoadConstantPoolPointerRegister();
    set_constant_pool_available(true);
  }
}

void MacroAssembler::DropArguments(Register count) {
  ShiftLeftU64(ip, count, Operand(kSystemPointerSizeLog2));
  add(sp, sp, ip);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

void MacroAssembler::EnterFrame(StackFrame::Type type,
                                bool load_constant_pool_pointer_reg) {
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL && load_constant_pool_pointer_reg) {
    // Push type explicitly so we can leverage the constant pool.
    // This path cannot rely on ip containing code entry.
    PushCommonFrame();
    LoadConstantPoolPointerRegister();
    if (!StackFrame::IsJavaScript(type)) {
      mov(ip, Operand(StackFrame::TypeToMarker(type)));
      push(ip);
    }
  } else {
    Register scratch = no_reg;
    if (!StackFrame::IsJavaScript(type)) {
      scratch = ip;
      mov(scratch, Operand(StackFrame::TypeToMarker(type)));
    }
    PushCommonFrame(scratch);
  }
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM) Push(kWasmImplicitArgRegister);
#endif  // V8_ENABLE_WEBASSEMBLY
}

int MacroAssembler::LeaveFrame(StackFrame::Type type, int stack_adjustment) {
  ConstantPoolUnavailableScope constant_pool_unavailable(this);
  // r3: preserved
  // r4: preserved
  // r5: preserved

  // Drop the execution stack down to the frame pointer and restore
  // the caller's state.
  int frame_ends;
  LoadU64(r0, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  LoadU64(ip, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    LoadU64(kConstantPoolRegister,
            MemOperand(fp, StandardFrameConstants::kConstantPoolOffset));
  }
  mtlr(r0);
  frame_ends = pc_offset();
  AddS64(sp, fp,
         Operand(StandardFrameConstants::kCallerSPOffset + stack_adjustment),
         r0);
  mr(fp, ip);
  return frame_ends;
}

// ExitFrame layout (probably wrongish.. needs updating)
//
//  SP -> previousSP
//        LK reserved
//        sp_on_exit (for debug?)
// oldSP->prev SP
//        LK
//        <parameters on stack>

// Prior to calling EnterExitFrame, we've got a bunch of parameters
// on the stack that we need to wrap a real frame around.. so first
// we reserve a slot for LK and push the previous SP which is captured
// in the fp register (r31)
// Then - we buy a new frame

void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  using ER = ExternalReference;

  // Set up the frame structure on the stack.
  DCHECK_EQ(2 * kSystemPointerSize, ExitFrameConstants::kCallerSPDisplacement);
  DCHECK_EQ(1 * kSystemPointerSize, ExitFrameConstants::kCallerPCOffset);
  DCHECK_EQ(0 * kSystemPointerSize, ExitFrameConstants::kCallerFPOffset);

  // This is an opportunity to build a frame to wrap
  // all of the pushes that have happened inside of V8
  // since we were called from C code

  mov(ip, Operand(StackFrame::TypeToMarker(frame_type)));
  PushCommonFrame(ip);
  // Reserve room for saved entry sp.
  subi(sp, fp, Operand(ExitFrameConstants::kFixedFrameSizeFromFp));

  if (v8_flags.debug_code) {
    li(r8, Operand::Zero());
    StoreU64(r8, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    StoreU64(kConstantPoolRegister,
             MemOperand(fp, ExitFrameConstants::kConstantPoolOffset));
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  StoreU64(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  StoreU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

  AddS64(sp, sp, Operand(-(stack_space + 1) * kSystemPointerSize));

  // Allocate and align the frame preparing for calling the runtime
  // function.
  const int frame_alignment = ActivationFrameAlignment();
  if (frame_alignment > kSystemPointerSize) {
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    ClearRightImm(sp, sp,
                  Operand(base::bits::WhichPowerOfTwo(frame_alignment)));
  }
  li(r0, Operand::Zero());
  StoreU64WithUpdate(
      r0, MemOperand(sp, -kNumRequiredStackFrameSlots * kSystemPointerSize));

  // Set the exit frame sp value to point just before the return address
  // location.
  AddS64(r8, sp, Operand((kStackFrameExtraParamSlot + 1) * kSystemPointerSize),
         r0);
  StoreU64(r8, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

int MacroAssembler::ActivationFrameAlignment() {
#if !defined(USE_SIMULATOR)
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one PPC
  // platform for another PPC platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else  // Simulated
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ConstantPoolUnavailableScope constant_pool_unavailable(this);

  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  LoadU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

#ifdef DEBUG
  mov(scratch, Operand(Context::kInvalidContext));
  StoreU64(scratch, ExternalReferenceAsOperand(context_address, no_reg));
#endif

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  mov(scratch, Operand::Zero());
  StoreU64(scratch, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Tear down the exit frame, pop the arguments, and return.
  LeaveFrame(StackFrame::EXIT);
}

void MacroAssembler::MovFromFloatResult(const DoubleRegister dst) {
  Move(dst, d1);
}

void MacroAssembler::MovFromFloatParameter(const DoubleRegister dst) {
  Move(dst, d1);
}

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind,
                                    Register scratch) {
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();
  CHECK(is_int32(offset));
  LoadU64(destination, MemOperand(kRootRegister, offset), scratch);
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch,
                                        Label* stack_overflow) {
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  LoadStackLimit(scratch, StackLimitKind::kRealStackLimit, r0);
  // Make scratch the space we have left. The stack might already be overflowed
  // here which will cause scratch to become negative.
  sub(scratch, sp, scratch);
  // Check if the arguments will overflow the stack.
  ShiftLeftU64(r0, num_args, Operand(kSystemPointerSizeLog2));
  CmpS64(scratch, r0);
  ble(stack_overflow);  // Signed comparison.
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  Label regular_invoke;

  //  r3: actual arguments count
  //  r4: function (passed through to callee)
  //  r5: expected arguments count

  DCHECK_EQ(actual_parameter_count, r3);
  DCHECK_EQ(expected_parameter_count, r5);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  sub(expected_parameter_count, expected_parameter_count,
      actual_parameter_count, LeaveOE, SetRC);
  ble(&regular_invoke, cr0);

  Label stack_overflow;
  Register scratch = r7;
  StackOverflowCheck(expected_parameter_count, scratch, &stack_overflow);

  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy, skip;
    Register src = r9, dest = r8;
    addi(src, sp, Operand(-kSystemPointerSize));
    ShiftLeftU64(r0, expected_parameter_count, Operand(kSystemPointerSizeLog2));
    sub(sp, sp, r0);
    // Update stack pointer.
    addi(dest, sp, Operand(-kSystemPointerSize));
    mr(r0, actual_parameter_count);
    cmpi(r0, Operand::Zero());
    ble(&skip);
    mtctr(r0);

    bind(&copy);
    LoadU64WithUpdate(r0, MemOperand(src, kSystemPointerSize));
    StoreU64WithUpdate(r0, MemOperand(dest, kSystemPointerSize));
    bdnz(&copy);
    bind(&skip);
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(scratch, RootIndex::kUndefinedValue);
  {
    mtctr(expected_parameter_count);

    Label loop;
    bind(&loop);
    StoreU64WithUpdate(scratch, MemOperand(r8, kSystemPointerSize));
    bdnz(&loop);
  }
  b(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    bkpt(0);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CheckDebugHook(Register fun, Register new_target,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count) {
  Label skip_hook;

  ExternalReference debug_hook_active =
      ExternalReference::debug_hook_on_function_call_address(isolate());
  Move(r7, debug_hook_active);
  LoadU8(r7, MemOperand(r7), r0);
  extsb(r7, r7);
  CmpSmiLiteral(r7, Smi::zero(), r0);
  beq(&skip_hook);

  {
    // Load receiver to pass it later to DebugOnFunctionCall hook.
    LoadReceiver(r7);
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

    SmiTag(expected_parameter_count);
    Push(expected_parameter_count);

    SmiTag(actual_parameter_count);
    Push(actual_parameter_count);

    if (new_target.is_valid()) {
      Push(new_target);
    }
    Push(fun, fun, r7);
    CallRuntime(Runtime::kDebugOnFunctionCall);
    Pop(fun);
    if (new_target.is_valid()) {
      Pop(new_target);
    }

    Pop(actual_parameter_count);
    SmiUntag(actual_parameter_count);

    Pop(expected_parameter_count);
    SmiUntag(expected_parameter_count);
  }
  bind(&skip_hook);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, r4);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == r6);

  // On function call, call into the debugger if necessary.
  CheckDebugHook(function, new_target, expected_parameter_count,
                 actual_parameter_count);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(r6, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count, r0);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function, r0);
      break;
  }

    // Continue here if InvokePrologue does handle the invocation due to
    // mismatched parameter counts.
    bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register fun, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r4.
  DCHECK_EQ(fun, r4);

  Register expected_reg = r5;
  Register temp_reg = r7;

  LoadTaggedField(
      temp_reg, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset), r0);
  LoadTaggedField(cp, FieldMemOperand(r4, JSFunction::kContextOffset), r0);
  LoadU16(expected_reg,
          FieldMemOperand(temp_reg,
                          SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(fun, new_target, expected_reg, actual_parameter_count,
                     type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r4.
  DCHECK_EQ(function, r4);

  // Get the function and setup the context.
  LoadTaggedField(cp, FieldMemOperand(r4, JSFunction::kContextOffset), r0);

  InvokeFunctionCode(r4, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize);

  Push(Smi::zero());  // Padding.

  // Link the current handler as the next handler.
  // Preserve r4-r8.
  Move(r3,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  LoadU64(r0, MemOperand(r3));
  push(r0);

  // Set this new handler as the current one.
  StoreU64(sp, MemOperand(r3));
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0);

  pop(r4);
  Move(ip,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  StoreU64(r4, MemOperand(ip));

  Drop(1);  // Drop padding.
}

#if V8_STATIC_ROOTS_BOOL
void MacroAssembler::CompareInstanceTypeWithUniqueCompressedMap(
    Register map, Register scratch, InstanceType type) {
  std::optional<RootIndex> expected =
      InstanceTypeChecker::UniqueMapOfInstanceType(type);
  CHECK(expected);
  Tagged_t expected_ptr = ReadOnlyRootPtr(*expected);
  DCHECK_NE(map, scratch);
  UseScratchRegisterScope temps(this);
  CHECK(scratch != Register::no_reg() || temps.CanAcquire());
  if (scratch == Register::no_reg()) {
    // TODO(tpearson): Figure out why ScratchRegisterScope returns a
    // register that is aliased with one of our other in-use registers
    // For now, use r11 (kScratchReg in the code generator)
    scratch = r11;
    DCHECK_NE(map, scratch);
  }
  mov(scratch, Operand(expected_ptr));
  CompareTagged(map, scratch);
}

void MacroAssembler::IsObjectTypeFast(Register object,
                                      Register compressed_map_scratch,
                                      InstanceType type, Register scratch) {
  ASM_CODE_COMMENT(this);
  CHECK(InstanceTypeChecker::UniqueMapOfInstanceType(type));
  LoadCompressedMap(compressed_map_scratch, object, scratch);
  CompareInstanceTypeWithUniqueCompressedMap(compressed_map_scratch,
                                             Register::no_reg(), type);
}
#endif  // V8_STATIC_ROOTS_BOOL

// Sets equality condition flags.
void MacroAssembler::IsObjectType(Register object, Register scratch1,
                                  Register scratch2,
"""


```
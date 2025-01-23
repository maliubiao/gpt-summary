Response:
My thinking process to analyze the provided V8 code snippet goes like this:

1. **Identify the file's purpose:** The file name `macro-assembler-s390.cc` and the directory `v8/src/codegen/s390/` immediately tell me this code is part of V8's code generation for the s390 architecture. The "macro-assembler" part suggests it provides higher-level abstractions over the basic assembly instructions.

2. **Scan for key functionalities:** I quickly skim the code, looking for function definitions and common programming patterns. I notice functions like `DoubleMax`, `DoubleMin`, `FloatMax`, `FloatMin`, `CeilF32`, `FloorF64`, etc. These clearly point to floating-point operations. I also see functions related to stack manipulation (`PushCallerSaved`, `PopCallerSaved`, `MultiPush`, `MultiPop`), loading data (`LoadFromConstantsTable`, `LoadRootRelative`), jumping and calling (`Jump`, `Call`), and data movement (`Move`, `MoveChar`).

3. **Categorize the functionalities:** Based on the initial scan, I start grouping the functionalities:
    * **Floating-point operations:**  Max, Min, Ceil, Floor, Trunc, Nearest Integer for both single and double-precision floats.
    * **Stack management:** Pushing and popping registers (general-purpose and floating-point), managing stack frame sizes.
    * **Data loading/storing:** Loading from constants table, root table, and general memory locations. Special handling for tagged values and Smi.
    * **Control flow:** Jumping and calling functions, including built-ins.
    * **Data movement:** Moving data between registers and memory, including block moves.
    * **Conditional operations:**  Using conditions in jumps and moves.
    * **Bit manipulation:** Rotate and insert bits.

4. **Look for architecture-specific details:** I note the `#if V8_TARGET_ARCH_S390X` guards, indicating this code is specific to the s390x architecture. The presence of instructions like `vfmax`, `vfmin`, `cdbr`, `ldr`, etc., confirms this. The handling of z/OS in the `Jump` function is also a key architecture-specific detail.

5. **Address specific prompt questions:**
    * **`.tq` extension:** The prompt asks if the file ends in `.tq`. I can see it ends in `.cc`, so it's a C++ file, not a Torque file.
    * **Relationship to JavaScript:** Many of the functions directly implement JavaScript's mathematical functions (like `Math.max`, `Math.min`, `Math.ceil`, etc.). The stack management is crucial for function calls in JavaScript. The loading of constants and roots is how V8 accesses internal JavaScript objects and data.
    * **JavaScript examples:**  I then formulate simple JavaScript examples to illustrate the use of the implemented functions. For example, `Math.max(1.0, 2.0)` directly relates to the `DoubleMax` function.
    * **Code logic and I/O:** I look for functions with explicit input and output based on register arguments. The `DoubleMax` and `DoubleMin` functions are good examples. I create simple hypothetical input values for the registers and predict the output.
    * **Common programming errors:**  I consider typical C++ programming errors that might occur in this context, such as incorrect register usage or stack imbalance, and relate them to the provided code.
    * **Overall functionality (summary):** Finally, I synthesize the identified functionalities into a concise summary.

6. **Refine and organize:** I review my findings and organize them logically, ensuring clarity and accuracy. I use bullet points and clear language to present the information effectively.

By following these steps, I can systematically analyze the V8 source code snippet and address all the points raised in the prompt. The key is to combine general programming knowledge with specific understanding of compiler construction and the target architecture.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>  // For assert
#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_S390X

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
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/s390/macro-assembler-s390.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

namespace {

// For WebAssembly we care about the full floating point (Simd) registers. If we
// are not running Wasm, we can get away with saving half of those (F64)
// registers.
#if V8_ENABLE_WEBASSEMBLY
constexpr int kStackSavedSavedFPSizeInBytes =
    kNumCallerSavedDoubles * kSimd128Size;
#else
constexpr int kStackSavedSavedFPSizeInBytes =
    kNumCallerSavedDoubles * kDoubleSize;
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace

void MacroAssembler::DoubleMax(DoubleRegister result_reg,
                               DoubleRegister left_reg,
                               DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmax(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(3));
    return;
  }

  Label check_zero, return_left, return_right, return_nan, done;
  cdbr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  bge(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cdbr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For max we want logical-and of sign bit: (L + R) */
  ldr(result_reg, left_reg);
  adbr(result_reg, right_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, adbr propagates the appropriate one.*/
  adbr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::DoubleMin(DoubleRegister result_reg,
                               DoubleRegister left_reg,
                               DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmin(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(3));
    return;
  }
  Label check_zero, return_left, return_right, return_nan, done;
  cdbr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  ble(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cdbr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For min we want logical-or of sign bit: -(-L + -R) */
  lcdbr(left_reg, left_reg);
  ldr(result_reg, left_reg);
  if (left_reg == right_reg) {
    adbr(result_reg, right_reg);
  } else {
    sdbr(result_reg, right_reg);
  }
  lcdbr(result_reg, result_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, adbr propagates the appropriate one.*/
  adbr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::FloatMax(DoubleRegister result_reg,
                              DoubleRegister left_reg,
                              DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmax(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(2));
    return;
  }
  Label check_zero, return_left, return_right, return_nan, done;
  cebr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  bge(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cebr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For max we want logical-and of sign bit: (L + R) */
  ldr(result_reg, left_reg);
  aebr(result_reg, right_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, aebr propagates the appropriate one.*/
  aebr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::FloatMin(DoubleRegister result_reg,
                              DoubleRegister left_reg,
                              DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmin(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(2));
    return;
  }

  Label check_zero, return_left, return_right, return_nan, done;
  cebr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  ble(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cebr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For min we want logical-or of sign bit: -(-L + -R) */
  lcebr(left_reg, left_reg);
  ldr(result_reg, left_reg);
  if (left_reg == right_reg) {
    aebr(result_reg, right_reg);
  } else {
    sebr(result_reg, right_reg);
  }
  lcebr(result_reg, result_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, aebr propagates the appropriate one.*/
  aebr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::CeilF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TOWARD_POS_INF, dst, src);
}

void MacroAssembler::CeilF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TOWARD_POS_INF, dst, src);
}

void MacroAssembler::FloorF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TOWARD_NEG_INF, dst, src);
}

void MacroAssembler::FloorF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TOWARD_NEG_INF, dst, src);
}

void MacroAssembler::TruncF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TOWARD_0, dst, src);
}

void MacroAssembler::TruncF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TOWARD_0, dst, src);
}

void MacroAssembler::NearestIntF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TO_NEAREST_TO_EVEN, dst, src);
}

void MacroAssembler::NearestIntF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TO_NEAREST_TO_EVEN, dst, src);
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
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register scratch,
                                    Register exclusion1, Register exclusion2,
                                    Register exclusion3) {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushF64OrV128(kCallerSavedDoubles, scratch);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register scratch,
                                   Register exclusion1, Register exclusion2,
                                   Register exclusion3) {
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopF64OrV128(kCallerSavedDoubles, scratch);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kSystemPointerSize;

  return bytes;
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));

  const uint32_t offset = OFFSET_OF_DATA_START(FixedArray) +
                          constant_index * kSystemPointerSize - kHeapObjectTag;

  CHECK(is_uint19(offset));
  DCHECK_NE(destination, r0);
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(destination,
                  FieldMemOperand(destination, FixedArray::OffsetOfElementAt(
                                                   constant_index)),
                  r1);
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  LoadU64(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  StoreU64(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    mov(destination, kRootRegister);
  } else if (is_uint12(offset)) {
    la(destination, MemOperand(kRootRegister, offset));
  } else {
    DCHECK(is_int20(offset));
    lay(destination, MemOperand(kRootRegister, offset));
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

void MacroAssembler::Jump(Register target, Condition cond) { b(cond, target); }

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond) {
  Label skip;

  if (cond != al) b(NegateCondition(cond), &skip);

  mov(ip, Operand(target, rmode));
  b(ip);

  bind(&skip);
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
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  jump(code, RelocInfo::RELATIVE_CODE_TARGET, cond);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
#if V8_OS_ZOS
  // Place reference into scratch r12 ip register
  Move(ip, reference);
  // z/OS uses function descriptors, extract code entry into r6
  LoadMultipleP(r5, r6, MemOperand(ip));
  // Preserve return address into r14
  mov(r14, r7);
  // Call C Function
  StoreReturnAddressAndCall(r6);
  // Branch to return address in r14
  b(r14);
#else
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, reference);
  Jump(scratch);
#endif
}

void MacroAssembler::Call(Register target) {
  // Branch to target via indirect branch
  basr(r14, target);
}

void MacroAssembler::CallJSEntry(Register target) {
  DCHECK(target == r4);
  Call(target);
}

int MacroAssembler::CallSizeNotPredictableCodeSize(Address target,
                                                   RelocInfo::Mode rmode,
                                                   Condition cond) {
  // S390 Assembler::move sequence is IILF / IIHF
  int size;
  size = 14;  // IILF + IIHF + BASR
  return size;
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(cond == al);

  mov(ip, Operand(target, rmode));
  basr(r14, ip);
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(RelocInfo::IsCodeTarget(rmode) && cond == al);

  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  call(code, rmode);
}

void MacroAssembler::CallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(ip);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect:
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
      Call(ip);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      call(code, RelocInfo::CODE_TARGET);
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
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
      Jump(ip, cond);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        jump(code, RelocInfo::RELATIVE_CODE_TARGET, cond);
      } else {
        LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
        Jump(ip, cond);
      }
      break;
    }
  }
}

void MacroAssembler::Drop(int count) {
  if (count > 0) {
    int total = count * kSystemPointerSize;
    if (is_uint12(total)) {
      la(sp, MemOperand(sp, total));
    } else if (is_int20(total)) {
      lay(sp, MemOperand(sp, total));
    } else {
      AddS64(sp, Operand(total));
    }
  }
}

void MacroAssembler::Drop(Register count, Register scratch) {
  ShiftLeftU64(scratch, count, Operand(kSystemPointerSizeLog2));
  AddS64(sp, sp, scratch);
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code,
                                                       Register scratch) {
  LoadU32(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  TestBit(scratch, Code::kMarkedForDeoptimizationBit, scratch);
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::Call(Label* target) { b(r14, target); }

void MacroAssembler::Push(Handle<HeapObject> handle) {
  mov(r0, Operand(handle));
  push(r0);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  mov(r0, Operand(smi));
  push(r0);
}

void MacroAssembler::Push(Tagged<TaggedIndex> index) {
  // TaggedIndex is the same as Smi for 32 bit archs.
  mov(r0, Operand(static_cast<uint32_t>(index.value())));
  push(r0);
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
  if (dst != src) {
    if (cond == al) {
      mov(dst, src);
    } else {
      LoadOnConditionP(cond, dst, src);
    }
  }
}

void MacroAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  if (dst != src) {
    ldr(dst, src);
  }
}

void MacroAssembler::Move(Register dst, const MemOperand& src) {
  LoadU64(dst, src);
}

// Wrapper around Assembler::mvc (SS-a format)
void MacroAssembler::MoveChar(const MemOperand& opnd1, const MemOperand& opnd2,
                              const Operand& length) {
  mvc(opnd1, opnd2, Operand(static_cast<intptr_t>(length.immediate() - 1)));
}

// Wrapper around Assembler::clc (SS-a format)
void MacroAssembler::CompareLogicalChar(const MemOperand& opnd1,
                                        const MemOperand& opnd2,
                                        const Operand& length) {
  clc(opnd1, opnd2, Operand(static_cast<intptr_t>(length.immediate() - 1)));
}

// Wrapper around Assembler::xc (SS-a format)
void MacroAssembler::ExclusiveOrChar(const MemOperand& opnd1,
                                     const MemOperand& opnd2,
                                     const Operand& length) {
  xc(opnd1, opnd2, Operand(static_cast<intptr_t>(length.immediate() - 1)));
}

// Wrapper around Assembler::risbg(n) (RIE-f)
void MacroAssembler::RotateInsertSelectBits(Register dst, Register src,
                                            const Operand& startBit,
                                            const Operand& endBit,
                                            const Operand& shiftAmt,
                                            bool zeroBits) {
  if (zeroBits)
    // High tag the top bit of I4/EndBit to zero out any unselected bits
    risbg(dst, src, startBit,
          Operand(static_cast<intptr_t>(endBit.immediate() | 0x80)), shiftAmt);
  else
    risbg(dst, src, startBit, endBit, shiftAmt);
}

void MacroAssembler::BranchRelativeOnIdxHighP(Register dst, Register inc,
                                              Label* L) {
  brxhg(dst, inc, L);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               Register scratch2, PushArrayOrder order) {
  Label loop, done;

  if (order == kNormal) {
    ShiftLeftU64(scratch, size, Operand(kSystemPointerSizeLog2));
    lay(scratch, MemOperand(array, scratch));
    bind(&loop);
    CmpS64(array, scratch);
    bge(&done);
    lay(scratch, MemOperand(scratch, -kSystemPointerSize));
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    MoveChar(MemOperand(sp), MemOperand(scratch), Operand(kSystemPointerSize));
    b(&loop);
    bind(&done);
  } else {
    DCHECK_NE(scratch2, r0);
    ShiftLeftU64(scratch, size, Operand(kSystemPointerSizeLog2));
    lay(scratch, MemOperand(array, scratch));
    mov(scratch2, array);
    bind(&loop);
    CmpS64(scratch2, scratch);
    bge(&done);
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    MoveChar(MemOperand(sp), MemOperand(scratch2), Operand(kSystemPointerSize));
    lay(scratch2, MemOperand(scratch2, kSystemPointerSize));
    b(&loop);
    bind(&done);
  }
}

void MacroAssembler::MultiPush(
### 提示词
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>  // For assert
#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_S390X

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
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/s390/macro-assembler-s390.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

namespace {

// For WebAssembly we care about the full floating point (Simd) registers. If we
// are not running Wasm, we can get away with saving half of those (F64)
// registers.
#if V8_ENABLE_WEBASSEMBLY
constexpr int kStackSavedSavedFPSizeInBytes =
    kNumCallerSavedDoubles * kSimd128Size;
#else
constexpr int kStackSavedSavedFPSizeInBytes =
    kNumCallerSavedDoubles * kDoubleSize;
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace

void MacroAssembler::DoubleMax(DoubleRegister result_reg,
                               DoubleRegister left_reg,
                               DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmax(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(3));
    return;
  }

  Label check_zero, return_left, return_right, return_nan, done;
  cdbr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  bge(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cdbr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For max we want logical-and of sign bit: (L + R) */
  ldr(result_reg, left_reg);
  adbr(result_reg, right_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, adbr propagates the appropriate one.*/
  adbr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::DoubleMin(DoubleRegister result_reg,
                               DoubleRegister left_reg,
                               DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmin(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(3));
    return;
  }
  Label check_zero, return_left, return_right, return_nan, done;
  cdbr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  ble(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cdbr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For min we want logical-or of sign bit: -(-L + -R) */
  lcdbr(left_reg, left_reg);
  ldr(result_reg, left_reg);
  if (left_reg == right_reg) {
    adbr(result_reg, right_reg);
  } else {
    sdbr(result_reg, right_reg);
  }
  lcdbr(result_reg, result_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, adbr propagates the appropriate one.*/
  adbr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::FloatMax(DoubleRegister result_reg,
                              DoubleRegister left_reg,
                              DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmax(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(2));
    return;
  }
  Label check_zero, return_left, return_right, return_nan, done;
  cebr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  bge(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cebr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For max we want logical-and of sign bit: (L + R) */
  ldr(result_reg, left_reg);
  aebr(result_reg, right_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, aebr propagates the appropriate one.*/
  aebr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::FloatMin(DoubleRegister result_reg,
                              DoubleRegister left_reg,
                              DoubleRegister right_reg) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_1)) {
    vfmin(result_reg, left_reg, right_reg, Condition(1), Condition(8),
          Condition(2));
    return;
  }

  Label check_zero, return_left, return_right, return_nan, done;
  cebr(left_reg, right_reg);
  bunordered(&return_nan, Label::kNear);
  beq(&check_zero);
  ble(&return_left, Label::kNear);
  b(&return_right, Label::kNear);

  bind(&check_zero);
  lzdr(kDoubleRegZero);
  cebr(left_reg, kDoubleRegZero);
  /* left == right != 0. */
  bne(&return_left, Label::kNear);
  /* At this point, both left and right are either 0 or -0. */
  /* N.B. The following works because +0 + -0 == +0 */
  /* For min we want logical-or of sign bit: -(-L + -R) */
  lcebr(left_reg, left_reg);
  ldr(result_reg, left_reg);
  if (left_reg == right_reg) {
    aebr(result_reg, right_reg);
  } else {
    sebr(result_reg, right_reg);
  }
  lcebr(result_reg, result_reg);
  b(&done, Label::kNear);

  bind(&return_nan);
  /* If left or right are NaN, aebr propagates the appropriate one.*/
  aebr(left_reg, right_reg);
  b(&return_left, Label::kNear);

  bind(&return_right);
  if (right_reg != result_reg) {
    ldr(result_reg, right_reg);
  }
  b(&done, Label::kNear);

  bind(&return_left);
  if (left_reg != result_reg) {
    ldr(result_reg, left_reg);
  }
  bind(&done);
}

void MacroAssembler::CeilF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TOWARD_POS_INF, dst, src);
}

void MacroAssembler::CeilF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TOWARD_POS_INF, dst, src);
}

void MacroAssembler::FloorF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TOWARD_NEG_INF, dst, src);
}

void MacroAssembler::FloorF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TOWARD_NEG_INF, dst, src);
}

void MacroAssembler::TruncF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TOWARD_0, dst, src);
}

void MacroAssembler::TruncF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TOWARD_0, dst, src);
}

void MacroAssembler::NearestIntF32(DoubleRegister dst, DoubleRegister src) {
  fiebra(ROUND_TO_NEAREST_TO_EVEN, dst, src);
}

void MacroAssembler::NearestIntF64(DoubleRegister dst, DoubleRegister src) {
  fidbra(ROUND_TO_NEAREST_TO_EVEN, dst, src);
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
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register scratch,
                                    Register exclusion1, Register exclusion2,
                                    Register exclusion3) {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushF64OrV128(kCallerSavedDoubles, scratch);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register scratch,
                                   Register exclusion1, Register exclusion2,
                                   Register exclusion3) {
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopF64OrV128(kCallerSavedDoubles, scratch);
    bytes += kStackSavedSavedFPSizeInBytes;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kSystemPointerSize;

  return bytes;
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));

  const uint32_t offset = OFFSET_OF_DATA_START(FixedArray) +
                          constant_index * kSystemPointerSize - kHeapObjectTag;

  CHECK(is_uint19(offset));
  DCHECK_NE(destination, r0);
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(destination,
                  FieldMemOperand(destination, FixedArray::OffsetOfElementAt(
                                                   constant_index)),
                  r1);
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  LoadU64(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  StoreU64(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    mov(destination, kRootRegister);
  } else if (is_uint12(offset)) {
    la(destination, MemOperand(kRootRegister, offset));
  } else {
    DCHECK(is_int20(offset));
    lay(destination, MemOperand(kRootRegister, offset));
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

void MacroAssembler::Jump(Register target, Condition cond) { b(cond, target); }

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond) {
  Label skip;

  if (cond != al) b(NegateCondition(cond), &skip);

  mov(ip, Operand(target, rmode));
  b(ip);

  bind(&skip);
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
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  jump(code, RelocInfo::RELATIVE_CODE_TARGET, cond);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
#if V8_OS_ZOS
  // Place reference into scratch r12 ip register
  Move(ip, reference);
  // z/OS uses function descriptors, extract code entry into r6
  LoadMultipleP(r5, r6, MemOperand(ip));
  // Preserve return address into r14
  mov(r14, r7);
  // Call C Function
  StoreReturnAddressAndCall(r6);
  // Branch to return address in r14
  b(r14);
#else
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Move(scratch, reference);
  Jump(scratch);
#endif
}

void MacroAssembler::Call(Register target) {
  // Branch to target via indirect branch
  basr(r14, target);
}

void MacroAssembler::CallJSEntry(Register target) {
  DCHECK(target == r4);
  Call(target);
}

int MacroAssembler::CallSizeNotPredictableCodeSize(Address target,
                                                   RelocInfo::Mode rmode,
                                                   Condition cond) {
  // S390 Assembler::move sequence is IILF / IIHF
  int size;
  size = 14;  // IILF + IIHF + BASR
  return size;
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(cond == al);

  mov(ip, Operand(target, rmode));
  basr(r14, ip);
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(RelocInfo::IsCodeTarget(rmode) && cond == al);

  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  call(code, rmode);
}

void MacroAssembler::CallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  // Use ip directly instead of using UseScratchRegisterScope, as we do not
  // preserve scratch registers across calls.
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      mov(ip, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(ip);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
    case BuiltinCallJumpMode::kIndirect:
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
      Call(ip);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      call(code, RelocInfo::CODE_TARGET);
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
      LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
      Jump(ip, cond);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        jump(code, RelocInfo::RELATIVE_CODE_TARGET, cond);
      } else {
        LoadU64(ip, EntryFromBuiltinAsOperand(builtin));
        Jump(ip, cond);
      }
      break;
    }
  }
}

void MacroAssembler::Drop(int count) {
  if (count > 0) {
    int total = count * kSystemPointerSize;
    if (is_uint12(total)) {
      la(sp, MemOperand(sp, total));
    } else if (is_int20(total)) {
      lay(sp, MemOperand(sp, total));
    } else {
      AddS64(sp, Operand(total));
    }
  }
}

void MacroAssembler::Drop(Register count, Register scratch) {
  ShiftLeftU64(scratch, count, Operand(kSystemPointerSizeLog2));
  AddS64(sp, sp, scratch);
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code,
                                                       Register scratch) {
  LoadU32(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  TestBit(scratch, Code::kMarkedForDeoptimizationBit, scratch);
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::Call(Label* target) { b(r14, target); }

void MacroAssembler::Push(Handle<HeapObject> handle) {
  mov(r0, Operand(handle));
  push(r0);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  mov(r0, Operand(smi));
  push(r0);
}

void MacroAssembler::Push(Tagged<TaggedIndex> index) {
  // TaggedIndex is the same as Smi for 32 bit archs.
  mov(r0, Operand(static_cast<uint32_t>(index.value())));
  push(r0);
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
  if (dst != src) {
    if (cond == al) {
      mov(dst, src);
    } else {
      LoadOnConditionP(cond, dst, src);
    }
  }
}

void MacroAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  if (dst != src) {
    ldr(dst, src);
  }
}

void MacroAssembler::Move(Register dst, const MemOperand& src) {
  LoadU64(dst, src);
}

// Wrapper around Assembler::mvc (SS-a format)
void MacroAssembler::MoveChar(const MemOperand& opnd1, const MemOperand& opnd2,
                              const Operand& length) {
  mvc(opnd1, opnd2, Operand(static_cast<intptr_t>(length.immediate() - 1)));
}

// Wrapper around Assembler::clc (SS-a format)
void MacroAssembler::CompareLogicalChar(const MemOperand& opnd1,
                                        const MemOperand& opnd2,
                                        const Operand& length) {
  clc(opnd1, opnd2, Operand(static_cast<intptr_t>(length.immediate() - 1)));
}

// Wrapper around Assembler::xc (SS-a format)
void MacroAssembler::ExclusiveOrChar(const MemOperand& opnd1,
                                     const MemOperand& opnd2,
                                     const Operand& length) {
  xc(opnd1, opnd2, Operand(static_cast<intptr_t>(length.immediate() - 1)));
}

// Wrapper around Assembler::risbg(n) (RIE-f)
void MacroAssembler::RotateInsertSelectBits(Register dst, Register src,
                                            const Operand& startBit,
                                            const Operand& endBit,
                                            const Operand& shiftAmt,
                                            bool zeroBits) {
  if (zeroBits)
    // High tag the top bit of I4/EndBit to zero out any unselected bits
    risbg(dst, src, startBit,
          Operand(static_cast<intptr_t>(endBit.immediate() | 0x80)), shiftAmt);
  else
    risbg(dst, src, startBit, endBit, shiftAmt);
}

void MacroAssembler::BranchRelativeOnIdxHighP(Register dst, Register inc,
                                              Label* L) {
  brxhg(dst, inc, L);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               Register scratch2, PushArrayOrder order) {
  Label loop, done;

  if (order == kNormal) {
    ShiftLeftU64(scratch, size, Operand(kSystemPointerSizeLog2));
    lay(scratch, MemOperand(array, scratch));
    bind(&loop);
    CmpS64(array, scratch);
    bge(&done);
    lay(scratch, MemOperand(scratch, -kSystemPointerSize));
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    MoveChar(MemOperand(sp), MemOperand(scratch), Operand(kSystemPointerSize));
    b(&loop);
    bind(&done);
  } else {
    DCHECK_NE(scratch2, r0);
    ShiftLeftU64(scratch, size, Operand(kSystemPointerSizeLog2));
    lay(scratch, MemOperand(array, scratch));
    mov(scratch2, array);
    bind(&loop);
    CmpS64(scratch2, scratch);
    bge(&done);
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    MoveChar(MemOperand(sp), MemOperand(scratch2), Operand(kSystemPointerSize));
    lay(scratch2, MemOperand(scratch2, kSystemPointerSize));
    b(&loop);
    bind(&done);
  }
}

void MacroAssembler::MultiPush(RegList regs, Register location) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kSystemPointerSize;

  SubS64(location, location, Operand(stack_offset));
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
  AddS64(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPushDoubles(DoubleRegList dregs, Register location) {
  int16_t num_to_push = dregs.Count();
  int16_t stack_offset = num_to_push * kDoubleSize;

  SubS64(location, location, Operand(stack_offset));
  for (int16_t i = DoubleRegister::kNumRegisters - 1; i >= 0; i--) {
    if ((dregs.bits() & (1 << i)) != 0) {
      DoubleRegister dreg = DoubleRegister::from_code(i);
      stack_offset -= kDoubleSize;
      StoreF64(dreg, MemOperand(location, stack_offset));
    }
  }
}

void MacroAssembler::MultiPushV128(DoubleRegList dregs, Register scratch,
                                   Register location) {
  int16_t num_to_push = dregs.Count();
  int16_t stack_offset = num_to_push * kSimd128Size;

  SubS64(location, location, Operand(stack_offset));
  for (int16_t i = Simd128Register::kNumRegisters - 1; i >= 0; i--) {
    if ((dregs.bits() & (1 << i)) != 0) {
      Simd128Register dreg = Simd128Register::from_code(i);
      stack_offset -= kSimd128Size;
      StoreV128(dreg, MemOperand(location, stack_offset), scratch);
    }
  }
}

void MacroAssembler::MultiPopDoubles(DoubleRegList dregs, Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < DoubleRegister::kNumRegisters; i++) {
    if ((dregs.bits() & (1 << i)) != 0) {
      DoubleRegister dreg = DoubleRegister::from_code(i);
      LoadF64(dreg, MemOperand(location, stack_offset));
      stack_offset += kDoubleSize;
    }
  }
  AddS64(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPopV128(DoubleRegList dregs, Register scratch,
                                  Register location) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < Simd128Register::kNumRegisters; i++) {
    if ((dregs.bits() & (1 << i)) != 0) {
      Simd128Register dreg = Simd128Register::from_code(i);
      LoadV128(dreg, MemOperand(location, stack_offset), scratch);
      stack_offset += kSimd128Size;
    }
  }
  AddS64(location, location, Operand(stack_offset));
}

void MacroAssembler::MultiPushF64OrV128(DoubleRegList dregs, Register scratch,
                                        Register location) {
#if V8_ENABLE_WEBASSEMBLY
  bool generating_bultins =
      isolate() && isolate()->IsGeneratingEmbeddedBuiltins();
  if (generating_bultins) {
    Label push_doubles, simd_pushed;
    Move(r1, ExternalReference::supports_wasm_simd_128_address());
    LoadU8(r1, MemOperand(r1));
    LoadAndTestP(r1, r1);  // If > 0 then simd is available.
    ble(&push_doubles, Label::kNear);
    // Save vector registers, don't save double registers anymore.
    MultiPushV128(dregs, scratch);
    b(&simd_pushed);
    bind(&push_doubles);
    // Simd not supported, only save double registers.
    MultiPushDoubles(dregs);
    // We still need to allocate empty space on the stack as if
    // Simd rgeisters were saved (see kFixedFrameSizeFromFp).
    lay(sp, MemOperand(sp, -(dregs.Count() * kDoubleSize)));
    bind(&simd_pushed);
  } else {
    if (CpuFeatures::SupportsWasmSimd128()) {
      MultiPushV128(dregs, scratch);
    } else {
      MultiPushDoubles(dregs);
      lay(sp, MemOperand(sp, -(dregs.Count() * kDoubleSize)));
    }
  }
#else
  MultiPushDoubles(dregs);
#endif
}

void MacroAssembler::MultiPopF64OrV128(DoubleRegList dregs, Register scratch,
                                       Register location) {
#if V8_ENABLE_WEBASSEMBLY
  bool generating_bultins =
      isolate() && isolate()->IsGeneratingEmbeddedBuiltins();
  if (generating_bultins) {
    Label pop_doubles, simd_popped;
    Move(r1, ExternalReference::supports_wasm_simd_128_address());
    LoadU8(r1, MemOperand(r1));
    LoadAndTestP(r1, r1);  // If > 0 then simd is available.
    ble(&pop_doubles, Label::kNear);
    // Pop vector registers, don't pop double registers anymore.
    MultiPopV128(dregs, scratch);
    b(&simd_popped);
    bind(&pop_doubles);
    // Simd not supported, only pop double registers.
    lay(sp, MemOperand(sp, dregs.Count() * kDoubleSize));
    MultiPopDoubles(dregs);
    bind(&simd_popped);
  } else {
    if (CpuFeatures::SupportsWasmSimd128()) {
      MultiPopV128(dregs, scratch);
    } else {
      lay(sp, MemOperand(sp, dregs.Count() * kDoubleSize));
      MultiPopDoubles(dregs);
    }
  }
#else
  MultiPopDoubles(dregs);
#endif
}

void MacroAssembler::PushAll(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  // TODO(victorgomes): {stm/ldm} pushes/pops registers in the opposite order
  // as expected by Maglev frame. Consider massaging Maglev to accept this
  // order instead.
  // Can not use MultiPush(registers, sp) due to orders
  for (Register reg : registers) {
    Push(reg);
  }
}

void MacroAssembler::PopAll(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  // Can not use MultiPop(registers, sp);
  for (Register reg : base::Reversed(registers)) {
    Pop(reg);
  }
}

void MacroAssembler::PushAll(DoubleRegList registers, int stack_slot_size) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  MultiPushDoubles(registers, sp);
}

void MacroAssembler::PopAll(DoubleRegList registers, int stack_slot_size) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  MultiPopDoubles(registers, sp);
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
                              Condition) {
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
void MacroAssembler::LoadTaggedFieldWithoutDecompressing(
    const Register& destination, const MemOperand& field_operand,
    const Register& scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    LoadU32(destination, field_operand, scratch);
  } else {
    LoadU64(destination, field_operand, scratch);
  }
}
void MacroAssembler::SmiUntag(Register dst, const MemOperand& src) {
  if (SmiValuesAre31Bits()) {
    LoadS32(dst, src);
  } else {
    LoadU64(dst, src);
  }
  SmiUntag(dst);
}

void MacroAssembler::SmiUntagField(Register dst, const MemOperand& src) {
  SmiUntag(dst, src);
}

void MacroAssembler::StoreTaggedField(const Register& value,
                                      const MemOperand& dst_field_operand,
                                      const Register& scratch) {
  if (COMPRESS_POINTERS_BOOL) {
    RecordComment("[ StoreTagged");
    StoreU32(value, dst_field_operand);
    RecordComment("]");
  } else {
    StoreU64(value, dst_field_operand, scratch);
  }
}

void MacroAssembler::DecompressTaggedSigned(Register destination,
                                            Register src) {
  RecordComment("[ DecompressTaggedSigned");
  llgfr(destination, src);
  RecordComment("]");
}

void MacroAssembler::DecompressTaggedSigned(Register destination,
                                            MemOperand field_operand) {
  RecordComment("[ DecompressTaggedSigned");
  llgf(destination, field_operand);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(Register destination, Register source) {
  RecordComment("[ DecompressTagged");
  llgfr(destination, source);
  agr(destination, kPtrComprCageBaseRegister);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(Register destination,
                                      MemOperand field_operand) {
  RecordComment("[ DecompressTagged");
  llgf(destination, field_operand);
  agr(destination, kPtrComprCageBaseRegister);
  RecordComment("]");
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  mov(destination, Operand(immediate, RelocInfo::NO_INFO));
  agr(destination, kRootRegister);
}

void MacroAssembler::LoadTaggedSignedField(Register destination,
                                           MemOperand field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destina
```
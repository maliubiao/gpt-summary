Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan for File Type:** The first instruction is to check the file extension. The filename `maglev-assembler-s390-inl.h` ends with `.h`, not `.tq`. This immediately tells us it's a C++ header, not a Torque file. We can note this down.

2. **Identify Core Purpose (Filename Clues):** The filename gives strong hints:
    * `maglev`: This likely relates to the Maglev compiler, a part of V8.
    * `assembler`:  This suggests the file deals with generating machine code instructions.
    * `s390`:  This specifies the target architecture – IBM's System/390 (or its successors).
    * `inl.h`: This is a common convention for inline header files in C++, meaning the file contains inline function definitions.

3. **Examine Includes:** The `#include` directives provide further context:
    * `"src/base/numbers/double.h"`: Deals with double-precision floating-point numbers.
    * `"src/codegen/interface-descriptors-inl.h"`: Likely related to how functions are called and their arguments/return values.
    * `"src/codegen/macro-assembler-inl.h"` and `"src/codegen/s390/assembler-s390.h"`: These confirm the file's role in assembly code generation for the s390 architecture. The "macro-assembler" part suggests higher-level abstractions over raw assembly instructions.
    * `"src/common/globals.h"`:  Provides access to global V8 settings and constants.
    * `"src/compiler/compilation-dependencies.h"`: Related to tracking dependencies during compilation.
    * `"src/maglev/maglev-assembler.h"`, `"src/maglev/maglev-basic-block.h"`, `"src/maglev/maglev-code-gen-state.h"`:  These strongly reinforce that this file is part of the Maglev compiler and its assembly generation process.

4. **Analyze the Namespace:** The code is within `namespace v8 { namespace internal { namespace maglev { ... }}}`. This clearly indicates its belonging within the V8 JavaScript engine's internal Maglev compiler components.

5. **Inspect Key Classes and Functions:** Now, we delve into the code's content:
    * `ConditionForFloat64`:  A simple function likely mapping Maglev's `Operation` enum to s390 condition codes for floating-point comparisons.
    * `ShiftFromScale`: Converts a scale factor (1, 2, 4, 8) into a bit shift amount. This is common in memory addressing calculations.
    * `MaglevAssembler::TemporaryRegisterScope`: A crucial class for managing the allocation and release of temporary registers during code generation. It prevents register conflicts.
    * `MapCompare`:  A class to compare the map (type information) of an object. This is fundamental in dynamically typed languages like JavaScript for determining object structure and behavior.
    * `detail::PushAllHelper`: A template metaprogramming construct to efficiently push various types of data onto the stack. This is used for function calls.
    * The numerous inline functions within `MaglevAssembler`: These are the core of the assembler. They provide high-level operations like:
        * `BindJumpTarget`, `BindBlock`:  Handling control flow.
        * `SmiTagInt32AndSetFlags`, `CheckInt32IsSmi`, `SmiAddConstant`, `SmiSubConstant`: Operations related to Smis (small integers), a common V8 optimization.
        * `MoveHeapNumber`: Loading floating-point constants.
        * `IsRootConstant`: Checking if a value is a specific V8 root object.
        * `StackSlotOperand`, `GetStackSlot`: Accessing the function's stack frame.
        * `BuildTypedArrayDataPointer`, `TypedArrayElementOperand`, `DataViewElementOperand`:  Operations specific to Typed Arrays.
        * `LoadTaggedFieldByIndex`, `LoadFixedArrayElement`, etc.: Loading and storing object properties and array elements, taking into account V8's object layout.
        * `StoreTaggedFieldNoWriteBarrier`, `StoreFixedArrayElementNoWriteBarrier`:  Optimized store operations that skip the write barrier (important for garbage collection).
        * `LoadSignedField`, `LoadUnsignedField`, `StoreField`:  Generic memory access for different data sizes.
        * `ReverseByteOrder`: Handling endianness.
        * Arithmetic and bitwise operations (`IncrementInt32`, `DecrementInt32`, `AddInt32`, `AndInt32`, `OrInt32`, `ShiftLeft`).
        * Function call related operations (`Call`, `EmitEnterExitFrame`, `PrepareCallCFunction`, `CallSelf`).
        * `Move`: Moving data between registers, stack slots, and memory.
        * Floating-point operations (`LoadFloat32`, `StoreFloat32`, `LoadFloat64`, `StoreFloat64`, `LoadUnalignedFloat64`, etc.).
        * Type checking operations (`IsCallableAndNotUndetectable`, `IsNotCallableNorUndetactable`, `LoadInstanceType`, `JumpIfObjectType`, `AssertObjectType`, `BranchOnObjectType`, `JumpIfObjectTypeInRange`, etc.).
        * Deoptimization support (`DeoptIfBufferDetached`).
        * Comparisons (`CompareMapWithRoot`, `CompareInstanceType`, `CompareInstanceTypeRange`, `CompareFloat64AndJumpIf`, `CompareFloat64AndBranch`).
        * Control flow (`Jump`, `JumpToDeopt`).

6. **Infer Functionality:** Based on the included files, namespaces, classes, and functions, we can conclude:
    * This header defines inline methods for the `MaglevAssembler` class, specifically for the s390 architecture.
    * It provides a higher-level interface for generating s390 assembly instructions, abstracting away low-level details.
    * It includes support for common JavaScript operations like object property access, array manipulation, arithmetic, floating-point math, and function calls.
    * It incorporates mechanisms for optimization (e.g., Smi handling, no-write-barrier stores) and deoptimization.
    * It heavily relies on V8's internal data structures and conventions (e.g., Maps, HeapObjects, Smis).

7. **Address Specific Instructions:**
    * **.tq check:** Already done in step 1.
    * **Relationship to JavaScript:** The operations directly correspond to JavaScript language features. For instance, `LoadTaggedField` is used to access object properties, array element access corresponds to `LoadFixedArrayElement`, arithmetic operations correspond to JavaScript's `+`, `-`, etc.
    * **JavaScript Examples:**  We can now create simple JavaScript examples that would utilize these underlying assembly operations.
    * **Code Logic Reasoning:** Choose a specific function (like `SmiAddConstant`) and create hypothetical inputs and outputs to illustrate its behavior.
    * **Common Programming Errors:** Think about how JavaScript developers might make mistakes that would lead to the execution of certain code paths in this assembler (e.g., type errors, accessing detached ArrayBuffers).

8. **Synthesize Summary:** Finally, combine all the observations into a concise summary of the file's purpose and functionality. This involves highlighting the key responsibilities and the target audience (V8 developers working on the Maglev compiler).
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_MAGLEV_S390_MAGLEV_ASSEMBLER_S390_INL_H_
#define V8_MAGLEV_S390_MAGLEV_ASSEMBLER_S390_INL_H_

#include "src/base/numbers/double.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/s390/assembler-s390.h"
#include "src/common/globals.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/maglev/maglev-assembler.h"
#include "src/maglev/maglev-basic-block.h"
#include "src/maglev/maglev-code-gen-state.h"

namespace v8 {
namespace internal {
namespace maglev {

constexpr Condition ConditionForFloat64(Operation operation) {
  return ConditionFor(operation);
}

// constexpr Condition ConditionForNaN() { return vs; }

inline int ShiftFromScale(int n) {
  switch (n) {
    case 1:
      return 0;
    case 2:
      return 1;
    case 4:
      return 2;
    case 8:
      return 3;
    default:
      UNREACHABLE();
  }
}

class MaglevAssembler::TemporaryRegisterScope
    : public TemporaryRegisterScopeBase<TemporaryRegisterScope> {
  using Base = TemporaryRegisterScopeBase<TemporaryRegisterScope>;

 public:
  struct SavedData : public Base::SavedData {
    RegList available_scratch_;
    DoubleRegList available_fp_scratch_;
  };

  explicit TemporaryRegisterScope(MaglevAssembler* masm)
      : Base(masm), scratch_scope_(masm) {
    if (prev_scope_ == nullptr) {
      // Add extra scratch register if no previous scope.
      // scratch_scope_.Include(kMaglevExtraScratchRegister);
    }
  }
  explicit TemporaryRegisterScope(MaglevAssembler* masm,
                                  const SavedData& saved_data)
      : Base(masm, saved_data), scratch_scope_(masm) {
    scratch_scope_.SetAvailable(saved_data.available_scratch_);
    scratch_scope_.SetAvailableDoubleRegList(saved_data.available_fp_scratch_);
  }

  Register AcquireScratch() {
    Register reg = scratch_scope_.Acquire();
    CHECK(!available_.has(reg));
    return reg;
  }
  DoubleRegister AcquireScratchDouble() {
    DoubleRegister reg = scratch_scope_.AcquireDouble();
    CHECK(!available_double_.has(reg));
    return reg;
  }
  void IncludeScratch(Register reg) { scratch_scope_.Include(reg); }

  SavedData CopyForDefer() {
    return SavedData{
        CopyForDeferBase(),
        scratch_scope_.Available(),
        scratch_scope_.AvailableDoubleRegList(),
    };
  }

  void ResetToDefaultImpl() {
    scratch_scope_.SetAvailable(Assembler::DefaultTmpList());
    scratch_scope_.SetAvailableDoubleRegList(Assembler::DefaultFPTmpList());
  }

 private:
  UseScratchRegisterScope scratch_scope_;
};

inline MapCompare::MapCompare(MaglevAssembler* masm, Register object,
                              size_t map_count)
    : masm_(masm), object_(object), map_count_(map_count) {
  map_ = masm_->scratch_register_scope()->Acquire();
  masm_->LoadMap(map_, object_);
  USE(map_count_);
}

void MapCompare::Generate(Handle<Map> map, Condition cond, Label* if_true,
                          Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(masm_);
  Register temp = temps.AcquireScratch();
  masm_->Move(temp, map);
  masm_->CmpS64(map_, temp);
  CHECK(is_signed(cond));
  masm_->JumpIf(cond, if_true, distance);
}

Register MapCompare::GetMap() { return map_; }

int MapCompare::TemporaryCount(size_t map_count) { return 1; }

namespace detail {

template <typename... Args>
struct PushAllHelper;

template <>
struct PushAllHelper<> {
  static void Push(MaglevAssembler* masm) {}
  static void PushReverse(MaglevAssembler* masm) {}
};

inline void PushInput(MaglevAssembler* masm, const Input& input) {
  if (input.operand().IsConstant()) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    Register scratch = temps.AcquireScratch();
    input.node()->LoadToRegister(masm, scratch);
    masm->Push(scratch);
  } else {
    // TODO(leszeks): Consider special casing the value. (Toon: could possibly
    // be done through Input directly?)
    const compiler::AllocatedOperand& operand =
        compiler::AllocatedOperand::cast(input.operand());
    if (operand.IsRegister()) {
      masm->Push(operand.GetRegister());
    } else {
      DCHECK(operand.IsStackSlot());
      masm->LoadU64(r0, masm->GetStackSlot(operand));
      masm->Push(r0);
    }
  }
}

template <typename T, typename... Args>
inline void PushIterator(MaglevAssembler* masm, base::iterator_range<T> range,
                         Args... args) {
  for (auto iter = range.begin(), end = range.end(); iter != end; ++iter) {
    masm->Push(*iter);
  }
  PushAllHelper<Args...>::Push(masm, args...);
}

template <typename T, typename... Args>
inline void PushIteratorReverse(MaglevAssembler* masm,
                                base::iterator_range<T> range, Args... args) {
  PushAllHelper<Args...>::PushReverse(masm, args...);
  for (auto iter = range.rbegin(), end = range.rend(); iter != end; ++iter) {
    masm->Push(*iter);
  }
}

template <typename... Args>
struct PushAllHelper<Input, Args...> {
  static void Push(MaglevAssembler* masm, const Input& arg, Args... args) {
    PushInput(masm, arg);
    PushAllHelper<Args...>::Push(masm, args...);
  }
  static void PushReverse(MaglevAssembler* masm, const Input& arg,
                          Args... args) {
    PushAllHelper<Args...>::PushReverse(masm, args...);
    PushInput(masm, arg);
  }
};
template <typename Arg, typename... Args>
struct PushAllHelper<Arg, Args...> {
  static void Push(MaglevAssembler* masm, Arg arg, Args... args) {
    if constexpr (is_iterator_range<Arg>::value) {
      PushIterator(masm, arg, args...);
    } else {
      masm->MacroAssembler::Push(arg);
      PushAllHelper<Args...>::Push(masm, args...);
    }
  }
  static void PushReverse(MaglevAssembler* masm, Arg arg, Args... args) {
    if constexpr (is_iterator_range<Arg>::value) {
      PushIteratorReverse(masm, arg, args...);
    } else {
      PushAllHelper<Args...>::PushReverse(masm, args...);
      masm->Push(arg);
    }
  }
};

}  // namespace detail

template <typename... T>
void MaglevAssembler::Push(T... vals) {
  detail::PushAllHelper<T...>::Push(this, vals...);
}

template <typename... T>
void MaglevAssembler::PushReverse(T... vals) {
  detail::PushAllHelper<T...>::PushReverse(this, vals...);
}

inline void MaglevAssembler::BindJumpTarget(Label* label) { bind(label); }

inline void MaglevAssembler::BindBlock(BasicBlock* block) {
  bind(block->label());
}

inline void MaglevAssembler::SmiTagInt32AndSetFlags(Register dst,
                                                    Register src) {
  if (SmiValuesAre31Bits()) {
    AddS32(dst, src, src);
  } else {
    SmiTag(dst, src);
  }
}

inline void MaglevAssembler::CheckInt32IsSmi(Register obj, Label* fail,
                                             Register scratch) {
  DCHECK(!SmiValuesAre32Bits());
  if (scratch == Register::no_reg()) {
    scratch = r0;
  }
  mov(scratch, obj);
  AddS32(scratch, scratch);
  JumpIf(kOverflow, fail);
}

inline void MaglevAssembler::SmiAddConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  AssertSmi(src);
  Move(dst, src);
  if (value != 0) {
    Register scratch = r0;
    Move(scratch, Smi::FromInt(value));
    if (SmiValuesAre31Bits()) {
      AddS32(dst, scratch);
    } else {
      AddS64(dst, scratch);
    }
    JumpIf(kOverflow, fail, distance);
  }
}

inline void MaglevAssembler::SmiSubConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  AssertSmi(src);
  Move(dst, src);
  if (value != 0) {
    Register scratch = r0;
    Move(scratch, Smi::FromInt(value));
    if (SmiValuesAre31Bits()) {
      SubS32(dst, scratch);
    } else {
      SubS64(dst, scratch);
    }
    JumpIf(kOverflow, fail, distance);
  }
}

inline void MaglevAssembler::MoveHeapNumber(Register dst, double value) {
  mov(dst, Operand::EmbeddedNumber(value));
}

inline Condition MaglevAssembler::IsRootConstant(Input input,
                                                 RootIndex root_index) {
  if (input.operand().IsRegister()) {
    CompareRoot(ToRegister(input), root_index);
  } else {
    DCHECK(input.operand().IsStackSlot());
    TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    LoadU64(scratch, ToMemOperand(input), scratch);
    CompareRoot(scratch, root_index);
  }
  return eq;
}

inline MemOperand MaglevAssembler::StackSlotOperand(StackSlot slot) {
  return MemOperand(fp, slot.index);
}

inline Register MaglevAssembler::GetFramePointer() { return fp; }

// TODO(Victorgomes): Unify this to use StackSlot struct.
inline MemOperand MaglevAssembler::GetStackSlot(
    const compiler::AllocatedOperand& operand) {
  return MemOperand(fp, GetFramePointerOffsetForStackSlot(operand));
}

inline MemOperand MaglevAssembler::ToMemOperand(
    const compiler::InstructionOperand& operand) {
  return GetStackSlot(compiler::AllocatedOperand::cast(operand));
}

inline MemOperand MaglevAssembler::ToMemOperand(const ValueLocation& location) {
  return ToMemOperand(location.operand());
}

inline void MaglevAssembler::BuildTypedArrayDataPointer(Register data_pointer,
                                                        Register object) {
  DCHECK_NE(data_pointer, object);
  LoadExternalPointerField(
      data_pointer,
      FieldMemOperand(object, JSTypedArray::kExternalPointerOffset));
  if (JSTypedArray::kMaxSizeInHeap == 0) return;
  // TemporaryRegisterScope temps(this);
  Register base = r0;
  if (COMPRESS_POINTERS_BOOL) {
    LoadU32(base, FieldMemOperand(object, JSTypedArray::kBasePointerOffset));
  } else {
    LoadU64(base, FieldMemOperand(object, JSTypedArray::kBasePointerOffset));
  }
  AddU64(data_pointer, data_pointer, base);
}

inline MemOperand MaglevAssembler::TypedArrayElementOperand(
    Register data_pointer, Register index, int element_size) {
  // TemporaryRegisterScope temps(this);
  Register temp = r0;
  ShiftLeftU64(temp, index, Operand(ShiftFromScale(element_size)));
  AddU64(data_pointer, data_pointer, temp);
  return MemOperand(data_pointer);
}

inline MemOperand MaglevAssembler::DataViewElementOperand(Register data_pointer,
                                                          Register index) {
  return MemOperand(data_pointer, index);
}

inline void MaglevAssembler::LoadTaggedFieldByIndex(Register result,
                                                    Register object,
                                                    Register index, int scale,
                                                    int offset) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  ShiftLeftU64(scratch, index, Operand(ShiftFromScale(scale)));
  AddU64(scratch, scratch, object);
  MacroAssembler::LoadTaggedField(result, FieldMemOperand(scratch, offset));
}

inline void MaglevAssembler::LoadBoundedSizeFromObject(Register result,
                                                       Register object,
                                                       int offset) {
  Move(result, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::LoadExternalPointerField(Register result,
                                                      MemOperand operand) {
  Move(result, operand);
}

void MaglevAssembler::LoadFixedArrayElement(Register result, Register array,
                                            Register index) {
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_ARRAY_TYPE, AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  LoadTaggedFieldByIndex(result, array, index, kTaggedSize,
                         OFFSET_OF_DATA_START(FixedArray));
}

inline void MaglevAssembler::LoadTaggedFieldWithoutDecompressing(
    Register result, Register object, int offset) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::LoadTaggedFieldWithoutDecompressing(
      result, FieldMemOperand(object, offset), scratch);
}

void MaglevAssembler::LoadFixedArrayElementWithoutDecompressing(
    Register result, Register array, Register index) {
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_ARRAY_TYPE, AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  int times_tagged_size = (kTaggedSize == 8) ? 3 : 2;
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register scratch2 = temps.AcquireScratch();
  ShiftLeftU64(scratch, index, Operand(times_tagged_size));
  MacroAssembler::LoadTaggedFieldWithoutDecompressing(
      result, FieldMemOperand(array, scratch, OFFSET_OF_DATA_START(FixedArray)),
      scratch2);
}

void MaglevAssembler::LoadFixedDoubleArrayElement(DoubleRegister result,
                                                  Register array,
                                                  Register index) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_DOUBLE_ARRAY_TYPE,
                     AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  ShiftLeftU64(scratch, index, Operand(kDoubleSizeLog2));
  LoadF64(result, FieldMemOperand(array, scratch,
                                  OFFSET_OF_DATA_START(FixedDoubleArray)));
}

inline void MaglevAssembler::StoreFixedDoubleArrayElement(
    Register array, Register index, DoubleRegister value) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  ShiftLeftU64(scratch, index, Operand(kDoubleSizeLog2));
  StoreF64(value, FieldMemOperand(array, scratch,
                                  OFFSET_OF_DATA_START(FixedDoubleArray)));
}

inline void MaglevAssembler::LoadSignedField(Register result,
                                             MemOperand operand, int size) {
  if (size == 1) {
    LoadS8(result, operand);
  } else if (size == 2) {
    LoadS16(result, operand);
  } else {
    DCHECK_EQ(size, 4);
    LoadS32(result, operand);
  }
}

inline void MaglevAssembler::LoadUnsignedField(Register result,
                                               MemOperand operand, int size) {
  if (size == 1) {
    LoadU8(result, operand);
  } else if (size == 2) {
    LoadU16(result, operand);
  } else {
    DCHECK_EQ(size, 4);
    LoadU32(result, operand);
  }
}

inline void MaglevAssembler::SetSlotAddressForTaggedField(Register slot_reg,
                                                          Register object,
                                                          int offset) {
  mov(slot_reg, object);
  AddS64(slot_reg, Operand(offset - kHeapObjectTag));
}

inline void MaglevAssembler::SetSlotAddressForFixedArrayElement(
    Register slot_reg, Register object, Register index) {
  // TemporaryRegisterScope temps(this);
  Register scratch = r0;
  mov(slot_reg, object);
  AddU64(slot_reg, Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
  ShiftLeftU64(scratch, index, Operand(kTaggedSizeLog2));
  AddU64(slot_reg, slot_reg, scratch);
}

inline void MaglevAssembler::StoreTaggedFieldNoWriteBarrier(Register object,
                                                            int offset,
                                                            Register value) {
  MacroAssembler::StoreTaggedField(value, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreFixedArrayElementNoWriteBarrier(
    Register array, Register index, Register value) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  ShiftLeftU64(scratch, index, Operand(kTaggedSizeLog2));
  AddU64(scratch, scratch, array);
  MacroAssembler::StoreTaggedField(
      value, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
}

inline void MaglevAssembler::StoreTaggedSignedField(Register object, int offset,
                                                    Register value) {
  AssertSmi(value);
  MacroAssembler::StoreTaggedField(value, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreTaggedSignedField(Register object, int offset,
                                                    Tagged<Smi> value) {
  TemporaryRegisterScope scope(this);
  Register scratch = r0;
  Move(scratch, value);
  MacroAssembler::StoreTaggedField(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreInt32Field(Register object, int offset,
                                             int32_t value) {
  TemporaryRegisterScope scope(this);
  Register scratch = r0;
  Move(scratch, value);
  StoreU32(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreField(MemOperand operand, Register value,
                                        int size) {
  DCHECK(size == 1 || size == 2 || size == 4);
  if (size == 1) {
    StoreU8(value, operand);
  } else if (size == 2) {
    StoreU16(value, operand);
  } else {
    DCHECK_EQ(size, 4);
    StoreU32(value, operand);
  }
}

inline void MaglevAssembler::ReverseByteOrder(Register value, int size) {
  if (size == 2) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreU16(value, MemOperand(sp));
    lrvh(value, MemOperand(sp));
    LoadS16(value, value);
    lay(sp, MemOperand(sp, kSystemPointerSize));
  } else if (size == 4) {
    lrvr(value, value);
    LoadS32(value, value);
  } else {
    DCHECK_EQ(size, 1);
  }
}

inline void MaglevAssembler::IncrementInt32(Register reg) {
  AddS32(reg, Operand(1));
}

inline void MaglevAssembler::DecrementInt32(Register reg) {
  SubS32(reg, Operand(1));
}

inline void MaglevAssembler::AddInt32(Register reg, int amount) {
  AddS32(reg, Operand(amount));
}

inline void MaglevAssembler::AndInt32(Register reg, int mask) {
  And(reg, Operand(mask));
  LoadU32(reg, reg);
}

inline void MaglevAssembler::OrInt32(Register reg, int mask) {
  Or(reg, Operand(mask));
  LoadU32(reg, reg);
}

inline void MaglevAssembler::ShiftLeft(Register reg, int amount) {
  ShiftLeftU32(reg, reg, Operand(amount));
}

inline void MaglevAssembler::IncrementAddress(Register reg, int32_t delta) {
  CHECK(is_int20(delta));
  lay(reg, MemOperand(reg, delta));
}

inline void MaglevAssembler::LoadAddress(Register dst, MemOperand location) {
  lay(dst, location);
}

inline void MaglevAssembler::Call(Label* target) {
  MacroAssembler::Call(target);
}

inline void MaglevAssembler::EmitEnterExitFrame(int extra_slots,
                                                StackFrame::Type frame_type,
                                                Register c_function,
                                                Register scratch) {
  EnterExitFrame(scratch, extra_slots, frame_type);
}

inline void MaglevAssembler::Move(StackSlot dst, Register src) {
  StoreU64(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(StackSlot dst, DoubleRegister src) {
  StoreF64(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(Register dst, StackSlot src) {
  LoadU64(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(DoubleRegister dst, StackSlot src) {
  LoadF64(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(MemOperand dst, Register src) {
  StoreU64(src, dst);
}
inline void MaglevAssembler::Move(Register dst, MemOperand src) {
  LoadU64(dst, src);
}
inline void MaglevAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  if (dst != src) {
    MacroAssembler::Move(dst, src);
  }
}
inline void MaglevAssembler::Move(Register dst, Tagged<Smi> src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, ExternalReference src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, Register src) {
  if (dst != src) {
    mov(dst, src);
  }
}
inline void MaglevAssembler::Move(Register dst, Tagged<TaggedIndex> i) {
  mov(dst, Operand(i.ptr()));
}
inline void MaglevAssembler::Move(Register dst, int32_t i) {
  mov(dst, Operand(i));
}
inline void MaglevAssembler::Move(DoubleRegister dst, double n) {
  TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch();
  MacroAssembler::LoadF64(dst, n, scratch);
}
inline void MaglevAssembler::Move(DoubleRegister dst, Float64 n) {
  TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch();
  MacroAssembler::LoadF64(dst, n, scratch);
}
inline void MaglevAssembler::Move(Register dst, Handle<HeapObject> obj) {
  MacroAssembler::Move(dst, obj);
}

inline void MaglevAssembler::Move(Register dst, uint32_t i) {
  // Move as a uint32 to avoid sign extension.
  mov(dst, Operand(i));
  LoadU32(dst, dst);
}

void MaglevAssembler::MoveTagged(Register dst, Handle<HeapObject> obj) {
#ifdef V8_COMPRESS_POINTERS
  MacroAssembler::Move(dst, obj, RelocInfo::COMPRESSED_EMBEDDED_OBJECT);
#else
  MacroAssembler::Move(dst, obj);
#endif
}

inline void MaglevAssembler::LoadFloat32(DoubleRegister dst, MemOperand src) {
  MacroAssembler::LoadF32AsF64(dst, src);
}
inline void MaglevAssembler::StoreFloat32(MemOperand dst, DoubleRegister src) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  DoubleRegister double_scratch = temps.AcquireScratchDouble();
  ledbr(double_scratch, src);
  MacroAssembler::StoreF32(double_scratch, dst);
}
inline void MaglevAssembler::LoadFloat64(DoubleRegister dst, MemOperand src) {
  MacroAssembler::LoadF64(dst, src);
}
inline void MaglevAssembler::StoreFloat64(MemOperand dst, DoubleRegister src) {
  MacroAssembler::StoreF64(src, dst);
}

inline void MaglevAssembler::LoadUnalignedFloat64(DoubleRegister dst,
                                                  Register base,
                                                  Register index) {
  LoadF64(dst, MemOperand(base, index));
}
inline void MaglevAssembler::LoadUnalignedFloat64AndReverseByteOrder(
    DoubleRegister dst, Register base, Register index) {
  TemporaryRegisterScope scope(this);
  Register
Prompt: 
```
这是目录为v8/src/maglev/s390/maglev-assembler-s390-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/s390/maglev-assembler-s390-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_MAGLEV_S390_MAGLEV_ASSEMBLER_S390_INL_H_
#define V8_MAGLEV_S390_MAGLEV_ASSEMBLER_S390_INL_H_

#include "src/base/numbers/double.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/s390/assembler-s390.h"
#include "src/common/globals.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/maglev/maglev-assembler.h"
#include "src/maglev/maglev-basic-block.h"
#include "src/maglev/maglev-code-gen-state.h"

namespace v8 {
namespace internal {
namespace maglev {

constexpr Condition ConditionForFloat64(Operation operation) {
  return ConditionFor(operation);
}

// constexpr Condition ConditionForNaN() { return vs; }

inline int ShiftFromScale(int n) {
  switch (n) {
    case 1:
      return 0;
    case 2:
      return 1;
    case 4:
      return 2;
    case 8:
      return 3;
    default:
      UNREACHABLE();
  }
}

class MaglevAssembler::TemporaryRegisterScope
    : public TemporaryRegisterScopeBase<TemporaryRegisterScope> {
  using Base = TemporaryRegisterScopeBase<TemporaryRegisterScope>;

 public:
  struct SavedData : public Base::SavedData {
    RegList available_scratch_;
    DoubleRegList available_fp_scratch_;
  };

  explicit TemporaryRegisterScope(MaglevAssembler* masm)
      : Base(masm), scratch_scope_(masm) {
    if (prev_scope_ == nullptr) {
      // Add extra scratch register if no previous scope.
      // scratch_scope_.Include(kMaglevExtraScratchRegister);
    }
  }
  explicit TemporaryRegisterScope(MaglevAssembler* masm,
                                  const SavedData& saved_data)
      : Base(masm, saved_data), scratch_scope_(masm) {
    scratch_scope_.SetAvailable(saved_data.available_scratch_);
    scratch_scope_.SetAvailableDoubleRegList(saved_data.available_fp_scratch_);
  }

  Register AcquireScratch() {
    Register reg = scratch_scope_.Acquire();
    CHECK(!available_.has(reg));
    return reg;
  }
  DoubleRegister AcquireScratchDouble() {
    DoubleRegister reg = scratch_scope_.AcquireDouble();
    CHECK(!available_double_.has(reg));
    return reg;
  }
  void IncludeScratch(Register reg) { scratch_scope_.Include(reg); }

  SavedData CopyForDefer() {
    return SavedData{
        CopyForDeferBase(),
        scratch_scope_.Available(),
        scratch_scope_.AvailableDoubleRegList(),
    };
  }

  void ResetToDefaultImpl() {
    scratch_scope_.SetAvailable(Assembler::DefaultTmpList());
    scratch_scope_.SetAvailableDoubleRegList(Assembler::DefaultFPTmpList());
  }

 private:
  UseScratchRegisterScope scratch_scope_;
};

inline MapCompare::MapCompare(MaglevAssembler* masm, Register object,
                              size_t map_count)
    : masm_(masm), object_(object), map_count_(map_count) {
  map_ = masm_->scratch_register_scope()->Acquire();
  masm_->LoadMap(map_, object_);
  USE(map_count_);
}

void MapCompare::Generate(Handle<Map> map, Condition cond, Label* if_true,
                          Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(masm_);
  Register temp = temps.AcquireScratch();
  masm_->Move(temp, map);
  masm_->CmpS64(map_, temp);
  CHECK(is_signed(cond));
  masm_->JumpIf(cond, if_true, distance);
}

Register MapCompare::GetMap() { return map_; }

int MapCompare::TemporaryCount(size_t map_count) { return 1; }

namespace detail {

template <typename... Args>
struct PushAllHelper;

template <>
struct PushAllHelper<> {
  static void Push(MaglevAssembler* masm) {}
  static void PushReverse(MaglevAssembler* masm) {}
};

inline void PushInput(MaglevAssembler* masm, const Input& input) {
  if (input.operand().IsConstant()) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    Register scratch = temps.AcquireScratch();
    input.node()->LoadToRegister(masm, scratch);
    masm->Push(scratch);
  } else {
    // TODO(leszeks): Consider special casing the value. (Toon: could possibly
    // be done through Input directly?)
    const compiler::AllocatedOperand& operand =
        compiler::AllocatedOperand::cast(input.operand());
    if (operand.IsRegister()) {
      masm->Push(operand.GetRegister());
    } else {
      DCHECK(operand.IsStackSlot());
      masm->LoadU64(r0, masm->GetStackSlot(operand));
      masm->Push(r0);
    }
  }
}

template <typename T, typename... Args>
inline void PushIterator(MaglevAssembler* masm, base::iterator_range<T> range,
                         Args... args) {
  for (auto iter = range.begin(), end = range.end(); iter != end; ++iter) {
    masm->Push(*iter);
  }
  PushAllHelper<Args...>::Push(masm, args...);
}

template <typename T, typename... Args>
inline void PushIteratorReverse(MaglevAssembler* masm,
                                base::iterator_range<T> range, Args... args) {
  PushAllHelper<Args...>::PushReverse(masm, args...);
  for (auto iter = range.rbegin(), end = range.rend(); iter != end; ++iter) {
    masm->Push(*iter);
  }
}

template <typename... Args>
struct PushAllHelper<Input, Args...> {
  static void Push(MaglevAssembler* masm, const Input& arg, Args... args) {
    PushInput(masm, arg);
    PushAllHelper<Args...>::Push(masm, args...);
  }
  static void PushReverse(MaglevAssembler* masm, const Input& arg,
                          Args... args) {
    PushAllHelper<Args...>::PushReverse(masm, args...);
    PushInput(masm, arg);
  }
};
template <typename Arg, typename... Args>
struct PushAllHelper<Arg, Args...> {
  static void Push(MaglevAssembler* masm, Arg arg, Args... args) {
    if constexpr (is_iterator_range<Arg>::value) {
      PushIterator(masm, arg, args...);
    } else {
      masm->MacroAssembler::Push(arg);
      PushAllHelper<Args...>::Push(masm, args...);
    }
  }
  static void PushReverse(MaglevAssembler* masm, Arg arg, Args... args) {
    if constexpr (is_iterator_range<Arg>::value) {
      PushIteratorReverse(masm, arg, args...);
    } else {
      PushAllHelper<Args...>::PushReverse(masm, args...);
      masm->Push(arg);
    }
  }
};

}  // namespace detail

template <typename... T>
void MaglevAssembler::Push(T... vals) {
  detail::PushAllHelper<T...>::Push(this, vals...);
}

template <typename... T>
void MaglevAssembler::PushReverse(T... vals) {
  detail::PushAllHelper<T...>::PushReverse(this, vals...);
}

inline void MaglevAssembler::BindJumpTarget(Label* label) { bind(label); }

inline void MaglevAssembler::BindBlock(BasicBlock* block) {
  bind(block->label());
}

inline void MaglevAssembler::SmiTagInt32AndSetFlags(Register dst,
                                                    Register src) {
  if (SmiValuesAre31Bits()) {
    AddS32(dst, src, src);
  } else {
    SmiTag(dst, src);
  }
}

inline void MaglevAssembler::CheckInt32IsSmi(Register obj, Label* fail,
                                             Register scratch) {
  DCHECK(!SmiValuesAre32Bits());
  if (scratch == Register::no_reg()) {
    scratch = r0;
  }
  mov(scratch, obj);
  AddS32(scratch, scratch);
  JumpIf(kOverflow, fail);
}

inline void MaglevAssembler::SmiAddConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  AssertSmi(src);
  Move(dst, src);
  if (value != 0) {
    Register scratch = r0;
    Move(scratch, Smi::FromInt(value));
    if (SmiValuesAre31Bits()) {
      AddS32(dst, scratch);
    } else {
      AddS64(dst, scratch);
    }
    JumpIf(kOverflow, fail, distance);
  }
}

inline void MaglevAssembler::SmiSubConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  AssertSmi(src);
  Move(dst, src);
  if (value != 0) {
    Register scratch = r0;
    Move(scratch, Smi::FromInt(value));
    if (SmiValuesAre31Bits()) {
      SubS32(dst, scratch);
    } else {
      SubS64(dst, scratch);
    }
    JumpIf(kOverflow, fail, distance);
  }
}

inline void MaglevAssembler::MoveHeapNumber(Register dst, double value) {
  mov(dst, Operand::EmbeddedNumber(value));
}

inline Condition MaglevAssembler::IsRootConstant(Input input,
                                                 RootIndex root_index) {
  if (input.operand().IsRegister()) {
    CompareRoot(ToRegister(input), root_index);
  } else {
    DCHECK(input.operand().IsStackSlot());
    TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    LoadU64(scratch, ToMemOperand(input), scratch);
    CompareRoot(scratch, root_index);
  }
  return eq;
}

inline MemOperand MaglevAssembler::StackSlotOperand(StackSlot slot) {
  return MemOperand(fp, slot.index);
}

inline Register MaglevAssembler::GetFramePointer() { return fp; }

// TODO(Victorgomes): Unify this to use StackSlot struct.
inline MemOperand MaglevAssembler::GetStackSlot(
    const compiler::AllocatedOperand& operand) {
  return MemOperand(fp, GetFramePointerOffsetForStackSlot(operand));
}

inline MemOperand MaglevAssembler::ToMemOperand(
    const compiler::InstructionOperand& operand) {
  return GetStackSlot(compiler::AllocatedOperand::cast(operand));
}

inline MemOperand MaglevAssembler::ToMemOperand(const ValueLocation& location) {
  return ToMemOperand(location.operand());
}

inline void MaglevAssembler::BuildTypedArrayDataPointer(Register data_pointer,
                                                        Register object) {
  DCHECK_NE(data_pointer, object);
  LoadExternalPointerField(
      data_pointer,
      FieldMemOperand(object, JSTypedArray::kExternalPointerOffset));
  if (JSTypedArray::kMaxSizeInHeap == 0) return;
  // TemporaryRegisterScope temps(this);
  Register base = r0;
  if (COMPRESS_POINTERS_BOOL) {
    LoadU32(base, FieldMemOperand(object, JSTypedArray::kBasePointerOffset));
  } else {
    LoadU64(base, FieldMemOperand(object, JSTypedArray::kBasePointerOffset));
  }
  AddU64(data_pointer, data_pointer, base);
}

inline MemOperand MaglevAssembler::TypedArrayElementOperand(
    Register data_pointer, Register index, int element_size) {
  // TemporaryRegisterScope temps(this);
  Register temp = r0;
  ShiftLeftU64(temp, index, Operand(ShiftFromScale(element_size)));
  AddU64(data_pointer, data_pointer, temp);
  return MemOperand(data_pointer);
}

inline MemOperand MaglevAssembler::DataViewElementOperand(Register data_pointer,
                                                          Register index) {
  return MemOperand(data_pointer, index);
}

inline void MaglevAssembler::LoadTaggedFieldByIndex(Register result,
                                                    Register object,
                                                    Register index, int scale,
                                                    int offset) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  ShiftLeftU64(scratch, index, Operand(ShiftFromScale(scale)));
  AddU64(scratch, scratch, object);
  MacroAssembler::LoadTaggedField(result, FieldMemOperand(scratch, offset));
}

inline void MaglevAssembler::LoadBoundedSizeFromObject(Register result,
                                                       Register object,
                                                       int offset) {
  Move(result, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::LoadExternalPointerField(Register result,
                                                      MemOperand operand) {
  Move(result, operand);
}

void MaglevAssembler::LoadFixedArrayElement(Register result, Register array,
                                            Register index) {
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_ARRAY_TYPE, AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  LoadTaggedFieldByIndex(result, array, index, kTaggedSize,
                         OFFSET_OF_DATA_START(FixedArray));
}

inline void MaglevAssembler::LoadTaggedFieldWithoutDecompressing(
    Register result, Register object, int offset) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::LoadTaggedFieldWithoutDecompressing(
      result, FieldMemOperand(object, offset), scratch);
}

void MaglevAssembler::LoadFixedArrayElementWithoutDecompressing(
    Register result, Register array, Register index) {
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_ARRAY_TYPE, AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  int times_tagged_size = (kTaggedSize == 8) ? 3 : 2;
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register scratch2 = temps.AcquireScratch();
  ShiftLeftU64(scratch, index, Operand(times_tagged_size));
  MacroAssembler::LoadTaggedFieldWithoutDecompressing(
      result, FieldMemOperand(array, scratch, OFFSET_OF_DATA_START(FixedArray)),
      scratch2);
}

void MaglevAssembler::LoadFixedDoubleArrayElement(DoubleRegister result,
                                                  Register array,
                                                  Register index) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_DOUBLE_ARRAY_TYPE,
                     AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  ShiftLeftU64(scratch, index, Operand(kDoubleSizeLog2));
  LoadF64(result, FieldMemOperand(array, scratch,
                                  OFFSET_OF_DATA_START(FixedDoubleArray)));
}

inline void MaglevAssembler::StoreFixedDoubleArrayElement(
    Register array, Register index, DoubleRegister value) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  ShiftLeftU64(scratch, index, Operand(kDoubleSizeLog2));
  StoreF64(value, FieldMemOperand(array, scratch,
                                  OFFSET_OF_DATA_START(FixedDoubleArray)));
}

inline void MaglevAssembler::LoadSignedField(Register result,
                                             MemOperand operand, int size) {
  if (size == 1) {
    LoadS8(result, operand);
  } else if (size == 2) {
    LoadS16(result, operand);
  } else {
    DCHECK_EQ(size, 4);
    LoadS32(result, operand);
  }
}

inline void MaglevAssembler::LoadUnsignedField(Register result,
                                               MemOperand operand, int size) {
  if (size == 1) {
    LoadU8(result, operand);
  } else if (size == 2) {
    LoadU16(result, operand);
  } else {
    DCHECK_EQ(size, 4);
    LoadU32(result, operand);
  }
}

inline void MaglevAssembler::SetSlotAddressForTaggedField(Register slot_reg,
                                                          Register object,
                                                          int offset) {
  mov(slot_reg, object);
  AddS64(slot_reg, Operand(offset - kHeapObjectTag));
}

inline void MaglevAssembler::SetSlotAddressForFixedArrayElement(
    Register slot_reg, Register object, Register index) {
  // TemporaryRegisterScope temps(this);
  Register scratch = r0;
  mov(slot_reg, object);
  AddU64(slot_reg, Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
  ShiftLeftU64(scratch, index, Operand(kTaggedSizeLog2));
  AddU64(slot_reg, slot_reg, scratch);
}

inline void MaglevAssembler::StoreTaggedFieldNoWriteBarrier(Register object,
                                                            int offset,
                                                            Register value) {
  MacroAssembler::StoreTaggedField(value, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreFixedArrayElementNoWriteBarrier(
    Register array, Register index, Register value) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  ShiftLeftU64(scratch, index, Operand(kTaggedSizeLog2));
  AddU64(scratch, scratch, array);
  MacroAssembler::StoreTaggedField(
      value, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
}

inline void MaglevAssembler::StoreTaggedSignedField(Register object, int offset,
                                                    Register value) {
  AssertSmi(value);
  MacroAssembler::StoreTaggedField(value, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreTaggedSignedField(Register object, int offset,
                                                    Tagged<Smi> value) {
  TemporaryRegisterScope scope(this);
  Register scratch = r0;
  Move(scratch, value);
  MacroAssembler::StoreTaggedField(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreInt32Field(Register object, int offset,
                                             int32_t value) {
  TemporaryRegisterScope scope(this);
  Register scratch = r0;
  Move(scratch, value);
  StoreU32(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreField(MemOperand operand, Register value,
                                        int size) {
  DCHECK(size == 1 || size == 2 || size == 4);
  if (size == 1) {
    StoreU8(value, operand);
  } else if (size == 2) {
    StoreU16(value, operand);
  } else {
    DCHECK_EQ(size, 4);
    StoreU32(value, operand);
  }
}

inline void MaglevAssembler::ReverseByteOrder(Register value, int size) {
  if (size == 2) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreU16(value, MemOperand(sp));
    lrvh(value, MemOperand(sp));
    LoadS16(value, value);
    lay(sp, MemOperand(sp, kSystemPointerSize));
  } else if (size == 4) {
    lrvr(value, value);
    LoadS32(value, value);
  } else {
    DCHECK_EQ(size, 1);
  }
}

inline void MaglevAssembler::IncrementInt32(Register reg) {
  AddS32(reg, Operand(1));
}

inline void MaglevAssembler::DecrementInt32(Register reg) {
  SubS32(reg, Operand(1));
}

inline void MaglevAssembler::AddInt32(Register reg, int amount) {
  AddS32(reg, Operand(amount));
}

inline void MaglevAssembler::AndInt32(Register reg, int mask) {
  And(reg, Operand(mask));
  LoadU32(reg, reg);
}

inline void MaglevAssembler::OrInt32(Register reg, int mask) {
  Or(reg, Operand(mask));
  LoadU32(reg, reg);
}

inline void MaglevAssembler::ShiftLeft(Register reg, int amount) {
  ShiftLeftU32(reg, reg, Operand(amount));
}

inline void MaglevAssembler::IncrementAddress(Register reg, int32_t delta) {
  CHECK(is_int20(delta));
  lay(reg, MemOperand(reg, delta));
}

inline void MaglevAssembler::LoadAddress(Register dst, MemOperand location) {
  lay(dst, location);
}

inline void MaglevAssembler::Call(Label* target) {
  MacroAssembler::Call(target);
}

inline void MaglevAssembler::EmitEnterExitFrame(int extra_slots,
                                                StackFrame::Type frame_type,
                                                Register c_function,
                                                Register scratch) {
  EnterExitFrame(scratch, extra_slots, frame_type);
}

inline void MaglevAssembler::Move(StackSlot dst, Register src) {
  StoreU64(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(StackSlot dst, DoubleRegister src) {
  StoreF64(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(Register dst, StackSlot src) {
  LoadU64(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(DoubleRegister dst, StackSlot src) {
  LoadF64(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(MemOperand dst, Register src) {
  StoreU64(src, dst);
}
inline void MaglevAssembler::Move(Register dst, MemOperand src) {
  LoadU64(dst, src);
}
inline void MaglevAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  if (dst != src) {
    MacroAssembler::Move(dst, src);
  }
}
inline void MaglevAssembler::Move(Register dst, Tagged<Smi> src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, ExternalReference src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, Register src) {
  if (dst != src) {
    mov(dst, src);
  }
}
inline void MaglevAssembler::Move(Register dst, Tagged<TaggedIndex> i) {
  mov(dst, Operand(i.ptr()));
}
inline void MaglevAssembler::Move(Register dst, int32_t i) {
  mov(dst, Operand(i));
}
inline void MaglevAssembler::Move(DoubleRegister dst, double n) {
  TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch();
  MacroAssembler::LoadF64(dst, n, scratch);
}
inline void MaglevAssembler::Move(DoubleRegister dst, Float64 n) {
  TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch();
  MacroAssembler::LoadF64(dst, n, scratch);
}
inline void MaglevAssembler::Move(Register dst, Handle<HeapObject> obj) {
  MacroAssembler::Move(dst, obj);
}

inline void MaglevAssembler::Move(Register dst, uint32_t i) {
  // Move as a uint32 to avoid sign extension.
  mov(dst, Operand(i));
  LoadU32(dst, dst);
}

void MaglevAssembler::MoveTagged(Register dst, Handle<HeapObject> obj) {
#ifdef V8_COMPRESS_POINTERS
  MacroAssembler::Move(dst, obj, RelocInfo::COMPRESSED_EMBEDDED_OBJECT);
#else
  MacroAssembler::Move(dst, obj);
#endif
}

inline void MaglevAssembler::LoadFloat32(DoubleRegister dst, MemOperand src) {
  MacroAssembler::LoadF32AsF64(dst, src);
}
inline void MaglevAssembler::StoreFloat32(MemOperand dst, DoubleRegister src) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  DoubleRegister double_scratch = temps.AcquireScratchDouble();
  ledbr(double_scratch, src);
  MacroAssembler::StoreF32(double_scratch, dst);
}
inline void MaglevAssembler::LoadFloat64(DoubleRegister dst, MemOperand src) {
  MacroAssembler::LoadF64(dst, src);
}
inline void MaglevAssembler::StoreFloat64(MemOperand dst, DoubleRegister src) {
  MacroAssembler::StoreF64(src, dst);
}

inline void MaglevAssembler::LoadUnalignedFloat64(DoubleRegister dst,
                                                  Register base,
                                                  Register index) {
  LoadF64(dst, MemOperand(base, index));
}
inline void MaglevAssembler::LoadUnalignedFloat64AndReverseByteOrder(
    DoubleRegister dst, Register base, Register index) {
  TemporaryRegisterScope scope(this);
  Register scratch = r0;
  LoadU64(scratch, MemOperand(base, index));
  lrvgr(scratch, scratch);
  ldgr(dst, scratch);
}
inline void MaglevAssembler::StoreUnalignedFloat64(Register base,
                                                   Register index,
                                                   DoubleRegister src) {
  StoreF64(src, MemOperand(base, index));
}
inline void MaglevAssembler::ReverseByteOrderAndStoreUnalignedFloat64(
    Register base, Register index, DoubleRegister src) {
  TemporaryRegisterScope scope(this);
  Register scratch = r0;
  lgdr(scratch, src);
  lrvgr(scratch, scratch);
  StoreU64(scratch, MemOperand(base, index));
}

inline void MaglevAssembler::SignExtend32To64Bits(Register dst, Register src) {
  // No 64-bit registers.
  LoadS32(dst, src);
}
inline void MaglevAssembler::NegateInt32(Register val) {
  LoadS32(val, val);
  lcgr(val, val);
}

inline void MaglevAssembler::ToUint8Clamped(Register result,
                                            DoubleRegister value, Label* min,
                                            Label* max, Label* done) {
  TemporaryRegisterScope temps(this);
  DoubleRegister scratch = temps.AcquireScratchDouble();
  lzdr(kDoubleRegZero);
  CmpF64(kDoubleRegZero, value);
  // Set to 0 if NaN.
  JumpIf(Condition(CC_OF | ge), min);
  LoadF64(scratch, 255.0, r0);
  CmpF64(value, scratch);
  JumpIf(ge, max);
  // if value in [0, 255], then round up to the nearest.
  ConvertDoubleToInt32(result, value, kRoundToNearest);
  Jump(done);
}

template <typename NodeT>
inline void MaglevAssembler::DeoptIfBufferDetached(Register array,
                                                   Register scratch,
                                                   NodeT* node) {
  // A detached buffer leads to megamorphic feedback, so we won't have a deopt
  // loop if we deopt here.
  LoadTaggedField(scratch,
                  FieldMemOperand(array, JSArrayBufferView::kBufferOffset));
  LoadU32(scratch, FieldMemOperand(scratch, JSArrayBuffer::kBitFieldOffset));
  tmll(scratch, Operand(JSArrayBuffer::WasDetachedBit::kMask));
  EmitEagerDeoptIf(ne, DeoptimizeReason::kArrayBufferWasDetached, node);
}

inline void MaglevAssembler::LoadByte(Register dst, MemOperand src) {
  LoadU8(dst, src);
}

inline Condition MaglevAssembler::IsCallableAndNotUndetectable(
    Register map, Register scratch) {
  LoadU8(scratch, FieldMemOperand(map, Map::kBitFieldOffset));
  And(scratch, Operand(Map::Bits1::IsUndetectableBit::kMask |
                       Map::Bits1::IsCallableBit::kMask));
  CmpU32(scratch, Operand(Map::Bits1::IsCallableBit::kMask));
  return eq;
}

inline Condition MaglevAssembler::IsNotCallableNorUndetactable(
    Register map, Register scratch) {
  tmy(FieldMemOperand(map, Map::kBitFieldOffset),
      Operand(Map::Bits1::IsUndetectableBit::kMask |
              Map::Bits1::IsCallableBit::kMask));
  return eq;
}

inline void MaglevAssembler::LoadInstanceType(Register instance_type,
                                              Register heap_object) {
  LoadMap(instance_type, heap_object);
  LoadU16(instance_type,
          FieldMemOperand(instance_type, Map::kInstanceTypeOffset));
}

inline void MaglevAssembler::JumpIfObjectType(Register heap_object,
                                              InstanceType type, Label* target,
                                              Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectType(heap_object, scratch, scratch, type);
  JumpIf(kEqual, target, distance);
}

inline void MaglevAssembler::JumpIfNotObjectType(Register heap_object,
                                                 InstanceType type,
                                                 Label* target,
                                                 Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectType(heap_object, scratch, scratch, type);
  JumpIf(kNotEqual, target, distance);
}

inline void MaglevAssembler::AssertObjectType(Register heap_object,
                                              InstanceType type,
                                              AbortReason reason) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareObjectType(heap_object, scratch, scratch, type);
  Assert(kEqual, reason);
}

inline void MaglevAssembler::BranchOnObjectType(
    Register heap_object, InstanceType type, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectType(heap_object, scratch, scratch, type);
  Branch(kEqual, if_true, true_distance, fallthrough_when_true, if_false,
         false_distance, fallthrough_when_false);
}

inline void MaglevAssembler::JumpIfObjectTypeInRange(Register heap_object,
                                                     InstanceType lower_limit,
                                                     InstanceType higher_limit,
                                                     Label* target,
                                                     Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectTypeRange(heap_object, scratch, scratch, scratch, lower_limit,
                         higher_limit);
  JumpIf(kUnsignedLessThanEqual, target, distance);
}

inline void MaglevAssembler::JumpIfObjectTypeNotInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectTypeRange(heap_object, scratch, scratch, scratch, lower_limit,
                         higher_limit);
  JumpIf(kUnsignedGreaterThan, target, distance);
}

inline void MaglevAssembler::AssertObjectTypeInRange(Register heap_object,
                                                     InstanceType lower_limit,
                                                     InstanceType higher_limit,
                                                     AbortReason reason) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareObjectTypeRange(heap_object, scratch, scratch, scratch, lower_limit,
                         higher_limit);
  Assert(kUnsignedLessThanEqual, reason);
}

inline void MaglevAssembler::BranchOnObjectTypeInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* if_true, Label::Distance true_distance, bool fallthrough_when_true,
    Label* if_false, Label::Distance false_distance,
    bool fallthrough_when_false) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectTypeRange(heap_object, scratch, scratch, scratch, lower_limit,
                         higher_limit);
  Branch(kUnsignedLessThanEqual, if_true, true_distance, fallthrough_when_true,
         if_false, false_distance, fallthrough_when_false);
}

inline void MaglevAssembler::JumpIfJSAnyIsNotPrimitive(
    Register heap_object, Label* target, Label::Distance distance) {
  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::CompareObjectType<true>(heap_object, scratch, scratch,
                                          FIRST_JS_RECEIVER_TYPE);
  JumpIf(ge, target, distance);
}

inline void MaglevAssembler::CompareMapWithRoot(Register object,
                                                RootIndex index,
                                                Register scratch) {
  LoadMap(scratch, object);
  CompareRoot(scratch, index);
}

inline void MaglevAssembler::CompareInstanceType(Register map,
                                                 InstanceType instance_type) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::CompareInstanceType(map, scratch, instance_type);
}

inline Condition MaglevAssembler::CompareInstanceTypeRange(
    Register map, Register instance_type_out, InstanceType lower_limit,
    InstanceType higher_limit) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::CompareInstanceTypeRange(map, instance_type_out, scratch,
                                           lower_limit, higher_limit);
  return kUnsignedLessThanEqual;
}

inline void MaglevAssembler::CompareFloat64AndJumpIf(
    DoubleRegister src1, DoubleRegister src2, Condition cond, Label* target,
    Label* nan_failed, Label::Distance distance) {
  CmpF64(src1, src2);
  JumpIf(CC_OF, nan_failed);
  JumpIf(cond, target, distance);
}

inline void MaglevAssembler::CompareFloat64AndBranch(
    DoubleRegister src1, DoubleRegister src2, Condition cond,
    BasicBlock* if_true, BasicBlock* if_false, BasicBlock* next_block,
    BasicBlock* nan_failed) {
  CmpF64(src1, src2);
  JumpIf(CC_OF, nan_failed->label());
  Branch(cond, if_true, if_false, next_block);
}

inline void MaglevAssembler::PrepareCallCFunction(int num_reg_arguments,
                                                  int num_double_registers) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::PrepareCallCFunction(num_reg_arguments, num_double_registers,
                                       scratch);
}

inline void MaglevAssembler::CallSelf() {
  DCHECK(code_gen_state()->entry_label()->is_bound());
  Call(code_gen_state()->entry_label());
}

inline void MaglevAssembler::Jump(Label* target, Label::Distance) {
  // Any eager deopts should go through JumpIf to enable us to support the
  // `--deopt-every-n-times` stress mode. See EmitEagerDeoptStress.
  DCHECK(!IsDeoptLabel(target));
  b(target);
}

inline void MaglevAssembler::JumpToDeopt(Label* target) {
  DCHECK(IsDeoptLabel(target));
  b(target);
}

inline void MaglevAssemb
"""


```
Response: The user wants to understand the functionality of the `maglev-assembler.cc` file in the V8 JavaScript engine. I need to:

1. **Summarize the file's purpose:** Based on the name and content, it seems to be responsible for generating machine code instructions at a higher level of abstraction within the Maglev compiler.
2. **Identify its relationship with JavaScript:**  The operations performed in the assembler are directly related to how JavaScript objects and data are represented and manipulated in memory.
3. **Provide JavaScript examples:**  Demonstrate how the assembler functions translate into observable JavaScript behavior.
这个C++源代码文件 `v8/src/maglev/maglev-assembler.cc` 是 V8 JavaScript 引擎中 Maglev 编译器的一部分， 它的主要功能是 **提供用于生成目标机器码的汇编器接口**。

更具体地说，`MaglevAssembler` 类提供了一组高级的指令，这些指令抽象了底层机器码的细节，使得 Maglev 编译器的其他部分（例如 `MaglevCodeGenerator`）可以更容易地生成高效的机器代码。

以下是该文件的一些关键功能归纳：

* **内存分配:**  提供了分配堆内存的方法，例如 `AllocateHeapNumber` (分配 `HeapNumber` 对象) 和 `AllocateTwoByteString` (分配双字节字符串)。
* **数据加载和存储:**  提供了加载和存储不同类型数据的方法，包括从对象字段、数组元素、以及常量加载数据。例如 `LoadTaggedField`, `StoreTaggedField`, `LoadDataField`。
* **控制流:** 提供了生成条件跳转指令的方法，这些跳转基于对象的类型、属性或值。例如 `JumpIfNotUndetectable`, `JumpIfUndetectable`, `JumpIfNotCallable`, `ToBoolean`, `TestTypeOf`。
* **类型检查:** 提供了检查对象类型的方法，例如检查是否为 Smi (小整数)、HeapObject (堆对象)、以及其他特定的对象类型。
* **内联缓存和属性访问:**  包含了与属性访问相关的逻辑，例如加载数据字段 ( `LoadDataField`)。
* **写入屏障:**  实现了垃圾回收的写入屏障机制，用于跟踪对象引用关系的变化，例如 `StoreTaggedFieldWithWriteBarrier`, `StoreFixedArrayElementWithWriteBarrier`。
* **调用内置函数和运行时函数:** 提供了调用 V8 内部内置函数 (`Builtin`) 和运行时函数 (`Runtime`) 的方法。
* **常量物化:** 提供了将常量值加载到寄存器的方法 (`MaterialiseValueNode`)，并根据常量的值选择合适的表示方式 (Smi 或 HeapNumber)。
* **TryMigrateInstance:** 提供了尝试迁移对象实例的逻辑，这与 V8 的对象优化有关。

**与 JavaScript 的功能关系及 JavaScript 示例:**

`MaglevAssembler` 中的操作直接反映了 JavaScript 引擎在底层如何处理 JavaScript 代码。以下是一些将 `MaglevAssembler` 的功能与 JavaScript 代码关联的例子：

**1. 内存分配 (`AllocateHeapNumber`, `AllocateTwoByteString`)**

当 JavaScript 代码创建一个新的数字或字符串时，`MaglevAssembler` 中的内存分配方法会被调用。

```javascript
// JavaScript 示例
let num = 1.23; // 会在堆上分配一个 HeapNumber 对象
let str = "hello"; // 会在堆上分配一个字符串对象
```

**2. 数据加载和存储 (`LoadTaggedField`, `StoreTaggedField`)**

当访问或修改 JavaScript 对象的属性时，会使用这些方法来加载或存储对象字段的值。

```javascript
// JavaScript 示例
let obj = { x: 10 };
console.log(obj.x); // LoadTaggedField 会被用来加载 obj 的 "x" 属性
obj.x = 20;        // StoreTaggedField 会被用来存储新的值到 obj 的 "x" 属性
```

**3. 控制流和类型检查 (`JumpIfSmi`, `JumpIfNotCallable`, `ToBoolean`, `TestTypeOf`)**

JavaScript 中的条件语句 (`if`, `else`)、循环 (`for`, `while`) 以及类型检查操作 (`typeof`) 在底层都会转化为 `MaglevAssembler` 中的控制流和类型检查指令。

```javascript
// JavaScript 示例
let value = "world";

if (typeof value === "string") { // TestTypeOf 会被用来检查 value 的类型
  console.log("It's a string!");
}

function myFunction() {}
if (typeof myFunction === "function") { // JumpIfNotCallable 会被用来检查 myFunction 是否可调用
  myFunction();
}

let boolValue = !!value; // ToBoolean 会被用来将 value 转换为布尔值
```

**4. 写入屏障 (`StoreTaggedFieldWithWriteBarrier`)**

当修改一个可能包含对象引用的 JavaScript 对象的属性时，写入屏障会被调用，以确保垃圾回收器能够正确地跟踪对象间的引用。

```javascript
// JavaScript 示例
let obj1 = {};
let obj2 = { ref: obj1 }; // StoreTaggedFieldWithWriteBarrier 会被用来存储 obj1 的引用到 obj2
```

**总结:**

`v8/src/maglev/maglev-assembler.cc` 文件是 Maglev 编译器的核心组成部分，它提供了一个平台无关的接口来生成底层的机器代码，从而执行 JavaScript 代码。它所提供的各种指令和功能都直接对应着 JavaScript 语言的特性和 V8 引擎的内部实现机制。理解 `MaglevAssembler` 的功能有助于深入了解 JavaScript 引擎的编译和执行过程。

Prompt: 
```
这是目录为v8/src/maglev/maglev-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/maglev/maglev-assembler.h"

#include "src/builtins/builtins-inl.h"
#include "src/codegen/reglist.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-code-generator.h"
#include "src/numbers/conversions.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

void MaglevAssembler::AllocateHeapNumber(RegisterSnapshot register_snapshot,
                                         Register result,
                                         DoubleRegister value) {
  // In the case we need to call the runtime, we should spill the value
  // register. Even if it is not live in the next node, otherwise the
  // allocation call might trash it.
  register_snapshot.live_double_registers.set(value);
  Allocate(register_snapshot, result, sizeof(HeapNumber));
  SetMapAsRoot(result, RootIndex::kHeapNumberMap);
  StoreFloat64(FieldMemOperand(result, offsetof(HeapNumber, value_)), value);
}

void MaglevAssembler::AllocateTwoByteString(RegisterSnapshot register_snapshot,
                                            Register result, int length) {
  int size = SeqTwoByteString::SizeFor(length);
  Allocate(register_snapshot, result, size);
  StoreTaggedSignedField(result, size - kObjectAlignment, Smi::zero());
  SetMapAsRoot(result, RootIndex::kSeqTwoByteStringMap);
  StoreInt32Field(result, offsetof(Name, raw_hash_field_),
                  Name::kEmptyHashField);
  StoreInt32Field(result, offsetof(String, length_), length);
}

Register MaglevAssembler::FromAnyToRegister(const Input& input,
                                            Register scratch) {
  if (input.operand().IsConstant()) {
    input.node()->LoadToRegister(this, scratch);
    return scratch;
  }
  const compiler::AllocatedOperand& operand =
      compiler::AllocatedOperand::cast(input.operand());
  if (operand.IsRegister()) {
    return ToRegister(input);
  } else {
    DCHECK(operand.IsStackSlot());
    Move(scratch, ToMemOperand(input));
    return scratch;
  }
}

void MaglevAssembler::LoadSingleCharacterString(Register result,
                                                int char_code) {
  DCHECK_GE(char_code, 0);
  DCHECK_LT(char_code, String::kMaxOneByteCharCode);
  Register table = result;
  LoadRoot(table, RootIndex::kSingleCharacterStringTable);
  LoadTaggedField(result, table,
                  OFFSET_OF_DATA_START(FixedArray) + char_code * kTaggedSize);
}

void MaglevAssembler::LoadDataField(const PolymorphicAccessInfo& access_info,
                                    Register result, Register object,
                                    Register scratch) {
  Register load_source = object;
  // Resolve property holder.
  if (access_info.holder().has_value()) {
    load_source = scratch;
    Move(load_source, access_info.holder().value().object());
  }
  FieldIndex field_index = access_info.field_index();
  if (!field_index.is_inobject()) {
    Register load_source_object = load_source;
    if (load_source == object) {
      load_source = scratch;
    }
    // The field is in the property array, first load it from there.
    AssertNotSmi(load_source_object);
    LoadTaggedField(load_source, load_source_object,
                    JSReceiver::kPropertiesOrHashOffset);
  }
  AssertNotSmi(load_source);
  LoadTaggedField(result, load_source, field_index.offset());
}

void MaglevAssembler::JumpIfNotUndetectable(Register object, Register scratch,
                                            CheckType check_type, Label* target,
                                            Label::Distance distance) {
  if (check_type == CheckType::kCheckHeapObject) {
    JumpIfSmi(object, target, distance);
  } else if (v8_flags.debug_code) {
    AssertNotSmi(object);
  }
  // For heap objects, check the map's undetectable bit.
  LoadMap(scratch, object);
  TestUint8AndJumpIfAllClear(FieldMemOperand(scratch, Map::kBitFieldOffset),
                             Map::Bits1::IsUndetectableBit::kMask, target,
                             distance);
}

void MaglevAssembler::JumpIfUndetectable(Register object, Register scratch,
                                         CheckType check_type, Label* target,
                                         Label::Distance distance) {
  Label detectable;
  if (check_type == CheckType::kCheckHeapObject) {
    JumpIfSmi(object, &detectable, Label::kNear);
  } else if (v8_flags.debug_code) {
    AssertNotSmi(object);
  }
  // For heap objects, check the map's undetectable bit.
  LoadMap(scratch, object);
  TestUint8AndJumpIfAnySet(FieldMemOperand(scratch, Map::kBitFieldOffset),
                           Map::Bits1::IsUndetectableBit::kMask, target,
                           distance);
  bind(&detectable);
}

void MaglevAssembler::JumpIfNotCallable(Register object, Register scratch,
                                        CheckType check_type, Label* target,
                                        Label::Distance distance) {
  if (check_type == CheckType::kCheckHeapObject) {
    JumpIfSmi(object, target, distance);
  } else if (v8_flags.debug_code) {
    AssertNotSmi(object);
  }
  LoadMap(scratch, object);
  static_assert(Map::kBitFieldOffsetEnd + 1 - Map::kBitFieldOffset == 1);
  TestUint8AndJumpIfAllClear(FieldMemOperand(scratch, Map::kBitFieldOffset),
                             Map::Bits1::IsCallableBit::kMask, target,
                             distance);
}

void MaglevAssembler::EnsureWritableFastElements(
    RegisterSnapshot register_snapshot, Register elements, Register object,
    Register scratch) {
  ZoneLabelRef done(this);
  CompareMapWithRoot(elements, RootIndex::kFixedArrayMap, scratch);
  JumpToDeferredIf(
      kNotEqual,
      [](MaglevAssembler* masm, ZoneLabelRef done, Register object,
         Register result_reg, RegisterSnapshot snapshot) {
        {
          snapshot.live_registers.clear(result_reg);
          snapshot.live_tagged_registers.clear(result_reg);
          SaveRegisterStateForCall save_register_state(masm, snapshot);
          __ CallBuiltin<Builtin::kCopyFastSmiOrObjectElements>(object);
          save_register_state.DefineSafepoint();
          __ Move(result_reg, kReturnRegister0);
        }
        __ Jump(*done);
      },
      done, object, elements, register_snapshot);
  bind(*done);
}

void MaglevAssembler::ToBoolean(Register value, CheckType check_type,
                                ZoneLabelRef is_true, ZoneLabelRef is_false,
                                bool fallthrough_when_true) {
  TemporaryRegisterScope temps(this);

  if (check_type == CheckType::kCheckHeapObject) {
    // Check if {{value}} is Smi.
    Condition is_smi = CheckSmi(value);
    JumpToDeferredIf(
        is_smi,
        [](MaglevAssembler* masm, Register value, ZoneLabelRef is_true,
           ZoneLabelRef is_false) {
          // Check if {value} is not zero.
          __ CompareSmiAndJumpIf(value, Smi::FromInt(0), kEqual, *is_false);
          __ Jump(*is_true);
        },
        value, is_true, is_false);
  } else if (v8_flags.debug_code) {
    AssertNotSmi(value);
  }

#if V8_STATIC_ROOTS_BOOL
  // Check if {{value}} is a falsey root or the true value.
  // Undefined is the first root, so it's the smallest possible pointer
  // value, which means we don't have to subtract it for the range check.
  ReadOnlyRoots roots(isolate_);
  static_assert(StaticReadOnlyRoot::kFirstAllocatedRoot ==
                StaticReadOnlyRoot::kUndefinedValue);
  static_assert(StaticReadOnlyRoot::kUndefinedValue + sizeof(Undefined) ==
                StaticReadOnlyRoot::kNullValue);
  static_assert(StaticReadOnlyRoot::kNullValue + sizeof(Null) ==
                StaticReadOnlyRoot::kempty_string);
  static_assert(StaticReadOnlyRoot::kempty_string +
                    SeqOneByteString::SizeFor(0) ==
                StaticReadOnlyRoot::kFalseValue);
  static_assert(StaticReadOnlyRoot::kFalseValue + sizeof(False) ==
                StaticReadOnlyRoot::kTrueValue);
  CompareInt32AndJumpIf(value, StaticReadOnlyRoot::kTrueValue,
                        kUnsignedLessThan, *is_false);
  // Reuse the condition flags from the above int32 compare to also check for
  // the true value itself.
  JumpIf(kEqual, *is_true);
#else
  // Check if {{value}} is false.
  JumpIfRoot(value, RootIndex::kFalseValue, *is_false);

  // Check if {{value}} is true.
  JumpIfRoot(value, RootIndex::kTrueValue, *is_true);

  // Check if {{value}} is empty string.
  JumpIfRoot(value, RootIndex::kempty_string, *is_false);

  // Only check null and undefined if we're not going to check the
  // undetectable bit.
  if (compilation_info()
          ->broker()
          ->dependencies()
          ->DependOnNoUndetectableObjectsProtector()) {
    // Check if {{value}} is undefined.
    JumpIfRoot(value, RootIndex::kUndefinedValue, *is_false);

    // Check if {{value}} is null.
    JumpIfRoot(value, RootIndex::kNullValue, *is_false);
  }
#endif
  Register map = temps.AcquireScratch();
  LoadMap(map, value);

  if (!compilation_info()
           ->broker()
           ->dependencies()
           ->DependOnNoUndetectableObjectsProtector()) {
    // Check if {{value}} is undetectable.
    TestUint8AndJumpIfAnySet(FieldMemOperand(map, Map::kBitFieldOffset),
                             Map::Bits1::IsUndetectableBit::kMask, *is_false);
  }

  // Check if {{value}} is a HeapNumber.
  JumpIfRoot(map, RootIndex::kHeapNumberMap,
             MakeDeferredCode(
                 [](MaglevAssembler* masm, Register value, ZoneLabelRef is_true,
                    ZoneLabelRef is_false) {
                   __ CompareDoubleAndJumpIfZeroOrNaN(
                       FieldMemOperand(value, offsetof(HeapNumber, value_)),
                       *is_false);
                   __ Jump(*is_true);
                 },
                 value, is_true, is_false));

  // Check if {{value}} is a BigInt.
  // {{map}} is not needed after this check, we pass to the deferred code, so it
  // can be added to the temporary registers.
  JumpIfRoot(map, RootIndex::kBigIntMap,
             MakeDeferredCode(
                 [](MaglevAssembler* masm, Register value, Register map,
                    ZoneLabelRef is_true, ZoneLabelRef is_false) {
                   TemporaryRegisterScope temps(masm);
                   temps.IncludeScratch(map);
                   __ TestInt32AndJumpIfAllClear(
                       FieldMemOperand(value, offsetof(BigInt, bitfield_)),
                       BigInt::LengthBits::kMask, *is_false);
                   __ Jump(*is_true);
                 },
                 value, map, is_true, is_false));
  // Otherwise true.
  if (!fallthrough_when_true) {
    Jump(*is_true);
  }
}

void MaglevAssembler::MaterialiseValueNode(Register dst, ValueNode* value) {
  switch (value->opcode()) {
    case Opcode::kInt32Constant: {
      int32_t int_value = value->Cast<Int32Constant>()->value();
      if (Smi::IsValid(int_value)) {
        Move(dst, Smi::FromInt(int_value));
      } else {
        MoveHeapNumber(dst, int_value);
      }
      return;
    }
    case Opcode::kUint32Constant: {
      uint32_t uint_value = value->Cast<Uint32Constant>()->value();
      if (Smi::IsValid(uint_value)) {
        Move(dst, Smi::FromInt(uint_value));
      } else {
        MoveHeapNumber(dst, uint_value);
      }
      return;
    }
    case Opcode::kFloat64Constant: {
      double double_value =
          value->Cast<Float64Constant>()->value().get_scalar();
      int smi_value;
      if (DoubleToSmiInteger(double_value, &smi_value)) {
        Move(dst, Smi::FromInt(smi_value));
      } else {
        MoveHeapNumber(dst, double_value);
      }
      return;
    }
    default:
      break;
  }
  DCHECK(!value->allocation().IsConstant());
  DCHECK(value->allocation().IsAnyStackSlot());
  using D = NewHeapNumberDescriptor;
  DoubleRegister builtin_input_value = D::GetDoubleRegisterParameter(D::kValue);
  MemOperand src = ToMemOperand(value->allocation());
  switch (value->properties().value_representation()) {
    case ValueRepresentation::kInt32: {
      Label done;
      TemporaryRegisterScope temps(this);
      Register scratch = temps.AcquireScratch();
      Move(scratch, src);
      SmiTagInt32AndJumpIfSuccess(dst, scratch, &done, Label::kNear);
      // If smi tagging fails, instead of bailing out (deopting), we change
      // representation to a HeapNumber.
      Int32ToDouble(builtin_input_value, scratch);
      CallBuiltin<Builtin::kNewHeapNumber>(builtin_input_value);
      Move(dst, kReturnRegister0);
      bind(&done);
      break;
    }
    case ValueRepresentation::kUint32: {
      Label done;
      TemporaryRegisterScope temps(this);
      Register scratch = temps.AcquireScratch();
      Move(scratch, src);
      SmiTagUint32AndJumpIfSuccess(dst, scratch, &done, Label::kNear);
      // If smi tagging fails, instead of bailing out (deopting), we change
      // representation to a HeapNumber.
      Uint32ToDouble(builtin_input_value, scratch);
      CallBuiltin<Builtin::kNewHeapNumber>(builtin_input_value);
      Move(dst, kReturnRegister0);
      bind(&done);
      break;
    }
    case ValueRepresentation::kFloat64:
      LoadFloat64(builtin_input_value, src);
      CallBuiltin<Builtin::kNewHeapNumber>(builtin_input_value);
      Move(dst, kReturnRegister0);
      break;
    case ValueRepresentation::kHoleyFloat64: {
      Label done, box;
      JumpIfNotHoleNan(src, &box, Label::kNear);
      LoadRoot(dst, RootIndex::kUndefinedValue);
      Jump(&done);
      bind(&box);
      LoadFloat64(builtin_input_value, src);
      CallBuiltin<Builtin::kNewHeapNumber>(builtin_input_value);
      Move(dst, kReturnRegister0);
      bind(&done);
      break;
    }
    case ValueRepresentation::kIntPtr:
    case ValueRepresentation::kTagged:
      UNREACHABLE();
  }
}

void MaglevAssembler::TestTypeOf(
    Register object, interpreter::TestTypeOfFlags::LiteralFlag literal,
    Label* is_true, Label::Distance true_distance, bool fallthrough_when_true,
    Label* is_false, Label::Distance false_distance,
    bool fallthrough_when_false) {
  // If both true and false are fallthroughs, we don't have to do anything.
  if (fallthrough_when_true && fallthrough_when_false) return;

  // IMPORTANT: Note that `object` could be a register that aliases registers in
  // the TemporaryRegisterScope. Make sure that all reads of `object` are before
  // any writes to scratch registers
  using LiteralFlag = interpreter::TestTypeOfFlags::LiteralFlag;
  switch (literal) {
    case LiteralFlag::kNumber: {
      MaglevAssembler::TemporaryRegisterScope temps(this);
      Register scratch = temps.AcquireScratch();
      JumpIfSmi(object, is_true, true_distance);
      CompareMapWithRoot(object, RootIndex::kHeapNumberMap, scratch);
      Branch(kEqual, is_true, true_distance, fallthrough_when_true, is_false,
             false_distance, fallthrough_when_false);
      return;
    }
    case LiteralFlag::kString: {
      JumpIfSmi(object, is_false, false_distance);
      CheckJSAnyIsStringAndBranch(object, is_true, true_distance,
                                  fallthrough_when_true, is_false,
                                  false_distance, fallthrough_when_false);
      return;
    }
    case LiteralFlag::kSymbol: {
      JumpIfSmi(object, is_false, false_distance);
      BranchOnObjectType(object, SYMBOL_TYPE, is_true, true_distance,
                         fallthrough_when_true, is_false, false_distance,
                         fallthrough_when_false);
      return;
    }
    case LiteralFlag::kBoolean:
      JumpIfRoot(object, RootIndex::kTrueValue, is_true, true_distance);
      CompareRoot(object, RootIndex::kFalseValue);
      Branch(kEqual, is_true, true_distance, fallthrough_when_true, is_false,
             false_distance, fallthrough_when_false);
      return;
    case LiteralFlag::kBigInt: {
      JumpIfSmi(object, is_false, false_distance);
      BranchOnObjectType(object, BIGINT_TYPE, is_true, true_distance,
                         fallthrough_when_true, is_false, false_distance,
                         fallthrough_when_false);
      return;
    }
    case LiteralFlag::kUndefined: {
      MaglevAssembler::TemporaryRegisterScope temps(this);
      Register map = temps.AcquireScratch();
      // Make sure `object` isn't a valid temp here, since we re-use it.
      DCHECK(!temps.Available().has(object));
      JumpIfSmi(object, is_false, false_distance);
      // Check it has the undetectable bit set and it is not null.
      LoadMap(map, object);
      TestUint8AndJumpIfAllClear(FieldMemOperand(map, Map::kBitFieldOffset),
                                 Map::Bits1::IsUndetectableBit::kMask, is_false,
                                 false_distance);
      CompareRoot(object, RootIndex::kNullValue);
      Branch(kNotEqual, is_true, true_distance, fallthrough_when_true, is_false,
             false_distance, fallthrough_when_false);
      return;
    }
    case LiteralFlag::kFunction: {
      MaglevAssembler::TemporaryRegisterScope temps(this);
      Register scratch = temps.AcquireScratch();
      JumpIfSmi(object, is_false, false_distance);
      // Check if callable bit is set and not undetectable.
      LoadMap(scratch, object);
      Branch(IsCallableAndNotUndetectable(scratch, scratch), is_true,
             true_distance, fallthrough_when_true, is_false, false_distance,
             fallthrough_when_false);
      return;
    }
    case LiteralFlag::kObject: {
      MaglevAssembler::TemporaryRegisterScope temps(this);
      Register scratch = temps.AcquireScratch();
      JumpIfSmi(object, is_false, false_distance);
      // If the object is null then return true.
      JumpIfRoot(object, RootIndex::kNullValue, is_true, true_distance);
      // Check if the object is a receiver type,
      LoadMap(scratch, object);
      CompareInstanceTypeAndJumpIf(scratch, FIRST_JS_RECEIVER_TYPE, kLessThan,
                                   is_false, false_distance);
      // ... and is not undefined (undetectable) nor callable.
      Branch(IsNotCallableNorUndetactable(scratch, scratch), is_true,
             true_distance, fallthrough_when_true, is_false, false_distance,
             fallthrough_when_false);
      return;
    }
    case LiteralFlag::kOther:
      if (!fallthrough_when_false) {
        Jump(is_false, false_distance);
      }
      return;
  }
  UNREACHABLE();
}

template <MaglevAssembler::StoreMode store_mode>
void MaglevAssembler::CheckAndEmitDeferredWriteBarrier(
    Register object, OffsetTypeFor<store_mode> offset, Register value,
    RegisterSnapshot register_snapshot, ValueIsCompressed value_is_compressed,
    ValueCanBeSmi value_can_be_smi) {
  ZoneLabelRef done(this);
  Label* deferred_write_barrier = MakeDeferredCode(
      [](MaglevAssembler* masm, ZoneLabelRef done, Register object,
         OffsetTypeFor<store_mode> offset, Register value,
         RegisterSnapshot register_snapshot, ValueIsCompressed value_type) {
        ASM_CODE_COMMENT_STRING(masm, "Write barrier slow path");
        if (PointerCompressionIsEnabled() && value_type == kValueIsCompressed) {
          __ DecompressTagged(value, value);
        }

        {
          // Use the value as the scratch register if possible, since
          // CheckPageFlag emits slightly better code when value == scratch.
          MaglevAssembler::TemporaryRegisterScope temp(masm);
          Register scratch = temp.AcquireScratch();
          if (value != object && !register_snapshot.live_registers.has(value)) {
            scratch = value;
          }
          __ CheckPageFlag(value, scratch,
                           MemoryChunk::kPointersToHereAreInterestingMask,
                           kEqual, *done);
        }

        Register stub_object_reg = WriteBarrierDescriptor::ObjectRegister();
        Register slot_reg = WriteBarrierDescriptor::SlotAddressRegister();

        RegList saved;
        // The RecordWrite stub promises to restore all allocatable registers,
        // but not necessarily non-allocatable registers like temporaries. Make
        // sure we're not trying to keep any non-allocatable registers alive.
        CHECK((register_snapshot.live_registers - kAllocatableGeneralRegisters)
                  .is_empty());
        if (object != stub_object_reg &&
            register_snapshot.live_registers.has(stub_object_reg)) {
          saved.set(stub_object_reg);
        }
        if (register_snapshot.live_registers.has(slot_reg)) {
          saved.set(slot_reg);
        }

        __ PushAll(saved);

        if (object != stub_object_reg) {
          __ Move(stub_object_reg, object);
          object = stub_object_reg;
        }

        if constexpr (store_mode == kElement) {
          __ SetSlotAddressForFixedArrayElement(slot_reg, object, offset);
        } else {
          static_assert(store_mode == kField);
          __ SetSlotAddressForTaggedField(slot_reg, object, offset);
        }

        SaveFPRegsMode const save_fp_mode =
            !register_snapshot.live_double_registers.is_empty()
                ? SaveFPRegsMode::kSave
                : SaveFPRegsMode::kIgnore;

        __ CallRecordWriteStub(object, slot_reg, save_fp_mode);

        __ PopAll(saved);
        __ Jump(*done);
      },
      done, object, offset, value, register_snapshot, value_is_compressed);

  if (!value_can_be_smi) {
    AssertNotSmi(value);
  }

#if V8_STATIC_ROOTS_BOOL
  // Quick check for Read-only and small Smi values.
  static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
  JumpIfUnsignedLessThan(value, kRegularPageSize, *done);
#endif  // V8_STATIC_ROOTS_BOOL

  if (value_can_be_smi) {
    JumpIfSmi(value, *done);
  }

  MaglevAssembler::TemporaryRegisterScope temp(this);
  Register scratch = temp.AcquireScratch();
  CheckPageFlag(object, scratch,
                MemoryChunk::kPointersFromHereAreInterestingMask, kNotEqual,
                deferred_write_barrier);
  bind(*done);
}

#ifdef V8_ENABLE_SANDBOX

void MaglevAssembler::CheckAndEmitDeferredIndirectPointerWriteBarrier(
    Register object, int offset, Register value,
    RegisterSnapshot register_snapshot, IndirectPointerTag tag) {
  ZoneLabelRef done(this);
  Label* deferred_write_barrier = MakeDeferredCode(
      [](MaglevAssembler* masm, ZoneLabelRef done, Register object, int offset,
         Register value, RegisterSnapshot register_snapshot,
         IndirectPointerTag tag) {
        ASM_CODE_COMMENT_STRING(masm, "Write barrier slow path");

        Register stub_object_reg =
            IndirectPointerWriteBarrierDescriptor::ObjectRegister();
        Register slot_reg =
            IndirectPointerWriteBarrierDescriptor::SlotAddressRegister();
        Register tag_reg =
            IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister();

        RegList saved;
        if (object != stub_object_reg &&
            register_snapshot.live_registers.has(stub_object_reg)) {
          saved.set(stub_object_reg);
        }
        if (register_snapshot.live_registers.has(slot_reg)) {
          saved.set(slot_reg);
        }
        if (register_snapshot.live_registers.has(tag_reg)) {
          saved.set(tag_reg);
        }

        __ PushAll(saved);

        if (object != stub_object_reg) {
          __ Move(stub_object_reg, object);
          object = stub_object_reg;
        }
        __ SetSlotAddressForTaggedField(slot_reg, object, offset);
        __ Move(tag_reg, tag);

        SaveFPRegsMode const save_fp_mode =
            !register_snapshot.live_double_registers.is_empty()
                ? SaveFPRegsMode::kSave
                : SaveFPRegsMode::kIgnore;

        __ CallBuiltin(Builtins::IndirectPointerBarrier(save_fp_mode));

        __ PopAll(saved);
        __ Jump(*done);
      },
      done, object, offset, value, register_snapshot, tag);

  AssertNotSmi(value);

  JumpIfMarking(deferred_write_barrier);
  bind(*done);
}

#endif  // V8_ENABLE_SANDBOX

void MaglevAssembler::StoreTaggedFieldWithWriteBarrier(
    Register object, int offset, Register value,
    RegisterSnapshot register_snapshot, ValueIsCompressed value_is_compressed,
    ValueCanBeSmi value_can_be_smi) {
  AssertNotSmi(object);
  StoreTaggedFieldNoWriteBarrier(object, offset, value);
  CheckAndEmitDeferredWriteBarrier<kField>(
      object, offset, value, register_snapshot, value_is_compressed,
      value_can_be_smi);
}

#ifdef V8_ENABLE_SANDBOX

void MaglevAssembler::StoreTrustedPointerFieldWithWriteBarrier(
    Register object, int offset, Register value,
    RegisterSnapshot register_snapshot, IndirectPointerTag tag) {
  AssertNotSmi(object);
  StoreTrustedPointerFieldNoWriteBarrier(object, offset, value);
  CheckAndEmitDeferredIndirectPointerWriteBarrier(object, offset, value,
                                                  register_snapshot, tag);
}

#endif  // V8_ENABLE_SANDBOX

void MaglevAssembler::StoreFixedArrayElementWithWriteBarrier(
    Register array, Register index, Register value,
    RegisterSnapshot register_snapshot) {
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_ARRAY_TYPE, AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  StoreFixedArrayElementNoWriteBarrier(array, index, value);
  CheckAndEmitDeferredWriteBarrier<kElement>(
      array, index, value, register_snapshot, kValueIsDecompressed,
      kValueCanBeSmi);
}

void MaglevAssembler::GenerateCheckConstTrackingLetCellFooter(Register context,
                                                              Register data,
                                                              int index,
                                                              Label* done) {
  Label smi_data, deopt;

  // Load the const tracking let side data.
  LoadTaggedField(
      data, context,
      Context::OffsetOfElementAt(Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX));

  LoadTaggedField(data, data,
                  FixedArray::OffsetOfElementAt(
                      index - Context::MIN_CONTEXT_EXTENDED_SLOTS));

  // Load property.
  JumpIfSmi(data, &smi_data, Label::kNear);
  JumpIfRoot(data, RootIndex::kUndefinedValue, &deopt);
  if (v8_flags.debug_code) {
    AssertObjectType(data, CONTEXT_SIDE_PROPERTY_CELL_TYPE,
                     AbortReason::kUnexpectedValue);
  }
  LoadTaggedField(data, data,
                  ContextSidePropertyCell::kPropertyDetailsRawOffset);

  // It must be different than kConst.
  bind(&smi_data);
  CompareTaggedAndJumpIf(data, ContextSidePropertyCell::Const(), kNotEqual,
                         done, Label::kNear);
  bind(&deopt);
}

void MaglevAssembler::TryMigrateInstance(Register object,
                                         RegisterSnapshot& register_snapshot,
                                         Label* fail) {
  Register return_val = Register::no_reg();
  {
    SaveRegisterStateForCall save_register_state(this, register_snapshot);

    Push(object);
    Move(kContextRegister, native_context().object());
    CallRuntime(Runtime::kTryMigrateInstance);
    save_register_state.DefineSafepoint();

    // Make sure the return value is preserved across the live register
    // restoring pop all.
    return_val = kReturnRegister0;
    MaglevAssembler::TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    if (register_snapshot.live_registers.has(return_val)) {
      DCHECK(!register_snapshot.live_registers.has(scratch));
      Move(scratch, return_val);
      return_val = scratch;
    }
  }

  // On failure, the returned value is Smi zero.
  CompareTaggedAndJumpIf(return_val, Smi::zero(), kEqual, fail);
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8

"""

```
Response: The user wants to understand the functionality of the C++ code in `v8/src/compiler/simplified-operator.cc`. This file seems to be related to the V8 JavaScript engine's compiler.

My plan is to:
1. Identify the main purpose of the code by looking at the class names and functions.
2. Explain the core concepts in simple terms.
3. If there's a direct connection to JavaScript features, provide a JavaScript example.
这个C++代码文件 `simplified-operator.cc` 的主要功能是**定义了 V8 编译器中简化阶段使用的操作符 (Operators)**。

更具体地说，它做了以下几件事情：

1. **定义了各种操作符的数据结构:**  它定义了表示不同操作的C++结构体，例如 `FieldAccess` (访问对象字段), `ElementAccess` (访问数组元素), `ObjectAccess` (访问一般对象属性) 等。这些结构体包含了操作所需的信息，比如内存偏移量、数据类型、是否需要进行写屏障等。

2. **为操作符定义了元数据:**  它定义了用于描述操作符属性的元数据，例如操作符的 `IrOpcode` (中间表示代码),  是否是纯函数 (`kPure`), 是否可消除 (`kEliminatable`), 输入和输出的数量等。

3. **提供了创建和访问操作符参数的方法:** 它提供了辅助函数，例如 `FieldAccessOf`, `ElementAccessOf` 等，用于从 `Operator` 对象中提取特定的参数信息。

4. **定义了特定操作的参数结构:** 对于一些复杂的操作，它定义了额外的参数结构来存储更详细的信息，例如 `CheckMapsParameters` (用于检查对象的Map), `NumberOperationParameters` (用于数值运算) 等。

5. **实现了操作符的比较和哈希函数:**  为了在编译器的优化阶段能够有效地比较和存储操作符，它重载了 `operator==` 和 `hash_value` 函数。

**与 JavaScript 功能的关系:**

这个文件定义的操作符直接对应了 JavaScript 语言中的各种操作。在 V8 的编译过程中，JavaScript 代码会被转换成中间表示 (Intermediate Representation, IR)，而这些操作符就是 IR 的基本构建块。简化阶段的目标是将复杂的、高层次的 IR 操作转换成更简单、更接近机器指令的操作，以便后续的优化和代码生成。

**JavaScript 例子:**

考虑以下简单的 JavaScript 代码：

```javascript
function add(obj) {
  return obj.x + 10;
}
```

当 V8 编译这个 `add` 函数时，会经历多个阶段，包括简化阶段。 在简化阶段，表达式 `obj.x + 10` 可能会被表示为以下操作符的组合 (简化起见，这里只是概念性描述)：

1. **LoadField 操作符:** 用于加载 `obj` 对象的 `x` 属性的值。  这个操作符会使用 `FieldAccess` 结构体来描述访问的细节，例如 `x` 属性在 `obj` 对象中的偏移量，预期的类型等。

2. **NumberAdd 操作符:** 用于执行加法运算。 这个操作符表示将加载到的 `obj.x` 的值与常量 `10` 相加。

**`simplified-operator.cc` 中可能相关的定义 (概念性映射):**

* **`FieldAccess` 结构体:** 用于描述 `obj.x` 的字段访问。
* **`IrOpcode::kLoadField`:** 表示加载字段的操作码。
* **`IrOpcode::kNumberAdd`:** 表示数值加法的操作码。

**更具体的 JavaScript 例子，涉及到类型检查:**

```javascript
function checkType(obj) {
  if (typeof obj === 'number') {
    return obj * 2;
  }
  return 0;
}
```

在编译这个函数时，`typeof obj === 'number'`  这个类型检查可能会用到以下操作符：

* **`TypeOf` 操作符:** 用于获取 `obj` 的类型。
* **`StringEqual` 操作符:** 用于比较 `typeof obj` 的结果和字符串 `'number'`。

如果 V8 能够确定 `obj` 在某些情况下总是数字，那么在简化阶段可能会引入更专门的操作符，例如：

* **`CheckNumber` 操作符:** 显式地检查 `obj` 是否为数字。
* **`SpeculativeNumberMultiply` 操作符:** 在假设 `obj` 是数字的情况下执行乘法运算，并可能带有性能优化。

**总结:**

`simplified-operator.cc` 文件是 V8 编译器中非常核心的一部分，它定义了在编译优化过程中用于表示和操作 JavaScript 代码的各种基本构建块。理解这个文件有助于深入了解 V8 如何将 JavaScript 代码转换成高效的机器码。

Prompt: 
```
这是目录为v8/src/compiler/simplified-operator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/simplified-operator.h"

#include "include/v8-fast-api-calls.h"
#include "src/base/lazy-instance.h"
#include "src/compiler/linkage.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator.h"
#include "src/compiler/turbofan-types.h"
#include "src/handles/handles-inl.h"  // for operator<<
#include "src/objects/feedback-cell.h"
#include "src/objects/map.h"
#include "src/objects/name.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/compiler/wasm-compiler-definitions.h"
#endif

namespace v8 {
namespace internal {
namespace compiler {

size_t hash_value(BaseTaggedness base_taggedness) {
  return static_cast<uint8_t>(base_taggedness);
}

std::ostream& operator<<(std::ostream& os, BaseTaggedness base_taggedness) {
  switch (base_taggedness) {
    case kUntaggedBase:
      return os << "untagged base";
    case kTaggedBase:
      return os << "tagged base";
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os,
                         ConstFieldInfo const& const_field_info) {
  if (const_field_info.IsConst()) {
    return os << "const (field owner: "
              << Brief(*const_field_info.owner_map->object()) << ")";
  } else {
    return os << "mutable";
  }
  UNREACHABLE();
}

bool operator==(ConstFieldInfo const& lhs, ConstFieldInfo const& rhs) {
  return lhs.owner_map == rhs.owner_map;
}

size_t hash_value(ConstFieldInfo const& const_field_info) {
  return hash_value(const_field_info.owner_map);
}

bool operator==(FieldAccess const& lhs, FieldAccess const& rhs) {
  // On purpose we don't include the write barrier kind here, as this method is
  // really only relevant for eliminating loads and they don't care about the
  // write barrier mode.
  return lhs.base_is_tagged == rhs.base_is_tagged && lhs.offset == rhs.offset &&
         lhs.map == rhs.map && lhs.machine_type == rhs.machine_type &&
         lhs.const_field_info == rhs.const_field_info &&
         lhs.is_store_in_literal == rhs.is_store_in_literal;
}

size_t hash_value(FieldAccess const& access) {
  // On purpose we don't include the write barrier kind here, as this method is
  // really only relevant for eliminating loads and they don't care about the
  // write barrier mode.
  return base::hash_combine(access.base_is_tagged, access.offset,
                            access.machine_type, access.const_field_info,
                            access.is_store_in_literal);
}

std::ostream& operator<<(std::ostream& os, FieldAccess const& access) {
  os << "[";
  if (access.creator_mnemonic != nullptr) {
    os << access.creator_mnemonic << ", ";
  }
  os << access.base_is_tagged << ", " << access.offset << ", ";
#ifdef OBJECT_PRINT
  Handle<Name> name;
  if (access.name.ToHandle(&name)) {
    name->NamePrint(os);
    os << ", ";
  }
  if (access.map.has_value()) {
    os << Brief(*access.map->object()) << ", ";
  }
#endif
  os << access.type << ", " << access.machine_type << ", "
     << access.write_barrier_kind << ", " << access.const_field_info;
  if (access.is_store_in_literal) {
    os << " (store in literal)";
  }
  if (access.maybe_initializing_or_transitioning_store) {
    os << " (initializing or transitioning store)";
  }
  os << "]";
  return os;
}

template <>
void Operator1<FieldAccess>::PrintParameter(std::ostream& os,
                                            PrintVerbosity verbose) const {
  if (verbose == PrintVerbosity::kVerbose) {
    os << parameter();
  } else {
    os << "[+" << parameter().offset << "]";
  }
}

bool operator==(ElementAccess const& lhs, ElementAccess const& rhs) {
  // On purpose we don't include the write barrier kind here, as this method is
  // really only relevant for eliminating loads and they don't care about the
  // write barrier mode.
  return lhs.base_is_tagged == rhs.base_is_tagged &&
         lhs.header_size == rhs.header_size &&
         lhs.machine_type == rhs.machine_type;
}

size_t hash_value(ElementAccess const& access) {
  // On purpose we don't include the write barrier kind here, as this method is
  // really only relevant for eliminating loads and they don't care about the
  // write barrier mode.
  return base::hash_combine(access.base_is_tagged, access.header_size,
                            access.machine_type);
}

std::ostream& operator<<(std::ostream& os, ElementAccess const& access) {
  os << access.base_is_tagged << ", " << access.header_size << ", "
     << access.type << ", " << access.machine_type << ", "
     << access.write_barrier_kind;
  return os;
}

bool operator==(ObjectAccess const& lhs, ObjectAccess const& rhs) {
  return lhs.machine_type == rhs.machine_type &&
         lhs.write_barrier_kind == rhs.write_barrier_kind;
}

size_t hash_value(ObjectAccess const& access) {
  return base::hash_combine(access.machine_type, access.write_barrier_kind);
}

std::ostream& operator<<(std::ostream& os, ObjectAccess const& access) {
  os << access.machine_type << ", " << access.write_barrier_kind;
  return os;
}

#if V8_ENABLE_WEBASSEMBLY

V8_EXPORT_PRIVATE bool operator==(WasmFieldInfo const& lhs,
                                  WasmFieldInfo const& rhs) {
  return lhs.field_index == rhs.field_index && lhs.type == rhs.type &&
         lhs.is_signed == rhs.is_signed && lhs.null_check == rhs.null_check;
}

size_t hash_value(WasmFieldInfo const& info) {
  return base::hash_combine(info.field_index, info.type, info.is_signed,
                            info.null_check);
}

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           WasmFieldInfo const& info) {
  return os << info.field_index << ", "
            << (info.is_signed ? "signed" : "unsigned") << ", "
            << (info.null_check == kWithNullCheck ? "null check"
                                                  : "no null check");
}

V8_EXPORT_PRIVATE bool operator==(WasmElementInfo const& lhs,
                                  WasmElementInfo const& rhs) {
  return lhs.type == rhs.type && lhs.is_signed == rhs.is_signed;
}

size_t hash_value(WasmElementInfo const& info) {
  return base::hash_combine(info.type, info.is_signed);
}

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           WasmElementInfo const& info) {
  return os << (info.is_signed ? "signed" : "unsigned");
}

#endif

const FieldAccess& FieldAccessOf(const Operator* op) {
  DCHECK_NOT_NULL(op);
  DCHECK(op->opcode() == IrOpcode::kLoadField ||
         op->opcode() == IrOpcode::kStoreField);
  return OpParameter<FieldAccess>(op);
}

const ElementAccess& ElementAccessOf(const Operator* op) {
  DCHECK_NOT_NULL(op);
  DCHECK(op->opcode() == IrOpcode::kLoadElement ||
         op->opcode() == IrOpcode::kStoreElement);
  return OpParameter<ElementAccess>(op);
}

const ObjectAccess& ObjectAccessOf(const Operator* op) {
  DCHECK_NOT_NULL(op);
  DCHECK(op->opcode() == IrOpcode::kLoadFromObject ||
         op->opcode() == IrOpcode::kLoadImmutableFromObject ||
         op->opcode() == IrOpcode::kStoreToObject ||
         op->opcode() == IrOpcode::kInitializeImmutableInObject);
  return OpParameter<ObjectAccess>(op);
}

ExternalArrayType ExternalArrayTypeOf(const Operator* op) {
  DCHECK(op->opcode() == IrOpcode::kLoadTypedElement ||
         op->opcode() == IrOpcode::kLoadDataViewElement ||
         op->opcode() == IrOpcode::kStoreTypedElement ||
         op->opcode() == IrOpcode::kStoreDataViewElement);
  return OpParameter<ExternalArrayType>(op);
}

ConvertReceiverMode ConvertReceiverModeOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kConvertReceiver, op->opcode());
  return OpParameter<ConvertReceiverMode>(op);
}

size_t hash_value(CheckFloat64HoleMode mode) {
  return static_cast<size_t>(mode);
}

std::ostream& operator<<(std::ostream& os, CheckFloat64HoleMode mode) {
  switch (mode) {
    case CheckFloat64HoleMode::kAllowReturnHole:
      return os << "allow-return-hole";
    case CheckFloat64HoleMode::kNeverReturnHole:
      return os << "never-return-hole";
  }
  UNREACHABLE();
}

CheckFloat64HoleParameters const& CheckFloat64HoleParametersOf(
    Operator const* op) {
  DCHECK_EQ(IrOpcode::kCheckFloat64Hole, op->opcode());
  return OpParameter<CheckFloat64HoleParameters>(op);
}

std::ostream& operator<<(std::ostream& os,
                         CheckFloat64HoleParameters const& params) {
  return os << params.mode() << ", " << params.feedback();
}

size_t hash_value(const CheckFloat64HoleParameters& params) {
  FeedbackSource::Hash feedback_hash;
  return base::hash_combine(params.mode(), feedback_hash(params.feedback()));
}

bool operator==(CheckFloat64HoleParameters const& lhs,
                CheckFloat64HoleParameters const& rhs) {
  return lhs.mode() == rhs.mode() && lhs.feedback() == rhs.feedback();
}

bool operator!=(CheckFloat64HoleParameters const& lhs,
                CheckFloat64HoleParameters const& rhs) {
  return !(lhs == rhs);
}

CheckForMinusZeroMode CheckMinusZeroModeOf(const Operator* op) {
  DCHECK(op->opcode() == IrOpcode::kChangeFloat64ToTagged ||
         op->opcode() == IrOpcode::kCheckedInt32Mul);
  return OpParameter<CheckForMinusZeroMode>(op);
}

std::ostream& operator<<(std::ostream& os, CheckMapsFlags flags) {
  if (flags & CheckMapsFlag::kTryMigrateInstance) {
    return os << "TryMigrateInstance";
  } else {
    return os << "None";
  }
}

bool operator==(CheckMapsParameters const& lhs,
                CheckMapsParameters const& rhs) {
  return lhs.flags() == rhs.flags() && lhs.maps() == rhs.maps() &&
         lhs.feedback() == rhs.feedback();
}

size_t hash_value(CheckMapsParameters const& p) {
  FeedbackSource::Hash feedback_hash;
  return base::hash_combine(p.flags(), p.maps(), feedback_hash(p.feedback()));
}

std::ostream& operator<<(std::ostream& os, CheckMapsParameters const& p) {
  return os << p.flags() << ", " << p.maps() << ", " << p.feedback();
}

CheckMapsParameters const& CheckMapsParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kCheckMaps, op->opcode());
  return OpParameter<CheckMapsParameters>(op);
}

ZoneRefSet<Map> const& CompareMapsParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kCompareMaps, op->opcode());
  return OpParameter<ZoneRefSet<Map>>(op);
}

ZoneRefSet<Map> const& MapGuardMapsOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kMapGuard, op->opcode());
  return OpParameter<ZoneRefSet<Map>>(op);
}

size_t hash_value(CheckTaggedInputMode mode) {
  return static_cast<size_t>(mode);
}

std::ostream& operator<<(std::ostream& os, CheckTaggedInputMode mode) {
  switch (mode) {
    case CheckTaggedInputMode::kNumber:
      return os << "Number";
    case CheckTaggedInputMode::kNumberOrBoolean:
      return os << "NumberOrBoolean";
    case CheckTaggedInputMode::kNumberOrOddball:
      return os << "NumberOrOddball";
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os, GrowFastElementsMode mode) {
  switch (mode) {
    case GrowFastElementsMode::kDoubleElements:
      return os << "DoubleElements";
    case GrowFastElementsMode::kSmiOrObjectElements:
      return os << "SmiOrObjectElements";
  }
  UNREACHABLE();
}

bool operator==(const GrowFastElementsParameters& lhs,
                const GrowFastElementsParameters& rhs) {
  return lhs.mode() == rhs.mode() && lhs.feedback() == rhs.feedback();
}

inline size_t hash_value(const GrowFastElementsParameters& params) {
  FeedbackSource::Hash feedback_hash;
  return base::hash_combine(params.mode(), feedback_hash(params.feedback()));
}

std::ostream& operator<<(std::ostream& os,
                         const GrowFastElementsParameters& params) {
  return os << params.mode() << ", " << params.feedback();
}

const GrowFastElementsParameters& GrowFastElementsParametersOf(
    const Operator* op) {
  DCHECK_EQ(IrOpcode::kMaybeGrowFastElements, op->opcode());
  return OpParameter<GrowFastElementsParameters>(op);
}

bool operator==(ElementsTransition const& lhs, ElementsTransition const& rhs) {
  return lhs.mode() == rhs.mode() && lhs.source() == rhs.source() &&
         lhs.target() == rhs.target();
}

size_t hash_value(ElementsTransition transition) {
  return base::hash_combine(static_cast<uint8_t>(transition.mode()),
                            transition.source(), transition.target());
}

std::ostream& operator<<(std::ostream& os, ElementsTransition transition) {
  switch (transition.mode()) {
    case ElementsTransition::kFastTransition:
      return os << "fast-transition from "
                << Brief(*transition.source().object()) << " to "
                << Brief(*transition.target().object());
    case ElementsTransition::kSlowTransition:
      return os << "slow-transition from "
                << Brief(*transition.source().object()) << " to "
                << Brief(*transition.target().object());
  }
  UNREACHABLE();
}

ElementsTransition const& ElementsTransitionOf(const Operator* op) {
  DCHECK_EQ(IrOpcode::kTransitionElementsKind, op->opcode());
  return OpParameter<ElementsTransition>(op);
}

namespace {

// Parameters for the TransitionAndStoreElement opcode.
class TransitionAndStoreElementParameters final {
 public:
  TransitionAndStoreElementParameters(MapRef double_map, MapRef fast_map);

  MapRef double_map() const { return double_map_; }
  MapRef fast_map() const { return fast_map_; }

 private:
  MapRef const double_map_;
  MapRef const fast_map_;
};

TransitionAndStoreElementParameters::TransitionAndStoreElementParameters(
    MapRef double_map, MapRef fast_map)
    : double_map_(double_map), fast_map_(fast_map) {}

bool operator==(TransitionAndStoreElementParameters const& lhs,
                TransitionAndStoreElementParameters const& rhs) {
  return lhs.fast_map() == rhs.fast_map() &&
         lhs.double_map() == rhs.double_map();
}

size_t hash_value(TransitionAndStoreElementParameters parameters) {
  return base::hash_combine(parameters.fast_map(), parameters.double_map());
}

std::ostream& operator<<(std::ostream& os,
                         TransitionAndStoreElementParameters parameters) {
  return os << "fast-map" << Brief(*parameters.fast_map().object())
            << " double-map" << Brief(*parameters.double_map().object());
}

}  // namespace

namespace {

// Parameters for the TransitionAndStoreNonNumberElement opcode.
class TransitionAndStoreNonNumberElementParameters final {
 public:
  TransitionAndStoreNonNumberElementParameters(MapRef fast_map,
                                               Type value_type);

  MapRef fast_map() const { return fast_map_; }
  Type value_type() const { return value_type_; }

 private:
  MapRef const fast_map_;
  Type value_type_;
};

TransitionAndStoreNonNumberElementParameters::
    TransitionAndStoreNonNumberElementParameters(MapRef fast_map,
                                                 Type value_type)
    : fast_map_(fast_map), value_type_(value_type) {}

bool operator==(TransitionAndStoreNonNumberElementParameters const& lhs,
                TransitionAndStoreNonNumberElementParameters const& rhs) {
  return lhs.fast_map() == rhs.fast_map() &&
         lhs.value_type() == rhs.value_type();
}

size_t hash_value(TransitionAndStoreNonNumberElementParameters parameters) {
  return base::hash_combine(parameters.fast_map(), parameters.value_type());
}

std::ostream& operator<<(
    std::ostream& os, TransitionAndStoreNonNumberElementParameters parameters) {
  return os << parameters.value_type() << ", fast-map"
            << Brief(*parameters.fast_map().object());
}

}  // namespace

namespace {

// Parameters for the TransitionAndStoreNumberElement opcode.
class TransitionAndStoreNumberElementParameters final {
 public:
  explicit TransitionAndStoreNumberElementParameters(MapRef double_map);

  MapRef double_map() const { return double_map_; }

 private:
  MapRef const double_map_;
};

TransitionAndStoreNumberElementParameters::
    TransitionAndStoreNumberElementParameters(MapRef double_map)
    : double_map_(double_map) {}

bool operator==(TransitionAndStoreNumberElementParameters const& lhs,
                TransitionAndStoreNumberElementParameters const& rhs) {
  return lhs.double_map() == rhs.double_map();
}

size_t hash_value(TransitionAndStoreNumberElementParameters parameters) {
  return base::hash_combine(parameters.double_map());
}

std::ostream& operator<<(std::ostream& os,
                         TransitionAndStoreNumberElementParameters parameters) {
  return os << "double-map" << Brief(*parameters.double_map().object());
}

}  // namespace

MapRef DoubleMapParameterOf(const Operator* op) {
  if (op->opcode() == IrOpcode::kTransitionAndStoreElement) {
    return OpParameter<TransitionAndStoreElementParameters>(op).double_map();
  } else if (op->opcode() == IrOpcode::kTransitionAndStoreNumberElement) {
    return OpParameter<TransitionAndStoreNumberElementParameters>(op)
        .double_map();
  }
  UNREACHABLE();
}

Type ValueTypeParameterOf(const Operator* op) {
  DCHECK_EQ(IrOpcode::kTransitionAndStoreNonNumberElement, op->opcode());
  return OpParameter<TransitionAndStoreNonNumberElementParameters>(op)
      .value_type();
}

MapRef FastMapParameterOf(const Operator* op) {
  if (op->opcode() == IrOpcode::kTransitionAndStoreElement) {
    return OpParameter<TransitionAndStoreElementParameters>(op).fast_map();
  } else if (op->opcode() == IrOpcode::kTransitionAndStoreNonNumberElement) {
    return OpParameter<TransitionAndStoreNonNumberElementParameters>(op)
        .fast_map();
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os, BigIntOperationHint hint) {
  switch (hint) {
    case BigIntOperationHint::kBigInt:
      return os << "BigInt";
    case BigIntOperationHint::kBigInt64:
      return os << "BigInt64";
  }
  UNREACHABLE();
}

size_t hash_value(BigIntOperationHint hint) {
  return static_cast<uint8_t>(hint);
}

std::ostream& operator<<(std::ostream& os, NumberOperationHint hint) {
  switch (hint) {
    case NumberOperationHint::kSignedSmall:
      return os << "SignedSmall";
    case NumberOperationHint::kSignedSmallInputs:
      return os << "SignedSmallInputs";
    case NumberOperationHint::kNumber:
      return os << "Number";
    case NumberOperationHint::kNumberOrBoolean:
      return os << "NumberOrBoolean";
    case NumberOperationHint::kNumberOrOddball:
      return os << "NumberOrOddball";
  }
  UNREACHABLE();
}

size_t hash_value(NumberOperationHint hint) {
  return static_cast<uint8_t>(hint);
}

NumberOperationHint NumberOperationHintOf(const Operator* op) {
  DCHECK(op->opcode() == IrOpcode::kSpeculativeNumberAdd ||
         op->opcode() == IrOpcode::kSpeculativeNumberSubtract ||
         op->opcode() == IrOpcode::kSpeculativeNumberMultiply ||
         op->opcode() == IrOpcode::kSpeculativeNumberPow ||
         op->opcode() == IrOpcode::kSpeculativeNumberDivide ||
         op->opcode() == IrOpcode::kSpeculativeNumberModulus ||
         op->opcode() == IrOpcode::kSpeculativeNumberShiftLeft ||
         op->opcode() == IrOpcode::kSpeculativeNumberShiftRight ||
         op->opcode() == IrOpcode::kSpeculativeNumberShiftRightLogical ||
         op->opcode() == IrOpcode::kSpeculativeNumberBitwiseAnd ||
         op->opcode() == IrOpcode::kSpeculativeNumberBitwiseOr ||
         op->opcode() == IrOpcode::kSpeculativeNumberBitwiseXor ||
         op->opcode() == IrOpcode::kSpeculativeNumberEqual ||
         op->opcode() == IrOpcode::kSpeculativeNumberLessThan ||
         op->opcode() == IrOpcode::kSpeculativeNumberLessThanOrEqual ||
         op->opcode() == IrOpcode::kSpeculativeSafeIntegerAdd ||
         op->opcode() == IrOpcode::kSpeculativeSafeIntegerSubtract);
  return OpParameter<NumberOperationHint>(op);
}

BigIntOperationHint BigIntOperationHintOf(const Operator* op) {
  // TODO(panq): Expand the DCHECK when more BigInt operations are supported.
  DCHECK(op->opcode() == IrOpcode::kSpeculativeBigIntAdd ||
         op->opcode() == IrOpcode::kSpeculativeBigIntSubtract ||
         op->opcode() == IrOpcode::kSpeculativeBigIntMultiply ||
         op->opcode() == IrOpcode::kSpeculativeBigIntDivide ||
         op->opcode() == IrOpcode::kSpeculativeBigIntModulus ||
         op->opcode() == IrOpcode::kSpeculativeBigIntBitwiseAnd ||
         op->opcode() == IrOpcode::kSpeculativeBigIntBitwiseOr ||
         op->opcode() == IrOpcode::kSpeculativeBigIntBitwiseXor ||
         op->opcode() == IrOpcode::kSpeculativeBigIntShiftLeft ||
         op->opcode() == IrOpcode::kSpeculativeBigIntShiftRight ||
         op->opcode() == IrOpcode::kSpeculativeBigIntEqual ||
         op->opcode() == IrOpcode::kSpeculativeBigIntLessThan ||
         op->opcode() == IrOpcode::kSpeculativeBigIntLessThanOrEqual);
  BigIntOperationHint hint = OpParameter<BigIntOperationHint>(op);
  DCHECK_IMPLIES(hint == BigIntOperationHint::kBigInt64, Is64());
  return hint;
}

bool operator==(NumberOperationParameters const& lhs,
                NumberOperationParameters const& rhs) {
  return lhs.hint() == rhs.hint() && lhs.feedback() == rhs.feedback();
}

size_t hash_value(NumberOperationParameters const& p) {
  FeedbackSource::Hash feedback_hash;
  return base::hash_combine(p.hint(), feedback_hash(p.feedback()));
}

std::ostream& operator<<(std::ostream& os, NumberOperationParameters const& p) {
  return os << p.hint() << ", " << p.feedback();
}

NumberOperationParameters const& NumberOperationParametersOf(
    Operator const* op) {
  DCHECK_EQ(IrOpcode::kSpeculativeToNumber, op->opcode());
  return OpParameter<NumberOperationParameters>(op);
}

bool operator==(BigIntOperationParameters const& lhs,
                BigIntOperationParameters const& rhs) {
  return lhs.hint() == rhs.hint() && lhs.feedback() == rhs.feedback();
}

size_t hash_value(BigIntOperationParameters const& p) {
  FeedbackSource::Hash feedback_hash;
  return base::hash_combine(p.hint(), feedback_hash(p.feedback()));
}

std::ostream& operator<<(std::ostream& os, BigIntOperationParameters const& p) {
  return os << p.hint() << ", " << p.feedback();
}

BigIntOperationParameters const& BigIntOperationParametersOf(
    Operator const* op) {
  DCHECK_EQ(IrOpcode::kSpeculativeToBigInt, op->opcode());
  return OpParameter<BigIntOperationParameters>(op);
}

bool operator==(SpeculativeBigIntAsNParameters const& lhs,
                SpeculativeBigIntAsNParameters const& rhs) {
  return lhs.bits() == rhs.bits() && lhs.feedback() == rhs.feedback();
}

size_t hash_value(SpeculativeBigIntAsNParameters const& p) {
  FeedbackSource::Hash feedback_hash;
  return base::hash_combine(p.bits(), feedback_hash(p.feedback()));
}

std::ostream& operator<<(std::ostream& os,
                         SpeculativeBigIntAsNParameters const& p) {
  return os << p.bits() << ", " << p.feedback();
}

SpeculativeBigIntAsNParameters const& SpeculativeBigIntAsNParametersOf(
    Operator const* op) {
  DCHECK(op->opcode() == IrOpcode::kSpeculativeBigIntAsUintN ||
         op->opcode() == IrOpcode::kSpeculativeBigIntAsIntN);
  return OpParameter<SpeculativeBigIntAsNParameters>(op);
}

size_t hash_value(AllocateParameters info) {
  return base::hash_combine(info.type(),
                            static_cast<int>(info.allocation_type()));
}

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           AllocateParameters info) {
  return os << info.type() << ", " << info.allocation_type();
}

bool operator==(AllocateParameters const& lhs, AllocateParameters const& rhs) {
  return lhs.allocation_type() == rhs.allocation_type() &&
         lhs.type() == rhs.type();
}

const AllocateParameters& AllocateParametersOf(const Operator* op) {
  DCHECK(op->opcode() == IrOpcode::kAllocate ||
         op->opcode() == IrOpcode::kAllocateRaw);
  return OpParameter<AllocateParameters>(op);
}

AllocationType AllocationTypeOf(const Operator* op) {
  if (op->opcode() == IrOpcode::kNewDoubleElements ||
      op->opcode() == IrOpcode::kNewSmiOrObjectElements) {
    return OpParameter<AllocationType>(op);
  }
  return AllocateParametersOf(op).allocation_type();
}

Type AllocateTypeOf(const Operator* op) {
  DCHECK_EQ(IrOpcode::kAllocate, op->opcode());
  return AllocateParametersOf(op).type();
}

AbortReason AbortReasonOf(const Operator* op) {
  DCHECK_EQ(IrOpcode::kRuntimeAbort, op->opcode());
  return static_cast<AbortReason>(OpParameter<int>(op));
}

const CheckTaggedInputParameters& CheckTaggedInputParametersOf(
    const Operator* op) {
  DCHECK(op->opcode() == IrOpcode::kCheckedTruncateTaggedToWord32 ||
         op->opcode() == IrOpcode::kCheckedTaggedToFloat64);
  return OpParameter<CheckTaggedInputParameters>(op);
}

std::ostream& operator<<(std::ostream& os,
                         const CheckTaggedInputParameters& params) {
  return os << params.mode() << ", " << params.feedback();
}

size_t hash_value(const CheckTaggedInputParameters& params) {
  FeedbackSource::Hash feedback_hash;
  return base::hash_combine(params.mode(), feedback_hash(params.feedback()));
}

bool operator==(CheckTaggedInputParameters const& lhs,
                CheckTaggedInputParameters const& rhs) {
  return lhs.mode() == rhs.mode() && lhs.feedback() == rhs.feedback();
}

const CheckMinusZeroParameters& CheckMinusZeroParametersOf(const Operator* op) {
  DCHECK(op->opcode() == IrOpcode::kCheckedTaggedToInt32 ||
         op->opcode() == IrOpcode::kCheckedTaggedToInt64 ||
         op->opcode() == IrOpcode::kCheckedFloat64ToInt32 ||
         op->opcode() == IrOpcode::kCheckedFloat64ToInt64);
  return OpParameter<CheckMinusZeroParameters>(op);
}

std::ostream& operator<<(std::ostream& os,
                         const CheckMinusZeroParameters& params) {
  return os << params.mode() << ", " << params.feedback();
}

size_t hash_value(const CheckMinusZeroParameters& params) {
  FeedbackSource::Hash feedback_hash;
  return base::hash_combine(params.mode(), feedback_hash(params.feedback()));
}

bool operator==(CheckMinusZeroParameters const& lhs,
                CheckMinusZeroParameters const& rhs) {
  return lhs.mode() == rhs.mode() && lhs.feedback() == rhs.feedback();
}

#if V8_ENABLE_WEBASSEMBLY
V8_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& os, AssertNotNullParameters const& params) {
  return os << params.type << ", " << params.trap_id;
}

size_t hash_value(AssertNotNullParameters const& params) {
  return base::hash_combine(params.type, params.trap_id);
}

bool operator==(AssertNotNullParameters const& lhs,
                AssertNotNullParameters const& rhs) {
  return lhs.type == rhs.type && lhs.trap_id == rhs.trap_id;
}
#endif

#define PURE_OP_LIST(V)                                           \
  V(BooleanNot, Operator::kNoProperties, 1, 0)                    \
  V(NumberEqual, Operator::kCommutative, 2, 0)                    \
  V(NumberLessThan, Operator::kNoProperties, 2, 0)                \
  V(NumberLessThanOrEqual, Operator::kNoProperties, 2, 0)         \
  V(NumberAdd, Operator::kCommutative, 2, 0)                      \
  V(NumberSubtract, Operator::kNoProperties, 2, 0)                \
  V(NumberMultiply, Operator::kCommutative, 2, 0)                 \
  V(NumberDivide, Operator::kNoProperties, 2, 0)                  \
  V(NumberModulus, Operator::kNoProperties, 2, 0)                 \
  V(NumberBitwiseOr, Operator::kCommutative, 2, 0)                \
  V(NumberBitwiseXor, Operator::kCommutative, 2, 0)               \
  V(NumberBitwiseAnd, Operator::kCommutative, 2, 0)               \
  V(NumberShiftLeft, Operator::kNoProperties, 2, 0)               \
  V(NumberShiftRight, Operator::kNoProperties, 2, 0)              \
  V(NumberShiftRightLogical, Operator::kNoProperties, 2, 0)       \
  V(NumberImul, Operator::kCommutative, 2, 0)                     \
  V(NumberAbs, Operator::kNoProperties, 1, 0)                     \
  V(NumberClz32, Operator::kNoProperties, 1, 0)                   \
  V(NumberCeil, Operator::kNoProperties, 1, 0)                    \
  V(NumberFloor, Operator::kNoProperties, 1, 0)                   \
  V(NumberFround, Operator::kNoProperties, 1, 0)                  \
  V(NumberAcos, Operator::kNoProperties, 1, 0)                    \
  V(NumberAcosh, Operator::kNoProperties, 1, 0)                   \
  V(NumberAsin, Operator::kNoProperties, 1, 0)                    \
  V(NumberAsinh, Operator::kNoProperties, 1, 0)                   \
  V(NumberAtan, Operator::kNoProperties, 1, 0)                    \
  V(NumberAtan2, Operator::kNoProperties, 2, 0)                   \
  V(NumberAtanh, Operator::kNoProperties, 1, 0)                   \
  V(NumberCbrt, Operator::kNoProperties, 1, 0)                    \
  V(NumberCos, Operator::kNoProperties, 1, 0)                     \
  V(NumberCosh, Operator::kNoProperties, 1, 0)                    \
  V(NumberExp, Operator::kNoProperties, 1, 0)                     \
  V(NumberExpm1, Operator::kNoProperties, 1, 0)                   \
  V(NumberLog, Operator::kNoProperties, 1, 0)                     \
  V(NumberLog1p, Operator::kNoProperties, 1, 0)                   \
  V(NumberLog10, Operator::kNoProperties, 1, 0)                   \
  V(NumberLog2, Operator::kNoProperties, 1, 0)                    \
  V(NumberMax, Operator::kNoProperties, 2, 0)                     \
  V(NumberMin, Operator::kNoProperties, 2, 0)                     \
  V(NumberPow, Operator::kNoProperties, 2, 0)                     \
  V(NumberRound, Operator::kNoProperties, 1, 0)                   \
  V(NumberSign, Operator::kNoProperties, 1, 0)                    \
  V(NumberSin, Operator::kNoProperties, 1, 0)                     \
  V(NumberSinh, Operator::kNoProperties, 1, 0)                    \
  V(NumberSqrt, Operator::kNoProperties, 1, 0)                    \
  V(NumberTan, Operator::kNoProperties, 1, 0)                     \
  V(NumberTanh, Operator::kNoProperties, 1, 0)                    \
  V(NumberTrunc, Operator::kNoProperties, 1, 0)                   \
  V(NumberToBoolean, Operator::kNoProperties, 1, 0)               \
  V(NumberToInt32, Operator::kNoProperties, 1, 0)                 \
  V(NumberToString, Operator::kNoProperties, 1, 0)                \
  V(NumberToUint32, Operator::kNoProperties, 1, 0)                \
  V(NumberToUint8Clamped, Operator::kNoProperties, 1, 0)          \
  V(Integral32OrMinusZeroToBigInt, Operator::kNoProperties, 1, 0) \
  V(NumberSilenceNaN, Operator::kNoProperties, 1, 0)              \
  V(BigIntEqual, Operator::kNoProperties, 2, 0)                   \
  V(BigIntLessThan, Operator::kNoProperties, 2, 0)                \
  V(BigIntLessThanOrEqual, Operator::kNoProperties, 2, 0)         \
  V(BigIntNegate, Operator::kNoProperties, 1, 0)                  \
  V(StringConcat, Operator::kNoProperties, 3, 0)                  \
  V(StringToNumber, Operator::kNoProperties, 1, 0)                \
  V(StringFromSingleCharCode, Operator::kNoProperties, 1, 0)      \
  V(StringFromSingleCodePoint, Operator::kNoProperties, 1, 0)     \
  V(StringIndexOf, Operator::kNoProperties, 3, 0)                 \
  V(StringLength, Operator::kNoProperties, 1, 0)                  \
  V(StringWrapperLength, Operator::kNoProperties, 1, 0)           \
  V(StringToLowerCaseIntl, Operator::kNoProperties, 1, 0)         \
  V(StringToUpperCaseIntl, Operator::kNoProperties, 1, 0)         \
  V(TypeOf, Operator::kNoProperties, 1, 1)                        \
  V(PlainPrimitiveToNumber, Operator::kNoProperties, 1, 0)        \
  V(PlainPrimitiveToWord32, Operator::kNoProperties, 1, 0)        \
  V(PlainPrimitiveToFloat64, Operator::kNoProperties, 1, 0)       \
  V(ChangeTaggedSignedToInt32, Operator::kNoProperties, 1, 0)     \
  V(ChangeTaggedSignedToInt64, Operator::kNoProperties, 1, 0)     \
  V(ChangeTaggedToInt32, Operator::kNoProperties, 1, 0)           \
  V(ChangeTaggedToInt64, Operator::kNoProperties, 1, 0)           \
  V(ChangeTaggedToUint32, Operator::kNoProperties, 1, 0)          \
  V(ChangeTaggedToFloat64, Operator::kNoProperties, 1, 0)         \
  V(ChangeTaggedToTaggedSigned, Operator::kNoProperties, 1, 0)    \
  V(ChangeFloat64ToTaggedPointer, Operator::kNoProperties, 1, 0)  \
  V(ChangeFloat64HoleToTagged, Operator::kNoProperties, 1, 0)     \
  V(ChangeInt31ToTaggedSigned, Operator::kNoProperties, 1, 0)     \
  V(ChangeInt32ToTagged, Operator::kNoProperties, 1, 0)           \
  V(ChangeInt64ToTagged, Operator::kNoProperties, 1, 0)           \
  V(ChangeUint32ToTagged, Operator::kNoProperties, 1, 0)          \
  V(ChangeUint64ToTagged, Operator::kNoProperties, 1, 0)          \
  V(ChangeTaggedToBit, Operator::kNoProperties, 1, 0)             \
  V(ChangeBitToTagged, Operator::kNoProperties, 1, 0)             \
  V(TruncateBigIntToWord64, Operator::kNoProperties, 1, 0)        \
  V(ChangeInt64ToBigInt, Operator::kNoProperties, 1, 0)           \
  V(ChangeUint64ToBigInt, Operator::kNoProperties, 1, 0)          \
  V(TruncateTaggedToBit, Operator::kNoProperties, 1, 0)           \
  V(TruncateTaggedPointerToBit, Operator::kNoProperties, 1, 0)    \
  V(TruncateTaggedToWord32, Operator::kNoProperties, 1, 0)        \
  V(TruncateTaggedToFloat64, Operator::kNoProperties, 1, 0)       \
  V(ObjectIsArrayBufferView, Operator::kNoProperties, 1, 0)       \
  V(ObjectIsBigInt, Operator::kNoProperties, 1, 0)                \
  V(ObjectIsCallable, Operator::kNoProperties, 1, 0)              \
  V(ObjectIsConstructor, Operator::kNoProperties, 1, 0)           \
  V(ObjectIsDetectableCallable, Operator::kNoProperties, 1, 0)    \
  V(ObjectIsMinusZero, Operator::kNoProperties, 1, 0)             \
  V(NumberIsMinusZero, Operator::kNoProperties, 1, 0)             \
  V(ObjectIsNaN, Operator::kNoProperties, 1, 0)                   \
  V(NumberIsNaN, Operator::kNoProperties, 1, 0)                   \
  V(ObjectIsNonCallable, Operator::kNoProperties, 1, 0)           \
  V(ObjectIsNumber, Operator::kNoProperties, 1, 0)                \
  V(ObjectIsReceiver, Operator::kNoProperties, 1, 0)              \
  V(ObjectIsSmi, Operator::kNoProperties, 1, 0)                   \
  V(ObjectIsString, Operator::kNoProperties, 1, 0)                \
  V(ObjectIsSymbol, Operator::kNoProperties, 1, 0)                \
  V(ObjectIsUndetectable, Operator::kNoProperties, 1, 0)          \
  V(NumberIsFloat64Hole, Operator::kNoProperties, 1, 0)           \
  V(NumberIsFinite, Operator::kNoProperties, 1, 0)                \
  V(ObjectIsFiniteNumber, Operator::kNoProperties, 1, 0)          \
  V(NumberIsInteger, Operator::kNoProperties, 1, 0)               \
  V(ObjectIsSafeInteger, Operator::kNoProperties, 1, 0)           \
  V(NumberIsSafeInteger, Operator::kNoProperties, 1, 0)           \
  V(ObjectIsInteger, Operator::kNoProperties, 1, 0)               \
  V(ConvertTaggedHoleToUndefined, Operator::kNoProperties, 1, 0)  \
  V(SameValue, Operator::kCommutative, 2, 0)                      \
  V(SameValueNumbersOnly, Operator::kCommutative, 2, 0)           \
  V(NumberSameValue, Operator::kCommutative, 2, 0)                \
  V(ReferenceEqual, Operator::kCommutative, 2, 0)                 \
  V(StringEqual, Operator::kCommutative, 2, 0)                    \
  V(StringLessThan, Operator::kNoProperties, 2, 0)                \
  V(StringLessThanOrEqual, Operator::kNoProperties, 2, 0)         \
  V(ToBoolean, Operator::kNoProperties, 1, 0)                     \
  V(NewConsString, Operator::kNoProperties, 3, 0)                 \
  V(Unsigned32Divide, Operator::kNoProperties, 2, 0)

#define EFFECT_DEPENDENT_OP_LIST(V)                       \
  V(BigIntAdd, Operator::kNoProperties, 2, 1)             \
  V(BigIntSubtract, Operator::kNoProperties, 2, 1)        \
  V(BigIntMultiply, Operator::kNoProperties, 2, 1)        \
  V(BigIntDivide, Operator::kNoProperties, 2, 1)          \
  V(BigIntModulus, Operator::kNoProperties, 2, 1)         \
  V(BigIntBitwiseAnd, Operator::kNoProperties, 2, 1)      \
  V(BigIntBitwiseOr, Operator::kNoProperties, 2, 1)       \
  V(BigIntBitwiseXor, Operator::kNoProperties, 2, 1)      \
  V(BigIntShiftLeft, Operator::kNoProperties, 2, 1)       \
  V(BigIntShiftRight, Operator::kNoProperties, 2, 1)      \
  V(StringCharCodeAt, Operator::kNoProperties, 2, 1)      \
  V(StringCodePointAt, Operator::kNoProperties, 2, 1)     \
  V(StringFromCodePointAt, Operator::kNoProperties, 2, 1) \
  V(StringSubstring, Operator::kNoProperties, 3, 1)       \
  V(DateNow, Operator::kNoProperties, 0, 1)               \
  V(DoubleArrayMax, Operator::kNoProperties, 1, 1)        \
  V(DoubleArrayMin, Operator::kNoProperties, 1, 1)

#define SPECULATIVE_NUMBER_BINOP_LIST(V)      \
  SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(V) \
  V(SpeculativeNumberEqual)                   \
  V(SpeculativeNumberLessThan)                \
  V(SpeculativeNumberLessThanOrEqual)

#define CHECKED_OP_LIST(V)                \
  V(CheckEqualsInternalizedString, 2, 0)  \
  V(CheckEqualsSymbol, 2, 0)              \
  V(CheckHeapObject, 1, 1)                \
  V(CheckInternalizedString, 1, 1)        \
  V(CheckNotTaggedHole, 1, 1)             \
  V(CheckReceiver, 1, 1)                  \
  V(CheckReceiverOrNullOrUndefined, 1, 1) \
  V(CheckSymbol, 1, 1)                    \
  V(CheckedInt32Add, 2, 1)                \
  V(CheckedInt32Div, 2, 1)                \
  V(CheckedInt32Mod, 2, 1)                \
  V(CheckedInt32Sub, 2, 1)                \
  V(CheckedUint32Div, 2, 1)               \
  V(CheckedUint32Mod, 2, 1)               \
  V(CheckedInt64Add, 2, 1)                \
  V(CheckedInt64Sub, 2, 1)                \
  V(CheckedInt64Mul, 2, 1)                \
  V(CheckedInt64Div, 2, 1)                \
  V(CheckedInt64Mod, 2, 1)

#define CHECKED_WITH_FEEDBACK_OP_LIST(V) \
  V(CheckNumber, 1, 1)                   \
  V(CheckSmi, 1, 1)                      \
  V(CheckString, 1, 1)                   \
  V(CheckStringOrStringWrapper, 1, 1)    \
  V(CheckBigInt, 1, 1)                   \
  V(CheckedBigIntToBigInt64, 1, 1)       \
  V(CheckedInt32ToTaggedSigned, 1, 1)    \
  V(CheckedInt64ToInt32, 1, 1)           \
  V(CheckedInt64ToTaggedSigned, 1, 1)    \
  V(CheckedTaggedToArrayIndex, 1, 1)     \
  V(CheckedTaggedSignedToInt32, 1, 1)    \
  V(CheckedTaggedToTaggedPointer, 1, 1)  \
  V(CheckedTaggedToTaggedSigned, 1, 1)   \
  V(CheckedUint32ToInt32, 1, 1)          \
  V(CheckedUint32ToTaggedSigned, 1, 1)   \
  V(CheckedUint64ToInt32, 1, 1)          \
  V(CheckedUint64ToInt64, 1, 1)          \
  V(CheckedUint64ToTaggedSigned, 1, 1)

#define CHECKED_BOUNDS_OP_LIST(V) \
  V(CheckedUint32Bounds)          \
  V(CheckedUint64Bounds)

struct SimplifiedOperatorGlobalCache final {
#define PURE(Name, properties, value_input_count, control_input_count)     \
  struct Name##Operator final : public Operator {                          \
    Name##Operator()                                                       \
        : Operator(IrOpcode::k##Name, Operator::kPure | properties, #Name, \
                   value_input_count, 0, control_input_count, 1, 0, 0) {}  \
  };                                                                       \
  Name##Operator k##Name;
  PURE_OP_LIST(PURE)
#undef PURE

#define EFFECT_DEPENDENT(Name, properties, value_input_count,               \
                         control_input_count)                               \
  struct Name##Operator final : public Operator {                           \
    Name##Operator()                                                        \
        : Operator(IrOpcode::k##Name, Operator::kEliminatable | properties, \
                   #Name, value_input_count, 1, control_input_count, 1, 1,  \
                   0) {}                                                    \
  };                                                                        \
  Name##Operator k##Name;
  EFFECT_DEPENDENT_OP_LIST(EFFECT_DEPENDENT)
#undef EFFECT_DEPENDENT

#define CHECKED(Name, value_input_count, value_output_count)             \
  struct Name##Operator final : public Operator {                        \
    Name##Operator()                                                     \
        : Operator(IrOpcode::k##Name,                                    \
                   Operator::kFoldable | Operator::kNoThrow, #Name,      \
                   value_input_count, 1, 1, value_output_count, 1, 0) {} \
  };                                                                     \
  Name##Operator k##Name;
  CHECKED_OP_LIST(CHECKED)
#undef CHECKED

#define CHECKED_WITH_FEEDBACK(Name, value_input_count, value_output_count) \
  struct Name##Operator final : public Operator1<CheckParameters> {        \
    Name##Operator()                                                       \
        : Operator1<CheckParameters>(                                      \
              IrOpcode::k##Name, Operator::kFoldable | Operator::kNoThrow, \
              #Name, value_input_count, 1, 1, value_output_count, 1, 0,    \
              CheckParameters(FeedbackSource())) {}                        \
  };                                                                       \
  Name##Operator k##Name;
  CHECKED_WITH_FEEDBACK_OP_LIST(CHECKED_WITH_FEEDBACK)
#undef CHECKED_WITH_FEEDBACK

#define CHECKED_BOUNDS(Name)                                               \
  struct Name##Operator final : public Operator1<CheckBoundsParameters> {  \
    Name##Operator(FeedbackSource feedback, CheckBoundsFlags flags)        \
        : Operator1<CheckBoundsParameters>(                                \
              IrOpcode::k##Name, Operator::kFoldable | Operator::kNoThrow, \
              #Name, 2, 1, 1, 1, 1, 0,                                     \
              CheckBoundsParameters(feedback, flags)) {}                   \
  };                                                                       \
  Name##Operator k##Name = {FeedbackSource(), CheckBoundsFlags()};         \
  Name##Operator k##Name##Aborting = {FeedbackSource(),                    \
                                      CheckBoundsFlag::kAbortOnOutOfBounds};
  CHECKED_BOUNDS_OP_LIST(CHECKED_BOUNDS)
  CHECKED_BOUNDS(CheckBounds)
  // For IrOpcode::kCheckBounds, we allow additional flags:
  CheckBoundsOperator kCheckBoundsConverting = {
      FeedbackSource(), CheckBoundsFlag::kConvertStringAndMinusZero};
  CheckBoundsOperator kCheckBoundsAbortingAndConverting = {
      FeedbackSource(),
      CheckBoundsFlags(CheckBoundsFlag::kAbortOnOutOfBounds) |
          CheckBoundsFlags(CheckBoundsFlag::kConvertStringAndMinusZero)};
#undef CHECKED_BOUNDS

  template <DeoptimizeReason kDeoptimizeReason>
  struct CheckIfOperator final : public Operator1<CheckIfParameters> {
    CheckIfOperator()
        : Operator1<CheckIfParameters>(
              IrOpcode::kCheckIf, Operator::kFoldable | Operator::kNoThrow,
              "CheckIf", 1, 1, 1, 0, 1, 0,
              CheckIfParameters(kDeoptimizeReason, FeedbackSource())) {}
  };
#define CHECK_IF(Name, message) \
  CheckIfOperator<DeoptimizeReason::k##Name> kCheckIf##Name;
  DEOPTIMIZE_REASON_LIST(CHECK_IF)
#undef CHECK_IF

  struct FindOrderedHashMapEntryOperator final : public Operator {
    FindOrderedHashMapEntryOperator()
        : Operator(IrOpcode::kFindOrderedHashMapEntry, Operator::kEliminatable,
                   "FindOrderedHashMapEntry", 2, 1, 1, 1, 1, 0) {}
  };
  FindOrderedHashMapEntryOperator kFindOrderedHashMapEntry;

  struct FindOrderedHashMapEntryForInt32KeyOperator final : public Operator {
    FindOrderedHashMapEntryForInt32KeyOperator()
        : Operator(IrOpcode::kFindOrderedHashMapEntryForInt32Key,
                   Operator::kEliminatable,
                   "FindOrderedHashMapEntryForInt32Key", 2, 1, 1, 1, 1, 0) {}
  };
  FindOrderedHashMapEntryForInt32KeyOperator
      kFindOrderedHashMapEntryForInt32Key;

  struct FindOrderedHashSetEntryOperator final : public Operator {
    FindOrderedHashSetEntryOperator()
        : Operator(IrOpcode::kFindOrderedHashSetEntry, Operator::kEliminatable,
                   "FindOrderedHashSetEntry", 2, 1, 1, 1, 1, 0) {}
  };
  FindOrderedHashSetEntryOperator kFindOrderedHashSetEntry;

  template <CheckForMinusZeroMode kMode>
  struct ChangeFloat64ToTaggedOperator final
      : public Operator1<CheckForMinusZeroMode> {
    ChangeFloat64ToTaggedOperator()
        : Operator1<CheckForMinusZeroMode>(
              IrOpcode::kChangeFloat64ToTagged, Operator::kPure,
              "ChangeFloat64ToTagged", 1, 0, 0, 1, 0, 0, kMode) {}
  };
  ChangeFloat64ToTaggedOperator<CheckForMinusZeroMode::kCheckForMinusZero>
      kChangeFloat64ToTaggedCheckForMinusZeroOperator;
  ChangeFloat64ToTaggedOperator<CheckForMinusZeroMode::kDontCheckForMinusZero>
      kChangeFloat64ToTaggedDontCheckForMinusZeroOperator;

  template <CheckForMinusZeroMode kMode>
  struct CheckedInt32MulOperator final
      : public Operator1<CheckForMinusZeroMode> {
    CheckedInt32MulOperator()
        : Operator1<CheckForMinusZeroMode>(
              IrOpcode::kCheckedInt32Mul,
              Operator::kFoldable | Operator::kNoThrow, "CheckedInt32Mul", 2, 1,
              1, 1, 1, 0, kMode) {}
  };
  CheckedInt32MulOperator<CheckForMinusZeroMode::kCheckForMinusZero>
      kCheckedInt32MulCheckForMinusZeroOperator;
  CheckedInt32MulOperator<CheckForMinusZeroMode::kDontCheckForMinusZero>
      kCheckedInt32MulDontCheckForMinusZeroOperator;

  template <CheckForMinusZeroMode kMode>
  struct CheckedFloat64ToInt32Operator final
      : public Operator1<CheckMinusZeroParameters> {
    CheckedFloat64ToInt32Operator()
        : Operator1<CheckMinusZeroParameters>(
              IrOpcode::kCheckedFloat64ToInt32,
              Operator::kFoldable | Operator::kNoThrow, "CheckedFloat64ToInt32",
              1, 1, 1, 1, 1, 0,
              CheckMinusZeroParameters(kMode, FeedbackSource())) {}
  };
  CheckedFloat64ToInt32Operator<CheckForMinusZeroMode::kCheckForMinusZero>
      kCheckedFloat64ToInt32CheckForMinusZeroOperator;
  CheckedFloat64ToInt32Operator<CheckForMinusZeroMode::kDontCheckForMinusZero>
      kCheckedFloat64ToInt32DontCheckForMinusZeroOperator;

  template <CheckForMinusZeroMode kMode>
  struct CheckedFloat64ToInt64Operator final
      : public Operator1<CheckMinusZeroParameters> {
    CheckedFloat64ToInt64Operator()
        : Operator1<CheckMinusZeroParameters>(
              IrOpcode::kCheckedFloat64ToInt64,
              Operator::kFoldable | Operator::kNoThrow, "CheckedFloat64ToInt64",
              1, 1, 1, 1, 1, 0,
              CheckMinusZeroParameters(kMode, FeedbackSource())) {}
  };
  CheckedFloat64ToInt64Operator<CheckForMinusZeroMode::kCheckForMinusZero>
      kCheckedFloat64ToInt64CheckForMinusZeroOperator;
  CheckedFloat64ToInt64Operator<CheckForMinusZeroMode::kDontCheckForMinusZero>
      kCheckedFloat64ToInt64DontCheckForMinusZeroOperator;

  template <CheckForMinusZeroMode kMode>
  struct CheckedTaggedToInt32Operator final
      : public Operator1<CheckMinusZeroParameters> {
    CheckedTaggedToInt32Operator()
        : Operator1<CheckMinusZeroParameters>(
              IrOpcode::kCheckedTaggedToInt32,
              Operator::kFoldable | Operator::kNoThrow, "CheckedTaggedToInt32",
              1, 1, 1, 1, 1, 0,
              CheckMinusZeroParameters(kMode, FeedbackSource())) {}
  };
  CheckedTaggedToInt32Operator<CheckForMinusZeroMode::kCheckForMinusZero>
      kCheckedTaggedToInt32CheckForMinusZeroOperator;
  CheckedTaggedToInt32Operator<CheckForMinusZeroMode::kDontCheckForMinusZero>
      kCheckedTaggedToInt32DontCheckForMinusZeroOperator;

  template <CheckForMinusZeroMode kMode>
  struct CheckedTaggedToInt64Operator final
      : public Operator1<CheckMinusZeroParameters> {
    CheckedTaggedToInt64Operator()
        : Operator1<CheckMinusZeroParameters>(
              IrOpcode::kCheckedTaggedToInt64,
              Operator::kFoldable | Operator::kNoThrow, "CheckedTaggedToInt64",
              1, 1, 1, 1, 1, 0,
              CheckMinusZeroParameters(kMode, FeedbackSource())) {}
  };
  CheckedTaggedToInt64Operator<CheckForMinusZeroMode::kCheckForMinusZero>
      kCheckedTaggedToInt64CheckForMinusZeroOperator;
  CheckedTaggedToInt64Operator<CheckForMinusZeroMode::kDontCheckForMinusZero>
      kCheckedTaggedToInt64DontCheckForMinusZeroOperator;

  template <CheckTaggedInputMode kMode>
  struct CheckedTaggedToFloat64Operator final
      : public Operator1<CheckTaggedInputParameters> {
    CheckedTaggedToFloat64Operator()
        : Operator1<CheckTaggedInputParameters>(
              IrOpcode::kCheckedTaggedToFloat64,
              Operator::kFoldable | Operator::kNoThrow,
              "CheckedTaggedToFloat64", 1, 1, 1, 1, 1, 0,
              CheckTaggedInputParameters(kMode, FeedbackSource())) {}
  };
  CheckedTaggedToFloat64Operator<CheckTaggedInputMode::kNumber>
      kCheckedTaggedToFloat64NumberOperator;
  CheckedTaggedToFloat64Operator<CheckTaggedInputMode::kNumberOrBoolean>
      kCheckedTaggedToFloat64NumberOrBooleanOperator;
  CheckedTaggedToFloat64Operator<CheckTaggedInputMode::kNumberOrOddball>
      kCheckedTaggedToFloat64NumberOrOddballOperator;

  template <CheckTaggedInputMode kMode>
  struct CheckedTruncateTaggedToWord32Operator final
      : public Operator1<CheckTaggedInputParameters> {
    CheckedTruncateTaggedToWord32Operator()
        : Operator1<CheckTaggedInputParameters>(
              IrOpcode::kCheckedTruncateTaggedToWord32,
              Operator::kFoldable | Operator::kNoThrow,
              "CheckedTruncateTaggedToWord32", 1, 1, 1, 1, 1, 0,
              CheckTaggedInputParameters(kMode, FeedbackSource())) {}
  };
  CheckedTruncateTaggedToWord32Operator<CheckTaggedInputMode::kNumber>
      kCheckedTruncateTaggedToWord32NumberOperator;
  CheckedTruncateTaggedToWord32Operator<CheckTaggedInputMode::kNumberOrOddball>
      kCheckedTruncateTaggedToWord32NumberOrOddballOperator;

  template <ConvertReceiverMode kMode>
  struct ConvertReceiverOperator final : public Operator1<ConvertReceiverMode> {
    ConvertReceiverOperator()
        : Operator1<ConvertReceiverMode>(  // --
              IrOpcode::kConvertReceiver,  // opcode
              Operator::kEliminatable,     // flags
              "ConvertReceiver",           // name
              3, 1, 1, 1, 1, 0,            // counts
              kMode) {}                    // param
  };
  ConvertReceiverOperator<ConvertReceiverMode::kAny>
      kConvertReceiverAnyOperator;
  ConvertReceiverOperator<ConvertReceiverMode::kNullOrUndefined>
      kConvertReceiverNullOrUndefinedOperator;
  ConvertReceiverOperator<ConvertReceiverMode::kNotNullOrUndefined>
      kConvertReceiverNotNullOrUndefinedOperator;

  template <CheckFloat64HoleMode kMode>
  struct CheckFloat64HoleNaNOperator final
      : public Operator1<CheckFloat64HoleParameters> {
    CheckFloat64HoleNaNOperator()
        : Operator1<CheckFloat64HoleParameters>(
              IrOpcode::kCheckFloat64Hole,
              Operator::kFoldable | Operator::kNoThrow, "CheckFloat64Hole", 1,
              1, 1, 1, 1, 0,
              CheckFloat64HoleParameters(kMode, FeedbackSource())) {}
  };
  CheckFloat64HoleNaNOperator<CheckFloat64HoleMode::kAllowReturnHole>
      kCheckFloat64HoleAllowReturnHoleOperator;
  CheckFloat64HoleNaNOperator<CheckFloat64HoleMode::kNeverReturnHole>
      kCheckFloat64HoleNeverReturnHoleOperator;

  struct EnsureWritableFastElementsOperator final : public Operator {
    EnsureWritableFastElementsOperator()
        : Operator(                                     // --
              IrOpcode::kEnsureWritableFastElements,    // opcode
              Operator::kNoDeopt | Operator::kNoThrow,  // flags
              "EnsureWritableFastElements",             // name
              2, 1, 1, 1, 1, 0) {}                      // counts
  };
  EnsureWritableFastElementsOperator kEnsureWritableFastElements;

  template <GrowFastElementsMode kMode>
  struct GrowFastElementsOperator final
      : public Operator1<GrowFastElementsParameters> {
    GrowFastElementsOperator()
        : Operator1(IrOpcode::kMaybeGrowFastElements, Operator::kNoThrow,
                    "MaybeGrowFastElements", 4, 1, 1, 1, 1, 0,
                    GrowFastElementsParameters(kMode, FeedbackSource())) {}
  };

  GrowFastElementsOperator<GrowFastElementsMode::kDoubleElements>
      kGrowFastElementsOperatorDoubleElements;
  GrowFastElementsOperator<GrowFastElementsMode::kSmiOrObjectElements>
      kGrowFastElementsOperatorSmiOrObjectElements;

  struct LoadFieldByIndexOperator final : public Operator {
    LoadFieldByIndexOperator()
        : Operator(                         // --
              IrOpcode::kLoadFieldByIndex,  // opcode
              Operator::kEliminatable,      // flags,
              "LoadFieldByIndex",           // name
              2, 1, 1, 1, 1, 0) {}          // counts;
  };
  LoadFieldByIndexOperator kLoadFieldByIndex;

  struct LoadStackArgumentOperator final : public Operator {
    LoadStackArgumentOperator()
        : Operator(                          // --
              IrOpcode::kLoadStackArgument,  // opcode
              Operator::kEliminatable,       // flags
              "LoadStackArgument",           // name
              2, 1, 1, 1, 1, 0) {}           // counts
  };
  LoadStackArgumentOperator kLoadStackArgument;

#if V8_ENABLE_WEBASSEMBLY
  struct WasmArrayLengthOperator final : public Operator1<bool> {
    explicit WasmArrayLengthOperator(bool null_check)
        : Operator1<bool>(IrOpcode::kWasmArrayLength, Operator::kEliminatable,
                          "WasmArrayLength", 1, 1, 1, 1, 1, 1, null_check) {}
  };
  WasmArrayLengthOperator kWasmArrayLengthNullCheck{true};
  WasmArrayLengthOperator kWasmArrayLengthNoNullCheck{false};

  struct WasmArrayInitializeLengthOperator final : public Operator {
    WasmArrayInitializeLengthOperator()
        : Operator(IrOpcode::kWasmArrayInitializeLength,
                   Operator::kNoThrow | Operator::kNoRead | Operator::kNoDeopt,
                   "WasmArrayInitializeLength", 2, 1, 1, 0, 1, 0) {}
  };
  WasmArrayInitializeLengthOperator kWasmArrayInitializeLength;

  struct StringAsWtf16Operator final : public Operator {
    StringAsWtf16Operator()
        : Operator(IrOpcode::kStringAsWtf16,
                   Operator::kEliminatable | Operator::kIdempotent,
                   "StringAsWtf16", 1, 1, 1, 1, 1, 1) {}
  };
  StringAsWtf16Operator kStringAsWtf16;

  struct StringPrepareForGetCodeunitOperator final : public Operator {
    StringPrepareForGetCodeunitOperator()
        : Operator(IrOpcode::kStringPrepareForGetCodeunit,
                   Operator::kEliminatable, "StringPrepareForGetCodeunit", 1, 1,
                   1, 3, 1, 1) {}
  };
  StringPrepareForGetCodeunitOperator kStringPrepareForGetCodeunit;

#endif

#define SPECULATIVE_NUMBER_BINOP(Name)                                      \
  template <NumberOperationHint kHint>                                      \
  struct Name##Operator final : public Operator1<NumberOperationHint> {     \
    Name##Operator()                                                        \
        : Operator1<NumberOperationHint>(                                   \
              IrOpcode::k##Name, Operator::kFoldable | Operator::kNoThrow,  \
              #Name, 2, 1, 1, 1, 1, 0, kHint) {}                            \
  };                                                                        \
  Name##Operator<NumberOperationHint::kSignedSmall>                         \
      k##Name##SignedSmallOperator;                                         \
  Name##Operator<NumberOperationHint::kSignedSmallInputs>                   \
      k##Name##SignedSmallInputsOperator;                                   \
  Name##Operator<NumberOperationHint::kNumber> k##Name##NumberOperator;     \
  Name##Operator<NumberOperationHint::kNumberOrOddball>                     \
      k##Name##NumberOrOddballOperator;
  SPECULATIVE_NUMBER_BINOP_LIST(SPECULATIVE_NUMBER_BINOP)
#undef SPECULATIVE_NUMBER_BINOP
  SpeculativeNumberEqualOperator<NumberOperationHint::kNumberOrBoolean>
      kSpeculativeNumberEqualNumberOrBooleanOperator;

  template <NumberOperationHint kHint>
  struct SpeculativeToNumberOperator final
      : public Operator1<NumberOperationParameters> {
    SpeculativeToNumberOperator()
        : Operator1<NumberOperationParameters>(
              IrOpcode::kSpeculativeToNumber,
              Operator::kFoldable | Operator::kNoThrow, "SpeculativeToNumber",
              1, 1, 1, 1, 1, 0,
              NumberOperationParameters(kHint, FeedbackSource())) {}
  };
  SpeculativeToNumberOperator<NumberOperationHint::kSignedSmall>
      kSpeculativeToNumberSignedSmallOperator;
  SpeculativeToNumberOperator<NumberOperationHint::kNumber>
      kSpeculativeToNumberNumberOperator;
  SpeculativeToNumberOperator<NumberOperationHint::kNumberOrOddball>
      kSpeculativeToNumberNumberOrOddballOperator;

  template <BigIntOperationHint kHint>
  struct SpeculativeToBigIntOperator final
      : public Operator1<BigIntOperationParameters> {
    SpeculativeToBigIntOperator()
        : Operator1<BigIntOperationParameters>(
              IrOpcode::kSpeculativeToBigInt,
              Operator::kFoldable | Operator::kNoThrow, "SpeculativeToBigInt",
              1, 1, 1, 1, 1, 0,
              BigIntOperationParameters(kHint, FeedbackSource())) {}
  };
  SpeculativeToBigIntOperator<BigIntOperationHint::kBigInt64>
      kSpeculativeToBigIntBigInt64Operator;
  SpeculativeToBigIntOperator<BigIntOperationHint::kBigInt>
      kSpeculativeToBigIntBigIntOperator;

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  struct GetContinuationPreservedEmbedderDataOperator : public Operator {
    GetContinuationPreservedEmbedderDataOperator()
        : Operator(IrOpcode::kGetContinuationPreservedEmbedderData,
                   Operator::kNoThrow | Operator::kNoDeopt | Operator::kNoWrite,
                   "GetContinuationPreservedEmbedderData", 0, 1, 0, 1, 1, 0) {}
  };
  GetContinuationPreservedEmbedderDataOperator
      kGetContinuationPreservedEmbedderData;

  struct SetContinuationPreservedEmbedderDataOperator : public Operator {
    SetContinuationPreservedEmbedderDataOperator()
        : Operator(IrOpcode::kSetContinuationPreservedEmbedderData,
                   Operator::kNoThrow | Operator::kNoDeopt | Operator::kNoRead,
                   "SetContinuationPreservedEmbedderData", 1, 1, 0, 0, 1, 0) {}
  };
  SetContinuationPreservedEmbedderDataOperator
      kSetContinuationPreservedEmbedderData;
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
};

namespace {
DEFINE_LAZY_LEAKY_OBJECT_GETTER(SimplifiedOperatorGlobalCache,
                                GetSimplifiedOperatorGlobalCache)
}  // namespace

SimplifiedOperatorBuilder::SimplifiedOperatorBuilder(Zone* zone)
    : cache_(*GetSimplifiedOperatorGlobalCache()), zone_(zone) {}

#define GET_FROM_CACHE(Name, ...) \
  const Operator* SimplifiedOperatorBuilder::Name() { return &cache_.k##Name; }
PURE_OP_LIST(GET_FROM_CACHE)
EFFECT_DEPENDENT_OP_LIST(GET_FROM_CACHE)
CHECKED_OP_LIST(GET_FROM_CACHE)
GET_FROM_CACHE(FindOrderedHashMapEntryForInt32Key)
GET_FROM_CACHE(LoadFieldByIndex)
#undef GET_FROM_CACHE

const Operator* SimplifiedOperatorBuilder::FindOrderedCollectionEntry(
    CollectionKind collection_kind) {
  switch (collection_kind) {
    case CollectionKind::kMap:
      return &cache_.kFindOrderedHashMapEntry;
    case CollectionKind::kSet:
      return &cache_.kFindOrderedHashSetEntry;
  }
}

#define GET_FROM_CACHE_WITH_FEEDBACK(Name, value_input_count,               \
                                     value_output_count)                    \
  const Operator* SimplifiedOperatorBuilder::Name(                          \
      const FeedbackSource& feedback) {                                     \
    if (!feedback.IsValid()) {                                              \
      return &cache_.k##Name;                                               \
    }                                                                       \
    return zone()->New<Operator1<CheckParameters>>(                         \
        IrOpcode::k##Name, Operator::kFoldable | Operator::kNoThrow, #Name, \
        value_input_count, 1, 1, value_output_count, 1, 0,                  \
        CheckParameters(feedback));                                         \
  }
CHECKED_WITH_FEEDBACK_OP_LIST(GET_FROM_CACHE_WITH_FEEDBACK)
#undef GET_FROM_CACHE_WITH_FEEDBACK

#define GET_FROM_CACHE_WITH_FEEDBACK(Name)                             \
  const Operator* SimplifiedOperatorBuilder::Name(                     \
      const FeedbackSource& feedback, CheckBoundsFlags flags) {        \
    DCHECK(!(flags & CheckBoundsFlag::kConvertStringAndMinusZero));    \
    if (!feedback.IsValid()) {                                         \
      if (flags & CheckBoundsFlag::kAbortOnOutOfBounds) {              \
        return &cache_.k##Name##Aborting;                              \
      } else {                                                         \
        return &cache_.k##Name;                                        \
      }                                                                \
    }                                                                  \
    return zone()->New<SimplifiedOperatorGlobalCache::Name##Operator>( \
        feedback, flags);                                              \
  }
CHECKED_BOUNDS_OP_LIST(GET_FROM_CACHE_WITH_FEEDBACK)
#undef GET_FROM_CACHE_WITH_FEEDBACK

// For IrOpcode::kCheckBounds, we allow additional flags:
const Operator* SimplifiedOperatorBuilder::CheckBounds(
    const FeedbackSource& feedback, CheckBoundsFlags flags) {
  if (!feedback.IsValid()) {
    if (flags & CheckBoundsFlag::kAbortOnOutOfBounds) {
      if (flags & CheckBoundsFlag::kConvertStringAndMinusZero) {
        return &cache_.kCheckBoundsAbortingAndConverting;
      } else {
        return &cache_.kCheckBoundsAborting;
      }
    } else {
      if (flags & CheckBoundsFlag::kConvertStringAndMinusZero) {
        return &cache_.kCheckBoundsConverting;
      } else {
        return &cache_.kCheckBounds;
      }
    }
  }
  return zone()->New<SimplifiedOperatorGlobalCache::CheckBoundsOperator>(
      feedback, flags);
}

bool IsCheckedWithFeedback(const Operator* op) {
#define CASE(Name, ...) case IrOpcode::k##Name:
  switch (op->opcode()) {
    CHECKED_WITH_FEEDBACK_OP_LIST(CASE) return true;
    default:
      return false;
  }
#undef CASE
}

const Operator* SimplifiedOperatorBuilder::RuntimeAbort(AbortReason reason) {
  return zone()->New<Operator1<int>>(           // --
      IrOpcode::kRuntimeAbort,                  // opcode
      Operator::kNoThrow | Operator::kNoDeopt,  // flags
      "RuntimeAbort",                           // name
      0, 1, 1, 0, 1, 0,                         // counts
      static_cast<int>(reason));                // parameter
}

const Operator* SimplifiedOperatorBuilder::SpeculativeBigIntAsIntN(
    int bits, const FeedbackSource& feedback) {
  CHECK(0 <= bits && bits <= 64);

  return zone()->New<Operator1<SpeculativeBigIntAsNParameters>>(
      IrOpcode::kSpeculativeBigIntAsIntN, Operator::kNoProperties,
      "SpeculativeBigIntAsIntN", 1, 1, 1, 1, 1, 0,
      SpeculativeBigIntAsNParameters(bits, feedback));
}

const Operator* SimplifiedOperatorBuilder::SpeculativeBigIntAsUintN(
    int bits, const FeedbackSource& feedback) {
  CHECK(0 <= bits && bits <= 64);

  return zone()->New<Operator1<SpeculativeBigIntAsNParameters>>(
      IrOpcode::kSpeculativeBigIntAsUintN, Operator::kNoProperties,
      "SpeculativeBigIntAsUintN", 1, 1, 1, 1, 1, 0,
      SpeculativeBigIntAsNParameters(bits, feedback));
}

const Operator* SimplifiedOperatorBuilder::AssertType(Type type) {
  DCHECK(type.CanBeAsserted());
  return zone()->New<Operator1<Type>>(IrOpcode::kAssertType,
                                      Operator::kEliminatable, "AssertType", 1,
                                      1, 0, 0, 1, 0, type);
}

const Operator* SimplifiedOperatorBuilder::VerifyType() {
  return zone()->New<Operator>(IrOpcode::kVerifyType,
                               Operator::kNoThrow | Operator::kNoDeopt,
                               "VerifyType", 1, 1, 0, 0, 1, 0);
}

const Operator* SimplifiedOperatorBuilder::CheckTurboshaftTypeOf() {
  return zone()->New<Operator>(IrOpcode::kCheckTurboshaftTypeOf,
                               Operator::kNoThrow | Operator::kNoDeopt,
                               "CheckTurboshaftTypeOf", 2, 1, 1, 1, 1, 0);
}

#if V8_ENABLE_WEBASSEMBLY
const Operator* SimplifiedOperatorBuilder::WasmTypeCheck(
    WasmTypeCheckConfig config) {
  return zone_->New<Operator1<WasmTypeCheckConfig>>(
      IrOpcode::kWasmTypeCheck, Operator::kEliminatable | Operator::kIdempotent,
      "WasmTypeCheck", 2, 1, 1, 1, 1, 1, config);
}

const Operator* SimplifiedOperatorBuilder::WasmTypeCheckAbstract(
    WasmTypeCheckConfig config) {
  return zone_->New<Operator1<WasmTypeCheckConfig>>(
      IrOpcode::kWasmTypeCheckAbstract,
      Operator::kEliminatable | Operator::kIdempotent, "WasmTypeCheckAbstract",
      1, 1, 1, 1, 1, 1, config);
}

const Operator* SimplifiedOperatorBuilder::WasmTypeCast(
    WasmTypeCheckConfig config) {
  return zone_->New<Operator1<WasmTypeCheckConfig>>(
      IrOpcode::kWasmTypeCast,
      Operator::kNoWrite | Operator::kNoThrow | Operator::kIdempotent,
      "WasmTypeCast", 2, 1, 1, 1, 1, 1, config);
}

const Operator* SimplifiedOperatorBuilder::WasmTypeCastAbstract(
    WasmTypeCheckConfig config) {
  return zone_->New<Operator1<WasmTypeCheckConfig>>(
      IrOpcode::kWasmTypeCastAbstract,
      Operator::kNoW
"""


```
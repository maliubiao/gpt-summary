Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/simplified-operator.cc`. The decomposed instructions are:

1. **Identify the core purpose of the file:**  The filename suggests it's related to "simplified operators" within the V8 compiler.

2. **Check for Torque:** Scan the code for `.tq` extension mentions. There are none.

3. **Analyze JavaScript relation:** Look for keywords or concepts that link to JavaScript functionality. Terms like "Number", "String", "Boolean", "BigInt", and concepts like "TypeOf" suggest a strong connection to JavaScript's data types and operations.

4. **Identify code logic and examples:** The code defines structs and functions for representing and comparing different kinds of "accesses" (field, element, object) and "operations" (arithmetic, type conversions). The overloaded `operator<<` and `hash_value` functions are used for debugging and internal data structures, respectively. Look for opportunities to create simple input/output examples related to these structures.

5. **Identify potential programming errors:** Examine the code for areas where incorrect usage or assumptions could lead to errors. The numerous type conversion operators are potential candidates.

6. **Summarize the functionality:** Combine the findings into a concise description of the file's role.

**Detailed Thought Process:**

* **Core Purpose:** The `#include "src/compiler/simplified-operator.h"` at the top strongly indicates this file *implements* the declarations in the header file. The content of the file revolves around defining structures and functions to represent and manipulate operators in the simplified IR (Intermediate Representation) of the V8 compiler.

* **Torque:** A quick scan reveals no mentions of `.tq`.

* **JavaScript Relation:**  The presence of operators corresponding to JavaScript's primitive types (Number, String, Boolean, BigInt) and operations (addition, comparison, type conversion) is undeniable. The `TypeOf` operator is directly related to JavaScript's `typeof` operator. The concepts of "FieldAccess" and "ElementAccess" relate to accessing object properties and array elements in JavaScript.

* **Code Logic and Examples:**
    * **FieldAccess:**  Represents accessing a named property of an object. A `FieldAccess` structure holds information like the offset of the field, its type, and whether the base object is tagged (a pointer in V8's heap).
    * **ElementAccess:** Represents accessing an element of an array. It includes the header size (for variable-sized arrays) and the element type.
    * **ObjectAccess:**  A more general form of object access.
    * **Type Conversions:** Several operators (`ChangeTaggedToInt32`, `ChangeFloat64ToTagged`) represent type conversions, a fundamental aspect of JavaScript.
    * **Arithmetic Operators:**  Operators like `NumberAdd`, `NumberMultiply` directly correspond to JavaScript's arithmetic operations.
    * **Comparison Operators:** `NumberEqual`, `BigIntLessThan` map to JavaScript's comparison operators.

* **Programming Errors:**
    * **Incorrect Type Assumptions:**  When converting between tagged and untagged representations, or between different numeric types, incorrect assumptions can lead to errors. For instance, trying to treat a tagged value as an immediate integer without checking its tag.
    * **Out-of-bounds Access:**  Although not directly shown in this snippet, the `FieldAccess` and `ElementAccess` structures are used in the context of memory access. Incorrectly calculated offsets or indices can lead to out-of-bounds reads or writes. This is a common source of bugs in lower-level programming.
    * **Type Mismatches in Operations:**  Performing arithmetic operations on values of incompatible types (e.g., adding a string and a number without explicit conversion) can lead to unexpected results or errors.

* **Summary:**  The file defines the data structures and associated functions to represent the simplified operators used in V8's Turbofan compiler. These operators correspond to fundamental JavaScript operations and data access mechanisms. The code facilitates the representation, comparison, and manipulation of these operators during the compilation process.

By following these steps, I can generate a comprehensive and accurate summary of the provided code snippet.
这是 V8 JavaScript 引擎源代码的一部分，位于 `v8/src/compiler/simplified-operator.cc`。这个文件的主要功能是**定义和实现用于表示 V8 编译器中 "简化" 操作的各种数据结构和辅助函数**。

**功能归纳：**

1. **定义操作符的参数结构体:**  该文件定义了许多结构体，用于表示不同简化操作的特定参数。例如：
    * `FieldAccess`:  表示访问对象字段所需的参数，如基地址是否已标记、偏移量、映射、机器类型等。
    * `ElementAccess`: 表示访问数组元素所需的参数，如基地址是否已标记、头大小、机器类型等。
    * `CheckMapsParameters`:  表示类型检查操作所需的参数，如期望的 Map、标志位等。
    * `NumberOperationHint`:  表示数值运算的类型提示。
    * `AllocateParameters`: 表示内存分配的参数。

2. **重载操作符和哈希函数:**  它为这些参数结构体重载了 `operator==` (相等比较) 和 `hash_value` 函数。这允许将这些结构体用作哈希表中的键，并进行比较。

3. **提供便捷的访问函数:**  文件提供了一系列形如 `XXXOf(const Operator* op)` 的函数，用于从 `Operator` 对象中提取特定操作的参数结构体。例如，`FieldAccessOf(const Operator* op)` 可以获取一个 LoadField 或 StoreField 操作的 `FieldAccess` 参数。

4. **为参数结构体提供输出流支持:**  重载了 `operator<<`，使得可以直接将这些参数结构体输出到 `std::ostream`，方便调试和日志记录。

5. **定义枚举和辅助函数:**  定义了一些枚举类型，如 `BaseTaggedness`、`CheckFloat64HoleMode` 等，以及与这些枚举相关的输出流支持。

**这个文件不是 Torque 源代码。**  Torque 源代码的文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系：**

`simplified-operator.cc` 中定义的操作符直接对应于 JavaScript 的各种操作。编译器在将 JavaScript 代码转换为机器码的过程中，会将 JavaScript 的操作转换为这些简化的中间表示形式。

**JavaScript 例子：**

* **`FieldAccess` (访问对象属性):**

```javascript
const obj = { a: 10 };
const value = obj.a; // 对应 LoadField 操作
obj.b = 20;         // 对应 StoreField 操作
```

在这个例子中，访问 `obj.a` 和 `obj.b` 会在编译器的简化阶段表示为 `LoadField` 和 `StoreField` 操作，并使用 `FieldAccess` 结构体来描述访问的细节（例如，`a` 和 `b` 的内存偏移量）。

* **`ElementAccess` (访问数组元素):**

```javascript
const arr = [1, 2, 3];
const first = arr[0]; // 对应 LoadElement 操作
arr[1] = 4;         // 对应 StoreElement 操作
```

访问 `arr[0]` 和 `arr[1]` 会在编译器的简化阶段表示为 `LoadElement` 和 `StoreElement` 操作，并使用 `ElementAccess` 结构体来描述访问的细节（例如，元素的大小和偏移量）。

* **类型检查 (`CheckMapsParameters`):**

```javascript
function foo(x) {
  if (typeof x === 'number') { // 隐含的类型检查
    return x + 1;
  }
  return 0;
}
```

`typeof x === 'number'` 这样的类型检查会在编译器的简化阶段使用 `CheckMaps` 操作来验证 `x` 的类型是否为 Number。`CheckMapsParameters` 结构体将包含期望的 `Map` (Number 类型的 Map)。

* **数值运算 (`NumberOperationHint`):**

```javascript
function add(a, b) {
  return a + b;
}
```

`a + b` 这个加法操作在编译器的简化阶段会表示为 `NumberAdd` 操作。编译器可能会根据对 `a` 和 `b` 类型的推断，使用不同的 `NumberOperationHint`，例如 `kSignedSmall` 如果推断出 `a` 和 `b` 都是小的有符号整数。

**代码逻辑推理和假设输入输出：**

假设我们有一个 `LoadField` 操作，要访问一个对象的属性 `name`，该属性的偏移量为 8 字节，对象基地址是已标记的，并且期望对象的 Map 是 `map1`，机器类型是 `kWord32`。

**假设输入：** 一个指向 `LoadField` 操作的 `Operator` 指针 `op`。

**代码逻辑 (`FieldAccessOf(op)`) 的推理：**

1. `FieldAccessOf` 函数会检查 `op` 的 opcode 是否为 `IrOpcode::kLoadField`。
2. 如果是，它会将 `op` 强制转换为包含 `FieldAccess` 结构体的 `Operator1<FieldAccess>` 类型。
3. 它会返回该 `Operator1` 结构体中存储的 `FieldAccess` 成员。

**假设输出：**  一个 `FieldAccess` 结构体，其成员值可能如下：

```
FieldAccess {
  base_is_tagged: true,
  offset: 8,
  map: optional<MapRef>(map1), // 假设 map1 是一个 MapRef 对象
  machine_type: kWord32,
  // 其他成员的值...
}
```

**用户常见的编程错误（与此文件相关的概念）：**

虽然 `simplified-operator.cc` 是编译器内部的代码，但它反映了 JavaScript 开发者可能遇到的问题：

1. **类型假设错误：**  JavaScript 是动态类型的，但 V8 编译器会尝试进行类型推断以优化代码。如果开发者的代码导致编译器做出错误的类型假设，可能会导致性能下降或运行时错误。例如，频繁改变变量的类型可能会阻止编译器进行有效的优化。

   ```javascript
   let x = 10; // 编译器可能推断 x 是一个数字
   x = "hello"; // 之后又将 x 赋值为字符串，可能导致优化失效
   ```

2. **属性访问性能问题：**  访问对象属性的方式和对象的结构会影响性能。例如，访问一个有很多层级的属性可能比访问直接属性慢。V8 的编译器会尝试优化属性访问，但某些模式可能难以优化。

   ```javascript
   const obj = { a: { b: { c: 1 } } };
   const value = obj.a.b.c; // 访问深层嵌套的属性
   ```

3. **数组元素类型不一致：**  如果数组中的元素类型不一致（例如，既有数字又有字符串），V8 可能需要使用更通用的方式来处理数组元素，这可能会降低性能。

   ```javascript
   const arr = [1, "hello", 2.5]; // 数组元素类型不一致
   ```

**总结：**

`v8/src/compiler/simplified-operator.cc` 是 V8 编译器中一个至关重要的文件，它定义了用于表示和操作 JavaScript 语义的中间表示形式。这些表示形式在编译器的优化和代码生成阶段被广泛使用，直接影响了最终生成的机器码的效率。理解这个文件中的概念有助于理解 V8 编译器的工作原理，并可以帮助开发者编写更易于 V8 优化的 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/compiler/simplified-operator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/simplified-operator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
  V(ChangeInt64ToBigIn
"""


```
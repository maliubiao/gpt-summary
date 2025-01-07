Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The primary goal is to understand the *functionality* of the provided C++ code, which belongs to V8's compiler. The request also asks for specific details like Torque relevance, JavaScript connections, logical inference examples, and common programming errors.

2. **Initial Scan and Key Terms:**  Quickly scan the code for recognizable keywords and patterns. Notice:
    * `#include`: This confirms it's C++ code.
    * `namespace v8::internal::compiler`:  This places the code within V8's compilation pipeline.
    * `class PropertyAccessBuilder`: This is likely the core component. The name suggests it builds the logic for accessing properties.
    * `JSGraph`, `SimplifiedOperatorBuilder`, `CommonOperatorBuilder`: These are V8 compiler infrastructure components.
    * `MapRef`, `ObjectRef`, `PropertyAccessInfo`:  These represent V8's internal representations of JavaScript objects and their properties.
    * `CheckString`, `CheckNumber`, `CheckMaps`, `LoadField`: These look like compiler operations.

3. **High-Level Purpose of `PropertyAccessBuilder`:** Based on the name and the included headers, the `PropertyAccessBuilder` is responsible for generating the low-level compiler instructions (the "how") for accessing JavaScript object properties. It bridges the gap between high-level JavaScript operations and the underlying machine code.

4. **Analyze Key Methods (Functionality Breakdown):**  Go through the public methods of the class and try to understand their purpose.

    * **`TryBuildStringCheck` and `TryBuildNumberCheck`:** These methods seem to insert checks to ensure the receiver of a property access is a string or a number, respectively. The `FeedbackSource()` argument hints at optimization based on runtime information.

    * **`BuildCheckMaps`:** This method generates code to check if an object's map matches a set of expected maps. This is crucial for V8's hidden class optimization.

    * **`BuildCheckValue`:**  This method creates a check to ensure an object has a specific expected value. This is likely used for optimizations based on constant values.

    * **`BuildCheckSmi` and `BuildCheckNumber`:** Similar to the `TryBuild...Check` methods, but seemingly unconditional. They ensure a value is a small integer (Smi) or a number.

    * **`ResolveHolder`:** Determines the object that actually holds the property being accessed. This can be different from the initial object due to prototype chains.

    * **`ConvertRepresentation`:** Converts between different ways of representing data in the compiler.

    * **`FoldLoadDictPrototypeConstant`:** This deals with optimizing access to constants stored in the prototype chain's dictionary (a slower but more flexible property storage).

    * **`TryFoldLoadConstantDataField`:** Attempts to directly embed the constant value of a property into the generated code, avoiding a memory load.

    * **`BuildLoadDataField` (multiple overloads):**  This is the core method for generating the code to load the value of a property. It handles various cases like in-object vs. out-of-object properties, different data representations (doubles, tagged pointers, etc.), and potential deoptimization scenarios.

5. **Torque Check:** The prompt specifically asks about Torque. The filename ends in `.cc`, not `.tq`. Therefore, it's C++, not Torque.

6. **JavaScript Relationship (with Examples):**  Think about how the C++ code relates to everyday JavaScript. Each of the methods identified in step 4 directly corresponds to certain JavaScript operations. For example:
    * Property access (`obj.prop` or `obj['prop']`) is the fundamental operation being optimized.
    * Type checks (`typeof obj === 'string'`, `typeof obj === 'number'`) are related to `TryBuildStringCheck` and `TryBuildNumberCheck`.
    * Checking object structure (hidden classes) relates to `BuildCheckMaps`.
    * Accessing prototype properties involves `ResolveHolder`.

7. **Logical Inference Examples:** Create simple scenarios and trace the potential flow through the code. Consider different input types and how the `PropertyAccessBuilder` might generate different instructions. Focus on:
    * Accessing a property of a string.
    * Accessing a property of a number.
    * Accessing a property on an object with a known shape (stable map).
    * Accessing a property that might be on the prototype chain.

8. **Common Programming Errors:** Connect the compiler optimizations to potential pitfalls for JavaScript developers. For example:
    * Modifying object structure after optimization can lead to deoptimization.
    * Relying on properties being present without checking can cause errors.
    * Unintentional type changes can hinder performance.

9. **Refine and Organize:**  Structure the findings into clear sections as requested by the prompt (functionality, Torque, JavaScript examples, inference, errors). Use precise language and avoid jargon where possible, explaining technical terms if necessary.

10. **Review:**  Read through the generated answer to ensure it's accurate, comprehensive, and addresses all parts of the prompt. Double-check the code snippets and explanations for correctness. For instance, ensure the JavaScript examples accurately illustrate the corresponding C++ functionality.

Self-Correction Example During the Process:

* **Initial thought:** "Maybe `PropertyAccessBuilder` directly executes the property access."
* **Correction:** "No, looking at the method names like `BuildCheck...` and `BuildLoad...`, it seems to be *generating* the code for property access, not performing it directly. It's part of the compilation process."  This refinement leads to a more accurate understanding of the class's role.
好的，让我们来分析一下 `v8/src/compiler/property-access-builder.cc` 这个文件。

**功能列举:**

`PropertyAccessBuilder` 类的主要功能是为 JavaScript 对象的属性访问（包括读取和写入）生成中间代码（在 V8 的 TurboFan 编译器中）。它负责根据对象的类型、属性的特性（例如，是否在对象自身，是否在原型链上，是否是常量等）以及编译时的已知信息，生成高效的机器码。

更具体地说，`PropertyAccessBuilder` 实现了以下功能：

1. **类型检查 (Type Checks):**
   - 尝试生成代码来检查接收器是否是字符串 (`TryBuildStringCheck`) 或数字 (`TryBuildNumberCheck`)。这允许针对特定类型进行优化。
   - 生成通用的类型检查 (`BuildCheckSmi`, `BuildCheckNumber`)。

2. **Map 检查 (Map Checks):**
   - `BuildCheckMaps`:  生成代码来检查对象的 Map（V8 中用于描述对象结构的隐藏类）是否与预期的 Map 集合匹配。这是 V8 优化的关键，因为它允许基于对象的形状进行假设。

3. **值检查 (Value Checks):**
   - `BuildCheckValue`: 生成代码来检查对象是否具有特定的预期值。

4. **持有者解析 (Holder Resolution):**
   - `ResolveHolder`: 确定实际拥有该属性的对象，这在处理原型链时非常重要。

5. **常量折叠 (Constant Folding):**
   - `FoldLoadDictPrototypeConstant`:  当可以确定属性值是原型链上字典中的常量时，尝试直接加载该常量值，避免实际的属性查找。
   - `TryFoldLoadConstantDataField`: 尝试直接加载对象自身快速属性中的常量值。

6. **数据字段加载 (Data Field Loading):**
   - `BuildLoadDataField`: 生成用于加载对象数据字段的代码。这包括处理内联属性（in-object properties）和存储在属性数组中的属性，以及处理不同的数据表示（例如，Smi，Double，Tagged 引用）。

7. **表示转换 (Representation Conversion):**
   - `ConvertRepresentation`:  将编译器的内部表示形式转换为机器表示形式。

**关于文件类型:**

`v8/src/compiler/property-access-builder.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果文件名以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 用来生成运行时代码（例如内置函数）的领域特定语言。

**与 JavaScript 的关系及示例:**

`PropertyAccessBuilder` 直接服务于 JavaScript 的属性访问操作。以下是一些 JavaScript 示例以及 `PropertyAccessBuilder` 如何参与其中：

```javascript
const obj = { x: 10, y: "hello" };
const value = obj.x; // 属性读取
obj.y = "world";     // 属性写入
```

**属性读取 (`obj.x`) 的幕后工作 (简化):**

1. **类型检查:** `PropertyAccessBuilder` 可能会生成类似 `CheckNumber` 的操作，假设 V8 的优化器已经推断出 `obj.x` 是一个数字。
2. **Map 检查:** 如果 `obj` 的 Map 是稳定的，`PropertyAccessBuilder` 可能会生成 `CheckMaps` 操作，以确保 `obj` 的结构没有改变。
3. **数据字段加载:** `BuildLoadDataField` 会生成指令来读取 `obj` 内部存储 `x` 的位置的值。如果 `x` 是一个内联属性，则直接从 `obj` 的内存布局中读取；如果不是，则可能需要先加载属性数组。

**属性写入 (`obj.y = "world"`) 的幕后工作 (简化，未在此文件中详细展示):**

虽然 `property-access-builder.cc` 主要关注读取，但它也为写入操作提供基础。写入操作会涉及查找属性、进行类型检查（如果需要），并更新对象内部的存储。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- `access_info`: 一个 `PropertyAccessInfo` 对象，描述了要访问的属性 `x`，它是一个内联的数字属性，属于一个 Map 为 `M` 的对象。
- `lookup_start_object`: 指向 `obj` 对象的节点。

**逻辑推理 (基于 `BuildLoadDataField`):**

1. `TryFoldLoadConstantDataField`: 如果 `x` 的值在编译时已知且是常量，则直接输出该常量值节点。
2. `ConvertRepresentation`:  确定 `x` 的表示形式，例如 `MachineRepresentation::kTaggedSigned` 或 `MachineRepresentation::kFloat64`。
3. `ResolveHolder`: 在这种情况下，持有者就是 `obj` 本身。
4. `BuildLoadDataField`:
   - 由于 `x` 是内联属性，不需要加载属性数组。
   - 生成 `simplified()->LoadField` 操作，从 `obj` 的特定偏移量处加载值。
   - 加载操作的机器类型会基于 `x` 的表示形式。

**假设输出 (抽象表示):**

```
// 假设 x 是一个 Smi (小整数)
LoadField {
  base: lookup_start_object, // 指向 obj 的节点
  offset: offset_of_x_in_obj,
  machine_type: kTaggedSigned
}
```

**涉及用户常见的编程错误:**

1. **假设对象结构不变导致的性能问题:**

   ```javascript
   function Point(x, y) {
     this.x = x;
     this.y = y;
   }

   const p1 = new Point(1, 2); // V8 会基于此形状进行优化
   const p2 = new Point(3, 4);

   p1.z = 5; // 修改了 p1 的形状

   console.log(p1.x + p1.y); // 访问 p1 的属性可能会变慢，因为形状不再一致
   console.log(p2.x + p2.y); // 访问 p2 的属性可能仍然很快
   ```

   **解释:**  V8 依赖于对象的 Map（隐藏类）来优化属性访问。如果运行时对象的形状发生改变（例如，动态添加或删除属性），之前基于该形状的优化可能失效，导致 deoptimization。`PropertyAccessBuilder` 生成的代码在很大程度上依赖于 Map 的稳定性。

2. **访问未定义的属性:**

   ```javascript
   const obj = { a: 1 };
   console.log(obj.b); // 输出 undefined
   ```

   **解释:**  当尝试访问一个不存在的属性时，JavaScript 返回 `undefined`。`PropertyAccessBuilder` 在编译时会尝试预测属性是否存在，并生成相应的加载或查找操作。如果预测错误，可能会导致性能损失或需要回退到更通用的查找路径。

3. **类型不一致导致的 deoptimization:**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(1, 2);      // V8 可能会假设 a 和 b 都是数字
   add("hello", 3); // 类型不一致，可能导致之前生成的优化代码失效
   ```

   **解释:**  `TryBuildStringCheck` 和 `TryBuildNumberCheck` 等方法的目标是利用类型信息进行优化。如果运行时类型与编译时的假设不符，V8 可能需要 deoptimize 并重新编译代码。

**总结:**

`v8/src/compiler/property-access-builder.cc` 是 V8 编译器中一个核心组件，负责生成高效的属性访问代码。它通过类型检查、Map 检查、常量折叠等多种技术来优化 JavaScript 的属性访问性能。理解这个文件的功能有助于深入理解 V8 的内部工作原理以及如何编写更易于优化的 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/compiler/property-access-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/property-access-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/property-access-builder.h"

#include <optional>

#include "src/compiler/access-builder.h"
#include "src/compiler/access-info.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/simplified-operator.h"
#include "src/objects/heap-number.h"
#include "src/objects/internal-index.h"
#include "src/objects/js-function.h"
#include "src/objects/map-inl.h"
#include "src/objects/property-details.h"

namespace v8 {
namespace internal {
namespace compiler {

Graph* PropertyAccessBuilder::graph() const { return jsgraph()->graph(); }

Isolate* PropertyAccessBuilder::isolate() const { return jsgraph()->isolate(); }

CommonOperatorBuilder* PropertyAccessBuilder::common() const {
  return jsgraph()->common();
}

SimplifiedOperatorBuilder* PropertyAccessBuilder::simplified() const {
  return jsgraph()->simplified();
}

bool HasOnlyStringMaps(JSHeapBroker* broker, ZoneVector<MapRef> const& maps) {
  for (MapRef map : maps) {
    if (!map.IsStringMap()) return false;
  }
  return true;
}

bool HasOnlyStringWrapperMaps(JSHeapBroker* broker,
                              ZoneVector<MapRef> const& maps) {
  for (MapRef map : maps) {
    if (!map.IsJSPrimitiveWrapperMap()) return false;
    auto elements_kind = map.elements_kind();
    if (elements_kind != FAST_STRING_WRAPPER_ELEMENTS &&
        elements_kind != SLOW_STRING_WRAPPER_ELEMENTS) {
      return false;
    }
  }
  return true;
}

namespace {

bool HasOnlyNumberMaps(JSHeapBroker* broker, ZoneVector<MapRef> const& maps) {
  for (MapRef map : maps) {
    if (map.instance_type() != HEAP_NUMBER_TYPE) return false;
  }
  return true;
}

}  // namespace

bool PropertyAccessBuilder::TryBuildStringCheck(JSHeapBroker* broker,
                                                ZoneVector<MapRef> const& maps,
                                                Node** receiver, Effect* effect,
                                                Control control) {
  if (HasOnlyStringMaps(broker, maps)) {
    // Monormorphic string access (ignoring the fact that there are multiple
    // String maps).
    *receiver = *effect =
        graph()->NewNode(simplified()->CheckString(FeedbackSource()), *receiver,
                         *effect, control);
    return true;
  }
  return false;
}

bool PropertyAccessBuilder::TryBuildNumberCheck(JSHeapBroker* broker,
                                                ZoneVector<MapRef> const& maps,
                                                Node** receiver, Effect* effect,
                                                Control control) {
  if (HasOnlyNumberMaps(broker, maps)) {
    // Monomorphic number access (we also deal with Smis here).
    *receiver = *effect =
        graph()->NewNode(simplified()->CheckNumber(FeedbackSource()), *receiver,
                         *effect, control);
    return true;
  }
  return false;
}

void PropertyAccessBuilder::BuildCheckMaps(Node* object, Effect* effect,
                                           Control control,
                                           ZoneVector<MapRef> const& maps) {
  HeapObjectMatcher m(object);
  if (m.HasResolvedValue()) {
    MapRef object_map = m.Ref(broker()).map(broker());
    if (object_map.is_stable()) {
      for (MapRef map : maps) {
        if (map.equals(object_map)) {
          dependencies()->DependOnStableMap(object_map);
          return;
        }
      }
    }
  }
  ZoneRefSet<Map> map_set;
  CheckMapsFlags flags = CheckMapsFlag::kNone;
  for (MapRef map : maps) {
    map_set.insert(map, graph()->zone());
    if (map.is_migration_target()) {
      flags |= CheckMapsFlag::kTryMigrateInstance;
    }
  }
  *effect = graph()->NewNode(simplified()->CheckMaps(flags, map_set), object,
                             *effect, control);
}

Node* PropertyAccessBuilder::BuildCheckValue(Node* receiver, Effect* effect,
                                             Control control, ObjectRef value) {
  if (value.IsHeapObject()) {
    HeapObjectMatcher m(receiver);
    if (m.Is(value.AsHeapObject().object())) return receiver;
  }
  Node* expected = jsgraph()->ConstantNoHole(value, broker());
  Node* check =
      graph()->NewNode(simplified()->ReferenceEqual(), receiver, expected);
  *effect =
      graph()->NewNode(simplified()->CheckIf(DeoptimizeReason::kWrongValue),
                       check, *effect, control);
  return expected;
}

Node* PropertyAccessBuilder::BuildCheckSmi(Node* value, Effect* effect,
                                           Control control,
                                           FeedbackSource feedback_source) {
  Node* smi_value = *effect = graph()->NewNode(
      simplified()->CheckSmi(feedback_source), value, *effect, control);
  return smi_value;
}

Node* PropertyAccessBuilder::BuildCheckNumber(Node* value, Effect* effect,
                                              Control control,
                                              FeedbackSource feedback_source) {
  Node* number = *effect = graph()->NewNode(
      simplified()->CheckNumber(feedback_source), value, *effect, control);
  return number;
}

Node* PropertyAccessBuilder::ResolveHolder(
    PropertyAccessInfo const& access_info, Node* lookup_start_object) {
  OptionalJSObjectRef holder = access_info.holder();
  if (holder.has_value()) {
    return jsgraph()->ConstantNoHole(holder.value(), broker());
  }
  return lookup_start_object;
}

MachineRepresentation PropertyAccessBuilder::ConvertRepresentation(
    Representation representation) {
  switch (representation.kind()) {
    case Representation::kSmi:
      return MachineRepresentation::kTaggedSigned;
    case Representation::kDouble:
      return MachineRepresentation::kFloat64;
    case Representation::kHeapObject:
      return MachineRepresentation::kTaggedPointer;
    case Representation::kTagged:
      return MachineRepresentation::kTagged;
    default:
      UNREACHABLE();
  }
}

std::optional<Node*> PropertyAccessBuilder::FoldLoadDictPrototypeConstant(
    PropertyAccessInfo const& access_info) {
  DCHECK(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);
  DCHECK(access_info.IsDictionaryProtoDataConstant());

  InternalIndex index = access_info.dictionary_index();
  OptionalObjectRef value = access_info.holder()->GetOwnDictionaryProperty(
      broker(), index, dependencies());
  if (!value) return {};

  for (MapRef map : access_info.lookup_start_object_maps()) {
    DirectHandle<Map> map_handle = map.object();
    // Non-JSReceivers that passed AccessInfoFactory::ComputePropertyAccessInfo
    // must have different lookup start map.
    if (!IsJSReceiverMap(*map_handle)) {
      // Perform the implicit ToObject for primitives here.
      // Implemented according to ES6 section 7.3.2 GetV (V, P).
      Tagged<JSFunction> constructor =
          Map::GetConstructorFunction(
              *map_handle, *broker()->target_native_context().object())
              .value();
      // {constructor.initial_map()} is loaded/stored with acquire-release
      // semantics for constructors.
      map = MakeRefAssumeMemoryFence(broker(), constructor->initial_map());
      DCHECK(IsJSObjectMap(*map.object()));
    }
    dependencies()->DependOnConstantInDictionaryPrototypeChain(
        map, access_info.name(), value.value(), PropertyKind::kData);
  }

  return jsgraph()->ConstantNoHole(value.value(), broker());
}

Node* PropertyAccessBuilder::TryFoldLoadConstantDataField(
    NameRef name, PropertyAccessInfo const& access_info,
    Node* lookup_start_object) {
  if (!access_info.IsFastDataConstant()) return nullptr;

  // First, determine if we have a constant holder to load from.
  OptionalJSObjectRef holder = access_info.holder();

  // If {access_info} has a holder, just use it.
  if (!holder.has_value()) {
    // Otherwise, try to match the {lookup_start_object} as a constant.
    if (lookup_start_object->opcode() == IrOpcode::kCheckString ||
        lookup_start_object->opcode() ==
            IrOpcode::kCheckStringOrStringWrapper) {
      // Bypassing Check inputs in order to allow constant folding.
      lookup_start_object = lookup_start_object->InputAt(0);
    }
    HeapObjectMatcher m(lookup_start_object);
    if (!m.HasResolvedValue() || !m.Ref(broker()).IsJSObject()) return nullptr;

    // Let us make sure the actual map of the constant lookup_start_object is
    // among the maps in {access_info}.
    MapRef lookup_start_object_map = m.Ref(broker()).map(broker());
    if (std::find_if(access_info.lookup_start_object_maps().begin(),
                     access_info.lookup_start_object_maps().end(),
                     [&](MapRef map) {
                       return map.equals(lookup_start_object_map);
                     }) == access_info.lookup_start_object_maps().end()) {
      // The map of the lookup_start_object is not in the feedback, let us bail
      // out.
      return nullptr;
    }
    holder = m.Ref(broker()).AsJSObject();
  }

  if (access_info.field_representation().IsDouble()) {
    std::optional<Float64> value = holder->GetOwnFastConstantDoubleProperty(
        broker(), access_info.field_index(), dependencies());
    return value.has_value() ? jsgraph()->ConstantNoHole(value->get_scalar())
                             : nullptr;
  }
  OptionalObjectRef value = holder->GetOwnFastConstantDataProperty(
      broker(), access_info.field_representation(), access_info.field_index(),
      dependencies());
  return value.has_value() ? jsgraph()->ConstantNoHole(*value, broker())
                           : nullptr;
}

Node* PropertyAccessBuilder::BuildLoadDataField(NameRef name, Node* holder,
                                                FieldAccess&& field_access,
                                                bool is_inobject, Node** effect,
                                                Node** control) {
  Node* storage = holder;
  if (!is_inobject) {
    storage = *effect = graph()->NewNode(
        simplified()->LoadField(
            AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer()),
        storage, *effect, *control);
  }
  if (field_access.machine_type.representation() ==
      MachineRepresentation::kFloat64) {
    if (dependencies() == nullptr) {
      FieldAccess const storage_access = {kTaggedBase,
                                          field_access.offset,
                                          name.object(),
                                          OptionalMapRef(),
                                          Type::Any(),
                                          MachineType::AnyTagged(),
                                          kPointerWriteBarrier,
                                          "BuildLoadDataField",
                                          field_access.const_field_info};
      storage = *effect = graph()->NewNode(
          simplified()->LoadField(storage_access), storage, *effect, *control);
      // We expect the loaded value to be a heap number here. With
      // in-place field representation changes it is possible this is a
      // no longer a heap number without map transitions. If we haven't taken
      // a dependency on field representation, we should verify the loaded
      // value is a heap number.
      storage = *effect = graph()->NewNode(simplified()->CheckHeapObject(),
                                           storage, *effect, *control);
      Node* map = *effect =
          graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                           storage, *effect, *control);
      Node* is_heap_number =
          graph()->NewNode(simplified()->ReferenceEqual(), map,
                           jsgraph()->HeapNumberMapConstant());
      *effect = graph()->NewNode(
          simplified()->CheckIf(DeoptimizeReason::kNotAHeapNumber),
          is_heap_number, *effect, *control);
    } else {
      FieldAccess const storage_access = {kTaggedBase,
                                          field_access.offset,
                                          name.object(),
                                          OptionalMapRef(),
                                          Type::OtherInternal(),
                                          MachineType::TaggedPointer(),
                                          kPointerWriteBarrier,
                                          "BuildLoadDataField",
                                          field_access.const_field_info};
      storage = *effect = graph()->NewNode(
          simplified()->LoadField(storage_access), storage, *effect, *control);
    }
    FieldAccess value_field_access = AccessBuilder::ForHeapNumberValue();
    value_field_access.const_field_info = field_access.const_field_info;
    field_access = value_field_access;
  }
  Node* value = *effect = graph()->NewNode(
      simplified()->LoadField(field_access), storage, *effect, *control);
  return value;
}

Node* PropertyAccessBuilder::BuildLoadDataField(
    NameRef name, PropertyAccessInfo const& access_info,
    Node* lookup_start_object, Node** effect, Node** control) {
  DCHECK(access_info.IsDataField() || access_info.IsFastDataConstant());

  if (Node* value = TryFoldLoadConstantDataField(name, access_info,
                                                 lookup_start_object)) {
    return value;
  }

  MachineRepresentation const field_representation =
      ConvertRepresentation(access_info.field_representation());
  Node* storage = ResolveHolder(access_info, lookup_start_object);

  FieldAccess field_access = {
      kTaggedBase,
      access_info.field_index().offset(),
      name.object(),
      OptionalMapRef(),
      access_info.field_type(),
      MachineType::TypeForRepresentation(field_representation),
      kFullWriteBarrier,
      "BuildLoadDataField",
      access_info.GetConstFieldInfo()};
  if (field_representation == MachineRepresentation::kTaggedPointer ||
      field_representation == MachineRepresentation::kCompressedPointer) {
    // Remember the map of the field value, if its map is stable. This is
    // used by the LoadElimination to eliminate map checks on the result.
    OptionalMapRef field_map = access_info.field_map();
    if (field_map.has_value()) {
      if (field_map->is_stable()) {
        dependencies()->DependOnStableMap(field_map.value());
        field_access.map = field_map;
      }
    }
  }
  return BuildLoadDataField(name, storage, std::move(field_access),
                            access_info.field_index().is_inobject(), effect,
                            control);
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```
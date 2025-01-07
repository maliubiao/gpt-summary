Response:
Let's break down the request and the provided C++ code to figure out how to best answer.

**Understanding the Request:**

The request asks for an analysis of a V8 source code file (`v8/src/compiler/access-info.cc`), specifically focusing on:

1. **Functionality:** What does this code do?
2. **Torque:**  Is it a Torque file (indicated by the `.tq` extension)?
3. **JavaScript Relevance:** How does it relate to JavaScript?  Provide JavaScript examples if applicable.
4. **Logic Inference:**  Illustrate with hypothetical inputs and outputs.
5. **Common Errors:**  Explain potential user programming mistakes related to this code.
6. **Summary:** A concise overview of its purpose.
7. **Context:**  This is the second part of a two-part analysis, implying some context might be missing.

**Analyzing the Code:**

The provided code snippet is a function within the `AccessInfoFactory` class, specifically the `LookupForRead` function and related helper functions. Here's a breakdown of its logic:

* **Purpose:** The core goal is to determine the most efficient way to access a property of an object in JavaScript. It analyzes the object's map (structure), prototype chain, and property descriptors. This is crucial for optimization in the V8 JavaScript engine.
* **Key Concepts:**
    * **Maps:** Hidden classes that describe the structure of JavaScript objects. Optimizations often rely on consistent map structures.
    * **Prototype Chain:**  The mechanism for inheritance in JavaScript.
    * **Property Descriptors:** Metadata about object properties (e.g., writable, enumerable, getter/setter).
    * **Access Modes:** Whether it's a read, write, define, etc.
    * **Property Location:**  Where the property is stored (e.g., in the object's fields or in its descriptor).
    * **Property Kind:** Whether it's a data property or an accessor (getter/setter).
    * **Transitions:**  Changes in an object's map structure when properties are added or modified.
    * **Inline Caching:**  A performance optimization where V8 remembers how it accessed a property previously to speed up future accesses. `access-info.cc` plays a key role in enabling this.
* **Workflow of `LookupForRead` (and related logic):**
    1. **Start with the receiver object's map.**
    2. **Check if the property exists directly on the object's map.**
       * If yes, and it's a data field, determine its location, representation (e.g., Smi, double, object), and type.
       * If yes, and it's an accessor, handle it (currently, the code seems to have limited support for general accessors).
    3. **If the property isn't found, traverse the prototype chain.**
       * For each prototype, check its map and property descriptors.
       * Consider special cases like `String.prototype.length`.
       * Handle dictionary prototypes (less optimized).
       * Stop if a proxy is encountered in the prototype chain (cannot optimize).
    4. **Handle "store" and "define" access modes differently (no prototype lookup).**
    5. **If the property is not found after traversing the chain, return `NotFound` or initiate a transition if it's a store operation.**
* **Helper Functions:**  Functions like `ComputeDataFieldAccessInfo`, `ComputeAccessorDescriptorAccessInfo`, `LookupTransition`, etc., refine the access information based on the property's details.
* **`FinalizePropertyAccessInfos`:** This function seems to merge and process multiple `PropertyAccessInfo` objects, potentially from different execution paths or optimizations.
* **`ElementAccessInfo`:** Handles accesses to array elements.

**Planning the Answer:**

Now, let's map the code analysis to the requested points:

1. **Functionality:** Explain the role of `access-info.cc` in determining efficient property access strategies. Highlight its interactions with maps, prototypes, and property descriptors.
2. **Torque:** State clearly that the `.cc` extension means it's **not** a Torque file.
3. **JavaScript Relevance:**  Provide examples of common JavaScript operations that would trigger the logic in this code (property access, both reads and writes, on regular objects and objects with prototypes).
4. **Logic Inference:** Choose a simple scenario (e.g., accessing a property on a basic object, accessing a property on a prototype) and trace the likely execution path, showing input (object and property name) and the output (`PropertyAccessInfo`).
5. **Common Errors:** Explain how misunderstandings of prototypes and object structures can lead to performance issues that this code tries to mitigate. Give examples of code that might inadvertently create less optimizable object structures.
6. **Summary:**  A concise restatement of the main purpose.
7. **Context:** Acknowledge that this is part two and emphasize the connection to the overall compilation process (e.g., how the information gathered here is used by the JIT compiler).

**Self-Correction/Refinement:**

* **Initial thought:** Focus heavily on the C++ details.
* **Correction:** Prioritize explaining the *JavaScript impact* of this code. The C++ is the implementation, but the user needs to understand *why* it matters in a JavaScript context.
* **Initial thought:** Provide very complex code tracing.
* **Correction:**  Simplify the logic inference example to be easily understandable. Focus on the *concept* rather than getting bogged down in every branch of the C++ code.
* **Initial thought:**  Only discuss reads.
* **Correction:** Include writes and defines, as the code handles different `AccessMode` values. This provides a more complete picture.

By following this thought process, I can construct a comprehensive and user-friendly answer that addresses all aspects of the request. The key is to bridge the gap between the low-level C++ implementation and the high-level JavaScript concepts that developers are familiar with.
好的，根据您提供的代码片段，我们来归纳一下 `v8/src/compiler/access-info.cc` 的功能（这是第 2 部分，我们结合上下文来理解）。

**功能归纳:**

从这段代码片段来看，`v8/src/compiler/access-info.cc` 的核心功能是 **为 JavaScript 对象的属性访问（读取和写入）生成优化信息 (PropertyAccessInfo) 和元素访问信息 (ElementAccessInfo)**。  它深入分析了对象的结构（通过 Map），属性的定义，以及原型链，以确定最有效的访问方式。

具体来说，这段代码片段主要负责以下几个方面：

1. **查找属性 (LookupForRead):**  当需要读取或写入对象的属性时，这个函数会根据属性名称 (`name`) 和访问模式 (`access_mode`) 查找属性的位置和特性。它会考虑：
   - **对象的 Map (结构):**  检查属性是否直接存在于对象的结构中。
   - **原型链:** 如果属性在当前对象中找不到，会沿着原型链向上查找。
   - **属性描述符:** 获取属性的详细信息，例如是否可写，是否是访问器等。
   - **特殊属性:** 处理像 `String.prototype.length` 这样的特殊属性。
   - **字典模式原型:**  考虑原型链中是否存在字典模式的对象，这会影响优化策略。
   - **访问模式:**  区分读取、写入、定义等不同的操作。
   - **私有符号:** 不会在原型链上查找私有符号。

2. **生成 PropertyAccessInfo:**  一旦找到了属性，或者确定了属性不存在，这个函数会生成 `PropertyAccessInfo` 对象。这个对象包含了用于后续代码生成和优化的关键信息，例如：
   - 属性的位置（字段、描述符）。
   - 属性的类型和表示（例如，Smi、Double、HeapObject）。
   - 属性是否是常量。
   - 如果访问需要进行状态转换，会记录转换的 Map。
   - 依赖信息，用于在对象结构发生变化时使优化失效。

3. **处理 Transition (LookupTransition):** 当尝试写入一个不存在的属性时，或者当属性写入导致对象结构发生变化时，`LookupTransition` 函数会查找或创建一个新的 Map 结构来反映这种变化。它会生成相应的 `PropertyAccessInfo`，包含新 Map 的信息。

4. **合并 AccessInfo (FinalizePropertyAccessInfosAsOne, MergePropertyAccessInfos):** 当有多个可能的属性访问路径时（例如，在内联缓存中），这些函数用于合并和最终确定一个最优的 `PropertyAccessInfo`。

5. **处理元素访问 (ConsolidateElementLoad):**  `ConsolidateElementLoad` 函数用于分析数组元素的访问模式，并生成 `ElementAccessInfo`，用于优化数组元素的读取。它会考虑数组的元素类型（例如，Smi、Double、Tagged）。

6. **查找特殊字段访问器 (LookupSpecialFieldAccessor):**  用于处理某些内置对象的特殊属性访问，例如 `String.prototype.length` 或 `Array.prototype.length`。

**关于您提出的问题:**

* **`.tq` 结尾:** `v8/src/compiler/access-info.cc` 以 `.cc` 结尾，这意味着它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。

* **与 JavaScript 的关系:**  `v8/src/compiler/access-info.cc` 与 JavaScript 的功能密切相关。它直接参与了 JavaScript 属性访问的优化过程。每当 JavaScript 代码尝试访问对象的属性时，V8 的编译器（Turbofan 或 Crankshaft）会使用 `AccessInfoFactory` 来获取关于该属性的访问信息，以便生成更高效的机器码。

**JavaScript 示例:**

```javascript
const obj = { x: 10 };
console.log(obj.x); // 读取属性 x

obj.y = 20; // 写入属性 y

function Point(a, b) {
  this.a = a;
  this.b = b;
}
const point = new Point(1, 2);
console.log(point.a); // 读取原型链上的属性
```

在上面的例子中，每当访问 `obj.x`、`obj.y` 或 `point.a` 时，V8 的编译器内部就会使用类似 `LookupForRead` 这样的函数来分析如何高效地访问这些属性。

* **代码逻辑推理:**

**假设输入:**

1. `receiver_map`:  一个指向以下 JavaScript 对象的 Map 的引用：`{ a: 1, b: 2 }`
2. `name`:  表示字符串 `"b"` 的 `NameRef`。
3. `access_mode`:  `AccessMode::kLoad` (读取操作)。

**可能的输出:**

一个 `PropertyAccessInfo` 对象，其中可能包含以下信息：

- `location`: `PropertyLocation::kField` (属性 `b` 存储在对象的字段中)。
- `kind`: `PropertyKind::kData` (属性 `b` 是一个数据属性)。
- `field_index`:  属性 `b` 在对象字段中的索引。
- `representation`:  `Representation::Smi()` (假设值为小整数)。
- `type`:  `Type::SignedSmall()` (推断出的类型)。
- `holder`:  指向接收者对象自身的引用。

**详细的推理步骤可能涉及:**

1. `LookupForRead` 被调用，传入 `receiver_map`，`name` (表示 "b")，和 `access_mode` (kLoad)。
2. 代码检查 `receiver_map` 是否直接包含名为 "b" 的属性。
3. 如果找到，获取属性的详细信息（位置、类型、表示等）。
4. 创建并返回一个包含这些信息的 `PropertyAccessInfo` 对象。

**假设输入 (原型链的情况):**

1. `receiver_map`:  一个指向空对象 `{}` 的 Map 的引用。
2. `name`:  表示字符串 `"toString"` 的 `NameRef`。
3. `access_mode`: `AccessMode::kLoad`.

**可能的输出:**

一个 `PropertyAccessInfo` 对象，指示属性 `toString` 在 `Object.prototype` 上找到，并包含关于 `Object.prototype.toString` 的信息（通常是一个原生访问器）。

**详细的推理步骤可能涉及:**

1. `LookupForRead` 被调用。
2. 代码在接收者对象的 `receiver_map` 中找不到属性 `"toString"`。
3. 代码会沿着原型链向上查找，首先查找 `Object.prototype`。
4. 在 `Object.prototype` 的 Map 中找到 `"toString"` 属性。
5. 获取 `Object.prototype.toString` 的详细信息（通常是一个描述符访问器）。
6. 创建并返回相应的 `PropertyAccessInfo`。

* **用户常见的编程错误:**

与这段代码逻辑相关的用户常见编程错误通常会导致 V8 无法进行有效的属性访问优化，从而降低性能。一些例子包括：

1. **频繁地动态添加或删除属性:** 这会导致对象 Map 的频繁变化，使得 V8 难以进行内联缓存等优化。

   ```javascript
   const obj = {};
   for (let i = 0; i < 1000; i++) {
     obj['prop' + i] = i; // 频繁添加新属性
   }
   ```

2. **以不一致的顺序添加属性:**  即使属性相同，添加顺序不同也会导致不同的 Map 结构。

   ```javascript
   const obj1 = { a: 1, b: 2 };
   const obj2 = { b: 2, a: 1 }; // obj1 和 obj2 的 Map 可能不同
   ```

3. **修改对象的 `__proto__` 属性:**  这会打破 V8 对原型链结构的假设，导致优化失效。

   ```javascript
   const obj = {};
   obj.__proto__ = null; // 避免这样做
   ```

4. **使用 `delete` 操作符频繁删除属性:**  类似于动态添加属性，这会导致 Map 的变化。

   ```javascript
   const obj = { a: 1, b: 2 };
   delete obj.a;
   ```

5. **对基本类型包装对象进行属性访问:** 虽然 JavaScript 允许这样做，但对基本类型包装对象（如 `new Number(5)`）的属性访问可能不如直接访问基本类型高效。

**总结:**

`v8/src/compiler/access-info.cc` (的这个部分) 的主要职责是在编译 JavaScript 代码时，分析对象的结构和属性，并生成用于优化属性访问的关键信息。它深入理解 JavaScript 的原型继承和对象模型，以便 V8 能够生成尽可能高效的机器码来执行属性读取和写入操作。理解其背后的逻辑有助于我们编写更易于 V8 优化的 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/compiler/access-info.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/access-info.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ssInfo(
            receiver_map, name, holder.value(), index, access_mode, details);
      }

      if (dictionary_prototype_on_chain) {
        // If V8_DICT_PROPERTY_CONST_TRACKING_BOOL was disabled, then a
        // dictionary prototype would have caused a bailout earlier.
        DCHECK(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);

        // TODO(v8:11248) We have a fast mode holder, but there was a dictionary
        // mode prototype earlier on the chain. Note that seeing a fast mode
        // prototype even though V8_DICT_PROPERTY_CONST_TRACKING is enabled
        // should only be possible while the implementation of dictionary mode
        // prototypes is work in progress. Eventually, enabling
        // V8_DICT_PROPERTY_CONST_TRACKING will guarantee that all prototypes
        // are always in dictionary mode, making this case unreachable. However,
        // due to the complications of checking dictionary mode prototypes for
        // modification, we don't attempt to support dictionary mode prototypes
        // occuring before a fast mode holder on the chain.
        return Invalid();
      }
      if (details.location() == PropertyLocation::kField) {
        if (details.kind() == PropertyKind::kData) {
          return ComputeDataFieldAccessInfo(receiver_map, map, name, holder,
                                            index, access_mode);
        } else {
          DCHECK_EQ(PropertyKind::kAccessor, details.kind());
          // TODO(turbofan): Add support for general accessors?
          return Invalid();
        }
      } else {
        DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        return ComputeAccessorDescriptorAccessInfo(receiver_map, name, map,
                                                   holder, index, access_mode);
      }

      UNREACHABLE();
    }

    // The property wasn't found on {map}. Look on the prototype if appropriate.
    DCHECK(!index.is_found());

    // Don't search on the prototype chain for special indices in case of
    // integer indexed exotic objects (see ES6 section 9.4.5).
    if (IsJSTypedArrayMap(*map.object()) && name.IsString()) {
      StringRef name_str = name.AsString();
      SharedStringAccessGuardIfNeeded access_guard(
          *name_str.object(), broker()->local_isolate_or_isolate());
      if (IsSpecialIndex(*name_str.object(), access_guard)) return Invalid();
    }

    // Don't search on the prototype when storing in literals, or performing a
    // Define operation
    if (access_mode == AccessMode::kStoreInLiteral ||
        access_mode == AccessMode::kDefine) {
      PropertyAttributes attrs = NONE;
      if (name.object()->IsPrivate()) {
        // When PrivateNames are added to an object, they are by definition
        // non-enumerable.
        attrs = DONT_ENUM;
      }
      return LookupTransition(receiver_map, name, holder, attrs);
    }

    // Don't lookup private symbols on the prototype chain.
    if (name.object()->IsPrivate()) {
      return Invalid();
    }

    if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL && holder.has_value()) {
      // At this point, we are past the first loop iteration.
      DCHECK(holder->object()->map()->is_prototype_map());
      DCHECK(!holder->map(broker()).equals(receiver_map));

      fast_mode_prototype_on_chain =
          fast_mode_prototype_on_chain || !map.is_dictionary_map();
      dictionary_prototype_on_chain =
          dictionary_prototype_on_chain || map.is_dictionary_map();
    }

    // Walk up the prototype chain.
    // Load the map's prototype's map to guarantee that every time we use it,
    // we use the same Map.
    HeapObjectRef prototype = map.prototype(broker());

    MapRef map_prototype_map = prototype.map(broker());
    if (!IsJSObjectMap(*map_prototype_map.object())) {
      // Don't allow proxies on the prototype chain.
      if (!prototype.IsNull()) {
        DCHECK(IsJSProxy(*prototype.object()) ||
               IsWasmObject(*prototype.object()));
        return Invalid();
      }

      DCHECK(prototype.IsNull());

      if (dictionary_prototype_on_chain) {
        // TODO(v8:11248) See earlier comment about
        // dictionary_prototype_on_chain. We don't support absent properties
        // with dictionary mode prototypes on the chain, either. This is again
        // just due to how we currently deal with dependencies for dictionary
        // properties during finalization.
        return Invalid();
      }

      // Store to property not found on the receiver or any prototype, we need
      // to transition to a new data property.
      // Implemented according to ES6 section 9.1.9 [[Set]] (P, V, Receiver)
      if (access_mode == AccessMode::kStore) {
        return LookupTransition(receiver_map, name, holder, NONE);
      }

      // The property was not found (access returns undefined or throws
      // depending on the language mode of the load operation.
      // Implemented according to ES6 section 9.1.8 [[Get]] (P, Receiver)
      return PropertyAccessInfo::NotFound(zone(), receiver_map, holder);
    }

    CHECK(prototype.IsJSObject());
    holder = prototype.AsJSObject();
    map = map_prototype_map;

    if (!CanInlinePropertyAccess(map, access_mode)) {
      return Invalid();
    }

    // Successful lookup on prototype chain needs to guarantee that all the
    // prototypes up to the holder have stable maps, except for dictionary-mode
    // prototypes. We currently do this by taking a
    // DependOnStablePrototypeChains dependency in the caller.
    //
    // TODO(jgruber): This is brittle and easy to miss. Consider a refactor
    // that moves the responsibility of taking the dependency into
    // AccessInfoFactory.
  }
  UNREACHABLE();
}

PropertyAccessInfo AccessInfoFactory::FinalizePropertyAccessInfosAsOne(
    ZoneVector<PropertyAccessInfo> access_infos, AccessMode access_mode) const {
  ZoneVector<PropertyAccessInfo> merged_access_infos(zone());
  MergePropertyAccessInfos(access_infos, access_mode, &merged_access_infos);
  if (merged_access_infos.size() == 1) {
    PropertyAccessInfo& result = merged_access_infos.front();
    if (!result.IsInvalid()) {
      result.RecordDependencies(dependencies());
      return result;
    }
  }
  return Invalid();
}

void PropertyAccessInfo::RecordDependencies(
    CompilationDependencies* dependencies) {
  for (CompilationDependency const* d : unrecorded_dependencies_) {
    dependencies->RecordDependency(d);
  }
  unrecorded_dependencies_.clear();
}

bool AccessInfoFactory::FinalizePropertyAccessInfos(
    ZoneVector<PropertyAccessInfo> access_infos, AccessMode access_mode,
    ZoneVector<PropertyAccessInfo>* result) const {
  if (access_infos.empty()) return false;
  MergePropertyAccessInfos(access_infos, access_mode, result);
  for (PropertyAccessInfo const& info : *result) {
    if (info.IsInvalid()) return false;
  }
  for (PropertyAccessInfo& info : *result) {
    info.RecordDependencies(dependencies());
  }
  return true;
}

void AccessInfoFactory::MergePropertyAccessInfos(
    ZoneVector<PropertyAccessInfo> infos, AccessMode access_mode,
    ZoneVector<PropertyAccessInfo>* result) const {
  DCHECK(result->empty());
  for (auto it = infos.begin(), end = infos.end(); it != end; ++it) {
    bool merged = false;
    for (auto ot = it + 1; ot != end; ++ot) {
      if (ot->Merge(&(*it), access_mode, zone())) {
        merged = true;
        break;
      }
    }
    if (!merged) result->push_back(*it);
  }
  CHECK(!result->empty());
}

CompilationDependencies* AccessInfoFactory::dependencies() const {
  return broker()->dependencies();
}
Isolate* AccessInfoFactory::isolate() const { return broker()->isolate(); }

namespace {

Maybe<ElementsKind> GeneralizeElementsKind(ElementsKind this_kind,
                                           ElementsKind that_kind) {
  if (IsHoleyElementsKind(this_kind)) {
    that_kind = GetHoleyElementsKind(that_kind);
  } else if (IsHoleyElementsKind(that_kind)) {
    this_kind = GetHoleyElementsKind(this_kind);
  }
  if (this_kind == that_kind) return Just(this_kind);
  if (IsDoubleElementsKind(that_kind) == IsDoubleElementsKind(this_kind)) {
    if (IsMoreGeneralElementsKindTransition(that_kind, this_kind)) {
      return Just(this_kind);
    }
    if (IsMoreGeneralElementsKindTransition(this_kind, that_kind)) {
      return Just(that_kind);
    }
  }
  return Nothing<ElementsKind>();
}

}  // namespace

std::optional<ElementAccessInfo> AccessInfoFactory::ConsolidateElementLoad(
    ElementAccessFeedback const& feedback) const {
  if (feedback.transition_groups().empty()) return {};

  DCHECK(!feedback.transition_groups().front().empty());
  MapRef first_map = feedback.transition_groups().front().front();
  InstanceType instance_type = first_map.instance_type();
  ElementsKind elements_kind = first_map.elements_kind();

  ZoneVector<MapRef> maps(zone());
  for (auto const& group : feedback.transition_groups()) {
    for (MapRef map : group) {
      if (map.instance_type() != instance_type ||
          !map.CanInlineElementAccess()) {
        return {};
      }
      if (!GeneralizeElementsKind(elements_kind, map.elements_kind())
               .To(&elements_kind)) {
        return {};
      }
      maps.push_back(map);
    }
  }

  return ElementAccessInfo(std::move(maps), elements_kind, zone());
}

PropertyAccessInfo AccessInfoFactory::LookupSpecialFieldAccessor(
    MapRef map, NameRef name) const {
  // Check for String::length field accessor.
  if (IsStringMap(*map.object())) {
    if (Name::Equals(isolate(), name.object(),
                     isolate()->factory()->length_string())) {
      return PropertyAccessInfo::StringLength(zone(), map);
    }
    return Invalid();
  }
  if (IsJSPrimitiveWrapperMap(*map.object()) &&
      (map.elements_kind() == FAST_STRING_WRAPPER_ELEMENTS ||
       map.elements_kind() == SLOW_STRING_WRAPPER_ELEMENTS)) {
    if (Name::Equals(isolate(), name.object(),
                     isolate()->factory()->length_string())) {
      return PropertyAccessInfo::StringWrapperLength(zone(), map);
    }
  }
  // Check for special JSObject field accessors.
  FieldIndex field_index;
  if (Accessors::IsJSObjectFieldAccessor(isolate(), map.object(), name.object(),
                                         &field_index)) {
    Type field_type = Type::NonInternal();
    Representation field_representation = Representation::Tagged();
    if (IsJSArrayMap(*map.object())) {
      DCHECK(Name::Equals(isolate(), isolate()->factory()->length_string(),
                          name.object()));
      // The JSArray::length property is a smi in the range
      // [0, FixedDoubleArray::kMaxLength] in case of fast double
      // elements, a smi in the range [0, FixedArray::kMaxLength]
      // in case of other fast elements, and [0, kMaxUInt32] in
      // case of other arrays.
      if (IsDoubleElementsKind(map.elements_kind())) {
        field_type = type_cache_->kFixedDoubleArrayLengthType;
        field_representation = Representation::Smi();
      } else if (IsFastElementsKind(map.elements_kind())) {
        field_type = type_cache_->kFixedArrayLengthType;
        field_representation = Representation::Smi();
      } else {
        field_type = type_cache_->kJSArrayLengthType;
      }
    }
    // Special fields are always mutable.
    return PropertyAccessInfo::DataField(broker(), zone(), map, {{}, zone()},
                                         field_index, field_representation,
                                         field_type, map, {}, {}, {});
  }
  return Invalid();
}

PropertyAccessInfo AccessInfoFactory::LookupTransition(
    MapRef map, NameRef name, OptionalJSObjectRef holder,
    PropertyAttributes attrs) const {
  // Check if the {map} has a data transition with the given {name}.
  Tagged<Map> transition =
      TransitionsAccessor(isolate(), *map.object(), true)
          .SearchTransition(*name.object(), PropertyKind::kData, attrs);
  if (transition.is_null()) return Invalid();
  OptionalMapRef maybe_transition_map = TryMakeRef(broker(), transition);
  if (!maybe_transition_map.has_value()) return Invalid();
  MapRef transition_map = maybe_transition_map.value();

  InternalIndex const number = transition_map.object()->LastAdded();
  DirectHandle<DescriptorArray> descriptors =
      transition_map.instance_descriptors(broker()).object();
  PropertyDetails const details = descriptors->GetDetails(number);

  // Don't bother optimizing stores to read-only properties.
  if (details.IsReadOnly()) return Invalid();

  // TODO(bmeurer): Handle transition to data constant?
  if (details.location() != PropertyLocation::kField) return Invalid();

  int const index = details.field_index();
  Representation details_representation = details.representation();
  if (details_representation.IsNone()) return Invalid();

  FieldIndex field_index = FieldIndex::ForPropertyIndex(
      *transition_map.object(), index, details_representation);
  Type field_type = Type::NonInternal();
  OptionalMapRef field_map;

  DCHECK_EQ(transition_map, transition_map.FindFieldOwner(broker(), number));

  ZoneVector<CompilationDependency const*> unrecorded_dependencies(zone());
  if (details_representation.IsSmi()) {
    field_type = Type::SignedSmall();
    unrecorded_dependencies.push_back(
        dependencies()->FieldRepresentationDependencyOffTheRecord(
            transition_map, transition_map, number, details_representation));
  } else if (details_representation.IsDouble()) {
    field_type = type_cache_->kFloat64;
    unrecorded_dependencies.push_back(
        dependencies()->FieldRepresentationDependencyOffTheRecord(
            transition_map, transition_map, number, details_representation));
  } else if (details_representation.IsHeapObject()) {
    // Extract the field type from the property details (make sure its
    // representation is TaggedPointer to reflect the heap object case).
    // TODO(jgruber,v8:7790): Use DescriptorArrayRef instead.
    Handle<FieldType> descriptors_field_type =
        broker()->CanonicalPersistentHandle(descriptors->GetFieldType(number));
    OptionalObjectRef descriptors_field_type_ref =
        TryMakeRef<Object>(broker(), descriptors_field_type);
    if (!descriptors_field_type_ref.has_value()) return Invalid();

    if (IsNone(*descriptors_field_type)) {
      // Cleared field-types are pre-monomorphic states. The field type was
      // garbge collected and we need to record an updated type.
      static_assert(FieldType::kFieldTypesCanBeClearedOnGC);
      return Invalid();
    }
    unrecorded_dependencies.push_back(
        dependencies()->FieldRepresentationDependencyOffTheRecord(
            transition_map, transition_map, number, details_representation));
    if (IsClass(*descriptors_field_type)) {
      unrecorded_dependencies.push_back(
          dependencies()->FieldTypeDependencyOffTheRecord(
              transition_map, transition_map, number,
              *descriptors_field_type_ref));
      // Remember the field map, and try to infer a useful type.
      OptionalMapRef maybe_field_map =
          TryMakeRef(broker(), FieldType::AsClass(*descriptors_field_type));
      if (!maybe_field_map.has_value()) return Invalid();
      field_type = Type::For(maybe_field_map.value(), broker());
      field_map = maybe_field_map;
    }
  }

  unrecorded_dependencies.push_back(
      dependencies()->TransitionDependencyOffTheRecord(transition_map));
  // Transitioning stores *may* store to const fields. The resulting
  // DataConstant access infos can be distinguished from later, i.e. redundant,
  // stores to the same constant field by the presence of a transition map.
  switch (dependencies()->DependOnFieldConstness(transition_map, transition_map,
                                                 number)) {
    case PropertyConstness::kMutable:
      return PropertyAccessInfo::DataField(
          broker(), zone(), map, std::move(unrecorded_dependencies),
          field_index, details_representation, field_type, transition_map,
          field_map, holder, transition_map);
    case PropertyConstness::kConst:
      return PropertyAccessInfo::FastDataConstant(
          zone(), map, std::move(unrecorded_dependencies), field_index,
          details_representation, field_type, transition_map, field_map, holder,
          transition_map);
  }
  UNREACHABLE();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```
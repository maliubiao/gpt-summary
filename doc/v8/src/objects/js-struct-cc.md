Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Identify the Core File and its Location:** The first and most important step is noting the file path: `v8/src/objects/js-struct.cc`. The `.cc` extension immediately tells us this is C++ source code, not Torque (`.tq`). The path suggests it's part of V8's object system, specifically dealing with some kind of structure (`js-struct`).

2. **Initial Scan for Keywords and Structure:**  Quickly scan the code for recognizable C++ keywords, class names, namespaces, and comments. This gives a high-level overview. We see namespaces `v8` and `internal`, suggesting this is internal V8 implementation. We see class names like `AlwaysSharedSpaceJSObject`, `JSSharedStruct`, and `SharedStructTypeRegistry`. The comments mention "shared objects" and "fixed layout," hinting at the purpose.

3. **Analyze Individual Classes/Structures:**  Go through each class or significant struct declaration.

    * **`AlwaysSharedSpaceJSObject`:** The name suggests it's about JS objects residing in shared space. The `PrepareMapCommon`, `PrepareMapNoEnumerableProperties`, and `PrepareMapWithEnumerableProperties` functions likely deal with setting up the object's `Map` (V8's object layout descriptor). The `DefineOwnProperty` function has logic to prevent modifications that would break the "fixed layout" invariant. `HasInstance` looks like a custom `instanceof` check.

    * **`JSSharedStruct`:** This seems to be the core entity. `CreateInstanceMap` is a key function, taking field names and element names as input and creating a `Map`. The functions like `GetRegistryKey` and `GetElementsTemplate` suggest this structure can have associated metadata.

    * **`SharedStructTypeRegistry`:** The name clearly indicates a registry for these `JSSharedStruct` types. The `Register` and `RegisterNoThrow` functions are the main ways to add new shared struct types. The `CheckIfEntryMatches` function handles checking if a requested type already exists. The `Data` inner class implements the underlying hash table for the registry.

4. **Focus on Key Functions and Logic:**  Deep dive into the most important functions, trying to understand their purpose and how they interact.

    * **`AlwaysSharedSpaceJSObject::PrepareMap...`:** These functions initialize the `Map` object. The comments emphasize "shared objects," "fixed layout," "not extensible," and "null prototype."  This tells us these objects have specific constraints.

    * **`AlwaysSharedSpaceJSObject::DefineOwnProperty`:** The logic here is crucial. It disallows redefining properties in ways that would change the object's layout (e.g., making a writable property non-writable). This reinforces the "fixed layout" concept.

    * **`JSSharedStruct::CreateInstanceMap`:**  This is the factory for creating `Map` objects for `JSSharedStruct` instances. It handles adding descriptors for fields and potentially a template for indexed properties (elements). The "shared space" allocation type is significant.

    * **`SharedStructTypeRegistry::Register...`:** The registry's purpose is to ensure that for a given set of field names and element names (and a key), there's only one canonical `Map`. This promotes sharing and reduces memory usage in shared contexts. The locking mechanism (`data_mutex_`) indicates thread safety concerns.

5. **Infer Relationships and Overall Purpose:**  Connect the dots. `JSSharedStruct` represents a specific type of object in shared space. These objects have a fixed structure defined by their fields and elements. The `SharedStructTypeRegistry` manages these types, ensuring uniqueness based on their structure and an optional registry key. `AlwaysSharedSpaceJSObject` provides base functionality for these shared objects.

6. **Address the Specific Questions from the Prompt:** Now, go back to the original prompt and answer each part systematically:

    * **Functionality:** Summarize the roles of each class and the overall purpose of the file.
    * **Torque:**  Explicitly state that the `.cc` extension means it's C++, not Torque.
    * **JavaScript Relationship:** This requires understanding how these low-level constructs manifest in JavaScript. Shared structs are likely related to features like shared arrays or potentially internal representations of certain built-in objects or modules. The example provided highlights the immutability aspect by demonstrating the failure to redefine a property.
    * **Code Logic Reasoning:**  Choose a key function like `DefineOwnProperty` and provide a clear "Given... Then..." example to illustrate its behavior. Focus on the "fixed layout" constraint.
    * **Common Programming Errors:** Think about what developers might try to do with these objects if they don't understand their limitations. Trying to add or delete properties or change their writability are obvious candidates.

7. **Refine and Organize:** Review the generated answers for clarity, accuracy, and completeness. Ensure the examples are correct and the explanations are easy to understand. Use clear headings and formatting.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe `JSSharedStruct` is just a regular struct.
* **Correction:**  The presence of `CreateInstanceMap` and the interaction with `Map` objects indicate it's more involved and tied to V8's object model. The "shared space" aspect is a significant clue.

* **Initial thought:**  The registry is just for optimization.
* **Correction:** The registry enforces uniqueness of types, which is crucial for the "fixed layout" guarantee and memory sharing. The locking mechanism suggests this is important for correctness in concurrent scenarios.

* **Initial thought:** Provide very complex JavaScript examples.
* **Correction:**  Keep the JavaScript examples simple and focused on the core concepts being illustrated (like immutability). Avoid unnecessary complexity.

By following this structured approach, combining code analysis with an understanding of V8's architecture and the prompt's specific questions, it's possible to generate a comprehensive and accurate explanation of the `js-struct.cc` file.
`v8/src/objects/js-struct.cc` 是 V8 源代码中的一个文件，它定义了与 **JavaScript 共享结构 (Shared Structs)** 相关的对象和功能。

**主要功能:**

1. **定义 `JSSharedStruct` 对象:**  这个文件定义了 `JSSharedStruct` 类，它代表了 V8 中共享的结构化对象。这些对象旨在在不同的 Isolate 之间共享，从而减少内存占用和提高性能。

2. **管理共享结构的元数据:**  `JSSharedStruct` 对象关联着一个 `Map` 对象，该 `Map` 对象描述了该结构的布局（例如，字段名称和类型）。这个文件中的代码负责创建和管理这些 `Map` 对象，确保相同结构的共享对象在不同的 Isolate 中具有相同的布局。

3. **实现共享结构的生命周期管理:** 代码中包含用于创建、注册和查找共享结构类型的机制。 `SharedStructTypeRegistry` 类负责维护一个已注册的共享结构类型的全局注册表，确保相同的结构只被创建一次。

4. **支持共享结构的属性定义和访问:**  `AlwaysSharedSpaceJSObject` 类提供了一些静态方法，用于在创建共享结构的 `Map` 时设置其属性，例如是否可枚举。它还处理定义属性的特定限制，因为共享结构的布局是固定的。

5. **处理共享结构的元素 (Indexed Properties):**  共享结构可以拥有数字索引的属性（类似于数组的元素）。代码中包含处理这些元素的逻辑，包括创建元素模板（`NumberDictionary`)。

**关于 .tq 结尾：**

你提到如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。 这是一个正确的判断。 `.cc` 文件是 C++ 源代码文件，而 `.tq` 文件是 V8 使用的名为 Torque 的领域特定语言编写的。 Torque 用于生成高效的运行时代码。 **`v8/src/objects/js-struct.cc` 是 C++ 源代码，不是 Torque 源代码。**

**与 JavaScript 功能的关系 (通过示例说明):**

共享结构在 JavaScript 中并没有直接对应的用户可见的 API。它们是 V8 内部用于优化特定场景的数据表示。 然而，它们的概念与以下 JavaScript 功能间接相关：

* **共享数组 (`SharedArrayBuffer`) 和原子操作 (`Atomics`):** 共享结构的设计目标之一是在多个 Isolate (可以理解为不同的 JavaScript 上下文或 Web Worker) 之间共享数据。 `SharedArrayBuffer` 允许在 Worker 之间共享原始内存，而原子操作提供了一种安全地访问和修改共享内存的方式。 共享结构可以被视为一种更高级别的、类型化的共享内存抽象。

* **WebAssembly (Wasm) 互操作性:**  共享结构可能在 V8 内部用于表示 Wasm 模块导出的共享对象或数据。

**JavaScript 示例 (概念性):**

虽然无法直接创建 `JSSharedStruct` 的实例，但我们可以设想一个场景，V8 内部可能会使用它来表示某些共享的数据结构。

```javascript
// 假设 V8 内部使用共享结构来表示一个共享的配置对象

// 在一个 Isolate 中设置配置
// (这部分是概念性的，实际 API 可能不同)
const config = V8Internal.createSharedStruct({
  version: "1.0",
  maxConnections: 100
});

// 在另一个 Isolate (例如，一个 Web Worker) 中访问相同的配置
// (同样是概念性的)
worker.onmessage = (event) => {
  const sharedConfig = event.data.sharedConfig;
  console.log("Worker received config:", sharedConfig.version);
};

worker.postMessage({ sharedConfig: config });
```

在这个概念性的例子中，`V8Internal.createSharedStruct` 代表 V8 内部创建共享结构的机制。 关键在于，多个 JavaScript 上下文可以访问和使用同一个共享结构实例，并且对该结构所做的更改在所有上下文中都是可见的。

**代码逻辑推理 (假设输入与输出):**

考虑 `AlwaysSharedSpaceJSObject::DefineOwnProperty` 函数。

**假设输入:**

* `isolate`: 当前 V8 Isolate 的指针。
* `shared_obj`: 一个指向 `AlwaysSharedSpaceJSObject` 实例的句柄。
* `key`:  一个表示属性名称的句柄 (例如，字符串 "name")。
* `desc`: 一个指向 `PropertyDescriptor` 的指针，描述了要定义的属性的特性 (例如，值，可写性，可枚举性)。
* `should_throw`: 一个指示是否在定义属性失败时抛出异常的枚举值。

**假设场景:**

假设我们尝试在一个已经存在的共享对象上重新定义一个属性，但更改了其可写性。例如，将一个可写属性变为只读。

**输出:**

由于共享对象的布局是固定的，尝试更改属性的特性（例如，可写性）通常会被阻止。 `DefineOwnProperty` 会检查新的属性描述符是否与现有属性的特性兼容。 如果不兼容，并且 `should_throw` 指示应该抛出异常，则函数将返回一个包含类型错误的 `Maybe<bool>`。 如果 `should_throw` 指示不应该抛出异常，则可能返回一个表示操作失败的 `Maybe<bool>`.

**示例:**

```c++
// 假设 shared_obj 的 "name" 属性是可写的
Handle<String> name_key = isolate->factory()->NewStringInternal("name").ToHandleChecked();
PropertyDescriptor new_desc;
new_desc.set_writable(false); // 尝试将 "name" 属性变为只读

Maybe<bool> result = AlwaysSharedSpaceJSObject::DefineOwnProperty(
    isolate, handle(shared_obj), name_key, &new_desc, Just(kThrowOnError));

// 由于共享对象的固定布局，result 可能会指示失败 (例如，IsNothing())
// 并且如果 kThrowOnError 被传递，可能会抛出一个异常。
```

**用户常见的编程错误 (涉及共享结构的概念):**

由于共享结构在 JavaScript 中是内部概念，用户通常不会直接与其交互并犯编程错误。 然而，如果考虑到共享内存的通用概念，一些潜在的错误可能包括：

1. **不正确的同步:** 如果多个 Isolate 或线程同时修改共享结构的数据，而没有适当的同步机制 (例如，原子操作，锁)，可能会导致数据竞争和不一致的状态。

2. **假设可变性:** 用户可能会错误地认为共享结构的属性可以像普通 JavaScript 对象一样随意修改。 然而，由于其固定布局，某些修改操作可能是不允许的。

3. **生命周期管理错误:**  在手动管理共享内存的情况下 (例如，使用 `SharedArrayBuffer`)，用户可能会遇到生命周期问题，例如过早释放内存或访问已释放的内存。 共享结构通过 V8 的垃圾回收机制进行管理，但在理解其共享性质时，仍然需要注意潜在的生命周期问题。

**总结:**

`v8/src/objects/js-struct.cc` 是 V8 中管理共享结构对象的关键文件。它定义了 `JSSharedStruct` 类，并提供了创建、注册和管理这些共享对象的功能。 虽然 JavaScript 用户不会直接操作这些对象，但理解它们的存在有助于理解 V8 如何在内部优化共享数据的表示，这与共享内存和跨 Isolate 通信等概念间接相关。

### 提示词
```
这是目录为v8/src/objects/js-struct.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-struct.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/js-struct.h"

#include "src/heap/heap-layout-inl.h"
#include "src/objects/lookup-inl.h"
#include "src/objects/map-inl.h"
#include "src/objects/off-heap-hash-table-inl.h"
#include "src/objects/property-descriptor.h"

namespace v8 {
namespace internal {

namespace {

void PrepareMapCommon(Tagged<Map> map) {
  DCHECK(IsAlwaysSharedSpaceJSObjectMap(map));
  DisallowGarbageCollection no_gc;
  // Shared objects have fixed layout ahead of time, so there's no slack.
  map->SetInObjectUnusedPropertyFields(0);
  // Shared objects are not extensible and have a null prototype.
  map->set_is_extensible(false);
  // Shared space objects are not optimizable as prototypes because it is
  // not threadsafe.
  map->set_prototype_validity_cell(Map::kPrototypeChainValidSmi, kRelaxedStore,
                                   SKIP_WRITE_BARRIER);
}

}  // namespace

// static
void AlwaysSharedSpaceJSObject::PrepareMapNoEnumerableProperties(
    Tagged<Map> map) {
  PrepareMapCommon(map);
  map->SetEnumLength(0);
}

// static
void AlwaysSharedSpaceJSObject::PrepareMapNoEnumerableProperties(
    Isolate* isolate, Tagged<Map> map, Tagged<DescriptorArray> descriptors) {
  PrepareMapCommon(map);
  map->InitializeDescriptors(isolate, *descriptors);
  DCHECK_EQ(0, map->NumberOfEnumerableProperties());
  map->SetEnumLength(0);
}

// static
void AlwaysSharedSpaceJSObject::PrepareMapWithEnumerableProperties(
    Isolate* isolate, DirectHandle<Map> map,
    DirectHandle<DescriptorArray> descriptors, int enum_length) {
  PrepareMapCommon(*map);
  // Shared objects with enumerable own properties need to pre-create the enum
  // cache, as creating it lazily is racy.
  map->InitializeDescriptors(isolate, *descriptors);
  FastKeyAccumulator::InitializeFastPropertyEnumCache(
      isolate, map, enum_length, AllocationType::kSharedOld);
  DCHECK_EQ(enum_length, map->EnumLength());
}

// static
Maybe<bool> AlwaysSharedSpaceJSObject::DefineOwnProperty(
    Isolate* isolate, Handle<AlwaysSharedSpaceJSObject> shared_obj,
    Handle<Object> key, PropertyDescriptor* desc,
    Maybe<ShouldThrow> should_throw) {
  // Shared objects are designed to have fixed layout, i.e. their maps are
  // effectively immutable. They are constructed seal, but the semantics of
  // ordinary ECMAScript objects allow writable properties to be upgraded to
  // non-writable properties. This upgrade violates the fixed layout invariant
  // and is disallowed.

  DCHECK(IsName(*key) || IsNumber(*key));  // |key| is a PropertyKey.
  PropertyKey lookup_key(isolate, key);
  LookupIterator it(isolate, shared_obj, lookup_key, LookupIterator::OWN);
  PropertyDescriptor current;
  MAYBE_RETURN(GetOwnPropertyDescriptor(&it, &current), Nothing<bool>());

  // The only redefinition allowed is to set the value if all attributes match.
  if (!it.IsFound() ||
      PropertyDescriptor::IsDataDescriptor(desc) !=
          PropertyDescriptor::IsDataDescriptor(&current) ||
      desc->ToAttributes() != current.ToAttributes()) {
    DCHECK(!shared_obj->map()->is_extensible());
    RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                   NewTypeError(MessageTemplate::kDefineDisallowedFixedLayout,
                                it.GetName()));
  }
  DCHECK(it.property_attributes() == desc->ToAttributes());
  if (desc->has_value()) {
    return Object::SetDataProperty(&it, desc->value());
  }
  return Just(true);
}

Maybe<bool> AlwaysSharedSpaceJSObject::HasInstance(
    Isolate* isolate, DirectHandle<JSFunction> constructor,
    Handle<Object> object) {
  if (!constructor->has_prototype_slot() || !constructor->has_initial_map() ||
      !IsJSReceiver(*object)) {
    return Just(false);
  }
  Handle<Map> constructor_map(constructor->initial_map(), isolate);
  PrototypeIterator iter(isolate, Cast<JSReceiver>(object), kStartAtReceiver);
  Handle<Map> current_map;
  while (true) {
    current_map = handle(PrototypeIterator::GetCurrent(iter)->map(), isolate);
    if (current_map.is_identical_to(constructor_map)) {
      return Just(true);
    }
    if (!iter.AdvanceFollowingProxies()) return Nothing<bool>();
    if (iter.IsAtEnd()) return Just(false);
  }
}

namespace {

// Currently there are 2, both optionally present:
//  - Registry key
//  - Elements template
constexpr int kSpecialSlots = 2;

InternalIndex GetSpecialSlotIndex(Tagged<Map> instance_map,
                                  Tagged<Symbol> special_slot_name) {
  DCHECK(IsJSSharedStructMap(instance_map));
  DCHECK(IsPrivateSymbol(special_slot_name));
  Tagged<DescriptorArray> descriptors = instance_map->instance_descriptors();
  // Special slots are optional and start at descriptor number 0.
  int end = std::min(static_cast<int>(descriptors->number_of_all_descriptors()),
                     kSpecialSlots);
  for (int i = 0; i < end; ++i) {
    InternalIndex idx(i);
    if (descriptors->GetKey(idx) == special_slot_name) {
      DCHECK_EQ(PropertyLocation::kDescriptor,
                descriptors->GetDetails(idx).location());
      return idx;
    }
  }
  return InternalIndex::NotFound();
}

template <typename T>
MaybeHandle<T> GetSpecialSlotValue(Isolate* isolate, Tagged<Map> instance_map,
                                   Tagged<Symbol> special_slot_name) {
  DisallowGarbageCollection no_gc;
  MaybeHandle<T> result;
  InternalIndex entry = GetSpecialSlotIndex(instance_map, special_slot_name);
  if (entry.is_found()) {
    DCHECK_IMPLIES(
        special_slot_name ==
            ReadOnlyRoots(isolate).shared_struct_map_registry_key_symbol(),
        entry.as_int() == 0);
    result =
        handle(Cast<T>(instance_map->instance_descriptors()->GetStrongValue(
                   isolate, entry)),
               isolate);
  }
  return result;
}

}  // namespace

// static
Handle<Map> JSSharedStruct::CreateInstanceMap(
    Isolate* isolate, const std::vector<Handle<Name>>& field_names,
    const std::set<uint32_t>& element_names,
    MaybeHandle<String> maybe_registry_key) {
  auto* factory = isolate->factory();

  int num_fields = 0;
  int num_elements = 0;

  int num_descriptors = static_cast<int>(field_names.size());
  // If there are elements, an template NumberDictionary is created and stored
  // as a data constant on a descriptor.
  if (!element_names.empty()) num_descriptors++;
  // If this is a registered map, the key is stored as a data constant on a
  // descriptor because the registry stores the maps weakly. Storing the key in
  // the map simplifies the weakness handling in the GC.
  if (!maybe_registry_key.is_null()) num_descriptors++;

  // Create the DescriptorArray if there are fields or elements.
  DirectHandle<DescriptorArray> descriptors;
  if (num_descriptors != 0) {
    descriptors = factory->NewDescriptorArray(num_descriptors, 0,
                                              AllocationType::kSharedOld);

    int special_slots = 0;

    // Store the registry key if the map is registered. This must be the first
    // slot if present. The registry depends on this for rehashing.
    Handle<String> registry_key;
    if (maybe_registry_key.ToHandle(&registry_key)) {
      Handle<String> registry_key = maybe_registry_key.ToHandleChecked();
      Descriptor d = Descriptor::DataConstant(
          factory->shared_struct_map_registry_key_symbol(), registry_key,
          ALL_ATTRIBUTES_MASK);
      DCHECK_EQ(0, special_slots);
      descriptors->Set(InternalIndex(special_slots++), &d);
    }

    // Elements in shared structs are only supported as a dictionary. Create the
    // template NumberDictionary if needed.
    if (!element_names.empty()) {
      Handle<NumberDictionary> elements_template;
      num_elements = static_cast<int>(element_names.size());
      elements_template = NumberDictionary::New(isolate, num_elements,
                                                AllocationType::kSharedOld);
      for (uint32_t index : element_names) {
        PropertyDetails details(PropertyKind::kData, SEALED,
                                PropertyConstness::kMutable, 0);
        NumberDictionary::UncheckedAdd<Isolate, AllocationType::kSharedOld>(
            isolate, elements_template, index,
            ReadOnlyRoots(isolate).undefined_value_handle(), details);
      }
      elements_template->SetInitialNumberOfElements(num_elements);
      DCHECK(HeapLayout::InAnySharedSpace(*elements_template));

      Descriptor d = Descriptor::DataConstant(
          factory->shared_struct_map_elements_template_symbol(),
          elements_template, ALL_ATTRIBUTES_MASK);
      descriptors->Set(InternalIndex(special_slots++), &d);
    }

    DCHECK_LE(special_slots, kSpecialSlots);

    for (DirectHandle<Name> field_name : field_names) {
      // Shared structs' fields need to be aligned, so make it all tagged.
      PropertyDetails details(
          PropertyKind::kData, SEALED, PropertyLocation::kField,
          PropertyConstness::kMutable, Representation::Tagged(), num_fields);
      descriptors->Set(InternalIndex(special_slots + num_fields), *field_name,
                       FieldType::Any(), details);
      num_fields++;
    }

    descriptors->Sort();
  }

  // Calculate the size for instances and create the map.
  int instance_size;
  int in_object_properties;
  JSFunction::CalculateInstanceSizeHelper(JS_SHARED_STRUCT_TYPE, false, 0,
                                          num_fields, &instance_size,
                                          &in_object_properties);
  Handle<Map> instance_map = factory->NewContextlessMap(
      JS_SHARED_STRUCT_TYPE, instance_size, DICTIONARY_ELEMENTS,
      in_object_properties, AllocationType::kSharedMap);

  // Prepare the enum cache if necessary.
  if (num_descriptors == 0) {
    DCHECK_EQ(0, num_fields);
    // No properties at all.
    AlwaysSharedSpaceJSObject::PrepareMapNoEnumerableProperties(*instance_map);
  } else if (num_fields == 0) {
    // Have descriptors, but no enumerable fields.
    AlwaysSharedSpaceJSObject::PrepareMapNoEnumerableProperties(
        isolate, *instance_map, *descriptors);
  } else {
    // Have enumerable fields.
    AlwaysSharedSpaceJSObject::PrepareMapWithEnumerableProperties(
        isolate, instance_map, descriptors, num_fields);
  }

  // Structs have fixed layout ahead of time, so there's no slack.
  int out_of_object_properties = num_fields - in_object_properties;
  if (out_of_object_properties != 0) {
    instance_map->SetOutOfObjectUnusedPropertyFields(0);
  }

  return instance_map;
}

// static
MaybeHandle<String> JSSharedStruct::GetRegistryKey(Isolate* isolate,
                                                   Tagged<Map> instance_map) {
  return GetSpecialSlotValue<String>(
      isolate, *instance_map,
      ReadOnlyRoots(isolate).shared_struct_map_registry_key_symbol());
}

// static
bool JSSharedStruct::IsRegistryKeyDescriptor(Isolate* isolate,
                                             Tagged<Map> instance_map,
                                             InternalIndex i) {
  DCHECK(IsJSSharedStructMap(instance_map));
  return instance_map->instance_descriptors(isolate)->GetKey(i) ==
         ReadOnlyRoots(isolate).shared_struct_map_registry_key_symbol();
}

// static
MaybeHandle<NumberDictionary> JSSharedStruct::GetElementsTemplate(
    Isolate* isolate, Tagged<Map> instance_map) {
  return GetSpecialSlotValue<NumberDictionary>(
      isolate, instance_map,
      ReadOnlyRoots(isolate).shared_struct_map_elements_template_symbol());
}

// static
bool JSSharedStruct::IsElementsTemplateDescriptor(Isolate* isolate,
                                                  Tagged<Map> instance_map,
                                                  InternalIndex i) {
  DCHECK(IsJSSharedStructMap(instance_map));
  return instance_map->instance_descriptors(isolate)->GetKey(i) ==
         ReadOnlyRoots(isolate).shared_struct_map_elements_template_symbol();
}

// Hash table mapping string keys to shared struct maps.
class SharedStructTypeRegistry::Data : public OffHeapHashTableBase<Data> {
 public:
  static constexpr int kEntrySize = 1;
  static constexpr int kMaxEmptyFactor = 4;
  static constexpr int kMinCapacity = 4;

  explicit Data(int capacity) : OffHeapHashTableBase<Data>(capacity) {}

  static uint32_t Hash(PtrComprCageBase cage_base, Tagged<Object> key) {
    // Registry keys, if present, store them at the first descriptor. All maps
    // in the registry have registry keys.
    return Cast<String>(
               Cast<Map>(key)->instance_descriptors(cage_base)->GetStrongValue(
                   InternalIndex(0)))
        ->hash();
  }

  template <typename IsolateT>
  static bool KeyIsMatch(IsolateT* isolate, DirectHandle<String> key,
                         Tagged<Object> obj) {
    DirectHandle<String> existing =
        JSSharedStruct::GetRegistryKey(isolate, Cast<Map>(obj))
            .ToHandleChecked();
    DCHECK(IsInternalizedString(*key));
    DCHECK(IsInternalizedString(*existing));
    return *key == *existing;
  }

  Tagged<Object> GetKey(PtrComprCageBase cage_base, InternalIndex index) const {
    return slot(index).load(cage_base);
  }

  void SetKey(InternalIndex index, Tagged<Object> key) {
    DCHECK(IsMap(key));
    slot(index).store(key);
  }
  void Set(InternalIndex index, Tagged<Map> map) { SetKey(index, map); }

  void CopyEntryExcludingKeyInto(PtrComprCageBase cage_base,
                                 InternalIndex from_index, Data* to,
                                 InternalIndex to_index) {
    // Do nothing, since kEntrySize is 1.
  }

  static std::unique_ptr<Data> New(int capacity) {
    return std::unique_ptr<Data>(new (capacity) Data(capacity));
  }

  void* operator new(size_t size, int capacity) {
    DCHECK_GE(capacity, kMinCapacity);
    DCHECK_EQ(size, sizeof(Data));
    return OffHeapHashTableBase<Data>::Allocate<Data,
                                                offsetof(Data, elements_)>(
        capacity);
  }
  void* operator new(size_t size) = delete;

  void operator delete(void* table) { OffHeapHashTableBase<Data>::Free(table); }
};

SharedStructTypeRegistry::SharedStructTypeRegistry()
    : data_(Data::New(Data::kMinCapacity)) {
  DCHECK_EQ(deleted_element(), Data::deleted_element());
}

SharedStructTypeRegistry::~SharedStructTypeRegistry() = default;

MaybeHandle<Map> SharedStructTypeRegistry::CheckIfEntryMatches(
    Isolate* isolate, InternalIndex entry, DirectHandle<String> key,
    const std::vector<Handle<Name>>& field_names,
    const std::set<uint32_t>& element_names) {
  Tagged<Map> existing_map = Cast<Map>(data_->GetKey(isolate, entry));

  // A map is considered a match iff all of the following hold:
  // - field names are the same element-wise (in order)
  // - element indices are the same

  // Registered types always have the key as the first descriptor.
  DCHECK_EQ(
      *JSSharedStruct::GetRegistryKey(isolate, existing_map).ToHandleChecked(),
      *key);

  int num_descriptors = static_cast<int>(field_names.size()) + 1;
  if (!element_names.empty()) {
    if (JSSharedStruct::GetElementsTemplate(isolate, existing_map).is_null()) {
      return MaybeHandle<Map>();
    }
    num_descriptors++;
  }

  if (num_descriptors != existing_map->NumberOfOwnDescriptors()) {
    return MaybeHandle<Map>();
  }

  Tagged<DescriptorArray> existing_descriptors =
      existing_map->instance_descriptors(isolate);
  auto field_names_iter = field_names.begin();
  for (InternalIndex i : existing_map->IterateOwnDescriptors()) {
    if (JSSharedStruct::IsElementsTemplateDescriptor(isolate, existing_map,
                                                     i)) {
      DirectHandle<NumberDictionary> elements_template(
          Cast<NumberDictionary>(
              existing_map->instance_descriptors()->GetStrongValue(isolate, i)),
          isolate);
      if (static_cast<int>(element_names.size()) !=
          elements_template->NumberOfElements()) {
        return MaybeHandle<Map>();
      }
      for (int element : element_names) {
        if (elements_template->FindEntry(isolate, element).is_not_found()) {
          return MaybeHandle<Map>();
        }
      }

      continue;
    }

    if (JSSharedStruct::IsRegistryKeyDescriptor(isolate, existing_map, i)) {
      continue;
    }

    Tagged<Name> existing_name = existing_descriptors->GetKey(i);
    DCHECK(IsUniqueName(existing_name));
    Tagged<Name> name = **field_names_iter;
    DCHECK(IsUniqueName(name));
    if (name != existing_name) return MaybeHandle<Map>();
    ++field_names_iter;
  }

  return handle(existing_map, isolate);
}

MaybeHandle<Map> SharedStructTypeRegistry::RegisterNoThrow(
    Isolate* isolate, Handle<String> key,
    const std::vector<Handle<Name>>& field_names,
    const std::set<uint32_t>& element_names) {
  key = isolate->factory()->InternalizeString(key);

  // To avoid deadlock with iteration during GC and modifying the table, no GC
  // must occur under lock.

  {
    NoGarbageCollectionMutexGuard data_guard(&data_mutex_);
    InternalIndex entry = data_->FindEntry(isolate, key, key->hash());
    if (entry.is_found()) {
      return CheckIfEntryMatches(isolate, entry, key, field_names,
                                 element_names);
    }
  }

  // We have a likely miss. Create a new instance map outside of the lock.
  Handle<Map> map = JSSharedStruct::CreateInstanceMap(isolate, field_names,
                                                      element_names, key);

  // Relookup to see if it's in fact a miss.
  NoGarbageCollectionMutexGuard data_guard(&data_mutex_);

  EnsureCapacity(isolate, 1);
  InternalIndex entry =
      data_->FindEntryOrInsertionEntry(isolate, key, key->hash());
  Tagged<Object> existing_key = data_->GetKey(isolate, entry);
  if (existing_key == Data::empty_element()) {
    data_->AddAt(isolate, entry, *map);
    return map;
  } else if (existing_key == Data::deleted_element()) {
    data_->OverwriteDeletedAt(isolate, entry, *map);
    return map;
  } else {
    // An entry with the same key was inserted between the two locks.
    return CheckIfEntryMatches(isolate, entry, key, field_names, element_names);
  }
}

MaybeHandle<Map> SharedStructTypeRegistry::Register(
    Isolate* isolate, Handle<String> key,
    const std::vector<Handle<Name>>& field_names,
    const std::set<uint32_t>& element_names) {
  MaybeHandle<Map> canonical_map =
      RegisterNoThrow(isolate, key, field_names, element_names);
  if (canonical_map.is_null()) {
    THROW_NEW_ERROR(
        isolate,
        NewTypeError(MessageTemplate::kSharedStructTypeRegistryMismatch, key));
  }
  return canonical_map;
}

void SharedStructTypeRegistry::IterateElements(Isolate* isolate,
                                               RootVisitor* visitor) {
  // Ideally this should only happen during a global safepoint, when all
  // workers and background threads are paused, so there would be no need to
  // take the data mutex. However, the array left trimming has a verifier
  // visitor that visits all roots (including weak ones), thus we take the
  // mutex.
  //
  // TODO(v8:12547): Figure out how to do
  // isolate->global_safepoint()->AssertActive() instead.
  base::MutexGuard data_guard(&data_mutex_);
  data_->IterateElements(Root::kSharedStructTypeRegistry, visitor);
}

void SharedStructTypeRegistry::NotifyElementsRemoved(int count) {
  data_->ElementsRemoved(count);
}

void SharedStructTypeRegistry::EnsureCapacity(PtrComprCageBase cage_base,
                                              int additional_elements) {
  data_mutex_.AssertHeld();

  int new_capacity;
  if (data_->ShouldResizeToAdd(additional_elements, &new_capacity)) {
    std::unique_ptr<Data> new_data(Data::New(new_capacity));
    data_->RehashInto(cage_base, new_data.get());
    data_ = std::move(new_data);
  }
}

}  // namespace internal
}  // namespace v8
```
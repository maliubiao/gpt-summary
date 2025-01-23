Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality in relation to JavaScript.

1. **Initial Scan for Keywords and Structure:**  The first step is to quickly read through the code, looking for familiar keywords and structural elements. Things like `namespace v8::internal`, `#include`, `class`, `static`, comments (especially the copyright notice), and function names like `CreateInstanceMap`, `DefineOwnProperty`, `GetRegistryKey`, and `Register` immediately stand out. The presence of `JSSharedStruct`, `Map`, `DescriptorArray`, and `SharedStructTypeRegistry` suggests this code is dealing with internal representations of JavaScript objects and their types within the V8 engine.

2. **Identify Core Components:** Based on the initial scan, I can identify the main components:
    * **`AlwaysSharedSpaceJSObject`:**  Seems to handle the setup and constraints of JavaScript objects living in a shared memory space.
    * **`JSSharedStruct`:** Likely represents a specific kind of JavaScript object (a "struct").
    * **`SharedStructTypeRegistry`:**  Appears to be a mechanism for keeping track of and reusing the structure (maps) of `JSSharedStruct` instances.

3. **Analyze `AlwaysSharedSpaceJSObject`:**  The functions within this class suggest its purpose:
    * `PrepareMapCommon`: Common setup for object maps in shared space (fixed layout, non-extensible, null prototype).
    * `PrepareMapNoEnumerableProperties`: Sets up a map with no enumerable properties.
    * `PrepareMapWithEnumerableProperties`: Sets up a map with enumerable properties, potentially involving a cache.
    * `DefineOwnProperty`: Enforces immutability rules for shared objects, disallowing redefinitions that change attributes.
    * `HasInstance`:  Implements the `instanceof` operator logic, checking the prototype chain.

4. **Analyze `JSSharedStruct`:** This class seems to be about the creation and management of a specific type of object.
    * `CreateInstanceMap`:  This is the key function. It takes field names and element names as input and creates a `Map` object that describes the structure of a `JSSharedStruct`. The logic around `DescriptorArray` and handling fields and elements (as a `NumberDictionary`) is crucial. The optional `registry_key` is also noted.
    * `GetRegistryKey`, `IsRegistryKeyDescriptor`, `GetElementsTemplate`, `IsElementsTemplateDescriptor`: These functions provide access to specific pieces of information stored within the `Map` of a `JSSharedStruct`.

5. **Analyze `SharedStructTypeRegistry`:** This appears to be a central registry for `JSSharedStruct` types.
    * `Data`:  An internal class likely implementing a hash table to store and retrieve `Map` objects based on their "shape" (fields and elements).
    * `RegisterNoThrow`, `Register`: Functions to register new `JSSharedStruct` types. The "no throw" version suggests an attempt to reuse existing types. The regular `Register` throws an error if a mismatch is found.
    * `CheckIfEntryMatches`:  Determines if a previously registered type matches the currently requested structure.
    * `IterateElements`, `NotifyElementsRemoved`, `EnsureCapacity`: Functions related to managing the internal hash table.

6. **Connect to JavaScript Concepts:** Now, the key is to relate these C++ internal details back to observable JavaScript behavior:

    * **Shared Space & Immutability:** The `AlwaysSharedSpaceJSObject` class points to the concept of shared objects in V8. These are likely related to built-in objects or objects that have a fixed structure for performance and memory efficiency. The restrictions on `DefineOwnProperty` directly connect to the immutability of these shared structures.

    * **`JSSharedStruct` and "Structs":** The name "struct" strongly suggests this is about creating objects with a predefined structure, similar to how structs work in languages like C. In JavaScript, while not explicitly called "structs," developers often create objects with a consistent set of properties. This C++ code provides the underlying mechanism for V8 to efficiently represent these structured objects, especially when they are shared across contexts.

    * **`SharedStructTypeRegistry` and Type Sharing/Optimization:** The registry is about ensuring that if two pieces of code request the same "shape" of a `JSSharedStruct` (same field names and element names), they get the *same* `Map` object. This is a significant optimization. It reduces memory usage (by not duplicating map objects) and improves performance (because operations on objects with the same map can be optimized). This is a behind-the-scenes optimization that JavaScript developers don't directly control, but it impacts performance.

7. **Construct JavaScript Examples:** The final step is to craft JavaScript examples that illustrate the *effects* of this C++ code, even though the internal workings are hidden.

    * **Immutability Example:** Demonstrate that trying to change the fundamental structure of a shared object (like a built-in) fails.
    * **"Struct"-like Usage:** Create JavaScript objects that resemble the concept of a struct (consistent properties). While not directly tied to *this specific* C++ code being *invoked* in that scenario, it reflects the idea of structured data.
    * **Registry (Implicit):**  This is harder to directly demonstrate. The best approach is to explain that the registry optimizes object creation when similar structures are requested, implying that if you create multiple objects with the same properties, V8 might reuse internal structures. You can't directly *see* the registry working, but you can explain its purpose.

**Self-Correction/Refinement during the process:**

* **Initial Misconceptions:**  I might initially assume "shared space" directly relates to multi-threading in user-level JavaScript. However, reading the comments and the code suggests it's more about internal V8 optimizations for built-in objects and potentially cross-context sharing. I need to adjust my explanation accordingly.
* **Overly Technical:** I might start explaining `DescriptorArray` in too much detail. I need to focus on the *purpose* of these internal structures and how they relate to JavaScript concepts, rather than the low-level implementation.
* **Clarity of Examples:** My initial JavaScript examples might be too simplistic or not directly illustrate the concepts. I need to refine them to be clear and relevant. For example, instead of just showing object creation, I should demonstrate attempts to modify properties or use `instanceof`.

By following this thought process, combining code analysis with understanding of JavaScript semantics, and iteratively refining the explanation and examples, I can arrive at a comprehensive and accurate summary of the C++ code's functionality and its relationship to JavaScript.
这个 C++ 代码文件 `v8/src/objects/js-struct.cc` 定义了 V8 引擎中 `JSSharedStruct` 相关的实现，它主要关注于 **共享的、结构化的 JavaScript 对象** 的创建、管理和属性定义。

以下是其功能的归纳：

**核心功能:**

1. **定义共享的结构化对象 (`JSSharedStruct`) 的内部表示:**
   - `JSSharedStruct` 是一种特殊的 JavaScript 对象，它的结构（属性及其类型）在创建时就被固定下来，并且可以跨多个 isolate（V8 引擎的独立实例）共享。
   - 这种共享特性主要用于优化内存占用和提高性能，特别是在创建大量具有相同结构的对象时。

2. **管理共享对象的元数据（`Map`）:**
   - `CreateInstanceMap`:  负责为 `JSSharedStruct` 创建并配置其对应的 `Map` 对象。 `Map` 对象是 V8 内部用于描述对象结构的关键数据结构，包括属性布局、类型信息等。
   - 此函数接收字段名 (`field_names`) 和元素名 (`element_names`) 来定义结构。
   - 可以选择性地注册到共享结构体类型注册表 (`SharedStructTypeRegistry`)。

3. **实现共享对象的属性定义和访问控制:**
   - `DefineOwnProperty`:  限制对共享对象的属性进行修改。 由于共享对象的结构是固定的，通常不允许添加、删除或更改属性的特性（如可写性、可枚举性）。 允许的唯一修改可能是设置已存在的、具有匹配属性的值。
   - 确保共享对象的布局一致性和跨 isolate 的共享特性。

4. **实现 `instanceof` 操作符:**
   - `HasInstance`: 实现了 `instanceof` 操作符对于 `JSSharedStruct` 构造函数的工作方式。

5. **管理共享结构体类型注册表 (`SharedStructTypeRegistry`):**
   -  这是一个用于存储和查找已创建的共享结构体类型的注册表。
   - 当需要创建新的共享结构体实例时，会先检查注册表中是否已存在具有相同结构的类型，如果存在则复用，避免重复创建 `Map` 对象，节省内存。
   - `RegisterNoThrow` 和 `Register` 函数用于向注册表添加新的共享结构体类型。

**与 JavaScript 的关系及示例:**

`JSSharedStruct` 虽然是 V8 内部的概念，但它与某些 JavaScript 的使用模式和优化策略相关。它主要应用于 V8 引擎内部，例如用于表示某些内置对象或者作为特定优化的基础。

**JavaScript 示例 (概念性):**

虽然 JavaScript 代码中没有直接的 `SharedStruct` 关键字，但我们可以通过一些模式来理解其背后的思想。

假设 V8 内部使用 `JSSharedStruct` 来优化具有固定结构的对象的创建，例如，某个图形库可能会频繁创建表示点的对象：

```javascript
// 假设在 V8 内部，类似这样的对象可能会被优化为 JSSharedStruct

class Point {
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }
}

// 创建大量 Point 对象
const points = [];
for (let i = 0; i < 1000; i++) {
  points.push(new Point(i, i * 2));
}
```

在这种情况下，V8 可能会识别出 `Point` 对象具有相同的结构（两个属性 `x` 和 `y`），并利用 `JSSharedStruct` 和 `SharedStructTypeRegistry` 来优化这些对象的创建和内存管理。

**更具体的与代码相关的 JavaScript 行为:**

1. **固定结构和不可变性:**  `DefineOwnProperty` 的限制意味着，如果 V8 内部使用了 `JSSharedStruct` 来表示某些对象，尝试动态地向这些对象添加或修改属性特性可能会失败或被阻止。

   ```javascript
   // 假设某个内部对象是基于 JSSharedStruct 实现的
   const sharedObject = /* ... V8 内部创建的共享对象 ... */;

   // 尝试添加新属性可能会失败
   try {
     sharedObject.z = 10;
   } catch (e) {
     console.error("无法向共享对象添加属性", e);
   }

   // 尝试修改现有属性的特性也可能失败
   try {
     Object.defineProperty(sharedObject, 'x', { writable: false });
   } catch (e) {
     console.error("无法修改共享对象属性特性", e);
   }
   ```

2. **类型注册和复用:**  `SharedStructTypeRegistry` 的作用是确保对于具有相同结构的对象，V8 尽可能地复用内部的 `Map` 对象。 这对 JavaScript 开发者是透明的，但有助于提高性能和减少内存占用。

   ```javascript
   // 假设 V8 内部根据对象结构进行优化

   function createSimilarObject(a, b) {
     return { a: a, b: b };
   }

   const obj1 = createSimilarObject(1, 2);
   const obj2 = createSimilarObject(3, 4);

   // V8 内部可能会发现 obj1 和 obj2 具有相同的结构，
   // 并可能复用某些内部表示 (类似于 JSSharedStruct 的 Map)
   ```

3. **`instanceof` 操作符:**  `HasInstance` 确保 `instanceof` 能够正确地判断对象是否是某个共享结构体构造函数的实例。

   ```javascript
   // 假设在 V8 内部存在一个与 JSSharedStruct 相关的构造函数
   class InternalSharedStructConstructor {
     // ... 内部实现，可能与 JSSharedStruct 相关联 ...
   }

   const sharedInstance = new InternalSharedStructConstructor();

   console.log(sharedInstance instanceof InternalSharedStructConstructor); // 输出 true
   ```

**总结:**

`v8/src/objects/js-struct.cc` 文件是 V8 引擎中实现共享的、结构化 JavaScript 对象的核心部分。它定义了 `JSSharedStruct` 的内部结构、管理其元数据、控制属性访问，并维护一个类型注册表以实现内存优化。虽然 JavaScript 开发者不能直接创建或操作 `JSSharedStruct`，但其存在影响着 V8 如何表示和优化某些类型的 JavaScript 对象，尤其是有着固定结构的对象。 理解这些内部机制有助于更深入地理解 V8 的性能优化策略。

### 提示词
```
这是目录为v8/src/objects/js-struct.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
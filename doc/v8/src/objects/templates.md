Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Initial Scan and Keyword Recognition:**  I first scanned the code for familiar terms and patterns. Keywords like `FunctionTemplateInfo`, `DictionaryTemplateInfo`, `Isolate`, `Map`, `JSObject`, `SharedFunctionInfo`, `api_func_data`, `prototype`, and function names like `GetOrCreateSharedFunctionInfo`, `IsTemplateFor`, `NewInstance` immediately stand out. These terms suggest that this code is dealing with the internal representation of JavaScript functions and objects within the V8 engine. The presence of `v8::internal` namespace confirms this is an internal V8 component.

2. **Focusing on Key Structures:**  I then zoomed in on the main classes: `FunctionTemplateInfo` and `DictionaryTemplateInfo`. The names themselves are quite descriptive and hint at their purpose:
    * `FunctionTemplateInfo`: Likely holds information about how to construct JavaScript functions (or function-like objects) from C++. The "Template" aspect suggests a blueprint or a factory.
    * `DictionaryTemplateInfo`: Seems related to creating objects with a predefined set of properties, like a dictionary or a plain JavaScript object.

3. **Analyzing `FunctionTemplateInfo` Methods:**
    * `HasInstanceType()`:  Suggests tracking the type of object instances created by this template. The `kNoJSApiObjectType` constant confirms its connection to the V8 API.
    * `GetOrCreateSharedFunctionInfo()`: This looks crucial. "SharedFunctionInfo" is a V8 internal concept for storing function metadata. The method name suggests that it either retrieves an existing one or creates a new one based on the `FunctionTemplateInfo`. The logic involving `class_name` and `interface_name` (and the `std::cout` statements, which are debugging artifacts) indicates this template is used in scenarios where C++ classes are exposed to JavaScript. The setting of `more_scope_info_class_name` and `more_scope_info_interface_name` in the `SharedFunctionInfo` further strengthens this idea.
    * `IsTemplateFor(Tagged<Map> map)`:  This strongly suggests a type checking mechanism. It determines if a given JavaScript object (represented by its `Map`) was created using this specific `FunctionTemplateInfo` or one of its ancestors in an inheritance hierarchy. The check for `IsJSObjectMap` and then looking at the `constructor` of the map are standard V8 patterns for type introspection.
    * `IsLeafTemplateForApiObject()`:  A more specific check to see if an object was created *directly* by this template, not an inherited one.
    * `AllocateFunctionTemplateRareData()`:  Likely deals with less frequently accessed data associated with the template, optimizing memory usage.
    * `TryGetCachedPropertyName()`: Hints at optimization related to accessing properties on objects created from this template. Caching is a common performance technique.
    * `GetCFunctionsCount()` and `GetCFunction()`/`GetCSignature()`: These methods point to the ability to associate C++ functions directly with the JavaScript function template. This is fundamental to the V8 API for binding C++ code to JavaScript.

4. **Analyzing `DictionaryTemplateInfo` Methods:**
    * `Create()`:  Clearly initializes a `DictionaryTemplateInfo` with a set of property names.
    * `NewInstance()`:  This is where the actual object creation happens. The logic involving `slow_object_with_object_prototype_map`, `PropertyDictionary`, `ObjectLiteralMapFromCache`, and `Map::TransitionToDataProperty` describes how V8 creates JavaScript objects, particularly when dealing with dynamic property addition and potential caching of object structures (`Map`s). The code handles both "fast" (in-object properties) and "slow" (dictionary properties) object creation. The caching mechanism here is also key for performance.

5. **Connecting to JavaScript:**  With the understanding of what these C++ classes *do*, I started thinking about how this manifests in JavaScript.
    * **`FunctionTemplateInfo`:**  The connection to the V8 API is crucial. The `v8::FunctionTemplate` in the public V8 API directly corresponds to `FunctionTemplateInfo` internally. This is how C++ code defines the structure and behavior of JavaScript constructor functions and the objects they create. I then thought of a simple example using `v8::FunctionTemplate` and how properties and methods are added.
    * **`DictionaryTemplateInfo`:** This is closely related to creating plain JavaScript objects with a specific set of initial properties. The most direct JavaScript equivalent is object literal syntax (`{}`) or using `Object.create(null)` for a truly empty object. The `NewInstance` method clearly mimics the process of creating and initializing such objects.

6. **Formulating the Explanation:** Finally, I organized my observations into a coherent explanation, focusing on:
    * The main purpose of the file: Managing templates for creating JavaScript functions and objects.
    * The roles of `FunctionTemplateInfo` and `DictionaryTemplateInfo`.
    * How these internal structures relate to the public V8 API (especially `v8::FunctionTemplate`).
    * Providing clear JavaScript examples that illustrate the concepts being managed by the C++ code. The examples aimed to be simple and directly demonstrate the functionality.
    * Highlighting the optimization aspects like caching, which are evident in the code.

Throughout this process, I was constantly asking myself: "How does this internal V8 mechanism enable a specific JavaScript feature or API?" and "What's the corresponding JavaScript code that would trigger this C++ code to execute?" This linkage between the internal implementation and the user-facing API is the key to understanding the purpose of this type of V8 code.
这个 C++ 代码文件 `templates.cc` 主要负责 **V8 引擎中模板（Templates）的创建、管理和使用**。模板是 V8 引擎中一个核心概念，用于将 C++ 的类和函数桥接到 JavaScript 环境。

更具体地说，这个文件定义了以下关键类和它们的功能：

**1. `FunctionTemplateInfo`:**

* **功能归纳:**  `FunctionTemplateInfo` 存储了创建 JavaScript 函数对象的模板信息。它定义了如何构造一个 JavaScript 函数，包括其名称、关联的 C++ 回调函数、原型、实例类型等。当在 JavaScript 中调用 `new` 关键字或者直接调用函数模板创建的函数时，V8 引擎会使用 `FunctionTemplateInfo` 中存储的信息来创建相应的 JavaScript 对象。
* **与 JavaScript 的关系和示例:**
    * `FunctionTemplateInfo` 是 V8 API 中 `v8::FunctionTemplate` 的内部表示。
    * JavaScript 中通过 `FunctionTemplate` 创建的函数，其内部信息就存储在 `FunctionTemplateInfo` 对象中。

    ```javascript
    const v8 = require('v8');

    // 在 C++ 中，你可能会创建一个 FunctionTemplateInfo 来表示 MyObject 构造函数
    // 例如，关联一个 C++ 函数作为构造逻辑

    // 在 JavaScript 中，使用 FunctionTemplate 创建的构造函数
    const myObjectTemplate = v8.FunctionTemplate.New();
    myObjectTemplate.setClassName(v8.String::NewFromUtf8(isolate, "MyObject").ToLocalChecked());

    // ... 可以设置原型方法，属性等 ...

    const myObjectClass = myObjectTemplate.getFunction(context).ToLocalChecked();
    const instance = new myObjectClass(); //  当执行 new 时，V8 会用到 FunctionTemplateInfo 中的信息
    ```

    这个例子中，`myObjectTemplate` 在 C++ 内部就对应一个 `FunctionTemplateInfo` 对象。当 `new myObjectClass()` 执行时，V8 会查找与 `myObjectClass` 关联的 `FunctionTemplateInfo`，并使用其中的信息来创建 `instance`。

* **代码中的关键功能点:**
    * `HasInstanceType()`:  检查模板是否定义了实例类型。
    * `GetOrCreateSharedFunctionInfo()`:  获取或创建一个与模板关联的 `SharedFunctionInfo` 对象。`SharedFunctionInfo` 存储了函数的共享信息，例如字节码。
    * `IsTemplateFor(Tagged<Map> map)`:  检查一个 JavaScript 对象的 `Map` 是否是由该模板或其父模板创建的。这用于类型检查。
    * `IsLeafTemplateForApiObject()`:  检查一个 JavaScript 对象是否直接由该模板创建。
    * `GetCFunctionsCount()`, `GetCFunction()`, `GetCSignature()`:  用于获取与该模板关联的 C++ 函数信息。

**2. `DictionaryTemplateInfo`:**

* **功能归纳:** `DictionaryTemplateInfo` 用于创建具有预定义属性名称的 JavaScript 对象。这在需要创建类似字典或具有固定键值的对象时很有用。
* **与 JavaScript 的关系和示例:**
    * `DictionaryTemplateInfo` 可以用来模拟创建具有一组已知属性的 JavaScript 对象。
    * 可以看作是 `v8::ObjectTemplate` 的一种特殊情况，专注于创建简单的键值对对象。

    ```javascript
    const v8 = require('v8');

    // 在 C++ 中，你可能会创建一个 DictionaryTemplateInfo 来表示一个具有 "name" 和 "age" 属性的对象

    // 在 JavaScript 中，创建具有特定属性的对象
    const myDict = { name: "John", age: 30 }; // 类似于 DictionaryTemplateInfo 创建的对象

    // 使用 v8 模块模拟 DictionaryTemplateInfo 的行为 (简化)
    const context = v8.Context::New(isolate);
    const global = context->Global();
    const objectTemplate = v8.ObjectTemplate::New(isolate);
    objectTemplate->Set(v8::String::NewFromUtf8(isolate, "name").ToLocalChecked(), v8::String::NewFromUtf8(isolate, "").ToLocalChecked());
    objectTemplate->Set(v8::String::NewFromUtf8(isolate, "age").ToLocalChecked(), v8::Number::New(isolate, 0));
    const instanceTemplate = objectTemplate->NewInstance(context).ToLocalChecked();
    // instanceTemplate 就类似于由 DictionaryTemplateInfo 创建的对象
    ```

    这个例子中，JavaScript 的对象字面量 `{ name: "John", age: 30 }` 的创建过程在 V8 内部可能会涉及到类似 `DictionaryTemplateInfo` 的机制，特别是当需要高效地创建具有已知结构的对象时。

* **代码中的关键功能点:**
    * `Create()`:  创建一个 `DictionaryTemplateInfo` 对象，并指定预期的属性名称。
    * `NewInstance()`:  根据 `DictionaryTemplateInfo` 创建一个新的 JavaScript 对象实例，并可以初始化属性值。这里涉及到 V8 的对象属性存储和优化机制，例如内联属性和字典模式。

**总结:**

`v8/src/objects/templates.cc` 文件是 V8 引擎中管理模板的核心部分。模板机制是 V8 将 C++ 代码集成到 JavaScript 环境的关键桥梁。

* **`FunctionTemplateInfo`** 负责定义如何创建和表示 JavaScript 函数（包括构造函数）。它与 `v8::FunctionTemplate` API 密切相关。
* **`DictionaryTemplateInfo`** 专注于创建具有预定义属性的简单 JavaScript 对象，可以看作是 `v8::ObjectTemplate` 的一种特化形式。

理解这些模板类的功能对于深入了解 V8 引擎的内部工作原理以及如何通过 C++ 扩展 JavaScript 功能至关重要。这个文件中的代码涉及到对象创建、类型检查、函数元数据管理以及性能优化等多个 V8 核心领域。

Prompt: 
```
这是目录为v8/src/objects/templates.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/templates.h"

#include <algorithm>
#include <cstdint>
#include <optional>

#include "src/api/api-inl.h"
#include "src/base/macros.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/contexts.h"
#include "src/objects/function-kind.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/js-function-inl.h"
#include "src/objects/map-inl.h"
#include "src/objects/name-inl.h"
#include "src/objects/objects.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/objects/string-inl.h"

namespace v8::internal {

bool FunctionTemplateInfo::HasInstanceType() {
  return instance_type() != kNoJSApiObjectType;
}

Handle<SharedFunctionInfo> FunctionTemplateInfo::GetOrCreateSharedFunctionInfo(
    Isolate* isolate, DirectHandle<FunctionTemplateInfo> info,
    MaybeDirectHandle<Name> maybe_name) {
  Tagged<Object> current_info = info->shared_function_info();
  if (IsSharedFunctionInfo(current_info)) {
    return handle(Cast<SharedFunctionInfo>(current_info), isolate);
  }
  DirectHandle<Name> name;
  DirectHandle<String> name_string;
  if (maybe_name.ToHandle(&name) && IsString(*name)) {
    name_string = Cast<String>(name);
  } else if (IsString(info->class_name())) {
    name_string = direct_handle(Cast<String>(info->class_name()), isolate);
  } else {
    name_string = isolate->factory()->empty_string();
  }
  if (IsString(info->interface_name()) && IsString(info->class_name())) {
    std::cout << "interface.class: " 
              << Cast<String>(info->interface_name())->ToCString().get() 
              << "." 
              << Cast<String>(info->class_name())->ToCString().get() 
              << std::endl;
  } else if (IsString(info->interface_name())) {
    std::cout << "interface.class: " 
              << Cast<String>(info->interface_name())->ToCString().get() 
              << ".<no class>" 
              << std::endl;
  } else if (IsString(info->class_name())) {
    std::cout << "interface.class: <no interface>." 
              << Cast<String>(info->class_name())->ToCString().get() 
              << std::endl;
  }
  
  FunctionKind function_kind;
  if (info->remove_prototype()) {
    function_kind = FunctionKind::kConciseMethod;
  } else {
    function_kind = FunctionKind::kNormalFunction;
  }
  Handle<SharedFunctionInfo> sfi =
      isolate->factory()->NewSharedFunctionInfoForApiFunction(name_string, info,
                                                              function_kind);
  DCHECK(sfi->IsApiFunction());
  // Transfer class name and interface name from template info to shared function info
  if (IsString(info->class_name())) {
    sfi->set_more_scope_info_class_name(Cast<String>(info->class_name()));
  }
  
  if (IsString(info->interface_name())) {
    sfi->set_more_scope_info_interface_name(Cast<String>(info->interface_name()));
  }
  info->set_shared_function_info(*sfi);
  return sfi;
}

bool FunctionTemplateInfo::IsTemplateFor(Tagged<Map> map) const {
  RCS_SCOPE(
      LocalHeap::Current() == nullptr
          ? GetIsolateChecked()->counters()->runtime_call_stats()
          : LocalIsolate::FromHeap(LocalHeap::Current())->runtime_call_stats(),
      RuntimeCallCounterId::kIsTemplateFor);

  // There is a constraint on the object; check.
  if (!IsJSObjectMap(map)) return false;

  if (v8_flags.experimental_embedder_instance_types) {
    DCHECK_IMPLIES(allowed_receiver_instance_type_range_start() == 0,
                   allowed_receiver_instance_type_range_end() == 0);
    if (base::IsInRange(map->instance_type(),
                        allowed_receiver_instance_type_range_start(),
                        allowed_receiver_instance_type_range_end())) {
      return true;
    }
  }

  // Fetch the constructor function of the object.
  Tagged<Object> cons_obj = map->GetConstructor();
  Tagged<Object> type;
  if (IsJSFunction(cons_obj)) {
    Tagged<JSFunction> fun = Cast<JSFunction>(cons_obj);
    if (!fun->shared()->IsApiFunction()) return false;
    type = fun->shared()->api_func_data();
  } else if (IsFunctionTemplateInfo(cons_obj)) {
    type = Cast<FunctionTemplateInfo>(cons_obj);
  } else {
    return false;
  }
  DCHECK(IsFunctionTemplateInfo(type));
  // Iterate through the chain of inheriting function templates to
  // see if the required one occurs.
  while (IsFunctionTemplateInfo(type)) {
    if (type == *this) return true;
    type = Cast<FunctionTemplateInfo>(type)->GetParentTemplate();
  }
  // Didn't find the required type in the inheritance chain.
  return false;
}

bool FunctionTemplateInfo::IsLeafTemplateForApiObject(
    Tagged<Object> object) const {
  i::DisallowGarbageCollection no_gc;

  if (!IsJSApiObject(object)) {
    return false;
  }

  bool result = false;
  Tagged<Map> map = Cast<HeapObject>(object)->map();
  Tagged<Object> constructor_obj = map->GetConstructor();
  if (IsJSFunction(constructor_obj)) {
    Tagged<JSFunction> fun = Cast<JSFunction>(constructor_obj);
    result = (*this == fun->shared()->api_func_data());
  } else if (IsFunctionTemplateInfo(constructor_obj)) {
    result = (*this == constructor_obj);
  }
  DCHECK_IMPLIES(result, IsTemplateFor(map));
  return result;
}

// static
Tagged<FunctionTemplateRareData>
FunctionTemplateInfo::AllocateFunctionTemplateRareData(
    Isolate* isolate,
    DirectHandle<FunctionTemplateInfo> function_template_info) {
  DCHECK(IsUndefined(function_template_info->rare_data(kAcquireLoad), isolate));
  DirectHandle<FunctionTemplateRareData> rare_data =
      isolate->factory()->NewFunctionTemplateRareData();
  function_template_info->set_rare_data(*rare_data, kReleaseStore);
  return *rare_data;
}

std::optional<Tagged<Name>> FunctionTemplateInfo::TryGetCachedPropertyName(
    Isolate* isolate, Tagged<Object> getter) {
  DisallowGarbageCollection no_gc;
  if (!IsFunctionTemplateInfo(getter)) {
    if (!IsJSFunction(getter)) return {};
    Tagged<SharedFunctionInfo> info = Cast<JSFunction>(getter)->shared();
    if (!info->IsApiFunction()) return {};
    getter = info->api_func_data();
  }
  // Check if the accessor uses a cached property.
  Tagged<Object> maybe_name =
      Cast<FunctionTemplateInfo>(getter)->cached_property_name();
  if (IsTheHole(maybe_name, isolate)) return {};
  return Cast<Name>(maybe_name);
}

int FunctionTemplateInfo::GetCFunctionsCount() const {
  i::DisallowHeapAllocation no_gc;
  return Cast<FixedArray>(GetCFunctionOverloads())->length() /
         kFunctionOverloadEntrySize;
}

Address FunctionTemplateInfo::GetCFunction(Isolate* isolate, int index) const {
  i::DisallowHeapAllocation no_gc;
  return v8::ToCData<kCFunctionTag>(
      isolate, Cast<FixedArray>(GetCFunctionOverloads())
                   ->get(index * kFunctionOverloadEntrySize));
}

const CFunctionInfo* FunctionTemplateInfo::GetCSignature(Isolate* isolate,
                                                         int index) const {
  i::DisallowHeapAllocation no_gc;
  return v8::ToCData<CFunctionInfo*, kCFunctionInfoTag>(
      isolate, Cast<FixedArray>(GetCFunctionOverloads())
                   ->get(index * kFunctionOverloadEntrySize + 1));
}

// static
Handle<DictionaryTemplateInfo> DictionaryTemplateInfo::Create(
    Isolate* isolate, const v8::MemorySpan<const std::string_view>& names) {
  DirectHandle<FixedArray> property_names = isolate->factory()->NewFixedArray(
      static_cast<int>(names.size()), AllocationType::kOld);
  int index = 0;
  uint32_t unused_array_index;
  for (const std::string_view& name : names) {
    DirectHandle<String> internalized_name =
        isolate->factory()->InternalizeString(
            base::Vector<const char>(name.data(), name.length()));
    // Check that property name cannot be used as index.
    CHECK(!internalized_name->AsArrayIndex(&unused_array_index));
    property_names->set(index, *internalized_name);
    ++index;
  }
  return isolate->factory()->NewDictionaryTemplateInfo(property_names);
}

namespace {

Handle<JSObject> CreateSlowJSObjectWithProperties(
    Isolate* isolate, DirectHandle<FixedArray> property_names,
    const MemorySpan<MaybeLocal<Value>>& property_values,
    int num_properties_set) {
  Handle<JSObject> object = isolate->factory()->NewSlowJSObjectFromMap(
      isolate->slow_object_with_object_prototype_map(), num_properties_set,
      AllocationType::kYoung);
  Handle<Object> properties = handle(object->raw_properties_or_hash(), isolate);
  for (int i = 0; i < static_cast<int>(property_values.size()); ++i) {
    Local<Value> property_value;
    if (!property_values[i].ToLocal(&property_value)) {
      continue;
    }
    properties = PropertyDictionary::Add(
        isolate, Cast<PropertyDictionary>(properties),
        Cast<String>(handle(property_names->get(i), isolate)),
        Utils::OpenHandle(*property_value), PropertyDetails::Empty());
  }
  object->set_raw_properties_or_hash(*properties);
  return object;
}

}  // namespace

// static
Handle<JSObject> DictionaryTemplateInfo::NewInstance(
    DirectHandle<NativeContext> context,
    DirectHandle<DictionaryTemplateInfo> self,
    const MemorySpan<MaybeLocal<Value>>& property_values) {
  Isolate* isolate = context->GetIsolate();
  DirectHandle<FixedArray> property_names(self->property_names(), isolate);

  const int property_names_len = property_names->length();
  CHECK_EQ(property_names_len, static_cast<int>(property_values.size()));
  const int num_properties_set = static_cast<int>(std::count_if(
      property_values.begin(), property_values.end(),
      [](const auto& maybe_value) { return !maybe_value.IsEmpty(); }));

  if (V8_UNLIKELY(num_properties_set > JSObject::kMaxInObjectProperties)) {
    return CreateSlowJSObjectWithProperties(
        isolate, property_names, property_values, num_properties_set);
  }

  const bool can_use_map_cache = num_properties_set == property_names_len;
  MaybeHandle<Map> maybe_cached_map;
  if (V8_LIKELY(can_use_map_cache)) {
    maybe_cached_map = TemplateInfo::ProbeInstantiationsCache<Map>(
        isolate, context, self->serial_number(),
        TemplateInfo::CachingMode::kUnlimited);
  }
  Handle<Map> cached_map;
  if (V8_LIKELY(can_use_map_cache && maybe_cached_map.ToHandle(&cached_map))) {
    DCHECK(!cached_map->is_dictionary_map());
    bool can_use_cached_map = !cached_map->is_deprecated();
    if (V8_LIKELY(can_use_cached_map)) {
      // Verify that the cached map can be reused.
      auto descriptors = handle(cached_map->instance_descriptors(), isolate);
      for (int i = 0; i < static_cast<int>(property_values.size()); ++i) {
        DirectHandle<Object> value =
            Utils::OpenDirectHandle(*property_values[i].ToLocalChecked());
        InternalIndex descriptor{static_cast<size_t>(i)};
        const auto details = descriptors->GetDetails(descriptor);

        if (!Object::FitsRepresentation(*value, details.representation()) ||
            !FieldType::NowContains(descriptors->GetFieldType(descriptor),
                                    value)) {
          can_use_cached_map = false;
          break;
        }
        // Double representation means mutable heap number. In this case we need
        // to allocate a new heap number to put in the dictionary.
        if (details.representation().Equals(Representation::Double())) {
          // We allowed coercion in `FitsRepresentation` above which means that
          // we may deal with a Smi here.
          property_values[i] =
              ToApiHandle<v8::Object>(isolate->factory()->NewHeapNumber(
                  Object::NumberValue(Cast<Number>(*value))));
        }
      }
      if (V8_LIKELY(can_use_cached_map)) {
        // Create the object from the cached map.
        CHECK(!cached_map->is_deprecated());
        CHECK_EQ(context->object_function_prototype(), cached_map->prototype());
        auto object = isolate->factory()->NewJSObjectFromMap(
            cached_map, AllocationType::kYoung);
        DisallowGarbageCollection no_gc;
        for (int i = 0; i < static_cast<int>(property_values.size()); ++i) {
          Local<Value> property_value = property_values[i].ToLocalChecked();
          DirectHandle<Object> value = Utils::OpenDirectHandle(*property_value);
          const FieldIndex index = FieldIndex::ForPropertyIndex(
              *cached_map, i, Representation::Tagged());
          object->FastPropertyAtPut(index, *value,
                                    WriteBarrierMode::SKIP_WRITE_BARRIER);
        }
        return object;
      }
    }
    // A cached map was either deprecated or the descriptors changed in
    // incompatible ways. We clear the cached map and continue with the generic
    // path.
    TemplateInfo::UncacheTemplateInstantiation(
        isolate, context, self, TemplateInfo::CachingMode::kUnlimited);
  }

  // General case: We either don't have a cached map, or it is unusuable for the
  // values provided.
  Handle<Map> current_map = isolate->factory()->ObjectLiteralMapFromCache(
      context, num_properties_set);
  Handle<JSObject> object = isolate->factory()->NewJSObjectFromMap(current_map);
  int current_property_index = 0;
  for (int i = 0; i < static_cast<int>(property_values.size()); ++i) {
    Local<Value> property_value;
    if (!property_values[i].ToLocal(&property_value)) {
      continue;
    }
    auto name = Cast<String>(handle(property_names->get(i), isolate));
    DirectHandle<Object> value = Utils::OpenDirectHandle(*property_value);
    constexpr PropertyAttributes attributes = PropertyAttributes::NONE;
    constexpr PropertyConstness constness = PropertyConstness::kConst;
    current_map = Map::TransitionToDataProperty(isolate, current_map, name,
                                                value, attributes, constness,
                                                StoreOrigin::kNamed);
    if (current_map->is_dictionary_map()) {
      return CreateSlowJSObjectWithProperties(
          isolate, property_names, property_values, num_properties_set);
    }
    JSObject::MigrateToMap(isolate, object, current_map);
    PropertyDetails details = current_map->GetLastDescriptorDetails(isolate);
    object->WriteToField(InternalIndex(current_property_index), details,
                         *value);
    current_property_index++;
  }
  if (V8_LIKELY(can_use_map_cache)) {
    TemplateInfo::CacheTemplateInstantiation(
        isolate, context, self, TemplateInfo::CachingMode::kUnlimited,
        handle(object->map(), isolate));
  }
  return object;
}

}  // namespace v8::internal

"""

```
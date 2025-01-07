Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Initial Scan for Keywords and Structure:**  First, I quickly scanned the code looking for recognizable C++ keywords (`class`, `namespace`, `bool`, `int`, `Handle`, `static`, etc.) and structural elements like function definitions and includes. This gives a general sense of what the code is doing and where to focus. I noted the namespace `v8::internal`, indicating this is internal V8 code.

2. **Identify the Core Class:** The filename `templates.cc` and the presence of classes like `FunctionTemplateInfo` and `DictionaryTemplateInfo` immediately suggest this code is about V8's templating system. Templates in this context are likely used to define the structure and behavior of JavaScript objects and functions created via the V8 API (like `v8::FunctionTemplate`).

3. **Analyze `FunctionTemplateInfo`:**
    * **`HasInstanceType()`:** This looks straightforward. It checks if the `instance_type()` is not the "no API object" type, suggesting it determines if a template is associated with a specific object type.
    * **`GetOrCreateSharedFunctionInfo()`:** This function is crucial. The name and the logic involving `SharedFunctionInfo` (a key V8 internal object representing functions) strongly suggest it's responsible for linking a `FunctionTemplateInfo` to the underlying executable code. The logging of "interface.class" also hinted at potential metadata associated with templates.
    * **`IsTemplateFor(Tagged<Map> map)`:**  This method's input of `Tagged<Map>` (representing the structure of a JavaScript object) and its logic of checking constructor functions and inheritance chains clearly indicate its role in determining if a given JavaScript object matches a specific template.
    * **`IsLeafTemplateForApiObject()`:**  The "leaf" suggests this is a more specific check, likely verifying if a template is the *direct* template for a given API object, not just an ancestor.
    * **`AllocateFunctionTemplateRareData()`:** The "rare data" suggests supplementary information associated with the template. This might be for less frequently accessed or more complex data.
    * **`TryGetCachedPropertyName()`:** The name and the logic involving `getter` and `cached_property_name()` point to handling cached properties, potentially related to accessors defined on the template.
    * **`GetCFunctionsCount()` and `GetCFunction()`/`GetCSignature()`:**  The "CFunction" in the names strongly indicates integration with native C++ functions. This aligns with how V8 allows embedding C++ functionality within JavaScript.

4. **Analyze `DictionaryTemplateInfo`:**
    * **`Create()`:** The function takes a vector of strings as input and creates a `FixedArray` of internalized strings. This strongly suggests it's used to define a template for objects with a fixed set of property names.
    * **`NewInstance()`:**  This is the key function for creating instances based on the `DictionaryTemplateInfo`. The logic involves checking for cached maps, handling in-object and dictionary properties, and optimizing object creation.

5. **Look for JavaScript Connections:** The mention of "API function," "constructor function," and the general concept of templates mapping to object structures directly relate to the V8 embedding API used in Node.js and Chromium. I started thinking about how `v8::FunctionTemplate` and `v8::ObjectTemplate` are used to define JavaScript object types from C++.

6. **Code Logic and Assumptions:**  For functions like `IsTemplateFor` and `NewInstance`, I mentally traced the code flow. For `IsTemplateFor`, I imagined a chain of templates and how the `while` loop would traverse it. For `NewInstance`, I noted the optimization for cached maps and the fallback to slower object creation if the cache isn't usable.

7. **Identify Potential Errors:** Based on my understanding of how templates are used, I considered common mistakes developers might make. For instance, forgetting to set the prototype, incorrect inheritance, or type mismatches during object instantiation seemed like likely candidates.

8. **Structure the Response:** I organized my findings into the requested categories:

    * **功能:** Summarized the overall purpose of the file and the roles of the key classes.
    * **Torque:**  Explicitly addressed the `.tq` question.
    * **与 JavaScript 的关系:**  Connected the C++ code to the corresponding JavaScript API concepts and provided concrete examples.
    * **代码逻辑推理:**  Focused on the `IsTemplateFor` and `NewInstance` functions, providing example inputs and expected behavior.
    * **用户常见的编程错误:**  Listed common errors related to template usage.

9. **Refine and Elaborate:** I reviewed my initial draft, adding more detail and clarity to each section. For example, I elaborated on the caching mechanism in `NewInstance` and provided more specific JavaScript examples. I also ensured the language was consistent and easy to understand.

This iterative process of scanning, identifying key components, analyzing logic, connecting to JavaScript concepts, and structuring the information allowed me to generate a comprehensive and accurate explanation of the provided V8 source code.
好的，让我们来分析一下 `v8/src/objects/templates.cc` 这个 V8 源代码文件的功能。

**文件功能概览**

`v8/src/objects/templates.cc` 文件主要负责实现 V8 中 **模板 (Templates)** 相关的对象和功能。模板是 V8 嵌入 (embedding) API 的核心概念，允许 C++ 代码定义 JavaScript 对象的结构和行为。

**详细功能分解**

1. **`FunctionTemplateInfo` 类及其相关功能:**
   - **表示函数模板:** `FunctionTemplateInfo` 对象存储了关于函数模板的信息，例如：
     - 函数的名称 (`class_name`, `interface_name`)
     - 是否移除原型 (`remove_prototype`)
     - 关联的共享函数信息 (`shared_function_info`)
     - 允许的接收者实例类型范围 (`allowed_receiver_instance_type_range_start`, `allowed_receiver_instance_type_range_end`)
     - 父模板 (`parent_template`)
   - **创建或获取 `SharedFunctionInfo`:** `GetOrCreateSharedFunctionInfo` 方法负责为函数模板创建或获取关联的 `SharedFunctionInfo` 对象。`SharedFunctionInfo` 包含了函数执行所需的元数据，例如字节码、作用域信息等。这个方法还负责将类名和接口名从模板信息传递到共享函数信息。
   - **检查对象是否由模板创建:** `IsTemplateFor` 方法判断一个给定的 JavaScript `Map` (对象的布局信息) 是否是由当前的 `FunctionTemplateInfo` 或其父模板创建的。这对于类型检查和确保对象符合预期结构非常重要。
   - **检查对象是否是叶子模板的 API 对象:** `IsLeafTemplateForApiObject` 方法检查一个对象是否是由当前函数模板直接创建的 API 对象。
   - **分配稀有数据:** `AllocateFunctionTemplateRareData` 用于为函数模板分配一些不常用的数据。
   - **获取缓存的属性名:** `TryGetCachedPropertyName` 尝试获取与 getter 函数关联的缓存属性名。
   - **获取 C 函数信息:** `GetCFunctionsCount`, `GetCFunction`, `GetCSignature` 用于获取与模板关联的 C++ 函数的信息，用于支持在 JavaScript 中调用 C++ 函数。

2. **`DictionaryTemplateInfo` 类及其相关功能:**
   - **表示字典模板:** `DictionaryTemplateInfo` 用于创建具有预定义属性名称的 JavaScript 对象。
   - **创建字典模板:** `Create` 方法接收一个属性名列表，并创建一个 `DictionaryTemplateInfo` 对象。
   - **创建字典模板的实例:** `NewInstance` 方法基于 `DictionaryTemplateInfo` 创建一个新的 JavaScript 对象。这个方法会尝试利用缓存的 `Map` 对象来优化对象创建过程。如果可以复用缓存的 `Map`，它可以显著提升性能。如果无法复用，它会创建新的 `Map` 并添加属性。

**关于 `.tq` 扩展名**

如果 `v8/src/objects/templates.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码文件**。Torque 是 V8 内部使用的一种类型化的 DSL (领域特定语言)，用于生成高效的 C++ 代码。目前 `templates.cc` 是一个 `.cc` 文件，所以它是直接用 C++ 编写的。

**与 JavaScript 的关系 (及其示例)**

`v8/src/objects/templates.cc` 中的代码是 V8 引擎实现 JavaScript 中与原生 C++ 代码交互的关键部分。它直接关联到 V8 的嵌入 API，允许开发者在 C++ 中定义 JavaScript 对象的行为。

**JavaScript 示例:**

```javascript
// 假设在 C++ 代码中，我们创建了一个名为 'MyObject' 的模板
// 并且定义了一个名为 'myProperty' 的属性和一个名为 'myMethod' 的方法。

// 在 JavaScript 中，我们可以使用这个模板创建对象：
const myObjectInstance = new MyObject();

// 访问属性
console.log(myObjectInstance.myProperty);

// 调用方法
myObjectInstance.myMethod();
```

在这个例子中，`MyObject` 的结构（例如 `myProperty` 的存在）和行为（例如 `myMethod` 的实现）很可能是在 C++ 代码中使用 `FunctionTemplateInfo` 和相关的 API 定义的。`templates.cc` 中的代码负责处理这些模板信息的创建、存储和使用。

**代码逻辑推理 (假设输入与输出)**

**场景：`FunctionTemplateInfo::IsTemplateFor(Tagged<Map> map)`**

**假设输入:**

- `this`: 一个 `FunctionTemplateInfo` 对象，代表一个名为 `MyClass` 的模板。
- `map`: 一个 JavaScript 对象的 `Map` 对象，该对象是通过 `new MyClass()` 创建的。

**预期输出:** `true`

**推理:** `IsTemplateFor` 方法会检查 `map` 的构造函数是否是由当前的 `FunctionTemplateInfo` (`MyClass` 的模板) 或其父模板创建的。由于 `map` 代表的对象是由 `MyClass` 创建的，所以其构造函数会与 `MyClass` 的模板关联，因此方法应该返回 `true`。

**场景：`DictionaryTemplateInfo::NewInstance(...)`**

**假设输入:**

- `context`: 当前的 V8 上下文。
- `self`: 一个 `DictionaryTemplateInfo` 对象，定义了属性 "name" 和 "age"。
- `property_values`: 一个包含两个 `MaybeLocal<Value>` 的数组，分别为 "Alice" 和 30。

**预期输出:** 一个新的 JavaScript 对象，具有属性 `name: "Alice"` 和 `age: 30`。

**推理:** `NewInstance` 方法会根据 `DictionaryTemplateInfo` 中定义的属性名和提供的属性值创建一个新的 JavaScript 对象。它会尝试使用缓存的 `Map` 进行优化，但最终会创建一个包含指定属性和值的对象。

**用户常见的编程错误 (与模板相关)**

1. **未正确设置原型:**  在使用 `FunctionTemplate` 创建对象时，忘记设置合适的原型链会导致创建的对象不具有期望的方法和属性继承。

   ```c++
   // C++ 代码
   v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
   // 错误：忘记设置原型模板
   // t->SetPrototypeTemplate(...);

   // JavaScript 代码
   // const obj = new MyObject();
   // obj.toString(); // 可能报错，因为原型上没有 toString 方法
   ```

2. **类型不匹配:**  在 C++ 中定义模板时，对属性的类型做出了假设，但在 JavaScript 中使用时传递了不兼容的类型。

   ```c++
   // C++ 代码，假设模板的某个属性期望一个整数
   v8::PropertyTemplate props[] = {
       v8::PropertyTemplate::New(isolate, "count", ...),
   };
   object_template->SetProperties(props);

   // JavaScript 代码
   const obj = new MyObject();
   obj.count = "abc"; // 类型不匹配，可能导致运行时错误或意外行为
   ```

3. **在不正确的隔离区 (Isolate) 中使用模板:** V8 的隔离区是独立的执行环境。在一个隔离区中创建的模板不能直接在另一个隔离区中使用。

4. **忘记处理异常:**  如果 C++ 方法在被 JavaScript 调用时抛出异常，需要在 V8 的回调函数中正确处理，否则可能导致 V8 崩溃。

5. **生命周期管理问题:**  当 C++ 对象与 JavaScript 对象关联时，需要仔细管理它们的生命周期，避免悬挂指针或内存泄漏。

总而言之，`v8/src/objects/templates.cc` 是 V8 引擎中至关重要的一个文件，它定义了模板机制，使得 C++ 代码能够灵活地定义和控制 JavaScript 对象的结构和行为，从而实现 JavaScript 与原生代码的高效互操作。

Prompt: 
```
这是目录为v8/src/objects/templates.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/templates.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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
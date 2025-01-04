Response: Let's break down the thought process for analyzing this C++ code.

1. **Identify the Core Purpose:** The file name `debug-wasm-objects.cc` immediately suggests this code is about debugging WebAssembly (Wasm) within the V8 JavaScript engine. The `#include "src/debug/debug-wasm-objects.h"` confirms this.

2. **Scan for Key Concepts and Data Structures:** Look for recurring keywords, class names, and patterns. The code heavily uses:
    * `DebugProxy`: This appears repeatedly, hinting at a core mechanism.
    * `IndexedDebugProxy`, `NamedDebugProxy`: Variations of `DebugProxy`, suggesting different access methods (numeric index vs. name).
    * Proxies for various Wasm components: `FunctionsProxy`, `GlobalsProxy`, `MemoriesProxy`, `TablesProxy`, `LocalsProxy`, `StackProxy`, `StructProxy`, `ArrayProxy`. This points to the code's goal of providing access to different parts of a Wasm instance and execution state.
    * `WasmInstanceObject`, `WasmModuleObject`:  Core Wasm data structures.
    * `WasmValueObject`:  A representation of Wasm values for debugging.
    * `ContextProxy`: A central object providing access to other proxies.
    * `ScopeIterator`:  Used for stepping through scopes during debugging.
    *  `GetOrCreate*`: Functions like `GetOrCreateDebugMaps`, `GetOrCreateDebugProxyMap`, `GetOrCreateInstanceProxyCache`, `GetOrCreateInstanceProxy`. These strongly suggest lazy initialization and caching for performance.

3. **Understand the Proxy Pattern:** The frequent use of "Proxy" indicates the Proxy design pattern. The core idea is to provide a surrogate object that controls access to another object. In this context, the proxies provide a structured way to inspect Wasm internals without directly exposing the underlying C++ objects. This also suggests a level of indirection for safety and abstraction.

4. **Analyze Individual Proxy Classes:**  Examine the purpose of each specific proxy:
    * `FunctionsProxy`:  Access functions within a Wasm module.
    * `GlobalsProxy`: Access global variables.
    * `MemoriesProxy`: Access memory objects.
    * `TablesProxy`: Access table objects.
    * `LocalsProxy`: Access local variables within a Wasm function's execution.
    * `StackProxy`: Access values on the Wasm execution stack.
    * `StructProxy`, `ArrayProxy`: Access members of Wasm struct and array instances.

5. **Trace the Flow and Relationships:** How do these proxies connect?  The `ContextProxy` seems to be the entry point, aggregating the other proxies. The `ScopeIterator` uses the proxies to expose information during debugging sessions. The "GetOrCreate" functions link proxies to specific `WasmInstanceObject` instances, enabling per-instance debugging data.

6. **Look for JavaScript Integration Points:** The code interacts with V8's JavaScript environment:
    * `v8::Local<v8::...>`:  V8's handle types for interacting with JavaScript objects.
    * `v8::FunctionTemplate`: Used to create JavaScript constructor functions for the proxies.
    * `PropertyCallbackInfo`: Used in the indexed and named property handlers, which are core to how JavaScript interacts with these proxy objects.
    * Setting properties on JavaScript objects (e.g., in `ContextProxy::Create` and `DebugWasmScopeIterator::GetObject`).
    * Returning JavaScript values (numbers, strings, objects) from the proxy getters.

7. **Infer Functionality from the Implementation:**
    * **Indexed and Named Access:**  The `IndexedDebugProxy` and `NamedDebugProxy` templates clearly show how properties can be accessed numerically or by name (using a `NameDictionary` for efficient lookup). The `$` prefix for named properties is significant.
    * **Lazy Initialization:** The `GetOrCreate` pattern prevents unnecessary object creation.
    * **Immutability (mostly):**  Properties are generally read-only (`descriptor.set_writable(false)`).
    * **Null Prototypes:** Setting prototypes to `null` prevents accidental prototype chain lookups and emphasizes the dictionary-like nature of some proxies.

8. **Consider the Debugging Context:**  The code is in the `debug` namespace, confirming its purpose. The interaction with `WasmFrame` and `WasmInterpreterEntryFrame` ties it to the execution context during debugging. The comments mentioning "inspector |Runtime.evaluateOnCallFrame()|" provide a concrete use case.

9. **Formulate a Summary:** Combine the observations into a concise description of the file's purpose. Emphasize the main goal (debugging Wasm), the key mechanisms (proxies, scope iteration), and the integration with JavaScript.

10. **Create JavaScript Examples:**  Based on the identified functionality, construct JavaScript examples that demonstrate how developers would interact with these debug objects through the debugger. Focus on accessing properties by index and name, inspecting different Wasm components, and the structure of the `WasmValue` object. Consider scenarios like inspecting local variables, global variables, memory, and function names.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe this is just about representing Wasm objects in JavaScript."
* **Correction:**  The "debug" in the name and the `ScopeIterator` class strongly suggest it's specifically for *debugging*.
* **Initial thought:** "The proxies are just simple wrappers."
* **Refinement:** The indexed and named property handlers show more complex logic for accessing and describing properties. The caching mechanism via `GetOrCreate` is also important.
* **Initial thought:** "The JavaScript examples should just show basic access."
* **Refinement:** The examples should demonstrate *both* indexed and named access, as well as the structure of the `WasmValue` objects to be more comprehensive. Highlighting the `$` prefix is also crucial for named access.

By following these steps, we can systematically analyze the C++ code and understand its functionality and relevance to JavaScript debugging.
这个C++源代码文件 `v8/src/debug/debug-wasm-objects.cc` 的主要功能是**为 WebAssembly (Wasm) 提供调试支持，允许开发者在 JavaScript 环境中检查和交互 Wasm 实例的内部状态。** 它创建了一系列特殊的 JavaScript 对象（称为“代理”），这些对象代表了 Wasm 实例的各种组成部分，例如函数、全局变量、内存、表、局部变量和堆栈。

**核心功能归纳:**

1. **创建 Wasm 调试代理对象:**  该文件定义了多种 "Proxy" 类 (例如 `FunctionsProxy`, `GlobalsProxy`, `MemoriesProxy` 等)，每种代理都负责暴露 Wasm 实例的特定类型的元素。这些代理对象在 JavaScript 中表现为普通的对象，但它们的属性访问被拦截并映射到对 Wasm 实例的内部数据的访问。

2. **提供命名和索引访问:**  对于大多数 Wasm 元素（例如函数、全局变量），代理对象支持通过数字索引和符号名称进行访问。这使得开发者可以使用更友好的方式来检查 Wasm 模块的内部结构。

3. **表示 Wasm 值:**  引入了 `WasmValueObject` 类，用于将 Wasm 的各种数据类型（如 i32, i64, f32, f64, 引用类型等）包装成 JavaScript 对象，并带有 `type` 和 `value` 属性，方便在 JavaScript 中检查。

4. **实现作用域迭代器:**  `DebugWasmScopeIterator` 和 `DebugWasmInterpreterScopeIterator` 用于在调试 Wasm 代码时遍历不同的作用域（例如，局部变量、模块级变量、表达式栈）。这些迭代器返回包含代理对象的 JavaScript 对象，允许调试器检查当前执行上下文的状态。

5. **集成到 JavaScript 调试流程:**  这些代理对象被 V8 的调试器使用，当在 Wasm 代码的断点处暂停时，开发者可以通过浏览器的开发者工具或调试 API 来检查这些代理对象，从而了解 Wasm 实例的当前状态。

**与 JavaScript 的关系及 JavaScript 示例:**

该文件通过 V8 的 C++ 接口与 JavaScript 环境紧密集成。它利用 V8 的 API 来创建 JavaScript 对象、设置属性拦截器、定义类模板等。

当在 JavaScript 中调试 Wasm 代码时，这些代理对象会被暴露出来，允许开发者使用 JavaScript 语法来访问 Wasm 的内部数据。

**JavaScript 示例:**

假设我们有一个简单的 Wasm 模块被加载到 JavaScript 中，并且我们在 Wasm 函数的某个位置设置了断点。当执行到断点时，开发者工具的 "Scope" 面板可能会显示类似于以下的 Wasm 作用域：

```javascript
// 假设在调试器中，当前作用域是 Wasm 的一个函数内部

// 可以访问 Wasm 实例的属性
console.log(instance); // 输出 WebAssembly.Instance 对象

// 可以访问 Wasm 模块的属性
console.log(module);  // 输出 WebAssembly.Module 对象

// 可以访问局部变量 (locals 代理对象)
console.log(locals); // 输出一个对象，其属性对应于局部变量
console.log(locals.$param0); // 假设 Wasm 函数的第一个参数名为 $param0，输出其 WasmValueObject
console.log(locals[0]);     // 通过索引访问局部变量

// 可以访问全局变量 (globals 代理对象)
console.log(globals); // 输出一个对象，其属性对应于全局变量
console.log(globals.$globalVar); // 假设 Wasm 模块有一个名为 $globalVar 的全局变量，输出其 WasmValueObject
console.log(globals[0]);       // 通过索引访问全局变量

// 可以访问内存 (memories 代理对象)
console.log(memories); // 输出一个对象，其属性对应于内存对象
console.log(memories[0]); // 输出 WebAssembly.Memory 对象

// 可以访问表 (tables 代理对象)
console.log(tables);   // 输出一个对象，其属性对应于表对象
console.log(tables[0]); // 输出 WebAssembly.Table 对象

// 可以访问函数 (functions 代理对象)
console.log(functions); // 输出一个对象，其属性对应于函数
console.log(functions.$myWasmFunction); // 假设 Wasm 模块有一个名为 $myWasmFunction 的函数，输出该函数的引用
console.log(functions[0]);             // 通过索引访问函数

// 可以访问 Wasm 表达式栈 (stack 代理对象)
console.log(stack); // 输出一个数组，包含当前 Wasm 表达式栈上的值
console.log(stack[0]); // 输出栈顶的 WasmValueObject

// 检查 WasmValueObject
let localVarValue = locals.$param0;
console.log(localVarValue.type); // 输出 Wasm 值的类型 (例如 "i32", "f64")
console.log(localVarValue.value); // 输出 Wasm 值的实际 JavaScript 表示

// 对于引用类型 (例如结构体或数组)
if (localVarValue.type.startsWith("struct")) {
  console.log(localVarValue.value.$field0); // 访问结构体的字段
} else if (localVarValue.type.startsWith("array")) {
  console.log(localVarValue.value[0]);     // 访问数组的元素
}
```

在这个例子中，`locals`, `globals`, `memories`, `tables`, `functions`, `stack` 这些变量实际上是由 `debug-wasm-objects.cc` 中定义的代理对象创建的。开发者可以通过这些对象，使用类似访问普通 JavaScript 对象的方式来检查 Wasm 的内部状态。以 `$` 开头的属性名通常表示 Wasm 元素的符号名称。

总而言之，`debug-wasm-objects.cc` 是 V8 引擎中实现 Wasm 调试支持的关键组成部分，它通过创建特殊的 JavaScript 代理对象，使得开发者能够在 JavaScript 环境中方便地检查和理解 Wasm 实例的内部状态。

Prompt: 
```
这是目录为v8/src/debug/debug-wasm-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/debug-wasm-objects.h"

#include <optional>

#include "src/api/api-inl.h"
#include "src/api/api-natives.h"
#include "src/base/strings.h"
#include "src/common/globals.h"
#include "src/debug/debug-interface.h"
#include "src/debug/debug-wasm-objects-inl.h"
#include "src/execution/frames-inl.h"
#include "src/objects/allocation-site.h"
#include "src/objects/property-descriptor.h"
#include "src/wasm/names-provider.h"
#include "src/wasm/string-builder.h"
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-value.h"

namespace v8 {
namespace internal {
namespace {

using StringBuilder = wasm::StringBuilder;
Handle<String> ToInternalString(StringBuilder& sb, Isolate* isolate) {
  return isolate->factory()->InternalizeString(
      base::VectorOf(sb.start(), sb.length()));
}

enum DebugProxyId {
  kFunctionsProxy,
  kGlobalsProxy,
  kMemoriesProxy,
  kTablesProxy,
  kLastInstanceProxyId = kTablesProxy,

  kContextProxy,
  kLocalsProxy,
  kStackProxy,
  kStructProxy,
  kArrayProxy,
  kLastProxyId = kArrayProxy,

  kNumProxies = kLastProxyId + 1,
  kNumInstanceProxies = kLastInstanceProxyId + 1
};

constexpr int kWasmValueMapIndex = kNumProxies;
constexpr int kNumDebugMaps = kWasmValueMapIndex + 1;

Handle<FixedArray> GetOrCreateDebugMaps(Isolate* isolate) {
  Handle<FixedArray> maps = isolate->wasm_debug_maps();
  if (maps->length() == 0) {
    maps = isolate->factory()->NewFixedArrayWithHoles(kNumDebugMaps);
    isolate->native_context()->set_wasm_debug_maps(*maps);
  }
  return maps;
}

// Creates a Map for the given debug proxy |id| using the |create_template_fn|
// on-demand and caches this map in the global object. The map is derived from
// the FunctionTemplate returned by |create_template_fn| and has its prototype
// set to |null| and is marked non-extensible (by default).
// TODO(bmeurer): remove the extensibility opt-out and replace it with a proper
// way to add non-intercepted named properties.
Handle<Map> GetOrCreateDebugProxyMap(
    Isolate* isolate, DebugProxyId id,
    v8::Local<v8::FunctionTemplate> (*create_template_fn)(v8::Isolate*),
    bool make_non_extensible = true) {
  auto maps = GetOrCreateDebugMaps(isolate);
  CHECK_LE(kNumProxies, maps->length());
  if (!maps->is_the_hole(isolate, id)) {
    return handle(Cast<Map>(maps->get(id)), isolate);
  }
  auto tmp = (*create_template_fn)(reinterpret_cast<v8::Isolate*>(isolate));
  auto fun = ApiNatives::InstantiateFunction(isolate, Utils::OpenHandle(*tmp))
                 .ToHandleChecked();
  auto map = JSFunction::GetDerivedMap(isolate, fun, fun).ToHandleChecked();
  Map::SetPrototype(isolate, map, isolate->factory()->null_value());
  if (make_non_extensible) {
    map->set_is_extensible(false);
  }
  maps->set(id, *map);
  return map;
}

// Base class for debug proxies, offers indexed access. The subclasses
// need to implement |Count| and |Get| methods appropriately.
template <typename T, DebugProxyId id, typename Provider>
struct IndexedDebugProxy {
  static constexpr DebugProxyId kId = id;

  static Handle<JSObject> Create(Isolate* isolate, Handle<Provider> provider,
                                 bool make_map_non_extensible = true) {
    auto object_map = GetOrCreateDebugProxyMap(isolate, kId, &T::CreateTemplate,
                                               make_map_non_extensible);
    auto object = isolate->factory()->NewFastOrSlowJSObjectFromMap(
        object_map, 0, AllocationType::kYoung,
        DirectHandle<AllocationSite>::null(), NewJSObjectType::kAPIWrapper);
    object->SetEmbedderField(kProviderField, *provider);
    return object;
  }

  enum {
    kProviderField,
    kFieldCount,
  };

  static v8::Local<v8::FunctionTemplate> CreateTemplate(v8::Isolate* isolate) {
    Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
    templ->SetClassName(
        v8::String::NewFromUtf8(isolate, T::kClassName).ToLocalChecked());
    templ->InstanceTemplate()->SetInternalFieldCount(T::kFieldCount);
    templ->InstanceTemplate()->SetHandler(
        v8::IndexedPropertyHandlerConfiguration(
            &T::IndexedGetter, {}, &T::IndexedQuery, {}, &T::IndexedEnumerator,
            {}, &T::IndexedDescriptor, {},
            v8::PropertyHandlerFlags::kHasNoSideEffect));
    return templ;
  }

  template <typename V>
  static Isolate* GetIsolate(const PropertyCallbackInfo<V>& info) {
    return reinterpret_cast<Isolate*>(info.GetIsolate());
  }

  template <typename V>
  static Handle<JSObject> GetHolder(const PropertyCallbackInfo<V>& info) {
    return Cast<JSObject>(Utils::OpenHandle(*info.HolderV2()));
  }

  static Handle<Provider> GetProvider(DirectHandle<JSObject> holder,
                                      Isolate* isolate) {
    return handle(Cast<Provider>(holder->GetEmbedderField(kProviderField)),
                  isolate);
  }

  template <typename V>
  static Handle<Provider> GetProvider(const PropertyCallbackInfo<V>& info) {
    return GetProvider(GetHolder(info), GetIsolate(info));
  }

  static v8::Intercepted IndexedGetter(
      uint32_t index, const PropertyCallbackInfo<v8::Value>& info) {
    auto isolate = GetIsolate(info);
    auto provider = GetProvider(info);
    if (index < T::Count(isolate, provider)) {
      auto value = T::Get(isolate, provider, index);
      info.GetReturnValue().Set(Utils::ToLocal(value));
      return v8::Intercepted::kYes;
    }
    return v8::Intercepted::kNo;
  }

  static v8::Intercepted IndexedDescriptor(
      uint32_t index, const PropertyCallbackInfo<v8::Value>& info) {
    auto isolate = GetIsolate(info);
    auto provider = GetProvider(info);
    if (index < T::Count(isolate, provider)) {
      PropertyDescriptor descriptor;
      descriptor.set_configurable(false);
      descriptor.set_enumerable(true);
      descriptor.set_writable(false);
      descriptor.set_value(Cast<JSAny>(T::Get(isolate, provider, index)));
      info.GetReturnValue().Set(Utils::ToLocal(descriptor.ToObject(isolate)));
      return v8::Intercepted::kYes;
    }
    return v8::Intercepted::kNo;
  }

  static v8::Intercepted IndexedQuery(
      uint32_t index, const PropertyCallbackInfo<v8::Integer>& info) {
    if (index < T::Count(GetIsolate(info), GetProvider(info))) {
      info.GetReturnValue().Set(Integer::New(
          info.GetIsolate(),
          PropertyAttribute::DontDelete | PropertyAttribute::ReadOnly));
      return v8::Intercepted::kYes;
    }
    return v8::Intercepted::kNo;
  }

  static void IndexedEnumerator(const PropertyCallbackInfo<v8::Array>& info) {
    auto isolate = GetIsolate(info);
    auto count = T::Count(isolate, GetProvider(info));
    auto indices = isolate->factory()->NewFixedArray(count);
    for (uint32_t index = 0; index < count; ++index) {
      indices->set(index, Smi::FromInt(index));
    }
    info.GetReturnValue().Set(
        Utils::ToLocal(isolate->factory()->NewJSArrayWithElements(
            indices, PACKED_SMI_ELEMENTS)));
  }
};

// Extends |IndexedDebugProxy| with named access, where the names are computed
// on-demand, and all names are assumed to start with a dollar char ($). This
// is important in order to scale to Wasm modules with hundreds of thousands
// of functions in them.
template <typename T, DebugProxyId id, typename Provider = WasmInstanceObject>
struct NamedDebugProxy : IndexedDebugProxy<T, id, Provider> {
  static v8::Local<v8::FunctionTemplate> CreateTemplate(v8::Isolate* isolate) {
    auto templ = IndexedDebugProxy<T, id, Provider>::CreateTemplate(isolate);
    templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
        &T::NamedGetter, {}, &T::NamedQuery, {}, &T::NamedEnumerator, {},
        &T::NamedDescriptor, {}, v8::PropertyHandlerFlags::kHasNoSideEffect));
    return templ;
  }

  static void IndexedEnumerator(const PropertyCallbackInfo<v8::Array>& info) {
    info.GetReturnValue().Set(v8::Array::New(info.GetIsolate()));
  }

  static Handle<NameDictionary> GetNameTable(Handle<JSObject> holder,
                                             Isolate* isolate) {
    Handle<Symbol> symbol = isolate->factory()->wasm_debug_proxy_names_symbol();
    Handle<Object> table_or_undefined =
        JSObject::GetProperty(isolate, holder, symbol).ToHandleChecked();
    if (!IsUndefined(*table_or_undefined, isolate)) {
      return Cast<NameDictionary>(table_or_undefined);
    }
    auto provider = T::GetProvider(holder, isolate);
    auto count = T::Count(isolate, provider);
    auto table = NameDictionary::New(isolate, count);
    for (uint32_t index = 0; index < count; ++index) {
      HandleScope scope(isolate);
      auto key = T::GetName(isolate, provider, index);
      if (table->FindEntry(isolate, key).is_found()) continue;
      Handle<Smi> value(Smi::FromInt(index), isolate);
      table = NameDictionary::Add(isolate, table, key, value,
                                  PropertyDetails::Empty());
    }
    Object::SetProperty(isolate, holder, symbol, table).Check();
    return table;
  }

  template <typename V>
  static std::optional<uint32_t> FindName(Local<v8::Name> name,
                                          const PropertyCallbackInfo<V>& info) {
    if (!name->IsString()) return {};
    auto name_str = Utils::OpenHandle(*name.As<v8::String>());
    if (name_str->length() == 0 || name_str->Get(0) != '$') return {};
    auto isolate = T::GetIsolate(info);
    auto table = GetNameTable(T::GetHolder(info), isolate);
    auto entry = table->FindEntry(isolate, name_str);
    if (entry.is_found()) return Smi::ToInt(table->ValueAt(entry));
    return {};
  }

  static v8::Intercepted NamedGetter(
      Local<v8::Name> name, const PropertyCallbackInfo<v8::Value>& info) {
    if (auto index = FindName(name, info)) {
      return T::IndexedGetter(*index, info);
    }
    return v8::Intercepted::kNo;
  }

  static v8::Intercepted NamedQuery(
      Local<v8::Name> name, const PropertyCallbackInfo<v8::Integer>& info) {
    if (auto index = FindName(name, info)) {
      return T::IndexedQuery(*index, info);
    }
    return v8::Intercepted::kNo;
  }

  static v8::Intercepted NamedDescriptor(
      Local<v8::Name> name, const PropertyCallbackInfo<v8::Value>& info) {
    if (auto index = FindName(name, info)) {
      return T::IndexedDescriptor(*index, info);
    }
    return v8::Intercepted::kNo;
  }

  static void NamedEnumerator(const PropertyCallbackInfo<v8::Array>& info) {
    auto isolate = T::GetIsolate(info);
    auto table = GetNameTable(T::GetHolder(info), isolate);
    auto names = NameDictionary::IterationIndices(isolate, table);
    for (int i = 0; i < names->length(); ++i) {
      InternalIndex entry(Smi::ToInt(names->get(i)));
      names->set(i, table->NameAt(entry));
    }
    info.GetReturnValue().Set(Utils::ToLocal(
        isolate->factory()->NewJSArrayWithElements(names, PACKED_ELEMENTS)));
  }
};

// This class implements the "functions" proxy.
struct FunctionsProxy : NamedDebugProxy<FunctionsProxy, kFunctionsProxy> {
  static constexpr char const* kClassName = "Functions";

  static uint32_t Count(Isolate* isolate,
                        DirectHandle<WasmInstanceObject> instance) {
    return static_cast<uint32_t>(instance->module()->functions.size());
  }

  static Handle<Object> Get(Isolate* isolate,
                            DirectHandle<WasmInstanceObject> instance,
                            uint32_t index) {
    DirectHandle<WasmTrustedInstanceData> trusted_data{
        instance->trusted_data(isolate), isolate};
    DirectHandle<WasmFuncRef> func_ref =
        WasmTrustedInstanceData::GetOrCreateFuncRef(isolate, trusted_data,
                                                    index);
    DirectHandle<WasmInternalFunction> internal_function{
        func_ref->internal(isolate), isolate};
    return WasmInternalFunction::GetOrCreateExternal(internal_function);
  }

  static Handle<String> GetName(Isolate* isolate,
                                DirectHandle<WasmInstanceObject> instance,
                                uint32_t index) {
    i::DirectHandle<i::WasmTrustedInstanceData> instance_data{
        instance->trusted_data(isolate), isolate};
    return GetWasmFunctionDebugName(isolate, instance_data, index);
  }
};

// This class implements the "globals" proxy.
struct GlobalsProxy : NamedDebugProxy<GlobalsProxy, kGlobalsProxy> {
  static constexpr char const* kClassName = "Globals";

  static uint32_t Count(Isolate* isolate,
                        DirectHandle<WasmInstanceObject> instance) {
    return static_cast<uint32_t>(instance->module()->globals.size());
  }

  static Handle<Object> Get(Isolate* isolate,
                            DirectHandle<WasmInstanceObject> instance,
                            uint32_t index) {
    Handle<WasmModuleObject> module(instance->module_object(), isolate);
    return WasmValueObject::New(
        isolate,
        instance->trusted_data(isolate)->GetGlobalValue(
            isolate, instance->module()->globals[index]),
        module);
  }

  static Handle<String> GetName(Isolate* isolate,
                                DirectHandle<WasmInstanceObject> instance,
                                uint32_t index) {
    wasm::NamesProvider* names =
        instance->module_object()->native_module()->GetNamesProvider();
    StringBuilder sb;
    names->PrintGlobalName(sb, index);
    return ToInternalString(sb, isolate);
  }
};

// This class implements the "memories" proxy.
struct MemoriesProxy : NamedDebugProxy<MemoriesProxy, kMemoriesProxy> {
  static constexpr char const* kClassName = "Memories";

  static uint32_t Count(Isolate* isolate,
                        DirectHandle<WasmInstanceObject> instance) {
    return instance->trusted_data(isolate)->memory_objects()->length();
  }

  static Handle<Object> Get(Isolate* isolate,
                            DirectHandle<WasmInstanceObject> instance,
                            uint32_t index) {
    return handle(instance->trusted_data(isolate)->memory_object(index),
                  isolate);
  }

  static Handle<String> GetName(Isolate* isolate,
                                DirectHandle<WasmInstanceObject> instance,
                                uint32_t index) {
    wasm::NamesProvider* names =
        instance->module_object()->native_module()->GetNamesProvider();
    StringBuilder sb;
    names->PrintMemoryName(sb, index);
    return ToInternalString(sb, isolate);
  }
};

// This class implements the "tables" proxy.
struct TablesProxy : NamedDebugProxy<TablesProxy, kTablesProxy> {
  static constexpr char const* kClassName = "Tables";

  static uint32_t Count(Isolate* isolate,
                        DirectHandle<WasmInstanceObject> instance) {
    return instance->trusted_data(isolate)->tables()->length();
  }

  static Handle<Object> Get(Isolate* isolate,
                            DirectHandle<WasmInstanceObject> instance,
                            uint32_t index) {
    return handle(instance->trusted_data(isolate)->tables()->get(index),
                  isolate);
  }

  static Handle<String> GetName(Isolate* isolate,
                                DirectHandle<WasmInstanceObject> instance,
                                uint32_t index) {
    wasm::NamesProvider* names =
        instance->module_object()->native_module()->GetNamesProvider();
    StringBuilder sb;
    names->PrintTableName(sb, index);
    return ToInternalString(sb, isolate);
  }
};

// This class implements the "locals" proxy.
struct LocalsProxy : NamedDebugProxy<LocalsProxy, kLocalsProxy, FixedArray> {
  static constexpr char const* kClassName = "Locals";

  static Handle<JSObject> Create(WasmFrame* frame) {
    auto isolate = frame->isolate();
    auto debug_info = frame->native_module()->GetDebugInfo();
    // TODO(bmeurer): Check if pc is inspectable.
    int count = debug_info->GetNumLocals(frame->pc(), isolate);
    auto function = debug_info->GetFunctionAtAddress(frame->pc(), isolate);
    auto values = isolate->factory()->NewFixedArray(count + 2);
    Handle<WasmModuleObject> module_object(
        frame->wasm_instance()->module_object(), isolate);
    for (int i = 0; i < count; ++i) {
      auto value = WasmValueObject::New(
          isolate,
          debug_info->GetLocalValue(i, frame->pc(), frame->fp(),
                                    frame->callee_fp(), isolate),
          module_object);
      values->set(i, *value);
    }
    values->set(count + 0, frame->wasm_instance()->module_object());
    values->set(count + 1, Smi::FromInt(function.func_index));
    return NamedDebugProxy::Create(isolate, values);
  }

  static uint32_t Count(Isolate* isolate, DirectHandle<FixedArray> values) {
    return values->length() - 2;
  }

  static Handle<Object> Get(Isolate* isolate, DirectHandle<FixedArray> values,
                            uint32_t index) {
    return handle(values->get(index), isolate);
  }

  static Handle<String> GetName(Isolate* isolate,
                                DirectHandle<FixedArray> values,
                                uint32_t index) {
    uint32_t count = Count(isolate, values);
    auto native_module =
        Cast<WasmModuleObject>(values->get(count + 0))->native_module();
    auto function_index = Smi::ToInt(Cast<Smi>(values->get(count + 1)));
    wasm::NamesProvider* names = native_module->GetNamesProvider();
    StringBuilder sb;
    names->PrintLocalName(sb, function_index, index);
    return ToInternalString(sb, isolate);
  }
};

// This class implements the "stack" proxy (which offers only indexed access).
struct StackProxy : IndexedDebugProxy<StackProxy, kStackProxy, FixedArray> {
  static constexpr char const* kClassName = "Stack";

  static Handle<JSObject> Create(WasmFrame* frame) {
    auto isolate = frame->isolate();
    auto debug_info =
        frame->trusted_instance_data()->native_module()->GetDebugInfo();
    int count = debug_info->GetStackDepth(frame->pc(), isolate);
    auto values = isolate->factory()->NewFixedArray(count);
    Handle<WasmModuleObject> module_object(
        frame->wasm_instance()->module_object(), isolate);
    for (int i = 0; i < count; ++i) {
      auto value = WasmValueObject::New(
          isolate,
          debug_info->GetStackValue(i, frame->pc(), frame->fp(),
                                    frame->callee_fp(), isolate),
          module_object);
      values->set(i, *value);
    }
    return IndexedDebugProxy::Create(isolate, values);
  }

  static uint32_t Count(Isolate* isolate, DirectHandle<FixedArray> values) {
    return values->length();
  }

  static Handle<Object> Get(Isolate* isolate, DirectHandle<FixedArray> values,
                            uint32_t index) {
    return handle(values->get(index), isolate);
  }
};

// Creates FixedArray with size |kNumInstanceProxies| as cache on-demand
// on the |instance|, stored under the |wasm_debug_proxy_cache_symbol|.
// This is used to cache the various instance debug proxies (functions,
// globals, tables, and memories) on the WasmInstanceObject.
Handle<FixedArray> GetOrCreateInstanceProxyCache(
    Isolate* isolate, Handle<WasmInstanceObject> instance) {
  Handle<Object> cache;
  Handle<Symbol> symbol = isolate->factory()->wasm_debug_proxy_cache_symbol();
  if (!Object::GetProperty(isolate, instance, symbol).ToHandle(&cache) ||
      IsUndefined(*cache, isolate)) {
    cache = isolate->factory()->NewFixedArrayWithHoles(kNumInstanceProxies);
    Object::SetProperty(isolate, instance, symbol, cache).Check();
  }
  return Cast<FixedArray>(cache);
}

// Creates an instance of the |Proxy| on-demand and caches that on the
// |instance|.
template <typename Proxy>
Handle<JSObject> GetOrCreateInstanceProxy(Isolate* isolate,
                                          Handle<WasmInstanceObject> instance) {
  static_assert(Proxy::kId < kNumInstanceProxies);
  DirectHandle<FixedArray> proxies =
      GetOrCreateInstanceProxyCache(isolate, instance);
  if (!proxies->is_the_hole(isolate, Proxy::kId)) {
    return handle(Cast<JSObject>(proxies->get(Proxy::kId)), isolate);
  }
  Handle<JSObject> proxy = Proxy::Create(isolate, instance);
  proxies->set(Proxy::kId, *proxy);
  return proxy;
}

// This class implements the debug proxy for a given Wasm frame. The debug
// proxy is used when evaluating JavaScript expressions on a wasm frame via
// the inspector |Runtime.evaluateOnCallFrame()| API and enables developers
// and extensions to inspect the WebAssembly engine state from JavaScript.
// The proxy provides the following interface:
//
// type WasmValue = {
//   type: string;
//   value: number | bigint | object | string;
// };
// type WasmFunction = (... args : WasmValue[]) = > WasmValue;
// interface WasmInterface {
//   $globalX: WasmValue;
//   $varX: WasmValue;
//   $funcX(a : WasmValue /*, ...*/) : WasmValue;
//   readonly $memoryX : WebAssembly.Memory;
//   readonly $tableX : WebAssembly.Table;
//
//   readonly instance : WebAssembly.Instance;
//   readonly module : WebAssembly.Module;
//
//   readonly memories : {[nameOrIndex:string | number] : WebAssembly.Memory};
//   readonly tables : {[nameOrIndex:string | number] : WebAssembly.Table};
//   readonly stack : WasmValue[];
//   readonly globals : {[nameOrIndex:string | number] : WasmValue};
//   readonly locals : {[nameOrIndex:string | number] : WasmValue};
//   readonly functions : {[nameOrIndex:string | number] : WasmFunction};
// }
//
// The wasm index spaces memories, tables, stack, globals, locals, and
// functions are JSObjects with interceptors that lazily produce values
// either by index or by name (except for stack).
// Only the names are reported by APIs such as Object.keys() and
// Object.getOwnPropertyNames(), since the indices are not meant to be
// used interactively by developers (in Chrome DevTools), but are provided
// for WebAssembly language extensions. Also note that these JSObjects
// all have null prototypes, to not confuse context lookup and to make
// their purpose as dictionaries clear.
//
// See http://doc/1VZOJrU2VsqOZe3IUzbwQWQQSZwgGySsm5119Ust1gUA and
// http://bit.ly/devtools-wasm-entities for more details.
class ContextProxyPrototype {
 public:
  static Handle<JSObject> Create(Isolate* isolate) {
    auto object_map =
        GetOrCreateDebugProxyMap(isolate, kContextProxy, &CreateTemplate);
    return isolate->factory()->NewJSObjectFromMap(
        object_map, AllocationType::kYoung,
        DirectHandle<AllocationSite>::null(), NewJSObjectType::kAPIWrapper);
  }

 private:
  static v8::Local<v8::FunctionTemplate> CreateTemplate(v8::Isolate* isolate) {
    Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
    templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
        &NamedGetter, {}, {}, {}, {}, {}, {}, {},
        static_cast<v8::PropertyHandlerFlags>(
            static_cast<unsigned>(
                v8::PropertyHandlerFlags::kOnlyInterceptStrings) |
            static_cast<unsigned>(
                v8::PropertyHandlerFlags::kHasNoSideEffect))));
    return templ;
  }

  static MaybeHandle<Object> GetNamedProperty(Isolate* isolate,
                                              Handle<JSObject> receiver,
                                              Handle<String> name) {
    if (name->length() != 0 && name->Get(0) == '$') {
      const char* kDelegateNames[] = {"memories", "locals", "tables",
                                      "functions", "globals"};
      for (auto delegate_name : kDelegateNames) {
        Handle<JSAny> delegate;
        ASSIGN_RETURN_ON_EXCEPTION(isolate, delegate,
                                   Cast<JSAny>(JSObject::GetProperty(
                                       isolate, receiver, delegate_name)));
        if (!IsUndefined(*delegate, isolate)) {
          Handle<Object> value;
          ASSIGN_RETURN_ON_EXCEPTION(
              isolate, value, Object::GetProperty(isolate, delegate, name));
          if (!IsUndefined(*value, isolate)) return value;
        }
      }
    }
    return {};
  }

  static v8::Intercepted NamedGetter(
      Local<v8::Name> name, const PropertyCallbackInfo<v8::Value>& info) {
    auto name_string = Cast<String>(Utils::OpenHandle(*name));
    auto isolate = reinterpret_cast<Isolate*>(info.GetIsolate());
    auto receiver = Cast<JSObject>(Utils::OpenHandle(*info.This()));
    Handle<Object> value;
    if (GetNamedProperty(isolate, receiver, name_string).ToHandle(&value)) {
      info.GetReturnValue().Set(Utils::ToLocal(value));
      return v8::Intercepted::kYes;
    }
    return v8::Intercepted::kNo;
  }
};

class ContextProxy {
 public:
  static Handle<JSObject> Create(WasmFrame* frame) {
    Isolate* isolate = frame->isolate();
    auto object = isolate->factory()->NewSlowJSObjectWithNullProto();
    Handle<WasmInstanceObject> instance(frame->wasm_instance(), isolate);
    JSObject::AddProperty(isolate, object, "instance", instance, FROZEN);
    DirectHandle<WasmModuleObject> module_object(instance->module_object(),
                                                 isolate);
    JSObject::AddProperty(isolate, object, "module", module_object, FROZEN);
    auto locals = LocalsProxy::Create(frame);
    JSObject::AddProperty(isolate, object, "locals", locals, FROZEN);
    auto stack = StackProxy::Create(frame);
    JSObject::AddProperty(isolate, object, "stack", stack, FROZEN);
    auto memories = GetOrCreateInstanceProxy<MemoriesProxy>(isolate, instance);
    JSObject::AddProperty(isolate, object, "memories", memories, FROZEN);
    auto tables = GetOrCreateInstanceProxy<TablesProxy>(isolate, instance);
    JSObject::AddProperty(isolate, object, "tables", tables, FROZEN);
    auto globals = GetOrCreateInstanceProxy<GlobalsProxy>(isolate, instance);
    JSObject::AddProperty(isolate, object, "globals", globals, FROZEN);
    auto functions =
        GetOrCreateInstanceProxy<FunctionsProxy>(isolate, instance);
    JSObject::AddProperty(isolate, object, "functions", functions, FROZEN);
    Handle<JSObject> prototype = ContextProxyPrototype::Create(isolate);
    JSObject::SetPrototype(isolate, object, prototype, false, kDontThrow)
        .Check();
    return object;
  }
};

class DebugWasmScopeIterator final : public debug::ScopeIterator {
 public:
  explicit DebugWasmScopeIterator(WasmFrame* frame)
      : frame_(frame),
        type_(debug::ScopeIterator::ScopeTypeWasmExpressionStack) {
    // Skip local scope and expression stack scope if the frame is not
    // inspectable.
    if (!frame->is_inspectable()) {
      type_ = debug::ScopeIterator::ScopeTypeModule;
    }
  }

  bool Done() override { return type_ == ScopeTypeWith; }

  void Advance() override {
    DCHECK(!Done());
    switch (type_) {
      case ScopeTypeWasmExpressionStack:
        type_ = debug::ScopeIterator::ScopeTypeLocal;
        break;
      case ScopeTypeLocal:
        type_ = debug::ScopeIterator::ScopeTypeModule;
        break;
      case ScopeTypeModule:
        // We use ScopeTypeWith type as marker for done.
        type_ = debug::ScopeIterator::ScopeTypeWith;
        break;
      default:
        UNREACHABLE();
    }
  }

  ScopeType GetType() override { return type_; }

  v8::Local<v8::Object> GetObject() override {
    Isolate* isolate = frame_->isolate();
    switch (type_) {
      case debug::ScopeIterator::ScopeTypeModule: {
        Handle<WasmInstanceObject> instance{frame_->wasm_instance(), isolate};
        Handle<JSObject> object =
            isolate->factory()->NewSlowJSObjectWithNullProto();
        JSObject::AddProperty(isolate, object, "instance", instance, FROZEN);
        DirectHandle<JSObject> module_object(instance->module_object(),
                                             isolate);
        JSObject::AddProperty(isolate, object, "module", module_object, FROZEN);
        if (FunctionsProxy::Count(isolate, instance) != 0) {
          JSObject::AddProperty(
              isolate, object, "functions",
              GetOrCreateInstanceProxy<FunctionsProxy>(isolate, instance),
              FROZEN);
        }
        if (GlobalsProxy::Count(isolate, instance) != 0) {
          JSObject::AddProperty(
              isolate, object, "globals",
              GetOrCreateInstanceProxy<GlobalsProxy>(isolate, instance),
              FROZEN);
        }
        if (MemoriesProxy::Count(isolate, instance) != 0) {
          JSObject::AddProperty(
              isolate, object, "memories",
              GetOrCreateInstanceProxy<MemoriesProxy>(isolate, instance),
              FROZEN);
        }
        if (TablesProxy::Count(isolate, instance) != 0) {
          JSObject::AddProperty(
              isolate, object, "tables",
              GetOrCreateInstanceProxy<TablesProxy>(isolate, instance), FROZEN);
        }
        return Utils::ToLocal(object);
      }
      case debug::ScopeIterator::ScopeTypeLocal: {
        return Utils::ToLocal(LocalsProxy::Create(frame_));
      }
      case debug::ScopeIterator::ScopeTypeWasmExpressionStack: {
        auto object = isolate->factory()->NewSlowJSObjectWithNullProto();
        auto stack = StackProxy::Create(frame_);
        JSObject::AddProperty(isolate, object, "stack", stack, FROZEN);
        return Utils::ToLocal(object);
      }
      default:
        UNREACHABLE();
    }
  }
  v8::Local<v8::Value> GetFunctionDebugName() override {
    return Utils::ToLocal(frame_->isolate()->factory()->empty_string());
  }

  int GetScriptId() override { return -1; }

  bool HasLocationInfo() override { return false; }

  debug::Location GetStartLocation() override { return {}; }

  debug::Location GetEndLocation() override { return {}; }

  bool SetVariableValue(v8::Local<v8::String> name,
                        v8::Local<v8::Value> value) override {
    return false;
  }

 private:
  WasmFrame* const frame_;
  ScopeType type_;
};

#if V8_ENABLE_DRUMBRAKE
class DebugWasmInterpreterScopeIterator final : public debug::ScopeIterator {
 public:
  explicit DebugWasmInterpreterScopeIterator(WasmInterpreterEntryFrame* frame)
      : frame_(frame), type_(debug::ScopeIterator::ScopeTypeModule) {
    // TODO(paolosev@microsoft.com) -  Enable local scopes and expression stack
    // scopes.
  }

  bool Done() override { return type_ == ScopeTypeWith; }

  void Advance() override {
    DCHECK(!Done());
    switch (type_) {
      case ScopeTypeModule:
        // We use ScopeTypeWith type as marker for done.
        type_ = debug::ScopeIterator::ScopeTypeWith;
        break;
      case ScopeTypeWasmExpressionStack:
      case ScopeTypeLocal:
      default:
        UNREACHABLE();
    }
  }

  ScopeType GetType() override { return type_; }

  v8::Local<v8::Object> GetObject() override {
    Isolate* isolate = frame_->isolate();
    switch (type_) {
      case debug::ScopeIterator::ScopeTypeModule: {
        Handle<WasmInstanceObject> instance(frame_->wasm_instance(), isolate);
        Handle<JSObject> object =
            isolate->factory()->NewSlowJSObjectWithNullProto();
        JSObject::AddProperty(isolate, object, "instance", instance, FROZEN);
        Handle<JSObject> module_object(instance->module_object(), isolate);
        JSObject::AddProperty(isolate, object, "module", module_object, FROZEN);
        if (FunctionsProxy::Count(isolate, instance) != 0) {
          JSObject::AddProperty(
              isolate, object, "functions",
              GetOrCreateInstanceProxy<FunctionsProxy>(isolate, instance),
              FROZEN);
        }
        if (GlobalsProxy::Count(isolate, instance) != 0) {
          JSObject::AddProperty(
              isolate, object, "globals",
              GetOrCreateInstanceProxy<GlobalsProxy>(isolate, instance),
              FROZEN);
        }
        if (MemoriesProxy::Count(isolate, instance) != 0) {
          JSObject::AddProperty(
              isolate, object, "memories",
              GetOrCreateInstanceProxy<MemoriesProxy>(isolate, instance),
              FROZEN);
        }
        if (TablesProxy::Count(isolate, instance) != 0) {
          JSObject::AddProperty(
              isolate, object, "tables",
              GetOrCreateInstanceProxy<TablesProxy>(isolate, instance), FROZEN);
        }
        return Utils::ToLocal(object);
      }
      case debug::ScopeIterator::ScopeTypeLocal:
      case debug::ScopeIterator::ScopeTypeWasmExpressionStack:
      default:
        UNREACHABLE();
    }
  }
  v8::Local<v8::Value> GetFunctionDebugName() override {
    return Utils::ToLocal(frame_->isolate()->factory()->empty_string());
  }

  int GetScriptId() override { return -1; }

  bool HasLocationInfo() override { return false; }

  debug::Location GetStartLocation() override { return {}; }

  debug::Location GetEndLocation() override { return {}; }

  bool SetVariableValue(v8::Local<v8::String> name,
                        v8::Local<v8::Value> value) override {
    return false;
  }

 private:
  WasmInterpreterEntryFrame* const frame_;
  ScopeType type_;
};
#endif  // V8_ENABLE_DRUMBRAKE

Handle<String> WasmSimd128ToString(Isolate* isolate, Simd128 s128) {
  // We use the canonical format as described in:
  // https://github.com/WebAssembly/simd/blob/master/proposals/simd/TextSIMD.md
  base::EmbeddedVector<char, 50> buffer;
  auto i32x4 = s128.to_i32x4();
  SNPrintF(buffer, "i32x4 0x%08X 0x%08X 0x%08X 0x%08X", i32x4.val[0],
           i32x4.val[1], i32x4.val[2], i32x4.val[3]);
  return isolate->factory()->NewStringFromAsciiChecked(buffer.data());
}

Handle<String> GetRefTypeName(Isolate* isolate, wasm::ValueType type,
                              wasm::NativeModule* module) {
  DCHECK(type.is_object_reference());
  StringBuilder name;
  module->GetNamesProvider()->PrintValueType(name, type);
  return ToInternalString(name, isolate);
}

// Returns the type name for the given value. Uses the module object for
// providing user-defined type names if available, otherwise falls back
// to numbers for indexed types.
Handle<String> GetRefTypeName(Isolate* isolate, wasm::ValueType type,
                              Handle<WasmModuleObject> module_object) {
  if (!module_object.is_null()) {
    return GetRefTypeName(isolate, type, module_object->native_module());
  }
  std::string name = type.name();
  return isolate->factory()->InternalizeString({name.data(), name.length()});
}

}  // namespace

// static
Handle<WasmValueObject> WasmValueObject::New(Isolate* isolate,
                                             DirectHandle<String> type,
                                             DirectHandle<Object> value) {
  auto maps = GetOrCreateDebugMaps(isolate);
  if (maps->is_the_hole(isolate, kWasmValueMapIndex)) {
    DirectHandle<Map> map =
        isolate->factory()->NewContextfulMapForCurrentContext(
            WASM_VALUE_OBJECT_TYPE, WasmValueObject::kSize,
            TERMINAL_FAST_ELEMENTS_KIND, 2);
    Map::EnsureDescriptorSlack(isolate, map, 2);
    map->SetConstructor(*isolate->object_function());
    {  // type
      Descriptor d = Descriptor::DataField(
          isolate,
          isolate->factory()->InternalizeString(base::StaticCharVector("type")),
          WasmValueObject::kTypeIndex, FROZEN, Representation::Tagged());
      map->AppendDescriptor(isolate, &d);
    }
    {  // value
      Descriptor d = Descriptor::DataField(
          isolate,
          isolate->factory()->InternalizeString(
              base::StaticCharVector("value")),
          WasmValueObject::kValueIndex, FROZEN, Representation::Tagged());
      map->AppendDescriptor(isolate, &d);
    }
    map->set_is_extensible(false);
    maps->set(kWasmValueMapIndex, *map);
  }
  DirectHandle<Map> value_map(Cast<Map>(maps->get(kWasmValueMapIndex)),
                              isolate);
  auto object =
      Cast<WasmValueObject>(isolate->factory()->NewJSObjectFromMap(value_map));
  object->set_type(*type);
  object->set_value(*value);
  return object;
}

// This class implements a proxy for a single inspectable Wasm struct.
struct StructProxy : NamedDebugProxy<StructProxy, kStructProxy, FixedArray> {
  static constexpr char const* kClassName = "Struct";

  static const int kObjectIndex = 0;
  static const int kModuleIndex = 1;
  static const int kTypeIndexIndex = 2;
  static const int kLength = 3;

  static Handle<JSObject> Create(Isolate* isolate,
                                 DirectHandle<WasmStruct> value,
                                 DirectHandle<WasmModuleObject> module) {
    Handle<FixedArray> data = isolate->factory()->NewFixedArray(kLength);
    data->set(kObjectIndex, *value);
    data->set(kModuleIndex, *module);
    int struct_type_index = value->map()->wasm_type_info()->module_type_index();
    data->set(kTypeIndexIndex, Smi::FromInt(struct_type_index));
    return NamedDebugProxy::Create(isolate, data);
  }

  static uint32_t Count(Isolate* isolate, DirectHandle<FixedArray> data) {
    return Cast<WasmStruct>(data->get(kObjectIndex))->type()->field_count();
  }

  static Handle<Object> Get(Isolate* isolate, DirectHandle<FixedArray> data,
                            uint32_t index) {
    DirectHandle<WasmStruct> obj(Cast<WasmStruct>(data->get(kObjectIndex)),
                                 isolate);
    Handle<WasmModuleObject> module(
        Cast<WasmModuleObject>(data->get(kModuleIndex)), isolate);
    return WasmValueObject::New(isolate, obj->GetFieldValue(index), module);
  }

  static Handle<String> GetName(Isolate* isolate, DirectHandle<FixedArray> data,
                                uint32_t index) {
    wasm::NativeModule* native_module =
        Cast<WasmModuleObject>(data->get(kModuleIndex))->native_module();
    int struct_type_index = Smi::ToInt(Cast<Smi>(data->get(kTypeIndexIndex)));
    wasm::NamesProvider* names = native_module->GetNamesProvider();
    StringBuilder sb;
    names->PrintFieldName(sb, struct_type_index, index);
    return ToInternalString(sb, isolate);
  }
};

// This class implements a proxy for a single inspectable Wasm array.
struct ArrayProxy : IndexedDebugProxy<ArrayProxy, kArrayProxy, FixedArray> {
  static constexpr char const* kClassName = "Array";

  static const int kObjectIndex = 0;
  static const int kModuleIndex = 1;
  static const int kLength = 2;

  static Handle<JSObject> Create(Isolate* isolate,
                                 DirectHandle<WasmArray> value,
                                 DirectHandle<WasmModuleObject> module) {
    Handle<FixedArray> data = isolate->factory()->NewFixedArray(kLength);
    data->set(kObjectIndex, *value);
    data->set(kModuleIndex, *module);
    Handle<JSObject> proxy = IndexedDebugProxy::Create(
        isolate, data, false /* leave map extensible */);
    uint32_t length = value->length();
    Handle<Object> length_obj = isolate->factory()->NewNumberFromUint(length);
    Object::SetProperty(isolate, proxy, isolate->factory()->length_string(),
                        length_obj, StoreOrigin::kNamed,
                        Just(ShouldThrow::kThrowOnError))
        .Check();
    return proxy;
  }

  static v8::Local<v8::FunctionTemplate> CreateTemplate(v8::Isolate* isolate) {
    Local<v8::FunctionTemplate> templ =
        IndexedDebugProxy::CreateTemplate(isolate);
    templ->InstanceTemplate()->Set(isolate, "length",
                                   v8::Number::New(isolate, 0));
    return templ;
  }

  static uint32_t Count(Isolate* isolate, DirectHandle<FixedArray> data) {
    return Cast<WasmArray>(data->get(kObjectIndex))->length();
  }

  static Handle<Object> Get(Isolate* isolate, DirectHandle<FixedArray> data,
                            uint32_t index) {
    DirectHandle<WasmArray> array(Cast<WasmArray>(data->get(kObjectIndex)),
                                  isolate);
    Handle<WasmModuleObject> module(
        Cast<WasmModuleObject>(data->get(kModuleIndex)), isolate);
    return WasmValueObject::New(isolate, array->GetElement(index), module);
  }
};

// static
Handle<WasmValueObject> WasmValueObject::New(
    Isolate* isolate, const wasm::WasmValue& value,
    Handle<WasmModuleObject> module_object) {
  DirectHandle<String> t;
  DirectHandle<Object> v;
  switch (value.type().kind()) {
    case wasm::kI8: {
      // This can't be reached for most "top-level" things, only via nested
      // calls for struct/array fields.
      t = isolate->factory()->InternalizeString(base::StaticCharVector("i8"));
      v = isolate->factory()->NewNumber(value.to_i8_unchecked());
      break;
    }
    case wasm::kI16: {
      // This can't be reached for most "top-level" things, only via nested
      // calls for struct/array fields.
      t = isolate->factory()->InternalizeString(base::StaticCharVector("i16"));
      v = isolate->factory()->NewNumber(value.to_i16_unchecked());
      break;
    }
    case wasm::kI32: {
      t = isolate->factory()->InternalizeString(base::StaticCharVector("i32"));
      v = isolate->factory()->NewNumberFromInt(value.to_i32_unchecked());
      break;
    }
    case wasm::kI64: {
      t = isolate->factory()->InternalizeString(base::StaticCharVector("i64"));
      v = BigInt::FromInt64(isolate, value.to_i64_unchecked());
      break;
    }
    case wasm::kF16: {
      // This can't be reached for most "top-level" things, only via nested
      // calls for struct/array fields.
      t = isolate->factory()->InternalizeString(base::StaticCharVector("f16"));
      v = isolate->factory()->NewNumber(value.to_f16_unchecked());
      break;
    }
    case wasm::kF32: {
      t = isolate->factory()->InternalizeString(base::StaticCharVector("f32"));
      v = isolate->factory()->NewNumber(value.to_f32_unchecked());
      break;
    }
    case wasm::kF64: {
      t = isolate->factory()->InternalizeString(base::StaticCharVector("f64"));
      v = isolate->factory()->NewNumber(value.to_f64_unchecked());
      break;
    }
    case wasm::kS128: {
      t = isolate->factory()->InternalizeString(base::StaticCharVector("v128"));
      v = WasmSimd128ToString(isolate, value.to_s128_unchecked());
      break;
    }
    case wasm::kRefNull:
    case wasm::kRef: {
      Handle<Object> ref = value.to_ref();
      if (value.type().heap_type().representation() == wasm::HeapType::kExn) {
        t = isolate->factory()->InternalizeString(
            base::StaticCharVector("exnref"));
        v = ref;
      } else if (IsWasmStruct(*ref)) {
        Tagged<WasmTypeInfo> type_info =
            Cast<HeapObject>(*ref)->map()->wasm_type_info();
        wasm::ValueType type = wasm::ValueType::Ref(type_info->type_index());
        // Getting the trusted data is safe; structs always have the instance
        // data defined.
        DirectHandle<WasmTrustedInstanceData> wtid(
            type_info->trusted_data(isolate), isolate);
        t = GetRefTypeName(isolate, type, wtid->native_module());
        v = StructProxy::Create(isolate, Cast<WasmStruct>(ref),
                                direct_handle(wtid->module_object(), isolate));
      } else if (IsWasmArray(*ref)) {
        Tagged<WasmTypeInfo> type_info =
            Cast<HeapObject>(*ref)->map()->wasm_type_info();
        wasm::ValueType type = wasm::ValueType::Ref(type_info->type_index());
        // Getting the trusted data is safe; arrays always have the instance
        // data defined.
        DirectHandle<WasmTrustedInstanceData> wtid(
            type_info->trusted_data(isolate), isolate);
        t = GetRefTypeName(isolate, type, wtid->native_module());
        v = ArrayProxy::Create(isolate, Cast<WasmArray>(ref),
                               direct_handle(wtid->module_object(), isolate));
      } else if (IsWasmFuncRef(*ref)) {
        DirectHandle<WasmInternalFunction> internal_fct{
            Cast<WasmFuncRef>(*ref)->internal(isolate), isolate};
        v = WasmInternalFunction::GetOrCreateExternal(internal_fct);
        // If the module is not provided by the caller, retrieve it from the
        // instance object. If the function was created in JavaScript using
        // `new WebAssembly.Function(...)`, a module for name resolution is not
        // available.
        if (module_object.is_null() &&
            IsWasmTrustedInstanceData(internal_fct->implicit_arg())) {
          module_object =
              handle(Cast<WasmTrustedInstanceData>(internal_fct->implicit_arg())
                         ->module_object(),
                     isolate);
        }
        t = GetRefTypeName(isolate, value.type(), module_object);
      } else if (IsWasmNull(*ref)) {
        // TODO(manoskouk): Is this value correct?
        v = isolate->factory()->null_value();
        t = GetRefTypeName(isolate, value.type(), module_object);
      } else if (IsJSFunction(*ref) || IsSmi(*ref) || IsNull(*ref) ||
                 IsString(*ref) ||
                 value.type().is_reference_to(wasm::HeapType::kExtern) ||
                 value.type().is_reference_to(wasm::HeapType::kAny)) {
        t = GetRefTypeName(isolate, value.type(), module_object);
        v = ref;
      } else {
        // Fail gracefully.
        base::EmbeddedVector<char, 64> error;
        int len = SNPrintF(error, "unimplemented object type: %d",
                           Cast<HeapObject>(*ref)->map()->instance_type());
        t = GetRefTypeName(isolate, value.type(), module_object);
        v = isolate->factory()->InternalizeString(error.SubVector(0, len));
      }
      break;
    }
    case wasm::kRtt:
    case wasm::kVoid:
    case wasm::kTop:
    case wasm::kBottom:
      UNREACHABLE();
  }
  return New(isolate, t, v);
}

Handle<JSObject> GetWasmDebugProxy(WasmFrame* frame) {
  return ContextProxy::Create(frame);
}

std::unique_ptr<debug::ScopeIterator> GetWasmScopeIterator(WasmFrame* frame) {
  return std::make_unique<DebugWasmScopeIterator>(frame);
}

#if V8_ENABLE_DRUMBRAKE
std::unique_ptr<debug::ScopeIterator> GetWasmInterpreterScopeIterator(
    WasmInterpreterEntryFrame* frame) {
  return std::make_unique<DebugWasmInterpreterScopeIterator>(frame);
}
#endif  // V8_ENABLE_DRUMBRAKE

Handle<String> GetWasmFunctionDebugName(
    Isolate* isolate, DirectHandle<WasmTrustedInstanceData> instance_data,
    uint32_t func_index) {
  wasm::NativeModule* native_module = instance_data->native_module();
  wasm::NamesProvider* names = native_module->GetNamesProvider();
  StringBuilder sb;
  wasm::NamesProvider::FunctionNamesBehavior behavior =
      is_asmjs_module(native_module->module())
          ? wasm::NamesProvider::kWasmInternal
          : wasm::NamesProvider::kDevTools;
  names->PrintFunctionName(sb, func_index, behavior);
  return ToInternalString(sb, isolate);
}

Handle<ArrayList> AddWasmInstanceObjectInternalProperties(
    Isolate* isolate, Handle<ArrayList> result,
    Handle<WasmInstanceObject> instance) {
  result = ArrayList::Add(
      isolate, result,
      isolate->factory()->NewStringFromAsciiChecked("[[Module]]"),
      handle(instance->module_object(), isolate));

  if (FunctionsProxy::Count(isolate, instance) != 0) {
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[Functions]]"),
        GetOrCreateInstanceProxy<FunctionsProxy>(isolate, instance));
  }

  if (GlobalsProxy::Count(isolate, instance) != 0) {
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[Globals]]"),
        GetOrCreateInstanceProxy<GlobalsProxy>(isolate, instance));
  }

  if (MemoriesProxy::Count(isolate, instance) != 0) {
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[Memories]]"),
        GetOrCreateInstanceProxy<MemoriesProxy>(isolate, instance));
  }

  if (TablesProxy::Count(isolate, instance) != 0) {
    result = ArrayList::Add(
        isolate, result,
        isolate->factory()->NewStringFromAsciiChecked("[[Tables]]"),
        GetOrCreateInstanceProxy<TablesProxy>(isolate, instance));
  }

  return result;
}

Handle<ArrayList> AddWasmModuleObjectInternalProperties(
    Isolate* isolate, Handle<ArrayList> result,
    DirectHandle<WasmModuleObject> module_object) {
  result = ArrayList::Add(
      isolate, result,
      isolate->factory()->NewStringFromStaticChars("[[Exports]]"),
      wasm::GetExports(isolate, module_object));
  result = ArrayList::Add(
      isolate, result,
      isolate->factory()->NewStringFromStaticChars("[[Imports]]"),
      wasm::GetImports(isolate, module_object));
  return result;
}

Handle<ArrayList> AddWasmTableObjectInternalProperties(
    Isolate* isolate, Handle<ArrayList> result,
    DirectHandle<WasmTableObject> table) {
  int length = table->current_length();
  DirectHandle<FixedArray> entries = isolate->factory()->NewFixedArray(length);
  for (int i = 0; i < length; ++i) {
    Handle<Object> entry = WasmTableObject::Get(isolate, table, i);
    Handle<WasmModuleObject> module;
    if (table->has_trusted_data()) {
      module = Handle<WasmModuleObject>(
          table->trusted_data(isolate)->module_object(), isolate);
    }
    wasm::WasmValue wasm_value(entry, table->type(),
                               !module.is_null() ? module->module() : nullptr);
    DirectHandle<Object> debug_value =
        WasmValueObject::New(isolate, wasm_value, module);
    entries->set(i, *debug_value);
  }
  Handle<JSArray> final_entries = isolate->factory()->NewJSArrayWithElements(
      entries, i::PACKED_ELEMENTS, length);
  JSObject::SetPrototype(isolate, final_entries,
                         isolate->factory()->null_value(), false, kDontThrow)
      .Check();
  DirectHandle<String> entries_string =
      isolate->factory()->NewStringFromStaticChars("[[Entries]]");
  result = ArrayList::Add(isolate, result, entries_string, final_entries);
  return result;
}

}  // namespace internal
}  // namespace v8

"""

```
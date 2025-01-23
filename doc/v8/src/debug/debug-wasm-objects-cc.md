Response:
The user wants a summary of the provided C++ code, specifically focusing on its functionality within the V8 JavaScript engine's debugging system for WebAssembly.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core purpose:** The filename `debug-wasm-objects.cc` and the namespace `v8::internal::debug` strongly suggest this code is responsible for creating and managing JavaScript objects that expose WebAssembly internals for debugging purposes.

2. **Analyze the major components:**  Scan the code for key data structures, classes, and functions. Notice the `IndexedDebugProxy` and `NamedDebugProxy` templates, and the specific proxies like `FunctionsProxy`, `GlobalsProxy`, `MemoriesProxy`, `TablesProxy`, `LocalsProxy`, and `StackProxy`. Also, the `ContextProxy` and `ContextProxyPrototype` classes stand out.

3. **Understand the proxy pattern:** The proxy classes seem to follow a pattern:
    * They have a `Create` method to instantiate the proxy object.
    * They implement `Count` and `Get` to provide indexed access to underlying WebAssembly data.
    * Some use `GetName` for named access (those inheriting from `NamedDebugProxy`).
    * They are associated with a `DebugProxyId`.

4. **Connect proxies to WebAssembly concepts:**  The names of the specific proxy classes directly correspond to core WebAssembly concepts: functions, globals, memories, tables, locals, and the stack. This suggests these proxies provide access to these elements of a running WebAssembly instance.

5. **Examine `ContextProxy`:** This class seems to be a central hub. It creates an object containing the other proxies (`locals`, `stack`, `memories`, `tables`, `globals`, `functions`) and properties like `instance` and `module`. This suggests it represents the debugging context for a WebAssembly frame.

6. **Investigate `DebugWasmScopeIterator`:** This class implements the `debug::ScopeIterator` interface. Its purpose is to allow the debugger to traverse the different scopes available within a WebAssembly frame (expression stack, locals, module).

7. **Consider the JavaScript interaction:** The code uses V8's API for creating JavaScript objects (`v8::FunctionTemplate`, `v8::Object::SetHandler`, etc.). The proxies use indexed and named property handlers, allowing access like `wasm_debug_object.functions[0]` or `wasm_debug_object.globals.$myGlobal`. This confirms the connection to JavaScript debugging.

8. **Look for potential user errors:** The code deals with indexing into arrays and accessing properties by name. A common user error would be trying to access an index that's out of bounds or a name that doesn't exist.

9. **Infer the workflow:**  The `ContextProxy` seems to be created for a specific `WasmFrame`. The `DebugWasmScopeIterator` uses this `ContextProxy` and other information to provide the debugger with access to the Wasm state.

10. **Structure the summary:** Organize the findings into logical sections:
    * Overall purpose.
    * Key classes and their roles.
    * How it relates to JavaScript.
    * Potential user errors.
    * Code logic (using an example).

11. **Refine and elaborate:** Add details and explanations to make the summary clearer and more comprehensive. For example, explicitly mention the lazy creation and caching of proxy objects. Explain the role of the `wasm_debug_proxy_cache_symbol`.

By following these steps, we can arrive at a detailed and accurate summary of the provided C++ code. The key is to understand the structure of the code, the purpose of the different components, and how they interact to achieve the overall goal of enabling WebAssembly debugging within V8.
好的，这是对 `v8/src/debug/debug-wasm-objects.cc` 文件功能的归纳：

**功能归纳：**

`v8/src/debug/debug-wasm-objects.cc` 文件的主要功能是为 V8 引擎的 WebAssembly 调试器提供 JavaScript 可访问的代理对象。这些代理对象允许开发者在调试 WebAssembly 代码时，通过 JavaScript 的方式检查和访问 WebAssembly 实例的内部状态，例如：

* **模块信息:** 访问 WebAssembly 模块的实例和模块对象。
* **函数:**  列出和访问 WebAssembly 实例中的函数，并允许以 JavaScript 函数的形式调用它们。
* **全局变量:**  列出和访问 WebAssembly 实例中的全局变量的值。
* **内存:** 列出和访问 WebAssembly 实例中的内存对象。
* **表格:** 列出和访问 WebAssembly 实例中的表格对象。
* **局部变量:** 在特定的 WebAssembly 帧中，列出和访问局部变量的值。
* **表达式栈:** 在特定的 WebAssembly 帧中，访问表达式栈上的值。

该文件定义了多种代理类，每种代理类负责暴露 WebAssembly 实例的不同部分。这些代理对象通常是懒加载的，只有在需要时才会被创建。

**代码结构和关键概念：**

* **`IndexedDebugProxy` 和 `NamedDebugProxy` 模板:**  这两个模板是创建代理对象的基础。`IndexedDebugProxy` 提供基于索引的访问，而 `NamedDebugProxy` 在此基础上增加了基于名称的访问（名称通常以 `$` 开头）。
* **具体的代理类:**  例如 `FunctionsProxy`, `GlobalsProxy`, `MemoriesProxy`, `TablesProxy`, `LocalsProxy`, `StackProxy` 等，它们继承自上述模板，并实现了访问特定 WebAssembly 数据的逻辑。
* **`ContextProxy`:**  这是一个核心的代理类，它代表了 WebAssembly 帧的调试上下文。它包含对其他各种代理对象的引用，例如 `locals`, `stack`, `memories`, `tables`, `globals`, `functions`。
* **`DebugWasmScopeIterator`:**  这个类实现了 `debug::ScopeIterator` 接口，用于在调试过程中遍历 WebAssembly 帧的各种作用域（例如局部作用域、模块作用域、表达式栈作用域）。
* **懒加载和缓存:** 为了提高性能，代理对象通常是懒加载的，并且会被缓存在 `WasmInstanceObject` 中。

**与 JavaScript 的关系：**

该文件生成的代理对象可以直接在 JavaScript 代码中使用，尤其是在调试器的上下文中。例如，当程序在 WebAssembly 代码中暂停时，开发者可以通过调试控制台访问这些代理对象来检查 WebAssembly 的状态。

**JavaScript 示例：**

假设我们在调试一个包含一个名为 `myGlobal` 的全局变量的 WebAssembly 模块，并且程序暂停在 WebAssembly 代码中。我们可以通过调试器的上下文访问到 `globals` 代理对象，并读取 `myGlobal` 的值：

```javascript
// 假设 'wasmDebugContext' 是调试器提供的访问 WebAssembly 上下文的入口
console.log(wasmDebugContext.globals.$myGlobal);
```

如果 WebAssembly 模块中有一个名为 `add` 的函数，我们可以通过 `functions` 代理对象来调用它：

```javascript
// 假设该函数接受两个 i32 类型的参数
let result = wasmDebugContext.functions.$add({ type: 'i32', value: 5 }, { type: 'i32', value: 10 });
console.log(result); // 输出类似 { type: 'i32', value: 15 } 的结果
```

**代码逻辑推理 (假设输入与输出):**

假设有一个 WebAssembly 实例 `instance`，它有一个名为 `counter` 的全局变量，其值为 10。当我们通过调试器访问 `globals` 代理并获取 `counter` 的值时：

**假设输入:**  一个 `WasmInstanceObject` 实例，其中全局变量 `counter` 的值为 10。

**预期输出:**  通过 `globals` 代理对象的 JavaScript 访问，返回一个表示该全局变量的对象，例如：`{ type: 'i32', value: 10 }` （假设 `counter` 是一个 i32 类型的全局变量）。

**用户常见的编程错误：**

在使用这些调试对象时，用户可能会犯以下错误：

* **访问不存在的属性:** 尝试访问不存在的全局变量、函数或内存的名称或索引。例如，如果模块中没有名为 `nonExistentGlobal` 的全局变量，尝试访问 `wasmDebugContext.globals.$nonExistentGlobal` 将会返回 `undefined`。
* **错误的参数类型:** 在调用 WebAssembly 函数时，传递了类型不匹配的参数。例如，如果一个函数期望一个 `i32` 类型的参数，却传递了一个字符串，会导致错误。
* **越界访问:** 尝试访问超出范围的内存或表格索引。例如，如果内存大小为 100 字节，尝试访问索引 100 或更大的位置将导致错误。

**总结：**

`v8/src/debug/debug-wasm-objects.cc` 文件定义了用于 WebAssembly 调试的 JavaScript 代理对象，它允许开发者在 JavaScript 环境中检查和操作 WebAssembly 实例的内部状态，极大地提升了 WebAssembly 代码的调试体验。它通过一系列精心设计的代理类和作用域迭代器，将 WebAssembly 的复杂结构映射到易于理解和使用的 JavaScript 对象。

### 提示词
```
这是目录为v8/src/debug/debug-wasm-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/debug-wasm-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```
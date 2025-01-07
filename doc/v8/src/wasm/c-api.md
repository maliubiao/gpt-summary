Response: The user wants a summary of the C++ code in `v8/src/wasm/c-api.cc`. The request explicitly mentions that this is the first part of a two-part file and asks to identify functionality and its relation to JavaScript, providing JavaScript examples if applicable.

**Plan:**

1. **Identify Core Functionality:** Read through the code, focusing on the defined structs, classes, and functions. Note the prefixes like `Wasm`, `Func`, `Global`, etc., which hint at the purpose of the code.
2. **Establish the High-Level Goal:** Based on the file path and the code itself, recognize that this file likely implements the WebAssembly C API for V8.
3. **Categorize Functionality:** Group related code sections. For example, sections dealing with `Store`, `Engine`, and `Config` seem related to the environment setup. Sections with `Func`, `Global`, `Table`, and `Memory` likely deal with WebAssembly instances.
4. **Relate to JavaScript:** Consider how these C++ constructs are exposed and used within a JavaScript environment. Think about the `WebAssembly` global object in JavaScript and its properties like `WebAssembly.Module`, `WebAssembly.Instance`, etc.
5. **Provide JavaScript Examples:**  For key functionalities, create simple JavaScript code snippets demonstrating how the underlying C++ is used. Focus on the high-level API usage rather than low-level details.
6. **Address the "Part 1" aspect:** Acknowledge that this is only the first part and therefore the summary is incomplete.
这个C++源代码文件 `v8/src/wasm/c-api.cc` 的主要功能是**实现了 WebAssembly 的 C API**。它是 V8 引擎中用于支持 WebAssembly C API 的核心部分。

更具体地说，这个文件的第 1 部分主要负责以下功能：

1. **定义了 C API 的数据结构和类型**： 例如 `wasm_config_t`, `wasm_engine_t`, `wasm_store_t`, `wasm_functype_t`, `wasm_globaltype_t` 等，这些结构体在 C API 中用于表示配置、引擎、存储、函数类型、全局变量类型等概念。
2. **实现了运行时环境的管理**： 包括 `wasm_config_new()`, `wasm_engine_new()`, `wasm_store_new()` 等函数，用于创建和管理 WebAssembly 的运行时环境，例如配置、执行引擎和存储上下文。
3. **实现了基本类型（Value Types）的表示和操作**： 例如 `wasm_valtype_t` 以及其预定义实例 `wasm_valtype_i32()`, `wasm_valtype_f64()` 等，用于表示 WebAssembly 中的基本数据类型 (i32, i64, f32, f64, funcref, anyref)。
4. **实现了外部类型（Extern Types）的表示和操作**： 包括 `wasm_externtype_t` 以及其子类型如 `wasm_functype_t`, `wasm_globaltype_t`, `wasm_tabletype_t`, `wasm_memorytype_t` 的创建和管理，用于描述导入和导出的外部对象的类型。
5. **实现了导入和导出类型（Import/Export Types）的表示和操作**：  定义了 `wasm_importtype_t` 和 `wasm_exporttype_t` 用于描述 WebAssembly 模块的导入和导出信息。
6. **实现了引用（References）的管理**： 定义了 `wasm_ref_t` 作为所有 C API 对象的基类，并提供了 `wasm_ref_copy()`, `wasm_ref_same()`, `wasm_ref_get_host_info()`, `wasm_ref_set_host_info()` 等通用操作。
7. **实现了运行时对象（Runtime Objects）的部分功能**：
    * **帧 (Frame)**: 定义了 `wasm_frame_t` 以及获取帧信息的函数，用于支持错误追踪和调试。
    * **陷阱 (Trap)**: 定义了 `wasm_trap_t` 以及创建和获取陷阱信息的函数，用于表示 WebAssembly 执行期间发生的运行时错误。
    * **外部对象 (Foreign)**: 定义了 `wasm_foreign_t` 用于表示宿主环境提供的外部对象。
    * **模块 (Module)**: 定义了 `wasm_module_t` 以及加载、验证、编译、序列化和反序列化 WebAssembly 模块的函数，例如 `wasm_module_validate()`, `wasm_module_new()`, `wasm_module_imports()`, `wasm_module_exports()`, `wasm_module_serialize()`, `wasm_module_deserialize()`, `wasm_module_share()`, `wasm_module_obtain()`.
    * **外部值 (Extern)**: 定义了 `wasm_extern_t` 作为函数、全局变量、表格和内存的基类，并提供了获取外部对象类型的方法。
    * **函数实例 (Func)**: 定义了 `wasm_func_t` 以及创建函数实例（包括从宿主函数创建）和调用函数实例的函数，例如 `wasm_func_new()`, `wasm_func_call()`, `wasm_func_type()`.
    * **全局变量实例 (Global)**: 定义了 `wasm_global_t` 以及创建和访问全局变量实例的函数，例如 `wasm_global_new()`, `wasm_global_get()`, `wasm_global_set()`, `wasm_global_type()`.

**与 JavaScript 的关系及 JavaScript 示例：**

这个 C++ 文件实现的 C API 是 V8 引擎暴露给外部使用 WebAssembly 功能的一种方式。虽然 JavaScript 通常直接使用 `WebAssembly` 全局对象提供的 API，但 V8 内部使用这些 C API 来实现 JavaScript 的 WebAssembly 功能。

以下是一些概念在 JavaScript 中对应的示例，展示了 C API 功能在 JavaScript 中的体现：

* **`wasm_module_new()` (C API)  ->  `WebAssembly.Module()` (JavaScript)**

   ```javascript
   const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]); // WebAssembly 二进制代码
   const wasmModule = new WebAssembly.Module(wasmCode);
   ```
   `wasm_module_new()`  在 C++ 中负责编译 WebAssembly 二进制代码，对应 JavaScript 中 `WebAssembly.Module()` 的功能。

* **`wasm_instance_new()` (C API，在后续部分) -> `WebAssembly.Instance()` (JavaScript)**

   ```javascript
   const wasmInstance = new WebAssembly.Instance(wasmModule);
   ```
   尽管在提供的第一部分代码中没有 `wasm_instance_new()`, 但可以推断其功能是创建 WebAssembly 模块的实例，这对应 JavaScript 中的 `WebAssembly.Instance()`。

* **`wasm_func_new()` (C API) 用于创建宿主函数 -> JavaScript 中导入的函数**

   虽然 JavaScript 不会直接调用 `wasm_func_new()` 创建宿主函数，但通过 `WebAssembly.instantiate()` 导入的 JavaScript 函数在 V8 内部会被表示为 `wasm_func_t`。

   ```javascript
   const importObject = {
       env: {
           myHostFunction: (arg) => { console.log("From host:", arg); }
       }
   };
   const wasmInstance = await WebAssembly.instantiate(wasmModule, importObject);
   wasmInstance.exports.callHostFunction(10);
   ```
   在上面的例子中，`myHostFunction` 在 C++ 内部会被表示为一个 `wasm_func_t` 实例。

* **`wasm_func_call()` (C API) -> 调用导出的 WebAssembly 函数**

   ```javascript
   const result = wasmInstance.exports.exportedFunction(20, 30);
   ```
   当 JavaScript 调用 `wasmInstance.exports.exportedFunction()` 时，V8 内部会调用相应的 `wasm_func_call()` 来执行 WebAssembly 函数。

* **`wasm_global_new()` / `wasm_global_get()` / `wasm_global_set()` (C API) ->  `WebAssembly.Global` (JavaScript)**

   ```javascript
   const globalDescriptor = { value: "i32", mutable: true };
   const myGlobal = new WebAssembly.Global(globalDescriptor, 5);
   console.log(myGlobal.value);
   myGlobal.value = 15;
   ```
   JavaScript 中的 `WebAssembly.Global` 对象对应 C API 中的 `wasm_global_t`，JavaScript 对 `myGlobal.value` 的读取和设置操作，在 V8 内部会通过 `wasm_global_get()` 和 `wasm_global_set()` 实现。

总结来说，这个 C++ 文件是 V8 引擎实现 WebAssembly C API 的基础，它定义了核心的数据结构和操作，为 JavaScript 中使用的 `WebAssembly` API 提供了底层的支持。 理解这些 C API 的功能有助于深入理解 V8 引擎是如何执行 WebAssembly 代码的。

Prompt: 
```
这是目录为v8/src/wasm/c-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This implementation is originally from
// https://github.com/WebAssembly/wasm-c-api/:

// Copyright 2019 Andreas Rossberg
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "src/wasm/c-api.h"

#include <cstring>
#include <iomanip>
#include <iostream>

#include "include/libplatform/libplatform.h"
#include "include/v8-initialization.h"
#include "src/api/api-inl.h"
#include "src/builtins/builtins.h"
#include "src/compiler/wasm-compiler.h"
#include "src/flags/flags.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/managed-inl.h"
#include "src/wasm/leb-helper.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/signature-hashing.h"
#include "src/wasm/wasm-arguments.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-result.h"
#include "src/wasm/wasm-serialization.h"
#include "third_party/wasm-api/wasm.h"
#ifdef ENABLE_VTUNE_JIT_INTERFACE
#include "src/third_party/vtune/v8-vtune.h"
#endif

#ifdef WASM_API_DEBUG
#error "WASM_API_DEBUG is unsupported"
#endif

// If you want counters support (what --dump-counters does for the d8 shell),
// then set this to 1 (in here, or via -DDUMP_COUNTERS=1 compiler argument).
#define DUMP_COUNTERS 0

namespace wasm {

namespace {

// Multi-cage pointer compression mode related note.
// Wasm C-Api is allowed to be used from a thread that's not bound to any
// Isolate. As a result, in a multi-cage pointer compression mode it's not
// guaranteed that current pointer compression cage base value is initialized
// for current thread (see V8HeapCompressionScheme::base_) which makes it
// impossible to read compressed pointers from V8 heap objects.
// This scope ensures that the pointer compression base value is set according
// to respective Wasm C-Api object.
// For all other configurations this scope is a no-op.
using PtrComprCageAccessScope = i::PtrComprCageAccessScope;

auto ReadLebU64(const byte_t** pos) -> uint64_t {
  uint64_t n = 0;
  uint64_t shift = 0;
  byte_t b;
  do {
    b = **pos;
    (*pos)++;
    n += (b & 0x7f) << shift;
    shift += 7;
  } while ((b & 0x80) != 0);
  return n;
}

template <typename T, typename = std::enable_if_t<
                          std::is_same_v<T, i::wasm::ValueType> ||
                          std::is_same_v<T, i::wasm::CanonicalValueType>>>
ValKind V8ValueTypeToWasm(T v8_valtype) {
  switch (v8_valtype.kind()) {
    case i::wasm::kI32:
      return I32;
    case i::wasm::kI64:
      return I64;
    case i::wasm::kF32:
      return F32;
    case i::wasm::kF64:
      return F64;
    case i::wasm::kRef:
    case i::wasm::kRefNull:
      switch (v8_valtype.heap_representation()) {
        case i::wasm::HeapType::kFunc:
          return FUNCREF;
        case i::wasm::HeapType::kExtern:
          return ANYREF;
        default:
          UNREACHABLE();
      }
    default:
      UNREACHABLE();
  }
}

i::wasm::ValueType WasmValKindToV8(ValKind kind) {
  switch (kind) {
    case I32:
      return i::wasm::kWasmI32;
    case I64:
      return i::wasm::kWasmI64;
    case F32:
      return i::wasm::kWasmF32;
    case F64:
      return i::wasm::kWasmF64;
    case FUNCREF:
      return i::wasm::kWasmFuncRef;
    case ANYREF:
      return i::wasm::kWasmExternRef;
    default:
      // TODO(wasm+): support new value types
      UNREACHABLE();
  }
}

Name GetNameFromWireBytes(const i::wasm::WireBytesRef& ref,
                          v8::base::Vector<const uint8_t> wire_bytes) {
  DCHECK_LE(ref.offset(), wire_bytes.length());
  DCHECK_LE(ref.end_offset(), wire_bytes.length());
  if (ref.length() == 0) return Name::make();
  Name name = Name::make_uninitialized(ref.length());
  std::memcpy(name.get(), wire_bytes.begin() + ref.offset(), ref.length());
  return name;
}

own<FuncType> FunctionSigToFuncType(const i::wasm::FunctionSig* sig) {
  size_t param_count = sig->parameter_count();
  ownvec<ValType> params = ownvec<ValType>::make_uninitialized(param_count);
  for (size_t i = 0; i < param_count; i++) {
    params[i] = ValType::make(V8ValueTypeToWasm(sig->GetParam(i)));
  }
  size_t return_count = sig->return_count();
  ownvec<ValType> results = ownvec<ValType>::make_uninitialized(return_count);
  for (size_t i = 0; i < return_count; i++) {
    results[i] = ValType::make(V8ValueTypeToWasm(sig->GetReturn(i)));
  }
  return FuncType::make(std::move(params), std::move(results));
}

own<ExternType> GetImportExportType(const i::wasm::WasmModule* module,
                                    const i::wasm::ImportExportKindCode kind,
                                    const uint32_t index) {
  switch (kind) {
    case i::wasm::kExternalFunction: {
      return FunctionSigToFuncType(module->functions[index].sig);
    }
    case i::wasm::kExternalTable: {
      const i::wasm::WasmTable& table = module->tables[index];
      own<ValType> elem = ValType::make(V8ValueTypeToWasm(table.type));
      Limits limits(table.initial_size,
                    table.has_maximum_size
                        ? v8::base::checked_cast<int32_t>(table.maximum_size)
                        : -1);
      return TableType::make(std::move(elem), limits);
    }
    case i::wasm::kExternalMemory: {
      const i::wasm::WasmMemory& memory = module->memories[index];
      Limits limits(memory.initial_pages,
                    memory.has_maximum_pages
                        ? v8::base::checked_cast<int32_t>(memory.maximum_pages)
                        : -1);
      return MemoryType::make(limits);
    }
    case i::wasm::kExternalGlobal: {
      const i::wasm::WasmGlobal& global = module->globals[index];
      own<ValType> content = ValType::make(V8ValueTypeToWasm(global.type));
      Mutability mutability = global.mutability ? VAR : CONST;
      return GlobalType::make(std::move(content), mutability);
    }
    case i::wasm::kExternalTag:
      UNREACHABLE();
  }
}

}  // namespace

/// BEGIN FILE wasm-v8.cc

///////////////////////////////////////////////////////////////////////////////
// Auxiliaries

[[noreturn]] void WASM_UNIMPLEMENTED(const char* s) {
  std::cerr << "Wasm API: " << s << " not supported yet!\n";
  exit(1);
}

template <class T>
void ignore(T) {}

template <class C>
struct implement;

template <class C>
auto impl(C* x) -> typename implement<C>::type* {
  return reinterpret_cast<typename implement<C>::type*>(x);
}

template <class C>
auto impl(const C* x) -> const typename implement<C>::type* {
  return reinterpret_cast<const typename implement<C>::type*>(x);
}

template <class C>
auto seal(typename implement<C>::type* x) -> C* {
  return reinterpret_cast<C*>(x);
}

template <class C>
auto seal(const typename implement<C>::type* x) -> const C* {
  return reinterpret_cast<const C*>(x);
}

///////////////////////////////////////////////////////////////////////////////
// Runtime Environment

// Configuration

struct ConfigImpl {};

template <>
struct implement<Config> {
  using type = ConfigImpl;
};

Config::~Config() { impl(this)->~ConfigImpl(); }

void Config::operator delete(void* p) { ::operator delete(p); }

auto Config::make() -> own<Config> {
  return own<Config>(seal<Config>(new (std::nothrow) ConfigImpl()));
}

// Engine

#if DUMP_COUNTERS
class Counter {
 public:
  static const int kMaxNameSize = 64;
  int32_t* Bind(const char* name, bool is_histogram) {
    int i;
    for (i = 0; i < kMaxNameSize - 1 && name[i]; i++) {
      name_[i] = static_cast<char>(name[i]);
    }
    name_[i] = '\0';
    is_histogram_ = is_histogram;
    return ptr();
  }
  int32_t* ptr() { return &count_; }
  int32_t count() { return count_; }
  int32_t sample_total() { return sample_total_; }
  bool is_histogram() { return is_histogram_; }
  void AddSample(int32_t sample) {
    count_++;
    sample_total_ += sample;
  }

 private:
  int32_t count_;
  int32_t sample_total_;
  bool is_histogram_;
  uint8_t name_[kMaxNameSize];
};

class CounterCollection {
 public:
  CounterCollection() = default;
  Counter* GetNextCounter() {
    if (counters_in_use_ == kMaxCounters) return nullptr;
    return &counters_[counters_in_use_++];
  }

 private:
  static const unsigned kMaxCounters = 512;
  uint32_t counters_in_use_{0};
  Counter counters_[kMaxCounters];
};

using CounterMap = std::unordered_map<std::string, Counter*>;

#endif

struct EngineImpl {
  static bool created;

  std::unique_ptr<v8::Platform> platform;

#if DUMP_COUNTERS
  static CounterCollection counters_;
  static CounterMap* counter_map_;

  static Counter* GetCounter(const char* name, bool is_histogram) {
    auto map_entry = counter_map_->find(name);
    Counter* counter =
        map_entry != counter_map_->end() ? map_entry->second : nullptr;

    if (counter == nullptr) {
      counter = counters_.GetNextCounter();
      if (counter != nullptr) {
        (*counter_map_)[name] = counter;
        counter->Bind(name, is_histogram);
      }
    } else {
      DCHECK(counter->is_histogram() == is_histogram);
    }
    return counter;
  }

  static int* LookupCounter(const char* name) {
    Counter* counter = GetCounter(name, false);

    if (counter != nullptr) {
      return counter->ptr();
    } else {
      return nullptr;
    }
  }

  static void* CreateHistogram(const char* name, int min, int max,
                               size_t buckets) {
    return GetCounter(name, true);
  }

  static void AddHistogramSample(void* histogram, int sample) {
    Counter* counter = reinterpret_cast<Counter*>(histogram);
    counter->AddSample(sample);
  }
#endif

  EngineImpl() {
    assert(!created);
    created = true;
#if DUMP_COUNTERS
    counter_map_ = new CounterMap();
#endif
  }

  ~EngineImpl() {
#if DUMP_COUNTERS
    std::vector<std::pair<std::string, Counter*>> counters(
        counter_map_->begin(), counter_map_->end());
    std::sort(counters.begin(), counters.end());
    // Dump counters in formatted boxes.
    constexpr int kNameBoxSize = 64;
    constexpr int kValueBoxSize = 13;
    std::cout << "+" << std::string(kNameBoxSize, '-') << "+"
              << std::string(kValueBoxSize, '-') << "+\n";
    std::cout << "| Name" << std::string(kNameBoxSize - 5, ' ') << "| Value"
              << std::string(kValueBoxSize - 6, ' ') << "|\n";
    std::cout << "+" << std::string(kNameBoxSize, '-') << "+"
              << std::string(kValueBoxSize, '-') << "+\n";
    for (const auto& pair : counters) {
      std::string key = pair.first;
      Counter* counter = pair.second;
      if (counter->is_histogram()) {
        std::cout << "| c:" << std::setw(kNameBoxSize - 4) << std::left << key
                  << " | " << std::setw(kValueBoxSize - 2) << std::right
                  << counter->count() << " |\n";
        std::cout << "| t:" << std::setw(kNameBoxSize - 4) << std::left << key
                  << " | " << std::setw(kValueBoxSize - 2) << std::right
                  << counter->sample_total() << " |\n";
      } else {
        std::cout << "| " << std::setw(kNameBoxSize - 2) << std::left << key
                  << " | " << std::setw(kValueBoxSize - 2) << std::right
                  << counter->count() << " |\n";
      }
    }
    std::cout << "+" << std::string(kNameBoxSize, '-') << "+"
              << std::string(kValueBoxSize, '-') << "+\n";
    delete counter_map_;
#endif
    v8::V8::Dispose();
    v8::V8::DisposePlatform();
  }
};

bool EngineImpl::created = false;

#if DUMP_COUNTERS
CounterCollection EngineImpl::counters_;
CounterMap* EngineImpl::counter_map_;
#endif

template <>
struct implement<Engine> {
  using type = EngineImpl;
};

Engine::~Engine() { impl(this)->~EngineImpl(); }

void Engine::operator delete(void* p) { ::operator delete(p); }

auto Engine::make(own<Config>&& config) -> own<Engine> {
  auto engine = new (std::nothrow) EngineImpl;
  if (!engine) return own<Engine>();
  engine->platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(engine->platform.get());
  v8::V8::Initialize();

  if (i::v8_flags.prof) {
    i::PrintF(
        "--prof is currently unreliable for V8's Wasm-C-API due to "
        "fast-c-calls.\n");
  }

  return make_own(seal<Engine>(engine));
}

// This should be called somewhat regularly, especially on potentially hot
// sections of pure C++ execution. To achieve that, we call it on API entry
// points that heap-allocate but don't call into generated code.
// For example, finalization of incremental marking is relying on it.
void CheckAndHandleInterrupts(i::Isolate* isolate) {
  i::StackLimitCheck check(isolate);
  if (check.InterruptRequested()) {
    isolate->stack_guard()->HandleInterrupts();
  }
}

// Stores

StoreImpl::~StoreImpl() {
  {
    v8::Isolate::Scope isolate_scope(isolate_);
#ifdef DEBUG
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate_);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    i_isolate->heap()->PreciseCollectAllGarbage(
        i::GCFlag::kForced, i::GarbageCollectionReason::kTesting,
        v8::kNoGCCallbackFlags);
#endif
    context()->Exit();
  }
  isolate_->Dispose();
  delete create_params_.array_buffer_allocator;
}

struct ManagedData {
  static constexpr i::ExternalPointerTag kManagedTag = i::kWasmManagedDataTag;

  ManagedData(void* info, void (*finalizer)(void*))
      : info(info), finalizer(finalizer) {}

  ~ManagedData() {
    if (finalizer) (*finalizer)(info);
  }

  void* info;
  void (*finalizer)(void*);
};

void StoreImpl::SetHostInfo(i::Handle<i::Object> object, void* info,
                            void (*finalizer)(void*)) {
  v8::Isolate::Scope isolate_scope(isolate());
  i::HandleScope scope(i_isolate());
  // Ideally we would specify the total size kept alive by {info} here,
  // but all we get from the embedder is a {void*}, so our best estimate
  // is the size of the metadata.
  size_t estimated_size = sizeof(ManagedData);
  i::DirectHandle<i::Object> wrapper = i::Managed<ManagedData>::From(
      i_isolate(), estimated_size,
      std::make_shared<ManagedData>(info, finalizer));
  int32_t hash = i::Object::GetOrCreateHash(*object, i_isolate()).value();
  i::JSWeakCollection::Set(host_info_map_, object, wrapper, hash);
}

void* StoreImpl::GetHostInfo(i::Handle<i::Object> key) {
  PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate());
  i::Tagged<i::Object> raw =
      i::Cast<i::EphemeronHashTable>(host_info_map_->table())->Lookup(key);
  if (IsTheHole(raw, i_isolate())) return nullptr;
  return i::Cast<i::Managed<ManagedData>>(raw)->raw()->info;
}

template <>
struct implement<Store> {
  using type = StoreImpl;
};

Store::~Store() { impl(this)->~StoreImpl(); }

void Store::operator delete(void* p) { ::operator delete(p); }

auto Store::make(Engine*) -> own<Store> {
  auto store = make_own(new (std::nothrow) StoreImpl());
  if (!store) return own<Store>();

  // Create isolate.
  store->create_params_.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
#ifdef ENABLE_VTUNE_JIT_INTERFACE
  store->create_params_.code_event_handler = vTune::GetVtuneCodeEventHandler();
#endif
#if DUMP_COUNTERS
  store->create_params_.counter_lookup_callback = EngineImpl::LookupCounter;
  store->create_params_.create_histogram_callback = EngineImpl::CreateHistogram;
  store->create_params_.add_histogram_sample_callback =
      EngineImpl::AddHistogramSample;
#endif
  v8::Isolate* isolate = v8::Isolate::New(store->create_params_);
  if (!isolate) return own<Store>();
  store->isolate_ = isolate;
  isolate->SetData(0, store.get());
  // We intentionally do not call isolate->Enter() here, because that would
  // prevent embedders from using stores with overlapping but non-nested
  // lifetimes. The consequence is that Isolate::Current() is dysfunctional
  // and hence must not be called by anything reachable via this file.

  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);

    // Create context.
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    if (context.IsEmpty()) return own<Store>();
    context->Enter();  // The Exit() call is in ~StoreImpl.
    store->context_ = v8::Eternal<v8::Context>(isolate, context);

    // Create weak map for Refs with host info.
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
    store->host_info_map_ = i_isolate->global_handles()->Create(
        *i_isolate->factory()->NewJSWeakMap());
  }
  // We want stack traces for traps.
  constexpr int kStackLimit = 10;
  isolate->SetCaptureStackTraceForUncaughtExceptions(true, kStackLimit,
                                                     v8::StackTrace::kOverview);

  return make_own(seal<Store>(store.release()));
}

///////////////////////////////////////////////////////////////////////////////
// Type Representations

// Value Types

struct ValTypeImpl {
  ValKind kind;

  explicit ValTypeImpl(ValKind kind) : kind(kind) {}
};

template <>
struct implement<ValType> {
  using type = ValTypeImpl;
};

ValTypeImpl* valtype_i32 = new ValTypeImpl(I32);
ValTypeImpl* valtype_i64 = new ValTypeImpl(I64);
ValTypeImpl* valtype_f32 = new ValTypeImpl(F32);
ValTypeImpl* valtype_f64 = new ValTypeImpl(F64);
ValTypeImpl* valtype_externref = new ValTypeImpl(ANYREF);
ValTypeImpl* valtype_funcref = new ValTypeImpl(FUNCREF);

ValType::~ValType() = default;

void ValType::operator delete(void*) {}

own<ValType> ValType::make(ValKind k) {
  ValTypeImpl* valtype;
  switch (k) {
    case I32:
      valtype = valtype_i32;
      break;
    case I64:
      valtype = valtype_i64;
      break;
    case F32:
      valtype = valtype_f32;
      break;
    case F64:
      valtype = valtype_f64;
      break;
    case ANYREF:
      valtype = valtype_externref;
      break;
    case FUNCREF:
      valtype = valtype_funcref;
      break;
    default:
      // TODO(wasm+): support new value types
      UNREACHABLE();
  }
  return own<ValType>(seal<ValType>(valtype));
}

auto ValType::copy() const -> own<ValType> { return make(kind()); }

auto ValType::kind() const -> ValKind { return impl(this)->kind; }

// Extern Types

struct ExternTypeImpl {
  ExternKind kind;

  explicit ExternTypeImpl(ExternKind kind) : kind(kind) {}
  virtual ~ExternTypeImpl() = default;
};

template <>
struct implement<ExternType> {
  using type = ExternTypeImpl;
};

ExternType::~ExternType() { impl(this)->~ExternTypeImpl(); }

void ExternType::operator delete(void* p) { ::operator delete(p); }

auto ExternType::copy() const -> own<ExternType> {
  switch (kind()) {
    case EXTERN_FUNC:
      return func()->copy();
    case EXTERN_GLOBAL:
      return global()->copy();
    case EXTERN_TABLE:
      return table()->copy();
    case EXTERN_MEMORY:
      return memory()->copy();
  }
}

auto ExternType::kind() const -> ExternKind { return impl(this)->kind; }

// Function Types

struct FuncTypeImpl : ExternTypeImpl {
  ownvec<ValType> params;
  ownvec<ValType> results;

  FuncTypeImpl(ownvec<ValType>& params, ownvec<ValType>& results)
      : ExternTypeImpl(EXTERN_FUNC),
        params(std::move(params)),
        results(std::move(results)) {}
};

template <>
struct implement<FuncType> {
  using type = FuncTypeImpl;
};

FuncType::~FuncType() = default;

auto FuncType::make(ownvec<ValType>&& params, ownvec<ValType>&& results)
    -> own<FuncType> {
  return params && results
             ? own<FuncType>(seal<FuncType>(new (std::nothrow)
                                                FuncTypeImpl(params, results)))
             : own<FuncType>();
}

auto FuncType::copy() const -> own<FuncType> {
  return make(params().deep_copy(), results().deep_copy());
}

auto FuncType::params() const -> const ownvec<ValType>& {
  return impl(this)->params;
}

auto FuncType::results() const -> const ownvec<ValType>& {
  return impl(this)->results;
}

auto ExternType::func() -> FuncType* {
  return kind() == EXTERN_FUNC
             ? seal<FuncType>(static_cast<FuncTypeImpl*>(impl(this)))
             : nullptr;
}

auto ExternType::func() const -> const FuncType* {
  return kind() == EXTERN_FUNC
             ? seal<FuncType>(static_cast<const FuncTypeImpl*>(impl(this)))
             : nullptr;
}

// Global Types

struct GlobalTypeImpl : ExternTypeImpl {
  own<ValType> content;
  Mutability mutability;

  GlobalTypeImpl(own<ValType>& content, Mutability mutability)
      : ExternTypeImpl(EXTERN_GLOBAL),
        content(std::move(content)),
        mutability(mutability) {}

  ~GlobalTypeImpl() override = default;
};

template <>
struct implement<GlobalType> {
  using type = GlobalTypeImpl;
};

GlobalType::~GlobalType() = default;

auto GlobalType::make(own<ValType>&& content, Mutability mutability)
    -> own<GlobalType> {
  return content ? own<GlobalType>(seal<GlobalType>(
                       new (std::nothrow) GlobalTypeImpl(content, mutability)))
                 : own<GlobalType>();
}

auto GlobalType::copy() const -> own<GlobalType> {
  return make(content()->copy(), mutability());
}

auto GlobalType::content() const -> const ValType* {
  return impl(this)->content.get();
}

auto GlobalType::mutability() const -> Mutability {
  return impl(this)->mutability;
}

auto ExternType::global() -> GlobalType* {
  return kind() == EXTERN_GLOBAL
             ? seal<GlobalType>(static_cast<GlobalTypeImpl*>(impl(this)))
             : nullptr;
}

auto ExternType::global() const -> const GlobalType* {
  return kind() == EXTERN_GLOBAL
             ? seal<GlobalType>(static_cast<const GlobalTypeImpl*>(impl(this)))
             : nullptr;
}

// Table Types

struct TableTypeImpl : ExternTypeImpl {
  own<ValType> element;
  Limits limits;

  TableTypeImpl(own<ValType>& element, Limits limits)
      : ExternTypeImpl(EXTERN_TABLE),
        element(std::move(element)),
        limits(limits) {}

  ~TableTypeImpl() override = default;
};

template <>
struct implement<TableType> {
  using type = TableTypeImpl;
};

TableType::~TableType() = default;

auto TableType::make(own<ValType>&& element, Limits limits) -> own<TableType> {
  return element ? own<TableType>(seal<TableType>(
                       new (std::nothrow) TableTypeImpl(element, limits)))
                 : own<TableType>();
}

auto TableType::copy() const -> own<TableType> {
  return make(element()->copy(), limits());
}

auto TableType::element() const -> const ValType* {
  return impl(this)->element.get();
}

auto TableType::limits() const -> const Limits& { return impl(this)->limits; }

auto ExternType::table() -> TableType* {
  return kind() == EXTERN_TABLE
             ? seal<TableType>(static_cast<TableTypeImpl*>(impl(this)))
             : nullptr;
}

auto ExternType::table() const -> const TableType* {
  return kind() == EXTERN_TABLE
             ? seal<TableType>(static_cast<const TableTypeImpl*>(impl(this)))
             : nullptr;
}

// Memory Types

struct MemoryTypeImpl : ExternTypeImpl {
  Limits limits;

  explicit MemoryTypeImpl(Limits limits)
      : ExternTypeImpl(EXTERN_MEMORY), limits(limits) {}

  ~MemoryTypeImpl() override = default;
};

template <>
struct implement<MemoryType> {
  using type = MemoryTypeImpl;
};

MemoryType::~MemoryType() = default;

auto MemoryType::make(Limits limits) -> own<MemoryType> {
  return own<MemoryType>(
      seal<MemoryType>(new (std::nothrow) MemoryTypeImpl(limits)));
}

auto MemoryType::copy() const -> own<MemoryType> {
  return MemoryType::make(limits());
}

auto MemoryType::limits() const -> const Limits& { return impl(this)->limits; }

auto ExternType::memory() -> MemoryType* {
  return kind() == EXTERN_MEMORY
             ? seal<MemoryType>(static_cast<MemoryTypeImpl*>(impl(this)))
             : nullptr;
}

auto ExternType::memory() const -> const MemoryType* {
  return kind() == EXTERN_MEMORY
             ? seal<MemoryType>(static_cast<const MemoryTypeImpl*>(impl(this)))
             : nullptr;
}

// Import Types

struct ImportTypeImpl {
  Name module;
  Name name;
  own<ExternType> type;

  ImportTypeImpl(Name& module, Name& name, own<ExternType>& type)
      : module(std::move(module)),
        name(std::move(name)),
        type(std::move(type)) {}
};

template <>
struct implement<ImportType> {
  using type = ImportTypeImpl;
};

ImportType::~ImportType() { impl(this)->~ImportTypeImpl(); }

void ImportType::operator delete(void* p) { ::operator delete(p); }

auto ImportType::make(Name&& module, Name&& name, own<ExternType>&& type)
    -> own<ImportType> {
  return module && name && type
             ? own<ImportType>(seal<ImportType>(
                   new (std::nothrow) ImportTypeImpl(module, name, type)))
             : own<ImportType>();
}

auto ImportType::copy() const -> own<ImportType> {
  return make(module().copy(), name().copy(), type()->copy());
}

auto ImportType::module() const -> const Name& { return impl(this)->module; }

auto ImportType::name() const -> const Name& { return impl(this)->name; }

auto ImportType::type() const -> const ExternType* {
  return impl(this)->type.get();
}

// Export Types

struct ExportTypeImpl {
  Name name;
  own<ExternType> type;

  ExportTypeImpl(Name& name, own<ExternType>& type)
      : name(std::move(name)), type(std::move(type)) {}
};

template <>
struct implement<ExportType> {
  using type = ExportTypeImpl;
};

ExportType::~ExportType() { impl(this)->~ExportTypeImpl(); }

void ExportType::operator delete(void* p) { ::operator delete(p); }

auto ExportType::make(Name&& name, own<ExternType>&& type) -> own<ExportType> {
  return name && type ? own<ExportType>(seal<ExportType>(
                            new (std::nothrow) ExportTypeImpl(name, type)))
                      : own<ExportType>();
}

auto ExportType::copy() const -> own<ExportType> {
  return make(name().copy(), type()->copy());
}

auto ExportType::name() const -> const Name& { return impl(this)->name; }

auto ExportType::type() const -> const ExternType* {
  return impl(this)->type.get();
}

i::Handle<i::String> VecToString(i::Isolate* isolate,
                                 const vec<byte_t>& chars) {
  size_t length = chars.size();
  // Some, but not all, {chars} vectors we get here are null-terminated,
  // so let's be robust to that.
  if (length > 0 && chars[length - 1] == 0) length--;
  return isolate->factory()
      ->NewStringFromUtf8({chars.get(), length})
      .ToHandleChecked();
}

// References

template <class Ref, class JSType>
class RefImpl {
 public:
  static own<Ref> make(StoreImpl* store, i::Handle<JSType> obj) {
    RefImpl* self = new (std::nothrow) RefImpl();
    if (!self) return nullptr;
    self->store_ = store;
    v8::Isolate::Scope isolate_scope(store->isolate());
    self->val_ = store->i_isolate()->global_handles()->Create(*obj);
    return make_own(seal<Ref>(self));
  }

  ~RefImpl() { i::GlobalHandles::Destroy(location()); }

  own<Ref> copy() const {
    v8::Isolate::Scope isolate_scope(store()->isolate());
    return make(store(), v8_object());
  }

  StoreImpl* store() const { return store_; }

  i::Isolate* isolate() const { return store()->i_isolate(); }

  i::Handle<JSType> v8_object() const {
#ifdef DEBUG
    PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate());
#endif  // DEBUG
    return i::Cast<JSType>(val_);
  }

  void* get_host_info() const {
    v8::Isolate::Scope isolate_scope(store()->isolate());
    return store()->GetHostInfo(v8_object());
  }

  void set_host_info(void* info, void (*finalizer)(void*)) {
    v8::Isolate::Scope isolate_scope(store()->isolate());
    store()->SetHostInfo(v8_object(), info, finalizer);
  }

 private:
  RefImpl() = default;

  i::Address* location() const {
    return reinterpret_cast<i::Address*>(val_.address());
  }

  i::Handle<i::JSReceiver> val_;
  StoreImpl* store_;
};

template <>
struct implement<Ref> {
  using type = RefImpl<Ref, i::JSReceiver>;
};

Ref::~Ref() { delete impl(this); }

void Ref::operator delete(void* p) {}

auto Ref::copy() const -> own<Ref> { return impl(this)->copy(); }

auto Ref::same(const Ref* that) const -> bool {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::HandleScope handle_scope(isolate);
  return i::Object::SameValue(*impl(this)->v8_object(),
                              *impl(that)->v8_object());
}

auto Ref::get_host_info() const -> void* { return impl(this)->get_host_info(); }

void Ref::set_host_info(void* info, void (*finalizer)(void*)) {
  impl(this)->set_host_info(info, finalizer);
}

///////////////////////////////////////////////////////////////////////////////
// Runtime Objects

// Frames

namespace {

struct FrameImpl {
  FrameImpl(own<Instance>&& instance, uint32_t func_index, size_t func_offset,
            size_t module_offset)
      : instance(std::move(instance)),
        func_index(func_index),
        func_offset(func_offset),
        module_offset(module_offset) {}

  own<Instance> instance;
  uint32_t func_index;
  size_t func_offset;
  size_t module_offset;
};

}  // namespace

template <>
struct implement<Frame> {
  using type = FrameImpl;
};

Frame::~Frame() { impl(this)->~FrameImpl(); }

void Frame::operator delete(void* p) { ::operator delete(p); }

own<Frame> Frame::copy() const {
  auto self = impl(this);
  return own<Frame>(seal<Frame>(
      new (std::nothrow) FrameImpl(self->instance->copy(), self->func_index,
                                   self->func_offset, self->module_offset)));
}

Instance* Frame::instance() const { return impl(this)->instance.get(); }

uint32_t Frame::func_index() const { return impl(this)->func_index; }

size_t Frame::func_offset() const { return impl(this)->func_offset; }

size_t Frame::module_offset() const { return impl(this)->module_offset; }

// Traps

template <>
struct implement<Trap> {
  using type = RefImpl<Trap, i::JSReceiver>;
};

Trap::~Trap() = default;

auto Trap::copy() const -> own<Trap> { return impl(this)->copy(); }

auto Trap::make(Store* store_abs, const Message& message) -> own<Trap> {
  auto store = impl(store_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope handle_scope(isolate);
  i::DirectHandle<i::String> string = VecToString(isolate, message);
  i::Handle<i::JSObject> exception =
      isolate->factory()->NewError(isolate->error_function(), string);
  i::JSObject::AddProperty(isolate, exception,
                           isolate->factory()->wasm_uncatchable_symbol(),
                           isolate->factory()->true_value(), i::NONE);
  return implement<Trap>::type::make(store, exception);
}

auto Trap::message() const -> Message {
  auto isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::HandleScope handle_scope(isolate);

  i::DirectHandle<i::JSMessageObject> message =
      isolate->CreateMessage(impl(this)->v8_object(), nullptr);
  i::Handle<i::String> result = i::MessageHandler::GetMessage(isolate, message);
  result = i::String::Flatten(isolate, result);  // For performance.
  size_t length = 0;
  std::unique_ptr<char[]> utf8 = result->ToCString(&length);
  return vec<byte_t>::adopt(length, utf8.release());
}

namespace {

own<Instance> GetInstance(StoreImpl* store,
                          i::Handle<i::WasmInstanceObject> instance);

own<Frame> CreateFrameFromInternal(i::DirectHandle<i::FixedArray> frames,
                                   int index, i::Isolate* isolate,
                                   StoreImpl* store) {
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::DirectHandle<i::CallSiteInfo> frame(
      i::Cast<i::CallSiteInfo>(frames->get(index)), isolate);
  i::Handle<i::WasmInstanceObject> instance(frame->GetWasmInstance(), isolate);
  uint32_t func_index = frame->GetWasmFunctionIndex();
  size_t module_offset = i::CallSiteInfo::GetSourcePosition(frame);
  size_t func_offset = module_offset - i::wasm::GetWasmFunctionOffset(
                                           instance->module(), func_index);
  return own<Frame>(seal<Frame>(new (std::nothrow) FrameImpl(
      GetInstance(store, instance), func_index, func_offset, module_offset)));
}

}  // namespace

own<Frame> Trap::origin() const {
  i::Isolate* isolate = impl(this)->isolate();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(impl(this)->isolate());
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::HandleScope handle_scope(isolate);

  i::DirectHandle<i::FixedArray> frames =
      isolate->GetSimpleStackTrace(impl(this)->v8_object());
  if (frames->length() == 0) {
    return own<Frame>();
  }
  return CreateFrameFromInternal(frames, 0, isolate, impl(this)->store());
}

ownvec<Frame> Trap::trace() const {
  i::Isolate* isolate = impl(this)->isolate();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::HandleScope handle_scope(isolate);

  i::DirectHandle<i::FixedArray> frames =
      isolate->GetSimpleStackTrace(impl(this)->v8_object());
  int num_frames = frames->length();
  // {num_frames} can be 0; the code below can handle that case.
  ownvec<Frame> result = ownvec<Frame>::make_uninitialized(num_frames);
  for (int i = 0; i < num_frames; i++) {
    result[i] =
        CreateFrameFromInternal(frames, i, isolate, impl(this)->store());
  }
  return result;
}

// Foreign Objects

template <>
struct implement<Foreign> {
  using type = RefImpl<Foreign, i::JSReceiver>;
};

Foreign::~Foreign() = default;

auto Foreign::copy() const -> own<Foreign> { return impl(this)->copy(); }

auto Foreign::make(Store* store_abs) -> own<Foreign> {
  StoreImpl* store = impl(store_abs);
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::Isolate* isolate = store->i_isolate();
  i::HandleScope handle_scope(isolate);

  i::Handle<i::JSObject> obj =
      isolate->factory()->NewJSObject(isolate->object_function());
  return implement<Foreign>::type::make(store, obj);
}

// Modules

template <>
struct implement<Module> {
  using type = RefImpl<Module, i::WasmModuleObject>;
};

Module::~Module() = default;

auto Module::copy() const -> own<Module> { return impl(this)->copy(); }

auto Module::validate(Store* store_abs, const vec<byte_t>& binary) -> bool {
  i::wasm::ModuleWireBytes bytes(
      {reinterpret_cast<const uint8_t*>(binary.get()), binary.size()});
  i::Isolate* isolate = impl(store_abs)->i_isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::HandleScope scope(isolate);
  i::wasm::WasmEnabledFeatures features =
      i::wasm::WasmEnabledFeatures::FromIsolate(isolate);
  i::wasm::CompileTimeImports imports;
  return i::wasm::GetWasmEngine()->SyncValidate(isolate, features,
                                                std::move(imports), bytes);
}

auto Module::make(Store* store_abs, const vec<byte_t>& binary) -> own<Module> {
  StoreImpl* store = impl(store_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope scope(isolate);
  CheckAndHandleInterrupts(isolate);
  i::wasm::ModuleWireBytes bytes(
      {reinterpret_cast<const uint8_t*>(binary.get()), binary.size()});
  i::wasm::WasmEnabledFeatures features =
      i::wasm::WasmEnabledFeatures::FromIsolate(isolate);
  i::wasm::CompileTimeImports imports;
  i::wasm::ErrorThrower thrower(isolate, "ignored");
  i::Handle<i::WasmModuleObject> module;
  if (!i::wasm::GetWasmEngine()
           ->SyncCompile(isolate, features, std::move(imports), &thrower, bytes)
           .ToHandle(&module)) {
    thrower.Reset();  // The API provides no way to expose the error.
    return nullptr;
  }
  return implement<Module>::type::make(store, module);
}

auto Module::imports() const -> ownvec<ImportType> {
  const i::wasm::NativeModule* native_module =
      impl(this)->v8_object()->native_module();
  const i::wasm::WasmModule* module = native_module->module();
  const v8::base::Vector<const uint8_t> wire_bytes =
      native_module->wire_bytes();
  const std::vector<i::wasm::WasmImport>& import_table = module->import_table;
  size_t size = import_table.size();
  ownvec<ImportType> imports = ownvec<ImportType>::make_uninitialized(size);
  for (uint32_t i = 0; i < size; i++) {
    const i::wasm::WasmImport& imp = import_table[i];
    Name module_name = GetNameFromWireBytes(imp.module_name, wire_bytes);
    Name name = GetNameFromWireBytes(imp.field_name, wire_bytes);
    own<ExternType> type = GetImportExportType(module, imp.kind, imp.index);
    imports[i] = ImportType::make(std::move(module_name), std::move(name),
                                  std::move(type));
  }
  return imports;
}

ownvec<ExportType> ExportsImpl(
    i::DirectHandle<i::WasmModuleObject> module_obj) {
  const i::wasm::NativeModule* native_module = module_obj->native_module();
  const i::wasm::WasmModule* module = native_module->module();
  const v8::base::Vector<const uint8_t> wire_bytes =
      native_module->wire_bytes();
  const std::vector<i::wasm::WasmExport>& export_table = module->export_table;
  size_t size = export_table.size();
  ownvec<ExportType> exports = ownvec<ExportType>::make_uninitialized(size);
  for (uint32_t i = 0; i < size; i++) {
    const i::wasm::WasmExport& exp = export_table[i];
    Name name = GetNameFromWireBytes(exp.name, wire_bytes);
    own<ExternType> type = GetImportExportType(module, exp.kind, exp.index);
    exports[i] = ExportType::make(std::move(name), std::move(type));
  }
  return exports;
}

auto Module::exports() const -> ownvec<ExportType> {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  return ExportsImpl(impl(this)->v8_object());
}

// We tier up all functions to TurboFan, and then serialize all TurboFan code.
// If no TurboFan code existed before calling this function, then the call to
// {serialize} may take a long time.
auto Module::serialize() const -> vec<byte_t> {
  i::Isolate* isolate = impl(this)->isolate();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  i::wasm::NativeModule* native_module =
      impl(this)->v8_object()->native_module();
  native_module->compilation_state()->TierUpAllFunctions();
  v8::base::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();
  size_t binary_size = wire_bytes.size();
  i::wasm::WasmSerializer serializer(native_module);
  size_t serial_size = serializer.GetSerializedNativeModuleSize();
  size_t size_size = i::wasm::LEBHelper::sizeof_u64v(binary_size);
  vec<byte_t> buffer =
      vec<byte_t>::make_uninitialized(size_size + binary_size + serial_size);
  byte_t* ptr = buffer.get();
  i::wasm::LEBHelper::write_u64v(reinterpret_cast<uint8_t**>(&ptr),
                                 binary_size);
  std::memcpy(ptr, wire_bytes.begin(), binary_size);
  ptr += binary_size;
  if (!serializer.SerializeNativeModule(
          {reinterpret_cast<uint8_t*>(ptr), serial_size})) {
    // Serialization fails if no TurboFan code is present. This may happen
    // because the module does not have any functions, or because another thread
    // modifies the {NativeModule} concurrently. In this case, the serialized
    // module just contains the wire bytes.
    buffer = vec<byte_t>::make_uninitialized(size_size + binary_size);
    byte_t* ptr = buffer.get();
    i::wasm::LEBHelper::write_u64v(reinterpret_cast<uint8_t**>(&ptr),
                                   binary_size);
    std::memcpy(ptr, wire_bytes.begin(), binary_size);
  }
  return buffer;
}

auto Module::deserialize(Store* store_abs, const vec<byte_t>& serialized)
    -> own<Module> {
  StoreImpl* store = impl(store_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope handle_scope(isolate);
  const byte_t* ptr = serialized.get();
  uint64_t binary_size = ReadLebU64(&ptr);
  ptrdiff_t size_size = ptr - serialized.get();
  size_t serial_size = serialized.size() - size_size - binary_size;
  i::Handle<i::WasmModuleObject> module_obj;
  if (serial_size > 0) {
    size_t data_size = static_cast<size_t>(binary_size);
    i::wasm::CompileTimeImports compile_imports{};
    if (!i::wasm::DeserializeNativeModule(
             isolate,
             {reinterpret_cast<const uint8_t*>(ptr + data_size), serial_size},
             {reinterpret_cast<const uint8_t*>(ptr), data_size},
             compile_imports, {})
             .ToHandle(&module_obj)) {
      // We were given a serialized module, but failed to deserialize. Report
      // this as an error.
      return nullptr;
    }
  } else {
    // No serialized module was given. This is fine, just create a module from
    // scratch.
    vec<byte_t> binary = vec<byte_t>::make_uninitialized(binary_size);
    std::memcpy(binary.get(), ptr, binary_size);
    return make(store_abs, binary);
  }
  return implement<Module>::type::make(store, module_obj);
}

// TODO(v8): do better when V8 can do better.
template <>
struct implement<Shared<Module>> {
  using type = vec<byte_t>;
};

template <>
Shared<Module>::~Shared() {
  impl(this)->~vec();
}

template <>
void Shared<Module>::operator delete(void* p) {
  ::operator delete(p);
}

auto Module::share() const -> own<Shared<Module>> {
  auto shared = seal<Shared<Module>>(new vec<byte_t>(serialize()));
  return make_own(shared);
}

auto Module::obtain(Store* store, const Shared<Module>* shared) -> own<Module> {
  return Module::deserialize(store, *impl(shared));
}

// Externals

template <>
struct implement<Extern> {
  using type = RefImpl<Extern, i::JSReceiver>;
};

Extern::~Extern() = default;

auto Extern::copy() const -> own<Extern> { return impl(this)->copy(); }

auto Extern::kind() const -> ExternKind {
  i::Isolate* isolate = impl(this)->isolate();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));

  i::DirectHandle<i::JSReceiver> obj = impl(this)->v8_object();
  if (i::WasmExternalFunction::IsWasmExternalFunction(*obj)) {
    return wasm::EXTERN_FUNC;
  }
  if (IsWasmGlobalObject(*obj)) return wasm::EXTERN_GLOBAL;
  if (IsWasmTableObject(*obj)) return wasm::EXTERN_TABLE;
  if (IsWasmMemoryObject(*obj)) return wasm::EXTERN_MEMORY;
  UNREACHABLE();
}

auto Extern::type() const -> own<ExternType> {
  switch (kind()) {
    case EXTERN_FUNC:
      return func()->type();
    case EXTERN_GLOBAL:
      return global()->type();
    case EXTERN_TABLE:
      return table()->type();
    case EXTERN_MEMORY:
      return memory()->type();
  }
}

auto Extern::func() -> Func* {
  return kind() == EXTERN_FUNC ? static_cast<Func*>(this) : nullptr;
}

auto Extern::global() -> Global* {
  return kind() == EXTERN_GLOBAL ? static_cast<Global*>(this) : nullptr;
}

auto Extern::table() -> Table* {
  return kind() == EXTERN_TABLE ? static_cast<Table*>(this) : nullptr;
}

auto Extern::memory() -> Memory* {
  return kind() == EXTERN_MEMORY ? static_cast<Memory*>(this) : nullptr;
}

auto Extern::func() const -> const Func* {
  return kind() == EXTERN_FUNC ? static_cast<const Func*>(this) : nullptr;
}

auto Extern::global() const -> const Global* {
  return kind() == EXTERN_GLOBAL ? static_cast<const Global*>(this) : nullptr;
}

auto Extern::table() const -> const Table* {
  return kind() == EXTERN_TABLE ? static_cast<const Table*>(this) : nullptr;
}

auto Extern::memory() const -> const Memory* {
  return kind() == EXTERN_MEMORY ? static_cast<const Memory*>(this) : nullptr;
}

auto extern_to_v8(const Extern* ex) -> i::Handle<i::JSReceiver> {
  return impl(ex)->v8_object();
}

// Function Instances

template <>
struct implement<Func> {
  using type = RefImpl<Func, i::JSFunction>;
};

Func::~Func() = default;

auto Func::copy() const -> own<Func> { return impl(this)->copy(); }

struct FuncData {
  static constexpr i::ExternalPointerTag kManagedTag = i::kWasmFuncDataTag;

  Store* store;
  own<FuncType> type;
  enum Kind { kCallback, kCallbackWithEnv } kind;
  union {
    Func::callback callback;
    Func::callback_with_env callback_with_env;
  };
  void (*finalizer)(void*);
  void* env;

  FuncData(Store* store, const FuncType* type, Kind kind)
      : store(store),
        type(type->copy()),
        kind(kind),
        finalizer(nullptr),
        env(nullptr) {}

  ~FuncData() {
    if (finalizer) (*finalizer)(env);
  }

  static i::Address v8_callback(i::Address host_data_foreign, i::Address argv);
};

namespace {

class SignatureHelper : public i::AllStatic {
 public:
  static const i::wasm::CanonicalTypeIndex Canonicalize(FuncType* type) {
    std::vector<i::wasm::ValueType> types;
    types.reserve(type->results().size() + type->params().size());

    // TODO(jkummerow): Consider making vec<> range-based for-iterable.
    for (size_t i = 0; i < type->results().size(); i++) {
      types.push_back(WasmValKindToV8(type->results()[i]->kind()));
    }
    for (size_t i = 0; i < type->params().size(); i++) {
      types.push_back(WasmValKindToV8(type->params()[i]->kind()));
    }

    i::wasm::FunctionSig non_canonical_sig{type->results().size(),
                                           type->params().size(), types.data()};
    return i::wasm::GetTypeCanonicalizer()->AddRecursiveGroup(
        &non_canonical_sig);
  }

  static own<FuncType> FromV8Sig(const i::wasm::CanonicalSig* sig) {
    int result_arity = static_cast<int>(sig->return_count());
    int param_arity = static_cast<int>(sig->parameter_count());
    ownvec<ValType> results = ownvec<ValType>::make_uninitialized(result_arity);
    ownvec<ValType> params = ownvec<ValType>::make_uninitialized(param_arity);

    for (int i = 0; i < result_arity; ++i) {
      results[i] = ValType::make(V8ValueTypeToWasm(sig->GetReturn(i)));
    }
    for (int i = 0; i < param_arity; ++i) {
      params[i] = ValType::make(V8ValueTypeToWasm(sig->GetParam(i)));
    }
    return FuncType::make(std::move(params), std::move(results));
  }

  static const i::wasm::CanonicalSig* GetSig(
      i::DirectHandle<i::JSFunction> function) {
    return i::Cast<i::WasmCapiFunction>(*function)->sig();
  }

#if V8_ENABLE_SANDBOX
  // Wraps {FuncType} so it has the same interface as {v8::internal::Signature}.
  struct FuncTypeAdapter {
    const FuncType* type = nullptr;
    size_t parameter_count() const { return type->params().size(); }
    size_t return_count() const { return type->results().size(); }
    i::wasm::ValueType GetParam(size_t i) const {
      return WasmValKindToV8(type->params()[i]->kind());
    }
    i::wasm::ValueType GetReturn(size_t i) const {
      return WasmValKindToV8(type->results()[i]->kind());
    }
  };
  static uint64_t Hash(FuncType* type) {
    FuncTypeAdapter adapter{type};
    return i::wasm::SignatureHasher::Hash(&adapter);
  }
#endif
};

auto make_func(Store* store_abs, std::shared_ptr<FuncData> data) -> own<Func> {
  auto store = impl(store_abs);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope handle_scope(isolate);
  CheckAndHandleInterrupts(isolate);
  i::DirectHandle<i::Managed<FuncData>> embedder_data =
      i::Managed<FuncData>::From(isolate, sizeof(FuncData), data);
#if V8_ENABLE_SANDBOX
  uint64_t signature_hash = SignatureHelper::Hash(data->type.get());
#else
  uintptr_t signature_hash = 0;
#endif  // V8_ENABLE_SANDBOX
  i::wasm::CanonicalTypeIndex sig_index =
      SignatureHelper::Canonicalize(data->type.get());
  const i::wasm::CanonicalSig* sig =
      i::wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_index);
  i::Handle<i::WasmCapiFunction> function = i::WasmCapiFunction::New(
      isolate, reinterpret_cast<i::Address>(&FuncData::v8_callback),
      embedder_data, sig_index, sig, signature_hash);
  i::Cast<i::WasmImportData>(
      function->shared()->wasm_capi_function_data()->internal()->implicit_arg())
      ->set_callable(*function);
  auto func = implement<Func>::type::make(store, function);
  return func;
}

}  // namespace

auto Func::make(Store* store, const FuncType* type, Func::callback callback)
    -> own<Func> {
  auto data = std::make_shared<FuncData>(store, type, FuncData::kCallback);
  data->callback = callback;
  return make_func(store, data);
}

auto Func::make(Store* store, const FuncType* type, callback_with_env callback,
                void* env, void (*finalizer)(void*)) -> own<Func> {
  auto data =
      std::make_shared<FuncData>(store, type, FuncData::kCallbackWithEnv);
  data->callback_with_env = callback;
  data->env = env;
  data->finalizer = finalizer;
  return make_func(store, data);
}

auto Func::type() const -> own<FuncType> {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::DirectHandle<i::JSFunction> func = impl(this)->v8_object();
  if (i::WasmCapiFunction::IsWasmCapiFunction(*func)) {
    return SignatureHelper::FromV8Sig(SignatureHelper::GetSig(func));
  }
  DCHECK(i::WasmExportedFunction::IsWasmExportedFunction(*func));
  auto function = i::Cast<i::WasmExportedFunction>(func);
  auto data = function->shared()->wasm_exported_function_data();
  return FunctionSigToFuncType(
      data->instance_data()->module()->functions[data->function_index()].sig);
}

auto Func::param_arity() const -> size_t {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::DirectHandle<i::JSFunction> func = impl(this)->v8_object();
  if (i::WasmCapiFunction::IsWasmCapiFunction(*func)) {
    return SignatureHelper::GetSig(func)->parameter_count();
  }
  DCHECK(i::WasmExportedFunction::IsWasmExportedFunction(*func));
  auto function = i::Cast<i::WasmExportedFunction>(func);
  auto data = function->shared()->wasm_exported_function_data();
  const i::wasm::FunctionSig* sig =
      data->instance_data()->module()->functions[data->function_index()].sig;
  return sig->parameter_count();
}

auto Func::result_arity() const -> size_t {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::DirectHandle<i::JSFunction> func = impl(this)->v8_object();
  if (i::WasmCapiFunction::IsWasmCapiFunction(*func)) {
    return SignatureHelper::GetSig(func)->return_count();
  }
  DCHECK(i::WasmExportedFunction::IsWasmExportedFunction(*func));
  auto function = i::Cast<i::WasmExportedFunction>(func);
  auto data = function->shared()->wasm_exported_function_data();
  const i::wasm::FunctionSig* sig =
      data->instance_data()->module()->functions[data->function_index()].sig;
  return sig->return_count();
}

namespace {

own<Ref> V8RefValueToWasm(StoreImpl* store, i::Handle<i::Object> value) {
  if (IsNull(*value, store->i_isolate())) return nullptr;
  return implement<Ref>::type::make(store, i::Cast<i::JSReceiver>(value));
}

i::Handle<i::Object> WasmRefToV8(i::Isolate* isolate, const Ref* ref) {
  if (ref == nullptr) return i::ReadOnlyRoots(isolate).null_value_handle();
  return impl(ref)->v8_object();
}

void PrepareFunctionData(
    i::Isolate* isolate,
    i::DirectHandle<i::WasmExportedFunctionData> function_data,
    const i::wasm::CanonicalSig* sig) {
  // If the data is already populated, return immediately.
  // TODO(saelo): We need to use full pointer comparison here while not all Code
  // objects have migrated into trusted space.
  static_assert(!i::kAllCodeObjectsLiveInTrustedSpace);
  if (!function_data->c_wrapper_code(isolate).SafeEquals(
          *BUILTIN_CODE(isolate, Illegal))) {
    return;
  }
  // Compile wrapper code.
  i::DirectHandle<i::Code> wrapper_code =
      i::compiler::CompileCWasmEntry(isolate, sig);
  function_data->set_c_wrapper_code(*wrapper_code);
  // Compute packed args size.
  function_data->set_packed_args_size(
      i::wasm::CWasmArgumentsPacker::TotalSize(sig));
}

void PushArgs(const i::wasm::CanonicalSig* sig, const Val args[],
              i::wasm::CWasmArgumentsPacker* packer, StoreImpl* store) {
  for (size_t i = 0; i < sig->parameter_count(); i++) {
    i::wasm::CanonicalValueType type = sig->GetParam(i);
    switch (type.kind()) {
      case i::wasm::kI32:
        packer->Push(args[i].i32());
        break;
      case i::wasm::kI64:
        packer->Push(args[i].i64());
        break;
      case i::wasm::kF32:
        packer->Push(args[i].f32());
        break;
      case i::wasm::kF64:
        packer->Push(args[i].f64());
        break;
      case i::wasm::kRef:
      case i::wasm::kRefNull:
        // TODO(14034): Make sure this works for all heap types.
        packer->Push((*WasmRefToV8(store->i_isolate(), args[i].ref())).ptr());
        break;
      case i::wasm::kS128:
        // TODO(14034): Implement.
        UNIMPLEMENTED();
      case i::wasm::kRtt:
      case i::wasm::kI8:
      case i::wasm::kI16:
      case i::wasm::kF16:
      case i::wasm::kVoid:
      case i::wasm::kTop:
      case i::wasm::kBottom:
        UNREACHABLE();
    }
  }
}

void PopArgs(const i::wasm::CanonicalSig* sig, Val results[],
             i::wasm::CWasmArgumentsPacker* packer, StoreImpl* store) {
  packer->Reset();
  for (size_t i = 0; i < sig->return_count(); i++) {
    i::wasm::CanonicalValueType type = sig->GetReturn(i);
    switch (type.kind()) {
      case i::wasm::kI32:
        results[i] = Val(packer->Pop<int32_t>());
        break;
      case i::wasm::kI64:
        results[i] = Val(packer->Pop<int64_t>());
        break;
      case i::wasm::kF32:
        results[i] = Val(packer->Pop<float>());
        break;
      case i::wasm::kF64:
        results[i] = Val(packer->Pop<double>());
        break;
      case i::wasm::kRef:
      case i::wasm::kRefNull: {
        // TODO(14034): Make sure this works for all heap types.
        i::Address raw = packer->Pop<i::Address>();
        i::Handle<i::Object> obj(i::Tagged<i::Object>(raw), store->i_isolate());
        results[i] = Val(V8RefValueToWasm(store, obj));
        break;
      }
      case i::wasm::kS128:
        // TODO(14034): Implement.
        UNIMPLEMENTED();
      case i::wasm::kRtt:
      case i::wasm::kI8:
      case i::wasm::kI16:
      case i::wasm::kF16:
      case i::wasm::kVoid:
      case i::wasm::kTop:
      case i::wasm::kBottom:
        UNREACHABLE();
    }
  }
}

own<Trap> CallWasmCapiFunction(i::Tagged<i::WasmCapiFunctionData> data,
                               const Val args[], Val results[]) {
  FuncData* func_data =
      i::Cast<i::Managed<FuncData>>(data->embedder_data())->raw();
  if (func_data->kind == FuncData::kCallback) {
    return (func_data->callback)(args, results);
  }
  DCHECK(func_data->kind == FuncData::kCallbackWithEnv);
  return (func_data->callback_with_env)(func_data->env, args, results);
}

i::Handle<i::JSReceiver> GetProperException(
    i::Isolate* isolate, i::Handle<i::Object> maybe_exception) {
  if (IsJSReceiver(*maybe_exception)) {
    return i::Cast<i::JSReceiver>(maybe_exception);
  }
  if (v8::internal::IsTerminationException(*maybe_exception)) {
    i::DirectHandle<i::String> string =
        isolate->factory()->NewStringFromAsciiChecked("TerminationException");
    return isolate->factory()->NewError(isolate->error_function(), string);
  }
  i::MaybeHandle<i::String> maybe_string =
      i::Object::ToString(isolate, maybe_exception);
  i::Handle<i::String> string = isolate->factory()->empty_string();
  if (!maybe_string.ToHandle(&string)) {
    // If converting the {maybe_exception} to string threw another exception,
    // just give up and leave {string} as the empty string.
    isolate->clear_exception();
  }
  // {NewError} cannot fail when its input is a plain String, so we always
  // get an Error object here.
  return i::Cast<i::JSReceiver>(
      isolate->factory()->NewError(isolate->error_function(), string));
}

}  // namespace

auto Func::call(const Val args[], Val results[]) const -> own<Trap> {
  auto func = impl(this);
  auto store = func->store();
  auto isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope handle_scope(isolate);
  i::Tagged<i::Object> raw_function_data =
      func->v8_object()->shared()->GetTrustedData(isolate);

  // WasmCapiFunctions can be called directly.
  if (IsWasmCapiFunctionData(raw_function_data)) {
    return CallWasmCapiFunction(
        i::Cast<i::WasmCapiFunctionData>(raw_function_data), args, results);
  }

  SBXCHECK(IsWasmExportedFunctionData(raw_function_data));
  i::DirectHandle<i::WasmExportedFunctionData> function_data{
      i::Cast<i::WasmExportedFunctionData>(raw_function_data), isolate};
  i::DirectHandle<i::WasmTrustedInstanceData> instance_data{
      function_data->instance_data(), isolate};
  int function_index = function_data->function_index();
  const i::wasm::WasmModule* module = instance_data->module();
  // Caching {sig} would reduce overhead substantially.
  const i::wasm::CanonicalSig* sig =
      i::wasm::GetTypeCanonicalizer()->LookupFunctionSignature(
          module->canonical_sig_id(
              module->functions[function_index].sig_index));
  PrepareFunctionData(isolate, function_data, sig);
  i::DirectHandle<i::Code> wrapper_code(function_data->c_wrapper_code(isolate),
                                        isolate);
  i::WasmCodePointer call_target = function_data->internal()->call_target();

  i::wasm::CWasmArgumentsPacker packer(function_data->packed_args_size());
  PushArgs(sig, args, &packer, store);

  i::DirectHandle<i::Object> object_ref;
  if (function_index < static_cast<int>(module->num_imported_functions)) {
    object_ref =
        i::handle(instance_data->dispatch_table_for_imports()->implicit_arg(
                      function_index),
                  isolate);
    if (IsWasmImportData(*object_ref)) {
      i::Tagged<i::JSFunction> jsfunc = i::Cast<i::JSFunction>(
          i::Cast<i::WasmImportData>(*object_ref)->callable());
      i::Tagged<i::Object> data = jsfunc->shared()->GetTrustedData(isolate);
      if (IsWasmCapiFunctionData(data)) {
        return CallWasmCapiFunction(i::Cast<i::WasmCapiFunctionData>(data),
                                    args, results);
      }
      // TODO(jkummerow): Imported and then re-exported JavaScript functions
      // are not supported yet. If we support C-API + JavaScript, we'll need
      // to call those here.
      UNIMPLEMENTED();
    } else {
      // A WasmFunction from another module.
      DCHECK(IsWasmInstanceObject(*object_ref));
    }
  } else {
    // TODO(42204563): Avoid crashing if the instance object is not available.
    CHECK(instance_data->has_instance_object());
    object_ref = handle(instance_data->instance_object(), isolate);
  }

  i::Execution::CallWasm(isolate, wrapper_code, call_target, object_ref,
                         packer.argv());

  if (isolate->has_exception()) {
    i::Handle<i::Object> exception(isolate->exception(), isolate);
    isolate->clear_exception();
    return implement<Trap>::type::make(store,
                                       GetProperException(isolate, exception));
  }

  PopArgs(sig, results, &packer, store);
  return nullptr;
}

i::Address FuncData::v8_callback(i::Address host_data_foreign,
                                 i::Address argv) {
  FuncData* self =
      i::Cast<i::Managed<FuncData>>(i::Tagged<i::Object>(host_data_foreign))
          ->raw();
  StoreImpl* store = impl(self->store);
  i::Isolate* isolate = store->i_isolate();
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::HandleScope scope(isolate);

  isolate->set_context(*v8::Utils::OpenDirectHandle(*store->context()));

  const ownvec<ValType>& param_types = self->type->params();
  const ownvec<ValType>& result_types = self->type->results();

  int num_param_types = static_cast<int>(param_types.size());
  int num_result_types = static_cast<int>(result_types.size());

  std::unique_ptr<Val[]> params(new Val[num_param_types]);
  std::unique_ptr<Val[]> results(new Val[num_result_types]);
  i::Address p = argv;
  for (int i = 0; i < num_param_types; ++i) {
    switch (param_types[i]->kind()) {
      case I32:
        params[i] = Val(v8::base::ReadUnalignedValue<int32_t>(p));
        p += 4;
        break;
      case I64:
        params[i] = Val(v8::base::ReadUnalignedValue<int64_t>(p));
        p += 8;
        break;
      case F32:
        params[i] = Val(v8::base::ReadUnalignedValue<float32_t>(p));
        p += 4;
        break;
      case F64:
        params[i] = Val(v8::base::ReadUnalignedValue<float64_t>(p));
        p += 8;
        break;
      case ANYREF:
      case FUNCREF: {
        i::Address raw = v8::base::ReadUnalignedValue<i::Address>(p);
        p += sizeof(raw);
        i::Handle<i::Object> obj(i::Tagged<i::Object>(raw), isolate);
        params[i] = Val(V8RefValueToWasm(store, obj));
        break;
      }
    }
  }

  own<Trap> trap;
  if (self->kind == kCallbackWithEnv) {
    trap = self->callback_with_env(self->env, params.get(), results.get());
  } else {
    trap = self->callback(params.get(), results.get());
  }

  if (trap) {
    isolate->Throw(*impl(trap.get())->v8_object());
    i::Tagged<i::Object> ex = isolate->exception();
    isolate->clear_exception();
    return ex.ptr();
  }

  p = argv;
  for (int i = 0; i < num_result_types; ++i) {
    switch (result_types[i]->kind()) {
      case I32:
        v8::base::WriteUnalignedValue(p, results[i].i32());
        p += 4;
        break;
      case I64:
        v8::base::WriteUnalignedValue(p, results[i].i64());
        p += 8;
        break;
      case F32:
        v8::base::WriteUnalignedValue(p, results[i].f32());
        p += 4;
        break;
      case F64:
        v8::base::WriteUnalignedValue(p, results[i].f64());
        p += 8;
        break;
      case ANYREF:
      case FUNCREF: {
        v8::base::WriteUnalignedValue(
            p, (*WasmRefToV8(isolate, results[i].ref())).ptr());
        p += sizeof(i::Address);
        break;
      }
    }
  }
  return i::kNullAddress;
}

// Global Instances

template <>
struct implement<Global> {
  using type = RefImpl<Global, i::WasmGlobalObject>;
};

Global::~Global() = default;

auto Global::copy() const -> own<Global> { return impl(this)->copy(); }

auto Global::make(Store* store_abs, const GlobalType* type, const Val& val)
    -> own<Global> {
  StoreImpl* store = impl(store_abs);
  v8::Isolate::Scope isolate_scope(store->isolate());
  i::Isolate* isolate = store->i_isolate();
  i::HandleScope handle_scope(isolate);
  CheckAndHandleInterrupts(isolate);

  DCHECK_EQ(type->content()->kind(), val.kind());

  i::wasm::ValueType i_type = WasmValKindToV8(type->content()->kind());
  bool is_mutable = (type->mutability() == VAR);
  const int32_t offset = 0;
  i::Handle<i::WasmGlobalObject> obj =
      i::WasmGlobalObject::New(isolate, i::Handle<i::WasmTrustedInstanceData>(),
                               i::MaybeHandle<i::JSArrayBuffer>(),
                               i::MaybeHandle<i::FixedArray>(), i_type, offset,
                               is_mutable)
          .ToHandleChecked();

  auto global = implement<Global>::type::make(store, obj);
  assert(global);
  global->set(val);
  return global;
}

auto Global::type() const -> own<GlobalType> {
  i::DirectHandle<i::WasmGlobalObject> v8_global = impl(this)->v8_object();
  ValKind kind = V8ValueTypeToWasm(v8_global->type());
  Mutability mutability = v8_global->is_mutable() ? VAR : CONST;
  return GlobalType::make(ValType::make(kind), mutability);
}

auto Global::get() const -> Val {
  i::Isolate* isolate = impl(this)->isolate();
  v8::Isolate::Scope isolate_scope(reinterpret_cast<v8::Isolate*>(isolate));
  PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate);
  i::DirectHandle<i::WasmGlobalObject> v8_global = impl(this)->v8_object();
  switch (v8_global->type().kind()) {
    case i::wasm::kI32:
      return Val(v8_global->GetI32());
    case i::wasm::kI64:
      return Val(v8_global->GetI64());
    case i::wasm::kF32:
      return Val(v8_global->GetF32());
    case i::wasm::kF64:
      return Val(v8_global->GetF64());
    case i::wasm::kRef:
    case i::wasm::kRefNull: {
      // TODO(14034): Handle types other than funcref and externref if needed.
      StoreImpl* store = impl(this)->store();
      i::HandleScope scope(store->i_isolate());
      v8::Isolate::Scope isolate_scope(store->isolate());
      i::Handle<i::Object> result = v8_global->GetRef();
      if (IsWasmFuncR
"""


```
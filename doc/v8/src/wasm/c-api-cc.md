Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine and specifically located in `v8/src/wasm/c-api.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file is named `c-api.cc` and resides in the `wasm` directory. This strongly suggests it implements the C API for WebAssembly within V8.

2. **Examine the includes:** The included headers provide clues about the functionalities involved:
    * `src/wasm/c-api.h`:  The corresponding header file, confirming the C API implementation.
    * Standard C++ headers (`cstring`, `iomanip`, `iostream`): Basic utilities.
    * `include/libplatform/libplatform.h`, `include/v8-initialization.h`: V8's platform and initialization mechanisms.
    * `src/api/api-inl.h`: Internal V8 API.
    * `src/builtins/builtins.h`: V8's built-in functions.
    * `src/compiler/wasm-compiler.h`:  Wasm compilation within V8.
    * `src/flags/flags.h`: V8's command-line flags.
    * `src/objects/...`: Various V8 object representations.
    * `src/wasm/...`:  Other core Wasm components within V8.
    * `third_party/wasm-api/wasm.h`: The standard WebAssembly C API definition.

3. **Analyze the namespaces:** The code is within the `wasm` namespace and an anonymous namespace. This structure is typical for C++ code organization.

4. **Look for key data structures and functions:**  The code defines several structs and classes with names like `Config`, `Engine`, `Store`, `ValType`, `FuncType`, `Instance`, `Trap`, etc. These names directly correspond to concepts in the WebAssembly C API. This indicates that the file is providing concrete implementations for these abstract C API types.

5. **Identify core API elements and their V8 counterparts:**  Notice the naming conventions, often `*Impl` for the internal V8 implementation. For example, `StoreImpl` manages a V8 `Isolate` and `Context`.

6. **Recognize the "implement" pattern:** The `implement` template is a common C++ idiom to associate a C API type (like `Config`) with its internal implementation (`ConfigImpl`). The `impl()` and `seal()` functions facilitate this mapping.

7. **Infer functionality from specific implementations:**
    * **`Config` and `Engine`:** Manage the global environment for Wasm execution within V8, including platform initialization.
    * **`Store`:** Represents an isolated instance of the Wasm runtime, containing a V8 `Isolate` and `Context`. It manages garbage collection and host information associated with Wasm objects.
    * **Type representations (`ValType`, `FuncType`, etc.):**  Implement the type system of WebAssembly, mapping to V8's internal type representations.
    * **`Ref`:**  A generic reference to a V8 object, used as the basis for more specific Wasm object references.
    * **`Frame`:** Represents a stack frame in a Wasm execution, linking to the `Instance` and execution offsets.
    * **`Trap`:**  Represents a runtime error during Wasm execution, wrapping a V8 error object.

8. **Address specific questions in the prompt:**
    * **`.tq` extension:** The file ends in `.cc`, not `.tq`, so it's standard C++, not Torque.
    * **Relationship with JavaScript:** The code directly interacts with V8's JavaScript engine (e.g., creating `v8::Isolate`, `v8::Context`, `i::Handle` to JavaScript objects). This interaction is crucial for integrating Wasm with JavaScript.
    * **Code logic inference:** The code involves object creation and management, but complex logic isn't readily apparent in this snippet. The focus is on bridging the C API to V8's internal structures.
    * **Common programming errors:**  Without more specific code, it's hard to pinpoint common errors *within this file*. However, the C API interaction itself can lead to errors (e.g., incorrect type handling, memory management issues on the embedder side).

9. **Synthesize the summary:** Combine the above observations into a concise description of the file's role. Emphasize that it's the V8 implementation of the WebAssembly C API, providing the necessary abstractions and mappings to V8's internal Wasm execution environment.

10. **Structure the response:** Organize the information logically, starting with the main purpose and then detailing the key components and their functions. Address each point from the prompt.
```
这是目录为v8/src/wasm/c-api.cc的一个v8源代码， 请列举一下它的功能,
如果v8/src/wasm/c-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

基于你提供的代码片段（第 1 部分），我们可以归纳出 `v8/src/wasm/c-api.cc` 的主要功能是：

**核心功能：实现 WebAssembly C API 在 V8 中的绑定**

这个文件是 V8 引擎中用于实现 WebAssembly C API 的 C++ 源代码。它提供了允许外部程序（通常是用 C/C++ 编写）与 V8 引擎中运行的 WebAssembly 模块进行交互的接口。

**具体功能点（基于第 1 部分）：**

1. **类型定义和管理:**
   - 定义了与 WebAssembly C API 相对应的 C++ 结构体，例如 `ConfigImpl`, `EngineImpl`, `StoreImpl`, `ValTypeImpl`, `FuncTypeImpl` 等。这些结构体内部包含了 V8 引擎中用于表示这些概念的数据。
   - 提供了创建、复制和销毁这些类型实例的方法，例如 `Config::make()`, `Store::make()`, `ValType::make()`, `FuncType::make()` 等。
   - 定义了 WebAssembly 的值类型 (`ValType`)、函数类型 (`FuncType`)、全局变量类型 (`GlobalType`)、表类型 (`TableType`) 和内存类型 (`MemoryType`) 的内部表示。

2. **运行时环境管理:**
   - 实现了 `Config` 类型，用于配置 WebAssembly 运行时的环境（目前看来实现比较简单）。
   - 实现了 `Engine` 类型，代表 V8 引擎本身，负责初始化和清理 V8 平台。
   - 实现了 `Store` 类型，代表一个独立的 WebAssembly 运行时实例，它拥有一个 V8 `Isolate` 和 `Context`。`Store` 负责管理与之关联的 V8 资源，包括垃圾回收和存储与 Wasm 对象相关的宿主信息。

3. **宿主信息关联:**
   - `StoreImpl` 提供了 `SetHostInfo` 和 `GetHostInfo` 方法，允许将宿主语言（例如 C++）的数据与 WebAssembly 对象关联起来。这对于在宿主语言和 Wasm 之间传递和管理数据非常重要。

4. **与 V8 引擎的集成:**
   - 代码中大量使用了 V8 引擎的内部 API，例如 `v8::Isolate`, `v8::Context`, `v8::Handle`, `i::wasm::ValueType` 等，说明该文件是 V8 内部实现的一部分，负责将 C API 的概念映射到 V8 引擎的内部表示。

5. **引用管理:**
   - 实现了 `Ref` 类，作为对 V8 内部 JavaScript 对象的通用引用。更具体的 Wasm 对象引用（如 `Trap`）继承自 `Ref`。这有助于管理 Wasm 对象在 V8 堆上的生命周期。

6. **Trap (异常) 处理:**
   - 实现了 `Trap` 类型，用于表示 WebAssembly 运行时发生的错误。提供了创建 `Trap` 对象和获取错误消息的方法。

**关于你的问题：**

* **`.tq` 结尾:** 代码以 `.cc` 结尾，所以它是标准的 C++ 源代码，而不是 V8 Torque 源代码。
* **与 Javascript 的关系:**  `v8/src/wasm/c-api.cc` 承担着将 WebAssembly 集成到 V8 (JavaScript 引擎) 的关键角色。虽然这段代码本身是用 C++ 写的，但它使得 JavaScript 可以加载、编译和执行 WebAssembly 模块。

   **JavaScript 示例:**

   ```javascript
   // 假设我们已经通过 C API 创建了一个 Wasm 模块的实例，
   // 并将其暴露给 JavaScript 环境

   // 获取导出的函数
   const exportedFunction = wasmInstance.exports.myFunction;

   // 调用 Wasm 导出的函数
   const result = exportedFunction(10, 20);

   console.log(result);
   ```

   在这个例子中，`wasmInstance` 是一个 JavaScript 对象，它代表了通过 C API 加载和实例化的 WebAssembly 模块。`exports` 属性包含了 Wasm 模块导出的函数、全局变量、内存和表。`v8/src/wasm/c-api.cc` 中的代码负责将 Wasm 模块的导出项映射到可以在 JavaScript 中访问的属性。

* **代码逻辑推理:**  第 1 部分主要关注类型定义和基础设施的搭建，逻辑推理相对较少。例如，`V8ValueTypeToWasm` 和 `WasmValKindToV8` 函数负责 V8 内部值类型和 WebAssembly C API 值类型之间的转换。

   **假设输入与输出 (以 `V8ValueTypeToWasm` 为例):**

   **假设输入:** `i::wasm::ValueType` (V8 内部的 Wasm 值类型) 为 `i::wasm::kWasmI32`。
   **输出:** `ValKind` (WebAssembly C API 的值类型枚举) 为 `I32`。

* **用户常见的编程错误:**  在这个代码片段中，主要关注 V8 的内部实现。用户常见的编程错误通常发生在 **使用 WebAssembly C API 的外部程序中**，例如：
    * **内存管理错误:**  不正确地分配或释放 C API 对象，导致内存泄漏或野指针。例如，创建了一个 `wasm_module_t` 但忘记 `wasm_module_delete`。
    * **类型不匹配:**  在调用 Wasm 函数时传递了错误类型的参数。
    * **生命周期管理错误:**  在 Wasm 对象被销毁后尝试访问它。例如，在 `wasm_instance_delete` 后尝试调用其导出的函数。
    * **不正确的 API 调用顺序:**  例如，在 `wasm_module_instantiate` 之前尝试获取模块的导出项。

**总结 (针对第 1 部分):**

`v8/src/wasm/c-api.cc` 的第 1 部分主要负责定义 WebAssembly C API 在 V8 引擎中的基础类型和运行时环境管理机制。它建立了将外部 C/C++ 代码与 V8 内部 WebAssembly 执行环境连接起来的桥梁，并提供了管理 Wasm 模块生命周期和关联宿主信息的初步功能。

Prompt: 
```
这是目录为v8/src/wasm/c-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/c-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
      GetInstance(store, in
"""


```
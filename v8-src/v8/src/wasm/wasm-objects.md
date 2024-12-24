Response: The user wants a summary of the C++ source code file `v8/src/wasm/wasm-objects.cc`.
The request explicitly asks to identify the functionality of the code and to illustrate its relation to JavaScript with examples, if any.
This is the first part of the file.

Based on the included headers and the overall structure, this file appears to be responsible for defining and implementing the runtime objects used by the V8 JavaScript engine to represent WebAssembly constructs.

Here's a breakdown of the key areas and potential connections to JavaScript:

1. **WasmModuleObject**: Represents a compiled WebAssembly module. This object is created when JavaScript calls `WebAssembly.compile` or `WebAssembly.instantiate`. It holds the compiled code and metadata of the module.

2. **WasmTableObject**: Represents a WebAssembly table. JavaScript can interact with tables through the `WebAssembly.Table` API. This file handles the internal representation of the table, including its elements and how they are accessed. The `uses` field and the logic around `UpdateDispatchTables` suggest this object plays a crucial role in indirect calls within WebAssembly.

3. **WasmMemoryObject**: Represents a WebAssembly linear memory. JavaScript can interact with memory through the `WebAssembly.Memory` API. This code manages the underlying `ArrayBuffer` that backs the memory and handles growth operations. The `UseInInstance` function indicates how the memory object is associated with a specific instance.

4. **WasmGlobalObject**: Represents a WebAssembly global variable. JavaScript can access and modify globals through the `WebAssembly.Global` API. This object holds the value and mutability information of the global.

5. **WasmSuspendingObject**:  This seems related to asynchronous operations or suspensions within WebAssembly, potentially tied to future proposals.

6. **WasmTrustedInstanceData**: This appears to be a crucial internal object that holds sensitive information about a WebAssembly instance. The "Trusted" aspect suggests it's a security boundary. It manages things like dispatch tables (for indirect calls), memory, and globals. This object isn't directly exposed to JavaScript but is essential for the internal execution of WebAssembly.

7. **ImportedFunctionEntry**: This likely deals with how imported functions from JavaScript or other WebAssembly modules are handled. The `SetGenericWasmToJs` and `SetCompiledWasmToJs` methods suggest different ways of wrapping JavaScript functions for use within WebAssembly.

The presence of `#include` directives for various other WASM-related components (compiler, decoder, engine, etc.) reinforces that this file is a core part of the WebAssembly runtime within V8.

Let's formulate the summary, highlighting the connection to JavaScript.
这个C++源代码文件 `v8/src/wasm/wasm-objects.cc` 的主要功能是定义和实现了 V8 JavaScript 引擎中用于表示 WebAssembly (Wasm) 概念的各种 **运行时对象 (runtime objects)**。这些对象是 JavaScript 代码与底层 WebAssembly 执行环境交互的桥梁。

以下是这个文件定义的一些关键对象的及其功能的归纳：

* **`WasmModuleObject`**:  表示一个已编译的 WebAssembly 模块。它包含了模块的元数据，例如导出的函数、导入的函数、内存、表等信息，并持有一个指向编译后的原生模块 (`NativeModule`) 的指针。它还负责从模块的字节码中提取字符串信息。

* **`WasmTableObject`**: 表示 WebAssembly 中的一个表 (Table)。表是类型化的元素的数组，主要用于实现函数指针和外部引用。这个类负责创建、管理表的大小、设置和获取表中的元素，以及在表增长时更新相关的分发表格 (`dispatch tables`)。

* **`WasmMemoryObject`**: 表示 WebAssembly 中的线性内存 (Linear Memory)。它封装了用于存储 WebAssembly 实例内存的 `JSArrayBuffer`，并负责管理内存的增长。

* **`WasmGlobalObject`**: 表示 WebAssembly 中的全局变量 (Global Variable)。它存储全局变量的值和类型信息，并处理可变全局变量的读写操作。

* **`WasmSuspendingObject`**:  这个对象可能与 WebAssembly 的异步操作或挂起/恢复功能相关，它包装了一个可调用的 JavaScript 对象。

* **`WasmTrustedInstanceData`**:  这是一个关键的内部对象，存储了 WebAssembly 实例的受信任数据，例如分发表格、内存的起始地址和大小、全局变量的起始地址等。它不直接暴露给 JavaScript，但对于 WebAssembly 的安全和高效执行至关重要。

* **`ImportedFunctionEntry`**:  这个结构体用于表示从 JavaScript 或其他 Wasm 模块导入到当前 Wasm 模块的函数。它存储了导入函数的元数据和执行入口点。

**与 JavaScript 的关系及示例：**

这个文件中的对象直接对应于 JavaScript 中 `WebAssembly` API 提供的概念。当 JavaScript 代码使用 `WebAssembly` API 时，V8 引擎会在内部创建和管理这些 C++ 对象。

**1. `WasmModuleObject` 与 `WebAssembly.Module`:**

当 JavaScript 代码编译 WebAssembly 字节码时，会创建一个 `WebAssembly.Module` 实例。在 V8 内部，这对应着一个 `WasmModuleObject` 的创建。

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  // ... 模块的字节码 ...
]);
const wasmModule = new WebAssembly.Module(wasmCode);
```
在上述 JavaScript 代码执行时，V8 会解析 `wasmCode` 并创建一个 `WasmModuleObject` 来存储编译后的模块信息。

**2. `WasmTableObject` 与 `WebAssembly.Table`:**

JavaScript 可以创建和操作 WebAssembly 表。

```javascript
const table = new WebAssembly.Table({ initial: 2, element: 'funcref' });
```
这个 JavaScript 代码会在 V8 内部创建一个 `WasmTableObject`，其初始大小为 2，元素类型为 `funcref` (函数引用)。

**3. `WasmMemoryObject` 与 `WebAssembly.Memory`:**

JavaScript 可以创建和操作 WebAssembly 内存。

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
```
这个 JavaScript 代码会在 V8 内部创建一个 `WasmMemoryObject`，它管理着一个初始大小为 1 个内存页的 `ArrayBuffer`。

**4. `WasmGlobalObject` 与 `WebAssembly.Global`:**

JavaScript 可以创建和访问 WebAssembly 全局变量。

```javascript
const global = new WebAssembly.Global({ value: "i32", mutable: true }, 42);
```
这个 JavaScript 代码会在 V8 内部创建一个 `WasmGlobalObject`，表示一个可变的 32 位整型全局变量，其初始值为 42。

**5. 导入 JavaScript 函数到 WebAssembly (与 `ImportedFunctionEntry` 相关):**

当 WebAssembly 模块导入一个 JavaScript 函数时，`ImportedFunctionEntry` 用于管理这个导入的函数。

```javascript
// JavaScript 函数
function jsFunction(arg) {
  console.log("JavaScript function called with:", arg);
  return arg * 2;
}

const importObject = {
  env: {
    imported_func: jsFunction
  }
};

WebAssembly.instantiate(wasmModule, importObject)
  .then(instance => {
    instance.exports.exported_wasm_function(10); // 调用会触发 imported_func
  });
```
在这个例子中，当 WebAssembly 模块被实例化时，V8 会在 `WasmTrustedInstanceData` 中为 `imported_func` 创建一个 `ImportedFunctionEntry`，其中可能包含一个指向 JavaScript 函数 `jsFunction` 的包装器。  `SetGenericWasmToJs` 或 `SetCompiledWasmToJs` 等方法可能被用于创建这个包装器。

总而言之，`v8/src/wasm/wasm-objects.cc` 文件是 V8 引擎中 WebAssembly 功能的核心组成部分，它定义了 WebAssembly 运行时对象的 C++ 表示形式，使得 JavaScript 代码能够与 WebAssembly 模块及其内部结构进行交互。

Prompt: 
```
这是目录为v8/src/wasm/wasm-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-objects.h"

#include <optional>

#include "src/base/iterator.h"
#include "src/base/vector.h"
#include "src/builtins/builtins-inl.h"
#include "src/compiler/wasm-compiler.h"
#include "src/debug/debug.h"
#include "src/logging/counters.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/shared-function-info.h"
#include "src/roots/roots-inl.h"
#include "src/utils/utils.h"
#include "src/wasm/canonical-types.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/signature-hashing.h"
#include "src/wasm/stacks.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-code-pointer-table-inl.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-subtyping.h"
#include "src/wasm/wasm-value.h"

#if V8_ENABLE_DRUMBRAKE
#include "src/wasm/interpreter/wasm-interpreter-inl.h"
#include "src/wasm/interpreter/wasm-interpreter-runtime.h"
#endif  // V8_ENABLE_DRUMBRAKE

// Needs to be last so macros do not get undefined.
#include "src/objects/object-macros.h"

#define TRACE_IFT(...)              \
  do {                              \
    if (false) PrintF(__VA_ARGS__); \
  } while (false)

namespace v8 {
namespace internal {

// Import a few often used types from the wasm namespace.
using WasmFunction = wasm::WasmFunction;
using WasmModule = wasm::WasmModule;

namespace {

// The WasmTableObject::uses field holds pairs of <instance, index>. This enum
// helps compute the respective offset.
enum TableUses : int {
  kInstanceOffset,
  kIndexOffset,
  // Marker:
  kNumElements
};

}  // namespace

// static
Handle<WasmModuleObject> WasmModuleObject::New(
    Isolate* isolate, std::shared_ptr<wasm::NativeModule> native_module,
    DirectHandle<Script> script) {
  DirectHandle<Managed<wasm::NativeModule>> managed_native_module;
  if (script->type() == Script::Type::kWasm) {
    managed_native_module = direct_handle(
        Cast<Managed<wasm::NativeModule>>(script->wasm_managed_native_module()),
        isolate);
  } else {
    const WasmModule* module = native_module->module();
    size_t memory_estimate =
        native_module->committed_code_space() +
        wasm::WasmCodeManager::EstimateNativeModuleMetaDataSize(module);
    managed_native_module = Managed<wasm::NativeModule>::From(
        isolate, memory_estimate, std::move(native_module));
  }
  Handle<WasmModuleObject> module_object = Cast<WasmModuleObject>(
      isolate->factory()->NewJSObject(isolate->wasm_module_constructor()));
  module_object->set_managed_native_module(*managed_native_module);
  module_object->set_script(*script);
  return module_object;
}

Handle<String> WasmModuleObject::ExtractUtf8StringFromModuleBytes(
    Isolate* isolate, DirectHandle<WasmModuleObject> module_object,
    wasm::WireBytesRef ref, InternalizeString internalize) {
  base::Vector<const uint8_t> wire_bytes =
      module_object->native_module()->wire_bytes();
  return ExtractUtf8StringFromModuleBytes(isolate, wire_bytes, ref,
                                          internalize);
}

Handle<String> WasmModuleObject::ExtractUtf8StringFromModuleBytes(
    Isolate* isolate, base::Vector<const uint8_t> wire_bytes,
    wasm::WireBytesRef ref, InternalizeString internalize) {
  base::Vector<const uint8_t> name_vec =
      wire_bytes.SubVector(ref.offset(), ref.end_offset());
  // UTF8 validation happens at decode time.
  DCHECK(unibrow::Utf8::ValidateEncoding(name_vec.begin(), name_vec.length()));
  auto* factory = isolate->factory();
  return internalize
             ? factory->InternalizeUtf8String(
                   base::Vector<const char>::cast(name_vec))
             : factory
                   ->NewStringFromUtf8(base::Vector<const char>::cast(name_vec))
                   .ToHandleChecked();
}

MaybeHandle<String> WasmModuleObject::GetModuleNameOrNull(
    Isolate* isolate, DirectHandle<WasmModuleObject> module_object) {
  const WasmModule* module = module_object->module();
  if (!module->name.is_set()) return {};
  return ExtractUtf8StringFromModuleBytes(isolate, module_object, module->name,
                                          kNoInternalize);
}

MaybeHandle<String> WasmModuleObject::GetFunctionNameOrNull(
    Isolate* isolate, DirectHandle<WasmModuleObject> module_object,
    uint32_t func_index) {
  DCHECK_LT(func_index, module_object->module()->functions.size());
  wasm::WireBytesRef name =
      module_object->module()->lazily_generated_names.LookupFunctionName(
          wasm::ModuleWireBytes(module_object->native_module()->wire_bytes()),
          func_index);
  if (!name.is_set()) return {};
  return ExtractUtf8StringFromModuleBytes(isolate, module_object, name,
                                          kNoInternalize);
}

base::Vector<const uint8_t> WasmModuleObject::GetRawFunctionName(
    int func_index) {
  if (func_index == wasm::kAnonymousFuncIndex) {
    return base::Vector<const uint8_t>({nullptr, 0});
  }
  DCHECK_GT(module()->functions.size(), func_index);
  wasm::ModuleWireBytes wire_bytes(native_module()->wire_bytes());
  wasm::WireBytesRef name_ref =
      module()->lazily_generated_names.LookupFunctionName(wire_bytes,
                                                          func_index);
  wasm::WasmName name = wire_bytes.GetNameOrNull(name_ref);
  return base::Vector<const uint8_t>::cast(name);
}

Handle<WasmTableObject> WasmTableObject::New(
    Isolate* isolate, Handle<WasmTrustedInstanceData> trusted_data,
    wasm::ValueType type, uint32_t initial, bool has_maximum, uint64_t maximum,
    DirectHandle<Object> initial_value, wasm::AddressType address_type) {
  CHECK(type.is_object_reference());

  DCHECK_LE(initial, v8_flags.wasm_max_table_size);
  DirectHandle<FixedArray> entries = isolate->factory()->NewFixedArray(initial);
  for (int i = 0; i < static_cast<int>(initial); ++i) {
    entries->set(i, *initial_value);
  }

  DirectHandle<UnionOf<Undefined, Number, BigInt>> max =
      isolate->factory()->undefined_value();
  if (has_maximum) {
    if (address_type == wasm::AddressType::kI32) {
      DCHECK_GE(kMaxUInt32, maximum);
      max = isolate->factory()->NewNumber(maximum);
    } else {
      max = BigInt::FromUint64(isolate, maximum);
    }
  }

  Handle<JSFunction> table_ctor(
      isolate->native_context()->wasm_table_constructor(), isolate);
  auto table_obj =
      Cast<WasmTableObject>(isolate->factory()->NewJSObject(table_ctor));
  DisallowGarbageCollection no_gc;

  if (!trusted_data.is_null()) {
    table_obj->set_trusted_data(*trusted_data);
  } else {
    table_obj->clear_trusted_data();
  }
  table_obj->set_entries(*entries);
  table_obj->set_current_length(initial);
  table_obj->set_maximum_length(*max);
  table_obj->set_raw_type(static_cast<int>(type.raw_bit_field()));
  table_obj->set_address_type(address_type);
  table_obj->set_padding_for_address_type_0(0);
  table_obj->set_padding_for_address_type_1(0);
#if TAGGED_SIZE_8_BYTES
  table_obj->set_padding_for_address_type_2(0);
#endif

  table_obj->set_uses(ReadOnlyRoots(isolate).empty_fixed_array());
  return table_obj;
}

void WasmTableObject::AddUse(Isolate* isolate,
                             DirectHandle<WasmTableObject> table_obj,
                             Handle<WasmInstanceObject> instance_object,
                             int table_index) {
  DirectHandle<FixedArray> old_uses(table_obj->uses(), isolate);
  int old_length = old_uses->length();
  DCHECK_EQ(0, old_length % TableUses::kNumElements);

  if (instance_object.is_null()) return;
  // TODO(titzer): use weak cells here to avoid leaking instances.

  // Grow the uses table and add a new entry at the end.
  DirectHandle<FixedArray> new_uses = isolate->factory()->CopyFixedArrayAndGrow(
      old_uses, TableUses::kNumElements);

  new_uses->set(old_length + TableUses::kInstanceOffset, *instance_object);
  new_uses->set(old_length + TableUses::kIndexOffset,
                Smi::FromInt(table_index));

  table_obj->set_uses(*new_uses);
}

int WasmTableObject::Grow(Isolate* isolate, DirectHandle<WasmTableObject> table,
                          uint32_t count, DirectHandle<Object> init_value) {
  uint32_t old_size = table->current_length();
  if (count == 0) return old_size;  // Degenerate case: nothing to do.

  // Check if growing by {count} is valid.
  static_assert(wasm::kV8MaxWasmTableSize <= kMaxUInt32);
  uint64_t static_max_size = v8_flags.wasm_max_table_size;
  uint32_t max_size = static_cast<uint32_t>(std::min(
      static_max_size, table->maximum_length_u64().value_or(static_max_size)));
  DCHECK_LE(old_size, max_size);
  if (count > max_size - old_size) return -1;

  uint32_t new_size = old_size + count;
  // Even with 2x over-allocation, there should not be an integer overflow.
  static_assert(wasm::kV8MaxWasmTableSize <= kMaxInt / 2);
  DCHECK_GE(kMaxInt, new_size);
  int old_capacity = table->entries()->length();
  if (new_size > static_cast<uint32_t>(old_capacity)) {
    int grow = static_cast<int>(new_size) - old_capacity;
    // Grow at least by the old capacity, to implement exponential growing.
    grow = std::max(grow, old_capacity);
    // Never grow larger than the max size.
    grow = std::min(grow, static_cast<int>(max_size - old_capacity));
    auto new_store = isolate->factory()->CopyFixedArrayAndGrow(
        handle(table->entries(), isolate), grow);
    table->set_entries(*new_store, WriteBarrierMode::UPDATE_WRITE_BARRIER);
  }
  table->set_current_length(new_size);

  DirectHandle<FixedArray> uses(table->uses(), isolate);
  DCHECK_EQ(0, uses->length() % TableUses::kNumElements);
  // Tables are stored in the instance object, no code patching is
  // necessary. We simply have to grow the raw tables in each instance
  // that has imported this table.

  // TODO(titzer): replace the dispatch table with a weak list of all
  // the instances that import a given table.
  for (int i = 0; i < uses->length(); i += TableUses::kNumElements) {
    int table_index = Cast<Smi>(uses->get(i + TableUses::kIndexOffset)).value();

    DirectHandle<WasmTrustedInstanceData> non_shared_trusted_instance_data{
        Cast<WasmInstanceObject>(uses->get(i + TableUses::kInstanceOffset))
            ->trusted_data(isolate),
        isolate};

    bool is_shared =
        non_shared_trusted_instance_data->module()->tables[table_index].shared;

    DirectHandle<WasmTrustedInstanceData> trusted_instance_data =
        is_shared
            ? handle(non_shared_trusted_instance_data->shared_part(), isolate)
            : non_shared_trusted_instance_data;

    DCHECK_EQ(old_size,
              trusted_instance_data->dispatch_table(table_index)->length());
    WasmTrustedInstanceData::EnsureMinimumDispatchTableSize(
        isolate, trusted_instance_data, table_index, new_size);

#if V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_jitless &&
        trusted_instance_data->has_interpreter_object()) {
      wasm::WasmInterpreterRuntime::UpdateIndirectCallTable(
          isolate, handle(trusted_instance_data->instance_object(), isolate),
          table_index);
    }
#endif  // V8_ENABLE_DRUMBRAKE
  }

  for (uint32_t entry = old_size; entry < new_size; ++entry) {
    WasmTableObject::Set(isolate, table, entry, init_value);
  }
  return old_size;
}

MaybeHandle<Object> WasmTableObject::JSToWasmElement(
    Isolate* isolate, DirectHandle<WasmTableObject> table, Handle<Object> entry,
    const char** error_message) {
  const WasmModule* module = !table->has_trusted_data()
                                 ? nullptr
                                 : table->trusted_data(isolate)->module();
  return wasm::JSToWasmObject(isolate, module, entry, table->type(),
                              error_message);
}

void WasmTableObject::SetFunctionTableEntry(Isolate* isolate,
                                            DirectHandle<WasmTableObject> table,
                                            int entry_index,
                                            DirectHandle<Object> entry) {
  if (IsWasmNull(*entry, isolate)) {
    table->ClearDispatchTables(entry_index);  // Degenerate case.
    table->entries()->set(entry_index, ReadOnlyRoots(isolate).wasm_null());
    return;
  }
  DCHECK(IsWasmFuncRef(*entry));
  DirectHandle<Object> external = WasmInternalFunction::GetOrCreateExternal(
      direct_handle(Cast<WasmFuncRef>(*entry)->internal(isolate), isolate));

  if (WasmExportedFunction::IsWasmExportedFunction(*external)) {
    auto exported_function = Cast<WasmExportedFunction>(external);
    auto func_data = exported_function->shared()->wasm_exported_function_data();
    DirectHandle<WasmTrustedInstanceData> target_instance_data(
        func_data->instance_data(), isolate);
    int func_index = func_data->function_index();
    const WasmModule* module = target_instance_data->module();
    SBXCHECK_BOUNDS(func_index, module->functions.size());
    auto* wasm_function = module->functions.data() + func_index;
    UpdateDispatchTables(isolate, table, entry_index, wasm_function,
                         target_instance_data
#if V8_ENABLE_DRUMBRAKE
                         ,
                         func_index
#endif  // V8_ENABLE_DRUMBRAKE
    );
  } else if (WasmJSFunction::IsWasmJSFunction(*external)) {
    UpdateDispatchTables(isolate, table, entry_index,
                         Cast<WasmJSFunction>(external));
  } else {
    DCHECK(WasmCapiFunction::IsWasmCapiFunction(*external));
    UpdateDispatchTables(isolate, table, entry_index,
                         Cast<WasmCapiFunction>(external));
  }
  table->entries()->set(entry_index, *entry);
}

// Note: This needs to be handlified because it transitively calls
// {ImportWasmJSFunctionIntoTable} which calls {NewWasmImportData}.
void WasmTableObject::Set(Isolate* isolate, DirectHandle<WasmTableObject> table,
                          uint32_t index, DirectHandle<Object> entry) {
  // Callers need to perform bounds checks, type check, and error handling.
  DCHECK(table->is_in_bounds(index));

  DirectHandle<FixedArray> entries(table->entries(), isolate);
  // The FixedArray is addressed with int's.
  int entry_index = static_cast<int>(index);

  switch (table->type().heap_representation_non_shared()) {
    case wasm::HeapType::kExtern:
    case wasm::HeapType::kString:
    case wasm::HeapType::kStringViewWtf8:
    case wasm::HeapType::kStringViewWtf16:
    case wasm::HeapType::kStringViewIter:
    case wasm::HeapType::kEq:
    case wasm::HeapType::kStruct:
    case wasm::HeapType::kArray:
    case wasm::HeapType::kAny:
    case wasm::HeapType::kI31:
    case wasm::HeapType::kNone:
    case wasm::HeapType::kNoFunc:
    case wasm::HeapType::kNoExtern:
    case wasm::HeapType::kExn:
    case wasm::HeapType::kNoExn:
      entries->set(entry_index, *entry);
      return;
    case wasm::HeapType::kFunc:
      SetFunctionTableEntry(isolate, table, entry_index, entry);
      return;
    case wasm::HeapType::kBottom:
    case wasm::HeapType::kTop:
      UNREACHABLE();
    default:
      DCHECK(table->has_trusted_data());
      if (table->trusted_data(isolate)->module()->has_signature(
              table->type().ref_index())) {
        SetFunctionTableEntry(isolate, table, entry_index, entry);
        return;
      }
      entries->set(entry_index, *entry);
      return;
  }
}

Handle<Object> WasmTableObject::Get(Isolate* isolate,
                                    DirectHandle<WasmTableObject> table,
                                    uint32_t index) {
  DirectHandle<FixedArray> entries(table->entries(), isolate);
  // Callers need to perform bounds checks and error handling.
  DCHECK(table->is_in_bounds(index));

  // The FixedArray is addressed with int's.
  int entry_index = static_cast<int>(index);

  Handle<Object> entry(entries->get(entry_index), isolate);

  if (IsWasmNull(*entry, isolate)) return entry;
  if (IsWasmFuncRef(*entry)) return entry;

  switch (table->type().heap_representation_non_shared()) {
    case wasm::HeapType::kStringViewWtf8:
    case wasm::HeapType::kStringViewWtf16:
    case wasm::HeapType::kStringViewIter:
    case wasm::HeapType::kExtern:
    case wasm::HeapType::kString:
    case wasm::HeapType::kEq:
    case wasm::HeapType::kI31:
    case wasm::HeapType::kStruct:
    case wasm::HeapType::kArray:
    case wasm::HeapType::kAny:
    case wasm::HeapType::kNone:
    case wasm::HeapType::kNoFunc:
    case wasm::HeapType::kNoExtern:
    case wasm::HeapType::kExn:
    case wasm::HeapType::kNoExn:
      return entry;
    case wasm::HeapType::kFunc:
      // Placeholder; handled below.
      break;
    case wasm::HeapType::kBottom:
    case wasm::HeapType::kTop:
      UNREACHABLE();
    default:
      DCHECK(table->has_trusted_data());
      const WasmModule* module = table->trusted_data(isolate)->module();
      if (module->has_array(table->type().ref_index()) ||
          module->has_struct(table->type().ref_index())) {
        return entry;
      }
      DCHECK(module->has_signature(table->type().ref_index()));
      break;
  }

  // {entry} is not a valid entry in the table. It has to be a placeholder
  // for lazy initialization.
  DirectHandle<Tuple2> tuple = Cast<Tuple2>(entry);
  auto trusted_instance_data =
      handle(Cast<WasmInstanceObject>(tuple->value1())->trusted_data(isolate),
             isolate);
  int function_index = Cast<Smi>(tuple->value2()).value();

  // Create a WasmInternalFunction and WasmFuncRef for the function if it does
  // not exist yet, and store it in the table.
  Handle<WasmFuncRef> func_ref = WasmTrustedInstanceData::GetOrCreateFuncRef(
      isolate, trusted_instance_data, function_index);
  entries->set(entry_index, *func_ref);
  return func_ref;
}

void WasmTableObject::Fill(Isolate* isolate,
                           DirectHandle<WasmTableObject> table, uint32_t start,
                           DirectHandle<Object> entry, uint32_t count) {
  // Bounds checks must be done by the caller.
  DCHECK_LE(start, table->current_length());
  DCHECK_LE(count, table->current_length());
  DCHECK_LE(start + count, table->current_length());

  for (uint32_t i = 0; i < count; i++) {
    WasmTableObject::Set(isolate, table, start + i, entry);
  }
}

#if V8_ENABLE_SANDBOX || DEBUG
bool FunctionSigMatchesTable(wasm::CanonicalTypeIndex sig_id,
                             const WasmModule* module, int table_index) {
  wasm::ValueType table_type = module->tables[table_index].type;
  DCHECK(table_type.is_object_reference());
  // When in-sandbox data is corrupted, we can't trust the statically
  // checked types; to prevent sandbox escapes, we have to verify actual
  // types before installing the dispatch table entry. There are three
  // alternative success conditions:
  // (1) Generic "funcref" tables can hold any function entry.
  if (table_type.heap_representation_non_shared() == wasm::HeapType::kFunc) {
    return true;
  }
  // (2) Most function types are expected to be final, so they can be compared
  //     cheaply by canonicalized index equality.
  wasm::CanonicalTypeIndex canonical_table_type =
      module->canonical_sig_id(table_type.ref_index());
  if (V8_LIKELY(sig_id == canonical_table_type)) return true;
  // (3) In the remaining cases, perform the full subtype check.
  return wasm::GetWasmEngine()->type_canonicalizer()->IsCanonicalSubtype(
      sig_id, canonical_table_type);
}
#endif  // V8_ENABLE_SANDBOX || DEBUG

// static
void WasmTableObject::UpdateDispatchTables(
    Isolate* isolate, DirectHandle<WasmTableObject> table, int entry_index,
    const wasm::WasmFunction* func,
    DirectHandle<WasmTrustedInstanceData> target_instance_data
#if V8_ENABLE_DRUMBRAKE
    ,
    int target_func_index
#endif  // V8_ENABLE_DRUMBRAKE
) {
  // We simply need to update the IFTs for each instance that imports
  // this table.
  DirectHandle<FixedArray> uses(table->uses(), isolate);
  DCHECK_EQ(0, uses->length() % TableUses::kNumElements);

  DirectHandle<TrustedObject> implicit_arg =
      func->imported
          // The function in the target instance was imported. Use its imports
          // table to look up the ref.
          ? direct_handle(Cast<TrustedObject>(
                              target_instance_data->dispatch_table_for_imports()
                                  ->implicit_arg(func->func_index)),
                          isolate)
          // For wasm functions, just pass the target instance data.
          : target_instance_data;
  WasmCodePointer call_target =
      target_instance_data->GetCallTarget(func->func_index);

#if V8_ENABLE_DRUMBRAKE
  if (target_func_index <
      static_cast<int>(
          target_instance_data->module()->num_imported_functions)) {
    target_func_index = target_instance_data->imported_function_indices()->get(
        target_func_index);
  }
#endif  // V8_ENABLE_DRUMBRAKE

  const WasmModule* target_module = target_instance_data->module();
  wasm::CanonicalTypeIndex sig_id =
      target_module->canonical_sig_id(func->sig_index);
  IsAWrapper is_a_wrapper =
      func->imported ? IsAWrapper::kMaybe : IsAWrapper::kNo;

  for (int i = 0, len = uses->length(); i < len; i += TableUses::kNumElements) {
    int table_index = Cast<Smi>(uses->get(i + TableUses::kIndexOffset)).value();
    DirectHandle<WasmInstanceObject> instance_object(
        Cast<WasmInstanceObject>(uses->get(i + TableUses::kInstanceOffset)),
        isolate);
    if (v8_flags.wasm_generic_wrapper && IsWasmImportData(*implicit_arg)) {
      auto import_data = Cast<WasmImportData>(implicit_arg);
      DirectHandle<WasmImportData> new_import_data =
          isolate->factory()->NewWasmImportData(import_data);
      if (new_import_data->instance_data() ==
          instance_object->trusted_data(isolate)) {
        WasmImportData::SetIndexInTableAsCallOrigin(new_import_data,
                                                    entry_index);
      } else {
        WasmImportData::SetCrossInstanceTableIndexAsCallOrigin(
            isolate, new_import_data, instance_object, entry_index);
      }
      implicit_arg = new_import_data;
    }
    Tagged<WasmTrustedInstanceData> non_shared_instance_data =
        instance_object->trusted_data(isolate);
    bool is_shared = instance_object->module()->tables[table_index].shared;
    Tagged<WasmTrustedInstanceData> target_instance_data =
        is_shared ? non_shared_instance_data->shared_part()
                  : non_shared_instance_data;
#if !V8_ENABLE_DRUMBRAKE
    SBXCHECK(FunctionSigMatchesTable(sig_id, target_instance_data->module(),
                                     table_index));
    Tagged<WasmDispatchTable> table =
        target_instance_data->dispatch_table(table_index);
    table->Set(entry_index, *implicit_arg, call_target, sig_id, nullptr,
               is_a_wrapper, WasmDispatchTable::kExistingEntry);
#else   // !V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_jitless &&
        instance_object->trusted_data(isolate)->has_interpreter_object()) {
      Handle<WasmInstanceObject> instance_handle(*instance_object, isolate);
      wasm::WasmInterpreterRuntime::UpdateIndirectCallTable(
          isolate, instance_handle, table_index);
    }
    target_instance_data->dispatch_table(table_index)
        ->Set(entry_index, *implicit_arg, call_target, sig_id,
              target_func_index, nullptr, is_a_wrapper,
              WasmDispatchTable::kExistingEntry);
#endif  // !V8_ENABLE_DRUMBRAKE
  }
}

// static
void WasmTableObject::UpdateDispatchTables(
    Isolate* isolate, DirectHandle<WasmTableObject> table, int entry_index,
    DirectHandle<WasmJSFunction> function) {
  DirectHandle<FixedArray> uses(table->uses(), isolate);
  DCHECK_EQ(0, uses->length() % TableUses::kNumElements);

  // Update the dispatch table for each instance that imports this table.
  for (int i = 0; i < uses->length(); i += TableUses::kNumElements) {
    int table_index = Cast<Smi>(uses->get(i + TableUses::kIndexOffset)).value();
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
        Cast<WasmInstanceObject>(uses->get(i + TableUses::kInstanceOffset))
            ->trusted_data(isolate),
        isolate);
    WasmTrustedInstanceData::ImportWasmJSFunctionIntoTable(
        isolate, trusted_instance_data, table_index, entry_index, function);
  }
}

// static
void WasmTableObject::UpdateDispatchTables(
    Isolate* isolate, DirectHandle<WasmTableObject> table, int entry_index,
    DirectHandle<WasmCapiFunction> capi_function) {
  DirectHandle<FixedArray> uses(table->uses(), isolate);
  DCHECK_EQ(0, uses->length() % TableUses::kNumElements);

  DirectHandle<WasmCapiFunctionData> func_data(
      capi_function->shared()->wasm_capi_function_data(), isolate);
  const wasm::CanonicalSig* sig = func_data->sig();
  DCHECK(wasm::GetTypeCanonicalizer()->Contains(sig));
  wasm::CanonicalTypeIndex sig_index = func_data->sig_index();

  wasm::WasmCodeRefScope code_ref_scope;

  // Update the dispatch table for each instance that imports this table.
  for (int i = 0; i < uses->length(); i += TableUses::kNumElements) {
    int table_index = Cast<Smi>(uses->get(i + TableUses::kIndexOffset)).value();
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
        Cast<WasmInstanceObject>(uses->get(i + TableUses::kInstanceOffset))
            ->trusted_data(isolate),
        isolate);
    wasm::WasmImportWrapperCache* cache = wasm::GetWasmImportWrapperCache();
    auto kind = wasm::ImportCallKind::kWasmToCapi;
    int param_count = static_cast<int>(sig->parameter_count());
    wasm::WasmCode* wasm_code =
        cache->MaybeGet(kind, sig_index, param_count, wasm::kNoSuspend);
    if (wasm_code == nullptr) {
      wasm::WasmCompilationResult result =
          compiler::CompileWasmCapiCallWrapper(sig);
      {
        wasm::WasmImportWrapperCache::ModificationScope cache_scope(cache);
        wasm::WasmImportWrapperCache::CacheKey key(kind, sig_index, param_count,
                                                   wasm::kNoSuspend);
        wasm_code = cache_scope.AddWrapper(
            key, std::move(result), wasm::WasmCode::Kind::kWasmToCapiWrapper);
      }
      // To avoid lock order inversion, code printing must happen after the
      // end of the {cache_scope}.
      wasm_code->MaybePrint();
      isolate->counters()->wasm_generated_code_size()->Increment(
          wasm_code->instructions().length());
      isolate->counters()->wasm_reloc_size()->Increment(
          wasm_code->reloc_info().length());
    }
    Tagged<HeapObject> implicit_arg = func_data->internal()->implicit_arg();
    WasmCodePointer call_target = wasm_code->code_pointer();
    Tagged<WasmDispatchTable> table =
        trusted_instance_data->dispatch_table(table_index);
    table->Set(entry_index, implicit_arg, call_target, sig_index,
#if V8_ENABLE_DRUMBRAKE
               WasmDispatchTable::kInvalidFunctionIndex,
#endif  // V8_ENABLE_DRUMBRAKE
               wasm_code, IsAWrapper::kYes, WasmDispatchTable::kExistingEntry);
  }
}

void WasmTableObject::ClearDispatchTables(int index) {
  DisallowGarbageCollection no_gc;
  Isolate* isolate = GetIsolate();
  Tagged<FixedArray> uses = this->uses();
  DCHECK_EQ(0, uses->length() % TableUses::kNumElements);
  for (int i = 0, e = uses->length(); i < e; i += TableUses::kNumElements) {
    int table_index = Cast<Smi>(uses->get(i + TableUses::kIndexOffset)).value();
    Tagged<WasmInstanceObject> target_instance_object =
        Cast<WasmInstanceObject>(uses->get(i + TableUses::kInstanceOffset));
    Tagged<WasmTrustedInstanceData> non_shared_instance_data =
        target_instance_object->trusted_data(isolate);
    bool is_shared =
        target_instance_object->module()->tables[table_index].shared;
    Tagged<WasmTrustedInstanceData> target_instance_data =
        is_shared ? non_shared_instance_data->shared_part()
                  : non_shared_instance_data;
    Tagged<WasmDispatchTable> table =
        target_instance_data->dispatch_table(table_index);
    table->Clear(index, WasmDispatchTable::kExistingEntry);
#if V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_jitless &&
        non_shared_instance_data->has_interpreter_object()) {
      Handle<WasmInstanceObject> instance_handle(*target_instance_object,
                                                 isolate);
      wasm::WasmInterpreterRuntime::ClearIndirectCallCacheEntry(
          isolate, instance_handle, table_index, index);
    }
#endif  // V8_ENABLE_DRUMBRAKE
  }
}

// static
void WasmTableObject::SetFunctionTablePlaceholder(
    Isolate* isolate, DirectHandle<WasmTableObject> table, int entry_index,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int func_index) {
  // Put (instance, func_index) as a Tuple2 into the entry_index.
  // The {WasmExportedFunction} will be created lazily.
  // Allocate directly in old space as the tuples are typically long-lived, and
  // we create many of them, which would result in lots of GC when initializing
  // large tables.
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(trusted_instance_data->has_instance_object());
  DirectHandle<Tuple2> tuple = isolate->factory()->NewTuple2(
      handle(trusted_instance_data->instance_object(), isolate),
      handle(Smi::FromInt(func_index), isolate), AllocationType::kOld);
  table->entries()->set(entry_index, *tuple);
}

// static
void WasmTableObject::GetFunctionTableEntry(
    Isolate* isolate, DirectHandle<WasmTableObject> table, int entry_index,
    bool* is_valid, bool* is_null,
    MaybeHandle<WasmTrustedInstanceData>* instance_data, int* function_index,
    MaybeDirectHandle<WasmJSFunction>* maybe_js_function) {
  // A function table defined outside a module may only have type exactly
  // {funcref}.
  DCHECK(table->has_trusted_data()
             ? wasm::IsSubtypeOf(table->type(), wasm::kWasmFuncRef,
                                 table->trusted_data(isolate)->module())
             : (table->type() == wasm::kWasmFuncRef));
  DCHECK_LT(entry_index, table->current_length());
  // We initialize {is_valid} with {true}. We may change it later.
  *is_valid = true;
  DirectHandle<Object> element(table->entries()->get(entry_index), isolate);

  *is_null = IsWasmNull(*element, isolate);
  if (*is_null) return;

  if (IsWasmFuncRef(*element)) {
    DirectHandle<WasmInternalFunction> internal{
        Cast<WasmFuncRef>(*element)->internal(isolate), isolate};
    element = WasmInternalFunction::GetOrCreateExternal(internal);
  }
  if (WasmExportedFunction::IsWasmExportedFunction(*element)) {
    auto target_func = Cast<WasmExportedFunction>(element);
    auto func_data = Cast<WasmExportedFunctionData>(
        target_func->shared()->wasm_exported_function_data());
    *instance_data = handle(func_data->instance_data(), isolate);
    *function_index = func_data->function_index();
    *maybe_js_function = MaybeHandle<WasmJSFunction>();
    return;
  }
  if (WasmJSFunction::IsWasmJSFunction(*element)) {
    *instance_data = MaybeHandle<WasmTrustedInstanceData>();
    *maybe_js_function = Cast<WasmJSFunction>(element);
    return;
  }
  if (IsTuple2(*element)) {
    auto tuple = Cast<Tuple2>(element);
    *instance_data =
        handle(Cast<WasmInstanceObject>(tuple->value1())->trusted_data(isolate),
               isolate);
    *function_index = Cast<Smi>(tuple->value2()).value();
    *maybe_js_function = MaybeDirectHandle<WasmJSFunction>();
    return;
  }
  *is_valid = false;
}

Handle<WasmSuspendingObject> WasmSuspendingObject::New(
    Isolate* isolate, DirectHandle<JSReceiver> callable) {
  Handle<JSFunction> suspending_ctor(
      isolate->native_context()->wasm_suspending_constructor(), isolate);
  auto suspending_obj = Cast<WasmSuspendingObject>(
      isolate->factory()->NewJSObject(suspending_ctor));
  suspending_obj->set_callable(*callable);
  return suspending_obj;
}

namespace {

void SetInstanceMemory(Tagged<WasmTrustedInstanceData> trusted_instance_data,
                       Tagged<JSArrayBuffer> buffer, int memory_index) {
  DisallowHeapAllocation no_gc;
  const WasmModule* module = trusted_instance_data->module();
  const wasm::WasmMemory& memory = module->memories[memory_index];

  bool is_wasm_module = module->origin == wasm::kWasmOrigin;
  bool use_trap_handler = memory.bounds_checks == wasm::kTrapHandler;
  // Asm.js does not use trap handling.
  CHECK_IMPLIES(use_trap_handler, is_wasm_module);
  // ArrayBuffers allocated for Wasm do always have a BackingStore.
  std::shared_ptr<BackingStore> backing_store = buffer->GetBackingStore();
  CHECK_IMPLIES(is_wasm_module, backing_store);
  CHECK_IMPLIES(is_wasm_module, backing_store->is_wasm_memory());
  // Wasm modules compiled to use the trap handler don't have bounds checks,
  // so they must have a memory that has guard regions.
  // Note: This CHECK can fail when in-sandbox corruption modified a
  // WasmMemoryObject. We currently believe that this would at worst
  // corrupt the contents of other Wasm memories or ArrayBuffers, but having
  // this CHECK in release mode is nice as an additional layer of defense.
  CHECK_IMPLIES(use_trap_handler, backing_store->has_guard_regions());
  // We checked this before, but a malicious worker thread with an in-sandbox
  // corruption primitive could have modified it since then.
  size_t byte_length = buffer->byte_length();
  SBXCHECK_GE(byte_length, memory.min_memory_size);

  trusted_instance_data->SetRawMemory(
      memory_index, reinterpret_cast<uint8_t*>(buffer->backing_store()),
      byte_length);

#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless &&
      trusted_instance_data->has_interpreter_object()) {
    AllowHeapAllocation allow_heap;
    Isolate* isolate = trusted_instance_data->instance_object()->GetIsolate();
    HandleScope scope(isolate);
    wasm::WasmInterpreterRuntime::UpdateMemoryAddress(
        handle(trusted_instance_data->instance_object(), isolate));
  }
#endif  // V8_ENABLE_DRUMBRAKE
}

}  // namespace

Handle<WasmMemoryObject> WasmMemoryObject::New(Isolate* isolate,
                                               Handle<JSArrayBuffer> buffer,
                                               int maximum,
                                               wasm::AddressType address_type) {
  Handle<JSFunction> memory_ctor(
      isolate->native_context()->wasm_memory_constructor(), isolate);

  auto memory_object = Cast<WasmMemoryObject>(
      isolate->factory()->NewJSObject(memory_ctor, AllocationType::kOld));
  memory_object->set_array_buffer(*buffer);
  memory_object->set_maximum_pages(maximum);
  memory_object->set_address_type(address_type);
  memory_object->set_padding_for_address_type_0(0);
  memory_object->set_padding_for_address_type_1(0);
#if TAGGED_SIZE_8_BYTES
  memory_object->set_padding_for_address_type_2(0);
#endif
  memory_object->set_instances(ReadOnlyRoots{isolate}.empty_weak_array_list());

  std::shared_ptr<BackingStore> backing_store = buffer->GetBackingStore();
  if (buffer->is_shared()) {
    // Only Wasm memory can be shared (in contrast to asm.js memory).
    CHECK(backing_store && backing_store->is_wasm_memory());
    backing_store->AttachSharedWasmMemoryObject(isolate, memory_object);
  } else if (backing_store) {
    CHECK(!backing_store->is_shared());
  }

  // For debugging purposes we memorize a link from the JSArrayBuffer
  // to its owning WasmMemoryObject instance.
  Handle<Symbol> symbol = isolate->factory()->array_buffer_wasm_memory_symbol();
  Object::SetProperty(isolate, buffer, symbol, memory_object).Check();

  return memory_object;
}

MaybeHandle<WasmMemoryObject> WasmMemoryObject::New(
    Isolate* isolate, int initial, int maximum, SharedFlag shared,
    wasm::AddressType address_type) {
  bool has_maximum = maximum != kNoMaximum;

  int engine_maximum = address_type == wasm::AddressType::kI64
                           ? static_cast<int>(wasm::max_mem64_pages())
                           : static_cast<int>(wasm::max_mem32_pages());

  if (initial > engine_maximum) return {};

#ifdef V8_TARGET_ARCH_32_BIT
  // On 32-bit platforms we need an heuristic here to balance overall memory
  // and address space consumption.
  constexpr int kGBPages = 1024 * 1024 * 1024 / wasm::kWasmPageSize;
  // We allocate the smallest of the following sizes, but at least the initial
  // size:
  // 1) the module-defined maximum;
  // 2) 1GB;
  // 3) the engine maximum;
  int allocation_maximum = std::min(kGBPages, engine_maximum);
  int heuristic_maximum;
  if (initial > kGBPages) {
    // We always allocate at least the initial size.
    heuristic_maximum = initial;
  } else if (has_maximum) {
    // We try to reserve the maximum, but at most the allocation_maximum to
    // avoid OOMs.
    heuristic_maximum = std::min(maximum, allocation_maximum);
  } else if (shared == SharedFlag::kShared) {
    // If shared memory has no maximum, we use the allocation_maximum as an
    // implicit maximum.
    heuristic_maximum = allocation_maximum;
  } else {
    // If non-shared memory has no maximum, we only allocate the initial size
    // and then grow with realloc.
    heuristic_maximum = initial;
  }
#else
  int heuristic_maximum =
      has_maximum ? std::min(engine_maximum, maximum) : engine_maximum;
#endif

  std::unique_ptr<BackingStore> backing_store =
      BackingStore::AllocateWasmMemory(isolate, initial, heuristic_maximum,
                                       address_type == wasm::AddressType::kI32
                                           ? WasmMemoryFlag::kWasmMemory32
                                           : WasmMemoryFlag::kWasmMemory64,
                                       shared);

  if (!backing_store) return {};

  Handle<JSArrayBuffer> buffer =
      shared == SharedFlag::kShared
          ? isolate->factory()->NewJSSharedArrayBuffer(std::move(backing_store))
          : isolate->factory()->NewJSArrayBuffer(std::move(backing_store));

  return New(isolate, buffer, maximum, address_type);
}

void WasmMemoryObject::UseInInstance(
    Isolate* isolate, DirectHandle<WasmMemoryObject> memory,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
    int memory_index_in_instance) {
  SetInstanceMemory(*trusted_instance_data, memory->array_buffer(),
                    memory_index_in_instance);
  if (!shared_trusted_instance_data.is_null()) {
    SetInstanceMemory(*shared_trusted_instance_data, memory->array_buffer(),
                      memory_index_in_instance);
  }
  Handle<WeakArrayList> instances{memory->instances(), isolate};
  auto weak_instance_object = MaybeObjectDirectHandle::Weak(
      trusted_instance_data->instance_object(), isolate);
  instances = WeakArrayList::Append(isolate, instances, weak_instance_object);
  memory->set_instances(*instances);
}

void WasmMemoryObject::SetNewBuffer(Tagged<JSArrayBuffer> new_buffer) {
  DisallowGarbageCollection no_gc;
  set_array_buffer(new_buffer);
  Tagged<WeakArrayList> instances = this->instances();
  Isolate* isolate = GetIsolate();
  for (int i = 0, len = instances->length(); i < len; ++i) {
    Tagged<MaybeObject> elem = instances->Get(i);
    if (elem.IsCleared()) continue;
    Tagged<WasmInstanceObject> instance_object =
        Cast<WasmInstanceObject>(elem.GetHeapObjectAssumeWeak());
    Tagged<WasmTrustedInstanceData> trusted_data =
        instance_object->trusted_data(isolate);
    // TODO(clemens): Avoid the iteration by also remembering the memory index
    // if we ever see larger numbers of memories.
    Tagged<FixedArray> memory_objects = trusted_data->memory_objects();
    int num_memories = memory_objects->length();
    for (int mem_idx = 0; mem_idx < num_memories; ++mem_idx) {
      if (memory_objects->get(mem_idx) == *this) {
        SetInstanceMemory(trusted_data, new_buffer, mem_idx);
      }
    }
  }
}

// static
int32_t WasmMemoryObject::Grow(Isolate* isolate,
                               Handle<WasmMemoryObject> memory_object,
                               uint32_t pages) {
  TRACE_EVENT0("v8.wasm", "wasm.GrowMemory");
  DirectHandle<JSArrayBuffer> old_buffer(memory_object->array_buffer(),
                                         isolate);

  std::shared_ptr<BackingStore> backing_store = old_buffer->GetBackingStore();
  // Only Wasm memory can grow, and Wasm memory always has a backing store.
  DCHECK_NOT_NULL(backing_store);

  // Check for maximum memory size.
  // Note: The {wasm::max_mem_pages()} limit is already checked in
  // {BackingStore::CopyWasmMemory}, and is irrelevant for
  // {GrowWasmMemoryInPlace} because memory is never allocated with more
  // capacity than that limit.
  size_t old_size = old_buffer->byte_length();
  DCHECK_EQ(0, old_size % wasm::kWasmPageSize);
  size_t old_pages = old_size / wasm::kWasmPageSize;
  size_t max_pages = memory_object->is_memory64() ? wasm::max_mem64_pages()
                                                  : wasm::max_mem32_pages();
  if (memory_object->has_maximum_pages()) {
    max_pages = std::min(max_pages,
                         static_cast<size_t>(memory_object->maximum_pages()));
  }
  DCHECK_GE(max_pages, old_pages);
  if (pages > max_pages - old_pages) return -1;

  const bool must_grow_in_place =
      old_buffer->is_shared() || backing_store->has_guard_regions();
  const bool try_grow_in_place =
      must_grow_in_place || !v8_flags.stress_wasm_memory_moving;

  std::optional<size_t> result_inplace =
      try_grow_in_place
          ? backing_store->GrowWasmMemoryInPlace(isolate, pages, max_pages)
          : std::nullopt;
  if (must_grow_in_place && !result_inplace.has_value()) {
    // There are different limits per platform, thus crash if the correctness
    // fuzzer is running.
    if (v8_flags.correctness_fuzzer_suppressions) {
      FATAL("could not grow wasm memory");
    }
    return -1;
  }

  // Handle shared memory first.
  if (old_buffer->is_shared()) {
    DCHECK(result_inplace.has_value());
    backing_store->BroadcastSharedWasmMemoryGrow(isolate);
    // Broadcasting the update should update this memory object too.
    CHECK_NE(*old_buffer, memory_object->array_buffer());
    size_t new_pages = result_inplace.value() + pages;
    // If the allocation succeeded, then this can't possibly overflow:
    size_t new_byte_length = new_pages * wasm::kWasmPageSize;
    // This is a less than check, as it is not guaranteed that the SAB
    // length here will be equal to the stashed length above as calls to
    // grow the same memory object can come in from different workers.
    // It is also possible that a call to Grow was in progress when
    // handling this call.
    CHECK_LE(new_byte_length, memory_object->array_buffer()->byte_length());
    // As {old_pages} was read racefully, we return here the synchronized
    // value provided by {GrowWasmMemoryInPlace}, to provide the atomic
    // read-modify-write behavior required by the spec.
    return static_cast<int32_t>(result_inplace.value());  // success
  }

  // Check if the non-shared memory could grow in-place.
  if (result_inplace.has_value()) {
    // Detach old and create a new one with the grown backing store.
    JSArrayBuffer::Detach(old_buffer, true).Check();
    Handle<JSArrayBuffer> new_buffer =
        isolate->factory()->NewJSArrayBuffer(std::move(backing_store));
    memory_object->SetNewBuffer(*new_buffer);
    // For debugging purposes we memorize a link from the JSArrayBuffer
    // to its owning WasmMemoryObject instance.
    Handle<Symbol> symbol =
        isolate->factory()->array_buffer_wasm_memory_symbol();
    Object::SetProperty(isolate, new_buffer, symbol, memory_object).Check();
    DCHECK_EQ(result_inplace.value(), old_pages);
    return static_cast<int32_t>(result_inplace.value());  // success
  }

  size_t new_pages = old_pages + pages;
  // Check for overflow (should be excluded via {max_pages} above).
  DCHECK_LE(old_pages, new_pages);
  // Trying to grow in-place without actually growing must always succeed.
  DCHECK_IMPLIES(try_grow_in_place, old_pages < new_pages);

  // Try allocating a new backing store and copying.
  // To avoid overall quadratic complexity of many small grow operations, we
  // grow by at least 0.5 MB + 12.5% of the existing memory size.
  // These numbers are kept small because we must be careful about address
  // space consumption on 32-bit platforms.
  size_t min_growth = old_pages + 8 + (old_pages >> 3);
  // First apply {min_growth}, then {max_pages}. The order is important, because
  // {min_growth} can be bigger than {max_pages}, and in that case we want to
  // cap to {max_pages}.
  size_t new_capacity = std::min(max_pages, std::max(new_pages, min_growth));
  DCHECK_LE(new_pages, new_capacity);
  std::unique_ptr<BackingStore> new_backing_store =
      backing_store->CopyWasmMemory(isolate, new_pages, new_capacity,
                                    memory_object->is_memory64()
                                        ? WasmMemoryFlag::kWasmMemory64
                                        : WasmMemoryFlag::kWasmMemory32);
  if (!new_backing_store) {
    // Crash on out-of-memory if the correctness fuzzer is running.
    if (v8_flags.correctness_fuzzer_suppressions) {
      FATAL("could not grow wasm memory");
    }
    return -1;
  }

  // Detach old and create a new one with the new backing store.
  JSArrayBuffer::Detach(old_buffer, true).Check();
  Handle<JSArrayBuffer> new_buffer =
      isolate->factory()->NewJSArrayBuffer(std::move(new_backing_store));
  memory_object->SetNewBuffer(*new_buffer);
  // For debugging purposes we memorize a link from the JSArrayBuffer
  // to its owning WasmMemoryObject instance.
  Handle<Symbol> symbol = isolate->factory()->array_buffer_wasm_memory_symbol();
  Object::SetProperty(isolate, new_buffer, symbol, memory_object).Check();
  return static_cast<int32_t>(old_pages);  // success
}

// static
MaybeHandle<WasmGlobalObject> WasmGlobalObject::New(
    Isolate* isolate, Handle<WasmTrustedInstanceData> trusted_data,
    MaybeHandle<JSArrayBuffer> maybe_untagged_buffer,
    MaybeHandle<FixedArray> maybe_tagged_buffer, wasm::ValueType type,
    int32_t offset, bool is_mutable) {
  Handle<JSFunction> global_ctor(
      isolate->native_context()->wasm_global_constructor(), isolate);
  auto global_obj =
      Cast<WasmGlobalObject>(isolate->factory()->NewJSObject(global_ctor));
  {
    // Disallow GC until all fields have acceptable types.
    DisallowGarbageCollection no_gc;
    if (!trusted_data.is_null()) {
      global_obj->set_trusted_data(*trusted_data);
    } else {
      global_obj->clear_trusted_data();
    }
    global_obj->set_type(type);
    global_obj->set_offset(offset);
    global_obj->set_is_mutable(is_mutable);
  }

  if (type.is_reference()) {
    DCHECK(maybe_untagged_buffer.is_null());
    Handle<FixedArray> tagged_buffer;
    if (!maybe_tagged_buffer.ToHandle(&tagged_buffer)) {
      // If no buffer was provided, create one.
      tagged_buffer =
          isolate->factory()->NewFixedArray(1, AllocationType::kOld);
      CHECK_EQ(offset, 0);
    }
    global_obj->set_tagged_buffer(*tagged_buffer);
  } else {
    DCHECK(maybe_tagged_buffer.is_null());
    uint32_t type_size = type.value_kind_size();

    Handle<JSArrayBuffer> untagged_buffer;
    if (!maybe_untagged_buffer.ToHandle(&untagged_buffer)) {
      MaybeHandle<JSArrayBuffer> result =
          isolate->factory()->NewJSArrayBufferAndBackingStore(
              offset + type_size, InitializedFlag::kZeroInitialized);

      if (!result.ToHandle(&untagged_buffer)) return {};
    }

    // Check that the offset is in bounds.
    CHECK_LE(offset + type_size, untagged_buffer->byte_length());

    global_obj->set_untagged_buffer(*untagged_buffer);
  }

  return global_obj;
}

FunctionTargetAndImplicitArg::FunctionTargetAndImplicitArg(
    Isolate* isolate, Handle<WasmTrustedInstanceData> target_instance_data,
    int target_func_index) {
  implicit_arg_ = target_instance_data;
  if (target_func_index <
      static_cast<int>(
          target_instance_data->module()->num_imported_functions)) {
    // The function in the target instance was imported. Load the ref from the
    // dispatch table for imports.
    implicit_arg_ = handle(
        Cast<TrustedObject>(
            target_instance_data->dispatch_table_for_imports()->implicit_arg(
                target_func_index)),
        isolate);
#if V8_ENABLE_DRUMBRAKE
    target_func_index_ = target_instance_data->imported_function_indices()->get(
        target_func_index);
#endif  // V8_ENABLE_DRUMBRAKE
  } else {
    // The function in the target instance was not imported.
#if V8_ENABLE_DRUMBRAKE
    target_func_index_ = target_func_index;
#endif  // V8_ENABLE_DRUMBRAKE
  }
  call_target_ = target_instance_data->GetCallTarget(target_func_index);
}

namespace {
Address WasmCodePointerAddress(WasmCodePointer pointer) {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  return wasm::GetProcessWideWasmCodePointerTable()->GetEntrypoint(pointer);
#else
  return pointer;
#endif
}
}  // namespace

void ImportedFunctionEntry::SetGenericWasmToJs(
    Isolate* isolate, DirectHandle<JSReceiver> callable, wasm::Suspend suspend,
    const wasm::CanonicalSig* sig) {
  WasmCodePointer wrapper_entry;
  if (wasm::IsJSCompatibleSignature(sig)) {
    DCHECK(
        UseGenericWasmToJSWrapper(wasm::kDefaultImportCallKind, sig, suspend));
    wrapper_entry =
        wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperAsm>(isolate);
  } else {
    wrapper_entry =
        wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperInvalidSig>(
            isolate);
  }
  TRACE_IFT("Import callable 0x%" PRIxPTR "[%d] = {callable=0x%" PRIxPTR
            ", target=0x%" PRIxPTR "}\n",
            instance_data_->ptr(), index_, callable->ptr(),
            WasmCodePointerAddress(wrapper_entry));
  DirectHandle<WasmImportData> import_data =
      isolate->factory()->NewWasmImportData(callable, suspend, instance_data_,
                                            sig);
  WasmImportData::SetImportIndexAsCallOrigin(import_data, index_);
  DisallowGarbageCollection no_gc;

  constexpr IsAWrapper kNotACompiledWrapper = IsAWrapper::kNo;
  instance_data_->dispatch_table_for_imports()->SetForImport(
      index_, *import_data, wrapper_entry, nullptr, kNotACompiledWrapper);
#if V8_ENABLE_DRUMBRAKE
  instance_data_->imported_function_indices()->set(index_, -1);
#endif  // V8_ENABLE_DRUMBRAKE
}

void ImportedFunctionEntry::SetCompiledWasmToJs(
    Isolate* isolate, DirectHandle<JSReceiver> callable,
    wasm::WasmCode* wasm_to_js_wrapper, wasm::Suspend suspend,
    const wasm::CanonicalSig* sig) {
  TRACE_IFT("Import callable 0x%" PRIxPTR "[%d] = {callable=0x%" PRIxPTR
            ", target=%p}\n",
            instance_data_->ptr(), index_, callable->ptr(),
            wasm_to_js_wrapper ? nullptr
                               : wasm_to_js_wrapper->instructions().begin());
  DCHECK(v8_flags.wasm_jitless ||
         wasm_to_js_wrapper->kind() == wasm::WasmCode::kWasmToJsWrapper ||
         wasm_to_js_wrapper->kind() == wasm::WasmCode::kWasmToCapiWrapper);
  DirectHandle<WasmImportData> import_data =
      isolate->factory()->NewWasmImportData(callable, suspend, instance_data_,
                                            sig);
  // The wasm-to-js wrapper is already optimized, the call_origin should never
  // be accessed.
  import_data->set_call_origin(
      Smi::FromInt(WasmImportData::kInvalidCallOrigin));
  DisallowGarbageCollection no_gc;
  Tagged<WasmDispatchTable> dispatch_table =
      instance_data_->dispatch_table_for_imports();
  if (V8_UNLIKELY(v8_flags.wasm_jitless)) {
    dispatch_table->SetForImport(index_, *import_data, Address{}, nullptr,
                                 IsAWrapper::kNo);
  } else {
    dispatch_table->SetForImport(index_, *import_data,
                                 wasm_to_js_wrapper->code_pointer(),
                                 wasm_to_js_wrapper, IsAWrapper::kYes);
  }

#if V8_ENABLE_DRUMBRAKE
  instance_data_->imported_function_indices()->set(index_, -1);
#endif  // V8_ENABLE_DRUMBRAKE
}

void ImportedFunctionEntry::SetWasmToWasm(
    Tagged<WasmTrustedInstanceData> target_instance_data,
    WasmCodePointer call_target
#if V8_ENABLE_DRUMBRAKE
    ,
    int exported_function_index
#endif  // V8_ENABLE_DRUMBRAKE
) {
  TRACE_IFT("Import Wasm 0x%" PRIxPTR "[%d] = {instance_data=0x%" PRIxPTR
            ", target=0x%" PRIxPTR "}\n",
            instance_data_->ptr(), index_, target_instance_data.ptr(),
            WasmCodePointerAddress(call_target));
  DisallowGarbageCollection no_gc;
  Tagged<WasmDispatchTable> dispatch_table =
      instance_data_->dispatch_table_for_imports();
  dispatch_table->SetForImport(index_, target_instance_data, call_target,
                               nullptr, IsAWrapper::kNo);

#if V8_ENABLE_DRUMBRAKE
  instance_data_->imported_function_indices()->set(index_,
                                                   exported_function_index);
#endif  // V8_ENABLE_DRUMBRAKE
}

// Returns an empty Tagged<Object>() if no callable is available, a JSReceiver
// otherwise.
Tagged<Object> ImportedFunctionEntry::maybe_callable() {
  Tagged<Object> data = implicit_arg();
  if (!IsWasmImportData(data)) return Tagged<Object>();
  return Cast<JSReceiver>(Cast<WasmImportData>(data)->callable());
}

Tagged<JSReceiver> ImportedFunctionEntry::callable() {
  return Cast<JSReceiver>(Cast<WasmImportData>(implicit_arg())->callable());
}

Tagged<Object> ImportedFunctionEntry::implicit_arg() {
  return instance_data_->dispatch_table_for_imports()->implicit_arg(index_);
}

WasmCodePointer ImportedFunctionEntry::target() {
  return instance_data_->dispatch_table_for_imports()->target(index_);
}

#if V8_ENABLE_DRUMBRAKE
int ImportedFunctionEntry::function_index_in_called_module() {
  return instance_data_->imported_function_indices()->get(index_);
}
#endif  // V8_ENABLE_DRUMBRAKE

// static
constexpr std::array<uint16_t, WasmTrustedInstanceData::kTaggedFieldsCount>
    WasmTrustedInstanceData::kTaggedFieldOffsets;
// static
constexpr std::array<const char*, WasmTrustedInstanceData::kTaggedFieldsCount>
    WasmTrustedInstanceData::kTaggedFieldNames;
// static
constexpr std::array<uint16_t, 6>
    WasmTrustedInstanceData::kProtectedFieldOffsets;
// static
constexpr std::array<const char*, 6>
    WasmTrustedInstanceData::kProtectedFieldNames;

// static
void WasmTrustedInstanceData::EnsureMinimumDispatchTableSize(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int table_index, int minimum_size) {
  Handle<WasmDispatchTable> old_dispatch_table{
      trusted_instance_data->dispatch_table(table_index), isolate};
  if (old_dispatch_table->length() >= minimum_size) return;
  DirectHandle<WasmDispatchTable> new_dispatch_table =
      WasmDispatchTable::Grow(isolate, old_dispatch_table, minimum_size);

  if (*old_dispatch_table == *new_dispatch_table) return;
  trusted_instance_data->dispatch_tables()->set(table_index,
                                                *new_dispatch_table);
  if (table_index == 0) {
    trusted_instance_data->set_dispatch_table0(*new_dispatch_table);
  }
}

void WasmTrustedInstanceData::SetRawMemory(int memory_index, uint8_t* mem_start,
                                           size_t mem_size) {
  CHECK_LT(memory_index, module()->memories.size());

  CHECK_LE(mem_size, module()->memories[memory_index].is_memory64()
                         ? wasm::max_mem64_bytes()
                         : wasm::max_mem32_bytes());
  // All memory bases and sizes are stored in a TrustedFixedAddressArray.
  Tagged<TrustedFixedAddressArray> bases_and_sizes = memory_bases_and_sizes();
  bases_and_sizes->set(memory_index * 2, reinterpret_cast<Address>(mem_start));
  bases_and_sizes->set(memory_index * 2 + 1, mem_size);
  // Memory 0 has fast-access fields.
  if (memory_index == 0) {
    set_memory0_start(mem_start);
    set_memory0_size(mem_size);
  }
}

#if V8_ENABLE_DRUMBRAKE
Handle<Tuple2> WasmTrustedInstanceData::GetOrCreateInterpreterObject(
    Handle<WasmInstanceObject> instance) {
  DCHECK(v8_flags.wasm_jitless);
  Isolate* isolate = instance->GetIsolate();
  Handle<WasmTrustedInstanceData> trusted_data =
      handle(instance->trusted_data(isolate), isolate);
  if (trusted_data->has_interpreter_object()) {
    return handle(trusted_data->interpreter_object(), isolate);
  }
  Handle<Tuple2> new_interpreter = WasmInterpreterObject::New(instance);
  DCHECK(trusted_data->has_interpreter_object());
  return new_interpreter;
}

Handle<Tuple2> WasmTrustedInstanceData::GetInterpreterObject(
    Handle<WasmInstanceObject> instance) {
  DCHECK(v8_flags.wasm_jitless);
  Isolate* isolate = instance->GetIsolate();
  Handle<WasmTrustedInstanceData> trusted_data =
      handle(instance->trusted_data(isolate), isolate);
  CHECK(trusted_data->has_interpreter_object());
  return handle(trusted_data->interpreter_object(), isolate);
}
#endif  // V8_ENABLE_DRUMBRAKE

Handle<WasmTrustedInstanceData> WasmTrustedInstanceData::New(
    Isolate* isolate, DirectHandle<WasmModuleObject> module_object,
    bool shared) {
  // Read the link to the {std::shared_ptr<NativeModule>} once from the
  // `module_object` and use it to initialize the fields of the
  // `WasmTrustedInstanceData`. It will then be stored in a `TrustedManaged` in
  // the `WasmTrustedInstanceData` where it is safe from manipulation.
  std::shared_ptr<wasm::NativeModule> native_module =
      module_object->shared_native_module();

  // Do first allocate all objects that will be stored in instance fields,
  // because otherwise we would have to allocate when the instance is not fully
  // initialized yet, which can lead to heap verification errors.
  const WasmModule* module = native_module->module();

  int num_imported_functions = module->num_imported_functions;
  DirectHandle<WasmDispatchTable> dispatch_table_for_imports =
      isolate->factory()->NewWasmDispatchTable(num_imported_functions);
  DirectHandle<FixedArray> well_known_imports =
      isolate->factory()->NewFixedArray(num_imported_functions);

  DirectHandle<FixedArray> func_refs =
      isolate->factory()->NewFixedArrayWithZeroes(
          static_cast<int>(module->functions.size()));

  int num_imported_mutable_globals = module->num_imported_mutable_globals;
  // The imported_mutable_globals is essentially a FixedAddressArray (storing
  // sandboxed pointers), but some entries (the indices for reference-type
  // globals) are accessed as 32-bit integers which is more convenient with a
  // raw ByteArray.
  DirectHandle<FixedAddressArray> imported_mutable_globals =
      FixedAddressArray::New(isolate, num_imported_mutable_globals);

  int num_data_segments = module->num_declared_data_segments;
  DirectHandle<FixedAddressArray> data_segment_starts =
      FixedAddressArray::New(isolate, num_data_segments);
  DirectHandle<FixedUInt32Array> data_segment_sizes =
      FixedUInt32Array::New(isolate, num_data_segments);

#if V8_ENABLE_DRUMBRAKE
  Handle<FixedInt32Array> imported_function_indices =
      FixedInt32Array::New(isolate, num_imported_functions);
#endif  // V8_ENABLE_DRUMBRAKE

  static_assert(wasm::kV8MaxWasmMemories < kMaxInt / 2);
  int num_memories = static_cast<int>(module->memories.size());
  DirectHandle<FixedArray> memory_objects =
      isolate->factory()->NewFixedArray(num_memories);
  DirectHandle<TrustedFixedAddressArray> memory_bases_and_sizes =
      TrustedFixedAddressArray::New(isolate, 2 * num_memories);

  // TODO(clemensb): Should we have singleton empty dispatch table in the
  // trusted space?
  DirectHandle<WasmDispatchTable> empty_dispatch_table =
      isolate->factory()->NewWasmDispatchTable(0);
  DirectHandle<ProtectedFixedArray> empty_protected_fixed_array =
      isolate->factory()->empty_protected_fixed_array();

  // Use the same memory estimate as the (untrusted) Managed in
  // WasmModuleObject. This is not security critical, and we at least always
  // read the memory estimation of *some* NativeModule here.
  size_t estimated_size =
      module_object->managed_native_module()->estimated_size();
  DirectHandle<TrustedManaged<wasm::NativeModule>>
      trusted_managed_native_module = TrustedManaged<wasm::NativeModule>::From(
          isolate, estimated_size, native_module);

  // Now allocate the WasmTrustedInstanceData.
  // During this step, no more allocations should happen because the instance is
  // incomplete yet, so we should not trigger heap verification at this point.
  Handle<WasmTrustedInstanceData> trusted_data =
      isolate->factory()->NewWasmTrustedInstanceData();
  {
    DisallowHeapAllocation no_gc;

    // Some constants:
    uint8_t* empty_backing_store_buffer =
        reinterpret_cast<uint8_t*>(EmptyBackingStoreBuffer());
    ReadOnlyRoots ro_roots{isolate};
    Tagged<FixedArray> empty_fixed_array = ro_roots.empty_fixed_array();

    trusted_data->set_dispatch_table_for_imports(*dispatch_table_for_imports);
    trusted_data->set_imported_mutable_globals(*imported_mutable_globals);
    trusted_data->set_dispatch_table0(*empty_dispatch_table);
    trusted_data->set_dispatch_tables(*empty_protected_fixed_array);
    trusted_data->set_shared_part(*trusted_data);  // TODO(14616): Good enough?
    trusted_data->set_data_segment_starts(*data_segment_starts);
    trusted_data->set_data_segment_sizes(*data_segment_sizes);
    trusted_data->set_element_segments(empty_fixed_array);
    trusted_data->set_managed_native_module(*trusted_managed_native_module);
    trusted_data->set_new_allocation_limit_address(
        isolate->heap()->NewSpaceAllocationLimitAddress());
    trusted_data->set_new_allocation_top_address(
        isolate->heap()->NewSpaceAllocationTopAddress());
    trusted_data->set_old_allocation_limit_address(
        isolate->heap()->OldSpaceAllocationLimitAddress());
    trusted_data->set_old_allocation_top_address(
        isolate->heap()->OldSpaceAllocationTopAddress());
    trusted_data->set_globals_start(empty_backing_store_buffer);
#if V8_ENABLE_DRUMBRAKE
    trusted_data->set_imported_function_indices(*imported_function_indices);
#endif  // V8_ENABLE_DRUMBRAKE
    trusted_data->set_native_context(*isolate->native_context());
    trusted_data->set_jump_table_start(native_module->jump_table_start());
    trusted_data->set_hook_on_function_call_address(
        isolate->debug()->hook_on_function_call_address());
    trusted_data->set_managed_object_maps(
        *isolate->factory()->empty_fixed_array());
    trusted_data->set_well_known_imports(*well_known_imports);
    trusted_data->set_func_refs(*func_refs);
    trusted_data->set_feedback_vectors(
        *isolate->factory()->empty_fixed_array());
    trusted_data->set_tiering_budget_array(
        native_module->tiering_budget_array());
    trusted_data->set_break_on_entry(module_object->script()->break_on_entry());
    trusted_data->InitDataSegmentArrays(native_module.get());
    trusted_data->set_memory0_start(empty_backing_store_buffer);
    trusted_data->set_memory0_size(0);
    trusted_data->set_memory_objects(*memory_objects);
    trusted_data->set_memory_bases_and_sizes(*memory_bases_and_sizes);
    trusted_data->set_stress_deopt_counter_address(
        ExternalReference::stress_deopt_count(isolate).address());

    for (int i = 0; i < num_memories; ++i) {
      memory_bases_and_sizes->set(
          2 * i, reinterpret_cast<Address>(empty_backing_store_buffer));
      memory_bases_and_sizes->set(2 * i + 1, 0);
    }
  }

  // Allocate the exports object, to be store in the instance object.
  DirectHandle<JSObject> exports_object =
      isolate->factory()->NewJSObjectWithNullProto();

  Handle<WasmInstanceObject> instance_object;

  if (!shared) {
    // Allocate the WasmInstanceObject (JS wrapper).
    Handle<JSFunction> instance_cons(
        isolate->native_context()->wasm_instance_constructor(), isolate);
    instance_object = Cast<WasmInstanceObject>(
        isolate->factory()->NewJSObject(instance_cons, AllocationType::kOld));
    instance_object->set_trusted_data(*trusted_data);
    instance_object->set_module_object(*module_object);
    instance_object->set_exports_object(*exports_object);
    trusted_data->set_instance_object(*instance_object);
  }

  // Insert the new instance into the scripts weak list of instances. This list
  // is used for breakpoints affecting all instances belonging to the script.
  if (module_object->script()->type() == Script::Type::kWasm &&
      !instance_object.is_null()) {
    Handle<WeakArrayList> weak_instance_list(
        module_object->script()->wasm_weak_instance_list(), isolate);
    weak_instance_list =
        WeakArrayList::Append(isolate, weak_instance_list,
                              MaybeObjectDirectHandle::Weak(instance_object));
    module_object->script()->set_wasm_weak_instance_list(*weak_instance_list);
  }

  return trusted_data;
}

void WasmTrustedInstanceData::InitDataSegmentArrays(
    const wasm::NativeModule* native_module) {
  const WasmModule* module = native_module->module();
  base
"""


```
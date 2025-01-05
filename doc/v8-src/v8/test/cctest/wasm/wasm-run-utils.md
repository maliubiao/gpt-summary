Response: The user wants to understand the functionality of the C++ file `wasm-run-utils.cc`. I need to:
1. Summarize the purpose of the code.
2. Identify any connections to JavaScript functionality within the code.
3. If there's a connection, provide a JavaScript example to illustrate it.

Based on the file name and content, it seems like this file provides utility functions for running and testing WebAssembly code within the V8 JavaScript engine. It likely helps in setting up WASM modules, instances, and executing WASM functions in a testing environment.

The file contains classes like `TestingModuleBuilder` and `WasmFunctionCompiler`, which suggests it's involved in creating and managing WASM modules and functions for testing purposes. The inclusion of headers like `src/wasm/wasm-objects-inl.h`, `src/wasm/module-compiler.h`, and `src/wasm/wasm-engine.h` confirms its role in interacting with the V8's WASM implementation.

The `TestingModuleBuilder` seems to be responsible for constructing WASM modules programmatically, adding functions, memory, globals, and tables. The `WasmFunctionCompiler` appears to handle the compilation of individual WASM functions.

The connection to JavaScript lies in the fact that WASM code is often executed within a JavaScript environment. V8, being a JavaScript engine, needs to provide mechanisms for JavaScript to interact with WASM modules. The presence of functions like `WrapCode` in `TestingModuleBuilder`, which returns a `JSFunction`, strongly indicates this interaction.

Let's formulate a summary and a JavaScript example demonstrating the interaction. The example should show how a WASM function created using these utilities can be called from JavaScript.
### 功能归纳:

`wasm-run-utils.cc` 文件提供了一系列用于在 V8 JavaScript 引擎的测试环境中构建和运行 WebAssembly (Wasm) 模块的实用工具类和函数。它的主要功能包括：

1. **模块构建 (`TestingModuleBuilder`):**  该类允许在测试中以编程方式创建和配置 Wasm 模块。这包括：
    * 添加函数 (包括导入函数和普通函数)。
    * 添加内存 (线性内存)。
    * 添加全局变量。
    * 添加表格 (函数表)。
    * 添加数据段。
    * 添加异常标签。
    * 管理模块的元数据和实例数据。
    * 创建 Wasm 模块对象和实例对象。
    * 支持手动导入 JavaScript 函数到 Wasm 模块中。

2. **函数编译 (`WasmFunctionCompiler`):**  该类用于构建单个 Wasm 函数的代码，包括：
    * 添加局部变量声明。
    * 添加 Wasm 指令字节码。
    * 执行函数的编译 (根据配置选择不同的编译层级，如 Liftoff 或 Turbofan)。
    * 将编译后的代码添加到 NativeModule 中。

3. **辅助函数:** 提供了一些用于比较浮点数 NaN 值的辅助函数 (`IsSameNan`)，因为 NaN 值的表示可能存在非确定性。

**总而言之，`wasm-run-utils.cc` 提供了一个方便的 C++ API，用于在 V8 的测试框架中动态地创建、配置和编译 Wasm 模块，以便进行各种 Wasm 功能和集成的测试。**

### 与 JavaScript 的关系及示例

此文件与 JavaScript 的功能有密切关系，因为它提供的工具是为了测试 V8 JavaScript 引擎中对 WebAssembly 的支持。WebAssembly 模块通常在 JavaScript 环境中加载和执行，并且 JavaScript 可以调用 Wasm 导出的函数，Wasm 也可以调用 JavaScript 导入的函数。

**JavaScript 示例:**

假设 `wasm-run-utils.cc` 中创建了一个简单的 Wasm 模块，其中包含一个名为 `add` 的导出函数，该函数接受两个整数参数并返回它们的和。在测试代码中，可能会使用 `TestingModuleBuilder` 和 `WasmFunctionCompiler` 来创建和编译这个 Wasm 模块。

在 JavaScript 中，可以像这样加载和调用这个 Wasm 模块：

```javascript
// 假设 'wasmCode' 是由测试工具生成的 Wasm 字节码 (Uint8Array)
WebAssembly.instantiate(wasmCode).then(module => {
  const instance = module.instance;
  const addFunction = instance.exports.add; // 获取导出的 'add' 函数

  const result = addFunction(5, 3);
  console.log(result); // 输出 8
});
```

**更具体地说明 `wasm-run-utils.cc` 中的工具如何与 JavaScript 交互:**

* **`TestingModuleBuilder::WrapCode(uint32_t index)`:**  这个方法会创建一个 JavaScript 函数 (`JSFunction`)，该函数可以调用指定的 Wasm 函数。在测试代码中，这允许将编译后的 Wasm 函数暴露给 JavaScript 环境进行调用。

* **手动导入 (`TestingModuleBuilder` 中添加导入函数):** `TestingModuleBuilder` 允许手动添加 JavaScript 函数作为 Wasm 模块的导入项。当 Wasm 代码调用这些导入的函数时，实际上是在执行 JavaScript 代码。

**一个使用 `TestingModuleBuilder` 手动导入 JavaScript 函数的 C++ 测试示例 (概念性):**

```c++
// ... 在 C++ 测试代码中 ...
TestingModuleBuilder builder;
// 定义一个 JavaScript 函数的签名
FunctionSig* import_sig = WasmRunnerBase::CreateSig(/* ... */);

// 创建一个代表 JavaScript 函数的对象
ManuallyImportedJSFunction js_import("myJsFunction", isolate->GetCurrentContext()->Global()->Get(isolate, v8_str("myJsFunction")));

// 将 JavaScript 函数作为导入添加到 Wasm 模块
builder.AddFunction(import_sig, nullptr, TestingModuleBuilder::kImport, &js_import);

// ... 编译 Wasm 模块，其中可能包含调用 "myJsFunction" 的代码 ...
```

在上面的 C++ 测试代码中，如果 Wasm 模块中存在调用名为 "myJsFunction" 的导入函数的代码，那么在执行 Wasm 代码时，实际上会调用在 JavaScript 全局对象中定义的 `myJsFunction` 函数。

总而言之，`wasm-run-utils.cc` 提供的是 C++ 级别的工具，用于搭建测试环境，模拟 Wasm 模块的创建和编译过程。这些工具最终目的是为了测试 V8 JavaScript 引擎正确地执行和与 WebAssembly 模块进行交互的能力。JavaScript 代码是 Wasm 模块的宿主环境，并通过 WebAssembly API 与之交互。

Prompt: 
```
这是目录为v8/test/cctest/wasm/wasm-run-utils.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/cctest/wasm/wasm-run-utils.h"

#include <optional>

#include "src/codegen/assembler-inl.h"
#include "src/compiler/pipeline.h"
#include "src/diagnostics/code-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/wasm/baseline/liftoff-compiler.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/graph-builder-interface.h"
#include "src/wasm/leb-helper.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8 {
namespace internal {
namespace wasm {

// Helper Functions.
bool IsSameNan(uint16_t expected, uint16_t actual) {
  // Sign is non-deterministic.
  uint16_t expected_bits = expected & ~0x8000;
  uint16_t actual_bits = actual & ~0x8000;
  return (expected_bits == actual_bits);
}

bool IsSameNan(float expected, float actual) {
  // Sign is non-deterministic.
  uint32_t expected_bits = base::bit_cast<uint32_t>(expected) & ~0x80000000;
  uint32_t actual_bits = base::bit_cast<uint32_t>(actual) & ~0x80000000;
  // Some implementations convert signaling NaNs to quiet NaNs.
  return (expected_bits == actual_bits) ||
         ((expected_bits | 0x00400000) == actual_bits);
}

bool IsSameNan(double expected, double actual) {
  // Sign is non-deterministic.
  uint64_t expected_bits =
      base::bit_cast<uint64_t>(expected) & ~0x8000000000000000;
  uint64_t actual_bits = base::bit_cast<uint64_t>(actual) & ~0x8000000000000000;
  // Some implementations convert signaling NaNs to quiet NaNs.
  return (expected_bits == actual_bits) ||
         ((expected_bits | 0x0008000000000000) == actual_bits);
}

TestingModuleBuilder::TestingModuleBuilder(
    Zone* zone, ModuleOrigin origin, ManuallyImportedJSFunction* maybe_import,
    TestExecutionTier tier, Isolate* isolate)
    : test_module_(std::make_shared<WasmModule>(origin)),
      isolate_(isolate ? isolate : CcTest::InitIsolateOnce()),
      enabled_features_(WasmEnabledFeatures::FromIsolate(isolate_)),
      execution_tier_(tier) {
  WasmJs::Install(isolate_);
  test_module_->untagged_globals_buffer_size = kMaxGlobalsSize;
  // The GlobalsData must be located inside the sandbox, so allocate it from the
  // ArrayBuffer allocator.
  globals_data_ = reinterpret_cast<uint8_t*>(
      CcTest::array_buffer_allocator()->Allocate(kMaxGlobalsSize));

  uint32_t maybe_import_index = 0;
  if (maybe_import) {
    // Manually add an imported function before any other functions.
    // This must happen before the instance object is created, since the
    // instance object allocates import entries.
    maybe_import_index = AddFunction(maybe_import->sig, nullptr, kImport);
    DCHECK_EQ(0, maybe_import_index);
  }

  instance_object_ = InitInstanceObject();
  trusted_instance_data_ =
      handle(instance_object_->trusted_data(isolate_), isolate_);
  DirectHandle<FixedArray> tables(isolate_->factory()->NewFixedArray(0));
  trusted_instance_data_->set_tables(*tables);

  if (maybe_import) {
    WasmCodeRefScope code_ref_scope;
    // Manually compile an import wrapper and insert it into the instance.
    CanonicalTypeIndex sig_index =
        GetTypeCanonicalizer()->AddRecursiveGroup(maybe_import->sig);
    const wasm::CanonicalSig* sig =
        GetTypeCanonicalizer()->LookupFunctionSignature(sig_index);
    ResolvedWasmImport resolved({}, -1, maybe_import->js_function, sig,
                                sig_index, WellKnownImport::kUninstantiated);
    ImportCallKind kind = resolved.kind();
    DirectHandle<JSReceiver> callable = resolved.callable();
    WasmCode* import_wrapper = GetWasmImportWrapperCache()->MaybeGet(
        kind, sig_index, static_cast<int>(sig->parameter_count()), kNoSuspend);
    if (import_wrapper == nullptr) {
      import_wrapper = CompileImportWrapperForTest(
          isolate_, native_module_, kind, sig, sig_index,
          static_cast<int>(sig->parameter_count()), kNoSuspend);
    }

    ImportedFunctionEntry(trusted_instance_data_, maybe_import_index)
        .SetCompiledWasmToJs(isolate_, callable, import_wrapper,
                             resolved.suspend(), sig);
  }
}

TestingModuleBuilder::~TestingModuleBuilder() {
  // When the native module dies and is erased from the cache, it is expected to
  // have either valid bytes or no bytes at all.
  native_module_->SetWireBytes({});
  CcTest::array_buffer_allocator()->Free(globals_data_, kMaxGlobalsSize);
}

uint8_t* TestingModuleBuilder::AddMemory(uint32_t size, SharedFlag shared,
                                         AddressType address_type,
                                         std::optional<size_t> max_size) {
  // The TestingModuleBuilder only supports one memory currently.
  CHECK_EQ(0, test_module_->memories.size());
  CHECK_NULL(mem0_start_);
  CHECK_EQ(0, mem0_size_);
  CHECK_EQ(0, trusted_instance_data_->memory_objects()->length());

  uint32_t initial_pages = RoundUp(size, kWasmPageSize) / kWasmPageSize;
  uint32_t maximum_pages =
      max_size.has_value()
          ? static_cast<uint32_t>(RoundUp(max_size.value(), kWasmPageSize) /
                                  kWasmPageSize)
          : initial_pages;
  test_module_->memories.resize(1);
  WasmMemory* memory = &test_module_->memories[0];
  memory->initial_pages = initial_pages;
  memory->maximum_pages = maximum_pages;
  memory->address_type = address_type;
  UpdateComputedInformation(memory, test_module_->origin);

  // Create the WasmMemoryObject.
  DirectHandle<WasmMemoryObject> memory_object =
      WasmMemoryObject::New(isolate_, initial_pages, maximum_pages, shared,
                            address_type)
          .ToHandleChecked();
  DirectHandle<FixedArray> memory_objects =
      isolate_->factory()->NewFixedArray(1);
  memory_objects->set(0, *memory_object);
  trusted_instance_data_->set_memory_objects(*memory_objects);

  // Create the memory_bases_and_sizes array.
  DirectHandle<TrustedFixedAddressArray> memory_bases_and_sizes =
      TrustedFixedAddressArray::New(isolate_, 2);
  uint8_t* mem_start = reinterpret_cast<uint8_t*>(
      memory_object->array_buffer()->backing_store());
  memory_bases_and_sizes->set_sandboxed_pointer(
      0, reinterpret_cast<Address>(mem_start));
  memory_bases_and_sizes->set(1, size);
  trusted_instance_data_->set_memory_bases_and_sizes(*memory_bases_and_sizes);

  mem0_start_ = mem_start;
  mem0_size_ = size;
  CHECK(size == 0 || mem0_start_);

  // TODO(14616): Add shared_trusted_instance_data_.
  WasmMemoryObject::UseInInstance(isolate_, memory_object,
                                  trusted_instance_data_,
                                  trusted_instance_data_, 0);
  // TODO(wasm): Delete the following line when test-run-wasm will use a
  // multiple of kPageSize as memory size. At the moment, the effect of these
  // two lines is used to shrink the memory for testing purposes.
  trusted_instance_data_->SetRawMemory(0, mem0_start_, mem0_size_);
  return mem0_start_;
}

uint32_t TestingModuleBuilder::AddFunction(const FunctionSig* sig,
                                           const char* name,
                                           FunctionType type) {
  if (test_module_->functions.size() == 0) {
    // TODO(titzer): Reserving space here to avoid the underlying WasmFunction
    // structs from moving.
    test_module_->functions.reserve(kMaxFunctions);
    DCHECK_NULL(test_module_->validated_functions);
    test_module_->validated_functions =
        std::make_unique<std::atomic<uint8_t>[]>((kMaxFunctions + 7) / 8);
    if (is_asmjs_module(test_module_.get())) {
      // All asm.js functions are valid by design.
      std::fill_n(test_module_->validated_functions.get(),
                  (kMaxFunctions + 7) / 8, 0xff);
    }
    test_module_->type_feedback.well_known_imports.Initialize(kMaxFunctions);
  }
  uint32_t index = static_cast<uint32_t>(test_module_->functions.size());
  test_module_->functions.push_back({sig,                 // sig
                                     index,               // func_index
                                     ModuleTypeIndex{0},  // sig_index
                                     {0, 0},              // code
                                     false,               // imported
                                     false,               // exported
                                     false});             // declared
  if (type == kImport) {
    DCHECK_EQ(0, test_module_->num_declared_functions);
    ++test_module_->num_imported_functions;
    test_module_->functions.back().imported = true;
  } else {
    ++test_module_->num_declared_functions;
  }
  DCHECK_EQ(test_module_->functions.size(),
            test_module_->num_imported_functions +
                test_module_->num_declared_functions);
  if (name) {
    base::Vector<const uint8_t> name_vec =
        base::Vector<const uint8_t>::cast(base::CStrVector(name));
    test_module_->lazily_generated_names.AddForTesting(
        index, {AddBytes(name_vec), static_cast<uint32_t>(name_vec.length())});
  }
  DCHECK_LT(index, kMaxFunctions);  // limited for testing.
  if (!trusted_instance_data_.is_null()) {
    DirectHandle<FixedArray> func_refs =
        isolate_->factory()->NewFixedArrayWithZeroes(
            static_cast<int>(test_module_->functions.size()));
    trusted_instance_data_->set_func_refs(*func_refs);
  }
  return index;
}

void TestingModuleBuilder::InitializeWrapperCache() {
  TypeCanonicalizer::PrepareForCanonicalTypeId(
      isolate_, test_module_->MaxCanonicalTypeIndex());
  Handle<FixedArray> maps = isolate_->factory()->NewFixedArray(
      static_cast<int>(test_module_->types.size()));
  for (uint32_t index = 0; index < test_module_->types.size(); index++) {
    // TODO(14616): Support shared types.
    CreateMapForType(
        isolate_, test_module_.get(), ModuleTypeIndex{index},
        handle(instance_object_->trusted_data(isolate()), isolate()),
        instance_object_, maps);
  }
  trusted_instance_data_->set_managed_object_maps(*maps);
}

Handle<JSFunction> TestingModuleBuilder::WrapCode(uint32_t index) {
  InitializeWrapperCache();
  DirectHandle<WasmFuncRef> func_ref =
      WasmTrustedInstanceData::GetOrCreateFuncRef(
          isolate_, trusted_instance_data_, index);
  DirectHandle<WasmInternalFunction> internal{func_ref->internal(isolate_),
                                              isolate_};
  return WasmInternalFunction::GetOrCreateExternal(internal);
}

void TestingModuleBuilder::AddIndirectFunctionTable(
    const uint16_t* function_indexes, uint32_t table_size,
    ValueType table_type) {
  uint32_t table_index = static_cast<uint32_t>(test_module_->tables.size());
  test_module_->tables.emplace_back();
  WasmTable& table = test_module_->tables.back();
  table.initial_size = table_size;
  table.maximum_size = table_size;
  table.has_maximum_size = true;
  table.type = table_type;

  {
    // Allocate the dispatch table.
    DirectHandle<ProtectedFixedArray> old_dispatch_tables{
        trusted_instance_data_->dispatch_tables(), isolate_};
    DCHECK_EQ(table_index, old_dispatch_tables->length());
    DirectHandle<ProtectedFixedArray> new_dispatch_tables =
        isolate_->factory()->NewProtectedFixedArray(table_index + 1);
    DirectHandle<WasmDispatchTable> new_dispatch_table =
        WasmDispatchTable::New(isolate_, table.initial_size);
    for (int i = 0; i < old_dispatch_tables->length(); ++i) {
      new_dispatch_tables->set(i, old_dispatch_tables->get(i));
    }
    new_dispatch_tables->set(table_index, *new_dispatch_table);
    if (table_index == 0) {
      trusted_instance_data_->set_dispatch_table0(*new_dispatch_table);
    }
    trusted_instance_data_->set_dispatch_tables(*new_dispatch_tables);
  }

  WasmTrustedInstanceData::EnsureMinimumDispatchTableSize(
      isolate_, trusted_instance_data_, table_index, table_size);
  DirectHandle<WasmTableObject> table_obj = WasmTableObject::New(
      isolate_, handle(instance_object_->trusted_data(isolate_), isolate_),
      table.type, table.initial_size, table.has_maximum_size,
      table.maximum_size,
      IsSubtypeOf(table.type, kWasmExternRef, test_module_.get())
          ? Handle<HeapObject>{isolate_->factory()->null_value()}
          : Handle<HeapObject>{isolate_->factory()->wasm_null()},
      // TODO(clemensb): Make this configurable.
      wasm::AddressType::kI32);

  WasmTableObject::AddUse(isolate_, table_obj, instance_object_, table_index);

  if (function_indexes) {
    for (uint32_t i = 0; i < table_size; ++i) {
      WasmFunction& function = test_module_->functions[function_indexes[i]];
      CanonicalTypeIndex sig_id =
          test_module_->canonical_sig_id(function.sig_index);
      FunctionTargetAndImplicitArg entry(isolate_, trusted_instance_data_,
                                         function.func_index);
      trusted_instance_data_->dispatch_table(table_index)
          ->Set(i, *entry.implicit_arg(), entry.call_target(), sig_id,
#if V8_ENABLE_DRUMBRAKE
                function.func_index,
#endif  // !V8_ENABLE_DRUMBRAKE
                nullptr, IsAWrapper::kMaybe, WasmDispatchTable::kNewEntry);
      WasmTableObject::SetFunctionTablePlaceholder(
          isolate_, table_obj, i, trusted_instance_data_, function_indexes[i]);
    }
  }

  DirectHandle<FixedArray> old_tables(trusted_instance_data_->tables(),
                                      isolate_);
  DirectHandle<FixedArray> new_tables =
      isolate_->factory()->CopyFixedArrayAndGrow(old_tables, 1);
  new_tables->set(old_tables->length(), *table_obj);
  trusted_instance_data_->set_tables(*new_tables);
}

uint32_t TestingModuleBuilder::AddBytes(base::Vector<const uint8_t> bytes) {
  base::Vector<const uint8_t> old_bytes = native_module_->wire_bytes();
  uint32_t old_size = static_cast<uint32_t>(old_bytes.size());
  // Avoid placing strings at offset 0, this might be interpreted as "not
  // set", e.g. for function names.
  uint32_t bytes_offset = old_size ? old_size : 1;
  size_t new_size = bytes_offset + bytes.size();
  base::OwnedVector<uint8_t> new_bytes =
      base::OwnedVector<uint8_t>::New(new_size);
  if (old_size > 0) {
    memcpy(new_bytes.begin(), old_bytes.begin(), old_size);
  } else {
    // Set the unused byte. It is never decoded, but the bytes are used as the
    // key in the native module cache.
    new_bytes[0] = 0;
  }
  memcpy(new_bytes.begin() + bytes_offset, bytes.begin(), bytes.length());
  native_module_->SetWireBytes(std::move(new_bytes));
  return bytes_offset;
}

uint32_t TestingModuleBuilder::AddException(const FunctionSig* sig) {
  DCHECK_EQ(0, sig->return_count());
  uint32_t index = static_cast<uint32_t>(test_module_->tags.size());
  test_module_->tags.emplace_back(sig, AddSignature(sig));
  DirectHandle<WasmExceptionTag> tag = WasmExceptionTag::New(isolate_, index);
  DirectHandle<FixedArray> table(trusted_instance_data_->tags_table(),
                                 isolate_);
  table = isolate_->factory()->CopyFixedArrayAndGrow(table, 1);
  trusted_instance_data_->set_tags_table(*table);
  table->set(index, *tag);
  return index;
}

uint32_t TestingModuleBuilder::AddPassiveDataSegment(
    base::Vector<const uint8_t> bytes) {
  uint32_t index = static_cast<uint32_t>(test_module_->data_segments.size());
  DCHECK_EQ(index, test_module_->data_segments.size());
  DCHECK_EQ(index, data_segment_starts_.size());
  DCHECK_EQ(index, data_segment_sizes_.size());

  // Add a passive data segment. This isn't used by function compilation, but
  // but it keeps the index in sync. The data segment's source will not be
  // correct, since we don't store data in the module wire bytes.
  test_module_->data_segments.push_back(WasmDataSegment::PassiveForTesting());

  // The num_declared_data_segments (from the DataCount section) is used
  // to validate the segment index, during function compilation.
  test_module_->num_declared_data_segments = index + 1;

  Address old_data_address =
      reinterpret_cast<Address>(data_segment_data_.data());
  size_t old_data_size = data_segment_data_.size();
  data_segment_data_.resize(old_data_size + bytes.length());
  Address new_data_address =
      reinterpret_cast<Address>(data_segment_data_.data());

  memcpy(data_segment_data_.data() + old_data_size, bytes.begin(),
         bytes.length());

  // The data_segment_data_ offset may have moved, so update all the starts.
  for (Address& start : data_segment_starts_) {
    start += new_data_address - old_data_address;
  }
  data_segment_starts_.push_back(new_data_address + old_data_size);
  data_segment_sizes_.push_back(bytes.length());

  // The vector pointers may have moved, so update the instance object.
  uint32_t size = static_cast<uint32_t>(data_segment_sizes_.size());
  DirectHandle<FixedAddressArray> data_segment_starts =
      FixedAddressArray::New(isolate_, size);
  MemCopy(data_segment_starts->begin(), data_segment_starts_.data(),
          size * sizeof(Address));
  trusted_instance_data_->set_data_segment_starts(*data_segment_starts);
  DirectHandle<FixedUInt32Array> data_segment_sizes =
      FixedUInt32Array::New(isolate_, size);
  MemCopy(data_segment_sizes->begin(), data_segment_sizes_.data(),
          size * sizeof(uint32_t));
  trusted_instance_data_->set_data_segment_sizes(*data_segment_sizes);
  return index;
}

const WasmGlobal* TestingModuleBuilder::AddGlobal(ValueType type) {
  uint8_t size = type.value_kind_size();
  global_offset = (global_offset + size - 1) & ~(size - 1);  // align
  test_module_->globals.push_back(
      {type, true, {}, {global_offset}, false, false, false});
  global_offset += size;
  // limit number of globals.
  CHECK_LT(global_offset, kMaxGlobalsSize);
  return &test_module_->globals.back();
}

Handle<WasmInstanceObject> TestingModuleBuilder::InitInstanceObject() {
  // In this test setup, the NativeModule gets allocated before functions get
  // added. The tiering budget array, which gets allocated in the NativeModule
  // constructor, therefore does not have slots for functions that get added
  // later. By disabling dynamic tiering, the tiering budget does not get
  // accessed by generated code.
  FlagScope<bool> no_dynamic_tiering(&v8_flags.wasm_dynamic_tiering, false);
  const bool kUsesLiftoff = true;
  // Compute the estimate based on {kMaxFunctions} because we might still add
  // functions later. Assume 1k of code per function.
  int estimated_code_section_length = kMaxFunctions * 1024;
  size_t code_size_estimate =
      wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
          kMaxFunctions, 0, estimated_code_section_length, kUsesLiftoff,
          DynamicTiering{v8_flags.wasm_dynamic_tiering.value()});
  auto native_module = GetWasmEngine()->NewNativeModule(
      isolate_, enabled_features_, WasmDetectedFeatures{}, CompileTimeImports{},
      test_module_, code_size_estimate);
  native_module->SetWireBytes(base::OwnedVector<const uint8_t>());
  native_module->compilation_state()->set_compilation_id(0);
  constexpr base::Vector<const char> kNoSourceUrl{"", 0};
  DirectHandle<Script> script =
      GetWasmEngine()->GetOrCreateScript(isolate_, native_module, kNoSourceUrl);
  // Asm.js modules are expected to have "normal" scripts, not Wasm scripts.
  if (is_asmjs_module(native_module->module())) {
    script->set_type(Script::Type::kNormal);
    script->set_infos(ReadOnlyRoots{isolate_}.empty_weak_fixed_array());
  }

  DirectHandle<WasmModuleObject> module_object =
      WasmModuleObject::New(isolate_, std::move(native_module), script);
  native_module_ = module_object->native_module();
  native_module_->ReserveCodeTableForTesting(kMaxFunctions);

  DirectHandle<WasmTrustedInstanceData> trusted_data =
      WasmTrustedInstanceData::New(isolate_, module_object, false);
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(trusted_data->has_instance_object());
  Handle<WasmInstanceObject> instance_object =
      handle(trusted_data->instance_object(), isolate_);
  trusted_data->set_tags_table(ReadOnlyRoots{isolate_}.empty_fixed_array());
  trusted_data->set_globals_start(globals_data_);
  DirectHandle<FixedArray> feedback_vector =
      isolate_->factory()->NewFixedArrayWithZeroes(kMaxFunctions);
  trusted_data->set_feedback_vectors(*feedback_vector);
  return instance_object;
}

// This struct is just a type tag for Zone::NewArray<T>(size_t) call.
struct WasmFunctionCompilerBuffer {};

void WasmFunctionCompiler::Build(base::Vector<const uint8_t> bytes) {
  size_t locals_size = local_decls_.Size();
  size_t total_size = bytes.size() + locals_size + 1;
  uint8_t* buffer =
      zone_->AllocateArray<uint8_t, WasmFunctionCompilerBuffer>(total_size);
  // Prepend the local decls to the code.
  local_decls_.Emit(buffer);
  // Emit the code.
  memcpy(buffer + locals_size, bytes.begin(), bytes.size());
  // Append an extra end opcode.
  buffer[total_size - 1] = kExprEnd;

  bytes = base::VectorOf(buffer, total_size);

  function_->code = {builder_->AddBytes(bytes),
                     static_cast<uint32_t>(bytes.size())};

  NativeModule* native_module =
      builder_->trusted_instance_data()->native_module();
  base::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();

  CompilationEnv env = CompilationEnv::ForModule(native_module);
  base::ScopedVector<uint8_t> func_wire_bytes(function_->code.length());
  memcpy(func_wire_bytes.begin(), wire_bytes.begin() + function_->code.offset(),
         func_wire_bytes.length());
  constexpr bool kIsShared = false;  // TODO(14616): Extend this.

  FunctionBody func_body{function_->sig, function_->code.offset(),
                         func_wire_bytes.begin(), func_wire_bytes.end(),
                         kIsShared};
  ForDebugging for_debugging =
      native_module->IsInDebugState() ? kForDebugging : kNotForDebugging;

  WasmDetectedFeatures unused_detected_features;
  // Validate Wasm modules; asm.js is assumed to be always valid.
  if (env.module->origin == kWasmOrigin) {
    DecodeResult validation_result =
        ValidateFunctionBody(zone_, env.enabled_features, env.module,
                             &unused_detected_features, func_body);
    if (validation_result.failed()) {
      FATAL("Validation failed: %s",
            validation_result.error().message().c_str());
    }
    env.module->set_function_validated(function_->func_index);
  }

  if (v8_flags.wasm_jitless) return;

  std::optional<WasmCompilationResult> result;
  if (builder_->test_execution_tier() ==
      TestExecutionTier::kLiftoffForFuzzing) {
    result.emplace(ExecuteLiftoffCompilation(
        &env, func_body,
        LiftoffOptions{}
            .set_func_index(function_->func_index)
            .set_for_debugging(kForDebugging)
            .set_max_steps(builder_->max_steps_ptr())
            .set_nondeterminism(builder_->non_determinism_ptr())));
  } else {
    WasmCompilationUnit unit(function_->func_index, builder_->execution_tier(),
                             for_debugging);
    result.emplace(unit.ExecuteCompilation(
        &env, native_module->compilation_state()->GetWireBytesStorage().get(),
        nullptr, &unused_detected_features));
  }
  CHECK(result->succeeded());
  WasmCode* code =
      native_module->PublishCode(native_module->AddCompiledCode(*result));
  DCHECK_NOT_NULL(code);
  DisallowGarbageCollection no_gc;
  Tagged<Script> script =
      builder_->instance_object()->module_object()->script();
  std::unique_ptr<char[]> source_url =
      Cast<String>(script->name())->ToCString();
  if (WasmCode::ShouldBeLogged(isolate())) {
    code->LogCode(isolate(), source_url.get(), script->id());
  }
}

WasmFunctionCompiler::WasmFunctionCompiler(Zone* zone, const FunctionSig* sig,
                                           TestingModuleBuilder* builder,
                                           const char* name)
    : zone_(zone), builder_(builder), local_decls_(zone, sig) {
  // Get a new function from the testing module.
  int index = builder->AddFunction(sig, name, TestingModuleBuilder::kWasm);
  function_ = builder_->GetFunctionAt(index);
}

WasmFunctionCompiler::~WasmFunctionCompiler() = default;

/* static */
FunctionSig* WasmRunnerBase::CreateSig(Zone* zone, MachineType return_type,
                                       base::Vector<MachineType> param_types) {
  int return_count = return_type.IsNone() ? 0 : 1;
  int param_count = param_types.length();

  // Allocate storage array in zone.
  ValueType* sig_types =
      zone->AllocateArray<ValueType>(return_count + param_count);

  // Convert machine types to local types, and check that there are no
  // MachineType::None()'s in the parameters.
  int idx = 0;
  if (return_count) sig_types[idx++] = ValueType::For(return_type);
  for (MachineType param : param_types) {
    CHECK_NE(MachineType::None(), param);
    sig_types[idx++] = ValueType::For(param);
  }
  return zone->New<FunctionSig>(return_count, param_count, sig_types);
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```
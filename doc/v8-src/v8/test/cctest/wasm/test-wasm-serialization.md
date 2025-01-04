Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The primary goal is to figure out what this C++ file does, especially in relation to JavaScript and WebAssembly. The filename "test-wasm-serialization.cc" is a huge clue.

2. **Identify Key Components:**  Scan the includes and the code structure for important pieces.
    * **Includes:** Look for `#include` directives that reveal the purpose. `v8-wasm.h`, `src/wasm/*`, `src/snapshot/*` immediately point to WebAssembly and serialization functionalities within V8.
    * **Namespaces:** The code is within `namespace v8::internal::wasm`, solidifying its connection to V8's internal WebAssembly implementation.
    * **Classes and Functions:** The `WasmSerializationTest` class is the core. Its methods like `BuildWireBytes`, `Deserialize`, `Serialize`, and `DeserializeAndRun` are strong indicators of serialization testing. The `TEST()` macros suggest these are unit tests.

3. **Analyze `WasmSerializationTest`:**  Dive deeper into the main class.
    * **`BuildWireBytes`:** This function seems to programmatically create a simple WebAssembly module with an exported "increment" function. It uses `WasmModuleBuilder`.
    * **`Deserialize`:** This function calls `DeserializeNativeModule`, which strongly implies it's responsible for taking serialized WebAssembly module data and turning it back into a usable module.
    * **`Serialize` (Implicit):**  While there's no explicit `Serialize` method in the `WasmSerializationTest` class itself, the `SetUp` method *performs* serialization within a temporary isolate and stores the result in `serialized_bytes_`. The calls to `compiled_module.Serialize()` are key.
    * **`DeserializeAndRun`:** This function combines deserialization with instantiation and execution of the WebAssembly module, demonstrating the end-to-end process.
    * **Methods for Invalidating Data:**  `InvalidateVersion`, `InvalidateWireBytes`, `PartlyDropTieringBudget` suggest tests are being performed on the robustness of the deserialization process against corrupted or incomplete data.
    * **`SetUp`:** This is a crucial function. It creates a temporary V8 isolate, compiles a WebAssembly module, serializes it, and then disposes of the temporary isolate. This is done specifically to test *deserialization* in a fresh isolate, ensuring that the serialized data contains all the necessary information.

4. **Connect to JavaScript:**  Think about how these C++ concepts relate to JavaScript's WebAssembly API.
    * **Compilation:** In JavaScript, you'd use `WebAssembly.compile()` or `WebAssembly.instantiate()` with raw bytecode. The C++ `SyncCompile` function mirrors this.
    * **Instantiation:**  `WebAssembly.instantiate()` in JavaScript corresponds to the `SyncInstantiate` in C++.
    * **Module Objects:**  The C++ `WasmModuleObject` has a direct analog in JavaScript's `WebAssembly.Module`.
    * **Instances:** Similarly, `WasmInstanceObject` corresponds to `WebAssembly.Instance`.
    * **Exports:** The "increment" export in the C++ code is accessed like any other WebAssembly export in JavaScript.
    * **Serialization (Implicit in JS API):** Although JavaScript doesn't have an explicit "serialize" API for `WebAssembly.Module`, the compiled module can be transferred or stored in various ways. The C++ code is testing the underlying mechanisms that would support such hypothetical serialization/deserialization scenarios within the engine.

5. **Construct the Summary:**  Based on the analysis, formulate a concise summary. Emphasize the core functionality: testing the serialization and deserialization of WebAssembly modules within V8. Highlight the key testing scenarios (valid module, invalid data, version mismatches, etc.).

6. **Create the JavaScript Example:**  Demonstrate the *equivalent* functionality using the JavaScript WebAssembly API. This involves:
    * **Fetching or defining WebAssembly bytecode:**  The C++ builds the bytecode programmatically, so you'd either fetch a `.wasm` file or create an `Uint8Array` representing the bytecode in JavaScript.
    * **Compiling the module:** Use `WebAssembly.compile()`.
    * **Instantiating the module:** Use `WebAssembly.instantiate()`.
    * **Accessing exports:** Access the exported function using dot notation on the `instance.exports` object.
    * **Calling the function:** Call the exported JavaScript function as you would any other function.

7. **Refine and Iterate:** Review the summary and the JavaScript example for clarity, accuracy, and completeness. Ensure the JavaScript example aligns with the C++ code's intent (e.g., calling the "increment" function). For example, initially, I might have forgotten to explicitly mention the temporary isolate setup in the `SetUp` function, which is a crucial detail. Iterating and rereading the code helps catch such omissions.
这个C++源代码文件 `test-wasm-serialization.cc` 的主要功能是**测试 V8 引擎中 WebAssembly 模块的序列化和反序列化功能**。

更具体地说，它包含了一系列的单元测试，用于验证以下场景：

* **成功地序列化和反序列化一个有效的 WebAssembly 模块:** 测试创建一个 WebAssembly 模块，将其序列化，然后在另一个 V8 隔离区反序列化，并确保反序列化后的模块可以正常运行。
* **处理反序列化时遇到的错误:** 测试各种错误情况，例如：
    * **版本不匹配:** 故意修改序列化数据中的版本信息，检查反序列化是否失败。
    * **缺少序列化数据:** 移除序列化数据，检查反序列化是否失败。
    * **序列化数据和原始字节码不一致:** 修改原始字节码，检查反序列化是否失败。
    * **在禁用 WebAssembly 代码生成的情况下反序列化:** 测试当 V8 配置不允许生成 WebAssembly 代码时，反序列化是否失败。
    * **部分 Tiering Budget 丢失:** 测试反序列化时部分优化信息丢失的情况。
* **跨隔离区传输编译后的 WebAssembly 模块:** 测试将一个隔离区中编译好的 WebAssembly 模块传递到另一个隔离区，并确保模块可以正常使用。
* **反序列化后代码的 Tier-down 行为:** 测试反序列化后的 WebAssembly 代码是否会根据需要进行优化级别的调整（Tier-down）。
* **序列化 Liftoff 编译的模块会失败:** 测试当模块只使用 Liftoff 编译器（一种快速但不完全优化的编译器）编译时，序列化会失败。
* **序列化 Tiering Budget 信息:** 测试序列化数据中包含了 WebAssembly 模块的性能优化信息（Tiering Budget），并在反序列化后能够正确恢复。
* **处理 Flags 或 Features 变化时的反序列化:** 测试当 V8 的配置选项或支持的 WebAssembly 功能发生变化时，反序列化是否会失败。
* **处理间接调用中 Canonical ID 的变化:** 测试在不同的编译上下文中，具有相同签名的间接调用是否能够正确反序列化。
* **保持序列化模块的 Detected Features 信息:** 测试序列化和反序列化后，模块检测到的 WebAssembly 功能是否能被正确保留，这对于延迟编译等场景非常重要。

**与 JavaScript 的关系及 JavaScript 示例**

虽然这个 C++ 文件本身是 V8 引擎的内部测试代码，但它所测试的序列化和反序列化功能直接关系到 JavaScript 中 WebAssembly 模块的使用。

在 JavaScript 中，我们通常使用 `WebAssembly.compile()` 或 `WebAssembly.instantiate()` 加载和编译 WebAssembly 模块。 然而，V8 引擎内部可能会将编译后的模块进行序列化缓存，以便在下次加载相同模块时能够更快地启动，而无需重新编译。

这个 C++ 测试文件就是为了确保 V8 引擎的这种内部序列化和反序列化机制能够正确可靠地工作。

**JavaScript 示例 (模拟概念)**

虽然 JavaScript API 中没有直接暴露 WebAssembly 模块的序列化和反序列化方法，但我们可以通过一些假设的 API 来理解其背后的概念：

```javascript
// 假设的 WebAssembly 模块序列化和反序列化 API (实际不存在)
async function serializeWasmModule(module) {
  // V8 内部会将 module 序列化为二进制数据
  return internalV8.serializeWasmModule(module);
}

async function deserializeWasmModule(serializedData) {
  // V8 内部会根据二进制数据重建 WebAssembly 模块
  return internalV8.deserializeWasmModule(serializedData);
}

async function runTest() {
  // 1. 定义 WebAssembly 字节码 (这里只是一个示例，实际会更复杂)
  const wasmBytes = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x07, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00,
    0x07, 0x0a, 0x01, 0x06, 0x69, 0x6e, 0x63, 0x72, 0x65, 0x6d, 0x00, 0x00,
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x41, 0x01, 0x6a, 0x0b
  ]);

  // 2. 编译 WebAssembly 模块
  const originalModule = await WebAssembly.compile(wasmBytes);

  // 3. 假设序列化模块 (V8 内部操作)
  const serializedData = await serializeWasmModule(originalModule);
  console.log("模块已序列化:", serializedData);

  // 4. 模拟在另一个上下文中反序列化模块
  const deserializedModule = await deserializeWasmModule(serializedData);
  console.log("模块已反序列化:", deserializedModule);

  // 5. 实例化反序列化后的模块
  const instance = await WebAssembly.instantiate(deserializedModule);

  // 6. 调用导出的函数
  const increment = instance.exports.increment;
  const result = increment(41);
  console.log("调用结果:", result); // 输出: 42
}

runTest();
```

在这个 JavaScript 示例中，我们模拟了 WebAssembly 模块的序列化和反序列化过程。虽然 JavaScript API 中没有直接提供 `serializeWasmModule` 和 `deserializeWasmModule` 这样的方法，但 V8 引擎在内部使用类似的技术来优化 WebAssembly 模块的加载速度。

总而言之，`test-wasm-serialization.cc` 是 V8 引擎中一个非常重要的测试文件，它确保了 WebAssembly 模块在被序列化和反序列化后依然能够保持其功能和性能，这对于提升 WebAssembly 应用的加载速度和整体性能至关重要。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-wasm-serialization.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>
#include <string.h>

#include "include/v8-wasm.h"
#include "src/api/api-inl.h"
#include "src/objects/objects-inl.h"
#include "src/snapshot/code-serializer.h"
#include "src/utils/version.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-serialization.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/common/wasm/wasm-module-runner.h"

namespace v8::internal::wasm {

// Approximate gtest TEST_F style, in case we adopt gtest.
class WasmSerializationTest {
 public:
  WasmSerializationTest() : zone_(&allocator_, ZONE_NAME) {
    // Don't call here if we move to gtest.
    SetUp();
  }

  static constexpr const char* kFunctionName = "increment";

  static void BuildWireBytes(Zone* zone, ZoneBuffer* buffer) {
    WasmModuleBuilder* builder = zone->New<WasmModuleBuilder>(zone);
    TestSignatures sigs;

    // Generate 3 functions, and export the last one with the name "increment".
    WasmFunctionBuilder* f;
    for (int i = 0; i < 3; ++i) {
      f = builder->AddFunction(sigs.i_i());
      f->EmitCode({WASM_LOCAL_GET(0), kExprI32Const, 1, kExprI32Add, kExprEnd});
    }
    builder->AddExport(base::CStrVector(kFunctionName), f);

    builder->WriteTo(buffer);
  }

  void ClearSerializedData() { serialized_bytes_ = {}; }

  void InvalidateVersion() {
    uint32_t* slot = reinterpret_cast<uint32_t*>(
        const_cast<uint8_t*>(serialized_bytes_.data()) +
        WasmSerializer::kVersionHashOffset);
    *slot = Version::Hash() + 1;
  }

  void InvalidateWireBytes() {
    memset(const_cast<uint8_t*>(wire_bytes_.data()), 0, wire_bytes_.size() / 2);
  }

  void PartlyDropTieringBudget() {
    serialized_bytes_ = {serialized_bytes_.data(),
                         serialized_bytes_.size() - 1};
  }

  MaybeHandle<WasmModuleObject> Deserialize(
      base::Vector<const char> source_url = {}) {
    return DeserializeNativeModule(
        CcTest::i_isolate(), base::VectorOf(serialized_bytes_),
        base::VectorOf(wire_bytes_), compile_imports_, source_url);
  }

  void DeserializeAndRun() {
    ErrorThrower thrower(CcTest::i_isolate(), "");
    Handle<WasmModuleObject> module_object;
    CHECK(Deserialize().ToHandle(&module_object));
    {
      DisallowGarbageCollection assume_no_gc;
      base::Vector<const uint8_t> deserialized_module_wire_bytes =
          module_object->native_module()->wire_bytes();
      CHECK_EQ(deserialized_module_wire_bytes.size(), wire_bytes_.size());
      CHECK_EQ(memcmp(deserialized_module_wire_bytes.begin(),
                      wire_bytes_.data(), wire_bytes_.size()),
               0);
    }
    Handle<WasmInstanceObject> instance =
        GetWasmEngine()
            ->SyncInstantiate(CcTest::i_isolate(), &thrower, module_object,
                              Handle<JSReceiver>::null(),
                              MaybeHandle<JSArrayBuffer>())
            .ToHandleChecked();
    Handle<Object> params[1] = {handle(Smi::FromInt(41), CcTest::i_isolate())};
    int32_t result = testing::CallWasmFunctionForTesting(
        CcTest::i_isolate(), instance, kFunctionName,
        base::ArrayVector(params));
    CHECK_EQ(42, result);
  }

  void CollectGarbage() {
    // Try hard to collect all garbage and will therefore also invoke all weak
    // callbacks of actually unreachable persistent handles.
    heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }

  v8::MemorySpan<const uint8_t> wire_bytes() const { return wire_bytes_; }

  CompileTimeImports MakeCompileTimeImports() { return CompileTimeImports{}; }

 private:
  Zone* zone() { return &zone_; }

  void SetUp() {
    CcTest::InitIsolateOnce();
    ZoneBuffer buffer(&zone_);
    WasmSerializationTest::BuildWireBytes(zone(), &buffer);

    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator =
        CcTest::i_isolate()->array_buffer_allocator();

    v8::Isolate* serialization_v8_isolate = v8::Isolate::New(create_params);
    Isolate* serialization_isolate =
        reinterpret_cast<Isolate*>(serialization_v8_isolate);
    ErrorThrower thrower(serialization_isolate, "");
    // Keep a weak pointer so we can check that the native module dies after
    // serialization (when the isolate is disposed).
    std::weak_ptr<NativeModule> weak_native_module;
    {
      v8::Isolate::Scope isolate_scope(serialization_v8_isolate);
      HandleScope scope(serialization_isolate);
      v8::Local<v8::Context> serialization_context =
          v8::Context::New(serialization_v8_isolate);
      serialization_context->Enter();

      auto enabled_features =
          WasmEnabledFeatures::FromIsolate(serialization_isolate);
      MaybeHandle<WasmModuleObject> maybe_module_object =
          GetWasmEngine()->SyncCompile(
              serialization_isolate, enabled_features, MakeCompileTimeImports(),
              &thrower, ModuleWireBytes(buffer.begin(), buffer.end()));
      Handle<WasmModuleObject> module_object =
          maybe_module_object.ToHandleChecked();
      weak_native_module = module_object->shared_native_module();
      // Check that the native module exists at this point.
      CHECK(weak_native_module.lock());

      v8::Local<v8::Object> v8_module_obj =
          v8::Utils::ToLocal(Cast<JSObject>(module_object));
      CHECK(v8_module_obj->IsWasmModuleObject());

      v8::Local<v8::WasmModuleObject> v8_module_object =
          v8_module_obj.As<v8::WasmModuleObject>();
      v8::CompiledWasmModule compiled_module =
          v8_module_object->GetCompiledModule();
      v8::MemorySpan<const uint8_t> uncompiled_bytes =
          compiled_module.GetWireBytesRef();
      uint8_t* bytes_copy =
          zone()->AllocateArray<uint8_t>(uncompiled_bytes.size());
      memcpy(bytes_copy, uncompiled_bytes.data(), uncompiled_bytes.size());
      wire_bytes_ = {bytes_copy, uncompiled_bytes.size()};

      // Run the code until tier-up (of the single function) was observed.
      Handle<WasmInstanceObject> instance =
          GetWasmEngine()
              ->SyncInstantiate(serialization_isolate, &thrower, module_object,
                                {}, {})
              .ToHandleChecked();
      CHECK_EQ(0, data_.size);
      while (data_.size == 0) {
        testing::CallWasmFunctionForTesting(serialization_isolate, instance,
                                            kFunctionName, {});
        data_ = compiled_module.Serialize();
      }
      CHECK_LT(0, data_.size);
    }
    // Dispose of serialization isolate to destroy the reference to the
    // NativeModule, which removes it from the module cache in the wasm engine
    // and forces de-serialization in the new isolate.
    serialization_v8_isolate->Dispose();

    // Busy-wait for the NativeModule to really die. Background threads might
    // temporarily keep it alive (happens very rarely, see
    // https://crbug.com/v8/10148).
    while (weak_native_module.lock()) {
    }

    serialized_bytes_ = {data_.buffer.get(), data_.size};

    v8::HandleScope new_scope(CcTest::isolate());
    v8::Local<v8::Context> deserialization_context =
        v8::Context::New(CcTest::isolate());
    deserialization_context->Enter();
  }

  v8::internal::AccountingAllocator allocator_;
  Zone zone_;
  // TODO(14179): Add tests for de/serializing modules with compile-time
  // imports.
  CompileTimeImports compile_imports_;
  v8::OwnedBuffer data_;
  v8::MemorySpan<const uint8_t> wire_bytes_ = {nullptr, 0};
  v8::MemorySpan<const uint8_t> serialized_bytes_ = {nullptr, 0};
  FlagScope<int> tier_up_quickly_{&v8_flags.wasm_tiering_budget, 1000};
};

TEST(DeserializeValidModule) {
  WasmSerializationTest test;
  {
    HandleScope scope(CcTest::i_isolate());
    test.DeserializeAndRun();
  }
  test.CollectGarbage();
}

TEST(DeserializeWithSourceUrl) {
  WasmSerializationTest test;
  {
    HandleScope scope(CcTest::i_isolate());
    const std::string url = "http://example.com/example.wasm";
    Handle<WasmModuleObject> module_object;
    CHECK(test.Deserialize(base::VectorOf(url)).ToHandle(&module_object));
    Tagged<String> url_str = Cast<String>(module_object->script()->name());
    CHECK_EQ(url, url_str->ToCString().get());
  }
  test.CollectGarbage();
}

TEST(DeserializeMismatchingVersion) {
  WasmSerializationTest test;
  {
    HandleScope scope(CcTest::i_isolate());
    test.InvalidateVersion();
    CHECK(test.Deserialize().is_null());
  }
  test.CollectGarbage();
}

TEST(DeserializeNoSerializedData) {
  WasmSerializationTest test;
  {
    HandleScope scope(CcTest::i_isolate());
    test.ClearSerializedData();
    CHECK(test.Deserialize().is_null());
  }
  test.CollectGarbage();
}

TEST(DeserializeWireBytesAndSerializedDataInvalid) {
  WasmSerializationTest test;
  {
    HandleScope scope(CcTest::i_isolate());
    test.InvalidateVersion();
    test.InvalidateWireBytes();
    CHECK(test.Deserialize().is_null());
  }
  test.CollectGarbage();
}

bool False(v8::Local<v8::Context> context, v8::Local<v8::String> source) {
  return false;
}

TEST(BlockWasmCodeGenAtDeserialization) {
  WasmSerializationTest test;
  {
    HandleScope scope(CcTest::i_isolate());
    CcTest::isolate()->SetAllowWasmCodeGenerationCallback(False);
    CHECK(test.Deserialize().is_null());
  }
  test.CollectGarbage();
}

UNINITIALIZED_TEST(CompiledWasmModulesTransfer) {
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);

  ZoneBuffer buffer(&zone);
  WasmSerializationTest::BuildWireBytes(&zone, &buffer);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* from_isolate = v8::Isolate::New(create_params);
  std::vector<v8::CompiledWasmModule> store;
  std::shared_ptr<NativeModule> original_native_module;
  {
    v8::Isolate::Scope isolate_scope(from_isolate);
    v8::HandleScope scope(from_isolate);
    LocalContext env(from_isolate);

    Isolate* from_i_isolate = reinterpret_cast<Isolate*>(from_isolate);
    testing::SetupIsolateForWasmModule(from_i_isolate);
    ErrorThrower thrower(from_i_isolate, "TestCompiledWasmModulesTransfer");
    auto enabled_features = WasmEnabledFeatures::FromIsolate(from_i_isolate);
    MaybeHandle<WasmModuleObject> maybe_module_object =
        GetWasmEngine()->SyncCompile(
            from_i_isolate, enabled_features, CompileTimeImports{}, &thrower,
            ModuleWireBytes(buffer.begin(), buffer.end()));
    Handle<WasmModuleObject> module_object =
        maybe_module_object.ToHandleChecked();
    v8::Local<v8::WasmModuleObject> v8_module =
        v8::Local<v8::WasmModuleObject>::Cast(
            v8::Utils::ToLocal(Cast<JSObject>(module_object)));
    store.push_back(v8_module->GetCompiledModule());
    original_native_module = module_object->shared_native_module();
  }

  {
    v8::Isolate* to_isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope isolate_scope(to_isolate);
      v8::HandleScope scope(to_isolate);
      LocalContext env(to_isolate);

      v8::MaybeLocal<v8::WasmModuleObject> transferred_module =
          v8::WasmModuleObject::FromCompiledModule(to_isolate, store[0]);
      CHECK(!transferred_module.IsEmpty());
      DirectHandle<WasmModuleObject> module_object = Cast<WasmModuleObject>(
          v8::Utils::OpenDirectHandle(*transferred_module.ToLocalChecked()));
      std::shared_ptr<NativeModule> transferred_native_module =
          module_object->shared_native_module();
      CHECK_EQ(original_native_module, transferred_native_module);
    }
    to_isolate->Dispose();
  }
  original_native_module.reset();
  from_isolate->Dispose();
}

TEST(TierDownAfterDeserialization) {
  WasmSerializationTest test;

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Handle<WasmModuleObject> module_object;
  CHECK(test.Deserialize().ToHandle(&module_object));

  auto* native_module = module_object->native_module();
  CHECK_EQ(3, native_module->module()->functions.size());
  WasmCodeRefScope code_ref_scope;
  // The deserialized code must be TurboFan (we wait for tier-up before
  // serializing).
  auto* turbofan_code = native_module->GetCode(2);
  CHECK_NOT_NULL(turbofan_code);
  CHECK_EQ(ExecutionTier::kTurbofan, turbofan_code->tier());

  GetWasmEngine()->EnterDebuggingForIsolate(isolate);

  // Entering debugging should delete all code, so that debug code gets compiled
  // lazily.
  CHECK_NULL(native_module->GetCode(0));
}

TEST(SerializeLiftoffModuleFails) {
  // Make sure that no function is tiered up to TurboFan.
  if (!v8_flags.liftoff) return;
  FlagScope<bool> no_tier_up(&v8_flags.wasm_tier_up, false);
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, "test_zone");

  CcTest::InitIsolateOnce();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  ZoneBuffer wire_bytes_buffer(&zone);
  WasmSerializationTest::BuildWireBytes(&zone, &wire_bytes_buffer);

  ErrorThrower thrower(isolate, "Test");
  MaybeHandle<WasmModuleObject> maybe_module_object =
      GetWasmEngine()->SyncCompile(
          isolate, WasmEnabledFeatures::All(), CompileTimeImports{}, &thrower,
          ModuleWireBytes(wire_bytes_buffer.begin(), wire_bytes_buffer.end()));
  DirectHandle<WasmModuleObject> module_object =
      maybe_module_object.ToHandleChecked();

  NativeModule* native_module = module_object->native_module();
  WasmSerializer wasm_serializer(native_module);
  size_t buffer_size = wasm_serializer.GetSerializedNativeModuleSize();
  std::unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_size]);
  // Serialization is expected to fail if there is no TurboFan function to
  // serialize.
  CHECK(!wasm_serializer.SerializeNativeModule({buffer.get(), buffer_size}));
}

TEST(SerializeTieringBudget) {
  WasmSerializationTest test;

  Isolate* isolate = CcTest::i_isolate();
  v8::OwnedBuffer serialized_bytes;
  uint32_t mock_budget[3]{1, 2, 3};
  {
    HandleScope scope(isolate);
    Handle<WasmModuleObject> module_object;
    CHECK(test.Deserialize().ToHandle(&module_object));

    auto* native_module = module_object->native_module();
    memcpy(native_module->tiering_budget_array(), mock_budget,
           arraysize(mock_budget) * sizeof(uint32_t));
    v8::Local<v8::Object> v8_module_obj =
        v8::Utils::ToLocal(Cast<JSObject>(module_object));
    CHECK(v8_module_obj->IsWasmModuleObject());

    v8::Local<v8::WasmModuleObject> v8_module_object =
        v8_module_obj.As<v8::WasmModuleObject>();
    serialized_bytes = v8_module_object->GetCompiledModule().Serialize();

    // Change one entry in the tiering budget after serialization to make sure
    // the module gets deserialized and not just loaded from the module cache.
    native_module->tiering_budget_array()[0]++;
  }
  // We need to invoke GC without stack, otherwise some objects may survive.
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      isolate->heap());
  test.CollectGarbage();
  HandleScope scope(isolate);
  Handle<WasmModuleObject> module_object;
  CompileTimeImports compile_imports = test.MakeCompileTimeImports();
  CHECK(
      DeserializeNativeModule(
          isolate,
          base::VectorOf(serialized_bytes.buffer.get(), serialized_bytes.size),
          base::VectorOf(test.wire_bytes()), compile_imports, {})
          .ToHandle(&module_object));

  auto* native_module = module_object->native_module();
  for (size_t i = 0; i < arraysize(mock_budget); ++i) {
    CHECK_EQ(mock_budget[i], native_module->tiering_budget_array()[i]);
  }
}

TEST(DeserializeTieringBudgetPartlyMissing) {
  WasmSerializationTest test;
  {
    HandleScope scope(CcTest::i_isolate());
    test.PartlyDropTieringBudget();
    CHECK(test.Deserialize().is_null());
  }
  test.CollectGarbage();
}

TEST(SerializationFailsOnChangedFlags) {
  WasmSerializationTest test;
  {
    HandleScope scope(CcTest::i_isolate());

    FlagScope<bool> no_bounds_checks(&v8_flags.wasm_bounds_checks, false);
    CHECK(test.Deserialize().is_null());

    FlagScope<bool> bounds_checks(&v8_flags.wasm_bounds_checks, true);
    CHECK(!test.Deserialize().is_null());
  }
}

TEST(SerializationFailsOnChangedFeatures) {
  WasmSerializationTest test;
  {
    HandleScope scope(CcTest::i_isolate());

    CcTest::isolate()->SetWasmImportedStringsEnabledCallback(
        [](auto) { return true; });
    CHECK(test.Deserialize().is_null());

    CcTest::isolate()->SetWasmImportedStringsEnabledCallback(
        [](auto) { return false; });
    CHECK(!test.Deserialize().is_null());
  }
}

TEST(DeserializeIndirectCallWithDifferentCanonicalId) {
  // This test compiles and serializes a module with an indirect call, then
  // resets the type canonicalizer, compiles another module, and then
  // deserializes the original module. This ensures that a different canonical
  // signature ID is used for the indirect call.
  // We then call the deserialized module to check that the right canonical
  // signature ID is being used.

  // Compile with Turbofan right away.
  FlagScope<bool> no_liftoff{&v8_flags.liftoff, false};
  FlagScope<bool> no_lazy_compilation{&v8_flags.wasm_lazy_compilation, false};
  FlagScope<bool> expose_gc{&v8_flags.expose_gc, true};

  i::Isolate* i_isolate = CcTest::InitIsolateOnce();
  v8::Isolate* v8_isolate = CcTest::isolate();
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  HandleScope scope(i_isolate);

  // Build a small module with an indirect call.
  ZoneBuffer buffer(&zone);
  {
    WasmModuleBuilder builder{&zone};
    TestSignatures sigs;

    // Add the "call_indirect" function which calls table0[0].
    ModuleTypeIndex sig_id = builder.AddSignature(sigs.i_i(), true);
    WasmFunctionBuilder* f = builder.AddFunction(sig_id);
    f->EmitCode({// (i) => i != 0 ? f(i-1) : 42
                 WASM_IF_ELSE_I(
                     // cond:
                     WASM_LOCAL_GET(0),
                     // if_true:
                     WASM_CALL_INDIRECT(
                         SIG_INDEX(sig_id.index),
                         WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_ONE), WASM_ZERO),
                     // if_false:
                     WASM_I32V_1(42)),
                 WASM_END});
    builder.AddExport(base::CStrVector("call_indirect"), f);
    // Add a function table.
    uint32_t table_id = builder.AddTable(kWasmFuncRef, 1);
    builder.SetIndirectFunction(
        table_id, 0, f->func_index(),
        WasmModuleBuilder::WasmElemSegment::kRelativeToImports);
    // Write the final module into {buffer}.
    builder.WriteTo(&buffer);
  }

  // Compile the module and serialize it.
  // Keep a weak pointer so we can check that the original native module died.
  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);
  std::weak_ptr<NativeModule> weak_native_module;
  v8::OwnedBuffer serialized_module;
  CanonicalTypeIndex canonical_sig_id_before_serialization;
  {
    ErrorThrower thrower(i_isolate, "");

    {
      v8::Isolate::Scope isolate_scope(v8_isolate);
      HandleScope scope(i_isolate);
      v8::Local<v8::Context> serialization_context =
          v8::Context::New(v8_isolate);
      serialization_context->Enter();

      Handle<WasmModuleObject> module_object =
          GetWasmEngine()
              ->SyncCompile(i_isolate, enabled_features, CompileTimeImports{},
                            &thrower,
                            ModuleWireBytes(buffer.begin(), buffer.end()))
              .ToHandleChecked();
      weak_native_module = module_object->shared_native_module();

      // Retrieve the canonicalized signature ID.
      const std::vector<CanonicalTypeIndex>& canonical_type_ids =
          module_object->native_module()
              ->module()
              ->isorecursive_canonical_type_ids;
      CHECK_EQ(1, canonical_type_ids.size());
      canonical_sig_id_before_serialization = canonical_type_ids[0];

      // Check that the embedded constant in the code is right.
      WasmCodeRefScope code_ref_scope;
      WasmCode* code = module_object->native_module()->GetCode(0);
      RelocIterator reloc_it{
          code->instructions(), code->reloc_info(), code->constant_pool(),
          RelocInfo::ModeMask(RelocInfo::WASM_CANONICAL_SIG_ID)};
      CHECK(!reloc_it.done());
      CHECK_EQ(canonical_sig_id_before_serialization.index,
               reloc_it.rinfo()->wasm_canonical_sig_id());
      reloc_it.next();
      CHECK(reloc_it.done());

      // Convert to API objects and serialize.
      v8::Local<v8::WasmModuleObject> v8_module_object =
          v8::Utils::ToLocal(module_object);
      serialized_module = v8_module_object->GetCompiledModule().Serialize();
    }

    CHECK_LT(0, serialized_module.size);

    // Run GC until the NativeModule died. Add a manual timeout of 60 seconds to
    // get a better error message than just a test timeout if this fails.
    const auto start_time = std::chrono::steady_clock::now();
    const auto end_time = start_time + std::chrono::seconds(60);
    while (weak_native_module.lock()) {
      v8_isolate->RequestGarbageCollectionForTesting(
          v8::Isolate::kFullGarbageCollection);
      if (std::chrono::steady_clock::now() > end_time) {
        FATAL("NativeModule did not die within 60 seconds");
      }
    }
  }

  // Clear canonicalized types, then compile another module which adds a
  // canonical type at the same index we used in the previous module.
  GetTypeCanonicalizer()->EmptyStorageForTesting();
  {
    ZoneBuffer buffer(&zone);
    WasmModuleBuilder builder{&zone};
    TestSignatures sigs;

    ModuleTypeIndex sig_id = builder.AddSignature(sigs.v_v(), true);
    WasmFunctionBuilder* f = builder.AddFunction(sig_id);
    f->EmitByte(kExprEnd);
    builder.WriteTo(&buffer);
    ErrorThrower thrower(i_isolate, "");
    GetWasmEngine()
        ->SyncCompile(i_isolate, enabled_features, CompileTimeImports{},
                      &thrower, ModuleWireBytes(buffer.begin(), buffer.end()))
        .ToHandleChecked();
  }

  // Now deserialize the previous module.
  CanonicalTypeIndex canonical_sig_id_after_deserialization{
      canonical_sig_id_before_serialization.index + 1};
  {
    v8::Local<v8::Context> deserialization_context =
        v8::Context::New(CcTest::isolate());
    deserialization_context->Enter();
    ErrorThrower thrower(CcTest::i_isolate(), "");
    base::Vector<const char> kNoSourceUrl;
    Handle<WasmModuleObject> module_object =
        DeserializeNativeModule(CcTest::i_isolate(),
                                base::VectorOf(serialized_module.buffer.get(),
                                               serialized_module.size),
                                base::VectorOf(buffer), CompileTimeImports{},
                                kNoSourceUrl)
            .ToHandleChecked();

    // Check that the signature ID got canonicalized to index 1.
    const std::vector<CanonicalTypeIndex>& canonical_type_ids =
        module_object->native_module()
            ->module()
            ->isorecursive_canonical_type_ids;
    CHECK_EQ(1, canonical_type_ids.size());
    CHECK_EQ(canonical_sig_id_after_deserialization, canonical_type_ids[0]);

    // Check that the embedded constant in the code is right.
    WasmCodeRefScope code_ref_scope;
    WasmCode* code = module_object->native_module()->GetCode(0);
    RelocIterator reloc_it{
        code->instructions(), code->reloc_info(), code->constant_pool(),
        RelocInfo::ModeMask(RelocInfo::WASM_CANONICAL_SIG_ID)};
    CHECK(!reloc_it.done());
    CHECK_EQ(canonical_sig_id_after_deserialization.index,
             reloc_it.rinfo()->wasm_canonical_sig_id());
    reloc_it.next();
    CHECK(reloc_it.done());

    // Now call the function.
    Handle<WasmInstanceObject> instance =
        GetWasmEngine()
            ->SyncInstantiate(CcTest::i_isolate(), &thrower, module_object,
                              Handle<JSReceiver>::null(),
                              MaybeHandle<JSArrayBuffer>())
            .ToHandleChecked();
    Handle<Object> params[1] = {handle(Smi::FromInt(1), i_isolate)};
    int32_t result = testing::CallWasmFunctionForTesting(
        i_isolate, instance, "call_indirect", base::ArrayVector(params));
    CHECK_EQ(42, result);
  }
}

// Regression test for https://crbug.com/372840600 /
// https://crbug.com/369793713 / https://crbug.com/369869947.
TEST(SerializeDetectedFeatures) {
  // This test compiles and serializes a module which uses a use-counter-tracked
  // feature (tail calls). We check that the set of detected features is
  // preserved across serialization and deserialization. Otherwise we would
  // fail a DCHECK in lazy compilation later.

  FlagScope<int> tier_up_quickly{&v8_flags.wasm_tiering_budget, 10};
  FlagScope<bool> expose_gc{&v8_flags.expose_gc, true};

  i::Isolate* i_isolate = CcTest::InitIsolateOnce();
  v8::Isolate* v8_isolate = CcTest::isolate();
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  HandleScope scope(i_isolate);

  // Build a small module with a tail call.
  ZoneBuffer buffer(&zone);
  {
    WasmModuleBuilder builder{&zone};

    // Add a function which is tail-called by another one.
    ModuleTypeIndex sig_i_v = builder.AddSignature(TestSignatures::i_v(), true);
    WasmFunctionBuilder* a = builder.AddFunction(sig_i_v);
    a->EmitCode({WASM_I32V_1(11), WASM_END});
    builder.AddExport(base::CStrVector("a"), a);
    // Add the function which tail-calls the first one.
    WasmFunctionBuilder* b = builder.AddFunction(sig_i_v);
    b->EmitCode({WASM_RETURN_CALL_FUNCTION0(a->func_index()), WASM_END});
    builder.AddExport(base::CStrVector("b"), b);
    // Write the final module into {buffer}.
    builder.WriteTo(&buffer);
  }

  // Compile and initialize the module and serialize it.
  // Keep a weak pointer so we can check that the original native module died.
  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);
  std::weak_ptr<NativeModule> weak_native_module;
  v8::OwnedBuffer serialized_module;
  {
    ErrorThrower thrower(i_isolate, "");

    {
      v8::Isolate::Scope isolate_scope(v8_isolate);
      HandleScope scope(i_isolate);
      v8::Local<v8::Context> serialization_context =
          v8::Context::New(v8_isolate);
      serialization_context->Enter();

      Handle<WasmModuleObject> module_object =
          GetWasmEngine()
              ->SyncCompile(i_isolate, enabled_features, CompileTimeImports{},
                            &thrower,
                            ModuleWireBytes(buffer.begin(), buffer.end()))
              .ToHandleChecked();
      // Check that "return_call" is in the set of detected features.
      CHECK_EQ(WasmDetectedFeatures{{WasmDetectedFeature::return_call}},
               module_object->native_module()
                   ->compilation_state()
                   ->detected_features());
      weak_native_module = module_object->shared_native_module();

      // Now call the tail-calling function "b". This triggers lazy compilation,
      // which should not DCHECK because of a new detected feature.
      Handle<WasmInstanceObject> instance =
          GetWasmEngine()
              ->SyncInstantiate(CcTest::i_isolate(), &thrower, module_object,
                                Handle<JSReceiver>::null(),
                                MaybeHandle<JSArrayBuffer>())
              .ToHandleChecked();

      v8::Local<v8::WasmModuleObject> v8_module_object =
          v8::Utils::ToLocal(module_object);
      // Call function "a" until serialization succeeds (once we have TF code).
      const auto start_time = std::chrono::steady_clock::now();
      const auto end_time = start_time + std::chrono::seconds(60);
      while (true) {
        int32_t result = testing::CallWasmFunctionForTesting(
            i_isolate, instance, "a",
            base::VectorOf<Handle<Object>>(nullptr, 0));
        CHECK_EQ(11, result);
        serialized_module = v8_module_object->GetCompiledModule().Serialize();
        if (serialized_module.size != 0) break;
        v8_isolate->RequestGarbageCollectionForTesting(
            v8::Isolate::kFullGarbageCollection);
        if (std::chrono::steady_clock::now() > end_time) {
          FATAL("Tier-up didn't complete within 60 seconds");
        }
      }
    }

    CHECK_LT(0, serialized_module.size);

    // Run GC until the NativeModule died. Add a manual timeout of 60 seconds to
    // get a better error message than just a test timeout if this fails.
    const auto start_time = std::chrono::steady_clock::now();
    const auto end_time = start_time + std::chrono::seconds(60);
    while (weak_native_module.lock()) {
      v8_isolate->RequestGarbageCollectionForTesting(
          v8::Isolate::kFullGarbageCollection);
      if (std::chrono::steady_clock::now() > end_time) {
        FATAL("NativeModule did not die within 60 seconds");
      }
    }
  }

  // Now deserialize the module and check the detected features again.
  {
    v8::Local<v8::Context> deserialization_context =
        v8::Context::New(CcTest::isolate());
    deserialization_context->Enter();
    ErrorThrower thrower(CcTest::i_isolate(), "");
    base::Vector<const char> kNoSourceUrl;
    Handle<WasmModuleObject> module_object =
        DeserializeNativeModule(CcTest::i_isolate(),
                                base::VectorOf(serialized_module.buffer.get(),
                                               serialized_module.size),
                                base::VectorOf(buffer), CompileTimeImports{},
                                kNoSourceUrl)
            .ToHandleChecked();

    CHECK_EQ(WasmDetectedFeatures{{WasmDetectedFeature::return_call}},
             module_object->native_module()
                 ->compilation_state()
                 ->detected_features());

    // Now call the tail-calling function "b". This triggers lazy compilation,
    // which should not DCHECK because of a new detected feature.
    Handle<WasmInstanceObject> instance =
        GetWasmEngine()
            ->SyncInstantiate(CcTest::i_isolate(), &thrower, module_object,
                              Handle<JSReceiver>::null(),
                              MaybeHandle<JSArrayBuffer>())
            .ToHandleChecked();
    int32_t result = testing::CallWasmFunctionForTesting(
        i_isolate, instance, "b", base::VectorOf<Handle<Object>>(nullptr, 0));
    CHECK_EQ(11, result);
  }
}

}  // namespace v8::internal::wasm

"""

```
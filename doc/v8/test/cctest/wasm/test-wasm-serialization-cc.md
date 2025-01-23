Response:
The user wants to understand the functionality of the C++ code snippet `v8/test/cctest/wasm/test-wasm-serialization.cc`. I need to analyze the code and explain its purpose, relating it to WebAssembly serialization in V8. I also need to address the user's specific questions about `.tq` files, JavaScript relevance, code logic inference, and common programming errors.

Here's a breakdown of my thought process:

1. **Identify the core purpose:** The filename and the content (e.g., `WasmSerializer`, `DeserializeNativeModule`, `WasmModuleObject`) clearly indicate this file tests the serialization and deserialization of WebAssembly modules in V8.

2. **Examine the test structure:** The code uses a class `WasmSerializationTest` to encapsulate setup and test helper functions. Individual tests are defined using the `TEST()` macro. This suggests a focus on unit testing specific scenarios.

3. **Analyze key functions and data structures:**
    * `BuildWireBytes`: Creates the binary representation of a simple WebAssembly module. This is the input for serialization.
    * `SerializeNativeModule` (indirectly through `GetCompiledModule().Serialize()`):  This is the core serialization function.
    * `DeserializeNativeModule`: The counterpart for deserialization.
    * `WasmModuleObject`:  Represents a compiled WebAssembly module in V8.
    * `NativeModule`:  Internal representation of the compiled Wasm module.
    * `WasmSerializer`:  Handles the serialization process.
    * Various `Invalidate...` functions:  Used to create invalid serialization data for testing error handling.

4. **Map tests to functionalities:** Each `TEST()` function focuses on a specific aspect of serialization:
    * `DeserializeValidModule`: Basic successful deserialization.
    * `DeserializeWithSourceUrl`: Deserialization with source URL information.
    * `DeserializeMismatchingVersion`: Handling of version mismatches.
    * `DeserializeNoSerializedData`: Handling of missing serialized data.
    * `DeserializeWireBytesAndSerializedDataInvalid`: Handling of invalid input data.
    * `BlockWasmCodeGenAtDeserialization`:  Testing the ability to block code generation during deserialization.
    * `CompiledWasmModulesTransfer`: Testing the transfer of compiled modules between isolates.
    * `TierDownAfterDeserialization`: Verifying that code can tier down after deserialization.
    * `SerializeLiftoffModuleFails`: Ensuring that serialization fails if only Liftoff code exists.
    * `SerializeTieringBudget`: Testing the serialization and deserialization of tiering budget information.
    * `DeserializeTieringBudgetPartlyMissing`: Handling of incomplete tiering budget data.
    * `SerializationFailsOnChangedFlags`:  Ensuring serialization is invalidated by flag changes.
    * `SerializationFailsOnChangedFeatures`: Ensuring serialization is invalidated by feature changes.
    * `DeserializeIndirectCallWithDifferentCanonicalId`:  Testing handling of indirect calls with potentially different canonical signature IDs.
    * `SerializeDetectedFeatures`: Testing the persistence of detected features across serialization.

5. **Address specific questions:**
    * **`.tq` files:**  Explain that `.tq` files are for Torque, a V8-specific language, and the current file is C++.
    * **JavaScript relevance:**  Explain the connection to JavaScript through the `v8::WasmModuleObject` API and how JavaScript can interact with WebAssembly modules. Provide a simple JavaScript example of instantiation.
    * **Code logic inference:** Choose a simple test case (like `DeserializeValidModule`) and walk through the setup, serialization, and deserialization steps, including the expected input (the wire bytes) and the output (a successfully instantiated module).
    * **Common programming errors:**  Focus on errors related to data integrity during serialization/deserialization, such as version mismatches or corrupted data, and provide C++ examples of how these might occur.

6. **Structure the response:** Organize the information logically, starting with a general overview of the file's purpose, then detailing the functionalities, addressing the specific questions, and finally summarizing the findings. Use clear and concise language.
这个 C++ 代码文件 `v8/test/cctest/wasm/test-wasm-serialization.cc` 的主要功能是 **测试 V8 引擎中 WebAssembly 模块的序列化和反序列化机制**。

具体来说，它包含了各种测试用例，用于验证在不同场景下，WebAssembly 模块能否被正确地序列化成字节流，并在之后被成功地反序列化回可用的模块对象。

以下是该文件主要功能点的详细列举：

* **构建 WebAssembly 模块的二进制表示 (Wire Bytes):**  `BuildWireBytes` 函数用于创建一个简单的 WebAssembly 模块的二进制表示，这个模块包含一个名为 "increment" 的导出函数。这个二进制数据将作为序列化的原始输入。
* **序列化 WebAssembly 模块:**  测试用例中会调用 V8 提供的接口来序列化编译后的 WebAssembly 模块。这通常涉及到将模块的元数据、代码等信息转换为字节流。
* **反序列化 WebAssembly 模块:**  测试用例的核心在于反序列化过程。它们尝试从之前序列化得到的字节流中重新构建 `WasmModuleObject`。
* **验证反序列化后的模块:**  测试用例会检查反序列化后的模块是否与原始模块一致，例如：
    * **执行功能:**  调用反序列化后的模块中的导出函数，验证其行为是否正确。
    * **模块结构:**  检查反序列化后的模块的内部结构，例如 Wire Bytes 是否一致。
    * **元数据:**  验证模块的源 URL 等信息是否被正确保留。
* **测试序列化和反序列化的各种边界情况和错误处理:**
    * **版本不匹配:**  测试当序列化和反序列化时 V8 版本不一致的情况。
    * **缺少序列化数据:**  测试尝试反序列化空数据的情况。
    * **序列化数据或 Wire Bytes 损坏:**  模拟数据损坏的情况，验证反序列化是否会失败。
    * **禁用 WebAssembly 代码生成:**  测试在反序列化时禁止代码生成的情况。
    * **在不同 Isolate 之间传输编译后的模块:**  测试编译后的 WebAssembly 模块在不同 V8 Isolate 之间的传输和使用。
    * **反序列化后代码的降级 (Tier-Down):** 测试反序列化后的代码是否可以根据需要进行优化或降级。
    * **序列化 Liftoff 编译的模块:**  验证是否能正确处理只使用 Liftoff 编译的模块的序列化。
    * **序列化分层编译预算 (Tiering Budget):**  测试分层编译相关的数据是否能被正确序列化和反序列化。
    * **部分缺少分层编译预算:** 测试部分分层编译预算丢失的情况。
    * **V8 Flag 或 Feature 改变时的序列化失败:**  验证当影响 WebAssembly 编译的 V8 Flag 或 Feature 发生变化时，反序列化是否会失败。
    * **处理具有不同规范 ID 的间接调用:** 测试在序列化和反序列化之间，如果类型规范化器的状态发生变化，间接调用是否仍然能正确工作。
    * **序列化检测到的特性 (Detected Features):** 测试模块中使用的特性信息是否能在序列化和反序列化之间被正确保留。

**关于 .tq 结尾的文件：**

如果 `v8/test/cctest/wasm/test-wasm-serialization.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码文件**。Torque 是 V8 开发的一种领域特定语言，用于生成 V8 的内置函数和类型检查代码。但根据你提供的文件内容来看，该文件以 `.cc` 结尾，因此是 **C++ 源代码文件**。

**与 JavaScript 的功能关系：**

`v8/test/cctest/wasm/test-wasm-serialization.cc` 测试的是 V8 引擎的内部机制，但这直接关系到 JavaScript 中使用 WebAssembly 的能力。在 JavaScript 中，你可以编译和实例化 WebAssembly 模块。V8 引擎负责处理这些操作，包括将编译后的模块进行缓存和潜在的序列化，以便在将来更快地加载。

**JavaScript 示例：**

```javascript
async function loadAndRunWasm() {
  // 假设 wasmBytes 是一个包含 WebAssembly 模块字节码的 Uint8Array
  const response = await fetch('path/to/your/module.wasm');
  const wasmBytes = new Uint8Array(await response.arrayBuffer());

  // 编译 WebAssembly 模块
  const wasmModule = await WebAssembly.compile(wasmBytes);

  // 实例化 WebAssembly 模块
  const wasmInstance = await WebAssembly.instantiate(wasmModule);

  // 调用导出的函数
  const result = wasmInstance.exports.increment(41);
  console.log(result); // 输出 42 (假设模块中 increment 函数的功能是将输入加 1)
}

loadAndRunWasm();
```

V8 引擎在内部处理 `WebAssembly.compile` 时，可能会将编译后的模块序列化到缓存中。当下次尝试加载相同的模块时，如果缓存命中，V8 可以直接从缓存中反序列化模块，而无需重新编译，从而提高性能。`v8/test/cctest/wasm/test-wasm-serialization.cc` 就是在测试这个内部序列化和反序列化的过程。

**代码逻辑推理 (以 `DeserializeValidModule` 测试为例):**

**假设输入:**

1. 使用 `BuildWireBytes` 函数生成的 WebAssembly 模块的二进制表示 (Wire Bytes)。这个二进制表示包含一个简单的模块，导出一个名为 "increment" 的函数，该函数将输入加 1。
2. 通过 `SetUp` 函数中的步骤，编译该模块并序列化，生成 `serialized_bytes_`。

**预期输出:**

1. `Deserialize()` 函数应该成功返回一个 `WasmModuleObject` 的 `MaybeHandle`。
2. `DeserializeAndRun()` 函数应该：
    * 成功反序列化模块。
    * 验证反序列化后的模块的 Wire Bytes 与原始 Wire Bytes 一致。
    * 成功实例化反序列化后的模块。
    * 成功调用名为 "increment" 的导出函数，并将输入 41 传递给它。
    * 函数返回结果为 42。

**代码逻辑流程 (简化):**

1. `WasmSerializationTest test;` 创建测试对象，`SetUp` 函数会编译并序列化 WebAssembly 模块。
2. `TEST(DeserializeValidModule)` 开始执行。
3. `test.DeserializeAndRun();` 被调用。
4. `Deserialize()` 函数使用 `DeserializeNativeModule` 尝试反序列化之前序列化的数据。
5. 如果反序列化成功，`Deserialize().ToHandle(&module_object)` 将 `WasmModuleObject` 赋值给 `module_object`。
6. 检查反序列化后的模块的 Wire Bytes 是否与原始的 `wire_bytes_` 一致。
7. `GetWasmEngine()->SyncInstantiate(...)` 实例化反序列化后的模块。
8. `testing::CallWasmFunctionForTesting(...)` 调用 "increment" 函数，输入 41。
9. 验证函数返回结果是否为 42。
10. `test.CollectGarbage();` 进行垃圾回收，确保没有内存泄漏。

**涉及用户常见的编程错误：**

虽然这个测试文件本身是 V8 引擎的内部测试，但它所测试的功能与用户在使用 WebAssembly 时可能遇到的问题相关。以下是一些可能的用户编程错误，与此文件测试的场景相关：

1. **尝试加载不兼容的序列化数据:**  如果用户尝试加载由不同版本的 V8 引擎序列化的 WebAssembly 模块数据，可能会遇到反序列化失败的情况，这类似于 `DeserializeMismatchingVersion` 测试所模拟的场景。
   ```javascript
   // 假设 serializedData 是从旧版本 V8 导出的数据
   try {
     const wasmModule = await WebAssembly.compile(serializedData);
   } catch (error) {
     console.error("Error compiling WebAssembly module:", error); // 可能会因为版本不兼容而失败
   }
   ```

2. **操作或修改序列化后的数据:** 用户不应该手动修改序列化后的字节流，因为这很可能导致反序列化失败，类似于 `DeserializeWireBytesAndSerializedDataInvalid` 测试所模拟的场景。

3. **假设序列化数据在不同环境下总是有效:**  用户可能会错误地认为，在一个环境中序列化的 WebAssembly 模块数据可以在任何其他环境中无条件地加载。然而，V8 引擎可能会因为安全原因或内部状态的差异而拒绝加载某些序列化数据，例如 `SerializationFailsOnChangedFlags` 和 `SerializationFailsOnChangedFeatures` 测试所验证的情况。

4. **不正确地处理编译和实例化的生命周期:**  虽然与直接的序列化错误不同，但用户可能会遇到与 WebAssembly 模块生命周期管理相关的问题，例如过早地释放资源，导致之后尝试反序列化或使用模块时出错。

总而言之，`v8/test/cctest/wasm/test-wasm-serialization.cc` 是 V8 引擎中一个重要的测试文件，它确保了 WebAssembly 模块的序列化和反序列化机制的正确性和健壮性，这对于提高 WebAssembly 的加载性能和确保其在不同环境下的兼容性至关重要。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-wasm-serialization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-wasm-serialization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```
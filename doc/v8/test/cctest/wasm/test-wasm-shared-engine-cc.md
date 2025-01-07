Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionalities of the given C++ file (`test-wasm-shared-engine.cc`), its potential connection to Torque, JavaScript examples if applicable, logical reasoning with input/output, and common programming errors it might reveal.

2. **Initial Code Scan (Keywords and Structure):**
   - Look for key namespaces: `v8::internal::wasm::test_wasm_shared_engine`. This immediately tells us it's a WebAssembly testing file within the V8 engine.
   - Spot important classes: `SharedEngineIsolate`, `SharedEngineThread`, `SharedModule`. These are likely the core components being tested.
   - Notice the `TEST(...)` macros. This confirms it's a gtest-based test suite.
   - Identify helper functions: `BuildReturnConstantModule`, `CompileAndInstantiateAsync`, `PumpMessageLoop`. These suggest common operations being performed in the tests.

3. **Deep Dive into Key Classes:**

   - **`SharedModule`:**  The comment clearly states this is a `std::shared_ptr<NativeModule>`, representing a WebAssembly module shared between isolates. This is a central concept.

   - **`SharedEngineIsolate`:**
     - The constructor initializes a V8 isolate specifically for WASM module testing. It sets up necessary components like the array buffer allocator and a context.
     - `CompileAndInstantiate`: This method compiles and instantiates a WASM module *synchronously*. It takes a `ZoneBuffer` (containing the WASM bytecode).
     - `ImportInstance`: This method imports a previously compiled `SharedModule` into the current isolate. This highlights the "shared" aspect.
     - `ExportInstance`: This method takes a `WasmInstanceObject` and extracts the `SharedModule` from it, making it shareable.
     - `Run`: Executes the "main" function of a WASM instance.

   - **`SharedEngineThread`:** This class creates a separate thread, each running its own `SharedEngineIsolate`. The constructor takes a callback function, allowing different operations to be performed within each thread.

4. **Analyze the Test Cases (`TEST(...)`):**

   - **`SharedEngineRunSeparated`:**  Tests that two different isolates can independently compile and run WASM modules. This verifies basic WASM functionality within separate environments.

   - **`SharedEngineRunImported`:** Demonstrates the core "shared engine" concept. One isolate compiles a module, exports it as a `SharedModule`, and another isolate imports and runs it.

   - **`SharedEngineRunThreadedBuildingSync`:**  Two threads concurrently compile and instantiate WASM modules *synchronously*. This tests the thread-safety of synchronous compilation in a shared engine context.

   - **`SharedEngineRunThreadedBuildingAsync`:**  Similar to the previous test, but uses *asynchronous* compilation. This introduces the complexities of asynchronous operations in a multi-threaded environment. The `CompileAndInstantiateAsync` function and the `PumpMessageLoop` helper are key here.

   - **`SharedEngineRunThreadedExecution`:** One isolate compiles and exports a module. Multiple threads then import and execute *the same* module. This directly validates the shared module concept for execution.

   - **`SharedEngineRunThreadedTierUp`:**  Focuses on the interaction between shared modules and V8's tiered compilation (where code is initially compiled quickly and later optimized). Multiple threads execute a shared module, and one thread explicitly triggers Turbofan compilation.

5. **Identify Potential JavaScript Connections:**

   - WASM is designed to be used with JavaScript. The core idea of compiling and running WASM modules in V8 directly relates to how JavaScript interacts with WASM. The `WebAssembly` API in JavaScript allows loading, compiling, and instantiating WASM modules.

6. **Consider Logical Reasoning (Input/Output):**

   - The `BuildReturnConstantModule` function provides a good example. Given an integer `constant`, it generates WASM bytecode that returns that constant. The tests then verify that running the compiled module produces the expected constant.

7. **Think About Common Programming Errors:**

   - **Race conditions:**  The multi-threaded tests immediately bring this to mind. If the shared engine or the module objects weren't properly thread-safe, you'd see unpredictable results or crashes.
   - **Incorrect memory management:** Sharing modules means careful handling of lifetimes and potential dangling pointers. The use of `std::shared_ptr` for `SharedModule` suggests an attempt to mitigate this.
   - **Asynchronous programming issues:** The asynchronous compilation tests could expose errors related to callbacks, promises (though not explicitly used here), and ensuring operations complete in the correct order.

8. **Structure the Output:** Organize the findings into the categories requested: functionality, Torque connection, JavaScript examples, logical reasoning, and common errors. Use clear and concise language.

9. **Refine and Review:** Read through the analysis to ensure accuracy and completeness. Check for any inconsistencies or areas that could be explained more clearly. For instance,  emphasize the role of the `WasmEngine` in managing shared modules.

By following these steps, systematically examining the code, and relating it to the broader context of WebAssembly and V8, one can arrive at a comprehensive understanding of the file's purpose and functionality.
好的，让我们来分析一下 `v8/test/cctest/wasm/test-wasm-shared-engine.cc` 这个 V8 源代码文件的功能。

**功能概览:**

该文件包含了针对 V8 中 WebAssembly 共享引擎的集成测试 (cctest)。其主要目的是测试在多个隔离（Isolate）之间共享 WebAssembly 模块的功能是否正常，以及在多线程环境下使用共享引擎的正确性。

**核心功能点:**

1. **共享 WebAssembly 模块:**  测试了将编译后的 WebAssembly 模块在不同的 V8 Isolate 之间共享的能力。这意味着多个 Isolate 可以加载和执行同一个编译后的模块，而无需重复编译。

2. **多 Isolate 测试:** 通过创建多个 `SharedEngineIsolate` 实例，模拟了在不同 Isolate 中使用共享模块的场景。

3. **多线程测试:**  使用了 `SharedEngineThread` 类来创建和管理多个线程，并在这些线程中测试共享模块的编译、实例化和执行。这验证了共享引擎在并发环境下的线程安全性。

4. **同步和异步编译:**  测试了同步和异步两种编译 WebAssembly 模块的方式，并验证了共享模块在这两种模式下的行为。

5. **模块的导入和导出:**  测试了如何将一个 Isolate 中编译的模块导出为共享模块，然后在另一个 Isolate 中导入并使用。

6. **执行 WebAssembly 代码:**  验证了在共享模块的不同实例中执行 WebAssembly 函数的行为，并确保结果的正确性。

7. **分层编译 (Tier-Up):**  测试了在多线程环境下，对共享模块进行分层编译（例如从解释执行到 TurboFan 优化编译）的场景。

**Torque 关联:**

这个文件以 `.cc` 结尾，这意味着它是一个 C++ 源文件，而不是 Torque 源文件。如果它以 `.tq` 结尾，那才是 V8 的 Torque 源代码。因此，`v8/test/cctest/wasm/test-wasm-shared-engine.cc` **不是**一个 Torque 源代码文件。

**与 JavaScript 的关系及示例:**

WebAssembly 的设计目标之一就是与 JavaScript 高效地互操作。这个测试文件虽然是 C++ 代码，但它测试的功能直接关系到 JavaScript 如何使用 WebAssembly。

在 JavaScript 中，我们可以使用 `WebAssembly` API 来加载、编译和实例化 WebAssembly 模块。共享引擎的概念在 JavaScript 中是隐式的。当多个 JavaScript 上下文（例如不同的 Worker 线程）加载同一个 WebAssembly 模块时，V8 的共享引擎会尽可能地复用编译结果，从而提高性能。

**JavaScript 示例:**

假设我们有一个简单的 WebAssembly 模块 `module.wasm`，它导出一个名为 `add` 的函数。

```javascript
// 主线程
fetch('module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.compile(bytes))
  .then(module => {
    // 将编译后的模块传递给 Worker
    worker.postMessage({ type: 'wasm-module', module });
  });

const worker = new Worker('worker.js');
worker.onmessage = function(event) {
  console.log('Worker 返回结果:', event.data);
};
```

```javascript
// worker.js (Worker 线程)
let wasmModule;
let wasmInstance;

onmessage = async function(event) {
  if (event.data.type === 'wasm-module') {
    wasmModule = event.data.module;
    wasmInstance = await WebAssembly.instantiate(wasmModule);
    const result = wasmInstance.exports.add(5, 10);
    postMessage(result);
  }
};
```

在这个例子中，主线程编译了 `module.wasm`，并将编译后的 `WebAssembly.Module` 对象传递给了 Worker 线程。V8 的共享引擎会识别出这两个上下文加载的是同一个模块，并可能共享编译结果，从而避免 Worker 线程重复编译。`test-wasm-shared-engine.cc` 中的测试正是验证了 V8 在这种场景下的行为。

**代码逻辑推理及假设输入/输出:**

我们来看一个简单的测试用例 `TEST(SharedEngineRunSeparated)`：

```c++
TEST(SharedEngineRunSeparated) {
  {
    SharedEngineIsolate isolate;
    HandleScope scope(isolate.isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate.zone(), 23);
    Handle<WasmInstanceObject> instance = isolate.CompileAndInstantiate(buffer);
    CHECK_EQ(23, isolate.Run(instance));
  }
  {
    SharedEngineIsolate isolate;
    HandleScope scope(isolate.isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate.zone(), 42);
    Handle<WasmInstanceObject> instance = isolate.CompileAndInstantiate(buffer);
    CHECK_EQ(42, isolate.Run(instance));
  }
}
```

**假设输入:**

- 第一次执行时，`BuildReturnConstantModule` 函数接收常量 `23`。
- 第二次执行时，`BuildReturnConstantModule` 函数接收常量 `42`。

**代码逻辑:**

1. **创建独立的 Isolate:**  创建两个独立的 `SharedEngineIsolate` 实例。
2. **构建 WebAssembly 模块:**  `BuildReturnConstantModule` 函数构建一个简单的 WebAssembly 模块，该模块导出一个名为 `main` 的函数，该函数返回传入的常量。
3. **编译和实例化:** `CompileAndInstantiate` 函数同步编译并实例化该模块。
4. **运行 WebAssembly 函数:** `Run` 函数调用实例中的 `main` 函数。
5. **断言:** `CHECK_EQ` 宏断言 `Run` 函数的返回值与构建模块时传入的常量一致。

**预期输出:**

- 第一次执行时，`isolate.Run(instance)` 应该返回 `23`。
- 第二次执行时，`isolate.Run(instance)` 应该返回 `42`。

这个测试用例验证了即使在不同的 Isolate 中独立地编译和运行 WebAssembly 模块，也能得到预期的结果。

**涉及用户常见的编程错误:**

虽然这个文件是 V8 内部的测试代码，但它所测试的功能与用户在编写 JavaScript/WebAssembly 代码时可能遇到的问题有关。

1. **在多线程环境中使用 WebAssembly:** 用户可能会错误地假设 WebAssembly 模块的实例可以在多个线程之间随意共享和操作，而忽略了线程安全问题。V8 的共享引擎旨在提供安全的共享机制，但用户仍然需要注意同步和数据竞争。

   **示例错误 (JavaScript):**

   ```javascript
   // 错误地在多个 Worker 中共享同一个 WebAssembly 实例
   const instance = await WebAssembly.instantiate(module);

   const worker1 = new Worker('worker1.js');
   worker1.postMessage({ type: 'run', instance }); // 错误：无法直接传递 WebAssembly.Instance

   const worker2 = new Worker('worker2.js');
   worker2.postMessage({ type: 'run', instance }); // 错误：无法直接传递 WebAssembly.Instance
   ```

   正确的做法是共享编译后的 `WebAssembly.Module`，然后在每个 Worker 中独立实例化。

2. **异步操作处理不当:**  在异步编译或实例化 WebAssembly 模块时，用户可能会忘记等待操作完成就尝试访问模块的导出，导致错误。

   **示例错误 (JavaScript):**

   ```javascript
   fetch('module.wasm')
     .then(response => response.arrayBuffer())
     .then(bytes => WebAssembly.compile(bytes))
     .then(module => {
       // 错误：没有等待实例化完成就尝试访问 exports
       const instance = WebAssembly.instantiate(module);
       console.log(instance.exports.add(1, 2)); // 可能会出错，因为实例化可能是异步的
     });
   ```

   应该使用 `await` 或者 `then` 链来确保实例化完成后再访问导出。

3. **内存管理问题:** 虽然 WebAssembly 提供了相对安全的内存管理，但在涉及到 JavaScript 和 WebAssembly 之间共享内存（例如使用 `SharedArrayBuffer`）时，用户仍然需要注意内存同步和数据一致性问题。

**总结:**

`v8/test/cctest/wasm/test-wasm-shared-engine.cc` 是一个重要的 V8 测试文件，它验证了 WebAssembly 共享引擎在多 Isolate 和多线程环境下的正确性。虽然它是 C++ 代码，但它测试的功能直接关系到 JavaScript 开发者如何安全高效地使用 WebAssembly。理解这些测试用例可以帮助我们更好地理解 V8 的内部机制，并避免在使用 WebAssembly 时犯常见的编程错误。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-wasm-shared-engine.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-wasm-shared-engine.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "src/execution/microtask-queue.h"
#include "src/objects/objects-inl.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"

#include "test/cctest/cctest.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/common/wasm/wasm-module-runner.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_wasm_shared_engine {

// Helper type definition representing a WebAssembly module shared between
// multiple Isolates with implicit reference counting.
using SharedModule = std::shared_ptr<NativeModule>;

// Helper class representing an Isolate that uses the process-wide (shared) wasm
// engine.
class SharedEngineIsolate {
 public:
  SharedEngineIsolate() : isolate_(v8::Isolate::Allocate()) {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate::Initialize(isolate_, create_params);
    v8_isolate()->Enter();
    v8::HandleScope handle_scope(v8_isolate());
    v8::Context::New(v8_isolate())->Enter();
    testing::SetupIsolateForWasmModule(isolate());
    zone_.reset(new Zone(isolate()->allocator(), ZONE_NAME));
  }
  ~SharedEngineIsolate() {
    v8_isolate()->Exit();
    zone_.reset();
    isolate_->Dispose();
  }

  Zone* zone() const { return zone_.get(); }
  v8::Isolate* v8_isolate() { return isolate_; }
  Isolate* isolate() { return reinterpret_cast<Isolate*>(isolate_); }

  Handle<WasmInstanceObject> CompileAndInstantiate(ZoneBuffer* buffer) {
    ErrorThrower thrower(isolate(), "CompileAndInstantiate");
    MaybeHandle<WasmInstanceObject> instance =
        testing::CompileAndInstantiateForTesting(
            isolate(), &thrower,
            ModuleWireBytes(buffer->begin(), buffer->end()));
    return instance.ToHandleChecked();
  }

  Handle<WasmInstanceObject> ImportInstance(SharedModule shared_module) {
    Handle<WasmModuleObject> module_object =
        GetWasmEngine()->ImportNativeModule(isolate(), shared_module, {});
    ErrorThrower thrower(isolate(), "ImportInstance");
    MaybeHandle<WasmInstanceObject> instance = GetWasmEngine()->SyncInstantiate(
        isolate(), &thrower, module_object, {}, {});
    return instance.ToHandleChecked();
  }

  SharedModule ExportInstance(DirectHandle<WasmInstanceObject> instance) {
    return instance->module_object()->shared_native_module();
  }

  int32_t Run(Handle<WasmInstanceObject> instance) {
    return testing::CallWasmFunctionForTesting(isolate(), instance, "main", {});
  }

 private:
  v8::Isolate* isolate_;
  std::unique_ptr<Zone> zone_;
};

// Helper class representing a Thread running its own instance of an Isolate
// with a shared WebAssembly engine available at construction time.
class SharedEngineThread : public v8::base::Thread {
 public:
  explicit SharedEngineThread(
      std::function<void(SharedEngineIsolate*)> callback)
      : Thread(Options("SharedEngineThread")), callback_(callback) {}

  void Run() override {
    SharedEngineIsolate isolate;
    callback_(&isolate);
  }

 private:
  std::function<void(SharedEngineIsolate*)> callback_;
};

namespace {

ZoneBuffer* BuildReturnConstantModule(Zone* zone, int constant) {
  TestSignatures sigs;
  ZoneBuffer* buffer = zone->New<ZoneBuffer>(zone);
  WasmModuleBuilder* builder = zone->New<WasmModuleBuilder>(zone);
  WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
  f->builder()->AddExport(base::CStrVector("main"), f);
  f->EmitCode({WASM_I32V_2(constant), WASM_END});
  builder->WriteTo(buffer);
  return buffer;
}

class MockInstantiationResolver : public InstantiationResultResolver {
 public:
  explicit MockInstantiationResolver(IndirectHandle<Object>* out_instance)
      : out_instance_(out_instance) {}
  void OnInstantiationSucceeded(Handle<WasmInstanceObject> result) override {
    *out_instance_->location() = result->ptr();
  }
  void OnInstantiationFailed(Handle<Object> error_reason) override {
    UNREACHABLE();
  }

 private:
  IndirectHandle<Object>* out_instance_;
};

class MockCompilationResolver : public CompilationResultResolver {
 public:
  MockCompilationResolver(SharedEngineIsolate* isolate,
                          IndirectHandle<Object>* out_instance)
      : isolate_(isolate), out_instance_(out_instance) {}
  void OnCompilationSucceeded(Handle<WasmModuleObject> result) override {
    GetWasmEngine()->AsyncInstantiate(
        isolate_->isolate(),
        std::make_unique<MockInstantiationResolver>(out_instance_), result, {});
  }
  void OnCompilationFailed(Handle<Object> error_reason) override {
    UNREACHABLE();
  }

 private:
  SharedEngineIsolate* isolate_;
  IndirectHandle<Object>* out_instance_;
};

void PumpMessageLoop(SharedEngineIsolate* isolate) {
  v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(),
                                isolate->v8_isolate(),
                                platform::MessageLoopBehavior::kWaitForWork);
  isolate->isolate()->default_microtask_queue()->RunMicrotasks(
      isolate->isolate());
}

Handle<WasmInstanceObject> CompileAndInstantiateAsync(
    SharedEngineIsolate* isolate, ZoneBuffer* buffer) {
  IndirectHandle<Object> maybe_instance(Smi::zero(), isolate->isolate());
  auto enabled_features = WasmEnabledFeatures::FromIsolate(isolate->isolate());
  constexpr const char* kAPIMethodName = "Test.CompileAndInstantiateAsync";
  GetWasmEngine()->AsyncCompile(
      isolate->isolate(), enabled_features, CompileTimeImports{},
      std::make_unique<MockCompilationResolver>(isolate, &maybe_instance),
      ModuleWireBytes(buffer->begin(), buffer->end()), true, kAPIMethodName);
  while (!IsWasmInstanceObject(*maybe_instance)) PumpMessageLoop(isolate);
  Handle<WasmInstanceObject> instance =
      Cast<WasmInstanceObject>(maybe_instance);
  return instance;
}

}  // namespace

TEST(SharedEngineRunSeparated) {
  {
    SharedEngineIsolate isolate;
    HandleScope scope(isolate.isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate.zone(), 23);
    Handle<WasmInstanceObject> instance = isolate.CompileAndInstantiate(buffer);
    CHECK_EQ(23, isolate.Run(instance));
  }
  {
    SharedEngineIsolate isolate;
    HandleScope scope(isolate.isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate.zone(), 42);
    Handle<WasmInstanceObject> instance = isolate.CompileAndInstantiate(buffer);
    CHECK_EQ(42, isolate.Run(instance));
  }
}

TEST(SharedEngineRunImported) {
  SharedModule module;
  {
    SharedEngineIsolate isolate;
    HandleScope scope(isolate.isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate.zone(), 23);
    Handle<WasmInstanceObject> instance = isolate.CompileAndInstantiate(buffer);
    module = isolate.ExportInstance(instance);
    CHECK_EQ(23, isolate.Run(instance));
  }
  {
    SharedEngineIsolate isolate;
    HandleScope scope(isolate.isolate());
    Handle<WasmInstanceObject> instance = isolate.ImportInstance(module);
    CHECK_EQ(23, isolate.Run(instance));
  }
}

TEST(SharedEngineRunThreadedBuildingSync) {
  SharedEngineThread thread1([](SharedEngineIsolate* isolate) {
    HandleScope scope(isolate->isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate->zone(), 23);
    Handle<WasmInstanceObject> instance =
        isolate->CompileAndInstantiate(buffer);
    CHECK_EQ(23, isolate->Run(instance));
  });
  SharedEngineThread thread2([](SharedEngineIsolate* isolate) {
    HandleScope scope(isolate->isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate->zone(), 42);
    Handle<WasmInstanceObject> instance =
        isolate->CompileAndInstantiate(buffer);
    CHECK_EQ(42, isolate->Run(instance));
  });
  CHECK(thread1.Start());
  CHECK(thread2.Start());
  thread1.Join();
  thread2.Join();
}

TEST(SharedEngineRunThreadedBuildingAsync) {
  SharedEngineThread thread1([](SharedEngineIsolate* isolate) {
    HandleScope scope(isolate->isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate->zone(), 23);
    Handle<WasmInstanceObject> instance =
        CompileAndInstantiateAsync(isolate, buffer);
    CHECK_EQ(23, isolate->Run(instance));
  });
  SharedEngineThread thread2([](SharedEngineIsolate* isolate) {
    HandleScope scope(isolate->isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate->zone(), 42);
    Handle<WasmInstanceObject> instance =
        CompileAndInstantiateAsync(isolate, buffer);
    CHECK_EQ(42, isolate->Run(instance));
  });
  CHECK(thread1.Start());
  CHECK(thread2.Start());
  thread1.Join();
  thread2.Join();
}

TEST(SharedEngineRunThreadedExecution) {
  SharedModule module;
  {
    SharedEngineIsolate isolate;
    HandleScope scope(isolate.isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate.zone(), 23);
    DirectHandle<WasmInstanceObject> instance =
        isolate.CompileAndInstantiate(buffer);
    module = isolate.ExportInstance(instance);
  }
  SharedEngineThread thread1([module](SharedEngineIsolate* isolate) {
    HandleScope scope(isolate->isolate());
    Handle<WasmInstanceObject> instance = isolate->ImportInstance(module);
    CHECK_EQ(23, isolate->Run(instance));
  });
  SharedEngineThread thread2([module](SharedEngineIsolate* isolate) {
    HandleScope scope(isolate->isolate());
    Handle<WasmInstanceObject> instance = isolate->ImportInstance(module);
    CHECK_EQ(23, isolate->Run(instance));
  });
  CHECK(thread1.Start());
  CHECK(thread2.Start());
  thread1.Join();
  thread2.Join();
}

TEST(SharedEngineRunThreadedTierUp) {
  SharedModule module;
  {
    SharedEngineIsolate isolate;
    HandleScope scope(isolate.isolate());
    ZoneBuffer* buffer = BuildReturnConstantModule(isolate.zone(), 23);
    DirectHandle<WasmInstanceObject> instance =
        isolate.CompileAndInstantiate(buffer);
    module = isolate.ExportInstance(instance);
  }
  constexpr int kNumberOfThreads = 5;
  std::list<SharedEngineThread> threads;
  for (int i = 0; i < kNumberOfThreads; ++i) {
    threads.emplace_back([module](SharedEngineIsolate* isolate) {
      constexpr int kNumberOfIterations = 100;
      HandleScope scope(isolate->isolate());
      Handle<WasmInstanceObject> instance = isolate->ImportInstance(module);
      for (int j = 0; j < kNumberOfIterations; ++j) {
        CHECK_EQ(23, isolate->Run(instance));
      }
    });
  }
  threads.emplace_back([module](SharedEngineIsolate* isolate) {
    HandleScope scope(isolate->isolate());
    Handle<WasmInstanceObject> instance = isolate->ImportInstance(module);
    WasmDetectedFeatures detected;
    WasmCompilationUnit::CompileWasmFunction(
        isolate->isolate()->counters(), module.get(), &detected,
        &module->module()->functions[0], ExecutionTier::kTurbofan);
    CHECK_EQ(23, isolate->Run(instance));
  });
  for (auto& thread : threads) CHECK(thread.Start());
  for (auto& thread : threads) thread.Join();
}

}  // namespace test_wasm_shared_engine
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```
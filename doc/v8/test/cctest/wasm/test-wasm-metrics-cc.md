Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The core request is to understand the functionality of `v8/test/cctest/wasm/test-wasm-metrics.cc`. This immediately tells us it's a *test* file for the *wasm* component of V8, specifically focusing on *metrics*.

2. **Initial Scan - Identify Key Components:**  Quickly skim the code, looking for familiar C++ structures and V8-related keywords.

    * `#include` directives point to dependencies: standard library (`memory`), V8 APIs (`v8-metrics.h`, `v8-platform.h`, `v8.h`), internal V8 (`src/...`), and testing frameworks (`test/cctest/...`, `test/common/wasm/...`). This gives a high-level idea of the code's scope.
    * `namespace v8 { namespace internal { namespace wasm { ... }}}` confirms the location within the V8 codebase.
    * Classes like `MockPlatform`, `TestInstantiateResolver`, `TestCompileResolver`, and `MetricsRecorder` stand out as important building blocks.
    * Macros like `RUN_COMPILE` and `COMPILE_TEST` suggest a test structure.

3. **Focus on the Core Functionality - `MetricsRecorder`:** The filename contains "metrics," so the `MetricsRecorder` class is likely central.

    * Examine its members: `module_decoded_`, `module_compiled_`, `module_instantiated_`. These are vectors of structs related to different stages of WebAssembly module processing. The names are self-explanatory.
    * Examine its methods: `AddMainThreadEvent`. This method is overloaded for the different module processing stages and takes the corresponding event struct. The `CHECK(!id.IsEmpty())` suggests these events are associated with a context.

4. **Investigate the Test Setup - `MockPlatform` and Resolvers:**  The `COMPILE_TEST` macro indicates the use of a `MockPlatform`.

    * Analyze `MockPlatform`: It overrides V8's platform interface, providing a controlled environment for testing. Notice the `MockTaskRunner` – this handles asynchronous task execution within the test, allowing for simulating asynchronous compilation. The `job_handles_` and related logic suggest testing of parallel or background operations.
    * Analyze `TestInstantiateResolver` and `TestCompileResolver`: These classes act as callbacks for the asynchronous compilation and instantiation processes. They update the `CompilationStatus` and `error_message_` based on the outcome. The `TestCompileResolver` also handles the subsequent instantiation after successful compilation.

5. **Understand the Test Flow - `COMPILE_TEST` Macro and `RUN_COMPILE`:**

    * The `COMPILE_TEST` macro generates three test cases: `Sync...`, `Async...`, and `Streaming...`. This suggests the code tests different modes of WebAssembly compilation.
    * `RUN_COMPILE` sets up the V8 environment (handlescope, context, Wasm module setup) and then calls the specific `RunCompile_...` function.

6. **Analyze the Specific Test Case - `TestEventMetrics`:**  This is the core test that uses the `MetricsRecorder`.

    * It sets up the `MetricsRecorder` and attaches it to the V8 isolate.
    * It creates a simple WebAssembly module using `WasmModuleBuilder`.
    * It initiates asynchronous compilation using `GetWasmEngine()->AsyncCompile`.
    * It uses a `while` loop and `platform->ExecuteTasks()` to simulate the progression of asynchronous tasks until compilation finishes.
    * **Crucially**, it then makes assertions about the contents of the `MetricsRecorder`'s vectors. This confirms that the expected events were recorded with the expected data (success, async flag, streamed flag, module size, function count, compilation duration, etc.).

7. **Connect to JavaScript (If Applicable):** Since this test focuses on WebAssembly metrics, it's directly related to the JavaScript API for WebAssembly. The `WebAssembly.compile()` and `WebAssembly.instantiate()` functions are the direct JavaScript equivalents of the internal compilation and instantiation processes being tested. The metrics collected here would be generated when these JavaScript APIs are used.

8. **Identify Potential Programming Errors (If Applicable):**  While this is a test file, we can infer potential user errors by looking at what the test verifies. For example, the test checks for successful compilation and instantiation. A common user error would be providing invalid WebAssembly bytecode, which would lead to failure. Asynchronous operations can also lead to errors if not handled correctly in user code (e.g., trying to use a module before it's fully compiled).

9. **Code Logic Inference (with Hypothetical Input/Output):**

    * **Input:**  A valid, small WebAssembly module (like the one created in `TestEventMetrics`).
    * **Process:** The V8 engine compiles and instantiates this module. The `MetricsRecorder` intercepts and records events during this process.
    * **Output:** The `MetricsRecorder` would contain entries in `module_decoded_`, `module_compiled_`, and `module_instantiated_`. The assertions in the test show the expected values of the fields in these entries. For instance, `module_decoded_.back().success` should be `true`, `module_decoded_.back().module_size_in_bytes` would be the size of the generated WebAssembly bytecode, and so on. If the input was invalid bytecode, `success` would be `false`, and an error message might be captured in the resolvers (although the test focuses on successful compilation).

10. **Refine and Organize:** Finally, structure the analysis into clear sections covering the different aspects of the code, as shown in the initial good answer. Use clear and concise language, and provide code examples where appropriate (especially for the JavaScript connection).
`v8/test/cctest/wasm/test-wasm-metrics.cc` 是一个 V8 的 C++ 源代码文件，其主要功能是**测试 WebAssembly 模块编译和实例化过程中产生的性能指标 (metrics)**。它模拟了 WebAssembly 模块的同步、异步和流式编译过程，并验证在这些过程中是否正确记录了相关的性能数据。

下面列举它的具体功能点：

1. **模拟 WebAssembly 模块的编译和实例化:**
   - 使用 `WasmModuleBuilder` 创建一个简单的 WebAssembly 模块。
   - 使用 V8 的内部 API (`GetWasmEngine()->AsyncCompile` 和 `GetWasmEngine()->AsyncInstantiate`) 模拟 WebAssembly 模块的编译和实例化过程。
   - 支持同步和异步两种编译模式，以及流式编译模式（通过编译宏控制）。

2. **自定义平台 (`MockPlatform`):**
   - 创建了一个名为 `MockPlatform` 的类，它继承自 `TestPlatform`，用于模拟 V8 平台的行为。
   - `MockPlatform` 允许控制任务的执行，例如同步执行所有已提交的任务 (`ExecuteTasks()`)，这对于测试异步操作非常重要。
   - 它还模拟了 `JobHandle` 和 `TaskRunner` 的行为，用于控制后台任务的执行。

3. **自定义编译和实例化解析器 (`TestCompileResolver`, `TestInstantiateResolver`):**
   - `TestCompileResolver` 和 `TestInstantiateResolver` 是编译和实例化过程的回调函数，用于接收编译和实例化的结果（成功或失败）。
   - 它们会更新 `CompilationStatus` 和 `error_message` 变量，以便测试代码可以检查编译和实例化是否成功，以及失败的原因。

4. **自定义指标记录器 (`MetricsRecorder`):**
   - 核心功能在于 `MetricsRecorder` 类，它继承自 `v8::metrics::Recorder`。
   - 它重写了 `AddMainThreadEvent` 方法，用于捕获 WebAssembly 模块解码、编译和实例化过程中产生的指标事件。
   - 它存储了捕获到的 `v8::metrics::WasmModuleDecoded`, `v8::metrics::WasmModuleCompiled`, 和 `v8::metrics::WasmModuleInstantiated` 事件，方便后续的断言检查。

5. **测试不同编译模式下的指标记录:**
   - 使用 `COMPILE_TEST` 宏定义了一系列测试用例，涵盖了同步编译 (`Sync##name`)、异步编译 (`Async##name`) 和流式编译 (`Streaming##name`) 三种模式。
   - 每个测试用例都会执行相同的编译和实例化逻辑，但会通过设置 V8 的 flag 来切换编译模式。

6. **验证记录的指标数据:**
   - 在 `TestEventMetrics` 测试用例中，创建了一个简单的 WebAssembly 模块，并分别在同步、异步和流式模式下进行编译和实例化。
   - 验证了 `MetricsRecorder` 中记录的事件数量和事件内容，例如：
     - `module_decoded_` 记录了解码事件，包含模块大小、函数数量、是否异步/流式等信息。
     - `module_compiled_` 记录了编译事件，包含编译是否成功、是否来自缓存/反序列化、代码大小、编译耗时等信息。
     - `module_instantiated_` 记录了实例化事件，包含实例化是否成功、导入函数数量、实例化耗时等信息。

**如果 `v8/test/cctest/wasm/test-wasm-metrics.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。** 但根据提供的内容，该文件以 `.cc` 结尾，因此它是 C++ 源代码。 Torque 文件通常用于定义 V8 内部的内置函数和类型系统。

**该文件与 JavaScript 的功能有直接关系，因为它测试的是 WebAssembly 功能的指标。**  WebAssembly 可以在 JavaScript 环境中运行，并且 JavaScript 提供了 API 来加载、编译和实例化 WebAssembly 模块。

**JavaScript 示例:**

```javascript
async function loadAndRunWasm() {
  try {
    const response = await fetch('module.wasm'); // 假设有一个名为 module.wasm 的 WebAssembly 文件
    const buffer = await response.arrayBuffer();

    // 编译 WebAssembly 模块
    const module = await WebAssembly.compile(buffer);

    // 实例化 WebAssembly 模块
    const instance = await WebAssembly.instantiate(module);

    // 调用导出的函数
    const result = instance.exports.main();
    console.log(result);
  } catch (e) {
    console.error("Error loading and running WASM:", e);
  }
}

loadAndRunWasm();
```

在这个 JavaScript 例子中，`WebAssembly.compile()` 和 `WebAssembly.instantiate()` 对应了 `test-wasm-metrics.cc` 中测试的编译和实例化过程。V8 引擎在执行这些 JavaScript API 时，会触发 `MetricsRecorder` 中记录的那些指标事件。

**代码逻辑推理（假设输入与输出）:**

假设我们运行 `AsyncTestEventMetrics` 测试用例，并且 `module.wasm` 的内容如测试代码中构建的简单模块（导出一个名为 `main` 的函数，该函数返回 0）。

**假设输入:**

- WebAssembly 字节码：一个非常简单的模块，包含一个导出函数 `main`，其实现是返回常量 0。
- V8 引擎配置为允许异步编译。

**预期输出 (`MetricsRecorder` 中的数据):**

- `module_decoded_`: 包含一个事件，`success` 为 `true`，`async` 为 `true`，`streamed` 为 `false`，`module_size_in_bytes` 为模块的实际字节大小，`function_count` 为 1。
- `module_compiled_`: 包含一个事件，`success` 为 `true`，`async` 为 `true`，`streamed` 为 `false`，`cached` 为 `false`，`deserialized` 为 `false`，`lazy` 的值取决于 V8 的配置，`code_size_in_bytes` 大于 0，表示生成的机器码大小。
- `module_instantiated_`: 包含一个事件，`success` 为 `true`，`async` 为 `false` (当前测试代码中实例化是同步完成的)，`imported_function_count` 为 0。

**涉及用户常见的编程错误（与 WebAssembly 相关）:**

1. **无效的 WebAssembly 模块字节码:**
   - **错误示例 (JavaScript):** 尝试编译一个损坏或格式错误的 `.wasm` 文件。
   ```javascript
   const invalidWasmCode = new Uint8Array([0, 0, 0, 0]); // 明显无效的 WASM
   WebAssembly.compile(invalidWasmCode)
     .catch(error => console.error("Compilation failed:", error));
   ```
   - 在 `test-wasm-metrics.cc` 中，这会导致 `TestCompileResolver::OnCompilationFailed` 被调用，`status` 被设置为 `CompilationStatus::kFailed`，并且会记录编译失败的指标。

2. **尝试实例化未成功编译的模块:**
   - **错误示例 (JavaScript):** 在编译 Promise rejected 后尝试使用 `WebAssembly.instantiate`。
   ```javascript
   WebAssembly.compile(fetch('invalid.wasm'))
     .then(module => WebAssembly.instantiate(module))
     .catch(error => console.error("Error during compilation or instantiation:", error));
   ```
   - 在 `test-wasm-metrics.cc` 中，如果编译失败，实例化步骤通常不会执行。如果手动尝试，`TestInstantiateResolver::OnInstantiationFailed` 会被调用。

3. **模块导出与 JavaScript 导入不匹配:**
   - **错误示例 (JavaScript):** WebAssembly 模块导出了一个名为 `add` 的函数，但在 JavaScript 中尝试访问 `instance.exports.calculate`.
   ```javascript
   WebAssembly.instantiateStreaming(fetch('module_with_add.wasm'))
     .then(result => {
       console.log(result.instance.exports.calculate(2, 3)); // 假设模块没有导出 calculate
     })
     .catch(console.error);
   ```
   - 虽然 `test-wasm-metrics.cc` 主要关注编译和实例化阶段的指标，但这种错误会导致 JavaScript 运行时错误，并且可能在更高级别的监控或性能分析中体现出来。

4. **在异步编译完成前尝试使用模块:**
   - **错误示例 (JavaScript):** 在 `WebAssembly.compileStreaming` 的 Promise resolve 之前就尝试访问模块。
   ```javascript
   const compilationPromise = WebAssembly.compileStreaming(fetch('large_module.wasm'));
   // 过早尝试使用，编译可能尚未完成
   // ...
   compilationPromise.then(module => { /* 现在可以使用模块 */ });
   ```
   - `test-wasm-metrics.cc` 通过使用 `MockPlatform` 和控制任务执行来模拟异步过程，确保指标在正确的时机被记录。

总而言之，`v8/test/cctest/wasm/test-wasm-metrics.cc` 的主要目的是确保 V8 引擎在处理 WebAssembly 模块时，能够正确地记录各种性能指标，这对于性能分析、监控和优化 WebAssembly 功能至关重要。它通过模拟不同的编译场景和使用自定义的平台和指标记录器来实现这一目标。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-wasm-metrics.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-wasm-metrics.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "include/libplatform/libplatform.h"
#include "include/v8-metrics.h"
#include "include/v8-platform.h"
#include "src/api/api-inl.h"
#include "src/base/platform/time.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module-builder.h"
#include "test/cctest/cctest.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/common/wasm/wasm-module-runner.h"

namespace v8 {
namespace internal {
namespace wasm {

namespace {

class MockPlatform final : public TestPlatform {
 public:
  MockPlatform() : task_runner_(std::make_shared<MockTaskRunner>()) {}

  ~MockPlatform() override {
    for (auto* job_handle : job_handles_) job_handle->ResetPlatform();
  }

  std::unique_ptr<v8::JobHandle> CreateJobImpl(
      v8::TaskPriority priority, std::unique_ptr<v8::JobTask> job_task,
      const v8::SourceLocation& location) override {
    auto orig_job_handle = v8::platform::NewDefaultJobHandle(
        this, priority, std::move(job_task), 1);
    auto job_handle =
        std::make_unique<MockJobHandle>(std::move(orig_job_handle), this);
    job_handles_.insert(job_handle.get());
    return job_handle;
  }

  std::shared_ptr<TaskRunner> GetForegroundTaskRunner(
      v8::Isolate* isolate, v8::TaskPriority) override {
    return task_runner_;
  }

  void PostTaskOnWorkerThreadImpl(v8::TaskPriority priority,
                                  std::unique_ptr<v8::Task> task,
                                  const v8::SourceLocation& location) override {
    task_runner_->PostTask(std::move(task));
  }

  bool IdleTasksEnabled(v8::Isolate* isolate) override { return false; }

  void ExecuteTasks() {
    task_runner_->ExecuteTasks();
  }

 private:
  class MockTaskRunner final : public TaskRunner {
   public:
    void PostTaskImpl(std::unique_ptr<v8::Task> task,
                      const SourceLocation& location) override {
      base::MutexGuard lock_scope(&tasks_lock_);
      tasks_.push(std::move(task));
    }

    void PostNonNestableTaskImpl(std::unique_ptr<Task> task,
                                 const SourceLocation& location) override {
      PostTask(std::move(task));
    }

    void PostDelayedTaskImpl(std::unique_ptr<Task> task,
                             double delay_in_seconds,
                             const SourceLocation& location) override {
      PostTask(std::move(task));
    }

    void PostNonNestableDelayedTaskImpl(
        std::unique_ptr<Task> task, double delay_in_seconds,
        const SourceLocation& location) override {
      PostTask(std::move(task));
    }

    void PostIdleTaskImpl(std::unique_ptr<IdleTask> task,
                          const SourceLocation& location) override {
      UNREACHABLE();
    }

    bool IdleTasksEnabled() override { return false; }
    bool NonNestableTasksEnabled() const override { return true; }
    bool NonNestableDelayedTasksEnabled() const override { return true; }

    void ExecuteTasks() {
      std::queue<std::unique_ptr<v8::Task>> tasks;
      while (true) {
        {
          base::MutexGuard lock_scope(&tasks_lock_);
          tasks.swap(tasks_);
        }
        if (tasks.empty()) break;
        while (!tasks.empty()) {
          std::unique_ptr<Task> task = std::move(tasks.front());
          tasks.pop();
          task->Run();
        }
      }
    }

   private:
    base::Mutex tasks_lock_;
    // We do not execute tasks concurrently, so we only need one list of tasks.
    std::queue<std::unique_ptr<v8::Task>> tasks_;
  };

  class MockJobHandle : public JobHandle {
   public:
    explicit MockJobHandle(std::unique_ptr<JobHandle> orig_handle,
                           MockPlatform* platform)
        : orig_handle_(std::move(orig_handle)), platform_(platform) {}

    ~MockJobHandle() {
      if (platform_) platform_->job_handles_.erase(this);
    }

    void ResetPlatform() { platform_ = nullptr; }

    void NotifyConcurrencyIncrease() override {
      orig_handle_->NotifyConcurrencyIncrease();
    }
    void Join() override { orig_handle_->Join(); }
    void Cancel() override { orig_handle_->Cancel(); }
    void CancelAndDetach() override { orig_handle_->CancelAndDetach(); }
    bool IsValid() override { return orig_handle_->IsValid(); }
    bool IsActive() override { return orig_handle_->IsActive(); }

   private:
    std::unique_ptr<JobHandle> orig_handle_;
    MockPlatform* platform_;
  };

  std::shared_ptr<MockTaskRunner> task_runner_;
  std::unordered_set<MockJobHandle*> job_handles_;
};

enum class CompilationStatus {
  kPending,
  kFinished,
  kFailed,
};

class TestInstantiateResolver : public InstantiationResultResolver {
 public:
  TestInstantiateResolver(Isolate* isolate, CompilationStatus* status,
                          std::string* error_message)
      : isolate_(isolate), status_(status), error_message_(error_message) {}

  void OnInstantiationSucceeded(
      i::Handle<i::WasmInstanceObject> instance) override {
    *status_ = CompilationStatus::kFinished;
  }

  void OnInstantiationFailed(i::Handle<i::Object> error_reason) override {
    *status_ = CompilationStatus::kFailed;
    DirectHandle<String> str =
        Object::ToString(isolate_, error_reason).ToHandleChecked();
    error_message_->assign(str->ToCString().get());
  }

 private:
  Isolate* isolate_;
  CompilationStatus* const status_;
  std::string* const error_message_;
};

class TestCompileResolver : public CompilationResultResolver {
 public:
  TestCompileResolver(CompilationStatus* status, std::string* error_message,
                      Isolate* isolate,
                      std::shared_ptr<NativeModule>* native_module)
      : status_(status),
        error_message_(error_message),
        isolate_(isolate),
        native_module_(native_module) {}

  void OnCompilationSucceeded(i::Handle<i::WasmModuleObject> module) override {
    if (!module.is_null()) {
      *native_module_ = module->shared_native_module();
      GetWasmEngine()->AsyncInstantiate(
          isolate_,
          std::make_unique<TestInstantiateResolver>(isolate_, status_,
                                                    error_message_),
          module, MaybeHandle<JSReceiver>());
    }
  }

  void OnCompilationFailed(i::Handle<i::Object> error_reason) override {
    *status_ = CompilationStatus::kFailed;
    DirectHandle<String> str =
        Object::ToString(CcTest::i_isolate(), error_reason).ToHandleChecked();
    error_message_->assign(str->ToCString().get());
  }

 private:
  CompilationStatus* const status_;
  std::string* const error_message_;
  Isolate* isolate_;
  std::shared_ptr<NativeModule>* const native_module_;
};

}  // namespace

#define RUN_COMPILE(name)                                               \
  v8::HandleScope handle_scope(CcTest::isolate());                      \
  v8::Local<v8::Context> context = v8::Context::New(CcTest::isolate()); \
  v8::Context::Scope context_scope(context);                            \
  Isolate* i_isolate = CcTest::i_isolate();                             \
  testing::SetupIsolateForWasmModule(i_isolate);                        \
  RunCompile_##name(&platform, i_isolate);

#define COMPILE_TEST(name)                                                     \
  void RunCompile_##name(MockPlatform*, i::Isolate*);                          \
  TEST_WITH_PLATFORM(Sync##name, MockPlatform) {                               \
    i::FlagScope<bool> sync_scope(&i::v8_flags.wasm_async_compilation, false); \
    RUN_COMPILE(name);                                                         \
  }                                                                            \
                                                                               \
  TEST_WITH_PLATFORM(Async##name, MockPlatform) { RUN_COMPILE(name); }         \
                                                                               \
  TEST_WITH_PLATFORM(Streaming##name, MockPlatform) {                          \
    i::FlagScope<bool> streaming_scope(&i::v8_flags.wasm_test_streaming,       \
                                       true);                                  \
    RUN_COMPILE(name);                                                         \
  }                                                                            \
  void RunCompile_##name(MockPlatform* platform, i::Isolate* isolate)

class MetricsRecorder : public v8::metrics::Recorder {
 public:
  std::vector<v8::metrics::WasmModuleDecoded> module_decoded_;
  std::vector<v8::metrics::WasmModuleCompiled> module_compiled_;
  std::vector<v8::metrics::WasmModuleInstantiated> module_instantiated_;

  void AddMainThreadEvent(const v8::metrics::WasmModuleDecoded& event,
                          v8::metrics::Recorder::ContextId id) override {
    CHECK(!id.IsEmpty());
    module_decoded_.emplace_back(event);
  }
  void AddMainThreadEvent(const v8::metrics::WasmModuleCompiled& event,
                          v8::metrics::Recorder::ContextId id) override {
    CHECK(!id.IsEmpty());
    module_compiled_.emplace_back(event);
  }
  void AddMainThreadEvent(const v8::metrics::WasmModuleInstantiated& event,
                          v8::metrics::Recorder::ContextId id) override {
    CHECK(!id.IsEmpty());
    module_instantiated_.emplace_back(event);
  }
};

COMPILE_TEST(TestEventMetrics) {
  if (v8_flags.memory_balancer) return;
  FlagScope<bool> no_wasm_dynamic_tiering(&v8_flags.wasm_dynamic_tiering,
                                          false);
  std::shared_ptr<MetricsRecorder> recorder =
      std::make_shared<MetricsRecorder>();
  reinterpret_cast<v8::Isolate*>(isolate)->SetMetricsRecorder(recorder);
  if (v8::base::ThreadTicks::IsSupported()) {
    v8::base::ThreadTicks::WaitUntilInitialized();
  }

  TestSignatures sigs;
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);

  WasmModuleBuilder* builder = zone.New<WasmModuleBuilder>(&zone);
  WasmFunctionBuilder* f = builder->AddFunction(sigs.i_v());
  f->builder()->AddExport(base::CStrVector("main"), f);
  f->EmitCode({WASM_I32V_2(0), WASM_END});
  ZoneBuffer buffer(&zone);
  builder->WriteTo(&buffer);

  auto enabled_features = WasmEnabledFeatures::FromIsolate(isolate);
  CompilationStatus status = CompilationStatus::kPending;
  std::string error_message;
  std::shared_ptr<NativeModule> native_module;
  GetWasmEngine()->AsyncCompile(
      isolate, enabled_features, CompileTimeImports{},
      std::make_shared<TestCompileResolver>(&status, &error_message, isolate,
                                            &native_module),
      ModuleWireBytes(buffer.begin(), buffer.end()), true,
      "CompileAndInstantiateWasmModuleForTesting");

  // Finish compilation tasks.
  while (status == CompilationStatus::kPending) {
    platform->ExecuteTasks();
  }
  platform->ExecuteTasks();  // Complete pending tasks beyond compilation.
  CHECK_EQ(CompilationStatus::kFinished, status);

  CHECK_EQ(1, recorder->module_decoded_.size());
  CHECK(recorder->module_decoded_.back().success);
  CHECK_EQ(i::v8_flags.wasm_async_compilation,
           recorder->module_decoded_.back().async);
  CHECK_EQ(i::v8_flags.wasm_test_streaming,
           recorder->module_decoded_.back().streamed);
  CHECK_EQ(buffer.size(),
           recorder->module_decoded_.back().module_size_in_bytes);
  CHECK_EQ(1, recorder->module_decoded_.back().function_count);
  CHECK_LE(0, recorder->module_decoded_.back().wall_clock_duration_in_us);

  CHECK_EQ(1, recorder->module_compiled_.size());
  CHECK(recorder->module_compiled_.back().success);
  CHECK_EQ(i::v8_flags.wasm_async_compilation,
           recorder->module_compiled_.back().async);
  CHECK_EQ(i::v8_flags.wasm_test_streaming,
           recorder->module_compiled_.back().streamed);
  CHECK(!recorder->module_compiled_.back().cached);
  CHECK(!recorder->module_compiled_.back().deserialized);
  CHECK_EQ(v8_flags.wasm_lazy_compilation,
           recorder->module_compiled_.back().lazy);
  CHECK_LT(0, recorder->module_compiled_.back().code_size_in_bytes);
  // We currently cannot ensure that no code is attributed to Liftoff after the
  // WasmModuleCompiled event has been emitted. We therefore only assume the
  // liftoff_code_size() to be an upper limit for the reported size.
  CHECK_GE(native_module->liftoff_code_size(),
           recorder->module_compiled_.back().code_size_in_bytes);
  CHECK_GE(native_module->generated_code_size(),
           recorder->module_compiled_.back().code_size_in_bytes);
  CHECK_LE(0, recorder->module_compiled_.back().wall_clock_duration_in_us);

  CHECK_EQ(1, recorder->module_instantiated_.size());
  CHECK(recorder->module_instantiated_.back().success);
  // We currently don't support true async instantiation.
  CHECK(!recorder->module_instantiated_.back().async);
  CHECK_EQ(0, recorder->module_instantiated_.back().imported_function_count);
  CHECK_LE(0, recorder->module_instantiated_.back().wall_clock_duration_in_us);
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8
```
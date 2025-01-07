Response:
The user wants me to analyze a C++ source code file related to WebAssembly streaming compilation in the V8 JavaScript engine.

Here's a breakdown of the request and how I'll address it:

1. **Identify the file's primary function:** The file name `test-streaming-compilation.cc` strongly suggests it's for testing the streaming compilation feature of WebAssembly in V8.

2. **Check for Torque source:** The prompt asks if the file ends with `.tq`. It doesn't, so it's not a Torque file.

3. **Relationship to JavaScript:** Streaming compilation directly relates to how WebAssembly modules are loaded and compiled in a JavaScript environment. I need to provide a JavaScript example.

4. **Code logic and examples:** The C++ code defines various test scenarios. I need to infer the logic of these tests (e.g., sending bytes in chunks, error conditions, aborting compilation) and provide hypothetical inputs and outputs.

5. **Common programming errors:**  While the C++ code isn't directly user-facing, the *concepts* it tests relate to how developers might interact with WebAssembly compilation. I should think about potential errors when using `WebAssembly.compileStreaming()`.

6. **Summarize the functionality:**  I need to synthesize all the observations into a concise summary.

**Mental Sandbox:**

* **JavaScript Example:**  I can use `fetch` and `WebAssembly.compileStreaming` to demonstrate the related JavaScript API.
* **Code Logic Inference:**  I see classes like `StreamTester` and functions like `OnBytesReceived` and `FinishStream`. These clearly control the flow of bytes to the streaming compiler. The `CompilationState` enum indicates the result of the compilation.
* **Hypothetical Input/Output:** For success cases, the input would be valid WebAssembly bytecode, and the output would be a successfully compiled module. For failure cases, the input would be invalid bytecode, and the output would be an error.
* **Common Errors:**  Incorrect MIME types, network errors during fetching, and invalid WebAssembly bytecode are potential user errors.

**Constraint Checklist:**

1. 列举一下它的功能: Yes
2. 如果v8/test/cctest/wasm/test-streaming-compilation.cc以.tq结尾，那它是个v8 torque源代码: Yes
3. 如果它与javascript的功能有关系，请用javascript举例说明: Yes
4. 如果有代码逻辑推理，请给出假设输入与输出: Yes
5. 如果涉及用户常见的编程错误，请举例说明: Yes
6. 这是第1部分，共3部分，请归纳一下它的功能: Yes

**Confidence Score:** 5/5 - I'm confident I can address all parts of the request.

Strategizing complete. I will now proceed with generating the response.

这个C++源代码文件 `v8/test/cctest/wasm/test-streaming-compilation.cc` 的主要功能是**测试 V8 JavaScript 引擎中 WebAssembly 模块的流式编译功能**。

根据您提供的代码片段，可以归纳出以下几点功能：

1. **模拟平台 (MockPlatform):**  它创建了一个模拟的平台环境，用于控制任务的执行，包括前台任务和后台 worker 线程上的任务。这使得测试可以同步地执行异步的流式编译过程，方便验证其正确性。

2. **模拟任务运行器 (MockTaskRunner):**  `MockPlatform` 内部使用了 `MockTaskRunner` 来管理和执行任务队列，包括延迟任务。这允许测试精确地控制编译任务的执行时机。

3. **模拟 JobHandle (MockJobHandle):**  用于模拟 V8 的 JobHandle，允许控制任务的生命周期，例如取消和加入。

4. **测试编译结果解析器 (TestResolver):**  `TestResolver` 类实现了 `CompilationResultResolver` 接口，用于接收流式编译的结果，包括成功编译的模块对象和编译失败的错误信息。它维护了编译状态（Pending, Finished, Failed）和错误消息。

5. **流式测试器 (StreamTester):**  `StreamTester` 类是核心的测试辅助类，它封装了启动和控制 WebAssembly 流式编译的过程。
    - 它使用 `GetWasmEngine()->StartStreamingCompilation` 启动流式编译。
    - 它通过 `OnBytesReceived` 方法接收 WebAssembly 模块的字节流。
    - 它通过 `FinishStream` 方法通知编译结束。
    - 它提供了访问编译后的模块对象 (`module_object`) 和本地模块 (`native_module`) 的方法。
    - 它使用 `RunCompilerTasks` 来触发模拟平台上任务的执行，从而驱动编译过程。
    - 它提供了检查 Promise 状态（fulfilled, rejected, pending）的方法。
    - 它能设置编译后的模块字节，用于测试编译模块缓存等场景。

6. **定义了多个测试用例 (STREAM_TEST 宏):**  文件中使用了 `STREAM_TEST` 宏定义了多个测试用例，每个测试用例模拟了不同的流式编译场景，例如：
    - 一次性接收所有字节后完成编译。
    - 分批接收字节，模拟网络传输。
    - 在编译过程中遇到错误（例如，无效的段，无效的段大小，代码段错误）。
    - 在编译过程中中止 (Abort)。
    - 测试使用编译后的模块缓存。

**由于 `v8/test/cctest/wasm/test-streaming-compilation.cc` 文件以 `.cc` 结尾，它是一个 C++ 源代码文件，而不是 Torque 源代码。**

**它与 JavaScript 的功能有直接关系。**  JavaScript 中可以使用 `WebAssembly.compileStreaming()` 方法来发起 WebAssembly 模块的流式编译。

**JavaScript 示例：**

```javascript
async function compileAndRun(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const module = await WebAssembly.compileStreaming(response);
    const instance = await WebAssembly.instantiate(module);
    // 使用 instance
    console.log(instance.exports.a());
  } catch (error) {
    console.error("流式编译或实例化失败:", error);
  }
}

compileAndRun('my_wasm_module.wasm');
```

在这个 JavaScript 示例中，`WebAssembly.compileStreaming(response)`  的功能与 `v8/test/cctest/wasm/test-streaming-compilation.cc`  测试的核心功能对应。该 C++ 代码通过模拟字节流的接收和编译过程，来测试 V8 引擎对 `WebAssembly.compileStreaming()` 的实现是否正确。

**代码逻辑推理与假设输入输出：**

以 `STREAM_TEST(TestCutAfterOneFunctionStreamFinishesFirst)` 为例：

**假设输入：** 一个包含三个函数的 WebAssembly 模块的字节流。

**执行步骤：**
1. `StreamTester` 接收到该模块前两个函数的字节。
2. 编译任务被执行，可能只编译了第一个函数。
3. `IsPromisePending()` 返回 true，表示编译仍在进行中。
4. `StreamTester` 接收到剩余字节（第三个函数）。
5. `FinishStream()` 被调用。
6. 所有编译任务执行完成。

**预期输出：** `IsPromiseFulfilled()` 返回 true，表示模块流式编译成功。

**涉及用户常见的编程错误：**

1. **MIME 类型错误：**  当使用 `fetch` 获取 WebAssembly 模块时，如果服务器返回的 `Content-Type` 不是 `application/wasm`，`WebAssembly.compileStreaming()` 可能会失败。

   ```javascript
   // 假设服务器配置错误，返回 text/plain
   fetch('invalid_mime.wasm')
     .then(response => WebAssembly.compileStreaming(response))
     .catch(error => console.error("编译失败:", error)); // 可能报错
   ```

2. **网络错误：**  在流式下载过程中，如果网络连接中断，会导致编译失败。

   ```javascript
   fetch('https://example.com/unstable_network.wasm')
     .then(response => WebAssembly.compileStreaming(response))
     .catch(error => console.error("编译失败:", error)); // 可能因为网络问题报错
   ```

3. **无效的 WebAssembly 模块：**  如果提供的字节流不是一个有效的 WebAssembly 模块，`WebAssembly.compileStreaming()` 将会抛出错误。  `v8/test/cctest/wasm/test-streaming-compilation.cc` 中很多测试用例都在模拟这种情况。

   ```javascript
   const invalidWasmBytes = new Uint8Array([0, 0, 0, 0]); // 无效的魔数
   WebAssembly.compileStreaming(new Response(invalidWasmBytes))
     .catch(error => console.error("编译失败:", error)); // 会报错
   ```

**归纳一下它的功能 (第 1 部分)：**

`v8/test/cctest/wasm/test-streaming-compilation.cc` 的第 1 部分主要定义了用于测试 V8 中 WebAssembly 流式编译功能的基础架构和一些基本的成功和失败测试用例。它创建了模拟平台和流式测试器，能够控制编译任务的执行，并验证在不同字节接收和完成编译的时机下，流式编译是否能正确完成或报告错误。这些测试覆盖了基本的流式编译流程，包括完整接收字节和分段接收字节的情况，以及在模块解析阶段就发现错误的场景。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-streaming-compilation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-streaming-compilation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/libplatform/libplatform.h"
#include "src/api/api-inl.h"
#include "src/base/vector.h"
#include "src/handles/global-handles-inl.h"
#include "src/init/v8.h"
#include "src/objects/managed.h"
#include "src/objects/objects-inl.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/streaming-decoder.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-serialization.h"
#include "test/cctest/cctest.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/common/wasm/wasm-module-runner.h"

namespace v8::internal::wasm {

class MockPlatform final : public TestPlatform {
 public:
  MockPlatform() : task_runner_(std::make_shared<MockTaskRunner>()) {}

  ~MockPlatform() {
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

  void ExecuteTasks() { task_runner_->ExecuteTasks(); }

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
      base::MutexGuard lock_scope(&tasks_lock_);
      delayed_tasks_.emplace_back(
          std::move(task), base::TimeTicks::Now() +
                               base::TimeDelta::FromSecondsD(delay_in_seconds));
    }

    void PostNonNestableDelayedTaskImpl(
        std::unique_ptr<Task> task, double delay_in_seconds,
        const SourceLocation& location) override {
      PostDelayedTask(std::move(task), delay_in_seconds);
    }

    void PostIdleTaskImpl(std::unique_ptr<IdleTask> task,
                          const SourceLocation& location) override {
      UNREACHABLE();
    }

    bool IdleTasksEnabled() override { return false; }
    bool NonNestableTasksEnabled() const override { return true; }
    bool NonNestableDelayedTasksEnabled() const override { return true; }

    // The test must call this repeatedly if delayed tasks were posted, until
    // all such tasks have been executed.
    void ExecuteTasks() {
      std::queue<std::unique_ptr<v8::Task>> tasks;
      while (true) {
        {
          base::MutexGuard lock_scope(&tasks_lock_);
          tasks.swap(tasks_);
          // Move all delayed tasks which are ready for execution to {tasks_}.
          base::TimeTicks now = base::TimeTicks::Now();
          for (auto it = delayed_tasks_.begin(), end = delayed_tasks_.end();
               it != end;) {
            if (it->second > now) {
              ++it;
              continue;
            }
            tasks.push(std::move(it->first));
            it = delayed_tasks_.erase(it);
          }
        }
        // Stop if there are no tasks to execute. Otherwise execute the tasks,
        // then check again.
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
    std::list<std::pair<std::unique_ptr<v8::Task>, base::TimeTicks>>
        delayed_tasks_;
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
    bool IsActive() override { return orig_handle_->IsActive(); }
    bool IsValid() override { return orig_handle_->IsValid(); }

   private:
    std::unique_ptr<JobHandle> orig_handle_;
    MockPlatform* platform_;
  };

  std::shared_ptr<MockTaskRunner> task_runner_;
  std::unordered_set<MockJobHandle*> job_handles_;
};

namespace {

enum class CompilationState {
  kPending,
  kFinished,
  kFailed,
};

class TestResolver : public CompilationResultResolver {
 public:
  TestResolver(i::Isolate* isolate, CompilationState* state,
               std::string* error_message,
               Handle<WasmModuleObject>* module_object)
      : isolate_(isolate),
        state_(state),
        error_message_(error_message),
        module_object_(module_object) {}

  void OnCompilationSucceeded(i::Handle<i::WasmModuleObject> module) override {
    *state_ = CompilationState::kFinished;
    *module_object_ = isolate_->global_handles()->Create(*module);
  }

  void OnCompilationFailed(i::Handle<i::Object> error_reason) override {
    *state_ = CompilationState::kFailed;
    DirectHandle<String> str =
        Object::ToString(isolate_, error_reason).ToHandleChecked();
    error_message_->assign(str->ToCString().get());
    // Print the error message, for easier debugging on tests that unexpectedly
    // fail compilation.
    PrintF("Compilation failed: %s\n", error_message_->c_str());
  }

 private:
  i::Isolate* isolate_;
  CompilationState* const state_;
  std::string* const error_message_;
  Handle<WasmModuleObject>* const module_object_;
};

class StreamTester {
 public:
  explicit StreamTester(v8::Isolate* isolate)
      : zone_(&allocator_, "StreamTester") {
    Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
    v8::Local<v8::Context> context = isolate->GetCurrentContext();

    WasmEnabledFeatures features = WasmEnabledFeatures::FromIsolate(i_isolate);
    stream_ = GetWasmEngine()->StartStreamingCompilation(
        i_isolate, features, CompileTimeImports{},
        v8::Utils::OpenHandle(*context), "WebAssembly.compileStreaming()",
        std::make_shared<TestResolver>(i_isolate, &state_, &error_message_,
                                       &module_object_));
  }

  std::shared_ptr<StreamingDecoder> stream() const { return stream_; }

  // Compiled module object, valid after successful compile.
  Handle<WasmModuleObject> module_object() const {
    CHECK(!module_object_.is_null());
    return module_object_;
  }

  // Compiled native module, valid after successful compile.
  NativeModule* native_module() const {
    return module_object()->native_module();
  }
  std::shared_ptr<NativeModule> shared_native_module() const {
    return module_object()->shared_native_module();
  }

  // Run all compiler tasks, both foreground and background tasks.
  void RunCompilerTasks() {
    static_cast<MockPlatform*>(i::V8::GetCurrentPlatform())->ExecuteTasks();
  }

  bool IsPromiseFulfilled() { return state_ == CompilationState::kFinished; }

  bool IsPromiseRejected() { return state_ == CompilationState::kFailed; }

  bool IsPromisePending() { return state_ == CompilationState::kPending; }

  void OnBytesReceived(const uint8_t* start, size_t length) {
    stream_->OnBytesReceived(base::Vector<const uint8_t>(start, length));
  }

  void FinishStream() { stream_->Finish(); }

  void SetCompiledModuleBytes(base::Vector<const uint8_t> bytes) {
    stream_->SetCompiledModuleBytes(bytes);
  }

  Zone* zone() { return &zone_; }

  const std::string& error_message() const { return error_message_; }

 private:
  AccountingAllocator allocator_;
  Zone zone_;
  CompilationState state_ = CompilationState::kPending;
  std::string error_message_;
  Handle<WasmModuleObject> module_object_;
  std::shared_ptr<StreamingDecoder> stream_;
};
}  // namespace

#define RUN_STREAM(name)                                                     \
  v8::Isolate* isolate = CcTest::isolate();                                  \
  v8::HandleScope handle_scope(isolate);                                     \
  v8::Local<v8::Context> context = v8::Context::New(isolate);                \
  v8::Context::Scope context_scope(context);                                 \
  /* Reduce tiering budget so we do not need to execute too long. */         \
  i::FlagScope<int> reduced_tiering_budget(&i::v8_flags.wasm_tiering_budget, \
                                           1);                               \
  RunStream_##name(&platform, isolate);

#define STREAM_TEST(name)                                                  \
  void RunStream_##name(MockPlatform*, v8::Isolate*);                      \
  TEST_WITH_PLATFORM(Async##name, MockPlatform) {                          \
    if (i::v8_flags.memory_balancer) return;                               \
    RUN_STREAM(name);                                                      \
  }                                                                        \
                                                                           \
  TEST_WITH_PLATFORM(SingleThreaded##name, MockPlatform) {                 \
    if (i::v8_flags.memory_balancer) return;                               \
    i::FlagScope<bool> single_threaded_scope(&i::v8_flags.single_threaded, \
                                             true);                        \
    RUN_STREAM(name);                                                      \
  }                                                                        \
  void RunStream_##name(MockPlatform* platform, v8::Isolate* isolate)

constexpr const char* kExportNames[] = {"a", "b", "c"};

// Create a valid module with 3 functions.
ZoneBuffer GetValidModuleBytes(Zone* zone) {
  ZoneBuffer buffer(zone);
  TestSignatures sigs;
  WasmModuleBuilder builder(zone);
  uint8_t i = 0;
  for (const char* export_name : kExportNames) {
    WasmFunctionBuilder* f = builder.AddFunction(sigs.i_iii());
    f->EmitCode({kExprLocalGet, i, kExprEnd});
    CHECK_GE(3, ++i);
    builder.AddExport(base::CStrVector(export_name), f);
  }
  builder.WriteTo(&buffer);
  return buffer;
}

// Create the same valid module as above and serialize it to test streaming
// with compiled module caching.
ZoneBuffer GetValidCompiledModuleBytes(v8::Isolate* isolate, Zone* zone,
                                       ZoneBuffer wire_bytes) {
  // Use a tester to compile to a NativeModule.
  StreamTester tester(isolate);
  tester.OnBytesReceived(wire_bytes.begin(), wire_bytes.size());
  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());

  NativeModule* native_module = tester.native_module();
  CHECK_NOT_NULL(native_module);

  auto* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  ErrorThrower thrower{i_isolate, "GetValidCompiledModuleBytes"};
  Handle<WasmInstanceObject> instance =
      GetWasmEngine()
          ->SyncInstantiate(i_isolate, &thrower, tester.module_object(), {}, {})
          .ToHandleChecked();
  CHECK(!thrower.error());

  // Call the exported functions repeatedly until they are all tiered up.
  std::vector<Handle<WasmExportedFunction>> exported_functions;
  for (const char* export_name : kExportNames) {
    exported_functions.push_back(
        testing::GetExportedFunction(i_isolate, instance, export_name)
            .ToHandleChecked());
  }
  while (true) {
    WasmCodeRefScope code_ref_scope;
    std::vector<WasmCode*> all_code = native_module->SnapshotCodeTable().first;
    if (std::all_of(all_code.begin(), all_code.end(), [](const WasmCode* code) {
          return code && code->tier() == ExecutionTier::kTurbofan;
        })) {
      break;
    }
    for (Handle<WasmExportedFunction> exported_function : exported_functions) {
      DirectHandle<Object> return_value =
          Execution::Call(i_isolate, exported_function,
                          ReadOnlyRoots{i_isolate}.undefined_value_handle(), 0,
                          nullptr)
              .ToHandleChecked();
      CHECK(IsSmi(*return_value));
      CHECK_EQ(0, Cast<Smi>(*return_value).value());
    }
    tester.RunCompilerTasks();
  }

  // Serialize the NativeModule.
  i::wasm::WasmSerializer serializer(native_module);
  size_t size = serializer.GetSerializedNativeModuleSize();
  std::vector<uint8_t> buffer(size);
  CHECK(serializer.SerializeNativeModule(base::VectorOf(buffer)));
  ZoneBuffer result(zone, size);
  result.write(buffer.data(), size);
  return result;
}

// Test that all bytes arrive before doing any compilation. FinishStream is
// called immediately.
STREAM_TEST(TestAllBytesArriveImmediatelyStreamFinishesFirst) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetValidModuleBytes(tester.zone());

  tester.OnBytesReceived(buffer.begin(), buffer.end() - buffer.begin());
  tester.FinishStream();

  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseFulfilled());
}

// Test that all bytes arrive before doing any compilation. FinishStream is
// called after the compilation is done.
STREAM_TEST(TestAllBytesArriveAOTCompilerFinishesFirst) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetValidModuleBytes(tester.zone());

  tester.OnBytesReceived(buffer.begin(), buffer.end() - buffer.begin());

  tester.RunCompilerTasks();
  tester.FinishStream();
  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseFulfilled());
}

size_t GetFunctionOffset(i::Isolate* isolate, base::Vector<const uint8_t> bytes,
                         size_t index) {
  WasmDetectedFeatures unused_detected_features;
  ModuleResult result =
      DecodeWasmModule(WasmEnabledFeatures::All(), bytes, false,
                       ModuleOrigin::kWasmOrigin, &unused_detected_features);
  CHECK(result.ok());
  const WasmFunction* func = &result.value()->functions[index];
  return func->code.offset();
}

// Test that some functions come in the beginning, some come after some
// functions already got compiled.
STREAM_TEST(TestCutAfterOneFunctionStreamFinishesFirst) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetValidModuleBytes(tester.zone());

  Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  size_t offset = GetFunctionOffset(i_isolate, base::VectorOf(buffer), 1);
  tester.OnBytesReceived(buffer.begin(), offset);
  tester.RunCompilerTasks();
  CHECK(tester.IsPromisePending());
  tester.OnBytesReceived(buffer.begin() + offset, buffer.size() - offset);
  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());
}

// Test that some functions come in the beginning, some come after some
// functions already got compiled. Call FinishStream after the compilation is
// done.
STREAM_TEST(TestCutAfterOneFunctionCompilerFinishesFirst) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetValidModuleBytes(tester.zone());

  Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  size_t offset = GetFunctionOffset(i_isolate, base::VectorOf(buffer), 1);
  tester.OnBytesReceived(buffer.begin(), offset);
  tester.RunCompilerTasks();
  CHECK(tester.IsPromisePending());
  tester.OnBytesReceived(buffer.begin() + offset, buffer.size() - offset);
  tester.RunCompilerTasks();
  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());
}

// Create a module with an invalid global section.
ZoneBuffer GetModuleWithInvalidSection(Zone* zone) {
  ZoneBuffer buffer(zone);
  TestSignatures sigs;
  WasmModuleBuilder builder(zone);
  // Add an invalid global to the module. The decoder will fail there.
  builder.AddGlobal(kWasmVoid, true, WasmInitExpr::GlobalGet(12));
  {
    WasmFunctionBuilder* f = builder.AddFunction(sigs.i_iii());
    f->EmitCode({kExprLocalGet, 0, kExprEnd});
  }
  {
    WasmFunctionBuilder* f = builder.AddFunction(sigs.i_iii());
    f->EmitCode({kExprLocalGet, 1, kExprEnd});
  }
  {
    WasmFunctionBuilder* f = builder.AddFunction(sigs.i_iii());
    f->EmitCode({kExprLocalGet, 2, kExprEnd});
  }
  builder.WriteTo(&buffer);
  return buffer;
}

// Test an error in a section, found by the ModuleDecoder.
STREAM_TEST(TestErrorInSectionStreamFinishesFirst) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetModuleWithInvalidSection(tester.zone());

  tester.OnBytesReceived(buffer.begin(), buffer.end() - buffer.begin());
  tester.FinishStream();

  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

STREAM_TEST(TestErrorInSectionCompilerFinishesFirst) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetModuleWithInvalidSection(tester.zone());

  tester.OnBytesReceived(buffer.begin(), buffer.end() - buffer.begin());
  tester.RunCompilerTasks();
  tester.FinishStream();
  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

STREAM_TEST(TestErrorInSectionWithCuts) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetModuleWithInvalidSection(tester.zone());

  const uint8_t* current = buffer.begin();
  size_t remaining = buffer.end() - buffer.begin();
  while (current < buffer.end()) {
    size_t size = std::min(remaining, size_t{10});
    tester.OnBytesReceived(current, size);
    tester.RunCompilerTasks();
    current += 10;
    remaining -= size;
  }
  tester.FinishStream();
  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

ZoneBuffer GetModuleWithInvalidSectionSize(Zone* zone) {
  // We get a valid module and overwrite the size of the first section with an
  // invalid value.
  ZoneBuffer buffer = GetValidModuleBytes(zone);
  // 9 == 4 (wasm magic) + 4 (version) + 1 (section code)
  uint8_t* section_size_address = const_cast<uint8_t*>(buffer.begin()) + 9;
  // 0x808080800F is an invalid module size in leb encoding.
  section_size_address[0] = 0x80;
  section_size_address[1] = 0x80;
  section_size_address[2] = 0x80;
  section_size_address[3] = 0x80;
  section_size_address[4] = 0x0F;
  return buffer;
}

STREAM_TEST(TestErrorInSectionSizeStreamFinishesFirst) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetModuleWithInvalidSectionSize(tester.zone());
  tester.OnBytesReceived(buffer.begin(), buffer.end() - buffer.begin());
  tester.FinishStream();
  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

STREAM_TEST(TestErrorInSectionSizeCompilerFinishesFirst) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetModuleWithInvalidSectionSize(tester.zone());
  tester.OnBytesReceived(buffer.begin(), buffer.end() - buffer.begin());
  tester.RunCompilerTasks();
  tester.FinishStream();
  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

STREAM_TEST(TestErrorInSectionSizeWithCuts) {
  StreamTester tester(isolate);
  ZoneBuffer buffer = GetModuleWithInvalidSectionSize(tester.zone());
  const uint8_t* current = buffer.begin();
  size_t remaining = buffer.end() - buffer.begin();
  while (current < buffer.end()) {
    size_t size = std::min(remaining, size_t{10});
    tester.OnBytesReceived(current, size);
    tester.RunCompilerTasks();
    current += 10;
    remaining -= size;
  }
  tester.RunCompilerTasks();
  tester.FinishStream();
  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

// Test an error in the code section, found by the ModuleDecoder. The error is a
// functions count in the code section which differs from the functions count in
// the function section.
STREAM_TEST(TestErrorInCodeSectionDetectedByModuleDecoder) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // body size
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(1 + arraysize(code) * 2),    // section size
      U32V_1(2),                          // !!! invalid function count !!!
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.FinishStream();

  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

STREAM_TEST(TestSectionOrderErrorWithEmptyCodeSection) {
  // Valid: Export, then Code.
  const uint8_t valid[] = {WASM_MODULE_HEADER, SECTION(Export, ENTRY_COUNT(0)),
                           SECTION(Code, ENTRY_COUNT(0))};
  // Invalid: Code, then Export.
  const uint8_t invalid[] = {WASM_MODULE_HEADER, SECTION(Code, ENTRY_COUNT(0)),
                             SECTION(Export, ENTRY_COUNT(0))};

  StreamTester tester_valid(isolate);
  tester_valid.OnBytesReceived(valid, arraysize(valid));
  tester_valid.FinishStream();
  tester_valid.RunCompilerTasks();
  CHECK(tester_valid.IsPromiseFulfilled());

  StreamTester tester_invalid(isolate);
  tester_invalid.OnBytesReceived(invalid, arraysize(invalid));
  tester_invalid.FinishStream();
  tester_invalid.RunCompilerTasks();
  CHECK(tester_invalid.IsPromiseRejected());
  CHECK_NE(std::string::npos,
           tester_invalid.error_message().find("unexpected section <Export>"));
}

STREAM_TEST(TestSectionOrderErrorWithNonEmptyCodeSection) {
  // Valid: Export, then Code.
  const uint8_t valid[] = {
      WASM_MODULE_HEADER, SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_v),
      SECTION(Function, ENTRY_COUNT(1), SIG_INDEX(0)),
      SECTION(Export, ENTRY_COUNT(0)),
      SECTION(Code, ENTRY_COUNT(1), ADD_COUNT(WASM_NO_LOCALS, kExprEnd))};
  // Invalid: Code, then Export.
  const uint8_t invalid[] = {
      WASM_MODULE_HEADER, SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_v),
      SECTION(Function, ENTRY_COUNT(1), SIG_INDEX(0)),
      SECTION(Code, ENTRY_COUNT(1), ADD_COUNT(WASM_NO_LOCALS, kExprEnd)),
      SECTION(Export, ENTRY_COUNT(0))};

  StreamTester tester_valid(isolate);
  tester_valid.OnBytesReceived(valid, arraysize(valid));
  tester_valid.FinishStream();
  tester_valid.RunCompilerTasks();
  CHECK(tester_valid.IsPromiseFulfilled());

  StreamTester tester_invalid(isolate);
  tester_invalid.OnBytesReceived(invalid, arraysize(invalid));
  tester_invalid.FinishStream();
  tester_invalid.RunCompilerTasks();
  CHECK(tester_invalid.IsPromiseRejected());
  CHECK_NE(std::string::npos,
           tester_invalid.error_message().find("unexpected section <Export>"));
}

// Test an error in the code section, found by the StreamingDecoder. The error
// is an invalid function body size, so that there are not enough bytes in the
// code section for the function body.
STREAM_TEST(TestErrorInCodeSectionDetectedByStreamingDecoder) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(26),                 // !!! invalid body size !!!
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(1 + arraysize(code) * 3),    // section size
      U32V_1(3),                          // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.FinishStream();

  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

// Test an error in the code section, found by the Compiler. The error is an
// invalid return type.
STREAM_TEST(TestErrorInCodeSectionDetectedByCompiler) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // !!! invalid body size !!!
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  uint8_t invalid_code[] = {
      U32V_1(4),                  // !!! invalid body size !!!
      U32V_1(0),                  // locals count
      kExprI64Const, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(1 + arraysize(code) * 2 +
             arraysize(invalid_code)),  // section size
      U32V_1(3),                        // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.RunCompilerTasks();
  tester.OnBytesReceived(code, arraysize(code));
  tester.RunCompilerTasks();
  tester.OnBytesReceived(invalid_code, arraysize(invalid_code));
  tester.RunCompilerTasks();
  tester.OnBytesReceived(code, arraysize(code));
  tester.RunCompilerTasks();
  tester.FinishStream();
  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

// Test Abort before any bytes arrive.
STREAM_TEST(TestAbortImmediately) {
  StreamTester tester(isolate);
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

// Test Abort within a section.
STREAM_TEST(TestAbortWithinSection1) {
  StreamTester tester(isolate);
  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                // module header
      kTypeSectionCode,                  // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),  // section size
      U32V_1(1)                          // type count
                                         // Type section is not yet complete.
  };
  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.RunCompilerTasks();
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

// Test Abort within a section.
STREAM_TEST(TestAbortWithinSection2) {
  StreamTester tester(isolate);
  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      // Function section is not yet complete.
  };
  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.RunCompilerTasks();
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

// Test Abort just before the code section.
STREAM_TEST(TestAbortAfterSection) {
  StreamTester tester(isolate);
  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
  };
  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.RunCompilerTasks();
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

// Test Abort after the function count in the code section. The compiler tasks
// execute before the abort.
STREAM_TEST(TestAbortAfterFunctionsCount1) {
  StreamTester tester(isolate);
  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(20),                         // section size
      U32V_1(3),                          // functions count
  };
  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.RunCompilerTasks();
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

// Test Abort after the function count in the code section. The compiler tasks
// do not execute before the abort.
STREAM_TEST(TestAbortAfterFunctionsCount2) {
  StreamTester tester(isolate);
  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(20),                         // section size
      U32V_1(3),                          // functions count
  };
  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

// Test Abort after some functions got compiled. The compiler tasks execute
// before the abort.
STREAM_TEST(TestAbortAfterFunctionGotCompiled1) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // !!! invalid body size !!!
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // bo
"""


```
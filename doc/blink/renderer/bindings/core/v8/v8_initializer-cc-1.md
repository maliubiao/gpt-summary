Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `v8_initializer.cc` in the Chromium Blink engine. The prompt specifically asks for its purpose, relationships with web technologies (JavaScript, HTML, CSS), logical deductions, common errors, user interaction tracing, and a summary. The fact that it's part 2 of 2 suggests this snippet likely handles some core initialization tasks, building on what was in part 1 (though we don't have that context).

**2. Initial Scan and Keyword Recognition:**

A quick read-through reveals key terms and patterns:

* **`v8`**:  This immediately tells us it's about the V8 JavaScript engine integration.
* **`InitializeIsolateHolder`**, **`InitializeMainThread`**, **`InitializeWorker`**: These are likely the main functions and indicate different V8 initialization scenarios (main browser thread, worker threads).
* **`Set...Callback`**:  This pattern signifies setting up handlers for various V8 events and functionalities (fatal errors, OOM errors, microtasks, WASM, modules, etc.).
* **`ArrayBufferAllocator`**:  Deals with memory allocation for `ArrayBuffer` objects (used for binary data).
* **`MessageHandler...`**: Handles messages/errors from V8.
* **`PromiseRejectCallback`**, **`ExceptionPropagationCallback`**: Deal with JavaScript promise rejections and exceptions.
* **`SetStackLimit`**:  Manages the call stack size, particularly for worker threads.
* **`BUILDFLAG`**: Indicates platform-specific or build configuration logic.
* **`LOG(FATAL)`**, `LOG(ERROR)`**:  Logging mechanisms for errors.
* **`crash_reporter`**:  Integration with the crash reporting system.

**3. Deeper Dive into Key Sections:**

* **`InitializeIsolateHolder`**:  This seems like the very first step, setting up the fundamental V8 isolate environment. The `ArrayBufferAllocator` is registered here. The presence of `reference_table` and `js_command_line_flags` hints at embedding V8 within a larger system.
* **`InitializeMainThread`**:  This section is rich with `Set...Callback` calls. The callbacks relate to crucial aspects of web page execution:
    * **Error Handling:** `MessageHandlerInMainThread`, `FailedAccessCheckCallbackInMainThread`.
    * **Security:** `CodeGenerationCheckCallbackInMainThread`, `AllowWasmCodeGenerationCallback`.
    * **Asynchronous Operations:** `WasmAsyncResolvePromiseCallback`, `PromiseRejectHandlerInMainThread`.
    * **Module Loading:** `HostImportModuleDynamically`, `HostGetImportMetaProperties`.
    * **Performance Monitoring:** `UseCounterCallback`, `SetMetricsRecorder`.
    * **Garbage Collection:** The interaction with `EmbedderGraphBuilder` and `ActiveScriptWrappableManager`.
* **`InitializeWorker`**: This is similar to `InitializeMainThread` but with adjustments for worker threads, like setting a stack limit. The reuse of some callbacks (`MessageHandlerInWorker`, `PromiseRejectHandlerInWorker`) suggests a common error handling mechanism, albeit with thread-specific implementations.
* **`ArrayBufferAllocator`**:  This class is essential for managing memory used by JavaScript `ArrayBuffer` objects. The logic here prevents excessive memory allocation, potentially leading to crashes. It interacts directly with the system's memory management functions.
* **Error Reporting Functions (`ReportV8FatalError`, `ReportV8OOMError`):** These are crucial for handling critical V8 errors and integrating with the crash reporting infrastructure.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:** The entire file revolves around initializing the JavaScript engine. The callbacks directly impact how JavaScript code is executed, how errors are handled, how asynchronous operations work, and how modules are loaded.
* **HTML:** The JavaScript engine interacts heavily with the DOM (Document Object Model), which represents the HTML structure. The initialization here sets the stage for JavaScript to manipulate the DOM. Callbacks related to security and module loading are relevant to how scripts embedded in HTML are processed.
* **CSS:** While this file doesn't directly manipulate CSS, JavaScript often interacts with CSS (e.g., changing styles dynamically). The correct initialization of the JavaScript engine is a prerequisite for these interactions.

**5. Logical Deductions, Assumptions, and Potential Issues:**

* **Assumption:**  The code assumes the existence of a `Platform` abstraction, `ThreadScheduler`, and other Blink-specific components.
* **Deduction:**  The separation of `InitializeMainThread` and `InitializeWorker` reflects the different execution environments for scripts in the main browser window and within web workers.
* **Potential Issue:**  Incorrectly configured command-line flags (passed to `InitializeIsolateHolder`) could lead to unexpected V8 behavior or crashes.
* **Potential Issue:** Memory allocation failures in `ArrayBufferAllocator` can lead to `RangeError` exceptions in JavaScript.

**6. Tracing User Operations (Debugging Clues):**

Thinking about how a user action might lead to this code involves considering the lifecycle of a web page:

1. **User opens a web page:**  This triggers the browser to load the HTML.
2. **Browser parses HTML:** The parser encounters `<script>` tags or inline JavaScript.
3. **Blink initializes V8:**  `V8Initializer::InitializeMainThread` is called to set up the JavaScript engine for the main page.
4. **JavaScript execution:**  The scripts are executed within the initialized V8 isolate. If a worker is created, `V8Initializer::InitializeWorker` is called for the worker thread.
5. **Errors or exceptions:** If JavaScript code throws an error or if V8 encounters a fatal error, the callback functions defined in this file (`MessageHandlerInMainThread`, `PromiseRejectHandlerInMainThread`, `ReportV8FatalError`) are invoked.

**7. Structuring the Response:**

The prompt asked for specific information (functionality, relationships, deductions, errors, tracing, summary). Organizing the answer into these categories makes it clear and easy to understand. Using bullet points and examples helps to illustrate the concepts.

**8. Refining and Summarizing:**

Finally, a concise summary reiterates the main purpose of the file. The iterative process of reading, analyzing, connecting concepts, and structuring leads to a comprehensive understanding of the code snippet. The focus is on explaining *what* the code does, *why* it does it, and *how* it relates to the broader context of web technologies and user interactions.
```
这是目录为blink/renderer/bindings/core/v8/v8_initializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

根据提供的代码片段，我们可以归纳一下 `v8_initializer.cc` 的功能：

**核心功能： 初始化和配置 V8 JavaScript 引擎实例 (Isolate)**

这个文件主要负责 V8 JavaScript 引擎在 Blink 渲染引擎中的初始化和配置工作。 它为主线程和 Worker 线程创建和设置 V8 实例，并配置各种回调函数和设置，以确保 V8 引擎能够正确地与 Blink 的其他部分交互并执行 JavaScript 代码。

**具体功能点：**

1. **Isolate Holder 初始化:** `InitializeIsolateHolder` 函数负责初始化 `gin::IsolateHolder`，这是 Chromium 中管理 V8 Isolate 的核心类。它设置了内存分配器 (`ArrayBufferAllocator`)，错误处理回调（`ReportV8FatalError`, `ReportV8OOMError`），以及传递给 V8 的命令行标志。

2. **主线程 V8 Isolate 初始化:** `InitializeMainThread` 函数负责创建和配置主线程的 V8 Isolate。 这包括：
    * 设置任务运行器 (TaskRunner)。
    * 根据配置决定是否使用 V8 上下文快照。
    * 注册消息监听器 (`MessageHandlerInMainThread`)，用于处理 V8 的消息，包括错误、警告等。
    * 设置访问检查失败回调 (`FailedAccessCheckCallbackInMainThread`)，用于处理 JavaScript 代码尝试访问不允许访问的属性或方法的情况。
    * 设置代码生成修改回调 (`CodeGenerationCheckCallbackInMainThread`) 和 WASM 代码生成允许回调 (`WasmCodeGenerationCheckCallbackInMainThread`)，用于安全检查。
    * 设置异步 WASM Promise 解析回调 (`WasmAsyncResolvePromiseCallback`)。
    * 根据特性开关启用空闲任务 (`V8IdleTaskRunner`)。
    * 设置 Promise 拒绝回调 (`PromiseRejectHandlerInMainThread`) 和异常传播回调 (`ExceptionPropagationCallback`)。
    * 设置线程调试器 (`MainThreadDebugger`)。
    * 设置创建 ShadowRealm 上下文的回调 (`OnCreateShadowRealmV8Context`)。
    * 根据平台状态设置 Isolate 的优先级。

3. **Worker 线程 V8 Isolate 初始化:** `InitializeWorker` 函数负责配置 Worker 线程的 V8 Isolate。 与主线程类似，但有一些针对 Worker 的特定设置，例如：
    * 设置消息监听器 (`MessageHandlerInWorker`)。
    * 设置堆栈大小限制 (`SetStackLimit`)，防止 Worker 线程耗尽堆栈空间。
    * 设置 Promise 拒绝回调 (`PromiseRejectHandlerInWorker`) 和异常传播回调 (`ExceptionPropagationCallback`)。
    * 设置代码生成修改回调和 WASM 代码生成允许回调。
    * 设置异步 WASM Promise 解析回调。
    * 设置创建 ShadowRealm 上下文的回调。

4. **内存管理:** `ArrayBufferAllocator` 类实现了 V8 的 `ArrayBuffer::Allocator` 接口，负责 `ArrayBuffer` 对象的内存分配和释放。它限制了总的分配量，以防止 V8 消耗过多的内存。

5. **错误报告:** `ReportV8FatalError` 和 `ReportV8OOMError` 函数是 V8 的致命错误和内存溢出错误的全局回调函数，用于记录错误信息并触发崩溃报告。

6. **其他配置:** 文件中还设置了其他 V8 的配置项，例如：
    * 设置 `UseCounterCallback` 用于跟踪 JavaScript 特性的使用情况。
    * 设置 WASM 相关的回调函数，如 `WasmModuleOverride`, `WasmInstanceOverride` 等。
    * 设置动态模块导入回调 (`HostImportModuleDynamically`) 和 `import.meta` 回调 (`HostGetImportMetaProperties`)。
    * 设置性能指标记录器 (`SetMetricsRecorder`).
    * 在 Windows 平台设置 ETW 会话过滤回调。
    * 初始化 V8 上下文快照相关的接口模板。
    * 初始化 WASM 响应扩展。
    * 设置堆分析器的回调函数。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  这个文件是 V8 引擎在 Blink 中的入口点之一，它的主要作用就是初始化和配置 JavaScript 引擎。所有在网页中运行的 JavaScript 代码都由这里初始化的 V8 引擎执行。例如，`MessageHandlerInMainThread` 会处理 JavaScript 运行时的错误信息，`PromiseRejectHandlerInMainThread` 会处理未处理的 Promise 拒绝。

* **HTML:** 当浏览器解析 HTML 遇到 `<script>` 标签时，Blink 会调用 V8 引擎来执行其中的 JavaScript 代码。这个文件的初始化工作是执行这些脚本的前提。`HostImportModuleDynamically` 回调函数就与 HTML 中使用 `<script type="module">` 引入的 JavaScript 模块有关。

* **CSS:**  虽然这个文件不直接处理 CSS，但 JavaScript 可以操作 CSS，例如通过 DOM API 修改元素的样式。 因此，正确初始化 V8 引擎是 JavaScript 操作 CSS 的基础。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  浏览器启动，开始加载网页。
* **输出:** `V8Initializer::InitializeMainThread()` 被调用，创建一个 V8 Isolate 实例并进行配置，以便后续执行网页中的 JavaScript 代码。

* **假设输入:**  网页中创建一个 Web Worker。
* **输出:** `V8Initializer::InitializeWorker()` 被调用，创建一个新的 V8 Isolate 实例并进行配置，用于执行 Worker 线程中的 JavaScript 代码。

**用户或编程常见的使用错误:**

* **内存泄漏:** 如果在 JavaScript 代码中创建了大量对象且没有正确释放，可能会导致 V8 引擎的内存使用量持续增加，最终可能触发 `ReportV8OOMError`。  开发者需要注意避免内存泄漏。

* **未处理的 Promise 拒绝:** 如果 JavaScript 代码中存在未处理的 Promise 拒绝，`PromiseRejectHandlerInMainThread` 或 `PromiseRejectHandlerInWorker` 会被调用，开发者需要在控制台中查看相关的错误信息并修复代码。

* **尝试访问未定义的变量或属性:**  这会导致 JavaScript 运行时错误，`MessageHandlerInMainThread` 会捕获这些错误并报告给开发者。

* **使用了被禁用或实验性的 JavaScript 特性:**  如果 V8 的配置禁用了某些 JavaScript 特性，或者特性开关没有启用，尝试使用这些特性可能会导致错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入网址或点击链接:** 浏览器开始加载网页的 HTML 内容。
2. **渲染引擎 (Blink) 解析 HTML:**  当解析器遇到 `<script>` 标签或需要执行内联 JavaScript 时，会触发 JavaScript 的执行。
3. **Blink 初始化 V8 引擎 (如果尚未初始化):**  `V8Initializer::InitializeMainThread()` 会被调用。
4. **V8 引擎编译和执行 JavaScript 代码:** 用户编写的 JavaScript 代码在 V8 引擎中运行。
5. **在 JavaScript 执行过程中发生错误:**  例如，尝试访问一个未定义的变量。
6. **V8 引擎调用错误处理回调:** `MessageHandlerInMainThread` 会被调用，并将错误信息传递给 Blink 的其他部分，最终可能会在浏览器的开发者工具的控制台中显示出来。

**归纳 `v8_initializer.cc` 的功能 (作为第 2 部分的总结):**

`v8_initializer.cc` 文件是 Chromium Blink 渲染引擎中 V8 JavaScript 引擎初始化和配置的关键组件。 它负责创建和设置主线程和 Worker 线程的 V8 Isolate 实例，并配置各种回调函数以处理错误、安全检查、异步操作、模块加载等。 该文件还负责 V8 引擎的内存管理和性能监控的配置。 它的核心作用是确保 V8 引擎能够正确地与 Blink 的其他部分协同工作，从而能够执行网页中的 JavaScript 代码，实现动态网页的功能。 作为第二部分，它延续了 V8 初始化的工作，可能在第一部分中处理了更基础的 V8 启动和库加载，而这里则专注于更具体的 Blink 集成和配置。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/v8_initializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
isolate, EmbedderGraphBuilder::BuildEmbedderGraphCallback);
  V8PerIsolateData::From(isolate)->SetActiveScriptWrappableManager(
      MakeGarbageCollected<ActiveScriptWrappableManager>());

  isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kScoped);
  isolate->SetUseCounterCallback(&UseCounterCallback);
  isolate->SetWasmModuleCallback(WasmModuleOverride);
  isolate->SetWasmInstanceCallback(WasmInstanceOverride);
  isolate->SetWasmImportedStringsEnabledCallback(
      WasmJSStringBuiltinsEnabledCallback);
  isolate->SetWasmJSPIEnabledCallback(WasmJSPromiseIntegrationEnabledCallback);
  isolate->SetSharedArrayBufferConstructorEnabledCallback(
      SharedArrayBufferConstructorEnabledCallback);
  isolate->SetHostImportModuleDynamicallyCallback(HostImportModuleDynamically);
  isolate->SetHostInitializeImportMetaObjectCallback(
      HostGetImportMetaProperties);
  isolate->SetMetricsRecorder(std::make_shared<V8MetricsRecorder>(isolate));

#if BUILDFLAG(IS_WIN)
  isolate->SetFilterETWSessionByURLCallback(FilterETWSessionByURLCallback);
#endif  // BUILDFLAG(IS_WIN)

  V8ContextSnapshot::EnsureInterfaceTemplates(isolate);

  WasmResponseExtensions::Initialize(isolate);

  if (v8::HeapProfiler* profiler = isolate->GetHeapProfiler()) {
    profiler->SetGetDetachednessCallback(
        V8GCController::DetachednessFromWrapper, nullptr);
  }
}

// Callback functions called when V8 encounters a fatal or OOM error.
// Keep them outside the anonymous namespace such that ChromeCrash recognizes
// them.
void ReportV8FatalError(const char* location, const char* message) {
  LOG(FATAL) << "V8 error: " << message << " (" << location << ").";
}

void ReportV8OOMError(const char* location, const v8::OOMDetails& details) {
  if (location) {
    static crash_reporter::CrashKeyString<64> location_key("v8-oom-location");
    location_key.Set(location);
  }

  if (details.detail) {
    static crash_reporter::CrashKeyString<128> detail_key("v8-oom-detail");
    detail_key.Set(details.detail);
  }

  LOG(ERROR) << PrintV8OOM{location, details};
  OOM_CRASH(0);
}

namespace {
class ArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
 public:
  ArrayBufferAllocator() : total_allocation_(0) {
    // size_t may be equivalent to uint32_t or uint64_t, cast all values to
    // uint64_t to compare.
    uint64_t virtual_size = base::SysInfo::AmountOfVirtualMemory();
    uint64_t size_t_max = std::numeric_limits<std::size_t>::max();
    DCHECK(virtual_size < size_t_max);
    // If AmountOfVirtualMemory() returns 0, there is no limit on virtual
    // memory, do not limit the total allocation. Otherwise, Limit the total
    // allocation to reserve up to 2 GiB virtual memory space for other
    // components.
    uint64_t memory_reserve = 2ull * 1024 * 1024 * 1024;  // 2 GiB
    if (virtual_size > memory_reserve * 2) {
      max_allocation_ = static_cast<size_t>(virtual_size - memory_reserve);
    } else {
      max_allocation_ = static_cast<size_t>(virtual_size / 2);
    }
  }

  // Allocate() methods return null to signal allocation failure to V8, which
  // should respond by throwing a RangeError, per
  // http://www.ecma-international.org/ecma-262/6.0/#sec-createbytedatablock.
  void* Allocate(size_t size) override {
    if (max_allocation_ != 0 &&
        std::atomic_load(&total_allocation_) > max_allocation_ - size)
      return nullptr;
    void* result = ArrayBufferContents::AllocateMemoryOrNull(
        size, ArrayBufferContents::kZeroInitialize);
    if (max_allocation_ != 0 && result)
      total_allocation_.fetch_add(size, std::memory_order_relaxed);
    return result;
  }

  void* AllocateUninitialized(size_t size) override {
    if (max_allocation_ != 0 &&
        std::atomic_load(&total_allocation_) > max_allocation_ - size)
      return nullptr;
    void* result = ArrayBufferContents::AllocateMemoryOrNull(
        size, ArrayBufferContents::kDontInitialize);
    if (max_allocation_ != 0 && result)
      total_allocation_.fetch_add(size, std::memory_order_relaxed);
    return result;
  }

  void Free(void* data, size_t size) override {
    if (max_allocation_ != 0 && data)
      total_allocation_.fetch_sub(size, std::memory_order_relaxed);
    ArrayBufferContents::FreeMemory(data);
  }

 private:
  // Total memory allocated in bytes.
  std::atomic_size_t total_allocation_;
  // If |max_allocation_| is 0, skip these atomic operations on
  // |total_allocation_|.
  size_t max_allocation_;
};

V8PerIsolateData::V8ContextSnapshotMode GetV8ContextSnapshotMode() {
#if BUILDFLAG(USE_V8_CONTEXT_SNAPSHOT)
  if (Platform::Current()->IsTakingV8ContextSnapshot())
    return V8PerIsolateData::V8ContextSnapshotMode::kTakeSnapshot;
  if (gin::GetLoadedSnapshotFileType() ==
      gin::V8SnapshotFileType::kWithAdditionalContext) {
    return V8PerIsolateData::V8ContextSnapshotMode::kUseSnapshot;
  }
#endif  // BUILDFLAG(USE_V8_CONTEXT_SNAPSHOT)
  return V8PerIsolateData::V8ContextSnapshotMode::kDontUseSnapshot;
}

}  // namespace

void V8Initializer::InitializeIsolateHolder(
    const intptr_t* reference_table,
    const std::string& js_command_line_flags) {
  DEFINE_STATIC_LOCAL(ArrayBufferAllocator, array_buffer_allocator, ());
  gin::IsolateHolder::Initialize(gin::IsolateHolder::kNonStrictMode,
                                 &array_buffer_allocator, reference_table,
                                 js_command_line_flags, ReportV8FatalError,
                                 ReportV8OOMError);
}

v8::Isolate* V8Initializer::InitializeMainThread() {
  DCHECK(IsMainThread());
  ThreadScheduler* scheduler = ThreadScheduler::Current();

  V8PerIsolateData::V8ContextSnapshotMode snapshot_mode =
      GetV8ContextSnapshotMode();
  v8::CreateHistogramCallback create_histogram_callback = nullptr;
  v8::AddHistogramSampleCallback add_histogram_sample_callback = nullptr;
  // We don't log histograms when taking a snapshot.
  if (snapshot_mode != V8PerIsolateData::V8ContextSnapshotMode::kTakeSnapshot) {
    create_histogram_callback = CreateHistogram;
    add_histogram_sample_callback = AddHistogramSample;
  }
  v8::Isolate* isolate = V8PerIsolateData::Initialize(
      scheduler->V8TaskRunner(), scheduler->V8UserVisibleTaskRunner(),
      scheduler->V8BestEffortTaskRunner(), snapshot_mode,
      create_histogram_callback, add_histogram_sample_callback);
  scheduler->SetV8Isolate(isolate);

  // ThreadState::isolate_ needs to be set before setting the EmbedderHeapTracer
  // as setting the tracer indicates that a V8 garbage collection should trace
  // over to Blink.
  DCHECK(ThreadStateStorage::MainThreadStateStorage());

  InitializeV8Common(isolate);

  isolate->AddMessageListenerWithErrorLevel(
      MessageHandlerInMainThread,
      v8::Isolate::kMessageError | v8::Isolate::kMessageWarning |
          v8::Isolate::kMessageInfo | v8::Isolate::kMessageDebug |
          v8::Isolate::kMessageLog);
  isolate->SetFailedAccessCheckCallbackFunction(
      V8Initializer::FailedAccessCheckCallbackInMainThread);
  isolate->SetModifyCodeGenerationFromStringsCallback(
      CodeGenerationCheckCallbackInMainThread);
  isolate->SetAllowWasmCodeGenerationCallback(
      WasmCodeGenerationCheckCallbackInMainThread);
  isolate->SetWasmAsyncResolvePromiseCallback(WasmAsyncResolvePromiseCallback);
  if (RuntimeEnabledFeatures::V8IdleTasksEnabled()) {
    V8PerIsolateData::EnableIdleTasks(
        isolate, std::make_unique<V8IdleTaskRunner>(scheduler));
  }

  isolate->SetPromiseRejectCallback(PromiseRejectHandlerInMainThread);
  isolate->SetExceptionPropagationCallback(ExceptionPropagationCallback);

  V8PerIsolateData::From(isolate)->SetThreadDebugger(
      std::make_unique<MainThreadDebugger>(isolate));

  isolate->SetHostCreateShadowRealmContextCallback(
      OnCreateShadowRealmV8Context);

  if (Platform::Current()->IsolateStartsInBackground()) {
    // If we do not track widget visibility, then assume conservatively that
    // the isolate is in background. This reduces memory usage.
    isolate->SetPriority(v8::Isolate::Priority::kBestEffort);
  }

  return isolate;
}

// Stack size for workers is limited to 500KB because default stack size for
// secondary threads is 512KB on macOS. See GetDefaultThreadStackSize() in
// base/threading/platform_thread_apple.mm for details.
//
// For 32-bit Windows, the stack region always starts with an odd number of
// reserved pages, followed by two guard pages, followed by the committed
// memory for the stack, and the worker stack size need to be reduced
// (https://crbug.com/1412239).
#if defined(ARCH_CPU_32_BITS) && BUILDFLAG(IS_WIN)
static const int kWorkerMaxStackSize = 492 * 1024;
#else
static const int kWorkerMaxStackSize = 500 * 1024;
#endif

void V8Initializer::InitializeWorker(v8::Isolate* isolate) {
  InitializeV8Common(isolate);

  isolate->AddMessageListenerWithErrorLevel(
      MessageHandlerInWorker,
      v8::Isolate::kMessageError | v8::Isolate::kMessageWarning |
          v8::Isolate::kMessageInfo | v8::Isolate::kMessageDebug |
          v8::Isolate::kMessageLog);

  isolate->SetStackLimit(WTF::GetCurrentStackPosition() - kWorkerMaxStackSize);
  isolate->SetPromiseRejectCallback(PromiseRejectHandlerInWorker);
  isolate->SetExceptionPropagationCallback(ExceptionPropagationCallback);
  isolate->SetModifyCodeGenerationFromStringsCallback(
      CodeGenerationCheckCallbackInMainThread);
  isolate->SetAllowWasmCodeGenerationCallback(
      WasmCodeGenerationCheckCallbackInMainThread);
  isolate->SetWasmAsyncResolvePromiseCallback(WasmAsyncResolvePromiseCallback);
  isolate->SetHostCreateShadowRealmContextCallback(
      OnCreateShadowRealmV8Context);
}

}  // namespace blink
```
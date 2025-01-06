Response:
The user wants a summary of the functionalities provided by the C++ header file `v8-isolate.h`.

Here's a plan to address the request:

1. **Identify the core purpose of `v8-isolate.h`**: It defines the `Isolate` class, which represents an isolated instance of the V8 JavaScript engine.
2. **Categorize the functionalities** based on the methods provided in the header file. Common categories might include:
    * Isolate lifecycle management (creation, disposal).
    * JavaScript execution and context management.
    * Memory management and garbage collection.
    * Error handling and exceptions.
    * Debugging and profiling.
    * Embedder integration (callbacks and notifications).
    * Performance tuning and resource management.
    * Concurrency and threading.
    * Feature enabling and configuration.
3. **Summarize the purpose of each category** with brief descriptions.
4. **Check for Torque source file**: The header file name doesn't end with `.tq`, so it's not a Torque file.
5. **Identify JavaScript-related functionalities**: Many of the functions directly interact with or influence JavaScript execution.
6. **Provide JavaScript examples**: For key JavaScript-related functionalities, provide simple illustrative examples.
7. **Analyze code logic and provide examples**:  Look for functions that involve explicit input and output, and demonstrate their behavior with examples.
8. **Identify common programming errors**: Point out potential pitfalls or common mistakes users might make when interacting with the `Isolate` API.
9. **Synthesize the information into a comprehensive summary**: Combine the categorized functionalities and examples into a concise overview.
这是 `v8/include/v8-isolate.h` 文件的第二部分，主要定义了 `v8::Isolate` 类提供的用于管理和控制 V8 引擎实例的各种功能。以下是这些功能的归纳：

**核心功能概述：**

这部分主要关注于 `Isolate` 实例在运行时与外部环境的交互、错误处理、内存管理、性能监控以及一些高级特性控制。

**具体功能分类：**

1. **外部内存管理：**
   - `AdjustAmountOfExternalAllocatedMemory`:  允许宿主环境告知 V8 由 JavaScript 对象引用的外部分配内存的变化量。这影响垃圾回收的触发时机。

2. **性能分析：**
   - `GetHeapProfiler`:  获取与此 `Isolate` 关联的堆分析器，用于分析内存使用情况。
   - `SetIdle`:  通知 VM 宿主应用是否处于空闲状态，可能影响 V8 的内部优化。

3. **上下文管理：**
   - `InContext`:  检查当前 `Isolate` 是否有正在活动的上下文。
   - `GetCurrentContext`: 获取当前正在运行的 JavaScript 的上下文，如果没有 JavaScript 运行，则获取栈顶的上下文。
   - `GetEnteredOrMicrotaskContext`:  获取通过 V8 C++ API 进入的最后一个上下文，或者在处理微任务时获取当前微任务的上下文。
   - `GetIncumbentContext`:  获取与 HTML 规范中的 Incumbent realm 对应的上下文。
   - `GetCurrentHostDefinedOptions`: 获取当前运行脚本或模块的主机定义选项（如果有）。

4. **异常处理：**
   - `ThrowError`: 抛出一个 JavaScript 错误。
   - `ThrowException`: 抛出一个 JavaScript 异常。
   - `HasPendingException`:  检查是否存在已抛出但尚未被 JavaScript 或 `v8::TryCatch` 处理的异常。

5. **垃圾回收回调：**
   - `AddGCPrologueCallback`, `AddGCEpilogueCallback`: 允许注册在垃圾回收开始前和结束后执行的回调函数，宿主应用可以借此进行资源管理。
   - `RemoveGCPrologueCallback`, `RemoveGCEpilogueCallback`: 移除已注册的垃圾回收回调。

6. **C++ 堆集成：**
   - `SetEmbedderRootsHandler`: 设置 V8 在执行非统一堆垃圾回收时应考虑的嵌入器根句柄。
   - `AttachCppHeap`:  将一个托管的 C++ 堆作为 JavaScript 堆的扩展附加到 V8。
   - `DetachCppHeap`:  分离之前附加的 C++ 堆。
   - `GetCppHeap`:  获取由 V8 管理的 C++ 堆（如果已附加）。

7. **`Atomics.wait()` 回调：**
   - `AtomicsWaitEvent`: 定义 `Atomics.wait()` 回调接收的事件类型。
   - `AtomicsWaitWakeHandle`:  允许在 `Atomics.wait()` 过程中停止等待。
   - `AtomicsWaitCallback`:  宿主环境为 `Atomics.wait()` 设置的回调函数，用于在等待开始前和结束后接收通知。
   - `SetAtomicsWaitCallback`:  设置新的 `AtomicsWaitCallback`。

8. **外部分配内存大小回调：**
   - `GetExternallyAllocatedMemoryInBytesCallback`: 定义用于获取外部分配内存大小的回调类型。
   - `SetGetExternallyAllocatedMemoryInBytesCallback`: 设置回调函数，用于告知 V8 当前 V8 堆外部的内存分配量。

9. **执行控制：**
   - `TerminateExecution`:  强制终止当前 `Isolate` 的 JavaScript 执行。
   - `IsExecutionTerminating`:  检查 V8 是否正在终止 JavaScript 执行。
   - `CancelTerminateExecution`:  恢复之前被强制终止的 `Isolate` 的执行能力。
   - `RequestInterrupt`: 请求 V8 中断长时间运行的 JavaScript 代码并执行指定的回调。
   - `HasPendingBackgroundTasks`: 检查 V8 中是否存在最终会发布前台任务的后台工作。

10. **测试和调试辅助功能：**
    - `RequestGarbageCollectionForTesting`:  请求执行垃圾回收（仅在启用 `--expose_gc` 时有效，仅用于测试）。
    - `SetEventLogger`: 设置用于记录事件的日志回调。

11. **脚本执行生命周期回调：**
    - `AddBeforeCallEnteredCallback`:  添加一个回调，在脚本即将运行时通知宿主应用。
    - `RemoveBeforeCallEnteredCallback`: 移除通过 `AddBeforeCallEnteredCallback` 安装的回调。
    - `AddCallCompletedCallback`:  添加一个回调，在脚本执行完成后通知宿主应用。
    - `RemoveCallCompletedCallback`: 移除通过 `AddCallCompletedCallback` 安装的回调。

12. **Promise 钩子和拒绝回调：**
    - `SetPromiseHook`: 设置用于 Promise 生命周期事件的钩子回调。
    - `SetPromiseRejectCallback`: 设置用于通知 Promise 拒绝但没有处理程序或撤销此类通知的回调。
    - `SetExceptionPropagationCallback`: 设置用于通知新的异常被抛出的回调（实验性 API）。

13. **微任务管理：**
    - `PerformMicrotaskCheckpoint`:  运行默认的微任务队列直到为空。
    - `EnqueueMicrotask`: 将回调添加到默认的微任务队列。
    - `SetMicrotasksPolicy`: 控制微任务的执行方式。
    - `GetMicrotasksPolicy`: 获取控制微任务执行的策略。
    - `AddMicrotasksCompletedCallback`: 添加一个回调，在默认微任务队列上的微任务运行后通知宿主应用。
    - `RemoveMicrotasksCompletedCallback`: 移除通过 `AddMicrotasksCompletedCallback` 安装的回调。

14. **性能统计回调：**
    - `SetUseCounterCallback`: 设置用于统计 V8 功能使用次数的回调。
    - `SetCounterFunction`: 启用宿主应用提供记录统计计数器的机制。
    - `SetCreateHistogramFunction`, `SetAddHistogramSampleFunction`: 启用宿主应用提供记录直方图的机制。
    - `SetMetricsRecorder`: 启用宿主应用提供记录基于事件的指标的机制。
    - `SetAddCrashKeyCallback`: 启用宿主应用提供记录崩溃键的机制。

15. **内存压力通知：**
    - `LowMemoryNotification`:  可选通知，告知 V8 系统内存不足。
    - `ContextDisposedNotification`: 可选通知，告知 V8 一个上下文已被释放。
    - `IsolateInForegroundNotification`, `IsolateInBackgroundNotification`, `SetPriority`: 可选通知，告知 V8 `Isolate` 的优先级状态，用于指导启发式策略。
    - `SetRAILMode`, `UpdateLoadStartTime`, `SetIsLoading`: 可选通知，告知 V8 嵌入器当前的性能需求或加载状态，用于指导启发式策略（部分已弃用）。
    - `IncreaseHeapLimitForDebugging`, `RestoreOriginalHeapLimit`, `IsHeapLimitIncreasedForDebugging`:  用于调试时临时增加堆限制的功能。

16. **代码生成事件处理：**
    - `SetJitCodeEventHandler`:  允许宿主应用提供一个函数，在代码被添加、移动或删除时收到通知。
    - `SetStackLimit`: 修改此 `Isolate` 的堆栈限制。
    - `GetCodeRange`, `GetEmbeddedCodeRange`: 返回可能包含 JIT 代码的内存范围。
    - `GetJSEntryStubs`: 返回用于 Unwinder API 的 JSEntryStubs。
    - `CopyCodePages`: 将 V8 当前使用的代码堆页面复制到指定的缓冲区。

17. **错误处理回调：**
    - `SetFatalErrorHandler`: 设置在发生致命错误时调用的回调。
    - `SetOOMErrorHandler`: 设置在发生内存溢出错误时调用的回调。
    - `AddNearHeapLimitCallback`, `RemoveNearHeapLimitCallback`, `AutomaticallyRestoreInitialHeapLimit`:  用于在堆大小接近限制时通知宿主应用的回调机制。

18. **代码生成控制回调：**
    - `SetModifyCodeGenerationFromStringsCallback`: 设置回调以检查是否允许从字符串生成代码。
    - `SetAllowWasmCodeGenerationCallback`: 设置回调以检查是否允许 WebAssembly 代码生成。

19. **WebAssembly 集成回调：**
    - `SetWasmModuleCallback`, `SetWasmInstanceCallback`, `SetWasmStreamingCallback`, `SetWasmAsyncResolvePromiseCallback`, `SetWasmLoadSourceMapCallback`, `SetWasmImportedStringsEnabledCallback`, `SetSharedArrayBufferConstructorEnabledCallback`, `SetWasmJSPIEnabledCallback`:  用于 WebAssembly API 的嵌入器重写/加载注入点。

20. **编译提示魔法注释回调（已弃用）：**
    - `SetJavaScriptCompileHintsMagicEnabledCallback`:  注册回调以控制是否启用编译提示魔法注释。

21. **条件特性安装：**
    - `InstallConditionalFeatures`: 允许宿主应用通知 V8 动态启用特性的过程已完成。

22. **Isolate 状态检查：**
    - `IsDead`: 检查 V8 是否已死亡（例如，由于致命错误）。
    - `IsInUse`: 检查此 `Isolate` 是否正在使用中。

23. **消息监听器：**
    - `AddMessageListener`, `AddMessageListenerWithErrorLevel`: 添加消息监听器（用于接收错误等消息）。
    - `RemoveMessageListeners`: 移除指定回调函数的所有消息监听器。
    - `SetFailedAccessCheckCallbackFunction`: 设置报告失败访问检查的回调函数。
    - `SetCaptureStackTraceForUncaughtExceptions`:  告知 V8 在发生未捕获异常时捕获当前堆栈跟踪并报告给消息监听器。

24. **外部资源访问 (已弃用)：**
    - `VisitExternalResources`: 遍历当前 `Isolate` 堆中引用的所有外部资源。

25. **Atomics.wait 允许控制：**
    - `SetAllowAtomicsWait`: 设置是否允许在此 `Isolate` 中调用可能阻塞的 `Atomics.wait` 函数。

26. **日期和时间配置变更通知：**
    - `TimeZoneDetection`: 定义时区重检测指示器。
    - `DateTimeConfigurationChangeNotification`:  通知 V8 宿主环境已更改时区或日期/时间配置。
    - `LocaleConfigurationChangeNotification`: 通知 V8 宿主环境已更改区域设置。
    - `GetDefaultLocale`: 返回默认区域设置字符串（如果启用了 Intl 支持）。

**关于 .tq 文件：**

`v8/include/v8-isolate.h` 文件以 `.h` 结尾，这是一个 C++ 头文件。如果它以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**与 JavaScript 功能的关系及示例：**

这部分列出的很多功能都直接或间接地与 JavaScript 功能相关。以下是一些示例：

* **`ThrowError` / `ThrowException`:**  用于在 C++ 代码中触发 JavaScript 异常。
   ```javascript
   // C++ 代码中调用 isolate->ThrowError("Something went wrong!");
   try {
       // JavaScript 代码执行
   } catch (e) {
       console.error(e); // e 将是 "Something went wrong!" 错误
   }
   ```

* **`AdjustAmountOfExternalAllocatedMemory`:**  影响垃圾回收器对哪些 JavaScript 对象需要回收的判断。例如，当 JavaScript 对象持有对 C++ 分配的资源的引用时，需要使用此方法。
   ```javascript
   // 假设 C++ 分配了一块内存并与一个 JavaScript 对象关联
   let myObject = {};
   // ... 在 C++ 中将外部内存与 myObject 关联 ...
   // ... 当外部内存大小变化时，在 C++ 中调用 AdjustAmountOfExternalAllocatedMemory ...
   ```

* **`SetIdle`:** 可能会影响 V8 的优化策略。当宿主应用知道自己将有一段空闲时间时，可以通知 V8。

* **上下文管理方法 (`GetCurrentContext`, `GetEnteredOrMicrotaskContext`, `GetIncumbentContext`):**  用于在 C++ 代码中获取当前或相关的 JavaScript 上下文，以便进行操作。例如，创建一个新的 JavaScript 值或调用 JavaScript 函数。
   ```c++
   v8::Local<v8::Context> context = isolate->GetCurrentContext();
   v8::Context::Scope context_scope(context);
   v8::Local<v8::String> str = v8::String::NewFromUtf8(isolate, "Hello").ToLocalChecked();
   context->Global()->Set(context, v8::String::NewFromUtf8(isolate, "greeting").ToLocalChecked(), str).Check();
   ```

* **垃圾回收回调 (`AddGCPrologueCallback`, `AddGCEpilogueCallback`):**  允许在垃圾回收前后执行 C++ 代码。
   ```c++
   void GCPrologue(v8::Isolate* isolate, v8::GCType type, v8::GCCallbackFlags flags) {
       std::cout << "Garbage collection started." << std::endl;
   }
   isolate->AddGCPrologueCallback(GCPrologue);
   ```

* **微任务 (`EnqueueMicrotask`):** 允许从 C++ 代码中调度 JavaScript 微任务。
   ```c++
   void MyMicrotask(void* data) {
       // 在 JavaScript 环境中执行的代码
       v8::Isolate* isolate = static_cast<v8::Isolate*>(data);
       v8::HandleScope handle_scope(isolate);
       v8::Local<v8::Context> context = isolate->GetCurrentContext();
       v8::Context::Scope context_scope(context);
       v8::Local<v8::String> log_message = v8::String::NewFromUtf8Literal(isolate, "Microtask executed from C++");
       v8::Local<v8::Value> console_log = context->Global()->Get(context, v8::String::NewFromUtf8Literal(isolate, "console")).ToLocalChecked()->ToObject(context).ToLocalChecked()->Get(context, v8::String::NewFromUtf8Literal(isolate, "log")).ToLocalChecked();
       v8::Function::Call(context, v8::Local<v8::Function>::Cast(console_log), context->Global(), 1, &log_message);
   }

   isolate->EnqueueMicrotask(MyMicrotask, isolate);
   ```

**代码逻辑推理示例：**

假设有以下调用序列：

1. `isolate->AdjustAmountOfExternalAllocatedMemory(1024);`  // 假设外部内存增加了 1024 字节
2. 一段时间后，JavaScript 执行并创建了一些对象。
3. `isolate->AdjustAmountOfExternalAllocatedMemory(-512);` // 假设之前增加的外部内存中有 512 字节被释放

**假设输入：** V8 的垃圾回收策略依赖于外部内存的报告。

**输出：**  V8 会根据 `AdjustAmountOfExternalAllocatedMemory` 报告的增减来调整其垃圾回收的触发频率。增加外部内存可能会导致更频繁的全局垃圾回收，以尝试回收引用这些外部内存的 JavaScript 对象。

**用户常见的编程错误示例：**

* **在错误的线程调用 `Isolate` 的方法：** 许多 `Isolate` 的方法必须在持有 `v8::Locker` 的线程中调用。在非 V8 管理的线程中直接调用可能会导致崩溃或未定义行为。

   ```c++
   // 错误示例 (假设在非 V8 管理的线程中)
   // v8::Isolate* isolate = ...;
   // isolate->GetCurrentContext(); // 错误：可能没有持有 Locker
   ```

* **在垃圾回收回调中执行 JavaScript 代码：**  垃圾回收回调不允许重新进入 JavaScript 执行。这样做会导致未定义行为或崩溃。

   ```c++
   void GCPrologueWithError(v8::Isolate* isolate, v8::GCType type, v8::GCCallbackFlags flags) {
       // 错误：尝试在 GC 回调中执行 JavaScript
       v8::HandleScope handle_scope(isolate);
       v8::Local<v8::Context> context = isolate->GetCurrentContext();
       // ... 执行 JavaScript 代码 ...
   }
   // isolate->AddGCPrologueCallback(GCPrologueWithError); // 错误用法
   ```

* **忘记处理异常：**  如果 C++ 代码调用了可能抛出 JavaScript 异常的 V8 API，并且没有使用 `v8::TryCatch` 进行处理，异常可能会传播到 C++ 代码并导致程序崩溃。

   ```c++
   v8::HandleScope handle_scope(isolate);
   v8::Local<v8::Context> context = isolate->GetCurrentContext();
   v8::Context::Scope context_scope(context);
   v8::Local<v8::String> code = v8::String::NewFromUtf8Literal(isolate, "throw new Error('Oops!');");
   v8::Local<v8::Script> script;
   if (v8::Script::Compile(context, code).ToLocal(&script)) {
       v8::Local<v8::Value> result;
       // 如果编译成功，但执行时抛出异常，这里没有处理
       script->Run(context);
   }
   ```

总而言之，`v8/include/v8-isolate.h` 的第二部分提供了大量用于与 V8 引擎实例交互的高级接口，涵盖了内存管理、错误处理、性能监控和与宿主环境集成的各个方面。理解这些功能对于将 V8 引擎有效地嵌入到 C++ 应用程序中至关重要。

Prompt: 
```
这是目录为v8/include/v8-isolate.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-isolate.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
ered external memory. Used to give V8 an
   * indication of the amount of externally allocated memory that is kept alive
   * by JavaScript objects. V8 uses this to decide when to perform global
   * garbage collections. Registering externally allocated memory will trigger
   * global garbage collections more often than it would otherwise in an attempt
   * to garbage collect the JavaScript objects that keep the externally
   * allocated memory alive.
   *
   * \param change_in_bytes the change in externally allocated memory that is
   *   kept alive by JavaScript objects.
   * \returns the adjusted value.
   */
  int64_t AdjustAmountOfExternalAllocatedMemory(int64_t change_in_bytes);

  /**
   * Returns heap profiler for this isolate. Will return NULL until the isolate
   * is initialized.
   */
  HeapProfiler* GetHeapProfiler();

  /**
   * Tells the VM whether the embedder is idle or not.
   */
  void SetIdle(bool is_idle);

  /** Returns the ArrayBuffer::Allocator used in this isolate. */
  ArrayBuffer::Allocator* GetArrayBufferAllocator();

  /** Returns true if this isolate has a current context. */
  bool InContext();

  /**
   * Returns the context of the currently running JavaScript, or the context
   * on the top of the stack if no JavaScript is running.
   */
  Local<Context> GetCurrentContext();

  /**
   * Returns either the last context entered through V8's C++ API, or the
   * context of the currently running microtask while processing microtasks.
   * If a context is entered while executing a microtask, that context is
   * returned.
   */
  Local<Context> GetEnteredOrMicrotaskContext();

  /**
   * Returns the Context that corresponds to the Incumbent realm in HTML spec.
   * https://html.spec.whatwg.org/multipage/webappapis.html#incumbent
   */
  Local<Context> GetIncumbentContext();

  /**
   * Returns the host defined options set for currently running script or
   * module, if available.
   */
  MaybeLocal<Data> GetCurrentHostDefinedOptions();

  /**
   * Schedules a v8::Exception::Error with the given message.
   * See ThrowException for more details. Templatized to provide compile-time
   * errors in case of too long strings (see v8::String::NewFromUtf8Literal).
   */
  template <int N>
  Local<Value> ThrowError(const char (&message)[N]) {
    return ThrowError(String::NewFromUtf8Literal(this, message));
  }
  Local<Value> ThrowError(Local<String> message);

  /**
   * Schedules an exception to be thrown when returning to JavaScript.  When an
   * exception has been scheduled it is illegal to invoke any JavaScript
   * operation; the caller must return immediately and only after the exception
   * has been handled does it become legal to invoke JavaScript operations.
   */
  Local<Value> ThrowException(Local<Value> exception);

  /**
   * Returns true if an exception was thrown but not processed yet by an
   * exception handler on JavaScript side or by v8::TryCatch handler.
   *
   * This is an experimental feature and may still change significantly.
   */
  bool HasPendingException();

  using GCCallback = void (*)(Isolate* isolate, GCType type,
                              GCCallbackFlags flags);
  using GCCallbackWithData = void (*)(Isolate* isolate, GCType type,
                                      GCCallbackFlags flags, void* data);

  /**
   * Enables the host application to receive a notification before a
   * garbage collection.
   *
   * \param callback The callback to be invoked. The callback is allowed to
   *     allocate but invocation is not re-entrant: a callback triggering
   *     garbage collection will not be called again. JS execution is prohibited
   *     from these callbacks. A single callback may only be registered once.
   * \param gc_type_filter A filter in case it should be applied.
   */
  void AddGCPrologueCallback(GCCallback callback,
                             GCType gc_type_filter = kGCTypeAll);

  /**
   * \copydoc AddGCPrologueCallback(GCCallback, GCType)
   *
   * \param data Additional data that should be passed to the callback.
   */
  void AddGCPrologueCallback(GCCallbackWithData callback, void* data = nullptr,
                             GCType gc_type_filter = kGCTypeAll);

  /**
   * This function removes a callback which was added by
   * `AddGCPrologueCallback`.
   *
   * \param callback the callback to remove.
   */
  void RemoveGCPrologueCallback(GCCallback callback);

  /**
   * \copydoc AddGCPrologueCallback(GCCallback)
   *
   * \param data Additional data that was used to install the callback.
   */
  void RemoveGCPrologueCallback(GCCallbackWithData, void* data = nullptr);

  /**
   * Enables the host application to receive a notification after a
   * garbage collection.
   *
   * \copydetails AddGCPrologueCallback(GCCallback, GCType)
   */
  void AddGCEpilogueCallback(GCCallback callback,
                             GCType gc_type_filter = kGCTypeAll);

  /**
   * \copydoc AddGCEpilogueCallback(GCCallback, GCType)
   *
   * \param data Additional data that should be passed to the callback.
   */
  void AddGCEpilogueCallback(GCCallbackWithData callback, void* data = nullptr,
                             GCType gc_type_filter = kGCTypeAll);

  /**
   * This function removes a callback which was added by
   * `AddGCEpilogueCallback`.
   *
   * \param callback the callback to remove.
   */
  void RemoveGCEpilogueCallback(GCCallback callback);

  /**
   * \copydoc RemoveGCEpilogueCallback(GCCallback)
   *
   * \param data Additional data that was used to install the callback.
   */
  void RemoveGCEpilogueCallback(GCCallbackWithData callback,
                                void* data = nullptr);

  /**
   * Sets an embedder roots handle that V8 should consider when performing
   * non-unified heap garbage collections. The intended use case is for setting
   * a custom handler after invoking `AttachCppHeap()`.
   *
   * V8 does not take ownership of the handler.
   */
  void SetEmbedderRootsHandler(EmbedderRootsHandler* handler);

  /**
   * Attaches a managed C++ heap as an extension to the JavaScript heap. The
   * embedder maintains ownership of the CppHeap. At most one C++ heap can be
   * attached to V8.
   *
   * Multi-threaded use requires the use of v8::Locker/v8::Unlocker, see
   * CppHeap.
   *
   * If a CppHeap is set via CreateParams, then this call is a noop.
   */
  V8_DEPRECATE_SOON(
      "Set the heap on Isolate creation using CreateParams instead.")
  void AttachCppHeap(CppHeap*);

  /**
   * Detaches a managed C++ heap if one was attached using `AttachCppHeap()`.
   *
   * If a CppHeap is set via CreateParams, then this call is a noop.
   */
  V8_DEPRECATE_SOON(
      "Set the heap on Isolate creation using CreateParams instead.")
  void DetachCppHeap();

  /**
   * \returns the C++ heap managed by V8. Only available if such a heap has been
   *   attached using `AttachCppHeap()`.
   */
  CppHeap* GetCppHeap() const;

  /**
   * Use for |AtomicsWaitCallback| to indicate the type of event it receives.
   */
  enum class AtomicsWaitEvent {
    /** Indicates that this call is happening before waiting. */
    kStartWait,
    /** `Atomics.wait()` finished because of an `Atomics.wake()` call. */
    kWokenUp,
    /** `Atomics.wait()` finished because it timed out. */
    kTimedOut,
    /** `Atomics.wait()` was interrupted through |TerminateExecution()|. */
    kTerminatedExecution,
    /** `Atomics.wait()` was stopped through |AtomicsWaitWakeHandle|. */
    kAPIStopped,
    /** `Atomics.wait()` did not wait, as the initial condition was not met. */
    kNotEqual
  };

  /**
   * Passed to |AtomicsWaitCallback| as a means of stopping an ongoing
   * `Atomics.wait` call.
   */
  class V8_EXPORT AtomicsWaitWakeHandle {
   public:
    /**
     * Stop this `Atomics.wait()` call and call the |AtomicsWaitCallback|
     * with |kAPIStopped|.
     *
     * This function may be called from another thread. The caller has to ensure
     * through proper synchronization that it is not called after
     * the finishing |AtomicsWaitCallback|.
     *
     * Note that the ECMAScript specification does not plan for the possibility
     * of wakeups that are neither coming from a timeout or an `Atomics.wake()`
     * call, so this may invalidate assumptions made by existing code.
     * The embedder may accordingly wish to schedule an exception in the
     * finishing |AtomicsWaitCallback|.
     */
    void Wake();
  };

  /**
   * Embedder callback for `Atomics.wait()` that can be added through
   * |SetAtomicsWaitCallback|.
   *
   * This will be called just before starting to wait with the |event| value
   * |kStartWait| and after finishing waiting with one of the other
   * values of |AtomicsWaitEvent| inside of an `Atomics.wait()` call.
   *
   * |array_buffer| will refer to the underlying SharedArrayBuffer,
   * |offset_in_bytes| to the location of the waited-on memory address inside
   * the SharedArrayBuffer.
   *
   * |value| and |timeout_in_ms| will be the values passed to
   * the `Atomics.wait()` call. If no timeout was used, |timeout_in_ms|
   * will be `INFINITY`.
   *
   * In the |kStartWait| callback, |stop_handle| will be an object that
   * is only valid until the corresponding finishing callback and that
   * can be used to stop the wait process while it is happening.
   *
   * This callback may schedule exceptions, *unless* |event| is equal to
   * |kTerminatedExecution|.
   */
  using AtomicsWaitCallback = void (*)(AtomicsWaitEvent event,
                                       Local<SharedArrayBuffer> array_buffer,
                                       size_t offset_in_bytes, int64_t value,
                                       double timeout_in_ms,
                                       AtomicsWaitWakeHandle* stop_handle,
                                       void* data);

  /**
   * Set a new |AtomicsWaitCallback|. This overrides an earlier
   * |AtomicsWaitCallback|, if there was any. If |callback| is nullptr,
   * this unsets the callback. |data| will be passed to the callback
   * as its last parameter.
   */
  void SetAtomicsWaitCallback(AtomicsWaitCallback callback, void* data);

  using GetExternallyAllocatedMemoryInBytesCallback = size_t (*)();

  /**
   * Set the callback that tells V8 how much memory is currently allocated
   * externally of the V8 heap. Ideally this memory is somehow connected to V8
   * objects and may get freed-up when the corresponding V8 objects get
   * collected by a V8 garbage collection.
   */
  void SetGetExternallyAllocatedMemoryInBytesCallback(
      GetExternallyAllocatedMemoryInBytesCallback callback);

  /**
   * Forcefully terminate the current thread of JavaScript execution
   * in the given isolate.
   *
   * This method can be used by any thread even if that thread has not
   * acquired the V8 lock with a Locker object.
   */
  void TerminateExecution();

  /**
   * Is V8 terminating JavaScript execution.
   *
   * Returns true if JavaScript execution is currently terminating
   * because of a call to TerminateExecution.  In that case there are
   * still JavaScript frames on the stack and the termination
   * exception is still active.
   */
  bool IsExecutionTerminating();

  /**
   * Resume execution capability in the given isolate, whose execution
   * was previously forcefully terminated using TerminateExecution().
   *
   * When execution is forcefully terminated using TerminateExecution(),
   * the isolate can not resume execution until all JavaScript frames
   * have propagated the uncatchable exception which is generated.  This
   * method allows the program embedding the engine to handle the
   * termination event and resume execution capability, even if
   * JavaScript frames remain on the stack.
   *
   * This method can be used by any thread even if that thread has not
   * acquired the V8 lock with a Locker object.
   */
  void CancelTerminateExecution();

  /**
   * Request V8 to interrupt long running JavaScript code and invoke
   * the given |callback| passing the given |data| to it. After |callback|
   * returns control will be returned to the JavaScript code.
   * There may be a number of interrupt requests in flight.
   * Can be called from another thread without acquiring a |Locker|.
   * Registered |callback| must not reenter interrupted Isolate.
   */
  void RequestInterrupt(InterruptCallback callback, void* data);

  /**
   * Returns true if there is ongoing background work within V8 that will
   * eventually post a foreground task, like asynchronous WebAssembly
   * compilation.
   */
  bool HasPendingBackgroundTasks();

  /**
   * Request garbage collection in this Isolate. It is only valid to call this
   * function if --expose_gc was specified.
   *
   * This should only be used for testing purposes and not to enforce a garbage
   * collection schedule. It has strong negative impact on the garbage
   * collection performance. Use MemoryPressureNotification() instead to
   * influence the garbage collection schedule.
   */
  void RequestGarbageCollectionForTesting(GarbageCollectionType type);

  /**
   * Request garbage collection with a specific embedderstack state in this
   * Isolate. It is only valid to call this function if --expose_gc was
   * specified.
   *
   * This should only be used for testing purposes and not to enforce a garbage
   * collection schedule. It has strong negative impact on the garbage
   * collection performance. Use MemoryPressureNotification() instead to
   * influence the garbage collection schedule.
   */
  void RequestGarbageCollectionForTesting(GarbageCollectionType type,
                                          StackState stack_state);

  /**
   * Set the callback to invoke for logging event.
   */
  void SetEventLogger(LogEventCallback that);

  /**
   * Adds a callback to notify the host application right before a script
   * is about to run. If a script re-enters the runtime during executing, the
   * BeforeCallEnteredCallback is invoked for each re-entrance.
   * Executing scripts inside the callback will re-trigger the callback.
   */
  void AddBeforeCallEnteredCallback(BeforeCallEnteredCallback callback);

  /**
   * Removes callback that was installed by AddBeforeCallEnteredCallback.
   */
  void RemoveBeforeCallEnteredCallback(BeforeCallEnteredCallback callback);

  /**
   * Adds a callback to notify the host application when a script finished
   * running.  If a script re-enters the runtime during executing, the
   * CallCompletedCallback is only invoked when the outer-most script
   * execution ends.  Executing scripts inside the callback do not trigger
   * further callbacks.
   */
  void AddCallCompletedCallback(CallCompletedCallback callback);

  /**
   * Removes callback that was installed by AddCallCompletedCallback.
   */
  void RemoveCallCompletedCallback(CallCompletedCallback callback);

  /**
   * Set the PromiseHook callback for various promise lifecycle
   * events.
   */
  void SetPromiseHook(PromiseHook hook);

  /**
   * Set callback to notify about promise reject with no handler, or
   * revocation of such a previous notification once the handler is added.
   */
  void SetPromiseRejectCallback(PromiseRejectCallback callback);

  /**
   * This is a part of experimental Api and might be changed without further
   * notice.
   * Do not use it.
   *
   * Set callback to notify about a new exception being thrown.
   */
  void SetExceptionPropagationCallback(ExceptionPropagationCallback callback);

  /**
   * Runs the default MicrotaskQueue until it gets empty and perform other
   * microtask checkpoint steps, such as calling ClearKeptObjects. Asserts that
   * the MicrotasksPolicy is not kScoped. Any exceptions thrown by microtask
   * callbacks are swallowed.
   */
  void PerformMicrotaskCheckpoint();

  /**
   * Enqueues the callback to the default MicrotaskQueue
   */
  void EnqueueMicrotask(Local<Function> microtask);

  /**
   * Enqueues the callback to the default MicrotaskQueue
   */
  void EnqueueMicrotask(MicrotaskCallback callback, void* data = nullptr);

  /**
   * Controls how Microtasks are invoked. See MicrotasksPolicy for details.
   */
  void SetMicrotasksPolicy(MicrotasksPolicy policy);

  /**
   * Returns the policy controlling how Microtasks are invoked.
   */
  MicrotasksPolicy GetMicrotasksPolicy() const;

  /**
   * Adds a callback to notify the host application after
   * microtasks were run on the default MicrotaskQueue. The callback is
   * triggered by explicit RunMicrotasks call or automatic microtasks execution
   * (see SetMicrotaskPolicy).
   *
   * Callback will trigger even if microtasks were attempted to run,
   * but the microtasks queue was empty and no single microtask was actually
   * executed.
   *
   * Executing scripts inside the callback will not re-trigger microtasks and
   * the callback.
   */
  void AddMicrotasksCompletedCallback(
      MicrotasksCompletedCallbackWithData callback, void* data = nullptr);

  /**
   * Removes callback that was installed by AddMicrotasksCompletedCallback.
   */
  void RemoveMicrotasksCompletedCallback(
      MicrotasksCompletedCallbackWithData callback, void* data = nullptr);

  /**
   * Sets a callback for counting the number of times a feature of V8 is used.
   */
  void SetUseCounterCallback(UseCounterCallback callback);

  /**
   * Enables the host application to provide a mechanism for recording
   * statistics counters.
   */
  void SetCounterFunction(CounterLookupCallback);

  /**
   * Enables the host application to provide a mechanism for recording
   * histograms. The CreateHistogram function returns a
   * histogram which will later be passed to the AddHistogramSample
   * function.
   */
  void SetCreateHistogramFunction(CreateHistogramCallback);
  void SetAddHistogramSampleFunction(AddHistogramSampleCallback);

  /**
   * Enables the host application to provide a mechanism for recording
   * event based metrics. In order to use this interface
   *   include/v8-metrics.h
   * needs to be included and the recorder needs to be derived from the
   * Recorder base class defined there.
   * This method can only be called once per isolate and must happen during
   * isolate initialization before background threads are spawned.
   */
  void SetMetricsRecorder(
      const std::shared_ptr<metrics::Recorder>& metrics_recorder);

  /**
   * Enables the host application to provide a mechanism for recording a
   * predefined set of data as crash keys to be used in postmortem debugging in
   * case of a crash.
   */
  void SetAddCrashKeyCallback(AddCrashKeyCallback);

  /**
   * Optional notification that the system is running low on memory.
   * V8 uses these notifications to attempt to free memory.
   */
  void LowMemoryNotification();

  /**
   * Optional notification that a context has been disposed. V8 uses these
   * notifications to guide the GC heuristic and cancel FinalizationRegistry
   * cleanup tasks. Returns the number of context disposals - including this one
   * - since the last time V8 had a chance to clean up.
   *
   * The optional parameter |dependant_context| specifies whether the disposed
   * context was depending on state from other contexts or not.
   */
  int ContextDisposedNotification(bool dependant_context = true);

  /**
   * Optional notification that the isolate switched to the foreground.
   * V8 uses these notifications to guide heuristics.
   */
  V8_DEPRECATE_SOON("Use SetPriority(Priority::kUserBlocking) instead")
  void IsolateInForegroundNotification();

  /**
   * Optional notification that the isolate switched to the background.
   * V8 uses these notifications to guide heuristics.
   */
  V8_DEPRECATE_SOON("Use SetPriority(Priority::kBestEffort) instead")
  void IsolateInBackgroundNotification();

  /**
   * Optional notification that the isolate changed `priority`.
   * V8 uses the priority value to guide heuristics.
   */
  void SetPriority(Priority priority);

  /**
   * Optional notification to tell V8 the current performance requirements
   * of the embedder based on RAIL.
   * V8 uses these notifications to guide heuristics.
   * This is an unfinished experimental feature. Semantics and implementation
   * may change frequently.
   */
  V8_DEPRECATED("Use SetIsLoading instead")
  void SetRAILMode(RAILMode rail_mode);

  /**
   * Update load start time of the RAIL mode
   */
  V8_DEPRECATED("Use SetIsLoading instead")
  void UpdateLoadStartTime();

  /**
   * Optional notification to tell V8 whether the embedder is currently loading
   * resources. If the embedder uses this notification, it should call
   * SetIsLoading(true) when loading starts and SetIsLoading(false) when it
   * ends.
   * It's valid to call SetIsLoading(true) again while loading, which will
   * update the timestamp when V8 considers the load started. Calling
   * SetIsLoading(false) while not loading does nothing.
   * V8 uses these notifications to guide heuristics.
   * This is an unfinished experimental feature. Semantics and implementation
   * may change frequently.
   */
  void SetIsLoading(bool is_loading);

  /**
   * Optional notification to tell V8 the current isolate is used for debugging
   * and requires higher heap limit.
   */
  void IncreaseHeapLimitForDebugging();

  /**
   * Restores the original heap limit after IncreaseHeapLimitForDebugging().
   */
  void RestoreOriginalHeapLimit();

  /**
   * Returns true if the heap limit was increased for debugging and the
   * original heap limit was not restored yet.
   */
  bool IsHeapLimitIncreasedForDebugging();

  /**
   * Allows the host application to provide the address of a function that is
   * notified each time code is added, moved or removed.
   *
   * \param options options for the JIT code event handler.
   * \param event_handler the JIT code event handler, which will be invoked
   *     each time code is added, moved or removed.
   * \note \p event_handler won't get notified of existent code.
   * \note since code removal notifications are not currently issued, the
   *     \p event_handler may get notifications of code that overlaps earlier
   *     code notifications. This happens when code areas are reused, and the
   *     earlier overlapping code areas should therefore be discarded.
   * \note the events passed to \p event_handler and the strings they point to
   *     are not guaranteed to live past each call. The \p event_handler must
   *     copy strings and other parameters it needs to keep around.
   * \note the set of events declared in JitCodeEvent::EventType is expected to
   *     grow over time, and the JitCodeEvent structure is expected to accrue
   *     new members. The \p event_handler function must ignore event codes
   *     it does not recognize to maintain future compatibility.
   * \note Use Isolate::CreateParams to get events for code executed during
   *     Isolate setup.
   */
  void SetJitCodeEventHandler(JitCodeEventOptions options,
                              JitCodeEventHandler event_handler);

  /**
   * Modifies the stack limit for this Isolate.
   *
   * \param stack_limit An address beyond which the Vm's stack may not grow.
   *
   * \note  If you are using threads then you should hold the V8::Locker lock
   *     while setting the stack limit and you must set a non-default stack
   *     limit separately for each thread.
   */
  void SetStackLimit(uintptr_t stack_limit);

  /**
   * Returns a memory range that can potentially contain jitted code. Code for
   * V8's 'builtins' will not be in this range if embedded builtins is enabled.
   *
   * On Win64, embedders are advised to install function table callbacks for
   * these ranges, as default SEH won't be able to unwind through jitted code.
   * The first page of the code range is reserved for the embedder and is
   * committed, writable, and executable, to be used to store unwind data, as
   * documented in
   * https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64.
   *
   * Might be empty on other platforms.
   *
   * https://code.google.com/p/v8/issues/detail?id=3598
   */
  void GetCodeRange(void** start, size_t* length_in_bytes);

  /**
   * As GetCodeRange, but for embedded builtins (these live in a distinct
   * memory region from other V8 Code objects).
   */
  void GetEmbeddedCodeRange(const void** start, size_t* length_in_bytes);

  /**
   * Returns the JSEntryStubs necessary for use with the Unwinder API.
   */
  JSEntryStubs GetJSEntryStubs();

  static constexpr size_t kMinCodePagesBufferSize = 32;

  /**
   * Copies the code heap pages currently in use by V8 into |code_pages_out|.
   * |code_pages_out| must have at least kMinCodePagesBufferSize capacity and
   * must be empty.
   *
   * Signal-safe, does not allocate, does not access the V8 heap.
   * No code on the stack can rely on pages that might be missing.
   *
   * Returns the number of pages available to be copied, which might be greater
   * than |capacity|. In this case, only |capacity| pages will be copied into
   * |code_pages_out|. The caller should provide a bigger buffer on the next
   * call in order to get all available code pages, but this is not required.
   */
  size_t CopyCodePages(size_t capacity, MemoryRange* code_pages_out);

  /** Set the callback to invoke in case of fatal errors. */
  void SetFatalErrorHandler(FatalErrorCallback that);

  /** Set the callback to invoke in case of OOM errors. */
  void SetOOMErrorHandler(OOMErrorCallback that);

  /**
   * Add a callback to invoke in case the heap size is close to the heap limit.
   * If multiple callbacks are added, only the most recently added callback is
   * invoked.
   */
  void AddNearHeapLimitCallback(NearHeapLimitCallback callback, void* data);

  /**
   * Remove the given callback and restore the heap limit to the
   * given limit. If the given limit is zero, then it is ignored.
   * If the current heap size is greater than the given limit,
   * then the heap limit is restored to the minimal limit that
   * is possible for the current heap size.
   */
  void RemoveNearHeapLimitCallback(NearHeapLimitCallback callback,
                                   size_t heap_limit);

  /**
   * If the heap limit was changed by the NearHeapLimitCallback, then the
   * initial heap limit will be restored once the heap size falls below the
   * given threshold percentage of the initial heap limit.
   * The threshold percentage is a number in (0.0, 1.0) range.
   */
  void AutomaticallyRestoreInitialHeapLimit(double threshold_percent = 0.5);

  /**
   * Set the callback to invoke to check if code generation from
   * strings should be allowed.
   */
  void SetModifyCodeGenerationFromStringsCallback(
      ModifyCodeGenerationFromStringsCallback2 callback);

  /**
   * Set the callback to invoke to check if wasm code generation should
   * be allowed.
   */
  void SetAllowWasmCodeGenerationCallback(
      AllowWasmCodeGenerationCallback callback);

  /**
   * Embedder over{ride|load} injection points for wasm APIs. The expectation
   * is that the embedder sets them at most once.
   */
  void SetWasmModuleCallback(ExtensionCallback callback);
  void SetWasmInstanceCallback(ExtensionCallback callback);

  void SetWasmStreamingCallback(WasmStreamingCallback callback);

  void SetWasmAsyncResolvePromiseCallback(
      WasmAsyncResolvePromiseCallback callback);

  void SetWasmLoadSourceMapCallback(WasmLoadSourceMapCallback callback);

  void SetWasmImportedStringsEnabledCallback(
      WasmImportedStringsEnabledCallback callback);

  void SetSharedArrayBufferConstructorEnabledCallback(
      SharedArrayBufferConstructorEnabledCallback callback);

  void SetWasmJSPIEnabledCallback(WasmJSPIEnabledCallback callback);

  /**
   * Register callback to control whether compile hints magic comments are
   * enabled.
   */
  V8_DEPRECATED(
      "Will be removed, use ScriptCompiler::CompileOptions for enabling the "
      "compile hints magic comments")
  void SetJavaScriptCompileHintsMagicEnabledCallback(
      JavaScriptCompileHintsMagicEnabledCallback callback);

  /**
   * This function can be called by the embedder to signal V8 that the dynamic
   * enabling of features has finished. V8 can now set up dynamically added
   * features.
   */
  void InstallConditionalFeatures(Local<Context> context);

  /**
   * Check if V8 is dead and therefore unusable.  This is the case after
   * fatal errors such as out-of-memory situations.
   */
  bool IsDead();

  /**
   * Adds a message listener (errors only).
   *
   * The same message listener can be added more than once and in that
   * case it will be called more than once for each message.
   *
   * If data is specified, it will be passed to the callback when it is called.
   * Otherwise, the exception object will be passed to the callback instead.
   */
  bool AddMessageListener(MessageCallback that,
                          Local<Value> data = Local<Value>());

  /**
   * Adds a message listener.
   *
   * The same message listener can be added more than once and in that
   * case it will be called more than once for each message.
   *
   * If data is specified, it will be passed to the callback when it is called.
   * Otherwise, the exception object will be passed to the callback instead.
   *
   * A listener can listen for particular error levels by providing a mask.
   */
  bool AddMessageListenerWithErrorLevel(MessageCallback that,
                                        int message_levels,
                                        Local<Value> data = Local<Value>());

  /**
   * Remove all message listeners from the specified callback function.
   */
  void RemoveMessageListeners(MessageCallback that);

  /** Callback function for reporting failed access checks.*/
  void SetFailedAccessCheckCallbackFunction(FailedAccessCheckCallback);

  /**
   * Tells V8 to capture current stack trace when uncaught exception occurs
   * and report it to the message listeners. The option is off by default.
   */
  void SetCaptureStackTraceForUncaughtExceptions(
      bool capture, int frame_limit = 10,
      StackTrace::StackTraceOptions options = StackTrace::kOverview);

  /**
   * Iterates through all external resources referenced from current isolate
   * heap.  GC is not invoked prior to iterating, therefore there is no
   * guarantee that visited objects are still alive.
   */
  V8_DEPRECATED("Will be removed without replacement. crbug.com/v8/14172")
  void VisitExternalResources(ExternalResourceVisitor* visitor);

  /**
   * Check if this isolate is in use.
   * True if at least one thread Enter'ed this isolate.
   */
  bool IsInUse();

  /**
   * Set whether calling Atomics.wait (a function that may block) is allowed in
   * this isolate. This can also be configured via
   * CreateParams::allow_atomics_wait.
   */
  void SetAllowAtomicsWait(bool allow);

  /**
   * Time zone redetection indicator for
   * DateTimeConfigurationChangeNotification.
   *
   * kSkip indicates V8 that the notification should not trigger redetecting
   * host time zone. kRedetect indicates V8 that host time zone should be
   * redetected, and used to set the default time zone.
   *
   * The host time zone detection may require file system access or similar
   * operations unlikely to be available inside a sandbox. If v8 is run inside a
   * sandbox, the host time zone has to be detected outside the sandbox before
   * calling DateTimeConfigurationChangeNotification function.
   */
  enum class TimeZoneDetection { kSkip, kRedetect };

  /**
   * Notification that the embedder has changed the time zone, daylight savings
   * time or other date / time configuration parameters. V8 keeps a cache of
   * various values used for date / time computation. This notification will
   * reset those cached values for the current context so that date / time
   * configuration changes would be reflected.
   *
   * This API should not be called more than needed as it will negatively impact
   * the performance of date operations.
   */
  void DateTimeConfigurationChangeNotification(
      TimeZoneDetection time_zone_detection = TimeZoneDetection::kSkip);

  /**
   * Notification that the embedder has changed the locale. V8 keeps a cache of
   * various values used for locale computation. This notification will reset
   * those cached values for the current context so that locale configuration
   * changes would be reflected.
   *
   * This API should not be called more than needed as it will negatively impact
   * the performance of locale operations.
   */
  void LocaleConfigurationChangeNotification();

  /**
   * Returns the default locale in a string if Intl support is enabled.
   * Otherwise returns an empty string.
"""


```
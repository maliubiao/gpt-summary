Response:
The user wants a summary of the functionality described in the provided C++ code snippet from `v8/src/execution/isolate.h`. This is the second part of a four-part section.

**Plan:**

1. **Identify key areas of functionality:** Scan the code for member variables, methods, and enums, grouping them by their apparent purpose.
2. **Summarize the functionality of each area:** Briefly describe what each group of members seems to be responsible for.
3. **Consider the context:** Recall that this is part 2 of 4, suggesting the code relates to a specific aspect of the `Isolate` class. Given the content, it likely deals with error handling, stack management, and context.
4. **Address specific instructions:**
    * **`.tq` extension:** Confirm if the file name suggests a Torque file. It doesn't.
    * **JavaScript relation:** Identify any functions or concepts that directly relate to JavaScript execution.
    * **JavaScript examples:** Provide simple JavaScript snippets to illustrate the related functionalities.
    * **Code logic reasoning:** Look for methods that perform logical operations and provide example inputs and outputs.
    * **Common programming errors:**  Think about how the features described in the code could be misused or lead to errors in JavaScript.
5. **Synthesize the summary:** Combine the identified functionalities into a concise overview.
好的，根据你提供的代码片段（第二部分），我们可以归纳出 `v8/src/execution/isolate.h` 文件的以下功能：

**主要功能归纳：**

这部分代码主要关注以下几个核心功能，它们是 V8 引擎中处理执行上下文和异常管理的关键组成部分：

1. **异常处理 (Exception Handling):**
   - 提供了管理 JavaScript 异常的机制，包括存储、设置、清除和检查异常状态。
   - 允许在 V8 内部以及通过 `v8::TryCatch` 进行异常捕获和处理。
   - 区分了 JavaScript 异常处理和外部 C++ 异常处理。
   - 提供了判断异常是否可以被 JavaScript 或 WebAssembly 代码捕获的方法。
   - 包含用于预测异常捕获位置的机制。
   - 提供了重新抛出异常的功能。
   - 定义了不同类型的异常捕获器 (`ExceptionHandlerType`)。

2. **执行栈管理 (Execution Stack Management):**
   - 维护了 C++ 级别的函数调用栈信息 (`c_entry_fp`, `handler`, `c_function`)。
   - 提供了访问和修改这些栈信息的接口。
   - 涉及到底层 C++ 函数调用与 JavaScript 执行之间的桥梁。

3. **反序列化管理 (Deserialization Management):**
   - 提供了在反序列化过程中进行注册和注销的机制。
   - 用于跟踪是否有正在进行的活动反序列化操作，这在内存管理和验证中很重要。

4. **全局对象和上下文 (Global Object and Context):**
   - 提供了获取当前上下文的全局对象和全局代理对象的方法。

5. **代码页管理 (Code Pages Management):**
   - 允许获取和设置代码页的内存范围，这与代码的加载和执行有关。

6. **调用栈遍历和 Promise 树遍历 (Call Stack and Promise Tree Walking):**
   - 提供了遍历调用栈和 Promise 树的机制，并在可能命中异常的每个函数上调用回调，用于异常捕获预测。

7. **异常作用域 (Exception Scope):**
   - 定义了一个 `ExceptionScope` 类，用于在特定的代码块内管理异常状态。

8. **未捕获异常处理 (Uncaught Exception Handling):**
   - 提供了设置和获取未捕获异常时是否捕获堆栈跟踪的选项。
   - 允许设置在未捕获异常时调用的中止回调函数。

9. **堆栈跟踪 (Stack Tracing):**
   - 提供了多种获取和打印当前堆栈跟踪的方法，包括简洁和详细模式。
   - 允许将堆栈跟踪信息存储到临时缓冲区，用于调试目的（例如生成 minidump）。
   - 提供了捕获详细堆栈跟踪信息、设置错误对象的堆栈信息以及获取简单堆栈跟踪的方法。
   - 提供了查找具有脚本名称或源 URL 的第一个堆栈帧的功能。

10. **访问控制 (Access Control):**
    - 提供了检查给定上下文是否可以访问给定全局对象的方法，并在访问失败时报告。
    - 允许设置访问检查失败时的回调函数。

11. **抛出异常辅助函数 (Throw Helpers):**
    - 提供了便捷的函数来抛出不同类型的异常。

12. **控制台和异步事件委托 (Console and Async Event Delegates):**
    - 提供了设置和获取控制台和异步事件委托的接口，用于调试和异步操作的跟踪。

13. **异步函数和 Promise 监控 (Async Function and Promise Instrumentation):**
    - 提供了在异步函数挂起、Promise then、before 和 after 阶段进行监控的回调。

14. **消息报告 (Message Reporting):**
    - 提供了报告待处理消息的机制。

15. **源代码位置计算 (Source Location Computation):**
    - 提供了计算当前源代码位置的函数，这些位置通常与错误消息相关联。

16. **消息对象创建 (Message Object Creation):**
    - 提供了创建 `JSMessageObject` 的函数，用于表示错误和警告信息。

17. **资源耗尽异常 (Out of Resource Exceptions):**
    - 提供了创建堆栈溢出和终止执行异常的辅助函数。

18. **中断请求 (Interrupt Requests):**
    - 允许请求中断并调用回调函数。

**与其他部分的关系推测：**

由于这是第二部分，我们可以推测：

* **第一部分：** 可能包含了 `Isolate` 类更基础的初始化、内存管理、以及一些核心数据结构的定义。
* **第三部分和第四部分：** 可能会涉及更高级的功能，例如代码编译、垃圾回收、调试支持、内置函数等。

**关于 .tq 扩展名：**

代码片段本身是 C++ 头文件内容。你提到如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。`v8/src/execution/isolate.h` 是一个 C++ 头文件，所以它不是 Torque 源代码。Torque 文件通常用于定义 V8 的内置函数和类型系统。

**与 JavaScript 功能的关系和 JavaScript 示例：**

这段代码与 JavaScript 的异常处理、函数调用、全局对象、Promise 等概念密切相关。以下是一些 JavaScript 示例，展示了这些概念如何与 `isolate.h` 中定义的功能相对应：

```javascript
// 异常处理
try {
  throw new Error("Something went wrong!");
} catch (e) {
  console.error("Caught an error:", e.message);
}

// Promise 异常处理
new Promise((resolve, reject) => {
  reject(new Error("Promise rejected!"));
}).catch(error => {
  console.error("Promise catch:", error.message);
});

// 未捕获异常 (在浏览器或 Node.js 环境中观察)
// 故意抛出一个未捕获的异常
// throw new Error("Uncaught exception!");

// 获取全局对象
console.log(globalThis); // 或 window (在浏览器中) 或 global (在 Node.js 中)
```

在 V8 引擎的内部实现中，当 JavaScript 代码执行这些操作时，`isolate.h` 中定义的机制会被用来管理异常状态、维护调用栈、处理 Promise 的生命周期等。例如：

* 当 JavaScript 代码抛出一个异常时，V8 会创建一个表示该异常的 `Object`，并将其存储在 `exception()` 方法访问的线程本地存储中。
* `TryCatch` 对象在 C++ 层面的注册和注销（`RegisterTryCatchHandler`, `UnregisterTryCatchHandler`）对应了 JavaScript 中 `try...catch` 语句的执行。
* 异步 Promise 的状态变化和回调执行会触发 `OnAsyncFunctionSuspended`, `OnPromiseThen`, `OnPromiseBefore`, `OnPromiseAfter` 等方法的调用，用于跟踪异步操作。

**代码逻辑推理示例：**

假设有以下输入和方法调用：

* **假设输入:** 一个 JavaScript 异常对象 `errorObj` 被抛出。
* **方法调用:** `isolate->Throw(errorObj)`

**推断输出:**

1. `isolate` 对象的内部状态会被更新，`exception()` 方法将返回 `errorObj`。
2. 如果当前有 `TryCatch` 处理器，`try_catch_handler()` 将返回该处理器的指针。
3. `has_exception()` 方法将返回 `true`。
4. `TopExceptionHandlerType(errorObj)` 方法可能会根据当前的调用栈和 `TryCatch` 状态返回 `kJavaScriptHandler` 或 `kExternalTryCatch`。

**用户常见的编程错误示例：**

1. **忘记捕获异常：**  JavaScript 代码中可能会抛出异常，但没有用 `try...catch` 语句包围，导致异常冒泡到顶层，可能导致程序崩溃或非预期行为。`isolate.h` 中的机制会处理这些未捕获的异常。

   ```javascript
   function mightThrow() {
     if (Math.random() > 0.5) {
       throw new Error("Oops!");
     }
     return "Success!";
   }

   // 忘记捕获异常
   let result = mightThrow(); // 如果抛出异常，这里会导致程序错误
   console.log(result);
   ```

2. **在异步操作中未正确处理 Promise 拒绝：**  如果 Promise 被拒绝且没有 `.catch()` 处理，会导致未处理的 Promise 拒绝错误。V8 的 Promise 监控机制会检测到这些情况。

   ```javascript
   function asyncOperation() {
     return new Promise((resolve, reject) => {
       setTimeout(() => {
         reject(new Error("Async operation failed!"));
       }, 100);
     });
   }

   asyncOperation(); // 忘记添加 .catch() 处理
   ```

总而言之，这部分 `isolate.h` 代码定义了 V8 引擎中至关重要的异常处理和执行上下文管理机制，为 JavaScript 代码的可靠执行提供了基础。

### 提示词
```
这是目录为v8/src/execution/isolate.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
trypoint)
  THREAD_LOCAL_TOP_ADDRESS(Address, pending_handler_constant_pool)
  THREAD_LOCAL_TOP_ADDRESS(Address, pending_handler_fp)
  THREAD_LOCAL_TOP_ADDRESS(Address, pending_handler_sp)
  THREAD_LOCAL_TOP_ADDRESS(uintptr_t, num_frames_above_pending_handler)

  v8::TryCatch* try_catch_handler() {
    return thread_local_top()->try_catch_handler_;
  }

  // Interface to exception.
  THREAD_LOCAL_TOP_ADDRESS(Tagged<Object>, exception)
  inline Tagged<Object> exception();
  inline void set_exception(Tagged<Object> exception_obj);
  // Clear thrown exception from V8 and a possible TryCatch.
  inline void clear_exception();

  // Clear the exception only from V8, not from a possible external try-catch.
  inline void clear_internal_exception();
  inline bool has_exception();

  THREAD_LOCAL_TOP_ADDRESS(Tagged<Object>, pending_message)
  inline void clear_pending_message();
  inline Tagged<Object> pending_message();
  inline bool has_pending_message();
  inline void set_pending_message(Tagged<Object> message_obj);

#ifdef DEBUG
  inline Tagged<Object> VerifyBuiltinsResult(Tagged<Object> result);
  inline ObjectPair VerifyBuiltinsResult(ObjectPair pair);
#endif

  enum class ExceptionHandlerType {
    kJavaScriptHandler,
    kExternalTryCatch,
    kNone
  };

  ExceptionHandlerType TopExceptionHandlerType(Tagged<Object> exception);

  inline bool is_catchable_by_javascript(Tagged<Object> exception);
  inline bool is_catchable_by_wasm(Tagged<Object> exception);
  inline bool is_execution_terminating();

  // JS execution stack (see frames.h).
  static Address c_entry_fp(ThreadLocalTop* thread) {
    return thread->c_entry_fp_;
  }
  static Address handler(ThreadLocalTop* thread) { return thread->handler_; }
  Address c_function() { return thread_local_top()->c_function_; }

  inline Address* c_entry_fp_address() {
    return &thread_local_top()->c_entry_fp_;
  }
  static uint32_t c_entry_fp_offset() {
    return static_cast<uint32_t>(OFFSET_OF(Isolate, isolate_data_) +
                                 OFFSET_OF(IsolateData, thread_local_top_) +
                                 OFFSET_OF(ThreadLocalTop, c_entry_fp_) -
                                 isolate_root_bias());
  }
  inline Address* handler_address() { return &thread_local_top()->handler_; }
  inline Address* c_function_address() {
    return &thread_local_top()->c_function_;
  }

#if defined(DEBUG) || defined(VERIFY_HEAP)
  // Count the number of active deserializers, so that the heap verifier knows
  // whether there is currently an active deserialization happening.
  //
  // This is needed as the verifier currently doesn't support verifying objects
  // which are partially deserialized.
  //
  // TODO(leszeks): Make the verifier a bit more deserialization compatible.
  void RegisterDeserializerStarted() { ++num_active_deserializers_; }
  void RegisterDeserializerFinished() {
    CHECK_GE(--num_active_deserializers_, 0);
  }
  bool has_active_deserializer() const {
    return num_active_deserializers_.load(std::memory_order_acquire) > 0;
  }
#else
  void RegisterDeserializerStarted() {}
  void RegisterDeserializerFinished() {}
  bool has_active_deserializer() const { UNREACHABLE(); }
#endif

  // Bottom JS entry.
  Address js_entry_sp() { return thread_local_top()->js_entry_sp_; }
  inline Address* js_entry_sp_address() {
    return &thread_local_top()->js_entry_sp_;
  }

  std::vector<MemoryRange>* GetCodePages() const;

  void SetCodePages(std::vector<MemoryRange>* new_code_pages);

  // Returns the global object of the current context. It could be
  // a builtin object, or a JS global object.
  inline Handle<JSGlobalObject> global_object();

  // Returns the global proxy object of the current context.
  inline Handle<JSGlobalProxy> global_proxy();

  static int ArchiveSpacePerThread() { return sizeof(ThreadLocalTop); }
  void FreeThreadResources() { thread_local_top()->Free(); }

  // Walks the call stack and promise tree and calls a callback on every
  // function an exception is likely to hit. Used in catch prediction.
  // Returns true if the exception is expected to be caught.
  bool WalkCallStackAndPromiseTree(
      MaybeHandle<JSPromise> rejected_promise,
      const std::function<void(PromiseHandler)>& callback);

  class V8_NODISCARD ExceptionScope {
   public:
    // Scope currently can only be used for regular exceptions,
    // not termination exception.
    inline explicit ExceptionScope(Isolate* isolate);
    inline ~ExceptionScope();

   private:
    Isolate* isolate_;
    Handle<Object> exception_;
  };

  void SetCaptureStackTraceForUncaughtExceptions(
      bool capture, int frame_limit, StackTrace::StackTraceOptions options);
  bool get_capture_stack_trace_for_uncaught_exceptions() const;

  void SetAbortOnUncaughtExceptionCallback(
      v8::Isolate::AbortOnUncaughtExceptionCallback callback);

  enum PrintStackMode { kPrintStackConcise, kPrintStackVerbose };
  void PrintCurrentStackTrace(std::ostream& out);
  void PrintStack(StringStream* accumulator,
                  PrintStackMode mode = kPrintStackVerbose);
  void PrintStack(FILE* out, PrintStackMode mode = kPrintStackVerbose);
  Handle<String> StackTraceString();
  // Stores a stack trace in a stack-allocated temporary buffer which will
  // end up in the minidump for debugging purposes.
  V8_NOINLINE void PushStackTraceAndDie(
      void* ptr1 = nullptr, void* ptr2 = nullptr, void* ptr3 = nullptr,
      void* ptr4 = nullptr, void* ptr5 = nullptr, void* ptr6 = nullptr);
  // Similar to the above but without collecting the stack trace.
  V8_NOINLINE void PushParamsAndDie(void* ptr1 = nullptr, void* ptr2 = nullptr,
                                    void* ptr3 = nullptr, void* ptr4 = nullptr,
                                    void* ptr5 = nullptr, void* ptr6 = nullptr);
  // Like PushStackTraceAndDie but uses DumpWithoutCrashing to continue
  // execution.
  V8_NOINLINE void PushStackTraceAndContinue(
      void* ptr1 = nullptr, void* ptr2 = nullptr, void* ptr3 = nullptr,
      void* ptr4 = nullptr, void* ptr5 = nullptr, void* ptr6 = nullptr);
  // Like PushParamsAndDie but uses DumpWithoutCrashing to continue
  // execution.
  V8_NOINLINE void PushParamsAndContinue(
      void* ptr1 = nullptr, void* ptr2 = nullptr, void* ptr3 = nullptr,
      void* ptr4 = nullptr, void* ptr5 = nullptr, void* ptr6 = nullptr);
  Handle<StackTraceInfo> CaptureDetailedStackTrace(
      int limit, StackTrace::StackTraceOptions options);
  MaybeHandle<JSObject> CaptureAndSetErrorStack(Handle<JSObject> error_object,
                                                FrameSkipMode mode,
                                                Handle<Object> caller);
  Handle<StackTraceInfo> GetDetailedStackTrace(Handle<JSReceiver> error_object);
  Handle<FixedArray> GetSimpleStackTrace(Handle<JSReceiver> error_object);
  // Walks the JS stack to find the first frame with a script name or
  // source URL. The inspected frames are the same as for the detailed stack
  // trace.
  Handle<String> CurrentScriptNameOrSourceURL();
  MaybeHandle<Script> CurrentReferrerScript();
  bool GetStackTraceLimit(Isolate* isolate, int* result);

  Address GetAbstractPC(int* line, int* column);

  // Returns if the given context may access the given global object. If
  // the result is false, the exception is guaranteed to be
  // set.
  bool MayAccess(Handle<NativeContext> accessing_context,
                 Handle<JSObject> receiver);

  void SetFailedAccessCheckCallback(v8::FailedAccessCheckCallback callback);
  V8_WARN_UNUSED_RESULT MaybeHandle<Object> ReportFailedAccessCheck(
      Handle<JSObject> receiver);

  // Exception throwing support. The caller should use the result of Throw() as
  // its return value. Returns the Exception sentinel.
  Tagged<Object> Throw(Tagged<Object> exception,
                       MessageLocation* location = nullptr);
  Tagged<Object> ThrowAt(Handle<JSObject> exception, MessageLocation* location);
  Tagged<Object> ThrowIllegalOperation();

  void FatalProcessOutOfHeapMemory(const char* location) {
    heap()->FatalProcessOutOfMemory(location);
  }

  void set_console_delegate(debug::ConsoleDelegate* delegate) {
    console_delegate_ = delegate;
  }
  debug::ConsoleDelegate* console_delegate() { return console_delegate_; }

  void set_async_event_delegate(debug::AsyncEventDelegate* delegate) {
    async_event_delegate_ = delegate;
    PromiseHookStateUpdated();
  }

  // Async function and promise instrumentation support.
  void OnAsyncFunctionSuspended(Handle<JSPromise> promise,
                                Handle<JSPromise> parent);
  void OnPromiseThen(DirectHandle<JSPromise> promise);
  void OnPromiseBefore(Handle<JSPromise> promise);
  void OnPromiseAfter(Handle<JSPromise> promise);
  void OnStackTraceCaptured(Handle<StackTraceInfo> stack_trace);
  void OnTerminationDuringRunMicrotasks();

  // Re-throw an exception.  This involves no error reporting since error
  // reporting was handled when the exception was thrown originally.
  // The first overload doesn't set the corresponding pending message, which
  // has to be set separately or be guaranteed to not have changed.
  Tagged<Object> ReThrow(Tagged<Object> exception);
  Tagged<Object> ReThrow(Tagged<Object> exception, Tagged<Object> message);

  // Find the correct handler for the current exception. This also
  // clears and returns the current exception.
  Tagged<Object> UnwindAndFindHandler();

  // Tries to predict whether an exception will be caught. Note that this can
  // only produce an estimate, because it is undecidable whether a finally
  // clause will consume or re-throw an exception.
  enum CatchType {
    NOT_CAUGHT,
    CAUGHT_BY_JAVASCRIPT,
    CAUGHT_BY_EXTERNAL,
    CAUGHT_BY_PROMISE,
    CAUGHT_BY_ASYNC_AWAIT,
  };
  CatchType PredictExceptionCatcher();

  void ReportPendingMessages(bool report = true);

  // Attempts to compute the current source location, storing the
  // result in the target out parameter. The source location is attached to a
  // Message object as the location which should be shown to the user. It's
  // typically the top-most meaningful location on the stack.
  bool ComputeLocation(MessageLocation* target);
  bool ComputeLocationFromException(MessageLocation* target,
                                    Handle<Object> exception);
  bool ComputeLocationFromSimpleStackTrace(MessageLocation* target,
                                           Handle<Object> exception);
  bool ComputeLocationFromDetailedStackTrace(MessageLocation* target,
                                             Handle<Object> exception);

  Handle<JSMessageObject> CreateMessage(Handle<Object> exception,
                                        MessageLocation* location);
  Handle<JSMessageObject> CreateMessageOrAbort(Handle<Object> exception,
                                               MessageLocation* location);
  // Similar to Isolate::CreateMessage but DOESN'T inspect the JS stack and
  // only looks at the "detailed stack trace" as the "simple stack trace" might
  // have already been stringified.
  Handle<JSMessageObject> CreateMessageFromException(Handle<Object> exception);

  // Out of resource exception helpers.
  Tagged<Object> StackOverflow();
  Tagged<Object> TerminateExecution();
  void CancelTerminateExecution();

  void RequestInterrupt(InterruptCallback callback, void* data);
  void InvokeApiInterruptCallbacks();

  void RequestInvalidateNoProfilingProtector();

  // Administration
  void Iterate(RootVisitor* v);
  void Iterate(RootVisitor* v, ThreadLocalTop* t);
  char* Iterate(RootVisitor* v, char* t);
  void IterateThread(ThreadVisitor* v, char* t);

  // Returns the current native context.
  inline Handle<NativeContext> native_context();
  inline Tagged<NativeContext> raw_native_context();

  inline Handle<NativeContext> GetIncumbentContext();
  Handle<NativeContext> GetIncumbentContextSlow();

  void RegisterTryCatchHandler(v8::TryCatch* that);
  void UnregisterTryCatchHandler(v8::TryCatch* that);

  char* ArchiveThread(char* to);
  char* RestoreThread(char* from);

  static const int kUC16AlphabetSize = 256;  // See StringSearchBase.
  static const int kBMMaxShift = 250;        // See StringSearchBase.

  // Accessors.
#define GLOBAL_ACCESSOR(type, name, initialvalue)                 \
  inline type name() const {                                      \
    DCHECK_EQ(OFFSET_OF(Isolate, name##_), name##_debug_offset_); \
    return name##_;                                               \
  }                                                               \
  inline void set_##name(type value) {                            \
    DCHECK_EQ(OFFSET_OF(Isolate, name##_), name##_debug_offset_); \
    name##_ = value;                                              \
  }
  ISOLATE_INIT_LIST(GLOBAL_ACCESSOR)
#undef GLOBAL_ACCESSOR

  void SetDetailedSourcePositionsForProfiling(bool value) {
    if (value) {
      CollectSourcePositionsForAllBytecodeArrays();
    }
    detailed_source_positions_for_profiling_ = value;
  }

  bool detailed_source_positions_for_profiling() const {
    return detailed_source_positions_for_profiling_;
  }

#define GLOBAL_ARRAY_ACCESSOR(type, name, length)                \
  inline type* name() {                                          \
    DCHECK(OFFSET_OF(Isolate, name##_) == name##_debug_offset_); \
    return &(name##_)[0];                                        \
  }
  ISOLATE_INIT_ARRAY_LIST(GLOBAL_ARRAY_ACCESSOR)
#undef GLOBAL_ARRAY_ACCESSOR

#define NATIVE_CONTEXT_FIELD_ACCESSOR(index, type, name) \
  inline Handle<UNPAREN(type)> name();                   \
  inline bool is_##name(Tagged<UNPAREN(type)> value);
  NATIVE_CONTEXT_FIELDS(NATIVE_CONTEXT_FIELD_ACCESSOR)
#undef NATIVE_CONTEXT_FIELD_ACCESSOR

  Bootstrapper* bootstrapper() { return bootstrapper_; }
  // Use for updating counters on a foreground thread.
  Counters* counters() { return async_counters().get(); }
  // Use for updating counters on a background thread.
  const std::shared_ptr<Counters>& async_counters() {
    // Make sure InitializeCounters() has been called.
    DCHECK_NOT_NULL(async_counters_.get());
    return async_counters_;
  }
  const std::shared_ptr<metrics::Recorder>& metrics_recorder() {
    return metrics_recorder_;
  }
  TieringManager* tiering_manager() { return tiering_manager_; }
  CompilationCache* compilation_cache() { return compilation_cache_; }
  V8FileLogger* v8_file_logger() const {
    // Call InitializeLoggingAndCounters() if logging is needed before
    // the isolate is fully initialized.
    DCHECK_NOT_NULL(v8_file_logger_);
    return v8_file_logger_;
  }
  StackGuard* stack_guard() { return isolate_data()->stack_guard(); }
  Heap* heap() { return &heap_; }
  const Heap* heap() const { return &heap_; }
  ReadOnlyHeap* read_only_heap() const { return read_only_heap_; }
  static Isolate* FromHeap(const Heap* heap) {
    return reinterpret_cast<Isolate*>(reinterpret_cast<Address>(heap) -
                                      OFFSET_OF(Isolate, heap_));
  }

  const IsolateData* isolate_data() const { return &isolate_data_; }
  IsolateData* isolate_data() { return &isolate_data_; }

  // When pointer compression is on, this is the base address of the pointer
  // compression cage, and the kPtrComprCageBaseRegister is set to this
  // value. When pointer compression is off, this is always kNullAddress.
  Address cage_base() const {
    DCHECK_IMPLIES(!COMPRESS_POINTERS_BOOL,
                   isolate_data()->cage_base() == kNullAddress);
    return isolate_data()->cage_base();
  }

  // When pointer compression and external code space are on, this is the base
  // address of the cage where the code space is allocated. Otherwise, it
  // defaults to cage_base().
  Address code_cage_base() const {
#ifdef V8_EXTERNAL_CODE_SPACE
    return code_cage_base_;
#else
    return cage_base();
#endif  // V8_EXTERNAL_CODE_SPACE
  }

  IsolateGroup* isolate_group() const { return isolate_group_; }

#ifdef V8_COMPRESS_POINTERS
  VirtualMemoryCage* GetPtrComprCage() const {
    return isolate_group()->GetPtrComprCage();
  }
  VirtualMemoryCage* GetPtrComprCodeCageForTesting();
#endif

  // Generated code can embed this address to get access to the isolate-specific
  // data (for example, roots, external references, builtins, etc.).
  // The kRootRegister is set to this value.
  Address isolate_root() const { return isolate_data()->isolate_root(); }
  constexpr static size_t isolate_root_bias() {
    return OFFSET_OF(Isolate, isolate_data_) + IsolateData::kIsolateRootBias;
  }
  static Isolate* FromRootAddress(Address isolate_root) {
    return reinterpret_cast<Isolate*>(isolate_root - isolate_root_bias());
  }

  RootsTable& roots_table() { return isolate_data()->roots(); }
  const RootsTable& roots_table() const { return isolate_data()->roots(); }

  // A sub-region of the Isolate object that has "predictable" layout which
  // depends only on the pointer size and therefore it's guaranteed that there
  // will be no compatibility issues because of different compilers used for
  // snapshot generator and actual V8 code.
  // Thus, kRootRegister may be used to address any location that falls into
  // this region.
  // See IsolateData::AssertPredictableLayout() for details.
  base::AddressRegion root_register_addressable_region() const {
    return base::AddressRegion(reinterpret_cast<Address>(&isolate_data_),
                               sizeof(IsolateData));
  }

  Tagged<Object> root(RootIndex index) const {
    return Tagged<Object>(roots_table()[index]);
  }

  Handle<Object> root_handle(RootIndex index) {
    return Handle<Object>(&roots_table()[index]);
  }

  ExternalReferenceTable* external_reference_table() {
    DCHECK(isolate_data()->external_reference_table()->is_initialized());
    return isolate_data()->external_reference_table();
  }

  ExternalReferenceTable* external_reference_table_unsafe() {
    // The table may only be partially initialized at this point.
    return isolate_data()->external_reference_table();
  }

  Address* builtin_entry_table() { return isolate_data_.builtin_entry_table(); }

#ifdef V8_ENABLE_LEAPTIERING
  // Predicting the handles using `GetStaticHandleForReadOnlySegmentEntry` is
  // only possible if we have just one sole read only heap. In case we extend
  // support to other build configurations we need a table of dispatch entries
  // per isolate. See https://crrev.com/c/5783686 on how to do that.
  static constexpr bool kBuiltinDispatchHandlesAreStatic =
      ReadOnlyHeap::IsReadOnlySpaceShared();

  static V8_INLINE JSDispatchHandle
  builtin_dispatch_handle(JSBuiltinDispatchHandleRoot::Idx idx) {
    static_assert(kBuiltinDispatchHandlesAreStatic);
    return JSDispatchTable::GetStaticHandleForReadOnlySegmentEntry(idx);
  }
  V8_INLINE JSDispatchHandle builtin_dispatch_handle(Builtin builtin) {
    return builtin_dispatch_handle(
        JSBuiltinDispatchHandleRoot::to_idx(builtin));
  }
#endif
  V8_INLINE Address* builtin_table() { return isolate_data_.builtin_table(); }
  V8_INLINE Address* builtin_tier0_table() {
    return isolate_data_.builtin_tier0_table();
  }

  bool IsBuiltinTableHandleLocation(Address* handle_location);

  StubCache* load_stub_cache() const { return load_stub_cache_; }
  StubCache* store_stub_cache() const { return store_stub_cache_; }
  StubCache* define_own_stub_cache() const { return define_own_stub_cache_; }
  Deoptimizer* GetAndClearCurrentDeoptimizer() {
    Deoptimizer* result = current_deoptimizer_;
    CHECK_NOT_NULL(result);
    current_deoptimizer_ = nullptr;
    return result;
  }
  void set_current_deoptimizer(Deoptimizer* deoptimizer) {
    DCHECK_NULL(current_deoptimizer_);
    DCHECK_NOT_NULL(deoptimizer);
    current_deoptimizer_ = deoptimizer;
  }
  bool deoptimizer_lazy_throw() const { return deoptimizer_lazy_throw_; }
  void set_deoptimizer_lazy_throw(bool value) {
    deoptimizer_lazy_throw_ = value;
  }
  void InitializeThreadLocal();
  ThreadLocalTop* thread_local_top() {
    return &isolate_data_.thread_local_top_;
  }
  ThreadLocalTop const* thread_local_top() const {
    return &isolate_data_.thread_local_top_;
  }

  static constexpr uint32_t thread_in_wasm_flag_address_offset() {
    // For WebAssembly trap handlers there is a flag in thread-local storage
    // which indicates that the executing thread executes WebAssembly code. To
    // access this flag directly from generated code, we store a pointer to the
    // flag in ThreadLocalTop in thread_in_wasm_flag_address_. This function
    // here returns the offset of that member from {isolate_root()}.
    return static_cast<uint32_t>(
        OFFSET_OF(Isolate, isolate_data_) +
        OFFSET_OF(IsolateData, thread_local_top_) +
        OFFSET_OF(ThreadLocalTop, thread_in_wasm_flag_address_) -
        isolate_root_bias());
  }

  constexpr static uint32_t context_offset() {
    return static_cast<uint32_t>(
        OFFSET_OF(Isolate, isolate_data_) +
        OFFSET_OF(IsolateData, thread_local_top_) +
        OFFSET_OF(ThreadLocalTop, context_) -
        isolate_root_bias());
  }

  static uint32_t error_message_param_offset() {
    return static_cast<uint32_t>(OFFSET_OF(Isolate, isolate_data_) +
                                 OFFSET_OF(IsolateData, error_message_param_) -
                                 isolate_root_bias());
  }

  uint8_t error_message_param() { return isolate_data_.error_message_param_; }

  THREAD_LOCAL_TOP_ADDRESS(Address, thread_in_wasm_flag_address)

  THREAD_LOCAL_TOP_ADDRESS(uint8_t, is_on_central_stack_flag)

  MaterializedObjectStore* materialized_object_store() const {
    return materialized_object_store_;
  }

  DescriptorLookupCache* descriptor_lookup_cache() const {
    return descriptor_lookup_cache_;
  }

  V8_INLINE HandleScopeData* handle_scope_data() {
    return &isolate_data_.handle_scope_data_;
  }

  HandleScopeImplementer* handle_scope_implementer() const {
    DCHECK(handle_scope_implementer_);
    return handle_scope_implementer_;
  }

  UnicodeCache* unicode_cache() const { return unicode_cache_; }

  InnerPointerToCodeCache* inner_pointer_to_code_cache() {
    return inner_pointer_to_code_cache_;
  }

#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmCodeLookupCache* wasm_code_look_up_cache() {
    return wasm_code_look_up_cache_;
  }
  wasm::WasmOrphanedGlobalHandle* NewWasmOrphanedGlobalHandle();
  wasm::StackPool& stack_pool() { return stack_pool_; }
  Builtins::WasmBuiltinHandleArray& wasm_builtin_code_handles() {
    return wasm_builtin_code_handles_;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  GlobalHandles* global_handles() const { return global_handles_; }

  TracedHandles* traced_handles() { return &traced_handles_; }

  EternalHandles* eternal_handles() const { return eternal_handles_; }

  ThreadManager* thread_manager() const { return thread_manager_; }

  bigint::Processor* bigint_processor() { return bigint_processor_; }

#ifndef V8_INTL_SUPPORT
  unibrow::Mapping<unibrow::Ecma262UnCanonicalize>* jsregexp_uncanonicalize() {
    return &jsregexp_uncanonicalize_;
  }

  unibrow::Mapping<unibrow::CanonicalizationRange>* jsregexp_canonrange() {
    return &jsregexp_canonrange_;
  }

  unibrow::Mapping<unibrow::Ecma262Canonicalize>*
  regexp_macro_assembler_canonicalize() {
    return &regexp_macro_assembler_canonicalize_;
  }
#endif  // !V8_INTL_SUPPORT

  RuntimeState* runtime_state() { return &runtime_state_; }

  Builtins* builtins() { return &builtins_; }

  RegExpStack* regexp_stack() const { return regexp_stack_; }

  // Either points to jsregexp_static_offsets_vector, or nullptr if the static
  // vector is in use.
  int32_t* regexp_static_result_offsets_vector() const {
    return isolate_data()->regexp_static_result_offsets_vector();
  }
  void set_regexp_static_result_offsets_vector(int32_t* value) {
    DCHECK_EQ(value == nullptr,
              regexp_static_result_offsets_vector() != nullptr);
    isolate_data()->set_regexp_static_result_offsets_vector(value);
  }
  Address address_of_regexp_static_result_offsets_vector() const {
    return isolate_data()->regexp_static_result_offsets_vector_address();
  }

  // This data structure is only used for an optimization in StringSplit.
  // TODO(jgruber): Consider removing it.
  std::vector<int>* regexp_indices() { return &regexp_indices_; }

  size_t total_regexp_code_generated() const {
    return total_regexp_code_generated_;
  }
  void IncreaseTotalRegexpCodeGenerated(DirectHandle<HeapObject> code);

  Debug* debug() const { return debug_; }

  bool is_profiling() const {
    return isolate_data_.execution_mode_ &
           IsolateExecutionModeFlag::kIsProfiling;
  }

  void SetIsProfiling(bool enabled) {
    if (enabled) {
      CollectSourcePositionsForAllBytecodeArrays();
      RequestInvalidateNoProfilingProtector();
    }
    isolate_data_.execution_mode_.set(IsolateExecutionModeFlag::kIsProfiling,
                                      enabled);
    UpdateLogObjectRelocation();
  }

  // Perform side effect checks on function calls and API callbacks.
  // See Debug::StartSideEffectCheckMode().
  bool should_check_side_effects() const {
    return isolate_data_.execution_mode_ &
           IsolateExecutionModeFlag::kCheckSideEffects;
  }

  DebugInfo::ExecutionMode debug_execution_mode() const {
    return should_check_side_effects() ? DebugInfo::kSideEffects
                                       : DebugInfo::kBreakpoints;
  }
  void set_debug_execution_mode(DebugInfo::ExecutionMode debug_execution_mode) {
    bool check_side_effects = debug_execution_mode == DebugInfo::kSideEffects;
    isolate_data_.execution_mode_.set(
        IsolateExecutionModeFlag::kCheckSideEffects, check_side_effects);
  }

  Logger* logger() const { return logger_; }
  HeapProfiler* heap_profiler() const { return heap_profiler_; }

#ifdef DEBUG
  static size_t non_disposed_isolates() { return non_disposed_isolates_; }

  // Turbofan's string builder optimization can introduce SlicedString that are
  // less than SlicedString::kMinLength characters. Their live range and scope
  // are pretty limitted, but they can be visible to the GC, which shouldn't
  // treat them as invalid. When such short SlicedString are introduced,
  // Turbofan will set has_turbofan_string_builders_ to true, which
  // SlicedString::SlicedStringVerify will check when verifying SlicedString to
  // decide if a too-short SlicedString is an issue or not.
  // See the compiler's StringBuilderOptimizer class for more details.
  bool has_turbofan_string_builders() { return has_turbofan_string_builders_; }
  void set_has_turbofan_string_builders() {
    has_turbofan_string_builders_ = true;
  }
#endif

  v8::internal::Factory* factory() {
    // Upcast to the privately inherited base-class using c-style casts to avoid
    // undefined behavior (as static_cast cannot cast across private bases).
    return (v8::internal::Factory*)this;
  }

  static const int kJSRegexpStaticOffsetsVectorSize = 128;

  THREAD_LOCAL_TOP_ACCESSOR(ExternalCallbackScope*, external_callback_scope)

  THREAD_LOCAL_TOP_ACCESSOR(StateTag, current_vm_state)
  THREAD_LOCAL_TOP_ACCESSOR(EmbedderState*, current_embedder_state)

  void SetData(uint32_t slot, void* data) {
    DCHECK_LT(slot, Internals::kNumIsolateDataSlots);
    isolate_data_.embedder_data_[slot] = data;
  }
  void* GetData(uint32_t slot) const {
    DCHECK_LT(slot, Internals::kNumIsolateDataSlots);
    return isolate_data_.embedder_data_[slot];
  }

  bool serializer_enabled() const { return serializer_enabled_; }

  void enable_serializer() { serializer_enabled_ = true; }

  bool snapshot_available() const {
    return snapshot_blob_ != nullptr && snapshot_blob_->raw_size != 0;
  }

  bool IsDead() const { return has_fatal_error_; }
  void SignalFatalError() { has_fatal_error_ = true; }

  bool use_optimizer();

  bool initialized_from_snapshot() { return initialized_from_snapshot_; }

  bool NeedsSourcePositions() const;

  bool IsLoggingCodeCreation() const;

  inline bool InFastCCall() const;

  bool AllowsCodeCompaction() const;

  bool NeedsDetailedOptimizedCodeLineInfo() const;

  bool is_best_effort_code_coverage() const {
    return code_coverage_mode() == debug::CoverageMode::kBestEffort;
  }

  bool is_precise_count_code_coverage() const {
    return code_coverage_mode() == debug::CoverageMode::kPreciseCount;
  }

  bool is_precise_binary_code_coverage() const {
    return code_coverage_mode() == debug::CoverageMode::kPreciseBinary;
  }

  bool is_block_count_code_coverage() const {
    return code_coverage_mode() == debug::CoverageMode::kBlockCount;
  }

  bool is_block_binary_code_coverage() const {
    return code_coverage_mode() == debug::CoverageMode::kBlockBinary;
  }

  bool is_block_code_coverage() const {
    return is_block_count_code_coverage() || is_block_binary_code_coverage();
  }

  bool is_binary_code_coverage() const {
    return is_precise_binary_code_coverage() || is_block_binary_code_coverage();
  }

  bool is_count_code_coverage() const {
    return is_precise_count_code_coverage() || is_block_count_code_coverage();
  }

  // Collect feedback vectors with data for code coverage or type profile.
  // Reset the list, when both code coverage and type profile are not
  // needed anymore. This keeps many feedback vectors alive, but code
  // coverage or type profile are used for debugging only and increase in
  // memory usage is expected.
  void SetFeedbackVectorsForProfilingTools(Tagged<Object> value);

  void MaybeInitializeVectorListFromHeap();

  double time_millis_since_init() const {
    return heap_.MonotonicallyIncreasingTimeInMs() - time_millis_at_init_;
  }

  DateCache* date_cache() const { return date_cache_; }

  void set_date_cache(DateCache* date_cache);

#ifdef V8_INTL_SUPPORT

  const std::string& DefaultLocale();

  void ResetDefaultLocale();

  void set_default_locale(const std::string& locale) {
    DCHECK_EQ(default_locale_.length(), 0);
    default_locale_ = locale;
  }

  enum class ICUObjectCacheType{
      kDefaultCollator, kDefaultNumberFormat, kDefaultSimpleDateFormat,
      kDefaultSimpleDateFormatForTime, kDefaultSimpleDateFormatForDate};
  static constexpr int kICUObjectCacheTypeCount = 5;

  icu::UMemory* get_cached_icu_object(ICUObjectCacheType cache_type,
                                      Handle<Object> locales);
  void set_icu_object_in_cache(ICUObjectCacheType cache_type,
                               DirectHandle<Object> locales,
                               std::shared_ptr<icu::UMemory> obj);
  void clear_cached_icu_object(ICUObjectCacheType cache_type);
  void clear_cached_icu_objects();

#endif  // V8_INTL_SUPPORT

  enum class KnownPrototype { kNone, kObject, kArray, kString };

  KnownPrototype IsArrayOrObjectOrStringPrototype(Tagged<JSObject> object);

  // On intent to set an element in object, make sure that appropriate
  // notifications occur if the set is on the elements of the array or
  // object prototype. Also ensure that changes to prototype chain between
  // Array and Object fire notifications.
  void UpdateNoElementsProtectorOnSetElement(DirectHandle<JSObject> object);
  void UpdateNoElementsProtectorOnSetLength(DirectHandle<JSObject> object) {
    UpdateNoElementsProtectorOnSetElement(object);
  }

  void UpdateProtectorsOnSetPrototype(DirectHandle<JSObject> object,
                                      DirectHandle<Object> new_prototype);

  void UpdateNoElementsProtectorOnSetPrototype(DirectHandle<JSObject> object) {
    UpdateNoElementsProtectorOnSetElement(object);
  }
  void UpdateTypedArraySpeciesLookupChainProtectorOnSetPrototype(
      DirectHandle<JSObject> object);
  void UpdateNumberStringNotRegexpLikeProtectorOnSetPrototype(
      DirectHandle<JSObject> object);
  void UpdateNoElementsProtectorOnNormalizeElements(
      DirectHandle<JSObject> object) {
    UpdateNoElementsProtectorOnSetElement(object);
  }
  void UpdateStringWrapperToPrimitiveProtectorOnSetPrototype(
      DirectHandle<JSObject> object, DirectHandle<Object> new_prototype);

  // Returns true if array is the initial array prototype of its own creation
  // context.
  inline bool IsInitialArrayPrototype(Tagged<JSArray> array);

  std::unique_ptr<PersistentHandles> NewPersistentHandles();

  PersistentHandlesList* persistent_handles_list() const {
    return persistent_handles_list_.get();
  }

#ifdef V8_ENABLE_SPARKPLUG
  baseline::BaselineBatchCompiler* baseline_batch_compiler() const {
    DCHECK_NOT_NULL(baseline_batch_compiler_);
    return baseline_batch_compiler_;
  }
#endif  // V8_ENABLE_SPARKPLUG

#ifdef V8_ENABLE_MAGLEV
  maglev::MaglevConcurrentDispatcher* maglev_concurrent_dispatcher() {
    DCHECK_NOT_N
```
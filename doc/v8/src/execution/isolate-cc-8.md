Response:
Let's break down the thought process to analyze the provided C++ code snippet and fulfill the request.

**1. Understanding the Request:**

The core task is to understand the functionality of `v8/src/execution/isolate.cc`. The prompt also includes specific constraints:

*   Identify its purpose within V8.
*   Check if it could be a Torque file (based on file extension).
*   If related to JavaScript, provide JavaScript examples.
*   If there's logic, demonstrate it with input/output.
*   Point out common user errors.
*   Summarize its overall function (since it's part 9/9).

**2. Initial Code Scan and Keyword Identification:**

The first step is to read through the code, looking for recurring themes and keywords. Some immediately jump out:

*   `Isolate`: This is central. The file is clearly about managing an isolate.
*   `Promise`: Several functions handle promise lifecycle events (`OnPromiseAfter`, `ReportPromiseReject`).
*   `Microtask`: Functions like `OnTerminationDuringRunMicrotasks` are present.
*   `StackTrace`: `OnStackTraceCaptured`.
*   `UseCounter`:  `SetUseCounterCallback`, `CountUsage`.
*   `Context`:  `AddDetachedContext`, `DetachGlobal`, `SaveContext`, `SaveAndSwitchContext`, `GetOrRegisterRecorderContextId`, `GetContextFromRecorderContextId`.
*   `RAILMode`, `IsLoading`, `SetPriority`: Performance-related settings.
*   `BuiltinJSDispatchTable`: Indicates interaction with built-in functions.
*   `ICUObjectCache`: Internationalization support.
*   `StackLimitCheck`:  Handling stack overflow.
*   `CodeMemoryRange`, `AddCodeMemoryChunk`, `AddCodeRange`, `RemoveCodeMemoryChunk`: Managing code memory.
*   `async_waiter_queue_nodes_`, `DefaultWasmAsyncResolvePromiseCallback`: Asynchronous operations, potentially related to WebAssembly.

**3. Categorizing Functionality:**

Based on the keywords and function names, we can start grouping the functionalities:

*   **Isolate Lifecycle and Management:**  This is the core. The file manages the state and resources of an isolate.
*   **Promises and Microtasks:** Handling asynchronous operations.
*   **Debugging and Profiling:** Capturing stack traces.
*   **Usage Tracking:**  `UseCounter` indicates tracking feature usage.
*   **Context Management:**  Detaching, switching, and managing contexts.
*   **Performance Tuning:**  RAIL mode, priority.
*   **Internationalization:**  ICU integration.
*   **Stack Overflow Handling:**  `StackLimitCheck`.
*   **Code Management:**  Tracking code memory.
*   **Built-in Functions:**  `BuiltinJSDispatchTable`.
*   **Asynchronous Operations (Wasm):** `DefaultWasmAsyncResolvePromiseCallback`.

**4. Addressing Specific Constraints:**

*   **File Extension:** The prompt explicitly asks about `.tq`. The code is `.cc`, so it's standard C++, not Torque.
*   **JavaScript Relation:**  Since V8 is a JavaScript engine, much of this *directly* relates to JavaScript. Promises, microtasks, and contexts are fundamental JavaScript concepts. We need to provide JavaScript examples for these.
*   **Code Logic and Examples:**  Focus on functions with clear input/output behavior. Promise handling is a good candidate. We can create a simple promise and demonstrate how the `OnPromiseAfter` function might be triggered conceptually (even though it's internal).
*   **Common User Errors:** Think about common mistakes developers make when working with the features this code manages. Promise rejections without catch handlers, memory leaks with detached contexts, and incorrect usage of `async`/`await` (related to microtasks) are good examples.

**5. Inferring Overall Function (Part 9/9):**

Given that this is the final part, the `isolate.cc` file likely encompasses a *broad* range of core functionalities essential for managing a V8 isolate. It acts as a central hub for various subsystems.

**6. Structuring the Output:**

Organize the findings logically:

*   Start with the core function of `isolate.cc`.
*   Address the Torque file question directly.
*   Detail the functionalities in categories identified earlier.
*   Provide JavaScript examples where relevant.
*   Illustrate code logic with input/output scenarios (even if simplified).
*   Give practical examples of common user errors.
*   Conclude with the summary.

**7. Refinement and Detail:**

Go back through the code and add more specific details within each category. For example:

*   For promises, mention the different promise states and the role of the async event delegate.
*   For contexts, explain the concept of detached contexts and potential memory leaks.
*   For performance, briefly explain what RAIL mode represents.
*   For ICU, mention its purpose in internationalization.

**Self-Correction/Refinement during the process:**

*   **Initial thought:**  Focus heavily on low-level memory management details.
*   **Correction:** While important, balance it with the higher-level JavaScript concepts that are more relevant to the prompt's focus on JavaScript interaction.
*   **Initial thought:**  Try to provide *exact* JavaScript code that triggers the C++ functions.
*   **Correction:**  Recognize that many of these C++ functions are internal. Instead, provide conceptual JavaScript examples that illustrate the *behavior* these functions manage. For instance, you can't directly call `Isolate::OnPromiseAfter` from JavaScript, but you can show how a resolved promise leads to a "then" callback execution, which `OnPromiseAfter` is involved in internally.
*   **Initial thought:** Get bogged down in the intricacies of the C++ code.
*   **Correction:**  Focus on explaining the *purpose* and *effect* of the code, rather than a line-by-line breakdown. The request is for understanding the functionality, not a deep dive into the implementation.

By following this systematic approach, combining code analysis with an understanding of the request's constraints, we can arrive at a comprehensive and informative answer like the example provided in the prompt.
这是 V8 引擎源代码 `v8/src/execution/isolate.cc` 文件的功能列表：

**核心功能：Isolate 的管理和生命周期**

`v8/src/execution/isolate.cc` 文件是 V8 引擎中 `Isolate` 类的实现，而 `Isolate` 是 V8 中最核心的概念之一。一个 `Isolate` 可以被认为是 V8 引擎的一个独立实例，它拥有自己的堆、垃圾回收器、编译管道以及所有执行 JavaScript 代码所需的资源。

具体功能包括：

1. **Isolate 的创建和销毁:**  负责 `Isolate` 对象的创建、初始化以及在生命周期结束时的清理工作。这包括分配和释放内存、初始化内部数据结构等。

2. **堆管理 (通过包含的 `heap()` 方法):**  虽然具体实现可能在其他文件中，但 `Isolate` 提供了访问和操作其关联堆的接口。这涉及内存分配、垃圾回收等。

3. **上下文 (Context) 管理:**
    *   **当前上下文的跟踪:**  维护当前正在执行的 JavaScript 代码的上下文。
    *   **上下文切换:**  提供保存和恢复上下文状态的机制。
    *   **分离的上下文管理:**  跟踪已分离的上下文，以便进行垃圾回收和避免内存泄漏。
    *   **全局对象分离 (`DetachGlobal`):**  处理全局对象与其原生上下文的解除关联。

4. **微任务 (Microtask) 队列管理:**  负责管理和执行微任务队列，这是 Promise 等异步操作的基础。
    *   **`OnTerminationDuringRunMicrotasks`:**  处理在执行微任务期间发生异常终止的情况，确保资源清理。

5. **Promise 处理:**
    *   **`OnPromiseAfter`:**  在 Promise 解决或拒绝后执行的操作，可能涉及调试事件的触发。
    *   **`ReportPromiseReject`:**  报告 Promise 拒绝事件，并调用用户自定义的回调函数 (`PromiseRejectCallback`)。
    *   **`SetPromiseRejectCallback`:**  允许用户设置处理 Promise 拒绝的回调函数。

6. **异常处理:**  尽管没有明显的异常抛出和捕获的直接代码，但 `Isolate` 的状态管理对于处理 JavaScript 异常至关重要。

7. **调试支持:**
    *   **`OnStackTraceCaptured`:**  当捕获到堆栈跟踪时通知调试器。
    *   **`HasAsyncEventDelegate`:**  检查是否设置了异步事件代理，用于调试异步操作。
    *   **`AsyncEventOccurred`:**  通知异步事件代理发生了特定事件。

8. **使用计数 (Use Counter):**  用于跟踪 V8 功能的使用情况，以便进行性能分析和优化。
    *   **`SetUseCounterCallback`:**  设置使用计数回调函数。
    *   **`CountUsage`:**  递增特定功能的使用计数器。

9. **脚本 ID 管理:**  `GetNextScriptId` 用于生成唯一的脚本 ID。

10. **性能和资源管理:**
    *   **RAIL 模式 (`SetRAILMode`, `SetIsLoading`):**  支持 RAIL (Response, Animation, Idle, Load) 性能模型，用于优化 Web 应用程序的性能。
    *   **优先级设置 (`SetPriority`):**  允许设置 `Isolate` 的优先级，影响其资源分配。

11. **代码内存管理:**
    *   **`AddCodeMemoryRange`, `AddCodeMemoryChunk`, `RemoveCodeMemoryChunk`:**  跟踪和管理代码段的内存范围，用于安全性和优化。

12. **国际化 (i18n) 支持 (如果 `V8_INTL_SUPPORT` 定义):**
    *   **默认区域设置管理 (`DefaultLocale`, `ResetDefaultLocale`):**  管理默认的国际化区域设置。
    *   **ICU 对象缓存 (`get_cached_icu_object`, `set_icu_object_in_cache`, `clear_cached_icu_object`, `clear_cached_icu_objects`):**  缓存 ICU (International Components for Unicode) 对象以提高性能。

13. **栈溢出检测 (`StackLimitCheck`):**  提供检测和处理栈溢出的机制。

14. **记录器上下文 ID 管理 (`GetOrRegisterRecorderContextId`, `GetContextFromRecorderContextId`):** 用于关联记录器上下文和 V8 上下文，这可能与性能分析或调试工具相关。

15. **长任务统计 (`UpdateLongTaskStats`, `GetCurrentLongTaskStats`):**  跟踪和管理长时间运行的任务的统计信息。

16. **内置函数分发表的初始化 (`InitializeBuiltinJSDispatchTable`):** 初始化用于快速调用内置 JavaScript 函数的分发表格。

17. **局部变量阻止列表缓存 (`LocalsBlockListCacheSet`, `LocalsBlockListCacheGet`):**  用于优化 JavaScript 代码的编译和执行，可能与作用域分析有关。

18. **异步 WebAssembly Promise 回调 (`DefaultWasmAsyncResolvePromiseCallback`):**  提供默认的回调函数来解决或拒绝异步 WebAssembly 操作产生的 Promise。

**关于文件扩展名和 Torque:**

如果 `v8/src/execution/isolate.cc` 以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 用来定义内置函数和运行时函数的领域特定语言。然而，从提供的文件扩展名来看，它是 `.cc`，所以这是一个 **C++ 源代码文件**。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`v8/src/execution/isolate.cc` 文件中的许多功能都直接关系到 JavaScript 的执行和特性。以下是一些示例：

*   **Promise 处理:**
    ```javascript
    const promise = new Promise((resolve, reject) => {
      setTimeout(() => {
        resolve("Promise resolved!");
      }, 1000);
    });

    promise.then(value => {
      console.log(value); // 当 Promise 解决时触发，对应 Isolate::OnPromiseAfter
    });

    const rejectedPromise = new Promise((resolve, reject) => {
      setTimeout(() => {
        reject("Promise rejected!");
      }, 500);
    });

    rejectedPromise.catch(error => {
      console.error(error); // 当 Promise 拒绝时触发
    });

    window.addEventListener('unhandledrejection', (event) => {
      console.error('Unhandled rejection:', event.reason); // 对应 Isolate::ReportPromiseReject，当没有 catch 处理拒绝时
    });
    ```

*   **微任务:**
    ```javascript
    Promise.resolve().then(() => {
      console.log("Microtask from Promise");
    });

    queueMicrotask(() => {
      console.log("Another microtask");
    });

    console.log("Regular task");
    // 输出顺序通常是: "Regular task", "Microtask from Promise", "Another microtask"
    // Isolate 负责管理这些微任务的执行队列。
    ```

*   **异步函数 (async/await):**  `async/await` 语法糖底层也依赖于 Promise 和微任务。
    ```javascript
    async function myFunction() {
      console.log("Start of async function");
      await Promise.resolve();
      console.log("After await");
    }

    myFunction();
    // "After await" 会作为一个微任务执行。
    ```

*   **使用计数 (无法直接在 JavaScript 中观察，但 V8 内部会记录):**  V8 可能会在内部记录某些 JavaScript 特性的使用频率，例如使用了新的 ES6 语法等。

*   **上下文:**
    ```javascript
    // 全局上下文
    console.log(this === window); // 在浏览器中通常为 true

    function createModule() {
      // 函数内部创建的作用域可以理解为与上下文相关联
      let privateVar = "secret";
      return {
        getPrivateVar: function() {
          return privateVar;
        }
      };
    }

    const myModule = createModule();
    console.log(myModule.getPrivateVar());
    ```

**代码逻辑推理及假设输入输出:**

考虑 `Isolate::OnPromiseAfter` 函数：

**假设输入:**

*   一个已解决或已拒绝的 `JSPromise` 对象。

**输出:**

*   如果设置了异步事件代理 (`HasAsyncEventDelegate()` 返回 `true`) 并且 Promise 有异步任务 ID (`promise->has_async_task_id()` 返回 `true`)，则会调用 `async_event_delegate_->AsyncEventOccurred`，传递 `debug::kDebugDidHandle` 事件类型和 Promise 的异步任务 ID。

**代码逻辑:**  该函数的主要目的是在 Promise 完成后通知潜在的调试器或其他监控工具，Promise 的状态已改变。

**用户常见的编程错误示例:**

*   **未处理的 Promise 拒绝:**  如果一个 Promise 被拒绝，但没有提供 `.catch()` 处理程序，会导致 `Isolate::ReportPromiseReject` 被调用，并且可能会触发一个全局的 `unhandledrejection` 事件。

    ```javascript
    // 错误示例：未处理的 Promise 拒绝
    new Promise((resolve, reject) => {
      throw new Error("Something went wrong!");
    });
    // 可能会在控制台看到 "Unhandled promise rejection" 警告。
    ```

*   **在微任务中忘记处理错误:**  微任务中的错误如果没有被捕获，可能会导致难以追踪的问题。

    ```javascript
    Promise.resolve().then(() => {
      throw new Error("Error in microtask"); // 如果没有全局错误处理，可能会导致 unhandled rejection
    });
    ```

*   **过度依赖同步操作阻塞事件循环:**  虽然 `Isolate` 负责管理事件循环，但编写阻塞事件循环的同步代码会影响性能和用户体验。

    ```javascript
    // 避免在主线程中进行长时间的同步操作
    let startTime = Date.now();
    while (Date.now() - startTime < 5000) {
      // 阻塞 5 秒
    }
    console.log("Done blocking");
    ```

*   **内存泄漏与分离的上下文:** 如果上下文被分离 (`DetachGlobal`) 但其资源没有被正确释放，可能会导致内存泄漏。这通常发生在复杂的 Web 应用程序中，例如单页应用 (SPA) 中页面切换时没有清理旧页面的资源。

**归纳 `v8/src/execution/isolate.cc` 的功能 (作为第 9 部分):**

作为系列的最后一部分，`v8/src/execution/isolate.cc` 文件是 V8 引擎中 **`Isolate` 核心功能的蓝图和实现**。它定义了 `Isolate` 的生命周期管理、资源分配、与 JavaScript 语言特性的集成（如 Promise 和微任务）、调试支持、性能优化以及与其他 V8 子系统的交互。  `Isolate` 是 V8 运行时的基石，这个文件中的代码是确保 JavaScript 代码能够安全、高效地执行的关键。它像一个操作系统的内核一样，管理着 V8 实例的各种核心服务和状态。

Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共9部分，请归纳一下它的功能

"""
value());
  if (HasAsyncEventDelegate()) {
    if (promise->has_async_task_id()) {
      async_event_delegate_->AsyncEventOccurred(
          debug::kDebugDidHandle, promise->async_task_id(), false);
    }
  }
}

void Isolate::OnStackTraceCaptured(Handle<StackTraceInfo> stack_trace) {
  if (HasAsyncEventDelegate()) {
    async_event_delegate_->AsyncEventOccurred(debug::kDebugStackTraceCaptured,
                                              stack_trace->id(), false);
  }
}

void Isolate::OnTerminationDuringRunMicrotasks() {
  DCHECK(is_execution_terminating());
  // This performs cleanup for when RunMicrotasks (in
  // builtins-microtask-queue-gen.cc) is aborted via a termination exception.
  // This has to be kept in sync with the code in said file. Currently this
  // includes:
  //
  //  (1) Resetting the |current_microtask| slot on the Isolate to avoid leaking
  //      memory (and also to keep |current_microtask| not being undefined as an
  //      indicator that we're currently pumping the microtask queue).
  //  (2) Empty the promise stack to avoid leaking memory.
  //  (3) If the |current_microtask| is a promise reaction or resolve thenable
  //      job task, then signal the async event delegate and debugger that the
  //      microtask finished running.
  //

  // Reset the |current_microtask| global slot.
  DirectHandle<Microtask> current_microtask(
      Cast<Microtask>(heap()->current_microtask()), this);
  heap()->set_current_microtask(ReadOnlyRoots(this).undefined_value());

  if (IsPromiseReactionJobTask(*current_microtask)) {
    auto promise_reaction_job_task =
        Cast<PromiseReactionJobTask>(current_microtask);
    Handle<HeapObject> promise_or_capability(
        promise_reaction_job_task->promise_or_capability(), this);
    if (IsPromiseCapability(*promise_or_capability)) {
      promise_or_capability = handle(
          Cast<PromiseCapability>(promise_or_capability)->promise(), this);
    }
    if (IsJSPromise(*promise_or_capability)) {
      OnPromiseAfter(Cast<JSPromise>(promise_or_capability));
    }
  } else if (IsPromiseResolveThenableJobTask(*current_microtask)) {
    auto promise_resolve_thenable_job_task =
        Cast<PromiseResolveThenableJobTask>(current_microtask);
    Handle<JSPromise> promise_to_resolve(
        promise_resolve_thenable_job_task->promise_to_resolve(), this);
    OnPromiseAfter(promise_to_resolve);
  }

  SetTerminationOnExternalTryCatch();
}

void Isolate::SetPromiseRejectCallback(PromiseRejectCallback callback) {
  promise_reject_callback_ = callback;
}

void Isolate::ReportPromiseReject(Handle<JSPromise> promise,
                                  Handle<Object> value,
                                  v8::PromiseRejectEvent event) {
  if (promise_reject_callback_ == nullptr) return;
  promise_reject_callback_(v8::PromiseRejectMessage(
      v8::Utils::PromiseToLocal(promise), event, v8::Utils::ToLocal(value)));
}

void Isolate::SetUseCounterCallback(v8::Isolate::UseCounterCallback callback) {
  DCHECK(!use_counter_callback_);
  use_counter_callback_ = callback;
}

void Isolate::CountUsage(v8::Isolate::UseCounterFeature feature) {
  CountUsage(base::VectorOf({feature}));
}

void Isolate::CountUsage(
    base::Vector<const v8::Isolate::UseCounterFeature> features) {
  // The counter callback
  // - may cause the embedder to call into V8, which is not generally possible
  //   during GC.
  // - requires a current native context, which may not always exist.
  // TODO(jgruber): Consider either removing the native context requirement in
  // blink, or passing it to the callback explicitly.
  if (heap_.gc_state() == Heap::NOT_IN_GC && !context().is_null()) {
    DCHECK(IsContext(context()));
    DCHECK(IsNativeContext(context()->native_context()));
    if (use_counter_callback_) {
      HandleScope handle_scope(this);
      for (auto feature : features) {
        use_counter_callback_(reinterpret_cast<v8::Isolate*>(this), feature);
      }
    }
  } else {
    heap_.IncrementDeferredCounts(features);
  }
}

int Isolate::GetNextScriptId() { return heap()->NextScriptId(); }

// static
std::string Isolate::GetTurboCfgFileName(Isolate* isolate) {
  if (const char* filename = v8_flags.trace_turbo_cfg_file) return filename;
  std::ostringstream os;
  os << "turbo-" << base::OS::GetCurrentProcessId() << "-";
  if (isolate != nullptr) {
    os << isolate->id();
  } else {
    os << "any";
  }
  os << ".cfg";
  return os.str();
}

// Heap::detached_contexts tracks detached contexts as pairs
// (the context, number of GC since the context was detached).
void Isolate::AddDetachedContext(Handle<Context> context) {
  HandleScope scope(this);
  Handle<WeakArrayList> detached_contexts = factory()->detached_contexts();
  detached_contexts = WeakArrayList::AddToEnd(
      this, detached_contexts, MaybeObjectDirectHandle::Weak(context),
      Smi::zero());
  heap()->set_detached_contexts(*detached_contexts);
}

void Isolate::CheckDetachedContextsAfterGC() {
  HandleScope scope(this);
  DirectHandle<WeakArrayList> detached_contexts =
      factory()->detached_contexts();
  int length = detached_contexts->length();
  if (length == 0) return;
  int new_length = 0;
  for (int i = 0; i < length; i += 2) {
    Tagged<MaybeObject> context = detached_contexts->Get(i);
    DCHECK(context.IsWeakOrCleared());
    if (!context.IsCleared()) {
      int mark_sweeps = detached_contexts->Get(i + 1).ToSmi().value();
      detached_contexts->Set(new_length, context);
      detached_contexts->Set(new_length + 1, Smi::FromInt(mark_sweeps + 1));
      new_length += 2;
    }
  }
  detached_contexts->set_length(new_length);
  while (new_length < length) {
    detached_contexts->Set(new_length, Smi::zero());
    ++new_length;
  }

  if (v8_flags.trace_detached_contexts) {
    PrintF("%d detached contexts are collected out of %d\n",
           length - new_length, length);
    for (int i = 0; i < new_length; i += 2) {
      Tagged<MaybeObject> context = detached_contexts->Get(i);
      int mark_sweeps = detached_contexts->Get(i + 1).ToSmi().value();
      DCHECK(context.IsWeakOrCleared());
      if (mark_sweeps > 3) {
        PrintF("detached context %p\n survived %d GCs (leak?)\n",
               reinterpret_cast<void*>(context.ptr()), mark_sweeps);
      }
    }
  }
}

void Isolate::DetachGlobal(Handle<Context> env) {
  counters()->errors_thrown_per_context()->AddSample(
      env->native_context()->GetErrorsThrown());

  ReadOnlyRoots roots(this);
  DirectHandle<JSGlobalProxy> global_proxy(env->global_proxy(), this);
  // NOTE: Turbofan's JSNativeContextSpecialization and Maglev depend on
  // DetachGlobal causing a map change.
  JSObject::ForceSetPrototype(this, global_proxy, factory()->null_value());
  // Detach the global object from the native context by making its map
  // contextless (use the global metamap instead of the contextful one).
  global_proxy->map()->set_map(this, roots.meta_map());
  global_proxy->map()->set_constructor_or_back_pointer(roots.null_value(),
                                                       kRelaxedStore);
  if (v8_flags.track_detached_contexts) AddDetachedContext(env);
  DCHECK(global_proxy->IsDetached());

  env->native_context()->set_microtask_queue(this, nullptr);
}

void Isolate::UpdateLoadStartTime() { heap()->UpdateLoadStartTime(); }

void Isolate::SetRAILMode(RAILMode rail_mode) {
  bool is_loading = rail_mode == PERFORMANCE_LOAD;
  bool was_loading = is_loading_.exchange(is_loading);
  if (is_loading && !was_loading) {
    heap()->NotifyLoadingStarted();
  }
  if (!is_loading && was_loading) {
    heap()->NotifyLoadingEnded();
  }
  if (v8_flags.trace_rail) {
    PrintIsolate(this, "RAIL mode: %s\n", RAILModeName(rail_mode));
  }
}

void Isolate::SetIsLoading(bool is_loading) {
  is_loading_.store(is_loading);
  if (is_loading) {
    heap()->NotifyLoadingStarted();
  } else {
    heap()->NotifyLoadingEnded();
  }
  if (v8_flags.trace_rail) {
    // TODO(crbug.com/373688984): Switch to a trace flag for loading state.
    PrintIsolate(this, "RAIL mode: %s\n", is_loading ? "LOAD" : "ANIMATION");
  }
}

void Isolate::SetPriority(v8::Isolate::Priority priority) {
  priority_ = priority;
  heap()->tracer()->UpdateCurrentEventPriority(priority_);
  if (priority_ == v8::Isolate::Priority::kBestEffort) {
    heap()->ActivateMemoryReducerIfNeeded();
  }
}

void Isolate::PrintWithTimestamp(const char* format, ...) {
  base::OS::Print("[%d:%p] %8.0f ms: ", base::OS::GetCurrentProcessId(),
                  static_cast<void*>(this), time_millis_since_init());
  va_list arguments;
  va_start(arguments, format);
  base::OS::VPrint(format, arguments);
  va_end(arguments);
}

void Isolate::SetIdle(bool is_idle) {
  StateTag state = current_vm_state();
  if (js_entry_sp() != kNullAddress) return;
  DCHECK(state == EXTERNAL || state == IDLE);
  if (is_idle) {
    set_current_vm_state(IDLE);
  } else if (state == IDLE) {
    set_current_vm_state(EXTERNAL);
  }
}

void Isolate::CollectSourcePositionsForAllBytecodeArrays() {
  if (!initialized_) return;

  HandleScope scope(this);
  std::vector<Handle<SharedFunctionInfo>> sfis;
  {
    HeapObjectIterator iterator(heap());
    for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
         obj = iterator.Next()) {
      if (!IsSharedFunctionInfo(obj)) continue;
      Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(obj);
      // If the script is a Smi, then the SharedFunctionInfo is in
      // the process of being deserialized.
      Tagged<Object> script = sfi->raw_script(kAcquireLoad);
      if (IsSmi(script)) {
        DCHECK_EQ(script, Smi::uninitialized_deserialization_value());
        continue;
      }
      if (!sfi->CanCollectSourcePosition(this)) continue;
      sfis.push_back(Handle<SharedFunctionInfo>(sfi, this));
    }
  }
  for (auto sfi : sfis) {
    SharedFunctionInfo::EnsureSourcePositionsAvailable(this, sfi);
  }
}

#ifdef V8_INTL_SUPPORT

namespace {

std::string GetStringFromLocales(Isolate* isolate,
                                 DirectHandle<Object> locales) {
  if (IsUndefined(*locales, isolate)) return "";
  return std::string(Cast<String>(*locales)->ToCString().get());
}

bool StringEqualsLocales(Isolate* isolate, const std::string& str,
                         Handle<Object> locales) {
  if (IsUndefined(*locales, isolate)) return str.empty();
  return Cast<String>(locales)->IsEqualTo(
      base::VectorOf(str.c_str(), str.length()));
}

}  // namespace

const std::string& Isolate::DefaultLocale() {
  if (default_locale_.empty()) {
    icu::Locale default_locale;
    // Translate ICU's fallback locale to a well-known locale.
    if (strcmp(default_locale.getName(), "en_US_POSIX") == 0 ||
        strcmp(default_locale.getName(), "c") == 0) {
      set_default_locale("en-US");
    } else {
      // Set the locale
      set_default_locale(default_locale.isBogus()
                             ? "und"
                             : Intl::ToLanguageTag(default_locale).FromJust());
    }
    DCHECK(!default_locale_.empty());
  }
  return default_locale_;
}

void Isolate::ResetDefaultLocale() {
  default_locale_.clear();
  clear_cached_icu_objects();
  // We inline fast paths assuming certain locales. Since this path is rarely
  // taken, we deoptimize everything to keep things simple.
  Deoptimizer::DeoptimizeAll(this);
}

icu::UMemory* Isolate::get_cached_icu_object(ICUObjectCacheType cache_type,
                                             Handle<Object> locales) {
  const ICUObjectCacheEntry& entry =
      icu_object_cache_[static_cast<int>(cache_type)];
  return StringEqualsLocales(this, entry.locales, locales) ? entry.obj.get()
                                                           : nullptr;
}

void Isolate::set_icu_object_in_cache(ICUObjectCacheType cache_type,
                                      DirectHandle<Object> locales,
                                      std::shared_ptr<icu::UMemory> obj) {
  icu_object_cache_[static_cast<int>(cache_type)] = {
      GetStringFromLocales(this, locales), std::move(obj)};
}

void Isolate::clear_cached_icu_object(ICUObjectCacheType cache_type) {
  icu_object_cache_[static_cast<int>(cache_type)] = ICUObjectCacheEntry{};
}

void Isolate::clear_cached_icu_objects() {
  for (int i = 0; i < kICUObjectCacheTypeCount; i++) {
    clear_cached_icu_object(static_cast<ICUObjectCacheType>(i));
  }
}

#endif  // V8_INTL_SUPPORT

bool StackLimitCheck::HandleStackOverflowAndTerminationRequest() {
  DCHECK(InterruptRequested());
  if (V8_UNLIKELY(HasOverflowed())) {
    isolate_->StackOverflow();
    return true;
  }
  if (V8_UNLIKELY(isolate_->stack_guard()->HasTerminationRequest())) {
    isolate_->TerminateExecution();
    return true;
  }
  return false;
}

bool StackLimitCheck::JsHasOverflowed(uintptr_t gap) const {
  StackGuard* stack_guard = isolate_->stack_guard();
#ifdef USE_SIMULATOR
  // The simulator uses a separate JS stack.
  Address jssp_address = Simulator::current(isolate_)->get_sp();
  uintptr_t jssp = static_cast<uintptr_t>(jssp_address);
  if (jssp - gap < stack_guard->real_jslimit()) return true;
#endif  // USE_SIMULATOR
  return GetCurrentStackPosition() - gap < stack_guard->real_climit();
}

bool StackLimitCheck::WasmHasOverflowed(uintptr_t gap) const {
  StackGuard* stack_guard = isolate_->stack_guard();
  auto sp = isolate_->thread_local_top()->secondary_stack_sp_;
  auto limit = isolate_->thread_local_top()->secondary_stack_limit_;
  if (sp == 0) {
#ifdef USE_SIMULATOR
    // The simulator uses a separate JS stack.
    // Use it if code is executed on the central stack.
    Address jssp_address = Simulator::current(isolate_)->get_sp();
    uintptr_t jssp = static_cast<uintptr_t>(jssp_address);
    if (jssp - gap < stack_guard->real_jslimit()) return true;
#endif  // USE_SIMULATOR
    sp = GetCurrentStackPosition();
    limit = stack_guard->real_climit();
  }
  return sp - gap < limit;
}

SaveContext::SaveContext(Isolate* isolate) : isolate_(isolate) {
  if (!isolate->context().is_null()) {
    context_ = Handle<Context>(isolate->context(), isolate);
  }
  if (!isolate->topmost_script_having_context().is_null()) {
    topmost_script_having_context_ =
        Handle<Context>(isolate->topmost_script_having_context(), isolate);
  }
}

SaveContext::~SaveContext() {
  isolate_->set_context(context_.is_null() ? Tagged<Context>() : *context_);
  isolate_->set_topmost_script_having_context(
      topmost_script_having_context_.is_null()
          ? Tagged<Context>()
          : *topmost_script_having_context_);
}

SaveAndSwitchContext::SaveAndSwitchContext(Isolate* isolate,
                                           Tagged<Context> new_context)
    : SaveContext(isolate) {
  isolate->set_context(new_context);
}

#ifdef DEBUG
AssertNoContextChange::AssertNoContextChange(Isolate* isolate)
    : isolate_(isolate),
      context_(isolate->context(), isolate),
      topmost_script_having_context_(isolate->topmost_script_having_context(),
                                     isolate) {}

namespace {

bool Overlapping(const MemoryRange& a, const MemoryRange& b) {
  uintptr_t a1 = reinterpret_cast<uintptr_t>(a.start);
  uintptr_t a2 = a1 + a.length_in_bytes;
  uintptr_t b1 = reinterpret_cast<uintptr_t>(b.start);
  uintptr_t b2 = b1 + b.length_in_bytes;
  // Either b1 or b2 are in the [a1, a2) range.
  return (a1 <= b1 && b1 < a2) || (a1 <= b2 && b2 < a2);
}

}  // anonymous namespace

#endif  // DEBUG

void Isolate::AddCodeMemoryRange(MemoryRange range) {
  base::MutexGuard guard(&code_pages_mutex_);
  std::vector<MemoryRange>* old_code_pages = GetCodePages();
  DCHECK_NOT_NULL(old_code_pages);
#ifdef DEBUG
  auto overlapping = [range](const MemoryRange& a) {
    return Overlapping(range, a);
  };
  DCHECK_EQ(old_code_pages->end(),
            std::find_if(old_code_pages->begin(), old_code_pages->end(),
                         overlapping));
#endif

  std::vector<MemoryRange>* new_code_pages;
  if (old_code_pages == &code_pages_buffer1_) {
    new_code_pages = &code_pages_buffer2_;
  } else {
    new_code_pages = &code_pages_buffer1_;
  }

  // Copy all existing data from the old vector to the new vector and insert the
  // new page.
  new_code_pages->clear();
  new_code_pages->reserve(old_code_pages->size() + 1);
  std::merge(old_code_pages->begin(), old_code_pages->end(), &range, &range + 1,
             std::back_inserter(*new_code_pages),
             [](const MemoryRange& a, const MemoryRange& b) {
               return a.start < b.start;
             });

  // Atomically switch out the pointer
  SetCodePages(new_code_pages);
}

// |chunk| is either a Page or an executable LargePage.
void Isolate::AddCodeMemoryChunk(MutablePageMetadata* chunk) {
  // We only keep track of individual code pages/allocations if we are on arm32,
  // because on x64 and arm64 we have a code range which makes this unnecessary.
#if defined(V8_TARGET_ARCH_ARM)
  void* new_page_start = reinterpret_cast<void*>(chunk->area_start());
  size_t new_page_size = chunk->area_size();

  MemoryRange new_range{new_page_start, new_page_size};

  AddCodeMemoryRange(new_range);
#endif  // !defined(V8_TARGET_ARCH_ARM)
}

void Isolate::AddCodeRange(Address begin, size_t length_in_bytes) {
  AddCodeMemoryRange(
      MemoryRange{reinterpret_cast<void*>(begin), length_in_bytes});
}

bool Isolate::RequiresCodeRange() const {
  return kPlatformRequiresCodeRange && !jitless_;
}

v8::metrics::Recorder::ContextId Isolate::GetOrRegisterRecorderContextId(
    DirectHandle<NativeContext> context) {
  if (serializer_enabled_) return v8::metrics::Recorder::ContextId::Empty();
  i::Tagged<i::Object> id = context->recorder_context_id();
  if (IsNullOrUndefined(id)) {
    CHECK_LT(last_recorder_context_id_, i::Smi::kMaxValue);
    context->set_recorder_context_id(
        i::Smi::FromIntptr(++last_recorder_context_id_));
    v8::HandleScope handle_scope(reinterpret_cast<v8::Isolate*>(this));
    auto result = recorder_context_id_map_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(last_recorder_context_id_),
        std::forward_as_tuple(reinterpret_cast<v8::Isolate*>(this),
                              ToApiHandle<v8::Context>(context)));
    result.first->second.SetWeak(
        reinterpret_cast<void*>(last_recorder_context_id_),
        RemoveContextIdCallback, v8::WeakCallbackType::kParameter);
    return v8::metrics::Recorder::ContextId(last_recorder_context_id_);
  } else {
    DCHECK(IsSmi(id));
    return v8::metrics::Recorder::ContextId(
        static_cast<uintptr_t>(i::Smi::ToInt(id)));
  }
}

MaybeLocal<v8::Context> Isolate::GetContextFromRecorderContextId(
    v8::metrics::Recorder::ContextId id) {
  auto result = recorder_context_id_map_.find(id.id_);
  if (result == recorder_context_id_map_.end() || result->second.IsEmpty())
    return MaybeLocal<v8::Context>();
  return result->second.Get(reinterpret_cast<v8::Isolate*>(this));
}

void Isolate::UpdateLongTaskStats() {
  if (last_long_task_stats_counter_ != isolate_data_.long_task_stats_counter_) {
    last_long_task_stats_counter_ = isolate_data_.long_task_stats_counter_;
    long_task_stats_ = v8::metrics::LongTaskStats{};
  }
}

v8::metrics::LongTaskStats* Isolate::GetCurrentLongTaskStats() {
  UpdateLongTaskStats();
  return &long_task_stats_;
}

void Isolate::RemoveContextIdCallback(const v8::WeakCallbackInfo<void>& data) {
  Isolate* isolate = reinterpret_cast<Isolate*>(data.GetIsolate());
  uintptr_t context_id = reinterpret_cast<uintptr_t>(data.GetParameter());
  isolate->recorder_context_id_map_.erase(context_id);
}

LocalHeap* Isolate::main_thread_local_heap() {
  return main_thread_local_isolate()->heap();
}

LocalHeap* Isolate::CurrentLocalHeap() {
  LocalHeap* local_heap = LocalHeap::Current();
  if (local_heap) return local_heap;
  DCHECK_EQ(ThreadId::Current(), thread_id());
  return main_thread_local_heap();
}

// |chunk| is either a Page or an executable LargePage.
void Isolate::RemoveCodeMemoryChunk(MutablePageMetadata* chunk) {
  // We only keep track of individual code pages/allocations if we are on arm32,
  // because on x64 and arm64 we have a code range which makes this unnecessary.
#if defined(V8_TARGET_ARCH_ARM)
  void* removed_page_start = reinterpret_cast<void*>(chunk->area_start());
  std::vector<MemoryRange>* old_code_pages = GetCodePages();
  DCHECK_NOT_NULL(old_code_pages);

  std::vector<MemoryRange>* new_code_pages;
  if (old_code_pages == &code_pages_buffer1_) {
    new_code_pages = &code_pages_buffer2_;
  } else {
    new_code_pages = &code_pages_buffer1_;
  }

  // Copy all existing data from the old vector to the new vector except the
  // removed page.
  new_code_pages->clear();
  new_code_pages->reserve(old_code_pages->size() - 1);
  std::remove_copy_if(old_code_pages->begin(), old_code_pages->end(),
                      std::back_inserter(*new_code_pages),
                      [removed_page_start](const MemoryRange& range) {
                        return range.start == removed_page_start;
                      });
  DCHECK_EQ(old_code_pages->size(), new_code_pages->size() + 1);
  // Atomically switch out the pointer
  SetCodePages(new_code_pages);
#endif  // !defined(V8_TARGET_ARCH_ARM)
}

#if V8_ENABLE_DRUMBRAKE
void Isolate::initialize_wasm_execution_timer() {
  DCHECK(v8_flags.wasm_enable_exec_time_histograms &&
         v8_flags.slow_histograms && !v8_flags.wasm_jitless);
  wasm_execution_timer_ =
      std::make_unique<wasm::WasmExecutionTimer>(this, false);
}
#endif  // V8_ENABLE_DRUMBRAKE

#undef TRACE_ISOLATE

// static
Address Isolate::load_from_stack_count_address(const char* function_name) {
  DCHECK_NOT_NULL(function_name);
  if (!stack_access_count_map) {
    stack_access_count_map = new MapOfLoadsAndStoresPerFunction{};
  }
  auto& map = *stack_access_count_map;
  std::string name(function_name);
  // It is safe to return the address of std::map values.
  // Only iterators and references to the erased elements are invalidated.
  return reinterpret_cast<Address>(&map[name].first);
}

// static
Address Isolate::store_to_stack_count_address(const char* function_name) {
  DCHECK_NOT_NULL(function_name);
  if (!stack_access_count_map) {
    stack_access_count_map = new MapOfLoadsAndStoresPerFunction{};
  }
  auto& map = *stack_access_count_map;
  std::string name(function_name);
  // It is safe to return the address of std::map values.
  // Only iterators and references to the erased elements are invalidated.
  return reinterpret_cast<Address>(&map[name].second);
}

void Isolate::LocalsBlockListCacheSet(Handle<ScopeInfo> scope_info,
                                      Handle<ScopeInfo> outer_scope_info,
                                      Handle<StringSet> locals_blocklist) {
  Handle<EphemeronHashTable> cache;
  if (IsEphemeronHashTable(heap()->locals_block_list_cache())) {
    cache = handle(Cast<EphemeronHashTable>(heap()->locals_block_list_cache()),
                   this);
  } else {
    CHECK(IsUndefined(heap()->locals_block_list_cache()));
    constexpr int kInitialCapacity = 8;
    cache = EphemeronHashTable::New(this, kInitialCapacity);
  }
  DCHECK(IsEphemeronHashTable(*cache));

  Handle<Object> value;
  if (!outer_scope_info.is_null()) {
    value = factory()->NewTuple2(outer_scope_info, locals_blocklist,
                                 AllocationType::kYoung);
  } else {
    value = locals_blocklist;
  }

  CHECK(!value.is_null());
  cache = EphemeronHashTable::Put(cache, scope_info, value);
  heap()->set_locals_block_list_cache(*cache);
}

Tagged<Object> Isolate::LocalsBlockListCacheGet(Handle<ScopeInfo> scope_info) {
  DisallowGarbageCollection no_gc;

  if (!IsEphemeronHashTable(heap()->locals_block_list_cache())) {
    return ReadOnlyRoots(this).the_hole_value();
  }

  Tagged<Object> maybe_value =
      Cast<EphemeronHashTable>(heap()->locals_block_list_cache())
          ->Lookup(scope_info);
  if (IsTuple2(maybe_value)) return Cast<Tuple2>(maybe_value)->value2();

  CHECK(IsStringSet(maybe_value) || IsTheHole(maybe_value));
  return maybe_value;
}

std::list<std::unique_ptr<detail::WaiterQueueNode>>&
Isolate::async_waiter_queue_nodes() {
  return async_waiter_queue_nodes_;
}

void DefaultWasmAsyncResolvePromiseCallback(
    v8::Isolate* isolate, v8::Local<v8::Context> context,
    v8::Local<v8::Promise::Resolver> resolver, v8::Local<v8::Value> result,
    WasmAsyncSuccess success) {
  MicrotasksScope microtasks_scope(context,
                                   MicrotasksScope::kDoNotRunMicrotasks);

  Maybe<bool> ret = success == WasmAsyncSuccess::kSuccess
                        ? resolver->Resolve(context, result)
                        : resolver->Reject(context, result);
  // It's guaranteed that no exceptions will be thrown by these
  // operations, but execution might be terminating.
  CHECK(ret.IsJust() ? ret.FromJust() : isolate->IsExecutionTerminating());
}

// Mutex used to ensure that the dispatch table entries for builtins are only
// initialized once.
base::LazyMutex read_only_dispatch_entries_mutex_ = LAZY_MUTEX_INITIALIZER;

void Isolate::InitializeBuiltinJSDispatchTable() {
#ifdef V8_ENABLE_LEAPTIERING
  // Ideally these entries would be created when the read only heap is
  // initialized. However, since builtins are deserialized later, we need to
  // patch it up here. Also, we need a mutex so the shared read only heaps space
  // is not initialized multiple times. This must be blocking as no isolate
  // should be allowed to proceed until the table is initialized.
  base::MutexGuard guard(read_only_dispatch_entries_mutex_.Pointer());
  auto jdt = GetProcessWideJSDispatchTable();
  if (jdt->PreAllocatedEntryNeedsInitialization(
          read_only_heap_->js_dispatch_table_space(),
          builtin_dispatch_handle(JSBuiltinDispatchHandleRoot::Idx::kFirst))) {
    JSDispatchTable::UnsealReadOnlySegmentScope unseal_scope(jdt);
    for (JSBuiltinDispatchHandleRoot::Idx idx =
             JSBuiltinDispatchHandleRoot::kFirst;
         idx < JSBuiltinDispatchHandleRoot::kCount;
         idx = static_cast<JSBuiltinDispatchHandleRoot::Idx>(
             static_cast<int>(idx) + 1)) {
      Builtin builtin = JSBuiltinDispatchHandleRoot::to_builtin(idx);
      DCHECK(Builtins::IsIsolateIndependent(builtin));
      Tagged<Code> code = builtins_.code(builtin);
      DCHECK(code->entrypoint_tag() == CodeEntrypointTag::kJSEntrypointTag);
      JSDispatchHandle handle = builtin_dispatch_handle(builtin);
      // TODO(olivf, 40931165): It might be more robust to get the static
      // parameter count of this builtin.
      int parameter_count = code->parameter_count();
      jdt->InitializePreAllocatedEntry(
          read_only_heap_->js_dispatch_table_space(), handle, code,
          parameter_count);
    }
  }
#endif
}

}  // namespace internal
}  // namespace v8

"""


```
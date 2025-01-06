Response: The user wants a summary of the C++ code in `v8/src/execution/isolate.cc`.
The focus should be on the functionalities within this specific part of the file (part 3 of 5).
If any of these functionalities relate to JavaScript, I should provide illustrative JavaScript examples.

Based on the code provided in part 3, it seems to be focusing on:

1. **Promise rejection handling and stack walking:** The `CallsCatchMethod` and `WalkCallStackAndPromiseTree` functions seem to be related to identifying if a promise rejection is handled (e.g., by a `.catch()` call) while traversing the call stack.
2. **Configuration of uncaught exception handling:** The `SetCaptureStackTraceForUncaughtExceptions` and `SetAbortOnUncaughtExceptionCallback` functions deal with how uncaught exceptions are processed.
3. **Feature enabling based on context:** Functions like `IsSharedArrayBufferConstructorEnabled`, `IsWasmStringRefEnabled`, `IsWasmJSPIRequested`, `IsWasmJSPIEnabled`, and `IsWasmImportedStringsEnabled` check and manage the availability of certain features within a given JavaScript context.
4. **Incumbent context determination:** `GetIncumbentContextSlow` attempts to find the relevant JavaScript context for a given operation.
5. **Thread management and data archival:** `ArchiveThread` and `RestoreThread` deal with saving and restoring thread-local data.
6. **Managed pointer handling:** `RegisterManagedPtrDestructor` and `UnregisterManagedPtrDestructor` manage the lifecycle of objects pointed to by shared pointers.
7. **WebAssembly stack management (conditional):** Code sections with `#if V8_ENABLE_WEBASSEMBLY` deal with WebAssembly-specific functionalities like stack management (`IsOnCentralStack`, `SyncStackLimit`, `UpdateCentralStackInfo`, `RetireWasmStack`) and tracking shared memory.
8. **Isolate creation and deletion:** The `Isolate::New` and `Isolate::Delete` methods are responsible for creating and destroying `Isolate` instances.
9. **Isolate initialization and deinitialization:** The `Isolate` constructor, `Deinit`, and destructor contain initialization and cleanup logic for the isolate.
10. **Exception propagation to external try-catch blocks:** The `PropagateExceptionToExternalTryCatch` function manages how exceptions are communicated to C++ try-catch blocks.
11. **Callbacks for exception propagation:**  `NotifyExceptionPropagationCallback`, `ReportExceptionFunctionCallback`, and `ReportExceptionPropertyCallback` handle informing the embedder about exceptions happening in API callbacks.
12. **Embedded blob management:** Functions like `InitializeDefaultEmbeddedBlob` and `CreateAndSetEmbeddedBlob` handle the initialization and management of the embedded V8 snapshot.
13. **Short builtin calls enablement:** `InitializeIsShortBuiltinCallsEnabled` checks if short calls to built-in functions are enabled based on memory conditions.

Now I need to generate JavaScript examples for the relevant points.
这是 `v8/src/execution/isolate.cc` 文件的第 3 部分，主要负责以下功能：

**1. Promise 拒绝处理和堆栈遍历:**

   - 包含用于检查调用堆栈中是否存在 `.catch()` 方法的逻辑 (`CallsCatchMethod`)，这对于确定 Promise 拒绝是否已被处理至关重要。
   - 提供了 `WalkCallStackAndPromiseTree` 函数，用于遍历调用堆栈和 Promise 树，以查找异常处理程序。这对于识别未处理的 Promise 拒绝很有用。

   **JavaScript 示例:**

   ```javascript
   async function fetchData() {
     const result = await fetch('invalid-url'); // 这会返回一个被拒绝的 Promise
     return result.json();
   }

   fetchData()
     .then(data => console.log(data))
     .catch(error => console.error("捕获到错误:", error)); // 这个 .catch() 会被代码识别
   ```

   V8 引擎会分析 `fetchData()` 的调用堆栈，并检测到 `.catch()` 方法，从而判断 Promise 拒绝已被处理。

**2. 配置未捕获异常的处理方式:**

   - `SetCaptureStackTraceForUncaughtExceptions` 函数允许设置是否为未捕获的异常捕获堆栈跟踪信息，并设置捕获的帧数限制和选项。
   - `SetAbortOnUncaughtExceptionCallback` 函数允许设置一个回调函数，当发生未捕获的异常时会调用该函数。

   **JavaScript 示例:**

   ```javascript
   // 假设 V8 内部实现了相关配置，以下代码展示了其可能的影响

   // 设置捕获未捕获异常的堆栈信息
   // V8 内部调用了类似 SetCaptureStackTraceForUncaughtExceptions(true, 10);

   setTimeout(() => {
     throw new Error("这是一个未捕获的错误");
   }, 100);

   // 如果设置了回调，当错误发生时，回调函数会被调用
   // V8 内部调用了设置的回调函数
   ```

**3. 基于上下文启用特定功能:**

   - 提供了一系列 `Is...Enabled` 函数，例如 `IsSharedArrayBufferConstructorEnabled`、`IsWasmStringRefEnabled` 等，这些函数用于检查在当前的 JavaScript 上下文中是否启用了特定的语言特性或 WebAssembly 功能。

   **JavaScript 示例:**

   ```javascript
   // 假设 V8 内部通过这些函数判断特性是否可用

   if (globalThis.SharedArrayBuffer) {
     console.log("SharedArrayBuffer 已启用");
   } else {
     console.log("SharedArrayBuffer 未启用");
   }

   // 对于 WebAssembly 相关特性，类似地：
   // if ('WebAssembly' in globalThis && WebAssembly.StringRef) { ... }
   ```

**4. 获取当前执行上下文 (Incumbent Context):**

   - `GetIncumbentContextSlow` 函数用于在没有直接上下文信息时，通过遍历堆栈等方式，尝试确定当前的 JavaScript 执行上下文。

   **JavaScript 场景 (内部行为):** 当需要在 V8 内部确定当前代码运行在哪个上下文中时 (例如，在处理原生模块或 API 调用时)，会使用类似这样的机制。

**5. 线程管理和数据归档:**

   - `ArchiveThread` 和 `RestoreThread` 函数用于保存和恢复线程的局部数据，这在 V8 的线程模型中用于隔离不同线程的状态。

   **JavaScript 场景 (内部行为):** V8 内部在线程切换或隔离操作时会使用这些函数。

**6. 管理对象析构器:**

   - `RegisterManagedPtrDestructor` 和 `UnregisterManagedPtrDestructor` 用于注册和注销由智能指针管理的对象的析构器。这允许在对象不再被引用时执行清理操作。

   **JavaScript 场景 (内部行为):** 这主要用于 V8 内部管理 C++ 对象的生命周期。

**7. WebAssembly 堆栈管理 (条件编译):**

   - 在 `#if V8_ENABLE_WEBASSEMBLY` 条件下，包含了一系列用于管理 WebAssembly 堆栈的函数，例如 `IsOnCentralStack`、`SyncStackLimit`、`UpdateCentralStackInfo` 和 `RetireWasmStack`。这些函数用于跟踪和控制 WebAssembly 代码的执行堆栈。

   **JavaScript 示例 (涉及 WebAssembly):**

   ```javascript
   // 假设有一个 WebAssembly 模块
   const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
   const wasmModule = new WebAssembly.Module(wasmCode);
   const wasmInstance = new WebAssembly.Instance(wasmModule);
   // V8 内部会使用上述函数来管理 WebAssembly 的执行
   ```

**8. Isolate 的创建和删除:**

   - `Isolate::New` 和 `Isolate::Delete` 是创建和销毁 V8 Isolate 实例的静态方法。Isolate 是 V8 引擎的独立执行环境。

   **JavaScript 场景 (外部 API):**

   ```c++
   // C++ 代码中使用 V8 API 创建和销毁 Isolate
   v8::Isolate* isolate = v8::Isolate::New();
   // ... 使用 isolate ...
   v8::Isolate::Dispose(isolate);
   ```

**9. Isolate 的初始化和反初始化:**

   - `Isolate` 的构造函数执行 Isolate 的初始化工作。
   - `Deinit` 方法执行 Isolate 的反初始化操作，清理资源。
   - 析构函数 `~Isolate` 执行 Isolate 对象的销毁。

   **JavaScript 场景 (内部行为):**  当 V8 引擎启动和关闭时，会创建和销毁 Isolate 实例。

**10. 将异常传播到外部 TryCatch 块:**

    - `PropagateExceptionToExternalTryCatch` 函数负责将 JavaScript 异常传递给 C++ 代码中设置的 `v8::TryCatch` 块。

    **JavaScript 示例:**

    ```c++
    // C++ 代码
    v8::TryCatch try_catch(isolate);
    {
      v8::Local<v8::String> source =
          v8::String::NewFromUtf8(isolate, "throw new Error('来自 JavaScript 的错误');").ToLocalChecked();
      v8::Local<v8::Script> script = v8::Script::Compile(context, source).ToLocalChecked();
      script->Run(context);
    }
    if (try_catch.HasCaught()) {
      v8::Local<v8::Value> exception = try_catch.Exception();
      v8::String::Utf8Value exception_str(isolate, exception);
      std::cout << "C++ 捕获到异常: " << *exception_str << std::endl;
    }
    ```

**11. 异常传播回调:**

    - `NotifyExceptionPropagationCallback`、`ReportExceptionFunctionCallback` 和 `ReportExceptionPropertyCallback` 用于通知宿主环境 (例如，浏览器或 Node.js) 关于在 API 回调中发生的异常。

    **JavaScript 示例:**

    ```c++
    // C++ 代码设置异常传播回调
    void ExceptionCallback(const v8::ExceptionPropagationMessage& message) {
      v8::String::Utf8Value error(message.GetIsolate(), message.GetException());
      std::cerr << "JavaScript 异常传播到 C++: " << *error << std::endl;
    }
    isolate->SetExceptionPropagationCallback(ExceptionCallback);

    // JavaScript 代码
    function myCallback() {
      throw new Error("API 回调中的错误");
    }

    const myObjectTemplate = v8::FunctionTemplate::New(isolate, myCallback);
    // ... 将模板注册到 V8 ...
    ```

**12. 初始化默认嵌入式 Blob:**

    - `InitializeDefaultEmbeddedBlob` 函数用于加载 V8 预编译的快照 (embedded blob)，其中包含内置对象和代码，以加速启动过程。

    **JavaScript 场景 (内部行为):**  在 V8 引擎启动时，会加载嵌入式 Blob。

**13. 创建和设置嵌入式 Blob:**

    - `CreateAndSetEmbeddedBlob` 函数负责创建或加载嵌入式 Blob，并将其设置为当前 Isolate 使用的 Blob。

    **JavaScript 场景 (内部行为/Snapshotting):**  在创建 V8 快照时会用到。

**14. 初始化是否启用短内置函数调用:**

    - `InitializeIsShortBuiltinCallsEnabled` 函数根据系统内存等条件，决定是否启用对内置函数的短调用优化，以减小代码大小。

    **JavaScript 场景 (内部优化):**  这是一种 V8 内部的性能优化。

总而言之，这部分代码主要关注 V8 引擎的执行环境管理，包括异常处理、上下文管理、线程管理、特定功能的启用以及与宿主环境的交互，还有一些关于 WebAssembly 的支持性功能。这些功能对于 V8 引擎的稳定运行和与 JavaScript 代码的正确交互至关重要。

Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
alse;
    }
    // The register it stores to will be assumed to be our promise
    int promise_register = iterator.GetStarTargetRegister().index();

    // TODO(crbug/40283993): Should we loop over non-matching instructions here
    // to allow code like
    // `const promise = foo(); console.log(...); promise.catch(...);`?

    iterator.Advance();
    // We should be on a GetNamedProperty instruction.
    if (iterator.done() ||
        iterator.current_bytecode() != Bytecode::kGetNamedProperty ||
        iterator.GetRegisterOperand(0).index() != promise_register) {
      return false;
    }
    PromiseMethod method = GetPromiseMethod(isolate, iterator);
    if (method == kInvalid) {
      return false;
    }

    iterator.Advance();
    // Next instruction should be a Star (save immediate to register)
    if (iterator.done() || !Bytecodes::IsAnyStar(iterator.current_bytecode())) {
      return false;
    }
    // This register contains the method we will eventually invoke
    int method_register = iterator.GetStarTargetRegister().index();
    if (method_register == promise_register) {
      return false;
    }

    // Now we step over multiple instructions creating the arguments for the
    // method.
    while (true) {
      iterator.Advance();
      if (iterator.done()) {
        return false;
      }
      Bytecode bytecode = iterator.current_bytecode();
      if (bytecode == Bytecode::kCallProperty1 ||
          bytecode == Bytecode::kCallProperty2) {
        // This is a call property call of the right size, but is it a call of
        // the method and on the promise?
        if (iterator.GetRegisterOperand(0).index() == method_register &&
            iterator.GetRegisterOperand(1).index() == promise_register) {
          // This is our method call, but does it catch?
          if (method == kCatch ||
              (method == kThen && bytecode == Bytecode::kCallProperty2)) {
            return true;
          }
          // Break out of the inner loop, continuing the outer loop. We
          // will use the same procedure to check for chained method calls.
          break;
        }
      }

      // Check for some instructions that should make us give up scanning.
      if (Bytecodes::IsJump(bytecode) || Bytecodes::IsSwitch(bytecode) ||
          Bytecodes::Returns(bytecode) ||
          Bytecodes::UnconditionallyThrows(bytecode)) {
        // Stop scanning at control flow instructions that aren't calls
        return false;
      }

      if (TouchesRegister(iterator, promise_register) ||
          TouchesRegister(iterator, method_register)) {
        // Stop scanning at instruction that unexpectedly interacts with one of
        // the registers we care about.
        return false;
      }
    }
  }
  return false;
}

bool CallsCatchMethod(const StackFrameSummaryIterator& iterator) {
  if (!iterator.frame()->is_javascript()) {
    return false;
  }
  if (iterator.frame_summary().IsJavaScript()) {
    auto& js_summary = iterator.frame_summary().AsJavaScript();
    if (IsBytecodeArray(*js_summary.abstract_code())) {
      if (CallsCatchMethod(iterator.isolate(),
                           Cast<BytecodeArray>(js_summary.abstract_code()),
                           js_summary.code_offset())) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

bool Isolate::WalkCallStackAndPromiseTree(
    MaybeHandle<JSPromise> rejected_promise,
    const std::function<void(PromiseHandler)>& callback) {
  bool is_promise_rejection = false;

  Handle<JSPromise> promise;
  if (rejected_promise.ToHandle(&promise)) {
    is_promise_rejection = true;
    // If the promise has reactions, follow them and assume we are done. If
    // it has no reactions, assume promise is returned up the call stack and
    // trace accordingly. If the promise is not pending, it has no reactions
    // and is probably the result of a call to Promise.reject().
    if (promise->status() != Promise::kPending) {
      // Ignore this promise; set to null
      rejected_promise = MaybeHandle<JSPromise>();
    } else if (IsSmi(promise->reactions())) {
      // Also check that there is no outer promise
      Handle<Symbol> key = factory()->promise_handled_by_symbol();
      if (!IsJSPromise(*JSObject::GetDataProperty(this, promise, key))) {
        // Ignore this promise; set to null
        rejected_promise = MaybeHandle<JSPromise>();
      }
    }
  }

  if (!is_promise_rejection && TopExceptionHandlerType(Tagged<Object>()) ==
                                   ExceptionHandlerType::kExternalTryCatch) {
    return true;  // caught by external
  }

  // Search for an exception handler by performing a full walk over the stack.
  for (StackFrameSummaryIterator iter(this); !iter.done(); iter.Advance()) {
    Isolate::CatchType prediction = PredictExceptionCatchAtFrame(iter);

    bool caught;
    if (rejected_promise.is_null()) {
      switch (prediction) {
        case NOT_CAUGHT:
          // Uncaught unless this is a promise rejection and the code will call
          // .catch()
          caught = is_promise_rejection && CallsCatchMethod(iter);
          break;
        case CAUGHT_BY_ASYNC_AWAIT:
          // Uncaught unless this is a promise rejection and the code will call
          // .catch()
          caught = is_promise_rejection && CallsCatchMethod(iter);
          // Exceptions turn into promise rejections here
          is_promise_rejection = true;
          break;
        case CAUGHT_BY_PROMISE:
          // Exceptions turn into promise rejections here
          // TODO(leese): Perhaps we can handle the case where the reject method
          // is called in the promise constructor and it is still on the stack
          // by ignoring all try/catches on the stack until we get to the right
          // CAUGHT_BY_PROMISE?
          is_promise_rejection = true;
          caught = false;
          break;
        case CAUGHT_BY_EXTERNAL:
          caught = !is_promise_rejection;
          break;
        case CAUGHT_BY_JAVASCRIPT:
          caught = true;
          // Unless this is a promise rejection and the function is not async...
          DCHECK(iter.has_frame_summary());
          const FrameSummary& summary = iter.frame_summary();
          if (is_promise_rejection && summary.IsJavaScript()) {
            // If the catch happens in an async function, assume it will
            // await this promise. Alternately, if the code will call .catch,
            // assume it is on this promise.
            caught = IsAsyncFunction(iter.frame_summary()
                                         .AsJavaScript()
                                         .function()
                                         ->shared()
                                         ->kind()) ||
                     CallsCatchMethod(iter);
          }
          break;
      }
    } else {
      // The frame that calls the reject handler will not catch that promise
      // regardless of what else it does. We will trace where this rejection
      // goes according to its reaction callbacks, but we first need to handle
      // the topmost debuggable frame just to ensure there is a debuggable
      // frame and to permit ignore listing there.
      caught = false;
    }

    if (iter.frame()->is_javascript()) {
      bool debuggable = false;
      DCHECK(iter.has_frame_summary());
      const FrameSummary& summary = iter.frame_summary();
      if (summary.IsJavaScript()) {
        const auto& info = summary.AsJavaScript().function()->shared();
        if (info->IsSubjectToDebugging()) {
          callback({*info, false});
          debuggable = true;
        }
      }

      // Ignore the rest of the call stack if this is a rejection and the
      // promise has handlers; we will trace where the rejection goes instead
      // of where it came from.
      if (debuggable && !rejected_promise.is_null()) {
        break;
      }
    }

    if (caught) {
      return true;
    }
  }

  if (rejected_promise.is_null()) {
    // Now follow promises if this is a promise reaction job.
    rejected_promise = TryGetCurrentTaskPromise(this);
  }

  if (rejected_promise.ToHandle(&promise)) {
    return WalkPromiseTreeInternal(this, promise, callback);
  }
  // Nothing caught.
  return false;
}

void Isolate::SetCaptureStackTraceForUncaughtExceptions(
    bool capture, int frame_limit, StackTrace::StackTraceOptions options) {
  capture_stack_trace_for_uncaught_exceptions_ = capture;
  stack_trace_for_uncaught_exceptions_frame_limit_ = frame_limit;
  stack_trace_for_uncaught_exceptions_options_ = options;
}

bool Isolate::get_capture_stack_trace_for_uncaught_exceptions() const {
  return capture_stack_trace_for_uncaught_exceptions_;
}

void Isolate::SetAbortOnUncaughtExceptionCallback(
    v8::Isolate::AbortOnUncaughtExceptionCallback callback) {
  abort_on_uncaught_exception_callback_ = callback;
}

void Isolate::InstallConditionalFeatures(Handle<NativeContext> context) {
  Handle<JSGlobalObject> global = handle(context->global_object(), this);
  // If some fuzzer decided to make the global object non-extensible, then
  // we can't install any features (and would CHECK-fail if we tried).
  if (!global->map()->is_extensible()) return;
  Handle<String> sab_name = factory()->SharedArrayBuffer_string();
  if (IsSharedArrayBufferConstructorEnabled(context)) {
    if (!JSObject::HasRealNamedProperty(this, global, sab_name)
             .FromMaybe(true)) {
      JSObject::AddProperty(this, global, factory()->SharedArrayBuffer_string(),
                            shared_array_buffer_fun(), DONT_ENUM);
    }
  }
}

bool Isolate::IsSharedArrayBufferConstructorEnabled(
    Handle<NativeContext> context) {
  if (!v8_flags.enable_sharedarraybuffer_per_context) return true;

  if (sharedarraybuffer_constructor_enabled_callback()) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(context);
    return sharedarraybuffer_constructor_enabled_callback()(api_context);
  }
  return false;
}

bool Isolate::IsWasmStringRefEnabled(Handle<NativeContext> context) {
#ifdef V8_ENABLE_WEBASSEMBLY
  // If Wasm imported strings are explicitly enabled via a callback, also enable
  // stringref.
  v8::WasmImportedStringsEnabledCallback callback_imported_strings =
      wasm_imported_strings_enabled_callback();
  if (callback_imported_strings) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(context);
    if (callback_imported_strings(api_context)) return true;
  }
  // Otherwise use the runtime flag.
  return v8_flags.experimental_wasm_stringref;
#else
  return false;
#endif
}

bool Isolate::IsWasmJSPIRequested(Handle<NativeContext> context) {
#ifdef V8_ENABLE_WEBASSEMBLY
  v8::WasmJSPIEnabledCallback jspi_callback = wasm_jspi_enabled_callback();
  if (jspi_callback) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(context);
    if (jspi_callback(api_context)) return true;
  }

  // Otherwise use the runtime flag.
  return v8_flags.experimental_wasm_jspi;
#else
  return false;
#endif
}

bool Isolate::IsWasmJSPIEnabled(Handle<NativeContext> context) {
#ifdef V8_ENABLE_WEBASSEMBLY
  return IsWasmJSPIRequested(context) &&
         context->is_wasm_jspi_installed() != Smi::zero();
#else
  return false;
#endif
}

bool Isolate::IsWasmImportedStringsEnabled(Handle<NativeContext> context) {
#ifdef V8_ENABLE_WEBASSEMBLY
  v8::WasmImportedStringsEnabledCallback callback =
      wasm_imported_strings_enabled_callback();
  if (callback) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(context);
    if (callback(api_context)) return true;
  }
  return v8_flags.experimental_wasm_imported_strings;
#else
  return false;
#endif
}

Handle<NativeContext> Isolate::GetIncumbentContextSlow() {
  JavaScriptStackFrameIterator it(this);

  // 1st candidate: most-recently-entered author function's context
  // if it's newer than the last Context::BackupIncumbentScope entry.
  //
  // NOTE: This code assumes that the stack grows downward.
  Address top_backup_incumbent =
      top_backup_incumbent_scope()
          ? top_backup_incumbent_scope()->JSStackComparableAddressPrivate()
          : 0;
  if (!it.done() &&
      (!top_backup_incumbent || it.frame()->sp() < top_backup_incumbent)) {
    Tagged<Context> context = Cast<Context>(it.frame()->context());
    // If the topmost_script_having_context is set then it must be correct.
    if (DEBUG_BOOL && !topmost_script_having_context().is_null()) {
      DCHECK_EQ(topmost_script_having_context()->native_context(),
                context->native_context());
    }
    return Handle<NativeContext>(context->native_context(), this);
  }
  DCHECK(topmost_script_having_context().is_null());

  // 2nd candidate: the last Context::Scope's incumbent context if any.
  if (top_backup_incumbent_scope()) {
    v8::Local<v8::Context> incumbent_context =
        top_backup_incumbent_scope()->backup_incumbent_context_;
    return Utils::OpenHandle(*incumbent_context);
  }

  // Last candidate: the entered context or microtask context.
  // Given that there is no other author function is running, there must be
  // no cross-context function running, then the incumbent realm must match
  // the entry realm.
  v8::Local<v8::Context> entered_context =
      reinterpret_cast<v8::Isolate*>(this)->GetEnteredOrMicrotaskContext();
  return Utils::OpenHandle(*entered_context);
}

char* Isolate::ArchiveThread(char* to) {
  MemCopy(to, reinterpret_cast<char*>(thread_local_top()),
          sizeof(ThreadLocalTop));
  return to + sizeof(ThreadLocalTop);
}

char* Isolate::RestoreThread(char* from) {
  MemCopy(reinterpret_cast<char*>(thread_local_top()), from,
          sizeof(ThreadLocalTop));
  DCHECK(context().is_null() || IsContext(context()));
  return from + sizeof(ThreadLocalTop);
}

void Isolate::ReleaseSharedPtrs() {
  base::MutexGuard lock(&managed_ptr_destructors_mutex_);
  while (managed_ptr_destructors_head_) {
    ManagedPtrDestructor* l = managed_ptr_destructors_head_;
    ManagedPtrDestructor* n = nullptr;
    managed_ptr_destructors_head_ = nullptr;
    for (; l != nullptr; l = n) {
      l->external_memory_accounter_.Decrease(this, l->estimated_size_);
      l->destructor_(l->shared_ptr_ptr_);
      n = l->next_;
      delete l;
    }
  }
}

bool Isolate::IsBuiltinTableHandleLocation(Address* handle_location) {
  FullObjectSlot location(handle_location);
  FullObjectSlot first_root(builtin_table());
  FullObjectSlot last_root(first_root + Builtins::kBuiltinCount);
  if (location >= last_root) return false;
  if (location < first_root) return false;
  return true;
}

void Isolate::RegisterManagedPtrDestructor(ManagedPtrDestructor* destructor) {
  base::MutexGuard lock(&managed_ptr_destructors_mutex_);
  DCHECK_NULL(destructor->prev_);
  DCHECK_NULL(destructor->next_);
  if (managed_ptr_destructors_head_) {
    managed_ptr_destructors_head_->prev_ = destructor;
  }
  destructor->next_ = managed_ptr_destructors_head_;
  managed_ptr_destructors_head_ = destructor;
}

void Isolate::UnregisterManagedPtrDestructor(ManagedPtrDestructor* destructor) {
  base::MutexGuard lock(&managed_ptr_destructors_mutex_);
  if (destructor->prev_) {
    destructor->prev_->next_ = destructor->next_;
  } else {
    DCHECK_EQ(destructor, managed_ptr_destructors_head_);
    managed_ptr_destructors_head_ = destructor->next_;
  }
  if (destructor->next_) destructor->next_->prev_ = destructor->prev_;
  destructor->prev_ = nullptr;
  destructor->next_ = nullptr;
}

#if V8_ENABLE_WEBASSEMBLY
bool Isolate::IsOnCentralStack(Address addr) {
  auto stack = SimulatorStack::GetCentralStackView(this);
  Address stack_top = reinterpret_cast<Address>(stack.begin());
  Address stack_base = reinterpret_cast<Address>(stack.end());
  return stack_top < addr && addr <= stack_base;
}

bool Isolate::IsOnCentralStack() {
#if USE_SIMULATOR
  return IsOnCentralStack(Simulator::current(this)->get_sp());
#else
  return IsOnCentralStack(GetCurrentStackPosition());
#endif
}

void Isolate::AddSharedWasmMemory(Handle<WasmMemoryObject> memory_object) {
  Handle<WeakArrayList> shared_wasm_memories =
      factory()->shared_wasm_memories();
  shared_wasm_memories = WeakArrayList::Append(
      this, shared_wasm_memories, MaybeObjectDirectHandle::Weak(memory_object));
  heap()->set_shared_wasm_memories(*shared_wasm_memories);
}

void Isolate::SyncStackLimit() {
  // Synchronize the stack limit with the active continuation for
  // stack-switching. This can be done before or after changing the stack
  // pointer itself, as long as we update both before the next stack check.
  // {StackGuard::SetStackLimitForStackSwitching} doesn't update the value of
  // the jslimit if it contains a sentinel value, and it is also thread-safe. So
  // if an interrupt is requested before, during or after this call, it will be
  // preserved and handled at the next stack check.

  DisallowGarbageCollection no_gc;
  auto continuation =
      Cast<WasmContinuationObject>(root(RootIndex::kActiveContinuation));
  wasm::StackMemory* stack =
      reinterpret_cast<wasm::StackMemory*>(continuation->stack());
  if (v8_flags.trace_wasm_stack_switching) {
    PrintF("Switch to stack #%d\n", stack->id());
  }
  uintptr_t limit = reinterpret_cast<uintptr_t>(stack->jmpbuf()->stack_limit);
  stack_guard()->SetStackLimitForStackSwitching(limit);
  UpdateCentralStackInfo();
}

void Isolate::UpdateCentralStackInfo() {
  Tagged<Object> current = root(RootIndex::kActiveContinuation);
  DCHECK(!IsUndefined(current));
  wasm::StackMemory* wasm_stack = reinterpret_cast<wasm::StackMemory*>(
      Cast<WasmContinuationObject>(current)->stack());
  current = Cast<WasmContinuationObject>(current)->parent();
  thread_local_top()->is_on_central_stack_flag_ =
      IsOnCentralStack(wasm_stack->jmpbuf()->sp);
  // Update the central stack info on switch. Only consider the innermost stack
  bool updated_central_stack = false;
  // We don't need to add all inactive stacks. Only the ones in the active chain
  // may contain cpp heap pointers.
  while (!IsUndefined(current)) {
    auto cont = Cast<WasmContinuationObject>(current);
    auto* wasm_stack = reinterpret_cast<wasm::StackMemory*>(cont->stack());
    // On x64 and arm64 we don't need to record the stack segments for
    // conservative stack scanning. We switch to the central stack for foreign
    // calls, so secondary stacks only contain wasm frames which use the precise
    // GC.
    current = cont->parent();
    if (!updated_central_stack && IsOnCentralStack(wasm_stack->jmpbuf()->sp)) {
      // This is the most recent use of the central stack in the call chain.
      // Switch to this SP if we need to switch to the central stack in the
      // future.
      thread_local_top()->central_stack_sp_ = wasm_stack->jmpbuf()->sp;
      thread_local_top()->central_stack_limit_ =
          reinterpret_cast<Address>(wasm_stack->jmpbuf()->stack_limit);
      updated_central_stack = true;
    }
  }
}

void Isolate::RetireWasmStack(wasm::StackMemory* stack) {
  stack->jmpbuf()->state = wasm::JumpBuffer::Retired;
  size_t index = stack->index();
  // We can only return from a stack that was still in the global list.
  DCHECK_LT(index, wasm_stacks().size());
  std::unique_ptr<wasm::StackMemory> stack_ptr =
      std::move(wasm_stacks()[index]);
  DCHECK_EQ(stack_ptr.get(), stack);
  if (index != wasm_stacks().size() - 1) {
    wasm_stacks()[index] = std::move(wasm_stacks().back());
    wasm_stacks()[index]->set_index(index);
  }
  wasm_stacks().pop_back();
  for (size_t i = 0; i < wasm_stacks().size(); ++i) {
    SLOW_DCHECK(wasm_stacks()[i]->index() == i);
  }
  stack_pool().Add(std::move(stack_ptr));
}

wasm::WasmOrphanedGlobalHandle* Isolate::NewWasmOrphanedGlobalHandle() {
  return wasm::WasmEngine::NewOrphanedGlobalHandle(&wasm_orphaned_handle_);
}

#endif  // V8_ENABLE_WEBASSEMBLY

Isolate::PerIsolateThreadData::~PerIsolateThreadData() {
#if defined(USE_SIMULATOR)
  delete simulator_;
#endif
}

Isolate::PerIsolateThreadData* Isolate::ThreadDataTable::Lookup(
    ThreadId thread_id) {
  auto t = table_.find(thread_id);
  if (t == table_.end()) return nullptr;
  return t->second;
}

void Isolate::ThreadDataTable::Insert(Isolate::PerIsolateThreadData* data) {
  bool inserted = table_.insert(std::make_pair(data->thread_id_, data)).second;
  CHECK(inserted);
}

void Isolate::ThreadDataTable::Remove(PerIsolateThreadData* data) {
  table_.erase(data->thread_id_);
  delete data;
}

void Isolate::ThreadDataTable::RemoveAllThreads() {
  for (auto& x : table_) {
    delete x.second;
  }
  table_.clear();
}

class TracingAccountingAllocator : public AccountingAllocator {
 public:
  explicit TracingAccountingAllocator(Isolate* isolate) : isolate_(isolate) {}
  ~TracingAccountingAllocator() = default;

 protected:
  void TraceAllocateSegmentImpl(v8::internal::Segment* segment) override {
    base::MutexGuard lock(&mutex_);
    UpdateMemoryTrafficAndReportMemoryUsage(segment->total_size());
  }

  void TraceZoneCreationImpl(const Zone* zone) override {
    base::MutexGuard lock(&mutex_);
    active_zones_.insert(zone);
    nesting_depth_++;
  }

  void TraceZoneDestructionImpl(const Zone* zone) override {
    base::MutexGuard lock(&mutex_);
#ifdef V8_ENABLE_PRECISE_ZONE_STATS
    if (v8_flags.trace_zone_type_stats) {
      type_stats_.MergeWith(zone->type_stats());
    }
#endif
    UpdateMemoryTrafficAndReportMemoryUsage(zone->segment_bytes_allocated());
    active_zones_.erase(zone);
    nesting_depth_--;

#ifdef V8_ENABLE_PRECISE_ZONE_STATS
    if (v8_flags.trace_zone_type_stats && active_zones_.empty()) {
      type_stats_.Dump();
    }
#endif
  }

 private:
  void UpdateMemoryTrafficAndReportMemoryUsage(size_t memory_traffic_delta) {
    if (!v8_flags.trace_zone_stats &&
        !(TracingFlags::zone_stats.load(std::memory_order_relaxed) &
          v8::tracing::TracingCategoryObserver::ENABLED_BY_TRACING)) {
      // Don't print anything if the zone tracing was enabled only because of
      // v8_flags.trace_zone_type_stats.
      return;
    }

    memory_traffic_since_last_report_ += memory_traffic_delta;
    if (memory_traffic_since_last_report_ < v8_flags.zone_stats_tolerance)
      return;
    memory_traffic_since_last_report_ = 0;

    Dump(buffer_, true);

    {
      std::string trace_str = buffer_.str();

      if (v8_flags.trace_zone_stats) {
        PrintF(
            "{"
            "\"type\": \"v8-zone-trace\", "
            "\"stats\": %s"
            "}\n",
            trace_str.c_str());
      }
      if (V8_UNLIKELY(
              TracingFlags::zone_stats.load(std::memory_order_relaxed) &
              v8::tracing::TracingCategoryObserver::ENABLED_BY_TRACING)) {
        TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("v8.zone_stats"),
                             "V8.Zone_Stats", TRACE_EVENT_SCOPE_THREAD, "stats",
                             TRACE_STR_COPY(trace_str.c_str()));
      }
    }

    // Clear the buffer.
    buffer_.str(std::string());
  }

  void Dump(std::ostringstream& out, bool dump_details) {
    // Note: Neither isolate nor zones are locked, so be careful with accesses
    // as the allocator is potentially used on a concurrent thread.
    double time = isolate_->time_millis_since_init();
    out << "{" << "\"isolate\": \"" << reinterpret_cast<void*>(isolate_)
        << "\", " << "\"time\": " << time << ", ";
    size_t total_segment_bytes_allocated = 0;
    size_t total_zone_allocation_size = 0;
    size_t total_zone_freed_size = 0;

    if (dump_details) {
      // Print detailed zone stats if memory usage changes direction.
      out << "\"zones\": [";
      bool first = true;
      for (const Zone* zone : active_zones_) {
        size_t zone_segment_bytes_allocated = zone->segment_bytes_allocated();
        size_t zone_allocation_size = zone->allocation_size_for_tracing();
        size_t freed_size = zone->freed_size_for_tracing();
        if (first) {
          first = false;
        } else {
          out << ", ";
        }
        out << "{" << "\"name\": \"" << zone->name() << "\", "
            << "\"allocated\": " << zone_segment_bytes_allocated << ", "
            << "\"used\": " << zone_allocation_size << ", "
            << "\"freed\": " << freed_size << "}";
        total_segment_bytes_allocated += zone_segment_bytes_allocated;
        total_zone_allocation_size += zone_allocation_size;
        total_zone_freed_size += freed_size;
      }
      out << "], ";
    } else {
      // Just calculate total allocated/used memory values.
      for (const Zone* zone : active_zones_) {
        total_segment_bytes_allocated += zone->segment_bytes_allocated();
        total_zone_allocation_size += zone->allocation_size_for_tracing();
        total_zone_freed_size += zone->freed_size_for_tracing();
      }
    }
    out << "\"allocated\": " << total_segment_bytes_allocated << ", "
        << "\"used\": " << total_zone_allocation_size << ", "
        << "\"freed\": " << total_zone_freed_size << "}";
  }

  Isolate* const isolate_;
  std::atomic<size_t> nesting_depth_{0};

  base::Mutex mutex_;
  std::unordered_set<const Zone*> active_zones_;
#ifdef V8_ENABLE_PRECISE_ZONE_STATS
  TypeStats type_stats_;
#endif
  std::ostringstream buffer_;
  // This value is increased on both allocations and deallocations.
  size_t memory_traffic_since_last_report_ = 0;
};

#ifdef DEBUG
std::atomic<size_t> Isolate::non_disposed_isolates_;
#endif  // DEBUG

// static
Isolate* Isolate::New() { return New(IsolateGroup::AcquireDefault()); }

// static
Isolate* Isolate::New(IsolateGroup* group) { return Allocate(group); }

// static
Isolate* Isolate::Allocate(IsolateGroup* group) {
  // v8::V8::Initialize() must be called before creating any isolates.
  DCHECK_NOT_NULL(V8::GetCurrentPlatform());
  // Allocate Isolate itself on C++ heap, ensuring page alignment.
  void* isolate_ptr = base::AlignedAlloc(sizeof(Isolate), kMinimumOSPageSize);
  // IsolateAllocator manages the virtual memory resources for the Isolate.
  Isolate* isolate = new (isolate_ptr) Isolate(group);

#ifdef DEBUG
  non_disposed_isolates_++;
#endif  // DEBUG

  return isolate;
}

// static
void Isolate::Delete(Isolate* isolate) {
  DCHECK_NOT_NULL(isolate);
  // v8::V8::Dispose() must only be called after deleting all isolates.
  DCHECK_NOT_NULL(V8::GetCurrentPlatform());
  // Temporarily set this isolate as current so that various parts of
  // the isolate can access it in their destructors without having a
  // direct pointer. We don't use Enter/Exit here to avoid
  // initializing the thread data.
  PerIsolateThreadData* saved_data = isolate->CurrentPerIsolateThreadData();
  Isolate* saved_isolate = isolate->TryGetCurrent();
  SetIsolateThreadLocals(isolate, nullptr);
  isolate->set_thread_id(ThreadId::Current());
  isolate->heap()->SetStackStart();

  isolate->Deinit();

#ifdef DEBUG
  non_disposed_isolates_--;
#endif  // DEBUG

  IsolateGroup* group = isolate->isolate_group();
  isolate->~Isolate();
  // Only release the group once all other Isolate members have been destroyed.
  group->Release();
  // Free the isolate itself.
  base::AlignedFree(isolate);

  // Restore the previous current isolate.
  SetIsolateThreadLocals(saved_isolate, saved_data);
}

void Isolate::SetUpFromReadOnlyArtifacts(ReadOnlyArtifacts* artifacts,
                                         ReadOnlyHeap* ro_heap) {
  if (ReadOnlyHeap::IsReadOnlySpaceShared()) {
    DCHECK_NOT_NULL(artifacts);
    InitializeNextUniqueSfiId(artifacts->initial_next_unique_sfi_id());
  } else {
    DCHECK_NULL(artifacts);
  }
  DCHECK_NOT_NULL(ro_heap);
  DCHECK_IMPLIES(read_only_heap_ != nullptr, read_only_heap_ == ro_heap);
  read_only_heap_ = ro_heap;
  heap_.SetUpFromReadOnlyHeap(read_only_heap_);
}

v8::PageAllocator* Isolate::page_allocator() const {
  return isolate_group()->page_allocator();
}

Isolate::Isolate(IsolateGroup* isolate_group)
    : isolate_data_(this, isolate_group),
      isolate_group_(isolate_group),
      id_(isolate_counter.fetch_add(1, std::memory_order_relaxed)),
      allocator_(new TracingAccountingAllocator(this)),
      traced_handles_(this),
      builtins_(this),
#if defined(DEBUG) || defined(VERIFY_HEAP)
      num_active_deserializers_(0),
#endif
      logger_(new Logger()),
      detailed_source_positions_for_profiling_(v8_flags.detailed_line_info),
      persistent_handles_list_(new PersistentHandlesList()),
      jitless_(v8_flags.jitless),
      next_unique_sfi_id_(0),
      next_module_async_evaluation_ordinal_(
          SourceTextModule::kFirstAsyncEvaluationOrdinal),
      cancelable_task_manager_(new CancelableTaskManager()) {
  TRACE_ISOLATE(constructor);
  CheckIsolateLayout();

  isolate_group->IncrementIsolateCount();

  // ThreadManager is initialized early to support locking an isolate
  // before it is entered.
  thread_manager_ = new ThreadManager(this);

  handle_scope_data()->Initialize();

#define ISOLATE_INIT_EXECUTE(type, name, initial_value) \
  name##_ = (initial_value);
  ISOLATE_INIT_LIST(ISOLATE_INIT_EXECUTE)
#undef ISOLATE_INIT_EXECUTE

#define ISOLATE_INIT_ARRAY_EXECUTE(type, name, length) \
  memset(name##_, 0, sizeof(type) * length);
  ISOLATE_INIT_ARRAY_LIST(ISOLATE_INIT_ARRAY_EXECUTE)
#undef ISOLATE_INIT_ARRAY_EXECUTE

  InitializeLoggingAndCounters();
  debug_ = new Debug(this);

  InitializeDefaultEmbeddedBlob();

#if V8_ENABLE_WEBASSEMBLY
  // If we are in production V8 and not in mksnapshot we have to pass the
  // landing pad builtin to the WebAssembly TrapHandler.
  // TODO(ahaas): Isolate creation is the earliest point in time when builtins
  // are available, so we cannot set the landing pad earlier at the moment.
  // However, if builtins ever get loaded during process initialization time,
  // then the initialization of the trap handler landing pad should also go
  // there.
  // TODO(ahaas): The code of the landing pad does not have to be a builtin,
  // we could also just move it to the trap handler, and implement it e.g. with
  // inline assembly. It's not clear if that's worth it.
  if (Isolate::CurrentEmbeddedBlobCodeSize()) {
    EmbeddedData embedded_data = EmbeddedData::FromBlob();
    Address landing_pad =
        embedded_data.InstructionStartOf(Builtin::kWasmTrapHandlerLandingPad);
    i::trap_handler::SetLandingPad(landing_pad);
  }

  for (size_t i = 0; i < Builtins::kNumWasmIndirectlyCallableBuiltins; i++) {
    wasm_builtin_code_handles_[i] = wasm::WasmCodePointerTable::kInvalidHandle;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  MicrotaskQueue::SetUpDefaultMicrotaskQueue(this);
}

void Isolate::CheckIsolateLayout() {
#ifdef V8_ENABLE_SANDBOX
  CHECK_EQ(static_cast<int>(OFFSET_OF(ExternalPointerTable, base_)),
           Internals::kExternalPointerTableBasePointerOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(TrustedPointerTable, base_)),
           Internals::kTrustedPointerTableBasePointerOffset);
  CHECK_EQ(static_cast<int>(sizeof(ExternalPointerTable)),
           Internals::kExternalPointerTableSize);
  CHECK_EQ(static_cast<int>(sizeof(ExternalPointerTable)),
           ExternalPointerTable::kSize);
  CHECK_EQ(static_cast<int>(sizeof(TrustedPointerTable)),
           Internals::kTrustedPointerTableSize);
  CHECK_EQ(static_cast<int>(sizeof(TrustedPointerTable)),
           TrustedPointerTable::kSize);
#endif

  CHECK_EQ(OFFSET_OF(Isolate, isolate_data_), 0);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.stack_guard_)),
           Internals::kIsolateStackGuardOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.is_marking_flag_)),
           Internals::kVariousBooleanFlagsOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.error_message_param_)),
      Internals::kErrorMessageParamOffset);
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.builtin_tier0_entry_table_)),
           Internals::kBuiltinTier0EntryTableOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.builtin_tier0_table_)),
      Internals::kBuiltinTier0TableOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.new_allocation_info_)),
      Internals::kNewAllocationInfoOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.old_allocation_info_)),
      Internals::kOldAllocationInfoOffset);
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.fast_c_call_caller_fp_)),
           Internals::kIsolateFastCCallCallerFpOffset);
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.fast_c_call_caller_pc_)),
           Internals::kIsolateFastCCallCallerPcOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.cage_base_)),
           Internals::kIsolateCageBaseOffset);
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.long_task_stats_counter_)),
           Internals::kIsolateLongTaskStatsCounterOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.stack_guard_)),
           Internals::kIsolateStackGuardOffset);

  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.thread_local_top_)),
      Internals::kIsolateThreadLocalTopOffset);
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.handle_scope_data_)),
      Internals::kIsolateHandleScopeDataOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.embedder_data_)),
           Internals::kIsolateEmbedderDataOffset);
#ifdef V8_COMPRESS_POINTERS
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.external_pointer_table_)),
           Internals::kIsolateExternalPointerTableOffset);

  CHECK_EQ(static_cast<int>(OFFSET_OF(
               Isolate, isolate_data_.shared_external_pointer_table_)),
           Internals::kIsolateSharedExternalPointerTableAddressOffset);
#endif
#ifdef V8_ENABLE_SANDBOX
  CHECK_EQ(
      static_cast<int>(OFFSET_OF(Isolate, isolate_data_.trusted_cage_base_)),
      Internals::kIsolateTrustedCageBaseOffset);

  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.trusted_pointer_table_)),
           Internals::kIsolateTrustedPointerTableOffset);

  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.shared_trusted_pointer_table_)),
           Internals::kIsolateSharedTrustedPointerTableAddressOffset);
#endif
  CHECK_EQ(static_cast<int>(
               OFFSET_OF(Isolate, isolate_data_.api_callback_thunk_argument_)),
           Internals::kIsolateApiCallbackThunkArgumentOffset);
  CHECK_EQ(static_cast<int>(OFFSET_OF(
               Isolate, isolate_data_.continuation_preserved_embedder_data_)),
           Internals::kContinuationPreservedEmbedderDataOffset);

  CHECK_EQ(static_cast<int>(OFFSET_OF(Isolate, isolate_data_.roots_table_)),
           Internals::kIsolateRootsOffset);

  CHECK(IsAligned(reinterpret_cast<Address>(&isolate_data_),
                  kIsolateDataAlignment));

  static_assert(Internals::kStackGuardSize == sizeof(StackGuard));
  static_assert(Internals::kBuiltinTier0TableSize ==
                Builtins::kBuiltinTier0Count * kSystemPointerSize);
  static_assert(Internals::kBuiltinTier0EntryTableSize ==
                Builtins::kBuiltinTier0Count * kSystemPointerSize);

  // Ensure that certain hot IsolateData fields fall into the same CPU cache
  // line.
  constexpr size_t kCacheLineSize = 64;
  static_assert(OFFSET_OF(Isolate, isolate_data_) == 0);

  // Fields written on every CEntry/CallApiCallback/CallApiGetter call.
  // See MacroAssembler::EnterExitFrame/LeaveExitFrame.
  constexpr size_t kCEntryFPCacheLine = RoundDown<kCacheLineSize>(
      OFFSET_OF(IsolateData, thread_local_top_.c_entry_fp_));
  static_assert(kCEntryFPCacheLine ==
                RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, thread_local_top_.c_function_)));
  static_assert(kCEntryFPCacheLine ==
                RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, thread_local_top_.context_)));
  static_assert(
      kCEntryFPCacheLine ==
      RoundDown<kCacheLineSize>(OFFSET_OF(
          IsolateData, thread_local_top_.topmost_script_having_context_)));
  static_assert(kCEntryFPCacheLine ==
                RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, thread_local_top_.last_api_entry_)));

  // Fields written on every MacroAssembler::CallCFunction call.
  static_assert(RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, fast_c_call_caller_fp_)) ==
                RoundDown<kCacheLineSize>(
                    OFFSET_OF(IsolateData, fast_c_call_caller_pc_)));

  // LinearAllocationArea objects must not cross cache line boundary.
  static_assert(
      RoundDown<kCacheLineSize>(OFFSET_OF(IsolateData, new_allocation_info_)) ==
      RoundDown<kCacheLineSize>(OFFSET_OF(IsolateData, new_allocation_info_) +
                                sizeof(LinearAllocationArea) - 1));
  static_assert(
      RoundDown<kCacheLineSize>(OFFSET_OF(IsolateData, old_allocation_info_)) ==
      RoundDown<kCacheLineSize>(OFFSET_OF(IsolateData, old_allocation_info_) +
                                sizeof(LinearAllocationArea) - 1));
}

void Isolate::ClearSerializerData() {
  delete external_reference_map_;
  external_reference_map_ = nullptr;
}

// When profiling status changes, call this function to update the single bool
// cache.
void Isolate::UpdateLogObjectRelocation() {
  log_object_relocation_ = v8_flags.verify_predictable ||
                           IsLoggingCodeCreation() ||
                           v8_file_logger()->is_logging() ||
                           (heap_profiler() != nullptr &&
                            heap_profiler()->is_tracking_object_moves()) ||
                           heap()->has_heap_object_allocation_tracker();
}

void Isolate::Deinit() {
  TRACE_ISOLATE(deinit);

#if defined(V8_USE_PERFETTO)
  PerfettoLogger::UnregisterIsolate(this);
#endif  // defined(V8_USE_PERFETTO)

  // All client isolates should already be detached when the shared heap isolate
  // tears down.
  if (is_shared_space_isolate()) {
    global_safepoint()->AssertNoClientsOnTearDown();
  }

  if (has_shared_space() && !is_shared_space_isolate()) {
    IgnoreLocalGCRequests ignore_gc_requests(heap());
    main_thread_local_heap()->ExecuteMainThreadWhileParked([this]() {
      shared_space_isolate()->global_safepoint()->clients_mutex_.Lock();
    });
  }

  // We start with the heap tear down so that releasing managed objects does
  // not cause a GC.
  heap_.StartTearDown();

  DisallowGarbageCollection no_gc;
  IgnoreLocalGCRequests ignore_gc_requests(heap());

#if V8_ENABLE_WEBASSEMBLY && V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    wasm::WasmInterpreter::NotifyIsolateDisposal(this);
  } else if (v8_flags.wasm_enable_exec_time_histograms &&
             v8_flags.slow_histograms) {
    wasm_execution_timer_->Terminate();
  }
#endif  // V8_ENABLE_WEBASSEMBLY && V8_ENABLE_DRUMBRAKE

  tracing_cpu_profiler_.reset();
  if (v8_flags.stress_sampling_allocation_profiler > 0) {
    heap_profiler()->StopSamplingHeapProfiler();
  }

  metrics_recorder_->NotifyIsolateDisposal();
  recorder_context_id_map_.clear();

  FutexEmulation::IsolateDeinit(this);
  if (v8_flags.harmony_struct) {
    JSSynchronizationPrimitive::IsolateDeinit(this);
  } else {
    DCHECK(async_waiter_queue_nodes_.empty());
  }

  debug()->Unload();

#if V8_ENABLE_WEBASSEMBLY
  wasm::GetWasmEngine()->DeleteCompileJobsOnIsolate(this);

  BackingStore::RemoveSharedWasmMemoryObjects(this);
#endif  // V8_ENABLE_WEBASSEMBLY

  if (concurrent_recompilation_enabled()) {
    optimizing_compile_dispatcher_->Stop();
    delete optimizing_compile_dispatcher_;
    optimizing_compile_dispatcher_ = nullptr;
  }

  if (v8_flags.print_deopt_stress) {
    PrintF(stdout, "=== Stress deopt counter: %u\n", stress_deopt_count_);
  }

  // We must stop the logger before we tear down other components.
  sampler::Sampler* sampler = v8_file_logger_->sampler();
  if (sampler && sampler->IsActive()) sampler->Stop();
  v8_file_logger_->StopProfilerThread();

  FreeThreadResources();

  // Stop concurrent tasks before destroying resources since they might still
  // use those.
  cancelable_task_manager()->CancelAndWait();

  // Cancel all compiler tasks.
#ifdef V8_ENABLE_SPARKPLUG
  delete baseline_batch_compiler_;
  baseline_batch_compiler_ = nullptr;
#endif  // V8_ENABLE_SPARKPLUG

#ifdef V8_ENABLE_MAGLEV
  delete maglev_concurrent_dispatcher_;
  maglev_concurrent_dispatcher_ = nullptr;
#endif  // V8_ENABLE_MAGLEV

  if (lazy_compile_dispatcher_) {
    lazy_compile_dispatcher_->AbortAll();
    lazy_compile_dispatcher_.reset();
  }

  // At this point there are no more background threads left in this isolate.
  heap_.safepoint()->AssertMainThreadIsOnlyThread();

  // Tear down data that requires the shared heap before detaching.
  heap_.TearDownWithSharedHeap();
  DumpAndResetBuiltinsProfileData();

  // Detach from the shared heap isolate and then unlock the mutex.
  if (has_shared_space() && !is_shared_space_isolate()) {
    GlobalSafepoint* global_safepoint =
        this->shared_space_isolate()->global_safepoint();
    global_safepoint->RemoveClient(this);
    global_safepoint->clients_mutex_.Unlock();
  }

  shared_space_isolate_.reset();

  // Since there are no other threads left, we can lock this mutex without any
  // ceremony. This signals to the tear down code that we are in a safepoint.
  base::RecursiveMutexGuard safepoint(&heap_.safepoint()->local_heaps_mutex_);

  ReleaseSharedPtrs();

  builtins_.TearDown();
  bootstrapper_->TearDown();

  if (tiering_manager_ != nullptr) {
    delete tiering_manager_;
    tiering_manager_ = nullptr;
  }

  delete heap_profiler_;
  heap_profiler_ = nullptr;

#if USE_SIMULATOR
  delete simulator_data_;
  simulator_data_ = nullptr;
#endif

  // After all concurrent tasks are stopped, we know for sure that stats aren't
  // updated anymore.
  DumpAndResetStats();

  heap_.TearDown();
  ReadOnlyHeap::TearDown(this);

  delete inner_pointer_to_code_cache_;
  inner_pointer_to_code_cache_ = nullptr;

  main_thread_local_isolate_.reset();

  FILE* logfile = v8_file_logger_->TearDownAndGetLogFile();
  if (logfile != nullptr) base::Fclose(logfile);

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
  if (v8_flags.enable_etw_stack_walking) {
    ETWJITInterface::RemoveIsolate(this);
  }
#endif  // defined(V8_OS_WIN)

#if V8_ENABLE_WEBASSEMBLY
  wasm::GetWasmEngine()->RemoveIsolate(this);

  delete wasm_code_look_up_cache_;
  wasm_code_look_up_cache_ = nullptr;
#endif  // V8_ENABLE_WEBASSEMBLY

  TearDownEmbeddedBlob();

  delete interpreter_;
  interpreter_ = nullptr;

  delete ast_string_constants_;
  ast_string_constants_ = nullptr;

  delete logger_;
  logger_ = nullptr;

  delete root_index_map_;
  root_index_map_ = nullptr;

  delete compiler_zone_;
  compiler_zone_ = nullptr;
  compiler_cache_ = nullptr;

  SetCodePages(nullptr);

  ClearSerializerData();

  if (OwnsStringTables()) {
    string_forwarding_table()->TearDown();
  } else {
    DCHECK_NULL(string_table_.get());
    DCHECK_NULL(string_forwarding_table_.get());
  }

  if (!is_shared_space_isolate()) {
    DCHECK_NULL(shared_struct_type_registry_.get());
  }

#ifdef V8_COMPRESS_POINTERS
  external_pointer_table().TearDownSpace(
      heap()->young_external_pointer_space());
  external_pointer_table().TearDownSpace(heap()->old_external_pointer_space());
  external_pointer_table().DetachSpaceFromReadOnlySegment(
      heap()->read_only_external_pointer_space());
  external_pointer_table().TearDownSpace(
      heap()->read_only_external_pointer_space());
  external_pointer_table().TearDown();
  if (owns_shareable_data()) {
    shared_external_pointer_table().TearDownSpace(
        shared_external_pointer_space());
    shared_external_pointer_table().TearDown();
    delete isolate_data_.shared_external_pointer_table_;
    isolate_data_.shared_external_pointer_table_ = nullptr;
    delete shared_external_pointer_space_;
    shared_external_pointer_space_ = nullptr;
  }
  cpp_heap_pointer_table().TearDownSpace(heap()->cpp_heap_pointer_space());
  cpp_heap_pointer_table().TearDown();
#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
  trusted_pointer_table().TearDownSpace(heap()->trusted_pointer_space());
  trusted_pointer_table().TearDown();
  if (owns_shareable_data()) {
    shared_trusted_pointer_table().TearDownSpace(
        shared_trusted_pointer_space());
    shared_trusted_pointer_table().TearDown();
    delete isolate_data_.shared_trusted_pointer_table_;
    isolate_data_.shared_trusted_pointer_table_ = nullptr;
    delete shared_trusted_pointer_space_;
    shared_trusted_pointer_space_ = nullptr;
  }

  IsolateGroup::current()->code_pointer_table()->TearDownSpace(
      heap()->code_pointer_space());
#endif  // V8_ENABLE_SANDBOX
#ifdef V8_ENABLE_LEAPTIERING
  GetProcessWideJSDispatchTable()->TearDownSpace(
      heap()->js_dispatch_table_space());
#endif  // V8_ENABLE_LEAPTIERING

  {
    base::MutexGuard lock_guard(&thread_data_table_mutex_);
    thread_data_table_.RemoveAllThreads();
  }
}

void Isolate::SetIsolateThreadLocals(Isolate* isolate,
                                     PerIsolateThreadData* data) {
  Isolate::SetCurrent(isolate);
  g_current_per_isolate_thread_data_ = data;

#ifdef V8_COMPRESS_POINTERS_IN_MULTIPLE_CAGES
  V8HeapCompressionScheme::InitBase(isolate ? isolate->cage_base()
                                            : kNullAddress);
  IsolateGroup::set_current(isolate ? isolate->isolate_group() : nullptr);
#ifdef V8_EXTERNAL_CODE_SPACE
  ExternalCodeCompressionScheme::InitBase(isolate ? isolate->code_cage_base()
                                                  : kNullAddress);
#endif
#endif  // V8_COMPRESS_POINTERS_IN_MULTIPLE_CAGES

  if (isolate && isolate->main_thread_local_isolate()) {
    WriteBarrier::SetForThread(
        isolate->main_thread_local_heap()->marking_barrier());
  } else {
    WriteBarrier::SetForThread(nullptr);
  }
}

Isolate::~Isolate() {
  TRACE_ISOLATE(destructor);
  DCHECK_NULL(current_deoptimizer_);

  // The entry stack must be empty when we get here.
  DCHECK(entry_stack_ == nullptr ||
         entry_stack_.load()->previous_item == nullptr);

  delete entry_stack_;
  entry_stack_ = nullptr;

  delete date_cache_;
  date_cache_ = nullptr;

  delete regexp_stack_;
  regexp_stack_ = nullptr;

  delete descriptor_lookup_cache_;
  descriptor_lookup_cache_ = nullptr;

  delete load_stub_cache_;
  load_stub_cache_ = nullptr;
  delete store_stub_cache_;
  store_stub_cache_ = nullptr;
  delete define_own_stub_cache_;
  define_own_stub_cache_ = nullptr;

  delete materialized_object_store_;
  materialized_object_store_ = nullptr;

  delete v8_file_logger_;
  v8_file_logger_ = nullptr;

  delete handle_scope_implementer_;
  handle_scope_implementer_ = nullptr;

  delete code_tracer();
  set_code_tracer(nullptr);

  delete compilation_cache_;
  compilation_cache_ = nullptr;
  delete bootstrapper_;
  bootstrapper_ = nullptr;

  delete thread_manager_;
  thread_manager_ = nullptr;

  bigint_processor_->Destroy();

  delete global_handles_;
  global_handles_ = nullptr;
  delete eternal_handles_;
  eternal_handles_ = nullptr;

#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmEngine::FreeAllOrphanedGlobalHandles(wasm_orphaned_handle_);
#endif

  delete string_stream_debug_object_cache_;
  string_stream_debug_object_cache_ = nullptr;

  delete random_number_generator_;
  random_number_generator_ = nullptr;

  delete fuzzer_rng_;
  fuzzer_rng_ = nullptr;

  delete debug_;
  debug_ = nullptr;

  delete cancelable_task_manager_;
  cancelable_task_manager_ = nullptr;

  delete allocator_;
  allocator_ = nullptr;

  // Assert that |default_microtask_queue_| is the last MicrotaskQueue instance.
  DCHECK_IMPLIES(default_microtask_queue_,
                 default_microtask_queue_ == default_microtask_queue_->next());
  delete default_microtask_queue_;
  default_microtask_queue_ = nullptr;

#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmCodePointerTable* wasm_code_pointer_table =
      wasm::GetProcessWideWasmCodePointerTable();
  for (size_t i = 0; i < Builtins::kNumWasmIndirectlyCallableBuiltins; i++) {
    wasm_code_pointer_table->FreeEntry(wasm_builtin_code_handles_[i]);
  }
#endif

  // isolate_group_ released in caller, to ensure that all member destructors
  // run before potentially unmapping the isolate's VirtualMemoryArea.
}

void Isolate::InitializeThreadLocal() {
  thread_local_top()->Initialize(this);
#ifdef DEBUG
  // This method might be called on a thread that's not bound to any Isolate
  // and thus pointer compression schemes might have cage base value unset.
  // Read-only roots accessors contain type DCHECKs which require access to
  // V8 heap in order to check the object type. So, allow heap access here
  // to let the checks work.
  i::PtrComprCageAccessScope ptr_compr_cage_access_scope(this);
#endif  // DEBUG
  clear_exception();
  clear_pending_message();
}

void Isolate::SetTerminationOnExternalTryCatch() {
  DCHECK_IMPLIES(v8_flags.strict_termination_checks,
                 is_execution_terminating());
  if (try_catch_handler() == nullptr) return;
  try_catch_handler()->can_continue_ = false;
  try_catch_handler()->exception_ = reinterpret_cast<void*>(
      ReadOnlyRoots(heap()).termination_exception().ptr());
}

bool Isolate::PropagateExceptionToExternalTryCatch(
    ExceptionHandlerType top_handler) {
  Tagged<Object> exception = this->exception();

  if (top_handler == ExceptionHandlerType::kJavaScriptHandler) return false;
  if (top_handler == ExceptionHandlerType::kNone) return true;

  DCHECK_EQ(ExceptionHandlerType::kExternalTryCatch, top_handler);
  if (!is_catchable_by_javascript(exception)) {
    SetTerminationOnExternalTryCatch();
  } else {
    v8::TryCatch* handler = try_catch_handler();
    DCHECK(IsJSMessageObject(pending_message()) ||
           IsTheHole(pending_message(), this));
    handler->can_continue_ = true;
    handler->exception_ = reinterpret_cast<void*>(exception.ptr());
    // Propagate to the external try-catch only if we got an actual message.
    if (!has_pending_message()) return true;
    handler->message_obj_ = reinterpret_cast<void*>(pending_message().ptr());
  }
  return true;
}

namespace {

inline Tagged<FunctionTemplateInfo> GetTargetFunctionTemplateInfo(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  Tagged<Object> target = FunctionCallbackArguments::GetTarget(info);
  if (IsFunctionTemplateInfo(target)) {
    return Cast<FunctionTemplateInfo>(target);
  }
  CHECK(Is<JSFunction>(target));
  Tagged<SharedFunctionInfo> shared_info = Cast<JSFunction>(target)->shared();
  return shared_info->api_func_data();
}

}  // namespace

void Isolate::NotifyExceptionPropagationCallback() {
  DCHECK_NOT_NULL(exception_propagation_callback_);

  // Try to figure out whether the exception was thrown directly from an
  // Api callback and if it's the case then call the
  // |exception_propagation_callback_| with relevant data.

  ExternalCallbackScope* ext_callback_scope = external_callback_scope();
  StackFrameIterator it(this);

  if (it.done() && !ext_callback_scope) {
    // The exception was thrown directly by embedder code without crossing
    // "C++ -> JS" or "C++ -> Api callback" boundary.
    return;
  }
  if (it.done() ||
      (ext_callback_scope &&
       ext_callback_scope->JSStackComparableAddress() < it.frame()->fp())) {
    // There were no crossings of "C++ -> JS" boundary at all or they happened
    // earlier than the last crossing of the  "C++ -> Api callback" boundary.
    // In this case all the data about Api callback is available in the
    // |ext_callback_scope| object.
    DCHECK_NOT_NULL(ext_callback_scope);
    v8::ExceptionContext kind = ext_callback_scope->exception_context();
    switch (kind) {
      case v8::ExceptionContext::kConstructor:
      case v8::ExceptionContext::kOperation: {
        DCHECK_NOT_NULL(ext_callback_scope->callback_info());
        auto callback_info =
            reinterpret_cast<const v8::FunctionCallbackInfo<v8::Value>*>(
                ext_callback_scope->callback_info());

        DirectHandle<JSReceiver> receiver =
            Utils::OpenDirectHandle(*callback_info->This());
        DirectHandle<FunctionTemplateInfo> function_template_info(
            GetTargetFunctionTemplateInfo(*callback_info), this);
        ReportExceptionFunctionCallback(receiver, function_template_info, kind);
        return;
      }
      case v8::ExceptionContext::kAttributeGet:
      case v8::ExceptionContext::kAttributeSet:
      case v8::ExceptionContext::kIndexedQuery:
      case v8::ExceptionContext::kIndexedGetter:
      case v8::ExceptionContext::kIndexedDescriptor:
      case v8::ExceptionContext::kIndexedSetter:
      case v8::ExceptionContext::kIndexedDefiner:
      case v8::ExceptionContext::kIndexedDeleter:
      case v8::ExceptionContext::kNamedQuery:
      case v8::ExceptionContext::kNamedGetter:
      case v8::ExceptionContext::kNamedDescriptor:
      case v8::ExceptionContext::kNamedSetter:
      case v8::ExceptionContext::kNamedDefiner:
      case v8::ExceptionContext::kNamedDeleter:
      case v8::ExceptionContext::kNamedEnumerator: {
        DCHECK_NOT_NULL(ext_callback_scope->callback_info());
        auto callback_info =
            reinterpret_cast<const v8::PropertyCallbackInfo<v8::Value>*>(
                ext_callback_scope->callback_info());

        // Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
        // TODO(https://crbug.com/333672197): remove.
        START_ALLOW_USE_DEPRECATED()

        Handle<Object> holder = Utils::OpenHandle(*callback_info->Holder());
        Handle<Object> maybe_name =
            PropertyCallbackArguments::GetPropertyKeyHandle(*callback_info);
        Handle<Name> name =
            IsSmi(*maybe_name)
                ? factory()->SizeToString(
                      PropertyCallbackArguments::GetPropertyIndex(
                          *callback_info))
                : Cast<Name>(maybe_name);
        DCHECK(IsJSReceiver(*holder));

        // Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
        // TODO(https://crbug.com/333672197): remove.
        END_ALLOW_USE_DEPRECATED()

        // Currently we call only ApiGetters from JS code.
        ReportExceptionPropertyCallback(Cast<JSReceiver>(holder), name, kind);
        return;
      }

      case v8::ExceptionContext::kUnknown:
        DCHECK_WITH_MSG(kind != v8::ExceptionContext::kUnknown,
                        "ExternalCallbackScope should not use "
                        "v8::ExceptionContext::kUnknown exception context");
        return;
    }
    UNREACHABLE();
  }

  // There were no crossings of "C++ -> Api callback" bondary or they
  // happened before crossing the "C++ -> JS" boundary.
  // In this case all the data about Api callback is available in the
  // topmost "JS -> Api callback" frame (ApiCallbackExitFrame or
  // ApiAccessorExitFrame).
  DCHECK(!it.done());
  StackFrame::Type frame_type = it.frame()->type();
  switch (frame_type) {
    case StackFrame::API_CALLBACK_EXIT: {
      ApiCallbackExitFrame* frame = ApiCallbackExitFrame::cast(it.frame());
      DirectHandle<JSReceiver> receiver(Cast<JSReceiver>(frame->receiver()),
                                        this);
      DirectHandle<FunctionTemplateInfo> function_template_info =
          frame->GetFunctionTemplateInfo();

      v8::ExceptionContext callback_kind =
          frame->IsConstructor() ? v8::ExceptionContext::kConstructor
                                 : v8::ExceptionContext::kOperation;
      ReportExceptionFunctionCallback(receiver, function_template_info,
                                      callback_kind);
      return;
    }
    case StackFrame::API_ACCESSOR_EXIT: {
      ApiAccessorExitFrame* frame = ApiAccessorExitFrame::cast(it.frame());

      Handle<Object> holder(frame->holder(), this);
      Handle<Name> name(frame->property_name(), this);
      DCHECK(IsJSReceiver(*holder));

      // Currently we call only ApiGetters from JS code.
      ReportExceptionPropertyCallback(Cast<JSReceiver>(holder), name,
                                      v8::ExceptionContext::kAttributeGet);
      return;
    }
    case StackFrame::TURBOFAN_JS:
      // This must be a fast Api call.
      CHECK(it.frame()->InFastCCall());
      // TODO(ishell): support fast Api calls.
      return;
    case StackFrame::EXIT:
    case StackFrame::BUILTIN_EXIT:
      // This is a regular runtime function or C++ builtin.
      return;
#if V8_ENABLE_WEBASSEMBLY
    case StackFrame::WASM:
    case StackFrame::WASM_SEGMENT_START:
      // No more info.
      return;
#endif  // V8_ENABLE_WEBASSEMBLY
    default:
      // Other types are not expected, so just hard-crash.
      CHECK_NE(frame_type, frame_type);
  }
}

void Isolate::ReportExceptionFunctionCallback(
    DirectHandle<JSReceiver> receiver,
    DirectHandle<FunctionTemplateInfo> function,
    v8::ExceptionContext exception_context) {
  DCHECK(exception_context == v8::ExceptionContext::kConstructor ||
         exception_context == v8::ExceptionContext::kOperation);
  DCHECK_NOT_NULL(exception_propagation_callback_);

  // Ignore exceptions that we can't extend.
  if (!IsJSReceiver(this->exception())) return;
  Handle<JSReceiver> exception(Cast<JSReceiver>(this->exception()), this);

  DirectHandle<Object> maybe_message(pending_message(), this);

  Handle<String> property_name =
      IsUndefined(function->class_name(), this)
          ? factory()->empty_string()
          : Handle<String>(Cast<String>(function->class_name()), this);
  Handle<String> interface_name =
      IsUndefined(function->interface_name(), this)
          ? factory()->empty_string()
          : Handle<String>(Cast<String>(function->interface_name()), this);
  if (exception_context != ExceptionContext::kConstructor) {
    exception_context =
        static_cast<ExceptionContext>(function->exception_context());
  }

  {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(this);
    // Ignore any exceptions thrown inside the callback and rethrow the
    // original exception/message.
    TryCatch try_catch(v8_isolate);

    exception_propagation_callback_(v8::ExceptionPropagationMessage(
        v8_isolate, v8::Utils::ToLocal(exception),
        v8::Utils::ToLocal(interface_name), v8::Utils::ToLocal(property_name),
        exception_context));

    try_catch.Reset();
  }
  ReThrow(*exception, *maybe_message);
}

void Isolate::ReportExceptionPropertyCallback(
    Handle<JSReceiver> holder, Handle<Name> name,
    v8::ExceptionContext exception_context) {
  DCHECK_NOT_NULL(exception_propagation_callback_);

  if (!IsJSReceiver(this->exception())) return;
  Handle<JSReceiver> exception(Cast<JSReceiver>(this->exception()), this);

  DirectHandle<Object> maybe_message(pending_message(), this);

  Handle<String> property_name;
  std::ignore = Name::ToFunctionName(this, name).ToHandle(&property_name);
  Handle<String> interface_name = JSReceiver::GetConstructorName(this, holder);

  {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(this);
    // Ignore any exceptions thrown inside the callback and rethrow the
    // original exception/message.
    TryCatch try_catch(v8_isolate);

    exception_propagation_callback_(v8::ExceptionPropagationMessage(
        v8_isolate, v8::Utils::ToLocal(exception),
        v8::Utils::ToLocal(interface_name), v8::Utils::ToLocal(property_name),
        exception_context));

    try_catch.Reset();
  }
  ReThrow(*exception, *maybe_message);
}

void Isolate::SetExceptionPropagationCallback(
    ExceptionPropagationCallback callback) {
  exception_propagation_callback_ = callback;
}

bool Isolate::InitializeCounters() {
  if (async_counters_) return false;
  async_counters_ = std::make_shared<Counters>(this);
  return true;
}

void Isolate::InitializeLoggingAndCounters() {
  if (v8_file_logger_ == nullptr) {
    v8_file_logger_ = new V8FileLogger(this);
  }
  InitializeCounters();
}

namespace {

void FinalizeBuiltinCodeObjects(Isolate* isolate) {
  DCHECK_NOT_NULL(isolate->embedded_blob_code());
  DCHECK_NE(0, isolate->embedded_blob_code_size());
  DCHECK_NOT_NULL(isolate->embedded_blob_data());
  DCHECK_NE(0, isolate->embedded_blob_data_size());

  EmbeddedData d = EmbeddedData::FromBlob(isolate);
  HandleScope scope(isolate);
  static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    DirectHandle<Code> old_code = isolate->builtins()->code_handle(builtin);
    // Note that `old_code.instruction_start` might point to `old_code`'s
    // InstructionStream which might be GCed once we replace the old code
    // with the new code.
    Address instruction_start = d.InstructionStartOf(builtin);
    DirectHandle<Code> new_code =
        isolate->factory()->NewCodeObjectForEmbeddedBuiltin(old_code,
                                                            instruction_start);

    // From this point onwards, the old builtin code object is unreachable and
    // will be collected by the next GC.
    isolate->builtins()->set_code(builtin, *new_code);
  }
}

#ifdef DEBUG
bool IsolateIsCompatibleWithEmbeddedBlob(Isolate* isolate) {
  EmbeddedData d = EmbeddedData::FromBlob(isolate);
  return (d.IsolateHash() == isolate->HashIsolateForEmbeddedBlob());
}
#endif  // DEBUG

}  // namespace

void Isolate::InitializeDefaultEmbeddedBlob() {
  const uint8_t* code = DefaultEmbeddedBlobCode();
  uint32_t code_size = DefaultEmbeddedBlobCodeSize();
  const uint8_t* data = DefaultEmbeddedBlobData();
  uint32_t data_size = DefaultEmbeddedBlobDataSize();

  if (StickyEmbeddedBlobCode() != nullptr) {
    base::MutexGuard guard(current_embedded_blob_refcount_mutex_.Pointer());
    // Check again now that we hold the lock.
    if (StickyEmbeddedBlobCode() != nullptr) {
      code = StickyEmbeddedBlobCode();
      code_size = StickyEmbeddedBlobCodeSize();
      data = StickyEmbeddedBlobData();
      data_size = StickyEmbeddedBlobDataSize();
      current_embedded_blob_refs_++;
    }
  }

  if (code_size == 0) {
    CHECK_EQ(0, data_size);
  } else {
    SetEmbeddedBlob(code, code_size, data, data_size);
  }
}

void Isolate::CreateAndSetEmbeddedBlob() {
  base::MutexGuard guard(current_embedded_blob_refcount_mutex_.Pointer());

  PrepareBuiltinSourcePositionMap();

  // If a sticky blob has been set, we reuse it.
  if (StickyEmbeddedBlobCode() != nullptr) {
    CHECK_EQ(embedded_blob_code(), StickyEmbeddedBlobCode());
    CHECK_EQ(embedded_blob_data(), StickyEmbeddedBlobData());
    CHECK_EQ(CurrentEmbeddedBlobCode(), StickyEmbeddedBlobCode());
    CHECK_EQ(CurrentEmbeddedBlobData(), StickyEmbeddedBlobData());
  } else {
    // Create and set a new embedded blob.
    uint8_t* code;
    uint32_t code_size;
    uint8_t* data;
    uint32_t data_size;
    OffHeapInstructionStream::CreateOffHeapOffHeapInstructionStream(
        this, &code, &code_size, &data, &data_size);

    CHECK_EQ(0, current_embedded_blob_refs_);
    const uint8_t* const_code = const_cast<const uint8_t*>(code);
    const uint8_t* const_data = const_cast<const uint8_t*>(data);
    SetEmbeddedBlob(const_code, code_size, const_data, data_size);
    current_embedded_blob_refs_++;

    SetStickyEmbeddedBlob(code, code_size, data, data_size);
  }

  MaybeRemapEmbeddedBuiltinsIntoCodeRange();
  FinalizeBuiltinCodeObjects(this);
}

void Isolate::InitializeIsShortBuiltinCallsEnabled() {
  if (V8_SHORT_BUILTIN_CALLS_BOOL && v8_flags.short_builtin_calls) {
#if defined(V8_OS_ANDROID)
    // On Android, the check is not operative to detect memory, and re-embedded
    // builtins don't have a memory cost.
    is_short_builtin_calls_enabled_ = true;
#else
    // Check if the system has more than 4GB of physical memory by comparing the
    // old space size with respective threshold value.
    is_short_builtin_calls_enabled_ = (heap_.MaxOldGenerationSize() >=
                                       kShortBuiltinCallsOldSpaceSizeThreshold);
#endif  // defined(V8_OS_ANDROID)
    // Additionally, enable if there is already a process-wide CodeRange that
    // has re-embedded builtins.
    if (COMPRESS_POINTERS_BOOL) {
      CodeRange* code_range = isolate_group()->GetCodeRange();
      if (code_range && code_range->embedded_blob_code_copy() != nullptr) {
        is_short_builtin_calls_enabled_ = true;
      }
    }
    if (V8_ENABLE_NEAR_CODE_RANGE_BOOL) {
      // The short builtin calls could still be enabled if allocated code range
      // is close enough to embedded builtins so that the latter could be
      // reached using pc-relative (short) calls/jumps.
      is_short_builtin_calls_enabled_ |=
          GetShortBuiltinsCallRegion().contains(heap_.code_region());
    }
  }
}

void Isolate::MaybeRemapEmbeddedBuiltinsIntoCodeRange() {
  if (!is_short_builtin_calls_enabled() || !RequiresCodeRange()) {
    return;
  }
  if (V8_ENABLE_NEAR_CODE_RANGE_BOOL &&
      GetShortBuiltinsCallRegion().contains(heap_.code_region())) {
    // The embedded builtins are within the pc-relative reach from the code
    // range, so there's no need to remap embedded builtins.
    return;
  }

  CHECK_NOT_NULL(embedded_blob_code_);
  CHECK_NE(embedded_blob_code_size_, 0);

  DCHECK_NOT_NULL(heap_.code_range_);
  embedded_blob_code_ = 
"""


```
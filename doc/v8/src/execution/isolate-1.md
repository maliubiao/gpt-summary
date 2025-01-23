Response: The user wants me to summarize the functionality of the provided C++ code snippet from `v8/src/execution/isolate.cc`. This is the second part of a five-part file.

My plan is to:
1. **Read through the code:** Carefully examine each function and its logic.
2. **Identify key functionalities:** Determine the main actions performed by the code.
3. **Summarize the functionality:** Concisely describe what the code does.
4. **Check for JavaScript relevance:** Look for connections between the C++ code and JavaScript concepts.
5. **Provide a JavaScript example (if applicable):** Illustrate the connection with a concrete JavaScript code snippet.这是 `v8/src/execution/isolate.cc` 文件的第二部分，主要负责处理以下功能：

**核心功能总结:**

* **堆栈打印和错误报告:**  提供打印 JavaScript 堆栈跟踪信息的功能，包括详细模式。同时也处理在打印堆栈期间发生错误的情况（双重错误）。
* **访问检查回调:**  管理和调用失败的属性访问检查回调函数。
* **对象访问控制:**  实现 `MayAccess` 函数，用于判断一个上下文是否有权限访问某个对象，涉及到安全令牌和访问检查回调。
* **栈溢出处理:**  检测并处理 JavaScript 栈溢出错误，创建并抛出 `RangeError` 异常。
* **异常抛出机制:**  提供 `Throw` 函数，用于抛出 JavaScript 异常，并支持携带位置信息。同时也处理 `TerminateExecution` 用于终止执行。
* **中断请求:**  允许请求中断，并维护一个中断回调队列，并在适当的时候执行这些回调。
* **引导过程中的异常报告:**  在 V8 启动过程中捕获并报告异常信息，方便调试。
* **创建消息对象:**  提供 `CreateMessage` 和 `CreateMessageOrAbort` 函数，用于根据异常和位置信息创建消息对象，用于错误报告。`CreateMessageOrAbort` 还会检查 `abort_on_uncaught_exception` 标志，并在满足条件时中止程序。
* **重新抛出异常:**  提供 `ReThrow` 函数用于重新抛出已捕获的异常。
* **查找异常处理器:**  `UnwindAndFindHandler` 函数负责在栈上查找能够处理当前异常的处理器 (包括 JavaScript 的 try-catch 块和 WebAssembly 的异常处理)。
* **预测异常捕获:**  `PredictExceptionCatcher` 函数通过分析当前堆栈帧来预测异常是否会被 JavaScript 的 try-catch 块、Promise 的 reject handler 或者 async/await 捕获。
* **非法操作处理:**  `ThrowIllegalOperation` 用于抛出非法操作异常。
* **捕获和打印当前堆栈跟踪:**  `PrintCurrentStackTrace` 函数用于捕获并打印当前的 JavaScript 堆栈信息。
* **计算代码位置:**  提供多种 `ComputeLocation` 函数，用于根据当前执行状态或异常对象来计算代码的具体位置信息（脚本、行号、列号）。
* **报告未捕获的异常消息:**  `ReportPendingMessages` 函数负责将未捕获的异常消息报告给注册的消息处理器。
* **Promise 树的遍历:**  `WalkPromiseTreeInternal` 函数用于遍历 Promise 链，判断 Promise 的 rejection 是否最终被处理。

**与 JavaScript 的关系及示例:**

这个代码文件中的许多功能都直接关系到 JavaScript 的执行和错误处理：

1. **堆栈打印和错误报告:** 当 JavaScript 代码抛出异常时，V8 会调用 `Isolate::PrintStack` 来生成并输出堆栈跟踪信息。

   ```javascript
   function a() {
     b();
   }
   function b() {
     c();
   }
   function c() {
     throw new Error("Something went wrong");
   }
   try {
     a();
   } catch (e) {
     console.error(e.stack); // V8 内部会调用 Isolate::PrintStack 来生成这个 stack 字符串
   }
   ```

2. **访问检查回调:**  JavaScript 中可以使用 Proxy 的 `get` 和 `set` 陷阱，结合 `Object.preventExtensions` 等方法来控制属性访问。当访问被阻止时，可能会触发 V8 内部的访问检查回调。

   ```javascript
   const target = {};
   Object.preventExtensions(target);
   const proxy = new Proxy(target, {
     get: function(obj, prop) {
       if (!(prop in obj)) {
         throw new Error("Cannot access non-existent property");
       }
       return obj[prop];
     }
   });

   try {
     proxy.nonExistentProperty; // 这可能会触发 V8 内部的访问检查机制和回调
   } catch (e) {
     console.error(e.message);
   }
   ```

3. **栈溢出处理:** 当 JavaScript 代码调用栈过深时，V8 会检测到栈溢出，并调用 `Isolate::StackOverflow` 来抛出异常。

   ```javascript
   function recursiveFunction() {
     recursiveFunction();
   }
   try {
     recursiveFunction(); // 这会导致栈溢出
   } catch (e) {
     console.error(e.message); // e.message 可能会是 "Maximum call stack size exceeded"
   }
   ```

4. **异常抛出机制:** JavaScript 的 `throw` 语句最终会通过 V8 内部的机制（例如 `Isolate::Throw`）来处理。

   ```javascript
   function mightFail() {
     if (Math.random() < 0.5) {
       throw new Error("Operation failed!");
     }
     return "Operation succeeded.";
   }

   try {
     console.log(mightFail());
   } catch (e) {
     console.error(e.message);
   }
   ```

5. **中断请求:**  虽然 JavaScript 本身没有直接请求中断的 API，但在一些嵌入 V8 的环境或调试场景下，可以通过 V8 提供的 API (对应 `Isolate::RequestInterrupt`) 来触发 JavaScript 执行的中断。

6. **Promise 树的遍历:**  当有未处理的 Promise rejection 时，V8 内部可能会使用类似 `WalkPromiseTreeInternal` 的机制来查找是否最终有 `catch` 或 rejection handler 处理了该 Promise。

   ```javascript
   const myPromise = new Promise((resolve, reject) => {
     setTimeout(() => {
       reject(new Error("Promise rejected!"));
     }, 100);
   });

   // 如果没有 .catch 处理 myPromise，V8 可能会遍历 Promise 链来报告未处理的 rejection
   ```

总而言之，这段 C++ 代码是 V8 引擎实现 JavaScript 错误处理、异常管理和一些底层控制机制的关键部分。它直接影响了 JavaScript 运行时错误的行为和开发者所看到的错误信息。

### 提示词
```
这是目录为v8/src/execution/isolate.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```
sage(v8::Isolate::kErrorStackTraceLimit);
  }

  return true;
}

void Isolate::PrintStack(FILE* out, PrintStackMode mode) {
  if (stack_trace_nesting_level_ == 0) {
    stack_trace_nesting_level_++;
    StringStream::ClearMentionedObjectCache(this);
    HeapStringAllocator allocator;
    StringStream accumulator(&allocator);
    incomplete_message_ = &accumulator;
    PrintStack(&accumulator, mode);
    accumulator.OutputToFile(out);
    InitializeLoggingAndCounters();
    accumulator.Log(this);
    incomplete_message_ = nullptr;
    stack_trace_nesting_level_ = 0;
  } else if (stack_trace_nesting_level_ == 1) {
    stack_trace_nesting_level_++;
    base::OS::PrintError(
        "\n\nAttempt to print stack while printing stack (double fault)\n");
    base::OS::PrintError(
        "If you are lucky you may find a partial stack dump on stdout.\n\n");
    incomplete_message_->OutputToFile(out);
  }
}

static void PrintFrames(Isolate* isolate, StringStream* accumulator,
                        StackFrame::PrintMode mode) {
  StackFrameIterator it(isolate);
  for (int i = 0; !it.done(); it.Advance()) {
    it.frame()->Print(accumulator, mode, i++);
  }
}

void Isolate::PrintStack(StringStream* accumulator, PrintStackMode mode) {
  HandleScope scope(this);
  DCHECK(accumulator->IsMentionedObjectCacheClear(this));

  // Avoid printing anything if there are no frames.
  if (c_entry_fp(thread_local_top()) == 0) return;

  accumulator->Add(
      "\n==== JS stack trace =========================================\n\n");
  PrintFrames(this, accumulator, StackFrame::OVERVIEW);
  if (mode == kPrintStackVerbose) {
    accumulator->Add(
        "\n==== Details ================================================\n\n");
    PrintFrames(this, accumulator, StackFrame::DETAILS);
    accumulator->PrintMentionedObjectCache(this);
  }
  accumulator->Add("=====================\n\n");
}

void Isolate::SetFailedAccessCheckCallback(
    v8::FailedAccessCheckCallback callback) {
  thread_local_top()->failed_access_check_callback_ = callback;
}

MaybeHandle<Object> Isolate::ReportFailedAccessCheck(
    Handle<JSObject> receiver) {
  if (!thread_local_top()->failed_access_check_callback_) {
    THROW_NEW_ERROR(this, NewTypeError(MessageTemplate::kNoAccess));
  }

  DCHECK(IsAccessCheckNeeded(*receiver));
  DCHECK(!context().is_null());

  // Get the data object from access check info.
  HandleScope scope(this);
  Handle<Object> data;
  {
    DisallowGarbageCollection no_gc;
    Tagged<AccessCheckInfo> access_check_info =
        AccessCheckInfo::Get(this, receiver);
    if (access_check_info.is_null()) {
      no_gc.Release();
      THROW_NEW_ERROR(this, NewTypeError(MessageTemplate::kNoAccess));
    }
    data = handle(access_check_info->data(), this);
  }

  {
    // Leaving JavaScript.
    VMState<EXTERNAL> state(this);
    thread_local_top()->failed_access_check_callback_(
        v8::Utils::ToLocal(receiver), v8::ACCESS_HAS, v8::Utils::ToLocal(data));
  }
  RETURN_VALUE_IF_EXCEPTION(this, {});
  // Throw exception even the callback forgot to do so.
  THROW_NEW_ERROR(this, NewTypeError(MessageTemplate::kNoAccess));
}

bool Isolate::MayAccess(Handle<NativeContext> accessing_context,
                        Handle<JSObject> receiver) {
  DCHECK(IsJSGlobalProxy(*receiver) || IsAccessCheckNeeded(*receiver));

  // Check for compatibility between the security tokens in the
  // current lexical context and the accessed object.

  // During bootstrapping, callback functions are not enabled yet.
  if (bootstrapper()->IsActive()) return true;
  {
    DisallowGarbageCollection no_gc;

    if (IsJSGlobalProxy(*receiver)) {
      std::optional<Tagged<Object>> receiver_context =
          Cast<JSGlobalProxy>(*receiver)->GetCreationContext();
      if (!receiver_context) return false;

      if (*receiver_context == *accessing_context) return true;

      if (Cast<Context>(*receiver_context)->security_token() ==
          accessing_context->security_token())
        return true;
    }
  }

  HandleScope scope(this);
  Handle<Object> data;
  v8::AccessCheckCallback callback = nullptr;
  {
    DisallowGarbageCollection no_gc;
    Tagged<AccessCheckInfo> access_check_info =
        AccessCheckInfo::Get(this, receiver);
    if (access_check_info.is_null()) return false;
    Tagged<Object> fun_obj = access_check_info->callback();
    callback = v8::ToCData<v8::AccessCheckCallback, kApiAccessCheckCallbackTag>(
        this, fun_obj);
    data = handle(access_check_info->data(), this);
  }

  {
    // Leaving JavaScript.
    VMState<EXTERNAL> state(this);
    return callback(v8::Utils::ToLocal(accessing_context),
                    v8::Utils::ToLocal(receiver), v8::Utils::ToLocal(data));
  }
}

Tagged<Object> Isolate::StackOverflow() {
  // Whoever calls this method should not have overflown the stack limit by too
  // much. Otherwise we risk actually running out of stack space.
  // We allow for up to 8kB overflow, because we typically allow up to 4KB
  // overflow per frame in generated code, but might call through more smaller
  // frames until we reach this method.
  // If this DCHECK fails, one of the frames on the stack should be augmented by
  // an additional stack check.
#if defined(V8_USE_ADDRESS_SANITIZER) || defined(MEMORY_SANITIZER)
  // Allow for a bit more overflow in sanitizer builds, because C++ frames take
  // significantly more space there.
  DCHECK_GE(GetCurrentStackPosition(), stack_guard()->real_climit() - 64 * KB);
#elif (defined(V8_TARGET_ARCH_RISCV64) || defined(V8_TARGET_ARCH_RISCV32)) && \
    defined(USE_SIMULATOR)
  // Allow for more overflow on riscv simulator, because C++ frames take more
  // there.
  DCHECK_GE(GetCurrentStackPosition(), stack_guard()->real_climit() - 12 * KB);
#else
  DCHECK_GE(GetCurrentStackPosition(), stack_guard()->real_climit() - 8 * KB);
#endif

  if (v8_flags.correctness_fuzzer_suppressions) {
    FATAL("Aborting on stack overflow");
  }

  DisallowJavascriptExecution no_js(this);
  HandleScope scope(this);

  Handle<JSFunction> fun = range_error_function();
  DirectHandle<Object> msg = factory()->NewStringFromAsciiChecked(
      MessageFormatter::TemplateString(MessageTemplate::kStackOverflow));
  Handle<Object> options = factory()->undefined_value();
  Handle<Object> no_caller;
  Handle<JSObject> exception;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      this, exception,
      ErrorUtils::Construct(this, fun, fun, msg, options, SKIP_NONE, no_caller,
                            ErrorUtils::StackTraceCollection::kEnabled));
  JSObject::AddProperty(this, exception, factory()->wasm_uncatchable_symbol(),
                        factory()->true_value(), NONE);

  Throw(*exception);

#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap && v8_flags.stress_compaction) {
    heap()->CollectAllGarbage(GCFlag::kNoFlags,
                              GarbageCollectionReason::kTesting);
  }
#endif  // VERIFY_HEAP

  return ReadOnlyRoots(heap()).exception();
}

Tagged<Object> Isolate::ThrowAt(Handle<JSObject> exception,
                                MessageLocation* location) {
  Handle<Name> key_start_pos = factory()->error_start_pos_symbol();
  Object::SetProperty(this, exception, key_start_pos,
                      handle(Smi::FromInt(location->start_pos()), this),
                      StoreOrigin::kMaybeKeyed,
                      Just(ShouldThrow::kThrowOnError))
      .Check();

  Handle<Name> key_end_pos = factory()->error_end_pos_symbol();
  Object::SetProperty(this, exception, key_end_pos,
                      handle(Smi::FromInt(location->end_pos()), this),
                      StoreOrigin::kMaybeKeyed,
                      Just(ShouldThrow::kThrowOnError))
      .Check();

  Handle<Name> key_script = factory()->error_script_symbol();
  Object::SetProperty(this, exception, key_script, location->script(),
                      StoreOrigin::kMaybeKeyed,
                      Just(ShouldThrow::kThrowOnError))
      .Check();

  return Throw(*exception, location);
}

Tagged<Object> Isolate::TerminateExecution() {
  return Throw(ReadOnlyRoots(this).termination_exception());
}

void Isolate::CancelTerminateExecution() {
  if (!is_execution_terminating()) return;
  clear_internal_exception();
  if (try_catch_handler()) try_catch_handler()->ResetInternal();
}

void Isolate::RequestInterrupt(InterruptCallback callback, void* data) {
  ExecutionAccess access(this);
  api_interrupts_queue_.push(InterruptEntry(callback, data));
  stack_guard()->RequestApiInterrupt();
}

void Isolate::InvokeApiInterruptCallbacks() {
  RCS_SCOPE(this, RuntimeCallCounterId::kInvokeApiInterruptCallbacks);
  // Note: callback below should be called outside of execution access lock.
  while (true) {
    InterruptEntry entry;
    {
      ExecutionAccess access(this);
      if (api_interrupts_queue_.empty()) return;
      entry = api_interrupts_queue_.front();
      api_interrupts_queue_.pop();
    }
    VMState<EXTERNAL> state(this);
    HandleScope handle_scope(this);
    entry.first(reinterpret_cast<v8::Isolate*>(this), entry.second);
  }
}

void Isolate::RequestInvalidateNoProfilingProtector() {
  // This request might be triggered from arbitrary thread but protector
  // invalidation must happen on the main thread, so use Api interrupt
  // to achieve that.
  RequestInterrupt(
      [](v8::Isolate* isolate, void*) {
        Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
        if (Protectors::IsNoProfilingIntact(i_isolate)) {
          Protectors::InvalidateNoProfiling(i_isolate);
        }
      },
      nullptr);
}

namespace {

void ReportBootstrappingException(DirectHandle<Object> exception,
                                  MessageLocation* location) {
  base::OS::PrintError("Exception thrown during bootstrapping\n");
  if (location == nullptr || location->script().is_null()) return;
  // We are bootstrapping and caught an error where the location is set
  // and we have a script for the location.
  // In this case we could have an extension (or an internal error
  // somewhere) and we print out the line number at which the error occurred
  // to the console for easier debugging.
  int line_number =
      location->script()->GetLineNumber(location->start_pos()) + 1;
  if (IsString(*exception) && IsString(location->script()->name())) {
    base::OS::PrintError(
        "Extension or internal compilation error: %s in %s at line %d.\n",
        Cast<String>(*exception)->ToCString().get(),
        Cast<String>(location->script()->name())->ToCString().get(),
        line_number);
  } else if (IsString(location->script()->name())) {
    base::OS::PrintError(
        "Extension or internal compilation error in %s at line %d.\n",
        Cast<String>(location->script()->name())->ToCString().get(),
        line_number);
  } else if (IsString(*exception)) {
    base::OS::PrintError("Extension or internal compilation error: %s.\n",
                         Cast<String>(*exception)->ToCString().get());
  } else {
    base::OS::PrintError("Extension or internal compilation error.\n");
  }
#ifdef OBJECT_PRINT
  // Since comments and empty lines have been stripped from the source of
  // builtins, print the actual source here so that line numbers match.
  if (IsString(location->script()->source())) {
    DirectHandle<String> src(Cast<String>(location->script()->source()),
                             location->script()->GetIsolate());
    PrintF("Failing script:");
    int len = src->length();
    if (len == 0) {
      PrintF(" <not available>\n");
    } else {
      PrintF("\n");
      line_number = 1;
      PrintF("%5d: ", line_number);
      for (int i = 0; i < len; i++) {
        uint16_t character = src->Get(i);
        PrintF("%c", character);
        if (character == '\n' && i < len - 2) {
          PrintF("%5d: ", ++line_number);
        }
      }
      PrintF("\n");
    }
  }
#endif
}

}  // anonymous namespace

Handle<JSMessageObject> Isolate::CreateMessageOrAbort(
    Handle<Object> exception, MessageLocation* location) {
  Handle<JSMessageObject> message_obj = CreateMessage(exception, location);

  // If the abort-on-uncaught-exception flag is specified, and if the
  // embedder didn't specify a custom uncaught exception callback,
  // or if the custom callback determined that V8 should abort, then
  // abort.
  // Cache the flag on a static so that we can modify the value looked up below
  // in the presence of read-only flags.
  static bool abort_on_uncaught_exception =
      v8_flags.abort_on_uncaught_exception;
  if (abort_on_uncaught_exception) {
    CatchType prediction = PredictExceptionCatcher();
    if ((prediction == NOT_CAUGHT || prediction == CAUGHT_BY_EXTERNAL) &&
        (!abort_on_uncaught_exception_callback_ ||
         abort_on_uncaught_exception_callback_(
             reinterpret_cast<v8::Isolate*>(this)))) {
      // Prevent endless recursion.
      abort_on_uncaught_exception = false;
      // This flag is intended for use by JavaScript developers, so
      // print a user-friendly stack trace (not an internal one).
      PrintF(stderr, "%s\n\nFROM\n",
             MessageHandler::GetLocalizedMessage(this, message_obj).get());
      std::ostringstream stack_trace_stream;
      PrintCurrentStackTrace(stack_trace_stream);
      PrintF(stderr, "%s", stack_trace_stream.str().c_str());
      base::OS::Abort();
    }
  }

  return message_obj;
}

Tagged<Object> Isolate::Throw(Tagged<Object> raw_exception,
                              MessageLocation* location) {
  DCHECK(!has_exception());
  DCHECK_IMPLIES(IsHole(raw_exception),
                 raw_exception == ReadOnlyRoots{this}.termination_exception());
  IF_WASM(DCHECK_IMPLIES, trap_handler::IsTrapHandlerEnabled(),
          !trap_handler::IsThreadInWasm());

  HandleScope scope(this);
  Handle<Object> exception(raw_exception, this);

  if (v8_flags.print_all_exceptions) {
    PrintF("=========================================================\n");
    PrintF("Exception thrown:\n");
    if (location) {
      DirectHandle<Script> script = location->script();
      DirectHandle<Object> name(script->GetNameOrSourceURL(), this);
      PrintF("at ");
      if (IsString(*name) && Cast<String>(*name)->length() > 0) {
        Cast<String>(*name)->PrintOn(stdout);
      } else {
        PrintF("<anonymous>");
      }
// Script::GetLineNumber and Script::GetColumnNumber can allocate on the heap to
// initialize the line_ends array, so be careful when calling them.
#ifdef DEBUG
      if (AllowGarbageCollection::IsAllowed()) {
#else
      if ((false)) {
#endif
        Script::PositionInfo start_pos;
        Script::PositionInfo end_pos;
        Script::GetPositionInfo(script, location->start_pos(), &start_pos);
        Script::GetPositionInfo(script, location->end_pos(), &end_pos);
        PrintF(", %d:%d - %d:%d\n", start_pos.line + 1, start_pos.column + 1,
               end_pos.line + 1, end_pos.column + 1);
      } else {
        PrintF(", line %d\n", script->GetLineNumber(location->start_pos()) + 1);
      }
    }
    Print(*exception);
    PrintF("Stack Trace:\n");
    PrintStack(stdout);
    PrintF("=========================================================\n");
  }

  // Determine whether a message needs to be created for the given exception
  // depending on the following criteria:
  // 1) External v8::TryCatch missing: Always create a message because any
  //    JavaScript handler for a finally-block might re-throw to top-level.
  // 2) External v8::TryCatch exists: Only create a message if the handler
  //    captures messages or is verbose (which reports despite the catch).
  // 3) ReThrow from v8::TryCatch: The message from a previous throw still
  //    exists and we preserve it instead of creating a new message.
  bool requires_message = try_catch_handler() == nullptr ||
                          try_catch_handler()->is_verbose_ ||
                          try_catch_handler()->capture_message_;
  bool rethrowing_message = thread_local_top()->rethrowing_message_;

  thread_local_top()->rethrowing_message_ = false;

  // Notify debugger of exception.
  if (is_catchable_by_javascript(*exception)) {
    std::optional<Tagged<Object>> maybe_exception = debug()->OnThrow(exception);
    if (maybe_exception.has_value()) {
      return *maybe_exception;
    }
  }

  // Generate the message if required.
  if (requires_message && !rethrowing_message) {
    MessageLocation computed_location;
    // If no location was specified we try to use a computed one instead.
    if (location == nullptr && ComputeLocation(&computed_location)) {
      location = &computed_location;
    }
    if (bootstrapper()->IsActive()) {
      // It's not safe to try to make message objects or collect stack traces
      // while the bootstrapper is active since the infrastructure may not have
      // been properly initialized.
      ReportBootstrappingException(exception, location);
    } else {
      DirectHandle<Object> message_obj =
          CreateMessageOrAbort(exception, location);
      set_pending_message(*message_obj);
    }
  }

  // Set the exception being thrown.
  set_exception(*exception);
  PropagateExceptionToExternalTryCatch(TopExceptionHandlerType(*exception));

  if (v8_flags.experimental_report_exceptions_from_callbacks &&
      exception_propagation_callback_ && !rethrowing_message &&
      !preprocessing_exception_) {
    // Don't preprocess exceptions that might happen inside
    // |exception_propagation_callback_|.
    preprocessing_exception_ = true;
    NotifyExceptionPropagationCallback();
    preprocessing_exception_ = false;
  }
  return ReadOnlyRoots(heap()).exception();
}

Tagged<Object> Isolate::ReThrow(Tagged<Object> exception) {
  DCHECK(!has_exception());

  // Set the exception being re-thrown.
  set_exception(exception);
  return ReadOnlyRoots(heap()).exception();
}

Tagged<Object> Isolate::ReThrow(Tagged<Object> exception,
                                Tagged<Object> message) {
  DCHECK(!has_exception());
  DCHECK(!has_pending_message());

  set_pending_message(message);
  return ReThrow(exception);
}

namespace {
#if V8_ENABLE_WEBASSEMBLY
// This scope will set the thread-in-wasm flag after the execution of all
// destructors. The thread-in-wasm flag is only set when the scope gets enabled.
class SetThreadInWasmFlagScope {
 public:
  SetThreadInWasmFlagScope() {
    DCHECK_IMPLIES(trap_handler::IsTrapHandlerEnabled(),
                   !trap_handler::IsThreadInWasm());
  }

  ~SetThreadInWasmFlagScope() {
    if (enabled_) trap_handler::SetThreadInWasm();
  }

  void Enable() { enabled_ = true; }

 private:
  bool enabled_ = false;
};
#endif  // V8_ENABLE_WEBASSEMBLY
}  // namespace

Tagged<Object> Isolate::UnwindAndFindHandler() {
  // TODO(v8:12676): Fix gcmole failures in this function.
  DisableGCMole no_gcmole;
  DisallowGarbageCollection no_gc;

  // The topmost_script_having_context value becomes outdated after frames
  // unwinding.
  clear_topmost_script_having_context();

#if V8_ENABLE_WEBASSEMBLY
  // Create the {SetThreadInWasmFlagScope} first in this function so that its
  // destructor gets called after all the other destructors. It is important
  // that the destructor sets the thread-in-wasm flag after all other
  // destructors. The other destructors may cause exceptions, e.g. ASan on
  // Windows, which would invalidate the thread-in-wasm flag when the wasm trap
  // handler handles such non-wasm exceptions.
  SetThreadInWasmFlagScope set_thread_in_wasm_flag_scope;
#endif  // V8_ENABLE_WEBASSEMBLY
  Tagged<Object> exception = this->exception();

  auto FoundHandler = [&](Tagged<Context> context, Address instruction_start,
                          intptr_t handler_offset,
                          Address constant_pool_address, Address handler_sp,
                          Address handler_fp, int num_frames_above_handler) {
    // Store information to be consumed by the CEntry.
    thread_local_top()->pending_handler_context_ = context;
    thread_local_top()->pending_handler_entrypoint_ =
        instruction_start + handler_offset;
    thread_local_top()->pending_handler_constant_pool_ = constant_pool_address;
    thread_local_top()->pending_handler_fp_ = handler_fp;
    thread_local_top()->pending_handler_sp_ = handler_sp;
    thread_local_top()->num_frames_above_pending_handler_ =
        num_frames_above_handler;

    // Return and clear exception. The contract is that:
    // (1) the exception is stored in one place (no duplication), and
    // (2) within generated-code land, that one place is the return register.
    // If/when we unwind back into C++ (returning to the JSEntry stub,
    // or to Execution::CallWasm), the returned exception will be sent
    // back to isolate->set_exception(...).
    clear_internal_exception();
    return exception;
  };

#if V8_ENABLE_WEBASSEMBLY
  auto HandleStackSwitch = [&](StackFrameIterator& iter) {
    if (iter.wasm_stack() == nullptr) return;
    auto& switch_info = iter.wasm_stack()->stack_switch_info();
    if (!switch_info.has_value()) return;
    Tagged<Object> suspender_obj = root(RootIndex::kActiveSuspender);
    if (!IsUndefined(suspender_obj)) {
      // If the wasm-to-js wrapper was on a secondary stack and switched
      // to the central stack, handle the implicit switch back.
      if (switch_info.source_fp == iter.frame()->fp()) {
        thread_local_top()->is_on_central_stack_flag_ = false;
        stack_guard()->SetStackLimitForStackSwitching(
            reinterpret_cast<uintptr_t>(iter.wasm_stack()->jslimit()));
        iter.wasm_stack()->clear_stack_switch_info();
      }
    }
  };
#endif

  // Special handling of termination exceptions, uncatchable by JavaScript and
  // Wasm code, we unwind the handlers until the top ENTRY handler is found.
  bool catchable_by_js = is_catchable_by_javascript(exception);
  if (!catchable_by_js && !context().is_null()) {
    // Because the array join stack will not pop the elements when throwing the
    // uncatchable terminate exception, we need to clear the array join stack to
    // avoid leaving the stack in an invalid state.
    // See also CycleProtectedArrayJoin.
    raw_native_context()->set_array_join_stack(
        ReadOnlyRoots(this).undefined_value());
  }

  // Compute handler and stack unwinding information by performing a full walk
  // over the stack and dispatching according to the frame type.
  int visited_frames = 0;
  for (StackFrameIterator iter(this, thread_local_top(),
                               StackFrameIterator::NoHandles{});
       ; iter.Advance(), visited_frames++) {
#if V8_ENABLE_WEBASSEMBLY
    if (iter.frame()->type() == StackFrame::STACK_SWITCH) {
      if (catchable_by_js && iter.frame()->LookupCode()->builtin_id() !=
                                 Builtin::kJSToWasmStressSwitchStacksAsm) {
        Tagged<Code> code =
            builtins()->code(Builtin::kWasmReturnPromiseOnSuspendAsm);
        HandlerTable table(code);
        Address instruction_start =
            code->InstructionStart(this, iter.frame()->pc());
        int handler_offset = table.LookupReturn(0);
        return FoundHandler(Context(), instruction_start, handler_offset,
                            kNullAddress, iter.frame()->sp(),
                            iter.frame()->fp(), visited_frames);
      } else {
        // We reached the base of the wasm stack. Follow the chain of
        // continuations to find the parent stack and reset the iterator.
        wasm::StackMemory* stack =
            reinterpret_cast<wasm::StackMemory*>(iter.continuation()->stack());
        RetireWasmStack(stack);
        iter.Advance();
        wasm::StackMemory* parent =
            reinterpret_cast<wasm::StackMemory*>(iter.continuation()->stack());
        parent->jmpbuf()->state = wasm::JumpBuffer::Active;
        roots_table()
            .slot(RootIndex::kActiveContinuation)
            .store(iter.continuation());
        SyncStackLimit();
        continue;
      }
    }
#endif
    // Handler must exist.
    DCHECK(!iter.done());

    StackFrame* frame = iter.frame();

    // The debugger implements the "restart frame" feature by throwing a
    // terminate exception. Check and if we need to restart `frame`,
    // jump into the `RestartFrameTrampoline` builtin instead of
    // a catch handler.
    // Optimized frames take a detour via the deoptimizer before also jumping
    // to the `RestartFrameTrampoline` builtin.
    if (debug()->ShouldRestartFrame(frame->id())) {
      CancelTerminateExecution();
      CHECK(!catchable_by_js);
      CHECK(frame->is_javascript());

      if (frame->is_optimized_js()) {
        Tagged<Code> code = frame->LookupCode();
        // The debugger triggers lazy deopt for the "to-be-restarted" frame
        // immediately when the CDP event arrives while paused.
        CHECK(code->marked_for_deoptimization());
        set_deoptimizer_lazy_throw(true);

        // Jump directly to the optimized frames return, to immediately fall
        // into the deoptimizer.
        const int offset =
            static_cast<int>(frame->pc() - code->instruction_start());

        // Compute the stack pointer from the frame pointer. This ensures that
        // argument slots on the stack are dropped as returning would.
        // Note: Needed by the deoptimizer to rematerialize frames.
        Address return_sp = frame->fp() +
                            StandardFrameConstants::kFixedFrameSizeAboveFp -
                            code->stack_slots() * kSystemPointerSize;
        return FoundHandler(Context(), code->instruction_start(), offset,
                            code->constant_pool(), return_sp, frame->fp(),
                            visited_frames);
      }

      debug()->clear_restart_frame();
      Tagged<Code> code = *BUILTIN_CODE(this, RestartFrameTrampoline);
      return FoundHandler(Context(), code->instruction_start(), 0,
                          code->constant_pool(), kNullAddress, frame->fp(),
                          visited_frames);
    }

    switch (frame->type()) {
      case StackFrame::ENTRY:
      case StackFrame::CONSTRUCT_ENTRY: {
        // For JSEntry frames we always have a handler.
        StackHandler* handler = frame->top_handler();

        // Restore the next handler.
        thread_local_top()->handler_ = handler->next_address();

        // Gather information from the handler.
        Tagged<Code> code = frame->LookupCode();
        HandlerTable table(code);
        return FoundHandler(Context(),
                            code->InstructionStart(this, frame->pc()),
                            table.LookupReturn(0), code->constant_pool(),
                            handler->address() + StackHandlerConstants::kSize,
                            0, visited_frames);
      }

#if V8_ENABLE_WEBASSEMBLY
      case StackFrame::C_WASM_ENTRY: {
#if V8_ENABLE_DRUMBRAKE
        if (v8_flags.wasm_jitless) {
          StackHandler* handler = frame->top_handler();
          thread_local_top()->handler_ = handler->next_address();
          Tagged<Code> code =
              frame->LookupCode();  // WasmInterpreterCWasmEntry.

          HandlerTable table(code);
          Address instruction_start = code->InstructionStart(this, frame->pc());
          // Compute the stack pointer from the frame pointer. This ensures that
          // argument slots on the stack are dropped as returning would.
          Address return_sp = *reinterpret_cast<Address*>(
              frame->fp() + WasmInterpreterCWasmEntryConstants::kSPFPOffset);
          const int handler_offset = table.LookupReturn(0);
          if (trap_handler::IsThreadInWasm()) {
            trap_handler::ClearThreadInWasm();
          }
          return FoundHandler(Context(), instruction_start, handler_offset,
                              code->constant_pool(), return_sp, frame->fp(),
                              visited_frames);
        }
#endif  // V8_ENABLE_DRUMBRAKE

        StackHandler* handler = frame->top_handler();
        thread_local_top()->handler_ = handler->next_address();
        Tagged<Code> code = frame->LookupCode();
        HandlerTable table(code);
        Address instruction_start = code->instruction_start();
        int return_offset = static_cast<int>(frame->pc() - instruction_start);
        int handler_offset = table.LookupReturn(return_offset);
        DCHECK_NE(-1, handler_offset);
        // Compute the stack pointer from the frame pointer. This ensures that
        // argument slots on the stack are dropped as returning would.
        Address return_sp = frame->fp() +
                            StandardFrameConstants::kFixedFrameSizeAboveFp -
                            code->stack_slots() * kSystemPointerSize;
        return FoundHandler(Context(), instruction_start, handler_offset,
                            code->constant_pool(), return_sp, frame->fp(),
                            visited_frames);
      }

#if V8_ENABLE_DRUMBRAKE
      case StackFrame::WASM_INTERPRETER_ENTRY: {
        if (trap_handler::IsThreadInWasm()) {
          trap_handler::ClearThreadInWasm();
        }
      } break;
#endif  // V8_ENABLE_DRUMBRAKE

      case StackFrame::WASM:
      case StackFrame::WASM_SEGMENT_START: {
        if (!is_catchable_by_wasm(exception)) break;

        WasmFrame* wasm_frame = static_cast<WasmFrame*>(frame);
        wasm::WasmCode* wasm_code =
            wasm::GetWasmCodeManager()->LookupCode(this, frame->pc());
        int offset = wasm_frame->LookupExceptionHandlerInTable();
        if (offset < 0) break;
        // Compute the stack pointer from the frame pointer. This ensures that
        // argument slots on the stack are dropped as returning would.
        // The stack slot count needs to be adjusted for Liftoff frames. It has
        // two components: the fixed frame slots, and the maximum number of
        // registers pushed on top of the frame in out-of-line code. We know
        // that we are not currently in an OOL call, because OOL calls don't
        // have exception handlers. So we subtract the OOL spill count from the
        // total stack slot count to compute the actual frame size:
        int stack_slots = wasm_code->stack_slots() - wasm_code->ool_spills();
        Address return_sp = frame->fp() +
                            StandardFrameConstants::kFixedFrameSizeAboveFp -
                            stack_slots * kSystemPointerSize;

#if V8_ENABLE_DRUMBRAKE
        // Transitioning from JS To Wasm.
        if (v8_flags.wasm_enable_exec_time_histograms &&
            v8_flags.slow_histograms && !v8_flags.wasm_jitless) {
          // Start measuring the time spent running Wasm for jitted Wasm.
          wasm_execution_timer()->Start();
        }
#endif  // V8_ENABLE_DRUMBRAKE

        // This is going to be handled by WebAssembly, so we need to set the TLS
        // flag. The {SetThreadInWasmFlagScope} will set the flag after all
        // destructors have been executed.
        set_thread_in_wasm_flag_scope.Enable();
        return FoundHandler(Context(), wasm_code->instruction_start(), offset,
                            wasm_code->constant_pool(), return_sp, frame->fp(),
                            visited_frames);
      }

      case StackFrame::WASM_LIFTOFF_SETUP: {
        // The WasmLiftoffFrameSetup builtin doesn't throw, and doesn't call
        // out to user code that could throw.
        UNREACHABLE();
      }
      case StackFrame::WASM_TO_JS:
      case StackFrame::WASM_TO_JS_FUNCTION: {
        HandleStackSwitch(iter);
        break;
      }
#endif  // V8_ENABLE_WEBASSEMBLY

      case StackFrame::MAGLEV:
      case StackFrame::TURBOFAN_JS: {
        // For optimized frames we perform a lookup in the handler table.
        if (!catchable_by_js) break;
        OptimizedJSFrame* opt_frame = static_cast<OptimizedJSFrame*>(frame);
        int offset = opt_frame->LookupExceptionHandlerInTable(nullptr, nullptr);
        if (offset < 0) break;
        // The code might be an optimized code or a turbofanned builtin.
        Tagged<Code> code = frame->LookupCode();
        // Compute the stack pointer from the frame pointer. This ensures
        // that argument slots on the stack are dropped as returning would.
        Address return_sp = frame->fp() +
                            StandardFrameConstants::kFixedFrameSizeAboveFp -
                            code->stack_slots() * kSystemPointerSize;

        // TODO(bmeurer): Turbofanned BUILTIN frames appear as TURBOFAN_JS,
        // but do not have a code kind of TURBOFAN_JS.
        if (CodeKindCanDeoptimize(code->kind()) &&
            code->marked_for_deoptimization()) {
          // If the target code is lazy deoptimized, we jump to the original
          // return address, but we make a note that we are throwing, so
          // that the deoptimizer can do the right thing.
          offset = static_cast<int>(frame->pc() - code->instruction_start());
          set_deoptimizer_lazy_throw(true);
        }

        return FoundHandler(
            Context(), code->InstructionStart(this, frame->pc()), offset,
            code->constant_pool(), return_sp, frame->fp(), visited_frames);
      }

      case StackFrame::STUB: {
#if V8_ENABLE_WEBASSEMBLY
        HandleStackSwitch(iter);
#endif
        // Some stubs are able to handle exceptions.
        if (!catchable_by_js) break;
        StubFrame* stub_frame = static_cast<StubFrame*>(frame);
#if V8_ENABLE_WEBASSEMBLY
        DCHECK_NULL(wasm::GetWasmCodeManager()->LookupCode(this, frame->pc()));
#endif  // V8_ENABLE_WEBASSEMBLY

        // The code might be a dynamically generated stub or a turbofanned
        // embedded builtin.
        Tagged<Code> code = stub_frame->LookupCode();
        if (!code->is_turbofanned() || !code->has_handler_table()) {
          break;
        }

        int offset = stub_frame->LookupExceptionHandlerInTable();
        if (offset < 0) break;

        // Compute the stack pointer from the frame pointer. This ensures
        // that argument slots on the stack are dropped as returning would.
        Address return_sp = frame->fp() +
                            StandardFrameConstants::kFixedFrameSizeAboveFp -
                            code->stack_slots() * kSystemPointerSize;

        return FoundHandler(
            Context(), code->InstructionStart(this, frame->pc()), offset,
            code->constant_pool(), return_sp, frame->fp(), visited_frames);
      }

      case StackFrame::INTERPRETED:
      case StackFrame::BASELINE: {
        // For interpreted frame we perform a range lookup in the handler table.
        if (!catchable_by_js) break;
        UnoptimizedJSFrame* js_frame = UnoptimizedJSFrame::cast(frame);
        int register_slots = UnoptimizedFrameConstants::RegisterStackSlotCount(
            js_frame->GetBytecodeArray()->register_count());
        int context_reg = 0;  // Will contain register index holding context.
        int offset =
            js_frame->LookupExceptionHandlerInTable(&context_reg, nullptr);
        if (offset < 0) break;
        // Compute the stack pointer from the frame pointer. This ensures that
        // argument slots on the stack are dropped as returning would.
        // Note: This is only needed for interpreted frames that have been
        //       materialized by the deoptimizer. If there is a handler frame
        //       in between then {frame->sp()} would already be correct.
        Address return_sp = frame->fp() -
                            InterpreterFrameConstants::kFixedFrameSizeFromFp -
                            register_slots * kSystemPointerSize;

        // Patch the bytecode offset in the interpreted frame to reflect the
        // position of the exception handler. The special builtin below will
        // take care of continuing to dispatch at that position. Also restore
        // the correct context for the handler from the interpreter register.
        Tagged<Context> context =
            Cast<Context>(js_frame->ReadInterpreterRegister(context_reg));
        DCHECK(IsContext(context));

        if (frame->is_baseline()) {
          BaselineFrame* sp_frame = BaselineFrame::cast(js_frame);
          Tagged<Code> code = sp_frame->LookupCode();
          intptr_t pc_offset = sp_frame->GetPCForBytecodeOffset(offset);
          // Patch the context register directly on the frame, so that we don't
          // need to have a context read + write in the baseline code.
          sp_frame->PatchContext(context);
          return FoundHandler(Context(), code->instruction_start(), pc_offset,
                              code->constant_pool(), return_sp, sp_frame->fp(),
                              visited_frames);
        } else {
          InterpretedFrame::cast(js_frame)->PatchBytecodeOffset(
              static_cast<int>(offset));

          Tagged<Code> code = *BUILTIN_CODE(this, InterpreterEnterAtBytecode);
          // We subtract a frame from visited_frames because otherwise the
          // shadow stack will drop the underlying interpreter entry trampoline
          // in which the handler runs.
          //
          // An interpreted frame cannot be the first frame we look at
          // because at a minimum, an exit frame into C++ has to separate
          // it and the context in which this C++ code runs.
          CHECK_GE(visited_frames, 1);
          return FoundHandler(context, code->instruction_start(), 0,
                              code->constant_pool(), return_sp, frame->fp(),
                              visited_frames - 1);
        }
      }

      case StackFrame::BUILTIN:
        // For builtin frames we are guaranteed not to find a handler.
        if (catchable_by_js) {
          CHECK_EQ(-1, BuiltinFrame::cast(frame)->LookupExceptionHandlerInTable(
                           nullptr, nullptr));
        }
        break;

      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH: {
        // Builtin continuation frames with catch can handle exceptions.
        if (!catchable_by_js) break;
        JavaScriptBuiltinContinuationWithCatchFrame* js_frame =
            JavaScriptBuiltinContinuationWithCatchFrame::cast(frame);
        js_frame->SetException(exception);

        // Reconstruct the stack pointer from the frame pointer.
        Address return_sp = js_frame->fp() - js_frame->GetSPToFPDelta();
        Tagged<Code> code = js_frame->LookupCode();
        return FoundHandler(Context(), code->instruction_start(), 0,
                            code->constant_pool(), return_sp, frame->fp(),
                            visited_frames);
      }

      default:
        // All other types can not handle exception.
        break;
    }

    if (frame->is_optimized_js()) {
      // Remove per-frame stored materialized objects.
      bool removed = materialized_object_store_->Remove(frame->fp());
      USE(removed);
      // If there were any materialized objects, the code should be
      // marked for deopt.
      DCHECK_IMPLIES(removed, frame->LookupCode()->marked_for_deoptimization());
    }
  }

  UNREACHABLE();
}  // namespace internal

namespace {

class StackFrameSummaryIterator {
 public:
  explicit StackFrameSummaryIterator(Isolate* isolate)
      : stack_iterator_(isolate), summaries_(), index_(0) {
    InitSummaries();
  }
  void Advance() {
    if (index_ == 0) {
      summaries_.clear();
      stack_iterator_.Advance();
      InitSummaries();
    } else {
      index_--;
    }
  }
  bool done() const { return stack_iterator_.done(); }
  StackFrame* frame() const { return stack_iterator_.frame(); }
  bool has_frame_summary() const { return index_ < summaries_.size(); }
  const FrameSummary& frame_summary() const {
    DCHECK(has_frame_summary());
    return summaries_[index_];
  }
  Isolate* isolate() const { return stack_iterator_.isolate(); }

 private:
  void InitSummaries() {
    if (!done() && frame()->is_javascript()) {
      JavaScriptFrame::cast(frame())->Summarize(&summaries_);
      DCHECK_GT(summaries_.size(), 0);
      index_ = summaries_.size() - 1;
    }
  }
  StackFrameIterator stack_iterator_;
  std::vector<FrameSummary> summaries_;
  size_t index_;
};

HandlerTable::CatchPrediction CatchPredictionFor(Builtin builtin_id) {
  switch (builtin_id) {
#define CASE(Name)       \
  case Builtin::k##Name: \
    return HandlerTable::PROMISE;
    BUILTIN_PROMISE_REJECTION_PREDICTION_LIST(CASE)
#undef CASE
    default:
      return HandlerTable::UNCAUGHT;
  }
}

HandlerTable::CatchPrediction PredictExceptionFromBytecode(
    Tagged<BytecodeArray> bytecode, int code_offset) {
  HandlerTable table(bytecode);
  int handler_index = table.LookupHandlerIndexForRange(code_offset);
  if (handler_index < 0) return HandlerTable::UNCAUGHT;
  return table.GetRangePrediction(handler_index);
}

HandlerTable::CatchPrediction PredictException(const FrameSummary& summary,
                                               Isolate* isolate) {
  if (!summary.IsJavaScript()) {
    // This can happen when WASM is inlined by TurboFan. For now we ignore
    // frames that are not JavaScript.
    // TODO(https://crbug.com/349588762): We should also check Wasm code
    // for exception handling.
    return HandlerTable::UNCAUGHT;
  }
  PtrComprCageBase cage_base(isolate);
  DirectHandle<AbstractCode> code = summary.AsJavaScript().abstract_code();
  if (code->kind(cage_base) == CodeKind::BUILTIN) {
    return CatchPredictionFor(code->GetCode()->builtin_id());
  }

  // Must have been constructed from a bytecode array.
  CHECK_EQ(CodeKind::INTERPRETED_FUNCTION, code->kind(cage_base));
  return PredictExceptionFromBytecode(code->GetBytecodeArray(),
                                      summary.code_offset());
}

HandlerTable::CatchPrediction PredictExceptionFromGenerator(
    DirectHandle<JSGeneratorObject> generator, Isolate* isolate) {
  return PredictExceptionFromBytecode(
      generator->function()->shared()->GetBytecodeArray(isolate),
      GetGeneratorBytecodeOffset(generator));
}

Isolate::CatchType ToCatchType(HandlerTable::CatchPrediction prediction) {
  switch (prediction) {
    case HandlerTable::UNCAUGHT:
      return Isolate::NOT_CAUGHT;
    case HandlerTable::CAUGHT:
      return Isolate::CAUGHT_BY_JAVASCRIPT;
    case HandlerTable::PROMISE:
      return Isolate::CAUGHT_BY_PROMISE;
    case HandlerTable::UNCAUGHT_ASYNC_AWAIT:
    case HandlerTable::ASYNC_AWAIT:
      return Isolate::CAUGHT_BY_ASYNC_AWAIT;
    default:
      UNREACHABLE();
  }
}

Isolate::CatchType PredictExceptionCatchAtFrame(
    const StackFrameSummaryIterator& iterator) {
  const StackFrame* frame = iterator.frame();
  switch (frame->type()) {
    case StackFrame::ENTRY:
    case StackFrame::CONSTRUCT_ENTRY: {
      Address external_handler =
          iterator.isolate()->thread_local_top()->try_catch_handler_address();
      Address entry_handler = frame->top_handler()->next_address();
      // The exception has been externally caught if and only if there is an
      // external handler which is on top of the top-most JS_ENTRY handler.
      if (external_handler != kNullAddress &&
          !iterator.isolate()->try_catch_handler()->IsVerbose()) {
        if (entry_handler == kNullAddress || entry_handler > external_handler) {
          return Isolate::CAUGHT_BY_EXTERNAL;
        }
      }
    } break;

    // For JavaScript frames we perform a lookup in the handler table.
    case StackFrame::INTERPRETED:
    case StackFrame::BASELINE:
    case StackFrame::TURBOFAN_JS:
    case StackFrame::MAGLEV:
    case StackFrame::BUILTIN: {
      DCHECK(iterator.has_frame_summary());
      return ToCatchType(
          PredictException(iterator.frame_summary(), iterator.isolate()));
    }

    case StackFrame::STUB: {
      Tagged<Code> code = *frame->LookupCode();
      if (code->kind() != CodeKind::BUILTIN || !code->has_handler_table() ||
          !code->is_turbofanned()) {
        break;
      }

      return ToCatchType(CatchPredictionFor(code->builtin_id()));
    }

    case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH: {
      Tagged<Code> code = *frame->LookupCode();
      return ToCatchType(CatchPredictionFor(code->builtin_id()));
    }

    default:
      // All other types can not handle exception.
      break;
  }
  return Isolate::NOT_CAUGHT;
}
}  // anonymous namespace

Isolate::CatchType Isolate::PredictExceptionCatcher() {
  if (TopExceptionHandlerType(Tagged<Object>()) ==
      ExceptionHandlerType::kExternalTryCatch) {
    return CAUGHT_BY_EXTERNAL;
  }

  // Search for an exception handler by performing a full walk over the stack.
  for (StackFrameSummaryIterator iter(this); !iter.done(); iter.Advance()) {
    Isolate::CatchType prediction = PredictExceptionCatchAtFrame(iter);
    if (prediction != NOT_CAUGHT) return prediction;
  }

  // Handler not found.
  return NOT_CAUGHT;
}

Tagged<Object> Isolate::ThrowIllegalOperation() {
  if (v8_flags.stack_trace_on_illegal) PrintStack(stdout);
  return Throw(ReadOnlyRoots(heap()).illegal_access_string());
}

void Isolate::PrintCurrentStackTrace(std::ostream& out) {
  DirectHandle<FixedArray> frames = CaptureSimpleStackTrace(
      this, FixedArray::kMaxLength, SKIP_NONE, factory()->undefined_value());

  IncrementalStringBuilder builder(this);
  for (int i = 0; i < frames->length(); ++i) {
    DirectHandle<CallSiteInfo> frame(Cast<CallSiteInfo>(frames->get(i)), this);
    SerializeCallSiteInfo(this, frame, &builder);
    if (i != frames->length() - 1) builder.AppendCharacter('\n');
  }

  DirectHandle<String> stack_trace = builder.Finish().ToHandleChecked();
  stack_trace->PrintOn(out);
}

bool Isolate::ComputeLocation(MessageLocation* target) {
  DebuggableStackFrameIterator it(this);
  if (it.done()) return false;
    // Compute the location from the function and the relocation info of the
    // baseline code. For optimized code this will use the deoptimization
    // information to get canonical location information.
#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmCodeRefScope code_ref_scope;
#endif  // V8_ENABLE_WEBASSEMBLY
  FrameSummary summary = it.GetTopValidFrame();
  Handle<SharedFunctionInfo> shared;
  Handle<Object> script = summary.script();
  if (!IsScript(*script) ||
      IsUndefined(Cast<Script>(*script)->source(), this)) {
    return false;
  }

  if (summary.IsJavaScript()) {
    shared = handle(summary.AsJavaScript().function()->shared(), this);
  }
  if (summary.AreSourcePositionsAvailable()) {
    int pos = summary.SourcePosition();
    *target = MessageLocation(Cast<Script>(script), pos, pos + 1, shared);
  } else {
    *target =
        MessageLocation(Cast<Script>(script), shared, summary.code_offset());
  }
  return true;
}

bool Isolate::ComputeLocationFromException(MessageLocation* target,
                                           Handle<Object> exception) {
  if (!IsJSObject(*exception)) return false;

  Handle<Name> start_pos_symbol = factory()->error_start_pos_symbol();
  DirectHandle<Object> start_pos = JSReceiver::GetDataProperty(
      this, Cast<JSObject>(exception), start_pos_symbol);
  if (!IsSmi(*start_pos)) return false;
  int start_pos_value = Cast<Smi>(*start_pos).value();

  Handle<Name> end_pos_symbol = factory()->error_end_pos_symbol();
  DirectHandle<Object> end_pos = JSReceiver::GetDataProperty(
      this, Cast<JSObject>(exception), end_pos_symbol);
  if (!IsSmi(*end_pos)) return false;
  int end_pos_value = Cast<Smi>(*end_pos).value();

  Handle<Name> script_symbol = factory()->error_script_symbol();
  DirectHandle<Object> script = JSReceiver::GetDataProperty(
      this, Cast<JSObject>(exception), script_symbol);
  if (!IsScript(*script)) return false;

  Handle<Script> cast_script(Cast<Script>(*script), this);
  *target = MessageLocation(cast_script, start_pos_value, end_pos_value);
  return true;
}

bool Isolate::ComputeLocationFromSimpleStackTrace(MessageLocation* target,
                                                  Handle<Object> exception) {
  if (!IsJSReceiver(*exception)) {
    return false;
  }
  DirectHandle<FixedArray> call_site_infos =
      GetSimpleStackTrace(Cast<JSReceiver>(exception));
  for (int i = 0; i < call_site_infos->length(); ++i) {
    DirectHandle<CallSiteInfo> call_site_info(
        Cast<CallSiteInfo>(call_site_infos->get(i)), this);
    if (CallSiteInfo::ComputeLocation(call_site_info, target)) {
      return true;
    }
  }
  return false;
}

bool Isolate::ComputeLocationFromDetailedStackTrace(MessageLocation* target,
                                                    Handle<Object> exception) {
  if (!IsJSReceiver(*exception)) return false;

  Handle<StackTraceInfo> stack_trace =
      GetDetailedStackTrace(Cast<JSReceiver>(exception));
  if (stack_trace.is_null() || stack_trace->length() == 0) {
    return false;
  }

  DirectHandle<StackFrameInfo> info(stack_trace->get(0), this);
  const int pos = StackFrameInfo::GetSourcePosition(info);
  *target = MessageLocation(handle(info->script(), this), pos, pos + 1);
  return true;
}

Handle<JSMessageObject> Isolate::CreateMessage(Handle<Object> exception,
                                               MessageLocation* location) {
  Handle<StackTraceInfo> stack_trace;
  if (capture_stack_trace_for_uncaught_exceptions_) {
    if (IsJSObject(*exception)) {
      // First, check whether a stack trace is already present on this object.
      // It maybe an Error, or the embedder may have stored a stack trace using
      // Exception::CaptureStackTrace().
      // If the lookup fails, we fall through and capture the stack trace
      // at this throw site.
      stack_trace = GetDetailedStackTrace(Cast<JSObject>(exception));
    }
    if (stack_trace.is_null()) {
      // Not an error object, we capture stack and location at throw site.
      stack_trace = CaptureDetailedStackTrace(
          stack_trace_for_uncaught_exceptions_frame_limit_,
          stack_trace_for_uncaught_exceptions_options_);
    }
  }
  MessageLocation computed_location;
  if (location == nullptr &&
      (ComputeLocationFromException(&computed_location, exception) ||
       ComputeLocationFromSimpleStackTrace(&computed_location, exception) ||
       ComputeLocation(&computed_location))) {
    location = &computed_location;
  }

  return MessageHandler::MakeMessageObject(this,
                                           MessageTemplate::kUncaughtException,
                                           location, exception, stack_trace);
}

Handle<JSMessageObject> Isolate::CreateMessageFromException(
    Handle<Object> exception) {
  DirectHandle<StackTraceInfo> stack_trace;
  if (IsJSError(*exception)) {
    stack_trace = GetDetailedStackTrace(Cast<JSObject>(exception));
  }

  MessageLocation* location = nullptr;
  MessageLocation computed_location;
  if (ComputeLocationFromException(&computed_location, exception) ||
      ComputeLocationFromDetailedStackTrace(&computed_location, exception)) {
    location = &computed_location;
  }

  return MessageHandler::MakeMessageObject(this,
                                           MessageTemplate::kPlaceholderOnly,
                                           location, exception, stack_trace);
}

Isolate::ExceptionHandlerType Isolate::TopExceptionHandlerType(
    Tagged<Object> exception) {
  DCHECK_NE(ReadOnlyRoots(heap()).the_hole_value(), exception);

  Address js_handler = Isolate::handler(thread_local_top());
  Address external_handler = thread_local_top()->try_catch_handler_address();

  // A handler cannot be on top if it doesn't exist. For uncatchable exceptions,
  // the JavaScript handler cannot be on top.
  if (js_handler == kNullAddress || !is_catchable_by_javascript(exception)) {
    if (external_handler == kNullAddress) {
      return ExceptionHandlerType::kNone;
    }
    return ExceptionHandlerType::kExternalTryCatch;
  }

  if (external_handler == kNullAddress) {
    return ExceptionHandlerType::kJavaScriptHandler;
  }

  // The exception has been externally caught if and only if there is an
  // external handler which is on top of the top-most JS_ENTRY handler.
  //
  // Note, that finally clauses would re-throw an exception unless it's aborted
  // by jumps in control flow (like return, break, etc.) and we'll have another
  // chance to set proper v8::TryCatch later.
  DCHECK_NE(kNullAddress, external_handler);
  DCHECK_NE(kNullAddress, js_handler);
  if (external_handler < js_handler) {
    return ExceptionHandlerType::kExternalTryCatch;
  }
  return ExceptionHandlerType::kJavaScriptHandler;
}

std::vector<MemoryRange>* Isolate::GetCodePages() const {
  return code_pages_.load(std::memory_order_acquire);
}

void Isolate::SetCodePages(std::vector<MemoryRange>* new_code_pages) {
  code_pages_.store(new_code_pages, std::memory_order_release);
}

void Isolate::ReportPendingMessages(bool report) {
  Tagged<Object> exception_obj = exception();
  ExceptionHandlerType top_handler = TopExceptionHandlerType(exception_obj);

  // Try to propagate the exception to an external v8::TryCatch handler. If
  // propagation was unsuccessful, then we will get another chance at reporting
  // the pending message if the exception is re-thrown.
  bool has_been_propagated = PropagateExceptionToExternalTryCatch(top_handler);
  if (!has_been_propagated) return;
  if (!report) return;

  DCHECK(AllowExceptions::IsAllowed(this));

  // The embedder might run script in response to an exception.
  AllowJavascriptExecutionDebugOnly allow_script(this);

  // Clear the pending message object early to avoid endless recursion.
  Tagged<Object> message_obj = pending_message();
  clear_pending_message();

  // For uncatchable exceptions we do nothing. If needed, the exception and the
  // message have already been propagated to v8::TryCatch.
  if (!is_catchable_by_javascript(exception_obj)) return;

  // Determine whether the message needs to be reported to all message handlers
  // depending on whether the topmost external v8::TryCatch is verbose. We know
  // there's no JavaScript handler on top; if there was, we would've returned
  // early.
  DCHECK_NE(ExceptionHandlerType::kJavaScriptHandler, top_handler);

  bool should_report_exception;
  if (top_handler == ExceptionHandlerType::kExternalTryCatch) {
    should_report_exception = try_catch_handler()->is_verbose_;
  } else {
    should_report_exception = true;
  }

  // Actually report the pending message to all message handlers.
  if (!IsTheHole(message_obj, this) && should_report_exception) {
    HandleScope scope(this);
    DirectHandle<JSMessageObject> message(Cast<JSMessageObject>(message_obj),
                                          this);
    Handle<Script> script(message->script(), this);
    // Clear the exception and restore it afterwards, otherwise
    // CollectSourcePositions will abort.
    {
      ExceptionScope exception_scope(this);
      JSMessageObject::EnsureSourcePositionsAvailable(this, message);
    }
    int start_pos = message->GetStartPosition();
    int end_pos = message->GetEndPosition();
    MessageLocation location(script, start_pos, end_pos);
    MessageHandler::ReportMessage(this, &location, message);
  }
}

namespace {
bool ReceiverIsForwardingHandler(Isolate* isolate, Handle<JSReceiver> handler) {
  // Recurse to the forwarding Promise (e.g. return false) due to
  //  - await reaction forwarding to the throwaway Promise, which has
  //    a dependency edge to the outer Promise.
  //  - PromiseIdResolveHandler forwarding to the output of .then
  //  - Promise.all/Promise.race forwarding to a throwaway Promise, which
  //    has a dependency edge to the generated outer Promise.
  // Otherwise, this is a real reject handler for the Promise.
  Handle<Symbol> key = isolate->factory()->promise_forwarding_handler_symbol();
  DirectHandle<Object> forwarding_handler =
      JSReceiver::GetDataProperty(isolate, handler, key);
  return !IsUndefined(*forwarding_handler, isolate);
}

bool WalkPromiseTreeInternal(
    Isolate* isolate, Handle<JSPromise> promise,
    const std::function<void(Isolate::PromiseHandler)>& callback) {
  if (promise->status() != Promise::kPending) {
    // If a rejection reaches an exception that isn't pending, it will be
    // treated as caught.
    return true;
  }

  bool any_caught = false;
  bool any_uncaught = false;
  DirectHandle<Object> current(promise->reactions(), isolate);
  while (!IsSmi(*current)) {
    auto reaction = Cast<PromiseReaction>(current);
    Handle<HeapObject> promise_or_capability(reaction->promise_or_capability(),
                                             isolate);
    if (!IsUndefined(*promise_or_capability, isolate)) {
      if (!IsJSPromise(*promise_or_capability)) {
        promise_or_capability = handle(
            Cast<PromiseCapability>(promise_or_capability)->promise(), isolate);
      }
      if (IsJSPromise(*promise_or_capability)) {
        Handle<JSPromise> next_promise = Cast<JSPromise>(promise_or_capability);
        bool caught = false;
        Handle<JSReceiver> reject_handler;
        if (!IsUndefined(reaction->reject_handler(), isolate)) {
          reject_handler =
              handle(Cast<JSReceiver>(reaction->reject_handler()), isolate);
          if (!ReceiverIsForwardingHandler(isolate, reject_handler) &&
              !IsBuiltinForwardingRejectHandler(isolate, *reject_handler)) {
            caught = true;
          }
        }
        // Pass each handler to the callback
        Handle<JSGeneratorObject> async_function;
        if (TryGetAsyncGenerator(isolate, reaction).ToHandle(&async_function)) {
          caught = caught ||
                   PredictExceptionFromGenerator(async_function, isolate) ==
                       HandlerTable::CAUGHT;
          // Look at the async function, not the individual handlers
          callback({async_function->function()->shared(), true});
        } else {
          // Not an async function, look at individual handlers
          if (!IsUndefined(reaction->fulfill_handler(), isolate)) {
            Handle<JSReceiver> fulfill_handler(
                Cast<JSReceiver>(reaction->fulfill_handler()), isolate);
            if (!ReceiverIsForwardingHandler(isolate, fulfill_handler)) {
              if (IsBuiltinFunction(isolate, *fulfill_handler,
                                    Builtin::kPromiseThenFinally)) {
                // If this is the finally handler, get the wrapped callback
                // from the context to use instead
                DirectHandle<Context> context(
                    Cast<JSFunction>(reaction->fulfill_handler())->context(),
                    isolate);
                int const index =
                    PromiseBuiltins::PromiseFinallyContextSlot::kOnFinallySlot;
                fulfill_handler =
                    handle(Cast<JSReceiver>(context->get(index)), isolate);
              }
              if (IsJSFunction(*fulfill_handler)) {
                callback({Cast<JSFunction>(fulfill_handler)->shared(), true});
              }
            }
          }
          if (caught) {
            // We've already checked that this isn't undefined or
            // a forwarding handler
            if (IsJSFunction(*reject_handler)) {
              callback({Cast<JSFunction>(reject_handler)->shared(), true});
            }
          }
        }
        caught =
            caught || WalkPromiseTreeInternal(isolate, next_promise, callback);
        any_caught = any_caught || caught;
        any_uncaught = any_uncaught || !caught;
      }
    } else {
#if V8_ENABLE_WEBASSEMBLY
      Handle<WasmSuspenderObject> suspender;
      if (TryGetWasmSuspender(isolate, reaction->fulfill_handler())
              .ToHandle(&suspender)) {
        // If in the future we support Wasm exceptions or ignore listing in
        // Wasm, we will need to iterate through these frames. For now, we
        // only care about the resulting promise.
        Handle<JSPromise> next_promise = handle(suspender->promise(), isolate);
        bool caught = WalkPromiseTreeInternal(isolate, next_promise, callback);
        any_caught = any_caught || caught;
        any_uncaught = any_uncaught || !caught;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }
    current = direct_handle(reaction->next(), isolate);
  }

  bool caught = any_caught && !any_uncaught;

  if (!caught) {
    // If there is an outer promise, follow that to see if it is caught.
    Handle<Symbol> key = isolate->factory()->promise_handled_by_symbol();
    Handle<Object> outer_promise_obj =
        JSObject::GetDataProperty(isolate, promise, key);
    if (IsJSPromise(*outer_promise_obj)) {
      return WalkPromiseTreeInternal(
          isolate, Cast<JSPromise>(outer_promise_obj), callback);
    }
  }
  return caught;
}

// Helper functions to scan for calls to .catch.
using interpreter::Bytecode;
using interpreter::Bytecodes;

enum PromiseMethod { kThen, kCatch, kFinally, kInvalid };

// Requires the iterator to be on a GetNamedProperty instruction
PromiseMethod GetPromiseMethod(
    Isolate* isolate, const interpreter::BytecodeArrayIterator& iterator) {
  DirectHandle<Object> object = iterator.GetConstantForIndexOperand(1, isolate);
  if (!IsString(*object)) {
    return kInvalid;
  }
  auto str = Cast<String>(object);
  if (str->Equals(ReadOnlyRoots(isolate).then_string())) {
    return kThen;
  } else if (str->IsEqualTo(base::StaticCharVector("catch"))) {
    return kCatch;
  } else if (str->IsEqualTo(base::StaticCharVector("finally"))) {
    return kFinally;
  } else {
    return kInvalid;
  }
}

bool TouchesRegister(const interpreter::BytecodeArrayIterator& iterator,
                     int index) {
  Bytecode bytecode = iterator.current_bytecode();
  int num_operands = Bytecodes::NumberOfOperands(bytecode);
  const interpreter::OperandType* operand_types =
      Bytecodes::GetOperandTypes(bytecode);

  for (int i = 0; i < num_operands; ++i) {
    if (Bytecodes::IsRegisterOperandType(operand_types[i])) {
      int base_index = iterator.GetRegisterOperand(i).index();
      int num_registers;
      if (Bytecodes::IsRegisterListOperandType(operand_types[i])) {
        num_registers = iterator.GetRegisterCountOperand(++i);
      } else {
        num_registers =
            Bytecodes::GetNumberOfRegistersRepresentedBy(operand_types[i]);
      }

      if (base_index <= index && index < base_index + num_registers) {
        return true;
      }
    }
  }

  if (Bytecodes::WritesImplicitRegister(bytecode)) {
    return iterator.GetStarTargetRegister().index() == index;
  }

  return false;
}

bool CallsCatchMethod(Isolate* isolate, Handle<BytecodeArray> bytecode_array,
                      int offset) {
  interpreter::BytecodeArrayIterator iterator(bytecode_array, offset);

  while (!iterator.done()) {
    // We should be on a call instruction of some kind. While we could check
    // this, it may be difficult to create an exhaustive list of instructions
    // that could call, such as property getters, but at a minimum this
    // instruction should write to the accumulator.
    if (!Bytecodes::WritesAccumulator(iterator.current_bytecode())) {
      return false;
    }

    iterator.Advance();
    // While usually the next instruction is a Star, sometimes we store and
    // reload from context first.
    if (iterator.done()) {
      return false;
    }
    if (iterator.current_bytecode() == Bytecode::kStaCurrentContextSlot) {
      // Step over patterns like:
      //     StaCurrentContextSlot [x]
      //     LdaImmutableCurrentContextSlot [x]
      unsigned int slot = iterator.GetIndexOperand(0);
      iterator.Advance();
      if (!iterator.done() &&
          (iterator.current_bytecode() ==
               Bytecode::kLdaImmutableCurrentContextSlot ||
           iterator.current_bytecode() == Bytecode::kLdaCurrentContextSlot)) {
        if (iterator.GetIndexOperand(0) != slot) {
          return false;
        }
        iterator.Advance();
      }
    } else if (iterator.current_bytecode() == Bytecode::kStaContextSlot) {
      // Step over patterns like:
      //     StaContextSlot r_x [y] [z]
      //     LdaContextSlot r_x [y] [z]
      int context = iterator.GetRegisterOperand(0).index();
      unsigned int slot = iterator.GetIndexOperand(1);
      unsigned int depth = iterator.GetUnsignedImmediateOperand(2);
      iterator.Advance();
      if (!iterator.done() &&
          (iterator.current_bytecode() == Bytecode::kLdaImmutableContextSlot ||
           iterator.current_bytecode() == Bytecode::kLdaContextSlot)) {
        if (iterator.GetRegisterOperand(0).index() != context ||
            iterator.GetIndexOperand(1) != slot ||
            iterator.GetUnsignedImmediateOperand(2) != depth) {
          return false;
        }
        iterator.Advance();
      }
    } else if (iterator.current_bytecode() == Bytecode::kStaLookupSlot) {
      // Step over patterns like:
      //     StaLookupSlot [x] [_]
      //     LdaLookupSlot [x]
      unsigned int slot = iterator.GetIndexOperand(0);
      iterator.Advance();
      if (!iterator.done() &&
          (iterator.current_bytecode() == Bytecode::kLdaLookupSlot ||
           iterator.current_bytecode() ==
               Bytecode::kLdaLookupSlotInsideTypeof)) {
        if (iterator.GetIndexOperand(0) != slot) {
          return false;
        }
        iterator.Advance();
      }
    }

    // Next instruction should be a Star (store accumulator to register)
    if (iterator.done() || !Bytecodes::IsAnyStar(iterator.current_bytecode())) {
      return f
```
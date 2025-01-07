Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/execution/isolate.cc`. I need to identify the key actions and purposes of the functions within this excerpt.

Here's a breakdown of the code's functionality:

1. **Stack Tracing:**  The `PrintStack` functions are clearly responsible for generating and outputting stack traces. This involves iterating through stack frames and formatting the output.
2. **Failed Access Checks:** The `SetFailedAccessCheckCallback` and `ReportFailedAccessCheck` functions deal with handling scenarios where access to an object is denied. They allow for a custom callback to be executed in such situations.
3. **Access Control:** The `MayAccess` function implements logic for determining if access to an object is permitted, considering security tokens and custom access check callbacks.
4. **Stack Overflow Handling:** The `StackOverflow` function is invoked when the stack limit is exceeded. It creates and throws a `RangeError` exception.
5. **Exception Throwing:** The `ThrowAt` and `Throw` functions are responsible for raising exceptions. They can attach additional information like script location to the exception object.
6. **Execution Termination:** The `TerminateExecution` and `CancelTerminateExecution` functions handle the process of abruptly stopping script execution.
7. **Interrupts:** The `RequestInterrupt` and `InvokeApiInterruptCallbacks` functions provide a mechanism for scheduling and executing asynchronous operations.
8. **Bootstrapping Exceptions:** The `ReportBootstrappingException` function handles errors that occur during the V8 initialization phase.
9. **Message Creation:** The `CreateMessageOrAbort` function creates error messages associated with exceptions, potentially aborting execution based on flags.
10. **Unwinding the Stack for Exception Handling:** The `UnwindAndFindHandler` function is the core of V8's exception handling mechanism. It iterates through the stack frames to find the appropriate catch handler for a thrown exception.

Now, I need to address the specific requirements in the prompt:

*   **List Functionality:**  I've done this in the breakdown above.
*   **.tq Check:** The filename ends in `.cc`, so it's not a Torque file.
*   **JavaScript Relationship:**  The concepts of stack traces, access control (think proxies), and exception handling are directly related to JavaScript.
*   **JavaScript Example:** I can provide a simple example demonstrating a `TypeError` due to an access restriction, or a stack overflow.
*   **Code Logic Reasoning:**  The `UnwindAndFindHandler` function has complex logic. I can provide a simplified scenario and trace its execution.
*   **Common Programming Errors:**  Accessing properties on `null` or `undefined` can trigger access check failures (though not exactly the same scenario), and infinite recursion leads to stack overflows.
*   **Part of a Series:**  This is part 3 of 9. I need to synthesize the functionalities described in this part.

Overall Function Summary: This section of `isolate.cc` focuses on the core mechanisms for error handling and control flow within the V8 engine, including stack management, access control, and exception propagation.
这是 `v8/src/execution/isolate.cc` 源代码的第三部分，主要涉及以下功能：

**1. 打印调用栈 (Stack Tracing):**

*   `PrintStack(FILE* out, PrintStackMode mode)`:  这个函数是打印调用栈的入口。它处理嵌套打印的情况，使用 `StringStream` 来格式化输出，并将结果输出到指定的文件流。`PrintStackMode` 参数控制打印的详细程度。
*   `PrintStack(StringStream* accumulator, PrintStackMode mode)`:  这个函数执行实际的调用栈打印逻辑。它遍历当前的调用栈帧，并调用 `PrintFrames` 来格式化每个帧的信息。根据 `PrintStackMode` 的不同，可以打印概要信息或者详细信息，并打印引用的对象缓存。
*   `PrintFrames(Isolate* isolate, StringStream* accumulator, StackFrame::PrintMode mode)`:  这是一个静态辅助函数，用于遍历调用栈帧并调用每个帧的 `Print` 方法进行格式化输出。

**与 JavaScript 的关系:**

JavaScript 运行时错误（例如，未捕获的异常）会导致 V8 打印调用栈。这有助于开发者理解错误的发生位置和调用路径。

**JavaScript 示例:**

```javascript
function a() {
  b();
}

function b() {
  c();
}

function c() {
  throw new Error("Something went wrong!");
}

try {
  a();
} catch (e) {
  console.error(e.stack); // 这会调用 V8 的栈打印功能
}
```

**2. 失败的访问检查 (Failed Access Check):**

*   `SetFailedAccessCheckCallback(v8::FailedAccessCheckCallback callback)`:  允许用户设置一个回调函数，当访问被拒绝时会被调用。这通常用于实现对象访问控制的自定义逻辑。
*   `ReportFailedAccessCheck(Handle<JSObject> receiver)`:  当访问一个需要访问检查的对象时，如果检查失败，此函数会被调用。如果设置了回调函数，则调用该函数；否则，抛出一个 `TypeError`。

**与 JavaScript 的关系:**

这与 JavaScript 的代理 (Proxy) 功能有关。可以使用代理来拦截属性访问，并设置访问检查。

**JavaScript 示例:**

```javascript
const target = {};
const handler = {
  get(target, prop, receiver) {
    if (prop === 'sensitiveData') {
      // 模拟访问检查失败的情况
      throw new TypeError("Access denied to sensitive data.");
    }
    return Reflect.get(...arguments);
  }
};

const proxy = new Proxy(target, handler);

try {
  console.log(proxy.sensitiveData); // 这会触发 V8 的访问检查机制，并可能调用失败回调或抛出异常
} catch (e) {
  console.error(e);
}
```

**3. 访问权限检查 (Access Control):**

*   `MayAccess(Handle<NativeContext> accessing_context, Handle<JSObject> receiver)`:  检查一个上下文是否有权限访问一个对象。这涉及到检查安全令牌以及调用用户自定义的访问检查回调函数。

**与 JavaScript 的关系:**

这与 JavaScript 的安全模型有关，特别是跨域访问和模块隔离。

**4. 栈溢出处理 (Stack Overflow Handling):**

*   `StackOverflow()`: 当调用栈超出限制时被调用。它创建一个 `RangeError` 异常并抛出。

**与 JavaScript 的关系:**

JavaScript 中过深的函数调用（例如，无限递归）会导致栈溢出。

**JavaScript 示例 (导致栈溢出):**

```javascript
function recursiveFunction() {
  recursiveFunction();
}

try {
  recursiveFunction();
} catch (e) {
  console.error(e); // 会捕获一个 RangeError: Maximum call stack size exceeded
}
```

**5. 抛出异常 (Throwing Exceptions):**

*   `ThrowAt(Handle<JSObject> exception, MessageLocation* location)`: 抛出一个异常，并附带错误发生的位置信息（脚本、起始位置、结束位置）。
*   `Throw(Tagged<Object> raw_exception, MessageLocation* location)`:  实际抛出异常的函数。它处理打印异常信息、通知调试器、创建错误消息等。
*   `TerminateExecution()`: 抛出一个特殊的终止执行异常。
*   `CancelTerminateExecution()`: 取消终止执行的请求。
*   `ReThrow(Tagged<Object> exception)`: 重新抛出一个已捕获的异常。
*   `ReThrow(Tagged<Object> exception, Tagged<Object> message)`: 重新抛出一个异常，并附带一个消息对象。

**与 JavaScript 的关系:**

这些函数与 JavaScript 的 `throw` 语句和异常处理机制 (`try...catch`) 直接相关。

**6. 中断请求 (Interrupt Requests):**

*   `RequestInterrupt(InterruptCallback callback, void* data)`: 请求一个中断，并在稍后的某个安全时间点执行指定的回调函数。
*   `InvokeApiInterruptCallbacks()`:  执行所有待处理的 API 中断回调。

**与 JavaScript 的关系:**

这允许 V8 的嵌入器（例如，Node.js 或浏览器）在 JavaScript 执行过程中插入自定义操作。

**7. 无性能分析保护器的失效请求 (Request Invalidate No Profiling Protector):**

*   `RequestInvalidateNoProfilingProtector()`: 请求使“无性能分析”保护器失效。这通常用于在某些特定操作后，确保后续的代码可以被正常分析和优化。

**8. 引导阶段的异常报告 (Report Bootstrapping Exception):**

*   `ReportBootstrappingException(DirectHandle<Object> exception, MessageLocation* location)`:  在 V8 启动阶段发生错误时，打印错误信息到控制台。

**9. 创建错误消息 (Create Message):**

*   `CreateMessageOrAbort(Handle<Object> exception, MessageLocation* location)`: 创建一个与异常关联的错误消息对象。如果设置了 `abort_on_uncaught_exception` 标志，并且没有提供自定义的未捕获异常回调，则可能会中止执行。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 JavaScript 函数调用栈如下：

```
global -> a -> b -> c
```

并且在函数 `c` 中抛出了一个异常。

**输入:**  V8 内部状态，当前执行到函数 `c`，抛出一个新的 `Error("Test Error")`。

**输出:**  当调用 `PrintStack` 时，输出可能如下所示（具体格式取决于 `PrintStackMode`）：

```
==== JS stack trace =========================================

    at c (your_script.js:8:9)
    at b (your_script.js:4:3)
    at a (your_script.js:1:3)
    at <anonymous> (your_script.js:12:1)

=========================================================
```

**用户常见的编程错误:**

*   **无限递归导致栈溢出:**  如上面的 `recursiveFunction` 示例。
*   **尝试访问未定义或空对象的属性:** 虽然不是直接触发 `ReportFailedAccessCheck`，但会导致 `TypeError`，而 V8 的栈打印功能会帮助定位错误。
*   **违反安全策略，尝试访问受限资源:**  这可能导致访问检查失败，如果设置了回调，则会调用该回调。

**如果 `v8/src/execution/isolate.cc` 以 `.tq` 结尾:**

如果文件名是 `isolate.tq`，那么它将是一个 **Torque** 源代码文件。 Torque 是 V8 用来生成高效的 C++ 代码的领域特定语言，主要用于实现内置函数和运行时功能。

**归纳功能 (第 3 部分):**

这部分 `v8/src/execution/isolate.cc` 的主要功能是 **提供 V8 引擎中处理错误和控制流的关键机制**。 它涵盖了：

*   **错误报告和诊断:**  生成和打印详细的调用栈信息，帮助开发者调试错误。
*   **安全和访问控制:**  管理对象访问权限，允许嵌入器自定义访问检查逻辑。
*   **异常处理的核心机制:**  提供抛出、捕获和重新抛出异常的基础设施，包括处理栈溢出和终止执行的情况。
*   **异步操作支持:**  通过中断机制允许在 JavaScript 执行过程中插入和执行操作。

简单来说，这部分代码是 V8 引擎处理错误、保证安全和控制程序流程的重要组成部分。

Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共9部分，请归纳一下它的功能

"""
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
          // If the target code is lazy deoptimized, we jump to 
"""


```
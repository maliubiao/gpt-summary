Response:
The user wants a summary of the provided C++ code snippet from `v8/src/execution/isolate.cc`. The summary should cover the functionality of the code. I need to analyze the code and identify its main purpose and key operations.

Based on the code, it seems to be focused on capturing and building stack traces within the V8 engine. Key components include `CallSiteBuilder`, `FrameSummary`, and functions for appending different types of frames (JavaScript, WASM, Builtin, Async). The code also handles asynchronous stack traces by traversing Promise chains.

Here's a breakdown of the code's functionalities:

1. **`CallSiteBuilder` Class:** This class is responsible for constructing a stack trace by collecting information about individual stack frames.
    - It iterates through frames using `FrameSummary`.
    - It filters frames based on visibility (`IsVisibleInStackTrace`).
    - It appends different types of frames (JavaScript, WASM, Builtin, Async, Promise Combinator) using dedicated `Append...Frame` methods.
    - It handles strict mode frames to avoid exposing sensitive information.
    - It manages a fixed-size array to store frame information.
    - It has methods to check if it's full (`Full`) and to build the final `FixedArray` representing the stack trace (`Build`).

2. **`CaptureAsyncStackTrace` Functions:** These functions are designed to capture the asynchronous part of a stack trace by following the chain of Promises and AsyncGeneratorObjects.
    - They traverse the `PromiseReaction` objects associated with Promises.
    - They identify different types of asynchronous operations (async functions, async generators, Promise combinators).
    - They use `AppendAsyncFrame` and `AppendPromiseCombinatorFrame` to add asynchronous frames to the `CallSiteBuilder`.
    - `TryGetCurrentTaskPromise` attempts to get the Promise associated with the current microtask.

3. **`VisitStack` Function:** This template function iterates through the current stack frames and calls the `Visit` method of a provided visitor (like `CallSiteBuilder` or `StackFrameBuilder`). It filters frames based on security origins if requested.

4. **`CaptureSimpleStackTrace` Function:** This function orchestrates the capture of a simple stack trace using `CallSiteBuilder` and `VisitStack`. It also integrates the capture of asynchronous stack traces if enabled.

5. **`GetDetailedStackTraceFromCallSiteInfos` Function:** This function converts the call site information collected in a `FixedArray` into a more detailed `StackTraceInfo` object, which includes script information and source positions.

6. **`Isolate::CaptureAndSetErrorStack` Method:** This method is responsible for capturing both simple and detailed stack traces for an error object and setting the `stack` property on the error. It considers `Error.stackTraceLimit` and handles the case where the inspector requests more frames.

7. **`Isolate::GetDetailedStackTrace` and `Isolate::GetSimpleStackTrace` Methods:** These methods retrieve the detailed or simple stack trace from an error object.

8. **Helper Functions:**  Functions like `IsStrictFrame`, `IsVisibleInStackTrace`, `ShouldIncludeFrame`, and `IsNotHidden` are used for filtering and determining the visibility of stack frames.

Based on this analysis, I can now formulate a concise summary of the code's functionality.
这段代码是 `v8/src/execution/isolate.cc` 文件的一部分，主要负责**构建和捕获 JavaScript 代码的调用栈信息**。它是 V8 引擎中用于生成错误堆栈跟踪的核心组件。

**功能归纳:**

1. **构建调用栈帧信息 (`CallSiteBuilder` 类):**
   - 遍历当前执行的 JavaScript 代码的调用栈。
   - 为每个栈帧提取必要的信息，例如接收者、函数、代码对象、偏移量和参数。
   - 区分不同类型的栈帧，例如 JavaScript 函数、WebAssembly 函数、内置函数和异步函数。
   - 可以跳过或包含特定的栈帧，例如内部帧或直到遇到特定调用者的帧。
   - 考虑严格模式，以避免在更深的栈帧中暴露敏感信息。
   - 可以构建包含异步操作信息的调用栈。

2. **捕获异步调用栈信息 (`CaptureAsyncStackTrace` 函数族):**
   - 追踪 Promise 链和 AsyncGeneratorObject，以构建异步操作的完整调用栈。
   - 识别 Promise 的各种状态和处理函数，例如 `Promise.all`、`Promise.any` 的处理闭包。
   - 将异步操作的栈帧添加到 `CallSiteBuilder` 中。
   - `TryGetCurrentTaskPromise` 函数尝试获取当前微任务相关的 Promise 对象。

3. **访问调用栈 (`VisitStack` 模板函数):**
   - 提供一个通用的机制来遍历当前的调用栈。
   - 接受一个访问器对象 (`Visitor`)，允许不同的操作在遍历栈帧时执行，例如构建调用栈信息或提取脚本信息。
   - 可以选择是否暴露跨安全域的栈帧。

4. **捕获简单调用栈 (`CaptureSimpleStackTrace` 函数):**
   - 使用 `CallSiteBuilder` 和 `VisitStack` 构建一个简化的调用栈信息，通常用于 `Error.stack` 属性。
   - 可以设置最大帧数限制。
   - 可以指定跳过栈帧的模式。

5. **获取详细调用栈 (`GetDetailedStackTraceFromCallSiteInfos` 函数):**
   - 将 `CallSiteInfo` 数组转换为更详细的 `StackTraceInfo` 对象，包含脚本信息和源码位置。

6. **捕获并设置错误对象的调用栈 (`Isolate::CaptureAndSetErrorStack` 方法):**
   - 根据 `Error.stackTraceLimit` 设置和调试器的要求，捕获简单或详细的调用栈。
   - 将调用栈信息存储在错误对象的特殊属性中 (`error_stack_symbol`)。
   - 可以处理未捕获异常的调用栈捕获。

7. **获取错误对象的调用栈信息 (`Isolate::GetDetailedStackTrace` 和 `Isolate::GetSimpleStackTrace` 方法):**
   - 从错误对象中检索之前捕获的详细或简单调用栈信息。

8. **获取抽象程序计数器 (`Isolate::GetAbstractPC` 方法):**
   - 获取当前执行位置的抽象程序计数器、行号和列号。

9. **构建详细调用栈 (`Isolate::CaptureDetailedStackTrace` 函数):**
   - 使用 `StackFrameBuilder` 和 `VisitStack` 构建包含详细信息的调用栈，例如脚本和源码位置。

10. **获取当前脚本信息 (`Isolate::CurrentScriptNameOrSourceURL` 和 `Isolate::CurrentReferrerScript` 方法):**
    - 遍历调用栈以查找当前正在执行的脚本的文件名或 URL。
    - `CurrentReferrerScript` 尝试获取触发当前脚本执行的脚本（eval 的源）。

11. **获取调用栈限制 (`Isolate::GetStackTraceLimit` 方法):**
    - 获取 `Error.stackTraceLimit` 的值，用于限制捕获的栈帧数量。

**如果 `v8/src/execution/isolate.cc` 以 `.tq` 结尾:**

如果文件名为 `isolate.tq`，那么它将是一个 **Torque 源代码文件**。Torque 是 V8 用来生成高效的运行时函数的领域特定语言。在这种情况下，该文件将包含用 Torque 编写的代码，用于实现与调用栈捕获相关的底层操作。Torque 代码会被编译成 C++ 代码。

**与 JavaScript 功能的关系及示例:**

这段代码直接支持 JavaScript 中的错误处理和调试功能，特别是 `Error` 对象的 `stack` 属性以及异步操作的调试。

**JavaScript 示例:**

```javascript
function foo() {
  bar();
}

function bar() {
  throw new Error("Something went wrong!");
}

try {
  foo();
} catch (e) {
  console.log(e.stack); // 这将打印出包含 foo 和 bar 函数调用的堆栈信息
}

async function asyncFoo() {
  await asyncBar();
}

async function asyncBar() {
  throw new Error("Async error!");
}

asyncFoo().catch(e => {
  console.log(e.stack); // 这将打印出包含 asyncFoo 和 asyncBar 函数调用的异步堆栈信息
});

Promise.resolve().then(() => {
  throw new Error("Promise error");
}).catch(e => {
  console.log(e.stack); // 这将打印出包含 Promise 链的异步堆栈信息
});
```

在上面的例子中，当抛出 `Error` 对象时，V8 引擎会使用 `v8/src/execution/isolate.cc` 中的代码来捕获当前的调用栈，并将其格式化为字符串赋值给 `e.stack` 属性。对于异步操作，V8 会追踪 Promise 链和 async 函数的执行，构建包含异步上下文的堆栈信息。

**代码逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 代码执行：

```javascript
function a() {
  b();
}

function b() {
  c();
}

function c() {
  throw new Error("Error in c");
}

a();
```

**假设输入:** 执行到 `c` 函数内部抛出 `Error` 的时刻。

**输出 (大致):** `CaptureSimpleStackTrace` 或 `CaptureDetailedStackTrace` 函数将会构建一个包含以下栈帧信息的数组或对象：

1. `c` 函数的栈帧信息 (包含函数名、代码位置等)
2. `b` 函数的栈帧信息
3. `a` 函数的栈帧信息
4. 可能的顶层调用栈帧信息

最终 `Error` 对象的 `stack` 属性可能会包含类似以下的字符串：

```
Error: Error in c
    at c (your_script.js:9:7)
    at b (your_script.js:5:3)
    at a (your_script.js:1:3)
    at <anonymous> (your_script.js:12:1)
```

**用户常见的编程错误举例:**

1. **忘记处理 Promise 的 rejection:** 如果一个 Promise 被 rejected 且没有 `.catch()` 处理，可能会导致 unhandled promise rejection 错误。V8 会尝试捕获异步调用栈，帮助开发者定位问题发生的位置。

    ```javascript
    async function fetchData() {
      // ... 可能会抛出错误的异步操作
      throw new Error("Failed to fetch data");
    }

    fetchData(); // 忘记添加 .catch()
    ```

2. **递归调用导致栈溢出:**  无限递归调用会导致调用栈不断增长，最终超出 V8 引擎的限制，抛出 `RangeError: Maximum call stack size exceeded` 错误。V8 捕获的调用栈可以帮助开发者理解递归调用的路径。

    ```javascript
    function recursiveFunction() {
      recursiveFunction();
    }

    recursiveFunction();
    ```

**这是第 2 部分，共 9 部分，请归纳一下它的功能:**

作为第 2 部分，这段代码主要关注 V8 引擎中**捕获和构建调用栈信息**的核心机制。它定义了用于遍历栈帧、提取信息、处理异步操作以及生成不同类型的调用栈表示（简单和详细）的关键类和函数。这些功能是 V8 错误处理和调试能力的基础。

### 提示词
```
这是目录为v8/src/execution/isolate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
ary code, and stack depth tends to be more than
    // a dozen frames, so we over-allocate a bit here to avoid growing
    // the elements array in the common case.
    elements_ = isolate->factory()->NewFixedArray(std::min(64, limit));
  }

  bool Visit(FrameSummary const& summary) {
    if (Full()) return false;
#if V8_ENABLE_WEBASSEMBLY
#if V8_ENABLE_DRUMBRAKE
    if (summary.IsWasmInterpreted()) {
      AppendWasmInterpretedFrame(summary.AsWasmInterpreted());
      return true;
      // FrameSummary::IsWasm() should be renamed FrameSummary::IsWasmCompiled
      // to be more precise, but we'll leave it as it is to try to reduce merge
      // churn.
    } else {
#endif  // V8_ENABLE_DRUMBRAKE
      if (summary.IsWasm()) {
        AppendWasmFrame(summary.AsWasm());
        return true;
      }
#if V8_ENABLE_DRUMBRAKE
    }
#endif  // V8_ENABLE_DRUMBRAKE
    if (summary.IsWasmInlined()) {
      AppendWasmInlinedFrame(summary.AsWasmInlined());
      return true;
    }
    if (summary.IsBuiltin()) {
      AppendBuiltinFrame(summary.AsBuiltin());
      return true;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    AppendJavaScriptFrame(summary.AsJavaScript());
    return true;
  }

  void AppendAsyncFrame(DirectHandle<JSGeneratorObject> generator_object) {
    DirectHandle<JSFunction> function(generator_object->function(), isolate_);
    if (!IsVisibleInStackTrace(function)) return;
    int flags = CallSiteInfo::kIsAsync;
    if (IsStrictFrame(function)) flags |= CallSiteInfo::kIsStrict;

    Handle<JSAny> receiver(generator_object->receiver(), isolate_);
    DirectHandle<BytecodeArray> code(
        function->shared()->GetBytecodeArray(isolate_), isolate_);
    int offset = GetGeneratorBytecodeOffset(generator_object);

    DirectHandle<FixedArray> parameters =
        isolate_->factory()->empty_fixed_array();
    if (V8_UNLIKELY(v8_flags.detailed_error_stack_trace)) {
      parameters = isolate_->factory()->CopyFixedArrayUpTo(
          handle(generator_object->parameters_and_registers(), isolate_),
          function->shared()
              ->internal_formal_parameter_count_without_receiver());
    }

    AppendFrame(receiver, function, code, offset, flags, parameters);
  }

  void AppendPromiseCombinatorFrame(DirectHandle<JSFunction> element_function,
                                    DirectHandle<JSFunction> combinator) {
    if (!IsVisibleInStackTrace(combinator)) return;
    int flags =
        CallSiteInfo::kIsAsync | CallSiteInfo::kIsSourcePositionComputed;

    Handle<JSFunction> receiver(
        combinator->native_context()->promise_function(), isolate_);
    DirectHandle<Code> code(combinator->code(isolate_), isolate_);

    // TODO(mmarchini) save Promises list from the Promise combinator
    DirectHandle<FixedArray> parameters =
        isolate_->factory()->empty_fixed_array();

    // We store the offset of the promise into the element function's
    // hash field for element callbacks.
    int promise_index = Smi::ToInt(element_function->GetIdentityHash()) - 1;

    AppendFrame(receiver, combinator, code, promise_index, flags, parameters);
  }

  void AppendJavaScriptFrame(
      FrameSummary::JavaScriptFrameSummary const& summary) {
    // Filter out internal frames that we do not want to show.
    if (!IsVisibleInStackTrace(summary.function())) return;

    int flags = 0;
    DirectHandle<JSFunction> function = summary.function();
    if (IsStrictFrame(function)) flags |= CallSiteInfo::kIsStrict;
    if (summary.is_constructor()) flags |= CallSiteInfo::kIsConstructor;

    AppendFrame(Cast<UnionOf<JSAny, Hole>>(summary.receiver()), function,
                summary.abstract_code(), summary.code_offset(), flags,
                summary.parameters());
  }

#if V8_ENABLE_WEBASSEMBLY
  void AppendWasmFrame(FrameSummary::WasmFrameSummary const& summary) {
    if (summary.code()->kind() != wasm::WasmCode::kWasmFunction) return;
    Handle<WasmInstanceObject> instance = summary.wasm_instance();
    int flags = CallSiteInfo::kIsWasm;
    if (instance->module_object()->is_asm_js()) {
      flags |= CallSiteInfo::kIsAsmJsWasm;
      if (summary.at_to_number_conversion()) {
        flags |= CallSiteInfo::kIsAsmJsAtNumberConversion;
      }
    }

    DirectHandle<HeapObject> code = isolate_->factory()->undefined_value();
    AppendFrame(instance,
                handle(Smi::FromInt(summary.function_index()), isolate_), code,
                summary.code_offset(), flags,
                isolate_->factory()->empty_fixed_array());
  }

#if V8_ENABLE_DRUMBRAKE
  void AppendWasmInterpretedFrame(
      FrameSummary::WasmInterpretedFrameSummary const& summary) {
    Handle<WasmInstanceObject> instance = summary.wasm_instance();
    int flags = CallSiteInfo::kIsWasm | CallSiteInfo::kIsWasmInterpretedFrame;
    DCHECK(!instance->module_object()->is_asm_js());
    // We don't have any code object in the interpreter, so we pass 'undefined'.
    auto code = isolate_->factory()->undefined_value();
    AppendFrame(instance,
                handle(Smi::FromInt(summary.function_index()), isolate_), code,
                summary.byte_offset(), flags,
                isolate_->factory()->empty_fixed_array());
  }
#endif  // V8_ENABLE_DRUMBRAKE

  void AppendWasmInlinedFrame(
      FrameSummary::WasmInlinedFrameSummary const& summary) {
    DirectHandle<HeapObject> code = isolate_->factory()->undefined_value();
    int flags = CallSiteInfo::kIsWasm;
    AppendFrame(summary.wasm_instance(),
                handle(Smi::FromInt(summary.function_index()), isolate_), code,
                summary.code_offset(), flags,
                isolate_->factory()->empty_fixed_array());
  }

  void AppendBuiltinFrame(FrameSummary::BuiltinFrameSummary const& summary) {
    Builtin builtin = summary.builtin();
    DirectHandle<Code> code = isolate_->builtins()->code_handle(builtin);
    DirectHandle<Smi> function(Smi::FromInt(static_cast<int>(builtin)),
                               isolate_);
    int flags = CallSiteInfo::kIsBuiltin;
    AppendFrame(Cast<UnionOf<JSAny, Hole>>(summary.receiver()), function, code,
                summary.code_offset(), flags,
                isolate_->factory()->empty_fixed_array());
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  bool Full() { return index_ >= limit_; }

  Handle<FixedArray> Build() {
    return FixedArray::RightTrimOrEmpty(isolate_, elements_, index_);
  }

 private:
  // Poison stack frames below the first strict mode frame.
  // The stack trace API should not expose receivers and function
  // objects on frames deeper than the top-most one with a strict mode
  // function.
  bool IsStrictFrame(DirectHandle<JSFunction> function) {
    if (!encountered_strict_function_) {
      encountered_strict_function_ =
          is_strict(function->shared()->language_mode());
    }
    return encountered_strict_function_;
  }

  // Determines whether the given stack frame should be displayed in a stack
  // trace.
  bool IsVisibleInStackTrace(DirectHandle<JSFunction> function) {
    return ShouldIncludeFrame(function) && IsNotHidden(function);
  }

  // This mechanism excludes a number of uninteresting frames from the stack
  // trace. This can be be the first frame (which will be a builtin-exit frame
  // for the error constructor builtin) or every frame until encountering a
  // user-specified function.
  bool ShouldIncludeFrame(DirectHandle<JSFunction> function) {
    switch (mode_) {
      case SKIP_NONE:
        return true;
      case SKIP_FIRST:
        if (!skip_next_frame_) return true;
        skip_next_frame_ = false;
        return false;
      case SKIP_UNTIL_SEEN:
        if (skip_next_frame_ && (*function == *caller_)) {
          skip_next_frame_ = false;
          return false;
        }
        return !skip_next_frame_;
    }
    UNREACHABLE();
  }

  bool IsNotHidden(DirectHandle<JSFunction> function) {
    // TODO(szuend): Remove this check once the flag is enabled
    //               by default.
    if (!v8_flags.experimental_stack_trace_frames &&
        function->shared()->IsApiFunction()) {
      return false;
    }
    // Functions defined not in user scripts are not visible unless directly
    // exposed, in which case the native flag is set.
    // The --builtins-in-stack-traces command line flag allows including
    // internal call sites in the stack trace for debugging purposes.
    if (!v8_flags.builtins_in_stack_traces &&
        !function->shared()->IsUserJavaScript()) {
      return function->shared()->native() ||
             function->shared()->IsApiFunction();
    }
    return true;
  }

  void AppendFrame(Handle<UnionOf<JSAny, Hole>> receiver_or_instance,
                   DirectHandle<UnionOf<Smi, JSFunction>> function,
                   DirectHandle<HeapObject> code, int offset, int flags,
                   DirectHandle<FixedArray> parameters) {
    if (IsTheHole(*receiver_or_instance, isolate_)) {
      // TODO(jgruber): Fix all cases in which frames give us a hole value
      // (e.g. the receiver in RegExp constructor frames).
      receiver_or_instance = isolate_->factory()->undefined_value();
    }
    auto info = isolate_->factory()->NewCallSiteInfo(
        Cast<JSAny>(receiver_or_instance), function, code, offset, flags,
        parameters);
    elements_ = FixedArray::SetAndGrow(isolate_, elements_, index_++, info);
  }

  Isolate* isolate_;
  const FrameSkipMode mode_;
  int index_ = 0;
  const int limit_;
  const Handle<Object> caller_;
  bool skip_next_frame_;
  bool encountered_strict_function_ = false;
  Handle<FixedArray> elements_;
};

void CaptureAsyncStackTrace(Isolate* isolate, DirectHandle<JSPromise> promise,
                            CallSiteBuilder* builder) {
  while (!builder->Full()) {
    // Check that the {promise} is not settled.
    if (promise->status() != Promise::kPending) return;

    // Check that we have exactly one PromiseReaction on the {promise}.
    if (!IsPromiseReaction(promise->reactions())) return;
    DirectHandle<PromiseReaction> reaction(
        Cast<PromiseReaction>(promise->reactions()), isolate);
    if (!IsSmi(reaction->next())) return;

    Handle<JSGeneratorObject> generator_object;

    if (TryGetAsyncGenerator(isolate, reaction).ToHandle(&generator_object)) {
      CHECK(generator_object->is_suspended());

      // Append async frame corresponding to the {generator_object}.
      builder->AppendAsyncFrame(generator_object);

      // Try to continue from here.
      if (IsJSAsyncFunctionObject(*generator_object)) {
        auto async_function_object =
            Cast<JSAsyncFunctionObject>(generator_object);
        promise = handle(async_function_object->promise(), isolate);
      } else {
        auto async_generator_object =
            Cast<JSAsyncGeneratorObject>(generator_object);
        if (IsUndefined(async_generator_object->queue(), isolate)) return;
        DirectHandle<AsyncGeneratorRequest> async_generator_request(
            Cast<AsyncGeneratorRequest>(async_generator_object->queue()),
            isolate);
        promise = handle(Cast<JSPromise>(async_generator_request->promise()),
                         isolate);
      }
    } else if (IsBuiltinFunction(isolate, reaction->fulfill_handler(),
                                 Builtin::kPromiseAllResolveElementClosure)) {
      DirectHandle<JSFunction> function(
          Cast<JSFunction>(reaction->fulfill_handler()), isolate);
      DirectHandle<Context> context(function->context(), isolate);
      DirectHandle<JSFunction> combinator(
          context->native_context()->promise_all(), isolate);
      builder->AppendPromiseCombinatorFrame(function, combinator);

      if (IsNativeContext(*context)) {
        // NativeContext is used as a marker that the closure was already
        // called. We can't access the reject element context any more.
        return;
      }

      // Now peek into the Promise.all() resolve element context to
      // find the promise capability that's being resolved when all
      // the concurrent promises resolve.
      int const index =
          PromiseBuiltins::kPromiseAllResolveElementCapabilitySlot;
      DirectHandle<PromiseCapability> capability(
          Cast<PromiseCapability>(context->get(index)), isolate);
      if (!IsJSPromise(capability->promise())) return;
      promise = handle(Cast<JSPromise>(capability->promise()), isolate);
    } else if (IsBuiltinFunction(
                   isolate, reaction->fulfill_handler(),
                   Builtin::kPromiseAllSettledResolveElementClosure)) {
      DirectHandle<JSFunction> function(
          Cast<JSFunction>(reaction->fulfill_handler()), isolate);
      DirectHandle<Context> context(function->context(), isolate);
      DirectHandle<JSFunction> combinator(
          context->native_context()->promise_all_settled(), isolate);
      builder->AppendPromiseCombinatorFrame(function, combinator);

      if (IsNativeContext(*context)) {
        // NativeContext is used as a marker that the closure was already
        // called. We can't access the reject element context any more.
        return;
      }

      // Now peek into the Promise.allSettled() resolve element context to
      // find the promise capability that's being resolved when all
      // the concurrent promises resolve.
      int const index =
          PromiseBuiltins::kPromiseAllResolveElementCapabilitySlot;
      DirectHandle<PromiseCapability> capability(
          Cast<PromiseCapability>(context->get(index)), isolate);
      if (!IsJSPromise(capability->promise())) return;
      promise = handle(Cast<JSPromise>(capability->promise()), isolate);
    } else if (IsBuiltinFunction(isolate, reaction->reject_handler(),
                                 Builtin::kPromiseAnyRejectElementClosure)) {
      DirectHandle<JSFunction> function(
          Cast<JSFunction>(reaction->reject_handler()), isolate);
      DirectHandle<Context> context(function->context(), isolate);
      DirectHandle<JSFunction> combinator(
          context->native_context()->promise_any(), isolate);
      builder->AppendPromiseCombinatorFrame(function, combinator);

      if (IsNativeContext(*context)) {
        // NativeContext is used as a marker that the closure was already
        // called. We can't access the reject element context any more.
        return;
      }

      // Now peek into the Promise.any() reject element context to
      // find the promise capability that's being resolved when any of
      // the concurrent promises resolve.
      int const index = PromiseBuiltins::kPromiseAnyRejectElementCapabilitySlot;
      DirectHandle<PromiseCapability> capability(
          Cast<PromiseCapability>(context->get(index)), isolate);
      if (!IsJSPromise(capability->promise())) return;
      promise = handle(Cast<JSPromise>(capability->promise()), isolate);
    } else if (IsBuiltinFunction(isolate, reaction->fulfill_handler(),
                                 Builtin::kPromiseCapabilityDefaultResolve)) {
      DirectHandle<JSFunction> function(
          Cast<JSFunction>(reaction->fulfill_handler()), isolate);
      DirectHandle<Context> context(function->context(), isolate);
      promise =
          handle(Cast<JSPromise>(context->get(PromiseBuiltins::kPromiseSlot)),
                 isolate);
    } else {
      // We have some generic promise chain here, so try to
      // continue with the chained promise on the reaction
      // (only works for native promise chains).
      Handle<HeapObject> promise_or_capability(
          reaction->promise_or_capability(), isolate);
      if (IsJSPromise(*promise_or_capability)) {
        promise = Cast<JSPromise>(promise_or_capability);
      } else if (IsPromiseCapability(*promise_or_capability)) {
        auto capability = Cast<PromiseCapability>(promise_or_capability);
        if (!IsJSPromise(capability->promise())) return;
        promise = handle(Cast<JSPromise>(capability->promise()), isolate);
      } else {
        // Otherwise the {promise_or_capability} must be undefined here.
        CHECK(IsUndefined(*promise_or_capability, isolate));
        return;
      }
    }
  }
}

MaybeHandle<JSPromise> TryGetCurrentTaskPromise(Isolate* isolate) {
  Handle<Object> current_microtask = isolate->factory()->current_microtask();
  if (IsPromiseReactionJobTask(*current_microtask)) {
    auto promise_reaction_job_task =
        Cast<PromiseReactionJobTask>(current_microtask);
    // Check if the {reaction} has one of the known async function or
    // async generator continuations as its fulfill handler.
    if (IsBuiltinAsyncFulfillHandler(isolate,
                                     promise_reaction_job_task->handler()) ||
        IsBuiltinAsyncRejectHandler(isolate,
                                    promise_reaction_job_task->handler())) {
      // Now peek into the handlers' AwaitContext to get to
      // the JSGeneratorObject for the async function.
      DirectHandle<Context> context(
          Cast<JSFunction>(promise_reaction_job_task->handler())->context(),
          isolate);
      Handle<JSGeneratorObject> generator_object(
          Cast<JSGeneratorObject>(context->extension()), isolate);
      if (generator_object->is_executing()) {
        if (IsJSAsyncFunctionObject(*generator_object)) {
          auto async_function_object =
              Cast<JSAsyncFunctionObject>(generator_object);
          Handle<JSPromise> promise(async_function_object->promise(), isolate);
          return promise;
        } else {
          auto async_generator_object =
              Cast<JSAsyncGeneratorObject>(generator_object);
          DirectHandle<Object> queue(async_generator_object->queue(), isolate);
          if (!IsUndefined(*queue, isolate)) {
            auto async_generator_request = Cast<AsyncGeneratorRequest>(queue);
            Handle<JSPromise> promise(
                Cast<JSPromise>(async_generator_request->promise()), isolate);
            return promise;
          }
        }
      }
    } else {
#if V8_ENABLE_WEBASSEMBLY
      Handle<WasmSuspenderObject> suspender;
      if (TryGetWasmSuspender(isolate, promise_reaction_job_task->handler())
              .ToHandle(&suspender)) {
        // The {promise_reaction_job_task} belongs to a suspended Wasm stack
        return handle(suspender->promise(), isolate);
      }
#endif  // V8_ENABLE_WEBASSEMBLY

      // The {promise_reaction_job_task} doesn't belong to an await (or
      // yield inside an async generator) or a suspended Wasm stack,
      // but we might still be able to find an async frame if we follow
      // along the chain of promises on the {promise_reaction_job_task}.
      Handle<HeapObject> promise_or_capability(
          promise_reaction_job_task->promise_or_capability(), isolate);
      if (IsJSPromise(*promise_or_capability)) {
        Handle<JSPromise> promise = Cast<JSPromise>(promise_or_capability);
        return promise;
      }
    }
  }
  return MaybeHandle<JSPromise>();
}

void CaptureAsyncStackTrace(Isolate* isolate, CallSiteBuilder* builder) {
  Handle<JSPromise> promise;
  if (TryGetCurrentTaskPromise(isolate).ToHandle(&promise)) {
    CaptureAsyncStackTrace(isolate, promise, builder);
  }
}

template <typename Visitor>
void VisitStack(Isolate* isolate, Visitor* visitor,
                StackTrace::StackTraceOptions options = StackTrace::kDetailed) {
  DisallowJavascriptExecution no_js(isolate);
  for (StackFrameIterator it(isolate); !it.done(); it.Advance()) {
    StackFrame* frame = it.frame();
    switch (frame->type()) {
      case StackFrame::API_CALLBACK_EXIT:
      case StackFrame::BUILTIN_EXIT:
      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION:
      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH:
      case StackFrame::TURBOFAN_JS:
      case StackFrame::MAGLEV:
      case StackFrame::INTERPRETED:
      case StackFrame::BASELINE:
      case StackFrame::BUILTIN:
#if V8_ENABLE_WEBASSEMBLY
      case StackFrame::STUB:
      case StackFrame::WASM:
      case StackFrame::WASM_SEGMENT_START:
#if V8_ENABLE_DRUMBRAKE
      case StackFrame::WASM_INTERPRETER_ENTRY:
#endif  // V8_ENABLE_DRUMBRAKE
#endif  // V8_ENABLE_WEBASSEMBLY
      {
        // A standard frame may include many summarized frames (due to
        // inlining).
        std::vector<FrameSummary> summaries;
        CommonFrame::cast(frame)->Summarize(&summaries);
        for (auto rit = summaries.rbegin(); rit != summaries.rend(); ++rit) {
          FrameSummary& summary = *rit;
          // Skip frames from other origins when asked to do so.
          if (!(options & StackTrace::kExposeFramesAcrossSecurityOrigins) &&
              !summary.native_context()->HasSameSecurityTokenAs(
                  isolate->context())) {
            continue;
          }
          if (!visitor->Visit(summary)) return;
        }
        break;
      }

      default:
        break;
    }
  }
}

Handle<FixedArray> CaptureSimpleStackTrace(Isolate* isolate, int limit,
                                           FrameSkipMode mode,
                                           Handle<Object> caller) {
  TRACE_EVENT_BEGIN1(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__,
                     "maxFrameCount", limit);

#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmCodeRefScope code_ref_scope;
#endif  // V8_ENABLE_WEBASSEMBLY

  CallSiteBuilder builder(isolate, mode, limit, caller);
  VisitStack(isolate, &builder);

  // If --async-stack-traces are enabled and the "current microtask" is a
  // PromiseReactionJobTask, we try to enrich the stack trace with async
  // frames.
  if (v8_flags.async_stack_traces) {
    CaptureAsyncStackTrace(isolate, &builder);
  }

  Handle<FixedArray> stack_trace = builder.Build();
  TRACE_EVENT_END1(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__,
                   "frameCount", stack_trace->length());
  return stack_trace;
}

Handle<StackTraceInfo> GetDetailedStackTraceFromCallSiteInfos(
    Isolate* isolate, DirectHandle<FixedArray> call_site_infos, int limit) {
  auto frames = isolate->factory()->NewFixedArray(
      std::min(limit, call_site_infos->length()));
  int index = 0;
  for (int i = 0; i < call_site_infos->length() && index < limit; ++i) {
    DirectHandle<CallSiteInfo> call_site_info(
        Cast<CallSiteInfo>(call_site_infos->get(i)), isolate);
    if (call_site_info->IsAsync()) {
      break;
    }
    Handle<Script> script;
    if (!CallSiteInfo::GetScript(isolate, call_site_info).ToHandle(&script) ||
        !script->IsSubjectToDebugging()) {
      continue;
    }
    DirectHandle<StackFrameInfo> stack_frame_info =
        isolate->factory()->NewStackFrameInfo(
            script, CallSiteInfo::GetSourcePosition(call_site_info),
            CallSiteInfo::GetFunctionDebugName(call_site_info),
            IsConstructor(*call_site_info));
    frames->set(index++, *stack_frame_info);
  }
  frames = FixedArray::RightTrimOrEmpty(isolate, frames, index);
  return isolate->factory()->NewStackTraceInfo(frames);
}

}  // namespace

MaybeHandle<JSObject> Isolate::CaptureAndSetErrorStack(
    Handle<JSObject> error_object, FrameSkipMode mode, Handle<Object> caller) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__);
  Handle<UnionOf<Undefined, FixedArray>> call_site_infos_or_formatted_stack =
      factory()->undefined_value();

  // Capture the "simple stack trace" for the error.stack property,
  // which can be disabled by setting Error.stackTraceLimit to a non
  // number value or simply deleting the property. If the inspector
  // is active, and requests more stack frames than the JavaScript
  // program itself, we collect up to the maximum.
  int stack_trace_limit = 0;
  if (GetStackTraceLimit(this, &stack_trace_limit)) {
    int limit = stack_trace_limit;
    if (capture_stack_trace_for_uncaught_exceptions_ &&
        !(stack_trace_for_uncaught_exceptions_options_ &
          StackTrace::kExposeFramesAcrossSecurityOrigins)) {
      // Collect up to the maximum of what the JavaScript program and
      // the inspector want. There's a special case here where the API
      // can ask the stack traces to also include cross-origin frames,
      // in which case we collect a separate trace below. Note that
      // the inspector doesn't use this option, so we could as well
      // just deprecate this in the future.
      if (limit < stack_trace_for_uncaught_exceptions_frame_limit_) {
        limit = stack_trace_for_uncaught_exceptions_frame_limit_;
      }
    }
    call_site_infos_or_formatted_stack =
        CaptureSimpleStackTrace(this, limit, mode, caller);
  }
  Handle<Object> error_stack = call_site_infos_or_formatted_stack;

  // Next is the inspector part: Depending on whether we got a "simple
  // stack trace" above and whether that's usable (meaning the API
  // didn't request to include cross-origin frames), we remember the
  // cap for the stack trace (either a positive limit indicating that
  // the Error.stackTraceLimit value was below what was requested via
  // the API, or a negative limit to indicate the opposite), or we
  // collect a "detailed stack trace" eagerly and stash that away.
  if (capture_stack_trace_for_uncaught_exceptions_) {
    Handle<StackTraceInfo> stack_trace;
    if (IsUndefined(*call_site_infos_or_formatted_stack, this) ||
        (stack_trace_for_uncaught_exceptions_options_ &
         StackTrace::kExposeFramesAcrossSecurityOrigins)) {
      stack_trace = CaptureDetailedStackTrace(
          stack_trace_for_uncaught_exceptions_frame_limit_,
          stack_trace_for_uncaught_exceptions_options_);
    } else {
      auto call_site_infos =
          Cast<FixedArray>(call_site_infos_or_formatted_stack);
      stack_trace = GetDetailedStackTraceFromCallSiteInfos(
          this, call_site_infos,
          stack_trace_for_uncaught_exceptions_frame_limit_);
      if (stack_trace_limit < call_site_infos->length()) {
        call_site_infos_or_formatted_stack = FixedArray::RightTrimOrEmpty(
            this, call_site_infos, stack_trace_limit);
      }
      // Notify the debugger.
      OnStackTraceCaptured(stack_trace);
    }
    error_stack = factory()->NewErrorStackData(
        call_site_infos_or_formatted_stack, stack_trace);
  }

  RETURN_ON_EXCEPTION(
      this,
      Object::SetProperty(this, error_object, factory()->error_stack_symbol(),
                          error_stack, StoreOrigin::kMaybeKeyed,
                          Just(ShouldThrow::kThrowOnError)));
  return error_object;
}

Handle<StackTraceInfo> Isolate::GetDetailedStackTrace(
    Handle<JSReceiver> maybe_error_object) {
  ErrorUtils::StackPropertyLookupResult lookup =
      ErrorUtils::GetErrorStackProperty(this, maybe_error_object);
  if (!IsErrorStackData(*lookup.error_stack)) return {};
  return handle(Cast<ErrorStackData>(lookup.error_stack)->stack_trace(), this);
}

Handle<FixedArray> Isolate::GetSimpleStackTrace(
    Handle<JSReceiver> maybe_error_object) {
  ErrorUtils::StackPropertyLookupResult lookup =
      ErrorUtils::GetErrorStackProperty(this, maybe_error_object);

  if (IsFixedArray(*lookup.error_stack)) {
    return Cast<FixedArray>(lookup.error_stack);
  }
  if (!IsErrorStackData(*lookup.error_stack)) {
    return factory()->empty_fixed_array();
  }
  auto error_stack_data = Cast<ErrorStackData>(lookup.error_stack);
  if (!error_stack_data->HasCallSiteInfos()) {
    return factory()->empty_fixed_array();
  }
  return handle(error_stack_data->call_site_infos(), this);
}

Address Isolate::GetAbstractPC(int* line, int* column) {
  JavaScriptStackFrameIterator it(this);

  if (it.done()) {
    *line = -1;
    *column = -1;
    return kNullAddress;
  }
  JavaScriptFrame* frame = it.frame();
  DCHECK(!frame->is_builtin());

  Handle<SharedFunctionInfo> shared(frame->function()->shared(), this);
  SharedFunctionInfo::EnsureSourcePositionsAvailable(this, shared);
  int position = frame->position();

  Tagged<Object> maybe_script = frame->function()->shared()->script();
  if (IsScript(maybe_script)) {
    DirectHandle<Script> script(Cast<Script>(maybe_script), this);
    Script::PositionInfo info;
    Script::GetPositionInfo(script, position, &info);
    *line = info.line + 1;
    *column = info.column + 1;
  } else {
    *line = position;
    *column = -1;
  }

  if (frame->is_unoptimized()) {
    UnoptimizedJSFrame* iframe = static_cast<UnoptimizedJSFrame*>(frame);
    Address bytecode_start =
        iframe->GetBytecodeArray()->GetFirstBytecodeAddress();
    return bytecode_start + iframe->GetBytecodeOffset();
  }

  return frame->pc();
}

namespace {

class StackFrameBuilder {
 public:
  StackFrameBuilder(Isolate* isolate, int limit)
      : isolate_(isolate),
        frames_(isolate_->factory()->empty_fixed_array()),
        index_(0),
        limit_(limit) {}

  bool Visit(FrameSummary& summary) {
    // Check if we have enough capacity left.
    if (index_ >= limit_) return false;
    // Skip frames that aren't subject to debugging.
    if (!summary.is_subject_to_debugging()) return true;
    DirectHandle<StackFrameInfo> frame = summary.CreateStackFrameInfo();
    frames_ = FixedArray::SetAndGrow(isolate_, frames_, index_++, frame);
    return true;
  }

  Handle<FixedArray> Build() {
    return FixedArray::RightTrimOrEmpty(isolate_, frames_, index_);
  }

 private:
  Isolate* isolate_;
  Handle<FixedArray> frames_;
  int index_;
  int limit_;
};

}  // namespace

Handle<StackTraceInfo> Isolate::CaptureDetailedStackTrace(
    int limit, StackTrace::StackTraceOptions options) {
  TRACE_EVENT_BEGIN1(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__,
                     "maxFrameCount", limit);
  StackFrameBuilder builder(this, limit);
  VisitStack(this, &builder, options);
  auto frames = builder.Build();
  TRACE_EVENT_END1(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__,
                   "frameCount", frames->length());
  auto stack_trace = factory()->NewStackTraceInfo(frames);
  OnStackTraceCaptured(stack_trace);
  return stack_trace;
}

namespace {

class CurrentScriptNameStackVisitor {
 public:
  explicit CurrentScriptNameStackVisitor(Isolate* isolate)
      : isolate_(isolate) {}

  bool Visit(FrameSummary& summary) {
    // Skip frames that aren't subject to debugging. Keep this in sync with
    // StackFrameBuilder::Visit so both visitors visit the same frames.
    if (!summary.is_subject_to_debugging()) return true;

    // Frames that are subject to debugging always have a valid script object.
    auto script = Cast<Script>(summary.script());
    Handle<Object> name_or_url_obj(script->GetNameOrSourceURL(), isolate_);
    if (!IsString(*name_or_url_obj)) return true;

    auto name_or_url = Cast<String>(name_or_url_obj);
    if (!name_or_url->length()) return true;

    name_or_url_ = name_or_url;
    return false;
  }

  Handle<String> CurrentScriptNameOrSourceURL() const { return name_or_url_; }

 private:
  Isolate* const isolate_;
  Handle<String> name_or_url_;
};

class CurrentScriptStackVisitor {
 public:
  bool Visit(FrameSummary& summary) {
    // Skip frames that aren't subject to debugging. Keep this in sync with
    // StackFrameBuilder::Visit so both visitors visit the same frames.
    if (!summary.is_subject_to_debugging()) return true;

    // Frames that are subject to debugging always have a valid script object.
    current_script_ = Cast<Script>(summary.script());
    return false;
  }

  MaybeHandle<Script> CurrentScript() const { return current_script_; }

 private:
  MaybeHandle<Script> current_script_;
};

}  // namespace

Handle<String> Isolate::CurrentScriptNameOrSourceURL() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__);
  CurrentScriptNameStackVisitor visitor(this);
  VisitStack(this, &visitor);
  return visitor.CurrentScriptNameOrSourceURL();
}

MaybeHandle<Script> Isolate::CurrentReferrerScript() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.stack_trace"), __func__);
  CurrentScriptStackVisitor visitor{};
  VisitStack(this, &visitor);
  Handle<Script> script;
  if (!visitor.CurrentScript().ToHandle(&script)) {
    return MaybeHandle<Script>();
  }
  return handle(script->GetEvalOrigin(), this);
}

bool Isolate::GetStackTraceLimit(Isolate* isolate, int* result) {
  if (v8_flags.correctness_fuzzer_suppressions) return false;
  Handle<JSObject> error = isolate->error_function();

  Handle<String> key = isolate->factory()->stackTraceLimit_string();
  DirectHandle<Object> stack_trace_limit =
      JSReceiver::GetDataProperty(isolate, error, key);
  if (!IsNumber(*stack_trace_limit)) return false;

  // Ensure that limit is not negative.
  *result = std::max(
      FastD2IChecked(Object::NumberValue(Cast<Number>(*stack_trace_limit))), 0);

  if (*result != v8_flags.stack_trace_limit) {
    isolate->CountU
```
Response:
Let's break down the thought process for analyzing the `callback_invoke_helper.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relation to web technologies (JS, HTML, CSS), examples, error scenarios, and debugging context. Essentially, it's asking for a comprehensive overview of this specific Blink component.

2. **Initial Scan and Keyword Identification:**  I start by quickly reading through the code, looking for key terms and patterns. Words like "Callback," "Invoke," "V8," "Promise," "Constructor," "Function," "Callable," "Exception," and "ScriptState" immediately stand out. The template structure also suggests genericity and handling of different callback types.

3. **Core Functionality - Deciphering the `CallbackInvokeHelper` Template:** The central piece of the code is the `CallbackInvokeHelper` template. I recognize it's parameterized by `CallbackBase`, `mode`, and `return_type_is_promise`. This hints that the class is designed to handle various kinds of callbacks and invocation scenarios.

    * **`CallbackBase`:**  The explicit template instantiations tell me that this can be `CallbackFunctionBase`, `CallbackFunctionWithTaskAttributionBase`, or `CallbackInterfaceBase`. This immediately suggests handling of regular JS functions, functions with task attribution (important for performance tracking), and interface-based callbacks (likely from Web IDL).

    * **`mode`:** The `CallbackInvokeHelperMode` enum with values like `kDefault`, `kConstructorCall`, and `kLegacyTreatNonObjectAsNull` indicates different ways a callback can be invoked (standard call, `new` operator, and a specific legacy handling).

    * **`return_type_is_promise`:** This boolean template parameter clearly handles callbacks that return promises differently, likely involving error handling with `v8::TryCatch`.

4. **Dissecting `PrepareForCall`:** This method seems crucial for setting up the callback invocation. I analyze its steps:

    * **ScriptForbiddenScope:** This is a safety mechanism in Blink to prevent script execution in disallowed contexts. The checks here ensure security and correct lifecycle management.
    * **Constructor Check:** When `mode` is `kConstructorCall`, it verifies the callback is indeed a constructor, throwing a `TypeError` if not.
    * **Callable Check:** Depending on the `CallbackBase` and `mode`, it verifies if the callback object is callable (either a function or an object with a callable property). The `kLegacyTreatNonObjectAsNull` mode shows a specific behavior for non-callable function callbacks.
    * **`this` Binding:** The code determines the `this` value for the callback invocation. It handles cases where it's explicitly provided or defaults to `undefined` or the callback object itself.
    * **Task Attribution:**  The code handles propagating task attribution information for callbacks that support it. This is important for performance analysis and debugging.

5. **Dissecting `CallInternal`:** This method performs the actual V8 function call:

    * **`V8ScriptRunner::CallAsConstructor`:** Used when `mode` is `kConstructorCall`.
    * **`V8ScriptRunner::CallFunction`:** Used for regular function calls.
    * **Probing:** The `probe::InvokeCallback` suggests instrumentation for performance monitoring.

6. **Dissecting `Call`:** This method orchestrates the call and handles promise rejections:

    * **`v8::TryCatch`:**  Wraps the `CallInternal` call when the return type is a promise to catch potential JavaScript exceptions.
    * **Promise Rejection:** If `CallInternal` fails within the `TryCatch`, it creates a rejected promise.

7. **Connecting to Web Technologies (JS, HTML, CSS):**

    * **JavaScript:** The entire file is about invoking JavaScript callbacks. Examples of event handlers, timers, and promises are directly relevant. The handling of `this`, constructors, and exceptions are core JavaScript concepts.
    * **HTML:**  HTML triggers JavaScript through events. The examples of button clicks and form submissions illustrate how user actions lead to JavaScript execution, which might involve invoking callbacks managed by this helper.
    * **CSS:** While less direct, CSS can trigger JavaScript through events (e.g., transitions, animations). The completion of a CSS animation might invoke a JavaScript callback.

8. **Identifying Error Scenarios:** I look for conditions that lead to exceptions or unexpected behavior:

    * **Non-constructor callback in constructor mode:**  Explicitly handled with a `TypeError`.
    * **Non-callable object used as a callback:** Handled, potentially throwing a `TypeError`.
    * **Script forbidden context:**  Throws a specific exception.
    * **JavaScript exceptions during callback execution:** Handled by `v8::TryCatch` for promise-returning callbacks.

9. **Inferring User Actions and Debugging:**  I think about how a developer might end up debugging code that involves this helper:

    * **Setting breakpoints:**  Placing breakpoints in `PrepareForCall` or `CallInternal` would allow inspection of the callback, arguments, and execution context.
    * **Observing call stacks:**  The call stack leading to these functions would reveal the sequence of events that triggered the callback.
    * **Looking for error messages:**  The `TypeError` messages thrown by this helper provide clues about incorrect callback usage.

10. **Structuring the Output:** Finally, I organize the findings into logical sections as requested: functionality, relation to web technologies, examples, error scenarios, and debugging. I use clear language and provide concrete examples to illustrate the concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the file directly executes JavaScript.
* **Correction:**  It *helps* execute JavaScript callbacks. The actual execution is delegated to `V8ScriptRunner`.

* **Initial thought:** The task attribution is just an internal detail.
* **Refinement:** It's important for understanding performance and can be a debugging aid, so it should be mentioned.

* **Initial thought:** Focus solely on the code provided.
* **Refinement:**  Contextualize the code by explaining *why* these checks and operations are necessary in a browser engine (security, correct JS semantics, performance).

By following this structured analysis and iterative refinement, I can create a comprehensive and accurate explanation of the `callback_invoke_helper.cc` file.
这个文件 `blink/renderer/bindings/core/v8/callback_invoke_helper.cc` 的主要功能是**帮助 Blink 引擎安全且正确地调用 JavaScript 回调函数**。它提供了一个模板类 `CallbackInvokeHelper`，用于处理不同类型的回调和调用场景。

以下是它的详细功能和与 Web 技术的关系：

**主要功能:**

1. **准备回调调用:**
   - 检查当前是否处于禁止执行脚本的上下文中 (`ScriptForbiddenScope`)，如果是则抛出异常，防止在不安全的时间或地点执行脚本。
   - 对于构造函数调用模式 (`CallbackInvokeHelperMode::kConstructorCall`)，它会验证提供的回调是否是一个构造函数。
   - 根据不同的回调类型 (`CallbackFunctionBase`, `CallbackInterfaceBase`) 和调用模式 (`CallbackInvokeHelperMode`)，获取或创建用于调用的 `v8::Function` 对象。
   - 设置回调函数的 `this` 上下文 (`thisArg`)。如果未提供，则默认为 `undefined`，或者对于某些类型的回调，设置为回调对象本身。
   - 如果回调函数支持任务归属 (`CallbackFunctionWithTaskAttributionBase`)，它会创建一个任务作用域，以便跟踪回调执行的来源。

2. **执行回调调用:**
   - 使用 `V8ScriptRunner` 来实际执行 JavaScript 回调函数。
   - 对于构造函数调用，使用 `V8ScriptRunner::CallAsConstructor`。
   - 对于普通函数调用，使用 `V8ScriptRunner::CallFunction`。
   - 在调用前后会插入性能探针 (`probe::InvokeCallback`)，用于性能分析。

3. **处理 Promise 返回值:**
   - 如果回调函数预期返回 Promise (`CallbackReturnTypeIsPromise::kYes`)，它会使用 `v8::TryCatch` 包裹回调的执行。
   - 如果回调执行过程中抛出异常，它会将异常捕获并创建一个 rejected 的 Promise。

**与 JavaScript, HTML, CSS 的关系:**

这个文件是 Blink 引擎中连接 C++ 代码和 JavaScript 代码的关键桥梁，它确保了 JavaScript 回调在各种场景下都能被正确调用。

**JavaScript:**

* **事件处理:** 当用户在网页上触发事件（例如点击按钮），浏览器通常会执行与之关联的 JavaScript 回调函数。`CallbackInvokeHelper` 就可能被用来调用这些事件处理函数。
   * **假设输入:** 一个 HTML 按钮被点击，其 `onclick` 属性关联了一个 JavaScript函数 `myClickHandler()`.
   * **输出:** `CallbackInvokeHelper` 负责调用 `myClickHandler()`，传入适当的 `this` 值（通常是按钮元素）和事件对象作为参数。
* **定时器 (setTimeout, setInterval):**  `setTimeout` 和 `setInterval` 注册的回调函数也需要被 Blink 引擎调用。
   * **假设输入:** JavaScript 代码执行了 `setTimeout(myTimeoutFunction, 1000)`.
   * **输出:** 1秒后，`CallbackInvokeHelper` 将负责调用 `myTimeoutFunction()`.
* **Promise 的 resolve/reject 回调:** 当一个 Promise 被 resolve 或 reject 时，与之关联的 `then` 或 `catch` 方法的回调函数需要被执行。
   * **假设输入:** 一个 Promise `myPromise` 被 resolve，并执行了 `myPromise.then(handleSuccess)`.
   * **输出:** `CallbackInvokeHelper` 将负责调用 `handleSuccess()`，并将 Promise 的 resolve 值作为参数传递给它。
* **Web API 的回调函数:** 许多 Web API (例如 `fetch`, `XMLHttpRequest`, `requestAnimationFrame`) 都接受回调函数作为参数，用于异步操作完成后的处理。
   * **假设输入:** JavaScript 代码调用了 `fetch('/data').then(processData)`.
   * **输出:** 当 `/data` 的请求完成后，Blink 引擎会使用 `CallbackInvokeHelper` 调用 `processData()`，并将响应数据作为参数传递给它。

**HTML:**

* HTML 定义了网页的结构，用户与 HTML 元素的交互会触发事件，最终导致 JavaScript 回调的执行。`CallbackInvokeHelper` 确保这些回调能够被正确触发和执行。

**CSS:**

* CSS 本身不直接涉及回调函数的调用。但是，CSS 动画和过渡完成后可能会触发 JavaScript 事件，这些事件的处理函数会通过 `CallbackInvokeHelper` 调用。
   * **假设输入:** 一个元素应用了 CSS 过渡，并在过渡完成后触发了 `transitionend` 事件，该事件关联了一个 JavaScript 函数 `myTransitionEndHandler()`.
   * **输出:** `CallbackInvokeHelper` 将负责调用 `myTransitionEndHandler()`。

**逻辑推理的假设输入与输出:**

假设我们有一个简单的 JavaScript 函数作为回调：

```javascript
function myFunction(arg1, arg2) {
  console.log("Callback called with:", arg1, arg2);
  return arg1 + arg2;
}
```

并且 Blink 引擎需要调用这个函数。

* **假设输入:**
    * `callback_`: 指向 `myFunction` 的 `CallbackFunctionBase` 对象。
    * `argc`: 2 (表示有两个参数)
    * `argv`: 一个包含两个 `v8::Local<v8::Value>` 的数组，分别表示参数值 (例如，数值 5 和 10)。
    * `mode`: `CallbackInvokeHelperMode::kDefault` (普通函数调用)

* **输出:**
    * `PrepareForCall` 会成功准备调用。
    * `CallInternal` 会使用 `V8ScriptRunner::CallFunction` 调用 `myFunction`，`this` 值为 `undefined` (默认情况)，并传入参数 5 和 10。
    * `Call` 方法会返回 `true`，并且 `result_` 会包含 `myFunction` 的返回值 (数值 15)。

**用户或编程常见的使用错误举例:**

1. **尝试在禁止脚本执行的上下文调用回调:** 例如，在文档解析的早期阶段，或者在某些扩展 API 的限制下，尝试执行 JavaScript 回调会导致异常。
   * **用户操作:** 用户可能安装了一个有缺陷的浏览器扩展，该扩展试图在页面加载的早期阶段执行脚本。
   * **调试线索:** 错误信息会指示脚本执行被禁止，并且堆栈信息会指向 `CallbackInvokeHelper::PrepareForCall` 中 `ScriptForbiddenScope::ThrowScriptForbiddenException` 的调用。

2. **将非构造函数作为构造函数调用:** 如果尝试使用 `new` 运算符调用一个普通的 JavaScript 函数，Blink 引擎会抛出 `TypeError`。
   * **用户操作:** 开发者在 JavaScript 代码中错误地使用了 `new myFunction()`，而 `myFunction` 并不是一个构造函数。
   * **调试线索:** 错误信息会是 "TypeError: The provided callback is not a constructor."，并且堆栈信息会指向 `CallbackInvokeHelper::PrepareForCall` 中检查构造函数的部分。

3. **回调函数不存在或不可调用:**  如果尝试调用一个不存在的或者不是函数的对象作为回调，Blink 引擎会抛出 `TypeError`。
   * **用户操作:** 开发者在事件监听器中注册了一个不存在的函数名或者一个非函数类型的变量。
   * **调试线索:** 错误信息可能是 "TypeError: 'undefined' is not a function" 或者 "TypeError: The provided callback is not callable."，堆栈信息会指向 `CallbackInvokeHelper::PrepareForCall` 中检查可调用性的部分。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户点击了一个按钮，触发了一个 JavaScript 事件处理函数。

1. **用户操作:** 用户在浏览器中点击了一个 HTML 按钮。
2. **浏览器事件处理:** 浏览器接收到点击事件，并查找与该按钮关联的事件监听器。
3. **事件监听器触发:** 找到了一个与 `click` 事件关联的 JavaScript 函数。
4. **Blink 事件派发:** Blink 的事件派发机制开始处理该事件。
5. **回调查找:** Blink 找到与该事件关联的 JavaScript 回调函数对象（通常是一个 `CallbackFunction` 或类似的）。
6. **进入 `CallbackInvokeHelper`:** Blink 的代码需要调用这个 JavaScript 回调函数，它会创建一个 `CallbackInvokeHelper` 对象来辅助调用。
7. **`PrepareForCall` 执行:** `CallbackInvokeHelper::PrepareForCall` 方法被调用，进行安全性和类型检查，设置 `this` 上下文等。
8. **`CallInternal` 执行:** `CallbackInvokeHelper::CallInternal` 方法被调用，使用 `V8ScriptRunner` 实际执行 JavaScript 回调函数。
9. **JavaScript 代码执行:** V8 引擎执行用户定义的 JavaScript 回调函数。
10. **回调返回:** JavaScript 回调函数执行完毕，返回值返回给 `CallbackInvokeHelper`。
11. **`Call` 方法返回:** `CallbackInvokeHelper::Call` 方法返回，整个回调调用过程结束。

在调试过程中，如果出现与回调函数相关的问题，开发者可以使用浏览器的开发者工具设置断点，例如在 `CallbackInvokeHelper::PrepareForCall` 或 `CallbackInvokeHelper::CallInternal` 中设置断点，来检查回调对象、参数、`this` 上下文以及执行流程，从而定位问题。堆栈信息也会显示从事件触发到回调调用的整个过程，帮助开发者理解代码的执行路径。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/callback_invoke_helper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/callback_invoke_helper.h"

#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/core_probes_inl.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/callback_function_base.h"
#include "third_party/blink/renderer/platform/bindings/callback_interface_base.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"

namespace blink {

namespace bindings {

template <class CallbackBase,
          CallbackInvokeHelperMode mode,
          CallbackReturnTypeIsPromise return_type_is_promise>
bool CallbackInvokeHelper<CallbackBase, mode, return_type_is_promise>::
    PrepareForCall(V8ValueOrScriptWrappableAdapter callback_this) {
  v8::Isolate* isolate = callback_->GetIsolate();
  if (ScriptForbiddenScope::IsScriptForbidden()) [[unlikely]] {
    ScriptForbiddenScope::ThrowScriptForbiddenException(isolate);
    return Abort();
  }
  if (RuntimeEnabledFeatures::BlinkLifecycleScriptForbiddenEnabled()) {
    CHECK(!ScriptForbiddenScope::WillBeScriptForbidden());
  } else {
    DCHECK(!ScriptForbiddenScope::WillBeScriptForbidden());
  }

  if constexpr (mode == CallbackInvokeHelperMode::kConstructorCall) {
    // step 3. If ! IsConstructor(F) is false, throw a TypeError exception.
    if (!callback_->IsConstructor()) {
      ExceptionState exception_state(isolate, v8::ExceptionContext::kOperation,
                                     class_like_name_, property_name_);
      exception_state.ThrowTypeError(
          "The provided callback is not a constructor.");
      return Abort();
    }
  }

  if constexpr (std::is_same<CallbackBase, CallbackFunctionBase>::value ||
                std::is_same<CallbackBase,
                             CallbackFunctionWithTaskAttributionBase>::value) {
    if constexpr (mode ==
                  CallbackInvokeHelperMode::kLegacyTreatNonObjectAsNull) {
      // step 4. If ! IsCallable(F) is false:
      if (!callback_->CallbackObject()->IsFunction()) {
        // step 4.2. Return the result of converting undefined to the callback
        // function's return type.
        result_ = v8::Undefined(isolate);
        return false;
      }
    }
    DCHECK(callback_->CallbackObject()->IsFunction());
    function_ = callback_->CallbackObject().template As<v8::Function>();
  }
  if constexpr (std::is_same<CallbackBase, CallbackInterfaceBase>::value) {
    if (callback_->IsCallbackObjectCallable()) {
      function_ = callback_->CallbackObject().template As<v8::Function>();
    } else {
      // step 10. If ! IsCallable(O) is false, then:
      v8::MicrotaskQueue* microtask_queue =
          ToMicrotaskQueue(callback_->CallbackRelevantScriptState());
      v8::MicrotasksScope microtasks_scope(isolate, microtask_queue,
                                           v8::MicrotasksScope::kRunMicrotasks);

      v8::Local<v8::Value> value;
      if (!callback_->CallbackObject()
               ->Get(callback_->CallbackRelevantScriptState()->GetContext(),
                     V8String(isolate, property_name_))
               .ToLocal(&value)) {
        return Abort();
      }
      if (!value->IsFunction()) {
        V8ThrowException::ThrowTypeError(
            isolate, ExceptionMessages::FailedToExecute(
                         property_name_, class_like_name_,
                         "The provided callback is not callable."));
        return Abort();
      }
      function_ = value.As<v8::Function>();
    }
  }

  if constexpr (mode != CallbackInvokeHelperMode::kConstructorCall) {
    bool is_callable = true;
    if constexpr (std::is_same<CallbackBase, CallbackInterfaceBase>::value)
      is_callable = callback_->IsCallbackObjectCallable();
    if (!is_callable) {
      // step 10.5. Set thisArg to O (overriding the provided value).
      callback_this_ = callback_->CallbackObject();
    } else if (callback_this.IsEmpty()) {
      // step 2. If thisArg was not given, let thisArg be undefined.
      callback_this_ = v8::Undefined(isolate);
    } else {
      callback_this_ =
          callback_this.V8Value(callback_->CallbackRelevantScriptState());
    }
    if (auto* tracker = scheduler::TaskAttributionTracker::From(isolate)) {
      scheduler::TaskAttributionInfo* task_state_to_propagate = nullptr;
      if constexpr (std::is_same<
                        CallbackBase,
                        CallbackFunctionWithTaskAttributionBase>::value) {
        task_state_to_propagate = callback_->GetParentTask();
      }
      task_attribution_scope_ = tracker->MaybeCreateTaskScopeForCallback(
          callback_->CallbackRelevantScriptState(), task_state_to_propagate);
    }
  }

  return true;
}

template <class CallbackBase,
          CallbackInvokeHelperMode mode,
          CallbackReturnTypeIsPromise return_type_is_promise>
bool CallbackInvokeHelper<CallbackBase, mode, return_type_is_promise>::
    CallInternal(int argc, v8::Local<v8::Value>* argv) {
  ScriptState* script_state = callback_->CallbackRelevantScriptState();
  DCHECK(script_state);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  probe::InvokeCallback probe_scope(*script_state, class_like_name_,
                                    /*callback=*/nullptr, function_);

  if constexpr (mode == CallbackInvokeHelperMode::kConstructorCall) {
    // step 10. Let callResult be Construct(F, esArgs).
    return V8ScriptRunner::CallAsConstructor(callback_->GetIsolate(), function_,
                                             execution_context, argc, argv)
        .ToLocal(&result_);
  } else {
    // step 12. Let callResult be Call(X, thisArg, esArgs).
    // or
    // step 11. Let callResult be Call(F, thisArg, esArgs).
    return V8ScriptRunner::CallFunction(function_, execution_context,
                                        callback_this_, argc, argv,
                                        callback_->GetIsolate())
        .ToLocal(&result_);
  }
}

template <class CallbackBase,
          CallbackInvokeHelperMode mode,
          CallbackReturnTypeIsPromise return_type_is_promise>
bool CallbackInvokeHelper<CallbackBase, mode, return_type_is_promise>::Call(
    int argc,
    v8::Local<v8::Value>* argv) {
  if constexpr (return_type_is_promise == CallbackReturnTypeIsPromise::kYes) {
    v8::TryCatch block(callback_->GetIsolate());
    if (!CallInternal(argc, argv)) {
      // We don't know the type of the promise here - but given that we're only
      // going to extract the v8::Value and discard the ScriptPromise, it
      // doesn't matter what type we use.
      result_ = ScriptPromise<IDLUndefined>::Reject(
                    callback_->CallbackRelevantScriptState(), block.Exception())
                    .V8Promise();
    }
  } else {
    if (!CallInternal(argc, argv))
      return Abort();
  }
  return true;
}

template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionBase,
                         CallbackInvokeHelperMode::kDefault>;
template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionBase,
                         CallbackInvokeHelperMode::kDefault,
                         CallbackReturnTypeIsPromise::kYes>;
template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionBase,
                         CallbackInvokeHelperMode::kConstructorCall>;
template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionBase,
                         CallbackInvokeHelperMode::kConstructorCall,
                         CallbackReturnTypeIsPromise::kYes>;
template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionBase,
                         CallbackInvokeHelperMode::kLegacyTreatNonObjectAsNull>;

template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionWithTaskAttributionBase,
                         CallbackInvokeHelperMode::kDefault>;
template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionWithTaskAttributionBase,
                         CallbackInvokeHelperMode::kDefault,
                         CallbackReturnTypeIsPromise::kYes>;
template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionWithTaskAttributionBase,
                         CallbackInvokeHelperMode::kConstructorCall>;
template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionWithTaskAttributionBase,
                         CallbackInvokeHelperMode::kConstructorCall,
                         CallbackReturnTypeIsPromise::kYes>;
template class CORE_TEMPLATE_EXPORT
    CallbackInvokeHelper<CallbackFunctionWithTaskAttributionBase,
                         CallbackInvokeHelperMode::kLegacyTreatNonObjectAsNull>;

template class CORE_TEMPLATE_EXPORT CallbackInvokeHelper<CallbackInterfaceBase>;

}  // namespace bindings

}  // namespace blink

"""

```
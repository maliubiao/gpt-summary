Response:
Let's break down the thought process for analyzing the `ScriptPromiseResolverBase.cc` file.

1. **Understanding the Goal:** The request asks for the functionality of the file, its relation to web technologies (JavaScript, HTML, CSS), potential errors, debugging information, and examples where applicable. The core task is to explain what this piece of Chromium's Blink rendering engine does.

2. **Initial Code Scan - Identifying Key Elements:**  A quick read-through reveals some prominent keywords and structures:
    * `ScriptPromiseResolverBase`:  This is clearly the central class.
    * `Promise`:  The name itself strongly suggests dealing with JavaScript Promises.
    * `Resolve`, `Reject`:  These are the fundamental operations of a Promise.
    * `ScriptState`, `ExecutionContext`: These indicate integration with Blink's scripting environment.
    * `DOMException`:  Signifies error handling related to the Document Object Model.
    * `v8`:  Indicates interaction with the V8 JavaScript engine.
    * `Detach`: A less common but present operation.

3. **Deconstructing the Functionality:** Based on the keywords, we can start to deduce the file's purpose: it's responsible for managing the *resolution* or *rejection* of JavaScript Promises within the Blink rendering engine.

4. **Analyzing Key Methods:**  Let's examine the most important methods and their roles:

    * **Constructor (`ScriptPromiseResolverBase`)**:  It takes a `ScriptState` (representing the JavaScript execution context) and creates a `v8::Promise::Resolver`. This confirms the direct link to V8 Promises. The initial state is `kPending`.

    * **`Reject(...)` overloads**:  These methods allow rejecting the Promise with different types of values (DOMException, v8::Value, ScriptValue, primitive types). This demonstrates flexibility in how a Promise can fail. The `RejectWithDOMException`, `RejectWithSecurityError`, `RejectWithTypeError`, `RejectWithRangeError`, `RejectWithWasmCompileError` functions highlight specific error scenarios.

    * **`Resolve(...)`**:  (Although not explicitly shown in the provided snippet, it's implied by the existence of `Reject` and the nature of Promises). This would handle successful Promise resolution. *Self-correction: I initially focused heavily on `Reject` but need to remember the dual nature of Promises.*

    * **`Detach()`**: This method allows explicitly detaching the resolver. The comments suggest this is important for memory management and preventing leaks. The `DCHECK` in the destructor reinforces the importance of proper detachment.

    * **`NotifyResolveOrReject()` and `ResolveOrRejectImmediately()` and `ScheduleResolveOrReject()` and `ResolveOrRejectDeferred()`**: This series of functions reveals the asynchronous nature of Promise resolution. It handles cases where the execution context is paused or scripting is forbidden, scheduling the resolution/rejection for later. This is crucial for understanding how Blink manages Promise execution.

    * **`GetExecutionContext()`**:  Provides access to the execution context, which is vital for interacting with the broader browser environment.

5. **Connecting to Web Technologies:**

    * **JavaScript:** The direct use of `v8::Promise` and the concepts of `resolve` and `reject` immediately link this code to JavaScript Promises. Examples of JavaScript code that would trigger this would be `new Promise((resolve, reject) => { ... })` and subsequently calling `resolve()` or `reject()`.

    * **HTML:**  HTML elements and their associated JavaScript event handlers can lead to asynchronous operations that use Promises. For instance, fetching data using `fetch()` returns a Promise.

    * **CSS:**  While CSS itself doesn't directly use Promises, JavaScript interacting with CSSOM (CSS Object Model) might use Promises for asynchronous operations like loading external stylesheets. This is a less direct connection.

6. **Logical Reasoning (Hypothetical Input & Output):**  Consider a scenario where JavaScript calls `resolve(someValue)` on a Promise. The `Resolve` method in this C++ code (not shown but implied) would be called with `someValue`. The output would be the Promise transitioning to the "resolved" state, and potentially triggering `.then()` callbacks in the JavaScript code. Similarly, `reject(someError)` would lead to the Promise being "rejected" and potentially triggering `.catch()` callbacks.

7. **Common Usage Errors:**  The `DCHECK` in the destructor is a big clue. Failing to properly resolve or reject a Promise and letting the resolver be garbage collected leads to a crash (in debug builds). This is a key error to highlight. Another error would be trying to resolve or reject a Promise multiple times, which is not allowed by the Promise specification.

8. **Debugging Scenario:**  Tracing the execution flow back from this C++ code involves understanding how JavaScript Promise resolution triggers the corresponding Blink internal mechanisms. A developer debugging a Promise-related issue in their JavaScript would likely set breakpoints in their JavaScript code's `resolve` or `reject` calls, or in the `.then()` or `.catch()` handlers. If the issue seems to be within the browser's implementation, they might then need to delve into Blink's codebase, potentially looking at `ScriptPromiseResolverBase` to understand how the resolution/rejection is being handled internally.

9. **Structuring the Answer:**  Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors, and Debugging. Use examples to illustrate the concepts. Be precise with terminology (e.g., "V8 isolate," "execution context").

10. **Review and Refine:** Read through the generated explanation to ensure clarity, accuracy, and completeness. Check for any logical gaps or areas where more detail could be beneficial. For instance, emphasizing the asynchronous nature of Promise resolution and how Blink handles it is important. Ensuring the connection to specific JavaScript APIs like `fetch()` strengthens the explanation.
好的，让我们来详细分析一下 `blink/renderer/bindings/core/v8/script_promise_resolver.cc` 这个文件。

**文件功能概述**

`ScriptPromiseResolverBase` 类是 Blink 渲染引擎中用于管理 JavaScript Promise 的解析和拒绝的核心组件。 它的主要功能包括：

1. **创建 Promise 解析器 (Resolver):**  当 JavaScript 代码创建一个新的 `Promise` 对象时，Blink 内部会创建一个 `ScriptPromiseResolverBase` 的实例。这个实例持有一个 V8 的 `Promise::Resolver` 对象，该对象是 V8 引擎中实际负责解析或拒绝 Promise 的机制。
2. **管理 Promise 状态:**  `ScriptPromiseResolverBase` 维护着 Promise 的当前状态（`kPending`, `kResolving`, `kRejecting`, `kDone`），跟踪 Promise 是否已被解析、拒绝或仍在等待。
3. **解析 (Resolve) Promise:**  当 JavaScript 代码调用 `resolve()` 方法时，会调用 `ScriptPromiseResolverBase` 的 `Resolve` 方法（虽然在提供的代码片段中没有显式展示 `Resolve` 方法，但它是 Promise Resolver 的基本功能）。`Resolve` 方法会将 Promise 的状态设置为 `kResolving`，并将解析值存储起来。然后，它会调度一个微任务来实际执行 Promise 的解析，最终触发 Promise 的 `then` 回调。
4. **拒绝 (Reject) Promise:** 当 JavaScript 代码调用 `reject()` 方法时，会调用 `ScriptPromiseResolverBase` 的 `Reject` 方法。`Reject` 方法会将 Promise 的状态设置为 `kRejecting`，并将拒绝原因（通常是一个错误对象）存储起来。同样，它也会调度一个微任务来执行 Promise 的拒绝，最终触发 Promise 的 `catch` 回调。
5. **处理不同类型的拒绝值:** `Reject` 方法提供了一系列重载，可以接受不同类型的拒绝值，例如 `DOMException` 对象、V8 的 `v8::Value`、`ScriptValue`、字符串、布尔值等。
6. **创建带上下文信息的异常:**  提供了一些辅助方法，如 `RejectWithDOMException`, `RejectWithSecurityError`, `RejectWithTypeError`, `RejectWithRangeError`, `RejectWithWasmCompileError`，这些方法可以创建包含更详细上下文信息的 `DOMException` 对象，方便开发者调试。
7. **分离 (Detach) 解析器:** `Detach()` 方法允许在某些情况下显式地分离解析器，清除其持有的 V8 `Promise::Resolver` 和值，这通常用于资源管理，防止内存泄漏。
8. **延迟执行解析/拒绝:**  `NotifyResolveOrReject`, `ScheduleResolveOrReject`, `ResolveOrRejectDeferred`, `ResolveOrRejectImmediately` 等方法用于处理在不同的执行上下文中解析或拒绝 Promise 的情况，例如，当 JavaScript 执行被暂停或者脚本被禁止时，需要延迟执行。
9. **调试支持:** 代码中包含一些 `DCHECK` 宏，用于在调试版本中检查是否存在未正确分离的 Promise 解析器，帮助开发者发现潜在的内存泄漏问题。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`ScriptPromiseResolverBase` 是 Blink 引擎中连接 JavaScript Promise 和底层 C++ 实现的关键桥梁。它不直接与 HTML 或 CSS 交互，但它们之间的关系是通过 JavaScript 来建立的。

* **JavaScript:**
    * **示例 1：创建和解析 Promise**
      ```javascript
      const myPromise = new Promise((resolve, reject) => {
        // 异步操作成功后调用 resolve
        setTimeout(() => {
          resolve("操作成功");
        }, 1000);
      });

      myPromise.then((result) => {
        console.log(result); // 一秒后输出 "操作成功"
      });
      ```
      在这个例子中，当 `new Promise` 被调用时，Blink 会创建 `ScriptPromiseResolverBase` 的实例。当 `resolve("操作成功")` 被调用时，`ScriptPromiseResolverBase` 的解析逻辑会被触发，最终导致 `then` 回调被执行。

    * **示例 2：创建和拒绝 Promise**
      ```javascript
      const anotherPromise = new Promise((resolve, reject) => {
        // 异步操作失败后调用 reject
        setTimeout(() => {
          reject(new Error("操作失败"));
        }, 500);
      });

      anotherPromise.catch((error) => {
        console.error(error); // 500 毫秒后输出 Error: 操作失败
      });
      ```
      类似地，当 `reject(new Error("操作失败"))` 被调用时，`ScriptPromiseResolverBase` 的拒绝逻辑会被触发，最终导致 `catch` 回调被执行。

* **HTML:**
    * HTML 中定义的事件处理程序可以触发返回 Promise 的 JavaScript 函数。例如，`fetch` API 返回一个 Promise。
    ```html
    <button onclick="fetchData()">获取数据</button>
    <script>
      function fetchData() {
        fetch('/api/data')
          .then(response => response.json())
          .then(data => console.log(data))
          .catch(error => console.error("获取数据失败:", error));
      }
    </script>
    ```
    当点击按钮时，`fetch` 函数返回的 Promise 的解析或拒绝会通过 `ScriptPromiseResolverBase` 来处理。

* **CSS:**
    * CSS 本身不直接创建或操作 Promise。然而，JavaScript 可以使用 Promise 来处理与 CSS 相关的异步操作，例如加载外部样式表或处理 CSS 动画的完成事件（虽然这种用例相对少见）。

**逻辑推理及假设输入与输出**

假设 JavaScript 代码创建了一个新的 Promise 并最终调用了 `resolve("Hello")`：

* **假设输入:**
    * JavaScript 代码: `const p = new Promise(resolve => setTimeout(() => resolve("Hello"), 100));`
    * 100 毫秒后，JavaScript 引擎执行 `resolve("Hello")`。

* **逻辑推理:**
    1. 当 `new Promise` 被调用时，Blink 创建一个 `ScriptPromiseResolverBase` 实例，状态为 `kPending`。
    2. `resolve("Hello")` 被调用，`ScriptPromiseResolverBase` 将状态设置为 `kResolving`，并将 `"Hello"` 存储为解析值。
    3. `ScriptPromiseResolverBase` 会调度一个微任务来执行实际的解析操作。
    4. 微任务执行时，V8 的 `Promise::Resolver` 被调用，Promise 的状态变为 "fulfilled"，值为 `"Hello"`。
    5. Promise 的 `then` 回调队列被检查，如果有注册的回调，它们将会在下一个微任务中被执行。

* **预期输出:** 如果有 `p.then(data => console.log(data))` 这样的代码，那么控制台将在稍后（微任务执行时）输出 `"Hello"`。

假设 JavaScript 代码创建了一个 Promise 并调用了 `reject(new Error("Something went wrong"))`：

* **假设输入:**
    * JavaScript 代码: `const p = new Promise((resolve, reject) => setTimeout(() => reject(new Error("Something went wrong")), 100));`
    * 100 毫秒后，JavaScript 引擎执行 `reject(new Error("Something went wrong"))`。

* **逻辑推理:**
    1. 当 `new Promise` 被调用时，Blink 创建一个 `ScriptPromiseResolverBase` 实例，状态为 `kPending`。
    2. `reject(new Error("Something went wrong"))` 被调用，`ScriptPromiseResolverBase` 将状态设置为 `kRejecting`，并将 `Error: Something went wrong` 对象存储为拒绝值。
    3. `ScriptPromiseResolverBase` 会调度一个微任务来执行实际的拒绝操作。
    4. 微任务执行时，V8 的 `Promise::Resolver` 被调用，Promise 的状态变为 "rejected"，拒绝值为 `Error: Something went wrong`。
    5. Promise 的 `catch` 回调队列被检查，如果有注册的回调，它们将会在下一个微任务中被执行。

* **预期输出:** 如果有 `p.catch(error => console.error(error))` 这样的代码，那么控制台将在稍后输出 `Error: Something went wrong`。

**用户或编程常见的使用错误**

1. **忘记调用 `resolve` 或 `reject`:**  如果 Promise 的 executor 函数中没有调用 `resolve` 或 `reject`，Promise 的状态将永远停留在 `pending`，相关的 `then` 和 `catch` 回调都不会被执行，导致程序逻辑停滞。
   ```javascript
   const neverResolves = new Promise(() => {}); // 忘记调用 resolve 或 reject
   neverResolves.then(() => console.log("This will never be printed"));
   ```

2. **多次调用 `resolve` 或 `reject`:**  Promise 的状态一旦被解析或拒绝，就不能再改变。多次调用 `resolve` 或 `reject`，只有第一次调用会生效，后续的调用会被忽略。这可能会导致意外的行为。
   ```javascript
   const myPromise = new Promise((resolve, reject) => {
     resolve("First resolve");
     resolve("Second resolve"); // This will be ignored
     reject("This will also be ignored");
   });

   myPromise.then(data => console.log(data)); // 输出 "First resolve"
   ```

3. **在 `then` 或 `catch` 回调中抛出错误:**  如果在 `then` 或 `catch` 回调中抛出错误，如果没有后续的 `catch` 处理，会导致 Promise 链中断，并可能导致未捕获的异常。
   ```javascript
   const failingPromise = Promise.reject("Initial rejection");

   failingPromise.catch(() => {
     throw new Error("Error in catch handler");
   }).catch(error => console.error("Caught error:", error)); // 需要有后续的 catch 来处理
   ```

4. **未处理的拒绝 (Unhandled Rejection):** 如果一个 Promise 被拒绝，但没有相应的 `catch` 回调来处理，这被称为未处理的拒绝。现代 JavaScript 环境会发出警告或错误，表明存在潜在的错误没有被处理。

**用户操作是如何一步步的到达这里，作为调试线索**

当开发者在浏览器中进行操作，触发了某些需要异步处理的任务，并且这些任务使用了 JavaScript Promise，那么就有可能涉及到 `ScriptPromiseResolverBase` 的代码。以下是一个典型的场景：

1. **用户在网页上点击了一个按钮。**
2. **该按钮的 `onclick` 事件处理程序中调用了一个返回 Promise 的 JavaScript 函数，例如 `fetch` API 发起网络请求。**
   ```javascript
   document.getElementById('myButton').onclick = function() {
     fetch('/api/data')
       .then(response => response.json())
       .then(data => console.log(data))
       .catch(error => console.error("Error fetching data:", error));
   };
   ```
3. **当 `fetch('/api/data')` 被调用时，Blink 的网络模块会发起一个异步请求。**
4. **`fetch` 函数会返回一个 Promise 对象。Blink 内部会创建一个 `ScriptPromiseResolverBase` 实例来管理这个 Promise。**
5. **如果网络请求成功返回，Blink 的网络模块会调用与该 Promise 关联的 `resolve` 方法（通过 `ScriptPromiseResolverBase`）。**  这会导致 `ScriptPromiseResolverBase` 调度微任务执行 `then` 回调 (`response => response.json()`).
6. **如果网络请求失败，Blink 的网络模块会调用与该 Promise 关联的 `reject` 方法（通过 `ScriptPromiseResolverBase`）。** 这会导致 `ScriptPromiseResolverBase` 调度微任务执行 `catch` 回调 (`error => console.error("Error fetching data:", error)`).

**调试线索:**

* **开发者在浏览器开发者工具的 "Sources" 面板中设置断点。** 他们可能会在 `fetch` 调用的地方，或者在 `then` 或 `catch` 回调中设置断点，以观察 Promise 的状态变化和数据的流动。
* **如果开发者怀疑 Promise 的解析或拒绝过程有问题，他们可能会尝试在 Blink 源代码中设置断点。**  例如，在 `blink/renderer/bindings/core/v8/script_promise_resolver.cc` 文件的 `Resolve` 或 `Reject` 方法中设置断点，以查看这些方法何时被调用，以及传递的参数是什么。
* **开发者可以使用浏览器的性能分析工具来观察 Promise 的生命周期。**  这些工具可以显示 Promise 何时被创建、解析或拒绝，以及执行回调所花费的时间。
* **查看浏览器的控制台输出的错误信息。** 如果存在未处理的拒绝，浏览器通常会输出警告信息，这可以作为调试的起点。

总而言之，`ScriptPromiseResolverBase.cc` 是 Blink 引擎中管理 JavaScript Promise 异步操作的核心组件，它负责 Promise 的状态管理、解析、拒绝以及与 V8 引擎的交互。理解它的功能有助于深入理解 JavaScript Promise 在浏览器中的实现机制。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/script_promise_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"

#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

#if DCHECK_IS_ON()
#include "base/debug/alias.h"
#include "components/crash/core/common/crash_key.h"
#endif

namespace blink {

ScriptPromiseResolverBase::ScriptPromiseResolverBase(
    ScriptState* script_state,
    const ExceptionContext& exception_context)
    : resolver_(script_state->GetIsolate(),
                v8::Promise::Resolver::New(script_state->GetContext())
                    .ToLocalChecked()),
      state_(kPending),
      script_state_(script_state),
      exception_context_(exception_context),
      script_url_(GetCurrentScriptUrl(script_state->GetIsolate())) {}

ScriptPromiseResolverBase::~ScriptPromiseResolverBase() = default;

#if DCHECK_IS_ON()
void ScriptPromiseResolverBase::Dispose() {
  // This assertion fails if:
  //  - promise() is called at least once and
  //  - this resolver is destructed before it is resolved, rejected,
  //    detached, the V8 isolate is terminated or the associated
  //    ExecutionContext is stopped.
  const bool is_properly_detached = state_ == kDone || !is_promise_called_ ||
                                    !GetScriptState()->ContextIsValid() ||
                                    !GetExecutionContext() ||
                                    GetExecutionContext()->IsContextDestroyed();
  if (!is_properly_detached && !suppress_detach_check_) {
    // This is here to make it easier to track down which promise resolvers are
    // being abandoned. See https://crbug.com/873980.
    static crash_reporter::CrashKeyString<1024> trace_key(
        "scriptpromiseresolver-trace");
    crash_reporter::SetCrashKeyStringToStackTrace(&trace_key,
                                                  create_stack_trace_);
    DCHECK(false)
        << "ScriptPromiseResolverBase was not properly detached; created at\n"
        << create_stack_trace_.ToString();
  }
}
#endif

void ScriptPromiseResolverBase::Reject(DOMException* value) {
  Reject<DOMException>(value);
}

void ScriptPromiseResolverBase::Reject(v8::Local<v8::Value> value) {
  Reject<IDLAny>(value);
}

void ScriptPromiseResolverBase::Reject(const ScriptValue& value) {
  Reject<IDLAny>(value);
}

void ScriptPromiseResolverBase::Reject(const char* value) {
  Reject<IDLString>(value);
}

void ScriptPromiseResolverBase::Reject(bool value) {
  Reject<IDLBoolean>(value);
}

void ScriptPromiseResolverBase::RejectWithDOMException(
    DOMExceptionCode exception_code,
    const String& message) {
  ScriptState::Scope scope(script_state_.Get());
  v8::Isolate* isolate = script_state_->GetIsolate();
  auto exception =
      V8ThrowDOMException::CreateOrDie(isolate, exception_code, message);
  ApplyContextToException(script_state_, exception, exception_context_);
  Reject(exception);
}

void ScriptPromiseResolverBase::RejectWithSecurityError(
    const String& sanitized_message,
    const String& unsanitized_message) {
  ScriptState::Scope scope(script_state_.Get());
  v8::Isolate* isolate = script_state_->GetIsolate();
  auto exception = V8ThrowDOMException::CreateOrDie(
      isolate, DOMExceptionCode::kSecurityError, sanitized_message,
      unsanitized_message);
  ApplyContextToException(script_state_, exception, exception_context_);
  Reject(exception);
}

String AddContext(const ExceptionContext& context, const String& message) {
  return ExceptionMessages::AddContextToMessage(
      context.GetType(), context.GetClassName(), context.GetPropertyName(),
      message);
}

void ScriptPromiseResolverBase::RejectWithTypeError(const String& message) {
  ScriptState::Scope scope(script_state_.Get());
  Reject(V8ThrowException::CreateTypeError(
      script_state_->GetIsolate(), AddContext(exception_context_, message)));
}

void ScriptPromiseResolverBase::RejectWithRangeError(const String& message) {
  ScriptState::Scope scope(script_state_.Get());
  Reject(V8ThrowException::CreateRangeError(
      script_state_->GetIsolate(), AddContext(exception_context_, message)));
}

void ScriptPromiseResolverBase::RejectWithWasmCompileError(
    const String& message) {
  ScriptState::Scope scope(script_state_.Get());
  Reject(V8ThrowException::CreateWasmCompileError(
      script_state_->GetIsolate(), AddContext(exception_context_, message)));
}

void ScriptPromiseResolverBase::Detach() {
  // Reset state even if we're already kDone. The resolver_ will not have been
  // reset yet if this was marked kDone due to resolve/reject, and an explicit
  // Detach() should really clear everything.
  state_ = kDone;
  resolver_.Reset();
  value_.Reset();
}

void ScriptPromiseResolverBase::NotifyResolveOrReject() {
  if (GetExecutionContext()->IsContextPaused()) {
    ScheduleResolveOrReject();
    return;
  }
  // TODO(esprehn): This is a hack, instead we should CHECK that
  // script is allowed, and v8 should be running the entry hooks below and
  // crashing if script is forbidden. We should then audit all users of
  // ScriptPromiseResolverBase and the related specs and switch to an async
  // resolve.
  // See: http://crbug.com/663476
  if (ScriptForbiddenScope::IsScriptForbidden()) {
    ScheduleResolveOrReject();
    return;
  }
  ResolveOrRejectImmediately();
}

void ScriptPromiseResolverBase::ResolveOrRejectImmediately() {
  DCHECK(!GetExecutionContext()->IsContextDestroyed());
  DCHECK(!GetExecutionContext()->IsContextPaused());

  probe::WillHandlePromise(GetExecutionContext(), script_state_,
                           state_ == kResolving,
                           exception_context_.GetClassName(),
                           exception_context_.GetPropertyName(), script_url_);

  v8::MicrotasksScope microtasks_scope(
      script_state_->GetIsolate(), ToMicrotaskQueue(script_state_),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  auto resolver = resolver_.Get(script_state_->GetIsolate());
  if (state_ == kResolving) {
    std::ignore = resolver->Resolve(script_state_->GetContext(),
                                    value_.Get(script_state_->GetIsolate()));
  } else {
    DCHECK_EQ(state_, kRejecting);
    std::ignore = resolver->Reject(script_state_->GetContext(),
                                   value_.Get(script_state_->GetIsolate()));
  }

  // Don't reset `resolver_`, so that Promise() still works.
  state_ = kDone;
  value_.Reset();
}

void ScriptPromiseResolverBase::ScheduleResolveOrReject() {
  GetExecutionContext()
      ->GetTaskRunner(TaskType::kMicrotask)
      ->PostTask(
          FROM_HERE,
          WTF::BindOnce(&ScriptPromiseResolverBase::ResolveOrRejectDeferred,
                        WrapPersistent(this)));
}

void ScriptPromiseResolverBase::ResolveOrRejectDeferred() {
  DCHECK(state_ == kResolving || state_ == kRejecting);
  if (!GetExecutionContext()) {
    return;
  }

  ScriptState::Scope scope(script_state_.Get());
  ResolveOrRejectImmediately();
}

void ScriptPromiseResolverBase::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(resolver_);
  visitor->Trace(value_);
}

ExecutionContext* ScriptPromiseResolverBase::GetExecutionContext() {
  if (!GetScriptState()->ContextIsValid()) {
    return nullptr;
  }
  auto* execution_context = ExecutionContext::From(script_state_);
  return execution_context->IsContextDestroyed() ? nullptr : execution_context;
}

}  // namespace blink
```
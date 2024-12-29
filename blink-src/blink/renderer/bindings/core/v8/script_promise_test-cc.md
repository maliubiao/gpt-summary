Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The core request is to understand the purpose of the `script_promise_test.cc` file in the Chromium Blink engine. This immediately signals that the file is a unit test suite for the `ScriptPromise` class.

2. **Identify Key Components:**  Scan the `#include` directives. These are crucial clues about the file's dependencies and what it interacts with:
    * `script_promise.h`: This is the header file for the class being tested, the central focus.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates the use of the Google Test framework. This confirms it's a test file.
    * Headers related to V8 (`idl_types.h`, `native_value_traits_impl.h`, `script_function.h`, `script_promise_resolver.h`, `script_value.h`, `to_v8_traits.h`, `v8_binding_for_core.h`, `v8_binding_for_testing.h`, `v8/include/v8.h`):  These highlight the interaction with the V8 JavaScript engine, which is how promises are implemented in Blink.
    * Headers related to Blink core (`document.h`, `dom_exception.h`, `local_dom_window.h`, `null_execution_context.h`): This suggests testing how promises interact with the DOM and other core Blink concepts.
    * Headers related to platform (`heap/garbage_collected.h`, `testing/task_environment.h`): These point to memory management and asynchronous task handling, both relevant to promises.

3. **Analyze the Test Structure:** Look for the `TEST()` macros. Each `TEST()` block defines an individual test case. Notice the naming convention (`ScriptPromiseTest`, `ThenResolve`, `ThenReject`, etc.). This gives a high-level overview of the functionalities being tested.

4. **Examine Individual Test Cases:**  Pick a few representative test cases and analyze their structure. For example, `ThenResolve`:
    * It sets up a `ScriptPromiseResolver`.
    * It creates `ResolveString` and `AnyCallable` objects (which are custom callbacks).
    * It uses `promise.Then()` to attach these callbacks.
    * It performs microtask checkpoints (`scope.PerformMicrotaskCheckpoint()`). This is critical for understanding asynchronous promise behavior.
    * It resolves the promise using `resolver->Resolve()`.
    * It asserts the expected state of the callbacks (`resolve->react_called`, `reject->react_called`, `resolve->resolve_string`).

5. **Identify Patterns and Common Elements:** Notice the recurring use of:
    * `V8TestingScope`:  A helper class for setting up the V8 environment.
    * `MakeGarbageCollected`:  Indicates manual memory management using Blink's garbage collection.
    * Custom callback structs (like `ResolveString`, `AnyCallable`, `ThrowingCallable`): These are used to observe the behavior of the promise callbacks.
    * `scope.PerformMicrotaskCheckpoint()`: This is consistently used to trigger promise resolution and rejection handlers.

6. **Connect to JavaScript/Web Concepts:**  Relate the C++ code to JavaScript promise behavior:
    * `ThenResolve`/`ThenReject`: Directly map to the `.then()` method's resolve and reject handlers.
    * `ThrowingOnFulfilled`/`ThrowingOnRejected`: Test error handling within promise chains.
    * `CastPromise`/`CastNonPromise`: Check the conversion between V8's native promises and Blink's `ScriptPromise` wrapper.
    * `Reject`/`RejectWithDOMException`: Test different ways a promise can be rejected.
    * `RejectTypeMismatch`:  Demonstrates how promises handle type errors when resolving with an unexpected type.
    * `ChainPromisesWithDifferentResolveTypes`: Shows how `.then()` can transform the resolved value's type.

7. **Infer Functionality:** Based on the test cases, deduce the core functionalities of `ScriptPromise`:
    * Creation and resolution/rejection.
    * Attaching `then` callbacks.
    * Asynchronous execution of callbacks (via microtasks).
    * Error propagation in promise chains.
    * Handling different resolve/reject values and types.
    * Interoperability with native V8 promises.

8. **Consider User Errors and Debugging:** Think about how a developer using promises in JavaScript might encounter issues that these tests cover:
    * Not handling rejections.
    * Errors in `then` callbacks causing unexpected behavior.
    * Type mismatches when working with promise results.
    * Understanding the asynchronous nature of promises.

9. **Trace User Actions:**  Imagine a sequence of user interactions that could lead to the code being executed. This requires some understanding of how browser features use promises internally (e.g., network requests, asynchronous APIs).

10. **Structure the Output:** Organize the findings logically, covering the requested points: functionality, relationship to web technologies, logical reasoning (input/output of tests), common errors, and debugging. Use clear language and provide specific examples from the code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just a basic test file."  **Correction:** Realized the depth of testing, covering various edge cases and interactions with V8.
* **Confusion about microtasks:**  Initially might not fully grasp the importance of `PerformMicrotaskCheckpoint`. **Refinement:**  Recognized that this is key to simulating the asynchronous nature of promises.
* **Overlooking the custom callbacks:**  Might initially treat `ResolveString` as just boilerplate. **Refinement:**  Understood that these callbacks are crucial for observing the promise's behavior.
* **Vague connection to web technologies:**  Initially might just say "it's related to promises." **Refinement:**  Provided concrete examples of how JavaScript promise features map to the C++ tests.

By following these steps, combining code analysis with an understanding of web development concepts, and iteratively refining the understanding, one can effectively analyze the functionality of the `script_promise_test.cc` file.
这个文件 `blink/renderer/bindings/core/v8/script_promise_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件，专门用于测试 `ScriptPromise` 类的功能。`ScriptPromise` 类是 Blink 对 JavaScript Promise 规范的 C++ 实现的封装。

**主要功能:**

1. **测试 `ScriptPromise` 的创建和状态转换:**
   - 测试如何创建一个 Promise 对象。
   - 测试 Promise 如何从 pending 状态转换为 fulfilled (已解决) 或 rejected (已拒绝) 状态。
   - 测试 Promise 的状态一旦确定就不可更改。

2. **测试 `then` 方法的行为:**
   - 测试在 Promise fulfilled 时，`then` 方法的 onFulfilled 回调函数是否被正确调用。
   - 测试在 Promise rejected 时，`then` 方法的 onRejected 回调函数是否被正确调用。
   - 测试 `then` 方法返回的新 Promise 的状态和值，包括 fulfilled 和 rejected 的情况。
   - 测试 `then` 方法中抛出异常时的行为，以及它如何影响返回的 Promise 的状态。
   - 测试当 `then` 的回调函数本身返回一个 Promise 时，如何进行 Promise 链式调用。

3. **测试 Promise 的解决 (resolve) 和拒绝 (reject) 机制:**
   - 测试使用 `ScriptPromiseResolver` 来解决和拒绝 Promise。
   - 测试当 Promise 已经被解决或拒绝后，再次调用 resolve 或 reject 的效果。

4. **测试 Promise 的类型转换和互操作性:**
   - 测试从 V8 的原生 `v8::Promise` 对象创建 `ScriptPromise` 对象。
   - 测试将其他类型的 JavaScript 值转换为已解决的 `ScriptPromise` 对象。
   - 测试当 Promise 尝试解决为错误类型的值时（类型不匹配）的行为。

5. **测试 Promise 与 DOM 异常的交互:**
   - 测试使用 `RejectWithDOMException` 来拒绝 Promise，并确保 rejection 的值是正确的 `DOMException` 对象。

6. **测试异步执行:**
   - 测试 Promise 的回调函数是异步执行的，通常在微任务队列中。
   - 使用 `PerformMicrotaskCheckpoint` 来模拟微任务的执行。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关系到 JavaScript 中的 Promise 功能。Promise 是 JavaScript 中处理异步操作的重要机制。

* **JavaScript Promise:**  `ScriptPromise` 是 Blink 引擎对 JavaScript Promise 的 C++ 实现。这个测试文件确保了 Blink 引擎中的 Promise 实现与 JavaScript 规范的行为一致。

   **举例:** 当 JavaScript 代码中执行以下操作时，Blink 引擎会创建并操作 `ScriptPromise` 对象：
   ```javascript
   let promise = new Promise((resolve, reject) => {
     setTimeout(() => {
       resolve("Hello from Promise!");
     }, 1000);
   });

   promise.then(result => {
     console.log(result); // 一秒后输出 "Hello from Promise!"
   });
   ```
   `script_promise_test.cc` 中的测试用例，例如 `ThenResolve` 和 `ThenReject`，就是为了验证这种 `then` 方法的行为在 Blink 引擎中是否正确。

* **与 HTML 的关系 (间接):**  许多浏览器 API，例如 `fetch`、`XMLHttpRequest` 以及一些与用户交互相关的 API (如 `navigator.mediaDevices.getUserMedia()`) 返回的是 Promise。`ScriptPromise` 的正确性直接影响这些 API 在网页上的行为。

   **举例:** 当 JavaScript 使用 `fetch` API 发起网络请求时：
   ```javascript
   fetch('https://example.com/data.json')
     .then(response => response.json())
     .then(data => console.log(data));
   ```
   Blink 引擎会创建 `ScriptPromise` 对象来管理这个异步请求的生命周期。 `script_promise_test.cc` 中的测试用例，如测试 Promise 链式调用的场景，就与此相关。

* **与 CSS 的关系 (间接):**  虽然 CSS 本身不直接涉及 Promise，但与 JavaScript 结合使用时，Promise 可以用于处理与 CSS 相关的异步操作，例如动态加载 CSS 文件或处理 CSS 动画和过渡的完成事件 (某些 API 可能返回 Promise)。

   **举例:**  考虑一个动态加载 CSS 的场景：
   ```javascript
   function loadCSS(url) {
     return new Promise((resolve, reject) => {
       const link = document.createElement('link');
       link.rel = 'stylesheet';
       link.href = url;
       link.onload = resolve;
       link.onerror = reject;
       document.head.appendChild(link);
     });
   }

   loadCSS('styles.css').then(() => {
     console.log('CSS loaded!');
   }).catch(() => {
     console.error('Failed to load CSS.');
   });
   ```
   虽然 `script_promise_test.cc` 不会直接测试 CSS 加载，但它测试了 `ScriptPromise` 自身的功能，这对于像 `loadCSS` 这样的异步操作的正确性至关重要。

**逻辑推理 (假设输入与输出):**

让我们以 `TEST(ScriptPromiseTest, ThenResolve)` 这个测试用例为例：

**假设输入:**

1. 创建一个 `ScriptPromiseResolver` 对象 `resolver`。
2. 通过 `resolver->Promise()` 获取一个 `ScriptPromise` 对象 `promise`。
3. 创建一个 `ResolveString` 类型的回调对象 `resolve` 和一个 `AnyCallable` 类型的回调对象 `reject`。
4. 调用 `promise.Then(scope.GetScriptState(), resolve, reject)` 来注册回调函数。
5. 调用 `resolver->Resolve("hello")` 来解决 Promise，并将值设置为 "hello"。
6. 执行微任务检查点 `scope.PerformMicrotaskCheckpoint()`。

**预期输出:**

1. 在第一个微任务检查点之前，`resolve->react_called` 和 `reject->react_called` 都为 `false`。
2. 在 `resolver->Resolve("hello")` 被调用后，立即检查，`resolve->react_called` 和 `reject->react_called` 仍然为 `false` (因为回调是异步的)。
3. 在第二个微任务检查点之后：
   - `resolve->react_called` 为 `true`，表示 resolve 回调被调用。
   - `reject->react_called` 为 `false`，表示 reject 回调没有被调用。
   - `resolve->resolve_string` 的值为 "hello"，表示 resolve 回调接收到的值正确。

**用户或编程常见的使用错误及举例说明:**

1. **未处理 Promise 的 rejection:** 如果 Promise 被拒绝，并且没有提供 `.catch()` 或第二个 `.then()` 回调来处理 rejection，可能会导致未捕获的错误。

   **例子 (JavaScript):**
   ```javascript
   // 假设 fetchData 返回一个 Promise，可能会被 reject
   fetchData().then(data => {
     console.log(data);
   });
   // 如果 fetchData 的 Promise 被 reject，这里没有处理，可能会在控制台看到错误。
   ```
   `script_promise_test.cc` 中的测试用例会验证在没有提供 rejection 处理程序时，Promise 的行为是否符合预期。

2. **在 `then` 回调中抛出异常:** 如果 `then` 的 onFulfilled 或 onRejected 回调中抛出异常，该异常会被捕获并导致返回的 Promise 被 rejected。

   **例子 (JavaScript):**
   ```javascript
   promise.then(data => {
     throw new Error("Something went wrong in onFulfilled");
     return data;
   }).catch(error => {
     console.error("Caught an error:", error);
   });
   ```
   `script_promise_test.cc` 中的 `ThrowingOnFulfilled` 和 `ThrowingOnRejected` 测试用例就是为了覆盖这种情况。

3. **类型错误:**  尝试用不兼容的类型解决 Promise，这在 C++ 代码中尤为重要，因为有更强的类型检查。

   **例子 (对应 `RejectTypeMismatch` 测试):**  在 Blink 内部，如果一个期望解决为 `Document` 类型的 Promise 实际上解决为了 `LocalDOMWindow` 类型，就会触发类型错误。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在网页上执行了某个操作，导致一个使用 Promise 的 JavaScript API 被调用，并且这个 Promise 最终因为某种原因被拒绝，我们可以跟踪这个过程：

1. **用户操作:** 用户点击了一个按钮，触发了一个 JavaScript 事件处理函数。
2. **JavaScript 代码执行:** 事件处理函数调用了一个会返回 Promise 的 Web API，例如 `fetch` 请求一个不存在的资源。
   ```javascript
   document.getElementById('myButton').addEventListener('click', () => {
     fetch('/nonexistent-resource')
       .then(response => response.json())
       .then(data => console.log(data))
       .catch(error => console.error("Fetch failed:", error));
   });
   ```
3. **Blink 引擎处理 `fetch`:** Blink 的网络模块处理 `fetch` 请求，发现资源不存在，因此 Promise 会被 reject。
4. **`ScriptPromise` 对象的状态改变:**  与这个 `fetch` 请求关联的 `ScriptPromise` 对象的状态从 pending 变为 rejected。
5. **`then` 或 `catch` 回调执行:**  由于上面的 JavaScript 代码提供了 `.catch()` 回调，这个回调函数会被放入微任务队列等待执行。
6. **微任务执行:** Blink 的事件循环处理微任务队列，执行 `.catch()` 回调。

**调试线索:**

* 如果在 `.catch()` 回调中设置断点，可以观察到 Promise 的 rejection 值。
* 如果在 Blink 的 C++ 代码中设置断点，例如在 `ScriptPromise::Reject` 或 `ScriptPromise::Then` 的实现中，可以更深入地了解 Promise 状态转换和回调执行的细节。
* `script_promise_test.cc` 中的测试用例模拟了这些状态转换和回调执行的各种场景，可以帮助开发者理解 Promise 的内部工作原理，从而更好地调试问题。

总而言之，`blink/renderer/bindings/core/v8/script_promise_test.cc` 是 Blink 引擎中至关重要的测试文件，它确保了 `ScriptPromise` 类的正确性和可靠性，这直接关系到网页上基于 Promise 的 JavaScript 代码的正常运行。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/script_promise_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2014 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

String ToString(v8::Local<v8::Context> context, const ScriptValue& value) {
  return ToCoreString(context->GetIsolate(),
                      value.V8Value()->ToString(context).ToLocalChecked());
}

struct ResolveString final : public ThenCallable<IDLString, ResolveString> {
 public:
  void React(ScriptState*, String value) {
    react_called = true;
    resolve_string = value;
  }
  bool react_called = false;
  String resolve_string;
};

struct AnyCallable final : public ThenCallable<IDLAny, AnyCallable> {
 public:
  void React(ScriptState*, ScriptValue value) {
    react_called = true;
    react_value = value;
  }
  void Trace(Visitor* visitor) const final {
    visitor->Trace(react_value);
    ThenCallable<IDLAny, AnyCallable>::Trace(visitor);
  }
  bool react_called = false;
  ScriptValue react_value;
};

struct AnyChainingCallable final
    : public ThenCallable<IDLAny, AnyChainingCallable, IDLAny> {
 public:
  ScriptValue React(ScriptState*, ScriptValue value) {
    react_called = true;
    react_value = value;
    return value;
  }
  void Trace(Visitor* visitor) const final {
    visitor->Trace(react_value);
    ThenCallable<IDLAny, AnyChainingCallable, IDLAny>::Trace(visitor);
  }
  bool react_called = false;
  ScriptValue react_value;
};

struct ThrowingCallable final
    : public ThenCallable<IDLAny, ThrowingCallable, IDLAny> {
 public:
  ScriptValue React(ScriptState* script_state, ScriptValue value) {
    v8::Isolate* isolate = script_state->GetIsolate();
    isolate->ThrowException(v8::Undefined(isolate));
    return value;
  }
};

struct ResolveDocument final : public ThenCallable<Document, ResolveDocument> {
 public:
  void React(ScriptState*, Document*) { react_called = true; }
  bool react_called = false;
};

struct ConvertAnyToStringCallable
    : public ThenCallable<IDLAny, ConvertAnyToStringCallable, IDLString> {
 public:
  String React(ScriptState* script_state, ScriptValue value) {
    react_called = true;
    return ToString(script_state->GetContext(), value);
  }
  bool react_called = false;
};

TEST(ScriptPromiseTest, ThenResolve) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
      scope.GetScriptState());
  auto promise = resolver->Promise();
  auto* resolve = MakeGarbageCollected<ResolveString>();
  auto* reject = MakeGarbageCollected<AnyCallable>();
  promise.Then(scope.GetScriptState(), resolve, reject);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_FALSE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);

  scope.PerformMicrotaskCheckpoint();
  resolver->Resolve("hello");

  EXPECT_FALSE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_TRUE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);
  EXPECT_EQ("hello", resolve->resolve_string);
}

TEST(ScriptPromiseTest, ThenOnAlreadyResolvedPromise) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto promise = ToResolvedPromise<IDLString>(scope.GetScriptState(), "hello");
  auto* resolve = MakeGarbageCollected<ResolveString>();
  auto* reject = MakeGarbageCollected<AnyCallable>();
  promise.Then(scope.GetScriptState(), resolve, reject);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_FALSE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_TRUE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);
  EXPECT_EQ("hello", resolve->resolve_string);
}

TEST(ScriptPromiseTest, ThenReject) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
      scope.GetScriptState());
  auto promise = resolver->Promise();
  auto* resolve = MakeGarbageCollected<ResolveString>();
  auto* reject = MakeGarbageCollected<AnyCallable>();
  promise.Then(scope.GetScriptState(), resolve, reject);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_FALSE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);

  scope.PerformMicrotaskCheckpoint();
  resolver->Reject(V8String(scope.GetIsolate(), "hello"));

  EXPECT_FALSE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_FALSE(resolve->react_called);
  EXPECT_TRUE(reject->react_called);
  EXPECT_EQ("hello", ToString(scope.GetContext(), reject->react_value));
}

TEST(ScriptPromiseTest, ThrowingOnFulfilled) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto promise = resolver->Promise();

  auto* throwing = MakeGarbageCollected<ThrowingCallable>();
  auto* resolve2 = MakeGarbageCollected<AnyCallable>();
  auto* reject1 = MakeGarbageCollected<AnyChainingCallable>();
  auto* reject2 = MakeGarbageCollected<AnyCallable>();
  auto promise2 = promise.Then(scope.GetScriptState(), throwing, reject1);
  promise2.Then(scope.GetScriptState(), resolve2, reject2);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_FALSE(resolve2->react_called);
  EXPECT_FALSE(reject1->react_called);
  EXPECT_FALSE(reject2->react_called);

  scope.PerformMicrotaskCheckpoint();
  resolver->Resolve(v8::Null(scope.GetIsolate()));

  EXPECT_FALSE(resolve2->react_called);
  EXPECT_FALSE(reject1->react_called);
  EXPECT_FALSE(reject2->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_FALSE(resolve2->react_called);
  EXPECT_FALSE(reject1->react_called);
  EXPECT_TRUE(reject2->react_called);
}

TEST(ScriptPromiseTest, ThrowingOnRejected) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto promise = resolver->Promise();

  auto* throwing = MakeGarbageCollected<ThrowingCallable>();
  auto* resolve1 = MakeGarbageCollected<AnyChainingCallable>();
  auto* resolve2 = MakeGarbageCollected<AnyCallable>();
  auto* reject2 = MakeGarbageCollected<AnyCallable>();
  auto promise2 = promise.Then(scope.GetScriptState(), resolve1, throwing);
  promise2.Then(scope.GetScriptState(), resolve2, reject2);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_FALSE(resolve1->react_called);
  EXPECT_FALSE(resolve2->react_called);
  EXPECT_FALSE(reject2->react_called);

  scope.PerformMicrotaskCheckpoint();
  resolver->Reject(V8String(scope.GetIsolate(), "hello"));

  EXPECT_FALSE(resolve1->react_called);
  EXPECT_FALSE(resolve2->react_called);
  EXPECT_FALSE(reject2->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_FALSE(resolve1->react_called);
  EXPECT_FALSE(resolve2->react_called);
  EXPECT_TRUE(reject2->react_called);
}

TEST(ScriptPromiseTest, ThenOnAlreadyRejectedPromise) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto promise = ScriptPromise<IDLString>::Reject(
      scope.GetScriptState(), V8String(scope.GetIsolate(), "hello"));
  auto* resolve = MakeGarbageCollected<ResolveString>();
  auto* reject = MakeGarbageCollected<AnyCallable>();
  promise.Then(scope.GetScriptState(), resolve, reject);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_FALSE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_FALSE(resolve->react_called);
  EXPECT_TRUE(reject->react_called);
  EXPECT_EQ("hello", ToString(scope.GetContext(), reject->react_value));
}

TEST(ScriptPromiseTest, CastPromise) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto resolver = v8::Promise::Resolver::New(scope.GetContext());
  v8::Local<v8::Promise> promise = resolver.ToLocalChecked()->GetPromise();
  auto new_promise =
      ScriptPromise<IDLAny>::FromV8Promise(scope.GetIsolate(), promise);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_EQ(promise, new_promise.V8Promise());
}

TEST(ScriptPromiseTest, CastNonPromise) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScriptValue value =
      ScriptValue(scope.GetIsolate(), V8String(scope.GetIsolate(), "hello"));
  ScriptPromise<IDLAny> promise1 =
      ToResolvedPromise<IDLAny>(scope.GetScriptState(), value);
  ScriptPromise<IDLAny> promise2 =
      ToResolvedPromise<IDLAny>(scope.GetScriptState(), value);
  auto* resolve1 = MakeGarbageCollected<AnyChainingCallable>();
  auto* reject1 = MakeGarbageCollected<AnyChainingCallable>();
  promise1.Then(scope.GetScriptState(), resolve1, reject1);
  auto* resolve2 = MakeGarbageCollected<AnyCallable>();
  auto* reject2 = MakeGarbageCollected<AnyCallable>();
  promise2.Then(scope.GetScriptState(), resolve2, reject2);

  ASSERT_FALSE(promise1.IsEmpty());
  ASSERT_FALSE(promise2.IsEmpty());
  EXPECT_NE(promise1.V8Promise(), promise2.V8Promise());

  EXPECT_FALSE(resolve1->react_called);
  EXPECT_FALSE(reject1->react_called);
  EXPECT_FALSE(resolve2->react_called);
  EXPECT_FALSE(reject2->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_TRUE(resolve1->react_called);
  EXPECT_FALSE(reject1->react_called);
  EXPECT_TRUE(resolve2->react_called);
  EXPECT_FALSE(reject2->react_called);
  EXPECT_EQ("hello", ToString(scope.GetContext(), resolve1->react_value));
  EXPECT_EQ("hello", ToString(scope.GetContext(), resolve2->react_value));
}

TEST(ScriptPromiseTest, Reject) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScriptValue value =
      ScriptValue(scope.GetIsolate(), V8String(scope.GetIsolate(), "hello"));
  auto promise = ScriptPromise<IDLString>::Reject(scope.GetScriptState(),
                                                  ScriptValue(value));
  auto* resolve = MakeGarbageCollected<ResolveString>();
  auto* reject = MakeGarbageCollected<AnyCallable>();
  promise.Then(scope.GetScriptState(), resolve, reject);

  ASSERT_FALSE(promise.IsEmpty());

  EXPECT_FALSE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_FALSE(resolve->react_called);
  EXPECT_TRUE(reject->react_called);
  EXPECT_EQ("hello", ToString(scope.GetContext(), reject->react_value));
}

TEST(ScriptPromiseTest, RejectWithDOMException) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto promise = ScriptPromise<IDLString>::RejectWithDOMException(
      scope.GetScriptState(),
      MakeGarbageCollected<DOMException>(DOMExceptionCode::kSyntaxError,
                                         "some syntax error"));
  auto* resolve = MakeGarbageCollected<ResolveString>();
  auto* reject = MakeGarbageCollected<AnyCallable>();
  promise.Then(scope.GetScriptState(), resolve, reject);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_FALSE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_FALSE(resolve->react_called);
  EXPECT_TRUE(reject->react_called);
  EXPECT_EQ("SyntaxError: some syntax error",
            ToString(scope.GetContext(), reject->react_value));
}

TEST(ScriptPromiseTest, RejectTypeMismatch) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

  auto promise = ScriptPromise<Document>::FromV8Value(
      script_state,
      ToV8Traits<LocalDOMWindow>::ToV8(script_state, &scope.GetWindow()));

  auto* resolve = MakeGarbageCollected<ResolveDocument>();
  auto* reject = MakeGarbageCollected<AnyCallable>();
  promise.Then(scope.GetScriptState(), resolve, reject);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_FALSE(resolve->react_called);
  EXPECT_FALSE(reject->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_FALSE(resolve->react_called);
  EXPECT_TRUE(reject->react_called);

  EXPECT_FALSE(reject->react_value.IsEmpty());
  EXPECT_EQ("TypeError: Failed to convert value to 'Document'.",
            ToString(scope.GetContext(), reject->react_value));
}

TEST(ScriptPromiseTest, ChainPromisesWithDifferentResolveTypes) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto promise = resolver->Promise();

  auto* resolve1 = MakeGarbageCollected<ConvertAnyToStringCallable>();
  auto* reject1 = MakeGarbageCollected<AnyChainingCallable>();
  auto promise2 =
      promise.Then<IDLString>(scope.GetScriptState(), resolve1, reject1);

  auto* resolve2 = MakeGarbageCollected<ResolveString>();
  auto* reject2 = MakeGarbageCollected<AnyCallable>();
  promise2.Then(scope.GetScriptState(), resolve2, reject2);

  ASSERT_FALSE(promise.IsEmpty());
  EXPECT_FALSE(resolve1->react_called);
  EXPECT_FALSE(reject1->react_called);
  EXPECT_FALSE(resolve2->react_called);
  EXPECT_FALSE(reject2->react_called);

  scope.PerformMicrotaskCheckpoint();
  resolver->Resolve(V8String(scope.GetIsolate(), "hello"));

  EXPECT_FALSE(resolve1->react_called);
  EXPECT_FALSE(reject1->react_called);
  EXPECT_FALSE(resolve2->react_called);
  EXPECT_FALSE(reject2->react_called);

  scope.PerformMicrotaskCheckpoint();

  EXPECT_TRUE(resolve1->react_called);
  EXPECT_FALSE(reject1->react_called);
  EXPECT_TRUE(resolve2->react_called);
  EXPECT_FALSE(reject2->react_called);
  EXPECT_EQ("hello", resolve2->resolve_string);
}

}  // namespace

}  // namespace blink

"""

```
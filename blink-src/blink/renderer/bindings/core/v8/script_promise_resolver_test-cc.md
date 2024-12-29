Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `script_promise_resolver_test.cc`. This involves identifying what it tests, how it relates to web technologies (JavaScript, HTML, CSS), and what potential developer errors it might expose.

**2. Initial Scan and Keyword Identification:**

A quick scan of the code reveals key terms:

* `ScriptPromiseResolver`: This is the core component being tested. The filename confirms this.
* `ScriptPromise`:  Promises are fundamental to asynchronous JavaScript.
* `resolve`, `reject`:  These are the core actions of a promise.
* `ThenCallable`: Suggests testing the `then` method of promises.
* `ScriptState`, `ExecutionContext`, `v8::Isolate`:  These point to the JavaScript execution environment within Blink.
* `TEST_F`: This indicates the use of Google Test framework for unit testing.
* `DummyPageHolder`, `LocalFrame`, `LocalDOMWindow`: These are Blink-specific classes related to page structure.
* `PerformMicrotaskCheckpoint`: This is crucial for understanding asynchronous behavior in JavaScript and how it's being tested.

**3. Deeper Dive into Test Cases:**

Now, let's analyze each `TEST_F` function individually:

* **`construct`**:  Verifies that a `ScriptPromiseResolver` can be created without crashing. This is a basic sanity check.
* **`resolve`**:  This is a core test. It checks:
    * Creating a resolver and a promise.
    * Attaching `then` handlers (`TestResolveFunction`, `TestRejectFunction`).
    * Resolving the promise with a value.
    * Verifying that the `on_fulfilled` handler is called with the correct value and `on_rejected` is not called.
    * Testing that subsequent calls to `resolve` and `reject` after the promise is resolved have no effect.
* **`reject`**: Similar to `resolve`, but tests the rejection path of the promise.
* **`stop`**:  Tests the scenario where the execution context (and thus the JavaScript environment) is destroyed *before* the promise is resolved. It checks that the `then` handlers are not called. This is important for resource management and preventing crashes.
* **`resolveUndefined`**: Tests resolving the promise without an explicit value, verifying that the `on_fulfilled` handler receives `undefined`.
* **`rejectUndefined`**: Tests rejecting the promise without an explicit value, verifying that the `on_rejected` handler receives `undefined`.
* **`OverrideScriptStateToCurrentContext`**: This is more complex. It involves iframes and different script contexts. It tests the `ResolveOverridingToCurrentContext` method, which seems designed to resolve the promise in a *different* JavaScript context than where it was originally created. This is likely related to how promises are handled across frame boundaries.

**4. Connecting to Web Technologies:**

Now, let's link the observed behavior to JavaScript, HTML, and CSS:

* **JavaScript:** The entire file revolves around testing the implementation of JavaScript Promises in Blink. The `resolve` and `reject` methods directly correspond to the JavaScript Promise API. The `then` method is also a core part of the Promise API.
* **HTML:** The `OverrideScriptStateToCurrentContext` test uses iframes, which are an HTML concept for embedding other web pages. This highlights the interaction of promises across different HTML documents within the same browser tab.
* **CSS:** While not directly involved, CSS rendering might be triggered as a *side effect* of JavaScript promise resolution, especially if the promise resolution modifies the DOM, leading to style recalculations and layout. However, this test file doesn't directly test CSS interaction.

**5. Logical Reasoning and Assumptions:**

For the `resolve` and `reject` tests, we can make assumptions about the input and expected output:

* **Input (for `resolve`):**  A promise is created, a `then` handler is attached, and the promise is resolved with the string "hello".
* **Output (for `resolve`):** The `on_fulfilled` handler will be called with the string "hello", and the `on_rejected` handler will not be called.

Similar reasoning applies to the `reject` test.

**6. Identifying Potential User/Programming Errors:**

Based on the tests, potential errors include:

* **Forgetting to handle rejections:** If a promise is rejected and there's no rejection handler attached (or no `.catch()` in JavaScript), the error might go unhandled.
* **Incorrectly assuming synchronous execution:** Promises are asynchronous. The tests emphasize the need for `PerformMicrotaskCheckpoint` to simulate the event loop processing. Developers might make mistakes if they expect code after a promise resolution to execute immediately.
* **Race conditions in asynchronous operations:** If multiple promises are involved, developers need to carefully manage the order of operations and potential race conditions.
* **Memory leaks (potentially addressed by the `stop` test):** If promise resolvers aren't properly cleaned up when their associated execution context is destroyed, it could lead to memory leaks.

**7. Tracing User Actions (Debugging Clues):**

To reach the code being tested, a user action would involve triggering a JavaScript promise within a web page. Here's a possible sequence:

1. **User interacts with a web page:** Clicks a button, submits a form, etc.
2. **JavaScript code is executed:** This code might create a new promise, for example, using `fetch()` to make a network request.
3. **The promise resolves or rejects:**  The network request succeeds or fails.
4. **The `then()` or `catch()` handlers are executed:**  These handlers might manipulate the DOM or perform other actions.

If something goes wrong in this process (e.g., the `then` handler isn't called when expected, or an error isn't caught), a developer might need to debug the promise resolution logic. The test file provides insights into how Blink's promise implementation behaves and can help developers understand potential issues.

**8. Iterative Refinement:**

Throughout this process, I would continually refer back to the code to confirm my understanding and refine my analysis. For example, noticing the `MakeGarbageCollected` calls reinforces the idea of memory management being important. Seeing the different `ScriptState::Scope` blocks highlights the importance of the JavaScript execution context.
这个文件 `script_promise_resolver_test.cc` 是 Chromium Blink 引擎中用于测试 `ScriptPromiseResolver` 类的单元测试文件。 `ScriptPromiseResolver` 是 Blink 内部用来管理 JavaScript Promise 对象的解析和拒绝的机制。

**文件功能总结:**

* **测试 `ScriptPromiseResolver` 的创建和销毁:**  验证 `ScriptPromiseResolver` 对象能否正确创建且不会导致内存泄漏。
* **测试 Promise 的 `resolve` 方法:** 验证当 `ScriptPromiseResolver` 调用 `Resolve` 方法时，相关的 Promise 对象的状态会变成 fulfilled，并且注册的 `then` 回调会被执行。
* **测试 Promise 的 `reject` 方法:** 验证当 `ScriptPromiseResolver` 调用 `Reject` 方法时，相关的 Promise 对象的状态会变成 rejected，并且注册的 `catch` 或 `then` 的拒绝回调会被执行。
* **测试在执行上下文销毁后 Promise 的行为:** 验证当关联的 JavaScript 执行上下文被销毁后，`ScriptPromiseResolver` 的操作不会导致崩溃或其他异常。
* **测试 `resolve` 和 `reject` 方法处理 `undefined` 值的情况:** 验证当 `resolve` 或 `reject` 不带参数调用时，Promise 的回调如何接收 `undefined` 值。
* **测试跨 JavaScript 上下文的 Promise 解析:** 验证 `ResolveOverridingToCurrentContext` 方法能在不同的 JavaScript 上下文中解析 Promise。

**与 JavaScript, HTML, CSS 的关系及举例:**

`ScriptPromiseResolver` 是 Blink 引擎中实现 JavaScript Promise 机制的关键部分，因此它与 JavaScript 的异步编程模型紧密相关。

* **JavaScript Promise:** `ScriptPromiseResolver` 的核心功能就是管理和控制 JavaScript Promise 的状态和结果。当 JavaScript 代码创建一个 Promise 对象时，通常会关联一个内部的 `ScriptPromiseResolver`。
    * **例子:** 在 JavaScript 中，你可能会这样创建一个 Promise:
      ```javascript
      const myPromise = new Promise((resolve, reject) => {
        setTimeout(() => {
          const data = "Hello from Promise!";
          resolve(data); // 调用 resolve，对应的 ScriptPromiseResolver 会被调用
        }, 1000);
      });

      myPromise.then(result => {
        console.log(result); // "Hello from Promise!"
      });
      ```
      在这个例子中，JavaScript 的 `resolve` 函数的调用最终会触发 Blink 引擎中关联的 `ScriptPromiseResolver` 的 `Resolve` 方法。

* **HTML:**  Promise 经常用于处理与 HTML 页面交互相关的异步操作，例如网络请求（`fetch` API）。
    * **例子:**  使用 `fetch` API 获取 HTML 文档的一部分：
      ```javascript
      fetch('/data.json')
        .then(response => response.json()) // response.json() 返回一个 Promise
        .then(data => console.log(data));
      ```
      `fetch` 函数返回一个 Promise，当服务器响应到达时，该 Promise 会被解析（`resolve`）。Blink 引擎的 `ScriptPromiseResolver` 负责处理 `fetch` 返回的 Promise 的状态变化。

* **CSS:**  虽然 `ScriptPromiseResolver` 本身不直接处理 CSS，但 Promise 可能会被用于与 CSS 相关的异步操作，例如加载外部 CSS 文件或执行 CSS 动画的完成回调。
    * **例子 (理论上的，实际加载 CSS 通常不直接用 Promise):**  假设有一个 API 可以异步加载 CSS 文件并返回一个 Promise：
      ```javascript
      loadCSS('/styles.css').then(() => {
        console.log('CSS loaded successfully!');
      });
      ```
      在这种情况下，当 CSS 文件加载完成，Promise 会被解析。

**逻辑推理及假设输入与输出:**

以 `TEST_F(ScriptPromiseResolverBaseTest, resolve)` 这个测试为例：

* **假设输入:**
    1. 创建一个 `ScriptPromiseResolver<IDLString>` 对象。
    2. 获取其关联的 `ScriptPromise<IDLString>` 对象。
    3. 为该 Promise 注册一个 `then` 回调 ( `TestResolveFunction` ) 和一个拒绝回调 (`TestRejectFunction`)。
    4. 调用 `resolver->Resolve("hello");`。
    5. 执行微任务队列 ( `PerformMicrotaskCheckpoint()` )。
* **预期输出:**
    1. 在 `PerformMicrotaskCheckpoint()` 执行后，`on_fulfilled` 字符串变量的值会变成 "hello"。
    2. `on_rejected` 字符串变量的值仍然为空字符串。
    3. 后续对 `resolver->Resolve("bye")` 和 `resolver->Reject("bye")` 的调用不会改变 Promise 的状态，因为 Promise 只能被解析或拒绝一次。

**用户或编程常见的使用错误及举例:**

* **忘记处理 Promise 的拒绝 (Unhandled Rejection):**
    * **错误代码 (JavaScript):**
      ```javascript
      new Promise((resolve, reject) => {
        setTimeout(() => {
          reject("Something went wrong!");
        }, 100);
      }); // 没有 .catch() 或第二个 then 参数来处理拒绝
      ```
    * **说明:** 如果 Promise 被拒绝但没有提供拒绝处理程序，浏览器可能会输出一个 "Unhandled Rejection" 的警告。在 Blink 引擎内部，当 `ScriptPromiseResolver` 调用 `Reject` 且没有相应的拒绝处理程序时，会触发相应的机制。

* **在 Promise 状态确定后尝试再次解析或拒绝:**
    * **错误代码 (对应测试中的 `resolver->Resolve("bye");` 和 `resolver->Reject("bye");` 在第一次 `resolve` 之后):**  Promise 的状态一旦确定 (resolved 或 rejected)，就不能再改变。虽然代码可以执行多次 `resolve` 或 `reject`，但只有第一次调用会生效。开发者可能会错误地认为可以多次改变 Promise 的状态。

* **混淆同步和异步执行:**
    * **错误代码 (JavaScript):**
      ```javascript
      let result = null;
      new Promise(resolve => {
        setTimeout(() => {
          result = "Operation completed";
          resolve();
        }, 100);
      });
      console.log(result); // 可能在 Promise resolve 之前执行，输出 null
      ```
    * **说明:**  开发者需要理解 Promise 的回调是异步执行的。在 Promise 的状态确定之前，回调不会立即执行。`PerformMicrotaskCheckpoint()` 的作用就是模拟 JavaScript 的事件循环，触发微任务队列的执行，这正是 Promise 回调执行的时机。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个网页。**
2. **网页的 JavaScript 代码执行，创建了一个 Promise 对象。** 这可能是因为一个异步操作，例如 `fetch` 请求、`setTimeout` 或用户事件触发。
3. **创建 Promise 的代码内部，会关联一个 Blink 引擎的 `ScriptPromiseResolver` 对象。**
4. **当异步操作完成 (成功或失败) 时，JavaScript 代码会调用与 Promise 相关的 `resolve` 或 `reject` 函数。**
5. **这些 `resolve` 或 `reject` 函数的调用最终会调用到 Blink 引擎中对应的 `ScriptPromiseResolver` 的 `Resolve` 或 `Reject` 方法。**
6. **Blink 引擎会更新 Promise 的状态，并将结果传递给注册的 `then` 或 `catch` 回调。**
7. **如果在这个过程中出现问题 (例如，回调没有按预期执行，或者 Promise 状态管理出现错误)，开发者可能会需要查看 Blink 引擎的源代码，包括 `script_promise_resolver_test.cc`，来理解 Promise 的内部工作机制并找到错误原因。**

作为调试线索，`script_promise_resolver_test.cc` 提供了关于 `ScriptPromiseResolver` 如何工作的清晰示例。如果开发者在自己的 JavaScript 代码中遇到 Promise 相关的 Bug，他们可以参考这些测试用例，理解在各种情况下 Promise 应该如何表现。例如，如果一个 Promise 似乎没有被正确解析或拒绝，开发者可以查看 `resolve` 和 `reject` 的测试用例，确认他们的 JavaScript 代码是否按照预期的方式调用了 `resolve` 或 `reject`，以及是否正确处理了异步执行的顺序。 此外，`stop` 测试用例可以帮助理解当页面或上下文被销毁时，Promise 的行为，这对于处理资源释放和避免内存泄漏非常重要。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/script_promise_resolver_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"

#include <memory>

#include "base/run_loop.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

class TestResolveFunction
    : public ThenCallable<IDLString, TestResolveFunction> {
 public:
  explicit TestResolveFunction(String* value) : value_(value) {}
  void React(ScriptState*, String value) { *value_ = value; }

 private:
  String* value_;
};

class TestRejectFunction : public ThenCallable<IDLAny, TestRejectFunction> {
 public:
  explicit TestRejectFunction(String* value) : value_(value) {}

  void React(ScriptState* script_state, ScriptValue value) {
    DCHECK(!value.IsEmpty());
    *value_ = ToCoreString(
        script_state->GetIsolate(),
        value.V8Value()->ToString(script_state->GetContext()).ToLocalChecked());
  }

 private:
  String* value_;
};

class ScriptPromiseResolverBaseTest : public testing::Test {
 public:
  ScriptPromiseResolverBaseTest()
      : page_holder_(std::make_unique<DummyPageHolder>()) {}

  ~ScriptPromiseResolverBaseTest() override {
    // Execute all pending microtasks
    PerformMicrotaskCheckpoint();
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
  ScriptState* GetScriptState() const {
    return ToScriptStateForMainWorld(&page_holder_->GetFrame());
  }
  ExecutionContext* GetExecutionContext() const {
    return page_holder_->GetFrame().DomWindow();
  }
  v8::Isolate* GetIsolate() const { return GetScriptState()->GetIsolate(); }

  void PerformMicrotaskCheckpoint() {
    ScriptState::Scope scope(GetScriptState());
    GetScriptState()->GetContext()->GetMicrotaskQueue()->PerformCheckpoint(
        GetIsolate());
  }
};

TEST_F(ScriptPromiseResolverBaseTest, construct) {
  ASSERT_FALSE(GetExecutionContext()->IsContextDestroyed());
  ScriptState::Scope scope(GetScriptState());
  MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(GetScriptState());
}

TEST_F(ScriptPromiseResolverBaseTest, resolve) {
  ScriptPromiseResolver<IDLString>* resolver = nullptr;
  ScriptPromise<IDLString> promise;
  {
    ScriptState::Scope scope(GetScriptState());
    resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
        GetScriptState());
    promise = resolver->Promise();
  }

  String on_fulfilled, on_rejected;
  ASSERT_FALSE(promise.IsEmpty());
  {
    ScriptState::Scope scope(GetScriptState());
    promise.Then(GetScriptState(),
                 MakeGarbageCollected<TestResolveFunction>(&on_fulfilled),
                 MakeGarbageCollected<TestRejectFunction>(&on_rejected));
  }

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ(String(), on_rejected);

  PerformMicrotaskCheckpoint();

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ(String(), on_rejected);

  resolver->Resolve("hello");

  {
    ScriptState::Scope scope(GetScriptState());
    EXPECT_FALSE(resolver->Promise().IsEmpty());
  }

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ(String(), on_rejected);

  PerformMicrotaskCheckpoint();

  EXPECT_EQ("hello", on_fulfilled);
  EXPECT_EQ(String(), on_rejected);

  resolver->Resolve("bye");
  resolver->Reject("bye");
  PerformMicrotaskCheckpoint();

  EXPECT_EQ("hello", on_fulfilled);
  EXPECT_EQ(String(), on_rejected);
}

TEST_F(ScriptPromiseResolverBaseTest, reject) {
  ScriptPromiseResolver<IDLString>* resolver = nullptr;
  ScriptPromise<IDLString> promise;
  {
    ScriptState::Scope scope(GetScriptState());
    resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
        GetScriptState());
    promise = resolver->Promise();
  }

  String on_fulfilled, on_rejected;
  ASSERT_FALSE(promise.IsEmpty());
  {
    ScriptState::Scope scope(GetScriptState());
    promise.Then(GetScriptState(),
                 MakeGarbageCollected<TestResolveFunction>(&on_fulfilled),
                 MakeGarbageCollected<TestRejectFunction>(&on_rejected));
  }

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ(String(), on_rejected);

  PerformMicrotaskCheckpoint();

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ(String(), on_rejected);

  resolver->Reject("hello");

  {
    ScriptState::Scope scope(GetScriptState());
    EXPECT_FALSE(resolver->Promise().IsEmpty());
  }

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ(String(), on_rejected);

  PerformMicrotaskCheckpoint();

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ("hello", on_rejected);

  resolver->Resolve("bye");
  resolver->Reject("bye");
  PerformMicrotaskCheckpoint();

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ("hello", on_rejected);
}

TEST_F(ScriptPromiseResolverBaseTest, stop) {
  ScriptPromiseResolver<IDLString>* resolver = nullptr;
  ScriptPromise<IDLString> promise;
  {
    ScriptState::Scope scope(GetScriptState());
    resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
        GetScriptState());
    promise = resolver->Promise();
  }

  String on_fulfilled, on_rejected;
  ASSERT_FALSE(promise.IsEmpty());
  {
    ScriptState::Scope scope(GetScriptState());
    promise.Then(GetScriptState(),
                 MakeGarbageCollected<TestResolveFunction>(&on_fulfilled),
                 MakeGarbageCollected<TestRejectFunction>(&on_rejected));
  }

  GetExecutionContext()->NotifyContextDestroyed();

  resolver->Resolve("hello");
  PerformMicrotaskCheckpoint();

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ(String(), on_rejected);
}

TEST_F(ScriptPromiseResolverBaseTest, resolveUndefined) {
  ScriptPromiseResolver<IDLString>* resolver = nullptr;
  ScriptPromise<IDLString> promise;
  {
    ScriptState::Scope scope(GetScriptState());
    resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
        GetScriptState());
    promise = resolver->Promise();
  }

  String on_fulfilled, on_rejected;
  ASSERT_FALSE(promise.IsEmpty());
  {
    ScriptState::Scope scope(GetScriptState());
    promise.Then(GetScriptState(),
                 MakeGarbageCollected<TestResolveFunction>(&on_fulfilled),
                 MakeGarbageCollected<TestRejectFunction>(&on_rejected));
  }

  resolver->Resolve();
  PerformMicrotaskCheckpoint();

  EXPECT_EQ("undefined", on_fulfilled);
  EXPECT_EQ(String(), on_rejected);
}

TEST_F(ScriptPromiseResolverBaseTest, rejectUndefined) {
  ScriptPromiseResolver<IDLString>* resolver = nullptr;
  ScriptPromise<IDLString> promise;
  {
    ScriptState::Scope scope(GetScriptState());
    resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
        GetScriptState());
    promise = resolver->Promise();
  }

  String on_fulfilled, on_rejected;
  ASSERT_FALSE(promise.IsEmpty());
  {
    ScriptState::Scope scope(GetScriptState());
    promise.Then(GetScriptState(),
                 MakeGarbageCollected<TestResolveFunction>(&on_fulfilled),
                 MakeGarbageCollected<TestRejectFunction>(&on_rejected));
  }

  resolver->Reject();
  PerformMicrotaskCheckpoint();

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ("undefined", on_rejected);
}

TEST_F(ScriptPromiseResolverBaseTest, OverrideScriptStateToCurrentContext) {
  frame_test_helpers::WebViewHelper web_view_helper;
  std::string base_url = "http://www.test.com/";
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8("single_iframe.html"));
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8("visible_iframe.html"));
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url + "single_iframe.html");

  LocalFrame* main_frame = web_view_impl->MainFrameImpl()->GetFrame();
  LocalFrame* iframe = To<LocalFrame>(main_frame->Tree().FirstChild());
  ScriptState* main_script_state = ToScriptStateForMainWorld(main_frame);
  ScriptState* iframe_script_state = ToScriptStateForMainWorld(iframe);

  ScriptPromiseResolver<IDLString>* resolver = nullptr;
  ScriptPromise<IDLString> promise;
  {
    ScriptState::Scope scope(main_script_state);
    resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
        main_script_state);
    promise = resolver->Promise();
  }

  String on_fulfilled, on_rejected;
  ASSERT_FALSE(promise.IsEmpty());
  {
    ScriptState::Scope scope(main_script_state);
    promise.Then(main_script_state,
                 MakeGarbageCollected<TestResolveFunction>(&on_fulfilled),
                 MakeGarbageCollected<TestRejectFunction>(&on_rejected));
  }

  {
    ScriptState::Scope scope(iframe_script_state);
    iframe->DomWindow()->NotifyContextDestroyed();
    resolver->ResolveOverridingToCurrentContext("hello");
  }
  PerformMicrotaskCheckpoint();

  EXPECT_EQ(String(), on_fulfilled);
  EXPECT_EQ(String(), on_rejected);
}

}  // namespace

}  // namespace blink

"""

```
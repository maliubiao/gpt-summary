Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Understanding of the Request:**

The request asks for the functionality of the `async_iterable.cc` file, its relation to JavaScript, HTML, and CSS, examples of logical reasoning (input/output), common user errors, and a debugging path to reach this code.

**2. High-Level Code Overview:**

The first step is to skim the code to grasp its general purpose. Key observations:

* **Copyright and Includes:** It's a Chromium Blink engine file related to bindings and V8 (the JavaScript engine). The includes hint at promises, script functions, and core binding functionalities.
* **`AsyncIterationSourceBase`:** This class seems central. It has nested classes like `CallableCommon`, `RunNextStepsCallable`, etc., suggesting a state machine or a series of asynchronous operations.
* **`Next()`, `Return()`:** These method names are strong indicators of implementing the asynchronous iterator protocol in JavaScript.
* **`Run...Steps` methods:** These look like internal steps in the asynchronous iteration process.
* **`ScriptPromise`:**  Promises are heavily used, confirming the asynchronous nature.

**3. Deeper Dive into `AsyncIterationSourceBase`:**

This class is the core. Let's analyze its key components:

* **Inheritance:** It inherits from `AsyncIteratorBase::IterationSourceBase`, indicating it's part of a larger asynchronous iteration framework.
* **Member Variables:**
    * `script_state_`:  Crucial for interacting with the V8 JavaScript engine.
    * `on_settled_function_`, `on_fulfilled_function_`, `on_rejected_function_`:  These are callbacks, likely related to promise resolution and rejection. The `Run...StepsCallable` nested classes confirm this.
    * `ongoing_promise_`:  Manages the currently active promise during iteration.
    * `pending_promise_resolver_`: Used to create and resolve/reject promises for the next iteration step.
    * `is_finished_`:  A boolean flag to track if the iteration is complete.
* **Methods:**
    * `Next()`: This is the entry point for getting the next value from the asynchronous iterator. It handles cases where a promise is already ongoing.
    * `Return()`:  Implements the `return()` method of an asynchronous iterator, allowing for early termination.
    * `RunNextSteps()`, `RunFulfillSteps()`, `RunRejectSteps()`, `RunReturnSteps()`, `RunReturnFulfillSteps()`: These methods encapsulate the internal logic for different stages of asynchronous iteration, handling promise resolution, rejection, and completion.
    * `MakeEndOfIteration()`: Returns the special "end of iteration" value (JavaScript `undefined`).

**4. Connecting to JavaScript, HTML, and CSS:**

* **JavaScript:** The direct link is to JavaScript's asynchronous iterator protocol (`Symbol.asyncIterator`). The code implements the underlying mechanics when a JavaScript `for await...of` loop or the `next()` method of an async iterator is used.
* **HTML:**  Asynchronous iterators are used in various Web APIs that interact with HTML elements or data. Examples include:
    * Fetch API's readable byte streams (`response.body`).
    * Server-Sent Events (SSE).
    * WebSockets (less direct, but can involve asynchronous data streams).
* **CSS:**  No direct relationship. CSS is primarily for styling and layout, not asynchronous data processing.

**5. Logical Reasoning (Input/Output):**

Here, we need to think about the state transitions and promise resolutions. Consider the `Next()` method:

* **Hypothetical Input:** A JavaScript `for await...of` loop starts iterating over an asynchronous iterable.
* **Processing in `Next()`:**
    * **Initial call:** `ongoing_promise_` is empty, so `RunNextSteps()` is called. This likely initiates an asynchronous operation to get the next value. A new promise is created and stored in `ongoing_promise_`.
    * **Subsequent calls (while the previous promise is pending):** `ongoing_promise_` is not empty. A `then` callback is added to the `ongoing_promise_`. This ensures sequential execution.
* **Output (from `RunNextSteps` and related):**  Eventually, a promise resolves with an iteration result object (`{ value: ..., done: false }`) or becomes rejected. If the iteration is complete, it resolves with `{ value: undefined, done: true }`.

**6. Common User/Programming Errors:**

Think about how developers might misuse asynchronous iterators:

* **Not handling rejections:** If the underlying asynchronous operation fails, the promise will reject. If the JavaScript code doesn't have a `try...catch` around the `for await...of` loop, this could lead to unhandled promise rejections.
* **Calling `next()` manually in unexpected ways:** While possible, manually calling `next()` might disrupt the expected flow if not done carefully.
* **Ignoring the `return()` method:** Some asynchronous iterators might have cleanup logic in their `return()` method. Failing to call it (or letting it be called implicitly on loop exit) could lead to resource leaks.

**7. Debugging Scenario:**

Imagine a web developer has a problem with a `for await...of` loop not working as expected. Here's a possible debugging path:

1. **JavaScript Level:**  The developer would likely start by inspecting the values being yielded by the iterator using `console.log`. They might check for errors in their asynchronous operations.
2. **Browser Developer Tools:**  They might use the Network tab to see if network requests (if the iterator fetches data) are succeeding or failing. They could also use breakpoints in their JavaScript code.
3. **Stepping into Browser Internals (if necessary):** If the issue seems to be within the browser's handling of asynchronous iteration, a Chromium developer (or someone debugging a browser issue) might:
    * Set breakpoints in `async_iterable.cc`, particularly in `Next()`, `Return()`, and the `Run...Steps` methods.
    * Observe the state of the `AsyncIterationSourceBase` object (e.g., the values of `ongoing_promise_`, `is_finished_`).
    * Trace the execution flow through the promise callbacks.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  Focus solely on the C++ code.
* **Correction:** Realize the strong connection to JavaScript and the need to explain the interaction.
* **Initial thought:**  Describe the code in isolation.
* **Correction:** Provide examples of how these concepts manifest in real-world web development scenarios (Fetch API, SSE).
* **Initial thought:**  The "user error" section is about C++ programmers.
* **Correction:**  Shift focus to *JavaScript* developers who use these features indirectly.

By following this thought process, combining code analysis with an understanding of the underlying web technologies, we can arrive at a comprehensive explanation of the `async_iterable.cc` file's functionality and its role in the browser.
好的，让我们来分析一下 `blink/renderer/bindings/core/v8/async_iterable.cc` 文件的功能。

**文件功能概述:**

这个 C++ 文件是 Chromium Blink 渲染引擎的一部分，专门负责实现 **JavaScript 中异步迭代器 (Async Iterators)** 的核心逻辑。它提供了一个基础类 `AsyncIterationSourceBase`，用于管理异步迭代的状态和执行流程。

**更具体的功能分解:**

1. **`AsyncIterationSourceBase` 类:**
   - **状态管理:**  维护异步迭代器的状态，例如是否已完成 (`is_finished_`)，当前正在处理的 Promise (`ongoing_promise_`)，以及用于创建和管理 Promise 的 `pending_promise_resolver_`。
   - **`Next()` 方法:**  实现了异步迭代器的 `next()` 方法。当 JavaScript 代码调用异步迭代器的 `next()` 时，会触发这个方法。它负责：
     - 检查是否存在正在处理的 Promise (`ongoing_promise_`)。
     - 如果有，则在现有 Promise 完成后继续执行下一步。
     - 如果没有，则调用 `RunNextSteps()` 启动获取下一个值的流程。
     - 返回一个 Promise，该 Promise 将在异步操作完成后 resolve 或 reject。
   - **`Return()` 方法:** 实现了异步迭代器的 `return()` 方法。当 JavaScript 代码调用异步迭代器的 `return()` 方法以提前终止迭代时，会触发这个方法。它负责：
     - 设置迭代器为完成状态 (`is_finished_ = true`).
     - 如果有正在处理的 Promise，则在该 Promise 完成后执行 `RunReturnSteps()`。
     - 调用 `AsyncIteratorReturn()` 执行特定的清理或返回逻辑。
     - 返回一个 Promise，该 Promise 将在清理操作完成后 resolve。
   - **`RunNextSteps()` 方法:**  负责实际获取下一个迭代值的逻辑。
     - 如果迭代已完成，则返回一个已 resolve 的 Promise，其值为 `{ value: undefined, done: true }`。
     - 否则，调用 `GetNextIterationResult()` (这是一个纯虚函数，需要在子类中实现) 来获取下一个迭代结果。
     - 创建一个新的 Promise 并将其存储在 `pending_promise_resolver_` 中。
     - 当 `GetNextIterationResult()` 完成后，根据结果 resolve 或 reject 该 Promise。
   - **`RunFulfillSteps()` 方法:** 当获取下一个值的 Promise resolve 时调用。
     - 清除 `ongoing_promise_`。
     - 如果迭代结果表示迭代结束（`undefined`），则设置 `is_finished_` 为 true 并返回一个表示迭代结束的结果对象。
     - 否则，返回迭代结果对象。
   - **`RunRejectSteps()` 方法:** 当获取下一个值的 Promise reject 时调用。
     - 清除 `ongoing_promise_`。
     - 设置 `is_finished_` 为 true。
     - 抛出一个 JavaScript 异常。
   - **`RunReturnSteps()` 方法:**  当 `Return()` 方法被调用时，实际执行清理或返回逻辑。
     - 如果迭代已完成，则返回一个已 resolve 的 Promise，其值为 `{ value: value, done: true }`。
     - 否则，设置 `is_finished_` 为 true。
     - 调用 `AsyncIteratorReturn()` (需要在子类中实现) 执行异步的清理操作。
     - 返回一个 Promise，该 Promise 将在清理操作完成后 resolve。
   - **`RunReturnFulfillSteps()` 方法:** 当 `RunReturnSteps()` 返回的 Promise resolve 时调用，用于构造最终的迭代结果对象。
   - **内部 Callable 类 (`CallableCommon`, `RunNextStepsCallable`, 等):**  这些类是用于 Promise 的 `then` 方法的回调函数对象，用于在 Promise 状态改变时执行相应的步骤。它们封装了对 `AsyncIterationSourceBase` 内部方法的调用。

2. **与 JavaScript, HTML, CSS 的关系:**

   - **JavaScript:** 这个文件直接关联到 JavaScript 的异步迭代器功能。当 JavaScript 代码使用 `for await...of` 循环或者手动调用异步迭代器的 `next()` 和 `return()` 方法时，Blink 引擎会调用这个文件中实现的 C++ 代码来执行相应的操作。

     **举例:**

     ```javascript
     async function* myAsyncGenerator() {
       yield 1;
       await new Promise(resolve => setTimeout(resolve, 100));
       yield 2;
     }

     async function main() {
       for await (const value of myAsyncGenerator()) {
         console.log(value);
       }
     }

     main();
     ```

     在这个例子中，当 `for await...of` 循环迭代 `myAsyncGenerator()` 返回的异步迭代器时，会多次调用 `async_iterable.cc` 中的 `Next()` 方法来获取下一个值。当循环结束或者调用 `break` 时，可能会调用 `Return()` 方法。

   - **HTML:** 异步迭代器通常用于处理来自 Web API 的异步数据流，这些 API 通常与 HTML 元素或操作相关。

     **举例:**

     - **Fetch API 的 ReadableStream:**  `response.body` 返回一个 `ReadableStream`，它是一个异步可迭代对象，允许逐步读取响应体的数据。

       ```javascript
       async function readResponseBody() {
         const response = await fetch('https://example.com/data');
         const reader = response.body.getReader();

         try {
           while (true) {
             const { done, value } = await reader.read();
             if (done) {
               break;
             }
             console.log('Received chunk:', value);
           }
         } finally {
           reader.releaseLock();
         }
       }
       ```
       在这个例子中，虽然没有直接使用 `for await...of`，但 `reader.read()` 的行为类似于异步迭代器的 `next()` 方法，其背后的实现可能涉及到类似 `async_iterable.cc` 中的逻辑。

     - **Server-Sent Events (SSE):** `EventSource` API 产生的事件流可以被视为异步数据源。虽然 JavaScript 中通常使用事件监听器处理 SSE，但在某些抽象层或者未来可能的设计中，异步迭代器可能被用来处理这些事件。

   - **CSS:**  与 CSS 的功能没有直接关系。CSS 主要负责页面的样式和布局。

**3. 逻辑推理 (假设输入与输出):**

假设我们有一个简单的异步生成器函数：

```javascript
async function* simpleGenerator() {
  yield 'a';
  yield 'b';
}
```

并且使用 `for await...of` 循环来迭代它：

```javascript
async function main() {
  const iterator = simpleGenerator();
  // 第一次迭代
  let result1 = await iterator.next();
  console.log(result1); // 输出: { value: 'a', done: false }

  // 第二次迭代
  let result2 = await iterator.next();
  console.log(result2); // 输出: { value: 'b', done: false }

  // 第三次迭代
  let result3 = await iterator.next();
  console.log(result3); // 输出: { value: undefined, done: true }
}

main();
```

**在 `async_iterable.cc` 中的执行流程 (简化版):**

- **第一次 `iterator.next()`:**
  - `AsyncIterationSourceBase::Next()` 被调用。
  - `ongoing_promise_` 为空，调用 `RunNextSteps()`。
  - `RunNextSteps()` 调用子类实现的 `GetNextIterationResult()`，该方法会返回一个 resolve 的 Promise，其值为表示第一个 `yield` 的结果对象 `{ value: 'a', done: false }`。
  - `RunFulfillSteps()` 被调用，`ongoing_promise_` 被清除，返回该结果对象。
- **第二次 `iterator.next()`:**
  - 流程类似，返回 `{ value: 'b', done: false }`。
- **第三次 `iterator.next()`:**
  - 流程类似，但 `GetNextIterationResult()` 会指示迭代已完成。
  - `RunFulfillSteps()` 检测到迭代结束，设置 `is_finished_` 为 true，并返回 `{ value: undefined, done: true }`。

**4. 用户或编程常见的使用错误:**

- **未处理 Promise 的 rejection:** 如果异步迭代器内部的异步操作发生错误并导致 Promise reject，而 JavaScript 代码没有适当的错误处理（例如，在 `for await...of` 循环中使用 `try...catch`），则可能导致未捕获的 Promise rejection。

  **举例:**

  ```javascript
  async function* failingGenerator() {
    throw new Error('Something went wrong!');
    yield 1;
  }

  async function main() {
    for await (const value of failingGenerator()) { // 如果没有 try...catch，这里会抛出未捕获的错误
      console.log(value);
    }
  }

  main();
  ```

- **在异步迭代器完成或出错后继续调用 `next()`:** 虽然规范允许这样做，但通常不会产生有意义的结果。`next()` 方法会返回一个已 resolve 的 Promise，其值为 `{ value: undefined, done: true }`。

- **混淆同步迭代器和异步迭代器:**  尝试对异步可迭代对象使用同步迭代器的语法（例如，普通的 `for...of` 循环）会导致错误。

**5. 用户操作如何一步步到达这里 (调试线索):**

假设用户在浏览网页时，某个 JavaScript 代码使用了 `for await...of` 循环来处理从服务器获取的数据流。

1. **用户发起操作:** 用户点击了一个按钮或者触发了某个事件，导致 JavaScript 代码开始执行。
2. **JavaScript 代码执行:** JavaScript 代码中调用了 `fetch` API 获取数据，并使用 `response.body` 的 `getReader()` 方法创建了一个 `ReadableStream` 的读取器。
3. **使用 `for await...of`:** JavaScript 代码使用 `for await...of` 循环来迭代 `reader`：

   ```javascript
   async function fetchData() {
     const response = await fetch('/api/stream');
     const reader = response.body.getReader();
     try {
       while (true) {
         const { done, value } = await reader.read();
         if (done) break;
         console.log('Received:', value);
       }
     } finally {
       reader.releaseLock();
     }
   }

   fetchData();
   ```

4. **调用 `reader.read()`:** 在 `for await...of` 循环的每次迭代中，`reader.read()` 方法被调用，这在底层会触发 Blink 引擎中与异步迭代器相关的代码。
5. **进入 `async_iterable.cc`:**  当 `reader.read()` 返回的 Promise resolve 时，Blink 引擎需要处理下一个迭代步骤。这会调用 `AsyncIterationSourceBase` 的 `Next()` 方法。
6. **内部流程:**  `Next()` 方法会根据当前状态调用 `RunNextSteps()`，`RunFulfillSteps()` 等方法来处理异步操作的结果并准备下一次迭代。

**调试线索:**

如果开发者在调试这个过程，可能会：

- **在 JavaScript 代码中设置断点:**  在 `for await...of` 循环内部，查看 `value` 的内容以及 `done` 的状态。
- **在浏览器开发者工具的网络面板中查看网络请求:**  确认 `/api/stream` 请求是否成功，以及响应的内容。
- **如果怀疑是 Blink 引擎的问题，可以在 `async_iterable.cc` 中设置断点:**  例如，在 `AsyncIterationSourceBase::Next()`，`RunNextSteps()`，`RunFulfillSteps()` 等方法中设置断点，查看异步迭代器的状态 (`is_finished_`, `ongoing_promise_` 等)，以及 Promise 的 resolve 和 reject 流程。

总而言之，`blink/renderer/bindings/core/v8/async_iterable.cc` 文件是 Blink 引擎中实现 JavaScript 异步迭代器功能的核心组件，它负责管理异步迭代的状态和执行流程，使得 JavaScript 代码能够方便地处理异步数据流。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/async_iterable.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/async_iterable.h"

#include "third_party/blink/renderer/bindings/core/v8/active_script_wrappable_creation_key.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"

namespace blink::bindings {

// Common implementation of
// Run{Next,Fulfill,Reject,Return,ReturnFulfill}StepsCallable.
class AsyncIterationSourceBase::CallableCommon
    : public ThenCallable<IDLAny, CallableCommon, IDLAny> {
 public:
  ~CallableCommon() override = default;

  virtual ScriptValue React(ScriptState*, ScriptValue) = 0;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(iteration_source_);
    ThenCallable<IDLAny, CallableCommon, IDLAny>::Trace(visitor);
  }

 protected:
  explicit CallableCommon(AsyncIterationSourceBase* iteration_source)
      : iteration_source_(iteration_source) {}

  Member<AsyncIterationSourceBase> iteration_source_;
};

class AsyncIterationSourceBase::RunNextStepsCallable final
    : public AsyncIterationSourceBase::CallableCommon {
 public:
  explicit RunNextStepsCallable(AsyncIterationSourceBase* iteration_source)
      : AsyncIterationSourceBase::CallableCommon(iteration_source) {}

  ScriptValue React(ScriptState* script_state, ScriptValue) override {
    return ScriptValue(
        script_state->GetIsolate(),
        iteration_source_->RunNextSteps(script_state).V8Promise());
  }
};

class AsyncIterationSourceBase::RunFulfillStepsCallable final
    : public AsyncIterationSourceBase::CallableCommon {
 public:
  explicit RunFulfillStepsCallable(AsyncIterationSourceBase* iteration_source)
      : AsyncIterationSourceBase::CallableCommon(iteration_source) {}

  ScriptValue React(ScriptState* script_state,
                    ScriptValue iter_result_object_or_undefined) override {
    return iteration_source_->RunFulfillSteps(script_state,
                                              iter_result_object_or_undefined);
  }
};

class AsyncIterationSourceBase::RunRejectStepsCallable final
    : public AsyncIterationSourceBase::CallableCommon {
 public:
  explicit RunRejectStepsCallable(AsyncIterationSourceBase* iteration_source)
      : AsyncIterationSourceBase::CallableCommon(iteration_source) {}

  ScriptValue React(ScriptState* script_state, ScriptValue reason) override {
    return iteration_source_->RunRejectSteps(script_state, reason);
  }
};

class AsyncIterationSourceBase::RunReturnStepsCallable final
    : public AsyncIterationSourceBase::CallableCommon {
 public:
  explicit RunReturnStepsCallable(AsyncIterationSourceBase* iteration_source,
                                  ScriptValue value)
      : AsyncIterationSourceBase::CallableCommon(iteration_source),
        value_(std::move(value)) {}

  ScriptValue React(ScriptState* script_state, ScriptValue) override {
    return ScriptValue(
        script_state->GetIsolate(),
        iteration_source_->RunReturnSteps(script_state, value_).V8Promise());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(value_);
    AsyncIterationSourceBase::CallableCommon::Trace(visitor);
  }

 private:
  const ScriptValue value_;
};

class AsyncIterationSourceBase::RunReturnFulfillStepsCallable final
    : public AsyncIterationSourceBase::CallableCommon {
 public:
  explicit RunReturnFulfillStepsCallable(
      AsyncIterationSourceBase* iteration_source,
      ScriptValue value)
      : AsyncIterationSourceBase::CallableCommon(iteration_source),
        value_(std::move(value)) {}

  ScriptValue React(ScriptState* script_state, ScriptValue) override {
    return iteration_source_->RunReturnFulfillSteps(script_state, value_);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(value_);
    AsyncIterationSourceBase::CallableCommon::Trace(visitor);
  }

 private:
  const ScriptValue value_;
};

AsyncIterationSourceBase::AsyncIterationSourceBase(ScriptState* script_state,
                                                   Kind kind)
    : AsyncIteratorBase::IterationSourceBase(kind),
      script_state_(script_state),
      on_settled_function_(MakeGarbageCollected<RunNextStepsCallable>(this)),
      on_fulfilled_function_(
          MakeGarbageCollected<RunFulfillStepsCallable>(this)),
      on_rejected_function_(
          MakeGarbageCollected<RunRejectStepsCallable>(this)) {}

v8::Local<v8::Promise> AsyncIterationSourceBase::Next(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  ScriptPromise<IDLAny> next_promise;
  if (!ongoing_promise_.IsEmpty()) {
    // step 10. If ongoingPromise is not null, then:
    // step 10.3. Perform PerformPromiseThen(ongoingPromise, onSettled,
    //     onSettled, afterOngoingPromiseCapability).
    // step 10.4. Set object's ongoing promise to
    //     afterOngoingPromiseCapability.[[Promise]].
    next_promise = ongoing_promise_.Unwrap().Then(
        script_state, on_settled_function_.Get(), on_settled_function_.Get());
  } else {
    // step 11. Otherwise:
    // step 11.1. Set object's ongoing promise to the result of running
    //     nextSteps.
    next_promise = RunNextSteps(script_state);
  }
  ongoing_promise_ = next_promise;
  // step 12. Return object's ongoing promise.
  return next_promise.V8Promise();
}

v8::Local<v8::Promise> AsyncIterationSourceBase::Return(
    ScriptState* script_state,
    v8::Local<v8::Value> value,
    ExceptionState& exception_state) {
  ScriptPromise<IDLAny> next_promise;
  ScriptPromise<IDLAny> return_steps_promise;
  if (!ongoing_promise_.IsEmpty()) {
    // step 10. If ongoingPromise is not null, then:
    // step 10.2. Let onSettled be CreateBuiltinFunction(returnSteps, << >>).
    auto* on_settled = MakeGarbageCollected<RunReturnStepsCallable>(
        this, ScriptValue(script_state->GetIsolate(), value));
    // step 10.3. Perform PerformPromiseThen(ongoingPromise, onSettled,
    //     onSettled, afterOngoingPromiseCapability).
    // step 11.4. Set object's ongoing promise to
    //     afterOngoingPromiseCapability.[[Promise]].
    next_promise =
        ongoing_promise_.Unwrap().Then(script_state, on_settled, on_settled);
  } else {
    // step 11. Otherwise:
    // step 11.1. Set object's ongoing promise to the result of
    //     running returnSteps.
    next_promise = RunReturnSteps(
        script_state, ScriptValue(script_state->GetIsolate(), value));
  }
  ongoing_promise_ = next_promise;

  // step 13. Let onFulfilled be CreateBuiltinFunction(fulfillSteps, << >>).
  auto* on_fulfilled = MakeGarbageCollected<RunReturnFulfillStepsCallable>(
      this, ScriptValue(script_state->GetIsolate(), value));
  // step 14. Perform PerformPromiseThen(object's ongoing promise, onFulfilled,
  //     undefined, returnPromiseCapability).
  return_steps_promise = next_promise.Then(script_state, on_fulfilled);
  // step 15. Return returnPromiseCapability.[[Promise]].
  return return_steps_promise.V8Promise();
}

void AsyncIterationSourceBase::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(on_settled_function_);
  visitor->Trace(on_fulfilled_function_);
  visitor->Trace(on_rejected_function_);
  visitor->Trace(ongoing_promise_);
  visitor->Trace(pending_promise_resolver_);
  AsyncIteratorBase::IterationSourceBase::Trace(visitor);
}

v8::Local<v8::Value> AsyncIterationSourceBase::MakeEndOfIteration() const {
  // Let ES undefined represent a special 'end of iteration' value.
  // https://webidl.spec.whatwg.org/#end-of-iteration
  return v8::Undefined(script_state_->GetIsolate());
}

// step 8. Let nextSteps be the following steps:
ScriptPromise<IDLAny> AsyncIterationSourceBase::RunNextSteps(
    ScriptState* script_state) {
  if (is_finished_) {
    // step 8.2. If object's is finished is true, then:
    // step 8.2.1. Let result be CreateIterResultObject(undefined, true).
    // step 8.2.2. Perform ! Call(nextPromiseCapability.[[Resolve]], undefined,
    //     << result >>).
    // step 8.2.3. Return nextPromiseCapability.[[Promise]].
    return ToResolvedPromise<IDLAny>(
        script_state,
        ESCreateIterResultObject(script_state, true,
                                 v8::Undefined(script_state->GetIsolate())));
  }

  // step 8.4. Let nextPromise be the result of getting the next iteration
  //     result with object's target and object.
  // step 8.9. Perform PerformPromiseThen(nextPromise, onFulfilled, onRejected,
  //     nextPromiseCapability).
  // step 8.10. Return nextPromiseCapability.[[Promise]].
  DCHECK(!pending_promise_resolver_);
  pending_promise_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = pending_promise_resolver_->Promise();
  GetNextIterationResult();
  return promise.Then(script_state, on_fulfilled_function_.Get(),
                      on_rejected_function_.Get());
}

// step 8.5. Let fulfillSteps be the following steps, given next:
ScriptValue AsyncIterationSourceBase::RunFulfillSteps(
    ScriptState* script_state,
    ScriptValue iter_result_object_or_undefined) {
  // This function takes `iter_result_object_or_undefined` instead of `next`
  // specified in the spec. The argument `iter_result_object_or_undefined` must
  // be an iter result object [1] or undefined which indicates end of
  // iteration [2].
  //
  // [1]
  // https://tc39.es/ecma262/multipage/abstract-operations.html#sec-createiterresultobject
  // [2] https://webidl.spec.whatwg.org/#end-of-iteration
  DCHECK(iter_result_object_or_undefined.IsObject() ||
         iter_result_object_or_undefined.IsUndefined());

  // step 8.5.1. Set object's ongoing promise to null.
  ongoing_promise_.Clear();

  // step 8.5.2. If next is end of iteration, then:
  if (iter_result_object_or_undefined.IsUndefined()) {
    // step 8.5.2.1. Set object's is finished to true.
    is_finished_ = true;
    // step 8.5.2.2. Return CreateIterResultObject(undefined, true).
    return ScriptValue(
        script_state->GetIsolate(),
        ESCreateIterResultObject(script_state, true,
                                 v8::Undefined(script_state->GetIsolate())));
  }

  // step 8.5.3. Otherwise, if interface has a pair asynchronously iterable
  //     declaration:
  // step 8.5.4. Otherwise:
  //
  // iter_result_object_or_undefined must already be an iter result object.
  return iter_result_object_or_undefined;
}

// step 8.7. Let rejectSteps be the following steps, given reason:
ScriptValue AsyncIterationSourceBase::RunRejectSteps(ScriptState* script_state,
                                                     ScriptValue reason) {
  // step 8.7.1. Set object's ongoing promise to null.
  ongoing_promise_.Clear();
  // step 8.7.2. Set object's is finished to true.
  is_finished_ = true;
  // step 8.7.3. Throw reason.
  V8ThrowException::ThrowException(script_state->GetIsolate(),
                                   reason.V8Value());
  return {};
}

// step 8. Let returnSteps be the following steps:
ScriptPromise<IDLAny> AsyncIterationSourceBase::RunReturnSteps(
    ScriptState* script_state,
    ScriptValue value) {
  if (is_finished_) {
    // step 8.2. If object's is finished is true, then:
    // step 8.2.1. Let result be CreateIterResultObject(value, true).
    // step 8.2.2. Perform ! Call(returnPromiseCapability.[[Resolve]],
    //     undefined, << result >>).
    // step 8.2.3. Return returnPromiseCapability.[[Promise]].
    return ToResolvedPromise<IDLAny>(
        script_state,
        ESCreateIterResultObject(script_state, true, value.V8Value()));
  }

  // step 8.3. Set object's is finished to true.
  is_finished_ = true;

  // step 8.4. Return the result of running the asynchronous iterator return
  //     algorithm for interface, given object's target, object, and value.
  DCHECK(!pending_promise_resolver_);
  pending_promise_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = pending_promise_resolver_->Promise();
  AsyncIteratorReturn(value);
  return promise;
}

// step 13. Let fulfillSteps be the following steps:
ScriptValue AsyncIterationSourceBase::RunReturnFulfillSteps(
    ScriptState* script_state,
    ScriptValue value) {
  // step 13.1. Return CreateIterResultObject(value, true).
  return ScriptValue(
      script_state->GetIsolate(),
      ESCreateIterResultObject(script_state, true, value.V8Value()));
}

}  // namespace blink::bindings

"""

```
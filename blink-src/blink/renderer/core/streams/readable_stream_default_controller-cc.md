Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for a functional breakdown of the `ReadableStreamDefaultController.cc` file in the Chromium Blink engine, focusing on its purpose, connections to web technologies (JavaScript, HTML, CSS), logic reasoning with examples, potential user errors, and debugging context.

2. **Initial Scan for Key Terms:**  I'd start by quickly scanning the code for prominent keywords and patterns. I see things like:
    * `ReadableStreamDefaultController` (obviously central)
    * `enqueue`, `close`, `error`, `pull`, `cancel` (common stream operations)
    * `queue_` (suggests buffering of data)
    * `Promise` (asynchronous operations)
    * `ScriptState`, `ScriptValue` (interaction with JavaScript)
    * `ExceptionState` (error handling)
    * `strategy_size_algorithm`, `strategy_high_water_mark` (related to stream capacity management)
    * Mentions of the WHATWG Streams Standard (important for context)

3. **Identify Core Functionality:** Based on the keywords, I can infer the main responsibilities of this class:
    * **Managing the flow of data into a readable stream.** This includes buffering (`queue_`), deciding when to pull more data, and handling enqueue/close/error operations.
    * **Interacting with JavaScript.**  The presence of `ScriptState` and `ScriptValue` indicates this class bridges the C++ stream implementation with JavaScript's ReadableStream API.
    * **Implementing parts of the WHATWG Streams Standard.** The comments directly reference the spec, suggesting a faithful implementation.

4. **Analyze Key Methods:** I'd then examine the individual methods to understand their specific roles:
    * **`enqueue`:** Adds data to the stream's internal queue. It needs to handle cases where the stream is closed or errored. It also interacts with the stream's "backpressure" mechanism.
    * **`close`:** Signals the end of the stream. It checks if the stream can be closed.
    * **`error`:** Signals an error condition in the stream.
    * **`pull` (and related `CallPullIfNeeded`, `ShouldCallPull`):**  This is crucial for the "pull" nature of readable streams. It determines when the underlying source should be asked for more data. The logic considers the queue size and whether there are pending read requests from JavaScript.
    * **`cancel`:**  Handles cancellation of the stream, potentially interacting with the underlying source.
    * **`GetDesiredSize`:**  Calculates how much more data the stream can accept based on the high-water mark and current queue size.
    * **`SetUp` and `SetUpFromUnderlyingSource`:**  These are initialization methods that connect the controller to the stream and configure its behavior based on the provided source.

5. **Map to Web Technologies:** This is where I connect the C++ code to the user-facing web APIs:
    * **JavaScript `ReadableStream` API:**  The methods in this C++ class directly correspond to methods and behaviors exposed by the JavaScript `ReadableStream` API (`enqueue()`, `close()`, `error()`, the "pull" mechanism).
    * **HTML:** While not directly interacting with HTML elements, the `ReadableStream` API is often used in conjunction with APIs that *do* interact with HTML, such as `fetch()` (for downloading data) or `<video>`/`<audio>` elements (for streaming media).
    * **CSS:**  Generally less direct. CSS might indirectly influence stream usage if the rendering of a page depends on data fetched via a stream.

6. **Logic Reasoning and Examples:**  For each key function, I'd consider:
    * **Inputs:** What data or conditions are necessary for the function to execute?
    * **Processing:** What steps does the function perform?
    * **Outputs:** What is the result of the function's execution?
    * **Assumptions:** What preconditions are expected?

    For example, for `enqueue`, the input is the data chunk. The processing involves checking the stream state and potentially adding the chunk to the queue. The output is either success or an error.

7. **Identify Potential User Errors:**  Think about how a JavaScript developer using the `ReadableStream` API could misuse it, leading to the execution of code within this C++ file and potentially triggering errors handled here. Examples include:
    * Calling `enqueue()` on a closed or errored stream.
    * Implementing the underlying source's `pull()` method incorrectly, leading to errors or unexpected behavior.

8. **Debugging Context:** Imagine a scenario where something goes wrong with a `ReadableStream`. How could a developer trace the execution to this specific C++ file?
    * **Browser DevTools:** Look for error messages or stack traces related to stream operations.
    * **Blink Internals:**  If deeper debugging is needed, developers might set breakpoints within this C++ file. The provided steps demonstrate a typical flow of how user actions in JavaScript can eventually lead to the execution of the `enqueue` method in this C++ file.

9. **Structure the Answer:** Organize the findings into clear sections as requested: Functionality, Relationship to Web Technologies, Logic Reasoning, User Errors, and Debugging. Use clear and concise language.

10. **Refine and Review:**  Read through the generated explanation to ensure accuracy, clarity, and completeness. Are the examples relevant? Is the logic easy to follow?  Is the debugging section helpful?

Self-Correction/Refinement During the Process:

* **Initial thought:** Focus solely on the individual functions. **Correction:** Realize the importance of understanding the overall data flow and the interplay between different methods.
* **Overly technical language:**  **Correction:**  Simplify explanations to make them accessible to a broader audience, including those familiar with web development but not necessarily Blink internals.
* **Missing examples:** **Correction:** Add concrete examples of JavaScript code that would trigger the C++ code.
* **Vague debugging context:** **Correction:** Provide specific steps a user might take in the browser that would lead to this code being executed.

By following this structured approach, combining code analysis with an understanding of web technologies and potential user interactions, I can generate a comprehensive and informative answer like the example provided.
好的，让我们来详细分析 `blink/renderer/core/streams/readable_stream_default_controller.cc` 这个文件。

**文件功能概览**

`ReadableStreamDefaultController.cc` 文件是 Chromium Blink 引擎中实现 Web Streams API 中 `ReadableStreamDefaultController` 接口的关键部分。它的主要职责是管理一个可读流的数据生产和消费过程，具体包括：

1. **数据缓冲管理:** 维护一个内部队列 (`queue_`) 来存储即将被读取的数据块 (chunks)。
2. **背压控制:**  根据策略 (`strategy_high_water_mark`) 和当前队列大小，决定是否需要暂停数据生产（背压）。
3. **数据拉取 (Pulling):**  当需要更多数据时，触发用户提供的拉取算法 (`pull_algorithm_`)。
4. **流的关闭和错误处理:**  处理流的正常关闭 (`close()`) 和错误状态 (`error()`)。
5. **与 JavaScript 的交互:**  作为 C++ 层面的实现，它需要与 JavaScript 层的 `ReadableStream` 对象进行交互，例如响应 JavaScript 的 `read()` 请求。
6. **实现 WHATWG Streams 标准:**  该文件的代码严格遵循 WHATWG Streams 标准的定义。

**与 JavaScript, HTML, CSS 的关系**

这个文件直接关联到 JavaScript 的 `ReadableStream` API，是其在 Blink 引擎中的核心实现。

* **JavaScript:**
    * 当你在 JavaScript 中创建一个 `ReadableStream` 实例时，你通常会提供一个底层源对象 (underlying source object)。这个底层源对象中的 `start()`, `pull()`, 和 `cancel()` 方法会在 `ReadableStreamDefaultController` 中被调用。
    * 例如，以下 JavaScript 代码创建了一个简单的可读流：

      ```javascript
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue('hello');
          controller.enqueue('world');
          controller.close();
        },
        pull(controller) {
          console.log('Need more data!');
        },
        cancel(reason) {
          console.log('Stream cancelled:', reason);
        }
      });

      const reader = stream.getReader();
      reader.read().then(({ value, done }) => {
        console.log(value); // 输出 "hello"
        return reader.read();
      }).then(({ value, done }) => {
        console.log(value); // 输出 "world"
      });
      ```

      在这个例子中，`start`, `pull`, 和 `cancel` 方法的逻辑最终会在 `ReadableStreamDefaultController.cc` 中被执行。特别是 `controller.enqueue()` 会调用到 `ReadableStreamDefaultController::enqueue()`, `controller.close()` 会调用 `ReadableStreamDefaultController::close()`, 而 `pull()` 的触发则与 `ReadableStreamDefaultController::CallPullIfNeeded()` 等方法相关。

* **HTML:**
    * `ReadableStream` 经常与 HTML 中的其他 API 结合使用，例如 `fetch API` 的响应体 (`response.body`) 就是一个 `ReadableStream`。
    * 例如，当你使用 `fetch` 下载一个文件时：

      ```javascript
      fetch('https://example.com/data.txt')
        .then(response => response.body) // response.body 是一个 ReadableStream
        .then(body => {
          const reader = body.getReader();
          return new ReadableStream({
            start(controller) {
              function push() {
                reader.read().then(({ done, value }) => {
                  if (done) {
                    controller.close();
                  } else {
                    controller.enqueue(value);
                    push();
                  }
                });
              }
              push();
            }
          });
        })
        .then(transformedStream => {
          // 对 transformedStream 进行进一步处理
        });
      ```
      在这个场景下，`response.body` 的 `ReadableStream` 的底层控制就是由 `ReadableStreamDefaultController` 负责的。

* **CSS:**
    * CSS 本身与 `ReadableStreamDefaultController` 的关系较为间接。然而，如果网页通过 JavaScript 使用 `ReadableStream` 来处理图像、字体或其他资源，那么 `ReadableStreamDefaultController` 的性能和正确性会影响到 CSS 渲染所需的资源加载。

**逻辑推理 (假设输入与输出)**

假设我们有一个 `ReadableStream`，其 `highWaterMark` 设置为 10，并且我们向其 `enqueue` 数据。

* **假设输入:**
    1. `highWaterMark` = 10
    2. 当前 `queue_->TotalSize()` = 5
    3. 调用 `enqueue(script_state, 'data1', exception_state)`，假设 'data1' 的大小为 3。

* **逻辑推理:**
    1. `CanCloseOrEnqueue()` 返回 `true` (假设流未关闭或出错)。
    2. 数据 'data1' 被添加到 `queue_` 中。
    3. `queue_->TotalSize()` 更新为 5 + 3 = 8。
    4. `GetDesiredSize()` 计算结果为 `10 - 8 = 2`。
    5. `ShouldCallPull()` 判断 `desiredSize > 0`，结果为 `true`。
    6. 如果 `is_pulling_` 为 `false`，则会触发 `pull_algorithm_` 的执行。

* **假设输入:**
    1. `highWaterMark` = 10
    2. 当前 `queue_->TotalSize()` = 9
    3. 调用 `enqueue(script_state, 'data2', exception_state)`，假设 'data2' 的大小为 4。

* **逻辑推理:**
    1. `CanCloseOrEnqueue()` 返回 `true`。
    2. 数据 'data2' 被添加到 `queue_` 中。
    3. `queue_->TotalSize()` 更新为 9 + 4 = 13。
    4. `GetDesiredSize()` 计算结果为 `10 - 13 = -3`。
    5. `ShouldCallPull()` 判断 `desiredSize > 0`，结果为 `false`。
    6. 不会立即触发 `pull_algorithm_`，可能会产生背压。

**用户或编程常见的使用错误**

1. **在流已关闭或出错后尝试 `enqueue()`:**

   ```javascript
   const stream = new ReadableStream({
     start(controller) {
       controller.close();
       controller.enqueue('data'); // 错误：流已关闭
     }
   });
   ```
   这将导致 `ReadableStreamDefaultController::enqueue()` 中的 `CanCloseOrEnqueue()` 返回 `false`，并抛出一个 `TypeError`。

2. **在流已请求关闭后尝试 `enqueue()`:**

   ```javascript
   const stream = new ReadableStream({
     start(controller) {
       controller.close(); // 请求关闭
       setTimeout(() => controller.enqueue('data'), 100); // 错误：流已请求关闭
     }
   });
   ```
   虽然 `start` 方法执行完毕时流可能还未完全关闭，但一旦调用了 `close()`, `is_close_requested_` 会被设置为 `true`，后续的 `enqueue()` 调用会失败。

3. **错误地实现 `pull()` 方法导致异常:**

   ```javascript
   const stream = new ReadableStream({
     pull(controller) {
       throw new Error('Failed to pull data');
     }
   });
   ```
   当 `ReadableStreamDefaultController::CallPullIfNeeded()` 调用 `pull_algorithm_` 时，如果 `pull()` 方法抛出异常，该异常会被捕获，并调用 `ReadableStreamDefaultController::Error()` 来标记流为错误状态。

**用户操作如何一步步到达这里 (调试线索)**

假设用户在网页上触发了一个下载操作，该操作使用 `fetch API` 并处理响应体作为一个可读流。以下是可能到达 `ReadableStreamDefaultController::enqueue()` 的步骤：

1. **用户操作:** 用户点击一个下载链接或按钮。
2. **JavaScript 发起 `fetch` 请求:**  JavaScript 代码调用 `fetch('...')` 发起网络请求。
3. **浏览器接收到响应头:** 浏览器接收到服务器的响应头。
4. **创建 `ReadableStream`:**  `fetch API` 会根据响应创建一个 `ReadableStream` 来表示响应体。这个 `ReadableStream` 的底层控制器是 `ReadableStreamDefaultController`。
5. **获取 `ReadableStream` 的 reader:** JavaScript 代码调用 `response.body.getReader()` 获取一个 reader。
6. **开始读取数据:** JavaScript 代码调用 `reader.read()` 开始从流中读取数据。
7. **触发 `pull()` (如果需要):** 如果内部缓冲区为空或低于阈值，`ReadableStreamDefaultController::CallPullIfNeeded()` 会被调用，并执行用户提供的 `pull()` 方法（或浏览器底层的网络数据接收逻辑）。
8. **底层数据到达:** 浏览器从网络接收到一部分数据。
9. **调用 `enqueue()`:**  浏览器底层的网络接收代码会将接收到的数据块传递给 `ReadableStreamDefaultController::enqueue()`，将其添加到内部队列中。
10. **`read()` Promise resolve:**  之前 `reader.read()` 返回的 Promise 会在 `enqueue()` 放入数据后 resolve，并将数据传递给 JavaScript。

**调试线索:**

* **查看 JavaScript 代码:** 检查与 `ReadableStream` 相关的 JavaScript 代码，特别是底层源对象的实现，以及如何使用 reader 读取数据。
* **使用浏览器开发者工具:**
    * **Network 面板:** 检查网络请求的状态和响应头，确认数据是否正常传输。
    * **Sources 面板:** 设置断点在与 `ReadableStream` 相关的 JavaScript 代码中，例如 `start`, `pull` 方法，以及 `reader.read()` 的回调中。
    * **Console 面板:** 查看可能的错误信息。
* **Blink 内部调试:** 如果需要深入调试 Blink 引擎，可以使用调试器 (例如 gdb) attach 到 Chromium 进程，并在 `ReadableStreamDefaultController.cc` 的关键方法上设置断点，例如 `enqueue`, `close`, `error`, `CallPullIfNeeded` 等。通过单步执行，可以观察数据的流动和状态变化。

希望以上分析能够帮助你理解 `blink/renderer/core/streams/readable_stream_default_controller.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/streams/readable_stream_default_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/readable_stream_default_controller.h"

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/promise_handler.h"
#include "third_party/blink/renderer/core/streams/queue_with_sizes.h"
#include "third_party/blink/renderer/core/streams/read_request.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_reader.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"

namespace blink {

class ReadableStreamDefaultController::CallPullIfNeededResolveFunction final
    : public ThenCallable<IDLUndefined, CallPullIfNeededResolveFunction> {
 public:
  explicit CallPullIfNeededResolveFunction(
      ReadableStreamDefaultController* controller)
      : controller_(controller) {}

  void React(ScriptState* script_state) {
    // https://streams.spec.whatwg.org/#readable-stream-default-controller-call-pull-if-needed
    // 7. Upon fulfillment of pullPromise,
    //   a. Set controller.[[pulling]] to false.
    controller_->is_pulling_ = false;

    //   b. If controller.[[pullAgain]] is true,
    if (controller_->will_pull_again_) {
      //  i. Set controller.[[pullAgain]] to false.
      controller_->will_pull_again_ = false;

      //  ii. Perform ! ReadableStreamDefaultControllerCallPullIfNeeded(
      //      controller).
      CallPullIfNeeded(script_state, controller_);
    }
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(controller_);
    ThenCallable<IDLUndefined, CallPullIfNeededResolveFunction>::Trace(visitor);
  }

 private:
  const Member<ReadableStreamDefaultController> controller_;
};

class ReadableStreamDefaultController::CallPullIfNeededRejectFunction final
    : public ThenCallable<IDLAny, CallPullIfNeededRejectFunction> {
 public:
  explicit CallPullIfNeededRejectFunction(
      ReadableStreamDefaultController* controller)
      : controller_(controller) {}

  void React(ScriptState* script_state, ScriptValue e) {
    // 8. Upon rejection of pullPromise with reason e,
    //   a. Perform ! ReadableStreamDefaultControllerError(controller, e).
    Error(script_state, controller_, e.V8Value());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(controller_);
    ThenCallable<IDLAny, CallPullIfNeededRejectFunction>::Trace(visitor);
  }

 private:
  const Member<ReadableStreamDefaultController> controller_;
};

// This constructor is used internally; it is not reachable from JavaScript.
ReadableStreamDefaultController::ReadableStreamDefaultController(
    ScriptState* script_state)
    : queue_(MakeGarbageCollected<QueueWithSizes>()),
      resolve_function_(
          MakeGarbageCollected<CallPullIfNeededResolveFunction>(this)),
      reject_function_(
          MakeGarbageCollected<CallPullIfNeededRejectFunction>(this)) {}

void ReadableStreamDefaultController::close(ScriptState* script_state,
                                            ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-default-controller-close
  // 2. If ! ReadableStreamDefaultControllerCanCloseOrEnqueue(this) is false,
  //    throw a TypeError exception.
  if (!CanCloseOrEnqueue(this)) {
    // The following code is just to provide a nice exception message.
    const char* errorDescription = nullptr;
    if (is_close_requested_) {
      errorDescription =
          "Cannot close a readable stream that has already been requested to "
          "be closed";
    } else {
      const ReadableStream* stream = controlled_readable_stream_;
      switch (stream->state_) {
        case ReadableStream::kErrored:
          errorDescription = "Cannot close an errored readable stream";
          break;

        case ReadableStream::kClosed:
          errorDescription = "Cannot close an errored readable stream";
          break;

        default:
          NOTREACHED();
      }
    }
    exception_state.ThrowTypeError(errorDescription);
    return;
  }

  // 3. Perform ! ReadableStreamDefaultControllerClose(this).
  return Close(script_state, this);
}

void ReadableStreamDefaultController::enqueue(ScriptState* script_state,
                                              ExceptionState& exception_state) {
  enqueue(script_state,
          ScriptValue(script_state->GetIsolate(),
                      v8::Undefined(script_state->GetIsolate())),
          exception_state);
}

void ReadableStreamDefaultController::enqueue(ScriptState* script_state,
                                              ScriptValue chunk,
                                              ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-default-controller-enqueue
  // 2. If ! ReadableStreamDefaultControllerCanCloseOrEnqueue(this) is false,
  //    throw a TypeError exception.
  if (!CanCloseOrEnqueue(this)) {
    exception_state.ThrowTypeError(EnqueueExceptionMessage(this));
    return;
  }

  // 3. Return ? ReadableStreamDefaultControllerEnqueue(this, chunk).
  return Enqueue(script_state, this, chunk.V8Value(), exception_state);
}

void ReadableStreamDefaultController::error(ScriptState* script_state) {
  error(script_state, ScriptValue(script_state->GetIsolate(),
                                  v8::Undefined(script_state->GetIsolate())));
}

void ReadableStreamDefaultController::error(ScriptState* script_state,
                                            ScriptValue e) {
  // https://streams.spec.whatwg.org/#rs-default-controller-error
  // 2. Perform ! ReadableStreamDefaultControllerError(this, e).
  Error(script_state, this, e.V8Value());
}

void ReadableStreamDefaultController::Close(
    ScriptState* script_state,
    ReadableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#readable-stream-default-controller-close
  // 1. Let stream be controller.[[controlledReadableStream]].
  ReadableStream* stream = controller->controlled_readable_stream_;

  // 2. Assert: ! ReadableStreamDefaultControllerCanCloseOrEnqueue(controller)
  //    is true.
  CHECK(CanCloseOrEnqueue(controller));

  // 3. Set controller.[[closeRequested]] to true.
  controller->is_close_requested_ = true;

  // 4. If controller.[[queue]] is empty,
  if (controller->queue_->IsEmpty()) {
    // a. Perform ! ReadableStreamDefaultControllerClearAlgorithms(controller).
    ClearAlgorithms(controller);

    // b. Perform ! ReadableStreamClose(stream).
    ReadableStream::Close(script_state, stream);
  }
}

void ReadableStreamDefaultController::Enqueue(
    ScriptState* script_state,
    ReadableStreamDefaultController* controller,
    v8::Local<v8::Value> chunk,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-stream-default-controller-enqueue
  // 1. If ! ReadableStreamDefaultControllerCanCloseOrEnqueue(controller) is
  //    false, return.
  if (!CanCloseOrEnqueue(controller)) {
    return;
  }

  // 2. Let stream be controller.[[stream]].
  const auto stream = controller->controlled_readable_stream_;

  // 3. If ! IsReadableStreamLocked(stream) is true and !
  //    ReadableStreamGetNumReadRequests(stream) > 0, perform !
  //    ReadableStreamFulfillReadRequest(stream, chunk, false).
  if (ReadableStream::IsLocked(stream) &&
      ReadableStream::GetNumReadRequests(stream) > 0) {
    ReadableStream::FulfillReadRequest(script_state, stream, chunk, false,
                                       exception_state);
  } else {
    // 4. Otherwise,
    //   a. Let result be the result of performing controller.
    //      [[strategySizeAlgorithm]], passing in chunk, and interpreting the
    //      result as an ECMAScript completion value.
    TryRethrowScope rethrow_scope(script_state->GetIsolate(), exception_state);
    std::optional<double> chunk_size =
        controller->strategy_size_algorithm_->Run(script_state, chunk);

    //   b. If result is an abrupt completion,
    if (rethrow_scope.HasCaught()) {
      //    i. Perform ! ReadableStreamDefaultControllerError(controller,
      //       result.[[Value]]).
      Error(script_state, controller, rethrow_scope.GetException());
      //    ii. Return result.
      return;
    }
    DCHECK(chunk_size.has_value());

    //  c. Let chunkSize be result.[[Value]].
    //  d. Let enqueueResult be EnqueueValueWithSize(controller, chunk,
    //     chunkSize).
    controller->queue_->EnqueueValueWithSize(
        script_state->GetIsolate(), chunk, chunk_size.value(),
        PassThroughException(script_state->GetIsolate()));

    //   e. If enqueueResult is an abrupt completion,
    if (rethrow_scope.HasCaught()) {
      //    i. Perform ! ReadableStreamDefaultControllerError(controller,
      //       enqueueResult.[[Value]]).
      Error(script_state, controller, rethrow_scope.GetException());
      //    ii. Return enqueueResult.
      return;
    }
  }

  // 5. Perform ! ReadableStreamDefaultControllerCallPullIfNeeded(controller).
  CallPullIfNeeded(script_state, controller);
}

void ReadableStreamDefaultController::Error(
    ScriptState* script_state,
    ReadableStreamDefaultController* controller,
    v8::Local<v8::Value> e) {
  // https://streams.spec.whatwg.org/#readable-stream-default-controller-error
  // 1. Let stream be controller.[[controlledReadableStream]].
  ReadableStream* stream = controller->controlled_readable_stream_;

  // 2. If stream.[[state]] is not "readable", return.
  if (stream->state_ != ReadableStream::kReadable) {
    return;
  }

  // 3. Perform ! ResetQueue(controller).
  controller->queue_->ResetQueue();

  // 4. Perform ! ReadableStreamDefaultControllerClearAlgorithms(controller).
  ClearAlgorithms(controller);

  // 5. Perform ! ReadableStreamError(stream, e).
  ReadableStream::Error(script_state, stream, e);
}

// This is an instance method rather than the static function in the standard,
// so |this| is |controller|.
std::optional<double> ReadableStreamDefaultController::GetDesiredSize() const {
  // https://streams.spec.whatwg.org/#readable-stream-default-controller-get-desired-size
  switch (controlled_readable_stream_->state_) {
    // 3. If state is "errored", return null.
    case ReadableStream::kErrored:
      return std::nullopt;

    // 4. If state is "closed", return 0.
    case ReadableStream::kClosed:
      return 0.0;

    case ReadableStream::kReadable:
      // 5. Return controller.[[strategyHWM]] − controller.[[queueTotalSize]].
      return strategy_high_water_mark_ - queue_->TotalSize();
  }
}

bool ReadableStreamDefaultController::CanCloseOrEnqueue(
    const ReadableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#readable-stream-default-controller-can-close-or-enqueue
  // 1. Let state be controller.[[controlledReadableStream]].[[state]].
  const auto state = controller->controlled_readable_stream_->state_;

  // 2. If controller.[[closeRequested]] is false and state is "readable",
  //    return true.
  // 3. Otherwise, return false.
  return !controller->is_close_requested_ && state == ReadableStream::kReadable;
}

bool ReadableStreamDefaultController::HasBackpressure(
    const ReadableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#rs-default-controller-has-backpressure
  // 1. If ! ReadableStreamDefaultControllerShouldCallPull(controller) is true,
  //    return false.
  // 2. Otherwise, return true.
  return !ShouldCallPull(controller);
}

// Used internally by enqueue() and also by TransformStream.
const char* ReadableStreamDefaultController::EnqueueExceptionMessage(
    const ReadableStreamDefaultController* controller) {
  if (controller->is_close_requested_) {
    return "Cannot enqueue a chunk into a readable stream that is closed or "
           "has been requested to be closed";
  }

  const ReadableStream* stream = controller->controlled_readable_stream_;
  const auto state = stream->state_;
  if (state == ReadableStream::kErrored) {
    return "Cannot enqueue a chunk into an errored readable stream";
  }
  CHECK(state == ReadableStream::kClosed);
  return "Cannot enqueue a chunk into a closed readable stream";
}

void ReadableStreamDefaultController::Trace(Visitor* visitor) const {
  visitor->Trace(cancel_algorithm_);
  visitor->Trace(controlled_readable_stream_);
  visitor->Trace(pull_algorithm_);
  visitor->Trace(queue_);
  visitor->Trace(strategy_size_algorithm_);
  visitor->Trace(resolve_function_);
  visitor->Trace(reject_function_);
  ScriptWrappable::Trace(visitor);
}

//
// Readable stream default controller internal methods
//

ScriptPromise<IDLUndefined> ReadableStreamDefaultController::CancelSteps(
    ScriptState* script_state,
    v8::Local<v8::Value> reason) {
  // https://streams.spec.whatwg.org/#rs-default-controller-private-cancel
  // 1. Perform ! ResetQueue(this).
  queue_->ResetQueue();

  // 2. Let result be the result of performing this.[[cancelAlgorithm]], passing
  //    reason.
  auto result = cancel_algorithm_->Run(script_state, 1, &reason);

  // 3. Perform ! ReadableStreamDefaultControllerClearAlgorithms(this).
  ClearAlgorithms(this);

  // 4. Return result.
  return result;
}

void ReadableStreamDefaultController::PullSteps(
    ScriptState* script_state,
    ReadRequest* read_request,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rs-default-controller-private-pull
  // 1. Let stream be this.[[stream]].
  ReadableStream* stream = controlled_readable_stream_;

  // 2. If this.[[queue]] is not empty,
  if (!queue_->IsEmpty()) {
    // a. Let chunk be ! DequeueValue(this).
    const auto chunk = queue_->DequeueValue(script_state->GetIsolate());

    // b. If this.[[closeRequested]] is true and this.[[queue]] is empty,
    if (is_close_requested_ && queue_->IsEmpty()) {
      //   i. Perform ! ReadableStreamDefaultControllerClearAlgorithms(this).
      ClearAlgorithms(this);

      //   ii. Perform ! ReadableStreamClose(stream).
      ReadableStream::Close(script_state, stream);
    } else {
      // c. Otherwise, perform !
      //    ReadableStreamDefaultControllerCallPullIfNeeded(this).
      CallPullIfNeeded(script_state, this);
    }

    // d. Perform readRequest’s chunk steps, given chunk.
    read_request->ChunkSteps(script_state, chunk, exception_state);
    // 3. Otherwise,
  } else {
    // a. Perform ! ReadableStreamAddReadRequest(stream, readRequest).
    ReadableStream::AddReadRequest(script_state, stream, read_request);

    // b. Perform ! ReadableStreamDefaultControllerCallPullIfNeeded(this).
    CallPullIfNeeded(script_state, this);
  }
}

void ReadableStreamDefaultController::ReleaseSteps() {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablestreamdefaultcontroller-releasesteps
  // 1. Return.
  return;
}

//
// Readable Stream Default Controller Abstract Operations
//

void ReadableStreamDefaultController::CallPullIfNeeded(
    ScriptState* script_state,
    ReadableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#readable-stream-default-controller-call-pull-if-needed
  // 1. Let shouldPull be ! ReadableStreamDefaultControllerShouldCallPull(
  //    controller).
  const bool should_pull = ShouldCallPull(controller);

  // 2. If shouldPull is false, return.
  if (!should_pull) {
    return;
  }

  // 3. If controller.[[pulling]] is true,
  if (controller->is_pulling_) {
    // a. Set controller.[[pullAgain]] to true.
    controller->will_pull_again_ = true;

    // b. Return.
    return;
  }

  // 4. Assert: controller.[[pullAgain]] is false.
  DCHECK(!controller->will_pull_again_);

  // 5. Set controller.[[pulling]] to true.
  controller->is_pulling_ = true;

  // 6. Let pullPromise be the result of performing
  //    controller.[[pullAlgorithm]].
  auto pull_promise =
      controller->pull_algorithm_->Run(script_state, 0, nullptr);

  pull_promise.Then(script_state, controller->resolve_function_.Get(),
                    controller->reject_function_.Get());
}

bool ReadableStreamDefaultController::ShouldCallPull(
    const ReadableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#readable-stream-default-controller-should-call-pull
  // 1. Let stream be controller.[[controlledReadableStream]].
  const ReadableStream* stream = controller->controlled_readable_stream_;

  // 2. If ! ReadableStreamDefaultControllerCanCloseOrEnqueue(controller) is
  //    false, return false.
  if (!CanCloseOrEnqueue(controller)) {
    return false;
  }

  // 3. If controller.[[started]] is false, return false.
  if (!controller->is_started_) {
    return false;
  }

  // 4. If ! IsReadableStreamLocked(stream) is true and !
  //    ReadableStreamGetNumReadRequests(stream) > 0, return true.
  if (ReadableStream::IsLocked(stream) &&
      ReadableStream::GetNumReadRequests(stream) > 0) {
    return true;
  }

  // 5. Let desiredSize be ! ReadableStreamDefaultControllerGetDesiredSize
  //    (controller).
  std::optional<double> desired_size = controller->GetDesiredSize();

  // 6. Assert: desiredSize is not null.
  DCHECK(desired_size.has_value());

  // 7. If desiredSize > 0, return true.
  // 8. Return false.
  return desired_size.value() > 0;
}

void ReadableStreamDefaultController::ClearAlgorithms(
    ReadableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#readable-stream-default-controller-clear-algorithms
  // 1. Set controller.[[pullAlgorithm]] to undefined.
  controller->pull_algorithm_ = nullptr;

  // 2. Set controller.[[cancelAlgorithm]] to undefined.
  controller->cancel_algorithm_ = nullptr;

  // 3. Set controller.[[strategySizeAlgorithm]] to undefined.
  controller->strategy_size_algorithm_ = nullptr;
}

void ReadableStreamDefaultController::SetUp(
    ScriptState* script_state,
    ReadableStream* stream,
    ReadableStreamDefaultController* controller,
    StreamStartAlgorithm* start_algorithm,
    StreamAlgorithm* pull_algorithm,
    StreamAlgorithm* cancel_algorithm,
    double high_water_mark,
    StrategySizeAlgorithm* size_algorithm,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#set-up-readable-stream-default-controller
  // 1. Assert: stream.[[readableStreamController]] is undefined.
  DCHECK(!stream->readable_stream_controller_);

  // 2. Set controller.[[controlledReadableStream]] to stream.
  controller->controlled_readable_stream_ = stream;

  // 3. Set controller.[[queue]] and controller.[[queueTotalSize]] to undefined,
  //    then perform ! ResetQueue(controller).
  // These steps are performed by the constructor, so just check that nothing
  // interfered.
  DCHECK(controller->queue_->IsEmpty());
  DCHECK_EQ(controller->queue_->TotalSize(), 0);

  // 5. Set controller.[[strategySizeAlgorithm]] to sizeAlgorithm and
  //    controller.[[strategyHWM]] to highWaterMark.
  controller->strategy_size_algorithm_ = size_algorithm;
  controller->strategy_high_water_mark_ = high_water_mark;

  // 6. Set controller.[[pullAlgorithm]] to pullAlgorithm.
  controller->pull_algorithm_ = pull_algorithm;

  // 7. Set controller.[[cancelAlgorithm]] to cancelAlgorithm.
  controller->cancel_algorithm_ = cancel_algorithm;

  // 8. Set stream.[[readableStreamController]] to controller.
  stream->readable_stream_controller_ = controller;

  // 9. Let startResult be the result of performing startAlgorithm. (This may
  //    throw an exception.)
  // 10. Let startPromise be a promise resolved with startResult.
  // The conversion of startResult to a promise happens inside start_algorithm
  // in this implementation.
  TryRethrowScope rethrow_scope(script_state->GetIsolate(), exception_state);
  auto start_promise = start_algorithm->Run(script_state);
  if (start_promise.IsEmpty()) {
    CHECK(rethrow_scope.HasCaught());
    return;
  }

  class ResolveFunction final
      : public ThenCallable<IDLUndefined, ResolveFunction> {
   public:
    explicit ResolveFunction(ReadableStreamDefaultController* controller)
        : controller_(controller) {}

    void React(ScriptState* script_state) {
      //  11. Upon fulfillment of startPromise,
      //    a. Set controller.[[started]] to true.
      controller_->is_started_ = true;

      //    b. Assert: controller.[[pulling]] is false.
      DCHECK(!controller_->is_pulling_);

      //    c. Assert: controller.[[pullAgain]] is false.
      DCHECK(!controller_->will_pull_again_);

      //    d. Perform ! ReadableStreamDefaultControllerCallPullIfNeeded(
      //       controller).
      CallPullIfNeeded(script_state, controller_);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(controller_);
      ThenCallable<IDLUndefined, ResolveFunction>::Trace(visitor);
    }

   private:
    const Member<ReadableStreamDefaultController> controller_;
  };

  class RejectFunction final : public ThenCallable<IDLAny, RejectFunction> {
   public:
    explicit RejectFunction(ReadableStreamDefaultController* controller)
        : controller_(controller) {}

    void React(ScriptState* script_state, ScriptValue r) {
      //  12. Upon rejection of startPromise with reason r,
      //    a. Perform ! ReadableStreamDefaultControllerError(controller, r).
      Error(script_state, controller_, r.V8Value());
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(controller_);
      ThenCallable<IDLAny, RejectFunction>::Trace(visitor);
    }

   private:
    const Member<ReadableStreamDefaultController> controller_;
  };

  start_promise.Then(script_state,
                     MakeGarbageCollected<ResolveFunction>(controller),
                     MakeGarbageCollected<RejectFunction>(controller));
}

void ReadableStreamDefaultController::SetUpFromUnderlyingSource(
    ScriptState* script_state,
    ReadableStream* stream,
    v8::Local<v8::Object> underlying_source,
    double high_water_mark,
    StrategySizeAlgorithm* size_algorithm,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#set-up-readable-stream-default-controller-from-underlying-source
  // 2. Let controller be ObjectCreate(the original value of
  //    ReadableStreamDefaultController's prototype property).
  auto* controller =
      MakeGarbageCollected<ReadableStreamDefaultController>(script_state);

  // This method is only called when a WritableStream is being constructed by
  // JavaScript. So the execution context should be valid and this call should
  // not crash.
  auto controller_value = ToV8Traits<ReadableStreamDefaultController>::ToV8(
      script_state, controller);

  // 3. Let startAlgorithm be the following steps:
  //   a. Return ? InvokeOrNoop(underlyingSource, "start", « controller »).
  auto* start_algorithm =
      CreateStartAlgorithm(script_state, underlying_source,
                           "underlyingSource.start", controller_value);

  // 4. Let pullAlgorithm be ? CreateAlgorithmFromUnderlyingMethod
  //    (underlyingSource, "pull", 0, « controller »).
  auto* pull_algorithm = CreateAlgorithmFromUnderlyingMethod(
      script_state, underlying_source, "pull", "underlyingSource.pull",
      controller_value, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 5. Let cancelAlgorithm be ? CreateAlgorithmFromUnderlyingMethod
  //    (underlyingSource, "cancel", 1, « »).
  auto* cancel_algorithm = CreateAlgorithmFromUnderlyingMethod(
      script_state, underlying_source, "cancel", "underlyingSource.cancel",
      controller_value, exception_state);
  if (exception_state.HadException()) {
    return;
  }

  // 6. Perform ? SetUpReadableStreamDefaultController(stream, controller,
  //    startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark,
  //    sizeAlgorithm).
  SetUp(script_state, stream, controller, start_algorithm, pull_algorithm,
        cancel_algorithm, high_water_mark, size_algorithm, exception_state);
}

}  // namespace blink

"""

```
Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Goal:** The request asks for the functionality of `writable_stream_default_controller.cc`, its relationship to web technologies, examples of logical reasoning, common user errors, and debugging steps.

2. **Initial Reading and Keyword Spotting:** Quickly skim the code, looking for recognizable terms and patterns. Keywords like "WritableStream," "Controller," "Promise," "queue," "abort," "close," "write," "backpressure," and the various "Algorithm" suffixes stand out. These immediately suggest this code is related to the Streams API in web browsers.

3. **Identify the Core Purpose:** The file name itself, `writable_stream_default_controller.cc`, strongly implies this class *controls* the behavior of a writable stream. The `#include` directives confirm this by referencing related stream classes.

4. **Deconstruct the Class Structure:** Notice the nested classes: `ProcessWriteResolveFunction` and `ProcessWriteRejectFunction`. These hint at how the controller handles the asynchronous nature of writing data to the underlying sink (success and failure). The presence of `ThenCallable` further reinforces the promise-based nature of the Streams API.

5. **Analyze Key Methods:**  Go through the public and significant private methods:
    * `SetUp` and `SetUpFromUnderlyingSink`: These are initialization methods. The latter clearly relates to how JavaScript creates writable streams with custom behavior.
    * `write`, `close`, `abort`, `error`: These are the core actions a writable stream controller needs to manage.
    * `AdvanceQueueIfNeeded`, `ProcessWrite`, `ProcessClose`: These suggest an internal mechanism for managing the order of write operations.
    * `GetBackpressure`, `GetDesiredSize`: These relate to flow control, a crucial aspect of streams.
    * `ErrorIfNeeded`:  Indicates error handling logic.

6. **Trace the Data Flow (Mentally):** Imagine how data moves through the system:
    * JavaScript calls `write()` on a `WritableStream`.
    * This triggers the `WritableStreamDefaultController::Write()` method.
    * The data is enqueued.
    * `AdvanceQueueIfNeeded()` checks if a write operation can be initiated.
    * `ProcessWrite()` executes the actual write operation (calling the `writeAlgorithm`).
    * The `ProcessWriteResolveFunction` or `ProcessWriteRejectFunction` handles the outcome.

7. **Connect to Web Technologies:**
    * **JavaScript:** The presence of `ScriptState`, `ScriptValue`, and interactions with V8 (e.g., `v8::Local<v8::Value>`) clearly show this code interfaces with JavaScript. The Streams API is a JavaScript API.
    * **HTML:** While not directly involved in *this* specific file, the Streams API is used in various web contexts, often dealing with data fetched or generated within a web page. Think of downloading files or processing media.
    * **CSS:** Less direct connection. However, if CSS animations or transitions were to *generate* data (conceivable, though less common), a writable stream could be used to handle that output.

8. **Identify Logical Reasoning:** Look for conditional logic (`if` statements) and how the code reacts to different states. The handling of backpressure (`GetBackpressure`, `UpdateBackpressure`) is a prime example of logical reasoning to manage data flow. The `AdvanceQueueIfNeeded` method embodies the logic of when to process the next chunk.

9. **Consider User Errors:**  Think about how a developer using the Streams API might make mistakes. For instance:
    * Writing to a closed or errored stream.
    * Providing an invalid size function.
    * The underlying sink throwing an error.

10. **Outline Debugging Steps:** Imagine you're a developer and something's going wrong with a writable stream. What would you do?  Setting breakpoints in relevant controller methods, inspecting the queue, and checking the stream's state are typical debugging approaches. Understanding the sequence of operations within the controller is key.

11. **Structure the Answer:**  Organize the findings into logical sections as requested by the prompt: functionality, relationship to web technologies, logical reasoning, user errors, and debugging. Use clear and concise language. Provide concrete examples wherever possible.

12. **Review and Refine:** Read through the answer to ensure accuracy, clarity, and completeness. Are the examples relevant? Is the explanation of logical reasoning clear? Is the debugging advice practical?

**Self-Correction/Refinement Example During Analysis:**

Initially, I might just say "handles writes." But then, by looking closer at `ProcessWriteResolveFunction` and `ProcessWriteRejectFunction`, I realize it's not just handling the write, but also the *asynchronous completion* (success or failure) of the write operation. This leads to a more nuanced understanding of the controller's role. Similarly, noticing the `close_queued_` flag helps understand how the "close" operation is handled as a special item in the queue. Recognizing the `AbortController` connects it to the broader web API for managing asynchronous operations.
好的，让我们来详细分析一下 `blink/renderer/core/streams/writable_stream_default_controller.cc` 这个文件。

**文件功能：**

`WritableStreamDefaultController` 类是 Blink 渲染引擎中用于管理 **WritableStream** API 的默认控制器。它的主要职责是协调和控制向底层数据接收器（sink）写入数据的过程。更具体地说，它负责：

1. **管理写入队列 (Queue):**  维护一个包含待写入数据的队列 (`queue_`)。
2. **处理写入请求 (Write):**  接收来自 JavaScript 的写入请求，并将数据加入队列。
3. **管理背压 (Backpressure):**  根据队列状态和高水位线 (high water mark) 计算背压，通知 `WritableStream` 何时可以继续写入。
4. **执行底层 Sink 的操作:** 调用底层 sink 对象的 `write`、`close` 和 `abort` 方法。
5. **处理 Promise:**  管理与底层 sink 操作相关的 Promise 的 resolve 和 reject 回调。
6. **处理关闭请求 (Close):**  处理 `WritableStream` 的关闭请求，调用底层 sink 的 `close` 方法。
7. **处理中止请求 (Abort):**  处理 `WritableStream` 的中止请求，调用底层 sink 的 `abort` 方法。
8. **处理错误 (Error):**  处理写入过程中发生的错误，并更新 `WritableStream` 的状态。
9. **管理状态:**  维护和更新与写入过程相关的内部状态。

**与 JavaScript, HTML, CSS 的关系：**

`WritableStreamDefaultController` 是 Web Streams API 在 Blink 引擎中的核心实现部分，它直接响应 JavaScript 代码的调用。

* **JavaScript:**
    * **创建 `WritableStream`:** 当 JavaScript 代码创建一个新的 `WritableStream` 实例时，通常会关联一个 `WritableStreamDefaultController`。例如：
      ```javascript
      const writableStream = new WritableStream({
        start(controller) {
          console.log("Stream started");
        },
        write(chunk, controller) {
          console.log("Writing chunk:", chunk);
          // 实际的写入逻辑（例如，发送到服务器）
        },
        close() {
          console.log("Stream closed");
        },
        abort(reason) {
          console.log("Stream aborted due to:", reason);
        }
      });
      ```
      在这个例子中，传递给 `WritableStream` 构造函数的对象定义了底层 sink 的行为，而 `WritableStreamDefaultController` 负责调用 `start`, `write`, `close`, 和 `abort` 方法。
    * **`WritableStream.getWriter()`:**  JavaScript 通过 `getWriter()` 方法获取一个 `WritableStreamDefaultWriter` 对象，然后使用该 writer 的 `write()`, `close()`, 和 `abort()` 方法来与 `WritableStreamDefaultController` 交互。例如：
      ```javascript
      const writer = writableStream.getWriter();
      writer.write("Hello, world!");
      writer.close();
      ```
      `writer.write()` 的调用最终会触发 `WritableStreamDefaultController::Write()` 方法。
    * **错误处理:** 当底层 sink 的 `write`, `close`, 或 `abort` 方法返回 rejected 的 Promise 时，`WritableStreamDefaultController` 会捕获这些 rejection 并更新 `WritableStream` 的状态，这会影响到 JavaScript 中对 stream 状态的观察和错误处理。

* **HTML:**
    * `WritableStream` 通常用于处理来自 HTML 元素（如 `<input type="file">` 或 `<canvas>`) 的数据流。例如，你可以创建一个 `WritableStream` 来接收从 canvas 读取的图像数据，并将其发送到服务器。
    * `fetch` API 的 `body` 可以是一个 `ReadableStream`，而你可以创建一个自定义的 `WritableStream` 并通过管道 (`pipeTo`) 将读取到的数据写入其中，实现自定义的数据处理逻辑。

* **CSS:**
    * CSS 本身与 `WritableStreamDefaultController` 的交互较少。然而，如果 CSS 动画或 transitions 触发了某些需要产生数据流的操作（这比较少见），那么这些操作可能会间接地使用 `WritableStream`。

**逻辑推理示例（假设输入与输出）：**

**假设输入：**

1. JavaScript 调用 `writer.write("some data")`。
2. 假设当前队列为空，且背压不高（`strategyHWM` 较高）。

**逻辑推理过程：**

1. `WritableStreamDefaultController::Write()` 被调用，参数 `chunk` 为 "some data"。
2. `GetChunkSize()` 方法可能会被调用来确定 chunk 的大小（取决于是否定义了 `size` 策略）。假设大小为 9（字符串长度）。
3. 数据 "some data" 和其大小 9 被加入到内部队列 `queue_` 中。
4. 由于队列之前为空，且背压不高，`WritableStreamDefaultController::AdvanceQueueIfNeeded()` 会被调用。
5. `AdvanceQueueIfNeeded()` 检查 `started_` 标志（假设为 true），没有正在进行的写入请求，且 stream 的状态是 "writable"。
6. `WritableStreamDefaultController::ProcessWrite()` 被调用，参数为 "some data"。
7. `ProcessWrite()` 调用底层 sink 的 `writeAlgorithm`（对应 JavaScript 中 `underlyingSink.write()` 方法），并将 "some data" 作为参数传递。
8. `writeAlgorithm` 返回一个 Promise。

**可能的输出：**

* **如果 `writeAlgorithm` 的 Promise resolve：**
    * `ProcessWriteResolveFunction::React()` 被调用。
    * `WritableStream::FinishInFlightWrite()` 被调用。
    * 数据 "some data" 从队列中移除。
    * 再次检查背压，并可能更新 `WritableStream` 的背压状态。
    * 再次调用 `AdvanceQueueIfNeeded()` 来处理队列中的下一个项目（如果存在）。
* **如果 `writeAlgorithm` 的 Promise reject：**
    * `ProcessWriteRejectFunction::React()` 被调用。
    * 如果 stream 状态仍然是 "writable"，则清除算法。
    * `WritableStream::FinishInFlightWriteWithError()` 被调用，并传递 rejection 的原因。
    * `WritableStream` 的状态会变为 "erroring" 或 "errored"。

**用户或编程常见的使用错误示例：**

1. **在流关闭后尝试写入:**
   * **用户操作:**  JavaScript 代码调用 `writer.close()` 关闭流后，仍然调用 `writer.write()` 尝试写入数据。
   * **到达这里:** `WritableStreamDefaultController::Write()` 会被调用。
   * **错误处理:**  `WritableStream` 的状态不再是 "writable"，`Write()` 方法会抛出一个错误（通常是 `InvalidStateError`）。

2. **底层 sink 的 `write` 方法抛出错误或返回 rejected Promise:**
   * **用户操作:**  底层 sink 的 `write` 方法实现中存在错误，例如网络请求失败或文件写入错误。
   * **到达这里:** `WritableStreamDefaultController::ProcessWrite()` 调用 `writeAlgorithm` 后，`writeAlgorithm` 返回的 Promise 被 reject。
   * **错误处理:** `ProcessWriteRejectFunction::React()` 被调用，`WritableStream` 进入错误状态，并且后续的写入操作会失败。

3. **在高背压时没有正确处理 "ready" Promise:**
   * **用户操作:**  JavaScript 代码没有正确地等待 `writer.ready` Promise resolve，就持续写入大量数据，导致背压过高。
   * **到达这里:**  虽然直接到达 `WritableStreamDefaultController` 的特定代码路径可能不明显，但背压的计算和更新逻辑在该控制器中。
   * **结果:**  虽然不会直接崩溃，但可能导致内存消耗过高或性能问题，最终可能导致浏览器标签页崩溃。

4. **提供无效的 `size` 函数:**
   * **用户操作:** 在创建 `WritableStream` 时，提供的 `size` 函数返回非数字值或抛出错误。
   * **到达这里:**  `WritableStreamDefaultController::GetChunkSize()` 会调用该 `size` 函数。
   * **错误处理:**  `GetChunkSize()` 会捕获错误，调用 `ErrorIfNeeded()`，并将 stream 置于错误状态。

**用户操作如何一步步到达这里（作为调试线索）：**

假设开发者遇到一个问题：向 `WritableStream` 写入数据时，数据没有被正确发送到服务器。

1. **JavaScript 代码创建 `WritableStream`:** 开发者首先在 JavaScript 中创建了一个 `WritableStream`，并定义了 `write` 方法来发送数据到服务器。
2. **获取 Writer:**  开发者通过 `writableStream.getWriter()` 获取了一个 `WritableStreamDefaultWriter` 实例。
3. **调用 `writer.write()`:**  开发者在某个事件触发时（例如，用户点击按钮），调用 `writer.write(data)` 来写入数据。
4. **Blink 处理 `writer.write()`:**  Blink 引擎接收到 `writer.write()` 的调用，并将其传递到 `blink::WritableStreamDefaultWriter::Write()`.
5. **进入 Controller:** `blink::WritableStreamDefaultWriter::Write()` 最终会调用到 `blink::WritableStreamDefaultController::Write()`.
6. **数据入队:**  在 `Write()` 方法中，数据被添加到内部队列 `queue_`。
7. **触发 `AdvanceQueueIfNeeded()`:**  `Write()` 方法可能会触发 `AdvanceQueueIfNeeded()` 来处理队列中的数据。
8. **执行底层写入:** `AdvanceQueueIfNeeded()` 判断可以进行写入后，会调用 `WritableStreamDefaultController::ProcessWrite()`.
9. **调用 `writeAlgorithm`:** `ProcessWrite()` 负责调用用户在 JavaScript 中定义的 `underlyingSink.write()` 方法 (由 `writeAlgorithm_` 指针指向)。
10. **调试线索:**  如果数据没有发送到服务器，开发者可以在以下几个关键点设置断点进行调试：
    * `WritableStreamDefaultController::Write()`: 检查数据是否正确进入队列。
    * `WritableStreamDefaultController::AdvanceQueueIfNeeded()`: 检查为什么队列中的数据没有被处理。
    * `WritableStreamDefaultController::ProcessWrite()`: 确认 `writeAlgorithm_` 是否被正确调用。
    * 用户自定义的 `underlyingSink.write()` 方法:  这是实际发送数据的逻辑，是排查网络问题的关键。
    * `ProcessWriteResolveFunction::React()` 和 `ProcessWriteRejectFunction::React()`: 检查 `writeAlgorithm_` 返回的 Promise 的状态，以确定写入是否成功。

通过理解 `WritableStreamDefaultController` 的功能和它在整个 Web Streams API 中的角色，开发者可以更有效地调试与 `WritableStream` 相关的错误。

### 提示词
```
这是目录为blink/renderer/core/streams/writable_stream_default_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/dom/abort_controller.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/promise_handler.h"
#include "third_party/blink/renderer/core/streams/queue_with_sizes.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

class WritableStreamDefaultController::ProcessWriteResolveFunction final
    : public ThenCallable<IDLUndefined, ProcessWriteResolveFunction> {
 public:
  ProcessWriteResolveFunction(WritableStream* stream,
                              WritableStreamDefaultController* controller)
      : stream_(stream), controller_(controller) {}

  void React(ScriptState* script_state) {
    // https://streams.spec.whatwg.org/#writable-stream-default-controller-process-write
    //  4. Upon fulfillment of sinkWritePromise,
    //      a. Perform ! WritableStreamFinishInFlightWrite(stream).
    WritableStream::FinishInFlightWrite(script_state, stream_);

    //      b. Let state be stream.[[state]].
    const auto state = stream_->GetState();

    //      c. Assert: state is "writable" or "erroring".
    CHECK(state == WritableStream::kWritable ||
          state == WritableStream::kErroring);

    //      d. Perform ! DequeueValue(controller).
    controller_->queue_->DequeueValue(script_state->GetIsolate());

    //      e. If ! WritableStreamCloseQueuedOrInFlight(stream) is false and
    //         state is "writable",
    if (!WritableStream::CloseQueuedOrInFlight(stream_) &&
        state == WritableStream::kWritable) {
      //          i. Let backpressure be !
      //             WritableStreamDefaultControllerGetBackpressure(
      //             controller).
      const bool backpressure =
          WritableStreamDefaultController::GetBackpressure(controller_);

      //         ii. Perform ! WritableStreamUpdateBackpressure(stream,
      //             backpressure).
      WritableStream::UpdateBackpressure(script_state, stream_, backpressure);
    }
    //      f. Perform ! WritableStreamDefaultControllerAdvanceQueueIfNeeded(
    //         controller).
    WritableStreamDefaultController::AdvanceQueueIfNeeded(script_state,
                                                          controller_);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream_);
    visitor->Trace(controller_);
    ThenCallable<IDLUndefined, ProcessWriteResolveFunction>::Trace(visitor);
  }

 private:
  Member<WritableStream> stream_;
  Member<WritableStreamDefaultController> controller_;
};

class WritableStreamDefaultController::ProcessWriteRejectFunction final
    : public ThenCallable<IDLAny, ProcessWriteRejectFunction> {
 public:
  ProcessWriteRejectFunction(WritableStream* stream,
                             WritableStreamDefaultController* controller)
      : stream_(stream), controller_(controller) {}

  void React(ScriptState* script_state, ScriptValue reason) {
    const auto state = stream_->GetState();
    //  5. Upon rejection of sinkWritePromise with reason,
    //      a. If stream.[[state]] is "writable", perform !
    //         WritableStreamDefaultControllerClearAlgorithms(controller).
    if (state == WritableStream::kWritable) {
      WritableStreamDefaultController::ClearAlgorithms(controller_);
    }

    //      b. Perform ! WritableStreamFinishInFlightWriteWithError(stream,
    //         reason).
    WritableStream::FinishInFlightWriteWithError(script_state, stream_,
                                                 reason.V8Value());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream_);
    visitor->Trace(controller_);
    ThenCallable<IDLAny, ProcessWriteRejectFunction>::Trace(visitor);
  }

 private:
  Member<WritableStream> stream_;
  Member<WritableStreamDefaultController> controller_;
};

WritableStreamDefaultController* WritableStreamDefaultController::From(
    ScriptState* script_state,
    ScriptValue controller) {
  CHECK(controller.IsObject());
  auto* controller_impl = V8WritableStreamDefaultController::ToWrappable(
      script_state->GetIsolate(), controller.V8Value().As<v8::Object>());
  CHECK(controller_impl);
  return controller_impl;
}

// Only used internally. Not reachable from JavaScript.
WritableStreamDefaultController::WritableStreamDefaultController()
    : queue_(MakeGarbageCollected<QueueWithSizes>()) {}

void WritableStreamDefaultController::error(ScriptState* script_state) {
  error(script_state, ScriptValue(script_state->GetIsolate(),
                                  v8::Undefined(script_state->GetIsolate())));
}

void WritableStreamDefaultController::error(ScriptState* script_state,
                                            ScriptValue e) {
  // https://streams.spec.whatwg.org/#ws-default-controller-error
  //  2. Let state be this.[[controlledWritableStream]].[[state]].
  const auto state = controlled_writable_stream_->GetState();

  //  3. If state is not "writable", return.
  if (state != WritableStream::kWritable) {
    return;
  }
  //  4. Perform ! WritableStreamDefaultControllerError(this, e).
  Error(script_state, this, e.V8Value());
}

// Writable Stream Default Controller Internal Methods

ScriptPromise<IDLUndefined> WritableStreamDefaultController::AbortSteps(
    ScriptState* script_state,
    v8::Local<v8::Value> reason) {
  // https://streams.spec.whatwg.org/#ws-default-controller-private-abort
  //  1. Let result be the result of performing this.[[abortAlgorithm]], passing
  //     reason.
  const auto result = abort_algorithm_->Run(script_state, 1, &reason);

  //  2. Perform ! WritableStreamDefaultControllerClearAlgorithms(this).
  ClearAlgorithms(this);

  //  3. Return result.
  return result;
}

void WritableStreamDefaultController::ErrorSteps() {
  // https://streams.spec.whatwg.org/#ws-default-controller-private-error
  //  1. Perform ! ResetQueue(this).
  queue_->ResetQueue();
}

// Writable Stream Default Controller Abstract Operations

// TODO(ricea): Should this be a constructor?
void WritableStreamDefaultController::SetUp(
    ScriptState* script_state,
    WritableStream* stream,
    WritableStreamDefaultController* controller,
    StreamStartAlgorithm* start_algorithm,
    StreamAlgorithm* write_algorithm,
    StreamAlgorithm* close_algorithm,
    StreamAlgorithm* abort_algorithm,
    double high_water_mark,
    StrategySizeAlgorithm* size_algorithm,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#set-up-writable-stream-default-controller
  //  2. Assert: stream.[[writableStreamController]] is undefined.
  DCHECK(!stream->Controller());

  //  3. Set controller.[[controlledWritableStream]] to stream.
  controller->controlled_writable_stream_ = stream;

  //  4. Set stream.[[writableStreamController]] to controller.
  stream->SetController(controller);

  // Step not needed because queue is initialised during construction.
  //  5. Perform ! ResetQueue(controller).

  //  6. Set controller.[[abortController]] to a new AbortController.
  controller->abort_controller_ = AbortController::Create(script_state);

  //  7. Set controller.[[started]] to false.
  controller->started_ = false;

  //  8. Set controller.[[strategySizeAlgorithm]] to sizeAlgorithm.
  controller->strategy_size_algorithm_ = size_algorithm;

  //  9. Set controller.[[strategyHWM]] to highWaterMark.
  controller->strategy_high_water_mark_ = high_water_mark;

  // 10. Set controller.[[writeAlgorithm]] to writeAlgorithm.
  controller->write_algorithm_ = write_algorithm;

  // 11. Set controller.[[closeAlgorithm]] to closeAlgorithm.
  controller->close_algorithm_ = close_algorithm;

  // 12. Set controller.[[abortAlgorithm]] to abortAlgorithm.
  controller->abort_algorithm_ = abort_algorithm;

  // 13. Let backpressure be !
  //     WritableStreamDefaultControllerGetBackpressure(controller).
  const bool backpressure = GetBackpressure(controller);

  // 14. Perform ! WritableStreamUpdateBackpressure(stream, backpressure).
  WritableStream::UpdateBackpressure(script_state, stream, backpressure);

  // 15. Let startResult be the result of performing startAlgorithm. (This may
  //     throw an exception.)
  // In this implementation, start_algorithm returns a Promise when it doesn't
  // throw.
  // 16. Let startPromise be a promise resolved with startResult.
  TryRethrowScope rethrow_scope(script_state->GetIsolate(), exception_state);
  auto start_promise = start_algorithm->Run(script_state);
  if (start_promise.IsEmpty()) {
    CHECK(rethrow_scope.HasCaught());
    return;
  }

  class ResolvePromiseFunction final
      : public ThenCallable<IDLUndefined, ResolvePromiseFunction> {
   public:
    explicit ResolvePromiseFunction(WritableStream* stream) : stream_(stream) {}

    void React(ScriptState* script_state) {
      // 17. Upon fulfillment of startPromise
      //      a. Assert: stream.[[state]] is "writable" or "erroring".
      const auto state = stream_->GetState();
      CHECK(state == WritableStream::kWritable ||
            state == WritableStream::kErroring);

      //      b. Set controller.[[started]] to true.
      WritableStreamDefaultController* controller = stream_->Controller();
      controller->started_ = true;

      //      c. Perform ! WritableStreamDefaultControllerAdvanceQueueIfNeeded(
      //         controller).
      WritableStreamDefaultController::AdvanceQueueIfNeeded(script_state,
                                                            controller);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(stream_);
      ThenCallable<IDLUndefined, ResolvePromiseFunction>::Trace(visitor);
    }

   private:
    Member<WritableStream> stream_;
  };

  class RejectPromiseFunction final
      : public ThenCallable<IDLAny, RejectPromiseFunction> {
   public:
    explicit RejectPromiseFunction(WritableStream* stream) : stream_(stream) {}

    void React(ScriptState* script_state, ScriptValue r) {
      // 18. Upon rejection of startPromise with reason r,
      //      a. Assert: stream.[[state]] is "writable" or "erroring".
      const auto state = stream_->GetState();
      CHECK(state == WritableStream::kWritable ||
            state == WritableStream::kErroring);

      //      b. Set controller.[[started]] to true.
      WritableStreamDefaultController* controller = stream_->Controller();
      controller->started_ = true;

      //      c. Perform ! WritableStreamDealWithRejection(stream, r).
      WritableStream::DealWithRejection(script_state, stream_, r.V8Value());
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(stream_);
      ThenCallable<IDLAny, RejectPromiseFunction>::Trace(visitor);
    }

   private:
    Member<WritableStream> stream_;
  };

  start_promise.Then(script_state,
                     MakeGarbageCollected<ResolvePromiseFunction>(stream),
                     MakeGarbageCollected<RejectPromiseFunction>(stream));

  controller->resolve_function_ =
      MakeGarbageCollected<ProcessWriteResolveFunction>(
          controller->controlled_writable_stream_, controller);
  controller->reject_function_ =
      MakeGarbageCollected<ProcessWriteRejectFunction>(
          controller->controlled_writable_stream_, controller);
}

// TODO(ricea): Should this be a constructor?
void WritableStreamDefaultController::SetUpFromUnderlyingSink(
    ScriptState* script_state,
    WritableStream* stream,
    v8::Local<v8::Object> underlying_sink,
    double high_water_mark,
    StrategySizeAlgorithm* size_algorithm,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#set-up-writable-stream-default-controller-from-underlying-sink
  //  1. Assert: underlyingSink is not undefined.
  DCHECK(!underlying_sink.IsEmpty());

  //  2. Let controller be ObjectCreate(the original value of
  //     WritableStreamDefaultController's prototype property).
  auto* controller = MakeGarbageCollected<WritableStreamDefaultController>();

  // This method is only called when a WritableStream is being constructed by
  // JavaScript. So the execution context should be valid and this call should
  // not crash.
  auto controller_value = ToV8Traits<WritableStreamDefaultController>::ToV8(
      script_state, controller);

  //  3. Let startAlgorithm be the following steps:
  //      a. Return ? InvokeOrNoop(underlyingSink, "start", « controller »).
  auto* start_algorithm = CreateStartAlgorithm(
      script_state, underlying_sink, "underlyingSink.start", controller_value);

  //  4. Let writeAlgorithm be ? CreateAlgorithmFromUnderlyingMethod(
  //     underlyingSink, "write", 1, « controller »).
  auto* write_algorithm = CreateAlgorithmFromUnderlyingMethod(
      script_state, underlying_sink, "write", "underlyingSink.write",
      controller_value, exception_state);
  if (exception_state.HadException()) {
    return;
  }
  DCHECK(write_algorithm);

  //  5. Let closeAlgorithm be ? CreateAlgorithmFromUnderlyingMethod(
  //     underlyingSink, "close", 0, « »).
  auto* close_algorithm = CreateAlgorithmFromUnderlyingMethod(
      script_state, underlying_sink, "close", "underlyingSink.close",
      v8::MaybeLocal<v8::Value>(), exception_state);
  if (exception_state.HadException()) {
    return;
  }
  DCHECK(close_algorithm);

  //  6. Let abortAlgorithm be ? CreateAlgorithmFromUnderlyingMethod(
  //     underlyingSink, "abort", 1, « »).
  auto* abort_algorithm = CreateAlgorithmFromUnderlyingMethod(
      script_state, underlying_sink, "abort", "underlyingSink.abort",
      v8::MaybeLocal<v8::Value>(), exception_state);
  if (exception_state.HadException()) {
    return;
  }
  DCHECK(abort_algorithm);

  //  7. Perform ? SetUpWritableStreamDefaultController(stream, controller,
  //     startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm,
  //     highWaterMark, sizeAlgorithm).
  SetUp(script_state, stream, controller, start_algorithm, write_algorithm,
        close_algorithm, abort_algorithm, high_water_mark, size_algorithm,
        exception_state);
}

void WritableStreamDefaultController::Close(
    ScriptState* script_state,
    WritableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-close
  //  1. Perform ! EnqueueValueWithSize(controller, "close", 0).
  // The |close_queued_| flag represents the presence of the `"close"` marker
  // in the queue.
  controller->close_queued_ = true;

  //  2. Perform ! WritableStreamDefaultControllerAdvanceQueueIfNeeded(
  //     controller).
  AdvanceQueueIfNeeded(script_state, controller);
}

double WritableStreamDefaultController::GetChunkSize(
    ScriptState* script_state,
    WritableStreamDefaultController* controller,
    v8::Local<v8::Value> chunk) {
  if (!controller->strategy_size_algorithm_) {
    DCHECK_NE(controller->controlled_writable_stream_->GetState(),
              WritableStream::kWritable);
    // No need to error since the stream is already stopped or stopping.
    return 1;
  }

  // https://streams.spec.whatwg.org/#writable-stream-default-controller-get-chunk-size
  //  1. Let returnValue be the result of performing
  //     controller.[[strategySizeAlgorithm]], passing in chunk, and
  //     interpreting the result as an ECMAScript completion value.
  v8::TryCatch try_catch(script_state->GetIsolate());
  auto return_value =
      controller->strategy_size_algorithm_->Run(script_state, chunk);

  //  2. If returnValue is an abrupt completion,
  if (!return_value.has_value()) {
    //      a. Perform ! WritableStreamDefaultControllerErrorIfNeeded(
    //         controller, returnValue.[[Value]]).
    ErrorIfNeeded(script_state, controller, try_catch.Exception());

    //      b. Return 1.
    return 1;
  }
  //  3. Return returnValue.[[Value]].
  return return_value.value();
}

double WritableStreamDefaultController::GetDesiredSize(
    const WritableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-get-desired-size
  //  1. Return controller.[[strategyHWM]] − controller.[[queueTotalSize]].
  return controller->strategy_high_water_mark_ -
         controller->queue_->TotalSize();
}

void WritableStreamDefaultController::Write(
    ScriptState* script_state,
    WritableStreamDefaultController* controller,
    v8::Local<v8::Value> chunk,
    double chunk_size,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-write
  // The chunk is represented literally in the queue, rather than being embedded
  // in an object, so the following step is not performed:
  //  1. Let writeRecord be Record {[[chunk]]: chunk}.
  {
    //  2. Let enqueueResult be EnqueueValueWithSize(controller, writeRecord,
    //     chunkSize).
    v8::Isolate* isolate = script_state->GetIsolate();
    v8::TryCatch try_catch(isolate);
    controller->queue_->EnqueueValueWithSize(isolate, chunk, chunk_size,
                                             PassThroughException(isolate));

    //  3. If enqueueResult is an abrupt completion,
    if (try_catch.HasCaught()) {
      //      a. Perform ! WritableStreamDefaultControllerErrorIfNeeded(
      //         controller, enqueueResult.[[Value]]).

      ErrorIfNeeded(script_state, controller, try_catch.Exception());

      //      b. Return.
      return;
    }
  }
  //  4. Let stream be controller.[[controlledWritableStream]].
  WritableStream* stream = controller->controlled_writable_stream_;

  //  5. If ! WritableStreamCloseQueuedOrInFlight(stream) is false and
  //     stream.[[state]] is "writable",
  if (!WritableStream::CloseQueuedOrInFlight(stream) &&
      stream->GetState() == WritableStream::kWritable) {
    //      a. Let backpressure be !
    //         WritableStreamDefaultControllerGetBackpressure(controller).
    const bool backpressure = GetBackpressure(controller);

    //      b. Perform ! WritableStreamUpdateBackpressure(stream, backpressure).
    WritableStream::UpdateBackpressure(script_state, stream, backpressure);
  }

  //  6. Perform ! WritableStreamDefaultControllerAdvanceQueueIfNeeded(
  //     controller).
  AdvanceQueueIfNeeded(script_state, controller);
}

void WritableStreamDefaultController::ErrorIfNeeded(
    ScriptState* script_state,
    WritableStreamDefaultController* controller,
    v8::Local<v8::Value> error) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-error-if-needed
  //  1. If controller.[[controlledWritableStream]].[[state]] is "writable",
  //     perform ! WritableStreamDefaultControllerError(controller, error).
  const auto state = controller->controlled_writable_stream_->GetState();
  if (state == WritableStream::kWritable) {
    Error(script_state, controller, error);
  }
}

void WritableStreamDefaultController::Trace(Visitor* visitor) const {
  visitor->Trace(abort_algorithm_);
  visitor->Trace(close_algorithm_);
  visitor->Trace(controlled_writable_stream_);
  visitor->Trace(queue_);
  visitor->Trace(abort_controller_);
  visitor->Trace(strategy_size_algorithm_);
  visitor->Trace(write_algorithm_);
  visitor->Trace(resolve_function_);
  visitor->Trace(reject_function_);
  ScriptWrappable::Trace(visitor);
}

void WritableStreamDefaultController::ClearAlgorithms(
    WritableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-clear-algorithms
  //  1. Set controller.[[writeAlgorithm]] to undefined.
  controller->write_algorithm_ = nullptr;

  //  2. Set controller.[[closeAlgorithm]] to undefined.
  controller->close_algorithm_ = nullptr;

  //  3. Set controller.[[abortAlgorithm]] to undefined.
  controller->abort_algorithm_ = nullptr;

  //  4. Set controller.[[strategySizeAlgorithm]] to undefined.
  controller->strategy_size_algorithm_ = nullptr;
}

void WritableStreamDefaultController::AdvanceQueueIfNeeded(
    ScriptState* script_state,
    WritableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-advance-queue-if-needed
  //  1. Let stream be controller.[[controlledWritableStream]].
  WritableStream* stream = controller->controlled_writable_stream_;

  //  2. If controller.[[started]] is false, return
  if (!controller->started_) {
    return;
  }

  //  3. If stream.[[inFlightWriteRequest]] is not undefined, return.
  if (stream->HasInFlightWriteRequest()) {
    return;
  }

  //  4. Let state be stream.[[state]].
  const auto state = stream->GetState();

  //  5. If state is "closed" or "errored", return.
  if (state == WritableStream::kClosed || state == WritableStream::kErrored) {
    return;
  }

  //  6. If state is "erroring",
  if (state == WritableStream::kErroring) {
    //      a. Perform ! WritableStreamFinishErroring(stream).
    WritableStream::FinishErroring(script_state, stream);

    //      b. Return.
    return;
  }

  //  7. If controller.[[queue]] is empty, return.
  if (controller->queue_->IsEmpty()) {
    // Empty queue + |close_queued_| true implies `"close"` marker in queue.
    //  9. If writeRecord is "close", perform !
    //     WritableStreamDefaultControllerProcessClose(controller).
    if (controller->close_queued_) {
      ProcessClose(script_state, controller);
    }
    return;
  }

  //  8. Let writeRecord be ! PeekQueueValue(controller).
  const auto chunk =
      controller->queue_->PeekQueueValue(script_state->GetIsolate());

  // 10. Otherwise, perform ! WritableStreamDefaultControllerProcessWrite(
  //     controller, writeRecord.[[chunk]]).
  // ("Otherwise" here means if the chunk is not a `"close"` marker).
  WritableStreamDefaultController::ProcessWrite(script_state, controller,
                                                chunk);
}

void WritableStreamDefaultController::ProcessClose(
    ScriptState* script_state,
    WritableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-process-close
  //  1. Let stream be controller.[[controlledWritableStream]].
  WritableStream* stream = controller->controlled_writable_stream_;

  //  2. Perform ! WritableStreamMarkCloseRequestInFlight(stream).
  WritableStream::MarkCloseRequestInFlight(stream);

  //  3. Perform ! DequeueValue(controller).
  // Here we "dequeue" the `"close"` marker, which is implied by the
  // |close_queued_| flag, by unsetting the flag.
  //  4. Assert: controller.[[queue]] is empty.
  DCHECK(controller->queue_->IsEmpty());
  DCHECK(controller->close_queued_);
  controller->close_queued_ = false;

  //  5. Let sinkClosePromise be the result of performing
  //     controller.[[closeAlgorithm]].
  const auto sinkClosePromise =
      controller->close_algorithm_->Run(script_state, 0, nullptr);

  //  6. Perform ! WritableStreamDefaultControllerClearAlgorithms(controller).
  ClearAlgorithms(controller);

  class ResolveFunction final
      : public ThenCallable<IDLUndefined, ResolveFunction> {
   public:
    explicit ResolveFunction(WritableStream* stream) : stream_(stream) {}

    void React(ScriptState* script_state) {
      //  7. Upon fulfillment of sinkClosePromise,
      //      a. Perform ! WritableStreamFinishInFlightClose(stream).
      WritableStream::FinishInFlightClose(script_state, stream_);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(stream_);
      ThenCallable<IDLUndefined, ResolveFunction>::Trace(visitor);
    }

   private:
    Member<WritableStream> stream_;
  };

  class RejectFunction final : public ThenCallable<IDLAny, RejectFunction> {
   public:
    explicit RejectFunction(WritableStream* stream) : stream_(stream) {}

    void React(ScriptState* script_state, ScriptValue reason) {
      //  8. Upon rejection of sinkClosePromise with reason reason,
      //      a. Perform ! WritableStreamFinishInFlightCloseWithError(stream,
      //         reason).
      WritableStream::FinishInFlightCloseWithError(script_state, stream_,
                                                   reason.V8Value());
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(stream_);
      ThenCallable<IDLAny, RejectFunction>::Trace(visitor);
    }

   private:
    Member<WritableStream> stream_;
  };

  sinkClosePromise.Then(script_state,
                        MakeGarbageCollected<ResolveFunction>(stream),
                        MakeGarbageCollected<RejectFunction>(stream));
}

void WritableStreamDefaultController::ProcessWrite(
    ScriptState* script_state,
    WritableStreamDefaultController* controller,
    v8::Local<v8::Value> chunk) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-process-write
  //  1. Let stream be controller.[[controlledWritableStream]].
  WritableStream* stream = controller->controlled_writable_stream_;

  //  2. Perform ! WritableStreamMarkFirstWriteRequestInFlight(stream).
  WritableStream::MarkFirstWriteRequestInFlight(stream);

  //  3. Let sinkWritePromise be the result of performing
  //     controller.[[writeAlgorithm]], passing in chunk.
  const auto sinkWritePromise =
      controller->write_algorithm_->Run(script_state, 1, &chunk);

  sinkWritePromise.Then(script_state, controller->resolve_function_.Get(),
                        controller->reject_function_.Get());
}

bool WritableStreamDefaultController::GetBackpressure(
    const WritableStreamDefaultController* controller) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-get-backpressure
  //  1. Let desiredSize be ! WritableStreamDefaultControllerGetDesiredSize(
  //     controller).
  const double desired_size = GetDesiredSize(controller);

  //  2. Return desiredSize ≤ 0.
  return desired_size <= 0;
}

void WritableStreamDefaultController::Error(
    ScriptState* script_state,
    WritableStreamDefaultController* controller,
    v8::Local<v8::Value> error) {
  // https://streams.spec.whatwg.org/#writable-stream-default-controller-error
  //  1. Let stream be controller.[[controlledWritableStream]].
  WritableStream* stream = controller->controlled_writable_stream_;

  //  2. Assert: stream.[[state]] is "writable".
  DCHECK_EQ(stream->GetState(), WritableStream::kWritable);

  //  3. Perform ! WritableStreamDefaultControllerClearAlgorithms(controller).
  ClearAlgorithms(controller);

  //  4. Perform ! WritableStreamStartErroring(stream, error).
  WritableStream::StartErroring(script_state, stream, error);
}

AbortSignal* WritableStreamDefaultController::signal() const {
  return abort_controller_->signal();
}

void WritableStreamDefaultController::Abort(ScriptState* script_state,
                                            ScriptValue reason) {
  abort_controller_->abort(script_state, reason);
}

}  // namespace blink
```
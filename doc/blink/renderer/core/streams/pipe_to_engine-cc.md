Response:
Let's break down the thought process to analyze the `pipe_to_engine.cc` file and generate the explanation.

1. **Understand the Goal:** The request asks for a functional overview of the file, its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning examples, common usage errors, and debugging guidance.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for prominent classes, methods, and concepts. Keywords like `PipeToEngine`, `ReadableStream`, `WritableStream`, `AbortSignal`, `Promise`, `ReadRequest`, `Write`, `Close`, `Cancel`, `Abort`, and function names like `Start`, `HandleNextEvent`, `Shutdown` immediately stand out. The namespaces and included headers (`bindings/core/v8`, `core/dom`, `core/execution_context`, `core/streams`) confirm it's part of the Blink rendering engine and deals with streams.

3. **Identify the Core Functionality:** The class name `PipeToEngine` and the method `Start` strongly suggest the primary purpose is to implement the `pipeTo()` functionality for streams. The presence of `ReadableStream` and `WritableStream` confirms this. The logic within `Start` seems to handle setting up the piping process.

4. **Deconstruct the `Start` Method:** This is crucial as it's the entry point. Analyze the steps:
    * **Assertions:** These validate preconditions (stream types, locking status).
    * **Reader/Writer Acquisition:** The code acquires readers and writers for the source and destination streams.
    * **Promise Creation:** A promise is created to represent the completion of the piping operation.
    * **Abort Signal Handling:** Logic is in place to handle abort signals, including an `AbortAlgorithm`.
    * **Initial State Checks:** `CheckInitialState` handles pre-existing error or closed states.
    * **Event Handling:** `HandleNextEvent` suggests the core read/write loop.
    * **Return Promise:** The function returns the promise created earlier.

5. **Trace the Data Flow and Control Flow:**  Follow the execution path after `Start`.
    * **`HandleNextEvent`:** This seems to manage backpressure and initiate reads.
    * **`PipeToReadRequest`:**  This class is used to handle data chunks read from the source stream. Its `ChunkSteps` method enqueues a microtask to write the chunk.
    * **`ReadRequestChunkStepsBody`:** This is the microtask that actually writes the chunk to the destination stream.
    * **Promise Chains:**  Notice the extensive use of `.Then()` and `.Catch()` on promises to handle success and error conditions at various stages (reader closed, writer closed, write errors).
    * **Shutdown Mechanisms:**  Several `Shutdown` and `ShutdownWithAction` methods indicate the logic for gracefully or abruptly stopping the piping process due to errors, closure, or abort signals.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  The core of the functionality is exposed through JavaScript's `ReadableStream.prototype.pipeTo()`. The code directly interacts with JavaScript promises and event loops.
    * **HTML:**  This code is indirectly related to HTML, as streams are often used in conjunction with fetching resources (e.g., `fetch().body.pipeTo()`).
    * **CSS:** Less direct relationship with CSS. Streams might be used for dynamically loading CSS resources, but this file doesn't handle CSS parsing or application directly.

7. **Identify Logical Reasoning Points:**
    * **Backpressure Handling:** The logic in `HandleNextEvent` based on `writer_->GetDesiredSizeInternal()` demonstrates reasoning about when to read more data based on the destination's capacity.
    * **Error Propagation:** The code explicitly handles propagating errors from either the source or destination stream and deciding whether to abort or cancel the other stream.
    * **Abort Signal Logic:**  The `AbortAlgorithm` shows reasoning about how to react to an abort signal and clean up resources.

8. **Consider Common Usage Errors:** Think about how a developer might misuse the `pipeTo()` API in JavaScript that would lead to this code being executed. Examples include piping to a locked stream or not handling potential errors.

9. **Debug Scenarios:** Imagine a situation where `pipeTo()` isn't working as expected. How would you trace the execution and potentially reach this C++ code?  Setting breakpoints in JavaScript and stepping into the browser's implementation is a key debugging technique.

10. **Structure the Explanation:** Organize the findings logically, starting with a high-level overview and then going into more detail for each aspect requested (functionality, web technology relation, logical reasoning, errors, debugging). Use clear headings and bullet points for readability.

11. **Refine and Elaborate:**  Review the generated explanation. Are there any ambiguities? Can any points be clarified further? For instance, explaining the purpose of the `WrappedPromiseResolve` and `WrappedPromiseReject` template classes adds detail.

**(Self-Correction Example during the process):**  Initially, I might focus heavily on the low-level stream operations. However, remembering the request to connect to web technologies, I would then shift focus to how this C++ code is invoked from JavaScript and the implications for web developers. Similarly, when describing logical reasoning, I need to provide concrete examples rather than just saying "it does logical reasoning."  Thinking about potential developer errors requires putting myself in the shoes of someone using the `pipeTo()` API.
这个文件 `blink/renderer/core/streams/pipe_to_engine.cc` 是 Chromium Blink 渲染引擎中，负责实现 **`ReadableStream.prototype.pipeTo()`** JavaScript API 的核心逻辑。  它处理将一个可读流（ReadableStream）的数据管道传输到一个可写流（WritableStream）的过程，并管理相关的错误处理、关闭和取消操作。

以下是它的主要功能和相关说明：

**1. 核心功能：实现 `ReadableStream.prototype.pipeTo()`**

*   **启动管道 (Start):**  `PipeToEngine::Start` 方法是管道操作的入口点。它接收可读流 (`readable`) 和可写流 (`destination`) 作为输入，并配置管道操作的各种参数（通过 `PipeOptions`）。
*   **数据传输循环 (HandleNextEvent, ReadRequestChunkStepsBody):**  它维护一个内部循环，从可读流读取数据块（chunk），然后将这些数据块写入可写流。
    *   `HandleNextEvent` 负责检查可写流的背压情况（`desiredSize`），只有当可写流准备好接收更多数据时，才会触发下一次读取。
    *   `PipeToReadRequest` 是一个 `ReadRequest` 的子类，用于处理从可读流读取数据的回调。当成功读取到数据块时，`ChunkSteps` 方法会被调用，它将数据块传递给 `ReadRequestChunkStepsBody` 进行写入操作。
    *   `ReadRequestChunkStepsBody`  实际调用可写流的 `Write` 方法来写入数据块。
*   **关闭和完成处理 (ReadableClosed):**  当可读流关闭时，`ReadableClosed` 方法会被调用。如果 `preventClose` 参数为 `false`，它会尝试关闭可写流。
*   **错误处理 (ReadableError, WritableError):**  处理可读流或可写流发生的错误。
    *   `ReadableError` 在可读流发生错误时调用，根据 `preventAbort` 参数决定是否中止可写流。
    *   `WritableError` 在可写流发生错误时调用，根据 `preventCancel` 参数决定是否取消可读流。
*   **中止处理 (AbortAlgorithm):**  处理通过 `AbortSignal` 传递的中止信号。
*   **资源清理 (Finalize):**  在管道操作完成（成功或失败）后，释放相关的资源，例如释放读写器的锁，移除中止信号监听器，并最终解决或拒绝与 `pipeTo()` 调用相关的 Promise。

**2. 与 JavaScript, HTML, CSS 的关系**

*   **JavaScript:**  这个文件直接实现了 JavaScript 的 `ReadableStream.prototype.pipeTo()` 方法的功能。JavaScript 代码调用 `pipeTo()` 后，Blink 引擎会将控制权交给这里的 C++ 代码来执行实际的流管道传输。
    ```javascript
    const readableStream = new ReadableStream(/* ... */);
    const writableStream = new WritableStream(/* ... */);

    readableStream.pipeTo(writableStream).then(() => {
      console.log('管道传输完成');
    }).catch(error => {
      console.error('管道传输出错:', error);
    });
    ```
    在这个 JavaScript 例子中，`pipeTo(writableStream)` 的调用最终会触发 `PipeToEngine::Start` 方法的执行。

*   **HTML:**  `pipeTo()` 经常用于处理从网络获取的资源，例如 `fetch` API 返回的 `ReadableStream`。HTML 中的 `<img>` 标签的 `src` 属性如果指向一个流式资源，也可能间接地涉及到流的处理，虽然 `pipe_to_engine.cc` 不直接处理 HTML 元素的渲染，但它是底层流处理的一部分。
    ```javascript
    fetch('https://example.com/some-large-file')
      .then(response => response.body.pipeTo(writableStream))
      .then(() => console.log('文件下载完成'));
    ```

*   **CSS:**  虽然不太常见，但理论上 `pipeTo()` 也可以用于处理 CSS 资源，例如动态加载 CSS 样式并通过流的方式应用到文档中。然而，`pipe_to_engine.cc` 自身不涉及 CSS 的解析和应用逻辑，它只负责流数据的传输。

**3. 逻辑推理举例**

假设输入：

*   `readableStream` 是一个产生数字 1 到 5 的可读流。
*   `writableStream` 是一个将接收到的数字打印到控制台的可写流。
*   `pipeOptions` 没有设置 `preventClose`, `preventAbort`, `preventCancel`。

输出：

1. `PipeToEngine::Start` 被调用。
2. `HandleNextEvent` 被调用，发现 `writableStream` 的 `desiredSize` 大于 0。
3. `ReadableStreamDefaultReader::Read` 从 `readableStream` 读取一个数据块（例如，数字 1）。
4. `PipeToReadRequest::ChunkSteps` 被调用，并将数据块 1 传递给 `ReadRequestChunkStepsBody`。
5. `ReadRequestChunkStepsBody` 调用 `WritableStreamDefaultWriter::Write` 将数字 1 写入 `writableStream`。
6. 重复步骤 2-5，直到 `readableStream` 的所有数据都被读取并写入。
7. 当 `readableStream` 关闭时，`ReadableClosed` 被调用。
8. 由于 `preventClose` 为 `false`，`WritableStreamDefaultWriter::CloseWithErrorPropagationAction` 被触发，尝试关闭 `writableStream`。
9. 与 `pipeTo()` 调用相关的 Promise 被解决。

**4. 用户或编程常见的使用错误**

*   **尝试将一个锁定的流传递给 `pipeTo()`:**  如果可读流或可写流已经被一个 reader 或 writer 锁定，调用 `pipeTo()` 会抛出异常。
    ```javascript
    const reader = readableStream.getReader();
    readableStream.pipeTo(writableStream); // 错误：readableStream 已被锁定
    ```
*   **在管道传输过程中关闭目标可写流：**  如果在管道传输过程中手动关闭了目标可写流，会导致管道提前结束，并且可能无法处理完所有的数据。
*   **未处理 `pipeTo()` 返回的 Promise 的 rejection:** 如果管道传输过程中发生错误（例如，可读流或可写流出错），`pipeTo()` 返回的 Promise 会被 rejected。如果开发者没有捕获这个 rejection，可能会导致未处理的 Promise 错误。
*   **忘记设置合适的 `pipeOptions`:**  例如，如果希望在源流出错时也中止目标流，需要确保不设置 `preventAbort: true`。

**5. 用户操作如何一步步到达这里（调试线索）**

1. **用户在网页上触发了一个操作，导致 JavaScript 代码执行。** 例如，点击了一个按钮，触发了一个 `fetch` 请求。
2. **JavaScript 代码获取到一个 `ReadableStream` 对象。** 这可能是 `fetch` API 的响应体 (`response.body`)，或者通过构造函数创建的自定义 `ReadableStream`。
3. **JavaScript 代码调用 `readableStream.pipeTo(writableStream, options)`。**  这是触发 `pipe_to_engine.cc` 中代码执行的关键步骤。
4. **Blink 引擎接收到 `pipeTo()` 的调用，并将控制权传递给 C++ 层的 `PipeToEngine::Start` 方法。**
5. **在 `PipeToEngine` 中，会创建相应的 reader 和 writer，并开始数据的管道传输循环。**
6. **如果需要在 C++ 代码中进行调试，开发者可以使用 Chromium 的调试工具 (如 `gdb`)，设置断点在 `pipe_to_engine.cc` 文件的相关方法中。**  例如，可以在 `PipeToEngine::Start` 或 `ReadRequestChunkStepsBody` 设置断点，观察数据流的传输过程和状态变化。

**调试技巧：**

*   **在 JavaScript 代码中记录流的状态：**  在调用 `pipeTo()` 前后，以及在 `pipeTo()` 返回的 Promise 的 `then` 和 `catch` 回调中，记录可读流和可写流的状态，有助于理解问题的发生阶段。
*   **使用浏览器开发者工具的网络面板：**  如果涉及网络请求，可以查看请求和响应的详情，包括 Headers 和 Response，以帮助理解流数据的来源和格式。
*   **在 Blink 源码中添加日志：**  如果需要深入了解 `pipe_to_engine.cc` 的执行过程，可以在关键方法中添加 `DLOG` 或 `LOG` 输出，然后在 Chromium 的控制台或日志文件中查看。

总而言之，`pipe_to_engine.cc` 是 Blink 引擎中实现 `pipeTo()` 功能的关键部分，它负责高效且可靠地将数据从一个流传输到另一个流，并处理各种可能的异常情况，与 JavaScript 的流 API 紧密相关。

### 提示词
```
这是目录为blink/renderer/core/streams/pipe_to_engine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/pipe_to_engine.h"

#include "third_party/blink/renderer/bindings/core/v8/promise_all.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/pipe_options.h"
#include "third_party/blink/renderer/core/streams/promise_handler.h"
#include "third_party/blink/renderer/core/streams/read_request.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_reader.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

class PipeToEngine::PipeToAbortAlgorithm final : public AbortSignal::Algorithm {
 public:
  PipeToAbortAlgorithm(PipeToEngine* engine, AbortSignal* signal)
      : engine_(engine), signal_(signal) {}
  ~PipeToAbortAlgorithm() override = default;

  void Run() override { engine_->AbortAlgorithm(signal_); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(engine_);
    visitor->Trace(signal_);
    Algorithm::Trace(visitor);
  }

 private:
  Member<PipeToEngine> engine_;
  Member<AbortSignal> signal_;
};

class PipeToEngine::PipeToReadRequest final : public ReadRequest {
 public:
  explicit PipeToReadRequest(PipeToEngine* instance) : instance_(instance) {}

  void ChunkSteps(ScriptState* script_state,
                  v8::Local<v8::Value> chunk,
                  ExceptionState&) const override {
    scoped_refptr<scheduler::EventLoop> event_loop =
        ExecutionContext::From(script_state)->GetAgent()->event_loop();
    v8::Global<v8::Value> value(script_state->GetIsolate(), chunk);
    event_loop->EnqueueMicrotask(
        WTF::BindOnce(&PipeToEngine::ReadRequestChunkStepsBody,
                      WrapPersistent(instance_.Get()),
                      WrapPersistent(script_state), std::move(value)));
  }

  void CloseSteps(ScriptState* script_state) const override {
    instance_->ReadableClosed();
  }

  void ErrorSteps(ScriptState* script_state,
                  v8::Local<v8::Value> e) const override {
    instance_->is_reading_ = false;
    if (instance_->is_shutting_down_) {
      // This function can be called during shutdown when the lock is
      // released. Exit early in that case.
      return;
    }
    instance_->ReadableError(
        instance_->Readable()->GetStoredError(script_state->GetIsolate()));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(instance_);
    ReadRequest::Trace(visitor);
  }

 private:
  Member<PipeToEngine> instance_;
};

// This implementation uses ScriptPromise::Then() extensively. Instead of
// creating  a dozen separate subclasses of ThenCallable<>, we use a single
// resolve and a single reject implementation and pass a method pointer at
// runtime to control the behaviour.
template <typename ReturnType>
class PipeToEngine::WrappedPromiseResolve final
    : public ThenCallable<IDLUndefined,
                          WrappedPromiseResolve<ReturnType>,
                          ReturnType> {
 public:
  using PromiseResolveReaction =
      std::conditional_t<std::is_same_v<IDLUndefined, ReturnType>,
                         void (PipeToEngine::*)(),
                         ScriptPromise<IDLUndefined> (PipeToEngine::*)()>;

  WrappedPromiseResolve(PipeToEngine* instance, PromiseResolveReaction method)
      : instance_(instance), method_(method) {}

  template <typename T = ReturnType>
    requires(std::is_same_v<T, IDLUndefined>)
  void React(ScriptState*) {
    (instance_->*method_)();
  }

  template <typename T = ReturnType>
    requires(std::is_same_v<T, IDLPromise<IDLUndefined>>)
  ScriptPromise<IDLUndefined> React(ScriptState*) {
    return (instance_->*method_)();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(instance_);
    ThenCallable<IDLUndefined, WrappedPromiseResolve<ReturnType>,
                 ReturnType>::Trace(visitor);
  }

 private:
  Member<PipeToEngine> instance_;
  PromiseResolveReaction method_;
};

class PipeToEngine::WrappedPromiseReject final
    : public ThenCallable<IDLAny, WrappedPromiseReject> {
 public:
  using PromiseRejectReaction = void (PipeToEngine::*)(v8::Local<v8::Value>);

  WrappedPromiseReject(PipeToEngine* instance, PromiseRejectReaction method)
      : instance_(instance), method_(method) {}

  void React(ScriptState*, ScriptValue value) {
    (instance_->*method_)(value.V8Value());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(instance_);
    ThenCallable<IDLAny, WrappedPromiseReject>::Trace(visitor);
  }

 private:
  Member<PipeToEngine> instance_;
  PromiseRejectReaction method_;
};

ScriptPromise<IDLUndefined> PipeToEngine::Start(
    ReadableStream* readable,
    WritableStream* destination,
    ExceptionState& exception_state) {
  // 1. Assert: source implements ReadableStream.
  DCHECK(readable);

  // 2. Assert: dest implements WritableStream.
  DCHECK(destination);

  // Not relevant to C++ implementation:
  // 3. Assert: preventClose, preventAbort, and preventCancel are all
  // booleans.

  // Already done by WebIDL bindings:
  // 4. If signal was not given, let signal be undefined.
  // 5. Assert: either signal is undefined, or signal implements AbortSignal.

  // 6. Assert: ! IsReadableStreamLocked(source) is false.
  DCHECK(!ReadableStream::IsLocked(readable));

  // 7. Assert: ! IsWritableStreamLocked(dest) is false.
  DCHECK(!WritableStream::IsLocked(destination));

  // 8. If source.[[controller]] implements ReadableByteStreamController, let
  //    reader be ! AcquireReadableStreamBYOBReader(source) or !
  //    AcquireReadableStreamDefaultReader(source), at the user agent's
  //    discretion.
  // 9. Otherwise, let reader be ! AcquireReadableStreamDefaultReader(source).
  reader_ = ReadableStream::AcquireDefaultReader(script_state_, readable,
                                                 exception_state);
  DCHECK(!exception_state.HadException());

  // 10. Let writer be ! AcquireWritableStreamDefaultWriter(dest).
  writer_ = WritableStream::AcquireDefaultWriter(script_state_, destination,
                                                 exception_state);
  DCHECK(!exception_state.HadException());

  // 11. Set source.[[disturbed]] to true.

  // 12. Let shuttingDown be false.
  DCHECK(!is_shutting_down_);

  // 13. Let promise be a new promise.
  promise_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state_);

  // 14. If signal is not undefined,
  if (auto* signal = pipe_options_->Signal()) {
    //   b. If signal is aborted, perform abortAlgorithm and
    //      return promise.
    if (signal->aborted()) {
      AbortAlgorithm(signal);
      return promise_->Promise();
    }

    //   c. Add abortAlgorithm to signal.
    abort_handle_ = signal->AddAlgorithm(
        MakeGarbageCollected<PipeToAbortAlgorithm>(this, signal));
  }

  // 15. In parallel ...
  // The rest of the algorithm is described in terms of a series of
  // constraints rather than as explicit steps.
  if (CheckInitialState()) {
    // Need to detect closing and error when we are not reading. This
    // corresponds to the following conditions from the standard:
    //     1. Errors must be propagated forward: if source.[[state]] is or
    //        becomes "errored", ...
    // and
    //     3. Closing must be propagated forward: if source.[[state]] is or
    //        becomes "closed", ...
    reader_->closed(script_state_)
        .Then(script_state_,
              MakeGarbageCollected<WrappedPromiseResolve<IDLUndefined>>(
                  this, &PipeToEngine::OnReaderClosed),
              MakeGarbageCollected<WrappedPromiseReject>(
                  this, &PipeToEngine::ReadableError));

    // Need to detect error when we are not writing. This corresponds to this
    // condition from the standard:
    //    2. Errors must be propagated backward: if dest.[[state]] is or
    //       becomes "errored", ...
    // We do not need to detect closure of the writable end of the pipe,
    // because we have it locked and so it can only be closed by us.
    writer_->closed(script_state_)
        .Catch(script_state_, MakeGarbageCollected<WrappedPromiseReject>(
                                  this, &PipeToEngine::WritableError));

    // Start the main read / write loop.
    HandleNextEvent();
  }

  // 16. Return promise.
  return promise_->Promise();
}

bool PipeToEngine::CheckInitialState() {
  auto* isolate = script_state_->GetIsolate();
  const auto state = Readable()->state_;

  // Both streams can be errored or closed. To perform the right action the
  // order of the checks must match the standard: "the following conditions
  // must be applied in order." This method only checks the initial state;
  // detection of state changes elsewhere is done through checking promise
  // reactions.

  // a. Errors must be propagated forward: if source.[[state]] is or
  //    becomes "errored",
  if (state == ReadableStream::kErrored) {
    ReadableError(Readable()->GetStoredError(isolate));
    return false;
  }

  // 2. Errors must be propagated backward: if dest.[[state]] is or becomes
  //    "errored",
  if (Destination()->IsErrored()) {
    WritableError(Destination()->GetStoredError(isolate));
    return false;
  }

  // 3. Closing must be propagated forward: if source.[[state]] is or
  //    becomes "closed", then
  if (state == ReadableStream::kClosed) {
    ReadableClosed();
    return false;
  }

  // 4. Closing must be propagated backward: if !
  //    WritableStreamCloseQueuedOrInFlight(dest) is true or dest.[[state]]
  //    is "closed",
  if (Destination()->IsClosingOrClosed()) {
    WritableStartedClosed();
    return false;
  }

  return true;
}

void PipeToEngine::AbortAlgorithm(AbortSignal* signal) {
  // a. Let abortAlgorithm be the following steps:
  //    i. Let error be signal's abort reason.
  v8::Local<v8::Value> error = signal->reason(script_state_).V8Value();

  // Steps ii. to iv. are implemented in AbortAlgorithmAction.

  //    v. Shutdown with an action consisting of getting a promise to wait for
  //       all of the actions in actions, and with error.
  ShutdownWithAction(&PipeToEngine::AbortAlgorithmAction, error);
}

ScriptPromise<IDLUndefined> PipeToEngine::AbortAlgorithmAction() {
  v8::Local<v8::Value> error = shutdown_error_.Get(script_state_->GetIsolate());

  // ii. Let actions be an empty ordered set.
  HeapVector<MemberScriptPromise<IDLUndefined>> actions;

  // This method runs later than the equivalent steps in the standard. This
  // means that it is safe to do the checks of the state of the destination
  // and source synchronously, simplifying the logic.

  // iii. If preventAbort is false, append the following action to actions:
  //      1. If dest.[[state]] is "writable", return !
  //         WritableStreamAbort(dest, error).
  //      2. Otherwise, return a promise resolved with undefined.
  if (!pipe_options_->PreventAbort() && Destination()->IsWritable()) {
    actions.push_back(
        WritableStream::Abort(script_state_, Destination(), error));
  }

  //  iv. If preventCancel is false, append the following action action to
  //      actions:
  //      1. If source.[[state]] is "readable", return !
  //         ReadableStreamCancel(source, error).
  //      2. Otherwise, return a promise resolved with undefined.
  if (!pipe_options_->PreventCancel() &&
      ReadableStream::IsReadable(Readable())) {
    actions.push_back(ReadableStream::Cancel(script_state_, Readable(), error));
  }

  return PromiseAll<IDLUndefined>::Create(script_state_.Get(), actions);
}

void PipeToEngine::HandleNextEvent() {
  DCHECK(!is_reading_);
  if (is_shutting_down_) {
    return;
  }

  std::optional<double> desired_size = writer_->GetDesiredSizeInternal();
  if (!desired_size.has_value()) {
    // This can happen if abort() is queued but not yet started when
    // pipeTo() is called. In that case [[storedError]] is not set yet, and
    // we need to wait until it is before we can cancel the pipe. Once
    // [[storedError]] has been set, the rejection handler set on the writer
    // closed promise above will detect it, so all we need to do here is
    // nothing.
    return;
  }

  if (desired_size.value() <= 0) {
    // Need to wait for backpressure to go away.
    writer_->ready(script_state_)
        .Then(script_state_,
              MakeGarbageCollected<WrappedPromiseResolve<IDLUndefined>>(
                  this, &PipeToEngine::HandleNextEvent),
              MakeGarbageCollected<WrappedPromiseReject>(
                  this, &PipeToEngine::WritableError));
    return;
  }

  ExceptionState exception_state(script_state_->GetIsolate(),
                                 v8::ExceptionContext::kUnknown, "", "");

  is_reading_ = true;
  auto* read_request = MakeGarbageCollected<PipeToReadRequest>(this);
  ReadableStreamDefaultReader::Read(script_state_, reader_, read_request,
                                    exception_state);
}

void PipeToEngine::ReadRequestChunkStepsBody(ScriptState* script_state,
                                             v8::Global<v8::Value> chunk) {
  // This is needed because this method runs as an enqueued microtask, so the
  // isolate needs a current context.
  ScriptState::Scope scope(script_state);
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kUnknown, "", "");
  is_reading_ = false;
  const auto write = WritableStreamDefaultWriter::Write(
      script_state, writer_, chunk.Get(script_state->GetIsolate()),
      exception_state);
  write.Catch(script_state_, MakeGarbageCollected<WrappedPromiseReject>(
                                 this, &PipeToEngine::WritableError));
  last_write_ = write;
  HandleNextEvent();
}

void PipeToEngine::OnReaderClosed() {
  if (!is_reading_) {
    ReadableClosed();
  }
}

void PipeToEngine::ReadableError(v8::Local<v8::Value> error) {
  // This function can be called during shutdown when the lock is released.
  // Exit early in that case.
  if (is_shutting_down_) {
    return;
  }

  // a. If preventAbort is false, shutdown with an action of !
  //    WritableStreamAbort(dest, source.[[storedError]]) and with
  //    source.[[storedError]].
  DCHECK(error->SameValue(
      Readable()->GetStoredError(script_state_->GetIsolate())));
  if (!pipe_options_->PreventAbort()) {
    ShutdownWithAction(&PipeToEngine::WritableStreamAbortAction, error);
  } else {
    // b. Otherwise, shutdown with source.[[storedError]].
    Shutdown(error);
  }
  return;
}

void PipeToEngine::WritableError(v8::Local<v8::Value> error) {
  // This function can be called during shutdown when the lock is released.
  // Exit early in that case.
  if (is_shutting_down_) {
    return;
  }

  // a. If preventCancel is false, shutdown with an action of !
  //    ReadableStreamCancel(source, dest.[[storedError]]) and with
  //    dest.[[storedError]].
  DCHECK(error->SameValue(
      Destination()->GetStoredError(script_state_->GetIsolate())));
  if (!pipe_options_->PreventCancel()) {
    ShutdownWithAction(&PipeToEngine::ReadableStreamCancelAction, error);
  } else {
    // b. Otherwise, shutdown with dest.[[storedError]].
    Shutdown(error);
  }
  return;
}

void PipeToEngine::ReadableClosed() {
  // a. If preventClose is false, shutdown with an action of !
  //    WritableStreamDefaultWriterCloseWithErrorPropagation(writer).
  if (!pipe_options_->PreventClose()) {
    ShutdownWithAction(
        &PipeToEngine::
            WritableStreamDefaultWriterCloseWithErrorPropagationAction,
        v8::MaybeLocal<v8::Value>());
  } else {
    // b. Otherwise, shutdown.
    Shutdown(v8::MaybeLocal<v8::Value>());
  }
}

void PipeToEngine::WritableStartedClosed() {
  // a. Assert: no chunks have been read or written.
  // This is trivially true because this method is only called from
  // CheckInitialState().

  // b. Let destClosed be a new TypeError.
  const auto dest_closed = v8::Exception::TypeError(
      V8String(script_state_->GetIsolate(), "Destination stream closed"));

  // c. If preventCancel is false, shutdown with an action of !
  //    ReadableStreamCancel(source, destClosed) and with destClosed.
  if (!pipe_options_->PreventCancel()) {
    ShutdownWithAction(&PipeToEngine::ReadableStreamCancelAction, dest_closed);
  } else {
    // d. Otherwise, shutdown with destClosed.
    Shutdown(dest_closed);
  }
}

void PipeToEngine::ShutdownWithAction(
    Action action,
    v8::MaybeLocal<v8::Value> original_error) {
  // a. If shuttingDown is true, abort these substeps.
  if (is_shutting_down_) {
    return;
  }

  // b. Set shuttingDown to true.
  is_shutting_down_ = true;

  // Store the action in case we need to call it asynchronously. This is safe
  // because the |is_shutting_down_| guard flag ensures that we can only reach
  // this assignment once.
  shutdown_action_ = action;

  // Store |original_error| as |shutdown_error_| if it was supplied.
  v8::Local<v8::Value> original_error_local;
  if (original_error.ToLocal(&original_error_local)) {
    shutdown_error_.Reset(script_state_->GetIsolate(), original_error_local);
  }
  ScriptPromise<IDLUndefined> p;

  // c. If dest.[[state]] is "writable" and !
  //    WritableStreamCloseQueuedOrInFlight(dest) is false,
  if (ShouldWriteQueuedChunks()) {
    //  i. If any chunks have been read but not yet written, write them to
    //     dest.
    // ii. Wait until every chunk that has been read has been written
    //     (i.e. the corresponding promises have settled).
    p = WriteQueuedChunks().Then(
        script_state_,
        MakeGarbageCollected<WrappedPromiseResolve<IDLPromise<IDLUndefined>>>(
            this, &PipeToEngine::InvokeShutdownAction));
  } else {
    // d. Let p be the result of performing action.
    p = InvokeShutdownAction();
  }

  // e. Upon fulfillment of p, finalize, passing along originalError if it
  //    was given.
  // f. Upon rejection of p with reason newError, finalize with newError.
  p.Then(script_state_,
         MakeGarbageCollected<WrappedPromiseResolve<IDLUndefined>>(
             this, &PipeToEngine::FinalizeWithOriginalErrorIfSet),
         MakeGarbageCollected<WrappedPromiseReject>(
             this, &PipeToEngine::FinalizeWithNewError));
}

void PipeToEngine::Shutdown(v8::MaybeLocal<v8::Value> error_maybe) {
  // a. If shuttingDown is true, abort these substeps.
  if (is_shutting_down_) {
    return;
  }

  // b. Set shuttingDown to true.
  is_shutting_down_ = true;

  // c. If dest.[[state]] is "writable" and !
  //    WritableStreamCloseQueuedOrInFlight(dest) is false,
  if (ShouldWriteQueuedChunks()) {
    // Need to stash the value of |error_maybe| since we are calling
    // Finalize() asynchronously.
    v8::Local<v8::Value> error;
    if (error_maybe.ToLocal(&error)) {
      shutdown_error_.Reset(script_state_->GetIsolate(), error);
    }

    //  i. If any chunks have been read but not yet written, write them to
    //     dest.
    // ii. Wait until every chunk that has been read has been written
    //     (i.e. the corresponding promises have settled).
    // d. Finalize, passing along error if it was given.
    WriteQueuedChunks().Then(
        script_state_,
        MakeGarbageCollected<WrappedPromiseResolve<IDLUndefined>>(
            this, &PipeToEngine::FinalizeWithOriginalErrorIfSet));
  } else {
    // d. Finalize, passing along error if it was given.
    Finalize(error_maybe);
  }
}

void PipeToEngine::FinalizeWithOriginalErrorIfSet() {
  v8::MaybeLocal<v8::Value> error_maybe;
  if (!shutdown_error_.IsEmpty()) {
    error_maybe = shutdown_error_.Get(script_state_->GetIsolate());
  }
  Finalize(error_maybe);
}

void PipeToEngine::FinalizeWithNewError(v8::Local<v8::Value> new_error) {
  Finalize(new_error);
}

void PipeToEngine::Finalize(v8::MaybeLocal<v8::Value> error_maybe) {
  // a. Perform ! WritableStreamDefaultWriterRelease(writer).
  WritableStreamDefaultWriter::Release(script_state_, writer_);

  // b. If reader implements ReadableStreamBYOBReader, perform !
  // ReadableStreamBYOBReaderRelease(reader).
  if (reader_->IsBYOBReader()) {
    ReadableStreamGenericReader* reader = reader_;
    ReadableStreamBYOBReader* byob_reader =
        To<ReadableStreamBYOBReader>(reader);
    ReadableStreamBYOBReader::Release(script_state_, byob_reader);
  } else {
    // c. Otherwise, perform ! ReadableStreamDefaultReaderRelease(reader).
    DCHECK(reader_->IsDefaultReader());
    ReadableStreamGenericReader* reader = reader_;
    ReadableStreamDefaultReader* default_reader =
        To<ReadableStreamDefaultReader>(reader);
    ReadableStreamDefaultReader::Release(script_state_, default_reader);
  }

  // d. If signal is not undefined, remove abortAlgorithm from signal.
  //
  // An abort algorithm is only added if the signal provided to pipeTo is not
  // undefined *and* not aborted, which means `abort_handle_` can be null if
  // signal is not undefined.
  if (abort_handle_) {
    auto* signal = pipe_options_->Signal();
    DCHECK(signal);
    signal->RemoveAlgorithm(abort_handle_);
  }

  v8::Local<v8::Value> error;
  if (error_maybe.ToLocal(&error)) {
    // e. If error was given, reject promise with error.
    promise_->Reject(error);
  } else {
    // f. Otherwise, resolve promise with undefined.
    promise_->Resolve();
  }
}

bool PipeToEngine::ShouldWriteQueuedChunks() const {
  // "If dest.[[state]] is "writable" and !
  // WritableStreamCloseQueuedOrInFlight(dest) is false"
  return Destination()->IsWritable() &&
         !WritableStream::CloseQueuedOrInFlight(Destination());
}

ScriptPromise<IDLUndefined> PipeToEngine::WriteQueuedChunks() {
  if (!last_write_.IsEmpty()) {
    // "Wait until every chunk that has been read has been written (i.e.
    // the corresponding promises have settled)"
    // This implies that we behave the same whether the promise fulfills or
    // rejects. IgnoreErrors() will convert a rejection into a successful
    // resolution.
    return last_write_.Unwrap().Catch(
        script_state_, MakeGarbageCollected<WrappedPromiseReject>(
                           this, &PipeToEngine::IgnoreErrors));
  }
  return ToResolvedUndefinedPromise(script_state_);
}

ScriptPromise<IDLUndefined> PipeToEngine::WritableStreamAbortAction() {
  return WritableStream::Abort(script_state_, Destination(), ShutdownError());
}

ScriptPromise<IDLUndefined> PipeToEngine::ReadableStreamCancelAction() {
  return ReadableStream::Cancel(script_state_, Readable(), ShutdownError());
}

ScriptPromise<IDLUndefined>
PipeToEngine::WritableStreamDefaultWriterCloseWithErrorPropagationAction() {
  return WritableStreamDefaultWriter::CloseWithErrorPropagation(script_state_,
                                                                writer_);
}

WritableStream* PipeToEngine::Destination() {
  return writer_->OwnerWritableStream();
}

const WritableStream* PipeToEngine::Destination() const {
  return writer_->OwnerWritableStream();
}

ReadableStream* PipeToEngine::Readable() {
  return reader_->owner_readable_stream_;
}

}  // namespace blink
```
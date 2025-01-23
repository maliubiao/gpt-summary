Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is a part of the `ReadableByteStreamController` class in the Chromium Blink engine. This class is responsible for managing the internal state and operations of a readable byte stream, which is a fundamental part of the Streams API in JavaScript.

To summarize the functionality, I need to analyze the methods present in the code snippet and understand their purpose within the context of the Streams API.

Here's a breakdown of the methods and their roles:

*   `InvalidateBYOBRequest`: Resets the `byob_request_`, likely related to "bring your own buffer" reading.
*   `SetUp`: Initializes the controller with essential parameters like algorithms for start, pull, and cancel operations, high water mark, and auto-allocation chunk size. It also handles the initial execution of the start algorithm.
*   `SetUpFromUnderlyingSource`: A higher-level setup method that takes an underlying source object (typically from JavaScript) and extracts the start, pull, and cancel algorithms, as well as the auto-allocate chunk size.
*   `FillHeadPullIntoDescriptor`: Updates the number of bytes filled in a `PullIntoDescriptor`.
*   `FillPullIntoDescriptorFromQueue`: Copies data from the internal queue to a `PullIntoDescriptor`.
*   `FillReadRequestFromQueue`:  Fulfills a read request by taking data from the internal queue.
*   `PullInto`: Handles a "pull into" request, where the consumer provides a buffer to read data into.
*   `HandleQueueDrain`: Called when the internal queue is drained, potentially closing the stream if necessary.
*   `ResetQueue`: Clears the internal queue.
*   `Respond`: Handles the response from a "pull into" request with a BYOB reader.
*   `RespondInClosedState`: Specific handling of a `respond` call when the stream is closed.
*   `RespondInReadableState`: Specific handling of a `respond` call when the stream is readable.
*   `RespondInternal`: The core logic for processing a `respond` call.

Based on these methods, the core functionality of `ReadableByteStreamController` revolves around:

1. **Initialization and Setup**: Setting up the stream and controller with configurations provided by the user or the underlying source.
2. **Data Management**: Managing an internal queue of data chunks and transferring data to consumers.
3. **Pulling Data**: Implementing the logic for fetching data from the underlying source when needed.
4. **"Pull Into" Requests**:  Handling requests where the consumer provides a buffer for reading data, especially with BYOB readers.
5. **State Management**: Keeping track of the stream's state (readable, closed, errored) and reacting accordingly.
6. **Error Handling**:  Managing and propagating errors.

The code interacts with JavaScript, HTML, and CSS indirectly through the Streams API. JavaScript uses the Streams API to interact with data sources and sinks. The behavior implemented in this C++ code directly affects how JavaScript streams function.

Regarding assumptions, the code relies on the correct implementation of the underlying algorithms (start, pull, cancel) and the integrity of the `PullIntoDescriptor` objects.

Potential usage errors include providing incorrect buffer sizes or types in "pull into" requests, or attempting to respond with an invalid number of bytes.
这是 `blink/renderer/core/streams/readable_byte_stream_controller.cc` 文件的第 2 部分，主要涵盖了 `ReadableByteStreamController` 的以下功能：

**核心功能归纳:**

*   **处理 “拉取到 (Pull Into)” 请求：**  这部分代码集中处理了客户端通过 `reader.read(view)`  发起的 "pull into" 请求，其中 `view` 是一个 `ArrayBufferView`。  `PullInto` 方法负责管理这些请求，包括：
    *   检查流的状态（关闭、可读）。
    *   处理 `ArrayBuffer` 的转移 (TransferArrayBuffer)。
    *   创建和管理 `PullIntoDescriptor` 对象，用于描述拉取操作的目标缓冲区。
    *   当有数据在队列中时，尝试直接从队列填充 `PullIntoDescriptor`。
    *   如果队列中没有足够的数据，将 `PullIntoDescriptor` 添加到 `pendingPullIntos_` 队列中，等待后续数据。
    *   如果流已关闭，则立即完成拉取操作。
    *   调用 `CallPullIfNeeded` 触发底层源的拉取操作。

*   **管理内部队列的排出 (Handle Queue Drain)：** `HandleQueueDrain` 方法在内部队列数据被消费后被调用。它的主要职责是：
    *   检查流的状态。
    *   如果队列已空且流请求关闭，则执行流的关闭操作。
    *   否则，调用 `CallPullIfNeeded` 尝试从底层源拉取更多数据。

*   **重置队列 (Reset Queue)：** `ResetQueue` 方法用于清空内部数据队列 (`queue_`) 并将队列总大小 (`queue_total_size_`) 重置为 0。

*   **处理 “响应 (Respond)” 请求 (针对 BYOB 读取器)：**  `Respond` 方法用于处理当使用 "bring your own buffer" (BYOB) 读取器时，底层源完成数据写入后发出的响应。它执行以下操作：
    *   断言存在待处理的 "pull into" 请求。
    *   检查流的状态，如果已关闭，则验证写入的字节数为 0。
    *   如果流可读，则验证写入的字节数不为 0，并且不会超出目标缓冲区的剩余空间。
    *   转移目标缓冲区的 `ArrayBuffer` 的所有权。
    *   调用 `RespondInternal` 执行核心的响应处理逻辑。

*   **根据流状态处理 “响应 (Respond)” 请求：**
    *   `RespondInClosedState`:  处理当流处于关闭状态时的响应。
    *   `RespondInReadableState`: 处理当流处于可读状态时的响应，包括填充 `PullIntoDescriptor`、将数据添加到队列（如果需要）、以及提交已完成的 `PullIntoDescriptor`。

*   **核心 “响应 (Respond)” 处理逻辑 (RespondInternal)：**  `RespondInternal` 方法包含了处理 "respond" 请求的核心步骤：
    *   获取第一个待处理的 `PullIntoDescriptor`。
    *   断言目标缓冲区是可以转移的。
    *   使当前的 BYOB 请求失效。
    *   根据流的状态调用相应的处理函数 (`RespondInClosedState` 或 `RespondInReadableState`)。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript `ReadableStream` API:** 这个 C++ 文件实现了 `ReadableByteStreamController` 的核心逻辑，它是 JavaScript 中 `ReadableStream` API 的底层实现。JavaScript 代码通过调用 `ReadableStream` 的方法（例如 `getReader({ mode: 'byob' })`，`reader.read(view)`，`controller.respond(bytesWritten)`）来间接地触发这里 C++ 代码的执行。

    **举例：**  在 JavaScript 中，你可以创建一个可读流并使用 BYOB 读取器：

    ```javascript
    const stream = new ReadableStream({
      start(controller) {
        // ...
      },
      pull(controller) {
        const view = controller.byobRequest.view;
        // ... 将数据写入 view ...
        controller.byobRequest.respond(bytesWritten);
      },
      cancel(reason) {
        // ...
      }
    }, {
      highWaterMark: 0,
      size() { return 1; }
    });

    const reader = stream.getReader({ mode: 'byob' });
    const buffer = new ArrayBuffer(1024);
    const view = new Uint8Array(buffer);
    reader.read(view).then(({ done, value }) => {
      // ... 处理读取的数据 ...
    });
    ```

    当 JavaScript 调用 `reader.read(view)` 时，最终会触发 `ReadableByteStreamController::PullInto` 方法，并将 `view` 封装成 `PullIntoDescriptor` 进行处理。 当底层 `pull` 方法通过 `controller.byobRequest.respond(bytesWritten)` 响应时，会触发 `ReadableByteStreamController::Respond` 方法。

*   **HTML 和 CSS：**  虽然这个文件本身不直接操作 HTML 或 CSS 的 DOM 结构，但 `ReadableStream` API 是 Web 平台的一部分，可以用于处理来自各种来源的数据，这些数据最终可能用于更新 HTML 或 CSS。

    **举例：** 你可以使用 `fetch` API 获取一个流式响应，这个响应的 `body` 就是一个 `ReadableStream`。 这个流的数据可能最终用于动态生成 HTML 内容或更新 CSS 样式。

**逻辑推理的假设输入与输出:**

**假设输入 (以 `FillPullIntoDescriptorFromQueue` 为例):**

*   `controller` 的内部队列 `queue_` 中包含多个 `QueueEntry` 对象，每个对象代表一个数据块（`ArrayBuffer`）。
*   `pull_into_descriptor` 描述了一个待填充的缓冲区，包含目标 `ArrayBuffer`、偏移量、长度等信息。
*   `controller->queue_total_size_` 大于 0。
*   `pull_into_descriptor->byte_length` 大于 `pull_into_descriptor->bytes_filled`。

**输出:**

*   如果队列中有足够的数据来填充 `pull_into_descriptor`，则会将队列中的数据复制到 `pull_into_descriptor` 的缓冲区中，并更新 `pull_into_descriptor->bytes_filled` 和 `controller->queue_total_size_`。返回 `true`。
*   如果队列中的数据不足以完全填充 `pull_into_descriptor`，则会尽可能多地复制数据，更新 `pull_into_descriptor->bytes_filled` 和 `controller->queue_total_size_`，但不会完全填满。返回 `false`。
*   如果 `pull_into_descriptor->buffer` 已分离，则抛出 `TypeError` 异常。

**用户或编程常见的使用错误举例:**

*   **在流关闭后尝试调用 `controller.respond()`:**  用户可能会在底层数据源操作完成之后，但流已经被关闭的情况下，尝试调用 `controller.respond()`。这会导致错误，因为流不再接受新的数据。
*   **在 `controller.respond()` 中提供不正确的 `bytesWritten` 值:**  `bytesWritten` 必须准确反映实际写入到 BYOB 缓冲区中的字节数。如果提供的 `bytesWritten` 为 0 但流仍处于可读状态，或者超过了缓冲区的剩余空间，都会导致错误。
*   **在 BYOB 模式下，提供的 `ArrayBufferView` 的大小不足以接收数据:** 如果底层数据源尝试写入的数据量超过了 `reader.read(view)` 中提供的 `view` 的剩余空间，会导致数据丢失或错误。
*   **在 `pull()` 方法中没有正确调用 `controller.byobRequest.respond()`:**  在使用 BYOB 读取器时，`pull()` 方法必须通过 `controller.byobRequest.respond()` 来通知流控制器数据已写入，否则流会一直处于等待状态。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在 JavaScript 中创建了一个 `ReadableStream` 并获取了一个 BYOB 读取器：**  例如 `stream.getReader({ mode: 'byob' })`。
2. **用户调用了 `reader.read(view)`，并提供了一个 `ArrayBufferView`：** 这会触发 `ReadableByteStreamController::PullInto` 方法。
3. **如果内部队列为空，并且需要从底层数据源拉取数据，会触发 `pull()` 方法。**
4. **在 `pull()` 方法中，底层数据源将数据写入到 `controller.byobRequest.view` 中。**
5. **底层数据源调用 `controller.byobRequest.respond(bytesWritten)` 来通知控制器数据已写入。**  这个调用会触发 `ReadableByteStreamController::Respond` 方法。
6. **`Respond` 方法会根据流的状态调用 `RespondInClosedState` 或 `RespondInReadableState` 来处理响应。**
7. **如果在可读状态下，`RespondInReadableState` 可能会调用 `FillHeadPullIntoDescriptor` 来更新已填充的字节数。**
8. **如果 `PullIntoDescriptor` 已经填满或者达到了元素大小的边界，可能会调用 `CommitPullIntoDescriptor` 来完成读取操作，并将数据传递回 JavaScript。**

通过查看 JavaScript 代码中 `ReadableStream` 的创建和读取操作，可以追踪到这里 C++ 代码的执行路径。调试时，可以在 C++ 代码中设置断点，观察 `ReadableByteStreamController` 的状态变化以及各个方法的调用顺序。

### 提示词
```
这是目录为blink/renderer/core/streams/readable_byte_stream_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
yBufferView>(nullptr);
  // 4. Set controller.[[byobRequest]] to null.
  controller->byob_request_ = nullptr;
}

void ReadableByteStreamController::SetUp(
    ScriptState* script_state,
    ReadableStream* stream,
    ReadableByteStreamController* controller,
    StreamStartAlgorithm* start_algorithm,
    StreamAlgorithm* pull_algorithm,
    StreamAlgorithm* cancel_algorithm,
    double high_water_mark,
    size_t auto_allocate_chunk_size,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#set-up-readable-byte-stream-controller
  // 1. Assert: stream.[[controller]] is undefined.
  DCHECK(!stream->readable_stream_controller_);
  // 2. If autoAllocateChunkSize is not undefined,
  if (auto_allocate_chunk_size) {
    //   a. Assert: ! IsInteger(autoAllocateChunkSize) is true.
    //   b. Assert: autoAllocateChunkSize is positive.
    //   Due to autoAllocateChunkSize having the [EnforceRange] attribute, it
    //   can never be negative.
    DCHECK_GT(auto_allocate_chunk_size, 0u);
  }
  // 3. Set controller.[[stream]] to stream.
  controller->controlled_readable_stream_ = stream;
  // 4. Set controller.[[pullAgain]] and controller.[[pulling]] to false.
  DCHECK(!controller->pull_again_);
  DCHECK(!controller->pulling_);
  // 5. Set controller.[[byobRequest]] to null.
  DCHECK(!controller->byob_request_);
  // 6. Perform ! ResetQueue(controller).
  ResetQueue(controller);
  // 7. Set controller.[[closeRequested]] and controller.[[started]] to false.
  DCHECK(!controller->close_requested_);
  DCHECK(!controller->started_);
  // 8. Set controller.[[strategyHWM]] to highWaterMark.
  controller->strategy_high_water_mark_ = high_water_mark;
  // 9. Set controller.[[pullAlgorithm]] to pullAlgorithm.
  controller->pull_algorithm_ = pull_algorithm;
  // 10. Set controller.[[cancelAlgorithm]] to cancelAlgorithm.
  controller->cancel_algorithm_ = cancel_algorithm;
  // 11. Set controller.[[autoAllocateChunkSize]] to autoAllocateChunkSize.
  controller->auto_allocate_chunk_size_ = auto_allocate_chunk_size;
  // 12. Set controller.[[pendingPullIntos]] to a new empty list.
  DCHECK(controller->pending_pull_intos_.empty());
  // 13. Set stream.[[controller]] to controller.
  stream->readable_stream_controller_ = controller;
  // 14. Let startResult be the result of performing startAlgorithm.
  // 15. Let startPromise be a promise resolved with startResult.
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
    explicit ResolveFunction(ReadableByteStreamController* controller)
        : controller_(controller) {}

    void React(ScriptState* script_state) {
      // 16. Upon fulfillment of startPromise,
      //   a. Set controller.[[started]] to true.
      controller_->started_ = true;
      //   b. Assert: controller.[[pulling]] is false.
      DCHECK(!controller_->pulling_);
      //   c. Assert: controller.[[pullAgain]] is false.
      DCHECK(!controller_->pull_again_);
      //   d. Perform !
      //   ReadableByteStreamControllerCallPullIfNeeded(controller).
      CallPullIfNeeded(script_state, controller_);
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(controller_);
      ThenCallable<IDLUndefined, ResolveFunction>::Trace(visitor);
    }

   private:
    const Member<ReadableByteStreamController> controller_;
  };

  class RejectFunction final : public ThenCallable<IDLAny, RejectFunction> {
   public:
    explicit RejectFunction(ReadableByteStreamController* controller)
        : controller_(controller) {}

    void React(ScriptState* script_state, ScriptValue r) {
      // 17. Upon rejection of startPromise with reason r,
      //   a. Perform ! ReadableByteStreamControllerError(controller, r).
      Error(script_state, controller_, r.V8Value());
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(controller_);
      ThenCallable<IDLAny, RejectFunction>::Trace(visitor);
    }

   private:
    const Member<ReadableByteStreamController> controller_;
  };

  start_promise.Then(script_state,
                     MakeGarbageCollected<ResolveFunction>(controller),
                     MakeGarbageCollected<RejectFunction>(controller));
}

void ReadableByteStreamController::SetUpFromUnderlyingSource(
    ScriptState* script_state,
    ReadableStream* stream,
    v8::Local<v8::Object> underlying_source,
    UnderlyingSource* underlying_source_dict,
    double high_water_mark,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#set-up-readable-byte-stream-controller-from-underlying-source
  // 1. Let controller be a new ReadableByteStreamController.
  ReadableByteStreamController* controller =
      MakeGarbageCollected<ReadableByteStreamController>();
  // 2. Let startAlgorithm be an algorithm that returns undefined.
  StreamStartAlgorithm* start_algorithm = CreateTrivialStartAlgorithm();
  // 3. Let pullAlgorithm be an algorithm that returns a promise resolved with
  // undefined.
  StreamAlgorithm* pull_algorithm = CreateTrivialStreamAlgorithm();
  // 4. Let cancelAlgorithm be an algorithm that returns a promise resolved with
  // undefined.
  StreamAlgorithm* cancel_algorithm = CreateTrivialStreamAlgorithm();

  const auto controller_value =
      ToV8Traits<ReadableByteStreamController>::ToV8(script_state, controller);
  // 5. If underlyingSourceDict["start"] exists, then set startAlgorithm to an
  // algorithm which returns the result of invoking
  // underlyingSourceDict["start"] with argument list « controller » and
  // callback this value underlyingSource.
  if (underlying_source_dict->hasStart()) {
    start_algorithm = CreateByteStreamStartAlgorithm(
        script_state, underlying_source,
        ToV8Traits<V8UnderlyingSourceStartCallback>::ToV8(
            script_state, underlying_source_dict->start()),
        controller_value);
  }
  // 6. If underlyingSourceDict["pull"] exists, then set pullAlgorithm to an
  // algorithm which returns the result of invoking underlyingSourceDict["pull"]
  // with argument list « controller » and callback this value underlyingSource.
  if (underlying_source_dict->hasPull()) {
    pull_algorithm = CreateAlgorithmFromResolvedMethod(
        script_state, underlying_source,
        ToV8Traits<V8UnderlyingSourcePullCallback>::ToV8(
            script_state, underlying_source_dict->pull()),
        controller_value);
  }
  // 7. If underlyingSourceDict["cancel"] exists, then set cancelAlgorithm to an
  // algorithm which takes an argument reason and returns the result of invoking
  // underlyingSourceDict["cancel"] with argument list « reason » and callback
  // this value underlyingSource.
  if (underlying_source_dict->hasCancel()) {
    cancel_algorithm = CreateAlgorithmFromResolvedMethod(
        script_state, underlying_source,
        ToV8Traits<V8UnderlyingSourceCancelCallback>::ToV8(
            script_state, underlying_source_dict->cancel()),
        controller_value);
  }
  // 8. Let autoAllocateChunkSize be
  // underlyingSourceDict["autoAllocateChunkSize"], if it exists, or undefined
  // otherwise.
  size_t auto_allocate_chunk_size =
      underlying_source_dict->hasAutoAllocateChunkSize()
          ? static_cast<size_t>(underlying_source_dict->autoAllocateChunkSize())
          : 0u;
  // 9. If autoAllocateChunkSize is 0, then throw a TypeError exception.
  if (underlying_source_dict->hasAutoAllocateChunkSize() &&
      auto_allocate_chunk_size == 0) {
    exception_state.ThrowTypeError("autoAllocateChunkSize cannot be 0");
    return;
  }
  // 10. Perform ? SetUpReadableByteStreamController(stream, controller,
  // startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark,
  // autoAllocateChunkSize).
  SetUp(script_state, stream, controller, start_algorithm, pull_algorithm,
        cancel_algorithm, high_water_mark, auto_allocate_chunk_size,
        exception_state);
}

void ReadableByteStreamController::FillHeadPullIntoDescriptor(
    ReadableByteStreamController* controller,
    size_t size,
    PullIntoDescriptor* pull_into_descriptor) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-fill-head-pull-into-descriptor
  // 1. Assert: either controller.[[pendingPullIntos]] is empty, or
  // controller.[[pendingPullIntos]][0] is pullIntoDescriptor.
  DCHECK(controller->pending_pull_intos_.empty() ||
         controller->pending_pull_intos_[0] == pull_into_descriptor);
  // 2. Assert: controller.[[byobRequest]] is null.
  DCHECK(!controller->byob_request_);
  // 3. Set pullIntoDescriptor’s bytes filled to bytes filled + size.
  pull_into_descriptor->bytes_filled =
      base::CheckAdd(pull_into_descriptor->bytes_filled, size).ValueOrDie();
}

bool ReadableByteStreamController::FillPullIntoDescriptorFromQueue(
    ReadableByteStreamController* controller,
    PullIntoDescriptor* pull_into_descriptor,
    ExceptionState& exception_state) {
  if (pull_into_descriptor->buffer->IsDetached()) {
    exception_state.ThrowTypeError("buffer is detached");
    return false;
  }
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-fill-pull-into-descriptor-from-queue
  // 1. Let elementSize be pullIntoDescriptor.[[elementSize]].
  const size_t element_size = pull_into_descriptor->element_size;
  // 2. Let currentAlignedBytes be pullIntoDescriptor's bytes filled −
  // (pullIntoDescriptor's bytes filled mod elementSize).
  const size_t current_aligned_bytes =
      pull_into_descriptor->bytes_filled -
      (pull_into_descriptor->bytes_filled % element_size);
  // 3. Let maxBytesToCopy be min(controller.[[queueTotalSize]],
  // pullIntoDescriptor’s byte length − pullIntoDescriptor’s bytes filled).
  // The subtraction will not underflow because bytes length will always be more
  // than or equal to bytes filled.
  const size_t max_bytes_to_copy = std::min(
      static_cast<size_t>(controller->queue_total_size_),
      pull_into_descriptor->byte_length - pull_into_descriptor->bytes_filled);
  // 4. Let maxBytesFilled be pullIntoDescriptor’s bytes filled +
  // maxBytesToCopy.
  // This addition will not overflow because maxBytesToCopy can be at most
  // queue_total_size_. Both bytes_filled and queue_total_size_ refer to
  // actually allocated memory, so together they cannot exceed size_t.
  const size_t max_bytes_filled =
      pull_into_descriptor->bytes_filled + max_bytes_to_copy;
  // 5. Let maxAlignedBytes be maxBytesFilled − (maxBytesFilled mod
  // elementSize).
  // This subtraction will not underflow because the modulus operator is
  // guaranteed to return a value less than or equal to the first argument.
  const size_t max_aligned_bytes =
      max_bytes_filled - (max_bytes_filled % element_size);
  // 6. Let totalBytesToCopyRemaining be maxBytesToCopy.
  size_t total_bytes_to_copy_remaining = max_bytes_to_copy;
  // 7. Let ready be false;
  bool ready = false;
  // 8. If maxAlignedBytes > currentAlignedBytes,
  if (max_aligned_bytes > current_aligned_bytes) {
    // a. Set totalBytesToCopyRemaining to maxAlignedBytes −
    // pullIntoDescriptor’s bytes filled.
    total_bytes_to_copy_remaining =
        base::CheckSub(max_aligned_bytes, pull_into_descriptor->bytes_filled)
            .ValueOrDie();
    // b. Set ready to true.
    ready = true;
  }
  // 9. Let queue be controller.[[queue]].
  HeapDeque<Member<QueueEntry>>& queue = controller->queue_;
  // 10. While totalBytesToCopyRemaining > 0,
  while (total_bytes_to_copy_remaining > 0) {
    // a. Let headOfQueue be queue[0].
    QueueEntry* head_of_queue = queue[0];
    // b. Let bytesToCopy be min(totalBytesToCopyRemaining,
    // headOfQueue’s byte length).
    size_t bytes_to_copy =
        std::min(total_bytes_to_copy_remaining, head_of_queue->byte_length);
    // c. Let destStart be pullIntoDescriptor’s byte offset +
    // pullIntoDescriptor’s bytes filled.
    // This addition will not overflow because byte offset and bytes filled
    // refer to actually allocated memory, so together they cannot exceed
    // size_t.
    size_t dest_start =
        pull_into_descriptor->byte_offset + pull_into_descriptor->bytes_filled;
    // d. Perform ! CopyDataBlockBytes(pullIntoDescriptor’s
    // buffer.[[ArrayBufferData]], destStart, headOfQueue’s
    // buffer.[[ArrayBufferData]], headOfQueue’s byte offset, bytesToCopy).
    auto copy_destination = pull_into_descriptor->buffer->ByteSpan().subspan(
        dest_start, bytes_to_copy);
    auto copy_source = head_of_queue->buffer->ByteSpan().subspan(
        head_of_queue->byte_offset, bytes_to_copy);
    copy_destination.copy_from(copy_source);
    // e. If headOfQueue’s byte length is bytesToCopy,
    if (head_of_queue->byte_length == bytes_to_copy) {
      //   i. Remove queue[0].
      queue.pop_front();
    } else {
      // f. Otherwise,
      //   i. Set headOfQueue’s byte offset to headOfQueue’s byte offset +
      //   bytesToCopy.
      head_of_queue->byte_offset =
          base::CheckAdd(head_of_queue->byte_offset, bytes_to_copy)
              .ValueOrDie();
      //   ii. Set headOfQueue’s byte length to headOfQueue’s byte
      //   length − bytesToCopy.
      head_of_queue->byte_length =
          base::CheckSub(head_of_queue->byte_length, bytes_to_copy)
              .ValueOrDie();
    }
    // g. Set controller.[[queueTotalSize]] to controller.[[queueTotalSize]] −
    // bytesToCopy.
    controller->queue_total_size_ =
        base::CheckSub(controller->queue_total_size_, bytes_to_copy)
            .ValueOrDie();
    // h. Perform !
    // ReadableByteStreamControllerFillHeadPullIntoDescriptor(controller,
    // bytesToCopy, pullIntoDescriptor).
    FillHeadPullIntoDescriptor(controller, bytes_to_copy, pull_into_descriptor);
    // i. Set totalBytesToCopyRemaining to totalBytesToCopyRemaining −
    // bytesToCopy.
    // This subtraction will not underflow because bytes_to_copy will always be
    // greater than or equal to total_bytes_to_copy_remaining.
    total_bytes_to_copy_remaining -= bytes_to_copy;
  }
  // 11. If ready is false,
  if (!ready) {
    // a. Assert: controller.[[queueTotalSize]] is 0.
    DCHECK_EQ(controller->queue_total_size_, 0u);
    // b. Assert: pullIntoDescriptor’s bytes filled > 0.
    DCHECK_GT(pull_into_descriptor->bytes_filled, 0.0);
    // c. Assert: pullIntoDescriptor’s bytes filled < pullIntoDescriptor’s
    // element size.
    DCHECK_LT(pull_into_descriptor->bytes_filled,
              pull_into_descriptor->element_size);
  }
  // 12. Return ready.
  return ready;
}

void ReadableByteStreamController::FillReadRequestFromQueue(
    ScriptState* script_state,
    ReadableByteStreamController* controller,
    ReadRequest* read_request,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablebytestreamcontrollerfillreadrequestfromqueue
  // 1. Assert: controller.[[queueTotalSize]] > 0.
  DCHECK_GT(controller->queue_total_size_, 0);
  // 2. Let entry be controller.[[queue]][0].
  QueueEntry* entry = controller->queue_[0];
  // 3. Remove entry from controller.[[queue]].
  controller->queue_.pop_front();
  // 4. Set controller.[[queueTotalSize]] to controller.[[queueTotalSize]] −
  // entry’s byte length.
  controller->queue_total_size_ -= entry->byte_length;
  // 5. Perform ! ReadableByteStreamControllerHandleQueueDrain(controller).
  HandleQueueDrain(script_state, controller);
  // 6. Let view be ! Construct(%Uint8Array%, « entry’s buffer, entry’s byte
  // offset, entry’s byte length »).
  DOMUint8Array* view = DOMUint8Array::Create(entry->buffer, entry->byte_offset,
                                              entry->byte_length);
  // 7. Perform readRequest’s chunk steps, given view.
  read_request->ChunkSteps(script_state,
                           ToV8Traits<DOMUint8Array>::ToV8(script_state, view),
                           exception_state);
}

void ReadableByteStreamController::PullInto(
    ScriptState* script_state,
    ReadableByteStreamController* controller,
    NotShared<DOMArrayBufferView> view,
    ReadIntoRequest* read_into_request,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-pull-into
  // 1. Let stream be controller.[[stream]].
  ReadableStream* const stream = controller->controlled_readable_stream_;
  // 2. Let elementSize be 1.
  size_t element_size = 1;
  // 3. Let ctor be %DataView%.
  auto* ctor = &CreateAsArrayBufferView<DOMDataView>;
  // 4. If view has a [[TypedArrayName]] internal slot (i.e., it is not a
  // DataView),
  if (view->GetType() != DOMArrayBufferView::kTypeDataView) {
    //   a. Set elementSize to be the element size specified in the typed array
    //   constructors table for view.[[TypedArrayName]].
    element_size = view->TypeSize();
    //   b. Set ctor to the constructor specified in the typed array
    //   constructors table for view.[[TypedArrayName]].
    switch (view->GetType()) {
      case DOMArrayBufferView::kTypeInt8:
        ctor = &CreateAsArrayBufferView<DOMInt8Array>;
        break;
      case DOMArrayBufferView::kTypeUint8:
        ctor = &CreateAsArrayBufferView<DOMUint8Array>;
        break;
      case DOMArrayBufferView::kTypeUint8Clamped:
        ctor = &CreateAsArrayBufferView<DOMUint8ClampedArray>;
        break;
      case DOMArrayBufferView::kTypeInt16:
        ctor = &CreateAsArrayBufferView<DOMInt16Array>;
        break;
      case DOMArrayBufferView::kTypeUint16:
        ctor = &CreateAsArrayBufferView<DOMUint16Array>;
        break;
      case DOMArrayBufferView::kTypeInt32:
        ctor = &CreateAsArrayBufferView<DOMInt32Array>;
        break;
      case DOMArrayBufferView::kTypeUint32:
        ctor = &CreateAsArrayBufferView<DOMUint32Array>;
        break;
      case DOMArrayBufferView::kTypeFloat16:
        ctor = &CreateAsArrayBufferView<DOMFloat16Array>;
        break;
      case DOMArrayBufferView::kTypeFloat32:
        ctor = &CreateAsArrayBufferView<DOMFloat32Array>;
        break;
      case DOMArrayBufferView::kTypeFloat64:
        ctor = &CreateAsArrayBufferView<DOMFloat64Array>;
        break;
      case DOMArrayBufferView::kTypeBigInt64:
        ctor = &CreateAsArrayBufferView<DOMBigInt64Array>;
        break;
      case DOMArrayBufferView::kTypeBigUint64:
        ctor = &CreateAsArrayBufferView<DOMBigUint64Array>;
        break;
      case DOMArrayBufferView::kTypeDataView:
        NOTREACHED();
    }
  }
  // 5. Let byteOffset be view.[[ByteOffset]].
  const size_t byte_offset = view->byteOffset();
  // 6. Let byteLength be view.[[ByteLength]].
  const size_t byte_length = view->byteLength();
  // 7. Let bufferResult be TransferArrayBuffer(view.[[ViewedArrayBuffer]]).
  DOMArrayBuffer* buffer = nullptr;
  {
    v8::TryCatch try_catch(script_state->GetIsolate());
    buffer =
        TransferArrayBuffer(script_state, view->buffer(),
                            PassThroughException(script_state->GetIsolate()));
    // 8. If bufferResult is an abrupt completion,
    if (try_catch.HasCaught()) {
      //  a. Perform readIntoRequest's error steps, given
      //     bufferResult.[[Value]].
      read_into_request->ErrorSteps(script_state, try_catch.Exception());
      //  b. Return.
      return;
    }
  }
  // 9. Let buffer be bufferResult.[[Value]].

  // 10. Let pullIntoDescriptor be a new pull-into descriptor with buffer
  // buffer, buffer byte length buffer.[[ArrayBufferByteLength]], byte offset
  // byteOffset, byte length byteLength, bytes filled 0, element size
  // elementSize, view constructor ctor, and reader type "byob".
  PullIntoDescriptor* pull_into_descriptor =
      MakeGarbageCollected<PullIntoDescriptor>(
          buffer, buffer->ByteLength(), byte_offset, byte_length, 0,
          element_size, ctor, ReaderType::kBYOB);
  // 11. If controller.[[pendingPullIntos]] is not empty,
  if (!controller->pending_pull_intos_.empty()) {
    //   a. Append pullIntoDescriptor to controller.[[pendingPullIntos]].
    controller->pending_pull_intos_.push_back(pull_into_descriptor);
    //   b. Perform ! ReadableStreamAddReadIntoRequest(stream, readIntoRequest).
    ReadableStream::AddReadIntoRequest(script_state, stream, read_into_request);
    //   c. Return.
    return;
  }
  // 12. If stream.[[state]] is "closed",
  if (stream->state_ == ReadableStream::kClosed) {
    //   a. Let emptyView be ! Construct(ctor, « pullIntoDescriptor’s buffer,
    //   pullIntoDescriptor’s byte offset, 0 »).
    DOMArrayBufferView* emptyView = ctor(pull_into_descriptor->buffer,
                                         pull_into_descriptor->byte_offset, 0);
    //   b. Perform readIntoRequest’s close steps, given emptyView.
    read_into_request->CloseSteps(script_state, emptyView);
    //   c. Return.
    return;
  }
  // 13. If controller.[[queueTotalSize]] > 0,
  if (controller->queue_total_size_ > 0) {
    //   a. If !
    //   ReadableByteStreamControllerFillPullIntoDescriptorFromQueue(controller,
    //   pullIntoDescriptor) is true,
    v8::TryCatch try_catch(script_state->GetIsolate());
    if (FillPullIntoDescriptorFromQueue(
            controller, pull_into_descriptor,
            PassThroughException(script_state->GetIsolate()))) {
      //     i. Let filledView be !
      //     ReadableByteStreamControllerConvertPullIntoDescriptor(pullIntoDescriptor).
      DOMArrayBufferView* filled_view = ConvertPullIntoDescriptor(
          script_state, pull_into_descriptor,
          PassThroughException(script_state->GetIsolate()));
      DCHECK(!try_catch.HasCaught());
      //     ii. Perform !
      //     ReadableByteStreamControllerHandleQueueDrain(controller).
      HandleQueueDrain(script_state, controller);
      //     iii. Perform readIntoRequest’s chunk steps, given filledView.
      read_into_request->ChunkSteps(script_state, filled_view, exception_state);
      //     iv. Return.
      return;
    }
    if (try_catch.HasCaught()) {
      // Instead of returning a rejection, which is inconvenient here,
      // call ControllerError(). The only difference this makes is that it
      // happens synchronously, but that should not be observable.
      ReadableByteStreamController::Error(script_state, controller,
                                          try_catch.Exception());
      return;
    }
    //   b. If controller.[[closeRequested]] is true,
    if (controller->close_requested_) {
      //     i. Let e be a TypeError exception.
      v8::Local<v8::Value> e = V8ThrowException::CreateTypeError(
          script_state->GetIsolate(), "close requested");
      //     ii. Perform ! ReadableByteStreamControllerError(controller, e).
      controller->Error(script_state, controller, e);
      //     iii. Perform readIntoRequest’s error steps, given e.
      read_into_request->ErrorSteps(script_state, e);
      //     iv. Return.
      return;
    }
  }
  // 14. Append pullIntoDescriptor to controller.[[pendingPullIntos]].
  controller->pending_pull_intos_.push_back(pull_into_descriptor);
  // 15. Perform ! ReadableStreamAddReadIntoRequest(stream, readIntoRequest).
  ReadableStream::AddReadIntoRequest(script_state, stream, read_into_request);
  // 16. Perform ! ReadableByteStreamControllerCallPullIfNeeded(controller).
  CallPullIfNeeded(script_state, controller);
}

void ReadableByteStreamController::HandleQueueDrain(
    ScriptState* script_state,
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-handle-queue-drain
  // 1. Assert: controller.[[stream]].[[state]] is "readable".
  DCHECK_EQ(controller->controlled_readable_stream_->state_,
            ReadableStream::kReadable);
  // 2. If controller.[[queueTotalSize]] is 0 and controller.[[closeRequested]]
  // is true,
  if (!controller->queue_total_size_ && controller->close_requested_) {
    //   a. Perform ! ReadableByteStreamControllerClearAlgorithms(controller).
    ClearAlgorithms(controller);
    //   b. Perform ! ReadableStreamClose(controller.[[stream]]).
    ReadableStream::Close(script_state,
                          controller->controlled_readable_stream_);
  } else {
    // 3. Otherwise,
    //   a. Perform ! ReadableByteStreamControllerCallPullIfNeeded(controller).
    CallPullIfNeeded(script_state, controller);
  }
}

void ReadableByteStreamController::ResetQueue(
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#reset-queue
  // 1. Assert: container has [[queue]] and [[queueTotalSize]] internal slots.
  // 2. Set container.[[queue]] to a new empty list.
  controller->queue_.clear();
  // 3. Set container.[[queueTotalSize]] to 0.
  controller->queue_total_size_ = 0;
}

void ReadableByteStreamController::Respond(
    ScriptState* script_state,
    ReadableByteStreamController* controller,
    size_t bytes_written,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-respond
  // 1. Assert: controller.[[pendingPullIntos]] is not empty.
  DCHECK(!controller->pending_pull_intos_.empty());
  // 2. Let firstDescriptor be controller.[[pendingPullIntos]][0].
  PullIntoDescriptor* first_descriptor = controller->pending_pull_intos_[0];
  // 3. Let state be controller.[[stream]].[[state]].
  const ReadableStream::State state =
      controller->controlled_readable_stream_->state_;
  // 4. If state is "closed",
  if (state == ReadableStream::kClosed) {
    //   a. If bytesWritten is not 0, throw a TypeError exception.
    if (bytes_written != 0) {
      exception_state.ThrowTypeError("bytes written is not 0");
      return;
    }
    // 5. Otherwise,
  } else {
    //   a. Assert: state is "readable".
    DCHECK_EQ(state, ReadableStream::kReadable);
    //   b. If bytesWritten is 0, throw a TypeError exception.
    if (bytes_written == 0) {
      exception_state.ThrowTypeError("bytes written is 0");
      return;
    }
    //   c. If firstDescriptor's bytes filled + bytesWritten > firstDescriptor's
    //   byte length, throw a RangeError exception.
    if (base::ClampAdd(first_descriptor->bytes_filled, bytes_written) >
        first_descriptor->byte_length) {
      exception_state.ThrowRangeError(
          "available read buffer is too small for specified number of bytes");
      return;
    }
  }
  // 6. Set firstDescriptor's buffer to ! TransferArrayBuffer(firstDescriptor's
  // buffer).
  first_descriptor->buffer = TransferArrayBuffer(
      script_state, first_descriptor->buffer, exception_state);
  // 7. Perform ? ReadableByteStreamControllerRespondInternal(controller,
  // bytesWritten).
  RespondInternal(script_state, controller, bytes_written, exception_state);
}

void ReadableByteStreamController::RespondInClosedState(
    ScriptState* script_state,
    ReadableByteStreamController* controller,
    PullIntoDescriptor* first_descriptor,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-respond-in-closed-state
  // 1. Assert: firstDescriptor’s bytes filled is 0.
  DCHECK_EQ(first_descriptor->bytes_filled, 0u);
  // 2. If firstDescriptor’s reader type is "none", perform !
  // ReadableByteStreamControllerShiftPendingPullInto(controller).
  if (first_descriptor->reader_type == ReaderType::kNone) {
    ShiftPendingPullInto(controller);
  }
  // 3. Let stream be controller.[[stream]].
  ReadableStream* const stream = controller->controlled_readable_stream_;
  // 4. If ! ReadableStreamHasBYOBReader(stream) is true,
  if (ReadableStream::HasBYOBReader(stream)) {
    //   a. While ! ReadableStreamGetNumReadIntoRequests(stream) > 0,
    while (ReadableStream::GetNumReadIntoRequests(stream) > 0) {
      //     i. Let pullIntoDescriptor be !
      //     ReadableByteStreamControllerShiftPendingPullInto(controller).
      PullIntoDescriptor* pull_into_descriptor =
          ShiftPendingPullInto(controller);
      //     ii. Perform !
      //     ReadableByteStreamControllerCommitPullIntoDescriptor(stream,
      //     pullIntoDescriptor).
      CommitPullIntoDescriptor(script_state, stream, pull_into_descriptor,
                               exception_state);
      DCHECK(!exception_state.HadException());
    }
  }
}

void ReadableByteStreamController::RespondInReadableState(
    ScriptState* script_state,
    ReadableByteStreamController* controller,
    size_t bytes_written,
    PullIntoDescriptor* pull_into_descriptor,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-respond-in-readable-state
  // 1. Assert: pullIntoDescriptor's bytes filled + bytesWritten ≤
  // pullIntoDescriptor's byte length.
  DCHECK_LE(pull_into_descriptor->bytes_filled + bytes_written,
            pull_into_descriptor->byte_length);
  // 2. Perform !
  // ReadableByteStreamControllerFillHeadPullIntoDescriptor(controller,
  // bytesWritten, pullIntoDescriptor).
  FillHeadPullIntoDescriptor(controller, bytes_written, pull_into_descriptor);
  // 3. If pullIntoDescriptor’s reader type is "none",
  if (pull_into_descriptor->reader_type == ReaderType::kNone) {
    //   a. Perform ?
    //   ReadableByteStreamControllerEnqueueDetachedPullIntoToQueue(controller,
    //   pullIntoDescriptor).
    EnqueueDetachedPullIntoToQueue(controller, pull_into_descriptor);
    //   b. Perform !
    //   ReadableByteStreamControllerProcessPullIntoDescriptorsUsingQueue(controller).
    ProcessPullIntoDescriptorsUsingQueue(script_state, controller);
    //   c. Return.
    return;
  }
  // 4. If pullIntoDescriptor’s bytes filled < pullIntoDescriptor’s element
  // size, return.
  if (pull_into_descriptor->bytes_filled < pull_into_descriptor->element_size) {
    return;
  }
  // 5. Perform ! ReadableByteStreamControllerShiftPendingPullInto(controller).
  ShiftPendingPullInto(controller);
  // 6. Let remainderSize be pullIntoDescriptor’s bytes filled mod
  // pullIntoDescriptor’s element size.
  const size_t remainder_size =
      pull_into_descriptor->bytes_filled % pull_into_descriptor->element_size;
  // 7. If remainderSize > 0,
  if (remainder_size > 0) {
    //   a. Let end be pullIntoDescriptor’s byte offset + pullIntoDescriptor’s
    //   bytes filled.
    //   This addition will not overflow because byte offset and bytes filled
    //   refer to actually allocated memory, so together they cannot exceed
    //   size_t.
    size_t end =
        pull_into_descriptor->byte_offset + pull_into_descriptor->bytes_filled;
    //   b. Perform ?
    //   ReadableByteStreamControllerEnqueueClonedChunkToQueue(controller,
    //   pullIntoDescriptor’s buffer, end − remainderSize, remainderSize).
    EnqueueClonedChunkToQueue(controller, pull_into_descriptor->buffer,
                              end - remainder_size, remainder_size);
  }
  // 8. Set pullIntoDescriptor’s bytes filled to pullIntoDescriptor’s bytes
  // filled − remainderSize.
  pull_into_descriptor->bytes_filled =
      pull_into_descriptor->bytes_filled - remainder_size;
  // 9. Perform !
  // ReadableByteStreamControllerCommitPullIntoDescriptor(controller.[[stream]],
  // pullIntoDescriptor).
  CommitPullIntoDescriptor(script_state,
                           controller->controlled_readable_stream_,
                           pull_into_descriptor, exception_state);
  DCHECK(!exception_state.HadException());
  // 10. Perform !
  // ReadableByteStreamControllerProcessPullIntoDescriptorsUsingQueue(controller).
  ProcessPullIntoDescriptorsUsingQueue(script_state, controller);
  DCHECK(!exception_state.HadException());
}

void ReadableByteStreamController::RespondInternal(
    ScriptState* script_state,
    ReadableByteStreamController* controller,
    size_t bytes_written,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-respond-internal
  // 1. Let firstDescriptor be controller.[[pendingPullIntos]][0].
  PullIntoDescriptor* const first_descriptor =
      controller->pending_pull_intos_[0];
  // 2. Assert: ! CanTransferArrayBuffer(firstDescriptor's buffer) is true.
  DCHECK(CanTransferArrayBuffer(first_descriptor->buffer));
  // 3. Perform ! ReadableByteStreamControllerInvalidateBYOBRequest(controller).
  InvalidateBYOBRequest(controller);
  // 4. Let state be controller.[[stream]].[[state]].
  const ReadableStream::State state =
      controller->controlled_readable_stream_->state_;
  // 5. If state is "closed",
  if (state == Readable
```
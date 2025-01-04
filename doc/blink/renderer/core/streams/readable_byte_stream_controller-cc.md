Response:
The user wants to understand the functionality of the `readable_byte_stream_controller.cc` file in the Chromium Blink engine. I need to:

1. **List the functions** provided by this class.
2. **Explain the purpose** of the `ReadableByteStreamController`.
3. **Identify relationships** with JavaScript, HTML, and CSS and provide examples.
4. **Illustrate logical reasoning** with hypothetical inputs and outputs.
5. **Point out common user/programming errors** related to this controller.
6. **Describe user operations** that might lead to the execution of this code for debugging purposes.
7. **Summarize** the file's functionality based on the provided code.
```
功能归纳：
```

`ReadableByteStreamController` 类的主要功能是作为 `ReadableStream` 的控制器，特别用于处理**字节流**。它负责管理字节数据的生产和消费，以及与 JavaScript 端的交互。

具体来说，该类的功能可以归纳为以下几点：

1. **管理内部队列：**  维护一个内部队列 (`queue_`) 来存储接收到的字节块（`DOMArrayBuffer`）。同时跟踪队列的总大小 (`queue_total_size_`)。
2. **处理数据入队：** 提供 `enqueue` 方法，允许生产者向流中添加字节数据。这个方法会检查流的状态，确保在合适的时机添加数据，并处理 `ArrayBuffer` 的转移。
3. **处理数据出队（拉取）：** 协调数据的拉取操作，包括两种模式：
    * **默认读取器 (Default Reader):**  通过 `ProcessReadRequestsUsingQueue` 处理来自默认读取器的读取请求，将队列中的数据填充到读取请求中。
    * **BYOB (Bring Your Own Buffer) 读取器:** 通过 `ProcessPullIntoDescriptorsUsingQueue` 处理 BYOB 读取请求，允许将数据直接写入用户提供的 `ArrayBuffer` 中。
4. **管理流的状态转换：**  提供 `close` 方法来请求关闭流，以及 `error` 方法来向流中报告错误。`Close` 方法会考虑队列中是否还有数据，而 `Error` 方法会清除内部状态。
5. **处理背压 (Backpressure)：** 通过 `desiredSize` 方法计算流的期望大小，用于控制数据生产的速度，避免消费者处理不过来。
6. **管理拉取机制 (Pulling):**  使用 `pullAlgorithm_` (未在提供的代码段中定义，但通过 `CallPullIfNeeded` 调用) 来触发数据生产。维护 `pulling_` 和 `pull_again_` 标志来处理并发的拉取请求。
7. **支持 BYOB 读取:**  管理 `byobRequest_`，当有 BYOB 读取请求时，提供一个指向内部缓冲区的 `ReadableStreamBYOBRequest` 对象。
8. **处理 `PullInto` 请求:** 管理 `pending_pull_intos_` 队列，用于存储 BYOB 读取请求的相关信息，并在数据可用时填充用户提供的缓冲区。
9. **内部操作辅助：** 提供一些内部辅助方法，例如 `EnqueueChunkToQueue`（将数据添加到队列）、`FillReadRequestFromQueue`（从队列填充读取请求）、`FillPullIntoDescriptorFromQueue`（从队列填充 `PullIntoDescriptor`）、`CommitPullIntoDescriptor`（完成 `PullInto` 操作）等。

**与 Javascript, HTML, CSS 的关系及举例说明：**

这个 C++ 文件是 Blink 渲染引擎的一部分，负责实现 Web Streams API 的一部分功能，这个 API 在 JavaScript 中暴露出来。

* **JavaScript:** `ReadableByteStreamController` 紧密关联 JavaScript 的 `ReadableStream` API。JavaScript 代码通过创建 `ReadableStream` 实例，并提供一个底层的 `start`, `pull`, 和 `cancel` 方法来与这个 C++ 控制器交互。

    **举例：**
    ```javascript
    const stream = new ReadableStream({
      start(controller) {
        // controller 是 ReadableByteStreamController 在 JavaScript 端的代理
        // 可以调用 controller.enqueue(), controller.error(), controller.close() 等方法
        controller.enqueue(new Uint8Array([1, 2, 3]));
      },
      pull(controller) {
        // 当需要更多数据时，会调用 pull 方法
        // 在这里可以从数据源获取更多数据并使用 controller.enqueue() 添加到流中
      },
      cancel(reason) {
        // 当流被取消时调用
        console.log('Stream cancelled:', reason);
      }
    });
    ```

* **HTML:**  HTML 本身不直接与 `ReadableByteStreamController` 交互。然而，HTML 中引用的 JavaScript 代码可以使用 Streams API 来处理网络请求、文件读取等操作，这些操作最终会触发 `ReadableByteStreamController` 的功能。

    **举例：**  使用 `fetch` API 获取一个流式响应：
    ```html
    <script>
      fetch('large-file.bin')
        .then(response => response.body) // response.body 是一个 ReadableStream
        .then(reader => {
          const read = () => {
            reader.read().then(({ done, value }) => {
              if (done) {
                console.log('Stream finished');
                return;
              }
              // 处理 value (Uint8Array)
              console.log('Received chunk:', value);
              read();
            });
          };
          read();
        });
    </script>
    ```
    在这个例子中，`response.body` 背后的实现会用到 `ReadableByteStreamController` 来管理从网络接收到的数据。

* **CSS:** CSS 与 `ReadableByteStreamController` 没有直接关系。

**逻辑推理及假设输入与输出：**

**场景：调用 `enqueue` 方法**

* **假设输入：**
    * `ReadableByteStreamController` 实例处于 `readable` 状态。
    * `closeRequested_` 为 `false`。
    * 调用 `enqueue` 方法，传入一个 `Uint8Array` `chunk`，其内容为 `[4, 5, 6]`，`byteLength` 为 3。
* **执行的逻辑：**
    1. `enqueue` 方法会检查 `chunk` 的 `byteLength` 和 `buffer` 的大小，确保不为 0。
    2. 检查 `closeRequested_` 和流的状态。
    3. 调用 `Enqueue` 内部方法。
    4. 在 `Enqueue` 中，获取 `chunk` 的 `buffer`, `byteOffset`, `byteLength`。
    5. 将 `chunk` 的 `ArrayBuffer` 进行转移 (`TransferArrayBuffer`)，创建新的 `DOMArrayBuffer`。
    6. 如果有等待的 `PullInto` 请求，并且是 BYOB 类型的，则进行处理（假设此处没有）。
    7. 如果流有默认读取器，则尝试使用队列处理读取请求。如果没有读取请求，则将 `chunk` 添加到队列中。
    8. 如果流有 BYOB 读取器，则将 `chunk` 添加到队列中，并尝试处理 `PullInto` 请求。
    9. 如果流没有锁定，则将 `chunk` 添加到队列中。
    10. 调用 `CallPullIfNeeded` 来决定是否需要从底层拉取更多数据。
* **假设输出（如果流没有锁定，也没有读取器）：**
    * `queue_` 中会添加一个新的 `QueueEntry`，其 `buffer` 指向转移后的 `ArrayBuffer`，`byte_offset` 为 0，`byte_length` 为 3。
    * `queue_total_size_` 的值会增加 3。
    * 根据 `strategy_high_water_mark_` 和 `queue_total_size_` 的比较结果，可能会触发 `pullAlgorithm_` 的调用。

**用户或编程常见的使用错误：**

1. **在流关闭后尝试入队 (`enqueue`)：**  如果 JavaScript 代码在流已经关闭（或正在关闭）后尝试调用 `controller.enqueue()`，C++ 代码会抛出 `TypeError` 异常。
    ```javascript
    const controller = ...;
    const stream = controller.controlledReadableStream;
    stream.close();
    controller.enqueue(new Uint8Array([7, 8, 9])); // 抛出 TypeError
    ```

2. **在流关闭请求后尝试入队 (`enqueue`)：** 类似于上一个错误，如果已经请求关闭流，则不能再入队。
    ```javascript
    const controller = ...;
    controller.close();
    controller.enqueue(new Uint8Array([7, 8, 9])); // 抛出 TypeError
    ```

3. **尝试关闭已经关闭的流 (`close`)：**  在流已经处于 "closed" 或 "errored" 状态时调用 `controller.close()` 会抛出 `TypeError`。

4. **入队空数据块 (`enqueue` 0 长度的 `ArrayBufferView`)：**  尝试使用 `controller.enqueue(new Uint8Array(0))` 会抛出 `TypeError`。

5. **在 BYOB 读取期间错误地操作缓冲区：**  当使用 BYOB 读取器时，用户需要小心操作提供的缓冲区。如果在读取操作完成之前就修改或分离缓冲区，可能会导致不可预测的行为或错误。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户与网页交互：** 用户在浏览器中与网页进行交互，例如点击按钮、滚动页面等。
2. **JavaScript 代码执行：**  用户的操作触发了网页上的 JavaScript 代码执行。
3. **创建并操作 `ReadableStream`：** JavaScript 代码创建了一个 `ReadableStream` 实例，可能用于处理网络请求、文件读取或自定义的数据源。
4. **`ReadableByteStreamController` 的创建和关联：** 当 `ReadableStream` 被创建时，Blink 引擎会创建一个关联的 `ReadableByteStreamController` 实例（如果流是字节流）。
5. **调用控制器的方法：**
    * **`enqueue`:**  如果 JavaScript 代码需要向流中添加数据，它会调用 `controller.enqueue()` 方法。这会触发 `ReadableByteStreamController::enqueue` 方法的执行.
    * **`close`:** 如果 JavaScript 代码需要关闭流，它会调用 `controller.close()` 方法，对应 `ReadableByteStreamController::close`.
    * **`error`:** 如果 JavaScript 代码检测到错误，会调用 `controller.error()`, 对应 `ReadableByteStreamController::error`.
    * **读取操作 (`read` 或 `readInto`):**  当 JavaScript 代码从流中读取数据时（通过 `getReader().read()` 或 BYOB 读取），会触发 `ReadableByteStreamController` 的相关逻辑，例如 `ProcessReadRequestsUsingQueue` 或 `ProcessPullIntoDescriptorsUsingQueue`。
    * **`pull` 方法的调用：**  当流需要更多数据时，Blink 引擎会调用用户在 `ReadableStream` 的构造函数中提供的 `pull` 方法。这个方法的执行可能会导致 JavaScript 代码调用 `controller.enqueue()`。

**调试线索示例：**

如果你在调试一个使用 `ReadableStream` 处理网络响应的程序，并且发现数据接收不完整或出现错误，你可以：

1. **在 JavaScript 代码中设置断点：** 在 `ReadableStream` 的 `start`, `pull` 或读取数据的回调函数中设置断点，查看流的状态和接收到的数据。
2. **在 C++ 代码中设置断点：** 在 `blink/renderer/core/streams/readable_byte_stream_controller.cc` 文件中的 `enqueue`, `Enqueue`, `Close`, `Error`, `ProcessReadRequestsUsingQueue`, `ProcessPullIntoDescriptorsUsingQueue` 等方法中设置断点，跟踪数据的流向和控制器的状态变化。
3. **查看调用堆栈：** 当断点命中时，查看调用堆栈，了解 JavaScript 代码是如何一步步调用到 C++ 代码的。
4. **检查变量值：** 检查 `controller->queue_`, `controller->queue_total_size_`, `controller->close_requested_`, `controlled_readable_stream_->state_` 等变量的值，以了解流的当前状态。

这是 `ReadableByteStreamController` 的第一部分功能归纳，后续部分可能会涉及更多细节，例如与错误处理、取消操作以及更复杂的背压控制相关的逻辑。

Prompt: 
```
这是目录为blink/renderer/core/streams/readable_byte_stream_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/streams/readable_byte_stream_controller.h"

#include "base/numerics/checked_math.h"
#include "base/numerics/clamped_math.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_underlying_source.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_underlying_source_cancel_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_underlying_source_pull_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_underlying_source_start_callback.h"
#include "third_party/blink/renderer/core/streams/miscellaneous_operations.h"
#include "third_party/blink/renderer/core/streams/promise_handler.h"
#include "third_party/blink/renderer/core/streams/read_into_request.h"
#include "third_party/blink/renderer/core/streams/read_request.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_request.h"
#include "third_party/blink/renderer/core/streams/stream_algorithms.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_data_view.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

template <typename DOMType>
DOMArrayBufferView* CreateAsArrayBufferView(DOMArrayBuffer* buffer,
                                            size_t byte_offset,
                                            size_t length) {
  return DOMType::Create(buffer, byte_offset, length);
}

}  // namespace

ReadableByteStreamController::QueueEntry::QueueEntry(DOMArrayBuffer* buffer,
                                                     size_t byte_offset,
                                                     size_t byte_length)
    : buffer(buffer), byte_offset(byte_offset), byte_length(byte_length) {}

void ReadableByteStreamController::QueueEntry::Trace(Visitor* visitor) const {
  visitor->Trace(buffer);
}

ReadableByteStreamController::PullIntoDescriptor::PullIntoDescriptor(
    DOMArrayBuffer* buffer,
    size_t buffer_byte_length,
    size_t byte_offset,
    size_t byte_length,
    size_t bytes_filled,
    size_t element_size,
    ViewConstructorType view_constructor,
    ReaderType reader_type)
    : buffer(buffer),
      buffer_byte_length(buffer_byte_length),
      byte_offset(byte_offset),
      byte_length(byte_length),
      bytes_filled(bytes_filled),
      element_size(element_size),
      view_constructor(view_constructor),
      reader_type(reader_type) {}

void ReadableByteStreamController::PullIntoDescriptor::Trace(
    Visitor* visitor) const {
  visitor->Trace(buffer);
}

// This constructor is used internally; it is not reachable from Javascript.
ReadableByteStreamController::ReadableByteStreamController()
    : queue_total_size_(queue_.size()) {}

ReadableStreamBYOBRequest* ReadableByteStreamController::byobRequest() {
  // https://streams.spec.whatwg.org/#rbs-controller-byob-request
  // 1. Return ReadableByteStreamControllerGetBYOBRequest(this).
  return GetBYOBRequest(this);
}

ReadableStreamBYOBRequest* ReadableByteStreamController::GetBYOBRequest(
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablebytestreamcontrollergetbyobrequest
  // 1. If controller.[[byobRequest]] is null and
  // controller.[[pendingPullIntos]] is not empty,
  if (!controller->byob_request_ && !controller->pending_pull_intos_.empty()) {
    //   a. Let firstDescriptor be controller.[[pendingPullIntos]][0].
    const PullIntoDescriptor* first_descriptor =
        controller->pending_pull_intos_[0];

    //   b. Let view be ! Construct(%Uint8Array%, « firstDescriptor’s buffer,
    //   firstDescriptor’s byte offset + firstDescriptor’s bytes filled,
    //   firstDescriptor’s byte length − firstDescriptor’s bytes filled »).
    DOMUint8Array* const view = DOMUint8Array::Create(
        first_descriptor->buffer,
        first_descriptor->byte_offset + first_descriptor->bytes_filled,
        first_descriptor->byte_length - first_descriptor->bytes_filled);

    //   c. Let byobRequest be a new ReadableStreamBYOBRequest.
    //   d. Set byobRequest.[[controller]] to controller.
    //   e. Set byobRequest.[[view]] to view.
    //   f. Set controller.[[byobRequest]] to byobRequest.
    controller->byob_request_ = MakeGarbageCollected<ReadableStreamBYOBRequest>(
        controller, NotShared<DOMUint8Array>(view));
  }

  // 2. Return controller.[[byobRequest]].
  return controller->byob_request_.Get();
}

std::optional<double> ReadableByteStreamController::desiredSize() {
  // https://streams.spec.whatwg.org/#rbs-controller-desired-size
  // 1. Return ! ReadableByteStreamControllerGetDesiredSize(this).
  return GetDesiredSize(this);
}

std::optional<double> ReadableByteStreamController::GetDesiredSize(
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-get-desired-size
  // 1. Let state be controller.[[stream]].[[state]].
  switch (controller->controlled_readable_stream_->state_) {
      // 2. If state is "errored", return null.
    case ReadableStream::kErrored:
      return std::nullopt;

      // 3. If state is "closed", return 0.
    case ReadableStream::kClosed:
      return 0.0;

    case ReadableStream::kReadable:
      // 4. Return controller.[[strategyHWM]]] - controller.[[queueTotalSize]].
      return controller->strategy_high_water_mark_ -
             controller->queue_total_size_;
  }
}

void ReadableByteStreamController::close(ScriptState* script_state,
                                         ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rbs-controller-close
  // 1. If this.[[closeRequested]] is true, throw a TypeError exception.
  if (close_requested_) {
    exception_state.ThrowTypeError(
        "Cannot close a readable stream that has already been requested "
        "to be closed");
    return;
  }

  // 2. If this.[[stream]].[[state]] is not "readable", throw a TypeError
  // exception.
  if (controlled_readable_stream_->state_ != ReadableStream::kReadable) {
    exception_state.ThrowTypeError(
        "Cannot close a readable stream that is not readable");
    return;
  }

  // 3. Perform ? ReadableByteStreamControllerClose(this).
  Close(script_state, this);
}

void ReadableByteStreamController::enqueue(ScriptState* script_state,
                                           NotShared<DOMArrayBufferView> chunk,
                                           ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#rbs-controller-enqueue
  // 1. If chunk.[[ByteLength]] is 0, throw a TypeError exception.
  if (chunk->byteLength() == 0) {
    exception_state.ThrowTypeError("chunk is empty");
    return;
  }

  // 2. If chunk.[[ViewedArrayBuffer]].[[ArrayBufferByteLength]] is 0, throw a
  // TypeError exception.
  if (chunk->buffer()->ByteLength() == 0) {
    exception_state.ThrowTypeError("chunk's buffer is empty");
    return;
  }

  // 3. If this.[[closeRequested]] is true, throw a TypeError exception.
  if (close_requested_) {
    exception_state.ThrowTypeError("close requested already");
    return;
  }

  // 4. If this.[[stream]].[[state]] is not "readable", throw a TypeError
  // exception.
  if (controlled_readable_stream_->state_ != ReadableStream::kReadable) {
    exception_state.ThrowTypeError("stream is not readable");
    return;
  }

  // 5. Return ! ReadableByteStreamControllerEnqueue(this, chunk).
  Enqueue(script_state, this, chunk, exception_state);
}

void ReadableByteStreamController::error(ScriptState* script_state) {
  error(script_state, ScriptValue(script_state->GetIsolate(),
                                  v8::Undefined(script_state->GetIsolate())));
}

void ReadableByteStreamController::error(ScriptState* script_state,
                                         const ScriptValue& e) {
  // https://streams.spec.whatwg.org/#rbs-controller-error
  // 1. Perform ! ReadableByteStreamControllerError(this, e).
  Error(script_state, this, e.V8Value());
}

void ReadableByteStreamController::Close(
    ScriptState* script_state,
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-close
  // 1. Let stream be controller.[[stream]].
  ReadableStream* const stream = controller->controlled_readable_stream_;

  // 2. If controller.[[closeRequested]] is true or stream.[[state]] is not
  // "readable", return.
  if (controller->close_requested_ ||
      stream->state_ != ReadableStream::kReadable) {
    return;
  }

  // 3. If controller.[[queueTotalSize]] > 0,
  if (controller->queue_total_size_ > 0) {
    //   a. Set controller.[[closeRequested]] to true.
    controller->close_requested_ = true;
    //   b. Return.
    return;
  }

  // 4. If controller.[[pendingPullIntos]] is not empty,
  if (!controller->pending_pull_intos_.empty()) {
    //   a. Let firstPendingPullInto be controller.[[pendingPullIntos]][0].
    const PullIntoDescriptor* first_pending_pull_into =
        controller->pending_pull_intos_[0];
    //   b. If firstPendingPullInto’s bytes filled > 0,
    if (first_pending_pull_into->bytes_filled > 0) {
      //     i. Let e be a new TypeError exception.
      v8::Local<v8::Value> e = V8ThrowException::CreateTypeError(
          script_state->GetIsolate(), "Cannot close while responding");
      //     ii. Perform ! ReadableByteStreamControllerError(controller, e).
      Error(script_state, controller, e);
      //     iii. Throw e.
      V8ThrowException::ThrowException(script_state->GetIsolate(), e);
      return;
    }
  }

  // 5. Perform ! ReadableByteStreamControllerClearAlgorithms(controller).
  ClearAlgorithms(controller);

  // 6. Perform ! ReadableStreamClose(stream).
  ReadableStream::Close(script_state, stream);
}

void ReadableByteStreamController::Error(
    ScriptState* script_state,
    ReadableByteStreamController* controller,
    v8::Local<v8::Value> e) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-error
  // 1. Let stream by controller.[[stream]].
  ReadableStream* const stream = controller->controlled_readable_stream_;

  // 2. If stream.[[state]] is not "readable", return.
  if (stream->state_ != ReadableStream::kReadable) {
    return;
  }

  // 3. Perform ! ReadableByteStreamControllerClearPendingPullIntos(controller).
  ClearPendingPullIntos(controller);

  // 4. Perform ! ResetQueue(controller).
  ResetQueue(controller);

  // 5. Perform ! ReadableByteStreamControllerClearAlgorithms(controller).
  ClearAlgorithms(controller);

  // 6. Perform ! ReadableStreamError(stream, e).
  ReadableStream::Error(script_state, stream, e);
}

void ReadableByteStreamController::Enqueue(
    ScriptState* script_state,
    ReadableByteStreamController* controller,
    NotShared<DOMArrayBufferView> chunk,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-enqueue
  // 1. Let stream be controller.[[stream]].
  ReadableStream* const stream = controller->controlled_readable_stream_;

  // 2. If controller.[[closeRequested]] is true or stream.[[state]] is not
  // "readable", return.
  if (controller->close_requested_ ||
      stream->state_ != ReadableStream::kReadable) {
    return;
  }

  // 3. Let buffer be chunk.[[ViewedArrayBuffer]].
  DOMArrayBuffer* const buffer = chunk->buffer();

  // 4. Let byteOffset be chunk.[[ByteOffset]].
  const size_t byte_offset = chunk->byteOffset();

  // 5. Let byteLength be chunk.[[ByteLength]].
  const size_t byte_length = chunk->byteLength();

  // 6. If ! IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  if (buffer->IsDetached()) {
    exception_state.ThrowTypeError("buffer is detached");
    return;
  }

  // 7. Let transferredBuffer be ? TransferArrayBuffer(buffer).
  DOMArrayBuffer* const transferred_buffer =
      TransferArrayBuffer(script_state, buffer, exception_state);
  if (!transferred_buffer) {
    return;
  }

  // 8. If controller.[[pendingPullIntos]] is not empty,
  if (!controller->pending_pull_intos_.empty()) {
    //     a. Let firstPendingPullInto be controller.[[pendingPullIntos]][0].
    PullIntoDescriptor* first_pending_pull_into =
        controller->pending_pull_intos_[0];
    //     b. If ! IsDetachedBuffer(firstPendingPullInto's buffer) is true,
    //     throw a TypeError exception.
    if (first_pending_pull_into->buffer->IsDetached()) {
      exception_state.ThrowTypeError("first pending read's buffer is detached");
      return;
    }
    //     c. Perform !
    //     ReadableByteStreamControllerInvalidateBYOBRequest(controller).
    InvalidateBYOBRequest(controller);
    //     d. Set firstPendingPullInto's buffer to ! TransferArrayBuffer(
    //     firstPendingPullInto's buffer).
    first_pending_pull_into->buffer = TransferArrayBuffer(
        script_state, first_pending_pull_into->buffer, exception_state);
    //     e. If firstPendingPullInto’s reader type is "none", perform ?
    //     ReadableByteStreamControllerEnqueueDetachedPullIntoToQueue(controller,
    //     firstPendingPullInto).
    if (first_pending_pull_into->reader_type == ReaderType::kNone) {
      EnqueueDetachedPullIntoToQueue(controller, first_pending_pull_into);
    }
  }

  // 9. If ! ReadableStreamHasDefaultReader(stream) is true
  if (ReadableStream::HasDefaultReader(stream)) {
    //   a. Perform !
    //   ReadableByteStreamControllerProcessReadRequestsUsingQueue(controller).
    ProcessReadRequestsUsingQueue(script_state, controller, exception_state);
    //   b. If ! ReadableStreamGetNumReadRequests(stream) is 0,
    if (ReadableStream::GetNumReadRequests(stream) == 0) {
      //     i. Assert: controller.[[pendingPullIntos]] is empty.
      DCHECK(controller->pending_pull_intos_.empty());

      //     ii. Perform !
      //     ReadableByteStreamControllerEnqueueChunkToQueue(controller,
      //     transferredBuffer, byteOffset, byteLength).
      EnqueueChunkToQueue(controller, transferred_buffer, byte_offset,
                          byte_length);
    } else {
      // c. Otherwise,
      //     i. Assert: controller.[[queue]] is empty.
      DCHECK(controller->queue_.empty());

      //     ii. If controller.[[pendingPullIntos]] is not empty,
      if (!controller->pending_pull_intos_.empty()) {
        //        1. Assert: controller.[[pendingPullIntos]][0]'s reader type is
        //        "default".
        DCHECK_EQ(controller->pending_pull_intos_[0]->reader_type,
                  ReaderType::kDefault);

        //        2. Perform !
        //        ReadableByteStreamControllerShiftPendingPullInto(controller).
        ShiftPendingPullInto(controller);
      }

      //     iii. Let transferredView be ! Construct(%Uint8Array%, «
      //     transferredBuffer, byteOffset, byteLength »).
      v8::Local<v8::Value> const transferred_view = v8::Uint8Array::New(
          ToV8Traits<DOMArrayBuffer>::ToV8(script_state, transferred_buffer)
              .As<v8::ArrayBuffer>(),
          byte_offset, byte_length);
      //     iv. Perform ! ReadableStreamFulfillReadRequest(stream,
      //     transferredView, false).
      ReadableStream::FulfillReadRequest(script_state, stream, transferred_view,
                                         false, exception_state);
    }
  }

  // 10. Otherwise, if ! ReadableStreamHasBYOBReader(stream) is true,
  else if (ReadableStream::HasBYOBReader(stream)) {
    //   a. Perform !
    //   ReadableByteStreamControllerEnqueueChunkToQueue(controller,
    //   transferredBuffer, byteOffset, byteLength).
    EnqueueChunkToQueue(controller, transferred_buffer, byte_offset,
                        byte_length);
    //   b. Perform !
    //   ReadableByteStreamControllerProcessPullIntoDescriptorsUsing
    //   Queue(controller).
    ProcessPullIntoDescriptorsUsingQueue(script_state, controller);
    DCHECK(!exception_state.HadException());
  } else {
    // 11. Otherwise,
    //   a. Assert: ! IsReadableStreamLocked(stream) is false.
    DCHECK(!ReadableStream::IsLocked(stream));
    //   b. Perform !
    //   ReadableByteStreamControllerEnqueueChunkToQueue(controller,
    //   transferredBuffer, byteOffset, byteLength).
    EnqueueChunkToQueue(controller, transferred_buffer, byte_offset,
                        byte_length);
  }

  // 12. Perform ! ReadableByteStreamControllerCallPullIfNeeded(controller).
  CallPullIfNeeded(script_state, controller);
}

void ReadableByteStreamController::EnqueueChunkToQueue(
    ReadableByteStreamController* controller,
    DOMArrayBuffer* buffer,
    size_t byte_offset,
    size_t byte_length) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-enqueue-chunk-to-queue
  // 1. Append a new readable byte stream queue entry with buffer buffer, byte
  // offset byteOffset, and byte length byteLength to controller.[[queue]].
  QueueEntry* const entry =
      MakeGarbageCollected<QueueEntry>(buffer, byte_offset, byte_length);
  controller->queue_.push_back(entry);
  // 2. Set controller.[[queueTotalSize]] to controller.[[queueTotalSize]] +
  // byteLength.
  controller->queue_total_size_ += byte_length;
}

void ReadableByteStreamController::EnqueueClonedChunkToQueue(
    ReadableByteStreamController* controller,
    DOMArrayBuffer* buffer,
    size_t byte_offset,
    size_t byte_length) {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablebytestreamcontrollerenqueueclonedchunktoqueue
  // 1. Let cloneResult be CloneArrayBuffer(buffer, byteOffset, byteLength,
  // %ArrayBuffer%).
  DOMArrayBuffer* const clone_result = DOMArrayBuffer::Create(
    buffer->ByteSpan().subspan(byte_offset, byte_length));
  // 2. If cloneResult is an abrupt completion,
  //   a. Perform ! ReadableByteStreamControllerError(controller,
  //   cloneResult.[[Value]]). b. Return cloneResult.
  // This is not needed as DOMArrayBuffer::Create() is designed to crash if it
  // cannot allocate the memory.

  // 3. Perform ! ReadableByteStreamControllerEnqueueChunkToQueue(controller,
  // cloneResult.[[Value]], 0, byteLength).
  EnqueueChunkToQueue(controller, clone_result, 0, byte_length);
}

void ReadableByteStreamController::EnqueueDetachedPullIntoToQueue(
    ReadableByteStreamController* controller,
    PullIntoDescriptor* pull_into_descriptor) {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablebytestreamcontrollerenqueuedetachedpullintotoqueue
  // Note: EnqueueDetachedPullIntoToQueue cannot throw in this implementation.
  // 1. Assert: pullIntoDescriptor’s reader type is "none".
  DCHECK_EQ(pull_into_descriptor->reader_type, ReaderType::kNone);

  // 2. If pullIntoDescriptor’s bytes filled > 0, perform ?
  // ReadableByteStreamControllerEnqueueClonedChunkToQueue(controller,
  // pullIntoDescriptor’s buffer, pullIntoDescriptor’s byte offset,
  // pullIntoDescriptor’s bytes filled).
  if (pull_into_descriptor->bytes_filled > 0) {
    EnqueueClonedChunkToQueue(controller, pull_into_descriptor->buffer,
                              pull_into_descriptor->byte_offset,
                              pull_into_descriptor->bytes_filled);
  }

  // 3. Perform ! ReadableByteStreamControllerShiftPendingPullInto(controller).
  ShiftPendingPullInto(controller);
}

void ReadableByteStreamController::ProcessPullIntoDescriptorsUsingQueue(
    ScriptState* script_state,
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-process-pull-into-descriptors-using-queue
  // 1. Assert: controller.[[closeRequested]] is false.
  DCHECK(!controller->close_requested_);
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::TryCatch try_catch(isolate);
  // 2. While controller.[[pendingPullIntos]] is not empty,
  while (!controller->pending_pull_intos_.empty()) {
    //   a. If controller.[[queueTotalSize]] is 0, return.
    if (controller->queue_total_size_ == 0) {
      return;
    }
    //   b. Let pullIntoDescriptor be controller.[[pendingPullIntos]][0].
    PullIntoDescriptor* const pull_into_descriptor =
        controller->pending_pull_intos_[0];
    //   c. If ! ReadableByteStreamControllerFillPullIntoDescriptorFromQueue(
    //   controller, pullIntoDescriptor) is true,
    if (FillPullIntoDescriptorFromQueue(controller, pull_into_descriptor,
                                        PassThroughException(isolate))) {
      //     i. Perform !
      //     ReadableByteStreamControllerShiftPendingPullInto(controller).
      ShiftPendingPullInto(controller);
      //     ii. Perform ! ReadableByteStreamControllerCommitPullIntoDescriptor(
      //     controller.[[stream]], pullIntoDescriptor).
      CommitPullIntoDescriptor(
          script_state, controller->controlled_readable_stream_,
          pull_into_descriptor, PassThroughException(isolate));
      DCHECK(!try_catch.HasCaught());
    }
    if (try_catch.HasCaught()) {
      // Instead of returning a rejection, which is inconvenient here,
      // call ControllerError(). The only difference this makes is that it
      // happens synchronously, but that should not be observable.
      ReadableByteStreamController::Error(script_state, controller,
                                          try_catch.Exception());
      return;
    }
  }
}

void ReadableByteStreamController::ProcessReadRequestsUsingQueue(
    ScriptState* script_state,
    ReadableByteStreamController* controller,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#abstract-opdef-readablebytestreamcontrollerprocessreadrequestsusingqueue
  // 1. Let reader be controller.[[stream]].[[reader]].
  ReadableStreamGenericReader* reader =
      controller->controlled_readable_stream_->reader_;
  // 2. Assert: reader implements ReadableStreamDefaultReader.
  DCHECK(reader->IsDefaultReader());
  ReadableStreamDefaultReader* default_reader =
      To<ReadableStreamDefaultReader>(reader);
  // 3. While reader.[[readRequests]] is not empty,
  while (!default_reader->read_requests_.empty()) {
    //   a. If controller.[[queueTotalSize]] is 0, return.
    if (controller->queue_total_size_ == 0) {
      return;
    }
    //   b. Let readRequest be reader.[[readRequests]][0].
    ReadRequest* read_request = default_reader->read_requests_[0];
    //   c. Remove readRequest from reader.[[readRequests]].
    default_reader->read_requests_.pop_front();
    //   d. Perform !
    //   ReadableByteStreamControllerFillReadRequestFromQueue(controller,
    //   readRequest).
    FillReadRequestFromQueue(script_state, controller, read_request,
                             exception_state);
  }
}

void ReadableByteStreamController::CallPullIfNeeded(
    ScriptState* script_state,
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-call-pull-if-needed
  // 1. Let shouldPull be !
  // ReadableByteStreamControllerShouldCallPull(controller).
  const bool should_pull = ShouldCallPull(controller);
  // 2. If shouldPull is false, return.
  if (!should_pull) {
    return;
  }
  // 3. If controller.[[pulling]] is true,
  if (controller->pulling_) {
    //   a. Set controller.[[pullAgain]] to true.
    controller->pull_again_ = true;
    //   b. Return.
    return;
  }
  // 4. Assert: controller.[[pullAgain]] is false.
  DCHECK(!controller->pull_again_);
  // 5. Set controller.[[pulling]] to true.
  controller->pulling_ = true;
  // 6. Let pullPromise be the result of performing
  // controller.[[pullAlgorithm]].
  auto pull_promise =
      controller->pull_algorithm_->Run(script_state, 0, nullptr);

  class ResolveFunction final
      : public ThenCallable<IDLUndefined, ResolveFunction> {
   public:
    explicit ResolveFunction(ReadableByteStreamController* controller)
        : controller_(controller) {}

    void React(ScriptState* script_state) {
      // 7. Upon fulfillment of pullPromise,
      //   a. Set controller.[[pulling]] to false.
      controller_->pulling_ = false;
      //   b. If controller.[[pullAgain]] is true,
      if (controller_->pull_again_) {
        //     i. Set controller.[[pullAgain]] to false.
        controller_->pull_again_ = false;
        //     ii. Perform !
        //     ReadableByteStreamControllerCallPullIfNeeded(controller).
        CallPullIfNeeded(script_state, controller_);
      }
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

    void React(ScriptState* script_state, ScriptValue e) {
      // 8. Upon rejection of pullPromise with reason e,
      //   a. Perform ! ReadableByteStreamControllerError(controller, e).
      Error(script_state, controller_, e.V8Value());
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(controller_);
      ThenCallable<IDLAny, RejectFunction>::Trace(visitor);
    }

   private:
    const Member<ReadableByteStreamController> controller_;
  };

  pull_promise.Then(script_state,
                    MakeGarbageCollected<ResolveFunction>(controller),
                    MakeGarbageCollected<RejectFunction>(controller));
}

ReadableByteStreamController::PullIntoDescriptor*
ReadableByteStreamController::ShiftPendingPullInto(
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-shift-pending-pull-into
  // 1. Assert: controller.[[byobRequest]] is null.
  DCHECK(!controller->byob_request_);
  // 2. Let descriptor be controller.[[pendingPullIntos]][0].
  PullIntoDescriptor* const descriptor = controller->pending_pull_intos_[0];
  // 3. Remove descriptor from controller.[[pendingPullIntos]].
  controller->pending_pull_intos_.pop_front();
  // 4. Return descriptor.
  return descriptor;
}

bool ReadableByteStreamController::ShouldCallPull(
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-should-call-pull
  // 1. Let stream be controller.[[stream]].
  ReadableStream* const stream = controller->controlled_readable_stream_;
  // 2. If stream.[[state]] is not "readable", return false.
  if (stream->state_ != ReadableStream::kReadable) {
    return false;
  }
  // 3. If controller.[[closeRequested]] is true, return false.
  if (controller->close_requested_) {
    return false;
  }
  // 4. If controller.[[started]] is false, return false.
  if (!controller->started_) {
    return false;
  }
  // 5. If ! ReadableStreamHasDefaultReader(stream) is true and !
  // ReadableStreamGetNumReadRequests(stream) > 0, return true.
  if (ReadableStream::HasDefaultReader(stream) &&
      ReadableStream::GetNumReadRequests(stream) > 0) {
    return true;
  }
  // 6. If ! ReadableStreamHasBYOBReader(stream) is true and !
  // ReadableStreamGetNumReadIntoRequests(stream) > 0, return true.
  if (ReadableStream::HasBYOBReader(stream) &&
      ReadableStream::GetNumReadIntoRequests(stream) > 0) {
    return true;
  }
  // 7. Let desiredSize be !
  // ReadableByteStreamControllerGetDesiredSize(controller).
  const std::optional<double> desired_size = GetDesiredSize(controller);
  // 8. Assert: desiredSize is not null.
  DCHECK(desired_size);
  // 9. If desiredSize > 0, return true.
  if (*desired_size > 0) {
    return true;
  }
  // 10. Return false.
  return false;
}

void ReadableByteStreamController::CommitPullIntoDescriptor(
    ScriptState* script_state,
    ReadableStream* stream,
    PullIntoDescriptor* pull_into_descriptor,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-commit-pull-into-descriptor
  // 1. Assert: stream.[[state]] is not "errored".
  DCHECK_NE(stream->state_, ReadableStream::kErrored);
  // 2. Assert: pullIntoDescriptor.reader type is not "none".
  DCHECK_NE(pull_into_descriptor->reader_type, ReaderType::kNone);
  // 3. Let done be false.
  bool done = false;
  // 4. If stream.[[state]] is "closed",
  if (stream->state_ == ReadableStream::kClosed) {
    //   a. Assert: pullIntoDescriptor’s bytes filled is 0.
    DCHECK_EQ(pull_into_descriptor->bytes_filled, 0u);
    //   b. Set done to true.
    done = true;
  }
  // 5. Let filledView be !
  // ReadableByteStreamControllerConvertPullIntoDescriptor(pullIntoDescriptor).
  auto* filled_view = ConvertPullIntoDescriptor(
      script_state, pull_into_descriptor, exception_state);
  DCHECK(!exception_state.HadException());
  // 6. If pullIntoDescriptor’s reader type is "default",
  if (pull_into_descriptor->reader_type == ReaderType::kDefault) {
    //   a. Perform ! ReadableStreamFulfillReadRequest(stream, filledView,
    //   done).
    ReadableStream::FulfillReadRequest(
        script_state, stream,
        ToV8Traits<DOMArrayBufferView>::ToV8(script_state, filled_view), done,
        exception_state);
  } else {
    // 7. Otherwise,
    //   a. Assert: pullIntoDescriptor’s reader type is "byob".
    DCHECK_EQ(pull_into_descriptor->reader_type, ReaderType::kBYOB);
    //   b. Perform ! ReadableStreamFulfillReadIntoRequest(stream, filledView,
    //   done).
    ReadableStream::FulfillReadIntoRequest(script_state, stream, filled_view,
                                           done, exception_state);
  }
}

DOMArrayBufferView* ReadableByteStreamController::ConvertPullIntoDescriptor(
    ScriptState* script_state,
    PullIntoDescriptor* pull_into_descriptor,
    ExceptionState& exception_state) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-convert-pull-into-descriptor
  // 1. Let bytesFilled be pullIntoDescriptor’s bytes filled.
  const size_t bytes_filled = pull_into_descriptor->bytes_filled;
  // 2. Let elementSize be pullIntoDescriptor’s element size.
  const size_t element_size = pull_into_descriptor->element_size;
  // 3. Assert: bytesFilled ≤ pullIntoDescriptor’s byte length.
  DCHECK_LE(bytes_filled, pull_into_descriptor->byte_length);
  // 4. Assert: bytesFilled mod elementSize is 0.
  DCHECK_EQ(bytes_filled % element_size, 0u);
  // 5. Let buffer be ! TransferArrayBuffer(pullIntoDescriptor's buffer).
  DOMArrayBuffer* const buffer = TransferArrayBuffer(
      script_state, pull_into_descriptor->buffer, exception_state);
  // 6. Return ! Construct(pullIntoDescriptor’s view constructor, « buffer,
  // pullIntoDescriptor’s byte offset, bytesFilled ÷ elementSize »).
  return pull_into_descriptor->view_constructor(
      buffer, pull_into_descriptor->byte_offset, (bytes_filled / element_size));
}

void ReadableByteStreamController::ClearPendingPullIntos(
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-clear-pending-pull-intos
  // 1. Perform ! ReadableByteStreamControllerInvalidateBYOBRequest(controller).
  InvalidateBYOBRequest(controller);
  // 2. Set controller.[[pendingPullIntos]] to a new empty list.
  controller->pending_pull_intos_.clear();
}

void ReadableByteStreamController::ClearAlgorithms(
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-clear-algorithms
  // 1. Set controller.[[pullAlgorithm]] to undefined.
  controller->pull_algorithm_ = nullptr;

  // 2. Set controller.[[cancelAlgorithm]] to undefined.
  controller->cancel_algorithm_ = nullptr;
}

void ReadableByteStreamController::InvalidateBYOBRequest(
    ReadableByteStreamController* controller) {
  // https://streams.spec.whatwg.org/#readable-byte-stream-controller-invalidate-byob-request
  // 1. If controller.[[byobRequest]] is null, return.
  if (!controller->byob_request_) {
    return;
  }
  // 2. Set controller.[[byobRequest]].[[controller]] to undefined.
  controller->byob_request_->controller_ = nullptr;
  // 3. Set controller.[[byobRequest]].[[view]] to null.
  controller->byob_request_->view_ = NotShared<DOMArra
"""


```
Response:
Let's break down the thought process for analyzing this `IncomingStream.cc` file.

**1. Initial Understanding of the File's Purpose:**

The file path `blink/renderer/modules/webtransport/incoming_stream.cc` immediately suggests its primary role: handling incoming data streams within the WebTransport API in the Blink rendering engine. "Incoming" implies it's responsible for processing data received *from* a remote endpoint.

**2. Identifying Key Data Structures and Classes:**

A quick scan of the `#include` directives and class declaration reveals the core components involved:

* **`IncomingStream`:** The central class, likely managing the state and operations of an incoming WebTransport stream.
* **`UnderlyingByteSource`:**  A nested class inheriting from `UnderlyingByteSourceBase`. This signals its connection to the Streams API and its role in providing data to the `ReadableStream`.
* **`ReadableStream` and `ReadableByteStreamController`:** These are fundamental classes from the WHATWG Streams API, indicating that `IncomingStream` exposes the received data as a readable stream.
* **`mojo::ScopedDataPipeConsumerHandle`:**  This points to the underlying communication mechanism, using Mojo data pipes for efficient data transfer between processes.
* **`WebTransportError`:** Handling errors specific to the WebTransport protocol.

**3. Analyzing Key Methods and their Functionality:**

I'd then go through the public and important private methods, inferring their purpose:

* **Constructor (`IncomingStream(...)`)**:  Likely initializes the stream with necessary components like the data pipe and an abort callback.
* **`Init()` and `InitWithExistingReadableStream()`:**  Sets up the `ReadableStream` and its controller, connecting it to the underlying data source.
* **`OnIncomingStreamClosed()`:** Handles the signal that the remote side has indicated the end of the stream.
* **`Error()`:**  Deals with errors reported from the WebTransport layer.
* **`ReadFromPipeAndEnqueue()`:** The core data processing method. It reads data from the Mojo pipe and pushes it into the `ReadableStream`. The "enqueue" part strongly suggests this.
* **`RespondBYOBRequestOrEnqueueBytes()`:** Handles both "bring your own buffer" (BYOB) reads for efficiency and regular enqueue operations for simpler cases.
* **`CloseAbortAndReset()`, `ErrorStreamAbortAndReset()`, `AbortAndReset()`:** Different ways to terminate the stream, potentially with error information.
* **`OnHandleReady()`:**  A callback triggered by the Mojo watcher when data is available in the pipe.
* **`HandlePipeClosed()`:**  Called when the Mojo data pipe is closed.
* **`ProcessClose()`:**  A consolidation point for handling stream closure after both the remote side signals closure and the underlying pipe is closed.
* **`ContextDestroyed()` and `Dispose()`:** Lifecycle management, cleaning up resources.

**4. Identifying Relationships with Web Technologies (JavaScript, HTML, CSS):**

The presence of `ReadableStream` immediately establishes a link with JavaScript. WebTransport's API is exposed through JavaScript, allowing developers to create and interact with these streams. HTML and CSS are less directly involved, as WebTransport is primarily about data transfer, but the *context* in which WebTransport is used (e.g., within a web page) involves these technologies.

**5. Considering Logical Reasoning (Hypothetical Inputs and Outputs):**

For `ReadFromPipeAndEnqueue()`:

* **Input:** Data arrives in the Mojo data pipe.
* **Output:** This data is enqueued into the `ReadableStream`, making it available to JavaScript via the stream's reader.

For `OnIncomingStreamClosed()`:

* **Input:** A signal from the WebTransport implementation that the remote side has finished sending data (FIN bit set).
* **Output:** The `fin_received_` flag is set, and the closing process is initiated, potentially leading to the `ReadableStream` being closed in JavaScript.

**6. Identifying Potential User/Programming Errors:**

Common errors often relate to misuse of asynchronous APIs like streams:

* Not properly handling the `ReadableStream`'s lifecycle (e.g., reading after it's closed).
* Incorrectly using BYOB readers.
* Expecting data to arrive immediately without handling the asynchronous nature of streams.

**7. Tracing User Actions to Code Execution (Debugging Clues):**

This requires thinking about the chain of events:

1. **JavaScript:** A script uses the WebTransport API to open a connection and receive an incoming stream.
2. **Blink (Renderer Process):** The JavaScript call triggers internal Blink code to create an `IncomingStream` object.
3. **Mojo Communication:** The underlying WebTransport implementation (likely in the network process) sends data over a Mojo data pipe, represented by `data_pipe_`.
4. **`OnHandleReady()`:** The Mojo watcher detects the incoming data and calls `OnHandleReady()`.
5. **`ReadFromPipeAndEnqueue()`:** This method is then invoked to read the data and push it into the `ReadableStream`.
6. **JavaScript Consumption:** The JavaScript code can then read data from the `ReadableStream`.

**Self-Correction/Refinement During Analysis:**

Initially, I might focus too much on the Mojo details. It's important to step back and remember the *purpose* of this code within the broader WebTransport context. The connection to the Streams API is a crucial piece of the puzzle, as it bridges the low-level data transfer with the JavaScript API. Also, distinguishing between different closure scenarios (`OnIncomingStreamClosed` vs. `HandlePipeClosed`) requires careful attention to detail.
好的，我们来分析一下 `blink/renderer/modules/webtransport/incoming_stream.cc` 这个文件。

**功能概要:**

`IncomingStream.cc` 文件实现了 Chromium Blink 引擎中用于处理 **WebTransport 协议接收到的单向数据流 (Incoming Stream)** 的核心逻辑。它的主要职责是：

1. **接收来自网络进程的底层数据:** 通过 Mojo DataPipe 接收从 WebTransport 连接的另一端发送过来的原始字节数据。
2. **将底层数据转换为 ReadableStream:**  它创建并管理一个 `ReadableStream` 对象，作为 JavaScript 可以消费的数据源。
3. **管理流的状态:** 跟踪流的打开、关闭、错误等状态。
4. **处理背压 (Backpressure):** 当 JavaScript 消费数据的速度慢于接收速度时，通过 `ReadableStream` 的机制来协调数据流。
5. **处理流的关闭和错误:**  当远程端关闭流或者发生错误时，会触发相应的处理逻辑，并通知 JavaScript。
6. **提供 BYOB (Bring Your Own Buffer) 读取优化:** 允许 JavaScript 提供预先分配的缓冲区来直接接收数据，提高性能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`IncomingStream.cc` 的功能直接关系到 WebTransport API 在 JavaScript 中的使用。

* **JavaScript:**
    * **`ReadableStream` 的暴露:**  `IncomingStream` 内部创建的 `ReadableStream` 对象最终会暴露给 JavaScript，可以通过 `WebTransportReceiveStream.readable` 属性访问。JavaScript 代码可以使用 `getReader()` 方法获取读取器，并使用 `read()` 方法从流中读取数据。
    * **错误处理:** 当 `IncomingStream` 遇到错误时，会触发 `ReadableStream` 的错误事件，JavaScript 可以通过监听 `catch` 或 `closed` promise 来处理这些错误。例如：

    ```javascript
    const transport = new WebTransport('...');
    await transport.ready;
    const receiveStream = await transport.createUnidirectionalStream();
    const reader = receiveStream.readable.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        // 处理接收到的数据 (value 是 Uint8Array)
        console.log('Received data:', value);
      }
    } catch (error) {
      console.error('Error reading stream:', error);
    } finally {
      reader.releaseLock();
    }
    ```

    * **BYOB 读取:** JavaScript 可以使用 `getReader({ mode: 'byob' })` 创建一个 BYOB 读取器，并提供 `ArrayBuffer` 或 `SharedArrayBuffer` 来接收数据，这直接对应了 `IncomingStream::RespondBYOBRequestOrEnqueueBytes` 方法的处理。

    ```javascript
    const transport = new WebTransport('...');
    await transport.ready;
    const receiveStream = await transport.createUnidirectionalStream();
    const reader = receiveStream.readable.getReader({ mode: 'byob' });
    const buffer = new ArrayBuffer(1024);
    while (true) {
      const { done, value } = await reader.read(new Uint8Array(buffer));
      if (done) {
        break;
      }
      // value 是包含接收到数据的 Uint8Array 视图
      console.log('Received data:', value);
    }
    reader.releaseLock();
    ```

* **HTML:**  HTML 本身不直接与 `IncomingStream.cc` 交互。但是，包含 WebTransport JavaScript 代码的 `<script>` 标签会使得浏览器执行相关的 WebTransport 操作，从而间接地触发 `IncomingStream.cc` 中的代码。

* **CSS:** CSS 与 `IncomingStream.cc` 没有直接关系。CSS 负责页面的样式，而 `IncomingStream.cc` 负责处理网络数据流。

**逻辑推理 (假设输入与输出):**

假设输入是一个 WebTransport 连接中接收到的数据包，Mojo DataPipe 将其传递给 `IncomingStream`。

* **假设输入:**  Mojo DataPipe 接收到来自网络进程的包含字符串 "Hello, WebTransport!" 的字节数据。
* **逻辑推理过程:**
    1. `OnHandleReady` 被触发，表示 DataPipe 中有数据可读。
    2. `ReadFromPipeAndEnqueue` 方法被调用。
    3. `data_pipe_->BeginReadData` 从 DataPipe 中读取数据到缓冲区。
    4. 如果 JavaScript 没有使用 BYOB 读取，`RespondBYOBRequestOrEnqueueBytes` 会创建一个 `DOMUint8Array` 包装这些字节，并调用 `controller_->enqueue` 将其添加到 `ReadableStream` 的队列中。
    5. 当 JavaScript 调用 `reader.read()` 时，`ReadableStream` 会从队列中取出数据并返回给 JavaScript。
* **假设输出:** JavaScript 的 `reader.read()` Promise resolve，返回一个 `{ done: false, value: Uint8Array[...] }`，其中 `Uint8Array` 包含了 "Hello, WebTransport!" 的 UTF-8 编码的字节。

**用户或编程常见的使用错误及举例说明:**

1. **未正确处理流的关闭:** JavaScript 代码可能没有正确监听 `ReadableStream` 的 `close` 或 `error` 事件，导致在流关闭或发生错误后仍然尝试读取数据。

    ```javascript
    const reader = receiveStream.readable.getReader();
    while (true) { // 错误示例：没有处理 done 的情况
      const { value } = await reader.read();
      console.log(value);
    }
    ```

    **正确做法:** 检查 `read()` 返回的 `done` 属性。

2. **在流关闭后尝试写入数据 (针对双向流，这里是接收流，但概念类似):**  虽然 `IncomingStream` 是接收流，但理解双向流的错误有助于理解流的生命周期管理。如果尝试在远程端已经关闭发送端的情况下继续发送数据，会导致错误。

3. **BYOB 读取器的使用不当:**  例如，提供的缓冲区大小不足以接收所有数据，或者在 `read()` 调用时传入了错误的参数。

    ```javascript
    const reader = receiveStream.readable.getReader({ mode: 'byob' });
    const buffer = new ArrayBuffer(5); // 缓冲区太小
    const result = await reader.read(new Uint8Array(buffer)); // 可能无法读取完整数据
    ```

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中打开一个网页，该网页包含使用 WebTransport API 的 JavaScript 代码。**
2. **JavaScript 代码创建一个 `WebTransport` 对象，并连接到服务器。**
   ```javascript
   const transport = new WebTransport('wss://example.com/webtransport');
   await transport.ready;
   ```
3. **服务器发起一个新的单向流并发送数据给客户端。**  这会在 Blink 渲染器进程中创建一个 `IncomingStream` 对象。
4. **底层网络栈接收到服务器发送的数据包。**
5. **数据通过 Mojo DataPipe 从网络进程传递到渲染器进程的 `IncomingStream` 对象。**
6. **`mojo::SimpleWatcher` 监听 DataPipe 的可读状态，并在数据到达时触发 `IncomingStream::OnHandleReady`。**
7. **`IncomingStream::ReadFromPipeAndEnqueue` 方法被调用，从 DataPipe 中读取数据并将其放入内部 `ReadableStream` 的队列中。**
8. **JavaScript 代码调用 `receiveStream.readable.getReader().read()` 来读取数据。**
9. **`ReadableStream` 的机制将数据从队列中取出，并返回给 JavaScript 代码。**

**调试线索:**

* **检查 JavaScript 代码中 WebTransport API 的使用是否正确。** 包括连接建立、流的创建和读取方式。
* **使用 Chrome 的 `chrome://webrtc-internals` 工具查看 WebTransport 连接的状态和统计信息。**  可以查看连接是否建立，是否有数据传输等。
* **在 `IncomingStream.cc` 中设置断点，例如在 `OnHandleReady`、`ReadFromPipeAndEnqueue` 和 `RespondBYOBRequestOrEnqueueBytes` 等关键方法中，来观察数据的流动和状态变化。**
* **检查 Mojo DataPipe 的状态，确保数据能够正确地从网络进程传递到渲染器进程。**
* **查看 `ReadableStream` 的状态和队列，确认数据是否被正确地添加到队列中。**

希望以上分析能够帮助你理解 `IncomingStream.cc` 文件的功能和它在 WebTransport 中的作用。

### 提示词
```
这是目录为blink/renderer/modules/webtransport/incoming_stream.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webtransport/incoming_stream.h"

#include <string.h>

#include <utility>

#include "base/compiler_specific.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_error.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_request.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/core/streams/readable_stream_generic_reader.h"
#include "third_party/blink/renderer/core/streams/readable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/streams/underlying_byte_source_base.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer/array_buffer_contents.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/webtransport/web_transport_error.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/trace_wrapper_v8_reference.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "v8/include/v8.h"

namespace blink {

// An implementation of UnderlyingByteSourceBase that forwards all operations to
// the IncomingStream object that created it.
class IncomingStream::UnderlyingByteSource final
    : public UnderlyingByteSourceBase {
 public:
  explicit UnderlyingByteSource(ScriptState* script_state,
                                IncomingStream* stream)
      : script_state_(script_state), incoming_stream_(stream) {}

  ScriptPromise<IDLUndefined> Pull(ReadableByteStreamController* controller,
                                   ExceptionState& exception_state) override {
    DCHECK_EQ(controller, incoming_stream_->controller_);
    incoming_stream_->ReadFromPipeAndEnqueue(exception_state);
    return ToResolvedUndefinedPromise(script_state_.Get());
  }

  ScriptPromise<IDLUndefined> Cancel() override {
    return Cancel(v8::Undefined(script_state_->GetIsolate()));
  }

  ScriptPromise<IDLUndefined> Cancel(v8::Local<v8::Value> reason) override {
    uint8_t code = 0;
    WebTransportError* exception =
        V8WebTransportError::ToWrappable(script_state_->GetIsolate(), reason);
    if (exception) {
      code = exception->streamErrorCode().value_or(0);
    }
    incoming_stream_->AbortAndReset(code);
    return ToResolvedUndefinedPromise(script_state_.Get());
  }

  ScriptState* GetScriptState() override { return script_state_.Get(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    visitor->Trace(incoming_stream_);
    UnderlyingByteSourceBase::Trace(visitor);
  }

 private:
  const Member<ScriptState> script_state_;
  const Member<IncomingStream> incoming_stream_;
};

IncomingStream::IncomingStream(
    ScriptState* script_state,
    base::OnceCallback<void(std::optional<uint8_t>)> on_abort,
    mojo::ScopedDataPipeConsumerHandle handle)
    : script_state_(script_state),
      on_abort_(std::move(on_abort)),
      data_pipe_(std::move(handle)),
      read_watcher_(FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL) {}

IncomingStream::~IncomingStream() = default;

void IncomingStream::Init(ExceptionState& exception_state) {
  DVLOG(1) << "IncomingStream::Init() this=" << this;
  auto* stream = MakeGarbageCollected<ReadableStream>();
  InitWithExistingReadableStream(stream, exception_state);
}

void IncomingStream::InitWithExistingReadableStream(
    ReadableStream* stream,
    ExceptionState& exception_state) {
  read_watcher_.Watch(
      data_pipe_.get(),
      MOJO_HANDLE_SIGNAL_READABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
      WTF::BindRepeating(&IncomingStream::OnHandleReady,
                         WrapWeakPersistent(this)));
  ReadableStream::InitByteStream(
      script_state_, stream,
      MakeGarbageCollected<UnderlyingByteSource>(script_state_, this),
      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  readable_ = stream;
  controller_ = To<ReadableByteStreamController>(stream->GetController());
}

void IncomingStream::OnIncomingStreamClosed(bool fin_received) {
  DVLOG(1) << "IncomingStream::OnIncomingStreamClosed(" << fin_received
           << ") this=" << this;

  DCHECK_NE(state_, State::kClosed);
  state_ = State::kClosed;

  DCHECK(!fin_received_.has_value());

  fin_received_ = fin_received;

  // Wait until HandlePipeClosed() has also been called before processing the
  // close.
  if (is_pipe_closed_) {
    ProcessClose();
  } else {
    // Wait for MOJO_HANDLE_SIGNAL_PEER_CLOSED.
    read_watcher_.ArmOrNotify();
  }
}

void IncomingStream::Error(ScriptValue reason) {
  DVLOG(1) << "IncomingStream::Error() this=" << this;

  // We no longer need to call |on_abort_|.
  on_abort_.Reset();

  ErrorStreamAbortAndReset(reason);
}

void IncomingStream::ContextDestroyed() {
  DVLOG(1) << "IncomingStream::ContextDestroyed() this=" << this;

  ResetPipe();
}

void IncomingStream::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(readable_);
  visitor->Trace(controller_);
}

void IncomingStream::OnHandleReady(MojoResult result,
                                   const mojo::HandleSignalsState&) {
  DVLOG(1) << "IncomingStream::OnHandleReady() this=" << this
           << " result=" << result;
  // |ReadFromPipeAndEnqueue| throws if close has been requested, stream state
  // is not readable, or buffer is invalid. Because both
  // |ErrorStreamAbortAndReset| and |ProcessClose| reset pipe, stream should be
  // readable here. Buffer returned by |BeginReadData| is expected to be valid
  // with size > 0.
  NonThrowableExceptionState exception_state;
  ReadFromPipeAndEnqueue(exception_state);
}

void IncomingStream::HandlePipeClosed() {
  DVLOG(1) << "IncomingStream::HandlePipeClosed() this=" << this;

  DCHECK(!is_pipe_closed_);

  is_pipe_closed_ = true;

  // Reset the pipe immediately to prevent being called in a loop.
  ResetPipe();

  // Wait until OnIncomingStreamClosed() has also been called before processing
  // the close.
  if (fin_received_.has_value()) {
    ProcessClose();
  }
}

void IncomingStream::ProcessClose() {
  DVLOG(1) << "IncomingStream::ProcessClose() this=" << this;

  DCHECK(fin_received_.has_value());

  if (fin_received_.value()) {
    ScriptState::Scope scope(script_state_);
    // Ignore exception because stream will be errored soon.
    CloseAbortAndReset(IGNORE_EXCEPTION);
  }

  ScriptValue error;
  {
    ScriptState::Scope scope(script_state_);
    DOMExceptionCode code = DOMExceptionCode::kNetworkError;
    String message =
        String::Format("The stream was aborted by the remote server");

    error = ScriptValue(script_state_->GetIsolate(),
                        V8ThrowDOMException::CreateOrEmpty(
                            script_state_->GetIsolate(), code, message));
  }
  ErrorStreamAbortAndReset(error);
}

void IncomingStream::ReadFromPipeAndEnqueue(ExceptionState& exception_state) {
  DVLOG(1) << "IncomingStream::ReadFromPipeAndEnqueue() this=" << this
           << " in_two_phase_read_=" << in_two_phase_read_
           << " read_pending_=" << read_pending_;
  if (is_pipe_closed_) {
    return;
  }

  // Protect against re-entrancy.
  if (in_two_phase_read_) {
    read_pending_ = true;
    return;
  }
  DCHECK(!read_pending_);

  base::span<const uint8_t> buffer;
  auto result =
      data_pipe_->BeginReadData(MOJO_BEGIN_READ_DATA_FLAG_NONE, buffer);
  switch (result) {
    case MOJO_RESULT_OK: {
      in_two_phase_read_ = true;

      // RespondBYOBRequestOrEnqueueBytes() may re-enter this method via pull().
      size_t read_bytes =
          RespondBYOBRequestOrEnqueueBytes(buffer, exception_state);
      if (exception_state.HadException()) {
        return;
      }
      // Casting back to `uint32_t` is safe because `read_bytes` cannot be
      // greater than `buffer_num_bytes`.
      data_pipe_->EndReadData(read_bytes);
      in_two_phase_read_ = false;
      if (read_pending_) {
        read_pending_ = false;
        // pull() will not be called when another pull() is in progress, so the
        // maximum recursion depth is 1.
        ReadFromPipeAndEnqueue(exception_state);
        if (exception_state.HadException()) {
          return;
        }
      }
      break;
    }

    case MOJO_RESULT_SHOULD_WAIT:
      read_watcher_.ArmOrNotify();
      return;

    case MOJO_RESULT_FAILED_PRECONDITION:
      HandlePipeClosed();
      return;

    default:
      NOTREACHED() << "Unexpected result: " << result;
  }
}

size_t IncomingStream::RespondBYOBRequestOrEnqueueBytes(
    base::span<const uint8_t> source,
    ExceptionState& exception_state) {
  DVLOG(1) << "IncomingStream::RespondBYOBRequestOrEnqueueBytes() this="
           << this;

  ScriptState::Scope scope(script_state_);

  if (ReadableStreamBYOBRequest* request = controller_->byobRequest()) {
    DOMArrayPiece view(request->view().Get());
    size_t byob_response_length = std::min(view.ByteLength(), source.size());
    view.ByteSpan().copy_prefix_from(source.first(byob_response_length));
    request->respond(script_state_, byob_response_length, exception_state);
    return byob_response_length;
  }

  auto* buffer = DOMUint8Array::Create(source);
  controller_->enqueue(script_state_, NotShared(buffer), exception_state);
  return source.size();
}

void IncomingStream::CloseAbortAndReset(ExceptionState& exception_state) {
  DVLOG(1) << "IncomingStream::CloseAbortAndReset() this=" << this;

  if (controller_) {
    ScriptState::Scope scope(script_state_);
    readable_->CloseStream(script_state_, exception_state);
    if (!exception_state.HadException()) {
      controller_ = nullptr;
    }
  }

  AbortAndReset(std::nullopt);
}

void IncomingStream::ErrorStreamAbortAndReset(ScriptValue exception) {
  DVLOG(1) << "IncomingStream::ErrorStreamAbortAndReset() this=" << this;

  if (controller_) {
    controller_->error(script_state_, exception);
    controller_ = nullptr;
  }

  AbortAndReset(std::nullopt);
}

void IncomingStream::AbortAndReset(std::optional<uint8_t> code) {
  DVLOG(1) << "IncomingStream::AbortAndReset() this=" << this;

  state_ = State::kAborted;

  if (on_abort_) {
    // Cause WebTransport to drop its reference to us.
    std::move(on_abort_).Run(code);
  }

  ResetPipe();
}

void IncomingStream::ResetPipe() {
  DVLOG(1) << "IncomingStream::ResetPipe() this=" << this;

  read_watcher_.Cancel();
  data_pipe_.reset();
}

void IncomingStream::Dispose() {
  DVLOG(1) << "IncomingStream::Dispose() this=" << this;

  ResetPipe();
}

}  // namespace blink
```
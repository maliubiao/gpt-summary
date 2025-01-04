Response:
Let's break down the thought process for analyzing this `OutgoingStream.cc` file.

**1. Initial Understanding and Goal:**

The first step is to recognize this is a C++ source file within the Chromium Blink rendering engine, specifically related to WebTransport. The request asks for its functionalities, relationships with web technologies, logical reasoning (with examples), potential errors, and user actions leading to its involvement.

**2. Core Functionality - Identifying the "What":**

The file name `outgoing_stream.cc` immediately suggests it handles sending data over a WebTransport stream. Reading through the code confirms this. Key elements that solidify this understanding:

* **`OutgoingStream` Class:** This is the central class, and its methods clearly deal with sending data (`SinkWrite`, `WriteOrCacheData`, `WriteDataSynchronously`), closing (`close`), and aborting (`abort`).
* **`UnderlyingSink` Class:**  This class implements the `UnderlyingSinkBase` interface, which is part of the Writable Streams API. This links the C++ implementation to the JavaScript API.
* **Mojo Data Pipe (`mojo::ScopedDataPipeProducerHandle`):**  This is the mechanism for sending data to the network service.
* **Promises (`ScriptPromise`):** The use of promises indicates asynchronous operations, aligning with how WebTransport works in JavaScript.
* **`WebTransportError`:** Handling of WebTransport specific errors.
* **State Management (`State::kOpen`, `State::kSentFin`, `State::kAborted`):** Indicates the lifecycle of an outgoing stream.

**3. Relating to Web Technologies (JavaScript, HTML, CSS):**

The core connection is through the Writable Streams API in JavaScript.

* **JavaScript:** The `OutgoingStream` class directly corresponds to the JavaScript `WebTransportSendStream` object. The methods like `write()`, `close()`, and `abort()` in the `UnderlyingSink` map to the corresponding methods on the JavaScript stream. The use of `ScriptPromise` and handling of `ScriptValue` are strong indicators of interaction with the JavaScript engine.
* **HTML:**  While not directly involved, HTML triggers the JavaScript that *uses* WebTransport. For example, a user clicking a button could initiate a WebTransport connection and start sending data via an `OutgoingStream`.
* **CSS:** CSS is even further removed. It styles the page but doesn't directly interact with the data transmission logic of WebTransport.

**4. Logical Reasoning and Examples:**

Here, the goal is to demonstrate *how* the code works and the flow of data.

* **Assumption:** A JavaScript calls `stream.getWriter().write(data)`.
* **Input:** `data` (an ArrayBuffer or ArrayBufferView).
* **Steps (simplified):**
    1. `WritableStreamDefaultController::enqueue()` is called in JS.
    2. This triggers the `UnderlyingSink::write()` method in C++.
    3. `OutgoingStream::SinkWrite()` is called.
    4. Data is written to the Mojo data pipe (`WriteDataSynchronously`).
    5. If the pipe is full, the data is cached (`WriteOrCacheData`).
    6. When the pipe is ready (`OnHandleReady`), cached data is flushed.
* **Output:** The `Promise` returned by `write()` resolves when the data is successfully sent (or rejects if there's an error).

**5. Common User/Programming Errors:**

This involves thinking about how developers might misuse the API.

* **Writing after closing:** A classic stream error. The code explicitly checks for this.
* **Aborting multiple times:** While the code handles it, it's important to note the implications and potential confusion.
* **Not handling errors:** WebTransport can have network issues. Developers need to use the promises to catch rejections.

**6. User Actions as Debugging Clues:**

This connects the code back to real-world usage.

* **Opening DevTools:**  A common starting point for debugging.
* **Network Tab:**  Monitoring WebTransport frames helps confirm data is being sent.
* **Console Logging:** Using `console.log()` in JavaScript to track the state of the stream and data being sent.
* **Breakpoints:** Setting breakpoints in the C++ code (if possible) to step through the execution.

**7. Iterative Refinement and Detail:**

As the analysis progresses, more specific details emerge. For instance:

* The role of `ScriptPromiseResolver` in managing asynchronous operations.
* The use of Mojo watchers (`write_watcher_`, `close_watcher_`).
* The caching mechanism for handling backpressure.
* The different states of the `OutgoingStream`.
* The handling of abort signals.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus only on the data sending.
* **Correction:** Realize the importance of the stream lifecycle (opening, closing, aborting) and the interaction with the Writable Streams API.
* **Initial thought:**  Explain errors in terms of low-level Mojo failures.
* **Correction:**  Frame errors in terms of the JavaScript API (e.g., "writing after close") as that's the user-facing perspective.
* **Initial thought:**  Overlook the `AbortSignal` integration.
* **Correction:** Recognize how abort signals from the JavaScript side trigger actions in the C++ code.

By following this structured approach, combining code reading with knowledge of web technologies and common programming practices, a comprehensive analysis like the example provided can be generated.
这个文件 `outgoing_stream.cc` 是 Chromium Blink 渲染引擎中负责处理 WebTransport 协议**出站数据流**的实现。它的主要功能是管理从浏览器发送到服务器的数据流。

以下是它的详细功能列表，以及与 JavaScript、HTML、CSS 的关系，逻辑推理示例，用户错误示例，以及用户操作如何到达这里的调试线索：

**文件功能:**

1. **管理出站数据流的生命周期:**  包括流的创建、数据写入、正常关闭和异常终止等状态管理。它维护了流的状态（例如：打开、已发送FIN、已中止）。
2. **实现 WritableStream API:**  `OutgoingStream` 类内部使用 `WritableStream` 来暴露给 JavaScript，允许 JavaScript 代码通过标准的 Streams API 将数据写入到 WebTransport 流。
3. **与 Mojo 数据管道交互:** 使用 `mojo::ScopedDataPipeProducerHandle` 与浏览器进程中的网络服务进行通信，实际发送数据。
4. **处理数据写入:**  接收来自 JavaScript 的数据块（可以是 `ArrayBuffer` 或 `ArrayBufferView`），并通过 Mojo 数据管道发送出去。它包含同步和异步写入机制，处理管道缓冲区满的情况。
5. **缓存待发送数据:** 当 Mojo 数据管道暂时不可写时，会将待发送的数据缓存起来，并在管道变为可写时继续发送。
6. **处理流的关闭:** 响应 JavaScript 代码的 `stream.getWriter().close()` 调用，向服务器发送 FIN (Finish) 帧，表示不再发送更多数据。
7. **处理流的终止 (Abort):** 响应 JavaScript 代码的 `stream.getWriter().abort(reason)` 调用，向服务器发送一个重置帧，并可以携带一个错误码。
8. **处理网络错误:**  监听 Mojo 数据管道的关闭事件，当连接异常断开时，会通知 JavaScript 并终止流。
9. **与 AbortSignal 集成:**  允许 JavaScript 的 `AbortSignal` 中止正在进行的写入操作或关闭操作。
10. **内存管理:**  使用分区分配器 (`WTF::Partitions::BufferPartition()`) 来管理缓存数据的内存，并使用 `V8ExternalMemoryAccounter` 来跟踪 V8 引擎的外部内存使用情况。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  `OutgoingStream` 是 WebTransport API 在 Blink 渲染引擎中的核心实现部分，直接与 JavaScript 代码交互。
    * **示例:**  JavaScript 代码通过 `WebTransportSendStream` 对象的 `getWriter()` 方法获取 `WritableStreamDefaultWriter`，然后使用 `writer.write(data)` 方法将数据发送到服务器。`OutgoingStream` 负责接收并处理这些 `write` 操作。
    ```javascript
    const transport = new WebTransport("https://example.com/webtransport");
    await transport.ready;
    const stream = await transport.createUnidirectionalStream();
    const writer = stream.getWriter();
    const data = new Uint8Array([1, 2, 3]);
    await writer.write(data);
    await writer.close();
    ```
    在这个例子中，`writer.write(data)` 的调用最终会触发 `OutgoingStream::SinkWrite` 方法。
    * **示例:** JavaScript 代码调用 `writer.close()`，会触发 `OutgoingStream::close` 方法。
    * **示例:** JavaScript 代码调用 `writer.abort(new Error("Something went wrong"))`，会触发 `OutgoingStream::abort` 方法。
    * **示例:**  JavaScript 可以使用 `AbortController` 来取消正在进行的写入操作。
    ```javascript
    const controller = new AbortController();
    const signal = controller.signal;
    // ... 获取 writer ...
    writer.write(data, { signal }).catch(error => {
      if (error.name === 'AbortError') {
        console.log("Write operation aborted.");
      }
    });
    controller.abort();
    ```
    这里的 `signal` 会关联到 `OutgoingStream` 的 `AbortAlgorithm`。

* **HTML:**  HTML 本身不直接与 `outgoing_stream.cc` 交互。但是，HTML 中包含的 JavaScript 代码会使用 WebTransport API，从而间接地触发 `OutgoingStream` 的功能。
    * **示例:**  一个 HTML 页面包含使用 WebTransport 发送数据的 JavaScript 代码。用户与页面交互（例如点击按钮），触发 JavaScript 代码创建 WebTransport 连接和流，最终使用 `OutgoingStream` 发送数据。

* **CSS:** CSS 与 `outgoing_stream.cc` 没有直接关系。CSS 负责页面的样式，而 `outgoing_stream.cc` 负责网络数据的传输。

**逻辑推理示例:**

**假设输入:**

1. JavaScript 调用 `writer.write(arrayBuffer)`，其中 `arrayBuffer` 的大小为 10KB。
2. 此时，Mojo 数据管道的剩余可写空间只有 5KB。

**逻辑推理:**

1. `OutgoingStream::SinkWrite` 被调用。
2. `OutgoingStream::WriteOrCacheData` 被调用。
3. `OutgoingStream::WriteDataSynchronously` 尝试写入 10KB 数据到管道。
4. 由于管道只有 5KB 可用空间，`WriteDataSynchronously` 写入 5KB 数据并返回。
5. `WriteOrCacheData` 检测到还有 5KB 数据未写入。
6. `OutgoingStream` 将剩余的 5KB 数据缓存到 `cached_data_` 中。
7. `write_watcher_` 被激活，等待 Mojo 数据管道变为可写。
8. 当 Mojo 数据管道再次变为可写时，`OutgoingStream::OnHandleReady` 被调用。
9. `OutgoingStream::WriteCachedData` 被调用，将缓存的 5KB 数据写入管道。
10. 当所有缓存数据写入成功后，与 `writer.write()` 关联的 Promise 被 resolve。

**输出:**

* 首次 `WriteDataSynchronously` 返回写入的字节数为 5KB。
* 最终所有 10KB 数据成功发送到服务器。
* JavaScript 中 `writer.write(arrayBuffer)` 返回的 Promise 成功 resolve。

**用户或编程常见的使用错误:**

1. **在流关闭后尝试写入数据:**
   * **示例:** JavaScript 代码在调用 `writer.close()` 后，仍然尝试调用 `writer.write()`。
   * **结果:** `OutgoingStream::SinkWrite` 会检查流的状态，如果流已关闭，则会拒绝 Promise 并抛出一个错误。
   * **错误信息 (类似):**  "Failed to execute 'write' on 'WritableStreamDefaultWriter': Cannot write to a closed writer."

2. **多次调用 `getWriter()`:**
   * **示例:**  尝试在一个 `WebTransportSendStream` 对象上多次调用 `getWriter()`。
   * **结果:** WritableStream 的规范禁止这样做，通常会在 JavaScript 层抛出错误。

3. **不处理 `write()` 返回的 Promise 的 rejection:**
   * **示例:**  JavaScript 代码调用 `writer.write()` 但没有使用 `then()` 或 `catch()` 来处理 Promise 的结果。
   * **结果:** 如果写入过程中发生错误（例如网络中断），Promise 会被 reject，如果没有处理，可能会导致未知的错误状态。

4. **过大的数据块导致内存问题:**
   * **示例:**  JavaScript 尝试写入非常大的 `ArrayBuffer`，超出浏览器或操作系统的内存限制。
   * **结果:**  可能导致内存分配失败，浏览器崩溃或性能下降。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在一个网页上执行了以下操作，最终导致 `outgoing_stream.cc` 中的代码被执行：

1. **用户打开一个支持 WebTransport 的网页。**
2. **网页中的 JavaScript 代码创建了一个 `WebTransport` 对象，并连接到服务器。**
   ```javascript
   const transport = new WebTransport("https://example.com/webtransport");
   await transport.ready;
   ```
3. **JavaScript 代码创建了一个出站单向流或双向流。**
   ```javascript
   const sendStream = transport.createUnidirectionalStream(); // 或 transport.createBidirectionalStream();
   ```
4. **JavaScript 代码获取流的 Writer。**
   ```javascript
   const writer = sendStream.getWriter();
   ```
5. **用户在网页上执行了某个操作（例如点击按钮、提交表单），触发 JavaScript 代码向流中写入数据。**
   ```javascript
   const dataToSend = new TextEncoder().encode("Hello, WebTransport!");
   await writer.write(dataToSend);
   ```

**调试线索:**

* **Network 面板 (Chrome DevTools):**  在 Chrome 开发者工具的 "Network" 面板中，可以查看 WebTransport 连接和流的信息，包括发送和接收的帧。可以确认是否成功建立了 WebTransport 连接，以及是否正在发送数据。
* **`chrome://webrtc-internals`:**  可以提供更底层的 WebRTC 和 WebTransport 相关的日志和统计信息。
* **设置断点:**  在 `outgoing_stream.cc` 中的关键方法（例如 `SinkWrite`, `WriteOrCacheData`, `OnHandleReady`）设置断点，可以跟踪数据写入的流程，查看变量的值，了解数据是否被缓存，以及何时发送。
* **日志输出:**  在 `outgoing_stream.cc` 中添加 `DVLOG` 调试日志，可以输出更详细的执行信息。需要在编译 Chromium 时启用相应的日志级别。
* **JavaScript 控制台:**  在 JavaScript 代码中使用 `console.log()` 记录关键事件和数据，例如写入的数据内容、Promise 的状态等。
* **检查 Mojo 连接:**  可以使用 Mojo 的调试工具或日志来检查 Mojo 数据管道的状态，确认管道是否正常工作。

通过以上分析，可以理解 `outgoing_stream.cc` 在 WebTransport 数据发送过程中的关键作用，以及如何与上层的 JavaScript 代码交互，并提供了一些调试的思路。

Prompt: 
```
这是目录为blink/renderer/modules/webtransport/outgoing_stream.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webtransport/outgoing_stream.h"

#include <cstring>
#include <utility>

#include "base/containers/heap_array.h"
#include "base/numerics/safe_conversions.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "partition_alloc/partition_alloc.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_error.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/underlying_sink_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/streams/writable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/modules/webtransport/web_transport_error.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_external_memory_accounter.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

class SendStreamAbortAlgorithm final : public AbortSignal::Algorithm {
 public:
  explicit SendStreamAbortAlgorithm(OutgoingStream* stream) : stream_(stream) {}
  ~SendStreamAbortAlgorithm() override = default;

  void Run() override { stream_->AbortAlgorithm(stream_); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(stream_);
    Algorithm::Trace(visitor);
  }

 private:
  Member<OutgoingStream> stream_;
};

struct CachedDataBufferDeleter {
  void operator()(void* buffer) {
    WTF::Partitions::BufferPartition()->Free(buffer);
  }
};

}  // namespace

class OutgoingStream::UnderlyingSink final : public UnderlyingSinkBase {
 public:
  explicit UnderlyingSink(OutgoingStream* outgoing_stream)
      : outgoing_stream_(outgoing_stream) {}

  // Implementation of UnderlyingSinkBase
  ScriptPromise<IDLUndefined> start(ScriptState* script_state,
                                    WritableStreamDefaultController* controller,
                                    ExceptionState&) override {
    DVLOG(1) << "OutgoingStream::UnderlyinkSink::start() outgoing_stream_="
             << outgoing_stream_;

    outgoing_stream_->controller_ = controller;
    return ToResolvedUndefinedPromise(script_state);
  }

  ScriptPromise<IDLUndefined> write(ScriptState* script_state,
                                    ScriptValue chunk,
                                    WritableStreamDefaultController*,
                                    ExceptionState& exception_state) override {
    DVLOG(1) << "OutgoingStream::UnderlyingSink::write() outgoing_stream_="
             << outgoing_stream_;

    // OutgoingStream::SinkWrite() is a separate method rather than being
    // inlined here because it makes many accesses to outgoing_stream_ member
    // variables.
    return outgoing_stream_->SinkWrite(script_state, chunk, exception_state);
  }

  ScriptPromise<IDLUndefined> close(ScriptState* script_state,
                                    ExceptionState&) override {
    DVLOG(1) << "OutgoingStream::UnderlingSink::close() outgoing_stream_="
             << outgoing_stream_;

    // The streams specification guarantees that this will only be called after
    // all pending writes have been completed.
    DCHECK(!outgoing_stream_->write_promise_resolver_);

    DCHECK(!outgoing_stream_->close_promise_resolver_);

    outgoing_stream_->close_promise_resolver_ =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
    outgoing_stream_->pending_operation_ =
        outgoing_stream_->close_promise_resolver_;

    // In some cases (when the stream is aborted by a network error for
    // example), there may not be a call to OnOutgoingStreamClose. In that case
    // we will not be able to resolve the promise, but that will be taken care
    // by streams so we don't care.
    outgoing_stream_->close_promise_resolver_->SuppressDetachCheck();

    DCHECK_EQ(outgoing_stream_->state_, State::kOpen);
    outgoing_stream_->state_ = State::kSentFin;
    outgoing_stream_->client_->SendFin();

    // Close the data pipe to signal to the network service that no more data
    // will be sent.
    outgoing_stream_->ResetPipe();

    return outgoing_stream_->close_promise_resolver_->Promise();
  }

  ScriptPromise<IDLUndefined> abort(ScriptState* script_state,
                                    ScriptValue reason,
                                    ExceptionState& exception_state) override {
    DVLOG(1) << "OutgoingStream::UnderlyingSink::abort() outgoing_stream_="
             << outgoing_stream_;
    DCHECK(!reason.IsEmpty());

    uint8_t code = 0;
    WebTransportError* exception = V8WebTransportError::ToWrappable(
        script_state->GetIsolate(), reason.V8Value());
    if (exception) {
      code = exception->streamErrorCode().value_or(0);
    }
    outgoing_stream_->client_->Reset(code);
    outgoing_stream_->AbortAndReset();

    return ToResolvedUndefinedPromise(script_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(outgoing_stream_);
    UnderlyingSinkBase::Trace(visitor);
  }

 private:
  const Member<OutgoingStream> outgoing_stream_;
};

class OutgoingStream::CachedDataBuffer {
 public:
  using HeapBuffer = base::HeapArray<uint8_t, CachedDataBufferDeleter>;

  CachedDataBuffer(v8::Isolate* isolate, base::span<const uint8_t> data)
      : isolate_(isolate) {
    // We use the BufferPartition() allocator here to allow big enough
    // allocations, and to do proper accounting of the used memory. If
    // BufferPartition() will ever not be able to provide big enough
    // allocations, e.g. because bigger ArrayBuffers get supported, then we
    // have to switch to another allocator, e.g. the ArrayBuffer allocator.
    void* memory_buffer = WTF::Partitions::BufferPartition()->Alloc(
        data.size(), "OutgoingStream");
    // SAFETY: WTF::Partitions::BufferPartition()->Alloc() returns a valid
    // pointer to at least data.size() bytes.
    buffer_ = UNSAFE_BUFFERS(HeapBuffer::FromOwningPointer(
        reinterpret_cast<uint8_t*>(memory_buffer), data.size()));
    buffer_.copy_from(data);
    external_memory_accounter_.Increase(isolate_.get(), buffer_.size());
  }

  ~CachedDataBuffer() {
    external_memory_accounter_.Decrease(isolate_.get(), buffer_.size());
  }

  base::span<const uint8_t> span() const { return buffer_; }

 private:
  // We need the isolate to report memory to
  // |external_memory_accounter_| for the memory stored in |buffer_|.
  raw_ptr<v8::Isolate> isolate_;
  HeapBuffer buffer_;
  NO_UNIQUE_ADDRESS V8ExternalMemoryAccounterBase external_memory_accounter_;
};

OutgoingStream::OutgoingStream(ScriptState* script_state,
                               Client* client,
                               mojo::ScopedDataPipeProducerHandle handle)
    : script_state_(script_state),
      client_(client),
      data_pipe_(std::move(handle)),
      write_watcher_(FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL),
      close_watcher_(FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::AUTOMATIC) {}

OutgoingStream::~OutgoingStream() = default;

void OutgoingStream::Init(ExceptionState& exception_state) {
  DVLOG(1) << "OutgoingStream::Init() this=" << this;
  auto* stream = MakeGarbageCollected<WritableStream>();
  InitWithExistingWritableStream(stream, exception_state);
}

void OutgoingStream::InitWithExistingWritableStream(
    WritableStream* stream,
    ExceptionState& exception_state) {
  write_watcher_.Watch(data_pipe_.get(), MOJO_HANDLE_SIGNAL_WRITABLE,
                       MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
                       WTF::BindRepeating(&OutgoingStream::OnHandleReady,
                                          WrapWeakPersistent(this)));
  close_watcher_.Watch(data_pipe_.get(), MOJO_HANDLE_SIGNAL_PEER_CLOSED,
                       MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
                       WTF::BindRepeating(&OutgoingStream::OnPeerClosed,
                                          WrapWeakPersistent(this)));

  writable_ = stream;
  stream->InitWithCountQueueingStrategy(
      script_state_, MakeGarbageCollected<UnderlyingSink>(this), 1,
      /*optimizer=*/nullptr, exception_state);
  send_stream_abort_handle_ = controller_->signal()->AddAlgorithm(
      MakeGarbageCollected<SendStreamAbortAlgorithm>(this));
}

void OutgoingStream::AbortAlgorithm(OutgoingStream* stream) {
  send_stream_abort_handle_.Clear();

  // Step 7 of https://w3c.github.io/webtransport/#webtransportsendstream-create
  // 1. Let pendingOperation be stream.[[PendingOperation]].
  // 2. If pendingOperation is null, then abort these steps.
  auto* pending_operation = stream->pending_operation_.Get();
  if (!pending_operation) {
    return;
  }

  // 3. Set stream.[[PendingOperation]] to null.
  stream->pending_operation_ = nullptr;

  // 4. Let reason be abortSignal’s abort reason.
  ScriptValue reason = stream->controller_->signal()->reason(script_state_);

  // 5. Let promise be the result of aborting stream with reason.
  // ASSERT_NO_EXCEPTION is used as OutgoingStream::UnderlyingSink::abort()
  // does not throw an exception, and hence a proper ExceptionState does not
  // have to be passed since it is not used.
  auto* underlying_sink = MakeGarbageCollected<UnderlyingSink>(stream);
  ScriptPromise<IDLUndefined> abort_promise =
      underlying_sink->abort(script_state_, reason, ASSERT_NO_EXCEPTION);

  // 6. Upon fulfillment of promise, reject pendingOperation with reason.
  class ResolveFunction final
      : public ThenCallable<IDLUndefined, ResolveFunction> {
   public:
    ResolveFunction(ScriptValue reason,
                    ScriptPromiseResolver<IDLUndefined>* resolver)
        : reason_(reason), resolver_(resolver) {}

    void React(ScriptState*) { resolver_->Reject(reason_); }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(reason_);
      visitor->Trace(resolver_);
      ThenCallable<IDLUndefined, ResolveFunction>::Trace(visitor);
    }

   private:
    ScriptValue reason_;
    Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  };
  abort_promise.Then(script_state_, MakeGarbageCollected<ResolveFunction>(
                                        reason, pending_operation));
}

void OutgoingStream::OnOutgoingStreamClosed() {
  DVLOG(1) << "OutgoingStream::OnOutgoingStreamClosed() this=" << this;

  DCHECK(close_promise_resolver_);
  pending_operation_ = nullptr;
  close_promise_resolver_->Resolve();
  close_promise_resolver_ = nullptr;
}

void OutgoingStream::Error(ScriptValue reason) {
  DVLOG(1) << "OutgoingStream::Error() this=" << this;

  ErrorStreamAbortAndReset(reason);
}

void OutgoingStream::ContextDestroyed() {
  DVLOG(1) << "OutgoingStream::ContextDestroyed() this=" << this;

  ResetPipe();
}

void OutgoingStream::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(client_);
  visitor->Trace(writable_);
  visitor->Trace(send_stream_abort_handle_);
  visitor->Trace(controller_);
  visitor->Trace(write_promise_resolver_);
  visitor->Trace(close_promise_resolver_);
  visitor->Trace(pending_operation_);
}

void OutgoingStream::OnHandleReady(MojoResult result,
                                   const mojo::HandleSignalsState&) {
  DVLOG(1) << "OutgoingStream::OnHandleReady() this=" << this
           << " result=" << result;

  switch (result) {
    case MOJO_RESULT_OK:
      WriteCachedData();
      break;
    case MOJO_RESULT_FAILED_PRECONDITION:
      HandlePipeClosed();
      break;
    default:
      NOTREACHED();
  }
}

void OutgoingStream::OnPeerClosed(MojoResult result,
                                  const mojo::HandleSignalsState&) {
  DVLOG(1) << "OutgoingStream::OnPeerClosed() this=" << this
           << " result=" << result;

  switch (result) {
    case MOJO_RESULT_OK:
      HandlePipeClosed();
      break;
    default:
      NOTREACHED();
  }
}

void OutgoingStream::HandlePipeClosed() {
  DVLOG(1) << "OutgoingStream::HandlePipeClosed() this=" << this;

  ScriptState::Scope scope(script_state_);
  ErrorStreamAbortAndReset(CreateAbortException(IsLocalAbort(false)));
}

ScriptPromise<IDLUndefined> OutgoingStream::SinkWrite(
    ScriptState* script_state,
    ScriptValue chunk,
    ExceptionState& exception_state) {
  DVLOG(1) << "OutgoingStream::SinkWrite() this=" << this;

  // There can only be one call to write() in progress at a time.
  DCHECK(!write_promise_resolver_);
  DCHECK_EQ(0u, offset_);

  auto* buffer_source = V8BufferSource::Create(
      script_state_->GetIsolate(), chunk.V8Value(), exception_state);
  if (exception_state.HadException())
    return EmptyPromise();
  DCHECK(buffer_source);

  if (!data_pipe_) {
    return ScriptPromise<IDLUndefined>::Reject(
        script_state, CreateAbortException(IsLocalAbort(false)));
  }

  DOMArrayPiece array_piece(buffer_source);
  return WriteOrCacheData(script_state, array_piece.ByteSpan());
}

// Attempt to write |data|. Cache anything that could not be written
// synchronously. Arrange for the cached data to be written asynchronously.
ScriptPromise<IDLUndefined> OutgoingStream::WriteOrCacheData(
    ScriptState* script_state,
    base::span<const uint8_t> data) {
  DVLOG(1) << "OutgoingStream::WriteOrCacheData() this=" << this << " data=("
           << static_cast<const void*>(data.data()) << ", " << data.size()
           << ")";
  size_t written = WriteDataSynchronously(data);

  if (written == data.size())
    return ToResolvedUndefinedPromise(script_state);

  DCHECK_LT(written, data.size());

  if (!data_pipe_) {
    return ScriptPromise<IDLUndefined>::Reject(
        script_state, CreateAbortException(IsLocalAbort(false)));
  }

  DCHECK(!cached_data_);
  cached_data_ = std::make_unique<CachedDataBuffer>(script_state->GetIsolate(),
                                                    data.subspan(written));
  DCHECK_EQ(offset_, 0u);
  write_watcher_.ArmOrNotify();
  write_promise_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  pending_operation_ = write_promise_resolver_;
  return write_promise_resolver_->Promise();
}

// Write data previously cached. Arrange for any remaining data to be sent
// asynchronously. Fulfill |write_promise_resolver_| once all data has been
// written.
void OutgoingStream::WriteCachedData() {
  DVLOG(1) << "OutgoingStream::WriteCachedData() this=" << this;

  auto data = cached_data_->span().subspan(offset_);
  size_t written = WriteDataSynchronously(data);

  if (written == data.size()) {
    ScriptState::Scope scope(script_state_);

    cached_data_.reset();
    offset_ = 0;
    pending_operation_ = nullptr;
    write_promise_resolver_->Resolve();
    write_promise_resolver_ = nullptr;
    return;
  }

  if (!data_pipe_) {
    cached_data_.reset();
    offset_ = 0;

    return;
  }

  offset_ += written;

  write_watcher_.ArmOrNotify();
}

// Write as much of |data| as can be written synchronously. Return the number of
// bytes written. May close |data_pipe_| as a side-effect on error.
size_t OutgoingStream::WriteDataSynchronously(base::span<const uint8_t> data) {
  DVLOG(1) << "OutgoingStream::WriteDataSynchronously() this=" << this
           << " data=(" << static_cast<const void*>(data.data()) << ", "
           << data.size() << ")";
  DCHECK(data_pipe_);

  size_t actually_written_bytes = 0;
  MojoResult result = data_pipe_->WriteData(data, MOJO_WRITE_DATA_FLAG_NONE,
                                            actually_written_bytes);
  switch (result) {
    case MOJO_RESULT_OK:
      return actually_written_bytes;

    case MOJO_RESULT_SHOULD_WAIT:
      return 0;

    case MOJO_RESULT_FAILED_PRECONDITION:
      HandlePipeClosed();
      return 0;

    default:
      NOTREACHED();
  }
}

ScriptValue OutgoingStream::CreateAbortException(IsLocalAbort is_local_abort) {
  DVLOG(1) << "OutgoingStream::CreateAbortException() this=" << this
           << " is_local_abort=" << static_cast<bool>(is_local_abort);

  DOMExceptionCode code = is_local_abort ? DOMExceptionCode::kAbortError
                                         : DOMExceptionCode::kNetworkError;
  String message =
      String::Format("The stream was aborted %s",
                     is_local_abort ? "locally" : "by the remote server");

  return ScriptValue(script_state_->GetIsolate(),
                     V8ThrowDOMException::CreateOrEmpty(
                         script_state_->GetIsolate(), code, message));
}

void OutgoingStream::ErrorStreamAbortAndReset(ScriptValue reason) {
  DVLOG(1) << "OutgoingStream::ErrorStreamAbortAndReset() this=" << this;

  if (write_promise_resolver_) {
    write_promise_resolver_->Reject(reason);
    write_promise_resolver_ = nullptr;
    controller_ = nullptr;
  } else if (controller_) {
    controller_->error(script_state_, reason);
    controller_ = nullptr;
  }
  if (close_promise_resolver_) {
    pending_operation_ = nullptr;
    close_promise_resolver_->Reject(reason);
    close_promise_resolver_ = nullptr;
  }

  AbortAndReset();
}

void OutgoingStream::AbortAndReset() {
  DVLOG(1) << "OutgoingStream::AbortAndReset() this=" << this;

  DCHECK(state_ == State::kOpen || state_ == State::kSentFin);
  state_ = State::kAborted;
  client_->ForgetStream();

  ResetPipe();
}

void OutgoingStream::ResetPipe() {
  DVLOG(1) << "OutgoingStream::ResetPipe() this=" << this;

  write_watcher_.Cancel();
  close_watcher_.Cancel();
  data_pipe_.reset();
  if (cached_data_)
    cached_data_.reset();
}

void OutgoingStream::Dispose() {
  DVLOG(1) << "OutgoingStream::Dispose() this=" << this;

  ResetPipe();
}

}  // namespace blink

"""

```
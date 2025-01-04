Response:
The user is asking for an analysis of the provided C++ source code file `web_transport.cc` from the Chromium Blink rendering engine. The request has several parts:

1. **Functionality:** List the functions of the code.
2. **Relation to Web Technologies:** Explain how it relates to JavaScript, HTML, and CSS, providing examples.
3. **Logical Inference:**  Illustrate logical deductions with assumed inputs and outputs.
4. **Common Usage Errors:**  Point out common mistakes users or programmers might make.
5. **User Operation Trace:** Describe how a user's actions might lead to this code being executed.
6. **Summary:** Provide a concise summary of the code's functionality.

This is part 1 of 2, so the focus should be on summarizing the functionality covered in the presented code snippet.

**Plan:**

1. **Identify Key Classes and Their Roles:** Analyze the code to understand the main classes (like `WebTransport`, `DatagramUnderlyingSink`, `DatagramUnderlyingSource`, `StreamVendingUnderlyingSource`, `ReceiveStreamVendor`, `BidirectionalStreamVendor`) and their responsibilities.
2. **Focus on WebTransport Functionality:** Concentrate on the methods and data members within the `WebTransport` class and how they manage the WebTransport connection and streams.
3. **Analyze Helper Classes:** Understand how the helper classes contribute to the overall functionality, particularly for handling datagrams and vending streams.
4. **Note Connections to Web APIs:**  Identify how the code interacts with Web APIs like `ReadableStream` and `WritableStream`.
5. **Defer Detailed Examples:** Since this is part 1, focus on general functionality and high-level relationships rather than detailed code examples or specific user actions.
6. **Summarize Part 1 Functionality:**  Synthesize the information into a concise summary of the code's purpose as represented in the provided snippet.
```
功能列表：

1. **WebTransport 连接的创建和初始化:**
   - `WebTransport::Create`: 静态方法，用于创建 `WebTransport` 对象。
   - `WebTransport::WebTransport`: 构造函数，初始化成员变量，例如 URL、Mojo 连接等。
   - `WebTransport::Init`:  初始化 WebTransport 连接，包括建立与网络服务的连接、处理握手等。

2. **发送和接收 Datagram (数据报):**
   - **发送:**
     - `WebTransport::DatagramUnderlyingSink`: 一个 `UnderlyingSinkBase` 的子类，用于处理通过 `WritableStream` 发送的数据报。
     - `DatagramUnderlyingSink::write`:  将 JavaScript 提供的 `ArrayBuffer` 或 `ArrayBufferView` 数据转换为可以发送的数据报。
     - `DatagramUnderlyingSink::SendDatagram`:  实际通过 Mojo 向网络服务发送数据报。
     - `DatagramUnderlyingSink::SendPendingDatagrams`: 在 WebTransport 连接建立后，发送之前缓存的待发送数据报。
   - **接收:**
     - `WebTransport::DatagramUnderlyingSource`: 一个 `UnderlyingByteSourceBase` 的子类，用于处理从网络服务接收到的数据报，并将其放入 `ReadableStream`。
     - `DatagramUnderlyingSource::OnDatagramReceived`:  接收来自网络服务的数据报，并将其添加到内部队列或直接传递给 `ReadableStream`。
     - `DatagramUnderlyingSource::Pull`:  当 JavaScript 请求读取数据时，从内部队列中取出数据报并传递给 `ReadableStreamController`。
     - `DatagramUnderlyingSource::MaybeExpireDatagrams`:  根据 `incomingMaxAge` 选项，定期检查并丢弃过期的接收数据报。

3. **创建和管理 Unidirectional Stream (单向流):**
   - `WebTransport::createUnidirectionalStream`:  允许 JavaScript 创建一个用于发送数据的单向流 (`WritableStream`)。
   - `WebTransport::OnCreateSendStreamResponse`:  处理创建发送流的响应，并将 `WritableStream` 连接到 Mojo 数据管道。
   - `WebTransport::incomingUnidirectionalStreams`: 提供一个 `ReadableStream`，用于接收来自服务器的单向流。
   - `WebTransport::ReceiveStreamVendor`:  一个 `StreamVendingUnderlyingSource::StreamVendor` 的子类，负责在需要时从网络服务请求新的接收单向流。
   - `ReceiveStreamVendor::OnAcceptUnidirectionalStreamResponse`: 处理接收单向流的响应，创建 `ReceiveStream` 对象，并将其添加到可读流中。

4. **创建和管理 Bidirectional Stream (双向流):**
   - `WebTransport::createBidirectionalStream`: 允许 JavaScript 创建一个双向流 (`BidirectionalStream`)，用于同时发送和接收数据。
   - `WebTransport::BidirectionalStreamVendor`: 一个 `StreamVendingUnderlyingSource::StreamVendor` 的子类，负责在需要时从网络服务请求新的双向流。
   - `BidirectionalStreamVendor::OnAcceptBidirectionalStreamResponse`: 处理接收双向流的响应，创建 `BidirectionalStream` 对象，并将其发送和接收端分别添加到对应的流映射中。

5. **管理连接状态:**
   - `ready_`: 一个 `ReadyProperty` 对象，表示 WebTransport 连接是否已建立。
   - `closed_`: 一个 `ScriptPromiseProperty` 对象，在连接关闭时 resolve，并提供关闭信息。

6. **内部数据结构:**
   - `incoming_stream_map_`:  存储接收到的流的映射，键是流 ID，值是 `ReceiveStream::IncomingStream` 或 `BidirectionalStream::IncomingStream`。
   - `outgoing_stream_map_`: 存储创建的发送流的映射，键是流 ID，值是 `SendStream` 或 `BidirectionalStream::OutgoingStream`。
   - `closed_potentially_pending_streams_`:  存储在网络服务中已关闭但在 Blink 中可能尚未完全处理的流的 ID。

7. **Mojo 接口:**
   - `transport_remote_`: 用于与网络服务进行通信的 Mojo 远程接口。
   - `handshake_client_receiver_`:  接收来自网络服务的握手消息的 Mojo 接收器。
   - `client_receiver_`:  接收来自网络服务的其他消息的 Mojo 接收器。

与 JavaScript, HTML, CSS 的功能关系：

* **JavaScript:**  `web_transport.cc` 实现了 WebTransport API 的核心逻辑，该 API 是通过 JavaScript 暴露给 Web 开发者的。JavaScript 代码会调用 `WebTransport` 对象的构造函数、`createUnidirectionalStream`、`createBidirectionalStream` 等方法来建立连接、创建流和发送/接收数据。例如：
    ```javascript
    const wt = new WebTransport("https://example.com");
    await wt.ready;

    // 发送数据报
    const writableDatagrams = wt.datagrams.writable;
    const writer = writableDatagrams.getWriter();
    writer.write(new Uint8Array([1, 2, 3]));
    writer.close();

    // 接收数据报
    const readableDatagrams = wt.datagrams.readable;
    const reader = readableDatagrams.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      console.log("Received datagram:", value);
    }

    // 创建单向流发送数据
    const sendStream = await wt.createUnidirectionalStream();
    const sendWriter = sendStream.getWriter();
    sendWriter.write(new TextEncoder().encode("Hello from client!"));
    sendWriter.close();

    // 接收单向流
    const readableStreams = wt.incomingUnidirectionalStreams;
    const streamReader = readableStreams.getReader();
    while (true) {
      const { value, done } = await streamReader.read();
      if (done) break;
      // 处理接收到的 ReceiveStream 对象
    }

    // 创建双向流
    const bidiStream = await wt.createBidirectionalStream();
    const bidiWriter = bidiStream.writable.getWriter();
    bidiWriter.write(new TextEncoder().encode("Message on bidi stream!"));
    bidiWriter.close();

    const bidiReader = bidiStream.readable.getReader();
    // ... 读取 bidiReader 的数据
    ```

* **HTML:** HTML 本身不直接与 `web_transport.cc` 交互。但是，HTML 中嵌入的 JavaScript 代码可以使用 WebTransport API。例如，一个网页的 `<script>` 标签内的 JavaScript 代码可以创建和使用 WebTransport 连接。

* **CSS:** CSS 与 `web_transport.cc` 没有直接关系。CSS 用于控制网页的样式和布局，而 WebTransport 专注于网络通信。

逻辑推理举例：

**假设输入：**

1. JavaScript 代码调用 `wt.createUnidirectionalStream()`。
2. `transport_remote_.is_bound()` 返回 `true` (连接已建立)。
3. `CreateStreamDataPipe` 成功创建了数据管道。

**输出：**

1. 创建一个新的 `ScriptPromiseResolver<WritableStream>` 对象。
2. 调用 `transport_remote_->CreateStream`，传递数据管道的 consumer handle。
3. `OnCreateSendStreamResponse` 回调函数会被调用，根据网络服务的响应创建 `WritableStream` 并 resolve promise。

**假设输入：**

1. 网络服务接收到一个新的单向流请求。
2. 调用 `client_receiver_->OnIncomingUnidirectionalStream` (假设这个方法在 `client_receiver_` 中，虽然代码片段中未完全展示)。

**输出：**

1. `WebTransport` 对象接收到流 ID 和可读数据管道的 handle。
2. `ReceiveStreamVendor::OnAcceptUnidirectionalStreamResponse` 被调用。
3. 创建一个新的 `ReceiveStream` 对象。
4. 新的 `ReceiveStream` 被添加到 `incomingUnidirectionalStreams()` 返回的 `ReadableStream` 中，使得 JavaScript 可以读取该流。

用户或编程常见的使用错误：

1. **在连接建立前尝试发送数据或创建流:**  如果在 `wt.ready` promise resolve 之前就尝试调用 `createUnidirectionalStream` 或发送数据报，会导致 `DOMExceptionCode::kNetworkError` 异常。
   ```javascript
   const wt = new WebTransport("https://example.com");
   // 错误：在连接就绪前尝试创建流
   wt.createUnidirectionalStream();
   await wt.ready;
   ```

2. **未正确处理流的关闭或错误:**  开发者可能没有正确监听和处理流的 `close` 或 `error` 事件，导致资源泄漏或程序行为异常。

3. **对已关闭的 WebTransport 连接进行操作:**  尝试在 `wt.closed` promise resolve 后继续使用该 `WebTransport` 对象可能会导致错误。

4. **数据报大小超出限制:**  虽然代码中没有明确限制，但网络协议或底层实现可能会对数据报的大小有限制。发送过大的数据报可能会失败。

5. **混淆 ReadableStream 和 WritableStream 的用途:**  尝试向接收单向流的 `ReadableStream` 写入数据，或者尝试从发送单向流的 `WritableStream` 读取数据。

用户操作是如何一步步的到达这里（作为调试线索）：

1. **用户在浏览器中访问一个网页。**
2. **网页的 JavaScript 代码中使用了 WebTransport API。** 例如，代码创建了一个 `WebTransport` 对象：
   ```javascript
   const wt = new WebTransport("https://example.com");
   ```
3. **浏览器开始建立与服务器的 WebTransport 连接。** 这会触发 Blink 引擎中 `WebTransport::Create` 和 `WebTransport::Init` 的执行。
4. **JavaScript 代码尝试发送数据报或创建流。** 例如：
   ```javascript
   wt.datagrams.writable.getWriter().write(new Uint8Array([1, 2, 3])); // 触发 DatagramUnderlyingSink::write
   await wt.createUnidirectionalStream(); // 触发 WebTransport::createUnidirectionalStream
   ```
5. **服务器向客户端发送数据报或创建流。** 这会导致网络栈接收数据，并最终传递到 Blink 引擎，触发 `DatagramUnderlyingSource::OnDatagramReceived` 或 `ReceiveStreamVendor::OnAcceptUnidirectionalStreamResponse` 等方法。

作为调试线索，开发者可以通过以下方式来定位问题：

* **查看浏览器的开发者工具的 "Network" (网络) 标签，** 检查 WebTransport 连接的状态和任何错误信息。
* **在 JavaScript 代码中设置断点，** 逐步执行代码，查看 `WebTransport` 对象的状态以及相关方法的调用。
* **在 `web_transport.cc` 中添加日志输出 (DVLOG)，**  跟踪代码的执行流程，观察关键变量的值。
* **使用 Chromium 的 tracing 工具，** 记录更底层的事件，例如 Mojo 消息的传递。

功能归纳 (Part 1):

`blink/renderer/modules/webtransport/web_transport.cc` 文件的主要功能是实现了 WebTransport API 的核心逻辑，用于在 Web 页面和服务器之间建立双向的、多路复用的连接。它处理了 WebTransport 连接的创建和初始化、数据报的发送和接收，以及单向和双向流的创建和管理。该文件通过与 JavaScript API 的绑定，使得 Web 开发者可以使用 WebTransport 技术进行实时的、低延迟的网络通信。 其核心在于管理与网络服务的 Mojo 连接，并利用 ReadableStream 和 WritableStream API 将网络数据流暴露给 JavaScript。
```
Prompt: 
```
这是目录为blink/renderer/modules/webtransport/web_transport.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webtransport/web_transport.h"

#include <stdint.h>

#include <optional>
#include <utility>

#include "base/numerics/safe_conversions.h"
#include "base/time/time.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_close_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_connection_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_datagram_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_error.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_hash.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_options.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/base_fetch_context.h"
#include "third_party/blink/renderer/core/loader/subresource_filter.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_request.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/core/streams/underlying_byte_source_base.h"
#include "third_party/blink/renderer/core/streams/underlying_sink_base.h"
#include "third_party/blink/renderer/core/streams/underlying_source_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/webtransport/bidirectional_stream.h"
#include "third_party/blink/renderer/modules/webtransport/datagram_duplex_stream.h"
#include "third_party/blink/renderer/modules/webtransport/receive_stream.h"
#include "third_party/blink/renderer/modules/webtransport/send_stream.h"
#include "third_party/blink/renderer/modules/webtransport/web_transport_error.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

// The incoming max age to to be used when datagrams.incomingMaxAge is set to
// null.
constexpr base::TimeDelta kDefaultIncomingMaxAge = base::Seconds(60);

// Creates a mojo DataPipe with the options we use for our stream data pipes. On
// success, returns true. On failure, throws an exception and returns false.
bool CreateStreamDataPipe(mojo::ScopedDataPipeProducerHandle* producer,
                          mojo::ScopedDataPipeConsumerHandle* consumer,
                          ExceptionState& exception_state) {
  MojoCreateDataPipeOptions options;
  options.struct_size = sizeof(MojoCreateDataPipeOptions);
  options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
  options.element_num_bytes = 1;
  // TODO(ricea): Find an appropriate value for capacity_num_bytes.
  options.capacity_num_bytes = 0;

  MojoResult result = mojo::CreateDataPipe(&options, *producer, *consumer);
  if (result != MOJO_RESULT_OK) {
    // Probably out of resources.
    exception_state.ThrowDOMException(DOMExceptionCode::kUnknownError,
                                      "Insufficient resources.");
    return false;
  }

  return true;
}

}  // namespace

// Sends a datagram on write().
class WebTransport::DatagramUnderlyingSink final : public UnderlyingSinkBase {
 public:
  DatagramUnderlyingSink(WebTransport* web_transport,
                         DatagramDuplexStream* datagrams)
      : web_transport_(web_transport), datagrams_(datagrams) {}

  ScriptPromise<IDLUndefined> start(ScriptState* script_state,
                                    WritableStreamDefaultController*,
                                    ExceptionState&) override {
    return ToResolvedUndefinedPromise(script_state);
  }

  ScriptPromise<IDLUndefined> write(ScriptState* script_state,
                                    ScriptValue chunk,
                                    WritableStreamDefaultController*,
                                    ExceptionState& exception_state) override {
    auto v8chunk = chunk.V8Value();
    auto* isolate = script_state->GetIsolate();

    if (v8chunk->IsArrayBuffer()) {
      DOMArrayBuffer* data = NativeValueTraits<DOMArrayBuffer>::NativeValue(
          isolate, v8chunk, exception_state);
      if (exception_state.HadException())
        return EmptyPromise();
      return SendDatagram(data->ByteSpan());
    }

    if (v8chunk->IsArrayBufferView()) {
      NotShared<DOMArrayBufferView> data =
          NativeValueTraits<NotShared<DOMArrayBufferView>>::NativeValue(
              isolate, v8chunk, exception_state);
      if (exception_state.HadException())
        return EmptyPromise();
      return SendDatagram(data->ByteSpan());
    }

    exception_state.ThrowTypeError(
        "Datagram is not an ArrayBuffer or ArrayBufferView type.");
    return EmptyPromise();
  }

  ScriptPromise<IDLUndefined> close(ScriptState* script_state,
                                    ExceptionState&) override {
    web_transport_ = nullptr;
    return ToResolvedUndefinedPromise(script_state);
  }

  ScriptPromise<IDLUndefined> abort(ScriptState* script_state,
                                    ScriptValue reason,
                                    ExceptionState&) override {
    web_transport_ = nullptr;
    return ToResolvedUndefinedPromise(script_state);
  }

  void SendPendingDatagrams() {
    DCHECK(web_transport_->transport_remote_.is_bound());
    for (const auto& datagram : pending_datagrams_) {
      web_transport_->transport_remote_->SendDatagram(
          base::make_span(datagram),
          WTF::BindOnce(&DatagramUnderlyingSink::OnDatagramProcessed,
                        WrapWeakPersistent(this)));
    }
    pending_datagrams_.clear();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(web_transport_);
    visitor->Trace(datagrams_);
    visitor->Trace(pending_datagrams_resolvers_);
    UnderlyingSinkBase::Trace(visitor);
  }

 private:
  ScriptPromise<IDLUndefined> SendDatagram(base::span<const uint8_t> data) {
    auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
        web_transport_->script_state_);
    // This resolver is for the return value of this function. When the
    // WebTransport is closed, the stream (for datagrams) is errored and
    // resolvers in `pending_datagrams_resolvers_` are released without
    // neither resolved nor rejected. That's fine, because the WritableStream
    // takes care of the case and reject all the pending promises when the
    // stream is errored. So we call SuppressDetachCheck here.
    resolver->SuppressDetachCheck();
    pending_datagrams_resolvers_.push_back(resolver);

    if (web_transport_->transport_remote_.is_bound()) {
      web_transport_->transport_remote_->SendDatagram(
          data, WTF::BindOnce(&DatagramUnderlyingSink::OnDatagramProcessed,
                              WrapWeakPersistent(this)));
    } else {
      Vector<uint8_t> datagram;
      datagram.AppendSpan(data);
      pending_datagrams_.push_back(std::move(datagram));
    }
    int high_water_mark = datagrams_->outgoingHighWaterMark();
    DCHECK_GT(high_water_mark, 0);
    if (pending_datagrams_resolvers_.size() <
        static_cast<wtf_size_t>(high_water_mark)) {
      // In this case we pretend that the datagram is processed immediately, to
      // get more requests from the stream.
      return ToResolvedUndefinedPromise(web_transport_->script_state_.Get());
    }
    return resolver->Promise();
  }

  void OnDatagramProcessed(bool sent) {
    DCHECK(!pending_datagrams_resolvers_.empty());
    pending_datagrams_resolvers_.TakeFirst()->Resolve();
  }

  Member<WebTransport> web_transport_;
  const Member<DatagramDuplexStream> datagrams_;
  Vector<Vector<uint8_t>> pending_datagrams_;
  HeapDeque<Member<ScriptPromiseResolver<IDLUndefined>>>
      pending_datagrams_resolvers_;
};

// Passes incoming datagrams to the datagrams.readable stream. It maintains its
// own internal queue of datagrams so that stale datagrams won't remain in
// ReadableStream's queue.
class WebTransport::DatagramUnderlyingSource final
    : public UnderlyingByteSourceBase {
 public:
  DatagramUnderlyingSource(ScriptState* script_state,
                           DatagramDuplexStream* datagram_duplex_stream)
      : UnderlyingByteSourceBase(),
        script_state_(script_state),
        datagram_duplex_stream_(datagram_duplex_stream),
        expiry_timer_(ExecutionContext::From(script_state)
                          ->GetTaskRunner(TaskType::kNetworking),
                      this,
                      &DatagramUnderlyingSource::ExpiryTimerFired) {}

  // Implementation of UnderlyingByteSourceBase.
  ScriptPromise<IDLUndefined> Pull(ReadableByteStreamController* controller,
                                   ExceptionState& exception_state) override {
    DVLOG(1) << "DatagramUnderlyingSource::pull()";

    if (waiting_for_datagrams_) {
      // This can happen if a second read is issued while a read is already
      // pending.
      DCHECK(queue_.empty());
      return ToResolvedUndefinedPromise(script_state_.Get());
    }

    // If high water mark is reset to 0 and then read() is called, it should
    // block waiting for a new datagram. So we may need to discard datagrams
    // here.
    DiscardExcessDatagrams();

    MaybeExpireDatagrams();

    if (queue_.empty()) {
      if (close_when_queue_empty_) {
        controller->close(script_state_, exception_state);
        return ToResolvedUndefinedPromise(script_state_.Get());
      }

      waiting_for_datagrams_ = true;
      return ToResolvedUndefinedPromise(script_state_.Get());
    }

    const QueueEntry* entry = queue_.front();
    queue_.pop_front();

    if (queue_.empty()) {
      expiry_timer_.Stop();
    }

    // This has to go after any mutations as it may run JavaScript, leading to
    // re-entry.
    controller->enqueue(script_state_,
                        NotShared<DOMUint8Array>(entry->datagram),
                        exception_state);
    if (exception_state.HadException()) {
      return ToResolvedUndefinedPromise(script_state_.Get());
    }

    // JavaScript could have called some other method at this point.
    // However, this is safe, because |close_when_queue_empty_| only ever
    // changes from false to true, and once it is true no more datagrams will
    // be added to |queue_|.
    if (close_when_queue_empty_ && queue_.empty()) {
      controller->close(script_state_, exception_state);
    }

    return ToResolvedUndefinedPromise(script_state_.Get());
  }

  ScriptPromise<IDLUndefined> Cancel() override {
    return Cancel(v8::Undefined(script_state_->GetIsolate()));
  }

  ScriptPromise<IDLUndefined> Cancel(v8::Local<v8::Value> reason) override {
    uint32_t code = 0;
    WebTransportError* exception =
        V8WebTransportError::ToWrappable(script_state_->GetIsolate(), reason);
    if (exception) {
      code = exception->streamErrorCode().value_or(0);
    }
    VLOG(1) << "DatagramUnderlyingSource::Cancel() with code " << code;

    waiting_for_datagrams_ = false;
    canceled_ = true;
    DiscardQueue();

    return ToResolvedUndefinedPromise(script_state_.Get());
  }

  ScriptState* GetScriptState() override { return script_state_.Get(); }

  // Interface for use by WebTransport.
  void Close(ReadableByteStreamController* controller,
             ExceptionState& exception_state) {
    DVLOG(1) << "DatagramUnderlyingSource::Close()";

    if (queue_.empty()) {
      controller->close(script_state_, exception_state);
    } else {
      close_when_queue_empty_ = true;
    }
  }

  void Error(ReadableByteStreamController* controller,
             v8::Local<v8::Value> error) {
    DVLOG(1) << "DatagramUnderlyingSource::Error()";

    waiting_for_datagrams_ = false;
    DiscardQueue();
    controller->error(script_state_,
                      ScriptValue(script_state_->GetIsolate(), error));
  }

  void OnDatagramReceived(ReadableByteStreamController* controller,
                          base::span<const uint8_t> data) {
    DVLOG(1) << "DatagramUnderlyingSource::OnDatagramReceived() size="
             << data.size();

    // We should not receive any datagrams after Close() was called.
    DCHECK(!close_when_queue_empty_);

    if (canceled_) {
      return;
    }

    DCHECK_GT(data.size(), 0u);

    // This fast path is expected to be hit frequently. Avoid the queue.
    if (waiting_for_datagrams_) {
      DCHECK(queue_.empty());
      waiting_for_datagrams_ = false;
      // This may run JavaScript, so it has to be called immediately before
      // returning to avoid confusion caused by re-entrant usage.
      ScriptState::Scope scope(script_state_);
      // |enqueue| and |respond| throw if close has been requested, stream state
      // is not readable, or buffer is invalid. We checked
      // |close_when_queue_empty_| and data.size() so stream is readable and
      // buffer size is not 0.
      // |respond| also throws if controller is undefined or destination's
      // buffer size is not large enough. Controller is defined because
      // the BYOB request is a property of the given controller. If
      // destination's buffer size is not large enough, stream is errored before
      // respond.
      NonThrowableExceptionState exception_state;

      if (ReadableStreamBYOBRequest* request = controller->byobRequest()) {
        DOMArrayPiece view(request->view().Get());
        // If the view supplied is not large enough, error the stream to avoid
        // splitting a datagram.
        if (view.ByteLength() < data.size()) {
          controller->error(
              script_state_,
              ScriptValue(script_state_->GetIsolate(),
                          V8ThrowException::CreateRangeError(
                              script_state_->GetIsolate(),
                              "supplied view is not large enough.")));
          return;
        }
        view.ByteSpan().copy_prefix_from(data);
        request->respond(script_state_, data.size(), exception_state);
        return;
      }

      auto* datagram = DOMUint8Array::Create(data);
      controller->enqueue(script_state_, NotShared(datagram), exception_state);
      return;
    }

    DiscardExcessDatagrams();

    auto high_water_mark = HighWaterMark();

    // A high water mark of 0 has the semantics that all datagrams are discarded
    // unless there is read pending. This might be useful to someone, so support
    // it.
    if (high_water_mark == 0) {
      DCHECK(queue_.empty());
      return;
    }

    if (queue_.size() == high_water_mark) {
      // Need to get rid of an entry for the new one to replace.
      queue_.pop_front();
      ++dropped_datagram_count_;
    }

    auto* datagram = DOMUint8Array::Create(data);
    auto now = base::TimeTicks::Now();
    queue_.push_back(MakeGarbageCollected<QueueEntry>(datagram, now));
    MaybeExpireDatagrams(now);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    visitor->Trace(queue_);
    visitor->Trace(datagram_duplex_stream_);
    visitor->Trace(expiry_timer_);
    UnderlyingByteSourceBase::Trace(visitor);
  }

  uint64_t dropped_datagram_count() const { return dropped_datagram_count_; }

 private:
  struct QueueEntry : GarbageCollected<QueueEntry> {
    QueueEntry(DOMUint8Array* datagram, base::TimeTicks received_time)
        : datagram(datagram), received_time(received_time) {}

    const Member<DOMUint8Array> datagram;
    const base::TimeTicks received_time;

    void Trace(Visitor* visitor) const { visitor->Trace(datagram); }
  };

  void DiscardExcessDatagrams() {
    DVLOG(1)
        << "DatagramUnderlyingSource::DiscardExcessDatagrams() queue_.size="
        << queue_.size();

    wtf_size_t high_water_mark = HighWaterMark();

    // The high water mark may have been set to a lower value, so the size can
    // be greater.
    while (queue_.size() > high_water_mark) {
      // TODO(ricea): Maybe free the memory associated with the array
      // buffer?
      queue_.pop_front();
      ++dropped_datagram_count_;
    }

    if (queue_.empty()) {
      DVLOG(1) << "DiscardExcessDatagrams: queue size now zero";
      expiry_timer_.Stop();
    }
  }

  void DiscardQueue() {
    queue_.clear();
    expiry_timer_.Stop();
  }

  void ExpiryTimerFired(TimerBase*) {
    DVLOG(1) << "DatagramUnderlyingSource::ExpiryTimerFired()";

    MaybeExpireDatagrams();
  }

  void MaybeExpireDatagrams() { MaybeExpireDatagrams(base::TimeTicks::Now()); }

  void MaybeExpireDatagrams(base::TimeTicks now) {
    DVLOG(1) << "DatagramUnderlyingSource::MaybeExpireDatagrams() now=" << now
             << " queue_.size=" << queue_.size();

    std::optional<double> optional_max_age =
        datagram_duplex_stream_->incomingMaxAge();
    bool max_age_is_default = false;
    base::TimeDelta max_age;
    if (optional_max_age.has_value()) {
      max_age = base::Milliseconds(optional_max_age.value());
    } else {
      max_age_is_default = true;
      max_age = kDefaultIncomingMaxAge;
    }

    DCHECK_GT(now, base::TimeTicks());

    // base::TimeTicks can take negative values, so this subtraction won't
    // underflow even if MaxAge() is huge.
    base::TimeTicks older_than = now - max_age;

    bool discarded = false;
    while (!queue_.empty() && queue_.front()->received_time < older_than) {
      discarded = true;
      queue_.pop_front();
    }

    if (discarded && max_age_is_default) {
      if (auto* execution_context = ExecutionContext::From(script_state_)) {
        execution_context->AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kNetwork,
                mojom::blink::ConsoleMessageLevel::kWarning,
                "Incoming datagram was discarded by WebTransport due to "
                "reaching default incomingMaxAge"),
            true);
      }
    }

    if (queue_.empty()) {
      DVLOG(1) << "MaybeExpireDatagrams queue is now empty";
      expiry_timer_.Stop();
      return;
    }

    base::TimeDelta age = now - queue_.front()->received_time;
    DCHECK_GE(max_age, age);
    base::TimeDelta time_until_next_expiry = max_age - age;

    // To reduce the number of wakeups, don't try to expire any more datagrams
    // for at least a second.
    if (time_until_next_expiry < base::Seconds(1)) {
      time_until_next_expiry = base::Seconds(1);
    }

    if (expiry_timer_.IsActive() &&
        expiry_timer_.NextFireInterval() <= time_until_next_expiry) {
      return;
    }

    expiry_timer_.StartOneShot(time_until_next_expiry, FROM_HERE);
  }

  wtf_size_t HighWaterMark() const {
    return base::checked_cast<wtf_size_t>(
        datagram_duplex_stream_->incomingHighWaterMark());
  }

  const Member<ScriptState> script_state_;
  HeapDeque<Member<const QueueEntry>> queue_;
  const Member<DatagramDuplexStream> datagram_duplex_stream_;
  HeapTaskRunnerTimer<DatagramUnderlyingSource> expiry_timer_;
  bool waiting_for_datagrams_ = false;
  bool canceled_ = false;
  bool close_when_queue_empty_ = false;
  uint64_t dropped_datagram_count_ = 0;
};

class WebTransport::StreamVendingUnderlyingSource final
    : public UnderlyingSourceBase {
 public:
  class StreamVendor : public GarbageCollected<StreamVendor> {
   public:
    using EnqueueCallback = base::OnceCallback<void(ScriptWrappable*)>;
    virtual void RequestStream(EnqueueCallback) = 0;
    virtual void Trace(Visitor*) const {}
  };

  template <class VendorType>
  static StreamVendingUnderlyingSource* CreateWithVendor(
      ScriptState* script_state,
      WebTransport* web_transport) {
    auto* vendor =
        MakeGarbageCollected<VendorType>(script_state, web_transport);
    return MakeGarbageCollected<StreamVendingUnderlyingSource>(script_state,
                                                               vendor);
  }

  StreamVendingUnderlyingSource(ScriptState* script_state, StreamVendor* vendor)
      : UnderlyingSourceBase(script_state),
        script_state_(script_state),
        vendor_(vendor) {}

  ScriptPromise<IDLUndefined> Pull(ScriptState* script_state,
                                   ExceptionState&) override {
    if (!is_opened_) {
      is_pull_waiting_ = true;
      return ToResolvedUndefinedPromise(script_state);
    }

    vendor_->RequestStream(WTF::BindOnce(
        &StreamVendingUnderlyingSource::Enqueue, WrapWeakPersistent(this)));

    return ToResolvedUndefinedPromise(script_state);
  }

  // Used by WebTransport to error the stream.
  void Error(v8::Local<v8::Value> reason) { Controller()->Error(reason); }

  // Used by WebTransport to close the stream.
  void Close() { Controller()->Close(); }

  // Used by WebTransport to notify that the WebTransport interface is
  // available.
  void NotifyOpened() {
    is_opened_ = true;

    if (is_pull_waiting_) {
      ScriptState::Scope scope(script_state_);
      NonThrowableExceptionState exception_state;
      Pull(script_state_, exception_state);
      is_pull_waiting_ = false;
    }
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    visitor->Trace(vendor_);
    UnderlyingSourceBase::Trace(visitor);
  }

 private:
  void Enqueue(ScriptWrappable* stream) {
    Controller()->Enqueue(
        ToV8Traits<ScriptWrappable>::ToV8(script_state_, stream));
  }

  const Member<ScriptState> script_state_;
  const Member<StreamVendor> vendor_;
  bool is_opened_ = false;
  bool is_pull_waiting_ = false;
};

class WebTransport::ReceiveStreamVendor final
    : public WebTransport::StreamVendingUnderlyingSource::StreamVendor {
 public:
  ReceiveStreamVendor(ScriptState* script_state, WebTransport* web_transport)
      : script_state_(script_state), web_transport_(web_transport) {}

  void RequestStream(EnqueueCallback enqueue) override {
    web_transport_->transport_remote_->AcceptUnidirectionalStream(WTF::BindOnce(
        &ReceiveStreamVendor::OnAcceptUnidirectionalStreamResponse,
        WrapWeakPersistent(this), std::move(enqueue)));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    visitor->Trace(web_transport_);
    StreamVendor::Trace(visitor);
  }

 private:
  void OnAcceptUnidirectionalStreamResponse(
      EnqueueCallback enqueue,
      uint32_t stream_id,
      mojo::ScopedDataPipeConsumerHandle readable) {
    ScriptState::Scope scope(script_state_);
    auto* receive_stream = MakeGarbageCollected<ReceiveStream>(
        script_state_, web_transport_, stream_id, std::move(readable));
    auto* isolate = script_state_->GetIsolate();
    v8::MicrotasksScope microtasks_scope(
        isolate, ToMicrotaskQueue(script_state_),
        v8::MicrotasksScope::kDoNotRunMicrotasks);
    v8::TryCatch try_catch(isolate);
    receive_stream->Init(PassThroughException(isolate));

    if (try_catch.HasCaught()) {
      // Abandon the stream.
      return;
    }

    // 0xfffffffe and 0xffffffff are reserved values in stream_map_.
    CHECK_LT(stream_id, 0xfffffffe);
    web_transport_->incoming_stream_map_.insert(
        stream_id, receive_stream->GetIncomingStream());

    auto it =
        web_transport_->closed_potentially_pending_streams_.find(stream_id);
    if (it != web_transport_->closed_potentially_pending_streams_.end()) {
      // The stream has already been closed in the network service.
      const bool fin_received = it->value;
      web_transport_->closed_potentially_pending_streams_.erase(it);

      // This can run JavaScript. This is safe because `receive_stream` hasn't
      // been exposed yet.
      receive_stream->GetIncomingStream()->OnIncomingStreamClosed(fin_received);
    }

    std::move(enqueue).Run(receive_stream);
  }

  const Member<ScriptState> script_state_;
  const Member<WebTransport> web_transport_;
};

class WebTransport::BidirectionalStreamVendor final
    : public WebTransport::StreamVendingUnderlyingSource::StreamVendor {
 public:
  BidirectionalStreamVendor(ScriptState* script_state,
                            WebTransport* web_transport)
      : script_state_(script_state), web_transport_(web_transport) {}

  void RequestStream(EnqueueCallback enqueue) override {
    web_transport_->transport_remote_->AcceptBidirectionalStream(WTF::BindOnce(
        &BidirectionalStreamVendor::OnAcceptBidirectionalStreamResponse,
        WrapWeakPersistent(this), std::move(enqueue)));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    visitor->Trace(web_transport_);
    StreamVendor::Trace(visitor);
  }

 private:
  void OnAcceptBidirectionalStreamResponse(
      EnqueueCallback enqueue,
      uint32_t stream_id,
      mojo::ScopedDataPipeConsumerHandle incoming_consumer,
      mojo::ScopedDataPipeProducerHandle outgoing_producer) {
    ScriptState::Scope scope(script_state_);
    auto* bidirectional_stream = MakeGarbageCollected<BidirectionalStream>(
        script_state_, web_transport_, stream_id, std::move(outgoing_producer),
        std::move(incoming_consumer));

    auto* isolate = script_state_->GetIsolate();
    v8::MicrotasksScope microtasks_scope(
        isolate, ToMicrotaskQueue(script_state_),
        v8::MicrotasksScope::kDoNotRunMicrotasks);
    v8::TryCatch try_catch(isolate);
    bidirectional_stream->Init(PassThroughException(isolate));
    if (try_catch.HasCaught()) {
      // Just throw away the stream.
      return;
    }

    // 0xfffffffe and 0xffffffff are reserved values in stream_map_.
    CHECK_LT(stream_id, 0xfffffffe);
    web_transport_->incoming_stream_map_.insert(
        stream_id, bidirectional_stream->GetIncomingStream());
    web_transport_->outgoing_stream_map_.insert(
        stream_id, bidirectional_stream->GetOutgoingStream());

    auto it =
        web_transport_->closed_potentially_pending_streams_.find(stream_id);
    if (it != web_transport_->closed_potentially_pending_streams_.end()) {
      // The stream has already been closed in the network service.
      const bool fin_received = it->value;
      web_transport_->closed_potentially_pending_streams_.erase(it);

      // This can run JavaScript. This is safe because `receive_stream` hasn't
      // been exposed yet.
      bidirectional_stream->GetIncomingStream()->OnIncomingStreamClosed(
          fin_received);
    }

    std::move(enqueue).Run(bidirectional_stream);
  }

  const Member<ScriptState> script_state_;
  const Member<WebTransport> web_transport_;
};

WebTransport* WebTransport::Create(ScriptState* script_state,
                                   const String& url,
                                   WebTransportOptions* options,
                                   ExceptionState& exception_state) {
  DVLOG(1) << "WebTransport::Create() url=" << url;
  DCHECK(options);
  UseCounter::Count(ExecutionContext::From(script_state),
                    WebFeature::kWebTransport);
  auto* transport =
      MakeGarbageCollected<WebTransport>(PassKey(), script_state, url);
  transport->Init(url, *options, exception_state);
  return transport;
}

WebTransport::WebTransport(PassKey,
                           ScriptState* script_state,
                           const String& url)
    : WebTransport(script_state, url, ExecutionContext::From(script_state)) {}

WebTransport::WebTransport(ScriptState* script_state,
                           const String& url,
                           ExecutionContext* context)
    : ActiveScriptWrappable<WebTransport>({}),
      ExecutionContextLifecycleObserver(context),
      script_state_(script_state),
      url_(NullURL(), url),
      connector_(context),
      transport_remote_(context),
      handshake_client_receiver_(this, context),
      client_receiver_(this, context),
      ready_(MakeGarbageCollected<ReadyProperty>(context)),
      closed_(MakeGarbageCollected<
              ScriptPromiseProperty<WebTransportCloseInfo, IDLAny>>(context)),
      inspector_transport_id_(CreateUniqueIdentifier()) {}

ScriptPromise<WritableStream> WebTransport::createUnidirectionalStream(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DVLOG(1) << "WebTransport::createUnidirectionalStream() this=" << this;

  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kQuicTransportStreamApis);
  if (!transport_remote_.is_bound()) {
    // TODO(ricea): Should we wait if we're still connecting?
    exception_state.ThrowDOMException(DOMExceptionCode::kNetworkError,
                                      "No connection.");
    return EmptyPromise();
  }

  mojo::ScopedDataPipeProducerHandle data_pipe_producer;
  mojo::ScopedDataPipeConsumerHandle data_pipe_consumer;

  if (!CreateStreamDataPipe(&data_pipe_producer, &data_pipe_consumer,
                            exception_state)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<WritableStream>>(
      script_state, exception_state.GetContext());
  create_stream_resolvers_.insert(resolver);
  transport_remote_->CreateStream(
      std::move(data_pipe_consumer), mojo::ScopedDataPipeProducerHandle(),
      WTF::BindOnce(&WebTransport::OnCreateSendStreamResponse,
                    WrapWeakPersistent(this), WrapWeakPersistent(resolver),
                    std::move(data_pipe_producer)));

  return resolver->Promise();
}

ReadableStream* WebTransport::incomingUnidirectionalStreams() {
  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kQuicTransportStreamApis);
  return received_streams_;
}

ScriptPromise<BidirectionalStream> WebTransport::createBidirectionalStream(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DVLOG(1) << "WebTransport::createBidirectionalStream() this=" << this;

  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kQuicTransportStreamApis);
  if (!transport_remote_.is_bound()) {
    // TODO(ricea): We should wait if we are still connecting.
    exception_state.ThrowDOMException(DOMExceptionCode::kNetworkError,
                                      "No connection.");
    return EmptyPromise();
  }

  mojo::ScopedDataPipeProducerHandle outgoing_producer;
  mojo::ScopedDataPipeConsumerHandle outgoing_consumer;
  if (!CreateStreamDataPipe(&outgoing_producer, &outgoing_consumer,
                            exception_state)) {
    return EmptyPromise();
  }

  mojo::ScopedDataPipeProducerHandle incoming_producer;
  mojo::ScopedDataPipeConsumerHandle incoming_consumer;
  if (!CreateStreamDataPipe(&incoming_producer, &incoming_consumer,
                            excep
"""


```
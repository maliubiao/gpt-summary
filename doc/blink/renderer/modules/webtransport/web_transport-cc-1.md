Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_transport.cc`. I need to identify the core features implemented in this part of the file and relate them to web technologies like JavaScript, HTML, and CSS if applicable. I also need to look for examples of logical reasoning, potential user errors, and how a user might reach this code through their actions in a browser.

Here's a plan:

1. **Identify Core Functions:** Go through each method in the provided snippet and understand its purpose.
2. **Relate to Web Technologies:** Determine if the functionality directly interacts with or is exposed to JavaScript, HTML, or CSS. Provide concrete examples if a relationship exists.
3. **Analyze Logic and Data Flow:** Look for decision-making processes and data transformations within the functions. Formulate simple "input -> output" scenarios to illustrate the logic.
4. **Identify Potential User Errors:** Think about how a developer using the WebTransport API in JavaScript might misuse the provided functionality, leading to errors.
5. **Trace User Actions:**  Describe a sequence of user interactions in a web browser that would eventually lead to the execution of code within this snippet.
6. **Summarize Functionality:** Condense the identified features into a concise summary.
这是对 `blink/renderer/modules/webtransport/web_transport.cc` 文件部分代码的功能归纳，主要涵盖了 WebTransport API 中关于流（Streams）、数据报（Datagrams）、连接管理以及统计信息获取的功能。

**功能归纳：**

1. **创建和管理双向流 (Bidirectional Streams):**
    *   `createBidirectionalStream(exception_state)`:  允许 JavaScript 代码创建一个新的双向流。
    *   该方法会创建一个 `ScriptPromise`，当流成功建立时，Promise 将会 resolve 并返回 `BidirectionalStream` 对象。
    *   内部通过 `transport_remote_->CreateStream` 向网络层发送创建流的请求。
    *   使用 `create_stream_resolvers_` 来管理待处理的 Promise resolver。
    *   `OnCreateBidirectionalStreamResponse`:  处理来自网络层的双向流创建响应，成功则 resolve 对应的 Promise，失败则 reject。

2. **获取接收到的双向流:**
    *   `incomingBidirectionalStreams()`: 返回一个 `ReadableStream` 对象，用于读取远程端创建的并发送过来的双向流。这个流在 JavaScript 中可以通过监听 "readable" 事件来处理接收到的数据。

3. **获取和管理数据报 (Datagrams):**
    *   `datagrams()`: 返回一个 `DatagramDuplexStream` 对象，用于发送和接收数据报。
    *   `datagramWritable()`: 返回一个 `WritableStream` 对象，用于向远程端发送数据报。
    *   `datagramReadable()`: 返回一个 `ReadableStream` 对象，用于接收远程端发送过来的数据报。
    *   `setDatagramWritableQueueExpirationDuration(double duration)`: 设置发送数据报的过期时间。如果数据报在指定时间内未发送，则会被丢弃。

4. **关闭 WebTransport 连接:**
    *   `close(WebTransportCloseInfo* close_info)`: 允许 JavaScript 代码关闭 WebTransport 连接。
    *   如果连接正在建立中，则会立即清理并 reject `ready_` Promise。
    *   如果连接已建立，则会向网络层发送关闭请求 (`transport_remote_->Close`)，并执行清理操作 `Cleanup`。

5. **获取连接状态相关的 Promise:**
    *   `ready(ScriptState* script_state)`: 返回一个 `ScriptPromise`，当 WebTransport 连接成功建立后 resolve。
    *   `closed(ScriptState* script_state)`: 返回一个 `ScriptPromise`，当 WebTransport 连接关闭后 resolve，并携带关闭信息 `WebTransportCloseInfo`。

6. **获取连接统计信息:**
    *   `getStats(ScriptState* script_state)`: 返回一个 `ScriptPromise`，resolve 后会提供 `WebTransportConnectionStats` 对象，包含 RTT、丢包等统计信息。
    *   如果连接尚未建立或已失败，则会 reject Promise 并抛出 `InvalidStateError`。
    *   使用 `pending_get_stats_resolvers_` 管理待处理的 Promise resolver。
    *   `OnGetStatsResponse`: 处理来自网络层的统计信息响应，并 resolve 相应的 Promise。
    *   `ConvertStatsFromMojom`: 将从 Mojo 层接收到的统计信息转换为 JavaScript 可用的 `WebTransportConnectionStats` 对象。

7. **处理连接建立成功的事件:**
    *   `OnConnectionEstablished(...)`:  当网络层报告连接建立成功时调用。
    *   绑定网络层的 `WebTransport` 接口和客户端接口。
    *   初始化数据报和流相关的底层源和接收器。
    *   resolve `ready_` Promise，并通知等待统计信息的 Promise resolver。

8. **处理握手失败事件:**
    *   `OnHandshakeFailed(...)`: 当 WebTransport 握手失败时调用。会清理连接并 reject 相关的 Promise。

9. **处理接收到的数据报:**
    *   `OnDatagramReceived(base::span<const uint8_t> data)`: 当从网络层接收到数据报时调用，将数据传递给 `received_datagrams_controller_` 以供 JavaScript 读取。

10. **处理接收到的流关闭事件:**
    *   `OnIncomingStreamClosed(uint32_t stream_id, bool fin_received)`: 当接收到远程端关闭流的信号时调用。
    *   查找对应的 `IncomingStream` 对象并通知其关闭。
    *   对于服务器端创建的流，如果尚未创建，则会记录流 ID 和 FIN 状态，以便稍后处理。

11. **处理接收到的流重置 (RESET_STREAM) 事件:**
    *   `OnReceivedResetStream(uint32_t stream_id, uint32_t stream_error_code)`: 当接收到远程端发送的流重置信号时调用。查找对应的 `IncomingStream` 并通知其发生错误。

12. **处理接收到的停止发送 (STOP_SENDING) 事件:**
    *   `OnReceivedStopSending(uint32_t stream_id, uint32_t stream_error_code)`: 当接收到远程端请求停止发送数据的信号时调用。查找对应的 `OutgoingStream` 并通知其发生错误。

13. **处理连接关闭事件:**
    *   `OnClosed(...)`: 当网络层通知连接已关闭时调用。
    *   更新最终的统计信息，创建 `WebTransportCloseInfo` 对象，并执行清理操作。
    *   resolve `closed_` Promise。

14. **处理发出的流关闭事件:**
    *   `OnOutgoingStreamClosed(uint32_t stream_id)`: 当本地发出的流被关闭时调用，清理 `outgoing_stream_map_` 中对应的条目。

15. **生命周期管理:**
    *   `ContextDestroyed()`: 当关联的渲染上下文被销毁时调用，负责清理和释放资源。
    *   `HasPendingActivity()`: 检查是否有待处理的网络活动。
    *   `Dispose()`:  释放资源，包括 Mojo 接口。

16. **控制流的状态:**
    *   `SendFin(uint32_t stream_id)`: 向网络层发送指定流的 FIN 信号，表示本地不再发送数据。
    *   `ResetStream(uint32_t stream_id, uint32_t code)`: 向网络层发送指定流的 RST 信号，表示流发生错误需要重置。
    *   `StopSending(uint32_t stream_id, uint32_t code)`: 向网络层发送请求停止向指定流发送数据的信号。
    *   `ForgetIncomingStream(uint32_t stream_id)`: 从内部映射中移除对接收到的流的跟踪。
    *   `ForgetOutgoingStream(uint32_t stream_id)`: 从内部映射中移除对发出的流的跟踪。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:**
    *   这些 C++ 代码是 WebTransport API 的底层实现，直接服务于 JavaScript 中 `WebTransport` 接口的使用。
    *   例如，`createBidirectionalStream` 方法对应 JavaScript 中调用 `WebTransport` 对象的 `createBidirectionalStream()` 方法。
    *   返回的 `ReadableStream` 和 `WritableStream` 对象可以直接在 JavaScript 中使用标准的 Stream API 进行数据读写。
    *   `ready()` 和 `closed()` 方法返回的 Promise 会在 JavaScript 中被 then 或者 await，以处理连接状态。
    *   `getStats()` 方法返回的 Promise 在 JavaScript 中 resolve 后，可以获取连接的统计信息。

*   **HTML:**
    *   HTML 本身不直接与这段代码交互。但是，包含创建和使用 `WebTransport` 对象的 JavaScript 代码会被嵌入到 HTML 文件中通过 `<script>` 标签加载和执行。

*   **CSS:**
    *   CSS 与这段代码的功能没有直接关系。

**逻辑推理的例子：**

假设输入：JavaScript 代码调用 `webTransport.createBidirectionalStream()`。

1. `createBidirectionalStream` 方法被调用。
2. 创建一个 `ScriptPromiseResolver` 并添加到 `create_stream_resolvers_`。
3. 调用 `transport_remote_->CreateStream` 向网络层发送创建流的请求。
4. 网络层处理请求并返回响应。
5. `OnCreateBidirectionalStreamResponse` 方法被调用，携带创建结果和流 ID。
6. 如果创建成功，则创建一个 `BidirectionalStream` 对象，将其关联的 `ReadableStream` 和 `WritableStream` 放入对应的映射中，并 resolve 之前创建的 Promise，将 `BidirectionalStream` 对象返回给 JavaScript。
7. 如果创建失败，则 reject 之前创建的 Promise，JavaScript 代码可以通过 Promise 的 catch 方法捕获错误。

**用户或编程常见的使用错误举例：**

1. **在连接建立完成前尝试创建流或发送数据报:** 用户可能会在 `webTransport.ready` Promise resolve 之前就尝试调用 `createBidirectionalStream()` 或通过 `datagramWritable()` 发送数据。 这会导致操作失败或抛出异常，因为底层的网络连接尚未就绪。

    ```javascript
    const transport = new WebTransport("https://example.com");
    transport.createBidirectionalStream(); // 潜在错误：连接可能尚未建立
    transport.datagramWritable.getWriter().write(new Uint8Array([1, 2, 3])); // 潜在错误：连接可能尚未建立

    transport.ready.then(() => {
      transport.createBidirectionalStream(); // 安全
      transport.datagramWritable.getWriter().write(new Uint8Array([1, 2, 3])); // 安全
    });
    ```

2. **未正确处理 `closed` Promise:** 用户可能没有正确监听 `closed` Promise 的 resolve 或 reject，导致连接关闭时没有执行必要的清理或错误处理。

    ```javascript
    const transport = new WebTransport("https://example.com");
    transport.closed.then(info => {
      console.log("连接已关闭，关闭代码：", info.closeCode, "原因：", info.reason);
    }).catch(error => {
      console.error("连接关闭出现错误：", error);
    });

    // 如果没有 .catch，连接异常关闭时可能不会被捕获。
    ```

3. **在连接已关闭后尝试操作:** 用户可能会在 `closed` Promise resolve 或 reject 后，仍然尝试创建流、发送数据报或获取统计信息，这会导致 `InvalidStateError` 或其他错误。

    ```javascript
    const transport = new WebTransport("https://example.com");
    transport.closed.then(() => {
      transport.createBidirectionalStream(); // 错误：连接已关闭
    });
    ```

**用户操作到达这里的步骤（调试线索）：**

1. 用户在浏览器中打开一个网页。
2. 网页的 JavaScript 代码中使用了 `WebTransport` API，例如：
    ```javascript
    const transport = new WebTransport("https://example.com");
    transport.ready.then(() => {
      transport.createBidirectionalStream();
      transport.datagramWritable.getWriter().write(new Uint8Array([1, 2, 3]));
      transport.getStats().then(stats => console.log(stats));
      transport.close();
    });
    ```
3. 当 JavaScript 执行到创建 `WebTransport` 对象时，Blink 引擎会创建对应的 `WebTransport` C++ 对象。
4. 当调用 `transport.createBidirectionalStream()` 时，会执行 `WebTransport::createBidirectionalStream()` 方法。
5. 当调用 `transport.datagramWritable` 时，会返回 `WebTransport::datagramWritable()` 返回的 `WritableStream` 对象。
6. 当调用 `transport.getStats()` 时，会执行 `WebTransport::getStats()` 方法。
7. 当调用 `transport.close()` 时，会执行 `WebTransport::close()` 方法。
8. 如果在连接过程中发生网络事件（例如，连接建立成功、接收到数据报、连接关闭等），网络层会调用 `WebTransport` 对象相应的回调方法（例如，`OnConnectionEstablished`、`OnDatagramReceived`、`OnClosed` 等）。

通过在这些 C++ 方法中设置断点，或者使用日志输出 (`DVLOG`)，开发者可以追踪 WebTransport 连接的状态和数据流，从而进行调试。

### 提示词
```
这是目录为blink/renderer/modules/webtransport/web_transport.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
tion_state)) {
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<BidirectionalStream>>(
          script_state, exception_state.GetContext());
  create_stream_resolvers_.insert(resolver);
  transport_remote_->CreateStream(
      std::move(outgoing_consumer), std::move(incoming_producer),
      WTF::BindOnce(&WebTransport::OnCreateBidirectionalStreamResponse,
                    WrapWeakPersistent(this), WrapWeakPersistent(resolver),
                    std::move(outgoing_producer),
                    std::move(incoming_consumer)));

  return resolver->Promise();
}

ReadableStream* WebTransport::incomingBidirectionalStreams() {
  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kQuicTransportStreamApis);
  return received_bidirectional_streams_;
}

DatagramDuplexStream* WebTransport::datagrams() {
  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kQuicTransportDatagramApis);
  return datagrams_;
}

WritableStream* WebTransport::datagramWritable() {
  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kQuicTransportDatagramApis);
  return outgoing_datagrams_;
}

ReadableStream* WebTransport::datagramReadable() {
  UseCounter::Count(GetExecutionContext(),
                    WebFeature::kQuicTransportDatagramApis);
  return received_datagrams_;
}

void WebTransport::close(WebTransportCloseInfo* close_info) {
  DVLOG(1) << "WebTransport::close() this=" << this;
  v8::Isolate* isolate = script_state_->GetIsolate();
  if (!connector_.is_bound() && !transport_remote_.is_bound()) {
    // This session has been closed or errored.
    return;
  }

  if (!transport_remote_.is_bound()) {
    // The state is "connecting".
    v8::Local<v8::Value> error =
        WebTransportError::Create(isolate, /*stream_error_code=*/std::nullopt,
                                  "close() is called while connecting.",
                                  V8WebTransportErrorSource::Enum::kSession);
    Cleanup(nullptr, error, /*abruptly=*/true);
    return;
  }

  v8::Local<v8::Value> error = WebTransportError::Create(
      isolate, /*stream_error_code=*/std::nullopt, "The session is closed.",
      V8WebTransportErrorSource::Enum::kSession);

  network::mojom::blink::WebTransportCloseInfoPtr close_info_to_pass;
  if (close_info) {
    close_info_to_pass = network::mojom::blink::WebTransportCloseInfo::New(
        close_info->closeCode(), close_info->reason());
  }

  transport_remote_->Close(std::move(close_info_to_pass));

  Cleanup(close_info ? close_info : WebTransportCloseInfo::Create(), error,
          /*abruptly=*/false);
}

void WebTransport::setDatagramWritableQueueExpirationDuration(double duration) {
  outgoing_datagram_expiration_duration_ = base::Milliseconds(duration);
  if (transport_remote_.is_bound()) {
    transport_remote_->SetOutgoingDatagramExpirationDuration(
        outgoing_datagram_expiration_duration_);
  }
}

ScriptPromise<IDLUndefined> WebTransport::ready(ScriptState* script_state) {
  return ready_->Promise(script_state->World());
}

ScriptPromise<WebTransportCloseInfo> WebTransport::closed(
    ScriptState* script_state) {
  return closed_->Promise(script_state->World());
}

ScriptPromise<WebTransportConnectionStats> WebTransport::getStats(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<WebTransportConnectionStats>>(
          script_state);
  if (!transport_remote_.is_bound() && !connection_pending_) {
    auto promise = resolver->Promise();
    if (latest_stats_) {
      resolver->Resolve(latest_stats_);
    } else {
      resolver->RejectWithDOMException(
          DOMExceptionCode::kInvalidStateError,
          "Cannot retreive stats on a failed connection.");
    }
    return promise;
  }

  const bool request_already_sent = !pending_get_stats_resolvers_.empty();
  pending_get_stats_resolvers_.push_back(resolver);
  if (transport_remote_.is_bound() && !request_already_sent) {
    transport_remote_->GetStats(WTF::BindOnce(&WebTransport::OnGetStatsResponse,
                                              WrapWeakPersistent(this)));
  }
  return resolver->Promise();
}

void WebTransport::OnConnectionEstablished(
    mojo::PendingRemote<network::mojom::blink::WebTransport> web_transport,
    mojo::PendingReceiver<network::mojom::blink::WebTransportClient>
        client_receiver,
    network::mojom::blink::HttpResponseHeadersPtr response_headers,
    network::mojom::blink::WebTransportStatsPtr initial_stats) {
  DVLOG(1) << "WebTransport::OnConnectionEstablished() this=" << this;
  connector_.reset();
  handshake_client_receiver_.reset();

  probe::WebTransportConnectionEstablished(GetExecutionContext(),
                                           inspector_transport_id_);

  auto task_runner =
      GetExecutionContext()->GetTaskRunner(TaskType::kNetworking);

  client_receiver_.Bind(std::move(client_receiver), task_runner);
  client_receiver_.set_disconnect_handler(WTF::BindOnce(
      &WebTransport::OnConnectionError, WrapWeakPersistent(this)));

  DCHECK(!transport_remote_.is_bound());
  transport_remote_.Bind(std::move(web_transport), task_runner);

  if (outgoing_datagram_expiration_duration_ != base::TimeDelta()) {
    transport_remote_->SetOutgoingDatagramExpirationDuration(
        outgoing_datagram_expiration_duration_);
  }

  latest_stats_ = ConvertStatsFromMojom(std::move(initial_stats));

  datagram_underlying_sink_->SendPendingDatagrams();

  received_streams_underlying_source_->NotifyOpened();
  received_bidirectional_streams_underlying_source_->NotifyOpened();

  connection_pending_ = false;
  ready_->ResolveWithUndefined();

  HeapVector<Member<ScriptPromiseResolver<WebTransportConnectionStats>>>
      stats_resolvers;
  pending_get_stats_resolvers_.swap(stats_resolvers);
  for (auto& resolver : stats_resolvers) {
    resolver->Resolve(latest_stats_);
  }
}

WebTransport::~WebTransport() = default;

void WebTransport::OnHandshakeFailed(
    network::mojom::blink::WebTransportErrorPtr error) {
  // |error| should be null from security/privacy reasons.
  DCHECK(!error);
  DVLOG(1) << "WebTransport::OnHandshakeFailed() this=" << this;
  ScriptState::Scope scope(script_state_);
  v8::Local<v8::Value> error_to_pass = WebTransportError::Create(
      script_state_->GetIsolate(),
      /*stream_error_code=*/std::nullopt, "Opening handshake failed.",
      V8WebTransportErrorSource::Enum::kSession);
  Cleanup(nullptr, error_to_pass, /*abruptly=*/true);
}

void WebTransport::OnDatagramReceived(base::span<const uint8_t> data) {
  datagram_underlying_source_->OnDatagramReceived(
      received_datagrams_controller_, data);
}

void WebTransport::OnIncomingStreamClosed(uint32_t stream_id,
                                          bool fin_received) {
  DVLOG(1) << "WebTransport::OnIncomingStreamClosed(" << stream_id << ", "
           << fin_received << ") this=" << this;
  auto it = incoming_stream_map_.find(stream_id);

  if (it == incoming_stream_map_.end()) {
    // We reach here from two reasons.
    // 1) The stream may have already been removed from the map because of races
    //    between different ways of closing bidirectional streams.
    // 2) The stream is a server created incoming stream, and we haven't created
    //    it yet.
    // For the second case, we need to store `stream_id` and `fin_received` and
    // dispatch them later.
    DCHECK(closed_potentially_pending_streams_.find(stream_id) ==
           closed_potentially_pending_streams_.end());
    closed_potentially_pending_streams_.insert(stream_id, fin_received);
    return;
  }

  IncomingStream* stream = it->value;
  stream->OnIncomingStreamClosed(fin_received);
}

void WebTransport::OnReceivedResetStream(uint32_t stream_id,
                                         uint32_t stream_error_code) {
  DVLOG(1) << "WebTransport::OnReceivedResetStream(" << stream_id << ", "
           << stream_error_code << ") this=" << this;
  auto it = incoming_stream_map_.find(stream_id);
  if (it == incoming_stream_map_.end()) {
    return;
  }
  IncomingStream* stream = it->value;

  ScriptState::Scope scope(script_state_);
  v8::Local<v8::Value> error = WebTransportError::Create(
      script_state_->GetIsolate(), stream_error_code, "Received RESET_STREAM.",
      V8WebTransportErrorSource::Enum::kStream);
  stream->Error(ScriptValue(script_state_->GetIsolate(), error));
}

void WebTransport::OnReceivedStopSending(uint32_t stream_id,
                                         uint32_t stream_error_code) {
  DVLOG(1) << "WebTransport::OnReceivedStopSending(" << stream_id << ", "
           << stream_error_code << ") this=" << this;

  auto it = outgoing_stream_map_.find(stream_id);
  if (it == outgoing_stream_map_.end()) {
    return;
  }
  OutgoingStream* stream = it->value;

  ScriptState::Scope scope(script_state_);
  v8::Local<v8::Value> error = WebTransportError::Create(
      script_state_->GetIsolate(), stream_error_code, "Received STOP_SENDING.",
      V8WebTransportErrorSource::Enum::kStream);
  stream->Error(ScriptValue(script_state_->GetIsolate(), error));
}

void WebTransport::OnClosed(
    network::mojom::blink::WebTransportCloseInfoPtr close_info,
    network::mojom::blink::WebTransportStatsPtr final_stats) {
  ScriptState::Scope scope(script_state_);
  v8::Isolate* isolate = script_state_->GetIsolate();

  latest_stats_ = ConvertStatsFromMojom(std::move(final_stats));

  auto* idl_close_info = MakeGarbageCollected<WebTransportCloseInfo>();
  if (close_info) {
    idl_close_info->setCloseCode(close_info->code);
    idl_close_info->setReason(close_info->reason);
  }

  v8::Local<v8::Value> error = WebTransportError::Create(
      isolate, /*stream_error_code=*/std::nullopt, "The session is closed.",
      V8WebTransportErrorSource::Enum::kSession);

  Cleanup(idl_close_info, error, /*abruptly=*/false);
}

void WebTransport::OnOutgoingStreamClosed(uint32_t stream_id) {
  DVLOG(1) << "WebTransport::OnOutgoingStreamClosed(" << stream_id
           << ") this=" << this;
  auto it = outgoing_stream_map_.find(stream_id);

  // If a close is aborted, we may get the close response on a stream we've
  // already erased.
  if (it == outgoing_stream_map_.end())
    return;

  OutgoingStream* stream = it->value;
  DCHECK(stream);

  // We do this deletion first because OnOutgoingStreamClosed may run JavaScript
  // and so modify |outgoing_stream_map_|. |stream| is kept alive by being on
  // the stack.
  outgoing_stream_map_.erase(it);

  stream->OnOutgoingStreamClosed();
}

void WebTransport::ContextDestroyed() {
  DVLOG(1) << "WebTransport::ContextDestroyed() this=" << this;
  // Child streams must be reset first to ensure that garbage collection
  // ordering is safe. ContextDestroyed() is required not to execute JavaScript,
  // so this loop will not be re-entered.
  for (IncomingStream* stream : incoming_stream_map_.Values()) {
    stream->ContextDestroyed();
  }
  for (OutgoingStream* stream : outgoing_stream_map_.Values()) {
    stream->ContextDestroyed();
  }
  Dispose();
}

bool WebTransport::HasPendingActivity() const {
  DVLOG(1) << "WebTransport::HasPendingActivity() this=" << this;
  return handshake_client_receiver_.is_bound() || client_receiver_.is_bound();
}

void WebTransport::SendFin(uint32_t stream_id) {
  DVLOG(1) << "WebTransport::SendFin() this=" << this
           << ", stream_id=" << stream_id;
  transport_remote_->SendFin(stream_id);
}

void WebTransport::ResetStream(uint32_t stream_id, uint32_t code) {
  VLOG(0) << "WebTransport::ResetStream(" << stream_id << ", "
          << static_cast<uint32_t>(code) << ") this = " << this;
  transport_remote_->AbortStream(stream_id, code);
}

void WebTransport::StopSending(uint32_t stream_id, uint32_t code) {
  DVLOG(1) << "WebTransport::StopSending(" << stream_id << ", " << code
           << ") this = " << this;
  transport_remote_->StopSending(stream_id, code);
}

void WebTransport::ForgetIncomingStream(uint32_t stream_id) {
  DVLOG(1) << "WebTransport::ForgetIncomingStream() this=" << this
           << ", stream_id=" << stream_id;
  incoming_stream_map_.erase(stream_id);
}

void WebTransport::ForgetOutgoingStream(uint32_t stream_id) {
  DVLOG(1) << "WebTransport::ForgetOutgoingStream() this=" << this
           << ", stream_id=" << stream_id;
  outgoing_stream_map_.erase(stream_id);
}

void WebTransport::Trace(Visitor* visitor) const {
  visitor->Trace(datagrams_);
  visitor->Trace(received_datagrams_);
  visitor->Trace(received_datagrams_controller_);
  visitor->Trace(datagram_underlying_source_);
  visitor->Trace(outgoing_datagrams_);
  visitor->Trace(datagram_underlying_sink_);
  visitor->Trace(script_state_);
  visitor->Trace(create_stream_resolvers_);
  visitor->Trace(connector_);
  visitor->Trace(transport_remote_);
  visitor->Trace(handshake_client_receiver_);
  visitor->Trace(client_receiver_);
  visitor->Trace(ready_);
  visitor->Trace(closed_);
  visitor->Trace(latest_stats_);
  visitor->Trace(pending_get_stats_resolvers_);
  visitor->Trace(incoming_stream_map_);
  visitor->Trace(outgoing_stream_map_);
  visitor->Trace(received_streams_);
  visitor->Trace(received_streams_underlying_source_);
  visitor->Trace(received_bidirectional_streams_);
  visitor->Trace(received_bidirectional_streams_underlying_source_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void WebTransport::Init(const String& url_for_diagnostics,
                        const WebTransportOptions& options,
                        ExceptionState& exception_state) {
  DVLOG(1) << "WebTransport::Init() url=" << url_for_diagnostics
           << " this=" << this;
  // This is an intentional spec violation due to our limited support for
  // detached realms.
  if (!script_state_->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Frame is detached.");
    return;
  }
  if (!url_.IsValid()) {
    // Do not use `url_` in the error message, since we want to display the
    // original URL and not the canonicalized version stored in `url_`.
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The URL '" + url_for_diagnostics + "' is invalid.");
    return;
  }

  if (!url_.ProtocolIs("https")) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "The URL's scheme must be 'https'. '" +
                                          url_.Protocol() +
                                          "' is not allowed.");
    return;
  }

  if (url_.HasFragmentIdentifier()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The URL contains a fragment identifier ('#" +
            url_.FragmentIdentifier() +
            "'). Fragment identifiers are not allowed in WebTransport URLs.");
    return;
  }

  auto* execution_context = GetExecutionContext();

  bool is_url_blocked = false;
  if (!execution_context->GetContentSecurityPolicyForCurrentWorld()
           ->AllowConnectToSource(url_, url_, RedirectStatus::kNoRedirect)) {
    ScriptValue error(
        script_state_->GetIsolate(),
        WebTransportError::Create(
            script_state_->GetIsolate(),
            /*stream_error_code=*/std::nullopt,
            "Refused to connect to '" + url_.ElidedString() +
                "' because it violates the document's Content Security Policy",
            V8WebTransportErrorSource::Enum::kSession));

    connection_pending_ = false;
    ready_->Reject(error);
    closed_->Reject(error);

    is_url_blocked = true;
  }

  Vector<network::mojom::blink::WebTransportCertificateFingerprintPtr>
      fingerprints;
  if (options.hasServerCertificateHashes()) {
    for (const auto& hash : options.serverCertificateHashes()) {
      if (!hash->hasAlgorithm() || !hash->hasValue())
        continue;
      StringBuilder value_builder;
      DOMArrayPiece array_piece(hash->value());

      auto data = array_piece.ByteSpan();
      for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) {
          value_builder.Append(":");
        }
        value_builder.AppendFormat("%02X", data[i]);
      }

      fingerprints.push_back(
          network::mojom::blink::WebTransportCertificateFingerprint::New(
              hash->algorithm(), value_builder.ToString()));
    }
  }
  if (!fingerprints.empty()) {
    execution_context->CountUse(
        WebFeature::kWebTransportServerCertificateHashes);
  }

  if (auto* scheduler = execution_context->GetScheduler()) {
    // Two features are registered with `DisableBackForwardCache` policy here:
    // - `kWebTransport`: a non-sticky feature that will disable BFCache for any
    // page. It will be reset after the `WebTransport` is disposed.
    // - `kWebTransportSticky`: a sticky feature that will only disable BFCache
    // for the page containing "Cache-Control: no-store" header. It won't be
    // reset even if the `WebTransport` is disposed.
    feature_handle_for_scheduler_ = scheduler->RegisterFeature(
        SchedulingPolicy::Feature::kWebTransport,
        SchedulingPolicy{SchedulingPolicy::DisableAggressiveThrottling(),
                         SchedulingPolicy::DisableBackForwardCache()});
    scheduler->RegisterStickyFeature(
        SchedulingPolicy::Feature::kWebTransportSticky,
        SchedulingPolicy{SchedulingPolicy::DisableBackForwardCache()});
  }

  if (DoesSubresourceFilterBlockConnection(url_)) {
    // SubresourceFilter::ReportLoad() may report an actual message.
    ScriptValue dom_exception(
        script_state_->GetIsolate(),
        V8ThrowDOMException::CreateOrEmpty(
            script_state_->GetIsolate(), DOMExceptionCode::kNetworkError, ""));

    connection_pending_ = false;
    ready_->Reject(dom_exception);
    closed_->Reject(dom_exception);
    is_url_blocked = true;
  }

  if (!is_url_blocked) {
    execution_context->GetBrowserInterfaceBroker().GetInterface(
        connector_.BindNewPipeAndPassReceiver(
            execution_context->GetTaskRunner(TaskType::kNetworking)));

    connector_->Connect(
        url_, std::move(fingerprints),
        handshake_client_receiver_.BindNewPipeAndPassRemote(
            execution_context->GetTaskRunner(TaskType::kNetworking)));

    handshake_client_receiver_.set_disconnect_handler(WTF::BindOnce(
        &WebTransport::OnConnectionError, WrapWeakPersistent(this)));
  }

  probe::WebTransportCreated(execution_context, inspector_transport_id_, url_);

  int outgoing_datagrams_high_water_mark = 1;
  datagrams_ = MakeGarbageCollected<DatagramDuplexStream>(
      this, outgoing_datagrams_high_water_mark);

  datagram_underlying_source_ =
      MakeGarbageCollected<DatagramUnderlyingSource>(script_state_, datagrams_);
  received_datagrams_ = ReadableStream::CreateByteStream(
      script_state_, datagram_underlying_source_);
  received_datagrams_controller_ =
      To<ReadableByteStreamController>(received_datagrams_->GetController());

  // We create a WritableStream with high water mark 1 and try to mimic the
  // given high water mark in the Sink, from two reasons:
  // 1. This is better because we can hide the RTT between the renderer and the
  //    network service.
  // 2. Keeping datagrams in the renderer would be confusing for the timer for
  // the datagram
  //    queue in the network service, because the timestamp is taken when the
  //    datagram is added to the queue.
  datagram_underlying_sink_ =
      MakeGarbageCollected<DatagramUnderlyingSink>(this, datagrams_);
  outgoing_datagrams_ = WritableStream::CreateWithCountQueueingStrategy(
      script_state_, datagram_underlying_sink_, 1);

  received_streams_underlying_source_ =
      StreamVendingUnderlyingSource::CreateWithVendor<ReceiveStreamVendor>(
          script_state_, this);
  received_streams_ = ReadableStream::CreateWithCountQueueingStrategy(
      script_state_, received_streams_underlying_source_, 1);

  received_bidirectional_streams_underlying_source_ =
      StreamVendingUnderlyingSource::CreateWithVendor<
          BidirectionalStreamVendor>(script_state_, this);

  received_bidirectional_streams_ =
      ReadableStream::CreateWithCountQueueingStrategy(
          script_state_, received_bidirectional_streams_underlying_source_, 1);
}

bool WebTransport::DoesSubresourceFilterBlockConnection(const KURL& url) {
  ResourceFetcher* resource_fetcher = GetExecutionContext()->Fetcher();
  SubresourceFilter* subresource_filter =
      static_cast<BaseFetchContext*>(&resource_fetcher->Context())
          ->GetSubresourceFilter();
  return subresource_filter &&
         !subresource_filter->AllowWebTransportConnection(url);
}

void WebTransport::Dispose() {
  DVLOG(1) << "WebTransport::Dispose() this=" << this;
  probe::WebTransportClosed(GetExecutionContext(), inspector_transport_id_);
  incoming_stream_map_.clear();
  outgoing_stream_map_.clear();
  connector_.reset();
  transport_remote_.reset();
  handshake_client_receiver_.reset();
  client_receiver_.reset();
  // Make the page back/forward cache-able.
  feature_handle_for_scheduler_.reset();
}

// https://w3c.github.io/webtransport/#webtransport-cleanup
void WebTransport::Cleanup(WebTransportCloseInfo* info,
                           v8::Local<v8::Value> error,
                           bool abruptly) {
  CHECK_EQ(!info, abruptly);
  v8::Isolate* isolate = script_state_->GetIsolate();

  RejectPendingStreamResolvers(error);
  HandlePendingGetStatsResolvers(error);
  ScriptValue error_value(isolate, error);
  datagram_underlying_source_->Error(received_datagrams_controller_, error);
  outgoing_datagrams_->Controller()->error(script_state_, error_value);

  // We use local variables to avoid re-entrant problems.
  auto* incoming_bidirectional_streams_source =
      received_bidirectional_streams_underlying_source_.Get();
  auto* incoming_unidirectional_streams_source =
      received_streams_underlying_source_.Get();
  auto incoming_stream_map = std::move(incoming_stream_map_);
  auto outgoing_stream_map = std::move(outgoing_stream_map_);

  Dispose();

  for (const auto& kv : incoming_stream_map) {
    kv.value->Error(error_value);
  }
  for (const auto& kv : outgoing_stream_map) {
    kv.value->Error(error_value);
  }

  if (abruptly) {
    connection_pending_ = false;
    closed_->Reject(ScriptValue(isolate, error));
    if (ready_->GetState() == ReadyProperty::kPending) {
      ready_->Reject(ScriptValue(isolate, error));
    }
    incoming_bidirectional_streams_source->Error(error);
    incoming_unidirectional_streams_source->Error(error);
  } else {
    CHECK(info);
    closed_->Resolve(info);
    DCHECK_EQ(ready_->GetState(), ReadyProperty::kResolved);
    incoming_bidirectional_streams_source->Close();
    incoming_unidirectional_streams_source->Close();
  }
}

void WebTransport::OnConnectionError() {
  DVLOG(1) << "WebTransport::OnConnectionError() this=" << this;
  v8::Isolate* isolate = script_state_->GetIsolate();

  ScriptState::Scope scope(script_state_);
  v8::Local<v8::Value> error = WebTransportError::Create(
      isolate,
      /*stream_error_code=*/std::nullopt, "Connection lost.",
      V8WebTransportErrorSource::Enum::kSession);

  Cleanup(nullptr, error, /*abruptly=*/true);
}

void WebTransport::RejectPendingStreamResolvers(v8::Local<v8::Value> error) {
  HeapHashSet<Member<ScriptPromiseResolverBase>> create_stream_resolvers;
  create_stream_resolvers_.swap(create_stream_resolvers);
  for (ScriptPromiseResolverBase* resolver : create_stream_resolvers) {
    resolver->Reject(error);
  }
}

void WebTransport::HandlePendingGetStatsResolvers(v8::Local<v8::Value> error) {
  HeapVector<Member<ScriptPromiseResolver<WebTransportConnectionStats>>>
      stats_resolvers;
  stats_resolvers.swap(pending_get_stats_resolvers_);
  for (auto& resolver : stats_resolvers) {
    if (latest_stats_) {
      // "If transport.[[State]] is "closed", resolve p with the most recent
      // stats available for the connection [...]"
      resolver->Resolve(latest_stats_);
    } else {
      // `latest_stats_` is always set upon connection being established,
      // meaning that this only happens when the connection failed before being
      // established.
      resolver->RejectWithDOMException(
          DOMExceptionCode::kInvalidStateError,
          "Cannot retreive stats on a failed connection.");
    }
  }
}

void WebTransport::OnCreateSendStreamResponse(
    ScriptPromiseResolver<WritableStream>* resolver,
    mojo::ScopedDataPipeProducerHandle producer,
    bool succeeded,
    uint32_t stream_id) {
  DVLOG(1) << "WebTransport::OnCreateSendStreamResponse() this=" << this
           << " succeeded=" << succeeded << " stream_id=" << stream_id;

  // Shouldn't resolve the promise if the execution context has gone away.
  if (!GetExecutionContext())
    return;

  // Shouldn't resolve the promise if the mojo interface is disconnected.
  if (!resolver || !create_stream_resolvers_.Take(resolver))
    return;

  ScriptState::Scope scope(script_state_);
  if (!succeeded) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state_->GetIsolate(), DOMExceptionCode::kNetworkError,
        "Failed to create send stream."));
    return;
  }

  auto* send_stream = MakeGarbageCollected<SendStream>(
      script_state_, this, stream_id, std::move(producer));

  auto* isolate = script_state_->GetIsolate();
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state_),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::TryCatch try_catch(isolate);
  send_stream->Init(PassThroughException(isolate));
  if (try_catch.HasCaught()) {
    resolver->Reject(try_catch.Exception());
    return;
  }

  // 0xfffffffe and 0xffffffff are reserved values in stream_map_.
  CHECK_LT(stream_id, 0xfffffffe);
  outgoing_stream_map_.insert(stream_id, send_stream->GetOutgoingStream());

  resolver->Resolve(send_stream);
}

void WebTransport::OnCreateBidirectionalStreamResponse(
    ScriptPromiseResolver<BidirectionalStream>* resolver,
    mojo::ScopedDataPipeProducerHandle outgoing_producer,
    mojo::ScopedDataPipeConsumerHandle incoming_consumer,
    bool succeeded,
    uint32_t stream_id) {
  DVLOG(1) << "WebTransport::OnCreateBidirectionalStreamResponse() this="
           << this << " succeeded=" << succeeded << " stream_id=" << stream_id;

  // Shouldn't resolve the promise if the execution context has gone away.
  if (!GetExecutionContext())
    return;

  // Shouldn't resolve the promise if the mojo interface is disconnected.
  if (!resolver || !create_stream_resolvers_.Take(resolver))
    return;

  ScriptState::Scope scope(script_state_);
  auto* isolate = script_state_->GetIsolate();
  if (!succeeded) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        isolate, DOMExceptionCode::kNetworkError,
        "Failed to create bidirectional stream."));
    return;
  }

  auto* bidirectional_stream = MakeGarbageCollected<BidirectionalStream>(
      script_state_, this, stream_id, std::move(outgoing_producer),
      std::move(incoming_consumer));

  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state_),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::TryCatch try_catch(isolate);
  bidirectional_stream->Init(PassThroughException(isolate));
  if (try_catch.HasCaught()) {
    resolver->Reject(try_catch.Exception());
    return;
  }

  // 0xfffffffe and 0xffffffff are reserved values in stream_map_.
  CHECK_LT(stream_id, 0xfffffffe);
  incoming_stream_map_.insert(stream_id,
                              bidirectional_stream->GetIncomingStream());
  outgoing_stream_map_.insert(stream_id,
                              bidirectional_stream->GetOutgoingStream());

  resolver->Resolve(bidirectional_stream);
}

void WebTransport::OnGetStatsResponse(
    network::mojom::blink::WebTransportStatsPtr stats) {
  auto* idl_stats = ConvertStatsFromMojom(std::move(stats));
  latest_stats_ = idl_stats;
  HeapVector<Member<ScriptPromiseResolver<WebTransportConnectionStats>>>
      resolvers;
  pending_get_stats_resolvers_.swap(resolvers);
  for (auto& resolver : resolvers) {
    resolver->Resolve(idl_stats);
  }
}

WebTransportConnectionStats* WebTransport::ConvertStatsFromMojom(
    network::mojom::blink::WebTransportStatsPtr in) {
  auto* out = MakeGarbageCollected<WebTransportConnectionStats>();
  out->setMinRtt(in->min_rtt.InMillisecondsF());
  out->setSmoothedRtt(in->smoothed_rtt.InMillisecondsF());
  out->setRttVariation(in->rtt_variation.InMillisecondsF());
  if (in->estimated_send_rate_bps > 0) {
    out->setEstimatedSendRate(in->estimated_send_rate_bps);
  } else {
    out->setEstimatedSendRate(std::nullopt);
  }
  auto* datagram_stats = MakeGarbageCollected<WebTransportDatagramStats>();
  datagram_stats->setExpiredOutgoing(in->datagrams_expired_outgoing);
  datagram_stats->setLostOutgoing(in->datagrams_lost_outgoing);
  if (datagram_underlying_source_) {
    datagram_stats->setDroppedIncoming(
        datagram_underlying_source_->dropped_datagram_count());
  }
  out->setDatagrams(datagram_stats);
  return out;
}

}  // namespace blink
```
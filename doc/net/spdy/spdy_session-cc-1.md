Response:
My thinking process to answer the request goes through these stages:

1. **Understand the Request:** The user wants a functional summary of the provided C++ code snippet from `net/spdy/spdy_session.cc`. They are also interested in connections to JavaScript, logical reasoning with input/output examples, common usage errors, debugging hints, and a summary of the current snippet's function within the larger context (it being part 2 of 4).

2. **High-Level Code Overview:**  I quickly scan the code to identify the main functionalities. Keywords like `InitializeWithSocket`, `ParseAlps`, `EnqueueStreamWrite`, `CreateHeaders`, `CreateDataBuffer`, `UpdateStreamPriority`, `CloseActiveStream`, `ResetStream`, `SendStreamWindowUpdate`, `StartGoingAway`, `TryCreateStream`, and the various `Enqueue...Frame` methods stand out. These suggest the code is responsible for managing the lifecycle of a SPDY/HTTP2 session, including initialization, handling ALPS (Application-Layer Protocol Settings), managing data and header frames for streams, prioritizing streams, handling stream closure and resets, and managing the session's "going away" state.

3. **Focus on the Current Snippet (Part 2):** The request specifically asks to summarize *this* part. This segment primarily deals with:
    * Initialization using either a `StreamSocketHandle` or a raw `StreamSocket`.
    * Parsing ALPS settings received from the peer.
    * Verifying domain authentication.
    * Enqueuing write operations (headers, data, and "greased" frames).
    * Managing HTTP/2 priority.
    * Confirming the TLS handshake.
    * Creating header and data frames.
    * Managing flow control (both stream and session level).
    * Updating stream priority.
    * Closing and resetting streams.
    * Getting session information.
    * Sending window updates.
    * Handling session going away and draining.
    * Managing pooled aliases.
    * Broken connection detection.
    * Creating new streams (with concurrency limits).
    * Handling pending stream requests.

4. **Functionality Listing:** I translate the code overview into a list of concrete functions, as requested. I try to be specific and use descriptive language.

5. **JavaScript Relationship:** I consider how these server-side networking functionalities might relate to client-side JavaScript. The key connection is through browser APIs like `fetch` or `XMLHttpRequest`. JavaScript initiates requests, and this C++ code handles the underlying HTTP/2 communication. I provide an example using `fetch` to illustrate this.

6. **Logical Reasoning (Input/Output):** I select a relatively self-contained function (`VerifyDomainAuthentication`) for this. I create a simple scenario with a secure connection and a valid domain, showing the expected true output. Then, I create a scenario with a non-secure connection, illustrating the default "true" output. This demonstrates how the function behaves under different conditions.

7. **Common Usage Errors:** I think about common mistakes a *programmer* (not a user) might make when using or interacting with this code. For example, trying to send data on a draining session, forgetting to check return values, or mismanaging stream IDs are all potential issues.

8. **User Operation to Reach Here (Debugging):**  I walk through a typical user scenario that would involve this code: opening a website. I break down the steps and highlight how network events, like establishing a secure connection and sending requests, lead to the execution of code within `SpdySession`.

9. **Summarize the Current Snippet's Function:** I synthesize the information gathered in the previous steps to create a concise summary of what this specific part of the code does. I focus on the core responsibilities evident in the included functions.

10. **Review and Refine:** I reread my answer to ensure accuracy, clarity, and completeness. I check that all parts of the request have been addressed and that the language is understandable. I might rephrase sentences or add more detail where needed. For instance, I made sure to explicitly mention the flow control aspects after noticing the related code.

By following these steps, I aim to provide a comprehensive and helpful answer that addresses all aspects of the user's request. The process involves understanding the code's purpose, identifying key functionalities, making connections to other technologies, demonstrating usage with examples, considering potential errors, and explaining the context within a larger system.
好的，让我们继续分析 `net/spdy/spdy_session.cc` 的剩余部分，并归纳一下这部分代码的功能。

**功能列举 (基于提供的代码片段):**

* **会话初始化:**
    * `InitializeWithSocket(std::unique_ptr<StreamSocket> stream_socket, ...)`:  使用一个已经创建好的 `StreamSocket` 对象来初始化 SpdySession。这通常发生在非连接池场景，或者连接已经被建立的情况。
    * `InitializeInternal(SpdySessionPool* pool)`: 执行内部的初始化步骤，例如设置窗口大小、创建 `BufferedSpdyFramer`、记录日志、以及启动读取循环。

* **ALPS (应用层协议设置) 处理:**
    * `ParseAlps()`: 解析从对端接收到的 ALPS 数据，用于协商和配置协议参数。
    * 处理 `accept-ch` 头域：解析通过 ALPS 接收到的 `accept-ch` 条目，并记录到 `accept_ch_entries_received_via_alps_`。

* **域名认证:**
    * `VerifyDomainAuthentication(std::string_view domain) const`: 验证给定的域名是否被当前会话所允许，考虑了传输层安全状态（TLS）。

* **帧写入队列管理:**
    * `EnqueueStreamWrite(...)`: 将用于特定流的 HEADERS 或 DATA 帧添加到写入队列。
    * `EnqueueGreasedFrame(...)`:  如果启用了 Greased 帧，则将一个预定义的 "无害" 帧添加到写入队列，用于测试对端兼容性。
    * `EnqueueResetStreamFrame(...)`: 将 RST_STREAM 帧添加到写入队列，用于中止一个流。
    * `EnqueuePriorityFrame(...)`: 将 PRIORITY 帧添加到写入队列，用于更新流的优先级。

* **HTTP/2 优先级处理:**
    * `GreasedFramesEnabled() const`: 检查是否启用了 Greased 帧的发送。
    * `ShouldSendHttp2Priority() const`: 确定是否应该发送 HTTP/2 优先级信息。
    * `ShouldSendPriorityUpdate() const`: 确定是否应该发送 PRIORITY 帧来更新优先级。
    * `UpdateStreamPriority(...)`:  更新流的优先级，并根据需要发送 PRIORITY 帧。

* **握手确认:**
    * `ConfirmHandshake(CompletionOnceCallback callback)`: 确认 TLS 握手完成，并通知等待的回调。

* **帧创建:**
    * `CreateHeaders(...)`: 创建一个 HEADERS 帧。
    * `CreateDataBuffer(...)`: 创建一个 DATA 帧的缓冲区。

* **流管理:**
    * `CloseActiveStream(...)`: 关闭一个活动状态的流。
    * `CloseCreatedStream(...)`: 关闭一个已创建但尚未激活的流。
    * `ResetStream(...)`: 重置一个流，发送 RST_STREAM 帧。
    * `IsStreamActive(...) const`: 检查一个流是否处于活动状态。
    * `SendStreamWindowUpdate(...)`: 发送 WINDOW_UPDATE 帧来增加流的接收窗口大小。

* **会话状态管理:**
    * `CloseSessionOnError(...)`:  由于错误而关闭会话。
    * `MakeUnavailable()`: 将会话标记为不可用。
    * `StartGoingAway(...)`:  启动会话的 "going away" 流程，优雅地关闭会话。
    * `MaybeFinishGoingAway()`: 检查是否可以完成 "going away" 流程。
    * `IsReused() const`:  判断会话是否被复用。

* **信息获取:**
    * `GetInfoAsValue() const`:  获取会话的各种信息，以 `base::Value::Dict` 的形式返回。
    * `GetLoadTimingInfo(...) const`: 获取会话的加载时间信息。
    * `GetRemoteEndpoint(...)`: 获取远端端点的地址。
    * `GetLocalAddress(...)`: 获取本地端点的地址。
    * `GetSSLInfo(...) const`: 获取 SSL 连接信息。
    * `GetAcceptChViaAlps(...) const`: 获取通过 ALPS 接收到的指定 origin 的 `accept-ch` 值。
    * `GetNegotiatedProtocol() const`: 获取协商的协议。
    * `GetLoadState() const`: 获取会话的加载状态。

* **连接池别名管理:**
    * `AddPooledAlias(...)`: 添加一个连接池别名。
    * `RemovePooledAlias(...)`: 移除一个连接池别名。

* **传输层安全:**
    * `HasAcceptableTransportSecurity() const`: 检查会话是否具有可接受的传输层安全性（例如，TLS 1.2+ 和允许的密码套件）。

* **空闲连接关闭:**
    * `CloseOneIdleConnection()`: 关闭一个空闲连接。

* **Socket Tag 管理:**
    * `ChangeSocketTag(...)`:  更改底层 socket 的 tag。

* **断线检测:**
    * `EnableBrokenConnectionDetection(...)`: 启用断线检测机制，定期发送心跳。
    * `IsBrokenConnectionDetectionEnabled() const`: 检查是否启用了断线检测。

* **流的创建和请求:**
    * `TryCreateStream(...)`: 尝试创建一个新的流，如果达到并发流限制，则将请求放入队列。
    * `CreateStream(...)`:  创建一个新的 `SpdyStream` 对象。
    * `CancelStreamRequest(...)`: 取消一个待创建的流请求。
    * `ChangeStreamRequestPriority(...)`: 更改待创建的流请求的优先级。
    * `GetNextPendingStreamRequest()`: 获取下一个待处理的流请求。
    * `ProcessPendingStreamRequests()`: 处理待处理的流请求队列，创建新的流。

* **内部辅助函数:**
    * `CloseActiveStreamIterator(...)`: 实际执行关闭活动流的操作。
    * `CloseCreatedStreamIterator(...)`: 实际执行关闭已创建流的操作。
    * `ResetStreamIterator(...)`: 实际执行重置流的操作。

**与 JavaScript 的关系举例说明:**

当 JavaScript 代码使用 `fetch` API 发起一个 HTTPS 请求时，如果浏览器决定使用 HTTP/2 协议，那么 `SpdySession` 的这些功能就会被调用来处理底层的网络通信。

**举例:**

假设 JavaScript 代码执行以下操作:

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. **`TryCreateStream` / `CreateStream`:** 当 `fetch` 被调用时，浏览器会尝试为这个请求创建一个 HTTP/2 流。`SpdySession::TryCreateStream` 和 `SpdySession::CreateStream` 会被调用来完成流的创建。
2. **`CreateHeaders`:**  浏览器会构造 HTTP 请求头 (例如 `GET`, `Host`, `User-Agent` 等)，然后 `SpdySession::CreateHeaders` 会将这些头信息封装成一个 HTTP/2 HEADERS 帧。
3. **`EnqueueStreamWrite`:**  封装好的 HEADERS 帧会被添加到写入队列中，等待发送。
4. **`ParseAlps` (如果连接是新建的):** 如果这是与 `example.com` 的新连接，并且服务器支持 ALPS，`SpdySession::ParseAlps` 会处理服务器发送的 ALPS 设置，以便协商协议参数。
5. **数据接收 (未在当前片段中):** 当服务器返回数据时，`SpdySession` 会接收 DATA 帧，并将数据传递给上层处理，最终传递给 JavaScript 的 `response.json()`。
6. **`CloseActiveStream`:** 请求完成后，对应的 HTTP/2 流会被关闭，`SpdySession::CloseActiveStream` 会被调用。

**逻辑推理的假设输入与输出 (以 `VerifyDomainAuthentication` 为例):**

**假设输入 1:**

* `availability_state_`: `STATE_AVAILABLE`
* `GetSSLInfo()` 返回成功，且 `ssl_info` 指示一个安全的连接 (例如，使用了 TLS)。
* `transport_security_state_`: 一个有效的 `TransportSecurityState` 对象。
* `ssl_config_service_`: 一个有效的 `SSLConfigService` 对象。
* `host_port_pair().host()`: "example.com"
* `domain`: "sub.example.com"

**预期输出 1:** `true` (假设 `TransportSecurityState` 和 `SSLConfigService` 的配置允许子域名)。

**假设输入 2:**

* `availability_state_`: `STATE_AVAILABLE`
* `GetSSLInfo()` 返回失败 (例如，这是一个非 HTTPS 连接)。
* `domain`: 任何字符串，例如 "some.other.domain"

**预期输出 2:** `true` (因为这不是一个安全的会话，所以所有域名都被认为是允许的)。

**用户或编程常见的使用错误举例说明:**

1. **在会话进入 `STATE_DRAINING` 后尝试创建新的流:**
   * **错误:** 开发者可能会在会话即将关闭时，没有正确检查会话状态，仍然尝试使用 `TryCreateStream` 或 `CreateStream` 创建新的请求。
   * **后果:** 这些方法会返回 `ERR_CONNECTION_CLOSED` 或 `ERR_FAILED`，导致请求失败。
   * **调试线索:** 检查调用 `TryCreateStream` 或 `CreateStream` 时的会话状态 (`availability_state_`)。

2. **没有正确处理 `ConfirmHandshake` 的异步完成:**
   * **错误:**  开发者可能在调用 `ConfirmHandshake` 后，没有正确处理 `ERR_IO_PENDING` 的情况，直接继续发送数据，而忽略了握手可能尚未完成。
   * **后果:**  数据发送可能会失败，或者发生未预期的行为。
   * **调试线索:** 确保在 `ConfirmHandshake` 返回 `ERR_IO_PENDING` 时，注册回调并在回调中继续操作。

3. **错误地假设在 `UpdateStreamPriority` 后 PRIORITY 帧会立即发送:**
   * **错误:** 开发者可能假设调用 `UpdateStreamPriority` 后，PRIORITY 帧会立刻被发送出去。实际上，帧的发送会受到写入队列和 I/O 调度的影响。
   * **后果:**  流的优先级更新可能不会立即生效。
   * **调试线索:**  通过网络日志查看 PRIORITY 帧的实际发送时间。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS URL 并按下回车，或者点击一个 HTTPS 链接。**
2. **浏览器首先会检查是否有可复用的 HTTP/2 连接到该域名。**
3. **如果不存在可复用的连接，浏览器会发起一个 TCP 连接到服务器的 443 端口。**
4. **TCP 连接建立后，会进行 TLS 握手。**
5. **在 TLS 握手过程中，ALPN (应用层协议协商) 扩展会被使用，浏览器和服务器会协商使用 HTTP/2 协议。**
6. **如果协商成功，`SpdySessionPool` (或类似的管理类) 会创建一个 `SpdySession` 对象。**
7. **`SpdySession::InitializeWithSocket` 会被调用，传入新建立的 `StreamSocket`。**
8. **`SpdySession::ParseAlps` 可能会被调用，解析服务器发送的 ALPS 设置。**
9. **当浏览器需要发送 HTTP 请求时 (例如获取网页的 HTML 内容)，`SpdySession::TryCreateStream` 和 `SpdySession::CreateStream` 会被调用来创建一个新的 HTTP/2 流。**
10. **`SpdySession::CreateHeaders` 会将请求头封装成 HEADERS 帧。**
11. **`SpdySession::EnqueueStreamWrite` 会将 HEADERS 帧添加到写入队列。**
12. **底层的网络栈会将写入队列中的帧发送到服务器。**
13. **服务器返回数据时，`SpdySession` 会接收 DATA 帧并进行处理。**
14. **如果用户在页面加载过程中点击了另一个链接，或者页面需要加载其他资源 (例如图片、CSS、JavaScript)，会重复步骤 9-12，可能会创建多个 HTTP/2 流并行下载资源。**

**归纳一下这部分的功能 (第 2 部分):**

这部分代码主要负责 **SpdySession 的初始化、配置、和基本操作管理**。它处理了会话的创建和初始化，包括与底层 socket 的关联，ALPS 设置的解析，以及初始的内部状态设置。此外，它还涵盖了 **帧的创建和写入队列的管理**，包括 HEADERS、DATA、RST_STREAM 和 PRIORITY 帧，以及与 **HTTP/2 优先级** 相关的逻辑。 关键功能还包括 **TLS 握手的确认** 和对 **流的基本生命周期管理** (创建、关闭、重置)。 这部分为后续的帧处理、数据传输和会话状态管理奠定了基础。

### 提示词
```
这是目录为net/spdy/spdy_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
treamSocketHandle> stream_socket_handle,
    SpdySessionPool* pool) {
  DCHECK(!stream_socket_handle_);
  DCHECK(!owned_stream_socket_);
  DCHECK(!socket_);

  // TODO(akalin): Check connection->is_initialized() instead. This
  // requires re-working CreateFakeSpdySession(), though.
  DCHECK(stream_socket_handle->socket());

  stream_socket_handle_ = std::move(stream_socket_handle);
  socket_ = stream_socket_handle_->socket();
  stream_socket_handle_->AddHigherLayeredPool(this);

  InitializeInternal(pool);
}

void SpdySession::InitializeWithSocket(
    std::unique_ptr<StreamSocket> stream_socket,
    const LoadTimingInfo::ConnectTiming& connect_timing,
    SpdySessionPool* pool) {
  DCHECK(!stream_socket_handle_);
  DCHECK(!owned_stream_socket_);
  DCHECK(!socket_);

  DCHECK(stream_socket);

  owned_stream_socket_ = std::move(stream_socket);
  socket_ = owned_stream_socket_.get();
  connect_timing_ =
      std::make_unique<LoadTimingInfo::ConnectTiming>(connect_timing);

  InitializeInternal(pool);
}

int SpdySession::ParseAlps() {
  auto alps_data = socket_->GetPeerApplicationSettings();
  if (!alps_data) {
    return OK;
  }

  AlpsDecoder alps_decoder;
  AlpsDecoder::Error error = alps_decoder.Decode(alps_data.value());
  base::UmaHistogramEnumeration("Net.SpdySession.AlpsDecoderStatus", error);
  if (error != AlpsDecoder::Error::kNoError) {
    DoDrainSession(
        ERR_HTTP2_PROTOCOL_ERROR,
        base::StrCat({"Error parsing ALPS: ",
                      base::NumberToString(static_cast<int>(error))}));
    return ERR_HTTP2_PROTOCOL_ERROR;
  }

  base::UmaHistogramCounts100("Net.SpdySession.AlpsSettingParameterCount",
                              alps_decoder.GetSettings().size());
  for (const auto& setting : alps_decoder.GetSettings()) {
    spdy::SpdySettingsId identifier = setting.first;
    uint32_t value = setting.second;
    net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_SETTING, [&] {
      return NetLogSpdyRecvSettingParams(identifier, value);
    });
    HandleSetting(identifier, value);
  }

  bool has_valid_entry = false;
  bool has_invalid_entry = false;
  for (const auto& entry : alps_decoder.GetAcceptCh()) {
    const url::SchemeHostPort scheme_host_port(GURL(entry.origin));
    // |entry.origin| must be a valid SchemeHostPort.
    std::string serialized = scheme_host_port.Serialize();
    if (serialized.empty() || entry.origin != serialized) {
      has_invalid_entry = true;
      continue;
    }
    has_valid_entry = true;
    accept_ch_entries_received_via_alps_.emplace(std::move(scheme_host_port),
                                                 entry.value);

    net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_ACCEPT_CH,
                      [&] { return NetLogSpdyRecvAcceptChParams(entry); });
  }

  SpdyAcceptChEntries value;
  if (has_valid_entry) {
    if (has_invalid_entry) {
      value = SpdyAcceptChEntries::kBothValidAndInvalidEntries;
    } else {
      value = SpdyAcceptChEntries::kOnlyValidEntries;
    }
  } else {
    if (has_invalid_entry) {
      value = SpdyAcceptChEntries::kOnlyInvalidEntries;
    } else {
      value = SpdyAcceptChEntries::kNoEntries;
    }
  }
  base::UmaHistogramEnumeration("Net.SpdySession.AlpsAcceptChEntries", value);

  return OK;
}

bool SpdySession::VerifyDomainAuthentication(std::string_view domain) const {
  if (availability_state_ == STATE_DRAINING)
    return false;

  SSLInfo ssl_info;
  if (!GetSSLInfo(&ssl_info))
    return true;  // This is not a secure session, so all domains are okay.

  return CanPool(transport_security_state_, ssl_info, *ssl_config_service_,
                 host_port_pair().host(), domain);
}

void SpdySession::EnqueueStreamWrite(
    const base::WeakPtr<SpdyStream>& stream,
    spdy::SpdyFrameType frame_type,
    std::unique_ptr<SpdyBufferProducer> producer) {
  DCHECK(frame_type == spdy::SpdyFrameType::HEADERS ||
         frame_type == spdy::SpdyFrameType::DATA);
  EnqueueWrite(stream->priority(), frame_type, std::move(producer), stream,
               stream->traffic_annotation());
}

bool SpdySession::GreasedFramesEnabled() const {
  return greased_http2_frame_.has_value();
}

void SpdySession::EnqueueGreasedFrame(const base::WeakPtr<SpdyStream>& stream) {
  if (availability_state_ == STATE_DRAINING)
    return;

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_SEND_GREASED_FRAME, [&] {
    return NetLogSpdyGreasedFrameParams(
        stream->stream_id(), greased_http2_frame_.value().type,
        greased_http2_frame_.value().flags,
        greased_http2_frame_.value().payload.length(), stream->priority());
  });

  EnqueueWrite(
      stream->priority(),
      static_cast<spdy::SpdyFrameType>(greased_http2_frame_.value().type),
      std::make_unique<GreasedBufferProducer>(
          stream, &greased_http2_frame_.value(), buffered_spdy_framer_.get()),
      stream, stream->traffic_annotation());
}

bool SpdySession::ShouldSendHttp2Priority() const {
  return !enable_priority_update_ || !deprecate_http2_priorities_;
}

bool SpdySession::ShouldSendPriorityUpdate() const {
  if (!enable_priority_update_) {
    return false;
  }

  return settings_frame_received_ ? deprecate_http2_priorities_ : true;
}

int SpdySession::ConfirmHandshake(CompletionOnceCallback callback) {
  if (availability_state_ == STATE_GOING_AWAY)
    return ERR_FAILED;

  if (availability_state_ == STATE_DRAINING)
    return ERR_CONNECTION_CLOSED;

  int rv = ERR_IO_PENDING;
  if (!in_confirm_handshake_) {
    rv = socket_->ConfirmHandshake(
        base::BindOnce(&SpdySession::NotifyRequestsOfConfirmation,
                       weak_factory_.GetWeakPtr()));
  }
  if (rv == ERR_IO_PENDING) {
    in_confirm_handshake_ = true;
    waiting_for_confirmation_callbacks_.push_back(std::move(callback));
  }
  return rv;
}

std::unique_ptr<spdy::SpdySerializedFrame> SpdySession::CreateHeaders(
    spdy::SpdyStreamId stream_id,
    RequestPriority priority,
    spdy::SpdyControlFlags flags,
    quiche::HttpHeaderBlock block,
    NetLogSource source_dependency) {
  ActiveStreamMap::const_iterator it = active_streams_.find(stream_id);
  CHECK(it != active_streams_.end());
  CHECK_EQ(it->second->stream_id(), stream_id);

  MaybeSendPrefacePing();

  DCHECK(buffered_spdy_framer_.get());
  spdy::SpdyPriority spdy_priority =
      ConvertRequestPriorityToSpdyPriority(priority);

  bool has_priority = true;
  int weight = 0;
  spdy::SpdyStreamId parent_stream_id = 0;
  bool exclusive = false;

  priority_dependency_state_.OnStreamCreation(
      stream_id, spdy_priority, &parent_stream_id, &weight, &exclusive);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_SEND_HEADERS,
                    [&](NetLogCaptureMode capture_mode) {
                      return NetLogSpdyHeadersSentParams(
                          &block, (flags & spdy::CONTROL_FLAG_FIN) != 0,
                          stream_id, has_priority, weight, parent_stream_id,
                          exclusive, source_dependency, capture_mode);
                    });

  spdy::SpdyHeadersIR headers(stream_id, std::move(block));
  headers.set_has_priority(has_priority);
  headers.set_weight(weight);
  headers.set_parent_stream_id(parent_stream_id);
  headers.set_exclusive(exclusive);
  headers.set_fin((flags & spdy::CONTROL_FLAG_FIN) != 0);

  streams_initiated_count_++;

  return std::make_unique<spdy::SpdySerializedFrame>(
      buffered_spdy_framer_->SerializeFrame(headers));
}

std::unique_ptr<SpdyBuffer> SpdySession::CreateDataBuffer(
    spdy::SpdyStreamId stream_id,
    IOBuffer* data,
    int len,
    spdy::SpdyDataFlags flags,
    int* effective_len,
    bool* end_stream) {
  if (availability_state_ == STATE_DRAINING) {
    return nullptr;
  }

  ActiveStreamMap::const_iterator it = active_streams_.find(stream_id);
  CHECK(it != active_streams_.end());
  SpdyStream* stream = it->second;
  CHECK_EQ(stream->stream_id(), stream_id);

  if (len < 0) {
    NOTREACHED();
  }

  *effective_len = std::min(len, kMaxSpdyFrameChunkSize);

  bool send_stalled_by_stream = (stream->send_window_size() <= 0);
  bool send_stalled_by_session = IsSendStalled();

  // NOTE: There's an enum of the same name in histograms.xml.
  enum SpdyFrameFlowControlState {
    SEND_NOT_STALLED,
    SEND_STALLED_BY_STREAM,
    SEND_STALLED_BY_SESSION,
    SEND_STALLED_BY_STREAM_AND_SESSION,
  };

  SpdyFrameFlowControlState frame_flow_control_state = SEND_NOT_STALLED;
  if (send_stalled_by_stream) {
    if (send_stalled_by_session) {
      frame_flow_control_state = SEND_STALLED_BY_STREAM_AND_SESSION;
    } else {
      frame_flow_control_state = SEND_STALLED_BY_STREAM;
    }
  } else if (send_stalled_by_session) {
    frame_flow_control_state = SEND_STALLED_BY_SESSION;
  }

  UMA_HISTOGRAM_ENUMERATION("Net.SpdyFrameStreamAndSessionFlowControlState",
                            frame_flow_control_state,
                            SEND_STALLED_BY_STREAM_AND_SESSION + 1);

  // Obey send window size of the stream.
  if (send_stalled_by_stream) {
    stream->set_send_stalled_by_flow_control(true);
    // Even though we're currently stalled only by the stream, we
    // might end up being stalled by the session also.
    QueueSendStalledStream(*stream);
    net_log_.AddEventWithIntParams(
        NetLogEventType::HTTP2_SESSION_STREAM_STALLED_BY_STREAM_SEND_WINDOW,
        "stream_id", stream_id);
    return nullptr;
  }

  *effective_len = std::min(*effective_len, stream->send_window_size());

  // Obey send window size of the session.
  if (send_stalled_by_session) {
    stream->set_send_stalled_by_flow_control(true);
    QueueSendStalledStream(*stream);
    net_log_.AddEventWithIntParams(
        NetLogEventType::HTTP2_SESSION_STREAM_STALLED_BY_SESSION_SEND_WINDOW,
        "stream_id", stream_id);
    return nullptr;
  }

  *effective_len = std::min(*effective_len, session_send_window_size_);

  DCHECK_GE(*effective_len, 0);

  // Clear FIN flag if only some of the data will be in the data
  // frame.
  if (*effective_len < len)
    flags = static_cast<spdy::SpdyDataFlags>(flags & ~spdy::DATA_FLAG_FIN);


  // Send PrefacePing for DATA_FRAMEs with nonzero payload size.
  if (*effective_len > 0)
    MaybeSendPrefacePing();

  // TODO(mbelshe): reduce memory copies here.
  DCHECK(buffered_spdy_framer_.get());
  std::unique_ptr<spdy::SpdySerializedFrame> frame(
      buffered_spdy_framer_->CreateDataFrame(
          stream_id, data->data(), static_cast<uint32_t>(*effective_len),
          flags));

  auto data_buffer = std::make_unique<SpdyBuffer>(std::move(frame));

  // Send window size is based on payload size, so nothing to do if this is
  // just a FIN with no payload.
  if (*effective_len != 0) {
    DecreaseSendWindowSize(static_cast<int32_t>(*effective_len));
    data_buffer->AddConsumeCallback(base::BindRepeating(
        &SpdySession::OnWriteBufferConsumed, weak_factory_.GetWeakPtr(),
        static_cast<size_t>(*effective_len)));
  }

  *end_stream = (flags & spdy::DATA_FLAG_FIN) == spdy::DATA_FLAG_FIN;
  return data_buffer;
}

void SpdySession::UpdateStreamPriority(SpdyStream* stream,
                                       RequestPriority old_priority,
                                       RequestPriority new_priority) {
  // There might be write frames enqueued for |stream| regardless of whether it
  // is active (stream_id != 0) or inactive (no HEADERS frame has been sent out
  // yet and stream_id == 0).
  write_queue_.ChangePriorityOfWritesForStream(stream, old_priority,
                                               new_priority);

  // PRIORITY frames only need to be sent if |stream| is active.
  const spdy::SpdyStreamId stream_id = stream->stream_id();
  if (stream_id == 0)
    return;

  DCHECK(IsStreamActive(stream_id));

  if (base::FeatureList::IsEnabled(features::kAvoidH2Reprioritization))
    return;

  auto updates = priority_dependency_state_.OnStreamUpdate(
      stream_id, ConvertRequestPriorityToSpdyPriority(new_priority));
  for (auto u : updates) {
    DCHECK(IsStreamActive(u.id));
    EnqueuePriorityFrame(u.id, u.parent_stream_id, u.weight, u.exclusive);
  }
}

void SpdySession::CloseActiveStream(spdy::SpdyStreamId stream_id, int status) {
  DCHECK_NE(stream_id, 0u);

  auto it = active_streams_.find(stream_id);
  if (it == active_streams_.end()) {
    NOTREACHED();
  }

  CloseActiveStreamIterator(it, status);
}

void SpdySession::CloseCreatedStream(const base::WeakPtr<SpdyStream>& stream,
                                     int status) {
  DCHECK_EQ(stream->stream_id(), 0u);

  auto it = created_streams_.find(stream.get());
  if (it == created_streams_.end()) {
    NOTREACHED();
  }

  CloseCreatedStreamIterator(it, status);
}

void SpdySession::ResetStream(spdy::SpdyStreamId stream_id,
                              int error,
                              const std::string& description) {
  DCHECK_NE(stream_id, 0u);

  auto it = active_streams_.find(stream_id);
  if (it == active_streams_.end()) {
    NOTREACHED();
  }

  ResetStreamIterator(it, error, description);
}

bool SpdySession::IsStreamActive(spdy::SpdyStreamId stream_id) const {
  return base::Contains(active_streams_, stream_id);
}

LoadState SpdySession::GetLoadState() const {
  // Just report that we're idle since the session could be doing
  // many things concurrently.
  return LOAD_STATE_IDLE;
}

int SpdySession::GetRemoteEndpoint(IPEndPoint* endpoint) {
  return GetPeerAddress(endpoint);
}

bool SpdySession::GetSSLInfo(SSLInfo* ssl_info) const {
  return socket_->GetSSLInfo(ssl_info);
}

std::string_view SpdySession::GetAcceptChViaAlps(
    const url::SchemeHostPort& scheme_host_port) const {
  auto it = accept_ch_entries_received_via_alps_.find(scheme_host_port);
  if (it == accept_ch_entries_received_via_alps_.end()) {
    LogSpdyAcceptChForOriginHistogram(false);
    return {};
  }

  LogSpdyAcceptChForOriginHistogram(true);
  return it->second;
}

NextProto SpdySession::GetNegotiatedProtocol() const {
  return socket_->GetNegotiatedProtocol();
}

void SpdySession::SendStreamWindowUpdate(spdy::SpdyStreamId stream_id,
                                         uint32_t delta_window_size) {
  ActiveStreamMap::const_iterator it = active_streams_.find(stream_id);
  CHECK(it != active_streams_.end());
  CHECK_EQ(it->second->stream_id(), stream_id);
  SendWindowUpdateFrame(stream_id, delta_window_size, it->second->priority());
}

void SpdySession::CloseSessionOnError(Error err,
                                      const std::string& description) {
  DCHECK_LT(err, ERR_IO_PENDING);
  DoDrainSession(err, description);
}

void SpdySession::MakeUnavailable() {
  if (availability_state_ == STATE_AVAILABLE) {
    availability_state_ = STATE_GOING_AWAY;
    pool_->MakeSessionUnavailable(GetWeakPtr());
  }
}

void SpdySession::StartGoingAway(spdy::SpdyStreamId last_good_stream_id,
                                 Error status) {
  DCHECK_GE(availability_state_, STATE_GOING_AWAY);
  DCHECK_NE(OK, status);
  DCHECK_NE(ERR_IO_PENDING, status);

  // The loops below are carefully written to avoid reentrancy problems.

  NotifyRequestsOfConfirmation(status);

  while (true) {
    size_t old_size = GetTotalSize(pending_create_stream_queues_);
    base::WeakPtr<SpdyStreamRequest> pending_request =
        GetNextPendingStreamRequest();
    if (!pending_request)
      break;
    // No new stream requests should be added while the session is
    // going away.
    DCHECK_GT(old_size, GetTotalSize(pending_create_stream_queues_));
    pending_request->OnRequestCompleteFailure(status);
  }

  while (true) {
    size_t old_size = active_streams_.size();
    auto it = active_streams_.lower_bound(last_good_stream_id + 1);
    if (it == active_streams_.end())
      break;
    LogAbandonedActiveStream(it, status);
    CloseActiveStreamIterator(it, status);
    // No new streams should be activated while the session is going
    // away.
    DCHECK_GT(old_size, active_streams_.size());
  }

  while (!created_streams_.empty()) {
    size_t old_size = created_streams_.size();
    auto it = created_streams_.begin();
    LogAbandonedStream(*it, status);
    CloseCreatedStreamIterator(it, status);
    // No new streams should be created while the session is going
    // away.
    DCHECK_GT(old_size, created_streams_.size());
  }

  write_queue_.RemovePendingWritesForStreamsAfter(last_good_stream_id);

  DcheckGoingAway();
  MaybeFinishGoingAway();
}

void SpdySession::MaybeFinishGoingAway() {
  if (active_streams_.empty() && created_streams_.empty() &&
      availability_state_ == STATE_GOING_AWAY) {
    DoDrainSession(OK, "Finished going away");
  }
}

base::Value::Dict SpdySession::GetInfoAsValue() const {
  DCHECK(buffered_spdy_framer_.get());

  auto dict =
      base::Value::Dict()
          .Set("source_id", static_cast<int>(net_log_.source().id))
          .Set("host_port_pair", host_port_pair().ToString())
          .Set("proxy", host_port_proxy_pair().second.ToDebugString())
          .Set("network_anonymization_key",
               spdy_session_key_.network_anonymization_key().ToDebugString())
          .Set("active_streams", static_cast<int>(active_streams_.size()))
          .Set("negotiated_protocol",
               NextProtoToString(socket_->GetNegotiatedProtocol()))
          .Set("error", error_on_close_)
          .Set("max_concurrent_streams",
               static_cast<int>(max_concurrent_streams_))
          .Set("streams_initiated_count", streams_initiated_count_)
          .Set("streams_abandoned_count", streams_abandoned_count_)
          .Set("frames_received", buffered_spdy_framer_->frames_received())
          .Set("send_window_size", session_send_window_size_)
          .Set("recv_window_size", session_recv_window_size_)
          .Set("unacked_recv_window_bytes", session_unacked_recv_window_bytes_);

  if (!pooled_aliases_.empty()) {
    base::Value::List alias_list;
    for (const auto& alias : pooled_aliases_) {
      alias_list.Append(alias.host_port_pair().ToString());
    }
    dict.Set("aliases", std::move(alias_list));
  }
  return dict;
}

bool SpdySession::IsReused() const {
  if (buffered_spdy_framer_->frames_received() > 0)
    return true;

  // If there's no socket pool in use (i.e., |owned_stream_socket_| is
  // non-null), then the SpdySession could only have been created with freshly
  // connected socket, since canceling the H2 session request would have
  // destroyed the socket.
  return owned_stream_socket_ ||
         stream_socket_handle_->reuse_type() ==
             StreamSocketHandle::SocketReuseType::kUnusedIdle;
}

bool SpdySession::GetLoadTimingInfo(spdy::SpdyStreamId stream_id,
                                    LoadTimingInfo* load_timing_info) const {
  if (stream_socket_handle_) {
    DCHECK(!connect_timing_);
    return stream_socket_handle_->GetLoadTimingInfo(stream_id != kFirstStreamId,
                                                    load_timing_info);
  }

  DCHECK(connect_timing_);
  DCHECK(socket_);

  // The socket is considered "fresh" (not reused) only for the first stream on
  // a SPDY session. All others consider it reused, and don't return connection
  // establishment timing information.
  load_timing_info->socket_reused = (stream_id != kFirstStreamId);
  if (!load_timing_info->socket_reused)
    load_timing_info->connect_timing = *connect_timing_;

  load_timing_info->socket_log_id = socket_->NetLog().source().id;

  return true;
}

int SpdySession::GetPeerAddress(IPEndPoint* address) const {
  if (socket_)
    return socket_->GetPeerAddress(address);

  return ERR_SOCKET_NOT_CONNECTED;
}

int SpdySession::GetLocalAddress(IPEndPoint* address) const {
  if (socket_)
    return socket_->GetLocalAddress(address);

  return ERR_SOCKET_NOT_CONNECTED;
}

void SpdySession::AddPooledAlias(const SpdySessionKey& alias_key) {
  pooled_aliases_.insert(alias_key);
}

void SpdySession::RemovePooledAlias(const SpdySessionKey& alias_key) {
  pooled_aliases_.erase(alias_key);
}

bool SpdySession::HasAcceptableTransportSecurity() const {
  SSLInfo ssl_info;
  CHECK(GetSSLInfo(&ssl_info));

  // HTTP/2 requires TLS 1.2+
  if (SSLConnectionStatusToVersion(ssl_info.connection_status) <
      SSL_CONNECTION_VERSION_TLS1_2) {
    return false;
  }

  if (!IsTLSCipherSuiteAllowedByHTTP2(
          SSLConnectionStatusToCipherSuite(ssl_info.connection_status))) {
    return false;
  }

  return true;
}

base::WeakPtr<SpdySession> SpdySession::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

bool SpdySession::CloseOneIdleConnection() {
  CHECK(!in_io_loop_);
  DCHECK(pool_);
  if (active_streams_.empty()) {
    DoDrainSession(ERR_CONNECTION_CLOSED, "Closing idle connection.");
  }
  // Return false as the socket wasn't immediately closed.
  return false;
}

bool SpdySession::ChangeSocketTag(const SocketTag& new_tag) {
  if (!IsAvailable() || !socket_)
    return false;

  // Changing the tag on the underlying socket will affect all streams,
  // so only allow changing the tag when there are no active streams.
  if (is_active())
    return false;

  socket_->ApplySocketTag(new_tag);

  SpdySessionKey new_key(
      spdy_session_key_.host_port_pair(), spdy_session_key_.privacy_mode(),
      spdy_session_key_.proxy_chain(), spdy_session_key_.session_usage(),
      new_tag, spdy_session_key_.network_anonymization_key(),
      spdy_session_key_.secure_dns_policy(),
      spdy_session_key_.disable_cert_verification_network_fetches());
  spdy_session_key_ = new_key;

  return true;
}

void SpdySession::EnableBrokenConnectionDetection(
    base::TimeDelta heartbeat_interval) {
  DCHECK_GE(broken_connection_detection_requests_, 0);
  if (broken_connection_detection_requests_++ > 0)
    return;

  DCHECK(!IsBrokenConnectionDetectionEnabled());
  NetworkChangeNotifier::AddDefaultNetworkActiveObserver(this);
  heartbeat_interval_ = heartbeat_interval;
  heartbeat_timer_.Start(
      FROM_HERE, heartbeat_interval_,
      base::BindOnce(&SpdySession::MaybeCheckConnectionStatus,
                     weak_factory_.GetWeakPtr()));
}

bool SpdySession::IsBrokenConnectionDetectionEnabled() const {
  return heartbeat_timer_.IsRunning();
}

void SpdySession::InitializeInternal(SpdySessionPool* pool) {
  CHECK(!in_io_loop_);
  DCHECK_EQ(availability_state_, STATE_AVAILABLE);
  DCHECK_EQ(read_state_, READ_STATE_DO_READ);
  DCHECK_EQ(write_state_, WRITE_STATE_IDLE);

  session_send_window_size_ = kDefaultInitialWindowSize;
  session_recv_window_size_ = kDefaultInitialWindowSize;

  buffered_spdy_framer_ = std::make_unique<BufferedSpdyFramer>(
      initial_settings_.find(spdy::SETTINGS_MAX_HEADER_LIST_SIZE)->second,
      net_log_, time_func_);
  buffered_spdy_framer_->set_visitor(this);
  buffered_spdy_framer_->set_debug_visitor(this);
  buffered_spdy_framer_->UpdateHeaderDecoderTableSize(max_header_table_size_);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_INITIALIZED, [&] {
    return NetLogSpdyInitializedParams(socket_->NetLog().source());
  });

  DCHECK_EQ(availability_state_, STATE_AVAILABLE);
  if (enable_sending_initial_data_)
    SendInitialData();
  pool_ = pool;

  // Bootstrap the read loop.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&SpdySession::PumpReadLoop, weak_factory_.GetWeakPtr(),
                     READ_STATE_DO_READ, OK));
}

// {,Try}CreateStream() can be called with |in_io_loop_| set if a stream is
// being created in response to another being closed due to received data.

int SpdySession::TryCreateStream(
    const base::WeakPtr<SpdyStreamRequest>& request,
    base::WeakPtr<SpdyStream>* stream) {
  DCHECK(request);

  if (availability_state_ == STATE_GOING_AWAY)
    return ERR_FAILED;

  if (availability_state_ == STATE_DRAINING)
    return ERR_CONNECTION_CLOSED;

  // Fail if ChangeSocketTag() has been called.
  if (request->socket_tag_ != spdy_session_key_.socket_tag())
    return ERR_FAILED;

  if ((active_streams_.size() + created_streams_.size() <
       max_concurrent_streams_)) {
    return CreateStream(*request, stream);
  }

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_STALLED_MAX_STREAMS, [&] {
    return NetLogSpdySessionStalledParams(
        active_streams_.size(), created_streams_.size(),
        max_concurrent_streams_, request->url().spec());
  });

  RequestPriority priority = request->priority();
  CHECK_GE(priority, MINIMUM_PRIORITY);
  CHECK_LE(priority, MAXIMUM_PRIORITY);
  pending_create_stream_queues_[priority].push_back(request);
  return ERR_IO_PENDING;
}

int SpdySession::CreateStream(const SpdyStreamRequest& request,
                              base::WeakPtr<SpdyStream>* stream) {
  DCHECK_GE(request.priority(), MINIMUM_PRIORITY);
  DCHECK_LE(request.priority(), MAXIMUM_PRIORITY);

  if (availability_state_ == STATE_GOING_AWAY)
    return ERR_FAILED;

  if (availability_state_ == STATE_DRAINING)
    return ERR_CONNECTION_CLOSED;

  DCHECK(socket_);
  UMA_HISTOGRAM_BOOLEAN("Net.SpdySession.CreateStreamWithSocketConnected",
                        socket_->IsConnected());
  if (!socket_->IsConnected()) {
    DoDrainSession(
        ERR_CONNECTION_CLOSED,
        "Tried to create SPDY stream for a closed socket connection.");
    return ERR_CONNECTION_CLOSED;
  }

  auto new_stream = std::make_unique<SpdyStream>(
      request.type(), GetWeakPtr(), request.url(), request.priority(),
      stream_initial_send_window_size_, stream_max_recv_window_size_,
      request.net_log(), request.traffic_annotation(),
      request.detect_broken_connection_);
  *stream = new_stream->GetWeakPtr();
  InsertCreatedStream(std::move(new_stream));
  if (request.detect_broken_connection_)
    EnableBrokenConnectionDetection(request.heartbeat_interval_);

  return OK;
}

bool SpdySession::CancelStreamRequest(
    const base::WeakPtr<SpdyStreamRequest>& request) {
  DCHECK(request);
  RequestPriority priority = request->priority();
  CHECK_GE(priority, MINIMUM_PRIORITY);
  CHECK_LE(priority, MAXIMUM_PRIORITY);

#if DCHECK_IS_ON()
  // |request| should not be in a queue not matching its priority.
  for (int i = MINIMUM_PRIORITY; i <= MAXIMUM_PRIORITY; ++i) {
    if (priority == i)
      continue;
    DCHECK(!base::Contains(pending_create_stream_queues_[i], request.get(),
                           &base::WeakPtr<SpdyStreamRequest>::get));
  }
#endif

  PendingStreamRequestQueue* queue = &pending_create_stream_queues_[priority];
  // Remove |request| from |queue| while preserving the order of the
  // other elements.
  PendingStreamRequestQueue::iterator it = base::ranges::find(
      *queue, request.get(), &base::WeakPtr<SpdyStreamRequest>::get);
  // The request may already be removed if there's a
  // CompleteStreamRequest() in flight.
  if (it != queue->end()) {
    it = queue->erase(it);
    // |request| should be in the queue at most once, and if it is
    // present, should not be pending completion.
    DCHECK(base::ranges::find(it, queue->end(), request.get(),
                              &base::WeakPtr<SpdyStreamRequest>::get) ==
           queue->end());
    return true;
  }
  return false;
}

void SpdySession::ChangeStreamRequestPriority(
    const base::WeakPtr<SpdyStreamRequest>& request,
    RequestPriority priority) {
  // |request->priority()| is updated by the caller after this returns.
  // |request| needs to still have its old priority in order for
  // CancelStreamRequest() to find it in the correct queue.
  DCHECK_NE(priority, request->priority());
  if (CancelStreamRequest(request)) {
    pending_create_stream_queues_[priority].push_back(request);
  }
}

base::WeakPtr<SpdyStreamRequest> SpdySession::GetNextPendingStreamRequest() {
  for (int j = MAXIMUM_PRIORITY; j >= MINIMUM_PRIORITY; --j) {
    if (pending_create_stream_queues_[j].empty())
      continue;

    base::WeakPtr<SpdyStreamRequest> pending_request =
        pending_create_stream_queues_[j].front();
    DCHECK(pending_request);
    pending_create_stream_queues_[j].pop_front();
    return pending_request;
  }
  return base::WeakPtr<SpdyStreamRequest>();
}

void SpdySession::ProcessPendingStreamRequests() {
  size_t max_requests_to_process =
      max_concurrent_streams_ -
      (active_streams_.size() + created_streams_.size());
  for (size_t i = 0; i < max_requests_to_process; ++i) {
    base::WeakPtr<SpdyStreamRequest> pending_request =
        GetNextPendingStreamRequest();
    if (!pending_request)
      break;

    // Note that this post can race with other stream creations, and it's
    // possible that the un-stalled stream will be stalled again if it loses.
    // TODO(jgraettinger): Provide stronger ordering guarantees.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&SpdySession::CompleteStreamRequest,
                                  weak_factory_.GetWeakPtr(), pending_request));
  }
}

void SpdySession::CloseActiveStreamIterator(ActiveStreamMap::iterator it,
                                            int status) {
  // TODO(mbelshe): We should send a RST_STREAM control frame here
  //                so that the server can cancel a large send.

  std::unique_ptr<SpdyStream> owned_stream(it->second);
  active_streams_.erase(it);
  priority_dependency_state_.OnStreamDestruction(owned_stream->stream_id());

  DeleteStream(std::move(owned_stream), status);

  if (active_streams_.empty() && created_streams_.empty()) {
    // If the socket belongs to a socket pool, and there are no active streams,
    // and the socket pool is stalled, then close the session to free up a
    // socket slot.
    if (stream_socket_handle_ && stream_socket_handle_->IsPoolStalled()) {
      DoDrainSession(ERR_CONNECTION_CLOSED, "Closing idle connection.");
    } else {
      MaybeFinishGoingAway();
    }
  }
}

void SpdySession::CloseCreatedStreamIterator(CreatedStreamSet::iterator it,
                                             int status) {
  std::unique_ptr<SpdyStream> owned_stream(*it);
  created_streams_.erase(it);
  DeleteStream(std::move(owned_stream), status);
}

void SpdySession::ResetStreamIterator(ActiveStreamMap::iterator it,
                                      int error,
                                      const std::string& description) {
  // Send the RST_STREAM frame first as CloseActiveStreamIterator()
  // may close us.
  spdy::SpdyErrorCode error_code = spdy::ERROR_CODE_PROTOCOL_ERROR;
  if (error == ERR_FAILED) {
    error_code = spdy::ERROR_CODE_INTERNAL_ERROR;
  } else if (error == ERR_ABORTED) {
    error_code = spdy::ERROR_CODE_CANCEL;
  } else if (error == ERR_HTTP2_FLOW_CONTROL_ERROR) {
    error_code = spdy::ERROR_CODE_FLOW_CONTROL_ERROR;
  } else if (error == ERR_TIMED_OUT) {
    error_code = spdy::ERROR_CODE_REFUSED_STREAM;
  } else if (error == ERR_HTTP2_STREAM_CLOSED) {
    error_code = spdy::ERROR_CODE_STREAM_CLOSED;
  }
  spdy::SpdyStreamId stream_id = it->first;
  RequestPriority priority = it->second->priority();
  EnqueueResetStreamFrame(stream_id, priority, error_code, description);

  // Removes any pending writes for the stream except for possibly an
  // in-flight one.
  CloseActiveStreamIterator(it, error);
}

void SpdySession::EnqueueResetStreamFrame(spdy::SpdyStreamId stream_id,
                                          RequestPriority priority,
                                          spdy::SpdyErrorCode error_code,
                                          const std::string& description) {
  DCHECK_NE(stream_id, 0u);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_SEND_RST_STREAM, [&] {
    return NetLogSpdySendRstStreamParams(stream_id, error_code, description);
  });

  DCHECK(buffered_spdy_framer_.get());
  std::unique_ptr<spdy::SpdySerializedFrame> rst_frame(
      buffered_spdy_framer_->CreateRstStream(stream_id, error_code));

  EnqueueSessionWrite(priority, spdy::SpdyFrameType::RST_STREAM,
                      std::move(rst_frame));
  RecordProtocolErrorHistogram(MapRstStreamStatusToProtocolError(error_code));
}

void SpdySession::EnqueuePriorityFrame(spdy::SpdyStreamId stream_id,
                                       spdy::SpdyStreamId dependency_id,
                                       int weight,
                                       bool exclusive) {
  net_log_.AddEvent(NetLogEventType::HTTP2_STREAM_SEND_PRIORITY, [&] {
    return NetLogSpdyPriorityParams(stream_id, dependency_id, weight,
                                    exclusive);
  });

  DCHECK(buffered_spdy_framer_.get());
  std::unique_ptr<spdy::SpdySerializedFrame> frame(
      buffered_spdy_framer_->CreatePriority(stream_id, dependency_id, weight,
                                            exclusive));

  // PRIORITY frames describe sequenced updates to the tree, so the
```
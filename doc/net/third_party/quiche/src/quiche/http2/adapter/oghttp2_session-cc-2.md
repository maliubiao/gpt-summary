Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the Chromium network stack related to HTTP/2. They are specifically interested in:

1. **General functionality:** What does this code do?
2. **Relationship to JavaScript:**  Are there any connections or interactions with JavaScript?
3. **Logical inferences:**  Can we deduce any behavior based on input and output?
4. **Common usage errors:** What mistakes might a user or programmer make when using this code?
5. **User journey:** How might a user's actions lead to this code being executed?
6. **Overall summary:** A concise description of the code's role.

**Plan:**

1. **Analyze the code:** Break down the methods and their purpose. Identify key data structures and interactions.
2. **JavaScript relationship:** Consider how HTTP/2 interactions in a browser (often initiated by JavaScript) might lead to this code being executed.
3. **Logical inferences:** Examine methods that take input and produce output to understand their behavior.
4. **Usage errors:** Think about common mistakes when configuring or interacting with an HTTP/2 session.
5. **User journey:**  Trace the steps from a user action in a browser to the execution of this C++ code.
6. **Summarize:**  Provide a high-level overview of the code's functionality.
这是 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session.cc` 文件代码的第三部分，主要负责处理 HTTP/2 会话中与数据发送、窗口管理、错误处理以及会话生命周期管理相关的操作。以下是对其功能的详细说明：

**主要功能归纳:**

延续前两部分，这部分代码主要负责 HTTP/2 会话的**出站数据处理、流量控制、错误处理和会话状态管理**。它定义了 `OgHttp2Session` 类中用于发送各种 HTTP/2 帧、更新窗口大小、处理连接错误以及管理流状态的方法。

**具体功能列举:**

* **准备 SETTINGS 帧:**
    * `PrepareSettingsFrame`:  将 `Http2Setting` 类型的设置转换为 `SpdySettingsIR` 对象，用于创建 SETTINGS 帧。
    * **假设输入:**  一个包含 `Http2Setting` 结构体（例如，`{{SETTINGS_MAX_CONCURRENT_STREAMS, 100}}`）的 `absl::Span`。
    * **假设输出:**  一个指向 `SpdySettingsIR` 对象的 `std::unique_ptr`，该对象内部存储了要发送的设置（例如，`id: 4, value: 100`）。

* **处理出站 SETTINGS 帧:**
    * `HandleOutboundSettings`:  处理即将发送的 SETTINGS 帧，并预先记录需要在收到 ACK 后执行的操作（通过 `settings_ack_callbacks_` 存储回调函数）。对于某些设置，例如 `MAX_CONCURRENT_STREAMS`，会立即更新本地的待生效值。
    * **逻辑推理:**  当发送 `MAX_CONCURRENT_STREAMS` 设置时，在收到 ACK 之前，会先将该值存储在 `pending_max_inbound_concurrent_streams_` 中，而实际生效的值 `max_inbound_concurrent_streams_` 则在收到 ACK 后更新。

* **发送 WINDOW_UPDATE 帧:**
    * `SendWindowUpdate`:  创建一个 `SpdyWindowUpdateIR` 对象并将其加入待发送队列，用于通知对端增加接收窗口。

* **发送 HEADERS 帧:**
    * `SendHeaders`:  创建一个 `SpdyHeadersIR` 对象并将其加入待发送队列，用于发送 HTTP 头部。可以设置 `end_stream` 标志来表示流的结束。

* **发送 TRAILERS 帧:**
    * `SendTrailers`:  创建一个 `SpdyHeadersIR` 对象并将其加入待发送队列，用于发送 HTTP 尾部。尾部总是表示流的结束。

* **使用 RST_STREAM 帧终止流:**
    * `MaybeFinWithRstStream`:  根据条件决定是否发送 RST_STREAM 帧来提前终止一个本地已关闭写入的流。服务端在远端未结束流的情况下，可能会发送 RST_STREAM NO_ERROR。
    * **假设输入:**  一个指向 `stream_map_` 中元素的迭代器，该流的 `half_closed_local` 为 true。
    * **假设输出:**  如果条件满足，会将一个 `SpdyRstStreamIR` 对象加入待发送队列。

* **标记数据已缓冲:**
    * `MarkDataBuffered`:  更新连接和流级别的窗口管理器，记录已缓冲但尚未发送的数据量。

* **创建新的 HTTP/2 流:**
    * `CreateStream`:  在 `stream_map_` 中创建一个新的 `StreamState` 条目，并将其注册到写调度器中。

* **启动请求发送:**
    * `StartRequest`:  开始发送一个新的 HTTP 请求。如果提供了数据源，则将其关联到流，否则根据 `end_stream` 决定是否需要等待数据。会发送初始的 HEADERS 帧。
    * **与 JavaScript 的关系:** 当 JavaScript 代码通过 Fetch API 或 XMLHttpRequest 发起一个 HTTP/2 请求时，浏览器网络栈会调用类似的方法来创建和启动 HTTP/2 流。例如，`fetch('/api/data', { method: 'POST', body: jsonData })` 可能会触发此方法，其中 `jsonData` 对应 `data_source`。

* **启动待处理的流:**
    * `StartPendingStreams`:  检查是否有待处理的流（由于并发连接数限制而等待），并尝试启动它们。

* **关闭 HTTP/2 流:**
    * `CloseStream`:  关闭指定的 HTTP/2 流。通知 `visitor_`，移除流的状态信息，并清理相关的待发送帧。
    * **用户或编程常见的使用错误:**  在流还在活跃时就尝试释放与流相关的资源，可能导致访问已释放内存。例如，在 `OnCloseStream` 回调之前就尝试删除与流关联的数据结构。

* **判断是否可以创建新流:**
    * `CanCreateStream`:  检查当前活跃的出站流数量是否低于配置的最大并发流数量。

* **确定下一个需要发送的头部类型:**
    * `NextHeaderType`:  根据当前状态判断下一个应该发送的头部是请求头、请求尾或者响应头、响应尾。

* **处理连接错误:**
    * `LatchErrorAndNotify`:  记录连接错误状态，通知 `visitor_`，并发送 GOAWAY 帧。

* **根据帧类型和流状态关闭流:**
    * `CloseStreamIfReady`:  根据接收到的帧类型（例如 RST_STREAM）或者流的本地和远端状态都为半关闭，来决定是否关闭流。

* **关闭被 GOAWAY 拒绝的流:**
    * `CloseGoAwayRejectedStreams`:  关闭由于接收到 GOAWAY 帧而被拒绝的流。

* **准备立即发送 GOAWAY 帧:**
    * `PrepareForImmediateGoAway`:  清空待发送帧队列，只保留 RST_STREAM 帧，并标记即将发送 GOAWAY 帧。

* **处理元数据结束:**
    * `MaybeHandleMetadataEndForStream`:  在元数据长度和结束标志满足条件时，通知 `visitor_` 元数据已结束。

* **递减排队帧计数:**
    * `DecrementQueuedFrameCount`:  减少特定流的待发送帧计数，并在计数归零时尝试关闭流。

* **处理 Content-Length 错误:**
    * `HandleContentLengthError`:  当检测到 Content-Length 不一致时，通知 `visitor_` 并发送 RST_STREAM 帧。

* **更新接收窗口:**
    * `UpdateReceiveWindow`:  根据收到的 WINDOW_UPDATE 帧更新连接或特定流的接收窗口大小。

* **更新流的发送窗口大小:**
    * `UpdateStreamSendWindowSizes`:  根据新的初始发送窗口大小更新所有活跃流的发送窗口。

* **更新流的接收窗口大小限制:**
    * `UpdateStreamReceiveWindowSizes`:  当收到 SETTINGS 帧更新初始窗口大小时，更新所有活跃流的窗口管理器。

* **判断流是否有更多数据待发送:**
    * `HasMoreData`:  检查流是否关联了数据源或者是否需要从 `visitor_` 获取数据。

* **判断流是否准备好发送数据:**
    * `IsReadyToWriteData`:  检查流是否有数据待发送且当前未被延迟发送。

* **放弃发送流的数据:**
    * `AbandonData`:  清除流关联的数据源，表示放弃发送剩余的数据。

* **获取 DATA 帧的信息:**
    * `GetDataFrameInfo`:  根据流的状态和可用的流量控制窗口，确定要发送的 DATA 帧的负载长度和结束标志。

* **实际发送 DATA 帧:**
    * `SendDataFrame`:  调用数据源或 `visitor_` 的方法来实际发送 DATA 帧的负载。

**与 JavaScript 的关系举例:**

1. 当 JavaScript 使用 `fetch()` 发起一个带有 `body` 的 POST 请求时，Chrome 的网络栈会创建对应的 HTTP/2 流，并调用 `StartRequest` 方法，将请求头和 `body` 数据封装起来。`body` 数据可能会被包装成一个 `DataFrameSource` 对象。
2. 当服务器通过 PUSH_PROMISE 主动向客户端推送资源时，相关的流创建和数据发送也由 `OgHttp2Session` 管理。这些推送的资源可以被 JavaScript 代码访问。
3. JavaScript 代码可能会设置一些影响 HTTP/2 连接的选项，例如通过 `navigator.connection.downlinkMax` 获取网络带宽信息，这些信息可能间接影响到 `OgHttp2Session` 的窗口管理策略。

**逻辑推理举例:**

* **假设输入:** 在一个 HTTP/2 连接上，服务端发送了一个 SETTINGS 帧，其中 `MAX_CONCURRENT_STREAMS` 的值为 10。
* **输出:** `HandleOutboundSettings` 方法会被调用，并且 `pending_max_inbound_concurrent_streams_` 会被设置为 10。当收到该 SETTINGS 帧的 ACK 后，`max_inbound_concurrent_streams_` 也会被设置为 10，从而限制了客户端可以同时创建的流的数量。

**用户或编程常见的使用错误举例:**

1. **过早关闭流:** 用户代码在数据还未完全发送完毕或者响应还未完全接收时就关闭了相关的流，可能导致数据丢失或者连接错误。
2. **不正确的窗口管理:**  程序员可能错误地计算或更新窗口大小，导致流量控制出现问题，例如发送方发送过多数据超出接收方窗口，或者接收方长时间不更新窗口导致发送方阻塞。
3. **错误地处理 `OnCloseStream` 回调:**  在 `OnCloseStream` 回调中，如果尝试访问已经被释放的流相关资源，会导致程序崩溃。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中输入 URL 并访问网站，或者 JavaScript 代码发起网络请求 (例如使用 `fetch` 或 `XMLHttpRequest`)。**
2. **浏览器解析 URL，并确定需要使用 HTTP/2 协议与服务器建立连接。**
3. **如果尚未建立连接，浏览器会进行 TCP 握手和 TLS 握手。**
4. **在 TLS 握手完成后，会发送 HTTP/2 连接前导码。**
5. **`OgHttp2Session` 对象被创建，用于管理该 HTTP/2 会话。**
6. **当需要发送请求头、请求体或接收响应时，`OgHttp2Session` 的相关方法会被调用，例如 `StartRequest`, `SendHeaders`, `SendDataFrame` 等。**
7. **如果服务器发送 SETTINGS 帧，`HandleOutboundSettings` 方法会被调用处理这些设置。**
8. **如果需要调整发送或接收窗口，`SendWindowUpdate` 或 `UpdateReceiveWindow` 方法会被调用。**
9. **如果发生错误，例如协议错误或连接超时，`LatchErrorAndNotify` 方法会被调用发送 GOAWAY 帧并通知上层。**
10. **当流结束或者连接关闭时，`CloseStream` 方法会被调用清理资源。**

**总结 `OgHttp2Session` 的功能 (全部三部分):**

`OgHttp2Session` 类是 Chromium 网络栈中负责处理 HTTP/2 会话的核心组件。它实现了 HTTP/2 协议的状态机，负责管理连接的生命周期、处理帧的发送和接收、维护流的状态、进行流量控制、处理错误以及与上层应用（通过 `Http2VisitorInterface`) 进行交互。它将底层的帧处理和连接管理细节抽象出来，为上层提供了一个易于使用的 HTTP/2 会话接口。

这第三部分主要关注**出站数据处理、流量控制、错误处理和会话状态管理**，确保数据能够正确且高效地发送到对端，并处理各种可能出现的错误情况，维持会话的稳定运行。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
s;
}

std::unique_ptr<SpdySettingsIR> OgHttp2Session::PrepareSettingsFrame(
    absl::Span<const Http2Setting> settings) {
  auto settings_ir = std::make_unique<SpdySettingsIR>();
  for (const Http2Setting& setting : settings) {
    settings_ir->AddSetting(setting.id, setting.value);
  }
  return settings_ir;
}

void OgHttp2Session::HandleOutboundSettings(
    const spdy::SpdySettingsIR& settings_frame) {
  for (const auto& [id, value] : settings_frame.values()) {
    switch (static_cast<Http2KnownSettingsId>(id)) {
      case MAX_CONCURRENT_STREAMS:
        pending_max_inbound_concurrent_streams_ = value;
        break;
      case ENABLE_CONNECT_PROTOCOL:
        if (value == 1u && IsServerSession()) {
          // Allow extended CONNECT semantics even before SETTINGS are acked, to
          // make things easier for clients.
          headers_handler_.SetAllowExtendedConnect();
        }
        break;
      case HEADER_TABLE_SIZE:
      case ENABLE_PUSH:
      case INITIAL_WINDOW_SIZE:
      case MAX_FRAME_SIZE:
      case MAX_HEADER_LIST_SIZE:
        QUICHE_VLOG(2)
            << "Not adjusting internal state for outbound setting with id "
            << id;
        break;
    }
  }

  // Copy the (small) map of settings we are about to send so that we can set
  // values in the SETTINGS ack callback.
  settings_ack_callbacks_.push_back(
      [this, settings_map = settings_frame.values()]() {
        for (const auto& [id, value] : settings_map) {
          switch (static_cast<Http2KnownSettingsId>(id)) {
            case MAX_CONCURRENT_STREAMS:
              max_inbound_concurrent_streams_ = value;
              break;
            case HEADER_TABLE_SIZE:
              decoder_.GetHpackDecoder().ApplyHeaderTableSizeSetting(value);
              break;
            case INITIAL_WINDOW_SIZE:
              UpdateStreamReceiveWindowSizes(value);
              initial_stream_receive_window_ = value;
              break;
            case MAX_FRAME_SIZE:
              decoder_.SetMaxFrameSize(value);
              break;
            case ENABLE_PUSH:
            case MAX_HEADER_LIST_SIZE:
            case ENABLE_CONNECT_PROTOCOL:
              QUICHE_VLOG(2)
                  << "No action required in ack for outbound setting with id "
                  << id;
              break;
          }
        }
      });
}

void OgHttp2Session::SendWindowUpdate(Http2StreamId stream_id,
                                      size_t update_delta) {
  EnqueueFrame(
      std::make_unique<spdy::SpdyWindowUpdateIR>(stream_id, update_delta));
}

void OgHttp2Session::SendHeaders(Http2StreamId stream_id,
                                 quiche::HttpHeaderBlock headers,
                                 bool end_stream) {
  auto frame =
      std::make_unique<spdy::SpdyHeadersIR>(stream_id, std::move(headers));
  frame->set_fin(end_stream);
  EnqueueFrame(std::move(frame));
}

void OgHttp2Session::SendTrailers(Http2StreamId stream_id,
                                  quiche::HttpHeaderBlock trailers) {
  auto frame =
      std::make_unique<spdy::SpdyHeadersIR>(stream_id, std::move(trailers));
  frame->set_fin(true);
  EnqueueFrame(std::move(frame));
  trailers_ready_.erase(stream_id);
}

void OgHttp2Session::MaybeFinWithRstStream(StreamStateMap::iterator iter) {
  QUICHE_DCHECK(iter != stream_map_.end() && iter->second.half_closed_local);

  if (options_.rst_stream_no_error_when_incomplete && IsServerSession() &&
      !iter->second.half_closed_remote) {
    // Since the peer has not yet ended the stream, this endpoint should
    // send a RST_STREAM NO_ERROR. See RFC 7540 Section 8.1.
    EnqueueFrame(std::make_unique<spdy::SpdyRstStreamIR>(
        iter->first, spdy::SpdyErrorCode::ERROR_CODE_NO_ERROR));
    iter->second.half_closed_remote = true;
  }
}

void OgHttp2Session::MarkDataBuffered(Http2StreamId stream_id, size_t bytes) {
  connection_window_manager_.MarkDataBuffered(bytes);
  if (auto it = stream_map_.find(stream_id); it != stream_map_.end()) {
    it->second.window_manager.MarkDataBuffered(bytes);
  }
}

OgHttp2Session::StreamStateMap::iterator OgHttp2Session::CreateStream(
    Http2StreamId stream_id) {
  WindowManager::WindowUpdateListener listener =
      [this, stream_id](size_t window_update_delta) {
        SendWindowUpdate(stream_id, window_update_delta);
      };
  auto [iter, inserted] = stream_map_.try_emplace(
      stream_id,
      StreamState(initial_stream_receive_window_, initial_stream_send_window_,
                  std::move(listener), options_.should_window_update_fn));
  if (inserted) {
    // Add the stream to the write scheduler.
    const spdy::SpdyPriority priority = 3;
    write_scheduler_.RegisterStream(stream_id, priority);

    highest_processed_stream_id_ =
        std::max(highest_processed_stream_id_, stream_id);
  }
  return iter;
}

void OgHttp2Session::StartRequest(Http2StreamId stream_id,
                                  quiche::HttpHeaderBlock headers,
                                  std::unique_ptr<DataFrameSource> data_source,
                                  void* user_data, bool end_stream) {
  if (received_goaway_) {
    // Do not start new streams after receiving a GOAWAY.
    goaway_rejected_streams_.insert(stream_id);
    return;
  }

  auto iter = CreateStream(stream_id);
  if (data_source != nullptr) {
    iter->second.outbound_body = std::move(data_source);
    write_scheduler_.MarkStreamReady(stream_id, false);
  } else if (!end_stream) {
    iter->second.check_visitor_for_body = true;
    write_scheduler_.MarkStreamReady(stream_id, false);
  }
  iter->second.user_data = user_data;
  for (const auto& [name, value] : headers) {
    if (name == kHttp2MethodPseudoHeader && value == kHeadValue) {
      iter->second.sent_head_method = true;
    }
  }
  SendHeaders(stream_id, std::move(headers), end_stream);
}

void OgHttp2Session::StartPendingStreams() {
  while (!pending_streams_.empty() && CanCreateStream()) {
    auto& [stream_id, pending_stream] = pending_streams_.front();
    StartRequest(stream_id, std::move(pending_stream.headers),
                 std::move(pending_stream.data_source),
                 pending_stream.user_data, pending_stream.end_stream);
    pending_streams_.pop_front();
  }
}

void OgHttp2Session::CloseStream(Http2StreamId stream_id,
                                 Http2ErrorCode error_code) {
  const bool result = visitor_.OnCloseStream(stream_id, error_code);
  if (!result) {
    latched_error_ = true;
    decoder_.StopProcessing();
  }
  stream_map_.erase(stream_id);
  trailers_ready_.erase(stream_id);
  streams_reset_.erase(stream_id);
  auto queued_it = queued_frames_.find(stream_id);
  if (queued_it != queued_frames_.end()) {
    // Remove any queued frames for this stream.
    int frames_remaining = queued_it->second;
    queued_frames_.erase(queued_it);
    for (auto it = frames_.begin();
         frames_remaining > 0 && it != frames_.end();) {
      if (static_cast<Http2StreamId>((*it)->stream_id()) == stream_id) {
        it = frames_.erase(it);
        --frames_remaining;
      } else {
        ++it;
      }
    }
  }
  if (write_scheduler_.StreamRegistered(stream_id)) {
    write_scheduler_.UnregisterStream(stream_id);
  }

  StartPendingStreams();
}

bool OgHttp2Session::CanCreateStream() const {
  return stream_map_.size() < max_outbound_concurrent_streams_;
}

HeaderType OgHttp2Session::NextHeaderType(
    std::optional<HeaderType> current_type) {
  if (IsServerSession()) {
    if (!current_type) {
      return HeaderType::REQUEST;
    } else {
      return HeaderType::REQUEST_TRAILER;
    }
  } else if (!current_type || *current_type == HeaderType::RESPONSE_100) {
    return HeaderType::RESPONSE;
  } else {
    return HeaderType::RESPONSE_TRAILER;
  }
}

void OgHttp2Session::LatchErrorAndNotify(Http2ErrorCode error_code,
                                         ConnectionError error) {
  if (latched_error_) {
    // Do not kick a connection when it is down.
    return;
  }

  latched_error_ = true;
  visitor_.OnConnectionError(error);
  decoder_.StopProcessing();
  EnqueueFrame(std::make_unique<spdy::SpdyGoAwayIR>(
      highest_processed_stream_id_, TranslateErrorCode(error_code),
      ConnectionErrorToString(error)));
}

void OgHttp2Session::CloseStreamIfReady(uint8_t frame_type,
                                        uint32_t stream_id) {
  auto iter = stream_map_.find(stream_id);
  if (iter == stream_map_.end()) {
    return;
  }
  const StreamState& state = iter->second;
  if (static_cast<FrameType>(frame_type) == FrameType::RST_STREAM ||
      (state.half_closed_local && state.half_closed_remote)) {
    CloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR);
  }
}

void OgHttp2Session::CloseGoAwayRejectedStreams() {
  for (Http2StreamId stream_id : goaway_rejected_streams_) {
    const bool result =
        visitor_.OnCloseStream(stream_id, Http2ErrorCode::REFUSED_STREAM);
    if (!result) {
      latched_error_ = true;
      decoder_.StopProcessing();
    }
  }
  goaway_rejected_streams_.clear();
}

void OgHttp2Session::PrepareForImmediateGoAway() {
  queued_immediate_goaway_ = true;

  // Keep the initial SETTINGS frame if the session has SETTINGS at the front of
  // the queue but has not sent SETTINGS yet. The session should send initial
  // SETTINGS before GOAWAY.
  std::unique_ptr<spdy::SpdyFrameIR> initial_settings;
  if (!sent_non_ack_settings_ && !frames_.empty() &&
      IsNonAckSettings(*frames_.front())) {
    initial_settings = std::move(frames_.front());
    frames_.pop_front();
  }

  // Remove all pending frames except for RST_STREAMs. It is important to send
  // RST_STREAMs so the peer knows of errors below the GOAWAY last stream ID.
  // TODO(diannahu): Consider informing the visitor of dropped frames. This may
  // mean keeping the frames and invoking a frame-not-sent callback, similar to
  // nghttp2. Could add a closure to each frame in the frames queue.
  frames_.remove_if([](const auto& frame) {
    return frame->frame_type() != spdy::SpdyFrameType::RST_STREAM;
  });

  if (initial_settings != nullptr) {
    frames_.push_front(std::move(initial_settings));
  }
}

void OgHttp2Session::MaybeHandleMetadataEndForStream(Http2StreamId stream_id) {
  if (metadata_length_ == 0 && end_metadata_) {
    const bool completion_success = visitor_.OnMetadataEndForStream(stream_id);
    if (!completion_success) {
      fatal_visitor_callback_failure_ = true;
      decoder_.StopProcessing();
    }
    process_metadata_ = false;
    end_metadata_ = false;
  }
}

void OgHttp2Session::DecrementQueuedFrameCount(uint32_t stream_id,
                                               uint8_t frame_type) {
  auto iter = queued_frames_.find(stream_id);
  if (iter == queued_frames_.end()) {
    QUICHE_LOG(ERROR) << "Unable to find a queued frame count for stream "
                      << stream_id;
    return;
  }
  if (static_cast<FrameType>(frame_type) != FrameType::DATA) {
    --iter->second;
  }
  if (iter->second == 0) {
    // TODO(birenroy): Consider passing through `error_code` here.
    CloseStreamIfReady(frame_type, stream_id);
  }
}

void OgHttp2Session::HandleContentLengthError(Http2StreamId stream_id) {
  if (current_frame_type_ == static_cast<uint8_t>(FrameType::HEADERS)) {
    // For consistency, either OnInvalidFrame should always be invoked,
    // regardless of frame type, or perhaps we should introduce an OnStreamError
    // callback.
    visitor_.OnInvalidFrame(
        stream_id, Http2VisitorInterface::InvalidFrameError::kHttpMessaging);
  }
  EnqueueFrame(std::make_unique<spdy::SpdyRstStreamIR>(
      stream_id, spdy::ERROR_CODE_PROTOCOL_ERROR));
}

void OgHttp2Session::UpdateReceiveWindow(Http2StreamId stream_id,
                                         int32_t delta) {
  if (stream_id == 0) {
    connection_window_manager_.IncreaseWindow(delta);
    // TODO(b/181586191): Provide an explicit way to set the desired window
    // limit, remove the upsize-on-window-update behavior.
    const int64_t current_window =
        connection_window_manager_.CurrentWindowSize();
    if (current_window > connection_window_manager_.WindowSizeLimit()) {
      connection_window_manager_.SetWindowSizeLimit(current_window);
    }
  } else {
    auto iter = stream_map_.find(stream_id);
    if (iter != stream_map_.end()) {
      WindowManager& manager = iter->second.window_manager;
      manager.IncreaseWindow(delta);
      // TODO(b/181586191): Provide an explicit way to set the desired window
      // limit, remove the upsize-on-window-update behavior.
      const int64_t current_window = manager.CurrentWindowSize();
      if (current_window > manager.WindowSizeLimit()) {
        manager.SetWindowSizeLimit(current_window);
      }
    }
  }
}

void OgHttp2Session::UpdateStreamSendWindowSizes(uint32_t new_value) {
  const int32_t delta =
      static_cast<int32_t>(new_value) - initial_stream_send_window_;
  initial_stream_send_window_ = new_value;
  for (auto& [stream_id, stream_state] : stream_map_) {
    const int64_t current_window_size = stream_state.send_window;
    const int64_t new_window_size = current_window_size + delta;
    if (new_window_size > spdy::kSpdyMaximumWindowSize) {
      EnqueueFrame(std::make_unique<spdy::SpdyRstStreamIR>(
          stream_id, spdy::ERROR_CODE_FLOW_CONTROL_ERROR));
    } else {
      stream_state.send_window += delta;
    }
    if (current_window_size <= 0 && new_window_size > 0) {
      write_scheduler_.MarkStreamReady(stream_id, false);
    }
  }
}

void OgHttp2Session::UpdateStreamReceiveWindowSizes(uint32_t new_value) {
  for (auto& [stream_id, stream_state] : stream_map_) {
    stream_state.window_manager.OnWindowSizeLimitChange(new_value);
  }
}

bool OgHttp2Session::HasMoreData(const StreamState& stream_state) const {
  return stream_state.outbound_body != nullptr ||
         stream_state.check_visitor_for_body;
}

bool OgHttp2Session::IsReadyToWriteData(const StreamState& stream_state) const {
  return HasMoreData(stream_state) && !stream_state.data_deferred;
}

void OgHttp2Session::AbandonData(StreamState& stream_state) {
  stream_state.outbound_body = nullptr;
  stream_state.check_visitor_for_body = false;
}

OgHttp2Session::DataFrameHeaderInfo OgHttp2Session::GetDataFrameInfo(
    Http2StreamId stream_id, size_t flow_control_available,
    StreamState& stream_state) {
  if (stream_state.outbound_body != nullptr) {
    DataFrameHeaderInfo info;
    std::tie(info.payload_length, info.end_data) =
        stream_state.outbound_body->SelectPayloadLength(flow_control_available);
    info.end_stream =
        info.end_data ? stream_state.outbound_body->send_fin() : false;
    return info;
  } else if (stream_state.check_visitor_for_body) {
    DataFrameHeaderInfo info =
        visitor_.OnReadyToSendDataForStream(stream_id, flow_control_available);
    info.end_data = info.end_data || info.end_stream;
    return info;
  }
  QUICHE_LOG(DFATAL) << "GetDataFrameInfo for stream " << stream_id
                     << " but no body available!";
  return {/*payload_length=*/0, /*end_data=*/true, /*end_stream=*/true};
}

bool OgHttp2Session::SendDataFrame(Http2StreamId stream_id,
                                   absl::string_view frame_header,
                                   size_t payload_length,
                                   StreamState& stream_state) {
  if (stream_state.outbound_body != nullptr) {
    return stream_state.outbound_body->Send(frame_header, payload_length);
  } else {
    QUICHE_DCHECK(stream_state.check_visitor_for_body);
    return visitor_.SendDataFrame(stream_id, frame_header, payload_length);
  }
}

}  // namespace adapter
}  // namespace http2
```
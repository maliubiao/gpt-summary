Response:
The user wants to understand the functionality of the `net/spdy/spdy_session.cc` file in Chromium's network stack, specifically the provided code snippet. I need to:

1. **Summarize the functions:** Describe what each function in the provided code does.
2. **Identify JavaScript relationships:** Explain if and how any of these functions relate to JavaScript functionality in a web browser.
3. **Provide logical input/output examples:** For some functions, create hypothetical scenarios with inputs and expected outputs.
4. **Point out common user/programming errors:** Indicate potential mistakes developers might make when interacting with this code or the concepts it represents.
5. **Describe user actions leading here:** Explain the sequence of user actions that could trigger the execution of this code.
6. **Summarize overall functionality:** Provide a concise overview of the role of this code snippet within the `SpdySession`.

**Thinking Process:**

* **Iterate through each function:**  I'll go through the code block by block, explaining the purpose of each function.
* **JavaScript connection:** I'll focus on how the network layer interacts with the rendering engine and JavaScript, particularly around data transfer and protocol events.
* **Input/Output scenarios:**  I will select a few key functions and create simple scenarios to illustrate their behavior.
* **Error Examples:** I'll think about common mistakes related to network protocols, stream management, and data handling.
* **User Action Trace:** I'll consider typical user interactions that involve network requests and how those requests are processed.
* **Overall Summary:** I will synthesize the information gathered to provide a high-level understanding of the code's function.
This is the fourth part of the `net/spdy/spdy_session.cc` file, continuing the implementation of the `SpdySession` class which handles HTTP/2 communication. Let's break down its functionality:

**Functionality Covered in This Snippet:**

This part of the `SpdySession` class focuses on handling incoming HTTP/2 frames and managing the flow control mechanisms for both the session and individual streams. Key areas include:

* **GOAWAY Frame Handling (`OnGoAway`):**  Processes the server-initiated shutdown signal, recording metrics and initiating the session's going-away process. It handles different error codes associated with GOAWAY.
* **Data Frame Handling (`OnDataFrameHeader`, `OnStreamFrameData`, `OnStreamEnd`):**  Receives and processes data chunks for a stream. It manages buffers, updates receive windows, and notifies the corresponding `SpdyStream`.
* **Padding Handling (`OnStreamPadding`):**  Accounts for padding bytes received on a stream, adjusting flow control appropriately.
* **Settings Frame Handling (`OnSettings`, `OnSettingsAck`, `OnSetting`, `OnSettingsEnd`):** Handles the reception and acknowledgement of HTTP/2 settings frames, updating the session's configuration based on the received settings.
* **Window Update Frame Handling (`OnWindowUpdate`):** Processes window update frames, increasing the send window size for either the session or a specific stream, allowing more data to be sent. It also handles potential errors in the window update.
* **PUSH_PROMISE Frame Handling (`OnPushPromise`):**  Indicates a server-initiated push, but in this implementation, receiving a PUSH_PROMISE results in draining the session as it's not fully supported here.
* **Headers Frame Handling (`OnHeaders`):**  Processes received header blocks for a stream, delivering them to the associated `SpdyStream`.
* **Alt-Svc Frame Handling (`OnAltSvc`):**  Handles Alternative Service (Alt-Svc) frames, updating the list of available alternative servers for a given origin.
* **Unknown Frame Handling (`OnUnknownFrame`):** Defines how the session reacts to receiving frames with unknown types.
* **Compressed Frame Handling (`OnSendCompressedFrame`, `OnReceiveCompressedFrame`):**  Logs compression statistics for sent and received HEADERS frames.
* **Flow Control Management (`OnWriteBufferConsumed`, `IncreaseSendWindowSize`, `DecreaseSendWindowSize`, `OnReadBufferConsumed`, `IncreaseRecvWindowSize`, `DecreaseRecvWindowSize`):**  Implements the core logic for managing send and receive windows at both the session and stream level. This ensures that neither side overwhelms the other with data.
* **Send Stalled Stream Management (`QueueSendStalledStream`, `ResumeSendStalledStreams`, `PopStreamToPossiblyResume`):** Manages a queue of streams that are currently blocked from sending data due to flow control limits. It attempts to resume these streams when the send window increases.
* **Connection Heartbeat (`CheckConnectionStatus`, `OnDefaultNetworkActive`, `MaybeDisableBrokenConnectionDetection`):** Implements a mechanism to periodically check the connection status using PING frames to detect broken connections.

**Relationship with JavaScript Functionality:**

While this C++ code doesn't directly execute JavaScript, it's crucial for how JavaScript in a web browser interacts with servers using HTTP/2. Here's the connection:

* **Fetching Resources:** When JavaScript uses `fetch()` or `XMLHttpRequest` to request resources from a server over HTTPS, and the connection negotiates HTTP/2, this `SpdySession` code is responsible for handling the underlying communication. The JavaScript code initiates the request, and this C++ code manages the sending of the request headers and the receiving of the response headers and body.
* **Server-Sent Events (SSE):** If a JavaScript application uses SSE over HTTP/2, this code handles the continuous stream of data sent from the server to the browser. The `OnStreamFrameData` function would be repeatedly called as new data arrives.
* **WebSockets (over HTTP/2):** While less common, WebSockets can theoretically run over HTTP/2. This code would manage the data frames exchanged over the WebSocket connection, ensuring proper flow control.

**Example:**

Imagine JavaScript code making a `fetch()` request:

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

**How it reaches `net/spdy/spdy_session.cc`:**

1. The JavaScript `fetch()` call triggers network stack operations in the browser.
2. The browser checks if there's an existing HTTP/2 connection to `example.com`.
3. If an HTTP/2 connection exists and is healthy, a new `SpdyStream` is created within the `SpdySession`.
4. The JavaScript request headers are translated into HTTP/2 HEADERS frames.
5. The `SpdySession`'s send logic (not shown in this snippet but present in other parts of the file) sends these HEADERS frames.
6. The server responds with HEADERS frames containing the response headers, which are handled by the `OnHeaders` function in this snippet.
7. The server then sends DATA frames containing the JSON response, which are handled by `OnDataFrameHeader` and `OnStreamFrameData`.
8. The received data is buffered and eventually made available to the JavaScript `response.json()` promise.

**Logical Input and Output Examples:**

**Function:** `OnWindowUpdate`

**Hypothetical Input:**
* `stream_id`: 5 (an active stream)
* `delta_window_size`: 1000

**Expected Output:**
* The send window size for stream 5 is increased by 1000.
* A log event `NetLogEventType::HTTP2_SESSION_RECV_WINDOW_UPDATE` is recorded.
* If stream 5 was send-stalled due to flow control, it might become eligible to send more data.

**Function:** `OnGoAway`

**Hypothetical Input:**
* `last_accepted_stream_id`: 7
* `error_code`: `spdy::ERROR_CODE_NO_ERROR`
* `debug_data`: "Server going down for maintenance"

**Expected Output:**
* The `SpdySession` is marked as unavailable.
* A log event `NetLogEventType::HTTP2_SESSION_RECV_GOAWAY` is recorded.
* The session starts the "going away" process, potentially refusing new streams (`StartGoingAway`).
* If there are no active streams, the going-away process might finish immediately.

**Common User or Programming Errors:**

* **Server Ignoring Flow Control:** A server that doesn't respect the client's advertised receive window could lead to the client's `DecreaseRecvWindowSize` detecting a violation and potentially closing the connection.
* **Client Not Consuming Data:** If the JavaScript code doesn't consume the data received for a stream (e.g., a slow-reading client), the `SpdySession`'s receive window will shrink, potentially causing the server to stop sending data until a WINDOW_UPDATE is sent.
* **Incorrectly Implementing Alt-Svc:** A server sending an invalid Alt-Svc frame (e.g., for a non-HTTPS origin) might be ignored or cause errors in the browser.
* **Mismatched Settings:** If the client and server disagree on certain HTTP/2 settings, it can lead to unexpected behavior or connection errors.

**User Operations Leading Here (Debugging Clues):**

To reach this code during debugging, you might observe the following user actions:

1. **Opening a Website over HTTPS:**  The initial connection establishment and subsequent resource loading for a website served over HTTPS with HTTP/2 will involve this code.
2. **Clicking Links or Submitting Forms:** Navigating within a website or submitting forms will trigger new HTTP requests that go through this `SpdySession`.
3. **Using Web Applications with Real-time Features:** Applications using SSE or WebSockets over HTTP/2 will heavily rely on this code for handling continuous data streams.
4. **A Website Suddenly Becoming Unresponsive:** If a server sends a GOAWAY frame, indicating a shutdown, this code will be involved in gracefully closing the connection.
5. **Network Issues:** Intermittent network problems or a server becoming unavailable might trigger the connection heartbeat mechanism (`CheckConnectionStatus`) and related logic.

**Summary of Functionality (Part 4):**

This portion of `net/spdy/spdy_session.cc` is primarily responsible for **handling incoming HTTP/2 frames, managing session lifecycle events (like GOAWAY), and enforcing flow control for both the overall session and individual streams.** It ensures reliable and efficient data transfer by processing server signals, managing data buffers, and regulating the rate at which data is sent and received. It also plays a role in optimizing connections through Alt-Svc and detecting broken connections.

Prompt: 
```
这是目录为net/spdy/spdy_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
ors to something sensical.
    //                For now, it doesn't matter much - it is a protocol error.
    CloseActiveStreamIterator(it, ERR_HTTP2_PROTOCOL_ERROR);
  }
}

void SpdySession::OnGoAway(spdy::SpdyStreamId last_accepted_stream_id,
                           spdy::SpdyErrorCode error_code,
                           std::string_view debug_data) {
  CHECK(in_io_loop_);

  // Use sparse histogram to record the unlikely case that a server sends
  // an unknown error code.
  base::UmaHistogramSparse("Net.SpdySession.GoAwayReceived", error_code);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_GOAWAY,
                    [&](NetLogCaptureMode capture_mode) {
                      return NetLogSpdyRecvGoAwayParams(
                          last_accepted_stream_id, active_streams_.size(),
                          error_code, debug_data, capture_mode);
                    });
  MakeUnavailable();
  if (error_code == spdy::ERROR_CODE_HTTP_1_1_REQUIRED) {
    // TODO(bnc): Record histogram with number of open streams capped at 50.
    DoDrainSession(ERR_HTTP_1_1_REQUIRED, "HTTP_1_1_REQUIRED for stream.");
  } else if (error_code == spdy::ERROR_CODE_NO_ERROR) {
    StartGoingAway(last_accepted_stream_id, ERR_HTTP2_SERVER_REFUSED_STREAM);
  } else {
    StartGoingAway(last_accepted_stream_id, ERR_HTTP2_PROTOCOL_ERROR);
  }
  // This is to handle the case when we already don't have any active
  // streams (i.e., StartGoingAway() did nothing). Otherwise, we have
  // active streams and so the last one being closed will finish the
  // going away process (see DeleteStream()).
  MaybeFinishGoingAway();
}

void SpdySession::OnDataFrameHeader(spdy::SpdyStreamId stream_id,
                                    size_t length,
                                    bool fin) {
  CHECK(in_io_loop_);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_DATA, [&] {
    return NetLogSpdyDataParams(stream_id, length, fin);
  });

  auto it = active_streams_.find(stream_id);

  // By the time data comes in, the stream may already be inactive.
  if (it == active_streams_.end())
    return;

  SpdyStream* stream = it->second;
  CHECK_EQ(stream->stream_id(), stream_id);

  DCHECK(buffered_spdy_framer_);
  stream->AddRawReceivedBytes(spdy::kDataFrameMinimumSize);
}

void SpdySession::OnStreamFrameData(spdy::SpdyStreamId stream_id,
                                    const char* data,
                                    size_t len) {
  CHECK(in_io_loop_);
  DCHECK_LT(len, 1u << 24);

  // Build the buffer as early as possible so that we go through the
  // session flow control checks and update
  // |unacked_recv_window_bytes_| properly even when the stream is
  // inactive (since the other side has still reduced its session send
  // window).
  std::unique_ptr<SpdyBuffer> buffer;
  if (data) {
    DCHECK_GT(len, 0u);
    CHECK_LE(len, static_cast<size_t>(kReadBufferSize));
    buffer = std::make_unique<SpdyBuffer>(data, len);

    DecreaseRecvWindowSize(static_cast<int32_t>(len));
    buffer->AddConsumeCallback(base::BindRepeating(
        &SpdySession::OnReadBufferConsumed, weak_factory_.GetWeakPtr()));
  } else {
    DCHECK_EQ(len, 0u);
  }

  auto it = active_streams_.find(stream_id);

  // By the time data comes in, the stream may already be inactive.
  if (it == active_streams_.end())
    return;

  SpdyStream* stream = it->second;
  CHECK_EQ(stream->stream_id(), stream_id);

  stream->AddRawReceivedBytes(len);
  stream->OnDataReceived(std::move(buffer));
}

void SpdySession::OnStreamEnd(spdy::SpdyStreamId stream_id) {
  CHECK(in_io_loop_);

  auto it = active_streams_.find(stream_id);
  // By the time data comes in, the stream may already be inactive.
  if (it == active_streams_.end())
    return;

  SpdyStream* stream = it->second;
  CHECK_EQ(stream->stream_id(), stream_id);

  stream->OnDataReceived(std::unique_ptr<SpdyBuffer>());
}

void SpdySession::OnStreamPadding(spdy::SpdyStreamId stream_id, size_t len) {
  CHECK(in_io_loop_);

  // Decrease window size because padding bytes are received.
  // Increase window size because padding bytes are consumed (by discarding).
  // Net result: |session_unacked_recv_window_bytes_| increases by |len|,
  // |session_recv_window_size_| does not change.
  DecreaseRecvWindowSize(static_cast<int32_t>(len));
  IncreaseRecvWindowSize(static_cast<int32_t>(len));

  auto it = active_streams_.find(stream_id);
  if (it == active_streams_.end())
    return;
  it->second->OnPaddingConsumed(len);
}

void SpdySession::OnSettings() {
  CHECK(in_io_loop_);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_SETTINGS);
  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_SEND_SETTINGS_ACK);

  if (!settings_frame_received_) {
    base::UmaHistogramCounts1000(
        "Net.SpdySession.OnSettings.CreatedStreamCount2",
        created_streams_.size());
    base::UmaHistogramCounts1000(
        "Net.SpdySession.OnSettings.ActiveStreamCount2",
        active_streams_.size());
    base::UmaHistogramCounts1000(
        "Net.SpdySession.OnSettings.CreatedAndActiveStreamCount2",
        created_streams_.size() + active_streams_.size());
    base::UmaHistogramCounts1000(
        "Net.SpdySession.OnSettings.PendingStreamCount2",
        GetTotalSize(pending_create_stream_queues_));
  }

  // Send an acknowledgment of the setting.
  spdy::SpdySettingsIR settings_ir;
  settings_ir.set_is_ack(true);
  auto frame = std::make_unique<spdy::SpdySerializedFrame>(
      buffered_spdy_framer_->SerializeFrame(settings_ir));
  EnqueueSessionWrite(HIGHEST, spdy::SpdyFrameType::SETTINGS, std::move(frame));
}

void SpdySession::OnSettingsAck() {
  CHECK(in_io_loop_);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_SETTINGS_ACK);
}

void SpdySession::OnSetting(spdy::SpdySettingsId id, uint32_t value) {
  CHECK(in_io_loop_);

  HandleSetting(id, value);

  // Log the setting.
  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_SETTING,
                    [&] { return NetLogSpdyRecvSettingParams(id, value); });
}

void SpdySession::OnSettingsEnd() {
  settings_frame_received_ = true;
}

void SpdySession::OnWindowUpdate(spdy::SpdyStreamId stream_id,
                                 int delta_window_size) {
  CHECK(in_io_loop_);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_WINDOW_UPDATE, [&] {
    return NetLogSpdyWindowUpdateFrameParams(stream_id, delta_window_size);
  });

  if (stream_id == spdy::kSessionFlowControlStreamId) {
    // WINDOW_UPDATE for the session.
    if (delta_window_size < 1) {
      RecordProtocolErrorHistogram(PROTOCOL_ERROR_INVALID_WINDOW_UPDATE_SIZE);
      DoDrainSession(
          ERR_HTTP2_PROTOCOL_ERROR,
          "Received WINDOW_UPDATE with an invalid delta_window_size " +
              base::NumberToString(delta_window_size));
      return;
    }

    IncreaseSendWindowSize(delta_window_size);
  } else {
    // WINDOW_UPDATE for a stream.
    auto it = active_streams_.find(stream_id);

    if (it == active_streams_.end()) {
      // NOTE:  it may just be that the stream was cancelled.
      LOG(WARNING) << "Received WINDOW_UPDATE for invalid stream " << stream_id;
      return;
    }

    SpdyStream* stream = it->second;
    CHECK_EQ(stream->stream_id(), stream_id);

    if (delta_window_size < 1) {
      ResetStreamIterator(
          it, ERR_HTTP2_FLOW_CONTROL_ERROR,
          "Received WINDOW_UPDATE with an invalid delta_window_size.");
      return;
    }

    CHECK_EQ(it->second->stream_id(), stream_id);
    it->second->IncreaseSendWindowSize(delta_window_size);
  }
}

void SpdySession::OnPushPromise(spdy::SpdyStreamId /*stream_id*/,
                                spdy::SpdyStreamId /*promised_stream_id*/,
                                quiche::HttpHeaderBlock /*headers*/) {
  CHECK(in_io_loop_);
  DoDrainSession(ERR_HTTP2_PROTOCOL_ERROR, "PUSH_PROMISE received");
}

void SpdySession::OnHeaders(spdy::SpdyStreamId stream_id,
                            bool has_priority,
                            int weight,
                            spdy::SpdyStreamId parent_stream_id,
                            bool exclusive,
                            bool fin,
                            quiche::HttpHeaderBlock headers,
                            base::TimeTicks recv_first_byte_time) {
  CHECK(in_io_loop_);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_HEADERS,
                    [&](NetLogCaptureMode capture_mode) {
                      return NetLogSpdyHeadersReceivedParams(
                          &headers, fin, stream_id, capture_mode);
                    });

  auto it = active_streams_.find(stream_id);
  if (it == active_streams_.end()) {
    // NOTE:  it may just be that the stream was cancelled.
    LOG(WARNING) << "Received HEADERS for invalid stream " << stream_id;
    return;
  }

  SpdyStream* stream = it->second;
  CHECK_EQ(stream->stream_id(), stream_id);

  stream->AddRawReceivedBytes(last_compressed_frame_len_);
  last_compressed_frame_len_ = 0;

  base::Time response_time = base::Time::Now();
  // May invalidate |stream|.
  stream->OnHeadersReceived(headers, response_time, recv_first_byte_time);
}

void SpdySession::OnAltSvc(
    spdy::SpdyStreamId stream_id,
    std::string_view origin,
    const spdy::SpdyAltSvcWireFormat::AlternativeServiceVector& altsvc_vector) {
  url::SchemeHostPort scheme_host_port;
  if (stream_id == 0) {
    if (origin.empty())
      return;
    const GURL gurl(origin);
    if (!gurl.is_valid() || gurl.host().empty())
      return;
    if (!gurl.SchemeIs(url::kHttpsScheme))
      return;
    SSLInfo ssl_info;
    if (!GetSSLInfo(&ssl_info)) {
      return;
    }
    if (!CanPool(transport_security_state_, ssl_info, *ssl_config_service_,
                 host_port_pair().host(), gurl.host_piece())) {
      return;
    }
    scheme_host_port = url::SchemeHostPort(gurl);
  } else {
    if (!origin.empty())
      return;
    const ActiveStreamMap::iterator it = active_streams_.find(stream_id);
    if (it == active_streams_.end())
      return;
    const GURL& gurl(it->second->url());
    if (!gurl.SchemeIs(url::kHttpsScheme))
      return;
    scheme_host_port = url::SchemeHostPort(gurl);
  }

  http_server_properties_->SetAlternativeServices(
      scheme_host_port, spdy_session_key_.network_anonymization_key(),
      ProcessAlternativeServices(altsvc_vector, is_http2_enabled_,
                                 is_quic_enabled_, quic_supported_versions_));
}

bool SpdySession::OnUnknownFrame(spdy::SpdyStreamId stream_id,
                                 uint8_t frame_type) {
  if (stream_id % 2 == 1) {
    return stream_id <= stream_hi_water_mark_;
  } else {
    // Reject frames on push streams, but not on the control stream.
    return stream_id == 0;
  }
}

void SpdySession::OnSendCompressedFrame(spdy::SpdyStreamId stream_id,
                                        spdy::SpdyFrameType type,
                                        size_t payload_len,
                                        size_t frame_len) {
  if (type != spdy::SpdyFrameType::HEADERS) {
    return;
  }

  DCHECK(buffered_spdy_framer_.get());
  size_t compressed_len = frame_len - spdy::kFrameMinimumSize;

  if (payload_len) {
    // Make sure we avoid early decimal truncation.
    int compression_pct = 100 - (100 * compressed_len) / payload_len;
    UMA_HISTOGRAM_PERCENTAGE("Net.SpdyHeadersCompressionPercentage",
                             compression_pct);
  }
}

void SpdySession::OnReceiveCompressedFrame(spdy::SpdyStreamId stream_id,
                                           spdy::SpdyFrameType type,
                                           size_t frame_len) {
  last_compressed_frame_len_ = frame_len;
}

void SpdySession::OnWriteBufferConsumed(
    size_t frame_payload_size,
    size_t consume_size,
    SpdyBuffer::ConsumeSource consume_source) {
  // We can be called with |in_io_loop_| set if a write SpdyBuffer is
  // deleted (e.g., a stream is closed due to incoming data).
  if (consume_source == SpdyBuffer::DISCARD) {
    // If we're discarding a frame or part of it, increase the send
    // window by the number of discarded bytes. (Although if we're
    // discarding part of a frame, it's probably because of a write
    // error and we'll be tearing down the session soon.)
    int remaining_payload_bytes = std::min(consume_size, frame_payload_size);
    DCHECK_GT(remaining_payload_bytes, 0);
    IncreaseSendWindowSize(remaining_payload_bytes);
  }
  // For consumed bytes, the send window is increased when we receive
  // a WINDOW_UPDATE frame.
}

void SpdySession::IncreaseSendWindowSize(int delta_window_size) {
  // We can be called with |in_io_loop_| set if a SpdyBuffer is
  // deleted (e.g., a stream is closed due to incoming data).
  DCHECK_GE(delta_window_size, 1);

  // Check for overflow.
  int32_t max_delta_window_size =
      std::numeric_limits<int32_t>::max() - session_send_window_size_;
  if (delta_window_size > max_delta_window_size) {
    RecordProtocolErrorHistogram(PROTOCOL_ERROR_INVALID_WINDOW_UPDATE_SIZE);
    DoDrainSession(
        ERR_HTTP2_PROTOCOL_ERROR,
        "Received WINDOW_UPDATE [delta: " +
            base::NumberToString(delta_window_size) +
            "] for session overflows session_send_window_size_ [current: " +
            base::NumberToString(session_send_window_size_) + "]");
    return;
  }

  session_send_window_size_ += delta_window_size;

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_UPDATE_SEND_WINDOW, [&] {
    return NetLogSpdySessionWindowUpdateParams(delta_window_size,
                                               session_send_window_size_);
  });

  DCHECK(!IsSendStalled());
  ResumeSendStalledStreams();
}

void SpdySession::DecreaseSendWindowSize(int32_t delta_window_size) {
  // We only call this method when sending a frame. Therefore,
  // |delta_window_size| should be within the valid frame size range.
  DCHECK_GE(delta_window_size, 1);
  DCHECK_LE(delta_window_size, kMaxSpdyFrameChunkSize);

  // |send_window_size_| should have been at least |delta_window_size| for
  // this call to happen.
  DCHECK_GE(session_send_window_size_, delta_window_size);

  session_send_window_size_ -= delta_window_size;

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_UPDATE_SEND_WINDOW, [&] {
    return NetLogSpdySessionWindowUpdateParams(-delta_window_size,
                                               session_send_window_size_);
  });
}

void SpdySession::OnReadBufferConsumed(
    size_t consume_size,
    SpdyBuffer::ConsumeSource consume_source) {
  // We can be called with |in_io_loop_| set if a read SpdyBuffer is
  // deleted (e.g., discarded by a SpdyReadQueue).
  DCHECK_GE(consume_size, 1u);
  DCHECK_LE(consume_size,
            static_cast<size_t>(std::numeric_limits<int32_t>::max()));

  IncreaseRecvWindowSize(static_cast<int32_t>(consume_size));
}

void SpdySession::IncreaseRecvWindowSize(int32_t delta_window_size) {
  DCHECK_GE(session_unacked_recv_window_bytes_, 0);
  DCHECK_GE(session_recv_window_size_, session_unacked_recv_window_bytes_);
  DCHECK_GE(delta_window_size, 1);
  // Check for overflow.
  DCHECK_LE(delta_window_size,
            std::numeric_limits<int32_t>::max() - session_recv_window_size_);

  session_recv_window_size_ += delta_window_size;
  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_UPDATE_RECV_WINDOW, [&] {
    return NetLogSpdySessionWindowUpdateParams(delta_window_size,
                                               session_recv_window_size_);
  });

  // Update the receive window once half of the buffer is ready to be acked
  // to prevent excessive window updates on fast downloads. Also send an update
  // if too much time has elapsed since the last update to deal with
  // slow-reading clients so the server doesn't think the session is idle.
  session_unacked_recv_window_bytes_ += delta_window_size;
  const base::TimeDelta elapsed =
      base::TimeTicks::Now() - last_recv_window_update_;
  if (session_unacked_recv_window_bytes_ > session_max_recv_window_size_ / 2 ||
      elapsed >= time_to_buffer_small_window_updates_) {
    last_recv_window_update_ = base::TimeTicks::Now();
    SendWindowUpdateFrame(spdy::kSessionFlowControlStreamId,
                          session_unacked_recv_window_bytes_, HIGHEST);
    session_unacked_recv_window_bytes_ = 0;
  }
}

void SpdySession::DecreaseRecvWindowSize(int32_t delta_window_size) {
  CHECK(in_io_loop_);
  DCHECK_GE(delta_window_size, 1);

  // The receiving window size as the peer knows it is
  // |session_recv_window_size_ - session_unacked_recv_window_bytes_|, if more
  // data are sent by the peer, that means that the receive window is not being
  // respected.
  int32_t receiving_window_size =
      session_recv_window_size_ - session_unacked_recv_window_bytes_;
  if (delta_window_size > receiving_window_size) {
    RecordProtocolErrorHistogram(PROTOCOL_ERROR_RECEIVE_WINDOW_VIOLATION);
    DoDrainSession(
        ERR_HTTP2_FLOW_CONTROL_ERROR,
        "delta_window_size is " + base::NumberToString(delta_window_size) +
            " in DecreaseRecvWindowSize, which is larger than the receive " +
            "window size of " + base::NumberToString(receiving_window_size));
    return;
  }

  session_recv_window_size_ -= delta_window_size;
  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_UPDATE_RECV_WINDOW, [&] {
    return NetLogSpdySessionWindowUpdateParams(-delta_window_size,
                                               session_recv_window_size_);
  });
}

void SpdySession::QueueSendStalledStream(const SpdyStream& stream) {
  DCHECK(stream.send_stalled_by_flow_control() || IsSendStalled());
  RequestPriority priority = stream.priority();
  CHECK_GE(priority, MINIMUM_PRIORITY);
  CHECK_LE(priority, MAXIMUM_PRIORITY);
  stream_send_unstall_queue_[priority].push_back(stream.stream_id());
}

void SpdySession::ResumeSendStalledStreams() {
  // We don't have to worry about new streams being queued, since
  // doing so would cause IsSendStalled() to return true. But we do
  // have to worry about streams being closed, as well as ourselves
  // being closed.

  base::circular_deque<SpdyStream*> streams_to_requeue;

  while (!IsSendStalled()) {
    size_t old_size = 0;
#if DCHECK_IS_ON()
    old_size = GetTotalSize(stream_send_unstall_queue_);
#endif

    spdy::SpdyStreamId stream_id = PopStreamToPossiblyResume();
    if (stream_id == 0)
      break;
    ActiveStreamMap::const_iterator it = active_streams_.find(stream_id);
    // The stream may actually still be send-stalled after this (due
    // to its own send window) but that's okay -- it'll then be
    // resumed once its send window increases.
    if (it != active_streams_.end()) {
      if (it->second->PossiblyResumeIfSendStalled() == SpdyStream::Requeue)
        streams_to_requeue.push_back(it->second);
    }

    // The size should decrease unless we got send-stalled again.
    if (!IsSendStalled())
      DCHECK_LT(GetTotalSize(stream_send_unstall_queue_), old_size);
  }
  while (!streams_to_requeue.empty()) {
    SpdyStream* stream = streams_to_requeue.front();
    streams_to_requeue.pop_front();
    QueueSendStalledStream(*stream);
  }
}

spdy::SpdyStreamId SpdySession::PopStreamToPossiblyResume() {
  for (int i = MAXIMUM_PRIORITY; i >= MINIMUM_PRIORITY; --i) {
    base::circular_deque<spdy::SpdyStreamId>* queue =
        &stream_send_unstall_queue_[i];
    if (!queue->empty()) {
      spdy::SpdyStreamId stream_id = queue->front();
      queue->pop_front();
      return stream_id;
    }
  }
  return 0;
}

void SpdySession::CheckConnectionStatus() {
  MaybeSendPrefacePing();
  // Also schedule the next check.
  heartbeat_timer_.Start(
      FROM_HERE, heartbeat_interval_,
      base::BindOnce(&SpdySession::MaybeCheckConnectionStatus,
                     weak_factory_.GetWeakPtr()));
}

void SpdySession::OnDefaultNetworkActive() {
  if (!check_connection_on_radio_wakeup_)
    return;

  check_connection_on_radio_wakeup_ = false;
  CheckConnectionStatus();
}

void SpdySession::MaybeDisableBrokenConnectionDetection() {
  DCHECK_GT(broken_connection_detection_requests_, 0);
  DCHECK(IsBrokenConnectionDetectionEnabled());
  if (--broken_connection_detection_requests_ > 0)
    return;

  heartbeat_timer_.Stop();
  NetworkChangeNotifier::RemoveDefaultNetworkActiveObserver(this);
  check_connection_on_radio_wakeup_ = false;
}

}  // namespace net

"""


```
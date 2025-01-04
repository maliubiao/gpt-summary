Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of the `QuicSpdySession` class in Chromium's network stack. Specifically, the request asks for:

1. **Functionality Summary:** A high-level overview of what the code does.
2. **Relationship to JavaScript:**  If and how the code interacts with JavaScript functionality.
3. **Logic and I/O:** Examples of input and output based on logical deductions.
4. **Common Errors:** Examples of user or programming errors related to this code.
5. **Debugging Context:**  How a user's actions might lead to this code being executed.
6. **Overall Functionality (Part 2):** A summary of the functionality covered in this specific snippet.

Let's break down the code section by section to identify the core functionalities:

* **`OnGoAwayFrame`:** Handles the reception of a `GOAWAY` frame, indicating the peer is going away. It can trigger WebTransport session closure.
* **`OnStreamsBlockedFrame`:** Processes a `STREAMS_BLOCKED` frame, used for flow control of streams. It can lead to sending a `GOAWAY` frame if the peer requests an excessive number of streams.
* **`SendHttp3GoAway`:** Sends an HTTP/3 `GOAWAY` frame to the peer, indicating this side is going away. It avoids sending redundant or invalid `GOAWAY` frames.
* **`SendInitialData`:** Sends initial data after encryption is established, including HTTP/3 settings.
* **`CheckStreamWriteBlocked`:** Determines if writing to a stream is blocked, with a special case for QPACK decoder stream.
* **`qpack_encoder`/`qpack_decoder`:** Accessors for the QPACK encoder and decoder objects.
* **`OnStreamCreated`:**  Handles stream creation, applying any buffered priority information.
* **`GetOrCreateSpdyDataStream`:** Retrieves or creates a data stream, ensuring it's not a static stream.
* **`OnNewEncryptionKeyAvailable`:**  Called when new encryption keys are available, triggers sending initial data after full encryption.
* **`ShouldNegotiateWebTransport`:** Determines if WebTransport negotiation should occur based on supported versions.
* **`LocallySupportedWebTransportVersions`:** Returns the set of WebTransport versions supported locally.
* **`WillNegotiateWebTransport`:** Checks if WebTransport negotiation will happen based on support and HTTP/3 usage.
* **`ShouldKeepConnectionAlive`:** Determines if the connection should be kept alive based on active and pending streams.
* **`UsesPendingStreamForFrame`:** Checks if a pending stream is used for a specific frame type.
* **`WriteHeadersOnHeadersStreamImpl`:** Writes headers on the dedicated headers stream (for HTTP/2). It includes logic for priority and compression tracking.
* **`ResumeApplicationState`:** Resumes application state from a cached state (for 0-RTT).
* **`OnAlpsData`:** Processes data received via ALPS (Application-Layer Protocol Settings), potentially containing `SETTINGS` or `ACCEPT_CH` frames.
* **`OnAcceptChFrameReceivedViaAlps`:** Handles received `ACCEPT_CH` frames from ALPS.
* **`OnSettingsFrame`:** Processes received HTTP/3 `SETTINGS` frames, updating internal state and notifying waiting streams. Includes validation for WebTransport settings.
* **`ValidateWebTransportSettingsConsistency`:** Enforces consistency rules for negotiated WebTransport settings.
* **`OnSettingsFrameViaAlps`:** Handles `SETTINGS` frames received via ALPS.
* **`VerifySettingIsZeroOrOne`:** Validates if a setting value is either 0 or 1.
* **`OnSetting`:** Processes individual settings from a `SETTINGS` frame, updating various parameters related to QPACK, WebTransport, HTTP datagrams, etc. Handles both HTTP/3 and HTTP/2 settings.
* **`ShouldReleaseHeadersStreamSequencerBuffer`:**  Determines if the headers stream sequencer buffer should be released.
* **`OnHeaders`:** Handles the start of a header block on the headers stream (HTTP/2).
* **`OnPriority`:** Handles `PRIORITY` frames on the headers stream (HTTP/2).
* **`OnHeaderList`:** Processes the complete header list received on the headers stream (HTTP/2).
* **`OnCompressedFrameSize`:** Tracks the size of compressed frames on the headers stream (HTTP/2).
* **`CloseConnectionWithDetails`:** Closes the connection with a specific error code and details.
* **`HasActiveRequestStreams`:** Checks if there are active request streams.
* **`ProcessReadUnidirectionalPendingStream`:** Processes incoming unidirectional streams, determining their type (control, QPACK, WebTransport) and creating the appropriate stream objects.
* **`MaybeInitializeHttp3UnidirectionalStreams`:**  Initializes outgoing HTTP/3 unidirectional streams (control, QPACK encoder/decoder).
* **`BeforeConnectionCloseSent`:** Actions taken before sending a connection close, including sending a final `GOAWAY` frame.
* **`MaybeBundleOpportunistically`:**  Attempts to opportunistically bundle data (e.g., QPACK decoder updates).
* **`OnCanCreateNewOutgoingStream`:** Callback when new outgoing streams can be created, potentially initializing HTTP/3 unidirectional streams.
* **`goaway_received`/`goaway_sent`:**  Accessors to check if `GOAWAY` frames have been received or sent.
* **`CloseConnectionOnDuplicateHttp3UnidirectionalStreams`:** Closes the connection due to duplicate HTTP/3 unidirectional streams.
* **`LogHeaderCompressionRatioHistogram`:** Logs the header compression ratio.

Now, let's address each point in the prompt.
This section of the `QuicSpdySession.cc` file in Chromium's network stack primarily handles the processing of various HTTP/3 and HTTP/2 control frames and settings, managing the session's state, and initializing/managing related streams like control streams and QPACK streams. It also includes logic for WebTransport negotiation and handling.

Here's a breakdown of its functionalities:

* **Handling `GOAWAY` Frames:** It processes incoming `GOAWAY` frames from the peer, potentially triggering actions like closing WebTransport sessions.
* **Managing Stream Limits:** It deals with `STREAMS_BLOCKED` frames, ensuring the peer doesn't request more streams than the implementation can handle. If the peer requests too many streams, it sends a `GOAWAY` frame.
* **Sending `GOAWAY` Frames:**  It provides a mechanism to send `GOAWAY` frames to the peer, indicating the session is going away. It prevents sending redundant or out-of-order `GOAWAY` frames.
* **Initial Data Transmission:** After encryption is established, it sends initial data, including HTTP/3 `SETTINGS` frames.
* **Stream Write Blocking Check:** It checks if writing to a specific stream is currently blocked, with a special case for the QPACK decoder stream.
* **Accessing QPACK Components:** It provides accessors to the QPACK encoder and decoder objects for header compression.
* **Stream Priority Management:** It handles applying buffered priority information to newly created streams.
* **Stream Creation:** It offers a method to get or create a regular data stream, ensuring it's not a static internal stream.
* **Encryption Key Updates:** It reacts to new encryption keys becoming available, triggering the sending of initial HTTP/3 data.
* **WebTransport Negotiation:** It includes logic for determining whether WebTransport should be negotiated and checks for locally supported WebTransport versions.
* **Connection Liveness:** It determines if the connection should be kept alive based on the presence of active and pending streams.
* **Pending Stream Usage:** It checks if a pending stream (for which the type is not yet fully determined) can be used for specific frame types (like `STREAM` or `RESET_STREAM`).
* **HTTP/2 Header Handling:** For HTTP/2, it handles writing headers onto the dedicated headers stream, including priority information and tracking compression ratios.
* **Resuming Application State:**  It supports resuming application state from a cached state, primarily used in 0-RTT connections.
* **Processing ALPS Data:** It handles data received via ALPS (Application-Layer Protocol Settings), which can contain `SETTINGS` or other frames.
* **Handling `SETTINGS` Frames:**  It processes incoming `SETTINGS` frames (both via the control stream and ALPS), updating the session's configuration based on the received values. This includes settings for QPACK, WebTransport, and HTTP Datagrams. It also validates the consistency of WebTransport-related settings.
* **Verifying Setting Values:** It includes a helper function to verify if a setting value is either 0 or 1.
* **HTTP/2 Specific Frame Handling:** For HTTP/2, it handles `HEADERS`, `PRIORITY`, and the accumulation of header list data from the headers stream.
* **Connection Closure:** It provides a utility function to close the connection with a specific error code and details.
* **Active Request Check:** It checks if there are any currently active request streams.
* **Processing Incoming Unidirectional Streams:** It handles the initial processing of incoming unidirectional streams, identifying their type (control stream, QPACK streams, WebTransport streams) based on the initial byte and creating the corresponding stream objects.
* **Initializing Outgoing Unidirectional Streams:** It initializes outgoing HTTP/3 unidirectional streams (control, QPACK encoder/decoder streams) when possible.
* **Pre-Connection Close Actions:**  It performs actions before sending a connection close, such as sending a final `GOAWAY` frame.
* **Opportunistic Bundling:** It attempts to opportunistically bundle data, such as flushing the QPACK decoder stream.
* **Outgoing Stream Creation Notification:** It handles notifications that new outgoing streams can be created, potentially triggering the initialization of HTTP/3 unidirectional streams.
* **`GOAWAY` State Tracking:** It tracks whether `GOAWAY` frames have been received or sent.
* **Handling Duplicate Unidirectional Streams:** It closes the connection if duplicate HTTP/3 unidirectional streams are received.
* **Logging Header Compression Ratio:** It logs the header compression ratio for statistical purposes.

**Relationship to JavaScript:**

This C++ code is part of the Chromium browser's network stack. It doesn't directly interact with JavaScript code in the same process. However, its functionality is crucial for handling network requests initiated by JavaScript code running in web pages.

Here's how they are related:

* **Network Requests:** When JavaScript in a web page makes an HTTP/3 request (e.g., using `fetch()` or `XMLHttpRequest`), the browser's network stack, including this `QuicSpdySession` class, handles the underlying QUIC and HTTP/3 communication.
* **WebSockets and WebTransport:** If the JavaScript code uses WebSockets over HTTP/3 or the WebTransport API, this class plays a vital role in establishing and managing those connections. The WebTransport logic within this code snippet is directly related to the WebTransport API exposed to JavaScript.
* **Browser Internals:**  While JavaScript developers don't directly manipulate this C++ code, the correct functioning of this code is essential for the network features that JavaScript relies on.

**Example of Relationship:**

Imagine a JavaScript application using the WebTransport API to establish a bidirectional connection with a server:

1. **JavaScript initiates WebTransport:** The JavaScript code calls `new WebTransport('https://example.com/wtransport')`.
2. **Browser's Network Stack:** The browser's networking code, including the `QuicSpdySession` class, will attempt to establish a QUIC connection to `example.com`.
3. **WebTransport Negotiation:** This C++ code will participate in the WebTransport negotiation process, potentially sending and receiving `SETTINGS` frames with WebTransport-specific parameters (like `SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07`).
4. **Stream Management:** Once the WebTransport connection is established, this code manages the underlying QUIC streams used for sending and receiving data between the JavaScript application and the server.

**Logical Inference with Input and Output:**

**Scenario:** Receiving a `STREAMS_BLOCKED` frame on the server-side.

**Hypothetical Input:** A `QuicStreamsBlockedFrame` with `frame.stream_count` equal to `QuicUtils::GetMaxStreamCount()`. The `perspective()` of the `QuicSpdySession` is `Perspective::IS_SERVER`.

**Logical Deduction:** The code checks if the received `stream_count` is greater than or equal to the maximum allowed stream count for the implementation. In this case, they are equal.

**Output:** The `SendHttp3GoAway` function will be called with `QUIC_PEER_GOING_AWAY` as the `error_code` and "stream count too large" as the `reason`. This will cause the server to send a `GOAWAY` frame to the client, indicating that the server cannot handle the requested number of streams.

**Common User or Programming Errors:**

1. **Incorrect Server Configuration:** If a server is configured to send a `SETTINGS` frame with a value for `SETTINGS_QPACK_MAX_TABLE_CAPACITY` that is lower than what the client has already advertised or is using, the connection might be closed with a `QUIC_HTTP_ZERO_RTT_REJECTION_SETTINGS_MISMATCH` or `QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH` error. This is a configuration error on the server-side.
2. **Exceeding Header Size Limits:** If the peer sends headers that exceed the `SETTINGS_MAX_FIELD_SECTION_SIZE` advertised by the local endpoint, the connection will be closed. This could be a programming error in the peer's HTTP implementation.
3. **Sending HTTP/2 Specific Settings in HTTP/3:** If a peer mistakenly sends an HTTP/2 specific setting like `SETTINGS_ENABLE_PUSH` or `SETTINGS_MAX_CONCURRENT_STREAMS` in an HTTP/3 connection, the `OnSetting` function will detect this and close the connection with `QUIC_HTTP_RECEIVE_SPDY_SETTING`. This is a protocol violation on the peer's side.

**User Operation to Reach This Code (Debugging Context):**

Let's consider the scenario where a user is experiencing issues with a WebTransport connection.

1. **User Opens a Web Page:** The user navigates to a web page that utilizes the WebTransport API.
2. **JavaScript Initiates WebTransport:** The JavaScript code on the page attempts to establish a WebTransport connection to a server.
3. **Connection Establishment:** The browser's network stack begins the process of establishing a QUIC connection and negotiating the WebTransport protocol. This involves sending and receiving various QUIC frames and HTTP/3 control frames, which are handled by the `QuicSpdySession` class.
4. **Potential Issue:**  During the negotiation, if the server sends a `SETTINGS` frame with incompatible WebTransport parameters (e.g., requiring extended CONNECT when the client doesn't support it), the `ValidateWebTransportSettingsConsistency` function in this code will detect the inconsistency.
5. **Connection Closure:** The `ValidateWebTransportSettingsConsistency` function will call `CloseConnectionWithDetails` with an appropriate error code (e.g., `QUIC_HTTP_INVALID_SETTING_VALUE`).
6. **Debugging:** A developer inspecting the browser's network logs or using debugging tools might see this error code and potentially trace the issue back to the `ValidateWebTransportSettingsConsistency` function within `QuicSpdySession.cc`.

**Functionality Summary (Part 2):**

This specific section of `QuicSpdySession.cc` focuses on:

* **Control Frame Processing:** Handling `GOAWAY` and `STREAMS_BLOCKED` frames, enabling the session to react to peer state changes and manage resource limits.
* **Configuration and Settings Management:** Processing `SETTINGS` frames (both HTTP/3 and HTTP/2), updating internal session parameters related to QPACK, WebTransport, and other features.
* **WebTransport Negotiation and Validation:** Implementing the core logic for negotiating and validating WebTransport settings, ensuring compatibility between endpoints.
* **Stream Lifecycle Management:**  Handling the creation and initialization of various types of streams (data, control, QPACK, WebTransport).
* **Error Handling and Connection Closure:** Providing mechanisms to detect protocol violations and inconsistencies and close the connection gracefully with informative error codes.
* **Initial Setup:** Handling the sending of initial data after encryption is established.
* **HTTP/2 Support:** Maintaining compatibility with HTTP/2 by handling frames on the headers stream.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
  return true;
      }
      web_transport->OnGoAwayReceived();
      return true;
    });
  }

  // TODO(b/161252736): Cancel client requests with ID larger than |id|.
  // If |id| is larger than numeric_limits<QuicStreamId>::max(), then use
  // max() instead of downcast value.
}

bool QuicSpdySession::OnStreamsBlockedFrame(
    const QuicStreamsBlockedFrame& frame) {
  if (!QuicSession::OnStreamsBlockedFrame(frame)) {
    return false;
  }

  // The peer asked for stream space more than this implementation has. Send
  // goaway.
  if (perspective() == Perspective::IS_SERVER &&
      frame.stream_count >= QuicUtils::GetMaxStreamCount()) {
    QUICHE_DCHECK_EQ(frame.stream_count, QuicUtils::GetMaxStreamCount());
    SendHttp3GoAway(QUIC_PEER_GOING_AWAY, "stream count too large");
  }
  return true;
}

void QuicSpdySession::SendHttp3GoAway(QuicErrorCode error_code,
                                      const std::string& reason) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  if (!IsEncryptionEstablished()) {
    QUIC_CODE_COUNT(quic_h3_goaway_before_encryption_established);
    connection()->CloseConnection(
        error_code, reason,
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  ietf_streamid_manager().StopIncreasingIncomingMaxStreams();

  QuicStreamId stream_id =
      QuicUtils::GetMaxClientInitiatedBidirectionalStreamId(
          transport_version());
  if (last_sent_http3_goaway_id_.has_value() &&
      *last_sent_http3_goaway_id_ <= stream_id) {
    // Do not send GOAWAY frame with a higher id, because it is forbidden.
    // Do not send one with same stream id as before, since frames on the
    // control stream are guaranteed to be processed in order.
    return;
  }

  send_control_stream_->SendGoAway(stream_id);
  last_sent_http3_goaway_id_ = stream_id;
}

void QuicSpdySession::SendInitialData() {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  QuicConnection::ScopedPacketFlusher flusher(connection());
  send_control_stream_->MaybeSendSettingsFrame();
  SendInitialDataAfterSettings();
}

bool QuicSpdySession::CheckStreamWriteBlocked(QuicStream* stream) const {
  if (qpack_decoder_send_stream_ != nullptr &&
      stream->id() == qpack_decoder_send_stream_->id()) {
    // Decoder data is always bundled opportunistically.
    return true;
  }
  return QuicSession::CheckStreamWriteBlocked(stream);
}

QpackEncoder* QuicSpdySession::qpack_encoder() {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  return qpack_encoder_.get();
}

QpackDecoder* QuicSpdySession::qpack_decoder() {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  return qpack_decoder_.get();
}

void QuicSpdySession::OnStreamCreated(QuicSpdyStream* stream) {
  auto it = buffered_stream_priorities_.find(stream->id());
  if (it == buffered_stream_priorities_.end()) {
    return;
  }

  stream->SetPriority(QuicStreamPriority(it->second));
  buffered_stream_priorities_.erase(it);
}

QuicSpdyStream* QuicSpdySession::GetOrCreateSpdyDataStream(
    const QuicStreamId stream_id) {
  QuicStream* stream = GetOrCreateStream(stream_id);
  if (stream && stream->is_static()) {
    QUIC_BUG(quic_bug_10360_5)
        << "GetOrCreateSpdyDataStream returns static stream " << stream_id
        << " in version " << transport_version() << "\n"
        << QuicStackTrace();
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID,
        absl::StrCat("stream ", stream_id, " is static"),
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return nullptr;
  }
  return static_cast<QuicSpdyStream*>(stream);
}

void QuicSpdySession::OnNewEncryptionKeyAvailable(
    EncryptionLevel level, std::unique_ptr<QuicEncrypter> encrypter) {
  QuicSession::OnNewEncryptionKeyAvailable(level, std::move(encrypter));
  if (IsEncryptionEstablished()) {
    // Send H3 SETTINGs once encryption is established.
    SendInitialData();
  }
}

bool QuicSpdySession::ShouldNegotiateWebTransport() const {
  return LocallySupportedWebTransportVersions().Any();
}

WebTransportHttp3VersionSet
QuicSpdySession::LocallySupportedWebTransportVersions() const {
  return WebTransportHttp3VersionSet();
}

bool QuicSpdySession::WillNegotiateWebTransport() {
  return LocalHttpDatagramSupport() != HttpDatagramSupport::kNone &&
         version().UsesHttp3() && ShouldNegotiateWebTransport();
}

// True if there are open HTTP requests.
bool QuicSpdySession::ShouldKeepConnectionAlive() const {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()) ||
                0u == pending_streams_size());
  return GetNumActiveStreams() + pending_streams_size() > 0;
}

bool QuicSpdySession::UsesPendingStreamForFrame(QuicFrameType type,
                                                QuicStreamId stream_id) const {
  // Pending streams can only be used to handle unidirectional stream with
  // STREAM & RESET_STREAM frames in IETF QUIC.
  return VersionUsesHttp3(transport_version()) &&
         (type == STREAM_FRAME || type == RST_STREAM_FRAME) &&
         QuicUtils::GetStreamType(stream_id, perspective(),
                                  IsIncomingStream(stream_id),
                                  version()) == READ_UNIDIRECTIONAL;
}

size_t QuicSpdySession::WriteHeadersOnHeadersStreamImpl(
    QuicStreamId id, quiche::HttpHeaderBlock headers, bool fin,
    QuicStreamId parent_stream_id, int weight, bool exclusive,
    quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
        ack_listener) {
  QUICHE_DCHECK(!VersionUsesHttp3(transport_version()));

  const QuicByteCount uncompressed_size = headers.TotalBytesUsed();
  SpdyHeadersIR headers_frame(id, std::move(headers));
  headers_frame.set_fin(fin);
  if (perspective() == Perspective::IS_CLIENT) {
    headers_frame.set_has_priority(true);
    headers_frame.set_parent_stream_id(parent_stream_id);
    headers_frame.set_weight(weight);
    headers_frame.set_exclusive(exclusive);
  }
  SpdySerializedFrame frame(spdy_framer_.SerializeFrame(headers_frame));
  headers_stream()->WriteOrBufferData(
      absl::string_view(frame.data(), frame.size()), false,
      std::move(ack_listener));

  // Calculate compressed header block size without framing overhead.
  QuicByteCount compressed_size = frame.size();
  compressed_size -= spdy::kFrameHeaderSize;
  if (perspective() == Perspective::IS_CLIENT) {
    // Exclusive bit and Stream Dependency are four bytes, weight is one more.
    compressed_size -= 5;
  }

  LogHeaderCompressionRatioHistogram(
      /* using_qpack = */ false,
      /* is_sent = */ true, compressed_size, uncompressed_size);

  return frame.size();
}

bool QuicSpdySession::ResumeApplicationState(ApplicationState* cached_state) {
  QUICHE_DCHECK_EQ(perspective(), Perspective::IS_CLIENT);
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  SettingsFrame out;
  if (!HttpDecoder::DecodeSettings(
          reinterpret_cast<char*>(cached_state->data()), cached_state->size(),
          &out)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnSettingsFrameResumed(out);
  }
  QUICHE_DCHECK(streams_waiting_for_settings_.empty());
  for (const auto& setting : out.values) {
    OnSetting(setting.first, setting.second);
  }
  return true;
}

std::optional<std::string> QuicSpdySession::OnAlpsData(const uint8_t* alps_data,
                                                       size_t alps_length) {
  AlpsFrameDecoder alps_frame_decoder(this);
  HttpDecoder decoder(&alps_frame_decoder);
  decoder.ProcessInput(reinterpret_cast<const char*>(alps_data), alps_length);
  if (alps_frame_decoder.error_detail()) {
    return alps_frame_decoder.error_detail();
  }

  if (decoder.error() != QUIC_NO_ERROR) {
    return decoder.error_detail();
  }

  if (!decoder.AtFrameBoundary()) {
    return "incomplete HTTP/3 frame";
  }

  return std::nullopt;
}

void QuicSpdySession::OnAcceptChFrameReceivedViaAlps(
    const AcceptChFrame& frame) {
  if (debug_visitor_) {
    debug_visitor_->OnAcceptChFrameReceivedViaAlps(frame);
  }
}

bool QuicSpdySession::OnSettingsFrame(const SettingsFrame& frame) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnSettingsFrameReceived(frame);
  }
  for (const auto& setting : frame.values) {
    if (!OnSetting(setting.first, setting.second)) {
      return false;
    }
  }

  if (!ValidateWebTransportSettingsConsistency()) {
    return false;
  }

  // This is the last point in the connection when we can receive new SETTINGS
  // values (ALPS and settings from the session ticket come before, and only one
  // SETTINGS frame per connection is allowed).  Notify all the streams that are
  // blocking on having the definitive settings list.
  QUICHE_DCHECK(!settings_received_);
  settings_received_ = true;
  for (QuicStreamId stream_id : streams_waiting_for_settings_) {
    QUICHE_RELOADABLE_FLAG_COUNT_N(quic_block_until_settings_received_copt, 4,
                                   4);
    QUICHE_DCHECK(ShouldBufferRequestsUntilSettings());
    QuicSpdyStream* stream = GetOrCreateSpdyDataStream(stream_id);
    if (stream == nullptr) {
      // The stream may no longer exist, since it is possible for a stream to
      // get reset while waiting for the SETTINGS frame.
      continue;
    }
    stream->OnDataAvailable();
  }
  streams_waiting_for_settings_.clear();

  return true;
}

bool QuicSpdySession::ValidateWebTransportSettingsConsistency() {
  // Only apply the following checks to draft-07 or later.
  std::optional<WebTransportHttp3Version> version =
      NegotiatedWebTransportVersion();
  if (!version.has_value() || *version == WebTransportHttp3Version::kDraft02) {
    return true;
  }

  if (!allow_extended_connect_) {
    CloseConnectionWithDetails(
        QUIC_HTTP_INVALID_SETTING_VALUE,
        "Negotiated use of WebTransport over HTTP/3 (draft-07 or later), but "
        "failed to negotiate extended CONNECT");
    return false;
  }

  if (http_datagram_support_ == HttpDatagramSupport::kDraft04) {
    CloseConnectionWithDetails(
        QUIC_HTTP_INVALID_SETTING_VALUE,
        "WebTransport over HTTP/3 version draft-07 and beyond requires the "
        "RFC version of HTTP datagrams");
    return false;
  }

  if (http_datagram_support_ != HttpDatagramSupport::kRfc) {
    CloseConnectionWithDetails(
        QUIC_HTTP_INVALID_SETTING_VALUE,
        "WebTransport over HTTP/3 requires HTTP datagrams support");
    return false;
  }

  return true;
}

std::optional<std::string> QuicSpdySession::OnSettingsFrameViaAlps(
    const SettingsFrame& frame) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnSettingsFrameReceivedViaAlps(frame);
  }
  for (const auto& setting : frame.values) {
    if (!OnSetting(setting.first, setting.second)) {
      // Do not bother adding the setting identifier or value to the error
      // message, because OnSetting() already closed the connection, therefore
      // the error message will be ignored.
      return "error parsing setting";
    }
  }
  return std::nullopt;
}

bool QuicSpdySession::VerifySettingIsZeroOrOne(uint64_t id, uint64_t value) {
  if (value == 0 || value == 1) {
    return true;
  }
  std::string error_details = absl::StrCat(
      "Received ",
      H3SettingsToString(static_cast<Http3AndQpackSettingsIdentifiers>(id)),
      " with invalid value ", value);
  QUIC_PEER_BUG(bad received setting) << ENDPOINT << error_details;
  CloseConnectionWithDetails(QUIC_HTTP_INVALID_SETTING_VALUE, error_details);
  return false;
}

bool QuicSpdySession::OnSetting(uint64_t id, uint64_t value) {
  if (VersionUsesHttp3(transport_version())) {
    // SETTINGS frame received on the control stream.
    switch (id) {
      case SETTINGS_QPACK_MAX_TABLE_CAPACITY: {
        QUIC_DVLOG(1)
            << ENDPOINT
            << "SETTINGS_QPACK_MAX_TABLE_CAPACITY received with value "
            << value;
        // Communicate |value| to encoder, because it is used for encoding
        // Required Insert Count.
        if (!qpack_encoder_->SetMaximumDynamicTableCapacity(value)) {
          CloseConnectionWithDetails(
              was_zero_rtt_rejected()
                  ? QUIC_HTTP_ZERO_RTT_REJECTION_SETTINGS_MISMATCH
                  : QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH,
              absl::StrCat(was_zero_rtt_rejected()
                               ? "Server rejected 0-RTT, aborting because "
                               : "",
                           "Server sent an SETTINGS_QPACK_MAX_TABLE_CAPACITY: ",
                           value, " while current value is: ",
                           qpack_encoder_->MaximumDynamicTableCapacity()));
          return false;
        }
        // However, limit the dynamic table capacity to
        // |qpack_maximum_dynamic_table_capacity_|.
        qpack_encoder_->SetDynamicTableCapacity(
            std::min(value, qpack_maximum_dynamic_table_capacity_));
        break;
      }
      case SETTINGS_MAX_FIELD_SECTION_SIZE:
        QUIC_DVLOG(1) << ENDPOINT
                      << "SETTINGS_MAX_FIELD_SECTION_SIZE received with value "
                      << value;
        if (max_outbound_header_list_size_ !=
                std::numeric_limits<size_t>::max() &&
            max_outbound_header_list_size_ > value) {
          CloseConnectionWithDetails(
              was_zero_rtt_rejected()
                  ? QUIC_HTTP_ZERO_RTT_REJECTION_SETTINGS_MISMATCH
                  : QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH,
              absl::StrCat(was_zero_rtt_rejected()
                               ? "Server rejected 0-RTT, aborting because "
                               : "",
                           "Server sent an SETTINGS_MAX_FIELD_SECTION_SIZE: ",
                           value, " which reduces current value: ",
                           max_outbound_header_list_size_));
          return false;
        }
        max_outbound_header_list_size_ = value;
        break;
      case SETTINGS_QPACK_BLOCKED_STREAMS: {
        QUIC_DVLOG(1) << ENDPOINT
                      << "SETTINGS_QPACK_BLOCKED_STREAMS received with value "
                      << value;
        if (!qpack_encoder_->SetMaximumBlockedStreams(value)) {
          CloseConnectionWithDetails(
              was_zero_rtt_rejected()
                  ? QUIC_HTTP_ZERO_RTT_REJECTION_SETTINGS_MISMATCH
                  : QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH,
              absl::StrCat(was_zero_rtt_rejected()
                               ? "Server rejected 0-RTT, aborting because "
                               : "",
                           "Server sent an SETTINGS_QPACK_BLOCKED_STREAMS: ",
                           value, " which reduces current value: ",
                           qpack_encoder_->maximum_blocked_streams()));
          return false;
        }
        break;
      }
      case SETTINGS_ENABLE_CONNECT_PROTOCOL: {
        QUIC_DVLOG(1) << ENDPOINT
                      << "SETTINGS_ENABLE_CONNECT_PROTOCOL received with value "
                      << value;
        if (!VerifySettingIsZeroOrOne(id, value)) {
          return false;
        }
        if (perspective() == Perspective::IS_CLIENT) {
          allow_extended_connect_ = value != 0;
        }
        break;
      }
      case spdy::SETTINGS_ENABLE_PUSH:
        ABSL_FALLTHROUGH_INTENDED;
      case spdy::SETTINGS_MAX_CONCURRENT_STREAMS:
        ABSL_FALLTHROUGH_INTENDED;
      case spdy::SETTINGS_INITIAL_WINDOW_SIZE:
        ABSL_FALLTHROUGH_INTENDED;
      case spdy::SETTINGS_MAX_FRAME_SIZE:
        CloseConnectionWithDetails(
            QUIC_HTTP_RECEIVE_SPDY_SETTING,
            absl::StrCat("received HTTP/2 specific setting in HTTP/3 session: ",
                         id));
        return false;
      case SETTINGS_H3_DATAGRAM_DRAFT04: {
        HttpDatagramSupport local_http_datagram_support =
            LocalHttpDatagramSupport();
        if (local_http_datagram_support != HttpDatagramSupport::kDraft04 &&
            local_http_datagram_support !=
                HttpDatagramSupport::kRfcAndDraft04) {
          break;
        }
        QUIC_DVLOG(1) << ENDPOINT
                      << "SETTINGS_H3_DATAGRAM_DRAFT04 received with value "
                      << value;
        if (!version().UsesHttp3()) {
          break;
        }
        if (!VerifySettingIsZeroOrOne(id, value)) {
          return false;
        }
        if (value && http_datagram_support_ != HttpDatagramSupport::kRfc) {
          // If both RFC 9297 and draft-04 are supported, we use the RFC. This
          // is implemented by ignoring SETTINGS_H3_DATAGRAM_DRAFT04 when we've
          // already parsed SETTINGS_H3_DATAGRAM.
          http_datagram_support_ = HttpDatagramSupport::kDraft04;
        }
        break;
      }
      case SETTINGS_H3_DATAGRAM: {
        HttpDatagramSupport local_http_datagram_support =
            LocalHttpDatagramSupport();
        if (local_http_datagram_support != HttpDatagramSupport::kRfc &&
            local_http_datagram_support !=
                HttpDatagramSupport::kRfcAndDraft04) {
          break;
        }
        QUIC_DVLOG(1) << ENDPOINT << "SETTINGS_H3_DATAGRAM received with value "
                      << value;
        if (!version().UsesHttp3()) {
          break;
        }
        if (!VerifySettingIsZeroOrOne(id, value)) {
          return false;
        }
        if (value) {
          http_datagram_support_ = HttpDatagramSupport::kRfc;
        }
        break;
      }
      case SETTINGS_WEBTRANS_DRAFT00:
        if (!WillNegotiateWebTransport()) {
          break;
        }
        QUIC_DVLOG(1) << ENDPOINT
                      << "SETTINGS_ENABLE_WEBTRANSPORT(02) received with value "
                      << value;
        if (!VerifySettingIsZeroOrOne(id, value)) {
          return false;
        }
        if (value == 1) {
          peer_web_transport_versions_.Set(WebTransportHttp3Version::kDraft02);
          if (perspective() == Perspective::IS_CLIENT) {
            allow_extended_connect_ = true;
          }
        }
        break;
      case SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07:
        if (!WillNegotiateWebTransport()) {
          break;
        }
        QUIC_DVLOG(1)
            << ENDPOINT
            << "SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07 received with value "
            << value;
        if (value > 0) {
          peer_web_transport_versions_.Set(WebTransportHttp3Version::kDraft07);
          if (perspective() == Perspective::IS_CLIENT) {
            max_webtransport_sessions_[WebTransportHttp3Version::kDraft07] =
                value;
          }
        }
        break;
      default:
        QUIC_DVLOG(1) << ENDPOINT << "Unknown setting identifier " << id
                      << " received with value " << value;
        // Ignore unknown settings.
        break;
    }
    return true;
  }

  // SETTINGS frame received on the headers stream.
  switch (id) {
    case spdy::SETTINGS_HEADER_TABLE_SIZE:
      QUIC_DVLOG(1) << ENDPOINT
                    << "SETTINGS_HEADER_TABLE_SIZE received with value "
                    << value;
      spdy_framer_.UpdateHeaderEncoderTableSize(
          std::min<uint64_t>(value, kHpackEncoderDynamicTableSizeLimit));
      break;
    case spdy::SETTINGS_ENABLE_PUSH:
      if (perspective() == Perspective::IS_SERVER) {
        // See rfc7540, Section 6.5.2.
        if (value > 1) {
          QUIC_DLOG(ERROR) << ENDPOINT << "Invalid value " << value
                           << " received for SETTINGS_ENABLE_PUSH.";
          if (IsConnected()) {
            CloseConnectionWithDetails(
                QUIC_INVALID_HEADERS_STREAM_DATA,
                absl::StrCat("Invalid value for SETTINGS_ENABLE_PUSH: ",
                             value));
          }
          return true;
        }
        QUIC_DVLOG(1) << ENDPOINT << "SETTINGS_ENABLE_PUSH received with value "
                      << value << ", ignoring.";
        break;
      } else {
        QUIC_DLOG(ERROR)
            << ENDPOINT
            << "Invalid SETTINGS_ENABLE_PUSH received by client with value "
            << value;
        if (IsConnected()) {
          CloseConnectionWithDetails(
              QUIC_INVALID_HEADERS_STREAM_DATA,
              absl::StrCat("Unsupported field of HTTP/2 SETTINGS frame: ", id));
        }
      }
      break;
    case spdy::SETTINGS_MAX_HEADER_LIST_SIZE:
      QUIC_DVLOG(1) << ENDPOINT
                    << "SETTINGS_MAX_HEADER_LIST_SIZE received with value "
                    << value;
      max_outbound_header_list_size_ = value;
      break;
    default:
      QUIC_DLOG(ERROR) << ENDPOINT << "Unknown setting identifier " << id
                       << " received with value " << value;
      if (IsConnected()) {
        CloseConnectionWithDetails(
            QUIC_INVALID_HEADERS_STREAM_DATA,
            absl::StrCat("Unsupported field of HTTP/2 SETTINGS frame: ", id));
      }
  }
  return true;
}

bool QuicSpdySession::ShouldReleaseHeadersStreamSequencerBuffer() {
  return false;
}

void QuicSpdySession::OnHeaders(SpdyStreamId stream_id, bool has_priority,
                                const spdy::SpdyStreamPrecedence& precedence,
                                bool fin) {
  if (has_priority) {
    if (perspective() == Perspective::IS_CLIENT) {
      CloseConnectionWithDetails(QUIC_INVALID_HEADERS_STREAM_DATA,
                                 "Server must not send priorities.");
      return;
    }
    OnStreamHeadersPriority(stream_id, precedence);
  } else {
    if (perspective() == Perspective::IS_SERVER) {
      CloseConnectionWithDetails(QUIC_INVALID_HEADERS_STREAM_DATA,
                                 "Client must send priorities.");
      return;
    }
  }
  QUICHE_DCHECK_EQ(QuicUtils::GetInvalidStreamId(transport_version()),
                   stream_id_);
  stream_id_ = stream_id;
  fin_ = fin;
}

// TODO (wangyix): Why is SpdyStreamId used instead of QuicStreamId?
// This occurs in many places in this file.
void QuicSpdySession::OnPriority(SpdyStreamId stream_id,
                                 const spdy::SpdyStreamPrecedence& precedence) {
  if (perspective() == Perspective::IS_CLIENT) {
    CloseConnectionWithDetails(QUIC_INVALID_HEADERS_STREAM_DATA,
                               "Server must not send PRIORITY frames.");
    return;
  }
  OnPriorityFrame(stream_id, precedence);
}

void QuicSpdySession::OnHeaderList(const QuicHeaderList& header_list) {
  QUIC_DVLOG(1) << ENDPOINT << "Received header list for stream " << stream_id_
                << ": " << header_list.DebugString();
  QUICHE_DCHECK(!VersionUsesHttp3(transport_version()));

  OnStreamHeaderList(stream_id_, fin_, frame_len_, header_list);

  // Reset state for the next frame.
  stream_id_ = QuicUtils::GetInvalidStreamId(transport_version());
  fin_ = false;
  frame_len_ = 0;
}

void QuicSpdySession::OnCompressedFrameSize(size_t frame_len) {
  frame_len_ += frame_len;
}

void QuicSpdySession::CloseConnectionWithDetails(QuicErrorCode error,
                                                 const std::string& details) {
  connection()->CloseConnection(
      error, details, ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

bool QuicSpdySession::HasActiveRequestStreams() const {
  return GetNumActiveStreams() + num_draining_streams() > 0;
}

QuicStream* QuicSpdySession::ProcessReadUnidirectionalPendingStream(
    PendingStream* pending) {
  struct iovec iov;
  if (!pending->sequencer()->GetReadableRegion(&iov)) {
    // The first byte hasn't been received yet.
    return nullptr;
  }

  QuicDataReader reader(static_cast<char*>(iov.iov_base), iov.iov_len);
  uint8_t stream_type_length = reader.PeekVarInt62Length();
  uint64_t stream_type = 0;
  if (!reader.ReadVarInt62(&stream_type)) {
    if (pending->sequencer()->NumBytesBuffered() ==
        pending->sequencer()->close_offset()) {
      // Stream received FIN but there are not enough bytes for stream type.
      // Mark all bytes consumed in order to close stream.
      pending->MarkConsumed(pending->sequencer()->close_offset());
    }
    return nullptr;
  }
  pending->MarkConsumed(stream_type_length);

  switch (stream_type) {
    case kControlStream: {  // HTTP/3 control stream.
      if (receive_control_stream_) {
        CloseConnectionOnDuplicateHttp3UnidirectionalStreams("Control");
        return nullptr;
      }
      auto receive_stream =
          std::make_unique<QuicReceiveControlStream>(pending, this);
      receive_control_stream_ = receive_stream.get();
      ActivateStream(std::move(receive_stream));
      QUIC_DVLOG(1) << ENDPOINT << "Receive Control stream is created";
      if (debug_visitor_ != nullptr) {
        debug_visitor_->OnPeerControlStreamCreated(
            receive_control_stream_->id());
      }
      return receive_control_stream_;
    }
    case kServerPushStream: {  // Push Stream.
      CloseConnectionWithDetails(QUIC_HTTP_RECEIVE_SERVER_PUSH,
                                 "Received server push stream");
      return nullptr;
    }
    case kQpackEncoderStream: {  // QPACK encoder stream.
      if (qpack_encoder_receive_stream_) {
        CloseConnectionOnDuplicateHttp3UnidirectionalStreams("QPACK encoder");
        return nullptr;
      }
      auto encoder_receive = std::make_unique<QpackReceiveStream>(
          pending, this, qpack_decoder_->encoder_stream_receiver());
      qpack_encoder_receive_stream_ = encoder_receive.get();
      ActivateStream(std::move(encoder_receive));
      QUIC_DVLOG(1) << ENDPOINT << "Receive QPACK Encoder stream is created";
      if (debug_visitor_ != nullptr) {
        debug_visitor_->OnPeerQpackEncoderStreamCreated(
            qpack_encoder_receive_stream_->id());
      }
      return qpack_encoder_receive_stream_;
    }
    case kQpackDecoderStream: {  // QPACK decoder stream.
      if (qpack_decoder_receive_stream_) {
        CloseConnectionOnDuplicateHttp3UnidirectionalStreams("QPACK decoder");
        return nullptr;
      }
      auto decoder_receive = std::make_unique<QpackReceiveStream>(
          pending, this, qpack_encoder_->decoder_stream_receiver());
      qpack_decoder_receive_stream_ = decoder_receive.get();
      ActivateStream(std::move(decoder_receive));
      QUIC_DVLOG(1) << ENDPOINT << "Receive QPACK Decoder stream is created";
      if (debug_visitor_ != nullptr) {
        debug_visitor_->OnPeerQpackDecoderStreamCreated(
            qpack_decoder_receive_stream_->id());
      }
      return qpack_decoder_receive_stream_;
    }
    case kWebTransportUnidirectionalStream: {
      // Note that this checks whether WebTransport is enabled on the receiver
      // side, as we may receive WebTransport streams before peer's SETTINGS are
      // received.
      // TODO(b/184156476): consider whether this means we should drop buffered
      // streams if we don't receive indication of WebTransport support.
      if (!WillNegotiateWebTransport()) {
        // Treat as unknown stream type.
        break;
      }
      QUIC_DVLOG(1) << ENDPOINT << "Created an incoming WebTransport stream "
                    << pending->id();
      auto stream_owned =
          std::make_unique<WebTransportHttp3UnidirectionalStream>(pending,
                                                                  this);
      WebTransportHttp3UnidirectionalStream* stream = stream_owned.get();
      ActivateStream(std::move(stream_owned));
      return stream;
    }
    default:
      break;
  }
  MaybeSendStopSendingFrame(
      pending->id(),
      QuicResetStreamError::FromInternal(QUIC_STREAM_STREAM_CREATION_ERROR));
  pending->StopReading();
  return nullptr;
}

void QuicSpdySession::MaybeInitializeHttp3UnidirectionalStreams() {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  if (!send_control_stream_ && CanOpenNextOutgoingUnidirectionalStream()) {
    auto send_control = std::make_unique<QuicSendControlStream>(
        GetNextOutgoingUnidirectionalStreamId(), this, settings_);
    send_control_stream_ = send_control.get();
    ActivateStream(std::move(send_control));
    if (debug_visitor_) {
      debug_visitor_->OnControlStreamCreated(send_control_stream_->id());
    }
  }

  if (!qpack_decoder_send_stream_ &&
      CanOpenNextOutgoingUnidirectionalStream()) {
    auto decoder_send = std::make_unique<QpackSendStream>(
        GetNextOutgoingUnidirectionalStreamId(), this, kQpackDecoderStream);
    qpack_decoder_send_stream_ = decoder_send.get();
    ActivateStream(std::move(decoder_send));
    qpack_decoder_->set_qpack_stream_sender_delegate(
        qpack_decoder_send_stream_);
    if (debug_visitor_) {
      debug_visitor_->OnQpackDecoderStreamCreated(
          qpack_decoder_send_stream_->id());
    }
  }

  if (!qpack_encoder_send_stream_ &&
      CanOpenNextOutgoingUnidirectionalStream()) {
    auto encoder_send = std::make_unique<QpackSendStream>(
        GetNextOutgoingUnidirectionalStreamId(), this, kQpackEncoderStream);
    qpack_encoder_send_stream_ = encoder_send.get();
    ActivateStream(std::move(encoder_send));
    qpack_encoder_->set_qpack_stream_sender_delegate(
        qpack_encoder_send_stream_);
    if (debug_visitor_) {
      debug_visitor_->OnQpackEncoderStreamCreated(
          qpack_encoder_send_stream_->id());
    }
  }
}

void QuicSpdySession::BeforeConnectionCloseSent() {
  if (!VersionUsesHttp3(transport_version()) || !IsEncryptionEstablished()) {
    return;
  }

  QUICHE_DCHECK_EQ(perspective(), Perspective::IS_SERVER);

  QuicStreamId stream_id =
      GetLargestPeerCreatedStreamId(/*unidirectional = */ false);

  if (stream_id == QuicUtils::GetInvalidStreamId(transport_version())) {
    // No client-initiated bidirectional streams received yet.
    // Send 0 to let client know that all requests can be retried.
    stream_id = 0;
  } else {
    // Tell client that streams starting with the next after the largest
    // received one can be retried.
    stream_id += QuicUtils::StreamIdDelta(transport_version());
  }
  if (last_sent_http3_goaway_id_.has_value() &&
      *last_sent_http3_goaway_id_ <= stream_id) {
    // Do not send GOAWAY frame with a higher id, because it is forbidden.
    // Do not send one with same stream id as before, since frames on the
    // control stream are guaranteed to be processed in order.
    return;
  }

  send_control_stream_->SendGoAway(stream_id);
  last_sent_http3_goaway_id_ = stream_id;
}

void QuicSpdySession::MaybeBundleOpportunistically() {
  if (qpack_decoder_ != nullptr) {
    qpack_decoder_->FlushDecoderStream();
  }
}

void QuicSpdySession::OnCanCreateNewOutgoingStream(bool unidirectional) {
  if (unidirectional && VersionUsesHttp3(transport_version())) {
    MaybeInitializeHttp3UnidirectionalStreams();
  }
}

bool QuicSpdySession::goaway_received() const {
  return VersionUsesHttp3(transport_version())
             ? last_received_http3_goaway_id_.has_value()
             : transport_goaway_received();
}

bool QuicSpdySession::goaway_sent() const {
  return VersionUsesHttp3(transport_version())
             ? last_sent_http3_goaway_id_.has_value()
             : transport_goaway_sent();
}

void QuicSpdySession::CloseConnectionOnDuplicateHttp3UnidirectionalStreams(
    absl::string_view type) {
  QUIC_PEER_BUG(quic_peer_bug_10360_9) << absl::StrCat(
      "Received a duplicate ", type, " stream: Closing connection.");
  CloseConnectionWithDetails(QUIC_HTTP_DUPLICATE_UNIDIRECTIONAL_STREAM,
                             absl::StrCat(type, " stream is received twice."));
}

// static
void QuicSpdySession::LogHeaderCompressionRatioHistogram(
    bool using_qpack, bool is_sent, QuicByteCount compressed,
    QuicByteCount uncompressed) {
  if (compressed <= 0 || uncompressed <= 0) {
    return;
  }

  int ratio = 100 * (compressed) / (uncompressed);
  if (ratio < 1) {
    ratio = 1;
  } else if (ratio > 200) {
    ratio = 200;
  }

  // Note that when using histogram macros in Chromium, the histogram name must
  // be the same across calls for any given call site.
  if (using_qpack) {
    if (is_sent) {
      QUIC_HISTOGRAM_COUNTS("QuicSession.HeaderCompressionRatioQpackSent",
                            ratio, 1, 200, 200,
                            "Header compression ratio as percentage for sent "
                            "headers using QPACK.");
    } else {
      QUIC_HISTOGRAM_COUNTS("QuicSession.HeaderCompressionRatioQpackReceived",
                            ratio, 1, 200, 200,
                            "Header compression ratio as percentage for "
                            "received headers using QPACK.");
    }
  } else {
    if (is_
"""


```
Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code belongs to the Chromium network stack and is specifically for handling HTTP/3 streams using the QUIC protocol.

Here's a breakdown of the code's responsibilities based on the provided functions:

1. **Header Handling:**
    - Parsing and validation of HTTP status codes (`ParseHeaderStatusCode`).
    - Tracking the completion of trailer headers (`FinishedReadingTrailers`).
    - Handling incoming HEADERS frames: starting, processing payload, and ending (`OnHeadersFrameStart`, `OnHeadersFramePayload`, `OnHeadersFrameEnd`).
    - Using `QpackDecodedHeadersAccumulator` for decoding headers.
    - Sending HEADERS frames (`WriteHeadersImpl`).
    - Validating received headers (`ValidateReceivedHeaders`, `AreHeaderFieldValuesValid`).

2. **Data Frame Handling:**
    - Handling incoming DATA frames: starting, processing payload, and ending (`OnDataFrameStart`, `OnDataFramePayload`, `OnDataFrameEnd`).

3. **Stream Frame Acknowledgement and Retransmission:**
    - Handling acknowledgement of stream frames (`OnStreamFrameAcked`).
    - Handling retransmission of stream frames (`OnStreamFrameRetransmitted`).
    - Calculating the number of header bytes within an acknowledged interval (`GetNumFrameHeadersInInterval`).

4. **WebTransport Integration:**
    - Handling `WEBTRANSPORT_STREAM` frames to establish WebTransport data streams (`OnWebTransportStreamFrameType`).
    - Managing the state of WebTransport connections (`MaybeProcessReceivedWebTransportHeaders`, `MaybeProcessSentWebTransportHeaders`).
    - Managing `WebTransportDataStream` objects.
    - Converting a regular QUIC stream to a WebTransport data stream (`ConvertToWebTransportDataStream`).
    - Preventing operations on WebTransport data streams when they are not allowed (`AssertNotWebTransportDataStream`).

5. **Metadata Frame Handling:**
    - Handling incoming METADATA frames: starting, processing payload, and ending (`OnMetadataFrameStart`, `OnMetadataFramePayload`, `OnMetadataFrameEnd`).
    - Using `MetadataDecoder` to decode metadata.

6. **Unknown Frame Handling:**
    - Handling frames of unknown types (`OnUnknownFrameStart`, `OnUnknownFramePayload`, `OnUnknownFrameEnd`).

7. **Capsule Handling (for Extensible Datagrams):**
    - Handling incoming capsules (`OnCapsule`).
    - Handling capsule parsing errors (`OnCapsuleParseFailure`).
    - Sending capsules (`WriteCapsule`, `WriteGreaseCapsule`).

8. **Datagram Handling (HTTP/3 Datagrams):**
    - Sending HTTP/3 datagrams (`SendHttp3Datagram`).
    - Receiving HTTP/3 datagrams (`OnDatagramReceived`, `HandleReceivedDatagram`).
    - Registering and unregistering datagram visitors (`RegisterHttp3DatagramVisitor`, `UnregisterHttp3DatagramVisitor`, `ReplaceHttp3DatagramVisitor`).
    - Getting the maximum datagram size (`GetMaxDatagramSize`).

9. **CONNECT-IP Capsule Handling:**
    - Registering and unregistering CONNECT-IP visitors (`RegisterConnectIpVisitor`, `UnregisterConnectIpVisitor`, `ReplaceConnectIpVisitor`).

10. **Flow Control and Buffering:**
    - Determining if new body data can be written (`CanWriteNewBodyData`).
    - Handling write availability (`OnCanWriteNewData`).
    - Managing the body data buffer (`HandleBodyAvailable`).

11. **Error Handling and Stream Management:**
    - Handling header decoding errors (`OnHeaderDecodingError`).
    - Stopping reading on the stream (`StopReading`).
    - Handling invalid headers (`OnInvalidHeaders`).
    - Closing the read side of the stream (`CloseReadSide`).

The code focuses on processing incoming and outgoing HTTP/3 messages and related extensions on a QUIC stream. It handles different frame types, manages header compression and decompression, and integrates with WebTransport and HTTP/3 datagrams.
这是 `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream.cc` 文件的第二部分，它延续了第一部分的功能，主要负责处理 QUIC 上 HTTP/3 流的接收和发送数据，以及处理与 HTTP/3 相关的扩展，例如 WebTransport 和 HTTP/3 Datagrams。

**归纳一下它的功能：**

1. **处理接收到的数据帧 (DATA Frames):**
   - `OnDataFrameStart`, `OnDataFramePayload`, `OnDataFrameEnd`:  负责接收 HTTP/3 的 DATA 帧，这些帧包含了 HTTP 消息的 body 部分。它会检查帧的顺序是否正确，并将 payload 数据传递给 `body_manager_` 进行管理。

2. **处理接收到的头部帧 (HEADERS Frames):**
   - `OnHeadersFrameStart`, `OnHeadersFramePayload`, `OnHeadersFrameEnd`: 负责接收 HTTP/3 的 HEADERS 帧，这些帧包含了 HTTP 头部信息。它使用 `QpackDecodedHeadersAccumulator` 来解码 QPACK 压缩的头部。

3. **处理接收到的流帧的确认和重传:**
   - `OnStreamFrameAcked`: 当发送的流帧被确认收到时调用，用于更新已确认的数据量。
   - `OnStreamFrameRetransmitted`: 当发送的流帧需要重传时调用。
   - `GetNumFrameHeadersInInterval`:  计算在给定的偏移量和长度区间内，有多少字节是头部信息。

4. **处理 WebTransport 流的转换:**
   - `OnWebTransportStreamFrameType`: 当接收到一个 `WEBTRANSPORT_STREAM` 帧时调用，用于将当前的 HTTP/3 流转换为 WebTransport 数据流。
   - `MaybeProcessReceivedWebTransportHeaders`, `MaybeProcessSentWebTransportHeaders`:  检查接收或发送的头部中是否包含 WebTransport 相关的头部信息，并据此创建 `WebTransportHttp3` 对象。
   - `ConvertToWebTransportDataStream`: 将当前的 QUIC 流转换为 WebTransport 数据流。
   - `AssertNotWebTransportDataStream`: 确保某些操作不会在 WebTransport 数据流上执行。

5. **处理元数据帧 (METADATA Frames):**
   - `OnMetadataFrameStart`, `OnMetadataFramePayload`, `OnMetadataFrameEnd`:  负责接收 HTTP/3 的 METADATA 帧，这些帧用于传输与 HTTP 消息相关的元数据。

6. **处理未知类型的帧:**
   - `OnUnknownFrameStart`, `OnUnknownFramePayload`, `OnUnknownFrameEnd`:  负责接收和处理未知类型的 HTTP/3 帧。

7. **发送头部信息:**
   - `WriteHeadersImpl`:  用于发送 HTTP 头部信息，如果是 HTTP/3，则会使用 QPACK 进行压缩。

8. **判断是否可以写入新的 Body 数据:**
   - `CanWriteNewBodyData`:  根据当前流的状态判断是否可以写入新的 HTTP Body 数据。

9. **处理写入就绪事件:**
   - `OnCanWriteNewData`: 当流可以写入更多数据时被调用，如果这是一个 WebTransport 数据流，则会通知相应的 WebTransport 组件。

10. **处理接收到的 HTTP/3 Datagrams (用户数据报):**
    - `HandleReceivedDatagram`: 处理接收到的 HTTP/3 用户数据报。
    - `OnDatagramReceived`: 当底层接收到数据报时调用，并将数据传递给 `HandleReceivedDatagram`。
    - `RegisterHttp3DatagramVisitor`, `UnregisterHttp3DatagramVisitor`, `ReplaceHttp3DatagramVisitor`:  用于注册和管理处理 HTTP/3 数据报的访问者对象。
    - `SendHttp3Datagram`: 用于发送 HTTP/3 数据报。
    - `GetMaxDatagramSize`: 获取可以发送的最大数据报大小。

11. **处理 Capsule (用于扩展数据报):**
    - `OnCapsule`: 处理接收到的 Capsule，这些 Capsule 可以包含 HTTP/3 Datagrams 或 WebTransport 相关的控制信息。
    - `OnCapsuleParseFailure`: 处理 Capsule 解析失败的情况。
    - `WriteCapsule`, `WriteGreaseCapsule`: 用于发送 Capsule。

12. **处理 CONNECT-IP 相关的 Capsule:**
    - `RegisterConnectIpVisitor`, `UnregisterConnectIpVisitor`, `ReplaceConnectIpVisitor`: 用于注册和管理处理 CONNECT-IP  Capsule 的访问者对象.

13. **设置最大数据报在队列中的时间:**
    - `SetMaxDatagramTimeInQueue`: 设置数据报在发送队列中的最大时间。

14. **处理可读的 Body 数据:**
    - `HandleBodyAvailable`: 当有新的 Body 数据可读时调用，如果启用了 Capsule，则会先尝试解析 Capsule。

15. **验证接收到的头部信息:**
    - `ValidateReceivedHeaders`: 验证接收到的 HTTP 头部信息的有效性。
    - `AreHeaderFieldValuesValid`: 检查头部字段的值是否包含非法字符（如 NULL, CR, LF）。

16. **停止读取流数据:**
    - `StopReading`: 停止读取流数据，对于 HTTP/3，还可以选择停止头部解压缩。

17. **处理无效的头部信息:**
    - `OnInvalidHeaders`: 当接收到无效的头部信息时调用。

18. **关闭读取端:**
    - `CloseReadSide`: 关闭流的读取端。

**与 Javascript 的关系举例：**

WebTransport 是一个与 Javascript 密切相关的特性。Javascript 可以使用 WebTransport API 通过 HTTP/3 连接建立双向的、低延迟的通信通道。

例如，一个 Javascript 客户端可以使用 WebTransport API 发起一个连接，服务器端的 `QuicSpdyStream` 接收到包含 `:method: CONNECT` 和 `:protocol: webtransport` 的头部时，会调用 `MaybeProcessReceivedWebTransportHeaders`，并创建一个 `WebTransportHttp3` 对象。之后，Javascript 可以在这个 WebTransport 连接上发送和接收数据，这些数据最终会通过 `QuicSpdyStream` 的相关方法进行处理。

**逻辑推理举例：**

**假设输入:** 接收到一个 HEADERS 帧，包含以下头部：
```
:status: 200
content-type: text/html
```

**处理过程:**
1. `OnHeadersFrameStart` 被调用，记录头部长度和 payload 长度。
2. `OnHeadersFramePayload` 被调用，将头部 payload 传递给 `qpack_decoded_headers_accumulator_` 进行解码。
3. `OnHeadersFrameEnd` 被调用，表示 HEADERS 帧结束。`qpack_decoded_headers_accumulator_` 完成解码，得到一个 `QuicHeaderList`。
4. 解码后的头部信息 (状态码 200, 内容类型 text/html) 会被传递给流的代理 (`stream_delegate()`) 的相应方法进行处理。

**输出:** 流的代理会收到一个包含解码后头部信息的事件，可以根据这些信息更新应用程序状态。

**用户或编程常见的使用错误举例：**

**错误:** 在发送 HTTP 请求的 Body 数据之前，尝试发送一个 `WEBTRANSPORT_STREAM` 帧。

**说明:**  根据代码中的 `ConvertToWebTransportDataStream` 方法，如果 `send_buffer().stream_offset()` 不为 0，表示已经发送了数据，此时尝试发送 `WEBTRANSPORT_STREAM` 帧会导致错误。这是因为 WebTransport 数据流的转换必须在发送任何其他数据之前完成。

**用户操作如何一步步到达这里，作为调试线索：**

假设用户正在使用 Chrome 浏览器访问一个支持 HTTP/3 和 WebTransport 的网站。

1. **用户在地址栏输入网址并回车。**
2. **Chrome 的网络栈开始建立 QUIC 连接。**
3. **连接建立成功后，Chrome 发送一个 HTTP 请求，该请求可能包含升级到 WebTransport 的意愿（通过发送特定的头部）。**
4. **服务器接受 WebTransport 升级，并可能立即发送一个 `WEBTRANSPORT_STREAM` 帧，指示该流将用于 WebTransport 会话。**
5. **Chrome 的网络栈接收到这个 `WEBTRANSPORT_STREAM` 帧，并调用 `QuicSpdyStream::OnWebTransportStreamFrameType` 方法。**

作为调试线索，如果在 `OnWebTransportStreamFrameType` 中出现问题，可以检查以下内容：
- 当前流的 ID (`id()`) 是否是服务器发起的流。
- 是否已经接收到该流的其他 HTTP 数据。
- `spdy_session_->SupportedWebTransportVersion()` 返回的值是否符合预期。

这段代码是 Chromium 网络栈中处理 HTTP/3 流的核心部分，它负责解析和处理各种 HTTP/3 帧，并集成了 WebTransport 和 HTTP/3 Datagrams 等重要的扩展功能。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
e(status, status_code);
}

bool QuicSpdyStream::ParseHeaderStatusCode(absl::string_view status,
                                           int* status_code) {
  if (status.size() != 3) {
    return false;
  }
  // First character must be an integer in range [1,5].
  if (status[0] < '1' || status[0] > '5') {
    return false;
  }
  // The remaining two characters must be integers.
  if (!isdigit(status[1]) || !isdigit(status[2])) {
    return false;
  }
  return absl::SimpleAtoi(status, status_code);
}

bool QuicSpdyStream::FinishedReadingTrailers() const {
  // If no further trailing headers are expected, and the decompressed trailers
  // (if any) have been consumed, then reading of trailers is finished.
  if (!fin_received()) {
    return false;
  } else if (!trailers_decompressed_) {
    return true;
  } else {
    return trailers_consumed_;
  }
}

bool QuicSpdyStream::OnDataFrameStart(QuicByteCount header_length,
                                      QuicByteCount payload_length) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  if (spdy_session_->debug_visitor()) {
    spdy_session_->debug_visitor()->OnDataFrameReceived(id(), payload_length);
  }

  if (!headers_decompressed_ || trailers_decompressed_) {
    QUICHE_LOG(INFO) << ENDPOINT << "stream_id: " << id()
                     << ", headers_decompressed: "
                     << (headers_decompressed_ ? "true" : "false")
                     << ", trailers_decompressed: "
                     << (trailers_decompressed_ ? "true" : "false")
                     << ", NumBytesConsumed: "
                     << sequencer()->NumBytesConsumed()
                     << ", total_body_bytes_received: "
                     << body_manager_.total_body_bytes_received()
                     << ", header_length: " << header_length
                     << ", payload_length: " << payload_length;
    stream_delegate()->OnStreamError(
        QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM,
        "Unexpected DATA frame received.");
    return false;
  }

  sequencer()->MarkConsumed(body_manager_.OnNonBody(header_length));

  return true;
}

bool QuicSpdyStream::OnDataFramePayload(absl::string_view payload) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  body_manager_.OnBody(payload);

  return true;
}

bool QuicSpdyStream::OnDataFrameEnd() {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  QUIC_DVLOG(1) << ENDPOINT
                << "Reaches the end of a data frame. Total bytes received are "
                << body_manager_.total_body_bytes_received();
  return true;
}

bool QuicSpdyStream::OnStreamFrameAcked(QuicStreamOffset offset,
                                        QuicByteCount data_length,
                                        bool fin_acked,
                                        QuicTime::Delta ack_delay_time,
                                        QuicTime receive_timestamp,
                                        QuicByteCount* newly_acked_length) {
  const bool new_data_acked = QuicStream::OnStreamFrameAcked(
      offset, data_length, fin_acked, ack_delay_time, receive_timestamp,
      newly_acked_length);

  const QuicByteCount newly_acked_header_length =
      GetNumFrameHeadersInInterval(offset, data_length);
  QUICHE_DCHECK_LE(newly_acked_header_length, *newly_acked_length);
  unacked_frame_headers_offsets_.Difference(offset, offset + data_length);
  if (ack_listener_ != nullptr && new_data_acked) {
    ack_listener_->OnPacketAcked(
        *newly_acked_length - newly_acked_header_length, ack_delay_time);
  }
  return new_data_acked;
}

void QuicSpdyStream::OnStreamFrameRetransmitted(QuicStreamOffset offset,
                                                QuicByteCount data_length,
                                                bool fin_retransmitted) {
  QuicStream::OnStreamFrameRetransmitted(offset, data_length,
                                         fin_retransmitted);

  const QuicByteCount retransmitted_header_length =
      GetNumFrameHeadersInInterval(offset, data_length);
  QUICHE_DCHECK_LE(retransmitted_header_length, data_length);

  if (ack_listener_ != nullptr) {
    ack_listener_->OnPacketRetransmitted(data_length -
                                         retransmitted_header_length);
  }
}

QuicByteCount QuicSpdyStream::GetNumFrameHeadersInInterval(
    QuicStreamOffset offset, QuicByteCount data_length) const {
  QuicByteCount header_acked_length = 0;
  QuicIntervalSet<QuicStreamOffset> newly_acked(offset, offset + data_length);
  newly_acked.Intersection(unacked_frame_headers_offsets_);
  for (const auto& interval : newly_acked) {
    header_acked_length += interval.Length();
  }
  return header_acked_length;
}

bool QuicSpdyStream::OnHeadersFrameStart(QuicByteCount header_length,
                                         QuicByteCount payload_length) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  QUICHE_DCHECK(!qpack_decoded_headers_accumulator_);

  if (spdy_session_->debug_visitor()) {
    spdy_session_->debug_visitor()->OnHeadersFrameReceived(id(),
                                                           payload_length);
  }

  headers_payload_length_ = payload_length;

  if (trailers_decompressed_) {
    QUICHE_LOG(INFO) << ENDPOINT << "stream_id: " << id()
                     << ", headers_decompressed: "
                     << (headers_decompressed_ ? "true" : "false")
                     << ", NumBytesConsumed: "
                     << sequencer()->NumBytesConsumed()
                     << ", total_body_bytes_received: "
                     << body_manager_.total_body_bytes_received();
    stream_delegate()->OnStreamError(
        QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM,
        "HEADERS frame received after trailing HEADERS.");
    return false;
  }

  sequencer()->MarkConsumed(body_manager_.OnNonBody(header_length));

  qpack_decoded_headers_accumulator_ =
      std::make_unique<QpackDecodedHeadersAccumulator>(
          id(), spdy_session_->qpack_decoder(), this,
          spdy_session_->max_inbound_header_list_size());

  return true;
}

bool QuicSpdyStream::OnHeadersFramePayload(absl::string_view payload) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  if (!qpack_decoded_headers_accumulator_) {
    QUIC_BUG(b215142466_OnHeadersFramePayload);
    OnHeaderDecodingError(QUIC_INTERNAL_ERROR,
                          "qpack_decoded_headers_accumulator_ is nullptr");
    return false;
  }

  qpack_decoded_headers_accumulator_->Decode(payload);

  // |qpack_decoded_headers_accumulator_| is reset if an error is detected.
  if (!qpack_decoded_headers_accumulator_) {
    return false;
  }

  sequencer()->MarkConsumed(body_manager_.OnNonBody(payload.size()));
  return true;
}

bool QuicSpdyStream::OnHeadersFrameEnd() {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  if (!qpack_decoded_headers_accumulator_) {
    QUIC_BUG(b215142466_OnHeadersFrameEnd);
    OnHeaderDecodingError(QUIC_INTERNAL_ERROR,
                          "qpack_decoded_headers_accumulator_ is nullptr");
    return false;
  }

  qpack_decoded_headers_accumulator_->EndHeaderBlock();

  // If decoding is complete or an error is detected, then
  // |qpack_decoded_headers_accumulator_| is already reset.
  if (qpack_decoded_headers_accumulator_) {
    blocked_on_decoding_headers_ = true;
    header_block_received_time_ = session()->GetClock()->ApproximateNow();
    return false;
  }

  return !sequencer()->IsClosed() && !reading_stopped();
}

void QuicSpdyStream::OnWebTransportStreamFrameType(
    QuicByteCount header_length, WebTransportSessionId session_id) {
  QUIC_DVLOG(1) << ENDPOINT << " Received WEBTRANSPORT_STREAM on stream "
                << id() << " for session " << session_id;
  QuicStreamOffset offset = sequencer()->NumBytesConsumed();
  sequencer()->MarkConsumed(header_length);

  std::optional<WebTransportHttp3Version> version =
      spdy_session_->SupportedWebTransportVersion();
  QUICHE_DCHECK(version.has_value());
  if (version == WebTransportHttp3Version::kDraft02) {
    if (headers_payload_length_ > 0 || headers_decompressed_) {
      std::string error =
          absl::StrCat("Stream ", id(),
                       " attempted to convert itself into a WebTransport data "
                       "stream, but it already has HTTP data on it");
      QUIC_PEER_BUG(WEBTRANSPORT_STREAM received on HTTP request)
          << ENDPOINT << error;
      OnUnrecoverableError(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM,
                           error);
      return;
    }
  } else {
    if (offset > 0) {
      std::string error =
          absl::StrCat("Stream ", id(),
                       " received WEBTRANSPORT_STREAM at a non-zero offset");
      QUIC_DLOG(ERROR) << ENDPOINT << error;
      OnUnrecoverableError(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM,
                           error);
      return;
    }
  }

  if (QuicUtils::IsOutgoingStreamId(spdy_session_->version(), id(),
                                    spdy_session_->perspective())) {
    std::string error = absl::StrCat(
        "Stream ", id(),
        " attempted to convert itself into a WebTransport data stream, but "
        "only the initiator of the stream can do that");
    QUIC_PEER_BUG(WEBTRANSPORT_STREAM received on outgoing request)
        << ENDPOINT << error;
    OnUnrecoverableError(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM,
                         error);
    return;
  }

  QUICHE_DCHECK(web_transport_ == nullptr);
  web_transport_data_ =
      std::make_unique<WebTransportDataStream>(this, session_id);
  spdy_session_->AssociateIncomingWebTransportStreamWithSession(session_id,
                                                                id());
}

bool QuicSpdyStream::OnMetadataFrameStart(QuicByteCount header_length,
                                          QuicByteCount payload_length) {
  if (metadata_visitor_ == nullptr) {
    return OnUnknownFrameStart(
        static_cast<uint64_t>(quic::HttpFrameType::METADATA), header_length,
        payload_length);
  }

  QUIC_BUG_IF(Invalid METADATA state, metadata_decoder_ != nullptr);
  constexpr size_t kMaxMetadataBlockSize = 1 << 20;  // 1 MB
  metadata_decoder_ = std::make_unique<MetadataDecoder>(
      id(), kMaxMetadataBlockSize, header_length, payload_length);

  // Consume the frame header.
  QUIC_DVLOG(1) << ENDPOINT << "Consuming " << header_length
                << " byte long frame header of METADATA.";
  sequencer()->MarkConsumed(body_manager_.OnNonBody(header_length));
  return true;
}

bool QuicSpdyStream::OnMetadataFramePayload(absl::string_view payload) {
  if (metadata_visitor_ == nullptr) {
    return OnUnknownFramePayload(payload);
  }

  if (!metadata_decoder_->Decode(payload)) {
    OnUnrecoverableError(QUIC_DECOMPRESSION_FAILURE,
                         metadata_decoder_->error_message());
    return false;
  }

  // Consume the frame payload.
  QUIC_DVLOG(1) << ENDPOINT << "Consuming " << payload.size()
                << " bytes of payload of METADATA.";
  sequencer()->MarkConsumed(body_manager_.OnNonBody(payload.size()));
  return true;
}

bool QuicSpdyStream::OnMetadataFrameEnd() {
  if (metadata_visitor_ == nullptr) {
    return OnUnknownFrameEnd();
  }

  if (!metadata_decoder_->EndHeaderBlock()) {
    OnUnrecoverableError(QUIC_DECOMPRESSION_FAILURE,
                         metadata_decoder_->error_message());
    return false;
  }

  metadata_visitor_->OnMetadataComplete(metadata_decoder_->frame_len(),
                                        metadata_decoder_->headers());
  metadata_decoder_.reset();
  return !sequencer()->IsClosed() && !reading_stopped();
}

bool QuicSpdyStream::OnUnknownFrameStart(uint64_t frame_type,
                                         QuicByteCount header_length,
                                         QuicByteCount payload_length) {
  if (spdy_session_->debug_visitor()) {
    spdy_session_->debug_visitor()->OnUnknownFrameReceived(id(), frame_type,
                                                           payload_length);
  }
  spdy_session_->OnUnknownFrameStart(id(), frame_type, header_length,
                                     payload_length);

  // Consume the frame header.
  QUIC_DVLOG(1) << ENDPOINT << "Consuming " << header_length
                << " byte long frame header of frame of unknown type "
                << frame_type << ".";
  sequencer()->MarkConsumed(body_manager_.OnNonBody(header_length));
  return true;
}

bool QuicSpdyStream::OnUnknownFramePayload(absl::string_view payload) {
  spdy_session_->OnUnknownFramePayload(id(), payload);

  // Consume the frame payload.
  QUIC_DVLOG(1) << ENDPOINT << "Consuming " << payload.size()
                << " bytes of payload of frame of unknown type.";
  sequencer()->MarkConsumed(body_manager_.OnNonBody(payload.size()));
  return true;
}

bool QuicSpdyStream::OnUnknownFrameEnd() { return true; }

size_t QuicSpdyStream::WriteHeadersImpl(
    quiche::HttpHeaderBlock header_block, bool fin,
    quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
        ack_listener) {
  if (!VersionUsesHttp3(transport_version())) {
    return spdy_session_->WriteHeadersOnHeadersStream(
        id(), std::move(header_block), fin,
        spdy::SpdyStreamPrecedence(priority().http().urgency),
        std::move(ack_listener));
  }

  // Encode header list.
  QuicByteCount encoder_stream_sent_byte_count;
  std::string encoded_headers =
      spdy_session_->qpack_encoder()->EncodeHeaderList(
          id(), header_block, &encoder_stream_sent_byte_count);

  if (spdy_session_->debug_visitor()) {
    spdy_session_->debug_visitor()->OnHeadersFrameSent(id(), header_block);
  }

  // Write HEADERS frame.
  std::string headers_frame_header =
      HttpEncoder::SerializeHeadersFrameHeader(encoded_headers.size());
  unacked_frame_headers_offsets_.Add(
      send_buffer().stream_offset(),
      send_buffer().stream_offset() + headers_frame_header.length());

  QUIC_DVLOG(1) << ENDPOINT << "Stream " << id()
                << " is writing HEADERS frame header of length "
                << headers_frame_header.length() << ", and payload of length "
                << encoded_headers.length() << " with fin " << fin;
  WriteOrBufferData(absl::StrCat(headers_frame_header, encoded_headers), fin,
                    /*ack_listener=*/nullptr);

  QuicSpdySession::LogHeaderCompressionRatioHistogram(
      /* using_qpack = */ true,
      /* is_sent = */ true,
      encoded_headers.size() + encoder_stream_sent_byte_count,
      header_block.TotalBytesUsed());

  return encoded_headers.size();
}

bool QuicSpdyStream::CanWriteNewBodyData(QuicByteCount write_size) const {
  QUICHE_DCHECK_NE(0u, write_size);
  if (!VersionUsesHttp3(transport_version())) {
    return CanWriteNewData();
  }

  return CanWriteNewDataAfterData(
      HttpEncoder::GetDataFrameHeaderLength(write_size));
}

void QuicSpdyStream::MaybeProcessReceivedWebTransportHeaders() {
  if (!spdy_session_->SupportsWebTransport()) {
    return;
  }
  if (session()->perspective() != Perspective::IS_SERVER) {
    return;
  }
  QUICHE_DCHECK(IsValidWebTransportSessionId(id(), version()));

  std::string method;
  std::string protocol;
  for (const auto& [header_name, header_value] : header_list_) {
    if (header_name == ":method") {
      if (!method.empty() || header_value.empty()) {
        return;
      }
      method = header_value;
    }
    if (header_name == ":protocol") {
      if (!protocol.empty() || header_value.empty()) {
        return;
      }
      protocol = header_value;
    }
    if (header_name == "datagram-flow-id") {
      QUIC_DLOG(ERROR) << ENDPOINT
                       << "Rejecting WebTransport due to unexpected "
                          "Datagram-Flow-Id header";
      return;
    }
  }

  if (method != "CONNECT" || protocol != "webtransport") {
    return;
  }

  web_transport_ =
      std::make_unique<WebTransportHttp3>(spdy_session_, this, id());
}

void QuicSpdyStream::MaybeProcessSentWebTransportHeaders(
    quiche::HttpHeaderBlock& headers) {
  if (!spdy_session_->SupportsWebTransport()) {
    return;
  }
  if (session()->perspective() != Perspective::IS_CLIENT) {
    return;
  }
  QUICHE_DCHECK(IsValidWebTransportSessionId(id(), version()));

  const auto method_it = headers.find(":method");
  const auto protocol_it = headers.find(":protocol");
  if (method_it == headers.end() || protocol_it == headers.end()) {
    return;
  }
  if (method_it->second != "CONNECT" && protocol_it->second != "webtransport") {
    return;
  }

  if (spdy_session_->SupportedWebTransportVersion() ==
      WebTransportHttp3Version::kDraft02) {
    headers["sec-webtransport-http3-draft02"] = "1";
  }

  web_transport_ =
      std::make_unique<WebTransportHttp3>(spdy_session_, this, id());
}

void QuicSpdyStream::OnCanWriteNewData() {
  if (web_transport_data_ != nullptr) {
    web_transport_data_->adapter.OnCanWriteNewData();
  }
}

bool QuicSpdyStream::AssertNotWebTransportDataStream(
    absl::string_view operation) {
  if (web_transport_data_ != nullptr) {
    QUIC_BUG(Invalid operation on WebTransport stream)
        << "Attempted to " << operation << " on WebTransport data stream "
        << id() << " associated with session "
        << web_transport_data_->session_id;
    OnUnrecoverableError(QUIC_INTERNAL_ERROR,
                         absl::StrCat("Attempted to ", operation,
                                      " on WebTransport data stream"));
    return false;
  }
  return true;
}

void QuicSpdyStream::ConvertToWebTransportDataStream(
    WebTransportSessionId session_id) {
  if (send_buffer().stream_offset() != 0) {
    QUIC_BUG(Sending WEBTRANSPORT_STREAM when data already sent)
        << "Attempted to send a WEBTRANSPORT_STREAM frame when other data has "
           "already been sent on the stream.";
    OnUnrecoverableError(QUIC_INTERNAL_ERROR,
                         "Attempted to send a WEBTRANSPORT_STREAM frame when "
                         "other data has already been sent on the stream.");
    return;
  }

  std::string header =
      HttpEncoder::SerializeWebTransportStreamFrameHeader(session_id);
  if (header.empty()) {
    QUIC_BUG(Failed to serialize WEBTRANSPORT_STREAM)
        << "Failed to serialize a WEBTRANSPORT_STREAM frame.";
    OnUnrecoverableError(QUIC_INTERNAL_ERROR,
                         "Failed to serialize a WEBTRANSPORT_STREAM frame.");
    return;
  }

  WriteOrBufferData(header, /*fin=*/false, nullptr);
  web_transport_data_ =
      std::make_unique<WebTransportDataStream>(this, session_id);
  QUIC_DVLOG(1) << ENDPOINT << "Successfully opened WebTransport data stream "
                << id() << " for session " << session_id;
}

QuicSpdyStream::WebTransportDataStream::WebTransportDataStream(
    QuicSpdyStream* stream, WebTransportSessionId session_id)
    : session_id(session_id),
      adapter(stream->spdy_session_, stream, stream->sequencer(), session_id) {}

void QuicSpdyStream::HandleReceivedDatagram(absl::string_view payload) {
  if (datagram_visitor_ == nullptr) {
    QUIC_DLOG(ERROR) << ENDPOINT << "Received datagram without any visitor";
    return;
  }
  datagram_visitor_->OnHttp3Datagram(id(), payload);
}

bool QuicSpdyStream::OnCapsule(const Capsule& capsule) {
  QUIC_DLOG(INFO) << ENDPOINT << "Stream " << id() << " received capsule "
                  << capsule;
  if (!headers_decompressed_) {
    QUIC_PEER_BUG(capsule before headers)
        << ENDPOINT << "Stream " << id() << " received capsule " << capsule
        << " before headers";
    return false;
  }
  if (web_transport_ != nullptr && web_transport_->close_received()) {
    QUIC_PEER_BUG(capsule after close)
        << ENDPOINT << "Stream " << id() << " received capsule " << capsule
        << " after CLOSE_WEBTRANSPORT_SESSION.";
    return false;
  }
  switch (capsule.capsule_type()) {
    case CapsuleType::DATAGRAM:
      HandleReceivedDatagram(capsule.datagram_capsule().http_datagram_payload);
      return true;
    case CapsuleType::LEGACY_DATAGRAM:
      HandleReceivedDatagram(
          capsule.legacy_datagram_capsule().http_datagram_payload);
      return true;
    case CapsuleType::LEGACY_DATAGRAM_WITHOUT_CONTEXT:
      HandleReceivedDatagram(capsule.legacy_datagram_without_context_capsule()
                                 .http_datagram_payload);
      return true;
    case CapsuleType::CLOSE_WEBTRANSPORT_SESSION:
      if (web_transport_ == nullptr) {
        QUIC_DLOG(ERROR) << ENDPOINT << "Received capsule " << capsule
                         << " for a non-WebTransport stream.";
        return false;
      }
      web_transport_->OnCloseReceived(
          capsule.close_web_transport_session_capsule().error_code,
          capsule.close_web_transport_session_capsule().error_message);
      return true;
    case CapsuleType::DRAIN_WEBTRANSPORT_SESSION:
      if (web_transport_ == nullptr) {
        QUIC_DLOG(ERROR) << ENDPOINT << "Received capsule " << capsule
                         << " for a non-WebTransport stream.";
        return false;
      }
      web_transport_->OnDrainSessionReceived();
      return true;
    case CapsuleType::ADDRESS_ASSIGN:
      if (connect_ip_visitor_ == nullptr) {
        return true;
      }
      return connect_ip_visitor_->OnAddressAssignCapsule(
          capsule.address_assign_capsule());
    case CapsuleType::ADDRESS_REQUEST:
      if (connect_ip_visitor_ == nullptr) {
        return true;
      }
      return connect_ip_visitor_->OnAddressRequestCapsule(
          capsule.address_request_capsule());
    case CapsuleType::ROUTE_ADVERTISEMENT:
      if (connect_ip_visitor_ == nullptr) {
        return true;
      }
      return connect_ip_visitor_->OnRouteAdvertisementCapsule(
          capsule.route_advertisement_capsule());

    // Ignore WebTransport over HTTP/2 capsules.
    case CapsuleType::WT_RESET_STREAM:
    case CapsuleType::WT_STOP_SENDING:
    case CapsuleType::WT_STREAM:
    case CapsuleType::WT_STREAM_WITH_FIN:
    case CapsuleType::WT_MAX_STREAM_DATA:
    case CapsuleType::WT_MAX_STREAMS_BIDI:
    case CapsuleType::WT_MAX_STREAMS_UNIDI:
      return true;
  }
  if (datagram_visitor_) {
    datagram_visitor_->OnUnknownCapsule(id(), capsule.unknown_capsule());
  }
  return true;
}

void QuicSpdyStream::OnCapsuleParseFailure(absl::string_view error_message) {
  QUIC_DLOG(ERROR) << ENDPOINT << "Capsule parse failure: " << error_message;
  Reset(QUIC_BAD_APPLICATION_PAYLOAD);
}

void QuicSpdyStream::WriteCapsule(const Capsule& capsule, bool fin) {
  QUIC_DLOG(INFO) << ENDPOINT << "Stream " << id() << " sending capsule "
                  << capsule;
  quiche::QuicheBuffer serialized_capsule = SerializeCapsule(
      capsule,
      spdy_session_->connection()->helper()->GetStreamSendBufferAllocator());
  QUICHE_DCHECK_GT(serialized_capsule.size(), 0u);
  WriteOrBufferBody(serialized_capsule.AsStringView(), /*fin=*/fin);
}

void QuicSpdyStream::WriteGreaseCapsule() {
  // GREASE capsulde IDs have a form of 41 * N + 23.
  QuicRandom* random = spdy_session_->connection()->random_generator();
  uint64_t type = random->InsecureRandUint64() >> 4;
  type = (type / 41) * 41 + 23;
  QUICHE_DCHECK_EQ((type - 23) % 41, 0u);

  constexpr size_t kMaxLength = 64;
  size_t length = random->InsecureRandUint64() % kMaxLength;
  std::string bytes(length, '\0');
  random->InsecureRandBytes(&bytes[0], bytes.size());
  Capsule capsule = Capsule::Unknown(type, bytes);
  WriteCapsule(capsule, /*fin=*/false);
}

MessageStatus QuicSpdyStream::SendHttp3Datagram(absl::string_view payload) {
  return spdy_session_->SendHttp3Datagram(id(), payload);
}

void QuicSpdyStream::RegisterHttp3DatagramVisitor(
    Http3DatagramVisitor* visitor) {
  if (visitor == nullptr) {
    QUIC_BUG(null datagram visitor)
        << ENDPOINT << "Null datagram visitor for stream ID " << id();
    return;
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Registering datagram visitor with stream ID "
                  << id();

  if (datagram_visitor_ != nullptr) {
    QUIC_BUG(h3 datagram double registration)
        << ENDPOINT
        << "Attempted to doubly register HTTP/3 datagram with stream ID "
        << id();
    return;
  }
  datagram_visitor_ = visitor;
  QUICHE_DCHECK(!capsule_parser_);
  capsule_parser_ = std::make_unique<quiche::CapsuleParser>(this);
}

void QuicSpdyStream::UnregisterHttp3DatagramVisitor() {
  if (datagram_visitor_ == nullptr) {
    QUIC_BUG(datagram visitor empty during unregistration)
        << ENDPOINT << "Cannot unregister datagram visitor for stream ID "
        << id();
    return;
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Unregistering datagram visitor for stream ID "
                  << id();
  datagram_visitor_ = nullptr;
}

void QuicSpdyStream::ReplaceHttp3DatagramVisitor(
    Http3DatagramVisitor* visitor) {
  QUIC_BUG_IF(h3 datagram unknown move, datagram_visitor_ == nullptr)
      << "Attempted to move missing datagram visitor on HTTP/3 stream ID "
      << id();
  datagram_visitor_ = visitor;
}

void QuicSpdyStream::RegisterConnectIpVisitor(ConnectIpVisitor* visitor) {
  if (visitor == nullptr) {
    QUIC_BUG(null connect - ip visitor)
        << ENDPOINT << "Null connect-ip visitor for stream ID " << id();
    return;
  }
  QUIC_DLOG(INFO) << ENDPOINT
                  << "Registering CONNECT-IP visitor with stream ID " << id();

  if (connect_ip_visitor_ != nullptr) {
    QUIC_BUG(connect - ip double registration)
        << ENDPOINT << "Attempted to doubly register CONNECT-IP with stream ID "
        << id();
    return;
  }
  connect_ip_visitor_ = visitor;
}

void QuicSpdyStream::UnregisterConnectIpVisitor() {
  if (connect_ip_visitor_ == nullptr) {
    QUIC_BUG(connect - ip visitor empty during unregistration)
        << ENDPOINT << "Cannot unregister CONNECT-IP visitor for stream ID "
        << id();
    return;
  }
  QUIC_DLOG(INFO) << ENDPOINT
                  << "Unregistering CONNECT-IP visitor for stream ID " << id();
  connect_ip_visitor_ = nullptr;
}

void QuicSpdyStream::ReplaceConnectIpVisitor(ConnectIpVisitor* visitor) {
  QUIC_BUG_IF(connect - ip unknown move, connect_ip_visitor_ == nullptr)
      << "Attempted to move missing CONNECT-IP visitor on HTTP/3 stream ID "
      << id();
  connect_ip_visitor_ = visitor;
}

void QuicSpdyStream::SetMaxDatagramTimeInQueue(
    QuicTime::Delta max_time_in_queue) {
  spdy_session_->SetMaxDatagramTimeInQueueForStreamId(id(), max_time_in_queue);
}

void QuicSpdyStream::OnDatagramReceived(QuicDataReader* reader) {
  if (!headers_decompressed_) {
    QUIC_DLOG(INFO) << "Dropping datagram received before headers on stream ID "
                    << id();
    return;
  }
  HandleReceivedDatagram(reader->ReadRemainingPayload());
}

QuicByteCount QuicSpdyStream::GetMaxDatagramSize() const {
  QuicByteCount prefix_size = 0;
  switch (spdy_session_->http_datagram_support()) {
    case HttpDatagramSupport::kDraft04:
    case HttpDatagramSupport::kRfc:
      prefix_size =
          QuicDataWriter::GetVarInt62Len(id() / kHttpDatagramStreamIdDivisor);
      break;
    case HttpDatagramSupport::kNone:
    case HttpDatagramSupport::kRfcAndDraft04:
      QUIC_BUG(GetMaxDatagramSize called with no datagram support)
          << "GetMaxDatagramSize() called when no HTTP/3 datagram support has "
             "been negotiated.  Support value: "
          << spdy_session_->http_datagram_support();
      break;
  }
  // If the logic above fails, use the largest possible value as the safe one.
  if (prefix_size == 0) {
    prefix_size = 8;
  }

  QuicByteCount max_datagram_size =
      session()->GetGuaranteedLargestMessagePayload();
  if (max_datagram_size < prefix_size) {
    QUIC_BUG(max_datagram_size smaller than prefix_size)
        << "GetGuaranteedLargestMessagePayload() returned a datagram size that "
           "is not sufficient to fit stream ID into it.";
    return 0;
  }
  return max_datagram_size - prefix_size;
}

void QuicSpdyStream::HandleBodyAvailable() {
  if (!capsule_parser_ || !uses_capsules()) {
    OnBodyAvailable();
    return;
  }
  while (body_manager_.HasBytesToRead()) {
    iovec iov;
    int num_iov = GetReadableRegions(&iov, /*iov_len=*/1);
    if (num_iov == 0) {
      break;
    }
    if (!capsule_parser_->IngestCapsuleFragment(absl::string_view(
            reinterpret_cast<const char*>(iov.iov_base), iov.iov_len))) {
      break;
    }
    MarkConsumed(iov.iov_len);
  }
  // If we received a FIN, make sure that there isn't a partial capsule buffered
  // in the capsule parser.
  if (sequencer()->IsClosed()) {
    capsule_parser_->ErrorIfThereIsRemainingBufferedData();
    if (web_transport_ != nullptr) {
      web_transport_->OnConnectStreamFinReceived();
    }
    OnFinRead();
  }
}

namespace {

// Return true if `name` only has allowed characters.
bool IsValidHeaderName(absl::string_view name) {
  if (name.empty()) {
    return true;
  }

  // Remove leading colon of pseudo-headers.
  // This is the only position where colon is allowed.
  if (name[0] == ':') {
    name.remove_prefix(1);
  }

  return http2::adapter::HeaderValidator::IsValidHeaderName(name);
}

}  // namespace

bool QuicSpdyStream::ValidateReceivedHeaders(
    const QuicHeaderList& header_list) {
  bool force_fail_validation = false;
  AdjustTestValue("quic::QuicSpdyStream::request_header_validation_adjust",
                  &force_fail_validation);
  if (force_fail_validation) {
    invalid_request_details_ =
        "request_header_validation_adjust force failed the validation.";
    QUIC_DLOG(ERROR) << invalid_request_details_;
    return false;
  }
  bool is_response = false;
  for (const std::pair<std::string, std::string>& pair : header_list) {
    const std::string& name = pair.first;
    if (!IsValidHeaderName(name)) {
      invalid_request_details_ =
          absl::StrCat("Invalid character in header name ", name);
      QUIC_DLOG(ERROR) << invalid_request_details_;
      return false;
    }
    if (name == ":status") {
      is_response = !pair.second.empty();
    }
    if (name == "host") {
      if (GetQuicReloadableFlag(quic_allow_host_in_request2)) {
        QUICHE_RELOADABLE_FLAG_COUNT_N(quic_allow_host_in_request2, 1, 3);
        continue;
      }
      if (is_response) {
        // Host header is allowed in response.
        continue;
      }
    }
    if (http2::GetInvalidHttp2HeaderSet().contains(name)) {
      invalid_request_details_ = absl::StrCat(name, " header is not allowed");
      QUIC_DLOG(ERROR) << invalid_request_details_;
      return false;
    }
  }
  return true;
}

void QuicSpdyStream::set_invalid_request_details(
    std::string invalid_request_details) {
  QUIC_BUG_IF(
      empty invalid request detail,
      !invalid_request_details_.empty() || invalid_request_details.empty());
  invalid_request_details_ = std::move(invalid_request_details);
}

bool QuicSpdyStream::AreHeaderFieldValuesValid(
    const QuicHeaderList& header_list) const {
  if (!VersionUsesHttp3(transport_version())) {
    return true;
  }
  // According to https://www.rfc-editor.org/rfc/rfc9114.html#section-10.3
  // "[...] HTTP/3 can transport field values that are not valid. While most
  // values that can be encoded will not alter field parsing, carriage return
  // (ASCII 0x0d), line feed (ASCII 0x0a), and the null character (ASCII 0x00)
  // might be exploited by an attacker if they are translated verbatim. Any
  // request or response that contains a character not permitted in a field
  // value MUST be treated as malformed.
  // [...]"
  for (const std::pair<std::string, std::string>& pair : header_list) {
    const std::string& value = pair.second;
    for (const auto c : value) {
      if (c == '\0' || c == '\n' || c == '\r') {
        return false;
      }
    }
  }
  return true;
}

void QuicSpdyStream::StopReading() {
  QuicStream::StopReading();
  if (GetQuicReloadableFlag(
          quic_stop_reading_also_stops_header_decompression) &&
      VersionUsesHttp3(transport_version()) && !fin_received() &&
      spdy_session_->qpack_decoder()) {
    QUIC_RELOADABLE_FLAG_COUNT(
        quic_stop_reading_also_stops_header_decompression);
    // Clean up Qpack decoding states.
    spdy_session_->qpack_decoder()->OnStreamReset(id());
    qpack_decoded_headers_accumulator_.reset();
  }
}

void QuicSpdyStream::OnInvalidHeaders() { Reset(QUIC_BAD_APPLICATION_PAYLOAD); }

void QuicSpdyStream::CloseReadSide() {
  QuicStream::CloseReadSide();

  // QuicStream::CloseReadSide() releases buffered read data from
  // QuicStreamSequencer, invalidating every reference held by `body_manager_`.
  body_manager_.Clear();
}

#undef ENDPOINT  // undef for jumbo builds
}  //
```
Response:
My thought process for analyzing the provided code and generating the summary went through these stages:

1. **Identify the Core Functionality:** The file name `quic_session.cc` immediately signals that this code manages a QUIC session. I scanned the code for keywords and function names that reinforced this: `QuicSession` class, `connection_`, `stream_map_`, `crypto_stream_`, `SendMessage`, `WriteStreamData`, `RetransmitLostData`, `On...Frame`, etc. This helped me establish the central role of this class.

2. **Break Down into Key Responsibilities:**  I started grouping related functionalities. For example, several methods deal with sending and receiving data (`WriteStreamData`, `SendMessage`, `OnStreamFrame`, `OnMessageAcked`). Others focus on stream management (`CreateIncomingStream`, `GetStream`, `CloseStream`, `OnMaxStreamsFrame`). Security aspects like encryption and stateless resets are also evident (`WriteCryptoData`, `GetStatelessResetToken`, `NeuterUnencryptedData`). Flow control and congestion management are hinted at by functions like `GetSendWindowSize` and mentions of blocking.

3. **Infer Interactions with Other Components:**  The presence of member variables like `connection_` (a `QuicConnection` object), `stream_map_`, and `crypto_stream_` strongly indicates interactions with other QUIC components. The `visitor_` pattern suggests a way to notify an external observer about session events.

4. **Look for JavaScript Relevance (Specific Request):** I looked for keywords or concepts that bridge the gap to JavaScript. While QUIC itself operates at a lower network layer than typical JavaScript interactions, I considered scenarios where JavaScript *might* indirectly be affected. This led to the idea of browser APIs using QUIC for underlying transport (like `fetch` or WebSockets). I also considered the idea of server-side JavaScript environments that might implement or interact with QUIC.

5. **Consider Logic and Control Flow:** I examined functions like `RetransmitLostData` and `ProcessAllPendingStreams` to understand how the session manages reliability and handles asynchronous operations. The presence of pending stream logic indicates how the session handles stream creation when resources are limited.

6. **Identify Potential User/Programming Errors:** I thought about common mistakes developers might make when working with a QUIC session, such as trying to send data before the connection is established or mismanaging stream IDs. The code itself provides clues, like the checks for `stream == nullptr` and the handling of `MESSAGE_STATUS_ENCRYPTION_NOT_ESTABLISHED`.

7. **Trace User Operations (Debugging Clues):** I tried to imagine a user interaction that would lead to this code being executed. Opening a webpage, clicking a link, or performing an action that triggers a network request are all potential triggers. The key is to connect the high-level user action to the low-level QUIC session management.

8. **Focus on the Specific Context ("Part 4 of 4"):**  The final instruction to summarize the overall function in the context of being the last part reinforced the need to provide a holistic view, drawing upon the details identified in the previous steps.

9. **Structure the Output Clearly:** I organized the findings into categories based on the request: Functionality, JavaScript relevance, Logic/I/O, User Errors, Debugging, and the final Summary. This provides a structured and easy-to-understand overview.

10. **Iterative Refinement:**  After the initial pass, I reviewed my analysis and the generated text to ensure accuracy, clarity, and completeness. I looked for opportunities to provide more specific examples or refine the explanations. For instance, I initially missed the `StreamsBlockedFrame` but caught it on a second pass. I also refined the JavaScript example to be more concrete (using `fetch`).

By following this multi-stage process, I could dissect the provided code snippet and extract the relevant information to address all aspects of the user's request. The key was to move from a high-level understanding of the component's purpose to a more detailed examination of its individual methods and their interactions.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_session.cc` 文件的第四部分，也是最后一部分。 综合前三部分的功能，我们可以归纳出 `QuicSession` 类的完整功能如下：

**`QuicSession` 类的核心职责是管理一个 QUIC 连接的生命周期和所有相关操作。它充当了 QUIC 连接的中心控制点。**

**综合功能归纳:**

1. **连接管理:**
   - **连接建立和关闭:**  处理连接的创建、握手、迁移和关闭。这包括处理连接级别的错误和状态转换。
   - **连接状态维护:**  跟踪连接的各种状态，例如加密级别、拥塞控制状态、路径验证状态等。
   - **连接参数协商:**  处理连接参数的协商和应用。

2. **流管理:**
   - **流的创建和销毁:**  管理双向和单向流的创建（包括客户端发起和服务端发起），以及流的关闭和清理。
   - **流 ID 分配和管理:**  负责分配和管理流的 ID，确保 ID 的正确性和唯一性，并处理流 ID 限制。
   - **流数据发送和接收:**  提供接口用于向流写入数据 (`WriteStreamData`)，并处理接收到的流数据。
   - **流的流量控制:**  管理每个流的发送窗口大小，并根据对端的反馈调整。
   - **流的重传:**  处理丢失流数据的重传 (`RetransmitLostData`)。
   - **处理流控制帧:**  响应 `MAX_STREAMS` 和 `STREAMS_BLOCKED` 帧，管理并发流的数量。

3. **数据发送和接收:**
   - **发送应用数据:**  通过 `SendMessage` 发送应用层消息。
   - **发送控制帧:**  通过 `control_frame_manager_` 发送各种控制帧。
   - **处理接收到的数据包:**  将接收到的数据包分发到相应的流或连接层处理。
   - **处理确认帧 (ACKs):**  处理收到的 ACK 帧，更新已发送数据的状态。

4. **加密和安全性:**
   - **加密状态管理:**  跟踪连接的加密级别。
   - **发送加密数据:**  通过 `WriteCryptoData` 发送握手数据。
   - **处理加密数据:**  通过 `QuicCryptoStream` 处理加密握手过程。
   - **处理无状态重置令牌:**  生成和验证无状态重置令牌。
   - **清理未加密数据:**  在加密建立后，清理未加密的流数据和数据包。

5. **路径管理和迁移:**
   - **路径验证:**  发起和处理路径验证，以确保连接的路径是可用的。
   - **连接迁移:**  支持连接迁移到新的网络路径 (`MigratePath`).
   - **处理服务器首选地址:**  接收并通知客户端服务器的首选地址。

6. **错误处理:**
   - **连接级别错误处理:**  处理连接级别的错误，并采取相应的行动（例如，关闭连接）。
   - **流级别错误处理:**  处理流级别的错误，并可能重置或关闭相关的流。

7. **性能优化:**
   - **控制帧的批量发送:**  提高控制帧发送的效率。
   - **避免不必要的重传:**  通过精确的丢包检测和重传机制来优化性能。

**本部分 (第四部分) 的功能：**

* **`RetransmitLostData()`:**  负责重传丢失的数据。它首先重传加密数据，然后重传控制帧，最后重传应用数据流的数据。它会检查连接是否被阻塞，避免在无法写入时进行重传。
* **`NeuterUnencryptedData()`:** 清理未加密的数据。这包括加密流的数据和连接层的数据包，通常在加密握手完成后执行，以增强安全性。
* **`SetTransmissionType(TransmissionType type)`:**  设置连接的传输类型（例如，初始、握手、应用程序）。这会影响连接的行为，例如拥塞控制。
* **`SendMessage()` (多个重载):**  发送应用层消息。它会检查连接是否已连接以及加密是否已建立。
* **`OnMessageAcked()` 和 `OnMessageLost()`:**  分别在消息被确认和被认为丢失时被调用，用于记录或触发相应的处理。
* **`CleanUpClosedStreams()`:** 清理已关闭的流的记录。
* **`GetCurrentLargestMessagePayload()` 和 `GetGuaranteedLargestMessagePayload()`:**  返回当前允许的最大消息负载大小。
* **`next_outgoing_bidirectional_stream_id()` 和 `next_outgoing_unidirectional_stream_id()`:** 返回下一个可用的外出双向和单向流 ID。
* **`OnMaxStreamsFrame()`:**  处理接收到的 `MAX_STREAMS` 帧，更新允许创建的最大流数量。
* **`OnStreamsBlockedFrame()`:** 处理接收到的 `STREAMS_BLOCKED` 帧，表示对端暂时无法创建新的流。
* **`max_open_incoming_bidirectional_streams()` 和 `max_open_incoming_unidirectional_streams()`:** 返回允许打开的最大传入双向和单向流的数量。
* **`SelectAlpn()`:**  根据支持的 ALPN 列表选择一个合适的 ALPN。
* **`OnAlpnSelected()`:**  在 ALPN 被选择后调用。
* **`NeuterCryptoDataOfEncryptionLevel()`:** 清理特定加密级别的加密数据。
* **`PerformActionOnActiveStreams()` (两个重载):**  对所有活跃的流执行一个给定的操作。
* **`GetEncryptionLevelToSendApplicationData()`:** 返回用于发送应用数据的加密级别。
* **`ProcessAllPendingStreams()`:** 处理所有待处理的传入流。
* **`ValidatePath()`:**  启动路径验证过程。
* **`HasPendingPathValidation()`:** 检查是否有待处理的路径验证。
* **`MigratePath()`:**  启动连接迁移过程。
* **`ValidateToken()`:**  验证接收到的地址令牌（通常用于 Retry 机制）。
* **`OnServerPreferredAddressAvailable()`:**  在接收到服务器首选地址时调用。
* **`ProcessPendingStream()`:**  处理一个待处理的传入流，根据流的类型创建相应的 `QuicStream` 对象。
* **`ExceedsPerLoopStreamLimit()`:** 检查当前循环中创建的传入流数量是否超过限制。
* **`OnStreamCountReset()`:** 在一个事件循环结束时重置传入流计数器。

**与 JavaScript 的关系举例:**

虽然 `quic_session.cc` 是 C++ 代码，直接在浏览器或 Node.js 等 JavaScript 运行环境中执行，但它支持的 QUIC 协议是下一代 Web 协议 HTTP/3 的基础。因此，它的功能直接影响到 JavaScript 中网络请求的行为。

**例子:**

假设一个 JavaScript 应用使用 `fetch` API 发起一个 HTTPS 请求到支持 HTTP/3 的服务器。

1. **用户操作:** 用户在浏览器中点击一个链接，或者 JavaScript 代码调用 `fetch('https://example.com/data')`。
2. **浏览器网络栈:** 浏览器会尝试与 `example.com` 建立连接。如果服务器支持 HTTP/3，浏览器可能会选择使用 QUIC 作为底层传输协议。
3. **`QuicSession` 的创建:**  浏览器网络栈的 QUIC 实现会创建一个 `QuicSession` 对象来管理与服务器的 QUIC 连接。
4. **流的创建:** 当 `fetch` 请求需要发送时，`QuicSession` 可能会创建一个新的 QUIC 流来传输 HTTP/3 请求。 `next_outgoing_bidirectional_stream_id()` 会被调用来获取新的流 ID。
5. **数据发送:**  `SendMessage()` 或 `WriteStreamData()` 会被调用，将 JavaScript `fetch` API 产生的 HTTP 请求数据通过 QUIC 流发送出去。
6. **数据接收:**  服务器响应的数据通过 QUIC 流到达浏览器，`QuicSession` 会处理接收到的数据，并将其传递给 `fetch` API 的回调函数。
7. **错误处理:** 如果网络出现问题导致数据丢失，`RetransmitLostData()` 会尝试重传丢失的数据，保证 `fetch` 请求的可靠性。
8. **连接迁移:** 如果用户网络发生变化（例如，从 Wi-Fi 切换到移动数据），`MigratePath()` 可能会被调用，尝试将 QUIC 连接迁移到新的网络路径，而 JavaScript 的 `fetch` 请求可能不会感知到这个底层的变化。

**逻辑推理的假设输入与输出:**

**假设输入:** 客户端尝试通过 `SendMessage` 发送一个 10KB 的消息，当前连接的发送窗口大小为 5KB。

**输出:** `SendMessage` 函数会返回一个表示发送失败的状态（例如，`MESSAGE_STATUS_BLOCKED` 或类似的），因为它不能立即发送所有数据。  可能还会触发连接级别的流量控制机制，等待发送窗口的增加。

**用户或编程常见的使用错误:**

1. **尝试在连接建立完成之前发送数据:**  如果 JavaScript 代码在 QUIC 握手完成之前就尝试使用 `fetch` 或 WebSocket 发送数据，`QuicSession` 的 `SendMessage` 或 `WriteStreamData` 可能会因为加密尚未建立而失败，导致请求延迟或失败。
2. **流 ID 管理错误 (理论上 JavaScript 不会直接接触):** 在 C++ 代码中，错误地管理流 ID，例如尝试使用已经被关闭的流 ID，会导致 `GetStream(id)` 返回空指针，从而触发 `QUIC_BUG` 并可能导致连接关闭。
3. **过度创建流:**  如果客户端或服务器过度创建流，超过了对端通过 `MAX_STREAMS` 帧声明的限制，会导致 `OnMaxStreamsFrame` 或 `OnStreamsBlockedFrame` 处理不当，最终可能导致连接关闭。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个使用了 HTTP/3 的网站或应用。**
2. **浏览器发起与服务器的 QUIC 连接。**  这涉及到 DNS 查询、TLS 握手升级到 QUIC 等步骤。
3. **JavaScript 代码通过 `fetch` API 发起一个网络请求。**
4. **浏览器网络栈的 QUIC 实现会调用 `QuicSession::SendMessage` 来发送请求数据。**
5. **如果此时网络条件不好，或者发送窗口受限，`RetransmitLostData` 可能会被周期性地调用，尝试重传丢失的数据包。**
6. **如果服务器发送了 `MAX_STREAMS` 帧限制了客户端可以创建的流数量，`QuicSession::OnMaxStreamsFrame` 会被调用。**
7. **如果在连接建立的早期，`NeuterUnencryptedData` 会在加密握手完成后被调用，清理未加密的数据。**

调试时，可以关注以下信息：

* **连接状态:**  检查连接是否已成功建立，加密级别是否正确。
* **流状态:**  查看流的状态，例如是否已打开、是否已关闭、是否存在待发送或待重传的数据。
* **发送窗口:**  检查发送窗口的大小，判断是否因为流量控制导致数据发送受阻。
* **QUIC 事件日志:**  查看 QUIC 连接的事件日志，例如发送和接收的帧类型、连接状态变化等。

总结来说，`QuicSession.cc` (的最后一部分) 负责 QUIC 会话中关键的可靠性、数据传输和资源管理功能，它是 QUIC 协议在 Chromium 网络栈中的核心实现之一，直接影响着基于 HTTP/3 的 Web 应用的性能和用户体验。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
ta as possible.
    return std::numeric_limits<QuicByteCount>::max();
  }
  return it->second->CalculateSendWindowSize();
}

WriteStreamDataResult QuicSession::WriteStreamData(QuicStreamId id,
                                                   QuicStreamOffset offset,
                                                   QuicByteCount data_length,
                                                   QuicDataWriter* writer) {
  QuicStream* stream = GetStream(id);
  if (stream == nullptr) {
    // This causes the connection to be closed because of failed to serialize
    // packet.
    QUIC_BUG(quic_bug_10866_13)
        << "Stream " << id << " does not exist when trying to write data."
        << " version:" << transport_version();
    return STREAM_MISSING;
  }
  if (stream->WriteStreamData(offset, data_length, writer)) {
    return WRITE_SUCCESS;
  }
  return WRITE_FAILED;
}

bool QuicSession::WriteCryptoData(EncryptionLevel level,
                                  QuicStreamOffset offset,
                                  QuicByteCount data_length,
                                  QuicDataWriter* writer) {
  return GetMutableCryptoStream()->WriteCryptoFrame(level, offset, data_length,
                                                    writer);
}

StatelessResetToken QuicSession::GetStatelessResetToken() const {
  return QuicUtils::GenerateStatelessResetToken(connection_->connection_id());
}

bool QuicSession::CanWriteStreamData() const {
  // Don't write stream data if there are queued data packets.
  if (connection_->HasQueuedPackets()) {
    return false;
  }
  // Immediately write handshake data.
  if (HasPendingHandshake()) {
    return true;
  }
  return connection_->CanWrite(HAS_RETRANSMITTABLE_DATA);
}

bool QuicSession::RetransmitLostData() {
  QuicConnection::ScopedPacketFlusher retransmission_flusher(connection_);
  // Retransmit crypto data first.
  bool uses_crypto_frames = QuicVersionUsesCryptoFrames(transport_version());
  if (QuicCryptoStream* const crypto_stream = GetMutableCryptoStream();
      uses_crypto_frames && crypto_stream->HasPendingCryptoRetransmission()) {
    crypto_stream->WritePendingCryptoRetransmission();
  }
  // Retransmit crypto data in stream 1 frames (version < 47).
  if (!uses_crypto_frames &&
      streams_with_pending_retransmission_.contains(
          QuicUtils::GetCryptoStreamId(transport_version()))) {
    // Retransmit crypto data first.
    QuicStream* const crypto_stream =
        GetStream(QuicUtils::GetCryptoStreamId(transport_version()));
    crypto_stream->OnCanWrite();
    QUICHE_DCHECK(CheckStreamWriteBlocked(crypto_stream));
    if (crypto_stream->HasPendingRetransmission()) {
      // Connection is write blocked.
      return false;
    } else {
      streams_with_pending_retransmission_.erase(
          QuicUtils::GetCryptoStreamId(transport_version()));
    }
  }
  if (control_frame_manager_.HasPendingRetransmission()) {
    control_frame_manager_.OnCanWrite();
    if (control_frame_manager_.HasPendingRetransmission()) {
      return false;
    }
  }
  while (!streams_with_pending_retransmission_.empty()) {
    if (!CanWriteStreamData()) {
      break;
    }
    // Retransmit lost data on headers and data streams.
    const QuicStreamId id = streams_with_pending_retransmission_.begin()->first;
    QuicStream* stream = GetStream(id);
    if (stream != nullptr) {
      stream->OnCanWrite();
      QUICHE_DCHECK(CheckStreamWriteBlocked(stream));
      if (stream->HasPendingRetransmission()) {
        // Connection is write blocked.
        break;
      } else if (!streams_with_pending_retransmission_.empty() &&
                 streams_with_pending_retransmission_.begin()->first == id) {
        // Retransmit lost data may cause connection close. If this stream
        // has not yet sent fin, a RST_STREAM will be sent and it will be
        // removed from streams_with_pending_retransmission_.
        streams_with_pending_retransmission_.pop_front();
      }
    } else {
      QUIC_BUG(quic_bug_10866_14)
          << "Try to retransmit data of a closed stream";
      streams_with_pending_retransmission_.pop_front();
    }
  }

  return streams_with_pending_retransmission_.empty();
}

void QuicSession::NeuterUnencryptedData() {
  QuicCryptoStream* crypto_stream = GetMutableCryptoStream();
  crypto_stream->NeuterUnencryptedStreamData();
  if (!crypto_stream->HasPendingRetransmission() &&
      !QuicVersionUsesCryptoFrames(transport_version())) {
    streams_with_pending_retransmission_.erase(
        QuicUtils::GetCryptoStreamId(transport_version()));
  }
  connection_->NeuterUnencryptedPackets();
}

void QuicSession::SetTransmissionType(TransmissionType type) {
  connection_->SetTransmissionType(type);
}

MessageResult QuicSession::SendMessage(
    absl::Span<quiche::QuicheMemSlice> message) {
  return SendMessage(message, /*flush=*/false);
}

MessageResult QuicSession::SendMessage(quiche::QuicheMemSlice message) {
  return SendMessage(absl::MakeSpan(&message, 1), /*flush=*/false);
}

MessageResult QuicSession::SendMessage(
    absl::Span<quiche::QuicheMemSlice> message, bool flush) {
  QUICHE_DCHECK(connection_->connected())
      << ENDPOINT << "Try to write messages when connection is closed.";
  if (!IsEncryptionEstablished()) {
    return {MESSAGE_STATUS_ENCRYPTION_NOT_ESTABLISHED, 0};
  }
  QuicConnection::ScopedEncryptionLevelContext context(
      connection(), GetEncryptionLevelToSendApplicationData());
  MessageStatus result =
      connection_->SendMessage(last_message_id_ + 1, message, flush);
  if (result == MESSAGE_STATUS_SUCCESS) {
    return {result, ++last_message_id_};
  }
  return {result, 0};
}

void QuicSession::OnMessageAcked(QuicMessageId message_id,
                                 QuicTime /*receive_timestamp*/) {
  QUIC_DVLOG(1) << ENDPOINT << "message " << message_id << " gets acked.";
}

void QuicSession::OnMessageLost(QuicMessageId message_id) {
  QUIC_DVLOG(1) << ENDPOINT << "message " << message_id
                << " is considered lost";
}

void QuicSession::CleanUpClosedStreams() { closed_streams_.clear(); }

QuicPacketLength QuicSession::GetCurrentLargestMessagePayload() const {
  return connection_->GetCurrentLargestMessagePayload();
}

QuicPacketLength QuicSession::GetGuaranteedLargestMessagePayload() const {
  return connection_->GetGuaranteedLargestMessagePayload();
}

QuicStreamId QuicSession::next_outgoing_bidirectional_stream_id() const {
  if (VersionHasIetfQuicFrames(transport_version())) {
    return ietf_streamid_manager_.next_outgoing_bidirectional_stream_id();
  }
  return stream_id_manager_.next_outgoing_stream_id();
}

QuicStreamId QuicSession::next_outgoing_unidirectional_stream_id() const {
  if (VersionHasIetfQuicFrames(transport_version())) {
    return ietf_streamid_manager_.next_outgoing_unidirectional_stream_id();
  }
  return stream_id_manager_.next_outgoing_stream_id();
}

bool QuicSession::OnMaxStreamsFrame(const QuicMaxStreamsFrame& frame) {
  const bool allow_new_streams =
      frame.unidirectional
          ? ietf_streamid_manager_.MaybeAllowNewOutgoingUnidirectionalStreams(
                frame.stream_count)
          : ietf_streamid_manager_.MaybeAllowNewOutgoingBidirectionalStreams(
                frame.stream_count);
  if (allow_new_streams) {
    OnCanCreateNewOutgoingStream(frame.unidirectional);
  }

  return true;
}

bool QuicSession::OnStreamsBlockedFrame(const QuicStreamsBlockedFrame& frame) {
  std::string error_details;
  if (ietf_streamid_manager_.OnStreamsBlockedFrame(frame, &error_details)) {
    return true;
  }
  connection_->CloseConnection(
      QUIC_STREAMS_BLOCKED_ERROR, error_details,
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  return false;
}

size_t QuicSession::max_open_incoming_bidirectional_streams() const {
  if (VersionHasIetfQuicFrames(transport_version())) {
    return ietf_streamid_manager_.GetMaxAllowdIncomingBidirectionalStreams();
  }
  return stream_id_manager_.max_open_incoming_streams();
}

size_t QuicSession::max_open_incoming_unidirectional_streams() const {
  if (VersionHasIetfQuicFrames(transport_version())) {
    return ietf_streamid_manager_.GetMaxAllowdIncomingUnidirectionalStreams();
  }
  return stream_id_manager_.max_open_incoming_streams();
}

std::vector<absl::string_view>::const_iterator QuicSession::SelectAlpn(
    const std::vector<absl::string_view>& alpns) const {
  const std::string alpn = AlpnForVersion(connection()->version());
  return std::find(alpns.cbegin(), alpns.cend(), alpn);
}

void QuicSession::OnAlpnSelected(absl::string_view alpn) {
  QUIC_DLOG(INFO) << (perspective() == Perspective::IS_SERVER ? "Server: "
                                                              : "Client: ")
                  << "ALPN selected: " << alpn;
}

void QuicSession::NeuterCryptoDataOfEncryptionLevel(EncryptionLevel level) {
  GetMutableCryptoStream()->NeuterStreamDataOfEncryptionLevel(level);
}

void QuicSession::PerformActionOnActiveStreams(
    quiche::UnretainedCallback<bool(QuicStream*)> action) {
  std::vector<QuicStream*> active_streams;
  for (const auto& it : stream_map_) {
    if (!it.second->is_static() && !it.second->IsZombie()) {
      active_streams.push_back(it.second.get());
    }
  }

  for (QuicStream* stream : active_streams) {
    if (!action(stream)) {
      return;
    }
  }
}

void QuicSession::PerformActionOnActiveStreams(
    quiche::UnretainedCallback<bool(QuicStream*)> action) const {
  for (const auto& it : stream_map_) {
    if (!it.second->is_static() && !it.second->IsZombie() &&
        !action(it.second.get())) {
      return;
    }
  }
}

EncryptionLevel QuicSession::GetEncryptionLevelToSendApplicationData() const {
  return connection_->framer().GetEncryptionLevelToSendApplicationData();
}

void QuicSession::ProcessAllPendingStreams() {
  std::vector<PendingStream*> pending_streams;
  pending_streams.reserve(pending_stream_map_.size());
  for (auto it = pending_stream_map_.begin(); it != pending_stream_map_.end();
       ++it) {
    pending_streams.push_back(it->second.get());
  }
  for (auto* pending_stream : pending_streams) {
    if (!MaybeProcessPendingStream(pending_stream)) {
      // Defer any further pending stream processing to the next event loop.
      return;
    }
  }
}

void QuicSession::ValidatePath(
    std::unique_ptr<QuicPathValidationContext> context,
    std::unique_ptr<QuicPathValidator::ResultDelegate> result_delegate,
    PathValidationReason reason) {
  connection_->ValidatePath(std::move(context), std::move(result_delegate),
                            reason);
}

bool QuicSession::HasPendingPathValidation() const {
  return connection_->HasPendingPathValidation();
}

bool QuicSession::MigratePath(const QuicSocketAddress& self_address,
                              const QuicSocketAddress& peer_address,
                              QuicPacketWriter* writer, bool owns_writer) {
  return connection_->MigratePath(self_address, peer_address, writer,
                                  owns_writer);
}

bool QuicSession::ValidateToken(absl::string_view token) {
  QUICHE_DCHECK_EQ(perspective_, Perspective::IS_SERVER);
  if (GetQuicFlag(quic_reject_retry_token_in_initial_packet)) {
    return false;
  }
  if (token.empty() || token[0] != kAddressTokenPrefix) {
    // Validate the prefix for token received in NEW_TOKEN frame.
    return false;
  }
  const bool valid = GetCryptoStream()->ValidateAddressToken(
      absl::string_view(token.data() + 1, token.length() - 1));
  if (valid) {
    const CachedNetworkParameters* cached_network_params =
        GetCryptoStream()->PreviousCachedNetworkParams();
    if (cached_network_params != nullptr &&
        cached_network_params->timestamp() > 0) {
      connection()->OnReceiveConnectionState(*cached_network_params);
    }
  }
  return valid;
}

void QuicSession::OnServerPreferredAddressAvailable(
    const QuicSocketAddress& server_preferred_address) {
  QUICHE_DCHECK_EQ(perspective_, Perspective::IS_CLIENT);
  if (visitor_ != nullptr) {
    visitor_->OnServerPreferredAddressAvailable(server_preferred_address);
  }
}

QuicStream* QuicSession::ProcessPendingStream(PendingStream* pending) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  QUICHE_DCHECK(connection()->connected());
  QuicStreamId stream_id = pending->id();
  QUIC_BUG_IF(bad pending stream, !IsIncomingStream(stream_id))
      << "Pending stream " << stream_id << " is not an incoming stream.";
  // TODO(b/305051334) check if this stream is incoming stream before making it
  // pending. If not, connection should be closed.
  StreamType stream_type = QuicUtils::GetStreamType(
      stream_id, perspective(), /*peer_initiated=*/true, version());
  switch (stream_type) {
    case BIDIRECTIONAL: {
      return ProcessBidirectionalPendingStream(pending);
    }
    case READ_UNIDIRECTIONAL: {
      return ProcessReadUnidirectionalPendingStream(pending);
    }
    case WRITE_UNIDIRECTIONAL:
      ABSL_FALLTHROUGH_INTENDED;
    case CRYPTO:
      QUICHE_BUG(unexpected pending stream)
          << "Unexpected pending stream " << stream_id << " with type "
          << stream_type;
      return nullptr;
  }
  return nullptr;  // Unreachable, unless the enum value is out-of-range
                   // (potentially undefined behavior)
}

bool QuicSession::ExceedsPerLoopStreamLimit() const {
  QUICHE_DCHECK(version().HasIetfQuicFrames());
  return new_incoming_streams_in_current_loop_ >=
         max_streams_accepted_per_loop_;
}

void QuicSession::OnStreamCountReset() {
  const bool exceeded_per_loop_stream_limit = ExceedsPerLoopStreamLimit();
  new_incoming_streams_in_current_loop_ = 0;
  if (exceeded_per_loop_stream_limit) {
    QUIC_CODE_COUNT_N(quic_pending_stream, 2, 3);
    // Convert as many leftover pending streams from last loop to active streams
    // as allowed.
    ProcessAllPendingStreams();
  }
}

#undef ENDPOINT  // undef for jumbo builds
}  // namespace quic

"""


```
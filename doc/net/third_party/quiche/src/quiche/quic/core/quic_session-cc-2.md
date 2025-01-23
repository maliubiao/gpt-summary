Response:
The user wants to understand the functionality of the `quic_session.cc` file in the Chromium network stack. They're specifically interested in:

1. **Listing the functionalities** of the code.
2. **Connections to JavaScript**:  If any functions relate to JavaScript interaction.
3. **Logical reasoning**: Identifying functions that perform logical operations and providing example inputs and outputs.
4. **Common user/programming errors**: Pinpointing potential pitfalls in using or interacting with this code.
5. **User journey**: Explaining how user actions might lead to this specific code being executed (debugging context).
6. **Summarizing the functionality**:  Providing a concise overview of the code's purpose.

**Mental Sandbox Simulation:**

* **Functionality Scan:**  I'll go through the code, method by method, and categorize each function based on its primary task. This will involve identifying patterns related to stream management, flow control, encryption, connection lifecycle, error handling, and IETF QUIC specific features.
* **JavaScript Linkage:** I need to consider the higher-level context of Chromium's networking stack. While this C++ code doesn't directly interact with JavaScript, it forms the core of the QUIC implementation. JavaScript in a browser would use WebSockets or fetch APIs, which internally might trigger QUIC connections handled by this code. The connection might be initiated by a JavaScript call, but the logic within this file is at a lower level.
* **Logical Reasoning Examples:** I'll look for functions that take input, perform comparisons or calculations, and produce an output. Flow control and stream ID management seem like good candidates. I'll need to create plausible scenarios with example values.
* **Error Scenarios:**  I need to identify situations where incorrect parameters or out-of-order events could cause problems. Flow control violations, invalid stream IDs, and handshake failures are likely areas to focus on.
* **User Journey:**  I'll consider typical web browsing actions that would involve QUIC. Visiting a website that uses QUIC, especially one with many resources, would be a good example. I need to trace the initiation of the connection down to the `QuicSession`.
* **Summarization:**  Once I have a good understanding of the individual functions, I can synthesize a concise summary of the `QuicSession`'s role in the QUIC connection.

**Constraint Checklist & Confidence Score:**

1. List functionalities: Yes.
2. JavaScript relation: Yes, though it will be indirect.
3. JavaScript examples: Yes, focusing on the initiation point.
4. Logical reasoning: Yes.
5. Input/output examples: Yes.
6. User/programming errors: Yes.
7. Error examples: Yes.
8. User operation to this point: Yes.
9. Debugging线索: Yes, framing it in terms of connection setup.
10. Summarize functionality: Yes.

Confidence Score: 5/5 - I'm confident I can address all aspects of the request.

**Key Learnings from Sandbox:**

* The connection to JavaScript is at the API level, not direct code interaction.
* Flow control and stream ID management are rich areas for logical reasoning examples.
* Error scenarios often involve violations of the QUIC protocol specifications.
* The user journey starts with a network request in the browser.

Strategizing complete. I will now proceed with generating the response based on these insights.

这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_session.cc` 文件的第三部分，主要负责处理 QUIC 会话生命周期中的各种事件和状态变化，并管理连接的流。以下是其功能的归纳和详细说明：

**功能归纳（第3部分）：**

* **密钥管理：** 处理新的加密和解密密钥的可用性，设置默认加密级别，并在不再需要时丢弃旧密钥。
* **TLS握手完成：** 响应 TLS 握手完成事件，并执行相应的操作，例如发送 HANDSHAKE_DONE 帧。
* **地址令牌管理：**  在服务器端，生成和发送地址令牌 (Address Token)。
* **零 RTT 处理：** 处理零 RTT 被拒绝的情况。
* **传输参数处理：** 填充和处理 QUIC 传输参数。
* **流优先级管理：** 注册、取消注册和更新流的优先级。
* **流激活和创建：** 激活新创建的流，并提供创建新的出站流的接口。
* **流 ID 管理：** 管理流 ID 的分配，并处理对端创建的流 ID。
* **流状态管理：**  跟踪流的 draining 状态，并根据流 ID 管理器更新流的状态。
* **流阻塞和让步：**  确定是否应该让出当前正在写入的流，处理连接级别和流级别的写阻塞。
* **待处理流管理：**  管理尚未完全创建的待处理流。
* **连接管理：** 提供删除连接对象的接口。
* **流关闭和清理：**  处理流的关闭，并将已关闭的流移动到待清理队列。
* **帧的确认和丢失处理：**  处理接收到的 ACK 帧，并标记丢失的帧。
* **帧的重传：**  根据丢失的帧进行重传。
* **流控阻塞判断：** 判断连接级别和流级别是否被流控阻塞。
* **活动流和静态流管理：**  跟踪活动流和静态流的数量。

**详细功能说明与示例：**

1. **密钥管理:**
   - `OnNewDecryptionKeyAvailable`: 当有新的解密密钥可用时被调用，用于安装新的解密器。
   - `OnNewEncryptionKeyAvailable`: 当有新的加密密钥可用时被调用，用于安装新的加密器并设置默认加密级别。
   - `SetDefaultEncryptionLevel`: 设置连接的默认加密级别。
   - `DiscardOldDecryptionKey`: 丢弃旧的解密密钥。
   - `DiscardOldEncryptionKey`: 丢弃旧的加密密钥。
   - `NeuterHandshakeData`:  清除握手阶段的数据。

   **假设输入与输出 (逻辑推理):**
   - **输入:** `OnNewEncryptionKeyAvailable` 被调用，`level` 参数为 `ENCRYPTION_FORWARD_SECURE`，表示有 1-RTT 加密密钥可用。
   - **输出:** 连接的加密器被更新为新的 1-RTT 加密器，默认加密级别被设置为 `ENCRYPTION_FORWARD_SECURE`。

2. **TLS握手完成:**
   - `OnTlsHandshakeComplete`: 在 TLS 握手完成后被调用，执行握手完成后的操作，例如发送 `HANDSHAKE_DONE` 帧。

3. **地址令牌管理:**
   - `MaybeSendAddressToken`: (服务器端) 尝试生成并发送地址令牌 (Address Token) 给客户端。

4. **零 RTT 处理:**
   - `OnZeroRttRejected`: 当服务器拒绝客户端的 0-RTT 数据时被调用，标记 0-RTT 数据需要重传。

   **用户或编程常见的使用错误:**
   - **错误:** 客户端发送 0-RTT 数据，但服务器配置不允许或因为安全原因拒绝了 0-RTT。
   - **结果:** `OnZeroRttRejected` 被调用，客户端需要重新发送数据，可能导致延迟增加。

5. **传输参数处理:**
   - `FillTransportParameters`:  填充要发送给对端的传输参数。
   - `ProcessTransportParameters`: 处理从对端接收到的传输参数。

6. **流优先级管理:**
   - `RegisterStreamPriority`: 注册流的优先级。
   - `UnregisterStreamPriority`: 取消注册流的优先级。
   - `UpdateStreamPriority`: 更新流的优先级。

7. **流激活和创建:**
   - `ActivateStream`: 激活新创建的流，将其添加到 `stream_map_` 中。
   - `GetNextOutgoingBidirectionalStreamId`: 获取下一个可用的出站双向流 ID。
   - `GetNextOutgoingUnidirectionalStreamId`: 获取下一个可用的出站单向流 ID。
   - `CanOpenNextOutgoingBidirectionalStream`: 检查是否可以创建新的出站双向流。
   - `CanOpenNextOutgoingUnidirectionalStream`: 检查是否可以创建新的出站单向流。

   **假设输入与输出 (逻辑推理):**
   - **输入:**  `CanOpenNextOutgoingBidirectionalStream` 被调用，当前已打开的出站双向流数量小于最大允许值。
   - **输出:** 返回 `true`，表示可以创建新的出站双向流。

8. **流 ID 管理:**
   - `GetAdvertisedMaxIncomingBidirectionalStreams`: 获取通告的最大入站双向流数量。
   - `GetOrCreateStream`: 根据流 ID 获取或创建流对象。
   - `MaybeIncreaseLargestPeerStreamId`:  更新对端创建的最大流 ID。

   **用户或编程常见的使用错误:**
   - **错误:**  接收到来自对端的流帧，其流 ID 大于本地允许的最大入站流 ID。
   - **结果:** `MaybeIncreaseLargestPeerStreamId` 返回 `false`，连接可能被关闭并显示 `QUIC_INVALID_STREAM_ID` 或 `QUIC_TOO_MANY_AVAILABLE_STREAMS` 错误。

9. **流状态管理:**
   - `StreamDraining`:  标记流正在 draining。
   - `set_largest_peer_created_stream_id`: 设置对端创建的最大流 ID。
   - `GetLargestPeerCreatedStreamId`: 获取对端创建的最大流 ID。
   - `IsClosedStream`: 检查流是否已关闭。
   - `IsOpenStream`: 检查流是否已打开。
   - `IsStaticStream`: 检查流是否是静态流。
   - `GetNumActiveStreams`: 获取当前活跃的流的数量。

10. **流阻塞和让步:**
    - `ShouldYield`: 确定当前流是否应该让出写入权限。
    - `MarkConnectionLevelWriteBlocked`: 将流标记为连接级别写阻塞。
    - `HasDataToWrite`: 检查会话是否有数据要写入。
    - `IsConnectionFlowControlBlocked`: 检查连接级别是否被流控阻塞。
    - `IsStreamFlowControlBlocked`: 检查是否有流被流控阻塞。

    **假设输入与输出 (逻辑推理):**
    - **输入:**  `ShouldYield` 被调用，当前正在写入的流的优先级低于参数中的 `stream_id` 的优先级。
    - **输出:** 返回 `true`，表示当前流应该让出写入权限。

11. **待处理流管理:**
    - `GetOrCreatePendingStream`: 获取或创建待处理流对象。

12. **连接管理:**
    - `DeleteConnection`: 删除连接对象。

13. **流关闭和清理:**
    - `MaybeCloseZombieStream`: 将已关闭的流移动到待清理队列。

14. **帧的确认和丢失处理:**
    - `OnFrameAcked`: 当收到帧的 ACK 时被调用。
    - `OnStreamFrameRetransmitted`: 当流帧被重传时调用。
    - `OnFrameLost`: 当检测到帧丢失时被调用。
    - `RetransmitFrames`:  重传指定的帧。
    - `IsFrameOutstanding`: 检查帧是否还在等待 ACK。
    - `HasUnackedCryptoData`: 检查是否有未被确认的加密数据。
    - `HasUnackedStreamData`: 检查是否有未被确认的流数据。

15. **流控阻塞判断:**
    - `IsConnectionFlowControlBlocked`: 检查连接级别是否被流控阻塞。
    - `IsStreamFlowControlBlocked`: 检查是否有任何流被流控阻塞。
    - `MaxAvailableBidirectionalStreams`: 获取最大可用的入站双向流数量。
    - `MaxAvailableUnidirectionalStreams`: 获取最大可用的入站单向流数量。
    - `IsIncomingStream`: 判断给定的流 ID 是否是入站流。

**与 JavaScript 的关系:**

虽然此 C++ 代码不直接与 JavaScript 交互，但它在 Chromium 浏览器中实现了 QUIC 协议的核心逻辑。当 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 WebSocket）时，如果协议协商选择了 QUIC，那么这里的 `QuicSession` 代码就会被调用来处理连接的建立、数据传输、流管理等。

**举例说明:**

1. **JavaScript 发起请求:**  用户在浏览器中访问一个使用 QUIC 的网站，JavaScript 代码执行 `fetch('https://example.com/data')`。
2. **连接建立:**  Chromium 网络栈会尝试与服务器建立 QUIC 连接。
3. **`QuicSession` 创建:**  如果连接成功建立，会创建一个 `QuicSession` 对象来管理这个连接。
4. **流创建:**  为了传输 `fetch` 请求的数据，会调用 `GetNextOutgoingBidirectionalStreamId` 来获取一个新的流 ID，并创建一个新的 QUIC 流。
5. **数据发送:**  JavaScript 获取到的数据会通过这个 QUIC 流发送出去，涉及 `QuicSession` 中与流数据写入相关的逻辑。
6. **流控和拥塞控制:**  `QuicSession` 会根据流控和拥塞控制的策略来管理数据的发送速率。
7. **帧的 ACK 和重传:**  当收到服务器的 ACK 帧时，`OnFrameAcked` 会被调用。如果某些帧丢失，`OnFrameLost` 会被调用，并触发 `RetransmitFrames` 进行重传。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。**
2. **浏览器解析 URL，确定目标服务器的 IP 地址和端口。**
3. **如果协议协商选择 QUIC，并且没有可重用的连接，浏览器会创建一个新的 QUIC 连接。**
4. **连接的握手过程会涉及到 TLS 和 QUIC 特定的握手消息交换，这会触发 `QuicSession` 中的密钥管理、传输参数处理等逻辑。**
5. **一旦连接建立，当 JavaScript 代码发起网络请求 (例如 `fetch`, WebSocket)，`QuicSession` 会负责创建新的流来传输数据。**
6. **数据的发送和接收会触发 `QuicSession` 中与流数据处理、流控、拥塞控制相关的函数。**
7. **当接收到对端的帧时，会调用相应的 `On` 开头的函数，例如 `OnStreamFrame`, `OnAckFrame` 等。**
8. **如果发生网络问题导致丢包，`OnFrameLost` 会被调用。**
9. **如果需要重传数据，`RetransmitFrames` 会被调用。**

在调试 QUIC 连接问题时，可以通过查看网络日志、抓包分析 QUIC 帧，以及在 `QuicSession` 的关键函数中设置断点来跟踪代码的执行流程，从而理解连接的状态变化和数据传输过程。例如，如果发现连接建立失败，可以检查密钥交换和传输参数处理的相关函数。如果发现数据传输缓慢或有丢包，可以检查流控、拥塞控制以及帧的 ACK 和重传处理逻辑。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
dow " << new_window;
    if (!kv.second->MaybeConfigSendWindowOffset(new_window,
                                                was_zero_rtt_rejected_)) {
      return;
    }
  }
}

void QuicSession::OnNewStreamIncomingBidirectionalFlowControlWindow(
    QuicStreamOffset new_window) {
  QUICHE_DCHECK_EQ(connection_->version().handshake_protocol, PROTOCOL_TLS1_3);
  QUIC_DVLOG(1) << ENDPOINT
                << "OnNewStreamIncomingBidirectionalFlowControlWindow "
                << new_window;
  // Inform all existing incoming bidirectional streams about the new window.
  for (auto const& kv : stream_map_) {
    const QuicStreamId id = kv.first;
    if (!version().HasIetfQuicFrames()) {
      if (kv.second->type() != BIDIRECTIONAL) {
        continue;
      }
    } else {
      if (!QuicUtils::IsBidirectionalStreamId(id, version())) {
        continue;
      }
    }
    if (QuicUtils::IsOutgoingStreamId(connection_->version(), id,
                                      perspective())) {
      continue;
    }
    QUIC_DVLOG(1) << ENDPOINT << "Informing incoming bidirectional stream "
                  << id << " of new stream flow control window " << new_window;
    if (!kv.second->MaybeConfigSendWindowOffset(new_window,
                                                was_zero_rtt_rejected_)) {
      return;
    }
  }
}

void QuicSession::OnNewSessionFlowControlWindow(QuicStreamOffset new_window) {
  QUIC_DVLOG(1) << ENDPOINT << "OnNewSessionFlowControlWindow " << new_window;

  if (was_zero_rtt_rejected_ && new_window < flow_controller_.bytes_sent()) {
    std::string error_details = absl::StrCat(
        "Server rejected 0-RTT. Aborting because the client received session "
        "flow control send window: ",
        new_window,
        ", which is below currently used: ", flow_controller_.bytes_sent());
    QUIC_LOG(ERROR) << error_details;
    connection_->CloseConnection(
        QUIC_ZERO_RTT_UNRETRANSMITTABLE, error_details,
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  if (!connection_->version().AllowsLowFlowControlLimits() &&
      new_window < kMinimumFlowControlSendWindow) {
    std::string error_details = absl::StrCat(
        "Peer sent us an invalid session flow control send window: ",
        new_window, ", below minimum: ", kMinimumFlowControlSendWindow);
    QUIC_LOG_FIRST_N(ERROR, 1) << error_details;
    connection_->CloseConnection(
        QUIC_FLOW_CONTROL_INVALID_WINDOW, error_details,
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  if (perspective_ == Perspective::IS_CLIENT &&
      new_window < flow_controller_.send_window_offset()) {
    // The client receives a lower limit than remembered, violating
    // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-7.3.1
    std::string error_details = absl::StrCat(
        was_zero_rtt_rejected_ ? "Server rejected 0-RTT, aborting because "
                               : "",
        "new session max data ", new_window,
        " decreases current limit: ", flow_controller_.send_window_offset());
    QUIC_LOG(ERROR) << error_details;
    connection_->CloseConnection(
        was_zero_rtt_rejected_ ? QUIC_ZERO_RTT_REJECTION_LIMIT_REDUCED
                               : QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED,
        error_details, ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  flow_controller_.UpdateSendWindowOffset(new_window);
}

bool QuicSession::OnNewDecryptionKeyAvailable(
    EncryptionLevel level, std::unique_ptr<QuicDecrypter> decrypter,
    bool set_alternative_decrypter, bool latch_once_used) {
  if (connection_->version().handshake_protocol == PROTOCOL_TLS1_3 &&
      !connection()->framer().HasEncrypterOfEncryptionLevel(
          QuicUtils::GetEncryptionLevelToSendAckofSpace(
              QuicUtils::GetPacketNumberSpace(level)))) {
    // This should never happen because connection should never decrypt a packet
    // while an ACK for it cannot be encrypted.
    return false;
  }
  if (connection()->version().KnowsWhichDecrypterToUse()) {
    connection()->InstallDecrypter(level, std::move(decrypter));
    return true;
  }
  if (set_alternative_decrypter) {
    connection()->SetAlternativeDecrypter(level, std::move(decrypter),
                                          latch_once_used);
    return true;
  }
  connection()->SetDecrypter(level, std::move(decrypter));
  return true;
}

void QuicSession::OnNewEncryptionKeyAvailable(
    EncryptionLevel level, std::unique_ptr<QuicEncrypter> encrypter) {
  connection()->SetEncrypter(level, std::move(encrypter));
  if (connection_->version().handshake_protocol != PROTOCOL_TLS1_3) {
    return;
  }

  bool reset_encryption_level = false;
  if (IsEncryptionEstablished() && level == ENCRYPTION_HANDSHAKE) {
    // ENCRYPTION_HANDSHAKE keys are only used for the handshake. If
    // ENCRYPTION_ZERO_RTT keys exist, it is possible for a client to send
    // stream data, which must not be sent at the ENCRYPTION_HANDSHAKE level.
    // Therefore, we avoid setting the default encryption level to
    // ENCRYPTION_HANDSHAKE.
    reset_encryption_level = true;
  }
  QUIC_DVLOG(1) << ENDPOINT << "Set default encryption level to " << level;
  connection()->SetDefaultEncryptionLevel(level);
  if (reset_encryption_level) {
    connection()->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  }
  QUIC_BUG_IF(quic_bug_12435_7,
              IsEncryptionEstablished() &&
                  (connection()->encryption_level() == ENCRYPTION_INITIAL ||
                   connection()->encryption_level() == ENCRYPTION_HANDSHAKE))
      << "Encryption is established, but the encryption level " << level
      << " does not support sending stream data";
}

void QuicSession::SetDefaultEncryptionLevel(EncryptionLevel level) {
  QUICHE_DCHECK_EQ(PROTOCOL_QUIC_CRYPTO,
                   connection_->version().handshake_protocol);
  QUIC_DVLOG(1) << ENDPOINT << "Set default encryption level to " << level;
  connection()->SetDefaultEncryptionLevel(level);

  switch (level) {
    case ENCRYPTION_INITIAL:
      break;
    case ENCRYPTION_ZERO_RTT:
      if (perspective() == Perspective::IS_CLIENT) {
        // Retransmit old 0-RTT data (if any) with the new 0-RTT keys, since
        // they can't be decrypted by the server.
        connection_->MarkZeroRttPacketsForRetransmission(0);
        if (!connection_->framer().is_processing_packet()) {
          // TODO(fayang): consider removing this OnCanWrite call.
          // Given any streams blocked by encryption a chance to write.
          QUIC_CODE_COUNT(
              quic_session_on_can_write_set_default_encryption_level);
          OnCanWrite();
        }
      }
      break;
    case ENCRYPTION_HANDSHAKE:
      break;
    case ENCRYPTION_FORWARD_SECURE:
      QUIC_BUG_IF(quic_bug_12435_8, !config_.negotiated())
          << ENDPOINT << "Handshake confirmed without parameter negotiation.";
      connection()->mutable_stats().handshake_completion_time =
          connection()->clock()->ApproximateNow();
      break;
    default:
      QUIC_BUG(quic_bug_10866_7) << "Unknown encryption level: " << level;
  }
}

void QuicSession::OnTlsHandshakeComplete() {
  QUICHE_DCHECK_EQ(PROTOCOL_TLS1_3, connection_->version().handshake_protocol);
  QUIC_BUG_IF(quic_bug_12435_9,
              !GetCryptoStream()->crypto_negotiated_params().cipher_suite)
      << ENDPOINT << "Handshake completes without cipher suite negotiation.";
  QUIC_BUG_IF(quic_bug_12435_10, !config_.negotiated())
      << ENDPOINT << "Handshake completes without parameter negotiation.";
  connection()->mutable_stats().handshake_completion_time =
      connection()->clock()->ApproximateNow();
  if (connection()->ShouldFixTimeouts(config_)) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_fix_timeouts, 2, 2);
    // Handshake complete, set handshake timeout to Infinite.
    connection()->SetNetworkTimeouts(QuicTime::Delta::Infinite(),
                                     config_.IdleNetworkTimeout());
  }
  if (connection()->version().UsesTls() &&
      perspective_ == Perspective::IS_SERVER) {
    // Server sends HANDSHAKE_DONE to signal confirmation of the handshake
    // to the client.
    control_frame_manager_.WriteOrBufferHandshakeDone();
    if (connection()->version().HasIetfQuicFrames()) {
      MaybeSendAddressToken();
    }
  }
}

bool QuicSession::MaybeSendAddressToken() {
  QUICHE_DCHECK(perspective_ == Perspective::IS_SERVER &&
                connection()->version().HasIetfQuicFrames());
  std::optional<CachedNetworkParameters> cached_network_params =
      GenerateCachedNetworkParameters();

  std::string address_token = GetCryptoStream()->GetAddressToken(
      cached_network_params.has_value() ? &*cached_network_params : nullptr);
  if (address_token.empty()) {
    return false;
  }
  const size_t buf_len = address_token.length() + 1;
  auto buffer = std::make_unique<char[]>(buf_len);
  QuicDataWriter writer(buf_len, buffer.get());
  // Add |kAddressTokenPrefix| for token sent in NEW_TOKEN frame.
  writer.WriteUInt8(kAddressTokenPrefix);
  writer.WriteBytes(address_token.data(), address_token.length());
  control_frame_manager_.WriteOrBufferNewToken(
      absl::string_view(buffer.get(), buf_len));
  if (cached_network_params.has_value()) {
    connection()->OnSendConnectionState(*cached_network_params);
  }
  return true;
}

void QuicSession::DiscardOldDecryptionKey(EncryptionLevel level) {
  if (!connection()->version().KnowsWhichDecrypterToUse()) {
    return;
  }
  connection()->RemoveDecrypter(level);
}

void QuicSession::DiscardOldEncryptionKey(EncryptionLevel level) {
  QUIC_DLOG(INFO) << ENDPOINT << "Discarding " << level << " keys";
  if (connection()->version().handshake_protocol == PROTOCOL_TLS1_3) {
    connection()->RemoveEncrypter(level);
  }
  switch (level) {
    case ENCRYPTION_INITIAL:
      NeuterUnencryptedData();
      break;
    case ENCRYPTION_HANDSHAKE:
      NeuterHandshakeData();
      break;
    case ENCRYPTION_ZERO_RTT:
      break;
    case ENCRYPTION_FORWARD_SECURE:
      QUIC_BUG(quic_bug_10866_8)
          << ENDPOINT << "Discarding 1-RTT keys is not allowed";
      break;
    default:
      QUIC_BUG(quic_bug_10866_9)
          << ENDPOINT
          << "Cannot discard keys for unknown encryption level: " << level;
  }
}

void QuicSession::NeuterHandshakeData() {
  GetMutableCryptoStream()->NeuterStreamDataOfEncryptionLevel(
      ENCRYPTION_HANDSHAKE);
  connection()->OnHandshakeComplete();
}

void QuicSession::OnZeroRttRejected(int reason) {
  was_zero_rtt_rejected_ = true;
  connection_->MarkZeroRttPacketsForRetransmission(reason);
  if (connection_->encryption_level() == ENCRYPTION_FORWARD_SECURE) {
    QUIC_BUG(quic_bug_10866_10)
        << "1-RTT keys already available when 0-RTT is rejected.";
    connection_->CloseConnection(
        QUIC_INTERNAL_ERROR,
        "1-RTT keys already available when 0-RTT is rejected.",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
}

bool QuicSession::FillTransportParameters(TransportParameters* params) {
  if (version().UsesTls()) {
    if (perspective() == Perspective::IS_SERVER) {
      config_.SetOriginalConnectionIdToSend(
          connection_->GetOriginalDestinationConnectionId());
      config_.SetInitialSourceConnectionIdToSend(connection_->connection_id());
    } else {
      config_.SetInitialSourceConnectionIdToSend(
          connection_->client_connection_id());
    }
  }
  return config_.FillTransportParameters(params);
}

QuicErrorCode QuicSession::ProcessTransportParameters(
    const TransportParameters& params, bool is_resumption,
    std::string* error_details) {
  return config_.ProcessTransportParameters(params, is_resumption,
                                            error_details);
}

void QuicSession::OnHandshakeCallbackDone() {
  if (!connection_->connected()) {
    return;
  }

  if (!connection()->is_processing_packet()) {
    connection()->MaybeProcessUndecryptablePackets();
  }
}

bool QuicSession::PacketFlusherAttached() const {
  QUICHE_DCHECK(connection_->connected());
  return connection()->packet_creator().PacketFlusherAttached();
}

void QuicSession::OnEncryptedClientHelloSent(
    absl::string_view client_hello) const {
  connection()->OnEncryptedClientHelloSent(client_hello);
}

void QuicSession::OnEncryptedClientHelloReceived(
    absl::string_view client_hello) const {
  connection()->OnEncryptedClientHelloReceived(client_hello);
}

void QuicSession::OnCryptoHandshakeMessageSent(
    const CryptoHandshakeMessage& /*message*/) {}

void QuicSession::OnCryptoHandshakeMessageReceived(
    const CryptoHandshakeMessage& /*message*/) {}

void QuicSession::RegisterStreamPriority(QuicStreamId id, bool is_static,
                                         const QuicStreamPriority& priority) {
  write_blocked_streams()->RegisterStream(id, is_static, priority);
}

void QuicSession::UnregisterStreamPriority(QuicStreamId id) {
  write_blocked_streams()->UnregisterStream(id);
}

void QuicSession::UpdateStreamPriority(QuicStreamId id,
                                       const QuicStreamPriority& new_priority) {
  write_blocked_streams()->UpdateStreamPriority(id, new_priority);
}

void QuicSession::ActivateStream(std::unique_ptr<QuicStream> stream) {
  const bool should_keep_alive = ShouldKeepConnectionAlive();
  QuicStreamId stream_id = stream->id();
  bool is_static = stream->is_static();
  QUIC_DVLOG(1) << ENDPOINT << "num_streams: " << stream_map_.size()
                << ". activating stream " << stream_id;
  QUICHE_DCHECK(!stream_map_.contains(stream_id));
  stream_map_[stream_id] = std::move(stream);
  if (is_static) {
    ++num_static_streams_;
    return;
  }
  if (version().HasIetfQuicFrames() && IsIncomingStream(stream_id) &&
      max_streams_accepted_per_loop_ != kMaxQuicStreamCount) {
    QUICHE_DCHECK(!ExceedsPerLoopStreamLimit());
    // Per-loop stream limit is emposed.
    ++new_incoming_streams_in_current_loop_;
    if (!stream_count_reset_alarm_->IsSet()) {
      stream_count_reset_alarm_->Set(connection()->clock()->ApproximateNow());
    }
  }
  if (!VersionHasIetfQuicFrames(transport_version())) {
    // Do not inform stream ID manager of static streams.
    stream_id_manager_.ActivateStream(
        /*is_incoming=*/IsIncomingStream(stream_id));
  }
  if (perspective() == Perspective::IS_CLIENT &&
      connection()->multi_port_stats() != nullptr && !should_keep_alive &&
      ShouldKeepConnectionAlive()) {
    connection()->MaybeProbeMultiPortPath();
  }
}

QuicStreamId QuicSession::GetNextOutgoingBidirectionalStreamId() {
  if (VersionHasIetfQuicFrames(transport_version())) {
    return ietf_streamid_manager_.GetNextOutgoingBidirectionalStreamId();
  }
  return stream_id_manager_.GetNextOutgoingStreamId();
}

QuicStreamId QuicSession::GetNextOutgoingUnidirectionalStreamId() {
  if (VersionHasIetfQuicFrames(transport_version())) {
    return ietf_streamid_manager_.GetNextOutgoingUnidirectionalStreamId();
  }
  return stream_id_manager_.GetNextOutgoingStreamId();
}

bool QuicSession::CanOpenNextOutgoingBidirectionalStream() {
  if (liveness_testing_in_progress_) {
    QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective());
    QUIC_CODE_COUNT(
        quic_client_fails_to_create_stream_liveness_testing_in_progress);
    return false;
  }
  if (!VersionHasIetfQuicFrames(transport_version())) {
    if (!stream_id_manager_.CanOpenNextOutgoingStream()) {
      return false;
    }
  } else {
    if (!ietf_streamid_manager_.CanOpenNextOutgoingBidirectionalStream()) {
      QUIC_CODE_COUNT(
          quic_fails_to_create_stream_close_too_many_streams_created);
      if (is_configured_) {
        // Send STREAM_BLOCKED after config negotiated.
        control_frame_manager_.WriteOrBufferStreamsBlocked(
            ietf_streamid_manager_.max_outgoing_bidirectional_streams(),
            /*unidirectional=*/false);
      }
      return false;
    }
  }
  if (perspective() == Perspective::IS_CLIENT &&
      connection_->MaybeTestLiveness()) {
    // Now is relatively close to the idle timeout having the risk that requests
    // could be discarded at the server.
    liveness_testing_in_progress_ = true;
    QUIC_CODE_COUNT(quic_client_fails_to_create_stream_close_to_idle_timeout);
    return false;
  }
  return true;
}

bool QuicSession::CanOpenNextOutgoingUnidirectionalStream() {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return stream_id_manager_.CanOpenNextOutgoingStream();
  }
  if (ietf_streamid_manager_.CanOpenNextOutgoingUnidirectionalStream()) {
    return true;
  }
  if (is_configured_) {
    // Send STREAM_BLOCKED after config negotiated.
    control_frame_manager_.WriteOrBufferStreamsBlocked(
        ietf_streamid_manager_.max_outgoing_unidirectional_streams(),
        /*unidirectional=*/true);
  }
  return false;
}

QuicStreamCount QuicSession::GetAdvertisedMaxIncomingBidirectionalStreams()
    const {
  QUICHE_DCHECK(VersionHasIetfQuicFrames(transport_version()));
  return ietf_streamid_manager_.advertised_max_incoming_bidirectional_streams();
}

QuicStream* QuicSession::GetOrCreateStream(const QuicStreamId stream_id) {
  QUICHE_DCHECK(!pending_stream_map_.contains(stream_id));
  if (QuicUtils::IsCryptoStreamId(transport_version(), stream_id)) {
    return GetMutableCryptoStream();
  }

  StreamMap::iterator it = stream_map_.find(stream_id);
  if (it != stream_map_.end()) {
    return it->second->IsZombie() ? nullptr : it->second.get();
  }

  if (IsClosedStream(stream_id)) {
    return nullptr;
  }

  if (!IsIncomingStream(stream_id)) {
    HandleFrameOnNonexistentOutgoingStream(stream_id);
    return nullptr;
  }

  // TODO(fkastenholz): If we are creating a new stream and we have sent a
  // goaway, we should ignore the stream creation. Need to add code to A) test
  // if goaway was sent ("if (transport_goaway_sent_)") and B) reject stream
  // creation ("return nullptr")

  if (!MaybeIncreaseLargestPeerStreamId(stream_id)) {
    return nullptr;
  }

  if (!VersionHasIetfQuicFrames(transport_version()) &&
      !stream_id_manager_.CanOpenIncomingStream()) {
    // Refuse to open the stream.
    ResetStream(stream_id, QUIC_REFUSED_STREAM);
    return nullptr;
  }

  return CreateIncomingStream(stream_id);
}

void QuicSession::StreamDraining(QuicStreamId stream_id, bool unidirectional) {
  QUICHE_DCHECK(stream_map_.contains(stream_id));
  QUIC_DVLOG(1) << ENDPOINT << "Stream " << stream_id << " is draining";
  if (VersionHasIetfQuicFrames(transport_version())) {
    ietf_streamid_manager_.OnStreamClosed(stream_id);
  } else {
    stream_id_manager_.OnStreamClosed(
        /*is_incoming=*/IsIncomingStream(stream_id));
  }
  ++num_draining_streams_;
  if (!IsIncomingStream(stream_id)) {
    ++num_outgoing_draining_streams_;
    if (!VersionHasIetfQuicFrames(transport_version())) {
      OnCanCreateNewOutgoingStream(unidirectional);
    }
  }
}

bool QuicSession::MaybeIncreaseLargestPeerStreamId(
    const QuicStreamId stream_id) {
  if (VersionHasIetfQuicFrames(transport_version())) {
    std::string error_details;
    if (ietf_streamid_manager_.MaybeIncreaseLargestPeerStreamId(
            stream_id, &error_details)) {
      return true;
    }
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, error_details,
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  if (!stream_id_manager_.MaybeIncreaseLargestPeerStreamId(stream_id)) {
    connection()->CloseConnection(
        QUIC_TOO_MANY_AVAILABLE_STREAMS,
        absl::StrCat(stream_id, " exceeds available streams ",
                     stream_id_manager_.MaxAvailableStreams()),
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  return true;
}

bool QuicSession::ShouldYield(QuicStreamId stream_id) {
  if (stream_id == currently_writing_stream_id_) {
    return false;
  }
  return write_blocked_streams()->ShouldYield(stream_id);
}

PendingStream* QuicSession::GetOrCreatePendingStream(QuicStreamId stream_id) {
  auto it = pending_stream_map_.find(stream_id);
  if (it != pending_stream_map_.end()) {
    return it->second.get();
  }

  if (IsClosedStream(stream_id) ||
      !MaybeIncreaseLargestPeerStreamId(stream_id)) {
    return nullptr;
  }

  auto pending = std::make_unique<PendingStream>(stream_id, this);
  PendingStream* unowned_pending = pending.get();
  pending_stream_map_[stream_id] = std::move(pending);
  return unowned_pending;
}

void QuicSession::set_largest_peer_created_stream_id(
    QuicStreamId largest_peer_created_stream_id) {
  QUICHE_DCHECK(!VersionHasIetfQuicFrames(transport_version()));
  stream_id_manager_.set_largest_peer_created_stream_id(
      largest_peer_created_stream_id);
}

QuicStreamId QuicSession::GetLargestPeerCreatedStreamId(
    bool unidirectional) const {
  // This method is only used in IETF QUIC.
  QUICHE_DCHECK(VersionHasIetfQuicFrames(transport_version()));
  return ietf_streamid_manager_.GetLargestPeerCreatedStreamId(unidirectional);
}

void QuicSession::DeleteConnection() {
  if (connection_) {
    delete connection_;
    connection_ = nullptr;
  }
}

bool QuicSession::MaybeSetStreamPriority(QuicStreamId stream_id,
                                         const QuicStreamPriority& priority) {
  auto active_stream = stream_map_.find(stream_id);
  if (active_stream != stream_map_.end()) {
    active_stream->second->SetPriority(priority);
    return true;
  }

  return false;
}

bool QuicSession::IsClosedStream(QuicStreamId id) {
  QUICHE_DCHECK_NE(QuicUtils::GetInvalidStreamId(transport_version()), id);
  if (IsOpenStream(id)) {
    // Stream is active
    return false;
  }

  if (VersionHasIetfQuicFrames(transport_version())) {
    return !ietf_streamid_manager_.IsAvailableStream(id);
  }

  return !stream_id_manager_.IsAvailableStream(id);
}

bool QuicSession::IsOpenStream(QuicStreamId id) {
  QUICHE_DCHECK_NE(QuicUtils::GetInvalidStreamId(transport_version()), id);
  const StreamMap::iterator it = stream_map_.find(id);
  if (it != stream_map_.end()) {
    return !it->second->IsZombie();
  }
  if (pending_stream_map_.contains(id) ||
      QuicUtils::IsCryptoStreamId(transport_version(), id)) {
    // Stream is active
    return true;
  }
  return false;
}

bool QuicSession::IsStaticStream(QuicStreamId id) const {
  auto it = stream_map_.find(id);
  if (it == stream_map_.end()) {
    return false;
  }
  return it->second->is_static();
}

size_t QuicSession::GetNumActiveStreams() const {
  QUICHE_DCHECK_GE(
      static_cast<QuicStreamCount>(stream_map_.size()),
      num_static_streams_ + num_draining_streams_ + num_zombie_streams_);
  return stream_map_.size() - num_draining_streams_ - num_static_streams_ -
         num_zombie_streams_;
}

void QuicSession::MarkConnectionLevelWriteBlocked(QuicStreamId id) {
  if (GetOrCreateStream(id) == nullptr) {
    QUIC_BUG(quic_bug_10866_11)
        << "Marking unknown stream " << id << " blocked.";
    QUIC_LOG_FIRST_N(ERROR, 2) << QuicStackTrace();
  }

  QUIC_DVLOG(1) << ENDPOINT << "Adding stream " << id
                << " to write-blocked list";

  write_blocked_streams_->AddStream(id);
}

bool QuicSession::HasDataToWrite() const {
  return write_blocked_streams_->HasWriteBlockedSpecialStream() ||
         write_blocked_streams_->HasWriteBlockedDataStreams() ||
         connection_->HasQueuedData() ||
         !streams_with_pending_retransmission_.empty() ||
         control_frame_manager_.WillingToWrite();
}

void QuicSession::OnAckNeedsRetransmittableFrame() {
  flow_controller_.SendWindowUpdate();
}

void QuicSession::SendAckFrequency(const QuicAckFrequencyFrame& frame) {
  control_frame_manager_.WriteOrBufferAckFrequency(frame);
}

void QuicSession::SendNewConnectionId(const QuicNewConnectionIdFrame& frame) {
  control_frame_manager_.WriteOrBufferNewConnectionId(
      frame.connection_id, frame.sequence_number, frame.retire_prior_to,
      frame.stateless_reset_token);
}

void QuicSession::SendRetireConnectionId(uint64_t sequence_number) {
  if (GetQuicReloadableFlag(
          quic_no_write_control_frame_upon_connection_close2)) {
    QUIC_RELOADABLE_FLAG_COUNT(
        quic_no_write_control_frame_upon_connection_close2);
    if (!connection_->connected()) {
      return;
    }
  }
  control_frame_manager_.WriteOrBufferRetireConnectionId(sequence_number);
}

bool QuicSession::MaybeReserveConnectionId(
    const QuicConnectionId& server_connection_id) {
  if (visitor_) {
    return visitor_->TryAddNewConnectionId(
        connection_->GetOneActiveServerConnectionId(), server_connection_id);
  }
  return true;
}

void QuicSession::OnServerConnectionIdRetired(
    const QuicConnectionId& server_connection_id) {
  if (visitor_) {
    visitor_->OnConnectionIdRetired(server_connection_id);
  }
}

bool QuicSession::IsConnectionFlowControlBlocked() const {
  return flow_controller_.IsBlocked();
}

bool QuicSession::IsStreamFlowControlBlocked() {
  for (auto const& kv : stream_map_) {
    if (kv.second->IsFlowControlBlocked()) {
      return true;
    }
  }
  if (!QuicVersionUsesCryptoFrames(transport_version()) &&
      GetMutableCryptoStream()->IsFlowControlBlocked()) {
    return true;
  }
  return false;
}

size_t QuicSession::MaxAvailableBidirectionalStreams() const {
  if (VersionHasIetfQuicFrames(transport_version())) {
    return ietf_streamid_manager_.GetMaxAllowdIncomingBidirectionalStreams();
  }
  return stream_id_manager_.MaxAvailableStreams();
}

size_t QuicSession::MaxAvailableUnidirectionalStreams() const {
  if (VersionHasIetfQuicFrames(transport_version())) {
    return ietf_streamid_manager_.GetMaxAllowdIncomingUnidirectionalStreams();
  }
  return stream_id_manager_.MaxAvailableStreams();
}

bool QuicSession::IsIncomingStream(QuicStreamId id) const {
  if (VersionHasIetfQuicFrames(transport_version())) {
    return !QuicUtils::IsOutgoingStreamId(version(), id, perspective_);
  }
  return stream_id_manager_.IsIncomingStream(id);
}

void QuicSession::MaybeCloseZombieStream(QuicStreamId id) {
  auto it = stream_map_.find(id);
  if (it == stream_map_.end()) {
    return;
  }
  --num_zombie_streams_;
  closed_streams_.push_back(std::move(it->second));
  stream_map_.erase(it);

  if (!closed_streams_clean_up_alarm_->IsSet()) {
    closed_streams_clean_up_alarm_->Set(connection_->clock()->ApproximateNow());
  }
  // Do not retransmit data of a closed stream.
  streams_with_pending_retransmission_.erase(id);
  connection_->QuicBugIfHasPendingFrames(id);
}

QuicStream* QuicSession::GetStream(QuicStreamId id) const {
  auto active_stream = stream_map_.find(id);
  if (active_stream != stream_map_.end()) {
    return active_stream->second.get();
  }

  if (QuicUtils::IsCryptoStreamId(transport_version(), id)) {
    return const_cast<QuicCryptoStream*>(GetCryptoStream());
  }

  return nullptr;
}

QuicStream* QuicSession::GetActiveStream(QuicStreamId id) const {
  auto stream = stream_map_.find(id);
  if (stream != stream_map_.end() && !stream->second->is_static()) {
    return stream->second.get();
  }
  return nullptr;
}

bool QuicSession::OnFrameAcked(const QuicFrame& frame,
                               QuicTime::Delta ack_delay_time,
                               QuicTime receive_timestamp) {
  if (frame.type == MESSAGE_FRAME) {
    OnMessageAcked(frame.message_frame->message_id, receive_timestamp);
    return true;
  }
  if (frame.type == CRYPTO_FRAME) {
    return GetMutableCryptoStream()->OnCryptoFrameAcked(*frame.crypto_frame,
                                                        ack_delay_time);
  }
  if (frame.type != STREAM_FRAME) {
    bool acked = control_frame_manager_.OnControlFrameAcked(frame);
    if (acked && frame.type == MAX_STREAMS_FRAME) {
      // Since there is a 2 frame limit on the number of outstanding max_streams
      // frames, when an outstanding max_streams frame is ack'd that frees up
      // room to potntially send another.
      ietf_streamid_manager_.MaybeSendMaxStreamsFrame();
    }
    return acked;
  }
  bool new_stream_data_acked = false;
  QuicStream* stream = GetStream(frame.stream_frame.stream_id);
  // Stream can already be reset when sent frame gets acked.
  if (stream != nullptr) {
    QuicByteCount newly_acked_length = 0;
    new_stream_data_acked = stream->OnStreamFrameAcked(
        frame.stream_frame.offset, frame.stream_frame.data_length,
        frame.stream_frame.fin, ack_delay_time, receive_timestamp,
        &newly_acked_length);
    if (!stream->HasPendingRetransmission()) {
      streams_with_pending_retransmission_.erase(stream->id());
    }
  }
  return new_stream_data_acked;
}

void QuicSession::OnStreamFrameRetransmitted(const QuicStreamFrame& frame) {
  QuicStream* stream = GetStream(frame.stream_id);
  if (stream == nullptr) {
    QUIC_BUG(quic_bug_10866_12)
        << "Stream: " << frame.stream_id << " is closed when " << frame
        << " is retransmitted.";
    connection()->CloseConnection(
        QUIC_INTERNAL_ERROR, "Attempt to retransmit frame of a closed stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  stream->OnStreamFrameRetransmitted(frame.offset, frame.data_length,
                                     frame.fin);
}

void QuicSession::OnFrameLost(const QuicFrame& frame) {
  if (frame.type == MESSAGE_FRAME) {
    ++total_datagrams_lost_;
    OnMessageLost(frame.message_frame->message_id);
    return;
  }
  if (frame.type == CRYPTO_FRAME) {
    GetMutableCryptoStream()->OnCryptoFrameLost(frame.crypto_frame);
    return;
  }
  if (frame.type != STREAM_FRAME) {
    control_frame_manager_.OnControlFrameLost(frame);
    return;
  }
  QuicStream* stream = GetStream(frame.stream_frame.stream_id);
  if (stream == nullptr) {
    return;
  }
  stream->OnStreamFrameLost(frame.stream_frame.offset,
                            frame.stream_frame.data_length,
                            frame.stream_frame.fin);
  if (stream->HasPendingRetransmission() &&
      !streams_with_pending_retransmission_.contains(
          frame.stream_frame.stream_id)) {
    streams_with_pending_retransmission_.insert(
        std::make_pair(frame.stream_frame.stream_id, true));
  }
}

bool QuicSession::RetransmitFrames(const QuicFrames& frames,
                                   TransmissionType type) {
  QuicConnection::ScopedPacketFlusher retransmission_flusher(connection_);
  for (const QuicFrame& frame : frames) {
    if (frame.type == MESSAGE_FRAME) {
      // Do not retransmit MESSAGE frames.
      continue;
    }
    if (frame.type == CRYPTO_FRAME) {
      if (!GetMutableCryptoStream()->RetransmitData(frame.crypto_frame, type)) {
        return false;
      }
      continue;
    }
    if (frame.type != STREAM_FRAME) {
      if (!control_frame_manager_.RetransmitControlFrame(frame, type)) {
        return false;
      }
      continue;
    }
    QuicStream* stream = GetStream(frame.stream_frame.stream_id);
    if (stream != nullptr &&
        !stream->RetransmitStreamData(frame.stream_frame.offset,
                                      frame.stream_frame.data_length,
                                      frame.stream_frame.fin, type)) {
      return false;
    }
  }
  return true;
}

bool QuicSession::IsFrameOutstanding(const QuicFrame& frame) const {
  if (frame.type == MESSAGE_FRAME) {
    return false;
  }
  if (frame.type == CRYPTO_FRAME) {
    return GetCryptoStream()->IsFrameOutstanding(
        frame.crypto_frame->level, frame.crypto_frame->offset,
        frame.crypto_frame->data_length);
  }
  if (frame.type != STREAM_FRAME) {
    return control_frame_manager_.IsControlFrameOutstanding(frame);
  }
  QuicStream* stream = GetStream(frame.stream_frame.stream_id);
  return stream != nullptr &&
         stream->IsStreamFrameOutstanding(frame.stream_frame.offset,
                                          frame.stream_frame.data_length,
                                          frame.stream_frame.fin);
}

bool QuicSession::HasUnackedCryptoData() const {
  const QuicCryptoStream* crypto_stream = GetCryptoStream();
  return crypto_stream->IsWaitingForAcks() || crypto_stream->HasBufferedData();
}

bool QuicSession::HasUnackedStreamData() const {
  for (const auto& it : stream_map_) {
    if (it.second->IsWaitingForAcks()) {
      return true;
    }
  }
  return false;
}

HandshakeState QuicSession::GetHandshakeState() const {
  return GetCryptoStream()->GetHandshakeState();
}

QuicByteCount QuicSession::GetFlowControlSendWindowSize(QuicStreamId id) {
  auto it = stream_map_.find(id);
  if (it == stream_map_.end()) {
    // No flow control for invalid or inactive stream ids. Returning uint64max
    // allows QuicPacketCreator to write as much da
```
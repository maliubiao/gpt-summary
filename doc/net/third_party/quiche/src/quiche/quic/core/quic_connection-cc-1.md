Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `QuicConnection` class in Chromium's QUIC implementation. I need to identify the key actions and responsibilities of this part of the code.

The code snippet appears to handle several aspects of connection management, particularly related to receiving and processing incoming QUIC packets. Key areas seem to be:

1. **Handling RETRY packets:**  Specifically for clients.
2. **Managing connection IDs:** Including handling original destination connection IDs and the exchange/retirement of connection IDs.
3. **Validating incoming packets:** Checking server and client connection IDs.
4. **Processing different QUIC frame types:** STREAM, CRYPTO, ACK, PING, RST_STREAM, STOP_SENDING, PATH_CHALLENGE, etc.
5. **Tracking packet reception and triggering actions based on received packets:** For example, updating the largest received packet, handling acknowledgements, and managing idle detection.
6. **Dealing with connection migration scenarios:** Detecting changes in the peer's address.
7. **Integrating with debug and visitor interfaces:** Notifying external components about various events.

Regarding the user's request for connections to JavaScript, logical inferences, and error examples, these will be addressed where applicable within the identified functionalities.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc` 文件 `QuicConnection` 类的代码片段，它主要负责处理接收到的 QUIC 数据包，并根据数据包类型执行相应的操作。以下是该代码片段功能的归纳：

**主要功能归纳：**

1. **处理连接重试 (RETRY) 包 (客户端)：**
   - 验证重试令牌的完整性。
   - 更新连接 ID 并保存重试令牌。
   - 标记初始数据包需要重传。

2. **设置和管理连接 ID：**
   - 允许设置原始目标连接 ID (在握手阶段，客户端可能使用一个初始的连接 ID，服务端会告知客户端一个实际使用的连接 ID)。
   - 记录和更新服务器和客户端的连接 ID。
   - 提供获取当前有效目标连接 ID 的方法。
   - 处理原始目标连接 ID 的退役。

3. **验证接收到的数据包的连接 ID：**
   - 验证数据包头中的服务器连接 ID 是否与期望的连接 ID 匹配。
   - 在服务器端，如果收到客户端的第一个数据包，则设置客户端连接 ID。
   - 在支持的情况下，验证客户端连接 ID。

4. **处理未认证的包头信息：**
   - 记录最后接收到的数据包的目的连接 ID。
   - 如果收到 INITIAL 包，则开始忽略后续的 RETRY 包。
   - 调用调试访问器 (debug visitor) 的相应方法。

5. **处理成功的版本协商：**
   - 通知访问器 (visitor) 连接已成功协商版本。
   - 通知调试访问器。

6. **处理成功的连接迁移：**
   - 在客户端，当连接迁移成功时，根据情况重启路径退化和黑洞检测。
   - 清除备用路径的状态。
   - 更新发送数据包管理器 (sent packet manager) 的状态。

7. **记录和通知传输参数的发送和接收：**
   - 在发送、接收或恢复传输参数时通知调试访问器。

8. **记录加密的 ClientHello 信息的发送和接收：**
   - 在发送或接收加密的 ClientHello 时通知调试访问器。

9. **记录解析后的 ClientHello 信息：**
   - 在解析 ClientHello 后通知调试访问器。

10. **检查是否有待处理的 ACK：**
    - 提供一个方法来判断是否设置了 ACK 警报。

11. **处理接收到的解密后的数据包：**
    - 记录解密级别和解密状态。
    - 在首次收到 Forward Secure 加密的数据包后，如果是在服务端，则启动一个定时器来丢弃 0-RTT 解密密钥。
    - 如果启用了抗放大限制，并且尚未确认握手，则在成功解密握手或 1-RTT 数据包后，标记路径为已验证。
    - 通知空闲网络检测器 (idle network detector) 收到了数据包。
    - 通知访问器数据包已解密。

12. **获取有效的对端地址：**
    - 提供一个方法来获取当前接收到的数据包的有效对端地址。

13. **处理接收到的数据包头：**
    - 调用调试访问器的相应方法。
    - 检查数据包是否已验证。
    - 初始化当前数据包内容的状态。
    - 处理基于 Flow Label 的黑洞规避逻辑。
    - 在客户端，更新对端地址信息。
    - 在服务端，记录对端地址的变化类型。
    - 记录接收到的数据包头信息，并更新统计信息。
    - 记录数据包接收时间并更新确认信息。
    - 如果收到的数据包包含有效的重试令牌，则标记地址已验证。

14. **处理各种类型的 QUIC 帧：**
    - **STREAM 帧:** 处理数据流数据，检查是否为未加密数据，更新确认超时，通知访问器。
    - **CRYPTO 帧:** 处理加密握手数据，更新确认超时，通知访问器。
    - **ACK 帧:**
        - 处理 ACK 帧的开始、范围、时间戳和结束。
        - 检查是否为过时的 ACK 帧。
        - 检查 ACK 中确认的最大数据包编号是否有效。
        - 调用发送数据包管理器 (sent packet manager) 的相应方法来处理 ACK 信息。
        - 根据 ACK 的结果更新连接状态，例如取消发送警报。
    - **STOP_WAITING 帧:**  记录收到该帧。
    - **PADDING 帧:**  记录收到该帧，通知调试访问器。
    - **PING 帧:**  记录收到该帧，通知调试访问器，更新确认超时。
    - **RST_STREAM 帧:** 处理流重置请求，更新确认超时，通知访问器。
    - **STOP_SENDING 帧:** 处理停止发送请求，更新确认超时，通知访问器。
    - **PATH_CHALLENGE 帧:**  此类帧的处理在后续代码片段中。

**与 JavaScript 功能的关系：**

这段 C++ 代码是 Chromium 网络栈的核心部分，负责底层的 QUIC 协议处理。它本身不直接与 JavaScript 交互。然而，JavaScript 可以通过 Chromium 提供的 Web API (例如 `fetch` 或 WebSocket) 发起网络请求。当浏览器使用 QUIC 协议进行通信时，这些 JavaScript 请求最终会触发这里的 C++ 代码执行，例如：

* **用户在 JavaScript 中发起一个 HTTPS 请求 (使用 QUIC)：**  `QuicConnection` 会处理连接的建立、数据传输、以及连接的关闭。
* **JavaScript 代码使用 WebSocket over QUIC：** `QuicConnection` 会处理 WebSocket 连接的 QUIC 层的握手、数据帧的发送和接收等。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch` API 发起一个 HTTPS 请求到支持 QUIC 的服务器：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

**用户操作步骤和调试线索：**

1. **用户在浏览器地址栏输入 `https://example.com/data` 或点击一个链接。**
2. **浏览器解析 URL，发现协议为 HTTPS。**
3. **浏览器查找或建立与 `example.com` 的 QUIC 连接。**
4. **如果连接是新建立的，`QuicConnection` 对象会被创建，并执行握手过程。**
5. **JavaScript 的 `fetch` 调用会被转换为一个 HTTP/QUIC 请求。**
6. **`QuicConnection` 对象会负责将 HTTP 请求数据封装成 QUIC 数据包并发送。**
7. **服务器响应的数据包会被 `QuicConnection` 接收并解析，例如 `OnStreamFrame` 会被调用处理数据流。**
8. **如果服务器发送了 `RETRY` 包（例如，客户端的初始连接 ID 不被接受），则会调用 `OnRetryPacket` 进行处理。**
9. **如果连接迁移发生，例如网络切换，则会触发连接迁移相关的逻辑。**
10. **开发者可以使用 Chrome 的 `chrome://net-internals/#quic` 页面来查看 QUIC 连接的详细信息，包括连接状态、收发的包、错误信息等，这可以帮助定位问题。**
11. **如果出现连接问题，例如连接被重置，开发者可以通过查看 `chrome://net-internals/#events` 来追踪网络事件，查看是否有与 QUIC 相关的错误信息。**
12. **在 C++ 代码层面，可以使用 QUIC 相关的日志宏（如 `QUIC_DLOG`）来输出调试信息，帮助理解代码的执行流程和状态。**

**逻辑推理的假设输入与输出：**

**假设输入:** 收到一个类型为 `RETRY` 的 QUIC 数据包，包含以下信息：
- `original_connection_id`:  客户端最初尝试连接的服务器连接 ID (假设为 `123`).
- `new_connection_id`: 服务器指示客户端后续应该使用的服务器连接 ID (假设为 `456`).
- `retry_token`:  服务器提供的重试令牌 (假设为 `abcdef`).

**预期输出:**
- `OnRetryPacket` 函数会被调用。
- 如果重试令牌验证成功（对于 TLS 连接），或者原始连接 ID 匹配，则：
    - `framer_.set_drop_incoming_retry_packets(true)` 被调用，停止处理后续的 RETRY 包。
    - `stats_.retry_packet_processed` 被设置为 `true`。
    - `default_path_.server_connection_id` 从 `123` 更新为 `456`。
    - `packet_creator_.SetRetryToken("abcdef")` 被调用。
    - 初始加密器 (initial crypters) 会被重新安装，使用新的连接 ID。
    - 之前发送的初始数据包会被标记为需要重传。

**用户或编程常见的使用错误示例：**

1. **客户端实现错误，未正确处理 `RETRY` 包：** 如果客户端收到 `RETRY` 包后没有更新连接 ID 和重试令牌，后续发送的数据包可能无法被服务器正确识别。
2. **服务端错误地发送了无效的 `RETRY` 包：** 例如，重试令牌的完整性校验失败，或者原始连接 ID 不匹配，导致客户端忽略该 `RETRY` 包，可能导致连接建立失败。
3. **在不应该设置原始目标连接 ID 的时候设置了：** 例如，在服务器端或者在连接建立之后设置，可能会导致连接状态混乱。
4. **连接 ID 冲突：**  如果客户端或服务器错误地使用了已经存在的连接 ID，可能会导致数据包被错误地路由到错误的连接。

这段代码是 QUIC 连接处理的核心部分，负责接收和初步处理各种 QUIC 数据包和帧，为更上层的 QUIC 功能提供基础。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共10部分，请归纳一下它的功能

"""
_version_
          ? ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET
          : ConnectionCloseBehavior::SILENT_CLOSE);
}

// Handles retry for client connection.
void QuicConnection::OnRetryPacket(QuicConnectionId original_connection_id,
                                   QuicConnectionId new_connection_id,
                                   absl::string_view retry_token,
                                   absl::string_view retry_integrity_tag,
                                   absl::string_view retry_without_tag) {
  QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective_);
  if (version().UsesTls()) {
    if (!CryptoUtils::ValidateRetryIntegrityTag(
            version(), default_path_.server_connection_id, retry_without_tag,
            retry_integrity_tag)) {
      QUIC_DLOG(ERROR) << "Ignoring RETRY with invalid integrity tag";
      return;
    }
  } else {
    if (original_connection_id != default_path_.server_connection_id) {
      QUIC_DLOG(ERROR) << "Ignoring RETRY with original connection ID "
                       << original_connection_id << " not matching expected "
                       << default_path_.server_connection_id << " token "
                       << absl::BytesToHexString(retry_token);
      return;
    }
  }
  framer_.set_drop_incoming_retry_packets(true);
  stats_.retry_packet_processed = true;
  QUIC_DLOG(INFO) << "Received RETRY, replacing connection ID "
                  << default_path_.server_connection_id << " with "
                  << new_connection_id << ", received token "
                  << absl::BytesToHexString(retry_token);
  if (!original_destination_connection_id_.has_value()) {
    original_destination_connection_id_ = default_path_.server_connection_id;
  }
  QUICHE_DCHECK(!retry_source_connection_id_.has_value())
      << *retry_source_connection_id_;
  retry_source_connection_id_ = new_connection_id;
  ReplaceInitialServerConnectionId(new_connection_id);
  packet_creator_.SetRetryToken(retry_token);

  // Reinstall initial crypters because the connection ID changed.
  InstallInitialCrypters(default_path_.server_connection_id);

  sent_packet_manager_.MarkInitialPacketsForRetransmission();
}

void QuicConnection::SetMultiPacketClientHello() {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->SetMultiPacketClientHello();
  }
}

void QuicConnection::SetOriginalDestinationConnectionId(
    const QuicConnectionId& original_destination_connection_id) {
  QUIC_DLOG(INFO) << "Setting original_destination_connection_id to "
                  << original_destination_connection_id
                  << " on connection with server_connection_id "
                  << default_path_.server_connection_id;
  QUICHE_DCHECK_NE(original_destination_connection_id,
                   default_path_.server_connection_id);
  InstallInitialCrypters(original_destination_connection_id);
  QUICHE_DCHECK(!original_destination_connection_id_.has_value())
      << *original_destination_connection_id_;
  original_destination_connection_id_ = original_destination_connection_id;
  original_destination_connection_id_replacement_ =
      default_path_.server_connection_id;
}

QuicConnectionId QuicConnection::GetOriginalDestinationConnectionId() const {
  if (original_destination_connection_id_.has_value()) {
    return *original_destination_connection_id_;
  }
  return default_path_.server_connection_id;
}

void QuicConnection::RetireOriginalDestinationConnectionId() {
  if (original_destination_connection_id_.has_value()) {
    visitor_->OnServerConnectionIdRetired(*original_destination_connection_id_);
    original_destination_connection_id_.reset();
  }
}

void QuicConnection::OnDiscardZeroRttDecryptionKeysAlarm() {
  QUICHE_DCHECK(connected());
  QUIC_DLOG(INFO) << "0-RTT discard alarm fired";
  RemoveDecrypter(ENCRYPTION_ZERO_RTT);
  RetireOriginalDestinationConnectionId();
}

bool QuicConnection::ValidateServerConnectionId(
    const QuicPacketHeader& header) const {
  if (perspective_ == Perspective::IS_CLIENT &&
      header.form == IETF_QUIC_SHORT_HEADER_PACKET) {
    return true;
  }

  QuicConnectionId server_connection_id =
      GetServerConnectionIdAsRecipient(header, perspective_);

  if (server_connection_id == default_path_.server_connection_id ||
      server_connection_id == original_destination_connection_id_) {
    return true;
  }

  if (PacketCanReplaceServerConnectionId(header, perspective_)) {
    QUIC_DLOG(INFO) << ENDPOINT << "Accepting packet with new connection ID "
                    << server_connection_id << " instead of "
                    << default_path_.server_connection_id;
    return true;
  }

  if (version().HasIetfQuicFrames() && perspective_ == Perspective::IS_SERVER &&
      self_issued_cid_manager_ != nullptr &&
      self_issued_cid_manager_->IsConnectionIdInUse(server_connection_id)) {
    return true;
  }

  if (NewServerConnectionIdMightBeValid(
          header, perspective_, server_connection_id_replaced_by_initial_)) {
    return true;
  }

  return false;
}

bool QuicConnection::OnUnauthenticatedPublicHeader(
    const QuicPacketHeader& header) {
  last_received_packet_info_.destination_connection_id =
      header.destination_connection_id;
  // If last packet destination connection ID is the original server
  // connection ID chosen by client, replaces it with the connection ID chosen
  // by server.
  if (perspective_ == Perspective::IS_SERVER &&
      original_destination_connection_id_.has_value() &&
      last_received_packet_info_.destination_connection_id ==
          *original_destination_connection_id_) {
    last_received_packet_info_.destination_connection_id =
        original_destination_connection_id_replacement_;
  }

  // As soon as we receive an initial we start ignoring subsequent retries.
  if (header.version_flag && header.long_packet_type == INITIAL) {
    framer_.set_drop_incoming_retry_packets(true);
  }

  if (!ValidateServerConnectionId(header)) {
    ++stats_.packets_dropped;
    QuicConnectionId server_connection_id =
        GetServerConnectionIdAsRecipient(header, perspective_);
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Ignoring packet from unexpected server connection ID "
                    << server_connection_id << " instead of "
                    << default_path_.server_connection_id;
    if (debug_visitor_ != nullptr) {
      debug_visitor_->OnIncorrectConnectionId(server_connection_id);
    }
    QUICHE_DCHECK_NE(Perspective::IS_SERVER, perspective_);
    return false;
  }

  if (!version().SupportsClientConnectionIds()) {
    return true;
  }

  if (perspective_ == Perspective::IS_SERVER &&
      header.form == IETF_QUIC_SHORT_HEADER_PACKET) {
    return true;
  }

  QuicConnectionId client_connection_id =
      GetClientConnectionIdAsRecipient(header, perspective_);

  if (client_connection_id == default_path_.client_connection_id) {
    return true;
  }

  if (!client_connection_id_is_set_ && perspective_ == Perspective::IS_SERVER) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Setting client connection ID from first packet to "
                    << client_connection_id;
    set_client_connection_id(client_connection_id);
    return true;
  }

  if (version().HasIetfQuicFrames() && perspective_ == Perspective::IS_CLIENT &&
      self_issued_cid_manager_ != nullptr &&
      self_issued_cid_manager_->IsConnectionIdInUse(client_connection_id)) {
    return true;
  }

  ++stats_.packets_dropped;
  QUIC_DLOG(INFO) << ENDPOINT
                  << "Ignoring packet from unexpected client connection ID "
                  << client_connection_id << " instead of "
                  << default_path_.client_connection_id;
  return false;
}

bool QuicConnection::OnUnauthenticatedHeader(const QuicPacketHeader& header) {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnUnauthenticatedHeader(header);
  }

  // Sanity check on the server connection ID in header.
  QUICHE_DCHECK(ValidateServerConnectionId(header));

  if (packet_creator_.HasPendingFrames()) {
    // Incoming packets may change a queued ACK frame.
    const std::string error_details =
        "Pending frames must be serialized before incoming packets are "
        "processed.";
    QUIC_BUG(quic_pending_frames_not_serialized)
        << error_details << ", received header: " << header;
    CloseConnection(QUIC_INTERNAL_ERROR, error_details,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  return true;
}

void QuicConnection::OnSuccessfulVersionNegotiation() {
  visitor_->OnSuccessfulVersionNegotiation(version());
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnSuccessfulVersionNegotiation(version());
  }
}

void QuicConnection::OnSuccessfulMigration(bool is_port_change) {
  QUICHE_DCHECK_EQ(perspective_, Perspective::IS_CLIENT);
  if (IsPathDegrading() && !multi_port_stats_) {
    // If path was previously degrading, and migration is successful after
    // probing, restart the path degrading and blackhole detection.
    // In the case of multi-port, since the alt-path state is inferred from
    // historical data, we can't trust it until we receive data on the new path.
    OnForwardProgressMade();
  }
  if (IsAlternativePath(default_path_.self_address,
                        default_path_.peer_address)) {
    // Reset alternative path state even if it is still under validation.
    alternative_path_.Clear();
  }
  // TODO(b/159074035): notify SentPacketManger with RTT sample from probing.
  if (version().HasIetfQuicFrames() && !is_port_change) {
    sent_packet_manager_.OnConnectionMigration(/*reset_send_algorithm=*/true);
  }
}

void QuicConnection::OnTransportParametersSent(
    const TransportParameters& transport_parameters) const {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnTransportParametersSent(transport_parameters);
  }
}

void QuicConnection::OnTransportParametersReceived(
    const TransportParameters& transport_parameters) const {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnTransportParametersReceived(transport_parameters);
  }
}

void QuicConnection::OnTransportParametersResumed(
    const TransportParameters& transport_parameters) const {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnTransportParametersResumed(transport_parameters);
  }
}

void QuicConnection::OnEncryptedClientHelloSent(
    absl::string_view client_hello) const {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnEncryptedClientHelloSent(client_hello);
  }
}

void QuicConnection::OnEncryptedClientHelloReceived(
    absl::string_view client_hello) const {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnEncryptedClientHelloReceived(client_hello);
  }
}

void QuicConnection::OnParsedClientHelloInfo(
    const ParsedClientHello& client_hello) {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnParsedClientHelloInfo(client_hello);
  }
}

bool QuicConnection::HasPendingAcks() const { return ack_alarm().IsSet(); }

void QuicConnection::OnUserAgentIdKnown(const std::string& /*user_agent_id*/) {
  sent_packet_manager_.OnUserAgentIdKnown();
}

void QuicConnection::OnDecryptedPacket(size_t /*length*/,
                                       EncryptionLevel level) {
  last_received_packet_info_.decrypted_level = level;
  last_received_packet_info_.decrypted = true;
  if (level == ENCRYPTION_FORWARD_SECURE &&
      !have_decrypted_first_one_rtt_packet_) {
    have_decrypted_first_one_rtt_packet_ = true;
    if (version().UsesTls() && perspective_ == Perspective::IS_SERVER) {
      // Servers MAY temporarily retain 0-RTT keys to allow decrypting reordered
      // packets without requiring their contents to be retransmitted with 1-RTT
      // keys. After receiving a 1-RTT packet, servers MUST discard 0-RTT keys
      // within a short time; the RECOMMENDED time period is three times the
      // Probe Timeout.
      // https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-discarding-0-rtt-keys
      discard_zero_rtt_decryption_keys_alarm().Set(
          clock_->ApproximateNow() + sent_packet_manager_.GetPtoDelay() * 3);
    }
  }
  if (EnforceAntiAmplificationLimit() && !IsHandshakeConfirmed() &&
      (level == ENCRYPTION_HANDSHAKE || level == ENCRYPTION_FORWARD_SECURE)) {
    // Address is validated by successfully processing a HANDSHAKE or 1-RTT
    // packet.
    default_path_.validated = true;
    stats_.address_validated_via_decrypting_packet = true;
  }
  idle_network_detector_.OnPacketReceived(
      last_received_packet_info_.receipt_time);

  visitor_->OnPacketDecrypted(level);
}

QuicSocketAddress QuicConnection::GetEffectivePeerAddressFromCurrentPacket()
    const {
  // By default, the connection is not proxied, and the effective peer address
  // is the packet's source address, i.e. the direct peer address.
  return last_received_packet_info_.source_address;
}

bool QuicConnection::OnPacketHeader(const QuicPacketHeader& header) {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPacketHeader(header, clock_->ApproximateNow(),
                                   last_received_packet_info_.decrypted_level);
  }

  // Will be decremented below if we fall through to return true.
  ++stats_.packets_dropped;

  if (!ProcessValidatedPacket(header)) {
    return false;
  }

  // Initialize the current packet content state.
  current_packet_content_ = NO_FRAMES_RECEIVED;
  is_current_packet_connectivity_probing_ = false;
  has_path_challenge_in_current_packet_ = false;
  current_effective_peer_migration_type_ = NO_CHANGE;

  if (enable_black_hole_avoidance_via_flow_label_) {
    if (!GetLargestReceivedPacket().IsInitialized()) {
      last_flow_label_received_ = last_received_packet_info_.flow_label;
    } else if (header.packet_number > GetLargestReceivedPacket() &&
               last_received_packet_info_.flow_label !=
                   last_flow_label_received_) {
      if (expect_peer_flow_label_change_) {
        expect_peer_flow_label_change_ = false;
        QUIC_CODE_COUNT(quic_detected_expected_flow_label_change);
      } else if (header.packet_number > GetLargestReceivedPacket() + 1) {
        // This packet introduced a packet number gap and came with a new flow
        // label so the peer is RTO'ing. In response, send a different flow
        // label.
        GenerateNewOutgoingFlowLabel();
        QUIC_CODE_COUNT(quic_generated_new_flow_label_on_flow_label_change);
      }
      last_flow_label_received_ = last_received_packet_info_.flow_label;
    }
  }

  if (perspective_ == Perspective::IS_CLIENT) {
    if (!GetLargestReceivedPacket().IsInitialized() ||
        header.packet_number > GetLargestReceivedPacket()) {
      if (version().HasIetfQuicFrames()) {
        // Client processes packets from any known server address, but only
        // updates peer address on initialization and/or to validated server
        // preferred address.
      } else {
        // Update direct_peer_address_ and default path peer_address immediately
        // for client connections.
        // TODO(fayang): only change peer addresses in application data packet
        // number space.
        UpdatePeerAddress(last_received_packet_info_.source_address);
        default_path_.peer_address = GetEffectivePeerAddressFromCurrentPacket();
      }
    }
  } else {
    // At server, remember the address change type of effective_peer_address
    // in current_effective_peer_migration_type_. But this variable alone
    // doesn't necessarily starts a migration. A migration will be started
    // later, once the current packet is confirmed to meet the following
    // conditions:
    // 1) current_effective_peer_migration_type_ is not NO_CHANGE.
    // 2) The current packet is not a connectivity probing.
    // 3) The current packet is not reordered, i.e. its packet number is the
    //    largest of this connection so far.
    // Once the above conditions are confirmed, a new migration will start
    // even if there is an active migration underway.
    current_effective_peer_migration_type_ =
        QuicUtils::DetermineAddressChangeType(
            default_path_.peer_address,
            GetEffectivePeerAddressFromCurrentPacket());

    if (version().HasIetfQuicFrames()) {
      auto effective_peer_address = GetEffectivePeerAddressFromCurrentPacket();
      // Since server does not send new connection ID to client before handshake
      // completion and source connection ID is omitted in short header packet,
      // the server_connection_id on PathState on the server side does not
      // affect the packets server writes after handshake completion. On the
      // other hand, it is still desirable to have the "correct" server
      // connection ID set on path.
      // 1) If client uses 1 unique server connection ID per path and the packet
      // is received from an existing path, then
      // last_received_packet_info_.destination_connection_id will always be the
      // same as the server connection ID on path. Server side will maintain the
      // 1-to-1 mapping from server connection ID to path. 2) If client uses
      // multiple server connection IDs on the same path, compared to the
      // server_connection_id on path,
      // last_received_packet_info_.destination_connection_id has the advantage
      // that it is still present in the session map since the packet can be
      // routed here regardless of packet reordering.
      if (IsDefaultPath(last_received_packet_info_.destination_address,
                        effective_peer_address)) {
        default_path_.server_connection_id =
            last_received_packet_info_.destination_connection_id;
      } else if (IsAlternativePath(
                     last_received_packet_info_.destination_address,
                     effective_peer_address)) {
        alternative_path_.server_connection_id =
            last_received_packet_info_.destination_connection_id;
      }
    }

    if (last_received_packet_info_.destination_connection_id !=
            default_path_.server_connection_id &&
        (!original_destination_connection_id_.has_value() ||
         last_received_packet_info_.destination_connection_id !=
             *original_destination_connection_id_)) {
      QUIC_CODE_COUNT(quic_connection_id_change);
    }

    QUIC_DLOG_IF(INFO, current_effective_peer_migration_type_ != NO_CHANGE)
        << ENDPOINT << "Effective peer's ip:port changed from "
        << default_path_.peer_address.ToString() << " to "
        << GetEffectivePeerAddressFromCurrentPacket().ToString()
        << ", active_effective_peer_migration_type is "
        << active_effective_peer_migration_type_;
  }

  --stats_.packets_dropped;
  QUIC_DVLOG(1) << ENDPOINT << "Received packet header: " << header;
  last_received_packet_info_.header = header;
  if (!stats_.first_decrypted_packet.IsInitialized()) {
    stats_.first_decrypted_packet =
        last_received_packet_info_.header.packet_number;
  }

  switch (last_received_packet_info_.ecn_codepoint) {
    case ECN_NOT_ECT:
      break;
    case ECN_ECT0:
      stats_.num_ecn_marks_received.ect0++;
      break;
    case ECN_ECT1:
      stats_.num_ecn_marks_received.ect1++;
      break;
    case ECN_CE:
      stats_.num_ecn_marks_received.ce++;
      break;
  }

  // Record packet receipt to populate ack info before processing stream
  // frames, since the processing may result in sending a bundled ack.
  QuicTime receipt_time = idle_network_detector_.time_of_last_received_packet();
  if (SupportsMultiplePacketNumberSpaces()) {
    receipt_time = last_received_packet_info_.receipt_time;
  }
  uber_received_packet_manager_.RecordPacketReceived(
      last_received_packet_info_.decrypted_level,
      last_received_packet_info_.header, receipt_time,
      last_received_packet_info_.ecn_codepoint);
  if (EnforceAntiAmplificationLimit() && !IsHandshakeConfirmed() &&
      !header.retry_token.empty() &&
      visitor_->ValidateToken(header.retry_token)) {
    QUIC_DLOG(INFO) << ENDPOINT << "Address validated via token.";
    QUIC_CODE_COUNT(quic_address_validated_via_token);
    default_path_.validated = true;
    stats_.address_validated_via_token = true;
  }
  QUICHE_DCHECK(connected_);
  return true;
}

bool QuicConnection::OnStreamFrame(const QuicStreamFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_3, !connected_)
      << "Processing STREAM frame when connection is closed. Received packet "
         "info: "
      << last_received_packet_info_;

  // Since a stream frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(STREAM_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnStreamFrame(frame);
  }
  if (!QuicUtils::IsCryptoStreamId(transport_version(), frame.stream_id) &&
      last_received_packet_info_.decrypted_level == ENCRYPTION_INITIAL) {
    if (MaybeConsiderAsMemoryCorruption(frame)) {
      CloseConnection(QUIC_MAYBE_CORRUPTED_MEMORY,
                      "Received crypto frame on non crypto stream.",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return false;
    }

    QUIC_PEER_BUG(quic_peer_bug_10511_6)
        << ENDPOINT << "Received an unencrypted data frame: closing connection"
        << " packet_number:" << last_received_packet_info_.header.packet_number
        << " stream_id:" << frame.stream_id
        << " received_packets:" << ack_frame();
    CloseConnection(QUIC_UNENCRYPTED_STREAM_DATA,
                    "Unencrypted stream data seen.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  // TODO(fayang): Consider moving UpdatePacketContent and
  // MaybeUpdateAckTimeout to a stand-alone function instead of calling them for
  // all frames.
  MaybeUpdateAckTimeout();
  visitor_->OnStreamFrame(frame);
  stats_.stream_bytes_received += frame.data_length;
  ping_manager_.reset_consecutive_retransmittable_on_wire_count();
  return connected_;
}

bool QuicConnection::OnCryptoFrame(const QuicCryptoFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_4, !connected_)
      << "Processing CRYPTO frame when connection is closed. Received packet "
         "info: "
      << last_received_packet_info_;

  // Since a CRYPTO frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(CRYPTO_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnCryptoFrame(frame);
  }
  MaybeUpdateAckTimeout();
  visitor_->OnCryptoFrame(frame);
  return connected_;
}

bool QuicConnection::OnAckFrameStart(QuicPacketNumber largest_acked,
                                     QuicTime::Delta ack_delay_time) {
  QUIC_BUG_IF(quic_bug_12714_5, !connected_)
      << "Processing ACK frame start when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;

  if (processing_ack_frame_) {
    CloseConnection(QUIC_INVALID_ACK_DATA,
                    "Received a new ack while processing an ack frame.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  // Since an ack frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(ACK_FRAME)) {
    return false;
  }

  QUIC_DVLOG(1) << ENDPOINT
                << "OnAckFrameStart, largest_acked: " << largest_acked;

  if (GetLargestReceivedPacketWithAck().IsInitialized() &&
      last_received_packet_info_.header.packet_number <=
          GetLargestReceivedPacketWithAck()) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received an old ack frame: ignoring";
    return true;
  }

  if (!sent_packet_manager_.GetLargestSentPacket().IsInitialized() ||
      largest_acked > sent_packet_manager_.GetLargestSentPacket()) {
    QUIC_DLOG(WARNING) << ENDPOINT
                       << "Peer's observed unsent packet:" << largest_acked
                       << " vs " << sent_packet_manager_.GetLargestSentPacket()
                       << ". SupportsMultiplePacketNumberSpaces():"
                       << SupportsMultiplePacketNumberSpaces()
                       << ", last_received_packet_info_.decrypted_level:"
                       << last_received_packet_info_.decrypted_level;
    // We got an ack for data we have not sent.
    CloseConnection(QUIC_INVALID_ACK_DATA, "Largest observed too high.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  processing_ack_frame_ = true;
  sent_packet_manager_.OnAckFrameStart(
      largest_acked, ack_delay_time,
      idle_network_detector_.time_of_last_received_packet());
  return true;
}

bool QuicConnection::OnAckRange(QuicPacketNumber start, QuicPacketNumber end) {
  QUIC_BUG_IF(quic_bug_12714_6, !connected_)
      << "Processing ACK frame range when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;
  QUIC_DVLOG(1) << ENDPOINT << "OnAckRange: [" << start << ", " << end << ")";

  if (GetLargestReceivedPacketWithAck().IsInitialized() &&
      last_received_packet_info_.header.packet_number <=
          GetLargestReceivedPacketWithAck()) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received an old ack frame: ignoring";
    return true;
  }

  sent_packet_manager_.OnAckRange(start, end);
  return true;
}

bool QuicConnection::OnAckTimestamp(QuicPacketNumber packet_number,
                                    QuicTime timestamp) {
  QUIC_BUG_IF(quic_bug_10511_7, !connected_)
      << "Processing ACK frame time stamp when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;
  QUIC_DVLOG(1) << ENDPOINT << "OnAckTimestamp: [" << packet_number << ", "
                << timestamp.ToDebuggingValue() << ")";

  if (GetLargestReceivedPacketWithAck().IsInitialized() &&
      last_received_packet_info_.header.packet_number <=
          GetLargestReceivedPacketWithAck()) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received an old ack frame: ignoring";
    return true;
  }

  sent_packet_manager_.OnAckTimestamp(packet_number, timestamp);
  return true;
}

bool QuicConnection::OnAckFrameEnd(
    QuicPacketNumber start, const std::optional<QuicEcnCounts>& ecn_counts) {
  QUIC_BUG_IF(quic_bug_12714_7, !connected_)
      << "Processing ACK frame end when connection is closed. Received packet "
         "info: "
      << last_received_packet_info_;
  QUIC_DVLOG(1) << ENDPOINT << "OnAckFrameEnd, start: " << start;

  if (GetLargestReceivedPacketWithAck().IsInitialized() &&
      last_received_packet_info_.header.packet_number <=
          GetLargestReceivedPacketWithAck()) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received an old ack frame: ignoring";
    return true;
  }
  const bool one_rtt_packet_was_acked =
      sent_packet_manager_.one_rtt_packet_acked();
  const bool zero_rtt_packet_was_acked =
      sent_packet_manager_.zero_rtt_packet_acked();
  const AckResult ack_result = sent_packet_manager_.OnAckFrameEnd(
      idle_network_detector_.time_of_last_received_packet(),
      last_received_packet_info_.header.packet_number,
      last_received_packet_info_.decrypted_level, ecn_counts);
  if (ack_result != PACKETS_NEWLY_ACKED &&
      ack_result != NO_PACKETS_NEWLY_ACKED) {
    // Error occurred (e.g., this ACK tries to ack packets in wrong packet
    // number space), and this would cause the connection to be closed.
    QUIC_DLOG(ERROR) << ENDPOINT
                     << "Error occurred when processing an ACK frame: "
                     << QuicUtils::AckResultToString(ack_result);
    return false;
  }
  if (SupportsMultiplePacketNumberSpaces() && !one_rtt_packet_was_acked &&
      sent_packet_manager_.one_rtt_packet_acked()) {
    visitor_->OnOneRttPacketAcknowledged();
  }
  if (debug_visitor_ != nullptr && version().UsesTls() &&
      !zero_rtt_packet_was_acked &&
      sent_packet_manager_.zero_rtt_packet_acked()) {
    debug_visitor_->OnZeroRttPacketAcked();
  }
  // Cancel the send alarm because new packets likely have been acked, which
  // may change the congestion window and/or pacing rate.  Canceling the alarm
  // causes CanWrite to recalculate the next send time.
  if (send_alarm().IsSet()) {
    send_alarm().Cancel();
  }
  if (supports_release_time_) {
    // Update pace time into future because smoothed RTT is likely updated.
    UpdateReleaseTimeIntoFuture();
  }
  SetLargestReceivedPacketWithAck(
      last_received_packet_info_.header.packet_number);
  PostProcessAfterAckFrame(ack_result == PACKETS_NEWLY_ACKED);
  processing_ack_frame_ = false;
  return connected_;
}

bool QuicConnection::OnStopWaitingFrame(const QuicStopWaitingFrame& /*frame*/) {
  QUIC_BUG_IF(quic_bug_12714_8, !connected_)
      << "Processing STOP_WAITING frame when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;

  // Since a stop waiting frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(STOP_WAITING_FRAME)) {
    return false;
  }
  return connected_;
}

bool QuicConnection::OnPaddingFrame(const QuicPaddingFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_9, !connected_)
      << "Processing PADDING frame when connection is closed. Received packet "
         "info: "
      << last_received_packet_info_;
  if (!UpdatePacketContent(PADDING_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPaddingFrame(frame);
  }
  return true;
}

bool QuicConnection::OnPingFrame(const QuicPingFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_10, !connected_)
      << "Processing PING frame when connection is closed. Received packet "
         "info: "
      << last_received_packet_info_;
  if (!UpdatePacketContent(PING_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    QuicTime::Delta ping_received_delay = QuicTime::Delta::Zero();
    const QuicTime now = clock_->ApproximateNow();
    if (now > stats_.connection_creation_time) {
      ping_received_delay = now - stats_.connection_creation_time;
    }
    debug_visitor_->OnPingFrame(frame, ping_received_delay);
  }
  MaybeUpdateAckTimeout();
  return true;
}

bool QuicConnection::OnRstStreamFrame(const QuicRstStreamFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_11, !connected_)
      << "Processing RST_STREAM frame when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;

  // Since a reset stream frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(RST_STREAM_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnRstStreamFrame(frame);
  }
  QUIC_DLOG(INFO) << ENDPOINT
                  << "RST_STREAM_FRAME received for stream: " << frame.stream_id
                  << " with error: "
                  << QuicRstStreamErrorCodeToString(frame.error_code);
  MaybeUpdateAckTimeout();
  visitor_->OnRstStream(frame);
  return connected_;
}

bool QuicConnection::OnStopSendingFrame(const QuicStopSendingFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_12, !connected_)
      << "Processing STOP_SENDING frame when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;

  // Since a reset stream frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(STOP_SENDING_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnStopSendingFrame(frame);
  }

  QUIC_DLOG(INFO) << ENDPOINT << "STOP_SENDING frame received for stream: "
                  << frame.stream_id
                  << " with error: " << frame.ietf_error_code;
  MaybeUpdateAckTimeout();
  visitor_->OnStopSendingFrame(frame);
  return connected_;
}

class ReversePathValidationContext : public QuicPathValidationContext {
 public:
  ReversePathValidationContext(const QuicSocketAddress& self_address,
                               const QuicSocketAddress& peer_address,
                               const QuicSocketAddress& effective_peer_address,
                               QuicConnection* connection)
      : QuicPathValidationContext(self_address, peer_address,
                                  effective_peer_address),
        connection_(connection) {}

  QuicPacketWriter* WriterToUse() override { return connection_->writer(); }

 private:
  QuicConnection* connection_;
};

bool QuicConnection::OnPathChallengeFrame(const QuicPathChallengeFrame& fra
"""


```
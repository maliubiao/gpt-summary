Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `QuicConnection` class in Chromium's QUIC implementation. The request also asks for:

1. **Relationship to JavaScript:**  If any part of the code interacts with JavaScript functionality.
2. **Logical Inference Examples:**  Scenarios with assumed input and output.
3. **Common User/Programming Errors:**  Examples of mistakes related to this code.
4. **User Journey to this Code:** How a user's actions might lead to this code being executed (as debugging hints).
5. **Overall Functionality (Part 4 of 10):** A high-level summary of the responsibilities covered in this specific section.

Here's a breakdown of the code and the thinking process to address each point:

**Code Analysis:**

The code snippet includes the following methods of the `QuicConnection` class:

* **`OnStreamReset`:** Handles stream reset events.
* **`GetStats`:** Returns connection statistics.
* **`OnCoalescedPacket`:** Processes coalesced packets.
* **`OnUndecryptablePacket`:**  Handles packets that cannot be decrypted immediately.
* **`ShouldEnqueueUnDecryptablePacket`:** Determines if an undecryptable packet should be queued.
* **`UndecryptablePacketsInfo`:**  Provides information about queued undecryptable packets.
* **`ProcessUdpPacket`:**  The main entry point for processing incoming UDP packets. This is a large and crucial function.
* **`OnBlockedWriterCanWrite`:**  Called when the underlying socket becomes writable.
* **`OnCanWrite`:**  Handles the event when the connection can write data.
* **`OnSendAlarm`:**  Triggered by the send alarm.
* **`WriteIfNotBlocked`:** Attempts to write data if not blocked.
* **`MaybeClearQueuedPacketsOnPathChange`:** Discards queued packets if the network path changes.
* **`ReplaceInitialServerConnectionId`:** Updates the server's connection ID.
* **`FindMatchingOrNewClientConnectionIdOrToken`:** Finds or allocates connection IDs and tokens for new paths.
* **`FindOnPathConnectionIds`:** Retrieves connection IDs associated with a specific network path.
* **`SetDefaultPathState`:** Sets the state of the primary network path.
* **`PeerAddressChanged`:** Detects if the peer's IP address has changed.
* **`GenerateNewOutgoingFlowLabel`:** Creates a new IPv6 flow label.
* **`ProcessValidatedPacket`:**  Performs checks on validated packets.
* **`ValidateReceivedPacketNumber`:** Verifies if a received packet number is expected.
* **`WriteQueuedPackets`:** Sends packets that were buffered.
* **`MarkZeroRttPacketsForRetransmission`:** Marks 0-RTT packets for retransmission if they are rejected.
* **`NeuterUnencryptedPackets`:**  Discards unencrypted packets from the send queue.
* **`IsMissingDestinationConnectionID`:** Checks if a destination connection ID is available.
* **`ShouldGeneratePacket`:** Determines if a new packet should be generated.
* **`MaybeBundleOpportunistically`:**  Attempts to bundle ACK frames with other data.
* **`CanWrite`:** Checks if the connection is able to send data.
* **`CalculatePacketSentTime`:** Determines the appropriate time to send a packet.

**Addressing the Specific Requests:**

1. **Relationship to JavaScript:**  QUIC is a transport protocol. While JavaScript running in a browser might *initiate* a QUIC connection (through browser APIs like `fetch`), this C++ code handles the low-level details of managing that connection within the browser's network stack. There's no direct JavaScript code within this snippet. The connection is managed by the underlying C++ networking libraries.

2. **Logical Inference Examples:**  For each function, think about possible inputs and their likely outputs. Focus on the core logic of the function.

3. **Common User/Programming Errors:**  Consider what mistakes developers or users of the Chromium networking stack might make that would lead to these functions being called or errors occurring within them.

4. **User Journey to this Code:** Imagine a user interacting with a website that uses QUIC. Trace the network events back to the point where these C++ functions are involved.

5. **Overall Functionality (Part 4 of 10):**  Based on the methods included in this snippet, identify the key areas of responsibility. Look for common themes or groups of related functions.

**Self-Correction/Refinement during thought process:**

* Initially, I might have overemphasized the direct interaction with JavaScript. It's important to clarify that QUIC is a lower-level transport protocol, and the connection management is handled in C++. The JavaScript interaction is at a higher level.
* For the logical inference examples, I need to be specific about the *input parameters* and the *output or side effects*. Vague descriptions aren't helpful.
* When considering user errors, it's crucial to differentiate between errors in the QUIC implementation itself and errors in how higher-level code (potentially JavaScript or the browser) interacts with the QUIC connection. The focus should be on errors relevant to the `QuicConnection` class's responsibilities.
*  For the user journey, I need to consider both successful and error scenarios. How does a normal page load lead here?  What happens if the network is unstable or there are security issues?
* When summarizing the functionality, I should avoid just listing the function names. Instead, group them into logical categories (e.g., handling incoming packets, managing sending, connection state management).

By following these steps, I can construct a comprehensive and accurate answer that addresses all aspects of the user's request.
这是对 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc` 文件部分代码的功能归纳。 这部分代码主要集中在**连接的接收处理、统计信息的获取、写操作管理、连接ID管理、路径管理以及数据包的验证和处理**等方面。

以下是这段代码的具体功能归纳：

**核心功能:**

* **处理流重置 (Stream Reset):** `OnStreamReset` 函数处理对 QUIC 流的重置请求，根据错误码决定是否刷新待发送的流帧。
* **获取连接统计信息 (Get Connection Stats):** `GetStats` 函数返回当前连接的各种统计数据，包括 RTT (往返时延)、带宽估计、MTU (最大传输单元) 等信息。
* **处理合并的数据包 (Coalesced Packet):** `OnCoalescedPacket` 函数接收并队列化合并的 QUIC 数据包。
* **处理无法解密的数据包 (Undecryptable Packet):** `OnUndecryptablePacket` 函数处理接收到的无法立即解密的数据包，并根据情况进行队列化或丢弃。它还负责检查 AEAD (Authenticated Encryption with Associated Data) 的完整性限制，防止攻击。
* **决定是否队列化无法解密的数据包:** `ShouldEnqueueUnDecryptablePacket` 函数根据密钥状态、握手状态和队列大小等因素，判断是否应该缓存无法解密的数据包。
* **提供无法解密数据包的信息:** `UndecryptablePacketsInfo` 函数返回关于已队列的无法解密数据包的详细信息。
* **处理 UDP 数据包 (Process UDP Packet):** `ProcessUdpPacket` 函数是处理接收到的 UDP 数据包的核心函数。它负责：
    * 更新连接的对端地址信息。
    * 统计接收到的字节数和包数。
    * 检查数据包的接收时间是否合理。
    * 调用 `framer_.ProcessPacket` 解密和解析数据包。
    * 处理合并的数据包和无法解密的数据包的队列。
    * 可能会发送响应数据包。
    * 设置 Ping 告警。
    * 清理不再使用的对端发布的连接ID。
* **处理写操作阻塞后的可写事件:** `OnBlockedWriterCanWrite` 函数在底层写操作从阻塞状态变为可写时被调用。
* **处理可写事件 (On Can Write):** `OnCanWrite` 函数处理连接可以发送数据的情况，负责发送队列中的数据包，并通知上层应用可以写入数据。
* **处理发送告警 (On Send Alarm):** `OnSendAlarm` 函数在发送告警触发时被调用，用于触发数据发送。
* **如果没有阻塞则执行写操作:** `WriteIfNotBlocked` 函数检查连接是否阻塞，如果没有则调用 `OnCanWrite` 进行数据发送。
* **在路径更改时可能清理队列中的数据包:** `MaybeClearQueuedPacketsOnPathChange` 函数在 QUIC 版本支持 IETF 帧且路径发生变化时，清理队列中等待发送的数据包。
* **替换初始服务器连接ID:** `ReplaceInitialServerConnectionId` 函数用于客户端在收到服务器的新连接ID后进行替换。
* **查找匹配或新的客户端连接ID或令牌:** `FindMatchingOrNewClientConnectionIdOrToken` 函数在服务器端用于查找或生成新的客户端连接ID和无状态重置令牌。
* **查找路径上的连接ID:** `FindOnPathConnectionIds` 函数根据源地址和目标地址查找对应的客户端和服务器连接ID。
* **设置默认路径状态:** `SetDefaultPathState` 函数用于设置连接的默认路径状态，包括连接ID等信息。
* **检测对端地址是否已更改:** `PeerAddressChanged` 函数用于判断接收到的数据包的源地址是否与之前记录的对端地址不同。
* **生成新的出站流标签:** `GenerateNewOutgoingFlowLabel` 函数用于生成新的 IPv6 流标签。
* **处理已验证的数据包:** `ProcessValidatedPacket` 函数对已经过初步验证的数据包进行进一步处理，包括检查对端地址是否发生变化，以及更新连接的各种状态信息。
* **验证接收到的数据包编号:** `ValidateReceivedPacketNumber` 函数检查接收到的数据包编号是否是我们期望接收的。
* **写入队列中的数据包:** `WriteQueuedPackets` 函数将缓冲区中等待发送的数据包发送出去。
* **标记 0-RTT 数据包以进行重传:** `MarkZeroRttPacketsForRetransmission` 函数在 0-RTT 连接被拒绝时，标记相关的未加密数据包需要重传。
* **使未加密的数据包失效:** `NeuterUnencryptedPackets` 函数将发送队列中未加密的数据包标记为不再需要发送。
* **检查是否缺少目标连接ID:** `IsMissingDestinationConnectionID` 函数检查当前是否缺少发送数据包所需的目标连接ID。
* **判断是否应该生成数据包:** `ShouldGeneratePacket` 函数根据连接状态、拥塞控制等因素判断是否应该生成新的数据包进行发送。
* **可能机会性地捆绑 ACK:** `MaybeBundleOpportunistically` 函数尝试将 ACK 帧与其它数据帧一起发送，以提高效率。
* **检查是否可以写入数据:** `CanWrite` 函数检查当前连接是否可以发送数据，考虑了拥塞控制、写阻塞、放大因子限制等因素。
* **计算数据包的发送时间:** `CalculatePacketSentTime` 函数根据连接的发送速率控制策略，计算数据包应该被发送的时间。

**与 JavaScript 的关系：**

这段 C++ 代码是 Chromium 浏览器网络栈的一部分，负责 QUIC 协议的底层实现。虽然 JavaScript 代码本身不直接操作这些函数，但当 JavaScript 发起网络请求 (例如使用 `fetch` API) 且浏览器协商使用 QUIC 协议时，最终会调用到这里的 C++ 代码来处理 QUIC 连接的建立、数据传输、错误处理等。

**举例说明:**

假设用户在浏览器中访问一个支持 QUIC 协议的网站：

1. **JavaScript 发起请求:**  JavaScript 代码使用 `fetch("https://example.com")` 发起一个 HTTPS 请求。
2. **协议协商:** 浏览器与服务器进行协议协商，确定使用 QUIC 协议。
3. **UDP 数据包接收 (进入 `ProcessUdpPacket`):** 服务器响应的 QUIC 数据包通过 UDP 传输到达浏览器，最终会进入 `QuicConnection::ProcessUdpPacket` 函数进行处理。
4. **数据包解密 (`framer_.ProcessPacket`):**  `ProcessUdpPacket` 函数会调用 `framer_.ProcessPacket` 来解密接收到的数据。
5. **获取连接统计 (可能调用 `GetStats`):**  浏览器的开发者工具或者内部监控系统可能会调用 `QuicConnection::GetStats` 来查看当前 QUIC 连接的性能指标，例如 RTT 和带宽。
6. **流重置 (可能调用 `OnStreamReset`):**  如果服务器或客户端决定提前终止某个数据流，可能会发送一个 RST_STREAM 帧，这会导致 `QuicConnection::OnStreamReset` 被调用。
7. **发送数据 (涉及 `OnCanWrite` 等):** 当 JavaScript 需要向服务器发送数据时，例如通过 WebSocket over QUIC，会触发 `QuicConnection::OnCanWrite` 等函数来管理数据的发送。

**逻辑推理的假设输入与输出:**

**例子 1: `OnUndecryptablePacket`**

* **假设输入:**
    * `packet`: 一个包含加密数据的 `QuicEncryptedPacket` 对象。
    * `decryption_level`: `ENCRYPTION_INITIAL` (表示用初始密钥尝试解密)。
    * `has_decryption_key`: `false` (表示当前没有对应的解密密钥)。
* **输出:**
    * `stats_.undecryptable_packets_received_before_handshake_complete` 计数器会增加。
    * `ShouldEnqueueUnDecryptablePacket` 返回 `true` (假设满足队列条件)，数据包会被添加到 `undecryptable_packets_` 队列中等待后续解密。

**例子 2: `GetStats`**

* **假设输入:**  连接已经建立并运行一段时间，`sent_packet_manager_` 中已经记录了一些 RTT 数据。
* **输出:**  `GetStats` 函数会返回一个 `QuicConnectionStats` 对象，其中包含：
    * `stats_.min_rtt_us`:  从 `rtt_stats_` 获取的最小 RTT 值（单位微秒）。
    * `stats_.srtt_us`: 从 `rtt_stats_` 获取的平滑 RTT 值（单位微秒）。
    * `stats_.estimated_bandwidth`: 从 `sent_packet_manager_` 获取的带宽估计值。
    * 其他连接相关的统计信息，如 MTU 等。

**用户或编程常见的使用错误:**

1. **在连接未建立时尝试发送数据:**  如果上层代码在 QUIC 连接尚未建立完成时就尝试发送数据，可能会导致数据被缓冲或丢失。`CanWrite` 函数的检查可以防止这种情况，但上层逻辑也需要进行判断。
2. **错误地处理连接状态:**  如果上层代码没有正确地监听连接状态变化的回调，可能会在连接已经关闭的情况下尝试发送或接收数据。
3. **服务端配置错误导致解密失败:**  服务端配置的加密参数与客户端不匹配，可能导致客户端收到无法解密的数据包，从而触发 `OnUndecryptablePacket`。
4. **网络环境不稳定导致路径变化未处理:**  如果网络环境不稳定，客户端的 IP 地址或端口发生变化，服务端可能无法正确识别连接，导致数据包被丢弃或处理错误。`MaybeClearQueuedPacketsOnPathChange` 和相关的路径管理代码旨在处理这类问题，但如果配置不当或处理逻辑有误，可能会出现问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入网址并访问一个 HTTPS 网站。**
2. **浏览器与服务器进行 TLS 握手。**
3. **在 TLS 握手过程中或之后，浏览器和服务器可能会协商使用 QUIC 协议。**
4. **如果协商成功，后续的数据传输将使用 QUIC 协议通过 UDP 进行。**
5. **当服务器向客户端发送 QUIC 数据包时，网络栈会接收到这些 UDP 数据包。**
6. **接收到的 UDP 数据包会传递给 `QuicConnection::ProcessUdpPacket` 函数进行处理。**
7. **在 `ProcessUdpPacket` 函数中，会进行数据包的解密、帧的解析、连接状态的更新等操作。**
8. **如果接收到的数据包无法解密，则会调用 `QuicConnection::OnUndecryptablePacket`。**
9. **如果需要发送数据，例如响应用户的请求，则会涉及到 `QuicConnection::OnCanWrite` 和相关的数据发送逻辑。**
10. **可以通过抓包工具 (如 Wireshark) 观察 UDP 数据包的交互，结合 Chromium 的网络日志 (chrome://net-internals/#quic) 来定位问题。**
11. **在 Chromium 源代码中设置断点，例如在 `QuicConnection::ProcessUdpPacket` 的入口处，可以逐步跟踪数据包的处理流程。**

**归纳一下它的功能 (作为第 4 部分):**

这段代码主要负责 **QUIC 连接的接收处理和状态管理**。 它处理接收到的 UDP 数据包，进行解密、验证和解析，并更新连接的统计信息。同时，它也负责管理数据发送的准备工作，包括检查连接状态、处理写阻塞等。 此外，连接ID的管理和路径的管理也是这部分代码的重要职责，确保在网络环境变化时连接能够保持稳定。  可以将其视为 QUIC 连接的核心数据包接收和初步发送管理的枢纽。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共10部分，请归纳一下它的功能

"""
id QuicConnection::OnStreamReset(QuicStreamId id,
                                   QuicRstStreamErrorCode error) {
  if (error == QUIC_STREAM_NO_ERROR) {
    // All data for streams which are reset with QUIC_STREAM_NO_ERROR must
    // be received by the peer.
    return;
  }
  // Flush stream frames of reset stream.
  if (packet_creator_.HasPendingStreamFramesOfStream(id)) {
    ScopedPacketFlusher flusher(this);
    packet_creator_.FlushCurrentPacket();
  }
  // TODO(ianswett): Consider checking for 3 RTOs when the last stream is
  // cancelled as well.
}

const QuicConnectionStats& QuicConnection::GetStats() {
  const RttStats* rtt_stats = sent_packet_manager_.GetRttStats();

  // Update rtt and estimated bandwidth.
  QuicTime::Delta min_rtt = rtt_stats->min_rtt();
  if (min_rtt.IsZero()) {
    // If min RTT has not been set, use initial RTT instead.
    min_rtt = rtt_stats->initial_rtt();
  }
  stats_.min_rtt_us = min_rtt.ToMicroseconds();

  QuicTime::Delta srtt = rtt_stats->SmoothedOrInitialRtt();
  stats_.srtt_us = srtt.ToMicroseconds();

  stats_.estimated_bandwidth = sent_packet_manager_.BandwidthEstimate();
  sent_packet_manager_.GetSendAlgorithm()->PopulateConnectionStats(&stats_);
  stats_.egress_mtu = long_term_mtu_;
  stats_.ingress_mtu = largest_received_packet_size_;
  return stats_;
}

void QuicConnection::OnCoalescedPacket(const QuicEncryptedPacket& packet) {
  QueueCoalescedPacket(packet);
}

void QuicConnection::OnUndecryptablePacket(const QuicEncryptedPacket& packet,
                                           EncryptionLevel decryption_level,
                                           bool has_decryption_key) {
  QUIC_DVLOG(1) << ENDPOINT << "Received undecryptable packet of length "
                << packet.length() << " with"
                << (has_decryption_key ? "" : "out") << " key at level "
                << decryption_level
                << " while connection is at encryption level "
                << encryption_level_;
  QUICHE_DCHECK(EncryptionLevelIsValid(decryption_level));
  if (encryption_level_ != ENCRYPTION_FORWARD_SECURE) {
    ++stats_.undecryptable_packets_received_before_handshake_complete;
  }

  const bool should_enqueue =
      ShouldEnqueueUnDecryptablePacket(decryption_level, has_decryption_key);
  if (should_enqueue) {
    QueueUndecryptablePacket(packet, decryption_level);
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnUndecryptablePacket(decryption_level,
                                          /*dropped=*/!should_enqueue);
  }

  if (has_decryption_key) {
    stats_.num_failed_authentication_packets_received++;
    if (version().UsesTls()) {
      // Should always be non-null if has_decryption_key is true.
      QUICHE_DCHECK(framer_.GetDecrypter(decryption_level));
      const QuicPacketCount integrity_limit =
          framer_.GetDecrypter(decryption_level)->GetIntegrityLimit();
      QUIC_DVLOG(2) << ENDPOINT << "Checking AEAD integrity limits:"
                    << " num_failed_authentication_packets_received="
                    << stats_.num_failed_authentication_packets_received
                    << " integrity_limit=" << integrity_limit;
      if (stats_.num_failed_authentication_packets_received >=
          integrity_limit) {
        const std::string error_details = absl::StrCat(
            "decrypter integrity limit reached:"
            " num_failed_authentication_packets_received=",
            stats_.num_failed_authentication_packets_received,
            " integrity_limit=", integrity_limit);
        CloseConnection(QUIC_AEAD_LIMIT_REACHED, error_details,
                        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      }
    }
  }

  if (version().UsesTls() && perspective_ == Perspective::IS_SERVER &&
      decryption_level == ENCRYPTION_ZERO_RTT && !has_decryption_key &&
      had_zero_rtt_decrypter_) {
    QUIC_CODE_COUNT_N(
        quic_server_received_tls_zero_rtt_packet_after_discarding_decrypter, 1,
        3);
    stats_
        .num_tls_server_zero_rtt_packets_received_after_discarding_decrypter++;
  }
}

bool QuicConnection::ShouldEnqueueUnDecryptablePacket(
    EncryptionLevel decryption_level, bool has_decryption_key) const {
  if (has_decryption_key) {
    // We already have the key for this decryption level, therefore no
    // future keys will allow it be decrypted.
    return false;
  }
  if (IsHandshakeComplete()) {
    // We do not expect to install any further keys.
    return false;
  }
  if (undecryptable_packets_.size() >= max_undecryptable_packets_) {
    // We do not queue more than max_undecryptable_packets_ packets.
    return false;
  }
  if (version().KnowsWhichDecrypterToUse() &&
      decryption_level == ENCRYPTION_INITIAL) {
    // When the corresponding decryption key is not available, all
    // non-Initial packets should be buffered until the handshake is complete.
    return false;
  }
  if (perspective_ == Perspective::IS_CLIENT && version().UsesTls() &&
      decryption_level == ENCRYPTION_ZERO_RTT) {
    // Only clients send Zero RTT packets in IETF QUIC.
    QUIC_PEER_BUG(quic_peer_bug_client_received_zero_rtt)
        << "Client received a Zero RTT packet, not buffering.";
    return false;
  }
  return true;
}

std::string QuicConnection::UndecryptablePacketsInfo() const {
  std::string info = absl::StrCat(
      "num_undecryptable_packets: ", undecryptable_packets_.size(), " {");
  for (const auto& packet : undecryptable_packets_) {
    absl::StrAppend(&info, "[",
                    EncryptionLevelToString(packet.encryption_level), ", ",
                    packet.packet->length(), "]");
  }
  absl::StrAppend(&info, "}");
  return info;
}

void QuicConnection::ProcessUdpPacket(const QuicSocketAddress& self_address,
                                      const QuicSocketAddress& peer_address,
                                      const QuicReceivedPacket& packet) {
  if (!connected_) {
    return;
  }
  QUIC_DVLOG(2) << ENDPOINT << "Received encrypted " << packet.length()
                << " bytes:" << std::endl
                << quiche::QuicheTextUtils::HexDump(
                       absl::string_view(packet.data(), packet.length()));
  QUIC_BUG_IF(quic_bug_12714_21, current_packet_data_ != nullptr)
      << "ProcessUdpPacket must not be called while processing a packet.";
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPacketReceived(self_address, peer_address, packet);
  }
  last_received_packet_info_ = ReceivedPacketInfo(
      self_address, peer_address, packet.receipt_time(), packet.length(),
      packet.ecn_codepoint(), packet.ipv6_flow_label());
  current_packet_data_ = packet.data();

  if (!default_path_.self_address.IsInitialized()) {
    default_path_.self_address = last_received_packet_info_.destination_address;
  } else if (default_path_.self_address != self_address &&
             expected_server_preferred_address_.IsInitialized() &&
             self_address.Normalized() ==
                 expected_server_preferred_address_.Normalized()) {
    // If the packet is received at the preferred address, treat it as if it is
    // received on the original server address.
    last_received_packet_info_.destination_address = default_path_.self_address;
    last_received_packet_info_.actual_destination_address = self_address;
  }

  if (!direct_peer_address_.IsInitialized()) {
    if (perspective_ == Perspective::IS_CLIENT) {
      AddKnownServerAddress(last_received_packet_info_.source_address);
    }
    UpdatePeerAddress(last_received_packet_info_.source_address);
  }

  if (!default_path_.peer_address.IsInitialized()) {
    const QuicSocketAddress effective_peer_addr =
        GetEffectivePeerAddressFromCurrentPacket();

    // The default path peer_address must be initialized at the beginning of the
    // first packet processed(here). If effective_peer_addr is uninitialized,
    // just set effective_peer_address_ to the direct peer address.
    default_path_.peer_address = effective_peer_addr.IsInitialized()
                                     ? effective_peer_addr
                                     : direct_peer_address_;
  }

  stats_.bytes_received += packet.length();
  ++stats_.packets_received;
  if (IsDefaultPath(last_received_packet_info_.destination_address,
                    last_received_packet_info_.source_address) &&
      EnforceAntiAmplificationLimit()) {
    last_received_packet_info_.received_bytes_counted = true;
    default_path_.bytes_received_before_address_validation +=
        last_received_packet_info_.length;
  }

  // Ensure the time coming from the packet reader is within 2 minutes of now.
  if (std::abs((packet.receipt_time() - clock_->ApproximateNow()).ToSeconds()) >
      2 * 60) {
    QUIC_LOG(WARNING) << "(Formerly quic_bug_10511_21): Packet receipt time: "
                      << packet.receipt_time().ToDebuggingValue()
                      << " too far from current time: "
                      << clock_->ApproximateNow().ToDebuggingValue();
  }
  QUIC_DVLOG(1) << ENDPOINT << "time of last received packet: "
                << packet.receipt_time().ToDebuggingValue() << " from peer "
                << last_received_packet_info_.source_address << ", to "
                << last_received_packet_info_.destination_address;

  ScopedPacketFlusher flusher(this);
  if (!framer_.ProcessPacket(packet)) {
    // If we are unable to decrypt this packet, it might be
    // because the CHLO or SHLO packet was lost.
    QUIC_DVLOG(1) << ENDPOINT
                  << "Unable to process packet.  Last packet processed: "
                  << last_received_packet_info_.header.packet_number;
    current_packet_data_ = nullptr;
    is_current_packet_connectivity_probing_ = false;

    MaybeProcessCoalescedPackets();
    return;
  }

  ++stats_.packets_processed;

  QUIC_DLOG_IF(INFO, active_effective_peer_migration_type_ != NO_CHANGE)
      << "sent_packet_manager_.GetLargestObserved() = "
      << sent_packet_manager_.GetLargestObserved()
      << ", highest_packet_sent_before_effective_peer_migration_ = "
      << highest_packet_sent_before_effective_peer_migration_;
  if (!framer_.version().HasIetfQuicFrames() &&
      active_effective_peer_migration_type_ != NO_CHANGE &&
      sent_packet_manager_.GetLargestObserved().IsInitialized() &&
      (!highest_packet_sent_before_effective_peer_migration_.IsInitialized() ||
       sent_packet_manager_.GetLargestObserved() >
           highest_packet_sent_before_effective_peer_migration_)) {
    if (perspective_ == Perspective::IS_SERVER) {
      OnEffectivePeerMigrationValidated(/*is_migration_linkable=*/true);
    }
  }

  if (!MaybeProcessCoalescedPackets()) {
    MaybeProcessUndecryptablePackets();
    MaybeSendInResponseToPacket();
  }
  SetPingAlarm();
  RetirePeerIssuedConnectionIdsNoLongerOnPath();
  current_packet_data_ = nullptr;
  is_current_packet_connectivity_probing_ = false;
}

void QuicConnection::OnBlockedWriterCanWrite() {
  writer_->SetWritable();
  OnCanWrite();
}

void QuicConnection::OnCanWrite() {
  if (!connected_) {
    return;
  }
  if (writer_->IsWriteBlocked()) {
    const std::string error_details =
        "Writer is blocked while calling OnCanWrite.";
    QUIC_BUG(quic_bug_10511_22) << ENDPOINT << error_details;
    CloseConnection(QUIC_INTERNAL_ERROR, error_details,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  ScopedPacketFlusher flusher(this);

  WriteQueuedPackets();
  const QuicTime ack_timeout =
      uber_received_packet_manager_.GetEarliestAckTimeout();
  if (ack_timeout.IsInitialized() && ack_timeout <= clock_->ApproximateNow()) {
    // Send an ACK now because either 1) we were write blocked when we last
    // tried to send an ACK, or 2) both ack alarm and send alarm were set to
    // go off together.
    if (SupportsMultiplePacketNumberSpaces()) {
      SendAllPendingAcks();
    } else {
      SendAck();
    }
  }

  // Sending queued packets may have caused the socket to become write blocked,
  // or the congestion manager to prohibit sending.
  if (!CanWrite(HAS_RETRANSMITTABLE_DATA)) {
    return;
  }

  // Tell the session it can write.
  visitor_->OnCanWrite();

  // After the visitor writes, it may have caused the socket to become write
  // blocked or the congestion manager to prohibit sending, so check again.
  if (visitor_->WillingAndAbleToWrite() && !send_alarm().IsSet() &&
      CanWrite(HAS_RETRANSMITTABLE_DATA)) {
    // We're not write blocked, but some data wasn't written. Register for
    // 'immediate' resumption so we'll keep writing after other connections.
    send_alarm().Set(clock_->ApproximateNow());
  }
}

void QuicConnection::OnSendAlarm() {
  QUICHE_DCHECK(connected());
  WriteIfNotBlocked();
}

void QuicConnection::WriteIfNotBlocked() {
  if (framer().is_processing_packet()) {
    QUIC_BUG(connection_write_mid_packet_processing)
        << ENDPOINT << "Tried to write in mid of packet processing";
    return;
  }
  if (IsMissingDestinationConnectionID()) {
    return;
  }
  if (!HandleWriteBlocked()) {
    OnCanWrite();
  }
}

void QuicConnection::MaybeClearQueuedPacketsOnPathChange() {
  if (version().HasIetfQuicFrames() && peer_issued_cid_manager_ != nullptr &&
      HasQueuedPackets()) {
    // Discard packets serialized with the connection ID on the old code path.
    // It is possible to clear queued packets only if connection ID changes.
    // However, the case where connection ID is unchanged and queued packets are
    // non-empty is quite rare.
    ClearQueuedPackets();
  }
}

void QuicConnection::ReplaceInitialServerConnectionId(
    const QuicConnectionId& new_server_connection_id) {
  QUICHE_DCHECK(perspective_ == Perspective::IS_CLIENT);
  if (version().HasIetfQuicFrames()) {
    if (new_server_connection_id.IsEmpty()) {
      peer_issued_cid_manager_ = nullptr;
    } else {
      if (peer_issued_cid_manager_ != nullptr) {
        QUIC_BUG_IF(quic_bug_12714_22,
                    !peer_issued_cid_manager_->IsConnectionIdActive(
                        default_path_.server_connection_id))
            << "Connection ID replaced header is no longer active. old id: "
            << default_path_.server_connection_id
            << " new_id: " << new_server_connection_id;
        peer_issued_cid_manager_->ReplaceConnectionId(
            default_path_.server_connection_id, new_server_connection_id);
      } else {
        peer_issued_cid_manager_ =
            std::make_unique<QuicPeerIssuedConnectionIdManager>(
                kMinNumOfActiveConnectionIds, new_server_connection_id, clock_,
                alarm_factory_, this, context());
      }
    }
  }
  default_path_.server_connection_id = new_server_connection_id;
  packet_creator_.SetServerConnectionId(default_path_.server_connection_id);
}

void QuicConnection::FindMatchingOrNewClientConnectionIdOrToken(
    const PathState& default_path, const PathState& alternative_path,
    const QuicConnectionId& server_connection_id,
    QuicConnectionId* client_connection_id,
    std::optional<StatelessResetToken>* stateless_reset_token) {
  QUICHE_DCHECK(perspective_ == Perspective::IS_SERVER &&
                version().HasIetfQuicFrames());
  if (peer_issued_cid_manager_ == nullptr ||
      server_connection_id == default_path.server_connection_id) {
    *client_connection_id = default_path.client_connection_id;
    *stateless_reset_token = default_path.stateless_reset_token;
    return;
  }
  if (server_connection_id == alternative_path_.server_connection_id) {
    *client_connection_id = alternative_path.client_connection_id;
    *stateless_reset_token = alternative_path.stateless_reset_token;
    return;
  }
  auto* connection_id_data =
      peer_issued_cid_manager_->ConsumeOneUnusedConnectionId();
  if (connection_id_data == nullptr) {
    return;
  }
  *client_connection_id = connection_id_data->connection_id;
  *stateless_reset_token = connection_id_data->stateless_reset_token;
}

bool QuicConnection::FindOnPathConnectionIds(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    QuicConnectionId* client_connection_id,
    QuicConnectionId* server_connection_id) const {
  if (IsDefaultPath(self_address, peer_address)) {
    *client_connection_id = default_path_.client_connection_id,
    *server_connection_id = default_path_.server_connection_id;
    return true;
  }
  if (IsAlternativePath(self_address, peer_address)) {
    *client_connection_id = alternative_path_.client_connection_id,
    *server_connection_id = alternative_path_.server_connection_id;
    return true;
  }
  // Client should only send packets on either default or alternative path, so
  // it shouldn't fail here. If the server fail to find CID to use, no packet
  // will be generated on this path.
  // TODO(danzh) fix SendPathResponse() to respond to probes from a different
  // client port with non-Zero client CID.
  QUIC_BUG_IF(failed to find on path connection ids,
              perspective_ == Perspective::IS_CLIENT)
      << "Fails to find on path connection IDs";
  return false;
}

void QuicConnection::SetDefaultPathState(PathState new_path_state) {
  QUICHE_DCHECK(version().HasIetfQuicFrames());
  default_path_ = std::move(new_path_state);
  packet_creator_.SetClientConnectionId(default_path_.client_connection_id);
  packet_creator_.SetServerConnectionId(default_path_.server_connection_id);
}

// TODO(wub): Inline this function when deprecating
// --quic_test_peer_addr_change_after_normalize.
bool QuicConnection::PeerAddressChanged() const {
  if (quic_test_peer_addr_change_after_normalize_) {
    return direct_peer_address_.Normalized() !=
           last_received_packet_info_.source_address.Normalized();
  }

  return direct_peer_address_ != last_received_packet_info_.source_address;
}

void QuicConnection::GenerateNewOutgoingFlowLabel() {
  uint32_t flow_label;
  random_generator_->RandBytes(&flow_label, sizeof(flow_label));
  set_outgoing_flow_label(flow_label);
}

bool QuicConnection::ProcessValidatedPacket(const QuicPacketHeader& header) {
  if (perspective_ == Perspective::IS_CLIENT && version().HasIetfQuicFrames() &&
      direct_peer_address_.IsInitialized() &&
      last_received_packet_info_.source_address.IsInitialized() &&
      PeerAddressChanged() &&
      !IsKnownServerAddress(last_received_packet_info_.source_address)) {
    // Discard packets received from unseen server addresses.
    return false;
  }

  if (perspective_ == Perspective::IS_SERVER &&
      default_path_.self_address.IsInitialized() &&
      last_received_packet_info_.destination_address.IsInitialized() &&
      default_path_.self_address !=
          last_received_packet_info_.destination_address) {
    // Allow change between pure IPv4 and equivalent mapped IPv4 address.
    if (default_path_.self_address.port() !=
            last_received_packet_info_.destination_address.port() ||
        default_path_.self_address.host().Normalized() !=
            last_received_packet_info_.destination_address.host()
                .Normalized()) {
      if (!visitor_->AllowSelfAddressChange()) {
        const std::string error_details = absl::StrCat(
            "Self address migration is not supported at the server, current "
            "address: ",
            default_path_.self_address.ToString(),
            ", expected server preferred address: ",
            expected_server_preferred_address_.ToString(),
            ", received packet address: ",
            last_received_packet_info_.destination_address.ToString(),
            ", size: ", last_received_packet_info_.length,
            ", packet number: ", header.packet_number.ToString(),
            ", encryption level: ",
            EncryptionLevelToString(
                last_received_packet_info_.decrypted_level));
        QUIC_LOG_EVERY_N_SEC(INFO, 100) << error_details;
        QUIC_CODE_COUNT(quic_dropped_packets_with_changed_server_address);
        return false;
      }
    }
    default_path_.self_address = last_received_packet_info_.destination_address;
  }

  if (GetQuicReloadableFlag(quic_use_received_client_addresses_cache) &&
      perspective_ == Perspective::IS_SERVER &&
      !last_received_packet_info_.actual_destination_address.IsInitialized() &&
      last_received_packet_info_.source_address.IsInitialized()) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_use_received_client_addresses_cache);
    // Record client address of packets received on server original address.
    received_client_addresses_cache_.Insert(
        last_received_packet_info_.source_address,
        std::make_unique<bool>(true));
  }

  if (perspective_ == Perspective::IS_SERVER &&
      last_received_packet_info_.actual_destination_address.IsInitialized() &&
      !IsHandshakeConfirmed() &&
      GetEffectivePeerAddressFromCurrentPacket() !=
          default_path_.peer_address) {
    // Our client implementation has an optimization to spray packets from
    // different sockets to the server's preferred address before handshake
    // gets confirmed. In this case, do not kick off client address migration
    // detection.
    QUICHE_DCHECK(expected_server_preferred_address_.IsInitialized());
    last_received_packet_info_.source_address = direct_peer_address_;
  }

  if (PacketCanReplaceServerConnectionId(header, perspective_) &&
      default_path_.server_connection_id != header.source_connection_id) {
    QUICHE_DCHECK_EQ(header.long_packet_type, INITIAL);
    if (server_connection_id_replaced_by_initial_) {
      QUIC_DLOG(ERROR) << ENDPOINT << "Refusing to replace connection ID "
                       << default_path_.server_connection_id << " with "
                       << header.source_connection_id;
      return false;
    }
    server_connection_id_replaced_by_initial_ = true;
    QUIC_DLOG(INFO) << ENDPOINT << "Replacing connection ID "
                    << default_path_.server_connection_id << " with "
                    << header.source_connection_id;
    if (!original_destination_connection_id_.has_value()) {
      original_destination_connection_id_ = default_path_.server_connection_id;
    }
    ReplaceInitialServerConnectionId(header.source_connection_id);
  }

  if (!ValidateReceivedPacketNumber(header.packet_number)) {
    return false;
  }

  if (!version_negotiated_) {
    if (perspective_ == Perspective::IS_CLIENT) {
      QUICHE_DCHECK(!header.version_flag || header.form != GOOGLE_QUIC_PACKET);
      version_negotiated_ = true;
      OnSuccessfulVersionNegotiation();
    }
  }

  if (last_received_packet_info_.length > largest_received_packet_size_) {
    largest_received_packet_size_ = last_received_packet_info_.length;
  }

  if (perspective_ == Perspective::IS_SERVER &&
      encryption_level_ == ENCRYPTION_INITIAL &&
      last_received_packet_info_.length > packet_creator_.max_packet_length()) {
    if (GetQuicFlag(quic_use_lower_server_response_mtu_for_test)) {
      SetMaxPacketLength(
          std::min(last_received_packet_info_.length, QuicByteCount(1250)));
    } else {
      SetMaxPacketLength(last_received_packet_info_.length);
    }
  }
  return true;
}

bool QuicConnection::ValidateReceivedPacketNumber(
    QuicPacketNumber packet_number) {
  // If this packet has already been seen, or the sender has told us that it
  // will not be retransmitted, then stop processing the packet.
  if (!uber_received_packet_manager_.IsAwaitingPacket(
          last_received_packet_info_.decrypted_level, packet_number)) {
    QUIC_DLOG(INFO) << ENDPOINT << "Packet " << packet_number
                    << " no longer being waited for at level "
                    << static_cast<int>(
                           last_received_packet_info_.decrypted_level)
                    << ".  Discarding.";
    if (debug_visitor_ != nullptr) {
      debug_visitor_->OnDuplicatePacket(packet_number);
    }
    return false;
  }

  return true;
}

void QuicConnection::WriteQueuedPackets() {
  QUICHE_DCHECK(!writer_->IsWriteBlocked());
  QUIC_CLIENT_HISTOGRAM_COUNTS("QuicSession.NumQueuedPacketsBeforeWrite",
                               buffered_packets_.size(), 1, 1000, 50, "");

  while (!buffered_packets_.empty()) {
    if (HandleWriteBlocked()) {
      break;
    }
    const BufferedPacket& packet = buffered_packets_.front();
    WriteResult result = SendPacketToWriter(
        packet.data.get(), packet.length, packet.self_address.host(),
        packet.peer_address, writer_, packet.ecn_codepoint, packet.flow_label);
    QUIC_DVLOG(1) << ENDPOINT << "Sending buffered packet, result: " << result;
    if (IsMsgTooBig(writer_, result) && packet.length > long_term_mtu_) {
      // When MSG_TOO_BIG is returned, the system typically knows what the
      // actual MTU is, so there is no need to probe further.
      // TODO(wub): Reduce max packet size to a safe default, or the actual MTU.
      mtu_discoverer_.Disable();
      mtu_discovery_alarm().Cancel();
      buffered_packets_.pop_front();
      continue;
    }
    if (IsWriteError(result.status)) {
      OnWriteError(result.error_code);
      break;
    }
    if (result.status == WRITE_STATUS_OK ||
        result.status == WRITE_STATUS_BLOCKED_DATA_BUFFERED) {
      buffered_packets_.pop_front();
    }
    if (IsWriteBlockedStatus(result.status)) {
      visitor_->OnWriteBlocked();
      break;
    }
  }
}

void QuicConnection::MarkZeroRttPacketsForRetransmission(int reject_reason) {
  sent_packet_manager_.MarkZeroRttPacketsForRetransmission();
  if (debug_visitor_ != nullptr && version().UsesTls()) {
    debug_visitor_->OnZeroRttRejected(reject_reason);
  }
}

void QuicConnection::NeuterUnencryptedPackets() {
  sent_packet_manager_.NeuterUnencryptedPackets();
  // This may have changed the retransmission timer, so re-arm it.
  SetRetransmissionAlarm();
  if (default_enable_5rto_blackhole_detection_) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_default_enable_5rto_blackhole_detection2,
                                 1, 3);
    // Consider this as forward progress since this is called when initial key
    // gets discarded (or previous unencrypted data is not needed anymore).
    OnForwardProgressMade();
  }
  if (SupportsMultiplePacketNumberSpaces()) {
    // Stop sending ack of initial packet number space.
    uber_received_packet_manager_.ResetAckStates(ENCRYPTION_INITIAL);
    // Re-arm ack alarm.
    ack_alarm().Update(uber_received_packet_manager_.GetEarliestAckTimeout(),
                       kAlarmGranularity);
  }
}

bool QuicConnection::IsMissingDestinationConnectionID() const {
  return peer_issued_cid_manager_ != nullptr &&
         packet_creator_.GetDestinationConnectionId().IsEmpty();
}

bool QuicConnection::ShouldGeneratePacket(
    HasRetransmittableData retransmittable, IsHandshake handshake) {
  QUICHE_DCHECK(handshake != IS_HANDSHAKE ||
                QuicVersionUsesCryptoFrames(transport_version()))
      << ENDPOINT
      << "Handshake in STREAM frames should not check ShouldGeneratePacket";
  if (IsMissingDestinationConnectionID()) {
    QUICHE_DCHECK(version().HasIetfQuicFrames());
    QUIC_CODE_COUNT(quic_generate_packet_blocked_by_no_connection_id);
    QUIC_BUG_IF(quic_bug_90265_1, perspective_ == Perspective::IS_CLIENT);
    QUIC_DLOG(INFO) << ENDPOINT
                    << "There is no destination connection ID available to "
                       "generate packet.";
    return false;
  }
  if (IsDefaultPath(default_path_.self_address,
                    packet_creator_.peer_address())) {
    return CanWrite(retransmittable);
  }
  // This is checking on the alternative path with a different peer address. The
  // self address and the writer used are the same as the default path. In the
  // case of different self address and writer, writing packet would use a
  // differnt code path without checking the states of the default writer.
  return connected_ && !HandleWriteBlocked();
}

void QuicConnection::MaybeBundleOpportunistically(
    TransmissionType transmission_type) {
  const bool should_bundle_ack_frequency =
      !ack_frequency_sent_ && sent_packet_manager_.CanSendAckFrequency() &&
      transmission_type == NOT_RETRANSMISSION &&
      packet_creator_.NextSendingPacketNumber() >=
          FirstSendingPacketNumber() + kMinReceivedBeforeAckDecimation;

  if (should_bundle_ack_frequency) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_can_send_ack_frequency, 3, 3);
    ack_frequency_sent_ = true;
    auto frame = sent_packet_manager_.GetUpdatedAckFrequencyFrame();
    visitor_->SendAckFrequency(frame);
  }

  if (transmission_type == NOT_RETRANSMISSION) {
    visitor_->MaybeBundleOpportunistically();
  }

  if (packet_creator_.has_ack() || !CanWrite(NO_RETRANSMITTABLE_DATA)) {
    return;
  }

  QuicFrames frames;
  const bool has_pending_ack =
      uber_received_packet_manager_
          .GetAckTimeout(QuicUtils::GetPacketNumberSpace(encryption_level_))
          .IsInitialized();
  if (!has_pending_ack) {
    // No need to send an ACK.
    return;
  }
  ResetAckStates();

  QUIC_DVLOG(1) << ENDPOINT << "Bundle an ACK opportunistically";
  QuicFrame updated_ack_frame = GetUpdatedAckFrame();
  QUIC_BUG_IF(quic_bug_12714_23, updated_ack_frame.ack_frame->packets.Empty())
      << ENDPOINT << "Attempted to opportunistically bundle an empty "
      << encryption_level_ << " ACK, " << (has_pending_ack ? "" : "!")
      << "has_pending_ack";
  frames.push_back(updated_ack_frame);

  const bool flushed = packet_creator_.FlushAckFrame(frames);
  QUIC_BUG_IF(failed_to_flush_ack, !flushed)
      << ENDPOINT << "Failed to flush ACK frame";
}

bool QuicConnection::CanWrite(HasRetransmittableData retransmittable) {
  if (!connected_) {
    return false;
  }

  if (IsMissingDestinationConnectionID()) {
    return false;
  }

  if (version().CanSendCoalescedPackets() &&
      framer_.HasEncrypterOfEncryptionLevel(ENCRYPTION_INITIAL) &&
      framer_.is_processing_packet()) {
    // While we still have initial keys, suppress sending in mid of packet
    // processing.
    // TODO(fayang): always suppress sending while in the mid of packet
    // processing.
    QUIC_DVLOG(1) << ENDPOINT
                  << "Suppress sending in the mid of packet processing";
    return false;
  }

  if (fill_coalesced_packet_) {
    // Try to coalesce packet, only allow to write when creator is on soft max
    // packet length. Given the next created packet is going to fill current
    // coalesced packet, do not check amplification factor.
    return packet_creator_.HasSoftMaxPacketLength();
  }

  if (sent_packet_manager_.pending_timer_transmission_count() > 0) {
    // Allow sending if there are pending tokens, which occurs when:
    // 1) firing PTO,
    // 2) bundling CRYPTO data with ACKs,
    // 3) coalescing CRYPTO data of higher space.
    return true;
  }

  if (LimitedByAmplificationFactor(packet_creator_.max_packet_length())) {
    // Server is constrained by the amplification restriction.
    QUIC_CODE_COUNT(quic_throttled_by_amplification_limit);
    QUIC_DVLOG(1) << ENDPOINT
                  << "Constrained by amplification restriction to peer address "
                  << default_path_.peer_address << " bytes received "
                  << default_path_.bytes_received_before_address_validation
                  << ", bytes sent"
                  << default_path_.bytes_sent_before_address_validation;
    ++stats_.num_amplification_throttling;
    return false;
  }

  if (HandleWriteBlocked()) {
    return false;
  }

  // Allow acks and probing frames to be sent immediately.
  if (retransmittable == NO_RETRANSMITTABLE_DATA) {
    return true;
  }
  // If the send alarm is set, wait for it to fire.
  if (send_alarm().IsSet()) {
    return false;
  }

  QuicTime now = clock_->Now();
  QuicTime::Delta delay = sent_packet_manager_.TimeUntilSend(now);
  if (delay.IsInfinite()) {
    send_alarm().Cancel();
    return false;
  }

  // Scheduler requires a delay.
  if (!delay.IsZero()) {
    if (delay <= release_time_into_future_) {
      // Required delay is within pace time into future, send now.
      return true;
    }
    // Cannot send packet now because delay is too far in the future.
    send_alarm().Update(now + delay, kAlarmGranularity);
    QUIC_DVLOG(1) << ENDPOINT << "Delaying sending " << delay.ToMilliseconds()
                  << "ms";
    return false;
  }

  return true;
}

QuicTime QuicConnection::CalculatePacketSentTime() {
  const QuicTime now = clock_->Now();
  if (!supports_release_time_) {
    // Don't change the release delay.
    return now;
  }

  auto next_release_time_result = sent_packet_manager_.GetNextReleaseTime();

  // Release before |now| is impossible.
  QuicTime next
"""


```
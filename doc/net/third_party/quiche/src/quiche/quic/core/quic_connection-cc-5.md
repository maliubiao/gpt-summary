Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's QUIC implementation. I need to identify the key actions and responsibilities of this part of the `QuicConnection` class. The request also asks for connections to Javascript (unlikely in this low-level networking code, but I'll keep an eye out), logical inference examples, common usage errors, and debugging hints.

Here's a plan:

1. **Identify the core purpose of each function.** I'll go through the methods in the snippet and briefly describe what they do.
2. **Look for relationships with Javascript.**  This will likely involve searching for concepts that might bridge the gap between C++ networking and browser-level Javascript (e.g., events, callbacks, handling of network events).
3. **Develop logical inference examples.** For functions that make decisions or calculations, I'll create simple input scenarios and predict the output.
4. **Identify potential user/programming errors.** I'll consider common mistakes when working with network connections, timers, packet handling, etc.
5. **Trace user actions to this code.** I'll think about how user interactions in a web browser could lead to the execution of these networking functions.
6. **Synthesize the overall functionality.** Based on the individual function summaries, I'll provide a concise description of what this part of the `QuicConnection` class does.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc` 文件的第 6 部分，主要涵盖了 `QuicConnection` 类中处理连接生命周期、数据发送、拥塞控制、加密以及错误处理等关键功能的代码片段。以下是该部分代码的功能归纳：

**主要功能归纳：**

* **处理服务器首选地址:**  `OnServerPreferredAddressAvailable` 函数接收并处理服务器发送的首选地址信息，这通常发生在连接建立初期，客户端可以尝试连接到该地址以优化连接。
* **管理多端口路径:** `MaybeCreateMultiPortPath` 函数负责在客户端决定是否以及何时创建用于多端口通信的新路径。它会检查是否允许主动迁移、是否存在待处理的路径验证以及是否已达到最大多端口路径数量。
* **发送和排队数据包:** `SendOrQueuePacket` 函数用于发送数据包，调用者需要确保连接处于可写状态。
* **处理 ACK 报警:** `OnAckAlarm` 函数在 ACK 计时器到期时被调用，负责发送待处理的 ACK 帧。根据是否支持多包编号空间，会调用 `SendAllPendingAcks` 或 `SendAck`。
* **发送 ACK 帧:** `SendAck` 函数构建并发送 ACK 帧，并根据情况决定是否需要与可重传帧捆绑发送，或者通知 `visitor_` 需要发送可重传帧。
* **确定发送 PING 的加密级别:** `GetEncryptionLevelToSendPingForSpace` 函数根据指定的包编号空间确定发送 PING 帧所需的加密级别。
* **检查已知的服务器地址:** `IsKnownServerAddress` 函数用于判断给定的地址是否是已知的服务器地址。
* **获取要发送的 ECN 代码点:** `GetEcnCodepointToSend` 函数根据目标地址和当前状态（例如，是否处于 PTO 状态）决定是否以及如何标记 ECN (Explicit Congestion Notification)。
* **通过 Writer 发送数据包:** `SendPacketToWriter` 函数将数据包传递给底层的 `QuicPacketWriter` 进行实际发送，并设置 ECN 代码点和流标签。
* **处理重传报警:** `OnRetransmissionAlarm` 函数在重传计时器到期时被调用。它会触发数据包的重传，并根据 PTO (Probe Timeout) 模式可能跳过包编号，或者在黑洞检测期间停止检测。如果此时没有数据要发送，可能会发送 PING 包。
* **设置和移除加密器:** `SetEncrypter` 和 `RemoveEncrypter` 函数用于设置和移除用于数据包加密的 `QuicEncrypter` 对象。
* **设置多样化 Nonce:** `SetDiversificationNonce` 函数（仅用于服务器端）用于设置数据包创建器使用的多样化 nonce。
* **设置默认加密级别:** `SetDefaultEncryptionLevel` 函数设置连接的默认加密级别，并在加密级别改变时刷新待处理的帧。
* **设置、安装和移除解密器:** `SetDecrypter`, `SetAlternativeDecrypter`, `InstallDecrypter`, 和 `RemoveDecrypter` 函数用于管理不同加密级别的 `QuicDecrypter` 对象，用于解密接收到的数据包。
* **处理过期的旧密钥报警:** `OnDiscardPreviousOneRttKeysAlarm` 函数在计时器到期时被调用，用于丢弃旧的 1-RTT 加密密钥。
* **管理密钥更新:**  `IsKeyUpdateAllowed`, `HaveSentPacketsInCurrentKeyPhaseButNoneAcked`, `PotentialPeerKeyUpdateAttemptCount`, 和 `InitiateKeyUpdate` 函数用于检查是否允许密钥更新、跟踪密钥更新尝试以及发起密钥更新过程。
* **获取当前解密器:** `decrypter` 和 `alternative_decrypter` 方法返回当前使用的解密器。
* **排队无法解密的包:** `QueueUndecryptablePacket` 函数用于存储暂时无法解密的接收到的数据包。
* **处理无法解密的包报警:** `OnProcessUndecryptablePacketsAlarm` 函数在计时器到期时被调用，尝试重新处理之前无法解密的包。
* **尝试处理无法解密的包:** `MaybeProcessUndecryptablePackets` 函数遍历并尝试解密之前排队的无法解密的包，并在成功解密后将其移除。
* **排队合并的包:** `QueueCoalescedPacket` 函数用于存储接收到的合并数据包。
* **尝试处理合并的包:** `MaybeProcessCoalescedPackets` 函数遍历并尝试处理接收到的合并数据包。
* **关闭连接:** `CloseConnection` 函数用于关闭连接，可以指定错误码和详细信息，并选择是否发送连接关闭数据包。
* **发送连接关闭包:** `SendConnectionClosePacket` 函数构建并发送连接关闭数据包。
* **清理本地连接状态:** `TearDownLocalConnectionState` 函数执行本地连接状态的清理工作，包括取消报警和通知 `visitor_` 连接已关闭。
* **取消所有报警:** `CancelAllAlarms` 函数取消所有与连接相关的计时器报警。
* **获取和设置最大数据包长度:** `max_packet_length` 和 `SetMaxPacketLength` 函数用于获取和设置连接允许的最大数据包长度。
* **检查是否有排队的数据:** `HasQueuedData` 函数检查是否有待发送的数据包或帧。
* **设置网络超时:** `SetNetworkTimeouts` 函数设置握手超时和空闲超时时间。
* **设置 PING 报警:** `SetPingAlarm` 函数设置 PING 帧的发送报警。
* **设置重传报警:** `SetRetransmissionAlarm` 函数设置重传计时器，用于在数据包丢失或超时时触发重传。
* **可能设置 MTU 探测报警:** `MaybeSetMtuAlarm` 函数根据条件设置 MTU (Maximum Transmission Unit) 探测报警。
* **ScopedPacketFlusher 类:**  这是一个辅助类，用于在特定作用域内确保数据包被刷新发送，并管理 ACK 报警的设置。

**与 Javascript 的关系：**

这段 C++ 代码是 Chromium 网络栈的核心部分，直接处理底层的 QUIC 协议实现。它本身不直接与 Javascript 代码交互。但是，它的功能为 Javascript 提供了网络传输的基础。

**举例说明:**

当用户在浏览器中通过 HTTPS 访问一个使用 QUIC 协议的网站时，Javascript 代码（例如，通过 `fetch` API）会发起网络请求。这个请求最终会传递到 Chromium 的网络栈，而 `QuicConnection` 类（包括这段代码）就负责处理 QUIC 连接的建立、数据包的发送和接收等底层操作。

1. **用户操作:** 用户在浏览器地址栏输入一个 HTTPS 地址并回车。
2. **Javascript 层面:**  浏览器中的渲染进程会通过 `fetch` 或类似 API 发起一个网络请求。
3. **C++ 网络栈层面:**  这个请求会被传递到网络栈，其中 `QuicConnection` 类的实例会负责与服务器建立 QUIC 连接。
4. **`OnServerPreferredAddressAvailable`:** 如果服务器发送了首选地址，这段代码会被调用来处理该地址，客户端可能会尝试连接到这个新的地址。
5. **数据发送:** 当 Javascript 需要发送数据（例如，HTTP 请求体），`SendOrQueuePacket` 会被调用来发送包含这些数据的 QUIC 数据包。
6. **ACK 处理:** 当收到服务器的确认包时，会影响本地的 ACK 状态，并可能触发 `OnAckAlarm` 来发送客户端的 ACK。
7. **重传处理:** 如果客户端发送的数据包丢失或超时，`OnRetransmissionAlarm` 会被触发，导致丢失的数据包被重新发送。

**逻辑推理举例说明：**

**假设输入:**

* `MaybeCreateMultiPortPath` 被调用。
* `active_migration_disabled_` 为 `false` (服务器允许主动迁移)。
* `path_validator_.HasPendingPathValidation()` 为 `false` (没有待处理的路径验证)。
* `multi_port_stats_->num_multi_port_paths_created` 小于 `kMaxNumMultiPortPaths`。

**输出:**

* `visitor_->CreateContextForMultiPortPath(std::move(context_observer))` 将会被调用，指示创建一个新的多端口路径。

**假设输入:**

* `OnRetransmissionAlarm` 被调用。
* `sent_packet_manager_.OnRetransmissionTimeout()` 返回 `QuicSentPacketManager::PTO_MODE`。
* `enable_black_hole_avoidance_via_flow_label_` 为 `true`。

**输出:**

* `packet_creator_.SkipNPacketNumbers(1, ...)` 将会被调用，跳过一个包编号。
* `GenerateNewOutgoingFlowLabel()` 将会被调用，生成新的流标签。
* `stats_.num_flow_label_changes` 会增加。
* `flow_label_has_changed_` 和 `expect_peer_flow_label_change_` 会被设置为 `true`。

**用户或编程常见的使用错误举例说明：**

* **未检查 `CanWrite()` 就调用 `SendOrQueuePacket()`:**  这会导致尝试在连接不可写时发送数据包，可能会导致数据丢失或程序崩溃。
    * **用户操作:**  这通常不是直接由用户操作触发的错误，而是编程错误。
    * **调试线索:** 如果在发送数据包时程序出现异常或数据发送失败，检查调用 `SendOrQueuePacket()` 之前是否正确检查了 `CanWrite()`。
* **在连接关闭后尝试发送数据:**  如果在连接已经关闭的情况下仍然尝试调用发送数据的相关函数，会导致未定义的行为。
    * **用户操作:** 用户可能在网络环境不稳定的情况下操作，导致连接意外关闭，而应用程序没有正确处理连接状态。
    * **调试线索:** 检查连接状态 (`connected()`) 在发送数据之前是否为 true。
* **错误地管理加密密钥:**  例如，过早地丢弃或未能正确安装解密器，会导致接收到的数据包无法解密。
    * **用户操作:** 这通常是协议实现或配置错误，用户无法直接触发。
    * **调试线索:** 检查加密器和解密器的安装和移除时机，以及密钥协商过程是否正确。查看 `QueueUndecryptablePacket` 和 `MaybeProcessUndecryptablePackets` 的执行情况。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个使用了 QUIC 协议的网站。** 浏览器会尝试与服务器建立 QUIC 连接。
2. **连接建立过程中，服务器可能会发送首选地址。**  这会触发 `OnServerPreferredAddressAvailable` 函数。
3. **如果客户端决定尝试使用多端口连接，并且满足条件，** `MaybeCreateMultiPortPath` 函数会被调用。
4. **当应用程序需要发送数据时（例如，HTTP 请求），** `SendOrQueuePacket` 函数会被调用来发送数据包。
5. **接收到数据包后，可能需要发送 ACK。**  如果一段时间没有发送其他数据，`OnAckAlarm` 会被触发。
6. **如果网络出现拥塞或数据包丢失，**  `OnRetransmissionAlarm` 会被触发来重传数据包。
7. **如果加密级别发生变化（例如，从握手加密到完全加密），** `SetDefaultEncryptionLevel`、`SetEncrypter`、`SetDecrypter` 等函数会被调用。
8. **如果接收到的数据包无法立即解密，** `QueueUndecryptablePacket` 会被调用，稍后 `OnProcessUndecryptablePacketsAlarm` 和 `MaybeProcessUndecryptablePackets` 会尝试解密。
9. **如果连接出现错误或需要关闭，** `CloseConnection` 函数会被调用。

**调试线索:**

* **查看日志:**  Chromium 的网络栈通常会有详细的日志输出，可以查看与 QUIC 连接相关的日志信息，例如连接状态变化、数据包发送和接收、报警触发等。
* **使用网络抓包工具:**  例如 Wireshark，可以捕获网络数据包，分析 QUIC 协议的交互过程，查看数据包的内容、类型、时间戳等信息。
* **断点调试:**  在相关的函数入口处设置断点，例如 `OnServerPreferredAddressAvailable`、`SendOrQueuePacket`、`OnRetransmissionAlarm` 等，可以单步执行代码，查看变量的值和程序执行流程。
* **检查连接状态:**  在关键代码路径上检查 `connected()` 的返回值，确保在执行操作时连接处于期望的状态。
* **分析报警状态:**  检查各种报警是否被正确设置和取消，例如 `ack_alarm().IsSet()`、`retransmission_alarm().IsSet()`。
* **查看统计信息:**  `stats_` 成员变量包含了很多连接的统计信息，例如发送和接收的数据包数量、重传次数、丢包率等，可以帮助分析连接状态。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective_);
    visitor_->OnServerPreferredAddressAvailable(
        received_server_preferred_address_);
  }
}

void QuicConnection::MaybeCreateMultiPortPath() {
  QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective_);
  QUIC_CLIENT_HISTOGRAM_BOOL(
      "QuicConnection.ServerAllowsActiveMigrationForMultiPort",
      !active_migration_disabled_,
      "Whether the server allows active migration that's required for "
      "multi-port");
  if (active_migration_disabled_) {
    return;
  }
  if (path_validator_.HasPendingPathValidation()) {
    QUIC_CLIENT_HISTOGRAM_ENUM("QuicConnection.MultiPortPathCreationCancelled",
                               path_validator_.GetPathValidationReason(),
                               PathValidationReason::kMaxValue,
                               "Reason for cancelled multi port path creation");
    return;
  }
  if (multi_port_stats_->num_multi_port_paths_created >=
      kMaxNumMultiPortPaths) {
    return;
  }

  auto context_observer = std::make_unique<ContextObserver>(this);
  visitor_->CreateContextForMultiPortPath(std::move(context_observer));
}

void QuicConnection::SendOrQueuePacket(SerializedPacket packet) {
  // The caller of this function is responsible for checking CanWrite().
  WritePacket(&packet);
}

void QuicConnection::OnAckAlarm() {
  QUICHE_DCHECK(ack_frame_updated());
  QUICHE_DCHECK(connected());
  QuicConnection::ScopedPacketFlusher flusher(this);
  if (SupportsMultiplePacketNumberSpaces()) {
    SendAllPendingAcks();
  } else {
    SendAck();
  }
}

void QuicConnection::SendAck() {
  QUICHE_DCHECK(!SupportsMultiplePacketNumberSpaces());
  QUIC_DVLOG(1) << ENDPOINT << "Sending an ACK proactively";
  QuicFrames frames;
  frames.push_back(GetUpdatedAckFrame());
  if (!packet_creator_.FlushAckFrame(frames)) {
    return;
  }
  ResetAckStates();
  if (!ShouldBundleRetransmittableFrameWithAck()) {
    return;
  }
  consecutive_num_packets_with_no_retransmittable_frames_ = 0;
  if (packet_creator_.HasPendingRetransmittableFrames() ||
      visitor_->WillingAndAbleToWrite()) {
    // There are pending retransmittable frames.
    return;
  }

  visitor_->OnAckNeedsRetransmittableFrame();
}

EncryptionLevel QuicConnection::GetEncryptionLevelToSendPingForSpace(
    PacketNumberSpace space) const {
  switch (space) {
    case INITIAL_DATA:
      return ENCRYPTION_INITIAL;
    case HANDSHAKE_DATA:
      return ENCRYPTION_HANDSHAKE;
    case APPLICATION_DATA:
      return framer_.GetEncryptionLevelToSendApplicationData();
    default:
      QUICHE_DCHECK(false);
      return NUM_ENCRYPTION_LEVELS;
  }
}

bool QuicConnection::IsKnownServerAddress(
    const QuicSocketAddress& address) const {
  QUICHE_DCHECK(address.IsInitialized());
  return std::find(known_server_addresses_.cbegin(),
                   known_server_addresses_.cend(),
                   address) != known_server_addresses_.cend();
}

QuicEcnCodepoint QuicConnection::GetEcnCodepointToSend(
    const QuicSocketAddress& destination_address) const {
  // Don't send ECN marks on alternate paths. Sending ECN marks might
  // cause the connectivity check to fail on some networks.
  if (destination_address != peer_address()) {
    return ECN_NOT_ECT;
  }
  // If the path might drop ECN marked packets, send retransmission without
  // them.
  if (in_probe_time_out_ && !default_path_.ecn_marked_packet_acked) {
    return ECN_NOT_ECT;
  }
  return packet_writer_params_.ecn_codepoint;
}

WriteResult QuicConnection::SendPacketToWriter(
    const char* buffer, size_t buf_len, const QuicIpAddress& self_address,
    const QuicSocketAddress& destination_address, QuicPacketWriter* writer,
    const QuicEcnCodepoint ecn_codepoint, uint32_t flow_label) {
  QuicPacketWriterParams params = packet_writer_params_;
  params.ecn_codepoint = ecn_codepoint;
  last_ecn_codepoint_sent_ = ecn_codepoint;
  last_flow_label_sent_ = flow_label;
  params.flow_label = flow_label;
  WriteResult result =
      writer->WritePacket(buffer, buf_len, self_address, destination_address,
                          per_packet_options_, params);
  return result;
}

void QuicConnection::OnRetransmissionAlarm() {
  QUICHE_DCHECK(connected());
  ScopedRetransmissionTimeoutIndicator indicator(this);
#ifndef NDEBUG
  if (sent_packet_manager_.unacked_packets().empty()) {
    QUICHE_DCHECK(sent_packet_manager_.handshake_mode_disabled());
    QUICHE_DCHECK(!IsHandshakeConfirmed());
  }
#endif
  if (!connected_) {
    return;
  }

  QuicPacketNumber previous_created_packet_number =
      packet_creator_.packet_number();
  const auto retransmission_mode =
      sent_packet_manager_.OnRetransmissionTimeout();
  if (retransmission_mode == QuicSentPacketManager::PTO_MODE) {
    // Skip a packet number when PTO fires to elicit an immediate ACK.
    const QuicPacketCount num_packet_numbers_to_skip = 1;
    packet_creator_.SkipNPacketNumbers(
        num_packet_numbers_to_skip,
        sent_packet_manager_.GetLeastPacketAwaitedByPeer(encryption_level_),
        sent_packet_manager_.EstimateMaxPacketsInFlight(max_packet_length()));
    previous_created_packet_number += num_packet_numbers_to_skip;
    if (debug_visitor_ != nullptr) {
      debug_visitor_->OnNPacketNumbersSkipped(num_packet_numbers_to_skip,
                                              clock_->Now());
    }
    if (enable_black_hole_avoidance_via_flow_label_) {
      GenerateNewOutgoingFlowLabel();
      ++stats_.num_flow_label_changes;
      flow_label_has_changed_ = true;
      expect_peer_flow_label_change_ = true;
      QUIC_CODE_COUNT(quic_generated_new_flow_label_on_pto);
    }
  }
  if (default_enable_5rto_blackhole_detection_ &&
      !sent_packet_manager_.HasInFlightPackets() &&
      blackhole_detector_.IsDetectionInProgress()) {
    // Stop detection in quiescence.
    QUICHE_DCHECK_EQ(QuicSentPacketManager::LOSS_MODE, retransmission_mode);
    blackhole_detector_.StopDetection(/*permanent=*/false);
  }
  WriteIfNotBlocked();

  // A write failure can result in the connection being closed, don't attempt to
  // write further packets, or to set alarms.
  if (!connected_) {
    return;
  }
  // When PTO fires, the SentPacketManager gives the connection the opportunity
  // to send new data before retransmitting.
  sent_packet_manager_.MaybeSendProbePacket();

  if (packet_creator_.packet_number() == previous_created_packet_number &&
      retransmission_mode == QuicSentPacketManager::PTO_MODE &&
      !visitor_->WillingAndAbleToWrite()) {
    // Send PING if timer fires in PTO mode but there is no data to send.
    QUIC_DLOG(INFO) << ENDPOINT
                    << "No packet gets sent when timer fires in mode "
                    << retransmission_mode << ", send PING";
    QUICHE_DCHECK_LT(0u,
                     sent_packet_manager_.pending_timer_transmission_count());
    if (SupportsMultiplePacketNumberSpaces()) {
      // Based on https://datatracker.ietf.org/doc/html/rfc9002#appendix-A.9
      PacketNumberSpace packet_number_space;
      if (sent_packet_manager_
              .GetEarliestPacketSentTimeForPto(&packet_number_space)
              .IsInitialized()) {
        SendPingAtLevel(
            GetEncryptionLevelToSendPingForSpace(packet_number_space));
      } else {
        // The client must PTO when there is nothing in flight if the server
        // could be blocked from sending by the amplification limit
        QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective_);
        if (framer_.HasEncrypterOfEncryptionLevel(ENCRYPTION_HANDSHAKE)) {
          SendPingAtLevel(ENCRYPTION_HANDSHAKE);
        } else if (framer_.HasEncrypterOfEncryptionLevel(ENCRYPTION_INITIAL)) {
          SendPingAtLevel(ENCRYPTION_INITIAL);
        } else {
          QUIC_BUG(quic_bug_no_pto) << "PTO fired but nothing was sent.";
        }
      }
    } else {
      SendPingAtLevel(encryption_level_);
    }
  }
  if (retransmission_mode == QuicSentPacketManager::PTO_MODE) {
    // When timer fires in PTO mode, ensure 1) at least one packet is created,
    // or there is data to send and available credit (such that packets will be
    // sent eventually).
    QUIC_BUG_IF(
        quic_bug_12714_27,
        packet_creator_.packet_number() == previous_created_packet_number &&
            (!visitor_->WillingAndAbleToWrite() ||
             sent_packet_manager_.pending_timer_transmission_count() == 0u))
        << "retransmission_mode: " << retransmission_mode
        << ", packet_number: " << packet_creator_.packet_number()
        << ", session has data to write: " << visitor_->WillingAndAbleToWrite()
        << ", writer is blocked: " << writer_->IsWriteBlocked()
        << ", pending_timer_transmission_count: "
        << sent_packet_manager_.pending_timer_transmission_count();
  }

  // Ensure the retransmission alarm is always set if there are unacked packets
  // and nothing waiting to be sent.
  // This happens if the loss algorithm invokes a timer based loss, but the
  // packet doesn't need to be retransmitted.
  if (!HasQueuedData() && !retransmission_alarm().IsSet()) {
    SetRetransmissionAlarm();
  }
  if (packet_writer_params_.ecn_codepoint == ECN_NOT_ECT ||
      default_path_.ecn_marked_packet_acked) {
    return;
  }
  ++default_path_.ecn_pto_count;
  if (default_path_.ecn_pto_count == kEcnPtoLimit) {
    // Give up on ECN. There are two scenarios:
    // 1. All packets are suffering PTO. In this case, the connection
    // abandons ECN after 1 failed ECT(1) flight and one failed Not-ECT
    // flight.
    // 2. Only ECN packets are suffering PTO. In that case, alternating
    // flights will have ECT(1). On the second ECT(1) failure, the
    // connection will abandon.
    // This behavior is in the range of acceptable choices in S13.4.2 of RFC
    // 9000.
    QUIC_DVLOG(1) << ENDPOINT << "ECN packets PTO 3 times.";
    OnInvalidEcnFeedback();
  }
}

void QuicConnection::SetEncrypter(EncryptionLevel level,
                                  std::unique_ptr<QuicEncrypter> encrypter) {
  packet_creator_.SetEncrypter(level, std::move(encrypter));
}

void QuicConnection::RemoveEncrypter(EncryptionLevel level) {
  framer_.RemoveEncrypter(level);
}

void QuicConnection::SetDiversificationNonce(
    const DiversificationNonce& nonce) {
  QUICHE_DCHECK_EQ(Perspective::IS_SERVER, perspective_);
  packet_creator_.SetDiversificationNonce(nonce);
}

void QuicConnection::SetDefaultEncryptionLevel(EncryptionLevel level) {
  QUIC_DVLOG(1) << ENDPOINT << "Setting default encryption level from "
                << encryption_level_ << " to " << level;
  const bool changing_level = level != encryption_level_;
  if (changing_level && packet_creator_.HasPendingFrames()) {
    // Flush all queued frames when encryption level changes.
    ScopedPacketFlusher flusher(this);
    packet_creator_.FlushCurrentPacket();
  }
  encryption_level_ = level;
  packet_creator_.set_encryption_level(level);
  QUIC_BUG_IF(quic_bug_12714_28, !framer_.HasEncrypterOfEncryptionLevel(level))
      << ENDPOINT << "Trying to set encryption level to "
      << EncryptionLevelToString(level) << " while the key is missing";

  if (!changing_level) {
    return;
  }
  // The least packet awaited by the peer depends on the encryption level so
  // we recalculate it here.
  packet_creator_.UpdatePacketNumberLength(
      sent_packet_manager_.GetLeastPacketAwaitedByPeer(encryption_level_),
      sent_packet_manager_.EstimateMaxPacketsInFlight(max_packet_length()));
}

void QuicConnection::SetDecrypter(EncryptionLevel level,
                                  std::unique_ptr<QuicDecrypter> decrypter) {
  framer_.SetDecrypter(level, std::move(decrypter));

  if (!undecryptable_packets_.empty() &&
      !process_undecryptable_packets_alarm().IsSet()) {
    process_undecryptable_packets_alarm().Set(clock_->ApproximateNow());
  }
}

void QuicConnection::SetAlternativeDecrypter(
    EncryptionLevel level, std::unique_ptr<QuicDecrypter> decrypter,
    bool latch_once_used) {
  framer_.SetAlternativeDecrypter(level, std::move(decrypter), latch_once_used);

  if (!undecryptable_packets_.empty() &&
      !process_undecryptable_packets_alarm().IsSet()) {
    process_undecryptable_packets_alarm().Set(clock_->ApproximateNow());
  }
}

void QuicConnection::InstallDecrypter(
    EncryptionLevel level, std::unique_ptr<QuicDecrypter> decrypter) {
  if (level == ENCRYPTION_ZERO_RTT) {
    had_zero_rtt_decrypter_ = true;
  }
  framer_.InstallDecrypter(level, std::move(decrypter));
  if (!undecryptable_packets_.empty() &&
      !process_undecryptable_packets_alarm().IsSet()) {
    process_undecryptable_packets_alarm().Set(clock_->ApproximateNow());
  }
}

void QuicConnection::RemoveDecrypter(EncryptionLevel level) {
  framer_.RemoveDecrypter(level);
}

void QuicConnection::OnDiscardPreviousOneRttKeysAlarm() {
  QUICHE_DCHECK(connected());
  framer_.DiscardPreviousOneRttKeys();
}

bool QuicConnection::IsKeyUpdateAllowed() const {
  return support_key_update_for_connection_ &&
         GetLargestAckedPacket().IsInitialized() &&
         lowest_packet_sent_in_current_key_phase_.IsInitialized() &&
         GetLargestAckedPacket() >= lowest_packet_sent_in_current_key_phase_;
}

bool QuicConnection::HaveSentPacketsInCurrentKeyPhaseButNoneAcked() const {
  return lowest_packet_sent_in_current_key_phase_.IsInitialized() &&
         (!GetLargestAckedPacket().IsInitialized() ||
          GetLargestAckedPacket() < lowest_packet_sent_in_current_key_phase_);
}

QuicPacketCount QuicConnection::PotentialPeerKeyUpdateAttemptCount() const {
  return framer_.PotentialPeerKeyUpdateAttemptCount();
}

bool QuicConnection::InitiateKeyUpdate(KeyUpdateReason reason) {
  QUIC_DLOG(INFO) << ENDPOINT << "InitiateKeyUpdate";
  if (!IsKeyUpdateAllowed()) {
    QUIC_BUG(quic_bug_10511_28) << "key update not allowed";
    return false;
  }
  return framer_.DoKeyUpdate(reason);
}

const QuicDecrypter* QuicConnection::decrypter() const {
  return framer_.decrypter();
}

const QuicDecrypter* QuicConnection::alternative_decrypter() const {
  return framer_.alternative_decrypter();
}

void QuicConnection::QueueUndecryptablePacket(
    const QuicEncryptedPacket& packet, EncryptionLevel decryption_level) {
  for (const auto& saved_packet : undecryptable_packets_) {
    if (packet.data() == saved_packet.packet->data() &&
        packet.length() == saved_packet.packet->length()) {
      QUIC_DVLOG(1) << ENDPOINT << "Not queueing known undecryptable packet";
      return;
    }
  }
  QUIC_DVLOG(1) << ENDPOINT << "Queueing undecryptable packet.";
  undecryptable_packets_.emplace_back(packet, decryption_level,
                                      last_received_packet_info_);
  if (perspective_ == Perspective::IS_CLIENT) {
    SetRetransmissionAlarm();
  }
}

void QuicConnection::OnProcessUndecryptablePacketsAlarm() {
  QUICHE_DCHECK(connected());
  ScopedPacketFlusher flusher(this);
  MaybeProcessUndecryptablePackets();
}

void QuicConnection::MaybeProcessUndecryptablePackets() {
  process_undecryptable_packets_alarm().Cancel();

  if (undecryptable_packets_.empty() ||
      encryption_level_ == ENCRYPTION_INITIAL) {
    return;
  }

  auto iter = undecryptable_packets_.begin();
  while (connected_ && iter != undecryptable_packets_.end()) {
    // Making sure there is no pending frames when processing next undecrypted
    // packet because the queued ack frame may change.
    packet_creator_.FlushCurrentPacket();
    if (!connected_) {
      return;
    }
    UndecryptablePacket* undecryptable_packet = &*iter;
    QUIC_DVLOG(1) << ENDPOINT << "Attempting to process undecryptable packet";
    if (debug_visitor_ != nullptr) {
      debug_visitor_->OnAttemptingToProcessUndecryptablePacket(
          undecryptable_packet->encryption_level);
    }
    last_received_packet_info_ = undecryptable_packet->packet_info;
    current_packet_data_ = undecryptable_packet->packet->data();
    const bool processed = framer_.ProcessPacket(*undecryptable_packet->packet);
    current_packet_data_ = nullptr;

    if (processed) {
      QUIC_DVLOG(1) << ENDPOINT << "Processed undecryptable packet!";
      iter = undecryptable_packets_.erase(iter);
      ++stats_.packets_processed;
      continue;
    }
    const bool has_decryption_key = version().KnowsWhichDecrypterToUse() &&
                                    framer_.HasDecrypterOfEncryptionLevel(
                                        undecryptable_packet->encryption_level);
    if (framer_.error() == QUIC_DECRYPTION_FAILURE &&
        ShouldEnqueueUnDecryptablePacket(undecryptable_packet->encryption_level,
                                         has_decryption_key)) {
      QUIC_DVLOG(1)
          << ENDPOINT
          << "Need to attempt to process this undecryptable packet later";
      ++iter;
      continue;
    }
    iter = undecryptable_packets_.erase(iter);
  }

  // Once handshake is complete, there will be no new keys installed and hence
  // any undecryptable packets will never be able to be decrypted.
  if (IsHandshakeComplete()) {
    if (debug_visitor_ != nullptr) {
      for (const auto& undecryptable_packet : undecryptable_packets_) {
        debug_visitor_->OnUndecryptablePacket(
            undecryptable_packet.encryption_level, /*dropped=*/true);
      }
    }
    undecryptable_packets_.clear();
  }
  if (perspective_ == Perspective::IS_CLIENT) {
    SetRetransmissionAlarm();
  }
}

void QuicConnection::QueueCoalescedPacket(const QuicEncryptedPacket& packet) {
  QUIC_DVLOG(1) << ENDPOINT << "Queueing coalesced packet.";
  received_coalesced_packets_.push_back(packet.Clone());
  ++stats_.num_coalesced_packets_received;
}

bool QuicConnection::MaybeProcessCoalescedPackets() {
  bool processed = false;
  while (connected_ && !received_coalesced_packets_.empty()) {
    // Making sure there are no pending frames when processing the next
    // coalesced packet because the queued ack frame may change.
    packet_creator_.FlushCurrentPacket();
    if (!connected_) {
      return processed;
    }

    std::unique_ptr<QuicEncryptedPacket> packet =
        std::move(received_coalesced_packets_.front());
    received_coalesced_packets_.pop_front();

    QUIC_DVLOG(1) << ENDPOINT << "Processing coalesced packet";
    if (framer_.ProcessPacket(*packet)) {
      processed = true;
      ++stats_.num_coalesced_packets_processed;
    } else {
      // If we are unable to decrypt this packet, it might be
      // because the CHLO or SHLO packet was lost.
    }
  }
  if (processed) {
    MaybeProcessUndecryptablePackets();
    MaybeSendInResponseToPacket();
  }
  return processed;
}

void QuicConnection::CloseConnection(
    QuicErrorCode error, const std::string& details,
    ConnectionCloseBehavior connection_close_behavior) {
  CloseConnection(error, NO_IETF_QUIC_ERROR, details,
                  connection_close_behavior);
}

void QuicConnection::CloseConnection(
    QuicErrorCode error, QuicIetfTransportErrorCodes ietf_error,
    const std::string& error_details,
    ConnectionCloseBehavior connection_close_behavior) {
  QUICHE_DCHECK(!error_details.empty());
  if (!connected_) {
    QUIC_DLOG(INFO) << "Connection is already closed.";
    return;
  }

  if (in_close_connection_) {
    QUIC_DLOG(INFO) << "Connection is being closed.";
    return;
  }

  if (GetQuicReloadableFlag(quic_avoid_nested_close_connection)) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_avoid_nested_close_connection);
    in_close_connection_ = true;
  }
  absl::Cleanup cleanup = [this]() { in_close_connection_ = false; };

  if (ietf_error != NO_IETF_QUIC_ERROR) {
    QUIC_DLOG(INFO) << ENDPOINT << "Closing connection: " << connection_id()
                    << ", with wire error: " << ietf_error
                    << ", error: " << QuicErrorCodeToString(error)
                    << ", and details:  " << error_details;
  } else {
    QUIC_DLOG(INFO) << ENDPOINT << "Closing connection: " << connection_id()
                    << ", with error: " << QuicErrorCodeToString(error) << " ("
                    << error << "), and details:  " << error_details;
  }

  if (connection_close_behavior != ConnectionCloseBehavior::SILENT_CLOSE) {
    SendConnectionClosePacket(error, ietf_error, error_details);
  }

  TearDownLocalConnectionState(error, ietf_error, error_details,
                               ConnectionCloseSource::FROM_SELF);
}

void QuicConnection::SendConnectionClosePacket(
    QuicErrorCode error, QuicIetfTransportErrorCodes ietf_error,
    const std::string& details) {
  // Always use the current path to send CONNECTION_CLOSE.
  QuicPacketCreator::ScopedPeerAddressContext peer_address_context(
      &packet_creator_, peer_address(), default_path_.client_connection_id,
      default_path_.server_connection_id);
  if (!SupportsMultiplePacketNumberSpaces()) {
    QUIC_DLOG(INFO) << ENDPOINT << "Sending connection close packet.";
    ScopedEncryptionLevelContext encryption_level_context(
        this, GetConnectionCloseEncryptionLevel());
    if (version().CanSendCoalescedPackets()) {
      coalesced_packet_.Clear();
    }
    ClearQueuedPackets();
    // If there was a packet write error, write the smallest close possible.
    ScopedPacketFlusher flusher(this);
    // Always bundle an ACK with connection close for debugging purpose.
    if (error != QUIC_PACKET_WRITE_ERROR &&
        !uber_received_packet_manager_.IsAckFrameEmpty(
            QuicUtils::GetPacketNumberSpace(encryption_level_)) &&
        !packet_creator_.has_ack()) {
      SendAck();
    }
    QuicConnectionCloseFrame* const frame = new QuicConnectionCloseFrame(
        transport_version(), error, ietf_error, details,
        framer_.current_received_frame_type());
    packet_creator_.ConsumeRetransmittableControlFrame(QuicFrame(frame));
    packet_creator_.FlushCurrentPacket();
    if (version().CanSendCoalescedPackets()) {
      FlushCoalescedPacket();
    }
    ClearQueuedPackets();
    return;
  }
  ScopedPacketFlusher flusher(this);

  // Now that the connection is being closed, discard any unsent packets
  // so the only packets to be sent will be connection close packets.
  if (version().CanSendCoalescedPackets()) {
    coalesced_packet_.Clear();
  }
  ClearQueuedPackets();

  for (EncryptionLevel level :
       {ENCRYPTION_INITIAL, ENCRYPTION_HANDSHAKE, ENCRYPTION_ZERO_RTT,
        ENCRYPTION_FORWARD_SECURE}) {
    if (!framer_.HasEncrypterOfEncryptionLevel(level)) {
      continue;
    }
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Sending connection close packet at level: " << level;
    ScopedEncryptionLevelContext context(this, level);
    // Bundle an ACK of the corresponding packet number space for debugging
    // purpose.
    if (error != QUIC_PACKET_WRITE_ERROR &&
        !uber_received_packet_manager_.IsAckFrameEmpty(
            QuicUtils::GetPacketNumberSpace(encryption_level_)) &&
        !packet_creator_.has_ack()) {
      QuicFrames frames;
      frames.push_back(GetUpdatedAckFrame());
      packet_creator_.FlushAckFrame(frames);
    }

    if (level == ENCRYPTION_FORWARD_SECURE &&
        perspective_ == Perspective::IS_SERVER) {
      visitor_->BeforeConnectionCloseSent();
    }

    auto* frame = new QuicConnectionCloseFrame(
        transport_version(), error, ietf_error, details,
        framer_.current_received_frame_type());
    packet_creator_.ConsumeRetransmittableControlFrame(QuicFrame(frame));
    packet_creator_.FlushCurrentPacket();
  }
  if (version().CanSendCoalescedPackets()) {
    FlushCoalescedPacket();
  }
  // Since the connection is closing, if the connection close packets were not
  // sent, then they should be discarded.
  ClearQueuedPackets();
}

void QuicConnection::TearDownLocalConnectionState(
    QuicErrorCode error, QuicIetfTransportErrorCodes ietf_error,
    const std::string& error_details, ConnectionCloseSource source) {
  QuicConnectionCloseFrame frame(transport_version(), error, ietf_error,
                                 error_details,
                                 framer_.current_received_frame_type());
  return TearDownLocalConnectionState(frame, source);
}

void QuicConnection::TearDownLocalConnectionState(
    const QuicConnectionCloseFrame& frame, ConnectionCloseSource source) {
  if (!connected_) {
    QUIC_DLOG(INFO) << "Connection is already closed.";
    return;
  }

  // If we are using a batch writer, flush packets queued in it, if any.
  FlushPackets();
  connected_ = false;
  QUICHE_DCHECK(visitor_ != nullptr);
  visitor_->OnConnectionClosed(frame, source);
  // LossDetectionTunerInterface::Finish() may be called from
  // sent_packet_manager_.OnConnectionClosed. Which may require the session to
  // finish its business first.
  sent_packet_manager_.OnConnectionClosed();
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnConnectionClosed(frame, source);
  }
  // Cancel the alarms so they don't trigger any action now that the
  // connection is closed.
  CancelAllAlarms();
  CancelPathValidation();

  peer_issued_cid_manager_.reset();
  self_issued_cid_manager_.reset();
}

void QuicConnection::CancelAllAlarms() {
  QUIC_DVLOG(1) << "Cancelling all QuicConnection alarms.";

  // Only active in new multiplexer code.
  alarms_.CancelAllAlarms();

  // PermanentCancel() is a no-op in multiplexer case.
  ack_alarm().PermanentCancel();
  ping_manager_.Stop();
  retransmission_alarm().PermanentCancel();
  send_alarm().PermanentCancel();
  mtu_discovery_alarm().PermanentCancel();
  process_undecryptable_packets_alarm().PermanentCancel();
  discard_previous_one_rtt_keys_alarm().PermanentCancel();
  discard_zero_rtt_decryption_keys_alarm().PermanentCancel();
  multi_port_probing_alarm().PermanentCancel();
  blackhole_detector_.StopDetection(/*permanent=*/true);
  idle_network_detector_.StopDetection();
}

QuicByteCount QuicConnection::max_packet_length() const {
  return packet_creator_.max_packet_length();
}

void QuicConnection::SetMaxPacketLength(QuicByteCount length) {
  long_term_mtu_ = length;
  stats_.max_egress_mtu = std::max(stats_.max_egress_mtu, long_term_mtu_);
  packet_creator_.SetMaxPacketLength(GetLimitedMaxPacketSize(length));
}

bool QuicConnection::HasQueuedData() const {
  return packet_creator_.HasPendingFrames() || !buffered_packets_.empty();
}

void QuicConnection::SetNetworkTimeouts(QuicTime::Delta handshake_timeout,
                                        QuicTime::Delta idle_timeout) {
  QUIC_BUG_IF(quic_bug_12714_29, idle_timeout > handshake_timeout)
      << "idle_timeout:" << idle_timeout.ToMilliseconds()
      << " handshake_timeout:" << handshake_timeout.ToMilliseconds();
  QUIC_DVLOG(1) << ENDPOINT << "Setting network timeouts: "
                << "handshake_timeout:" << handshake_timeout.ToMilliseconds()
                << " idle_timeout:" << idle_timeout.ToMilliseconds();
  // Adjust the idle timeout on client and server to prevent clients from
  // sending requests to servers which have already closed the connection.
  if (perspective_ == Perspective::IS_SERVER) {
    idle_timeout = idle_timeout + QuicTime::Delta::FromSeconds(3);
  } else if (idle_timeout > QuicTime::Delta::FromSeconds(1)) {
    idle_timeout = idle_timeout - QuicTime::Delta::FromSeconds(1);
  }
  idle_network_detector_.SetTimeouts(handshake_timeout, idle_timeout);
}

void QuicConnection::SetPingAlarm() {
  if (!connected_) {
    return;
  }
  ping_manager_.SetAlarm(clock_->ApproximateNow(),
                         visitor_->ShouldKeepConnectionAlive(),
                         sent_packet_manager_.HasInFlightPackets());
}

void QuicConnection::SetRetransmissionAlarm() {
  if (!connected_) {
    if (retransmission_alarm().IsSet()) {
      QUIC_BUG(quic_bug_10511_29)
          << ENDPOINT << "Retransmission alarm is set while disconnected";
      retransmission_alarm().Cancel();
    }
    return;
  }
  if (packet_creator_.PacketFlusherAttached()) {
    pending_retransmission_alarm_ = true;
    return;
  }
  if (LimitedByAmplificationFactor(packet_creator_.max_packet_length())) {
    // Do not set retransmission timer if connection is anti-amplification limit
    // throttled. Otherwise, nothing can be sent when timer fires.
    retransmission_alarm().Cancel();
    return;
  }
  PacketNumberSpace packet_number_space;
  if (SupportsMultiplePacketNumberSpaces() && !IsHandshakeConfirmed() &&
      !sent_packet_manager_
           .GetEarliestPacketSentTimeForPto(&packet_number_space)
           .IsInitialized()) {
    // Before handshake gets confirmed, GetEarliestPacketSentTimeForPto
    // returning 0 indicates no packets are in flight or only application data
    // is in flight.
    if (perspective_ == Perspective::IS_SERVER) {
      // No need to arm PTO on server side.
      retransmission_alarm().Cancel();
      return;
    }
    if (retransmission_alarm().IsSet() &&
        GetRetransmissionDeadline() > retransmission_alarm().deadline()) {
      // Do not postpone armed PTO on the client side.
      return;
    }
  }

  retransmission_alarm().Update(GetRetransmissionDeadline(), kAlarmGranularity);
}

void QuicConnection::MaybeSetMtuAlarm(QuicPacketNumber sent_packet_number) {
  if (mtu_discovery_alarm().IsSet() ||
      !mtu_discoverer_.ShouldProbeMtu(sent_packet_number)) {
    return;
  }
  mtu_discovery_alarm().Set(clock_->ApproximateNow());
}

QuicConnection::ScopedPacketFlusher::ScopedPacketFlusher(
    QuicConnection* connection)
    : connection_(connection),
      active_(false),
      handshake_packet_sent_(connection != nullptr &&
                             connection->handshake_packet_sent_) {
  if (connection_ == nullptr) {
    return;
  }

  if (!connection_->packet_creator_.PacketFlusherAttached()) {
    active_ = true;
    connection->packet_creator_.AttachPacketFlusher();
    connection_->alarms_.DeferUnderlyingAlarmScheduling();
  }
}

QuicConnection::ScopedPacketFlusher::~ScopedPacketFlusher() {
  if (connection_ == nullptr || !connection_->connected()) {
    return;
  }

  if (active_) {
    const QuicTime ack_timeout =
        connection_->uber_received_packet_manager_.GetEarliestAckTimeout();
    if (ack_timeout.IsInitialized()) {
      if (ack_timeout <= connection_->clock_->ApproximateNow() &&
          !connection_->CanWrite(NO_RETRANSMITTABLE_DATA)) {
        // Cancel ACK alarm if connection is write blocked, and ACK will be
        // sent when connection gets unblocked.
        connection_->ack_alarm().Cancel();
      } else if (!connection_->ack_alarm().IsSet() ||
                 connection_->ack_alarm().deadline() > ack_timeout) {
        connection_->ack_alarm().Update(ack_timeout, QuicTime::Delta::Zero());
      }
    }
    if (connection_->ack_alarm().IsSet() &&
        connection_->ack_alarm().deadline() <=
            connection_->clock_->ApproximateNow()) {
      // An ACK needs to be sent right now. This ACK did not get bundled
      // because either there was no data to write or packets were marked as
      // received after frames were queued in the generator.
      if (connection_->send_alarm().IsSet() &&
          connection_->send_alarm().deadline() <=
              connection_->clock_->ApproximateNow()) {
        // If send alarm will go off soon, let send alarm send the ACK.
        connection_->ack_alarm().Cancel();
      } else if (connection_->SupportsMultiplePacketNumberSpaces()) {
        connection_->SendAllPendingAcks();
      } else {
        connection_->SendAck();
      }
    }

    // INITIAL or HANDSHAKE retransmission could cause peer to derive new
    // keys, such that the buffered undecryptable packets may be processed.
    // This endpoint would derive an inflated RTT sample when receiving ACKs
    // of those undecryptable packets. To mitigate this, tries to coalesce as
    // many higher space packets as possible (via for loop inside
    // MaybeCoalescePacketOfHigherSpace) to fill the remaining space in the
    // coalescer.
    if (connection_->version().CanSendCoalescedPackets()) {
      connection_->MaybeCoalescePacketOfHigherSpace();
    }
    connection_->packet_creator_.Flush();
    if (connection_->version().CanSendCoalescedPackets()) {
      connection_->FlushCoalescedPacket();
    }
    connection_->FlushPackets();

    if (!connection_->connected()) {
      return;
    }

    if (!handshake_packet_sent_ && connection_->handshake_packet_sent_) {
      // This would cause INITIAL key to be dropped. Drop keys here to avoid
      // missing the write keys in the middle of writing.
      connection_->visitor_->OnHandshakePacketSent();
    }
    // Reset transmission type.
    connection_->SetTransmissionType(NOT_RETRANSMISSION);

    // Once all transmissions are done, check if there is any outstanding data
    // to send and notify th
```
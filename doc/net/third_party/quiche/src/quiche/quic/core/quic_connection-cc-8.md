Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc`. I need to identify the core purposes of the functions within this segment, look for connections to Javascript (likely related to web browsers and network communication), identify any logical inferences with example inputs and outputs, and note common user or programming errors related to these functions. Finally, since this is part 9 of 10, I should synthesize the overall purpose of this section within the broader context of the `QuicConnection` class.

**Plan:**

1. **Function Analysis:** Go through each function (`SendRetireConnectionId`, `SendNewConnectionId`, `MaybeReserveConnectionId`, etc.) and describe its role in managing the QUIC connection.
2. **Javascript Relationship:** Consider if any of these functions directly correspond to observable network behavior in a browser, or if they manage underlying mechanics that impact Javascript's network APIs (like `fetch`).
3. **Logical Inference (Input/Output):** For functions performing calculations or conditional logic (e.g., `ShouldDetectPathDegrading`, `GetNetworkBlackholeDeadline`), devise simple scenarios to illustrate the inputs and outputs.
4. **User/Programming Errors:** Identify potential misuse of these functions or common pitfalls in implementing or configuring QUIC.
5. **User Operations and Debugging:**  Think about how user actions in a browser might lead to these functions being executed, providing debugging context.
6. **Part 9 Summary:** Synthesize the common themes or high-level purpose of the functions in this section, considering it's the penultimate part of the file. It seems to heavily focus on path management, validation, and connection ID handling.
这是 `QuicConnection.cc` 文件的一部分，主要负责 QUIC 连接的连接 ID 管理、路径验证和探测、以及相关的超时和重传机制。

以下是这段代码片段中各个功能的详细解释：

**核心功能:**

1. **连接ID管理:**
   - `SendRetireConnectionId`:  发送一个 `RETIRE_CONNECTION_ID` 帧，通知对端某个连接 ID 不再使用。
   - `SendNewConnectionId`: 发送一个 `NEW_CONNECTION_ID` 帧，告知对端一个新的可用连接 ID。
   - `MaybeReserveConnectionId`:  作为服务器端，尝试预留一个给定的连接 ID。
   - `OnSelfIssuedConnectionIdRetired`: 作为服务器端，处理自身发出的连接 ID 被退休的事件。
   - `RetirePeerIssuedConnectionIdsNoLongerOnPath`:  退休对端发行的，当前路径上不再使用的连接 ID。
   - `UpdateConnectionIdsOnMigration`: 在客户端进行路径迁移时更新连接 ID。
   - `CreateConnectionIdManager`: 创建连接 ID 管理器（根据是客户端还是服务端）。
   - `GetOneActiveServerConnectionId`: 获取一个活跃的服务器连接 ID。
   - `GetActiveServerConnectionIds`: 获取所有活跃的服务器连接 ID 列表。

2. **路径验证与探测:**
   - `SendPathChallenge`:  发送 `PATH_CHALLENGE` 帧以探测路径是否可用。
   - `SendPathResponse`:  发送 `PATH_RESPONSE` 帧以响应 `PATH_CHALLENGE`。
   - `ValidatePath`:  启动路径验证过程。
   - `HasPendingPathValidation`:  检查是否有正在进行的路径验证。
   - `GetPathValidationContext`: 获取当前路径验证的上下文信息。
   - `CancelPathValidation`: 取消当前正在进行的路径验证。
   - `MigratePath`: 执行路径迁移操作。
   - `OnPathValidationFailureAtClient`:  在客户端路径验证失败时的处理。
   - `IsDefaultPath`: 判断给定的地址是否是默认路径。
   - `IsAlternativePath`: 判断给定的地址是否是备用路径。
   - `OnMultiPortPathProbingSuccess`:  多端口路径探测成功时的处理。
   - `MaybeProbeMultiPortPath`: 尝试探测多端口路径。

3. **超时与重传相关的计算:**
   - `MaybeUpdateAckTimeout`:  根据接收到的数据包信息，可能更新 ACK 超时时间。
   - `GetPathDegradingDeadline`:  计算路径退化检测的截止时间。
   - `ShouldDetectPathDegrading`:  判断是否应该进行路径退化检测。
   - `GetNetworkBlackholeDeadline`: 计算网络黑洞检测的截止时间。
   - `CalculateNetworkBlackholeDelay`: 计算网络黑洞延迟。
   - `GetRetransmissionDeadline`: 获取数据包重传的截止时间。
   - `GetRetryTimeout`: 获取重试超时时间。

4. **其他功能:**
   - `AddKnownServerAddress`:  添加已知的服务器地址。
   - `MaybeIssueNewConnectionIdForPreferredAddress`:  为首选地址可能颁发新的连接 ID。
   - `ShouldDetectBlackhole`: 判断是否应该进行网络黑洞检测。
   - `SendPingAtLevel`: 在指定的加密级别发送 PING 帧。
   - `UpdatePeerAddress`: 更新对端地址。
   - `MaybeClearQueuedPacketsOnPathChange`: 在路径改变时可能清除排队的数据包。
   - `SetSourceAddressTokenToSend`: 设置要发送的源地址令牌 (Source Address Token)。
   - `MaybeUpdateBytesSentToAlternativeAddress`:  可能更新发送到备用地址的字节数（用于抗放大攻击）。
   - `MaybeUpdateBytesReceivedFromAlternativeAddress`: 可能更新从备用地址接收到的字节数（用于抗放大攻击）。
   - `IsReceivedPeerAddressValidated`: 判断接收到的对端地址是否已验证。
   - `QuicBugIfHasPendingFrames`:  用于调试，如果指定的 Stream ID 意外地有待处理的帧，则触发断言。
   - `SetUnackedMapInitialCapacity`: 设置未确认数据包映射的初始容量。

**与 JavaScript 的关系:**

这段 C++ 代码是 Chromium 网络栈的一部分，负责底层的 QUIC 协议实现。虽然 JavaScript 代码本身不直接调用这些函数，但 JavaScript 的网络 API（例如 `fetch`、`XMLHttpRequest` 或 WebSocket）在底层会依赖 Chromium 的网络栈来建立和管理网络连接，包括 QUIC 连接。

**举例说明:**

当你在浏览器中使用 `fetch` API 向一个支持 QUIC 的服务器发起请求时：

1. **连接建立阶段:** Chromium 网络栈可能会调用 `CreateConnectionIdManager` 来创建连接 ID 管理器，用于后续的连接 ID 的分配和管理。
2. **路径探测:** 如果网络环境发生变化，Chromium 可能会使用 `SendPathChallenge` 和 `SendPathResponse` 来探测新的网络路径是否可用。这对于用户来说是透明的，但可以提高连接的稳定性和性能。
3. **连接迁移:** 如果用户的网络地址发生变化（例如从 Wi-Fi 切换到移动网络），Chromium 可能会调用 `MigratePath` 来迁移连接到新的路径，并使用 `UpdateConnectionIdsOnMigration` 来更新连接 ID。
4. **超时与重传:**  如果网络出现延迟或丢包，`MaybeUpdateAckTimeout` 和 `GetRetransmissionDeadline` 等函数会参与计算超时时间和触发重传，确保数据的可靠传输。这最终会影响到 JavaScript 中 `fetch` 请求的响应速度或成功与否。

**逻辑推理与假设输入/输出:**

**示例 1: `ShouldDetectPathDegrading`**

* **假设输入:**
    * `connected_` = `true`
    * `perspective_` = `Perspective::IS_CLIENT`
    * `IsHandshakeConfirmed()` = `true`
    * `is_path_degrading_` = `false`
    * `GetQuicReloadableFlag(quic_no_path_degrading_before_handshake_confirmed)` 返回 `true`
    * `SupportsMultiplePacketNumberSpaces()` 返回 `true`

* **逻辑推理:** 因为所有条件都满足，所以应该检测路径退化。

* **输出:** `true`

**示例 2: `GetNetworkBlackholeDeadline`**

* **假设输入:**
    * `ShouldDetectBlackhole()` 返回 `true`
    * `num_rtos_for_blackhole_detection_` = 3
    * `sent_packet_manager_.GetNetworkBlackholeDelay(3)` 返回 `QuicTime::Delta::FromSeconds(10)`
    * `ShouldDetectPathDegrading()` 返回 `false`
    * `clock_->ApproximateNow()` 返回 `QuicTime::Zero() + QuicTime::Delta::FromSeconds(100)`

* **逻辑推理:** 因为不进行路径退化检测，所以黑洞截止时间是当前时间加上黑洞延迟。

* **输出:** `QuicTime::Zero() + QuicTime::Delta::FromSeconds(110)`

**用户或编程常见的使用错误:**

1. **错误地配置连接 ID 限制:**  如果在服务器端错误地配置了允许的连接 ID 数量，可能导致连接 ID 耗尽，从而影响新的连接或连接迁移。
2. **路径验证逻辑错误:** 在实现自定义的路径验证逻辑时，如果处理 `PATH_CHALLENGE` 和 `PATH_RESPONSE` 的方式不正确，可能导致路径验证失败，影响连接的稳定性和性能。
3. **忽略连接迁移的必要性:**  在网络环境发生变化时，如果应用程序没有适当地处理连接迁移，可能导致连接中断。
4. **错误地假设网络条件:**  在配置超时时间和重传参数时，如果对网络条件的假设与实际情况不符，可能导致不必要的重传或过早地断开连接。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个使用 QUIC 协议的网站。**
2. **浏览器尝试与服务器建立 QUIC 连接。** 这涉及到连接 ID 的协商和分配（`CreateConnectionIdManager`，`SendNewConnectionId`）。
3. **如果用户的网络环境发生变化 (例如切换 Wi-Fi)，或者服务器尝试迁移连接:**  会触发路径验证和连接迁移相关的逻辑 (`ValidatePath`, `SendPathChallenge`, `MigratePath`).
4. **如果在网络传输过程中出现丢包或延迟:**  `MaybeUpdateAckTimeout` 和 `GetRetransmissionDeadline` 会被调用，决定何时重传数据。
5. **如果服务器希望客户端使用新的连接 ID:**  服务器会发送 `RETIRE_CONNECTION_ID` 和 `NEW_CONNECTION_ID` 帧，客户端的 `QuicConnection` 对象会调用 `SendRetireConnectionId` 和 `SendNewConnectionId` 来处理这些帧。
6. **在多端口场景下:** 如果客户端尝试使用新的本地端口进行连接，会涉及到多端口路径探测 (`MaybeProbeMultiPortPath`, `OnMultiPortPathProbingSuccess`).

**作为调试线索:**

* 查看日志中是否有关于发送 `RETIRE_CONNECTION_ID` 或 `NEW_CONNECTION_ID` 帧的记录，可以帮助理解连接 ID 的管理过程。
* 检查路径验证相关的事件，例如 `PATH_CHALLENGE` 和 `PATH_RESPONSE` 帧的发送和接收，可以帮助诊断路径迁移或探测的问题。
* 观察超时和重传的发生频率，可以帮助判断网络状况是否良好，以及超时参数是否配置合理。

**第 9 部分的功能归纳:**

这部分代码主要集中在 **QUIC 连接的连接 ID 生命周期管理和网络路径的动态管理** 上。它涵盖了以下关键功能：

* **连接 ID 的发行、退休和协商:**  确保连接能够平滑地更换连接 ID，提高安全性和应对网络变化。
* **路径验证和探测:**  允许连接在网络条件变化时探测和切换到更优的路径，保证连接的稳定性和性能。
* **超时和重传机制的辅助计算:**  为可靠的数据传输提供基础。
* **抗放大攻击的机制:**  限制在路径验证完成前向新路径发送的数据量。

总的来说，这部分代码是 `QuicConnection` 类中负责维护连接活性、适应网络变化和保障安全性的重要组成部分。它体现了 QUIC 协议在连接管理和路径优化方面的复杂性和灵活性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
red_cid_sequence_numbers =
      peer_issued_cid_manager_->ConsumeToBeRetiredConnectionIdSequenceNumbers();
  QUICHE_DCHECK(!retired_cid_sequence_numbers.empty());
  for (const auto& sequence_number : retired_cid_sequence_numbers) {
    ++stats_.num_retire_connection_id_sent;
    visitor_->SendRetireConnectionId(sequence_number);
  }
}

bool QuicConnection::SendNewConnectionId(
    const QuicNewConnectionIdFrame& frame) {
  visitor_->SendNewConnectionId(frame);
  ++stats_.num_new_connection_id_sent;
  return connected_;
}

bool QuicConnection::MaybeReserveConnectionId(
    const QuicConnectionId& connection_id) {
  if (perspective_ == Perspective::IS_SERVER) {
    return visitor_->MaybeReserveConnectionId(connection_id);
  }
  return true;
}

void QuicConnection::OnSelfIssuedConnectionIdRetired(
    const QuicConnectionId& connection_id) {
  if (perspective_ == Perspective::IS_SERVER) {
    visitor_->OnServerConnectionIdRetired(connection_id);
  }
}

void QuicConnection::MaybeUpdateAckTimeout() {
  if (should_last_packet_instigate_acks_) {
    return;
  }
  should_last_packet_instigate_acks_ = true;
  uber_received_packet_manager_.MaybeUpdateAckTimeout(
      /*should_last_packet_instigate_acks=*/true,
      last_received_packet_info_.decrypted_level,
      last_received_packet_info_.header.packet_number,
      last_received_packet_info_.receipt_time, clock_->ApproximateNow(),
      sent_packet_manager_.GetRttStats());
}

QuicTime QuicConnection::GetPathDegradingDeadline() const {
  if (!ShouldDetectPathDegrading()) {
    return QuicTime::Zero();
  }
  return clock_->ApproximateNow() +
         sent_packet_manager_.GetPathDegradingDelay();
}

bool QuicConnection::ShouldDetectPathDegrading() const {
  if (!connected_) {
    return false;
  }
  if (GetQuicReloadableFlag(
          quic_no_path_degrading_before_handshake_confirmed) &&
      SupportsMultiplePacketNumberSpaces()) {
    QUIC_RELOADABLE_FLAG_COUNT_N(
        quic_no_path_degrading_before_handshake_confirmed, 1, 2);
    // No path degrading detection before handshake confirmed.
    return perspective_ == Perspective::IS_CLIENT && IsHandshakeConfirmed() &&
           !is_path_degrading_;
  }
  // No path degrading detection before handshake completes.
  if (!idle_network_detector_.handshake_timeout().IsInfinite()) {
    return false;
  }
  return perspective_ == Perspective::IS_CLIENT && !is_path_degrading_;
}

QuicTime QuicConnection::GetNetworkBlackholeDeadline() const {
  if (!ShouldDetectBlackhole()) {
    return QuicTime::Zero();
  }
  QUICHE_DCHECK_LT(0u, num_rtos_for_blackhole_detection_);

  const QuicTime::Delta blackhole_delay =
      sent_packet_manager_.GetNetworkBlackholeDelay(
          num_rtos_for_blackhole_detection_);
  if (!ShouldDetectPathDegrading()) {
    return clock_->ApproximateNow() + blackhole_delay;
  }
  return clock_->ApproximateNow() +
         CalculateNetworkBlackholeDelay(
             blackhole_delay, sent_packet_manager_.GetPathDegradingDelay(),
             sent_packet_manager_.GetPtoDelay());
}

// static
QuicTime::Delta QuicConnection::CalculateNetworkBlackholeDelay(
    QuicTime::Delta blackhole_delay, QuicTime::Delta path_degrading_delay,
    QuicTime::Delta pto_delay) {
  const QuicTime::Delta min_delay = path_degrading_delay + pto_delay * 2;
  if (blackhole_delay < min_delay) {
    QUIC_CODE_COUNT(quic_extending_short_blackhole_delay);
  }
  return std::max(min_delay, blackhole_delay);
}

void QuicConnection::AddKnownServerAddress(const QuicSocketAddress& address) {
  QUICHE_DCHECK(perspective_ == Perspective::IS_CLIENT);
  if (!address.IsInitialized() || IsKnownServerAddress(address)) {
    return;
  }
  known_server_addresses_.push_back(address);
}

std::optional<QuicNewConnectionIdFrame>
QuicConnection::MaybeIssueNewConnectionIdForPreferredAddress() {
  if (self_issued_cid_manager_ == nullptr) {
    return std::nullopt;
  }
  return self_issued_cid_manager_
      ->MaybeIssueNewConnectionIdForPreferredAddress();
}

bool QuicConnection::ShouldDetectBlackhole() const {
  if (!connected_ || blackhole_detection_disabled_) {
    return false;
  }
  if (GetQuicReloadableFlag(
          quic_no_path_degrading_before_handshake_confirmed) &&
      SupportsMultiplePacketNumberSpaces() && !IsHandshakeConfirmed()) {
    QUIC_RELOADABLE_FLAG_COUNT_N(
        quic_no_path_degrading_before_handshake_confirmed, 2, 2);
    return false;
  }
  // No blackhole detection before handshake completes.
  if (default_enable_5rto_blackhole_detection_) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_default_enable_5rto_blackhole_detection2,
                                 3, 3);
    return IsHandshakeComplete();
  }

  if (!idle_network_detector_.handshake_timeout().IsInfinite()) {
    return false;
  }
  return num_rtos_for_blackhole_detection_ > 0;
}

QuicTime QuicConnection::GetRetransmissionDeadline() const {
  if (perspective_ == Perspective::IS_CLIENT &&
      SupportsMultiplePacketNumberSpaces() && !IsHandshakeConfirmed() &&
      stats_.pto_count == 0 &&
      !framer_.HasDecrypterOfEncryptionLevel(ENCRYPTION_HANDSHAKE) &&
      !undecryptable_packets_.empty()) {
    // Retransmits ClientHello quickly when a Handshake or 1-RTT packet is
    // received prior to having Handshake keys. Adding kAlarmGranulary will
    // avoid spurious retransmissions in the case of small-scale reordering.
    return clock_->ApproximateNow() + kAlarmGranularity;
  }
  return sent_packet_manager_.GetRetransmissionTime();
}

bool QuicConnection::SendPathChallenge(
    const QuicPathFrameBuffer& data_buffer,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    const QuicSocketAddress& effective_peer_address, QuicPacketWriter* writer) {
  if (!framer_.HasEncrypterOfEncryptionLevel(ENCRYPTION_FORWARD_SECURE)) {
    return connected_;
  }

  QuicConnectionId client_cid, server_cid;
  FindOnPathConnectionIds(self_address, effective_peer_address, &client_cid,
                          &server_cid);
  if (writer == writer_) {
    ScopedPacketFlusher flusher(this);
    {
      QuicPacketCreator::ScopedPeerAddressContext context(
          &packet_creator_, peer_address, client_cid, server_cid);
      // It's using the default writer, add the PATH_CHALLENGE the same way as
      // other frames. This may cause connection to be closed.
      packet_creator_.AddPathChallengeFrame(data_buffer);
    }
  } else if (!writer->IsWriteBlocked()) {
    // Switch to the right CID and source/peer addresses.
    QuicPacketCreator::ScopedPeerAddressContext context(
        &packet_creator_, peer_address, client_cid, server_cid);
    std::unique_ptr<SerializedPacket> probing_packet =
        packet_creator_.SerializePathChallengeConnectivityProbingPacket(
            data_buffer);
    QUICHE_DCHECK_EQ(IsRetransmittable(*probing_packet),
                     NO_RETRANSMITTABLE_DATA)
        << ENDPOINT << "Probing Packet contains retransmittable frames";
    QUICHE_DCHECK_EQ(self_address, alternative_path_.self_address)
        << ENDPOINT
        << "Send PATH_CHALLENGE from self_address: " << self_address.ToString()
        << " which is different from alt_path self address: "
        << alternative_path_.self_address.ToString();
    WritePacketUsingWriter(std::move(probing_packet), writer, self_address,
                           peer_address, /*measure_rtt=*/false);
  } else {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Writer blocked when sending PATH_CHALLENGE.";
  }
  return connected_;
}

QuicTime QuicConnection::GetRetryTimeout(
    const QuicSocketAddress& peer_address_to_use,
    QuicPacketWriter* writer_to_use) const {
  if (writer_to_use == writer_ && peer_address_to_use == peer_address()) {
    return clock_->ApproximateNow() + sent_packet_manager_.GetPtoDelay();
  }
  return clock_->ApproximateNow() +
         QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs);
}

void QuicConnection::ValidatePath(
    std::unique_ptr<QuicPathValidationContext> context,
    std::unique_ptr<QuicPathValidator::ResultDelegate> result_delegate,
    PathValidationReason reason) {
  QUICHE_DCHECK(version().HasIetfQuicFrames());
  if (path_validator_.HasPendingPathValidation()) {
    if (perspective_ == Perspective::IS_CLIENT &&
        IsValidatingServerPreferredAddress()) {
      QUIC_CLIENT_HISTOGRAM_BOOL(
          "QuicSession.ServerPreferredAddressValidationCancelled", true,
          "How often the caller kicked off another validation while there is "
          "an on-going server preferred address validation.");
    }
    // Cancel and fail any earlier validation.
    path_validator_.CancelPathValidation();
  }
  if (perspective_ == Perspective::IS_CLIENT &&
      !IsDefaultPath(context->self_address(), context->peer_address())) {
    if (self_issued_cid_manager_ != nullptr) {
      self_issued_cid_manager_->MaybeSendNewConnectionIds();
      if (!connected_) {
        return;
      }
    }
    if ((self_issued_cid_manager_ != nullptr &&
         !self_issued_cid_manager_->HasConnectionIdToConsume()) ||
        (peer_issued_cid_manager_ != nullptr &&
         !peer_issued_cid_manager_->HasUnusedConnectionId())) {
      QUIC_DVLOG(1) << "Client cannot start new path validation as there is no "
                       "requried connection ID is available.";
      result_delegate->OnPathValidationFailure(std::move(context));
      return;
    }
    QuicConnectionId client_connection_id, server_connection_id;
    std::optional<StatelessResetToken> stateless_reset_token;
    if (self_issued_cid_manager_ != nullptr) {
      client_connection_id =
          *self_issued_cid_manager_->ConsumeOneConnectionId();
    }
    if (peer_issued_cid_manager_ != nullptr) {
      const auto* connection_id_data =
          peer_issued_cid_manager_->ConsumeOneUnusedConnectionId();
      server_connection_id = connection_id_data->connection_id;
      stateless_reset_token = connection_id_data->stateless_reset_token;
    }
    alternative_path_ = PathState(context->self_address(),
                                  context->peer_address(), client_connection_id,
                                  server_connection_id, stateless_reset_token);
  }
  if (multi_port_stats_ != nullptr &&
      reason == PathValidationReason::kMultiPort) {
    multi_port_stats_->num_client_probing_attempts++;
  }
  if (perspective_ == Perspective::IS_CLIENT) {
    stats_.num_client_probing_attempts++;
  }

  path_validator_.StartPathValidation(std::move(context),
                                      std::move(result_delegate), reason);
  if (perspective_ == Perspective::IS_CLIENT &&
      IsValidatingServerPreferredAddress()) {
    AddKnownServerAddress(received_server_preferred_address_);
  }
}

bool QuicConnection::SendPathResponse(
    const QuicPathFrameBuffer& data_buffer,
    const QuicSocketAddress& peer_address_to_send,
    const QuicSocketAddress& effective_peer_address) {
  if (!framer_.HasEncrypterOfEncryptionLevel(ENCRYPTION_FORWARD_SECURE)) {
    return false;
  }
  QuicConnectionId client_cid, server_cid;
  FindOnPathConnectionIds(last_received_packet_info_.destination_address,
                          effective_peer_address, &client_cid, &server_cid);
  // Send PATH_RESPONSE using the provided peer address. If the creator has been
  // using a different peer address, it will flush before and after serializing
  // the current PATH_RESPONSE.
  QuicPacketCreator::ScopedPeerAddressContext context(
      &packet_creator_, peer_address_to_send, client_cid, server_cid);
  QUIC_DVLOG(1) << ENDPOINT << "Send PATH_RESPONSE to " << peer_address_to_send;
  if (default_path_.self_address ==
      last_received_packet_info_.destination_address) {
    // The PATH_CHALLENGE is received on the default socket. Respond on the same
    // socket.
    return packet_creator_.AddPathResponseFrame(data_buffer);
  }

  QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective_);
  // This PATH_CHALLENGE is received on an alternative socket which should be
  // used to send PATH_RESPONSE.
  if (!path_validator_.HasPendingPathValidation() ||
      path_validator_.GetContext()->self_address() !=
          last_received_packet_info_.destination_address) {
    // Ignore this PATH_CHALLENGE if it's received from an uninteresting
    // socket.
    return true;
  }
  QuicPacketWriter* writer = path_validator_.GetContext()->WriterToUse();
  if (writer->IsWriteBlocked()) {
    QUIC_DLOG(INFO) << ENDPOINT << "Writer blocked when sending PATH_RESPONSE.";
    return true;
  }

  std::unique_ptr<SerializedPacket> probing_packet =
      packet_creator_.SerializePathResponseConnectivityProbingPacket(
          {data_buffer}, /*is_padded=*/true);
  QUICHE_DCHECK_EQ(IsRetransmittable(*probing_packet), NO_RETRANSMITTABLE_DATA);
  QUIC_DVLOG(1) << ENDPOINT
                << "Send PATH_RESPONSE from alternative socket with address "
                << last_received_packet_info_.destination_address;
  // Ignore the return value to treat write error on the alternative writer as
  // part of network error. If the writer becomes blocked, wait for the peer to
  // send another PATH_CHALLENGE.
  WritePacketUsingWriter(std::move(probing_packet), writer,
                         last_received_packet_info_.destination_address,
                         peer_address_to_send,
                         /*measure_rtt=*/false);
  return true;
}

void QuicConnection::UpdatePeerAddress(QuicSocketAddress peer_address) {
  direct_peer_address_ = peer_address;
  packet_creator_.SetDefaultPeerAddress(peer_address);
}

void QuicConnection::SendPingAtLevel(EncryptionLevel level) {
  ScopedEncryptionLevelContext context(this, level);
  SendControlFrame(QuicFrame(QuicPingFrame()));
}

bool QuicConnection::HasPendingPathValidation() const {
  return path_validator_.HasPendingPathValidation();
}

QuicPathValidationContext* QuicConnection::GetPathValidationContext() const {
  return path_validator_.GetContext();
}

void QuicConnection::CancelPathValidation() {
  path_validator_.CancelPathValidation();
}

bool QuicConnection::UpdateConnectionIdsOnMigration(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address) {
  QUICHE_DCHECK(perspective_ == Perspective::IS_CLIENT);
  if (IsAlternativePath(self_address, peer_address)) {
    // Client migration is after path validation.
    default_path_.client_connection_id = alternative_path_.client_connection_id;
    default_path_.server_connection_id = alternative_path_.server_connection_id;
    default_path_.stateless_reset_token =
        alternative_path_.stateless_reset_token;
    return true;
  }
  // Client migration is without path validation.
  if (self_issued_cid_manager_ != nullptr) {
    self_issued_cid_manager_->MaybeSendNewConnectionIds();
    if (!connected_) {
      return false;
    }
  }
  if ((self_issued_cid_manager_ != nullptr &&
       !self_issued_cid_manager_->HasConnectionIdToConsume()) ||
      (peer_issued_cid_manager_ != nullptr &&
       !peer_issued_cid_manager_->HasUnusedConnectionId())) {
    return false;
  }
  if (self_issued_cid_manager_ != nullptr) {
    default_path_.client_connection_id =
        *self_issued_cid_manager_->ConsumeOneConnectionId();
  }
  if (peer_issued_cid_manager_ != nullptr) {
    const auto* connection_id_data =
        peer_issued_cid_manager_->ConsumeOneUnusedConnectionId();
    default_path_.server_connection_id = connection_id_data->connection_id;
    default_path_.stateless_reset_token =
        connection_id_data->stateless_reset_token;
  }
  return true;
}

void QuicConnection::RetirePeerIssuedConnectionIdsNoLongerOnPath() {
  if (!version().HasIetfQuicFrames() || peer_issued_cid_manager_ == nullptr) {
    return;
  }
  if (perspective_ == Perspective::IS_CLIENT) {
    peer_issued_cid_manager_->MaybeRetireUnusedConnectionIds(
        {default_path_.server_connection_id,
         alternative_path_.server_connection_id});
  } else {
    peer_issued_cid_manager_->MaybeRetireUnusedConnectionIds(
        {default_path_.client_connection_id,
         alternative_path_.client_connection_id});
  }
}

bool QuicConnection::MigratePath(const QuicSocketAddress& self_address,
                                 const QuicSocketAddress& peer_address,
                                 QuicPacketWriter* writer, bool owns_writer) {
  QUICHE_DCHECK(perspective_ == Perspective::IS_CLIENT);
  if (!connected_) {
    if (owns_writer) {
      delete writer;
    }
    return false;
  }
  QUICHE_DCHECK(!version().UsesHttp3() || IsHandshakeConfirmed() ||
                accelerated_server_preferred_address_);

  if (version().UsesHttp3()) {
    if (!UpdateConnectionIdsOnMigration(self_address, peer_address)) {
      if (owns_writer) {
        delete writer;
      }
      return false;
    }
    if (packet_creator_.GetServerConnectionId().length() !=
        default_path_.server_connection_id.length()) {
      packet_creator_.FlushCurrentPacket();
    }
    packet_creator_.SetClientConnectionId(default_path_.client_connection_id);
    packet_creator_.SetServerConnectionId(default_path_.server_connection_id);
  }

  const auto self_address_change_type = QuicUtils::DetermineAddressChangeType(
      default_path_.self_address, self_address);
  const auto peer_address_change_type = QuicUtils::DetermineAddressChangeType(
      default_path_.peer_address, peer_address);
  QUICHE_DCHECK(self_address_change_type != NO_CHANGE ||
                peer_address_change_type != NO_CHANGE);
  const bool is_port_change = (self_address_change_type == PORT_CHANGE ||
                               self_address_change_type == NO_CHANGE) &&
                              (peer_address_change_type == PORT_CHANGE ||
                               peer_address_change_type == NO_CHANGE);
  SetSelfAddress(self_address);
  UpdatePeerAddress(peer_address);
  default_path_.peer_address = peer_address;
  if (writer_ != writer) {
    SetQuicPacketWriter(writer, owns_writer);
  }
  MaybeClearQueuedPacketsOnPathChange();
  OnSuccessfulMigration(is_port_change);
  return true;
}

void QuicConnection::OnPathValidationFailureAtClient(
    bool is_multi_port, const QuicPathValidationContext& context) {
  QUICHE_DCHECK(perspective_ == Perspective::IS_CLIENT &&
                version().HasIetfQuicFrames());
  alternative_path_.Clear();

  if (is_multi_port && multi_port_stats_ != nullptr) {
    if (is_path_degrading_) {
      multi_port_stats_->num_multi_port_probe_failures_when_path_degrading++;
    } else {
      multi_port_stats_
          ->num_multi_port_probe_failures_when_path_not_degrading++;
    }
  }

  if (context.peer_address() == received_server_preferred_address_ &&
      received_server_preferred_address_ != default_path_.peer_address) {
    QUIC_DLOG(INFO) << "Failed to validate server preferred address : "
                    << received_server_preferred_address_;
    mutable_stats().failed_to_validate_server_preferred_address = true;
  }

  RetirePeerIssuedConnectionIdsNoLongerOnPath();
}

QuicConnectionId QuicConnection::GetOneActiveServerConnectionId() const {
  if (perspective_ == Perspective::IS_CLIENT ||
      self_issued_cid_manager_ == nullptr) {
    return connection_id();
  }
  auto active_connection_ids = GetActiveServerConnectionIds();
  QUIC_BUG_IF(quic_bug_6944, active_connection_ids.empty());
  if (active_connection_ids.empty() ||
      std::find(active_connection_ids.begin(), active_connection_ids.end(),
                connection_id()) != active_connection_ids.end()) {
    return connection_id();
  }
  QUICHE_CODE_COUNT(connection_id_on_default_path_has_been_retired);
  auto active_connection_id =
      self_issued_cid_manager_->GetOneActiveConnectionId();
  return active_connection_id;
}

std::vector<QuicConnectionId> QuicConnection::GetActiveServerConnectionIds()
    const {
  QUICHE_DCHECK_EQ(Perspective::IS_SERVER, perspective_);
  std::vector<QuicConnectionId> result;
  if (self_issued_cid_manager_ == nullptr) {
    result.push_back(default_path_.server_connection_id);
  } else {
    QUICHE_DCHECK(version().HasIetfQuicFrames());
    result = self_issued_cid_manager_->GetUnretiredConnectionIds();
  }
  if (!original_destination_connection_id_.has_value()) {
    return result;
  }
  // Add the original connection ID
  if (std::find(result.begin(), result.end(),
                *original_destination_connection_id_) != result.end()) {
    QUIC_BUG(quic_unexpected_original_destination_connection_id)
        << "original_destination_connection_id: "
        << *original_destination_connection_id_
        << " is unexpectedly in active list";
  } else {
    result.insert(result.end(), *original_destination_connection_id_);
  }
  return result;
}

void QuicConnection::CreateConnectionIdManager() {
  if (!version().HasIetfQuicFrames()) {
    return;
  }

  if (perspective_ == Perspective::IS_CLIENT) {
    if (!default_path_.server_connection_id.IsEmpty()) {
      peer_issued_cid_manager_ =
          std::make_unique<QuicPeerIssuedConnectionIdManager>(
              kMinNumOfActiveConnectionIds, default_path_.server_connection_id,
              clock_, alarm_factory_, this, context());
    }
  } else {
    if (!default_path_.server_connection_id.IsEmpty()) {
      self_issued_cid_manager_ = MakeSelfIssuedConnectionIdManager();
    }
  }
}

void QuicConnection::QuicBugIfHasPendingFrames(QuicStreamId id) const {
  QUIC_BUG_IF(quic_has_pending_frames_unexpectedly,
              connected_ && packet_creator_.HasPendingStreamFramesOfStream(id))
      << "Stream " << id
      << " has pending frames unexpectedly. Received packet info: "
      << last_received_packet_info_;
}

void QuicConnection::SetUnackedMapInitialCapacity() {
  sent_packet_manager_.ReserveUnackedPacketsInitialCapacity(
      GetUnackedMapInitialCapacity());
}

void QuicConnection::SetSourceAddressTokenToSend(absl::string_view token) {
  QUICHE_DCHECK_EQ(perspective_, Perspective::IS_CLIENT);
  if (!packet_creator_.HasRetryToken()) {
    // Ignore received tokens (via NEW_TOKEN frame) from previous connections
    // when a RETRY token has been received.
    packet_creator_.SetRetryToken(std::string(token.data(), token.length()));
  }
}

void QuicConnection::MaybeUpdateBytesSentToAlternativeAddress(
    const QuicSocketAddress& peer_address, QuicByteCount sent_packet_size) {
  if (!version().SupportsAntiAmplificationLimit() ||
      perspective_ != Perspective::IS_SERVER) {
    return;
  }
  QUICHE_DCHECK(!IsDefaultPath(default_path_.self_address, peer_address));
  if (!IsAlternativePath(default_path_.self_address, peer_address)) {
    QUIC_DLOG(INFO) << "Wrote to uninteresting peer address: " << peer_address
                    << " default direct_peer_address_ " << direct_peer_address_
                    << " alternative path peer address "
                    << alternative_path_.peer_address;
    return;
  }
  if (alternative_path_.validated) {
    return;
  }
  if (alternative_path_.bytes_sent_before_address_validation >=
      anti_amplification_factor_ *
          alternative_path_.bytes_received_before_address_validation) {
    QUIC_LOG_FIRST_N(WARNING, 100)
        << "Server sent more data than allowed to unverified alternative "
           "peer address "
        << peer_address << " bytes sent "
        << alternative_path_.bytes_sent_before_address_validation
        << ", bytes received "
        << alternative_path_.bytes_received_before_address_validation;
  }
  alternative_path_.bytes_sent_before_address_validation += sent_packet_size;
}

void QuicConnection::MaybeUpdateBytesReceivedFromAlternativeAddress(
    QuicByteCount received_packet_size) {
  if (!version().SupportsAntiAmplificationLimit() ||
      perspective_ != Perspective::IS_SERVER ||
      !IsAlternativePath(last_received_packet_info_.destination_address,
                         GetEffectivePeerAddressFromCurrentPacket()) ||
      last_received_packet_info_.received_bytes_counted) {
    return;
  }
  // Only update bytes received if this probing frame is received on the most
  // recent alternative path.
  QUICHE_DCHECK(!IsDefaultPath(last_received_packet_info_.destination_address,
                               GetEffectivePeerAddressFromCurrentPacket()));
  if (!alternative_path_.validated) {
    alternative_path_.bytes_received_before_address_validation +=
        received_packet_size;
  }
  last_received_packet_info_.received_bytes_counted = true;
}

bool QuicConnection::IsDefaultPath(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address) const {
  return direct_peer_address_ == peer_address &&
         default_path_.self_address == self_address;
}

bool QuicConnection::IsAlternativePath(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address) const {
  return alternative_path_.peer_address == peer_address &&
         alternative_path_.self_address == self_address;
}

void QuicConnection::PathState::Clear() {
  self_address = QuicSocketAddress();
  peer_address = QuicSocketAddress();
  client_connection_id = {};
  server_connection_id = {};
  validated = false;
  bytes_received_before_address_validation = 0;
  bytes_sent_before_address_validation = 0;
  send_algorithm = nullptr;
  rtt_stats = std::nullopt;
  stateless_reset_token.reset();
  ecn_marked_packet_acked = false;
  ecn_pto_count = 0;
}

QuicConnection::PathState::PathState(PathState&& other) {
  *this = std::move(other);
}

QuicConnection::PathState& QuicConnection::PathState::operator=(
    QuicConnection::PathState&& other) {
  if (this != &other) {
    self_address = other.self_address;
    peer_address = other.peer_address;
    client_connection_id = other.client_connection_id;
    server_connection_id = other.server_connection_id;
    stateless_reset_token = other.stateless_reset_token;
    validated = other.validated;
    bytes_received_before_address_validation =
        other.bytes_received_before_address_validation;
    bytes_sent_before_address_validation =
        other.bytes_sent_before_address_validation;
    send_algorithm = std::move(other.send_algorithm);
    if (other.rtt_stats.has_value()) {
      rtt_stats.emplace();
      rtt_stats->CloneFrom(*other.rtt_stats);
    } else {
      rtt_stats.reset();
    }
    other.Clear();
  }
  return *this;
}

bool QuicConnection::IsReceivedPeerAddressValidated() const {
  QuicSocketAddress current_effective_peer_address =
      GetEffectivePeerAddressFromCurrentPacket();
  QUICHE_DCHECK(current_effective_peer_address.IsInitialized());
  return (alternative_path_.peer_address.host() ==
              current_effective_peer_address.host() &&
          alternative_path_.validated) ||
         (default_path_.validated && default_path_.peer_address.host() ==
                                         current_effective_peer_address.host());
}

void QuicConnection::OnMultiPortPathProbingSuccess(
    std::unique_ptr<QuicPathValidationContext> context, QuicTime start_time) {
  QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective());
  alternative_path_.validated = true;
  multi_port_path_context_ = std::move(context);
  multi_port_probing_alarm().Set(clock_->ApproximateNow() +
                                 multi_port_probing_interval_);
  if (multi_port_stats_ != nullptr) {
    multi_port_stats_->num_successful_probes++;
    auto now = clock_->Now();
    auto time_delta = now - start_time;
    multi_port_stats_->rtt_stats.UpdateRtt(time_delta, QuicTime::Delta::Zero(),
                                           now);
    if (is_path_degrading_) {
      multi_port_stats_->rtt_stats_when_default_path_degrading.UpdateRtt(
          time_delta, QuicTime::Delta::Zero(), now);
    }
  }
}

void QuicConnection::MaybeProbeMultiPortPath() {
  if (!connected_ || path_validator_.HasPendingPathValidation() ||
      !multi_port_path_context_ ||
      alternative_path_.self_address !=
          multi_port_path_context_->self_address() ||
      alternative_path_.peer_address !=
          multi_port_path_context_->peer_address() ||
      !visitor_->ShouldKeepConnectionAlive() ||
      multi_port_probing_alarm().IsSet()) {
    return;
  }
  if (multi_port_stats_ != nullptr) {
    multi_port_stats_->num_client_probing_attempts++;
  }
  auto multi_port_validation_result_delegate =
      std::make_unique<MultiPortPathValidationResultDelegate>(this);
  path_validator_.StartPathValidation(
      std::move(multi_port_path_context_),
      std::move(multi_port_validation_result_delegate),
      PathValidationReason::kMultiPort);
}

void QuicConnection::ContextObserver::OnMultiPortPathContextAvailable(
    std::unique_ptr<QuicPathValidationContext> path_context) {
  if (!path_context) {
    return;
  }
  auto multi_port_validation_result_delegate =
      std::make_unique<MultiPortPathValidationResultDelegate>(connection_);
  connection_->multi_port_probing_alarm().Cancel();
  connection_->multi_port_path_context_ = nullptr;
  connection_->multi_port_stats_->num_multi_port_paths_created++;
  connection_->ValidatePath(std::move(path_context),
                            std::move(multi_port_validation_result_delegate),
                            PathValidationReason::kMultiPort);
}

QuicConnection::MultiPortPathValidationResultDelegate::
    MultiPortPathValidationResultDelegate(QuicConnection* connection)
    : connection_(connection) {
  QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, connection->perspective());
}

void QuicConnection::MultiPortPathValidationResultDelegate::
    OnPathValidationSuccess(std::unique_ptr<QuicPathValidationContext> context,
                            QuicTime start_time) {
  connection_->OnMultiPortPathProbingSuccess(std::move(context), start_time);
}

void QuicConnection::MultiPortPathValidationResultDelegate::
    OnPathValidationFailure(
        std::unique_ptr<QuicPathValidationContext> context) {
  connection_->OnPathValidationFailureAtClient(/*is_multi_port=*/true,
                                               *context);
}

QuicConnection::ReversePathValidationResultDelegate::
    ReversePathValidationResultDelegate(
        QuicConnection* connection,
        const QuicSocketAddress& direct_peer_address)
    : QuicPathValidator::ResultDelegate(),
      connection_(connection),
      original_direct_peer_address_(direct_peer_address),
      peer_address_default_path_(connection->direct_peer_address_),
      peer_address_alternative_path_(
          connection_->alternative_path_.peer_address),
      active_effective_peer_migration_type_(
          connection_->active_effective_peer_migration_type_) {}

void QuicConnection::ReversePathValidationResultDelegate::
    OnPathValidationSuccess(std::unique_ptr<QuicPathValidationContext> context,
                            QuicTime start_time) {
  QUIC_DLOG(INFO) << "Successfully validated new path " << *context
                  << ", validation started at " << start_time;
  if (connection_->IsDefaultPath(context->self_address(),
                                 context->peer_address())) {
    QUIC_CODE_COUNT_N(quic_kick_off_client_address_validation, 3, 6);
    if (connection_->active_effective_peer_migration_type_ == NO_CHANGE) {
      std::string error_detail = absl::StrCat(
          "Reverse path validation on default path from ",
          context->self_address().ToString(), " to ",
          context->peer_address().ToString(),
          " completed without active peer address change: current "
          "peer address on default path ",
          connection_->direct_peer_address_.ToString(),
          ", peer address on default path when the reverse path "
          "validation was kicked off ",
          peer_address_default_path_.ToString(),
          ", peer address on alternative path when the reverse "
          "path validation was kicked off ",
          peer_address_alternative_path_.ToString(),
          ", with active_effective_peer_migration_type_ = ",
          AddressChangeTypeToString(active_effective_peer_migration_type_),
          ". The last received packet number ",
          connection_->last_received_packet_info_.header.packet_number
              .ToString(),
          " Connection is connected: ", connection_->connected_);
      QUIC_BUG(quic_bug_10511_43) << error_detail;
    }
    connection_->OnEffectivePeerMigrationValidated(
        connection_->alternative_path_.server_connection_id ==
        connection_->default_path_.server_connection_id);
  } else {
    QUICHE_DCHECK(connection_->IsAlternativePath(
        context->self_address(), context->effective_peer_address()));
    QUIC_CODE_COUNT_N(quic_kick_off_client_address_validation, 4, 6);
    QUIC_DVLOG(1) << "Mark alternative peer address "
                  << context->effective_peer_address() << " validated.";
```
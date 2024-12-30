Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `QuicSentPacketManager` class in Chromium's QUIC implementation.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class:** The code is within the `QuicSentPacketManager` class. This class is responsible for managing sent packets in a QUIC connection.

2. **Analyze the Functions:** Go through each function in the snippet and understand its purpose:
    * `GetRetransmissionMode()`: Determines the current retransmission mode (Handshake, Loss, or PTO).
    * `RetransmitCryptoPackets()`: Specifically retransmits handshake packets.
    * `MaybeRetransmitOldestPacket()`:  Potentially retransmits the oldest sent, unacked packet.
    * `MaybeSendProbePacket()`: Sends probe packets to trigger acknowledgments when timers expire.
    * `EnableIetfPtoAndLossDetection()`: Enables the IETF standard for Probing Transmission and Loss Detection.
    * `RetransmitDataOfSpaceIfAny()`: Retransmits data from a specific packet number space (used with multiple packet number spaces).
    * `GetRetransmissionMode()`: (Again) Returns the retransmission mode.
    * `InvokeLossDetection()`: Runs the loss detection algorithm to identify lost packets.
    * `MaybeUpdateRTT()`: Updates the Round-Trip Time (RTT) estimate based on acknowledgments.
    * `TimeUntilSend()`: Determines how long to wait before sending the next packet, considering pacing and congestion control.
    * `GetRetransmissionTime()`: Calculates the next time a retransmission should occur.
    * `GetPathDegradingDelay()`: Calculates the delay to wait before considering the path degraded.
    * `GetNetworkBlackholeDelay()`: Calculates the delay to detect a network blackhole.
    * `GetMtuReductionDelay()`: Calculates the delay before attempting MTU reduction.
    * `GetCryptoRetransmissionDelay()`: Calculates the delay for retransmitting crypto packets.
    * `GetProbeTimeoutDelay()`: Calculates the Probe Timeout (PTO) delay.
    * `GetSlowStartDuration()`: Returns the duration of the slow start phase.
    * `GetAvailableCongestionWindowInBytes()`: Calculates the available space in the congestion window.
    * `GetDebugState()`: Retrieves debug information about the send algorithm.
    * `SetSendAlgorithm()`: Sets the congestion control algorithm.
    * `SetSendAlgorithm()`: (Overload) Sets a specific `SendAlgorithmInterface`.
    * `OnConnectionMigration()`: Handles actions when the connection migrates to a new path.
    * `OnAckFrameStart()`: Processes the beginning of an ACK frame.
    * `OnAckRange()`: Processes a range of acknowledged packets within an ACK frame.
    * `OnAckTimestamp()`: Records the timestamp of a specific acknowledged packet.
    * `IsEcnFeedbackValid()`: Validates Explicit Congestion Notification (ECN) feedback.
    * `OnAckFrameEnd()`: Processes the end of an ACK frame.
    * `SetDebugDelegate()`: Sets a delegate for debugging events.
    * `OnApplicationLimited()`:  Handles the case when the application is limiting the sending rate.
    * `GetNextReleaseTime()`: Gets the next time a packet can be released based on pacing.
    * `SetInitialRtt()`: Sets the initial RTT estimate.
    * `EnableMultiplePacketNumberSpacesSupport()`: Enables support for multiple packet number spaces.
    * `GetLargestAckedPacket()`: Gets the largest acknowledged packet number in a specific packet number space.
    * `GetLeastPacketAwaitedByPeer()`: Gets the smallest packet number the peer expects.
    * `GetLargestPacketPeerKnowsIsAcked()`: Gets the largest packet number the peer has acknowledged (in a specific space).
    * `GetNConsecutiveRetransmissionTimeoutDelay()`: Calculates the delay for a number of consecutive retransmission timeouts.
    * `PeerCompletedAddressValidation()`: Checks if the peer has completed address validation.

3. **Group Functionalities:**  Group the functions based on their high-level purpose. This leads to categories like:
    * **Retransmission Management:** Handling different types of retransmissions (crypto, oldest, probe).
    * **Loss Detection:** Implementing algorithms to detect packet loss.
    * **RTT and Timing:** Calculating and managing round-trip time and various timeouts.
    * **Congestion Control:** Interacting with the congestion control algorithm.
    * **ACK Processing:** Handling acknowledgment frames and ECN feedback.
    * **Connection Management:** Handling connection migration.
    * **Configuration and State:** Setting initial parameters and retrieving state information.

4. **Synthesize the Summary:** Write a concise summary based on the grouped functionalities. Focus on the overall role of the component.

5. **Address Specific Instructions:**  Review the instructions and ensure they are addressed:
    * **Function Listing:** The initial analysis covers this.
    * **Relationship to JavaScript:** While the code is C++, its functionality directly impacts network performance, which is relevant to JavaScript applications using QUIC over the network. Give an example of how slow retransmissions would affect a web application.
    * **Logical Inference (Hypothetical Input/Output):** Choose a function like `GetRetransmissionTime()` and provide a simple scenario and its expected outcome.
    * **Common Usage Errors:** Think about scenarios where incorrect configuration or assumptions could lead to issues. An example is incorrect RTT settings.
    * **User Operation to Reach Here (Debugging):** Explain the high-level user actions that would trigger this code to be involved (e.g., loading a webpage).
    * **Part 2 Summary:**  Rephrase the main functionality based on the specific code snippet provided. This involves focusing on the retransmission mechanisms, loss detection triggering, RTT updates, and timeout calculations. Emphasize the interaction with the congestion control algorithm.

6. **Refine and Organize:**  Ensure the summary is clear, well-organized, and easy to understand. Use bullet points or numbered lists for better readability.

By following these steps, a comprehensive and accurate summary of the provided code snippet can be generated, addressing all aspects of the user's request.
这是 `QuicSentPacketManager.cc` 文件的第二部分，主要涵盖了以下功能：

**核心功能归纳： 管理发送数据包的重传、拥塞控制和确认处理**

更细致的功能点包括：

* **重传机制的判断和触发:**
    *  `GetRetransmissionMode()`:  判断当前应采用哪种重传模式（握手重传、基于丢包的重传、PTO重传）。
    *  `RetransmitCryptoPackets()`:  专门用于重传握手阶段的加密数据包。
    *  `MaybeRetransmitOldestPacket()`:  尝试重传最老的未确认数据包，用于某些特定的重传场景。
    *  `MaybeSendProbePacket()`:  在定时器到期时，可能会发送探测包以触发对端确认。
    *  `EnableIetfPtoAndLossDetection()`:  启用 IETF 标准的 PTO（Probing Transmission）和丢包检测机制。
    *  `RetransmitDataOfSpaceIfAny()`:  针对多包号空间，重传特定空间的数据包。

* **丢包检测:**
    *  `InvokeLossDetection()`:  调用丢包检测算法来判断哪些数据包丢失，并标记需要重传。

* **RTT (Round-Trip Time) 计算和更新:**
    *  `MaybeUpdateRTT()`:  根据收到的 ACK 帧更新 RTT 估计值。

* **发送控制和定时:**
    *  `TimeUntilSend()`:  根据拥塞控制和 pacing 算法，判断还需要等待多久才能发送下一个数据包。
    *  `GetRetransmissionTime()`:  计算下一次重传应该发生的时间。
    *  `GetPathDegradingDelay()`:  计算路径降级的延迟时间。
    *  `GetNetworkBlackholeDelay()`:  计算网络黑洞检测的延迟时间。
    *  `GetMtuReductionDelay()`:  计算 MTU 缩减的延迟时间。
    *  `GetCryptoRetransmissionDelay()`:  计算握手数据包的重传延迟。
    *  `GetProbeTimeoutDelay()`:  计算 PTO 的超时延迟。
    *  `GetSlowStartDuration()`:  获取慢启动阶段的持续时间。
    *  `GetAvailableCongestionWindowInBytes()`:  计算当前可用的拥塞窗口大小。

* **拥塞控制算法的设置和调试:**
    *  `GetDebugState()`:  获取拥塞控制算法的调试状态信息。
    *  `SetSendAlgorithm()`:  设置使用的拥塞控制算法。

* **连接迁移处理:**
    *  `OnConnectionMigration()`:  处理连接迁移事件，包括重置拥塞控制状态和标记需要重传的旧路径数据包。

* **ACK 帧的处理:**
    *  `OnAckFrameStart()`:  开始处理 ACK 帧，初始化相关状态。
    *  `OnAckRange()`:  处理 ACK 帧中的确认范围。
    *  `OnAckTimestamp()`:  处理 ACK 帧中的时间戳信息。
    *  `IsEcnFeedbackValid()`:  验证收到的 ECN (Explicit Congestion Notification) 反馈是否有效。
    *  `OnAckFrameEnd()`:  完成 ACK 帧的处理，更新相关状态并通知拥塞控制算法。

* **调试支持:**
    *  `SetDebugDelegate()`:  设置调试委托，用于输出调试信息。

* **应用层限制处理:**
    *  `OnApplicationLimited()`:  当应用层限制发送速率时，通知拥塞控制算法。
    *  `GetNextReleaseTime()`:  获取基于 pacing 的下一次数据包发送时间。

* **初始 RTT 设置:**
    *  `SetInitialRtt()`:  设置连接的初始 RTT 值。

* **多包号空间支持:**
    *  `EnableMultiplePacketNumberSpacesSupport()`:  启用多包号空间的支持。
    *  `GetLargestAckedPacket()`:  获取特定加密级别的最大确认包号。
    *  `GetLeastPacketAwaitedByPeer()`:  获取对端期望接收的最小包号。
    *  `GetLargestPacketPeerKnowsIsAcked()`:  获取对端已知的最大确认包号。

* **计算连续重传超时延迟:**
    *  `GetNConsecutiveRetransmissionTimeoutDelay()`: 计算连续多次重传超时后的总延迟。

* **判断对端是否完成地址验证:**
    *  `PeerCompletedAddressValidation()`: 判断对端是否完成了地址验证过程。

**与 JavaScript 的关系：**

虽然这段代码是 C++ 实现的，但它直接影响着基于 Chromium 内核的浏览器中 QUIC 连接的性能。JavaScript 代码可以通过浏览器提供的 WebTransport 或 QUIC API 来利用 QUIC 协议。

例如：

* **网络延迟:** 如果 `QuicSentPacketManager` 的重传机制不高效，或者 RTT 估计不准确，会导致 JavaScript 发起的网络请求延迟增加，影响用户体验。
* **丢包率:**  如果丢包检测算法不够好，可能会导致不必要的重传，或者延迟重传，最终 JavaScript 感知到的就是网络不稳定，数据加载缓慢。
* **拥塞控制:** `QuicSentPacketManager` 中实现的拥塞控制算法直接决定了发送速率。如果算法过于保守，JavaScript 应用的网络吞吐量就会受限；如果过于激进，可能会导致网络拥塞。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `unacked_packets_` 中存在一些未确认的加密握手包。
* `consecutive_crypto_retransmission_count_` 为 2。

**函数:** `GetCryptoRetransmissionDelay()`

**预期输出:**  根据 `conservative_handshake_retransmits_` 的值，返回一个基于 RTT 的延迟时间，并且由于 `consecutive_crypto_retransmission_count_` 为 2，这个延迟时间会乘以 2 的平方（即 4）。  例如，如果保守模式未启用，并且 SRTT 为 100ms，那么返回的延迟可能接近 1.5 * 100ms * 4 = 600ms。

**用户或编程常见的使用错误：**

* **错误的初始 RTT 设置:**  如果在创建 `QuicSentPacketManager` 时设置了不准确的初始 RTT 值，会影响后续的重传超时计算和拥塞控制行为。例如，如果初始 RTT 设置过小，可能会导致过早的 PTO 重传。
* **不理解拥塞控制算法的影响:**  开发者可能不理解不同拥塞控制算法的特性，导致选择了不适合当前网络环境的算法，从而影响性能。
* **在调试时忽略关键日志:**  `QuicSentPacketManager` 提供了丰富的日志信息，如果开发者在调试网络问题时忽略这些日志，可能会难以定位问题根源。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个支持 QUIC 的网站。**
2. **浏览器尝试与服务器建立 QUIC 连接。**
3. **在连接建立的握手阶段，浏览器发送 ClientHello 等加密数据包。** 这些包的信息会被 `QuicSentPacketManager` 管理。
4. **如果这些握手包在一定时间内没有收到 ACK，`QuicSentPacketManager` 的定时器会触发。**
5. **`GetRetransmissionTime()` 会被调用，判断是否需要重传。** 如果判断需要重传，可能会进入 `RetransmitCryptoPackets()`。
6. **如果持续无法完成握手，`consecutive_crypto_retransmission_count_` 会增加。**
7. **用户可能会注意到网页加载缓慢或者连接超时，这可能是因为握手重传机制没有正常工作。**  开发者在调试时，可能会查看 `QuicSentPacketManager` 的状态和日志，分析重传延迟是否合理，以及是否触发了丢包检测。

总而言之，这段代码是 QUIC 协议中非常核心的组件，负责可靠地发送数据，处理网络拥塞，并确保连接的稳定性和性能。它的行为直接影响着用户在使用基于 QUIC 的网络应用时的体验。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
   << "Unknown retransmission mode " << GetRetransmissionMode();
  return GetRetransmissionMode();
}

void QuicSentPacketManager::RetransmitCryptoPackets() {
  QUICHE_DCHECK_EQ(HANDSHAKE_MODE, GetRetransmissionMode());
  ++consecutive_crypto_retransmission_count_;
  bool packet_retransmitted = false;
  std::vector<QuicPacketNumber> crypto_retransmissions;
  if (!unacked_packets_.empty()) {
    QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
    QuicPacketNumber largest_sent_packet =
        unacked_packets_.largest_sent_packet();
    for (; packet_number <= largest_sent_packet; ++packet_number) {
      QuicTransmissionInfo* transmission_info =
          unacked_packets_.GetMutableTransmissionInfo(packet_number);
      // Only retransmit frames which are in flight, and therefore have been
      // sent.
      if (!transmission_info->in_flight ||
          transmission_info->state != OUTSTANDING ||
          !transmission_info->has_crypto_handshake ||
          !unacked_packets_.HasRetransmittableFrames(*transmission_info)) {
        continue;
      }
      packet_retransmitted = true;
      crypto_retransmissions.push_back(packet_number);
      ++pending_timer_transmission_count_;
    }
  }
  QUICHE_DCHECK(packet_retransmitted)
      << "No crypto packets found to retransmit.";
  for (QuicPacketNumber retransmission : crypto_retransmissions) {
    MarkForRetransmission(retransmission, HANDSHAKE_RETRANSMISSION);
  }
}

bool QuicSentPacketManager::MaybeRetransmitOldestPacket(TransmissionType type) {
  if (!unacked_packets_.empty()) {
    QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
    QuicPacketNumber largest_sent_packet =
        unacked_packets_.largest_sent_packet();
    for (; packet_number <= largest_sent_packet; ++packet_number) {
      QuicTransmissionInfo* transmission_info =
          unacked_packets_.GetMutableTransmissionInfo(packet_number);
      // Only retransmit frames which are in flight, and therefore have been
      // sent.
      if (!transmission_info->in_flight ||
          transmission_info->state != OUTSTANDING ||
          !unacked_packets_.HasRetransmittableFrames(*transmission_info)) {
        continue;
      }
      MarkForRetransmission(packet_number, type);
      return true;
    }
  }
  QUIC_DVLOG(1)
      << "No retransmittable packets, so RetransmitOldestPacket failed.";
  return false;
}

void QuicSentPacketManager::MaybeSendProbePacket() {
  if (pending_timer_transmission_count_ == 0) {
    return;
  }
  PacketNumberSpace packet_number_space;
  if (supports_multiple_packet_number_spaces()) {
    // Find out the packet number space to send probe packets.
    if (!GetEarliestPacketSentTimeForPto(&packet_number_space)
             .IsInitialized()) {
      QUIC_BUG_IF(quic_earliest_sent_time_not_initialized,
                  unacked_packets_.perspective() == Perspective::IS_SERVER)
          << "earliest_sent_time not initialized when trying to send PTO "
             "retransmissions";
      return;
    }
  }
  std::vector<QuicPacketNumber> probing_packets;
  if (!unacked_packets_.empty()) {
    QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
    QuicPacketNumber largest_sent_packet =
        unacked_packets_.largest_sent_packet();
    for (; packet_number <= largest_sent_packet; ++packet_number) {
      QuicTransmissionInfo* transmission_info =
          unacked_packets_.GetMutableTransmissionInfo(packet_number);
      if (transmission_info->state == OUTSTANDING &&
          unacked_packets_.HasRetransmittableFrames(*transmission_info) &&
          (!supports_multiple_packet_number_spaces() ||
           unacked_packets_.GetPacketNumberSpace(
               transmission_info->encryption_level) == packet_number_space)) {
        QUICHE_DCHECK(transmission_info->in_flight);
        probing_packets.push_back(packet_number);
        if (probing_packets.size() == pending_timer_transmission_count_) {
          break;
        }
      }
    }
  }

  for (QuicPacketNumber retransmission : probing_packets) {
    QUIC_DVLOG(1) << ENDPOINT << "Marking " << retransmission
                  << " for probing retransmission";
    MarkForRetransmission(retransmission, PTO_RETRANSMISSION);
  }
  // It is possible that there is not enough outstanding data for probing.
}

void QuicSentPacketManager::EnableIetfPtoAndLossDetection() {
  // Disable handshake mode.
  handshake_mode_disabled_ = true;
}

void QuicSentPacketManager::RetransmitDataOfSpaceIfAny(
    PacketNumberSpace space) {
  QUICHE_DCHECK(supports_multiple_packet_number_spaces());
  if (!unacked_packets_.GetLastInFlightPacketSentTime(space).IsInitialized()) {
    // No in flight data of space.
    return;
  }
  if (unacked_packets_.empty()) {
    return;
  }
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  QuicPacketNumber largest_sent_packet = unacked_packets_.largest_sent_packet();
  for (; packet_number <= largest_sent_packet; ++packet_number) {
    QuicTransmissionInfo* transmission_info =
        unacked_packets_.GetMutableTransmissionInfo(packet_number);
    if (transmission_info->state == OUTSTANDING &&
        unacked_packets_.HasRetransmittableFrames(*transmission_info) &&
        unacked_packets_.GetPacketNumberSpace(
            transmission_info->encryption_level) == space) {
      QUICHE_DCHECK(transmission_info->in_flight);
      if (pending_timer_transmission_count_ == 0) {
        pending_timer_transmission_count_ = 1;
      }
      MarkForRetransmission(packet_number, PTO_RETRANSMISSION);
      return;
    }
  }
}

QuicSentPacketManager::RetransmissionTimeoutMode
QuicSentPacketManager::GetRetransmissionMode() const {
  QUICHE_DCHECK(unacked_packets_.HasInFlightPackets() ||
                (handshake_mode_disabled_ && !handshake_finished_));
  if (!handshake_mode_disabled_ && !handshake_finished_ &&
      unacked_packets_.HasPendingCryptoPackets()) {
    return HANDSHAKE_MODE;
  }
  if (loss_algorithm_->GetLossTimeout() != QuicTime::Zero()) {
    return LOSS_MODE;
  }
  return PTO_MODE;
}

void QuicSentPacketManager::InvokeLossDetection(QuicTime time) {
  if (!packets_acked_.empty()) {
    QUICHE_DCHECK_LE(packets_acked_.front().packet_number,
                     packets_acked_.back().packet_number);
    largest_newly_acked_ = packets_acked_.back().packet_number;
  }
  LossDetectionInterface::DetectionStats detection_stats =
      loss_algorithm_->DetectLosses(unacked_packets_, time, rtt_stats_,
                                    largest_newly_acked_, packets_acked_,
                                    &packets_lost_);

  if (detection_stats.sent_packets_max_sequence_reordering >
      stats_->sent_packets_max_sequence_reordering) {
    stats_->sent_packets_max_sequence_reordering =
        detection_stats.sent_packets_max_sequence_reordering;
  }

  stats_->sent_packets_num_borderline_time_reorderings +=
      detection_stats.sent_packets_num_borderline_time_reorderings;

  stats_->total_loss_detection_response_time +=
      detection_stats.total_loss_detection_response_time;

  for (const LostPacket& packet : packets_lost_) {
    QuicTransmissionInfo* info =
        unacked_packets_.GetMutableTransmissionInfo(packet.packet_number);
    ++stats_->packets_lost;
    if (debug_delegate_ != nullptr) {
      debug_delegate_->OnPacketLoss(packet.packet_number,
                                    info->encryption_level, LOSS_RETRANSMISSION,
                                    time);
    }
    unacked_packets_.RemoveFromInFlight(info);

    MarkForRetransmission(packet.packet_number, LOSS_RETRANSMISSION);
  }
}

bool QuicSentPacketManager::MaybeUpdateRTT(QuicPacketNumber largest_acked,
                                           QuicTime::Delta ack_delay_time,
                                           QuicTime ack_receive_time) {
  // We rely on ack_delay_time to compute an RTT estimate, so we
  // only update rtt when the largest observed gets acked and the acked packet
  // is not useless.
  if (!unacked_packets_.IsUnacked(largest_acked)) {
    return false;
  }
  // We calculate the RTT based on the highest ACKed packet number, the lower
  // packet numbers will include the ACK aggregation delay.
  const QuicTransmissionInfo& transmission_info =
      unacked_packets_.GetTransmissionInfo(largest_acked);
  // Ensure the packet has a valid sent time.
  if (transmission_info.sent_time == QuicTime::Zero()) {
    QUIC_BUG(quic_bug_10750_4)
        << "Acked packet has zero sent time, largest_acked:" << largest_acked;
    return false;
  }
  if (transmission_info.state == NOT_CONTRIBUTING_RTT) {
    return false;
  }
  if (transmission_info.sent_time > ack_receive_time) {
    QUIC_CODE_COUNT(quic_receive_acked_before_sending);
  }

  QuicTime::Delta send_delta = ack_receive_time - transmission_info.sent_time;
  const bool min_rtt_available = !rtt_stats_.min_rtt().IsZero();
  rtt_stats_.UpdateRtt(send_delta, ack_delay_time, ack_receive_time);

  if (!min_rtt_available && !rtt_stats_.min_rtt().IsZero()) {
    loss_algorithm_->OnMinRttAvailable();
  }

  return true;
}

QuicTime::Delta QuicSentPacketManager::TimeUntilSend(QuicTime now) const {
  // The TLP logic is entirely contained within QuicSentPacketManager, so the
  // send algorithm does not need to be consulted.
  if (pending_timer_transmission_count_ > 0) {
    return QuicTime::Delta::Zero();
  }

  if (using_pacing_) {
    return pacing_sender_.TimeUntilSend(now,
                                        unacked_packets_.bytes_in_flight());
  }

  return send_algorithm_->CanSend(unacked_packets_.bytes_in_flight())
             ? QuicTime::Delta::Zero()
             : QuicTime::Delta::Infinite();
}

const QuicTime QuicSentPacketManager::GetRetransmissionTime() const {
  if (!unacked_packets_.HasInFlightPackets() &&
      PeerCompletedAddressValidation()) {
    return QuicTime::Zero();
  }
  if (pending_timer_transmission_count_ > 0) {
    // Do not set the timer if there is any credit left.
    return QuicTime::Zero();
  }
  switch (GetRetransmissionMode()) {
    case HANDSHAKE_MODE:
      return unacked_packets_.GetLastCryptoPacketSentTime() +
             GetCryptoRetransmissionDelay();
    case LOSS_MODE:
      return loss_algorithm_->GetLossTimeout();
    case PTO_MODE: {
      if (!supports_multiple_packet_number_spaces()) {
        if (unacked_packets_.HasInFlightPackets() &&
            consecutive_pto_count_ == 0) {
          // Arm 1st PTO with earliest in flight sent time, and make sure at
          // least kFirstPtoSrttMultiplier * RTT has been passed since last
          // in flight packet.
          return std::max(
              clock_->ApproximateNow(),
              std::max(unacked_packets_.GetFirstInFlightTransmissionInfo()
                               ->sent_time +
                           GetProbeTimeoutDelay(NUM_PACKET_NUMBER_SPACES),
                       unacked_packets_.GetLastInFlightPacketSentTime() +
                           kFirstPtoSrttMultiplier *
                               rtt_stats_.SmoothedOrInitialRtt()));
        }
        // Ensure PTO never gets set to a time in the past.
        return std::max(clock_->ApproximateNow(),
                        unacked_packets_.GetLastInFlightPacketSentTime() +
                            GetProbeTimeoutDelay(NUM_PACKET_NUMBER_SPACES));
      }

      PacketNumberSpace packet_number_space = NUM_PACKET_NUMBER_SPACES;
      // earliest_right_edge is the earliest sent time of the last in flight
      // packet of all packet number spaces.
      QuicTime earliest_right_edge =
          GetEarliestPacketSentTimeForPto(&packet_number_space);
      if (!earliest_right_edge.IsInitialized()) {
        // Arm PTO from now if there is no in flight packets.
        earliest_right_edge = clock_->ApproximateNow();
      }
      if (packet_number_space == APPLICATION_DATA &&
          consecutive_pto_count_ == 0) {
        const QuicTransmissionInfo* first_application_info =
            unacked_packets_.GetFirstInFlightTransmissionInfoOfSpace(
                APPLICATION_DATA);
        if (first_application_info != nullptr) {
          // Arm 1st PTO with earliest in flight sent time, and make sure at
          // least kFirstPtoSrttMultiplier * RTT has been passed since last
          // in flight packet. Only do this for application data.
          return std::max(
              clock_->ApproximateNow(),
              std::max(
                  first_application_info->sent_time +
                      GetProbeTimeoutDelay(packet_number_space),
                  earliest_right_edge + kFirstPtoSrttMultiplier *
                                            rtt_stats_.SmoothedOrInitialRtt()));
        }
      }
      return std::max(
          clock_->ApproximateNow(),
          earliest_right_edge + GetProbeTimeoutDelay(packet_number_space));
    }
  }
  QUICHE_DCHECK(false);
  return QuicTime::Zero();
}

const QuicTime::Delta QuicSentPacketManager::GetPathDegradingDelay() const {
  QUICHE_DCHECK_GT(num_ptos_for_path_degrading_, 0);
  return num_ptos_for_path_degrading_ * GetPtoDelay();
}

const QuicTime::Delta QuicSentPacketManager::GetNetworkBlackholeDelay(
    int8_t num_rtos_for_blackhole_detection) const {
  return GetNConsecutiveRetransmissionTimeoutDelay(
      kDefaultMaxTailLossProbes + num_rtos_for_blackhole_detection);
}

QuicTime::Delta QuicSentPacketManager::GetMtuReductionDelay(
    int8_t num_rtos_for_blackhole_detection) const {
  return GetNetworkBlackholeDelay(num_rtos_for_blackhole_detection / 2);
}

const QuicTime::Delta QuicSentPacketManager::GetCryptoRetransmissionDelay()
    const {
  // This is equivalent to the TailLossProbeDelay, but slightly more aggressive
  // because crypto handshake messages don't incur a delayed ack time.
  QuicTime::Delta srtt = rtt_stats_.SmoothedOrInitialRtt();
  int64_t delay_ms;
  if (conservative_handshake_retransmits_) {
    // Using the delayed ack time directly could cause conservative handshake
    // retransmissions to actually be more aggressive than the default.
    delay_ms = std::max(peer_max_ack_delay_.ToMilliseconds(),
                        static_cast<int64_t>(2 * srtt.ToMilliseconds()));
  } else {
    delay_ms = std::max(kMinHandshakeTimeoutMs,
                        static_cast<int64_t>(1.5 * srtt.ToMilliseconds()));
  }
  return QuicTime::Delta::FromMilliseconds(
      delay_ms << consecutive_crypto_retransmission_count_);
}

const QuicTime::Delta QuicSentPacketManager::GetProbeTimeoutDelay(
    PacketNumberSpace space) const {
  if (rtt_stats_.smoothed_rtt().IsZero()) {
    // Respect kMinHandshakeTimeoutMs to avoid a potential amplification attack.
    QUIC_BUG_IF(quic_bug_12552_6, rtt_stats_.initial_rtt().IsZero());
    return std::max(kPtoMultiplierWithoutRttSamples * rtt_stats_.initial_rtt(),
                    QuicTime::Delta::FromMilliseconds(kMinHandshakeTimeoutMs)) *
           (1 << consecutive_pto_count_);
  }
  QuicTime::Delta pto_delay =
      rtt_stats_.smoothed_rtt() +
      std::max(kPtoRttvarMultiplier * rtt_stats_.mean_deviation(),
               kAlarmGranularity) +
      (ShouldAddMaxAckDelay(space) ? peer_max_ack_delay_
                                   : QuicTime::Delta::Zero());
  return pto_delay * (1 << consecutive_pto_count_);
}

QuicTime::Delta QuicSentPacketManager::GetSlowStartDuration() const {
  if (send_algorithm_->GetCongestionControlType() == kBBR ||
      send_algorithm_->GetCongestionControlType() == kBBRv2) {
    return stats_->slowstart_duration.GetTotalElapsedTime(
        clock_->ApproximateNow());
  }
  return QuicTime::Delta::Infinite();
}

QuicByteCount QuicSentPacketManager::GetAvailableCongestionWindowInBytes()
    const {
  QuicByteCount congestion_window = GetCongestionWindowInBytes();
  QuicByteCount bytes_in_flight = GetBytesInFlight();
  return congestion_window - std::min(congestion_window, bytes_in_flight);
}

std::string QuicSentPacketManager::GetDebugState() const {
  return send_algorithm_->GetDebugState();
}

void QuicSentPacketManager::SetSendAlgorithm(
    CongestionControlType congestion_control_type) {
  if (send_algorithm_ &&
      send_algorithm_->GetCongestionControlType() == congestion_control_type) {
    return;
  }

  SetSendAlgorithm(SendAlgorithmInterface::Create(
      clock_, &rtt_stats_, &unacked_packets_, congestion_control_type, random_,
      stats_, initial_congestion_window_, send_algorithm_.get()));
}

void QuicSentPacketManager::SetSendAlgorithm(
    SendAlgorithmInterface* send_algorithm) {
  if (debug_delegate_ != nullptr && send_algorithm != nullptr) {
    debug_delegate_->OnSendAlgorithmChanged(
        send_algorithm->GetCongestionControlType());
  }
  send_algorithm_.reset(send_algorithm);
  pacing_sender_.set_sender(send_algorithm);
}

std::unique_ptr<SendAlgorithmInterface>
QuicSentPacketManager::OnConnectionMigration(bool reset_send_algorithm) {
  consecutive_pto_count_ = 0;
  rtt_stats_.OnConnectionMigration();
  if (!reset_send_algorithm) {
    send_algorithm_->OnConnectionMigration();
    return nullptr;
  }

  std::unique_ptr<SendAlgorithmInterface> old_send_algorithm =
      std::move(send_algorithm_);
  SetSendAlgorithm(old_send_algorithm->GetCongestionControlType());
  // Treat all in flight packets sent to the old peer address as lost and
  // retransmit them.
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  for (auto it = unacked_packets_.begin(); it != unacked_packets_.end();
       ++it, ++packet_number) {
    if (it->in_flight) {
      // Proactively retransmit any packet which is in flight on the old path.
      // As a result, these packets will not contribute to congestion control.
      unacked_packets_.RemoveFromInFlight(packet_number);
      // Retransmitting these packets with PATH_CHANGE_RETRANSMISSION will mark
      // them as useless, thus not contributing to RTT stats.
      if (unacked_packets_.HasRetransmittableFrames(packet_number)) {
        MarkForRetransmission(packet_number, PATH_RETRANSMISSION);
        QUICHE_DCHECK_EQ(it->state, NOT_CONTRIBUTING_RTT);
      }
    }
    it->state = NOT_CONTRIBUTING_RTT;
  }
  return old_send_algorithm;
}

void QuicSentPacketManager::OnAckFrameStart(QuicPacketNumber largest_acked,
                                            QuicTime::Delta ack_delay_time,
                                            QuicTime ack_receive_time) {
  QUICHE_DCHECK(packets_acked_.empty());
  QUICHE_DCHECK_LE(largest_acked, unacked_packets_.largest_sent_packet());
  // Ignore peer_max_ack_delay and use received ack_delay during
  // handshake when supporting multiple packet number spaces.
  if (!supports_multiple_packet_number_spaces() || handshake_finished_) {
    if (ack_delay_time > peer_max_ack_delay()) {
      ack_delay_time = peer_max_ack_delay();
    }
    if (ignore_ack_delay_) {
      ack_delay_time = QuicTime::Delta::Zero();
    }
  }
  rtt_updated_ =
      MaybeUpdateRTT(largest_acked, ack_delay_time, ack_receive_time);
  last_ack_frame_.ack_delay_time = ack_delay_time;
  acked_packets_iter_ = last_ack_frame_.packets.rbegin();
}

void QuicSentPacketManager::OnAckRange(QuicPacketNumber start,
                                       QuicPacketNumber end) {
  if (!last_ack_frame_.largest_acked.IsInitialized() ||
      end > last_ack_frame_.largest_acked + 1) {
    // Largest acked increases.
    unacked_packets_.IncreaseLargestAcked(end - 1);
    last_ack_frame_.largest_acked = end - 1;
  }
  // Drop ack ranges which ack packets below least_unacked.
  QuicPacketNumber least_unacked = unacked_packets_.GetLeastUnacked();
  if (least_unacked.IsInitialized() && end <= least_unacked) {
    return;
  }
  start = std::max(start, least_unacked);
  do {
    QuicPacketNumber newly_acked_start = start;
    if (acked_packets_iter_ != last_ack_frame_.packets.rend()) {
      newly_acked_start = std::max(start, acked_packets_iter_->max());
    }
    for (QuicPacketNumber acked = end - 1; acked >= newly_acked_start;
         --acked) {
      // Check if end is above the current range. If so add newly acked packets
      // in descending order.
      packets_acked_.push_back(AckedPacket(acked, 0, QuicTime::Zero()));
      if (acked == FirstSendingPacketNumber()) {
        break;
      }
    }
    if (acked_packets_iter_ == last_ack_frame_.packets.rend() ||
        start > acked_packets_iter_->min()) {
      // Finish adding all newly acked packets.
      return;
    }
    end = std::min(end, acked_packets_iter_->min());
    ++acked_packets_iter_;
  } while (start < end);
}

void QuicSentPacketManager::OnAckTimestamp(QuicPacketNumber packet_number,
                                           QuicTime timestamp) {
  last_ack_frame_.received_packet_times.push_back({packet_number, timestamp});
  for (AckedPacket& packet : packets_acked_) {
    if (packet.packet_number == packet_number) {
      packet.receive_timestamp = timestamp;
      return;
    }
  }
}

bool QuicSentPacketManager::IsEcnFeedbackValid(
    PacketNumberSpace space, const std::optional<QuicEcnCounts>& ecn_counts,
    QuicPacketCount newly_acked_ect0, QuicPacketCount newly_acked_ect1) {
  if (!ecn_counts.has_value()) {
    if (newly_acked_ect0 > 0 || newly_acked_ect1 > 0) {
      QUIC_DVLOG(1) << ENDPOINT
                    << "ECN packets acknowledged, no counts reported.";
      return false;
    }
    return true;
  }
  if (ecn_counts->ect0 < peer_ack_ecn_counts_[space].ect0 ||
      ecn_counts->ect1 < peer_ack_ecn_counts_[space].ect1 ||
      ecn_counts->ce < peer_ack_ecn_counts_[space].ce) {
    QUIC_DVLOG(1) << ENDPOINT << "Reported ECN count declined.";
    return false;
  }
  if (ecn_counts->ect0 > ect0_packets_sent_[space] ||
      ecn_counts->ect1 > ect1_packets_sent_[space] ||
      (ecn_counts->ect0 + ecn_counts->ect1 + ecn_counts->ce >
       ect0_packets_sent_[space] + ect1_packets_sent_[space])) {
    QUIC_DVLOG(1) << ENDPOINT << "Reported ECT + CE exceeds packets sent:"
                  << " reported " << ecn_counts->ToString() << " , ECT(0) sent "
                  << ect0_packets_sent_[space] << " , ECT(1) sent "
                  << ect1_packets_sent_[space];
    return false;
  }
  if ((newly_acked_ect0 >
       (ecn_counts->ect0 + ecn_counts->ce - peer_ack_ecn_counts_[space].ect0 +
        peer_ack_ecn_counts_[space].ce)) ||
      (newly_acked_ect1 >
       (ecn_counts->ect1 + ecn_counts->ce - peer_ack_ecn_counts_[space].ect1 +
        peer_ack_ecn_counts_[space].ce))) {
    QUIC_DVLOG(1) << ENDPOINT
                  << "Peer acked packet but did not report the ECN mark: "
                  << " New ECN counts: " << ecn_counts->ToString()
                  << " Old ECN counts: "
                  << peer_ack_ecn_counts_[space].ToString()
                  << " Newly acked ECT(0) : " << newly_acked_ect0
                  << " Newly acked ECT(1) : " << newly_acked_ect1;
    return false;
  }
  return true;
}

AckResult QuicSentPacketManager::OnAckFrameEnd(
    QuicTime ack_receive_time, QuicPacketNumber ack_packet_number,
    EncryptionLevel ack_decrypted_level,
    const std::optional<QuicEcnCounts>& ecn_counts) {
  QuicByteCount prior_bytes_in_flight = unacked_packets_.bytes_in_flight();
  QuicPacketCount newly_acked_ect0 = 0;
  QuicPacketCount newly_acked_ect1 = 0;
  PacketNumberSpace acked_packet_number_space =
      QuicUtils::GetPacketNumberSpace(ack_decrypted_level);
  QuicPacketNumber old_largest_acked =
      unacked_packets_.GetLargestAckedOfPacketNumberSpace(
          acked_packet_number_space);
  // Reverse packets_acked_ so that it is in ascending order.
  std::reverse(packets_acked_.begin(), packets_acked_.end());
  for (AckedPacket& acked_packet : packets_acked_) {
    QuicTransmissionInfo* info =
        unacked_packets_.GetMutableTransmissionInfo(acked_packet.packet_number);
    if (!QuicUtils::IsAckable(info->state)) {
      if (info->state == ACKED) {
        QUIC_BUG(quic_bug_10750_5)
            << "Trying to ack an already acked packet: "
            << acked_packet.packet_number
            << ", last_ack_frame_: " << last_ack_frame_
            << ", least_unacked: " << unacked_packets_.GetLeastUnacked()
            << ", packets_acked_: " << quiche::PrintElements(packets_acked_);
      } else {
        QUIC_PEER_BUG(quic_peer_bug_10750_6)
            << "Received " << ack_decrypted_level
            << " ack for unackable packet: " << acked_packet.packet_number
            << " with state: "
            << QuicUtils::SentPacketStateToString(info->state);
        if (supports_multiple_packet_number_spaces()) {
          if (info->state == NEVER_SENT) {
            return UNSENT_PACKETS_ACKED;
          }
          return UNACKABLE_PACKETS_ACKED;
        }
      }
      continue;
    }
    QUIC_DVLOG(1) << ENDPOINT << "Got an " << ack_decrypted_level
                  << " ack for packet " << acked_packet.packet_number
                  << " , state: "
                  << QuicUtils::SentPacketStateToString(info->state);
    const PacketNumberSpace packet_number_space =
        unacked_packets_.GetPacketNumberSpace(info->encryption_level);
    if (supports_multiple_packet_number_spaces() &&
        QuicUtils::GetPacketNumberSpace(ack_decrypted_level) !=
            packet_number_space) {
      return PACKETS_ACKED_IN_WRONG_PACKET_NUMBER_SPACE;
    }
    last_ack_frame_.packets.Add(acked_packet.packet_number);
    if (info->encryption_level == ENCRYPTION_HANDSHAKE) {
      handshake_packet_acked_ = true;
    } else if (info->encryption_level == ENCRYPTION_ZERO_RTT) {
      zero_rtt_packet_acked_ = true;
    } else if (info->encryption_level == ENCRYPTION_FORWARD_SECURE) {
      one_rtt_packet_acked_ = true;
    }
    largest_packet_peer_knows_is_acked_.UpdateMax(info->largest_acked);
    if (supports_multiple_packet_number_spaces()) {
      largest_packets_peer_knows_is_acked_[packet_number_space].UpdateMax(
          info->largest_acked);
    }
    // If data is associated with the most recent transmission of this
    // packet, then inform the caller.
    if (info->in_flight) {
      acked_packet.bytes_acked = info->bytes_sent;
    } else {
      acked_packet.spurious_loss = (info->state == LOST);
      // Unackable packets are skipped earlier.
      largest_newly_acked_ = acked_packet.packet_number;
    }
    switch (info->ecn_codepoint) {
      case ECN_NOT_ECT:
        break;
      case ECN_CE:
        // ECN_CE should only happen in tests. Feedback validation doesn't track
        // newly acked CEs, and if newly_acked_ect0 and newly_acked_ect1 are
        // lower than expected that won't fail validation. So when it's CE don't
        // increment anything.
        break;
      case ECN_ECT0:
        ++newly_acked_ect0;
        if (info->in_flight) {
          network_change_visitor_->OnInFlightEcnPacketAcked();
        }
        break;
      case ECN_ECT1:
        ++newly_acked_ect1;
        if (info->in_flight) {
          network_change_visitor_->OnInFlightEcnPacketAcked();
        }
        break;
    }
    unacked_packets_.MaybeUpdateLargestAckedOfPacketNumberSpace(
        packet_number_space, acked_packet.packet_number);
    MarkPacketHandled(acked_packet.packet_number, info, ack_receive_time,
                      last_ack_frame_.ack_delay_time,
                      acked_packet.receive_timestamp);
  }
  // Copy raw ECN counts to last_ack_frame_ so it is logged properly. Validated
  // ECN counts are stored in valid_ecn_counts, and the congestion controller
  // uses that for processing.
  last_ack_frame_.ecn_counters = ecn_counts;
  // Validate ECN feedback.
  std::optional<QuicEcnCounts> valid_ecn_counts;
  if (GetQuicRestartFlag(quic_support_ect1)) {
    QUIC_RESTART_FLAG_COUNT_N(quic_support_ect1, 1, 9);
    if (IsEcnFeedbackValid(acked_packet_number_space, ecn_counts,
                           newly_acked_ect0, newly_acked_ect1)) {
      valid_ecn_counts = ecn_counts;
    } else if (!old_largest_acked.IsInitialized() ||
               old_largest_acked <
                   unacked_packets_.GetLargestAckedOfPacketNumberSpace(
                       acked_packet_number_space)) {
      // RFC 9000 S13.4.2.1: "An endpoint MUST NOT fail ECN validation as a
      // result of processing an ACK frame that does not increase the largest
      // acknowledged packet number."
      network_change_visitor_->OnInvalidEcnFeedback();
    }
  }
  const bool acked_new_packet = !packets_acked_.empty();
  PostProcessNewlyAckedPackets(ack_packet_number, ack_decrypted_level,
                               last_ack_frame_, ack_receive_time, rtt_updated_,
                               prior_bytes_in_flight, valid_ecn_counts);
  if (valid_ecn_counts.has_value()) {
    peer_ack_ecn_counts_[acked_packet_number_space] = *valid_ecn_counts;
  }
  return acked_new_packet ? PACKETS_NEWLY_ACKED : NO_PACKETS_NEWLY_ACKED;
}

void QuicSentPacketManager::SetDebugDelegate(DebugDelegate* debug_delegate) {
  debug_delegate_ = debug_delegate;
}

void QuicSentPacketManager::OnApplicationLimited() {
  if (using_pacing_) {
    pacing_sender_.OnApplicationLimited();
  }
  send_algorithm_->OnApplicationLimited(unacked_packets_.bytes_in_flight());
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnApplicationLimited();
  }
}

NextReleaseTimeResult QuicSentPacketManager::GetNextReleaseTime() const {
  if (!using_pacing_) {
    return {QuicTime::Zero(), false};
  }

  return pacing_sender_.GetNextReleaseTime();
}

void QuicSentPacketManager::SetInitialRtt(QuicTime::Delta rtt, bool trusted) {
  const QuicTime::Delta min_rtt = QuicTime::Delta::FromMicroseconds(
      trusted ? kMinTrustedInitialRoundTripTimeUs
              : kMinUntrustedInitialRoundTripTimeUs);
  QuicTime::Delta max_rtt =
      QuicTime::Delta::FromMicroseconds(kMaxInitialRoundTripTimeUs);
  rtt_stats_.set_initial_rtt(std::max(min_rtt, std::min(max_rtt, rtt)));
}

void QuicSentPacketManager::EnableMultiplePacketNumberSpacesSupport() {
  EnableIetfPtoAndLossDetection();
  unacked_packets_.EnableMultiplePacketNumberSpacesSupport();
}

QuicPacketNumber QuicSentPacketManager::GetLargestAckedPacket(
    EncryptionLevel decrypted_packet_level) const {
  QUICHE_DCHECK(supports_multiple_packet_number_spaces());
  return unacked_packets_.GetLargestAckedOfPacketNumberSpace(
      QuicUtils::GetPacketNumberSpace(decrypted_packet_level));
}

QuicPacketNumber QuicSentPacketManager::GetLeastPacketAwaitedByPeer(
    EncryptionLevel encryption_level) const {
  QuicPacketNumber largest_acked;
  if (supports_multiple_packet_number_spaces()) {
    largest_acked = GetLargestAckedPacket(encryption_level);
  } else {
    largest_acked = GetLargestObserved();
  }
  if (!largest_acked.IsInitialized()) {
    // If no packets have been acked, return the first sent packet to ensure
    // we use a large enough packet number length.
    return FirstSendingPacketNumber();
  }
  QuicPacketNumber least_awaited = largest_acked + 1;
  QuicPacketNumber least_unacked = GetLeastUnacked();
  if (least_unacked.IsInitialized() && least_unacked < least_awaited) {
    least_awaited = least_unacked;
  }
  return least_awaited;
}

QuicPacketNumber QuicSentPacketManager::GetLargestPacketPeerKnowsIsAcked(
    EncryptionLevel decrypted_packet_level) const {
  QUICHE_DCHECK(supports_multiple_packet_number_spaces());
  return largest_packets_peer_knows_is_acked_[QuicUtils::GetPacketNumberSpace(
      decrypted_packet_level)];
}

QuicTime::Delta
QuicSentPacketManager::GetNConsecutiveRetransmissionTimeoutDelay(
    int num_timeouts) const {
  QuicTime::Delta total_delay = QuicTime::Delta::Zero();
  const QuicTime::Delta srtt = rtt_stats_.SmoothedOrInitialRtt();
  int num_tlps =
      std::min(num_timeouts, static_cast<int>(kDefaultMaxTailLossProbes));
  num_timeouts -= num_tlps;
  if (num_tlps > 0) {
    const QuicTime::Delta tlp_delay = std::max(
        2 * srtt,
        unacked_packets_.HasMultipleInFlightPackets()
            ? QuicTime::Delta::FromMilliseconds(kMinTailLossProbeTimeoutMs)
            : (1.5 * srtt +
               (QuicTime::Delta::FromMilliseconds(kMinRetransmissionTimeMs) *
                0.5)));
    total_delay = total_delay + num_tlps * tlp_delay;
  }
  if (num_timeouts == 0) {
    return total_delay;
  }

  const QuicTime::Delta retransmission_delay =
      rtt_stats_.smoothed_rtt().IsZero()
          ? QuicTime::Delta::FromMilliseconds(kDefaultRetransmissionTimeMs)
          : std::max(
                srtt + 4 * rtt_stats_.mean_deviation(),
                QuicTime::Delta::FromMilliseconds(kMinRetransmissionTimeMs));
  total_delay = total_delay + ((1 << num_timeouts) - 1) * retransmission_delay;
  return total_delay;
}

bool QuicSentPacketManager::PeerCompletedAddressValidation() const {
  if 
"""


```
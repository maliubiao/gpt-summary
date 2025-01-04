Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium network stack file. The file is related to managing sent QUIC packets. I need to analyze the test cases to understand the functionalities being tested.

Here's a breakdown of the test cases and their corresponding functionalities:

* **RttWith...Delta:**  These tests (`RttWithAckDelay`, `RttWithInfiniteDelta`, `RttWithDeltaExceedingLimit`, `RttZeroDelta`) focus on how the `QuicSentPacketManager` calculates Round Trip Time (RTT) based on the acknowledgement delay.
* **CryptoHandshakeTimeout/SpuriousRetransmission:** These tests examine the behavior of the manager during the QUIC handshake when crypto packets are lost or spuriously retransmitted, including how retransmissions are handled and how the manager reacts to acknowledgements after retransmissions.
* **GetTransmissionTime...:** These tests verify how the retransmission timeout is calculated, particularly during the crypto handshake, and explore the impact of connection options on this calculation.
* **GetLossDelay:** This test checks how the manager interacts with a loss detection algorithm to determine when to trigger a retransmission due to loss.
* **NegotiateIetfLossDetectionFromOptions:** These tests explore how different IETF loss detection mechanisms are negotiated via connection options.
* **NegotiateCongestionControlFromOptions:** These tests verify how different congestion control algorithms are negotiated via connection options for both the server and client sides.
* **UseInitialRoundTripTimeToSend:** This test checks if the manager can be configured to use an initial RTT value provided in the connection configuration.
* **ResumeConnectionState:** This test examines how the manager resumes a connection using cached network parameters, specifically focusing on RTT.
* **ConnectionMigrationUnspecifiedChange...:** These tests focus on how the manager handles connection migration events, including resetting the congestion control algorithm and handling in-flight and unacknowledged packets.

Based on this analysis, the core functionality is managing the state of sent QUIC packets, including:

1. **Tracking packet state:**  Knowing which packets have been sent, acknowledged, lost, or are awaiting acknowledgement.
2. **RTT estimation:** Calculating and updating the round-trip time.
3. **Retransmission management:**  Determining when to retransmit lost packets (both data and crypto packets) and handling spurious retransmissions.
4. **Congestion control:** Interacting with a congestion control algorithm to manage the sending rate.
5. **Loss detection:** Utilizing a loss detection algorithm to identify lost packets.
6. **Handling connection migration:** Adapting to changes in the network path.
7. **Negotiating features:**  Using connection options to agree on loss detection and congestion control algorithms.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc` 文件的一部分，它主要测试了 `QuicSentPacketManager` 的以下功能：

**核心功能归纳：**

这部分代码主要测试了 `QuicSentPacketManager` 在接收到 ACK 帧时的行为，以及在处理加密握手超时和连接迁移时的行为。具体来说，它测试了以下几个方面：

1. **RTT (Round Trip Time) 计算:**
   - 测试了在收到 ACK 时，如何根据 `ack_delay_time` (来自对端的 ACK 延迟信息) 和本地时间计算 RTT。
   - 验证了在 `ack_delay_time` 为无限大或超出限制时，RTT 的计算逻辑。
   - 验证了 `ack_delay_time` 为零时的 RTT 计算。

2. **加密握手超时处理:**
   - 测试了在加密握手期间，当发送的加密包超时未收到 ACK 时，`QuicSentPacketManager` 如何触发重传。
   - 验证了重传的机制，包括指数退避。
   - 测试了在重传后，如果原始的或重传的加密包收到 ACK，如何正确处理，以及如何识别并丢弃冗余的重传包。
   - 测试了在握手过程中，如果数据包尚未被发送就触发超时，如何处理。
   - 验证了在加密握手完成（例如，进入前向安全加密状态）后，如何“中和” (neuter) 尚未被 ACK 的未加密数据包。

3. **获取重传时间:**
   - 测试了在加密握手期间，如何计算下一次重传的时间，包括考虑初始 RTT 和指数退避。
   - 验证了在启用保守的重传定时器（例如，通过 `kCONH` 连接选项）时，重传时间的计算逻辑。

4. **损失延迟 (Loss Delay) 计算:**
   - 测试了如何使用损失检测算法来确定何时触发超时并声明丢包。

5. **协商 IETF 丢包检测算法:**
   - 测试了如何通过连接选项协商不同的 IETF 丢包检测算法 (例如 `kILD0`, `kILD1`, `kILD2`, `kILD3`, `kILD4`)。

6. **协商拥塞控制算法:**
   - 测试了如何通过连接选项协商不同的拥塞控制算法 (例如 `kRENO`, `kTBBR`, `kBYTE`, `kPRGC`)。
   - 区分了服务端和客户端在协商拥塞控制算法时的行为。

7. **使用初始 RTT 发送:**
   - 测试了如何使用配置中指定的初始 RTT 值。

8. **恢复连接状态:**
   - 测试了如何使用缓存的网络参数（例如，最小 RTT）来恢复连接状态。

9. **连接迁移:**
   - 测试了在连接迁移时，`QuicSentPacketManager` 如何处理，包括重置拥塞控制算法和 RTT 统计信息。
   - 验证了在连接迁移后，如何处理之前发送但尚未 ACK 的数据包，以及如何避免将迁移前发送的包计入拥塞控制。

**与 JavaScript 功能的关系：**

`QuicSentPacketManager` 是 Chromium 网络栈的底层 C++ 组件，直接与 JavaScript 没有直接的功能对应关系。然而，JavaScript 代码（例如在浏览器中运行的 Web 应用）可以通过浏览器提供的 API（例如 Fetch API、WebSocket API）来发起网络请求。当底层使用 QUIC 协议时，`QuicSentPacketManager` 负责管理这些请求的发送、重传和拥塞控制。

**举例说明：**

假设一个 JavaScript 应用使用 Fetch API 发送一个 HTTP/3 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，如果底层使用了 QUIC 协议，`QuicSentPacketManager` 会处理以下情况（与这段 C++ 测试代码相关）：

* **RTT 计算：** 当服务器响应到达时，服务器发送的 ACK 帧会包含 `ack_delay_time`。`QuicSentPacketManager` 会根据这个信息和本地时间计算 RTT，以便更好地进行拥塞控制和重传决策。
* **加密握手超时：** 在连接建立的早期阶段，如果发送的加密握手包丢失或延迟，`QuicSentPacketManager` 会触发重传，确保连接能够建立。
* **连接迁移：** 如果用户的网络发生变化（例如，从 Wi-Fi 切换到移动网络），`QuicSentPacketManager` 需要处理连接迁移，可能需要重置拥塞控制状态，避免旧的网络状态影响新的网络连接。

**逻辑推理与假设输入输出：**

**示例：RTT 计算**

**假设输入：**

* 发送数据包的时间 (send_time): `T0`
* 接收到 ACK 的时间 (ack_receive_time): `T1`
* ACK 帧中携带的 `ack_delay_time`: `Delta_ack`

**逻辑：**

`latest_rtt = (T1 - T0) - Delta_ack`

**预期输出：**

* `manager_.GetRttStats()->latest_rtt()` 的值应该等于 `latest_rtt`。

**示例：加密握手超时重传**

**假设输入：**

* 发送了加密握手包 P1。
* 超时时间到达，未收到 P1 的 ACK。

**逻辑：**

`QuicSentPacketManager` 会触发重传机制。

**预期输出：**

* 调用 `notifier_.RetransmitFrames()` 发送重传包 P2 (包号不同于 P1)。
* 内部状态更新，记录 P2 的发送时间。

**用户或编程常见的使用错误：**

1. **不正确的 ACK 延迟设置：**  如果对端实现的 ACK 延迟信息不准确，会导致 RTT 计算错误，影响拥塞控制和重传策略。
2. **错误的连接选项配置：**  配置不兼容的或错误的连接选项（例如，同时启用冲突的丢包检测算法）可能导致连接行为异常。
3. **在连接迁移后仍然依赖旧的连接状态：**  开发者需要确保在连接迁移后，应用程序能够适应新的网络状况，避免因依赖旧的连接状态而导致问题。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户发起网络请求：** 用户在浏览器中访问一个使用了 QUIC 协议的网站，或者 JavaScript 代码通过 Fetch API 或 WebSocket API 发起了一个 QUIC 连接。
2. **连接建立阶段：**  `QuicSentPacketManager` 负责发送和管理加密握手包。如果网络不稳定，可能会出现包丢失或延迟。
3. **收到 ACK：** 当远端服务器发送 ACK 帧时，这些帧会被传递给 `QuicSentPacketManager` 进行处理。
4. **触发 RTT 计算/超时/连接迁移：**  根据 ACK 帧的内容、本地时间以及网络状况，`QuicSentPacketManager` 会进行 RTT 计算、检测超时或处理连接迁移事件。
5. **调试线索：** 如果网络连接出现问题（例如，连接速度慢、连接中断），开发者可以通过查看 Chromium 的网络日志（`chrome://net-export/`）来分析底层的 QUIC 行为，包括查看发送的包、接收到的 ACK、RTT 值、超时事件等，从而定位到 `QuicSentPacketManager` 的相关代码进行调试。

总而言之，这部分代码专注于测试 `QuicSentPacketManager` 在关键网络事件（接收 ACK、超时、连接迁移）下的核心逻辑和状态管理，确保 QUIC 连接的可靠性和性能。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
::Delta::FromMilliseconds(11), clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(expected_rtt, manager_.GetRttStats()->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, RttWithInfiniteDelta) {
  // Expect that the RTT is equal to the local time elapsed, since the
  // ack_delay_time is infinite, and is hence invalid.
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(1);
  clock_.AdvanceTime(expected_rtt);

  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(expected_rtt, manager_.GetRttStats()->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, RttWithDeltaExceedingLimit) {
  // Initialize min and smoothed rtt to 10ms.
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(10),
                       QuicTime::Delta::Zero(), QuicTime::Zero());

  QuicTime::Delta send_delta = QuicTime::Delta::FromMilliseconds(100);
  QuicTime::Delta ack_delay =
      QuicTime::Delta::FromMilliseconds(5) + manager_.peer_max_ack_delay();
  ASSERT_GT(send_delta - rtt_stats->min_rtt(), ack_delay);
  SendDataPacket(1);
  clock_.AdvanceTime(send_delta);

  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), ack_delay, clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));

  QuicTime::Delta expected_rtt_sample =
      send_delta - manager_.peer_max_ack_delay();
  EXPECT_EQ(expected_rtt_sample, manager_.GetRttStats()->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, RttZeroDelta) {
  // Expect that the RTT is the time between send and receive since the
  // ack_delay_time is zero.
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(1);
  clock_.AdvanceTime(expected_rtt);

  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Zero(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(expected_rtt, manager_.GetRttStats()->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeTimeout) {
  // Send 2 crypto packets and 3 data packets.
  const size_t kNumSentCryptoPackets = 2;
  for (size_t i = 1; i <= kNumSentCryptoPackets; ++i) {
    SendCryptoPacket(i);
  }
  const size_t kNumSentDataPackets = 3;
  for (size_t i = 1; i <= kNumSentDataPackets; ++i) {
    SendDataPacket(kNumSentCryptoPackets + i);
  }
  EXPECT_TRUE(manager_.HasUnackedCryptoPackets());
  EXPECT_EQ(5 * kDefaultLength, manager_.GetBytesInFlight());

  // The first retransmits 2 packets.
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .Times(2)
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(6); }))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(7); }));
  manager_.OnRetransmissionTimeout();
  // Expect all 4 handshake packets to be in flight and 3 data packets.
  EXPECT_EQ(7 * kDefaultLength, manager_.GetBytesInFlight());
  EXPECT_TRUE(manager_.HasUnackedCryptoPackets());

  // The second retransmits 2 packets.
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .Times(2)
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(8); }))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(9); }));
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(9 * kDefaultLength, manager_.GetBytesInFlight());
  EXPECT_TRUE(manager_.HasUnackedCryptoPackets());

  // Now ack the two crypto packets and the speculatively encrypted request,
  // and ensure the first four crypto packets get abandoned, but not lost.
  // Crypto packets remain in flight, so any that aren't acked will be lost.
  uint64_t acked[] = {3, 4, 5, 8, 9};
  uint64_t lost[] = {1, 2, 6};
  ExpectAcksAndLosses(true, acked, ABSL_ARRAYSIZE(acked), lost,
                      ABSL_ARRAYSIZE(lost));
  EXPECT_CALL(notifier_, OnFrameLost(_)).Times(3);
  EXPECT_CALL(notifier_, HasUnackedCryptoData()).WillRepeatedly(Return(false));
  manager_.OnAckFrameStart(QuicPacketNumber(9), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(8), QuicPacketNumber(10));
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(6));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  EXPECT_FALSE(manager_.HasUnackedCryptoPackets());
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeSpuriousRetransmission) {
  // Send 1 crypto packet.
  SendCryptoPacket(1);
  EXPECT_TRUE(manager_.HasUnackedCryptoPackets());

  // Retransmit the crypto packet as 2.
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(2); }));
  manager_.OnRetransmissionTimeout();

  // Retransmit the crypto packet as 3.
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(3); }));
  manager_.OnRetransmissionTimeout();

  // Now ack the second crypto packet, and ensure the first gets removed, but
  // the third does not.
  uint64_t acked[] = {2};
  ExpectAcksAndLosses(true, acked, ABSL_ARRAYSIZE(acked), nullptr, 0);
  EXPECT_CALL(notifier_, HasUnackedCryptoData()).WillRepeatedly(Return(false));
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  EXPECT_FALSE(manager_.HasUnackedCryptoPackets());
  uint64_t unacked[] = {1, 3};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeTimeoutUnsentDataPacket) {
  // Send 2 crypto packets and 1 data packet.
  const size_t kNumSentCryptoPackets = 2;
  for (size_t i = 1; i <= kNumSentCryptoPackets; ++i) {
    SendCryptoPacket(i);
  }
  SendDataPacket(3);
  EXPECT_TRUE(manager_.HasUnackedCryptoPackets());

  // Retransmit 2 crypto packets, but not the serialized packet.
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .Times(2)
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(4); }))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(5); }));
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasUnackedCryptoPackets());
}

TEST_F(QuicSentPacketManagerTest,
       CryptoHandshakeRetransmissionThenNeuterAndAck) {
  // Send 1 crypto packet.
  SendCryptoPacket(1);

  EXPECT_TRUE(manager_.HasUnackedCryptoPackets());

  // Retransmit the crypto packet as 2.
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(2); }));
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasUnackedCryptoPackets());

  // Retransmit the crypto packet as 3.
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(3); }));
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasUnackedCryptoPackets());

  // Now neuter all unacked unencrypted packets, which occurs when the
  // connection goes forward secure.
  EXPECT_CALL(notifier_, HasUnackedCryptoData()).WillRepeatedly(Return(false));
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  manager_.NeuterUnencryptedPackets();
  EXPECT_FALSE(manager_.HasUnackedCryptoPackets());
  uint64_t unacked[] = {1, 2, 3};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
  EXPECT_FALSE(manager_.HasUnackedCryptoPackets());
  EXPECT_FALSE(manager_.HasInFlightPackets());

  // Ensure both packets get discarded when packet 2 is acked.
  uint64_t acked[] = {3};
  ExpectAcksAndLosses(true, acked, ABSL_ARRAYSIZE(acked), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(4));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  VerifyUnackedPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTime) {
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTimeCryptoHandshake) {
  QuicTime crypto_packet_send_time = clock_.Now();
  SendCryptoPacket(1);

  // Check the min.
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->set_initial_rtt(QuicTime::Delta::FromMilliseconds(1));
  EXPECT_EQ(clock_.Now() + QuicTime::Delta::FromMilliseconds(10),
            manager_.GetRetransmissionTime());

  // Test with a standard smoothed RTT.
  rtt_stats->set_initial_rtt(QuicTime::Delta::FromMilliseconds(100));

  QuicTime::Delta srtt = rtt_stats->initial_rtt();
  QuicTime expected_time = clock_.Now() + 1.5 * srtt;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(1.5 * srtt);
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(2); }));
  // When session decides what to write, crypto_packet_send_time gets updated.
  crypto_packet_send_time = clock_.Now();
  manager_.OnRetransmissionTimeout();

  // The retransmission time should now be twice as far in the future.
  expected_time = crypto_packet_send_time + srtt * 2 * 1.5;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet for the 2nd time.
  clock_.AdvanceTime(2 * 1.5 * srtt);
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(3); }));
  // When session decides what to write, crypto_packet_send_time gets updated.
  crypto_packet_send_time = clock_.Now();
  manager_.OnRetransmissionTimeout();

  // Verify exponential backoff of the retransmission timeout.
  expected_time = crypto_packet_send_time + srtt * 4 * 1.5;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest,
       GetConservativeTransmissionTimeCryptoHandshake) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kCONH);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  // Calling SetFromConfig requires mocking out some send algorithm methods.
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));

  QuicTime crypto_packet_send_time = clock_.Now();
  SendCryptoPacket(1);

  // Check the min.
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->set_initial_rtt(QuicTime::Delta::FromMilliseconds(1));
  EXPECT_EQ(clock_.Now() + QuicTime::Delta::FromMilliseconds(25),
            manager_.GetRetransmissionTime());

  // Test with a standard smoothed RTT.
  rtt_stats->set_initial_rtt(QuicTime::Delta::FromMilliseconds(100));

  QuicTime::Delta srtt = rtt_stats->initial_rtt();
  QuicTime expected_time = clock_.Now() + 2 * srtt;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(2 * srtt);
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(
          InvokeWithoutArgs([this]() { return RetransmitCryptoPacket(2); }));
  crypto_packet_send_time = clock_.Now();
  manager_.OnRetransmissionTimeout();

  // The retransmission time should now be twice as far in the future.
  expected_time = crypto_packet_send_time + srtt * 2 * 2;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetLossDelay) {
  auto loss_algorithm = std::make_unique<MockLossAlgorithm>();
  QuicSentPacketManagerPeer::SetLossAlgorithm(&manager_, loss_algorithm.get());

  EXPECT_CALL(*loss_algorithm, GetLossTimeout())
      .WillRepeatedly(Return(QuicTime::Zero()));
  SendDataPacket(1);
  SendDataPacket(2);

  // Handle an ack which causes the loss algorithm to be evaluated and
  // set the loss timeout.
  ExpectAck(2);
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  QuicTime timeout(clock_.Now() + QuicTime::Delta::FromMilliseconds(10));
  EXPECT_CALL(*loss_algorithm, GetLossTimeout())
      .WillRepeatedly(Return(timeout));
  EXPECT_EQ(timeout, manager_.GetRetransmissionTime());

  // Fire the retransmission timeout and ensure the loss detection algorithm
  // is invoked.
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
  manager_.OnRetransmissionTimeout();
}

TEST_F(QuicSentPacketManagerTest, NegotiateIetfLossDetectionFromOptions) {
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
  EXPECT_FALSE(
      QuicSentPacketManagerPeer::AdaptiveTimeThresholdEnabled(&manager_));
  EXPECT_EQ(kDefaultLossDelayShift,
            QuicSentPacketManagerPeer::GetReorderingShift(&manager_));

  QuicConfig config;
  QuicTagVector options;
  options.push_back(kILD0);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);

  EXPECT_EQ(3, QuicSentPacketManagerPeer::GetReorderingShift(&manager_));
  EXPECT_FALSE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
}

TEST_F(QuicSentPacketManagerTest,
       NegotiateIetfLossDetectionOneFourthRttFromOptions) {
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
  EXPECT_FALSE(
      QuicSentPacketManagerPeer::AdaptiveTimeThresholdEnabled(&manager_));
  EXPECT_EQ(kDefaultLossDelayShift,
            QuicSentPacketManagerPeer::GetReorderingShift(&manager_));

  QuicConfig config;
  QuicTagVector options;
  options.push_back(kILD1);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);

  EXPECT_EQ(kDefaultLossDelayShift,
            QuicSentPacketManagerPeer::GetReorderingShift(&manager_));
  EXPECT_FALSE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
}

TEST_F(QuicSentPacketManagerTest,
       NegotiateIetfLossDetectionAdaptiveReorderingThreshold) {
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
  EXPECT_FALSE(
      QuicSentPacketManagerPeer::AdaptiveTimeThresholdEnabled(&manager_));
  EXPECT_EQ(kDefaultLossDelayShift,
            QuicSentPacketManagerPeer::GetReorderingShift(&manager_));

  QuicConfig config;
  QuicTagVector options;
  options.push_back(kILD2);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);

  EXPECT_EQ(3, QuicSentPacketManagerPeer::GetReorderingShift(&manager_));
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
}

TEST_F(QuicSentPacketManagerTest,
       NegotiateIetfLossDetectionAdaptiveReorderingThreshold2) {
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
  EXPECT_FALSE(
      QuicSentPacketManagerPeer::AdaptiveTimeThresholdEnabled(&manager_));
  EXPECT_EQ(kDefaultLossDelayShift,
            QuicSentPacketManagerPeer::GetReorderingShift(&manager_));

  QuicConfig config;
  QuicTagVector options;
  options.push_back(kILD3);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kDefaultLossDelayShift,
            QuicSentPacketManagerPeer::GetReorderingShift(&manager_));
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
}

TEST_F(QuicSentPacketManagerTest,
       NegotiateIetfLossDetectionAdaptiveReorderingAndTimeThreshold) {
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
  EXPECT_FALSE(
      QuicSentPacketManagerPeer::AdaptiveTimeThresholdEnabled(&manager_));
  EXPECT_EQ(kDefaultLossDelayShift,
            QuicSentPacketManagerPeer::GetReorderingShift(&manager_));

  QuicConfig config;
  QuicTagVector options;
  options.push_back(kILD4);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);

  EXPECT_EQ(kDefaultLossDelayShift,
            QuicSentPacketManagerPeer::GetReorderingShift(&manager_));
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::AdaptiveReorderingThresholdEnabled(&manager_));
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::AdaptiveTimeThresholdEnabled(&manager_));
}

TEST_F(QuicSentPacketManagerTest, NegotiateCongestionControlFromOptions) {
  QuicConfig config;
  QuicTagVector options;

  options.push_back(kRENO);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kRenoBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                            ->GetCongestionControlType());

  options.clear();
  options.push_back(kTBBR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kBBR, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                      ->GetCongestionControlType());

  options.clear();
  options.push_back(kBYTE);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kCubicBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                             ->GetCongestionControlType());
  options.clear();
  options.push_back(kRENO);
  options.push_back(kBYTE);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kRenoBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                            ->GetCongestionControlType());

  options.clear();
  options.push_back(kPRGC);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  // The server does nothing on kPRGC.
  EXPECT_EQ(kRenoBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                            ->GetCongestionControlType());
}

TEST_F(QuicSentPacketManagerTest, NegotiateClientCongestionControlFromOptions) {
  QuicConfig config;
  QuicTagVector options;

  // No change if the server receives client options.
  const SendAlgorithmInterface* mock_sender =
      QuicSentPacketManagerPeer::GetSendAlgorithm(manager_);
  options.push_back(kRENO);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(mock_sender, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_));

  // Change the congestion control on the client with client options.
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kRenoBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                            ->GetCongestionControlType());

  options.clear();
  options.push_back(kTBBR);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kBBR, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                      ->GetCongestionControlType());

  options.clear();
  options.push_back(kBYTE);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kCubicBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                             ->GetCongestionControlType());

  options.clear();
  options.push_back(kRENO);
  options.push_back(kBYTE);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kRenoBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                            ->GetCongestionControlType());

  options.clear();
  options.push_back(kPRGC);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kPragueCubic, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                              ->GetCongestionControlType());

  // Test that kPRGC is overriden by other options.
  options.clear();
  options.push_back(kPRGC);
  options.push_back(kTBBR);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kBBR, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                      ->GetCongestionControlType());
}

TEST_F(QuicSentPacketManagerTest, UseInitialRoundTripTimeToSend) {
  QuicTime::Delta initial_rtt = QuicTime::Delta::FromMilliseconds(325);
  EXPECT_NE(initial_rtt, manager_.GetRttStats()->smoothed_rtt());

  QuicConfig config;
  config.SetInitialRoundTripTimeUsToSend(initial_rtt.ToMicroseconds());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);

  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.GetRttStats()->smoothed_rtt());
  EXPECT_EQ(initial_rtt, manager_.GetRttStats()->initial_rtt());
}

TEST_F(QuicSentPacketManagerTest, ResumeConnectionState) {
  // The sent packet manager should use the RTT from CachedNetworkParameters if
  // it is provided.
  const QuicTime::Delta kRtt = QuicTime::Delta::FromMilliseconds(123);
  CachedNetworkParameters cached_network_params;
  cached_network_params.set_min_rtt_ms(kRtt.ToMilliseconds());

  SendAlgorithmInterface::NetworkParams params;
  params.bandwidth = QuicBandwidth::Zero();
  params.allow_cwnd_to_decrease = false;
  params.rtt = kRtt;
  params.is_rtt_trusted = true;

  EXPECT_CALL(*send_algorithm_, AdjustNetworkParameters(params));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .Times(testing::AnyNumber());
  manager_.ResumeConnectionState(cached_network_params, false);
  EXPECT_EQ(kRtt, manager_.GetRttStats()->initial_rtt());
}

TEST_F(QuicSentPacketManagerTest, ConnectionMigrationUnspecifiedChange) {
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  QuicTime::Delta default_init_rtt = rtt_stats->initial_rtt();
  rtt_stats->set_initial_rtt(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt());

  QuicSentPacketManagerPeer::SetConsecutivePtoCount(&manager_, 1);
  EXPECT_EQ(1u, manager_.GetConsecutivePtoCount());

  EXPECT_CALL(*send_algorithm_, OnConnectionMigration());
  EXPECT_EQ(nullptr,
            manager_.OnConnectionMigration(/*reset_send_algorithm=*/false));

  EXPECT_EQ(default_init_rtt, rtt_stats->initial_rtt());
  EXPECT_EQ(0u, manager_.GetConsecutivePtoCount());
}

// Tests that ResetCongestionControlUponPeerAddressChange() resets send
// algorithm and RTT. And unACK'ed packets are handled correctly.
TEST_F(QuicSentPacketManagerTest,
       ConnectionMigrationUnspecifiedChangeResetSendAlgorithm) {
  auto loss_algorithm = std::make_unique<MockLossAlgorithm>();
  QuicSentPacketManagerPeer::SetLossAlgorithm(&manager_, loss_algorithm.get());

  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  QuicTime::Delta default_init_rtt = rtt_stats->initial_rtt();
  rtt_stats->set_initial_rtt(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt());

  QuicSentPacketManagerPeer::SetConsecutivePtoCount(&manager_, 1);
  EXPECT_EQ(1u, manager_.GetConsecutivePtoCount());

  SendDataPacket(1, ENCRYPTION_FORWARD_SECURE);

  RttStats old_rtt_stats;
  old_rtt_stats.CloneFrom(*manager_.GetRttStats());

  // Packet1 will be mark for retransmission upon migration.
  EXPECT_CALL(notifier_, OnFrameLost(_));
  std::unique_ptr<SendAlgorithmInterface> old_send_algorithm =
      manager_.OnConnectionMigration(/*reset_send_algorithm=*/true);

  EXPECT_NE(old_send_algorithm.get(), manager_.GetSendAlgorithm());
  EXPECT_EQ(old_send_algorithm->GetCongestionControlType(),
            manager_.GetSendAlgorithm()->GetCongestionControlType());
  EXPECT_EQ(default_init_rtt, rtt_stats->initial_rtt());
  EXPECT_EQ(0u, manager_.GetConsecutivePtoCount());
  // Packets sent earlier shouldn't be regarded as in flight.
  EXPECT_EQ(0u, BytesInFlight());

  // Replace the new send algorithm with the mock object.
  manager_.SetSendAlgorithm(old_send_algorithm.release());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  // Application retransmit the data as LOSS_RETRANSMISSION.
  RetransmitDataPacket(2, LOSS_RETRANSMISSION, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kDefaultLength, BytesInFlight());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  // Receiving an ACK for packet1 20s later shouldn't update the RTT, and
  // shouldn't be treated as spurious retransmission.
  EXPECT_CALL(
      *send_algorithm_,
      OnCongestionEvent(/*rtt_updated=*/false, kDefaultLength, _, _, _, _, _))
      .WillOnce(testing::WithArg<3>(
          Invoke([](const AckedPacketVector& acked_packets) {
            EXPECT_EQ(1u, acked_packets.size());
            EXPECT_EQ(QuicPacketNumber(1), acked_packets[0].packet_number);
            // The bytes in packet1 shouldn't contribute to congestion control.
            EXPECT_EQ(0u, acked_packets[0].bytes_acked);
          })));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*loss_algorithm, SpuriousLossDetected(_, _, _, _, _)).Times(0u);
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
  EXPECT_TRUE(manager_.GetRttStats()->latest_rtt().IsZero());

  // Receiving an ACK for packet2 should update RTT and congestion control.
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(3));
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(
      *send_algorithm_,
      OnCongestionEvent(/*rtt_updated=*/true, kDefaultLength, _, _, _, _, _))
      .WillOnce(testing::WithArg<3>(
          Invoke([](const AckedPacketVector& acked_packets) {
            EXPECT_EQ(1u, acked_packets.size());
            EXPECT_EQ(QuicPacketNumber(2), acked_packets[0].packet_number);
            // The bytes in packet2 should contribute to congestion control.
            EXPECT_EQ(kDefaultLength, acked_packets[0].bytes_acked);
          })));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
  EXPECT_EQ(0u, BytesInFlight());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10),
            manager_.GetRttStats()->latest_rtt());

  SendDataPacket(3, ENCRYPTION_FORWARD_SECURE);
  // Trigger loss timeout and mark packet3 for retransmission.
  EXPECT_CALL(*loss_algorithm, GetLossTimeout())
      .WillOnce(Return(clock_.Now() + QuicTime::Delta::FromMilliseconds(10)));
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _))
      .WillOnce(WithArgs<5>(Invoke([](LostPacketVector* packet_lost) {
        packet_lost->emplace_back(QuicPacketNumber(3u), kDefaultLength);
        return LossDetectionInterface::DetectionStats();
      })));
  EXPECT_CALL(notifier_, OnFrameLost(_));
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(false, kDefaultLength, _, _, _, _, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(0u, BytesInFlight());

  // Migrate again with unACK'ed but not in-flight packet.
  // Packet3 shouldn't be marked for retransmission again as it is not in
  // flight.
  old_send_algorithm =
      manager_.OnConnectionMigration(/*reset_send_algorithm=*/true);

  EXPECT_NE(old_send_algorithm.get(), manager_.GetSendAlgorithm());
  EXPECT_EQ(old_send_algorithm->GetCongestionControlType(),
            manager_.GetSendAlgorithm()->GetCongestionControlType());
  EXPECT_EQ(default_init_rtt, rtt_stats->initial_rtt());
  EXPECT_EQ(0u, manager_.GetConsecutivePtoCount());
  EXPECT_EQ(0u, BytesInFlight());
  EXPECT_TRUE(manager_.GetRttStats()->latest_rtt().IsZero());

  manager_.SetSendAlgorithm(old_send_algorithm.release());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(30));
  // Receiving an ACK for packet3 shouldn't update RTT. Though packet 3 was
  // marked lost, this spurious retransmission shouldn't be reported to the loss
  // algorithm.
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(4));
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*loss_algorithm, SpuriousLossDetected(_, _, _, _, _)).Times(0u);
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(/*rtt_updated=*/false, 0, _, _, _, _, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(3),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
  EXPECT_EQ(0u, BytesInFlight());
  EXPECT_TRUE(manager_.GetRttStats()->latest_rtt().IsZero());

"""


```
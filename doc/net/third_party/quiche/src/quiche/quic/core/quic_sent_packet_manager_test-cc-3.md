Response:
The user is asking for an analysis of a C++ source code file related to network management in Chromium's QUIC implementation. Specifically, it's `quic_sent_packet_manager_test.cc`.

Here's a breakdown of the request and how to address it:

1. **Functionality:** The core request is to describe what this test file does. Test files in software projects generally focus on verifying the behavior of specific code components. In this case, it's testing the `QuicSentPacketManager`.

2. **Relationship to JavaScript:**  I need to determine if the functionalities tested here have any direct or indirect implications for JavaScript. Since this is a low-level networking component, the connection is likely indirect, but important for understanding how web traffic behaves.

3. **Logical Reasoning (Input/Output):** Test cases often demonstrate specific scenarios. I need to identify some key test functions and describe the setup (input) and expected outcome (output).

4. **User/Programming Errors:**  Consider common mistakes developers or users might make that these tests help prevent or highlight.

5. **User Path to this Code (Debugging):** Imagine a scenario where a developer needs to debug an issue related to this code. How would they end up looking at this file?

6. **Summary of Functionality (Part 4 of 5):** Based on the provided code snippet, I need to summarize the specific functionalities covered in this section of the tests. This requires identifying the main themes of the tests within the given excerpt.

**Mental Walkthrough of the Code Snippet:**

The provided code heavily focuses on testing the Probe Timeout (PTO) mechanism and related aspects in `QuicSentPacketManager`. Key areas include:

* **Computing PTO:**  Verifying how the PTO timer is calculated under various conditions, including initial RTT, smoothed RTT, and handling of multiple packet number spaces.
* **PTO Triggering:**  Simulating PTO events and checking the resulting actions, such as retransmitting probe packets.
* **Interaction with Packet Number Spaces:**  Ensuring the PTO logic correctly handles scenarios involving different encryption levels (INITIAL, HANDSHAKE, 1-RTT).
* **Handshake Confirmation:** Testing the impact of handshake confirmation on packet management and PTO.
* **Neuter Unencrypted Packets:** Verifying the mechanism for discarding unencrypted packets.
* **Handling of PING packets:**  Specific tests address how PING packets are treated, especially on the client-side.
* **Exponential Backoff:**  Confirming the exponential backoff behavior of the PTO timer when no RTT measurements are available.
* **Tiny Initial RTT:** Testing the handling of very small initial RTT values for PTO.
* **Path Challenges:**  Verifying the sending and acknowledgment of PATH_CHALLENGE frames.
* **ACK Frequency Frames:**  Testing the mechanism for updating the peer's maximum allowed ACK delay based on ACK Frequency frames.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能: Yes
2. 如果它与javascript的功能有关系，请做出对应的举例说明: Yes
3. 如果做了逻辑推理，请给出假设输入与输出: Yes
4. 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
5. 说明用户操作是如何一步步的到达这里，作为调试线索。Yes
6. 这是第4部分，共5部分，请归纳一下它的功能: Yes

Confidence Score: 5/5 - I'm confident I can address all parts of the request based on the code snippet and my understanding of network testing.

**Strategizing complete. I will now generate the response.**

这是Chromium网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc` 文件的**第四部分**，该文件主要用于测试 `QuicSentPacketManager` 类的功能。 `QuicSentPacketManager` 负责管理已发送但尚未被确认的QUIC数据包，并处理诸如重传、拥塞控制和PTO（Probing Timeout）等关键任务。

**本部分的功能归纳:**

本部分的测试用例主要集中在以下几个方面：

1. **更精细的PTO（Probing Timeout）计算和触发机制:**  测试在更复杂的场景下，例如当有新的数据包发送、收到ACK确认等事件发生时，PTO定时器如何被计算和更新。特别关注了当PTO即将到期时发送新数据包对PTO的影响，以及在多包编号空间下PTO的计算逻辑。
2. **多包编号空间（Multiple Packet Number Spaces）下的PTO行为:** 验证在INITIAL、HANDSHAKE和应用数据包（1-RTT）使用不同包编号空间的情况下，PTO定时器如何根据最老的未被确认的数据包进行计算。
3. **握手确认（Handshake Confirmation）和密钥丢弃的影响:** 测试握手完成后，`QuicSentPacketManager` 如何处理未加密的数据包（INITIAL），并更新PTO定时器。
4. **丢弃未加密数据包（Neuter Unencrypted Packets）:** 验证在密钥更新后，丢弃使用旧密钥加密的数据包的功能。
5. **初始数据包的重传（Retransmission of Initial Packets）:** 测试只标记INITIAL阶段的数据包进行重传的功能。
6. **忽略客户端的PING包:** 验证作为客户端时，如何配置并忽略接收到的PING包，避免因此产生不必要的RTT样本。
7. **在没有RTT测量的情况下的指数退避（Exponential Backoff without RTT Measurement）:**  测试在没有有效的RTT测量时，PTO定时器如何进行指数退避。
8. **处理极小的初始RTT（Handling Tiny Initial RTT）:**  测试当初始RTT非常小时，PTO定时器是否能正确地设置最小超时时间。
9. **握手ACK导致INITIAL密钥丢弃:** 验证收到握手阶段的ACK后，是否会触发INITIAL阶段密钥的丢弃。
10. **清理最后在途数据包的发送时间:** 测试在收到某些ACK后，是否能正确清理最后在途数据包的发送时间，以便正确计算后续的PTO。
11. **可能重传初始数据:** 测试在需要发送INITIAL ACK时，可能触发INITIAL数据的重传机制。
12. **发送路径挑战并收到ACK（Send Path Challenge and Get Ack）:** 验证发送PATH_CHALLENGE帧并收到ACK的功能。
13. **根据ACK频率帧更新对端最大ACK延迟（Peer Max Ack Delay Updated from Ack Frequency Frame）:**  测试根据接收到的ACK频率帧中的信息，动态更新对端允许的最大ACK延迟的功能。

**与JavaScript功能的关联及举例:**

虽然 `QuicSentPacketManager` 是C++实现的底层网络组件，但它的行为直接影响QUIC连接的可靠性和性能，而QUIC是HTTP/3的基础。因此，它间接地与JavaScript在浏览器中的网络请求行为相关。

例如：

* **PTO和延迟:**  如果PTO设置不当，可能导致连接在丢包时等待过长时间才进行重传，从而增加页面加载延迟。JavaScript发起的 `fetch()` 请求或 `XMLHttpRequest` 请求可能会因为底层的QUIC连接的PTO问题而响应缓慢。
* **多包编号空间和连接建立:** 多包编号空间的正确处理对于QUIC连接的快速建立至关重要。如果测试失败，可能导致QUIC握手失败，浏览器可能回退到TCP，影响JavaScript发起的初始连接速度。
* **ACK频率帧和延迟:**  ACK频率帧允许接收端告知发送端期望的ACK发送频率。如果此功能工作不正常，可能导致ACK发送过于频繁或过于稀疏，影响拥塞控制和延迟。JavaScript应用可能会因为ACK的延迟而感受到网络延迟的变化。

**逻辑推理的假设输入与输出:**

**示例1: `ComputingProbeTimeoutByLeftEdge2` 测试**

* **假设输入:**
    1. 初始RTT为100ms。
    2. 发送数据包1。
    3. 在PTO即将到期前10ms发送数据包2。
    4. 模拟PTO超时。
    5. 发送一个探测包3。
    6. 收到数据包1和2的ACK。
* **预期输出:**
    1. 数据包1发送后，PTO被设置为 `packet1_sent_time + srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() + GetDefaultDelayedAckTimeMs()`。
    2. 数据包2发送后，由于在PTO即将到期时发送，PTO被扩展为 `packet2_sent_time + kFirstPtoSrttMultiplier * rtt_stats->smoothed_rtt()`。
    3. PTO超时后，`pto_count` 增加。
    4. 探测包3发送后，新的PTO被设置为 `packet3_sent_time + srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() + GetDefaultDelayedAckTimeMs() * 2`。
    5. 收到数据包1和2的ACK后，PTO根据数据包3的发送时间重新计算。

**涉及用户或编程常见的使用错误:**

* **配置错误的PTO参数:**  开发者可能错误地配置了PTO相关的参数，例如 `kPtoRttvarMultiplier` 或初始RTT，导致连接在丢包时的行为不符合预期。例如，如果 `kPtoRttvarMultiplier` 设置过小，可能导致过早的超时重传，浪费带宽。
* **在多包编号空间下假设单一的PTO定时器:** 开发者可能错误地认为只有一个全局的PTO定时器，而没有考虑到不同包编号空间需要分别维护PTO状态。这可能导致在握手阶段出现非预期的超时行为。
* **没有正确处理握手确认事件:**  如果上层协议没有正确地通知 `QuicSentPacketManager` 握手已完成，可能导致资源无法及时释放，例如旧的加密密钥。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在使用Chrome浏览器访问某个使用了HTTP/3的网站时，遇到了连接不稳定或者加载缓慢的问题。作为开发人员，为了调试这个问题，可能会采取以下步骤：

1. **使用Chrome的 `chrome://net-export/` 工具抓取网络日志:**  这可以提供详细的QUIC连接事件信息，包括数据包的发送、接收、ACK以及超时等。
2. **分析网络日志:**  在日志中查找与特定QUIC连接相关的事件，例如PTO事件、重传事件或拥塞控制事件。
3. **定位到 `QuicSentPacketManager`:**  如果日志显示频繁的PTO事件或者重传行为异常，开发者可能会怀疑是发送端的数据包管理出现了问题。
4. **查看 `QuicSentPacketManager` 的代码:**  为了深入了解PTO的计算逻辑和重传机制，开发者可能会查看 `quic_sent_packet_manager.cc` 的源代码。
5. **阅读或运行 `quic_sent_packet_manager_test.cc`:** 为了验证自己的理解或排查潜在的bug，开发者会查看或运行相关的测试用例，例如本文件中与PTO计算相关的测试。 通过阅读测试用例，可以了解各种场景下 `QuicSentPacketManager` 的预期行为。
6. **单步调试:**  如果仍然无法定位问题，开发者可能会设置断点在 `QuicSentPacketManager` 的关键代码路径上，例如 `GetRetransmissionTime()` 或 `OnRetransmissionTimeout()`，以便单步跟踪代码执行过程，观察变量的值和程序流程。

总而言之， `net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc` 的这部分着重测试了QUIC发送端数据包管理中至关重要的PTO机制在各种复杂场景下的正确性，确保QUIC连接的稳定性和性能。 这些测试覆盖了多包编号空间、握手流程以及各种边界情况，有助于防止潜在的bug并保证QUIC协议的健壮性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
manager_.GetRetransmissionTime());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(2, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO is still based on packet 1.
  EXPECT_EQ(packet1_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());
  EXPECT_EQ(0u, stats_.pto_count);

  // Invoke PTO.
  clock_.AdvanceTime(expected_pto_delay);
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_EQ(1u, stats_.pto_count);

  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(WithArgs<1>(Invoke([this](TransmissionType type) {
        return RetransmitDataPacket(3, type, ENCRYPTION_FORWARD_SECURE);
      })));
  manager_.MaybeSendProbePacket();
  // Verify PTO period gets set to twice the current value and based on packet3.
  QuicTime packet3_sent_time = clock_.Now();
  EXPECT_EQ(packet3_sent_time + expected_pto_delay * 2,
            manager_.GetRetransmissionTime());

  // Received ACK for packets 1 and 2.
  uint64_t acked[] = {1, 2};
  ExpectAcksAndLosses(true, acked, ABSL_ARRAYSIZE(acked), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
  expected_pto_delay =
      rtt_stats->SmoothedOrInitialRtt() +
      std::max(kPtoRttvarMultiplier * rtt_stats->mean_deviation(),
               QuicTime::Delta::FromMilliseconds(1)) +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());

  // Verify PTO is correctly re-armed based on sent time of packet 4.
  EXPECT_EQ(packet3_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, ComputingProbeTimeoutByLeftEdge2) {
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  QuicTime::Delta srtt = rtt_stats->smoothed_rtt();

  SendDataPacket(1, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO is correctly set.
  QuicTime::Delta expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  const QuicTime packet1_sent_time = clock_.Now();
  EXPECT_EQ(packet1_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Sent a packet 10ms before PTO expiring.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(
      expected_pto_delay.ToMilliseconds() - 10));
  SendDataPacket(2, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO expands to packet 2 sent time + 1.5 * srtt.
  expected_pto_delay = kFirstPtoSrttMultiplier * rtt_stats->smoothed_rtt();
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());
  EXPECT_EQ(0u, stats_.pto_count);

  // Invoke PTO.
  clock_.AdvanceTime(expected_pto_delay);
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_EQ(1u, stats_.pto_count);

  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(WithArgs<1>(Invoke([this](TransmissionType type) {
        return RetransmitDataPacket(3, type, ENCRYPTION_FORWARD_SECURE);
      })));
  manager_.MaybeSendProbePacket();
  // Verify PTO period gets set to twice the expected value and based on
  // packet3 (right edge).
  expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  QuicTime packet3_sent_time = clock_.Now();
  EXPECT_EQ(packet3_sent_time + expected_pto_delay * 2,
            manager_.GetRetransmissionTime());

  // Received ACK for packets 1 and 2.
  uint64_t acked[] = {1, 2};
  ExpectAcksAndLosses(true, acked, ABSL_ARRAYSIZE(acked), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
  expected_pto_delay =
      rtt_stats->SmoothedOrInitialRtt() +
      std::max(kPtoRttvarMultiplier * rtt_stats->mean_deviation(),
               QuicTime::Delta::FromMilliseconds(1)) +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());

  // Verify PTO is correctly re-armed based on sent time of packet 3 (left
  // edge).
  EXPECT_EQ(packet3_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest,
       ComputingProbeTimeoutByLeftEdgeMultiplePacketNumberSpaces) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  QuicTime::Delta srtt = rtt_stats->smoothed_rtt();

  // Send packet 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  const QuicTime packet1_sent_time = clock_.Now();
  // Verify PTO is correctly set.
  QuicTime::Delta expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::Zero();
  EXPECT_EQ(packet1_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Send packet 2 in handshake.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  const QuicTime packet2_sent_time = clock_.Now();
  // Verify PTO timeout is still based on packet 1.
  EXPECT_EQ(packet1_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Discard initial keys.
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  manager_.NeuterUnencryptedPackets();

  // Send packet 3 in 1-RTT.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(3, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO timeout is based on packet 2.
  const QuicTime packet3_sent_time = clock_.Now();
  EXPECT_EQ(packet2_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Send packet 4 in handshake.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(4, ENCRYPTION_HANDSHAKE);
  // Verify PTO timeout is based on packet 4 as application data is ignored.
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Discard handshake keys.
  manager_.SetHandshakeConfirmed();
  // Verify PTO timeout is now based on packet 3 as handshake is
  // complete/confirmed.
  expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  EXPECT_EQ(packet3_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(5, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO timeout is still based on packet 3.
  EXPECT_EQ(packet3_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest,
       ComputingProbeTimeoutByLeftEdge2MultiplePacketNumberSpaces) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  QuicTime::Delta srtt = rtt_stats->smoothed_rtt();

  // Send packet 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  const QuicTime packet1_sent_time = clock_.Now();
  // Verify PTO is correctly set.
  QuicTime::Delta expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::Zero();
  EXPECT_EQ(packet1_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Send packet 2 in handshake.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  const QuicTime packet2_sent_time = clock_.Now();
  // Verify PTO timeout is still based on packet 1.
  EXPECT_EQ(packet1_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Discard initial keys.
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  manager_.NeuterUnencryptedPackets();

  // Send packet 3 in 1-RTT.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(3, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO timeout is based on packet 2.
  const QuicTime packet3_sent_time = clock_.Now();
  EXPECT_EQ(packet2_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Send packet 4 in handshake.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(4, ENCRYPTION_HANDSHAKE);
  // Verify PTO timeout is based on packet 4 as application data is ignored.
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Discard handshake keys.
  manager_.SetHandshakeConfirmed();
  // Verify PTO timeout is now based on packet 3 as handshake is
  // complete/confirmed.
  expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  EXPECT_EQ(packet3_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Send packet 5 10ms before PTO expiring.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(
      expected_pto_delay.ToMilliseconds() - 10));
  SendDataPacket(5, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO timeout expands to packet 5 sent time + 1.5 * srtt.
  EXPECT_EQ(clock_.Now() + kFirstPtoSrttMultiplier * rtt_stats->smoothed_rtt(),
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, SetHandshakeConfirmed) {
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  manager_.EnableMultiplePacketNumberSpacesSupport();

  SendDataPacket(1, ENCRYPTION_INITIAL);

  SendDataPacket(2, ENCRYPTION_HANDSHAKE);

  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _))
      .WillOnce(
          Invoke([](const QuicFrame& /*frame*/, QuicTime::Delta ack_delay_time,
                    QuicTime receive_timestamp) {
            EXPECT_TRUE(ack_delay_time.IsZero());
            EXPECT_EQ(receive_timestamp, QuicTime::Zero());
            return true;
          }));

  EXPECT_CALL(*send_algorithm_, OnPacketNeutered(QuicPacketNumber(2))).Times(1);
  manager_.SetHandshakeConfirmed();
}

// Regresstion test for b/148841700.
TEST_F(QuicSentPacketManagerTest, NeuterUnencryptedPackets) {
  SendCryptoPacket(1);
  SendPingPacket(2, ENCRYPTION_INITIAL);
  // Crypto data has been discarded but ping does not.
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _))
      .Times(2)
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*send_algorithm_, OnPacketNeutered(QuicPacketNumber(1))).Times(1);
  manager_.NeuterUnencryptedPackets();
}

TEST_F(QuicSentPacketManagerTest, MarkInitialPacketsForRetransmission) {
  SendCryptoPacket(1);
  SendPingPacket(2, ENCRYPTION_HANDSHAKE);
  // Only the INITIAL packet will be retransmitted.
  EXPECT_CALL(notifier_, OnFrameLost(_)).Times(1);
  manager_.MarkInitialPacketsForRetransmission();
}

TEST_F(QuicSentPacketManagerTest, NoPacketThresholdDetectionForRuntPackets) {
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::UsePacketThresholdForRuntPackets(&manager_));

  QuicConfig config;
  QuicTagVector options;
  options.push_back(kRUNT);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);

  EXPECT_FALSE(
      QuicSentPacketManagerPeer::UsePacketThresholdForRuntPackets(&manager_));
}

TEST_F(QuicSentPacketManagerTest, GetPathDegradingDelayDefaultPTO) {
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  QuicTime::Delta expected_delay = 4 * manager_.GetPtoDelay();
  EXPECT_EQ(expected_delay, manager_.GetPathDegradingDelay());
}

TEST_F(QuicSentPacketManagerTest, ClientsIgnorePings) {
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  QuicConfig client_config;
  QuicTagVector options;
  QuicTagVector client_options;
  client_options.push_back(kIGNP);
  client_config.SetConnectionOptionsToSend(options);
  client_config.SetClientConnectionOptions(client_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(client_config);

  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));

  SendPingPacket(1, ENCRYPTION_INITIAL);
  // Verify PING only packet is not considered in flight.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
  SendDataPacket(2, ENCRYPTION_INITIAL);
  EXPECT_NE(QuicTime::Zero(), manager_.GetRetransmissionTime());

  uint64_t acked[] = {1};
  ExpectAcksAndLosses(/*rtt_updated=*/false, acked, ABSL_ARRAYSIZE(acked),
                      nullptr, 0);
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(90));
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  // Verify no RTT samples for PING only packet.
  EXPECT_TRUE(rtt_stats->smoothed_rtt().IsZero());

  ExpectAck(2);
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(100), rtt_stats->smoothed_rtt());
}

// Regression test for b/154050235.
TEST_F(QuicSentPacketManagerTest, ExponentialBackoffWithNoRttMeasurement) {
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  manager_.EnableMultiplePacketNumberSpacesSupport();
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(kInitialRttMs),
            rtt_stats->initial_rtt());
  EXPECT_TRUE(rtt_stats->smoothed_rtt().IsZero());

  SendCryptoPacket(1);
  QuicTime::Delta expected_pto_delay =
      QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs);
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Invoke PTO.
  clock_.AdvanceTime(expected_pto_delay);
  manager_.OnRetransmissionTimeout();

  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(
          WithArgs<1>(Invoke([this]() { return RetransmitCryptoPacket(3); })));
  manager_.MaybeSendProbePacket();
  // Verify exponential backoff of the PTO timeout.
  EXPECT_EQ(clock_.Now() + 2 * expected_pto_delay,
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, PtoDelayWithTinyInitialRtt) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  // Assume client provided a tiny initial RTT.
  rtt_stats->set_initial_rtt(QuicTime::Delta::FromMicroseconds(1));
  EXPECT_EQ(QuicTime::Delta::FromMicroseconds(1), rtt_stats->initial_rtt());
  EXPECT_TRUE(rtt_stats->smoothed_rtt().IsZero());

  SendCryptoPacket(1);
  QuicTime::Delta expected_pto_delay = QuicTime::Delta::FromMilliseconds(10);
  // Verify kMinHandshakeTimeoutMs is respected.
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Invoke PTO.
  clock_.AdvanceTime(expected_pto_delay);
  manager_.OnRetransmissionTimeout();

  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(
          WithArgs<1>(Invoke([this]() { return RetransmitCryptoPacket(3); })));
  manager_.MaybeSendProbePacket();
  // Verify exponential backoff of the PTO timeout.
  EXPECT_EQ(clock_.Now() + 2 * expected_pto_delay,
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, HandshakeAckCausesInitialKeyDropping) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  // Send INITIAL packet 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  QuicTime::Delta expected_pto_delay =
      QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs);
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());
  // Send HANDSHAKE ack.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendAckPacket(2, /*largest_acked=*/1, ENCRYPTION_HANDSHAKE);
  // Sending HANDSHAKE packet causes dropping of INITIAL key.
  EXPECT_CALL(notifier_, HasUnackedCryptoData()).WillRepeatedly(Return(false));
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  manager_.NeuterUnencryptedPackets();
  // There is no in flight packets.
  EXPECT_FALSE(manager_.HasInFlightPackets());
  // Verify PTO timer gets rearmed from now because of anti-amplification.
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Invoke PTO.
  clock_.AdvanceTime(expected_pto_delay);
  manager_.OnRetransmissionTimeout();
  // Verify nothing to probe (and connection will send PING for current
  // encryption level).
  EXPECT_CALL(notifier_, RetransmitFrames(_, _)).Times(0);
  manager_.MaybeSendProbePacket();
}

// Regression test for b/156487311
TEST_F(QuicSentPacketManagerTest, ClearLastInflightPacketsSentTime) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));

  // Send INITIAL 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  // Send HANDSHAKE 2.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  SendDataPacket(3, ENCRYPTION_HANDSHAKE);
  SendDataPacket(4, ENCRYPTION_HANDSHAKE);
  const QuicTime packet2_sent_time = clock_.Now();

  // Send half RTT 5.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(5, ENCRYPTION_FORWARD_SECURE);

  // Received ACK for INITIAL 1.
  ExpectAck(1);
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(90));
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  const QuicTime::Delta pto_delay =
      rtt_stats->smoothed_rtt() +
      kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::Zero();
  // Verify PTO is armed based on handshake data.
  EXPECT_EQ(packet2_sent_time + pto_delay, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, MaybeRetransmitInitialData) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  QuicTime::Delta srtt = rtt_stats->smoothed_rtt();

  // Send packet 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  QuicTime packet1_sent_time = clock_.Now();

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  // Send packets 2 and 3.
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  QuicTime packet2_sent_time = clock_.Now();
  SendDataPacket(3, ENCRYPTION_HANDSHAKE);
  // Verify PTO is correctly set based on packet 1.
  QuicTime::Delta expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::Zero();
  EXPECT_EQ(packet1_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Assume connection is going to send INITIAL ACK.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(WithArgs<1>(Invoke([this](TransmissionType type) {
        return RetransmitDataPacket(4, type, ENCRYPTION_INITIAL);
      })));
  manager_.RetransmitDataOfSpaceIfAny(INITIAL_DATA);
  // Verify PTO is re-armed based on packet 2.
  EXPECT_EQ(packet2_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Connection is going to send another INITIAL ACK.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(WithArgs<1>(Invoke([this](TransmissionType type) {
        return RetransmitDataPacket(5, type, ENCRYPTION_INITIAL);
      })));
  manager_.RetransmitDataOfSpaceIfAny(INITIAL_DATA);
  // Verify PTO does not change.
  EXPECT_EQ(packet2_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, SendPathChallengeAndGetAck) {
  QuicPacketNumber packet_number(1);
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, BytesInFlight(), packet_number, _, _));
  SerializedPacket packet(packet_number, PACKET_4BYTE_PACKET_NUMBER, nullptr,
                          kDefaultLength, false, false);
  QuicPathFrameBuffer path_frame_buffer{0, 1, 2, 3, 4, 5, 6, 7};
  packet.nonretransmittable_frames.push_back(
      QuicFrame(QuicPathChallengeFrame(0, path_frame_buffer)));
  packet.encryption_level = ENCRYPTION_FORWARD_SECURE;
  manager_.OnPacketSent(&packet, clock_.Now(), NOT_RETRANSMISSION,
                        NO_RETRANSMITTABLE_DATA, false, ECN_NOT_ECT);
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  EXPECT_CALL(
      *send_algorithm_,
      OnCongestionEvent(/*rtt_updated=*/false, _, _,
                        Pointwise(PacketNumberEq(), {1}), IsEmpty(), _, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());

  // Get ACK for the packet.
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
}

SerializedPacket MakePacketWithAckFrequencyFrame(
    int packet_number, int ack_frequency_sequence_number,
    QuicTime::Delta max_ack_delay) {
  auto* ack_frequency_frame = new QuicAckFrequencyFrame();
  ack_frequency_frame->max_ack_delay = max_ack_delay;
  ack_frequency_frame->sequence_number = ack_frequency_sequence_number;
  SerializedPacket packet(QuicPacketNumber(packet_number),
                          PACKET_4BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                          /*has_ack=*/false,
                          /*has_stop_waiting=*/false);
  packet.retransmittable_frames.push_back(QuicFrame(ack_frequency_frame));
  packet.has_ack_frequency = true;
  packet.encryption_level = ENCRYPTION_FORWARD_SECURE;
  return packet;
}

TEST_F(QuicSentPacketManagerTest,
       PeerMaxAckDelayUpdatedFromAckFrequencyFrameOneAtATime) {
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(AnyNumber());
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange())
      .Times(AnyNumber());

  auto initial_peer_max_ack_delay = manager_.peer_max_ack_delay();
  auto one_ms = QuicTime::Delta::FromMilliseconds(1);
  auto plus_1_ms_delay = initial_peer_max_ack_delay + one_ms;
  auto minus_1_ms_delay = initial_peer_max_ack_delay - one_ms;

  // Send and Ack frame1.
  SerializedPacket packet1 = MakePacketWithAckFrequencyFrame(
      /*packet_number=*/1, /*ack_frequency_sequence_number=*/1,
      plus_1_ms_delay);
  // Higher on the fly max_ack_delay changes peer_max_ack_delay.
  manager_.OnPacketSent(&packet1, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                        ECN_NOT_ECT);
  EXPECT_EQ(manager_.peer_max_ack_delay(), plus_1_ms_delay);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                         ENCRYPTION_FORWARD_SECURE, kEmptyCounts);
  EXPECT_EQ(manager_.peer_max_ack_delay(), plus_1_ms_delay);

  // Send and Ack frame2.
  SerializedPacket packet2 = MakePacketWithAckFrequencyFrame(
      /*packet_number=*/2, /*ack_frequency_sequence_number=*/2,
      minus_1_ms_delay);
  // Lower on the fly max_ack_delay does not change peer_max_ack_delay.
  manager_.OnPacketSent(&packet2, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                        ECN_NOT_ECT);
  EXPECT_EQ(manager_.peer_max_ack_delay(), plus_1_ms_delay);
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(3));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                         ENCRYPTION_FORWARD_SECURE, kEmptyCounts);
  EXPECT_EQ(manager_.peer_max_ack_delay(), minus_1_ms_delay);
}

TEST_F(QuicSentPacketManagerTest,
       PeerMaxAckDelayUpdatedFromInOrderAckFrequencyFrames) {
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(AnyNumber());
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange())
      .Times(AnyNumber());

  auto initial_peer_max_ack_delay = manager_.peer_max_ack_delay();
  auto one_ms = QuicTime::Delta::FromMilliseconds(1);
  auto extra_1_ms = initial_peer_max_ack_delay + one_ms;
  auto extra_2_ms = initial_peer_max_ack_delay + 2 * one_ms;
  auto extra_3_ms = initial_peer_max_ack_delay + 3 * one_ms;
  SerializedPacket packet1 = MakePacketWithAckFrequencyFrame(
      /*packet_number=*/1, /*ack_frequency_sequence_number=*/1, extra_1_ms);
  SerializedPacket packet2 = MakePacketWithAckFrequencyFrame(
      /*packet_number=*/2, /*ack_frequency_sequence_number=*/2, extra_3_ms);
  SerializedPacket packet3 = MakePacketWithAckFrequencyFrame(
      /*packet_number=*/3, /*ack_frequency_sequence_number=*/3, extra_2_ms);

  // Send frame1, farme2, frame3.
  manager_.OnPacketSent(&packet1, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                        ECN_NOT_ECT);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_1_ms);
  manager_.OnPacketSent(&packet2, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                        ECN_NOT_ECT);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_3_ms);
  manager_.OnPacketSent(&packet3, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                        ECN_NOT_ECT);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_3_ms);

  // Ack frame1, farme2, frame3.
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                         ENCRYPTION_FORWARD_SECURE, kEmptyCounts);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_3_ms);
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(3));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                         ENCRYPTION_FORWARD_SECURE, kEmptyCounts);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_3_ms);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(4));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                         ENCRYPTION_FORWARD_SECURE, kEmptyCounts);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_2_ms);
}

TEST_F(QuicSentPacketManagerTest,
       PeerMaxAckDelayUpdatedFromOutOfOrderAckedAckFrequencyFrames) {
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(AnyNumber());
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange())
      .Times(AnyNumber());

  auto initial_peer_max_ack_delay = manager_.peer_max_ack_delay();
  auto one_ms = QuicTime::Delta::FromMilliseconds(1);
  auto extra_1_ms = initial_peer_max_ack_delay + one_ms;
  auto extra_2_ms = initial_peer_max_ack_delay + 2 * one_ms;
  auto extra_3_ms = initial_peer_max_ack_delay + 3 * one_ms;
  auto extra_4_ms = initial_peer_max_ack_delay + 4 * one_ms;
  SerializedPacket packet1 = MakePacketWithAckFrequencyFrame(
      /*packet_number=*/1, /*ack_frequency_sequence_number=*/1, extra_4_ms);
  SerializedPacket packet2 = MakePacketWithAckFrequencyFrame(
      /*packet_number=*/2, /*ack_frequency_sequence_number=*/2, extra_3_ms);
  SerializedPacket packet3 = MakePacketWithAckFrequencyFrame(
      /*packet_number=*/3, /*ack_frequency_sequence_number=*/3, extra_2_ms);
  SerializedPacket packet4 = MakePacketWithAckFrequencyFrame(
      /*packet_number=*/4, /*ack_frequency_sequence_number=*/4, extra_1_ms);

  // Send frame1, farme2, frame3, frame4.
  manager_.OnPacketSent(&packet1, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                        ECN_NOT_ECT);
  manager_.OnPacketSent(&packet2, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                        ECN_NOT_ECT);
  manager_.OnPacketSent(&packet3, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                        ECN_NOT_ECT);
  manager_.OnPacketSent(&packet4, clock_.Now(), NOT_RETRANSMISSION,
```
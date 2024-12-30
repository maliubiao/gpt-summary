Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the `QuicSentPacketManager` class in Chromium's QUIC implementation.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class Under Test:** The filename `quic_sent_packet_manager_test.cc` and the test fixture name `QuicSentPacketManagerTest` immediately indicate that the core class being tested is `QuicSentPacketManager`.

2. **Recognize the Purpose of Test Files:** Test files aim to verify the correct behavior of a specific class or component. This involves setting up various scenarios, calling methods of the class under test, and asserting that the results match expectations.

3. **Analyze the Test Cases:**  Read through the provided code snippet, paying attention to the names of the test cases and the actions performed within them. Look for keywords like `EXPECT_CALL`, `SendDataPacket`, `RetransmitDataPacket`, `OnAckFrameStart`, `OnAckRange`, `OnAckFrameEnd`, `OnRetransmissionTimeout`, `OnConnectionMigration`, etc. These keywords indicate specific functionalities being tested.

4. **Group Related Test Cases:** Notice patterns and themes in the test cases. For example:
    * Several tests involve sending packets and then receiving acknowledgments (`OnAckFrame...`).
    * Some tests explicitly deal with retransmission timeouts (`OnRetransmissionTimeout`).
    *  The `MultiplePacketNumberSpaces` tests indicate functionality related to different encryption levels.
    *  Tests like `PathMtuIncreased` point to features beyond basic packet sending and acknowledgment.

5. **Infer Functionality from Actions and Assertions:** Based on the actions and assertions within the test cases, deduce the underlying functionality of the `QuicSentPacketManager`. For instance:
    * Sending a data packet and the subsequent `EXPECT_CALL` on `OnPacketSent` means the manager handles sending packets.
    * The `OnAckFrame...` calls and assertions about `BytesInFlight` and RTT suggest the manager tracks acknowledgments and updates connection metrics.
    * The tests involving loss algorithms (`EXPECT_CALL(*loss_algorithm, ...)`) indicate the manager integrates with loss detection mechanisms.
    * Retransmission tests show the manager handles packet retransmissions.
    * `OnConnectionMigration` suggests support for connection migration.

6. **Relate Functionality to Network Concepts:** Connect the observed functionalities to standard network concepts like:
    * **Packet transmission and reception:**  The core of the manager's job.
    * **Acknowledgment handling:** Processing ACK frames to confirm packet delivery.
    * **Retransmission:** Resending lost packets.
    * **Congestion control:** Interacting with a congestion control algorithm.
    * **Round-trip time (RTT) estimation:** Tracking network latency.
    * **Path Maximum Transmission Unit (MTU) discovery:** Adapting to network path characteristics.
    * **Packet number spaces:** Managing packets with different encryption levels.
    * **Probe timeouts (PTO):** Mechanisms to detect packet loss when acknowledgments are delayed.
    * **Connection migration:**  Changing the network path of a connection.

7. **Address Specific Questions from the Prompt:**  Now, go back to the user's specific requests:
    * **List the functionalities:**  Compile the list of inferred functionalities.
    * **Relationship to JavaScript:**  Consider if any of the tested functionalities have direct parallels in JavaScript's network APIs (like `fetch` or WebSockets). In this case, the connection is conceptual rather than direct code interaction.
    * **Logical Reasoning (Assumptions/Inputs/Outputs):**  Take a specific test case (like the retransmission timeout one) and explicitly state the assumed input (sending a packet, then a timeout) and the expected output (the packet being marked for retransmission).
    * **User/Programming Errors:** Think about common mistakes a developer might make when using a packet manager (e.g., not handling acknowledgments correctly, misconfiguring timeouts).
    * **User Steps to Reach This Code (Debugging):**  Describe a scenario where a developer would be looking at this test code (e.g., investigating retransmission issues).
    * **Part 3 Summary:**  Focus on the functionalities demonstrated in this specific code snippet, noting the continuation from previous parts (indicated by "part 3 of 5").

8. **Refine and Organize:**  Structure the summary logically, using clear and concise language. Use bullet points or numbered lists for readability.

By following this systematic approach, we can effectively analyze the C++ test code and provide a comprehensive and accurate summary of its functionality, addressing all aspects of the user's request.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc` 文件的第 3 部分，主要侧重于 `QuicSentPacketManager` 类在处理数据包确认（ACK）、丢包检测、重传超时（PTO）以及多数据包编号空间时的行为。

以下是这部分代码片段的功能归纳：

**核心功能：**

* **处理重传超时 (RTO) 并触发重传:**  测试了在没有收到 ACK 的情况下，通过 `OnRetransmissionTimeout()` 触发丢包检测并标记数据包进行重传的场景。
* **应用层触发重传:**  模拟了应用层在得知丢包后，主动调用 `RetransmitDataPacket` 进行重传的情况。
* **处理重复 ACK (Spurious Retransmission):**  当收到之前因超时而被标记为丢失的数据包的 ACK 时，验证 `QuicSentPacketManager` 能正确更新 RTT，但不增加正在传输的字节数，并将此情况报告给丢包算法。
* **连接迁移后的处理:** 测试了连接迁移后，对于仍在途中的数据包的处理，包括标记重传但无需实际重传的情况。
* **处理连接迁移后的 ACK:**  验证了在连接迁移后收到旧路径上发送的数据包的 ACK 时，不会更新 RTT。
* **处理路径 MTU 增加:**  测试了当发送一个更大的数据包并收到 ACK 后，`QuicSentPacketManager` 能否通知网络状态监听器 MTU 增加。
* **处理乱序 ACK 范围:**  详细测试了 `OnAckRange` 方法处理多个不连续 ACK 范围的能力，包括正确标记 ACK 和丢包。
* **容忍重复的 ACK:**  验证了 `QuicSentPacketManager` 可以容忍重复的 ACK 范围，而不会出错。
* **支持多数据包编号空间:**  测试了在启用多数据包编号空间的情况下，`QuicSentPacketManager` 如何管理不同加密级别（INITIAL, HANDSHAKE, ZERO_RTT, FORWARD_SECURE）的数据包的发送和 ACK。
* **处理错误数据包编号空间的 ACK:** 测试了收到属于错误数据包编号空间的数据包的 ACK 时，`QuicSentPacketManager` 的行为，包括识别并标记这种情况。
* **容忍错误数据包编号空间的 ACK (在正确空间 ACK 之后):**  验证了如果一个数据包已经在正确的编号空间被 ACK，那么在错误的编号空间收到同样的 ACK 时可以被容忍。
* **计算探测超时 (PTO):**  测试了在不同情况下 `QuicSentPacketManager` 如何计算和更新 PTO 时间。
* **发送一个探测包:**  验证了在 PTO 超时后，`QuicSentPacketManager` 可以发送一个探测包。
* **禁用握手模式 (客户端/服务端):** 测试了在握手完成后，PTO 机制的调整，特别是在客户端和服务端行为上的差异。
* **使用 RTT 方差倍数计算 PTO 超时:**  验证了 PTO 超时时间的计算包含了 RTT 方差。
* **处理初始拥塞窗口 (IW) 配置:**  测试了如何根据配置设置初始拥塞窗口。
* **客户端多数据包编号空间下的 PTO 超时:**  详细测试了客户端在多数据包编号空间下，PTO 超时的计算和处理逻辑，包括在不同加密级别下发送数据包的影响。
* **服务端多数据包编号空间下的 PTO 超时:** 详细测试了服务端在多数据包编号空间下，PTO 超时的计算和处理逻辑。
* **基于最旧的未确认包计算 PTO 超时:**  验证了 PTO 超时是基于最早发送但尚未确认的数据包的时间来计算的。

**与 Javascript 的关系：**

`QuicSentPacketManager` 是 Chromium 网络栈中 QUIC 协议的核心组件，主要负责管理已发送但尚未确认的数据包，并进行丢包检测和重传等操作。 **它本身与 Javascript 没有直接的代码关系。**

然而，从概念上讲， Javascript 中使用 `fetch` API 或 WebSockets API 发起网络请求时，底层可能会使用 QUIC 协议（如果浏览器和服务器都支持）。  `QuicSentPacketManager` 的功能保证了这些请求的可靠传输。

**举例说明:**

假设一个 Javascript 应用使用 `fetch` API 发送了一个 HTTP/3 请求。

1. **Javascript (`fetch`):**  `fetch('/data')`
2. **浏览器网络栈:**  浏览器会将这个请求交给底层的网络栈处理，如果协商使用了 QUIC，则会进入 QUIC 协议栈。
3. **`QuicSentPacketManager`:**  `QuicSentPacketManager` 负责将请求数据封装成 QUIC 数据包并发送出去。
4. **丢包和重传 (本代码测试的功能):** 如果网络出现丢包，`QuicSentPacketManager` (通过其测试的逻辑) 会检测到丢包，并根据配置和算法自动重传丢失的数据包。
5. **数据传输完成:**  最终，数据包会可靠地到达服务器。
6. **服务器响应:** 服务器处理请求并返回响应。
7. **反向过程:**  服务器的 `QuicSentPacketManager` 也会进行类似的数据包管理。
8. **浏览器网络栈:** 浏览器网络栈接收到响应数据。
9. **Javascript (`fetch` promise resolve):** `fetch` API 的 Promise 会 resolve，Javascript 代码可以处理服务器返回的数据。

**逻辑推理 (假设输入与输出):**

**场景:**  触发重传超时 (RTO)

* **假设输入:**
    * 发送了数据包 4 (`SendDataPacket(4, ENCRYPTION_FORWARD_SECURE);`)。
    * 经过一段时间后，没有收到数据包 4 的 ACK。
    * 丢包检测算法判断需要触发重传超时 (`EXPECT_CALL(*loss_algorithm, GetLossTimeout()).WillOnce(Return(clock_.Now() + QuicTime::Delta::FromMilliseconds(10)));`).
* **预期输出:**
    * `OnRetransmissionTimeout()` 被调用。
    * 数据包 4 被标记为丢失 (`packet_lost->emplace_back(QuicPacketNumber(4u), kDefaultLength);`)。
    * `OnFrameLost` 通知被触发 (`EXPECT_CALL(notifier_, OnFrameLost(_));`).
    * 拥塞控制算法被通知 (`EXPECT_CALL(*send_algorithm_, OnCongestionEvent(false, kDefaultLength, _, _, _, _, _));`).
    * 正在传输的字节数变为 0 (`EXPECT_EQ(0u, BytesInFlight());`)，因为超时后认为数据包已丢失。

**用户或编程常见的使用错误:**

* **没有正确处理 ACK:** 如果上层代码没有正确地将接收到的 ACK 帧传递给 `QuicSentPacketManager`，会导致 `QuicSentPacketManager` 无法更新状态，可能错误地触发重传，影响性能。
* **错误配置重传超时参数:** 如果配置了不合理的重传超时时间，可能导致过早或过晚的重传，影响连接的响应速度和效率。
* **在连接迁移后没有清除旧路径状态:**  如果在连接迁移后没有正确地清理旧路径相关的状态信息，`QuicSentPacketManager` 可能会基于旧路径的状态做出错误的决策。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在使用 Chrome 浏览器访问一个使用 QUIC 协议的网站时遇到连接卡顿或数据传输缓慢的问题。作为开发者，在排查问题时，可能会逐步深入到 QUIC 协议栈的细节：

1. **用户报告问题:** 用户反馈网页加载缓慢或出现连接问题。
2. **网络抓包分析:**  开发者可能会使用 Wireshark 等工具抓取网络包，查看 QUIC 连接的详细信息，例如是否有大量的重传、ACK 延迟等。
3. **查看 Chrome Netlog:** Chrome 浏览器内置了 Netlog 功能，可以记录详细的网络事件，包括 QUIC 连接的状态、数据包的发送和接收情况、重传事件等。开发者可以通过 Netlog 分析找到可疑的事件。
4. **定位到 QUIC 协议栈:** 通过 Netlog 或抓包信息，开发者可能会怀疑问题出在 QUIC 协议栈的拥塞控制或丢包重传机制上。
5. **查看 `QuicSentPacketManager` 相关日志或代码:**  如果怀疑是数据包发送管理的问题，开发者可能会查看 `QuicSentPacketManager` 相关的代码和日志，了解数据包的发送、ACK 处理和重传逻辑。
6. **阅读测试代码 (`quic_sent_packet_manager_test.cc`):** 为了更深入地理解 `QuicSentPacketManager` 的工作原理和各种边界情况的处理，开发者可能会查看其单元测试代码，例如本文件。通过阅读测试代码，开发者可以了解在各种场景下 `QuicSentPacketManager` 的预期行为，从而更好地定位问题。

**总结这部分的功能:**

这部分测试代码主要关注 `QuicSentPacketManager` 在以下方面的功能：

* **可靠性保障:**  通过测试重传超时、重复 ACK 处理等，验证其在网络不稳定的情况下保证数据可靠传输的能力。
* **效率优化:**  通过测试连接迁移后的处理、多数据包编号空间的支持等，验证其在复杂网络环境下的效率。
* **协议一致性:** 通过测试 PTO 计算等，验证其对 QUIC 协议规范的实现。

总而言之，这部分代码是对 `QuicSentPacketManager` 核心功能的深入测试，确保其在各种场景下都能正确、高效地管理已发送的数据包，并处理丢包和重传等复杂情况，是 QUIC 协议可靠运行的关键保障。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""

  SendDataPacket(4, ENCRYPTION_FORWARD_SECURE);
  // Trigger loss timeout and mark packet4 for retransmission.
  EXPECT_CALL(*loss_algorithm, GetLossTimeout())
      .WillOnce(Return(clock_.Now() + QuicTime::Delta::FromMilliseconds(10)));
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _))
      .WillOnce(WithArgs<5>(Invoke([](LostPacketVector* packet_lost) {
        packet_lost->emplace_back(QuicPacketNumber(4u), kDefaultLength);
        return LossDetectionInterface::DetectionStats();
      })));
  EXPECT_CALL(notifier_, OnFrameLost(_));
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(false, kDefaultLength, _, _, _, _, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(0u, BytesInFlight());

  // Application retransmit the data as LOSS_RETRANSMISSION.
  RetransmitDataPacket(5, LOSS_RETRANSMISSION, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kDefaultLength, BytesInFlight());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(30));
  // Receiving an ACK for packet4 should update RTT, but not bytes in flight.
  // This spurious retransmission should be reported to the loss algorithm.
  manager_.OnAckFrameStart(QuicPacketNumber(4), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(4), QuicPacketNumber(5));
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*loss_algorithm, SpuriousLossDetected(_, _, _, _, _));
  EXPECT_CALL(
      *send_algorithm_,
      OnCongestionEvent(/*rtt_updated=*/true, kDefaultLength, _, _, _, _, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(3),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
  EXPECT_EQ(kDefaultLength, BytesInFlight());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(30),
            manager_.GetRttStats()->latest_rtt());

  // Migrate again with in-flight packet5 whose retransmittable frames are all
  // ACKed. Packet5 should be marked for retransmission but nothing to
  // retransmit.
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillOnce(Return(false));
  EXPECT_CALL(notifier_, OnFrameLost(_)).Times(0u);
  old_send_algorithm =
      manager_.OnConnectionMigration(/*reset_send_algorithm=*/true);
  EXPECT_EQ(default_init_rtt, rtt_stats->initial_rtt());
  EXPECT_EQ(0u, manager_.GetConsecutivePtoCount());
  EXPECT_EQ(0u, BytesInFlight());
  EXPECT_TRUE(manager_.GetRttStats()->latest_rtt().IsZero());

  manager_.SetSendAlgorithm(old_send_algorithm.release());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  // Receiving an ACK for packet5 shouldn't update RTT. Though packet 5 was
  // marked for retransmission, this spurious retransmission shouldn't be
  // reported to the loss algorithm.
  manager_.OnAckFrameStart(QuicPacketNumber(5), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(5), QuicPacketNumber(6));
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*loss_algorithm, SpuriousLossDetected(_, _, _, _, _)).Times(0u);
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(/*rtt_updated=*/false, 0, _, _, _, _, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(3),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
  EXPECT_EQ(0u, BytesInFlight());
  EXPECT_TRUE(manager_.GetRttStats()->latest_rtt().IsZero());
}

TEST_F(QuicSentPacketManagerTest, PathMtuIncreased) {
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, BytesInFlight(), QuicPacketNumber(1), _, _));
  SerializedPacket packet(QuicPacketNumber(1), PACKET_4BYTE_PACKET_NUMBER,
                          nullptr, kDefaultLength + 100, false, false);
  manager_.OnPacketSent(&packet, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA, true, ECN_NOT_ECT);

  // Ack the large packet and expect the path MTU to increase.
  ExpectAck(1);
  EXPECT_CALL(*network_change_visitor_,
              OnPathMtuIncreased(kDefaultLength + 100));
  QuicAckFrame ack_frame = InitAckFrame(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
}

TEST_F(QuicSentPacketManagerTest, OnAckRangeSlowPath) {
  // Send packets 1 - 20.
  for (size_t i = 1; i <= 20; ++i) {
    SendDataPacket(i);
  }
  // Ack [5, 7), [10, 12), [15, 17).
  uint64_t acked1[] = {5, 6, 10, 11, 15, 16};
  uint64_t lost1[] = {1, 2, 3, 4, 7, 8, 9, 12, 13};
  ExpectAcksAndLosses(true, acked1, ABSL_ARRAYSIZE(acked1), lost1,
                      ABSL_ARRAYSIZE(lost1));
  EXPECT_CALL(notifier_, OnFrameLost(_)).Times(AnyNumber());
  manager_.OnAckFrameStart(QuicPacketNumber(16), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(15), QuicPacketNumber(17));
  manager_.OnAckRange(QuicPacketNumber(10), QuicPacketNumber(12));
  manager_.OnAckRange(QuicPacketNumber(5), QuicPacketNumber(7));
  // Make sure empty range does not harm.
  manager_.OnAckRange(QuicPacketNumber(4), QuicPacketNumber(4));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  // Ack [4, 8), [9, 13), [14, 21).
  uint64_t acked2[] = {4, 7, 9, 12, 14, 17, 18, 19, 20};
  ExpectAcksAndLosses(true, acked2, ABSL_ARRAYSIZE(acked2), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(20), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(14), QuicPacketNumber(21));
  manager_.OnAckRange(QuicPacketNumber(9), QuicPacketNumber(13));
  manager_.OnAckRange(QuicPacketNumber(4), QuicPacketNumber(8));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
}

TEST_F(QuicSentPacketManagerTest, TolerateReneging) {
  // Send packets 1 - 20.
  for (size_t i = 1; i <= 20; ++i) {
    SendDataPacket(i);
  }
  // Ack [5, 7), [10, 12), [15, 17).
  uint64_t acked1[] = {5, 6, 10, 11, 15, 16};
  uint64_t lost1[] = {1, 2, 3, 4, 7, 8, 9, 12, 13};
  ExpectAcksAndLosses(true, acked1, ABSL_ARRAYSIZE(acked1), lost1,
                      ABSL_ARRAYSIZE(lost1));
  EXPECT_CALL(notifier_, OnFrameLost(_)).Times(AnyNumber());
  manager_.OnAckFrameStart(QuicPacketNumber(16), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(15), QuicPacketNumber(17));
  manager_.OnAckRange(QuicPacketNumber(10), QuicPacketNumber(12));
  manager_.OnAckRange(QuicPacketNumber(5), QuicPacketNumber(7));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  // Making sure reneged ACK does not harm. Ack [4, 8), [9, 13).
  uint64_t acked2[] = {4, 7, 9, 12};
  ExpectAcksAndLosses(true, acked2, ABSL_ARRAYSIZE(acked2), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(12), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(9), QuicPacketNumber(13));
  manager_.OnAckRange(QuicPacketNumber(4), QuicPacketNumber(8));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(QuicPacketNumber(16), manager_.GetLargestObserved());
}

TEST_F(QuicSentPacketManagerTest, MultiplePacketNumberSpaces) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  const QuicUnackedPacketMap* unacked_packets =
      QuicSentPacketManagerPeer::GetUnackedPacketMap(&manager_);
  EXPECT_FALSE(
      unacked_packets
          ->GetLargestSentRetransmittableOfPacketNumberSpace(INITIAL_DATA)
          .IsInitialized());
  EXPECT_FALSE(
      manager_.GetLargestAckedPacket(ENCRYPTION_INITIAL).IsInitialized());
  // Send packet 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  EXPECT_EQ(QuicPacketNumber(1),
            unacked_packets->GetLargestSentRetransmittableOfPacketNumberSpace(
                INITIAL_DATA));
  EXPECT_FALSE(
      unacked_packets
          ->GetLargestSentRetransmittableOfPacketNumberSpace(HANDSHAKE_DATA)
          .IsInitialized());
  // Ack packet 1.
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(QuicPacketNumber(1),
            manager_.GetLargestAckedPacket(ENCRYPTION_INITIAL));
  EXPECT_FALSE(
      manager_.GetLargestAckedPacket(ENCRYPTION_HANDSHAKE).IsInitialized());
  // Send packets 2 and 3.
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  SendDataPacket(3, ENCRYPTION_HANDSHAKE);
  EXPECT_EQ(QuicPacketNumber(1),
            unacked_packets->GetLargestSentRetransmittableOfPacketNumberSpace(
                INITIAL_DATA));
  EXPECT_EQ(QuicPacketNumber(3),
            unacked_packets->GetLargestSentRetransmittableOfPacketNumberSpace(
                HANDSHAKE_DATA));
  EXPECT_FALSE(
      unacked_packets
          ->GetLargestSentRetransmittableOfPacketNumberSpace(APPLICATION_DATA)
          .IsInitialized());
  // Ack packet 2.
  ExpectAck(2);
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_HANDSHAKE, kEmptyCounts));
  EXPECT_EQ(QuicPacketNumber(2),
            manager_.GetLargestAckedPacket(ENCRYPTION_HANDSHAKE));
  EXPECT_FALSE(
      manager_.GetLargestAckedPacket(ENCRYPTION_ZERO_RTT).IsInitialized());
  // Ack packet 3.
  ExpectAck(3);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(4));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(3),
                                   ENCRYPTION_HANDSHAKE, kEmptyCounts));
  EXPECT_EQ(QuicPacketNumber(3),
            manager_.GetLargestAckedPacket(ENCRYPTION_HANDSHAKE));
  EXPECT_FALSE(
      manager_.GetLargestAckedPacket(ENCRYPTION_ZERO_RTT).IsInitialized());
  // Send packets 4 and 5.
  SendDataPacket(4, ENCRYPTION_ZERO_RTT);
  SendDataPacket(5, ENCRYPTION_ZERO_RTT);
  EXPECT_EQ(QuicPacketNumber(1),
            unacked_packets->GetLargestSentRetransmittableOfPacketNumberSpace(
                INITIAL_DATA));
  EXPECT_EQ(QuicPacketNumber(3),
            unacked_packets->GetLargestSentRetransmittableOfPacketNumberSpace(
                HANDSHAKE_DATA));
  EXPECT_EQ(QuicPacketNumber(5),
            unacked_packets->GetLargestSentRetransmittableOfPacketNumberSpace(
                APPLICATION_DATA));
  // Ack packet 5.
  ExpectAck(5);
  manager_.OnAckFrameStart(QuicPacketNumber(5), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(5), QuicPacketNumber(6));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(4),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
  EXPECT_EQ(QuicPacketNumber(3),
            manager_.GetLargestAckedPacket(ENCRYPTION_HANDSHAKE));
  EXPECT_EQ(QuicPacketNumber(5),
            manager_.GetLargestAckedPacket(ENCRYPTION_ZERO_RTT));
  EXPECT_EQ(QuicPacketNumber(5),
            manager_.GetLargestAckedPacket(ENCRYPTION_FORWARD_SECURE));

  // Send packets 6 - 8.
  SendDataPacket(6, ENCRYPTION_FORWARD_SECURE);
  SendDataPacket(7, ENCRYPTION_FORWARD_SECURE);
  SendDataPacket(8, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(QuicPacketNumber(1),
            unacked_packets->GetLargestSentRetransmittableOfPacketNumberSpace(
                INITIAL_DATA));
  EXPECT_EQ(QuicPacketNumber(3),
            unacked_packets->GetLargestSentRetransmittableOfPacketNumberSpace(
                HANDSHAKE_DATA));
  EXPECT_EQ(QuicPacketNumber(8),
            unacked_packets->GetLargestSentRetransmittableOfPacketNumberSpace(
                APPLICATION_DATA));
  // Ack all packets.
  uint64_t acked[] = {4, 6, 7, 8};
  ExpectAcksAndLosses(true, acked, ABSL_ARRAYSIZE(acked), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(8), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(4), QuicPacketNumber(9));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(5),
                                   ENCRYPTION_FORWARD_SECURE, kEmptyCounts));
  EXPECT_EQ(QuicPacketNumber(3),
            manager_.GetLargestAckedPacket(ENCRYPTION_HANDSHAKE));
  EXPECT_EQ(QuicPacketNumber(8),
            manager_.GetLargestAckedPacket(ENCRYPTION_ZERO_RTT));
  EXPECT_EQ(QuicPacketNumber(8),
            manager_.GetLargestAckedPacket(ENCRYPTION_FORWARD_SECURE));
}

TEST_F(QuicSentPacketManagerTest, PacketsGetAckedInWrongPacketNumberSpace) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  // Send packet 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  // Send packets 2 and 3.
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  SendDataPacket(3, ENCRYPTION_HANDSHAKE);

  // ACK packets 2 and 3 in the wrong packet number space.
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(4));
  EXPECT_EQ(PACKETS_ACKED_IN_WRONG_PACKET_NUMBER_SPACE,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
}

TEST_F(QuicSentPacketManagerTest, PacketsGetAckedInWrongPacketNumberSpace2) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  // Send packet 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  // Send packets 2 and 3.
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  SendDataPacket(3, ENCRYPTION_HANDSHAKE);

  // ACK packet 1 in the wrong packet number space.
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(4));
  EXPECT_EQ(PACKETS_ACKED_IN_WRONG_PACKET_NUMBER_SPACE,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_HANDSHAKE, kEmptyCounts));
}

TEST_F(QuicSentPacketManagerTest,
       ToleratePacketsGetAckedInWrongPacketNumberSpace) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  // Send packet 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  // Ack packet 1.
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  // Send packets 2 and 3.
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  SendDataPacket(3, ENCRYPTION_HANDSHAKE);

  // Packet 1 gets acked in the wrong packet number space. Since packet 1 has
  // been acked in the correct packet number space, tolerate it.
  uint64_t acked[] = {2, 3};
  ExpectAcksAndLosses(true, acked, ABSL_ARRAYSIZE(acked), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(4));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_HANDSHAKE, kEmptyCounts));
}

TEST_F(QuicSentPacketManagerTest, ComputingProbeTimeout) {
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
  QuicTime packet1_sent_time = clock_.Now();
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(2, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO is set based on left edge.
  QuicTime deadline = packet1_sent_time + expected_pto_delay;
  EXPECT_EQ(deadline, manager_.GetRetransmissionTime());
  EXPECT_EQ(0u, stats_.pto_count);

  // Invoke PTO.
  clock_.AdvanceTime(deadline - clock_.Now());
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_EQ(1u, stats_.pto_count);
  EXPECT_EQ(0u, stats_.max_consecutive_rto_with_forward_progress);

  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(WithArgs<1>(Invoke([this](TransmissionType type) {
        return RetransmitDataPacket(3, type, ENCRYPTION_FORWARD_SECURE);
      })));
  manager_.MaybeSendProbePacket();
  // Verify PTO period gets set to twice the current value.
  QuicTime sent_time = clock_.Now();
  EXPECT_EQ(sent_time + expected_pto_delay * 2,
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
  EXPECT_EQ(sent_time + expected_pto_delay, manager_.GetRetransmissionTime());
  EXPECT_EQ(1u, stats_.max_consecutive_rto_with_forward_progress);
}

TEST_F(QuicSentPacketManagerTest, SendOneProbePacket) {
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));

  SendDataPacket(1, ENCRYPTION_FORWARD_SECURE);
  QuicTime packet1_sent_time = clock_.Now();
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(2, ENCRYPTION_FORWARD_SECURE);

  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  QuicTime::Delta srtt = rtt_stats->smoothed_rtt();
  // Verify PTO period is correctly set.
  QuicTime::Delta expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  // Verify PTO is set based on left edge.
  QuicTime deadline = packet1_sent_time + expected_pto_delay;
  EXPECT_EQ(deadline, manager_.GetRetransmissionTime());

  // Invoke PTO.
  clock_.AdvanceTime(deadline - clock_.Now());
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));

  // Verify one probe packet gets sent.
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(WithArgs<1>(Invoke([this](TransmissionType type) {
        return RetransmitDataPacket(3, type, ENCRYPTION_FORWARD_SECURE);
      })));
  manager_.MaybeSendProbePacket();
}

TEST_F(QuicSentPacketManagerTest, DisableHandshakeModeClient) {
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  manager_.EnableMultiplePacketNumberSpacesSupport();
  // Send CHLO.
  SendCryptoPacket(1);
  EXPECT_NE(QuicTime::Zero(), manager_.GetRetransmissionTime());
  // Ack packet 1.
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(0u, manager_.GetBytesInFlight());
  // Verify retransmission timeout is not zero because handshake is not
  // confirmed although there is no in flight packet.
  EXPECT_NE(QuicTime::Zero(), manager_.GetRetransmissionTime());
  // Fire PTO.
  EXPECT_EQ(QuicSentPacketManager::PTO_MODE,
            manager_.OnRetransmissionTimeout());
  // Send handshake packet.
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  // Ack packet 2.
  ExpectAck(2);
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_HANDSHAKE, kEmptyCounts));
  // Verify retransmission timeout is zero because server has successfully
  // processed HANDSHAKE packet.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, DisableHandshakeModeServer) {
  manager_.EnableIetfPtoAndLossDetection();
  // Send SHLO.
  SendCryptoPacket(1);
  EXPECT_NE(QuicTime::Zero(), manager_.GetRetransmissionTime());
  // Ack packet 1.
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(0u, manager_.GetBytesInFlight());
  // Verify retransmission timeout is not set on server side because there is
  // nothing in flight.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, PtoTimeoutRttVarMultiple) {
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  QuicTime::Delta srtt = rtt_stats->smoothed_rtt();

  SendDataPacket(1, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO is correctly set based on 2 times rtt var.
  QuicTime::Delta expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, IW10ForUpAndDown) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kBWS5);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*send_algorithm_, SetInitialCongestionWindowInPackets(10));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);

  EXPECT_EQ(10u, manager_.initial_congestion_window());
}

TEST_F(QuicSentPacketManagerTest, ClientMultiplePacketNumberSpacePtoTimeout) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  QuicTime::Delta srtt = rtt_stats->smoothed_rtt();
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);

  // Send packet 1.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  // Verify PTO is correctly set.
  QuicTime::Delta expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::Zero();
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());

  // Discard initial key and send packet 2 in handshake.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  manager_.NeuterUnencryptedPackets();

  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(true));
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);
  // Verify PTO is correctly set based on sent time of packet 2.
  EXPECT_EQ(clock_.Now() + expected_pto_delay,
            manager_.GetRetransmissionTime());
  // Invoke PTO.
  clock_.AdvanceTime(expected_pto_delay);
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_EQ(1u, stats_.pto_count);
  EXPECT_EQ(1u, stats_.crypto_retransmit_count);

  // Verify probe packet gets sent.
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(WithArgs<1>(Invoke([this](TransmissionType type) {
        return RetransmitDataPacket(3, type, ENCRYPTION_HANDSHAKE);
      })));
  manager_.MaybeSendProbePacket();
  // Verify PTO period gets set to twice the current value.
  const QuicTime packet3_sent_time = clock_.Now();
  EXPECT_EQ(packet3_sent_time + expected_pto_delay * 2,
            manager_.GetRetransmissionTime());

  // Send packet 4 in application data with 0-RTT.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(4, ENCRYPTION_ZERO_RTT);
  const QuicTime packet4_sent_time = clock_.Now();
  // Verify PTO timeout is still based on packet 3.
  EXPECT_EQ(packet3_sent_time + expected_pto_delay * 2,
            manager_.GetRetransmissionTime());

  // Send packet 5 in handshake.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(5, ENCRYPTION_HANDSHAKE);
  const QuicTime packet5_sent_time = clock_.Now();
  // Verify PTO timeout is now based on packet 5 because packet 4 should be
  // ignored.
  EXPECT_EQ(clock_.Now() + expected_pto_delay * 2,
            manager_.GetRetransmissionTime());

  // Send packet 6 in 1-RTT.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  SendDataPacket(6, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO timeout is now based on packet 5.
  EXPECT_EQ(packet5_sent_time + expected_pto_delay * 2,
            manager_.GetRetransmissionTime());

  // Send packet 7 in handshake.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  const QuicTime packet7_sent_time = clock_.Now();
  SendDataPacket(7, ENCRYPTION_HANDSHAKE);

  expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation();
  // Verify PTO timeout is now based on packet 7.
  EXPECT_EQ(packet7_sent_time + expected_pto_delay * 2,
            manager_.GetRetransmissionTime());

  // Neuter handshake key.
  manager_.SetHandshakeConfirmed();
  // Forward progress has been made, verify PTO counter gets reset. PTO timeout
  // is armed by left edge.
  expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  EXPECT_EQ(packet4_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, ServerMultiplePacketNumberSpacePtoTimeout) {
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
  expected_pto_delay =
      srtt + kPtoRttvarMultiplier * rtt_stats->mean_deviation() +
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  // Verify PTO timeout is now based on packet 3 as handshake is
  // complete/confirmed.
  EXPECT_EQ(packet3_sent_time + expected_pto_delay,
            manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, ComputingProbeTimeoutByLeftEdge) {
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
        
"""


```
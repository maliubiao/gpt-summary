Response:
The user wants to understand the functionality of the given C++ code snippet, which is part of a test file for the `QuicSentPacketManager` class in Chromium's QUIC implementation.

Here's a breakdown of the thinking process to analyze the code:

1. **Identify the Core Class Under Test:** The filename `quic_sent_packet_manager_test.cc` and the test fixture `QuicSentPacketManagerTest` clearly indicate that the code is testing the `QuicSentPacketManager` class.

2. **Understand the Role of `QuicSentPacketManager`:** Based on its name, this class likely manages the state of sent QUIC packets, including tracking acknowledgments, retransmissions, and congestion control.

3. **Analyze Individual Test Cases:**  Each `TEST_F` block represents a specific test case for a particular aspect of `QuicSentPacketManager`'s functionality. I'll go through each test case and summarize its purpose.

4. **Look for Interactions with JavaScript:**  Consider if any of the tested functionalities directly relate to how a web browser (which uses JavaScript) would interact with QUIC. Specifically, think about:
    * How acknowledgments are handled (impacts reliability and performance).
    * Congestion control mechanisms (affects network throughput).
    * Round-trip time (RTT) measurements (crucial for latency).
    * ECN (Explicit Congestion Notification) handling (for advanced congestion control).

5. **Identify Logic and Potential User Errors:**
    * **Logic:**  Focus on the assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`) and how the test setup leads to these assertions. This reveals the expected behavior.
    * **User Errors:** Think about how a programmer using the `QuicSentPacketManager` might misuse it or encounter issues due to incorrect configuration or assumptions.

6. **Trace User Operations (Debugging):**  Consider the sequence of actions that would lead to the execution of the code being tested. This involves thinking about the typical lifecycle of a QUIC connection.

7. **Address Specific Constraints:**  Pay attention to the explicit instructions in the prompt, such as providing input/output examples for logical reasoning and explaining the debugging process.

8. **Synthesize a Summary:** Combine the analysis of individual test cases into a concise overview of the file's purpose.

**Detailed Analysis of Test Cases:**

* **`UpdatePeerMaxAckDelay`:** Tests how the `peer_max_ack_delay` (advertised by the peer) is updated based on received ACK frames. It checks that later ACKs with smaller `max_ack_delay` values overwrite earlier ones.
* **`ClearDataInMessageFrameAfterPacketSent`:**  Verifies that the data within a `QuicMessageFrame` is cleared after the packet containing the message is sent. This likely prevents accidental re-use of the same buffer.
* **`BuildAckFrequencyFrame`:** Checks the construction of `AckFrequencyFrame`, focusing on the `max_ack_delay` field, which is calculated based on RTT. It also tests the packet tolerance.
* **`SmoothedRttIgnoreAckDelay`:** Examines how the smoothed RTT is calculated, specifically that the `ack_delay` from the peer is ignored during the initial RTT measurements.
* **`IgnorePeerMaxAckDelayDuringHandshake`:**  Confirms that the peer's advertised `max_ack_delay` is ignored during the QUIC handshake process.
* **`BuildAckFrequencyFrameWithSRTT`:** Similar to `BuildAckFrequencyFrame`, but tests the case where SRTT (smoothed RTT) is used in the calculation of `max_ack_delay`.
* **`SetInitialRtt`:**  Tests the setting of the initial RTT value, ensuring it respects the defined minimum and maximum bounds.
* **`GetAvailableCongestionWindow`:** Checks how the available congestion window is calculated based on the bytes in flight and the congestion window provided by the congestion control algorithm.
* **`EcnCountsAreStored`:**  Verifies that ECN (Explicit Congestion Notification) counts received in ACK frames are correctly stored and associated with the corresponding encryption level.
* **ECN Related Tests (`EcnCountsReceived`, `PeerDecrementsEcnCounts`, `TooManyEcnCountsReported`, `PeerReportsWrongCodepoint`, `TooFewEcnCountsReported`, `EcnCountsNotValidatedIfLargestAckedUnchanged`, `EcnAckedButNoMarksReported`):**  These tests thoroughly examine how the `QuicSentPacketManager` handles ECN feedback from the peer, including validating the reported counts and reacting to different scenarios (e.g., lost ACKs, incorrect counts, wrong codepoints).

**Relating to JavaScript:**  The core functions tested here directly impact the performance and reliability of web traffic. When a website is loaded in a browser, the browser uses network protocols like QUIC. The `QuicSentPacketManager`'s correct functioning is essential for a smooth user experience.

**Synthesizing the Conclusion (Part 5):**  The final part should summarize the overall purpose of the test file, emphasizing that it's a comprehensive suite for verifying the correct behavior of the `QuicSentPacketManager`.
这个C++源代码文件 `net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `QuicSentPacketManager` 类的功能。  `QuicSentPacketManager` 负责管理已发送的 QUIC 数据包，包括跟踪它们的状态（例如，是否被确认、是否需要重传）、计算 RTT (Round-Trip Time)、处理拥塞控制等关键任务。

**本代码片段的功能归纳 (第 5 部分)：**

这段代码主要集中在以下几个方面的测试：

1. **ECN (Explicit Congestion Notification) 功能的测试:**  这部分测试了 `QuicSentPacketManager` 如何处理接收到的 ACK 帧中携带的 ECN 信息。它涵盖了各种场景，例如：
    * 正确存储和关联不同加密级别的 ECN 计数。
    * 基于收到的 ECN 计数更新拥塞控制状态。
    * 验证收到的 ECN 计数的有效性，包括计数是否一致、是否报告了错误的 codepoint 等。
    * 在 `largest_acked` 包没有更新时，是否会跳过 ECN 验证。
    * 当收到确认但没有 ECN 标记报告时的处理。

**与 Javascript 功能的关系:**

`QuicSentPacketManager` 本身是用 C++ 实现的，与 JavaScript 没有直接的代码级别的关系。然而，它的功能直接影响着基于 Chromium 内核的浏览器（如 Chrome）中 JavaScript 发起的网络请求的性能和可靠性。

* **性能:**  `QuicSentPacketManager` 负责管理拥塞控制和 RTT 估计，这些都直接影响着网络连接的速度和效率。JavaScript 发起的 AJAX 请求、Fetch API 调用等，底层都依赖 QUIC 连接的有效管理。如果 `QuicSentPacketManager` 工作不正常，会导致网络请求延迟增加，甚至失败，从而影响 JavaScript 应用的用户体验。
* **可靠性:**  `QuicSentPacketManager` 负责跟踪已发送的数据包并处理重传。这确保了即使在网络不稳定的情况下，JavaScript 应用发送的数据也能可靠地到达服务器。

**举例说明:**

假设一个 JavaScript 应用程序通过 `fetch()` API 发送一个 POST 请求到服务器。

1. **用户操作:** 用户在网页上点击一个按钮，触发 JavaScript 代码执行 `fetch('/api/data', { method: 'POST', body: JSON.stringify({key: 'value'}) })`。
2. **到达 `QuicSentPacketManager`:**  Chromium 的网络栈会将这个请求的数据分割成 QUIC 数据包。`QuicSentPacketManager` 会记录这些数据包的信息，包括包编号、发送时间、包含的数据类型等。
3. **ECN 相关功能 (本代码片段测试的内容):**
   * 如果连接启用了 ECN，当服务器发送 ACK 帧时，可能会携带 ECN 信息（例如，ECT(1) 或 CE 标记）。
   * `QuicSentPacketManager` 会解析这些 ECN 信息，并将其与发送的数据包关联起来。
   * 例如，如果 ACK 帧报告了 CE 标记，`QuicSentPacketManager` 会根据配置，通知拥塞控制算法，可能导致发送速率的降低，以避免网络拥塞。
4. **影响 JavaScript:** 如果 `QuicSentPacketManager` 中处理 ECN 的逻辑存在错误（如代码片段测试的场景），可能导致：
   * **误判拥塞:**  即使网络没有真正拥塞，错误地接收或解析 ECN 信息可能导致错误地降低发送速率，从而降低 JavaScript 应用的网络性能。
   * **忽略拥塞:**  反之，如果 `QuicSentPacketManager` 没有正确处理 ECN 信息，可能会忽略网络拥塞的信号，导致数据包丢失增加，最终影响 JavaScript 应用的可靠性。

**逻辑推理，假设输入与输出:**

考虑 `TEST_F(QuicSentPacketManagerTest, EcnCountsReceived)` 这个测试用例：

* **假设输入:**
    * 发送了 3 个数据包 (Packet Number 1, 2, 3)，都标记了 ECN_ECT1。
    * 接收到一个 ACK 帧，确认了 Packet Number 2 和 3。
    * ACK 帧报告的 ECN 计数为 ECT(1) = 2, CE = 1。

* **逻辑推理:**
    * 由于 Packet 1 的 ACK 丢失，只有 Packet 2 和 3 被成功确认。
    * ACK 帧报告的 ECT(1) = 2 意味着接收端收到了 2 个带有 ECT(1) 标记的包。由于 Packet 1 的 ACK 丢失，发送端也认为有两个带有 ECT(1) 标记的包被成功接收。
    * ACK 帧报告的 CE = 1 意味着接收端观察到了 1 个拥塞事件。

* **预期输出:**
    * `OnInFlightEcnPacketAcked()` 应该被调用两次，对应 Packet 2 和 3 的确认。
    * 拥塞控制算法的 `OnCongestionEvent` 方法应该被调用，并且 `acked_packets` 参数应该包含 Packet Number 2 和 3。
    * `OnCongestionEvent` 的 `ecn_counters` 参数应该与 ACK 帧报告的 ECN 计数一致 (ECT(1) = 2, CE = 1)。

**涉及用户或者编程常见的使用错误:**

虽然用户（开发者）通常不会直接操作 `QuicSentPacketManager`，但理解其工作原理有助于理解网络性能问题。

* **配置错误 (虽然不直接在 `QuicSentPacketManager` 中配置):**  服务器或客户端的 QUIC 配置可能不一致，导致 ECN 功能无法正常工作。例如，服务器支持 ECN，但客户端没有启用，或者反之。
* **网络环境问题:**  某些中间网络设备可能错误地剥离或修改 ECN 标记，导致 `QuicSentPacketManager` 收到错误的 ECN 信息。
* **调试困难:**  由于网络协议的复杂性，与 ECN 相关的错误可能难以调试。开发者可能需要使用网络抓包工具 (如 Wireshark) 来分析数据包，才能理解 ECN 信息是否正确传递。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个用户在 Chrome 浏览器中访问一个网站，该网站使用了 QUIC 协议，并且网络环境可能存在拥塞。以下是可能导致相关代码被执行的步骤，作为调试线索：

1. **用户在浏览器地址栏输入网址并回车，或者点击一个链接。**
2. **浏览器发起连接请求。**  如果服务器支持 QUIC，浏览器会尝试建立 QUIC 连接。
3. **QUIC 握手阶段。**  客户端和服务器协商 QUIC 参数，包括是否启用 ECN。
4. **数据传输阶段。**  浏览器（作为 QUIC 客户端）发送 HTTP/3 请求的数据包。
5. **网络拥塞发生。**  在数据包传输过程中，网络中的路由器可能检测到拥塞，并设置数据包的 ECN 标记 (例如，CE)。
6. **服务器接收到带有 ECN 标记的数据包。**
7. **服务器发送 ACK 帧。**  ACK 帧会携带接收到的 ECN 计数信息。
8. **客户端（浏览器）接收到带有 ECN 信息的 ACK 帧。**
9. **`QuicSentPacketManager::OnAckFrameEnd` 被调用。**  这个函数会解析 ACK 帧中的 ECN 信息。
10. **ECN 计数处理逻辑执行。**  `QuicSentPacketManager` 会根据收到的 ECN 计数，更新内部状态，并通知拥塞控制算法。
11. **如果出现与 ECN 相关的错误，例如收到的 ECN 计数与预期不符，或者 ECN 标记错误，那么在 `quic_sent_packet_manager_test.cc` 中编写的相应测试用例就会模拟这些场景，帮助开发者发现和修复这些问题。**

因此，当开发者在调试与 QUIC 相关的网络性能或可靠性问题，特别是涉及到网络拥塞的场景时，`QuicSentPacketManager` 以及其处理 ECN 的逻辑就成为了重要的排查点。 代码中的测试用例可以帮助验证这部分逻辑的正确性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
NO_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                        ECN_NOT_ECT);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_4_ms);

  // Ack frame3.
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(4));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                         ENCRYPTION_FORWARD_SECURE, kEmptyCounts);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_2_ms);
  // Acking frame1 do not affect peer_max_ack_delay after frame3 is acked.
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(4));
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                         ENCRYPTION_FORWARD_SECURE, kEmptyCounts);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_2_ms);
  // Acking frame2 do not affect peer_max_ack_delay after frame3 is acked.
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(4));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                         ENCRYPTION_FORWARD_SECURE, kEmptyCounts);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_2_ms);
  // Acking frame4 updates peer_max_ack_delay.
  manager_.OnAckFrameStart(QuicPacketNumber(4), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(5));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                         ENCRYPTION_FORWARD_SECURE, kEmptyCounts);
  EXPECT_EQ(manager_.peer_max_ack_delay(), extra_1_ms);
}

TEST_F(QuicSentPacketManagerTest, ClearDataInMessageFrameAfterPacketSent) {
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);

  QuicMessageFrame* message_frame = nullptr;
  {
    quiche::QuicheMemSlice slice(quiche::QuicheBuffer(&allocator_, 1024));
    message_frame = new QuicMessageFrame(/*message_id=*/1, std::move(slice));
    EXPECT_FALSE(message_frame->message_data.empty());
    EXPECT_EQ(message_frame->message_length, 1024);

    SerializedPacket packet(QuicPacketNumber(1), PACKET_4BYTE_PACKET_NUMBER,
                            /*encrypted_buffer=*/nullptr, kDefaultLength,
                            /*has_ack=*/false,
                            /*has_stop_waiting*/ false);
    packet.encryption_level = ENCRYPTION_FORWARD_SECURE;
    packet.retransmittable_frames.push_back(QuicFrame(message_frame));
    packet.has_message = true;
    manager_.OnPacketSent(&packet, clock_.Now(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA, /*measure_rtt=*/true,
                          ECN_NOT_ECT);
  }

  EXPECT_TRUE(message_frame->message_data.empty());
  EXPECT_EQ(message_frame->message_length, 0);
}

TEST_F(QuicSentPacketManagerTest, BuildAckFrequencyFrame) {
  SetQuicReloadableFlag(quic_can_send_ack_frequency, true);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  QuicConfig config;
  QuicConfigPeer::SetReceivedMinAckDelayMs(&config, /*min_ack_delay_ms=*/1);
  manager_.SetFromConfig(config);
  manager_.SetHandshakeConfirmed();

  // Set up RTTs.
  auto* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(80),
                       /*ack_delay=*/QuicTime::Delta::Zero(),
                       /*now=*/QuicTime::Zero());
  // Make sure srtt and min_rtt are different.
  rtt_stats->UpdateRtt(
      QuicTime::Delta::FromMilliseconds(160),
      /*ack_delay=*/QuicTime::Delta::Zero(),
      /*now=*/QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(24));

  auto frame = manager_.GetUpdatedAckFrequencyFrame();
  EXPECT_EQ(frame.max_ack_delay,
            std::max(rtt_stats->min_rtt() * 0.25,
                     QuicTime::Delta::FromMilliseconds(1u)));
  EXPECT_EQ(frame.packet_tolerance, 10u);
}

TEST_F(QuicSentPacketManagerTest, SmoothedRttIgnoreAckDelay) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kMAD0);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));
  manager_.SetFromConfig(config);

  SendDataPacket(1);
  // Ack 1.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(300));
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1),
                           QuicTime::Delta::FromMilliseconds(100),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  // Verify that ack_delay is ignored in the first measurement.
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300),
            manager_.GetRttStats()->latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300),
            manager_.GetRttStats()->smoothed_rtt());

  SendDataPacket(2);
  // Ack 2.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(300));
  ExpectAck(2);
  manager_.OnAckFrameStart(QuicPacketNumber(2),
                           QuicTime::Delta::FromMilliseconds(100),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300),
            manager_.GetRttStats()->latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300),
            manager_.GetRttStats()->smoothed_rtt());

  SendDataPacket(3);
  // Ack 3.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(300));
  ExpectAck(3);
  manager_.OnAckFrameStart(QuicPacketNumber(3),
                           QuicTime::Delta::FromMilliseconds(50), clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(4));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(3),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300),
            manager_.GetRttStats()->latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300),
            manager_.GetRttStats()->smoothed_rtt());

  SendDataPacket(4);
  // Ack 4.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(200));
  ExpectAck(4);
  manager_.OnAckFrameStart(QuicPacketNumber(4),
                           QuicTime::Delta::FromMilliseconds(300),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(4), QuicPacketNumber(5));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(4),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  // Verify that large erroneous ack_delay does not change Smoothed RTT.
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200),
            manager_.GetRttStats()->latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMicroseconds(287500),
            manager_.GetRttStats()->smoothed_rtt());
}

TEST_F(QuicSentPacketManagerTest, IgnorePeerMaxAckDelayDuringHandshake) {
  manager_.EnableMultiplePacketNumberSpacesSupport();
  // 100ms RTT.
  const QuicTime::Delta kTestRTT = QuicTime::Delta::FromMilliseconds(100);

  // Server sends INITIAL 1 and HANDSHAKE 2.
  SendDataPacket(1, ENCRYPTION_INITIAL);
  SendDataPacket(2, ENCRYPTION_HANDSHAKE);

  // Receive client ACK for INITIAL 1 after one RTT.
  clock_.AdvanceTime(kTestRTT);
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(kTestRTT, manager_.GetRttStats()->latest_rtt());

  // Assume the cert verification on client takes 50ms, such that the HANDSHAKE
  // packet is queued for 50ms.
  const QuicTime::Delta queuing_delay = QuicTime::Delta::FromMilliseconds(50);
  clock_.AdvanceTime(queuing_delay);
  // Ack 2.
  ExpectAck(2);
  manager_.OnAckFrameStart(QuicPacketNumber(2), queuing_delay, clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_HANDSHAKE, kEmptyCounts));
  EXPECT_EQ(kTestRTT, manager_.GetRttStats()->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, BuildAckFrequencyFrameWithSRTT) {
  SetQuicReloadableFlag(quic_can_send_ack_frequency, true);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  QuicConfig config;
  QuicConfigPeer::SetReceivedMinAckDelayMs(&config, /*min_ack_delay_ms=*/1);
  QuicTagVector quic_tag_vector;
  quic_tag_vector.push_back(kAFF1);  // SRTT enabling tag.
  QuicConfigPeer::SetReceivedConnectionOptions(&config, quic_tag_vector);
  manager_.SetFromConfig(config);
  manager_.SetHandshakeConfirmed();

  // Set up RTTs.
  auto* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(80),
                       /*ack_delay=*/QuicTime::Delta::Zero(),
                       /*now=*/QuicTime::Zero());
  // Make sure srtt and min_rtt are different.
  rtt_stats->UpdateRtt(
      QuicTime::Delta::FromMilliseconds(160),
      /*ack_delay=*/QuicTime::Delta::Zero(),
      /*now=*/QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(24));

  auto frame = manager_.GetUpdatedAckFrequencyFrame();
  EXPECT_EQ(frame.max_ack_delay,
            std::max(rtt_stats->SmoothedOrInitialRtt() * 0.25,
                     QuicTime::Delta::FromMilliseconds(1u)));
}

TEST_F(QuicSentPacketManagerTest, SetInitialRtt) {
  // Upper bounds.
  manager_.SetInitialRtt(
      QuicTime::Delta::FromMicroseconds(kMaxInitialRoundTripTimeUs + 1), false);
  EXPECT_EQ(manager_.GetRttStats()->initial_rtt().ToMicroseconds(),
            kMaxInitialRoundTripTimeUs);

  manager_.SetInitialRtt(
      QuicTime::Delta::FromMicroseconds(kMaxInitialRoundTripTimeUs + 1), true);
  EXPECT_EQ(manager_.GetRttStats()->initial_rtt().ToMicroseconds(),
            kMaxInitialRoundTripTimeUs);

  EXPECT_GT(kMinUntrustedInitialRoundTripTimeUs,
            kMinTrustedInitialRoundTripTimeUs);

  // Lower bounds for untrusted rtt.
  manager_.SetInitialRtt(QuicTime::Delta::FromMicroseconds(
                             kMinUntrustedInitialRoundTripTimeUs - 1),
                         false);
  EXPECT_EQ(manager_.GetRttStats()->initial_rtt().ToMicroseconds(),
            kMinUntrustedInitialRoundTripTimeUs);

  // Lower bounds for trusted rtt.
  manager_.SetInitialRtt(QuicTime::Delta::FromMicroseconds(
                             kMinUntrustedInitialRoundTripTimeUs - 1),
                         true);
  EXPECT_EQ(manager_.GetRttStats()->initial_rtt().ToMicroseconds(),
            kMinUntrustedInitialRoundTripTimeUs - 1);

  manager_.SetInitialRtt(
      QuicTime::Delta::FromMicroseconds(kMinTrustedInitialRoundTripTimeUs - 1),
      true);
  EXPECT_EQ(manager_.GetRttStats()->initial_rtt().ToMicroseconds(),
            kMinTrustedInitialRoundTripTimeUs);
}

TEST_F(QuicSentPacketManagerTest, GetAvailableCongestionWindow) {
  SendDataPacket(1);
  EXPECT_EQ(kDefaultLength, manager_.GetBytesInFlight());

  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillOnce(Return(kDefaultLength + 10));
  EXPECT_EQ(10u, manager_.GetAvailableCongestionWindowInBytes());

  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillOnce(Return(kDefaultLength));
  EXPECT_EQ(0u, manager_.GetAvailableCongestionWindowInBytes());

  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillOnce(Return(kDefaultLength - 10));
  EXPECT_EQ(0u, manager_.GetAvailableCongestionWindowInBytes());
}

TEST_F(QuicSentPacketManagerTest, EcnCountsAreStored) {
  if (!GetQuicRestartFlag(quic_support_ect1)) {
    return;
  }
  std::optional<QuicEcnCounts> ecn_counts1, ecn_counts2, ecn_counts3;
  ecn_counts1 = {1, 0, 3};
  ecn_counts2 = {0, 3, 1};
  ecn_counts3 = {0, 2, 0};
  SendDataPacket(1, ENCRYPTION_INITIAL, ECN_ECT0);
  SendDataPacket(2, ENCRYPTION_INITIAL, ECN_ECT0);
  SendDataPacket(3, ENCRYPTION_INITIAL, ECN_ECT0);
  SendDataPacket(4, ENCRYPTION_INITIAL, ECN_ECT0);
  SendDataPacket(5, ENCRYPTION_HANDSHAKE, ECN_ECT1);
  SendDataPacket(6, ENCRYPTION_HANDSHAKE, ECN_ECT1);
  SendDataPacket(7, ENCRYPTION_HANDSHAKE, ECN_ECT1);
  SendDataPacket(8, ENCRYPTION_HANDSHAKE, ECN_ECT1);
  SendDataPacket(9, ENCRYPTION_FORWARD_SECURE, ECN_ECT1);
  SendDataPacket(10, ENCRYPTION_FORWARD_SECURE, ECN_ECT1);
  MockDebugDelegate debug_delegate;
  manager_.SetDebugDelegate(&debug_delegate);
  bool correct_report = false;
  EXPECT_CALL(debug_delegate, OnIncomingAck(_, _, _, _, _, _, _))
      .WillOnce(Invoke(
          [&](QuicPacketNumber /*ack_packet_number*/,
              EncryptionLevel /*ack_decrypted_level*/,
              const QuicAckFrame& ack_frame, QuicTime /*ack_receive_time*/,
              QuicPacketNumber /*largest_observed*/, bool /*rtt_updated*/,
              QuicPacketNumber /*least_unacked_sent_packet*/) {
            correct_report = (ack_frame.ecn_counters == ecn_counts1);
          }));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1), ENCRYPTION_INITIAL,
                         ecn_counts1);
  EXPECT_TRUE(correct_report);
  correct_report = false;
  EXPECT_CALL(debug_delegate, OnIncomingAck(_, _, _, _, _, _, _))
      .WillOnce(Invoke(
          [&](QuicPacketNumber /*ack_packet_number*/,
              EncryptionLevel /*ack_decrypted_level*/,
              const QuicAckFrame& ack_frame, QuicTime /*ack_receive_time*/,
              QuicPacketNumber /*largest_observed*/, bool /*rtt_updated*/,
              QuicPacketNumber /*least_unacked_sent_packet*/) {
            correct_report = (ack_frame.ecn_counters == ecn_counts2);
          }));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                         ENCRYPTION_HANDSHAKE, ecn_counts2);
  EXPECT_TRUE(correct_report);
  correct_report = false;
  EXPECT_CALL(debug_delegate, OnIncomingAck(_, _, _, _, _, _, _))
      .WillOnce(Invoke(
          [&](QuicPacketNumber /*ack_packet_number*/,
              EncryptionLevel /*ack_decrypted_level*/,
              const QuicAckFrame& ack_frame, QuicTime /*ack_receive_time*/,
              QuicPacketNumber /*largest_observed*/, bool /*rtt_updated*/,
              QuicPacketNumber /*least_unacked_sent_packet*/) {
            correct_report = (ack_frame.ecn_counters == ecn_counts3);
          }));
  manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(3),
                         ENCRYPTION_FORWARD_SECURE, ecn_counts3);
  EXPECT_TRUE(correct_report);
  EXPECT_EQ(
      *QuicSentPacketManagerPeer::GetPeerEcnCounts(&manager_, INITIAL_DATA),
      ecn_counts1);
  EXPECT_EQ(
      *QuicSentPacketManagerPeer::GetPeerEcnCounts(&manager_, HANDSHAKE_DATA),
      ecn_counts2);
  EXPECT_EQ(
      *QuicSentPacketManagerPeer::GetPeerEcnCounts(&manager_, APPLICATION_DATA),
      ecn_counts3);
}

TEST_F(QuicSentPacketManagerTest, EcnCountsReceived) {
  if (!GetQuicRestartFlag(quic_support_ect1)) {
    return;
  }
  // Basic ECN reporting test. The reported counts are equal to the total sent,
  // but more than the total acked. This is legal per the spec.
  for (uint64_t i = 1; i <= 3; ++i) {
    SendDataPacket(i, ENCRYPTION_FORWARD_SECURE, ECN_ECT1);
  }
  // Ack the last two packets, but report 3 counts (ack of 1 was lost).
  EXPECT_CALL(*network_change_visitor_, OnInFlightEcnPacketAcked()).Times(2);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(4));
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(_, _, _, Pointwise(PacketNumberEq(), {2, 3}),
                                IsEmpty(), 2, 1))
      .Times(1);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange()).Times(1);
  std::optional<QuicEcnCounts> ecn_counts = QuicEcnCounts();
  ecn_counts->ect1 = QuicPacketCount(2);
  ecn_counts->ce = QuicPacketCount(1);
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, ecn_counts));
}

TEST_F(QuicSentPacketManagerTest, PeerDecrementsEcnCounts) {
  if (!GetQuicRestartFlag(quic_support_ect1)) {
    return;
  }
  for (uint64_t i = 1; i <= 5; ++i) {
    SendDataPacket(i, ENCRYPTION_FORWARD_SECURE, ECN_ECT1);
  }
  // Ack all three packets).
  EXPECT_CALL(*network_change_visitor_, OnInFlightEcnPacketAcked()).Times(3);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(4));
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(_, _, _, Pointwise(PacketNumberEq(), {1, 2, 3}),
                                IsEmpty(), 2, 1))
      .Times(1);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange()).Times(1);
  std::optional<QuicEcnCounts> ecn_counts = QuicEcnCounts();
  ecn_counts->ect1 = QuicPacketCount(2);
  ecn_counts->ce = QuicPacketCount(1);
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, ecn_counts));
  // New ack, counts decline
  EXPECT_CALL(*network_change_visitor_, OnInFlightEcnPacketAcked()).Times(1);
  manager_.OnAckFrameStart(QuicPacketNumber(4), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(4), QuicPacketNumber(5));
  EXPECT_CALL(*network_change_visitor_, OnInvalidEcnFeedback());
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(_, _, _, Pointwise(PacketNumberEq(), {4}),
                                IsEmpty(), 0, 0))
      .Times(1);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange()).Times(1);
  ecn_counts = QuicEcnCounts();
  ecn_counts->ect1 = QuicPacketCount(3);
  ecn_counts->ce = QuicPacketCount(0);  // Reduced CE count
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_FORWARD_SECURE, ecn_counts));
}

TEST_F(QuicSentPacketManagerTest, TooManyEcnCountsReported) {
  if (!GetQuicRestartFlag(quic_support_ect1)) {
    return;
  }
  for (uint64_t i = 1; i <= 3; ++i) {
    SendDataPacket(i, ENCRYPTION_FORWARD_SECURE, ECN_ECT1);
  }
  // Ack the last two packets, but report 3 counts (ack of 1 was lost).
  EXPECT_CALL(*network_change_visitor_, OnInFlightEcnPacketAcked()).Times(2);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(4));
  std::optional<QuicEcnCounts> ecn_counts = QuicEcnCounts();
  // Report 4 counts, but only 3 packets were sent.
  ecn_counts->ect1 = QuicPacketCount(3);
  ecn_counts->ce = QuicPacketCount(1);
  EXPECT_CALL(*network_change_visitor_, OnInvalidEcnFeedback());
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(_, _, _, Pointwise(PacketNumberEq(), {2, 3}),
                                IsEmpty(), 0, 0))
      .Times(1);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange()).Times(1);

  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, ecn_counts));
}

TEST_F(QuicSentPacketManagerTest, PeerReportsWrongCodepoint) {
  if (!GetQuicRestartFlag(quic_support_ect1)) {
    return;
  }
  for (uint64_t i = 1; i <= 3; ++i) {
    SendDataPacket(i, ENCRYPTION_FORWARD_SECURE, ECN_ECT1);
  }
  // Ack the last two packets, but report 3 counts (ack of 1 was lost).
  EXPECT_CALL(*network_change_visitor_, OnInFlightEcnPacketAcked()).Times(2);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(4));
  std::optional<QuicEcnCounts> ecn_counts = QuicEcnCounts();
  // Report the wrong codepoint.
  ecn_counts->ect0 = QuicPacketCount(2);
  ecn_counts->ce = QuicPacketCount(1);
  EXPECT_CALL(*network_change_visitor_, OnInvalidEcnFeedback());
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(_, _, _, Pointwise(PacketNumberEq(), {2, 3}),
                                IsEmpty(), 0, 0))
      .Times(1);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange()).Times(1);

  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, ecn_counts));
}

TEST_F(QuicSentPacketManagerTest, TooFewEcnCountsReported) {
  if (!GetQuicRestartFlag(quic_support_ect1)) {
    return;
  }
  for (uint64_t i = 1; i <= 3; ++i) {
    SendDataPacket(i, ENCRYPTION_FORWARD_SECURE, ECN_ECT1);
  }
  // Ack the last two packets, but report 3 counts (ack of 1 was lost).
  EXPECT_CALL(*network_change_visitor_, OnInFlightEcnPacketAcked()).Times(2);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(4));
  EXPECT_CALL(*network_change_visitor_, OnInvalidEcnFeedback());
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(_, _, _, Pointwise(PacketNumberEq(), {2, 3}),
                                IsEmpty(), 0, 0))
      .Times(1);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange()).Times(1);
  std::optional<QuicEcnCounts> ecn_counts = QuicEcnCounts();
  // 2 ECN packets were newly acked, but only one count was reported.
  ecn_counts->ect1 = QuicPacketCount(1);
  ecn_counts->ce = QuicPacketCount(0);
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, ecn_counts));
}

TEST_F(QuicSentPacketManagerTest,
       EcnCountsNotValidatedIfLargestAckedUnchanged) {
  if (!GetQuicRestartFlag(quic_support_ect1)) {
    return;
  }
  for (uint64_t i = 1; i <= 3; ++i) {
    SendDataPacket(i, ENCRYPTION_FORWARD_SECURE, ECN_ECT1);
  }
  // Ack two packets.
  EXPECT_CALL(*network_change_visitor_, OnInFlightEcnPacketAcked()).Times(2);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(4));
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(_, _, _, Pointwise(PacketNumberEq(), {2, 3}),
                                IsEmpty(), 2, 1))
      .Times(1);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange()).Times(1);
  std::optional<QuicEcnCounts> ecn_counts = QuicEcnCounts();
  ecn_counts->ect1 = QuicPacketCount(2);
  ecn_counts->ce = QuicPacketCount(1);
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, ecn_counts));
  // Ack the first packet, which will not update largest_acked.
  EXPECT_CALL(*network_change_visitor_, OnInFlightEcnPacketAcked()).Times(1);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(4));
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(_, _, _, Pointwise(PacketNumberEq(), {1}),
                                IsEmpty(), 0, 0))
      .Times(1);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange()).Times(1);
  ecn_counts = QuicEcnCounts();
  // Counts decline, but there's no validation because largest_acked didn't
  // change.
  ecn_counts->ect1 = QuicPacketCount(2);
  ecn_counts->ce = QuicPacketCount(0);  // Reduced CE count
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_FORWARD_SECURE, ecn_counts));
}

TEST_F(QuicSentPacketManagerTest, EcnAckedButNoMarksReported) {
  if (!GetQuicRestartFlag(quic_support_ect1)) {
    return;
  }
  for (uint64_t i = 1; i <= 3; ++i) {
    SendDataPacket(i, ENCRYPTION_FORWARD_SECURE, ECN_ECT1);
  }
  // Ack the last two packets, but report 3 counts (ack of 1 was lost).
  EXPECT_CALL(*network_change_visitor_, OnInFlightEcnPacketAcked()).Times(2);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(4));
  EXPECT_CALL(*network_change_visitor_, OnInvalidEcnFeedback());
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(_, _, _, Pointwise(PacketNumberEq(), {2, 3}),
                                IsEmpty(), 0, 0))
      .Times(1);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange()).Times(1);
  std::optional<QuicEcnCounts> ecn_counts = std::nullopt;
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_FORWARD_SECURE, ecn_counts));
}

}  // namespace
}  // namespace test
}  // namespace quic
```
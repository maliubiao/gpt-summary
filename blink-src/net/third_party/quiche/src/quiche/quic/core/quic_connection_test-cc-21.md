Response:
The user is asking for a summary of the functionality of a specific part of the `quic_connection_test.cc` file. This part seems to focus on various aspects of QUIC connection management, especially related to packet processing, retransmission, encryption levels, connection ID management, and server preferred address handling. I need to go through the provided code snippet and identify the key functionalities being tested.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Test Fixture:** The code is part of the `QuicConnectionTest` fixture, indicating that it's testing the `QuicConnection` class.

2. **Analyze Individual Tests:** Examine each `TEST_P` block to understand the specific scenario being tested.

3. **Group Related Tests:** Look for tests that address similar concepts. For instance, multiple tests deal with encryption levels (INITIAL, HANDSHAKE, FORWARD_SECURE) and how packets at those levels are processed and retransmitted. Connection ID changes and server preferred address validation also form distinct groups.

4. **Focus on the Actions:** Within each test, identify the key actions being performed by the connection object (e.g., `SendCryptoDataWithString`, `SendStreamDataWithString`, `RemoveEncrypter`, `NeuterUnencryptedPackets`, `ProcessUdpPacket`).

5. **Determine the Assertions:** Note the `ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE` calls. These reveal the expected outcomes of the tested actions and thus the functionality being verified.

6. **Look for Specific Features:** Pay attention to keywords like "coalesced packet," "retransmission alarm," "ACK delay," "undecryptable packets," "anti-amplification," "server preferred address," and "connection ID." These highlight the specific QUIC features being tested.

7. **Infer the Functionality:** Based on the actions and assertions, deduce the functionality being tested. For example, tests involving sending data at different encryption levels and then removing keys likely test key management and packet discard. Tests involving `GetRetransmissionAlarm()->Fire()` test retransmission logic.

8. **Address Specific Instructions:**  The prompt asks about relationships with JavaScript, logical reasoning with input/output, common user errors, debugging, and the overall function of this specific part.

    * **JavaScript:**  QUIC is a transport protocol. While JavaScript might use QUIC through browser APIs for network communication, the core logic within `quic_connection_test.cc` is at a lower level and doesn't directly interact with JavaScript code in the same process. However, the *effects* of QUIC behavior (like faster connection establishment or better handling of packet loss) would be observable by JavaScript applications.

    * **Logical Reasoning (Input/Output):**  Many tests set up specific scenarios (e.g., receiving certain packets) and then check the output (e.g., what packets are sent, alarm states, internal connection state). The "Process..." functions act as inputs, and the assertions verify the outputs. I can construct simple examples of these.

    * **User/Programming Errors:**  Tests involving incorrect key management or assumptions about packet processing can illustrate potential errors.

    * **Debugging:** The tests themselves provide debugging information by setting up specific sequences of events and verifying the intermediate and final states. The user actions would involve setting up a connection and observing its behavior.

    * **Overall Function:**  Synthesize the individual functionalities into a broader description of what this section of the test file covers.

9. **Handle the "Part 22 of 24" Instruction:**  This suggests that the current section focuses on specific, possibly advanced or later-stage, aspects of connection management after the initial handshake.

By following these steps, I can systematically analyze the code and construct a comprehensive and accurate summary that addresses all the user's requirements.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 文件的第 22 部分，共 24 部分。 从提供的代码片段来看，这一部分主要集中在测试 `QuicConnection` 类的以下功能：

**核心功能归纳:**

1. **重传和拥塞控制的交互:**
   - 测试了在接收到握手阶段的 Ping 帧后丢弃初始加密密钥，并随后触发重传报警的情况。
   - 验证了重传的包是否正确地包含了握手和 1-RTT 数据包，以及重传报警是否仍然被激活。
   - 模拟了由于接收到握手 Ping 而丢弃初始密钥后，发送数据导致拥塞窗口受限的情况。

2. **RTT 采样和延迟 ACK 处理:**
   - 测试了当 ACK 包对应的解密密钥不可用时，RTT 采样是否不包含排队延迟。
   - 模拟了接收到针对 0-RTT 数据包的 1-RTT ACK，并在一段时间后才提供 1-RTT 解密密钥的情况。
   - 验证了 RTT 样本的计算是否正确排除了密钥不可用期间的延迟。

3. **避免重复序列化 Initial 包中的额外填充:**
   - 这是一个回归测试，旨在确保在重新序列化 Initial 包时不会出现额外的填充字节。
   - 模拟了接收到 INITIAL 和 0-RTT 包后，发送包含 INITIAL、HANDSHAKE 和 1-RTT 数据的合并包的场景。
   - 验证了在特定情况下，序列化第二个 1-RTT 包后的待处理填充字节是否为零，以避免潜在的 bug。

4. **报告的 ACK 延迟包含排队延迟:**
   - 测试了当接收到需要 ACK 的 1-RTT 包但密钥不可用时，报告的 ACK 延迟是否包含了排队延迟。
   - 模拟了在密钥不可用时接收到 PING 帧，然后在密钥可用后触发 ACK 报警的情况。
   - 验证了 ACK 帧中的 `ack_delay_time` 是否正确反映了延迟 ACK 的时间。

5. **合并 1-RTT 包与 Initial 和 Handshake 包:**
   - 测试了将 1-RTT 数据包与 Initial 和 Handshake 数据包合并发送的能力。
   - 模拟了接收到 INITIAL 和 0-RTT 包后，发送包含 INITIAL、HANDSHAKE 和 1-RTT 数据的合并包，并随后接收到另一个 INITIAL 包的场景。
   - 验证了合并包的发送和处理，以及各个加密级别的包的正确处理。

6. **发送多个连接关闭帧:**
   - 这是一个回归测试，旨在防止在黑洞检测期间多次调用 `BeforeConnectionCloseSent` 导致问题。
   - 模拟了连接处于黑洞检测状态时，发送连接关闭包，然后触发黑洞检测报警，导致再次发送连接关闭包的情况。
   - 验证了 `BeforeConnectionCloseSent` 被调用了两次，而 `OnConnectionClosed` 只被调用一次。

7. **PTO 触发时最早发送时间未初始化:**
   - 这是一个回归测试，确保在 PTO (Path Transmission Timeout) 触发时，最早发送时间已正确初始化。
   - 模拟了接收到 INITIAL 包并发送包含 INITIAL、HANDSHAKE 和部分 1-RTT 数据的包，然后接收到 INITIAL 和 HANDSHAKE 包的 ACK 的情况。
   - 验证了在只有部分 1-RTT 数据未被 ACK 的情况下，PTO 报警不会被触发。

8. **计算网络黑洞延迟:**
   - 测试了 `CalculateNetworkBlackholeDelay` 函数的计算逻辑。
   - 提供了不同的输入参数（黑洞延迟，路径降级延迟，PTO 延迟），并验证了计算出的黑洞延迟是否符合预期。

9. **修复缓冲合并包的字节统计:**
   - 测试了当写入被阻塞时，合并包的填充字节是否被正确计入已发送字节数。
   - 模拟了写入被阻塞后，发送一个 PING 包的情况。
   - 验证了统计数据中已发送的字节数是否等于最大包长度。

10. **严格的反放大限制:**
    - 测试了服务器在握手完成前，发送数据量是否受到接收数据量的严格限制，以防止放大攻击。
    - 模拟了服务器在不同阶段发送数据，并验证发送的数据量是否符合反放大系数的限制。
    - 验证了在违反严格反放大限制的情况下，连接关闭的行为。

11. **原始连接 ID 的处理:**
    - 测试了 `GetOriginalDestinationConnectionId` 的功能以及在服务器端处理 0-RTT 解密密钥丢弃定时器的情况。
    - 模拟了设置原始目标连接 ID 并接收 1-RTT 数据包的场景。
    - 验证了定时器的启动和触发，以及原始连接 ID 的保留。

12. **服务器连接 ID 在接收到延迟的 Initial 包后更改:**
    - 测试了服务器在接收到客户端的 Initial 包后更改连接 ID 的情况，并处理延迟到达的 Initial 包。
    - 模拟了客户端发送 Initial 包后，服务器发送包含新连接 ID 的 Handshake 包和 1-RTT 包，然后接收到延迟的 Initial 包的情况。
    - 验证了连接 ID 的更改和未解密数据包的正确处理。

13. **服务器连接 ID 在接收到延迟的 Initial 包后更改两次:**
    - 扩展了上面的测试，模拟了服务器在接收到延迟的 Initial 包后更改两次连接 ID 的情况。
    - 验证了在连接 ID 发生变化后，之前缓冲的包是否被正确处理或丢弃。

14. **客户端验证服务器首选地址:**
    - 测试了客户端通过从服务器首选地址接收 PATH_RESPONSE 帧来验证服务器首选地址的场景。
    - 模拟了客户端接收到服务器首选地址后，发起路径验证，并在验证期间发送数据的情况。
    - 验证了路径验证的流程，包括 PATH_CHALLENGE 和 PATH_RESPONSE 帧的交互，以及成功验证后连接路径的切换和连接 ID 的更新。

**与 JavaScript 功能的关系:**

虽然这段 C++ 代码直接操作的是网络协议栈的底层实现，与 JavaScript 代码没有直接的语法或 API 上的联系，但它所测试的 QUIC 连接的特性会直接影响到基于浏览器的 JavaScript 应用的网络性能和用户体验。

例如：

* **更快的连接建立:**  测试中涉及的 0-RTT 数据发送和早期密钥交换功能，能够让 JavaScript 应用在连接建立时更快地发送数据，减少页面加载时间。
* **更好的抗丢包能力:**  测试中关于重传机制的验证，确保了即使在网络不稳定的情况下，JavaScript 应用也能可靠地传输数据。
* **连接迁移:**  测试中关于客户端验证服务器首选地址的功能，确保了在网络地址发生变化时，连接能够平滑迁移，避免 JavaScript 应用中断连接。
* **安全性:**  测试中关于加密级别和密钥管理的验证，保证了 JavaScript 应用通过 QUIC 连接传输数据的安全性。

**逻辑推理和假设输入/输出示例:**

**测试用例:** `RTTSampleDoesNotIncludeQueuingDelayWithPostponedAckProcessing`

**假设输入:**
1. 客户端发送一个 0-RTT 数据包。
2. 服务器在一段时间后发送一个 1-RTT ACK 包，但客户端此时还没有 1-RTT 解密密钥。
3. 客户端在收到 ACK 包一段时间后才获得 1-RTT 解密密钥。

**预期输出:**
* 当客户端处理 ACK 包时，计算出的 RTT 样本不应包含 ACK 包在客户端等待密钥期间的排队延迟。

**测试用例:** `CoalesceOneRTTPacketWithInitialAndHandshakePackets`

**假设输入:**
1. 客户端发送一个 INITIAL 包。
2. 服务器接收到该 INITIAL 包。
3. 客户端发送一个 0-RTT 包。
4. 服务器接收到该 0-RTT 包。

**操作:** 服务器尝试发送一个包含 INITIAL、HANDSHAKE 和 1-RTT 数据的合并包，然后接收到另一个 INITIAL 包。

**预期输出:**
* 服务器能够成功发送合并包，并且所有加密级别的包都能被正确处理。
* 合并包中的每个子包都能被独立解析和处理。

**用户或编程常见的使用错误示例:**

* **密钥管理错误:**  如果在握手过程中，客户端或服务器没有正确地安装或激活相应的加密密钥，会导致数据包无法解密，就像测试用例中模拟的场景一样。这可能是由于编程错误或配置不当造成的。
* **对合并包处理的误解:**  开发者可能会错误地认为合并包只是一个单一的包，而忽略了其中可能包含多个不同加密级别的子包，导致处理逻辑错误。
* **反放大限制的理解不足:**  服务器开发者可能不清楚反放大限制，在握手完成前发送过多的数据，导致连接被断开。
* **连接 ID 管理错误:**  在连接迁移或更换连接 ID 的过程中，如果端点没有正确地更新和使用新的连接 ID，会导致数据包丢失或无法路由。

**用户操作如何到达这里作为调试线索:**

1. **用户发起网络请求:** 用户在浏览器中访问一个使用 QUIC 协议的网站或应用。
2. **浏览器建立 QUIC 连接:** 浏览器与服务器之间开始 QUIC 握手过程。
3. **握手阶段的密钥交换:**  在握手过程中，客户端和服务器会协商加密密钥。如果密钥交换过程中出现问题（例如，由于网络延迟或数据包丢失），可能会导致测试用例中模拟的密钥不可用或延迟到达的情况。
4. **数据传输:** 握手完成后，浏览器和服务器开始传输应用数据。如果数据传输过程中出现丢包或网络拥塞，可能会触发重传机制，对应测试用例中关于重传的测试。
5. **网络地址变化:**  如果用户的网络环境发生变化（例如，从 Wi-Fi 切换到移动网络），可能会触发连接迁移，对应测试用例中关于客户端验证服务器首选地址的测试。
6. **服务器配置:** 服务器的配置（例如，是否启用 0-RTT、是否支持连接迁移）也会影响 QUIC 连接的行为，这些行为在测试用例中都有所覆盖。

当调试 QUIC 连接问题时，可以关注以下线索，这些线索与测试用例中模拟的场景相关：

* **握手失败或延迟:** 检查握手过程中的数据包交换，特别是密钥交换相关的包。
* **数据包丢失和重传:**  观察是否有大量的重传发生，以及重传的数据包类型和加密级别。
* **RTT 波动:**  测量 RTT 值，看是否出现异常的延迟或抖动。
* **连接迁移失败:**  检查连接迁移过程中是否有错误发生，例如，新的路径验证失败。
* **连接被意外关闭:**  查看连接关闭的原因码，是否与反放大限制或内部错误有关。

**第 22 部分功能归纳:**

总的来说，这部分测试代码主要关注 QUIC 连接在握手完成前后的一些关键功能和边界情况，包括：

* **数据传输的可靠性和效率:** 通过测试重传、拥塞控制和合并包等机制。
* **连接的安全性和抗攻击能力:** 通过测试加密级别和反放大限制等功能。
* **连接的灵活性和适应性:** 通过测试连接迁移和连接 ID 管理等功能。
* **协议实现的健壮性:** 通过进行各种回归测试，确保代码在各种场景下都能正常工作。

作为 24 部分中的第 22 部分，可以推测这部分测试涵盖了相对高级或在连接生命周期后期才会触发的功能，例如连接迁移、更细致的拥塞控制交互以及对特定边界情况的处理。它可能依赖于之前部分测试中建立的连接基础功能，并在此基础上进行更深入的测试。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第22部分，共24部分，请归纳一下它的功能

"""
   connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
    connection_.SendCryptoDataWithString(std::string(200, 'a'), 0,
                                         ENCRYPTION_HANDSHAKE);
    // Send 1-RTT 3.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    connection_.SendStreamDataWithString(0, std::string(40, 'a'), 0, NO_FIN);
  }
  // Received HANDSHAKE Ping, hence discard INITIAL keys.
  peer_framer_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                            std::make_unique<TaggingEncrypter>(0x03));
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_HANDSHAKE);
  clock_.AdvanceTime(kAlarmGranularity);
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // Sending this 1-RTT data would leave the coalescer only have space to
    // accommodate the HANDSHAKE ACK. The crypto data cannot be bundled with the
    // ACK.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    connection_.SendStreamDataWithString(0, std::string(1395, 'a'), 40, NO_FIN);
  }
  // Verify retransmission alarm is armed.
  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  const QuicTime retransmission_time =
      connection_.GetRetransmissionAlarm()->deadline();
  clock_.AdvanceTime(retransmission_time - clock_.Now());
  connection_.GetRetransmissionAlarm()->Fire();

  // Verify the retransmission is a coalesced packet with HANDSHAKE 2 and
  // 1-RTT 3.
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
  // Only the first packet in the coalesced packet has been processed.
  EXPECT_EQ(1u, writer_->crypto_frames().size());
  // Process the coalesced 1-RTT packet.
  ASSERT_TRUE(writer_->coalesced_packet() != nullptr);
  auto packet = writer_->coalesced_packet()->Clone();
  writer_->framer()->ProcessPacket(*packet);
  EXPECT_EQ(1u, writer_->stream_frames().size());
  ASSERT_TRUE(writer_->coalesced_packet() == nullptr);
  // Verify retransmission alarm is still armed.
  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest,
       RTTSampleDoesNotIncludeQueuingDelayWithPostponedAckProcessing) {
  // An endpoint might postpone the processing of ACK when the corresponding
  // decryption key is not available. This test makes sure the RTT sample does
  // not include the queuing delay.
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.set_max_undecryptable_packets(3);
  connection_.SetFromConfig(config);

  // 30ms RTT.
  const QuicTime::Delta kTestRTT = QuicTime::Delta::FromMilliseconds(30);
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(kTestRTT, QuicTime::Delta::Zero(), QuicTime::Zero());

  // Send 0-RTT packet.
  connection_.RemoveDecrypter(ENCRYPTION_FORWARD_SECURE);
  connection_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  connection_.SendStreamDataWithString(0, std::string(10, 'a'), 0, FIN);

  // Receives 1-RTT ACK for 0-RTT packet after RTT + ack_delay.
  clock_.AdvanceTime(kTestRTT + QuicTime::Delta::FromMilliseconds(
                                    GetDefaultDelayedAckTimeMs()));
  EXPECT_EQ(0u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));
  peer_framer_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  QuicAckFrame ack_frame = InitAckFrame(1);
  // Peer reported ACK delay.
  ack_frame.ack_delay_time =
      QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  QuicFrames frames;
  frames.push_back(QuicFrame(&ack_frame));
  QuicPacketHeader header =
      ConstructPacketHeader(30, ENCRYPTION_FORWARD_SECURE);
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));

  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length = peer_framer_.EncryptPayload(
      ENCRYPTION_FORWARD_SECURE, QuicPacketNumber(30), *packet, buffer,
      kMaxOutgoingPacketSize);
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false));
  if (connection_.GetSendAlarm()->IsSet()) {
    connection_.GetSendAlarm()->Fire();
  }
  ASSERT_EQ(1u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));

  // Assume 1-RTT decrypter is available after 10ms.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  EXPECT_FALSE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());
  SetDecrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  ASSERT_TRUE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  connection_.GetProcessUndecryptablePacketsAlarm()->Fire();
  // Verify RTT sample does not include queueing delay.
  EXPECT_EQ(rtt_stats->latest_rtt(), kTestRTT);
}

// Regression test for b/112480134.
TEST_P(QuicConnectionTest, NoExtraPaddingInReserializedInitial) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration() ||
      !connection_.version().CanSendCoalescedPackets()) {
    return;
  }

  set_perspective(Perspective::IS_SERVER);
  MockQuicConnectionDebugVisitor debug_visitor;
  connection_.set_debug_visitor(&debug_visitor);

  uint64_t debug_visitor_sent_count = 0;
  EXPECT_CALL(debug_visitor, OnPacketSent(_, _, _, _, _, _, _, _, _))
      .WillRepeatedly([&]() { debug_visitor_sent_count++; });

  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());

  // Received INITIAL 1.
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);

  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_HANDSHAKE));
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));

  // Received ENCRYPTION_ZERO_RTT 2.
  ProcessDataPacketAtLevel(2, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);

  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // Send INITIAL 1.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
    connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_INITIAL);
    // Send HANDSHAKE 2.
    EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
    connection_.SendCryptoDataWithString(std::string(200, 'a'), 0,
                                         ENCRYPTION_HANDSHAKE);
    // Send 1-RTT 3.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    connection_.SendStreamDataWithString(0, std::string(400, 'b'), 0, NO_FIN);
  }

  // Arrange the stream data to be sent in response to ENCRYPTION_INITIAL 3.
  const std::string data4(1000, '4');  // Data to send in stream id 4
  const std::string data8(3000, '8');  // Data to send in stream id 8
  EXPECT_CALL(visitor_, OnCanWrite()).WillOnce([&]() {
    connection_.producer()->SaveStreamData(4, data4);
    connection_.producer()->SaveStreamData(8, data8);

    notifier_.WriteOrBufferData(4, data4.size(), FIN_AND_PADDING);

    // This should trigger FlushCoalescedPacket.
    notifier_.WriteOrBufferData(8, data8.size(), FIN);
  });

  QuicByteCount pending_padding_after_serialize_2nd_1rtt_packet = 0;
  QuicPacketCount num_1rtt_packets_serialized = 0;
  EXPECT_CALL(connection_, OnSerializedPacket(_))
      .WillRepeatedly([&](SerializedPacket packet) {
        if (packet.encryption_level == ENCRYPTION_FORWARD_SECURE) {
          num_1rtt_packets_serialized++;
          if (num_1rtt_packets_serialized == 2) {
            pending_padding_after_serialize_2nd_1rtt_packet =
                connection_.packet_creator().pending_padding_bytes();
          }
        }
        connection_.QuicConnection::OnSerializedPacket(std::move(packet));
      });

  // Server receives INITIAL 3, this will serialzie FS 7 (stream 4, stream 8),
  // which will trigger a flush of a coalesced packet consists of INITIAL 4,
  // HS 5 and FS 6 (stream 4).

  // Expect no QUIC_BUG.
  ProcessDataPacketAtLevel(3, !kHasStopWaiting, ENCRYPTION_INITIAL);
  EXPECT_EQ(
      debug_visitor_sent_count,
      connection_.sent_packet_manager().GetLargestSentPacket().ToUint64());

  // The error only happens if after serializing the second 1RTT packet(pkt #7),
  // the pending padding bytes is non zero.
  EXPECT_GT(pending_padding_after_serialize_2nd_1rtt_packet, 0u);
  EXPECT_TRUE(connection_.connected());
}

TEST_P(QuicConnectionTest, ReportedAckDelayIncludesQueuingDelay) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.set_max_undecryptable_packets(3);
  connection_.SetFromConfig(config);

  // Receive 1-RTT ack-eliciting packet while keys are not available.
  connection_.RemoveDecrypter(ENCRYPTION_FORWARD_SECURE);
  peer_framer_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicPingFrame()));
  frames.push_back(QuicFrame(QuicPaddingFrame(100)));
  QuicPacketHeader header =
      ConstructPacketHeader(30, ENCRYPTION_FORWARD_SECURE);
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));

  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length = peer_framer_.EncryptPayload(
      ENCRYPTION_FORWARD_SECURE, QuicPacketNumber(30), *packet, buffer,
      kMaxOutgoingPacketSize);
  EXPECT_EQ(0u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));
  const QuicTime packet_receipt_time = clock_.Now();
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false));
  if (connection_.GetSendAlarm()->IsSet()) {
    connection_.GetSendAlarm()->Fire();
  }
  ASSERT_EQ(1u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));
  // 1-RTT keys become available after 10ms.
  const QuicTime::Delta kQueuingDelay = QuicTime::Delta::FromMilliseconds(10);
  clock_.AdvanceTime(kQueuingDelay);
  EXPECT_FALSE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  SetDecrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  ASSERT_TRUE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());

  connection_.GetProcessUndecryptablePacketsAlarm()->Fire();
  ASSERT_TRUE(connection_.HasPendingAcks());
  EXPECT_EQ(packet_receipt_time + DefaultDelayedAckTime(),
            connection_.GetAckAlarm()->deadline());
  clock_.AdvanceTime(packet_receipt_time + DefaultDelayedAckTime() -
                     clock_.Now());
  // Fire ACK alarm.
  connection_.GetAckAlarm()->Fire();
  ASSERT_EQ(1u, writer_->ack_frames().size());
  // Verify ACK delay time does not include queuing delay.
  EXPECT_EQ(DefaultDelayedAckTime(), writer_->ack_frames()[0].ack_delay_time);
}

TEST_P(QuicConnectionTest, CoalesceOneRTTPacketWithInitialAndHandshakePackets) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());

  // Received INITIAL 1.
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);

  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));

  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_HANDSHAKE));
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));

  // Received ENCRYPTION_ZERO_RTT 2.
  ProcessDataPacketAtLevel(2, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);

  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // Send INITIAL 1.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
    connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_INITIAL);
    // Send HANDSHAKE 2.
    EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
    connection_.SendCryptoDataWithString(std::string(200, 'a'), 0,
                                         ENCRYPTION_HANDSHAKE);
    // Send 1-RTT data.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    connection_.SendStreamDataWithString(0, std::string(2000, 'b'), 0, FIN);
  }
  // Verify coalesced packet [INITIAL 1 + HANDSHAKE 2 + part of 1-RTT data] +
  // rest of 1-RTT data get sent.
  EXPECT_EQ(2u, writer_->packets_write_attempts());

  // Received ENCRYPTION_INITIAL 3.
  ProcessDataPacketAtLevel(3, !kHasStopWaiting, ENCRYPTION_INITIAL);

  // Verify a coalesced packet gets sent.
  EXPECT_EQ(3u, writer_->packets_write_attempts());

  // Only the first INITIAL packet has been processed yet.
  EXPECT_EQ(1u, writer_->ack_frames().size());
  EXPECT_EQ(1u, writer_->crypto_frames().size());

  // Process HANDSHAKE packet.
  ASSERT_TRUE(writer_->coalesced_packet() != nullptr);
  auto packet = writer_->coalesced_packet()->Clone();
  writer_->framer()->ProcessPacket(*packet);
  EXPECT_EQ(1u, writer_->crypto_frames().size());
  // Process 1-RTT packet.
  ASSERT_TRUE(writer_->coalesced_packet() != nullptr);
  packet = writer_->coalesced_packet()->Clone();
  writer_->framer()->ProcessPacket(*packet);
  EXPECT_EQ(1u, writer_->stream_frames().size());
}

// Regression test for b/180103273
TEST_P(QuicConnectionTest, SendMultipleConnectionCloses) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration()) {
    return;
  }
  if (!version().HasIetfQuicFrames() ||
      !GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2)) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  // Finish handshake.
  QuicConnectionPeer::SetAddressValidated(&connection_);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  notifier_.NeuterUnencryptedData();
  connection_.NeuterUnencryptedPackets();
  connection_.OnHandshakeComplete();
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.RemoveEncrypter(ENCRYPTION_HANDSHAKE);
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));

  SendStreamDataToPeer(1, "foo", 0, NO_FIN, nullptr);
  ASSERT_TRUE(connection_.BlackholeDetectionInProgress());
  // Verify that BeforeConnectionCloseSent() gets called twice,
  // while OnConnectionClosed() is called only once.
  EXPECT_CALL(visitor_, BeforeConnectionCloseSent()).Times(2);
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  // Send connection close w/o closing connection.
  QuicConnectionPeer::SendConnectionClosePacket(
      &connection_, INTERNAL_ERROR, QUIC_INTERNAL_ERROR, "internal error");
  // Fire blackhole detection alarm.  This will invoke
  // SendConnectionClosePacket() a second time.
  EXPECT_QUIC_BUG(connection_.GetBlackholeDetectorAlarm()->Fire(),
                  // 1=QUIC_INTERNAL_ERROR, 85=QUIC_TOO_MANY_RTOS.
                  "Initial error code: 1, new error code: 85");
}

// Regression test for b/157895910.
TEST_P(QuicConnectionTest, EarliestSentTimeNotInitializedWhenPtoFires) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());

  // Received INITIAL 1.
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // Send INITIAL 1.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
    connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_INITIAL);
    // Send HANDSHAKE 2.
    EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
    connection_.SendCryptoDataWithString(std::string(200, 'a'), 0,
                                         ENCRYPTION_HANDSHAKE);
    // Send half RTT data.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    connection_.SendStreamDataWithString(0, std::string(2000, 'b'), 0, FIN);
  }

  // Received ACKs for both INITIAL and HANDSHAKE packets.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(AnyNumber());
  QuicFrames frames1;
  QuicAckFrame ack_frame1 = InitAckFrame(1);
  frames1.push_back(QuicFrame(&ack_frame1));

  QuicFrames frames2;
  QuicAckFrame ack_frame2 =
      InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)}});
  frames2.push_back(QuicFrame(&ack_frame2));
  ProcessCoalescedPacket(
      {{2, frames1, ENCRYPTION_INITIAL}, {3, frames2, ENCRYPTION_HANDSHAKE}});
  // Verify PTO is not armed given the only outstanding data is half RTT data.
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, CalculateNetworkBlackholeDelay) {
  if (!IsDefaultTestConfiguration()) {
    return;
  }

  const QuicTime::Delta kOneSec = QuicTime::Delta::FromSeconds(1);
  const QuicTime::Delta kTwoSec = QuicTime::Delta::FromSeconds(2);
  const QuicTime::Delta kFourSec = QuicTime::Delta::FromSeconds(4);

  // Normal case: blackhole_delay longer than path_degrading_delay +
  // 2*pto_delay.
  EXPECT_EQ(QuicConnection::CalculateNetworkBlackholeDelay(kFourSec, kOneSec,
                                                           kOneSec),
            kFourSec);

  EXPECT_EQ(QuicConnection::CalculateNetworkBlackholeDelay(kFourSec, kOneSec,
                                                           kTwoSec),
            QuicTime::Delta::FromSeconds(5));
}

TEST_P(QuicConnectionTest, FixBytesAccountingForBufferedCoalescedPackets) {
  if (!connection_.version().CanSendCoalescedPackets()) {
    return;
  }
  // Write is blocked.
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AnyNumber());
  writer_->SetWriteBlocked();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  QuicConnectionPeer::SendPing(&connection_);
  const QuicConnectionStats& stats = connection_.GetStats();
  // Verify padding is accounted.
  EXPECT_EQ(stats.bytes_sent, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, StrictAntiAmplificationLimit) {
  if (!connection_.version().SupportsAntiAmplificationLimit()) {
    return;
  }
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(AnyNumber());
  set_perspective(Perspective::IS_SERVER);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Verify no data can be sent at the beginning because bytes received is 0.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SendCryptoDataWithString("foo", 0);
  EXPECT_FALSE(connection_.CanWrite(HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(connection_.CanWrite(NO_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  const size_t anti_amplification_factor =
      GetQuicFlag(quic_anti_amplification_factor);
  // Receives packet 1.
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(anti_amplification_factor);
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  connection_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<TaggingEncrypter>(0x03));

  for (size_t i = 1; i < anti_amplification_factor - 1; ++i) {
    connection_.SendCryptoDataWithString("foo", i * 3);
  }
  // Send an addtion packet with max_packet_size - 1.
  connection_.SetMaxPacketLength(connection_.max_packet_length() - 1);
  connection_.SendCryptoDataWithString("bar",
                                       (anti_amplification_factor - 1) * 3);
  EXPECT_LT(writer_->total_bytes_written(),
            anti_amplification_factor *
                QuicConnectionPeer::BytesReceivedOnDefaultPath(&connection_));
  if (GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    // 3 connection closes which will be buffered.
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(3);
    // Verify retransmission alarm is not set.
    EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  } else {
    // Crypto + 3 connection closes.
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(4);
    EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  }
  // Try to send another packet with max_packet_size.
  connection_.SetMaxPacketLength(connection_.max_packet_length() + 1);
  connection_.SendCryptoDataWithString("bar", anti_amplification_factor * 3);
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  // Close connection.
  EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  connection_.CloseConnection(
      QUIC_INTERNAL_ERROR, "error",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  if (GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    EXPECT_LT(writer_->total_bytes_written(),
              anti_amplification_factor *
                  QuicConnectionPeer::BytesReceivedOnDefaultPath(&connection_));
  } else {
    EXPECT_LT(writer_->total_bytes_written(),
              (anti_amplification_factor + 2) *
                  QuicConnectionPeer::BytesReceivedOnDefaultPath(&connection_));
    EXPECT_GT(writer_->total_bytes_written(),
              (anti_amplification_factor + 1) *
                  QuicConnectionPeer::BytesReceivedOnDefaultPath(&connection_));
  }
}

TEST_P(QuicConnectionTest, OriginalConnectionId) {
  set_perspective(Perspective::IS_SERVER);
  EXPECT_FALSE(connection_.GetDiscardZeroRttDecryptionKeysAlarm()->IsSet());
  EXPECT_EQ(connection_.GetOriginalDestinationConnectionId(),
            connection_.connection_id());
  QuicConnectionId original({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
  connection_.SetOriginalDestinationConnectionId(original);
  EXPECT_EQ(original, connection_.GetOriginalDestinationConnectionId());
  // Send a 1-RTT packet to start the DiscardZeroRttDecryptionKeys timer.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(1, false, ENCRYPTION_FORWARD_SECURE);
  if (connection_.version().UsesTls()) {
    EXPECT_TRUE(connection_.GetDiscardZeroRttDecryptionKeysAlarm()->IsSet());
    EXPECT_CALL(visitor_, OnServerConnectionIdRetired(original));
    connection_.GetDiscardZeroRttDecryptionKeysAlarm()->Fire();
    EXPECT_EQ(connection_.GetOriginalDestinationConnectionId(),
              connection_.connection_id());
  } else {
    EXPECT_EQ(connection_.GetOriginalDestinationConnectionId(), original);
  }
}

ACTION_P2(InstallKeys, conn, level) {
  uint8_t crypto_input = (level == ENCRYPTION_FORWARD_SECURE) ? 0x03 : 0x02;
  conn->SetEncrypter(level, std::make_unique<TaggingEncrypter>(crypto_input));
  conn->InstallDecrypter(
      level, std::make_unique<StrictTaggingDecrypter>(crypto_input));
  conn->SetDefaultEncryptionLevel(level);
}

TEST_P(QuicConnectionTest, ServerConnectionIdChangeWithLateInitial) {
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  // Call SetFromConfig so that the undecrypted packet buffer size is
  // initialized above zero.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(1);
  QuicConfig config;
  connection_.SetFromConfig(config);
  connection_.RemoveEncrypter(ENCRYPTION_FORWARD_SECURE);
  connection_.RemoveDecrypter(ENCRYPTION_FORWARD_SECURE);

  // Send Client Initial.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.SendCryptoStreamData();

  EXPECT_EQ(1u, writer_->packets_write_attempts());
  // Server Handshake packet with new connection ID is buffered.
  QuicConnectionId old_id = connection_id_;
  connection_id_ = TestConnectionId(2);
  peer_creator_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                             std::make_unique<TaggingEncrypter>(0x02));
  ProcessCryptoPacketAtLevel(0, ENCRYPTION_HANDSHAKE);
  EXPECT_EQ(QuicConnectionPeer::NumUndecryptablePackets(&connection_), 1u);
  EXPECT_EQ(connection_.connection_id(), old_id);

  // Server 1-RTT Packet is buffered.
  peer_creator_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                             std::make_unique<TaggingEncrypter>(0x03));
  ProcessDataPacket(0);
  EXPECT_EQ(QuicConnectionPeer::NumUndecryptablePackets(&connection_), 2u);

  // Pretend the server Initial packet will yield the Handshake keys.
  EXPECT_CALL(visitor_, OnCryptoFrame(_))
      .Times(2)
      .WillOnce(InstallKeys(&connection_, ENCRYPTION_HANDSHAKE))
      .WillOnce(InstallKeys(&connection_, ENCRYPTION_FORWARD_SECURE));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessCryptoPacketAtLevel(0, ENCRYPTION_INITIAL);
  // Two packets processed, connection ID changed.
  EXPECT_EQ(QuicConnectionPeer::NumUndecryptablePackets(&connection_), 0u);
  EXPECT_EQ(connection_.connection_id(), connection_id_);
}

TEST_P(QuicConnectionTest, ServerConnectionIdChangeTwiceWithLateInitial) {
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  // Call SetFromConfig so that the undecrypted packet buffer size is
  // initialized above zero.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(1);
  QuicConfig config;
  connection_.SetFromConfig(config);

  // Send Client Initial.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.SendCryptoStreamData();

  EXPECT_EQ(1u, writer_->packets_write_attempts());
  // Server Handshake Packet Arrives with new connection ID.
  QuicConnectionId old_id = connection_id_;
  connection_id_ = TestConnectionId(2);
  peer_creator_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                             std::make_unique<TaggingEncrypter>(0x02));
  ProcessCryptoPacketAtLevel(0, ENCRYPTION_HANDSHAKE);
  // Packet is buffered.
  EXPECT_EQ(QuicConnectionPeer::NumUndecryptablePackets(&connection_), 1u);
  EXPECT_EQ(connection_.connection_id(), old_id);

  // Pretend the server Initial packet will yield the Handshake keys.
  EXPECT_CALL(visitor_, OnCryptoFrame(_))
      .WillOnce(InstallKeys(&connection_, ENCRYPTION_HANDSHAKE));
  connection_id_ = TestConnectionId(1);
  ProcessCryptoPacketAtLevel(0, ENCRYPTION_INITIAL);
  // Handshake packet discarded because there's a different connection ID.
  EXPECT_EQ(QuicConnectionPeer::NumUndecryptablePackets(&connection_), 0u);
  EXPECT_EQ(connection_.connection_id(), connection_id_);
}

TEST_P(QuicConnectionTest, ClientValidatedServerPreferredAddress) {
  // Test the scenario where the client validates server preferred address by
  // receiving PATH_RESPONSE from server preferred address.
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  QuicConfig config;
  ServerPreferredAddressInit(config);
  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  const StatelessResetToken kNewStatelessResetToken =
      QuicUtils::GenerateStatelessResetToken(TestConnectionId(17));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  // Kick off path validation of server preferred address on handshake
  // confirmed.
  EXPECT_CALL(visitor_,
              OnServerPreferredAddressAvailable(kServerPreferredAddress))
      .WillOnce(Invoke([&]() {
        connection_.ValidatePath(
            std::make_unique<TestQuicPathValidationContext>(
                kNewSelfAddress, kServerPreferredAddress, &new_writer),
            std::make_unique<ServerPreferredAddressTestResultDelegate>(
                &connection_),
            PathValidationReason::kReasonUnknown);
      }));
  connection_.OnHandshakeComplete();
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, kServerPreferredAddress));
  EXPECT_EQ(TestConnectionId(17),
            new_writer.last_packet_header().destination_connection_id);
  EXPECT_EQ(kServerPreferredAddress, new_writer.last_write_peer_address());

  ASSERT_FALSE(new_writer.path_challenge_frames().empty());
  QuicPathFrameBuffer payload =
      new_writer.path_challenge_frames().front().data_buffer;
  // Send data packet while path validation is pending.
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  ASSERT_FALSE(writer_->stream_frames().empty());
  // While path validation is pending, packet is sent on default path.
  EXPECT_EQ(TestConnectionId(),
            writer_->last_packet_header().destination_connection_id);
  EXPECT_EQ(kPeerAddress, writer_->last_write_peer_address());
  EXPECT_TRUE(connection_.IsValidStatelessResetToken(kTestStatelessResetToken));
  EXPECT_FALSE(connection_.IsValidStatelessResetToken(kNewStatelessResetToken));

  // Receive path response from server preferred address.
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicPathResponseFrame(99, payload)));
  // Verify send_algorithm gets reset after migration (new sent packet is not
  // updated to exsting send_algorithm_).
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessFramesPacketWithAddresses(frames, kNewSelfAddress,
                                   kServerPreferredAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  ASSERT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsDefaultPath(&connection_, kNewSelfAddress,
                                                kServerPreferredAddress));
  ASSERT_FALSE(new_writer.stream_frames().empty());
  // Verify stream data is retransmitted on new path.
  EXPECT_EQ(TestConnectionId(17),
            new_writer.last_packet_header().destination_connection_id);
  EXPECT_EQ(kServerPreferredAddress, new_writer.last_write_peer_address());
  // Verify stateless reset token gets changed.
  EXPECT_FALSE(
      connection_.IsValidStatelessResetToken(kTestStatelessResetToken));
  EXPECT_TRUE(connection_.IsValidStatelessResetToken(kNewStatelessResetToken));

  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  // Verify client retires connection ID with sequence number 0.
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();
  EXPECT_TRUE(connection_.GetStats().server_preferred_address_validated);
  EXPECT_FALSE(
      connection_.GetStats().failed_to_validate_server_preferred_address);
}

TEST_P(QuicConnectionTest, ClientValidatedServerPreferredAddress2) {
  // Test the scenario where the client validates server preferred address by
  // receiving PATH_RESPONSE from original server address.
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  QuicConfig config;
  ServerPreferredAddressInit(config);
  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  co
"""


```
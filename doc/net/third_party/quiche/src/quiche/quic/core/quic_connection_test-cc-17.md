Response:
The user wants to understand the functionality of the `quic_connection_test.cc` file in the Chromium network stack.

Here's a plan to address the request:

1. **Identify the core purpose of the file:**  It's a test file for the `QuicConnection` class.
2. **Analyze the provided code snippets:** Focus on the test cases present. Each `TEST_P` macro defines a specific scenario being tested.
3. **Summarize the functionalities tested:**  Group the test cases by the feature they are verifying.
4. **Check for JavaScript relevance:**  Determine if any of the tested features have direct counterparts or implications for web browsers and JavaScript.
5. **Infer logical reasoning:**  For specific tests, try to deduce the expected input and output based on the test setup and assertions.
6. **Identify potential user/programming errors:**  Based on the test scenarios, point out common mistakes related to the tested functionalities.
7. **Explain user actions leading to these tests:** Describe how user interactions can trigger the underlying connection logic being tested.
8. **Synthesize the overall functionality:**  Provide a concise summary of the file's purpose based on the analysis of its parts.
9. **Address the "part 18 of 24" aspect:** Reiterate that this file focuses on testing specific aspects of connection management within the QUIC protocol.

**Detailed Analysis of Code Snippets:**

* **Integrity Limit Tests:** The first few test cases (`CloseConnectionOnIntegrityLimitDuringHandshake`, `CloseConnectionOnIntegrityLimitAfterHandshake`, `CloseConnectionOnIntegrityLimitAcrossEncryptionLevels`, `IntegrityLimitDoesNotApplyWithoutDecryptionKey`, `CloseConnectionOnIntegrityLimitAcrossKeyPhases`) focus on how the connection handles exceeding the allowed number of authentication failures for received packets. They test this behavior during handshake, after handshake completion, across different encryption levels, and during key updates.
* **Ack Frequency Frame Test:** The `SendAckFrequencyFrame` and `SendAckFrequencyFrameUponHandshakeCompletion` tests verify the functionality of sending ACK frequency frames, which are used to signal the desired acknowledgement behavior to the peer.
* **Fast Recovery Tests:** `FastRecoveryOfLostServerHello` and `ServerHelloGetsReordered` check how the connection reacts to lost or reordered ServerHello messages during the handshake, particularly with respect to fast retransmission mechanisms.
* **Path Migration Tests:** The `MigratePath` and `MigrateToNewPathDuringProbing` tests examine the connection's ability to migrate to a new network path, either due to path degradation or during probing for alternative paths.
* **Multi-Port Connection Tests:**  The remaining tests (`MultiPortConnection`, `TooManyMultiPortPathCreations`, `MultiPortPathReceivesStatelessReset`) cover the functionality related to establishing and managing connections over multiple network paths simultaneously (multi-port QUIC). They test scenarios like path degradation, probing, handling of NEW_CONNECTION_ID frames, limits on path creation, and reaction to stateless resets on alternative paths.

**JavaScript Relevance:** The multi-port connection functionality is particularly relevant to JavaScript in a web browser context. When a browser establishes a connection to a server, it might attempt to use multiple network interfaces or paths to improve performance and resilience. This is transparent to the JavaScript code but affects the underlying network communication.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 文件的第 18 部分（共 24 部分）。这个文件是一个单元测试文件，专门用于测试 `QuicConnection` 类的各种功能和行为。

**总体功能归纳（基于提供的代码片段）：**

这一部分主要集中在测试 `QuicConnection` 类在以下几个方面的行为：

1. **连接完整性限制 (Integrity Limit):**
   - 测试连接在握手期间、握手完成后、跨不同加密级别、以及密钥更新时，当接收到超过完整性限制的无法解密的包时，是否能够正确关闭连接。
   - 验证当没有可用的解密密钥时，完整性限制是否不适用。
   - 涵盖了密钥更新过程中完整性限制的应用。

2. **发送 ACK 频率帧 (ACK Frequency Frame):**
   - 测试作为服务器，在满足条件时（例如，接收到对延迟 ACK 有要求的配置），是否能够发送 `ACK_FREQUENCY` 帧。
   - 测试在握手完成时发送 `ACK_FREQUENCY` 帧的场景。

3. **快速恢复机制 (Fast Recovery):**
   - 测试客户端在 `ServerHello` 丢失时是否能进行快速恢复，通过缩短 PTO (Probe Timeout) 时间来实现。
   - 测试当 `ServerHello` 乱序到达时，快速恢复机制是否不会被触发。

4. **路径迁移 (Path Migration):**
   - 测试连接在检测到路径退化后，能否成功迁移到新的网络路径。
   - 测试在路径探测 (Path Probing) 期间迁移到新路径的情况。

5. **多端口连接 (Multi-Port Connection):**
   - 测试客户端在启用多端口 QUIC 的情况下，如何处理路径退化并尝试利用新的网络路径。
   - 测试客户端如何处理服务器发送的 `NEW_CONNECTION_ID` 帧来创建新的多端口路径。
   - 测试当新的多端口路径验证成功或失败时的行为。
   - 测试在没有活跃请求时，多端口路径探测的暂停和恢复。
   - 测试在路径退化的情况下，多端口路径迁移的触发条件。
   - 测试多端口路径验证失败后的重试机制。
   - 测试创建过多多端口路径时的限制。
   - 测试多端口路径接收到无状态重置 (Stateless Reset) 的处理。

**与 JavaScript 功能的关系：**

虽然这些测试直接针对 C++ 的网络栈实现，但它们所验证的功能直接影响着 Web 浏览器和 JavaScript 的网络性能和稳定性。

* **连接完整性限制:** 这关系到连接的安全性和可靠性。如果攻击者发送大量恶意篡改的包，浏览器需要能够及时检测并关闭连接，防止进一步的攻击。这对于用户使用 JavaScript 发起的网络请求至关重要。
* **ACK 频率帧:** 这影响着延迟 ACK 机制，进而影响网络的往返时间 (RTT) 和吞吐量。浏览器可能会根据网络状况调整 ACK 频率，以优化用户通过 JavaScript 发起的请求的性能。
* **快速恢复机制:** 当网络出现丢包时，快速恢复能力能显著减少延迟，提升用户体验。这对于 JavaScript 发起的实时通信或流媒体应用尤其重要。
* **路径迁移和多端口连接:** 这些功能提高了连接的鲁棒性和性能。当网络环境发生变化时（例如，Wi-Fi 切换到移动网络），浏览器能够平滑地迁移连接，保持 JavaScript 应用的网络连接，或者利用多个网络接口并行传输数据，提高速度。

**举例说明（与 JavaScript 的关系）：**

假设用户在一个支持多端口 QUIC 的浏览器中运行一个 JavaScript 应用程序，该应用需要频繁地从服务器下载数据。

1. **假设输入:**  用户当前连接使用 Wi-Fi，但 Wi-Fi 信号变弱，导致路径退化。服务器开始发送 `NEW_CONNECTION_ID` 帧。
2. **逻辑推理:** `MultiPortConnection` 测试中模拟了这种情况。浏览器（QUIC 客户端）接收到 `NEW_CONNECTION_ID` 帧后，会尝试在新的网络路径上进行路径验证。
3. **输出:** 如果路径验证成功（如测试所示），浏览器可能会将部分或全部连接迁移到新的路径上，从而保持连接的稳定性和数据传输的连续性，即使 Wi-Fi 信号不稳定。这对于 JavaScript 应用程序来说是无缝的，用户不会感知到网络切换。

**用户或编程常见的使用错误：**

* **误配置加密参数:**  如果服务器或客户端的加密配置不一致，可能导致解密失败，触发完整性限制，就像测试中故意设置错误的 `wrong_tag` 一样。用户或开发者在配置 QUIC 连接时需要确保加密参数的正确性。
* **网络中间设备干扰:** 某些中间设备可能会错误地修改 QUIC 数据包，导致认证失败，同样可能触发完整性限制。这不在用户的直接控制范围内，但开发者需要意识到这种可能性，并考虑使用 TLS 等安全机制来提高连接的健壮性。
* **过多的路径探测尝试:**  如果服务器频繁地发送 `NEW_CONNECTION_ID` 帧，客户端可能会创建过多的多端口路径，导致资源消耗。`TooManyMultiPortPathCreations` 测试验证了客户端对这种情况的处理，防止资源耗尽。开发者需要合理控制多端口路径的创建和管理。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户访问一个支持 QUIC 的网站:** 用户在 Chrome 浏览器中输入一个使用 QUIC 协议的网站地址并访问。
2. **建立 QUIC 连接:**  浏览器开始与服务器建立 QUIC 连接。
3. **网络环境变化或潜在攻击:**
   - **路径迁移:** 用户移动设备，导致 Wi-Fi 信号变差，触发路径退化检测。
   - **多端口连接:**  浏览器尝试利用多个网络接口来提高连接性能。
   - **完整性限制:** 可能有恶意网络行为，导致接收到无法解密的 QUIC 数据包。
4. **触发 QUIC 连接逻辑:**  这些用户操作和网络状况会触发 `QuicConnection` 类中的相应逻辑，例如路径迁移、多端口路径管理、完整性检查等。
5. **单元测试覆盖:**  `quic_connection_test.cc` 文件中的测试用例就是为了覆盖这些场景，验证 `QuicConnection` 类的行为是否符合预期。当开发者修改 `QuicConnection` 的代码时，会运行这些测试来确保修改没有引入 bug。

**总结第 18 部分的功能：**

第 18 部分的 `quic_connection_test.cc` 文件主要测试了 `QuicConnection` 类在处理连接完整性限制、发送 ACK 频率帧、快速恢复丢失的 `ServerHello`、进行路径迁移以及管理多端口连接等方面的功能。这些测试确保了 QUIC 连接在各种网络条件下，包括潜在的攻击和网络变化时，能够保持安全、可靠和高效。 这些功能对于提升用户的网络体验至关重要，尤其是在现代 Web 应用中，JavaScript 经常需要与服务器进行复杂的网络交互。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第18部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
ionOnIntegrityLimitDuringHandshake) {
  if (!connection_.version().UsesTls()) {
    return;
  }

  constexpr uint8_t correct_tag = ENCRYPTION_HANDSHAKE;
  constexpr uint8_t wrong_tag = 0xFE;
  constexpr QuicPacketCount kIntegrityLimit = 3;

  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypterWithIntegrityLimit>(
                   correct_tag, kIntegrityLimit));
  connection_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                           std::make_unique<TaggingEncrypter>(correct_tag));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  peer_framer_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                            std::make_unique<TaggingEncrypter>(wrong_tag));
  for (uint64_t i = 1; i <= kIntegrityLimit; ++i) {
    EXPECT_TRUE(connection_.connected());
    if (i == kIntegrityLimit) {
      EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
      EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(AnyNumber());
    }
    ProcessDataPacketAtLevel(i, !kHasStopWaiting, ENCRYPTION_HANDSHAKE);
    EXPECT_EQ(
        i, connection_.GetStats().num_failed_authentication_packets_received);
  }
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_AEAD_LIMIT_REACHED);
}

TEST_P(QuicConnectionTest, CloseConnectionOnIntegrityLimitAfterHandshake) {
  if (!connection_.version().UsesTls()) {
    return;
  }

  constexpr uint8_t correct_tag = ENCRYPTION_FORWARD_SECURE;
  constexpr uint8_t wrong_tag = 0xFE;
  constexpr QuicPacketCount kIntegrityLimit = 3;

  SetDecrypter(ENCRYPTION_FORWARD_SECURE,
               std::make_unique<StrictTaggingDecrypterWithIntegrityLimit>(
                   correct_tag, kIntegrityLimit));
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<TaggingEncrypter>(correct_tag));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  peer_framer_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                            std::make_unique<TaggingEncrypter>(wrong_tag));
  for (uint64_t i = 1; i <= kIntegrityLimit; ++i) {
    EXPECT_TRUE(connection_.connected());
    if (i == kIntegrityLimit) {
      EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
    }
    ProcessDataPacketAtLevel(i, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
    EXPECT_EQ(
        i, connection_.GetStats().num_failed_authentication_packets_received);
  }
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_AEAD_LIMIT_REACHED);
}

TEST_P(QuicConnectionTest,
       CloseConnectionOnIntegrityLimitAcrossEncryptionLevels) {
  if (!connection_.version().UsesTls()) {
    return;
  }

  uint8_t correct_tag = ENCRYPTION_HANDSHAKE;
  constexpr uint8_t wrong_tag = 0xFE;
  constexpr QuicPacketCount kIntegrityLimit = 4;

  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypterWithIntegrityLimit>(
                   correct_tag, kIntegrityLimit));
  connection_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                           std::make_unique<TaggingEncrypter>(correct_tag));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  peer_framer_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                            std::make_unique<TaggingEncrypter>(wrong_tag));
  for (uint64_t i = 1; i <= 2; ++i) {
    EXPECT_TRUE(connection_.connected());
    ProcessDataPacketAtLevel(i, !kHasStopWaiting, ENCRYPTION_HANDSHAKE);
    EXPECT_EQ(
        i, connection_.GetStats().num_failed_authentication_packets_received);
  }

  correct_tag = ENCRYPTION_FORWARD_SECURE;
  SetDecrypter(ENCRYPTION_FORWARD_SECURE,
               std::make_unique<StrictTaggingDecrypterWithIntegrityLimit>(
                   correct_tag, kIntegrityLimit));
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<TaggingEncrypter>(correct_tag));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.RemoveEncrypter(ENCRYPTION_HANDSHAKE);
  peer_framer_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                            std::make_unique<TaggingEncrypter>(wrong_tag));
  for (uint64_t i = 3; i <= kIntegrityLimit; ++i) {
    EXPECT_TRUE(connection_.connected());
    if (i == kIntegrityLimit) {
      EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
    }
    ProcessDataPacketAtLevel(i, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
    EXPECT_EQ(
        i, connection_.GetStats().num_failed_authentication_packets_received);
  }
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_AEAD_LIMIT_REACHED);
}

TEST_P(QuicConnectionTest, IntegrityLimitDoesNotApplyWithoutDecryptionKey) {
  if (!connection_.version().UsesTls()) {
    return;
  }

  constexpr uint8_t correct_tag = ENCRYPTION_HANDSHAKE;
  constexpr uint8_t wrong_tag = 0xFE;
  constexpr QuicPacketCount kIntegrityLimit = 3;

  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypterWithIntegrityLimit>(
                   correct_tag, kIntegrityLimit));
  connection_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                           std::make_unique<TaggingEncrypter>(correct_tag));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  connection_.RemoveDecrypter(ENCRYPTION_FORWARD_SECURE);

  peer_framer_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                            std::make_unique<TaggingEncrypter>(wrong_tag));
  for (uint64_t i = 1; i <= kIntegrityLimit * 2; ++i) {
    EXPECT_TRUE(connection_.connected());
    ProcessDataPacketAtLevel(i, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
    EXPECT_EQ(
        0u, connection_.GetStats().num_failed_authentication_packets_received);
  }
  EXPECT_TRUE(connection_.connected());
}

TEST_P(QuicConnectionTest, CloseConnectionOnIntegrityLimitAcrossKeyPhases) {
  if (!connection_.version().UsesTls()) {
    return;
  }

  constexpr QuicPacketCount kIntegrityLimit = 4;

  TransportParameters params;
  QuicConfig config;
  std::string error_details;
  EXPECT_THAT(config.ProcessTransportParameters(
                  params, /* is_resumption = */ false, &error_details),
              IsQuicNoError());
  QuicConfigPeer::SetNegotiated(&config, true);
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);

  MockFramerVisitor peer_framer_visitor_;
  peer_framer_.set_visitor(&peer_framer_visitor_);

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<TaggingEncrypter>(0x01));
  SetDecrypter(ENCRYPTION_FORWARD_SECURE,
               std::make_unique<StrictTaggingDecrypterWithIntegrityLimit>(
                   ENCRYPTION_FORWARD_SECURE, kIntegrityLimit));
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);

  peer_framer_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                            std::make_unique<TaggingEncrypter>(0xFF));
  for (uint64_t i = 1; i <= 2; ++i) {
    EXPECT_TRUE(connection_.connected());
    ProcessDataPacketAtLevel(i, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
    EXPECT_EQ(
        i, connection_.GetStats().num_failed_authentication_packets_received);
  }

  peer_framer_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  // Send packet 1.
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(1u), last_packet);
  // Receive ack for packet 1.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame1 = InitAckFrame(1);
  ProcessAckPacket(&frame1);
  // Key update should now be allowed, initiate it.
  EXPECT_CALL(visitor_, AdvanceKeysAndCreateCurrentOneRttDecrypter())
      .WillOnce([kIntegrityLimit]() {
        return std::make_unique<StrictTaggingDecrypterWithIntegrityLimit>(
            0x02, kIntegrityLimit);
      });
  EXPECT_CALL(visitor_, CreateCurrentOneRttEncrypter()).WillOnce([]() {
    return std::make_unique<TaggingEncrypter>(0x02);
  });
  EXPECT_CALL(visitor_, OnKeyUpdate(KeyUpdateReason::kLocalForTests));
  EXPECT_TRUE(connection_.InitiateKeyUpdate(KeyUpdateReason::kLocalForTests));

  // Pretend that peer accepts the key update.
  EXPECT_CALL(peer_framer_visitor_,
              AdvanceKeysAndCreateCurrentOneRttDecrypter())
      .WillOnce(
          []() { return std::make_unique<StrictTaggingDecrypter>(0x02); });
  EXPECT_CALL(peer_framer_visitor_, CreateCurrentOneRttEncrypter())
      .WillOnce([]() { return std::make_unique<TaggingEncrypter>(0x02); });
  peer_framer_.SetKeyUpdateSupportForConnection(true);
  peer_framer_.DoKeyUpdate(KeyUpdateReason::kLocalForTests);

  // Send packet 2.
  SendStreamDataToPeer(2, "bar", 0, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(2u), last_packet);
  // Receive ack for packet 2.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame2 = InitAckFrame(2);
  ProcessAckPacket(&frame2);

  EXPECT_EQ(2u,
            connection_.GetStats().num_failed_authentication_packets_received);

  // Do two more undecryptable packets. Integrity limit should be reached.
  peer_framer_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                            std::make_unique<TaggingEncrypter>(0xFF));
  for (uint64_t i = 3; i <= kIntegrityLimit; ++i) {
    EXPECT_TRUE(connection_.connected());
    if (i == kIntegrityLimit) {
      EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
    }
    ProcessDataPacketAtLevel(i, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
    EXPECT_EQ(
        i, connection_.GetStats().num_failed_authentication_packets_received);
  }
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_AEAD_LIMIT_REACHED);
}

TEST_P(QuicConnectionTest, SendAckFrequencyFrame) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  SetQuicReloadableFlag(quic_can_send_ack_frequency, true);
  set_perspective(Perspective::IS_SERVER);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());

  QuicConfig config;
  QuicConfigPeer::SetReceivedMinAckDelayMs(&config, /*min_ack_delay_ms=*/1);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  QuicConnectionPeer::SetAddressValidated(&connection_);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  connection_.OnHandshakeComplete();

  writer_->SetWritable();
  QuicPacketCreatorPeer::SetPacketNumber(creator_, 99);
  // Send packet 100
  SendStreamDataToPeer(/*id=*/1, "foo", /*offset=*/0, NO_FIN, nullptr);

  QuicAckFrequencyFrame captured_frame;
  EXPECT_CALL(visitor_, SendAckFrequency(_))
      .WillOnce(Invoke([&captured_frame](const QuicAckFrequencyFrame& frame) {
        captured_frame = frame;
      }));
  // Send packet 101.
  SendStreamDataToPeer(/*id=*/1, "bar", /*offset=*/3, NO_FIN, nullptr);

  EXPECT_EQ(captured_frame.packet_tolerance, 10u);
  EXPECT_EQ(captured_frame.max_ack_delay,
            QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs()));

  // Sending packet 102 does not trigger sending another AckFrequencyFrame.
  SendStreamDataToPeer(/*id=*/1, "baz", /*offset=*/6, NO_FIN, nullptr);
}

TEST_P(QuicConnectionTest, SendAckFrequencyFrameUponHandshakeCompletion) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  SetQuicReloadableFlag(quic_can_send_ack_frequency, true);
  set_perspective(Perspective::IS_SERVER);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());

  QuicConfig config;
  QuicConfigPeer::SetReceivedMinAckDelayMs(&config, /*min_ack_delay_ms=*/1);
  QuicTagVector quic_tag_vector;
  // Enable sending AckFrequency upon handshake completion.
  quic_tag_vector.push_back(kAFF2);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, quic_tag_vector);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  QuicConnectionPeer::SetAddressValidated(&connection_);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  QuicAckFrequencyFrame captured_frame;
  EXPECT_CALL(visitor_, SendAckFrequency(_))
      .WillOnce(Invoke([&captured_frame](const QuicAckFrequencyFrame& frame) {
        captured_frame = frame;
      }));

  connection_.OnHandshakeComplete();

  EXPECT_EQ(captured_frame.packet_tolerance, 2u);
  EXPECT_EQ(captured_frame.max_ack_delay,
            QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs()));
}

TEST_P(QuicConnectionTest, FastRecoveryOfLostServerHello) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.SendCryptoStreamData();
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));

  // Assume ServerHello gets lost.
  peer_framer_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                            std::make_unique<TaggingEncrypter>(0x02));
  ProcessCryptoPacketAtLevel(2, ENCRYPTION_HANDSHAKE);
  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  // Shorten PTO for fast recovery from lost ServerHello.
  EXPECT_EQ(clock_.ApproximateNow() + kAlarmGranularity,
            connection_.GetRetransmissionAlarm()->deadline());
}

TEST_P(QuicConnectionTest, ServerHelloGetsReordered) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  EXPECT_CALL(visitor_, OnCryptoFrame(_))
      .WillRepeatedly(Invoke([=, this](const QuicCryptoFrame& frame) {
        if (frame.level == ENCRYPTION_INITIAL) {
          // Install handshake read keys.
          SetDecrypter(
              ENCRYPTION_HANDSHAKE,
              std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_HANDSHAKE));
          connection_.SetEncrypter(
              ENCRYPTION_HANDSHAKE,
              std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
          connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
        }
      }));

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.SendCryptoStreamData();
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));

  // Assume ServerHello gets reordered.
  peer_framer_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                            std::make_unique<TaggingEncrypter>(0x02));
  ProcessCryptoPacketAtLevel(2, ENCRYPTION_HANDSHAKE);
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  // Verify fast recovery is not enabled.
  EXPECT_EQ(connection_.sent_packet_manager().GetRetransmissionTime(),
            connection_.GetRetransmissionAlarm()->deadline());
}

TEST_P(QuicConnectionTest, MigratePath) {
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  EXPECT_CALL(visitor_, OnPathDegrading());
  connection_.OnPathDegradingDetected();
  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_NE(kNewSelfAddress, connection_.self_address());

  // Buffer a packet.
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(1);
  writer_->SetWriteBlocked();
  connection_.SendMtuDiscoveryPacket(kMaxOutgoingPacketSize);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  if (version().HasIetfQuicFrames()) {
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(1234);
    ASSERT_NE(frame.connection_id, connection_.connection_id());
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    frame.retire_prior_to = 0u;
    frame.sequence_number = 1u;
    connection_.OnNewConnectionIdFrame(frame);
  }

  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  EXPECT_CALL(visitor_, OnForwardProgressMadeAfterPathDegrading());
  EXPECT_TRUE(connection_.MigratePath(kNewSelfAddress,
                                      connection_.peer_address(), &new_writer,
                                      /*owns_writer=*/false));

  EXPECT_EQ(kNewSelfAddress, connection_.self_address());
  EXPECT_EQ(&new_writer, QuicConnectionPeer::GetWriter(&connection_));
  EXPECT_FALSE(connection_.IsPathDegrading());
  // Buffered packet on the old path should be discarded.
  if (version().HasIetfQuicFrames()) {
    EXPECT_EQ(0u, connection_.NumQueuedPackets());
  } else {
    EXPECT_EQ(1u, connection_.NumQueuedPackets());
  }
}

TEST_P(QuicConnectionTest, MigrateToNewPathDuringProbing) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_NE(kNewSelfAddress, connection_.self_address());
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  bool success = false;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), &new_writer),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));

  connection_.MigratePath(kNewSelfAddress, connection_.peer_address(),
                          &new_writer, /*owns_writer=*/false);
  EXPECT_EQ(kNewSelfAddress, connection_.self_address());
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_FALSE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
}

TEST_P(QuicConnectionTest, MultiPortConnection) {
  set_perspective(Perspective::IS_CLIENT);
  QuicConfig config;
  config.SetClientConnectionOptions(QuicTagVector{kMPQC});
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();

  EXPECT_CALL(visitor_, OnPathDegrading());
  connection_.OnPathDegradingDetected();

  auto self_address = connection_.self_address();
  const QuicSocketAddress kNewSelfAddress(self_address.host(),
                                          self_address.port() + 1);
  EXPECT_NE(kNewSelfAddress, self_address);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);

  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive()).WillOnce(Return(false));
  QuicNewConnectionIdFrame frame;
  frame.connection_id = TestConnectionId(1234);
  ASSERT_NE(frame.connection_id, connection_.connection_id());
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;
  frame.sequence_number = 1u;
  EXPECT_CALL(visitor_, CreateContextForMultiPortPath)
      .WillRepeatedly(testing::WithArgs<0>([&](auto&& observer) {
        observer->OnMultiPortPathContextAvailable(
            std::move(std::make_unique<TestQuicPathValidationContext>(
                kNewSelfAddress, connection_.peer_address(), &new_writer)));
      }));
  connection_.OnNewConnectionIdFrame(frame);
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  auto* alt_path = QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_FALSE(alt_path->validated);
  EXPECT_EQ(PathValidationReason::kMultiPort,
            QuicConnectionPeer::path_validator(&connection_)
                ->GetPathValidationReason());

  // Suppose the server retransmits the NEW_CID frame, the client will receive
  // the same frame again. It should be ignored.
  // Regression test of crbug.com/1406762
  connection_.OnNewConnectionIdFrame(frame);

  // 30ms RTT.
  const QuicTime::Delta kTestRTT = QuicTime::Delta::FromMilliseconds(30);
  // Fake a response delay.
  clock_.AdvanceTime(kTestRTT);

  QuicFrames frames;
  frames.push_back(QuicFrame(QuicPathResponseFrame(
      99, new_writer.path_challenge_frames().back().data_buffer)));
  ProcessFramesPacketWithAddresses(frames, kNewSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  // No migration should happen and the alternative path should still be alive.
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  EXPECT_TRUE(alt_path->validated);
  auto stats = connection_.multi_port_stats();
  EXPECT_EQ(1, connection_.GetStats().num_path_degrading);
  EXPECT_EQ(1, stats->num_successful_probes);
  EXPECT_EQ(1, stats->num_client_probing_attempts);
  EXPECT_EQ(1, connection_.GetStats().num_client_probing_attempts);
  EXPECT_EQ(0, stats->num_multi_port_probe_failures_when_path_degrading);
  EXPECT_EQ(kTestRTT, stats->rtt_stats.latest_rtt());
  EXPECT_EQ(kTestRTT,
            stats->rtt_stats_when_default_path_degrading.latest_rtt());

  // Receiving the retransmitted NEW_CID frame now should still have no effect.
  EXPECT_CALL(visitor_, CreateContextForMultiPortPath).Times(0);
  connection_.OnNewConnectionIdFrame(frame);

  // When there's no active request, the probing shouldn't happen. But the
  // probing context should be saved.
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive()).WillOnce(Return(false));
  connection_.GetMultiPortProbingAlarm()->Fire();
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_FALSE(connection_.GetMultiPortProbingAlarm()->IsSet());

  // Simulate the situation where a new request stream is created.
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));
  random_generator_.ChangeValue();
  connection_.MaybeProbeMultiPortPath();
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  EXPECT_TRUE(alt_path->validated);
  // Fake a response delay.
  clock_.AdvanceTime(kTestRTT);
  QuicFrames frames2;
  frames2.push_back(QuicFrame(QuicPathResponseFrame(
      99, new_writer.path_challenge_frames().back().data_buffer)));
  ProcessFramesPacketWithAddresses(frames2, kNewSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  // No migration should happen and the alternative path should still be alive.
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  EXPECT_TRUE(alt_path->validated);
  EXPECT_EQ(1, connection_.GetStats().num_path_degrading);
  EXPECT_EQ(0, stats->num_multi_port_probe_failures_when_path_degrading);
  EXPECT_EQ(kTestRTT, stats->rtt_stats.latest_rtt());
  EXPECT_EQ(kTestRTT,
            stats->rtt_stats_when_default_path_degrading.latest_rtt());

  EXPECT_CALL(visitor_, OnForwardProgressMadeAfterPathDegrading());
  QuicConnectionPeer::OnForwardProgressMade(&connection_);

  EXPECT_TRUE(connection_.GetMultiPortProbingAlarm()->IsSet());
  // Since there's already a scheduled probing alarm, manual calls won't have
  // any effect.
  connection_.MaybeProbeMultiPortPath();
  EXPECT_FALSE(connection_.HasPendingPathValidation());

  // Since kMPQM is not set, migration shouldn't happen
  EXPECT_CALL(visitor_, OnPathDegrading());
  EXPECT_CALL(visitor_, MigrateToMultiPortPath(_)).Times(0);
  connection_.OnPathDegradingDetected();
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));

  // Simulate the case where the path validation fails after retries.
  connection_.GetMultiPortProbingAlarm()->Fire();
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  for (size_t i = 0; i < QuicPathValidator::kMaxRetryTimes + 1; ++i) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
    static_cast<TestAlarmFactory::TestAlarm*>(
        QuicPathValidatorPeer::retry_timer(
            QuicConnectionPeer::path_validator(&connection_)))
        ->Fire();
  }

  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_FALSE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  EXPECT_EQ(2, connection_.GetStats().num_path_degrading);
  EXPECT_EQ(1, stats->num_multi_port_probe_failures_when_path_degrading);
  EXPECT_EQ(0, stats->num_multi_port_probe_failures_when_path_not_degrading);
  EXPECT_EQ(0, connection_.GetStats().num_stateless_resets_on_alternate_path);
}

TEST_P(QuicConnectionTest, TooManyMultiPortPathCreations) {
  set_perspective(Perspective::IS_CLIENT);
  QuicConfig config;
  config.SetClientConnectionOptions(QuicTagVector{kMPQC});
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();

  EXPECT_CALL(visitor_, OnPathDegrading());
  connection_.OnPathDegradingDetected();

  auto self_address = connection_.self_address();
  const QuicSocketAddress kNewSelfAddress(self_address.host(),
                                          self_address.port() + 1);
  EXPECT_NE(kNewSelfAddress, self_address);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);

  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

  {
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(1234);
    ASSERT_NE(frame.connection_id, connection_.connection_id());
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    frame.retire_prior_to = 0u;
    frame.sequence_number = 1u;
    EXPECT_CALL(visitor_, CreateContextForMultiPortPath)
        .WillRepeatedly(testing::WithArgs<0>([&](auto&& observer) {
          observer->OnMultiPortPathContextAvailable(
              std::move(std::make_unique<TestQuicPathValidationContext>(
                  kNewSelfAddress, connection_.peer_address(), &new_writer)));
        }));
    EXPECT_TRUE(connection_.OnNewConnectionIdFrame(frame));
  }
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  auto* alt_path = QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_FALSE(alt_path->validated);

  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  for (size_t i = 0; i < QuicPathValidator::kMaxRetryTimes + 1; ++i) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
    static_cast<TestAlarmFactory::TestAlarm*>(
        QuicPathValidatorPeer::retry_timer(
            QuicConnectionPeer::path_validator(&connection_)))
        ->Fire();
  }

  auto stats = connection_.multi_port_stats();
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_FALSE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  EXPECT_EQ(1, connection_.GetStats().num_path_degrading);
  EXPECT_EQ(1, stats->num_multi_port_probe_failures_when_path_degrading);

  uint64_t connection_id = 1235;
  for (size_t i = 0; i < kMaxNumMultiPortPaths - 1; ++i) {
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(connection_id + i);
    ASSERT_NE(frame.connection_id, connection_.connection_id());
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    frame.retire_prior_to = 0u;
    frame.sequence_number = i + 2;
    EXPECT_CALL(visitor_, CreateContextForMultiPortPath)
        .WillRepeatedly(testing::WithArgs<0>([&](auto&& observer) {
          observer->OnMultiPortPathContextAvailable(
              std::move(std::make_unique<TestQuicPathValidationContext>(
                  kNewSelfAddress, connection_.peer_address(), &new_writer)));
        }));
    EXPECT_TRUE(connection_.OnNewConnectionIdFrame(frame));
    EXPECT_TRUE(connection_.HasPendingPathValidation());
    EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
        &connection_, kNewSelfAddress, connection_.peer_address()));
    EXPECT_FALSE(alt_path->validated);

    for (size_t j = 0; j < QuicPathValidator::kMaxRetryTimes + 1; ++j) {
      clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
      static_cast<TestAlarmFactory::TestAlarm*>(
          QuicPathValidatorPeer::retry_timer(
              QuicConnectionPeer::path_validator(&connection_)))
          ->Fire();
    }

    EXPECT_FALSE(connection_.HasPendingPathValidation());
    EXPECT_FALSE(QuicConnectionPeer::IsAlternativePath(
        &connection_, kNewSelfAddress, connection_.peer_address()));
    EXPECT_EQ(1, connection_.GetStats().num_path_degrading);
    EXPECT_EQ(i + 2, stats->num_multi_port_probe_failures_when_path_degrading);
  }

  // The 6th attemp should fail.
  QuicNewConnectionIdFrame frame2;
  frame2.connection_id = TestConnectionId(1239);
  ASSERT_NE(frame2.connection_id, connection_.connection_id());
  frame2.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame2.connection_id);
  frame2.retire_prior_to = 0u;
  frame2.sequence_number = 6u;
  EXPECT_TRUE(connection_.OnNewConnectionIdFrame(frame2));
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_EQ(kMaxNumMultiPortPaths,
            stats->num_multi_port_probe_failures_when_path_degrading);
}

TEST_P(QuicConnectionTest, MultiPortPathReceivesStatelessReset) {
  set_perspective(Perspective::IS_CLIENT);
  QuicConfig config;
  QuicConfigPeer::SetReceivedStatelessResetToken(&config,
                                                 kTestStatelessResetToken);
  config.SetClientConnectionOptions(QuicTagVector{kMPQC});
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();

  EXPECT_CALL(visitor_, OnPathDegrading());
  connection_.OnPathDegradingDetected();

  auto self_address = connection_.self_address();
  const QuicSocketAddress kNewSelfAddress(self_address.host(),
                                          self_address.port() + 1);
  EXPECT_NE(kNewSelfAddress, self_address);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);

  QuicNewConnectionIdFrame frame;
  frame.connection_id = TestConnectionId(1234);
  ASSERT_NE(frame.connection_id, connection_.connection_id());
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;
  frame.sequence_number = 1u;
  EXPECT_CALL(visitor_, CreateContextForMultiPortPath)
      .WillRepeatedly(testing::WithArgs<0>([&](auto&& o
```
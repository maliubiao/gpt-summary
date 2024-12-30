Response:
The user is asking for an analysis of a C++ source code file related to the QUIC protocol in Chromium's network stack. The request includes several specific points to address:

1. **Functionality:** Describe what the code does.
2. **Relationship to JavaScript:** Explain any connections to JavaScript functionality.
3. **Logic and Examples:** Provide examples of logical operations with hypothetical inputs and outputs.
4. **Common User/Programming Errors:**  Illustrate potential mistakes in using the code.
5. **Debugging Path:** Explain how a user's actions might lead to this code being executed.
6. **Summary:** Condense the functionality of the provided code snippet (part 15 of 24).

**Mental Model:**

* This is a unit test file (`quic_connection_test.cc`). Therefore, its primary function is to test the `QuicConnection` class. Each `TEST_P` block represents a specific test case.
* The tests cover various scenarios related to connection management, error handling, packet processing, and interaction with other QUIC components (like `QuicConfig`, `SendAlgorithm`, `Visitor`, etc.).
* Since it's a network stack component, direct interaction with JavaScript is unlikely. However, QUIC is used by web browsers, so the indirect connection exists in how network requests are handled.
* The code uses mocking (via `EXPECT_CALL`) to simulate the behavior of dependencies.
* The examples will need to focus on the specific scenarios being tested in this part of the file.

**Plan:**

1. **Scan the code:** Identify the main themes and individual tests within the provided snippet.
2. **Summarize the overarching functionality of the file:** It's a unit test suite for `QuicConnection`.
3. **Analyze each `TEST_P` block:**
    * **Identify the tested feature:** What aspect of `QuicConnection` is being verified?
    * **Describe the test scenario:** What conditions are being set up? What actions are being performed? What is the expected outcome?
    * **Relate to JavaScript (if applicable):** Explain how the tested feature might indirectly affect JavaScript-based web applications (e.g., connection stability, error handling).
    * **Create hypothetical input/output examples:** Focus on the state changes and function calls being asserted.
    * **Identify potential user/programming errors:**  Think about how incorrect configurations or misuse of the API could lead to the observed behavior.
    * **Describe the debugging path:** How might a network issue or specific browser behavior lead to these tests failing?
4. **Synthesize the functionality of this part (part 15):** Combine the individual test functionalities into a concise summary.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果它与javascript的功能有关系，请做出对应的举例说明: Yes (indirect relationship)
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 这是第15部分，共24部分，请归纳一下它的功能: Yes

Confidence Score: 5/5 - I am confident I can address all parts of the request.

**Self-Correction/Refinement:**

* Initial thought: Focus heavily on the technical details of each test.
* Refinement:  Balance the technical details with explanations that are accessible to someone who might not be a QUIC expert, especially regarding the JavaScript connection and user errors. The debugging path should focus on actionable steps a developer might take. The summary needs to be concise but informative, reflecting the overall theme of this section.

Strategizing complete. I will now proceed with generating the response.

这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的关键部分，它专门用于测试 `QuicConnection` 类的各种功能。`QuicConnection` 类负责管理一个 QUIC 连接的生命周期，包括握手、数据传输、拥塞控制、错误处理等。

**这个代码片段（第 15 部分）的主要功能集中在以下几个方面：**

1. **处理接收到的配置信息 (QuicConfig)：**  测试当连接接收到对端发送的配置信息时，`QuicConnection` 的行为。这包括对 `original_connection_id` 和 `retry_source_connection_id` 等传输参数的处理，尤其是在握手阶段，确保在没有收到 `RETRY` 包的情况下收到 `retry_source_connection_id` 会导致连接关闭。

2. **处理接收到的控制帧 (Control Frames)：**  测试 `QuicConnection` 如何处理特定的控制帧，例如 `MAX_STREAMS` 和 `STREAMS_BLOCKED` 帧。这些测试验证了当接收到这些帧时，连接会正确地触发关闭流程。

3. **连接关闭与 ACK 的捆绑：**  测试在连接关闭时，`QuicConnection` 能否将 ACK 帧与 `CONNECTION_CLOSE` 帧捆绑在一起发送，特别是在多包号码空间 (Multiple Packet Number Spaces) 的情况下。

4. **处理 PTO (Probe Timeout) 事件：**  测试在 PTO 计时器触发时，如果没有数据可发送，`QuicConnection` 是否会发送 PING 包以探测连接活性。

5. **防止 queued ACK 被修改：**  测试在接收到数据并需要发送 ACK 时，即使有其他需要发送的控制帧，已排队的 ACK 信息是否会被正确保留。

6. **不因无法解密的包而延长空闲时间：**  测试当收到无法解密的包时，连接的空闲超时计时器是否不会被不正确地重置，防止恶意攻击者通过发送垃圾数据来保持连接活跃。

7. **将 ACK 与立即响应捆绑：**  测试当收到数据包并需要立即发送响应（例如 `WINDOW_UPDATE` 帧）时，`QuicConnection` 是否会将 ACK 帧与响应帧捆绑发送。

8. **提前触发 ACK 告警：**  测试 ACK 告警在特定情况下是否能提前触发，例如在多包号码空间中接收到不同加密级别的包时。

9. **客户端黑洞检测 (Client-Only Blackhole Detection)：** 测试客户端是否能启动黑洞检测机制，以应对网络中丢包严重的情况。同时也测试了服务端在这种情况下不会启动黑洞检测。

10. **在丢弃密钥后取得进展：** 测试在握手密钥被丢弃后，连接是否能正确地进行后续操作，例如黑洞检测的停止。

11. **基于加密级别处理无法解密的包：** 测试 `QuicConnection` 如何根据不同的加密级别缓存和处理无法解密的包，并在获得相应的解密密钥后进行处理。

12. **服务端捆绑 Initial 数据与 Initial ACK：** 测试服务端是否能将 Initial 级别的加密数据与 Initial ACK 捆绑发送。

13. **客户端捆绑 Handshake 数据与 Handshake ACK：** 测试客户端是否能将 Handshake 级别的加密数据与 Handshake ACK 捆绑发送。

14. **合并较低加密级别的包：** 测试能否在一个已包含较高加密级别数据包的 UDP 包中合并较低加密级别的包。

15. **服务端提前重传 Handshake 数据：** 测试服务端在收到部分 Handshake 包的 ACK 后，能否及时重传剩余的 Handshake 数据。

16. **膨胀的 RTT 样本处理：** 测试在发生重传的情况下，如何避免 RTT 样本被不合理地放大。

17. **合并数据包导致无限循环的避免：** 测试在特定配置下，合并数据包是否会导致无限循环的问题，并验证是否已修复。

18. **客户端异步包处理的 ACK 延迟：** 测试客户端在异步处理包时，ACK 延迟时间是否被正确计算和设置。

19. **连接活性测试 (Testing Liveness)：**  测试连接的活性管理机制，例如空闲超时和 PING 帧的使用。

**与 JavaScript 的关系：**

这个 C++ 代码文件直接与 JavaScript 没有代码级别的交互。然而，它所测试的 `QuicConnection` 类是 Chromium 浏览器网络栈的核心组件，负责处理浏览器与服务器之间的 QUIC 连接。当用户在浏览器中进行网络操作（例如访问网页），如果启用了 QUIC 协议，那么底层的 `QuicConnection` 类就会被使用。

**举例说明：**

假设一个用户在 Chrome 浏览器中访问一个支持 QUIC 的网站。

1. **用户操作：** 用户在地址栏输入网址 `https://example.com` 并按下回车。
2. **网络请求：** Chrome 的网络栈发起与 `example.com` 服务器的连接。如果服务器支持 QUIC 并且协商成功，就会建立一个 `QuicConnection` 实例。
3. **配置处理：** 服务器可能会在握手过程中发送包含 `original_connection_id` 等信息的 `QuicConfig`。本代码片段中的测试就覆盖了客户端接收到这些配置信息后的处理逻辑，例如 `ClientReceivesOriginalConnectionIdWithoutNegotiated` 测试了在握手完成前收到 `original_connection_id` 的情况。如果这个测试失败，可能意味着浏览器在处理服务器配置时存在错误，导致连接不稳定甚至失败，最终用户可能会看到网页加载失败。
4. **控制帧处理：** 如果服务器因为某些原因需要限制客户端创建的流的数量，它可能会发送 `MAX_STREAMS` 帧。`MaxStreamsFrameCausesConnectionClose` 测试了接收到此类帧后连接的关闭行为。如果这个测试失败，可能导致浏览器在不应该关闭连接的时候关闭了连接，影响用户体验。
5. **PTO 和连接活性：** 如果网络出现短暂中断，客户端可能会触发 PTO 机制。`SendPingWhenSkipPacketNumberForPto` 测试了在这种情况下发送 PING 包以保持连接活性的逻辑。如果这个测试失败，可能导致连接在网络恢复后仍然处于断开状态。

虽然 JavaScript 代码本身不直接调用这些 C++ 类，但 JavaScript 发起的网络请求最终会通过这些底层的网络协议实现来完成。因此，这些 C++ 代码的正确性直接影响到基于 JavaScript 的 Web 应用的网络性能和稳定性。

**逻辑推理的假设输入与输出：**

**测试案例：`ClientReceivesRetrySourceConnectionIdWithoutRetry`**

* **假设输入：**
    * 连接处于握手阶段，尚未收到服务器发送的 `RETRY` 包。
    * 客户端接收到服务器发送的 `QuicConfig`，其中包含了 `retry_source_connection_id` 传输参数。
* **预期输出：**
    * `connection_.connected()` 返回 `false`，表示连接已关闭。
    * `visitor_.OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF)` 被调用一次，表示连接由本地发起关闭。
    * 连接关闭的原因是 `IETF_QUIC_PROTOCOL_VIOLATION`，表示违反了 QUIC 协议规范。

**用户或编程常见的使用错误：**

* **配置错误：** 开发者在实现 QUIC 服务器时，可能错误地在没有发送 `RETRY` 包的情况下，就包含了 `retry_source_connection_id` 传输参数。这会导致遵循 QUIC 规范的客户端（如 Chromium）关闭连接。
* **状态机错误：** 在实现 `QuicConnection` 的状态机时，如果没有正确处理在特定握手阶段接收到特定配置参数的情况，可能会导致意外的行为，例如没有按预期关闭连接。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户报告连接问题：** 用户在使用 Chrome 浏览器访问某个网站时，遇到连接失败、连接中断或者握手失败的问题。
2. **网络工程师/开发者介入：**  开发者或网络工程师开始调查问题。他们可能会抓取网络包 (packet capture) 来分析 QUIC 握手过程。
3. **分析 QUIC 握手信息：** 通过分析抓包信息，他们可能会发现服务器在握手过程中发送了包含 `retry_source_connection_id` 的 `QuicConfig`，但客户端并没有收到之前的 `RETRY` 包。
4. **定位到相关代码：** 基于以上分析，开发者会怀疑是客户端的 QUIC 实现问题，特别是关于配置处理的部分。他们会查看 `QuicConnection` 类中处理 `QuicConfig` 的代码。
5. **运行相关测试：** 开发者可能会运行 `quic_connection_test.cc` 中的 `ClientReceivesRetrySourceConnectionIdWithoutRetry` 测试，以验证客户端在这种特定情况下的行为是否符合预期。如果测试失败，则表明代码存在缺陷。
6. **调试代码：** 开发者会使用调试器来跟踪代码执行流程，查看 `QuicConnection` 如何处理接收到的 `QuicConfig`，以及为什么会或不会触发连接关闭。

**归纳一下它的功能 (第 15 部分):**

这个代码片段主要测试了 `QuicConnection` 类在处理握手阶段的配置信息、接收到的控制帧，以及连接关闭与 ACK 捆绑等方面的功能。它还覆盖了 PTO 机制、防止 ACK 被修改、不因无法解密的包延长空闲时间、ACK 与响应的捆绑、提前触发 ACK 告警、客户端黑洞检测以及在密钥丢弃后连接状态管理等多个关键场景，确保 `QuicConnection` 能够按照 QUIC 协议规范正确地管理连接生命周期，处理各种网络事件和异常情况。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第15部分，共24部分，请归纳一下它的功能

"""
g, true);
  QuicConfigPeer::SetReceivedOriginalConnectionId(&received_config,
                                                  TestConnectionId(0x12345));
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .Times(1);
  connection_.SetFromConfig(received_config);
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(IETF_QUIC_PROTOCOL_VIOLATION);
}

TEST_P(QuicConnectionTest, ClientReceivesRetrySourceConnectionIdWithoutRetry) {
  if (!connection_.version().UsesTls()) {
    // Versions that do not authenticate connection IDs never send the
    // retry_source_connection_id transport parameter.
    return;
  }
  // Make sure that receiving the retry_source_connection_id transport parameter
  // fails the handshake when no RETRY packet was received before it.
  QuicConfig received_config;
  QuicConfigPeer::SetNegotiated(&received_config, true);
  QuicConfigPeer::SetReceivedRetrySourceConnectionId(&received_config,
                                                     TestConnectionId(0x12345));
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .Times(1);
  connection_.SetFromConfig(received_config);
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(IETF_QUIC_PROTOCOL_VIOLATION);
}

// Regression test for http://crbug/1047977
TEST_P(QuicConnectionTest, MaxStreamsFrameCausesConnectionClose) {
  if (!VersionHasIetfQuicFrames(connection_.transport_version())) {
    return;
  }
  // Received frame causes connection close.
  EXPECT_CALL(visitor_, OnMaxStreamsFrame(_))
      .WillOnce(InvokeWithoutArgs([this]() {
        EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
        connection_.CloseConnection(
            QUIC_TOO_MANY_BUFFERED_CONTROL_FRAMES, "error",
            ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
        return true;
      }));
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicMaxStreamsFrame()));
  frames.push_back(QuicFrame(QuicPaddingFrame(-1)));
  ProcessFramesPacketAtLevel(1, frames, ENCRYPTION_FORWARD_SECURE);
}

TEST_P(QuicConnectionTest, StreamsBlockedFrameCausesConnectionClose) {
  if (!VersionHasIetfQuicFrames(connection_.transport_version())) {
    return;
  }
  // Received frame causes connection close.
  EXPECT_CALL(visitor_, OnStreamsBlockedFrame(_))
      .WillOnce(InvokeWithoutArgs([this]() {
        EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
        connection_.CloseConnection(
            QUIC_TOO_MANY_BUFFERED_CONTROL_FRAMES, "error",
            ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
        return true;
      }));
  QuicFrames frames;
  frames.push_back(
      QuicFrame(QuicStreamsBlockedFrame(kInvalidControlFrameId, 10, false)));
  frames.push_back(QuicFrame(QuicPaddingFrame(-1)));
  ProcessFramesPacketAtLevel(1, frames, ENCRYPTION_FORWARD_SECURE);
}

TEST_P(QuicConnectionTest,
       BundleAckWithConnectionCloseMultiplePacketNumberSpace) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  // Receives packet 1000 in initial data.
  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);
  // Receives packet 2000 in application data.
  ProcessDataPacketAtLevel(2000, false, ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  const QuicErrorCode kQuicErrorCode = QUIC_INTERNAL_ERROR;
  connection_.CloseConnection(
      kQuicErrorCode, "Some random error message",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);

  EXPECT_EQ(2u, QuicConnectionPeer::GetNumEncryptionLevels(&connection_));

  TestConnectionCloseQuicErrorCode(kQuicErrorCode);
  EXPECT_EQ(1u, writer_->connection_close_frames().size());
  // Verify ack is bundled.
  EXPECT_EQ(1u, writer_->ack_frames().size());

  if (!connection_.version().CanSendCoalescedPackets()) {
    // Each connection close packet should be sent in distinct UDP packets.
    EXPECT_EQ(QuicConnectionPeer::GetNumEncryptionLevels(&connection_),
              writer_->connection_close_packets());
    EXPECT_EQ(QuicConnectionPeer::GetNumEncryptionLevels(&connection_),
              writer_->packets_write_attempts());
    return;
  }

  // A single UDP packet should be sent with multiple connection close packets
  // coalesced together.
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  // Only the first packet has been processed yet.
  EXPECT_EQ(1u, writer_->connection_close_packets());

  // ProcessPacket resets the visitor and frees the coalesced packet.
  ASSERT_TRUE(writer_->coalesced_packet() != nullptr);
  auto packet = writer_->coalesced_packet()->Clone();
  writer_->framer()->ProcessPacket(*packet);
  EXPECT_EQ(1u, writer_->connection_close_packets());
  EXPECT_EQ(1u, writer_->connection_close_frames().size());
  // Verify ack is bundled.
  EXPECT_EQ(1u, writer_->ack_frames().size());
  ASSERT_TRUE(writer_->coalesced_packet() == nullptr);
}

// Regression test for b/151220135.
TEST_P(QuicConnectionTest, SendPingWhenSkipPacketNumberForPto) {
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kPTOS);
  connection_options.push_back(k1PTO);
  config.SetConnectionOptionsToSend(connection_options);
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedMaxDatagramFrameSize(
        &config, kMaxAcceptedDatagramFrameSize);
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  connection_.OnHandshakeComplete();
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  EXPECT_EQ(MESSAGE_STATUS_SUCCESS, SendMessage("message"));
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // PTO fires, verify a PING packet gets sent because there is no data to
  // send.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(3), _, _));
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(1u, connection_.GetStats().pto_count);
  EXPECT_EQ(0u, connection_.GetStats().crypto_retransmit_count);
  EXPECT_EQ(1u, writer_->ping_frames().size());
}

// Regression test for b/155757133
TEST_P(QuicConnectionTest, DonotChangeQueuedAcks) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_COMPLETE));

  ProcessPacket(2);
  ProcessPacket(3);
  ProcessPacket(4);
  // Process a packet containing stream frame followed by ACK of packets 1.
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicStreamFrame(
      QuicUtils::GetFirstBidirectionalStreamId(
          connection_.version().transport_version, Perspective::IS_CLIENT),
      false, 0u, absl::string_view())));
  QuicAckFrame ack_frame = InitAckFrame(1);
  frames.push_back(QuicFrame(&ack_frame));
  // Receiving stream frame causes something to send.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).WillOnce(Invoke([this]() {
    connection_.SendControlFrame(QuicFrame(QuicWindowUpdateFrame(1, 0, 0)));
    // Verify now the queued ACK contains packet number 2.
    EXPECT_TRUE(QuicPacketCreatorPeer::QueuedFrames(
                    QuicConnectionPeer::GetPacketCreator(&connection_))[0]
                    .ack_frame->packets.Contains(QuicPacketNumber(2)));
  }));
  ProcessFramesPacketAtLevel(9, frames, ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(writer_->ack_frames()[0].packets.Contains(QuicPacketNumber(2)));
}

TEST_P(QuicConnectionTest, DoNotExtendIdleTimeOnUndecryptablePackets) {
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  // Subtract a second from the idle timeout on the client side.
  QuicTime initial_deadline =
      clock_.ApproximateNow() +
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  EXPECT_EQ(initial_deadline, connection_.GetTimeoutAlarm()->deadline());

  // Received an undecryptable packet.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  peer_framer_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<quic::NullEncrypter>(Perspective::IS_CLIENT));
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
  // Verify deadline does not get extended.
  EXPECT_EQ(initial_deadline, connection_.GetTimeoutAlarm()->deadline());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(1);
  QuicTime::Delta delay = initial_deadline - clock_.ApproximateNow();
  clock_.AdvanceTime(delay);
  connection_.GetTimeoutAlarm()->Fire();
  // Verify connection gets closed.
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest, BundleAckWithImmediateResponse) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  EXPECT_CALL(visitor_, OnStreamFrame(_)).WillOnce(Invoke([this]() {
    notifier_.WriteOrBufferWindowUpate(0, 0);
  }));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ProcessDataPacket(1);
  // Verify ACK is bundled with WINDOW_UPDATE.
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, AckAlarmFiresEarly) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  // Receives packet 1000 in initial data.
  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());

  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  // Receives packet 1000 in application data.
  ProcessDataPacketAtLevel(1000, false, ENCRYPTION_ZERO_RTT);
  EXPECT_TRUE(connection_.HasPendingAcks());
  // Verify ACK deadline does not change.
  EXPECT_EQ(clock_.ApproximateNow() + kAlarmGranularity,
            connection_.GetAckAlarm()->deadline());

  // Ack alarm fires early.
  // Verify the earliest ACK is flushed.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.GetAckAlarm()->Fire();
  EXPECT_TRUE(connection_.HasPendingAcks());
  EXPECT_EQ(clock_.ApproximateNow() + DefaultDelayedAckTime(),
            connection_.GetAckAlarm()->deadline());
}

TEST_P(QuicConnectionTest, ClientOnlyBlackholeDetectionClient) {
  if (!GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2)) {
    return;
  }
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kCBHD);
  config.SetConnectionOptionsToSend(connection_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();
  EXPECT_FALSE(connection_.GetBlackholeDetectorAlarm()->IsSet());
  // Send stream data.
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, FIN, nullptr);
  // Verify blackhole detection is in progress.
  EXPECT_TRUE(connection_.GetBlackholeDetectorAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, ClientOnlyBlackholeDetectionServer) {
  if (!GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2)) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  if (version().SupportsAntiAmplificationLimit()) {
    QuicConnectionPeer::SetAddressValidated(&connection_);
  }
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kCBHD);
  config.SetInitialReceivedConnectionOptions(connection_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_COMPLETE));
  EXPECT_FALSE(connection_.GetBlackholeDetectorAlarm()->IsSet());
  // Send stream data.
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, FIN, nullptr);
  // Verify blackhole detection is disabled.
  EXPECT_FALSE(connection_.GetBlackholeDetectorAlarm()->IsSet());
}

// Regresstion test for b/158491591.
TEST_P(QuicConnectionTest, MadeForwardProgressOnDiscardingKeys) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  // Send handshake packet.
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k5RTO);
  config.SetConnectionOptionsToSend(connection_options);
  QuicConfigPeer::SetNegotiated(&config, true);
  if (GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2) ||
      GetQuicReloadableFlag(
          quic_no_path_degrading_before_handshake_confirmed)) {
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_COMPLETE));
  }
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);

  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_HANDSHAKE);
  if (GetQuicReloadableFlag(
          quic_no_path_degrading_before_handshake_confirmed)) {
    // No blackhole detection before handshake confirmed.
    EXPECT_FALSE(connection_.BlackholeDetectionInProgress());
  } else {
    EXPECT_TRUE(connection_.BlackholeDetectionInProgress());
  }
  // Discard handshake keys.
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();
  if (GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2) ||
      GetQuicReloadableFlag(
          quic_no_path_degrading_before_handshake_confirmed)) {
    // Verify blackhole detection stops.
    EXPECT_FALSE(connection_.BlackholeDetectionInProgress());
  } else {
    // Problematic: although there is nothing in flight, blackhole detection is
    // still in progress.
    EXPECT_TRUE(connection_.BlackholeDetectionInProgress());
  }
}

TEST_P(QuicConnectionTest, ProcessUndecryptablePacketsBasedOnEncryptionLevel) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  // SetFromConfig is always called after construction from InitializeSession.
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(AnyNumber());
  QuicConfig config;
  connection_.SetFromConfig(config);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.RemoveDecrypter(ENCRYPTION_FORWARD_SECURE);

  peer_framer_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  peer_framer_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));

  for (uint64_t i = 1; i <= 3; ++i) {
    ProcessDataPacketAtLevel(i, !kHasStopWaiting, ENCRYPTION_HANDSHAKE);
  }
  ProcessDataPacketAtLevel(4, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
  for (uint64_t j = 5; j <= 7; ++j) {
    ProcessDataPacketAtLevel(j, !kHasStopWaiting, ENCRYPTION_HANDSHAKE);
  }
  EXPECT_EQ(7u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));
  EXPECT_FALSE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());
  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_HANDSHAKE));
  EXPECT_TRUE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  // Verify all ENCRYPTION_HANDSHAKE packets get processed.
  if (!VersionHasIetfQuicFrames(version().transport_version)) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(6);
  }
  connection_.GetProcessUndecryptablePacketsAlarm()->Fire();
  EXPECT_EQ(1u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));

  SetDecrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  EXPECT_TRUE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  // Verify the 1-RTT packet gets processed.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  connection_.GetProcessUndecryptablePacketsAlarm()->Fire();
  EXPECT_EQ(0u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));
}

TEST_P(QuicConnectionTest, ServerBundlesInitialDataWithInitialAck) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  // Receives packet 1000 in initial data.
  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_INITIAL);
  QuicTime expected_pto_time =
      connection_.sent_packet_manager().GetRetransmissionTime();

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  connection_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_HANDSHAKE);
  // Verify PTO time does not change.
  EXPECT_EQ(expected_pto_time,
            connection_.sent_packet_manager().GetRetransmissionTime());

  // Receives packet 1001 in initial data.
  ProcessCryptoPacketAtLevel(1001, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());
  // Receives packet 1002 in initial data.
  ProcessCryptoPacketAtLevel(1002, ENCRYPTION_INITIAL);
  EXPECT_FALSE(writer_->ack_frames().empty());
  // Verify CRYPTO frame is bundled with INITIAL ACK.
  EXPECT_FALSE(writer_->crypto_frames().empty());
  // Verify PTO time changes.
  EXPECT_NE(expected_pto_time,
            connection_.sent_packet_manager().GetRetransmissionTime());
}

TEST_P(QuicConnectionTest, ClientBundlesHandshakeDataWithHandshakeAck) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_HANDSHAKE));
  peer_framer_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  // Receives packet 1000 in handshake data.
  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_HANDSHAKE);
  EXPECT_TRUE(connection_.HasPendingAcks());
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_HANDSHAKE);

  // Receives packet 1001 in handshake data.
  ProcessCryptoPacketAtLevel(1001, ENCRYPTION_HANDSHAKE);
  EXPECT_TRUE(connection_.HasPendingAcks());
  // Receives packet 1002 in handshake data.
  ProcessCryptoPacketAtLevel(1002, ENCRYPTION_HANDSHAKE);
  EXPECT_FALSE(writer_->ack_frames().empty());
  // Verify CRYPTO frame is bundled with HANDSHAKE ACK.
  EXPECT_FALSE(writer_->crypto_frames().empty());
}

// Regresstion test for b/156232673.
TEST_P(QuicConnectionTest, CoalescePacketOfLowerEncryptionLevel) {
  if (!connection_.version().CanSendCoalescedPackets()) {
    return;
  }
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.SetEncrypter(
        ENCRYPTION_HANDSHAKE,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
    connection_.SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    SendStreamDataToPeer(2, std::string(1286, 'a'), 0, NO_FIN, nullptr);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
    // Try to coalesce a HANDSHAKE packet after 1-RTT packet.
    // Verify soft max packet length gets resumed and handshake packet gets
    // successfully sent.
    connection_.SendCryptoDataWithString("a", 0, ENCRYPTION_HANDSHAKE);
  }
}

// Regression test for b/160790422.
TEST_P(QuicConnectionTest, ServerRetransmitsHandshakeDataEarly) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  // Receives packet 1000 in initial data.
  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Send INITIAL 1.
  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_INITIAL);
  QuicTime expected_pto_time =
      connection_.sent_packet_manager().GetRetransmissionTime();

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  // Send HANDSHAKE 2 and 3.
  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_HANDSHAKE);
  connection_.SendCryptoDataWithString("bar", 3, ENCRYPTION_HANDSHAKE);
  // Verify PTO time does not change.
  EXPECT_EQ(expected_pto_time,
            connection_.sent_packet_manager().GetRetransmissionTime());

  // Receives ACK for HANDSHAKE 2.
  QuicFrames frames;
  auto ack_frame = InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)}});
  frames.push_back(QuicFrame(&ack_frame));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  ProcessFramesPacketAtLevel(30, frames, ENCRYPTION_HANDSHAKE);
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  // Receives PING from peer.
  frames.clear();
  frames.push_back(QuicFrame(QuicPingFrame()));
  frames.push_back(QuicFrame(QuicPaddingFrame(3)));
  ProcessFramesPacketAtLevel(31, frames, ENCRYPTION_HANDSHAKE);
  EXPECT_EQ(clock_.Now() + kAlarmGranularity,
            connection_.GetAckAlarm()->deadline());
  // Fire ACK alarm.
  clock_.AdvanceTime(kAlarmGranularity);
  connection_.GetAckAlarm()->Fire();
  EXPECT_FALSE(writer_->ack_frames().empty());
  // Verify handshake data gets retransmitted early.
  EXPECT_FALSE(writer_->crypto_frames().empty());
}

// Regression test for b/161228202
TEST_P(QuicConnectionTest, InflatedRttSample) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  // 30ms RTT.
  const QuicTime::Delta kTestRTT = QuicTime::Delta::FromMilliseconds(30);
  set_perspective(Perspective::IS_SERVER);
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  // Receives packet 1000 in initial data.
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Send INITIAL 1.
  std::string initial_crypto_data(512, 'a');
  connection_.SendCryptoDataWithString(initial_crypto_data, 0,
                                       ENCRYPTION_INITIAL);
  ASSERT_TRUE(connection_.sent_packet_manager()
                  .GetRetransmissionTime()
                  .IsInitialized());
  QuicTime::Delta pto_timeout =
      connection_.sent_packet_manager().GetRetransmissionTime() - clock_.Now();
  // Send Handshake 2.
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  std::string handshake_crypto_data(1024, 'a');
  connection_.SendCryptoDataWithString(handshake_crypto_data, 0,
                                       ENCRYPTION_HANDSHAKE);

  // INITIAL 1 gets lost and PTO fires.
  clock_.AdvanceTime(pto_timeout);
  connection_.GetRetransmissionAlarm()->Fire();

  clock_.AdvanceTime(kTestRTT);
  // Assume retransmitted INITIAL gets received.
  QuicFrames frames;
  auto ack_frame = InitAckFrame({{QuicPacketNumber(4), QuicPacketNumber(5)}});
  frames.push_back(QuicFrame(&ack_frame));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(AnyNumber());
  ProcessFramesPacketAtLevel(1001, frames, ENCRYPTION_INITIAL);
  EXPECT_EQ(kTestRTT, rtt_stats->latest_rtt());
  // Because retransmitted INITIAL gets received so HANDSHAKE 2 gets processed.
  frames.clear();
  // HANDSHAKE 5 is also processed.
  QuicAckFrame ack_frame2 =
      InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)},
                    {QuicPacketNumber(5), QuicPacketNumber(6)}});
  ack_frame2.ack_delay_time = QuicTime::Delta::Zero();
  frames.push_back(QuicFrame(&ack_frame2));
  ProcessFramesPacketAtLevel(1, frames, ENCRYPTION_HANDSHAKE);
  // Verify RTT inflation gets mitigated.
  EXPECT_EQ(rtt_stats->latest_rtt(), kTestRTT);
}

// Regression test for b/161228202
TEST_P(QuicConnectionTest, CoalescingPacketCausesInfiniteLoop) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  // Receives packet 1000 in initial data.
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());

  // Set anti amplification factor to 2, such that RetransmitDataOfSpaceIfAny
  // makes no forward progress and causes infinite loop.
  SetQuicFlag(quic_anti_amplification_factor, 2);

  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Send INITIAL 1.
  std::string initial_crypto_data(512, 'a');
  connection_.SendCryptoDataWithString(initial_crypto_data, 0,
                                       ENCRYPTION_INITIAL);
  ASSERT_TRUE(connection_.sent_packet_manager()
                  .GetRetransmissionTime()
                  .IsInitialized());
  QuicTime::Delta pto_timeout =
      connection_.sent_packet_manager().GetRetransmissionTime() - clock_.Now();
  // Send Handshake 2.
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  // Verify HANDSHAKE packet is coalesced with INITIAL retransmission.
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  std::string handshake_crypto_data(1024, 'a');
  connection_.SendCryptoDataWithString(handshake_crypto_data, 0,
                                       ENCRYPTION_HANDSHAKE);

  // INITIAL 1 gets lost and PTO fires.
  clock_.AdvanceTime(pto_timeout);
  connection_.GetRetransmissionAlarm()->Fire();
}

TEST_P(QuicConnectionTest, ClientAckDelayForAsyncPacketProcessing) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  // SetFromConfig is always called after construction from InitializeSession.
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).WillOnce(Invoke([this]() {
    connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
    connection_.NeuterUnencryptedPackets();
  }));
  QuicConfig config;
  connection_.SetFromConfig(config);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  peer_framer_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  EXPECT_EQ(0u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));

  // Received undecryptable HANDSHAKE 2.
  ProcessDataPacketAtLevel(2, !kHasStopWaiting, ENCRYPTION_HANDSHAKE);
  ASSERT_EQ(1u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));
  // Received INITIAL 4 (which is retransmission of INITIAL 1) after 100ms.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100));
  ProcessDataPacketAtLevel(4, !kHasStopWaiting, ENCRYPTION_INITIAL);
  // Generate HANDSHAKE key.
  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_HANDSHAKE));
  EXPECT_TRUE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  // Verify HANDSHAKE packet gets processed.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.GetProcessUndecryptablePacketsAlarm()->Fire();
  // Verify immediate ACK has been sent out when flush went out of scope.
  ASSERT_FALSE(connection_.HasPendingAcks());
  ASSERT_FALSE(writer_->ack_frames().empty());
  // Verify the ack_delay_time in the sent HANDSHAKE ACK frame is 100ms.
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(100),
            writer_->ack_frames()[0].ack_delay_time);
  ASSERT_TRUE(writer_->coalesced_packet() == nullptr);
}

TEST_P(QuicConnectionTest, TestingLiveness) {
  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;

  CryptoHandshakeMessage msg;
  std::string error_details;
  QuicConfig client_config;
  client_config.SetInitialStreamFlowControlWindowToSend(
      kInitialStreamFlowControlWindowForTest);
  client_config.SetInitialSessionFlowControlWindowToSend(
      kInitialSessionFlowControlWindowForTest);
  client_config.SetIdleNetworkTimeout(QuicTime::Delta::FromSeconds(30));
  client_config.ToHandshakeMessage(&msg, connection_.transport_version());
  const QuicErrorCode error =
      config.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_THAT(error, IsQuicNoError());

  if (connection_.ve
"""


```
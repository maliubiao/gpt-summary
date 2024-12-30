Response:
My thought process to analyze the provided C++ code snippet and generate the summary involves the following steps:

1. **Identify the Core Class:** The filename `quic_connection_test.cc` immediately tells me the code is testing the `QuicConnection` class. This becomes the central focus.

2. **Recognize the Testing Framework:** The presence of `TEST_P`, `EXPECT_CALL`, `EXPECT_EQ`, etc., clearly indicates this is a unit test file using a testing framework (likely Google Test, given the Chromium context).

3. **Analyze Individual Test Cases:** I go through each `TEST_P` block, understanding its purpose by looking at the test name and the operations performed within it. I try to distill the core functionality being tested in each case. For example:
    * `SendFailsIfNoWritablePath`:  Testing the scenario where sending fails if there's no usable path.
    * `SendSchedulerEAGAIN`: Testing how the connection handles `EAGAIN` (resource temporarily unavailable) during sending.
    * `TestQueueLimitsOnSendStreamData`: Testing queue limits when sending stream data.
    * `SendingThreePackets`: Testing sending data that requires multiple packets.
    * `LoopThroughSendingPacketsWithTruncation`: Testing how connection ID truncation affects packet sending.
    * `SendDelayedAck`: Testing the delayed acknowledgment mechanism.
    * `SendDelayedAckDecimation`: Testing delayed ack with decimation (sending fewer acks).
    * `SendDelayedAckOnHandshakeConfirmed`: Testing delayed ack behavior after handshake completion.
    * `SendDelayedAckOnSecondPacket`: Testing delayed ack after receiving a second packet.
    * `NoAckOnOldNacks`: Testing that old negative acknowledgments don't trigger immediate acks.
    * `SendDelayedAckOnOutgoingPacket`: Testing bundling acks with outgoing data packets.
    * `SendDelayedAckOnOutgoingCryptoPacket`: Testing bundling acks with outgoing crypto packets.
    * `BlockAndBufferOnFirstCHLOPacketOfTwo`: Testing blocking and buffering when sending the first ClientHello (CHLO).
    * `BundleAckForSecondCHLO`: Testing bundling an ack for the second CHLO.
    * `BundleAckForSecondCHLOTwoPacketReject`: Testing bundling an ack after a two-packet rejection during handshake.
    * `BundleAckWithDataOnIncomingAck`: Testing bundling an ack with data in response to an incoming ack.
    * `NoAckSentForClose`: Testing that no ack is sent when closing the connection.
    * `SendWhenDisconnected`: Testing behavior when sending after the connection is closed.
    * `SendConnectivityProbingWhenDisconnected`: Testing sending connectivity probes when disconnected (and expecting a bug).
    * `WriteBlockedAfterClientSendsConnectivityProbe`: Testing write blocking after sending a client-initiated connectivity probe.
    * `WriterBlockedAfterServerSendsConnectivityProbe`: Testing write blocking after sending a server-initiated connectivity probe.
    * `WriterErrorWhenClientSendsConnectivityProbe`: Testing handling write errors during client-side connectivity probing.
    * `WriterErrorWhenServerSendsConnectivityProbe`: Testing handling write errors during server-side connectivity probing.
    * `IetfStatelessReset`: Testing handling of IETF stateless reset packets.
    * `GoAway`: Testing handling of `GOAWAY` frames.
    * `WindowUpdate`: Testing handling of `WINDOW_UPDATE` frames.
    * `Blocked`: Testing handling of `BLOCKED` frames.
    * `ZeroBytePacket`: Testing handling of zero-byte packets.
    * `ClientHandlesVersionNegotiation`: Testing how a client handles version negotiation.

4. **Identify Common Themes and Functionality:**  As I go through the tests, I notice recurring themes:
    * **Packet Sending and Receiving:**  Many tests focus on how the `QuicConnection` sends and receives different types of packets (data, ACK, crypto, close, etc.).
    * **Flow Control and Congestion Control:** Tests related to queue limits, sending multiple packets, and interactions with the `SendAlgorithm` fall under this.
    * **Acknowledgment (ACK) Management:**  A significant number of tests are dedicated to delayed acknowledgments, ack decimation, and bundling acks.
    * **Connection Closure:**  Tests cover both graceful and abrupt connection closures.
    * **Error Handling:**  Tests simulate scenarios like write failures and stateless resets.
    * **Handshake:** Tests involving CHLO and REJ relate to the connection handshake process.
    * **Connectivity Probing:** Tests specifically examine sending and handling connectivity probes.
    * **Frame Processing:** Tests involving `GOAWAY`, `WINDOW_UPDATE`, and `BLOCKED` frames focus on how the connection processes these control frames.

5. **Relate to JavaScript (If Applicable):** I consider how these lower-level networking functionalities might manifest in a JavaScript environment, specifically in the context of web browsers:
    * **Fetch API/WebSockets:**  The underlying mechanisms being tested here enable the reliable and efficient data transfer used by these higher-level APIs. For example, the delayed ack mechanism helps optimize network usage for `fetch` requests.
    * **Error Handling in Browsers:**  The connection closure and error handling tests relate to how browsers might handle network disruptions or server errors, potentially leading to error messages or retries in web applications.
    * **QUIC Protocol Support in Browsers:** These tests are foundational for the QUIC protocol implementation that browsers are increasingly adopting.

6. **Consider User/Developer Errors:** I think about common mistakes developers might make when interacting with networking concepts or when potentially dealing with lower-level APIs (though direct interaction with `QuicConnection` in JS is unlikely). Examples include:
    * **Not handling network errors:**  A web application not gracefully handling failed requests.
    * **Incorrectly managing timeouts:** Leading to stalled connections.
    * **Assuming immediate delivery:**  Not understanding the asynchronous nature of network communication.

7. **Trace User Actions (Debugging Perspective):** I try to imagine a sequence of user actions that could lead to the code paths being tested. For example, a user browsing a website (leading to `GET` requests), encountering network issues, or a server intentionally closing the connection.

8. **Synthesize the Summary:** Finally, I combine the information gathered in the previous steps to create a concise summary that captures the key functionalities being tested in the provided code snippet. I focus on the core responsibility of the `QuicConnection` class and the various scenarios covered by the tests. I also include the JavaScript relation, error examples, and debugging context as requested.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 文件的第 9 部分（共 24 部分）。这个文件主要用于测试 `QuicConnection` 类的各种功能。

**本部分（第 9 部分）的功能归纳：**

这部分主要集中在测试 `QuicConnection` 类的**数据发送、流量控制、拥塞控制以及延迟确认 (Delayed ACK)** 相关的行为。具体来说，测试了以下几个方面：

* **发送失败处理:** 当底层写入操作失败时，连接如何处理，例如标记连接不可写。
* **发送调度:** 当底层写入被阻塞 (`EAGAIN`) 时，连接如何处理排队的数据包。
* **发送队列限制:** 测试当发送队列达到限制时，如何阻止新的数据发送。
* **发送多个数据包:** 测试发送超过单个数据包大小的数据，以及连接如何将其分割成多个包并发送。
* **循环发送数据包与连接ID截断:**  测试在连接ID长度变化时，发送多个数据包的行为。
* **延迟确认机制 (Delayed ACK):**  这是本部分的核心内容，测试了多种延迟确认的场景：
    * **基本延迟确认:**  接收到数据包后，延迟一段时间发送 ACK。
    * **延迟确认的消减 (Decimation):**  根据 RTT 等因素，减少发送 ACK 的频率。
    * **根据 RTT 调整延迟确认时间:**  当 RTT 较低时，延迟确认时间也会相应减少。
    * **握手完成后的延迟确认:**  测试客户端和服务端在握手完成后，延迟确认的行为差异。
    * **接收到第二个数据包后发送延迟确认:**  测试接收到一定数量的数据包后触发延迟确认。
    * **忽略旧的 NACK:**  确保不会因为旧的 NACK 立即发送 ACK。
    * **将延迟 ACK 与发送数据包捆绑:**  测试在有待发送数据时，将 ACK 与数据包一起发送。
    * **将延迟 ACK 与发送加密数据包捆绑:**  测试在发送加密数据时，将 ACK 与加密数据包一起发送。
* **阻塞和缓冲:** 测试在加密握手阶段，当写入被阻塞时，连接如何缓冲数据。
* **为第二个 CHLO (ClientHello) 捆绑 ACK:** 测试在握手过程中，接收到第二个 CHLO 时立即发送 ACK。
* **为包含拒绝的第二个 CHLO 捆绑 ACK:** 测试在握手过程中，接收到包含拒绝信息的第二个 CHLO 时发送 ACK。
* **在接收到 ACK 的同时发送数据:** 测试在接收到对端 ACK 后，如果也有数据要发送，则将 ACK 和数据一起发送。
* **连接关闭时不发送 ACK:**  测试当连接收到关闭帧时不发送 ACK。
* **断开连接后的发送行为:** 测试在连接已经断开后尝试发送数据的情况。
* **断开连接后发送连通性探测:** 测试在连接断开后尝试发送连通性探测包的情况 (期望触发断言)。
* **客户端发送连通性探测后写入被阻塞:** 测试客户端在发送连通性探测包时遇到写入阻塞的情况。
* **服务端发送连通性探测后写入被阻塞:** 测试服务端在发送连通性探测包时遇到写入阻塞的情况。
* **客户端发送连通性探测时发生写入错误:** 测试客户端在发送连通性探测包时写入失败的情况。
* **服务端发送连通性探测时发生写入错误:** 测试服务端在发送连通性探测包时写入失败的情况。
* **IETF 无状态重置:** 测试接收到 IETF 无状态重置包的处理。
* **GOAWAY 帧:** 测试接收到 GOAWAY 帧的处理 (在某些 QUIC 版本中不可用)。
* **WINDOW_UPDATE 帧:** 测试接收到 WINDOW_UPDATE 帧的处理。
* **BLOCKED 帧:** 测试接收到 BLOCKED 帧的处理。
* **零字节数据包:** 测试接收到零字节数据包的处理 (不应关闭连接)。
* **客户端处理版本协商:** 测试客户端如何处理版本协商数据包。

**与 JavaScript 的功能关系：**

这些底层网络功能的测试直接关系到 JavaScript 中使用的网络 API，例如：

* **Fetch API:**  Fetch API 底层使用了 HTTP/3 和 QUIC 协议，这些测试中关于数据发送、接收、拥塞控制和延迟 ACK 的机制，直接影响了 Fetch API 的性能和可靠性。例如，延迟 ACK 可以减少不必要的 ACK 包，提高网络利用率，从而加快 Fetch 请求的响应速度。
* **WebSockets:**  WebSockets 也可能基于 QUIC 构建，这些测试中关于连接管理、数据传输和错误处理的部分，同样适用于 WebSockets。例如，连接关闭的测试确保了 WebSocket 连接在异常情况下的正确关闭。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch` API 向服务器请求一个较大的文件。

* **假设输入:**  JavaScript 代码调用 `fetch('https://example.com/large_file')`。
* **内部逻辑推理:**  QUIC 连接会将这个请求分割成多个数据包进行发送（对应 `SendingThreePackets` 测试）。如果网络条件不好，服务器可能会延迟发送 ACK (对应 `SendDelayedAck` 测试)。如果客户端发送速度过快，可能会触发流量控制机制 (虽然本部分没有直接测试流量控制，但在 `QuicConnection` 的其他部分有测试)。
* **输出:**  最终，浏览器会接收到完整的 `large_file` 数据，并传递给 JavaScript 代码。如果过程中出现网络错误或服务器关闭连接，`fetch` API 会抛出相应的错误，这与 `SendWhenDisconnected` 和 `NoAckSentForClose` 等测试相关。

**用户或编程常见的使用错误：**

虽然用户通常不会直接与 `QuicConnection` 类交互，但编程错误可能会导致与之相关的底层行为出现问题。例如：

* **错误处理不当:**  JavaScript 开发者如果没有正确处理 `fetch` API 或 WebSocket 连接可能出现的错误（例如网络断开），可能会导致应用卡死或数据丢失。这与 `SendWhenDisconnected` 等测试覆盖的场景相关。
* **不合理的超时设置:**  如果 JavaScript 代码设置了过短的网络请求超时时间，可能会导致请求在 QUIC 连接还在尝试恢复或发送数据时就被中断。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个使用 HTTP/3 或 QUIC 协议的网站。**
2. **浏览器建立与服务器的 QUIC 连接。**  `QuicConnection` 类负责管理这个连接。
3. **用户执行某些操作，例如点击链接或提交表单，导致浏览器发起网络请求 (使用 Fetch API 或其他方式)。**
4. **浏览器将请求数据发送到服务器，这会触发 `QuicConnection::SendPacket` 等方法 (对应本部分测试的各种发送场景)。**
5. **服务器响应数据，浏览器接收数据包，这会触发 `QuicConnection::ProcessUdpPacket` 等方法。**
6. **QUIC 连接根据网络状况和协议规则，可能会延迟发送 ACK（对应本部分测试的延迟 ACK 场景）。**
7. **如果网络出现问题，或者服务器主动关闭连接，会触发 `QuicConnection` 的连接关闭逻辑（对应 `NoAckSentForClose` 和 `SendWhenDisconnected` 等测试）。**

在调试网络问题时，开发者可以使用浏览器提供的网络调试工具（例如 Chrome 的 "开发者工具" -> "Network" 面板）来查看网络请求的详细信息，包括使用的协议、连接状态、数据包的发送和接收情况等。这些信息可以帮助开发者定位问题是否出在 QUIC 连接层面。

**总结（第 9 部分）：**

第 9 部分的测试重点在于验证 `QuicConnection` 类在各种数据发送、流量控制、拥塞控制以及延迟确认场景下的正确行为。它涵盖了发送失败处理、发送调度、队列限制、多包发送、连接 ID 截断以及多种延迟确认的策略。这些测试确保了 QUIC 连接能够高效、可靠地传输数据，并能应对各种网络状况和异常情况。这些底层的网络机制对于上层 JavaScript 网络 API 的性能和稳定性至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共24部分，请归纳一下它的功能

"""
ht be uninitialized.
  QuicFramerPeer::SetPerspective(&peer_framer_, Perspective::IS_CLIENT);
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(1);
  std::unique_ptr<QuicPacket> packet =
      ConstructDataPacket(1, !kHasStopWaiting, ENCRYPTION_INITIAL);
  QuicPacketCreatorPeer::SetPacketNumber(creator_, 1);
  writer_->SetShouldWriteFail();
  connection_.SendPacket(ENCRYPTION_INITIAL, 1, std::move(packet),
                         HAS_RETRANSMITTABLE_DATA, false, false);
}

TEST_P(QuicConnectionTest, SendSchedulerEAGAIN) {
  QuicFramerPeer::SetPerspective(&peer_framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> packet =
      ConstructDataPacket(1, !kHasStopWaiting, ENCRYPTION_INITIAL);
  QuicPacketCreatorPeer::SetPacketNumber(creator_, 1);
  BlockOnNextWrite();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(2u), _, _))
      .Times(0);
  connection_.SendPacket(ENCRYPTION_INITIAL, 1, std::move(packet),
                         HAS_RETRANSMITTABLE_DATA, false, false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, TestQueueLimitsOnSendStreamData) {
  // Queue the first packet.
  size_t payload_length = connection_.max_packet_length();
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillOnce(testing::Return(false));
  const std::string payload(payload_length, 'a');
  QuicStreamId first_bidi_stream_id(QuicUtils::GetFirstBidirectionalStreamId(
      connection_.version().transport_version, Perspective::IS_CLIENT));
  EXPECT_EQ(0u, connection_
                    .SendStreamDataWithString(first_bidi_stream_id, payload, 0,
                                              NO_FIN)
                    .bytes_consumed);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, SendingThreePackets) {
  // Make the payload twice the size of the packet, so 3 packets are written.
  size_t total_payload_length = 2 * connection_.max_packet_length();
  const std::string payload(total_payload_length, 'a');
  QuicStreamId first_bidi_stream_id(QuicUtils::GetFirstBidirectionalStreamId(
      connection_.version().transport_version, Perspective::IS_CLIENT));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(3);
  EXPECT_EQ(payload.size(), connection_
                                .SendStreamDataWithString(first_bidi_stream_id,
                                                          payload, 0, NO_FIN)
                                .bytes_consumed);
}

TEST_P(QuicConnectionTest, LoopThroughSendingPacketsWithTruncation) {
  set_perspective(Perspective::IS_SERVER);
  // Set up a larger payload than will fit in one packet.
  const std::string payload(connection_.max_packet_length(), 'a');
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(AnyNumber());

  // Now send some packets with no truncation.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  EXPECT_EQ(payload.size(),
            connection_.SendStreamDataWithString(3, payload, 0, NO_FIN)
                .bytes_consumed);
  // Track the size of the second packet here.  The overhead will be the largest
  // we see in this test, due to the non-truncated connection id.
  size_t non_truncated_packet_size = writer_->last_packet_size();

  // Change to a 0 byte connection id.
  QuicConfig config;
  QuicConfigPeer::SetReceivedBytesForConnectionId(&config, 0);
  connection_.SetFromConfig(config);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  EXPECT_EQ(payload.size(),
            connection_.SendStreamDataWithString(3, payload, 1350, NO_FIN)
                .bytes_consumed);
  // Short header packets sent from server omit connection ID already, and
  // stream offset size increases from 0 to 2.
  EXPECT_EQ(non_truncated_packet_size, writer_->last_packet_size() - 2);
}

TEST_P(QuicConnectionTest, SendDelayedAck) {
  QuicTime ack_time = clock_.ApproximateNow() + DefaultDelayedAckTime();
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.HasPendingAcks());
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // The same as ProcessPacket(1) except that ENCRYPTION_ZERO_RTT is used
  // instead of ENCRYPTION_INITIAL.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.HasPendingAcks());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());
  // Simulate delayed ack alarm firing.
  clock_.AdvanceTime(DefaultDelayedAckTime());
  connection_.GetAckAlarm()->Fire();
  // Check that ack is sent and that delayed ack alarm is reset.
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, SendDelayedAckDecimation) {
  EXPECT_CALL(visitor_, OnAckNeedsRetransmittableFrame()).Times(AnyNumber());

  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  // The ack time should be based on min_rtt/4, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() +
                      QuicTime::Delta::FromMilliseconds(kMinRttMs / 4);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.HasPendingAcks());
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // Process all the initial packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (unsigned int i = 0; i < kFirstDecimatedPacket - 1; ++i) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(1 + i, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
  }
  EXPECT_FALSE(connection_.HasPendingAcks());
  // The same as ProcessPacket(1) except that ENCRYPTION_ZERO_RTT is used
  // instead of ENCRYPTION_INITIAL.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kFirstDecimatedPacket, !kHasStopWaiting,
                           ENCRYPTION_ZERO_RTT);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.HasPendingAcks());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // The 10th received packet causes an ack to be sent.
  for (int i = 0; i < 9; ++i) {
    EXPECT_TRUE(connection_.HasPendingAcks());
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kFirstDecimatedPacket + 1 + i, !kHasStopWaiting,
                             ENCRYPTION_ZERO_RTT);
  }
  // Check that ack is sent and that delayed ack alarm is reset.
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, SendDelayedAckDecimationUnlimitedAggregation) {
  EXPECT_CALL(visitor_, OnAckNeedsRetransmittableFrame()).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  QuicTagVector connection_options;
  // No limit on the number of packets received before sending an ack.
  connection_options.push_back(kAKDU);
  config.SetConnectionOptionsToSend(connection_options);
  connection_.SetFromConfig(config);

  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  // The ack time should be based on min_rtt/4, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() +
                      QuicTime::Delta::FromMilliseconds(kMinRttMs / 4);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.HasPendingAcks());
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // Process all the initial packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (unsigned int i = 0; i < kFirstDecimatedPacket - 1; ++i) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(1 + i, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
  }
  EXPECT_FALSE(connection_.HasPendingAcks());
  // The same as ProcessPacket(1) except that ENCRYPTION_ZERO_RTT is used
  // instead of ENCRYPTION_INITIAL.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kFirstDecimatedPacket, !kHasStopWaiting,
                           ENCRYPTION_ZERO_RTT);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.HasPendingAcks());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // 18 packets will not cause an ack to be sent.  19 will because when
  // stop waiting frames are in use, we ack every 20 packets no matter what.
  for (int i = 0; i < 18; ++i) {
    EXPECT_TRUE(connection_.HasPendingAcks());
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kFirstDecimatedPacket + 1 + i, !kHasStopWaiting,
                             ENCRYPTION_ZERO_RTT);
  }
  // The delayed ack timer should still be set to the expected deadline.
  EXPECT_TRUE(connection_.HasPendingAcks());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());
}

TEST_P(QuicConnectionTest, SendDelayedAckDecimationEighthRtt) {
  EXPECT_CALL(visitor_, OnAckNeedsRetransmittableFrame()).Times(AnyNumber());
  QuicConnectionPeer::SetAckDecimationDelay(&connection_, 0.125);

  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  // The ack time should be based on min_rtt/8, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() +
                      QuicTime::Delta::FromMilliseconds(kMinRttMs / 8);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.HasPendingAcks());
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // Process all the initial packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (unsigned int i = 0; i < kFirstDecimatedPacket - 1; ++i) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(1 + i, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
  }
  EXPECT_FALSE(connection_.HasPendingAcks());
  // The same as ProcessPacket(1) except that ENCRYPTION_ZERO_RTT is used
  // instead of ENCRYPTION_INITIAL.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kFirstDecimatedPacket, !kHasStopWaiting,
                           ENCRYPTION_ZERO_RTT);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.HasPendingAcks());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // The 10th received packet causes an ack to be sent.
  for (int i = 0; i < 9; ++i) {
    EXPECT_TRUE(connection_.HasPendingAcks());
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kFirstDecimatedPacket + 1 + i, !kHasStopWaiting,
                             ENCRYPTION_ZERO_RTT);
  }
  // Check that ack is sent and that delayed ack alarm is reset.
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, SendDelayedAckOnHandshakeConfirmed) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(1);
  // Check that ack is sent and that delayed ack alarm is set.
  EXPECT_TRUE(connection_.HasPendingAcks());
  QuicTime ack_time = clock_.ApproximateNow() + DefaultDelayedAckTime();
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // Completing the handshake as the server does nothing.
  QuicConnectionPeer::SetPerspective(&connection_, Perspective::IS_SERVER);
  connection_.OnHandshakeComplete();
  EXPECT_TRUE(connection_.HasPendingAcks());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // Complete the handshake as the client decreases the delayed ack time to 0ms.
  QuicConnectionPeer::SetPerspective(&connection_, Perspective::IS_CLIENT);
  connection_.OnHandshakeComplete();
  EXPECT_TRUE(connection_.HasPendingAcks());
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    EXPECT_EQ(clock_.ApproximateNow() + DefaultDelayedAckTime(),
              connection_.GetAckAlarm()->deadline());
  } else {
    EXPECT_EQ(clock_.ApproximateNow(), connection_.GetAckAlarm()->deadline());
  }
}

TEST_P(QuicConnectionTest, SendDelayedAckOnSecondPacket) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(1);
  ProcessPacket(2);
  // Check that ack is sent and that delayed ack alarm is reset.
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, NoAckOnOldNacks) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessPacket(2);
  size_t frames_per_ack = 1;

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ProcessPacket(3);
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + frames_per_ack, writer_->frame_count());
  EXPECT_FALSE(writer_->ack_frames().empty());
  writer_->Reset();

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessPacket(4);
  EXPECT_EQ(0u, writer_->frame_count());

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ProcessPacket(5);
  padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + frames_per_ack, writer_->frame_count());
  EXPECT_FALSE(writer_->ack_frames().empty());
  writer_->Reset();

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  // Now only set the timer on the 6th packet, instead of sending another ack.
  ProcessPacket(6);
  padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count, writer_->frame_count());
  EXPECT_TRUE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, SendDelayedAckOnOutgoingPacket) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_));
  peer_framer_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  SetDecrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  ProcessDataPacket(1);
  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, NO_FIN);
  // Check that ack is bundled with outgoing data and that delayed ack
  // alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, SendDelayedAckOnOutgoingCryptoPacket) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  }
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  connection_.SendCryptoDataWithString("foo", 0);
  // Check that ack is bundled with outgoing crypto data.
  EXPECT_FALSE(writer_->ack_frames().empty());
  if (!QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_FALSE(writer_->stream_frames().empty());
  } else {
    EXPECT_FALSE(writer_->crypto_frames().empty());
  }
  EXPECT_FALSE(writer_->padding_frames().empty());
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, BlockAndBufferOnFirstCHLOPacketOfTwo) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(1);
  BlockOnNextWrite();
  writer_->set_is_write_blocked_data_buffered(true);
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  } else {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  }
  connection_.SendCryptoDataWithString("foo", 0);
  EXPECT_TRUE(writer_->IsWriteBlocked());
  EXPECT_FALSE(connection_.HasQueuedData());
  connection_.SendCryptoDataWithString("bar", 3);
  EXPECT_TRUE(writer_->IsWriteBlocked());
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    // CRYPTO frames are not flushed when writer is blocked.
    EXPECT_FALSE(connection_.HasQueuedData());
  } else {
    EXPECT_TRUE(connection_.HasQueuedData());
  }
}

TEST_P(QuicConnectionTest, BundleAckForSecondCHLO) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.HasPendingAcks());
  EXPECT_CALL(visitor_, OnCanWrite())
      .WillOnce(IgnoreResult(InvokeWithoutArgs(
          &connection_, &TestConnection::SendCryptoStreamData)));
  // Process a packet from the crypto stream, which is frame1_'s default.
  // Receiving the CHLO as packet 2 first will cause the connection to
  // immediately send an ack, due to the packet gap.
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  }
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessCryptoPacketAtLevel(2, ENCRYPTION_INITIAL);
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());
  if (!QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_FALSE(writer_->stream_frames().empty());
  } else {
    EXPECT_FALSE(writer_->crypto_frames().empty());
  }
  EXPECT_FALSE(writer_->padding_frames().empty());
  ASSERT_FALSE(writer_->ack_frames().empty());
  EXPECT_EQ(QuicPacketNumber(2u), LargestAcked(writer_->ack_frames().front()));
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, BundleAckForSecondCHLOTwoPacketReject) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.HasPendingAcks());

  // Process two packets from the crypto stream, which is frame1_'s default,
  // simulating a 2 packet reject.
  {
    if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
      EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
    } else {
      EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    }
    ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
    // Send the new CHLO when the REJ is processed.
    if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
      EXPECT_CALL(visitor_, OnCryptoFrame(_))
          .WillOnce(IgnoreResult(InvokeWithoutArgs(
              &connection_, &TestConnection::SendCryptoStreamData)));
    } else {
      EXPECT_CALL(visitor_, OnStreamFrame(_))
          .WillOnce(IgnoreResult(InvokeWithoutArgs(
              &connection_, &TestConnection::SendCryptoStreamData)));
    }
    ForceWillingAndAbleToWriteOnceForDeferSending();
    ProcessCryptoPacketAtLevel(2, ENCRYPTION_INITIAL);
  }
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());
  if (!QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_FALSE(writer_->stream_frames().empty());
  } else {
    EXPECT_FALSE(writer_->crypto_frames().empty());
  }
  EXPECT_FALSE(writer_->padding_frames().empty());
  ASSERT_FALSE(writer_->ack_frames().empty());
  EXPECT_EQ(QuicPacketNumber(2u), LargestAcked(writer_->ack_frames().front()));
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, BundleAckWithDataOnIncomingAck) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, NO_FIN);
  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      3, NO_FIN);
  // Ack the second packet, which will retransmit the first packet.
  QuicAckFrame ack = ConstructAckFrame(2, 1);
  LostPacketVector lost_packets;
  lost_packets.push_back(
      LostPacket(QuicPacketNumber(1), kMaxOutgoingPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&ack);
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  writer_->Reset();

  // Now ack the retransmission, which will both raise the high water mark
  // and see if there is more data to send.
  ack = ConstructAckFrame(3, 1);
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&ack);

  // Check that no packet is sent and the ack alarm isn't set.
  EXPECT_EQ(0u, writer_->frame_count());
  EXPECT_FALSE(connection_.HasPendingAcks());
  writer_->Reset();

  // Send the same ack, but send both data and an ack together.
  ack = ConstructAckFrame(3, 1);
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(visitor_, OnCanWrite())
      .WillOnce(IgnoreResult(InvokeWithoutArgs(
          &connection_, &TestConnection::EnsureWritableAndSendStreamData5)));
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessAckPacket(&ack);

  // Check that ack is bundled with outgoing data and the delayed ack
  // alarm is reset.
  // Do not ACK acks.
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_TRUE(writer_->ack_frames().empty());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, NoAckSentForClose) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(1);
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_PEER))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessClosePacket(2);
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_PEER_GOING_AWAY));
}

TEST_P(QuicConnectionTest, SendWhenDisconnected) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  connection_.CloseConnection(QUIC_PEER_GOING_AWAY, "no reason",
                              ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_FALSE(connection_.connected());
  EXPECT_FALSE(connection_.CanWrite(HAS_RETRANSMITTABLE_DATA));
  EXPECT_EQ(DISCARD, connection_.GetSerializedPacketFate(
                         /*is_mtu_discovery=*/false, ENCRYPTION_INITIAL));
}

TEST_P(QuicConnectionTest, SendConnectivityProbingWhenDisconnected) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration()) {
    return;
  }

  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  connection_.CloseConnection(QUIC_PEER_GOING_AWAY, "no reason",
                              ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_FALSE(connection_.connected());
  EXPECT_FALSE(connection_.CanWrite(HAS_RETRANSMITTABLE_DATA));

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(1), _, _))
      .Times(0);

  EXPECT_QUIC_BUG(connection_.SendConnectivityProbingPacket(
                      writer_.get(), connection_.peer_address()),
                  "Not sending connectivity probing packet as connection is "
                  "disconnected.");
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_PEER_GOING_AWAY));
}

TEST_P(QuicConnectionTest, WriteBlockedAfterClientSendsConnectivityProbe) {
  PathProbeTestInit(Perspective::IS_CLIENT);
  TestPacketWriter probing_writer(version(), &clock_, Perspective::IS_CLIENT);
  // Block next write so that sending connectivity probe will encounter a
  // blocked write when send a connectivity probe to the peer.
  probing_writer.BlockOnNextWrite();
  // Connection will not be marked as write blocked as connectivity probe only
  // affects the probing_writer which is not the default.
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(0);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(1), _, _))
      .Times(1);
  connection_.SendConnectivityProbingPacket(&probing_writer,
                                            connection_.peer_address());
}

TEST_P(QuicConnectionTest, WriterBlockedAfterServerSendsConnectivityProbe) {
  PathProbeTestInit(Perspective::IS_SERVER);
  if (version().SupportsAntiAmplificationLimit()) {
    QuicConnectionPeer::SetAddressValidated(&connection_);
  }

  // Block next write so that sending connectivity probe will encounter a
  // blocked write when send a connectivity probe to the peer.
  writer_->BlockOnNextWrite();
  // Connection will be marked as write blocked as server uses the default
  // writer to send connectivity probes.
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(1);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(1), _, _))
      .Times(1);
  if (VersionHasIetfQuicFrames(GetParam().version.transport_version)) {
    QuicPathFrameBuffer payload{
        {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xfe}};
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.SendPathChallenge(
        payload, connection_.self_address(), connection_.peer_address(),
        connection_.effective_peer_address(), writer_.get());
  } else {
    connection_.SendConnectivityProbingPacket(writer_.get(),
                                              connection_.peer_address());
  }
}

TEST_P(QuicConnectionTest, WriterErrorWhenClientSendsConnectivityProbe) {
  PathProbeTestInit(Perspective::IS_CLIENT);
  TestPacketWriter probing_writer(version(), &clock_, Perspective::IS_CLIENT);
  probing_writer.SetShouldWriteFail();

  // Connection should not be closed if a connectivity probe is failed to be
  // sent.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(0);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(1), _, _))
      .Times(0);
  connection_.SendConnectivityProbingPacket(&probing_writer,
                                            connection_.peer_address());
}

TEST_P(QuicConnectionTest, WriterErrorWhenServerSendsConnectivityProbe) {
  PathProbeTestInit(Perspective::IS_SERVER);

  writer_->SetShouldWriteFail();
  // Connection should not be closed if a connectivity probe is failed to be
  // sent.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(0);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(1), _, _))
      .Times(0);
  connection_.SendConnectivityProbingPacket(writer_.get(),
                                            connection_.peer_address());
}

TEST_P(QuicConnectionTest, IetfStatelessReset) {
  QuicConfig config;
  QuicConfigPeer::SetReceivedStatelessResetToken(&config,
                                                 kTestStatelessResetToken);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  std::unique_ptr<QuicEncryptedPacket> packet(
      QuicFramer::BuildIetfStatelessResetPacket(connection_id_,
                                                /*received_packet_length=*/100,
                                                kTestStatelessResetToken));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*packet, QuicTime::Zero()));
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_PEER))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *received);
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_PUBLIC_RESET));
}

TEST_P(QuicConnectionTest, GoAway) {
  if (VersionHasIetfQuicFrames(GetParam().version.transport_version)) {
    // GoAway is not available in version 99.
    return;
  }

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicGoAwayFrame* goaway = new QuicGoAwayFrame();
  goaway->last_good_stream_id = 1;
  goaway->error_code = QUIC_PEER_GOING_AWAY;
  goaway->reason_phrase = "Going away.";
  EXPECT_CALL(visitor_, OnGoAway(_));
  ProcessGoAwayPacket(goaway);
}

TEST_P(QuicConnectionTest, WindowUpdate) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicWindowUpdateFrame window_update;
  window_update.stream_id = 3;
  window_update.max_data = 1234;
  EXPECT_CALL(visitor_, OnWindowUpdateFrame(_));
  ProcessFramePacket(QuicFrame(window_update));
}

TEST_P(QuicConnectionTest, Blocked) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicBlockedFrame blocked;
  blocked.stream_id = 3;
  EXPECT_CALL(visitor_, OnBlockedFrame(_));
  ProcessFramePacket(QuicFrame(blocked));
  EXPECT_EQ(1u, connection_.GetStats().blocked_frames_received);
  EXPECT_EQ(0u, connection_.GetStats().blocked_frames_sent);
}

TEST_P(QuicConnectionTest, ZeroBytePacket) {
  // Don't close the connection for zero byte packets.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(0);
  QuicReceivedPacket encrypted(nullptr, 0, QuicTime::Zero());
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, encrypted);
}

TEST_P(QuicConnectionTest, ClientHandlesVersionNegotiation) {
  // All supported versions except the one the connection supports.
  ParsedQuicVersionVector versions;
  for (auto version : AllSupportedVersions()) {
    if (version != connection_.version()) {
      versions.push_back(version);
    }
  }

  // Send a version negotiation packet.
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      QuicFramer::BuildVersionNegotiationPacket(
          connection_id_, EmptyQuicConnectionId(), /*ietf_quic=*/true,
          connection_.version().HasLengthPrefixedConnectionIds(), versions));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*encrypted, QuicTime::Zero()));
  EXPECT_CALL(visitor_, OnConne
"""


```
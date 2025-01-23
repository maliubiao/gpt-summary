Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of a larger file (`quic_connection_test.cc`) testing the QUIC connection logic in Chromium's network stack.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Functionality:** The code consists of several test cases (`TEST_P`) within the `QuicConnectionTest` class. Each test case focuses on a specific aspect of QUIC connection management. Keywords like "RetireConnectionId", "PatchMissingClientConnectionId", "ShouldGeneratePacketBlockedByMissingConnectionId", "LostDataThenGetAcknowledged", "PtoSendStreamData", "SendingZeroRttPacketsDoesNotPostponePTO", "QueueingUndecryptablePackets", "PingNotSentAt0RTTLevel", "AckElicitingFrames", "ReceivedChloAndAck", and "FailedToRetransmitShlo/ConsumeCryptoData" clearly indicate the areas being tested.

2. **Summarize Individual Test Case Functionality:** Go through each `TEST_P` block and distill its purpose. For instance:
    * `ServerRetireSelfIssuedConnectionIdWithoutSendingNewConnectionIdBefore`: Checks the behavior when a server tries to retire its own connection ID without issuing a new one first.
    * `PatchMissingClientConnectionIdOntoAlternativePath`: Verifies that a server can learn the client's connection ID for an alternative path.
    * `AckElicitingFrames`: Tests how the connection handles different frame types that require an acknowledgment.

3. **Identify Common Themes:** Notice recurring concepts like connection ID management (issuing, retiring, patching), packet loss and retransmission (PTO), handling undecryptable packets, address validation, and acknowledgment mechanisms.

4. **Determine Relevance to JavaScript:**  Consider how these low-level connection details relate to web developers using JavaScript. While JavaScript doesn't directly manipulate these QUIC internals, the behavior tested here impacts the reliability and performance of network requests made by JavaScript code.

5. **Provide JavaScript Examples (Indirect Relationship):**  Since the connection management is transparent to JavaScript, the examples should focus on the *outcomes* of these tests. For instance, connection migration (tested in some of these cases) improves resilience to network changes, which translates to a smoother user experience in JavaScript web applications.

6. **Look for Logic and Potential User/Programming Errors:** Some tests directly highlight error scenarios (e.g., retiring a connection ID prematurely). Consider how these could manifest as common mistakes in related areas (though not directly in this low-level code itself). For example, incorrect handling of connection IDs in a server implementation *using* this QUIC library.

7. **Infer User Actions Leading to the Code:** Think about the sequence of events in a network connection that would trigger these code paths. Establishing a QUIC connection, experiencing network changes, sending and receiving data, and handling errors are all relevant.

8. **Address the "Part 21 of 24" Instruction:**  Since this is a part of a larger test suite, infer that the overall purpose is comprehensive testing of the `QuicConnection` class. This specific part likely focuses on connection ID management, error handling, and some aspects of packet processing during and after the handshake.

9. **Structure the Answer:** Organize the information logically with clear headings for functionality, JavaScript relevance, logical inferences, user errors, debugging, and the overall summary.

10. **Refine and Elaborate:** Flesh out the explanations, providing more context and specific examples where necessary. For instance, explain *why* patching missing connection IDs is important for connection migration.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Directly correlate the C++ code to specific JavaScript APIs.
* **Correction:** Realize the connection is more indirect. Focus on the *impact* on JavaScript's network operations rather than direct code equivalents.
* **Initial thought:** Focus only on the positive scenarios.
* **Correction:** Recognize that test code often highlights error conditions and potential issues, which should be included in the analysis.
* **Initial thought:**  Explain each line of C++ code in detail.
* **Correction:**  Focus on the *high-level functionality* being tested rather than an exhaustive line-by-line explanation. The user asked for the *function* of the file, not a deep dive into the implementation details.

By following these steps, the aim is to provide a comprehensive and understandable explanation of the provided code snippet, addressing all aspects of the user's request.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 文件的第 21 部分，主要涵盖了 `QuicConnection` 类关于连接 ID 管理、数据包处理、以及一些错误处理场景的单元测试。

以下是该部分代码的功能归纳：

**主要功能:**

1. **连接 ID 管理测试 (Connection ID Management):**
   - **`ServerRetireSelfIssuedConnectionIdWithoutSendingNewConnectionIdBefore`:** 测试服务器在没有先发送新的连接 ID 的情况下尝试撤销自己颁发的连接 ID 的行为。预期会触发连接关闭，因为这违反了协议。
   - **`ServerRetireSelfIssuedConnectionId`:** 测试服务器撤销自己颁发的连接 ID 的流程，包括发送 `RETIRE_CONNECTION_ID` 帧，以及在收到该帧后，连接如何更新激活的连接 ID 列表，并触发 `NEW_CONNECTION_ID` 的发送。
   - **`PatchMissingClientConnectionIdOntoAlternativePath`:** 测试当服务器尝试迁移到新的路径时，如何通过收到的 `NEW_CONNECTION_ID` 帧来补全之前未知的新路径上的客户端连接 ID 信息。
   - **`PatchMissingClientConnectionIdOntoDefaultPath`:** 类似于上一个测试，但是针对的是迁移回默认路径的情况。
   - **`ShouldGeneratePacketBlockedByMissingConnectionId`:** 测试在没有可用的连接 ID 的情况下，连接是否会阻止发送数据包。这在连接迁移等场景中很重要。

2. **数据包处理和确认测试 (Packet Processing and Acknowledgement):**
   - **`LostDataThenGetAcknowledged`:**  一个回归测试，模拟数据包丢失后又被确认的场景，特别是涉及到路径迁移和乱序到达的数据包。
   - **`PtoSendStreamData`:** 测试当发生 PTO (Probe Timeout) 时，连接是否会正确地重传数据，包括不同加密级别的数据包（INITIAL, HANDSHAKE）。
   - **`SendingZeroRttPacketsDoesNotPostponePTO`:** 测试发送 0-RTT 数据包是否会延迟 PTO 定时器。预期是不会，因为 PTO 主要用于确保握手包的可靠传输。
   - **`QueueingUndecryptablePacketsDoesntPostponePTO`:** 测试队列中存在无法解密的包是否会延迟 PTO。
   - **`QueueUndecryptableHandshakePackets`:** 测试无法解密的握手包是否会被正确地加入队列等待后续处理。
   - **`PingNotSentAt0RTTLevelWhenInitialAvailable`:** 测试当 INITIAL 包可用时，PING 包是否不会在 0-RTT 级别发送。

3. **帧处理测试 (Frame Processing):**
   - **`AckElicitingFrames`:**  一个重要的测试，遍历所有被认为是“确认触发” (ack-eliciting) 的 QUIC 帧类型，并验证当收到这些帧时，连接是否会正确地标记需要发送 ACK。
   - **`ReceivedChloAndAck`:** 测试服务器接收到包含 CHLO (Client Hello) 和 ACK 帧的数据包时的处理情况。

4. **错误处理和边界情况测试 (Error Handling and Edge Cases):**
   - **`FailedToRetransmitShlo`:**  一个回归测试，模拟在某些情况下 SHLO (Server Hello) 重传失败的情况，可能与拥塞控制或反放大限制有关。
   - **`FailedToConsumeCryptoData`:**  一个回归测试，模拟在处理加密数据时可能发生的失败情况。

**与 JavaScript 功能的关系：**

这些测试直接作用于 QUIC 协议的底层实现，JavaScript 无法直接触及这些层面。然而，这些测试保证了 QUIC 连接的稳定性和可靠性，从而间接地影响了 JavaScript 中基于 WebTransport 或 Fetch API 等发起的网络请求的性能和用户体验。

**举例说明：**

- **连接迁移测试 (`PatchMissingClientConnectionId...`)：**  当用户在移动设备上从 Wi-Fi 切换到蜂窝网络时，底层的 QUIC 连接可能会尝试迁移到新的网络路径。这些测试确保了在迁移过程中，即使新的路径上客户端的连接 ID 最初未知，连接也能正确地恢复通信。这对于 JavaScript 应用来说，意味着即使网络环境发生变化，用户也可能不会感受到明显的连接中断。
- **PTO 测试 (`PtoSendStreamData`)：**  如果网络不稳定，某些数据包可能会丢失。PTO 机制保证了关键的握手信息能够被重传，从而确保连接建立成功。这对 JavaScript 应用至关重要，因为它依赖于可靠的连接来加载资源和进行 API 调用。

**逻辑推理、假设输入与输出：**

以 `ServerRetireSelfIssuedConnectionIdWithoutSendingNewConnectionIdBefore` 测试为例：

**假设输入：**

- 服务器当前连接状态：已连接。
- 服务器尝试撤销自己的连接 ID。
- 服务器尚未发送新的连接 ID 给客户端。
- 客户端发送了一个 `RETIRE_CONNECTION_ID` 帧，请求撤销一个尚未颁发的连接 ID。

**预期输出：**

- 连接应该被关闭。
- 关闭原因是 `IETF_QUIC_PROTOCOL_VIOLATION`，因为客户端不应该请求撤销一个服务器尚未颁发的连接 ID。

**用户或编程常见的使用错误：**

虽然这些是底层的连接测试，但相关的用户或编程错误可能发生在更上层的 QUIC 应用开发中：

- **错误地管理连接 ID：** 在服务器端或客户端，如果没有正确地跟踪和管理连接 ID 的生命周期，可能会导致尝试撤销不存在的连接 ID，或者在错误的连接 ID 上发送数据。
- **没有正确处理连接迁移：**  如果应用程序没有考虑到连接可能迁移到新的路径，可能会导致在旧的连接信息上发送数据，导致连接失败。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户发起网络请求：** 用户在浏览器中访问一个使用 QUIC 协议的网站，或者 JavaScript 代码通过 `fetch` 或 WebTransport API 发起一个请求。
2. **建立 QUIC 连接：** 底层的网络栈开始与服务器建立 QUIC 连接，包括握手过程。
3. **连接 ID 的协商和使用：**  连接建立后，客户端和服务器会协商并使用连接 ID 来标识连接。
4. **可能触发连接 ID 相关的操作：**
   - **连接迁移：** 如果用户的网络环境发生变化（例如，从 Wi-Fi 切换到蜂窝网络），连接可能会尝试迁移，这会涉及到新的连接 ID 的生成和交换。
   - **连接 ID 的轮换：** 为了增强安全性，QUIC 连接可能会定期轮换连接 ID。
5. **收到 `RETIRE_CONNECTION_ID` 帧 (在错误的情况下)：**  如果客户端实现有错误，可能会意外地发送 `RETIRE_CONNECTION_ID` 帧，请求撤销一个不存在或不应该被撤销的连接 ID，从而触发 `ServerRetireSelfIssuedConnectionIdWithoutSendingNewConnectionIdBefore` 测试所覆盖的场景。

**作为第 21 部分的功能归纳：**

作为整个 `quic_connection_test.cc` 文件的一部分，这第 21 部分主要集中在以下几个方面：

- **确保连接 ID 管理的正确性：**  测试了连接 ID 的颁发、撤销、以及在连接迁移过程中的更新和使用。
- **验证数据包处理和确认机制的可靠性：**  测试了 PTO 机制，以及不同帧类型对确认机制的影响。
- **覆盖了多种错误和边界情况：**  包括错误的连接 ID 操作、无法解密的数据包、以及在特定场景下的重传失败。

总而言之，这部分代码通过一系列细致的单元测试，旨在验证 `QuicConnection` 类在连接 ID 管理和数据包处理方面的正确性和健壮性，从而保障基于 QUIC 协议的网络连接的稳定性和可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第21部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
(!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
        .WillOnce(Return(TestConnectionId(456)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_)).WillOnce(Return(true));
  EXPECT_CALL(visitor_, SendNewConnectionId(_));
  connection_.MaybeSendConnectionIdToClient();

  EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  QuicRetireConnectionIdFrame frame;
  frame.sequence_number = 2u;  // The corresponding ID is never issued.

  EXPECT_FALSE(connection_.OnRetireConnectionIdFrame(frame));

  EXPECT_FALSE(connection_.connected());
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(IETF_QUIC_PROTOCOL_VIOLATION));
}

TEST_P(QuicConnectionTest,
       ServerRetireSelfIssuedConnectionIdWithoutSendingNewConnectionIdBefore) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  connection_.CreateConnectionIdManager();

  auto* retire_self_issued_cid_alarm =
      connection_.GetRetireSelfIssuedConnectionIdAlarm();
  ASSERT_FALSE(retire_self_issued_cid_alarm->IsSet());

  QuicConnectionId cid0 = connection_id_;
  QuicRetireConnectionIdFrame frame;
  frame.sequence_number = 0u;

  if (!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(cid0))
        .WillOnce(Return(TestConnectionId(456)));
    EXPECT_CALL(connection_id_generator_,
                GenerateNextConnectionId(TestConnectionId(456)))
        .WillOnce(Return(TestConnectionId(789)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_))
      .Times(2)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(visitor_, SendNewConnectionId(_)).Times(2);
  EXPECT_TRUE(connection_.OnRetireConnectionIdFrame(frame));
}

TEST_P(QuicConnectionTest, ServerRetireSelfIssuedConnectionId) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  connection_.CreateConnectionIdManager();
  QuicConnectionId recorded_cid;
  auto cid_recorder = [&recorded_cid](const QuicConnectionId& cid) -> bool {
    recorded_cid = cid;
    return true;
  };
  QuicConnectionId cid0 = connection_id_;
  QuicConnectionId cid1;
  QuicConnectionId cid2;
  EXPECT_EQ(connection_.connection_id(), cid0);
  EXPECT_EQ(connection_.GetOneActiveServerConnectionId(), cid0);

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  if (!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
        .WillOnce(Return(TestConnectionId(456)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_))
      .WillOnce(Invoke(cid_recorder));
  EXPECT_CALL(visitor_, SendNewConnectionId(_));
  connection_.MaybeSendConnectionIdToClient();
  cid1 = recorded_cid;

  auto* retire_self_issued_cid_alarm =
      connection_.GetRetireSelfIssuedConnectionIdAlarm();
  ASSERT_FALSE(retire_self_issued_cid_alarm->IsSet());

  // Generate three packets with different connection IDs that will arrive out
  // of order (2, 1, 3) later.
  char buffers[3][kMaxOutgoingPacketSize];
  // Destination connection ID of packet1 is cid0.
  auto packet1 =
      ConstructPacket({QuicFrame(QuicPingFrame())}, ENCRYPTION_FORWARD_SECURE,
                      buffers[0], kMaxOutgoingPacketSize);
  peer_creator_.SetServerConnectionId(cid1);
  auto retire_cid_frame = std::make_unique<QuicRetireConnectionIdFrame>();
  retire_cid_frame->sequence_number = 0u;
  // Destination connection ID of packet2 is cid1.
  auto packet2 = ConstructPacket({QuicFrame(retire_cid_frame.release())},
                                 ENCRYPTION_FORWARD_SECURE, buffers[1],
                                 kMaxOutgoingPacketSize);
  // Destination connection ID of packet3 is cid1.
  auto packet3 =
      ConstructPacket({QuicFrame(QuicPingFrame())}, ENCRYPTION_FORWARD_SECURE,
                      buffers[2], kMaxOutgoingPacketSize);

  // Packet2 with RetireConnectionId frame trigers sending NewConnectionId
  // immediately.
  if (!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
        .WillOnce(Return(TestConnectionId(456)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_))
      .WillOnce(Invoke(cid_recorder));
  EXPECT_CALL(visitor_, SendNewConnectionId(_));
  peer_creator_.SetServerConnectionId(cid1);
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *packet2);
  cid2 = recorded_cid;
  // cid0 is not retired immediately.
  EXPECT_THAT(connection_.GetActiveServerConnectionIds(),
              ElementsAre(cid0, cid1, cid2));
  ASSERT_TRUE(retire_self_issued_cid_alarm->IsSet());
  EXPECT_EQ(connection_.connection_id(), cid1);
  EXPECT_TRUE(connection_.GetOneActiveServerConnectionId() == cid0 ||
              connection_.GetOneActiveServerConnectionId() == cid1 ||
              connection_.GetOneActiveServerConnectionId() == cid2);

  // Packet1 updates the connection ID on the default path but not the active
  // connection ID.
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *packet1);
  EXPECT_EQ(connection_.connection_id(), cid0);
  EXPECT_TRUE(connection_.GetOneActiveServerConnectionId() == cid0 ||
              connection_.GetOneActiveServerConnectionId() == cid1 ||
              connection_.GetOneActiveServerConnectionId() == cid2);

  // cid0 is retired when the retire CID alarm fires.
  EXPECT_CALL(visitor_, OnServerConnectionIdRetired(cid0));
  retire_self_issued_cid_alarm->Fire();
  EXPECT_THAT(connection_.GetActiveServerConnectionIds(),
              ElementsAre(cid1, cid2));
  EXPECT_TRUE(connection_.GetOneActiveServerConnectionId() == cid1 ||
              connection_.GetOneActiveServerConnectionId() == cid2);

  // Packet3 updates the connection ID on the default path.
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *packet3);
  EXPECT_EQ(connection_.connection_id(), cid1);
  EXPECT_TRUE(connection_.GetOneActiveServerConnectionId() == cid1 ||
              connection_.GetOneActiveServerConnectionId() == cid2);
}

TEST_P(QuicConnectionTest, PatchMissingClientConnectionIdOntoAlternativePath) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  connection_.CreateConnectionIdManager();
  connection_.set_client_connection_id(TestConnectionId(1));

  // Set up the state after path probing.
  const auto* default_path = QuicConnectionPeer::GetDefaultPath(&connection_);
  auto* alternative_path = QuicConnectionPeer::GetAlternativePath(&connection_);
  QuicIpAddress new_host;
  new_host.FromString("12.12.12.12");
  alternative_path->self_address = default_path->self_address;
  alternative_path->peer_address = QuicSocketAddress(new_host, 12345);
  alternative_path->server_connection_id = TestConnectionId(3);
  ASSERT_TRUE(alternative_path->client_connection_id.IsEmpty());
  ASSERT_FALSE(alternative_path->stateless_reset_token.has_value());

  QuicNewConnectionIdFrame frame;
  frame.sequence_number = 1u;
  frame.connection_id = TestConnectionId(5);
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;
  // New ID is patched onto the alternative path when the needed
  // NEW_CONNECTION_ID frame is received after PATH_CHALLENGE frame.
  connection_.OnNewConnectionIdFrame(frame);

  ASSERT_EQ(alternative_path->client_connection_id, frame.connection_id);
  ASSERT_EQ(alternative_path->stateless_reset_token,
            frame.stateless_reset_token);
}

TEST_P(QuicConnectionTest, PatchMissingClientConnectionIdOntoDefaultPath) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  connection_.CreateConnectionIdManager();
  connection_.set_client_connection_id(TestConnectionId(1));

  // Set up the state after peer migration without probing.
  auto* default_path = QuicConnectionPeer::GetDefaultPath(&connection_);
  auto* alternative_path = QuicConnectionPeer::GetAlternativePath(&connection_);
  auto* packet_creator = QuicConnectionPeer::GetPacketCreator(&connection_);
  *alternative_path = std::move(*default_path);
  QuicIpAddress new_host;
  new_host.FromString("12.12.12.12");
  default_path->self_address = default_path->self_address;
  default_path->peer_address = QuicSocketAddress(new_host, 12345);
  default_path->server_connection_id = TestConnectionId(3);
  packet_creator->SetDefaultPeerAddress(default_path->peer_address);
  packet_creator->SetServerConnectionId(default_path->server_connection_id);
  packet_creator->SetClientConnectionId(default_path->client_connection_id);

  ASSERT_FALSE(default_path->validated);
  ASSERT_TRUE(default_path->client_connection_id.IsEmpty());
  ASSERT_FALSE(default_path->stateless_reset_token.has_value());

  QuicNewConnectionIdFrame frame;
  frame.sequence_number = 1u;
  frame.connection_id = TestConnectionId(5);
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;
  // New ID is patched onto the default path when the needed
  // NEW_CONNECTION_ID frame is received after PATH_CHALLENGE frame.
  connection_.OnNewConnectionIdFrame(frame);

  ASSERT_EQ(default_path->client_connection_id, frame.connection_id);
  ASSERT_EQ(default_path->stateless_reset_token, frame.stateless_reset_token);
  ASSERT_EQ(packet_creator->GetDestinationConnectionId(), frame.connection_id);
}

TEST_P(QuicConnectionTest, ShouldGeneratePacketBlockedByMissingConnectionId) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  connection_.set_client_connection_id(TestConnectionId(1));
  connection_.CreateConnectionIdManager();
  if (version().SupportsAntiAmplificationLimit()) {
    QuicConnectionPeer::SetAddressValidated(&connection_);
  }

  ASSERT_TRUE(
      connection_.ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA, NOT_HANDSHAKE));

  QuicPacketCreator* packet_creator =
      QuicConnectionPeer::GetPacketCreator(&connection_);
  QuicIpAddress peer_host1;
  peer_host1.FromString("12.12.12.12");
  QuicSocketAddress peer_address1(peer_host1, 1235);

  {
    // No connection ID is available as context is created without any.
    QuicPacketCreator::ScopedPeerAddressContext context(
        packet_creator, peer_address1, EmptyQuicConnectionId(),
        EmptyQuicConnectionId());
    ASSERT_FALSE(connection_.ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA,
                                                  NOT_HANDSHAKE));
  }
  ASSERT_TRUE(
      connection_.ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA, NOT_HANDSHAKE));
}

// Regression test for b/182571515
TEST_P(QuicConnectionTest, LostDataThenGetAcknowledged) {
  set_perspective(Perspective::IS_SERVER);
  if (!version().SupportsAntiAmplificationLimit() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }

  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  if (version().SupportsAntiAmplificationLimit()) {
    QuicConnectionPeer::SetAddressValidated(&connection_);
  }
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));

  QuicPacketNumber last_packet;
  // Send packets 1 to 4.
  SendStreamDataToPeer(3, "foo", 0, NO_FIN, &last_packet);  // Packet 1
  SendStreamDataToPeer(3, "foo", 3, NO_FIN, &last_packet);  // Packet 2
  SendStreamDataToPeer(3, "foo", 6, NO_FIN, &last_packet);  // Packet 3
  SendStreamDataToPeer(3, "foo", 9, NO_FIN, &last_packet);  // Packet 4

  // Process a PING packet to set peer address.
  ProcessFramePacket(QuicFrame(QuicPingFrame()));

  // Process a packet containing a STREAM_FRAME and an ACK with changed peer
  // address.
  QuicFrames frames;
  frames.push_back(QuicFrame(frame1_));
  QuicAckFrame ack = InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(5)}});
  frames.push_back(QuicFrame(&ack));

  // Invoke OnCanWrite.
  QuicIpAddress ip_address;
  ASSERT_TRUE(ip_address.FromString("127.0.52.223"));
  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(visitor_, OnConnectionMigration(_)).Times(1);
        EXPECT_CALL(visitor_, OnStreamFrame(_))
            .WillOnce(InvokeWithoutArgs(&notifier_,
                                        &SimpleSessionNotifier::OnCanWrite));
        ProcessFramesPacketWithAddresses(frames, kSelfAddress,
                                         QuicSocketAddress(ip_address, 1000),
                                         ENCRYPTION_FORWARD_SECURE);
        EXPECT_EQ(1u, writer_->path_challenge_frames().size());

        // Verify stream frame will not be retransmitted.
        EXPECT_TRUE(writer_->stream_frames().empty());
      },
      "Try to write mid packet processing");
}

TEST_P(QuicConnectionTest, PtoSendStreamData) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Send INITIAL 1.
  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_INITIAL);

  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  SetDecrypter(ENCRYPTION_HANDSHAKE,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_HANDSHAKE));
  // Send HANDSHAKE packets.
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_HANDSHAKE);

  connection_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  // Send half RTT packet with congestion control blocked.
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(false));
  connection_.SendStreamDataWithString(2, std::string(1500, 'a'), 0, NO_FIN);

  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  connection_.GetRetransmissionAlarm()->Fire();
  // Verify INITIAL and HANDSHAKE get retransmitted.
  EXPECT_EQ(0x01010101u, writer_->final_bytes_of_last_packet());
}

TEST_P(QuicConnectionTest, SendingZeroRttPacketsDoesNotPostponePTO) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Send CHLO.
  connection_.SendCryptoStreamData();
  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  // Install 0-RTT keys.
  connection_.SetEncrypter(ENCRYPTION_ZERO_RTT,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);

  // CHLO gets acknowledged after 10ms.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  QuicAckFrame frame1 = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  ProcessFramePacketAtLevel(1, QuicFrame(&frame1), ENCRYPTION_INITIAL);
  // Verify PTO is still armed since address validation is not finished yet.
  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  QuicTime pto_deadline = connection_.GetRetransmissionAlarm()->deadline();

  // Send 0-RTT packet.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  connection_.SetEncrypter(ENCRYPTION_ZERO_RTT,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  connection_.SendStreamDataWithString(2, "foo", 0, NO_FIN);
  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  // PTO deadline should be unchanged.
  EXPECT_EQ(pto_deadline, connection_.GetRetransmissionAlarm()->deadline());
}

TEST_P(QuicConnectionTest, QueueingUndecryptablePacketsDoesntPostponePTO) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.set_max_undecryptable_packets(3);
  connection_.SetFromConfig(config);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.RemoveDecrypter(ENCRYPTION_FORWARD_SECURE);
  // Send CHLO.
  connection_.SendCryptoStreamData();

  // Send 0-RTT packet.
  connection_.SetEncrypter(ENCRYPTION_ZERO_RTT,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  connection_.SendStreamDataWithString(2, "foo", 0, NO_FIN);

  // CHLO gets acknowledged after 10ms.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  QuicAckFrame frame1 = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  ProcessFramePacketAtLevel(1, QuicFrame(&frame1), ENCRYPTION_INITIAL);
  // Verify PTO is still armed since address validation is not finished yet.
  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  QuicTime pto_deadline = connection_.GetRetransmissionAlarm()->deadline();

  // Receive an undecryptable packets.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  peer_framer_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                            std::make_unique<TaggingEncrypter>(0xFF));
  ProcessDataPacketAtLevel(3, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
  // Verify PTO deadline is sooner.
  EXPECT_GT(pto_deadline, connection_.GetRetransmissionAlarm()->deadline());
  pto_deadline = connection_.GetRetransmissionAlarm()->deadline();

  // PTO fires.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  clock_.AdvanceTime(pto_deadline - clock_.ApproximateNow());
  connection_.GetRetransmissionAlarm()->Fire();
  // Verify PTO is still armed since address validation is not finished yet.
  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  pto_deadline = connection_.GetRetransmissionAlarm()->deadline();

  // Verify PTO deadline does not change.
  ProcessDataPacketAtLevel(4, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(pto_deadline, connection_.GetRetransmissionAlarm()->deadline());
}

TEST_P(QuicConnectionTest, QueueUndecryptableHandshakePackets) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.set_max_undecryptable_packets(3);
  connection_.SetFromConfig(config);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.RemoveDecrypter(ENCRYPTION_HANDSHAKE);
  // Send CHLO.
  connection_.SendCryptoStreamData();

  // Send 0-RTT packet.
  connection_.SetEncrypter(ENCRYPTION_ZERO_RTT,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  connection_.SendStreamDataWithString(2, "foo", 0, NO_FIN);
  EXPECT_EQ(0u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));

  // Receive an undecryptable handshake packet.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  peer_framer_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                            std::make_unique<TaggingEncrypter>(0xFF));
  ProcessDataPacketAtLevel(3, !kHasStopWaiting, ENCRYPTION_HANDSHAKE);
  // Verify this handshake packet gets queued.
  EXPECT_EQ(1u, QuicConnectionPeer::NumUndecryptablePackets(&connection_));
}

TEST_P(QuicConnectionTest, PingNotSentAt0RTTLevelWhenInitialAvailable) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Send CHLO.
  connection_.SendCryptoStreamData();
  // Send 0-RTT packet.
  connection_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  connection_.SendStreamDataWithString(2, "foo", 0, NO_FIN);

  // CHLO gets acknowledged after 10ms.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  QuicAckFrame frame1 = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  ProcessFramePacketAtLevel(1, QuicFrame(&frame1), ENCRYPTION_INITIAL);
  // Verify PTO is still armed since address validation is not finished yet.
  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  QuicTime pto_deadline = connection_.GetRetransmissionAlarm()->deadline();

  // PTO fires.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  clock_.AdvanceTime(pto_deadline - clock_.ApproximateNow());
  connection_.GetRetransmissionAlarm()->Fire();
  // Verify the PING gets sent in ENCRYPTION_INITIAL.
  EXPECT_NE(0x02020202u, writer_->final_bytes_of_last_packet());
}

TEST_P(QuicConnectionTest, AckElicitingFrames) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.SetReliableStreamReset(true);
  connection_.SetFromConfig(config);

  EXPECT_CALL(connection_id_generator_,
              GenerateNextConnectionId(TestConnectionId(12)))
      .WillOnce(Return(TestConnectionId(456)));
  EXPECT_CALL(connection_id_generator_,
              GenerateNextConnectionId(TestConnectionId(456)))
      .WillOnce(Return(TestConnectionId(789)));
  EXPECT_CALL(visitor_, SendNewConnectionId(_)).Times(2);
  EXPECT_CALL(visitor_, OnRstStream(_));
  EXPECT_CALL(visitor_, OnResetStreamAt(_));
  EXPECT_CALL(visitor_, OnWindowUpdateFrame(_));
  EXPECT_CALL(visitor_, OnBlockedFrame(_));
  EXPECT_CALL(visitor_, OnHandshakeDoneReceived());
  EXPECT_CALL(visitor_, OnStreamFrame(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  EXPECT_CALL(visitor_, OnMaxStreamsFrame(_));
  EXPECT_CALL(visitor_, OnStreamsBlockedFrame(_));
  EXPECT_CALL(visitor_, OnStopSendingFrame(_));
  EXPECT_CALL(visitor_, OnMessageReceived(""));
  EXPECT_CALL(visitor_, OnNewTokenReceived(""));

  SetClientConnectionId(TestConnectionId(12));
  connection_.CreateConnectionIdManager();
  QuicConnectionPeer::GetSelfIssuedConnectionIdManager(&connection_)
      ->MaybeSendNewConnectionIds();
  connection_.set_can_receive_ack_frequency_frame();

  QuicAckFrame ack_frame = InitAckFrame(1);
  QuicRstStreamFrame rst_stream_frame;
  QuicWindowUpdateFrame window_update_frame;
  QuicPathChallengeFrame path_challenge_frame;
  QuicNewConnectionIdFrame new_connection_id_frame;
  new_connection_id_frame.sequence_number = 1u;
  QuicRetireConnectionIdFrame retire_connection_id_frame;
  retire_connection_id_frame.sequence_number = 1u;
  QuicStopSendingFrame stop_sending_frame;
  QuicPathResponseFrame path_response_frame;
  QuicMessageFrame message_frame;
  QuicNewTokenFrame new_token_frame;
  QuicAckFrequencyFrame ack_frequency_frame;
  QuicResetStreamAtFrame reset_stream_at_frame;
  QuicBlockedFrame blocked_frame;
  size_t packet_number = 1;

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  QuicFramer* framer = const_cast<QuicFramer*>(&connection_.framer());
  framer->set_process_reset_stream_at(true);
  peer_framer_.set_process_reset_stream_at(true);

  for (uint8_t i = 0; i < NUM_FRAME_TYPES; ++i) {
    QuicFrameType frame_type = static_cast<QuicFrameType>(i);
    bool skipped = false;
    QuicFrame frame;
    QuicFrames frames;
    // Add some padding to fullfill the min size requirement of header
    // protection.
    frames.push_back(QuicFrame(QuicPaddingFrame(10)));
    switch (frame_type) {
      case PADDING_FRAME:
        frame = QuicFrame(QuicPaddingFrame(10));
        break;
      case MTU_DISCOVERY_FRAME:
        frame = QuicFrame(QuicMtuDiscoveryFrame());
        break;
      case PING_FRAME:
        frame = QuicFrame(QuicPingFrame());
        break;
      case MAX_STREAMS_FRAME:
        frame = QuicFrame(QuicMaxStreamsFrame());
        break;
      case STOP_WAITING_FRAME:
        // Not supported.
        skipped = true;
        break;
      case STREAMS_BLOCKED_FRAME:
        frame = QuicFrame(QuicStreamsBlockedFrame());
        break;
      case STREAM_FRAME:
        frame = QuicFrame(QuicStreamFrame());
        break;
      case HANDSHAKE_DONE_FRAME:
        frame = QuicFrame(QuicHandshakeDoneFrame());
        break;
      case ACK_FRAME:
        frame = QuicFrame(&ack_frame);
        break;
      case RST_STREAM_FRAME:
        frame = QuicFrame(&rst_stream_frame);
        break;
      case CONNECTION_CLOSE_FRAME:
        // Do not test connection close.
        skipped = true;
        break;
      case GOAWAY_FRAME:
        // Does not exist in IETF QUIC.
        skipped = true;
        break;
      case BLOCKED_FRAME:
        frame = QuicFrame(blocked_frame);
        break;
      case WINDOW_UPDATE_FRAME:
        frame = QuicFrame(window_update_frame);
        break;
      case PATH_CHALLENGE_FRAME:
        frame = QuicFrame(path_challenge_frame);
        break;
      case STOP_SENDING_FRAME:
        frame = QuicFrame(stop_sending_frame);
        break;
      case NEW_CONNECTION_ID_FRAME:
        frame = QuicFrame(&new_connection_id_frame);
        break;
      case RETIRE_CONNECTION_ID_FRAME:
        frame = QuicFrame(&retire_connection_id_frame);
        break;
      case PATH_RESPONSE_FRAME:
        frame = QuicFrame(path_response_frame);
        break;
      case MESSAGE_FRAME:
        frame = QuicFrame(&message_frame);
        break;
      case CRYPTO_FRAME:
        // CRYPTO_FRAME is ack eliciting is covered by other tests.
        skipped = true;
        break;
      case NEW_TOKEN_FRAME:
        frame = QuicFrame(&new_token_frame);
        break;
      case ACK_FREQUENCY_FRAME:
        frame = QuicFrame(&ack_frequency_frame);
        break;
      case RESET_STREAM_AT_FRAME:
        frame = QuicFrame(&reset_stream_at_frame);
        break;
      case NUM_FRAME_TYPES:
        skipped = true;
        break;
    }
    if (skipped) {
      continue;
    }
    ASSERT_EQ(frame_type, frame.type);
    frames.push_back(frame);
    EXPECT_FALSE(connection_.HasPendingAcks());
    // Process frame.
    ProcessFramesPacketAtLevel(packet_number++, frames,
                               ENCRYPTION_FORWARD_SECURE);
    if (QuicUtils::IsAckElicitingFrame(frame_type)) {
      ASSERT_TRUE(connection_.HasPendingAcks()) << frame;
      // Flush ACK.
      clock_.AdvanceTime(DefaultDelayedAckTime());
      connection_.GetAckAlarm()->Fire();
    }
    EXPECT_FALSE(connection_.HasPendingAcks());
    ASSERT_TRUE(connection_.connected());
  }
}

TEST_P(QuicConnectionTest, ReceivedChloAndAck) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  QuicFrames frames;
  QuicAckFrame ack_frame = InitAckFrame(1);
  frames.push_back(MakeCryptoFrame());
  frames.push_back(QuicFrame(&ack_frame));

  EXPECT_CALL(visitor_, OnCryptoFrame(_))
      .WillOnce(IgnoreResult(InvokeWithoutArgs(
          &connection_, &TestConnection::SendCryptoStreamData)));
  EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kPeerAddress,
                                   ENCRYPTION_INITIAL);
}

// Regression test for b/201643321.
TEST_P(QuicConnectionTest, FailedToRetransmitShlo) {
  if (!version().SupportsAntiAmplificationLimit() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  // Received INITIAL 1.
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());

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
  // Received ENCRYPTION_ZERO_RTT 1.
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // Send INITIAL 1.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
    connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_INITIAL);
    // Send HANDSHAKE 2.
    EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
    connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_HANDSHAKE);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    // Send half RTT data to exhaust amplification credit.
    connection_.SendStreamDataWithString(0, std::string(100 * 1024, 'a'), 0,
                                         NO_FIN);
  }
  // Received INITIAL 2.
  ProcessCryptoPacketAtLevel(2, ENCRYPTION_INITIAL);
  ASSERT_TRUE(connection_.HasPendingAcks());
  // Verify ACK delay is 1ms.
  EXPECT_EQ(clock_.Now() + kAlarmGranularity,
            connection_.GetAckAlarm()->deadline());
  // ACK is not throttled by amplification limit, and SHLO is bundled. Also
  // HANDSHAKE + 1RTT packets get coalesced.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(3);
  // ACK alarm fires.
  clock_.AdvanceTime(kAlarmGranularity);
  connection_.GetAckAlarm()->Fire();
  // Verify 1-RTT packet is coalesced.
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
  // Only the first packet in the coalesced packet has been processed,
  // verify SHLO is bundled with INITIAL ACK.
  EXPECT_EQ(1u, writer_->ack_frames().size());
  EXPECT_EQ(1u, writer_->crypto_frames().size());
  // Process the coalesced HANDSHAKE packet.
  ASSERT_TRUE(writer_->coalesced_packet() != nullptr);
  auto packet = writer_->coalesced_packet()->Clone();
  writer_->framer()->ProcessPacket(*packet);
  EXPECT_EQ(0u, writer_->ack_frames().size());
  EXPECT_EQ(1u, writer_->crypto_frames().size());
  // Process the coalesced 1-RTT packet.
  ASSERT_TRUE(writer_->coalesced_packet() != nullptr);
  packet = writer_->coalesced_packet()->Clone();
  writer_->framer()->ProcessPacket(*packet);
  EXPECT_EQ(0u, writer_->crypto_frames().size());
  EXPECT_EQ(1u, writer_->stream_frames().size());

  // Received INITIAL 3.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  ProcessCryptoPacketAtLevel(3, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());
}

// Regression test for b/216133388.
TEST_P(QuicConnectionTest, FailedToConsumeCryptoData) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  // Received INITIAL 1.
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());

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
  // Received ENCRYPTION_ZERO_RTT 1.
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // Send INITIAL 1.
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
    connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_INITIAL);
    // Send HANDSHAKE 2.
    EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
```
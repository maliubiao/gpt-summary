Response:
My thinking process to answer the request about `quic_connection_test.cc` went through these stages:

1. **Understanding the Core Request:** The user wants to know the functionality of the provided C++ code snippet from Chromium's QUIC implementation. They are particularly interested in its relationship to JavaScript, logical inferences, potential user errors, debugging context, and a summary of its purpose (as part 4 of 24).

2. **Identifying the Code's Nature:**  The file name `quic_connection_test.cc` immediately signals that this is a *unit test* file. Unit tests are designed to verify the behavior of specific units of code in isolation. In this case, the "unit" is likely the `QuicConnection` class or related components.

3. **Analyzing the Code Snippet:** I scanned the provided code, looking for keywords and patterns:
    * `TEST_P`: This indicates parameterized tests, a common testing pattern.
    * `EXPECT_CALL`:  This is characteristic of mocking frameworks (likely Google Mock) used for testing interactions with other objects.
    * `visitor_`: This suggests an object adhering to the Visitor pattern, likely the `QuicConnectionVisitorInterface`.
    * `ProcessFramesPacketWithAddresses`, `ProcessFramePacketWithAddresses`, `ProcessReceivedPacket`: These function calls clearly indicate the processing of incoming QUIC packets.
    * `OnConnectionMigration`: This event is frequently checked, pointing to tests related to connection migration.
    * `kSelfAddress`, `kPeerAddress`, `kNewPeerAddress`:  These constants likely represent source and destination addresses for packets.
    * `ENCRYPTION_FORWARD_SECURE`, `ENCRYPTION_INITIAL`: These constants refer to different encryption levels in the QUIC handshake.
    * `SendStreamDataToPeer`, `SendConnectivityProbingPacket`, `SendMtuDiscoveryPacket`: These functions indicate sending various types of QUIC packets.
    * `GetStats()`: This hints at tests examining connection statistics.
    * `NumQueuedPackets()`:  This suggests tests related to packet queuing.

4. **Inferring Functionality (Based on the Snippet and General Knowledge of QUIC):** Based on the code analysis, I could infer the following functionalities being tested:
    * **Connection Migration:**  A significant portion of the code deals with scenarios involving changing peer addresses (`kNewPeerAddress`), indicating tests for connection migration (moving the connection to a new network path).
    * **Reverse Path Validation:** The checks for `QuicPathResponseFrame` and the retry logic suggest tests for verifying the reachability of the peer at the new address.
    * **Connectivity Probing:** The terms "probing packet," `PATH_CHALLENGE`, and `PATH_RESPONSE` point to tests for QUIC's mechanism to actively check network connectivity.
    * **Packet Processing with Different Addresses:** The repeated use of `ProcessFramesPacketWithAddresses` with different source and destination addresses confirms that the code tests how the `QuicConnection` handles packets from various network locations.
    * **Packet Queuing and Blocking:** The tests involving `writer_->SetWriteBlocked()` and `NumQueuedPackets()` indicate tests for how the connection handles situations where it can't immediately send data.
    * **Handling of Packet Too Large:** The `BufferedMtuPacketTooBig` test specifically addresses how the connection reacts to Path MTU Discovery (PMTUD) signals.
    * **Out-of-Order Packet Handling:** The `ReceiveReorderedPathProbingAtServer` test checks how the connection deals with packets arriving in a different order than they were sent.
    * **Connection Closure:** The `DiscardQueuedPacketsAfterConnectionClose` test verifies the behavior when a connection is closed while there are still packets to be sent.

5. **Considering the JavaScript Relationship:**  QUIC is a transport protocol typically used under HTTP/3. While the *core implementation* is in C++, JavaScript interacts with it through browser APIs. I focused on:
    * **`fetch()` API:**  This is the primary way JavaScript initiates network requests, and QUIC would be the underlying transport for HTTP/3 requests.
    * **WebSockets:**  While not directly demonstrated in the snippet, WebSockets can also potentially use QUIC as a transport.
    * **User Experience:**  Connection migration, which is heavily tested here, directly impacts the user experience by maintaining connectivity during network changes.

6. **Developing Logical Inferences (Hypothetical Inputs and Outputs):**  For specific test cases, I tried to imagine the setup and expected outcome:
    * **Migration Scenario:**  Input: A packet arrives from a new peer address. Output: The connection migrates to the new address, and a path validation process starts.
    * **Probing Failure:** Input:  Repeated path validation attempts fail. Output: The connection reverts to the original path.

7. **Identifying Potential User/Programming Errors:**  I thought about common pitfalls:
    * **Firewall Issues:**  Misconfigured firewalls could block packets from new addresses, interfering with migration.
    * **Network Instability:** Frequent network changes could lead to repeated migration attempts and potential connection flapping.
    * **Incorrect Server Configuration:**  Servers might not be configured to handle connection migration correctly.

8. **Constructing the Debugging Scenario:** I outlined the steps a developer might take to reach this code:  starting with a network issue, examining connection state, and potentially stepping into the QUIC implementation.

9. **Summarizing the Functionality (Part 4 of 24):** I synthesized the identified functionalities into a concise summary, emphasizing that this part focuses on testing connection migration and related robustness mechanisms.

10. **Review and Refinement:** I reviewed my answer to ensure it was clear, accurate, and addressed all aspects of the user's request. I made sure to connect the low-level C++ details to higher-level concepts like user experience and JavaScript APIs where applicable.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 文件的这个代码片段的功能。

**代码片段功能归纳**

这个代码片段主要集中在测试 `QuicConnection` 类在以下几种与连接迁移和路径验证相关的场景下的行为：

* **服务器端反向路径验证失败 (Reverse Path Validation Failure at Server):**  测试当服务器检测到客户端 IP 地址发生变化时，启动反向路径验证，如果验证失败，服务器会回滚到之前的连接状态。
* **服务器端接收到相同地址的路径探测 (Receive Path Probe With No Address Change at Server):** 测试服务器接收到来自相同 IP 地址的路径探测包 (PATH_CHALLENGE 或填充的 PING 包) 时的处理逻辑。
* **处理 MTU 过大的缓冲包 (Buffered Mtu Packet Too Big):** 测试当连接处于写入阻塞状态时，如果尝试发送一个 MTU 探测包，该包是否会被正确缓冲，并在稍后写入。
* **乱序写入队列中的包 (Write OutOfOrder Queued Packets):**  测试在某些特定情况下（例如，写入被阻塞），如果尝试发送探测包，是否会产生不期望的行为。
* **连接关闭后丢弃队列中的包 (Discard Queued Packets After Connection Close):** 测试当连接关闭时，是否会正确丢弃尚未发送的队列中的数据包。
* **服务器端接收到来自新地址的路径探测 (Receive Path Probing From New Peer Address At Server):** 测试服务器接收到来自新的客户端 IP 地址的路径探测包时的处理逻辑，以及如何启动路径验证。
* **服务器端接收到发往首选地址的路径探测 (Receive Path Probing To Preferred Address At Server):** 测试服务器接收到发往其首选地址的路径探测包时的处理逻辑。
* **服务器端接收到端口变化的填充 PING 包 (Receive Padded Ping With Port Change At Server):** 测试服务器接收到来自新的客户端端口的填充 PING 包时的处理逻辑，以及是否触发连接迁移。
* **服务器端接收到乱序的路径探测 (Receive Reordered Path Probing At Server):** 测试服务器接收到乱序的路径探测包时的处理逻辑。
* **服务器端在探测后迁移 (Migrate After Probing At Server):** 测试服务器在接收到来自新地址的探测包后，如果后续收到非探测包，是否会触发连接迁移。
* **客户端接收到连接性探测包 (Receive Connectivity Probing Packet At Client):** 测试客户端接收到服务器发送的连接性探测包（例如，填充的 PING 包）时的处理逻辑。
* **客户端接收到连接性探测响应 (Receive Connectivity Probing Response At Client):** 测试客户端接收到来自不同自身地址的连接性探测包时的处理逻辑。
* **客户端的对端地址变化 (Peer Address Change At Client):**  这是代码片段的结尾，预示着后续的测试将关注客户端检测到服务器 IP 地址变化时的行为。

**与 JavaScript 的关系**

虽然这段 C++ 代码本身不直接包含 JavaScript 代码，但它测试的网络协议 QUIC 是 Web 技术的重要组成部分，与 JavaScript 的功能有间接但重要的关系：

* **`fetch()` API:**  当 JavaScript 代码使用 `fetch()` API 发起网络请求时，如果浏览器和服务器支持 HTTP/3，那么底层很可能使用 QUIC 协议。这段代码测试的连接迁移功能，可以保证在网络环境变化时，`fetch()` 请求仍然能够保持连接，提高用户体验，避免请求中断。
    * **举例说明:**  假设一个用户在一个移动设备上浏览网页，JavaScript 代码通过 `fetch()` 定期从服务器拉取数据。当用户从 Wi-Fi 网络切换到移动数据网络时，设备的 IP 地址可能会发生变化。这段代码测试的服务器端反向路径验证机制，可以确保服务器能够验证客户端的新地址，从而维持连接，让 `fetch()` 请求能够继续正常工作，而不会因为网络切换导致连接中断。

* **WebSockets:**  QUIC 也可以作为 WebSockets 的底层传输协议。这段代码测试的连接迁移功能，同样可以提高 WebSocket 连接的稳定性和可靠性，即使在网络环境变化的情况下，也能尽量保持连接不断开，提供更好的实时通信体验。
    * **举例说明:** 一个在线多人游戏使用 WebSocket 进行实时通信。当玩家的网络环境发生变化时（例如，从家庭 Wi-Fi 切换到移动热点），这段代码测试的连接迁移机制有助于维持 WebSocket 连接，避免游戏中断或延迟增加。

**逻辑推理 (假设输入与输出)**

**场景：服务器端反向路径验证失败 (Reverse Path Validation Failure at Server)**

* **假设输入:**
    1. 服务器与客户端建立连接，客户端 IP 地址为 `kPeerAddress`。
    2. 服务器检测到来自客户端的新 IP 地址 `kPeerAddress3` 的数据包。
    3. 服务器启动反向路径验证，向 `kPeerAddress3` 发送 `PATH_CHALLENGE`。
    4. 客户端发送的 `PATH_RESPONSE` 验证失败（例如，内容不匹配）。
* **预期输出:**
    1. `visitor_.OnConnectionMigration(IPV4_TO_IPV6_CHANGE)` 被调用 (假设是 IPv4 到 IPv6 的变化)。
    2. 连接状态回滚到使用原始的客户端 IP 地址 `kPeerAddress`。
    3. 与新 IP 地址 `kPeerAddress3` 相关的路径信息被清除。

**用户或编程常见的使用错误**

* **客户端网络配置错误:**  如果客户端的网络配置不正确，例如防火墙阻止了对新 IP 地址的响应，可能导致服务器端反向路径验证失败，连接回滚，影响用户体验。
    * **例子:** 用户在一个受限的网络环境中，该网络阻止了某些出站连接，导致客户端无法响应服务器发送的 `PATH_CHALLENGE`。

* **服务器端网络配置错误:**  如果服务器端的网络配置不正确，例如负载均衡器没有正确处理连接迁移，可能导致服务器无法正确识别客户端的新地址，或者无法将数据包正确路由到客户端的新地址。
    * **例子:**  服务器部署在一个有多层 NAT 的环境中，配置不当导致服务器无法正确感知客户端的真实 IP 地址变化。

* **应用程序逻辑错误:**  在某些场景下，应用程序可能没有正确处理连接迁移事件，导致状态不一致或者数据丢失。
    * **例子:**  一个实时通信应用在连接迁移后，没有正确更新内部的连接状态，导致后续的消息发送到旧的连接路径，从而失败。

**用户操作如何一步步到达这里 (调试线索)**

假设一个用户在使用一个基于 QUIC 的 Web 应用，并且遇到了连接不稳定的问题：

1. **用户网络环境变化:** 用户从一个 Wi-Fi 网络移动到另一个 Wi-Fi 网络，或者从 Wi-Fi 切换到移动数据网络，导致设备的 IP 地址或端口发生变化。

2. **QUIC 连接尝试迁移:** 底层的 QUIC 连接检测到网络地址的变化，并尝试迁移到新的网络路径。

3. **调试关注点:**  如果迁移过程出现问题，开发人员可能会关注以下几个方面，而这些正是这段测试代码所覆盖的：
    * **服务器是否正确检测到客户端地址变化？**  相关的测试是 `ReversePathValidationFailureAtServer` 和 `Receive Path Probing From New Peer Address At Server`。
    * **服务器的反向路径验证是否正常工作？**  测试 `ReversePathValidationFailureAtServer` 可以帮助排查这类问题。
    * **客户端是否能够正确响应服务器的路径探测？**  如果客户端的网络配置有问题，可能会导致验证失败。
    * **连接迁移后，数据包的发送和接收是否正常？**  其他的测试用例，例如测试 MTU 处理、乱序包处理等，都有助于验证连接迁移后的数据传输质量。

4. **查看 QUIC 连接状态和日志:** 开发人员可能会使用 Chromium 提供的网络调试工具（例如 `chrome://net-internals/#quic`）来查看 QUIC 连接的详细状态，包括连接迁移事件、路径验证结果等。

5. **分析网络抓包:**  使用 Wireshark 等工具抓取网络包，可以详细分析 QUIC 连接建立、迁移和数据传输的过程，帮助定位问题。

**这是第 4 部分，共 24 部分，请归纳一下它的功能**

考虑到这是测试文件的第 4 部分，并且之前的代码片段主要关注服务器端的连接迁移和路径验证，我们可以推断这部分的功能主要是 **测试 `QuicConnection` 类在服务器端处理连接迁移和路径验证相关的各种复杂场景，确保其在网络环境变化时能够保持连接的稳定性和可靠性。**  这包括成功迁移的场景，也包括迁移失败需要回滚的场景，以及各种边缘情况下的处理。

希望以上分析能够帮助你理解这段代码的功能。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
ame = InitAckFrame(1);
    EXPECT_CALL(visitor_, OnConnectionMigration(IPV4_TO_IPV6_CHANGE)).Times(1);
    EXPECT_CALL(visitor_, MaybeSendAddressToken()).WillOnce(Invoke([this]() {
      connection_.SendControlFrame(
          QuicFrame(new QuicNewTokenFrame(1, "new_token")));
      return true;
    }));
    ProcessFramesPacketWithAddresses(
        {QuicFrame(QuicPathResponseFrame(0, reverse_path_challenge_payload)),
         QuicFrame(&ack_frame)},
        kSelfAddress, kPeerAddress3, ENCRYPTION_FORWARD_SECURE);
  }
}

TEST_P(QuicConnectionTest, ReversePathValidationFailureAtServer) {
  set_perspective(Perspective::IS_SERVER);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());
  SetClientConnectionId(TestConnectionId(1));
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  // Prevent packets from being coalesced.
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  QuicConnectionPeer::SetAddressValidated(&connection_);

  QuicConnectionId client_cid0 = connection_.client_connection_id();
  QuicConnectionId client_cid1 = TestConnectionId(2);
  QuicConnectionId server_cid0 = connection_.connection_id();
  QuicConnectionId server_cid1;
  // Sends new server CID to client.
  if (!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
        .WillOnce(Return(TestConnectionId(456)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_))
      .WillOnce(Invoke([&](const QuicConnectionId& cid) {
        server_cid1 = cid;
        return true;
      }));
  EXPECT_CALL(visitor_, SendNewConnectionId(_));
  connection_.OnHandshakeComplete();
  // Receives new client CID from client.
  QuicNewConnectionIdFrame new_cid_frame;
  new_cid_frame.connection_id = client_cid1;
  new_cid_frame.sequence_number = 1u;
  new_cid_frame.retire_prior_to = 0u;
  connection_.OnNewConnectionIdFrame(new_cid_frame);
  auto* packet_creator = QuicConnectionPeer::GetPacketCreator(&connection_);
  ASSERT_EQ(packet_creator->GetDestinationConnectionId(), client_cid0);
  ASSERT_EQ(packet_creator->GetSourceConnectionId(), server_cid0);

  // Clear direct_peer_address.
  QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
  // Clear effective_peer_address, it is the same as direct_peer_address for
  // this test.
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                              QuicSocketAddress());
  EXPECT_FALSE(connection_.effective_peer_address().IsInitialized());

  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback4(), /*port=*/23456);
  EXPECT_CALL(visitor_, OnStreamFrame(_))
      .WillOnce(Invoke(
          [=, this]() { EXPECT_EQ(kPeerAddress, connection_.peer_address()); }))
      .WillOnce(Invoke([=, this]() {
        EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
      }));
  QuicFrames frames;
  frames.push_back(QuicFrame(frame1_));
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());

  // Process another packet with a different peer address on server side will
  // start connection migration.
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE)).Times(1);
  // IETF QUIC send algorithm should be changed to a different object, so no
  // OnPacketSent() called on the old send algorithm.
  EXPECT_CALL(*send_algorithm_, OnConnectionMigration()).Times(0);

  QuicFrames frames2;
  frames2.push_back(QuicFrame(frame2_));
  QuicPaddingFrame padding;
  frames2.push_back(QuicFrame(padding));
  peer_creator_.SetServerConnectionId(server_cid1);
  ProcessFramesPacketWithAddresses(frames2, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            connection_.active_effective_peer_migration_type());
  EXPECT_LT(0u, writer_->packets_write_attempts());
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_NE(connection_.sent_packet_manager().GetSendAlgorithm(),
            send_algorithm_);
  EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  const auto* default_path = QuicConnectionPeer::GetDefaultPath(&connection_);
  const auto* alternative_path =
      QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_EQ(default_path->client_connection_id, client_cid1);
  EXPECT_EQ(default_path->server_connection_id, server_cid1);
  EXPECT_EQ(alternative_path->client_connection_id, client_cid0);
  EXPECT_EQ(alternative_path->server_connection_id, server_cid0);
  EXPECT_EQ(packet_creator->GetDestinationConnectionId(), client_cid1);
  EXPECT_EQ(packet_creator->GetSourceConnectionId(), server_cid1);

  for (size_t i = 0; i < QuicPathValidator::kMaxRetryTimes; ++i) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
    static_cast<TestAlarmFactory::TestAlarm*>(
        QuicPathValidatorPeer::retry_timer(
            QuicConnectionPeer::path_validator(&connection_)))
        ->Fire();
  }
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            connection_.active_effective_peer_migration_type());

  // Make sure anti-amplification limit is not reached.
  ProcessFramesPacketWithAddresses(
      {QuicFrame(QuicPingFrame()), QuicFrame(QuicPaddingFrame())}, kSelfAddress,
      kNewPeerAddress, ENCRYPTION_FORWARD_SECURE);
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, nullptr);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Advance the time so that the reverse path validation times out.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
  static_cast<TestAlarmFactory::TestAlarm*>(
      QuicPathValidatorPeer::retry_timer(
          QuicConnectionPeer::path_validator(&connection_)))
      ->Fire();
  EXPECT_EQ(NO_CHANGE, connection_.active_effective_peer_migration_type());
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(connection_.sent_packet_manager().GetSendAlgorithm(),
            send_algorithm_);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Verify that default_path_ is reverted and alternative_path_ is cleared.
  EXPECT_EQ(default_path->client_connection_id, client_cid0);
  EXPECT_EQ(default_path->server_connection_id, server_cid0);
  EXPECT_TRUE(alternative_path->server_connection_id.IsEmpty());
  EXPECT_FALSE(alternative_path->stateless_reset_token.has_value());
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/1u));
  retire_peer_issued_cid_alarm->Fire();
  EXPECT_EQ(packet_creator->GetDestinationConnectionId(), client_cid0);
  EXPECT_EQ(packet_creator->GetSourceConnectionId(), server_cid0);
}

TEST_P(QuicConnectionTest, ReceivePathProbeWithNoAddressChangeAtServer) {
  if (!version().HasIetfQuicFrames() &&
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);

  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
  EXPECT_CALL(visitor_, OnPacketReceived(_, _, false)).Times(0);

  // Process a padded PING packet with no peer address change on server side
  // will be ignored. But a PATH CHALLENGE packet with no peer address change
  // will be considered as path probing.
  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();

  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));

  uint64_t num_probing_received =
      connection_.GetStats().num_connectivity_probing_received;
  ProcessReceivedPacket(kSelfAddress, kPeerAddress, *received);

  EXPECT_EQ(
      num_probing_received + (GetParam().version.HasIetfQuicFrames() ? 1u : 0u),
      connection_.GetStats().num_connectivity_probing_received);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
}

// Regression test for b/150161358.
TEST_P(QuicConnectionTest, BufferedMtuPacketTooBig) {
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(1);
  writer_->SetWriteBlocked();

  // Send a MTU packet while blocked. It should be buffered.
  connection_.SendMtuDiscoveryPacket(kMaxOutgoingPacketSize);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
  EXPECT_TRUE(writer_->IsWriteBlocked());

  writer_->AlwaysGetPacketTooLarge();
  writer_->SetWritable();
  connection_.OnCanWrite();
}

TEST_P(QuicConnectionTest, WriteOutOfOrderQueuedPackets) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration()) {
    return;
  }

  set_perspective(Perspective::IS_CLIENT);

  BlockOnNextWrite();

  QuicStreamId stream_id = 2;
  connection_.SendStreamDataWithString(stream_id, "foo", 0, NO_FIN);

  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  writer_->SetWritable();
  connection_.SendConnectivityProbingPacket(writer_.get(),
                                            connection_.peer_address());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(0);
  connection_.OnCanWrite();
}

TEST_P(QuicConnectionTest, DiscardQueuedPacketsAfterConnectionClose) {
  // Regression test for b/74073386.
  {
    InSequence seq;
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AtLeast(1));
    EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(AtLeast(1));
  }

  set_perspective(Perspective::IS_CLIENT);

  writer_->SimulateNextPacketTooLarge();

  // This packet write should fail, which should cause the connection to close
  // after sending a connection close packet, then the failed packet should be
  // queued.
  connection_.SendStreamDataWithString(/*id=*/2, "foo", 0, NO_FIN);

  EXPECT_FALSE(connection_.connected());
  // No need to buffer packets.
  EXPECT_EQ(0u, connection_.NumQueuedPackets());

  EXPECT_EQ(0u, connection_.GetStats().packets_discarded);
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.GetStats().packets_discarded);
}

class TestQuicPathValidationContext : public QuicPathValidationContext {
 public:
  TestQuicPathValidationContext(const QuicSocketAddress& self_address,
                                const QuicSocketAddress& peer_address,

                                QuicPacketWriter* writer)
      : QuicPathValidationContext(self_address, peer_address),
        writer_(writer) {}

  QuicPacketWriter* WriterToUse() override { return writer_; }

 private:
  QuicPacketWriter* writer_;
};

class TestValidationResultDelegate : public QuicPathValidator::ResultDelegate {
 public:
  TestValidationResultDelegate(QuicConnection* connection,
                               const QuicSocketAddress& expected_self_address,
                               const QuicSocketAddress& expected_peer_address,
                               bool* success)
      : QuicPathValidator::ResultDelegate(),
        connection_(connection),
        expected_self_address_(expected_self_address),
        expected_peer_address_(expected_peer_address),
        success_(success) {}
  void OnPathValidationSuccess(
      std::unique_ptr<QuicPathValidationContext> context,
      QuicTime /*start_time*/) override {
    EXPECT_EQ(expected_self_address_, context->self_address());
    EXPECT_EQ(expected_peer_address_, context->peer_address());
    *success_ = true;
  }

  void OnPathValidationFailure(
      std::unique_ptr<QuicPathValidationContext> context) override {
    EXPECT_EQ(expected_self_address_, context->self_address());
    EXPECT_EQ(expected_peer_address_, context->peer_address());
    if (connection_->perspective() == Perspective::IS_CLIENT) {
      connection_->OnPathValidationFailureAtClient(/*is_multi_port=*/false,
                                                   *context);
    }
    *success_ = false;
  }

 private:
  QuicConnection* connection_;
  QuicSocketAddress expected_self_address_;
  QuicSocketAddress expected_peer_address_;
  bool* success_;
};

// A test implementation which migrates to server preferred address
// on path validation suceeds. Otherwise, client cleans up alternative path.
class ServerPreferredAddressTestResultDelegate
    : public QuicPathValidator::ResultDelegate {
 public:
  explicit ServerPreferredAddressTestResultDelegate(QuicConnection* connection)
      : connection_(connection) {}
  void OnPathValidationSuccess(
      std::unique_ptr<QuicPathValidationContext> context,
      QuicTime /*start_time*/) override {
    connection_->OnServerPreferredAddressValidated(*context, false);
  }

  void OnPathValidationFailure(
      std::unique_ptr<QuicPathValidationContext> context) override {
    connection_->OnPathValidationFailureAtClient(/*is_multi_port=*/false,
                                                 *context);
  }

 protected:
  QuicConnection* connection() { return connection_; }

 private:
  QuicConnection* connection_;
};

// Receive a path probe request at the server side, in IETF version: receive a
// packet contains PATH CHALLENGE with peer address change.
TEST_P(QuicConnectionTest, ReceivePathProbingFromNewPeerAddressAtServer) {
  if (!version().HasIetfQuicFrames() &&
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);

  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
  QuicPathFrameBuffer payload;
  if (!GetParam().version.HasIetfQuicFrames()) {
    EXPECT_CALL(visitor_,
                OnPacketReceived(_, _, /*is_connectivity_probe=*/true))
        .Times(1);
  } else {
    EXPECT_CALL(visitor_, OnPacketReceived(_, _, _)).Times(0);
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AtLeast(1u))
        .WillOnce(Invoke([&]() {
          EXPECT_EQ(1u, writer_->path_challenge_frames().size());
          EXPECT_EQ(1u, writer_->path_response_frames().size());
          payload = writer_->path_challenge_frames().front().data_buffer;
        }))
        .WillRepeatedly(DoDefault());
  }
  // Process a probing packet from a new peer address on server side
  // is effectively receiving a connectivity probing.
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback4(),
                                          /*port=*/23456);

  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();
  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));
  uint64_t num_probing_received =
      connection_.GetStats().num_connectivity_probing_received;
  ProcessReceivedPacket(kSelfAddress, kNewPeerAddress, *received);

  EXPECT_EQ(num_probing_received + 1,
            connection_.GetStats().num_connectivity_probing_received);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
  if (GetParam().version.HasIetfQuicFrames()) {
    QuicByteCount bytes_sent =
        QuicConnectionPeer::BytesSentOnAlternativePath(&connection_);
    EXPECT_LT(0u, bytes_sent);
    EXPECT_EQ(received->length(),
              QuicConnectionPeer::BytesReceivedOnAlternativePath(&connection_));

    // Receiving one more probing packet should update the bytes count.
    probing_packet = ConstructProbingPacket();
    received.reset(ConstructReceivedPacket(
        QuicEncryptedPacket(probing_packet->encrypted_buffer,
                            probing_packet->encrypted_length),
        clock_.Now()));
    ProcessReceivedPacket(kSelfAddress, kNewPeerAddress, *received);

    EXPECT_EQ(num_probing_received + 2,
              connection_.GetStats().num_connectivity_probing_received);
    EXPECT_EQ(2 * bytes_sent,
              QuicConnectionPeer::BytesSentOnAlternativePath(&connection_));
    EXPECT_EQ(2 * received->length(),
              QuicConnectionPeer::BytesReceivedOnAlternativePath(&connection_));

    EXPECT_EQ(2 * bytes_sent,
              QuicConnectionPeer::BytesSentOnAlternativePath(&connection_));
    QuicFrames frames;
    frames.push_back(QuicFrame(QuicPathResponseFrame(99, payload)));
    ProcessFramesPacketWithAddresses(frames, connection_.self_address(),
                                     kNewPeerAddress,
                                     ENCRYPTION_FORWARD_SECURE);
    EXPECT_LT(2 * received->length(),
              QuicConnectionPeer::BytesReceivedOnAlternativePath(&connection_));
    EXPECT_TRUE(QuicConnectionPeer::IsAlternativePathValidated(&connection_));
    // Receiving another probing packet from a newer address with a different
    // port shouldn't trigger another reverse path validation.
    QuicSocketAddress kNewerPeerAddress(QuicIpAddress::Loopback4(),
                                        /*port=*/34567);
    probing_packet = ConstructProbingPacket();
    received.reset(ConstructReceivedPacket(
        QuicEncryptedPacket(probing_packet->encrypted_buffer,
                            probing_packet->encrypted_length),
        clock_.Now()));
    ProcessReceivedPacket(kSelfAddress, kNewerPeerAddress, *received);
    EXPECT_FALSE(connection_.HasPendingPathValidation());
    EXPECT_TRUE(QuicConnectionPeer::IsAlternativePathValidated(&connection_));
  }

  // Process another packet with the old peer address on server side will not
  // start peer migration.
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
}

// Receive a packet contains PATH CHALLENGE with self address change.
TEST_P(QuicConnectionTest, ReceivePathProbingToPreferredAddressAtServer) {
  if (!GetParam().version.HasIetfQuicFrames()) {
    return;
  }
  ServerHandlePreferredAddressInit();

  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
  EXPECT_CALL(visitor_, OnPacketReceived(_, _, _)).Times(0);

  // Process a probing packet to the server preferred address.
  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();
  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));
  uint64_t num_probing_received =
      connection_.GetStats().num_connectivity_probing_received;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, writer_->path_response_frames().size());
        // Verify that the PATH_RESPONSE is sent from the original self address.
        EXPECT_EQ(kSelfAddress.host(), writer_->last_write_source_address());
        EXPECT_EQ(kPeerAddress, writer_->last_write_peer_address());
      }));
  ProcessReceivedPacket(kServerPreferredAddress, kPeerAddress, *received);

  EXPECT_EQ(num_probing_received + 1,
            connection_.GetStats().num_connectivity_probing_received);
  EXPECT_FALSE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kServerPreferredAddress, kPeerAddress));
  EXPECT_NE(kServerPreferredAddress, connection_.self_address());

  // Receiving another probing packet from a new client address.
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback4(),
                                          /*port=*/34567);
  probing_packet = ConstructProbingPacket();
  received.reset(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, writer_->path_response_frames().size());
        EXPECT_EQ(1u, writer_->path_challenge_frames().size());
        EXPECT_EQ(kServerPreferredAddress.host(),
                  writer_->last_write_source_address());
        // The responses should be sent from preferred address given server
        // has not received packet on original address from the new client
        // address.
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
      }));
  ProcessReceivedPacket(kServerPreferredAddress, kNewPeerAddress, *received);

  EXPECT_EQ(num_probing_received + 2,
            connection_.GetStats().num_connectivity_probing_received);
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(&connection_, kSelfAddress,
                                                    kNewPeerAddress));
  EXPECT_LT(0u, QuicConnectionPeer::BytesSentOnAlternativePath(&connection_));
  EXPECT_EQ(received->length(),
            QuicConnectionPeer::BytesReceivedOnAlternativePath(&connection_));
}

// Receive a padded PING packet with a port change on server side.
TEST_P(QuicConnectionTest, ReceivePaddedPingWithPortChangeAtServer) {
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());
  if (version().SupportsAntiAmplificationLimit()) {
    QuicConnectionPeer::SetAddressValidated(&connection_);
  }

  // Clear direct_peer_address.
  QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
  // Clear effective_peer_address, it is the same as direct_peer_address for
  // this test.
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                              QuicSocketAddress());
  EXPECT_FALSE(connection_.effective_peer_address().IsInitialized());

  if (GetParam().version.UsesCryptoFrames()) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  }
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());

  if (GetParam().version.HasIetfQuicFrames() ||
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    // In IETF version, a padded PING packet with port change is not taken as
    // connectivity probe.
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
    EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(1);
    EXPECT_CALL(visitor_, OnPacketReceived(_, _, _)).Times(0);
  } else {
    // In non-IETF version, process a padded PING packet from a new peer
    // address on server side is effectively receiving a connectivity probing.
    EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
    EXPECT_CALL(visitor_,
                OnPacketReceived(_, _, /*is_connectivity_probe=*/true))
        .Times(1);
  }
  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);

  QuicFrames frames;
  // Write a PING frame, which has no data payload.
  QuicPingFrame ping_frame;
  frames.push_back(QuicFrame(ping_frame));

  // Add padding to the rest of the packet.
  QuicPaddingFrame padding_frame;
  frames.push_back(QuicFrame(padding_frame));

  uint64_t num_probing_received =
      connection_.GetStats().num_connectivity_probing_received;

  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_INITIAL);

  if (GetParam().version.HasIetfQuicFrames() ||
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    // Padded PING with port changen is not considered as connectivity probe but
    // a PORT CHANGE.
    EXPECT_EQ(num_probing_received,
              connection_.GetStats().num_connectivity_probing_received);
    EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
    EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  } else {
    EXPECT_EQ(num_probing_received + 1,
              connection_.GetStats().num_connectivity_probing_received);
    EXPECT_EQ(kPeerAddress, connection_.peer_address());
    EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
  }

  if (GetParam().version.HasIetfQuicFrames() ||
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(1);
  }
  // Process another packet with the old peer address on server side.
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
}

TEST_P(QuicConnectionTest, ReceiveReorderedPathProbingAtServer) {
  if (!GetParam().version.HasIetfQuicFrames() &&
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);

  // Decrease packet number to simulate out-of-order packets.
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 4);

  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
  if (!GetParam().version.HasIetfQuicFrames()) {
    EXPECT_CALL(visitor_,
                OnPacketReceived(_, _, /*is_connectivity_probe=*/true))
        .Times(1);
  } else {
    EXPECT_CALL(visitor_, OnPacketReceived(_, _, _)).Times(0);
  }

  // Process a padded PING packet from a new peer address on server side
  // is effectively receiving a connectivity probing, even if a newer packet has
  // been received before this one.
  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);

  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();
  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));

  uint64_t num_probing_received =
      connection_.GetStats().num_connectivity_probing_received;
  ProcessReceivedPacket(kSelfAddress, kNewPeerAddress, *received);

  EXPECT_EQ(num_probing_received +
                (!version().HasIetfQuicFrames() &&
                         GetQuicReloadableFlag(quic_ignore_gquic_probing)
                     ? 0u
                     : 1u),
            connection_.GetStats().num_connectivity_probing_received);
  EXPECT_EQ((!version().HasIetfQuicFrames() &&
                     GetQuicReloadableFlag(quic_ignore_gquic_probing)
                 ? kNewPeerAddress
                 : kPeerAddress),
            connection_.peer_address());
  EXPECT_EQ((!version().HasIetfQuicFrames() &&
                     GetQuicReloadableFlag(quic_ignore_gquic_probing)
                 ? kNewPeerAddress
                 : kPeerAddress),
            connection_.effective_peer_address());
}

TEST_P(QuicConnectionTest, MigrateAfterProbingAtServer) {
  if (!GetParam().version.HasIetfQuicFrames() &&
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);

  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
  if (!GetParam().version.HasIetfQuicFrames()) {
    EXPECT_CALL(visitor_,
                OnPacketReceived(_, _, /*is_connectivity_probe=*/true))
        .Times(1);
  } else {
    EXPECT_CALL(visitor_, OnPacketReceived(_, _, _)).Times(0);
  }

  // Process a padded PING packet from a new peer address on server side
  // is effectively receiving a connectivity probing.
  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);

  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();
  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));
  ProcessReceivedPacket(kSelfAddress, kNewPeerAddress, *received);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());

  // Process another non-probing packet with the new peer address on server
  // side will start peer migration.
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(1);

  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                  kNewPeerAddress, ENCRYPTION_INITIAL);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
}

TEST_P(QuicConnectionTest, ReceiveConnectivityProbingPacketAtClient) {
  if (!version().HasIetfQuicFrames() &&
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  PathProbeTestInit(Perspective::IS_CLIENT);

  // Client takes all padded PING packet as speculative connectivity
  // probing packet, and reports to visitor.
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);

  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();
  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));
  uint64_t num_probing_received =
      connection_.GetStats().num_connectivity_probing_received;
  ProcessReceivedPacket(kSelfAddress, kPeerAddress, *received);

  EXPECT_EQ(
      num_probing_received + (GetParam().version.HasIetfQuicFrames() ? 1u : 0u),
      connection_.GetStats().num_connectivity_probing_received);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
}

TEST_P(QuicConnectionTest, ReceiveConnectivityProbingResponseAtClient) {
  if (GetParam().version.HasIetfQuicFrames() ||
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  PathProbeTestInit(Perspective::IS_CLIENT);

  // Process a padded PING packet with a different self address on client side
  // is effectively receiving a connectivity probing.
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
  if (!GetParam().version.HasIetfQuicFrames()) {
    EXPECT_CALL(visitor_,
                OnPacketReceived(_, _, /*is_connectivity_probe=*/true))
        .Times(1);
  } else {
    EXPECT_CALL(visitor_, OnPacketReceived(_, _, _)).Times(0);
  }

  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);

  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();
  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));
  uint64_t num_probing_received =
      connection_.GetStats().num_connectivity_probing_received;
  ProcessReceivedPacket(kNewSelfAddress, kPeerAddress, *received);

  EXPECT_EQ(num_probing_received + 1,
            connection_.GetStats().num_connectivity_probing_received);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
}

TEST_P(QuicConnectionTest, PeerAddressChangeAtClient) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  set_perspective(Perspective::IS_CLIENT);
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());

  // Clear direct_peer_address.
  QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
  // Clear effective_peer_address, i
```
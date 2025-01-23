Response:
My thinking process to arrive at the summary of the `QuicConnectionTest.cc` file goes through these stages:

1. **Understanding the Context:** The initial prompt tells me this is a test file for the `QuicConnection` class in Chromium's QUIC implementation. The path `net/third_party/quiche/src/quiche/quic/core/` confirms this. Knowing it's a test file is crucial; its primary function is to verify the behavior of the `QuicConnection` class under various conditions.

2. **Analyzing the Code Snippet (Section 3):**  I carefully read the provided code snippet, paying attention to the test names, the actions being performed (e.g., `CloseConnection`, `ProcessFramePacketWithAddresses`), and the expectations (`EXPECT_CALL`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`). I identify key areas being tested in this section:

    * **Error Handling during Connection Closure:**  The first test in the snippet focuses on what happens when a connection closure attempt fails due to packet size limits.
    * **Error Code Mapping:** Two tests (`CloseErrorCodeTestTransport` and `CloseErrorCodeTestApplication`) specifically check how different QUIC error codes are mapped to transport-level and application-level connection closures.
    * **Address Changes:**  A significant portion of the snippet deals with how the `QuicConnection` handles changes in both the local (self) and remote (peer) IP addresses and ports. This includes scenarios for both clients and servers.
    * **Connection Migration:** The tests explore different types of connection migration (port change, IP address change), how it's initiated, and its consequences, particularly on servers.
    * **Path Validation:**  Several tests touch on the mechanism of path validation, which is used to confirm the reachability of a new network path during migration.
    * **Handling Out-of-Order Packets during Migration:** One test specifically looks at how the connection behaves when older packets arrive after a migration.
    * **Interaction with Send Algorithm:**  Some tests show how connection migration can trigger changes in the congestion control algorithm.
    * **Handling Missing Connection IDs:** One test examines the case where a server needs to perform a migration but is missing the client's connection ID.
    * **Effective Peer Address:** Several tests differentiate between the direct peer address and the effective peer address, investigating scenarios where these differ and how migrations are handled.
    * **Pending Padding during Migration:**  One test addresses a specific regression scenario where connection migration interacts with pending padding bytes in packets.
    * **Unexpected Reverse Path Validation Responses:**  A test checks how the connection reacts to reverse path validation responses coming from unexpected sources.

3. **Identifying Core Functionalities:** Based on the code analysis, I distill the core functionalities being tested:

    * **Connection Closure and Error Handling:** This is fundamental to any network connection.
    * **Connection Migration:** A key feature of QUIC to maintain connection continuity despite network changes.
    * **Address Management:**  Essential for correctly identifying and communicating with the peer.
    * **Path Validation:** A security and reliability mechanism during migration.

4. **Considering JavaScript Relevance (and Absence):** I specifically look for any mentions of JavaScript or browser APIs. In this snippet, there are none. QUIC is a transport layer protocol, and while it's used by web browsers (which use JavaScript), the core logic tested here is at a lower level. Therefore, I conclude there's no direct, demonstrable relationship with JavaScript functionality *within this specific code snippet*. It's important to distinguish between the implementation level and the usage level.

5. **Looking for Logical Reasoning (Hypothetical Inputs and Outputs):**  The tests themselves demonstrate logical reasoning. For each test, there's an implicit "if we do X (send this packet, trigger this event), then Y should happen (this callback should be invoked, this state should change)."  I can generalize some examples:

    * **Hypothetical Input:** A packet arrives from a new IP address for the peer.
    * **Output:**  The `OnConnectionMigration` callback should be triggered on the visitor.

    * **Hypothetical Input:** An attempt to close the connection fails because the packet is too large.
    * **Output:** The `saved_connection_close_frame_` member should be populated with the appropriate error code.

6. **Identifying Common User/Programming Errors:** I think about what mistakes developers or users might make that would lead to these test scenarios being relevant:

    * **Incorrect Error Code Handling:**  A developer might not correctly map or handle QUIC error codes.
    * **Network Configuration Issues:** Network changes or misconfigurations can trigger connection migrations, making the migration tests relevant.
    * **Incorrectly Assuming Stable Network Paths:** Developers might not anticipate or handle IP address or port changes.

7. **Considering Debugging Information:** I imagine a scenario where a QUIC connection is behaving unexpectedly. The tests provide clues for debugging:

    * If the connection is closing unexpectedly, the error code mapping tests help verify if the correct error code is being generated.
    * If migration isn't happening when it should, the address change and migration tests help pinpoint issues in address tracking or migration logic.

8. **Synthesizing the Summary:** Finally, I combine the information gathered to create a concise summary, focusing on the key functionalities tested in this section of the file. I emphasize the focus on connection closure, error handling, connection migration (including different scenarios and path validation), and address management. I also explicitly state the lack of direct JavaScript relation in this particular code. I highlight the logical reasoning inherent in the tests and provide examples of potential user/programming errors and debugging scenarios.

By following these steps, I can effectively understand the purpose and functionality of the given code snippet and generate a comprehensive and informative summary.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 文件的第 3 部分，它专注于测试 `QuicConnection` 类的各种功能，特别是与连接关闭、地址变更和连接迁移相关的行为。

**功能归纳:**

这部分代码主要测试了 `QuicConnection` 类在以下方面的功能：

1. **连接关闭和错误处理:**
   - 测试在发送连接关闭包时发生错误（例如，包太大无法发送）的情况，以及如何处理和报告这些错误。
   - 测试 QUIC 错误码到更通用的传输层和应用层连接关闭错误的映射是否正确。

2. **地址变更处理:**
   - 测试客户端和服务器端在连接存活期间自身 IP 地址发生变化时的处理。
   - 测试服务器端在接收到来自不同 IP 地址和端口的客户端数据包时，如何检测和处理对端地址的变更，包括端口变更和 IP 地址变更（IPv6 到 IPv4）。
   - 测试在地址变更期间收到乱序数据包的情况。
   - 测试当服务器预期看到有效对端地址但实际接收到的数据包缺少连接 ID 时的情况。

3. **连接迁移:**
   - 测试服务器端如何检测对端端口的变化并启动连接迁移。
   - 测试服务器端如何检测对端 IP 地址的变化并启动连接迁移，包括与黑洞检测和 5-RTO 机制的交互。
   - 测试“有效对端地址”的概念，即实际通信的对端地址可能与直接连接的对端地址不同，并测试在这种情况下连接迁移的行为。
   - 测试在连接迁移进行中，如果还有待发送的 padding 字节会发生什么。
   - 测试在反向路径验证期间，如果收到来自意外对端地址的响应会如何处理。

**与 JavaScript 功能的关系:**

`QuicConnection` 类本身是 C++ 代码，位于网络协议栈的底层，与 JavaScript 没有直接的代码级别的交互。然而，QUIC 协议是现代 Web 浏览器中用于 HTTP/3 的基础协议，因此它的功能间接地影响着 JavaScript 应用的性能和可靠性。

**举例说明:**

- **连接迁移和无缝切换网络:** 当用户从 Wi-Fi 切换到移动网络时，底层的 QUIC 连接可能会发生迁移，而 JavaScript 应用（例如，正在加载网页的脚本）通常不会感知到这个切换，连接可以保持活跃，下载可以继续，这得益于 QUIC 的连接迁移功能。 这部分测试确保了 `QuicConnection` 在处理地址变更时能正确迁移连接，避免连接中断。

**逻辑推理和假设输入与输出:**

**示例 1：测试连接关闭时发送失败**

- **假设输入:**
    - 一个 `QuicConnection` 对象处于连接状态。
    - 尝试调用 `CloseConnection` 方法，并且 `writer_` 模拟发送失败，返回“包太大”的错误。
- **输出:**
    - 如果启用了 `quic_avoid_nested_close_connection` flag，则 `saved_connection_close_frame_` 会记录下原始的关闭原因 (`QUIC_CRYPTO_TOO_MANY_ENTRIES`)。
    - 如果未启用该 flag，则会触发 `EXPECT_QUIC_BUG`，因为在尝试发送关闭包失败后，会尝试用新的错误码再次关闭连接。

**示例 2：测试服务器端对端端口变更**

- **假设输入:**
    - 一个作为服务器的 `QuicConnection` 对象处于连接状态。
    - 接收到一个来自新对端端口 (`kNewPeerAddress`) 的数据包。
- **输出:**
    - `visitor_->OnConnectionMigration(PORT_CHANGE)` 会被调用，表明发生了端口迁移。
    - `connection_.peer_address()` 和 `connection_.effective_peer_address()` 会更新为新的对端地址。

**用户或编程常见的使用错误:**

1. **错误地假设网络地址永远不变:** 开发者如果假设客户端或服务器的 IP 地址和端口在连接期间不会变化，可能会导致应用在网络环境变化时出现问题。QUIC 的连接迁移功能正是为了应对这种情况。

2. **在网络状态不稳定的情况下未进行重试或错误处理:**  虽然 QUIC 提供了连接迁移，但开发者仍然需要在应用层考虑网络不稳定性，并进行适当的重试或错误处理，例如，当迁移失败时。

**用户操作如何一步步到达这里 (调试线索):**

假设一个用户在使用 Chrome 浏览器浏览网页，并遇到了连接中断或网络切换导致的问题：

1. **用户网络环境变化:** 用户可能从一个 Wi-Fi 网络移动到另一个 Wi-Fi 网络，或者从 Wi-Fi 断开连接切换到移动数据网络。

2. **操作系统网络层通知:** 操作系统会检测到网络接口的变化，并通知应用程序。

3. **Chrome 网络栈处理:** Chrome 的网络栈（包括 QUIC 实现）会接收到这些网络变化的通知。

4. **`QuicConnection` 尝试处理地址变更:** 如果当前存在 QUIC 连接，`QuicConnection` 对象会尝试处理新的网络地址。这可能会涉及到发送新的数据包到新的地址，或者接收来自新地址的数据包。

5. **触发测试场景:** 在开发和测试阶段，工程师会编写像 `QuicConnectionTest` 这样的单元测试来模拟这些场景。例如，`PeerPortChangeAtServer` 测试模拟了服务器接收到来自不同端口的数据包的情况，这可能发生在客户端的网络地址发生变化时。

6. **调试信息:** 如果在实际运行中出现问题，开发者可能会查看 QUIC 连接的日志，例如连接迁移事件、错误码等，这些信息可以帮助他们定位问题是否与地址变更或连接迁移相关，并可能最终追踪到 `quic_connection_test.cc` 中相关的测试用例，以了解预期的行为和可能的错误原因。

总而言之，这部分 `QuicConnectionTest.cc` 主要关注 `QuicConnection` 在处理连接生命周期结束和网络地址变化时的稳定性和正确性，这对于保证基于 QUIC 的网络连接的可靠性和用户体验至关重要。它通过模拟各种网络场景和错误情况，验证了 `QuicConnection` 类的关键逻辑。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
osed(_, ConnectionCloseSource::FROM_SELF))
      .WillRepeatedly(
          Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  EXPECT_CALL(connection_, OnSerializedPacket(_)).Times(AnyNumber());

  // Prepare the writer to fail to send the first connection close packet due
  // to the packet being too large.
  writer_->SetShouldWriteFail();
  writer_->SetWriteError(*writer_->MessageTooBigErrorCode());

  if (GetQuicReloadableFlag(quic_avoid_nested_close_connection)) {
    connection_.CloseConnection(
        QUIC_CRYPTO_TOO_MANY_ENTRIES, "Closed by test",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
                IsError(QUIC_CRYPTO_TOO_MANY_ENTRIES));
  } else {
    EXPECT_QUIC_BUG(
        connection_.CloseConnection(
            QUIC_CRYPTO_TOO_MANY_ENTRIES, "Closed by test",
            ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET),
        // 30=QUIC_CRYPTO_TOO_MANY_ENTRIES, 27=QUIC_PACKET_WRITE_ERROR.
        "Initial error code: 30, new error code: 27");
  }
}

// These two tests ensure that the QuicErrorCode mapping works correctly.
// Both tests expect to see a Google QUIC close if not running IETF QUIC.
// If running IETF QUIC, the first will generate a transport connection
// close, the second an application connection close.
// The connection close codes for the two tests are manually chosen;
// they are expected to always map to transport- and application-
// closes, respectively. If that changes, new codes should be chosen.
TEST_P(QuicConnectionTest, CloseErrorCodeTestTransport) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  connection_.CloseConnection(
      IETF_QUIC_PROTOCOL_VIOLATION, "Should be transport close",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(IETF_QUIC_PROTOCOL_VIOLATION);
}

// Test that the IETF QUIC Error code mapping function works
// properly for application connection close codes.
TEST_P(QuicConnectionTest, CloseErrorCodeTestApplication) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  connection_.CloseConnection(
      QUIC_HEADERS_STREAM_DATA_DECOMPRESS_FAILURE,
      "Should be application close",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_HEADERS_STREAM_DATA_DECOMPRESS_FAILURE);
}

TEST_P(QuicConnectionTest, SelfAddressChangeAtClient) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());
  EXPECT_TRUE(connection_.connected());

  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_));
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_));
  }
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  // Cause change in self_address.
  QuicIpAddress host;
  host.FromString("1.1.1.1");
  QuicSocketAddress self_address(host, 123);
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_));
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_));
  }
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), self_address, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.connected());
  EXPECT_NE(connection_.self_address(), self_address);
}

TEST_P(QuicConnectionTest, SelfAddressChangeAtServer) {
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);

  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());
  EXPECT_TRUE(connection_.connected());

  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_));
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_));
  }
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  // Cause change in self_address.
  QuicIpAddress host;
  host.FromString("1.1.1.1");
  QuicSocketAddress self_address(host, 123);
  EXPECT_EQ(0u, connection_.GetStats().packets_dropped);
  EXPECT_CALL(visitor_, AllowSelfAddressChange()).WillOnce(Return(false));
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), self_address, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(1u, connection_.GetStats().packets_dropped);
}

TEST_P(QuicConnectionTest, AllowSelfAddressChangeToMappedIpv4AddressAtServer) {
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);

  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());
  EXPECT_TRUE(connection_.connected());

  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(3);
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(3);
  }
  QuicIpAddress host;
  host.FromString("1.1.1.1");
  QuicSocketAddress self_address1(host, 443);
  connection_.SetSelfAddress(self_address1);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), self_address1,
                                  kPeerAddress, ENCRYPTION_INITIAL);
  // Cause self_address change to mapped Ipv4 address.
  QuicIpAddress host2;
  host2.FromString(
      absl::StrCat("::ffff:", connection_.self_address().host().ToString()));
  QuicSocketAddress self_address2(host2, connection_.self_address().port());
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), self_address2,
                                  kPeerAddress, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.connected());
  // self_address change back to Ipv4 address.
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), self_address1,
                                  kPeerAddress, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.connected());
}

TEST_P(QuicConnectionTest, ClientAddressChangeAndPacketReordered) {
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));

  // Clear direct_peer_address.
  QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
  // Clear effective_peer_address, it is the same as direct_peer_address for
  // this test.
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                              QuicSocketAddress());

  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  }
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 5);
  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(),
                        /*port=*/23456);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                  kNewPeerAddress, ENCRYPTION_INITIAL);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());

  // Decrease packet number to simulate out-of-order packets.
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 4);
  // This is an old packet, do not migrate.
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
}

TEST_P(QuicConnectionTest, PeerPortChangeAtServer) {
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  // Prevent packets from being coalesced.
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
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

  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  QuicTime::Delta default_init_rtt = rtt_stats->initial_rtt();
  rtt_stats->set_initial_rtt(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt());

  QuicSentPacketManagerPeer::SetConsecutivePtoCount(manager_, 1);
  EXPECT_EQ(1u, manager_->GetConsecutivePtoCount());

  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
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
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(1);
  QuicFrames frames2;
  frames2.push_back(QuicFrame(frame2_));
  ProcessFramesPacketWithAddresses(frames2, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  // PORT_CHANGE shouldn't state change in sent packet manager.
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt());
  EXPECT_EQ(1u, manager_->GetConsecutivePtoCount());
  EXPECT_EQ(manager_->GetSendAlgorithm(), send_algorithm_);
  if (version().HasIetfQuicFrames()) {
    EXPECT_EQ(NO_CHANGE, connection_.active_effective_peer_migration_type());
    EXPECT_EQ(1u, connection_.GetStats().num_validated_peer_migration);
    EXPECT_EQ(1u, connection_.num_linkable_client_migration());
  }
}

TEST_P(QuicConnectionTest, PeerIpAddressChangeAtServer) {
  set_perspective(Perspective::IS_SERVER);
  if (!version().SupportsAntiAmplificationLimit() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  // Prevent packets from being coalesced.
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  QuicConnectionPeer::SetAddressValidated(&connection_);
  connection_.OnHandshakeComplete();

  // Enable 5 RTO
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k5RTO);
  config.SetInitialReceivedConnectionOptions(connection_options);
  QuicConfigPeer::SetNegotiated(&config, true);
  QuicConfigPeer::SetReceivedOriginalConnectionId(&config,
                                                  connection_.connection_id());
  QuicConfigPeer::SetReceivedInitialSourceConnectionId(&config,
                                                       QuicConnectionId());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);

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

  // Send some data to make connection has packets in flight.
  connection_.SendStreamData3();
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_TRUE(connection_.BlackholeDetectionInProgress());
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Process another packet with a different peer address on server side will
  // start connection migration.
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE)).Times(1);
  // IETF QUIC send algorithm should be changed to a different object, so no
  // OnPacketSent() called on the old send algorithm.
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, NO_RETRANSMITTABLE_DATA))
      .Times(0);
  // Do not propagate OnCanWrite() to session notifier.
  EXPECT_CALL(visitor_, OnCanWrite()).Times(AnyNumber());

  QuicFrames frames2;
  frames2.push_back(QuicFrame(frame2_));
  ProcessFramesPacketWithAddresses(frames2, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            connection_.active_effective_peer_migration_type());
  EXPECT_FALSE(connection_.BlackholeDetectionInProgress());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  EXPECT_EQ(2u, writer_->packets_write_attempts());
  EXPECT_FALSE(writer_->path_challenge_frames().empty());
  QuicPathFrameBuffer payload =
      writer_->path_challenge_frames().front().data_buffer;
  EXPECT_NE(connection_.sent_packet_manager().GetSendAlgorithm(),
            send_algorithm_);
  // Switch to use the mock send algorithm.
  send_algorithm_ = new StrictMock<MockSendAlgorithm>();
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(kDefaultTCPMSS));
  EXPECT_CALL(*send_algorithm_, OnApplicationLimited(_)).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, BandwidthEstimate())
      .Times(AnyNumber())
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, InSlowStart()).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, InRecovery()).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, PopulateConnectionStats(_)).Times(AnyNumber());
  connection_.SetSendAlgorithm(send_algorithm_);

  // PATH_CHALLENGE is expanded upto the max packet size which may exceeds the
  // anti-amplification limit.
  EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(1u,
            connection_.GetStats().num_reverse_path_validtion_upon_migration);

  // Verify server is throttled by anti-amplification limit.
  connection_.SendCryptoDataWithString("foo", 0);
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Receiving an ACK to the packet sent after changing peer address doesn't
  // finish migration validation.
  QuicAckFrame ack_frame = InitAckFrame(2);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  ProcessFramePacketWithAddresses(QuicFrame(&ack_frame), kSelfAddress,
                                  kNewPeerAddress, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            connection_.active_effective_peer_migration_type());

  // Receiving PATH_RESPONSE should lift the anti-amplification limit.
  QuicFrames frames3;
  frames3.push_back(QuicFrame(QuicPathResponseFrame(99, payload)));
  EXPECT_CALL(visitor_, MaybeSendAddressToken());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(testing::AtLeast(1u));
  ProcessFramesPacketWithAddresses(frames3, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(NO_CHANGE, connection_.active_effective_peer_migration_type());

  // Verify the anti-amplification limit is lifted by sending a packet larger
  // than the anti-amplification limit.
  connection_.SendCryptoDataWithString(std::string(1200, 'a'), 0);
  EXPECT_EQ(1u, connection_.GetStats().num_validated_peer_migration);
  EXPECT_EQ(1u, connection_.num_linkable_client_migration());
}

TEST_P(QuicConnectionTest, PeerIpAddressChangeAtServerWithMissingConnectionId) {
  set_perspective(Perspective::IS_SERVER);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());

  QuicConnectionId client_cid0 = TestConnectionId(1);
  QuicConnectionId client_cid1 = TestConnectionId(3);
  QuicConnectionId server_cid1;
  SetClientConnectionId(client_cid0);
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  // Prevent packets from being coalesced.
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  QuicConnectionPeer::SetAddressValidated(&connection_);

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

  // Clear direct_peer_address.
  QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
  // Clear effective_peer_address, it is the same as direct_peer_address for
  // this test.
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                              QuicSocketAddress());
  EXPECT_FALSE(connection_.effective_peer_address().IsInitialized());

  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback4(), /*port=*/23456);
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(2);
  QuicFrames frames;
  frames.push_back(QuicFrame(frame1_));
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());

  // Send some data to make connection has packets in flight.
  connection_.SendStreamData3();
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  // Process another packet with a different peer address on server side will
  // start connection migration.
  peer_creator_.SetServerConnectionId(server_cid1);
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE)).Times(1);
  // Do not propagate OnCanWrite() to session notifier.
  EXPECT_CALL(visitor_, OnCanWrite()).Times(AnyNumber());

  QuicFrames frames2;
  frames2.push_back(QuicFrame(frame2_));
  if (GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    frames2.push_back(QuicFrame(QuicPaddingFrame(-1)));
  }
  ProcessFramesPacketWithAddresses(frames2, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());

  // Writing path response & reverse path challenge is blocked due to missing
  // client connection ID, i.e., packets_write_attempts is unchanged.
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  // Receives new client CID from client would unblock write.
  QuicNewConnectionIdFrame new_cid_frame;
  new_cid_frame.connection_id = client_cid1;
  new_cid_frame.sequence_number = 1u;
  new_cid_frame.retire_prior_to = 0u;
  connection_.OnNewConnectionIdFrame(new_cid_frame);
  connection_.SendStreamData3();

  EXPECT_EQ(2u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, EffectivePeerAddressChangeAtServer) {
  if (GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());
  if (version().SupportsAntiAmplificationLimit()) {
    QuicConnectionPeer::SetAddressValidated(&connection_);
  }
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));

  // Clear direct_peer_address.
  QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
  // Clear effective_peer_address, it is different from direct_peer_address for
  // this test.
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                              QuicSocketAddress());
  const QuicSocketAddress kEffectivePeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/43210);
  connection_.ReturnEffectivePeerAddressForNextPacket(kEffectivePeerAddress);

  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  }
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kEffectivePeerAddress, connection_.effective_peer_address());

  // Process another packet with the same direct peer address and different
  // effective peer address on server side will start connection migration.
  const QuicSocketAddress kNewEffectivePeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/54321);
  connection_.ReturnEffectivePeerAddressForNextPacket(kNewEffectivePeerAddress);
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(1);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewEffectivePeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(kPeerAddress, writer_->last_write_peer_address());
  if (GetParam().version.HasIetfQuicFrames()) {
    EXPECT_EQ(NO_CHANGE, connection_.active_effective_peer_migration_type());
    EXPECT_EQ(1u, connection_.GetStats().num_validated_peer_migration);
    EXPECT_EQ(1u, connection_.num_linkable_client_migration());
  }

  // Process another packet with a different direct peer address and the same
  // effective peer address on server side will not start connection migration.
  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  connection_.ReturnEffectivePeerAddressForNextPacket(kNewEffectivePeerAddress);
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);

  if (!GetParam().version.HasIetfQuicFrames()) {
    // ack_frame is used to complete the migration started by the last packet,
    // we need to make sure a new migration does not start after the previous
    // one is completed.
    QuicAckFrame ack_frame = InitAckFrame(1);
    EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
    ProcessFramePacketWithAddresses(QuicFrame(&ack_frame), kSelfAddress,
                                    kNewPeerAddress, ENCRYPTION_FORWARD_SECURE);
    EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
    EXPECT_EQ(kNewEffectivePeerAddress, connection_.effective_peer_address());
    EXPECT_EQ(NO_CHANGE, connection_.active_effective_peer_migration_type());
  }

  // Process another packet with different direct peer address and different
  // effective peer address on server side will start connection migration.
  const QuicSocketAddress kNewerEffectivePeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/65432);
  const QuicSocketAddress kFinalPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/34567);
  connection_.ReturnEffectivePeerAddressForNextPacket(
      kNewerEffectivePeerAddress);
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(1);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                  kFinalPeerAddress, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kFinalPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewerEffectivePeerAddress, connection_.effective_peer_address());
  if (GetParam().version.HasIetfQuicFrames()) {
    EXPECT_EQ(NO_CHANGE, connection_.active_effective_peer_migration_type());
    EXPECT_EQ(send_algorithm_,
              connection_.sent_packet_manager().GetSendAlgorithm());
    EXPECT_EQ(2u, connection_.GetStats().num_validated_peer_migration);
  }

  // While the previous migration is ongoing, process another packet with the
  // same direct peer address and different effective peer address on server
  // side will start a new connection migration.
  const QuicSocketAddress kNewestEffectivePeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback4(), /*port=*/65430);
  connection_.ReturnEffectivePeerAddressForNextPacket(
      kNewestEffectivePeerAddress);
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE)).Times(1);
  if (!GetParam().version.HasIetfQuicFrames()) {
    EXPECT_CALL(*send_algorithm_, OnConnectionMigration()).Times(1);
  }
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                  kFinalPeerAddress, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kFinalPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewestEffectivePeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            connection_.active_effective_peer_migration_type());
  if (GetParam().version.HasIetfQuicFrames()) {
    EXPECT_NE(send_algorithm_,
              connection_.sent_packet_manager().GetSendAlgorithm());
    EXPECT_EQ(kFinalPeerAddress, writer_->last_write_peer_address());
    EXPECT_FALSE(writer_->path_challenge_frames().empty());
    EXPECT_EQ(0u, connection_.GetStats()
                      .num_peer_migration_while_validating_default_path);
    EXPECT_TRUE(connection_.HasPendingPathValidation());
  }
}

// Regression test for b/200020764.
TEST_P(QuicConnectionTest, ConnectionMigrationWithPendingPaddingBytes) {
  // TODO(haoyuewang) Move these test setup code to a common member function.
  set_perspective(Perspective::IS_SERVER);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  QuicConnectionPeer::SetPeerAddress(&connection_, kPeerAddress);
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_, kPeerAddress);
  QuicConnectionPeer::SetAddressValidated(&connection_);

  // Sends new server CID to client.
  QuicConnectionId new_cid;
  if (!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
        .WillOnce(Return(TestConnectionId(456)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_))
      .WillOnce(Invoke([&](const QuicConnectionId& cid) {
        new_cid = cid;
        return true;
      }));
  EXPECT_CALL(visitor_, SendNewConnectionId(_));
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  connection_.OnHandshakeComplete();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));

  auto* packet_creator = QuicConnectionPeer::GetPacketCreator(&connection_);
  packet_creator->FlushCurrentPacket();
  packet_creator->AddPendingPadding(50u);
  const QuicSocketAddress kPeerAddress3 =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/56789);
  auto ack_frame = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(1);
  ProcessFramesPacketWithAddresses({QuicFrame(&ack_frame)}, kSelfAddress,
                                   kPeerAddress3, ENCRYPTION_FORWARD_SECURE);
  // Any pending frames/padding should be flushed before default_path_ is
  // temporarily reset.
  ASSERT_EQ(connection_.self_address_on_default_path_while_sending_packet()
                .host()
                .address_family(),
            IpAddressFamily::IP_V6);
}

// Regression test for b/196208556.
TEST_P(QuicConnectionTest,
       ReversePathValidationResponseReceivedFromUnexpectedPeerAddress) {
  set_perspective(Perspective::IS_SERVER);
  if (!version().HasIetfQuicFrames() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  QuicConnectionPeer::SetPeerAddress(&connection_, kPeerAddress);
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_, kPeerAddress);
  QuicConnectionPeer::SetAddressValidated(&connection_);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());

  // Sends new server CID to client.
  QuicConnectionId new_cid;
  if (!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
        .WillOnce(Return(TestConnectionId(456)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_))
      .WillOnce(Invoke([&](const QuicConnectionId& cid) {
        new_cid = cid;
        return true;
      }));
  EXPECT_CALL(visitor_, SendNewConnectionId(_));
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  connection_.OnHandshakeComplete();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));

  // Process a non-probing packet to migrate to path 2 and kick off reverse path
  // validation.
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE)).Times(1);
  const QuicSocketAddress kPeerAddress2 =
      QuicSocketAddress(QuicIpAddress::Loopback4(), /*port=*/23456);
  peer_creator_.SetServerConnectionId(new_cid);
  ProcessFramesPacketWithAddresses({QuicFrame(QuicPingFrame())}, kSelfAddress,
                                   kPeerAddress2, ENCRYPTION_FORWARD_SECURE);
  EXPECT_FALSE(writer_->path_challenge_frames().empty());
  QuicPathFrameBuffer reverse_path_challenge_payload =
      writer_->path_challenge_frames().front().data_buffer;

  // Receiveds a packet from path 3 with PATH_RESPONSE frame intended to
  // validate path 2 and a non-probing frame.
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    const QuicSocketAddress kPeerAddress3 =
        QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/56789);
    auto ack_fr
```
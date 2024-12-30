Response:
The user is asking for a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc`. This file appears to contain unit tests for the `QuicConnection` class in the Chromium network stack.

Here's a breakdown of the request and how to address it:

1. **List the functions:** The core purpose of a test file is to verify the behavior of a specific class or component. Therefore, the primary function is to test different aspects of the `QuicConnection` class.

2. **Relationship with Javascript:**  QUIC is a transport layer protocol. While Javascript in a browser interacts with network requests, it doesn't directly deal with the implementation details of QUIC connections. The browser handles the underlying QUIC implementation. I need to find a way to illustrate this indirect relationship.

3. **Logical Reasoning (Hypothetical Input/Output):**  Test files often demonstrate specific scenarios. I should look for test cases that simulate certain actions and verify expected outcomes. This will involve identifying the "input" (the setup of the test) and the "output" (the assertions made about the state or actions).

4. **Common Usage Errors:**  Testing often reveals potential pitfalls for users (in this case, developers working with the QUIC stack). I need to look for tests that highlight incorrect configurations or usage patterns.

5. **User Operations Leading to This Code:** This requires thinking about how a QUIC connection is established and how these tests fit into that process. The user here is a developer, and the "operation" is running these unit tests.

6. **File Context (Part 23 of 24):**  This indicates the file is part of a larger set of tests for the `QuicConnection`. The previous parts likely covered other aspects of the connection lifecycle. This part likely focuses on more specific or advanced features. Scanning the test names and the code snippet itself will help identify the focus.

**Mental Sandbox/Pre-computation:**

* **Scanning the provided code:** The code snippet focuses heavily on server preferred addresses and multi-port connections. Keywords like `ServerPreferredAddress`, `ValidatePath`, `MultiPortCreation`, and `ClientReceivePathChallengeAfterServerMigration` are prominent. This suggests a significant portion of this section tests connection migration and related features. The ECN tests at the end are a separate focus.
* **Javascript connection:**  Javascript makes requests using APIs like `fetch()`. The browser's networking stack then handles the underlying protocol negotiation and connection management, potentially using QUIC. Javascript wouldn't be directly manipulating `QuicConnection` objects.
* **Hypothetical Input/Output:** A test like `ClientFailedToValidateServerPreferredAddress` has an implicit input: a server offering a preferred address that the client fails to validate. The expected output is that the connection falls back to the original address and handles the failure gracefully.
* **Common Errors:** A potential developer error might be incorrectly configuring the client to handle server preferred addresses or misinterpreting the connection migration events.
* **User Operations:** A developer would run this test to ensure that the QUIC connection handles server preferred addresses and multi-port scenarios correctly.

**Constraint Checklist & Confidence Score:**

1. List functions? Yes.
2. Javascript relation? Yes.
3. Javascript examples? Yes.
4. Logical reasoning? Yes.
5. Hypothetical input? Yes.
6. Hypothetical output? Yes.
7. Usage errors? Yes.
8. Examples of errors? Yes.
9. User operation steps? Yes.
10. Debugging线索? Yes. (The tests themselves act as debugging clues).
11.归纳一下它的功能? Yes.
12. Part 23 of 24?  Acknowledge this and use it to infer the file's focus.

Confidence Score: 5/5 - I am confident I can address all aspects of the request accurately.

Strategizing complete. I will now generate the response based on these steps.

这个C++源代码文件 `net/third_party/quiche/src/quiche/quiche/quic/core/quic_connection_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的单元测试文件，专门用于测试 `QuicConnection` 类的各种功能和行为。 作为第 23 部分，它主要关注以下功能：

**主要功能归纳 (基于提供的代码片段和上下文):**

* **测试客户端对服务端首选地址的处理:**  这部分测试了当服务端提供一个首选地址时，客户端如何进行路径验证，以及在验证成功和失败的不同场景下的行为。 包括：
    * **成功验证服务端首选地址:** 测试客户端如何启动对服务端首选地址的路径验证，并在验证成功后切换到该地址，同时验证旧的连接ID会被安全地废弃。
    * **未能验证服务端首选地址:** 测试客户端在尝试验证服务端首选地址失败后的处理，例如回退到原始地址，并废弃与首选地址相关的连接ID。
    * **优化的服务端首选地址:** 测试客户端在启用优化选项后，在路径验证期间如何同时向原始地址和首选地址发送数据包，以及在握手完成后停止重复发送的行为。
    * **限制发送到服务端首选地址的重复包数量:** 测试客户端在路径验证期间，向服务端首选地址发送重复数据包的数量限制。
* **测试多端口连接的创建 (在服务端迁移后):** 这部分测试了在服务端发生地址迁移后，客户端如何创建新的连接，利用新的源端口与服务端通信，并验证路径。
* **测试客户端在服务端迁移后接收和响应路径挑战:**  测试在客户端已经迁移到服务端首选地址后，如何处理来自原始服务端地址的路径挑战，并使用正确的路径进行响应。
* **测试客户端在服务端迁移后发起新的探测:** 测试客户端在迁移后，如何使用新的本地地址和端口，对服务端发起新的路径验证探测。
* **测试显式拥塞通知 (ECN) 标记的正确记录:**  测试接收到的数据包中 ECN 标记（ECT(0), ECT(1), CE）是否被正确记录到连接统计信息中。
* **测试合并数据包中的 ECN 标记:** 测试当接收到合并的数据包时，其中的 ECN 标记是否被正确地处理和记录。
* **测试无法解密的合并数据包中的 ECN 标记:** 测试当合并的数据包中部分数据包无法解密时，ECN 标记的处理情况。

**与 Javascript 的关系：**

`QuicConnection` 类本身是用 C++ 实现的，直接与 Javascript 没有直接关系。 然而，当用户在 Chromium 浏览器中使用 Javascript 发起网络请求时（例如使用 `fetch()` API），浏览器底层可能会使用 QUIC 协议与服务器建立连接。

* **举例说明:**  当 Javascript 代码使用 `fetch('https://example.com')` 发起 HTTPS 请求时，如果浏览器和服务器都支持 QUIC 协议，那么浏览器网络栈中的 QUIC 实现（包括 `QuicConnection` 类）会参与建立和维护这个连接。  这个测试文件中的代码，例如测试服务端首选地址的功能，间接地影响着 Javascript 发起的请求的性能和连接的健壮性。 如果服务端迁移了地址，QUIC 协议的客户端实现（此处测试的 `QuicConnection`）能够正确处理，从而保证 Javascript 请求的持续性。

**逻辑推理与假设输入输出:**

**测试用例:** `TEST_P(QuicConnectionTest, ClientFailedToValidateServerPreferredAddress)`

* **假设输入:**
    * 客户端尝试连接到服务端。
    * 服务端在握手过程中提供了首选地址 `kServerPreferredAddress`。
    * 客户端尝试对该首选地址进行路径验证，但验证过程超时或收到错误的响应。
* **预期输出:**
    * `connection_.HasPendingPathValidation()` 在超时后返回 `false`，表示路径验证已结束。
    * 数据包继续通过原始路径发送 (`writer_->stream_frames()` 不为空，且目标地址是 `kPeerAddress`)。
    *  `connection_.GetStats().server_preferred_address_validated` 为 `false`。
    * `connection_.GetStats().failed_to_validate_server_preferred_address` 为 `true`。
    * 客户端会发送 `RETIRE_CONNECTION_ID` 帧来废弃与服务端首选地址相关的连接ID。

**用户或编程常见的使用错误:**

* **客户端配置错误:**  如果客户端没有正确配置以处理服务端首选地址，或者禁用了相关功能，那么这些测试用例所覆盖的场景就可能无法正常工作。 例如，开发者可能错误地配置了 `QuicConfig`，导致客户端忽略服务端提供的首选地址。
* **服务端实现不一致:** 如果服务端提供的首选地址信息不正确，或者服务端在路径验证过程中的行为与客户端预期不符，也会导致客户端验证失败，这部分测试可以帮助发现这类服务端实现的问题。
* **网络环境问题:**  虽然测试代码通常在模拟环境下运行，但在实际部署中，网络环境的不可靠性（例如数据包丢失、延迟）可能导致路径验证失败，开发者需要考虑这种情况并进行相应的处理。

**用户操作如何一步步到达这里 (调试线索):**

假设开发者在调试一个与 QUIC 连接相关的 Bug，例如在服务端迁移后客户端连接出现问题。 开发者可能会采取以下步骤：

1. **复现问题:** 尝试重现客户端在服务端迁移后连接失败或性能下降的问题。
2. **查看网络日志:** 分析网络请求的日志，看是否涉及到地址迁移，以及迁移过程中是否发生错误。
3. **阅读 QUIC 协议规范:**  查阅 QUIC 协议关于服务端首选地址和连接迁移的规范，理解其工作原理。
4. **查找相关代码:** 在 Chromium 源码中搜索与服务端首选地址、路径验证、连接迁移相关的代码，找到 `quic_connection.cc` 和 `quic_connection_test.cc` 等文件。
5. **分析单元测试:**  阅读 `quic_connection_test.cc` 中与服务端首选地址相关的测试用例，例如本文件中列举的测试，理解客户端在各种场景下的预期行为。
6. **运行特定的测试用例:**  开发者可以运行与自己遇到的问题相关的特定测试用例，例如 `ClientFailedToValidateServerPreferredAddress` 或 `MultiPortCreationAfterServerMigration`，来验证 QUIC 连接的实现是否符合预期。
7. **设置断点和单步调试:** 在 `quic_connection.cc` 的相关代码中设置断点，结合单元测试，单步执行代码，观察连接状态的变化，以及数据包的发送和接收过程，从而定位 Bug 的原因。
8. **修改代码并重新测试:**  根据调试结果修改 `quic_connection.cc` 中的代码，并重新运行相关的单元测试，确保修改后的代码能够解决问题，并且没有引入新的问题。

**第23部分的功能归纳:**

作为 `quic_connection_test.cc` 的第 23 部分，本部分主要集中在测试 `QuicConnection` 类在处理服务端首选地址和连接迁移场景下的行为，包括路径验证、连接ID管理、以及与多端口连接相关的逻辑。 此外，还包括对 ECN 标记处理的测试。 这部分测试确保了 QUIC 连接在网络拓扑变化和服务端地址迁移时，能够保持连接的可靠性和性能。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第23部分，共24部分，请归纳一下它的功能

"""
nnection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
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
  ASSERT_FALSE(new_writer.path_challenge_frames().empty());
  QuicPathFrameBuffer payload =
      new_writer.path_challenge_frames().front().data_buffer;
  // Send data packet while path validation is pending.
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  ASSERT_FALSE(writer_->stream_frames().empty());
  EXPECT_EQ(TestConnectionId(),
            writer_->last_packet_header().destination_connection_id);
  EXPECT_EQ(kPeerAddress, writer_->last_write_peer_address());

  // Receive path response from original server address.
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicPathResponseFrame(99, payload)));
  ProcessFramesPacketWithAddresses(frames, kNewSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  ASSERT_FALSE(connection_.HasPendingPathValidation());
  ASSERT_FALSE(new_writer.stream_frames().empty());
  // Verify stream data is retransmitted on new path.
  EXPECT_EQ(TestConnectionId(17),
            new_writer.last_packet_header().destination_connection_id);
  EXPECT_EQ(kServerPreferredAddress, new_writer.last_write_peer_address());

  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  // Verify client retires connection ID with sequence number 0.
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();

  // Verify another packet from original server address gets processed.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  frames.clear();
  frames.push_back(QuicFrame(frame1_));
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(connection_.GetStats().server_preferred_address_validated);
  EXPECT_FALSE(
      connection_.GetStats().failed_to_validate_server_preferred_address);
}

TEST_P(QuicConnectionTest, ClientFailedToValidateServerPreferredAddress) {
  // Test the scenario where the client fails to validate server preferred
  // address.
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  QuicConfig config;
  ServerPreferredAddressInit(config);
  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
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
  EXPECT_TRUE(connection_.IsValidatingServerPreferredAddress());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, kServerPreferredAddress));
  ASSERT_FALSE(new_writer.path_challenge_frames().empty());

  // Receive mismatched path challenge from original server address.
  QuicFrames frames;
  frames.push_back(
      QuicFrame(QuicPathResponseFrame(99, {0, 1, 2, 3, 4, 5, 6, 7})));
  ProcessFramesPacketWithAddresses(frames, kNewSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  ASSERT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, kServerPreferredAddress));

  // Simluate path validation times out.
  for (size_t i = 0; i < QuicPathValidator::kMaxRetryTimes + 1; ++i) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
    static_cast<TestAlarmFactory::TestAlarm*>(
        QuicPathValidatorPeer::retry_timer(
            QuicConnectionPeer::path_validator(&connection_)))
        ->Fire();
  }
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_FALSE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, kServerPreferredAddress));
  // Verify stream data is sent on the default path.
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  ASSERT_FALSE(writer_->stream_frames().empty());
  EXPECT_EQ(TestConnectionId(),
            writer_->last_packet_header().destination_connection_id);
  EXPECT_EQ(kPeerAddress, writer_->last_write_peer_address());

  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  // Verify client retires connection ID with sequence number 1.
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/1u));
  retire_peer_issued_cid_alarm->Fire();
  EXPECT_TRUE(connection_.IsValidStatelessResetToken(kTestStatelessResetToken));
  EXPECT_FALSE(connection_.GetStats().server_preferred_address_validated);
  EXPECT_TRUE(
      connection_.GetStats().failed_to_validate_server_preferred_address);
}

TEST_P(QuicConnectionTest, OptimizedServerPreferredAddress) {
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
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
  QuicConfig config;
  config.SetClientConnectionOptions(QuicTagVector{kSPA2});
  ServerPreferredAddressInit(config);
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  ASSERT_FALSE(new_writer.path_challenge_frames().empty());

  // Send data packet while path validation is pending.
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  // Verify the packet is sent on both paths.
  EXPECT_FALSE(writer_->stream_frames().empty());
  EXPECT_FALSE(new_writer.stream_frames().empty());

  // Verify packet duplication stops on handshake confirmed.
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();
  SendPing();
  EXPECT_FALSE(writer_->ping_frames().empty());
  EXPECT_TRUE(new_writer.ping_frames().empty());
}

TEST_P(QuicConnectionTest, OptimizedServerPreferredAddress2) {
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
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
  QuicConfig config;
  config.SetClientConnectionOptions(QuicTagVector{kSPA2});
  ServerPreferredAddressInit(config);
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  ASSERT_FALSE(new_writer.path_challenge_frames().empty());

  // Send data packet while path validation is pending.
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  // Verify the packet is sent on both paths.
  EXPECT_FALSE(writer_->stream_frames().empty());
  EXPECT_FALSE(new_writer.stream_frames().empty());

  // Simluate path validation times out.
  for (size_t i = 0; i < QuicPathValidator::kMaxRetryTimes + 1; ++i) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
    static_cast<TestAlarmFactory::TestAlarm*>(
        QuicPathValidatorPeer::retry_timer(
            QuicConnectionPeer::path_validator(&connection_)))
        ->Fire();
  }
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  // Verify packet duplication stops if there is no pending validation.
  SendPing();
  EXPECT_FALSE(writer_->ping_frames().empty());
  EXPECT_TRUE(new_writer.ping_frames().empty());
}

TEST_P(QuicConnectionTest, MaxDuplicatedPacketsSentToServerPreferredAddress) {
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
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
  QuicConfig config;
  config.SetClientConnectionOptions(QuicTagVector{kSPA2});
  ServerPreferredAddressInit(config);
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  ASSERT_FALSE(new_writer.path_challenge_frames().empty());

  // Send data packet while path validation is pending.
  size_t write_limit = writer_->packets_write_attempts();
  size_t new_write_limit = new_writer.packets_write_attempts();
  for (size_t i = 0; i < kMaxDuplicatedPacketsSentToServerPreferredAddress;
       ++i) {
    connection_.SendStreamDataWithString(3, "foo", i * 3, NO_FIN);
    // Verify the packet is sent on both paths.
    ASSERT_EQ(write_limit + 1, writer_->packets_write_attempts());
    ASSERT_EQ(new_write_limit + 1, new_writer.packets_write_attempts());
    ++write_limit;
    ++new_write_limit;
    EXPECT_FALSE(writer_->stream_frames().empty());
    EXPECT_FALSE(new_writer.stream_frames().empty());
  }

  // Verify packet duplication stops if duplication limit is hit.
  SendPing();
  ASSERT_EQ(write_limit + 1, writer_->packets_write_attempts());
  ASSERT_EQ(new_write_limit, new_writer.packets_write_attempts());
  EXPECT_FALSE(writer_->ping_frames().empty());
  EXPECT_TRUE(new_writer.ping_frames().empty());
}

TEST_P(QuicConnectionTest, MultiPortCreationAfterServerMigration) {
  if (!GetParam().version.HasIetfQuicFrames()) {
    return;
  }
  QuicConfig config;
  config.SetClientConnectionOptions(QuicTagVector{kMPQC});
  ServerPreferredAddressInit(config);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  QuicConnectionId cid_for_preferred_address = TestConnectionId(17);
  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
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
  // The connection should start probing the preferred address after handshake
  // confirmed.
  QuicPathFrameBuffer payload;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(testing::AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, new_writer.path_challenge_frames().size());
        payload = new_writer.path_challenge_frames().front().data_buffer;
        EXPECT_EQ(kServerPreferredAddress,
                  new_writer.last_write_peer_address());
      }));
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();
  EXPECT_TRUE(connection_.IsValidatingServerPreferredAddress());

  // Receiving PATH_RESPONSE should cause the connection to migrate to the
  // preferred address.
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicPathResponseFrame(99, payload)));
  ProcessFramesPacketWithAddresses(frames, kNewSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_FALSE(connection_.IsValidatingServerPreferredAddress());
  EXPECT_EQ(kServerPreferredAddress, connection_.effective_peer_address());
  EXPECT_EQ(kNewSelfAddress, connection_.self_address());
  EXPECT_EQ(connection_.connection_id(), cid_for_preferred_address);

  // As the default path changed, the server issued CID 1 should be retired.
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();

  const QuicSocketAddress kNewSelfAddress2(kNewSelfAddress.host(),
                                           kNewSelfAddress.port() + 1);
  EXPECT_NE(kNewSelfAddress2, kNewSelfAddress);
  TestPacketWriter new_writer2(version(), &clock_, Perspective::IS_CLIENT);
  QuicNewConnectionIdFrame frame;
  frame.connection_id = TestConnectionId(789);
  ASSERT_NE(frame.connection_id, connection_.connection_id());
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;
  frame.sequence_number = 2u;
  EXPECT_CALL(visitor_, CreateContextForMultiPortPath)
      .WillOnce(testing::WithArgs<0>([&](auto&& observer) {
        observer->OnMultiPortPathContextAvailable(
            std::move(std::make_unique<TestQuicPathValidationContext>(
                kNewSelfAddress2, connection_.peer_address(), &new_writer2)));
      }));
  connection_.OnNewConnectionIdFrame(frame);
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_EQ(1u, new_writer.path_challenge_frames().size());
  payload = new_writer.path_challenge_frames().front().data_buffer;
  EXPECT_EQ(kServerPreferredAddress, new_writer.last_write_peer_address());
  EXPECT_EQ(kNewSelfAddress2.host(), new_writer.last_write_source_address());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress2, connection_.peer_address()));
  auto* alt_path = QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_FALSE(alt_path->validated);
  QuicFrames frames2;
  frames2.push_back(QuicFrame(QuicPathResponseFrame(99, payload)));
  ProcessFramesPacketWithAddresses(frames2, kNewSelfAddress2, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(alt_path->validated);
}

// Tests that after half-way server migration, the client should be able to
// respond to any reverse path validation from the original server address.
TEST_P(QuicConnectionTest, ClientReceivePathChallengeAfterServerMigration) {
  if (!GetParam().version.HasIetfQuicFrames()) {
    return;
  }
  QuicConfig config;
  ServerPreferredAddressInit(config);
  QuicConnectionId cid_for_preferred_address = TestConnectionId(17);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(visitor_,
              OnServerPreferredAddressAvailable(kServerPreferredAddress))
      .WillOnce(Invoke([&]() {
        connection_.AddKnownServerAddress(kServerPreferredAddress);
      }));
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();

  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), kTestPort + 1);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  auto context = std::make_unique<TestQuicPathValidationContext>(
      kNewSelfAddress, kServerPreferredAddress, &new_writer);
  // Pretend that the validation already succeeded. And start to use the server
  // preferred address.
  connection_.OnServerPreferredAddressValidated(*context, false);
  EXPECT_EQ(kServerPreferredAddress, connection_.effective_peer_address());
  EXPECT_EQ(kServerPreferredAddress, connection_.peer_address());
  EXPECT_EQ(kNewSelfAddress, connection_.self_address());
  EXPECT_EQ(connection_.connection_id(), cid_for_preferred_address);
  EXPECT_NE(connection_.sent_packet_manager().GetSendAlgorithm(),
            send_algorithm_);
  // Switch to use a mock send algorithm.
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

  // As the default path changed, the server issued CID 123 should be retired.
  QuicConnectionPeer::RetirePeerIssuedConnectionIdsNoLongerOnPath(&connection_);
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();

  // Receive PATH_CHALLENGE from the original server
  // address. The client connection responds it on the default path.
  QuicPathFrameBuffer path_challenge_payload{0, 1, 2, 3, 4, 5, 6, 7};
  QuicFrames frames1;
  frames1.push_back(
      QuicFrame(QuicPathChallengeFrame(0, path_challenge_payload)));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1))
      .WillOnce(Invoke([&]() {
        ASSERT_FALSE(new_writer.path_response_frames().empty());
        EXPECT_EQ(
            0, memcmp(&path_challenge_payload,
                      &(new_writer.path_response_frames().front().data_buffer),
                      sizeof(path_challenge_payload)));
        EXPECT_EQ(kServerPreferredAddress,
                  new_writer.last_write_peer_address());
        EXPECT_EQ(kNewSelfAddress.host(),
                  new_writer.last_write_source_address());
      }));
  ProcessFramesPacketWithAddresses(frames1, kNewSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
}

// Tests that after half-way server migration, the client should be able to
// probe with a different socket and respond to reverse path validation.
TEST_P(QuicConnectionTest, ClientProbesAfterServerMigration) {
  if (!GetParam().version.HasIetfQuicFrames()) {
    return;
  }
  QuicConfig config;
  ServerPreferredAddressInit(config);
  QuicConnectionId cid_for_preferred_address = TestConnectionId(17);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  // The connection should start probing the preferred address after handshake
  // confirmed.
  EXPECT_CALL(visitor_,
              OnServerPreferredAddressAvailable(kServerPreferredAddress))
      .WillOnce(Invoke([&]() {
        connection_.AddKnownServerAddress(kServerPreferredAddress);
      }));
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();

  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), kTestPort + 1);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  auto context = std::make_unique<TestQuicPathValidationContext>(
      kNewSelfAddress, kServerPreferredAddress, &new_writer);
  // Pretend that the validation already succeeded.
  connection_.OnServerPreferredAddressValidated(*context, false);
  EXPECT_EQ(kServerPreferredAddress, connection_.effective_peer_address());
  EXPECT_EQ(kServerPreferredAddress, connection_.peer_address());
  EXPECT_EQ(kNewSelfAddress, connection_.self_address());
  EXPECT_EQ(connection_.connection_id(), cid_for_preferred_address);
  EXPECT_NE(connection_.sent_packet_manager().GetSendAlgorithm(),
            send_algorithm_);
  // Switch to use a mock send algorithm.
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

  // Receiving data from the original server address should not change the peer
  // address.
  EXPECT_CALL(visitor_, OnCryptoFrame(_));
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kNewSelfAddress,
                                  kPeerAddress, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kServerPreferredAddress, connection_.effective_peer_address());
  EXPECT_EQ(kServerPreferredAddress, connection_.peer_address());

  // As the default path changed, the server issued CID 123 should be retired.
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();

  // Receiving a new CID from the server.
  QuicNewConnectionIdFrame new_cid_frame1;
  new_cid_frame1.connection_id = TestConnectionId(456);
  ASSERT_NE(new_cid_frame1.connection_id, connection_.connection_id());
  new_cid_frame1.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(new_cid_frame1.connection_id);
  new_cid_frame1.retire_prior_to = 0u;
  new_cid_frame1.sequence_number = 2u;
  connection_.OnNewConnectionIdFrame(new_cid_frame1);

  // Probe from a new socket.
  const QuicSocketAddress kNewSelfAddress2 =
      QuicSocketAddress(QuicIpAddress::Loopback4(), kTestPort + 2);
  TestPacketWriter new_writer2(version(), &clock_, Perspective::IS_CLIENT);
  bool success;
  QuicPathFrameBuffer payload;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(testing::AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, new_writer2.path_challenge_frames().size());
        payload = new_writer2.path_challenge_frames().front().data_buffer;
        EXPECT_EQ(kServerPreferredAddress,
                  new_writer2.last_write_peer_address());
        EXPECT_EQ(kNewSelfAddress2.host(),
                  new_writer2.last_write_source_address());
      }));
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress2, connection_.peer_address(), &new_writer2),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress2, connection_.peer_address(), &success),
      PathValidationReason::kServerPreferredAddressMigration);
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress2, kServerPreferredAddress));

  // Our server implementation will send PATH_CHALLENGE from the original server
  // address. The client connection send PATH_RESPONSE to the default peer
  // address.
  QuicPathFrameBuffer path_challenge_payload{0, 1, 2, 3, 4, 5, 6, 7};
  QuicFrames frames;
  frames.push_back(
      QuicFrame(QuicPathChallengeFrame(0, path_challenge_payload)));
  frames.push_back(QuicFrame(QuicPathResponseFrame(99, payload)));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1))
      .WillOnce(Invoke([&]() {
        EXPECT_FALSE(new_writer2.path_response_frames().empty());
        EXPECT_EQ(
            0, memcmp(&path_challenge_payload,
                      &(new_writer2.path_response_frames().front().data_buffer),
                      sizeof(path_challenge_payload)));
        EXPECT_EQ(kServerPreferredAddress,
                  new_writer2.last_write_peer_address());
        EXPECT_EQ(kNewSelfAddress2.host(),
                  new_writer2.last_write_source_address());
      }));
  ProcessFramesPacketWithAddresses(frames, kNewSelfAddress2, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(success);
}

TEST_P(QuicConnectionTest, EcnMarksCorrectlyRecorded) {
  set_perspective(Perspective::IS_SERVER);
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicPingFrame()));
  frames.push_back(QuicFrame(QuicPaddingFrame(7)));
  QuicAckFrame ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(APPLICATION_DATA)
          : connection_.received_packet_manager().ack_frame();
  EXPECT_FALSE(ack_frame.ecn_counters.has_value());

  ProcessFramesPacketAtLevelWithEcn(1, frames, ENCRYPTION_FORWARD_SECURE,
                                    ECN_ECT0);
  ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(APPLICATION_DATA)
          : connection_.received_packet_manager().ack_frame();
  // Send two PINGs so that the ACK goes too. The second packet should not
  // include an ACK, which checks that the packet state is cleared properly.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  if (connection_.version().HasIetfQuicFrames()) {
    QuicConnectionPeer::SendPing(&connection_);
    QuicConnectionPeer::SendPing(&connection_);
  }
  QuicConnectionStats stats = connection_.GetStats();
  ASSERT_TRUE(ack_frame.ecn_counters.has_value());
  EXPECT_EQ(ack_frame.ecn_counters->ect0, 1);
  EXPECT_EQ(stats.num_ack_frames_sent_with_ecn,
            connection_.version().HasIetfQuicFrames() ? 1 : 0);
  EXPECT_EQ(stats.num_ecn_marks_received.ect0, 1);
  EXPECT_EQ(stats.num_ecn_marks_received.ect1, 0);
  EXPECT_EQ(stats.num_ecn_marks_received.ce, 0);
}

TEST_P(QuicConnectionTest, EcnMarksCoalescedPacket) {
  if (!connection_.version().CanSendCoalescedPackets()) {
    return;
  }
  QuicCryptoFrame crypto_frame1{ENCRYPTION_HANDSHAKE, 0, "foo"};
  QuicFrames frames1;
  frames1.push_back(QuicFrame(&crypto_frame1));
  QuicFrames frames2;
  QuicCryptoFrame crypto_frame2{ENCRYPTION_FORWARD_SECURE, 0, "bar"};
  frames2.push_back(QuicFrame(&crypto_frame2));
  std::vector<PacketInfo> packets = {{2, frames1, ENCRYPTION_HANDSHAKE},
                                     {3, frames2, ENCRYPTION_FORWARD_SECURE}};
  QuicAckFrame ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(APPLICATION_DATA)
          : connection_.received_packet_manager().ack_frame();
  EXPECT_FALSE(ack_frame.ecn_counters.has_value());
  ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(HANDSHAKE_DATA)
          : connection_.received_packet_manager().ack_frame();
  EXPECT_FALSE(ack_frame.ecn_counters.has_value());
  // Deliver packets.
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(2);
  ProcessCoalescedPacket(packets, ECN_ECT0);
  // Send two PINGs so that the ACKs go too.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  if (connection_.version().HasIetfQuicFrames()) {
    EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
    QuicConnectionPeer::SendPing(&connection_);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    QuicConnectionPeer::SendPing(&connection_);
  }
  QuicConnectionStats stats = connection_.GetStats();
  ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(HANDSHAKE_DATA)
          : connection_.received_packet_manager().ack_frame();
  ASSERT_TRUE(ack_frame.ecn_counters.has_value());
  EXPECT_EQ(ack_frame.ecn_counters->ect0,
            connection_.SupportsMultiplePacketNumberSpaces() ? 1 : 2);
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    ack_frame = connection_.SupportsMultiplePacketNumberSpaces()
                    ? connection_.received_packet_manager().GetAckFrame(
                          APPLICATION_DATA)
                    : connection_.received_packet_manager().ack_frame();
    EXPECT_TRUE(ack_frame.ecn_counters.has_value());
    EXPECT_EQ(ack_frame.ecn_counters->ect0, 1);
  }
  EXPECT_EQ(stats.num_ecn_marks_received.ect0, 2);
  EXPECT_EQ(stats.num_ack_frames_sent_with_ecn,
            connection_.version().HasIetfQuicFrames() ? 2 : 0);
  EXPECT_EQ(stats.num_ecn_marks_received.ect1, 0);
  EXPECT_EQ(stats.num_ecn_marks_received.ce, 0);
}

TEST_P(QuicConnectionTest, EcnMarksUndecryptableCoalescedPacket) {
  if (!connection_.version().CanSendCoalescedPackets()) {
    return;
  }
  // SetFromConfig is always called after construction from InitializeSession.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.set_max_undecryptable_packets(100);
  connection_.SetFromConfig(config);
  QuicCryptoFrame crypto_frame1{ENCRYPTION_HANDSHAKE, 0, "foo"};
  QuicFrames frames1;
  frames1.push_back(QuicFrame(&crypto_frame1));
  QuicFrames frames2;
  QuicCryptoFrame crypto_frame2{ENCRYPTION_FORWARD_SECURE, 0, "bar"};
  frames2.push_back(QuicFrame(&crypto_frame2));
  std::vector<PacketInfo> packets = {{2, frames1, ENCRYPTION_HANDSHAKE},
                                     {3, frames2, ENCRYPTION_FORWARD_SECURE}};
  char coalesced_buffer[kMaxOutgoingPacketSize];
  size_t coalesced_size = 0;
  for (const auto& packet : packets) {
    QuicPacketHeader header =
        ConstructPacketHeader(packet.packet_number, packet.level);
    // Set the correct encryption level and encrypter on peer_creator and
    // peer_framer, respectively.
    peer_creator_.set_encryption_level(packet.level);
    peer_framer_.SetEncrypter(packet.level,
                              std::make_unique<TaggingEncrypter>(packet.level));
    // Set the corresponding decrypter.
    if (packet.level == ENCRYPTION_HANDSHAKE) {
      connection_.SetEncrypter(
          packet.level, std::make_unique<TaggingEncrypter>(packet.level));
      connection_.SetDefaultEncryptionLevel(packet.level);
      SetDecrypter(packet.level,
                   std::make_unique<StrictTaggingDecrypter>(packet.level));
    }
    // Forward Secure packet is undecryptable.
    std::unique_ptr<QuicPacket> constructed_packet(
        ConstructPacket(header, packet.frames));

    char buffer[kMaxOutgoingPacketSize];
    size_t encrypted_length = peer_framer_.EncryptPayload(
        packet.level, QuicPacketNumber(packet.packet_number),
        *constructed_packet, buffer, kMaxOutgoingPacketSize);
    QUICHE_DCHECK_LE(coalesced_size + encrypted_length, kMaxOutgoingPacketSize);
    memcpy(coalesced_buffer + coalesce
"""


```
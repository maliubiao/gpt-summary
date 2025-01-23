Response:
The user is asking for a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc`. This is a test file for the `QuicConnection` class in Chromium's QUIC implementation.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename clearly indicates this is a test file. Therefore, its primary function is to test the behavior of `QuicConnection`.

2. **Scan the code for key features and tests:** Look for `TEST_P` macros which define individual test cases. The names of these tests often reveal the specific functionality being tested. Keywords like "MultiPortPath", "PathDegrading", "Migration", "Handshake", "ZeroRtt", "RetryToken", "Ack", "NewToken", "PathChallenge", "ConnectionClose" etc., point to the areas of `QuicConnection` being exercised.

3. **Group related tests:** Notice patterns in the test names. For instance, several tests deal with multi-port path functionality, others with path degradation, and so on. This allows for categorizing the features being tested.

4. **Look for interactions with JavaScript (if any):** QUIC is a transport protocol, and while it facilitates web communication often involving JavaScript, the core `QuicConnection` logic is in C++. Look for any explicit mentions or implications of JavaScript interaction. This is likely to be minimal or indirect, focusing on network behavior rather than application-layer specifics.

5. **Analyze logical reasoning and examples:**  Within each test case, understand the setup (assumptions/input), the action being performed, and the verification (expected output). This involves understanding how the test simulates various scenarios and validates the `QuicConnection`'s response.

6. **Identify common usage errors:**  Tests that involve negative scenarios or edge cases often reveal potential mistakes developers might make when using `QuicConnection` or related QUIC features.

7. **Trace user operations:**  Consider how a user's actions in a web browser (which would utilize this networking stack) might lead to the execution of the code being tested. Think about the sequence of events during a QUIC connection lifecycle.

8. **Consider the file's position in the overall structure:** The prompt mentions this is part 19 of 24. This suggests the file focuses on a specific set of features within the larger `QuicConnection` testing suite. The preceding and subsequent files likely cover other aspects.

9. **Synthesize the findings:**  Combine the observations from the previous steps into a concise summary of the file's functionality.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on individual test details. Recognizing the need for a higher-level summary, I would shift to grouping related tests and identifying broader functional areas.
* If I couldn't find direct JavaScript links, I would note the C++ nature of the code and explain the indirect relationship through the browser's networking stack.
* When considering user operations, I'd start broadly (e.g., opening a webpage) and then narrow down to specific QUIC connection events (handshake, migration, etc.).
* The "part 19 of 24" information is crucial for contextualizing the scope of this particular file. It helps to avoid overgeneralizing the summary to cover all `QuicConnection` features.

By following these steps, I can generate a comprehensive and accurate summary of the provided C++ test file.
这是 Chromium 网络栈中 QUIC 协议核心连接功能测试的第 19 部分，共 24 部分。从代码片段来看，这个文件主要集中在测试 `QuicConnection` 类在特定场景下的行为，尤其是关于多路径 (Multi-Port Path) 功能和连接迁移 (Connection Migration) 相关的测试。

以下是该文件主要功能的归纳：

**核心功能：测试 `QuicConnection` 类的多路径和连接迁移功能**

**具体测试点包括：**

* **多路径 (Multi-Port Path) 功能：**
    * **启用和禁用：** 测试在启用和禁用多路径功能时，连接对 `NEW_CONNECTION_ID` 帧的响应。
    * **路径验证：** 测试当收到 `NEW_CONNECTION_ID` 帧时，连接是否会发起新的路径验证流程。
    * **备用路径的创建和状态：** 验证备用路径是否被正确创建，以及其 `validated` 状态和验证原因。
    * **Stateless Reset 对备用路径的影响：**  测试在备用路径上收到 Stateless Reset 包时，连接的行为，例如探测和统计。
    * **与主动迁移配置的交互：** 测试当客户端禁用主动迁移时，多路径功能是否会被尊重。
    * **路径降级 (Path Degrading) 触发多路径迁移：**
        * 测试当检测到路径降级时，如果备用路径未就绪，连接是否会进行迁移。
        * 测试当检测到路径降级时，如果备用路径已就绪且未在探测，连接是否会迁移到备用路径。
        * 测试当检测到路径降级时，如果备用路径已就绪且正在探测，连接是否会取消探测并迁移到备用路径。

* **其他连接功能：**
    * **单个 ACK 帧的处理：** 测试当收到包含单个 ACK 帧的包时连接的行为。
    * **服务器接收到 0-RTT 包的时机：** 测试服务器在收到 1-RTT 包后，如何处理收到的 0-RTT 包，包括密钥保留和丢弃的场景。
    * **`NEW_TOKEN` 帧的处理：**
        * 测试收到 `NEW_TOKEN` 帧是否会触发 ACK 机制。
        * 测试服务器收到 `NEW_TOKEN` 帧时是否会关闭连接。
    * **Retry Token 的覆盖：** 测试使用 Retry Packet 是否会覆盖已有的 Address Token。
    * **0-RTT 包的乱序处理：** 测试服务器收到比 1-RTT 包序号更高的 0-RTT 包时的处理逻辑，预期是关闭连接。
    * **握手完成前的连接迁移：** 测试在握手完成前，对端发起迁移时服务器的处理，预期是关闭连接。
    * **ACK 帧的刷新：** 测试在有待处理 ACK 时尝试刷新 ACK 队列的行为。
    * **路径挑战 (Path Challenge) 的处理：**
        * 测试在对端 IP 地址改变之前发送路径挑战的行为。
        * 测试在对端 IP 地址改变之前路径验证成功的情况。

**与 JavaScript 的关系：**

该文件是 C++ 代码，直接与 JavaScript 没有关系。然而，QUIC 协议是现代网络通信的基础，JavaScript 代码在浏览器中发起网络请求时，底层很可能会使用 QUIC 协议。

**举例说明：**

假设一个用户在 Chrome 浏览器中访问一个支持 QUIC 协议的网站。

1. **多路径功能：** 如果网络环境不稳定，例如 Wi-Fi 信号弱，或者用户同时连接了多个网络接口 (例如 Wi-Fi 和移动数据)，浏览器可能会利用 QUIC 的多路径功能尝试使用不同的网络路径来传输数据，以提高连接的稳定性和性能。这段代码中的测试用例就在验证 `QuicConnection` 类在处理多路径相关的事件时的正确性。

2. **连接迁移：** 如果用户的网络环境发生变化，例如从 Wi-Fi 断开连接并切换到移动数据，QUIC 协议支持连接迁移，允许连接在不中断的情况下切换到新的网络路径。这段代码中的测试用例就在验证 `QuicConnection` 类在处理连接迁移时的各种场景，例如 IP 地址变化、端口变化等。

**逻辑推理、假设输入与输出：**

**示例：测试路径降级时，备用路径已就绪且未在探测的情况**

* **假设输入：**
    * 客户端启用了多路径功能 (`kMPQC`, `kMPQM`)。
    * 客户端检测到当前路径质量下降 (触发 `OnPathDegradingDetected`)。
    * 客户端已经通过 `NEW_CONNECTION_ID` 帧创建了一个备用路径，并且该备用路径已经通过路径验证。
    * 备用路径当前没有在进行路径探测。

* **预期输出：**
    * `QuicConnection` 会调用 `visitor_->MigrateToMultiPortPath()`，指示进行多路径迁移。
    * 迁移的目标地址是备用路径的地址。
    * 连接会切换到备用路径进行数据传输。

**用户或编程常见的使用错误：**

* **错误地配置多路径功能：**  例如，服务器没有正确配置以支持多路径，导致客户端尝试多路径连接时失败。这段代码中的测试用例可以帮助开发者确保多路径功能在各种配置下都能正常工作。
* **错误地处理连接迁移事件：**  例如，应用程序没有正确监听连接迁移事件，导致在连接迁移后出现状态不一致的问题。
* **在不应该发送 `NEW_TOKEN` 帧的时候发送：** 服务器不应该主动发送 `NEW_TOKEN` 帧，测试用例 `ServerClosesConnectionOnNewTokenFrame` 就验证了服务器收到 `NEW_TOKEN` 帧会关闭连接。

**用户操作到达此处的调试线索：**

1. **用户在 Chrome 浏览器中访问一个网站。**
2. **浏览器与服务器建立 QUIC 连接。**
3. **在连接建立后，网络环境可能发生变化，例如：**
    * 用户的 Wi-Fi 信号变弱。
    * 用户从 Wi-Fi 切换到移动数据。
    * 用户所处的网络环境存在多条可用路径。
4. **QUIC 连接的 `QuicConnection` 对象会检测到这些变化。**
5. **根据配置和网络状况，`QuicConnection` 可能会尝试进行多路径连接或连接迁移。**
6. **如果开发者怀疑多路径或连接迁移相关的逻辑存在问题，他们可能会运行 `quic_connection_test.cc` 中的相关测试用例进行调试，例如：**
    * `MultiPortPathRespectsActiveMigrationConfig`：检查多路径是否尊重主动迁移配置。
    * `PathDegradingWhenAltPathIsReadyAndNotProbing`：检查路径降级时迁移到就绪的备用路径的逻辑。
7. **通过查看测试的执行结果和相关的日志，开发者可以定位问题所在。**

**作为第 19 部分的功能归纳：**

作为整个 `QuicConnection` 测试套件的第 19 部分，这个文件专注于 **深入测试 `QuicConnection` 类的多路径和连接迁移机制在各种复杂场景下的正确性和健壮性**。它涵盖了多路径的启用、禁用、路径验证、路径降级触发的迁移以及与连接迁移相关的各种细节处理，例如 `NEW_TOKEN` 帧和 Retry Token 的交互。它也涵盖了一些边缘情况和错误处理，例如收到乱序的 0-RTT 包和握手前的连接迁移。

总而言之，这个文件通过大量的单元测试用例，确保了 Chromium 中 QUIC 连接的核心功能（特别是多路径和连接迁移）能够按照预期工作，从而保证了基于 QUIC 协议的网络连接的稳定性和性能。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第19部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
bserver) {
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

  std::unique_ptr<QuicEncryptedPacket> packet(
      QuicFramer::BuildIetfStatelessResetPacket(connection_id_,
                                                /*received_packet_length=*/100,
                                                kTestStatelessResetToken));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*packet, QuicTime::Zero()));
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_PEER))
      .Times(0);
  connection_.ProcessUdpPacket(kNewSelfAddress, kPeerAddress, *received);
  EXPECT_EQ(connection_.GetStats().num_client_probing_attempts, 1);
  EXPECT_EQ(connection_.GetStats().num_stateless_resets_on_alternate_path, 1);
}

// Test that if the client's active migration is disabled, multi-port will not
// be attempted.
TEST_P(QuicConnectionTest, MultiPortPathRespectsActiveMigrationConfig) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_CLIENT);
  QuicConfig config;
  QuicConfigPeer::SetReceivedStatelessResetToken(&config,
                                                 kTestStatelessResetToken);
  QuicConfigPeer::SetReceivedDisableConnectionMigration(&config);
  config.SetClientConnectionOptions(QuicTagVector{kMPQC});
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();

  EXPECT_CALL(visitor_, OnPathDegrading());
  connection_.OnPathDegradingDetected();

  QuicNewConnectionIdFrame frame;
  frame.connection_id = TestConnectionId(1234);
  ASSERT_NE(frame.connection_id, connection_.connection_id());
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;
  frame.sequence_number = 1u;
  EXPECT_CALL(visitor_, CreateContextForMultiPortPath).Times(0);
  connection_.OnNewConnectionIdFrame(frame);
  EXPECT_FALSE(connection_.HasPendingPathValidation());
}

// Verify that when multi-port is enabled and path degrading is triggered, if
// the alt-path is not ready, nothing happens.
TEST_P(QuicConnectionTest, PathDegradingWhenAltPathIsNotReady) {
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

  auto self_address = connection_.self_address();
  const QuicSocketAddress kNewSelfAddress(self_address.host(),
                                          self_address.port() + 1);
  EXPECT_NE(kNewSelfAddress, self_address);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);

  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

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
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  auto* alt_path = QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_FALSE(alt_path->validated);

  // The alt path is not ready, path degrading doesn't do anything.
  EXPECT_CALL(visitor_, OnPathDegrading());
  EXPECT_CALL(visitor_, MigrateToMultiPortPath(_)).Times(0);
  connection_.OnPathDegradingDetected();

  // 30ms RTT.
  const QuicTime::Delta kTestRTT = QuicTime::Delta::FromMilliseconds(30);
  // Fake a response delay.
  clock_.AdvanceTime(kTestRTT);

  // Even if the alt path is validated after path degrading, nothing should
  // happen.
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
}

// Verify that when multi-port is enabled and path degrading is triggered, if
// the alt-path is ready and not probing, it should be migrated.
TEST_P(QuicConnectionTest, PathDegradingWhenAltPathIsReadyAndNotProbing) {
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  set_perspective(Perspective::IS_CLIENT);
  QuicConfig config;
  config.SetClientConnectionOptions(QuicTagVector{kMPQC, kMPQM});
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();

  auto self_address = connection_.self_address();
  const QuicSocketAddress kNewSelfAddress(self_address.host(),
                                          self_address.port() + 1);
  EXPECT_NE(kNewSelfAddress, self_address);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);

  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

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
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  auto* alt_path = QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_FALSE(alt_path->validated);

  // 30ms RTT.
  const QuicTime::Delta kTestRTT = QuicTime::Delta::FromMilliseconds(30);
  // Fake a response delay.
  clock_.AdvanceTime(kTestRTT);

  // Even if the alt path is validated after path degrading, nothing should
  // happen.
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

  // Trigger path degrading and the connection should attempt to migrate.
  EXPECT_CALL(visitor_, OnPathDegrading());
  EXPECT_CALL(visitor_, OnForwardProgressMadeAfterPathDegrading()).Times(0);
  EXPECT_CALL(visitor_, MigrateToMultiPortPath(_))
      .WillOnce(Invoke([&](std::unique_ptr<QuicPathValidationContext> context) {
        EXPECT_EQ(context->self_address(), kNewSelfAddress);
        connection_.MigratePath(context->self_address(),
                                context->peer_address(), context->WriterToUse(),
                                /*owns_writer=*/false);
      }));
  connection_.OnPathDegradingDetected();
}

// Verify that when multi-port is enabled and path degrading is triggered, if
// the alt-path is probing, the probing should be cancelled and the path should
// be migrated.
TEST_P(QuicConnectionTest, PathDegradingWhenAltPathIsReadyAndProbing) {
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  set_perspective(Perspective::IS_CLIENT);
  QuicConfig config;
  config.SetClientConnectionOptions(QuicTagVector{kMPQC, kMPQM});
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  connection_.CreateConnectionIdManager();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();

  auto self_address = connection_.self_address();
  const QuicSocketAddress kNewSelfAddress(self_address.host(),
                                          self_address.port() + 1);
  EXPECT_NE(kNewSelfAddress, self_address);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);

  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

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
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(
      &connection_, kNewSelfAddress, connection_.peer_address()));
  auto* alt_path = QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_FALSE(alt_path->validated);

  // 30ms RTT.
  const QuicTime::Delta kTestRTT = QuicTime::Delta::FromMilliseconds(30);
  // Fake a response delay.
  clock_.AdvanceTime(kTestRTT);

  // Even if the alt path is validated after path degrading, nothing should
  // happen.
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

  random_generator_.ChangeValue();
  connection_.GetMultiPortProbingAlarm()->Fire();
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_FALSE(connection_.GetMultiPortProbingAlarm()->IsSet());

  // Trigger path degrading and the connection should attempt to migrate.
  EXPECT_CALL(visitor_, OnPathDegrading());
  EXPECT_CALL(visitor_, OnForwardProgressMadeAfterPathDegrading()).Times(0);
  EXPECT_CALL(visitor_, MigrateToMultiPortPath(_))
      .WillOnce(Invoke([&](std::unique_ptr<QuicPathValidationContext> context) {
        EXPECT_EQ(context->self_address(), kNewSelfAddress);
        connection_.MigratePath(context->self_address(),
                                context->peer_address(), context->WriterToUse(),
                                /*owns_writer=*/false);
      }));
  connection_.OnPathDegradingDetected();
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  auto* path_validator = QuicConnectionPeer::path_validator(&connection_);
  EXPECT_FALSE(QuicPathValidatorPeer::retry_timer(path_validator)->IsSet());
}

TEST_P(QuicConnectionTest, SingleAckInPacket) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  connection_.OnHandshakeComplete();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_COMPLETE));

  EXPECT_CALL(visitor_, OnStreamFrame(_)).WillOnce(Invoke([=, this]() {
    connection_.SendStreamData3();
    connection_.CloseConnection(
        QUIC_INTERNAL_ERROR, "error",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }));
  QuicFrames frames;
  frames.push_back(QuicFrame(frame1_));
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  ASSERT_FALSE(writer_->ack_frames().empty());
  EXPECT_EQ(1u, writer_->ack_frames().size());
}

TEST_P(QuicConnectionTest,
       ServerReceivedZeroRttPacketAfterOneRttPacketWithRetainedKey) {
  if (!connection_.version().UsesTls()) {
    return;
  }

  set_perspective(Perspective::IS_SERVER);
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));

  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);

  // Finish handshake.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  notifier_.NeuterUnencryptedData();
  connection_.NeuterUnencryptedPackets();
  connection_.OnHandshakeComplete();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_COMPLETE));

  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(4, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(connection_.GetDiscardZeroRttDecryptionKeysAlarm()->IsSet());

  // 0-RTT packet received out of order should be decoded since the decrypter
  // is temporarily retained.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(2, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
  EXPECT_EQ(
      0u,
      connection_.GetStats()
          .num_tls_server_zero_rtt_packets_received_after_discarding_decrypter);

  // Simulate the timeout for discarding 0-RTT keys passing.
  connection_.GetDiscardZeroRttDecryptionKeysAlarm()->Fire();

  // Another 0-RTT packet received now should not be decoded.
  EXPECT_FALSE(connection_.GetDiscardZeroRttDecryptionKeysAlarm()->IsSet());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(0);
  ProcessDataPacketAtLevel(3, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
  EXPECT_EQ(
      1u,
      connection_.GetStats()
          .num_tls_server_zero_rtt_packets_received_after_discarding_decrypter);

  // The |discard_zero_rtt_decryption_keys_alarm_| should only be set on the
  // first 1-RTT packet received.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(5, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
  EXPECT_FALSE(connection_.GetDiscardZeroRttDecryptionKeysAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, NewTokenFrameInstigateAcks) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicNewTokenFrame* new_token = new QuicNewTokenFrame();
  EXPECT_CALL(visitor_, OnNewTokenReceived(_));
  ProcessFramePacket(QuicFrame(new_token));

  // Ensure that this has caused the ACK alarm to be set.
  EXPECT_TRUE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, ServerClosesConnectionOnNewTokenFrame) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  QuicNewTokenFrame* new_token = new QuicNewTokenFrame();
  EXPECT_CALL(visitor_, OnNewTokenReceived(_)).Times(0);
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  ProcessFramePacket(QuicFrame(new_token));
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest, OverrideRetryTokenWithRetryPacket) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  std::string address_token = "TestAddressToken";
  connection_.SetSourceAddressTokenToSend(address_token);
  EXPECT_EQ(QuicPacketCreatorPeer::GetRetryToken(
                QuicConnectionPeer::GetPacketCreator(&connection_)),
            address_token);
  // Passes valid retry and verify token gets overridden.
  TestClientRetryHandling(/*invalid_retry_tag=*/false,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/false);
}

TEST_P(QuicConnectionTest, DonotOverrideRetryTokenWithAddressToken) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  // Passes valid retry and verify token gets overridden.
  TestClientRetryHandling(/*invalid_retry_tag=*/false,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/false);
  std::string retry_token = QuicPacketCreatorPeer::GetRetryToken(
      QuicConnectionPeer::GetPacketCreator(&connection_));

  std::string address_token = "TestAddressToken";
  connection_.SetSourceAddressTokenToSend(address_token);
  EXPECT_EQ(QuicPacketCreatorPeer::GetRetryToken(
                QuicConnectionPeer::GetPacketCreator(&connection_)),
            retry_token);
}

TEST_P(QuicConnectionTest,
       ServerReceivedZeroRttWithHigherPacketNumberThanOneRtt) {
  if (!connection_.version().UsesTls()) {
    return;
  }

  // The code that checks for this error piggybacks on some book-keeping state
  // kept for key update, so enable key update for the test.
  std::string error_details;
  TransportParameters params;
  QuicConfig config;
  EXPECT_THAT(config.ProcessTransportParameters(
                  params, /* is_resumption = */ false, &error_details),
              IsQuicNoError());
  QuicConfigPeer::SetNegotiated(&config, true);
  QuicConfigPeer::SetReceivedOriginalConnectionId(&config,
                                                  connection_.connection_id());
  QuicConfigPeer::SetReceivedInitialSourceConnectionId(
      &config, connection_.connection_id());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);

  set_perspective(Perspective::IS_SERVER);
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));

  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);

  // Finish handshake.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  notifier_.NeuterUnencryptedData();
  connection_.NeuterUnencryptedPackets();
  connection_.OnHandshakeComplete();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_COMPLETE));

  // Decrypt a 1-RTT packet.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(2, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(connection_.GetDiscardZeroRttDecryptionKeysAlarm()->IsSet());

  // 0-RTT packet with higher packet number than a 1-RTT packet is invalid and
  // should cause the connection to be closed.
  EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  ProcessDataPacketAtLevel(3, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(
      QUIC_INVALID_0RTT_PACKET_NUMBER_OUT_OF_ORDER);
}

// Regression test for b/177312785
TEST_P(QuicConnectionTest, PeerMigrateBeforeHandshakeConfirm) {
  if (!VersionHasIetfQuicFrames(version().transport_version)) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_START));

  // Clear direct_peer_address.
  QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
  // Clear effective_peer_address, it is the same as direct_peer_address for
  // this test.
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                              QuicSocketAddress());
  EXPECT_FALSE(connection_.effective_peer_address().IsInitialized());

  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());

  // Process another packet with a different peer address on server side will
  // close connection.
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0u);

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(0);
  ProcessFramePacketWithAddresses(QuicFrame(&frame), kSelfAddress,
                                  kNewPeerAddress, ENCRYPTION_INITIAL);
  EXPECT_FALSE(connection_.connected());
}

// Regresstion test for b/175685916
TEST_P(QuicConnectionTest, TryToFlushAckWithAckQueued) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  SetQuicReloadableFlag(quic_can_send_ack_frequency, true);
  set_perspective(Perspective::IS_SERVER);

  QuicConfig config;
  QuicConfigPeer::SetReceivedMinAckDelayMs(&config, /*min_ack_delay_ms=*/1);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();
  QuicPacketCreatorPeer::SetPacketNumber(creator_, 200);

  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_FORWARD_SECURE);
  // Sending ACK_FREQUENCY bundles ACK. QuicConnectionPeer::SendPing
  // will try to bundle ACK but there is no pending ACK.
  EXPECT_CALL(visitor_, SendAckFrequency(_))
      .WillOnce(Invoke(&notifier_,
                       &SimpleSessionNotifier::WriteOrBufferAckFrequency));
  QuicConnectionPeer::SendPing(&connection_);
}

TEST_P(QuicConnectionTest, PathChallengeBeforePeerIpAddressChangeAtServer) {
  set_perspective(Perspective::IS_SERVER);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);
  SetClientConnectionId(TestConnectionId(1));
  connection_.CreateConnectionIdManager();

  QuicConnectionId server_cid0 = connection_.connection_id();
  QuicConnectionId client_cid0 = connection_.client_connection_id();
  QuicConnectionId client_cid1 = TestConnectionId(2);
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
  connection_.MaybeSendConnectionIdToClient();
  // Receives new client CID from client.
  QuicNewConnectionIdFrame new_cid_frame;
  new_cid_frame.connection_id = client_cid1;
  new_cid_frame.sequence_number = 1u;
  new_cid_frame.retire_prior_to = 0u;
  connection_.OnNewConnectionIdFrame(new_cid_frame);
  auto* packet_creator = QuicConnectionPeer::GetPacketCreator(&connection_);
  ASSERT_EQ(packet_creator->GetDestinationConnectionId(), client_cid0);
  ASSERT_EQ(packet_creator->GetSourceConnectionId(), server_cid0);

  peer_creator_.SetServerConnectionId(server_cid1);
  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback4(), /*port=*/23456);
  QuicPathFrameBuffer path_challenge_payload{0, 1, 2, 3, 4, 5, 6, 7};
  QuicFrames frames1;
  frames1.push_back(
      QuicFrame(QuicPathChallengeFrame(0, path_challenge_payload)));
  QuicPathFrameBuffer payload;
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, NO_RETRANSMITTABLE_DATA))
      .Times(AtLeast(1))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
        EXPECT_EQ(kPeerAddress, connection_.peer_address());
        EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
        EXPECT_FALSE(writer_->path_response_frames().empty());
        EXPECT_FALSE(writer_->path_challenge_frames().empty());
        payload = writer_->path_challenge_frames().front().data_buffer;
      }))
      .WillRepeatedly(DoDefault());
  ;
  ProcessFramesPacketWithAddresses(frames1, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  const auto* default_path = QuicConnectionPeer::GetDefaultPath(&connection_);
  const auto* alternative_path =
      QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_EQ(default_path->client_connection_id, client_cid0);
  EXPECT_EQ(default_path->server_connection_id, server_cid0);
  EXPECT_EQ(alternative_path->client_connection_id, client_cid1);
  EXPECT_EQ(alternative_path->server_connection_id, server_cid1);
  EXPECT_EQ(packet_creator->GetDestinationConnectionId(), client_cid0);
  EXPECT_EQ(packet_creator->GetSourceConnectionId(), server_cid0);

  // Process another packet with a different peer address on server side will
  // start connection migration.
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE)).Times(1);
  EXPECT_CALL(visitor_, OnStreamFrame(_)).WillOnce(Invoke([=, this]() {
    EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  }));
  // IETF QUIC send algorithm should be changed to a different object, so no
  // OnPacketSent() called on the old send algorithm.
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, NO_RETRANSMITTABLE_DATA))
      .Times(0);
  QuicFrames frames2;
  frames2.push_back(QuicFrame(frame2_));
  ProcessFramesPacketWithAddresses(frames2, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            connection_.active_effective_peer_migration_type());
  EXPECT_TRUE(writer_->path_challenge_frames().empty());
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
  EXPECT_EQ(default_path->client_connection_id, client_cid1);
  EXPECT_EQ(default_path->server_connection_id, server_cid1);
  // The previous default path is kept as alternative path before reverse path
  // validation finishes.
  EXPECT_EQ(alternative_path->client_connection_id, client_cid0);
  EXPECT_EQ(alternative_path->server_connection_id, server_cid0);
  EXPECT_EQ(packet_creator->GetDestinationConnectionId(), client_cid1);
  EXPECT_EQ(packet_creator->GetSourceConnectionId(), server_cid1);

  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            connection_.active_effective_peer_migration_type());
  EXPECT_EQ(1u, connection_.GetStats()
                    .num_peer_migration_to_proactively_validated_address);

  // The PATH_CHALLENGE and PATH_RESPONSE is expanded upto the max packet size
  // which may exceeds the anti-amplification limit. Verify server is throttled
  // by anti-amplification limit.
  connection_.SendCryptoDataWithString("foo", 0);
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Receiving PATH_RESPONSE should lift the anti-amplification limit.
  QuicFrames frames3;
  frames3.push_back(QuicFrame(QuicPathResponseFrame(99, payload)));
  EXPECT_CALL(visitor_, MaybeSendAddressToken());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(testing::AtLeast(1u));
  ProcessFramesPacketWithAddresses(frames3, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(NO_CHANGE, connection_.active_effective_peer_migration_type());
  // Verify that alternative_path_ is cleared and the peer CID is retired.
  EXPECT_TRUE(alternative_path->client_connection_id.IsEmpty());
  EXPECT_TRUE(alternative_path->server_connection_id.IsEmpty());
  EXPECT_FALSE(alternative_path->stateless_reset_token.has_value());
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();

  // Verify the anti-amplification limit is lifted by sending a packet larger
  // than the anti-amplification limit.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  connection_.SendCryptoDataWithString(std::string(1200, 'a'), 0);
  EXPECT_EQ(1u, connection_.GetStats().num_validated_peer_migration);
  EXPECT_EQ(1u, connection_.num_unlinkable_client_migration());
}

TEST_P(QuicConnectionTest,
       PathValidationSucceedsBeforePeerIpAddressChangeAtServer) {
  set_perspective(Perspective::IS_SERVER);
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);
  connection_.CreateConnectionIdManager();

  QuicConnectionId server_cid0 = connection_.connection_id();
  QuicConnectionId server_cid1;
  // Sends new server CID to client.
  if (!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
        .WillOnce(Return(TestConnectionId(456)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_))
      .WillOnce(Invoke([&](const QuicConnectionId& c
```
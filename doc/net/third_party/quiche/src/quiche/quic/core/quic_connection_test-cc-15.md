Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `quic_connection_test.cc` file in Chromium's network stack.

I need to:
1. **Identify the main functionalities** demonstrated in the code. These appear to be related to connection idle timeout, liveness testing, PING frames, loss detection, path validation, and handling write errors during path validation.
2. **Check for JavaScript relevance**. Based on the code, it seems to be low-level network functionality, unlikely to have direct JavaScript interaction within the browser's standard API. However, it underlies network operations that JavaScript initiates.
3. **Illustrate with examples** where appropriate, including hypothetical inputs and outputs for logical reasoning.
4. **Point out common usage errors** from a programming perspective.
5. **Explain how a user action might lead to this code being executed**, focusing on debugging aspects.
6. **Summarize the overall functionality** of this specific part of the test file, considering it's part 16 of 24.

Let's break down the code sections and their functionalities:

- **`DisableLivenessTesting`**: Tests disabling liveness probes.
- **`SilentIdleTimeout`**: Tests the behavior when an idle timeout occurs without sending a probe.
- **`DoNotSendPing`**: Tests scenarios where PING frames are not sent based on connection activity and the `ShouldKeepConnectionAlive` visitor method.
- **`DuplicateAckCausesLostPackets`**: Tests how duplicate acknowledgments can trigger loss detection.
- **`ShorterIdleTimeoutOnSentPackets`**: Tests how sending packets affects the idle timeout.
- **`ReserializeInitialPacketInCoalescerAfterDiscardingInitialKey`**:  A regression test related to packet coalescing and key discarding.
- **`PathValidationOnNewSocketSuccess`**: Tests successful path validation on a new socket.
- **`PathValidationOnNewSocketWriteBlocked`**: Tests path validation when writing to a new socket is initially blocked.
- **`NewPathValidationCancelsPreviousOne`**: Tests that a new path validation request cancels the previous one.
- **`PathValidationRetry`**: Tests the retry mechanism for path validation.
- **`PathValidationReceivesStatelessReset`**: Tests how path validation handles stateless resets.
- **`SendPathChallengeUsingBlockedNewSocket`**: Tests sending PATH_CHALLENGE when the new socket is blocked.
- **`SendPathChallengeUsingBlockedDefaultSocket`**: Tests sending PATH_CHALLENGE when the default socket is blocked.
- **`SendPathChallengeFailOnNewSocket`**: Tests handling write errors on a new socket during path validation.
- **`SendPathChallengeFailOnDefaultPath`**: Tests handling write errors on the default socket during path validation.
- **`SendPathChallengeFailOnAlternativePeerAddress`**: Tests handling write errors when sending PATH_CHALLENGE to an alternative peer address.
- **`SendPathChallengeFailPacketTooBigOnAlternativePeerAddress`**: Tests handling "packet too big" errors during path validation to an alternative peer address.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 文件的第 16 部分，主要侧重于 **QUIC 连接的超时、保活机制、丢包检测以及路径验证**相关的测试。

以下是本部分代码的功能详细列表：

**1. 连接保活 (Liveness Testing):**

*   **`DisableLivenessTesting` 测试:**
    *   **功能:** 验证了可以通过 `DisableLivenessTesting()` 方法禁用连接的保活探测机制。禁用后，即使接近空闲超时，也不会发送保活探测包。
    *   **假设输入:**  配置连接，设置一个较短的空闲超时时间，禁用保活测试。
    *   **预期输出:** 在接近空闲超时时，`MaybeTestLiveness()` 返回 `false`，并且不会调用 `send_algorithm_->OnPacketSent()` 发送探测包。

**2. 静默空闲超时 (Silent Idle Timeout):**

*   **`SilentIdleTimeout` 测试:**
    *   **功能:** 模拟了服务器端在空闲超时后，不发送 PING 包直接关闭连接的情况。
    *   **假设输入:**  将连接设置为服务器端，模拟空闲超时。
    *   **预期输出:**  连接状态变为断开，调用 `visitor_->OnConnectionClosed()`，并且不会调用 `send_algorithm_->OnPacketSent()` 发送数据包（包括 PING）。

**3. 不发送 PING 包 (DoNotSendPing):**

*   **`DoNotSendPing` 测试:**
    *   **功能:**  测试在特定条件下，即使连接空闲，也不会发送 PING 包的情况。这通常与 `visitor_->ShouldKeepConnectionAlive()` 的返回值有关。
    *   **假设输入:**  完成握手，初始时 `ShouldKeepConnectionAlive` 返回 `true`，发送一些数据，触发 PING 告警。然后，将 `ShouldKeepConnectionAlive` 设置为 `false`。
    *   **预期输出:** 当 `ShouldKeepConnectionAlive` 为 `false` 时，即使 PING 告警触发，也不会调用 `send_algorithm_->OnPacketSent()` 发送 PING 包。

**4. 重复 ACK 导致丢包 (DuplicateAckCausesLostPackets):**

*   **`DuplicateAckCausesLostPackets` 测试:**
    *   **功能:**  这是一个回归测试，用于验证重复的 ACK 帧是否能正确触发丢包检测。
    *   **假设输入:**  发送多个数据包，然后接收到一些 ACK 帧，其中包含重复的确认信息。
    *   **预期输出:** 丢包算法 (`loss_algorithm_`) 会被调用，检测到丢失的数据包，并触发重传告警。即使后续收到新的 ACK，如果不再有新的确认包，丢包检测会取消。

**5. 发送数据包后缩短空闲超时 (ShorterIdleTimeoutOnSentPackets):**

*   **`ShorterIdleTimeoutOnSentPackets` 测试:**
    *   **功能:**  验证发送数据包后，空闲超时时间是否会被调整，但不会缩短到小于 PTO (Path Throughput Oscillation) 的延迟。
    *   **假设输入:**  配置连接，设置一个初始的空闲超时时间，发送一个数据包，并在稍后收到 ACK。
    *   **预期输出:**  发送数据包后，空闲超时时间会被延长，但不会因为发送数据包而立即大幅度延长，以避免频繁发送小包导致的超时时间抖动。收到 ACK 后，超时时间会根据 RTT 进行调整。

**6. 丢弃初始密钥后在合并器中重新序列化初始数据包 (ReserializeInitialPacketInCoalescerAfterDiscardingInitialKey):**

*   **`ReserializeInitialPacketInCoalescerAfterDiscardingInitialKey` 测试:**
    *   **功能:**  这是一个回归测试，确保在丢弃初始加密密钥后，仍然可以正确处理和重新序列化合并的数据包，避免潜在的崩溃问题。
    *   **假设输入:**  客户端发送初始加密数据，服务器端处理后升级加密级别，并尝试发送握手数据和待处理的 ACK。
    *   **预期输出:**  即使初始密钥被移除，合并器也能正确处理待发送的 ACK 帧，并且在需要发送连接关闭帧时不会发生崩溃。

**7. 新 Socket 上的路径验证成功 (PathValidationOnNewSocketSuccess):**

*   **`PathValidationOnNewSocketSuccess` 测试:**
    *   **功能:**  测试在新的网络路径上进行路径验证并成功的情况。
    *   **假设输入:**  客户端发起路径验证，指定新的本地地址和新的 `TestPacketWriter`。
    *   **预期输出:**  客户端会通过新的 `TestPacketWriter` 发送 PATH_CHALLENGE 帧，并在收到来自新路径的 PATH_RESPONSE 帧后，验证成功。

**8. 新 Socket 上的路径验证被写入阻塞 (PathValidationOnNewSocketWriteBlocked):**

*   **`PathValidationOnNewSocketWriteBlocked` 测试:**
    *   **功能:**  测试当尝试在新 Socket 上进行路径验证时，如果写入操作被阻塞，连接如何处理。
    *   **假设输入:**  客户端发起路径验证，使用一个初始状态为写入阻塞的 `TestPacketWriter`。
    *   **预期输出:**  初始写入会失败，路径验证会处于挂起状态。当写入变为可操作后，会重新尝试发送 PATH_CHALLENGE。

**9. 新的路径验证取消之前的验证 (NewPathValidationCancelsPreviousOne):**

*   **`NewPathValidationCancelsPreviousOne` 测试:**
    *   **功能:**  测试当发起新的路径验证请求时，是否会取消正在进行的旧的路径验证请求。
    *   **假设输入:**  客户端发起一个路径验证请求，然后立即发起另一个到不同的本地地址的路径验证请求。
    *   **预期输出:**  之前的路径验证会被取消，只进行新的路径验证。

**10. 路径验证重试 (PathValidationRetry):**

*   **`PathValidationRetry` 测试:**
    *   **功能:**  测试路径验证的重试机制，当在一定时间内没有收到响应时，会重新发送 PATH_CHALLENGE。
    *   **假设输入:**  客户端发起路径验证，等待超过重试时间。
    *   **预期输出:**  在超时后，会重新发送 PATH_CHALLENGE 帧。

**11. 路径验证接收到无状态重置 (PathValidationReceivesStatelessReset):**

*   **`PathValidationReceivesStatelessReset` 测试:**
    *   **功能:**  测试在进行路径验证时，如果收到无状态重置包，连接会如何处理。
    *   **假设输入:**  客户端发起路径验证，然后模拟接收到一个来自新路径的无状态重置包。
    *   **预期输出:**  路径验证会被取消，连接不会被立即关闭（因为是来自一个正在验证的路径）。

**12. 使用阻塞的新 Socket 发送 PATH_CHALLENGE (SendPathChallengeUsingBlockedNewSocket):**

*   **`SendPathChallengeUsingBlockedNewSocket` 测试:**
    *   **功能:**  测试当尝试通过一个写入被阻塞的新 Socket 发送 PATH_CHALLENGE 时，会发生什么。
    *   **假设输入:**  客户端发起路径验证，使用一个初始状态为写入阻塞的 `TestPacketWriter`。
    *   **预期输出:**  即使 Socket 被阻塞，PATH_CHALLENGE 也会被标记为已发送（但实际上可能没有发送出去），并且在 Socket 变为可写后可能会被发送。

**13. 使用阻塞的默认 Socket 发送 PATH_CHALLENGE (SendPathChallengeUsingBlockedDefaultSocket):**

*   **`SendPathChallengeUsingBlockedDefaultSocket` 测试:**
    *   **功能:**  测试当尝试通过默认的、写入被阻塞的 Socket 发送 PATH_CHALLENGE 时，会发生什么。
    *   **假设输入:**  服务器端接收到来自新对端地址的 PATH_CHALLENGE，并尝试通过阻塞的默认 Socket 发送 PATH_RESPONSE。
    *   **预期输出:**  PATH_RESPONSE 会被缓冲，直到 Socket 变为可写。后续的重试发送 PATH_CHALLENGE 请求会被丢弃。

**14. 在新 Socket 上发送 PATH_CHALLENGE 失败 (SendPathChallengeFailOnNewSocket):**

*   **`SendPathChallengeFailOnNewSocket` 测试:**
    *   **功能:**  测试当尝试通过新的 Socket 发送 PATH_CHALLENGE 时发生写入错误，连接会如何处理。
    *   **假设输入:**  客户端发起路径验证，使用一个会返回写入错误的 `TestPacketWriter`。
    *   **预期输出:**  写入错误会被忽略，连接仍然保持连接状态，但路径验证可能会失败。

**15. 在默认路径上发送 PATH_CHALLENGE 失败 (SendPathChallengeFailOnDefaultPath):**

*   **`SendPathChallengeFailOnDefaultPath` 测试:**
    *   **功能:**  测试当尝试通过默认 Socket 发送 PATH_CHALLENGE 时发生写入错误，连接会如何处理。
    *   **假设输入:**  客户端发起路径验证，使用一个会返回写入错误的默认 `TestPacketWriter`。
    *   **预期输出:**  写入错误会导致连接关闭。

**16. 向备用对端地址发送 PATH_CHALLENGE 失败 (SendPathChallengeFailOnAlternativePeerAddress):**

*   **`SendPathChallengeFailOnAlternativePeerAddress` 测试:**
    *   **功能:**  测试当尝试向备用对端地址发送 PATH_CHALLENGE 时发生写入错误，连接会如何处理。
    *   **假设输入:**  客户端发起路径验证，目标是备用对端地址，使用一个会返回写入错误的默认 `TestPacketWriter`。
    *   **预期输出:**  写入错误会导致连接关闭。

**17. 向备用对端地址发送 PATH_CHALLENGE 失败，原因是包太大 (SendPathChallengeFailPacketTooBigOnAlternativePeerAddress):**

*   **`SendPathChallengeFailPacketTooBigOnAlternativePeerAddress` 测试:**
    *   **功能:** 测试当尝试向备用对端地址发送 PATH_CHALLENGE 时，由于包太大而发生写入错误，连接会如何处理。
    *   **假设输入:** 客户端发起路径验证，目标是备用对端地址，默认 `TestPacketWriter` 模拟返回 "包太大" 的错误。
    *   **预期输出:**  连接不会立即关闭，因为这可能是由于路径 MTU 发现导致的。连接会尝试其他机制，例如调整包大小。

**与 JavaScript 的关系：**

这段 C++ 代码是 Chromium 网络栈的底层实现，直接与 JavaScript 没有交互。然而，JavaScript 发起的网络请求（例如，通过 `fetch` API 或 `XMLHttpRequest`）最终会由这些底层的 C++ 代码处理。

*   **例如：** 当一个 JavaScript 应用使用 `fetch` API 请求一个资源时，浏览器会建立一个 QUIC 连接（如果适用）。这段代码中测试的超时、保活、丢包检测和路径验证机制，都直接影响着这个 QUIC 连接的稳定性和性能。如果连接因为空闲超时而关闭，或者因为丢包严重而中断，JavaScript 代码可能会收到网络错误。

**用户或编程常见的使用错误：**

*   **配置不当的超时时间:**  如果编程时设置了过短的空闲超时时间，可能会导致连接频繁断开，影响用户体验。
*   **没有正确处理网络错误:**  JavaScript 开发者需要妥善处理 `fetch` 或 `XMLHttpRequest` 返回的网络错误，这些错误可能源于底层 QUIC 连接的问题，例如超时或连接被重置。
*   **在移动网络环境下不合理的假设:**  移动网络的波动性较高，可能会频繁切换网络路径。如果不对路径验证和迁移做合理的处理，可能导致连接不稳定。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个使用 HTTPS 的网站 (例如，使用了 QUIC 协议)。**
2. **浏览器尝试与服务器建立 QUIC 连接。**
3. **连接建立后，如果一段时间内没有数据传输，QUIC 连接可能会触发空闲超时机制，这段代码中的测试用例模拟了这种情况。**
4. **如果网络环境发生变化（例如，用户从 Wi-Fi 切换到移动数据），QUIC 连接可能会尝试进行路径验证，以确保连接的有效性。这段代码测试了路径验证的各种场景。**
5. **如果网络质量不稳定，可能发生丢包，QUIC 连接的丢包检测机制会被触发，这段代码测试了相关的逻辑。**
6. **在开发和测试阶段，网络工程师或 Chromium 开发者可能会运行这些单元测试，以确保 QUIC 连接的各种功能正常工作。**

**本部分的功能归纳 (作为第 16 部分):**

本部分主要集中在 QUIC 连接的 **健壮性和适应性** 方面。它测试了连接在不同网络条件下的行为，例如空闲状态、丢包情况以及网络路径变化时的处理。通过这些测试，可以确保 QUIC 连接能够在各种复杂网络环境中保持稳定和高效。作为测试套件的一部分，这部分确保了 QUIC 连接的核心机制（超时、保活、丢包检测、路径验证）的正确实现，为用户提供可靠的网络连接体验。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第16部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
rsion().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }

  connection_.SetFromConfig(config);
  connection_.OnHandshakeComplete();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  ASSERT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.MaybeTestLiveness());

  QuicTime deadline = QuicConnectionPeer::GetIdleNetworkDeadline(&connection_);
  QuicTime::Delta timeout = deadline - clock_.ApproximateNow();
  // Advance time to near the idle timeout.
  clock_.AdvanceTime(timeout - QuicTime::Delta::FromMilliseconds(1));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  EXPECT_TRUE(connection_.MaybeTestLiveness());
  // Verify idle deadline does not change.
  EXPECT_EQ(deadline, QuicConnectionPeer::GetIdleNetworkDeadline(&connection_));
}

TEST_P(QuicConnectionTest, DisableLivenessTesting) {
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

  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }

  connection_.SetFromConfig(config);
  connection_.OnHandshakeComplete();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.DisableLivenessTesting();
  ASSERT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.MaybeTestLiveness());

  QuicTime deadline = QuicConnectionPeer::GetIdleNetworkDeadline(&connection_);
  QuicTime::Delta timeout = deadline - clock_.ApproximateNow();
  // Advance time to near the idle timeout.
  clock_.AdvanceTime(timeout - QuicTime::Delta::FromMilliseconds(1));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  EXPECT_FALSE(connection_.MaybeTestLiveness());
}

TEST_P(QuicConnectionTest, SilentIdleTimeout) {
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  if (version().SupportsAntiAmplificationLimit()) {
    QuicConnectionPeer::SetAddressValidated(&connection_);
  }

  QuicConfig config;
  QuicConfigPeer::SetNegotiated(&config, true);
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(&config,
                                                         QuicConnectionId());
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);

  EXPECT_TRUE(connection_.connected());
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());

  if (version().handshake_protocol == PROTOCOL_TLS1_3) {
    EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  }
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.GetTimeoutAlarm()->Fire();
  // Verify the connection close packets get serialized and added to
  // termination packets list.
  EXPECT_NE(nullptr,
            QuicConnectionPeer::GetConnectionClosePacket(&connection_));
}

TEST_P(QuicConnectionTest, DoNotSendPing) {
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(0, connection_.transport_version()),
      "GET /", 0, FIN, nullptr);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(15),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Now recevie an ACK and response of the previous packet, which will move the
  // ping alarm forward.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  QuicFrames frames;
  QuicAckFrame ack_frame = InitAckFrame(1);
  frames.push_back(QuicFrame(&ack_frame));
  frames.push_back(QuicFrame(QuicStreamFrame(
      GetNthClientInitiatedStreamId(0, connection_.transport_version()), true,
      0u, absl::string_view())));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessFramesPacketAtLevel(1, frames, ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  // The ping timer is set slightly less than 15 seconds in the future, because
  // of the 1s ping timer alarm granularity.
  EXPECT_EQ(
      QuicTime::Delta::FromSeconds(15) - QuicTime::Delta::FromMilliseconds(5),
      connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(15));
  // Suppose now ShouldKeepConnectionAlive returns false.
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(false));
  // Verify PING does not get sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.GetPingAlarm()->Fire();
}

// Regression test for b/159698337
TEST_P(QuicConnectionTest, DuplicateAckCausesLostPackets) {
  if (!GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2)) {
    return;
  }
  // Finish handshake.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  notifier_.NeuterUnencryptedData();
  connection_.NeuterUnencryptedPackets();
  connection_.OnHandshakeComplete();
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));

  std::string data(1200, 'a');
  // Send data packets 1 - 5.
  for (size_t i = 0; i < 5; ++i) {
    SendStreamDataToPeer(
        GetNthClientInitiatedStreamId(1, connection_.transport_version()), data,
        i * 1200, i == 4 ? FIN : NO_FIN, nullptr);
  }
  ASSERT_TRUE(connection_.BlackholeDetectionInProgress());

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(3);

  // ACK packet 5 and 1 and 2 are detected lost.
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(5), QuicPacketNumber(6)}});
  LostPacketVector lost_packets;
  lost_packets.push_back(
      LostPacket(QuicPacketNumber(1), kMaxOutgoingPacketSize));
  lost_packets.push_back(
      LostPacket(QuicPacketNumber(2), kMaxOutgoingPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .Times(AnyNumber())
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())))
      .WillRepeatedly(DoDefault());
  ;
  ProcessAckPacket(1, &frame);
  EXPECT_TRUE(connection_.BlackholeDetectionInProgress());
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // ACK packet 1 - 5 and 7.
  QuicAckFrame frame2 =
      InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(6)},
                    {QuicPacketNumber(7), QuicPacketNumber(8)}});
  ProcessAckPacket(2, &frame2);
  EXPECT_TRUE(connection_.BlackholeDetectionInProgress());

  // ACK packet 7 again and assume packet 6 is detected lost.
  QuicAckFrame frame3 =
      InitAckFrame({{QuicPacketNumber(7), QuicPacketNumber(8)}});
  lost_packets.clear();
  lost_packets.push_back(
      LostPacket(QuicPacketNumber(6), kMaxOutgoingPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .Times(AnyNumber())
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())));
  ProcessAckPacket(3, &frame3);
  // Make sure loss detection is cancelled even there is no new acked packets.
  EXPECT_FALSE(connection_.BlackholeDetectionInProgress());
}

TEST_P(QuicConnectionTest, ShorterIdleTimeoutOnSentPackets) {
  EXPECT_TRUE(connection_.connected());
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.SetClientConnectionOptions(QuicTagVector{kFIDT});
  QuicConfigPeer::SetNegotiated(&config, true);
  if (GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2)) {
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_COMPLETE));
  }
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }
  connection_.SetFromConfig(config);

  ASSERT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  // Send a packet close to timeout.
  QuicTime::Delta timeout =
      connection_.GetTimeoutAlarm()->deadline() - clock_.Now();
  clock_.AdvanceTime(timeout - QuicTime::Delta::FromSeconds(1));
  // Send stream data.
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, FIN, nullptr);
  // Verify this sent packet does not extend idle timeout since 1s is > PTO
  // delay.
  ASSERT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(1),
            connection_.GetTimeoutAlarm()->deadline() - clock_.Now());

  // Received an ACK 100ms later.
  clock_.AdvanceTime(timeout - QuicTime::Delta::FromMilliseconds(100));
  QuicAckFrame ack = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(1, &ack);
  // Verify idle timeout gets extended.
  EXPECT_EQ(clock_.Now() + timeout, connection_.GetTimeoutAlarm()->deadline());
}

// Regression test for b/166255274
TEST_P(QuicConnectionTest,
       ReserializeInitialPacketInCoalescerAfterDiscardingInitialKey) {
  if (!connection_.version().CanSendCoalescedPackets()) {
    return;
  }
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());
  connection_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).WillOnce(Invoke([this]() {
    connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
    connection_.NeuterUnencryptedPackets();
  }));
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_HANDSHAKE);
    // Verify the packet is on hold.
    EXPECT_EQ(0u, writer_->packets_write_attempts());
    // Flush pending ACKs.
    connection_.GetAckAlarm()->Fire();
  }
  EXPECT_FALSE(connection_.packet_creator().HasPendingFrames());
  // The ACK frame is deleted along with initial_packet_ in coalescer. Sending
  // connection close would cause this (released) ACK frame be serialized (and
  // crashes).
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(1000, false, ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(connection_.connected());
}

TEST_P(QuicConnectionTest, PathValidationOnNewSocketSuccess) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_NE(kNewSelfAddress, connection_.self_address());
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, new_writer.packets_write_attempts());
        EXPECT_EQ(1u, new_writer.path_challenge_frames().size());
        EXPECT_EQ(1u, new_writer.padding_frames().size());
        EXPECT_EQ(kNewSelfAddress.host(),
                  new_writer.last_write_source_address());
      }))
      .WillRepeatedly(DoDefault());
  ;
  bool success = false;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), &new_writer),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);
  EXPECT_EQ(0u, writer_->packets_write_attempts());

  QuicFrames frames;
  frames.push_back(QuicFrame(QuicPathResponseFrame(
      99, new_writer.path_challenge_frames().front().data_buffer)));
  ProcessFramesPacketWithAddresses(frames, kNewSelfAddress, kPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(success);
}

TEST_P(QuicConnectionTest, PathValidationOnNewSocketWriteBlocked) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_NE(kNewSelfAddress, connection_.self_address());
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  new_writer.SetWriteBlocked();
  bool success = false;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), &new_writer),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);
  EXPECT_EQ(0u, new_writer.packets_write_attempts());
  EXPECT_TRUE(connection_.HasPendingPathValidation());

  new_writer.SetWritable();
  // Retry after time out.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
  static_cast<test::MockRandom*>(helper_->GetRandomGenerator())->ChangeValue();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, new_writer.packets_write_attempts());
        EXPECT_EQ(1u, new_writer.path_challenge_frames().size());
        EXPECT_EQ(1u, new_writer.padding_frames().size());
        EXPECT_EQ(kNewSelfAddress.host(),
                  new_writer.last_write_source_address());
      }));
  static_cast<TestAlarmFactory::TestAlarm*>(
      QuicPathValidatorPeer::retry_timer(
          QuicConnectionPeer::path_validator(&connection_)))
      ->Fire();
  EXPECT_EQ(1u, new_writer.packets_write_attempts());

  QuicFrames frames;
  QuicPathFrameBuffer path_frame_buffer{0, 1, 2, 3, 4, 5, 6, 7};
  frames.push_back(QuicFrame(QuicPathChallengeFrame(0, path_frame_buffer)));
  new_writer.SetWriteBlocked();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillRepeatedly(Invoke([&] {
        // Packets other than PATH_RESPONSE may be sent over the default writer.
        EXPECT_EQ(1u, new_writer.packets_write_attempts());
        EXPECT_TRUE(new_writer.path_response_frames().empty());
        EXPECT_EQ(1u, writer_->packets_write_attempts());
      }));
  ProcessFramesPacketWithAddresses(frames, kNewSelfAddress,
                                   connection_.peer_address(),
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(1u, new_writer.packets_write_attempts());
}

TEST_P(QuicConnectionTest, NewPathValidationCancelsPreviousOne) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_NE(kNewSelfAddress, connection_.self_address());
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, new_writer.packets_write_attempts());
        EXPECT_EQ(1u, new_writer.path_challenge_frames().size());
        EXPECT_EQ(1u, new_writer.padding_frames().size());
        EXPECT_EQ(kNewSelfAddress.host(),
                  new_writer.last_write_source_address());
      }));
  bool success = true;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), &new_writer),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);
  EXPECT_EQ(0u, writer_->packets_write_attempts());

  // Start another path validation request.
  const QuicSocketAddress kNewSelfAddress2(QuicIpAddress::Any4(), 12346);
  EXPECT_NE(kNewSelfAddress2, connection_.self_address());
  TestPacketWriter new_writer2(version(), &clock_, Perspective::IS_CLIENT);
  bool success2 = false;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress2, connection_.peer_address(), &new_writer2),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress2, connection_.peer_address(),
          &success2),
      PathValidationReason::kReasonUnknown);
  EXPECT_FALSE(success);
  // There is no pening path validation as there is no available connection ID.
  EXPECT_FALSE(connection_.HasPendingPathValidation());
}

// Regression test for b/182571515.
TEST_P(QuicConnectionTest, PathValidationRetry) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(2u)
      .WillRepeatedly(Invoke([&]() {
        EXPECT_EQ(1u, writer_->path_challenge_frames().size());
        EXPECT_EQ(1u, writer_->padding_frames().size());
      }));
  bool success = true;
  connection_.ValidatePath(std::make_unique<TestQuicPathValidationContext>(
                               connection_.self_address(),
                               connection_.peer_address(), writer_.get()),
                           std::make_unique<TestValidationResultDelegate>(
                               &connection_, connection_.self_address(),
                               connection_.peer_address(), &success),
                           PathValidationReason::kReasonUnknown);
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_TRUE(connection_.HasPendingPathValidation());

  // Retry after time out.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
  static_cast<test::MockRandom*>(helper_->GetRandomGenerator())->ChangeValue();
  static_cast<TestAlarmFactory::TestAlarm*>(
      QuicPathValidatorPeer::retry_timer(
          QuicConnectionPeer::path_validator(&connection_)))
      ->Fire();
  EXPECT_EQ(2u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, PathValidationReceivesStatelessReset) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  QuicConfig config;
  QuicConfigPeer::SetReceivedStatelessResetToken(&config,
                                                 kTestStatelessResetToken);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_NE(kNewSelfAddress, connection_.self_address());
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, new_writer.packets_write_attempts());
        EXPECT_EQ(1u, new_writer.path_challenge_frames().size());
        EXPECT_EQ(1u, new_writer.padding_frames().size());
        EXPECT_EQ(kNewSelfAddress.host(),
                  new_writer.last_write_source_address());
      }))
      .WillRepeatedly(DoDefault());
  ;
  bool success = true;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), &new_writer),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);
  EXPECT_EQ(0u, writer_->packets_write_attempts());
  EXPECT_TRUE(connection_.HasPendingPathValidation());

  std::unique_ptr<QuicEncryptedPacket> packet(
      QuicFramer::BuildIetfStatelessResetPacket(connection_id_,
                                                /*received_packet_length=*/100,
                                                kTestStatelessResetToken));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*packet, QuicTime::Zero()));
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(0);
  connection_.ProcessUdpPacket(kNewSelfAddress, kPeerAddress, *received);
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_FALSE(success);
}

// Tests that PATH_CHALLENGE is dropped if it is sent via a blocked alternative
// writer.
TEST_P(QuicConnectionTest, SendPathChallengeUsingBlockedNewSocket) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_NE(kNewSelfAddress, connection_.self_address());
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  new_writer.BlockOnNextWrite();
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(0);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1))
      .WillOnce(Invoke([&]() {
        // Even though the socket is blocked, the PATH_CHALLENGE should still be
        // treated as sent.
        EXPECT_EQ(1u, new_writer.packets_write_attempts());
        EXPECT_EQ(1u, new_writer.path_challenge_frames().size());
        EXPECT_EQ(1u, new_writer.padding_frames().size());
        EXPECT_EQ(kNewSelfAddress.host(),
                  new_writer.last_write_source_address());
      }))
      .WillRepeatedly(DoDefault());
  ;
  bool success = false;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), &new_writer),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);
  EXPECT_EQ(0u, writer_->packets_write_attempts());

  new_writer.SetWritable();
  // Write event on the default socket shouldn't make any difference.
  connection_.OnCanWrite();
  // A NEW_CONNECTION_ID frame is received in PathProbeTestInit and OnCanWrite
  // will write a acking packet.
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_EQ(1u, new_writer.packets_write_attempts());
}

//  Tests that PATH_CHALLENGE is dropped if it is sent via the default writer
//  and the writer is blocked.
TEST_P(QuicConnectionTest, SendPathChallengeUsingBlockedDefaultSocket) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Any4(), 12345);
  writer_->BlockOnNextWrite();
  // 1st time is after writer returns WRITE_STATUS_BLOCKED. 2nd time is in
  // ShouldGeneratePacket().
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AtLeast(2));
  QuicPathFrameBuffer path_challenge_payload{0, 1, 2, 3, 4, 5, 6, 7};
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([&]() {
        // This packet isn't sent actually, instead it is buffered in the
        // connection.
        EXPECT_EQ(1u, writer_->packets_write_attempts());
        EXPECT_EQ(1u, writer_->path_response_frames().size());
        EXPECT_EQ(0,
                  memcmp(&path_challenge_payload,
                         &writer_->path_response_frames().front().data_buffer,
                         sizeof(path_challenge_payload)));
        EXPECT_EQ(1u, writer_->path_challenge_frames().size());
        EXPECT_EQ(1u, writer_->padding_frames().size());
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
      }))
      .WillRepeatedly(Invoke([&]() {
        // Only one PATH_CHALLENGE should be sent out.
        EXPECT_EQ(0u, writer_->path_challenge_frames().size());
      }));
  // Receiving a PATH_CHALLENGE from the new peer address should trigger address
  // validation.
  QuicFrames frames;
  frames.push_back(
      QuicFrame(QuicPathChallengeFrame(0, path_challenge_payload)));
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  // Try again with the new socket blocked from the beginning. The 2nd
  // PATH_CHALLENGE shouldn't be serialized, but be dropped.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3 * kInitialRttMs));
  static_cast<test::MockRandom*>(helper_->GetRandomGenerator())->ChangeValue();
  static_cast<TestAlarmFactory::TestAlarm*>(
      QuicPathValidatorPeer::retry_timer(
          QuicConnectionPeer::path_validator(&connection_)))
      ->Fire();

  // No more write attempt should be made.
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  writer_->SetWritable();
  // OnCanWrite() should actually write out the 1st PATH_CHALLENGE packet
  // buffered earlier, thus incrementing the write counter. It may also send
  // ACKs to previously received packets.
  connection_.OnCanWrite();
  EXPECT_LE(2u, writer_->packets_write_attempts());
}

// Tests that write error on the alternate socket should be ignored.
TEST_P(QuicConnectionTest, SendPathChallengeFailOnNewSocket) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_NE(kNewSelfAddress, connection_.self_address());
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  new_writer.SetShouldWriteFail();
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .Times(0);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0u);

  bool success = false;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), &new_writer),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);
  EXPECT_EQ(1u, new_writer.packets_write_attempts());
  EXPECT_EQ(1u, new_writer.path_challenge_frames().size());
  EXPECT_EQ(1u, new_writer.padding_frames().size());
  EXPECT_EQ(kNewSelfAddress.host(), new_writer.last_write_source_address());

  EXPECT_EQ(0u, writer_->packets_write_attempts());
  //  Regardless of the write error, the connection should still be connected.
  EXPECT_TRUE(connection_.connected());
}

// Tests that write error while sending PATH_CHALLANGE from the default socket
// should close the connection.
TEST_P(QuicConnectionTest, SendPathChallengeFailOnDefaultPath) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);

  writer_->SetShouldWriteFail();
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(
          Invoke([](QuicConnectionCloseFrame frame, ConnectionCloseSource) {
            EXPECT_EQ(QUIC_PACKET_WRITE_ERROR, frame.quic_error_code);
          }));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0u);
  {
    // Add a flusher to force flush, otherwise the frames will remain in the
    // packet creator.
    bool success = false;
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.ValidatePath(std::make_unique<TestQuicPathValidationContext>(
                                 connection_.self_address(),
                                 connection_.peer_address(), writer_.get()),
                             std::make_unique<TestValidationResultDelegate>(
                                 &connection_, connection_.self_address(),
                                 connection_.peer_address(), &success),
                             PathValidationReason::kReasonUnknown);
  }
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_EQ(1u, writer_->path_challenge_frames().size());
  EXPECT_EQ(1u, writer_->padding_frames().size());
  EXPECT_EQ(connection_.peer_address(), writer_->last_write_peer_address());
  EXPECT_FALSE(connection_.connected());
  // Closing connection should abandon ongoing path validation.
  EXPECT_FALSE(connection_.HasPendingPathValidation());
}

TEST_P(QuicConnectionTest, SendPathChallengeFailOnAlternativePeerAddress) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);

  writer_->SetShouldWriteFail();
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(
          Invoke([](QuicConnectionCloseFrame frame, ConnectionCloseSource) {
            EXPECT_EQ(QUIC_PACKET_WRITE_ERROR, frame.quic_error_code);
          }));
  // Sending PATH_CHALLENGE to trigger a flush write which will fail and close
  // the connection.
  bool success = false;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          connection_.self_address(), kNewPeerAddress, writer_.get()),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, connection_.self_address(), kNewPeerAddress, &success),
      PathValidationReason::kReasonUnknown);

  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_EQ(1u, writer_->path_challenge_frames().size());
  EXPECT_EQ(1u, writer_->padding_frames().size());
  EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest,
       SendPathChallengeFailPacketTooBigOnAlternativePeerAddress) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  // Make sure there is no outstanding ACK_FRAME to write.
  connection_.OnCanWrite();
  uint32_t num_packets_write_attempts = writer_->packets_write_attempts();

  writer_->SetShouldWriteFail();
  writer_->SetWriteError(*writer_->MessageTooBigErrorCode());
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Any4(), 12345);
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .Times(0u);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0u);
  // Sending PATH_CHALLENGE to trigger a flush write which will fail with
  // MSG_TOO_BIG.
  bool success = false;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          connection_.self_address(), kNewPeerAddress, writer_.get()),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, connection_.self_addres
```
Response:
The user wants a summary of the functionality of the provided C++ code, which is a test file for `QuicConnection` in Chromium's QUIC implementation.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file is a test suite (`*_test.cc`) for the `QuicConnection` class. This means it tests various aspects of how a QUIC connection behaves.

2. **Scan the test names:** The names of the `TEST_P` functions give clues about the specific functionalities being tested. Look for keywords like "ReceivePathChallenge", "ReceiveStreamFrame", "InitiateKeyUpdate", "Coalescer", etc.

3. **Analyze individual test cases:**  For each test, understand:
    * What scenario is being set up (e.g., receiving a PATH_CHALLENGE, receiving a STREAM frame, initiating a key update).
    * What actions are being performed (e.g., processing packets, sending data).
    * What the expected outcome is (using `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_CALL`). Pay attention to what is being asserted – connection state, sent frames, visitor method calls, etc.

4. **Look for patterns and groupings:**  Group related tests together. For example, several tests deal with PATH_CHALLENGE and PATH_RESPONSE frames. Others focus on key updates.

5. **Identify potential interactions with Javascript:**  QUIC is a transport protocol, and while the core implementation is in C++, it directly impacts how web browsers (which use Javascript) communicate. Focus on features related to security (key updates), network path changes (path validation), and connection establishment/handling.

6. **Consider error scenarios and debugging:**  Note tests that simulate errors or edge cases. Think about how a developer might encounter these issues during debugging.

7. **Infer user actions:**  Think about what user actions in a browser or application would lead to the QUIC connection behaviors being tested.

8. **Address the "part X of Y" request:**  The user specified that this is part 17 of 24. Consider what broader functionality the tests in this part might represent within the overall QUIC connection lifecycle.

9. **Formulate the summary:** Combine the observations into a concise description of the file's purpose and the specific functionalities it tests.

**Mental Walkthrough of Key Sections:**

* **`ReceivePathChallenge` family:** Tests how the connection reacts to incoming PATH_CHALLENGE frames, including sending PATH_RESPONSEs, handling multiple challenges, and interactions with other frame types. This is related to path validation and migration.
* **`ReceiveStreamFrame` interactions:**  Examines how receiving STREAM frames interacts with path validation, ensuring correct packet construction and handling of potential migration.
* **`FailToWritePathResponseAtServer`:**  Tests error handling during path response sending.
* **`HandshakeDataDoesNotGetPtoed` and `CoalescerHandlesInitialKeyDiscard`:** These tests are related to the handshake process and how the connection manages encryption keys and packet coalescing, especially during the initial stages.
* **`ZeroRttRejectionAndMissingInitialKeys` and `OnZeroRttPacketAcked`:** Focus on 0-RTT data transmission, its rejection scenarios, and the handling of acknowledgments.
* **`InitiateKeyUpdate` family:**  Covers the process of initiating and handling key updates, including local initiation, peer acceptance, and limits based on confidentiality.

**Relating to Javascript:**

* Path validation:  When a browser's network environment changes (e.g., Wi-Fi to cellular), QUIC performs path validation to ensure the connection remains viable. This is transparent to the Javascript code but ensures a more robust connection.
* Key updates:  QUIC's key update mechanism provides forward security. While Javascript doesn't directly control this, it benefits from the enhanced security of the underlying connection. A user browsing a secure website relies on this.
* 0-RTT:  This allows for faster connection establishment for returning clients, improving page load times, which is directly experienced by the user in the browser.

By following these steps and focusing on the test names and assertions, a comprehensive summary of the file's functionality can be constructed.
这个C++源代码文件 `quic_connection_test.cc` 是 Chromium 网络栈中 QUIC 协议核心连接功能 `QuicConnection` 的单元测试文件。它的主要功能是：

**核心功能：测试 `QuicConnection` 类的各种行为和状态转换。**

具体来说，这个文件中的测试用例覆盖了 `QuicConnection` 在以下场景中的行为：

* **路径验证 (Path Validation)：**
    * 接收和处理 `PATH_CHALLENGE` 帧。
    * 发送 `PATH_RESPONSE` 帧。
    * 处理接收到多个 `PATH_CHALLENGE` 的情况。
    * 在接收到 `PATH_CHALLENGE` 前后接收到 `STREAM` 帧的处理。
    * 在乱序包中接收到 `PATH_CHALLENGE` 的处理。
    * 测试当 `PATH_RESPONSE` 发送失败时的处理。
* **密钥更新 (Key Update)：**
    * 本地发起密钥更新。
    * 模拟对端接受密钥更新。
    * 测试在接近保密性限制时发起密钥更新。
    * 测试当保密性限制阻止密钥更新时关闭连接。
* **握手过程 (Handshake)：**
    * 确保握手数据不会被 PTO (Probing Transmission Opportunity) 触发重传。
    * 测试当丢弃 Initial 密钥时，数据包聚合器 (Coalescer) 的处理。
    * 测试 0-RTT 数据包被拒绝和缺少 Initial 密钥的情况。
    * 测试 0-RTT 数据包被确认 (ACKed) 的处理。
* **连接迁移 (Connection Migration)：** 虽然在这个代码片段中没有直接体现明显的连接迁移测试，但路径验证是连接迁移的基础，这些测试间接覆盖了相关逻辑。
* **数据包的发送和接收：**
    * 测试在不同加密级别下发送和接收数据包。
    * 测试数据包的聚合 (Coalescing)。
* **错误处理：**
    * 测试连接在特定错误条件下的关闭。
* **其他：**
    * 设置和使用 `QuicConfig`。
    * 与 `QuicConnectionVisitor` 的交互。
    * 与 `QuicPacketWriter` 的交互。
    * 与拥塞控制算法的交互。

**与 Javascript 功能的关系及举例说明：**

虽然这段 C++ 代码是 QUIC 协议的底层实现，但它直接影响着浏览器中 Javascript 的网络请求行为。

* **路径验证与网络切换：** 当用户在浏览器中进行操作，例如加载网页或发送数据时，如果网络环境发生变化（例如从 Wi-Fi 切换到蜂窝网络），QUIC 的路径验证机制会尝试验证新的网络路径是否可用。这保证了即使网络环境变化，用户的网络连接也能保持稳定，不会轻易中断。Javascript 代码无需关心底层的路径验证过程，但用户体验会得到提升，例如网页加载不会因为网络切换而卡住。
* **密钥更新与安全性：** QUIC 的密钥更新机制提供了前向安全性。用户在浏览器中访问 HTTPS 网站时，QUIC 会定期更新加密密钥，即使之前的密钥泄露，也无法解密之后的数据。Javascript 代码无需处理密钥更新，但用户浏览的安全性得到了保障。
* **0-RTT 连接与速度：** 对于曾经连接过的服务器，QUIC 允许客户端发送 0-RTT 数据，从而减少连接建立的延迟，加快页面加载速度。用户在浏览器中再次访问相同的网站时，会感觉加载速度更快。Javascript 代码发起的请求可以更快地到达服务器。

**逻辑推理、假设输入与输出：**

**假设输入：** 接收到一个包含 `PATH_CHALLENGE` 帧的数据包，源地址与当前连接地址不同。

**输出：**

1. `QuicConnection` 会生成一个包含 `PATH_RESPONSE` 帧的数据包，其中包含与 `PATH_CHALLENGE` 帧相同的数据。
2. `QuicConnection` 会将该 `PATH_RESPONSE` 数据包发送到接收到的 `PATH_CHALLENGE` 帧的源地址。
3. `QuicConnection` 会标记路径需要验证。
4. `QuicConnectionVisitor` 的 `OnConnectionMigration` 方法可能会被调用，具体取决于配置和网络环境。

**涉及用户或编程常见的使用错误及举例说明：**

* **配置错误：**  如果服务器或客户端的 QUIC 配置不正确，例如禁用了路径验证或密钥更新，可能会导致连接不稳定或安全性降低。例如，如果服务器错误地配置为不响应 `PATH_CHALLENGE`，客户端可能会错误地认为路径不可用而断开连接。
* **状态管理错误：** 在实现 QUIC 应用时，如果开发者没有正确管理连接的状态，例如在连接关闭后尝试发送数据，可能会导致程序崩溃或出现未定义的行为。例如，在 `QuicConnection` 已经进入关闭状态后，仍然调用发送数据的接口。
* **网络环境假设错误：** 开发者可能假设网络环境是静态的，没有考虑到网络切换或 NAT 重绑定等情况，导致程序在复杂网络环境下出现问题。例如，服务器端没有正确处理客户端 IP 地址变化的场景。

**用户操作是如何一步步的到达这里，作为调试线索：**

当网络工程师或 QUIC 协议开发者在 Chromium 项目中调试 QUIC 连接相关问题时，可能会逐步深入到 `quic_connection_test.cc` 文件中查找线索：

1. **用户报告网络连接问题：** 用户可能报告在使用 Chrome 浏览器访问特定网站时遇到连接断开、加载缓慢或安全警告等问题。
2. **网络团队初步排查：**  网络团队可能会使用网络抓包工具 (如 Wireshark) 捕获网络数据包，发现 QUIC 连接存在异常，例如路径验证失败、密钥更新失败或连接意外关闭。
3. **QUIC 协议开发者介入：**  QUIC 协议开发者会根据抓包信息和错误日志，初步判断问题可能与 `QuicConnection` 的核心逻辑有关。
4. **定位到 `QuicConnection` 相关代码：** 开发者可能会查看 `QuicConnection` 类的实现代码 (`quic_connection.cc`)，尝试理解连接状态转换和帧处理逻辑。
5. **查阅 `quic_connection_test.cc` 单元测试：** 为了更深入地理解 `QuicConnection` 在各种场景下的行为，开发者会查看 `quic_connection_test.cc` 文件中的单元测试用例。这些测试用例模拟了各种网络场景和帧交互，可以帮助开发者理解代码的预期行为和潜在的 bug。例如，如果怀疑路径验证存在问题，开发者会查看 `ReceivePathChallenge` 相关的测试用例。
6. **单步调试或添加日志：** 开发者可能会在 `quic_connection_test.cc` 中添加新的测试用例来复现用户报告的问题，或者在现有测试用例中添加断点或日志，进行单步调试，观察 `QuicConnection` 的状态变化和变量值，从而找到问题的根源。

**归纳一下它的功能 (作为第 17 部分，共 24 部分)：**

考虑到这是测试套件的第 17 部分，并且前面的部分可能已经测试了连接的建立、数据传输等基本功能，**这部分 (第 17 部分) 的功能很可能专注于测试 `QuicConnection` 的更高级和复杂的特性，例如路径验证和密钥更新在各种边缘情况下的行为**。

总而言之，`net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 的这段代码是 QUIC 连接核心逻辑的严格测试，确保了 QUIC 协议在各种网络条件和交互场景下的正确性和稳定性。这对于保证基于 QUIC 的网络应用（如 Chrome 浏览器）的可靠性和安全性至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第17部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
s(), kNewPeerAddress, &success),
      PathValidationReason::kReasonUnknown);
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  // Connection shouldn't be closed.
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(++num_packets_write_attempts, writer_->packets_write_attempts());
  EXPECT_EQ(1u, writer_->path_challenge_frames().size());
  EXPECT_EQ(1u, writer_->padding_frames().size());
  EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
}

// Check that if there are two PATH_CHALLENGE frames in the packet, the latter
// one is ignored.
TEST_P(QuicConnectionTest, ReceiveMultiplePathChallenge) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);

  QuicPathFrameBuffer path_frame_buffer1{0, 1, 2, 3, 4, 5, 6, 7};
  QuicPathFrameBuffer path_frame_buffer2{8, 9, 10, 11, 12, 13, 14, 15};
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicPathChallengeFrame(0, path_frame_buffer1)));
  frames.push_back(QuicFrame(QuicPathChallengeFrame(0, path_frame_buffer2)));
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback6(),
                                          /*port=*/23456);

  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);

  // Expect 2 packets to be sent: the first are padded PATH_RESPONSE(s) to the
  // alternative peer address. The 2nd is a ACK-only packet to the original
  // peer address.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(2)
      .WillOnce(Invoke([=, this]() {
        EXPECT_EQ(1u, writer_->path_response_frames().size());
        // The final check is to ensure that the random data in the response
        // matches the random data from the challenge.
        EXPECT_EQ(0,
                  memcmp(path_frame_buffer1.data(),
                         &(writer_->path_response_frames().front().data_buffer),
                         sizeof(path_frame_buffer1)));
        EXPECT_EQ(1u, writer_->padding_frames().size());
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
      }))
      .WillOnce(Invoke([=, this]() {
        // The last write of ACK-only packet should still use the old peer
        // address.
        EXPECT_EQ(kPeerAddress, writer_->last_write_peer_address());
      }));
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
}

TEST_P(QuicConnectionTest, ReceiveStreamFrameBeforePathChallenge) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);

  QuicFrames frames;
  frames.push_back(QuicFrame(frame1_));
  QuicPathFrameBuffer path_frame_buffer{0, 1, 2, 3, 4, 5, 6, 7};
  frames.push_back(QuicFrame(QuicPathChallengeFrame(0, path_frame_buffer)));
  frames.push_back(QuicFrame(QuicPaddingFrame(-1)));
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback4(),
                                          /*port=*/23456);

  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE));
  EXPECT_CALL(*send_algorithm_, OnConnectionMigration()).Times(0u);
  EXPECT_CALL(visitor_, OnStreamFrame(_))
      .WillOnce(Invoke([=, this](const QuicStreamFrame& frame) {
        // Send some data on the stream. The STREAM_FRAME should be built into
        // one packet together with the latter PATH_RESPONSE and PATH_CHALLENGE.
        const std::string data{"response body"};
        connection_.producer()->SaveStreamData(frame.stream_id, data);
        return notifier_.WriteOrBufferData(frame.stream_id, data.length(),
                                           NO_FIN);
      }));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0u);
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);

  // Verify that this packet contains a STREAM_FRAME and a
  // PATH_RESPONSE_FRAME.
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(1u, writer_->path_response_frames().size());
  EXPECT_EQ(1u, writer_->path_challenge_frames().size());
  // The final check is to ensure that the random data in the response
  // matches the random data from the challenge.
  EXPECT_EQ(0, memcmp(path_frame_buffer.data(),
                      &(writer_->path_response_frames().front().data_buffer),
                      sizeof(path_frame_buffer)));
  EXPECT_EQ(1u, writer_->path_challenge_frames().size());
  EXPECT_EQ(1u, writer_->padding_frames().size());
  EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
  EXPECT_TRUE(connection_.HasPendingPathValidation());
}

TEST_P(QuicConnectionTest, ReceiveStreamFrameFollowingPathChallenge) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);

  QuicFrames frames;
  QuicPathFrameBuffer path_frame_buffer{0, 1, 2, 3, 4, 5, 6, 7};
  frames.push_back(QuicFrame(QuicPathChallengeFrame(0, path_frame_buffer)));
  // PATH_RESPONSE should be flushed out before the rest packet is parsed.
  frames.push_back(QuicFrame(frame1_));
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback4(),
                                          /*port=*/23456);
  QuicByteCount received_packet_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([=, this, &received_packet_size]() {
        // Verify that this packet contains a PATH_RESPONSE_FRAME.
        EXPECT_EQ(0u, writer_->stream_frames().size());
        EXPECT_EQ(1u, writer_->path_response_frames().size());
        // The final check is to ensure that the random data in the response
        // matches the random data from the challenge.
        EXPECT_EQ(0,
                  memcmp(path_frame_buffer.data(),
                         &(writer_->path_response_frames().front().data_buffer),
                         sizeof(path_frame_buffer)));
        EXPECT_EQ(1u, writer_->path_challenge_frames().size());
        EXPECT_EQ(1u, writer_->padding_frames().size());
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
        received_packet_size =
            QuicConnectionPeer::BytesReceivedOnAlternativePath(&connection_);
      }));
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE));
  EXPECT_CALL(*send_algorithm_, OnConnectionMigration()).Times(0u);
  EXPECT_CALL(visitor_, OnStreamFrame(_))
      .WillOnce(Invoke([=, this](const QuicStreamFrame& frame) {
        // Send some data on the stream. The STREAM_FRAME should be built into a
        // new packet but throttled by anti-amplifciation limit.
        const std::string data{"response body"};
        connection_.producer()->SaveStreamData(frame.stream_id, data);
        return notifier_.WriteOrBufferData(frame.stream_id, data.length(),
                                           NO_FIN);
      }));

  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_EQ(0u,
            QuicConnectionPeer::BytesReceivedOnAlternativePath(&connection_));
  EXPECT_EQ(
      received_packet_size,
      QuicConnectionPeer::BytesReceivedBeforeAddressValidation(&connection_));
}

// Tests that a PATH_CHALLENGE is received in between other frames in an out of
// order packet.
TEST_P(QuicConnectionTest, PathChallengeWithDataInOutOfOrderPacket) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);

  QuicFrames frames;
  frames.push_back(QuicFrame(frame1_));
  QuicPathFrameBuffer path_frame_buffer{0, 1, 2, 3, 4, 5, 6, 7};
  frames.push_back(QuicFrame(QuicPathChallengeFrame(0, path_frame_buffer)));
  frames.push_back(QuicFrame(frame2_));
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback6(),
                                          /*port=*/23456);

  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0u);
  EXPECT_CALL(visitor_, OnStreamFrame(_))
      .Times(2)
      .WillRepeatedly(Invoke([=, this](const QuicStreamFrame& frame) {
        // Send some data on the stream. The STREAM_FRAME should be built into
        // one packet together with the latter PATH_RESPONSE.
        const std::string data{"response body"};
        connection_.producer()->SaveStreamData(frame.stream_id, data);
        return notifier_.WriteOrBufferData(frame.stream_id, data.length(),
                                           NO_FIN);
      }));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(Invoke([=, this]() {
        // Verify that this packet contains a STREAM_FRAME and is sent to the
        // original peer address.
        EXPECT_EQ(1u, writer_->stream_frames().size());
        // No connection migration should happen because the packet is received
        // out of order.
        EXPECT_EQ(kPeerAddress, writer_->last_write_peer_address());
      }))
      .WillOnce(Invoke([=, this]() {
        EXPECT_EQ(1u, writer_->path_response_frames().size());
        // The final check is to ensure that the random data in the response
        // matches the random data from the challenge.
        EXPECT_EQ(0,
                  memcmp(path_frame_buffer.data(),
                         &(writer_->path_response_frames().front().data_buffer),
                         sizeof(path_frame_buffer)));
        EXPECT_EQ(1u, writer_->padding_frames().size());
        // PATH_RESPONSE should be sent in another packet to a different peer
        // address.
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
      }))
      .WillOnce(Invoke([=, this]() {
        // Verify that this packet contains a STREAM_FRAME and is sent to the
        // original peer address.
        EXPECT_EQ(1u, writer_->stream_frames().size());
        // No connection migration should happen because the packet is received
        // out of order.
        EXPECT_EQ(kPeerAddress, writer_->last_write_peer_address());
      }));
  // Lower the packet number so that receiving this packet shouldn't trigger
  // peer migration.
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 1);
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
}

// Tests that a PATH_CHALLENGE is cached if its PATH_RESPONSE can't be sent.
TEST_P(QuicConnectionTest, FailToWritePathResponseAtServer) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);

  QuicFrames frames;
  QuicPathFrameBuffer path_frame_buffer{0, 1, 2, 3, 4, 5, 6, 7};
  frames.push_back(QuicFrame(QuicPathChallengeFrame(0, path_frame_buffer)));
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback6(),
                                          /*port=*/23456);

  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0u);
  // Lower the packet number so that receiving this packet shouldn't trigger
  // peer migration.
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 1);
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AtLeast(1));
  writer_->SetWriteBlocked();
  ProcessFramesPacketWithAddresses(frames, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
}

// Regression test for b/168101557.
TEST_P(QuicConnectionTest, HandshakeDataDoesNotGetPtoed) {
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
  // Send half RTT packet.
  connection_.SendStreamDataWithString(2, "foo", 0, NO_FIN);

  // Receives HANDSHAKE 1.
  peer_framer_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_HANDSHAKE);
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.NeuterUnencryptedPackets();
  // Verify there is pending ACK.
  ASSERT_TRUE(connection_.HasPendingAcks());
  // Set the send alarm.
  connection_.GetSendAlarm()->Set(clock_.ApproximateNow());

  // Fire ACK alarm.
  connection_.GetAckAlarm()->Fire();
  // Verify 1-RTT packet is coalesced with handshake packet.
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
  connection_.GetSendAlarm()->Fire();

  ASSERT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  connection_.GetRetransmissionAlarm()->Fire();
  // Verify a handshake packet gets PTOed and 1-RTT packet gets coalesced.
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
}

// Regression test for b/168294218.
TEST_P(QuicConnectionTest, CoalescerHandlesInitialKeyDiscard) {
  if (!connection_.version().CanSendCoalescedPackets()) {
    return;
  }
  SetQuicReloadableFlag(quic_discard_initial_packet_with_key_dropped, true);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).WillOnce(Invoke([this]() {
    connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
    connection_.NeuterUnencryptedPackets();
  }));
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());

  EXPECT_EQ(0u, connection_.GetStats().packets_discarded);
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
    connection_.SetEncrypter(
        ENCRYPTION_HANDSHAKE,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
    connection_.SendCryptoDataWithString(std::string(1200, 'a'), 0);
    // Verify this packet is on hold.
    EXPECT_EQ(0u, writer_->packets_write_attempts());
  }
  EXPECT_TRUE(connection_.connected());
}

// Regresstion test for b/168294218
TEST_P(QuicConnectionTest, ZeroRttRejectionAndMissingInitialKeys) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  // Not defer send in response to packet.
  connection_.set_defer_send_in_response_to_packets(false);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).WillOnce(Invoke([this]() {
    connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
    connection_.NeuterUnencryptedPackets();
  }));
  EXPECT_CALL(visitor_, OnCryptoFrame(_))
      .WillRepeatedly(Invoke([=, this](const QuicCryptoFrame& frame) {
        if (frame.level == ENCRYPTION_HANDSHAKE) {
          // 0-RTT gets rejected.
          connection_.MarkZeroRttPacketsForRetransmission(0);
          // Send Crypto data.
          connection_.SetEncrypter(
              ENCRYPTION_HANDSHAKE,
              std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
          connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
          connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_HANDSHAKE);
          connection_.SetEncrypter(
              ENCRYPTION_FORWARD_SECURE,
              std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
          connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
          // Advance INITIAL ack delay to trigger initial ACK to be sent AFTER
          // the retransmission of rejected 0-RTT packets while the HANDSHAKE
          // packet is still in the coalescer, such that the INITIAL key gets
          // dropped between SendAllPendingAcks and actually send the ack frame,
          // bummer.
          clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
        }
      }));
  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_INITIAL);
  // Send 0-RTT packet.
  connection_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  connection_.SendStreamDataWithString(2, "foo", 0, NO_FIN);

  QuicAckFrame frame1 = InitAckFrame(1);
  // Received ACK for packet 1.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  ProcessFramePacketAtLevel(1, QuicFrame(&frame1), ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Fire retransmission alarm.
  connection_.GetRetransmissionAlarm()->Fire();

  QuicFrames frames1;
  frames1.push_back(QuicFrame(&crypto_frame_));
  QuicFrames frames2;
  QuicCryptoFrame crypto_frame(ENCRYPTION_HANDSHAKE, 0,
                               absl::string_view(data1));
  frames2.push_back(QuicFrame(&crypto_frame));
  ProcessCoalescedPacket(
      {{2, frames1, ENCRYPTION_INITIAL}, {3, frames2, ENCRYPTION_HANDSHAKE}});
}

TEST_P(QuicConnectionTest, OnZeroRttPacketAcked) {
  if (!connection_.version().UsesTls()) {
    return;
  }
  MockQuicConnectionDebugVisitor debug_visitor;
  connection_.set_debug_visitor(&debug_visitor);
  connection_.SendCryptoStreamData();
  // Send 0-RTT packet.
  connection_.SetEncrypter(ENCRYPTION_ZERO_RTT,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  connection_.SendStreamDataWithString(2, "foo", 0, NO_FIN);
  connection_.SendStreamDataWithString(4, "bar", 0, NO_FIN);
  // Received ACK for packet 1, HANDSHAKE packet and 1-RTT ACK.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _))
      .Times(AnyNumber());
  QuicFrames frames1;
  QuicAckFrame ack_frame1 = InitAckFrame(1);
  frames1.push_back(QuicFrame(&ack_frame1));

  QuicFrames frames2;
  QuicCryptoFrame crypto_frame(ENCRYPTION_HANDSHAKE, 0,
                               absl::string_view(data1));
  frames2.push_back(QuicFrame(&crypto_frame));
  EXPECT_CALL(debug_visitor, OnZeroRttPacketAcked()).Times(0);
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  ProcessCoalescedPacket(
      {{1, frames1, ENCRYPTION_INITIAL}, {2, frames2, ENCRYPTION_HANDSHAKE}});

  QuicFrames frames3;
  QuicAckFrame ack_frame2 =
      InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)}});
  frames3.push_back(QuicFrame(&ack_frame2));
  EXPECT_CALL(debug_visitor, OnZeroRttPacketAcked()).Times(1);
  ProcessCoalescedPacket({{3, frames3, ENCRYPTION_FORWARD_SECURE}});

  QuicFrames frames4;
  QuicAckFrame ack_frame3 =
      InitAckFrame({{QuicPacketNumber(3), QuicPacketNumber(4)}});
  frames4.push_back(QuicFrame(&ack_frame3));
  EXPECT_CALL(debug_visitor, OnZeroRttPacketAcked()).Times(0);
  ProcessCoalescedPacket({{4, frames4, ENCRYPTION_FORWARD_SECURE}});
}

TEST_P(QuicConnectionTest, InitiateKeyUpdate) {
  if (!connection_.version().UsesTls()) {
    return;
  }

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

  EXPECT_FALSE(connection_.IsKeyUpdateAllowed());

  MockFramerVisitor peer_framer_visitor_;
  peer_framer_.set_visitor(&peer_framer_visitor_);

  uint8_t correct_tag = ENCRYPTION_FORWARD_SECURE;
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<TaggingEncrypter>(correct_tag));
  SetDecrypter(ENCRYPTION_FORWARD_SECURE,
               std::make_unique<StrictTaggingDecrypter>(correct_tag));
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();

  peer_framer_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                            std::make_unique<TaggingEncrypter>(correct_tag));

  // Key update should still not be allowed, since no packet has been acked
  // from the current key phase.
  EXPECT_FALSE(connection_.IsKeyUpdateAllowed());
  EXPECT_FALSE(connection_.HaveSentPacketsInCurrentKeyPhaseButNoneAcked());

  // Send packet 1.
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(1u), last_packet);

  // Key update should still not be allowed, even though a packet was sent in
  // the current key phase it hasn't been acked yet.
  EXPECT_FALSE(connection_.IsKeyUpdateAllowed());
  EXPECT_TRUE(connection_.HaveSentPacketsInCurrentKeyPhaseButNoneAcked());

  EXPECT_FALSE(connection_.GetDiscardPreviousOneRttKeysAlarm()->IsSet());
  // Receive ack for packet 1.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame1 = InitAckFrame(1);
  ProcessAckPacket(&frame1);

  // OnDecryptedFirstPacketInKeyPhase is called even on the first key phase,
  // so discard_previous_keys_alarm_ should be set now.
  EXPECT_TRUE(connection_.GetDiscardPreviousOneRttKeysAlarm()->IsSet());
  EXPECT_FALSE(connection_.HaveSentPacketsInCurrentKeyPhaseButNoneAcked());

  correct_tag++;
  // Key update should now be allowed.
  EXPECT_CALL(visitor_, AdvanceKeysAndCreateCurrentOneRttDecrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<StrictTaggingDecrypter>(correct_tag);
      });
  EXPECT_CALL(visitor_, CreateCurrentOneRttEncrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<TaggingEncrypter>(correct_tag);
      });
  EXPECT_CALL(visitor_, OnKeyUpdate(KeyUpdateReason::kLocalForTests));
  EXPECT_TRUE(connection_.InitiateKeyUpdate(KeyUpdateReason::kLocalForTests));
  // discard_previous_keys_alarm_ should not be set until a packet from the new
  // key phase has been received. (The alarm that was set above should be
  // cleared if it hasn't fired before the next key update happened.)
  EXPECT_FALSE(connection_.GetDiscardPreviousOneRttKeysAlarm()->IsSet());
  EXPECT_FALSE(connection_.HaveSentPacketsInCurrentKeyPhaseButNoneAcked());

  // Pretend that peer accepts the key update.
  EXPECT_CALL(peer_framer_visitor_,
              AdvanceKeysAndCreateCurrentOneRttDecrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<StrictTaggingDecrypter>(correct_tag);
      });
  EXPECT_CALL(peer_framer_visitor_, CreateCurrentOneRttEncrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<TaggingEncrypter>(correct_tag);
      });
  peer_framer_.SetKeyUpdateSupportForConnection(true);
  peer_framer_.DoKeyUpdate(KeyUpdateReason::kRemote);

  // Another key update should not be allowed yet.
  EXPECT_FALSE(connection_.IsKeyUpdateAllowed());

  // Send packet 2.
  SendStreamDataToPeer(2, "bar", 0, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(2u), last_packet);
  EXPECT_TRUE(connection_.HaveSentPacketsInCurrentKeyPhaseButNoneAcked());
  // Receive ack for packet 2.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame2 = InitAckFrame(2);
  ProcessAckPacket(&frame2);
  EXPECT_TRUE(connection_.GetDiscardPreviousOneRttKeysAlarm()->IsSet());
  EXPECT_FALSE(connection_.HaveSentPacketsInCurrentKeyPhaseButNoneAcked());

  correct_tag++;
  // Key update should be allowed again now that a packet has been acked from
  // the current key phase.
  EXPECT_CALL(visitor_, AdvanceKeysAndCreateCurrentOneRttDecrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<StrictTaggingDecrypter>(correct_tag);
      });
  EXPECT_CALL(visitor_, CreateCurrentOneRttEncrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<TaggingEncrypter>(correct_tag);
      });
  EXPECT_CALL(visitor_, OnKeyUpdate(KeyUpdateReason::kLocalForTests));
  EXPECT_TRUE(connection_.InitiateKeyUpdate(KeyUpdateReason::kLocalForTests));

  // Pretend that peer accepts the key update.
  EXPECT_CALL(peer_framer_visitor_,
              AdvanceKeysAndCreateCurrentOneRttDecrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<StrictTaggingDecrypter>(correct_tag);
      });
  EXPECT_CALL(peer_framer_visitor_, CreateCurrentOneRttEncrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<TaggingEncrypter>(correct_tag);
      });
  peer_framer_.DoKeyUpdate(KeyUpdateReason::kRemote);

  // Another key update should not be allowed yet.
  EXPECT_FALSE(connection_.IsKeyUpdateAllowed());

  // Send packet 3.
  SendStreamDataToPeer(3, "baz", 0, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(3u), last_packet);

  // Another key update should not be allowed yet.
  EXPECT_FALSE(connection_.IsKeyUpdateAllowed());
  EXPECT_TRUE(connection_.HaveSentPacketsInCurrentKeyPhaseButNoneAcked());

  // Receive ack for packet 3.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame3 = InitAckFrame(3);
  ProcessAckPacket(&frame3);
  EXPECT_TRUE(connection_.GetDiscardPreviousOneRttKeysAlarm()->IsSet());
  EXPECT_FALSE(connection_.HaveSentPacketsInCurrentKeyPhaseButNoneAcked());

  correct_tag++;
  // Key update should be allowed now.
  EXPECT_CALL(visitor_, AdvanceKeysAndCreateCurrentOneRttDecrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<StrictTaggingDecrypter>(correct_tag);
      });
  EXPECT_CALL(visitor_, CreateCurrentOneRttEncrypter())
      .WillOnce([&correct_tag]() {
        return std::make_unique<TaggingEncrypter>(correct_tag);
      });
  EXPECT_CALL(visitor_, OnKeyUpdate(KeyUpdateReason::kLocalForTests));
  EXPECT_TRUE(connection_.InitiateKeyUpdate(KeyUpdateReason::kLocalForTests));
  EXPECT_FALSE(connection_.GetDiscardPreviousOneRttKeysAlarm()->IsSet());
  EXPECT_FALSE(connection_.HaveSentPacketsInCurrentKeyPhaseButNoneAcked());
}

TEST_P(QuicConnectionTest, InitiateKeyUpdateApproachingConfidentialityLimit) {
  if (!connection_.version().UsesTls()) {
    return;
  }

  SetQuicFlag(quic_key_update_confidentiality_limit, 3U);

  std::string error_details;
  TransportParameters params;
  // Key update is enabled.
  QuicConfig config;
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

  uint8_t current_tag = ENCRYPTION_FORWARD_SECURE;

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<TaggingEncrypter>(current_tag));
  SetDecrypter(ENCRYPTION_FORWARD_SECURE,
               std::make_unique<StrictTaggingDecrypter>(current_tag));
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();

  peer_framer_.SetKeyUpdateSupportForConnection(true);
  peer_framer_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                            std::make_unique<TaggingEncrypter>(current_tag));

  const QuicConnectionStats& stats = connection_.GetStats();

  for (int packet_num = 1; packet_num <= 8; ++packet_num) {
    if (packet_num == 3 || packet_num == 6) {
      current_tag++;
      EXPECT_CALL(visitor_, AdvanceKeysAndCreateCurrentOneRttDecrypter())
          .WillOnce([current_tag]() {
            return std::make_unique<StrictTaggingDecrypter>(current_tag);
          });
      EXPECT_CALL(visitor_, CreateCurrentOneRttEncrypter())
          .WillOnce([current_tag]() {
            return std::make_unique<TaggingEncrypter>(current_tag);
          });
      EXPECT_CALL(visitor_,
                  OnKeyUpdate(KeyUpdateReason::kLocalKeyUpdateLimitOverride));
    }
    // Send packet.
    QuicPacketNumber last_packet;
    SendStreamDataToPeer(packet_num, "foo", 0, NO_FIN, &last_packet);
    EXPECT_EQ(QuicPacketNumber(packet_num), last_packet);
    if (packet_num >= 6) {
      EXPECT_EQ(2U, stats.key_update_count);
    } else if (packet_num >= 3) {
      EXPECT_EQ(1U, stats.key_update_count);
    } else {
      EXPECT_EQ(0U, stats.key_update_count);
    }

    if (packet_num == 4 || packet_num == 7) {
      // Pretend that peer accepts the key update.
      EXPECT_CALL(peer_framer_visitor_,
                  AdvanceKeysAndCreateCurrentOneRttDecrypter())
          .WillOnce([current_tag]() {
            return std::make_unique<StrictTaggingDecrypter>(current_tag);
          });
      EXPECT_CALL(peer_framer_visitor_, CreateCurrentOneRttEncrypter())
          .WillOnce([current_tag]() {
            return std::make_unique<TaggingEncrypter>(current_tag);
          });
      peer_framer_.DoKeyUpdate(KeyUpdateReason::kRemote);
    }
    // Receive ack for packet.
    EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
    QuicAckFrame frame1 = InitAckFrame(packet_num);
    ProcessAckPacket(&frame1);
  }
}

TEST_P(QuicConnectionTest,
       CloseConnectionOnConfidentialityLimitKeyUpdateNotAllowed) {
  if (!connection_.version().UsesTls()) {
    return;
  }

  // Set key update confidentiality limit to 1 packet.
  SetQuicFlag(quic_key_update_confidentiality_limit, 1U);
  // Use confidentiality limit for connection close of 3 packets.
  constexpr size_t kConfidentialityLimit = 3U;

  std::string error_details;
  TransportParameters params;
  // Key update is enabled.
  QuicConfig config;
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

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypterWithConfidentialityLimit>(
          ENCRYPTION_FORWARD_SECURE, kConfidentialityLimit));
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();

  QuicPacketNumber last_packet;
  // Send 3 packets without receiving acks for any of them. Key update will not
  // be allowed, so the confidentiality limit should be reached, forcing the
  // connection to be closed.
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, &last_packet);
  EXPECT_TRUE(connection_.connected());
  SendStreamDataToPeer(2, "foo", 0, NO_FIN, &last_packet);
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  SendStreamDataToPeer(3, "foo", 0, NO_FIN, &last_packet);
  EXPECT_FALSE(connection_.connected());
  const QuicConnectionStats& stats = connection_.GetStats();
  EXPECT_EQ(0U, stats.key_update_count);
  TestConnectionCloseQuicErrorCode(QUIC_AEAD_LIMIT_REACHED);
}

TEST_P(QuicConnectionTest, CloseConnect
```
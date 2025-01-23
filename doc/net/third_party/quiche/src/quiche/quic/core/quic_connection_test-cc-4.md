Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium network stack and located in `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc`.

I need to identify the main purposes of the code, check for any relationships with JavaScript functionality (which is unlikely given the file path and content), analyze any logical reasoning with potential inputs and outputs, point out common user or programming errors related to this code, and describe how a user might reach this code during debugging.

The code consists of multiple test cases for the `QuicConnection` class. Each test focuses on a specific aspect of the connection's behavior.

Here's a breakdown of the functionalities covered in the snippet:

1. **Address Handling**: Tests related to how the `QuicConnection` handles peer address changes and normalization, including scenarios for both clients and servers.
2. **Max Packet Size**: Tests verifying the mechanisms for setting and limiting the maximum packet size, considering both client and server perspectives and the influence of the writer.
3. **Packet Processing Order**: Tests to ensure correct handling of packets arriving in order, out of order, and as duplicates.
4. **Encryption**: Tests concerning the handling of unencrypted stream data and its rejection.
5. **ACK Management**: Tests on how the `QuicConnection` manages acknowledgments, including sending ACKs based on out-of-order arrival, the effect of receiving out-of-order ACKs, and the timing of ACK sending.
6. **ACK Frequency and Decimation**: Tests related to the ACK frequency feature and ACK decimation logic to reduce the number of ACKs sent.
7. **Retransmission and Loss Detection**: Tests related to ACK triggering retransmissions and the `AckNeedsRetransmittableFrames` mechanism to ensure important control frames are sent.
8. **Connection Limits**: Tests regarding limits on the number of outstanding sent packets.
9. **Largest Observed Packet**: Tests on how the `QuicConnection` tracks and updates the largest observed packet number.
10. **Invalid ACK Handling**: Tests how the connection reacts to receiving ACKs for packets that haven't been sent.
11. **Basic Sending**: Basic tests for sending data and acknowledgments.
12. **Sent Time Recording**: Tests ensuring the correct recording of packet send times.
13. **Retransmission Counters**: Tests related to tracking retransmission events in connection statistics.

Regarding JavaScript, there's no direct interaction visible in this C++ test code. QUIC is a transport layer protocol, and while JavaScript in browsers uses it, the internal workings of the `QuicConnection` are handled in C++.

For logical reasoning, the tests often involve sending specific sequences of packets and asserting the state of the `QuicConnection` afterwards.

Common errors would include misconfiguring connection parameters, sending packets in incorrect sequences, or failing to handle address changes properly.

Debugging would lead here when investigating issues related to connection establishment, packet delivery, or acknowledgment handling in the QUIC protocol within Chromium.

This is part 5 of 24, suggesting that this file focuses on testing core functionalities of the `QuicConnection` class.
这是目录为`net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc`的 Chromium 网络栈的源代码文件的第 5 部分，主要涵盖了 `QuicConnection` 类的以下功能测试：

**归纳一下它的功能:**

这部分代码主要测试了 `QuicConnection` 在以下几个方面的行为和逻辑：

1. **对等方地址变更处理 (Peer Address Changes):**
    *   测试客户端和服务器在连接过程中对对等方 IP 地址和端口变更的处理，包括是否允许变更，以及如何更新内部状态。
    *   区分了已知地址和未知地址的情况，以及 IETF QUIC 和非 IETF QUIC 的行为差异。
    *   测试了客户端在收到服务器发来的包含备用地址信息的包时的处理方式。

2. **最大包大小 (Max Packet Size):**
    *   测试了客户端和服务器如何确定和调整最大发送包大小。
    *   验证了对等方可以降低但不能提高最大包大小的行为。
    *   测试了在 `QuicConnection` 创建时以及运行时设置最大包大小的影响，以及 `QuicWriter` 的限制。

3. **数据包接收顺序 (Packets In Order / Out Of Order):**
    *   测试了 `QuicConnection` 正确处理按顺序和乱序到达的数据包，并更新确认帧（ACK Frame）的状态。
    *   验证了重复数据包的处理逻辑。
    *   测试了在乱序接收数据包后，何时发送 ACK 包以及 ACK 包的内容。

4. **未加密数据处理 (Reject Unencrypted Stream Data):**
    *   测试了 `QuicConnection` 在握手完成前拒绝接收未加密应用数据的行为，以保证安全性。

5. **ACK 包的发送时机 (OutOfOrderReceiptCausesAckSend / AckReceiptCausesAckSend):**
    *   测试了当接收到乱序数据包时，`QuicConnection` 是否会立即发送 ACK 包以通知对等方。
    *   验证了接收到 ACK 包后，是否会触发新的 ACK 包的发送，以及在需要重传数据时的处理。

6. **ACK 频率控制 (AckFrequencyUpdatedFromAckFrequencyFrame / AckDecimationReducesAcks):**
    *   测试了接收到 `ACK_FREQUENCY` 帧后，如何根据指定的频率发送 ACK 包。
    *   验证了 ACK 抑制 (decimation) 机制，在网络状况良好时减少 ACK 包的发送频率。

7. **需要携带可重传帧的 ACK 包 (AckNeedsRetransmittableFrames):**
    *   测试了当需要发送某些控制帧（如 `WINDOW_UPDATE`）时，如何触发 ACK 包的发送，并将这些控制帧与 ACK 包一起发送。
    *   验证了在发生 PTO (Path Throughput Optimization) 后，需要发送可重传帧的 ACK 包的行为。

8. **连接限制 (TooManySentPackets):**
    *   测试了当发送过多未确认的数据包时，`QuicConnection` 会主动关闭连接以防止资源耗尽。

9. **最大观察到的包序号 (LargestObservedLower):**
    *   测试了接收到 ACK 包时，如果 ACK 包中声明的最大观察到的包序号小于当前连接记录的，连接如何处理。

10. **无效 ACK 数据处理 (AckUnsentData):**
    *   测试了接收到针对未发送数据包的 ACK 时，`QuicConnection` 会判定为错误并关闭连接。

11. **基本发送流程 (BasicSending):**
    *   测试了 `QuicConnection` 基本的数据发送和 ACK 确认流程。

12. **记录发送时间 (RecordSentTimeBeforePacketSent):**
    *   测试了 `QuicConnection` 在发送数据包之前正确记录发送时间。

13. **连接统计 - 重传 (ConnectionStatsRetransmission_WithRetransmissions):**
    *   测试了连接统计信息中关于重传的计数功能。

**与 Javascript 的关系：**

这段 C++ 代码是 Chromium 网络栈 QUIC 实现的核心部分，直接负责 QUIC 连接的管理和数据传输。它本身**不直接与 Javascript 功能有关系**。

然而，从更高的层面来看，当用户在 Chrome 浏览器中访问使用 QUIC 协议的网站时，Javascript 代码可能会触发网络请求。这些网络请求最终会由底层的 QUIC 实现（包括这里的 `QuicConnection` 类）来处理。

**举例说明:**

假设一个网页的 Javascript 代码使用 `fetch()` API 发起一个 HTTPS 请求到一个支持 QUIC 的服务器：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，底层的 Chromium 网络栈会：

1. 创建一个 `QuicConnection` 对象来与服务器建立 QUIC 连接。
2. Javascript 发起的请求会被转换为 QUIC 数据流。
3. 这里的 `QuicConnection` 测试代码所涉及的功能，例如地址管理、最大包大小协商、数据包的发送和接收、ACK 处理等，都会在幕后发生，以保证数据可靠高效地传输。

虽然 Javascript 代码本身不直接调用 `QuicConnection` 的方法，但它的行为依赖于 `QuicConnection` 的正确实现。

**逻辑推理，假设输入与输出:**

例如，在 `TEST_P(QuicConnectionTest, PeerAddressChangesToKnownAddress)` 测试中：

*   **假设输入:**
    1. `QuicConnection` 对象处于客户端状态。
    2. 接收到来自 `kPeerAddress` 的一个 `CRYPTO` 帧数据包。
    3. 接收到来自 `kNewPeerAddress` 的另一个 `CRYPTO` 帧数据包，且 `kNewPeerAddress` 已被添加到已知服务器地址列表中。
    4. 接收到来自原始 `kPeerAddress` 的第三个 `CRYPTO` 帧数据包。

*   **预期输出:**
    1. 第一个数据包处理后，`connection_.peer_address()` 和 `connection_.effective_peer_address()` 都应为 `kPeerAddress`。
    2. 第二个数据包处理后，由于 `kNewPeerAddress` 是已知地址，`connection_.peer_address()` 和 `connection_.effective_peer_address()` 仍然应为 `kPeerAddress` (不发生迁移)。
    3. 第三个数据包处理后，地址保持不变，仍然为 `kPeerAddress`。

**用户或编程常见的使用错误：**

与这段代码相关的用户或编程常见错误可能发生在网络应用的开发或 QUIC 协议的实现中：

*   **地址处理不当:**  在多网卡或 NAT 环境下，没有正确处理地址变更可能导致连接中断或数据传输失败。例如，客户端在网络切换后，如果服务器没有正确处理新的客户端 IP 地址，可能会丢弃数据包。
*   **最大包大小配置错误:**  设置过大的最大包大小可能导致 IP 分片，降低性能甚至导致数据包丢失。设置过小则可能增加包头开销。
*   **对数据包乱序的理解不足:**  在实现可靠传输协议时，需要正确处理乱序和重复的数据包，避免数据丢失或重复处理。
*   **没有正确处理加密:**  在 QUIC 连接建立初期，如果尝试发送或接收未加密的应用数据，可能会导致连接错误。
*   **ACK 机制理解偏差:**  对 ACK 的发送时机和内容理解不足，可能导致不必要的重传或延迟。

**用户操作如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个网站时遇到连接问题，例如页面加载缓慢或连接中断。作为开发人员，在调试过程中可能会走到这里：

1. **用户访问网站:** 用户在 Chrome 浏览器的地址栏输入网址并按下回车。
2. **浏览器发起请求:** Chrome 浏览器的网络栈开始处理该请求，如果目标网站支持 QUIC，可能会尝试建立 QUIC 连接。
3. **QUIC 连接建立:**  `QuicConnection` 对象被创建，并进行握手过程。
4. **连接不稳定或地址变更:**  在连接建立后，如果用户的网络环境发生变化（例如，从 Wi-Fi 切换到移动网络），或者服务器进行了负载均衡等操作，可能导致 IP 地址或端口发生变化。
5. **调试 QUIC 连接行为:**  开发人员可能会使用 Chrome 提供的网络调试工具（`chrome://net-internals/#quic`）来查看 QUIC 连接的详细信息，包括连接状态、数据包发送接收情况、错误信息等。
6. **定位到地址变更相关问题:**  如果调试信息显示对等方地址发生了变化，并且连接行为异常，开发人员可能会查看 `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc` 中的地址管理代码，以及对应的测试代码 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 来理解和验证地址变更的处理逻辑。
7. **查看测试用例:**  例如，查看 `PeerAddressChangesToKnownAddress` 或 `NoNormalizedPeerAddressChangeAtClient` 等测试用例，可以帮助理解在各种场景下 `QuicConnection` 应该如何处理地址变更。
8. **单步调试:**  如果需要更深入的分析，开发人员可能会在 `QuicConnection` 的相关代码中设置断点，例如在处理接收到数据包的函数中，来观察地址信息的变化和连接状态的更新。

总而言之，这段测试代码覆盖了 `QuicConnection` 核心的网络连接管理和数据传输功能，理解这些测试用例有助于深入理解 QUIC 协议在 Chromium 中的实现细节。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
t is the same as direct_peer_address for
  // this test.
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                              QuicSocketAddress());
  EXPECT_FALSE(connection_.effective_peer_address().IsInitialized());

  if (connection_.version().HasIetfQuicFrames()) {
    // Verify the 2nd packet from unknown server address gets dropped.
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  } else if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(2);
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(2);
  }
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  EXPECT_CALL(visitor_, OnConnectionMigration(PORT_CHANGE)).Times(0);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                  kNewPeerAddress, ENCRYPTION_INITIAL);
  if (connection_.version().HasIetfQuicFrames()) {
    // IETF QUIC disallows server initiated address change.
    EXPECT_EQ(kPeerAddress, connection_.peer_address());
    EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
  } else {
    EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
    EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  }
}

TEST_P(QuicConnectionTest, NoNormalizedPeerAddressChangeAtClient) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  QuicIpAddress peer_ip;
  peer_ip.FromString("1.1.1.1");

  QuicSocketAddress peer_addr = QuicSocketAddress(peer_ip, /*port=*/443);
  QuicSocketAddress dualstack_peer_addr =
      QuicSocketAddress(peer_addr.host().DualStacked(), peer_addr.port());

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_)).Times(AnyNumber());
  set_perspective(Perspective::IS_CLIENT);
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());

  QuicConnectionPeer::SetDirectPeerAddress(&connection_, dualstack_peer_addr);

  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, peer_addr,
                                  ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.connected());

  if (GetQuicReloadableFlag(quic_test_peer_addr_change_after_normalize)) {
    EXPECT_EQ(0u, connection_.GetStats().packets_dropped);
  } else {
    EXPECT_EQ(1u, connection_.GetStats().packets_dropped);
  }
}

TEST_P(QuicConnectionTest, ServerAddressChangesToKnownAddress) {
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  set_perspective(Perspective::IS_CLIENT);
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());

  // Clear direct_peer_address.
  QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
  // Clear effective_peer_address, it is the same as direct_peer_address for
  // this test.
  QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                              QuicSocketAddress());
  EXPECT_FALSE(connection_.effective_peer_address().IsInitialized());

  // Verify all 3 packets get processed.
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(3);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());

  // Process another packet with a different but known server address.
  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  connection_.AddKnownServerAddress(kNewPeerAddress);
  EXPECT_CALL(visitor_, OnConnectionMigration(_)).Times(0);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                  kNewPeerAddress, ENCRYPTION_INITIAL);
  // Verify peer address does not change.
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());

  // Process 3rd packet from previous server address.
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  // Verify peer address does not change.
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
}

TEST_P(QuicConnectionTest,
       PeerAddressChangesToPreferredAddressBeforeClientInitiates) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  ASSERT_EQ(Perspective::IS_CLIENT, connection_.perspective());
  ASSERT_TRUE(connection_.self_address().host().IsIPv6());
  const QuicConnectionId connection_id = TestConnectionId(17);
  const StatelessResetToken reset_token =
      QuicUtils::GenerateStatelessResetToken(connection_id);

  connection_.CreateConnectionIdManager();

  connection_.SendCryptoStreamData();
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame = InitAckFrame(1);
  // Received ACK for packet 1.
  ProcessFramePacketAtLevel(1, QuicFrame(&frame), ENCRYPTION_INITIAL);
  // Discard INITIAL key.
  connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  QuicConfig config;
  QuicConfigPeer::SetReceivedStatelessResetToken(&config,
                                                 kTestStatelessResetToken);
  QuicConfigPeer::SetReceivedAlternateServerAddress(&config,
                                                    kServerPreferredAddress);
  QuicConfigPeer::SetPreferredAddressConnectionIdAndToken(
      &config, connection_id, reset_token);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
  ASSERT_TRUE(
      QuicConnectionPeer::GetReceivedServerPreferredAddress(&connection_)
          .IsInitialized());
  EXPECT_EQ(
      kServerPreferredAddress,
      QuicConnectionPeer::GetReceivedServerPreferredAddress(&connection_));

  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(0);
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                  kServerPreferredAddress, ENCRYPTION_INITIAL);
}

TEST_P(QuicConnectionTest, MaxPacketSize) {
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());
  EXPECT_EQ(1250u, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, PeerLowersMaxPacketSize) {
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());

  // SetFromConfig is always called after construction from InitializeSession.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  constexpr uint32_t kTestMaxPacketSize = 1233u;
  QuicConfig config;
  QuicConfigPeer::SetReceivedMaxPacketSize(&config, kTestMaxPacketSize);
  connection_.SetFromConfig(config);

  EXPECT_EQ(kTestMaxPacketSize, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, PeerCannotRaiseMaxPacketSize) {
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());

  // SetFromConfig is always called after construction from InitializeSession.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  constexpr uint32_t kTestMaxPacketSize = 1450u;
  QuicConfig config;
  QuicConfigPeer::SetReceivedMaxPacketSize(&config, kTestMaxPacketSize);
  connection_.SetFromConfig(config);

  EXPECT_EQ(kDefaultMaxPacketSize, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, SmallerServerMaxPacketSize) {
  TestConnection connection(TestConnectionId(), kSelfAddress, kPeerAddress,
                            helper_.get(), alarm_factory_.get(), writer_.get(),
                            Perspective::IS_SERVER, version(),
                            connection_id_generator_);
  EXPECT_EQ(Perspective::IS_SERVER, connection.perspective());
  EXPECT_EQ(1000u, connection.max_packet_length());
}

TEST_P(QuicConnectionTest, LowerServerResponseMtuTest) {
  set_perspective(Perspective::IS_SERVER);
  connection_.SetMaxPacketLength(1000);
  EXPECT_EQ(1000u, connection_.max_packet_length());

  SetQuicFlag(quic_use_lower_server_response_mtu_for_test, true);
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(::testing::AtMost(1));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(::testing::AtMost(1));
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  EXPECT_EQ(1250u, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, IncreaseServerMaxPacketSize) {
  set_perspective(Perspective::IS_SERVER);
  connection_.SetMaxPacketLength(1000);

  QuicPacketHeader header;
  header.destination_connection_id = connection_id_;
  header.version_flag = true;
  header.packet_number = QuicPacketNumber(12);

  if (QuicVersionHasLongHeaderLengths(
          peer_framer_.version().transport_version)) {
    header.long_packet_type = INITIAL;
    header.retry_token_length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
    header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  }

  QuicFrames frames;
  QuicPaddingFrame padding;
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    frames.push_back(QuicFrame(&crypto_frame_));
  } else {
    frames.push_back(QuicFrame(frame1_));
  }
  frames.push_back(QuicFrame(padding));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length =
      peer_framer_.EncryptPayload(ENCRYPTION_INITIAL, QuicPacketNumber(12),
                                  *packet, buffer, kMaxOutgoingPacketSize);
  EXPECT_EQ(kMaxOutgoingPacketSize,
            encrypted_length +
                (connection_.version().KnowsWhichDecrypterToUse() ? 0 : 4));

  framer_.set_version(version());
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  }
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, clock_.ApproximateNow(),
                         false));

  EXPECT_EQ(kMaxOutgoingPacketSize,
            connection_.max_packet_length() +
                (connection_.version().KnowsWhichDecrypterToUse() ? 0 : 4));
}

TEST_P(QuicConnectionTest, IncreaseServerMaxPacketSizeWhileWriterLimited) {
  const QuicByteCount lower_max_packet_size = 1240;
  writer_->set_max_packet_size(lower_max_packet_size);
  set_perspective(Perspective::IS_SERVER);
  connection_.SetMaxPacketLength(1000);
  EXPECT_EQ(1000u, connection_.max_packet_length());

  QuicPacketHeader header;
  header.destination_connection_id = connection_id_;
  header.version_flag = true;
  header.packet_number = QuicPacketNumber(12);

  if (QuicVersionHasLongHeaderLengths(
          peer_framer_.version().transport_version)) {
    header.long_packet_type = INITIAL;
    header.retry_token_length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
    header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  }

  QuicFrames frames;
  QuicPaddingFrame padding;
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    frames.push_back(QuicFrame(&crypto_frame_));
  } else {
    frames.push_back(QuicFrame(frame1_));
  }
  frames.push_back(QuicFrame(padding));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length =
      peer_framer_.EncryptPayload(ENCRYPTION_INITIAL, QuicPacketNumber(12),
                                  *packet, buffer, kMaxOutgoingPacketSize);
  EXPECT_EQ(kMaxOutgoingPacketSize,
            encrypted_length +
                (connection_.version().KnowsWhichDecrypterToUse() ? 0 : 4));

  framer_.set_version(version());
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  }
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, clock_.ApproximateNow(),
                         false));

  // Here, the limit imposed by the writer is lower than the size of the packet
  // received, so the writer max packet size is used.
  EXPECT_EQ(lower_max_packet_size, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, LimitMaxPacketSizeByWriter) {
  const QuicByteCount lower_max_packet_size = 1240;
  writer_->set_max_packet_size(lower_max_packet_size);

  static_assert(lower_max_packet_size < kDefaultMaxPacketSize,
                "Default maximum packet size is too low");
  connection_.SetMaxPacketLength(kDefaultMaxPacketSize);

  EXPECT_EQ(lower_max_packet_size, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, LimitMaxPacketSizeByWriterForNewConnection) {
  const QuicConnectionId connection_id = TestConnectionId(17);
  const QuicByteCount lower_max_packet_size = 1240;
  writer_->set_max_packet_size(lower_max_packet_size);
  TestConnection connection(connection_id, kSelfAddress, kPeerAddress,
                            helper_.get(), alarm_factory_.get(), writer_.get(),
                            Perspective::IS_CLIENT, version(),
                            connection_id_generator_);
  EXPECT_EQ(Perspective::IS_CLIENT, connection.perspective());
  EXPECT_EQ(lower_max_packet_size, connection.max_packet_length());
}

TEST_P(QuicConnectionTest, PacketsInOrder) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(1);
  EXPECT_EQ(QuicPacketNumber(1u), LargestAcked(connection_.ack_frame()));
  EXPECT_EQ(1u, connection_.ack_frame().packets.NumIntervals());

  ProcessPacket(2);
  EXPECT_EQ(QuicPacketNumber(2u), LargestAcked(connection_.ack_frame()));
  EXPECT_EQ(1u, connection_.ack_frame().packets.NumIntervals());

  ProcessPacket(3);
  EXPECT_EQ(QuicPacketNumber(3u), LargestAcked(connection_.ack_frame()));
  EXPECT_EQ(1u, connection_.ack_frame().packets.NumIntervals());
}

TEST_P(QuicConnectionTest, PacketsOutOfOrder) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(3);
  EXPECT_EQ(QuicPacketNumber(3u), LargestAcked(connection_.ack_frame()));
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(2);
  EXPECT_EQ(QuicPacketNumber(3u), LargestAcked(connection_.ack_frame()));
  EXPECT_FALSE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(1);
  EXPECT_EQ(QuicPacketNumber(3u), LargestAcked(connection_.ack_frame()));
  EXPECT_FALSE(IsMissing(2));
  EXPECT_FALSE(IsMissing(1));
}

TEST_P(QuicConnectionTest, DuplicatePacket) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(3);
  EXPECT_EQ(QuicPacketNumber(3u), LargestAcked(connection_.ack_frame()));
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  // Send packet 3 again, but do not set the expectation that
  // the visitor OnStreamFrame() will be called.
  ProcessDataPacket(3);
  EXPECT_EQ(QuicPacketNumber(3u), LargestAcked(connection_.ack_frame()));
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));
}

TEST_P(QuicConnectionTest, PacketsOutOfOrderWithAdditionsAndLeastAwaiting) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(3);
  EXPECT_EQ(QuicPacketNumber(3u), LargestAcked(connection_.ack_frame()));
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(2);
  EXPECT_EQ(QuicPacketNumber(3u), LargestAcked(connection_.ack_frame()));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(5);
  EXPECT_EQ(QuicPacketNumber(5u), LargestAcked(connection_.ack_frame()));
  EXPECT_TRUE(IsMissing(1));
  EXPECT_TRUE(IsMissing(4));

  // Pretend at this point the client has gotten acks for 2 and 3 and 1 is a
  // packet the peer will not retransmit.  It indicates this by sending 'least
  // awaiting' is 4.  The connection should then realize 1 will not be
  // retransmitted, and will remove it from the missing list.
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  ProcessAckPacket(6, &frame);

  // Force an ack to be sent.
  SendAckPacketToPeer();
  EXPECT_TRUE(IsMissing(4));
}

TEST_P(QuicConnectionTest, RejectUnencryptedStreamData) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration() ||
      VersionHasIetfQuicFrames(version().transport_version)) {
    return;
  }

  // Process an unencrypted packet from the non-crypto stream.
  frame1_.stream_id = 3;
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_QUIC_PEER_BUG(ProcessDataPacketAtLevel(1, false, ENCRYPTION_INITIAL),
                       "");
  TestConnectionCloseQuicErrorCode(QUIC_UNENCRYPTED_STREAM_DATA);
}

TEST_P(QuicConnectionTest, OutOfOrderReceiptCausesAckSend) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(3);
  // Should not cause an ack.
  EXPECT_EQ(0u, writer_->packets_write_attempts());

  ProcessPacket(2);
  // Should ack immediately, since this fills the last hole.
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  ProcessPacket(1);
  // Should ack immediately, since this fills the last hole.
  EXPECT_EQ(2u, writer_->packets_write_attempts());

  ProcessPacket(4);
  // Should not cause an ack.
  EXPECT_EQ(2u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, OutOfOrderAckReceiptCausesNoAck) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  SendStreamDataToPeer(1, "foo", 0, NO_FIN, nullptr);
  SendStreamDataToPeer(1, "bar", 3, NO_FIN, nullptr);
  EXPECT_EQ(2u, writer_->packets_write_attempts());

  QuicAckFrame ack1 = InitAckFrame(1);
  QuicAckFrame ack2 = InitAckFrame(2);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    EXPECT_CALL(visitor_, OnOneRttPacketAcknowledged()).Times(1);
  }
  ProcessAckPacket(2, &ack2);
  // Should ack immediately since we have missing packets.
  EXPECT_EQ(2u, writer_->packets_write_attempts());

  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    EXPECT_CALL(visitor_, OnOneRttPacketAcknowledged()).Times(0);
  }
  ProcessAckPacket(1, &ack1);
  // Should not ack an ack filling a missing packet.
  EXPECT_EQ(2u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, AckReceiptCausesAckSend) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  QuicPacketNumber original, second;

  QuicByteCount packet_size =
      SendStreamDataToPeer(3, "foo", 0, NO_FIN, &original);  // 1st packet.
  SendStreamDataToPeer(3, "bar", 3, NO_FIN, &second);        // 2nd packet.

  QuicAckFrame frame = InitAckFrame({{second, second + 1}});
  // First nack triggers early retransmit.
  LostPacketVector lost_packets;
  lost_packets.push_back(LostPacket(original, kMaxOutgoingPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicPacketNumber retransmission;
  // Packet 1 is short header for IETF QUIC because the encryption level
  // switched to ENCRYPTION_FORWARD_SECURE in SendStreamDataToPeer.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, packet_size, _))
      .WillOnce(SaveArg<2>(&retransmission));

  ProcessAckPacket(&frame);

  QuicAckFrame frame2 = ConstructAckFrame(retransmission, original);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  ProcessAckPacket(&frame2);

  // Now if the peer sends an ack which still reports the retransmitted packet
  // as missing, that will bundle an ack with data after two acks in a row
  // indicate the high water mark needs to be raised.
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, HAS_RETRANSMITTABLE_DATA));
  connection_.SendStreamDataWithString(3, "foo", 6, NO_FIN);
  // No ack sent.
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());

  // No more packet loss for the rest of the test.
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .Times(AnyNumber());
  ProcessAckPacket(&frame2);
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, HAS_RETRANSMITTABLE_DATA));
  connection_.SendStreamDataWithString(3, "foofoofoo", 9, NO_FIN);
  // Ack bundled.
  // Do not ACK acks.
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_TRUE(writer_->ack_frames().empty());

  // But an ack with no missing packets will not send an ack.
  AckPacket(original, &frame2);
  ProcessAckPacket(&frame2);
  ProcessAckPacket(&frame2);
}

TEST_P(QuicConnectionTest, AckFrequencyUpdatedFromAckFrequencyFrame) {
  if (!GetParam().version.HasIetfQuicFrames()) {
    return;
  }
  connection_.set_can_receive_ack_frequency_frame();

  // Expect 13 acks, every 3rd packet including the first packet with
  // AckFrequencyFrame.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(13);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicAckFrequencyFrame ack_frequency_frame;
  ack_frequency_frame.packet_tolerance = 3;
  ProcessFramePacketAtLevel(1, QuicFrame(&ack_frequency_frame),
                            ENCRYPTION_FORWARD_SECURE);

  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(38);
  // Receives packets 2 - 39.
  for (size_t i = 2; i <= 39; ++i) {
    ProcessDataPacket(i);
  }
}

TEST_P(QuicConnectionTest, AckDecimationReducesAcks) {
  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_CALL(visitor_, OnAckNeedsRetransmittableFrame()).Times(AnyNumber());

  // Start ack decimation from 10th packet.
  connection_.set_min_received_before_ack_decimation(10);

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(30);

  // Expect 6 acks: 5 acks between packets 1-10, and ack at 20.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(6);
  // Receives packets 1 - 29.
  for (size_t i = 1; i <= 29; ++i) {
    ProcessDataPacket(i);
  }

  // We now receive the 30th packet, and so we send an ack.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ProcessDataPacket(30);
}

TEST_P(QuicConnectionTest, AckNeedsRetransmittableFrames) {
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(99);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(19);
  // Receives packets 1 - 39.
  for (size_t i = 1; i <= 39; ++i) {
    ProcessDataPacket(i);
  }
  // Receiving Packet 40 causes 20th ack to send. Session is informed and adds
  // WINDOW_UPDATE.
  EXPECT_CALL(visitor_, OnAckNeedsRetransmittableFrame())
      .WillOnce(Invoke([this]() {
        connection_.SendControlFrame(QuicFrame(QuicWindowUpdateFrame(1, 0, 0)));
      }));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  EXPECT_EQ(0u, writer_->window_update_frames().size());
  ProcessDataPacket(40);
  EXPECT_EQ(1u, writer_->window_update_frames().size());

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(9);
  // Receives packets 41 - 59.
  for (size_t i = 41; i <= 59; ++i) {
    ProcessDataPacket(i);
  }
  // Send a packet containing stream frame.
  SendStreamDataToPeer(
      QuicUtils::GetFirstBidirectionalStreamId(
          connection_.version().transport_version, Perspective::IS_CLIENT),
      "bar", 0, NO_FIN, nullptr);

  // Session will not be informed until receiving another 20 packets.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(19);
  for (size_t i = 60; i <= 98; ++i) {
    ProcessDataPacket(i);
    EXPECT_EQ(0u, writer_->window_update_frames().size());
  }
  // Session does not add a retransmittable frame.
  EXPECT_CALL(visitor_, OnAckNeedsRetransmittableFrame())
      .WillOnce(Invoke([this]() {
        connection_.SendControlFrame(QuicFrame(QuicPingFrame(1)));
      }));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  EXPECT_EQ(0u, writer_->ping_frames().size());
  ProcessDataPacket(99);
  EXPECT_EQ(0u, writer_->window_update_frames().size());
  // A ping frame will be added.
  EXPECT_EQ(1u, writer_->ping_frames().size());
}

TEST_P(QuicConnectionTest, AckNeedsRetransmittableFramesAfterPto) {
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kEACK);
  config.SetConnectionOptionsToSend(connection_options);
  connection_.SetFromConfig(config);

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.OnHandshakeComplete();

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(10);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(4);
  // Receive packets 1 - 9.
  for (size_t i = 1; i <= 9; ++i) {
    ProcessDataPacket(i);
  }

  // Send a ping and fire the retransmission alarm.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  SendPing();
  QuicTime retransmission_time =
      connection_.GetRetransmissionAlarm()->deadline();
  clock_.AdvanceTime(retransmission_time - clock_.Now());
  connection_.GetRetransmissionAlarm()->Fire();
  ASSERT_LT(0u, manager_->GetConsecutivePtoCount());

  // Process a packet, which requests a retransmittable frame be bundled
  // with the ACK.
  EXPECT_CALL(visitor_, OnAckNeedsRetransmittableFrame())
      .WillOnce(Invoke([this]() {
        connection_.SendControlFrame(QuicFrame(QuicWindowUpdateFrame(1, 0, 0)));
      }));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ProcessDataPacket(11);
  EXPECT_EQ(1u, writer_->window_update_frames().size());
}

TEST_P(QuicConnectionTest, TooManySentPackets) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicPacketCount max_tracked_packets = 50;
  QuicConnectionPeer::SetMaxTrackedPackets(&connection_, max_tracked_packets);

  const int num_packets = max_tracked_packets + 5;

  for (int i = 0; i < num_packets; ++i) {
    SendStreamDataToPeer(1, "foo", 3 * i, NO_FIN, nullptr);
  }

  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));

  ProcessFramePacket(QuicFrame(QuicPingFrame()));

  TestConnectionCloseQuicErrorCode(QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS);
}

TEST_P(QuicConnectionTest, LargestObservedLower) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  SendStreamDataToPeer(1, "foo", 0, NO_FIN, nullptr);
  SendStreamDataToPeer(1, "bar", 3, NO_FIN, nullptr);
  SendStreamDataToPeer(1, "eep", 6, NO_FIN, nullptr);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));

  // Start out saying the largest observed is 2.
  QuicAckFrame frame1 = InitAckFrame(1);
  QuicAckFrame frame2 = InitAckFrame(2);
  ProcessAckPacket(&frame2);

  EXPECT_CALL(visitor_, OnCanWrite()).Times(AnyNumber());
  ProcessAckPacket(&frame1);
}

TEST_P(QuicConnectionTest, AckUnsentData) {
  // Ack a packet which has not been sent.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(visitor_, OnCanWrite()).Times(0);
  ProcessAckPacket(&frame);
  TestConnectionCloseQuicErrorCode(QUIC_INVALID_ACK_DATA);
}

TEST_P(QuicConnectionTest, BasicSending) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  const QuicConnectionStats& stats = connection_.GetStats();
  EXPECT_FALSE(stats.first_decrypted_packet.IsInitialized());
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacket(1);
  EXPECT_EQ(QuicPacketNumber(1), stats.first_decrypted_packet);
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 2);
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, &last_packet);  // Packet 1
  EXPECT_EQ(QuicPacketNumber(1u), last_packet);
  SendAckPacketToPeer();  // Packet 2

  SendAckPacketToPeer();  // Packet 3

  SendStreamDataToPeer(1, "bar", 3, NO_FIN, &last_packet);  // Packet 4
  EXPECT_EQ(QuicPacketNumber(4u), last_packet);
  SendAckPacketToPeer();  // Packet 5

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));

  // Peer acks up to packet 3.
  QuicAckFrame frame = InitAckFrame(3);
  ProcessAckPacket(&frame);
  SendAckPacketToPeer();  // Packet 6

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));

  // Peer acks up to packet 4, the last packet.
  QuicAckFrame frame2 = InitAckFrame(6);
  ProcessAckPacket(&frame2);  // Acks don't instigate acks.

  // Verify that we did not send an ack.
  EXPECT_EQ(QuicPacketNumber(6u), writer_->header().packet_number);

  // If we force an ack, we shouldn't change our retransmit state.
  SendAckPacketToPeer();  // Packet 7

  // But if we send more data it should.
  SendStreamDataToPeer(1, "eep", 6, NO_FIN, &last_packet);  // Packet 8
  EXPECT_EQ(QuicPacketNumber(8u), last_packet);
  SendAckPacketToPeer();  // Packet 9
  EXPECT_EQ(QuicPacketNumber(1), stats.first_decrypted_packet);
}

// QuicConnection should record the packet sent-time prior to sending the
// packet.
TEST_P(QuicConnectionTest, RecordSentTimeBeforePacketSent) {
  // We're using a MockClock for the tests, so we have complete control over the
  // time.
  // Our recorded timestamp for the last packet sent time will be passed in to
  // the send_algorithm.  Make sure that it is set to the correct value.
  QuicTime actual_recorded_send_time = QuicTime::Zero();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<0>(&actual_recorded_send_time));

  // First send without any pause and check the result.
  QuicTime expected_recorded_send_time = clock_.Now();
  connection_.SendStreamDataWithString(1, "foo", 0, NO_FIN);
  EXPECT_EQ(expected_recorded_send_time, actual_recorded_send_time)
      << "Expected time = " << expected_recorded_send_time.ToDebuggingValue()
      << ".  Actual time = " << actual_recorded_send_time.ToDebuggingValue();

  // Now pause during the write, and check the results.
  actual_recorded_send_time = QuicTime::Zero();
  const QuicTime::Delta write_pause_time_delta =
      QuicTime::Delta::FromMilliseconds(5000);
  SetWritePauseTimeDelta(write_pause_time_delta);
  expected_recorded_send_time = clock_.Now();

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<0>(&actual_recorded_send_time));
  connection_.SendStreamDataWithString(2, "baz", 0, NO_FIN);
  EXPECT_EQ(expected_recorded_send_time, actual_recorded_send_time)
      << "Expected time = " << expected_recorded_send_time.ToDebuggingValue()
      << ".  Actual time = " << actual_recorded_send_time.ToDebuggingValue();
}

TEST_P(QuicConnectionTest, ConnectionStatsRetransmission_WithRetransmissions) {
  // Send two stream frames in 1 packet by queueing them.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.SaveAndSendStreamData(
        GetNthClientInitiatedStreamId(1, connection_.transport_version()),
        "helloworld", 0, NO_FIN, PTO_RETRANSMISSION);
    connection_.SaveAndSendStreamData(
        GetNthClientInitiatedStreamId(2, connection_.transport_version()),
        "helloworld", 0, NO_FIN, LOSS_RETRANSMISSION);
    EX
```
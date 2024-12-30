Response:
The user is asking for a summary of the functionality of the C++ code provided, which is a test file for `QuicSession` in Chromium's QUIC implementation. I need to analyze the provided code snippets and identify the key functionalities being tested. Since this is the last part of a multi-part request, I also need to summarize the overall purpose of the file based on the tested functionalities across all parts.

Here's a breakdown of the code's functionality in this specific part:

1. **Handling `STOP_SENDING` frames:** Tests how the `QuicSession` reacts to receiving `STOP_SENDING` frames for various stream states (non-existent, new, valid).
2. **Writing buffered crypto frames:** Verifies how crypto frames are buffered and sent when encryption levels change.
3. **Handling stream frames after FIN:** Checks that receiving a stream frame after the FIN has been sent results in a connection close.
4. **Resetting streams for IETF stream types:** Tests the functionality of resetting different types of IETF QUIC streams.
5. **Decryption key availability:** Verifies the behavior when a decryption key is available before the encryption key.
6. **Handling incoming streams with server-initiated IDs:** Checks the error handling when a client receives data for a stream ID it shouldn't.
7. **Write errors due to flow control and buffered crypto frames:** Tests scenarios where writing data or buffered crypto frames fails and how the connection reacts.
8. **Preventing PTO stream data before handshake confirmation:** Ensures that stream data is not sent during Probe Timeout (PTO) before the handshake is confirmed.
9. **Setting stateless reset token:** Confirms that the session configuration includes a stateless reset token.
10. **Setting server preferred address:** Tests how the server's preferred address is set based on the address family.
11. **Opening stream limit per event loop:** Verifies the mechanism to limit the number of new streams opened within a single event loop.
12. **Handling initially blocked streams:** Tests how streams are initially blocked due to flow control limits and then unblocked after configuration.

Based on these individual tests, the overall function of `quic_session_test.cc` is to rigorously test the `QuicSession` class, covering various aspects of stream management, error handling, connection lifecycle events, and interactions with the underlying `QuicConnection`.
这是`net/third_party/quiche/src/quiche/quic/core/quic_session_test.cc`文件的第五部分，也是最后一部分，主要功能是**测试`QuicSession`类作为服务器端的行为和功能**。

**归纳一下它的功能:**

综合前几部分的内容，`quic_session_test.cc` 作为一个单元测试文件，其主要功能是全面测试 `QuicSession` 类的各种行为和功能，包括作为客户端和服务器端的情况。 具体而言，它涵盖了以下核心方面：

1. **连接建立与握手:** 测试会话的创建、握手过程的各种阶段、秘钥协商、连接参数协商等。
2. **数据流管理:** 测试数据流的创建、发送、接收、流量控制、拥塞控制、流的终止和重置等。
3. **错误处理:** 测试会话对各种错误的反应，例如无效的帧、连接超时、流量控制违规、协议错误等。
4. **帧处理:** 测试会话如何处理各种 QUIC 帧，例如 `STREAM`，`RST_STREAM`，`STOP_SENDING`，`ACK`，`CRYPTO`，`PING`，`GOAWAY` 等。
5. **状态管理:** 测试会话的各种状态转换，例如打开、关闭、空闲、阻塞等。
6. **安全功能:** 测试加密密钥的更新、零 RTT 连接、重放保护等安全特性。
7. **配置管理:** 测试会话配置的设置和协商。
8. **IETF QUIC 特性:**  针对 IETF QUIC 标准的新特性进行测试，例如双向连接迁移、连接ID管理、优先级控制等。
9. **性能相关:**  虽然不是主要关注点，但部分测试可能隐含地涉及到性能，例如流量控制和拥塞控制的测试。

**本部分（第五部分）的功能总结：**

本部分专注于测试服务器端 `QuicSession` 的特定行为，包括：

* **处理 `STOP_SENDING` 帧：** 测试服务器如何响应客户端发送的 `STOP_SENDING` 帧，包括针对不存在的流、新建的流以及已存在的流。
* **写入缓冲的加密帧：** 测试服务器如何在加密级别变化时管理和发送缓冲的加密帧。
* **接收 FIN 后的流帧：**  测试服务器在发送 `FIN` 后收到更多数据帧时的处理行为，预期会关闭连接。
* **重置 IETF 流类型：** 测试服务器如何重置不同类型的 IETF QUIC 流（单向只读、单向只写、双向）。
* **解密密钥的可用性：** 测试服务器在加密密钥可用之前收到解密密钥的情况。
* **处理带有服务器发起 Stream ID 的入站流：** 测试服务器收到客户端发送的、但使用了服务器端 Stream ID 的数据帧时的处理，预期会关闭连接。
* **流量控制阻塞导致写入错误：** 测试服务器在流量控制限制下尝试写入过多数据时，以及由于缓冲的加密帧导致写入错误的情况。
* **握手确认前不进行 PTO 流数据发送：** 测试服务器在握手未确认前，在发生 PTO (Path Timeout) 时是否会发送应用数据流。
* **设置无状态重置令牌：** 验证服务器是否设置了无状态重置令牌。
* **根据地址族设置服务器首选地址：** 测试服务器如何根据连接的地址族（IPv4 或 IPv6）设置首选的服务器地址。
* **每个事件循环的打开流限制：** 测试服务器如何限制在单个事件循环中打开的新流的数量。
* **初始阻塞然后解除阻塞的流：** 测试在配置协商之前创建的流如何因为流量控制而被阻塞，并在配置协商后解除阻塞。

**与 JavaScript 功能的关系及举例说明：**

虽然 `quic_session_test.cc` 是 C++ 代码，直接与 JavaScript 没有运行时的关联，但它测试的网络协议 QUIC 是 Web 技术栈的重要组成部分，并且与 JavaScript 在浏览器中的使用息息相关。

* **HTTP/3 和 Fetch API:** QUIC 是 HTTP/3 的底层传输协议。当 JavaScript 代码在浏览器中使用 `fetch` API 或 `XMLHttpRequest` 发起 HTTP/3 请求时，浏览器底层会使用 QUIC 协议与服务器进行通信。`QuicSession` 的功能直接影响着这些 API 的性能和可靠性。

   **假设输入与输出：**
   * **假设输入 (JavaScript):**  一个 JavaScript 应用使用 `fetch` API 向支持 HTTP/3 的服务器发送一个大的 GET 请求。
   * **对应 C++ 代码测试的功能:**  `QuicSessionTestServer.WriteBufferedCryptoFrames` 测试了在连接握手阶段，加密级别变化时，服务器如何正确地发送和管理加密帧。这直接影响到 `fetch` 请求的连接建立速度和安全性。
   * **预期输出 (JavaScript):**  `fetch` 请求能够快速建立连接并安全地接收到服务器的响应数据。

* **WebSockets over QUIC:**  QUIC 也可以作为 WebSockets 的传输层。JavaScript 中的 WebSocket API 如果底层使用 QUIC，其连接管理、数据传输等都依赖于 `QuicSession` 的实现。

   **假设输入与输出：**
   * **假设输入 (JavaScript):**  一个 JavaScript 应用使用 WebSocket API 建立了一个基于 QUIC 的长连接，并持续发送和接收数据。
   * **对应 C++ 代码测试的功能:** `QuicSessionTestServer.OnStopSendingInputValidStream` 测试了服务器如何响应客户端发送的 `STOP_SENDING` 帧，这可能发生在 WebSocket 连接中客户端主动取消某个数据流的情况。
   * **预期输出 (JavaScript):**  WebSocket 连接能够平稳地处理流的取消，而不会导致整个连接中断。

**用户或编程常见的使用错误及举例说明：**

虽然 `quic_session_test.cc` 主要面向开发者，但其中测试的场景也反映了用户或开发者可能遇到的问题。

* **接收到错误方向的 Stream ID 数据：**
    * **用户操作:**  用户可能因为网络配置错误或者中间件的问题，导致客户端发送的数据包被错误地路由到服务器，并且数据包中包含了本应由服务器发起的 Stream ID。
    * **对应测试:** `QuicSessionTestServer.IncomingStreamWithServerInitiatedStreamId` 测试了服务器在这种情况下会立即关闭连接，避免协议状态混乱。
    * **错误表现:**  用户可能会看到浏览器报错 "协议错误" 或 "连接被重置"。

* **流量控制问题导致写入失败：**
    * **编程错误:** 开发者可能在客户端或服务器端发送了远超对方流量控制窗口的数据量，导致数据被阻塞或写入失败。
    * **对应测试:** `QuicSessionTestServer.BlockedFrameCausesWriteError` 和 `QuicSessionTestServer.BufferedCryptoFrameCausesWriteError` 测试了这种场景。
    * **错误表现:**  数据传输延迟增加，或者连接因为协议错误而被关闭。

**用户操作如何一步步的到达这里，作为调试线索：**

当用户遇到网络问题，并且怀疑是 QUIC 层的问题时，开发者可能会使用 Chromium 的网络调试工具（如 `chrome://net-internals`）来查看 QUIC 连接的详细信息。如果发现连接异常关闭、数据传输失败等问题，开发者可能会深入到 QUIC 的源代码进行调试。

1. **用户报告网络问题:** 用户在使用 Chrome 浏览器访问某个网站或应用时，遇到加载缓慢、连接中断等问题。
2. **开发者使用 `chrome://net-internals`:**  开发者打开 `chrome://net-internals/#quic` 查看 QUIC 连接的信息。
3. **发现异常:**  开发者在连接列表中发现与问题相关的连接状态异常，例如连接被过早关闭，或者存在大量的丢包和重传。
4. **查看事件日志:**  开发者查看连接的事件日志，可能会看到与特定 QUIC 帧（例如 `STREAM_BLOCKED`，`CONNECTION_CLOSE`）相关的错误信息。
5. **怀疑 `QuicSession` 问题:**  如果错误信息指向连接或流管理的问题，开发者可能会怀疑是 `QuicSession` 类的实现存在 bug。
6. **查阅 `quic_session_test.cc`:**  为了理解 `QuicSession` 的预期行为，开发者会查看相关的单元测试文件，例如 `quic_session_test.cc`，特别是与错误处理、流量控制、帧处理相关的测试用例。
7. **设置断点并调试:** 开发者可能会在 `quic_session.cc` 源代码中设置断点，并复现用户遇到的问题，以便跟踪代码执行流程，查看 `QuicSession` 在处理特定帧或事件时的状态和行为，从而定位问题原因。  例如，如果用户遇到了因为接收到错误 Stream ID 导致连接关闭的问题，开发者可能会查看 `QuicSession::OnStreamFrame` 函数以及 `QuicSessionTestServer.IncomingStreamWithServerInitiatedStreamId` 这个测试用例。

总而言之，`quic_session_test.cc` 是 QUIC 协议实现质量的重要保障，它通过大量的单元测试覆盖了 `QuicSession` 类的各种功能和边界情况，帮助开发者确保 QUIC 连接的稳定性和可靠性，从而间接地提升用户在使用基于 QUIC 的 Web 应用时的体验。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
, QUIC_STREAM_CANCELLED);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_.OnStopSendingFrame(frame);
}

// If stream id is a nonexistent local stream, return false and close the
// connection.
TEST_P(QuicSessionTestServer, OnStopSendingInputNonExistentLocalStream) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }

  QuicStopSendingFrame frame(1, GetNthServerInitiatedBidirectionalId(123456),
                             QUIC_STREAM_CANCELLED);
  EXPECT_CALL(*connection_, CloseConnection(QUIC_HTTP_STREAM_WRONG_DIRECTION,
                                            "Data for nonexistent stream", _))
      .Times(1);
  session_.OnStopSendingFrame(frame);
}

// If a STOP_SENDING is received for a peer initiated stream, the new stream
// will be created.
TEST_P(QuicSessionTestServer, OnStopSendingNewStream) {
  CompleteHandshake();
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  QuicStopSendingFrame frame(1, GetNthClientInitiatedBidirectionalId(1),
                             QUIC_STREAM_CANCELLED);

  // A Rst will be sent as a response for STOP_SENDING.
  EXPECT_CALL(*connection_, SendControlFrame(_)).Times(1);
  EXPECT_CALL(*connection_, OnStreamReset(_, _)).Times(1);
  session_.OnStopSendingFrame(frame);

  QuicStream* stream =
      session_.GetOrCreateStream(GetNthClientInitiatedBidirectionalId(1));
  EXPECT_TRUE(stream);
  EXPECT_TRUE(stream->write_side_closed());
}

// For a valid stream, ensure that all works
TEST_P(QuicSessionTestServer, OnStopSendingInputValidStream) {
  CompleteHandshake();
  if (!VersionHasIetfQuicFrames(transport_version())) {
    // Applicable only to IETF QUIC
    return;
  }

  TestStream* stream = session_.CreateOutgoingBidirectionalStream();

  // Ensure that the stream starts out open in both directions.
  EXPECT_FALSE(stream->write_side_closed());
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream));

  QuicStreamId stream_id = stream->id();
  QuicStopSendingFrame frame(1, stream_id, QUIC_STREAM_CANCELLED);
  // Expect a reset to come back out.
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream_id, QUIC_STREAM_CANCELLED));
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_.OnStopSendingFrame(frame);

  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream));
  EXPECT_TRUE(stream->write_side_closed());
}

TEST_P(QuicSessionTestServer, WriteBufferedCryptoFrames) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  std::string data(1350, 'a');
  TestCryptoStream* crypto_stream = session_.GetMutableCryptoStream();
  // Only consumed 1000 bytes.
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 1350, 0))
      .WillOnce(Return(1000));
  crypto_stream->WriteCryptoData(ENCRYPTION_INITIAL, data);
  EXPECT_TRUE(session_.HasPendingHandshake());
  EXPECT_TRUE(session_.WillingAndAbleToWrite());

  EXPECT_CALL(*connection_, SendCryptoData(_, _, _)).Times(0);
  connection_->SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<NullEncrypter>(connection_->perspective()));
  crypto_stream->WriteCryptoData(ENCRYPTION_ZERO_RTT, data);

  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 350, 1000))
      .WillOnce(Return(350));
  EXPECT_CALL(
      *connection_,
      SendCryptoData(crypto_stream->GetEncryptionLevelToSendCryptoDataOfSpace(
                         QuicUtils::GetPacketNumberSpace(ENCRYPTION_ZERO_RTT)),
                     1350, 0))
      .WillOnce(Return(1350));
  session_.OnCanWrite();
  EXPECT_FALSE(session_.HasPendingHandshake());
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

// Regression test for
// https://bugs.chromium.org/p/chromium/issues/detail?id=1002119
TEST_P(QuicSessionTestServer, StreamFrameReceivedAfterFin) {
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  QuicStreamFrame frame(stream->id(), true, 0, ",");
  session_.OnStreamFrame(frame);

  QuicStreamFrame frame1(stream->id(), false, 1, ",");
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_STREAM_DATA_BEYOND_CLOSE_OFFSET, _, _));
  session_.OnStreamFrame(frame1);
}

TEST_P(QuicSessionTestServer, ResetForIETFStreamTypes) {
  CompleteHandshake();
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }

  QuicStreamId read_only = GetNthClientInitiatedUnidirectionalId(0);

  EXPECT_CALL(*connection_, SendControlFrame(_))
      .Times(1)
      .WillOnce(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(read_only, _));
  session_.ResetStream(read_only, QUIC_STREAM_CANCELLED);

  QuicStreamId write_only = GetNthServerInitiatedUnidirectionalId(0);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .Times(1)
      .WillOnce(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(write_only, _));
  session_.ResetStream(write_only, QUIC_STREAM_CANCELLED);

  QuicStreamId bidirectional = GetNthClientInitiatedBidirectionalId(0);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .Times(2)
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(bidirectional, _));
  session_.ResetStream(bidirectional, QUIC_STREAM_CANCELLED);
}

TEST_P(QuicSessionTestServer, DecryptionKeyAvailableBeforeEncryptionKey) {
  if (connection_->version().handshake_protocol != PROTOCOL_TLS1_3) {
    return;
  }
  ASSERT_FALSE(connection_->framer().HasEncrypterOfEncryptionLevel(
      ENCRYPTION_HANDSHAKE));
  EXPECT_FALSE(session_.OnNewDecryptionKeyAvailable(
      ENCRYPTION_HANDSHAKE, /*decrypter=*/nullptr,
      /*set_alternative_decrypter=*/false, /*latch_once_used=*/false));
}

TEST_P(QuicSessionTestServer, IncomingStreamWithServerInitiatedStreamId) {
  const QuicErrorCode expected_error =
      VersionHasIetfQuicFrames(transport_version())
          ? QUIC_HTTP_STREAM_WRONG_DIRECTION
          : QUIC_INVALID_STREAM_ID;
  EXPECT_CALL(
      *connection_,
      CloseConnection(expected_error, "Data for nonexistent stream",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));

  QuicStreamFrame frame(GetNthServerInitiatedBidirectionalId(1),
                        /* fin = */ false, /* offset = */ 0,
                        absl::string_view("foo"));
  session_.OnStreamFrame(frame);
}

// Regression test for b/235204908.
TEST_P(QuicSessionTestServer, BlockedFrameCausesWriteError) {
  CompleteHandshake();
  MockPacketWriter* writer = static_cast<MockPacketWriter*>(
      QuicConnectionPeer::GetWriter(session_.connection()));
  EXPECT_CALL(*writer, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  // Set a small connection level flow control limit.
  const uint64_t kWindow = 36;
  QuicFlowControllerPeer::SetSendWindowOffset(session_.flow_controller(),
                                              kWindow);
  auto stream =
      session_.GetOrCreateStream(GetNthClientInitiatedBidirectionalId(0));
  // Try to send more data than the flow control limit allows.
  const uint64_t kOverflow = 15;
  std::string body(kWindow + kOverflow, 'a');
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(testing::InvokeWithoutArgs([this]() {
        connection_->ReallyCloseConnection(
            QUIC_PACKET_WRITE_ERROR, "write error",
            ConnectionCloseBehavior::SILENT_CLOSE);
        return false;
      }));
  stream->WriteOrBufferData(body, false, nullptr);
}

TEST_P(QuicSessionTestServer, BufferedCryptoFrameCausesWriteError) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  std::string data(1350, 'a');
  TestCryptoStream* crypto_stream = session_.GetMutableCryptoStream();
  // Only consumed 1000 bytes.
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_FORWARD_SECURE, 1350, 0))
      .WillOnce(Return(1000));
  crypto_stream->WriteCryptoData(ENCRYPTION_FORWARD_SECURE, data);
  EXPECT_TRUE(session_.HasPendingHandshake());
  EXPECT_TRUE(session_.WillingAndAbleToWrite());

  EXPECT_CALL(*connection_,
              SendCryptoData(ENCRYPTION_FORWARD_SECURE, 350, 1000))
      .WillOnce(Return(0));
  // Buffer the HANDSHAKE_DONE frame.
  EXPECT_CALL(*connection_, SendControlFrame(_)).WillOnce(Return(false));
  CryptoHandshakeMessage msg;
  session_.GetMutableCryptoStream()->OnHandshakeMessage(msg);

  // Flush both frames.
  EXPECT_CALL(*connection_,
              SendCryptoData(ENCRYPTION_FORWARD_SECURE, 350, 1000))
      .WillOnce(testing::InvokeWithoutArgs([this]() {
        connection_->ReallyCloseConnection(
            QUIC_PACKET_WRITE_ERROR, "write error",
            ConnectionCloseBehavior::SILENT_CLOSE);
        return 350;
      }));
  if (!GetQuicReloadableFlag(
          quic_no_write_control_frame_upon_connection_close)) {
    EXPECT_CALL(*connection_, SendControlFrame(_)).WillOnce(Return(false));
    EXPECT_QUIC_BUG(session_.OnCanWrite(), "Try to write control frame");
  } else {
    session_.OnCanWrite();
  }
}

TEST_P(QuicSessionTestServer, DonotPtoStreamDataBeforeHandshakeConfirmed) {
  if (!session_.version().UsesTls()) {
    return;
  }
  EXPECT_NE(HANDSHAKE_CONFIRMED, session_.GetHandshakeState());

  TestCryptoStream* crypto_stream = session_.GetMutableCryptoStream();
  EXPECT_FALSE(crypto_stream->HasBufferedCryptoFrames());
  std::string data(1350, 'a');
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 1350, 0))
      .WillOnce(Return(1000));
  crypto_stream->WriteCryptoData(ENCRYPTION_INITIAL, data);
  ASSERT_TRUE(crypto_stream->HasBufferedCryptoFrames());

  TestStream* stream = session_.CreateOutgoingBidirectionalStream();

  session_.MarkConnectionLevelWriteBlocked(stream->id());
  // Buffered crypto data gets sent.
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, _, _))
      .WillOnce(Return(350));
  // Verify stream data is not sent on PTO before handshake confirmed.
  EXPECT_CALL(*stream, OnCanWrite()).Times(0);

  // Fire PTO.
  QuicConnectionPeer::SetInProbeTimeOut(connection_, true);
  session_.OnCanWrite();
  EXPECT_FALSE(crypto_stream->HasBufferedCryptoFrames());
}

TEST_P(QuicSessionTestServer, SetStatelessResetTokenToSend) {
  if (!session_.version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_TRUE(session_.config()->HasStatelessResetTokenToSend());
}

TEST_P(QuicSessionTestServer,
       SetServerPreferredAddressAccordingToAddressFamily) {
  if (!session_.version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_EQ(quiche::IpAddressFamily::IP_V4,
            connection_->peer_address().host().address_family());
  QuicConnectionPeer::SetEffectivePeerAddress(connection_,
                                              connection_->peer_address());
  QuicTagVector copt;
  copt.push_back(kSPAD);
  QuicConfigPeer::SetReceivedConnectionOptions(session_.config(), copt);
  QuicSocketAddress preferred_address(QuicIpAddress::Loopback4(), 12345);
  session_.config()->SetIPv4AlternateServerAddressToSend(preferred_address);
  session_.config()->SetIPv6AlternateServerAddressToSend(
      QuicSocketAddress(QuicIpAddress::Loopback6(), 12345));

  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_.OnConfigNegotiated();
  EXPECT_EQ(QuicSocketAddress(QuicIpAddress::Loopback4(), 12345),
            session_.config()
                ->GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V4)
                .value());
  EXPECT_FALSE(session_.config()
                   ->GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V6)
                   .has_value());
  EXPECT_EQ(preferred_address,
            connection_->expected_server_preferred_address());
}

TEST_P(QuicSessionTestServer,
       SetDNatServerPreferredAddressAccordingToAddressFamily) {
  if (!session_.version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_EQ(quiche::IpAddressFamily::IP_V4,
            connection_->peer_address().host().address_family());
  QuicConnectionPeer::SetEffectivePeerAddress(connection_,
                                              connection_->peer_address());
  QuicTagVector copt;
  copt.push_back(kSPAD);
  QuicConfigPeer::SetReceivedConnectionOptions(session_.config(), copt);
  QuicSocketAddress sent_preferred_address(QuicIpAddress::Loopback4(), 12345);
  QuicSocketAddress expected_preferred_address(QuicIpAddress::Loopback4(),
                                               12346);
  session_.config()->SetIPv4AlternateServerAddressForDNat(
      sent_preferred_address, expected_preferred_address);
  session_.config()->SetIPv6AlternateServerAddressForDNat(
      QuicSocketAddress(QuicIpAddress::Loopback6(), 12345),
      QuicSocketAddress(QuicIpAddress::Loopback6(), 12346));

  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_.OnConfigNegotiated();
  EXPECT_EQ(QuicSocketAddress(QuicIpAddress::Loopback4(), 12345),
            session_.config()
                ->GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V4)
                .value());
  EXPECT_FALSE(session_.config()
                   ->GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V6)
                   .has_value());
  EXPECT_EQ(expected_preferred_address,
            connection_->expected_server_preferred_address());
}

TEST_P(QuicSessionTestServer, NoServerPreferredAddressIfAddressFamilyMismatch) {
  if (!session_.version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_EQ(quiche::IpAddressFamily::IP_V4,
            connection_->peer_address().host().address_family());
  QuicConnectionPeer::SetEffectivePeerAddress(connection_,
                                              connection_->peer_address());
  QuicTagVector copt;
  copt.push_back(kSPAD);
  QuicConfigPeer::SetReceivedConnectionOptions(session_.config(), copt);
  session_.config()->SetIPv6AlternateServerAddressToSend(
      QuicSocketAddress(QuicIpAddress::Loopback6(), 12345));

  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_.OnConfigNegotiated();
  EXPECT_FALSE(session_.config()
                   ->GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V4)
                   .has_value());
  EXPECT_FALSE(session_.config()
                   ->GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V6)
                   .has_value());
  EXPECT_FALSE(
      connection_->expected_server_preferred_address().IsInitialized());
}

TEST_P(QuicSessionTestServer, OpenStreamLimitPerEventLoop) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    // Only needed for version 99/IETF QUIC. Noop otherwise.
    return;
  }
  session_.set_uses_pending_streams(true);
  CompleteHandshake();

  // Receive data on a read uni stream without 1st byte and the stream
  // should become pending.
  QuicStreamId unidirectional_stream_id =
      QuicUtils::GetFirstUnidirectionalStreamId(transport_version(),
                                                Perspective::IS_CLIENT);
  QuicStreamFrame data1(unidirectional_stream_id, false, 10,
                        absl::string_view("HT"));
  session_.OnStreamFrame(data1);
  EXPECT_TRUE(
      QuicSessionPeer::GetPendingStream(&session_, unidirectional_stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());
  // Receive data on 10 more bidi streams. Only the first 5 should open new
  // streams.
  size_t i = 0u;
  for (; i < 10u; ++i) {
    QuicStreamId bidi_stream_id = GetNthClientInitiatedBidirectionalId(i);
    QuicStreamFrame data(bidi_stream_id, false, 0, "aaaa");
    session_.OnStreamFrame(data);
    if (i > 4u) {
      EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&session_, bidi_stream_id));
    }
  }
  EXPECT_EQ(5u, session_.num_incoming_streams_created());
  EXPECT_EQ(GetNthClientInitiatedBidirectionalId(i - 1),
            QuicSessionPeer::GetLargestPeerCreatedStreamId(&session_, false));
  EXPECT_TRUE(session_.GetActiveStream(GetNthClientInitiatedBidirectionalId(4))
                  ->pending_duration()
                  .IsZero());
  // Receive 1st byte on the read uni stream. The stream should still be pending
  // due to the stream limit.
  QuicStreamFrame data2(unidirectional_stream_id, false, 0,
                        absl::string_view("HT"));
  session_.OnStreamFrame(data2);
  EXPECT_TRUE(
      QuicSessionPeer::GetPendingStream(&session_, unidirectional_stream_id));

  // Start another loop should cause 5 more pending streams to open, including
  // the unidirectional stream.
  helper_.GetClock()->AdvanceTime(QuicTime::Delta::FromMicroseconds(100));
  QuicAlarm* alarm = QuicSessionPeer::GetStreamCountResetAlarm(&session_);
  EXPECT_TRUE(alarm->IsSet());
  alarm_factory_.FireAlarm(alarm);
  EXPECT_EQ(10u, session_.num_incoming_streams_created());
  EXPECT_NE(nullptr, session_.GetActiveStream(unidirectional_stream_id));
  EXPECT_EQ(100, session_.GetActiveStream(unidirectional_stream_id)
                     ->pending_duration()
                     .ToMicroseconds());
  EXPECT_EQ(
      100,
      session_.GetActiveStream(GetNthClientInitiatedBidirectionalId(i - 2))
          ->pending_duration()
          .ToMicroseconds());
  // The 10th bidi stream should remain pending.
  EXPECT_EQ(nullptr, session_.GetActiveStream(
                         GetNthClientInitiatedBidirectionalId(i - 1)));
}

// A client test class that can be used when the automatic configuration is not
// desired.
class QuicSessionTestClientUnconfigured : public QuicSessionTestBase {
 protected:
  QuicSessionTestClientUnconfigured()
      : QuicSessionTestBase(Perspective::IS_CLIENT,
                            /*configure_session=*/false) {}
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicSessionTestClientUnconfigured,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicSessionTestClientUnconfigured, StreamInitiallyBlockedThenUnblocked) {
  if (!connection_->version().AllowsLowFlowControlLimits()) {
    return;
  }
  // Create a stream before negotiating the config and verify it starts off
  // blocked.
  QuicSessionPeer::SetMaxOpenOutgoingBidirectionalStreams(&session_, 10);
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  EXPECT_TRUE(stream2->IsFlowControlBlocked());
  EXPECT_TRUE(session_.IsConnectionFlowControlBlocked());
  EXPECT_TRUE(session_.IsStreamFlowControlBlocked());

  // Negotiate the config with higher received limits.
  QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
      session_.config(), kMinimumFlowControlSendWindow);
  QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
      session_.config(), kMinimumFlowControlSendWindow);
  session_.OnConfigNegotiated();

  // Stream is now unblocked.
  EXPECT_FALSE(stream2->IsFlowControlBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
}

}  // namespace
}  // namespace test
}  // namespace quic

"""


```
Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of the Chromium network stack and specifically focuses on testing the `QuicSpdySession` class.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Functionality:** The filename `quic_spdy_session_test.cc` immediately suggests that this code is for testing the `QuicSpdySession` class. The tests are within the context of the QUIC protocol and the SPDY/HTTP semantics layered on top.

2. **Analyze the Test Cases:**  Each `TEST_P` block represents a distinct test scenario. By reading the test names and the code within each block, I can infer the specific feature being tested. Key areas that emerge are:
    * **Flow Control:**  Tests like `ReceiveFlowControlWindow`, `TooLowInitialStreamFlowControlWindow`, `CustomFlowControlWindow`, and `WindowUpdateUnblocksHeadersStream` clearly deal with flow control mechanisms.
    * **Stream Limits:** `TooManyUnfinishedStreamsCauseServerRejectStream` and `DrainingStreamsDoNotCountAsOpened` test how the session handles limits on the number of open streams.
    * **HTTP/3 Specifics:** Several tests are conditional on `VersionUsesHttp3`, indicating they are specific to the HTTP/3 mapping over QUIC, including handling server push, QPACK integration, and control streams.
    * **Error Handling:** Tests like `TooLargeHeadersMustNotCauseWriteAfterReset` and `BadStreamFramePendingStream` focus on how the session reacts to invalid or out-of-spec behavior.
    * **Retransmission and Loss Recovery:** `OnStreamFrameLost`, `DonotRetransmitDataOfClosedStreams`, and `RetransmitFrames` cover the session's behavior when frames are lost and need retransmission.
    * **Priority:** `OnPriorityFrame` and `OnPriorityUpdateFrame` test the handling of stream priorities.
    * **Connection Management:**  `TooLowUnidirectionalStreamLimitHttp3` checks connection closure scenarios.

3. **Categorize the Functionality:**  Group the individual test functionalities into broader categories. This helps in creating a more structured summary. Good categories include: Flow Control, Stream Management, HTTP/3 Specific Features, Error Handling, Retransmission and Loss Recovery, and Stream Prioritization.

4. **Address Specific Requirements:** The prompt also asks about:
    * **Relationship to JavaScript:**  Consider where these low-level networking concepts might interact with JavaScript in a browser environment. The connection lifecycle, data transfer, and handling of errors are relevant.
    * **Logic and I/O:** Look for tests that simulate specific input conditions and verify the expected output (e.g., connection closure, stream reset).
    * **User/Programming Errors:** Identify tests that prevent or handle incorrect usage or malicious behavior (e.g., exceeding stream limits, sending invalid data).
    * **User Operations and Debugging:**  Think about the sequence of user actions that could lead to the tested scenarios and how these tests could aid in debugging.

5. **Synthesize the Summary:**  Combine the categorized functionalities and the answers to the specific requirements into a concise and informative summary. Use clear and precise language. Emphasize the role of the code as a *testing* component.

6. **Review and Refine:**  Read through the generated summary to ensure accuracy, completeness, and clarity. Make any necessary adjustments to improve readability and flow. For example, initially, I might have just listed individual test names. Refining it involves grouping them thematically for a better overview. Also, ensure that the summary accurately reflects the fact that this is *part 3* of a larger set of files.

By following these steps, I can create a comprehensive summary that addresses all aspects of the user's request.这是 `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc` 文件的第三部分，它主要包含了一系列针对 `QuicSpdySession` 类作为 **服务器端** 的单元测试。`QuicSpdySession` 是 Chromium QUIC 协议栈中处理 HTTP/2 或 HTTP/3 连接的核心类。

**本部分（第三部分）的功能归纳如下：**

* **流控 (Flow Control) 相关测试 (服务器端):**
    * 测试服务器端接收到过小的初始流控窗口时的处理，预期会关闭连接。
    * 测试服务器端接收到减小单向流数量限制时的处理，预期会关闭连接。
    * 测试服务器端协商自定义初始流控窗口的功能。
    * 测试接收到 WINDOW_UPDATE 帧后，阻塞的 Headers Stream 是否能被解除阻塞。

* **流管理 (Stream Management) 相关测试 (服务器端):**
    * 测试当客户端创建过多未完成的流（未发送 FIN 或 RST）时，服务器是否会拒绝新的流请求。
    * 测试处于 Draining 状态的流（已收到 FIN 但未完全消费）是否会计入最大打开流的数量限制。

* **HTTP/3 特性测试 (客户端和服务器端):**
    * **UsesPendingStreamsForFrame (客户端):** 测试客户端是否正确判断哪些帧类型可以使用 Pending Stream。
    * **BadStreamFramePendingStream (客户端):** 测试客户端接收到错误的 Stream 帧时（无数据和 FIN）的处理。
    * **PendingStreamKeepsConnectionAlive (客户端):** 测试当有等待处理的流时，连接是否保持活跃。
    * **AvailableStreamsClient (客户端):** 测试客户端对可用流的判断。
    * **Http3ServerPush (客户端):** 测试客户端接收到服务器推送流的起始帧时的处理 (预期会关闭连接，因为客户端不应该收到推送)。
    * **Http3ServerPushOutofOrderFrame (客户端):** 测试客户端接收到乱序的服务器推送流帧时的处理 (预期会关闭连接)。
    * **ServerDisableQpackDynamicTable & DisableQpackDynamicTable (客户端):** 测试服务器和客户端禁用 QPACK 动态表的功能。

* **错误处理 (Error Handling) 相关测试 (客户端):**
    * **TooLargeHeadersMustNotCauseWriteAfterReset:**  测试接收到过大或空的头部时，流被重置后不会再进行写操作，防止 double free 等问题。
    * **RecordFinAfterReadSideClosed:** 测试即使在读取端关闭后，仍然能记录收到的 FIN，避免资源泄漏。

* **数据重传和丢失恢复 (Retransmission and Loss Recovery) 相关测试 (服务器端):**
    * **OnStreamFrameLost:** 测试当数据帧丢失时，会话如何进行重传，包括加密流和普通数据流。
    * **DonotRetransmitDataOfClosedStreams:** 测试已关闭的流的数据是否会被排除在重传队列之外。
    * **RetransmitFrames:** 测试会话如何处理需要重传的帧集合。

* **优先级 (Priority) 相关测试 (服务器端):**
    * **OnPriorityFrame:** 测试服务器端接收到 PRIORITY 帧时的处理。
    * **OnPriorityUpdateFrame:** 测试服务器端接收到 PRIORITY_UPDATE 帧时的处理，包括在流创建前后接收到优先级更新的情况。
    * **OnInvalidPriorityUpdateFrame:** 测试服务器端接收到无效的 PRIORITY_UPDATE 帧时的处理，预期会关闭连接。

**与 JavaScript 的功能关系：**

这些底层的 QUIC 和 HTTP/3 功能直接影响着浏览器中 JavaScript 发起的网络请求的性能和可靠性。

* **流控：** 浏览器中的 JavaScript 发起请求时，底层的 QUIC 流控机制确保了数据不会压垮接收端，从而保证了连接的稳定性。如果服务器实现了自定义的流控窗口，JavaScript 感知不到，但底层的连接会按照协商的规则运行。
* **流管理：**  限制最大并发流的数量可以防止恶意客户端占用过多资源。JavaScript 发起的多个请求会被映射到不同的 QUIC 流上，底层的流管理确保了这些流的有序和高效管理。
* **HTTP/3 特性：**
    * **Server Push:** 虽然测试中客户端拒绝服务器推送，但 HTTP/3 允许服务器主动向客户端推送资源。这可以优化页面加载速度，但需要 JavaScript 能够处理这些推送的资源。
    * **QPACK:** QPACK 是 HTTP/3 的头部压缩协议。JavaScript 感知不到压缩的细节，但底层的 QPACK 编解码影响着 HTTP 头部的大小，从而影响网络传输效率。
* **错误处理：** 当发生错误（例如头部过大），QUIC 会话会进行错误处理，这可能导致 JavaScript 请求失败，需要在 JavaScript 代码中进行相应的错误处理。
* **数据重传：** QUIC 协议自带可靠性，当数据包丢失时会自动重传。这对于 JavaScript 发起的请求来说是透明的，保证了数据的完整性。
* **优先级：**  HTTP/3 的优先级机制允许浏览器告诉服务器哪些资源更重要，应该优先发送。这可以优化关键资源的加载顺序，提升用户体验。JavaScript 可以通过 Fetch API 等设置请求的优先级。

**逻辑推理、假设输入与输出：**

以 `TEST_P(QuicSpdySessionTestServer, TooLowInitialStreamFlowControlWindowHttp3)` 为例：

* **假设输入：**
    * QUIC 连接已建立。
    * 使用 HTTP/3。
    * 服务器接收到一个 `SETTINGS` 帧，其中 `SETTINGS_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL` 或 `SETTINGS_INITIAL_MAX_STREAM_DATA_UNI` 的值过小（例如 `kInvalidWindow`）。
* **逻辑推理：** 服务器端 `QuicSpdySession` 检测到初始流控窗口过小，违反了协议规范。
* **预期输出：**
    * 服务器端会发送 `CONNECTION_CLOSE` 帧，错误码为 `QUIC_FLOW_CONTROL_INVALID_WINDOW`。
    * 连接断开。

**用户或编程常见的使用错误：**

* **服务器端配置错误的初始流控窗口：**  如果服务器的配置中设置了一个非常小的初始流控窗口，可能会导致连接建立后立即断开，或者限制了数据传输的速率。
* **客户端尝试发送过多的未完成流：** 恶意客户端或有 bug 的客户端可能会尝试创建大量的流而不发送 FIN 或 RST，试图耗尽服务器资源。服务器需要正确处理这种情况，防止被 DoS 攻击。
* **没有正确处理流的关闭状态：**  在编程中，如果没有正确处理流的关闭状态，可能会导致在流已经关闭后尝试写入数据，或者没有释放相关的资源。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设一个用户在使用 Chrome 浏览器访问一个使用了 HTTP/3 的网站，并且该网站的服务器配置了错误的初始流控窗口：

1. **用户在 Chrome 浏览器的地址栏输入网址并回车。**
2. **Chrome 浏览器发起与服务器的 QUIC 连接握手。**
3. **在握手过程中，服务器发送包含初始流控窗口设置的 `SETTINGS` 帧。**
4. **Chrome 浏览器 (作为客户端) 的 QUIC 栈接收到该 `SETTINGS` 帧。**
5. **Chrome 浏览器检测到服务器发送的初始流控窗口过小，可能触发本地的错误处理，或者继续连接但受到严格的流控限制。**
6. **如果服务器端在处理协商时发现本地配置的初始流控窗口过小，相关的代码逻辑就会走到 `quic_spdy_session_test.cc` 中 `TooLowInitialStreamFlowControlWindowHttp3` 测试覆盖的路径。**
7. **作为调试线索，如果用户报告访问该网站失败，开发者可以检查 Chrome 浏览器的网络日志，查看是否发生了 `QUIC_FLOW_CONTROL_INVALID_WINDOW` 错误，从而怀疑是服务器端的流控配置问题。**

**总结第三部分的功能：**

这部分测试主要关注 `QuicSpdySession` 作为 **服务器端** 在处理流控、流管理、HTTP/3 特定帧、错误情况以及数据重传等方面的功能是否正确。同时也包含了一些客户端特定场景的测试，特别是针对 HTTP/3 的交互。 这些测试用例确保了 `QuicSpdySession` 类在各种复杂和异常情况下都能按照 QUIC 和 HTTP/3 协议的规定正确运行，保证了网络连接的稳定性和可靠性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
eivedInitialStreamFlowControlWindow(session_->config(),
                                                            kInvalidWindow);

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_INVALID_WINDOW, _, _));
  session_->OnConfigNegotiated();
}

TEST_P(QuicSpdySessionTestServer, TooLowUnidirectionalStreamLimitHttp3) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  session_->GetMutableCryptoStream()->EstablishZeroRttEncryption();
  QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(session_->config(), 2u);
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  EXPECT_CALL(
      *connection_,
      CloseConnection(
          _, "new unidirectional limit 2 decreases the current limit: 3", _));
  session_->OnConfigNegotiated();
}

// Test negotiation of custom server initial flow control window.
TEST_P(QuicSpdySessionTestServer, CustomFlowControlWindow) {
  Initialize();
  QuicTagVector copt;
  copt.push_back(kIFW7);
  QuicConfigPeer::SetReceivedConnectionOptions(session_->config(), copt);
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_->OnConfigNegotiated();
  EXPECT_EQ(192 * 1024u, QuicFlowControllerPeer::ReceiveWindowSize(
                             session_->flow_controller()));
}

TEST_P(QuicSpdySessionTestServer, WindowUpdateUnblocksHeadersStream) {
  Initialize();
  if (VersionUsesHttp3(transport_version())) {
    // The test relies on headers stream, which no longer exists in IETF QUIC.
    return;
  }

  // Test that a flow control blocked headers stream gets unblocked on recipt of
  // a WINDOW_UPDATE frame.

  // Set the headers stream to be flow control blocked.
  QuicHeadersStream* headers_stream =
      QuicSpdySessionPeer::GetHeadersStream(&*session_);
  QuicStreamPeer::SetSendWindowOffset(headers_stream, 0);
  EXPECT_TRUE(headers_stream->IsFlowControlBlocked());
  EXPECT_FALSE(session_->IsConnectionFlowControlBlocked());
  EXPECT_TRUE(session_->IsStreamFlowControlBlocked());

  // Unblock the headers stream by supplying a WINDOW_UPDATE.
  QuicWindowUpdateFrame window_update_frame(kInvalidControlFrameId,
                                            headers_stream->id(),
                                            2 * kMinimumFlowControlSendWindow);
  session_->OnWindowUpdateFrame(window_update_frame);
  EXPECT_FALSE(headers_stream->IsFlowControlBlocked());
  EXPECT_FALSE(session_->IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_->IsStreamFlowControlBlocked());
}

TEST_P(QuicSpdySessionTestServer,
       TooManyUnfinishedStreamsCauseServerRejectStream) {
  Initialize();
  // If a buggy/malicious peer creates too many streams that are not ended
  // with a FIN or RST then we send an RST to refuse streams for versions other
  // than version 99. In version 99 the connection gets closed.
  CompleteHandshake();
  const QuicStreamId kMaxStreams = 5;
  if (VersionHasIetfQuicFrames(transport_version())) {
    QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(&*session_,
                                                            kMaxStreams);
  } else {
    QuicSessionPeer::SetMaxOpenIncomingStreams(&*session_, kMaxStreams);
  }
  // GetNth assumes that both the crypto and header streams have been
  // open, but the stream id manager, using GetFirstBidirectional... only
  // assumes that the crypto stream is open. This means that GetNth...(0)
  // Will return stream ID == 8 (with id ==0 for crypto and id==4 for headers).
  // It also means that GetNth(kMax..=5) returns 28 (streams 0/1/2/3/4 are ids
  // 8, 12, 16, 20, 24, respectively, so stream#5 is stream id 28).
  // However, the stream ID manager does not assume stream 4 is for headers.
  // The ID manager would assume that stream#5 is streamid 24.
  // In order to make this all work out properly, kFinalStreamId will
  // be set to GetNth...(kMaxStreams-1)... but only for IETF QUIC
  const QuicStreamId kFirstStreamId = GetNthClientInitiatedBidirectionalId(0);
  const QuicStreamId kFinalStreamId =
      GetNthClientInitiatedBidirectionalId(kMaxStreams);
  // Create kMaxStreams data streams, and close them all without receiving a
  // FIN or a RST_STREAM from the client.
  const QuicStreamId kNextId = QuicUtils::StreamIdDelta(transport_version());
  for (QuicStreamId i = kFirstStreamId; i < kFinalStreamId; i += kNextId) {
    QuicStreamFrame data1(i, false, 0, absl::string_view("HT"));
    session_->OnStreamFrame(data1);
    CloseStream(i);
  }
  // Try and open a stream that exceeds the limit.
  if (!VersionHasIetfQuicFrames(transport_version())) {
    // On versions other than 99, opening such a stream results in a
    // RST_STREAM.
    EXPECT_CALL(*connection_, SendControlFrame(_)).Times(1);
    EXPECT_CALL(*connection_,
                OnStreamReset(kFinalStreamId, QUIC_REFUSED_STREAM))
        .Times(1);
  } else {
    // On version 99 opening such a stream results in a connection close.
    EXPECT_CALL(
        *connection_,
        CloseConnection(QUIC_INVALID_STREAM_ID,
                        testing::MatchesRegex(
                            "Stream id \\d+ would exceed stream count limit 5"),
                        _));
  }
  // Create one more data streams to exceed limit of open stream.
  QuicStreamFrame data1(kFinalStreamId, false, 0, absl::string_view("HT"));
  session_->OnStreamFrame(data1);
}

TEST_P(QuicSpdySessionTestServer, DrainingStreamsDoNotCountAsOpened) {
  Initialize();
  // Verify that a draining stream (which has received a FIN but not consumed
  // it) does not count against the open quota (because it is closed from the
  // protocol point of view).
  CompleteHandshake();
  if (VersionHasIetfQuicFrames(transport_version())) {
    // Simulate receiving a config. so that MAX_STREAMS/etc frames may
    // be transmitted
    QuicSessionPeer::set_is_configured(&*session_, true);
    // Version 99 will result in a MAX_STREAMS frame as streams are consumed
    // (via the OnStreamFrame call) and then released (via
    // StreamDraining). Eventually this node will believe that the peer is
    // running low on available stream ids and then send a MAX_STREAMS frame,
    // caught by this EXPECT_CALL.
    EXPECT_CALL(*connection_, SendControlFrame(_)).Times(1);
  } else {
    EXPECT_CALL(*connection_, SendControlFrame(_)).Times(0);
  }
  EXPECT_CALL(*connection_, OnStreamReset(_, QUIC_REFUSED_STREAM)).Times(0);
  const QuicStreamId kMaxStreams = 5;
  if (VersionHasIetfQuicFrames(transport_version())) {
    QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(&*session_,
                                                            kMaxStreams);
  } else {
    QuicSessionPeer::SetMaxOpenIncomingStreams(&*session_, kMaxStreams);
  }

  // Create kMaxStreams + 1 data streams, and mark them draining.
  const QuicStreamId kFirstStreamId = GetNthClientInitiatedBidirectionalId(0);
  const QuicStreamId kFinalStreamId =
      GetNthClientInitiatedBidirectionalId(kMaxStreams + 1);
  for (QuicStreamId i = kFirstStreamId; i < kFinalStreamId; i += IdDelta()) {
    QuicStreamFrame data1(i, true, 0, absl::string_view("HT"));
    session_->OnStreamFrame(data1);
    EXPECT_EQ(1u, QuicSessionPeer::GetNumOpenDynamicStreams(&*session_));
    session_->StreamDraining(i, /*unidirectional=*/false);
    EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&*session_));
  }
}

class QuicSpdySessionTestClient : public QuicSpdySessionTestBase {
 protected:
  QuicSpdySessionTestClient()
      : QuicSpdySessionTestBase(Perspective::IS_CLIENT, false) {}
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicSpdySessionTestClient,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicSpdySessionTestClient, UsesPendingStreamsForFrame) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  EXPECT_TRUE(session_->UsesPendingStreamForFrame(
      STREAM_FRAME, QuicUtils::GetFirstUnidirectionalStreamId(
                        transport_version(), Perspective::IS_SERVER)));
  EXPECT_TRUE(session_->UsesPendingStreamForFrame(
      RST_STREAM_FRAME, QuicUtils::GetFirstUnidirectionalStreamId(
                            transport_version(), Perspective::IS_SERVER)));
  EXPECT_FALSE(session_->UsesPendingStreamForFrame(
      RST_STREAM_FRAME, QuicUtils::GetFirstUnidirectionalStreamId(
                            transport_version(), Perspective::IS_CLIENT)));
  EXPECT_FALSE(session_->UsesPendingStreamForFrame(
      STOP_SENDING_FRAME, QuicUtils::GetFirstUnidirectionalStreamId(
                              transport_version(), Perspective::IS_SERVER)));
  EXPECT_FALSE(session_->UsesPendingStreamForFrame(
      RST_STREAM_FRAME, QuicUtils::GetFirstBidirectionalStreamId(
                            transport_version(), Perspective::IS_SERVER)));
}

// Regression test for crbug.com/977581.
TEST_P(QuicSpdySessionTestClient, BadStreamFramePendingStream) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&*session_));
  QuicStreamId stream_id1 =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);
  // A bad stream frame with no data and no fin.
  QuicStreamFrame data1(stream_id1, false, 0, 0);
  session_->OnStreamFrame(data1);
}

TEST_P(QuicSpdySessionTestClient, PendingStreamKeepsConnectionAlive) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();
  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_SERVER);

  QuicStreamFrame frame(stream_id, false, 1, "test");
  EXPECT_FALSE(session_->ShouldKeepConnectionAlive());
  session_->OnStreamFrame(frame);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&*session_, stream_id));
  EXPECT_TRUE(session_->ShouldKeepConnectionAlive());
}

TEST_P(QuicSpdySessionTestClient, AvailableStreamsClient) {
  Initialize();
  ASSERT_TRUE(session_->GetOrCreateStream(
                  GetNthServerInitiatedBidirectionalId(2)) != nullptr);
  // Both server initiated streams with smaller stream IDs should be available.
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &*session_, GetNthServerInitiatedBidirectionalId(0)));
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &*session_, GetNthServerInitiatedBidirectionalId(1)));
  ASSERT_TRUE(session_->GetOrCreateStream(
                  GetNthServerInitiatedBidirectionalId(0)) != nullptr);
  ASSERT_TRUE(session_->GetOrCreateStream(
                  GetNthServerInitiatedBidirectionalId(1)) != nullptr);
  // And client initiated stream ID should be not available.
  EXPECT_FALSE(QuicSessionPeer::IsStreamAvailable(
      &*session_, GetNthClientInitiatedBidirectionalId(0)));
}

// Regression test for b/130740258 and https://crbug.com/971779.
// If headers that are too large or empty are received (these cases are handled
// the same way, as QuicHeaderList clears itself when headers exceed the limit),
// then the stream is reset.  No more frames must be sent in this case.
TEST_P(QuicSpdySessionTestClient, TooLargeHeadersMustNotCauseWriteAfterReset) {
  Initialize();
  // In IETF QUIC, HEADERS do not carry FIN flag, and OnStreamHeaderList() is
  // never called after an error, including too large headers.
  if (VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();
  TestStream* stream = session_->CreateOutgoingBidirectionalStream();

  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  // Write headers with FIN set to close write side of stream.
  // Header block does not matter.
  stream->WriteHeaders(HttpHeaderBlock(), /* fin = */ true, nullptr);

  // Receive headers that are too large or empty, with FIN set.
  // This causes the stream to be reset.  No frames must be written after this.
  QuicHeaderList headers;
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_,
              OnStreamReset(stream->id(), QUIC_HEADERS_TOO_LARGE));
  stream->OnStreamHeaderList(/* fin = */ true,
                             headers.uncompressed_header_bytes(), headers);
}

TEST_P(QuicSpdySessionTestClient, RecordFinAfterReadSideClosed) {
  Initialize();
  // Verify that an incoming FIN is recorded in a stream object even if the read
  // side has been closed.  This prevents an entry from being made in
  // locally_closed_streams_highest_offset_ (which will never be deleted).
  CompleteHandshake();
  TestStream* stream = session_->CreateOutgoingBidirectionalStream();
  QuicStreamId stream_id = stream->id();

  // Close the read side manually.
  QuicStreamPeer::CloseReadSide(stream);

  // Receive a stream data frame with FIN.
  QuicStreamFrame frame(stream_id, true, 0, absl::string_view());
  session_->OnStreamFrame(frame);
  EXPECT_TRUE(stream->fin_received());

  // Reset stream locally.
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream->id(), _));
  stream->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream));

  EXPECT_TRUE(connection_->connected());
  EXPECT_TRUE(QuicSessionPeer::IsStreamClosed(&*session_, stream_id));
  EXPECT_FALSE(QuicSessionPeer::IsStreamCreated(&*session_, stream_id));

  // The stream is not waiting for the arrival of the peer's final offset as it
  // was received with the FIN earlier.
  EXPECT_EQ(
      0u,
      QuicSessionPeer::GetLocallyClosedStreamsHighestOffset(&*session_).size());
}

TEST_P(QuicSpdySessionTestClient, WritePriority) {
  Initialize();
  if (VersionUsesHttp3(transport_version())) {
    // IETF QUIC currently doesn't support PRIORITY.
    return;
  }
  CompleteHandshake();

  TestHeadersStream* headers_stream;
  QuicSpdySessionPeer::SetHeadersStream(&*session_, nullptr);
  headers_stream = new TestHeadersStream(&*session_);
  QuicSpdySessionPeer::SetHeadersStream(&*session_, headers_stream);

  // Make packet writer blocked so |headers_stream| will buffer its write data.
  EXPECT_CALL(*writer_, IsWriteBlocked()).WillRepeatedly(Return(true));

  const QuicStreamId id = 4;
  const QuicStreamId parent_stream_id = 9;
  const SpdyPriority priority = kV3HighestPriority;
  const bool exclusive = true;
  session_->WritePriority(id, parent_stream_id,
                          Spdy3PriorityToHttp2Weight(priority), exclusive);

  QuicStreamSendBuffer& send_buffer =
      QuicStreamPeer::SendBuffer(headers_stream);
  ASSERT_EQ(1u, send_buffer.size());

  SpdyPriorityIR priority_frame(
      id, parent_stream_id, Spdy3PriorityToHttp2Weight(priority), exclusive);
  SpdyFramer spdy_framer(SpdyFramer::ENABLE_COMPRESSION);
  SpdySerializedFrame frame = spdy_framer.SerializeFrame(priority_frame);

  const quiche::QuicheMemSlice& slice =
      QuicStreamSendBufferPeer::CurrentWriteSlice(&send_buffer)->slice;
  EXPECT_EQ(absl::string_view(frame.data(), frame.size()),
            absl::string_view(slice.data(), slice.length()));
}

TEST_P(QuicSpdySessionTestClient, Http3ServerPush) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&*session_));

  // Push unidirectional stream is type 0x01.
  std::string frame_type1;
  ASSERT_TRUE(absl::HexStringToBytes("01", &frame_type1));
  QuicStreamId stream_id1 =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_RECEIVE_SERVER_PUSH, _, _))
      .Times(1);
  session_->OnStreamFrame(QuicStreamFrame(stream_id1, /* fin = */ false,
                                          /* offset = */ 0, frame_type1));
}

TEST_P(QuicSpdySessionTestClient, Http3ServerPushOutofOrderFrame) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&*session_));

  // Push unidirectional stream is type 0x01.
  std::string frame_type;
  ASSERT_TRUE(absl::HexStringToBytes("01", &frame_type));
  // The first field of a push stream is the Push ID.
  std::string push_id;
  ASSERT_TRUE(absl::HexStringToBytes("4000", &push_id));

  QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);

  QuicStreamFrame data1(stream_id,
                        /* fin = */ false, /* offset = */ 0, frame_type);
  QuicStreamFrame data2(stream_id,
                        /* fin = */ false, /* offset = */ frame_type.size(),
                        push_id);

  // Receiving some stream data without stream type does not open the stream.
  session_->OnStreamFrame(data2);
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&*session_));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_RECEIVE_SERVER_PUSH, _, _))
      .Times(1);
  session_->OnStreamFrame(data1);
}

TEST_P(QuicSpdySessionTestClient, ServerDisableQpackDynamicTable) {
  SetQuicFlag(quic_server_disable_qpack_dynamic_table, true);
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();

  // Use an arbitrary stream id for creating the receive control stream.
  QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  QuicStreamFrame data1(stream_id, false, 0, absl::string_view(type, 1));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());
  // Receive the QPACK dynamic table capacity from the peer.
  const uint64_t capacity = 512;
  SettingsFrame settings;
  settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = capacity;
  std::string data = HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamFrame frame(stream_id, false, 1, data);
  session_->OnStreamFrame(frame);

  // Verify that the encoder's dynamic table capacity is limited to the
  // peer's value.
  QpackEncoder* qpack_encoder = session_->qpack_encoder();
  EXPECT_EQ(capacity, qpack_encoder->MaximumDynamicTableCapacity());
  QpackEncoderHeaderTable* encoder_header_table =
      QpackEncoderPeer::header_table(qpack_encoder);
  EXPECT_EQ(capacity, encoder_header_table->dynamic_table_capacity());
  EXPECT_EQ(capacity, encoder_header_table->maximum_dynamic_table_capacity());

  // Verify that the advertised capacity is the default.
  SettingsFrame outgoing_settings = session_->settings();
  EXPECT_EQ(kDefaultQpackMaxDynamicTableCapacity,
            outgoing_settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY]);
}

TEST_P(QuicSpdySessionTestClient, DisableQpackDynamicTable) {
  SetQuicFlag(quic_server_disable_qpack_dynamic_table, false);
  qpack_maximum_dynamic_table_capacity_ = 0;
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();

  // Use an arbitrary stream id for creating the receive control stream.
  QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  QuicStreamFrame data1(stream_id, false, 0, absl::string_view(type, 1));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());
  // Receive the QPACK dynamic table capacity from the peer.
  const uint64_t capacity = 512;
  SettingsFrame settings;
  settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = capacity;
  std::string data = HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamFrame frame(stream_id, false, 1, data);
  session_->OnStreamFrame(frame);

  // Verify that the encoder's dynamic table capacity is 0.
  QpackEncoder* qpack_encoder = session_->qpack_encoder();
  EXPECT_EQ(capacity, qpack_encoder->MaximumDynamicTableCapacity());
  QpackEncoderHeaderTable* encoder_header_table =
      QpackEncoderPeer::header_table(qpack_encoder);
  EXPECT_EQ(0, encoder_header_table->dynamic_table_capacity());
  EXPECT_EQ(capacity, encoder_header_table->maximum_dynamic_table_capacity());

  // Verify that the advertised capacity is 0.
  SettingsFrame outgoing_settings = session_->settings();
  EXPECT_EQ(0, outgoing_settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY]);
}

TEST_P(QuicSpdySessionTestServer, OnStreamFrameLost) {
  Initialize();
  CompleteHandshake();
  InSequence s;

  // Drive congestion control manually.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_->connection(), send_algorithm);

  TestCryptoStream* crypto_stream = session_->GetMutableCryptoStream();
  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_->CreateOutgoingBidirectionalStream();

  QuicStreamFrame frame2(stream2->id(), false, 0, 9);
  QuicStreamFrame frame3(stream4->id(), false, 0, 9);

  // Lost data on cryption stream, streams 2 and 4.
  EXPECT_CALL(*stream4, HasPendingRetransmission()).WillOnce(Return(true));
  if (!QuicVersionUsesCryptoFrames(transport_version())) {
    EXPECT_CALL(*crypto_stream, HasPendingRetransmission())
        .WillOnce(Return(true));
  }
  EXPECT_CALL(*stream2, HasPendingRetransmission()).WillOnce(Return(true));
  session_->OnFrameLost(QuicFrame(frame3));
  if (!QuicVersionUsesCryptoFrames(transport_version())) {
    QuicStreamFrame frame1(QuicUtils::GetCryptoStreamId(transport_version()),
                           false, 0, 1300);
    session_->OnFrameLost(QuicFrame(frame1));
  } else {
    QuicCryptoFrame crypto_frame(ENCRYPTION_INITIAL, 0, 1300);
    session_->OnFrameLost(QuicFrame(&crypto_frame));
  }
  session_->OnFrameLost(QuicFrame(frame2));
  EXPECT_TRUE(session_->WillingAndAbleToWrite());

  // Mark streams 2 and 4 write blocked.
  session_->MarkConnectionLevelWriteBlocked(stream2->id());
  session_->MarkConnectionLevelWriteBlocked(stream4->id());

  // Lost data is retransmitted before new data, and retransmissions for crypto
  // stream go first.
  // Do not check congestion window when crypto stream has lost data.
  EXPECT_CALL(*send_algorithm, CanSend(_)).Times(0);
  if (!QuicVersionUsesCryptoFrames(transport_version())) {
    EXPECT_CALL(*crypto_stream, OnCanWrite());
    EXPECT_CALL(*crypto_stream, HasPendingRetransmission())
        .WillOnce(Return(false));
  }
  // Check congestion window for non crypto streams.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream4, OnCanWrite());
  EXPECT_CALL(*stream4, HasPendingRetransmission()).WillOnce(Return(false));
  // Connection is blocked.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillRepeatedly(Return(false));

  session_->OnCanWrite();
  EXPECT_TRUE(session_->WillingAndAbleToWrite());

  // Unblock connection.
  // Stream 2 retransmits lost data.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*stream2, HasPendingRetransmission()).WillOnce(Return(false));
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  // Stream 2 sends new data.
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream4, OnCanWrite());
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));

  session_->OnCanWrite();
  EXPECT_FALSE(session_->WillingAndAbleToWrite());
}

TEST_P(QuicSpdySessionTestServer, DonotRetransmitDataOfClosedStreams) {
  Initialize();
  // Resetting a stream will send a QPACK Stream Cancellation instruction on the
  // decoder stream.  For simplicity, ignore writes on this stream.
  CompleteHandshake();
  NoopQpackStreamSenderDelegate qpack_stream_sender_delegate;
  if (VersionUsesHttp3(transport_version())) {
    session_->qpack_decoder()->set_qpack_stream_sender_delegate(
        &qpack_stream_sender_delegate);
  }

  InSequence s;

  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_->CreateOutgoingBidirectionalStream();

  QuicStreamFrame frame1(stream2->id(), false, 0, 9);
  QuicStreamFrame frame2(stream4->id(), false, 0, 9);
  QuicStreamFrame frame3(stream6->id(), false, 0, 9);

  EXPECT_CALL(*stream6, HasPendingRetransmission()).WillOnce(Return(true));
  EXPECT_CALL(*stream4, HasPendingRetransmission()).WillOnce(Return(true));
  EXPECT_CALL(*stream2, HasPendingRetransmission()).WillOnce(Return(true));
  session_->OnFrameLost(QuicFrame(frame3));
  session_->OnFrameLost(QuicFrame(frame2));
  session_->OnFrameLost(QuicFrame(frame1));

  session_->MarkConnectionLevelWriteBlocked(stream2->id());
  session_->MarkConnectionLevelWriteBlocked(stream4->id());
  session_->MarkConnectionLevelWriteBlocked(stream6->id());

  // Reset stream 4 locally.
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream4->id(), _));
  stream4->Reset(QUIC_STREAM_CANCELLED);

  // Verify stream 4 is removed from streams with lost data list.
  EXPECT_CALL(*stream6, OnCanWrite());
  EXPECT_CALL(*stream6, HasPendingRetransmission()).WillOnce(Return(false));
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*stream2, HasPendingRetransmission()).WillOnce(Return(false));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*stream6, OnCanWrite());
  session_->OnCanWrite();
}

TEST_P(QuicSpdySessionTestServer, RetransmitFrames) {
  Initialize();
  CompleteHandshake();
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_->connection(), send_algorithm);
  InSequence s;

  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_->CreateOutgoingBidirectionalStream();
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&ClearControlFrame));
  session_->SendWindowUpdate(stream2->id(), 9);

  QuicStreamFrame frame1(stream2->id(), false, 0, 9);
  QuicStreamFrame frame2(stream4->id(), false, 0, 9);
  QuicStreamFrame frame3(stream6->id(), false, 0, 9);
  QuicWindowUpdateFrame window_update(1, stream2->id(), 9);
  QuicFrames frames;
  frames.push_back(QuicFrame(frame1));
  frames.push_back(QuicFrame(window_update));
  frames.push_back(QuicFrame(frame2));
  frames.push_back(QuicFrame(frame3));
  EXPECT_FALSE(session_->WillingAndAbleToWrite());

  EXPECT_CALL(*stream2, RetransmitStreamData(_, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&ClearControlFrame));
  EXPECT_CALL(*stream4, RetransmitStreamData(_, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*stream6, RetransmitStreamData(_, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));
  session_->RetransmitFrames(frames, PTO_RETRANSMISSION);
}

TEST_P(QuicSpdySessionTestServer, OnPriorityFrame) {
  Initialize();
  QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
  TestStream* stream = session_->CreateIncomingStream(stream_id);
  session_->OnPriorityFrame(stream_id,
                            spdy::SpdyStreamPrecedence(kV3HighestPriority));

  EXPECT_EQ((QuicStreamPriority(HttpStreamPriority{
                kV3HighestPriority, HttpStreamPriority::kDefaultIncremental})),
            stream->priority());
}

TEST_P(QuicSpdySessionTestServer, OnPriorityUpdateFrame) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);
  EXPECT_CALL(debug_visitor, OnSettingsFrameSent(_));
  CompleteHandshake();

  // Create control stream.
  QuicStreamId receive_control_stream_id =
      GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  absl::string_view stream_type(type, 1);
  QuicStreamOffset offset = 0;
  QuicStreamFrame data1(receive_control_stream_id, false, offset, stream_type);
  offset += stream_type.length();
  EXPECT_CALL(debug_visitor,
              OnPeerControlStreamCreated(receive_control_stream_id));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(receive_control_stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());

  // Send SETTINGS frame.
  std::string serialized_settings = HttpEncoder::SerializeSettingsFrame({});
  QuicStreamFrame data2(receive_control_stream_id, false, offset,
                        serialized_settings);
  offset += serialized_settings.length();
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(_));
  session_->OnStreamFrame(data2);

  // PRIORITY_UPDATE frame for first request stream.
  const QuicStreamId stream_id1 = GetNthClientInitiatedBidirectionalId(0);
  PriorityUpdateFrame priority_update1{stream_id1, "u=2"};
  std::string serialized_priority_update1 =
      HttpEncoder::SerializePriorityUpdateFrame(priority_update1);
  QuicStreamFrame data3(receive_control_stream_id,
                        /* fin = */ false, offset, serialized_priority_update1);
  offset += serialized_priority_update1.size();

  // PRIORITY_UPDATE frame arrives after stream creation.
  TestStream* stream1 = session_->CreateIncomingStream(stream_id1);
  EXPECT_EQ(QuicStreamPriority(
                HttpStreamPriority{HttpStreamPriority::kDefaultUrgency,
                                   HttpStreamPriority::kDefaultIncremental}),
            stream1->priority());
  EXPECT_CALL(debug_visitor, OnPriorityUpdateFrameReceived(priority_update1));
  session_->OnStreamFrame(data3);
  EXPECT_EQ(QuicStreamPriority(HttpStreamPriority{
                2u, HttpStreamPriority::kDefaultIncremental}),
            stream1->priority());

  // PRIORITY_UPDATE frame for second request stream.
  const QuicStreamId stream_id2 = GetNthClientInitiatedBidirectionalId(1);
  PriorityUpdateFrame priority_update2{stream_id2, "u=5, i"};
  std::string serialized_priority_update2 =
      HttpEncoder::SerializePriorityUpdateFrame(priority_update2);
  QuicStreamFrame stream_frame3(receive_control_stream_id,
                                /* fin = */ false, offset,
                                serialized_priority_update2);

  // PRIORITY_UPDATE frame arrives before stream creation,
  // priority value is buffered.
  EXPECT_CALL(debug_visitor, OnPriorityUpdateFrameReceived(priority_update2));
  session_->OnStreamFrame(stream_frame3);
  // Priority is applied upon stream construction.
  TestStream* stream2 = session_->CreateIncomingStream(stream_id2);
  EXPECT_EQ(QuicStreamPriority(HttpStreamPriority{5u, true}),
            stream2->priority());
}

TEST_P(QuicSpdySessionTestServer, OnInvalidPriorityUpdateFrame) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  // Create control stream.
  QuicStreamId receive_control_stream_id =
      GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  absl::string_view stream_type(type, 1);
  QuicStreamOffset offset = 0;
  QuicStreamFrame data1(receive_control_stream_id, false, offset, stream_type);
  offset += stream_type.length();
  EXPECT_CALL(debug_visitor,
              OnPeerControlStreamCreated(receive_control_stream_id));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(receive_control_stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());

  // Send SETTINGS frame.
  std::string serialized_settings = HttpEncoder::SerializeSettingsFrame({});
  QuicStreamFrame data2(receive_control_stream_id, false, offset,
                        serialized_settings);
  offset += serialized_settings.length();
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(_));
  session_->OnStreamFrame(data2);

  // PRIORITY_UPDATE frame with Priority Field Value that is not valid
  // Structured Headers.
  const QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
  PriorityUpdateFrame priority_update{stream_id, "00"};

  EXPECT_CALL(debug_visitor, OnPriorityUpdateFrameReceived(priority_update));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_PRIORITY_UPDATE,
                              "Invalid PRIORITY_UPDATE frame payload.", _));

  std::string serialized_priority_update =
      HttpEncoder::SerializePriorityUpdateFrame(priority_update);
  Quic
"""


```
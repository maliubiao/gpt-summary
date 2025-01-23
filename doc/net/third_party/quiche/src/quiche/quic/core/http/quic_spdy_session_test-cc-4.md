Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium networking stack file. Specifically, they are asking for:

1. **Functionality description:** What does this code do?
2. **Relationship to JavaScript:** Does this code interact with JavaScript? If so, how?
3. **Logic and I/O:**  Can we infer input and output based on the code?
4. **Common user/programming errors:** What mistakes might lead to this code being executed?
5. **User journey:** How might a user's actions lead to this code being involved (for debugging)?
6. **Overall summary:** A concise summary of the code's purpose.

This is part 5 of 6, indicating a larger context. The code appears to be a series of C++ unit tests for the `QuicSpdySession` class, specifically focusing on HTTP/3 functionality and WebTransport.

Let's break down the code and address each point:

* **Test Naming Convention:** The tests are named using `TEST_P`, indicating parameterized tests. This means they are run with different configurations defined elsewhere (likely the different `transport_version()` values).
* **`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`:** These are standard Google Test assertions, verifying conditions within the tests.
* **`Mock*` Classes:**  Classes like `MockQuicConnection`, `MockHttp3DebugVisitor` are used for mocking dependencies, allowing isolated testing of `QuicSpdySession`.
* **HTTP/3 Concepts:** The tests involve concepts like:
    * Control Streams (`kControlStream`)
    * Settings Frames (`SETTINGS_*`)
    * QPACK (header compression)
    * GOAWAY frames
    * CANCEL_PUSH frames
    * Accept-CH frames
    * HTTP Datagrams (`SETTINGS_H3_DATAGRAM`, `SETTINGS_H3_DATAGRAM_DRAFT04`)
    * WebTransport (`SETTINGS_WEBTRANS_DRAFT00`)
* **Stream Management:**  The tests manipulate and observe the creation and management of QUIC streams.
* **Connection Closure:** Several tests check scenarios where the connection is intentionally closed due to errors.

**Plan:**

1. **Summarize the core functionality:**  This file tests the HTTP/3 and WebTransport aspects of `QuicSpdySession`.
2. **JavaScript Relationship:** Explain how these networking features relate to browser APIs used by JavaScript.
3. **Input/Output:**  Focus on the test setup and the expected outcomes based on assertions.
4. **User Errors:**  Think about scenarios where misconfiguration or unexpected server behavior could trigger these code paths.
5. **User Journey:**  Consider the steps a user might take in a browser that would lead to HTTP/3 or WebTransport being used.
6. **Summarize the specific functionality of *this* snippet:** Focus on what the tests in *this* specific part are doing (handling connection blocking, critical stream closure, CANCEL_PUSH, GOAWAY, settings negotiation, HTTP datagrams, and WebTransport).
这是Chromium网络栈中 `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc` 文件的第五部分，主要功能是**测试 `QuicSpdySession` 类在 HTTP/3 和 WebTransport 场景下的行为**。

**具体功能归纳如下：**

1. **连接阻塞测试:**
   - 测试当连接级别的流控被阻塞时，`QuicSpdySession` 是否正确报告状态。
   - 模拟发送控制流被阻塞的情况，并验证会话是否处于无法写入的状态。

2. **对端关闭关键发送流测试:**
   - 针对 HTTP/3，测试当对端发送 `STOP_SENDING` 帧关闭关键的发送流（控制流、QPACK 编码器流、QPACK 解码器流）时，`QuicSpdySession` 是否会正确关闭连接，并给出相应的错误代码和原因。

3. **接收 CANCEL_PUSH 帧测试:**
   - 针对 HTTP/3，测试当接收到 `CANCEL_PUSH` 帧时，`QuicSpdySession` 是否会关闭连接，并给出 `QUIC_HTTP_FRAME_ERROR` 错误。

4. **连接关闭时发送 HTTP/3 GOAWAY 帧测试:**
   - 针对 HTTP/3，测试在关闭连接时，`QuicSpdySession` 是否会发送 `GOAWAY` 帧，指示对端不再接受新流，并确保 `GOAWAY` 帧包含正确的下一个可创建的流 ID。

5. **客户端不发送初始 Max Push ID 设置测试:**
   - 针对 HTTP/3 客户端，测试在没有设置初始最大 Push ID 的情况下，是否不会发送相关的设置。

6. **客户端接收到 SPDY 设置时的处理测试:**
   - 针对 HTTP/3 客户端，测试当接收到 HTTP/2 的 SPDY 设置时，`QuicSpdySession` 是否会关闭连接，并给出 `QUIC_HTTP_RECEIVE_SPDY_SETTING` 错误。

7. **客户端接收 Accept-CH 帧测试:**
   - 针对 HTTP/3 客户端，测试当接收到 `ACCEPT_CH` 帧时，`QuicSpdySession` 是否能正确解析并触发相应的回调。

8. **通过 ALPS 接收 Accept-CH 帧测试:**
   - 针对 HTTP/3 客户端，测试当通过 ALPS（应用层协议协商）接收到序列化的 `ACCEPT_CH` 帧时，`QuicSpdySession` 是否能正确解析并触发回调。

9. **ALPS 传输禁止帧测试:**
   - 针对 HTTP/3 客户端，测试当通过 ALPS 接收到禁止的帧类型（例如 DATA 帧）时，`QuicSpdySession` 是否会返回错误。

10. **ALPS 传输不完整帧测试:**
    - 针对 HTTP/3 客户端，测试当通过 ALPS 接收到不完整的 HTTP/3 帧时，`QuicSpdySession` 是否会返回错误。

11. **通过 ALPS 接收 Settings 帧后再通过控制流接收 Settings 帧测试:**
    - 针对 HTTP/3 客户端，测试先通过 ALPS 接收 `SETTINGS` 帧，再通过控制流接收 `SETTINGS` 帧时，`QuicSpdySession` 的行为。验证重复的设置必须保持一致，并且限制值不能减少。

12. **通过 ALPS 接收 Settings 帧与通过控制流接收 Settings 帧冲突测试:**
    - 针对 HTTP/3 客户端，测试先通过 ALPS 接收 `SETTINGS` 帧，再通过控制流接收 `SETTINGS` 帧，如果存在冲突的值，`QuicSpdySession` 是否会关闭连接。

13. **ALPS 传输两个 Settings 帧测试:**
    - 针对 HTTP/3 客户端，测试当通过 ALPS 接收到多个 `SETTINGS` 帧时，`QuicSpdySession` 是否会返回错误。

14. **HTTP Datagram 设置测试 (多种组合):**
    - 测试客户端和服务端在支持不同版本的 HTTP Datagram (Draft04 和 RFC) 时，`QuicSpdySession` 如何协商最终支持的版本。

15. **WebTransport 设置测试 (多种组合):**
    - 测试客户端和服务端在支持不同版本的 WebTransport (Draft02 和 Draft07) 时，`QuicSpdySession` 如何协商最终支持的版本。
    - 测试 WebTransport 设置为 0 的情况。

16. **服务端 WebTransport 设置测试:**
    - 测试服务端启用 WebTransport 功能后，是否能正确处理 WebTransport 相关的设置。

17. **服务端缓冲传入流测试:**
    - 测试服务端在接收到与 WebTransport 会话关联的流之前，是否会缓冲这些流。
    - 测试服务端缓冲传入流的数量限制。

18. **服务端缓冲传入流并带有 FIN 测试:**
    - 测试服务端接收到带有 FIN 标志的 WebTransport 流时的处理。

19. **服务端重置传出 WebTransport 流测试:**
    - 测试服务端重置与 WebTransport 会话关联的传出流时的行为。

20. **客户端在没有 Extended Connect 的情况下使用 WebTransport 测试:**
    - 测试客户端在没有启用 Extended CONNECT 的情况下尝试使用 WebTransport 的行为。

**与 JavaScript 的关系及举例说明:**

这些测试的代码本身是 C++，并不直接运行在 JavaScript 环境中。但是，这些测试验证的网络协议功能（HTTP/3, WebTransport）是浏览器与服务器进行通信的基础。JavaScript 可以通过浏览器提供的 Web API 使用这些功能。

* **HTTP/3:** JavaScript 的 `fetch()` API 可以使用 HTTP/3 进行数据请求，前提是浏览器和服务器都支持 HTTP/3。
    ```javascript
    fetch('https://example.com/data', {
      // ...其他选项
    }).then(response => {
      // 处理响应
    });
    ```
    这段 JavaScript 代码发起的网络请求，底层可能会使用 `QuicSpdySession` 中测试的 HTTP/3 功能进行通信，例如协商 `SETTINGS`、处理头部、进行流控等。

* **WebTransport:** JavaScript 提供了 WebTransport API，允许在浏览器和服务器之间建立双向的、低延迟的连接。
    ```javascript
    const transport = new WebTransport('https://example.com/webtransport');

    transport.ready.then(() => {
      console.log('WebTransport 连接已建立');
      // 发送和接收数据
    });
    ```
    当 JavaScript 代码使用 `WebTransport` API 时，浏览器底层会使用 `QuicSpdySession` 中测试的 WebTransport 相关功能来建立和管理连接、发送和接收数据流。例如，测试中关于 `SETTINGS_WEBTRANS_DRAFT00` 的协商就直接影响到 JavaScript 的 `WebTransport` API 是否可用以及使用的版本。

**逻辑推理及假设输入与输出:**

以 **客户端接收 Accept-CH 帧测试** 为例：

* **假设输入:**
    * 已建立的 QUIC 连接 (`session_`)。
    * 对端发送的包含 `ACCEPT_CH` 帧的 QUIC 流数据包 (`data3`)。
    * 假设 `ACCEPT_CH` 帧的内容是 `{"foo", "bar"}`。

* **逻辑推理:**
    1. `session_->OnStreamFrame(data3)` 被调用，表示接收到包含 `ACCEPT_CH` 帧的数据。
    2. `QuicSpdySession` 的 HTTP/3 帧解析逻辑会解析出 `ACCEPT_CH` 帧。
    3. 预期会调用 `debug_visitor` 的 `OnAcceptChFrameReceived` 方法，传入解析出的 `AcceptChFrame`。
    4. 预期会调用 `session_` 的 `OnAcceptChFrame` 方法，同样传入解析出的 `AcceptChFrame`。

* **预期输出:**
    * `EXPECT_CALL(debug_visitor, OnAcceptChFrameReceived(accept_ch))` 成功匹配。
    * `EXPECT_CALL(*session_, OnAcceptChFrame(accept_ch))` 成功匹配。

**用户或编程常见的使用错误及举例说明:**

* **HTTP/3 设置错误:** 如果服务端错误地发送了 HTTP/2 的 SPDY 设置，例如 `SETTINGS_INITIAL_WINDOW_SIZE`，客户端会关闭连接，如 **客户端接收到 SPDY 设置时的处理测试** 所示。这可能是服务端配置错误或协议版本协商错误导致。
* **WebTransport 版本不匹配:** 如果客户端和服务端配置的 WebTransport 版本不一致，连接可能无法建立或在使用过程中出现错误，如 **WebTransport 设置版本不匹配** 所示。这可能是由于客户端或服务端没有正确更新或配置支持的 WebTransport 版本。
* **ALPS 配置错误:** 如果通过 ALPS 传递了错误的 HTTP/3 帧，例如在连接建立后发送 DATA 帧，会导致连接错误，如 **ALPS 传输禁止帧测试** 所示。这可能是因为 ALPS 的数据格式或内容不符合 HTTP/3 的规范。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个支持 HTTP/3 和 WebTransport 的网站，并遇到了连接问题：

1. **用户在地址栏输入网址并回车:** 浏览器开始尝试与服务器建立连接，可能会进行 HTTP/3 的协议协商。
2. **QUIC 连接建立:** 底层使用 QUIC 协议建立连接，`QuicSpdySession` 对象被创建用于处理 HTTP/3 相关的逻辑。
3. **接收到服务器的 SETTINGS 帧:**  `QuicSpdySession` 会处理服务器发送的 `SETTINGS` 帧，例如协商 HTTP/3 Datagram 或 WebTransport 的支持情况。 如果服务器发送了错误的设置（如 SPDY 设置），则会触发 **客户端接收到 SPDY 设置时的处理测试** 中模拟的情况，导致连接关闭。
4. **尝试建立 WebTransport 连接:**  如果网页 JavaScript 代码使用了 `new WebTransport(...)` 尝试建立 WebTransport 连接，则会涉及到 **WebTransport 设置测试** 中测试的流程，例如检查服务器是否支持 WebTransport 以及支持的版本。如果版本不匹配，则会触发 **WebTransport 设置版本不匹配** 中模拟的情况。
5. **接收到服务器的 ACCEPT_CH 帧:** 如果服务器发送了 `Accept-CH` 头部，`QuicSpdySession` 会处理这个帧，对应 **客户端接收 Accept-CH 帧测试**。

**调试线索:** 如果在浏览器控制台看到与 HTTP/3 或 WebTransport 相关的连接错误，或者发现某些功能无法正常工作（例如 Datagram 无法发送，WebTransport 连接失败），开发者可以查看 Chrome 的 `net-internals` (chrome://net-internals/#quic) 工具，查看 QUIC 连接的详细信息，包括收发的帧、设置等，从而定位问题是否发生在 `QuicSpdySession` 的处理逻辑中。例如，可以查看是否收到了错误的 `SETTINGS` 帧，或者 WebTransport 的版本协商是否成功。

**这是第5部分，共6部分，请归纳一下它的功能:**

这部分测试主要集中在 **`QuicSpdySession` 类在处理 HTTP/3 特有的帧和设置，以及支持 WebTransport 功能时的正确性**。它涵盖了连接管理、错误处理、协议协商等多个方面，确保 `QuicSpdySession` 能够按照 HTTP/3 和 WebTransport 的规范正常工作。特别是对于客户端行为的测试较为详细，包括对接收到各种类型的帧和设置的处理。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
);
  EXPECT_TRUE(session_->IsConnectionFlowControlBlocked());

  QuicSendControlStream* send_control_stream =
      QuicSpdySessionPeer::GetSendControlStream(&*session_);
  // Mark send_control stream write blocked.
  session_->MarkConnectionLevelWriteBlocked(send_control_stream->id());
  EXPECT_FALSE(session_->WillingAndAbleToWrite());
}

TEST_P(QuicSpdySessionTestServer, PeerClosesCriticalSendStream) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  QuicSendControlStream* control_stream =
      QuicSpdySessionPeer::GetSendControlStream(&*session_);
  ASSERT_TRUE(control_stream);

  QuicStopSendingFrame stop_sending_control_stream(
      kInvalidControlFrameId, control_stream->id(), QUIC_STREAM_CANCELLED);
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_CLOSED_CRITICAL_STREAM,
                      "STOP_SENDING received for send control stream", _));
  session_->OnStopSendingFrame(stop_sending_control_stream);

  QpackSendStream* decoder_stream =
      QuicSpdySessionPeer::GetQpackDecoderSendStream(&*session_);
  ASSERT_TRUE(decoder_stream);

  QuicStopSendingFrame stop_sending_decoder_stream(
      kInvalidControlFrameId, decoder_stream->id(), QUIC_STREAM_CANCELLED);
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_CLOSED_CRITICAL_STREAM,
                      "STOP_SENDING received for QPACK send stream", _));
  session_->OnStopSendingFrame(stop_sending_decoder_stream);

  QpackSendStream* encoder_stream =
      QuicSpdySessionPeer::GetQpackEncoderSendStream(&*session_);
  ASSERT_TRUE(encoder_stream);

  QuicStopSendingFrame stop_sending_encoder_stream(
      kInvalidControlFrameId, encoder_stream->id(), QUIC_STREAM_CANCELLED);
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_CLOSED_CRITICAL_STREAM,
                      "STOP_SENDING received for QPACK send stream", _));
  session_->OnStopSendingFrame(stop_sending_encoder_stream);
}

TEST_P(QuicSpdySessionTestServer, CloseConnectionOnCancelPush) {
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
  QuicStreamFrame data1(receive_control_stream_id, /* fin = */ false, offset,
                        stream_type);
  offset += stream_type.length();
  EXPECT_CALL(debug_visitor,
              OnPeerControlStreamCreated(receive_control_stream_id));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(receive_control_stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());

  // First frame has to be SETTINGS.
  std::string serialized_settings = HttpEncoder::SerializeSettingsFrame({});
  QuicStreamFrame data2(receive_control_stream_id, /* fin = */ false, offset,
                        serialized_settings);
  offset += serialized_settings.length();
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(_));
  session_->OnStreamFrame(data2);

  std::string cancel_push_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("03"   // CANCEL_PUSH
                             "01"   // length
                             "00",  // push ID
                             &cancel_push_frame));
  QuicStreamFrame data3(receive_control_stream_id, /* fin = */ false, offset,
                        cancel_push_frame);
  EXPECT_CALL(*connection_, CloseConnection(QUIC_HTTP_FRAME_ERROR,
                                            "CANCEL_PUSH frame received.", _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_,
              SendConnectionClosePacket(QUIC_HTTP_FRAME_ERROR, _,
                                        "CANCEL_PUSH frame received."));
  session_->OnStreamFrame(data3);
}

TEST_P(QuicSpdySessionTestServer, Http3GoAwayWhenClosingConnection) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  EXPECT_CALL(debug_visitor, OnSettingsFrameSent(_));
  CompleteHandshake();

  QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);

  // Create stream by receiving some data (CreateIncomingStream() would not
  // update the session's largest peer created stream ID).
  const QuicByteCount headers_payload_length = 10;
  std::string headers_frame_header =
      HttpEncoder::SerializeHeadersFrameHeader(headers_payload_length);
  EXPECT_CALL(debug_visitor,
              OnHeadersFrameReceived(stream_id, headers_payload_length));
  session_->OnStreamFrame(
      QuicStreamFrame(stream_id, false, 0, headers_frame_header));

  EXPECT_EQ(stream_id, QuicSessionPeer::GetLargestPeerCreatedStreamId(
                           &*session_, /*unidirectional = */ false));

  // Stream with stream_id is already received and potentially processed,
  // therefore a GOAWAY frame is sent with the next stream ID.
  EXPECT_CALL(debug_visitor,
              OnGoAwayFrameSent(stream_id +
                                QuicUtils::StreamIdDelta(transport_version())));

  // Close connection.
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_NO_ERROR, _, _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(QUIC_NO_ERROR, _, _))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::ReallySendConnectionClosePacket));
  connection_->CloseConnection(
      QUIC_NO_ERROR, "closing connection",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

TEST_P(QuicSpdySessionTestClient, DoNotSendInitialMaxPushIdIfNotSet) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  InSequence s;
  EXPECT_CALL(debug_visitor, OnSettingsFrameSent(_));

  CompleteHandshake();
}

TEST_P(QuicSpdySessionTestClient, ReceiveSpdySettingInHttp3) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  SettingsFrame frame;
  frame.values[SETTINGS_MAX_FIELD_SECTION_SIZE] = 5;
  // https://datatracker.ietf.org/doc/html/draft-ietf-quic-http-30#section-7.2.4.1
  // specifies the presence of HTTP/2 setting as error.
  frame.values[spdy::SETTINGS_INITIAL_WINDOW_SIZE] = 100;

  CompleteHandshake();

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_RECEIVE_SPDY_SETTING, _, _));
  session_->OnSettingsFrame(frame);
}

TEST_P(QuicSpdySessionTestClient, ReceiveAcceptChFrame) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  // Create control stream.
  QuicStreamId receive_control_stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  absl::string_view stream_type(type, 1);
  QuicStreamOffset offset = 0;
  QuicStreamFrame data1(receive_control_stream_id, /* fin = */ false, offset,
                        stream_type);
  offset += stream_type.length();
  EXPECT_CALL(debug_visitor,
              OnPeerControlStreamCreated(receive_control_stream_id));

  session_->OnStreamFrame(data1);
  EXPECT_EQ(receive_control_stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());

  // First frame has to be SETTINGS.
  std::string serialized_settings = HttpEncoder::SerializeSettingsFrame({});
  QuicStreamFrame data2(receive_control_stream_id, /* fin = */ false, offset,
                        serialized_settings);
  offset += serialized_settings.length();
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(_));

  session_->OnStreamFrame(data2);

  // Receive ACCEPT_CH frame.
  AcceptChFrame accept_ch;
  accept_ch.entries.push_back({"foo", "bar"});
  std::string accept_ch_frame = HttpEncoder::SerializeAcceptChFrame(accept_ch);
  QuicStreamFrame data3(receive_control_stream_id, /* fin = */ false, offset,
                        accept_ch_frame);

  EXPECT_CALL(debug_visitor, OnAcceptChFrameReceived(accept_ch));
  EXPECT_CALL(*session_, OnAcceptChFrame(accept_ch));

  session_->OnStreamFrame(data3);
}

TEST_P(QuicSpdySessionTestClient, AcceptChViaAlps) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  std::string serialized_accept_ch_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("4089"     // type (ACCEPT_CH)
                             "08"       // length
                             "03"       // length of origin
                             "666f6f"   // origin "foo"
                             "03"       // length of value
                             "626172",  // value "bar"
                             &serialized_accept_ch_frame));

  AcceptChFrame expected_accept_ch_frame{{{"foo", "bar"}}};
  EXPECT_CALL(debug_visitor,
              OnAcceptChFrameReceivedViaAlps(expected_accept_ch_frame));

  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(serialized_accept_ch_frame.data()),
      serialized_accept_ch_frame.size());
  EXPECT_FALSE(error);
}

TEST_P(QuicSpdySessionTestClient, AlpsForbiddenFrame) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  std::string forbidden_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("00"       // type (DATA)
                             "03"       // length
                             "66666f",  // "foo"
                             &forbidden_frame));

  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(forbidden_frame.data()),
      forbidden_frame.size());
  ASSERT_TRUE(error);
  EXPECT_EQ("DATA frame forbidden", error.value());
}

TEST_P(QuicSpdySessionTestClient, AlpsIncompleteFrame) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  std::string incomplete_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("04"   // type (SETTINGS)
                             "03",  // non-zero length but empty payload
                             &incomplete_frame));

  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(incomplete_frame.data()),
      incomplete_frame.size());
  ASSERT_TRUE(error);
  EXPECT_EQ("incomplete HTTP/3 frame", error.value());
}

// After receiving a SETTINGS frame via ALPS,
// another SETTINGS frame is still allowed on control frame.
TEST_P(QuicSpdySessionTestClient, SettingsViaAlpsThenOnControlStream) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  QpackEncoder* qpack_encoder = session_->qpack_encoder();
  EXPECT_EQ(0u, qpack_encoder->MaximumDynamicTableCapacity());
  EXPECT_EQ(0u, qpack_encoder->maximum_blocked_streams());

  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  std::string serialized_settings_frame1;
  ASSERT_TRUE(
      absl::HexStringToBytes("04"    // type (SETTINGS)
                             "05"    // length
                             "01"    // SETTINGS_QPACK_MAX_TABLE_CAPACITY
                             "4400"  // 0x0400 = 1024
                             "07"    // SETTINGS_QPACK_BLOCKED_STREAMS
                             "20",   // 0x20 = 32
                             &serialized_settings_frame1));

  SettingsFrame expected_settings_frame1{
      {{SETTINGS_QPACK_MAX_TABLE_CAPACITY, 1024},
       {SETTINGS_QPACK_BLOCKED_STREAMS, 32}}};
  EXPECT_CALL(debug_visitor,
              OnSettingsFrameReceivedViaAlps(expected_settings_frame1));

  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(serialized_settings_frame1.data()),
      serialized_settings_frame1.size());
  EXPECT_FALSE(error);

  EXPECT_EQ(1024u, qpack_encoder->MaximumDynamicTableCapacity());
  EXPECT_EQ(32u, qpack_encoder->maximum_blocked_streams());

  const QuicStreamId control_stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);
  EXPECT_CALL(debug_visitor, OnPeerControlStreamCreated(control_stream_id));

  std::string stream_type;
  ASSERT_TRUE(absl::HexStringToBytes("00", &stream_type));
  session_->OnStreamFrame(QuicStreamFrame(control_stream_id, /* fin = */ false,
                                          /* offset = */ 0, stream_type));

  // SETTINGS_QPACK_MAX_TABLE_CAPACITY, if advertised again, MUST have identical
  // value.
  // SETTINGS_QPACK_BLOCKED_STREAMS is a limit.  Limits MUST NOT be reduced, but
  // increasing is okay.
  SettingsFrame expected_settings_frame2{
      {{SETTINGS_QPACK_MAX_TABLE_CAPACITY, 1024},
       {SETTINGS_QPACK_BLOCKED_STREAMS, 48}}};
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(expected_settings_frame2));
  std::string serialized_settings_frame2;
  ASSERT_TRUE(
      absl::HexStringToBytes("04"    // type (SETTINGS)
                             "05"    // length
                             "01"    // SETTINGS_QPACK_MAX_TABLE_CAPACITY
                             "4400"  // 0x0400 = 1024
                             "07"    // SETTINGS_QPACK_BLOCKED_STREAMS
                             "30",   // 0x30 = 48
                             &serialized_settings_frame2));
  session_->OnStreamFrame(QuicStreamFrame(control_stream_id, /* fin = */ false,
                                          /* offset = */ stream_type.length(),
                                          serialized_settings_frame2));

  EXPECT_EQ(1024u, qpack_encoder->MaximumDynamicTableCapacity());
  EXPECT_EQ(48u, qpack_encoder->maximum_blocked_streams());
}

// A SETTINGS frame received via ALPS and another one on the control stream
// cannot have conflicting values.
TEST_P(QuicSpdySessionTestClient,
       SettingsViaAlpsConflictsSettingsViaControlStream) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  QpackEncoder* qpack_encoder = session_->qpack_encoder();
  EXPECT_EQ(0u, qpack_encoder->MaximumDynamicTableCapacity());

  std::string serialized_settings_frame1;
  ASSERT_TRUE(
      absl::HexStringToBytes("04"     // type (SETTINGS)
                             "03"     // length
                             "01"     // SETTINGS_QPACK_MAX_TABLE_CAPACITY
                             "4400",  // 0x0400 = 1024
                             &serialized_settings_frame1));

  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(serialized_settings_frame1.data()),
      serialized_settings_frame1.size());
  EXPECT_FALSE(error);

  EXPECT_EQ(1024u, qpack_encoder->MaximumDynamicTableCapacity());

  const QuicStreamId control_stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);

  std::string stream_type;
  ASSERT_TRUE(absl::HexStringToBytes("00", &stream_type));
  session_->OnStreamFrame(QuicStreamFrame(control_stream_id, /* fin = */ false,
                                          /* offset = */ 0, stream_type));

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH,
                      "Server sent an SETTINGS_QPACK_MAX_TABLE_CAPACITY: "
                      "32 while current value is: 1024",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  std::string serialized_settings_frame2;
  ASSERT_TRUE(
      absl::HexStringToBytes("04"   // type (SETTINGS)
                             "02"   // length
                             "01"   // SETTINGS_QPACK_MAX_TABLE_CAPACITY
                             "20",  // 0x20 = 32
                             &serialized_settings_frame2));
  session_->OnStreamFrame(QuicStreamFrame(control_stream_id, /* fin = */ false,
                                          /* offset = */ stream_type.length(),
                                          serialized_settings_frame2));
}

TEST_P(QuicSpdySessionTestClient, AlpsTwoSettingsFrame) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  std::string banned_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("04"   // type (SETTINGS)
                             "00"   // length
                             "04"   // type (SETTINGS)
                             "00",  // length
                             &banned_frame));

  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(banned_frame.data()),
      banned_frame.size());
  ASSERT_TRUE(error);
  EXPECT_EQ("multiple SETTINGS frames", error.value());
}

void QuicSpdySessionTestBase::TestHttpDatagramSetting(
    HttpDatagramSupport local_support, HttpDatagramSupport remote_support,
    HttpDatagramSupport expected_support, bool expected_datagram_supported) {
  if (!version().UsesHttp3()) {
    return;
  }
  CompleteHandshake();
  session_->set_local_http_datagram_support(local_support);
  // HTTP/3 datagrams aren't supported before SETTINGS are received.
  EXPECT_FALSE(session_->SupportsH3Datagram());
  EXPECT_EQ(session_->http_datagram_support(), HttpDatagramSupport::kNone);
  // Receive SETTINGS.
  SettingsFrame settings;
  switch (remote_support) {
    case HttpDatagramSupport::kNone:
      break;
    case HttpDatagramSupport::kDraft04:
      settings.values[SETTINGS_H3_DATAGRAM_DRAFT04] = 1;
      break;
    case HttpDatagramSupport::kRfc:
      settings.values[SETTINGS_H3_DATAGRAM] = 1;
      break;
    case HttpDatagramSupport::kRfcAndDraft04:
      settings.values[SETTINGS_H3_DATAGRAM] = 1;
      settings.values[SETTINGS_H3_DATAGRAM_DRAFT04] = 1;
      break;
  }
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 3);
  QuicStreamFrame frame(stream_id, /*fin=*/false, /*offset=*/0, data);
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);
  EXPECT_CALL(debug_visitor, OnPeerControlStreamCreated(stream_id));
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(settings));
  session_->OnStreamFrame(frame);
  EXPECT_EQ(session_->http_datagram_support(), expected_support);
  EXPECT_EQ(session_->SupportsH3Datagram(), expected_datagram_supported);
}

TEST_P(QuicSpdySessionTestClient, HttpDatagramSettingLocal04Remote04) {
  Initialize();
  TestHttpDatagramSetting(
      /*local_support=*/HttpDatagramSupport::kDraft04,
      /*remote_support=*/HttpDatagramSupport::kDraft04,
      /*expected_support=*/HttpDatagramSupport::kDraft04,
      /*expected_datagram_supported=*/true);
}

TEST_P(QuicSpdySessionTestClient, HttpDatagramSettingLocal04Remote09) {
  Initialize();
  TestHttpDatagramSetting(
      /*local_support=*/HttpDatagramSupport::kDraft04,
      /*remote_support=*/HttpDatagramSupport::kRfc,
      /*expected_support=*/HttpDatagramSupport::kNone,
      /*expected_datagram_supported=*/false);
}

TEST_P(QuicSpdySessionTestClient, HttpDatagramSettingLocal04Remote04And09) {
  Initialize();
  TestHttpDatagramSetting(
      /*local_support=*/HttpDatagramSupport::kDraft04,
      /*remote_support=*/HttpDatagramSupport::kRfcAndDraft04,
      /*expected_support=*/HttpDatagramSupport::kDraft04,
      /*expected_datagram_supported=*/true);
}

TEST_P(QuicSpdySessionTestClient, HttpDatagramSettingLocal09Remote04) {
  Initialize();
  TestHttpDatagramSetting(
      /*local_support=*/HttpDatagramSupport::kRfc,
      /*remote_support=*/HttpDatagramSupport::kDraft04,
      /*expected_support=*/HttpDatagramSupport::kNone,
      /*expected_datagram_supported=*/false);
}

TEST_P(QuicSpdySessionTestClient, HttpDatagramSettingLocal09Remote09) {
  Initialize();
  TestHttpDatagramSetting(
      /*local_support=*/HttpDatagramSupport::kRfc,
      /*remote_support=*/HttpDatagramSupport::kRfc,
      /*expected_support=*/HttpDatagramSupport::kRfc,
      /*expected_datagram_supported=*/true);
}

TEST_P(QuicSpdySessionTestClient, HttpDatagramSettingLocal09Remote04And09) {
  Initialize();
  TestHttpDatagramSetting(
      /*local_support=*/HttpDatagramSupport::kRfc,
      /*remote_support=*/HttpDatagramSupport::kRfcAndDraft04,
      /*expected_support=*/HttpDatagramSupport::kRfc,
      /*expected_datagram_supported=*/true);
}

TEST_P(QuicSpdySessionTestClient, HttpDatagramSettingLocal04And09Remote04) {
  Initialize();
  TestHttpDatagramSetting(
      /*local_support=*/HttpDatagramSupport::kRfcAndDraft04,
      /*remote_support=*/HttpDatagramSupport::kDraft04,
      /*expected_support=*/HttpDatagramSupport::kDraft04,
      /*expected_datagram_supported=*/true);
}

TEST_P(QuicSpdySessionTestClient, HttpDatagramSettingLocal04And09Remote09) {
  Initialize();
  TestHttpDatagramSetting(
      /*local_support=*/HttpDatagramSupport::kRfcAndDraft04,
      /*remote_support=*/HttpDatagramSupport::kRfc,
      /*expected_support=*/HttpDatagramSupport::kRfc,
      /*expected_datagram_supported=*/true);
}

TEST_P(QuicSpdySessionTestClient,
       HttpDatagramSettingLocal04And09Remote04And09) {
  Initialize();
  TestHttpDatagramSetting(
      /*local_support=*/HttpDatagramSupport::kRfcAndDraft04,
      /*remote_support=*/HttpDatagramSupport::kRfcAndDraft04,
      /*expected_support=*/HttpDatagramSupport::kRfc,
      /*expected_datagram_supported=*/true);
}

TEST_P(QuicSpdySessionTestClient, WebTransportSettingDraft02OnlyBothSides) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_locally_supported_web_transport_versions(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft02}));

  EXPECT_FALSE(session_->SupportsWebTransport());
  CompleteHandshake();
  ReceiveWebTransportSettings(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft02}));
  EXPECT_TRUE(session_->ShouldProcessIncomingRequests());
  EXPECT_TRUE(session_->SupportsWebTransport());
  EXPECT_EQ(session_->SupportedWebTransportVersion(),
            WebTransportHttp3Version::kDraft02);
}

TEST_P(QuicSpdySessionTestClient, WebTransportSettingDraft07OnlyBothSides) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_locally_supported_web_transport_versions(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft07}));

  EXPECT_FALSE(session_->SupportsWebTransport());
  CompleteHandshake();
  ReceiveWebTransportSettings(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft07}));
  EXPECT_TRUE(session_->ShouldProcessIncomingRequests());
  EXPECT_TRUE(session_->SupportsWebTransport());
  EXPECT_EQ(session_->SupportedWebTransportVersion(),
            WebTransportHttp3Version::kDraft07);
}

TEST_P(QuicSpdySessionTestClient, WebTransportSettingBothDraftsBothSides) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_locally_supported_web_transport_versions(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft02,
                                   WebTransportHttp3Version::kDraft07}));

  EXPECT_FALSE(session_->SupportsWebTransport());
  CompleteHandshake();
  ReceiveWebTransportSettings(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft02,
                                   WebTransportHttp3Version::kDraft07}));
  EXPECT_TRUE(session_->ShouldProcessIncomingRequests());
  EXPECT_TRUE(session_->SupportsWebTransport());
  EXPECT_EQ(session_->SupportedWebTransportVersion(),
            WebTransportHttp3Version::kDraft07);
}

TEST_P(QuicSpdySessionTestClient, WebTransportSettingVersionMismatch) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_locally_supported_web_transport_versions(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft07}));

  EXPECT_FALSE(session_->SupportsWebTransport());
  CompleteHandshake();
  ReceiveWebTransportSettings(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft02}));
  EXPECT_FALSE(session_->SupportsWebTransport());
  EXPECT_EQ(session_->SupportedWebTransportVersion(), std::nullopt);
}

TEST_P(QuicSpdySessionTestClient, WebTransportSettingSetToZero) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_supports_webtransport(true);

  EXPECT_FALSE(session_->SupportsWebTransport());

  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  // Note that this does not actually fill out correct settings because the
  // settings are filled in at the construction time.
  EXPECT_CALL(debug_visitor, OnSettingsFrameSent(_));
  session_->set_debug_visitor(&debug_visitor);
  CompleteHandshake();

  SettingsFrame server_settings;
  server_settings.values[SETTINGS_H3_DATAGRAM_DRAFT04] = 1;
  server_settings.values[SETTINGS_WEBTRANS_DRAFT00] = 0;
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(server_settings);
  QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 3);
  QuicStreamFrame frame(stream_id, /*fin=*/false, /*offset=*/0, data);
  EXPECT_CALL(debug_visitor, OnPeerControlStreamCreated(stream_id));
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(server_settings));
  session_->OnStreamFrame(frame);
  EXPECT_FALSE(session_->SupportsWebTransport());
}

TEST_P(QuicSpdySessionTestServer, WebTransportSetting) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_supports_webtransport(true);

  EXPECT_FALSE(session_->SupportsWebTransport());
  EXPECT_FALSE(session_->ShouldProcessIncomingRequests());

  CompleteHandshake();

  ReceiveWebTransportSettings();
  EXPECT_TRUE(session_->SupportsWebTransport());
  EXPECT_TRUE(session_->ShouldProcessIncomingRequests());
}

TEST_P(QuicSpdySessionTestServer, BufferingIncomingStreams) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_supports_webtransport(true);

  CompleteHandshake();
  QuicStreamId session_id =
      GetNthClientInitiatedBidirectionalStreamId(transport_version(), 1);

  QuicStreamId data_stream_id =
      GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(session_id, data_stream_id);

  ReceiveWebTransportSettings();

  ReceiveWebTransportSession(session_id);
  WebTransportHttp3* web_transport =
      session_->GetWebTransportSession(session_id);
  ASSERT_TRUE(web_transport != nullptr);

  EXPECT_EQ(web_transport->NumberOfAssociatedStreams(), 1u);

  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(session_id, _));
  EXPECT_CALL(
      *connection_,
      OnStreamReset(data_stream_id, QUIC_STREAM_WEBTRANSPORT_SESSION_GONE));
  session_->ResetStream(session_id, QUIC_STREAM_INTERNAL_ERROR);
}

TEST_P(QuicSpdySessionTestServer, BufferingIncomingStreamsLimit) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_supports_webtransport(true);

  CompleteHandshake();
  QuicStreamId session_id =
      GetNthClientInitiatedBidirectionalStreamId(transport_version(), 1);

  const int streams_to_send = kMaxUnassociatedWebTransportStreams + 4;
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_,
              OnStreamReset(
                  _, QUIC_STREAM_WEBTRANSPORT_BUFFERED_STREAMS_LIMIT_EXCEEDED))
      .Times(4);
  for (int i = 0; i < streams_to_send; i++) {
    QuicStreamId data_stream_id =
        GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4 + i);
    ReceiveWebTransportUnidirectionalStream(session_id, data_stream_id);
  }

  ReceiveWebTransportSettings();

  ReceiveWebTransportSession(session_id);
  WebTransportHttp3* web_transport =
      session_->GetWebTransportSession(session_id);
  ASSERT_TRUE(web_transport != nullptr);

  EXPECT_EQ(web_transport->NumberOfAssociatedStreams(),
            kMaxUnassociatedWebTransportStreams);

  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(kMaxUnassociatedWebTransportStreams + 1);
  session_->ResetStream(session_id, QUIC_STREAM_INTERNAL_ERROR);
}

TEST_P(QuicSpdySessionTestServer, BufferingIncomingStreamsWithFin) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }

  CompleteHandshake();

  const UberQuicStreamIdManager& stream_id_manager =
      *QuicSessionPeer::ietf_streamid_manager(&*session_);
  const QuicStreamId initial_advertized_max_streams =
      stream_id_manager.advertised_max_incoming_unidirectional_streams();
  const size_t num_streams_to_open =
      session_->max_open_incoming_unidirectional_streams();
  // The max_streams limit should be increased repeatedly.
  EXPECT_CALL(*connection_, SendControlFrame(_)).Times(testing::AnyNumber());
  for (size_t i = 0; i < num_streams_to_open; i++) {
    const QuicStreamId stream_id =
        GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4 + i);
    QuicStreamFrame frame(stream_id, /*fin=*/true, /*offset=*/0, /*data=*/"");
    session_->OnStreamFrame(frame);
  }
  EXPECT_LT(initial_advertized_max_streams,
            stream_id_manager.advertised_max_incoming_unidirectional_streams());
  EXPECT_EQ(0, session_->pending_streams_size());
}

TEST_P(QuicSpdySessionTestServer, ResetOutgoingWebTransportStreams) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_supports_webtransport(true);

  CompleteHandshake();
  QuicStreamId session_id =
      GetNthClientInitiatedBidirectionalStreamId(transport_version(), 1);

  ReceiveWebTransportSettings();
  ReceiveWebTransportSession(session_id);
  WebTransportHttp3* web_transport =
      session_->GetWebTransportSession(session_id);
  ASSERT_TRUE(web_transport != nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_TRUE(web_transport->CanOpenNextOutgoingUnidirectionalStream());
  EXPECT_EQ(web_transport->NumberOfAssociatedStreams(), 0u);
  WebTransportStream* stream =
      web_transport->OpenOutgoingUnidirectionalStream();
  EXPECT_EQ(web_transport->NumberOfAssociatedStreams(), 1u);
  ASSERT_TRUE(stream != nullptr);
  QuicStreamId stream_id = stream->GetStreamId();

  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(session_id, _));
  EXPECT_CALL(*connection_,
              OnStreamReset(stream_id, QUIC_STREAM_WEBTRANSPORT_SESSION_GONE));
  session_->ResetStream(session_id, QUIC_STREAM_INTERNAL_ERROR);
  EXPECT_EQ(web_transport->NumberOfAssociatedStreams(), 0u);
}

TEST_P(QuicSpdySessionTestClient, WebTransportWithoutExtendedConnect) {
  Initialize();
  if (!version().UsesHttp3()) {
    return;
  }
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  session_->set_local_http_datagram_support(
      HttpDatagramSupport::kRfcAndDraft04);
  session_->set_supports_webtransport(true);

  EXPECT_FALSE(session_->SupportsWebTransport());
  CompleteHandshake();

  SettingsFrame settings;
  settings.values[SETTINGS_H3_DATAGRAM_DRAFT04] = 1;
  settings.values[SETTINGS_WEBTRANS_DRAFT00] = 1;
  // No SETTINGS_ENABLE_CONNECT_PROTOCOL here.
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId control_stream_id =
      session_->perspective() == Perspective::IS_SERVER
```
Response:
The user is asking for a summary of the functionality of the C++ code snippet provided, which is part of a larger unit test file for the Chromium network stack's SPDY session implementation. I need to identify the test cases within this snippet and infer what aspects of the `SpdySession` they are designed to verify. I should also look for potential connections to JavaScript, logical deductions, common user errors, and how a user's actions might lead to this code being executed.

**Functionality Breakdown:**

1. **Flow Control and Stalled Sends:** The first few tests (`StallSessionSend`, `ResumeSessionSend`, `ResumeSessionWithStalledStream`) focus on how the `SpdySession` handles send operations when flow control mechanisms are in place. They simulate scenarios where the session or individual streams are stalled due to flow control limits and then resumed.

2. **Broken Connection Detection:** Tests like `BrokenConnectionDetectionEOF`, `BrokenConnectionDetectionCloseSession`, `BrokenConnectionDetectionCloseStream`, `BrokenConnectionDetectionCancelStream`, and `BrokenConnectionDetectionMultipleRequests` examine the logic for detecting broken connections. They check if the session correctly identifies connection issues based on events like EOF or stream closure and how multiple streams requesting this detection interact.

3. **Handling Deleted Streams during Unstall:** The `SendWindowSizeIncreaseWithDeletedStreams` test verifies that the `SpdySession` can correctly manage the scenario where streams are closed or deleted while the session's send window is being increased after a stall.

4. **Handling Deleted Session during Unstall:**  Similar to the above, `SendWindowSizeIncreaseWithDeletedSession` checks the behavior when the session itself is closed while streams are stalled and the send window is being adjusted.

5. **GOAWAY on Flow Control Error:** The `GoAwayOnSessionFlowControlError` test checks if the session correctly sends a GOAWAY frame when a flow control error occurs at the session level (e.g., exceeding the receive window).

6. **Handling Invalid Unknown Frames:** `RejectInvalidUnknownFrames` verifies that the session correctly rejects unknown SPDY frames, particularly those with invalid stream IDs (e.g., exceeding the high watermark or belonging to push streams).

7. **WebSocket Support:** The tests related to WebSocket (`EnableWebSocket`, `DisableWebSocketDoesNothing`, `EnableWebSocketThenDisableIsProtocolError`) investigate how the `SpdySession` handles the `SETTINGS_ENABLE_CONNECT_PROTOCOL` setting, which is used to indicate support for the CONNECT method (used for WebSockets).

8. **Greasing Frame Types:**  `GreaseFrameTypeAfterSettings` explores the behavior when a "grease" frame (a frame with a reserved or unused type, intended for testing robustness) is received after the initial SETTINGS frame.

**JavaScript Relationship:**

SPDY is a transport protocol that underlies HTTP/2. Web browsers use SPDY/HTTP/2 to communicate with web servers. JavaScript running in a browser initiates requests that ultimately utilize the browser's networking stack, which includes the SPDY session implementation being tested here.

**Logical Deductions (Hypothetical Inputs/Outputs):**

*   **Input:**  A server sends a `WINDOW_UPDATE` frame increasing the session's flow control window.
    *   **Output:**  The `SpdySession` should allow previously stalled streams to resume sending data.

*   **Input:** A TCP connection abruptly closes without a proper shutdown sequence.
    *   **Output:** The `SpdySession`'s broken connection detection mechanism should trigger and potentially close any active streams.

**Common User/Programming Errors:**

*   **Not Handling `ERR_IO_PENDING` Correctly:**  Developers working with asynchronous network operations might not correctly handle the `ERR_IO_PENDING` error, which signals that an operation is in progress and will complete later. The tests involving `SendRequestHeaders` demonstrate the expected behavior with `ERR_IO_PENDING`.

*   **Incorrectly Managing Stream Lifecycles:**  Prematurely closing or deleting streams without proper synchronization could lead to issues. The tests involving closing streams during unstall scenarios highlight the session's ability to handle these situations.

**User Operation and Debugging:**

1. **User Navigates to a Website:** A user enters a URL in their browser or clicks a link.
2. **Browser Initiates Request:** The browser resolves the domain name and establishes a connection to the server.
3. **SPDY/HTTP/2 Negotiation:**  If the server supports SPDY or HTTP/2, the browser and server negotiate the protocol.
4. **SPDY Session Creation:** A `SpdySession` object is created to manage the connection.
5. **Data Transfer:** The browser sends requests and receives responses over the SPDY session.
6. **Flow Control Events:**  If the server is sending a large amount of data, the browser's flow control mechanisms might limit the rate of data reception. This could trigger the flow control logic tested in the initial tests.
7. **Connection Errors:** If the network connection becomes unstable or is interrupted, the broken connection detection logic might be invoked.

**Debugging Scenario:** If a user reports that a website is slow to load or that requests are failing intermittently, developers might investigate the SPDY session behavior. They might use network debugging tools to capture SPDY frames and analyze flow control, error conditions, or unexpected disconnections. The unit tests here help ensure the robustness of the `SpdySession` implementation in such scenarios.
这是第 6 部分，名为 `SpdySessionTest` 的单元测试文件的一部分，它主要关注 `SpdySession` 类的各种功能和边缘情况的处理。从提供的代码片段来看，这部分主要测试了以下功能：

**1. 流控（Flow Control）机制下的发送阻塞和恢复：**

*   测试了当会话（Session）级别的流控阻止了数据发送时，如何正确地阻塞和恢复不同的流（Stream）的发送。
*   验证了先阻塞会话发送，然后再阻塞单个流发送，最后先恢复会话发送，再恢复单个流发送的场景，确保流不会因此失败。
*   涉及到 `StallSessionSend()`, `UnstallSessionSend()`, `StallStreamSend()` 这些辅助函数，模拟流控阻塞和恢复。

**2. 断开连接检测（Broken Connection Detection）：**

*   测试了当连接意外断开（例如收到 EOF）时，`SpdySession` 是否能够正确检测到，并通知相关的流。
*   测试了在启用断开连接检测的情况下，当会话或流被关闭或取消时，是否会禁用断开连接检测。
*   验证了当多个流请求断开连接检测时，只有最后一个完成的流才会禁用连接状态检查。
*   涉及到 `IsBrokenConnectionDetectionEnabled()` 方法以及在 `StreamDelegate` 的 `OnClose` 方法中进行断言。

**3. 处理已删除的流和会话：**

*   测试了当会话因为流控而被阻塞，然后在恢复发送窗口大小时，如果某些流已经被删除，会话是否能够正确处理。
*   测试了类似的场景，但这次是当会话本身在恢复发送窗口大小时被删除。
*   验证了在这些情况下，程序不会崩溃，并且能正确地清理资源。

**4. 会话级别的流控错误处理：**

*   测试了当会话级别的接收窗口溢出时，`SpdySession` 是否会发送 `GOAWAY` 帧来关闭连接。
*   模拟了接收到超过会话接收窗口大小的数据的情况。

**5. 拒绝无效的未知帧：**

*   测试了 `SpdySession` 是否会拒绝接收无效的或未知的 SPDY 帧。
*   特别关注了流 ID 不合法的情况，例如客户端发起的流 ID 为偶数（应该为奇数），或者流 ID 超出上限。

**6. WebSocket 支持的启用和禁用：**

*   测试了通过接收 `SETTINGS` 帧并设置 `SETTINGS_ENABLE_CONNECT_PROTOCOL` 参数为 1 来启用 WebSocket 支持。
*   验证了尝试禁用 WebSocket 支持（设置 `SETTINGS_ENABLE_CONNECT_PROTOCOL` 为 0）不会有任何影响。
*   测试了如果先启用 WebSocket 支持，然后又收到禁用 WebSocket 支持的 `SETTINGS` 帧，`SpdySession` 会发送 `GOAWAY` 帧并关闭连接，因为这是一个协议错误。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不包含 JavaScript 代码，但它测试的网络协议 SPDY（以及其后续的 HTTP/2）是现代 Web 浏览器与服务器通信的基础。JavaScript 代码在浏览器中发起的网络请求最终会通过浏览器的网络栈，而 `SpdySession` 就是网络栈中处理 SPDY/HTTP/2 连接的关键部分。

**举例说明：**

假设一个网页上的 JavaScript 代码通过 `fetch` API 发起了一个 POST 请求，请求头中包含了大量的数据。如果服务器的响应速度较慢，或者网络状况不佳，导致客户端的 `SpdySession` 的接收窗口即将被填满，此时服务器发送了一个更大的数据帧。`GoAwayOnSessionFlowControlError` 这个测试就模拟了这种情况，确保 `SpdySession` 能正确地发送 `GOAWAY` 帧来避免进一步的错误。

**逻辑推理 (假设输入与输出):**

*   **假设输入:** 服务器发送一个类型未知的 SPDY 帧，其流 ID 为一个偶数（例如 2）。
*   **预期输出:** `RejectInvalidUnknownFrames` 测试会验证 `OnUnknownFrame(2, 0)` 返回 `false`，表示该帧被拒绝，因为客户端发起的流 ID 必须是奇数。

**用户或编程常见的使用错误：**

*   **未处理 `ERR_IO_PENDING`：** 在异步网络编程中，如果 `SendRequestHeaders` 返回 `ERR_IO_PENDING`，表示操作正在进行中，需要等待完成。如果开发者没有正确处理这种情况，可能会导致数据发送不完整或者出现其他错误。本例中，多次使用了 `EXPECT_EQ(ERR_IO_PENDING, ...)` 来验证异步操作的正确性。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户浏览网页：** 用户在浏览器地址栏输入网址或点击链接。
2. **浏览器建立连接：** 浏览器解析域名，并尝试与服务器建立连接，如果服务器支持 HTTP/2 或 SPDY，则会使用这些协议。
3. **建立 `SpdySession`：**  一旦连接建立，`SpdySession` 对象会被创建来管理这个连接。
4. **发送请求：** 用户在网页上的操作（例如提交表单、点击按钮）可能触发 JavaScript 代码发起 HTTP 请求。
5. **流控发生：** 如果用户上传大量数据，或者网络拥塞，客户端可能会因为流控机制而暂停发送数据。`StallSessionSend` 和相关的测试模拟了这种情况。
6. **连接问题：**  如果网络不稳定，连接可能会中断。`BrokenConnectionDetectionEOF` 等测试模拟了这类情况。
7. **接收到未知帧：**  虽然不常见，但如果服务器端实现有 bug，可能会发送一些格式不正确的 SPDY 帧。`RejectInvalidUnknownFrames` 测试了客户端如何处理这种情况。
8. **WebSocket 连接：** 如果网页尝试建立 WebSocket 连接，浏览器会发送一个特殊的 HTTP 请求，并在底层使用 SPDY 的 CONNECT 方法。与 WebSocket 相关的测试验证了 `SpdySession` 对此的支持。

作为调试线索，如果用户报告某些网站连接不稳定，或者上传大文件时出现问题，开发者可能会关注 `SpdySession` 相关的代码，检查流控、连接管理以及错误处理的逻辑是否正确。这些单元测试就是用来确保这些关键部分的健壮性。

**功能归纳：**

总的来说，这部分 `SpdySessionTest` 单元测试文件的功能是验证 `SpdySession` 类在各种复杂和异常情况下的行为，包括流控、断开连接检测、处理已删除的流和会话、会话级别的错误处理、对无效帧的拒绝以及对 WebSocket 连接的支持。这些测试旨在确保 `SpdySession` 的稳定性和可靠性，使其能够正确处理各种网络事件和协议交互。

### 提示词
```
这是目录为net/spdy/spdy_session_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
erializedFrame req2(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 3, kBodyDataSize, MEDIUM, nullptr, 0));
  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataStringPiece, true));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(3, kBodyDataStringPiece, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
      CreateMockWrite(body2, 2), CreateMockWrite(body1, 3),
  };

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  MockRead reads[] = {
      CreateMockRead(resp1, 4), CreateMockRead(resp2, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream1);

  test::StreamDelegateWithBody delegate1(stream1, kBodyDataStringPiece);
  stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(stream2);

  test::StreamDelegateWithBody delegate2(stream2, kBodyDataStringPiece);
  stream2->SetDelegate(&delegate2);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  StallSessionSend();

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream1->SendRequestHeaders(std::move(headers1),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream1->url().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, stream1->stream_id());
  EXPECT_TRUE(stream1->send_stalled_by_flow_control());

  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream2->SendRequestHeaders(std::move(headers2),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream2->url().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3u, stream2->stream_id());
  EXPECT_TRUE(stream2->send_stalled_by_flow_control());

  // This should unstall only stream2.
  UnstallSessionSend(kBodyDataSize);

  EXPECT_TRUE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  // This should then unstall stream1.
  UnstallSessionSend(kBodyDataSize);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate1.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  EXPECT_THAT(delegate2.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate1.send_headers_completed());
  EXPECT_EQ("200", delegate1.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate1.TakeReceivedData());

  EXPECT_TRUE(delegate2.send_headers_completed());
  EXPECT_EQ("200", delegate2.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate2.TakeReceivedData());

  EXPECT_FALSE(session_);
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// An upload stream is stalled when the session gets unstalled, then the session
// is stalled again when the stream gets unstalled.  The stream should not fail.
// Regression test for https://crbug.com/761919.
TEST_F(SpdySessionTest, ResumeSessionWithStalledStream) {
  spdy::SpdySerializedFrame req1(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame req2(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 3, kBodyDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(3, kBodyDataStringPiece, true));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataStringPiece, true));
  MockWrite writes[] = {CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
                        CreateMockWrite(body1, 2), CreateMockWrite(body2, 3)};

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  MockRead reads[] = {CreateMockRead(resp1, 4), CreateMockRead(resp2, 5),
                      MockRead(ASYNC, 0, 6)};

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream1);

  test::StreamDelegateWithBody delegate1(stream1, kBodyDataStringPiece);
  stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream2);

  test::StreamDelegateWithBody delegate2(stream2, kBodyDataStringPiece);
  stream2->SetDelegate(&delegate2);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  StallSessionSend();

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream1->SendRequestHeaders(std::move(headers1),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream1->url().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, stream1->stream_id());
  EXPECT_TRUE(stream1->send_stalled_by_flow_control());

  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream2->SendRequestHeaders(std::move(headers2),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream2->url().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3u, stream2->stream_id());
  EXPECT_TRUE(stream2->send_stalled_by_flow_control());

  StallStreamSend(stream1.get());

  // At this point, both |session| and |stream1| are stalled
  // by their respective flow control mechanisms.  Now unstall the session.
  // This calls session->ResumeSendStalledStreams(), which calls
  // stream1->PossiblyResumeIfSendStalled().  However, |stream1| is stalled, so
  // no data are sent on that stream.  At this point, |stream1| should not be
  // removed from session_->stream_send_unstall_queue_.
  // Then stream2->PossiblyResumeIfSendStalled() is called,
  // data are sent on |stream2|, and |session_| stalls again.
  UnstallSessionSend(kBodyDataSize);

  EXPECT_TRUE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  // Make sure that the session is stalled.  Otherwise
  // stream1->PossiblyResumeIfSendStalled() would resume the stream as soon as
  // the stream is unstalled, hiding the bug.
  EXPECT_TRUE(session_->IsSendStalled());
  UnstallStreamSend(stream1.get(), kBodyDataSize);

  // Finally, unstall session.
  UnstallSessionSend(kBodyDataSize);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate1.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  EXPECT_THAT(delegate2.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate1.send_headers_completed());
  EXPECT_EQ("200", delegate1.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate1.TakeReceivedData());

  EXPECT_TRUE(delegate2.send_headers_completed());
  EXPECT_EQ("200", delegate2.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate2.TakeReceivedData());

  EXPECT_FALSE(session_);
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

class StreamBrokenConnectionDetectionCheckDelegate
    : public test::StreamDelegateDoNothing {
 public:
  StreamBrokenConnectionDetectionCheckDelegate(
      const base::WeakPtr<SpdyStream>& stream,
      const base::WeakPtr<SpdySession>& session,
      bool expected_is_broken_connection_detection_enabled)
      : StreamDelegateDoNothing(stream),
        session_(session),
        expected_is_broken_connection_detection_enabled_(
            expected_is_broken_connection_detection_enabled) {}

  ~StreamBrokenConnectionDetectionCheckDelegate() override = default;

  void OnClose(int status) override {
    ASSERT_EQ(expected_is_broken_connection_detection_enabled_,
              session_->IsBrokenConnectionDetectionEnabled());
  }

 private:
  const base::WeakPtr<SpdySession> session_;
  bool expected_is_broken_connection_detection_enabled_;
};

TEST_F(SpdySessionTest, BrokenConnectionDetectionEOF) {
  MockRead reads[] = {
      MockRead(ASYNC, 0, 0),  // EOF
  };

  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  ASSERT_FALSE(session_->IsBrokenConnectionDetectionEnabled());
  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_, MEDIUM,
      NetLogWithSource(), true, kHeartbeatInterval);
  ASSERT_TRUE(stream);
  ASSERT_TRUE(session_->IsBrokenConnectionDetectionEnabled());
  StreamBrokenConnectionDetectionCheckDelegate delegate(stream, session_,
                                                        false);
  stream->SetDelegate(&delegate);

  // Let the delegate run and check broken connection detection status during
  // OnClose().
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(session_);
}

TEST_F(SpdySessionTest, BrokenConnectionDetectionCloseSession) {
  MockRead reads[] = {
      MockRead(ASYNC, 0, 0),  // EOF
  };

  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  ASSERT_FALSE(session_->IsBrokenConnectionDetectionEnabled());
  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_, MEDIUM,
      NetLogWithSource(), true, kHeartbeatInterval);
  ASSERT_TRUE(stream);
  ASSERT_TRUE(session_->IsBrokenConnectionDetectionEnabled());
  StreamBrokenConnectionDetectionCheckDelegate delegate(stream, session_,
                                                        false);
  stream->SetDelegate(&delegate);

  session_->CloseSessionOnError(ERR_ABORTED, "Aborting session");
  ASSERT_FALSE(session_->IsBrokenConnectionDetectionEnabled());

  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(session_);
}

TEST_F(SpdySessionTest, BrokenConnectionDetectionCloseStream) {
  MockRead reads[] = {
      MockRead(ASYNC, 0, 0),  // EOF
  };

  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  ASSERT_FALSE(session_->IsBrokenConnectionDetectionEnabled());
  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_, MEDIUM,
      NetLogWithSource(), true, kHeartbeatInterval);
  ASSERT_TRUE(stream);
  ASSERT_TRUE(session_->IsBrokenConnectionDetectionEnabled());
  StreamBrokenConnectionDetectionCheckDelegate delegate(stream, session_,
                                                        false);
  stream->SetDelegate(&delegate);

  stream->Close();
  ASSERT_FALSE(session_->IsBrokenConnectionDetectionEnabled());

  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(session_);
}

TEST_F(SpdySessionTest, BrokenConnectionDetectionCancelStream) {
  MockRead reads[] = {
      MockRead(ASYNC, 0, 0),
  };

  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  ASSERT_FALSE(session_->IsBrokenConnectionDetectionEnabled());
  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_, MEDIUM,
      NetLogWithSource(), true, kHeartbeatInterval);
  ASSERT_TRUE(stream);
  ASSERT_TRUE(session_->IsBrokenConnectionDetectionEnabled());
  StreamBrokenConnectionDetectionCheckDelegate delegate(stream, session_,
                                                        false);
  stream->SetDelegate(&delegate);

  stream->Cancel(ERR_ABORTED);
  ASSERT_FALSE(session_->IsBrokenConnectionDetectionEnabled());

  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(session_);
}

// When multiple streams request broken connection detection, only the last one
// to complete should disable the connection status check.
TEST_F(SpdySessionTest, BrokenConnectionDetectionMultipleRequests) {
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), CreateMockRead(goaway, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), MockRead(ASYNC, 0, 5)  // EOF
  };
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req2, 1),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_FALSE(session_->IsBrokenConnectionDetectionEnabled());
  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_, MEDIUM,
      NetLogWithSource(), true, kHeartbeatInterval);
  EXPECT_TRUE(spdy_stream1);
  EXPECT_TRUE(session_->IsBrokenConnectionDetectionEnabled());
  StreamBrokenConnectionDetectionCheckDelegate delegate1(spdy_stream1, session_,
                                                         false);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_, MEDIUM,
      NetLogWithSource(), true, kHeartbeatInterval);
  EXPECT_TRUE(spdy_stream2);
  EXPECT_TRUE(session_->IsBrokenConnectionDetectionEnabled());
  StreamBrokenConnectionDetectionCheckDelegate delegate2(spdy_stream2, session_,
                                                         true);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  quiche::HttpHeaderBlock headers2(headers.Clone());

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(session_->IsBrokenConnectionDetectionEnabled());
  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  // Read and process the GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(session_->IsBrokenConnectionDetectionEnabled());
  EXPECT_FALSE(session_->IsStreamActive(3));
  EXPECT_FALSE(spdy_stream2);
  EXPECT_TRUE(session_->IsStreamActive(1));
  EXPECT_TRUE(session_->IsGoingAway());

  // Should close the session.
  spdy_stream1->Close();
  EXPECT_FALSE(spdy_stream1);

  EXPECT_TRUE(session_);
  EXPECT_FALSE(session_->IsBrokenConnectionDetectionEnabled());
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Delegate that closes a given stream after sending its body.
class StreamClosingDelegate : public test::StreamDelegateWithBody {
 public:
  StreamClosingDelegate(const base::WeakPtr<SpdyStream>& stream,
                        std::string_view data)
      : StreamDelegateWithBody(stream, data) {}

  ~StreamClosingDelegate() override = default;

  void set_stream_to_close(const base::WeakPtr<SpdyStream>& stream_to_close) {
    stream_to_close_ = stream_to_close;
  }

  void OnDataSent() override {
    test::StreamDelegateWithBody::OnDataSent();
    if (stream_to_close_.get()) {
      stream_to_close_->Close();
      EXPECT_FALSE(stream_to_close_);
    }
  }

 private:
  base::WeakPtr<SpdyStream> stream_to_close_;
};

// Cause a stall by reducing the flow control send window to
// 0. Unstalling the session should properly handle deleted streams.
TEST_F(SpdySessionTest, SendWindowSizeIncreaseWithDeletedStreams) {
  spdy::SpdySerializedFrame req1(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame req2(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 3, kBodyDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame req3(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 5, kBodyDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(3, kBodyDataStringPiece, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
      CreateMockWrite(req3, 2), CreateMockWrite(body2, 3),
  };

  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  MockRead reads[] = {
      CreateMockRead(resp2, 4), MockRead(ASYNC, ERR_IO_PENDING, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream1);

  test::StreamDelegateWithBody delegate1(stream1, kBodyDataStringPiece);
  stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream2);

  StreamClosingDelegate delegate2(stream2, kBodyDataStringPiece);
  stream2->SetDelegate(&delegate2);

  base::WeakPtr<SpdyStream> stream3 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream3);

  test::StreamDelegateWithBody delegate3(stream3, kBodyDataStringPiece);
  stream3->SetDelegate(&delegate3);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());
  EXPECT_FALSE(stream3->send_stalled_by_flow_control());

  StallSessionSend();

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream1->SendRequestHeaders(std::move(headers1),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream1->url().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, stream1->stream_id());
  EXPECT_TRUE(stream1->send_stalled_by_flow_control());

  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream2->SendRequestHeaders(std::move(headers2),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream2->url().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3u, stream2->stream_id());
  EXPECT_TRUE(stream2->send_stalled_by_flow_control());

  quiche::HttpHeaderBlock headers3(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream3->SendRequestHeaders(std::move(headers3),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream3->url().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(5u, stream3->stream_id());
  EXPECT_TRUE(stream3->send_stalled_by_flow_control());

  spdy::SpdyStreamId stream_id1 = stream1->stream_id();
  spdy::SpdyStreamId stream_id2 = stream2->stream_id();
  spdy::SpdyStreamId stream_id3 = stream3->stream_id();

  // Close stream1 preemptively.
  session_->CloseActiveStream(stream_id1, ERR_CONNECTION_CLOSED);
  EXPECT_FALSE(stream1);

  EXPECT_FALSE(session_->IsStreamActive(stream_id1));
  EXPECT_TRUE(session_->IsStreamActive(stream_id2));
  EXPECT_TRUE(session_->IsStreamActive(stream_id3));

  // Unstall stream2, which should then close stream3.
  delegate2.set_stream_to_close(stream3);
  UnstallSessionSend(kBodyDataSize);

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(stream3);

  EXPECT_FALSE(stream2->send_stalled_by_flow_control());
  EXPECT_FALSE(session_->IsStreamActive(stream_id1));
  EXPECT_TRUE(session_->IsStreamActive(stream_id2));
  EXPECT_FALSE(session_->IsStreamActive(stream_id3));

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(stream2);
  EXPECT_FALSE(session_);

  EXPECT_THAT(delegate1.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  EXPECT_THAT(delegate2.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  EXPECT_THAT(delegate3.WaitForClose(), IsOk());

  EXPECT_TRUE(delegate1.send_headers_completed());
  EXPECT_EQ(std::string(), delegate1.TakeReceivedData());

  EXPECT_TRUE(delegate2.send_headers_completed());
  EXPECT_EQ("200", delegate2.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate2.TakeReceivedData());

  EXPECT_TRUE(delegate3.send_headers_completed());
  EXPECT_EQ(std::string(), delegate3.TakeReceivedData());

  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Cause a stall by reducing the flow control send window to
// 0. Unstalling the session should properly handle the session itself
// being closed.
TEST_F(SpdySessionTest, SendWindowSizeIncreaseWithDeletedSession) {
  spdy::SpdySerializedFrame req1(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame req2(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 3, kBodyDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataStringPiece, false));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream1);

  test::StreamDelegateWithBody delegate1(stream1, kBodyDataStringPiece);
  stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream2);

  test::StreamDelegateWithBody delegate2(stream2, kBodyDataStringPiece);
  stream2->SetDelegate(&delegate2);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  StallSessionSend();

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream1->SendRequestHeaders(std::move(headers1),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream1->url().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, stream1->stream_id());
  EXPECT_TRUE(stream1->send_stalled_by_flow_control());

  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream2->SendRequestHeaders(std::move(headers2),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream2->url().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3u, stream2->stream_id());
  EXPECT_TRUE(stream2->send_stalled_by_flow_control());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Unstall stream1.
  UnstallSessionSend(kBodyDataSize);

  // Close the session (since we can't do it from within the delegate
  // method, since it's in the stream's loop).
  session_->CloseSessionOnError(ERR_CONNECTION_CLOSED, "Closing session");
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_THAT(delegate1.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  EXPECT_THAT(delegate2.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate1.send_headers_completed());
  EXPECT_EQ(std::string(), delegate1.TakeReceivedData());

  EXPECT_TRUE(delegate2.send_headers_completed());
  EXPECT_EQ(std::string(), delegate2.TakeReceivedData());

  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdySessionTest, GoAwayOnSessionFlowControlError) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_FLOW_CONTROL_ERROR,
      "delta_window_size is 6 in DecreaseRecvWindowSize, which is larger than "
      "the receive window size of 1"));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(goaway, 4),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(resp, 2),
      CreateMockRead(body, 3),
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream);
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Write request.
  base::RunLoop().RunUntilIdle();

  // Put session on the edge of overflowing it's recv window.
  set_session_recv_window_size(1);

  // Read response headers & body. Body overflows the session window, and a
  // goaway is written.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_FLOW_CONTROL_ERROR));
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, RejectInvalidUnknownFrames) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  set_stream_hi_water_mark(5);
  // Low client (odd) ids are fine.
  EXPECT_TRUE(OnUnknownFrame(3, 0));
  // Client id exceeding watermark.
  EXPECT_FALSE(OnUnknownFrame(9, 0));

  // Frames on push streams are rejected.
  EXPECT_FALSE(OnUnknownFrame(2, 0));
}

TEST_F(SpdySessionTest, EnableWebSocket) {
  spdy::SettingsMap settings_map;
  settings_map[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  spdy::SpdySerializedFrame settings(
      spdy_util_.ConstructSpdySettings(settings_map));
  MockRead reads[] = {CreateMockRead(settings, 0),
                      MockRead(ASYNC, ERR_IO_PENDING, 2),
                      MockRead(ASYNC, 0, 3)};

  spdy::SpdySerializedFrame ack(spdy_util_.ConstructSpdySettingsAck());
  MockWrite writes[] = {CreateMockWrite(ack, 1)};

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_FALSE(session_->support_websocket());

  // Read SETTINGS frame.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(session_->support_websocket());

  // Read EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, DisableWebSocketDoesNothing) {
  spdy::SettingsMap settings_map;
  settings_map[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 0;
  spdy::SpdySerializedFrame settings(
      spdy_util_.ConstructSpdySettings(settings_map));
  MockRead reads[] = {CreateMockRead(settings, 0),
                      MockRead(ASYNC, ERR_IO_PENDING, 2),
                      MockRead(ASYNC, 0, 3)};

  spdy::SpdySerializedFrame ack(spdy_util_.ConstructSpdySettingsAck());
  MockWrite writes[] = {CreateMockWrite(ack, 1)};

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_FALSE(session_->support_websocket());

  // Read SETTINGS frame.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(session_->support_websocket());

  // Read EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, EnableWebSocketThenDisableIsProtocolError) {
  spdy::SettingsMap settings_map1;
  settings_map1[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  spdy::SpdySerializedFrame settings1(
      spdy_util_.ConstructSpdySettings(settings_map1));
  spdy::SettingsMap settings_map2;
  settings_map2[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 0;
  spdy::SpdySerializedFrame settings2(
      spdy_util_.ConstructSpdySettings(settings_map2));
  MockRead reads[] = {CreateMockRead(settings1, 0),
                      MockRead(ASYNC, ERR_IO_PENDING, 2),
                      CreateMockRead(settings2, 3)};

  spdy::SpdySerializedFrame ack1(spdy_util_.ConstructSpdySettingsAck());
  spdy::SpdySerializedFrame ack2(spdy_util_.ConstructSpdySettingsAck());
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_PROTOCOL_ERROR,
      "Invalid value for spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL."));
  MockWrite writes[] = {CreateMockWrite(ack1, 1), CreateMockWrite(ack2, 4),
                        CreateMockWrite(goaway, 5)};

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_FALSE(session_->support_websocket());

  // Read first SETTINGS frame.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(session_->support_websocket());

  // Read second SETTINGS frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, GreaseFrameTypeAfterSettings) {
  const uint8_t type = 0x0b;
  const uint8_t flags = 0xcc;
  const std::string payload("foo");
  session_deps_.greased_http2_frame =
      std::optional<net::SpdySessionPool::GreasedHttp2Frame>(
          {type, flags, payload});

  // Connection preface.
  spdy::SpdySerializedFrame preface(spdy::test::MakeSerializedFrame(
      const_cast<char*>(spdy::kHttp2ConnectionHeaderPrefix),
      spdy::kHttp2ConnectionHeaderPrefixSize));

  // Initial SETTINGS frame.
  spdy::SettingsMap expected_settings;
  expected_settings[spdy::SETTINGS_HEADER_TABLE_SIZE] = kSpdyMaxHeaderTableSize;
  expected_settings[spdy::SETTINGS_MAX_HEADER_LIST_SIZE] =
      kSpdyMaxHeaderLi
```
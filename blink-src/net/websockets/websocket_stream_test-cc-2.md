Response:
The user wants to understand the functionality of the provided C++ code snippet from `websocket_stream_test.cc`. I need to:

1. **Summarize the functionality:** This file contains unit tests for WebSocket stream creation in Chromium's network stack.
2. **Identify relationships with JavaScript:** WebSocket functionality in the browser's JavaScript API relies on the underlying network stack, which this code tests.
3. **Provide examples with assumptions:** Illustrate test cases with hypothetical inputs and expected outputs.
4. **Highlight common user/programming errors:** Show potential pitfalls related to WebSocket usage.
5. **Explain how a user reaches this code:** Describe the steps a user takes that lead to the execution of this code (as a debugging context).
6. **Summarize the functionality (again):**  Concisely restate the file's purpose.
这是 `net/websockets/websocket_stream_test.cc` 文件的第三部分，该文件是 Chromium 网络栈中用于测试 WebSocket 流功能的单元测试代码。

**归纳一下它的功能:**

这部分代码主要包含针对 WebSocket 流创建和连接过程中的各种异常情况和特定场景的测试用例。它验证了在这些情况下 WebSocket 流的行为是否符合预期，例如：

* **认证 (Authentication):** 测试在 URL 中包含用户名和密码进行摘要式身份验证的情况。
* **连接未完成 (Incomplete Connection):** 测试在握手过程中连接未完成的情况，并验证是否正确记录了相应的统计信息。
* **HTTP/2 流重置 (HTTP/2 Stream Reset):** 测试当底层的 HTTP/2 流被重置时，WebSocket 连接的处理情况。
* **连接关闭错误 (ERR_CONNECTION_CLOSED):** 测试在接收到部分握手响应后连接关闭的情况。
* **隧道连接失败 (ERR_TUNNEL_CONNECTION_FAILED):** 测试在使用代理时建立隧道连接失败的情况。
* **取消和继续 SSL 请求 (Cancel/Continue SSL Request):** 测试在 SSL 握手过程中删除 WebSocket 请求后取消或继续 SSL 请求的情况。
* **在第一个数据段中处理连接关闭 (Handle Connection Close in First Segment):** 测试在收到握手响应后立即收到关闭帧的情况。

**与 JavaScript 的功能关系及举例说明:**

这段 C++ 代码测试的是浏览器底层网络栈的 WebSocket 实现。当 JavaScript 代码中使用 `WebSocket` API 建立 WebSocket 连接时，最终会调用到 Chromium 网络栈的这部分代码。

**举例说明:**

假设 JavaScript 代码尝试连接到一个需要摘要式身份验证的 WebSocket 服务器，并在 URL 中包含了用户名和密码：

```javascript
const websocket = new WebSocket("ws://FooBar:pass@www.example.org/");

websocket.onopen = function(event) {
  console.log("WebSocket connection opened!");
};

websocket.onmessage = function(event) {
  console.log("Message received:", event.data);
};

websocket.onerror = function(error) {
  console.error("WebSocket error:", error);
};

websocket.onclose = function(event) {
  console.log("WebSocket connection closed.");
};
```

当这段 JavaScript 代码运行时，浏览器会构造一个 WebSocket 连接请求。对于摘要式身份验证的情况，网络栈的 `WebSocketStreamCreateDigestAuthTest` 测试用例（例如 `DigestPasswordInUrl`）就是用来验证底层网络代码是否能正确处理 URL 中包含的用户名和密码，并完成握手。

**逻辑推理、假设输入与输出:**

**测试用例:** `TEST_P(WebSocketStreamCreateDigestAuthTest, DigestPasswordInUrl)`

* **假设输入:**
    * WebSocket URL: `ws://FooBar:pass@www.example.org/`
    * 服务器返回未授权响应 (401 Unauthorized)。
    * 客户端使用 URL 中的用户名和密码生成正确的摘要式认证请求。
    * 服务器返回成功的 WebSocket 升级响应 (101 Switching Protocols)。
* **预期输出:**
    * WebSocket 连接成功建立 (`EXPECT_FALSE(has_failed())`)。
    * 存在有效的 WebSocket 流 (`EXPECT_TRUE(stream_)`)。
    * 接收到成功的升级响应 (`EXPECT_EQ(101, response_info_->headers->response_code())`)。

**测试用例:** `TEST_P(WebSocketMultiProtocolStreamCreateTest, Incomplete)`

* **假设输入 (Basic Handshake Stream):**
    * WebSocket URL: `wss://www.example.org/`
    * 服务器在发送完整握手响应前保持连接挂起 (`MockRead(ASYNC, ERR_IO_PENDING, 0)`)。
* **预期输出 (Basic Handshake Stream):**
    * 连接未完成 (`stream_request_.reset()`)。
    * 记录了 `Net.WebSocket.HandshakeResult2` 的直方图信息，表明握手未完成 (`EXPECT_EQ(1, samples->GetCount(static_cast<int>(WebSocketHandshakeStreamBase::HandshakeResult::INCOMPLETE))))`)。

**涉及用户或编程常见的使用错误及举例说明:**

* **不正确的认证信息:** 用户在 JavaScript 中建立 WebSocket 连接时，如果提供的用户名或密码不正确，服务器可能会返回 401 未授权响应，导致连接失败。`WebSocketStreamCreateDigestAuthTest` 测试确保了即使认证信息包含在 URL 中，也能正确处理。
* **网络问题导致连接中断:** 在 WebSocket 握手过程中，如果网络连接出现问题（例如连接超时、连接被重置），可能会导致连接无法完成。`WebSocketMultiProtocolStreamCreateTest` 的 `Incomplete` 测试就模拟了这种情况。
* **代理配置错误:**  如果用户在使用代理服务器，但代理配置不正确，可能会导致 WebSocket 连接建立隧道失败。`WebSocketStreamCreateTest` 的 `HandleErrTunnelConnectionFailed` 测试覆盖了这种情况。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入或点击一个包含 `ws://` 或 `wss://` 协议的链接。** 或者，网页上的 JavaScript 代码尝试创建一个新的 `WebSocket` 对象。
2. **浏览器解析 URL，确定需要建立 WebSocket 连接。**
3. **浏览器网络栈开始处理 WebSocket 连接请求。** 这涉及到查找 DNS，建立 TCP 连接（如果是 `wss://`，还会进行 TLS 握手）。
4. **如果需要通过代理服务器连接，则会先尝试建立 HTTP 隧道 (`CONNECT` 请求)。** `HandleErrTunnelConnectionFailed` 测试模拟了代理连接失败的情况。
5. **客户端发送 WebSocket 握手请求。** 例如，`WebSocketStandardRequest` 函数生成的握手请求。
6. **服务器返回握手响应。**
7. **`websocket_stream_test.cc` 中的测试代码模拟了各种服务器响应和网络状态。** 例如，`HandleErrConnectionClosed` 模拟了接收到部分响应后连接关闭的情况，`HandleConnectionCloseInFirstSegment` 模拟了接收到握手成功响应后立即收到关闭帧的情况。
8. **如果在 TLS 握手过程中出现证书错误，可能会触发 SSL 错误处理。** `CancelSSLRequestAfterDelete` 和 `ContinueSSLRequestAfterDelete` 测试了在这种情况下删除 WebSocket 请求后的行为。
9. **如果底层使用 HTTP/2 协议，并且 HTTP/2 流被重置，则 WebSocket 连接也会失败。** `Http2StreamReset` 测试了这种情况。
10. **最终，WebSocket 连接成功建立或失败。** 测试用例会检查连接状态、接收到的数据、以及记录的统计信息。

当开发者在调试 WebSocket 连接问题时，了解这些底层的网络交互和测试用例可以帮助他们更好地理解问题发生的原因，例如是握手失败、认证问题、网络问题还是服务器错误。他们可以使用 Chromium 的网络日志工具 (chrome://net-export/) 来查看详细的网络交互过程，并与这些测试用例中模拟的情况进行对比。

Prompt: 
```
这是目录为net/websockets/websocket_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
er works for Basic auth will also work for
// Digest. There's just one test here, to confirm that it works at all.
TEST_P(WebSocketStreamCreateDigestAuthTest, DigestPasswordInUrl) {
  CreateAndConnectRawExpectations(
      "ws://FooBar:pass@www.example.org/", NoSubProtocols(),
      HttpRequestHeaders(),
      helper_.BuildAuthSocketData(kUnauthorizedResponse, kAuthorizedRequest,
                                  WebSocketStandardResponse(std::string())));
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
  EXPECT_TRUE(stream_);
  ASSERT_TRUE(response_info_);
  EXPECT_EQ(101, response_info_->headers->response_code());
}

TEST_P(WebSocketMultiProtocolStreamCreateTest, Incomplete) {
  base::HistogramTester histogram_tester;

  AddSSLData();
  if (stream_type_ == BASIC_HANDSHAKE_STREAM) {
    std::string request = WebSocketStandardRequest(
        "/", "www.example.org", Origin(),
        /*send_additional_request_headers=*/{}, /*extra_headers=*/{});
    MockRead reads[] = {MockRead(ASYNC, ERR_IO_PENDING, 0)};
    MockWrite writes[] = {MockWrite(ASYNC, 1, request.c_str())};
    CreateAndConnectRawExpectations("wss://www.example.org/", NoSubProtocols(),
                                    HttpRequestHeaders(),
                                    BuildSocketData(reads, writes));
    base::RunLoop().RunUntilIdle();
    stream_request_.reset();

    auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
        "Net.WebSocket.HandshakeResult2");
    EXPECT_EQ(1, samples->TotalCount());
    EXPECT_EQ(1,
              samples->GetCount(static_cast<int>(
                  WebSocketHandshakeStreamBase::HandshakeResult::INCOMPLETE)));
  } else {
    DCHECK_EQ(stream_type_, HTTP2_HANDSHAKE_STREAM);
    CreateAndConnectStandard("wss://www.example.org/", NoSubProtocols(), {}, {},
                             {});
    stream_request_.reset();

    auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
        "Net.WebSocket.HandshakeResult2");
    EXPECT_EQ(1, samples->TotalCount());
    EXPECT_EQ(
        1,
        samples->GetCount(static_cast<int>(
            WebSocketHandshakeStreamBase::HandshakeResult::HTTP2_INCOMPLETE)));
  }
}

TEST_P(WebSocketMultiProtocolStreamCreateTest, Http2StreamReset) {
  AddSSLData();

  if (stream_type_ == BASIC_HANDSHAKE_STREAM) {
    // This is a dummy transaction to avoid crash in ~URLRequestContext().
    CreateAndConnectStandard("wss://www.example.org/", NoSubProtocols(), {}, {},
                             {});
  } else {
    DCHECK_EQ(stream_type_, HTTP2_HANDSHAKE_STREAM);
    base::HistogramTester histogram_tester;

    SetResetWebSocketHttp2Stream(true);
    CreateAndConnectStandard("wss://www.example.org/", NoSubProtocols(), {}, {},
                             {});
    base::RunLoop().RunUntilIdle();
    stream_request_.reset();

    EXPECT_TRUE(has_failed());
    EXPECT_EQ("Stream closed with error: net::ERR_HTTP2_PROTOCOL_ERROR",
              failure_message());

    auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
        "Net.WebSocket.HandshakeResult2");
    EXPECT_EQ(1, samples->TotalCount());
    EXPECT_EQ(
        1, samples->GetCount(static_cast<int>(
               WebSocketHandshakeStreamBase::HandshakeResult::HTTP2_FAILED)));
  }
}

TEST_P(WebSocketStreamCreateTest, HandleErrConnectionClosed) {
  base::HistogramTester histogram_tester;

  static constexpr char kTruncatedResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "Cache-Control: no-sto";

  std::string request = WebSocketStandardRequest(
      "/", "www.example.org", Origin(), /*send_additional_request_headers=*/{},
      /*extra_headers=*/{});
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, 1, kTruncatedResponse),
      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED, 2),
  };
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0, request.c_str())};
  std::unique_ptr<SequencedSocketData> socket_data(
      BuildSocketData(reads, writes));
  socket_data->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());

  stream_request_.reset();

  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());
  EXPECT_EQ(1, samples->GetCount(static_cast<int>(
                   WebSocketHandshakeStreamBase::HandshakeResult::
                       FAILED_SWITCHING_PROTOCOLS)));
}

TEST_P(WebSocketStreamCreateTest, HandleErrTunnelConnectionFailed) {
  static constexpr char kConnectRequest[] =
      "CONNECT www.example.org:80 HTTP/1.1\r\n"
      "Host: www.example.org:80\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "\r\n";

  static constexpr char kProxyResponse[] =
      "HTTP/1.1 403 Forbidden\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 9\r\n"
      "Connection: keep-alive\r\n"
      "\r\n"
      "Forbidden";

  MockRead reads[] = {MockRead(SYNCHRONOUS, 1, kProxyResponse)};
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0, kConnectRequest)};
  std::unique_ptr<SequencedSocketData> socket_data(
      BuildSocketData(reads, writes));
  url_request_context_host_.SetProxyConfig("https=proxy:8000");
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Establishing a tunnel via proxy server failed.",
            failure_message());
}

TEST_P(WebSocketStreamCreateTest, CancelSSLRequestAfterDelete) {
  auto ssl_socket_data = std::make_unique<SSLSocketDataProvider>(
      ASYNC, ERR_CERT_AUTHORITY_INVALID);
  ssl_socket_data->ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "unittest.selfsigned.der");
  ASSERT_TRUE(ssl_socket_data->ssl_info.cert.get());
  url_request_context_host_.AddSSLSocketDataProvider(
      std::move(ssl_socket_data));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_CONNECTION_RESET, 0)};
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET, 1)};
  std::unique_ptr<SequencedSocketData> raw_socket_data(
      BuildSocketData(reads, writes));
  CreateAndConnectRawExpectations("wss://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(),
                                  std::move(raw_socket_data));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(has_failed());
  ASSERT_TRUE(ssl_error_callbacks_);
  stream_request_.reset();
  ssl_error_callbacks_->CancelSSLRequest(ERR_CERT_AUTHORITY_INVALID,
                                         &ssl_info_);
}

TEST_P(WebSocketStreamCreateTest, ContinueSSLRequestAfterDelete) {
  auto ssl_socket_data = std::make_unique<SSLSocketDataProvider>(
      ASYNC, ERR_CERT_AUTHORITY_INVALID);
  ssl_socket_data->ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "unittest.selfsigned.der");
  ASSERT_TRUE(ssl_socket_data->ssl_info.cert.get());
  url_request_context_host_.AddSSLSocketDataProvider(
      std::move(ssl_socket_data));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_CONNECTION_RESET, 0)};
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET, 1)};
  std::unique_ptr<SequencedSocketData> raw_socket_data(
      BuildSocketData(reads, writes));
  CreateAndConnectRawExpectations("wss://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(),
                                  std::move(raw_socket_data));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(has_failed());
  ASSERT_TRUE(ssl_error_callbacks_);
  stream_request_.reset();
  ssl_error_callbacks_->ContinueSSLRequest();
}

TEST_P(WebSocketStreamCreateTest, HandleConnectionCloseInFirstSegment) {
  std::string request = WebSocketStandardRequest(
      "/", "www.example.org", Origin(), /*send_additional_request_headers=*/{},
      /*extra_headers=*/{});

  // The response headers are immediately followed by a close frame, length 11,
  // code 1013, reason "Try Again".
  std::string close_body = "\x03\xf5Try Again";
  std::string response = WebSocketStandardResponse(std::string()) + "\x88" +
                         static_cast<char>(close_body.size()) + close_body;
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, response.data(), response.size(), 1),
      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED, 2),
  };
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0, request.c_str())};
  std::unique_ptr<SequencedSocketData> socket_data(
      BuildSocketData(reads, writes));
  socket_data->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  WaitUntilConnectDone();
  ASSERT_TRUE(stream_);

  {
    std::vector<std::unique_ptr<WebSocketFrame>> frames;
    TestCompletionCallback callback1;
    int rv1 = stream_->ReadFrames(&frames, callback1.callback());
    rv1 = callback1.GetResult(rv1);
    ASSERT_THAT(rv1, IsOk());
    ASSERT_EQ(1U, frames.size());
    EXPECT_EQ(frames[0]->header.opcode, WebSocketFrameHeader::kOpCodeClose);
    EXPECT_TRUE(frames[0]->header.final);
    EXPECT_EQ(close_body, base::as_string_view(frames[0]->payload));
  }

  std::vector<std::unique_ptr<WebSocketFrame>> empty_frames;
  TestCompletionCallback callback2;
  int rv2 = stream_->ReadFrames(&empty_frames, callback2.callback());
  rv2 = callback2.GetResult(rv2);
  ASSERT_THAT(rv2, IsError(ERR_CONNECTION_CLOSED));
}

}  // namespace
}  // namespace net

"""


```
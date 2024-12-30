Response:
The user wants a summary of the functionalities present in the provided C++ code snippet, which is part of a test file for WebSocket stream creation in Chromium's networking stack. I need to go through each test case and understand what scenario it is verifying. If a test relates to JavaScript, I'll need to provide an example of how a similar feature would be used in JavaScript. If a test involves specific input and output, I need to detail that. If it demonstrates common user/programming errors, I need to illustrate those. Finally, I need to explain how a user's actions might lead to this code being executed for debugging purposes. This is part 2 of a 3-part request, so I need to focus on summarizing the functionality *within this specific snippet*.

Here's a breakdown of the tests in the snippet:

- **UnacceptedSubProtocol:** Tests rejection when the server doesn't respond with a requested sub-protocol.
- **MultipleSubProtocolsInResponse:** Tests rejection when the server sends multiple sub-protocol headers.
- **UnmatchedSubProtocolInResponse:** Tests rejection when the server responds with a sub-protocol not requested.
- **PerMessageDeflateSuccess:** Tests the successful negotiation of the `permessage-deflate` extension.
- **PerMessageDeflateParamsSuccess:** Tests successful negotiation with all possible parameters for `permessage-deflate`.
- **PerMessageDeflateInflates:** Verifies that messages are actually decompressed when `permessage-deflate` is enabled.
- **UnknownExtension:** Tests rejection of an unknown extension.
- **MalformedExtension:** Tests rejection of a malformed extension string.
- **OnlyOnePerMessageDeflateAllowed:** Tests rejection when the server sends duplicate `permessage-deflate` headers.
- **NoMaxWindowBitsArgument:** Tests rejection when `client_max_window_bits` is specified without a value.
- **DoubleAccept:** Tests rejection of multiple `Sec-WebSocket-Accept` headers.
- **InvalidStatusCode:** Tests rejection of invalid HTTP status codes (200 for HTTP/1.1 and 101 for HTTP/2) during the handshake.
- **RedirectsRejected:** Tests that redirects during the WebSocket handshake are rejected.
- **MalformedResponse:** Tests rejection of malformed HTTP responses.
- **MissingUpgradeHeader:** Tests rejection when the `Upgrade` header is missing.
- **DoubleUpgradeHeader:** Tests rejection of multiple `Upgrade` headers.
- **IncorrectUpgradeHeader:** Tests rejection when the `Upgrade` header value is incorrect.
- **MissingConnectionHeader:** Tests rejection when the `Connection` header is missing.
- **IncorrectConnectionHeader:** Tests rejection when the `Connection` header doesn't contain "Upgrade".
- **AdditionalTokenInConnectionHeader:** Tests that additional tokens in the `Connection` header are allowed.
- **MissingSecWebSocketAccept:** Tests rejection when the `Sec-WebSocket-Accept` header is missing.
- **WrongSecWebSocketAccept:** Tests rejection when the `Sec-WebSocket-Accept` value is incorrect.
- **Cancellation:** Tests the cancellation of a WebSocket stream request.
- **ConnectionFailure:** Tests how connection failures are handled.
- **ConnectionTimeout:** Tests how connection timeouts are handled.
- **HandshakeTimeout:** Tests the timeout mechanism for the WebSocket handshake.
- **HandshakeTimerOnSuccess:** Verifies that the handshake timer is stopped on a successful connection.
- **HandshakeTimerOnFailure:** Verifies that the handshake timer is stopped on a connection failure.
- **CancellationDuringConnect:** Tests cancellation during the connection establishment phase.
- **CancellationDuringWrite:** Tests cancellation while writing request headers.
- **CancellationDuringRead:** Tests cancellation while reading response headers.
- **VeryLargeResponseHeaders:** Tests that very large response headers don't cause a crash.
- **NoResponse:** Tests the scenario where the server closes the connection without sending a handshake response.
- **SelfSignedCertificateFailure:** Tests the handling of self-signed certificate failures.
- **SelfSignedCertificateSuccess:** Tests the scenario where a user overrides a self-signed certificate error.
- **FailureNoCredentials:** Tests handling of basic authentication failures when no credentials are provided.
- **SuccessPasswordInUrl:** Tests successful authentication when credentials are in the URL.
- **FailureIncorrectPasswordInUrl:** Tests authentication failure with incorrect credentials in the URL.
- **SuccessfulConnectionReuse:** Tests connection reuse after successful authentication.
- **OnAuthRequiredCancelAuth:** Tests cancellation of authentication via `OnAuthRequired`.
- **OnAuthRequiredSetAuth:** Tests providing credentials via `OnAuthRequired`.
这个代码片段主要包含了一系列针对 WebSocket 多协议和扩展握手过程的单元测试。这些测试旨在验证 `net/websockets/websocket_stream_test.cc` 文件中的 WebSocket 流创建逻辑是否按照预期工作，特别是在处理各种成功的和失败的握手场景时。

**主要功能归纳:**

1. **子协议协商测试:**
   - 验证当服务端未接受任何客户端请求的子协议时，连接应被拒绝。
   - 验证当服务端在响应中发送多个 `Sec-WebSocket-Protocol` 头时，连接应被拒绝。
   - 验证当服务端响应的子协议与客户端请求的任何子协议都不匹配时，连接应被拒绝。

2. **扩展协商测试 (主要针对 `permessage-deflate` 扩展):**
   - 验证 `permessage-deflate` 扩展的基本成功协商场景。
   - 验证带有所有可选参数的 `permessage-deflate` 扩展的成功协商。
   - 验证当协商了 `permessage-deflate` 扩展后，接收到的数据会被正确解压。
   - 验证当服务端响应中包含未知的扩展时，连接应被拒绝。
   - 验证当服务端响应中包含格式错误的扩展信息时，连接应被拒绝。
   - 验证服务端发送重复的 `permessage-deflate` 响应头时，连接应被拒绝。
   - 验证当 `client_max_window_bits` 参数缺少值时，连接应被拒绝。

3. **HTTP 握手头测试:**
   - 验证当服务端响应中包含多个 `Sec-WebSocket-Accept` 头时，连接应被拒绝。
   - 验证当使用 HTTP/1.1 时，服务端返回 200 状态码，或使用 HTTP/2 时返回 101 状态码时，连接应被拒绝。
   - 验证 WebSocket 握手过程中不允许重定向。
   - 验证格式错误的 HTTP 响应应导致握手失败。
   - 验证服务端响应中缺少 `Upgrade` 头时，连接应被拒绝。
   - 验证服务端响应中包含多个 `Upgrade` 头时，连接应被拒绝。
   - 验证服务端响应中 `Upgrade` 头的值不为 "websocket" 时，连接应被拒绝。
   - 验证服务端响应中缺少 `Connection` 头时，连接应被拒绝。
   - 验证服务端响应中 `Connection` 头的值不包含 "Upgrade" 时，连接应被拒绝。
   - 验证服务端响应中 `Connection` 头可以包含 "Upgrade" 之外的其他 token。
   - 验证服务端响应中缺少 `Sec-WebSocket-Accept` 头时，连接应被拒绝。
   - 验证服务端响应中 `Sec-WebSocket-Accept` 头的值不正确时，连接应被拒绝。

4. **连接生命周期和错误处理测试:**
   - 验证 WebSocket 流请求可以被取消。
   - 验证连接建立失败的情况应被正确处理。
   - 验证连接超时的情况应被正确处理。
   - 验证 WebSocket 握手超时的情况应被正确处理。
   - 验证连接成功时握手定时器应停止。
   - 验证连接失败时握手定时器应停止。
   - 验证在连接建立过程中取消请求的情况。
   - 验证在写入请求头过程中取消请求的情况。
   - 验证在读取响应头过程中取消请求的情况。
   - 验证超大的响应头不会导致崩溃。
   - 验证服务端在发送握手响应之前关闭连接的情况。
   - 验证自签名证书导致的连接失败情况。
   - 验证用户允许自签名证书的情况。

5. **HTTP 认证测试 (Basic 认证):**
   - 验证当服务端请求认证但客户端没有提供凭据时，连接应失败。
   - 验证当 URL 中包含正确的用户名和密码时，认证应成功。
   - 验证当 URL 中包含不正确的用户名或密码时，认证应失败。
   - 验证在认证成功后，连接可以被复用。
   - 验证可以通过 `OnAuthRequired` 回调取消认证。
   - 验证可以通过 `OnAuthRequired` 回调提供认证凭据。

**与 JavaScript 的关系举例说明:**

这些测试直接关系到浏览器中 JavaScript WebSocket API 的实现。例如，以下 JavaScript 代码尝试连接到一个 WebSocket 服务器并请求一个子协议 "chat":

```javascript
const websocket = new WebSocket('wss://www.example.org/testing_path', ['chat']);

websocket.onerror = (event) => {
  console.error('WebSocket error observed:', event);
};

websocket.onopen = () => {
  console.log('WebSocket connection opened.');
};

websocket.onmessage = (event) => {
  console.log('Message from server ', event.data);
};

websocket.onclose = () => {
  console.log('WebSocket connection closed.');
};
```

- **`UnacceptedSubProtocol` 测试**模拟了服务器拒绝 "chat" 子协议的情况。在 JavaScript 中，`onerror` 事件会被触发，并且错误消息可能包含 "Error during WebSocket handshake: Sent non-empty 'Sec-WebSocket-Protocol' header but no response was received"。

- **`PerMessageDeflateSuccess` 测试**对应了服务器在握手响应中包含 `Sec-WebSocket-Extensions: permessage-deflate` 头的情况。在 JavaScript 中，这意味着浏览器和服务器之间传输的消息会被压缩和解压缩，对 JavaScript 代码是透明的。

- **`InvalidStatusCode` 测试**模拟了服务器返回了错误的 HTTP 状态码（例如 200）。在 JavaScript 中，`onerror` 事件会被触发，因为 WebSocket 连接建立失败。

**逻辑推理的假设输入与输出:**

**假设输入 (针对 `UnmatchedSubProtocolInResponse` 测试):**

- 客户端请求连接到 `wss://www.example.org/testing_path`，并指定了子协议列表 `["chatv11.chromium.org", "chatv20.chromium.org"]`。
- 服务端响应的 `Sec-WebSocket-Protocol` 头为 `"chatv21.chromium.org"`。

**输出:**

- 连接建立失败。
- `failure_message()` 返回 "Error during WebSocket handshake: 'Sec-WebSocket-Protocol' header value 'chatv21.chromium.org' in response does not match any of sent values"。

**用户或编程常见的使用错误举例说明:**

- **子协议不匹配:**  用户在 JavaScript 中指定了某些子协议，但服务器配置或实现不支持这些子协议，导致 `UnacceptedSubProtocol` 或 `UnmatchedSubProtocolInResponse` 类型的错误。

  ```javascript
  const websocket = new WebSocket('wss://example.com', ['unsupported-protocol']);
  ```

- **服务端配置错误导致扩展协商失败:** 服务端错误地配置了 `permessage-deflate` 扩展的参数，或者发送了重复的扩展头，这会触发 `MalformedExtension` 或 `OnlyOnePerMessageDeflateAllowed` 类型的错误。用户在 JavaScript 中可能看不到直接的错误，但 WebSocket 连接会失败。

- **未处理自签名证书:** 用户尝试连接到使用自签名证书的 `wss` 地址，但没有采取任何措施信任该证书，这会导致 `SelfSignedCertificateFailure` 类型的错误。浏览器通常会阻止这种连接，并可能向用户显示警告。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个使用了 WebSocket 的网页。**
2. **网页中的 JavaScript 代码尝试创建一个 WebSocket 连接。** 例如，使用 `new WebSocket('wss://...')`。
3. **浏览器网络栈开始处理 WebSocket 连接请求。** 这会触发 `net/websockets` 目录下的代码执行。
4. **`WebSocketHandshakeStream` 类负责处理握手过程。**
5. **在握手过程中，会解析服务器的响应头。** 如果服务器的响应头不符合 WebSocket 协议规范 (例如，缺少必要的头，头的值不正确，使用了不支持的扩展等)，相关的测试用例 (如 `MissingUpgradeHeader`, `WrongSecWebSocketAccept`, `UnknownExtension` 等) 模拟的情况就会发生。
6. **如果握手失败，`WebSocketHandshakeStream` 会报告错误。** 开发者可以通过浏览器开发者工具的网络选项卡或控制台查看错误信息，这些错误信息可能与测试用例中的 `failure_message()` 输出类似。

例如，如果用户尝试连接到一个返回 200 状态码的 WebSocket 服务器，浏览器开发者工具的网络选项卡可能会显示该请求失败，并带有 "Error during WebSocket handshake: Unexpected response code: 200" 这样的错误信息，这对应了 `InvalidStatusCode` 测试用例模拟的场景. 开发者可以检查服务器的配置和响应头来排查问题。

Prompt: 
```
这是目录为net/websockets/websocket_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
== BASIC_HANDSHAKE_STREAM) {
    EXPECT_EQ(
        1,
        samples->GetCount(static_cast<int>(
            WebSocketHandshakeStreamBase::HandshakeResult::FAILED_SUBPROTO)));
  } else {
    DCHECK_EQ(stream_type_, HTTP2_HANDSHAKE_STREAM);
    EXPECT_EQ(1, samples->GetCount(static_cast<int>(
                     WebSocketHandshakeStreamBase::HandshakeResult::
                         HTTP2_FAILED_SUBPROTO)));
  }
}

// Missing sub-protocol response is rejected.
TEST_P(WebSocketMultiProtocolStreamCreateTest, UnacceptedSubProtocol) {
  AddSSLData();
  std::vector<std::string> sub_protocols;
  sub_protocols.push_back("chat.example.com");
  CreateAndConnectStandard("wss://www.example.org/testing_path", sub_protocols,
                           {}, {{"Sec-WebSocket-Protocol", "chat.example.com"}},
                           {});
  WaitUntilConnectDone();
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "Sent non-empty 'Sec-WebSocket-Protocol' header "
            "but no response was received",
            failure_message());
}

// Only one sub-protocol can be accepted.
TEST_P(WebSocketMultiProtocolStreamCreateTest, MultipleSubProtocolsInResponse) {
  AddSSLData();
  std::vector<std::string> sub_protocols;
  sub_protocols.push_back("chatv11.chromium.org");
  sub_protocols.push_back("chatv20.chromium.org");
  CreateAndConnectStandard("wss://www.example.org/testing_path", sub_protocols,
                           {},
                           {{"Sec-WebSocket-Protocol",
                             "chatv11.chromium.org, chatv20.chromium.org"}},
                           {{"Sec-WebSocket-Protocol",
                             "chatv11.chromium.org, chatv20.chromium.org"}});
  WaitUntilConnectDone();
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
  EXPECT_EQ(
      "Error during WebSocket handshake: "
      "'Sec-WebSocket-Protocol' header must not appear "
      "more than once in a response",
      failure_message());
}

// Unmatched sub-protocol should be rejected.
TEST_P(WebSocketMultiProtocolStreamCreateTest, UnmatchedSubProtocolInResponse) {
  AddSSLData();
  std::vector<std::string> sub_protocols;
  sub_protocols.push_back("chatv11.chromium.org");
  sub_protocols.push_back("chatv20.chromium.org");
  CreateAndConnectStandard(
      "wss://www.example.org/testing_path", sub_protocols, {},
      {{"Sec-WebSocket-Protocol",
        "chatv11.chromium.org, chatv20.chromium.org"}},
      {{"Sec-WebSocket-Protocol", "chatv21.chromium.org"}});
  WaitUntilConnectDone();
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "'Sec-WebSocket-Protocol' header value 'chatv21.chromium.org' "
            "in response does not match any of sent values",
            failure_message());
}

// permessage-deflate extension basic success case.
TEST_P(WebSocketStreamCreateExtensionTest, PerMessageDeflateSuccess) {
  CreateAndConnectWithExtensions("permessage-deflate");
  EXPECT_TRUE(stream_);
  EXPECT_FALSE(has_failed());
}

// permessage-deflate extensions success with all parameters.
TEST_P(WebSocketStreamCreateExtensionTest, PerMessageDeflateParamsSuccess) {
  CreateAndConnectWithExtensions(
      "permessage-deflate; client_no_context_takeover; "
      "server_max_window_bits=11; client_max_window_bits=13; "
      "server_no_context_takeover");
  EXPECT_TRUE(stream_);
  EXPECT_FALSE(has_failed());
}

// Verify that incoming messages are actually decompressed with
// permessage-deflate enabled.
TEST_P(WebSocketStreamCreateExtensionTest, PerMessageDeflateInflates) {
  AddSSLData();
  SetAdditionalResponseData(std::string(
      "\xc1\x07"  // WebSocket header (FIN + RSV1, Text payload 7 bytes)
      "\xf2\x48\xcd\xc9\xc9\x07\x00",  // "Hello" DEFLATE compressed
      9));
  CreateAndConnectStandard(
      "wss://www.example.org/testing_path", NoSubProtocols(), {}, {},
      {{"Sec-WebSocket-Extensions", "permessage-deflate"}});
  WaitUntilConnectDone();

  ASSERT_TRUE(stream_);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  TestCompletionCallback callback;
  int rv = stream_->ReadFrames(&frames, callback.callback());
  rv = callback.GetResult(rv);
  ASSERT_THAT(rv, IsOk());
  ASSERT_EQ(1U, frames.size());
  ASSERT_EQ(5U, frames[0]->header.payload_length);
  EXPECT_EQ("Hello", base::as_string_view(frames[0]->payload));
}

// Unknown extension in the response is rejected
TEST_P(WebSocketStreamCreateExtensionTest, UnknownExtension) {
  CreateAndConnectWithExtensions("x-unknown-extension");
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "Found an unsupported extension 'x-unknown-extension' "
            "in 'Sec-WebSocket-Extensions' header",
            failure_message());
}

// Malformed extensions are rejected (this file does not cover all possible
// parse failures, as the parser is covered thoroughly by its own unit tests).
TEST_P(WebSocketStreamCreateExtensionTest, MalformedExtension) {
  CreateAndConnectWithExtensions(";");
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
  EXPECT_EQ(
      "Error during WebSocket handshake: 'Sec-WebSocket-Extensions' header "
      "value is rejected by the parser: ;",
      failure_message());
}

// The permessage-deflate extension may only be specified once.
TEST_P(WebSocketStreamCreateExtensionTest, OnlyOnePerMessageDeflateAllowed) {
  base::HistogramTester histogram_tester;

  CreateAndConnectWithExtensions(
      "permessage-deflate, permessage-deflate; client_max_window_bits=10");
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
  EXPECT_EQ(
      "Error during WebSocket handshake: "
      "Received duplicate permessage-deflate response",
      failure_message());

  stream_request_.reset();

  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());
  if (stream_type_ == BASIC_HANDSHAKE_STREAM) {
    EXPECT_EQ(
        1,
        samples->GetCount(static_cast<int>(
            WebSocketHandshakeStreamBase::HandshakeResult::FAILED_EXTENSIONS)));
  } else {
    DCHECK_EQ(stream_type_, HTTP2_HANDSHAKE_STREAM);
    EXPECT_EQ(1, samples->GetCount(static_cast<int>(
                     WebSocketHandshakeStreamBase::HandshakeResult::
                         HTTP2_FAILED_EXTENSIONS)));
  }
}

// client_max_window_bits must have an argument
TEST_P(WebSocketStreamCreateExtensionTest, NoMaxWindowBitsArgument) {
  CreateAndConnectWithExtensions("permessage-deflate; client_max_window_bits");
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
  EXPECT_EQ(
      "Error during WebSocket handshake: Error in permessage-deflate: "
      "client_max_window_bits must have value",
      failure_message());
}

// Other cases for permessage-deflate parameters are tested in
// websocket_deflate_parameters_test.cc.

// TODO(ricea): Check that WebSocketDeflateStream is initialised with the
// arguments from the server. This is difficult because the data written to the
// socket is randomly masked.

// Additional Sec-WebSocket-Accept headers should be rejected.
TEST_P(WebSocketStreamCreateTest, DoubleAccept) {
  CreateAndConnectStandard(
      "ws://www.example.org/", NoSubProtocols(), {}, {},
      {{"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}});
  WaitUntilConnectDone();
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "'Sec-WebSocket-Accept' header must not appear "
            "more than once in a response",
            failure_message());
}

// When upgrading an HTTP/1 connection, response code 200 is invalid and must be
// rejected.  Response code 101 means success.  On the other hand, when
// requesting a WebSocket stream over HTTP/2, response code 101 is invalid and
// must be rejected.  Response code 200 means success.
TEST_P(WebSocketMultiProtocolStreamCreateTest, InvalidStatusCode) {
  base::HistogramTester histogram_tester;

  AddSSLData();
  if (stream_type_ == BASIC_HANDSHAKE_STREAM) {
    static constexpr char kInvalidStatusCodeResponse[] =
        "HTTP/1.1 200 OK\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "\r\n";
    CreateAndConnectCustomResponse("wss://www.example.org/", NoSubProtocols(),
                                   {}, {}, kInvalidStatusCodeResponse);
  } else {
    DCHECK_EQ(stream_type_, HTTP2_HANDSHAKE_STREAM);
    SetHttp2ResponseStatus("101");
    CreateAndConnectStandard("wss://www.example.org/", NoSubProtocols(), {}, {},
                             {});
  }

  WaitUntilConnectDone();
  stream_request_.reset();
  EXPECT_TRUE(has_failed());
  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());

  if (stream_type_ == BASIC_HANDSHAKE_STREAM) {
    EXPECT_EQ("Error during WebSocket handshake: Unexpected response code: 200",
              failure_message());
    EXPECT_EQ(failure_response_code(), 200);
    EXPECT_EQ(
        1, samples->GetCount(static_cast<int>(
               WebSocketHandshakeStreamBase::HandshakeResult::INVALID_STATUS)));
  } else {
    DCHECK_EQ(stream_type_, HTTP2_HANDSHAKE_STREAM);
    EXPECT_EQ("Error during WebSocket handshake: Unexpected response code: 101",
              failure_message());
    EXPECT_EQ(failure_response_code(), 101);
    EXPECT_EQ(1, samples->GetCount(static_cast<int>(
                     WebSocketHandshakeStreamBase::HandshakeResult::
                         HTTP2_INVALID_STATUS)));
  }
}

// Redirects are not followed (according to the WHATWG WebSocket API, which
// overrides RFC6455 for browser applications).
TEST_P(WebSocketMultiProtocolStreamCreateTest, RedirectsRejected) {
  AddSSLData();
  if (stream_type_ == BASIC_HANDSHAKE_STREAM) {
    static constexpr char kRedirectResponse[] =
        "HTTP/1.1 302 Moved Temporarily\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 34\r\n"
        "Connection: keep-alive\r\n"
        "Location: wss://www.example.org/other\r\n"
        "\r\n"
        "<title>Moved</title><h1>Moved</h1>";
    CreateAndConnectCustomResponse("wss://www.example.org/", NoSubProtocols(),
                                   {}, {}, kRedirectResponse);
  } else {
    DCHECK_EQ(stream_type_, HTTP2_HANDSHAKE_STREAM);
    SetHttp2ResponseStatus("302");
    CreateAndConnectStandard("wss://www.example.org/", NoSubProtocols(), {}, {},
                             {});
  }
  WaitUntilConnectDone();

  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: Unexpected response code: 302",
            failure_message());
}

// Malformed responses should be rejected. HttpStreamParser will accept just
// about any garbage in the middle of the headers. To make it give up, the junk
// has to be at the start of the response. Even then, it just gets treated as an
// HTTP/0.9 response.
TEST_P(WebSocketStreamCreateTest, MalformedResponse) {
  static constexpr char kMalformedResponse[] =
      "220 mx.google.com ESMTP\r\n"
      "HTTP/1.1 101 OK\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "\r\n";
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kMalformedResponse);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: Invalid status line",
            failure_message());
}

// Upgrade header must be present.
TEST_P(WebSocketStreamCreateTest, MissingUpgradeHeader) {
  base::HistogramTester histogram_tester;

  static constexpr char kMissingUpgradeResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "\r\n";
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kMissingUpgradeResponse);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: 'Upgrade' header is missing",
            failure_message());

  stream_request_.reset();

  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());
  EXPECT_EQ(
      1, samples->GetCount(static_cast<int>(
             WebSocketHandshakeStreamBase::HandshakeResult::FAILED_UPGRADE)));
}

// There must only be one upgrade header.
TEST_P(WebSocketStreamCreateTest, DoubleUpgradeHeader) {
  CreateAndConnectStandard("ws://www.example.org/", NoSubProtocols(), {}, {},
                           {{"Upgrade", "HTTP/2.0"}});
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "'Upgrade' header must not appear more than once in a response",
            failure_message());
}

// There must only be one correct upgrade header.
TEST_P(WebSocketStreamCreateTest, IncorrectUpgradeHeader) {
  static constexpr char kMissingUpgradeResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "Upgrade: hogefuga\r\n"
      "\r\n";
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kMissingUpgradeResponse);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "'Upgrade' header value is not 'WebSocket': hogefuga",
            failure_message());
}

// Connection header must be present.
TEST_P(WebSocketStreamCreateTest, MissingConnectionHeader) {
  base::HistogramTester histogram_tester;

  static constexpr char kMissingConnectionResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "\r\n";
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kMissingConnectionResponse);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "'Connection' header is missing",
            failure_message());

  stream_request_.reset();

  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());
  EXPECT_EQ(
      1,
      samples->GetCount(static_cast<int>(
          WebSocketHandshakeStreamBase::HandshakeResult::FAILED_CONNECTION)));
}

// Connection header must contain "Upgrade".
TEST_P(WebSocketStreamCreateTest, IncorrectConnectionHeader) {
  static constexpr char kMissingConnectionResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "Connection: hogefuga\r\n"
      "\r\n";
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kMissingConnectionResponse);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "'Connection' header value must contain 'Upgrade'",
            failure_message());
}

// Connection header is permitted to contain other tokens.
TEST_P(WebSocketStreamCreateTest, AdditionalTokenInConnectionHeader) {
  static constexpr char kAdditionalConnectionTokenResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade, Keep-Alive\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "\r\n";
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kAdditionalConnectionTokenResponse);
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
  EXPECT_TRUE(stream_);
}

// Sec-WebSocket-Accept header must be present.
TEST_P(WebSocketStreamCreateTest, MissingSecWebSocketAccept) {
  base::HistogramTester histogram_tester;

  static constexpr char kMissingAcceptResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "\r\n";
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kMissingAcceptResponse);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "'Sec-WebSocket-Accept' header is missing",
            failure_message());

  stream_request_.reset();

  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());
  EXPECT_EQ(1,
            samples->GetCount(static_cast<int>(
                WebSocketHandshakeStreamBase::HandshakeResult::FAILED_ACCEPT)));
}

// Sec-WebSocket-Accept header must match the key that was sent.
TEST_P(WebSocketStreamCreateTest, WrongSecWebSocketAccept) {
  static constexpr char kIncorrectAcceptResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: x/byyPZ2tOFvJCGkkugcKvqhhPk=\r\n"
      "\r\n";
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kIncorrectAcceptResponse);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "Incorrect 'Sec-WebSocket-Accept' header value",
            failure_message());
}

// Cancellation works.
TEST_P(WebSocketStreamCreateTest, Cancellation) {
  CreateAndConnectStandard("ws://www.example.org/", NoSubProtocols(), {}, {},
                           {});
  stream_request_.reset();
  // WaitUntilConnectDone doesn't work in this case.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(has_failed());
  EXPECT_FALSE(stream_);
  EXPECT_FALSE(request_info_);
  EXPECT_FALSE(response_info_);
}

// Connect failure must look just like negotiation failure.
TEST_P(WebSocketStreamCreateTest, ConnectionFailure) {
  std::unique_ptr<SequencedSocketData> socket_data(BuildNullSocketData());
  socket_data->set_connect_data(
      MockConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED));
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error in connection establishment: net::ERR_CONNECTION_REFUSED",
            failure_message());
  EXPECT_FALSE(request_info_);
  EXPECT_FALSE(response_info_);
}

// Connect timeout must look just like any other failure.
TEST_P(WebSocketStreamCreateTest, ConnectionTimeout) {
  std::unique_ptr<SequencedSocketData> socket_data(BuildNullSocketData());
  socket_data->set_connect_data(
      MockConnect(ASYNC, ERR_CONNECTION_TIMED_OUT));
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error in connection establishment: net::ERR_CONNECTION_TIMED_OUT",
            failure_message());
}

// The server doesn't respond to the opening handshake.
TEST_P(WebSocketStreamCreateTest, HandshakeTimeout) {
  std::unique_ptr<SequencedSocketData> socket_data(BuildNullSocketData());
  socket_data->set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  auto timer = std::make_unique<MockWeakTimer>();
  base::WeakPtr<MockWeakTimer> weak_timer = timer->AsWeakPtr();
  SetTimer(std::move(timer));
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  EXPECT_FALSE(has_failed());
  ASSERT_TRUE(weak_timer.get());
  EXPECT_TRUE(weak_timer->IsRunning());

  weak_timer->Fire();
  WaitUntilConnectDone();

  EXPECT_TRUE(has_failed());
  EXPECT_EQ("WebSocket opening handshake timed out", failure_message());
  ASSERT_TRUE(weak_timer.get());
  EXPECT_FALSE(weak_timer->IsRunning());
}

// When the connection establishes the timer should be stopped.
TEST_P(WebSocketStreamCreateTest, HandshakeTimerOnSuccess) {
  auto timer = std::make_unique<MockWeakTimer>();
  base::WeakPtr<MockWeakTimer> weak_timer = timer->AsWeakPtr();

  SetTimer(std::move(timer));
  CreateAndConnectStandard("ws://www.example.org/", NoSubProtocols(), {}, {},
                           {});
  ASSERT_TRUE(weak_timer);
  EXPECT_TRUE(weak_timer->IsRunning());

  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
  EXPECT_TRUE(stream_);
  ASSERT_TRUE(weak_timer);
  EXPECT_FALSE(weak_timer->IsRunning());
}

// When the connection fails the timer should be stopped.
TEST_P(WebSocketStreamCreateTest, HandshakeTimerOnFailure) {
  std::unique_ptr<SequencedSocketData> socket_data(BuildNullSocketData());
  socket_data->set_connect_data(
      MockConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED));
  auto timer = std::make_unique<MockWeakTimer>();
  base::WeakPtr<MockWeakTimer> weak_timer = timer->AsWeakPtr();
  SetTimer(std::move(timer));
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  ASSERT_TRUE(weak_timer.get());
  EXPECT_TRUE(weak_timer->IsRunning());

  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error in connection establishment: net::ERR_CONNECTION_REFUSED",
            failure_message());
  ASSERT_TRUE(weak_timer.get());
  EXPECT_FALSE(weak_timer->IsRunning());
}

// Cancellation during connect works.
TEST_P(WebSocketStreamCreateTest, CancellationDuringConnect) {
  std::unique_ptr<SequencedSocketData> socket_data(BuildNullSocketData());
  socket_data->set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  stream_request_.reset();
  // WaitUntilConnectDone doesn't work in this case.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(has_failed());
  EXPECT_FALSE(stream_);
}

// Cancellation during write of the request headers works.
TEST_P(WebSocketStreamCreateTest, CancellationDuringWrite) {
  // First write never completes.
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto socket_data =
      std::make_unique<SequencedSocketData>(base::span<MockRead>(), writes);
  auto* socket_data_ptr = socket_data.get();
  socket_data->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(socket_data_ptr->AllWriteDataConsumed());
  stream_request_.reset();
  // WaitUntilConnectDone doesn't work in this case.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(has_failed());
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(request_info_);
  EXPECT_FALSE(response_info_);
}

// Cancellation during read of the response headers works.
TEST_P(WebSocketStreamCreateTest, CancellationDuringRead) {
  std::string request = WebSocketStandardRequest(
      "/", "www.example.org", Origin(), /*send_additional_request_headers=*/{},
      /*extra_headers=*/{});
  MockWrite writes[] = {MockWrite(ASYNC, 0, request.c_str())};
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 1),
  };
  std::unique_ptr<SequencedSocketData> socket_data(
      BuildSocketData(reads, writes));
  SequencedSocketData* socket_data_raw_ptr = socket_data.get();
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(socket_data_raw_ptr->AllReadDataConsumed());
  stream_request_.reset();
  // WaitUntilConnectDone doesn't work in this case.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(has_failed());
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(request_info_);
  EXPECT_FALSE(response_info_);
}

// Over-size response headers (> 256KB) should not cause a crash.  This is a
// regression test for crbug.com/339456. It is based on the layout test
// "cookie-flood.html".
TEST_P(WebSocketStreamCreateTest, VeryLargeResponseHeaders) {
  base::HistogramTester histogram_tester;

  std::string set_cookie_headers;
  set_cookie_headers.reserve(24 * 20000);
  for (int i = 0; i < 20000; ++i) {
    set_cookie_headers += base::StringPrintf("Set-Cookie: ws-%d=1\r\n", i);
  }
  ASSERT_GT(set_cookie_headers.size(), 256U * 1024U);
  CreateAndConnectStringResponse("ws://www.example.org/", NoSubProtocols(),
                                 set_cookie_headers);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_FALSE(response_info_);

  stream_request_.reset();

  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());
  EXPECT_EQ(1, samples->GetCount(static_cast<int>(
                   WebSocketHandshakeStreamBase::HandshakeResult::FAILED)));
}

// If the remote host closes the connection without sending headers, we should
// log the console message "Connection closed before receiving a handshake
// response".
TEST_P(WebSocketStreamCreateTest, NoResponse) {
  base::HistogramTester histogram_tester;

  std::string request = WebSocketStandardRequest(
      "/", "www.example.org", Origin(), /*send_additional_request_headers=*/{},
      /*extra_headers=*/{});
  MockWrite writes[] = {MockWrite(ASYNC, request.data(), request.size(), 0)};
  MockRead reads[] = {MockRead(ASYNC, 0, 1)};
  std::unique_ptr<SequencedSocketData> socket_data(
      BuildSocketData(reads, writes));
  SequencedSocketData* socket_data_raw_ptr = socket_data.get();
  CreateAndConnectRawExpectations("ws://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(), std::move(socket_data));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(socket_data_raw_ptr->AllReadDataConsumed());
  EXPECT_TRUE(has_failed());
  EXPECT_FALSE(stream_);
  EXPECT_FALSE(response_info_);
  EXPECT_EQ("Connection closed before receiving a handshake response",
            failure_message());

  stream_request_.reset();

  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());
  EXPECT_EQ(
      1, samples->GetCount(static_cast<int>(
             WebSocketHandshakeStreamBase::HandshakeResult::EMPTY_RESPONSE)));
}

TEST_P(WebSocketStreamCreateTest, SelfSignedCertificateFailure) {
  auto ssl_socket_data = std::make_unique<SSLSocketDataProvider>(
      ASYNC, ERR_CERT_AUTHORITY_INVALID);
  ssl_socket_data->ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "unittest.selfsigned.der");
  ASSERT_TRUE(ssl_socket_data->ssl_info.cert.get());
  url_request_context_host_.AddSSLSocketDataProvider(
      std::move(ssl_socket_data));
  std::unique_ptr<SequencedSocketData> raw_socket_data(BuildNullSocketData());
  CreateAndConnectRawExpectations("wss://www.example.org/", NoSubProtocols(),
                                  HttpRequestHeaders(),
                                  std::move(raw_socket_data));
  // WaitUntilConnectDone doesn't work in this case.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(has_failed());
  ASSERT_TRUE(ssl_error_callbacks_);
  ssl_error_callbacks_->CancelSSLRequest(ERR_CERT_AUTHORITY_INVALID,
                                         &ssl_info_);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
}

TEST_P(WebSocketStreamCreateTest, SelfSignedCertificateSuccess) {
  auto ssl_socket_data = std::make_unique<SSLSocketDataProvider>(
      ASYNC, ERR_CERT_AUTHORITY_INVALID);
  ssl_socket_data->ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "unittest.selfsigned.der");
  ASSERT_TRUE(ssl_socket_data->ssl_info.cert.get());
  url_request_context_host_.AddSSLSocketDataProvider(
      std::move(ssl_socket_data));
  url_request_context_host_.AddSSLSocketDataProvider(
      std::make_unique<SSLSocketDataProvider>(ASYNC, OK));
  AddRawExpectations(BuildNullSocketData());
  CreateAndConnectStandard("wss://www.example.org/", NoSubProtocols(), {}, {},
                           {});
  // WaitUntilConnectDone doesn't work in this case.
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(ssl_error_callbacks_);
  ssl_error_callbacks_->ContinueSSLRequest();
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
  EXPECT_TRUE(stream_);
}

// If the server requests authorisation, but we have no credentials, the
// connection should fail cleanly.
TEST_P(WebSocketStreamCreateBasicAuthTest, FailureNoCredentials) {
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kUnauthorizedResponse);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("HTTP Authentication failed; no valid credentials available",
            failure_message());
  EXPECT_FALSE(response_info_);
}

TEST_P(WebSocketStreamCreateBasicAuthTest, SuccessPasswordInUrl) {
  CreateAndConnectAuthHandshake("ws://foo:bar@www.example.org/", "Zm9vOmJhcg==",
                                WebSocketStandardResponse(std::string()));
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
  EXPECT_TRUE(stream_);
  ASSERT_TRUE(response_info_);
  EXPECT_EQ(101, response_info_->headers->response_code());
}

TEST_P(WebSocketStreamCreateBasicAuthTest, FailureIncorrectPasswordInUrl) {
  CreateAndConnectAuthHandshake("ws://foo:baz@www.example.org/",
                                "Zm9vOmJheg==", kUnauthorizedResponse);
  WaitUntilConnectDone();
  EXPECT_TRUE(has_failed());
  EXPECT_FALSE(response_info_);
}

TEST_P(WebSocketStreamCreateBasicAuthTest, SuccessfulConnectionReuse) {
  std::string request1 = WebSocketStandardRequest(
      "/", "www.example.org", Origin(), /*send_additional_request_headers=*/{},
      /*extra_headers=*/{});
  std::string response1 = kUnauthorizedResponse;
  std::string request2 = WebSocketStandardRequest(
      "/", "www.example.org", Origin(),
      {{"Authorization", "Basic Zm9vOmJhcg=="}}, /*extra_headers=*/{});
  std::string response2 = WebSocketStandardResponse(std::string());
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0, request1.c_str()),
      MockWrite(SYNCHRONOUS, 2, request2.c_str()),
  };
  MockRead reads[3] = {
      MockRead(SYNCHRONOUS, 1, response1.c_str()),
      MockRead(SYNCHRONOUS, 3, response2.c_str()),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 4),
  };
  CreateAndConnectRawExpectations("ws://foo:bar@www.example.org/",
                                  NoSubProtocols(), HttpRequestHeaders(),
                                  BuildSocketData(reads, writes));
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
  EXPECT_TRUE(stream_);
  ASSERT_TRUE(response_info_);
  EXPECT_EQ(101, response_info_->headers->response_code());
}

TEST_P(WebSocketStreamCreateBasicAuthTest, OnAuthRequiredCancelAuth) {
  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kUnauthorizedResponse);

  EXPECT_FALSE(request_info_);
  EXPECT_FALSE(response_info_);
  on_auth_required_rv_ = ERR_IO_PENDING;
  WaitUntilOnAuthRequired();

  EXPECT_FALSE(stream_);
  EXPECT_FALSE(has_failed());

  std::move(on_auth_required_callback_).Run(nullptr);
  WaitUntilConnectDone();
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
}

TEST_P(WebSocketStreamCreateBasicAuthTest, OnAuthRequiredSetAuth) {
  CreateAndConnectRawExpectations(
      "ws://www.example.org/", NoSubProtocols(), HttpRequestHeaders(),
      helper_.BuildAuthSocketData(kUnauthorizedResponse,
                                  RequestExpectation("Zm9vOmJheg=="),
                                  WebSocketStandardResponse(std::string())));

  EXPECT_FALSE(request_info_);
  EXPECT_FALSE(response_info_);
  on_auth_required_rv_ = ERR_IO_PENDING;
  WaitUntilOnAuthRequired();

  EXPECT_FALSE(stream_);
  EXPECT_FALSE(has_failed());

  AuthCredentials credentials(u"foo", u"baz");
  std::move(on_auth_required_callback_).Run(&credentials);

  WaitUntilConnectDone();
  EXPECT_TRUE(stream_);
  EXPECT_FALSE(has_failed());
}

// Digest auth has the same connection semantics as Basic auth, so we can
// generally assume that whatev
"""


```
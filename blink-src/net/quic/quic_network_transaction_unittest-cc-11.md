Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/quic/quic_network_transaction_unittest.cc`. They are interested in:

1. **Functionality:** What does this code test?
2. **JavaScript Relation:** Does it have any connection to JavaScript? If so, provide examples.
3. **Logical Inference:** If there's logical reasoning, give example inputs and outputs.
4. **Common Errors:**  Are there common user or programming errors illustrated? Provide examples.
5. **User Journey:** How does a user's interaction lead to this code being executed (debugging context)?
6. **Summary:**  What is the overall purpose of this specific code block, considering it's part 12 of 13?

Let's break down the code block by block to address these points.

**Code Block Analysis:**

*   **`TEST_P(QuicNetworkTransactionTest, DataStream)`:** Tests a basic successful QUIC transaction. It sets up mock QUIC and SSL data, creates a session, makes a request, and verifies the response.
*   **`TEST_P(QuicNetworkTransactionTest, AllowHTTP1FalseProhibitsH1)`:** Tests the scenario where HTTP/1 is explicitly disallowed for an upload stream. It expects an error (`ERR_H2_OR_QUIC_REQUIRED`).
*   **`TEST_P(QuicNetworkTransactionTest, AllowHTTP1MockTest)`:** Confirms that an `UploadDataStreamNotAllowHTTP1` can successfully upload data over QUIC. It sets up a forced QUIC connection and verifies the data transfer.
*   **`TEST_P(QuicNetworkTransactionTest, AllowHTTP1UploadPauseAndResume)`:** Tests pausing and resuming a QUIC upload. It simulates a handshake delay and verifies that the upload completes after the session becomes ready.
*   **`TEST_P(QuicNetworkTransactionTest, AllowHTTP1UploadFailH1AndResumeQuic)`:** Tests a scenario where an initial HTTP/1 connection fails, and a subsequent QUIC connection is attempted and succeeds.
*   **`TEST_P(QuicNetworkTransactionTest, IncorrectHttp3GoAway)`:** Tests how the client handles an invalid `GOAWAY` frame from the server, which should result in a connection closure.
*   **`TEST_P(QuicNetworkTransactionTest, RetryOnHttp3GoAway)`:** Tests the retry mechanism when a valid `GOAWAY` frame is received, indicating that some streams can be retried on a new connection.
*   **`TEST_P(QuicNetworkTransactionTest, WebsocketOpensNewConnectionWithHttp1)`:** Verifies that a WebSocket request, even when a QUIC connection exists, will open a new HTTP/1.1 connection.
*   **`TEST_P(QuicNetworkTransactionTest, WebsocketOpensNewConnectionWithHttp1AfterAltSvcQuic)`:** Similar to the previous test, but after an Alt-Svc advertised QUIC connection has been established.
*   **`TEST_P(QuicNetworkTransactionTest, WebsocketOpensNewConnectionWithHttp1AfterDnsHttpsSvcbAlpn)`:**  Similar to the previous tests, but with DNS HTTPS SVCB ALPN negotiation.

**Synthesis for the Answer:**

Now, I need to structure the answer based on the user's request, covering functionality, JavaScript relation, logical inference, common errors, user journey, and the summary as part 12 of 13.
这个C++源代码文件 `net/quic/quic_network_transaction_unittest.cc` 是 Chromium 网络栈中 QUIC 协议相关的网络事务处理的单元测试文件。它主要用于验证 `HttpNetworkTransaction` 类在与 QUIC 协议交互时的各种行为和正确性。

**功能列举:**

1. **基本 QUIC 请求测试:** 测试使用 QUIC 发送和接收基本 HTTP 请求和响应的能力，包括处理请求头、响应头和响应数据。 (`DataStream` 测试)
2. **禁止 HTTP/1 的场景测试:** 验证在明确禁止使用 HTTP/1 的情况下，请求是否会正确地尝试使用 QUIC，并在无法使用时返回相应的错误。 (`AllowHTTP1FalseProhibitsH1` 测试)
3. **上传数据流测试:** 测试通过 QUIC 上传数据的功能，包括确认特定的上传数据流类型能够正确工作。 (`AllowHTTP1MockTest`, `AllowHTTP1UploadPauseAndResume`, `AllowHTTP1UploadFailH1AndResumeQuic` 测试)
4. **上传暂停和恢复测试:** 验证在 QUIC 连接中上传数据时，暂停和恢复上传操作的功能。 (`AllowHTTP1UploadPauseAndResume` 测试)
5. **HTTP/1 连接失败后尝试 QUIC 测试:** 测试当 HTTP/1 连接尝试失败后，系统是否能够正确回退并尝试使用可用的 QUIC 连接。 (`AllowHTTP1UploadFailH1AndResumeQuic` 测试)
6. **错误的 HTTP/3 GOAWAY 帧处理测试:** 验证客户端如何处理来自服务器的格式不正确的 HTTP/3 GOAWAY 帧，通常应导致连接关闭。 (`IncorrectHttp3GoAway` 测试)
7. **HTTP/3 GOAWAY 帧后的重试机制测试:** 测试当收到服务器发送的 HTTP/3 GOAWAY 帧时，客户端是否能够正确地识别可以安全重试的请求，并在新的连接上重新发起这些请求。 (`RetryOnHttp3GoAway` 测试)
8. **WebSocket 与 QUIC 的交互测试:** 验证当存在到服务器的 QUIC 连接时，发起 WebSocket 连接是否会建立新的 HTTP/1.1 连接，而不是尝试在现有的 QUIC 连接上升级协议。 (`WebsocketOpensNewConnectionWithHttp1`, `WebsocketOpensNewConnectionWithHttp1AfterAltSvcQuic`, `WebsocketOpensNewConnectionWithHttp1AfterDnsHttpsSvcbAlpn` 测试)
9. **Alt-Svc 和 QUIC 的交互测试:**  测试在通过 Alt-Svc 发现 QUIC 支持后，后续请求是否能够正确使用 QUIC。 (`WebsocketOpensNewConnectionWithHttp1AfterAltSvcQuic` 测试)
10. **DNS HTTPS SVCB ALPN 的交互测试:** 测试在使用 DNS HTTPS SVCB 记录和 ALPN 进行协议协商时，QUIC 连接的建立和使用是否正确。 (`WebsocketOpensNewConnectionWithHttp1AfterDnsHttpsSvcbAlpn` 测试)

**与 JavaScript 的关系:**

这个 C++ 文件本身不包含任何 JavaScript 代码，它是在 Chromium 的网络层进行底层网络协议测试的。然而，它的功能直接影响到 web 浏览器中 JavaScript 发起的网络请求的行为：

*   **QUIC 协议支持:**  JavaScript 通过浏览器提供的 Web API（例如 `fetch` 或 `XMLHttpRequest`）发起网络请求时，浏览器底层可能会使用 QUIC 协议来传输数据。这个测试文件确保了在各种场景下，QUIC 协议的实现能够正确处理这些请求。
*   **协议协商和回退:**  JavaScript 代码通常不关心底层使用的具体协议。浏览器会根据服务器的支持情况自动选择合适的协议（例如，优先选择 QUIC，如果不可用则回退到 HTTP/2 或 HTTP/1.1）。这个测试文件验证了这种协议协商和回退机制在涉及到 QUIC 时的正确性。
*   **WebSocket:** JavaScript 可以使用 WebSocket API 建立持久的双向通信连接。这个测试文件确保了在 QUIC 环境下，WebSocket 连接能够正确建立，并且不会错误地尝试在 QUIC 连接上升级协议。

**JavaScript 举例说明:**

假设一个网页的 JavaScript 代码使用 `fetch` API 发起一个请求：

```javascript
fetch('https://mail.example.org/')
  .then(response => response.text())
  .then(data => console.log(data));
```

这个测试文件中的 `DataStream` 测试就验证了当浏览器决定使用 QUIC 来处理这个 `fetch` 请求时，底层 C++ 代码能够正确地发送请求并接收到来自 `mail.example.org` 的响应数据。

再比如，一个 JavaScript 代码尝试建立 WebSocket 连接：

```javascript
const websocket = new WebSocket('wss://mail.example.org/');

websocket.onopen = function(event) {
  console.log("WebSocket connection opened");
  websocket.send("Hello, server!");
};

websocket.onmessage = function(event) {
  console.log("Message from server:", event.data);
};
```

`WebsocketOpensNewConnectionWithHttp1` 等测试就保证了即使浏览器已经和 `mail.example.org` 建有 QUIC 连接，新的 WebSocket 连接也会使用标准的 HTTP/1.1 升级握手过程，而不是错误地尝试在 QUIC 上进行。

**逻辑推理和假设输入/输出:**

以 `AllowHTTP1FalseProhibitsH1` 测试为例：

*   **假设输入:**
    *   一个 `HttpNetworkTransaction` 对象被创建，目标 URL 支持 QUIC。
    *   请求的 `upload_data_stream` 被设置为 `UploadDataStreamNotAllowHTTP1`，明确禁止使用 HTTP/1。
    *   没有可用的 QUIC 连接，或者 QUIC 连接建立过程存在延迟。
*   **逻辑推理:** 由于请求明确禁止使用 HTTP/1，且 QUIC 连接可能暂时不可用，`HttpNetworkTransaction` 应该直接返回一个错误，指示需要使用 HTTP/2 或 QUIC。
*   **预期输出:** `trans.Start()` 方法返回 `ERR_IO_PENDING`，回调函数最终接收到的结果是 `ERR_H2_OR_QUIC_REQUIRED`。

以 `RetryOnHttp3GoAway` 测试为例：

*   **假设输入:**
    *   客户端发起两个并发的 HTTP/3 请求到服务器。
    *   服务器处理完第一个请求后，发送一个 HTTP/3 GOAWAY 帧，指示第二个请求（及其之后的请求）没有被处理。
*   **逻辑推理:**  客户端应该能够识别 GOAWAY 帧，并判断第二个请求可以安全地在新的连接上重试。
*   **预期输出:**
    *   第一个请求在原始连接上成功完成。
    *   第二个请求会在一个新的 QUIC 连接上重新发起并成功完成。

**用户或编程常见的使用错误:**

*   **错误地假设 WebSocket 可以直接在 QUIC 上升级:**  开发者可能会错误地认为，如果浏览器和服务器之间已经存在 QUIC 连接，那么 WebSocket 连接就可以直接在这个连接上升级。这个测试文件 (`WebsocketOpensNewConnectionWithHttp1` 等) 表明事实并非如此，WebSocket 握手仍然需要通过 HTTP/1.1 的 Upgrade 机制。如果开发者没有考虑到这一点，可能会导致 WebSocket 连接建立失败。
*   **没有正确处理协议回退:**  开发者编写的网络应用可能依赖于特定的协议特性。如果 QUIC 不可用，浏览器可能会回退到 HTTP/2 或 HTTP/1.1。开发者需要确保应用能够兼容这些不同的协议，或者在必要时进行特性检测。
*   **服务端错误配置 GOAWAY 帧:**  服务端在实现 HTTP/3 时，如果错误地配置了 GOAWAY 帧的流 ID，可能会导致客户端错误地关闭连接，影响用户体验。`IncorrectHttp3GoAway` 测试就是为了确保客户端能够正确处理这种情况。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在使用 Chrome 浏览器访问一个支持 QUIC 的网站 `https://mail.example.org/`，并且这个网站的某些资源加载非常慢或者失败了。以下是一些可能的调试步骤，可能会涉及到这个测试文件覆盖的代码：

1. **打开 Chrome 的开发者工具 (DevTools)。**
2. **切换到 "Network" (网络) 面板。**
3. **刷新页面，观察网络请求。**
4. **查看请求的 "Protocol" (协议) 列。** 如果显示 "h3" 或 "quic"，则表明该请求使用了 QUIC 协议。
5. **如果请求失败，查看 "Status" (状态) 列和 "Timing" (时间) 选项卡。**  这可以提供关于连接建立、TLS 握手、发送请求和接收响应等阶段的信息。
6. **如果怀疑是 QUIC 相关的问题，可以尝试禁用 QUIC 协议来排除故障。**  在 Chrome 地址栏输入 `chrome://flags/#enable-quic`，将 "Experimental QUIC protocol" 设置为 "Disabled"，然后重启浏览器。如果禁用 QUIC 后问题消失，则可能意味着 QUIC 实现存在问题。
7. **如果需要更深入的调试，可以启用 Chrome 的 NetLog 功能。**  在地址栏输入 `chrome://net-export/`，记录网络日志，然后分析日志文件。NetLog 中会包含更详细的 QUIC 连接事件和错误信息，这可以帮助定位问题是在哪个阶段发生的（例如，连接建立失败、数据传输错误、GOAWAY 帧处理等）。

当 Chromium 的开发者进行 QUIC 协议的开发和调试时，`quic_network_transaction_unittest.cc` 文件中的测试用例可以帮助他们验证代码的正确性。例如，如果开发者修改了处理 GOAWAY 帧的逻辑，他们会运行 `IncorrectHttp3GoAway` 和 `RetryOnHttp3GoAway` 测试来确保修改没有引入新的 bug。

**功能归纳 (作为第 12 部分，共 13 部分):**

考虑到这是测试套件的第 12 部分，并且总共有 13 部分，可以推断出这部分测试主要集中在 **`HttpNetworkTransaction` 与 QUIC 协议的复杂交互场景和错误处理**。前面的部分可能已经涵盖了更基础的 QUIC 连接和请求处理，而这一部分深入探讨了诸如协议回退、错误帧处理、与 WebSocket 的交互等更高级或边界情况。这部分测试的目标是确保 `HttpNetworkTransaction` 在各种复杂的 QUIC 使用场景下都能表现出正确的行为，包括优雅地处理错误和与其他网络协议的协同工作。

Prompt: 
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共13部分，请归纳一下它的功能

"""
ataProvider(&ssl_data_);
  SSLSocketDataProvider ssl_data2(ASYNC, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data2);

  CreateSession();

  request_.url = GURL("http://mail.example.org/");
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  RunTransaction(&trans);
  CheckResponseData(&trans, kRespData);

  const SchemefulSite kSite1(GURL("http://origin1/"));
  request_.network_isolation_key = NetworkIsolationKey(kSite1, kSite1);
  request_.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session_.get());
  RunTransaction(&trans2);
  CheckResponseData(&trans2, kRespData);

  EXPECT_TRUE(mock_quic_data[0]->AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data[0]->AllWriteDataConsumed());
  EXPECT_TRUE(mock_quic_data[1]->AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data[1]->AllWriteDataConsumed());
}

TEST_P(QuicNetworkTransactionTest, AllowHTTP1FalseProhibitsH1) {
  MockRead http_reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING),
                           MockRead(ASYNC, OK)};
  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  request_.method = "POST";
  UploadDataStreamNotAllowHTTP1 upload_data("");
  request_.upload_data_stream = &upload_data;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_H2_OR_QUIC_REQUIRED));
}

// Confirm mock class UploadDataStreamNotAllowHTTP1 can upload content over
// QUIC.
TEST_P(QuicNetworkTransactionTest, AllowHTTP1MockTest) {
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data(version_);
  int write_packet_index = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(write_packet_index++));
  const std::string kUploadContent = "foo";
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersAndDataFramesPacket(
          write_packet_index++, GetNthClientInitiatedBidirectionalStreamId(0),
          true, DEFAULT_PRIORITY, GetRequestHeaders("POST", "https", "/"),
          nullptr, {ConstructDataFrame(kUploadContent)}));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));

  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));

  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(write_packet_index++, 2, 1));

  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  request_.method = "POST";
  UploadDataStreamNotAllowHTTP1 upload_data(kUploadContent);
  request_.upload_data_stream = &upload_data;

  SendRequestAndExpectQuicResponse(kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, AllowHTTP1UploadPauseAndResume) {
  FLAGS_quic_enable_chaos_protection = false;
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data(version_);
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Hanging read
  int write_packet_index = 1;
  mock_quic_data.AddWrite(
      ASYNC, client_maker_->MakeDummyCHLOPacket(write_packet_index++));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(write_packet_index++));
  const std::string kUploadContent = "foo";
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersAndDataFramesPacket(
          write_packet_index++, GetNthClientInitiatedBidirectionalStreamId(0),
          true, DEFAULT_PRIORITY, GetRequestHeaders("POST", "https", "/"),
          nullptr, {ConstructDataFrame(kUploadContent)}));
  mock_quic_data.AddRead(
      SYNCHRONOUS, ConstructServerResponseHeadersPacket(
                       1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                       GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      SYNCHRONOUS, ConstructServerDataPacket(
                       2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                       ConstructDataFrame(kQuicRespData)));

  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(write_packet_index++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);
  SequencedSocketData* socket_data = mock_quic_data.GetSequencedSocketData();

  CreateSession();

  AddQuicAlternateProtocolMapping(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  // Set up request.
  request_.method = "POST";
  UploadDataStreamNotAllowHTTP1 upload_data(kUploadContent);
  request_.upload_data_stream = &upload_data;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();
  // Resume QUIC job
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  socket_data->Resume();

  base::RunLoop().RunUntilIdle();
  CheckResponseData(&trans, kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, AllowHTTP1UploadFailH1AndResumeQuic) {
  FLAGS_quic_enable_chaos_protection = false;
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  // This test confirms failed main job should not bother quic job.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead("1.1 Body"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};
  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Hanging read
  int write_packet_index = 1;
  mock_quic_data.AddWrite(
      ASYNC, client_maker_->MakeDummyCHLOPacket(write_packet_index++));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(write_packet_index++));
  const std::string kUploadContent = "foo";
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersAndDataFramesPacket(
          write_packet_index++, GetNthClientInitiatedBidirectionalStreamId(0),
          true, DEFAULT_PRIORITY, GetRequestHeaders("POST", "https", "/"),
          nullptr, {ConstructDataFrame(kUploadContent)}));
  mock_quic_data.AddRead(
      SYNCHRONOUS, ConstructServerResponseHeadersPacket(
                       1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                       GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      SYNCHRONOUS, ConstructServerDataPacket(
                       2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                       ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(write_packet_index++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);
  SequencedSocketData* socket_data = mock_quic_data.GetSequencedSocketData();

  // This packet won't be read because AllowHTTP1:false doesn't allow H/1
  // connection.
  MockRead http_reads2[] = {MockRead("HTTP/1.1 200 OK\r\n")};
  StaticSocketDataProvider http_data2(http_reads2, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data2);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  // Send the first request via TCP and set up alternative service (QUIC) for
  // the origin.
  SendRequestAndExpectHttpResponse("1.1 Body");

  // Settings to resume main H/1 job quickly while pausing quic job.
  AddQuicAlternateProtocolMapping(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);
  ServerNetworkStats stats1;
  stats1.srtt = base::Microseconds(10);
  http_server_properties_->SetServerNetworkStats(
      url::SchemeHostPort(request_.url), NetworkAnonymizationKey(), stats1);

  // Set up request.
  request_.method = "POST";
  UploadDataStreamNotAllowHTTP1 upload_data(kUploadContent);
  request_.upload_data_stream = &upload_data;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Confirm TCP job was resumed.
  // We can not check its failure because HttpStreamFactory::JobController.
  // main_job_net_error is not exposed.
  while (socket_factory_.mock_data().next_index() < 3u) {
    base::RunLoop().RunUntilIdle();
  }
  // Resume QUIC job.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  socket_data->Resume();
  rv = callback.WaitForResult();
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    // This test depends heavily on the internal behavior of
    // HttpStreamFactory's JobController and Jobs, which aren't used when
    // the HappyEyeballsV3 is enabled, and when the HappyEyeballsV3 is enabled
    // we create an HttpStream on HTTP/1.1 for the request. Just check we get
    // an appropriate error.
    EXPECT_THAT(rv, IsError(ERR_H2_OR_QUIC_REQUIRED));
  } else {
    EXPECT_THAT(rv, IsOk());
    CheckResponseData(&trans, kQuicRespData);
  }
}

TEST_P(QuicNetworkTransactionTest, IncorrectHttp3GoAway) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;

  MockQuicData mock_quic_data(version_);
  int write_packet_number = 1;
  mock_quic_data.AddWrite(
      SYNCHRONOUS, ConstructInitialSettingsPacket(write_packet_number++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          write_packet_number++, GetNthClientInitiatedBidirectionalStreamId(0),
          true, GetRequestHeaders("GET", "https", "/")));

  int read_packet_number = 1;
  mock_quic_data.AddRead(
      ASYNC, server_maker_.MakeInitialSettingsPacket(read_packet_number++));
  // The GOAWAY frame sent by the server MUST have a stream ID corresponding to
  // a client-initiated bidirectional stream.  Any other kind of stream ID
  // should cause the client to close the connection.
  quic::GoAwayFrame goaway{3};
  auto goaway_buffer = quic::HttpEncoder::SerializeGoAwayFrame(goaway);
  const quic::QuicStreamId control_stream_id =
      quic::QuicUtils::GetFirstUnidirectionalStreamId(
          version_.transport_version, quic::Perspective::IS_SERVER);
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(read_packet_number++, control_stream_id,
                                       false, goaway_buffer));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckAndConnectionClosePacket(
          write_packet_number++, 2, 4, quic::QUIC_HTTP_GOAWAY_INVALID_STREAM_ID,
          "GOAWAY with invalid stream ID", 0));
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ASYNC_ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));

  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());

  NetErrorDetails details;
  trans.PopulateNetErrorDetails(&details);
  EXPECT_THAT(details.quic_connection_error,
              quic::test::IsError(quic::QUIC_HTTP_GOAWAY_INVALID_STREAM_ID));
}

TEST_P(QuicNetworkTransactionTest, RetryOnHttp3GoAway) {
  MockQuicData mock_quic_data1(version_);
  int write_packet_number1 = 1;
  mock_quic_data1.AddWrite(
      SYNCHRONOUS, ConstructInitialSettingsPacket(write_packet_number1++));
  const quic::QuicStreamId stream_id1 =
      GetNthClientInitiatedBidirectionalStreamId(0);
  mock_quic_data1.AddWrite(SYNCHRONOUS,
                           ConstructClientRequestHeadersPacket(
                               write_packet_number1++, stream_id1, true,
                               GetRequestHeaders("GET", "https", "/")));
  const quic::QuicStreamId stream_id2 =
      GetNthClientInitiatedBidirectionalStreamId(1);
  mock_quic_data1.AddWrite(SYNCHRONOUS,
                           ConstructClientRequestHeadersPacket(
                               write_packet_number1++, stream_id2, true,
                               GetRequestHeaders("GET", "https", "/foo")));

  int read_packet_number1 = 1;
  mock_quic_data1.AddRead(
      ASYNC, server_maker_.MakeInitialSettingsPacket(read_packet_number1++));

  // GOAWAY with stream_id2 informs the client that stream_id2 (and streams with
  // larger IDs) have not been processed and can safely be retried.
  quic::GoAwayFrame goaway{stream_id2};
  auto goaway_buffer = quic::HttpEncoder::SerializeGoAwayFrame(goaway);
  const quic::QuicStreamId control_stream_id =
      quic::QuicUtils::GetFirstUnidirectionalStreamId(
          version_.transport_version, quic::Perspective::IS_SERVER);
  mock_quic_data1.AddRead(
      ASYNC, ConstructServerDataPacket(read_packet_number1++, control_stream_id,
                                       false, goaway_buffer));
  mock_quic_data1.AddWrite(
      ASYNC, ConstructClientAckPacket(write_packet_number1++, 2, 1));

  // Response to first request is accepted after GOAWAY.
  mock_quic_data1.AddRead(ASYNC, ConstructServerResponseHeadersPacket(
                                     read_packet_number1++, stream_id1, false,
                                     GetResponseHeaders("200")));
  const char kRespData1[] = "response on the first connection";
  mock_quic_data1.AddRead(
      ASYNC, ConstructServerDataPacket(read_packet_number1++, stream_id1, true,
                                       ConstructDataFrame(kRespData1)));
  mock_quic_data1.AddWrite(
      ASYNC, ConstructClientAckPacket(write_packet_number1++, 4, 1));
  // Make socket hang to make sure connection stays in connection pool.
  // This should not prevent the retry from opening a new connection.
  mock_quic_data1.AddRead(ASYNC, ERR_IO_PENDING);
  mock_quic_data1.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  mock_quic_data1.AddSocketDataToFactory(&socket_factory_);

  // Second request is retried on a new connection.
  MockQuicData mock_quic_data2(version_);
  QuicTestPacketMaker client_maker2(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true, /*use_priority_header=*/true);
  int write_packet_number2 = 1;
  mock_quic_data2.AddWrite(SYNCHRONOUS, client_maker2.MakeInitialSettingsPacket(
                                            write_packet_number2++));
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
  mock_quic_data2.AddWrite(
      SYNCHRONOUS, client_maker2.MakeRequestHeadersPacket(
                       write_packet_number2++, stream_id1, true, priority,
                       GetRequestHeaders("GET", "https", "/foo"), nullptr));

  QuicTestPacketMaker server_maker2(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), kDefaultServerHostName, quic::Perspective::IS_SERVER,
      /*client_priority_uses_incremental=*/false,
      /*use_priority_header=*/false);
  int read_packet_number2 = 1;
  mock_quic_data2.AddRead(ASYNC, server_maker2.MakeResponseHeadersPacket(
                                     read_packet_number2++, stream_id1, false,
                                     GetResponseHeaders("200"), nullptr));
  const char kRespData2[] = "response on the second connection";
  mock_quic_data2.AddRead(
      ASYNC,
      server_maker2.Packet(read_packet_number2++)
          .AddStreamFrame(stream_id1, true, ConstructDataFrame(kRespData2))
          .Build());
  mock_quic_data2.AddWrite(ASYNC, client_maker2.Packet(write_packet_number2++)
                                      .AddAckFrame(1, 2, 1)
                                      .Build());
  mock_quic_data2.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data2.AddRead(ASYNC, 0);               // EOF
  mock_quic_data2.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback1;
  int rv = trans1.Start(&request_, callback1.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();

  HttpRequestInfo request2;
  request2.method = "GET";
  std::string url("https://");
  url.append(kDefaultServerHostName);
  url.append("/foo");
  request2.url = GURL(url);
  request2.load_flags = 0;
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  CheckResponseData(&trans1, kRespData1);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  CheckResponseData(&trans2, kRespData2);

  mock_quic_data1.Resume();
  mock_quic_data2.Resume();
  EXPECT_TRUE(mock_quic_data1.AllWriteDataConsumed());
  EXPECT_TRUE(mock_quic_data1.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data2.AllWriteDataConsumed());
  EXPECT_TRUE(mock_quic_data2.AllReadDataConsumed());
}

// TODO(yoichio):  Add the TCP job reuse case. See crrev.com/c/2174099.

#if BUILDFLAG(ENABLE_WEBSOCKETS)

// This test verifies that when there is an HTTP/3 connection open to a server,
// a WebSocket request does not use it, but instead opens a new connection with
// HTTP/1.
TEST_P(QuicNetworkTransactionTest, WebsocketOpensNewConnectionWithHttp1) {
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));
  context_.params()->retry_without_alt_svc_on_quic_errors = false;

  MockQuicData mock_quic_data(version_);

  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);

  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));

  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  // The request will initially go out over HTTP/3.
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->MakeRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          priority, GetRequestHeaders("GET", "https", "/"), nullptr));
  mock_quic_data.AddRead(
      ASYNC, server_maker_.MakeResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 server_maker_.GetResponseHeaders("200"), nullptr));
  mock_quic_data.AddRead(
      ASYNC, server_maker_.Packet(2)
                 .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                                 true, ConstructDataFrame(kQuicRespData))
                 .Build());
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read.
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0,
                "GET / HTTP/1.1\r\n"
                "Host: mail.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://mail.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};

  MockRead http_reads[] = {
      MockRead(SYNCHRONOUS, 1,
               "HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};

  SequencedSocketData http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);

  CreateSession();

  TestCompletionCallback callback1;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session_.get());
  int rv = trans1.Start(&request_, callback1.callback(), net_log_with_source_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_EQ(kQuic200RespStatusLine, response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans1, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ(kQuicRespData, response_data);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("wss://mail.example.org/");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(HostPortPair::FromURL(request_.url)
                  .Equals(HostPortPair::FromURL(request2.url)));
  request2.extra_headers.SetHeader("Connection", "Upgrade");
  request2.extra_headers.SetHeader("Upgrade", "websocket");
  request2.extra_headers.SetHeader("Origin", "http://mail.example.org");
  request2.extra_headers.SetHeader("Sec-WebSocket-Version", "13");

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session_.get());
  trans2.SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), net_log_with_source_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  ASSERT_FALSE(mock_quic_data.AllReadDataConsumed());
  mock_quic_data.Resume();
  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

// Much like above, but for Alt-Svc QUIC.
TEST_P(QuicNetworkTransactionTest,
       WebsocketOpensNewConnectionWithHttp1AfterAltSvcQuic) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockWrite http_writes2[] = {
      MockWrite(SYNCHRONOUS, 0,
                "GET / HTTP/1.1\r\n"
                "Host: mail.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://mail.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};

  MockRead http_reads2[] = {
      MockRead(SYNCHRONOUS, 1,
               "HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};

  SequencedSocketData http_data2(http_reads2, http_writes2);
  socket_factory_.AddSocketDataProvider(&http_data2);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("wss://mail.example.org/");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(HostPortPair::FromURL(request_.url)
                  .Equals(HostPortPair::FromURL(request2.url)));
  request2.extra_headers.SetHeader("Connection", "Upgrade");
  request2.extra_headers.SetHeader("Upgrade", "websocket");
  request2.extra_headers.SetHeader("Origin", "http://mail.example.org");
  request2.extra_headers.SetHeader("Sec-WebSocket-Version", "13");

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session_.get());
  trans2.SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback2;
  int rv = trans2.Start(&request2, callback2.callback(), net_log_with_source_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  ASSERT_FALSE(mock_quic_data.AllReadDataConsumed());
  mock_quic_data.Resume();
  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

// Much like above, but for DnsHttpsSvcbAlpn QUIC.
TEST_P(QuicNetworkTransactionTest,
       WebsocketOpensNewConnectionWithHttp1AfterDnsHttpsSvcbAlpn) {
  session_params_.use_dns_https_svcb_alpn = true;

  MockQuicData mock_quic_data(version_);

  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));

  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  // The request will initially go out over HTTP/3.
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->MakeRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          priority, GetRequestHeaders("GET", "https", "/"), nullptr));
  mock_quic_data.AddRead(
      ASYNC, server_maker_.MakeResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 server_maker_.GetResponseHeaders("200"), nullptr));
  mock_quic_data.AddRead(
      ASYNC, server_maker_.Packet(2)
                 .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                                 true, ConstructDataFrame(kQuicRespData))
                 .Build());
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read.
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0,
                "GET / HTTP/1.1\r\n"
                "Host: mail.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://mail.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};

  MockRead http_reads[] = {
      MockRead(SYNCHRONOUS, 1,
               "HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};

  SequencedSocketData http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  HostResolverEndpointResult endpoint_result1;
  endpoint_result1.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoint_result1.metadata.supported_protocol_alpns = {
      quic::QuicVersionLabelToString(quic::CreateQuicVersionLabel(version_))};
  HostResolverEndpointResult endpoint_result2;
  endpoint_result2.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  std::vector<HostResolverEndpointResult> endpoints;
  endpoints.push_back(endpoint_result1);
  endpoints.push_back(endpoint_result2);
  host_resolver_.rules()->AddRule(
      "mail.example.org",
      MockHostResolverBase::RuleResolver::RuleResult(
          std::move(endpoints),
          /*aliases=*/std::set<std::string>{"mail.example.org"}));

  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);
  TestCompletionCallback callback1;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session_.get());
  int rv = trans1.Start(&request_, callback1.callback(), net_log_with_source_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  const HttpResponseInfo* response = tr
"""


```
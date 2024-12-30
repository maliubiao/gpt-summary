Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. They are particularly interested in:

1. **Functionality:** What does this code do?
2. **Relation to JavaScript:** Does it have any connection to JavaScript functionality?
3. **Logic and Input/Output:** Can we infer logic with hypothetical inputs and outputs?
4. **Common User Errors:** What are some common mistakes users or programmers might make related to this code?
5. **Debugging:** How does a user's action lead to this code being executed, serving as a debugging clue?
6. **Summary:** A concise summary of the code's purpose.

Based on the `TEST_F` macros and the names of the test cases (e.g., `TcpFailSync`, `TlsOkAsync`, `ReachedGroupLimit`), it's clear this file contains unit tests for a component related to managing attempts to establish HTTP stream connections. Specifically, the tests seem to focus on:

*   **Connection Success and Failure:** Testing scenarios for successful and failed TCP and TLS connections (both synchronous and asynchronous).
*   **Connection Priority:** How connection priorities are handled.
*   **TLS Handshake:** Testing TLS handshake scenarios, including delays and errors (like certificate errors and client authentication).
*   **Connection Cancellation:** How cancellations are handled.
*   **Happy Eyeballs (IP Endpoint Selection):** Testing the logic for trying different IP endpoints.
*   **Connection Pooling Limits:** Testing the enforcement of per-group and per-pool connection limits.
*   **Connection Reuse (Idle Sockets):** How idle sockets are reused.

**Plan:**

1. **Summarize the core functionality:** The file tests the `HttpStreamPoolAttemptManager`, which manages attempts to create HTTP stream connections.
2. **JavaScript Relation:** Explain that this is backend C++ code and not directly related to JavaScript. Mention that the *results* of these connection attempts might be used by the browser's rendering engine, which interacts with JavaScript, but the C++ code itself is lower-level.
3. **Logical Inference (Example):** Choose a test case (e.g., `TcpFailSync`) and explain the expected input and output.
4. **Common User Errors:**  Think about scenarios where a developer misconfigures networking settings or server behavior that would trigger these error conditions.
5. **User Operation for Debugging:** Consider a basic user action (e.g., navigating to a website) and trace how the network stack might get to this component.
6. **Summarize the provided code snippet:** Focus on the specific test cases in this second part of the file.
这是 `net/http/http_stream_pool_attempt_manager_unittest.cc` 文件的一部分，主要功能是**测试 `HttpStreamPoolAttemptManager` 类的各种场景下的行为**。`HttpStreamPoolAttemptManager` 负责管理尝试建立 HTTP 流连接的过程，包括选择合适的网络协议、处理连接失败、处理连接超时、管理连接优先级、以及与连接池的交互等。

**归纳一下这部分代码的功能：**

这部分代码主要测试了以下 `HttpStreamPoolAttemptManager` 的功能：

*   **连接优先级管理：** 测试在存在多个请求时，高优先级的请求能够抢占资源，优先完成连接。
*   **TCP 连接失败处理：** 测试同步和异步 TCP 连接失败时的处理逻辑，包括错误码的记录。
*   **TLS 连接成功处理：** 测试异步 TLS 连接成功建立的场景。
*   **同步 TCP + 异步 TLS 连接成功处理：** 测试先同步完成 TCP 连接，再异步完成 TLS 握手的场景。
*   **延迟的 TLS 就绪通知：** 测试在 TLS 相关信息（例如 ALPN 协商结果）延迟到达时，连接建立流程的处理。
*   **证书错误处理：** 测试遇到证书错误（如证书过期）时的处理，包括错误码的传递和后续请求的处理。
*   **客户端认证需求处理：** 测试服务器需要客户端证书进行认证时的处理。
*   **客户端认证需求后 TCP 连接失败处理：** 测试在需要客户端认证失败后，后续的 TCP 连接失败是否会被忽略，并返回相同的认证失败错误。
*   **请求在尝试成功前取消：** 测试当请求在连接尝试成功之前被取消时，连接池资源的管理。
*   **单个 IP 端点连接失败：** 测试在多个 IP 端点可用时，其中一个 IP 端点连接失败，尝试连接其他 IP 端点的情况。
*   **IP 端点连接超时：** 测试连接到某个 IP 端点超时时的处理。
*   **多个 IP 端点连接缓慢：** 测试在多个 IP 端点连接速度较慢时，`HttpStreamPoolAttemptManager` 如何管理并发连接尝试。
*   **在 TLS 握手期间暂停慢速定时器：** 测试在 TCP 握手完成后，TLS 握手未完成时，慢速连接尝试定时器的行为。
*   **在空闲 socket 可用后触发慢速定时器：** 测试当存在空闲 socket 时，慢速连接尝试定时器的行为。
*   **通过 Feature Param 设置连接限制：** 测试通过 Feature Param 配置连接池大小和每个组的连接数限制。
*   **达到组连接数限制：** 测试当达到每个组的连接数限制时，新请求的处理，包括等待已有连接释放。
*   **达到连接池总数限制：** 测试当达到连接池总数限制时，新请求的处理，包括进入等待队列。
*   **达到连接池限制时高优先级组优先：** 测试在达到连接池限制时，高优先级的请求组能够优先获得连接资源。
*   **在有空闲 socket 的情况下达到组连接限制：** 测试当存在空闲 socket 时，是否仍然会遵守组连接数限制。
*   **请求使用空闲的 StreamSocket：** (这部分代码未完全展示，但根据上下文，推测是测试请求能够复用连接池中的空闲 socket)。

**它与 JavaScript 的功能关系不大，主要体现在网络请求的底层实现部分。** JavaScript 发起的网络请求（例如通过 `fetch` API 或 `XMLHttpRequest`）最终会由浏览器内核的网络栈处理，而 `HttpStreamPoolAttemptManager` 正是这个网络栈中的一个组件。

**举例说明：**

假设一个 JavaScript 代码发起了一个 HTTPS 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这个请求被发送时，浏览器网络栈会进行以下操作，其中可能涉及到 `HttpStreamPoolAttemptManager`：

1. **查找空闲连接：** 浏览器会首先查看连接池中是否已经存在到 `example.com` 的空闲 HTTPS 连接。
2. **建立新连接（如果需要）：** 如果没有空闲连接，`HttpStreamPoolAttemptManager` 会被调用来尝试建立一个新的连接。这包括：
    *   **DNS 解析：**  解析 `example.com` 的 IP 地址。
    *   **选择 IP 端点：** 如果 DNS 返回多个 IP 地址，`HttpStreamPoolAttemptManager` 会根据策略选择尝试连接的 IP 地址。
    *   **建立 TCP 连接：** 尝试与服务器建立 TCP 连接。`TcpFailSync` 和 `TcpFailAsync` 的测试就覆盖了 TCP 连接失败的情况。
    *   **建立 TLS 连接：** 如果是 HTTPS 请求，会进行 TLS 握手。`TlsOkAsync` 等测试覆盖了 TLS 相关的场景。
    *   **处理连接优先级：** 如果同时有多个请求等待连接，`HttpStreamPoolAttemptManager` 会根据请求的优先级进行处理，如 `SetPriorityCompletesHighestPriorityFirst` 测试所示。
3. **复用连接（如果可能）：** 如果成功建立连接，这个连接会被放入连接池中，以便后续请求复用。

**逻辑推理，给出假设输入与输出：**

**测试用例：** `TcpFailSync`

**假设输入：**

*   一个到 `192.0.2.1` 的 HTTP 请求。
*   `socket_factory()` 被配置为同步返回 `ERR_FAILED` 的连接结果。

**预期输出：**

*   `requester.result()` 将包含 `ERR_FAILED` 错误码。
*   `requester.connection_attempts().size()` 将为 1，表示尝试连接了一次。
*   `requester.connection_attempts()[0].result` 将为 `ERR_FAILED`。

**涉及用户或者编程常见的使用错误，请举例说明：**

*   **网络配置错误：** 用户的网络配置有问题，例如 DNS 服务器配置错误，导致无法解析域名，这可能会触发 `HttpStreamPoolAttemptManager` 进行连接尝试并最终失败。例如，用户配置了一个错误的 DNS 服务器地址，导致域名解析失败，最终请求失败。
*   **服务器不可用：** 用户尝试访问的服务器宕机或者网络不可达，会导致连接尝试失败，这会被 `HttpStreamPoolAttemptManager` 记录。例如，用户尝试访问一个已经关闭的网站。
*   **防火墙阻止连接：** 用户的防火墙或者网络中的防火墙阻止了到目标服务器的连接，会导致连接尝试失败。
*   **HTTPS 证书问题：** 对于 HTTPS 请求，如果服务器的证书无效（过期、自签名、域名不匹配等），会导致 TLS 握手失败，如 `CertificateError` 测试所示。用户可能会看到浏览器提示证书错误。
*   **客户端认证配置错误：** 如果服务器需要客户端证书认证，但用户没有配置或者配置了错误的客户端证书，会导致认证失败，如 `NeedsClientAuth` 测试所示。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在 Chrome 浏览器中访问 `https://example.com`：

1. **用户输入 URL 并按下回车。**
2. **浏览器 UI 进程接收到请求。**
3. **浏览器 UI 进程将请求传递给网络进程。**
4. **网络进程首先进行 DNS 解析，查找 `example.com` 的 IP 地址。**
5. **网络进程的 `HttpStreamFactory` 组件负责创建或复用 HTTP 连接。**
6. **`HttpStreamPool` 管理着已建立的 HTTP 连接。**
7. **如果连接池中没有可用的到 `example.com` 的 HTTPS 连接，`HttpStreamPoolAttemptManager` 会被创建或使用来尝试建立新的连接。**
8. **`HttpStreamPoolAttemptManager` 会根据获取到的 IP 地址尝试建立 TCP 连接。**
9. **如果 `socket_factory()` 被配置为模拟同步 TCP 连接失败 (如 `TcpFailSync` 测试)，那么在这个阶段就会触发相应的测试代码逻辑。**
10. **如果 TCP 连接成功，对于 HTTPS 请求，会进行 TLS 握手。** 如果 TLS 握手过程中出现证书错误，则会触发 `CertificateError` 相关的测试逻辑。

**作为调试线索：** 如果开发者在调试网络连接问题，例如连接失败或者性能问题，他们可能会查看 Chrome 的 `net-internals` (chrome://net-internals/#events) 工具，该工具会记录网络请求的详细事件，包括连接尝试、连接成功、连接失败等信息。这些信息可以帮助开发者定位问题发生在哪个环节，是否与 `HttpStreamPoolAttemptManager` 的行为有关。例如，如果看到连接尝试很快失败并返回特定错误码，可以参考相关的测试用例来理解可能的原因。

希望以上解释能够帮助理解这部分代码的功能。

Prompt: 
```
这是目录为net/http/http_stream_pool_attempt_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共7部分，请归纳一下它的功能

"""
ster2;
  HttpStreamRequest* request2 =
      requester2.set_priority(RequestPriority::IDLE).RequestStream(pool());
  ASSERT_EQ(manager, pool()
                         .GetOrCreateGroupForTesting(requester2.GetStreamKey())
                         .GetAttemptManagerForTesting());
  ASSERT_EQ(endpoint_request->priority(), RequestPriority::LOW);
  ASSERT_EQ(manager->GetPriority(), RequestPriority::LOW);

  // Set the second request's priority to HIGHEST. The corresponding service
  // endpoint request and attempt manager should update their priorities.
  request2->SetPriority(RequestPriority::HIGHEST);
  ASSERT_EQ(endpoint_request->priority(), RequestPriority::HIGHEST);
  ASSERT_EQ(manager->GetPriority(), RequestPriority::HIGHEST);

  // Check `request2` completes first.

  auto data1 = std::make_unique<SequencedSocketData>();
  data1->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data1.get());

  auto data2 = std::make_unique<SequencedSocketData>();
  data2->set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(data2.get());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .set_crypto_ready(true)
      .CallOnServiceEndpointsUpdated();
  ASSERT_EQ(pool().TotalActiveStreamCount(), 2u);
  ASSERT_EQ(request1->GetLoadState(), LOAD_STATE_CONNECTING);
  ASSERT_EQ(request2->GetLoadState(), LOAD_STATE_CONNECTING);

  RunUntilIdle();
  ASSERT_FALSE(request1->completed());
  ASSERT_TRUE(request2->completed());
  ASSERT_EQ(request1->GetLoadState(), LOAD_STATE_CONNECTING);
  ASSERT_EQ(request2->GetLoadState(), LOAD_STATE_IDLE);
  std::unique_ptr<HttpStream> stream = requester2.ReleaseStream();
  ASSERT_TRUE(stream);
}

TEST_F(HttpStreamPoolAttemptManagerTest, TcpFailSync) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  requester.RequestStream(pool());

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(SYNCHRONOUS, ERR_FAILED));
  socket_factory()->AddSocketDataProvider(data.get());

  endpoint_request->add_endpoint(
      ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint());
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_FAILED)));
  ASSERT_EQ(requester.connection_attempts().size(), 1u);
  ASSERT_EQ(requester.connection_attempts()[0].result, ERR_FAILED);
}

TEST_F(HttpStreamPoolAttemptManagerTest, TcpFailAsync) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  requester.RequestStream(pool());

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, ERR_FAILED));
  socket_factory()->AddSocketDataProvider(data.get());

  endpoint_request->add_endpoint(
      ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint());
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_FAILED)));
  ASSERT_EQ(requester.connection_attempts().size(), 1u);
  ASSERT_EQ(requester.connection_attempts()[0].result, ERR_FAILED);
}

TEST_F(HttpStreamPoolAttemptManagerTest, TlsOkAsync) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  auto data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(data.get());
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination("https://a.test").RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, TcpSyncTlsAsyncOk) {
  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory()->AddSocketDataProvider(data.get());
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination("https://a.test").RequestStream(pool());

  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, TlsCryptoReadyDelayed) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  auto data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(data.get());
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  HttpStreamRequest* request =
      requester.set_destination("https://a.test").RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  ASSERT_FALSE(requester.result().has_value());
  ASSERT_EQ(request->GetLoadState(), LOAD_STATE_SSL_HANDSHAKE);

  endpoint_request->set_crypto_ready(true).CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, CertificateError) {
  // Set the per-group limit to one to allow only one attempt.
  constexpr size_t kMaxPerGroup = 1;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  const scoped_refptr<X509Certificate> kCert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");

  auto data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(data.get());
  SSLSocketDataProvider ssl(ASYNC, ERR_CERT_DATE_INVALID);
  ssl.ssl_info.cert_status = ERR_CERT_DATE_INVALID;
  ssl.ssl_info.cert = kCert;
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  constexpr std::string_view kDestination = "https://a.test";
  StreamRequester requester1;
  requester1.set_destination(kDestination).RequestStream(pool());
  StreamRequester requester2;
  requester2.set_destination(kDestination).RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  EXPECT_FALSE(requester1.result().has_value());
  EXPECT_FALSE(requester2.result().has_value());

  endpoint_request->set_crypto_ready(true).CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsError(ERR_CERT_DATE_INVALID)));
  EXPECT_THAT(requester2.result(), Optional(IsError(ERR_CERT_DATE_INVALID)));
  ASSERT_TRUE(
      requester1.cert_error_ssl_info().cert->EqualsIncludingChain(kCert.get()));
  ASSERT_EQ(requester1.connection_attempts().size(), 1u);
  ASSERT_EQ(requester1.connection_attempts()[0].result, ERR_CERT_DATE_INVALID);

  ASSERT_TRUE(
      requester2.cert_error_ssl_info().cert->EqualsIncludingChain(kCert.get()));
  ASSERT_EQ(requester2.connection_attempts().size(), 1u);
  ASSERT_EQ(requester2.connection_attempts()[0].result, ERR_CERT_DATE_INVALID);
}

TEST_F(HttpStreamPoolAttemptManagerTest, NeedsClientAuth) {
  // Set the per-group limit to one to allow only one attempt.
  constexpr size_t kMaxPerGroup = 1;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  const url::SchemeHostPort kDestination(GURL("https://a.test"));

  auto data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(data.get());
  SSLSocketDataProvider ssl(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl.cert_request_info = base::MakeRefCounted<SSLCertRequestInfo>();
  ssl.cert_request_info->host_and_port =
      HostPortPair::FromSchemeHostPort(kDestination);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester1;
  requester1.set_destination(kDestination).RequestStream(pool());
  StreamRequester requester2;
  requester2.set_destination(kDestination).RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  EXPECT_FALSE(requester1.result().has_value());
  EXPECT_FALSE(requester2.result().has_value());

  endpoint_request->set_crypto_ready(true).CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  EXPECT_EQ(requester1.cert_info()->host_and_port,
            HostPortPair::FromSchemeHostPort(kDestination));
  EXPECT_EQ(requester2.cert_info()->host_and_port,
            HostPortPair::FromSchemeHostPort(kDestination));
}

// Tests that after a fatal error (e.g., the server required a client cert),
// following attempt failures are ignored and the existing requests get the
// same fatal error.
TEST_F(HttpStreamPoolAttemptManagerTest, TcpFailAfterNeedsClientAuth) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  const url::SchemeHostPort kDestination(GURL("https://a.test"));

  auto data1 = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(data1.get());
  SSLSocketDataProvider ssl(SYNCHRONOUS, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl.cert_request_info = base::MakeRefCounted<SSLCertRequestInfo>();
  ssl.cert_request_info->host_and_port =
      HostPortPair::FromSchemeHostPort(kDestination);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  auto data2 = std::make_unique<SequencedSocketData>();
  data2->set_connect_data(MockConnect(ASYNC, ERR_FAILED));
  socket_factory()->AddSocketDataProvider(data2.get());

  StreamRequester requester1;
  requester1.set_destination(kDestination).RequestStream(pool());
  StreamRequester requester2;
  requester2.set_destination(kDestination).RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .set_crypto_ready(true)
      .CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  EXPECT_EQ(requester1.cert_info()->host_and_port,
            HostPortPair::FromSchemeHostPort(kDestination));
  EXPECT_EQ(requester2.cert_info()->host_and_port,
            HostPortPair::FromSchemeHostPort(kDestination));
}

TEST_F(HttpStreamPoolAttemptManagerTest, RequestCancelledBeforeAttemptSuccess) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  requester.RequestStream(pool());

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data.get());

  endpoint_request->add_endpoint(
      ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint());
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);

  requester.ResetRequest();
  RunUntilIdle();

  Group& group = pool().GetOrCreateGroupForTesting(requester.GetStreamKey());
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, OneIPEndPointFailed) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  requester.RequestStream(pool());

  auto data1 = std::make_unique<SequencedSocketData>();
  data1->set_connect_data(MockConnect(ASYNC, ERR_FAILED));
  socket_factory()->AddSocketDataProvider(data1.get());
  auto data2 = std::make_unique<SequencedSocketData>();
  data2->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data2.get());

  endpoint_request->add_endpoint(ServiceEndpointBuilder()
                                     .add_v6("2001:db8::1")
                                     .add_v4("192.0.2.1")
                                     .endpoint());
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, IPEndPointTimedout) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  requester.RequestStream(pool());

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(data.get());

  endpoint_request->add_endpoint(
      ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint());
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);
  ASSERT_FALSE(requester.result().has_value());

  FastForwardBy(HttpStreamPool::kConnectionAttemptDelay);
  ASSERT_FALSE(requester.result().has_value());

  FastForwardBy(TcpStreamAttempt::kTcpHandshakeTimeout);
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_TIMED_OUT)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, IPEndPointsSlow) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  HttpStreamRequest* request = requester.RequestStream(pool());

  auto data1 = std::make_unique<SequencedSocketData>();
  // Make the first and the second attempt stalled.
  data1->set_connect_data(MockConnect(ASYNC, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(data1.get());
  auto data2 = std::make_unique<SequencedSocketData>();
  data2->set_connect_data(MockConnect(ASYNC, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(data2.get());
  // The third attempt succeeds.
  auto data3 = std::make_unique<SequencedSocketData>();
  data3->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data3.get());

  endpoint_request->add_endpoint(ServiceEndpointBuilder()
                                     .add_v6("2001:db8::1")
                                     .add_v6("2001:db8::2")
                                     .add_v4("192.0.2.1")
                                     .endpoint());
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  AttemptManager* manager =
      pool()
          .GetOrCreateGroupForTesting(requester.GetStreamKey())
          .GetAttemptManagerForTesting();
  ASSERT_EQ(manager->InFlightAttemptCount(), 1u);
  ASSERT_FALSE(request->completed());

  FastForwardBy(HttpStreamPool::kConnectionAttemptDelay);
  ASSERT_EQ(manager->InFlightAttemptCount(), 2u);
  ASSERT_EQ(manager->PendingJobCount(), 0u);
  ASSERT_FALSE(request->completed());

  // FastForwardBy() executes non-delayed tasks so the request finishes
  // immediately.
  FastForwardBy(HttpStreamPool::kConnectionAttemptDelay);
  ASSERT_TRUE(request->completed());
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       PauseSlowTimerAfterTcpHandshakeForTls) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  requester.set_destination("https://a.test").RequestStream(pool());

  MockConnectCompleter tcp_connect_completer1;
  auto data1 = std::make_unique<SequencedSocketData>();
  data1->set_connect_data(MockConnect(&tcp_connect_completer1));
  socket_factory()->AddSocketDataProvider(data1.get());
  // This TLS handshake never finishes.
  auto ssl1 =
      std::make_unique<SSLSocketDataProvider>(SYNCHRONOUS, ERR_IO_PENDING);
  socket_factory()->AddSSLSocketDataProvider(ssl1.get());

  MockConnectCompleter tcp_connect_completer2;
  auto data2 = std::make_unique<SequencedSocketData>();
  data2->set_connect_data(MockConnect(&tcp_connect_completer2));
  socket_factory()->AddSocketDataProvider(data2.get());
  auto ssl2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(ssl2.get());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder()
                         .add_v6("2001:db8::1")
                         .add_v4("192.0.2.1")
                         .endpoint())
      .set_crypto_ready(false)
      .CallOnServiceEndpointsUpdated();
  AttemptManager* manager =
      pool()
          .GetOrCreateGroupForTesting(requester.GetStreamKey())
          .GetAttemptManagerForTesting();
  ASSERT_EQ(manager->InFlightAttemptCount(), 1u);
  ASSERT_FALSE(requester.result().has_value());

  // Complete TCP handshake after a delay that is less than the connection
  // attempt delay.
  constexpr base::TimeDelta kTcpDelay = base::Milliseconds(30);
  ASSERT_LT(kTcpDelay, HttpStreamPool::kConnectionAttemptDelay);
  FastForwardBy(kTcpDelay);
  tcp_connect_completer1.Complete(OK);
  RunUntilIdle();
  ASSERT_EQ(manager->InFlightAttemptCount(), 1u);

  // Fast-forward to the connection attempt delay. Since the in-flight attempt
  // has completed TCP handshake and is waiting for HTTPS RR, the manager
  // shouldn't start another attempt.
  FastForwardBy(HttpStreamPool::kConnectionAttemptDelay);
  ASSERT_EQ(manager->InFlightAttemptCount(), 1u);

  // Complete DNS resolution fully.
  endpoint_request->set_crypto_ready(true).CallOnServiceEndpointRequestFinished(
      OK);
  ASSERT_EQ(manager->InFlightAttemptCount(), 1u);

  // Fast-forward to the connection attempt delay again. This time the in-flight
  // attempt is still doing TLS handshake, it's treated as slow and the manager
  // should start another attempt.
  FastForwardBy(HttpStreamPool::kConnectionAttemptDelay);
  ASSERT_EQ(manager->InFlightAttemptCount(), 2u);

  // Complete the second attempt. The request should finish successfully.
  tcp_connect_completer2.Complete(OK);
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

// Regression test for crbug.com/368187247. Tests that an idle stream socket
// is reused when an in-flight connection attempt is slow.
TEST_F(HttpStreamPoolAttemptManagerTest,
       SlowTimerFiredAfterIdleSocketAvailable) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  HttpStreamKey stream_key =
      StreamKeyBuilder().set_destination("http://a.test").Build();

  MockConnectCompleter connect_completer;
  SequencedSocketData data;
  data.set_connect_data(MockConnect(&connect_completer));
  socket_factory()->AddSocketDataProvider(&data);

  StreamRequester requester(stream_key);
  requester.RequestStream(pool());
  ASSERT_FALSE(requester.result().has_value());

  // Create an active text-based stream and release it to create an idle stream.
  // The idle stream should be reused for the in-flight request.
  Group& group = pool().GetOrCreateGroupForTesting(stream_key);
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::make_unique<FakeStreamSocket>(),
      StreamSocketHandle::SocketReuseType::kReusedIdle,
      LoadTimingInfo::ConnectTiming());
  stream.reset();
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
  ASSERT_EQ(group.ActiveStreamSocketCount(), 2u);

  // Fire the slow timer. It should not attempt another connection.
  FastForwardBy(HttpStreamPool::kConnectionAttemptDelay);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
  ASSERT_EQ(group.ActiveStreamSocketCount(), 2u);

  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, FeatureParamStreamLimits) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeatureWithParameters(
      features::kHappyEyeballsV3,
      {{std::string(HttpStreamPool::kMaxStreamSocketsPerPoolParamName), "2"},
       {std::string(HttpStreamPool::kMaxStreamSocketsPerGroupParamName), "3"}});
  InitializeSession();
  ASSERT_EQ(pool().max_stream_sockets_per_pool(), 2u);
  ASSERT_EQ(pool().max_stream_sockets_per_group(), 2u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, ReachedGroupLimit) {
  constexpr size_t kMaxPerGroup = 4;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  // Create streams up to the per-group limit for a destination.
  std::vector<std::unique_ptr<StreamRequester>> requesters;
  std::vector<std::unique_ptr<SequencedSocketData>> data_providers;
  for (size_t i = 0; i < kMaxPerGroup; ++i) {
    auto requester = std::make_unique<StreamRequester>();
    StreamRequester* raw_requester = requester.get();
    requesters.emplace_back(std::move(requester));
    raw_requester->RequestStream(pool());

    auto data = std::make_unique<SequencedSocketData>();
    data->set_connect_data(MockConnect(ASYNC, OK));
    socket_factory()->AddSocketDataProvider(data.get());
    data_providers.emplace_back(std::move(data));
  }

  endpoint_request->add_endpoint(
      ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint());
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);

  Group& group =
      pool().GetOrCreateGroupForTesting(requesters[0]->GetStreamKey());
  AttemptManager* manager = group.GetAttemptManagerForTesting();
  ASSERT_EQ(pool().TotalActiveStreamCount(), kMaxPerGroup);
  ASSERT_EQ(group.ActiveStreamSocketCount(), kMaxPerGroup);
  ASSERT_EQ(manager->InFlightAttemptCount(), kMaxPerGroup);
  ASSERT_EQ(manager->PendingJobCount(), 0u);

  // This request should not start an attempt as the group reached its limit.
  StreamRequester stalled_requester;
  HttpStreamRequest* stalled_request = stalled_requester.RequestStream(pool());
  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data.get());
  data_providers.emplace_back(std::move(data));

  ASSERT_EQ(pool().TotalActiveStreamCount(), kMaxPerGroup);
  ASSERT_EQ(group.ActiveStreamSocketCount(), kMaxPerGroup);
  ASSERT_EQ(manager->InFlightAttemptCount(), kMaxPerGroup);
  ASSERT_EQ(manager->PendingJobCount(), 1u);
  ASSERT_EQ(stalled_request->GetLoadState(),
            LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET);

  // Finish all in-flight attempts successfully.
  RunUntilIdle();
  ASSERT_EQ(pool().TotalActiveStreamCount(), kMaxPerGroup);
  ASSERT_EQ(group.ActiveStreamSocketCount(), kMaxPerGroup);
  ASSERT_EQ(manager->InFlightAttemptCount(), 0u);
  ASSERT_EQ(manager->PendingJobCount(), 1u);

  // Release one HttpStream and close it to make non-reusable.
  std::unique_ptr<StreamRequester> released_requester =
      std::move(requesters.back());
  requesters.pop_back();
  std::unique_ptr<HttpStream> released_stream =
      released_requester->ReleaseStream();

  // Need to initialize the HttpStream as HttpBasicStream doesn't disconnect
  // the underlying stream socket when not initialized.
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  released_stream->RegisterRequest(&request_info);
  released_stream->InitializeStream(/*can_send_early=*/false,
                                    RequestPriority::IDLE, NetLogWithSource(),
                                    base::DoNothing());

  released_stream->Close(/*not_reusable=*/true);
  released_stream.reset();

  ASSERT_EQ(pool().TotalActiveStreamCount(), kMaxPerGroup);
  ASSERT_EQ(group.ActiveStreamSocketCount(), kMaxPerGroup);
  ASSERT_EQ(manager->InFlightAttemptCount(), 1u);
  ASSERT_EQ(manager->PendingJobCount(), 0u);

  RunUntilIdle();

  ASSERT_EQ(pool().TotalActiveStreamCount(), kMaxPerGroup);
  ASSERT_EQ(group.ActiveStreamSocketCount(), kMaxPerGroup);
  ASSERT_EQ(manager->InFlightAttemptCount(), 0u);
  ASSERT_EQ(manager->PendingJobCount(), 0u);
  ASSERT_TRUE(stalled_request->completed());
  std::unique_ptr<HttpStream> stream = stalled_requester.ReleaseStream();
  ASSERT_TRUE(stream);
}

TEST_F(HttpStreamPoolAttemptManagerTest, ReachedPoolLimit) {
  constexpr size_t kMaxPerGroup = 2;
  constexpr size_t kMaxPerPool = 3;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);
  pool().set_max_stream_sockets_per_pool_for_testing(kMaxPerPool);

  const HttpStreamKey key_a(url::SchemeHostPort("http", "a.test", 80),
                            PRIVACY_MODE_DISABLED, SocketTag(),
                            NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                            /*disable_cert_network_fetches=*/false);

  const HttpStreamKey key_b(url::SchemeHostPort("http", "b.test", 80),
                            PRIVACY_MODE_DISABLED, SocketTag(),
                            NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                            /*disable_cert_network_fetches=*/false);

  // Create HttpStreams up to the group limit in group A.
  Group& group_a = pool().GetOrCreateGroupForTesting(key_a);
  std::vector<std::unique_ptr<HttpStream>> streams_a;
  for (size_t i = 0; i < kMaxPerGroup; ++i) {
    streams_a.emplace_back(group_a.CreateTextBasedStream(
        std::make_unique<FakeStreamSocket>(),
        StreamSocketHandle::SocketReuseType::kUnused,
        LoadTimingInfo::ConnectTiming()));
  }

  ASSERT_FALSE(pool().ReachedMaxStreamLimit());
  ASSERT_FALSE(pool().IsPoolStalled());
  ASSERT_TRUE(group_a.ReachedMaxStreamLimit());
  ASSERT_EQ(pool().TotalActiveStreamCount(), kMaxPerGroup);
  ASSERT_EQ(group_a.ActiveStreamSocketCount(), kMaxPerGroup);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  // Create a HttpStream in group B. It should not be blocked because both
  // per-group and per-pool limits are not reached yet.
  StreamRequester requester1(key_b);
  HttpStreamRequest* request1 = requester1.RequestStream(pool());
  auto data1 = std::make_unique<SequencedSocketData>();
  data1->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data1.get());

  endpoint_request->add_endpoint(
      ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint());
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();

  ASSERT_TRUE(request1->completed());

  // The pool reached the limit, but it doesn't have any blocked request. Group
  // A reached the group limit. Group B doesn't reach the group limit.
  Group& group_b = pool().GetOrCreateGroupForTesting(key_b);
  ASSERT_TRUE(pool().ReachedMaxStreamLimit());
  ASSERT_FALSE(pool().IsPoolStalled());
  ASSERT_TRUE(group_a.ReachedMaxStreamLimit());
  ASSERT_FALSE(group_b.ReachedMaxStreamLimit());

  // Create another HttpStream in group B. It should be blocked because the pool
  // reached limit, event when group B doesn't reach its limit.
  StreamRequester requester2(key_b);
  HttpStreamRequest* request2 = requester2.RequestStream(pool());
  auto data2 = std::make_unique<SequencedSocketData>();
  data2->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data2.get());
  ASSERT_EQ(request2->GetLoadState(),
            LOAD_STATE_WAITING_FOR_STALLED_SOCKET_POOL);

  RunUntilIdle();
  AttemptManager* manager_b = group_b.GetAttemptManagerForTesting();
  ASSERT_FALSE(request2->completed());
  ASSERT_TRUE(pool().ReachedMaxStreamLimit());
  ASSERT_TRUE(pool().IsPoolStalled());
  ASSERT_EQ(manager_b->InFlightAttemptCount(), 0u);
  ASSERT_EQ(manager_b->PendingJobCount(), 1u);

  // Release one HttpStream from group A. It should unblock the in-flight
  // request in group B.
  std::unique_ptr<HttpStream> released_stream = std::move(streams_a.back());
  streams_a.pop_back();
  released_stream.reset();
  RunUntilIdle();

  ASSERT_TRUE(request2->completed());
  ASSERT_EQ(manager_b->PendingJobCount(), 0u);
  ASSERT_TRUE(pool().ReachedMaxStreamLimit());
  ASSERT_FALSE(pool().IsPoolStalled());
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       ReachedPoolLimitHighPriorityGroupFirst) {
  constexpr size_t kMaxPerGroup = 1;
  constexpr size_t kMaxPerPool = 2;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);
  pool().set_max_stream_sockets_per_pool_for_testing(kMaxPerPool);

  // Create 4 requests with different destinations and priorities.
  constexpr struct Item {
    std::string_view host;
    std::string_view ip_address;
    RequestPriority priority;
  } items[] = {
      {"a.test", "192.0.2.1", RequestPriority::IDLE},
      {"b.test", "192.0.2.2", RequestPriority::IDLE},
      {"c.test", "192.0.2.3", RequestPriority::LOWEST},
      {"d.test", "192.0.2.4", RequestPriority::HIGHEST},
  };

  std::vector<FakeServiceEndpointRequest*> endpoint_requests;
  std::vector<std::unique_ptr<StreamRequester>> requesters;
  std::vector<std::unique_ptr<SequencedSocketData>> socket_datas;
  for (const auto& [host, ip_address, priority] : items) {
    FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
    endpoint_request->add_endpoint(
        ServiceEndpointBuilder().add_v4(ip_address).endpoint());
    endpoint_requests.emplace_back(endpoint_request);

    auto requester = std::make_unique<StreamRequester>();
    requester->set_destination(url::SchemeHostPort("http", host, 80))
        .set_priority(priority);
    requesters.emplace_back(std::move(requester));

    auto data = std::make_unique<SequencedSocketData>();
    data->set_connect_data(MockConnect(ASYNC, OK));
    socket_factory()->AddSocketDataProvider(data.get());
    socket_datas.emplace_back(std::move(data));
  }

  // Complete the first two requests to reach the pool's limit.
  for (size_t i = 0; i < kMaxPerPool; ++i) {
    HttpStreamRequest* request = requesters[i]->RequestStream(pool());
    endpoint_requests[i]->CallOnServiceEndpointRequestFinished(OK);
    RunUntilIdle();
    ASSERT_TRUE(request->completed());
  }

  ASSERT_TRUE(pool().ReachedMaxStreamLimit());

  // Start the remaining requests. These requests should be blocked.
  HttpStreamRequest* request_c = requesters[2]->RequestStream(pool());
  endpoint_requests[2]->CallOnServiceEndpointRequestFinished(OK);

  HttpStreamRequest* request_d = requesters[3]->RequestStream(pool());
  endpoint_requests[3]->CallOnServiceEndpointRequestFinished(OK);

  RunUntilIdle();

  ASSERT_FALSE(request_c->completed());
  ASSERT_FALSE(request_d->completed());

  // Release the HttpStream from group A. It should unblock group D, which has
  // higher priority than group C.
  std::unique_ptr<HttpStream> stream_a = requesters[0]->ReleaseStream();
  stream_a.reset();

  RunUntilIdle();

  ASSERT_FALSE(request_c->completed());
  ASSERT_TRUE(request_d->completed());

  // Release the HttpStream from group B. It should unblock group C.
  std::unique_ptr<HttpStream> stream_b = requesters[1]->ReleaseStream();
  stream_b.reset();

  RunUntilIdle();

  ASSERT_TRUE(request_c->completed());
}

// Regression test for crbug.com/368164182. Tests that the per-group limit is
// respected when there is an idle stream socket.
TEST_F(HttpStreamPoolAttemptManagerTest,
       ReachedPerGroupLimitWithIdleStreamSocket) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  HttpStreamKey stream_key =
      StreamKeyBuilder().set_destination("http://a.test").Build();

  Group& group = pool().GetOrCreateGroupForTesting(stream_key);

  // Create an active text-based stream and release it to create an idle stream.
  std::unique_ptr<HttpStream> stream = group.CreateTextBasedStream(
      std::make_unique<FakeStreamSocket>(),
      StreamSocketHandle::SocketReuseType::kReusedIdle,
      LoadTimingInfo::ConnectTiming());
  stream.reset();

  // Create requests up to the per-group limit + 1. Active stream counts for the
  // group should not exceed the per-group limit.
  std::vector<std::unique_ptr<StreamRequester>> requesters;
  std::vector<std::unique_ptr<SequencedSocketData>> datas;
  for (size_t i = 0; i < pool().max_stream_sockets_per_group() + 1; ++i) {
    auto data = std::make_unique<SequencedSocketData>();
    data->set_connect_data(MockConnect(ASYNC, OK));
    socket_factory()->AddSocketDataProvider(data.get());
    datas.emplace_back(std::move(data));

    auto requester = std::make_unique<StreamRequester>(stream_key);
    StreamRequester* raw_requester = requester.get();
    requesters.emplace_back(std::move(requester));
    raw_requester->RequestStream(pool());
    ASSERT_FALSE(raw_requester->result().has_value());
    ASSERT_LE(group.ActiveStreamSocketCount(),
              pool().max_stream_sockets_per_group());
  }

  for (const auto& requester : requesters) {
    requester->WaitForResult();
    EXPECT_THAT(requester->result(), Optional(IsOk()));
    // Release the stream to unblock other requests.
    requester->ReleaseStream();
  }
}

TEST_F(HttpStreamPoolAttemptManagerTest, RequestStreamIdleStreamSocket) {
  StreamRequester requester;
  Group& group = pool().GetOr
"""


```
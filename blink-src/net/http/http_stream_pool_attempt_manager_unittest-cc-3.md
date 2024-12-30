Response:
The user wants a summary of the provided C++ code, specifically focusing on its functionality, relationship to JavaScript (if any), logical reasoning with input/output examples, common usage errors, debugging steps, and a high-level overview. This is part 4 of a 7-part series.

Here's a breakdown of the thought process to generate the answer:

1. **Understand the Context:** The code is a unit test file (`*_unittest.cc`) for `HttpStreamPoolAttemptManager` in Chromium's network stack. This means it tests the behavior of this manager under various scenarios.

2. **Identify Key Functionality:** The test cases revolve around managing attempts to establish HTTP/1.1 and HTTP/2 connections, including connection reuse (IP-based pooling), pre-connection, and throttling. The core functionality seems to be about efficiently and correctly managing connection attempts to avoid unnecessary resource usage and improve performance.

3. **Scan for Core Concepts:** Look for repeated patterns and terms: `HttpStreamPoolAttemptManager`, `StreamRequester`, `Preconnector`, `FakeServiceEndpointRequest`, `SpdySession`, `IPEndPoint`, `MockWrite`, `MockRead`, `SequencedSocketData`, `SSLSocketDataProvider`, `RunUntilIdle()`, `EXPECT_THAT()`, `ASSERT_TRUE()`, etc. These are the building blocks of the tests.

4. **Group Test Cases by Functionality:**  The tests can be broadly grouped as follows:
    * **Spdy (HTTP/2) Connection Reuse:** Tests related to finding and reusing existing HTTP/2 sessions based on IP addresses.
    * **Spdy Preconnect:** Tests specifically targeting the pre-connection mechanism for HTTP/2.
    * **Spdy Connection Throttling:** Tests focusing on limiting the number of concurrent HTTP/2 connection attempts.
    * **HTTP/1.1 and HTTP/2 Preconnect:** Tests for pre-connecting HTTP/1.1 and HTTP/2 connections, including handling multiple concurrent pre-connects and failures.
    * **Handling Failures:** Tests related to how the manager behaves when connection attempts fail.
    * **Prioritization:** Tests how the manager handles prioritization, particularly for pre-connects.

5. **Analyze Individual Test Cases:** For each test case, understand:
    * **Setup:** What initial conditions are being created (e.g., existing sessions, fake DNS responses)?
    * **Action:** What action is being tested (e.g., requesting a stream, pre-connecting)?
    * **Assertion:** What is being checked to verify the correct behavior (e.g., the result of the request, the number of active streams)?

6. **Look for JavaScript Relevance:** The code is C++ and directly part of Chromium's network stack. It manages the underlying connection establishment. JavaScript in a browser interacts with these connections through higher-level APIs (like `fetch` or `XMLHttpRequest`). The connection is *indirect*. Example: A JavaScript `fetch` request might trigger the code being tested when a new connection is needed or an existing one can be reused.

7. **Develop Logical Reasoning Examples:** Choose a representative test case and create a simplified scenario:
    * **Input:** Describe the state before the action (e.g., a request for "example.test" with an existing connection to the same IP).
    * **Output:** Describe the expected outcome (e.g., the existing connection is reused).

8. **Identify Potential User/Programming Errors:** Think about how developers might misuse the underlying mechanisms or what common issues arise in network programming:
    * Not handling connection failures.
    * Incorrectly configuring connection parameters.
    * Over-aggressively pre-connecting without understanding the limits.

9. **Trace User Actions (Debugging):**  Consider a scenario where a user experiences a connection problem:
    * **Steps:** Describe the user actions (typing a URL, clicking a link).
    * **Reaching the Code:** Explain how those actions lead to the network stack and potentially involve the `HttpStreamPoolAttemptManager`.

10. **Synthesize a Summary:** Combine the understanding of the different test cases into a concise overview of the file's purpose.

11. **Address Part 4 of 7:** Explicitly mention that this analysis covers the functionality demonstrated in *this specific part* of the larger test file.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the technical details of each test case.
* **Correction:** Shift focus to the higher-level *purpose* and *functionality* being tested by these cases, making it more understandable for a broader audience.
* **Initial thought:**  Try to find direct JavaScript code within the C++ file.
* **Correction:** Recognize the separation of concerns and focus on the *indirect* relationship through browser APIs.
* **Initial thought:**  Provide very specific input/output based on internal data structures.
* **Correction:**  Abstract the input/output to be more user-centric and easier to grasp.

By following these steps, the detailed and informative answer can be generated.
这是文件 `net/http/http_stream_pool_attempt_manager_unittest.cc` 的第四部分，主要集中在测试 `HttpStreamPoolAttemptManager` 如何处理 **SPDY (HTTP/2) 连接的重用、预连接和连接尝试的节流**，以及一些 **HTTP/1.1 的预连接**场景。

**本部分的功能归纳：**

* **SPDY 连接的 IP 地址匹配重用:** 测试了当请求新的连接时，`HttpStreamPoolAttemptManager` 如何查找并重用与目标主机 IP 地址相同的现有 SPDY 会话。
    * 涵盖了 DNS 解析完成时同步和异步的情况。
    * 测试了禁用 IP 地址匹配重用、会话密钥不匹配以及域名验证失败的情况，在这些情况下不会重用现有会话。
* **SPDY 连接的预连接:** 测试了 `HttpStreamPoolAttemptManager` 如何处理 SPDY 会话的预连接请求。
    * 验证了在已存在匹配 IP 地址的 SPDY 会话时，预连接能够成功。
* **SPDY 连接尝试的节流:** 测试了 `HttpStreamPoolAttemptManager` 如何对同一目标主机的 SPDY 连接尝试进行节流，防止同时发起过多的连接。
    * 测试了延迟一段时间后允许发起新的连接尝试的情况。
* **HTTP/1.1 连接的预连接:**  测试了 `HttpStreamPoolAttemptManager` 如何处理 HTTP/1.1 连接的预连接请求。
    * 包括预连接成功、失败、以及预连接多个连接的情况。
    * 涵盖了当已存在可用连接时，预连接能够直接返回成功的情况。
    * 测试了达到连接数限制的情况。
* **连接失败时的处理:** 测试了在连接尝试失败时，`HttpStreamPoolAttemptManager` 如何处理后续的连接请求和预连接。
* **连接释放时的处理:** 测试了当一个连接正在失败过程中，释放该连接时 `HttpStreamPoolAttemptManager` 的行为。
* **预连接的优先级:** 测试了预连接操作的优先级被设置为 `RequestPriority::IDLE`。

**与 JavaScript 功能的关系 (间接):**

虽然这段 C++ 代码本身不包含 JavaScript，但它直接影响着浏览器中通过 JavaScript 发起的网络请求的性能和效率。

* **`fetch()` API 和 `XMLHttpRequest`:** 当 JavaScript 使用 `fetch()` 或 `XMLHttpRequest` 发起 HTTPS 请求时，Chromium 的网络栈会负责建立连接。`HttpStreamPoolAttemptManager` 的功能，例如 SPDY 会话的重用和预连接，能够显著减少连接建立的时间，从而提高网页加载速度和 API 响应速度，最终提升 JavaScript 应用的性能。
* **Service Workers:** Service Workers 可以拦截网络请求，并可能触发新的请求。`HttpStreamPoolAttemptManager` 在 Service Worker 的上下文中同样发挥作用，优化其发起的连接。

**举例说明:**

假设一个 JavaScript 应用需要从 `https://example.test/data` 获取数据。

1. **首次请求:** 当 JavaScript 首次发起请求时，`HttpStreamPoolAttemptManager` 会尝试为 `example.test` 建立一个新的连接。
2. **后续请求 (SPDY 重用):** 如果稍后 JavaScript 又发起对 `https://example.test/images/logo.png` 的请求，并且 IP 地址与之前的连接相同，`HttpStreamPoolAttemptManager` 很可能重用之前的 SPDY 会话，而无需建立新的 TCP 连接和 TLS 握手，这比重新建立连接要快得多。
3. **预连接:** 如果一个网站预先知道用户可能会访问某些页面（例如通过鼠标悬停在链接上触发预连接），JavaScript 可以指示浏览器进行预连接。`HttpStreamPoolAttemptManager` 会尝试提前建立连接，这样当用户真的点击链接时，连接可能已经建立好，从而实现更快的页面加载。

**逻辑推理 (假设输入与输出):**

**场景:** 用户访问 `https://example.test`，该网站支持 HTTP/2。浏览器之前已经与 `example.test` 的服务器 (假设 IP 为 `2001:db8::1`) 建立了一个 SPDY 会话。

**假设输入 (requester_b):**  一个新的请求，目标是 `https://example.test/api/data`。

**预期输出 (requester_b.result()):**  `Optional(IsOk())`，表示请求成功。

**逻辑推理:** `HttpStreamPoolAttemptManager` 会检查是否存在与 `example.test` 的 IP 地址 `2001:db8::1` 匹配的可用 SPDY 会话。如果存在，则该请求会重用现有的 SPDY 会话，而无需建立新的连接。测试用例 `SpdyPreconnectMatchingIpSession` 和 `SpdyMatchingIpSessionAlreadyHaveSession` 就覆盖了这种场景。

**用户或编程常见的使用错误:**

* **配置错误导致无法重用连接:**  开发者可能会错误地配置 HTTP 头或缓存策略，导致浏览器无法判断是否可以重用现有的连接。例如，设置了 `Cache-Control: no-store` 可能会阻止某些连接的重用优化。
* **过度预连接:**  开发者可能会滥用预连接功能，预连接过多的资源，反而浪费了用户的带宽和客户端资源。
* **依赖特定协议而未做兼容性处理:** 某些代码可能假设总是使用 HTTP/2，但如果服务器不支持，可能会导致连接失败。开发者应该进行适当的协议协商和错误处理。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 `https://example.test` 并按下回车键。**
2. **浏览器解析 URL 并进行 DNS 查询，获取 `example.test` 的 IP 地址。**
3. **浏览器检测到需要建立 HTTPS 连接。**
4. **Chromium 的网络栈开始尝试建立连接。`HttpStreamPoolAttemptManager` 负责管理连接尝试。**
5. **`HttpStreamPoolAttemptManager` 会检查是否已经存在与 `example.test` 的 IP 地址匹配的可用 SPDY 会话。**
6. **如果存在，且满足重用条件（例如会话未关闭、密钥匹配等），则会重用现有会话。**  相关的测试用例就是 `SpdyMatchingIpSessionAlreadyHaveSession`。
7. **如果不存在，则 `HttpStreamPoolAttemptManager` 会创建一个新的连接尝试，涉及到 TCP 握手、TLS 握手以及可能的 HTTP/2 协商。**
8. **如果用户在页面加载过程中点击了另一个链接到同一域名下的页面，`HttpStreamPoolAttemptManager` 会再次尝试重用现有的连接。**

在调试网络连接问题时，开发者可以使用 Chrome 的 **开发者工具 (DevTools)** 的 **Network** 标签来查看请求的详细信息，包括连接是否被重用、使用的协议版本等。如果怀疑是连接重用或预连接的问题，可以查看 `chrome://net-internals/#http_stream_pool` 和 `chrome://net-internals/#spdy` 获取更底层的网络信息。

**总结本部分的功能:**

这部分测试主要关注 `HttpStreamPoolAttemptManager` 在处理 **SPDY (HTTP/2) 连接的优化**方面的功能，包括 **IP 地址匹配的会话重用、预连接以及防止过度并发连接尝试的节流机制**。同时也涉及到一些 **HTTP/1.1 的预连接场景**。这些功能旨在提高网络连接的效率和性能，从而提升用户体验。

Prompt: 
```
这是目录为net/http/http_stream_pool_attempt_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共7部分，请归纳一下它的功能

"""
 Finish the service endpoint resolution. It should create a new SPDY
  // session.
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);
  requester_b.WaitForResult();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));
  ASSERT_TRUE(spdy_session_pool()->FindAvailableSession(
      requester_b.GetStreamKey().CalculateSpdySessionKey(),
      /*enable_ip_based_pooling=*/true, /*is_websocket=*/false,
      NetLogWithSource()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, SpdyPreconnectMatchingIpSession) {
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("2001:db8::1", 443);

  StreamRequester requester_a;
  requester_a.set_destination("https://www.example.org");

  CreateFakeSpdySession(requester_a.GetStreamKey(), kCommonEndPoint);
  requester_a.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_a.result(), Optional(IsOk()));

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector_b("https://example.test");
  preconnector_b.Preconnect(pool());

  endpoint_request
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(preconnector_b.result(), Optional(IsOk()));
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       SpdyMatchingIpSessionAlreadyHaveSession) {
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("2001:db8::1", 443);

  StreamRequester requester_a;
  requester_a.set_destination("https://www.example.org");

  CreateFakeSpdySession(requester_a.GetStreamKey(), kCommonEndPoint);
  requester_a.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_a.result(), Optional(IsOk()));

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester_b;
  requester_b.set_destination("https://example.test").RequestStream(pool());

  // Call both CallOnServiceEndpointsUpdated() and
  // CallOnServiceEndpointRequestFinished() to check existing sessions twice.
  endpoint_request
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CallOnServiceEndpointsUpdated()
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       SpdyMatchingIpSessionDnsResolutionFinishSynchronously) {
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("2001:db8::1", 443);

  StreamRequester requester_a;
  requester_a.set_destination("https://www.example.org");

  CreateFakeSpdySession(requester_a.GetStreamKey(), kCommonEndPoint);
  requester_a.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_a.result(), Optional(IsOk()));

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .set_start_result(OK);

  StreamRequester requester_b;
  requester_b.set_destination("https://example.test").RequestStream(pool());
  ASSERT_FALSE(requester_b.result().has_value());

  RunUntilIdle();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, SpdyMatchingIpSessionDisabled) {
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("192.0.2.1", 443);

  StreamRequester requester_a;
  requester_a.set_destination("https://www.example.org");

  CreateFakeSpdySession(requester_a.GetStreamKey(), kCommonEndPoint);
  requester_a.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_a.result(), Optional(IsOk()));

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(data.get());
  auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  StreamRequester requester_b;
  requester_b.set_destination("https://example.test")
      .set_enable_ip_based_pooling(false)
      .RequestStream(pool());

  endpoint_request
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));
  ASSERT_EQ(pool().TotalActiveStreamCount(), 2u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, SpdyMatchingIpSessionKeyMismatch) {
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("192.0.2.1", 443);

  StreamRequester requester_a;
  // Set privacy mode to make SpdySessionKey different.
  requester_a.set_destination("https://www.example.org")
      .set_privacy_mode(PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS);

  CreateFakeSpdySession(requester_a.GetStreamKey(), kCommonEndPoint);
  requester_a.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_a.result(), Optional(IsOk()));

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(data.get());
  auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  StreamRequester requester_b;
  requester_b.set_destination("https://example.test").RequestStream(pool());

  endpoint_request
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));
  ASSERT_EQ(pool().TotalActiveStreamCount(), 2u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       SpdyMatchingIpSessionVerifyDomainFailed) {
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("192.0.2.1", 443);

  StreamRequester requester_a;
  requester_a.set_destination("https://www.example.org");

  CreateFakeSpdySession(requester_a.GetStreamKey(), kCommonEndPoint);
  requester_a.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_a.result(), Optional(IsOk()));

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(data.get());
  auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  // Use a destination that is not listed in spdy_pooling.pem.
  StreamRequester requester_b;
  requester_b.set_destination("https://non-alternative.test")
      .RequestStream(pool());

  endpoint_request
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));
  ASSERT_EQ(pool().TotalActiveStreamCount(), 2u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       ThrottleAttemptForSpdyBlockSecondAttempt) {
  constexpr std::string_view kDestination = "https://a.test";

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester1;
  requester1.set_destination(kDestination).RequestStream(pool());

  StreamRequester requester2;
  requester2.set_destination(kDestination).RequestStream(pool());

  // Set the destination is known to support HTTP/2.
  HttpStreamKey stream_key = requester1.GetStreamKey();
  http_server_properties()->SetSupportsSpdy(
      stream_key.destination(), stream_key.network_anonymization_key(),
      /*supports_spdy=*/true);

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(data.get());
  auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  // There should be only one in-flight attempt because attempts are throttled.
  Group& group = pool().GetOrCreateGroupForTesting(requester1.GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 1u);

  // This should not enter an infinite loop.
  pool().ProcessPendingRequestsInGroups();

  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       ThrottleAttemptForSpdyDelayPassedHttp2) {
  constexpr std::string_view kDestination = "https://a.test";

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester1;
  requester1.set_destination(kDestination).RequestStream(pool());

  StreamRequester requester2;
  requester2.set_destination(kDestination).RequestStream(pool());

  // Set the destination is known to support HTTP/2.
  HttpStreamKey stream_key = requester1.GetStreamKey();
  http_server_properties()->SetSupportsSpdy(
      stream_key.destination(), stream_key.network_anonymization_key(),
      /*supports_spdy=*/true);

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  MockConnectCompleter connect_completer1;
  auto data1 = std::make_unique<SequencedSocketData>(reads, writes);
  data1->set_connect_data(MockConnect(&connect_completer1));
  socket_factory()->AddSocketDataProvider(data1.get());
  auto ssl1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl1->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl1.get());

  MockConnectCompleter connect_completer2;
  auto data2 = std::make_unique<SequencedSocketData>(reads, writes);
  data2->set_connect_data(MockConnect(&connect_completer2));
  socket_factory()->AddSocketDataProvider(data2.get());
  auto ssl2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl2->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl2.get());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  // There should be only one in-flight attempt because attempts are throttled.
  Group& group = pool().GetOrCreateGroupForTesting(requester1.GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 1u);

  FastForwardBy(AttemptManager::kSpdyThrottleDelay);
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 2u);

  connect_completer1.Complete(OK);
  RunUntilIdle();
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 0u);

  EXPECT_THAT(requester1.result(), Optional(IsOk()));
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       ThrottleAttemptForSpdyDelayPassedHttp1) {
  constexpr std::string_view kDestination = "https://a.test";

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester1;
  requester1.set_destination(kDestination).RequestStream(pool());

  StreamRequester requester2;
  requester2.set_destination(kDestination).RequestStream(pool());

  // Set the destination is known to support HTTP/2.
  HttpStreamKey stream_key = requester1.GetStreamKey();
  http_server_properties()->SetSupportsSpdy(
      stream_key.destination(), stream_key.network_anonymization_key(),
      /*supports_spdy=*/true);

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  MockConnectCompleter connect_completer1;
  auto data1 = std::make_unique<SequencedSocketData>(reads, writes);
  data1->set_connect_data(MockConnect(&connect_completer1));
  socket_factory()->AddSocketDataProvider(data1.get());
  auto ssl1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(ssl1.get());

  MockConnectCompleter connect_completer2;
  auto data2 = std::make_unique<SequencedSocketData>(reads, writes);
  data2->set_connect_data(MockConnect(&connect_completer2));
  socket_factory()->AddSocketDataProvider(data2.get());
  auto ssl2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(ssl2.get());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  // There should be only one in-flight attempt because attempts are throttled.
  Group& group = pool().GetOrCreateGroupForTesting(requester1.GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 1u);

  FastForwardBy(AttemptManager::kSpdyThrottleDelay);
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 2u);

  connect_completer1.Complete(OK);
  RunUntilIdle();
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 1u);

  connect_completer2.Complete(OK);
  RunUntilIdle();

  EXPECT_THAT(requester1.result(), Optional(IsOk()));
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectSpdySessionAvailable) {
  Preconnector preconnector("https://a.test");
  CreateFakeSpdySession(preconnector.GetStreamKey());

  int rv = preconnector.Preconnect(pool());
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectActiveStreamsAvailable) {
  Preconnector preconnector("http://a.test");
  Group& group = pool().GetOrCreateGroupForTesting(preconnector.GetStreamKey());
  group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());

  int rv = preconnector.Preconnect(pool());
  EXPECT_THAT(rv, IsOk());
  ASSERT_EQ(group.GetAttemptManagerForTesting(), nullptr);
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectFail) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector("http://a.test");

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, ERR_FAILED));
  socket_factory()->AddSocketDataProvider(data.get());

  int rv = preconnector.Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  Group& group = pool().GetOrCreateGroupForTesting(preconnector.GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 1u);
  ASSERT_FALSE(preconnector.result().has_value());

  RunUntilIdle();
  EXPECT_THAT(*preconnector.result(), IsError(ERR_FAILED));
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectMultipleStreamsHttp1) {
  constexpr size_t kNumStreams = 2;

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector("http://a.test");

  std::vector<std::unique_ptr<SequencedSocketData>> datas;
  for (size_t i = 0; i < kNumStreams; ++i) {
    auto data = std::make_unique<SequencedSocketData>();
    data->set_connect_data(MockConnect(ASYNC, OK));
    socket_factory()->AddSocketDataProvider(data.get());
    datas.emplace_back(std::move(data));
  }

  int rv = preconnector.set_num_streams(kNumStreams).Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  Group& group = pool().GetOrCreateGroupForTesting(preconnector.GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(),
            kNumStreams);
  ASSERT_FALSE(preconnector.result().has_value());

  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsOk()));
  ASSERT_EQ(group.IdleStreamSocketCount(), kNumStreams);
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectMultipleStreamsHttp2) {
  constexpr size_t kNumStreams = 2;

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector("https://a.test");

  HttpStreamKey stream_key = preconnector.GetStreamKey();
  http_server_properties()->SetSupportsSpdy(
      stream_key.destination(), stream_key.network_anonymization_key(),
      /*supports_spdy=*/true);

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(data.get());
  auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  int rv = preconnector.set_num_streams(kNumStreams).Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  Group& group = pool().GetOrCreateGroupForTesting(preconnector.GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 1u);
  ASSERT_FALSE(preconnector.result().has_value());

  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsOk()));
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
  ASSERT_TRUE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), false));
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectRequireHttp1) {
  constexpr size_t kNumStreams = 2;

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector("https://a.test");

  HttpStreamKey stream_key = preconnector.GetStreamKey();
  http_server_properties()->SetHTTP11Required(
      stream_key.destination(), stream_key.network_anonymization_key());

  std::vector<std::unique_ptr<SequencedSocketData>> datas;
  std::vector<std::unique_ptr<SSLSocketDataProvider>> ssls;
  for (size_t i = 0; i < kNumStreams; ++i) {
    auto data = std::make_unique<SequencedSocketData>();
    data->set_connect_data(MockConnect(ASYNC, OK));
    socket_factory()->AddSocketDataProvider(data.get());
    datas.emplace_back(std::move(data));
    auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
    ssl->next_protos_expected_in_ssl_config = {kProtoHTTP11};
    socket_factory()->AddSSLSocketDataProvider(ssl.get());
    ssls.emplace_back(std::move(ssl));
  }

  int rv = preconnector.set_num_streams(kNumStreams).Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  Group& group = pool().GetOrCreateGroupForTesting(preconnector.GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 2u);
  ASSERT_FALSE(preconnector.result().has_value());

  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsOk()));
  ASSERT_EQ(group.IdleStreamSocketCount(), 2u);
  ASSERT_FALSE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), false));
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectMultipleStreamsOkAndFail) {
  constexpr size_t kNumStreams = 2;

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector("http://a.test");

  std::vector<MockConnect> connects = {
      {MockConnect(ASYNC, OK), MockConnect(ASYNC, ERR_FAILED)}};
  std::vector<std::unique_ptr<SequencedSocketData>> datas;
  for (const auto& connect : connects) {
    auto data = std::make_unique<SequencedSocketData>();
    data->set_connect_data(connect);
    socket_factory()->AddSocketDataProvider(data.get());
    datas.emplace_back(std::move(data));
  }

  int rv = preconnector.set_num_streams(kNumStreams).Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  Group& group = pool().GetOrCreateGroupForTesting(preconnector.GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(),
            kNumStreams);
  ASSERT_FALSE(preconnector.result().has_value());

  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsError(ERR_FAILED)));
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectMultipleStreamsFailAndOk) {
  constexpr size_t kNumStreams = 2;

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector("http://a.test");

  std::vector<MockConnect> connects = {
      {MockConnect(ASYNC, ERR_FAILED), MockConnect(ASYNC, OK)}};
  std::vector<std::unique_ptr<SequencedSocketData>> datas;
  for (const auto& connect : connects) {
    auto data = std::make_unique<SequencedSocketData>();
    data->set_connect_data(connect);
    socket_factory()->AddSocketDataProvider(data.get());
    datas.emplace_back(std::move(data));
  }

  int rv = preconnector.set_num_streams(kNumStreams).Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  Group& group = pool().GetOrCreateGroupForTesting(preconnector.GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(),
            kNumStreams);
  ASSERT_FALSE(preconnector.result().has_value());

  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsError(ERR_FAILED)));
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectMultipleRequests) {
  constexpr std::string_view kDestination("http://a.test");

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector1(kDestination);
  Preconnector preconnector2(kDestination);

  MockConnectCompleter completers[2];
  std::vector<MockConnect> connects = {
      {MockConnect(&completers[0]), MockConnect(&completers[1])}};
  std::vector<std::unique_ptr<SequencedSocketData>> datas;
  for (const auto& connect : connects) {
    auto data = std::make_unique<SequencedSocketData>();
    data->set_connect_data(connect);
    socket_factory()->AddSocketDataProvider(data.get());
    datas.emplace_back(std::move(data));
  }

  int rv = preconnector1.set_num_streams(1).Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = preconnector2.set_num_streams(2).Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  ASSERT_FALSE(preconnector1.result().has_value());
  ASSERT_FALSE(preconnector2.result().has_value());

  completers[0].Complete(OK);
  RunUntilIdle();
  ASSERT_TRUE(preconnector1.result().has_value());
  EXPECT_THAT(*preconnector1.result(), IsOk());
  ASSERT_FALSE(preconnector2.result().has_value());

  completers[1].Complete(OK);
  RunUntilIdle();
  EXPECT_THAT(preconnector2.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectReachedGroupLimit) {
  constexpr size_t kMaxPerGroup = 1;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);

  constexpr size_t kNumStreams = 2;

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector("http://a.test");

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data.get());

  int rv = preconnector.set_num_streams(kNumStreams).Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  Group& group = pool().GetOrCreateGroupForTesting(preconnector.GetStreamKey());
  EXPECT_THAT(preconnector.result(),
              Optional(IsError(ERR_PRECONNECT_MAX_SOCKET_LIMIT)));
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectReachedPoolLimit) {
  constexpr size_t kMaxPerGroup = 1;
  constexpr size_t kMaxPerPool = 2;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);
  pool().set_max_stream_sockets_per_pool_for_testing(kMaxPerPool);

  constexpr size_t kNumStreams = 2;

  auto key_a = StreamKeyBuilder("http://a.test").Build();
  pool().GetOrCreateGroupForTesting(key_a).CreateTextBasedStream(
      std::make_unique<FakeStreamSocket>(),
      StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  Preconnector preconnector_b("http://b.test");

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data.get());

  int rv = preconnector_b.set_num_streams(kNumStreams).Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  Group& group_b =
      pool().GetOrCreateGroupForTesting(preconnector_b.GetStreamKey());
  EXPECT_THAT(preconnector_b.result(),
              Optional(IsError(ERR_PRECONNECT_MAX_SOCKET_LIMIT)));
  ASSERT_EQ(group_b.IdleStreamSocketCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       RequestStreamAndPreconnectWhileFailing) {
  constexpr std::string_view kDestination = "http://a.test";

  // Add two fake DNS resolutions (one for failing case, another is for success
  // case).
  for (size_t i = 0; i < 2; ++i) {
    FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
    endpoint_request
        ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
        .set_start_result(OK);
  }

  auto failed_data = std::make_unique<SequencedSocketData>();
  failed_data->set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_RESET));
  socket_factory()->AddSocketDataProvider(failed_data.get());

  auto success_data = std::make_unique<SequencedSocketData>();
  success_data->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(success_data.get());

  StreamRequester requester1;
  requester1.set_destination(kDestination).RequestStream(pool());

  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsError(ERR_CONNECTION_RESET)));

  // The first request isn't destroyed yet so the failing attempt manager is
  // still alive. A request that comes during a failure also fails.
  StreamRequester requester2;
  requester2.set_destination(kDestination).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester2.result(), Optional(IsError(ERR_CONNECTION_RESET)));

  // Preconnect fails too.
  Preconnector preconnector1(kDestination);
  EXPECT_THAT(preconnector1.Preconnect(pool()), IsError(ERR_CONNECTION_RESET));

  // Destroy failed requests. This should destroy the failing attempt manager.
  requester1.ResetRequest();
  requester2.ResetRequest();

  // Request a stream again. This time server is happy to accept the connection.
  StreamRequester requester3;
  requester3.set_destination(kDestination).RequestStream(pool());

  RunUntilIdle();
  EXPECT_THAT(requester3.result(), Optional(IsOk()));

  Preconnector preconnector2(kDestination);
  EXPECT_THAT(preconnector2.Preconnect(pool()), IsOk());
}

TEST_F(HttpStreamPoolAttemptManagerTest, ReleaseStreamWhileFailing) {
  constexpr std::string_view kDestination = "http://a.test";

  SequencedSocketData data1;
  data1.set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(&data1);

  SequencedSocketData data2;
  data2.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  socket_factory()->AddSocketDataProvider(&data2);

  // Add two fake DNS resolutions (one for success case, another is for failure
  // case).
  for (size_t i = 0; i < 2; ++i) {
    resolver()
        ->AddFakeRequest()
        ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
        .CompleteStartSynchronously(OK);
  }

  // Create an active HttpStream.
  StreamRequester requester1;
  requester1.set_destination(kDestination).RequestStream(pool());
  requester1.WaitForResult();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));

  std::unique_ptr<HttpStream> stream1 = requester1.ReleaseStream();
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream1->RegisterRequest(&request_info);
  stream1->InitializeStream(/*can_send_early=*/false, RequestPriority::IDLE,
                            NetLogWithSource(), base::DoNothing());

  // Request the second stream. The request fails. The corresponding manager
  // becomes the failing state.
  StreamRequester requester2;
  requester2.set_destination(kDestination).RequestStream(pool());
  requester2.WaitForResult();
  EXPECT_THAT(requester2.result(), Optional(IsError(ERR_CONNECTION_REFUSED)));

  // Release the HttpStream. The manager should not do anything since it's
  // failing and requests are still alive.
  stream1.reset();

  // Reset the requests. The manager should complete.
  HttpStreamKey stream_key = requester1.GetStreamKey();
  requester1.ResetRequest();
  requester2.ResetRequest();
  ASSERT_FALSE(pool()
                   .GetOrCreateGroupForTesting(stream_key)
                   .GetAttemptManagerForTesting());
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectPriority) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);
  auto data_a = std::make_unique<SequencedSocketData>();
  data_a->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data_a.get());

  Preconnector preconnector("https://a.test");
  int rv = preconnector.Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(pool()
                .GetOrCreateGroupForTesting(preconnector.GetStreamKey())
                .GetAttemptManagerForTesting()
                ->GetPriority(),
            RequestPriority::IDLE);
}

// Tests that when an AttemptManager is failing, it's not treated as stalled.
TEST_F(HttpStreamPoolAttemptManagerTest, FailingIsNotStalled) {
  constexpr std::string_view kDestinationA = "http://a.test";
  constexpr std::string_view kDestinationB = "http://b.test";

  // For destination A. This fails.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);
  auto data_a = std::make_unique<SequencedSocketData>();
  data_a->set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_RESET));
  socket_factory()->AddSocketDataProvider(data_a.get());

  // For destination B. This succeeds.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);
  auto data_b = std::make_unique<SequencedSocketData>();
  data_b->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data_b.get());

  StreamRequester requester_a;
  requester_a.set_destination(kDestinationA).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_a.result(), Optional(IsError(ERR_CONNECTION_RESET)));

  StreamRequester requester_b;
  
"""


```
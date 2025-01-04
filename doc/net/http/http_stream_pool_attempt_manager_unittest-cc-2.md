Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for Chromium's network stack. The file `http_stream_pool_attempt_manager_unittest.cc` tests the `HttpStreamPoolAttemptManager` class.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the core class under test:** The filename clearly indicates that the primary focus is the `HttpStreamPoolAttemptManager`.

2. **Recognize the nature of the code:** The `TEST_F` macros signify that this is a unit test file using Google Test. Each `TEST_F` function represents a specific test case.

3. **Infer the purpose of the tested class:** Based on the name `HttpStreamPoolAttemptManager`, it likely manages attempts to establish HTTP stream connections within a pool. This involves handling connection limits, reusing existing connections, and managing connection attempts.

4. **Analyze individual test cases to understand specific functionalities:** Go through each `TEST_F` function and deduce the feature being tested. Look for keywords like "IgnoreLimits", "UseIdleStreamSocket", "CloseIdleStream", "CancelAttempt", "SSLConfigChanged", "SpdyAvailableSession", etc.

5. **Group related functionalities:**  Notice patterns and categorize the tests. For example, several tests deal with connection limits (group and pool), others with idle socket management, some with SSL configuration changes, and a significant number related to SPDY (HTTP/2).

6. **Summarize the key functionalities:**  Based on the analysis of individual tests, formulate concise descriptions of the main responsibilities of the `HttpStreamPoolAttemptManager`. These should include:
    * Managing attempts to create HTTP stream connections.
    * Pooling and reusing HTTP stream sockets.
    * Enforcing connection limits (per group and globally).
    * Handling idle stream sockets.
    * Managing connections for HTTP/1.1 and HTTP/2 (SPDY).
    * Responding to network changes (IP address change).
    * Reacting to SSL configuration changes.
    * Prioritizing requests.

7. **Address the specific prompts:**

    * **Functionality listing:** Directly list the identified key functionalities.
    * **Relationship with JavaScript:**  Consider how these network stack components relate to web browsers and JavaScript. JavaScript makes HTTP requests, and this code manages the underlying connection details. Provide an example like `fetch()`.
    * **Logical reasoning (input/output):**  For some tests, the input and expected output are implicit in the test setup and assertions. Choose a simple example like the `CreateBasic` test.
    * **User/programming errors:**  Think about common mistakes when dealing with network connections. Examples include exceeding connection limits or not handling network errors.
    * **User operation leading here:** Trace back how a user action in a browser (e.g., clicking a link) triggers a network request, eventually leading to this code being executed.
    * **Overall summary (for part 3 of 7):** Combine the identified functionalities into a concise paragraph that captures the essence of the code's role in managing HTTP connection attempts. Emphasize that it's a piece of the broader connection management process.

8. **Refine and organize the summary:** Ensure the language is clear, concise, and addresses all aspects of the prompt. Structure the information logically with headings and bullet points.

By following these steps, we can systematically analyze the code snippet and generate a comprehensive and accurate summary of its functionality, addressing all the specific requirements of the user's request.
这是Chromium网络栈中 `net/http/http_stream_pool_attempt_manager_unittest.cc` 文件的第三部分，它继续测试 `HttpStreamPoolAttemptManager` 类的功能。 `HttpStreamPoolAttemptManager` 负责管理 HTTP 流连接的尝试，包括连接的建立、复用、以及在各种情况下的管理策略。

**本部分的功能归纳：**

本部分主要测试了 `HttpStreamPoolAttemptManager` 在以下场景下的行为：

* **空闲连接的复用:**  测试在连接释放后，新的请求能否复用这些空闲连接。
* **连接池限制和组限制:** 测试当达到连接池或组的连接数限制时，如何处理新的连接请求，以及 `LOAD_IGNORE_LIMITS` 标志的作用。
* **达到连接池限制时关闭空闲连接:** 测试当连接池达到限制时，为了建立新的连接，是否会关闭其他组的空闲连接。
* **DNS 解析过程中的请求处理:** 测试在 DNS 解析进行中时，`ProcessPendingRequestsInGroups` 方法的行为，避免无限循环。
* **IP 地址变更时的处理:** 测试当网络 IP 地址发生变化时，是否能正确取消正在进行的连接尝试和等待中的请求。
* **SSL 配置变更时的处理:** 测试当 SSL 配置发生变化时，是否会关闭空闲连接，以及已释放但代数过期的连接是否会被加入连接池。
* **针对特定服务器的 SSL 配置变更:** 测试 `OnSSLConfigForServersChanged` 方法是否能正确关闭对应服务器的空闲连接。
* **SPDY (HTTP/2) 会话的可用性和复用:** 测试当存在可用的 SPDY 会话时，新的请求能否直接使用。
* **SPDY 会话的优先级设置:** 测试为将要使用现有 SPDY 会话的请求设置优先级是否会导致崩溃。
* **成功建立 SPDY 会话:** 测试在建立 SPDY 会话后，后续请求是否会复用该会话，并且正在进行的同目标连接尝试会被取消。
* **SPDY 会话建立失败:** 测试 SPDY 会话建立失败时的处理情况。
* **建立 SPDY 会话后强制使用 HTTP/1.1:** 测试在已经建立 SPDY 会话的情况下，如果服务端要求使用 HTTP/1.1，会发生什么，以及 SPDY 会话是否会被标记为不可用。
* **在 HTTP 请求中使用 SPDY 会话的限制:** 测试对于非 HTTPS 的 HTTP 请求，是否会使用已经建立的 SPDY 会话。
* **连接池拥塞时关闭空闲 SPDY 会话:** 测试当连接池达到限制并拥塞时，是否会关闭其他空闲的 SPDY 会话来腾出位置。
* **预连接和强制使用 HTTP/1.1:** 测试在预连接场景下，如果服务端要求使用 HTTP/1.1，预连接是否会失败，以及 SPDY 会话是否会被标记为不可用。
* **SPDY 会话达到连接池限制:** 测试当 SPDY 会话达到连接池限制时，新的请求会被阻塞，直到有 SPDY 会话被关闭。
* **基于 IP 的 SPDY 会话复用:** 测试在支持 IP 地址匹配的 SPDY 会话复用场景下，具有相同 IP 地址的不同域名能否复用同一个 SPDY 会话。
* **基于 IP 的 SPDY 会话在通知前变得不可用:** 测试在基于 IP 地址匹配 SPDY 会话复用时，如果匹配到的 SPDY 会话在通知请求方之前关闭，请求方会如何处理。

**与 Javascript 的关系举例说明：**

虽然此代码是 C++，位于浏览器底层网络栈，但它直接影响着 Javascript 中发起的网络请求的行为。

例如，当 Javascript 使用 `fetch()` API 发起一个 HTTPS 请求时：

```javascript
fetch('https://www.example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. **连接池限制:** 如果 `HttpStreamPoolAttemptManager` 的连接池已经达到了 `kMaxPerPool` 的限制，后续的 `fetch()` 请求可能会被阻塞，直到有连接释放。本部分测试了这种限制的执行情况。
2. **空闲连接复用:**  如果之前已经向 `www.example.com` 发起过请求，并且连接被保持在空闲状态，那么后续的 `fetch()` 请求很可能会复用这个空闲连接，而不是建立新的连接。本部分测试了空闲连接的复用逻辑。
3. **SPDY/HTTP/2:** 如果服务器支持 HTTP/2，并且之前已经和该服务器建立了 HTTP/2 连接，那么 `fetch()` 请求会使用已有的 SPDY 会话，这部分代码测试了 SPDY 会话的建立和复用。
4. **IP 地址变更:** 如果在 `fetch()` 请求进行过程中，用户的网络 IP 地址发生了变化，`HttpStreamPoolAttemptManager` 会取消正在进行的连接尝试，`fetch()` 请求会失败，并可能在 Javascript 中抛出一个网络错误。

**逻辑推理的假设输入与输出：**

**场景：测试达到连接池限制时关闭空闲连接 (`CloseIdleStreamAttemptConnectionReachedPoolLimit`)**

* **假设输入:**
    * 连接池最大连接数 `kMaxPerPool` = 3
    * 每个组最大连接数 `kMaxPerGroup` = 2
    * 存在两个域名 `a.test` 和 `b.test`
    * `a.test` 组已经有 2 个空闲连接（达到组限制）。
    * 向 `b.test` 发起一个请求，建立了一个连接，此时连接池达到上限。
    * 向 `b.test` 发起第二个请求。
* **预期输出:**
    * 第二个请求会触发 `HttpStreamPoolAttemptManager` 关闭 `a.test` 组的一个空闲连接，以便为 `b.test` 建立新的连接。
    * `a.test` 组的空闲连接数变为 1。
    * 第二个请求最终成功建立连接。

**用户或编程常见的使用错误举例说明：**

1. **超过连接池限制:** 用户或程序短时间内向同一域名或多个域名发起大量并发请求，可能导致达到连接池的限制。这会导致新的请求被阻塞，影响用户体验。开发者需要考虑请求的并发量和连接复用策略。
2. **不当的连接管理:** 某些程序可能会长时间持有连接而不释放，即使连接处于空闲状态，这也会占用连接池的资源，导致其他请求无法建立连接。
3. **忽略网络错误:**  例如，IP 地址变更会导致连接被取消，如果 Javascript 代码没有正确处理 `fetch()` API 返回的错误，可能会导致程序逻辑错误或用户体验问题。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户在浏览器地址栏输入 URL 或点击链接。**
2. **浏览器解析 URL，确定目标服务器。**
3. **网络栈开始处理请求，首先会查询是否已经存在到目标服务器的可用连接。**
4. **`HttpStreamPool` 负责管理连接池。**
5. **`HttpStreamPoolAttemptManager` 负责管理建立新连接的尝试。**
6. **如果需要建立新的 HTTP 流连接，`HttpStreamPoolAttemptManager` 会根据连接池的当前状态、连接限制、以及是否存在可复用的连接（包括 SPDY 会话）来决定如何进行连接尝试。**
7.
Prompt: 
```
这是目录为net/http/http_stream_pool_attempt_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共7部分，请归纳一下它的功能

"""
CreateGroupForTesting(requester.GetStreamKey());
  group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());

  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

  HttpStreamRequest* request = requester.RequestStream(pool());
  RunUntilIdle();
  ASSERT_TRUE(request->completed());

  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
}

// Tests that the group and pool limits are ignored when requests set
// LOAD_IGNORE_LIMITS.
TEST_F(HttpStreamPoolAttemptManagerTest, IgnoreLimits) {
  constexpr size_t kMaxPerGroup = 2;
  constexpr size_t kMaxPerPool = 3;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);
  pool().set_max_stream_sockets_per_pool_for_testing(kMaxPerPool);

  std::vector<std::unique_ptr<StreamRequester>> requesters;
  std::vector<std::unique_ptr<SequencedSocketData>> data_providers;

  for (size_t i = 0; i < kMaxPerPool + 1; ++i) {
    auto data = std::make_unique<SequencedSocketData>();
    socket_factory()->AddSocketDataProvider(data.get());
    data_providers.emplace_back(std::move(data));
    resolver()
        ->AddFakeRequest()
        ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
        .CompleteStartSynchronously(OK);
    auto requester = std::make_unique<StreamRequester>();
    requester->set_load_flags(LOAD_IGNORE_LIMITS).RequestStream(pool());
    requester->WaitForResult();
    EXPECT_THAT(requester->result(), Optional(IsOk()));
    requesters.emplace_back(std::move(requester));
  }
}

TEST_F(HttpStreamPoolAttemptManagerTest, UseIdleStreamSocketAfterRelease) {
  StreamRequester requester;
  Group& group = pool().GetOrCreateGroupForTesting(requester.GetStreamKey());

  // Create HttpStreams up to the group's limit.
  std::vector<std::unique_ptr<HttpStream>> streams;
  for (size_t i = 0; i < pool().max_stream_sockets_per_group(); ++i) {
    std::unique_ptr<HttpStream> http_stream = group.CreateTextBasedStream(
        std::make_unique<FakeStreamSocket>(),
        StreamSocketHandle::SocketReuseType::kUnused,
        LoadTimingInfo::ConnectTiming());
    streams.emplace_back(std::move(http_stream));
  }
  ASSERT_EQ(group.ActiveStreamSocketCount(),
            pool().max_stream_sockets_per_group());
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);

  // Request a stream. The request should be blocked.
  resolver()->AddFakeRequest();
  HttpStreamRequest* request = requester.RequestStream(pool());
  RunUntilIdle();
  AttemptManager* manager = group.GetAttemptManagerForTesting();
  ASSERT_FALSE(request->completed());
  ASSERT_EQ(manager->PendingJobCount(), 1u);

  // Release an active HttpStream. The underlying StreamSocket should be used
  // to the pending request.
  std::unique_ptr<HttpStream> released_stream = std::move(streams.back());
  streams.pop_back();

  released_stream.reset();
  requester.WaitForResult();
  ASSERT_TRUE(request->completed());
  ASSERT_EQ(manager->PendingJobCount(), 0u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       CloseIdleStreamAttemptConnectionReachedPoolLimit) {
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

  // Add idle streams up to the group's limit in group A.
  Group& group_a = pool().GetOrCreateGroupForTesting(key_a);
  for (size_t i = 0; i < kMaxPerGroup; ++i) {
    group_a.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());
  }
  ASSERT_EQ(group_a.IdleStreamSocketCount(), 2u);
  ASSERT_FALSE(pool().ReachedMaxStreamLimit());

  // Create an HttpStream in group B. The pool should reach its limit.
  Group& group_b = pool().GetOrCreateGroupForTesting(key_b);
  std::unique_ptr<HttpStream> stream1 = group_b.CreateTextBasedStream(
      std::make_unique<FakeStreamSocket>(),
      StreamSocketHandle::SocketReuseType::kUnused,
      LoadTimingInfo::ConnectTiming());
  ASSERT_TRUE(pool().ReachedMaxStreamLimit());

  // Request a stream in group B. The request should close an idle stream in
  // group A.
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  StreamRequester requester;
  HttpStreamRequest* request = requester.RequestStream(pool());
  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data.get());

  endpoint_request->add_endpoint(
      ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint());
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();

  ASSERT_TRUE(request->completed());
  ASSERT_EQ(group_a.IdleStreamSocketCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       ProcessPendingRequestDnsResolutionOngoing) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  auto data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(data.get());

  StreamRequester requester;
  requester.RequestStream(pool());
  ASSERT_FALSE(requester.result().has_value());

  // This should not enter an infinite loop.
  pool().ProcessPendingRequestsInGroups();

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

// Tests that all in-flight requests and connection attempts are canceled
// when an IP address change event happens.
TEST_F(HttpStreamPoolAttemptManagerTest,
       CancelAttemptAndRequestsOnIPAddressChange) {
  FakeServiceEndpointRequest* endpoint_request1 = resolver()->AddFakeRequest();
  FakeServiceEndpointRequest* endpoint_request2 = resolver()->AddFakeRequest();

  auto data1 = std::make_unique<SequencedSocketData>();
  data1->set_connect_data(MockConnect(ASYNC, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(data1.get());

  auto data2 = std::make_unique<SequencedSocketData>();
  data2->set_connect_data(MockConnect(ASYNC, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(data2.get());

  StreamRequester requester1;
  requester1.set_destination("https://a.test").RequestStream(pool());

  StreamRequester requester2;
  requester2.set_destination("https://b.test").RequestStream(pool());

  endpoint_request1->add_endpoint(
      ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint());
  endpoint_request1->CallOnServiceEndpointRequestFinished(OK);
  endpoint_request2->add_endpoint(
      ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint());
  endpoint_request2->CallOnServiceEndpointRequestFinished(OK);

  AttemptManager* manager1 =
      pool()
          .GetOrCreateGroupForTesting(requester1.GetStreamKey())
          .GetAttemptManagerForTesting();
  AttemptManager* manager2 =
      pool()
          .GetOrCreateGroupForTesting(requester2.GetStreamKey())
          .GetAttemptManagerForTesting();
  ASSERT_EQ(manager1->JobCount(), 1u);
  ASSERT_EQ(manager1->InFlightAttemptCount(), 1u);
  ASSERT_EQ(manager2->JobCount(), 1u);
  ASSERT_EQ(manager2->InFlightAttemptCount(), 1u);

  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  RunUntilIdle();
  ASSERT_EQ(manager1->JobCount(), 0u);
  ASSERT_EQ(manager1->InFlightAttemptCount(), 0u);
  ASSERT_EQ(manager2->JobCount(), 0u);
  ASSERT_EQ(manager2->InFlightAttemptCount(), 0u);
  EXPECT_THAT(requester1.result(), Optional(IsError(ERR_NETWORK_CHANGED)));
  EXPECT_THAT(requester2.result(), Optional(IsError(ERR_NETWORK_CHANGED)));
}

// Tests that the network change error is reported even when a different error
// has already happened.
TEST_F(HttpStreamPoolAttemptManagerTest, IPAddressChangeAfterNeedsClientAuth) {
  // Set the per-group limit to one to allow only one attempt.
  constexpr size_t kMaxPerGroup = 1;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  const url::SchemeHostPort kDestination(GURL("https://a.test"));

  auto data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(data.get());
  SSLSocketDataProvider ssl(SYNCHRONOUS, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
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
      .set_crypto_ready(true)
      .CallOnServiceEndpointsUpdated();
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  RunUntilIdle();
  EXPECT_THAT(requester1.result(),
              Optional(IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED)));
  EXPECT_THAT(requester2.result(), Optional(IsError(ERR_NETWORK_CHANGED)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, SSLConfigChangedCloseIdleStream) {
  StreamRequester requester;
  requester.set_destination("https://a.test");
  Group& group = pool().GetOrCreateGroupForTesting(requester.GetStreamKey());
  group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());
  ASSERT_EQ(group.IdleStreamSocketCount(), 1u);

  ssl_config_service()->NotifySSLContextConfigChange();
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       SSLConfigChangedReleasedStreamGenerationOutdated) {
  StreamRequester requester;
  requester.set_destination("https://a.test");
  Group& group = pool().GetOrCreateGroupForTesting(requester.GetStreamKey());
  std::unique_ptr<HttpStream> stream =
      group.CreateTextBasedStream(std::make_unique<FakeStreamSocket>(),
                                  StreamSocketHandle::SocketReuseType::kUnused,
                                  LoadTimingInfo::ConnectTiming());
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);

  ssl_config_service()->NotifySSLContextConfigChange();
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);

  // Release the HttpStream, the underlying StreamSocket should not be pooled
  // as an idle stream since the generation is different.
  stream.reset();
  ASSERT_FALSE(pool().GetGroupForTesting(requester.GetStreamKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, SSLConfigForServersChanged) {
  // Create idle streams in group A and group B.
  StreamRequester requester_a;
  requester_a.set_destination("https://a.test");
  Group& group_a =
      pool().GetOrCreateGroupForTesting(requester_a.GetStreamKey());
  group_a.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());
  ASSERT_EQ(group_a.IdleStreamSocketCount(), 1u);

  StreamRequester requester_b;
  requester_b.set_destination("https://b.test");
  Group& group_b =
      pool().GetOrCreateGroupForTesting(requester_b.GetStreamKey());
  group_b.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());
  ASSERT_EQ(group_b.IdleStreamSocketCount(), 1u);

  // Simulate an SSLConfigForServers change event for group A. The idle stream
  // in group A should be gone but the idle stream in group B should remain.
  pool().OnSSLConfigForServersChanged({HostPortPair::FromSchemeHostPort(
      requester_a.GetStreamKey().destination())});
  ASSERT_EQ(group_a.IdleStreamSocketCount(), 0u);
  ASSERT_EQ(group_b.IdleStreamSocketCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, SpdyAvailableSession) {
  StreamRequester requester;
  requester.set_destination("https://a.test")
      .set_enable_ip_based_pooling(false);

  CreateFakeSpdySession(requester.GetStreamKey());
  requester.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

// Test that setting the priority for a request that will be served via an
// existing SPDY session doesn't crash the network service.
TEST_F(HttpStreamPoolAttemptManagerTest, ChangePriorityForPooledStreamRequest) {
  StreamRequester requester;
  requester.set_destination("https://a.test");

  CreateFakeSpdySession(requester.GetStreamKey());

  HttpStreamRequest* request = requester.RequestStream(pool());
  request->SetPriority(RequestPriority::HIGHEST);
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  // HttpStream{,Request} don't provide a way to get its priority.
}

TEST_F(HttpStreamPoolAttemptManagerTest, SpdyOk) {
  // Create two requests for the same destination. Once a connection is
  // established and is negotiated to use H2, another connection attempts should
  // be canceled and all requests should receive HttpStreams on top of the
  // SpdySession.

  constexpr size_t kNumRequests = 2;
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  std::vector<std::unique_ptr<SequencedSocketData>> socket_datas;
  std::vector<std::unique_ptr<SSLSocketDataProvider>> ssls;
  std::vector<std::unique_ptr<StreamRequester>> requesters;

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  for (size_t i = 0; i < kNumRequests; ++i) {
    auto data = std::make_unique<SequencedSocketData>(reads, writes);
    socket_factory()->AddSocketDataProvider(data.get());
    socket_datas.emplace_back(std::move(data));
    auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
    ssl->next_proto = NextProto::kProtoHTTP2;
    socket_factory()->AddSSLSocketDataProvider(ssl.get());
    ssls.emplace_back(std::move(ssl));

    auto requester = std::make_unique<StreamRequester>();
    requester->set_destination("https://a.test")
        .set_enable_ip_based_pooling(false)
        .RequestStream(pool());
    requesters.emplace_back(std::move(requester));
  }

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();

  for (auto& requester : requesters) {
    ASSERT_TRUE(requester->result().has_value());
    EXPECT_THAT(requester->result(), Optional(IsOk()));
  }
  Group& group =
      pool().GetOrCreateGroupForTesting(requesters[0]->GetStreamKey());
  ASSERT_EQ(group.GetAttemptManagerForTesting()->InFlightAttemptCount(), 0u);
  ASSERT_EQ(group.IdleStreamSocketCount(), 0u);
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_EQ(pool().TotalConnectingStreamCount(), 0u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, SpdyCreateSessionFail) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  auto data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(data.get());
  auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl->next_proto = NextProto::kProtoHTTP2;
  // Set an invalid ALPS to make SPDY session creation fail.
  ssl->peer_application_settings = "invalid alps";
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  StreamRequester requester;
  requester.set_destination("https://a.test").RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();

  EXPECT_THAT(requester.result(), Optional(IsError(ERR_HTTP2_PROTOCOL_ERROR)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, RequireHttp11AfterSpdySessionCreated) {
  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto h2_data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(h2_data.get());
  auto h2_ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  h2_ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(h2_ssl.get());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination).RequestStream(pool());
  HttpStreamKey stream_key = requester1.GetStreamKey();
  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));
  ASSERT_TRUE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), /*is_websocket=*/false));

  // Disable HTTP/2.
  http_server_properties()->SetHTTP11Required(
      stream_key.destination(), stream_key.network_anonymization_key());
  // At this point, the SPDY session is still available because it becomes
  // unavailable after the next request is made.
  ASSERT_TRUE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), /*is_websocket=*/false));

  // Request a stream again. The second request fails because the first request
  // is still alive and the corresponding attempt manager is still alive. The
  // existing SPDY session should become unavailable.
  StreamRequester requester2;
  requester2.set_destination(kDefaultDestination).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester2.result(), Optional(IsError(ERR_HTTP_1_1_REQUIRED)));
  ASSERT_FALSE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), /*is_websocket=*/false));
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       RequireHttp11AfterSpdySessionCreatedRequestDestroyed) {
  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto h2_data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(h2_data.get());
  auto h2_ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  h2_ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(h2_ssl.get());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination).RequestStream(pool());
  HttpStreamKey stream_key = requester1.GetStreamKey();
  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));
  ASSERT_TRUE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), /*is_websocket=*/false));

  // Disable HTTP/2.
  http_server_properties()->SetHTTP11Required(
      stream_key.destination(), stream_key.network_anonymization_key());
  // At this point, the SPDY session is still available because it becomes
  // unavailable after the next request is made.
  ASSERT_TRUE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), /*is_websocket=*/false));

  // Destroy the first request.
  requester1.ResetRequest();

  // Request a stream again. The second request should succeed using HTTP/1.1.
  // The existing SPDY session should become unavailable.
  auto h1_data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(h1_data.get());
  SSLSocketDataProvider h1_ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&h1_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester2;
  requester2.set_destination(kDefaultDestination).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
  ASSERT_FALSE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), /*is_websocket=*/false));
}

TEST_F(HttpStreamPoolAttemptManagerTest, DoNotUseSpdySessionForHttpRequest) {
  constexpr std::string_view kHttpsDestination = "https://www.example.com";
  constexpr std::string_view kHttpDestination = "http://www.example.com";

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto h2_data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(h2_data.get());
  auto h2_ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  h2_ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(h2_ssl.get());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester_https;
  requester_https.set_destination(kHttpsDestination).RequestStream(pool());
  HttpStreamKey stream_key = requester_https.GetStreamKey();
  RunUntilIdle();
  EXPECT_THAT(requester_https.result(), Optional(IsOk()));
  EXPECT_EQ(requester_https.negotiated_protocol(), NextProto::kProtoHTTP2);
  ASSERT_TRUE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), /*is_websocket=*/false));

  // Request a stream for http (not https). The second request should use
  // HTTP/1.1 and should not use the existing SPDY session.
  auto h1_data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(h1_data.get());
  SSLSocketDataProvider h1_ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&h1_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester_http;
  requester_http.set_destination(kHttpDestination).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_http.result(), Optional(IsOk()));
  EXPECT_NE(requester_http.negotiated_protocol(), NextProto::kProtoHTTP2);
}

TEST_F(HttpStreamPoolAttemptManagerTest, CloseIdleSpdySessionWhenPoolStalled) {
  pool().set_max_stream_sockets_per_group_for_testing(1u);
  pool().set_max_stream_sockets_per_pool_for_testing(1u);

  constexpr std::string_view kDestinationA = "https://a.test";
  constexpr std::string_view kDestinationB = "https://b.test";

  // Create an idle SPDY session for `kDestinationA`. This session should be
  // closed when a request is created for `kDestinationB`.
  const HttpStreamKey stream_key_a =
      StreamKeyBuilder().set_destination(kDestinationA).Build();
  CreateFakeSpdySession(stream_key_a);
  ASSERT_TRUE(spdy_session_pool()->HasAvailableSession(
      stream_key_a.CalculateSpdySessionKey(), /*is_websocket=*/false));

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(data.get());
  auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  StreamRequester requester_b;
  requester_b.set_destination(kDestinationB).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));
  EXPECT_EQ(requester_b.negotiated_protocol(), NextProto::kProtoHTTP2);
  ASSERT_TRUE(spdy_session_pool()->HasAvailableSession(
      requester_b.GetStreamKey().CalculateSpdySessionKey(),
      /*is_websocket=*/false));
  ASSERT_FALSE(spdy_session_pool()->HasAvailableSession(
      stream_key_a.CalculateSpdySessionKey(), /*is_websocket=*/false));
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       PreconnectRequireHttp11AfterSpdySessionCreated) {
  const MockWrite writes[] = {MockWrite(ASYNC, OK, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto h2_data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(h2_data.get());
  auto h2_ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  h2_ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(h2_ssl.get());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  Preconnector preconnector1(kDefaultDestination);
  HttpStreamKey stream_key = preconnector1.GetStreamKey();
  preconnector1.Preconnect(pool());
  RunUntilIdle();
  EXPECT_THAT(preconnector1.result(), Optional(IsOk()));
  ASSERT_TRUE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), /*is_websocket=*/false));

  // Disable HTTP/2.
  http_server_properties()->SetHTTP11Required(
      stream_key.destination(), stream_key.network_anonymization_key());

  // Preconnect again. The existing SPDY session should become unavailable.

  auto h1_data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(h1_data.get());
  SSLSocketDataProvider h1_ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&h1_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  Preconnector preconnector2(kDefaultDestination);
  int rv = preconnector2.Preconnect(pool());
  EXPECT_THAT(rv, IsError(ERR_HTTP_1_1_REQUIRED));
  RunUntilIdle();
  ASSERT_FALSE(spdy_session_pool()->HasAvailableSession(
      stream_key.CalculateSpdySessionKey(), /*is_websocket=*/false));
}

TEST_F(HttpStreamPoolAttemptManagerTest, SpdyReachedPoolLimit) {
  constexpr size_t kMaxPerGroup = 1;
  constexpr size_t kMaxPerPool = 2;
  pool().set_max_stream_sockets_per_group_for_testing(kMaxPerGroup);
  pool().set_max_stream_sockets_per_pool_for_testing(kMaxPerPool);

  // Create SPDY sessions up to the pool limit. Initialize streams to make
  // SPDY sessions active.
  StreamRequester requester_a;
  requester_a.set_destination("https://a.test");
  base::WeakPtr<SpdySession> spdy_session_a = CreateFakeSpdySession(
      requester_a.GetStreamKey(), MakeIPEndPoint("192.0.2.1"));
  requester_a.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_a.result(), Optional(IsOk()));

  std::unique_ptr<HttpStream> stream_a = requester_a.ReleaseStream();
  HttpRequestInfo request_info_a;
  request_info_a.url = GURL("https://a.test");
  request_info_a.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream_a->RegisterRequest(&request_info_a);
  stream_a->InitializeStream(/*can_send_early=*/false, DEFAULT_PRIORITY,
                             NetLogWithSource(), base::DoNothing());

  StreamRequester requester_b;
  requester_b.set_destination("https://b.test");
  CreateFakeSpdySession(requester_b.GetStreamKey(),
                        MakeIPEndPoint("192.0.2.2"));
  requester_b.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));

  std::unique_ptr<HttpStream> stream_b = requester_b.ReleaseStream();
  HttpRequestInfo request_info_b;
  request_info_b.url = GURL("https://b.test");
  request_info_b.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream_b->RegisterRequest(&request_info_b);
  stream_b->InitializeStream(/*can_send_early=*/false, DEFAULT_PRIORITY,
                             NetLogWithSource(), base::DoNothing());

  ASSERT_TRUE(pool().ReachedMaxStreamLimit());
  ASSERT_FALSE(pool().IsPoolStalled());

  // Request a stream in group C. It should be blocked.
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(data.get());
  auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  StreamRequester requester_c;
  requester_c.set_destination("https://c.test").RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  Group& group_c =
      pool().GetOrCreateGroupForTesting(requester_c.GetStreamKey());
  ASSERT_EQ(group_c.GetAttemptManagerForTesting()->PendingJobCount(), 1u);
  ASSERT_TRUE(pool().ReachedMaxStreamLimit());
  ASSERT_TRUE(pool().IsPoolStalled());

  // Close the group A's SPDY session. It should unblock the request in group C.
  spdy_session_a->CloseSessionOnError(ERR_ABORTED,
                                      /*description=*/"for testing");
  RunUntilIdle();
  EXPECT_THAT(requester_c.result(), Optional(IsOk()));
  ASSERT_TRUE(pool().ReachedMaxStreamLimit());
  ASSERT_FALSE(pool().IsPoolStalled());

  // Need to close HttpStreams before finishing this test due to the DCHECK in
  // the destructor of SpdyHttpStream.
  // TODO(crbug.com/346835898): Figure out a way not to rely on this behavior,
  // or fix SpdySessionStream somehow.
  stream_a->Close(/*not_reusable=*/true);
  stream_b->Close(/*not_reusable=*/true);
}

// In the following SPDY IP-based pooling tests, we use spdy_pooling.pem that
// has "www.example.org" and "example.test" as alternate names.

TEST_F(HttpStreamPoolAttemptManagerTest, SpdyMatchingIpSessionOk) {
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

  endpoint_request
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));
  ASSERT_EQ(pool().TotalActiveStreamCount(), 1u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       SpdyMatchingIpSessionBecomeUnavailableBeforeNotify) {
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("2001:db8::1", 443);

  // Add a SpdySession for www.example.org.
  StreamRequester requester_a;
  requester_a.set_destination("https://www.example.org");

  CreateFakeSpdySession(requester_a.GetStreamKey(), kCommonEndPoint);
  requester_a.RequestStream(pool());
  requester_a.WaitForResult();
  EXPECT_THAT(requester_a.result(), Optional(IsOk()));

  // Data for the second request.
  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  auto data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_factory()->AddSocketDataProvider(data.get());
  auto ssl = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl->next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  // Create the second request to example.test. It will finds the matching
  // SPDY session, but the task to use the session runs asynchronously, so it
  // hasn't run yet.
  StreamRequester requester_b;
  requester_b.set_destination("https://example.test").RequestStream(pool());
  endpoint_request
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CallOnServiceEndpointsUpdated();
  ASSERT_FALSE(requester_b.result().has_value());

  // Close the session before the second request can try to use it.
  spdy_session_pool()->CloseAllSessions();

  //
"""


```
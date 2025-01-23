Response:
The user wants to understand the functionality of the C++ source code file `net/http/http_stream_pool_attempt_manager_unittest.cc` in the Chromium project.

Here's a breakdown of the thought process to address the request:

1. **Identify the Core Purpose:** The file name strongly suggests this is a unit test file for `HttpStreamPoolAttemptManager`. Unit tests verify the behavior of a specific class or component in isolation.

2. **Analyze the Test Structure:**  The code consists of multiple `TEST_F` macros. Each `TEST_F` represents an individual test case. The `HttpStreamPoolAttemptManagerTest` likely sets up a test fixture for these tests.

3. **Examine Individual Test Cases:**  Go through each `TEST_F` and try to understand what it's testing. Look for keywords like `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`, and assertions (`ASSERT_THAT`, `ASSERT_EQ`). These indicate the expected outcome of the test. Pay attention to setup code, especially interactions with mock objects (`resolver()`, `socket_factory()`, `quic_session_pool()`).

4. **Group Related Tests:** Notice patterns in the test names. For example, tests involving "Stalled," "SPDY," "QUIC," and "ReuseType" are clearly testing different aspects of the `HttpStreamPoolAttemptManager`.

5. **Infer Functionality from Tests:** Based on the test cases, deduce the responsibilities of `HttpStreamPoolAttemptManager`. For example, tests around "IsStalledByPoolLimit" suggest it manages connection attempts within pool limits. Tests involving SPDY and QUIC show it handles different transport protocols. Tests with "ReuseType" indicate it manages connection reuse.

6. **Look for Relationships with JavaScript:** Since the request specifically asks about JavaScript, consider how networking components in Chromium might interact with the browser's JavaScript engine. This is less likely at this low level, but it's worth considering. The primary interaction would be the initiation of network requests from JavaScript, which eventually leads to these lower-level components.

7. **Address Logical Reasoning (Assumptions/Inputs/Outputs):**  For each test case, think about the assumptions being made (e.g., network conditions, server responses). Identify the "input" (e.g., requesting a stream with specific parameters) and the expected "output" (e.g., a successful connection, a specific error).

8. **Identify Potential User/Programming Errors:**  Think about how developers using the `HttpStreamPool` or related classes might misuse them or encounter errors. Tests that check for specific error conditions can provide clues.

9. **Trace User Actions to the Code:**  Consider the sequence of user actions that could lead to this code being executed. This usually involves the user initiating a network request in the browser.

10. **Synthesize a Summary:** Combine the insights from the individual test cases and the inferred functionality into a concise summary of the file's purpose.

**Applying the Process to the Provided Code Snippet (Part 5):**

* **Initial Scan:** The code continues the pattern of `TEST_F` macros within the `HttpStreamPoolAttemptManagerTest` fixture. It focuses heavily on QUIC functionality.
* **Individual Tests:**
    * `DelayStreamAttemptQuicOk`:  Suggests testing how the attempt manager handles delayed stream attempts when QUIC succeeds.
    * `DelayStreamAttemptQuicFail`:  Likely tests the same scenario but when QUIC fails.
* **Inference:** This part seems to focus on the interaction of the `HttpStreamPoolAttemptManager` with delayed attempts and QUIC connections (both successful and unsuccessful).

**Addressing the Specific Points:**

* **Functionality:**  Testing scenarios where stream attempts are deliberately delayed, specifically when using QUIC. This includes cases where the QUIC connection succeeds and where it fails.
* **JavaScript Relationship:**  JavaScript initiates network requests. If a request uses QUIC and there's a delay in the connection process (simulated in the tests), the behavior being tested here would be relevant. For instance, a JavaScript fetch might experience this delay before either establishing a QUIC connection or falling back to TCP.
* **Logical Reasoning:**
    * **Assumption (for `DelayStreamAttemptQuicOk`):**  A delay is set for waiting jobs. QUIC connection succeeds.
    * **Input:** A stream request for `kDefaultDestination` using QUIC.
    * **Output:** The request completes successfully.
    * **Assumption (for `DelayStreamAttemptQuicFail`):**  A delay is set for waiting jobs. QUIC connection fails.
    * **Input:** A stream request for `kDefaultDestination` using QUIC.
    * **Output:** The request eventually fails, likely falling back to TCP or resulting in an error.
* **User/Programming Errors:** Developers might misconfigure delays or have unexpected network conditions that trigger these delayed attempt scenarios. If QUIC fails after a delay, the application needs to handle the fallback or error gracefully.
* **User Operation as Debugging Clue:**  A user navigating to a website that attempts a QUIC connection but experiences initial delays (due to network conditions or server behavior) could trigger the logic being tested here. Debugging would involve looking at connection timings and whether QUIC attempts were made and their outcomes.
* **Summary of Part 5:** This section tests the behavior of the `HttpStreamPoolAttemptManager` when there's a delay in attempting to establish a network stream, specifically focusing on scenarios involving QUIC, both when QUIC succeeds and when it fails.
好的，让我们来分析一下 `net/http/http_stream_pool_attempt_manager_unittest.cc` 文件的第五部分代码的功能。

**功能归纳 (针对第五部分代码):**

这部分代码主要集中测试 `HttpStreamPoolAttemptManager` 在存在延迟尝试建立连接的情况下的行为，并且特别关注了 QUIC 协议的影响。测试用例覆盖了以下场景：

* **延迟后 QUIC 连接成功：** 测试当设置了延迟后，如果 QUIC 连接能够成功建立，`HttpStreamPoolAttemptManager` 是否能正确处理。
* **延迟后 QUIC 连接失败：** 测试当设置了延迟后，如果 QUIC 连接建立失败，`HttpStreamPoolAttemptManager` 是否能正确处理失败情况，例如是否会回退到 TCP 连接或其他处理。

**与 JavaScript 的关系举例说明:**

当 JavaScript 发起一个网络请求时 (例如使用 `fetch` API)，浏览器底层网络栈会处理这个请求。如果启用了 QUIC 协议，并且服务器支持，浏览器会尝试使用 QUIC 建立连接。

* **延迟后 QUIC 连接成功的情况：**  假设 JavaScript 发起了一个 `fetch('https://example.com')` 请求，并且网络栈决定尝试 QUIC 连接。如果由于某些原因（例如网络条件），QUIC 连接的尝试被延迟了一段时间，但最终成功建立，那么此部分测试代码覆盖了 `HttpStreamPoolAttemptManager` 如何处理这种情况。JavaScript 代码最终会成功获取到 `https://example.com` 的响应，但可能需要比预期更长的时间。

* **延迟后 QUIC 连接失败的情况：**  同样，如果 JavaScript 发起了一个 `fetch('https://example.com')` 请求，并且 QUIC 连接的尝试被延迟，但最终失败（例如连接超时），那么此部分测试代码覆盖了 `HttpStreamPoolAttemptManager` 如何处理。在这种情况下，网络栈可能会回退到使用 TCP 连接来完成请求。JavaScript 代码最终可能会成功获取响应（如果 TCP 连接成功），或者会收到一个网络错误。

**逻辑推理 (假设输入与输出):**

**测试用例: `DelayStreamAttemptQuicOk`**

* **假设输入:**
    * 设置了一个连接尝试延迟 `kDelay` (例如 10 毫秒)。
    * DNS 解析成功返回目标 IP 地址。
    * QUIC 数据模拟器配置为连接成功。
    * 没有提供 TCP 连接的数据模拟器。
    * 发起一个针对 `kDefaultDestination` 的 QUIC 连接请求。
* **预期输出:**
    * 请求成功完成 (`requester.result()` 为 `Optional(IsOk())`)。
    * 由于没有 TCP 数据模拟器，连接应该通过 QUIC 成功建立。

**测试用例: `DelayStreamAttemptQuicFail`**

* **假设输入:**
    * 设置了一个连接尝试延迟 `kDelay`。
    * DNS 解析成功返回目标 IP 地址。
    * QUIC 数据模拟器配置为连接失败 (例如返回 `ERR_CONNECTION_REFUSED`)。
    * 提供了用于 TCP 连接的数据模拟器，模拟 TCP 连接成功。
    * 发起一个针对 `kDefaultDestination` 的 QUIC 连接请求。
* **预期输出:**
    * QUIC 连接尝试失败。
    * `HttpStreamPoolAttemptManager` 应该回退到 TCP 连接。
    * 请求最终通过 TCP 连接成功完成 (`requester.result()` 为 `Optional(IsOk())`)。
    * 协商的协议不是 QUIC (`requester.negotiated_protocol()` 不等于 `NextProto::kProtoQUIC`)。

**用户或编程常见的使用错误:**

* **配置了过长的连接尝试延迟:** 如果开发者或者系统配置了过长的连接尝试延迟，可能会导致用户在网络状况良好时仍然需要等待较长时间才能建立连接。这会影响用户体验。
* **错误地假设 QUIC 总是可用:** 开发者不应该假设 QUIC 连接总是能够成功建立。网络环境复杂，QUIC 可能被防火墙阻止或者服务器不支持。代码应该能优雅地处理 QUIC 连接失败的情况，例如回退到 TCP。
* **没有正确处理 QUIC 连接失败的回调:** 如果应用程序依赖于某些在 QUIC 连接成功时才执行的操作，而没有正确处理 QUIC 连接失败的情况，可能会导致程序行为异常。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:**  例如，用户访问 `https://example.com`。
2. **浏览器解析 URL 并查找 IP 地址:** 浏览器会进行 DNS 查询获取 `example.com` 的 IP 地址。
3. **浏览器网络栈决定尝试建立连接:** 根据协议协商和配置，网络栈可能会尝试使用 QUIC 协议建立连接。
4. **`HttpStreamPool` 管理连接池:** `HttpStreamPool` 负责管理和复用 HTTP 连接。
5. **`HttpStreamPoolAttemptManager` 管理连接尝试:** 对于新的连接请求，`HttpStreamPoolAttemptManager` 负责协调连接尝试，包括可能的延迟尝试。
6. **设置连接尝试延迟 (如果在测试环境中):** 在测试环境中，可能会人为设置连接尝试延迟以模拟特定场景。
7. **QUIC 连接尝试 (可能延迟):**  网络栈尝试使用 QUIC 协议与服务器建立连接。这部分代码测试了当这个尝试被延迟后会发生什么。
8. **QUIC 连接成功或失败:**  QUIC 连接尝试可能成功建立，也可能因为各种原因失败（例如网络错误、服务器不支持）。
9. **`HttpStreamPoolAttemptManager` 根据结果进行处理:**
    * **成功:**  连接被添加到连接池，后续请求可以复用。
    * **失败:**  可能尝试回退到 TCP 连接，或者返回错误。
10. **将结果返回给上层 (例如 `HttpStream`):**  连接建立的结果会返回给负责处理 HTTP 流的对象。
11. **最终传递给 JavaScript (如果请求是由 JavaScript 发起的):**  如果请求是由 JavaScript 的 `fetch` API 发起的，最终结果会通过 Promise 或回调函数传递回 JavaScript 代码。

**总结第五部分的功能:**

总而言之，这部分代码专注于测试 `HttpStreamPoolAttemptManager` 在处理延迟的连接尝试，特别是针对 QUIC 协议时的行为。它验证了在 QUIC 连接延迟后成功和失败的场景下，`HttpStreamPoolAttemptManager` 是否能按照预期工作，例如在 QUIC 失败时能否正确回退到 TCP。这对于保证网络连接的稳定性和性能至关重要。

### 提示词
```
这是目录为net/http/http_stream_pool_attempt_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
requester_b.set_destination(kDestinationB).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester_b.result(), Optional(IsOk()));

  // Release the connection for B. It triggers processing pending requests in
  // group/attemt manager for A. The group/attempt manager for A is still alive
  // because we don't release `requester_a` yet. The group/attempt manager
  // should not be treated as stalled because these are failing.
  requester_b.ReleaseStream().reset();
  EXPECT_FALSE(pool()
                   .GetOrCreateGroupForTesting(requester_a.GetStreamKey())
                   .GetAttemptManagerForTesting()
                   ->IsStalledByPoolLimit());
}

// Tests that when an AttemptManager has a SPDY session, it's not treated as
// stalled.
TEST_F(HttpStreamPoolAttemptManagerTest, HavingSpdySessionIsNotStalled) {
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

  StreamRequester requester;
  requester.set_destination("https://a.test").RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));

  EXPECT_FALSE(pool()
                   .GetOrCreateGroupForTesting(requester.GetStreamKey())
                   .GetAttemptManagerForTesting()
                   ->IsStalledByPoolLimit());
}

// Tests that when an AttemptManager has a QUIC session, it's not treated as
// stalled.
TEST_F(HttpStreamPoolAttemptManagerTest, HavingQuicSessionIsNotStalled) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  AddQuicData();

  // Make the TCP attempt stalled forever.
  SequencedSocketData tcp_data;
  tcp_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));

  EXPECT_FALSE(pool()
                   .GetOrCreateGroupForTesting(requester.GetStreamKey())
                   .GetAttemptManagerForTesting()
                   ->IsStalledByPoolLimit());
}

TEST_F(HttpStreamPoolAttemptManagerTest, ReuseTypeUnused) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data.get());

  StreamRequester requester;
  requester.RequestStream(pool());
  RunUntilIdle();
  ASSERT_THAT(requester.result(), Optional(IsOk()));
  std::unique_ptr<HttpStream> stream = requester.ReleaseStream();
  ASSERT_FALSE(stream->IsConnectionReused());
}

TEST_F(HttpStreamPoolAttemptManagerTest, ReuseTypeUnusedIdle) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data.get());

  // Preconnect to put an idle stream to the pool.
  Preconnector preconnector("http://a.test");
  preconnector.Preconnect(pool());
  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsOk()));
  ASSERT_EQ(pool()
                .GetOrCreateGroupForTesting(preconnector.GetStreamKey())
                .IdleStreamSocketCount(),
            1u);

  StreamRequester requester;
  requester.RequestStream(pool());
  RunUntilIdle();
  ASSERT_THAT(requester.result(), Optional(IsOk()));
  std::unique_ptr<HttpStream> stream = requester.ReleaseStream();
  ASSERT_TRUE(stream->IsConnectionReused());
}

TEST_F(HttpStreamPoolAttemptManagerTest, ReuseTypeReusedIdle) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(ASYNC, OK));
  socket_factory()->AddSocketDataProvider(data.get());

  StreamRequester requester1;
  requester1.RequestStream(pool());
  RunUntilIdle();
  ASSERT_THAT(requester1.result(), Optional(IsOk()));
  std::unique_ptr<HttpStream> stream1 = requester1.ReleaseStream();
  ASSERT_FALSE(stream1->IsConnectionReused());

  // Destroy the stream to make it an idle stream.
  stream1.reset();

  StreamRequester requester2;
  requester2.RequestStream(pool());
  RunUntilIdle();
  ASSERT_THAT(requester2.result(), Optional(IsOk()));
  std::unique_ptr<HttpStream> stream2 = requester2.ReleaseStream();
  ASSERT_TRUE(stream2->IsConnectionReused());
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicOk) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  // Set `is_quic_known_to_work_on_current_network` to false to check the flag
  // is updated to true after the QUIC attempt succeeds.
  quic_session_pool()->set_has_quic_ever_worked_on_current_network(false);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  AddQuicData();

  // Make TCP attempts stalled forever.
  SequencedSocketData tcp_data;
  tcp_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  ASSERT_FALSE(requester.result().has_value());

  // Call both update and finish callbacks to make sure we don't attempt twice
  // for a single endpoint.
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .set_crypto_ready(true)
      .CallOnServiceEndpointsUpdated()
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();

  EXPECT_THAT(requester.result(), Optional(IsOk()));
  EXPECT_THAT(pool()
                  .GetOrCreateGroupForTesting(requester.GetStreamKey())
                  .GetAttemptManagerForTesting()
                  ->GetQuicTaskResultForTesting(),
              Optional(IsOk()));
  EXPECT_TRUE(quic_session_pool()->has_quic_ever_worked_on_current_network());

  std::unique_ptr<HttpStream> stream = requester.ReleaseStream();
  LoadTimingInfo timing_info;
  ASSERT_TRUE(stream->GetLoadTimingInfo(&timing_info));
  ValidateConnectTiming(timing_info.connect_timing);
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicOkSynchronouslyNoTcpAttempt) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);
  AddQuicData();

  // No TCP data is needed because QUIC session attempt succeeds synchronously.

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());

  AttemptManager* manager =
      pool()
          .GetOrCreateGroupForTesting(requester.GetStreamKey())
          .GetAttemptManagerForTesting();
  ASSERT_EQ(manager->InFlightAttemptCount(), 0u);

  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicOkDnsAlpn) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  AddQuicData();

  // Make TCP attempts stalled forever.
  SequencedSocketData tcp_data1;
  tcp_data1.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data1);
  SequencedSocketData tcp_data2;
  tcp_data2.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data2);

  // Create two requests to make sure that one success QUIC session creation
  // completes all on-going requests.
  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination).RequestStream(pool());
  StreamRequester requester2;
  requester2.set_destination(kDefaultDestination).RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder()
                         .add_v4("192.0.2.1")
                         .set_alpns({"h3", "h2"})
                         .endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();

  EXPECT_THAT(requester1.result(), Optional(IsOk()));
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
  EXPECT_THAT(pool()
                  .GetOrCreateGroupForTesting(requester1.GetStreamKey())
                  .GetAttemptManagerForTesting()
                  ->GetQuicTaskResultForTesting(),
              Optional(IsOk()));
}

// Tests that QUIC is not attempted when marked broken.
TEST_F(HttpStreamPoolAttemptManagerTest, QuicBroken) {
  AlternativeService alternative_service(kProtoQUIC, "www.example.org", 443);
  http_server_properties()->MarkAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  EXPECT_NE(requester.negotiated_protocol(), NextProto::kProtoQUIC);
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicFailBeforeTls) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  MockConnectCompleter quic_completer;
  MockQuicData quic_data(quic_version());
  quic_data.AddConnect(&quic_completer);
  quic_data.AddSocketDataToFactory(socket_factory());

  MockConnectCompleter tls_completer;
  SequencedSocketData tls_data;
  tls_data.set_connect_data(MockConnect(&tls_completer));
  socket_factory()->AddSocketDataProvider(&tls_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  ASSERT_FALSE(requester.result().has_value());

  quic_completer.Complete(ERR_CONNECTION_REFUSED);
  // Fast forward to make QUIC attempt fail first.
  FastForwardBy(base::Milliseconds(1));
  EXPECT_THAT(pool()
                  .GetOrCreateGroupForTesting(requester.GetStreamKey())
                  .GetAttemptManagerForTesting()
                  ->GetQuicTaskResultForTesting(),
              Optional(IsError(ERR_CONNECTION_REFUSED)));
  ASSERT_FALSE(requester.result().has_value());

  tls_completer.Complete(ERR_SOCKET_NOT_CONNECTED);

  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_SOCKET_NOT_CONNECTED)));

  // QUIC should not be marked as broken because TLS attempt also failed.
  const AlternativeService alternative_service(
      NextProto::kProtoQUIC,
      HostPortPair::FromSchemeHostPort(requester.GetStreamKey().destination()));
  EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicFailAfterTls) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  MockConnectCompleter quic_completer;
  MockQuicData quic_data(quic_version());
  quic_data.AddConnect(&quic_completer);
  quic_data.AddSocketDataToFactory(socket_factory());

  MockConnectCompleter tls_completer;
  SequencedSocketData tls_data;
  tls_data.set_connect_data(MockConnect(&tls_completer));
  socket_factory()->AddSocketDataProvider(&tls_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  ASSERT_FALSE(requester.result().has_value());

  tls_completer.Complete(ERR_SOCKET_NOT_CONNECTED);
  // Fast forward to make TLS attempt fail first.
  FastForwardBy(base::Milliseconds(1));
  ASSERT_FALSE(requester.result().has_value());

  quic_completer.Complete(ERR_CONNECTION_REFUSED);
  requester.WaitForResult();
  EXPECT_THAT(pool()
                  .GetOrCreateGroupForTesting(requester.GetStreamKey())
                  .GetAttemptManagerForTesting()
                  ->GetQuicTaskResultForTesting(),
              Optional(IsError(ERR_CONNECTION_REFUSED)));
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_CONNECTION_REFUSED)));

  // QUIC should not be marked as broken because TLS attempt also failed.
  const AlternativeService alternative_service(
      NextProto::kProtoQUIC,
      HostPortPair::FromSchemeHostPort(requester.GetStreamKey().destination()));
  EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicFailNonBrokenErrors) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  const int kErrors[] = {ERR_NETWORK_CHANGED, ERR_INTERNET_DISCONNECTED};
  for (const int net_error : kErrors) {
    // Reset HttpServerProperties.
    InitializeSession();

    MockQuicData quic_data(quic_version());
    quic_data.AddConnect(ASYNC, net_error);
    quic_data.AddSocketDataToFactory(socket_factory());

    SequencedSocketData tcp_data;
    socket_factory()->AddSocketDataProvider(&tcp_data);
    SSLSocketDataProvider ssl(ASYNC, OK);
    socket_factory()->AddSSLSocketDataProvider(&ssl);

    resolver()
        ->AddFakeRequest()
        ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
        .CompleteStartSynchronously(OK);

    StreamRequester requester;
    requester.set_destination(kDefaultDestination)
        .set_quic_version(quic_version())
        .RequestStream(pool());
    requester.WaitForResult();
    EXPECT_THAT(requester.result(), Optional(IsOk()));
    EXPECT_NE(requester.negotiated_protocol(), NextProto::kProtoQUIC);

    // QUIC should not be marked as broken because QUIC attempt failed with
    // a protocol independent error.
    const AlternativeService alternative_service(
        NextProto::kProtoQUIC, HostPortPair::FromSchemeHostPort(
                                   requester.GetStreamKey().destination()));
    EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
        alternative_service, NetworkAnonymizationKey()))
        << ErrorToString(net_error);
  }
}

// Test that NetErrorDetails is populated when a QUIC session is created but
// it fails later.
TEST_F(HttpStreamPoolAttemptManagerTest, QuicNetErrorDetails) {
  // QUIC attempt will pause. When resumed, it will fail.
  MockQuicData quic_data(quic_version());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(socket_factory());

  SequencedSocketData tls_data;
  tls_data.set_connect_data(MockConnect(ASYNC, ERR_SOCKET_NOT_CONNECTED));
  socket_factory()->AddSocketDataProvider(&tls_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  crypto_client_stream_factory()->set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());

  // Fast forward to make TLS attempt fail first.
  FastForwardBy(base::Milliseconds(1));
  quic_data.Resume();
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_QUIC_PROTOCOL_ERROR)));
  EXPECT_EQ(requester.net_error_details().quic_connection_error,
            quic::QUIC_PACKET_READ_ERROR);
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicCanUseExistingSession) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  AddQuicData();

  // Make TCP attempts stalled forever.
  SequencedSocketData tcp_data;
  tcp_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data);

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());

  // Invoke the update callback, run tasks, then invoke the finish callback to
  // make sure the finish callback checks the existing session.
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .set_crypto_ready(true)
      .CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  endpoint_request->CallOnServiceEndpointRequestFinished(OK);

  EXPECT_THAT(requester1.result(), Optional(IsOk()));

  // The previous request created a session. This request should use the
  // existing session.
  StreamRequester requester2;
  requester2.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester2.result(), Optional(IsOk()));

  EXPECT_THAT(pool()
                  .GetOrCreateGroupForTesting(requester1.GetStreamKey())
                  .GetAttemptManagerForTesting()
                  ->GetQuicTaskResultForTesting(),
              Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AlternativeSerivcesDisabled) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_enable_alternative_services(false)
      .RequestStream(pool());
  RunUntilIdle();

  EXPECT_THAT(requester.result(), Optional(IsOk()));
  ASSERT_FALSE(pool()
                   .GetOrCreateGroupForTesting(requester.GetStreamKey())
                   .GetAttemptManagerForTesting()
                   ->GetQuicTaskResultForTesting()
                   .has_value());
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       AlternativeSerivcesDisabledQuicSessionExists) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);

  // Prerequisite: Create a QUIC session.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);
  AddQuicData();

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  requester1.WaitForResult();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));

  // Actual test: Request a stream without alternative services.
  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester2;
  requester2.set_destination(kDefaultDestination)
      .set_enable_alternative_services(false)
      .RequestStream(pool());
  requester2.WaitForResult();
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
  EXPECT_NE(requester2.negotiated_protocol(), NextProto::kProtoQUIC);
}

// Tests that QUIC attempt fails when there is no known QUIC version and the
// DNS resolution indicates that the endpoint doesn't support QUIC.
TEST_F(HttpStreamPoolAttemptManagerTest, QuicEndpointNotFoundNoDnsAlpn) {
  // Set that QUIC is working on the current network.
  quic_session_pool()->set_has_quic_ever_worked_on_current_network(true);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic::ParsedQuicVersion::Unsupported())
      .RequestStream(pool());
  RunUntilIdle();

  EXPECT_THAT(requester.result(), Optional(IsOk()));
  EXPECT_THAT(pool()
                  .GetOrCreateGroupForTesting(requester.GetStreamKey())
                  .GetAttemptManagerForTesting()
                  ->GetQuicTaskResultForTesting(),
              Optional(IsError(ERR_DNS_NO_MATCHING_SUPPORTED_ALPN)));
  // No matching ALPN should not update
  // `is_quic_known_to_work_on_current_network()`.
  EXPECT_TRUE(quic_session_pool()->has_quic_ever_worked_on_current_network());

  // QUIC should not be marked as broken.
  const AlternativeService alternative_service(
      NextProto::kProtoQUIC,
      HostPortPair::FromSchemeHostPort(requester.GetStreamKey().destination()));
  EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicPreconnect) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  AddQuicData();

  SequencedSocketData tcp_data1;
  tcp_data1.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data1);
  SequencedSocketData tcp_data2;
  tcp_data2.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data2);

  Preconnector preconnector1(kDefaultDestination);
  preconnector1.set_num_streams(2)
      .set_quic_version(quic_version())
      .Preconnect(pool());
  RunUntilIdle();
  EXPECT_THAT(preconnector1.result(), Optional(IsOk()));

  // This preconnect request should complete immediately because we already have
  // an existing QUIC session.
  Preconnector preconnector2(kDefaultDestination);
  int rv = preconnector2.set_num_streams(1)
               .set_quic_version(quic_version())
               .Preconnect(pool());
  RunUntilIdle();
  EXPECT_THAT(rv, IsOk());
}

// Tests that two destinations that resolve to the same IP address share the
// same QUIC session if allowed.
TEST_F(HttpStreamPoolAttemptManagerTest, QuicMatchingIpSession) {
  constexpr std::string_view kAltDestination = "https://alt.example.org";
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("2001:db8::1", 443);

  AddQuicData();

  // Make the TCP attempt stalled forever.
  SequencedSocketData tcp_data;
  tcp_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data);

  FakeServiceEndpointRequest* endpoint_request1 = resolver()->AddFakeRequest();
  endpoint_request1
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));

  FakeServiceEndpointRequest* endpoint_request2 = resolver()->AddFakeRequest();
  endpoint_request2
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester2;
  requester2.set_destination(kAltDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
  QuicSessionAliasKey quic_key1 =
      requester1.GetStreamKey().CalculateQuicSessionAliasKey();
  QuicSessionAliasKey quic_key2 =
      requester2.GetStreamKey().CalculateQuicSessionAliasKey();
  ASSERT_EQ(quic_session_pool()->FindExistingSession(quic_key1.session_key(),
                                                     quic_key1.destination()),
            quic_session_pool()->FindExistingSession(quic_key2.session_key(),
                                                     quic_key2.destination()));
}

// The same as above test, but the ServiceEndpointRequest provides two IP
// addresses separately, the first address does not match the existing session
// and the second address matches the existing session.
TEST_F(HttpStreamPoolAttemptManagerTest,
       QuicMatchingIpSessionOnEndpointsUpdated) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  constexpr std::string_view kAltDestination = "https://alt.example.org";
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("2001:db8::1", 443);

  AddQuicData();

  // Make the TCP attempt stalled forever.
  SequencedSocketData tcp_data;
  tcp_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data);

  // Make the second QUIC attempt stalled forever.
  SequencedSocketData quic_data2;
  quic_data2.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&quic_data2);

  FakeServiceEndpointRequest* endpoint_request1 = resolver()->AddFakeRequest();
  endpoint_request1
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));

  FakeServiceEndpointRequest* endpoint_request2 = resolver()->AddFakeRequest();

  StreamRequester requester2;
  requester2.set_destination(kAltDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  endpoint_request2
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .set_crypto_ready(true)
      .CallOnServiceEndpointsUpdated();
  ASSERT_FALSE(requester2.result().has_value());

  endpoint_request2
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
  QuicSessionAliasKey quic_key1 =
      requester1.GetStreamKey().CalculateQuicSessionAliasKey();
  QuicSessionAliasKey quic_key2 =
      requester2.GetStreamKey().CalculateQuicSessionAliasKey();
  EXPECT_EQ(quic_session_pool()->FindExistingSession(quic_key1.session_key(),
                                                     quic_key1.destination()),
            quic_session_pool()->FindExistingSession(quic_key2.session_key(),
                                                     quic_key2.destination()));
}

// Tests that preconnect completes when there is a QUIC session of which IP
// address matches to the service endpoint resolution of the preconnect.
TEST_F(HttpStreamPoolAttemptManagerTest, QuicPreconnectMatchingIpSession) {
  constexpr std::string_view kAltDestination = "https://alt.example.org";
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("2001:db8::1", 443);

  AddQuicData();

  // Make the TCP attempt stalled forever.
  SequencedSocketData tcp_data;
  tcp_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data);

  FakeServiceEndpointRequest* endpoint_request1 = resolver()->AddFakeRequest();
  endpoint_request1
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));

  FakeServiceEndpointRequest* endpoint_request2 = resolver()->AddFakeRequest();
  endpoint_request2
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CompleteStartSynchronously(OK);

  Preconnector preconnector2(kAltDestination);
  preconnector2.set_quic_version(quic_version()).Preconnect(pool());
  RunUntilIdle();
  EXPECT_THAT(preconnector2.result(), Optional(IsOk()));
  QuicSessionAliasKey quic_key1 =
      requester1.GetStreamKey().CalculateQuicSessionAliasKey();
  QuicSessionAliasKey quic_key2 =
      preconnector2.GetStreamKey().CalculateQuicSessionAliasKey();
  EXPECT_EQ(quic_session_pool()->FindExistingSession(quic_key1.session_key(),
                                                     quic_key1.destination()),
            quic_session_pool()->FindExistingSession(quic_key2.session_key(),
                                                     quic_key2.destination()));
}

// Tests that when disabled IP-based pooling, QUIC attempts are also disabled.
// TODO(crbug.com/346835898): Make sure this behavior is what we actually want.
// In production code, we currently disable both IP-based pooling and QUIC at
// the same time.
TEST_F(HttpStreamPoolAttemptManagerTest, QuicMatchingIpSessionDisabled) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_enable_ip_based_pooling(false)
      .RequestStream(pool());
  RunUntilIdle();

  EXPECT_THAT(requester.result(), Optional(IsOk()));
  ASSERT_FALSE(pool()
                   .GetOrCreateGroupForTesting(requester.GetStreamKey())
                   .GetAttemptManagerForTesting()
                   ->GetQuicTaskResultForTesting()
                   .has_value());
}

TEST_F(HttpStreamPoolAttemptManagerTest, DelayStreamAttemptQuicOk) {
  constexpr base::TimeDelta kDelay = base::Milliseconds(10);
  quic_session_pool()->SetTimeDelayForWaitingJobForTesting(kDelay);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  AddQuicData();

  // Don't add any TCP data. This makes sure that the following request
  // completes with a QUIC session without attempting TCP-based protocols.

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, DelayStreamAttemptQuicFail) {
  constexpr base::TimeDelta kDela
```
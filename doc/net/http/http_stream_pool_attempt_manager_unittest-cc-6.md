Response:
My thinking process to analyze the C++ test file and generate the response involved these steps:

1. **Understand the Core Purpose:** I first looked at the filename `http_stream_pool_attempt_manager_unittest.cc`. The key terms are `HttpStreamPool`, `AttemptManager`, and `unittest`. This immediately tells me the file is testing the functionality of a component responsible for managing attempts to establish HTTP connections within a pool of connections.

2. **Identify the Testing Framework:** The code uses `TEST_F`, `ASSERT_*`, `EXPECT_*`, and `Mock*`, indicating the use of Google Test (gtest) and likely a mocking framework (like gmock, although not explicitly used for mocking objects, but data providers).

3. **Analyze Individual Test Cases (Functions starting with `TEST_F`):** I went through each test case, trying to understand what specific scenario it was verifying. I looked for:
    * **Setup:** What preconditions are being set up (e.g., adding fake DNS records with `resolver()->AddFakeRequest()`, providing socket data with `socket_factory()->AddSocketDataProvider()`).
    * **Action:** What action is being performed (e.g., creating a `StreamRequester` and calling `RequestStream()`, creating and starting a `TestJobDelegate`).
    * **Verification:** What assertions are being made (e.g., `EXPECT_THAT(requester.result(), Optional(IsOk()))`, `EXPECT_EQ(delegate.negotiated_protocol(), NextProto::kProtoHTTP2)`).

4. **Categorize Functionality Based on Test Cases:** As I analyzed the test cases, I started grouping them by the aspect of the `HttpStreamPoolAttemptManager` they were testing. This led to categories like:
    * Basic successful connection attempts (HTTP/1.1, HTTP/2, QUIC).
    * Handling connection failures.
    * Interaction with DNS resolution (ServiceEndpoint).
    * Handling of alternative services (Alt-Svc).
    * Race conditions and cleanup scenarios.
    * ECH (Encrypted Client Hello) support.
    * Prioritization of connection attempts based on allowed protocols.

5. **Identify Relationships to JavaScript (if any):** I considered how the network stack interacts with JavaScript in a browser. JavaScript uses APIs like `fetch()` or `XMLHttpRequest` to make network requests. The underlying network stack, including the `HttpStreamPoolAttemptManager`, is responsible for handling these requests. Therefore, the test cases indirectly demonstrate scenarios triggered by JavaScript. I looked for keywords like "request," "stream," "protocol," "connection," which are concepts relevant to network requests initiated from JavaScript.

6. **Infer Logic and Provide Examples:** For test cases involving more complex logic (like handling Alt-Svc or protocol negotiation), I tried to infer the underlying logic of the `AttemptManager`. I then created hypothetical inputs (like specific DNS records or server configurations) and predicted the outputs (successful connection with a particular protocol, connection failure, etc.). This helped illustrate the decision-making process of the component.

7. **Identify Potential User/Programming Errors:** I looked for test cases that simulated error conditions or unexpected behavior. This helped me identify common mistakes developers or users might make that could lead to these scenarios (e.g., incorrect server configuration, network issues, canceling requests prematurely).

8. **Trace User Actions (Debugging Clues):** I considered how a user's actions in a browser could lead to the execution of the code being tested. This involved thinking about the sequence of events when a user navigates to a website, clicks a link, or submits a form. The test cases simulate parts of this process (DNS resolution, connection establishment), so I linked the test scenarios back to these user actions.

9. **Summarize Overall Functionality:** Based on the categorization and analysis of the individual test cases, I formulated a concise summary of the `HttpStreamPoolAttemptManager`'s responsibilities.

10. **Address the "Part 7 of 7" Instruction:**  I explicitly stated that this file focuses on *testing* the `HttpStreamPoolAttemptManager` and doesn't represent the core implementation. This clarifies its role within the larger codebase.

**Self-Correction/Refinement during the process:**

* **Initial thought:** I might have initially focused too much on the low-level socket details.
* **Correction:** I realized the higher-level purpose was managing *attempts* and the *selection* of connection methods (HTTP/1.1, HTTP/2, QUIC), so I shifted my focus accordingly.
* **Clarification:** Some test case names were a bit cryptic, so I had to carefully examine the code to understand the exact scenario being tested.
* **JavaScript Connection:** I initially struggled to make a strong direct link to JavaScript. I then realized the connection is through the browser's network request APIs, which are ultimately served by the underlying C++ network stack.

By following this structured approach, I was able to extract the key functionalities being tested, explain their relevance, provide examples, and summarize the overall purpose of the test file within the Chromium networking stack.
这个C++源代码文件 `net/http/http_stream_pool_attempt_manager_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `HttpStreamPoolAttemptManager` 组件的功能。  `HttpStreamPoolAttemptManager` 的核心职责是管理尝试建立 HTTP 连接的过程，并从多种可能的连接方式（例如，直接 TCP 连接、TLS 连接、QUIC 连接）中选择最佳的方式。

**以下是该文件测试的主要功能归纳：**

1. **基本的连接尝试和成功建立连接:**
   - 测试在正常情况下，`HttpStreamPoolAttemptManager` 是否能够成功建立 HTTP/1.1、HTTP/2 和 QUIC 连接。
   - 验证在连接成功后，是否能够正确地获取到协商的协议。

2. **连接失败处理:**
   - 测试当连接尝试失败时，`HttpStreamPoolAttemptManager` 是否能够正确处理错误，例如连接被拒绝、连接超时等。
   - 验证在连接失败后，是否会进行重试或其他备用连接尝试（例如，回退到不同的协议）。

3. **与 DNS 解析的交互 (ServiceEndpoint):**
   - 测试 `HttpStreamPoolAttemptManager` 如何利用 DNS 解析返回的 `ServiceEndpoint` 信息，包括 IP 地址、端口、ALPN 协议列表、ECH 配置等，来决定连接尝试的策略。
   - 验证当 DNS 解析返回多个 `ServiceEndpoint` 时，`AttemptManager` 是否能够按优先级或策略进行尝试。
   - 测试当 DNS 解析结果更新时，`AttemptManager` 是否能够动态调整连接尝试策略。

4. **Alt-Svc (Alternative Services) 支持:**
   - 测试 `HttpStreamPoolAttemptManager` 如何利用 Alt-Svc 信息来尝试连接到备用服务器。
   - 验证当 Alt-Svc 连接成功或失败时，`AttemptManager` 的行为。
   - 测试在异步创建 QUIC 会话的情况下，如果 Alt-Svc 会话在创建前被销毁，是否会发生崩溃。

5. **ECH (Encrypted Client Hello) 支持:**
   - 测试 `HttpStreamPoolAttemptManager` 如何处理 ECH 配置。
   - 验证在启用和禁用 ECH 的情况下，连接尝试的行为是否符合预期。
   - 测试当 DNS 返回的 `ServiceEndpoint` 包含 ECH 配置时，是否会被正确使用。
   - 测试在 SVCB 记录中，ECH 配置的存在与否对连接尝试的影响 (SVCB-optional 和 SVCB-reliant)。

6. **连接请求的取消和资源管理:**
   - 测试在连接请求被取消的情况下，`HttpStreamPoolAttemptManager` 是否能够正确清理资源，避免内存泄漏或悬挂指针。
   - 验证在 `HttpNetworkSession` 被销毁时，未完成的连接请求是否能够安全处理。

7. **协议优先级和选择:**
   - 测试通过 `HttpStreamJob` 设置期望协议 (例如，只允许 HTTP/2 或只允许 QUIC) 时，`AttemptManager` 的行为。
   - 验证当设置了特定协议限制时，`AttemptManager` 是否会取消不符合要求的连接尝试。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的功能直接影响到 Web 浏览器中 JavaScript 发起的网络请求。

* **`fetch()` API 和 `XMLHttpRequest`:** 当 JavaScript 代码使用 `fetch()` 或 `XMLHttpRequest` 发起 HTTP 请求时，Chromium 的网络栈会处理这些请求。`HttpStreamPoolAttemptManager` 负责决定如何建立到服务器的连接，例如是否尝试 HTTP/2 或 QUIC。
* **性能优化:** `AttemptManager` 的高效工作直接影响到网页的加载速度。例如，快速尝试 QUIC 连接可以减少延迟。
* **安全连接:** ECH 功能的测试确保了浏览器能够安全地建立 TLS 连接，保护用户隐私。

**举例说明 JavaScript 的影响：**

假设 JavaScript 代码使用 `fetch()` 发起一个 HTTPS 请求到一个支持 HTTP/2 和 QUIC 的服务器。

1. **DNS 解析:**  Chromium 会首先进行 DNS 查询，获取服务器的 IP 地址和可能的 `ServiceEndpoint` 记录（包含 ALPN、ECH 等信息）。
2. **`HttpStreamPoolAttemptManager` 的工作:**  `AttemptManager` 会根据 DNS 返回的信息以及浏览器自身的配置，决定尝试哪些连接方式。如果服务器支持 QUIC 且浏览器启用了 QUIC，`AttemptManager` 可能会优先尝试 QUIC 连接。
3. **测试用例的关联:** 该测试文件中的 `EchOk`、`EchDisabled`、`JobAllowH2OnlyOk`、`JobAllowH3OnlyOk` 等测试用例，模拟了 `AttemptManager` 在处理类似 JavaScript 发起的请求时可能遇到的场景。例如，`JobAllowH3OnlyOk` 测试模拟了当 JavaScript (或者更准确地说，网络栈上层的逻辑) 要求只使用 QUIC 时，`AttemptManager` 的行为。

**逻辑推理、假设输入与输出：**

**测试用例：** `AsyncQuicSessionDestroyRequestBeforeSessionCreation`

**假设输入：**

1. 一个支持 QUIC 的服务器 `alt.example.org`。
2. 一个已经建立的与服务器 IP 地址相同的 QUIC 会话。
3. 发起一个新的到 `alt.example.org` 的请求。
4. 在 QUIC 会话尝试建立完成之前，由于存在共享的 IP 会话，该尝试被取消。

**预期输出：**

1. 新的请求最终使用已存在的 QUIC 会话。
2. 在取消 QUIC 会话尝试的过程中，不会发生崩溃或内存错误。

**用户或编程常见的使用错误：**

* **错误配置 Alt-Svc 信息：** 如果服务器发送错误的 Alt-Svc 头信息，可能会导致浏览器尝试连接到不可用的备用服务器，从而导致连接失败。测试用例中可能会模拟这种情况来验证 `AttemptManager` 的健壮性。
* **过早取消请求：** 用户在网页加载过程中点击“停止”按钮或关闭标签页，可能会导致请求被过早取消。测试用例 `CancelRequestBeforeDestructingSession` 模拟了这种情况，验证了 `AttemptManager` 在这种情况下不会崩溃。
* **期望的协议与服务器支持不匹配：**  开发者可能错误地假设服务器支持某个协议 (例如 HTTP/2)，但服务器实际上不支持。相关的测试用例 (如 `JobAllowH2OnlyFail` 的反向情况，虽然此文件中没有明确体现) 可以验证 `AttemptManager` 在这种情况下是否能够回退到其他协议或返回错误。

**用户操作如何一步步到达这里（调试线索）：**

假设用户在浏览器中访问 `https://www.example.org`，并且该网站配置了 Alt-Svc 指向另一个服务器。

1. **用户在地址栏输入 `https://www.example.org` 并回车。**
2. **浏览器发起 DNS 查询，获取 `www.example.org` 的 IP 地址，并可能获取到 Alt-Svc 记录。**
3. **Chromium 网络栈的 `HttpStreamFactory` 开始尝试建立连接。**
4. **`HttpStreamPoolAttemptManager` 根据 DNS 结果和 Alt-Svc 信息，决定尝试连接到 `www.example.org` 的原始地址，或者尝试连接到 Alt-Svc 指向的备用服务器。**
5. **如果尝试连接到备用服务器，相关的 `HttpStreamPoolAttemptManager` 的代码会被执行，类似于测试用例 `AsyncAltSvc` 所模拟的场景。**
6. **如果连接过程中出现问题，例如备用服务器连接失败，测试用例中模拟的错误处理逻辑会被触发。**

**作为第 7 部分，共 7 部分的功能归纳：**

作为整个测试套件的最后一部分，这个文件专注于测试 `HttpStreamPoolAttemptManager` 这个关键组件的各种功能和边界情况。它确保了在不同的网络环境、服务器配置和用户行为下，连接尝试管理能够正确、高效、安全地进行。  这个文件与其他测试文件一起，共同验证了 Chromium 网络栈的健壮性和可靠性。它特别关注连接建立的策略选择、错误处理和资源管理，这对于提供良好的用户浏览体验至关重要。

### 提示词
```
这是目录为net/http/http_stream_pool_attempt_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
ilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&data);
  requester.RequestStream(pool());
  ASSERT_FALSE(requester.result().has_value());

  // Cancel the request before destructing HttpNetworkSession to avoid a
  // dangling pointer.
  requester.ResetRequest();

  // Destroying HttpNetworkSession should not cause crash.
  DestroyHttpNetworkSession();
}

// Regression test for crbug.com/371894055.
TEST_F(HttpStreamPoolAttemptManagerTest,
       AsyncQuicSessionDestroyRequestBeforeSessionCreation) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  constexpr std::string_view kAltDestination = "https://alt.example.org";
  const IPEndPoint kCommonEndPoint = MakeIPEndPoint("2001:db8::1", 443);

  // Precondition: Create a QUIC session that can be shared for destinations
  // that are resolved to kCommonEndPoint.
  AddQuicData();

  SequencedSocketData tcp_data1;
  tcp_data1.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data1);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  requester1.WaitForResult();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));

  // Actual test: Create a request that starts a QuicSessionAttempt, which
  // is later destroyed since there is a matching IP session.

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  MockConnectCompleter quic_completer;
  MockQuicData quic_data(quic_version());
  quic_data.AddConnect(&quic_completer);
  quic_data.AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data2;
  tcp_data2.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&tcp_data2);

  StreamRequester requester2;
  requester2.set_destination(kAltDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  ASSERT_FALSE(requester2.result().has_value());

  // Provide a different IP address to start a QUIC attempt.
  endpoint_request->set_crypto_ready(true)
      .add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointsUpdated();
  ASSERT_FALSE(requester2.result().has_value());

  // Provide kCommonEndPoint so that the corresponding attempt manager cancel
  // the in-flight QUIC attempt and use the existing session.
  endpoint_request->set_crypto_ready(true)
      .add_endpoint(
          ServiceEndpointBuilder().add_ip_endpoint(kCommonEndPoint).endpoint())
      .CallOnServiceEndpointsUpdated();

  // Resume the QUIC attempt. This should not detect a dangling pointer.
  quic_completer.Complete(OK);
  requester2.WaitForResult();
}

TEST_F(HttpStreamPoolAttemptManagerTest, EchOk) {
  std::vector<uint8_t> ech_config_list;
  ASSERT_TRUE(MakeTestEchKeys("www.example.org", /*max_name_len=*/128,
                              &ech_config_list));

  SequencedSocketData data;
  socket_factory()->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.expected_ech_config_list = ech_config_list;
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder()
                         .add_v4("192.0.2.1")
                         .set_alpns({"http/1.1"})
                         .set_ech_config_list(ech_config_list)
                         .endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());

  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, EchDisabled) {
  SetEchEnabled(false);

  std::vector<uint8_t> ech_config_list;
  ASSERT_TRUE(MakeTestEchKeys("www.example.org", /*max_name_len=*/128,
                              &ech_config_list));

  SequencedSocketData data;
  socket_factory()->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  // ECH config list should not be set since ECH is disabled.
  ssl.expected_ech_config_list = std::vector<uint8_t>();
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder()
                         .add_v4("192.0.2.1")
                         .set_alpns({"http/1.1"})
                         .set_ech_config_list(ech_config_list)
                         .endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());

  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, EchSvcbOptional) {
  std::vector<uint8_t> ech_config_list;
  ASSERT_TRUE(MakeTestEchKeys("www.example.org", /*max_name_len=*/128,
                              &ech_config_list));

  // The first endpoint provides ECH config list. The second endpoint doesn't.
  // This makes attempts SVCB-optional.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder()
                         .add_v4("192.0.2.1")
                         .set_alpns({"http/1.1"})
                         .set_ech_config_list(ech_config_list)
                         .endpoint())
      .add_endpoint(ServiceEndpointBuilder()
                        .add_v4("192.0.2.2")
                        .set_alpns({"http/1.1"})
                        .endpoint())
      .CompleteStartSynchronously(OK);

  // The first endpoint fails.
  SequencedSocketData data1;
  data1.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_FAILED));
  socket_factory()->AddSocketDataProvider(&data1);

  // The second endpoint succeeds.
  SequencedSocketData data2;
  socket_factory()->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl2);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());

  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, EchSvcbReliant) {
  std::vector<uint8_t> ech_config_list;
  ASSERT_TRUE(MakeTestEchKeys("www.example.org", /*max_name_len=*/128,
                              &ech_config_list));

  // All endpoints have ECH config list. The first endpoint only accepts H3. The
  // second endpoint only accepts HTTP/1.1. This makes attempts SVCB-relient.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder()
                         .add_v4("192.0.2.1")
                         .set_alpns({"h3"})
                         .set_ech_config_list(ech_config_list)
                         .endpoint())
      .add_endpoint(ServiceEndpointBuilder()
                        .add_v4("192.0.2.2")
                        .set_alpns({"http/1.1"})
                        .set_ech_config_list(ech_config_list)
                        .endpoint())
      .CompleteStartSynchronously(OK);

  // The first endpoint (H3) fails.
  MockQuicData quic_data(quic_version());
  quic_data.AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data.AddSocketDataToFactory(socket_factory());

  // The second endpoint succeeds.
  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.expected_ech_config_list = ech_config_list;
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());

  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       EchSvcbReliantQuicOnlyAbortTcpAttempt) {
  std::vector<uint8_t> ech_config_list;
  ASSERT_TRUE(MakeTestEchKeys("www.example.org", /*max_name_len=*/128,
                              &ech_config_list));

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  SequencedSocketData tcp_data;
  tcp_data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory()->AddSocketDataProvider(&tcp_data);

  AddQuicData();

  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());
  ASSERT_FALSE(requester.result().has_value());

  // Simulate A record resolution. This starts a TCP attempt.
  endpoint_request
      ->set_endpoints({ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint()})
      .CallOnServiceEndpointsUpdated();
  Group& group = pool().GetOrCreateGroupForTesting(requester.GetStreamKey());
  EXPECT_EQ(group.ActiveStreamSocketCount(), 1u);
  ASSERT_FALSE(requester.result().has_value());

  // Simulate HTTPS record resolution. We now know that the endpoint is QUIC
  // only and SVCB-reliant.
  endpoint_request
      ->set_endpoints({ServiceEndpointBuilder()
                           .add_v4("192.0.2.1")
                           .set_alpns({"h3"})
                           .set_ech_config_list(ech_config_list)
                           .endpoint()})
      .set_crypto_ready(true)
      .CallOnServiceEndpointRequestFinished(OK);

  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  // The TCP attempt should be aborted.
  EXPECT_EQ(requester.negotiated_protocol(), NextProto::kProtoQUIC);
  EXPECT_EQ(group.ActiveStreamSocketCount(), 0u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, JobAllowH2Only) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData data(reads, writes);
  socket_factory()->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  HttpStreamKey stream_key = StreamKeyBuilder(kDefaultDestination).Build();
  TestJobDelegate delegate;
  delegate.set_expected_protocol(NextProto::kProtoHTTP2);
  delegate.CreateAndStartJob(pool());
  EXPECT_THAT(delegate.GetResult(), IsOk());
  EXPECT_EQ(delegate.negotiated_protocol(), NextProto::kProtoHTTP2);
}

TEST_F(HttpStreamPoolAttemptManagerTest, JobAllowH2OnlyCancelQuicAttempt) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  MockConnectCompleter h3_completer;
  MockQuicData quic_data(quic_version());
  quic_data.AddConnect(&h3_completer);
  quic_data.AddSocketDataToFactory(socket_factory());

  MockConnectCompleter h2_completer;
  const MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  const MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData data(reads, writes);
  data.set_connect_data(MockConnect(&h2_completer));
  socket_factory()->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  HttpStreamKey stream_key = StreamKeyBuilder(kDefaultDestination).Build();

  // Set the destination is known to support H2. This prevents the
  // AttemptManager from attempting more than one TCP handshake.
  http_server_properties()->SetSupportsSpdy(
      stream_key.destination(), stream_key.network_anonymization_key(),
      /*supports_spdy=*/true);

  // Create the first job that allows all protocols to attempt.
  TestJobDelegate delegate1(stream_key);
  delegate1.set_quic_version(quic_version());
  delegate1.CreateAndStartJob(pool());

  // Create the second job that only allows H2.
  TestJobDelegate delegate2(stream_key);
  delegate2.set_expected_protocol(NextProto::kProtoHTTP2);
  delegate2.CreateAndStartJob(pool());

  h3_completer.Complete(OK);
  h2_completer.Complete(OK);

  EXPECT_THAT(delegate1.GetResult(), IsOk());
  EXPECT_EQ(delegate1.negotiated_protocol(), NextProto::kProtoHTTP2);
  EXPECT_THAT(delegate2.GetResult(), IsOk());
  EXPECT_EQ(delegate2.negotiated_protocol(), NextProto::kProtoHTTP2);

  EXPECT_THAT(pool()
                  .GetOrCreateGroupForTesting(stream_key)
                  .GetAttemptManagerForTesting()
                  ->GetQuicTaskResultForTesting(),
              Optional(IsError(ERR_ABORTED)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, JobAllowH3OnlyOk) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  AddQuicData();

  TestJobDelegate delegate;
  delegate.set_expected_protocol(NextProto::kProtoQUIC);
  delegate.set_quic_version(quic_version());
  delegate.CreateAndStartJob(pool());
  EXPECT_THAT(delegate.GetResult(), IsOk());
  EXPECT_EQ(delegate.negotiated_protocol(), NextProto::kProtoQUIC);
}

TEST_F(HttpStreamPoolAttemptManagerTest, JobAllowH3OnlyFail) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  MockQuicData quic_data(quic_version());
  quic_data.AddRead(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data.AddSocketDataToFactory(socket_factory());

  TestJobDelegate delegate;
  delegate.set_expected_protocol(NextProto::kProtoQUIC);
  delegate.set_quic_version(quic_version());
  delegate.CreateAndStartJob(pool());
  EXPECT_THAT(delegate.GetResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
}

TEST_F(HttpStreamPoolAttemptManagerTest, JobAllowH3OnlyCancelTcpBasedAttempt) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  MockConnectCompleter quic_completer;

  AddQuicData(/*host=*/kDefaultDestination, &quic_completer);

  // Make the TCP attempt stalled forever.
  SequencedSocketData data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&data);

  HttpStreamKey stream_key = StreamKeyBuilder(kDefaultDestination).Build();

  // Create the first job that allows all protocols to attempt.
  TestJobDelegate delegate1(stream_key);
  delegate1.set_quic_version(quic_version());
  delegate1.CreateAndStartJob(pool());

  Group& group = pool().GetOrCreateGroupForTesting(stream_key);
  ASSERT_EQ(group.ActiveStreamSocketCount(), 1u);

  // Create the second job that only allows H3.
  TestJobDelegate delegate2(stream_key);
  delegate2.set_quic_version(quic_version());
  delegate2.set_expected_protocol(NextProto::kProtoQUIC);
  delegate2.CreateAndStartJob(pool());

  ASSERT_EQ(group.ActiveStreamSocketCount(), 0u);

  quic_completer.Complete(OK);

  EXPECT_THAT(delegate1.GetResult(), IsOk());
  EXPECT_EQ(delegate1.negotiated_protocol(), NextProto::kProtoQUIC);

  EXPECT_THAT(delegate2.GetResult(), IsOk());
  EXPECT_EQ(delegate2.negotiated_protocol(), NextProto::kProtoQUIC);
}

}  // namespace net
```
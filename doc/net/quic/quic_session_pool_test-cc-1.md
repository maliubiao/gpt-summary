Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/quic/quic_session_pool_test.cc`. This is part 2 of a 20-part series, so I should focus on summarizing the functionality present in this specific segment.

Here's a breakdown of the code's actions:

1. **Test Scenarios:** The code defines several test cases within the `QuicSessionPoolTest` class. Each test case focuses on a specific aspect of how the `QuicSessionPool` manages QUIC sessions.

2. **Session Creation and Management:**  Many tests involve creating QUIC sessions, checking their states (active, requiring confirmation), and observing how the pool handles multiple requests.

3. **Zero-RTT:** Several tests explore Zero Round Trip Time (0-RTT) connection establishment, both synchronously and asynchronously. This includes scenarios where 0-RTT is successful and where it's initially delayed or requires confirmation.

4. **Initial RTT:**  Tests examine how the initial Round Trip Time (RTT) is determined and used, including cases with default values, cached values from `HttpServerProperties`, and adjustments based on network conditions (e.g., 2G, 3G).

5. **`Http3GoAway` Frame:**  One test demonstrates the handling of the `Http3GoAway` frame, which signals the end of a session.

6. **`ServerNetworkStats` and Network Anonymization Key:**  A significant test explores how `ServerNetworkStats` (like RTT) are stored and retrieved in `HttpServerProperties`, particularly in the context of `NetworkAnonymizationKey` for privacy. It also covers scenarios where these stats are cleared due to connection errors.

7. **Origin Frames and Pooling:** Several tests deal with the QUIC `Origin` frame, which allows a server to inform the client about other origins it serves. These tests check if the `QuicSessionPool` correctly pools connections to these other origins based on the received `Origin` frame, considering factors like IP address and ALPN. The concept of skipping DNS resolution when an `Origin` frame is present is also tested.

8. **Mocking and Testing Infrastructure:** The tests heavily rely on mocking frameworks like `MockQuicData`, `MockCryptoClientStream`, and `MockHostResolver` to simulate network behavior and server responses.

**Relationship to JavaScript:** While the core of this code is C++, it directly impacts the performance and security of web requests initiated by JavaScript in a browser. QUIC is a transport protocol used for HTTP/3, and this code tests the underlying mechanics of how those connections are managed. A faster and more reliable QUIC connection benefits JavaScript applications by reducing latency and improving the user experience.

**Hypothetical Input and Output (for a specific test, e.g., `AsyncZeroRtt`):**

* **Input:** A request to a server supporting QUIC, where the client has previously connected (allowing for 0-RTT). The server's `MockQuicData` is set up to simulate a successful 0-RTT handshake.
* **Output:**  The test asserts that the `CallRequest()` initially returns `ERR_IO_PENDING` (because it's asynchronous), then `WaitForResult()` returns `OK`. A new `HttpStream` is successfully created using the 0-RTT session.

**User/Programming Errors:**

* **Incorrect Mock Setup:**  A common mistake when writing these tests would be to incorrectly configure the `MockQuicData` or `MockCryptoClientStream` to simulate the desired network conditions or server behavior. For example, forgetting to add the `ConstructInitialSettingsPacket()` would lead to handshake failures.
* **Asynchronous Handling:**  Failing to correctly handle asynchronous operations (like waiting for callbacks) can lead to premature assertions and test failures. The `EXPECT_EQ(ERR_IO_PENDING, ...)` and `callback_.WaitForResult()` pattern is crucial for testing asynchronous scenarios.

**User Operation to Reach This Code:**

A user browsing the web might trigger this code indirectly through the following steps:

1. **User types a URL (e.g., `https://example.com`) in the browser's address bar or clicks a link.**
2. **The browser determines that the server supports QUIC (potentially through Alt-Svc headers from previous visits or via DNS records).**
3. **The browser's network stack attempts to establish a QUIC connection.**
4. **The `QuicSessionPool` is involved in finding an existing session or creating a new one.**
5. **The code in `quic_session_pool_test.cc` simulates these connection attempts and tests the logic of the `QuicSessionPool`.**

**Summary of Functionality (Part 2):**

This part of the `quic_session_pool_test.cc` file primarily focuses on testing:

* **Asynchronous and synchronous QUIC session creation.**
* **Zero Round Trip Time (0-RTT) connection establishment in various scenarios.**
* **The handling of initial Round Trip Time (RTT) values, including defaults, cached values, and network-based adjustments.**
* **The impact of the `Http3GoAway` frame on session management.**
* **The storage and retrieval of server network statistics (`ServerNetworkStats`) in conjunction with Network Anonymization Keys for privacy.**
* **Connection pooling based on QUIC `Origin` frames, including scenarios where DNS resolution can be skipped.**

这是 `net/quic/quic_session_pool_test.cc` 文件的第二部分，主要功能是测试 Chromium 网络栈中 `QuicSessionPool` 类的各种行为和功能。以下是具体的功能归纳：

**核心测试功能：**

* **异步和同步 QUIC 会话创建：** 测试在异步和同步模式下创建 QUIC 会话的流程和结果，例如 `CreateAsyncQuicSession` 和 `SyncCreateZeroRtt`。
* **0-RTT (Zero Round Trip Time) 连接：**  详细测试 0-RTT 连接建立的不同场景，包括同步和异步的 0-RTT (`SyncCreateZeroRtt`, `AsyncCreateZeroRtt`)，以及异步 0-RTT 的完成流程和状态 (`AsyncZeroRtt`)。
* **初始 RTT (Round Trip Time) 的处理：** 测试 QUIC 会话如何使用初始 RTT 值，包括默认值 (`DefaultInitialRtt`)，从 `HttpServerProperties` 中缓存的值 (`CachedInitialRtt`, `CachedInitialRttWithNetworkAnonymizationKey`)，以及根据网络类型（如 2G, 3G）调整初始 RTT 的机制 (`2gInitialRtt`, `3gInitialRtt`)。
* **`Http3GoAway` 帧的处理：** 测试 `QuicSessionPool` 如何处理服务器发送的 `Http3GoAway` 帧，以及对活跃会话的影响 (`GoAway`)。
* **`ServerNetworkStats` 和 `NetworkAnonymizationKey` 的交互：**  测试 `HttpServerProperties` 如何存储和检索服务器网络统计信息，并验证 `NetworkAnonymizationKey` 是否被正确用于隔离不同站点的统计信息 (`ServerNetworkStatsWithNetworkAnonymizationKey`)。
* **连接确认 (`RequireConfirmation`)：** 测试在某些情况下，例如首次连接或从未使用 QUIC 的网络连接时，QUIC 会话是否需要确认，以及如何影响 `HttpServerProperties` 的状态 (`RequireConfirmation`, `RequireConfirmationAsyncQuicSession`, `DontRequireConfirmationFromSameIP`)。
* **当有待处理任务时工厂销毁的处理：** 测试在有待处理的 QUIC 会话创建任务时销毁 `QuicSessionPool` 工厂是否会导致崩溃 (`FactoryDestroyedWhenJobPending`)。
* **基于 Origin Frame 的连接池化：** 测试在接收到服务器发送的 Origin Frame 后，客户端是否能够将后续对相同 IP 地址但不同域名的请求池化到现有的 QUIC 会话中 (`PooledWithDifferentIpSession`)，以及在启用 `skip_dns_with_origin_frame` 特性后是否能跳过 DNS 解析 (`PoolingSkipDns`)。

**与 JavaScript 的关系：**

虽然这段代码是 C++，但它直接影响了通过 JavaScript 发起的网络请求的性能和安全性。

* **QUIC 协议的底层实现：**  这段代码测试了 QUIC 协议在 Chromium 中的实现细节，而 QUIC 是 HTTP/3 的基础。当 JavaScript 代码发起 HTTPS 请求时，如果协商使用了 HTTP/3，那么底层的 QUIC 连接管理就由 `QuicSessionPool` 负责。
* **性能优化：**  例如，0-RTT 连接的测试直接关系到用户首次访问网站的速度。如果 0-RTT 工作正常，JavaScript 应用可以更快地获取资源，提升用户体验。
* **安全性：** 连接确认机制的测试关系到 QUIC 连接的安全性。确保在需要时进行确认可以防止某些类型的攻击。
* **网络状态感知：**  对初始 RTT 的处理以及根据网络类型进行调整，可以使 QUIC 连接更好地适应不同的网络环境，从而提升 JavaScript 应用在各种网络条件下的性能。

**逻辑推理的假设输入与输出示例 (`AsyncZeroRtt` 测试):**

* **假设输入:**
    * 客户端首次访问 `kDefaultUrl` (假设已启用 0-RTT)。
    * `MockQuicData` 被配置为模拟成功的 0-RTT 握手，包括接收服务器的响应。
    * `crypto_client_stream_factory_` 被设置为 `MockCryptoClientStream::ASYNC_ZERO_RTT` 模式。
* **输出:**
    * `builder.CallRequest()` 返回 `ERR_IO_PENDING`，因为是异步操作。
    * `HasActiveSession(kDefaultDestination)` 返回 `false`，因为 0-RTT 握手可能还在进行中。
    * `CreateStream(&builder.request)` 返回 `nullptr`，因为会话可能尚未完全建立。
    * 在 `crypto_client_stream_factory_.last_stream()->NotifySessionZeroRttComplete()` 调用后，`callback_.WaitForResult()` 返回 `IsOk()`。
    * `HasActiveSession(kDefaultDestination)` 返回 `true`，表示 0-RTT 会话已成功建立。
    * `CreateStream(&builder.request)` 返回一个有效的 `HttpStream` 指针。

**用户或编程常见的使用错误示例：**

* **忘记设置 `has_quic_ever_worked_on_current_network`：** 在测试 0-RTT 时，如果忘记设置 `factory_->set_has_quic_ever_worked_on_current_network(true)`，可能会导致 0-RTT 尝试失败，因为客户端会认为这是首次连接。
* **Mock 数据配置错误：** 在使用 `MockQuicData` 时，如果忘记添加必要的握手数据包（例如 `ConstructInitialSettingsPacket()`），会导致连接建立失败，测试也会失败。
* **异步操作处理不当：** 对于异步操作的测试，如果没有正确使用 `EXPECT_EQ(ERR_IO_PENDING, ...)` 和 `callback_.WaitForResult()` 来等待异步操作完成，可能会导致测试结果不准确。

**用户操作到达此代码的调试线索：**

作为一个开发者，当需要调试与 QUIC 连接池相关的网络问题时，可能会逐步追踪到这段代码：

1. **用户报告连接问题：** 用户可能会遇到网页加载缓慢、连接失败或者间歇性断开等问题，这些问题可能与 QUIC 连接有关。
2. **网络日志分析：** 开发者会查看浏览器的网络日志 (chrome://net-export/)，其中可能会显示 QUIC 连接建立失败、会话被重置或者使用了非预期的 RTT 值等信息。
3. **怀疑 QUIC 连接池：** 如果日志信息指向 QUIC 协议，开发者可能会怀疑是 `QuicSessionPool` 的行为异常导致了问题。
4. **代码追踪：** 开发者会根据网络栈的调用流程，逐步追踪到 `QuicSessionPool` 相关的代码，例如 `QuicSessionPool::GetOrCreate` 等方法。
5. **单元测试：** 为了验证 `QuicSessionPool` 的行为，开发者可能会查看或运行 `quic_session_pool_test.cc` 中的单元测试，以了解在各种场景下 `QuicSessionPool` 的预期行为。例如，如果怀疑 0-RTT 有问题，可能会重点关注 `AsyncZeroRtt` 等测试。
6. **断点调试：**  开发者可能会在 `quic_session_pool_test.cc` 中设置断点，模拟用户操作，然后逐步执行代码，观察 `QuicSessionPool` 的状态变化和决策过程。

**第2部分功能归纳：**

这部分 `quic_session_pool_test.cc` 文件主要负责测试 `QuicSessionPool` 在以下关键方面的功能：**QUIC 会话的创建（同步和异步），0-RTT 连接的建立和处理，初始 RTT 值的管理和优化，`Http3GoAway` 帧的响应，以及与服务器网络统计和 NetworkAnonymizationKey 的协同工作。此外，还测试了基于 Origin Frame 的连接池化能力。** 这些测试确保了 `QuicSessionPool` 的核心功能能够正确可靠地运行，为基于 QUIC 的网络连接提供稳定和高效的基础。

Prompt: 
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共20部分，请归纳一下它的功能

"""
(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  EXPECT_EQ(DEFAULT_PRIORITY, host_resolver_->last_request_priority());

  RequestBuilder builder2(this);
  EXPECT_EQ(OK, builder2.CallRequest());
  // Will reset stream 3.
  stream = CreateStream(&builder2.request);

  EXPECT_TRUE(stream.get());

  // TODO(rtenneti): We should probably have a tests that HTTP and HTTPS result
  // in streams on different sessions.
  RequestBuilder builder3(this);
  EXPECT_EQ(OK, builder3.CallRequest());
  stream = CreateStream(&builder3.request);  // Will reset stream 5.
  stream.reset();                            // Will reset stream 7.

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, CreateAsyncQuicSession) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  EXPECT_EQ(DEFAULT_PRIORITY, host_resolver_->last_request_priority());

  RequestBuilder builder2(this);
  EXPECT_EQ(OK, builder2.CallRequest());
  // Will reset stream 3.
  stream = CreateStream(&builder2.request);
  EXPECT_TRUE(stream.get());

  // TODO(rtenneti): We should probably have a tests that HTTP and HTTPS result
  // in streams on different sessions.
  RequestBuilder builder3(this);
  EXPECT_EQ(OK, builder3.CallRequest());
  stream = CreateStream(&builder3.request);  // Will reset stream 5.
  stream.reset();                            // Will reset stream 7.

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// This test uses synchronous QUIC session creation
TEST_P(QuicSessionPoolTest, SyncCreateZeroRtt) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);
  Initialize();
  factory_->set_has_quic_ever_worked_on_current_network(true);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  RequestBuilder builder(this);
  EXPECT_EQ(OK, builder.CallRequest());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, AsyncCreateZeroRtt) {
  Initialize();
  factory_->set_has_quic_ever_worked_on_current_network(true);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  int rv = callback_.WaitForResult();
  EXPECT_EQ(OK, rv);

  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// Regression test for crbug.com/1117331.
TEST_P(QuicSessionPoolTest, AsyncZeroRtt) {
  Initialize();

  factory_->set_has_quic_ever_worked_on_current_network(true);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ASYNC_ZERO_RTT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(nullptr, CreateStream(&builder.request));

  base::RunLoop().RunUntilIdle();
  crypto_client_stream_factory_.last_stream()->NotifySessionZeroRttComplete();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, DefaultInitialRtt) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(session->require_confirmation());
  EXPECT_EQ(100000u, session->connection()->GetStats().srtt_us);
  ASSERT_FALSE(session->config()->HasInitialRoundTripTimeUsToSend());
}

TEST_P(QuicSessionPoolTest, FactoryDestroyedWhenJobPending) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  auto builder = std::make_unique<RequestBuilder>(this);
  EXPECT_EQ(ERR_IO_PENDING, builder->CallRequest());
  builder.reset();
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  // Tearing down a QuicSessionPool with a pending Job should not cause any
  // crash. crbug.com/768343.
  factory_.reset();
}

TEST_P(QuicSessionPoolTest, RequireConfirmation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");
  Initialize();
  factory_->set_has_quic_ever_worked_on_current_network(false);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_FALSE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());

  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  EXPECT_TRUE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(session->require_confirmation());
}

TEST_P(QuicSessionPoolTest, RequireConfirmationAsyncQuicSession) {
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");
  Initialize();
  factory_->set_has_quic_ever_worked_on_current_network(false);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_FALSE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());

  base::RunLoop().RunUntilIdle();
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  EXPECT_TRUE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(session->require_confirmation());
}

TEST_P(QuicSessionPoolTest, DontRequireConfirmationFromSameIP) {
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");
  Initialize();
  factory_->set_has_quic_ever_worked_on_current_network(false);
  http_server_properties_->SetLastLocalAddressWhenQuicWorked(
      IPAddress(192, 0, 2, 33));

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_FALSE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());

  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_FALSE(session->require_confirmation());

  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_TRUE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());
}

TEST_P(QuicSessionPoolTest, CachedInitialRtt) {
  ServerNetworkStats stats;
  stats.srtt = base::Milliseconds(10);
  http_server_properties_->SetServerNetworkStats(
      url::SchemeHostPort(GURL(kDefaultUrl)), NetworkAnonymizationKey(), stats);
  quic_params_->estimate_initial_rtt = true;

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_EQ(10000u, session->connection()->GetStats().srtt_us);
  ASSERT_TRUE(session->config()->HasInitialRoundTripTimeUsToSend());
  EXPECT_EQ(10000u, session->config()->GetInitialRoundTripTimeUsToSend());
}

// Test that QUIC sessions use the cached RTT from HttpServerProperties for the
// correct NetworkAnonymizationKey.
TEST_P(QuicSessionPoolTest, CachedInitialRttWithNetworkAnonymizationKey) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  http_server_properties_ = std::make_unique<HttpServerProperties>();

  ServerNetworkStats stats;
  stats.srtt = base::Milliseconds(10);
  http_server_properties_->SetServerNetworkStats(
      url::SchemeHostPort(GURL(kDefaultUrl)), kNetworkAnonymizationKey1, stats);
  quic_params_->estimate_initial_rtt = true;
  Initialize();

  for (const auto& network_anonymization_key :
       {kNetworkAnonymizationKey1, kNetworkAnonymizationKey2,
        NetworkAnonymizationKey()}) {
    SCOPED_TRACE(network_anonymization_key.ToDebugString());

    ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

    QuicTestPacketMaker packet_maker(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
        true);

    MockQuicData socket_data(version_);
    socket_data.AddReadPauseForever();
    socket_data.AddWrite(SYNCHRONOUS,
                         packet_maker.MakeInitialSettingsPacket(1));
    socket_data.AddSocketDataToFactory(socket_factory_.get());

    RequestBuilder builder(this);
    builder.network_anonymization_key = network_anonymization_key;
    EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
    EXPECT_THAT(callback_.WaitForResult(), IsOk());
    std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
    EXPECT_TRUE(stream.get());

    QuicChromiumClientSession* session = GetActiveSession(
        kDefaultDestination, PRIVACY_MODE_DISABLED, network_anonymization_key);
    if (network_anonymization_key == kNetworkAnonymizationKey1) {
      EXPECT_EQ(10000, session->connection()->GetStats().srtt_us);
      ASSERT_TRUE(session->config()->HasInitialRoundTripTimeUsToSend());
      EXPECT_EQ(10000u, session->config()->GetInitialRoundTripTimeUsToSend());
    } else {
      EXPECT_EQ(quic::kInitialRttMs * 1000,
                session->connection()->GetStats().srtt_us);
      EXPECT_FALSE(session->config()->HasInitialRoundTripTimeUsToSend());
    }
  }
}

TEST_P(QuicSessionPoolTest, 2gInitialRtt) {
  ScopedMockNetworkChangeNotifier notifier;
  notifier.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_2G);
  quic_params_->estimate_initial_rtt = true;

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_EQ(1000000u, session->connection()->GetStats().srtt_us);
  ASSERT_TRUE(session->config()->HasInitialRoundTripTimeUsToSend());
  EXPECT_EQ(1200000u, session->config()->GetInitialRoundTripTimeUsToSend());
}

TEST_P(QuicSessionPoolTest, 3gInitialRtt) {
  ScopedMockNetworkChangeNotifier notifier;
  notifier.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_3G);
  quic_params_->estimate_initial_rtt = true;

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_EQ(400000u, session->connection()->GetStats().srtt_us);
  ASSERT_TRUE(session->config()->HasInitialRoundTripTimeUsToSend());
  EXPECT_EQ(400000u, session->config()->GetInitialRoundTripTimeUsToSend());
}

TEST_P(QuicSessionPoolTest, GoAway) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);

  session->OnHttp3GoAway(0);

  EXPECT_FALSE(HasActiveSession(kDefaultDestination));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// Makes sure that setting and clearing ServerNetworkStats respects the
// NetworkAnonymizationKey.
TEST_P(QuicSessionPoolTest, ServerNetworkStatsWithNetworkAnonymizationKey) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  const NetworkAnonymizationKey kNetworkAnonymizationKeys[] = {
      kNetworkAnonymizationKey1, kNetworkAnonymizationKey2,
      NetworkAnonymizationKey()};

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  http_server_properties_ = std::make_unique<HttpServerProperties>();
  Initialize();

  // For each server, set up and tear down a QUIC session cleanly, and check
  // that stats have been added to HttpServerProperties using the correct
  // NetworkAnonymizationKey.
  for (size_t i = 0; i < std::size(kNetworkAnonymizationKeys); ++i) {
    SCOPED_TRACE(i);

    ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

    QuicTestPacketMaker packet_maker(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
        true);

    MockQuicData socket_data(version_);
    socket_data.AddReadPauseForever();
    socket_data.AddWrite(SYNCHRONOUS,
                         packet_maker.MakeInitialSettingsPacket(1));
    socket_data.AddSocketDataToFactory(socket_factory_.get());

    RequestBuilder builder(this);
    builder.network_anonymization_key = kNetworkAnonymizationKeys[i];
    EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
    EXPECT_THAT(callback_.WaitForResult(), IsOk());
    std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
    EXPECT_TRUE(stream.get());

    QuicChromiumClientSession* session =
        GetActiveSession(kDefaultDestination, PRIVACY_MODE_DISABLED,
                         kNetworkAnonymizationKeys[i]);

    session->OnHttp3GoAway(0);

    EXPECT_FALSE(HasActiveSession(kDefaultDestination, PRIVACY_MODE_DISABLED,
                                  kNetworkAnonymizationKeys[i]));

    socket_data.ExpectAllReadDataConsumed();
    socket_data.ExpectAllWriteDataConsumed();

    for (size_t j = 0; j < std::size(kNetworkAnonymizationKeys); ++j) {
      // Stats up to kNetworkAnonymizationKeys[j] should have been populated,
      // all others should remain empty.
      if (j <= i) {
        EXPECT_TRUE(http_server_properties_->GetServerNetworkStats(
            url::SchemeHostPort(GURL(kDefaultUrl)),
            kNetworkAnonymizationKeys[j]));
      } else {
        EXPECT_FALSE(http_server_properties_->GetServerNetworkStats(
            url::SchemeHostPort(GURL(kDefaultUrl)),
            kNetworkAnonymizationKeys[j]));
      }
    }
  }

  // Use unmocked crypto stream to do crypto connect, since crypto errors result
  // in deleting network stats..
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  // For each server, simulate an error during session creation, and check that
  // stats have been deleted from HttpServerProperties using the correct
  // NetworkAnonymizationKey.
  for (size_t i = 0; i < std::size(kNetworkAnonymizationKeys); ++i) {
    SCOPED_TRACE(i);

    MockQuicData socket_data(version_);
    socket_data.AddReadPauseForever();
    // Trigger PACKET_WRITE_ERROR when sending packets in crypto connect.
    socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
    socket_data.AddSocketDataToFactory(socket_factory_.get());

    RequestBuilder builder(this);
    builder.network_anonymization_key = kNetworkAnonymizationKeys[i];
    EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
    EXPECT_THAT(callback_.WaitForResult(), IsError(ERR_QUIC_HANDSHAKE_FAILED));

    EXPECT_FALSE(HasActiveSession(kDefaultDestination, PRIVACY_MODE_DISABLED,
                                  kNetworkAnonymizationKeys[i]));

    for (size_t j = 0; j < std::size(kNetworkAnonymizationKeys); ++j) {
      // Stats up to kNetworkAnonymizationKeys[j] should have been deleted, all
      // others should still be populated.
      if (j <= i) {
        EXPECT_FALSE(http_server_properties_->GetServerNetworkStats(
            url::SchemeHostPort(GURL(kDefaultUrl)),
            kNetworkAnonymizationKeys[j]));
      } else {
        EXPECT_TRUE(http_server_properties_->GetServerNetworkStats(
            url::SchemeHostPort(GURL(kDefaultUrl)),
            kNetworkAnonymizationKeys[j]));
      }
    }
  }
}

TEST_P(QuicSessionPoolTest, PooledWithDifferentIpSession) {
  quic_params_->supported_versions = {version_};
  quic_params_->enable_origin_frame = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  const IPEndPoint kRightIP(*IPAddress::FromIPLiteral("192.168.0.1"),
                            kDefaultServerPort);
  const IPEndPoint kWrongIP(*IPAddress::FromIPLiteral("192.168.0.2"),
                            kDefaultServerPort);
  const std::string kRightALPN = quic::AlpnForVersion(version_);
  const std::string kWrongALPN = "h2";

  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName,
                              kDefaultServerPort);
  url::SchemeHostPort server3(url::kHttpsScheme, kServer3HostName,
                              kDefaultServerPort);
  url::SchemeHostPort server4(url::kHttpsScheme, kServer4HostName,
                              kDefaultServerPort);
  url::SchemeHostPort server5(url::kHttpsScheme, kServer5HostName,
                              kDefaultServerPort);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  // `server2` resolves to the same IP address via A/AAAA records, i.e. without
  // ALPN information.
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  // `server3` resolves to the same IP address, but only via an alternative
  // endpoint with matching ALPN.
  std::vector<HostResolverEndpointResult> endpoints(1);
  endpoints[0].ip_endpoints = {kRightIP};
  endpoints[0].metadata.supported_protocol_alpns = {kRightALPN};
  host_resolver_->rules()->AddRule(
      server3.host(),
      MockHostResolverBase::RuleResolver::RuleResult({std::move(endpoints)}));

  // `server4` resolves to the same IP address, but only via an alternative
  // endpoint with a mismatching ALPN.
  endpoints = std::vector<HostResolverEndpointResult>(2);
  endpoints[0].ip_endpoints = {kRightIP};
  endpoints[0].metadata.supported_protocol_alpns = {kWrongALPN};
  endpoints[1].ip_endpoints = {kWrongIP};
  endpoints[1].metadata.supported_protocol_alpns = {kRightALPN};
  host_resolver_->rules()->AddRule(
      server4.host(),
      MockHostResolverBase::RuleResolver::RuleResult({std::move(endpoints)}));

  // `server5` resolves to the different IP address, and via an alternative
  // endpoint with a mismatching ALPN.
  endpoints = std::vector<HostResolverEndpointResult>(3);
  endpoints[0].ip_endpoints = {kWrongIP};
  endpoints[0].metadata.supported_protocol_alpns = {kWrongALPN};
  host_resolver_->rules()->AddRule(
      server5.host(),
      MockHostResolverBase::RuleResolver::RuleResult({std::move(endpoints)}));

  // Establish a QUIC session to pool against.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Receive origin frame on the session.
  quic::OriginFrame frame;
  frame.origins.push_back(base::StrCat({"https://", kServer2HostName}));
  frame.origins.push_back(base::StrCat({"https://", kServer3HostName}));
  frame.origins.push_back(base::StrCat({"https://", kServer4HostName}));
  frame.origins.push_back(base::StrCat({"https://", kServer5HostName}));
  GetActiveSession(kDefaultDestination)->OnOriginFrame(frame);
  ASSERT_EQ(4u,
            GetActiveSession(kDefaultDestination)->received_origins().size());

  // `server2` can pool with the existing session. Although the endpoint does
  // not specify ALPN, we connect here with preexisting knowledge of the version
  // (from Alt-Svc), so an A/AAAA match is sufficient.
  TestCompletionCallback callback;
  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());
  EXPECT_EQ(GetActiveSession(kDefaultDestination), GetActiveSession(server2));

  // `server3` can pool with the existing session. The endpoint's ALPN protocol
  // matches.
  RequestBuilder builder3(this);
  builder3.destination = server3;
  builder3.url = GURL(kServer3Url);
  EXPECT_EQ(OK, builder3.CallRequest());
  std::unique_ptr<HttpStream> stream3 = CreateStream(&builder3.request);
  EXPECT_TRUE(stream3.get());
  EXPECT_EQ(GetActiveSession(kDefaultDestination), GetActiveSession(server3));

  // `server4` can pool with the existing session. Although the IP is different,
  // it is included in the received origins.
  RequestBuilder builder4(this);
  builder4.destination = server4;
  builder4.url = GURL(kServer4Url);
  EXPECT_EQ(OK, builder4.CallRequest());
  std::unique_ptr<HttpStream> stream4 = CreateStream(&builder4.request);
  EXPECT_TRUE(stream4.get());
  EXPECT_EQ(GetActiveSession(kDefaultDestination), GetActiveSession(server4));

  // `server5` cannot pool with the existing session. Although it is in the
  // received origins, if we connect without prior knowledge of QUIC support,
  // endpoints are only eligible for cross-name pooling when associated with a
  // QUIC ALPN.
  //
  // Without pooling, the DNS response is insufficient to start a QUIC
  // connection, so the connection will fail.
  RequestBuilder builder5(this);
  builder5.destination = server5;
  builder5.quic_version = quic::ParsedQuicVersion::Unsupported();
  builder5.require_dns_https_alpn = true;
  builder5.url = GURL(kServer5Url);
  EXPECT_EQ(ERR_DNS_NO_MATCHING_SUPPORTED_ALPN, builder5.CallRequest());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, PoolingSkipDns) {
  quic_params_->supported_versions = {version_};
  quic_params_->enable_origin_frame = true;
  quic_params_->skip_dns_with_origin_frame = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  const std::string kRightALPN = quic::AlpnForVersion(version_);
  const std::string kWrongALPN = "h2";

  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName,
                              kDefaultServerPort);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  // Establish a QUIC session to pool against.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Receive origin frame on the session.
  quic::OriginFrame frame;
  frame.origins.push_back(base::StrCat({"https://", kServer2HostName}));
  GetActiveSession(kDefaultDestination)->OnOriginFrame(frame);
  ASSERT_EQ(1u,
            GetActiveSession(kDefaultDestination)->received_origins().size());

  // `server2` can pool with the existing session and DNS gets skipped.
  TestCompletionCallback callback;
  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());
  EXPECT_EQ(GetActiveSession(kDefaultD
"""


```
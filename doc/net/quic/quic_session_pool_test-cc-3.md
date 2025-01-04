Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/quic/quic_session_pool_test.cc`. The snippet contains several test cases for the `QuicSessionPool` class in Chromium's network stack. I need to identify the purpose of each test and look for any connections to JavaScript, logical deductions, potential user errors, and debugging information.

**Plan:**

1. **Iterate through each `TEST_P` block:**  Each block represents a test case.
2. **Summarize the functionality of each test:** Focus on what the test is verifying regarding the `QuicSessionPool`.
3. **Look for JavaScript relevance:**  QUIC is a transport protocol, unlikely to have direct JavaScript interaction, but I'll keep an eye out for anything related to web APIs or browser behavior.
4. **Identify logical deductions:**  Analyze the `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_EQ` assertions to understand the expected outcomes based on the test setup. I'll consider the "Arrange, Act, Assert" pattern.
5. **Find common usage errors:** Consider scenarios where a user or programmer might misuse the QUIC API or encounter unexpected behavior based on the test conditions.
6. **Trace user operations:**  Think about how a user's actions in a browser could lead to the execution of this code (e.g., navigating to a website, encountering network issues).
7. **Synthesize the overall functionality:** Combine the individual test summaries into a concise description of the code's purpose.
这是 chromium 网络栈的源代码文件 `net/quic/quic_session_pool_test.cc` 的一部分，主要功能是 **测试 `QuicSessionPool` 类的各种行为和功能**。`QuicSessionPool` 负责管理和复用 QUIC 会话。

以下是这段代码片段中各个测试用例的功能归纳：

* **`WriteErrorInCryptoConnectWithAsyncHostResolutionAsyncSessionCreation`**:  测试在加密连接握手过程中（发送 CHLO 包时）发生写错误（例如 `ERR_ADDRESS_UNREACHABLE`），并且主机名解析和 QUIC 会话创建都是异步的情况。测试验证在这种错误情况下，请求会失败，并且后续请求可以正常发送。
* **`WriteErrorInCryptoConnectWithSyncHostResolutionSyncQuicSession`**: 测试在加密连接握手过程中发生写错误，并且主机名解析和 QUIC 会话创建都是同步的情况。测试验证错误发生后，请求立即失败，并且后续请求可以正常发送。
* **`WriteErrorInCryptoConnectWithSyncHostResolutionAsyncQuicSession`**: 测试在加密连接握手过程中发生写错误，并且主机名解析是同步的，但 QUIC 会话创建是异步的情况。测试验证错误发生后，请求会进入挂起状态然后失败，并且后续请求可以正常发送。
* **`CloseSessionDuringCreation`**:  回归测试，用于验证在 QUIC 会话创建完成（`FinishCreateSession` 运行后），但在 IP 地址改变通知到达之前，如果会话被关闭，不会发生崩溃。模拟了 IP 地址改变导致会话关闭的情况。
* **`CloseSessionsOnIPAddressChanged`**: 测试当 `close_sessions_on_ip_change` 参数设置为 true 时，当检测到 IP 地址改变时，现有的 QUIC 会话会被立即关闭。新的请求会建立新的会话。
* **`GoAwaySessionsOnIPAddressChanged`**: 测试当 `goaway_sessions_on_ip_change` 参数设置为 true 时，当检测到 IP 地址改变时，现有的 QUIC 会话会被标记为 "going away"，而不是立即关闭。新的请求会建立新的会话，但旧的会话仍然可以完成正在进行的请求。
* **`OnIPAddressChangedWithConnectionMigration`**: 测试在启用连接迁移 (V2) 的情况下，当 IP 地址改变时，现有的连接不会受到影响。新的请求仍然可以使用相同的连接。
* **`MigrateOnNetworkMadeDefaultWithSynchronousWrite`**: 测试当一个网络被设置为默认网络，并且在 `OnNetworkMadeDefault` 通知到达会话之前，最后一个写操作是同步的时，连接迁移是否能成功进行。
* **`MigrateOnNetworkMadeDefaultWithAsyncWrite`**: 测试当一个网络被设置为默认网络，并且在 `OnNetworkMadeDefault` 通知到达会话之前，最后一个写操作是异步的时，连接迁移是否能成功进行。
* **`TestMigrationOnNetworkMadeDefault(IoMode write_mode)`**:  这是一个辅助函数，被上面两个测试用例调用，用于设置和执行在网络被设置为默认网络时进行连接迁移的测试。它模拟了连接迁移的流程，包括发送探测包、接收响应以及重传数据。
* **`MigratedToBlockedSocketAfterProbing`**:  这是一个回归测试，验证了当连接迁移到新的网络套接字后，如果新的套接字处于阻塞状态，writer 不会尝试写入数据，直到套接字解除阻塞。它模拟了在连接迁移过程中，探测 writer 被阻塞的情况。

**与 JavaScript 的关系：**

这段 C++ 代码直接处理底层的网络协议，与 JavaScript 没有直接的功能关联。JavaScript 通过浏览器提供的 Web API (例如 `fetch`) 发起网络请求，这些请求最终可能会使用 QUIC 协议，并由底层的 C++ 代码处理。

**举例说明:**

假设一个用户在浏览器中访问一个使用 QUIC 协议的网站。当用户的网络环境发生变化，例如从 Wi-Fi 切换到移动数据网络，浏览器底层的 QUIC 实现（由 `QuicSessionPool` 管理）可能需要处理这个变化。

* **`CloseSessionsOnIPAddressChanged` 的场景:**  如果浏览器配置了在 IP 地址改变时关闭旧的 QUIC 连接，那么当网络切换时，JavaScript 发起的新的 `fetch` 请求将建立一个新的 QUIC 连接。
* **`GoAwaySessionsOnIPAddressChanged` 的场景:**  如果浏览器配置为 "go away" 旧连接，那么在网络切换时，当前正在进行的 JavaScript `fetch` 请求可能会在旧的连接上完成，而新的 `fetch` 请求将使用新的连接。
* **`OnIPAddressChangedWithConnectionMigration` 的场景:** 如果浏览器支持连接迁移，并且网络切换是平滑的，那么 JavaScript 发起的 `fetch` 请求可能不会中断，底层的 QUIC 连接会迁移到新的网络接口。

**逻辑推理、假设输入与输出:**

以 `WriteErrorInCryptoConnectWithAsyncHostResolutionAsyncSessionCreation` 为例：

* **假设输入:**
    * 请求目标服务器的主机名和端口。
    * 模拟的网络环境，在发送 CHLO 包时返回 `ERR_ADDRESS_UNREACHABLE` 的写错误。
    * 主机名解析器和 QUIC 会话创建机制都是异步的。
* **逻辑推理:**
    1. 尝试建立 QUIC 连接，发送 CHLO 包。
    2. 由于网络错误，CHLO 包发送失败。
    3. 连接握手失败，请求回调收到 `ERR_QUIC_HANDSHAKE_FAILED`。
    4. `QuicSessionPool` 中没有为此目标服务器的活跃会话或正在进行的任务。
    5. 发起新的请求，主机名解析和 QUIC 会话创建都是异步的。
    6. 完成新的连接握手。
    7. `QuicSessionPool` 中存在为此目标服务器的活跃会话，但没有正在进行的任务。
    8. 可以创建新的 `HttpStream`。
* **预期输出:**
    * 第一个请求的回调结果是 `ERR_QUIC_HANDSHAKE_FAILED`。
    * 在第一个请求失败后，`HasActiveSession` 返回 `false`，`HasActiveJob` 返回 `false`。
    * 第二个请求的回调结果是 `OK`。
    * 在第二个请求成功后，`HasActiveSession` 返回 `true`，`HasActiveJob` 返回 `false`。

**用户或编程常见的使用错误:**

这段代码主要测试网络栈内部的逻辑，用户或开发者直接使用 `QuicSessionPool` 的场景较少。但以下是一些可能相关的错误：

* **配置错误:**  如果开发者错误地配置了 QUIC 参数，例如错误地设置了是否在 IP 地址改变时关闭会话，可能会导致意外的网络行为。例如，如果期望连接能够迁移，但却配置了在 IP 地址改变时关闭会话，会导致连接中断。
* **网络环境假设错误:**  开发者在进行网络编程时，可能会对用户的网络环境做出错误的假设，例如假设网络永远稳定。这段测试代码模拟了各种网络错误和变化的情况，提醒开发者考虑这些情况。
* **调试困难:**  底层的网络协议问题通常难以调试。这段测试代码提供了各种场景的测试用例，可以帮助开发者理解在不同情况下 `QuicSessionPool` 的行为，从而更好地定位问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入网址并回车**，或者点击一个链接。
2. **浏览器解析 URL，获取目标服务器的主机名和端口。**
3. **浏览器查询本地 DNS 缓存或者发起 DNS 查询，解析主机名到 IP 地址。** (在异步主机名解析的测试用例中，这个过程可能是异步的)
4. **浏览器根据协议判断是否可以使用 QUIC。**
5. **如果可以使用 QUIC，浏览器会尝试从 `QuicSessionPool` 中查找是否有可复用的现有会话。**
6. **如果没有可复用的会话，`QuicSessionPool` 会创建一个新的 `QuicSession::Job` 来建立新的 QUIC 会话。** (在异步会话创建的测试用例中，这个过程是异步的)
7. **在建立连接的过程中，可能会遇到网络错误，例如地址不可达。** (对应 `WriteErrorInCryptoConnect` 相关的测试用例)
8. **如果用户的网络环境发生变化，例如 IP 地址改变，`QuicSessionPool` 会根据配置采取相应的措施，例如关闭旧会话或者迁移连接。** (对应 `CloseSessionsOnIPAddressChanged`, `GoAwaySessionsOnIPAddressChanged`, `OnIPAddressChangedWithConnectionMigration` 相关的测试用例)

当调试 QUIC 相关问题时，可以关注以下几点：

* **网络事件:**  使用浏览器的网络面板 (Chrome DevTools) 查看网络请求的详细信息，包括是否使用了 QUIC，连接状态等。
* **QUIC Internal Log:** Chromium 提供了 QUIC 内部日志，可以记录 QUIC 连接的详细信息，包括握手过程、数据传输、错误信息等。
* **网络环境模拟:**  可以使用网络模拟工具 (例如 Chromium 的网络模拟功能) 来模拟不同的网络状况，例如延迟、丢包、IP 地址改变等，来复现问题。
* **查看 `QuicSessionPool` 的状态:**  虽然不能直接查看运行时的 `QuicSessionPool` 状态，但可以通过日志或者添加断点的方式，理解 `QuicSessionPool` 在不同场景下的行为。

**归纳其功能:**

这段代码是 `net/quic/quic_session_pool_test.cc` 文件的一部分，主要功能是 **对 `QuicSessionPool` 类在各种网络错误和网络环境变化情况下的行为进行全面的单元测试**。它覆盖了连接建立失败、IP 地址改变时的会话管理、连接迁移等关键场景，确保 `QuicSessionPool` 能够正确地管理和复用 QUIC 会话，并能应对各种异常情况，保证网络连接的稳定性和可靠性。

Prompt: 
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共20部分，请归纳一下它的功能

"""
t_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  // Create QuicHttpStream.
  std::unique_ptr<HttpStream> stream = CreateStream(&builder2.request);
  EXPECT_TRUE(stream.get());
  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       WriteErrorInCryptoConnectWithAsyncHostResolutionAsyncSessionCreation) {
  Initialize();
  // Use unmocked crypto stream to do crypto connect.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  // Trigger PACKET_WRITE_ERROR when sending packets in crypto connect.
  socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request, should fail after the write of the CHLO fails.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_EQ(ERR_QUIC_HANDSHAKE_FAILED, callback_.WaitForResult());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  // Verify new requests can be sent normally without hanging.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  // Run the message loop to complete host resolution.
  base::RunLoop().RunUntilIdle();

  // Complete handshake. QuicSessionPool::Job should complete and succeed.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  // Create QuicHttpStream.
  std::unique_ptr<HttpStream> stream = CreateStream(&builder2.request);
  EXPECT_TRUE(stream.get());
  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       WriteErrorInCryptoConnectWithSyncHostResolutionSyncQuicSession) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);
  Initialize();
  // Use unmocked crypto stream to do crypto connect.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  // Trigger PACKET_WRITE_ERROR when sending packets in crypto connect.
  socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request, should fail immediately.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_QUIC_HANDSHAKE_FAILED, builder.CallRequest());
  // Check no active session, or active jobs left for this server.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  // Verify new requests can be sent normally without hanging.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  base::RunLoop().RunUntilIdle();
  // Complete handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  // Create QuicHttpStream.
  std::unique_ptr<HttpStream> stream = CreateStream(&builder2.request);
  EXPECT_TRUE(stream.get());
  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       WriteErrorInCryptoConnectWithSyncHostResolutionAsyncQuicSession) {
  Initialize();
  // Use unmocked crypto stream to do crypto connect.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  // Trigger PACKET_WRITE_ERROR when sending packets in crypto connect.
  socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request, should fail immediately.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_EQ(ERR_QUIC_HANDSHAKE_FAILED, callback_.WaitForResult());
  // Check no active session, or active jobs left for this server.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  // Verify new requests can be sent normally without hanging.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  base::RunLoop().RunUntilIdle();
  // Complete handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  // Create QuicHttpStream.
  std::unique_ptr<HttpStream> stream = CreateStream(&builder2.request);
  EXPECT_TRUE(stream.get());
  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// Regression test for crbug.com/1409382. Test that OnCreateSessionComplete()
// will not crash if sessions are closed after FinishCreateSession runs.
TEST_P(QuicSessionPoolTest, CloseSessionDuringCreation) {
  quic_params_->close_sessions_on_ip_change = true;
  // close_sessions_on_ip_change == true requires
  // migrate_sessions_on_network_change_v2 == false.
  quic_params_->migrate_sessions_on_network_change_v2 = false;
  auto factory = MockQuicSessionPool(
      net_log_.net_log(), host_resolver_.get(), &ssl_config_service_,
      socket_factory_.get(), http_server_properties_.get(),
      cert_verifier_.get(), &transport_security_state_, proxy_delegate_.get(),
      /*sct_auditing_delegate=*/nullptr,
      /*SocketPerformanceWatcherFactory*/ nullptr,
      &crypto_client_stream_factory_, &context_);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  if (VersionUsesHttp3(version_.transport_version)) {
    socket_data.AddWrite(SYNCHRONOUS,
                         ConstructInitialSettingsPacket(packet_num++));
  }
  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num)
          .AddConnectionCloseFrame(quic::QUIC_IP_ADDRESS_CHANGED, "net error")
          .Build());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this, &factory);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  // QuicSessionPool should be notified of IP address change after
  // FinishConnectAndConfigureSocket runs FinishCreateSession.
  EXPECT_CALL(factory, MockFinishConnectAndConfigureSocket()).WillOnce([] {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  });

  // Session should have been created before the factory is notified of IP
  // address change.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  quic::QuicServerId server_id(kDefaultServerHostName, kDefaultServerPort);
  EXPECT_TRUE(QuicSessionPoolPeer::HasActiveSession(
      &factory, server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey()));
  QuicChromiumClientSession* session = QuicSessionPoolPeer::GetActiveSession(
      &factory, server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey());
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(&factory, session));

  base::RunLoop().RunUntilIdle();

  // Session should now be closed.
  EXPECT_FALSE(QuicSessionPoolPeer::HasActiveSession(
      &factory, server_id, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey()));
}

TEST_P(QuicSessionPoolTest, CloseSessionsOnIPAddressChanged) {
  quic_params_->close_sessions_on_ip_change = true;
  // close_sessions_on_ip_change == true requires
  // migrate_sessions_on_network_change_v2 == false.
  quic_params_->migrate_sessions_on_network_change_v2 = false;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num)
          .AddConnectionCloseFrame(quic::QUIC_IP_ADDRESS_CHANGED, "net error")
          .Build());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  // Check an active session exists for the destination.
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));

  EXPECT_TRUE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());
  // Change the IP address and verify that stream saw the error and the active
  // session is closed.
  NotifyIPAddressChanged();
  EXPECT_EQ(ERR_NETWORK_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_FALSE(factory_->has_quic_ever_worked_on_current_network());
  EXPECT_FALSE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());
  // Check no active session exists for the destination.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));

  // Now attempting to request a stream to the same origin should create
  // a new session.
  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  stream = CreateStream(&builder2.request);

  // Check a new active session exists for the destination and the old session
  // is no longer live.
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  QuicChromiumClientSession* session2 = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session2));

  stream.reset();  // Will reset stream 3.
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// Test that if goaway_session_on_ip_change is set, old sessions will be marked
// as going away on IP address change instead of being closed. New requests will
// go to a new connection.
TEST_P(QuicSessionPoolTest, GoAwaySessionsOnIPAddressChanged) {
  quic_params_->goaway_sessions_on_ip_change = true;
  // close_sessions_on_ip_change == true requires
  // migrate_sessions_on_network_change_v2 == false.
  quic_params_->migrate_sessions_on_network_change_v2 = false;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData quic_data1(version_);
  int packet_num = 1;
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_num++));
  quic_data1.AddWrite(
      SYNCHRONOUS,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddReadPause();
  quic_data1.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddReadPauseForever();
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  client_maker_.Reset();
  MockQuicData quic_data2(version_);
  quic_data2.AddReadPauseForever();
  quic_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(1));
  quic_data2.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL(kDefaultUrl);
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Receive an IP address change notification.
  NotifyIPAddressChanged();

  // The connection should still be alive, but marked as going away.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Resume the data, response should be read from the original connection.
  quic_data1.Resume();
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());
  EXPECT_EQ(0u, session->GetNumActiveStreams());

  // Second request should be sent on a new connection.
  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  // Check an active session exists for the destination.
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  QuicChromiumClientSession* session2 = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session2));

  stream.reset();
  stream2.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, OnIPAddressChangedWithConnectionMigration) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));

  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  EXPECT_TRUE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());

  // Change the IP address and verify that the connection is unaffected.
  NotifyIPAddressChanged();
  EXPECT_TRUE(factory_->has_quic_ever_worked_on_current_network());
  EXPECT_TRUE(http_server_properties_->HasLastLocalAddressWhenQuicWorked());

  // Attempting a new request to the same origin uses the same connection.
  RequestBuilder builder2(this);
  EXPECT_EQ(OK, builder2.CallRequest());
  stream = CreateStream(&builder2.request);

  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, MigrateOnNetworkMadeDefaultWithSynchronousWrite) {
  TestMigrationOnNetworkMadeDefault(SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest, MigrateOnNetworkMadeDefaultWithAsyncWrite) {
  TestMigrationOnNetworkMadeDefault(ASYNC);
}

// Sets up a test which attempts connection migration successfully after probing
// when a new network is made as default and the old default is still available.
// |write_mode| specifies the write mode for the last write before
// OnNetworkMadeDefault is delivered to session.
void QuicSessionPoolTest::TestMigrationOnNetworkMadeDefault(IoMode write_mode) {
  InitializeConnectionMigrationV2Test({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->QueueNetworkMadeDefault(kDefaultNetworkForTests);

  MockQuicData quic_data1(version_);
  quic_data1.AddReadPauseForever();
  int packet_num = 1;
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_num++));
  quic_data1.AddWrite(
      write_mode,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the second socket data provider that is used after migration.
  // The response to the earlier request is read on the new socket.
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
  MockQuicData quic_data2(version_);
  // Connectivity probe to be sent on the new path.
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                       .AddPathChallengeFrame()
                                       .AddPaddingFrame()
                                       .Build());
  quic_data2.AddReadPause();
  // Connectivity probe to receive from the server.
  quic_data2.AddRead(
      ASYNC,
      server_maker_.Packet(1).AddPathResponseFrame().AddPaddingFrame().Build());
  // in-flight SETTINGS and requests will be retransmitted. Since data is
  // already sent on the new address, ping will no longer be sent.
  quic_data2.AddWrite(ASYNC,
                      client_maker_.MakeCombinedRetransmissionPacket(
                          /*original_packet_numbers=*/{1, 2}, packet_num++));
  quic_data2.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), false));
  quic_data2.AddReadPauseForever();
  quic_data2.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddAckFrame(/*first_received=*/1, /*largest_received=*/2,
                       /*smallest_received=*/2)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  quic_data2.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL(kDefaultUrl);
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Deliver a signal that a alternate network is connected now, this should
  // cause the connection to start early migration on path degrading.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->SetConnectedNetworksList(
          {kDefaultNetworkForTests, kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkConnected(kNewNetworkForTests);

  // Cause the connection to report path degrading to the session.
  // Due to lack of alternate network, session will not migrate connection.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  // A task was posted to migrate to the new default network. Execute that task.
  task_runner->RunUntilIdle();

  // The connection should still be alive, and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Resume quic data and a connectivity probe response will be read on the new
  // socket, declare probing as successful. And a new task to WriteToNewSocket
  // will be posted to complete migration.
  quic_data2.Resume();

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // There should be a task that will complete the migration to the new network.
  task_runner->RunUntilIdle();

  // Response headers are received over the new network.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Verify that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

// Regression test for http://859674.
// This test veries that a writer will not attempt to write packets until being
// unblocked on both socket level and network level. In this test, a probing
// writer is used to send two connectivity probes to the peer: where the first
// one completes successfully, while a connectivity response is received before
// completes sending the second one. The connection migration attempt will
// proceed while the probing writer is blocked at the socket level, which will
// block the writer on the network level. Once connection migration completes
// successfully, the probing writer will be unblocked on the network level, it
// will not attempt to write new packets until the socket level is unblocked.
TEST_P(QuicSessionPoolTest, MigratedToBlockedSocketAfterProbing) {
  InitializeConnectionMigrationV2Test({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->QueueNetworkMadeDefault(kDefaultNetworkForTests);

  MockQuicData quic_data1(version_);
  quic_data1.AddReadPauseForever();
  int packet_num = 1;
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_num++));
  quic_data1.AddWrite(
      SYNCHRONOUS,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the second socket data provider that is used after migration.
  // The response to the earlier request is read on the new socket.
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
  MockQuicData quic_data2(version_);
  // First connectivity probe to be sent on the new path.
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                       .AddPathChallengeFrame()
                                       .AddPaddingFrame()
                                       .Build());
  quic_data2.AddRead(ASYNC,
                     ERR_IO_PENDING);  // Pause so that we can control time.
  // Connectivity probe to receive from the server.
  quic_data2.AddRead(
      ASYNC,
      server_maker_.Packet(1).AddPathResponseFrame().AddPaddingFrame().Build());
  // Second connectivity probe which will complete asynchronously.
  quic_data2.AddWrite(ASYNC, client_maker_.Packet(packet_num++)
                                 .AddPathChallengeFrame()
                                 .AddPaddingFrame()
                                 .Build());
  quic_data2.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), false));
  quic_data2.AddReadPauseForever();

  quic_data2.AddWrite(ASYNC,
                      client_maker_.MakeCombinedRetransmissionPacket(
                          /*original_packet_numbers=*/{1, 2}, packet_num++));
  quic_data2.AddWrite(SYNCHRONOUS,
                      client_maker_.Packet(packet_num++)
                          .AddAckFrame(/*first_received=*/1,
                                       /*largest_received=*/2,
                                       /*smallest_received=*/1)
                          .AddRetireConnectionIdFrame(/*sequence_number=*/0u)
                          .Build());
  quic_data2.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());

  quic_data2.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL(kDefaultUrl);
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, s
"""


```
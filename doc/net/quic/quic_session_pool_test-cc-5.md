Response:
My thought process for analyzing the provided code snippet and generating the summary goes through these stages:

1. **Identify the Core Functionality:** The filename `net/quic/quic_session_pool_test.cc` immediately signals that this is a test file for the `QuicSessionPool` component within Chromium's networking stack. The presence of `TEST_P` indicates it's using Google Test parameterized tests, allowing for running the same test logic with different parameter sets (likely QUIC versions in this context, though not explicitly shown in the snippet).

2. **Recognize the Focus:** The code is heavily focused on connection migration. Keywords like `MigrateOnDefaultNetworkDisconnected`, `MigrateOnPathDegrading`, `NewNetworkConnectedAfterNoNetwork`, `MigrateToProbingSocket`, and the use of `scoped_mock_network_change_notifier_` are strong indicators. The tests simulate network events (disconnection, path degradation, new connections) and verify how the `QuicSessionPool` handles these scenarios.

3. **Analyze Individual Test Cases:** I examine each `TEST_P` function to understand its specific purpose:
    * `MigrateOnDefaultNetworkDisconnectedWithAsyncWrite`: This test checks if connection migration works correctly when there's an asynchronous write pending *before* the migration trigger. The `async_write_before` parameter controls this.
    * `MigrateOnDefaultNetworkDisconnectedWithProxiedSession`:  This explores a more complex scenario involving a proxied QUIC connection. It verifies that when the default network disconnects, the direct connection *and* the proxied connection (to the proxy server) handle the migration correctly, likely migrating the direct connection but potentially keeping the proxied connection alive on the original path if it's still available.
    * `MigrateOnPathDegradingWithProxiedSession`: Similar to the previous test, but it triggers migration based on path quality degradation instead of a complete disconnection.
    * `NewNetworkConnectedAfterNoNetwork`:  This addresses a scenario where the network is completely lost and then a new network becomes available. It tests the pool's ability to handle this transition.
    * `MigrateToProbingSocket`: This seems like a more specific regression test related to the probing process during connection migration. It aims to ensure that certain actions during probing don't cause errors.

4. **Identify Common Patterns and Key Concepts:** Across these tests, I notice recurring patterns:
    * **Mocking:** The tests heavily rely on mocking, particularly `MockQuicData` and `scoped_mock_network_change_notifier_`, to simulate network behavior and control the test environment.
    * **Session Management:**  The tests frequently check the liveness and activity of `QuicChromiumClientSession` objects using methods like `GetActiveSession` and `QuicSessionPoolPeer::IsLiveSession`.
    * **Stream Creation and Usage:**  The creation and use of `HttpStream` objects are central to triggering QUIC stream activity and observing the impact of connection migration.
    * **Packet Construction:**  The tests use `QuicTestPacketMaker` to craft specific QUIC packets for simulating communication with the server.
    * **Asynchronous Operations:** The use of `CompletionOnceCallback` and `callback_.WaitForResult()` highlights the asynchronous nature of network operations.
    * **Network Change Notifications:** The `scoped_mock_network_change_notifier_` is crucial for simulating network events that trigger connection migration.

5. **Look for JavaScript Relevance:**  I consider how QUIC and these tests might relate to JavaScript. While the core implementation is in C++, the networking stack is used by the Chromium browser, which runs JavaScript. Therefore, any network issues, including migration problems, can affect JavaScript-based web applications. Specific examples would be:
    * A dropped connection during a fetch request initiated by JavaScript.
    * A delay or failure during a WebSocket connection established by JavaScript.
    * Issues with streaming data accessed via JavaScript.

6. **Infer Assumptions, Inputs, and Outputs:** Although the full test logic isn't shown, I can infer:
    * **Inputs:** Network state changes (connect, disconnect, degrade), HTTP requests, QUIC protocol parameters.
    * **Outputs:**  Success or failure of HTTP requests, establishment or termination of QUIC connections, correct migration of connections to new networks.

7. **Consider User/Programming Errors:**  I think about potential mistakes:
    * Incorrectly configuring network settings on the user's machine.
    * Flaky network connections causing unexpected migrations.
    * Bugs in the QUIC implementation that these tests aim to catch.

8. **Trace User Operations:** I imagine a user scenario: a user browsing a website on a laptop that switches between Wi-Fi and cellular networks. This triggers the network events simulated in the tests.

9. **Synthesize the Summary:** Finally, I combine all the observations and analysis into a concise summary that covers the key functionalities, relationships to JavaScript, logical reasoning, potential errors, and user actions leading to these scenarios. I also acknowledge the context of being part 6 of a larger set of tests.
这是 Chromium 网络栈中 `net/quic/quic_session_pool_test.cc` 文件的第 6 部分，主要侧重于 **QUIC 会话池在网络连接迁移场景下的行为测试**，特别是当存在代理连接时的迁移。

**本部分的主要功能归纳如下：**

* **测试在默认网络断开连接时，直接连接和代理连接的迁移行为：**
    * `MigrateOnDefaultNetworkDisconnectedWithProxiedSession` 测试用例模拟了默认网络断开的情况，验证了直接连接会迁移到新网络，而代理连接（如果仍然可用）可能不会迁移。
    * 它验证了在这种情况下，两个会话（到目标服务器和到代理服务器）都应该保持活跃，并且数据能够在新连接上继续传输。
* **测试在路径质量下降时，直接连接和代理连接的迁移行为：**
    * `MigrateOnPathDegradingWithProxiedSession` 测试用例模拟了网络路径质量下降的情况。
    * 它验证了当检测到路径质量下降时，两个会话都会收到通知，并启动探测替代路径的过程。
    * 同样，它也验证了在这种情况下，两个会话都应该保持活跃，并且数据最终能够在新的、更好的连接上继续传输。
* **测试在没有网络连接后重新连接新网络的场景：**
    * `NewNetworkConnectedAfterNoNetwork` 测试用例模拟了网络完全断开后，又连接上新网络的情况。
    * 它验证了当没有可用网络迁移时，会话会等待新网络的连接。
    * 一旦新网络连接上，会话能够迁移到新网络并继续数据传输。
* **测试迁移到探测 Socket 的场景：**
    * `MigrateToProbingSocket` 测试用例是一个回归测试，旨在解决一个特定的 Bug（crbug.com/872011）。
    * 它验证了在连接迁移到探测 Socket 的过程中，不会因为同步读取新数据包而导致错误，避免在处理初始连接性探测响应时生成 ACK 帧，从而防止连接因内部错误而关闭。

**与 Javascript 功能的关系：**

虽然这段 C++ 代码本身不直接包含 Javascript，但它测试的网络功能是浏览器与 Web 服务器通信的基础。当 Javascript 发起网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`）时，底层的 Chromium 网络栈（包括 QUIC 协议的实现）会处理这些请求。

* **举例说明：** 假设一个 Javascript 应用程序正在通过 QUIC 连接从服务器下载一个大型文件。如果在下载过程中用户的网络从 Wi-Fi 断开并切换到移动网络，这段代码测试的逻辑就负责确保 QUIC 连接能够平滑地迁移到新的移动网络连接，而不会中断下载过程。如果迁移失败，Javascript 应用程序可能会收到网络错误，从而影响用户体验。

**逻辑推理（假设输入与输出）：**

以 `MigrateOnDefaultNetworkDisconnectedWithProxiedSession` 为例：

* **假设输入：**
    * 存在一个活跃的 QUIC 连接到目标服务器（`kDefaultDestination`）。
    * 存在一个通过代理的 QUIC 连接到代理服务器（`kProxy1Url`）。
    * 在目标服务器连接上有一个活跃的 HTTP 流。
    * 默认网络（`kDefaultNetworkForTests`）断开连接。
    * 存在一个可用的新网络（`kNewNetworkForTests`）。
* **预期输出：**
    * 到目标服务器的 QUIC 连接成功迁移到新网络。
    * 到代理服务器的 QUIC 连接保持在原来的网络上（假设代理连接没有受到影响）。
    * 正在进行的 HTTP 流能够在新连接上继续传输数据，最终成功接收到响应。
    * 两个 QUIC 会话都保持活跃状态。

**用户或编程常见的使用错误：**

这些测试主要关注 Chromium 内部的网络栈实现，用户或编程错误通常不会直接导致执行到这段特定的测试代码。然而，理解这些测试有助于开发者理解 QUIC 连接迁移的复杂性，并避免可能导致迁移问题的配置或使用方式：

* **用户错误：** 用户在使用移动设备时频繁切换网络（例如，从 Wi-Fi 到蜂窝网络，再到另一个 Wi-Fi），可能会触发连接迁移。如果底层的 QUIC 实现存在 Bug，可能导致连接不稳定或失败。这段代码的测试目标就是确保在这种用户场景下，连接迁移能够正常工作。
* **编程错误（在 Chromium 网络栈的开发中）：**  如果 QUIC 连接迁移的逻辑实现不正确，例如没有正确处理网络状态变化，或者在迁移过程中出现资源竞争或死锁，就可能导致连接失败。这些测试用例旨在发现并防止这类编程错误。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户发起一个需要 QUIC 连接的网络请求：** 例如，用户在 Chrome 浏览器中访问一个支持 QUIC 的网站。
2. **Chromium 网络栈尝试建立 QUIC 连接：** `QuicSessionPool` 负责管理和复用 QUIC 会话。
3. **网络环境发生变化：**
    * **默认网络断开：** 用户从连接的 Wi-Fi 断开，设备尝试切换到蜂窝网络。这会触发 `scoped_mock_network_change_notifier_->mock_network_change_notifier()->NotifyNetworkDisconnected(kDefaultNetworkForTests);` 这样的事件。
    * **路径质量下降：** 网络信号变弱或拥塞，导致数据包丢失率增加，触发 `destination_session->connection()->OnPathDegradingDetected();`。
    * **无网络后连接新网络：** 用户从无网络状态（例如在飞机上关闭 Wi-Fi 和蜂窝网络）切换到连接新的 Wi-Fi 网络。
4. **`QuicSessionPool` 接收到网络状态变化的通知：**  相关的逻辑会判断是否需要进行连接迁移。
5. **执行连接迁移的逻辑：**  `QuicSessionPool` 会尝试在新网络上建立新的连接或利用现有的连接。
6. **执行相关的测试代码：**  在开发和测试阶段，工程师会运行 `quic_session_pool_test.cc` 中的测试用例来验证连接迁移逻辑的正确性。这些测试通过模拟上述用户操作和网络环境变化来检查系统的行为。

**总结本部分的功能：**

总而言之，`net/quic/quic_session_pool_test.cc` 的第 6 部分专注于测试 Chromium QUIC 客户端在各种网络迁移场景下的稳定性和正确性，特别是当涉及到通过代理建立的 QUIC 连接时。它通过模拟不同的网络事件来验证连接池是否能够正确地管理和迁移 QUIC 会话，确保用户即使在网络环境变化的情况下也能获得流畅的网络体验。这些测试对于确保 QUIC 协议在实际网络环境中的可靠性至关重要。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
(stream.get());

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
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  if (async_write_before) {
    session->connection()->SendPing();
  }

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  MockQuicData socket_data1(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.MakeCombinedRetransmissionPacket({1, 2}, packet_number++));
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++).AddPingFrame().Build());
  socket_data1.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_number++)
                                         .AddRetireConnectionIdFrame(0u)
                                         .Build());
  socket_data1.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false));
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  socket_data1.AddSocketDataToFactory(socket_factory_.get());

  // Trigger connection migration.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  base::RunLoop().RunUntilIdle();
  // The connection should still be alive, not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Ensure that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  runner_->RunNextTask();

  // Response headers are received over the new network.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Check that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // There should be posted tasks not executed, which is to migrate back to
  // default network.
  EXPECT_FALSE(runner_->GetPostedTasks().empty());

  // Receive signal to mark new network as default.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
}

// This test verifies a direct session carrying a proxied session migrates when
// the default network disconnects, but the proxied session does not migrate.
TEST_P(QuicSessionPoolTest,
       MigrateOnDefaultNetworkDisconnectedWithProxiedSession) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kDefaultNetworkForTests);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);
  client_maker_.set_use_priority_header(false);

  GURL proxy(kProxy1Url);
  auto proxy_origin = url::SchemeHostPort(proxy);
  auto proxy_chain = ProxyChain::ForIpProtection({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::SCHEME_QUIC,
                                         proxy_origin.host(), 443),
  });
  EXPECT_TRUE(proxy_chain.IsValid());

  // Use the test task runner.
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), runner_.get());

  // Use a separate packet maker for the connection to the endpoint.
  QuicTestPacketMaker to_endpoint_maker(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true,
      /*use_priority_header=*/true);
  QuicTestPacketMaker from_endpoint_maker(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), "mail.example.org", quic::Perspective::IS_SERVER,
      /*client_priority_uses_incremental=*/false,
      /*use_priority_header=*/true);

  int to_proxy_packet_num = 1;
  int from_proxy_packet_num = 1;
  int to_endpoint_packet_num = 1;
  int from_endpoint_packet_num = 1;
  const uint64_t stream_id = GetNthClientInitiatedBidirectionalStreamId(0);
  QuicSocketDataProvider socket_data(version_);
  socket_data
      .AddWrite("initial-settings",
                ConstructInitialSettingsPacket(to_proxy_packet_num++))
      .Sync();
  socket_data
      .AddWrite("connect-udp",
                ConstructConnectUdpRequestPacket(
                    to_proxy_packet_num++, stream_id, proxy.host(),
                    "/.well-known/masque/udp/www.example.org/443/", false))
      .Sync();
  socket_data.AddRead("server-settings",
                      ConstructServerSettingsPacket(from_proxy_packet_num++));
  socket_data.AddRead(
      "connect-ok-response",
      ConstructOkResponsePacket(from_proxy_packet_num++, stream_id, true));

  socket_data.AddWrite(
      "ack-ok",
      client_maker_.Packet(to_proxy_packet_num++).AddAckFrame(1, 2, 1).Build());

  quiche::HttpHeaderBlock headers =
      to_endpoint_maker.GetRequestHeaders("GET", "https", "/");
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  socket_data.AddWrite(
      "initial-settings-and-get",
      client_maker_.Packet(to_proxy_packet_num++)
          .AddMessageFrame(ConstructClientH3DatagramFrame(
              stream_id, kConnectUdpContextId,
              to_endpoint_maker.MakeInitialSettingsPacket(
                  to_endpoint_packet_num++)))
          .AddMessageFrame(ConstructClientH3DatagramFrame(
              stream_id, kConnectUdpContextId,
              to_endpoint_maker.MakeRequestHeadersPacket(
                  to_endpoint_packet_num++, stream_id, /*fin=*/true, priority,
                  std::move(headers), nullptr)))
          .Build());

  socket_factory_->AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  builder.proxy_chain = proxy_chain;
  builder.http_user_agent_settings = &http_user_agent_settings_;
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

  // Ensure that session to the destination is alive and active.
  QuicChromiumClientSession* destination_session =
      GetActiveSession(kDefaultDestination, PRIVACY_MODE_DISABLED,
                       NetworkAnonymizationKey(), proxy_chain);
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), destination_session));

  // Ensure that the session to the proxy is alive and active.
  QuicChromiumClientSession* proxy_session = GetActiveSession(
      proxy_origin, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      ProxyChain::ForIpProtection({}), SessionUsage::kProxy);
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), proxy_session));
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, proxy_session);

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  QuicSocketDataProvider socket_data1(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  socket_data1
      .AddWrite("retransmit", client_maker_.MakeCombinedRetransmissionPacket(
                                  {1, 2}, to_proxy_packet_num++))
      .Sync();
  socket_data1
      .AddWrite(
          "ping",
          client_maker_.Packet(to_proxy_packet_num++).AddPingFrame().Build())
      .Sync();
  socket_data1
      .AddWrite("retire-cid", client_maker_.Packet(to_proxy_packet_num++)
                                  .AddRetireConnectionIdFrame(0u)
                                  .Build())
      .Sync();
  quiche::HttpHeaderBlock response_headers =
      from_endpoint_maker.GetResponseHeaders("200");
  socket_data1.AddRead(
      "proxied-ok-response",
      server_maker_.Packet(from_proxy_packet_num++)
          .AddMessageFrame(ConstructClientH3DatagramFrame(
              stream_id, kConnectUdpContextId,
              from_endpoint_maker.MakeResponseHeadersPacket(
                  from_endpoint_packet_num++, stream_id, /*fin=*/true,
                  std::move(response_headers), nullptr)))
          .Build());

  socket_factory_->AddSocketDataProvider(&socket_data1);

  // Trigger connection migration.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  base::RunLoop().RunUntilIdle();

  // Both sessions should still be alive, not marked as going away.
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), destination_session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination, PRIVACY_MODE_DISABLED,
                               NetworkAnonymizationKey(), proxy_chain));
  EXPECT_EQ(1u, destination_session->GetNumActiveStreams());
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), proxy_session));
  EXPECT_EQ(1u, proxy_session->GetNumActiveStreams());

  // Begin reading the response, which only appears on the new connection,
  // verifying the session to the proxy migrated.
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Ensure that the session to the destination is still alive.
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), destination_session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination, PRIVACY_MODE_DISABLED,
                               NetworkAnonymizationKey(), proxy_chain));
  EXPECT_EQ(1u, destination_session->GetNumActiveStreams());
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), proxy_session));
  EXPECT_EQ(1u, proxy_session->GetNumActiveStreams());

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  runner_->RunNextTask();

  // Wait for the response headers to be read; this must occur over the new
  // connection.
  ASSERT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Check that the sessions are still alive.
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), destination_session));
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), proxy_session));

  // There should be posted tasks not executed, which is to migrate back to
  // default network.
  EXPECT_FALSE(runner_->GetPostedTasks().empty());

  // Receive signal to mark new network as default.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  stream.reset();
  EXPECT_TRUE(socket_data.AllDataConsumed());
  EXPECT_TRUE(socket_data1.AllDataConsumed());
}

// This test verifies a direct session carrying a proxied session migrates when
// the default network disconnects, but the proxied session does not migrate.
TEST_P(QuicSessionPoolTest, MigrateOnPathDegradingWithProxiedSession) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kDefaultNetworkForTests);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);
  client_maker_.set_use_priority_header(false);
  client_maker_.set_max_plaintext_size(1350);
  server_maker_.set_max_plaintext_size(1350);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  GURL proxy(kProxy1Url);
  auto proxy_origin = url::SchemeHostPort(proxy);
  auto proxy_chain = ProxyChain::ForIpProtection({
      ProxyServer::FromSchemeHostAndPort(ProxyServer::SCHEME_QUIC,
                                         proxy_origin.host(), 443),
  });
  EXPECT_TRUE(proxy_chain.IsValid());

  // Use a separate packet maker for the connection to the endpoint.
  QuicTestPacketMaker to_endpoint_maker(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true,
      /*use_priority_header=*/true);
  QuicTestPacketMaker from_endpoint_maker(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), "mail.example.org", quic::Perspective::IS_SERVER,
      /*client_priority_uses_incremental=*/false,
      /*use_priority_header=*/true);

  int to_proxy_packet_num = 1;
  int from_proxy_packet_num = 1;
  int to_endpoint_packet_num = 1;
  int from_endpoint_packet_num = 1;
  const uint64_t stream_id = GetNthClientInitiatedBidirectionalStreamId(0);
  QuicSocketDataProvider socket_data(version_);
  socket_data
      .AddWrite("initial-settings",
                ConstructInitialSettingsPacket(to_proxy_packet_num++))
      .Sync();
  socket_data
      .AddWrite("connect-udp",
                ConstructConnectUdpRequestPacket(
                    to_proxy_packet_num++, stream_id, proxy.host(),
                    "/.well-known/masque/udp/www.example.org/443/", false))
      .Sync();
  socket_data.AddRead("server-settings",
                      ConstructServerSettingsPacket(from_proxy_packet_num++));
  socket_data.AddRead(
      "connect-ok-response",
      ConstructOkResponsePacket(from_proxy_packet_num++, stream_id, true));

  socket_data.AddWrite(
      "ack-ok",
      client_maker_.Packet(to_proxy_packet_num++).AddAckFrame(1, 2, 1).Build());

  quiche::HttpHeaderBlock headers =
      to_endpoint_maker.GetRequestHeaders("GET", "https", "/");
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  socket_data.AddWrite(
      "initial-settings-and-get",
      client_maker_.Packet(to_proxy_packet_num++)
          .AddMessageFrame(ConstructClientH3DatagramFrame(
              stream_id, kConnectUdpContextId,
              to_endpoint_maker.MakeInitialSettingsPacket(
                  to_endpoint_packet_num++)))
          .AddMessageFrame(ConstructClientH3DatagramFrame(
              stream_id, kConnectUdpContextId,
              to_endpoint_maker.MakeRequestHeadersPacket(
                  to_endpoint_packet_num++, stream_id, /*fin=*/true, priority,
                  std::move(headers), nullptr)))
          .Build());

  socket_factory_->AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  builder.proxy_chain = proxy_chain;
  builder.http_user_agent_settings = &http_user_agent_settings_;
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

  // Ensure that session to the destination is alive and active.
  QuicChromiumClientSession* destination_session =
      GetActiveSession(kDefaultDestination, PRIVACY_MODE_DISABLED,
                       NetworkAnonymizationKey(), proxy_chain);
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), destination_session));

  // Ensure that the session to the proxy is alive and active.
  QuicChromiumClientSession* proxy_session = GetActiveSession(
      proxy_origin, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      ProxyChain::ForIpProtection({}), SessionUsage::kProxy);
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), proxy_session));
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, proxy_session);

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  QuicSocketDataProvider socket_data1(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  socket_data1
      .AddWrite("probe", client_maker_.Packet(to_proxy_packet_num++)
                             .AddPathChallengeFrame()
                             .AddPaddingFrame(1315)
                             .Build())
      .Sync();
  socket_data1.AddRead("probe-back",
                       server_maker_.Packet(from_proxy_packet_num++)
                           .AddPathResponseFrame()
                           .AddPaddingFrame(1315)
                           .Build());
  socket_data1
      .AddWrite("retransmit-and-retire",
                client_maker_.Packet(to_proxy_packet_num++)
                    .AddPacketRetransmission(1)
                    .AddPacketRetransmission(2)
                    .AddRetireConnectionIdFrame(0u)
                    .Build())
      .Sync();
  socket_data1
      .AddWrite(
          "ping",
          client_maker_.Packet(to_proxy_packet_num++).AddPingFrame().Build())
      .Sync();
  quiche::HttpHeaderBlock response_headers =
      from_endpoint_maker.GetResponseHeaders("200");
  socket_data1.AddRead(
      "proxied-ok-response",
      server_maker_.Packet(from_proxy_packet_num++)
          .AddMessageFrame(ConstructClientH3DatagramFrame(
              stream_id, kConnectUdpContextId,
              from_endpoint_maker.MakeResponseHeadersPacket(
                  from_endpoint_packet_num++, stream_id, /*fin=*/true,
                  std::move(response_headers), nullptr)))
          .Build());

  socket_factory_->AddSocketDataProvider(&socket_data1);

  // Trigger connection migration.
  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  // Cause the connection to report path degrading to both sessions.
  // The destination session will start to probe the alternate network.
  destination_session->connection()->OnPathDegradingDetected();
  proxy_session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Both sessions should still be alive, not marked as going away.
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), destination_session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination, PRIVACY_MODE_DISABLED,
                               NetworkAnonymizationKey(), proxy_chain));
  EXPECT_EQ(1u, destination_session->GetNumActiveStreams());
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), proxy_session));
  EXPECT_EQ(1u, proxy_session->GetNumActiveStreams());

  // Begin reading the response, which only appears on the new connection,
  // verifying the session to the proxy migrated.
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Ensure that the session to the destination is still alive.
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), destination_session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination, PRIVACY_MODE_DISABLED,
                               NetworkAnonymizationKey(), proxy_chain));
  EXPECT_EQ(1u, destination_session->GetNumActiveStreams());
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), proxy_session));
  EXPECT_EQ(1u, proxy_session->GetNumActiveStreams());

  // There should be a task that will complete the migration to the new network.
  task_runner->RunUntilIdle();

  // Wait for the response headers to be read; this must occur over the new
  // connection.
  ASSERT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Deliver a signal that the alternate network now becomes default to session,
  // this will cancel mgirate back to default network timer.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  // Check that the sessions are still alive.
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), destination_session));
  EXPECT_TRUE(
      QuicSessionPoolPeer::IsLiveSession(factory_.get(), proxy_session));

  // Migration back to the default network has begun, so there are no more
  // posted tasks.
  EXPECT_TRUE(runner_->GetPostedTasks().empty());

  stream.reset();
  EXPECT_TRUE(socket_data.AllDataConsumed());
  EXPECT_TRUE(socket_data1.AllDataConsumed());
}

// This test receives NCN signals in the following order:
// - default network disconnected
// - after a pause, new network is connected.
// - new network is made default.
TEST_P(QuicSessionPoolTest, NewNetworkConnectedAfterNoNetwork) {
  InitializeConnectionMigrationV2Test({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Use the test task runner.
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(
      SYNCHRONOUS,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
  socket_data.AddSocketDataToFactory(socket_factory_.get());

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
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause the session to wait for a new network.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // The connection should still be alive, not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  MockQuicData socket_data1(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.MakeCombinedRetransmissionPacket({1, 2}, packet_num++));
  socket_data1.AddWrite(
      SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
  socket_data1.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                         .AddRetireConnectionIdFrame(0u)
                                         .Build());
  socket_data1.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false));
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  socket_data1.AddSocketDataToFactory(socket_factory_.get());

  // Add a new network and notify the stream factory of a new connected network.
  // This causes a PING packet to be sent over the new network.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->SetConnectedNetworksList({kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkConnected(kNewNetworkForTests);

  // Ensure that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  runner_->RunNextTask();

  // Response headers are received over the new network.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Check that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // There should posted tasks not executed, which is to migrate back to default
  // network.
  EXPECT_FALSE(runner_->GetPostedTasks().empty());

  // Receive signal to mark new network as default.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
}

// Regression test for http://crbug.com/872011.
// This test verifies that migrate to the probing socket will not trigger
// new packets being read synchronously and generate ACK frame while
// processing the initial connectivity probe response, which may cause a
// connection being closed with INTERNAL_ERROR as pending ACK frame is not
// allowed when processing a new packet.
TEST_P(QuicSessionPoolTest, MigrateToProbingSocket) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->QueueNetworkMadeDefault(kDefaultNetworkForTests);

  int packet_number = 1;
  MockQuicData quic_data1(version_);
  quic_data1.AddReadPauseForever();
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_number++));
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructGetRequestPacket(
                          packet_number++,
                          GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the second socket data provider that is used for probing on the
  // alternate network.
  MockQuicData quic_data2(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
  // Connectivity probe to be sent on the new path.
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_number++)
                                       .AddPathChallengeFrame()
                                       .AddPaddingFrame()
                                       .Build());
  quic_data2.AddReadPause();
  // First connectivity probe to receive from the server, which will complete
  // connection migraiton on path degrading.
  quic_data2.AddRead(
      ASYNC,
      server_maker_.Packet(1).AddPathResponseFrame().AddPaddingFrame().Build());
  // Read multiple connectivity probes synchronously.
  quic_data2.
```
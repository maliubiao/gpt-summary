Response:
The user wants a breakdown of the functionality of the provided C++ code snippet from Chromium's network stack, specifically `net/quic/quic_session_pool_test.cc`. I need to identify the key actions being tested and explain their purpose. Additionally, I need to consider:

1. **Relationship to Javascript:** If any of the tested functionalities have a direct impact on how Javascript interacts with the network (e.g., through the Fetch API or WebSockets over QUIC), I need to illustrate that.
2. **Logical Inferences:**  I should identify specific test cases that demonstrate a clear input and output based on logical conditions within the code.
3. **Common User/Programming Errors:**  I need to think about scenarios where a developer or user might misuse the tested functionality and provide examples.
4. **User Operation to Reach Here:** I should trace back how a user's action in a browser might eventually lead to this code being executed.
5. **Summary of Functionality (Part 11/20):** Based on the provided snippet, I should summarize the main themes and purposes of these particular tests.

Let's analyze the code blocks sequentially:

* **First Block (Migration Fail):**  This tests what happens when a network disconnect occurs, followed by an attempt to migrate to new networks that immediately fail. It checks that the sessions are initially paused, then closed upon failed migration.
* **Second Block (No New Network):** This examines the scenario where path degradation is detected, but no alternative network is available. It verifies that the session remains on the original network and isn't marked as going away.
* **Third Block (Non-Migratable Stream):** This tests how the session handles path degradation when a non-migratable stream is present. It covers two sub-cases: migrating idle sessions and not migrating them. The expected outcome is the probing of the alternate network and potential closure of the non-migratable stream.
* **Fourth Block (Migration Disabled):** This checks the behavior when connection migration is explicitly disabled in the session's configuration. It verifies that migration doesn't occur despite path degradation.
* **Fifth Block (Async Write Error):** This focuses on connection migration triggered by an asynchronous write error. It verifies that new writes are blocked until the erroneous packet is retransmitted on the new network.
* **Sixth Block (Migrate Back to Default):** This tests the scenario where a session migrates due to a write error, then attempts to migrate back to the default network. It verifies the timing and success of this fallback mechanism.

Now, let's formulate the detailed response incorporating these observations.
这个文件 `net/quic/quic_session_pool_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的测试文件，专门用于测试 `QuicSessionPool` 类的各种功能。`QuicSessionPool` 的主要职责是管理和复用 QUIC 会话 (sessions)。

根据提供的代码片段，这个文件的功能主要集中在 **测试连接迁移 (Connection Migration)** 的各种场景，特别是在以下几种情况下的行为：

**核心功能：测试连接迁移的各种场景**

* **网络断开并尝试迁移到失败的网络：**  测试当网络断开时，已有的 QUIC 会话会被暂停，然后尝试迁移到新的网络连接，但新的连接立即失败，导致会话最终关闭。
* **检测到路径退化但没有新网络可用：** 测试当 QUIC 连接检测到路径性能下降（例如丢包率增加）时，如果没有可用的替代网络，会话会保持在原网络上，并且不会被标记为即将关闭。
* **存在不可迁移的流时的迁移：** 测试当 QUIC 会话中存在被标记为不可迁移的流（例如，由于某些配置或请求特性）时，发生路径退化会如何处理。它包含两种情况：是否迁移空闲的会话。
* **连接迁移被禁用时的行为：** 测试当 QUIC 会话的配置中明确禁用了连接迁移功能时，即使检测到路径退化也不会发生迁移。
* **异步写入错误时的迁移：** 测试当 QUIC 会话在旧的网络连接上发生异步写入错误时，如何触发连接迁移，并确保在新的网络连接上重新发送数据。
* **迁移后尝试迁移回默认网络：** 测试当 QUIC 会话由于写入错误迁移到非默认网络后，会尝试在一段时间后迁移回默认网络。

**与 JavaScript 功能的关系及举例说明：**

QUIC 协议是下一代互联网协议，旨在提供更快速、更可靠的网络连接。虽然这段 C++ 代码本身不直接涉及 JavaScript，但它测试的功能直接影响着浏览器中 JavaScript 发起的网络请求的行为，特别是使用了 QUIC 协议的请求。

**举例说明：**

假设一个网页通过 JavaScript 的 `fetch()` API 发起一个 HTTPS 请求。如果浏览器和服务器支持 QUIC，并且协商使用了 QUIC，那么：

* **网络断开与迁移：** 如果用户的网络突然断开，然后连接到另一个 WiFi 网络，`QuicSessionPool` 的连接迁移功能会尝试将现有的 QUIC 会话迁移到新的网络连接上，而不需要重新建立连接。这对于用户来说是透明的，可以避免请求中断，提升用户体验。
* **路径退化：** 如果用户的网络连接质量变差，例如信号弱或者网络拥塞，`QuicSessionPool` 检测到路径退化后可能会尝试迁移到另一个可用的网络接口（例如从 WiFi 切换到蜂窝网络），以维持连接质量。
* **不可迁移的流：** 某些特定的请求可能被标记为不可迁移，例如涉及到重要事务或安全敏感的操作。在这种情况下，即使网络条件变差，也不会尝试迁移这些请求所在的连接，以保证数据传输的完整性。这可能由浏览器内部策略或服务器指令控制。
* **异步写入错误：** 如果在发送请求的过程中，底层的网络连接出现问题导致写入失败，连接迁移功能会将连接迁移到新的网络，并重新发送尚未成功发送的数据，确保请求最终能够完成。

**逻辑推理、假设输入与输出：**

**场景：网络断开并尝试迁移到失败的网络**

* **假设输入：**
    1. 存在一个已建立的 QUIC 会话 `session1` 和 `session2`，并且都有正在进行的流 (`stream1` 和 `stream2`)。
    2. 网络连接 `kDefaultNetworkForTests` 断开。
    3. 尝试连接到新的网络，但 `socket_data3` 和 `socket_data4` 模拟了连接失败 (`ERR_INTERNET_DISCONNECTED`)。
* **预期输出：**
    1. 在网络断开后，`session1` 和 `session2` 仍然存活 (`IsLiveSession` 为 `true`)，但处于暂停状态。
    2. 在尝试连接新网络失败后，`session1` 和 `session2` 不再存活 (`IsLiveSession` 为 `false`)，即会话被关闭。

**场景：检测到路径退化但没有新网络可用**

* **假设输入：**
    1. 存在一个已建立的 QUIC 会话，并且有一个正在进行的流。
    2. 通过 `session->connection()->OnPathDegradingDetected()` 模拟检测到路径退化。
    3. 没有可用的替代网络。
* **预期输出：**
    1. 会话仍然存活 (`IsLiveSession` 为 `true`)。
    2. 会话没有被标记为即将关闭。
    3. 数据传输会继续在原始网络上进行。

**用户或编程常见的使用错误：**

* **错误地配置不可迁移的流：** 开发者可能错误地将某些本应可以迁移的流标记为不可迁移，导致在网络条件不佳时，用户体验下降，因为无法利用连接迁移来维持连接。
* **对连接迁移的理解不足：** 开发者可能没有充分理解连接迁移的工作原理，导致在某些网络切换场景下出现意料之外的行为，例如请求失败或者重复请求。
* **测试环境与真实环境的差异：** 测试代码中使用的模拟网络环境可能与用户实际使用的网络环境存在差异，导致在测试中表现良好的连接迁移策略在真实场景下效果不佳。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中发起一个 HTTPS 请求：** 例如，在地址栏输入网址或点击链接。
2. **浏览器检查是否支持 QUIC 协议：** 浏览器会检查服务器是否支持 QUIC，并尝试建立 QUIC 连接。
3. **建立 QUIC 连接并发送请求：** 如果成功建立 QUIC 连接，浏览器会通过该连接发送用户的请求。
4. **网络环境变化：** 在请求进行过程中，用户的网络环境可能发生变化，例如：
    * **网络断开：** 用户从一个 WiFi 网络切换到另一个 WiFi 网络，或者离开 WiFi 覆盖范围。
    * **路径退化：** 当前网络信号变差，丢包率增加。
    * **网络地址变化：** 用户的 IP 地址发生变化。
5. **触发 `QuicSessionPool` 的连接迁移逻辑：**  底层的网络层检测到网络环境变化，会通知 `QuicSessionPool`，触发相应的连接迁移逻辑。 这段测试代码就是用来验证在这些情况下 `QuicSessionPool` 的行为是否符合预期。
6. **执行测试用例中的代码：** 当开发者或自动化测试系统运行 `net/quic/quic_session_pool_test.cc` 中的测试用例时，会模拟上述用户操作和网络环境变化，来检查 `QuicSessionPool` 的行为。

**第 11 部分，共 20 部分，功能归纳：**

这段代码是 `QuicSessionPool` 测试的第 11 部分，它主要关注 **连接迁移 (Connection Migration)** 功能的各种边缘情况和异常情况下的行为。 具体来说，这部分测试集中在以下几点：

* **连接迁移的鲁棒性：**  测试在网络断开、连接失败等异常情况下，连接迁移机制的健壮性。
* **连接迁移的策略：** 测试在不同网络状态（路径退化、无可用新网络）下，连接迁移策略的决策。
* **对不可迁移流的处理：** 测试连接迁移功能如何与不可迁移的流进行交互，并保证这些流的完整性。
* **处理异步错误的能力：** 测试连接迁移机制如何应对底层的异步写入错误，并确保数据传输的可靠性。
* **优化连接重用：** 测试迁移后尝试返回到更优的网络连接的能力，以提高性能。

总的来说，这部分测试旨在确保 `QuicSessionPool` 能够可靠且智能地管理 QUIC 会话，并在各种网络条件下提供最佳的用户体验。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
so session1 has an open
  // stream.
  HttpRequestInfo request_info1;
  request_info1.method = "GET";
  request_info1.url = GURL(kDefaultUrl);
  request_info1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream1->RegisterRequest(&request_info1);
  EXPECT_EQ(OK, stream1->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                          CompletionOnceCallback()));
  HttpResponseInfo response1;
  HttpRequestHeaders request_headers1;
  EXPECT_EQ(OK, stream1->SendRequest(request_headers1, &response1,
                                     callback_.callback()));

  // Cause QUIC stream to be created and send GET so session2 has an open
  // stream.
  HttpRequestInfo request_info2;
  request_info2.method = "GET";
  request_info2.url = GURL(kDefaultUrl);
  request_info2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream2->RegisterRequest(&request_info2);
  EXPECT_EQ(OK, stream2->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                          CompletionOnceCallback()));
  HttpResponseInfo response2;
  HttpRequestHeaders request_headers2;
  EXPECT_EQ(OK, stream2->SendRequest(request_headers2, &response2,
                                     callback_.callback()));

  // Cause both sessions to be paused due to DISCONNECTED.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // Ensure that both sessions are paused but alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session1));
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session2));

  // Add new sockets to use post migration. Those are bad sockets and will cause
  // migration to fail.
  MockConnect connect_result =
      MockConnect(SYNCHRONOUS, ERR_INTERNET_DISCONNECTED);
  SequencedSocketData socket_data3(connect_result, base::span<MockRead>(),
                                   base::span<MockWrite>());
  socket_factory_->AddSocketDataProvider(&socket_data3);
  SequencedSocketData socket_data4(connect_result, base::span<MockRead>(),
                                   base::span<MockWrite>());
  socket_factory_->AddSocketDataProvider(&socket_data4);

  // Connect the new network and cause migration to bad sockets, causing
  // sessions to close.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->SetConnectedNetworksList({kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkConnected(kNewNetworkForTests);

  EXPECT_FALSE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session1));
  EXPECT_FALSE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session2));

  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// This test verifies that session attempts connection migration with signals
// delivered in the following order (no alternate network is available):
// - path degrading is detected: session attempts connection migration but no
//   alternate network is available, session caches path degrading signal in
//   connection and stays on the original network.
// - original network backs up, request is served in the orignal network,
//   session is not marked as going away.
TEST_P(QuicSessionPoolTest, MigrateOnPathDegradingWithNoNewNetwork) {
  InitializeConnectionMigrationV2Test({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data.AddReadPause();

  // The rest of the data will still flow in the original socket as there is no
  // new network after path degrading.
  quic_data.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false));
  quic_data.AddReadPauseForever();
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddAckFrame(/*first_received=*/1, /*largest_received=*/1,
                       /*smallest_received=*/1)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  quic_data.AddSocketDataToFactory(socket_factory_.get());

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

  // Trigger connection migration on path degrading. Since there are no networks
  // to migrate to, the session will remain on the original network, not marked
  // as going away.
  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(session->connection()->IsPathDegrading());
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Resume so that rest of the data will flow in the original socket.
  quic_data.Resume();

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();
  quic_data.ExpectAllReadDataConsumed();
  quic_data.ExpectAllWriteDataConsumed();
}

// This test verifies that session with non-migratable stream will probe the
// alternate network on path degrading, and close the non-migratable streams
// when probe is successful.
TEST_P(QuicSessionPoolTest,
       MigrateSessionEarlyNonMigratableStream_DoNotMigrateIdleSessions) {
  TestMigrateSessionEarlyNonMigratableStream(false);
}

TEST_P(QuicSessionPoolTest,
       MigrateSessionEarlyNonMigratableStream_MigrateIdleSessions) {
  TestMigrateSessionEarlyNonMigratableStream(true);
}

void QuicSessionPoolTest::TestMigrateSessionEarlyNonMigratableStream(
    bool migrate_idle_sessions) {
  quic_params_->migrate_idle_sessions = migrate_idle_sessions;
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));

  // Set up the second socket data provider that is used for probing.
  MockQuicData quic_data1(version_);
  quic::QuicConnectionId cid_on_old_path =
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator());
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
  // Connectivity probe to be sent on the new path.
  quic_data1.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                       .AddPathChallengeFrame()
                                       .AddPaddingFrame()
                                       .Build());
  quic_data1.AddReadPause();
  // Connectivity probe to receive from the server.
  quic_data1.AddRead(
      ASYNC,
      server_maker_.Packet(1).AddPathResponseFrame().AddPaddingFrame().Build());

  if (migrate_idle_sessions) {
    quic_data1.AddReadPauseForever();
    // A RESET will be sent to the peer to cancel the non-migratable stream.
    quic_data1.AddWrite(
        SYNCHRONOUS,
        client_maker_.Packet(packet_num++)
            .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                            StreamCancellationQpackDecoderInstruction(0))
            .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                                 quic::QUIC_STREAM_CANCELLED)
            .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
            .Build());
    quic_data1.AddWrite(
        SYNCHRONOUS, client_maker_.MakeRetransmissionPacket(1, packet_num++));
    // Ping packet to send after migration is completed.
    quic_data1.AddWrite(
        SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
    quic_data1.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                         .AddRetireConnectionIdFrame(0u)
                                         .Build());
  } else {
    client_maker_.set_connection_id(cid_on_old_path);
    socket_data.AddWrite(
        SYNCHRONOUS,
        client_maker_.Packet(packet_num++)
            .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                            StreamCancellationQpackDecoderInstruction(0))
            .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                                 quic::QUIC_STREAM_CANCELLED)
            .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
            .AddAckFrame(/*first_received=*/1, /*largest_received=*/1,
                         /*smallest_received=*/1)
            .AddConnectionCloseFrame(
                quic::QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
                "net error", /*frame_type=*/0x1b)
            .Build());
  }

  socket_data.AddSocketDataToFactory(socket_factory_.get());
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created, but marked as non-migratable.
  HttpRequestInfo request_info;
  request_info.load_flags |= LOAD_DISABLE_CONNECTION_MIGRATION_TO_CELLULAR;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Trigger connection migration. Since there is a non-migratable stream,
  // this should cause session to migrate.
  session->OnPathDegrading();

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Resume the data to read the connectivity probing response to declare probe
  // as successful. Non-migratable streams will be closed.
  quic_data1.Resume();
  if (migrate_idle_sessions) {
    base::RunLoop().RunUntilIdle();
  }

  EXPECT_EQ(migrate_idle_sessions, HasActiveSession(kDefaultDestination));
  EXPECT_EQ(0u, session->GetNumActiveStreams());

  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, MigrateSessionEarlyConnectionMigrationDisabled) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
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

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Set session config to have connection migration disabled.
  quic::test::QuicConfigPeer::SetReceivedDisableConnectionMigration(
      session->config());
  EXPECT_TRUE(session->config()->DisableConnectionMigration());

  // Trigger connection migration. Since there is a non-migratable stream,
  // this should cause session to be continue without migrating.
  session->OnPathDegrading();

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// Regression test for http://crbug.com/791886.
// This test verifies that the old packet writer which encountered an
// asynchronous write error will be blocked during migration on write error. New
// packets would not be written until the one with write error is rewritten on
// the new network.
TEST_P(QuicSessionPoolTest, MigrateSessionOnAsyncWriteError) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Using a testing task runner so that we can control time.
  // base::RunLoop() controls mocked socket writes and reads.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(ASYNC, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  MockQuicData socket_data1(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
  ConstructGetRequestPacket(
      packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true);
  quiche::HttpHeaderBlock headers =
      client_maker_.GetRequestHeaders("GET", "https", "/");
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
  size_t spdy_headers_frame_len;
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.MakeRetransmissionAndRequestHeadersPacket(
          {1, 2}, packet_num++, GetNthClientInitiatedBidirectionalStreamId(1),
          true, priority, std::move(headers), &spdy_headers_frame_len));
  socket_data1.AddWrite(
      SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
  socket_data1.AddWrite(SYNCHRONOUS,
                        client_maker_.Packet(packet_num++)
                            .AddRetireConnectionIdFrame(/*sequence_number=*/0u)
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
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(1, false))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(1),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(1),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  socket_data1.AddSocketDataToFactory(socket_factory_.get());

  // Create request #1 and QuicHttpStream.
  RequestBuilder builder1(this);
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());

  HttpRequestInfo request_info1;
  request_info1.method = "GET";
  request_info1.url = GURL("https://www.example.org/");
  request_info1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream1->RegisterRequest(&request_info1);
  EXPECT_EQ(OK, stream1->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                          CompletionOnceCallback()));

  // Request #2 returns synchronously because it pools to existing session.
  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.callback = callback2.callback();
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  HttpRequestInfo request_info2;
  request_info2.method = "GET";
  request_info2.url = GURL("https://www.example.org/");
  request_info2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream2->RegisterRequest(&request_info2);
  EXPECT_EQ(OK, stream2->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                          CompletionOnceCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(2u, session->GetNumActiveStreams());
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Send GET request on stream1. This should cause an async write error.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream1->SendRequest(request_headers, &response,
                                     callback_.callback()));
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());

  // Run the message loop so that asynchronous write completes and a connection
  // migration on write error attempt is posted in QuicSessionPool's task
  // runner.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());

  // Send GET request on stream. This will cause another write attempt before
  // migration on write error is exectued.
  HttpResponseInfo response2;
  HttpRequestHeaders request_headers2;
  EXPECT_EQ(OK, stream2->SendRequest(request_headers2, &response2,
                                     callback2.callback()));

  // Run the task runner so that migration on write error is finally executed.
  task_runner->RunUntilIdle();
  // Fire the retire connection ID alarm.
  base::RunLoop().RunUntilIdle();

  // Verify the session is still alive and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(2u, session->GetNumActiveStreams());
  // There should be one task posted to migrate back to the default network in
  // kMinRetryTimeForDefaultNetworkSecs.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  EXPECT_EQ(base::Seconds(kMinRetryTimeForDefaultNetworkSecs),
            task_runner->NextPendingTaskDelay());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream1->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  stream1.reset();
  stream2.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
}

// Verify session is not marked as going away after connection migration on
// write error and migrate back to default network logic is applied to bring the
// migrated session back to the default network. Migration singals delivered
// in the following order (alternate network is always availabe):
// - session on the default network encountered a write error;
// - session successfully migrated to the non-default network;
// - session attempts to migrate back to default network post migration;
// - migration back to the default network is successful.
TEST_P(QuicSessionPoolTest, MigrateBackToDefaultPostMigrationOnWriteError) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  int peer_packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(ASYNC, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  MockQuicData quic_data2(version_);
  quic::QuicConnectionId cid1 = quic::test::TestConnectionId(12345678);
  quic::QuicConnectionId cid2 = quic::test::TestConnectionId(87654321);

  client_maker_.set_connection_id(cid1);
  // Increment packet number to account for packet write error on the old
  // path. Also save the packet in client_maker_ for constructing the
  // retransmission packet.
  ConstructGetRequestPacket(packet_num++,
                            GetNthClientInitiatedBidirectionalStreamId(0),
                            /*fin=*/true);
  quic_data2.AddWrite(SYNCHRONOUS,
                      client_maker_.MakeCombinedRetransmissionPacket(
                          /*original_packet_numbers=*/{1, 2}, packet_num++));
  quic_data2.AddWrite(
      SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
  quic_data2.AddWrite(SYNCHRONOUS,
                      client_maker_.Packet(packet_num++)
                          .AddRetireConnectionIdFrame(/*sequence_number=*/0u)
                          .Build());
  quic_data2.AddRead(ASYNC, server_maker_.Packet(peer_packet_num++)
                                .AddAckFrame(1, packet_num - 1, 1u)
                                .AddNewConnectionIdFrame(cid2,
                                                         /*sequence_number=*/2u,
                                                         /*retire_prior_to=*/1u)
                                .Build());
  quic_data2.AddRead(ASYNC,
                     ConstructOkResponsePacket(
                         peer_packet_num++,
                         GetNthClientInitiatedBidirectionalStreamId(0), false));
  quic_data2.AddReadPauseForever();
  quic_data2.AddSocketDataToFactory(socket_factory_.get());

  // Create request QuicHttpStream.
  RequestBuilder builder1(this);
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());

  HttpRequestInfo request_info1;
  request_info1.method = "GET";
  request_info1.url = GURL("https://www.example.org/");
  request_info1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream1->RegisterRequest(&request_info1);
  EXPECT_EQ(OK, stream1->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                          CompletionOnceCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  MaybeMakeNewConnectionIdAvailableToSession(cid1, session);

  // Send GET request. This should cause an async write error.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream1->SendRequest(request_headers, &response,
                                     callback_.callback()));
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());

  // Run the message loop so that asynchronous write completes and a connection
  // migration on write error attempt is posted in QuicSessionPool's task
  // runner.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());

  // Run the task runner so that migration on write error is finally executed.
  task_runner->RunUntilIdle();
  // Make sure the alarm that retires connection ID on the old path is fired.
  base::RunLoop().RunUntilIdle();

  // Verify the session is still alive and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  // There should be one task posted to migrate back to the default network in
  // kMinRetryTimeForDefaultNetworkSecs.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  base::TimeDelta expected_delay =
      base::Seconds(kMinRetryTimeForDefaultNetworkSecs);
  EXPECT_EQ(expected_delay, task_runner->NextPendingTaskDelay());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream1->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  // Set up the third socket data provider for migrate back to default network.
  MockQuicData quic_data3(version_);
  client_maker_.set_connection_id(cid2);
  // Connectivity probe to be sent on the new path.
  quic_data3.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                       .AddPathChallengeFrame()
                                       .AddPaddingFrame()
                                       .Build());
  // Connectivity probe to receive from the server.
  quic_data3.AddRead(ASYNC, server_maker_.Packet(peer_packet_num++)
                                .AddPathResponseFrame()
                                .AddPaddingFrame()
                                .Build());
  quic_data3.AddReadPauseForever();
  // There is no other data to retransmit as they have been acknowledged by
  // the packet containing NEW_CONNECTION_ID frame from the server.
  quic_data3.AddWrite(ASYNC,
                      client_maker_.Packet(packet_num++)
                          .AddAckFrame(/*first_received=*/1,
                                       /*largest_received=*/peer_packet_num - 1,
                                       /*smallest_received=*/1)
                          .Build());

  quic_data3.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  quic_data3.AddSocketDataToFactory(socket_factory_.get());

  // Fast forward to fire the migrate back timer and verify the session
  // successfully migrates back to the default network.
  task_runner->FastForwardBy(expected_delay);

  // Verify the session is still alive and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // There should be one task posted to one will resend a connectivity probe and
  // the other will retry migrate back, both are cancelled.
  task_runner->FastForwardUntilNoTasksRemain();

  // Verify the session is still alive and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLive
```
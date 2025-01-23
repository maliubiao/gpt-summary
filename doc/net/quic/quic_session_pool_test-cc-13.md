Response:
The user wants to understand the functionality of the given C++ code snippet, which is part of a test file for the QUIC protocol implementation in Chromium.

I need to:
1. **Summarize the main purpose of the code:** It seems to be testing different scenarios of QUIC connection migration, particularly focusing on how the system behaves when network conditions change or when write errors occur.
2. **Identify connections to JavaScript (if any):** QUIC is a transport layer protocol, so its interaction with JavaScript is indirect. I need to think about where QUIC would be used in a browser context that involves JavaScript.
3. **Analyze logical reasoning:**  The tests often involve setting up specific conditions (e.g., network disconnection, write errors) and verifying the resulting behavior. I need to identify the assumptions and expected outcomes.
4. **Point out potential user/programming errors:**  These would relate to misconfigurations or incorrect assumptions about QUIC's behavior, particularly around connection migration.
5. **Describe the user actions leading to this code:**  This involves understanding the browser's network stack and how QUIC is used when a user interacts with a website.
6. **Summarize the overall function of this specific part (part 14 of 20):**  Given the surrounding test names, this part seems heavily focused on connection migration triggered by various network events and write errors.
这个C++ 代码文件 `net/quic/quic_session_pool_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的**单元测试文件**。它的主要功能是测试 `QuicSessionPool` 类的各种行为，特别是围绕 **QUIC 连接迁移 (Connection Migration)** 的各种场景。

具体来说，从提供的代码片段来看，这个文件中的测试用例主要关注以下功能：

**核心功能：QUIC 连接迁移测试**

* **在发生多次写错误时的连接迁移：** 测试在旧网络和新网络上发生多次写错误时，连接是否能正确迁移。测试了同步和异步两种写错误模式的组合 (`MigrateSessionOnMultipleWriteErrorsSyncSync`, `MigrateSessionOnMultipleWriteErrorsSyncAsync`, `MigrateSessionOnMultipleWriteErrorsAsyncSync`, `MigrateSessionOnMultipleWriteErrorsAsyncAsync`)。
* **握手完成前网络断开不迁移：** 测试在 QUIC 握手尚未完成（例如，只发送了 CHLO 包）时，如果网络断开，连接是否会被关闭，而不是尝试迁移 (`NoMigrationBeforeHandshakeOnNetworkDisconnected`)。
* **网络通知与写错误的顺序：** 测试网络状态变更通知（断开或设为默认）与因写错误触发的连接迁移尝试之间的执行顺序对连接迁移的影响。测试了网络通知先于写错误排队 (`TestMigrationOnNetworkNotificationWithWriteErrorQueuedLater`, `MigrateOnNetworkDisconnectedWithWriteErrorQueuedLater`, `MigrateOnWriteErrorWithNetworkMadeDefaultQueuedEarlier`) 和写错误先于网络通知排队 (`TestMigrationOnWriteErrorWithNotificationQueuedLater`, `MigrateOnWriteErrorWithNetworkMadeDefaultQueuedLater`, `MigrateOnWriteErrorWithNetworkDisconnectedQueuedLater`) 的情况。
* **写错误时暂停等待网络连接：** 测试在发生写错误后，如果旧网络断开，连接迁移会等待新网络连接，并在新网络连接后进行迁移 (`TestMigrationOnWriteErrorPauseBeforeConnected`, `MigrateSessionOnSyncWriteErrorPauseBeforeConnected`, `MigrateSessionOnAsyncWriteErrorPauseBeforeConnected`)。
* **迁移后忽略旧连接的错误：** 测试连接成功迁移到新网络后，旧连接上的写错误 (`IgnoreWriteErrorFromOldWriterAfterMigration`) 和读错误 (`IgnoreReadErrorFromOldReaderAfterMigration`) 是否会被正确忽略，不会导致新的连接迁移或连接关闭。

**与 JavaScript 的关系：**

QUIC 协议本身位于网络传输层，JavaScript 代码通常运行在应用层（例如，在浏览器中）。它们之间的关系是 **间接的**。

* **浏览器发起网络请求：** 当 JavaScript 代码（例如，通过 `fetch` API 或 `XMLHttpRequest`）向服务器发起 HTTPS 请求时，浏览器底层可能会选择使用 QUIC 协议来建立和维护连接（如果服务器支持且配置允许）。
* **QUIC 负责数据传输：** QUIC 协议负责在客户端（浏览器）和服务器之间可靠、安全地传输数据，包括 JavaScript 代码请求的数据（例如，HTML、CSS、JavaScript 文件、JSON 数据）以及服务器返回的响应。
* **连接迁移对用户透明：** 当网络条件变化时，QUIC 的连接迁移功能可以帮助维持连接的活跃性，避免用户感知到网络中断，这对于运行在浏览器中的 JavaScript 应用来说是有益的。例如，用户可能正在使用一个 Web 应用，突然从 Wi-Fi 切换到移动网络，QUIC 连接迁移可以尝试在不中断用户体验的情况下切换底层网络连接。

**举例说明：**

假设一个用户正在使用一个基于 React 开发的 Web 应用，该应用通过 `fetch` API 定期从服务器拉取数据。

1. **用户操作：** 用户在笔记本电脑上使用 Wi-Fi 连接访问该 Web 应用。
2. **QUIC 连接建立：** 浏览器与服务器之间通过 QUIC 协议建立了一个连接。
3. **网络切换：** 用户带着笔记本电脑移动，离开了 Wi-Fi 覆盖范围，笔记本电脑自动切换到了有线网络。
4. **连接迁移触发：** 底层的 QUIC 实现检测到网络变化，并尝试将连接迁移到新的有线网络接口。`quic_session_pool_test.cc` 中类似的测试用例就在验证这个迁移过程的正确性。
5. **JavaScript 无感知：** 如果连接迁移成功，正在运行的 React 应用中的 `fetch` 调用可能不会感知到网络的切换，数据拉取操作可以继续进行，用户体验不会受到影响。

**逻辑推理、假设输入与输出：**

以 `MigrateSessionOnMultipleWriteErrorsSyncSync` 测试为例：

* **假设输入：**
    * 两个网络：一个默认网络和一个新网络。
    * 在默认网络上建立了一个 QUIC 连接。
    * 在默认网络上尝试写入数据时，发生了多次同步写错误。
    * 新网络可用。
* **逻辑推理：** QUIC 实现应该检测到默认网络上的写错误，并尝试将连接迁移到可用的新网络。
* **预期输出：**
    * 连接成功迁移到新网络。
    * 之前在旧网络上未完成的写操作（如果可以重试）在新网络上重新尝试。
    * 测试断言会检查连接迁移是否成功，旧连接是否关闭，新连接是否正常工作。

**用户或编程常见的使用错误：**

* **错误配置防火墙或网络策略：** 如果防火墙或网络策略阻止了 QUIC 协议的 UDP 数据包传输，或者对连接迁移所需的网络操作进行了限制，可能导致连接建立失败或迁移失败。用户可能会遇到页面加载缓慢或连接中断的问题。
* **服务器不支持 QUIC 或连接迁移：** 如果服务器没有启用 QUIC 协议或不支持连接迁移功能，客户端将无法利用这些特性。开发者需要确保服务器端的配置正确。
* **假设连接总是稳定的：** 开发者在编写网络应用时，如果假设网络连接总是稳定可靠的，没有考虑到网络切换或临时中断的情况，可能会导致应用在网络环境不稳定时出现错误。QUIC 的连接迁移功能正是为了应对这种情况，但开发者也需要在应用层做一些容错处理。
* **调试连接迁移问题：** 开发者在调试与 QUIC 连接迁移相关的问题时，如果没有合适的工具和日志，可能很难定位问题原因。`quic_session_pool_test.cc` 这样的单元测试可以帮助开发者理解 QUIC 连接迁移的行为，但实际应用中还需要依赖浏览器提供的网络日志和调试工具。

**用户操作如何一步步到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个网站时遇到了网络连接问题，开发者需要调试 QUIC 连接迁移的相关逻辑。

1. **用户访问网站：** 用户在 Chrome 浏览器地址栏输入网址并访问，浏览器尝试与服务器建立连接，可能会使用 QUIC 协议。
2. **网络环境变化：** 在浏览过程中，用户的网络环境发生变化，例如从 Wi-Fi 断开连接，切换到移动网络。
3. **QUIC 连接迁移尝试：** 底层的 QUIC 实现检测到网络变化，并尝试进行连接迁移。
4. **迁移失败或出现异常：** 如果连接迁移失败或出现异常行为，用户可能会看到页面加载失败、部分内容无法加载或者连接中断的提示。
5. **开发者介入调试：**
    * **启用 Chrome 网络日志：** 开发者可以在 Chrome 中启用网络日志 ( `chrome://net-export/` )，记录详细的网络事件，包括 QUIC 连接的建立、迁移过程等信息。
    * **查看 QUIC 内部状态：** Chrome 提供了 `chrome://webrtc-internals/` 和 `chrome://net-internals/#quic` 等页面，可以查看 QUIC 连接的内部状态、统计信息和错误信息。
    * **分析崩溃报告或错误信息：** 如果发生崩溃或出现明确的错误信息，开发者可以分析相关的崩溃报告或错误日志，寻找与 QUIC 连接迁移相关的线索。
    * **查看 `quic_session_pool_test.cc`：** 开发者可能会参考 `quic_session_pool_test.cc` 中的测试用例，了解 QUIC 连接迁移在各种场景下的预期行为，并尝试复现或理解问题发生的场景。例如，如果错误发生在网络切换的瞬间，开发者可能会重点查看测试网络切换场景的用例。
    * **单步调试 Chromium 源码：** 在更复杂的情况下，开发者可能需要下载 Chromium 源码，并使用调试器单步跟踪 QUIC 连接迁移相关的代码，例如 `QuicSessionPool` 类及其相关的网络操作，以精确定位问题原因。

**第 14 部分的功能归纳：**

作为 20 个部分中的第 14 部分，从提供的代码片段来看，这一部分的主要功能集中在 **详细测试 QUIC 连接在各种网络状态变化和发生写错误时的迁移行为**。它涵盖了多种场景，包括同步和异步写错误、网络通知与写错误发生的先后顺序、以及迁移过程中和迁移后对旧连接错误的处理。这部分旨在确保 QUIC 连接迁移机制的健壮性和正确性，能够有效地应对不同的网络状况，提升用户的网络体验。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第14部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
pectAllReadDataConsumed();
  failed_quic_data2.ExpectAllWriteDataConsumed();
  failed_quic_data1.ExpectAllReadDataConsumed();
  failed_quic_data1.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, MigrateSessionOnMultipleWriteErrorsSyncSync) {
  TestMigrationOnMultipleWriteErrors(
      /*write_error_mode_on_old_network*/ SYNCHRONOUS,
      /*write_error_mode_on_new_network*/ SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest, MigrateSessionOnMultipleWriteErrorsSyncAsync) {
  TestMigrationOnMultipleWriteErrors(
      /*write_error_mode_on_old_network*/ SYNCHRONOUS,
      /*write_error_mode_on_new_network*/ ASYNC);
}

TEST_P(QuicSessionPoolTest, MigrateSessionOnMultipleWriteErrorsAsyncSync) {
  TestMigrationOnMultipleWriteErrors(
      /*write_error_mode_on_old_network*/ ASYNC,
      /*write_error_mode_on_new_network*/ SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest, MigrateSessionOnMultipleWriteErrorsAsyncAsync) {
  TestMigrationOnMultipleWriteErrors(
      /*write_error_mode_on_old_network*/ ASYNC,
      /*write_error_mode_on_new_network*/ ASYNC);
}

// Verifies that a connection is closed when connection migration is triggered
// on network being disconnected and the handshake is not confirmed.
TEST_P(QuicSessionPoolTest, NoMigrationBeforeHandshakeOnNetworkDisconnected) {
  FLAGS_quic_enable_chaos_protection = false;
  // TODO(crbug.com/40821140): Make this test work with asynchronous QUIC
  // session creation. This test only works with synchronous session creation
  // for now.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);

  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});

  // Use cold start mode to do crypto connect, and send CHLO packet on wire.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(ASYNC, client_maker_.MakeDummyCHLOPacket(1));
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  // Deliver the network notification, which should cause the connection to be
  // closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  EXPECT_EQ(ERR_NETWORK_CHANGED, callback_.WaitForResult());

  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// Sets up the connection migration test where network change notification is
// queued BEFORE connection migration attempt on write error is posted.
void QuicSessionPoolTest::
    TestMigrationOnNetworkNotificationWithWriteErrorQueuedLater(
        bool disconnected) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
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

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  MockQuicData socket_data1(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  // Increment packet number to account for packet write error on the old
  // path. Also save the packet in client_maker_ for constructing the
  // retransmission packet.
  ConstructGetRequestPacket(packet_num++,
                            GetNthClientInitiatedBidirectionalStreamId(0),
                            /*fin=*/true);
  socket_data1.AddWrite(SYNCHRONOUS,
                        client_maker_.MakeCombinedRetransmissionPacket(
                            /*original_packet_numbers=*/{1, 2}, packet_num++));
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

  socket_data1.AddSocketDataToFactory(socket_factory_.get());

  // First queue a network change notification in the message loop.
  if (disconnected) {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->QueueNetworkDisconnected(kDefaultNetworkForTests);
  } else {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->QueueNetworkMadeDefault(kNewNetworkForTests);
  }
  // Send GET request on stream. This should cause a write error,
  // which triggers a connection migration attempt. This will queue a
  // migration attempt behind the notification in the message loop.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  base::RunLoop().RunUntilIdle();
  // Verify the session is still alive and not marked as going away post
  // migration.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  stream.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
}

// This test verifies that session attempts connection migration successfully
// with signals delivered in the following order (alternate network is always
// available):
// - a notification that default network is disconnected is queued.
// - write error is triggered: session posts a task to attempt connection
//   migration, |migration_pending_| set to true.
// - default network disconnected is delivered: session immediately migrates to
//   the alternate network, |migration_pending_| set to false.
// - connection migration on write error attempt aborts: writer encountered
//   error is no longer in active use.
TEST_P(QuicSessionPoolTest,
       MigrateOnNetworkDisconnectedWithWriteErrorQueuedLater) {
  TestMigrationOnNetworkNotificationWithWriteErrorQueuedLater(
      /*disconnected=*/true);
}

// This test verifies that session attempts connection migration successfully
// with signals delivered in the following order (alternate network is always
// available):
// - a notification that alternate network is made default is queued.
// - write error is triggered: session posts a task to attempt connection
//   migration, block future migrations.
// - new default notification is delivered: migrate back timer spins and task is
//   posted to migrate to the new default network.
// - connection migration on write error attempt proceeds successfully: session
// is
//   marked as going away, future migrations unblocked.
// - migrate back to default network task executed: session is already on the
//   default network, no-op.
TEST_P(QuicSessionPoolTest,
       MigrateOnWriteErrorWithNetworkMadeDefaultQueuedEarlier) {
  TestMigrationOnNetworkNotificationWithWriteErrorQueuedLater(
      /*disconnected=*/false);
}

// Sets up the connection migration test where network change notification is
// queued AFTER connection migration attempt on write error is posted.
void QuicSessionPoolTest::TestMigrationOnWriteErrorWithNotificationQueuedLater(
    bool disconnected) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
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

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  MockQuicData socket_data1(version_);

  client_maker_.set_connection_id(cid_on_new_path);
  // Increment packet number to account for packet write error on the old
  // path. Also save the packet in client_maker_ for constructing the
  // retransmission packet.
  ConstructGetRequestPacket(packet_num++,
                            GetNthClientInitiatedBidirectionalStreamId(0),
                            /*fin=*/true);
  socket_data1.AddWrite(SYNCHRONOUS,
                        client_maker_.MakeCombinedRetransmissionPacket(
                            /*original_packet_numbers=*/{1, 2}, packet_num++));
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

  socket_data1.AddSocketDataToFactory(socket_factory_.get());

  // Send GET request on stream. This should cause a write error,
  // which triggers a connection migration attempt. This will queue a
  // migration attempt in the message loop.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));
  base::RunLoop().RunUntilIdle();

  // Now queue a network change notification in the message loop behind
  // the migration attempt.
  if (disconnected) {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->QueueNetworkDisconnected(kDefaultNetworkForTests);
  } else {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->QueueNetworkMadeDefault(kNewNetworkForTests);
  }

  // Verify session is still alive and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  stream.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
}

// This test verifies that session attempts connection migration successfully
// with signals delivered in the following order (alternate network is always
// available):
// - write error is triggered: session posts a task to complete connection
//   migration.
// - a notification that alternate network is made default is queued.
// - connection migration attempt proceeds successfully, session is marked as
//   going away.
// - new default notification is delivered after connection migration has been
//   completed.
TEST_P(QuicSessionPoolTest,
       MigrateOnWriteErrorWithNetworkMadeDefaultQueuedLater) {
  TestMigrationOnWriteErrorWithNotificationQueuedLater(/*disconnected=*/false);
}

// This test verifies that session attempts connection migration successfully
// with signals delivered in the following order (alternate network is always
// available):
// - write error is triggered: session posts a task to complete connection
//   migration.
// - a notification that default network is diconnected is queued.
// - connection migration attempt proceeds successfully, session is marked as
//   going away.
// - disconnect notification is delivered after connection migration has been
//   completed.
TEST_P(QuicSessionPoolTest,
       MigrateOnWriteErrorWithNetworkDisconnectedQueuedLater) {
  TestMigrationOnWriteErrorWithNotificationQueuedLater(/*disconnected=*/true);
}

// This tests connection migration on write error with signals delivered in the
// following order:
// - a synchronous/asynchronous write error is triggered base on
//   |write_error_mode|: connection migration attempt is posted.
// - old default network disconnects, migration waits for a new network.
// - after a pause, new network is connected: session will migrate to new
//   network immediately.
// - migration on writer error is exectued and aborts as writer passed in is no
//   longer active in use.
// - new network is made default.
void QuicSessionPoolTest::TestMigrationOnWriteErrorPauseBeforeConnected(
    IoMode write_error_mode) {
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
  socket_data.AddWrite(write_error_mode, ERR_FAILED);
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

  // The connection should still be alive, not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  MockQuicData socket_data1(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  // Increment packet number to account for packet write error on the old
  // path. Also save the packet in client_maker_ for constructing the
  // retransmission packet.
  ConstructGetRequestPacket(packet_num++,
                            GetNthClientInitiatedBidirectionalStreamId(0),
                            /*fin=*/true);
  socket_data1.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false));
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                         .AddPacketRetransmission(1)
                                         .AddPacketRetransmission(2)
                                         .AddRetireConnectionIdFrame(0)
                                         .Build());
  socket_data1.AddWrite(
      SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
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

  // On a DISCONNECTED notification, nothing happens.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
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

  // Run the message loop migration for write error can finish.
  runner_->RunUntilIdle();

  // Response headers are received over the new network.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Check that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // There should be no posted tasks not executed, no way to migrate back to
  // default network.
  EXPECT_TRUE(runner_->GetPostedTasks().empty());

  // Receive signal to mark new network as default.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       MigrateSessionOnSyncWriteErrorPauseBeforeConnected) {
  TestMigrationOnWriteErrorPauseBeforeConnected(SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest,
       MigrateSessionOnAsyncWriteErrorPauseBeforeConnected) {
  TestMigrationOnWriteErrorPauseBeforeConnected(ASYNC);
}

// This test verifies that when session successfully migrate to the alternate
// network, packet write error on the old writer will be ignored and will not
// trigger connection migration on write error.
TEST_P(QuicSessionPoolTest, IgnoreWriteErrorFromOldWriterAfterMigration) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Using a testing task runner so that we can verify whether the migrate on
  // write error task is posted.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  MockQuicData socket_data(version_);
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddReadPause();
  socket_data.AddWrite(
      ASYNC, ERR_ADDRESS_UNREACHABLE,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
  socket_data.AddReadPauseForever();
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
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

  // Set up second socket data provider that is used after
  // migration. The response to the request is read on this new socket.
  MockQuicData socket_data1(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.MakeCombinedRetransmissionPacket({1, 2}, packet_num++));
  socket_data1.AddWrite(
      SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
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

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());
  // Now notify network is disconnected, cause the migration to complete
  // immediately.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  // There will be two pending task, one will complete migration with no delay
  // and the other will attempt to migrate back to the default network with
  // delay.
  EXPECT_EQ(2u, task_runner->GetPendingTaskCount());

  // Complete migration.
  task_runner->RunUntilIdle();
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  // Resume the old socket data, a write error will be delivered to the old
  // packet writer. Verify no additional task is posted.
  socket_data.Resume();
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());

  stream.reset();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
}

// This test verifies that when session successfully migrate to the alternate
// network, packet read error on the old reader will be ignored and will not
// close the connection.
TEST_P(QuicSessionPoolTest, IgnoreReadErrorFromOldReaderAfterMigration) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Using a testing task runner.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  MockQuicData socket_data(version_);
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddReadPause();
  socket_data.AddRead(ASYNC, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
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

  // Set up second socket data provider that is used after
  // migration. The request is written to this new socket, and the
  // response to the request is read on this new socket.
  MockQuicData socket_data1(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  socket_data1.AddWrite(
      SYNCHRONOUS, client_maker_.MakeRetransmissionPacket(1, packet_num++));
  socket_data1.AddWrite(
      SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
  socket_data1.AddWrite(
      SYNCHRONOUS,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
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
  socket_data1.AddSocke
```
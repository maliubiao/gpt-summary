Response:
My goal is to summarize the functionality of the provided C++ code snippet and relate it to JavaScript if possible, along with other specified requirements. Here's a breakdown of my thought process:

1. **Understand the Core Purpose:** The filename `net/quic/quic_session_pool_test.cc` strongly suggests this is a unit test file for the QUIC session pool within the Chromium networking stack. The tests seem to focus on connection migration scenarios.

2. **Identify Key Classes and Concepts:**  I scanned the code for recurring class names and concepts. `QuicSessionPoolTest`, `QuicChromiumClientSession`, `MockQuicData`, `NetworkChangeNotifier`, `HttpStream`, `Connection Migration`, `Path Challenge`, `Path Response`, `Retransmission`, `Non-Migratable Stream`, and various packet construction methods (`ConstructInitialSettingsPacket`, `ConstructGetRequestPacket`) are prominent.

3. **Recognize the Testing Framework:** The use of `TEST_P`, `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`, `IsOk()`, `WaitForResult()`, and `ExpectAll*Consumed()` clearly indicates the use of Google Test. This helps understand the structure and assertions within each test case.

4. **Group Tests by Functionality:** I noticed patterns in the test names and the actions performed within them. The tests generally fall into these categories related to connection migration:
    * **Successful Migration:** Tests where migration happens smoothly after a network change. Examples: `MigrateOnDefaultNetworkMadeDefault`, `MigrationWithNewNetwork`.
    * **Migration Timeout:** Tests where migration fails due to a timeout. Example: `MigrationTimeoutWithNoNewNetwork`.
    * **Handling Non-Migratable Streams:** Tests focusing on how the session pool behaves when there are streams that cannot be migrated. Examples: `OnNetworkMadeDefaultNonMigratableStream_*`, `OnNetworkDisconnectedNonMigratableStream_*`.
    * **Migration Disabled:** Tests verifying behavior when connection migration is explicitly disabled. Example: `OnNetworkMadeDefaultConnectionMigrationDisabled`, `OnNetworkDisconnectedConnectionMigrationDisabled`.
    * **No Open Streams:** Tests dealing with scenarios where migration is triggered but no streams are currently active. Examples: `OnNetworkMadeDefaultNoOpenStreams_*`, `OnNetworkDisconnectedNoOpenStreams_*`.
    * **Migration on Disconnect:** Tests specifically focused on migration triggered by a network disconnection. Examples: `MigrateOnDefaultNetworkDisconnectedSync`, `MigrateOnDefaultNetworkDisconnectedAsync`.

5. **Analyze Individual Tests (Example: `MigrateOnDefaultNetworkMadeDefault`):** I broke down the steps within a representative test:
    * **Initialization:** Setting up mock network conditions, socket data, and a task runner.
    * **Request Creation:** Creating an HTTP request and a QUIC stream.
    * **Network Change Simulation:**  Using `MockNetworkChangeNotifier` to simulate a new default network.
    * **Verification:** Asserting that the session remains alive, a new connection ID is available, a task is posted for migration, and the response is received on the new network.
    * **Resource Cleanup:** Ensuring all data is consumed.

6. **Identify Common Patterns:**  Many tests follow a similar pattern: set up mock data, create a request/stream, trigger a network change, and then assert the expected behavior of the session pool. This helps in summarizing the overall functionality.

7. **Address Specific Requirements:**
    * **Functionality Listing:** I listed the identified categories of tests and the specific scenarios they cover.
    * **Relationship to JavaScript:**  I considered how these low-level networking concepts might relate to JavaScript. While direct interaction isn't present in this C++ code, I noted the connection to browser behavior (network changes, user experience) and the potential exposure of related APIs. I specifically mentioned the `navigator.connection` API as a possible point of contact, even though this C++ code doesn't *directly* interact with it.
    * **Logic and Assumptions:** I tried to infer the intended behavior and potential issues the tests are designed to uncover. I formulated simple "if-then" scenarios to illustrate the logic.
    * **User/Programming Errors:** I considered common mistakes, such as mishandling network connectivity, not accounting for migration delays, or misunderstanding the conditions under which migration occurs.
    * **User Operation Steps:** I traced back how a user action (e.g., changing Wi-Fi networks) could lead to the execution of this code.
    * **Debugging Clues:** I pointed out the types of checks and assertions within the tests that would be helpful during debugging (session status, active streams, packet exchanges).
    * **Overall Functionality (Part 5 of 20):** I synthesized a concise summary based on the observed patterns and the focus on connection migration. I emphasized the testing nature of the code and its role in ensuring the robustness of the QUIC session pool.

8. **Refinement and Iteration:** I reviewed my initial thoughts and refined the language to be more precise and comprehensive, ensuring all aspects of the prompt were addressed. For example, I made sure to explicitly mention that this is *testing* code and not the core implementation. I also considered the "Part 5 of 20" context and aimed for a summary that fits within a larger sequence.
好的，让我们分析一下 `net/quic/quic_session_pool_test.cc` 的这一部分代码的功能。

**功能归纳（基于提供的代码片段）**

这段代码是 Chromium 网络栈中 QUIC 协议会话池的单元测试代码的一部分，主要关注以下功能点的测试：

* **连接迁移 (Connection Migration) 的各种场景：**  这是这段代码的核心关注点。它测试了在不同网络条件变化下，QUIC 连接的迁移行为，包括：
    * **成功迁移到新的默认网络 (OnNetworkMadeDefault):**  测试当系统切换到新的默认网络时，QUIC 连接是否能够成功迁移，并且旧的网络路径仍然可以重试。
    * **迁移超时 (MigrationTimeoutWithNoNewNetwork):** 测试在没有可用的替代网络时，连接迁移尝试是否会超时，并且连接最终会被关闭。
    * **存在不可迁移的流 (Non-Migratable Stream) 的情况 (OnNetworkMadeDefaultNonMigratableStream_, OnNetworkDisconnectedNonMigratableStream_):** 测试当连接中存在被标记为不可迁移的流时，网络变化（变为默认或断开）如何影响连接迁移。它会验证连接是否仍然会尝试探测新路径，以及不可迁移的流是否会被重置。
    * **连接迁移被禁用 (OnNetworkMadeDefaultConnectionMigrationDisabled, OnNetworkDisconnectedConnectionMigrationDisabled):** 测试当 QUIC 会话配置为禁用连接迁移时，网络变化是否会导致连接迁移的发生。
    * **没有打开的流 (No Open Streams) 的情况 (OnNetworkMadeDefaultNoOpenStreams_, OnNetworkDisconnectedNoOpenStreams_):** 测试当没有活跃的 QUIC 流时，网络变化是否会导致连接迁移。
    * **默认网络断开连接时的迁移 (MigrateOnDefaultNetworkDisconnectedSync, MigrateOnDefaultNetworkDisconnectedAsync):** 测试当默认网络断开时，QUIC 连接是否能立即迁移到可用的替代网络，并考虑了在迁移前是否有同步或异步的写入操作。

* **测试连接活性 (Session Liveness) 和活动状态 (Active Status):** 每个测试都会验证在各种网络变化后，QUIC 会话是否仍然存活并且处于活动状态。

* **测试流的状态和操作:**  例如，测试中会创建 QUIC 流，发送请求，读取响应头，并验证流在连接迁移过程中的状态（例如，是否被重置）。

* **使用 Mock 对象模拟网络环境和 QUIC 协议行为:**  代码中大量使用了 `MockQuicData` 和 `MockNetworkChangeNotifier` 来模拟不同的网络场景和 QUIC 数据包的发送接收，以便在测试环境中控制和验证 QUIC 连接的行为。

**与 JavaScript 的关系**

这段 C++ 代码本身并不直接包含 JavaScript 代码。然而，它测试的是 Chromium 浏览器网络栈的核心 QUIC 实现，而这个实现会影响到浏览器中所有使用 QUIC 协议的网络请求，包括通过 JavaScript 发起的请求。

**举例说明:**

假设一个用户通过浏览器中的 JavaScript 代码发起了一个使用了 QUIC 协议的 HTTP 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当用户的网络环境发生变化，例如从 Wi-Fi 切换到移动数据网络时，这段 C++ 测试代码所验证的逻辑（连接迁移）就会在浏览器的底层网络栈中被执行。如果测试覆盖了当前的网络切换场景，并且没有发现问题，那么用户的 JavaScript 代码发起的请求就能在底层无缝地迁移到新的网络连接上，而用户可能不会感知到网络的变化。

**逻辑推理（假设输入与输出）**

以下以 `TEST_P(QuicSessionPoolTest, MigrateOnDefaultNetworkMadeDefault)` 为例：

**假设输入:**

1. 一个已建立的 QUIC 连接 (`kDefaultDestination`) 在 `kDefaultNetworkForTests` 网络上。
2. 连接上有一个活跃的 QUIC 流正在发送 GET 请求。
3. 系统检测到新的默认网络 `kNewNetworkForTests`。
4. `quic_data2` 模拟了在新网络上接收到服务器的响应数据。

**预期输出:**

1. QUIC 连接会尝试迁移到 `kNewNetworkForTests`。
2. 会向新的网络路径发送 `PATH_CHALLENGE`。
3. 收到 `PATH_RESPONSE` 后，确认新的路径可用。
4. 原有的请求的响应头会通过新的网络连接接收到 (`response.headers->response_code()` 为 200)。
5. QUIC 会话仍然存活并且处于活动状态。

**用户或编程常见的使用错误**

这段测试代码主要关注网络栈的内部逻辑，不太容易直接体现用户或编程的错误。但是，可以从测试覆盖的场景反推一些潜在的错误：

* **没有正确处理网络切换事件:**  如果应用程序或网络库没有正确监听和处理网络切换事件，可能导致连接中断或性能下降。这段测试确保了 QUIC 协议栈能够正确响应网络变化。
* **对连接迁移的假设不正确:** 开发者可能错误地假设连接迁移总是会成功，或者没有考虑到迁移过程中可能出现的延迟或失败。这段测试覆盖了各种迁移场景，有助于发现这些假设中的错误。
* **没有考虑不可迁移的流:**  如果应用程序在网络切换时没有考虑到某些流可能无法迁移，可能会导致应用程序状态不一致。测试中针对不可迁移流的场景可以帮助发现这类问题。

**用户操作如何到达这里（调试线索）**

作为一个单元测试，用户操作通常不会直接触发这段代码的执行。这段代码是在 Chromium 的开发和测试过程中被执行的。但是，用户的某些操作会间接地触发这段代码所测试的网络栈逻辑：

1. **用户打开一个网页或应用程序，该应用使用了 HTTPS/QUIC 协议进行通信。** 这会导致浏览器建立 QUIC 连接。
2. **用户在浏览或使用应用程序的过程中，其网络环境发生变化。** 例如：
    *   从连接的 Wi-Fi 网络断开，切换到移动数据网络。
    *   从一个 Wi-Fi 网络切换到另一个 Wi-Fi 网络。
    *   在移动网络信号不稳定时，网络连接可能会短暂中断和恢复。
3. **操作系统会通知浏览器底层网络状态的变化。**
4. **浏览器的 QUIC 协议栈会根据这些网络状态变化，尝试进行连接迁移（如果配置允许）。** 这就是这段测试代码所模拟和验证的场景。

作为调试线索，如果用户在使用 Chromium 浏览器时遇到网络连接问题，例如在网络切换时连接中断或请求失败，开发者可能会查看 QUIC 连接迁移相关的日志和状态，并可能需要运行类似的单元测试来复现和诊断问题。测试的输出结果（成功或失败）以及断言的具体信息可以帮助定位问题所在。

**总结这段代码的功能（作为第 5 部分）**

作为 20 部分中的第 5 部分，这段代码专注于 **QUIC 连接迁移机制的详细单元测试**。它深入测试了在各种网络变化场景下，QUIC 连接池如何管理和迁移连接，以保证连接的稳定性和连续性。 这部分测试涵盖了成功迁移、迁移失败（超时）、处理不可迁移流以及迁移被禁用等多种情况，是确保 Chromium 浏览器 QUIC 实现健壮性的关键组成部分。它通过模拟各种网络条件和 QUIC 协议行为，验证了连接迁移逻辑的正确性，为后续更高级别的网络功能提供可靠的基础。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
tream->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
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
  // Due to lack of alternate network, session will not mgirate connection.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  // A task was posted to migrate to the new default network. Execute that task.
  task_runner->RunUntilIdle();

  // Manually trigger retransmission of PATH_CHALLENGE.
  auto* path_validator =
      quic::test::QuicConnectionPeer::path_validator(session->connection());
  quic::test::QuicPathValidatorPeer::retry_timer(path_validator)->Cancel();
  path_validator->OnRetryTimeout();

  // Resume quic data and a connectivity probe response will be read on the new
  // socket, declare probing as successful.
  quic_data2.Resume();

  // The connection should still be alive, and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // There should be a task that will complete the migration to the new network.
  task_runner->RunUntilIdle();

  // Response headers are received over the new network.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Run the message loop to complete the asynchronous write of ack and ping.
  base::RunLoop().RunUntilIdle();

  // Verify that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

// This test verifies that session times out connection migration attempt
// with signals delivered in the following order (no alternate network is
// available):
// - default network disconnected is delivered: session attempts connection
//   migration but found not alternate network. Session waits for a new network
//   comes up in the next kWaitTimeForNewNetworkSecs seconds.
// - no new network is connected, migration times out. Session is closed.
TEST_P(QuicSessionPoolTest, MigrationTimeoutWithNoNewNetwork) {
  InitializeConnectionMigrationV2Test({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
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

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause the session to wait for a new network.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // The migration will not fail until the migration alarm timeout.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(true, session->connection()->writer()->IsWriteBlocked());

  // Migration will be timed out after kWaitTimeForNewNetwokSecs.
  task_runner->FastForwardBy(base::Seconds(kWaitTimeForNewNetworkSecs));

  // The connection should now be closed. A request for response
  // headers should fail.
  EXPECT_FALSE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(ERR_INTERNET_DISCONNECTED, callback_.WaitForResult());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// This test verifies that connectivity probes will be sent even if there is
// a non-migratable stream. However, when connection migrates to the
// successfully probed path, any non-migratable streams will be reset.
TEST_P(QuicSessionPoolTest,
       OnNetworkMadeDefaultNonMigratableStream_MigrateIdleSessions) {
  TestOnNetworkMadeDefaultNonMigratableStream(true);
}

// This test verifies that connectivity probes will be sent even if there is
// a non-migratable stream. However, when connection migrates to the
// successfully probed path, any non-migratable stream will be reset. And if
// the connection becomes idle then, close the connection.
TEST_P(QuicSessionPoolTest,
       OnNetworkMadeDefaultNonMigratableStream_DoNotMigrateIdleSessions) {
  TestOnNetworkMadeDefaultNonMigratableStream(false);
}

void QuicSessionPoolTest::TestOnNetworkMadeDefaultNonMigratableStream(
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
  quic::QuicConnectionId cid_on_old_path =
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator());
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
  MockQuicData quic_data1(version_);
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

  // Trigger connection migration. Session will start to probe the alternative
  // network. Although there is a non-migratable stream, session will still be
  // active until probing is declared as successful.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Resume data to read a connectivity probing response, which will cause
  // non-migtable streams to be closed.
  quic_data1.Resume();
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(migrate_idle_sessions, HasActiveSession(kDefaultDestination));
  EXPECT_EQ(0u, session->GetNumActiveStreams());

  base::RunLoop().RunUntilIdle();

  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, OnNetworkMadeDefaultConnectionMigrationDisabled) {
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
  // this should cause session to continue but be marked as going away.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       OnNetworkDisconnectedNonMigratableStream_DoNotMigrateIdleSessions) {
  TestOnNetworkDisconnectedNonMigratableStream(false);
}

TEST_P(QuicSessionPoolTest,
       OnNetworkDisconnectedNonMigratableStream_MigrateIdleSessions) {
  TestOnNetworkDisconnectedNonMigratableStream(true);
}

void QuicSessionPoolTest::TestOnNetworkDisconnectedNonMigratableStream(
    bool migrate_idle_sessions) {
  quic_params_->migrate_idle_sessions = migrate_idle_sessions;
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  MockQuicData failed_socket_data(version_);
  quic::QuicConnectionId cid_on_old_path =
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator());
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  MockQuicData socket_data(version_);
  if (migrate_idle_sessions) {
    failed_socket_data.AddReadPauseForever();
    int packet_num = 1;
    failed_socket_data.AddWrite(SYNCHRONOUS,
                                ConstructInitialSettingsPacket(packet_num++));
    // A RESET will be sent to the peer to cancel the non-migratable stream.
    failed_socket_data.AddWrite(
        SYNCHRONOUS,
        client_maker_.Packet(packet_num++)
            .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                            StreamCancellationQpackDecoderInstruction(0))
            .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                                 quic::QUIC_STREAM_CANCELLED)
            .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
            .Build());
    failed_socket_data.AddSocketDataToFactory(socket_factory_.get());

    // Set up second socket data provider that is used after migration.
    client_maker_.set_connection_id(cid_on_new_path);
    socket_data.AddReadPauseForever();
    auto packet_one_frames = client_maker_.CloneSavedFrames(1);  // STREAM
    auto packet_two_frames =
        client_maker_.CloneSavedFrames(2);  // STREAM, RST_STREAM
    auto& packet = client_maker_.Packet(packet_num++);
    for (size_t i = 1; i < packet_two_frames.size(); ++i) {
      packet.AddFrame(packet_two_frames[i]);
    }
    for (auto& frame : packet_one_frames) {
      packet.AddFrame(frame);
    }
    packet.AddFrame(packet_two_frames[0]);
    socket_data.AddWrite(SYNCHRONOUS, packet.Build());
    // Ping packet to send after migration.
    socket_data.AddWrite(
        SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
    socket_data.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                          .AddRetireConnectionIdFrame(0u)
                                          .Build());
    socket_data.AddSocketDataToFactory(socket_factory_.get());
  } else {
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
  }

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
  // this should cause a RST_STREAM frame to be emitted with
  // quic::QUIC_STREAM_CANCELLED error code.
  // If migrate idle session, the connection will then be migrated to the
  // alternate network. Otherwise, the connection will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_EQ(migrate_idle_sessions,
            QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(migrate_idle_sessions, HasActiveSession(kDefaultDestination));

  if (migrate_idle_sessions) {
    EXPECT_EQ(0u, session->GetNumActiveStreams());
    base::RunLoop().RunUntilIdle();

    failed_socket_data.ExpectAllReadDataConsumed();
    failed_socket_data.ExpectAllWriteDataConsumed();
  }
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, OnNetworkDisconnectedConnectionMigrationDisabled) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
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

  // Trigger connection migration.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       OnNetworkMadeDefaultNoOpenStreams_DoNotMigrateIdleSessions) {
  TestOnNetworkMadeDefaultNoOpenStreams(false);
}

TEST_P(QuicSessionPoolTest,
       OnNetworkMadeDefaultNoOpenStreams_MigrateIdleSessions) {
  TestOnNetworkMadeDefaultNoOpenStreams(true);
}

void QuicSessionPoolTest::TestOnNetworkMadeDefaultNoOpenStreams(
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
  if (!migrate_idle_sessions) {
    socket_data.AddWrite(
        SYNCHRONOUS,
        client_maker_.Packet(packet_num)
            .AddConnectionCloseFrame(
                quic::QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
                "net error")
            .Build());
  }
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  MockQuicData quic_data1(version_);
  if (migrate_idle_sessions) {
    client_maker_.set_connection_id(cid_on_new_path);
    // Set up the second socket data provider that is used for probing.
    // Connectivity probe to be sent on the new path.
    quic_data1.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                         .AddPathChallengeFrame()
                                         .AddPaddingFrame()
                                         .Build());
    quic_data1.AddReadPause();
    // Connectivity probe to receive from the server.
    quic_data1.AddRead(ASYNC, server_maker_.Packet(1)
                                  .AddPathResponseFrame()
                                  .AddPaddingFrame()
                                  .Build());
    quic_data1.AddReadPauseForever();
    // in-flight SETTINGS and requests will be retransmitted. Since data is
    // already sent on the new address, ping will no longer be sent.
    quic_data1.AddWrite(ASYNC, client_maker_.MakeRetransmissionPacket(
                                   /*original_packet_number=*/1, packet_num++));
    quic_data1.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                         .AddRetireConnectionIdFrame(0u)
                                         .Build());
    quic_data1.AddSocketDataToFactory(socket_factory_.get());
  }

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(session->HasActiveRequestStreams());
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Trigger connection migration.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);
  EXPECT_EQ(migrate_idle_sessions, HasActiveSession(kDefaultDestination));

  if (migrate_idle_sessions) {
    quic_data1.Resume();
    base::RunLoop().RunUntilIdle();
    quic_data1.ExpectAllReadDataConsumed();
    quic_data1.ExpectAllWriteDataConsumed();
  }
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       OnNetworkDisconnectedNoOpenStreams_DoNotMigateIdleSessions) {
  TestOnNetworkDisconnectedNoOpenStreams(false);
}

TEST_P(QuicSessionPoolTest,
       OnNetworkDisconnectedNoOpenStreams_MigateIdleSessions) {
  TestOnNetworkDisconnectedNoOpenStreams(true);
}

void QuicSessionPoolTest::TestOnNetworkDisconnectedNoOpenStreams(
    bool migrate_idle_sessions) {
  quic_params_->migrate_idle_sessions = migrate_idle_sessions;
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  MockQuicData default_socket_data(version_);
  default_socket_data.AddReadPauseForever();
  int packet_num = 1;
  default_socket_data.AddWrite(SYNCHRONOUS,
                               ConstructInitialSettingsPacket(packet_num++));
  default_socket_data.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData alternate_socket_data(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  if (migrate_idle_sessions) {
    client_maker_.set_connection_id(cid_on_new_path);
    // Set up second socket data provider that is used after migration.
    alternate_socket_data.AddRead(SYNCHRONOUS,
                                  ERR_IO_PENDING);  // Hanging read.
    alternate_socket_data.AddWrite(
        SYNCHRONOUS, client_maker_.MakeRetransmissionPacket(1, packet_num++));
    // Ping packet to send after migration.
    alternate_socket_data.AddWrite(
        SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
    alternate_socket_data.AddWrite(SYNCHRONOUS,
                                   client_maker_.Packet(packet_num++)
                                       .AddRetireConnectionIdFrame(0u)
                                       .Build());
    alternate_socket_data.AddSocketDataToFactory(socket_factory_.get());
  }

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Ensure that session is active.
  auto* session = GetActiveSession(kDefaultDestination);
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Trigger connection migration. Since there are no active streams,
  // the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_EQ(migrate_idle_sessions, HasActiveSession(kDefaultDestination));

  default_socket_data.ExpectAllReadDataConsumed();
  default_socket_data.ExpectAllWriteDataConsumed();
  if (migrate_idle_sessions) {
    alternate_socket_data.ExpectAllReadDataConsumed();
    alternate_socket_data.ExpectAllWriteDataConsumed();
  }
}

// This test verifies session migrates to the alternate network immediately when
// default network disconnects with a synchronous write before migration.
TEST_P(QuicSessionPoolTest, MigrateOnDefaultNetworkDisconnectedSync) {
  TestMigrationOnNetworkDisconnected(/*async_write_before*/ false);
}

// This test verifies session migrates to the alternate network immediately when
// default network disconnects with an asynchronously write before migration.
TEST_P(QuicSessionPoolTest, MigrateOnDefaultNetworkDisconnectedAsync) {
  TestMigrationOnNetworkDisconnected(/*async_write_before*/ true);
}

void QuicSessionPoolTest::TestMigrationOnNetworkDisconnected(
    bool async_write_before) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kDefaultNetworkForTests);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Use the test task runner.
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), runner_.get());

  int packet_number = 1;
  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_number++));
  socket_data.AddWrite(
      SYNCHRONOUS, ConstructGetRequestPacket(
                       packet_number++,
                       GetNthClientInitiatedBidirectionalStreamId(0), true));
  if (async_write_before) {
    socket_data.AddWrite(ASYNC, OK);
    packet_number++;
  }
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE
```
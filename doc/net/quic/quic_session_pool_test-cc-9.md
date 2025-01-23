Response:
My thought process for analyzing the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The filename `net/quic/quic_session_pool_test.cc` immediately suggests this is a testing file for the `QuicSessionPool` class within Chromium's networking stack. The presence of `TEST_P` macros confirms this is a parameterized test suite.

2. **Deconstruct the Test Cases:** I start by reading the names of the `TEST_P` functions:
    * `MigratePortOnPathDegrading_MaxMigrations`
    * `MigratePortOnPathDegrading_MigrateIdleSession_PathValidator`
    * `DoNotMigrateToBadSocketOnPathDegrading`
    * `MigrateSessionWithDrainingStreamSync`
    * `MigrateSessionWithDrainingStreamAsync`
    * `MigrateOnNewNetworkConnectAfterPathDegrading`
    * `MigrateMultipleSessionsToBadSocketsAfterDisconnected`

    These names give strong clues about the functionality being tested. They all revolve around connection migration, particularly in scenarios involving path degradation, idle sessions, bad sockets, and different network connectivity events.

3. **Analyze Common Setup and Actions:**  I notice recurring patterns within the test cases:
    * **`Initialize()` or `InitializeConnectionMigrationV2Test()`:**  This suggests a setup phase to configure the testing environment, likely involving setting QUIC parameters and mocking network behavior.
    * **`MockQuicData`:** This is used to simulate network traffic, defining what data is sent and received by the client and server. `AddWrite` and `AddRead` are key methods. `AddReadPause` and `AddReadPauseForever` are used for controlling the timing of data reception.
    * **`socket_factory_`:**  A mock socket factory is used to control how new sockets are created, particularly during migration scenarios. `TestPortMigrationSocketFactory` is mentioned, indicating tests specifically for port migration.
    * **`scoped_mock_network_change_notifier_`:** This mocks network change events, essential for testing connection migration on network changes.
    * **`base::RunLoop().RunUntilIdle()` and `task_runner`:** These are used for managing asynchronous operations and controlling the timing of events within the test.
    * **`QuicSessionPoolPeer`:**  This appears to be a test utility class to access internal state of the `QuicSessionPool`.
    * **`CreateStream()`:**  This creates a `HttpStream`, which interacts with the QUIC session.
    * **`session->connection()->OnPathDegradingDetected()`:** This simulates the server detecting a problem with the network path.
    * **`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`:** These are standard Google Test assertions to verify the expected behavior.
    * **Connection ID manipulation:** The tests frequently change the client's connection ID (`client_maker_.set_connection_id`).

4. **Infer Functionality from Test Scenarios:** Based on the test case names and their setup, I can infer the following functionalities being tested:

    * **Path Degradation Handling:** The pool can detect when a network path is performing poorly and trigger migration attempts.
    * **Port Migration:** The pool can migrate a connection to a new local port on the same network when path degradation is detected.
    * **Connection Migration (Network Change):** The pool can migrate connections when the underlying network changes (e.g., switching from Wi-Fi to cellular).
    * **Migration Limits:** The pool respects limits on the number of allowed migration attempts.
    * **Idle Session Migration:** The pool can migrate sessions that are currently idle.
    * **Handling Bad Sockets:** The pool avoids migrating to unusable network interfaces or ports.
    * **Migration with Draining Streams:** The pool can handle migration even when there are streams in the process of closing.
    * **Early Migration:** Migration can be triggered proactively when a new network becomes available after path degradation is detected.
    * **Migration of Multiple Sessions:** The pool can manage migration for multiple active QUIC sessions.

5. **Relate to JavaScript (if applicable):**  QUIC itself is a transport protocol, and this C++ code is about the underlying implementation. JavaScript in a browser interacts with QUIC indirectly through higher-level APIs like `fetch`. Therefore, the connection is as follows:

    * **JavaScript `fetch` API:** When a JavaScript application uses `fetch` to make an HTTPS request, the browser's networking stack (including the QUIC implementation tested here) might be used to establish the connection and transfer data.
    * **Connection Migration and User Experience:** The connection migration features being tested directly impact the user experience in cases of network changes or degradation. If migration is successful, the user might experience seamless transitions without interruptions. If migration fails or is delayed, the user might see connection errors or slowdowns.

    * **Example:** If a user is on a mobile device with a flaky Wi-Fi connection and makes a request via `fetch`, the `QuicSessionPool`'s migration logic would be crucial in seamlessly switching to the cellular network if Wi-Fi becomes unreliable. This would happen transparently to the JavaScript code.

6. **Logical Reasoning (Hypothetical Inputs and Outputs):**

    * **Scenario:**  Path degradation is detected on the current Wi-Fi network. A cellular network is available.
    * **Input:**  `session->connection()->OnPathDegradingDetected()` is called. The network change notifier indicates a new network.
    * **Output:**  The `QuicSessionPool` will attempt to establish a new connection over the cellular network. New `MockQuicData` will be used for the new connection. `EXPECT_TRUE(HasActiveSession(kNewNetworkDestination))` would likely pass after a successful migration. `task_runner` will have tasks related to probing and completing the migration.

7. **Common User/Programming Errors:**

    * **Incorrect Network Configuration:**  If the user's network configuration is faulty (e.g., no internet connectivity on the alternate network), migration will fail. The tests simulate this with the "bad socket" scenario.
    * **Aggressive Firewall Rules:** A firewall might block connections on new ports or interfaces, preventing successful migration.
    * **Server-Side Issues:**  The server might not support connection migration or might have misconfigurations that prevent the client from migrating successfully.
    * **Programming Errors in QUIC Implementation:** Bugs in the `QuicSessionPool`'s migration logic could lead to unexpected behavior, such as failing to migrate when it should or migrating unnecessarily. The tests aim to catch these bugs.

8. **User Operations Leading to This Code:**

    * A user navigates to a website that uses HTTPS and QUIC.
    * The user's network conditions change (e.g., Wi-Fi signal weakens, switches to cellular).
    * The underlying QUIC connection experiences path degradation.
    * The browser's networking stack, specifically the `QuicSessionPool`, will be involved in deciding whether and how to migrate the connection to maintain connectivity.

9. **Summary of Functionality (Part 10 of 20):** Based on the analyzed tests, this part of `quic_session_pool_test.cc` focuses on rigorously testing the connection migration capabilities of the `QuicSessionPool`, particularly in scenarios involving path degradation and network changes. It covers various aspects like port migration, migration limits, handling bad sockets, and the interaction between path degradation detection and network availability. The tests use mocking and simulated network conditions to ensure the migration logic behaves correctly under different circumstances.

This detailed breakdown allows me to address all aspects of your request, from outlining the code's function to relating it to user behavior and potential errors.
这个 `net/quic/quic_session_pool_test.cc` 文件是 Chromium 网络栈中 QUIC 协议会话池 (`QuicSessionPool`) 的单元测试文件。它包含了多个测试用例，用于验证 `QuicSessionPool` 在各种场景下的行为和功能。

**主要功能归纳:**

这个代码片段主要测试了 `QuicSessionPool` 在 **连接迁移 (Connection Migration)** 场景下的功能，特别是当检测到 **路径退化 (Path Degrading)** 时如何处理。具体来说，它涵盖了以下几个方面：

1. **路径退化时的端口迁移 (Port Migration on Path Degrading):**
   - 测试当检测到当前网络路径性能下降时，`QuicSessionPool` 是否能够尝试迁移连接到新的本地端口。
   - 测试了最大迁移次数的限制 (`MigratePortOnPathDegrading_MaxMigrations`)。
   - 测试了路径验证器 (Path Validator) 如何参与空闲会话的端口迁移 (`MigratePortOnPathDegrading_MigrateIdleSession_PathValidator`)。

2. **避免迁移到坏的 Socket (Do Not Migrate to Bad Socket):**
   - 测试当检测到路径退化时，`QuicSessionPool` 是否能够避免迁移到无法使用的网络接口或端口。

3. **处理带有 Draining Stream 的会话迁移 (Migrate Session with Draining Stream):**
   - 测试当会话中存在正在关闭 (draining) 的 Stream 时，`QuicSessionPool` 是否能够正确地迁移连接，并区分同步和异步写入的情况 (`MigrateSessionWithDrainingStreamSync`, `MigrateSessionWithDrainingStreamAsync`)。

4. **在新网络连接后迁移 (Migrate on New Network Connect After Path Degrading):**
   - 测试当检测到路径退化后，如果连接到新的网络，`QuicSessionPool` 是否能够及时地迁移连接到新的网络。

5. **断开连接后迁移多个会话到坏的 Socket (Migrate Multiple Sessions to Bad Sockets After Disconnected):**
   - 虽然测试名称包含 "bad sockets"，但从后续代码来看，这个测试更侧重于验证在连接迁移信号触发时，`QuicSessionPool` 如何处理多个会话的迁移。这里模拟了迁移后连接立即断开的情况。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络功能是 Web 浏览器与服务器进行通信的基础。当 JavaScript 代码通过 `fetch` API 或 `XMLHttpRequest` 发起网络请求时，底层的网络栈（包括 QUIC 实现）会处理连接的建立、数据传输和连接管理。

- **举例说明:**
  - 当用户在浏览器中访问一个使用 QUIC 协议的网站时，浏览器会使用 `QuicSessionPool` 来管理与服务器的 QUIC 连接。
  - 如果用户的网络环境发生变化，例如从 Wi-Fi 切换到蜂窝网络，或者 Wi-Fi 信号变弱，`QuicSessionPool` 中测试的连接迁移功能就会发挥作用，尝试保持连接的稳定性和性能。
  - JavaScript 代码通常不需要直接处理这些底层的连接迁移细节，浏览器会负责处理。但是，连接迁移的成功与否会直接影响 JavaScript 发起的网络请求的成功率和速度。

**逻辑推理 (假设输入与输出):**

以 `MigratePortOnPathDegrading_MaxMigrations` 测试为例：

- **假设输入:**
    - 检测到路径退化。
    - 尝试进行多次端口迁移，超过允许的最大次数。
- **预期输出:**
    - `QuicSessionPoolPeer::GetNumDegradingSessions` 的值会递增。
    - 在达到最大迁移次数后，不再进行新的迁移尝试。
    - 会话仍然存活 (`IsLiveSession` 为 true)。
    - 已有的 Stream 仍然活跃。
    - 相关的 `MockQuicData` 模拟的读写操作符合预期。

**用户或编程常见的使用错误:**

- **用户操作错误:**
    - **网络不稳定:** 用户在移动过程中，网络信号频繁切换或不稳定，会导致路径退化的频繁发生，触发连接迁移。如果目标网络也不稳定，可能会导致迁移失败或连接中断。
    - **防火墙配置:** 用户的防火墙或网络配置可能阻止连接迁移到新的端口或网络，导致连接中断或性能下降。

- **编程错误 (QUIC 实现层面):**
    - **迁移策略错误:**  `QuicSessionPool` 的迁移策略可能过于激进或保守，导致不必要的迁移或在应该迁移时没有迁移。
    - **状态管理错误:** 在迁移过程中，会话的状态管理可能出现错误，导致数据丢失或连接异常。
    - **资源泄漏:**  在迁移过程中，如果资源管理不当，可能会导致内存泄漏或其他资源泄漏。

**用户操作到达此处的调试线索:**

当开发者需要调试与 QUIC 连接迁移相关的问题时，可能会关注这个测试文件。以下是一些可能的调试场景和线索：

1. **用户报告连接不稳定的问题:**
   - 用户反馈在使用某些网络环境时，网页加载缓慢或频繁中断。
   - 开发者可能会怀疑是连接迁移功能出现问题，导致迁移失败或性能下降。
   - 可以通过抓包工具观察 QUIC 连接的迁移过程，查看是否有异常发生。
   - 可以查看 Chromium 的网络日志 (`chrome://net-export/`)，寻找与 QUIC 连接迁移相关的错误或警告信息。

2. **开发者修改了 QUIC 连接迁移相关的代码:**
   - 当开发者修改了 `QuicSessionPool` 或相关的连接迁移逻辑后，会运行这些单元测试来确保修改没有引入新的错误。
   - 如果某个测试失败，开发者会仔细分析测试用例的逻辑，并检查自己修改的代码是否符合预期。

3. **性能分析:**
   - 开发者可能会使用性能分析工具来评估连接迁移对性能的影响。
   - 可以通过修改测试用例，模拟不同的网络环境和迁移场景，来评估迁移策略的效率。

**作为第 10 部分的功能归纳:**

作为 20 个部分中的第 10 部分，这个代码片段集中测试了 `QuicSessionPool` 的核心功能之一：**在检测到路径退化时的连接迁移能力**。它覆盖了端口迁移、避免迁移到坏的 Socket、处理带有 Draining Stream 的会话迁移以及在新网络连接后进行迁移等多个关键场景。这些测试用例旨在确保 `QuicSessionPool` 能够有效地应对网络环境的变化，保持 QUIC 连接的稳定性和性能。通过对这些特定场景的深入测试，可以验证连接迁移机制的健壮性和正确性，为用户提供更流畅的网络体验。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
quic_data2.AddRead(ASYNC, server_maker_.Packet(server_packet_num++)
                                    .AddPathResponseFrame()
                                    .AddPaddingFrame()
                                    .Build());
      quic_data2.AddWrite(
          SYNCHRONOUS,
          client_maker_.Packet(packet_number++).AddAckFrame(1, 9, 9).Build());
    }
    quic_data2.AddReadPauseForever();
    quic_data2.AddSocketDataToFactory(socket_factory_.get());

    EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

    // Cause the connection to report path degrading to the session.
    // Session will start to probe a different port.
    session->connection()->OnPathDegradingDetected();
    base::RunLoop().RunUntilIdle();

    EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

    // The retry mechanism is internal to path validator.
    EXPECT_EQ(1u, task_runner->GetPendingTaskCount());

    // The connection should still be alive, and not marked as going away.
    EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
    EXPECT_TRUE(HasActiveSession(kDefaultDestination));
    EXPECT_EQ(1u, session->GetNumActiveStreams());

    // Resume quic data and a connectivity probe response will be read on the
    // new socket.
    quic_data2.Resume();
    base::RunLoop().RunUntilIdle();

    EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
    EXPECT_TRUE(HasActiveSession(kDefaultDestination));
    EXPECT_EQ(1u, session->GetNumActiveStreams());

    if (i < 4) {
      // There's a pending task to complete migration to the new port.
      task_runner->RunUntilIdle();
    } else {
      // Last attempt to migrate will abort due to hitting the limit of max
      // number of allowed migrations.
      task_runner->FastForwardUntilNoTasksRemain();
    }

    quic_data2.ExpectAllWriteDataConsumed();
    // The last round of migration will abort upon reading the probing response.
    // Future reads in the same socket is ignored.
    if (i != 4) {
      quic_data2.ExpectAllReadDataConsumed();
    } else {
      EXPECT_FALSE(quic_data2.AllReadDataConsumed());
    }
  }

  // Verify that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       MigratePortOnPathDegrading_MigrateIdleSession_PathValidator) {
  scoped_mock_network_change_notifier_ =
      std::make_unique<ScopedMockNetworkChangeNotifier>();
  MockNetworkChangeNotifier* mock_ncn =
      scoped_mock_network_change_notifier_->mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();
  mock_ncn->SetConnectedNetworksList({kDefaultNetworkForTests});
  // Enable migration on network change.
  quic_params_->migrate_sessions_on_network_change_v2 = true;
  quic_params_->migrate_idle_sessions = true;
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kDefaultNetworkForTests);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  int packet_number = 1;
  MockQuicData quic_data1(version_);
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_number++));
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructGetRequestPacket(
                          packet_number++,
                          GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddReadPause();
  // The client session will receive the response first and closes its only
  // stream.
  quic_data1.AddRead(ASYNC,
                     ConstructOkResponsePacket(
                         1, GetNthClientInitiatedBidirectionalStreamId(0),
                         /*fin = */ true));
  quic_data1.AddReadPauseForever();
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the second socket data provider that is used after migration.
  // The response to the earlier request is read on the new socket.
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
  // Connectivity probe to receive from the server.
  quic_data2.AddRead(
      ASYNC,
      server_maker_.Packet(2).AddPathResponseFrame().AddPaddingFrame().Build());
  quic_data2.AddReadPauseForever();
  // Ping packet to send after migration is completed.
  quic_data2.AddWrite(ASYNC, client_maker_.Packet(packet_number++)
                                 .AddAckFrame(/*first_received=*/1,
                                              /*largest_received=*/2,
                                              /*smallest_received=*/1)
                                 .AddPingFrame()
                                 .Build());

  quic_data2.AddWrite(SYNCHRONOUS,
                      client_maker_.Packet(packet_number++)
                          .AddRetireConnectionIdFrame(/*sequence_number=*/0u)
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
  // Disable connection migration on the request streams.
  // This should have no effect for port migration.
  QuicChromiumClientStream* chrome_stream =
      static_cast<QuicChromiumClientStream*>(
          quic::test::QuicSessionPeer::GetStream(
              session, GetNthClientInitiatedBidirectionalStreamId(0)));
  EXPECT_TRUE(chrome_stream);
  chrome_stream->DisableConnectionMigrationToCellularNetwork();

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Manually initialize the connection's self address. In real life, the
  // initialization will be done during crypto handshake.
  IPEndPoint ip;
  session->GetDefaultSocket()->GetLocalAddress(&ip);
  quic::test::QuicConnectionPeer::SetSelfAddress(session->connection(),
                                                 ToQuicSocketAddress(ip));

  // Cause the connection to report path degrading to the session.
  // Session will start to probe a different port.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));
  // A response will be received on the current path and closes the request
  // stream.
  quic_data1.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());
  EXPECT_EQ(0u, session->GetNumActiveStreams());

  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // There should be one pending task as the probe posted a DoNothingAs
  // callback.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  task_runner->ClearPendingTasks();

  // The connection should still be alive, and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Resume quic data and a connectivity probe response will be read on the new
  // socket.
  quic_data2.Resume();

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  // Successful port migration causes the path no longer degrading on the same
  // network.
  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // There should be pending tasks, the nearest one will complete
  // migration to the new port.
  task_runner->RunUntilIdle();

  // Fire any outstanding quic alarms.
  base::RunLoop().RunUntilIdle();

  // Now there may be one pending task to send connectivity probe that has been
  // cancelled due to successful migration.
  task_runner->FastForwardUntilNoTasksRemain();

  // Verify that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

// This test verifies that the connection will not migrate to a bad socket
// when path degrading is detected.
TEST_P(QuicSessionPoolTest, DoNotMigrateToBadSocketOnPathDegrading) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->QueueNetworkMadeDefault(kDefaultNetworkForTests);

  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data.AddReadPause();
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

  // Set up second socket that will immediately return disconnected.
  // The stream factory will abort probe the alternate network.
  MockConnect bad_connect = MockConnect(SYNCHRONOUS, ERR_INTERNET_DISCONNECTED);
  SequencedSocketData socket_data(bad_connect, base::span<MockRead>(),
                                  base::span<MockWrite>());
  socket_factory_->AddSocketDataProvider(&socket_data);

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

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  // Cause the connection to report path degrading to the session.
  // Session will start to probe the alternate network.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // The connection should still be alive, and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Resume the data, and response header is received over the original network.
  quic_data.Resume();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());
  // There should be one pending task left as the probe posted a
  // DoNothingAsCallback.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());

  // Verify that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  stream.reset();
  quic_data.ExpectAllReadDataConsumed();
  quic_data.ExpectAllWriteDataConsumed();
}

// Regression test for http://crbug.com/847569.
// This test verifies that the connection migrates to the alternate network
// early when there is no active stream but a draining stream.
// The first packet being written after migration is a synchrnous write, which
// will cause a PING packet being sent.
TEST_P(QuicSessionPoolTest, MigrateSessionWithDrainingStreamSync) {
  TestMigrateSessionWithDrainingStream(SYNCHRONOUS);
}

// Regression test for http://crbug.com/847569.
// This test verifies that the connection migrates to the alternate network
// early when there is no active stream but a draining stream.
// The first packet being written after migration is an asynchronous write, no
// PING packet will be sent.
TEST_P(QuicSessionPoolTest, MigrateSessionWithDrainingStreamAsync) {
  TestMigrateSessionWithDrainingStream(ASYNC);
}

void QuicSessionPoolTest::TestMigrateSessionWithDrainingStream(
    IoMode write_mode_for_queued_packet) {
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
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_number++));
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructGetRequestPacket(
                          packet_number++,
                          GetNthClientInitiatedBidirectionalStreamId(0), true));
  // Read an out of order packet with FIN to drain the stream.
  quic_data1.AddRead(ASYNC,
                     ConstructOkResponsePacket(
                         2, GetNthClientInitiatedBidirectionalStreamId(0),
                         true));  // keep sending version.
  quic_data1.AddReadPauseForever();
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the second socket data provider that is used after migration.
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
  // Connectivity probe to receive from the server.
  quic_data2.AddRead(
      ASYNC,
      server_maker_.Packet(3).AddPathResponseFrame().AddPaddingFrame().Build());
  // Ping packet to send after migration is completed.
  quic_data2.AddWrite(write_mode_for_queued_packet,
                      client_maker_.MakeAckAndRetransmissionPacket(
                          packet_number++, 2, 3, 3, {1, 2}));
  if (write_mode_for_queued_packet == SYNCHRONOUS) {
    quic_data2.AddWrite(
        ASYNC, client_maker_.Packet(packet_number++).AddPingFrame().Build());
  }
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_number++)
                                       .AddRetireConnectionIdFrame(0u)
                                       .Build());
  server_maker_.Reset();
  quic_data2.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false));
  quic_data2.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++).AddAckFrame(1, 3, 1).Build());
  quic_data2.AddReadPauseForever();
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

  // Run the message loop to receive the out of order packet which contains a
  // FIN and drains the stream.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, session->GetNumActiveStreams());

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  // Cause the connection to report path degrading to the session.
  // Session should still start to probe the alternate network.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // The connection should still be alive, and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));

  // Resume quic data and a connectivity probe response will be read on the new
  // socket.
  quic_data2.Resume();

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(0u, session->GetNumActiveStreams());
  EXPECT_TRUE(session->HasActiveRequestStreams());

  // There should be a task that will complete the migration to the new network.
  task_runner->RunUntilIdle();

  // Deliver a signal that the alternate network now becomes default to session,
  // this will cancel mgirate back to default network timer.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  task_runner->FastForwardBy(base::Seconds(kMinRetryTimeForDefaultNetworkSecs));

  // Verify that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));

  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

// Regression test for http://crbug.com/835444.
// This test verifies that the connection migrates to the alternate network
// when the alternate network is connected after path has been degrading.
TEST_P(QuicSessionPoolTest, MigrateOnNewNetworkConnectAfterPathDegrading) {
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
  MockQuicData quic_data2(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
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
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_num++)
                                       .AddRetireConnectionIdFrame(0u)
                                       .Build());
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

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Cause the connection to report path degrading to the session.
  // Due to lack of alternate network, session will not mgirate connection.
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());
  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());

  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Deliver a signal that a alternate network is connected now, this should
  // cause the connection to start early migration on path degrading.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->SetConnectedNetworksList(
          {kDefaultNetworkForTests, kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkConnected(kNewNetworkForTests);

  // The connection should still be alive, and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Resume quic data and a connectivity probe response will be read on the new
  // socket.
  quic_data2.Resume();

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // There should be a task that will complete the migration to the new network.
  task_runner->RunUntilIdle();

  // Although the session successfully migrates, it is still considered
  // degrading sessions.
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Response headers are received over the new network.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Deliver a signal that the alternate network now becomes default to session,
  // this will cancel mgirate back to default network timer.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  // There's one more task to mgirate back to the default network in 0.4s.
  task_runner->FastForwardBy(base::Seconds(kMinRetryTimeForDefaultNetworkSecs));

  // Verify that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

// This test verifies that multiple sessions are migrated on connection
// migration signal.
TEST_P(QuicSessionPoolTest,
       MigrateMultipleSessionsToBadSocketsAfterDisconnected) {
  InitializeConnectionMigrationV2Test({kDefaultNetworkForTests});

  MockQuicData socket_data1(version_);
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data1.AddWrite(ASYNC, OK);
  socket_data1.AddSocketDataToFactory(socket_factory_.get());
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddWrite(ASYNC, OK);
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  url::SchemeHostPort server1(url::kHttpsScheme, kDefaultServerHostName, 443);
  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName, 443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.2", "");

  // Create request and QuicHttpStream to create session1.
  RequestBuilder builder1(this);
  builder1.destination = server1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());

  // Create request and QuicHttpStream to create session2.
  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  QuicChromiumClientSession* session1 = GetActiveSession(server1);
  QuicChromiumClientSession* session2 = GetActiveSession(server2);
  EXPECT_NE(session1, session2);

  // Cause QUIC stream to be created and send GET
```
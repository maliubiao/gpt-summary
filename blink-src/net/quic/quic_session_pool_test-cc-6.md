Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Goal:**

The primary request is to analyze a Chromium network stack source file (`net/quic/quic_session_pool_test.cc`) and identify its function, relate it to JavaScript (if possible), infer logic with inputs and outputs, highlight potential user/programming errors, explain user interaction leading to the code, and summarize its function as part of a larger series.

**2. Initial Scan and Keyword Recognition:**

A quick scan reveals key terms and patterns:

* `TEST_P`:  Indicates parameterized unit tests. This immediately tells us the file's primary purpose is testing.
* `QuicSessionPoolTest`:  The class name confirms this is a test fixture for the `QuicSessionPool` component.
* `Migrate`, `Migration`, `PathDegrading`, `MultiPort`:  These words point to the core functionality being tested: QUIC connection migration, specifically when network paths degrade or when multi-port connections are involved.
* `MockQuicData`, `AddRead`, `AddWrite`: These suggest the tests simulate network interactions by injecting and inspecting QUIC packets.
* `RequestBuilder`, `CreateStream`, `HttpRequestInfo`, `SendRequest`:  These indicate the tests are simulating HTTP requests over QUIC.
* `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_THAT`:  Standard C++ testing assertions.
* `scoped_mock_network_change_notifier_`: This is used to simulate network changes.
* `CompletionOnceCallback`:  Asynchronous operations.
* `ERR_IO_PENDING`:  Indicates an asynchronous operation is in progress.
* `base::RunLoop().RunUntilIdle()`:  Waiting for asynchronous tasks to complete.
* `task_runner`:  Managing asynchronous tasks, allowing controlled time progression in tests.

**3. Deconstructing the Tests:**

Focus on individual `TEST_P` blocks. Each test aims to verify a specific scenario related to connection migration.

* **`MigrateOnPathDegrading*`:**  These tests check how the `QuicSessionPool` handles path degradation, simulating scenarios with synchronous and asynchronous writes before migration.
* **`MigrateSessionEarlyProbingWriterError*`:** These tests examine the behavior when the attempt to probe a new network path fails due to a write error. The "ThreeNetworks" variant tests what happens when multiple alternate networks exist.
* **`MultiPortSessionWithMigration`:**  This specifically tests the multi-port connection migration feature.
* **`SuccessfullyMigratedToServerPreferredAddress`:** Tests the scenario where the client successfully migrates to the server's preferred address.

**4. Identifying the Core Functionality:**

Based on the test names and the actions within them, the core function of `QuicSessionPoolTest` is to verify the correct behavior of the `QuicSessionPool` in various connection migration scenarios. This includes:

* **Initiating migration:**  Triggered by path degradation.
* **Probing new paths:** Sending and receiving `PathChallengeFrame` and `PathResponseFrame`.
* **Retransmitting data:** Ensuring in-flight data is retransmitted on the new path.
* **Handling migration errors:**  Testing how the pool reacts to failures in probing new paths.
* **Multi-port migration:** Validating the specific logic for migrating to a different port on the same IP.
* **Migration to server-preferred addresses:** Checking that the client uses the server's hinted address.

**5. Connecting to JavaScript (If Applicable):**

While this specific C++ file doesn't directly *execute* JavaScript, it tests the underlying network logic that a browser (which *does* execute JavaScript) relies upon. Therefore, the connection is indirect. JavaScript making network requests will ultimately utilize the QUIC protocol and the logic tested here. The example provided in the initial prompt illustrates this by showing a simple `fetch` request.

**6. Inferring Logic, Inputs, and Outputs:**

For each test, consider:

* **Input (Simulated):**  Network conditions (path degradation, network changes), server responses (success, failure), packet sequences injected via `MockQuicData`.
* **Logic:** The `QuicSessionPool`'s internal decision-making processes based on these inputs, such as deciding when and how to migrate.
* **Output (Observed):**  The state of the `QuicSessionPool` (number of active/degrading sessions), the success or failure of the HTTP request, the packets sent and received.

**Example Inference (for `MigrateOnPathDegradingSync`):**

* **Input:**
    * Initial network connection.
    * Simulated path degradation signal.
    * Server responding on the new path with `PathResponseFrame`.
    * Client successfully writing a packet synchronously before migration.
* **Logic:**
    * Upon path degradation, the session probes the alternate network.
    * Once a valid response is received, the session migrates.
    * Retransmission of pending data occurs on the new path.
* **Output:**
    * The HTTP request eventually succeeds (response code 200).
    * The connection successfully migrates to the new network.
    * The original socket's data is consumed.
    * The new socket's data is consumed.

**7. Identifying User/Programming Errors:**

Common errors relate to misconfigurations or misunderstandings of QUIC behavior:

* **Incorrect Network Configuration:**  If the browser or OS isn't correctly configured for multi-path QUIC, migration might not work as expected.
* **Firewall Issues:** Firewalls might block traffic on new paths or ports, preventing successful migration.
* **Server-Side Issues:**  The server must also support connection migration for it to work.
* **Application Logic Errors:** While less directly related to *this specific file*, incorrect application logic could lead to premature closing of streams, interfering with migration.

**8. Explaining User Operation as a Debugging Clue:**

The step-by-step user interaction helps understand the context in which this code is executed. It's about tracing the user's action to the network stack's behavior. For example, a user experiencing intermittent connectivity issues might trigger the path degradation logic being tested.

**9. Summarizing the Function (Part 7 of 20):**

Considering it's part 7 of 20, and the focus is on connection migration, this section likely deals with the core mechanisms and early stages of migration, possibly covering the detection of path degradation and the initial attempts to switch to alternative paths. The later parts might cover more complex scenarios, error handling, or optimizations related to migration.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** This file just tests basic QUIC functionality.
* **Correction:**  The presence of "Migrate" and related terms heavily suggests the focus is specifically on connection migration.
* **Initial thought:**  The JavaScript connection is direct.
* **Correction:** The connection is indirect. This C++ code tests the underlying network logic that JavaScript uses.

By following this structured approach, breaking down the code into smaller pieces, and focusing on the core concepts being tested, we can effectively analyze the purpose and functionality of the given source code snippet.
这个C++源代码文件 `net/quic/quic_session_pool_test.cc` 是 Chromium 网络栈中 QUIC 协议会话池的单元测试文件。它的主要功能是**测试 `QuicSessionPool` 类的各种行为和功能，特别是与连接迁移和多路径 QUIC 相关的场景**。

以下是更详细的功能列表：

1. **测试会话的创建和管理:**  验证 `QuicSessionPool` 如何创建、存储、获取和移除 QUIC 会话。
2. **测试连接迁移:** 重点测试在不同网络条件下（例如网络路径劣化、网络切换）QUIC 连接的迁移行为，包括：
    * **主动迁移:** 当检测到当前路径质量下降时，会话迁移到备用网络。
    * **多端口迁移:**  在支持多端口 QUIC 的情况下，迁移到相同的 IP 地址但不同的端口。
    * **迁移到服务器首选地址:** 测试客户端是否能成功迁移到服务器通过 `NEW_CONNECTION_ID` 帧指示的首选地址。
3. **测试路径验证:** 验证在连接迁移过程中，客户端如何探测新的网络路径以确保其可用性。
4. **测试连接 ID 的管理:**  验证连接 ID 的分配、使用和退休机制在连接迁移中的作用。
5. **模拟网络事件:** 使用 `MockQuicData` 和 `TestPortMigrationSocketFactory` 来模拟各种网络数据包的发送和接收，以及网络状态的变化。
6. **使用 Mock 对象:**  使用 Mock 对象（例如 `MockCryptoClientStreamFactory`，`MockNetworkChangeNotifier`) 来隔离被测试的单元，并控制依赖项的行为。
7. **异步操作测试:**  利用 `base::RunLoop` 和 `base::TestMockTimeTaskRunner` 来测试异步操作的正确性，并控制时间流逝。
8. **测试连接错误处理:**  验证在连接迁移过程中发生错误（例如写错误）时的处理逻辑。
9. **与 HTTP Stream 集成测试:**  部分测试涉及到创建 `HttpStream` 对象，模拟 HTTP 请求，以验证 QUIC 会话池在实际应用场景中的行为。

**与 JavaScript 的关系 (间接)：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 QUIC 协议是现代 Web 浏览器与服务器通信的关键协议之一。  当 JavaScript 代码（例如在网页中执行的 `fetch` 或 `XMLHttpRequest`）发起网络请求时，如果协议协商结果是 QUIC，那么浏览器底层就会使用这部分 C++ 代码实现的 QUIC 栈来处理网络连接。

**举例说明:**

假设一个用户正在使用 Chrome 浏览器访问一个支持 QUIC 的网站。在访问过程中，用户的网络从 Wi-Fi 切换到了移动数据网络。

1. **JavaScript 发起请求:** 网页中的 JavaScript 代码发起了一个 `fetch('https://example.com/data')` 请求。
2. **协议协商:** 浏览器在建立连接时，与服务器协商使用 QUIC 协议。
3. **QUIC 会话建立:** `QuicSessionPool` 负责创建和管理与 `example.com` 的 QUIC 会话。
4. **网络切换检测:**  Chromium 的网络层检测到网络从 Wi-Fi 切换到移动数据网络。
5. **连接迁移 (测试重点):**  `QuicSessionPoolTest.cc` 中测试的连接迁移逻辑会被触发。`QuicSessionPool` 尝试在新的网络接口上建立新的 QUIC 连接，并将正在进行的请求迁移到新的连接上。
6. **数据传输:**  一旦迁移成功，JavaScript 发起的 `fetch` 请求的数据会通过新的移动数据网络连接传输到浏览器。
7. **用户感知:**  用户可能只会注意到网络切换时可能出现的短暂延迟，但请求最终会成功完成。

**逻辑推理，假设输入与输出:**

**测试场景:** `MigrateOnPathDegradingSync` (同步写入后路径劣化迁移)

* **假设输入:**
    * 初始网络连接正常。
    * `session->connection()->OnPathDegradingDetected()` 被调用，模拟检测到当前网络路径质量下降。
    * `quic_data2` 模拟了备用网络上的数据包交互，包括 `PathResponseFrame`。
    * 在路径劣化发生前，客户端成功同步地写入了一个数据包。
* **预期输出:**
    * QUIC 会话会尝试迁移到备用网络。
    * 客户端会在备用网络上发送 `PathChallengeFrame` 进行探测。
    * 收到 `PathResponseFrame` 后，迁移被确认为成功。
    * 正在进行的 HTTP 请求会通过备用网络继续完成。
    * `EXPECT_THAT(callback_.WaitForResult(), IsOk())` 断言会成功，表明请求最终成功。

**用户或编程常见的使用错误:**

* **网络配置错误:**  用户的操作系统或防火墙可能阻止 QUIC 连接迁移到新的网络接口或端口。例如，防火墙可能只允许特定端口的 UDP 流量。
* **服务器不支持连接迁移:** 如果服务器没有实现或启用 QUIC 连接迁移功能，客户端的迁移尝试会失败，可能导致连接中断。
* **应用程序逻辑错误:**  在某些情况下，应用程序的逻辑可能与连接迁移的预期行为冲突。例如，应用程序可能在连接迁移完成前就关闭了相关的 socket。
* **测试代码中的错误:**  `QuicSessionPoolTest.cc` 本身是测试代码，如果测试用例编写不当，可能会导致误判或无法覆盖所有场景。例如，模拟的网络数据包序列不完整或不正确。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户网络环境发生变化:** 用户可能从 Wi-Fi 网络断开，并连接到蜂窝数据网络，或者网络信号突然变差。
2. **Chromium 网络栈检测到网络变化或路径劣化:**  Chromium 的网络状态监听器会检测到这些变化。
3. **QUIC 连接检测到路径劣化:**  底层的 QUIC 连接会通过丢包率、延迟等指标判断当前路径的质量是否下降。
4. **`QuicConnection::OnPathDegradingDetected()` 被调用:**  QUIC 连接层通知 `QuicSession` 连接路径可能需要切换。
5. **`QuicSession` 触发连接迁移逻辑:**  `QuicSession` 决定是否以及如何进行连接迁移，并与 `QuicSessionPool` 交互。
6. **`QuicSessionPool` 参与连接迁移管理:**  `QuicSessionPool` 负责管理可用的备用会话或创建新的会话，并协调连接迁移的过程。
7. **相关的 `QuicSessionPoolTest` 测试用例被执行 (在开发或测试阶段):**  开发人员或测试人员会运行 `QuicSessionPoolTest.cc` 中的测试用例，例如 `MigrateOnPathDegradingSync`，来验证上述步骤的逻辑是否正确。如果出现问题，可以通过调试这些测试用例来定位错误。

**作为第 7 部分的功能归纳:**

作为共 20 部分的第 7 部分，这个文件 `net/quic/quic_session_pool_test.cc` 的重点很可能在于 **QUIC 连接迁移的核心机制和早期阶段的测试**。  它可能涵盖了以下方面：

* **基本的连接迁移流程:**  从检测到路径劣化到尝试迁移到备用网络。
* **同步场景下的迁移行为:**  测试在同步操作进行时发生的迁移。
* **路径验证的初步测试:**  验证客户端如何探测备用网络。
* **连接 ID 管理在简单迁移场景中的应用。**

后续的部分很可能会涉及更复杂的连接迁移场景，例如：

* 异步场景下的迁移。
* 多路径 QUIC 的更深入测试。
* 连接迁移的错误处理和回滚机制。
* 与不同网络状态和网络变化的交互。
* 性能和资源管理方面的测试。

总而言之， `net/quic/quic_session_pool_test.cc`  是 Chromium QUIC 栈中至关重要的测试文件，用于确保连接迁移功能的正确性和健壮性，这对于提供流畅的网络体验至关重要，尤其是在移动网络等不稳定的环境下。

Prompt: 
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共20部分，请归纳一下它的功能

"""
AddRead(
      SYNCHRONOUS,
      server_maker_.Packet(2).AddPathResponseFrame().AddPaddingFrame().Build());
  quic_data2.AddRead(
      SYNCHRONOUS,
      server_maker_.Packet(3).AddPathResponseFrame().AddPaddingFrame().Build());
  quic_data2.AddRead(
      SYNCHRONOUS,
      server_maker_.Packet(4).AddPathResponseFrame().AddPaddingFrame().Build());
  quic_data2.AddWrite(ASYNC, client_maker_.MakeAckAndRetransmissionPacket(
                                 packet_number++, 1, 4, 1, {1, 2}));
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_number++)
                                       .AddRetireConnectionIdFrame(0u)
                                       .Build());
  quic_data2.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 5, GetNthClientInitiatedBidirectionalStreamId(0), false));
  quic_data2.AddReadPauseForever();
  quic_data2.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++)
          .AddAckFrame(/*first_received=*/1, /*largest_received=*/5,
                       /*smallest_received=*/1)
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
  // Session will start to probe the alternate network.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

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

  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Response headers are received over the new network.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Deliver a signal that the alternate network now becomes default to session,
  // this will cancel migrate back to default network timer.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

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

// This test verifies that the connection migrates to the alternate network
// early when path degrading is detected with an ASYNCHRONOUS write before
// migration.
TEST_P(QuicSessionPoolTest, MigrateEarlyOnPathDegradingAsync) {
  TestMigrationOnPathDegrading(/*async_write_before_migration*/ true);
}

// This test verifies that the connection migrates to the alternate network
// early when path degrading is detected with a SYNCHRONOUS write before
// migration.
TEST_P(QuicSessionPoolTest, MigrateEarlyOnPathDegradingSync) {
  TestMigrationOnPathDegrading(/*async_write_before_migration*/ false);
}

void QuicSessionPoolTest::TestMigrationOnPathDegrading(
    bool async_write_before) {
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
  if (async_write_before) {
    quic_data1.AddWrite(ASYNC, OK);
    packet_number++;
  }
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
      server_maker_.Packet(1).AddPathResponseFrame().AddPaddingFrame().Build());
  // in-flight SETTINGS and requests will be retransmitted. Since data is
  // already sent on the new address, ping will no longer be sent.
  quic_data2.AddWrite(ASYNC,
                      client_maker_.MakeCombinedRetransmissionPacket(
                          /*original_packet_numbers=*/{1, 2}, packet_number++));
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_number++)
                                       .AddRetireConnectionIdFrame(0u)
                                       .Build());
  quic_data2.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), false));
  quic_data2.AddReadPauseForever();
  quic_data2.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++)
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

  if (async_write_before) {
    session->connection()->SendPing();
  }

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

  // Resume quic data and a connectivity probe response will be read on the new
  // socket.
  quic_data2.Resume();

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // There should be a task that will complete the migration to the new network.
  task_runner->RunUntilIdle();

  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Response headers are received over the new network.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Deliver a signal that the alternate network now becomes default to session,
  // this will cancel mgirate back to default network timer.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

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

TEST_P(QuicSessionPoolTest, MigrateSessionEarlyProbingWriterError) {
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

  int packet_number = 1;
  MockQuicData quic_data1(version_);
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_number++));
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructGetRequestPacket(
                          packet_number++,
                          GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddReadPause();
  quic_data1.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddReadPauseForever();

  // Set up the second socket data provider that is used for path validation.
  MockQuicData quic_data2(version_);
  quic::QuicConnectionId cid_on_old_path =
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator());
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
  // Connectivity probe to be sent on the new path.
  quic_data2.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  ++packet_number;  // Account for the packet encountering write error.
  quic_data2.AddReadPause();
  quic_data2.AddRead(
      ASYNC,
      server_maker_.Packet(1).AddPathResponseFrame().AddPaddingFrame().Build());

  // Connection ID is retired on the old path.
  client_maker_.set_connection_id(cid_on_old_path);
  quic_data1.AddWrite(SYNCHRONOUS,
                      client_maker_.Packet(packet_number++)
                          .AddRetireConnectionIdFrame(/*sequence_number=*/1u)
                          .Build());

  quic_data1.AddSocketDataToFactory(socket_factory_.get());
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
  // Session will start to probe the alternate network.
  // However, the probing writer will fail. This should result in a failed probe
  // but no connection close.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // The connection should still be alive, and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // There should be one task of notifying the session that probing failed, and
  // a second as a DoNothingAs callback.
  EXPECT_TRUE(session->connection()->HasPendingPathValidation());
  EXPECT_EQ(2u, task_runner->GetPendingTaskCount());
  base::TimeDelta next_task_delay = task_runner->NextPendingTaskDelay();
  EXPECT_EQ(base::TimeDelta(), next_task_delay);
  task_runner->FastForwardBy(next_task_delay);
  // Verify that path validation is cancelled.
  EXPECT_FALSE(session->connection()->HasPendingPathValidation());

  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  quic_data1.Resume();
  // Response headers are received on the original network..
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Verify that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       MigrateSessionEarlyProbingWriterErrorThreeNetworks) {
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
  base::RunLoop().RunUntilIdle();

  quic::QuicConnectionId cid_on_path1 =
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator());
  quic::QuicConnectionId cid_on_path2 = quic::test::TestConnectionId(12345678);

  int packet_number = 1;
  MockQuicData quic_data1(version_);
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_number++));
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructGetRequestPacket(
                          packet_number++,
                          GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddReadPause();
  quic_data1.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddReadPauseForever();

  // Set up the second socket data provider that is used for path validation.
  MockQuicData quic_data2(version_);
  client_maker_.set_connection_id(cid_on_path2);
  // Connectivity probe to be sent on the new path.
  quic_data2.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data2.AddReadPause();
  quic_data2.AddRead(
      ASYNC,
      server_maker_.Packet(1).AddPathResponseFrame().AddPaddingFrame().Build());
  packet_number++;  // Account for packet encountering write error.

  // Connection ID is retired on the old path.
  client_maker_.set_connection_id(cid_on_path1);
  quic_data1.AddWrite(ASYNC,
                      client_maker_.Packet(packet_number++)
                          .AddRetireConnectionIdFrame(/*sequence_number=*/1u)
                          .Build());

  // A socket will be created for a new path, but there would be no write
  // due to lack of new connection ID.
  MockQuicData quic_data3(version_);
  quic_data3.AddReadPauseForever();

  quic_data1.AddSocketDataToFactory(socket_factory_.get());
  quic_data2.AddSocketDataToFactory(socket_factory_.get());
  quic_data3.AddSocketDataToFactory(socket_factory_.get());

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
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_path2, session);
  base::RunLoop().RunUntilIdle();
  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  // Cause the connection to report path degrading to the session.
  // Session will start to probe the alternate network.
  // However, the probing writer will fail. This should result in a failed probe
  // but no connection close.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // The connection should still be alive, and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // There should be one task of notifying the session that probing failed, and
  // one that was posted as a DoNothingAs callback.
  EXPECT_TRUE(session->connection()->HasPendingPathValidation());
  EXPECT_EQ(2u, task_runner->GetPendingTaskCount());

  // Trigger another path degrading, but this time another network is available.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->SetConnectedNetworksList({kDefaultNetworkForTests, 3});
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();

  base::TimeDelta next_task_delay = task_runner->NextPendingTaskDelay();
  EXPECT_EQ(base::TimeDelta(), next_task_delay);
  task_runner->FastForwardBy(next_task_delay);
  // Verify that the task is executed.
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());
  // No pending path validation as there is no connection ID available.
  EXPECT_FALSE(session->connection()->HasPendingPathValidation());

  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  quic_data1.Resume();
  // Response headers are received on the original network..
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  base::RunLoop().RunUntilIdle();
  // Verify that the session is still alive.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  base::RunLoop().RunUntilIdle();
  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, MultiPortSessionWithMigration) {
  // Turning on both MPQC and MPQM will implicitly turn on port migration.
  quic_params_->client_connection_options.push_back(quic::kMPQC);
  quic_params_->client_connection_options.push_back(quic::kMPQM);
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  MockQuicData quic_data1(version_);
  quic_data1.AddReadPauseForever();
  quic_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(1));
  quic_data1.AddWrite(
      SYNCHRONOUS, ConstructGetRequestPacket(
                       3, GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the second socket data provider that is used for multi-port
  MockQuicData quic_data2(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);

  client_maker_.set_connection_id(cid_on_new_path);
  // Connectivity probe to be sent on the new path.
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(2)
                                       .AddPathChallengeFrame()
                                       .AddPaddingFrame()
                                       .Build());
  quic_data2.AddReadPause();
  // Connectivity probe to receive from the server.
  quic_data2.AddRead(
      ASYNC,
      server_maker_.Packet(1).AddPathResponseFrame().AddPaddingFrame().Build());
  quic_data2.AddReadPause();
  quic_data2.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), false));
  quic_data2.AddReadPause();
  quic_data2.AddWrite(ASYNC, client_maker_.Packet(4)
                                 .AddAckFrame(/*first_received=*/1,
                                              /*largest_received=*/2,
                                              /*smallest_received=*/1)
                                 .AddPingFrame()
                                 .Build());
  quic_data2.AddWrite(SYNCHRONOUS,
                      client_maker_.Packet(5)
                          .AddRetireConnectionIdFrame(/*sequence_number=*/0u)
                          .Build());
  quic_data2.AddRead(ASYNC,
                     server_maker_.Packet(3).AddAckFrame(1, 5, 1).Build());
  quic_data2.AddReadPauseForever();
  quic_data2.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(6)
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
  // Manually initialize the connection's self address. In real life, the
  // initialization will be done during crypto handshake.
  IPEndPoint ip;
  session->GetDefaultSocket()->GetLocalAddress(&ip);
  quic::test::QuicConnectionPeer::SetSelfAddress(session->connection(),
                                                 ToQuicSocketAddress(ip));

  // This will trigger multi-port path creation.
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);
  base::RunLoop().RunUntilIdle();

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

  // Resume quic data and a connectivity probe response will be read on the new
  // socket. This makes the multi-port path ready to migrate.
  quic_data2.Resume();

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Cause the connection to report path degrading to the session.
  // Session will start migrate to multi-port path immediately.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  // The connection should still be degrading because no new packets are
  // received from the new path.
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // The response is received on the new path.
  quic_data2.Resume();
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());
  task_runner->RunUntilIdle();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Receives an ack from the server, this will be considered forward progress.
  quic_data2.Resume();
  task_runner->RunUntilIdle();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  stream.reset();
  task_runner->RunUntilIdle();
  base::RunLoop().RunUntilIdle();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, SuccessfullyMigratedToServerPreferredAddress) {
  IPEndPoint server_preferred_address = IPEndPoint(IPAddress(1, 2, 3, 4), 123);
  FLAGS_quic_enable_chaos_protection = false;
  quic_params_->allow_server_migration = true;
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  quic::QuicConfig config;
  config.SetIPv4AlternateServerAddressToSend(
      ToQuicSocketAddress(server_preferred_address));
  quic::test::QuicConfigPeer::SetPreferredAddressConnectionIdAndToken(
      &config, kNewCID, quic::QuicUtils::GenerateStatelessResetToken(kNewCID));
  crypto_client_stream_factory_.SetConfig(config);
  // Use cold start mode to send crypto message for handshake.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  int packet_number = 1;
  MockQuicData quic_data1(vers
"""


```
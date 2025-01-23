Response:
My thinking process to analyze the provided C++ code snippet and generate the summary went through these steps:

1. **Understand the Goal:** The prompt asks for a functional summary of the `net/quic/quic_session_pool_test.cc` file, focusing on its relationship with JavaScript, logical reasoning (with input/output examples), common user/programming errors, debugging information, and a concise overall function summary. It also specifies this is part 12 of 20.

2. **Initial Code Scan (Keywords and Structure):** I quickly scanned the code looking for keywords and structural elements that provide clues about its purpose. I noticed:
    * `TEST_P`:  Indicates parameterized tests, a common pattern in C++ testing frameworks. This tells me the code is about testing.
    * `QuicSessionPoolTest`:  The name of the test fixture, clearly pointing to testing the `QuicSessionPool`.
    * `MockQuicData`, `MockCryptoClientStreamFactory`, `socket_factory_`: Suggests the use of mocking to simulate network interactions and crypto operations.
    * `InitializeConnectionMigrationV2Test`:  A function name indicating testing of connection migration, especially version 2.
    * `ERR_IO_PENDING`, `OK`, `ERR_QUIC_HANDSHAKE_FAILED`, `ERR_NETWORK_CHANGED`: Error codes relevant to network operations.
    * `base::RunLoop().RunUntilIdle()`:  Indicates asynchronous operations and waiting for them to complete.
    *  Various `EXPECT_*` macros: Standard C++ testing assertions.

3. **Identify Core Functionality:** Based on the keywords and structure, I concluded that the primary function of this file is to **test the `QuicSessionPool` component of Chromium's QUIC implementation.**  Specifically, it focuses heavily on **connection migration** scenarios.

4. **Analyze Individual Tests (Pattern Recognition):** I then started examining the individual test cases. I noticed repeating patterns:
    * **Setup:** Initializing mocks (`MockQuicData`, etc.), configuring the test environment (e.g., enabling/disabling features like `FLAGS_quic_enable_chaos_protection`), and creating a request (`RequestBuilder`).
    * **Execution:** Performing actions that trigger QUIC behavior, such as initiating a connection, sending data (simulated through `socket_data.AddWrite`), and simulating network events (e.g., `session->connection()->OnPathDegradingDetected()`, `scoped_mock_network_change_notifier_->...`).
    * **Assertions:** Using `EXPECT_*` macros to verify the expected outcomes, like the presence or absence of active sessions, the completion status of requests, and the consumption of simulated data.

5. **Focus on Connection Migration:** The repeated use of `InitializeConnectionMigrationV2Test` and tests with names like `NoMigrationOnPathDegradingBeforeHandshakeConfirmed`, `NewConnectionBeforeHandshakeAfterIdleTimeout`, `MigrationOnWriteErrorBeforeHandshakeConfirmed`, etc., confirmed that a significant portion of the testing is dedicated to connection migration, including different scenarios (before/after handshake, with/without alternate networks, triggered by different events).

6. **JavaScript Relationship (Absence):**  I carefully reviewed the code and found no direct interaction with JavaScript. The tests operate at a lower level within the Chromium network stack. Therefore, I concluded there's no direct functional relationship.

7. **Logical Reasoning (Input/Output):** I considered how to illustrate logical reasoning. A good example is the `NoMigrationOnPathDegradingBeforeHandshakeConfirmed` test.
    * **Input:** A simulated network path degradation signal (`session->connection()->OnPathDegradingDetected()`) *before* the QUIC handshake is confirmed.
    * **Expected Output:** The test verifies that connection migration *does not* occur in this scenario (no new tasks scheduled, `GetNumDegradingSessions` increments but no migration). This demonstrates a conditional logic based on the handshake status.

8. **Common Errors:** I looked for test scenarios that implicitly reveal potential usage errors. Tests involving write errors (`MigrationOnWriteError...`) and network changes (`MigrateSessionOnWriteErrorNoNewNetwork...`) highlight situations where network conditions can lead to errors. A user might encounter `ERR_NETWORK_CHANGED` if the underlying network connection is disrupted during a QUIC session.

9. **Debugging Clues:** The test setup itself provides debugging clues. The use of `MockQuicData` allows developers to precisely control the sequence of bytes sent and received, making it easier to isolate and debug network-related issues. The assertions help pinpoint where the actual behavior deviates from the expected behavior.

10. **User Operation to Code Path:** I thought about how a user action might lead to this code being relevant. A simple scenario is a user browsing a website over a QUIC connection. If the network conditions change (e.g., switching from Wi-Fi to cellular), the connection migration logic tested here would be invoked to maintain the connection.

11. **Part 12 of 20:**  Knowing this is part 12 helped frame the summary. It suggests the file likely covers a specific subset of the `QuicSessionPool`'s functionality, which in this case is heavily focused on connection migration.

12. **Concise Summary:** Finally, I synthesized the findings into a concise summary, highlighting the core purpose (testing `QuicSessionPool`, especially connection migration), the use of mocks, and the types of scenarios covered.

By following these steps, I was able to dissect the C++ code snippet, understand its purpose, identify relevant details, and generate the comprehensive summary provided earlier. The key was to combine a high-level understanding of the testing framework with a detailed examination of the individual test cases.
这个文件 `net/quic/quic_session_pool_test.cc` 是 Chromium 网络栈中 QUIC 协议的 `QuicSessionPool` 组件的 **单元测试** 文件。它的主要功能是验证 `QuicSessionPool` 在各种场景下的行为是否符合预期。

以下是该文件的功能归纳和详细说明：

**功能归纳 (基于提供的代码片段):**

这个测试文件主要关注 `QuicSessionPool` 在 **连接迁移 (Connection Migration)** 方面的行为，特别是：

* **在握手完成前后，网络路径发生变化时的处理:**
    * 测试在握手完成前，检测到路径退化是否会触发迁移。
    * 测试在握手完成前，连接因超时（网络空闲或握手超时）关闭时，是否会在没有备用网络的情况下创建新连接。
    * 测试在握手完成前，连接因超时关闭时，是否会在有备用网络的情况下创建新连接。
* **在握手完成前后，遇到写入错误时的处理:**
    * 测试在握手完成前遇到写入错误时，是否会触发迁移。
    * 测试在握手完成前遇到写入错误时，是否会在有备用网络的情况下重试连接。
    * 测试在握手完成后遇到写入错误时，是否会触发迁移到备用网络。
    * 测试在握手完成后遇到写入错误且没有备用网络时，会发生什么。
* **基本的会话管理和流管理:**
    * 测试成功建立连接和创建流的基本场景。

**详细功能说明:**

1. **连接管理:**  `QuicSessionPool` 负责管理和复用 QUIC 会话。测试用例验证了会话的创建、激活、关闭以及在网络状态变化时的行为。例如：
    * 测试了在连接建立过程中，如果底层网络出现问题，`QuicSessionPool` 是否能正确处理，并根据配置决定是否尝试新的连接。
    * 测试了在没有备用网络的情况下，连接因超时关闭后，不会尝试创建新的连接。
    * 测试了在有备用网络的情况下，连接因超时或写入错误关闭后，会尝试在备用网络上建立新连接。

2. **连接迁移 (Connection Migration):**  QUIC 的一个重要特性是连接迁移，允许在网络路径发生变化时保持连接。测试用例重点验证了 `QuicSessionPool` 在以下连接迁移场景下的行为：
    * **路径退化 (Path Degrading):**  模拟网络质量下降的情况，测试是否会触发连接迁移。
    * **网络超时 (Network Timeout):**  模拟连接因空闲或握手超时而关闭的情况，测试是否会尝试新的连接。
    * **写入错误 (Write Error):**  模拟发送数据包时遇到错误的情况，测试是否会触发连接迁移。
    * **备用网络 (Alternate Network):**  测试在有备用网络的情况下，连接迁移是否能成功切换到备用网络。

3. **流管理 (Stream Management):**  QUIC 连接上可以创建多个流用于并发传输数据。测试用例验证了基本的流创建和使用。例如：
    * 测试了在成功建立连接后，可以创建和使用 QUIC 流。

**与 Javascript 的关系:**

这个 C++ 测试文件 **没有直接的 Javascript 功能关系**。它位于 Chromium 的网络栈底层，负责 QUIC 协议的具体实现。Javascript (通常运行在浏览器渲染进程中) 通过 Chromium 提供的更上层的 API (例如 Fetch API 或 XMLHttpRequest) 来发起网络请求，这些请求最终可能会使用 QUIC 协议，并间接地依赖于 `QuicSessionPool` 的正确工作。

**举例说明 (如果存在间接关系):**

假设一个 Javascript 应用使用 `fetch('https://www.example.org')` 发起一个 HTTPS 请求。如果浏览器和服务器支持 QUIC，这个请求可能会通过 QUIC 进行传输。

* **情景:**  在数据传输过程中，用户的网络从 Wi-Fi 切换到移动数据网络。
* **`QuicSessionPool` 的作用 (这个测试文件验证的行为):**
    * 测试文件中的 `TestMigrationOnWriteErrorSynchronous` 或 `TestMigrationOnWriteErrorAsync` 等测试用例模拟了类似的底层网络写入错误场景。
    * 这些测试验证了 `QuicSessionPool` 能否检测到写入错误，并尝试在新的网络路径上重新建立连接，从而保证 Javascript 应用的 `fetch` 请求不会因为网络切换而中断。

**逻辑推理 (假设输入与输出):**

**示例 1:  `NoMigrationOnPathDegradingBeforeHandshakeConfirmed` 测试**

* **假设输入:**
    * QUIC 连接正在建立握手，但尚未完成。
    * 底层网络报告路径退化 (例如，延迟增加，丢包率上升)。
* **预期输出:**
    * `HasActiveSession(kDefaultDestination)` 为 `false` (因为握手尚未完成)。
    * 连接 **不会** 尝试迁移到新的路径 (`task_runner->GetPendingTaskCount()` 为 `0`)。
    * `QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get())` 会增加，表示 `QuicSessionPool` 知道有连接正在退化。

**示例 2: `NewConnectionBeforeHandshakeAfterIdleTimeout` 测试**

* **假设输入:**
    * QUIC 连接正在尝试握手。
    * 在握手完成前，连接由于网络空闲超时而关闭。
    * 存在一个可用的备用网络。
* **预期输出:**
    * 原来的连接被关闭。
    * `QuicSessionPool` 会尝试在备用网络上建立新的 QUIC 连接。
    * `HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED)` 为 `true`，表示正在尝试建立新的连接。

**用户或编程常见的使用错误:**

虽然用户不会直接操作 `QuicSessionPool`，但编程错误可能会导致与 `QuicSessionPool` 相关的行为异常：

* **错误配置 QUIC 参数:** 例如，错误地配置连接迁移相关的参数，可能导致连接在网络变化时无法正常迁移，或者过于激进地迁移。
* **Mock 设置不当:** 在测试中，如果 `MockQuicData` 的设置与实际的网络行为不符，可能会导致测试结果不准确。例如，忘记 `Resume()` 模拟的 socket 数据读取，导致测试一直阻塞。
* **没有正确处理异步操作:**  QUIC 操作是异步的，如果没有正确使用 `base::RunLoop().RunUntilIdle()` 或其他异步处理机制，可能会导致测试提前结束，无法覆盖到完整的场景。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在 Chrome 浏览器中访问一个支持 QUIC 的网站 (例如使用 HTTPS)。**
2. **浏览器网络栈尝试与服务器建立 QUIC 连接。**
3. **`QuicSessionPool` 负责查找或创建到目标服务器的 QUIC 会话。**
4. **如果网络环境发生变化 (例如 Wi-Fi 断开，切换到移动网络)，QUIC 连接可能会触发连接迁移。**
5. **`QuicSessionPool` 会根据当前的网络状态和配置，决定是否尝试迁移到新的网络路径。**
6. **如果调试时发现连接迁移行为异常，开发者可能会查看 `net/quic/quic_session_pool_test.cc` 中的相关测试用例，例如 `MigrateSessionOnWriteErrorSynchronous`，来理解和验证 `QuicSessionPool` 在类似场景下的预期行为。**
7. **开发者可能会修改测试用例，添加断点，或者使用日志输出等手段来定位问题。**
8. **通过分析测试用例的执行过程和 `MockQuicData` 的交互，开发者可以深入了解 `QuicSessionPool` 的内部逻辑，并找出导致问题的根源。**

**第 12 部分，共 20 部分，它的功能:**

考虑到这是测试套件的第 12 部分，并且内容主要集中在连接迁移上，可以推断这部分测试主要负责 **验证 `QuicSessionPool` 在各种连接迁移场景下的正确性和健壮性**。 这部分可能涵盖了从简单的迁移到更复杂的场景，例如在握手期间的迁移、在有或没有备用网络的情况下的迁移、以及由不同事件触发的迁移。 整个测试套件的其他部分可能会涵盖 `QuicSessionPool` 的其他功能，例如会话的创建和销毁、流的管理、拥塞控制等等。

总而言之，`net/quic/quic_session_pool_test.cc` 是一个关键的测试文件，用于确保 Chromium 的 QUIC 连接管理组件 `QuicSessionPool` 能够可靠地工作，特别是在网络环境发生变化时能够平滑地进行连接迁移，从而提供更好的用户体验。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
Session(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream1.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
  quic_data3.ExpectAllReadDataConsumed();
  quic_data3.ExpectAllWriteDataConsumed();
}

// This test verifies that the connection will not attempt connection migration
// (send connectivity probes on alternate path) when path degrading is detected
// and handshake is not confirmed.
TEST_P(QuicSessionPoolTest,
       NoMigrationOnPathDegradingBeforeHandshakeConfirmed) {
  FLAGS_quic_enable_chaos_protection = false;
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});

  // Using a testing task runner.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  // Use cold start mode to send crypto message for handshake.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(ASYNC, client_maker_.MakeDummyCHLOPacket(1));
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  base::RunLoop().RunUntilIdle();

  // Ensure that session is alive but not active.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  QuicChromiumClientSession* session = GetPendingSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());

  // Cause the connection to report path degrading to the session.
  // Session will ignore the signal as handshake is not completed.
  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

// This test verifies that if a connection is closed with
// QUIC_NETWORK_IDLE_TIMEOUT before handshake is completed and there is no
// alternate network, no new connection will be created.
TEST_P(QuicSessionPoolTest, NoAlternateNetworkBeforeHandshakeOnIdleTimeout) {
  TestNoAlternateNetworkBeforeHandshake(quic::QUIC_NETWORK_IDLE_TIMEOUT);
}

// This test verifies that if a connection is closed with QUIC_HANDSHAKE_TIMEOUT
// and there is no alternate network, no new connection will be created.
TEST_P(QuicSessionPoolTest, NoAlternateNetworkOnHandshakeTimeout) {
  TestNoAlternateNetworkBeforeHandshake(quic::QUIC_HANDSHAKE_TIMEOUT);
}

void QuicSessionPoolTest::TestNoAlternateNetworkBeforeHandshake(
    quic::QuicErrorCode quic_error) {
  FLAGS_quic_enable_chaos_protection = false;
  DCHECK(quic_error == quic::QUIC_NETWORK_IDLE_TIMEOUT ||
         quic_error == quic::QUIC_HANDSHAKE_TIMEOUT);
  InitializeConnectionMigrationV2Test({kDefaultNetworkForTests});

  // Using a testing task runner.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  // Use cold start mode to send crypto message for handshake.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(ASYNC, client_maker_.MakeDummyCHLOPacket(1));
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  base::RunLoop().RunUntilIdle();

  // Ensure that session is alive but not active.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  QuicChromiumClientSession* session = GetPendingSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  // Cause the connection to report path degrading to the session.
  // Session will ignore the signal as handshake is not completed.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  // Cause the connection to close due to |quic_error| before handshake.
  std::string error_details;
  if (quic_error == quic::QUIC_NETWORK_IDLE_TIMEOUT) {
    error_details = "No recent network activity.";
  } else {
    error_details = "Handshake timeout expired.";
  }
  session->connection()->CloseConnection(
      quic_error, error_details, quic::ConnectionCloseBehavior::SILENT_CLOSE);

  // A task will be posted to clean up the session in the factory.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  task_runner->FastForwardUntilNoTasksRemain();

  // No new session should be created as there is no alternate network.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, NewConnectionBeforeHandshakeAfterIdleTimeout) {
  TestNewConnectionOnAlternateNetworkBeforeHandshake(
      quic::QUIC_NETWORK_IDLE_TIMEOUT);
}

TEST_P(QuicSessionPoolTest, NewConnectionAfterHandshakeTimeout) {
  TestNewConnectionOnAlternateNetworkBeforeHandshake(
      quic::QUIC_HANDSHAKE_TIMEOUT);
}

// Sets up a test to verify that a new connection will be created on the
// alternate network after the initial connection fails before handshake with
// signals delivered in the following order (alternate network is available):
// - the default network is not able to complete crypto handshake;
// - the original connection is closed with |quic_error|;
// - a new connection is created on the alternate network and is able to finish
//   crypto handshake;
// - the new session on the alternate network attempts to migrate back to the
//   default network by sending probes;
// - default network being disconnected is delivered: session will stop probing
//   the original network.
// - alternate network is made by default.
void QuicSessionPoolTest::TestNewConnectionOnAlternateNetworkBeforeHandshake(
    quic::QuicErrorCode quic_error) {
  DCHECK(quic_error == quic::QUIC_NETWORK_IDLE_TIMEOUT ||
         quic_error == quic::QUIC_HANDSHAKE_TIMEOUT);
  FLAGS_quic_enable_chaos_protection = false;
  // TODO(crbug.com/40821140): Make this test work with asynchronous QUIC
  // session creation. This test only works with synchronous session creation
  // for now.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);

  quic_params_->retry_on_alternate_network_before_handshake = true;
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});

  // Using a testing task runner.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  // Use cold start mode to send crypto message for handshake.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  // Socket data for connection on the default network.
  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(ASYNC, client_maker_.MakeDummyCHLOPacket(1));
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Socket data for connection on the alternate network.
  MockQuicData socket_data2(version_);
  int packet_num = 1;
  socket_data2.AddWrite(SYNCHRONOUS,
                        client_maker_.MakeDummyCHLOPacket(packet_num++));
  socket_data2.AddReadPause();
  // Change the encryption level after handshake is confirmed.
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  socket_data2.AddWrite(ASYNC, ConstructInitialSettingsPacket(packet_num++));
  socket_data2.AddWrite(
      ASYNC,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
  socket_data2.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false));
  socket_data2.AddReadPauseForever();
  int probing_packet_num = packet_num++;
  socket_data2.AddWrite(SYNCHRONOUS,
                        client_maker_.Packet(packet_num++)
                            .AddRetireConnectionIdFrame(/*sequence_number=*/1u)
                            .Build());
  socket_data2.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  // Socket data for probing on the default network.
  MockQuicData probing_data(version_);
  quic::QuicConnectionId cid_on_path1 = quic::test::TestConnectionId(1234567);
  client_maker_.set_connection_id(cid_on_path1);
  probing_data.AddReadPauseForever();
  probing_data.AddWrite(SYNCHRONOUS, client_maker_.Packet(probing_packet_num)
                                         .AddPathChallengeFrame()
                                         .AddPaddingFrame()
                                         .Build());
  probing_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  base::RunLoop().RunUntilIdle();

  // Ensure that session is alive but not active.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  QuicChromiumClientSession* session = GetPendingSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());
  EXPECT_FALSE(failed_on_default_network_);

  std::string error_details;
  if (quic_error == quic::QUIC_NETWORK_IDLE_TIMEOUT) {
    error_details = "No recent network activity.";
  } else {
    error_details = "Handshake timeout expired.";
  }
  session->connection()->CloseConnection(
      quic_error, error_details, quic::ConnectionCloseBehavior::SILENT_CLOSE);

  // A task will be posted to clean up the session in the factory.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  task_runner->FastForwardUntilNoTasksRemain();

  // Verify a new session is created on the alternate network.
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  QuicChromiumClientSession* session2 = GetPendingSession(kDefaultDestination);
  EXPECT_NE(session, session2);
  EXPECT_TRUE(failed_on_default_network_);

  // Confirm the handshake on the alternate network.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_path1, session2);
  // Resume the data now so that data can be sent and read.
  socket_data2.Resume();

  // Create the stream.
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));
  // Send the request.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));
  // Run the message loop to finish asynchronous mock write.
  base::RunLoop().RunUntilIdle();
  // Read the response.
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  // There should be a new task posted to migrate back to the default network.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  base::TimeDelta next_task_delay = task_runner->NextPendingTaskDelay();
  EXPECT_EQ(base::Seconds(kMinRetryTimeForDefaultNetworkSecs), next_task_delay);
  task_runner->FastForwardBy(next_task_delay);

  // Deliver the signal that the default network is disconnected.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  // Verify no connectivity probes will be sent as probing will be cancelled.
  task_runner->FastForwardUntilNoTasksRemain();
  // Deliver the signal that the alternate network is made default.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());

  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// Test that connection will be closed with PACKET_WRITE_ERROR if a write error
// is triggered before handshake is confirmed and connection migration is turned
// on.
TEST_P(QuicSessionPoolTest, MigrationOnWriteErrorBeforeHandshakeConfirmed) {
  DCHECK(!quic_params_->retry_on_alternate_network_before_handshake);
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});

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

  // Verify new requests can be sent normally.
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

// Test that if the original connection is closed with QUIC_PACKET_WRITE_ERROR
// before handshake is confirmed and new connection before handshake is turned
// on, a new connection will be retried on the alternate network.
TEST_P(QuicSessionPoolTest,
       RetryConnectionOnWriteErrorBeforeHandshakeConfirmed) {
  FLAGS_quic_enable_chaos_protection = false;
  quic_params_->retry_on_alternate_network_before_handshake = true;
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});

  // Use unmocked crypto stream to do crypto connect.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  // Socket data for connection on the default network.
  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  // Trigger PACKET_WRITE_ERROR when sending packets in crypto connect.
  socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Socket data for connection on the alternate network.
  MockQuicData socket_data2(version_);
  int packet_num = 1;
  socket_data2.AddWrite(SYNCHRONOUS,
                        client_maker_.MakeDummyCHLOPacket(packet_num++));
  socket_data2.AddReadPause();
  // Change the encryption level after handshake is confirmed.
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  socket_data2.AddWrite(ASYNC, ConstructInitialSettingsPacket(packet_num++));
  socket_data2.AddWrite(
      ASYNC,
      ConstructGetRequestPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true));
  socket_data2.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false));
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(
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
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  // Create request, should fail after the write of the CHLO fails.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  // Ensure that the session is alive but not active.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  base::RunLoop().RunUntilIdle();
  QuicChromiumClientSession* session = GetPendingSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));

  // Confirm the handshake on the alternate network.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Resume the data now so that data can be sent and read.
  socket_data2.Resume();

  // Create the stream.
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));
  // Send the request.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));
  // Run the message loop to finish asynchronous mock write.
  base::RunLoop().RunUntilIdle();
  // Read the response.
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  stream.reset();
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

void QuicSessionPoolTest::TestMigrationOnWriteError(IoMode write_error_mode) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
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
      ASYNC, client_maker_.Packet(packet_num++).AddPingFrame().Build());
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

  // Send GET request on stream. This should cause a write error, which triggers
  // a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Run the message loop so that the migration attempt is executed and
  // data queued in the new socket is read by the packet reader.
  base::RunLoop().RunUntilIdle();

  // Verify that session is alive and not marked as going away.
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

TEST_P(QuicSessionPoolTest, MigrateSessionOnWriteErrorSynchronous) {
  TestMigrationOnWriteError(SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest, MigrateSessionOnWriteErrorAsync) {
  TestMigrationOnWriteError(ASYNC);
}

void QuicSessionPoolTest::TestMigrationOnWriteErrorNoNewNetwork(
    IoMode write_error_mode) {
  InitializeConnectionMigrationV2Test({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Use the test task runner, to force the migration alarm timeout later.
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
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

  // Send GET request on stream. This causes a write error, which triggers
  // a connection migration attempt. Since there are no networks
  // to migrate to, this causes the session to wait for a new network.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Complete any pending writes. Pending async MockQuicData writes
  // are run on the message loop, not on the test runner.
  base::RunLoop().RunUntilIdle();

  // Write error causes migration task to be posted. Spin the loop.
  if (write_error_mode == ASYNC) {
    runner_->RunNextTask();
  }

  // Migration has not yet failed. The session should be alive and active.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_TRUE(session->connection()->writer()->IsWriteBlocked());

  // The migration will not fail until the migration alarm timeout.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Force migration alarm timeout to run.
  RunTestLoopUntilIdle();

  // The connection should be closed. A request for response headers
  // should fail.
  EXPECT_FALSE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(ERR_NETWORK_CHANGED, callback_.WaitForResult());
  EXPECT_EQ(ERR_NETWORK_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));

  NetErrorDetails error_details;
  stream->PopulateNetErrorDetails(&error_details);
  EXPECT_EQ(error_details.quic_connection_error,
            quic::QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK);

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, MigrateSessionOnWriteErrorNoNewNetworkSynchronous) {
  TestMigrationOnWriteErrorNoNewNetwork(SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest, MigrateSessionOnWriteErrorNoNewNetworkAsync) {
  TestMigrationOnWriteErrorNoNewNetwork(ASYNC);
}

TEST_P(QuicSessionPoolTest,
       MigrateSessionOnWriteErrorWithMultipleRequestsSync) {
  TestMigrationOnWriteErrorWithMultipleRequests(SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest,
       MigrateSessionOnWriteErrorWithMultipleRequestsAsync) {
  TestMigrationOnWriteErrorWithMultipleRequests(ASYNC);
}

// Sets up a test which verifies that connection migration on write error can
// eventually succeed and rewrite the packet on the new network with *multiple*
// migratable streams.
void QuicSessionPoolTest::TestMigrationOnWriteErrorWithMultipleRequests(
    IoMode write_error_mode) {
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
  socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  MockQuicData socket_data1(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_o
```
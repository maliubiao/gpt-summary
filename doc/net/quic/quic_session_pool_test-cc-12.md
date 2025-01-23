Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/quic/quic_session_pool_test.cc`. Specifically, I need to:

1. **Summarize the code's functionality**: This file seems to contain unit tests for the `QuicSessionPool` in Chromium's network stack. The tests focus on connection migration scenarios when write errors occur.

2. **Identify connections to JavaScript**: QUIC and the network stack are generally lower-level than JavaScript. However, JavaScript in web browsers interacts with these components through APIs like `fetch`. I need to think about how the behaviors tested here might manifest in a browser's JavaScript environment.

3. **Provide examples of logical reasoning**:  The tests involve setting up specific conditions (network errors, multiple requests) and verifying the resulting behavior of the `QuicSessionPool`. I need to create simple "if this input, then this output" scenarios based on the code.

4. **Highlight common user/programming errors**: Incorrect network configuration, issues with server-side implementations, and misunderstandings of QUIC's connection migration behavior could lead to unexpected outcomes.

5. **Explain how a user might reach this code (debugging perspective)**:  If a user is experiencing network connectivity issues, particularly with QUIC connections, they might investigate the network logs or even delve into the Chromium source code to understand how connection migration is behaving.

6. **Summarize the overall function of this specific (13th) code block**: This section seems to be heavily focused on testing various scenarios of connection migration when write errors occur, especially with combinations of migratable and non-migratable streams.

**Mental Sandbox:**

* **JavaScript Connection:** I can imagine a `fetch` call failing due to a network error. If the underlying connection is QUIC, the behavior tested here (migration) could influence whether the `fetch` eventually succeeds on a different network path.
* **Logical Reasoning:**  A simple case: "If a QUIC connection encounters a write error on the current network and an alternate network is available, then the connection should migrate."
* **User Error:**  A user might have a firewall that blocks UDP traffic on certain networks, causing connection migration to fail repeatedly.
* **Debugging Path:** A developer might use `chrome://net-internals` to examine QUIC connection events and see if migrations are occurring as expected. If not, they might look at the `QuicSessionPool` logic.
* **Specific Block Function:** This block seems to be exploring edge cases of migration with different types of streams and error conditions.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果它与javascript的功能有关系，请做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 这是第13部分，共20部分，请归纳一下它的功能: Yes

Confidence Score: 5/5  I have a good understanding of what's needed.

Strategizing complete. I will now generate the response based on the outlined points.
这个文件 `net/quic/quic_session_pool_test.cc` 是 Chromium 网络栈中用于测试 `QuicSessionPool` 类的单元测试文件。 `QuicSessionPool` 的主要职责是管理和复用 QUIC 会话（connections）。

**这个代码片段（第13部分）的主要功能是测试在 QUIC 连接遇到写错误 (write error) 时的连接迁移 (connection migration) 行为。**  它涵盖了多种场景，包括：

* **在有多个并发请求的情况下发生写错误时的迁移。**
* **当请求分为可迁移 (migratable) 和不可迁移 (non-migratable) 时发生写错误时的迁移。**
* **在禁用连接迁移的情况下发生写错误时的行为。**
* **在连续多次遇到写错误时的迁移行为。**

以下是对其功能的详细解释：

**1. 功能列举:**

* **测试连接迁移的基本流程:** 验证当连接在当前网络上遇到写错误时，是否能够成功迁移到备用网络。
* **测试不同 `IoMode` 下的写错误处理:**  `SYNCHRONOUS` 和 `ASYNC` 模拟同步和异步的 I/O 操作，测试在不同 I/O 模式下发生写错误时的迁移行为。
* **测试可迁移和不可迁移请求的混合场景:**  验证当连接上有同时存在可以迁移和不可以迁移的请求时，发生写错误后的迁移行为。不可迁移的请求在迁移时应该会被取消。
* **测试 `migrate_idle_sessions` 配置的影响:** 验证当配置允许迁移空闲会话时，即使只有不可迁移的请求导致写错误，连接是否也会迁移。
* **测试禁用连接迁移时的行为:** 验证当服务器指示禁用连接迁移时，发生写错误是否会导致连接关闭而不是迁移。
* **测试连续写错误时的行为:**  验证在短时间内连续在不同网络上遇到写错误时，连接的迁移和最终状态。

**2. 与 JavaScript 的关系:**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它测试的网络栈功能直接影响到浏览器中 JavaScript 发起的网络请求，尤其是使用 `fetch` API 或 WebSocket 等协议时。

**举例说明:**

假设一个网页通过 `fetch` API 发起了一个请求到启用了 QUIC 的服务器。

* **假设输入 (JavaScript):**
  ```javascript
  fetch('https://www.example.org/data')
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error('请求失败:', error));
  ```

* **内部 QUIC 层面的事件 (对应测试代码):**
  * 客户端的 QUIC 连接当前使用一个网络接口（例如 Wi-Fi）。
  * 由于网络问题（例如 Wi-Fi 信号突然变弱），在尝试发送数据包时遇到了写错误（对应测试代码中的 `ERR_ADDRESS_UNREACHABLE`）。
  * `QuicSessionPool` 检测到错误，并尝试迁移连接到另一个可用的网络接口（例如蜂窝网络，如果允许的话）。
  * 如果迁移成功（对应测试代码中验证迁移后新连接上的数据交互），那么 JavaScript 的 `fetch` 请求可能会在延迟后继续完成，最终 `then` 代码块会被执行。
  * 如果迁移失败（例如服务器禁用了迁移或没有可用的备用网络），JavaScript 的 `fetch` 请求会最终失败，触发 `catch` 代码块。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入:**
    * QUIC 连接当前使用 Wi-Fi 网络。
    * 尝试通过该连接发送一个 GET 请求。
    * Wi-Fi 网络突然出现问题，导致写操作返回 `ERR_ADDRESS_UNREACHABLE`。
    * 客户端配置允许连接迁移，并且有可用的蜂窝网络。
* **预期输出:**
    * `QuicSessionPool` 尝试将 QUIC 连接迁移到蜂窝网络。
    * 迁移过程中，原始的 GET 请求会被重新发送到新的网络路径。
    * 如果迁移成功，服务器会在新的网络路径上响应 GET 请求。
    * 最终，JavaScript 的 `fetch` API 可能会在短暂延迟后接收到响应。

**4. 用户或编程常见的使用错误:**

* **网络配置错误:** 用户的网络环境可能没有正确配置，例如防火墙阻止了 UDP 流量，导致 QUIC 连接建立或迁移失败。
* **服务器不支持连接迁移:**  如果服务器配置为不允许连接迁移，客户端的迁移尝试将会失败。
* **错误的负载标志 (load flags):**  开发者可能错误地设置了 `LOAD_DISABLE_CONNECTION_MIGRATION_TO_CELLULAR` 标志，导致在 Wi-Fi 出现问题时无法迁移到蜂窝网络。
* **不理解连接迁移的限制:**  开发者可能认为连接迁移是无缝的，但实际上迁移过程可能会有延迟，并且并非所有类型的请求都适合在迁移后重试。

**5. 用户操作如何一步步到达这里 (调试线索):**

一个开发者可能因为以下原因查看这段代码：

1. **用户报告网络连接问题:**  用户反馈在使用他们的应用或网站时，QUIC 连接不稳定，经常中断或延迟很高。
2. **开发者使用网络诊断工具:** 开发者可能会使用 Chromium 的内置工具 `chrome://net-internals` 来查看 QUIC 连接的详细信息。他们可能会看到连接迁移尝试失败或频繁迁移的日志。
3. **怀疑是连接迁移的问题:** 基于 `chrome://net-internals` 的信息，开发者可能会怀疑是连接迁移的逻辑出现了问题。
4. **查看 `QuicSessionPool` 的代码:**  为了深入了解连接迁移的实现细节和测试用例，开发者可能会查看 `net/quic/quic_session_pool_test.cc` 中的相关测试，特别是测试连接迁移的场景，以理解可能出现问题的环节。
5. **分析测试用例:** 开发者会阅读像这段代码一样的测试用例，了解在特定网络错误情况下，连接迁移的预期行为，以便对比实际发生的情况，找出差异并定位 bug。

**6. 代码片段功能归纳 (第13部分):**

这段代码片段集中测试了 **在各种写错误场景下，`QuicSessionPool` 如何处理连接迁移，特别是涉及到不同类型的请求（可迁移和不可迁移）以及不同的网络状态时**。它旨在验证连接迁移机制的健壮性和正确性，确保在网络环境不稳定时，QUIC 连接能够尽可能地保持连接，或者在无法保持时能够优雅地处理。这部分测试对于保证 QUIC 连接的稳定性和性能至关重要。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第13部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
n_new_path);
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

  // Second request returns synchronously because it pools to existing session.
  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
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

  // Send GET request on stream. This should cause a write error, which triggers
  // a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream1->SendRequest(request_headers, &response,
                                     callback_.callback()));

  // Run the message loop so that the migration attempt is executed and
  // data queued in the new socket is read by the packet reader.
  base::RunLoop().RunUntilIdle();

  // Verify session is still alive and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(2u, session->GetNumActiveStreams());

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

TEST_P(QuicSessionPoolTest, MigrateOnWriteErrorWithMixedRequestsSync) {
  TestMigrationOnWriteErrorMixedStreams(SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest, MigrateOnWriteErrorWithMixedRequestsAsync) {
  TestMigrationOnWriteErrorMixedStreams(ASYNC);
}

// Sets up a test that verifies connection migration manages to migrate to
// alternate network after encountering a SYNC/ASYNC write error based on
// |write_error_mode| on the original network.
// Note there are mixed types of unfinished requests before migration: one
// migratable and one non-migratable. The *migratable* one triggers write
// error.
void QuicSessionPoolTest::TestMigrationOnWriteErrorMixedStreams(
    IoMode write_error_mode) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  int packet_number = 1;
  MockQuicData socket_data(version_);

  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_number++));
  socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  MockQuicData socket_data1(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(1234567);
  client_maker_.set_connection_id(cid_on_new_path);
  // Increment packet number to account for packet write error on the old
  // path. Also save the packet in client_maker_ for constructing the
  // retransmission packet.
  ConstructGetRequestPacket(packet_number++,
                            GetNthClientInitiatedBidirectionalStreamId(0),
                            /*fin=*/true);
  quic::QuicStreamId stream_1 = GetNthClientInitiatedBidirectionalStreamId(1);
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++)
          .AddPacketRetransmission(1)
          .AddPacketRetransmission(2)
          .AddStopSendingFrame(stream_1, quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(stream_1, quic::QUIC_STREAM_CANCELLED)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(1))
          .Build());
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++).AddPingFrame().Build());
  socket_data1.AddWrite(SYNCHRONOUS,
                        client_maker_.Packet(packet_number++)
                            .AddRetireConnectionIdFrame(/*sequence_number=*/0u)
                            .Build());
  socket_data1.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false));
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0, false))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
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

  // Second request returns synchronously because it pools to existing
  // session.
  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.callback = callback2.callback();
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  HttpRequestInfo request_info2;
  request_info2.method = "GET";
  request_info2.load_flags |= LOAD_DISABLE_CONNECTION_MIGRATION_TO_CELLULAR;
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

  // Send GET request on stream 1. This should cause a write error, which
  // triggers a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream1->SendRequest(request_headers, &response,
                                     callback_.callback()));

  // Run the message loop so that the migration attempt is executed and
  // data queued in the new socket is read by the packet reader.
  base::RunLoop().RunUntilIdle();

  // Verify that the session is still alive and not marked as going away.
  // Non-migratable stream should be closed due to migration.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream1->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  stream1.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, MigrateOnWriteErrorWithMixedRequests2Sync) {
  TestMigrationOnWriteErrorMixedStreams2(SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest, MigrateOnWriteErrorWithMixedRequests2Async) {
  TestMigrationOnWriteErrorMixedStreams2(ASYNC);
}

// The one triggers write error is a non-migratable stream.
// Sets up a test that verifies connection migration manages to migrate to
// alternate network after encountering a SYNC/ASYNC write error based on
// |write_error_mode| on the original network.
// Note there are mixed types of unfinished requests before migration: one
// migratable and one non-migratable. The *non-migratable* one triggers write
// error.
void QuicSessionPoolTest::TestMigrationOnWriteErrorMixedStreams2(
    IoMode write_error_mode) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  int packet_number = 1;
  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_number++));
  socket_data.AddWrite(write_error_mode,
                       ERR_ADDRESS_UNREACHABLE);  // Write error.
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Set up second socket data provider that is used after migration. The
  // request is rewritten to this new socket, and the response to the request is
  // read on this new socket.
  MockQuicData socket_data1(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
  // Increment packet number to account for packet write error on the old
  // path. Also save the packet in client_maker_ for constructing the
  // retransmission packet.
  ConstructGetRequestPacket(packet_number++,
                            GetNthClientInitiatedBidirectionalStreamId(1),
                            /*fin=*/true);

  base::RepeatingCallback<bool(const quic::QuicFrame&)> control_stream_only =
      FilterControlStreamOnly();
  quic::QuicStreamId stream_1 = GetNthClientInitiatedBidirectionalStreamId(1);
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++)
          .AddPacketRetransmission(1, control_stream_only)
          .AddPacketRetransmission(2, control_stream_only)
          .AddStopSendingFrame(stream_1, quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(stream_1, quic::QUIC_STREAM_CANCELLED)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(1))
          .Build());
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++).AddPingFrame().Build());
  socket_data1.AddWrite(SYNCHRONOUS,
                        client_maker_.Packet(packet_number++)
                            .AddRetireConnectionIdFrame(/*sequence_number=*/0u)
                            .Build());
  socket_data1.AddWrite(
      SYNCHRONOUS, ConstructGetRequestPacket(
                       packet_number++,
                       GetNthClientInitiatedBidirectionalStreamId(0), true));
  socket_data1.AddRead(
      ASYNC, ConstructOkResponsePacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false));
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0, false))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
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

  // Second request returns synchronously because it pools to existing session.
  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.callback = callback2.callback();
  EXPECT_EQ(OK, builder2.CallRequest());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  HttpRequestInfo request_info2;
  request_info2.method = "GET";
  request_info2.load_flags |= LOAD_DISABLE_CONNECTION_MIGRATION_TO_CELLULAR;
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

  // Send GET request on stream 2 which is non-migratable. This should cause a
  // write error, which triggers a connection migration attempt.
  HttpResponseInfo response2;
  HttpRequestHeaders request_headers2;
  EXPECT_EQ(OK, stream2->SendRequest(request_headers2, &response2,
                                     callback2.callback()));

  // Run the message loop so that the migration attempt is executed and
  // data queued in the new socket is read by the packet reader. Session is
  // still alive and not marked as going away, non-migratable stream will be
  // closed.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Send GET request on stream 1.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream1->SendRequest(request_headers, &response,
                                     callback_.callback()));

  base::RunLoop().RunUntilIdle();

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream1->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  stream1.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
}

// This test verifies that when a connection encounters a packet write error, it
// will cancel non-migratable streams, and migrate to the alternate network.
void QuicSessionPoolTest::TestMigrationOnWriteErrorNonMigratableStream(
    IoMode write_error_mode,
    bool migrate_idle_sessions) {
  quic_params_->migrate_idle_sessions = migrate_idle_sessions;
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  MockQuicData failed_socket_data(version_);
  MockQuicData socket_data(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  int packet_num = 1;
  if (migrate_idle_sessions) {
    // The socket data provider for the original socket before migration.
    failed_socket_data.AddReadPauseForever();
    failed_socket_data.AddWrite(SYNCHRONOUS,
                                ConstructInitialSettingsPacket(packet_num++));
    failed_socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
    failed_socket_data.AddSocketDataToFactory(socket_factory_.get());

    // Set up second socket data provider that is used after migration.
    socket_data.AddReadPauseForever();
    client_maker_.set_connection_id(cid_on_new_path);
    // Increment packet number to account for packet write error on the old
    // path. Also save the packet in client_maker_ for constructing the
    // retransmission packet.
    ConstructGetRequestPacket(packet_num++,
                              GetNthClientInitiatedBidirectionalStreamId(0),
                              /*fin=*/true);

    base::RepeatingCallback<bool(const quic::QuicFrame&)> control_stream_only =
        FilterControlStreamOnly();
    quic::QuicStreamId stream_0 = GetNthClientInitiatedBidirectionalStreamId(0);
    socket_data.AddWrite(
        SYNCHRONOUS,
        client_maker_.Packet(packet_num++)
            .AddPacketRetransmission(1, control_stream_only)
            .AddPacketRetransmission(2, control_stream_only)
            .AddStopSendingFrame(stream_0, quic::QUIC_STREAM_CANCELLED)
            .AddRstStreamFrame(stream_0, quic::QUIC_STREAM_CANCELLED)
            .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                            StreamCancellationQpackDecoderInstruction(0))
            .Build());
    socket_data.AddWrite(
        SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
    socket_data.AddWrite(SYNCHRONOUS,
                         client_maker_.Packet(packet_num++)
                             .AddRetireConnectionIdFrame(/*sequence_number=*/0u)
                             .Build());
    socket_data.AddSocketDataToFactory(socket_factory_.get());
  } else {
    socket_data.AddReadPauseForever();
    socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
    socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
    socket_data.AddSocketDataToFactory(socket_factory_.get());
  }

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created, but marked as non-migratable.
  HttpRequestInfo request_info;
  request_info.load_flags |= LOAD_DISABLE_CONNECTION_MIGRATION_TO_CELLULAR;
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
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Send GET request on stream. This should cause a write error, which triggers
  // a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Run message loop to execute migration attempt.
  base::RunLoop().RunUntilIdle();

  // Migration closes the non-migratable stream and:
  // if migrate idle session is enabled, it migrates to the alternate network
  // successfully; otherwise the connection is closed.
  EXPECT_EQ(migrate_idle_sessions,
            QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(migrate_idle_sessions, HasActiveSession(kDefaultDestination));

  if (migrate_idle_sessions) {
    failed_socket_data.ExpectAllReadDataConsumed();
    failed_socket_data.ExpectAllWriteDataConsumed();
  }
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(
    QuicSessionPoolTest,
    MigrateSessionOnWriteErrorNonMigratableStreamSync_DoNotMigrateIdleSessions) {
  TestMigrationOnWriteErrorNonMigratableStream(SYNCHRONOUS, false);
}

TEST_P(
    QuicSessionPoolTest,
    MigrateSessionOnWriteErrorNonMigratableStreamAsync_DoNotMigrateIdleSessions) {
  TestMigrationOnWriteErrorNonMigratableStream(ASYNC, false);
}

TEST_P(QuicSessionPoolTest,
       MigrateSessionOnWriteErrorNonMigratableStreamSync_MigrateIdleSessions) {
  TestMigrationOnWriteErrorNonMigratableStream(SYNCHRONOUS, true);
}

TEST_P(QuicSessionPoolTest,
       MigrateSessionOnWriteErrorNonMigratableStreamAsync_MigrateIdleSessions) {
  TestMigrationOnWriteErrorNonMigratableStream(ASYNC, true);
}

void QuicSessionPoolTest::TestMigrationOnWriteErrorMigrationDisabled(
    IoMode write_error_mode) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

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

  // Set session config to have connection migration disabled.
  quic::test::QuicConfigPeer::SetReceivedDisableConnectionMigration(
      session->config());
  EXPECT_TRUE(session->config()->DisableConnectionMigration());

  // Send GET request on stream. This should cause a write error, which triggers
  // a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));
  // Run message loop to execute migration attempt.
  base::RunLoop().RunUntilIdle();
  // Migration fails, and session is closed and deleted.
  EXPECT_FALSE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       MigrateSessionOnWriteErrorMigrationDisabledSynchronous) {
  TestMigrationOnWriteErrorMigrationDisabled(SYNCHRONOUS);
}

TEST_P(QuicSessionPoolTest, MigrateSessionOnWriteErrorMigrationDisabledAsync) {
  TestMigrationOnWriteErrorMigrationDisabled(ASYNC);
}

// For IETF QUIC, this test the following scenario:
// - original network encounters a SYNC/ASYNC write error based on
//   |write_error_mode_on_old_network|, the packet failed to be written is
//   cached, session migrates immediately to the alternate network.
// - an immediate SYNC/ASYNC write error based on
//   |write_error_mode_on_new_network| is encountered after migration to the
//   alternate network, session migrates immediately to the original network.
// - After a new socket for the original network is created and starts to read,
//   connection migration fails due to lack of unused connection ID and
//   connection is closed.
// TODO(zhongyi): once https://crbug.com/855666 is fixed, this test should be
// modified to test that session is closed early if hopping between networks
// with consecutive write errors is detected.
void QuicSessionPoolTest::TestMigrationOnMultipleWriteErrors(
    IoMode write_error_mode_on_old_network,
    IoMode write_error_mode_on_new_network) {
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Set up the socket data used by the original network, which encounters a
  // write error.
  MockQuicData socket_data1(version_);
  socket_data1.AddReadPauseForever();
  int packet_num = 1;
  socket_data1.AddWrite(SYNCHRONOUS,
                        ConstructInitialSettingsPacket(packet_num++));
  socket_data1.AddWrite(write_error_mode_on_old_network,
                        ERR_ADDRESS_UNREACHABLE);  // Write Error
  socket_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the socket data used by the alternate network, which
  // - is not used to write as migration fails due to lack of connection ID.
  // - encounters a write error in gQUIC.
  MockQuicData failed_quic_data2(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  failed_quic_data2.AddReadPauseForever();
  failed_quic_data2.AddWrite(write_error_mode_on_new_network, ERR_FAILED);
  failed_quic_data2.AddSocketDataToFactory(socket_factory_.get());

  // Set up the third socket data used by original network, which
  // - encounters a write error again.
  MockQuicData failed_quic_data1(version_);
  failed_quic_data1.AddReadPauseForever();
  failed_quic_data1.AddSocketDataToFactory(socket_factory_.get());

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
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Send GET request on stream.
  // This should encounter a write error on network 1,
  // then migrate to network 2, which encounters another write error,
  // and migrate again to network 1, which encoutners one more write error.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));
  base::RunLoop().RunUntilIdle();
  // Connection is closed as there is no connection ID available yet for the
  // second migration.
  EXPECT_FALSE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  stream.reset();
  socket_data1.ExpectAllReadDataConsumed();
  socket_data1.ExpectAllWriteDataConsumed();
  failed_quic_data2.Ex
```
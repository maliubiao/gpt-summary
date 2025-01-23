Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger test file for Chromium's QUIC client session implementation.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core component under test:** The filename `net/quic/quic_chromium_client_session_test.cc` and the class name `QuicChromiumClientSessionTest` clearly indicate that the code is testing the `QuicChromiumClientSession` class.

2. **Recognize the testing methodology:** The code uses `MockQuicData` to simulate network interactions and `TestCompletionCallback` for asynchronous operations. The presence of `TEST_P` indicates parameterized testing, likely testing different QUIC versions.

3. **Analyze individual test cases:**  Go through each `TEST_P` function and identify its primary purpose. Look for keywords like `CloseConnection`, `RequestStream`, `CancelPendingStreamRequest`, `MaxNumStreams`, `GoAwayReceived`, and `CanPool`.

4. **Group similar functionalities:**  Cluster related test cases together to form logical categories of functionality being tested. For instance, tests involving closing the connection can be grouped. Tests related to stream creation and limits form another group.

5. **Extract key actions and assertions:** For each test case, note the key actions being performed (e.g., creating handles, requesting streams, closing connections) and the assertions being made (e.g., `EXPECT_EQ(ERR_IO_PENDING, ...)`, `EXPECT_FALSE(handle2.get())`, `EXPECT_TRUE(session_->CanPool(...))`).

6. **Identify potential areas of interest for a user/developer:** Focus on aspects that might lead to common usage errors or provide insights into debugging. This includes scenarios like connection closure, stream limits, and the impact of external factors like `GoAway` frames.

7. **Look for interactions with external components (even if simulated):** Note any interaction with the underlying QUIC connection, simulated network data, and potentially the impact of settings or configurations.

8. **Address specific user requests:**
    * **Functionality:**  Summarize the identified groups of test cases into concise points.
    * **JavaScript Relation:**  Consider if any of the tested scenarios have direct equivalents in web development or JavaScript's interaction with network requests. While the C++ code is low-level, the concepts of stream limits, connection closures, and error handling are relevant.
    * **Logic/Input/Output:**  For tests involving specific sequences of events, describe the setup and the expected outcome. Focus on the cause-and-effect relationship.
    * **User Errors:** Identify scenarios that could arise from incorrect usage patterns or misunderstandings of QUIC's behavior.
    * **Debugging Steps:**  Outline the steps leading to the execution of these test scenarios, emphasizing the role of network events and state changes.

9. **Synthesize the summary:** Combine the identified functionalities, JavaScript connections, logic examples, potential errors, and debugging hints into a coherent and informative summary.

10. **Address the "Part 2" requirement:**  Explicitly state that the summary covers the functionality within the provided code snippet.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the low-level QUIC details.
* **Correction:**  Broaden the scope to include higher-level concepts like connection management and stream handling, which are more relevant to understanding the purpose of the tests.
* **Initial thought:**  Assume a direct mapping between C++ QUIC implementation and JavaScript.
* **Correction:**  Acknowledge that the relationship is conceptual and focuses on the user-facing implications of the underlying QUIC behavior.
* **Initial thought:**  Treat each test case in isolation.
* **Correction:** Group related tests to provide a more thematic overview of the functionality being tested.

By following these steps, the goal is to create a comprehensive and user-friendly summary that addresses the user's request effectively.
这是对 `net/quic/quic_chromium_client_session_test.cc` 文件第二部分的功能归纳。这部分主要集中在测试 `QuicChromiumClientSession` 类在处理连接关闭、流请求以及连接池化等方面的行为。

**功能归纳：**

这部分测试用例主要验证了以下 `QuicChromiumClientSession` 的功能：

1. **连接关闭场景下的流请求处理:**
   - 测试了在客户端尝试创建流时，连接由于网络空闲超时而被服务端或客户端关闭的情况。
   - 验证了在同步和异步流请求的情况下，连接关闭如何导致这些待处理的流请求失败并触发相应的回调。
   - 包括了在握手完成前连接关闭的情况，以及在有待处理流请求时连接关闭的情况。

2. **取消待处理的流请求:**
   - 测试了客户端如何取消一个尚未建立的流请求。
   - 验证了取消操作后，即使连接收到针对该流的 RST_STREAM 帧，也不会创建新的流。

3. **连接关闭发生在流请求之前:**
   - 测试了在客户端尝试创建流之前，连接已经关闭的情况。
   - 验证了流请求会立即失败，并返回连接已关闭的错误。

4. **最大并发流数量限制:**
   - 测试了当客户端达到最大允许的并发流数量时，尝试创建新流会失败。
   - 验证了服务端发送 `MAX_STREAMS` 帧增加流限制后，客户端可以创建更多的流。
   - 包括了通过 `CreateOutgoingStream` 直接创建流和通过 `RequestStream` 请求流两种方式达到流限制的场景。

5. **接收到 GOAWAY 帧:**
   - 测试了当客户端收到服务端的 `GOAWAY` 帧后，是否还能创建新的流。
   - 验证了收到 `GOAWAY` 后，客户端应该停止创建新的出站流。

6. **连接池化 (Connection Pooling):**
   - 测试了 `CanPool` 方法，用于判断当前的 `QuicChromiumClientSession` 是否可以被用于处理与特定主机和端口的连接，以实现连接复用。
   - 验证了 `CanPool` 方法会考虑以下因素：
     - 主机名（支持通配符证书）。
     - 是否启用了隐私模式 (PRIVACY_MODE_ENABLED)。
     - 是否使用了代理。
     - `SocketTag` (Android 特定)。
     - `NetworkAnonymizationKey` (用于网络隔离)。
     - 安全 DNS 策略 (`SecureDnsPolicy`).
     - TLS pinning 信息。

**与 Javascript 的关系：**

虽然这些测试直接针对 C++ 代码，但其测试的场景和概念与 Javascript 在网络请求中的行为有间接关系：

* **流请求和并发限制:** Javascript 中的 `fetch` API 或 `XMLHttpRequest` 在底层也可能受到浏览器对 HTTP/3 (QUIC) 连接的并发流数量的限制。当达到限制时，新的请求可能会被延迟，直到有空闲的流。
    * **举例:** 在一个使用了 HTTP/3 的网页中，如果页面同时发起了大量的 `fetch` 请求，浏览器可能会先建立一部分连接，并等待这些连接上的请求完成后再发送新的请求。这与测试中创建大量流并等待 `MAX_STREAMS` 帧的场景类似。
* **连接关闭和错误处理:** Javascript 代码需要处理网络连接错误，例如 `fetch` 请求可能会因为连接关闭而失败。测试中模拟的连接关闭场景，例如 `ERR_CONNECTION_CLOSED`，对应了 Javascript 中需要捕获和处理的网络错误。
    * **举例:** Javascript 代码可以使用 `try...catch` 块来捕获 `fetch` 请求可能抛出的异常，这些异常可能源于底层的 QUIC 连接关闭。
* **连接池化和性能优化:** 浏览器通过连接池化来复用已建立的连接，减少建立新连接的开销，提升页面加载速度。`CanPool` 方法的测试模拟了浏览器判断是否可以复用 QUIC 连接的逻辑。
    * **举例:** 当用户在同一个域名下的不同页面之间导航时，浏览器会尝试复用已有的 HTTP/3 连接，而不是为每个页面都建立新的连接。这背后的判断逻辑与 `CanPool` 方法的测试目标相关。

**逻辑推理、假设输入与输出：**

以下是一个测试用例的逻辑推理示例：

**测试用例:** `ClosedWithAsyncStreamRequest`

**假设输入:**
1. 初始化一个 `QuicChromiumClientSession`。
2. 完成 TLS 握手。
3. 客户端已经打开了最大允许的并发双向流数量。
4. 客户端异步地请求两个新的流 (`handle` 和 `handle2`)。
5. 模拟服务端发送连接关闭帧。

**预期输出:**
1. 当请求新的流时，`handle->RequestStream` 和 `handle2->RequestStream` 都会返回 `ERR_IO_PENDING`，表示请求正在等待。
2. 当连接关闭后，`handle2.get()` 应该为 `false`，表明该待处理的流请求被取消。
3. `quic_data.AllReadDataConsumed()` 和 `quic_data.AllWriteDataConsumed()` 应该为 `true`，表示模拟的网络数据都被消费了。

**用户或编程常见的使用错误：**

1. **未处理连接关闭错误:** 用户或开发者可能没有妥善处理网络连接关闭的错误，导致程序在连接意外断开时崩溃或行为异常。
   * **举例:** 在 Javascript 中，如果 `fetch` 请求返回的 `Promise` 被 reject，开发者需要提供适当的错误处理逻辑，而不是简单地假设请求总是成功。
2. **超出最大并发流限制:** 开发者可能会发起过多的并发请求，导致请求被延迟或失败，影响用户体验。
   * **举例:** 在一个网页中，如果同时加载大量的图片或资源，可能会超过浏览器的并发连接限制，导致部分资源加载缓慢。
3. **错误地假设连接可以被池化:** 开发者可能会错误地假设某些连接可以被复用，但由于证书、安全策略或其他因素的差异，实际无法复用，导致性能下降。
   * **举例:**  如果一个网站使用了严格的 HSTS 和证书 pinning，尝试将该站点的连接用于另一个具有不同 pinning 信息的站点将会失败。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器中访问一个使用 HTTP/3 的网站。**
2. **浏览器尝试与服务器建立 QUIC 连接。**
3. **在连接建立后，用户在网页上执行了某些操作，例如点击链接或提交表单，导致浏览器需要发起新的 HTTP 请求。**
4. **如果此时 QUIC 连接已经接近或达到其最大并发流数量限制，浏览器会尝试请求新的流，但这可能会被阻塞。** (对应 `MaxNumStreams` 相关的测试)
5. **如果在此期间，网络出现问题或者服务端主动关闭了连接，可能会触发连接关闭的流程。** (对应 `ClosedWithAsyncStreamRequest`, `ConnectionCloseBeforeStreamRequest` 等测试)
6. **开发者在调试网络问题时，可能会查看浏览器的网络面板，看到请求状态为 "Pending" 或 "Failed"，并可能深入查看 QUIC 连接的详细信息。**
7. **如果开发者怀疑是 QUIC 连接管理的问题，他们可能会查看 Chromium 的网络栈源代码，例如 `quic_chromium_client_session.cc` 和相关的测试文件 `quic_chromium_client_session_test.cc`，以了解连接和流的管理逻辑。**
8. **相关的测试用例，例如本部分讨论的，可以帮助开发者理解在各种连接状态下，流请求是如何被处理的，以及连接池化是如何工作的。**

总而言之，这部分测试代码覆盖了 `QuicChromiumClientSession` 在连接生命周期管理和流请求处理的关键方面，特别是关注了错误处理、资源限制和连接复用等重要场景。这些测试对于确保 QUIC 客户端的稳定性和性能至关重要。

### 提示词
```
这是目录为net/quic/quic_chromium_client_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
);

  Initialize();
  CompleteCryptoHandshake();

  // Open the maximum number of streams so that a subsequent request
  // can not proceed immediately.
  const size_t kMaxOpenStreams = GetMaxAllowedOutgoingBidirectionalStreams();
  for (size_t i = 0; i < kMaxOpenStreams; i++) {
    QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get());
  }
  EXPECT_EQ(kMaxOpenStreams, session_->GetNumActiveStreams());

  // Request two streams which will both be pending.
  // In V99 each will generate a max stream id for each attempt.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  std::unique_ptr<QuicChromiumClientSession::Handle> handle2 =
      session_->CreateHandle(destination_);

  ASSERT_EQ(
      ERR_IO_PENDING,
      handle->RequestStream(
          /*requires_confirmation=*/false,
          base::BindOnce(&QuicChromiumClientSessionTest::ResetHandleOnError,
                         base::Unretained(this), &handle2),
          TRAFFIC_ANNOTATION_FOR_TESTS));

  TestCompletionCallback callback2;
  ASSERT_EQ(ERR_IO_PENDING,
            handle2->RequestStream(/*requires_confirmation=*/false,
                                   callback2.callback(),
                                   TRAFFIC_ANNOTATION_FOR_TESTS));

  session_->connection()->CloseConnection(
      quic::QUIC_NETWORK_IDLE_TIMEOUT, "Timed out",
      quic::ConnectionCloseBehavior::SILENT_CLOSE);

  // Pump the message loop to read the connection close packet.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(handle2.get());
  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, ClosedWithAsyncStreamRequest) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  // The open stream limit is set to 50 by
  // MockCryptoClientStream::SetConfigNegotiated() so when the 51st stream is
  // requested, a STREAMS_BLOCKED will be sent, indicating that it's blocked
  // at the limit of 50.
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(2)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(3)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  // Open the maximum number of streams so that a subsequent request
  // can not proceed immediately.
  const size_t kMaxOpenStreams = GetMaxAllowedOutgoingBidirectionalStreams();
  for (size_t i = 0; i < kMaxOpenStreams; i++) {
    QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get());
  }
  EXPECT_EQ(kMaxOpenStreams, session_->GetNumActiveStreams());

  // Request two streams which will both be pending.
  // In V99 each will generate a max stream id for each attempt.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  std::unique_ptr<QuicChromiumClientSession::Handle> handle2 =
      session_->CreateHandle(destination_);

  ASSERT_EQ(
      ERR_IO_PENDING,
      handle->RequestStream(
          /*requires_confirmation=*/false,
          base::BindOnce(&QuicChromiumClientSessionTest::ResetHandleOnError,
                         base::Unretained(this), &handle2),
          TRAFFIC_ANNOTATION_FOR_TESTS));

  TestCompletionCallback callback2;
  ASSERT_EQ(ERR_IO_PENDING,
            handle2->RequestStream(/*requires_confirmation=*/false,
                                   callback2.callback(),
                                   TRAFFIC_ANNOTATION_FOR_TESTS));

  session_->connection()->CloseConnection(
      quic::QUIC_NETWORK_IDLE_TIMEOUT, "Timed out",
      quic::ConnectionCloseBehavior::SILENT_CLOSE);

  // Pump the message loop to read the connection close packet.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(handle2.get());
  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, CancelPendingStreamRequest) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  // The open stream limit is set to 50 by
  // MockCryptoClientStream::SetConfigNegotiated() so when the 51st stream is
  // requested, a STREAMS_BLOCKED will be sent.
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(2)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  // This node receives the RST_STREAM+STOP_SENDING, it responds
  // with only a RST_STREAM.
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(3)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  // Open the maximum number of streams so that a subsequent request
  // can not proceed immediately.
  const size_t kMaxOpenStreams = GetMaxAllowedOutgoingBidirectionalStreams();
  for (size_t i = 0; i < kMaxOpenStreams; i++) {
    QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get());
  }
  EXPECT_EQ(kMaxOpenStreams, session_->GetNumActiveStreams());

  // Request a stream and verify that it's pending.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(
      ERR_IO_PENDING,
      handle->RequestStream(/*requires_confirmation=*/false,
                            callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));

  // Cancel the pending stream request.
  handle.reset();

  // Close a stream and ensure that no new stream is created.
  quic::QuicRstStreamFrame rst(quic::kInvalidControlFrameId,
                               GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED, 0);
  session_->OnRstStream(rst);
  // We require a STOP_SENDING as well as a RESET_STREAM to fully close the
  // stream.
  quic::QuicStopSendingFrame stop_sending(
      quic::kInvalidControlFrameId,
      GetNthClientInitiatedBidirectionalStreamId(0),
      quic::QUIC_STREAM_CANCELLED);
  session_->OnStopSendingFrame(stop_sending);
  EXPECT_EQ(kMaxOpenStreams - 1, session_->GetNumActiveStreams());

  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, ConnectionCloseBeforeStreamRequest) {
  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.Packet(packet_num++).AddPingFrame().Build());
  quic_data.AddRead(
      ASYNC, server_maker_.Packet(1)
                 .AddConnectionCloseFrame(
                     quic::QUIC_CRYPTO_VERSION_NOT_SUPPORTED, "Time to panic!")
                 .Build());

  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  // Send a ping so that client has outgoing traffic before receiving packets.
  session_->connection()->SendPing();

  // Pump the message loop to read the connection close packet.
  base::RunLoop().RunUntilIdle();

  // Request a stream and verify that it failed.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(
      ERR_CONNECTION_CLOSED,
      handle->RequestStream(/*requires_confirmation=*/false,
                            callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));

  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, ConnectionCloseBeforeHandshakeConfirmed) {
  if (version_.UsesTls()) {
    // TODO(nharper, b/112643533): Figure out why this test fails when TLS is
    // enabled and fix it.
    return;
  }

  // Force the connection close packet to use long headers with connection ID.
  server_maker_.SetEncryptionLevel(quic::ENCRYPTION_INITIAL);

  MockQuicData quic_data(version_);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(
      ASYNC, server_maker_.Packet(1)
                 .AddConnectionCloseFrame(
                     quic::QUIC_CRYPTO_VERSION_NOT_SUPPORTED, "Time to panic!")
                 .Build());
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();

  // Request a stream and verify that it's pending.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(
      ERR_IO_PENDING,
      handle->RequestStream(/*requires_confirmation=*/true, callback.callback(),
                            TRAFFIC_ANNOTATION_FOR_TESTS));

  // Close the connection and verify that the StreamRequest completes with
  // an error.
  quic_data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, ConnectionCloseWithPendingStreamRequest) {
  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.Packet(packet_num++).AddPingFrame().Build());
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(
      ASYNC, server_maker_.Packet(1)
                 .AddConnectionCloseFrame(
                     quic::QUIC_CRYPTO_VERSION_NOT_SUPPORTED, "Time to panic!")
                 .Build());
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  // Send a ping so that client has outgoing traffic before receiving packets.
  session_->connection()->SendPing();

  // Open the maximum number of streams so that a subsequent request
  // can not proceed immediately.
  const size_t kMaxOpenStreams = GetMaxAllowedOutgoingBidirectionalStreams();
  for (size_t i = 0; i < kMaxOpenStreams; i++) {
    QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get());
  }
  EXPECT_EQ(kMaxOpenStreams, session_->GetNumActiveStreams());

  // Request a stream and verify that it's pending.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(
      ERR_IO_PENDING,
      handle->RequestStream(/*requires_confirmation=*/false,
                            callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));

  // Close the connection and verify that the StreamRequest completes with
  // an error.
  quic_data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, MaxNumStreams) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  // Initial configuration is 50 dynamic streams. Taking into account
  // the static stream (headers), expect to block on when hitting the limit
  // of 50 streams
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(2)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(3)
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_RST_ACKNOWLEDGEMENT)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_RST_ACKNOWLEDGEMENT)
          .Build());
  // For the second CreateOutgoingStream that fails because of hitting the
  // stream count limit.
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(4)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  quic_data.AddRead(ASYNC, server_maker_.Packet(1)
                               .AddMaxStreamsFrame(/*control_frame_id=*/1,
                                                   /*stream_count=*/50 + 2,
                                                   /*unidirectional=*/false)
                               .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();
  const size_t kMaxOpenStreams = GetMaxAllowedOutgoingBidirectionalStreams();

  std::vector<QuicChromiumClientStream*> streams;
  for (size_t i = 0; i < kMaxOpenStreams; i++) {
    QuicChromiumClientStream* stream =
        QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get());
    EXPECT_TRUE(stream);
    streams.push_back(stream);
  }
  // This stream, the 51st dynamic stream, can not be opened.
  EXPECT_FALSE(
      QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get()));

  EXPECT_EQ(kMaxOpenStreams, session_->GetNumActiveStreams());

  // Close a stream and ensure I can now open a new one.
  quic::QuicStreamId stream_id = streams[0]->id();
  session_->ResetStream(stream_id, quic::QUIC_RST_ACKNOWLEDGEMENT);

  // Pump data, bringing in the max-stream-id
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(
      QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get()));
  quic::QuicRstStreamFrame rst1(quic::kInvalidControlFrameId, stream_id,
                                quic::QUIC_STREAM_NO_ERROR, 0);
  session_->OnRstStream(rst1);
  EXPECT_EQ(kMaxOpenStreams - 1, session_->GetNumActiveStreams());
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(
      QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get()));
}

// Regression test for crbug.com/968621.
TEST_P(QuicChromiumClientSessionTest, PendingStreamOnRst) {
  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(ASYNC,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      ASYNC,
      client_maker_.Packet(packet_num++)
          .AddStopSendingFrame(GetNthServerInitiatedUnidirectionalStreamId(0),
                               quic::QUIC_RST_ACKNOWLEDGEMENT)
          .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  quic::QuicStreamFrame data(GetNthServerInitiatedUnidirectionalStreamId(0),
                             false, 1, std::string_view("SP"));
  session_->OnStreamFrame(data);
  EXPECT_EQ(0u, session_->GetNumActiveStreams());
  quic::QuicRstStreamFrame rst(quic::kInvalidControlFrameId,
                               GetNthServerInitiatedUnidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED, 0);
  session_->OnRstStream(rst);
}

// Regression test for crbug.com/971361.
TEST_P(QuicChromiumClientSessionTest, ClosePendingStream) {
  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(ASYNC,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      ASYNC,
      client_maker_.Packet(packet_num++)
          .AddStopSendingFrame(GetNthServerInitiatedUnidirectionalStreamId(0),
                               quic::QUIC_RST_ACKNOWLEDGEMENT)
          .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  quic::QuicStreamId id = GetNthServerInitiatedUnidirectionalStreamId(0);
  quic::QuicStreamFrame data(id, false, 1, std::string_view("SP"));
  session_->OnStreamFrame(data);
  EXPECT_EQ(0u, session_->GetNumActiveStreams());
  session_->ResetStream(id, quic::QUIC_STREAM_NO_ERROR);
}

TEST_P(QuicChromiumClientSessionTest, MaxNumStreamsViaRequest) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(2)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(3)
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_RST_ACKNOWLEDGEMENT)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_RST_ACKNOWLEDGEMENT)
          .Build());
  quic_data.AddRead(ASYNC, server_maker_.Packet(1)
                               .AddMaxStreamsFrame(/*control_frame_id=*/1,
                                                   /*stream_count=*/52,
                                                   /*unidirectional=*/false)
                               .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();
  const size_t kMaxOpenStreams = GetMaxAllowedOutgoingBidirectionalStreams();
  std::vector<QuicChromiumClientStream*> streams;
  for (size_t i = 0; i < kMaxOpenStreams; i++) {
    QuicChromiumClientStream* stream =
        QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get());
    EXPECT_TRUE(stream);
    streams.push_back(stream);
  }

  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(
      ERR_IO_PENDING,
      handle->RequestStream(/*requires_confirmation=*/false,
                            callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));

  // Close a stream and ensure I can now open a new one.
  quic::QuicStreamId stream_id = streams[0]->id();
  session_->ResetStream(stream_id, quic::QUIC_RST_ACKNOWLEDGEMENT);
  quic::QuicRstStreamFrame rst1(quic::kInvalidControlFrameId, stream_id,
                                quic::QUIC_STREAM_NO_ERROR, 0);
  session_->OnRstStream(rst1);
  // Pump data, bringing in the max-stream-id
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_TRUE(handle->ReleaseStream() != nullptr);
}

TEST_P(QuicChromiumClientSessionTest, GoAwayReceived) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();
  CompleteCryptoHandshake();

  // After receiving a GoAway, I should no longer be able to create outgoing
  // streams.
  session_->OnHttp3GoAway(0);
  EXPECT_EQ(nullptr, QuicChromiumClientSessionPeer::CreateOutgoingStream(
                         session_.get()));
}

TEST_P(QuicChromiumClientSessionTest, CanPool) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   www.example.com

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  EXPECT_TRUE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_FALSE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_ENABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_FALSE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kDisable,
                     /*require_dns_https_alpn=*/false)));
#if BUILDFLAG(IS_ANDROID)
  SocketTag tag1(SocketTag::UNSET_UID, 0x12345678);
  SocketTag tag2(getuid(), 0x87654321);
  EXPECT_FALSE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, tag1,
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_FALSE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, tag2,
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
#endif
  EXPECT_FALSE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED,
                     ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_QUIC,
                                                       "bar", 443),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_FALSE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kProxy, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));

  EXPECT_TRUE(session_->CanPool(
      "mail.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_TRUE(session_->CanPool(
      "mail.example.com",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_FALSE(session_->CanPool(
      "mail.google.com",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));

  const SchemefulSite kSiteFoo(GURL("http://foo.test/"));

  // Check that NetworkAnonymizationKey is respected when feature is enabled.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndDisableFeature(
        features::kPartitionConnectionsByNetworkIsolationKey);
    EXPECT_TRUE(session_->CanPool(
        "mail.example.com",
        QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                       SessionUsage::kDestination, SocketTag(),
                       NetworkAnonymizationKey::CreateSameSite(kSiteFoo),
                       SecureDnsPolicy::kAllow,
                       /*require_dns_https_alpn=*/false)));
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndEnableFeature(
        features::kPartitionConnectionsByNetworkIsolationKey);
    EXPECT_FALSE(session_->CanPool(
        "mail.example.com",
        QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                       SessionUsage::kDestination, SocketTag(),
                       NetworkAnonymizationKey::CreateSameSite(kSiteFoo),
                       SecureDnsPolicy::kAllow,
                       /*require_dns_https_alpn=*/false)));
  }
}

// Much as above, but uses a non-empty NetworkAnonymizationKey.
TEST_P(QuicChromiumClientSessionTest, CanPoolWithNetworkAnonymizationKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  const SchemefulSite kSiteFoo(GURL("http://foo.test/"));
  const SchemefulSite kSiteBar(GURL("http://bar.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSiteFoo);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSiteBar);

  session_key_ = QuicSessionKey(
      kServerHostname, kServerPort, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
      SessionUsage::kDestination, SocketTag(), kNetworkAnonymizationKey1,
      SecureDnsPolicy::kAllow,
      /*require_dns_https_alpn=*/false);

  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   www.example.com

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  EXPECT_TRUE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     kNetworkAnonymizationKey1, SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_FALSE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_ENABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     kNetworkAnonymizationKey1, SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
#if BUILDFLAG(IS_ANDROID)
  SocketTag tag1(SocketTag::UNSET_UID, 0x12345678);
  SocketTag tag2(getuid(), 0x87654321);
  EXPECT_FALSE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, tag1,
                     kNetworkAnonymizationKey1, SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_FALSE(session_->CanPool(
      "www.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, tag2,
                     kNetworkAnonymizationKey1, SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
#endif
  EXPECT_TRUE(session_->CanPool(
      "mail.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     kNetworkAnonymizationKey1, SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_TRUE(session_->CanPool(
      "mail.example.com",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     kNetworkAnonymizationKey1, SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_FALSE(session_->CanPool(
      "mail.google.com",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     kNetworkAnonymizationKey1, SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));

  EXPECT_FALSE(session_->CanPool(
      "mail.example.com",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     kNetworkAnonymizationKey2, SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
  EXPECT_FALSE(session_->CanPool(
      "mail.example.com",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
}

TEST_P(QuicChromiumClientSessionTest, ConnectionNotPooledWithDifferentPin) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  // Configure the TransportSecurityStateSource so that kPreloadedPKPHost will
  // have static PKP pins set.
  ScopedTransportSecurityStateSource scoped_security_state_source;

  // |net::test_default::kHSTSSource| defines pins for kPreloadedPKPHost.
  // (This hostname must be in the spdy_pooling.pem SAN.)
  const char kPreloadedPKPHost[] = "www.example.org";
  // A hostname without any static state.  (This hostname isn't in
  // spdy_pooling.pem SAN, but that's okay because the
  // ProofVerifyDetailsChromium are faked.)
  const char kNoPinsHost[] = "no-pkp.example.org";

  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();

  transport_security_state_->EnableStaticPinsForTesting();
  transport_security_state_->SetPinningListAlwaysTimelyForTesting(true);

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  details.cert_verify_result.is_issued_by_known_root = true;
  uint8_t bad_pin = 3;
  details.cert_verify_result.public_key_hashes.push_back(
      GetTestHashValue(bad_pin));

  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);
  QuicChromiumClientSessionPeer::SetHostname(session_.get(), kNoPinsHost);

  EXPECT_FALSE(session_->CanPool(
      kPreloadedPKPHost,
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
}

TEST_P(QuicChromiumClientSessionTest, ConnectionPooledWithMatchingPin) {
  ScopedTransportSecurityStateSource scoped_secur
```
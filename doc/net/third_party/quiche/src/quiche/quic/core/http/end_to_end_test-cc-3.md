Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger file `end_to_end_test.cc` in the Chromium network stack. The file seems to contain integration tests for the QUIC protocol's HTTP implementation.

Here's a breakdown of the thought process to achieve the desired output:

1. **Identify the Core Purpose:** The filename `end_to_end_test.cc` strongly suggests these are integration tests. The tests cover various aspects of a QUIC connection, especially in the context of HTTP.

2. **Analyze Individual Test Cases:** Go through each `TEST_P` function and summarize its purpose. Look for keywords like `Reject`, `Set`, `Large`, `DoNotSet`, `Invalid`, `EarlyResponse`, `Timeout`, `MaxDynamicStreams`, `NegotiateCongestionControl`, `ClientSuggestsRTT`, `ResetConnection`, `ConnectionMigration`, etc. These keywords often reveal the core functionality being tested.

3. **Group Related Tests:** Notice patterns in the test names. For example, several tests deal with connection migration (`ConnectionMigrationClientIPChanged`, `IetfConnectionMigrationClientIPChangedMultipleTimes`). Grouping these helps create a more organized summary.

4. **Look for Specific Functionality:** Identify the QUIC features being tested. Zero-RTT, connection options, flow control, stream limits, congestion control, connection migration are all evident.

5. **Address the JavaScript Relationship:**  Consider how the tested QUIC functionality relates to JavaScript. QUIC is a transport protocol, and while JavaScript doesn't directly interact with it, browsers use QUIC for network requests made by JavaScript. The performance and reliability tested here directly impact the user experience of web applications.

6. **Handle Logical Reasoning (Hypothetical Inputs/Outputs):** For specific tests, imagine simplified scenarios. For example, in the "LargeHeaders" test, the input is a request with very large headers, and the expected output is a stream reset with a specific error code. This demonstrates understanding of the test's goal.

7. **Identify Common User/Programming Errors:** Think about common mistakes when using network protocols. Sending data after closing a stream (as hinted in the `MultipleTermination` test) or exceeding stream limits are good examples.

8. **Trace User Operations (Debugging):**  Consider how a user action in a browser could lead to this code being executed. A user navigating to a website, especially over HTTPS, is the primary trigger. Configuration issues or network problems could also lead to these tests being relevant for debugging.

9. **Address the "Part 4 of 10" Instruction:** Acknowledge this context. It reinforces the idea that this is one part of a larger testing effort.

10. **Synthesize the Summary:** Combine the information gathered into a concise summary of the file's functionality. Emphasize the end-to-end nature of the tests and the various QUIC features being validated.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** "Just list all the test names."  **Correction:** This isn't very informative. Summarize the *purpose* of each test.
* **Initial thought:** "JavaScript doesn't use QUIC directly." **Correction:** While technically true, JavaScript's network requests *use* QUIC under the hood in the browser. Explain this indirect relationship.
* **Initial thought:** Focus only on successful scenarios. **Correction:**  The tests also cover error handling, like rejecting 0-RTT or handling invalid streams. Include these aspects.
* **Overly technical description:**  Simplify language to be understandable even to someone with a basic understanding of networking concepts.

By following these steps, the detailed and informative summary provided in the initial prompt can be generated.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc` 文件的第四部分，其主要功能是 **对 QUIC 协议在 HTTP 场景下的各种端到端行为进行测试**。

**归纳一下它的功能:**

这部分代码主要涵盖了以下方面的端到端测试：

* **0-RTT 连接拒绝和处理:** 测试服务器在特定情况下拒绝 0-RTT 连接，以及客户端如何处理这种情况（例如，在握手后立即重启服务器导致 0-RTT 失败）。
* **处理丢包情况下的连接建立:**  测试在初始握手阶段服务器丢弃第一个数据包（REJ 响应）时，连接是否能正确建立。
* **设置初始接收连接选项:**  测试服务器如何设置并验证客户端发送的初始连接选项。
* **大 POST 请求和带宽限制:**  测试在小带宽和大缓冲区的情况下，客户端发送大 POST 请求是否能够正常工作，并可能存在丢包的情况。
* **连接级流量控制阻止时的处理:**  测试当连接级流量控制被阻止时，是否会不正确地设置发送警报，避免进入死循环。
* **无效 Stream ID 的处理:** 测试客户端使用不存在的服务端 Stream ID 发送请求时，服务器如何处理并返回错误。
* **过大的 HTTP 头部处理:** 测试客户端发送包含过大 HTTP 头的请求时，服务器如何处理并重置连接或 Stream。
* **提前响应处理:**  测试服务器在接收到无效请求（例如，错误的 Content-Length）时发送提前响应的情况。
* **多次终止请求的处理 (DISABLED):**  测试客户端在发送 FIN 后再次发送数据的情况（客户端行为不当），以及服务器如何处理。
* **连接超时测试:**  测试连接在空闲一段时间后是否会超时断开。
* **最大动态 Stream 数量限制:**  测试服务器设置最大动态 Stream 数量限制后，客户端是否会遵守，以及超出限制时的行为。
* **独立设置最大动态 Stream 数量限制:** 测试客户端和服务器可以独立设置各自的最大动态 Stream 数量限制。
* **协商拥塞控制算法:**  测试客户端和服务器之间如何协商并使用特定的拥塞控制算法。
* **客户端建议初始 RTT:** 测试客户端可以建议初始 RTT (Round Trip Time)，并验证服务器是否使用了该值。
* **客户端建议被忽略的 RTT:** 测试当客户端同时指定了 NRTT (No Round Trip Time required) 时，服务器是否会忽略客户端建议的初始 RTT。
* **客户端禁用 gQUIC 的 0-RTT:** 测试客户端可以禁用 gQUIC 的 0-RTT 功能。
* **最大和最小初始 RTT:** 测试客户端尝试设置超出服务器限制的最大或最小初始 RTT 时，服务器如何处理。
* **重置连接:** 测试客户端可以主动重置连接，并建立新的连接发送请求。
* **半 RTT 响应阻止 SHLO 重传 (需要禁用 Token Based Address Validation):** 测试在特定条件下，服务器发送半 RTT 响应时，是否会阻止 SHLO (Server Hello) 的重传。
* **高并发请求测试:** 测试在高并发请求下连接的稳定性和性能。
* **Stream 取消错误测试:** 测试客户端在发送请求后取消 Stream，服务器如何处理。
* **连接迁移 (客户端 IP 变更):** 测试在客户端 IP 地址变更后，连接是否能够迁移并继续工作。
* **IETF 连接迁移 (客户端 IP 多次变更):** 针对 IETF QUIC，测试客户端 IP 地址多次变更后的连接迁移情况。
* **非零连接 ID 的连接迁移:**  测试在连接 ID 不为零的情况下，客户端 IP 地址变更后的连接迁移情况。

**与 Javascript 功能的关系 (举例说明):**

虽然这段 C++ 代码本身不包含 Javascript，但它测试的网络协议 QUIC 却直接影响着 Javascript 在浏览器中的网络请求行为。例如：

* **0-RTT 连接:**  如果这里的测试成功，意味着使用支持 0-RTT 的 QUIC 连接的网站，在用户第二次访问时，Javascript 发起的请求可以更快地发送和接收数据，提升网页加载速度。
* **连接迁移:**  当用户在移动网络和 Wi-Fi 之间切换时，这里的测试保障了 Javascript 发起的网络请求不会中断，用户体验更加流畅。
* **拥塞控制:**  测试不同的拥塞控制算法确保了 Javascript 发起的网络请求能够更有效地利用网络带宽，减少延迟和丢包，提升性能。

**逻辑推理 (假设输入与输出):**

以 `TEST_P(EndToEndTest, LargeHeaders)` 为例：

* **假设输入:** 客户端发送一个 HTTP POST 请求，其头部包含三个自定义字段 "key1", "key2", "key3"，每个字段的值都是 15KB 的字符串。服务器配置的最大头部大小限制小于 45KB (3 * 15KB)。
* **预期输出:**
    * 服务器检测到头部过大，会重置该 Stream。
    * 客户端会收到一个 Stream 错误，错误码为 `QUIC_HEADERS_TOO_LARGE` (或者在 HTTP/3 中会被映射为 `QUIC_STREAM_EXCESSIVE_LOAD`)。
    * 连接级别的错误应该为 `QUIC_NO_ERROR`，因为只是单个 Stream 出现问题。

**用户或编程常见的使用错误 (举例说明):**

* **发送数据到已关闭的 Stream:**  在 `TEST_P(EndToEndTest, QUIC_TEST_DISABLED_IN_CHROME(MultipleTermination))` 中，模拟了客户端在 Stream 已经发送 FIN 后再次尝试发送数据的情况。这是一个编程错误，因为按照协议，Stream 一旦关闭就不能再发送数据。测试验证了服务器如何处理这种不当行为。
* **超出最大 Stream 数量限制:**  在 `TEST_P(EndToEndTest, MaxDynamicStreamsLimitRespected)` 中，客户端尝试打开比服务器允许的最大动态 Stream 数量更多的 Stream。这是一个常见的使用错误，如果程序没有正确管理 Stream 的创建和关闭，就可能导致超出限制。测试验证了服务器会拒绝新的 Stream 请求，并返回 `QUIC_REFUSED_STREAM` 错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

假设一个用户在使用 Chrome 浏览器访问一个使用了 QUIC 协议的网站，并遇到了连接不稳定的问题，可以按以下步骤进行调试，并可能涉及到这里的测试代码：

1. **用户访问网站:** 用户在 Chrome 浏览器的地址栏输入网址并回车。
2. **浏览器发起连接:** Chrome 浏览器会尝试与网站服务器建立 QUIC 连接。
3. **QUIC 握手:**  QUIC 客户端和服务器之间进行握手，协商连接参数，包括是否使用 0-RTT、最大 Stream 数量、拥塞控制算法等。
4. **数据传输:**  连接建立后，浏览器使用 QUIC Stream 发送 HTTP 请求，接收服务器的 HTTP 响应 (HTML, CSS, Javascript 等)。
5. **可能出现的问题和调试线索:**
    * **页面加载缓慢 (可能与 0-RTT 失败有关):** 如果用户是第二次访问该网站，但页面加载速度依然很慢，可能是 0-RTT 握手失败了。可以查看 Chrome 的 `chrome://net-internals/#quic` 页面，查看连接的详细信息，例如 `early_accepted` 字段是否为 true。`TEST_P(EndToEndTest, RejectZeroRtt)` 和 `TEST_P(EndToEndTest, RejectZeroRttAfterHandshake)` 测试了 0-RTT 拒绝的场景，如果测试失败，可能意味着 0-RTT 逻辑存在问题。
    * **连接频繁断开 (可能与连接迁移或超时有关):**  如果用户在移动网络环境下访问网站，可能会在 Wi-Fi 和移动数据之间切换，导致 IP 地址变更。如果连接迁移失败，会导致连接断开。`TEST_P(EndToEndTest, ConnectionMigrationClientIPChanged)` 和相关的测试覆盖了连接迁移的场景。此外，如果网络空闲时间过长，也可能触发连接超时，`TEST_P(EndToEndTest, Timeout)` 测试了连接超时的行为。
    * **请求失败 (可能与 Stream 限制或头部过大有关):**  如果网站的 Javascript 代码尝试发送大量的并发请求，可能会超出服务器允许的最大 Stream 数量，导致请求失败。`TEST_P(EndToEndTest, MaxDynamicStreamsLimitRespected)` 测试了最大 Stream 数量限制。如果请求的头部非常大，也可能被服务器拒绝，`TEST_P(EndToEndTest, LargeHeaders)` 测试了这种情况。
    * **特定请求失败 (可能与无效 Stream ID 有关):** 理论上，正常情况下不应该出现客户端使用无效 Stream ID 的情况，但这可能是由于客户端的编程错误导致的。`TEST_P(EndToEndTest, InvalidStream)` 测试了服务器如何处理这种情况。

当开发者或网络工程师遇到这些问题时，他们可能会查看 Chrome 的网络日志，分析 QUIC 连接的细节，并可能需要深入到 Chromium 的网络栈代码中进行调试。`end_to_end_test.cc` 中的这些测试用例就为他们提供了验证 QUIC 协议实现的正确性和稳定性的手段。如果相关的测试失败，就可能指示了 QUIC 实现中存在 Bug。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
ect();

  // Restart the server so that the 0-RTT handshake will take 1 RTT.
  StopServer();
  server_writer_ = new PacketDroppingTestWriter();
  StartServer();

  ON_CALL(visitor, OnZeroRttRejected(_)).WillByDefault(Invoke([this]() {
    EXPECT_FALSE(GetClientSession()->IsEncryptionEstablished());
  }));

  // The 0-RTT handshake should fail.
  client_->Connect();
  ASSERT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  client_->WaitForWriteToFlush();
  client_->WaitForResponse();
  ASSERT_TRUE(client_->client()->connected());

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
}

TEST_P(EndToEndTest, RejectWithPacketLoss) {
  // In this test, we intentionally drop the first packet from the
  // server, which corresponds with the initial REJ response from
  // the server.
  server_writer_->set_fake_drop_first_n_packets(1);
  ASSERT_TRUE(Initialize());
}

TEST_P(EndToEndTest, SetInitialReceivedConnectionOptions) {
  QuicTagVector initial_received_options;
  initial_received_options.push_back(kTBBR);
  initial_received_options.push_back(kIW10);
  initial_received_options.push_back(kPRST);
  EXPECT_TRUE(server_config_.SetInitialReceivedConnectionOptions(
      initial_received_options));

  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  server_thread_->WaitForCryptoHandshakeConfirmed();

  EXPECT_FALSE(server_config_.SetInitialReceivedConnectionOptions(
      initial_received_options));

  // Verify that server's configuration is correct.
  server_thread_->Pause();
  EXPECT_TRUE(server_config_.HasReceivedConnectionOptions());
  EXPECT_TRUE(
      ContainsQuicTag(server_config_.ReceivedConnectionOptions(), kTBBR));
  EXPECT_TRUE(
      ContainsQuicTag(server_config_.ReceivedConnectionOptions(), kIW10));
  EXPECT_TRUE(
      ContainsQuicTag(server_config_.ReceivedConnectionOptions(), kPRST));
}

TEST_P(EndToEndTest, LargePostSmallBandwidthLargeBuffer) {
  ASSERT_TRUE(Initialize());
  SetPacketSendDelay(QuicTime::Delta::FromMicroseconds(1));
  // 256KB per second with a 256KB buffer from server to client.  Wireless
  // clients commonly have larger buffers, but our max CWND is 200.
  server_writer_->set_max_bandwidth_and_buffer_size(
      QuicBandwidth::FromBytesPerSecond(256 * 1024), 256 * 1024);

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  // 1 MB body.
  std::string body(1024 * 1024, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
  // This connection may drop packets, because the buffer is smaller than the
  // max CWND.
  VerifyCleanConnection(true);
}

TEST_P(EndToEndTest, DoNotSetSendAlarmIfConnectionFlowControlBlocked) {
  // Regression test for b/14677858.
  // Test that the resume write alarm is not set in QuicConnection::OnCanWrite
  // if currently connection level flow control blocked. If set, this results in
  // an infinite loop in the EventLoop, as the alarm fires and is immediately
  // rescheduled.
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  // Ensure both stream and connection level are flow control blocked by setting
  // the send window offset to 0.
  const uint64_t flow_control_window =
      server_config_.GetInitialStreamFlowControlWindowToSend();
  QuicSpdyClientStream* stream = client_->GetOrCreateStream();
  QuicSession* session = GetClientSession();
  ASSERT_TRUE(session);
  QuicStreamPeer::SetSendWindowOffset(stream, 0);
  QuicFlowControllerPeer::SetSendWindowOffset(session->flow_controller(), 0);
  EXPECT_TRUE(stream->IsFlowControlBlocked());
  EXPECT_TRUE(session->flow_controller()->IsBlocked());

  // Make sure that the stream has data pending so that it will be marked as
  // write blocked when it receives a stream level WINDOW_UPDATE.
  stream->WriteOrBufferBody("hello", false);

  // The stream now attempts to write, fails because it is still connection
  // level flow control blocked, and is added to the write blocked list.
  QuicWindowUpdateFrame window_update(kInvalidControlFrameId, stream->id(),
                                      2 * flow_control_window);
  stream->OnWindowUpdateFrame(window_update);

  // Prior to fixing b/14677858 this call would result in an infinite loop in
  // Chromium. As a proxy for detecting this, we now check whether the
  // send alarm is set after OnCanWrite. It should not be, as the
  // connection is still flow control blocked.
  session->connection()->OnCanWrite();

  EXPECT_FALSE(QuicConnectionPeer::GetSendAlarm(session->connection()).IsSet());
}

TEST_P(EndToEndTest, InvalidStream) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  std::string body(kMaxOutgoingPacketSize, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  // Force the client to write with a stream ID belonging to a nonexistent
  // server-side stream.
  QuicSpdySession* session = GetClientSession();
  ASSERT_TRUE(session);
  QuicSessionPeer::SetNextOutgoingBidirectionalStreamId(
      session, GetNthServerInitiatedBidirectionalId(0));

  client_->SendCustomSynchronousRequest(headers, body);
  EXPECT_THAT(client_->stream_error(),
              IsStreamError(QUIC_STREAM_CONNECTION_ERROR));
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_INVALID_STREAM_ID));
}

// Test that the server resets the stream if the client sends a request
// with overly large headers.
TEST_P(EndToEndTest, LargeHeaders) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  std::string body(kMaxOutgoingPacketSize, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  headers["key1"] = std::string(15 * 1024, 'a');
  headers["key2"] = std::string(15 * 1024, 'a');
  headers["key3"] = std::string(15 * 1024, 'a');

  client_->SendCustomSynchronousRequest(headers, body);

  if (version_.UsesHttp3()) {
    // QuicSpdyStream::OnHeadersTooLarge() resets the stream with
    // QUIC_HEADERS_TOO_LARGE.  This is sent as H3_EXCESSIVE_LOAD, the closest
    // HTTP/3 error code, and translated back to QUIC_STREAM_EXCESSIVE_LOAD on
    // the receiving side.
    EXPECT_THAT(client_->stream_error(),
                IsStreamError(QUIC_STREAM_EXCESSIVE_LOAD));
  } else {
    EXPECT_THAT(client_->stream_error(), IsStreamError(QUIC_HEADERS_TOO_LARGE));
  }
  EXPECT_THAT(client_->connection_error(), IsQuicNoError());
}

TEST_P(EndToEndTest, EarlyResponseWithQuicStreamNoError) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  std::string large_body(1024 * 1024, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  // Insert an invalid content_length field in request to trigger an early
  // response from server.
  headers["content-length"] = "-3";

  client_->SendCustomSynchronousRequest(headers, large_body);
  EXPECT_EQ("bad", client_->response_body());
  CheckResponseHeaders("500");
  EXPECT_THAT(client_->stream_error(), IsQuicStreamNoError());
  EXPECT_THAT(client_->connection_error(), IsQuicNoError());
}

// TODO(rch): this test seems to cause net_unittests timeouts :|
TEST_P(EndToEndTest, QUIC_TEST_DISABLED_IN_CHROME(MultipleTermination)) {
  ASSERT_TRUE(Initialize());

  // Set the offset so we won't frame.  Otherwise when we pick up termination
  // before HTTP framing is complete, we send an error and close the stream,
  // and the second write is picked up as writing on a closed stream.
  QuicSpdyClientStream* stream = client_->GetOrCreateStream();
  ASSERT_TRUE(stream != nullptr);
  QuicStreamPeer::SetStreamBytesWritten(3, stream);

  client_->SendData("bar", true);
  client_->WaitForWriteToFlush();

  // By default the stream protects itself from writes after terminte is set.
  // Override this to test the server handling buggy clients.
  QuicStreamPeer::SetWriteSideClosed(false, client_->GetOrCreateStream());

  EXPECT_QUIC_BUG(client_->SendData("eep", true), "Fin already buffered");
}

TEST_P(EndToEndTest, Timeout) {
  client_config_.SetIdleNetworkTimeout(QuicTime::Delta::FromMicroseconds(500));
  // Note: we do NOT ASSERT_TRUE: we may time out during initial handshake:
  // that's enough to validate timeout in this case.
  Initialize();
  while (client_->client()->connected()) {
    client_->client()->WaitForEvents();
  }
}

TEST_P(EndToEndTest, MaxDynamicStreamsLimitRespected) {
  // Set a limit on maximum number of incoming dynamic streams.
  // Make sure the limit is respected by the peer.
  const uint32_t kServerMaxDynamicStreams = 1;
  server_config_.SetMaxBidirectionalStreamsToSend(kServerMaxDynamicStreams);
  ASSERT_TRUE(Initialize());
  if (version_.HasIetfQuicFrames()) {
    // Do not run this test for /IETF QUIC. This test relies on the fact that
    // Google QUIC allows a small number of additional streams beyond the
    // negotiated limit, which is not supported in IETF QUIC. Note that the test
    // needs to be here, after calling Initialize(), because all tests end up
    // calling EndToEndTest::TearDown(), which asserts that Initialize has been
    // called and then proceeds to tear things down -- which fails if they are
    // not properly set up.
    return;
  }
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  // Make the client misbehave after negotiation.
  const int kServerMaxStreams = kMaxStreamsMinimumIncrement + 1;
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicSessionPeer::SetMaxOpenOutgoingStreams(client_session,
                                             kServerMaxStreams + 1);

  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  headers["content-length"] = "3";

  // The server supports a small number of additional streams beyond the
  // negotiated limit. Open enough streams to go beyond that limit.
  for (int i = 0; i < kServerMaxStreams + 1; ++i) {
    client_->SendMessage(headers, "", /*fin=*/false);
  }
  client_->WaitForResponse();

  EXPECT_TRUE(client_->connected());
  EXPECT_THAT(client_->stream_error(), IsStreamError(QUIC_REFUSED_STREAM));
  EXPECT_THAT(client_->connection_error(), IsQuicNoError());
}

TEST_P(EndToEndTest, SetIndependentMaxDynamicStreamsLimits) {
  // Each endpoint can set max dynamic streams independently.
  const uint32_t kClientMaxDynamicStreams = 4;
  const uint32_t kServerMaxDynamicStreams = 3;
  client_config_.SetMaxBidirectionalStreamsToSend(kClientMaxDynamicStreams);
  server_config_.SetMaxBidirectionalStreamsToSend(kServerMaxDynamicStreams);
  client_config_.SetMaxUnidirectionalStreamsToSend(kClientMaxDynamicStreams);
  server_config_.SetMaxUnidirectionalStreamsToSend(kServerMaxDynamicStreams);

  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  // The client has received the server's limit and vice versa.
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  // The value returned by max_allowed... includes the Crypto and Header
  // stream (created as a part of initialization). The config. values,
  // above, are treated as "number of requests/responses" - that is, they do
  // not include the static Crypto and Header streams. Reduce the value
  // returned by max_allowed... by 2 to remove the static streams from the
  // count.
  size_t client_max_open_outgoing_bidirectional_streams =
      version_.HasIetfQuicFrames()
          ? QuicSessionPeer::ietf_streamid_manager(client_session)
                ->max_outgoing_bidirectional_streams()
          : QuicSessionPeer::GetStreamIdManager(client_session)
                ->max_open_outgoing_streams();
  size_t client_max_open_outgoing_unidirectional_streams =
      version_.HasIetfQuicFrames()
          ? QuicSessionPeer::ietf_streamid_manager(client_session)
                    ->max_outgoing_unidirectional_streams() -
                kHttp3StaticUnidirectionalStreamCount
          : QuicSessionPeer::GetStreamIdManager(client_session)
                ->max_open_outgoing_streams();
  EXPECT_EQ(kServerMaxDynamicStreams,
            client_max_open_outgoing_bidirectional_streams);
  EXPECT_EQ(kServerMaxDynamicStreams,
            client_max_open_outgoing_unidirectional_streams);
  server_thread_->Pause();
  QuicSession* server_session = GetServerSession();
  if (server_session != nullptr) {
    size_t server_max_open_outgoing_bidirectional_streams =
        version_.HasIetfQuicFrames()
            ? QuicSessionPeer::ietf_streamid_manager(server_session)
                  ->max_outgoing_bidirectional_streams()
            : QuicSessionPeer::GetStreamIdManager(server_session)
                  ->max_open_outgoing_streams();
    size_t server_max_open_outgoing_unidirectional_streams =
        version_.HasIetfQuicFrames()
            ? QuicSessionPeer::ietf_streamid_manager(server_session)
                      ->max_outgoing_unidirectional_streams() -
                  kHttp3StaticUnidirectionalStreamCount
            : QuicSessionPeer::GetStreamIdManager(server_session)
                  ->max_open_outgoing_streams();
    EXPECT_EQ(kClientMaxDynamicStreams,
              server_max_open_outgoing_bidirectional_streams);
    EXPECT_EQ(kClientMaxDynamicStreams,
              server_max_open_outgoing_unidirectional_streams);
  } else {
    ADD_FAILURE() << "Missing server session";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, NegotiateCongestionControl) {
  ASSERT_TRUE(Initialize());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  CongestionControlType expected_congestion_control_type = kRenoBytes;
  switch (GetParam().congestion_control_tag) {
    case kRENO:
      expected_congestion_control_type = kRenoBytes;
      break;
    case kTBBR:
      expected_congestion_control_type = kBBR;
      break;
    case kQBIC:
      expected_congestion_control_type = kCubicBytes;
      break;
    case kB2ON:
      expected_congestion_control_type = kBBRv2;
      break;
    default:
      QUIC_DLOG(FATAL) << "Unexpected congestion control tag";
  }

  server_thread_->Pause();
  const QuicSentPacketManager* server_sent_packet_manager =
      GetSentPacketManagerFromFirstServerSession();
  if (server_sent_packet_manager != nullptr) {
    EXPECT_EQ(
        expected_congestion_control_type,
        QuicSentPacketManagerPeer::GetSendAlgorithm(*server_sent_packet_manager)
            ->GetCongestionControlType());
  } else {
    ADD_FAILURE() << "Missing server sent packet manager";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, ClientSuggestsRTT) {
  // Client suggests initial RTT, verify it is used.
  const QuicTime::Delta kInitialRTT = QuicTime::Delta::FromMicroseconds(20000);
  client_config_.SetInitialRoundTripTimeUsToSend(kInitialRTT.ToMicroseconds());

  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(server_thread_);
  server_thread_->WaitForCryptoHandshakeConfirmed();

  // Pause the server so we can access the server's internals without races.
  server_thread_->Pause();
  const QuicSentPacketManager* client_sent_packet_manager =
      GetSentPacketManagerFromClientSession();
  const QuicSentPacketManager* server_sent_packet_manager =
      GetSentPacketManagerFromFirstServerSession();
  if (client_sent_packet_manager != nullptr &&
      server_sent_packet_manager != nullptr) {
    EXPECT_EQ(kInitialRTT,
              client_sent_packet_manager->GetRttStats()->initial_rtt());
    EXPECT_EQ(kInitialRTT,
              server_sent_packet_manager->GetRttStats()->initial_rtt());
  } else {
    ADD_FAILURE() << "Missing sent packet manager";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, ClientSuggestsIgnoredRTT) {
  // Client suggests initial RTT, but also specifies NRTT, so it's not used.
  const QuicTime::Delta kInitialRTT = QuicTime::Delta::FromMicroseconds(20000);
  client_config_.SetInitialRoundTripTimeUsToSend(kInitialRTT.ToMicroseconds());
  QuicTagVector options;
  options.push_back(kNRTT);
  client_config_.SetConnectionOptionsToSend(options);

  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(server_thread_);
  server_thread_->WaitForCryptoHandshakeConfirmed();

  // Pause the server so we can access the server's internals without races.
  server_thread_->Pause();
  const QuicSentPacketManager* client_sent_packet_manager =
      GetSentPacketManagerFromClientSession();
  const QuicSentPacketManager* server_sent_packet_manager =
      GetSentPacketManagerFromFirstServerSession();
  if (client_sent_packet_manager != nullptr &&
      server_sent_packet_manager != nullptr) {
    EXPECT_EQ(kInitialRTT,
              client_sent_packet_manager->GetRttStats()->initial_rtt());
    EXPECT_EQ(kInitialRTT,
              server_sent_packet_manager->GetRttStats()->initial_rtt());
  } else {
    ADD_FAILURE() << "Missing sent packet manager";
  }
  server_thread_->Resume();
}

// Regression test for b/171378845
TEST_P(EndToEndTest, ClientDisablesGQuicZeroRtt) {
  if (version_.UsesTls()) {
    // This feature is gQUIC only.
    ASSERT_TRUE(Initialize());
    return;
  }
  QuicTagVector options;
  options.push_back(kQNZ2);
  client_config_.SetClientConnectionOptions(options);

  ASSERT_TRUE(Initialize());

  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  client_->Disconnect();

  // Make sure that the request succeeds but 0-RTT was not used.
  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
}

TEST_P(EndToEndTest, MaxInitialRTT) {
  // Client tries to suggest twice the server's max initial rtt and the server
  // uses the max.
  client_config_.SetInitialRoundTripTimeUsToSend(2 *
                                                 kMaxInitialRoundTripTimeUs);

  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(server_thread_);
  server_thread_->WaitForCryptoHandshakeConfirmed();

  // Pause the server so we can access the server's internals without races.
  server_thread_->Pause();
  const QuicSentPacketManager* client_sent_packet_manager =
      GetSentPacketManagerFromClientSession();
  const QuicSentPacketManager* server_sent_packet_manager =
      GetSentPacketManagerFromFirstServerSession();
  if (client_sent_packet_manager != nullptr &&
      server_sent_packet_manager != nullptr) {
    // Now that acks have been exchanged, the RTT estimate has decreased on the
    // server and is not infinite on the client.
    EXPECT_FALSE(
        client_sent_packet_manager->GetRttStats()->smoothed_rtt().IsInfinite());
    const RttStats* server_rtt_stats =
        server_sent_packet_manager->GetRttStats();
    EXPECT_EQ(static_cast<int64_t>(kMaxInitialRoundTripTimeUs),
              server_rtt_stats->initial_rtt().ToMicroseconds());
    EXPECT_GE(static_cast<int64_t>(kMaxInitialRoundTripTimeUs),
              server_rtt_stats->smoothed_rtt().ToMicroseconds());
  } else {
    ADD_FAILURE() << "Missing sent packet manager";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, MinInitialRTT) {
  // Client tries to suggest 0 and the server uses the default.
  client_config_.SetInitialRoundTripTimeUsToSend(0);

  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  server_thread_->WaitForCryptoHandshakeConfirmed();

  // Pause the server so we can access the server's internals without races.
  server_thread_->Pause();
  const QuicSentPacketManager* client_sent_packet_manager =
      GetSentPacketManagerFromClientSession();
  const QuicSentPacketManager* server_sent_packet_manager =
      GetSentPacketManagerFromFirstServerSession();
  if (client_sent_packet_manager != nullptr &&
      server_sent_packet_manager != nullptr) {
    // Now that acks have been exchanged, the RTT estimate has decreased on the
    // server and is not infinite on the client.
    EXPECT_FALSE(
        client_sent_packet_manager->GetRttStats()->smoothed_rtt().IsInfinite());
    // Expect the default rtt of 100ms.
    EXPECT_EQ(QuicTime::Delta::FromMilliseconds(100),
              server_sent_packet_manager->GetRttStats()->initial_rtt());
    // Ensure the bandwidth is valid.
    client_sent_packet_manager->BandwidthEstimate();
    server_sent_packet_manager->BandwidthEstimate();
  } else {
    ADD_FAILURE() << "Missing sent packet manager";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, ResetConnection) {
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  client_->ResetConnection();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  SendSynchronousBarRequestAndCheckResponse();
}

// Regression test for b/180737158.
TEST_P(
    EndToEndTest,
    HalfRttResponseBlocksShloRetransmissionWithoutTokenBasedAddressValidation) {
  // Turn off token based address validation to make the server get constrained
  // by amplification factor during handshake.
  SetQuicFlag(quic_reject_retry_token_in_initial_packet, true);
  ASSERT_TRUE(Initialize());
  if (!version_.SupportsAntiAmplificationLimit()) {
    return;
  }
  // Perform a full 1-RTT handshake to get the new session ticket such that the
  // next connection will perform a 0-RTT handshake.
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  client_->Disconnect();

  server_thread_->Pause();
  // Drop the 1st server packet which is the coalesced INITIAL + HANDSHAKE +
  // 1RTT.
  PacketDroppingTestWriter* writer = new PacketDroppingTestWriter();
  writer->set_fake_drop_first_n_packets(1);
  QuicDispatcherPeer::UseWriter(
      QuicServerPeer::GetDispatcher(server_thread_->server()), writer);
  server_thread_->Resume();

  // Large response (100KB) for 0-RTT request.
  std::string large_body(102400, 'a');
  AddToCache("/large_response", 200, large_body);
  SendSynchronousRequestAndCheckResponse(client_.get(), "/large_response",
                                         large_body);
}

TEST_P(EndToEndTest, MaxStreamsUberTest) {
  // Connect with lower fake packet loss than we'd like to test.  Until
  // b/10126687 is fixed, losing handshake packets is pretty brutal.
  SetPacketLossPercentage(1);
  ASSERT_TRUE(Initialize());
  std::string large_body(10240, 'a');
  int max_streams = 100;

  AddToCache("/large_response", 200, large_body);

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  SetPacketLossPercentage(10);

  for (int i = 0; i < max_streams; ++i) {
    EXPECT_LT(0, client_->SendRequest("/large_response"));
  }

  // WaitForEvents waits 50ms and returns true if there are outstanding
  // requests.
  while (client_->client()->WaitForEvents()) {
    ASSERT_TRUE(client_->connected());
  }
}

TEST_P(EndToEndTest, StreamCancelErrorTest) {
  ASSERT_TRUE(Initialize());
  std::string small_body(256, 'a');

  AddToCache("/small_response", 200, small_body);

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  QuicSession* session = GetClientSession();
  ASSERT_TRUE(session);
  // Lose the request.
  SetPacketLossPercentage(100);
  EXPECT_LT(0, client_->SendRequest("/small_response"));
  client_->client()->WaitForEvents();
  // Transmit the cancel, and ensure the connection is torn down properly.
  SetPacketLossPercentage(0);
  QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  const QuicPacketCount packets_sent_before =
      client_connection->GetStats().packets_sent;
  session->ResetStream(stream_id, QUIC_STREAM_CANCELLED);
  const QuicPacketCount packets_sent_now =
      client_connection->GetStats().packets_sent;

  if (version_.UsesHttp3()) {
    // QPACK decoder instructions and RESET_STREAM and STOP_SENDING frames are
    // sent in a single packet.
    EXPECT_EQ(packets_sent_before + 1, packets_sent_now);
  }

  // WaitForEvents waits 50ms and returns true if there are outstanding
  // requests.
  while (client_->client()->WaitForEvents()) {
    ASSERT_TRUE(client_->connected());
  }
  // It should be completely fine to RST a stream before any data has been
  // received for that stream.
  EXPECT_THAT(client_->connection_error(), IsQuicNoError());
}

TEST_P(EndToEndTest, ConnectionMigrationClientIPChanged) {
  ASSERT_TRUE(Initialize());
  if (GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  SendSynchronousFooRequestAndCheckResponse();

  // Store the client IP address which was used to send the first request.
  QuicIpAddress old_host =
      client_->client()->network_helper()->GetLatestClientAddress().host();

  // Migrate socket to the new IP address.
  QuicIpAddress new_host = TestLoopback(2);
  EXPECT_NE(old_host, new_host);
  ASSERT_TRUE(client_->client()->MigrateSocket(new_host));

  // Send a request using the new socket.
  SendSynchronousBarRequestAndCheckResponse();

  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(1u,
            client_connection->GetStats().num_connectivity_probing_received);

  // Send another request.
  SendSynchronousBarRequestAndCheckResponse();
  // By the time the 2nd request is completed, the PATH_RESPONSE must have been
  // received by the server.
  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    EXPECT_FALSE(server_connection->HasPendingPathValidation());
    EXPECT_EQ(1u, server_connection->GetStats().num_validated_peer_migration);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, IetfConnectionMigrationClientIPChangedMultipleTimes) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  SendSynchronousFooRequestAndCheckResponse();

  // Store the client IP address which was used to send the first request.
  QuicIpAddress host0 =
      client_->client()->network_helper()->GetLatestClientAddress().host();
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection != nullptr);

  // Migrate socket to a new IP address.
  QuicIpAddress host1 = TestLoopback(2);
  EXPECT_NE(host0, host1);
  ASSERT_TRUE(
      QuicConnectionPeer::HasUnusedPeerIssuedConnectionId(client_connection));
  QuicConnectionId server_cid0 = client_connection->connection_id();
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  EXPECT_TRUE(client_->client()->MigrateSocket(host1));
  QuicConnectionId server_cid1 = client_connection->connection_id();
  EXPECT_FALSE(server_cid1.IsEmpty());
  EXPECT_NE(server_cid0, server_cid1);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());

  // Send a request using the new socket.
  SendSynchronousBarRequestAndCheckResponse();
  EXPECT_EQ(1u,
            client_connection->GetStats().num_connectivity_probing_received);

  // Send another request and wait for response making sure path response is
  // received at server.
  SendSynchronousBarRequestAndCheckResponse();

  // Migrate socket to a new IP address.
  WaitForNewConnectionIds();
  EXPECT_EQ(1u, client_connection->GetStats().num_retire_connection_id_sent);
  QuicIpAddress host2 = TestLoopback(3);
  EXPECT_NE(host0, host2);
  EXPECT_NE(host1, host2);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  EXPECT_TRUE(client_->client()->MigrateSocket(host2));
  QuicConnectionId server_cid2 = client_connection->connection_id();
  EXPECT_FALSE(server_cid2.IsEmpty());
  EXPECT_NE(server_cid0, server_cid2);
  EXPECT_NE(server_cid1, server_cid2);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());

  // Send another request using the new socket and wait for response making sure
  // path response is received at server.
  SendSynchronousBarRequestAndCheckResponse();
  EXPECT_EQ(2u,
            client_connection->GetStats().num_connectivity_probing_received);

  // Migrate socket back to an old IP address.
  WaitForNewConnectionIds();
  EXPECT_EQ(2u, client_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  EXPECT_TRUE(client_->client()->MigrateSocket(host1));
  QuicConnectionId server_cid3 = client_connection->connection_id();
  EXPECT_FALSE(server_cid3.IsEmpty());
  EXPECT_NE(server_cid0, server_cid3);
  EXPECT_NE(server_cid1, server_cid3);
  EXPECT_NE(server_cid2, server_cid3);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  const auto* client_packet_creator =
      QuicConnectionPeer::GetPacketCreator(client_connection);
  EXPECT_TRUE(client_packet_creator->GetClientConnectionId().IsEmpty());
  EXPECT_EQ(server_cid3, client_packet_creator->GetServerConnectionId());

  // Send another request using the new socket and wait for response making sure
  // path response is received at server.
  SendSynchronousBarRequestAndCheckResponse();
  // Even this is an old path, server has forgotten about it and thus needs to
  // validate the path again.
  EXPECT_EQ(3u,
            client_connection->GetStats().num_connectivity_probing_received);

  WaitForNewConnectionIds();
  EXPECT_EQ(3u, client_connection->GetStats().num_retire_connection_id_sent);

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  // By the time the 2nd request is completed, the PATH_RESPONSE must have been
  // received by the server.
  EXPECT_FALSE(server_connection->HasPendingPathValidation());
  EXPECT_EQ(3u, server_connection->GetStats().num_validated_peer_migration);
  EXPECT_EQ(server_cid3, server_connection->connection_id());
  const auto* server_packet_creator =
      QuicConnectionPeer::GetPacketCreator(server_connection);
  EXPECT_EQ(server_cid3, server_packet_creator->GetServerConnectionId());
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  server_connection)
                  .IsEmpty());
  EXPECT_EQ(4u, server_connection->GetStats().num_new_connection_id_sent);
  server_thread_->Resume();
}

TEST_P(EndToEndTest,
       ConnectionMigrationWithNonZeroConnectionIDClientIPChangedMultipleTimes) {
  if (!version_.HasIetfQuicFrames() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    ASSERT_TRUE(Initialize());
    return;
  }
  override_client_connection_id_length_ = kQuicDefaultConnectionIdLength;
  ASSERT_TRUE(Initialize());
  SendSynchronousFooRequestAndCheckResponse();

  // Store the client IP address which was used to send the first request.
  QuicIpAddress host0 =
      client_->client()->network_helper()->GetLatestClientAddress().host();
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection != nullptr);

  {
    QuicConnection::ScopedPacketFlusher flusher(client_connection);
    if (
```
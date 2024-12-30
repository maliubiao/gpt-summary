Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/spdy/spdy_session_unittest.cc`. This is part 2 of an 8-part explanation, so I need to summarize the functionality demonstrated in this specific part.

The code consists of several test cases for the `SpdySession` class in Chromium's network stack. Each `TEST_F` function represents a unit test verifying a specific behavior of the `SpdySession`.

Here's a breakdown of the test cases and their functionalities:

*   **`GoAwayThenNew الابداع RequestFails`**: Tests that after receiving a `GOAWAY` frame, new stream requests fail.
*   **`HeadersAfterGoAway`**:  Tests that receiving a `HEADERS` frame (like a `PUSH_PROMISE`) after a `GOAWAY` frame results in the stream being refused (RST_STREAM sent).
*   **`NetworkChangeWithActiveStreams`**: Tests how a `SpdySession` handles a network change while there are active streams. The behavior varies by operating system.
*   **`ClientPing`**: Tests the client-initiated ping mechanism for keep-alive.
*   **`ServerPing`**: Tests the server-initiated ping mechanism where the client responds.
*   **`PingAndWriteLoop`**: Tests that sending a ping during an ongoing write operation doesn't cause issues with the write loop.
*   **`DetectBrokenConnectionPing`**: Tests the mechanism for detecting broken connections using ping with a specified heartbeat interval.
*   **`StreamIdSpaceExhausted`**: Tests the scenario where the available stream ID space is exhausted.
*   **`MaxConcurrentStreamsZero`**: Tests the behavior when the server sends a `SETTINGS` frame setting `max_concurrent_streams` to zero, and then to one.
*   **`UnstallRacesWithStreamCreation`**: Tests a race condition scenario where an unstalled pending stream creation competes with a new stream creation.
*   **`FailedPing`**: Tests the case where a client-initiated ping fails to receive a response, leading to the connection being closed.
*   **`NoPingSentWhenCheckPingPending`**: Tests that a new ping is not sent if a previous ping's status check is still pending.
*   **`OnSettings`**: Tests how the session handles receiving a `SETTINGS` frame that increases the maximum concurrent streams, particularly when there are already pending stream creations.
*   **`CancelPendingCreateStream`**: Tests that canceling a pending stream creation doesn't cause a crash.

Therefore, the overall function of this code snippet is to **test various scenarios related to the lifecycle and behavior of a SPDY session, including handling `GOAWAY` frames, network changes, ping mechanisms (client and server initiated), stream ID exhaustion, `max_concurrent_streams` settings, and race conditions during stream creation and cancellation.**
这个C++ 代码片段是 `net/spdy/spdy_session_unittest.cc` 文件的一部分，它主要的功能是 **对 Chromium 网络栈中的 `SpdySession` 类进行单元测试**。

具体来说，这个代码片段中的每个 `TEST_F` 函数都针对 `SpdySession` 的特定功能或边界情况进行测试，以确保其行为符合预期。 归纳一下这些测试用例的功能：

1. **`GoAwayThenNewRequestFails`**:  测试当 `SpdySession` 收到 `GOAWAY` 帧后，新的请求是否会失败。这验证了会话终止后不能再创建新流的行为。

2. **`HeadersAfterGoAway`**: 测试当 `SpdySession` 收到 `GOAWAY` 帧后，如果服务端仍然发送 `HEADERS` 帧（例如 `PUSH_PROMISE`），会发生什么。这通常会导致客户端发送 `RST_STREAM` 帧来拒绝该流。

3. **`NetworkChangeWithActiveStreams`**: 测试当网络发生变化（例如 IP 地址改变）时，拥有活跃流的 `SpdySession` 如何处理。不同的操作系统对此可能有不同的反应，测试会覆盖这些情况。

4. **`ClientPing`**: 测试客户端发起 PING 帧以进行连接保活的机制。它验证了客户端发送 PING 以及接收 PING 响应的功能，并检查了相关的网络质量估算器的更新。

5. **`ServerPing`**: 测试服务端发起 PING 帧，客户端响应的机制。

6. **`PingAndWriteLoop`**: 测试在发送数据的过程中，如果触发了 PING 的发送，写入循环是否能够正确处理，避免出现问题。

7. **`DetectBrokenConnectionPing`**: 测试使用 PING 机制来检测断开连接的功能。它验证了在指定的心跳间隔后发送 PING，并在收到响应后更新状态。

8. **`StreamIdSpaceExhausted`**: 测试当可用的流 ID 空间耗尽时，`SpdySession` 的行为。这涉及到最大流 ID 的限制和会话的终止。

9. **`MaxConcurrentStreamsZero`**: 测试当服务端发送 `SETTINGS` 帧将最大并发流数量设置为 0 时，客户端如何处理。以及之后如果服务端又将其设置为 1，客户端是否能够正确创建流。

10. **`UnstallRacesWithStreamCreation`**: 测试一个被阻塞的流创建请求在取消阻塞时，与新的流创建请求之间可能发生的竞争情况，确保不会违反最大并发流的限制。

11. **`FailedPing`**: 测试当客户端发送 PING 帧后，没有收到响应时，`SpdySession` 如何处理，通常会导致连接关闭。

12. **`NoPingSentWhenCheckPingPending`**: 测试当一个 PING 的状态检查还在 pending 状态时，是否会发送新的 PING，以避免重复发送。

13. **`OnSettings`**: 测试当 `SpdySession` 接收到一个增加最大并发流数量的 `SETTINGS` 帧时，是否能够正确处理，特别是当有待处理的流创建请求时。

14. **`CancelPendingCreateStream`**: 测试取消一个正在等待创建的流，确保不会导致程序崩溃。

**与 Javascript 的关系：**

这个 C++ 代码直接在 Chromium 的网络层运行，处理底层的 SPDY/HTTP/2 协议。它与 Javascript 的功能没有直接的交互。然而，Javascript (通常在浏览器环境中运行) 发起的网络请求最终会通过 Chromium 的网络栈处理，包括这里的 `SpdySession`。

**举例说明：**

假设一个网页 (Javascript 代码运行在其中) 发起了一个 HTTP/2 请求。

1. **Javascript 发起请求:**  `fetch('https://example.com/data')`
2. **浏览器处理请求:**  浏览器会解析 URL，确定需要使用哪个协议，并查找或建立到 `example.com` 的 HTTP/2 连接。
3. **`SpdySession` 参与:**  如果已经存在一个到 `example.com` 的活跃的 `SpdySession`，则会使用该会话。否则，会创建一个新的 `SpdySession`。
4. **流的创建:**  `SpdySession` 会创建一个新的 SPDY 流来处理这个请求。这可能涉及到上述测试用例中涉及的逻辑，例如检查最大并发流数，处理 `GOAWAY` 帧等。
5. **数据传输:**  请求头和数据会通过这个 SPDY 流发送。
6. **响应处理:**  `SpdySession` 接收并解析服务器的响应头和数据，然后将数据传递给浏览器的渲染引擎，最终 Javascript 可以通过 `fetch` 的 Promise 获得响应。

**逻辑推理，假设输入与输出：**

以 `GoAwayThenNewRequestFails` 测试为例：

*   **假设输入:**
    *   一个已经建立的 `SpdySession` (`session_`).
    *   一个模拟的读取数据流，其中包含一个 `GOAWAY` 帧。
    *   之后尝试创建一个新的 SPDY 流。
*   **预期输出:**
    *   当读取到 `GOAWAY` 帧后，`SpdySession` 会进入 going-away 状态。
    *   尝试创建新的 SPDY 流会失败，并返回一个错误 (`ERR_FAILED`).
    *   `HasSpdySession` 返回 `false`，表示该会话已不再可用。

**用户或编程常见的使用错误：**

*   **在收到 `GOAWAY` 后仍然尝试发送请求:**  用户（或者更准确地说，是依赖网络连接的应用程序逻辑）可能会错误地认为连接仍然可用，并在收到 `GOAWAY` 后继续尝试发送请求。这会导致请求失败。测试用例 `GoAwayThenNewRequestFails` 和 `HeadersAfterGoAway` 模拟了这种情况。
*   **长时间没有活动导致连接断开:**  服务器可能会发送 PING 帧来检测连接是否仍然活跃。如果客户端没有响应，服务器可能会关闭连接。客户端的 PING 机制可以防止这种情况发生，但如果配置不当或网络环境恶劣，仍然可能遇到连接断开的问题。`ClientPing` 和 `FailedPing` 测试用例覆盖了这方面。
*   **超过最大并发流限制:**  如果客户端尝试创建的流数量超过服务器允许的最大并发流数量，请求会被阻塞。开发者需要理解这个限制并合理管理请求队列。`MaxConcurrentStreamsZero` 和 `UnstallRacesWithStreamCreation` 测试用例与此相关。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器浏览网页时遇到网络问题，例如页面加载缓慢或失败。作为开发人员，为了调试问题，可能会检查网络日志，发现使用了 HTTP/2 协议。如果怀疑是底层连接的问题，可能会深入到 `SpdySession` 的层面进行调试。

1. **用户访问网页:** 用户在 Chrome 浏览器中输入 URL 并访问一个使用 HTTPS 的网站。
2. **建立连接:**  Chrome 会尝试与服务器建立 TLS 连接。
3. **协议协商:**  在 TLS 握手过程中，Chrome 和服务器会协商使用 HTTP/2 协议（如果服务器支持）。
4. **`SpdySession` 创建:**  如果协商成功，Chrome 会创建一个 `SpdySession` 对象来管理与服务器的 HTTP/2 连接。
5. **发送请求:** 当网页需要加载资源时，Javascript 会发起 `fetch` 或 `XMLHttpRequest` 请求。
6. **流的创建和管理:**  `SpdySession` 会创建和管理 SPDY 流来发送这些请求。这里的逻辑就可能涉及到上述测试用例中涉及的各种情况，例如检查最大并发流数，处理服务端发送的 `SETTINGS` 帧或 `GOAWAY` 帧等。
7. **网络问题出现:**  如果此时网络不稳定，或者服务器发送了 `GOAWAY` 帧，或者达到了最大并发流限制，用户可能会遇到页面加载问题。
8. **开发人员调试:**  开发人员可能会查看 Chrome 的内部网络日志 (`chrome://net-internals/#http2`)，或者使用调试工具来跟踪网络请求，可能会看到与 `SpdySession` 相关的事件或错误信息。
9. **查看源代码:**  为了更深入地理解问题，开发人员可能会查看 Chromium 的源代码，例如 `net/spdy/spdy_session.cc` 和 `net/spdy/spdy_session_unittest.cc`，特别是相关的测试用例，来了解 `SpdySession` 在遇到特定情况时的预期行为。

因此，`spdy_session_unittest.cc` 中的测试用例可以作为调试的参考，帮助开发人员理解 `SpdySession` 在各种场景下的工作方式，从而定位和解决实际的网络问题。

**归纳一下它的功能 (针对这部分代码):**

这部分 `spdy_session_unittest.cc` 的代码主要功能是 **验证 `SpdySession` 类在处理连接生命周期中的各种事件和状态变化时的正确性**。 它通过模拟不同的网络场景和协议帧交互，测试了 `SpdySession` 对 `GOAWAY` 帧、网络变化、PING 帧、流 ID 耗尽、最大并发流设置等关键特性的处理逻辑，确保了 HTTP/2 连接管理的稳定性和可靠性。

Prompt: 
```
这是目录为net/spdy/spdy_session_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共8部分，请归纳一下它的功能

"""
spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_TRUE(session_->IsStreamActive(1));

  SpdyStreamRequest stream_request;
  int rv = stream_request.StartRequest(
      SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_, false, MEDIUM,
      SocketTag(), NetLogWithSource(), CompletionOnceCallback(),
      TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_THAT(rv, IsError(ERR_FAILED));

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Receiving a HEADERS frame after a GOAWAY frame should result in
// the stream being refused.
TEST_F(SpdySessionTest, HeadersAfterGoAway) {
  spdy::SpdySerializedFrame goaway_received(spdy_util_.ConstructSpdyGoAway(1));
  spdy::SpdySerializedFrame push(spdy_util_.ConstructSpdyPushPromise(1, 2, {}));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(goaway_received, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), CreateMockRead(push, 4),
      MockRead(ASYNC, 0, 6)  // EOF
  };
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  spdy::SpdySerializedFrame goaway_sent(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_PROTOCOL_ERROR, "PUSH_PROMISE received"));
  MockWrite writes[] = {CreateMockWrite(req, 0),
                        CreateMockWrite(goaway_sent, 5)};
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_TRUE(session_->IsStreamActive(1));

  // Read and process the HEADERS frame, the subsequent RST_STREAM,
  // and EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// A session observing a network change with active streams should close
// when the last active stream is closed.
TEST_F(SpdySessionTest, NetworkChangeWithActiveStreams) {
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), MockRead(ASYNC, 0, 2)  // EOF
  };
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));

  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  spdy_session_pool_->OnIPAddressChanged();

  // The SpdySessionPool behavior differs based on how the OSs reacts to
  // network changes; see comment in SpdySessionPool::OnIPAddressChanged().
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN) || BUILDFLAG(IS_IOS)
  // For OSs where the TCP connections will close upon relevant network
  // changes, SpdySessionPool doesn't need to force them to close, so in these
  // cases verify the session has become unavailable but remains open and the
  // pre-existing stream is still active.
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_TRUE(session_->IsGoingAway());

  EXPECT_TRUE(session_->IsStreamActive(1));

  // Should close the session.
  spdy_stream->Close();
#endif
  EXPECT_FALSE(spdy_stream);

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTestWithMockTime, ClientPing) {
  session_deps_.enable_ping = true;

  spdy::SpdySerializedFrame read_ping(spdy_util_.ConstructSpdyPing(1, true));
  MockRead reads[] = {
      CreateMockRead(read_ping, 1), MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };
  spdy::SpdySerializedFrame write_ping(spdy_util_.ConstructSpdyPing(1, false));
  MockWrite writes[] = {
      CreateMockWrite(write_ping, 0),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  TestNetworkQualityEstimator estimator;

  spdy_session_pool_->set_network_quality_estimator(&estimator);

  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  test::StreamDelegateSendImmediate delegate(spdy_stream1, "");
  spdy_stream1->SetDelegate(&delegate);

  base::TimeTicks before_ping_time = base::TimeTicks::Now();

  // Negative value means a preface ping will always be sent.
  set_connection_at_risk_of_loss_time(base::Seconds(-1));

  // Send a PING frame.  This posts CheckPingStatus() with delay.
  MaybeSendPrefacePing();

  EXPECT_TRUE(ping_in_flight());
  EXPECT_EQ(2u, next_ping_id());
  EXPECT_TRUE(check_ping_status_pending());

  // MaybeSendPrefacePing() should not send another PING frame if there is
  // already one in flight.
  MaybeSendPrefacePing();

  EXPECT_TRUE(ping_in_flight());
  EXPECT_EQ(2u, next_ping_id());
  EXPECT_TRUE(check_ping_status_pending());

  // Run posted CheckPingStatus() task.
  FastForwardUntilNoTasksRemain();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(ping_in_flight());
  EXPECT_EQ(2u, next_ping_id());
  EXPECT_FALSE(check_ping_status_pending());
  EXPECT_GE(last_read_time(), before_ping_time);

  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(MainThreadIsIdle());
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);
  EXPECT_FALSE(spdy_stream1);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());

  EXPECT_LE(1u, estimator.ping_rtt_received_count());
}

TEST_F(SpdySessionTest, ServerPing) {
  spdy::SpdySerializedFrame read_ping(spdy_util_.ConstructSpdyPing(2, false));
  MockRead reads[] = {
      CreateMockRead(read_ping), MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };
  spdy::SpdySerializedFrame write_ping(spdy_util_.ConstructSpdyPing(2, true));
  MockWrite writes[] = {
      CreateMockWrite(write_ping),
  };
  StaticSocketDataProvider data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  test::StreamDelegateSendImmediate delegate(spdy_stream1, "");
  spdy_stream1->SetDelegate(&delegate);

  // Flush the read completion task.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_FALSE(session_);
  EXPECT_FALSE(spdy_stream1);
}

// Cause a ping to be sent out while producing a write. The write loop
// should handle this properly, i.e. another DoWriteLoop task should
// not be posted. This is a regression test for
// http://crbug.com/261043 .
TEST_F(SpdySessionTest, PingAndWriteLoop) {
  session_deps_.enable_ping = true;
  session_deps_.time_func = TheNearFuture;

  spdy::SpdySerializedFrame write_ping(spdy_util_.ConstructSpdyPing(1, false));
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(write_ping, 1),
  };

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Shift time so that a ping will be sent out.
  g_time_delta = base::Seconds(11);

  base::RunLoop().RunUntilIdle();
  session_->CloseSessionOnError(ERR_ABORTED, "Aborting");

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTestWithMockTime, DetectBrokenConnectionPing) {
  session_deps_.enable_ping = true;

  spdy::SpdySerializedFrame read_ping1(spdy_util_.ConstructSpdyPing(1, true));
  spdy::SpdySerializedFrame read_ping2(spdy_util_.ConstructSpdyPing(2, true));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      CreateMockRead(read_ping1, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 5),
      CreateMockRead(read_ping2, 6),
      MockRead(ASYNC, ERR_IO_PENDING, 7),
      MockRead(ASYNC, 0, 8)  // EOF
  };
  spdy::SpdySerializedFrame write_ping1(spdy_util_.ConstructSpdyPing(1, false));
  spdy::SpdySerializedFrame write_ping2(spdy_util_.ConstructSpdyPing(2, false));
  MockWrite writes[] = {CreateMockWrite(write_ping1, 0),
                        CreateMockWrite(write_ping2, 4)};
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  TestNetworkQualityEstimator estimator;

  spdy_session_pool_->set_network_quality_estimator(&estimator);

  CreateSpdySession();

  constexpr base::TimeDelta kHeartbeatInterval = base::Seconds(15);
  ASSERT_FALSE(session_->IsBrokenConnectionDetectionEnabled());
  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session_, test_url_, MEDIUM,
      NetLogWithSource(), true, kHeartbeatInterval);
  ASSERT_TRUE(spdy_stream1);
  ASSERT_TRUE(session_->IsBrokenConnectionDetectionEnabled());
  test::StreamDelegateSendImmediate delegate(spdy_stream1, "");
  spdy_stream1->SetDelegate(&delegate);

  // Negative value means a preface ping will always be sent.
  set_connection_at_risk_of_loss_time(base::Seconds(-1));

  // Initially there should be no PING in flight or check pending.
  EXPECT_FALSE(ping_in_flight());
  EXPECT_FALSE(check_ping_status_pending());
  // After kHeartbeatInterval time has passed the first PING should be in flight
  // and its status check pending.
  FastForwardBy(kHeartbeatInterval);
  EXPECT_TRUE(ping_in_flight());
  EXPECT_TRUE(check_ping_status_pending());

  // Consume the PING ack.
  data.Resume();
  base::RunLoop run_loop;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, run_loop.QuitClosure());
  run_loop.Run();
  EXPECT_FALSE(ping_in_flight());
  EXPECT_TRUE(check_ping_status_pending());
  // Consume the pending check_ping_status callback, we should be back to the
  // starting state.
  FastForwardBy(NextMainThreadPendingTaskDelay());
  EXPECT_FALSE(ping_in_flight());
  EXPECT_FALSE(check_ping_status_pending());

  // Unblock data and trigger the next heartbeat.
  data.Resume();
  FastForwardBy(NextMainThreadPendingTaskDelay());
  EXPECT_TRUE(ping_in_flight());
  EXPECT_TRUE(check_ping_status_pending());

  // Consume PING ack and check_ping_status callback.
  data.Resume();
  FastForwardBy(NextMainThreadPendingTaskDelay());
  EXPECT_FALSE(ping_in_flight());
  EXPECT_FALSE(check_ping_status_pending());

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(MainThreadIsIdle());
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);
  EXPECT_FALSE(spdy_stream1);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());

  EXPECT_EQ(2u, estimator.ping_rtt_received_count());
}

TEST_F(SpdySessionTest, StreamIdSpaceExhausted) {
  // Test setup: |stream_hi_water_mark_| and |max_concurrent_streams_| are
  // fixed to allow for two stream ID assignments, and three concurrent
  // streams. Four streams are started, and two are activated. Verify the
  // session goes away, and that the created (but not activated) and
  // stalled streams are aborted. Also verify the activated streams complete,
  // at which point the session closes.

  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, kLastStreamId - 2, MEDIUM));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, kLastStreamId, MEDIUM));

  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, kLastStreamId - 2));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, kLastStreamId));

  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(kLastStreamId - 2, true));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(kLastStreamId, true));

  MockRead reads[] = {
      CreateMockRead(resp1, 2),           CreateMockRead(resp2, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), CreateMockRead(body1, 5),
      CreateMockRead(body2, 6),           MockRead(ASYNC, 0, 7)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  // Fix stream_hi_water_mark_ to allow for two stream activations.
  set_stream_hi_water_mark(kLastStreamId - 2);
  // Fix max_concurrent_streams to allow for three stream creations.
  set_max_concurrent_streams(3);

  // Create three streams synchronously, and begin a fourth (which is stalled).
  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(stream1);
  stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate2(stream2);
  stream2->SetDelegate(&delegate2);

  base::WeakPtr<SpdyStream> stream3 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate3(stream3);
  stream3->SetDelegate(&delegate3);

  SpdyStreamRequest request4;
  TestCompletionCallback callback4;
  EXPECT_EQ(ERR_IO_PENDING,
            request4.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                  test_url_, false, MEDIUM, SocketTag(),
                                  NetLogWithSource(), callback4.callback(),
                                  TRAFFIC_ANNOTATION_FOR_TESTS));

  // Streams 1-3 were created. 4th is stalled. No streams are active yet.
  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(3u, num_created_streams());
  EXPECT_EQ(1u, pending_create_stream_queue_size(MEDIUM));

  // Activate stream 1. One ID remains available.
  stream1->SendRequestHeaders(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl),
                              NO_MORE_DATA_TO_SEND);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(kLastStreamId - 2u, stream1->stream_id());
  EXPECT_EQ(1u, num_active_streams());
  EXPECT_EQ(2u, num_created_streams());
  EXPECT_EQ(1u, pending_create_stream_queue_size(MEDIUM));

  // Activate stream 2. ID space is exhausted.
  stream2->SendRequestHeaders(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl),
                              NO_MORE_DATA_TO_SEND);
  base::RunLoop().RunUntilIdle();

  // Active streams remain active.
  EXPECT_EQ(kLastStreamId, stream2->stream_id());
  EXPECT_EQ(2u, num_active_streams());

  // Session is going away. Created and stalled streams were aborted.
  EXPECT_TRUE(session_->IsGoingAway());
  EXPECT_THAT(delegate3.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));
  EXPECT_THAT(callback4.WaitForResult(), IsError(ERR_HTTP2_PROTOCOL_ERROR));
  EXPECT_EQ(0u, num_created_streams());
  EXPECT_EQ(0u, pending_create_stream_queue_size(MEDIUM));

  // Read responses on remaining active streams.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(delegate1.WaitForClose(), IsOk());
  EXPECT_EQ(kUploadData, delegate1.TakeReceivedData());
  EXPECT_THAT(delegate2.WaitForClose(), IsOk());
  EXPECT_EQ(kUploadData, delegate2.TakeReceivedData());

  // Session was destroyed.
  EXPECT_FALSE(session_);
}

// Regression test for https://crbug.com/481009.
TEST_F(SpdySessionTest, MaxConcurrentStreamsZero) {

  // Receive SETTINGS frame that sets max_concurrent_streams to zero.
  spdy::SettingsMap settings_zero;
  settings_zero[spdy::SETTINGS_MAX_CONCURRENT_STREAMS] = 0;
  spdy::SpdySerializedFrame settings_frame_zero(
      spdy_util_.ConstructSpdySettings(settings_zero));

  // Acknowledge it.
  spdy::SpdySerializedFrame settings_ack0(
      spdy_util_.ConstructSpdySettingsAck());

  // Receive SETTINGS frame that sets max_concurrent_streams to one.
  spdy::SettingsMap settings_one;
  settings_one[spdy::SETTINGS_MAX_CONCURRENT_STREAMS] = 1;
  spdy::SpdySerializedFrame settings_frame_one(
      spdy_util_.ConstructSpdySettings(settings_one));

  // Acknowledge it.
  spdy::SpdySerializedFrame settings_ack1(
      spdy_util_.ConstructSpdySettingsAck());

  // Request and response.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead reads[] = {CreateMockRead(settings_frame_zero, 0),
                      MockRead(ASYNC, ERR_IO_PENDING, 2),
                      CreateMockRead(settings_frame_one, 3),
                      CreateMockRead(resp, 6),
                      CreateMockRead(body, 7),
                      MockRead(ASYNC, 0, 8)};

  MockWrite writes[] = {CreateMockWrite(settings_ack0, 1),
                        CreateMockWrite(settings_ack1, 4),
                        CreateMockWrite(req, 5)};

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  // Create session.
  CreateNetworkSession();
  CreateSpdySession();

  // Receive SETTINGS frame that sets max_concurrent_streams to zero.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, max_concurrent_streams());

  // Start request.
  SpdyStreamRequest request;
  TestCompletionCallback callback;
  int rv =
      request.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_,
                           false, MEDIUM, SocketTag(), NetLogWithSource(),
                           callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Stream is stalled.
  EXPECT_EQ(1u, pending_create_stream_queue_size(MEDIUM));
  EXPECT_EQ(0u, num_created_streams());

  // Receive SETTINGS frame that sets max_concurrent_streams to one.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, max_concurrent_streams());

  // Stream is created.
  EXPECT_EQ(0u, pending_create_stream_queue_size(MEDIUM));
  EXPECT_EQ(1u, num_created_streams());

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Send request.
  base::WeakPtr<SpdyStream> stream = request.ReleaseStream();
  test::StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);
  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  EXPECT_THAT(delegate.WaitForClose(), IsOk());
  EXPECT_EQ("hello!", delegate.TakeReceivedData());

  // Finish async network reads/writes.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());

  // Session is destroyed.
  EXPECT_FALSE(session_);
}

// Verifies that an unstalled pending stream creation racing with a new stream
// creation doesn't violate the maximum stream concurrency. Regression test for
// crbug.com/373858.
TEST_F(SpdySessionTest, UnstallRacesWithStreamCreation) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  // Fix max_concurrent_streams to allow for one open stream.
  set_max_concurrent_streams(1);

  // Create two streams: one synchronously, and one which stalls.
  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());

  SpdyStreamRequest request2;
  TestCompletionCallback callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            request2.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                  test_url_, false, MEDIUM, SocketTag(),
                                  NetLogWithSource(), callback2.callback(),
                                  TRAFFIC_ANNOTATION_FOR_TESTS));

  EXPECT_EQ(1u, num_created_streams());
  EXPECT_EQ(1u, pending_create_stream_queue_size(MEDIUM));

  // Cancel the first stream. A callback to unstall the second stream was
  // posted. Don't run it yet.
  stream1->Cancel(ERR_ABORTED);

  EXPECT_EQ(0u, num_created_streams());
  EXPECT_EQ(0u, pending_create_stream_queue_size(MEDIUM));

  // Create a third stream prior to the second stream's callback.
  base::WeakPtr<SpdyStream> stream3 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());

  EXPECT_EQ(1u, num_created_streams());
  EXPECT_EQ(0u, pending_create_stream_queue_size(MEDIUM));

  // Now run the message loop. The unstalled stream will re-stall itself.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, num_created_streams());
  EXPECT_EQ(1u, pending_create_stream_queue_size(MEDIUM));

  // Cancel the third stream and run the message loop. Verify that the second
  // stream creation now completes.
  stream3->Cancel(ERR_ABORTED);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, num_created_streams());
  EXPECT_EQ(0u, pending_create_stream_queue_size(MEDIUM));
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
}

TEST_F(SpdySessionTestWithMockTime, FailedPing) {
  session_deps_.enable_ping = true;
  session_deps_.time_func = TheNearFuture;

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};  // Stall forever.
  spdy::SpdySerializedFrame write_ping(spdy_util_.ConstructSpdyPing(1, false));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_PROTOCOL_ERROR, "Failed ping."));
  MockWrite writes[] = {CreateMockWrite(write_ping), CreateMockWrite(goaway)};

  StaticSocketDataProvider data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  test::StreamDelegateSendImmediate delegate(spdy_stream1, "");
  spdy_stream1->SetDelegate(&delegate);

  // Negative value means a preface ping will always be sent.
  set_connection_at_risk_of_loss_time(base::Seconds(-1));

  // Send a PING frame.  This posts CheckPingStatus() with delay.
  MaybeSendPrefacePing();
  EXPECT_TRUE(ping_in_flight());
  EXPECT_EQ(2u, next_ping_id());
  EXPECT_TRUE(check_ping_status_pending());

  // Assert session is not closed.
  EXPECT_TRUE(session_->IsAvailable());
  EXPECT_LT(0u, num_active_streams() + num_created_streams());
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Run CheckPingStatus() and make it believe hung_interval has passed.
  g_time_delta = base::Seconds(15);
  FastForwardUntilNoTasksRemain();
  base::RunLoop().RunUntilIdle();

  // Since no response to PING has been received,
  // CheckPingStatus() closes the connection.
  EXPECT_TRUE(MainThreadIsIdle());
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);
  EXPECT_FALSE(spdy_stream1);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Regression test for https://crbug.com/784975.
TEST_F(SpdySessionTestWithMockTime, NoPingSentWhenCheckPingPending) {
  session_deps_.enable_ping = true;
  session_deps_.time_func = TheNearFuture;

  spdy::SpdySerializedFrame read_ping(spdy_util_.ConstructSpdyPing(1, true));
  MockRead reads[] = {CreateMockRead(read_ping, 1),
                      MockRead(ASYNC, ERR_IO_PENDING, 2),
                      MockRead(ASYNC, 0, 3)};

  spdy::SpdySerializedFrame write_ping0(spdy_util_.ConstructSpdyPing(1, false));
  MockWrite writes[] = {CreateMockWrite(write_ping0, 0)};

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  // Negative value means a preface ping will always be sent.
  set_connection_at_risk_of_loss_time(base::Seconds(-1));

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  test::StreamDelegateSendImmediate delegate(spdy_stream1, "");
  spdy_stream1->SetDelegate(&delegate);

  EXPECT_FALSE(ping_in_flight());
  EXPECT_EQ(1u, next_ping_id());
  EXPECT_FALSE(check_ping_status_pending());

  // Send preface ping and post CheckPingStatus() task with delay.
  MaybeSendPrefacePing();

  EXPECT_TRUE(ping_in_flight());
  EXPECT_EQ(2u, next_ping_id());
  EXPECT_TRUE(check_ping_status_pending());

  // Read PING ACK.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(ping_in_flight());
  EXPECT_TRUE(check_ping_status_pending());

  // Fast forward mock time so that normally another ping would be sent out.
  // However, since CheckPingStatus() is still pending, no new ping is sent.
  g_time_delta = base::Seconds(15);
  MaybeSendPrefacePing();

  EXPECT_FALSE(ping_in_flight());
  EXPECT_EQ(2u, next_ping_id());
  EXPECT_TRUE(check_ping_status_pending());

  // Run CheckPingStatus().
  FastForwardUntilNoTasksRemain();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(check_ping_status_pending());

  // Read EOF.
  data.Resume();
  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  // Finish going away.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Request kInitialMaxConcurrentStreams + 1 streams.  Receive a
// settings frame increasing the max concurrent streams by 1.  Make
// sure nothing blows up. This is a regression test for
// http://crbug.com/57331 .
TEST_F(SpdySessionTest, OnSettings) {
  const spdy::SpdySettingsId kSpdySettingsId =
      spdy::SETTINGS_MAX_CONCURRENT_STREAMS;

  spdy::SettingsMap new_settings;
  const uint32_t max_concurrent_streams = kInitialMaxConcurrentStreams + 1;
  new_settings[kSpdySettingsId] = max_concurrent_streams;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(new_settings));
  MockRead reads[] = {
      CreateMockRead(settings_frame, 0), MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 0, 3),
  };

  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  MockWrite writes[] = {CreateMockWrite(settings_ack, 1)};

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  // Create the maximum number of concurrent streams.
  for (size_t i = 0; i < kInitialMaxConcurrentStreams; ++i) {
    base::WeakPtr<SpdyStream> spdy_stream =
        CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, MEDIUM, NetLogWithSource());
    ASSERT_TRUE(spdy_stream);
  }

  StreamReleaserCallback stream_releaser;
  SpdyStreamRequest request;
  ASSERT_EQ(ERR_IO_PENDING,
            request.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                 false, MEDIUM, SocketTag(), NetLogWithSource(),
                                 stream_releaser.MakeCallback(&request),
                                 TRAFFIC_ANNOTATION_FOR_TESTS));

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(stream_releaser.WaitForResult(), IsOk());

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Create one more stream than maximum number of concurrent streams,
// so that one of them is pending.  Cancel one stream, which should trigger the
// creation of the pending stream.  Then cancel that one immediately as well,
// and make sure this does not lead to a crash.
// This is a regression test for https://crbug.com/63532.
TEST_F(SpdySessionTest, CancelPendingCreateStream) {
  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  // Leave room for only one more stream to be created.
  for (size_t i = 0; i < kInitialMaxConcurrentStreams - 1; ++i) {
    base::WeakPtr<SpdyStream> spdy_stream =
        CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, MEDIUM, NetLogWithSource());
    ASSERT_TRUE(spdy_stream);
  }

  // Create 2 more streams.  First will succeed.  Second will be pending.
  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);

  // Use unique_ptr to let us invalidate the memory when we want to, to trigger
  // an error in memory corruption detectors if the callback is invoked when
  // it's not supposed to be.
  auto callback = std::make_unique<TestCompletionCallback>();

  SpdyStreamRequest request;
  ASSERT_THAT(
      request.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                           false, MEDIUM, SocketTag(), NetLogWithSource(),
                           callback->callback(), TRAFFIC_ANNOTAT
"""


```
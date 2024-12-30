Response:
My thinking process for analyzing the provided code snippet and generating the summary involved the following steps:

1. **Understand the Context:** The prompt clearly states this is part of a larger unit test file (`spdy_session_unittest.cc`) for the Chromium network stack, specifically the SPDY (and likely HTTP/2) session implementation. The "part 3 of 8" indicates a logical division within the test suite.

2. **Identify Key Classes and Concepts:**  I recognized several important classes and concepts immediately:
    * `SpdySessionTest`: The main fixture class, inheriting from `testing::Test`. This signals a standard C++ unit testing setup.
    * `SpdySession`: The core class being tested.
    * `SpdyStream`: Represents an individual HTTP/2 (or SPDY) stream within a session.
    * `SpdyStreamRequest`:  A mechanism to request the creation of a new stream.
    * `MockRead`, `MockWrite`, `StaticSocketDataProvider`, `SequencedSocketData`:  These are mocking tools for simulating network socket behavior without actually making network calls. This is essential for unit testing.
    * `TestCompletionCallback`:  A helper class for asynchronous operation testing.
    * `NetLog`, `NetLogWithSource`:  Chromium's logging system for network events.
    * `base::RunLoop`:  A mechanism for running asynchronous tasks in a controlled way within the tests.
    * `base::WeakPtr`: Used to avoid dangling pointers, especially important in asynchronous scenarios.
    * `quiche::HttpHeaderBlock`: Represents HTTP headers.
    * `spdy::SpdySerializedFrame`: Represents a raw SPDY/HTTP/2 frame.
    * `spdy_util_`:  A utility class for constructing SPDY frames.
    * `HIGHEST`, `MEDIUM`, `LOWEST`:  Constants representing stream priorities.
    * `ERR_IO_PENDING`, `ERR_ABORTED`, `OK`, `ERR_CONNECTION_CLOSED`, `ERR_HTTP2_PROTOCOL_ERROR`:  Network error codes.
    * `TRAFFIC_ANNOTATION_FOR_TESTS`:  Indicates network traffic annotations are being used, a security/privacy feature in Chromium.

3. **Analyze Individual Test Cases:** I went through each `TEST_F` function, focusing on what each test is trying to achieve:
    * **`PendingStreamCreationMax`:** Tests the limit on the number of pending stream creation requests. It checks that attempting to create more streams than allowed results in an error.
    * **`ChangeStreamRequestPriority`:** Verifies the ability to change the priority of a pending stream creation request. It confirms the request is moved to the correct priority queue.
    * **`Initialize`:** Checks the basic initialization of a `SpdySession`, specifically looking for the `HTTP2_SESSION_INITIALIZED` log event.
    * **`NetLogOnSessionGoaway`:** Tests the logging of `GOAWAY` frames, which signal the session is closing. It verifies specific log events and parameters.
    * **`NetLogOnSessionEOF`:** Tests the logging of session closure due to an EOF (end-of-file) on the socket.
    * **`HeadersCompressionHistograms`:**  Measures the compression ratio of HTTP headers and records it in a histogram.
    * **`OutOfOrderHeaders`:** Verifies that streams are processed based on priority, even if the requests are sent in a different order.
    * **`CancelStream`:** Tests the ability to cancel a stream before it's fully established.
    * **`CloseSessionWithTwoCreatedSelfClosingStreams`:** Checks that closing the session with pending streams that are designed to close themselves doesn't lead to crashes.
    * **`CloseSessionWithTwoCreatedMutuallyClosingStreams`:**  Similar to the above, but the pending streams are designed to close each other.
    * **`CloseSessionWithTwoActivatedSelfClosingStreams`:** Tests session closure with *active* streams that close themselves.
    * **`CloseSessionWithTwoActivatedMutuallyClosingStreams`:** Tests session closure with *active* streams that close each other.
    * **`CloseActivatedStreamThatClosesSession`:** Checks that closing an active stream which, in turn, closes the session, doesn't crash.
    * **`VerifyDomainAuthentication`:** Tests a method to verify if a given domain is authorized for the current session.
    * **`CloseTwoStalledCreateStream`:**  Tests a scenario where multiple stream creations are stalled due to concurrency limits, and ensures correct handling when they are eventually allowed to proceed.
    * **`CancelTwoStalledCreateStream`:** Tests canceling stream creation requests when the session has reached its concurrency limit.

4. **Identify Common Themes:**  As I analyzed the individual tests, I noticed several recurring themes:
    * **Asynchronous Operations:** Many tests involve `ERR_IO_PENDING` and `base::RunLoop`, indicating the asynchronous nature of network operations and the need to manage these operations in the tests.
    * **Stream Prioritization:** Several tests explicitly deal with setting and verifying stream priorities.
    * **Session and Stream Lifecycle:**  Tests cover the creation, activation, cancellation, and closure of both sessions and streams.
    * **Error Handling:** Tests check how the session handles various error conditions (e.g., `ERR_ABORTED`, `GOAWAY` frames).
    * **NetLog Integration:**  Several tests verify that appropriate events are logged to the NetLog.
    * **Concurrency Limits:** Tests explore the behavior of the session when the maximum number of concurrent streams is reached.

5. **Synthesize the Functionality:** Based on the individual tests and the recurring themes, I formulated the main functionalities of this code snippet: testing the core behaviors of `SpdySession`, including stream creation, prioritization, cancellation, session closure, error handling, and logging.

6. **Address Specific Prompt Points:**  I then went back to the prompt and specifically addressed each of the questions:
    * **Functionality:**  Summarized the core testing areas.
    * **Relationship to JavaScript:**  Acknowledged the indirect relationship via the network stack being used by web browsers, but pointed out no direct JavaScript interaction in the *unit test* code itself.
    * **Logical Reasoning (Hypothetical Input/Output):** Provided a simple example of the priority change test to illustrate the concept.
    * **User/Programming Errors:** Gave examples of common mistakes in using the `SpdyStreamRequest` class.
    * **User Operation to Reach This Code:** Described a simplified browser interaction leading to network requests.
    * **Summary of Part 3:** Focused on the core areas covered in this specific section of the tests.

7. **Refine and Organize:**  Finally, I organized the information logically, using clear headings and bullet points to make it easy to read and understand. I ensured that the language was precise and avoided jargon where possible, while still being technically accurate.
这是 `net/spdy/spdy_session_unittest.cc` 文件的第三部分，它主要包含了针对 `SpdySession` 类的各种单元测试。`SpdySession` 是 Chromium 网络栈中用于处理 SPDY 和 HTTP/2 会话的核心类。

**本部分的功能归纳如下：**

这部分测试主要集中在以下 `SpdySession` 的功能点：

* **限制并发创建流的请求数量 (Pending Stream Creation Limits):** 测试了当请求创建的流的数量超过允许的最大并发数时，`SpdySession` 的行为，包括请求会被挂起以及取消请求的情况。
* **更改流请求的优先级 (Change Stream Request Priority):** 测试了在流创建请求被挂起时，更改其优先级的功能是否正常工作，以及优先级变更是否会影响请求在队列中的顺序。
* **会话初始化时的 NetLog 记录 (Initialize):** 验证了 `SpdySession` 初始化时是否正确地记录了相应的 NetLog 事件。
* **接收 GOAWAY 帧时的 NetLog 记录 (NetLogOnSessionGoaway):** 测试了当 `SpdySession` 接收到 `GOAWAY` 帧时，是否正确记录了相关的 NetLog 事件，包括错误码和调试信息。
* **会话因 EOF 关闭时的 NetLog 记录 (NetLogOnSessionEOF):** 验证了当连接因接收到 EOF 而关闭时，`SpdySession` 是否正确记录了关闭事件，并包含了相应的错误码。
* **头部压缩的直方图记录 (HeadersCompressionHistograms):** 测试了发送请求头部时，头部压缩率是否被正确记录到直方图中。
* **乱序的头部发送 (OutOfOrderHeaders):** 验证了当低优先级的头部请求先于高优先级的请求发送时，`SpdySession` 是否仍然按照优先级顺序处理请求和响应。
* **取消流 (CancelStream):** 测试了在流发送数据之前取消流的功能是否正常工作。
* **关闭包含自关闭或互相关闭流的会话 (Close Session with Self/Mutually Closing Streams):**  这些测试用例旨在验证在会话关闭时，如果存在一些特殊的流（例如，流关闭时会触发会话关闭，或者多个流关闭时会互相触发），`SpdySession` 是否能安全地处理这些情况，避免崩溃。
* **关闭触发会话关闭的激活流 (Close Activated Stream That Closes Session):** 测试了关闭一个已激活的流，而该流的关闭操作会触发整个会话的关闭，`SpdySession` 能否正确处理。
* **验证域名认证 (VerifyDomainAuthentication):** 测试了 `SpdySession` 的域名认证功能，用于判断给定的域名是否被允许在该会话中进行通信。
* **关闭两个挂起的创建流 (Close Two Stalled Create Stream):** 测试了在高并发限制下，当两个流创建请求被挂起时，随着之前活跃的流关闭，这两个挂起的请求是否能被正确处理和激活。
* **取消两个挂起的创建流 (Cancel Two Stalled Create Stream):** 测试了在高并发限制下，当两个流创建请求被挂起时，取消这些请求的功能是否正常。

**与 JavaScript 功能的关系 (间接关系):**

`SpdySession` 本身是用 C++ 实现的，与 JavaScript 没有直接的编程接口或语法上的关系。然而，它的功能对于支持 Web 浏览器的网络请求至关重要。当 JavaScript 代码（运行在浏览器中）发起一个网络请求到支持 HTTP/2 的服务器时，Chromium 的网络栈会使用 `SpdySession` 来处理底层的 HTTP/2 通信。

**举例说明:**

假设一个用户在浏览器中访问一个网页，网页需要加载多个资源（图片、CSS、JavaScript 文件）。如果服务器支持 HTTP/2，浏览器会尝试与服务器建立一个 HTTP/2 连接，这个连接就由 `SpdySession` 对象来管理。

* **流的创建和优先级:**  当浏览器解析网页并发现需要加载多个资源时，它可能会为每个资源创建一个 HTTP/2 流。浏览器可以根据资源的类型（例如，优先加载 CSS 以更快渲染页面）为这些流设置不同的优先级。`SpdySessionTest::ChangeStreamRequestPriority` 测试的就是这种优先级管理机制。
* **并发限制:** 浏览器在建立 HTTP/2 连接后，会受到服务器通告的最大并发流数的限制。如果网页需要加载的资源超过了这个限制，额外的请求会被放入队列等待。`SpdySessionTest::PendingStreamCreationMax` 测试了这种并发控制机制。
* **会话关闭:**  当用户关闭网页或网络连接中断时，`SpdySession` 会被关闭。`SpdySessionTest::NetLogOnSessionGoaway` 和 `SpdySessionTest::NetLogOnSessionEOF` 测试了不同场景下会话关闭时的日志记录。

**逻辑推理的假设输入与输出:**

以 `SpdySessionTest::ChangeStreamRequestPriority` 为例：

**假设输入:**

1. `SpdySession` 的最大并发流数设置为 1。
2. 创建第一个流请求 (request1)，优先级为 `LOWEST`。
3. 创建第二个流请求 (request2)，优先级也为 `LOWEST`。由于最大并发数限制，request2 会被挂起。
4. 将 request1 的优先级更改为 `HIGHEST`。
5. 将 request2 的优先级更改为 `MEDIUM`。

**预期输出:**

1. request1 成功创建流，因为会话还有空闲的流 ID。
2. request2 仍然处于挂起状态，但其在挂起队列中的优先级已更新为 `MEDIUM`。后续当有空闲流时，优先级为 `MEDIUM` 的请求会比优先级为 `LOWEST` 的请求更早被处理。

**用户或编程常见的使用错误:**

* **忘记处理 `ERR_IO_PENDING`:**  在异步操作中，例如 `SpdyStreamRequest::StartRequest` 返回 `ERR_IO_PENDING` 时，必须等待回调通知操作完成。如果程序直接认为请求失败或尝试访问未创建的流对象，会导致错误。
    ```c++
    TestCompletionCallback callback;
    SpdyStreamRequest request;
    int rv = request.StartRequest(..., callback.callback());
    if (rv == OK) {
      // 错误：如果 rv 是 ERR_IO_PENDING，流可能还未创建完成
      base::WeakPtr<SpdyStream> stream = request.ReleaseStream();
      // ... 使用 stream ...
    } else if (rv != ERR_IO_PENDING) {
      // 处理错误
    }
    ```
* **在回调未执行前释放 `SpdyStreamRequest` 对象:**  `SpdyStreamRequest` 对象负责管理流的创建过程。如果在回调执行之前就释放了 `SpdyStreamRequest`，可能会导致程序崩溃或资源泄漏。
    ```c++
    {
      TestCompletionCallback callback;
      SpdyStreamRequest request;
      request.StartRequest(..., callback.callback());
      // 错误：在回调执行前 request 对象就离开了作用域
    }
    // ... 回调执行 ... (可能访问已释放的 request 对象)
    ```
* **在高并发场景下，没有正确处理流创建的挂起和恢复:** 当达到最大并发数限制时，新的流创建请求会返回 `ERR_IO_PENDING`。开发者需要理解这种机制，并在之前的流完成后，通过事件通知或轮询等方式来处理挂起的请求。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:** 这会触发浏览器发起网络请求。
2. **浏览器解析 URL 并查找对应的服务器 IP 地址:**  DNS 查询等操作会发生。
3. **浏览器与服务器建立 TCP 连接:**  进行三次握手。
4. **浏览器与服务器进行 TLS 握手 (如果使用 HTTPS):**  协商加密参数，验证服务器证书。
5. **浏览器和服务器协商使用 HTTP/2 协议:**  通过 ALPN 或其他机制。
6. **Chromium 网络栈创建 `SpdySession` 对象:**  用于管理与该服务器的 HTTP/2 会话。
7. **JavaScript 代码通过 Fetch API 或 XMLHttpRequest 发起资源请求:**  这些请求会转化为 HTTP/2 流。
8. **`SpdySession` 处理这些流的创建、发送数据、接收数据、优先级管理等操作:**  `spdy_session_unittest.cc` 中测试的各种场景就在这个阶段发生。例如，当发起多个请求时，可能会触发并发限制的逻辑；设置请求头时，会涉及到头部压缩；服务器发送 `GOAWAY` 帧时，会触发会话关闭的流程。

**总结第 3 部分的功能:**

这部分单元测试主要关注 `SpdySession` 在管理流的创建和优先级、处理会话生命周期事件（初始化、关闭）、记录 NetLog 信息以及在高并发场景下的行为。它涵盖了从请求创建到会话终止的多个关键方面，并验证了 `SpdySession` 在各种复杂情况下的正确性和健壮性。

Prompt: 
```
这是目录为net/spdy/spdy_session_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共8部分，请归纳一下它的功能

"""
ION_FOR_TESTS),
      IsError(ERR_IO_PENDING));

  // Release the first one, this will allow the second to be created.
  spdy_stream1->Cancel(ERR_ABORTED);
  EXPECT_FALSE(spdy_stream1);

  request.CancelRequest();
  callback.reset();

  // Should not crash when running the pending callback.
  base::RunLoop().RunUntilIdle();
}

TEST_F(SpdySessionTest, ChangeStreamRequestPriority) {
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  set_max_concurrent_streams(1);

  TestCompletionCallback callback1;
  SpdyStreamRequest request1;
  ASSERT_EQ(OK, request1.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                      test_url_, false, LOWEST, SocketTag(),
                                      NetLogWithSource(), callback1.callback(),
                                      TRAFFIC_ANNOTATION_FOR_TESTS));
  TestCompletionCallback callback2;
  SpdyStreamRequest request2;
  ASSERT_EQ(ERR_IO_PENDING,
            request2.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                  test_url_, false, LOWEST, SocketTag(),
                                  NetLogWithSource(), callback2.callback(),
                                  TRAFFIC_ANNOTATION_FOR_TESTS));

  request1.SetPriority(HIGHEST);
  request2.SetPriority(MEDIUM);

  ASSERT_EQ(0u, pending_create_stream_queue_size(HIGHEST));
  // Priority of queued request is changed.
  ASSERT_EQ(1u, pending_create_stream_queue_size(MEDIUM));
  ASSERT_EQ(0u, pending_create_stream_queue_size(LOWEST));

  base::WeakPtr<SpdyStream> stream1 = request1.ReleaseStream();
  // Priority of stream is updated if request has been fulfilled.
  ASSERT_EQ(HIGHEST, stream1->priority());
}

// Attempts to extract a NetLogSource from a set of event parameters.  Returns
// true and writes the result to |source| on success.  Returns false and
// makes |source| an invalid source on failure.
bool NetLogSourceFromEventParameters(const base::Value::Dict* event_params,
                                     NetLogSource* source) {
  const base::Value::Dict* source_dict = nullptr;
  int source_id = -1;
  int source_type = static_cast<int>(NetLogSourceType::COUNT);
  if (!event_params) {
    *source = NetLogSource();
    return false;
  }
  source_dict = event_params->FindDict("source_dependency");
  if (!source_dict) {
    *source = NetLogSource();
    return false;
  }
  std::optional<int> opt_int;
  opt_int = source_dict->FindInt("id");
  if (!opt_int) {
    *source = NetLogSource();
    return false;
  }
  source_id = opt_int.value();
  opt_int = source_dict->FindInt("type");
  if (!opt_int) {
    *source = NetLogSource();
    return false;
  }
  source_type = opt_int.value();

  DCHECK_GE(source_id, 0);
  DCHECK_LT(source_type, static_cast<int>(NetLogSourceType::COUNT));
  *source = NetLogSource(static_cast<NetLogSourceType>(source_type), source_id);
  return true;
}

TEST_F(SpdySessionTest, Initialize) {
  MockRead reads[] = {
    MockRead(ASYNC, 0, 0)  // EOF
  };

  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Flush the read completion task.
  base::RunLoop().RunUntilIdle();

  auto entries = net_log_observer_.GetEntries();
  EXPECT_LT(0u, entries.size());

  // Check that we logged HTTP2_SESSION_INITIALIZED correctly.
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_SESSION_INITIALIZED,
      NetLogEventPhase::NONE);
  EXPECT_LT(0, pos);

  NetLogSource socket_source;
  EXPECT_TRUE(
      NetLogSourceFromEventParameters(&entries[pos].params, &socket_source));
  EXPECT_TRUE(socket_source.IsValid());
  EXPECT_NE(net_log_with_source_.source().id, socket_source.id);
}

TEST_F(SpdySessionTest, NetLogOnSessionGoaway) {
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      42, spdy::ERROR_CODE_ENHANCE_YOUR_CALM, "foo"));
  MockRead reads[] = {
      CreateMockRead(goaway), MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };

  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Flush the read completion task.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);

  // Check that the NetLog was filled reasonably.
  auto entries = net_log_observer_.GetEntries();
  EXPECT_LT(0u, entries.size());

  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_SESSION_RECV_GOAWAY,
      NetLogEventPhase::NONE);
  ASSERT_EQ(0, GetIntegerValueFromParams(entries[pos], "active_streams"));
  ASSERT_EQ("11 (ENHANCE_YOUR_CALM)",
            GetStringValueFromParams(entries[pos], "error_code"));
  ASSERT_EQ("foo", GetStringValueFromParams(entries[pos], "debug_data"));

  // Check that we logged SPDY_SESSION_CLOSE correctly.
  pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_SESSION_CLOSE, NetLogEventPhase::NONE);
  EXPECT_THAT(GetNetErrorCodeFromParams(entries[pos]), IsOk());
}

TEST_F(SpdySessionTest, NetLogOnSessionEOF) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };

  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Flush the read completion task.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);

  // Check that the NetLog was filled reasonably.
  auto entries = net_log_observer_.GetEntries();
  EXPECT_LT(0u, entries.size());

  // Check that we logged SPDY_SESSION_CLOSE correctly.
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_SESSION_CLOSE, NetLogEventPhase::NONE);

  if (pos < static_cast<int>(entries.size())) {
    ASSERT_THAT(GetNetErrorCodeFromParams(entries[pos]),
                IsError(ERR_CONNECTION_CLOSED));
  } else {
    ADD_FAILURE();
  }
}

TEST_F(SpdySessionTest, HeadersCompressionHistograms) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), MockRead(ASYNC, 0, 2)  // EOF
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

  // Write request headers & capture resulting histogram update.
  base::HistogramTester histogram_tester;

  base::RunLoop().RunUntilIdle();
  // Regression test of compression performance under the request fixture.
  histogram_tester.ExpectBucketCount("Net.SpdyHeadersCompressionPercentage", 76,
                                     1);

  // Read and process EOF.
  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Queue up a low-priority HEADERS followed by a high-priority
// one. The high priority one should still send first and receive
// first.
TEST_F(SpdySessionTest, OutOfOrderHeaders) {
  // Construct the request.
  spdy::SpdySerializedFrame req_highest(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));
  spdy::SpdySerializedFrame req_lowest(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req_highest, 0), CreateMockWrite(req_lowest, 1),
  };

  spdy::SpdySerializedFrame resp_highest(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body_highest(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame resp_lowest(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body_lowest(
      spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads[] = {
      CreateMockRead(resp_highest, 2), CreateMockRead(body_highest, 3),
      CreateMockRead(resp_lowest, 4), CreateMockRead(body_lowest, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream_lowest =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream_lowest);
  EXPECT_EQ(0u, spdy_stream_lowest->stream_id());
  test::StreamDelegateDoNothing delegate_lowest(spdy_stream_lowest);
  spdy_stream_lowest->SetDelegate(&delegate_lowest);

  base::WeakPtr<SpdyStream> spdy_stream_highest =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, HIGHEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream_highest);
  EXPECT_EQ(0u, spdy_stream_highest->stream_id());
  test::StreamDelegateDoNothing delegate_highest(spdy_stream_highest);
  spdy_stream_highest->SetDelegate(&delegate_highest);

  // Queue the lower priority one first.

  quiche::HttpHeaderBlock headers_lowest(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream_lowest->SendRequestHeaders(std::move(headers_lowest),
                                         NO_MORE_DATA_TO_SEND);

  quiche::HttpHeaderBlock headers_highest(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream_highest->SendRequestHeaders(std::move(headers_highest),
                                          NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(spdy_stream_lowest);
  EXPECT_FALSE(spdy_stream_highest);
  EXPECT_EQ(3u, delegate_lowest.stream_id());
  EXPECT_EQ(1u, delegate_highest.stream_id());
}

TEST_F(SpdySessionTest, CancelStream) {
  // Request 1, at HIGHEST priority, will be cancelled before it writes data.
  // Request 2, at LOWEST priority, will be a full request and will be id 1.
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req2, 0),
  };

  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp2, 1), MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(body2, 3), MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, HIGHEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());
  test::StreamDelegateDoNothing delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  EXPECT_EQ(0u, spdy_stream1->stream_id());

  spdy_stream1->Cancel(ERR_ABORTED);
  EXPECT_FALSE(spdy_stream1);

  EXPECT_EQ(0u, delegate1.stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0u, delegate1.stream_id());
  EXPECT_EQ(1u, delegate2.stream_id());

  spdy_stream2->Cancel(ERR_ABORTED);
  EXPECT_FALSE(spdy_stream2);
}

// Create two streams that are set to re-close themselves on close,
// and then close the session. Nothing should blow up. Also a
// regression test for http://crbug.com/139518 .
TEST_F(SpdySessionTest, CloseSessionWithTwoCreatedSelfClosingStreams) {
  // No actual data will be sent.
  MockWrite writes[] = {
    MockWrite(ASYNC, 0, 1)  // EOF
  };

  MockRead reads[] = {
    MockRead(ASYNC, 0, 0)  // EOF
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                HIGHEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  test::ClosingDelegate delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  test::ClosingDelegate delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Ensure that the streams have not yet been activated and assigned an id.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Ensure we don't crash while closing the session.
  session_->CloseSessionOnError(ERR_ABORTED, std::string());

  EXPECT_FALSE(spdy_stream1);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(delegate1.StreamIsClosed());
  EXPECT_TRUE(delegate2.StreamIsClosed());

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Create two streams that are set to close each other on close, and
// then close the session. Nothing should blow up.
TEST_F(SpdySessionTest, CloseSessionWithTwoCreatedMutuallyClosingStreams) {
  SequencedSocketData data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                HIGHEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Make |spdy_stream1| close |spdy_stream2|.
  test::ClosingDelegate delegate1(spdy_stream2);
  spdy_stream1->SetDelegate(&delegate1);

  // Make |spdy_stream2| close |spdy_stream1|.
  test::ClosingDelegate delegate2(spdy_stream1);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Ensure that the streams have not yet been activated and assigned an id.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Ensure we don't crash while closing the session.
  session_->CloseSessionOnError(ERR_ABORTED, std::string());

  EXPECT_FALSE(spdy_stream1);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(delegate1.StreamIsClosed());
  EXPECT_TRUE(delegate2.StreamIsClosed());

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Create two streams that are set to re-close themselves on close,
// activate them, and then close the session. Nothing should blow up.
TEST_F(SpdySessionTest, CloseSessionWithTwoActivatedSelfClosingStreams) {
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  test::ClosingDelegate delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  test::ClosingDelegate delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Ensure that the streams have not yet been activated and assigned an id.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  // Ensure we don't crash while closing the session.
  session_->CloseSessionOnError(ERR_ABORTED, std::string());

  EXPECT_FALSE(spdy_stream1);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(delegate1.StreamIsClosed());
  EXPECT_TRUE(delegate2.StreamIsClosed());

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Create two streams that are set to close each other on close,
// activate them, and then close the session. Nothing should blow up.
TEST_F(SpdySessionTest, CloseSessionWithTwoActivatedMutuallyClosingStreams) {
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Make |spdy_stream1| close |spdy_stream2|.
  test::ClosingDelegate delegate1(spdy_stream2);
  spdy_stream1->SetDelegate(&delegate1);

  // Make |spdy_stream2| close |spdy_stream1|.
  test::ClosingDelegate delegate2(spdy_stream1);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Ensure that the streams have not yet been activated and assigned an id.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  // Ensure we don't crash while closing the session.
  session_->CloseSessionOnError(ERR_ABORTED, std::string());

  EXPECT_FALSE(spdy_stream1);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(delegate1.StreamIsClosed());
  EXPECT_TRUE(delegate2.StreamIsClosed());

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Delegate that closes a given session when the stream is closed.
class SessionClosingDelegate : public test::StreamDelegateDoNothing {
 public:
  SessionClosingDelegate(const base::WeakPtr<SpdyStream>& stream,
                         const base::WeakPtr<SpdySession>& session_to_close)
      : StreamDelegateDoNothing(stream),
        session_to_close_(session_to_close) {}

  ~SessionClosingDelegate() override = default;

  void OnClose(int status) override {
    session_to_close_->CloseSessionOnError(ERR_HTTP2_PROTOCOL_ERROR, "Error");
  }

 private:
  base::WeakPtr<SpdySession> session_to_close_;
};

// Close an activated stream that closes its session. Nothing should
// blow up. This is a regression test for https://crbug.com/263691.
TEST_F(SpdySessionTest, CloseActivatedStreamThatClosesSession) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_PROTOCOL_ERROR, "Error"));
  // The GOAWAY has higher-priority than the RST_STREAM, and is written first
  // despite being queued second.
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(goaway, 1),
      CreateMockWrite(rst, 3),
  };

  MockRead reads[] = {
      MockRead(ASYNC, 0, 2)  // EOF
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream);
  EXPECT_EQ(0u, spdy_stream->stream_id());

  SessionClosingDelegate delegate(spdy_stream, session_);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  EXPECT_EQ(0u, spdy_stream->stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  // Ensure we don't crash while closing the stream (which closes the
  // session).
  spdy_stream->Cancel(ERR_ABORTED);

  EXPECT_FALSE(spdy_stream);
  EXPECT_TRUE(delegate.StreamIsClosed());

  // Write the RST_STREAM & GOAWAY.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdySessionTest, VerifyDomainAuthentication) {
  SequencedSocketData data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_TRUE(session_->VerifyDomainAuthentication("www.example.org"));
  EXPECT_TRUE(session_->VerifyDomainAuthentication("mail.example.org"));
  EXPECT_TRUE(session_->VerifyDomainAuthentication("mail.example.com"));
  EXPECT_FALSE(session_->VerifyDomainAuthentication("mail.google.com"));
}

TEST_F(SpdySessionTest, CloseTwoStalledCreateStream) {
  // TODO(rtenneti): Define a helper class/methods and move the common code in
  // this file.
  spdy::SettingsMap new_settings;
  const spdy::SpdySettingsId kSpdySettingsId1 =
      spdy::SETTINGS_MAX_CONCURRENT_STREAMS;
  const uint32_t max_concurrent_streams = 1;
  new_settings[kSpdySettingsId1] = max_concurrent_streams;

  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(3);
  spdy::SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(settings_ack, 1), CreateMockWrite(req1, 2),
      CreateMockWrite(req2, 5), CreateMockWrite(req3, 8),
  };

  // Set up the socket so we read a SETTINGS frame that sets max concurrent
  // streams to 1.
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(new_settings));

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));

  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));

  spdy::SpdySerializedFrame resp3(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 5));
  spdy::SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(5, true));

  MockRead reads[] = {
      CreateMockRead(settings_frame, 0),
      CreateMockRead(resp1, 3),
      CreateMockRead(body1, 4),
      CreateMockRead(resp2, 6),
      CreateMockRead(body2, 7),
      CreateMockRead(resp3, 9),
      CreateMockRead(body3, 10),
      MockRead(ASYNC, ERR_IO_PENDING, 11),
      MockRead(ASYNC, 0, 12)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  // Read the settings frame.
  base::RunLoop().RunUntilIdle();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  TestCompletionCallback callback2;
  SpdyStreamRequest request2;
  ASSERT_EQ(ERR_IO_PENDING,
            request2.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                  test_url_, false, LOWEST, SocketTag(),
                                  NetLogWithSource(), callback2.callback(),
                                  TRAFFIC_ANNOTATION_FOR_TESTS));

  TestCompletionCallback callback3;
  SpdyStreamRequest request3;
  ASSERT_EQ(ERR_IO_PENDING,
            request3.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                  test_url_, false, LOWEST, SocketTag(),
                                  NetLogWithSource(), callback3.callback(),
                                  TRAFFIC_ANNOTATION_FOR_TESTS));

  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(1u, num_created_streams());
  EXPECT_EQ(2u, pending_create_stream_queue_size(LOWEST));

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Run until 1st stream is activated and then closed.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);
  EXPECT_EQ(1u, delegate1.stream_id());

  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(1u, pending_create_stream_queue_size(LOWEST));

  // Pump loop for SpdySession::ProcessPendingStreamRequests() to
  // create the 2nd stream.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(1u, num_created_streams());
  EXPECT_EQ(1u, pending_create_stream_queue_size(LOWEST));

  base::WeakPtr<SpdyStream> stream2 = request2.ReleaseStream();
  test::StreamDelegateDoNothing delegate2(stream2);
  stream2->SetDelegate(&delegate2);
  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Run until 2nd stream is activated and then closed.
  EXPECT_EQ(0u, delegate2.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(stream2);
  EXPECT_EQ(3u, delegate2.stream_id());

  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(0u, pending_create_stream_queue_size(LOWEST));

  // Pump loop for SpdySession::ProcessPendingStreamRequests() to
  // create the 3rd stream.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(1u, num_created_streams());
  EXPECT_EQ(0u, pending_create_stream_queue_size(LOWEST));

  base::WeakPtr<SpdyStream> stream3 = request3.ReleaseStream();
  test::StreamDelegateDoNothing delegate3(stream3);
  stream3->SetDelegate(&delegate3);
  quiche::HttpHeaderBlock headers3(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  stream3->SendRequestHeaders(std::move(headers3), NO_MORE_DATA_TO_SEND);

  // Run until 2nd stream is activated and then closed.
  EXPECT_EQ(0u, delegate3.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(stream3);
  EXPECT_EQ(5u, delegate3.stream_id());

  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(0u, num_created_streams());
  EXPECT_EQ(0u, pending_create_stream_queue_size(LOWEST));

  data.Resume();
  base::RunLoop().RunUntilIdle();
}

TEST_F(SpdySessionTest, CancelTwoStalledCreateStream) {
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

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  TestCompletionCallback callback2;
  SpdyStreamRequest request2;
  ASSERT_EQ(ERR_IO_PENDING,
            request2.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, false, LOWEST, SocketTag(),
                                  NetLogWithSource(), callback2.callback(),
                                  TRAFFIC_ANNOTATION_FOR_TESTS));

  TestCompletionCallback callback3;
  SpdyStreamRequest request3;
  ASSERT_EQ(ERR_IO_PENDING,
            request3.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, false, LOWEST, SocketTag(),
                     
"""


```
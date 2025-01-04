Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/spdy/spdy_session_unittest.cc`. I need to analyze the code and identify its purpose. Since it's a unit test file, its primary function is to test the `SpdySession` class.

Here's a breakdown of what the code does:

1. **Test Scenarios:**  Each `TEST_F` function represents a specific test scenario for the `SpdySession`.
2. **Mocking and Setup:**  The tests use mocking (`MockWrite`, `MockRead`, `SequencedSocketData`, `StaticSocketDataProvider`) to simulate network interactions and control the behavior of the underlying socket.
3. **Session and Stream Creation:**  Tests create `SpdySession` objects and `SpdyStream` objects.
4. **Sending and Receiving Data:**  Tests simulate sending request headers and receiving response headers and data frames.
5. **Verifying Behavior:**  Tests use `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT` to assert the expected state of the `SpdySession` and related objects after certain actions.
6. **Focus Areas:** The tests cover various aspects of `SpdySession` functionality, including:
    - Stream creation and cancellation.
    - Reading data from the socket (with and without yielding).
    - Handling `GOAWAY` frames.
    - Protocol negotiation.
    - Closing idle sessions.
    - The impact of privacy mode on session keys.
    - Creating new streams when existing streams are reset.

Regarding the user's specific requests:

* **Functionality:**  The main function is to unit test the `SpdySession` class in the Chromium network stack.
* **Relationship with JavaScript:**  While this C++ code doesn't directly execute JavaScript, the functionality it tests (SPDY/HTTP/2 session management) is crucial for how web browsers communicate with servers. JavaScript running in a browser relies on these underlying network mechanisms to fetch resources.
* **Logical Reasoning (Hypothetical Input/Output):**  I can analyze a specific test case and describe the input (mocked network data) and expected output (state of the session and streams).
* **Common Usage Errors:** I can infer potential errors based on the tests (e.g., not handling stream cancellation correctly, issues with concurrent stream limits).
* **User Operations as Debugging Clues:** I can explain how certain user actions (like opening multiple tabs or downloading large files) might lead to the code being executed.
* **Summary of Functionality (Part 4):** I need to summarize the specific aspects of `SpdySession` being tested in this particular code snippet.

**Plan:**

1. Provide a high-level summary of the file's purpose.
2. Select a few representative test cases and explain their functionality with hypothetical input/output.
3. Discuss the connection to JavaScript.
4. Identify potential user errors based on the tests.
5. Explain how user actions might lead to this code being executed.
6. Summarize the functionality covered in this part of the file.
```cpp
// Delegate that creates another stream when its stream is closed.
class StreamCreatingDelegate : public test::StreamDelegateDoNothing {
 public:
  StreamCreatingDelegate(const base::WeakPtr<SpdyStream>& stream,
                         const base::WeakPtr<SpdySession>& session)
      : StreamDelegateDoNothing(stream),
        session_(session) {}

  ~StreamCreatingDelegate() override = default;

  void OnClose(int status) override {
    GURL url(kDefaultUrl);
    std::ignore =
        CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_, url,
                                  MEDIUM, NetLogWithSource());
  }

 private:
  const base::WeakPtr<SpdySession> session_;
};

// Create another stream in response to a stream being reset. Nothing
// should blow up. This is a regression test for
// http://crbug.com/263690 .
TEST_F(SpdySessionTest, CreateStreamOnStreamReset) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  spdy::SpdySerializedFrame rs
```

这是 `net/spdy/spdy_session_unittest.cc` 文件的**第 4 部分**，它延续了对 `SpdySession` 类的单元测试。

**此部分的功能归纳：**

这部分主要关注 `SpdySession` 在以下几种场景下的行为和健壮性：

* **流的创建和取消：** 测试在高并发创建流请求的情况下，如何取消部分流请求，以及这如何影响后续流的创建和会话状态。
* **数据读取和 Yielding (让步/暂停)：**  测试 `SpdySession` 的 `DoReadLoop` 方法如何从 socket 读取数据，并模拟了两种情况：
    * **不让步读取：**  当可以一次性读取足够多的数据时，`DoReadLoop` 是否能够高效地读取所有数据而不需要暂停并重新调度任务。
    * **让步读取：**  当读取耗时过长或者读取了大量数据时，`DoReadLoop` 是否会主动让步，避免阻塞事件循环。这包括了同步读取和异步读取的场景。
* **`GOAWAY` 帧的处理：** 测试当 `SpdySession` 正在读取数据时接收到 `GOAWAY` 帧会发生什么，确保程序不会崩溃。
* **协议协商和流量控制：** 验证 `SpdySession` 在不同协议版本下流量控制的初始化状态。
* **空闲连接的关闭：** 测试当 SPDY 会话空闲时，在资源受限的情况下（例如，HTTP 连接池达到最大连接数），是否能够被正确关闭以释放资源。包括了有别名（alias）的 SPDY 会话的关闭场景。
* **在 HTTP 连接池受限时关闭空闲会话：**  测试当底层的 HTTP 连接池因为达到连接数限制而阻塞时，SPDY 会话在空闲时是否能够主动关闭。
* **隐私模式对会话键的影响：**  验证是否在启用或禁用隐私模式下，`SpdySessionKey` 是不同的，从而确保隐私模式下的连接不会与非隐私模式下的连接混用。
* **流重置时创建新流：**  测试当一个 SPDY 流被重置时，如果其代理尝试创建新的流，是否能够正常工作，避免程序崩溃。

**与 JavaScript 的功能关系：**

虽然这段 C++ 代码本身不涉及 JavaScript，但它测试的网络栈功能是现代 Web 浏览器的基础。当 JavaScript 代码发起网络请求 (例如，使用 `fetch` API 或 `XMLHttpRequest`) 时，Chromium 的网络栈（包括 SPDY/HTTP/2 的处理逻辑）会在幕后工作。

* **资源加载优化:** SPDY/HTTP/2 允许多路复用，允许浏览器并行加载多个资源，这显著提高了网页加载速度。JavaScript 发起的请求会受益于这种优化。
* **服务器推送:** SPDY/HTTP/2 允许服务器在客户端明确请求之前主动推送资源。JavaScript 可以接收并利用这些推送的资源。
* **头部压缩:** SPDY/HTTP/2 压缩 HTTP 头部，减少了传输的数据量，提高了网络效率，这也有利于 JavaScript 发起的请求。

**举例说明：**

假设 JavaScript 代码发起多个请求去加载图片和脚本：

```javascript
fetch('/image1.png');
fetch('/image2.png');
fetch('/script.js');
```

这段 C++ 代码中的测试用例，例如 `TestMaxConcurrentStreamCreation`, `CancelPendingStreamCreation`,  验证了当 JavaScript 发起多个并发请求时，底层的 SPDY 会话如何管理这些流的创建和优先级，以及当达到并发限制时如何处理。

**逻辑推理与假设输入/输出：**

**测试用例:** `TestMaxConcurrentStreamCreation`

**假设输入:**

1. `kInitialMaxConcurrentStreams` 被设置为 2。
2. 连续创建 3 个流请求（`request1`, `request2`, `request3`），优先级均为 `LOWEST`。

**预期输出:**

1. 最开始只有 2 个流被立即创建 (因为 `kInitialMaxConcurrentStreams` 为 2)。
2. 第 3 个流请求会进入待创建队列。
3. `num_active_streams()` 初始为 2。
4. `num_created_streams()` 初始为 2。
5. `pending_create_stream_queue_size(LOWEST)` 初始为 1。

**测试用例:** `ReadDataWithoutYielding`

**假设输入:**

1. 服务端响应头部（`resp1`）。
2. 紧接着服务端发送了多个数据帧，总计大小略小于 `kYieldAfterBytesRead` (32KB)。

**预期输出:**

1. `SpdySession::DoReadLoop` 能够一次性读取所有数据，而不需要暂停并重新调度任务。
2. `observer.executed_count()` 将为 0，表明 `DoReadLoop` 没有发布新的任务来继续读取。

**用户或编程常见的使用错误：**

* **未正确处理流的取消:**  开发者在实现基于 SPDY 的客户端时，可能没有正确处理流的取消操作。例如，在请求发送后立即取消请求，而没有等待服务器响应，可能会导致资源泄漏或状态不一致。`CancelPendingStreamCreation` 测试用例验证了框架对这种情况的处理。
* **假设无限的并发流:**  开发者可能没有考虑到 SPDY 会话的并发流限制。如果应用程序尝试创建超过限制的并发流，可能会导致请求被延迟或失败。`TestMaxConcurrentStreamCreation` 相关的测试强调了这一限制。
* **不理解 Yielding 的概念:**  对于需要处理大量数据的网络应用程序，理解 `DoReadLoop` 的 Yielding 机制很重要。如果开发者期望在短时间内处理完大量数据，可能会因为 `DoReadLoop` 的 Yielding 行为而感到意外。`ReadDataWithoutYielding` 和 `TestYieldingDuringReadData` 等测试用例展示了 Yielding 的工作方式。

**用户操作如何一步步地到达这里，作为调试线索：**

1. **用户打开一个包含多个资源的网页：** 浏览器会尝试并行加载 HTML、CSS、JavaScript、图片等资源。对于支持 HTTP/2 的网站，浏览器会与服务器建立一个 SPDY 会话。
2. **浏览器创建多个 SPDY 流：**  为了并行加载资源，浏览器会在 SPDY 会话上创建多个流。这会触发 `SpdySession::CreateStream` 等方法。
3. **网络延迟或服务器处理缓慢：**  在资源加载过程中，可能会出现网络延迟或服务器处理缓慢的情况，导致数据读取速度变慢。这会触发 `SpdySession::DoReadLoop` 中的读取逻辑。
4. **用户取消导航或关闭标签页：**  如果用户在资源加载过程中取消导航或关闭标签页，浏览器可能会取消部分正在进行的 SPDY 流。这会触发流的取消逻辑，例如 `SpdyStream::Cancel`。
5. **服务器发送 `GOAWAY` 帧：**  服务器可能因为过载或维护等原因发送 `GOAWAY` 帧，告知客户端即将关闭连接。这会触发 `SpdySession::OnGoAwayFrame` 等方法。

在调试网络问题时，如果发现连接被意外关闭、资源加载缓慢或出现错误，可以查看网络日志，关注 SPDY 会话的状态、流的创建和取消、以及是否收到了 `GOAWAY` 帧等信息。这些信息可以帮助定位问题是否发生在 SPDY 会话层面。

**总结此部分的功能：**

总而言之，这部分 `net/spdy/spdy_session_unittest.cc` 代码主要测试了 `SpdySession` 在处理并发流创建、流的取消、数据读取的效率和健壮性、`GOAWAY` 帧的处理、协议协商和流量控制、以及空闲连接管理等关键方面的功能。 这些测试确保了 `SpdySession` 能够可靠高效地管理 SPDY 连接，为上层应用提供稳定的网络传输服务。

Prompt: 
```
这是目录为net/spdy/spdy_session_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共8部分，请归纳一下它的功能

"""
             NetLogWithSource(), callback3.callback(),
                                  TRAFFIC_ANNOTATION_FOR_TESTS));

  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(kInitialMaxConcurrentStreams, num_created_streams());
  EXPECT_EQ(2u, pending_create_stream_queue_size(LOWEST));

  // Cancel the first stream; this will allow the second stream to be created.
  EXPECT_TRUE(spdy_stream1);
  spdy_stream1->Cancel(ERR_ABORTED);
  EXPECT_FALSE(spdy_stream1);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(kInitialMaxConcurrentStreams, num_created_streams());
  EXPECT_EQ(1u, pending_create_stream_queue_size(LOWEST));

  // Cancel the second stream; this will allow the third stream to be created.
  base::WeakPtr<SpdyStream> spdy_stream2 = request2.ReleaseStream();
  spdy_stream2->Cancel(ERR_ABORTED);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(kInitialMaxConcurrentStreams, num_created_streams());
  EXPECT_EQ(0u, pending_create_stream_queue_size(LOWEST));

  // Cancel the third stream.
  base::WeakPtr<SpdyStream> spdy_stream3 = request3.ReleaseStream();
  spdy_stream3->Cancel(ERR_ABORTED);
  EXPECT_FALSE(spdy_stream3);
  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(kInitialMaxConcurrentStreams - 1, num_created_streams());
  EXPECT_EQ(0u, pending_create_stream_queue_size(LOWEST));
}

// Test that SpdySession::DoReadLoop reads data from the socket
// without yielding.  This test makes 32k - 1 bytes of data available
// on the socket for reading. It then verifies that it has read all
// the available data without yielding.
TEST_F(SpdySessionTest, ReadDataWithoutYielding) {
  session_deps_.time_func = InstantaneousReads;

  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  // Build buffer of size kYieldAfterBytesRead / 4
  // (-spdy_data_frame_size).
  ASSERT_EQ(32 * 1024, kYieldAfterBytesRead);
  const int kPayloadSize = kYieldAfterBytesRead / 4 - spdy::kFrameHeaderSize;
  TestDataStream test_stream;
  auto payload = base::MakeRefCounted<IOBufferWithSize>(kPayloadSize);
  char* payload_data = payload->data();
  test_stream.GetBytes(payload_data, kPayloadSize);

  spdy::SpdySerializedFrame partial_data_frame(
      spdy_util_.ConstructSpdyDataFrame(
          1, std::string_view(payload_data, kPayloadSize), /*fin=*/false));
  spdy::SpdySerializedFrame finish_data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, std::string_view(payload_data, kPayloadSize - 1), /*fin=*/true));

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Write 1 byte less than kMaxReadBytes to check that DoRead reads up to 32k
  // bytes.
  MockRead reads[] = {
      CreateMockRead(resp1, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(partial_data_frame, 3),
      CreateMockRead(partial_data_frame, 4, SYNCHRONOUS),
      CreateMockRead(partial_data_frame, 5, SYNCHRONOUS),
      CreateMockRead(finish_data_frame, 6, SYNCHRONOUS),
      MockRead(ASYNC, 0, 7)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
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
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Set up the TaskObserver to verify SpdySession::DoReadLoop doesn't
  // post a task.
  SpdySessionTestTaskObserver observer("spdy_session.cc", "DoReadLoop");

  // Run until 1st read.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(0u, observer.executed_count());

  // Read all the data and verify SpdySession::DoReadLoop has not
  // posted a task.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);

  // Verify task observer's executed_count is zero, which indicates DoRead read
  // all the available data.
  EXPECT_EQ(0u, observer.executed_count());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Test that SpdySession::DoReadLoop yields if more than
// |kYieldAfterDurationMilliseconds| has passed.  This test uses a mock time
// function that makes the response frame look very slow to read.
TEST_F(SpdySessionTest, TestYieldingSlowReads) {
  session_deps_.time_func = SlowReads;

  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  MockRead reads[] = {
      CreateMockRead(resp1, 1), MockRead(ASYNC, 0, 2)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
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
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Set up the TaskObserver to verify that SpdySession::DoReadLoop posts a
  // task.
  SpdySessionTestTaskObserver observer("spdy_session.cc", "DoReadLoop");

  EXPECT_EQ(0u, delegate1.stream_id());
  EXPECT_EQ(0u, observer.executed_count());

  // Read all the data and verify that SpdySession::DoReadLoop has posted a
  // task.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_FALSE(spdy_stream1);

  // Verify task that the observer's executed_count is 1, which indicates DoRead
  // has posted only one task and thus yielded though there is data available
  // for it to read.
  EXPECT_EQ(1u, observer.executed_count());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Regression test for https://crbug.com/531570.
// Test the case where DoRead() takes long but returns synchronously.
TEST_F(SpdySessionTest, TestYieldingSlowSynchronousReads) {
  session_deps_.time_func = SlowReads;

  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  spdy::SpdySerializedFrame partial_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "foo ", /*fin=*/false));
  spdy::SpdySerializedFrame finish_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "bar", /*fin=*/true));

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  MockRead reads[] = {
      CreateMockRead(resp1, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(partial_data_frame, 3, ASYNC),
      CreateMockRead(partial_data_frame, 4, SYNCHRONOUS),
      CreateMockRead(partial_data_frame, 5, SYNCHRONOUS),
      CreateMockRead(finish_data_frame, 6, SYNCHRONOUS),
      MockRead(ASYNC, 0, 7)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
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
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Run until 1st read.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());

  // Read all the data and verify SpdySession::DoReadLoop has posted a task.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ("foo foo foo bar", delegate1.TakeReceivedData());
  EXPECT_FALSE(spdy_stream1);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Test that SpdySession::DoReadLoop yields while reading the
// data. This test makes 32k + 1 bytes of data available on the socket
// for reading. It then verifies that DoRead has yielded even though
// there is data available for it to read (i.e, socket()->Read didn't
// return ERR_IO_PENDING during socket reads).
TEST_F(SpdySessionTest, TestYieldingDuringReadData) {
  session_deps_.time_func = InstantaneousReads;

  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  // Build buffer of size kYieldAfterBytesRead / 4
  // (-spdy_data_frame_size).
  ASSERT_EQ(32 * 1024, kYieldAfterBytesRead);
  const int kPayloadSize = kYieldAfterBytesRead / 4 - spdy::kFrameHeaderSize;
  TestDataStream test_stream;
  auto payload = base::MakeRefCounted<IOBufferWithSize>(kPayloadSize);
  char* payload_data = payload->data();
  test_stream.GetBytes(payload_data, kPayloadSize);

  spdy::SpdySerializedFrame partial_data_frame(
      spdy_util_.ConstructSpdyDataFrame(
          1, std::string_view(payload_data, kPayloadSize), /*fin=*/false));
  spdy::SpdySerializedFrame finish_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "h", /*fin=*/true));

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Write 1 byte more than kMaxReadBytes to check that DoRead yields.
  MockRead reads[] = {
      CreateMockRead(resp1, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(partial_data_frame, 3),
      CreateMockRead(partial_data_frame, 4, SYNCHRONOUS),
      CreateMockRead(partial_data_frame, 5, SYNCHRONOUS),
      CreateMockRead(partial_data_frame, 6, SYNCHRONOUS),
      CreateMockRead(finish_data_frame, 7, SYNCHRONOUS),
      MockRead(ASYNC, 0, 8)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
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
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Set up the TaskObserver to verify SpdySession::DoReadLoop posts a task.
  SpdySessionTestTaskObserver observer("spdy_session.cc", "DoReadLoop");

  // Run until 1st read.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(0u, observer.executed_count());

  // Read all the data and verify SpdySession::DoReadLoop has posted a task.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);

  // Verify task observer's executed_count is 1, which indicates DoRead has
  // posted only one task and thus yielded though there is data available for it
  // to read.
  EXPECT_EQ(1u, observer.executed_count());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Test that SpdySession::DoReadLoop() tests interactions of yielding
// + async, by doing the following MockReads.
//
// MockRead of SYNCHRONOUS 8K, SYNCHRONOUS 8K, SYNCHRONOUS 8K, SYNCHRONOUS 2K
// ASYNC 8K, SYNCHRONOUS 8K, SYNCHRONOUS 8K, SYNCHRONOUS 8K, SYNCHRONOUS 2K.
//
// The above reads 26K synchronously. Since that is less that 32K, we
// will attempt to read again. However, that DoRead() will return
// ERR_IO_PENDING (because of async read), so DoReadLoop() will
// yield. When we come back, DoRead() will read the results from the
// async read, and rest of the data synchronously.
TEST_F(SpdySessionTest, TestYieldingDuringAsyncReadData) {
  session_deps_.time_func = InstantaneousReads;

  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  // Build buffer of size kYieldAfterBytesRead / 4
  // (-spdy_data_frame_size).
  ASSERT_EQ(32 * 1024, kYieldAfterBytesRead);
  TestDataStream test_stream;
  const int kEightKPayloadSize =
      kYieldAfterBytesRead / 4 - spdy::kFrameHeaderSize;
  auto eightk_payload =
      base::MakeRefCounted<IOBufferWithSize>(kEightKPayloadSize);
  char* eightk_payload_data = eightk_payload->data();
  test_stream.GetBytes(eightk_payload_data, kEightKPayloadSize);

  // Build buffer of 2k size.
  TestDataStream test_stream2;
  const int kTwoKPayloadSize = kEightKPayloadSize - 6 * 1024;
  auto twok_payload = base::MakeRefCounted<IOBufferWithSize>(kTwoKPayloadSize);
  char* twok_payload_data = twok_payload->data();
  test_stream2.GetBytes(twok_payload_data, kTwoKPayloadSize);

  spdy::SpdySerializedFrame eightk_data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, std::string_view(eightk_payload_data, kEightKPayloadSize),
      /*fin=*/false));
  spdy::SpdySerializedFrame twok_data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, std::string_view(twok_payload_data, kTwoKPayloadSize),
      /*fin=*/false));
  spdy::SpdySerializedFrame finish_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "h", /*fin=*/true));

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  MockRead reads[] = {
      CreateMockRead(resp1, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(eightk_data_frame, 3),
      CreateMockRead(eightk_data_frame, 4, SYNCHRONOUS),
      CreateMockRead(eightk_data_frame, 5, SYNCHRONOUS),
      CreateMockRead(twok_data_frame, 6, SYNCHRONOUS),
      CreateMockRead(eightk_data_frame, 7, ASYNC),
      CreateMockRead(eightk_data_frame, 8, SYNCHRONOUS),
      CreateMockRead(eightk_data_frame, 9, SYNCHRONOUS),
      CreateMockRead(eightk_data_frame, 10, SYNCHRONOUS),
      CreateMockRead(twok_data_frame, 11, SYNCHRONOUS),
      CreateMockRead(finish_data_frame, 12, SYNCHRONOUS),
      MockRead(ASYNC, 0, 13)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
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
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Set up the TaskObserver to monitor SpdySession::DoReadLoop
  // posting of tasks.
  SpdySessionTestTaskObserver observer("spdy_session.cc", "DoReadLoop");

  // Run until 1st read.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(0u, observer.executed_count());

  // Read all the data and verify SpdySession::DoReadLoop has posted a
  // task.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);

  // Verify task observer's executed_count is 1, which indicates DoRead has
  // posted only one task and thus yielded though there is data available for
  // it to read.
  EXPECT_EQ(1u, observer.executed_count());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Send a GoAway frame when SpdySession is in DoReadLoop. Make sure
// nothing blows up.
TEST_F(SpdySessionTest, GoAwayWhileInDoReadLoop) {
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(0));

  MockRead reads[] = {
      CreateMockRead(resp1, 1), MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(body1, 3), CreateMockRead(goaway, 4),
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Run until 1st read.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, spdy_stream1->stream_id());

  // Run until GoAway.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_FALSE(session_);
}

// Within this framework, a SpdySession should be initialized with
// flow control disabled for protocol version 2, with flow control
// enabled only for streams for protocol version 3, and with flow
// control enabled for streams and sessions for higher versions.
TEST_F(SpdySessionTest, ProtocolNegotiation) {
  MockRead reads[] = {
    MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  CreateNetworkSession();
  session_ = CreateFakeSpdySession(spdy_session_pool_, key_);

  EXPECT_EQ(kDefaultInitialWindowSize, session_send_window_size());
  EXPECT_EQ(kDefaultInitialWindowSize, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());
}

// Tests the case of a non-SPDY request closing an idle SPDY session when no
// pointers to the idle session are currently held.
TEST_F(SpdySessionTest, CloseOneIdleConnection) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();

  ClientSocketPool* pool = http_session_->GetSocketPool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct());

  // Create an idle SPDY session.
  CreateSpdySession();
  EXPECT_FALSE(pool->IsStalled());

  // Trying to create a new connection should cause the pool to be stalled, and
  // post a task asynchronously to try and close the session.
  TestCompletionCallback callback2;
  auto connection2 = std::make_unique<ClientSocketHandle>();
  EXPECT_EQ(
      ERR_IO_PENDING,
      connection2->Init(
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpScheme, "2.com", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          ClientSocketPool::SocketParams::CreateForHttpForTesting(),
          std::nullopt /* proxy_annotation_tag */, DEFAULT_PRIORITY,
          SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
          callback2.callback(), ClientSocketPool::ProxyAuthCallback(), pool,
          NetLogWithSource()));
  EXPECT_TRUE(pool->IsStalled());

  // The socket pool should close the connection asynchronously and establish a
  // new connection.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(pool->IsStalled());
  EXPECT_FALSE(session_);
}

// Tests the case of a non-SPDY request closing an idle SPDY session when no
// pointers to the idle session are currently held, in the case the SPDY session
// has an alias.
TEST_F(SpdySessionTest, CloseOneIdleConnectionWithAlias) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  session_deps_.host_resolver->rules()->AddIPLiteralRule(
      "www.example.org", "192.168.0.2", std::string());

  CreateNetworkSession();

  ClientSocketPool* pool = http_session_->GetSocketPool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct());

  // Create an idle SPDY session.
  SpdySessionKey key1(HostPortPair("www.example.org", 80),
                      PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                      SessionUsage::kDestination, SocketTag(),
                      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> session1 =
      ::net::CreateSpdySession(http_session_.get(), key1, NetLogWithSource());
  EXPECT_FALSE(pool->IsStalled());

  // Set up an alias for the idle SPDY session, increasing its ref count to 2.
  SpdySessionKey key2(HostPortPair("mail.example.org", 80),
                      PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                      SessionUsage::kDestination, SocketTag(),
                      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  std::unique_ptr<SpdySessionPool::SpdySessionRequest> request;
  bool is_blocking_request_for_session = false;
  SpdySessionRequestDelegate request_delegate;
  EXPECT_FALSE(spdy_session_pool_->RequestSession(
      key2, /* enable_ip_based_pooling = */ true,
      /* is_websocket = */ false, NetLogWithSource(),
      /* on_blocking_request_destroyed_callback = */ base::RepeatingClosure(),
      &request_delegate, &request, &is_blocking_request_for_session));
  EXPECT_TRUE(request);

  HostResolverEndpointResult endpoint;
  endpoint.ip_endpoints = {IPEndPoint(IPAddress(192, 168, 0, 2), 80)};
  // Simulate DNS resolution completing, which should set up an alias.
  EXPECT_EQ(OnHostResolutionCallbackResult::kMayBeDeletedAsync,
            spdy_session_pool_->OnHostResolutionComplete(
                key2, /* is_websocket = */ false, {endpoint},
                /*aliases=*/{}));

  // Get a session for |key2|, which should return the session created earlier.
  base::WeakPtr<SpdySession> session2 =
      spdy_session_pool_->FindAvailableSession(
          key2, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ false, NetLogWithSource());
  EXPECT_TRUE(session2);
  ASSERT_EQ(session1.get(), session2.get());
  EXPECT_FALSE(pool->IsStalled());

  // Trying to create a new connection should cause the pool to be stalled, and
  // post a task asynchronously to try and close the session.
  TestCompletionCallback callback3;
  auto connection3 = std::make_unique<ClientSocketHandle>();
  EXPECT_EQ(
      ERR_IO_PENDING,
      connection3->Init(
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpScheme, "3.com", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          ClientSocketPool::SocketParams::CreateForHttpForTesting(),
          std::nullopt /* proxy_annotation_tag */, DEFAULT_PRIORITY,
          SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
          callback3.callback(), ClientSocketPool::ProxyAuthCallback(), pool,
          NetLogWithSource()));
  EXPECT_TRUE(pool->IsStalled());

  // The socket pool should close the connection asynchronously and establish a
  // new connection.
  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_FALSE(pool->IsStalled());
  EXPECT_FALSE(session1);
  EXPECT_FALSE(session2);
}

// Tests that when a SPDY session becomes idle, it closes itself if there is
// a lower layer pool stalled on the per-pool socket limit.
TEST_F(SpdySessionTest, CloseSessionOnIdleWhenPoolStalled) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame cancel1(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req1, 1), CreateMockWrite(cancel1, 1),
  };
  StaticSocketDataProvider data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  MockRead http_reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  AddSSLSocketData();

  CreateNetworkSession();

  ClientSocketPool* pool = http_session_->GetSocketPool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct());

  // Create a SPDY session.
  CreateSpdySession();
  EXPECT_FALSE(pool->IsStalled());

  // Create a stream using the session, and send a request.

  TestCompletionCallback callback1;
  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_, DEFAULT_PRIORITY,
      NetLogWithSource());
  ASSERT_TRUE(spdy_stream1.get());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, spdy_stream1->SendRequestHeaders(
                                std::move(headers1), NO_MORE_DATA_TO_SEND));

  base::RunLoop().RunUntilIdle();

  // Trying to create a new connection should cause the pool to be stalled, and
  // post a task asynchronously to try and close the session.
  TestCompletionCallback callback2;
  auto connection2 = std::make_unique<ClientSocketHandle>();
  EXPECT_EQ(
      ERR_IO_PENDING,
      connection2->Init(
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpScheme, "2.com", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          ClientSocketPool::SocketParams::CreateForHttpForTesting(),
          std::nullopt /* proxy_annotation_tag */, DEFAULT_PRIORITY,
          SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
          callback2.callback(), ClientSocketPool::ProxyAuthCallback(), pool,
          NetLogWithSource()));
  EXPECT_TRUE(pool->IsStalled());

  // Running the message loop should cause the socket pool to ask the SPDY
  // session to close an idle socket, but since the socket is in use, nothing
  // happens.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(pool->IsStalled());
  EXPECT_FALSE(callback2.have_result());

  // Cancelling the request should result in the session's socket being
  // closed, since the pool is stalled.
  ASSERT_TRUE(spdy_stream1.get());
  spdy_stream1->Cancel(ERR_ABORTED);
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(pool->IsStalled());
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
}

// Verify that SpdySessionKey and therefore SpdySession is different when
// privacy mode is enabled or disabled.
TEST_F(SpdySessionTest, SpdySessionKeyPrivacyMode) {
  CreateNetworkSession();

  HostPortPair host_port_pair("www.example.org", 443);
  SpdySessionKey key_privacy_enabled(
      host_port_pair, PRIVACY_MODE_ENABLED, ProxyChain::Direct(),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);
  SpdySessionKey key_privacy_disabled(
      host_port_pair, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));

  // Add SpdySession with PrivacyMode Enabled to the pool.
  base::WeakPtr<SpdySession> session_privacy_enabled =
      CreateFakeSpdySession(spdy_session_pool_, key_privacy_enabled);

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));

  // Add SpdySession with PrivacyMode Disabled to the pool.
  base::WeakPtr<SpdySession> session_privacy_disabled =
      CreateFakeSpdySession(spdy_session_pool_, key_privacy_disabled);

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));

  session_privacy_enabled->CloseSessionOnError(ERR_ABORTED, std::string());
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));

  session_privacy_disabled->CloseSessionOnError(ERR_ABORTED, std::string());
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));
}

// Delegate that creates another stream when its stream is closed.
class StreamCreatingDelegate : public test::StreamDelegateDoNothing {
 public:
  StreamCreatingDelegate(const base::WeakPtr<SpdyStream>& stream,
                         const base::WeakPtr<SpdySession>& session)
      : StreamDelegateDoNothing(stream),
        session_(session) {}

  ~StreamCreatingDelegate() override = default;

  void OnClose(int status) override {
    GURL url(kDefaultUrl);
    std::ignore =
        CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_, url,
                                  MEDIUM, NetLogWithSource());
  }

 private:
  const base::WeakPtr<SpdySession> session_;
};

// Create another stream in response to a stream being reset. Nothing
// should blow up. This is a regression test for
// http://crbug.com/263690 .
TEST_F(SpdySessionTest, CreateStreamOnStreamReset) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  spdy::SpdySerializedFrame rs
"""


```
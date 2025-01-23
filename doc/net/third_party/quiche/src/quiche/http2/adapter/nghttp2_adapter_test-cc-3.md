Response:
The user wants a summary of the functionality of the provided C++ code, which is part of the Chromium network stack and specifically tests the `NgHttp2Adapter` class.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The filename `nghttp2_adapter_test.cc` immediately indicates that this file contains unit tests for the `NgHttp2Adapter` class. This class likely serves as an adapter between the Chromium network stack and the `nghttp2` library, which is a popular HTTP/2 library.

2. **Analyze the Test Names:**  The test names provide high-level information about the functionalities being tested. Go through each test name and extract the key actions and scenarios:
    * `ClientBasicSends`: Basic client-side sending of requests.
    * `ClientSendsLargeTrailers`: Sending large HTTP trailers.
    * `ClientFinishesStreamOnEmptyDataSend`: How the adapter handles sending empty data to finish a stream.
    * `ClientNotifiesOnDataAvailableAfterPause`:  Resuming data sending after a pause.
    * `ClientSubmitRequestWithDataProviderAndWriteBlock`: Handling write blocking during request submission.
    * `ClientReceivesDataOnClosedStream`:  Handling incoming data on a stream that has already been closed by the client.
    * `ClientQueuesRequests`: Testing the request queuing mechanism when the number of concurrent streams is limited.
    * `ClientAcceptsHeadResponseWithContentLength`: Handling responses to HEAD requests.
    * `MetadataApiTest`:  A test suite for the metadata API (likely for sending HTTP/2 or HTTP/3 metadata frames).
    * `SubmitMetadata`, `SubmitMetadataMultipleFrames`, `SubmitConnectionMetadata`, `ClientSubmitMetadataWithGoaway`, `ClientSubmitMetadataWithFailureBefore`, `ClientSubmitMetadataWithFailureDuring`, `ClientSubmitMetadataWithFailureSending`: Specific tests within the metadata API suite, covering different scenarios like sending metadata, sending multiple metadata frames, connection-level metadata, and interactions with GOAWAY frames or sending failures.
    * `ClientObeysMaxConcurrentStreams`:  Verifying that the adapter respects the `MAX_CONCURRENT_STREAMS` setting.
    * `ClientReceivesInitialWindowSetting`: Handling the `INITIAL_WINDOW_SIZE` setting from the server.
    * `ClientReceivesInitialWindowSettingAfterStreamStart`: Handling `INITIAL_WINDOW_SIZE` when it arrives after a stream has started.

3. **Group Related Tests:** Notice the grouping of tests under `MetadataApiTest`. This signals a distinct feature being tested.

4. **Identify Key Concepts:** Based on the test names, identify the key HTTP/2 concepts being exercised:
    * Request submission (HEADERS frames)
    * Data sending (DATA frames)
    * Stream management (closing streams, RST_STREAM)
    * Settings frames
    * Connection management (preface, GOAWAY)
    * Flow control (window updates, `INITIAL_WINDOW_SIZE`)
    * Concurrent stream limits
    * Metadata frames

5. **Look for JavaScript Relevance (If Any):** Consider how these HTTP/2 features might relate to JavaScript in a browser context. JavaScript making HTTP requests using `fetch` or `XMLHttpRequest` interacts with these underlying HTTP/2 mechanisms. While this specific C++ code isn't directly JavaScript, it's part of the browser's networking implementation that *enables* JavaScript's network functionality.

6. **Infer Assumptions, Inputs, and Outputs:** For each test, consider what the "input" to the `NgHttp2Adapter` would be (e.g., a request, incoming bytes from the server) and the expected "output" (e.g., sending frames, callbacks to the visitor). Since the code uses `EXPECT_*` macros, the "expected output" is explicitly defined within the tests.

7. **Identify Potential User/Programming Errors:** Think about what mistakes a user or a programmer might make that would lead to the scenarios being tested. For example, trying to send data on a closed stream, not handling write blocking, or exceeding concurrent stream limits.

8. **Consider Debugging Scenarios:**  How would a developer end up inspecting this code during debugging?  They might be investigating issues related to:
    * Failed HTTP/2 requests.
    * Performance problems related to concurrency or flow control.
    * Unexpected connection closures.
    * Issues with custom metadata.

9. **Synthesize the Summary:** Combine the information gathered in the previous steps into a concise summary. Organize it logically, highlighting the main functionalities and any JavaScript relevance, assumptions, potential errors, and debugging contexts.

10. **Address the "Part 4 of 11" Instruction:**  Acknowledge that this is a part of a larger test suite and infer that the overall functionality of the adapter is being tested across these multiple parts.

**(Self-Correction during the process):**  Initially, I might focus too much on the low-level details of each test. However, the request asks for a functional overview. Therefore, I need to abstract away the specific frame types and focus on the higher-level actions like "submitting a request," "receiving data," "handling settings," etc. Also, while direct JavaScript interaction isn't present, the *relevance* to JavaScript's networking capabilities is important to highlight.这是 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc` 文件的第 4 部分，该文件是 Chromium 网络栈的一部分，专门用于测试 `NgHttp2Adapter` 类。 `NgHttp2Adapter` 的作用是作为 Chromium 网络栈和 `nghttp2` 库之间的适配器，`nghttp2` 是一个流行的 HTTP/2 协议的 C 库。

**本部分代码的功能归纳如下：**

本部分主要测试了 `NgHttp2Adapter` 在客户端模式下的以下功能：

* **流的恢复 (Resume Stream):** 测试当流之前因为 `Send()` 返回 0 而暂停发送数据后，如何使用 `ResumeStream()` 恢复发送。
* **客户端提交带数据提供器的请求并遇到写阻塞 (Client Submit Request With DataProvider And Write Block):**  测试客户端在提交包含请求体的请求时，如果底层网络遇到写阻塞（暂时无法发送数据），`NgHttp2Adapter` 如何处理这种情况。它验证了当写阻塞时，`Send()` 方法会返回，并且在解除阻塞后再次调用 `Send()` 可以继续发送剩余的数据。
* **客户端接收已关闭流的数据 (Client Receives Data On Closed Stream):** 测试客户端发送 `RST_STREAM` 关闭一个流后，服务器仍然尝试在该流上发送数据，客户端如何处理这些数据。预期行为是客户端会收到 HEADERS 帧的通知，但不会处理后续的 DATA 帧。
* **客户端队列请求 (Client Queues Requests):** 测试当客户端提交的请求数量超过服务器允许的最大并发流数量 (`MAX_CONCURRENT_STREAMS`) 时，`NgHttp2Adapter` 如何将额外的请求加入队列，并在有可用流时发送这些请求。
* **客户端接受带有 Content-Length 的 HEAD 响应 (Client Accepts Head Response With Content-Length):** 测试客户端发送 `HEAD` 请求后，如何正确处理带有 `content-length` 头的响应。`HEAD` 请求不应该有消息体，因此客户端在收到 HEADERS 帧后就应该认为流已结束。
* **元数据 API 测试 (Metadata API Test):**  这是一组测试用例，用于测试 `NgHttp2Adapter` 中处理 HTTP/2 元数据帧的功能。这些测试覆盖了以下场景：
    * 提交元数据 (Submit Metadata)
    * 提交多个元数据帧 (Submit Metadata Multiple Frames)
    * 提交连接级别的元数据 (Submit Connection Metadata)
    * 在发送元数据时遇到 GOAWAY 帧 (Client Submit Metadata With Goaway)
    * 在发送元数据之前、期间或发送时发生错误 (Client Submit Metadata WithFailureBefore/During/Sending)。
* **客户端遵守最大并发流限制 (Client Obeys MaxConcurrentStreams):** 测试客户端在收到服务器的 `SETTINGS` 帧并设置了 `MAX_CONCURRENT_STREAMS` 后，是否会遵守这个限制，不再发送超出限制的请求。
* **客户端接收初始窗口设置 (Client Receives Initial Window Setting):** 测试客户端接收服务器发送的 `SETTINGS` 帧，其中包含了 `INITIAL_WINDOW_SIZE` 设置，并更新本地的流控窗口大小。
* **客户端在流启动后接收初始窗口设置 (Client Receives Initial Window Setting After Stream Start):** 测试客户端在已经开始发送请求后，才收到服务器的 `INITIAL_WINDOW_SIZE` 设置的情况。

**与 Javascript 功能的关系 (举例说明):**

虽然这段 C++ 代码本身不是 Javascript，但它所测试的功能直接影响着 Javascript 在浏览器中发起 HTTP/2 请求的行为。例如：

* **`ClientQueuesRequests` 测试的功能与浏览器中 Javascript 发起多个 `fetch` 请求时的行为相关。** 当浏览器向同一个 HTTP/2 服务器发起多个请求，而服务器设置了 `MAX_CONCURRENT_STREAMS` 时，浏览器底层的网络栈（由 `NgHttp2Adapter` 参与实现）会负责将超出并发限制的请求放入队列，并在有空闲连接时发送。Javascript 代码无需关心这些细节，只需发起请求即可。

   **假设输入:** Javascript 代码连续发起 5 个 `fetch` 请求到同一个 HTTP/2 服务器，该服务器的 `MAX_CONCURRENT_STREAMS` 设置为 2。

   **预期输出:** 底层的 `NgHttp2Adapter` 会先发送前两个请求，然后将剩余的 3 个请求放入队列。当服务器处理完前两个请求并关闭连接或流后，`NgHttp2Adapter` 会从队列中取出请求并发送。

* **`ClientObeysMaxConcurrentStreams` 测试的功能确保了浏览器不会过度请求服务器，导致服务器过载。** Javascript 发起的请求最终会受到这个机制的限制。

**逻辑推理 (假设输入与输出):**

* **测试用例: `ClientFinishesStreamOnEmptyDataSend`**
    * **假设输入:** 客户端提交一个 POST 请求，并尝试使用空的 `DataFrameSource` 发送数据，并设置 `fin = true`。
    * **预期输出:**  `NgHttp2Adapter` 会发送一个空的 DATA 帧，并设置 END_STREAM 标志，以通知服务器该流的数据发送已完成。`visitor.OnFrameSent` 会被调用，参数为 `DATA` 帧类型，并且 `flags` 参数会包含 `0x1` (END_STREAM)。

**用户或编程常见的使用错误 (举例说明):**

* **尝试在已关闭的流上发送数据：**  开发者错误地在已经调用 `SubmitRst` 关闭的流上，仍然尝试使用 `SendData` 或通过 `DataProvider` 提供数据。`NgHttp2Adapter` 会阻止这种操作，并且可能触发断言或错误回调。
* **没有处理写阻塞：** 在发送大量数据时，开发者假设 `Send()` 会一次性发送所有数据。然而，由于网络拥塞等原因，`Send()` 可能会返回 0 表示写阻塞。如果开发者没有检查 `want_write()` 的状态并在之后重新调用 `Send()`，数据可能无法全部发送出去。

**用户操作如何一步步的到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器访问一个使用了 HTTP/2 协议的网站时遇到问题，例如请求被挂起，或者数据传输异常。作为 Chromium 的开发者，在调试这个问题时可能会查看 `NgHttp2Adapter` 的相关代码：

1. **用户在浏览器地址栏输入网址并回车，或者点击了页面上的链接。**
2. **浏览器解析 URL，并建立与服务器的 TCP 连接。**
3. **在 TCP 连接建立后，浏览器和服务器进行 HTTP/2 协商。**
4. **如果协商成功，后续的 HTTP 请求和响应会通过 HTTP/2 协议进行传输。**
5. **当 Javascript 代码 (例如通过 `fetch` API) 发起一个 HTTP 请求时，**  Chromium 的网络栈会创建对应的 HTTP/2 流，并使用 `NgHttp2Adapter` 将请求头和数据转换为 `nghttp2` 库可以处理的格式。
6. **如果发送请求时遇到网络问题 (例如写阻塞)，或者服务器的并发流限制影响了请求的发送，或者服务器发送了非预期的响应 (例如在客户端关闭流后仍然发送数据)，**  `NgHttp2Adapter` 的相关代码会被执行。
7. **开发者可能会通过添加日志、断点等方式来跟踪 `NgHttp2Adapter` 的执行流程，例如查看 `Send()` 方法的返回值，`want_write()` 的状态，以及 `visitor` 回调函数的调用情况，从而定位问题。**  这段测试代码的存在，可以帮助开发者理解 `NgHttp2Adapter` 在各种场景下的预期行为，从而更容易发现和修复 bug。

总而言之，本部分代码主要关注 `NgHttp2Adapter` 在客户端模式下处理各种 HTTP/2 交互场景的正确性，包括流的控制、数据发送、并发管理以及对服务器设置的遵守。 这些测试确保了 Chromium 网络栈能够可靠地处理 HTTP/2 通信。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
EXPECT_TRUE(adapter->ResumeStream(stream_id));
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, 0, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
  EXPECT_FALSE(adapter->want_write());

  // Stream data is done, so this stream cannot be resumed.
  EXPECT_FALSE(adapter->ResumeStream(stream_id));
  EXPECT_FALSE(adapter->want_write());
}

// This test verifies how nghttp2 behaves when a connection becomes
// write-blocked while sending HEADERS.
TEST(NgHttp2AdapterTest, ClientSubmitRequestWithDataProviderAndWriteBlock) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  // Flushes the connection preface.
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  // Client preface does not appear to include the mandatory SETTINGS frame.
  EXPECT_EQ(visitor.data(), spdy::kHttp2ConnectionHeaderPrefix);
  visitor.Clear();

  const absl::string_view kBody = "This is an example request body.";
  // This test will use TestDataSource as the source of the body payload data.
  TestDataSource body1{kBody};
  // The TestDataSource is wrapped in the nghttp2_data_provider data type.
  nghttp2_data_provider provider = body1.MakeDataProvider();
  nghttp2_send_data_callback send_callback = &TestSendCallback;

  // This call transforms it back into a DataFrameSource, which is compatible
  // with the Http2Adapter API.
  std::unique_ptr<DataFrameSource> frame_source =
      MakeZeroCopyDataFrameSource(provider, &visitor, std::move(send_callback));
  int stream_id =
      adapter->SubmitRequest(ToHeaders({{":method", "POST"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/one"}}),
                             std::move(frame_source), false, nullptr);
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(adapter->want_write());

  visitor.set_is_write_blocked(true);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  result = adapter->Send();

  EXPECT_EQ(0, result);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  visitor.set_is_write_blocked(false);
  result = adapter->Send();
  EXPECT_EQ(0, result);

  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(NgHttp2AdapterTest, ClientReceivesDataOnClosedStream) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  // Client preface does not appear to include the mandatory SETTINGS frame.
  EXPECT_THAT(visitor.data(),
              testing::StrEq(spdy::kHttp2ConnectionHeaderPrefix));
  visitor.Clear();

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  // Client SETTINGS ack
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // Let the client open a stream with a request.
  int stream_id =
      adapter->SubmitRequest(ToHeaders({{":method", "GET"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/one"}}),
                             nullptr, true, nullptr);
  EXPECT_GT(stream_id, 0);

  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();

  // Let the client RST_STREAM the stream it opened.
  adapter->SubmitRst(stream_id, Http2ErrorCode::CANCEL);
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, stream_id, _, 0x0,
                                   static_cast<int>(Http2ErrorCode::CANCEL)));
  EXPECT_CALL(visitor, OnCloseStream(stream_id, Http2ErrorCode::CANCEL));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::RST_STREAM}));
  visitor.Clear();

  // Let the server send a response on the stream. (It might not have received
  // the RST_STREAM yet.)
  const std::string response_frames =
      TestFrameSequence()
          .Headers(stream_id,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(stream_id, "This is the response body.", /*fin=*/true)
          .Serialize();

  // The visitor gets notified about the HEADERS frame but not the DATA frame on
  // the closed stream. No further processing for either frame occurs.
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 0x4));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, DATA, _)).Times(0);

  const int64_t response_result = adapter->ProcessBytes(response_frames);
  EXPECT_EQ(response_frames.size(), response_result);

  EXPECT_FALSE(adapter->want_write());
}

TEST(NgHttp2AdapterTest, ClientQueuesRequests) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  adapter->SubmitSettings({});

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  adapter->Send();

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface({{MAX_CONCURRENT_STREAMS, 2}})
          .SettingsAck()
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0x0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{
                           Http2KnownSettingsId::MAX_CONCURRENT_STREAMS, 2u}));
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck());

  adapter->ProcessBytes(initial_frames);

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/example/request"}});
  std::vector<int32_t> stream_ids;
  // Start two, which hits the limit.
  int32_t stream_id = adapter->SubmitRequest(headers, nullptr, true, nullptr);
  stream_ids.push_back(stream_id);
  stream_id = adapter->SubmitRequest(headers, nullptr, true, nullptr);
  stream_ids.push_back(stream_id);
  // Start two more, which must be queued.
  stream_id = adapter->SubmitRequest(headers, nullptr, true, nullptr);
  stream_ids.push_back(stream_id);
  stream_id = adapter->SubmitRequest(headers, nullptr, true, nullptr);
  stream_ids.push_back(stream_id);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[0], _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[0], _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[1], _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[1], _, 0x5, 0));

  adapter->Send();

  const std::string update_streams =
      TestFrameSequence().Settings({{MAX_CONCURRENT_STREAMS, 5}}).Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0x0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{
                           Http2KnownSettingsId::MAX_CONCURRENT_STREAMS, 5u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  adapter->ProcessBytes(update_streams);

  stream_id = adapter->SubmitRequest(headers, nullptr, true, nullptr);
  stream_ids.push_back(stream_id);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[2], _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[2], _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[3], _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[3], _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[4], _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[4], _, 0x5, 0));
  // Header frames should all have been sent in order, regardless of any
  // queuing.

  adapter->Send();
}

TEST(NgHttp2AdapterTest, ClientAcceptsHeadResponseWithContentLength) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  const std::vector<Header> headers = ToHeaders({{":method", "HEAD"},
                                                 {":scheme", "http"},
                                                 {":authority", "example.com"},
                                                 {":path", "/"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

  adapter->Send();

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(stream_id, {{":status", "200"}, {"content-length", "101"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, _, SETTINGS, 0x0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnHeaderForStream).Times(2);
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnEndStream(stream_id));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR));

  adapter->ProcessBytes(initial_frames);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  adapter->Send();
}

class MetadataApiTest : public quiche::test::QuicheTestWithParam<bool> {};

INSTANTIATE_TEST_SUITE_P(WithAndWithoutNewApi, MetadataApiTest,
                         testing::Bool());

TEST_P(MetadataApiTest, SubmitMetadata) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  const quiche::HttpHeaderBlock block = ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(1, block);
    adapter->SubmitMetadata(1, 1);
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(1, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({static_cast<SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter->want_write());
}

size_t DivRoundUp(size_t numerator, size_t denominator) {
  return numerator / denominator + (numerator % denominator == 0 ? 0 : 1);
}

TEST_P(MetadataApiTest, SubmitMetadataMultipleFrames) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  const auto kLargeValue = std::string(63 * 1024, 'a');
  const quiche::HttpHeaderBlock block =
      ToHeaderBlock(ToHeaders({{"large-value", kLargeValue}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(1, block);
    adapter->SubmitMetadata(1, DivRoundUp(kLargeValue.size(), 16384u));
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(1, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  testing::InSequence seq;
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({static_cast<SpdyFrameType>(kMetadataFrameType),
                            static_cast<SpdyFrameType>(kMetadataFrameType),
                            static_cast<SpdyFrameType>(kMetadataFrameType),
                            static_cast<SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter->want_write());
}

TEST_P(MetadataApiTest, SubmitConnectionMetadata) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  const quiche::HttpHeaderBlock block = ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(0, block);
    adapter->SubmitMetadata(0, 1);
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(0, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 0, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 0, _, 0x4, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({static_cast<SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter->want_write());
}

TEST_P(MetadataApiTest, ClientSubmitMetadataWithGoaway) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  adapter->SubmitSettings({});

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, _, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, _, _, 0x0, 0));
  adapter->Send();

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  const quiche::HttpHeaderBlock block = ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(stream_id, block);
    adapter->SubmitMetadata(stream_id, 1);
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(stream_id, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface()
          .GoAway(3, Http2ErrorCode::HTTP2_NO_ERROR, "server shutting down")
          .Serialize();
  testing::InSequence s;

  // Server preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  EXPECT_CALL(visitor, OnGoAway(3, Http2ErrorCode::HTTP2_NO_ERROR, _));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  // HEADERS frame is not sent.
  EXPECT_CALL(visitor,
              OnBeforeFrameSent(kMetadataFrameType, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::REFUSED_STREAM));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            static_cast<SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter->want_write());
}

TEST_P(MetadataApiTest, ClientSubmitMetadataWithFailureBefore) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  adapter->SubmitSettings({});

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, _, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, _, _, 0x0, 0));
  adapter->Send();

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  const quiche::HttpHeaderBlock block = ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(stream_id, block);
    adapter->SubmitMetadata(stream_id, 1);
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(stream_id, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  testing::InSequence s;

  // Server preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, stream_id, _, 0x4))
      .WillOnce(testing::Return(NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE));
  EXPECT_CALL(visitor, OnConnectionError(
                           Http2VisitorInterface::ConnectionError::kSendError));

  int result = adapter->Send();
  EXPECT_EQ(NGHTTP2_ERR_CALLBACK_FAILURE, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
}

TEST_P(MetadataApiTest, ClientSubmitMetadataWithFailureDuring) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  adapter->SubmitSettings({});

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, _, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, _, _, 0x0, 0));
  adapter->Send();

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  const quiche::HttpHeaderBlock block = ToHeaderBlock(
      ToHeaders({{"more-than-one-frame", std::string(20000, 'a')}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(stream_id, block);
    adapter->SubmitMetadata(stream_id, 2);
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(stream_id, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  testing::InSequence s;

  // Server preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor,
              OnBeforeFrameSent(kMetadataFrameType, stream_id, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, stream_id, _, 0x0, 0))
      .WillOnce(testing::Return(NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE));
  EXPECT_CALL(visitor, OnConnectionError(
                           Http2VisitorInterface::ConnectionError::kSendError));

  int result = adapter->Send();
  EXPECT_EQ(NGHTTP2_ERR_CALLBACK_FAILURE, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            static_cast<SpdyFrameType>(kMetadataFrameType)}));
}

TEST_P(MetadataApiTest, ClientSubmitMetadataWithFailureSending) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  adapter->SubmitSettings({});

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, _, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, _, _, 0x0, 0));
  adapter->Send();

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  if (GetParam()) {
    // The test visitor returns an error if no metadata payload is found for the
    // stream.
    adapter->SubmitMetadata(stream_id, 2);
  } else {
    auto source = std::make_unique<TestMetadataSource>(ToHeaderBlock(
        ToHeaders({{"more-than-one-frame", std::string(20000, 'a')}})));
    source->InjectFailure();
    adapter->SubmitMetadata(stream_id, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  testing::InSequence s;

  // Server preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnConnectionError(
                           Http2VisitorInterface::ConnectionError::kSendError));

  int result = adapter->Send();
  EXPECT_EQ(NGHTTP2_ERR_CALLBACK_FAILURE, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({
                              SpdyFrameType::SETTINGS,
                              SpdyFrameType::SETTINGS,
                          }));
}

TEST_P(NgHttp2AdapterDataTest, ClientObeysMaxConcurrentStreams) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  // Client preface does not appear to include the mandatory SETTINGS frame.
  EXPECT_THAT(visitor.data(),
              testing::StrEq(spdy::kHttp2ConnectionHeaderPrefix));
  visitor.Clear();

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface({{MAX_CONCURRENT_STREAMS, 1}})
          .Serialize();
  testing::InSequence s;

  // Server preface (SETTINGS with MAX_CONCURRENT_STREAMS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting);
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(adapter->want_write());
  const absl::string_view kBody = "This is an example request body.";
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  const int stream_id = adapter->SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      GetParam() ? nullptr : std::move(body1), false, nullptr);
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  const int next_stream_id =
      adapter->SubmitRequest(ToHeaders({{":method", "POST"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/two"}}),
                             nullptr, true, nullptr);

  // A new pending stream is created, but because of MAX_CONCURRENT_STREAMS, the
  // session should not want to write it at the moment.
  EXPECT_GT(next_stream_id, stream_id);
  EXPECT_FALSE(adapter->want_write());

  const std::string stream_frames =
      TestFrameSequence()
          .Headers(stream_id,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(stream_id, "This is the response body.", /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, ":status", "200"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(stream_id, "server", "my-fake-server"));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, "date",
                                         "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, 26, DATA, 0x1));
  EXPECT_CALL(visitor, OnBeginDataForStream(stream_id, 26));
  EXPECT_CALL(visitor,
              OnDataForStream(stream_id, "This is the response body."));
  EXPECT_CALL(visitor, OnEndStream(stream_id));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR));

  // The first stream should close, which should make the session want to write
  // the next stream.
  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, next_stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, next_stream_id, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());
}

TEST_P(NgHttp2AdapterDataTest, ClientReceivesInitialWindowSetting) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  const std::string initial_frames =
      TestFrameSequence()
          .Settings({{INITIAL_WINDOW_SIZE, 80000u}})
          .WindowUpdate(0, 65536)
          .Serialize();
  // Server preface (SETTINGS with INITIAL_STREAM_WINDOW)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{INITIAL_WINDOW_SIZE, 80000u}));
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 65536));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Session will want to write a SETTINGS ack.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int64_t result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string kLongBody = std::string(81000, 'c');
  visitor.AppendPayloadForStream(1, kLongBody);
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, true);
  const int stream_id = adapter->SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      GetParam() ? nullptr : std::move(body1), false, nullptr);
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  // The client can send more than 4 frames (65536 bytes) of data.
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, 16384, 0x0, 0)).Times(4);
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, 14464, 0x0, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA,
                            SpdyFrameType::DATA, SpdyFrameType::DATA,
                            SpdyFrameType::DATA, SpdyFrameType::DATA}));
}

TEST_P(NgHttp2AdapterDataTest,
       ClientReceivesInitialWindowSettingAfterStreamStart) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  const std::string initial_frames =
      TestFrame
```
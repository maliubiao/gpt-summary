Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. This file seems to be a unit test for `NgHttp2Adapter`, which is likely an adapter class for the `nghttp2` library, used for handling HTTP/2 communication.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Function:** The filename `nghttp2_adapter_test.cc` strongly suggests this is a unit test file. Its primary purpose is to verify the correct behavior of the `NgHttp2Adapter` class.

2. **Analyze the Test Structure:** The code is structured using the Google Test framework (`TEST`, `TEST_P`, `EXPECT_CALL`, `ASSERT_...`, `EXPECT_...`). Each `TEST` or `TEST_P` function represents a specific test case.

3. **Understand the Mocking:** The `TestVisitor` class and the `EXPECT_CALL` macros indicate mocking is used to observe and control the interactions of the `NgHttp2Adapter` with its underlying components (likely the `nghttp2` library and a higher-level HTTP/2 interface).

4. **Infer Functionality from Test Names and Actions:**
    * Test names like `ClientStartsShutdown`, `ClientReceivesGoAway`, `ClientFailsOnGoAway`, `ClientSubmitRequest` provide direct hints about the tested scenarios.
    * The sequence of actions within each test (e.g., `SubmitRequest`, `Send`, `ProcessBytes`) reveals the methods being tested and the expected call flow.
    * The arguments passed to `EXPECT_CALL` (e.g., frame types like `HEADERS`, `DATA`, `GOAWAY`, and visitor methods like `OnFrameSent`, `OnGoAway`) detail the expected interactions.

5. **Identify Key HTTP/2 Concepts:** The tests cover fundamental HTTP/2 concepts like:
    * **Connection Preface:** The initial handshake.
    * **Headers and Data Frames:** The basic units of HTTP/2 communication.
    * **Stream Management:** Creating and closing streams.
    * **Flow Control:**  `WINDOW_UPDATE` frames.
    * **Server-Initiated Shutdown:** `GOAWAY` frames.
    * **Error Handling:** `RST_STREAM`, connection errors.
    * **Settings Frames:** Configuration parameters.
    * **Metadata Frames:**  (Although not heavily tested in this snippet).
    * **101 (Switching Protocols) Responses:** Handling of these specific status codes.

6. **Address the JavaScript Relation:** Since HTTP/2 is a network protocol, its effects are visible in JavaScript when web pages interact with servers. Browsers use HTTP/2 to fetch resources. The tests here ensure the underlying HTTP/2 implementation correctly handles server responses and client requests, which directly impacts how JavaScript applications running in the browser function.

7. **Create Hypothetical Input/Output Examples:**  For specific tests like `ClientReceivesGoAway`, it's possible to imagine the input (a GOAWAY frame from the server) and the expected output (the client closing streams).

8. **Identify Common Usage Errors:** Based on the test scenarios, potential user errors include:
    * Incorrectly handling `GOAWAY` frames, leading to continued attempts to use closed connections.
    * Sending or expecting certain frames in the wrong order.
    * Not respecting flow control limits.

9. **Explain Debugging Context:** The file being a unit test is itself a crucial debugging clue. If an HTTP/2 interaction is failing in a larger application, examining the behavior of the `NgHttp2Adapter` using these tests (or similar tests) can help isolate the problem.

10. **Summarize the Functionality (for Part 3 of 11):**  Given this is part 3, focusing on the specific tests within this snippet is important. The key functions demonstrated here relate to client-side behaviors like initiating requests, handling server responses (including errors and `GOAWAY`), and managing data flow.

By following these steps, a comprehensive understanding of the code's functionality can be derived, and the user's specific questions can be addressed with relevant examples and explanations.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc` 文件的第三部分，该文件主要用于测试 `NgHttp2Adapter` 类。`NgHttp2Adapter` 是一个适配器类，它封装了 `nghttp2` 库，使得 Chromium 的网络栈可以使用 `nghttp2` 来处理 HTTP/2 协议。

**本部分代码的功能归纳：**

这部分代码主要测试了 `NgHttp2Adapter` 作为 HTTP/2 客户端时，处理服务器发送的 `GOAWAY` 帧的各种场景，以及客户端发起请求并处理响应的场景，包括错误处理和数据传输。具体来说，涵盖了以下功能：

* **客户端接收 `GOAWAY` 帧:**
    * 测试客户端接收到 `GOAWAY` 帧后，如何关闭已有的和待处理的 Stream。
    * 测试客户端接收到多个 `GOAWAY` 帧的情况，包括 last_stream_id 的变化以及对已存在 Stream 的影响。
    * 测试客户端接收到 `GOAWAY` 帧后，即使 `MAX_CONCURRENT_STREAMS` 增加，也不会发送待处理的请求。
    * 测试客户端在接收到 `GOAWAY` 帧的回调中返回失败的情况，导致连接错误。
* **客户端拒绝 101 响应:**
    * 测试客户端收到服务器发送的 `101 Switching Protocols` 响应时，会发送 `RST_STREAM` 帧并关闭 Stream，因为 HTTP/2 不支持 101 响应。
* **客户端提交请求并发送数据:**
    * 测试客户端通过 `SubmitRequest` 方法提交请求，并可以附带请求体数据。
    * 测试了有无请求体数据的情况，以及设置用户数据的情况。
    * 测试了获取 Stream 的发送和接收窗口大小。
* **客户端使用 Data Provider 提交请求:**
    * 测试了客户端使用 `MakeZeroCopyDataFrameSource` 创建的 Data Provider 来提供请求体数据。
    * 测试了 Data Provider 阻塞读取的情况，以及后续恢复发送的情况。
    * 测试了 Data Provider 阻塞后，以空的 DATA 帧结束的情况。

**与 JavaScript 功能的关系：**

虽然这段 C++ 代码本身不直接涉及 JavaScript，但它所测试的功能是 HTTP/2 协议客户端实现的关键部分。当 JavaScript 在浏览器中发起 HTTP 请求时，底层的网络栈（包括这个 `NgHttp2Adapter`）负责处理 HTTP/2 协议的细节。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch` API 发起一个 HTTP/2 POST 请求：

```javascript
fetch('https://example.com/api/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ key: 'value' })
})
.then(response => response.json())
.then(data => console.log(data));
```

当这个请求发送到服务器时，Chromium 的网络栈会使用 `NgHttp2Adapter` 将这个请求转换为 HTTP/2 帧（例如 HEADERS 帧和 DATA 帧）。

* **`ClientSubmitRequest` 测试模拟了 `fetch` 发起请求的过程。**  测试代码中的 `adapter->SubmitRequest` 对应着 JavaScript 发起请求的动作。`visitor.AppendPayloadForStream` 模拟了将请求体数据传递给底层。
* **`ClientReceivesGoAway` 测试模拟了服务器可能在任何时候发送 `GOAWAY` 帧的情况，这可能会导致 JavaScript 中的 `fetch` 请求失败或中断。** 浏览器需要正确处理 `GOAWAY` 帧，避免在连接关闭后继续发送请求。
* **`ClientRejects101Response` 测试确保了浏览器不会错误地处理服务器发送的 101 响应。**  这保证了 HTTP/2 协议的正确性。

**逻辑推理，假设输入与输出：**

**测试用例：`TEST(NgHttp2AdapterTest, ClientReceivesGoAway)`**

* **假设输入 (服务器发送的帧序列)：**
    * `SETTINGS` (服务器前导)
    * `RST_STREAM` (Stream 1, 错误码 ENHANCE_YOUR_CALM)
    * `GOAWAY` (Last-Stream-ID 1, 错误码 INTERNAL_ERROR, 调试信息 "indigestion")
    * `WINDOW_UPDATE` (Connection, 增加 42 窗口大小)
    * `WINDOW_UPDATE` (Stream 1, 增加 42 窗口大小)

* **预期输出 (客户端 `TestVisitor` 的回调)：**
    * `OnFrameHeader` (SETTINGS)
    * `OnSettingsStart`
    * `OnSettingsEnd`
    * `OnFrameHeader` (RST_STREAM)
    * `OnRstStream` (Stream 1, ENHANCE_YOUR_CALM)
    * `OnCloseStream` (Stream 1, ENHANCE_YOUR_CALM)
    * `OnFrameHeader` (GOAWAY)
    * `OnGoAway` (1, INTERNAL_ERROR, "indigestion")
    * `OnCloseStream` (Stream 3, REFUSED_STREAM)  // 因为 Last-Stream-ID 是 1，Stream 3 被拒绝
    * `OnFrameHeader` (WINDOW_UPDATE)
    * `OnWindowUpdate` (0, 42)
    * `OnFrameHeader` (WINDOW_UPDATE)
    * 客户端发送 `SETTINGS` (ACK)

**用户或编程常见的使用错误：**

* **不正确处理 `GOAWAY` 帧：**  如果客户端代码没有正确监听和处理 `GOAWAY` 帧，可能会在服务器指示关闭连接后继续发送请求，导致错误。
    * **举例：**  一个 HTTP 客户端在收到 `GOAWAY` 帧后，仍然尝试在该连接上创建新的 Stream 并发送请求。
* **在 HTTP/2 连接上期望收到 101 响应：**  开发者可能会错误地认为 HTTP/2 支持 101 响应，并在代码中尝试处理。
    * **举例：**  客户端代码在发送包含 `Upgrade` 头的请求后，尝试解析服务器返回的 101 响应头。实际上 HTTP/2 应该直接处理新的协议，而不是通过 101 切换。
* **不正确使用 Data Provider：**  如果 Data Provider 的实现不正确，例如在数据不可用时没有正确指示，可能导致发送不完整的请求体。
    * **举例：**  Data Provider 在 `Read` 回调中，当没有数据可读时，没有返回 `NGHTTP2_ERR_DEFERRED`，导致 `nghttp2` 库无法正确处理阻塞的情况。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个网站 (例如 `https://example.com`)。**
2. **浏览器发起多个 HTTP/2 请求获取网页资源（HTML、CSS、JavaScript、图片等）。**
3. **在某些情况下，服务器可能会因为过载、维护或其他原因决定关闭连接，并发送 `GOAWAY` 帧。**
4. **或者，服务器可能返回一个携带 `Upgrade` 头的请求，但错误地返回了 `101` 响应。**
5. **在发送 POST 请求时，JavaScript 代码可能通过 `fetch` API 发送了包含请求体的数据。**  底层网络栈使用了 Data Provider 来处理请求体数据的发送。
6. **如果在这个过程中出现了 HTTP/2 协议相关的错误，网络栈的开发者可能会需要调试 `NgHttp2Adapter` 的行为。** 他们可能会使用类似这里的单元测试来重现和分析问题。`nghttp2_adapter_test.cc` 文件就是用于测试 `NgHttp2Adapter` 在各种场景下的行为是否符合预期。

**本部分功能归纳：**

总而言之，这部分 `nghttp2_adapter_test.cc` 的代码主要关注于测试 `NgHttp2Adapter` 作为 HTTP/2 客户端时，如何正确处理服务器的连接关闭信号 (`GOAWAY`)，如何拒绝不支持的 HTTP 响应 (101)，以及如何正确地发送带有或不带请求体的 HTTP/2 请求，并使用 Data Provider 处理请求体数据发送的阻塞和恢复。 这些测试确保了 Chromium 的 HTTP/2 客户端能够健壮且符合规范地与服务器进行通信。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共11部分，请归纳一下它的功能

"""
  {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const int32_t stream_id1 = adapter->SubmitRequest(
      headers1, nullptr, true, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1))
      .WillOnce(testing::Return(false));
  // Rejecting headers leads to a connection error.
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(NGHTTP2_ERR_CALLBACK_FAILURE, stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ClientStartsShutdown) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  EXPECT_FALSE(adapter->want_write());

  // No-op for a client implementation.
  adapter->SubmitShutdownNotice();
  EXPECT_FALSE(adapter->want_write());

  int result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_EQ(visitor.data(), spdy::kHttp2ConnectionHeaderPrefix);
}

TEST(NgHttp2AdapterTest, ClientReceivesGoAway) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});

  const int32_t stream_id2 =
      adapter->SubmitRequest(headers2, nullptr, true, nullptr);
  ASSERT_GT(stream_id2, stream_id1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::HEADERS}));
  visitor.Clear();

  // Submit a pending WINDOW_UPDATE for a stream that will be closed due to
  // GOAWAY. The WINDOW_UPDATE should not be sent.
  adapter->SubmitWindowUpdate(3, 42);

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .RstStream(1, Http2ErrorCode::ENHANCE_YOUR_CALM)
          .GoAway(1, Http2ErrorCode::INTERNAL_ERROR, "indigestion")
          .WindowUpdate(0, 42)
          .WindowUpdate(1, 42)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(1, Http2ErrorCode::ENHANCE_YOUR_CALM));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::ENHANCE_YOUR_CALM));
  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  EXPECT_CALL(visitor,
              OnGoAway(1, Http2ErrorCode::INTERNAL_ERROR, "indigestion"));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::REFUSED_STREAM));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 42));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  // SETTINGS ack (but only after the enqueue of the seemingly unrelated
  // WINDOW_UPDATE). The WINDOW_UPDATE is not written.
  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ClientReceivesMultipleGoAways) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface()
          .GoAway(kMaxStreamId, Http2ErrorCode::INTERNAL_ERROR, "indigestion")
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  EXPECT_CALL(visitor, OnGoAway(kMaxStreamId, Http2ErrorCode::INTERNAL_ERROR,
                                "indigestion"));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Submit a WINDOW_UPDATE for the open stream. Because the stream is below the
  // GOAWAY's last_stream_id, it should be sent.
  adapter->SubmitWindowUpdate(1, 42);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 1, 4, 0x0, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::WINDOW_UPDATE}));
  visitor.Clear();

  const std::string final_frames =
      TestFrameSequence()
          .GoAway(0, Http2ErrorCode::INTERNAL_ERROR, "indigestion")
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  EXPECT_CALL(visitor,
              OnGoAway(0, Http2ErrorCode::INTERNAL_ERROR, "indigestion"));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::REFUSED_STREAM));

  const int64_t final_result = adapter->ProcessBytes(final_frames);
  EXPECT_EQ(final_frames.size(), static_cast<size_t>(final_result));

  EXPECT_FALSE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
}

TEST(NgHttp2AdapterTest, ClientReceivesMultipleGoAwaysWithIncreasingStreamId) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();

  auto source = std::make_unique<TestMetadataSource>(ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}})));
  adapter->SubmitMetadata(stream_id1, 16384u, std::move(source));

  const std::string frames =
      TestFrameSequence()
          .ServerPreface()
          .GoAway(0, Http2ErrorCode::HTTP2_NO_ERROR, "")
          .GoAway(0, Http2ErrorCode::ENHANCE_YOUR_CALM, "")
          .GoAway(1, Http2ErrorCode::INTERNAL_ERROR, "")
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  EXPECT_CALL(visitor, OnGoAway(0, Http2ErrorCode::HTTP2_NO_ERROR, ""));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::REFUSED_STREAM));
  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  EXPECT_CALL(visitor, OnGoAway(0, Http2ErrorCode::ENHANCE_YOUR_CALM, ""));
  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));

  const int64_t frames_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(frames_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(NgHttp2AdapterTest, ClientReceivesGoAwayWithPendingStreams) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  // Client preface does not appear to include the mandatory SETTINGS frame.
  EXPECT_THAT(visitor.data(),
              testing::StrEq(spdy::kHttp2ConnectionHeaderPrefix));
  visitor.Clear();

  testing::InSequence s;

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface({{MAX_CONCURRENT_STREAMS, 1}})
          .Serialize();

  // Server preface (SETTINGS with MAX_CONCURRENT_STREAMS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting);
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});

  const int32_t stream_id2 =
      adapter->SubmitRequest(headers2, nullptr, true, nullptr);
  ASSERT_GT(stream_id2, stream_id1);

  // The second request should be pending because of
  // SETTINGS_MAX_CONCURRENT_STREAMS.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  visitor.Clear();

  // Let the client receive a GOAWAY and raise MAX_CONCURRENT_STREAMS. Even
  // though the GOAWAY last_stream_id is higher than the pending request's
  // stream ID, pending request should not be sent.
  const std::string stream_frames =
      TestFrameSequence()
          .GoAway(kMaxStreamId, Http2ErrorCode::INTERNAL_ERROR, "indigestion")
          .Settings({{MAX_CONCURRENT_STREAMS, 42u}})
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  EXPECT_CALL(visitor, OnGoAway(kMaxStreamId, Http2ErrorCode::INTERNAL_ERROR,
                                "indigestion"));
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{MAX_CONCURRENT_STREAMS, 42u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  // Nghttp2 closes the pending stream on the next write attempt.
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::REFUSED_STREAM));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // Requests submitted after receiving the GOAWAY should not be sent.
  const std::vector<Header> headers3 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/three"}});

  const int32_t stream_id3 =
      adapter->SubmitRequest(headers3, nullptr, true, nullptr);
  ASSERT_GT(stream_id3, stream_id2);

  // Nghttp2 closes the pending stream on the next write attempt.
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::REFUSED_STREAM));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
  EXPECT_FALSE(adapter->want_write());
}

TEST(NgHttp2AdapterTest, ClientFailsOnGoAway) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const int32_t stream_id1 = adapter->SubmitRequest(
      headers1, nullptr, true, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .GoAway(1, Http2ErrorCode::INTERNAL_ERROR, "indigestion")
          .Data(1, "This is the response body.")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  EXPECT_CALL(visitor,
              OnGoAway(1, Http2ErrorCode::INTERNAL_ERROR, "indigestion"))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(NGHTTP2_ERR_CALLBACK_FAILURE, stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ClientRejects101Response) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"},
                 {"upgrade", "new-protocol"}});

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1,
                   {{":status", "101"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 1, name: [:status], value: [101]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(static_cast<int64_t>(stream_frames.size()), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(RST_STREAM, 1, 4, 0x0,
                  static_cast<uint32_t>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST_P(NgHttp2AdapterDataTest, ClientSubmitRequest) {
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

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_EQ(0, adapter->GetHpackEncoderDynamicTableSize());
  EXPECT_FALSE(adapter->want_write());
  const char* kSentinel = "";
  const absl::string_view kBody = "This is an example request body.";
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int stream_id =
      adapter->SubmitRequest(ToHeaders({{":method", "POST"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/one"}}),
                             GetParam() ? nullptr : std::move(body1), false,
                             const_cast<char*>(kSentinel));
  ASSERT_EQ(1, stream_id);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(stream_id));
  EXPECT_EQ(kInitialFlowControlWindowSize, adapter->GetReceiveWindowSize());
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowLimit(stream_id));

  EXPECT_GT(adapter->GetHpackEncoderDynamicTableSize(), 0);

  // Some data was sent, so the remaining send window size should be less than
  // the default.
  EXPECT_LT(adapter->GetStreamSendWindowSize(stream_id),
            kInitialFlowControlWindowSize);
  EXPECT_GT(adapter->GetStreamSendWindowSize(stream_id), 0);
  // Send window for a nonexistent stream is not available.
  EXPECT_EQ(-1, adapter->GetStreamSendWindowSize(stream_id + 2));

  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  stream_id =
      adapter->SubmitRequest(ToHeaders({{":method", "POST"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/one"}}),
                             nullptr, true, nullptr);
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(adapter->want_write());
  const char* kSentinel2 = "arbitrary pointer 2";
  EXPECT_EQ(nullptr, adapter->GetStreamUserData(stream_id));
  adapter->SetStreamUserData(stream_id, const_cast<char*>(kSentinel2));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));

  EXPECT_EQ(kSentinel2, adapter->GetStreamUserData(stream_id));

  // No data was sent (just HEADERS), so the remaining send window size should
  // still be the default.
  EXPECT_EQ(adapter->GetStreamSendWindowSize(stream_id),
            kInitialFlowControlWindowSize);
}

// This is really a test of the MakeZeroCopyDataFrameSource adapter, but I
// wasn't sure where else to put it.
TEST(NgHttp2AdapterTest, ClientSubmitRequestWithDataProvider) {
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

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(adapter->want_write());
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  EXPECT_FALSE(adapter->want_write());
}

// This test verifies how nghttp2 behaves when a data source becomes
// read-blocked.
TEST(NgHttp2AdapterTest, ClientSubmitRequestWithDataProviderAndReadBlock) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  const absl::string_view kBody = "This is an example request body.";
  // This test will use TestDataSource as the source of the body payload data.
  TestDataSource body1{kBody};
  body1.set_is_data_available(false);
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  // Client preface does not appear to include the mandatory SETTINGS frame.
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  // Resume the deferred stream.
  body1.set_is_data_available(true);
  EXPECT_TRUE(adapter->ResumeStream(stream_id));
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
  EXPECT_FALSE(adapter->want_write());

  // Stream data is done, so this stream cannot be resumed.
  EXPECT_FALSE(adapter->ResumeStream(stream_id));
  EXPECT_FALSE(adapter->want_write());
}

// This test verifies how nghttp2 behaves when a data source is read block, then
// ends with an empty DATA frame.
TEST(NgHttp2AdapterTest, ClientSubmitRequestEmptyDataWithFin) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  const absl::string_view kEmptyBody = "";
  // This test will use TestDataSource as the source of the body payload data.
  TestDataSource body1{kEmptyBody};
  body1.set_is_data_available(false);
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  // Client preface does not appear to include the mandatory SETTINGS frame.
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  // Resume the deferred stream.
  body1.set_is_data_available(true);
  
"""


```
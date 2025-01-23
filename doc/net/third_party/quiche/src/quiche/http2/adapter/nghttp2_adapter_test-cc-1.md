Response:
The user wants me to analyze a C++ source code file for the Chromium network stack, specifically `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc`.

Here's a breakdown of the request and my thought process:

1. **Identify the file's purpose:** The file name ends in `_test.cc`, indicating this is a unit test file. It likely tests the `NgHttp2Adapter` class.

2. **List its functions:**  Unit tests primarily exercise different scenarios and functionalities of the class being tested. I'll scan the code for `TEST` macros, as these define individual test cases. Each test case name usually hints at the functionality being tested.

3. **Check for JavaScript relevance:** HTTP/2 is a fundamental protocol for web communication. While the C++ code directly implements the protocol, its behavior directly impacts how JavaScript running in a browser interacts with servers. I need to look for scenarios in the tests that relate to common web development concepts.

4. **Provide input/output examples:** For each test case, I can infer the expected input (server frames) and the expected output (actions on the `visitor` mock object, which represents the upper layer of the HTTP/2 implementation).

5. **Highlight common usage errors:**  Test cases often include scenarios with errors or unexpected behavior. These can point to common mistakes developers might make when implementing HTTP/2.

6. **Explain user steps to reach this code:**  Since this is a low-level networking component, direct user interaction is minimal. The connection happens behind the scenes when a user visits a website. I'll describe the general flow of how a network request triggers this code.

7. **Summarize the functionality (for part 2):** Based on the analyzed test cases in this snippet, I'll provide a concise summary of the functionalities covered in this specific part of the file.

**Detailed Analysis of the Code Snippet:**

* **Error Handling:**  Several tests focus on how the `NgHttp2Adapter` handles errors like `PROTOCOL_ERROR` when the server sends unexpected data (e.g., data with a 304 status, RST_STREAM frames).
* **304 Not Modified:**  Specific tests (`ClientHandles304WithContent`, `ClientHandles304WithContentLength`) verify correct behavior when a server responds with a 304 status code, including cases with and without a content-length.
* **Trailers:**  Tests like `ClientHandlesTrailers` and `ClientSendsTrailers` examine how the adapter handles HTTP trailers (headers sent after the body).
* **Metadata Frames:**  The `ClientHandlesMetadata` tests cover the processing of HTTP/2 metadata frames, which are extensions to the base protocol.
* **HPACK Header Table:** The `ClientHandlesHpackHeaderTableSetting` test verifies handling of the `HEADER_TABLE_SIZE` setting, important for header compression.
* **Invalid Trailers:**  The `ClientHandlesInvalidTrailers` test checks how the adapter reacts to trailers with invalid headers.
* **RST_STREAM during Headers:** The `ClientRstStreamWhileHandlingHeaders` test simulates the client receiving a `RST_STREAM` frame while processing headers.
* **Connection Errors:** The `ClientConnectionErrorWhileHandlingHeaders` and `ClientConnectionErrorWhileHandlingHeadersOnly` tests cover scenarios where processing headers leads to a connection-level error.
* **Rejecting Headers:** The snippet ends with a test case named `ClientRejectsHeaders`, suggesting it will cover scenarios where the client rejects received headers.

**Planning the Response:**

I will structure the response by first listing the functionalities tested in this code snippet. Then, for each functionality, I will try to connect it to JavaScript concepts and provide input/output examples where applicable. I will also include potential user errors and how a user's actions might lead to these code paths. Finally, I'll provide a summary for this specific part of the file.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc` 文件的第二部分，主要包含以下功能的测试：

**功能列表：**

* **客户端处理带有内容体的 304 状态码响应：** 测试当客户端收到带有 `content-length` 头部的 304 Not Modified 响应时，是否会正确处理并发送 RST_STREAM 帧关闭连接（因为按照 HTTP/2 规范，304 响应不应该有消息体）。
* **客户端处理带有 Content-Length 的 304 状态码响应：** 测试当客户端收到带有 `content-length` 头部的 304 Not Modified 响应（且 `fin` 标志位为 true）时，是否会正确处理并仅发送 SETTINGS 帧。
* **客户端处理尾部（Trailers）：** 测试客户端如何处理服务器发送的尾部，即在响应主体之后发送的头部。
* **客户端发送尾部（Trailers）：** 测试客户端如何发送尾部，可以先发送请求头和数据，然后再发送尾部。
* **客户端处理元数据（Metadata）：** 测试客户端如何处理 HTTP/2 的元数据帧，包括连接级别的元数据和流级别的元数据。
* **客户端处理带有空有效载荷的元数据：** 测试客户端处理带有空数据的元数据帧的情况。
* **客户端处理带有错误的元数据：** 测试当处理元数据帧时发生错误（例如，visitor 回调返回 false）时，客户端的行为。
* **客户端处理 HPACK 头部表设置：** 测试客户端如何处理服务器发送的 SETTINGS 帧，特别是 `HEADER_TABLE_SIZE` 设置，并更新本地的 HPACK 编码器动态表大小。
* **客户端处理无效的尾部：** 测试客户端接收到包含非法头部的尾部时的处理方式，预期会发送 RST_STREAM 帧。
* **客户端在处理头部时发送 RST_STREAM：** 测试客户端在接收服务器发送的头部时主动发送 RST_STREAM 帧的情况。
* **客户端在处理头部时遇到连接错误：** 测试当处理接收到的头部时，visitor 回调指示发生连接错误时客户端的行为。
* **客户端在仅处理头部时遇到连接错误：** 类似于上一个测试，但响应中没有数据体，只有头部。
* **客户端拒绝头部：**  （本部分末尾，未完整展示） 预计会测试客户端在接收到不符合预期的头部时如何拒绝。

**与 JavaScript 的关系及举例说明：**

虽然这段代码是 C++ 实现的 HTTP/2 协议栈，但其行为直接影响着运行在浏览器中的 JavaScript 代码的网络请求。

* **304 Not Modified:** 当 JavaScript 发起一个带有缓存策略的请求，服务器返回 304 时，浏览器会从缓存中加载资源，而不会处理响应体。这段 C++ 代码的测试确保了底层协议栈在收到错误的带有内容的 304 响应时能正确处理，避免干扰上层 JavaScript 的行为。
* **尾部（Trailers）：**  一些较新的 JavaScript API (例如 `fetch` API 的 `response.trailers`) 允许访问 HTTP 尾部。这段 C++ 代码的测试保证了当服务器发送尾部时，底层的处理是正确的，从而使得 JavaScript 可以正确地获取这些信息。
    * **假设输入：** 服务器发送包含尾部的 HTTP/2 响应。
    * **输出：** C++ 代码正确解析尾部，并通过 Visitor 接口传递给上层，最终 JavaScript 可以通过 `response.trailers` 访问到这些尾部。
* **元数据（Metadata）：**  虽然 JavaScript 目前没有直接访问 HTTP/2 元数据帧的 API，但理解底层协议栈如何处理这些帧对于未来可能的 API 设计和优化是很重要的。
* **HPACK 头部表设置：** HPACK 压缩直接影响 HTTP 头部的大小，进而影响网络性能。这段 C++ 代码测试了对 HPACK 设置的处理，保证了头部压缩的效率，这最终会提升 JavaScript 应用的网络加载速度。

**逻辑推理的假设输入与输出：**

以 `TEST(NgHttp2AdapterTest, ClientHandles304WithContent)` 为例：

* **假设输入：**
    * 客户端发送一个 GET 请求。
    * 服务器响应一个 HTTP/2 HEADERS 帧，状态码为 "304"，但包含 "content-length: 2" 头部，并且之后发送了一个 DATA 帧包含 "hi"。
* **输出：**
    * `OnFrameHeader`, `OnSettingsStart`, `OnSettingsEnd` 被调用以处理服务器的 preface。
    * `OnFrameHeader`, `OnBeginHeadersForStream`, `OnHeaderForStream` (针对 `:status` 和 `content-length`), `OnEndHeadersForStream` 被调用以处理 HEADERS 帧。
    * `OnFrameHeader`, `OnBeginDataForStream` 被调用以处理 DATA 帧。
    * 客户端检测到 304 响应不应该有内容，发送一个 SETTINGS 帧作为 ACK。
    * 客户端发送一个 RST_STREAM 帧来关闭流，错误码为 `PROTOCOL_ERROR`。
    * `OnCloseStream` 被调用。

**用户或编程常见的使用错误：**

* **服务器错误地在 304 响应中发送内容：** 这是 `ClientHandles304WithContent` 测试所覆盖的场景。开发者可能会错误地认为所有 3xx 响应都可以包含内容。
* **不正确的尾部格式：**  `ClientHandlesInvalidTrailers` 测试了这种情况。开发者可能会在尾部中包含不合法的头部字段（例如，以冒号开头的头部，在尾部中是不允许的）。
* **不理解 HTTP/2 规范对 304 响应的限制：**  开发者可能不清楚 HTTP/2 协议对 304 响应体的限制，导致服务端返回不符合规范的响应。

**用户操作如何一步步的到达这里（调试线索）：**

1. **用户在浏览器中输入 URL 并访问一个网站。**
2. **浏览器解析 URL，并确定需要建立 HTTP/2 连接（如果服务器支持）。**
3. **浏览器（客户端）的网络栈开始与服务器进行 TCP 握手和 TLS 握手。**
4. **TLS 连接建立后，客户端和服务器发送 HTTP/2 连接前导（connection preface）。**
5. **客户端发送 HTTP 请求（HEADERS 帧）。**
6. **服务器响应 HTTP 响应头（HEADERS 帧）。**
7. **如果服务器错误地发送了一个带有内容的 304 响应，或者发送了带有非法头部的尾部，那么 `NgHttp2Adapter::ProcessBytes` 方法会被调用来处理接收到的字节流。**
8. **在 `NgHttp2Adapter::ProcessBytes` 内部，nghttp2 库会解析帧，并调用 `TestVisitor` 中定义的回调函数（例如 `OnFrameHeader`, `OnBeginHeadersForStream` 等）。**
9. **测试代码中的断言（例如 `EXPECT_CALL`）会验证这些回调函数是否按照预期被调用，以及参数是否正确。**
10. **如果测试失败，则表明 `NgHttp2Adapter` 在处理特定类型的 HTTP/2 帧时存在问题。**

**功能归纳（第 2 部分）：**

这部分测试主要集中在 `NgHttp2Adapter` 作为 HTTP/2 客户端时，对各种服务器响应场景的处理，包括对错误格式响应（如带有内容的 304）、尾部、元数据以及 HPACK 设置的处理。此外，还测试了客户端主动断开连接以及在处理头部时遇到错误的情况，确保了客户端在各种异常和正常情况下的健壮性和符合 HTTP/2 规范的行为。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::RST_STREAM,
                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientHandles304WithContent) {
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
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "304"}, {"content-length", "2"}},
                   /*fin=*/false)
          .Data(1, "hi")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "304"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "content-length", "2"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 2));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientHandles304WithContentLength) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  ASSERT_GT(stream_id, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "304"}, {"content-length", "2"}},
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "304"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "content-length", "2"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ClientHandlesTrailers) {
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
          .Data(1, "This is the response body.")
          .Headers(1, {{"final-status", "A-OK"}},
                   /*fin=*/true)
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
  EXPECT_CALL(visitor, OnFrameHeader(1, 26, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "final-status", "A-OK"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

class NgHttp2AdapterDataTest : public quiche::test::QuicheTestWithParam<bool> {
};

INSTANTIATE_TEST_SUITE_P(BothValues, NgHttp2AdapterDataTest, testing::Bool());

TEST_P(NgHttp2AdapterDataTest, ClientSendsTrailers) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const Http2StreamId kStreamId = 1;
  const std::string kBody = "This is an example request body.";
  visitor.AppendPayloadForStream(kStreamId, kBody);
  visitor.SetEndData(kStreamId, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, kStreamId);
  // nghttp2 does not require that the data source indicate the end of data
  // before trailers are enqueued.

  const int32_t stream_id1 = adapter->SubmitRequest(
      headers1, GetParam() ? nullptr : std::move(body1), false, nullptr);
  ASSERT_GT(stream_id1, 0);
  EXPECT_EQ(stream_id1, kStreamId);
  EXPECT_EQ(adapter->sources_size(), GetParam() ? 0 : 1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id1, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  visitor.Clear();

  const std::vector<Header> trailers1 =
      ToHeaders({{"extra-info", "Trailers are weird but good?"}});
  adapter->SubmitTrailer(stream_id1, trailers1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  data = visitor.data();
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::HEADERS}));
}

TEST(NgHttp2AdapterTest, ClientHandlesMetadata) {
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
          .Metadata(0, "Example connection metadata")
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Metadata(1, "Example stream metadata")
          .Data(1, "This is the response body.", true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(0));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 26, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ClientHandlesMetadataWithEmptyPayload) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

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
          .Metadata(1, "")
          .Data(1, "This is the response body.", true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(3);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));
}

TEST(NgHttp2AdapterTest, ClientHandlesMetadataWithError) {
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
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Metadata(0, "Example connection metadata")
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Metadata(1, "Example stream metadata")
          .Data(1, "This is the response body.", true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(0));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _))
      .WillOnce(testing::Return(false));
  // Remaining frames are not processed due to the error.
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  // The false return from OnMetadataForStream() results in a connection error.
  EXPECT_EQ(stream_result, NGHTTP2_ERR_CALLBACK_FAILURE);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  EXPECT_TRUE(adapter->want_read());  // Even after an error. Why?
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ClientHandlesHpackHeaderTableSetting) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 = ToHeaders({
      {":method", "GET"},
      {":scheme", "http"},
      {":authority", "example.com"},
      {":path", "/this/is/request/one"},
      {"x-i-do-not-like", "green eggs and ham"},
      {"x-i-will-not-eat-them", "here or there, in a box, with a fox"},
      {"x-like-them-in-a-house", "no"},
      {"x-like-them-with-a-mouse", "no"},
  });

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  EXPECT_GT(adapter->GetHpackEncoderDynamicTableSize(), 100);

  const std::string stream_frames =
      TestFrameSequence().Settings({{HEADER_TABLE_SIZE, 100u}}).Serialize();
  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{HEADER_TABLE_SIZE, 100u}));

  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_LE(adapter->GetHpackEncoderDynamicTableSize(), 100);
}

TEST(NgHttp2AdapterTest, ClientHandlesInvalidTrailers) {
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
          .Data(1, "This is the response body.")
          .Headers(1, {{":bad-status", "9000"}},
                   /*fin=*/true)
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
  EXPECT_CALL(visitor, OnFrameHeader(1, 26, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 1, name: [:bad-status], value: [9000]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  // Bad status trailer will cause a PROTOCOL_ERROR. The header is never
  // delivered in an OnHeaderForStream callback.

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, stream_id1, 4, 0x0, 1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientRstStreamWhileHandlingHeaders) {
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
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"))
      .WillOnce(testing::DoAll(
          testing::InvokeWithoutArgs([&adapter]() {
            adapter->SubmitRst(1, Http2ErrorCode::REFUSED_STREAM);
          }),
          testing::Return(Http2VisitorInterface::HEADER_RST_STREAM)));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, stream_id1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::REFUSED_STREAM)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::REFUSED_STREAM));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientConnectionErrorWhileHandlingHeaders) {
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
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"))
      .WillOnce(
          testing::Return(Http2VisitorInterface::HEADER_CONNECTION_ERROR));
  // Translation to nghttp2 treats this error as a general parsing error.
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(-902 /* NGHTTP2_ERR_CALLBACK_FAILURE */, stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ClientConnectionErrorWhileHandlingHeadersOnly) {
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
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"))
      .WillOnce(
          testing::Return(Http2VisitorInterface::HEADER_CONNECTION_ERROR));
  // Translation to nghttp2 treats this error as a general parsing error.
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(-902 /* NGHTTP2_ERR_CALLBACK_FAILURE */, stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ClientRejectsHeaders) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
```
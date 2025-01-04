Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is a part of Chromium's network stack related to HTTP/2. They are specifically interested in:

1. **General Functionality:** What does this code do?
2. **Relationship to Javascript:** Does this code interact with Javascript, and if so, how?
3. **Logical Reasoning (Input/Output):** Can we infer input and output based on the tests?
4. **Common Usage Errors:** What mistakes might users or programmers make when using this code?
5. **Debugging Context:** How does a user reach this code during the normal operation of a browser?
6. **Summary of Functionality (Part 3 of 12):**  A concise summary of the functionality within this specific snippet.

Let's break down the code and address each point:

* **Code Analysis:** The code is a series of C++ unit tests using the Google Test framework. The tests are named descriptively and focus on the `OgHttp2Adapter` class. The `OgHttp2Adapter` appears to be an adapter for handling HTTP/2 communication, likely bridging the gap between a higher-level HTTP/2 implementation and a lower-level network I/O layer (represented by the `TestVisitor`). The tests cover scenarios like:
    * Handling trailers (headers sent after the body).
    * Sending trailers.
    * Handling stream resets (`RST_STREAM`).
    * Handling connection errors (`GOAWAY`).
    * Handling invalid trailers.
    * Handling HPACK header table size settings.
    * Initiating shutdown.
    * Receiving `GOAWAY` frames.

* **Relationship to Javascript:**  HTTP/2 functionality in a browser is often exposed to Javascript through higher-level APIs like `fetch`. While this specific C++ code doesn't directly execute Javascript, it's a crucial part of the browser's underlying network stack that makes Javascript's network requests possible.

* **Logical Reasoning (Input/Output):** We can deduce input and output by examining the test cases. The input is typically a series of HTTP/2 frames (headers, data, settings, etc.) either being sent or received. The output is the actions taken by the `OgHttp2Adapter`, such as sending frames, calling methods on the `TestVisitor` to signal events, and potentially closing connections or streams.

* **Common Usage Errors:**  Given the nature of the code, user-level errors are less relevant here. Programmer errors might involve incorrectly implementing the `Http2VisitorInterface`, mishandling the state of HTTP/2 streams, or sending malformed HTTP/2 frames.

* **Debugging Context:**  A developer might encounter this code when debugging network issues in Chrome, particularly related to HTTP/2. This could involve inspecting network logs, using debugging tools to step through the code, or analyzing crash dumps.

* **Summary of Functionality (Part 3 of 12):** This particular snippet focuses on the client-side behavior of the `OgHttp2Adapter` when handling various server responses and actions, including trailers, errors, and settings changes. It demonstrates how the adapter reacts to different incoming HTTP/2 frames and manages the state of client-initiated streams.

**Plan:**

1. Start with a general description of the file's purpose.
2. Explain the connection to Javascript through the `fetch` API.
3. Provide a concrete example of input and output based on one of the test cases.
4. Detail potential programmer errors related to HTTP/2 concepts.
5. Describe the debugging process that would lead a developer here.
6. Conclude with a summary of the tested functionalities.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc` 文件的第三部分，主要包含了针对 `OgHttp2Adapter` 类作为 HTTP/2 客户端时的行为进行测试的用例。

**功能归纳 (基于提供的代码片段):**

这部分代码主要测试了客户端 `OgHttp2Adapter` 如何处理来自服务器的以下情况：

* **处理尾部（Trailers）:** 测试客户端如何接收和解析服务器在响应主体之后发送的尾部 header。
* **发送尾部（Trailers）:** 测试客户端如何构建并发送尾部 header。
* **在处理头部时接收 RST_STREAM:** 测试当客户端正在接收服务器的响应头时，服务器发送 `RST_STREAM` 帧中止流的情况，客户端如何处理。
* **在处理头部时发生连接错误:** 测试当客户端正在接收服务器的响应头时，由于某些原因导致连接级别错误的情况，客户端如何处理。
* **拒绝接收头部:** 测试客户端在接收到服务器发送的响应头时，决定拒绝处理这些头部的情况。
* **处理较小的 HPACK 头部表大小设置:** 测试客户端如何接收并应用服务器发送的减小 HPACK 头部表大小的 `SETTINGS` 帧。
* **处理较大的 HPACK 头部表大小设置:** 测试客户端如何接收服务器发送的增大 HPACK 头部表大小的 `SETTINGS` 帧，以及应用该设置的时机。
* **发送 HPACK 头部表大小设置:** 测试客户端主动向服务器发送 `SETTINGS` 帧来设置 HPACK 头部表大小的情况。
* **处理无效的尾部:** 测试客户端接收到包含无效 header 的尾部时会发生什么，例如尾部中出现了 `:status` 伪头。
* **开始关闭连接:** 测试客户端主动发起关闭连接的流程。
* **接收 GOAWAY 帧:** 测试客户端接收到服务器发送的 `GOAWAY` 帧，表明服务器要关闭连接的情况。

**与 Javascript 的关系及举例说明:**

虽然这段 C++ 代码本身不包含 Javascript，但它是 Chromium 网络栈的一部分，负责处理底层的 HTTP/2 协议。当 Javascript 代码通过 `fetch` API 或 `XMLHttpRequest` 发起 HTTP/2 请求时，最终会调用到类似 `OgHttp2Adapter` 这样的 C++ 组件来处理实际的网络通信。

**举例说明:**

假设一个 Javascript 网页通过 `fetch` API 向服务器请求一个资源，并且服务器返回的响应包含了尾部 header：

```javascript
fetch('https://example.com/resource')
  .then(response => {
    console.log(response.headers.get('content-type')); // 获取初始响应头
    const reader = response.body.getReader();
    return new ReadableStream({
      start(controller) {
        function push() {
          reader.read().then(({ done, value }) => {
            if (done) {
              // 尾部 header 可能在 done 为 true 时通过 response.trailers 获取
              response.trailer.then(trailers => {
                console.log('Trailers:', trailers.get('final-status'));
              });
              controller.close();
              return;
            }
            controller.enqueue(value);
            push();
          });
        }
        push();
      }
    });
  })
  .then(stream => new Response(stream))
  .then(responseWithTrailers => {
    // 某些浏览器可能直接在 responseWithTrailers 对象上暴露 trailers
    if (responseWithTrailers.trailers) {
      responseWithTrailers.trailers.then(trailers => {
        console.log('Trailers (alternative):', trailers.get('final-status'));
      });
    }
  });
```

在这个例子中，底层的 `OgHttp2Adapter` 组件就会负责接收服务器发送的 HTTP/2 帧，包括响应头、响应体以及尾部 header，并将这些信息传递给上层的 Javascript API，最终让 Javascript 代码能够通过 `response.headers` 和 `response.trailers` 访问到这些信息。

**逻辑推理 (假设输入与输出):**

**例子：`ClientHandlesTrailers` 测试用例**

**假设输入 (服务器发送的 HTTP/2 帧序列):**

```
[SETTINGS frame] (空)
[HEADERS frame] (stream_id=1, :status=200, server=my-fake-server, date=...)
[DATA frame] (stream_id=1, "This is the response body.")
[HEADERS frame] (stream_id=1, final-status=A-OK, END_STREAM)
```

**预期输出 (客户端 `OgHttp2Adapter` 的行为和 `TestVisitor` 的回调):**

1. `OnFrameHeader` (SETTINGS)
2. `OnSettingsStart`
3. `OnSettingsEnd`
4. `OnFrameHeader` (HEADERS, stream_id=1)
5. `OnBeginHeadersForStream` (stream_id=1)
6. `OnHeaderForStream` (stream_id=1, ":status", "200")
7. `OnHeaderForStream` (stream_id=1, "server", "my-fake-server")
8. `OnHeaderForStream` (stream_id=1, "date", "Tue, 6 Apr 2021 12:54:01 GMT")
9. `OnEndHeadersForStream` (stream_id=1)
10. `OnFrameHeader` (DATA, stream_id=1)
11. `OnBeginDataForStream` (stream_id=1, 26)
12. `OnDataForStream` (stream_id=1, "This is the response body.")
13. `OnFrameHeader` (HEADERS, stream_id=1)
14. `OnBeginHeadersForStream` (stream_id=1)
15. `OnHeaderForStream` (stream_id=1, "final-status", "A-OK")
16. `OnEndHeadersForStream` (stream_id=1)
17. `OnEndStream` (stream_id=1)
18. `OnCloseStream` (stream_id=1, Http2ErrorCode::HTTP2_NO_ERROR)
19. `OnBeforeFrameSent` (SETTINGS, ACK)
20. `OnFrameSent` (SETTINGS, ACK)

**用户或编程常见的使用错误 (针对与此代码相关的 HTTP/2 客户端实现):**

* **不处理或错误处理尾部 header:**  客户端可能没有正确实现接收和处理尾部 header 的逻辑，导致关键信息丢失或解析错误。
* **过早关闭连接:** 在服务器发送完所有数据（包括尾部 header）之前就关闭连接，导致数据不完整。
* **发送无效的尾部 header:**  客户端尝试发送不符合 HTTP/2 规范的尾部 header，例如在尾部中包含 `:status` 伪头。
* **错误地假设 HPACK 头部表大小:**  客户端可能没有正确处理服务器发送的 HPACK 头部表大小设置，导致头部压缩和解压缩出现问题。
* **未处理 `GOAWAY` 帧:** 客户端没有正确处理服务器发送的 `GOAWAY` 帧，可能导致在服务器即将关闭连接时仍然尝试发送请求。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个支持 HTTP/2 并且使用了尾部 header 的网站，遇到了一些问题，例如尾部 header 没有被正确显示或处理。作为开发人员，进行调试的步骤可能如下：

1. **用户报告问题:** 用户反馈在特定网站上，某些应该在尾部 header 中返回的信息丢失了。
2. **检查浏览器开发者工具:**  开发人员打开 Chrome 的开发者工具，查看 Network 面板，检查该请求的 Headers 部分，看是否能看到尾部 header。
3. **抓包分析 (可选):**  如果开发者工具中没有显示尾部 header，可能会使用 Wireshark 等抓包工具捕获网络数据包，分析底层的 HTTP/2 帧序列，确认服务器是否真的发送了尾部 header。
4. **查看 Chromium 网络日志 (net-internals):**  开发人员可以访问 `chrome://net-internals/#http2` 查看更详细的 HTTP/2 会话信息，包括发送和接收的帧。
5. **源码调试 (针对 Chromium 开发人员):** 如果怀疑是客户端的 HTTP/2 实现有问题，Chromium 开发人员可能会设置断点在 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter.cc` 相关的代码中，例如 `OgHttp2Adapter::ProcessBytes` 方法，逐步跟踪代码执行流程，查看是否正确解析和处理了尾部 header 相关的 `HEADERS` 帧。
6. **关注 `TestVisitor` 的回调:**  在单元测试中使用的 `TestVisitor` 模拟了底层的网络操作。在实际调试中，开发人员会关注 `OgHttp2Adapter` 如何调用其内部的 `Http2VisitorInterface` 实现，来判断是否正确接收和处理了帧。例如，是否调用了 `OnBeginHeadersForStream`、`OnHeaderForStream` 并带有 `END_STREAM` 标志。

**总结这部分的功能:**

总而言之，这部分 `oghttp2_adapter_test.cc` 代码主要关注客户端 `OgHttp2Adapter` 对服务器各种行为的健壮性和正确性，特别是针对尾部 header 的处理、错误处理（如 `RST_STREAM` 和连接错误）、HPACK 头部表大小的协商以及连接关闭流程的测试。它确保了客户端在各种复杂场景下能够按照 HTTP/2 协议规范正确地与服务器进行交互。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共12部分，请归纳一下它的功能

"""
_, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, ClientHandlesTrailers) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
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
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

class OgHttp2AdapterDataTest : public quiche::test::QuicheTestWithParam<bool> {
};

INSTANTIATE_TEST_SUITE_P(BothValues, OgHttp2AdapterDataTest, testing::Bool());

TEST_P(OgHttp2AdapterDataTest, ClientSendsTrailers) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const std::string kBody = "This is an example request body.";
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);

  const int32_t stream_id1 = adapter->SubmitRequest(
      headers1, GetParam() ? nullptr : std::move(body1), false, nullptr);
  ASSERT_EQ(stream_id1, 1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id1, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS,
                            SpdyFrameType::DATA}));
  visitor.Clear();

  const std::vector<Header> trailers1 =
      ToHeaders({{"extra-info", "Trailers are weird but good?"}});
  adapter->SubmitTrailer(stream_id1, trailers1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  data = visitor.data();
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::HEADERS}));
}

TEST(OgHttp2AdapterTest, ClientRstStreamWhileHandlingHeaders) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
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
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, stream_id1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::REFUSED_STREAM)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ClientConnectionErrorWhileHandlingHeaders) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
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
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kHeaderError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ClientConnectionErrorWhileHandlingHeadersOnly) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
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
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kHeaderError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ClientRejectsHeaders) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
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
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kHeaderError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ClientHandlesSmallerHpackHeaderTableSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

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
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_EQ(adapter->GetHpackEncoderDynamicTableCapacity(), 100);
  EXPECT_LE(adapter->GetHpackEncoderDynamicTableSize(), 100);
}

TEST(OgHttp2AdapterTest, ClientHandlesLargerHpackHeaderTableSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  EXPECT_EQ(adapter->GetHpackEncoderDynamicTableCapacity(), 4096);

  const std::string stream_frames =
      TestFrameSequence().Settings({{HEADER_TABLE_SIZE, 40960u}}).Serialize();
  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{HEADER_TABLE_SIZE, 40960u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  // The increased capacity will not be applied until a SETTINGS ack is
  // serialized.
  EXPECT_EQ(adapter->GetHpackEncoderDynamicTableCapacity(), 4096);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  EXPECT_EQ(adapter->GetHpackEncoderDynamicTableCapacity(), 40960);
}

TEST(OgHttp2AdapterTest, ClientSendsHpackHeaderTableSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers1 = ToHeaders({
      {":method", "GET"},
      {":scheme", "http"},
      {":authority", "example.com"},
      {":path", "/this/is/request/one"},
  });

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .SettingsAck()
          .Headers(
              1,
              {{":status", "200"},
               {"server", "my-fake-server"},
               {"date", "Tue, 6 Apr 2021 12:54:01 GMT"},
               {"x-i-do-not-like", "green eggs and ham"},
               {"x-i-will-not-eat-them", "here or there, in a box, with a fox"},
               {"x-like-them-in-a-house", "no"},
               {"x-like-them-with-a-mouse", "no"}},
              /*fin=*/true)
          .Serialize();
  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Server acks client's initial SETTINGS.
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 1));
  EXPECT_CALL(visitor, OnSettingsAck());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(7);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_GT(adapter->GetHpackDecoderSizeLimit(), 100);

  // Submit settings, check decoder table size.
  adapter->SubmitSettings({{HEADER_TABLE_SIZE, 100u}});
  EXPECT_GT(adapter->GetHpackDecoderSizeLimit(), 100);

  // Server preface SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  // SETTINGS with the new header table size value
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  // Because the client has not yet seen an ack from the server for the SETTINGS
  // with header table size, it has not applied the new value.
  EXPECT_GT(adapter->GetHpackDecoderSizeLimit(), 100);

  result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::vector<Header> headers2 = ToHeaders({
      {":method", "GET"},
      {":scheme", "http"},
      {":authority", "example.com"},
      {":path", "/this/is/request/two"},
  });

  const int32_t stream_id2 =
      adapter->SubmitRequest(headers2, nullptr, true, nullptr);
  ASSERT_GT(stream_id2, stream_id1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string response_frames =
      TestFrameSequence()
          .Headers(stream_id2,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(stream_id2, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id2));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id2, _, _)).Times(3);
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id2));
  EXPECT_CALL(visitor, OnEndStream(stream_id2));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id2, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t response_result = adapter->ProcessBytes(response_frames);
  EXPECT_EQ(response_frames.size(), static_cast<size_t>(response_result));

  // Still no ack for the outbound settings.
  EXPECT_GT(adapter->GetHpackDecoderSizeLimit(), 100);

  const std::string settings_ack =
      TestFrameSequence().SettingsAck().Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 1));
  EXPECT_CALL(visitor, OnSettingsAck());

  const int64_t ack_result = adapter->ProcessBytes(settings_ack);
  EXPECT_EQ(settings_ack.size(), static_cast<size_t>(ack_result));
  // Ack has finally arrived.
  EXPECT_EQ(adapter->GetHpackDecoderSizeLimit(), 100);
}

// TODO(birenroy): Validate headers and re-enable this test. The library should
// invoke OnErrorDebug() with an error message for the invalid header. The
// library should also invoke OnInvalidFrame() for the invalid HEADERS frame.
TEST(OgHttp2AdapterTest, DISABLED_ClientHandlesInvalidTrailers) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
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

  // Bad status trailer will cause a PROTOCOL_ERROR. The header is never
  // delivered in an OnHeaderForStream callback.

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, stream_id1, 4, 0x0, 1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ClientStartsShutdown) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_FALSE(adapter->want_write());

  // No-op (except for logging) for a client implementation.
  adapter->SubmitShutdownNotice();
  EXPECT_FALSE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);

  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, ClientReceivesGoAway) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | EN
"""


```
Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of a larger test file for an HTTP/2 adapter. I need to analyze the code and identify the main scenarios being tested.

The code appears to be testing the client-side behavior of the HTTP/2 adapter in various situations. Specifically, it seems to be focusing on how the adapter handles:

1. **Flow control updates:** Submitting settings to update the receive window size and verifying the update takes effect after the settings are acknowledged.
2. **Rejection of 100 (Continue) responses with a FIN flag:** Testing that the adapter correctly rejects such responses.
3. **Handling of a FIN flag following a 100 response:**  Verifying the adapter's behavior in this edge case.
4. **Rejection of 100 responses with content:** Ensuring the adapter rejects 100 responses that include a body.
5. **Rejection of 100 responses with `content-length`:**  Confirming the adapter rejects these responses.
6. **Handling of responses with `content-length` and padding:** Checking if the adapter correctly handles padding in data frames when a `content-length` is present.
7. **Handling of a complete server response before the client finishes sending the request:** Testing how the adapter manages this out-of-order scenario, including cases with and without trailers and RST_STREAM frames.
8. **Handling of 204 (No Content) responses with content:** Verifying the adapter's rejection of such responses.
9. **Handling of 304 (Not Modified) responses with content:**  Confirming the adapter's rejection.
10. **Handling of 304 responses with `content-length`:**  Testing the adapter's behavior in this scenario.

I will now summarize these functionalities in a concise manner.
这个代码片段主要测试了 `OgHttp2Adapter` 作为 HTTP/2 客户端时，对各种服务器响应的处理情况，特别是涉及到状态码 100 (Continue), 204 (No Content) 和 304 (Not Modified) 的场景，以及流量控制更新的情况。

以下是该代码片段功能的归纳：

1. **测试客户端发送请求并处理流量控制更新：**
   - 客户端可以发送请求头。
   - 客户端可以发送 SETTINGS 帧来更新初始窗口大小。
   - 客户端在收到服务器对 SETTINGS 帧的 ACK 后，会更新对应流的接收窗口大小。

2. **测试客户端拒绝携带 FIN 标志的 100 (Continue) 响应头：**
   - 当服务器发送带有 FIN 标志的 100 响应头时，客户端会认为这是无效的帧，并发送 RST_STREAM 帧终止连接。

3. **测试客户端处理 100 (Continue) 响应头后跟随 FIN 标志的情况：**
   - 当服务器先发送 100 响应头，然后立即发送带有 FIN 标志的 DATA 帧，客户端会识别到这是不符合规范的行为，并关闭流。

4. **测试客户端拒绝携带内容的 100 (Continue) 响应头：**
   - 当服务器发送带有 DATA 帧的 100 响应时，客户端会认为这是无效的帧，并发送 RST_STREAM 帧终止连接。

5. **测试客户端拒绝携带 `content-length` 的 100 (Continue) 响应头：**
   - 当服务器发送带有 `content-length` 头的 100 响应时，客户端会认为这是无效的帧，并发送 RST_STREAM 帧终止连接。

6. **测试客户端处理带有 `content-length` 和 padding 的响应：**
   - 客户端能够正确处理带有 `content-length` 头的响应，即使 DATA 帧包含 padding。

7. **测试客户端在请求完成前处理完整的服务器响应：**
   - 服务器可以在客户端发送完请求体之前发送完整的响应。
   - 测试了包含和不包含 Trailing Headers 的情况。
   - 测试了响应后是否跟随 RST_STREAM 帧的情况。
   - 客户端在这种情况下能够正确处理服务器的响应。

8. **测试客户端拒绝带有内容的 204 (No Content) 响应：**
   - 当服务器发送带有 DATA 帧的 204 响应时，客户端会认为这是不符合规范的行为，并发送 RST_STREAM 帧终止连接。

9. **测试客户端拒绝带有内容的 304 (Not Modified) 响应：**
   - 当服务器发送带有 DATA 帧的 304 响应时，客户端会认为这是不符合规范的行为，并发送 RST_STREAM 帧终止连接。

10. **测试客户端处理带有 `content-length` 的 304 (Not Modified) 响应：**
    - 客户端能够正确处理带有 `content-length` 头的 304 响应。

**与 JavaScript 的关系：**

虽然这段 C++ 代码直接与 JavaScript 无关，但它所测试的 HTTP/2 协议行为直接影响着浏览器中 JavaScript 发起的网络请求。

* **流量控制:**  JavaScript 发起的请求最终会受到浏览器底层 HTTP/2 实现的流量控制的影响。如果服务器发送速度过快，浏览器的 HTTP/2 实现会通过发送 WINDOW_UPDATE 帧来告知服务器可以继续发送数据。
* **状态码处理:** JavaScript 代码会根据 HTTP 响应的状态码 (例如 100, 204, 304) 执行不同的逻辑。这段测试确保了浏览器底层的 HTTP/2 实现正确处理这些状态码，避免了错误的数据或状态被传递给 JavaScript。例如，如果 JavaScript 代码期望一个 204 响应不包含任何内容，但底层的 HTTP/2 实现没有正确拒绝包含内容的 204 响应，可能会导致 JavaScript 代码出现意外行为。
* **Headers 和 Data 处理:** JavaScript 通过 `fetch` API 或 `XMLHttpRequest` 获取响应头和响应体。这段测试保证了底层的 HTTP/2 实现正确解析和传递这些信息，包括处理 padding 和 trailing headers 等细节。

**逻辑推理的假设输入与输出：**

**假设输入 (基于其中一个测试用例 `ClientHandlesResponseBeforeRequestComplete`)：**

* **客户端操作:**
    1. 创建一个 HTTP/2 连接。
    2. 构造一个 POST 请求头 (例如，`:method: POST`, `:path: /resource`)。
    3. 通过 `SubmitRequest` 提交请求头，但不立即发送请求体 (设置 `end_stream` 为 `false`)。
* **服务器操作:**
    1. 接收到客户端的请求头。
    2. 立即发送一个完整的 HTTP/2 响应头 (例如，`:status: 200`, `content-length: 2`)。
    3. 发送响应体数据 ("hi")，并设置 FIN 标志。
    4. (可选) 发送 Trailing Headers。
    5. (可选) 发送 RST_STREAM 帧。

**预期输出 (基于 `ClientHandlesResponseBeforeRequestComplete` 测试用例)：**

* **客户端行为:**
    1. 成功发送 SETTINGS 帧。
    2. 成功发送请求头 (HEADERS 帧)。
    3. 接收到服务器的响应头，触发 `OnBeginHeadersForStream` 和 `OnHeaderForStream` 回调。
    4. 接收到服务器的响应数据，触发 `OnBeginDataForStream` 和 `OnDataForStream` 回调。
    5. 接收到服务器的 FIN 标志，触发 `OnEndStream` 回调。
    6. (如果服务器发送了 Trailing Headers) 接收到 Trailing Headers，触发相应的回调。
    7. (如果服务器发送了 RST_STREAM 帧) 接收到 RST_STREAM 帧，触发 `OnRstStream` 回调。
    8. 最终客户端会发送 SETTINGS ACK 帧。
    9. 当客户端尝试发送剩余的请求体时，由于流已经关闭，可能会直接触发 `OnCloseStream` 回调。

**用户或编程常见的使用错误：**

* **服务器错误地发送带有内容的 204 或 304 响应：**  根据 HTTP 规范，204 和 304 响应通常不应包含消息体。服务器这样做会导致客户端连接错误或数据解析异常。
* **服务器在发送 100 响应时携带了不应该携带的信息：**  100 响应是临时响应，不应包含最终的元数据或消息体。
* **客户端未正确处理服务器发送的 RST_STREAM 帧：**  客户端应该能够优雅地处理 RST_STREAM 帧，停止对该流的进一步操作。
* **客户端在收到服务器的 FIN 后继续向该流发送数据：**  这会导致错误，因为流已经被服务器关闭。

**用户操作如何一步步到达这里 (作为调试线索)：**

假设用户在浏览器中访问一个网页：

1. **用户在浏览器地址栏输入 URL 并按下回车键，或者点击了一个链接。**
2. **浏览器解析 URL，并根据协议 (通常是 HTTPS) 建立与服务器的连接。** 对于 HTTPS，会先进行 TLS 握手。
3. **在 TLS 连接建立后，浏览器和服务器会协商使用 HTTP/2 协议 (如果双方都支持)。**
4. **浏览器构建 HTTP/2 请求，包括请求方法 (GET, POST 等)、路径、头部等信息。**  如果请求是 POST 并且有请求体，浏览器会准备发送请求体数据。
5. **浏览器底层的 HTTP/2 实现 (例如 Chromium 的网络栈) 会将请求头和请求体数据封装成 HTTP/2 帧 (HEADERS, DATA)。**
6. **如果服务器需要更多信息 (例如 Expect: 100-continue)，浏览器可能会先发送一个不带请求体的 HEADERS 帧。**
7. **服务器接收到请求，并根据需要发送响应。**  这段测试代码模拟了服务器发送各种类型的响应，包括状态码 100, 204, 304 以及包含或不包含内容、padding、trailing headers 的情况。
8. **浏览器底层的 HTTP/2 实现接收到服务器发送的 HTTP/2 帧，并调用 `OgHttp2Adapter` 的 `ProcessBytes` 方法进行解析。**
9. **`OgHttp2Adapter` 会根据接收到的帧类型和内容，调用 `TestVisitor` 中模拟的回调函数，例如 `OnFrameHeader`, `OnBeginHeadersForStream`, `OnDataForStream` 等。**  测试代码中的 `EXPECT_CALL` 语句就是用来验证这些回调函数是否被正确调用以及调用时携带的参数是否符合预期。
10. **如果发生错误 (例如服务器发送了带有内容的 204 响应)，`OgHttp2Adapter` 可能会发送 RST_STREAM 帧来关闭流。**
11. **最终，浏览器会将解析后的响应头和响应体数据传递给 JavaScript 代码 (通过 `fetch` API 的 Promise 或 `XMLHttpRequest` 的回调函数)。**

因此，当用户在浏览器中遇到网络请求错误或页面显示异常时，可以查看浏览器的开发者工具 (Network 选项卡) 来检查 HTTP 请求和响应的详细信息，包括状态码、头部、内容等，从而帮助定位问题是否与 HTTP/2 协议的实现有关。这段测试代码就是为了确保 Chromium 的 HTTP/2 实现能够正确处理各种边界情况，避免将错误传递到上层的 JavaScript 代码。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface()
          .SettingsAck()  // Ack of the client's initial settings.
          .Serialize();
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck);

  int64_t parse_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(parse_result));

  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1),
            kInitialFlowControlWindowSize);
  adapter->SubmitSettings({{INITIAL_WINDOW_SIZE, 80000u}});
  // No update for the first stream, yet.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1),
            kInitialFlowControlWindowSize);

  // Ack of server's initial settings.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  // Outbound SETTINGS containing INITIAL_WINDOW_SIZE.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);

  // Still no update, as a SETTINGS ack has not yet been received.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1),
            kInitialFlowControlWindowSize);

  const std::string settings_ack =
      TestFrameSequence().SettingsAck().Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck);

  parse_result = adapter->ProcessBytes(settings_ack);
  EXPECT_EQ(settings_ack.size(), static_cast<size_t>(parse_result));

  // Stream window has been updated.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id1), 80000);

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});
  const int32_t stream_id2 =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(stream_id2), 80000);
}

TEST(OgHttp2AdapterTest, ClientRejects100HeadersWithFin) {
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
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

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
          .Headers(1, {{":status", "100"}}, /*fin=*/false)
          .Headers(1, {{":status", "100"}}, /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  1, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, 1, _, 0x0, 1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ClientHandlesFinFollowing100Headers) {
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
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

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
          .Headers(stream_id1, {{":status", "100"}}, /*fin=*/false)
          .Data(stream_id1, "", /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(stream_id1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id1));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id1));

  EXPECT_CALL(visitor, OnFrameHeader(stream_id1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(stream_id1, _));
  // Behavior difference: nghttp2 generates a RST_STREAM PROTOCOL_ERROR.
  EXPECT_CALL(visitor, OnEndStream(stream_id1));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, ClientRejects100HeadersWithContent) {
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
          .Headers(1, {{":status", "100"}},
                   /*fin=*/false)
          .Data(1, "We needed the final headers before data, whoops")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ClientRejects100HeadersWithContentLength) {
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
          .Headers(1, {{":status", "100"}, {"content-length", "42"}},
                   /*fin=*/false)
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

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ClientHandlesResponseWithContentLengthAndPadding) {
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
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  // * Stream 1 sends a response with padding that exceeds the total
  //   Content-Length in the first DATA frame.
  // * Stream 3 sends a response with padding that exceeds the total
  //   Content-Length in the 2nd frame of 3.
  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "200"}, {"content-length", "2"}},
                   /*fin=*/false)
          .Data(1, "hi", /*fin=*/true, /*padding_length=*/10)
          .Headers(3, {{":status", "200"}, {"content-length", "24"}},
                   /*fin=*/false)
          .Data(3, "hi", false, 11)
          .Data(3, " it's nice", false, 12)
          .Data(3, " to meet you", true, 13)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // HEADERS for stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "content-length", "2"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  // DATA frame with padding for stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, 2 + 10, DATA, 0x9));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 2 + 10));
  EXPECT_CALL(visitor, OnDataPaddingLength(1, 10));
  EXPECT_CALL(visitor, OnDataForStream(1, "hi"));
  // END_STREAM for stream 1
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  // HEADERS for stream 3
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, "content-length", "24"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  // DATA frame with padding for stream 3 (1 of 3)
  EXPECT_CALL(visitor, OnFrameHeader(3, 2 + 11, DATA, 0x8));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 2 + 11));
  EXPECT_CALL(visitor, OnDataPaddingLength(3, 11));
  EXPECT_CALL(visitor, OnDataForStream(3, "hi"));
  // DATA frame with padding for stream 3 (2 of 3)
  EXPECT_CALL(visitor, OnFrameHeader(3, 10 + 12, DATA, 0x8));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 10 + 12));
  EXPECT_CALL(visitor, OnDataPaddingLength(3, 12));
  EXPECT_CALL(visitor, OnDataForStream(3, " it's nice"));
  // DATA frame with padding for stream 3 (3 of 3)
  EXPECT_CALL(visitor, OnFrameHeader(3, 12 + 13, DATA, 0x9));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 12 + 13));
  EXPECT_CALL(visitor, OnDataPaddingLength(3, 13));
  EXPECT_CALL(visitor, OnDataForStream(3, " to meet you"));
  // END_STREAM for stream 3
  EXPECT_CALL(visitor, OnEndStream(3));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({
                                  SpdyFrameType::SETTINGS,
                              }));
}

class ResponseCompleteBeforeRequestTest
    : public quiche::test::QuicheTestWithParam<std::tuple<bool, bool>> {
 public:
  bool HasTrailers() const { return std::get<0>(GetParam()); }
  bool HasRstStream() const { return std::get<1>(GetParam()); }
};

INSTANTIATE_TEST_SUITE_P(TrailersAndRstStreamAllCombinations,
                         ResponseCompleteBeforeRequestTest,
                         testing::Combine(testing::Bool(), testing::Bool()));

TEST_P(ResponseCompleteBeforeRequestTest,
       ClientHandlesResponseBeforeRequestComplete) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, std::move(body1), false, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor,
              OnBeforeFrameSent(HEADERS, stream_id1, _, END_HEADERS_FLAG));
  EXPECT_CALL(visitor,
              OnFrameSent(HEADERS, stream_id1, _, END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  // * The server sends a complete response on stream 1 before the client has
  //   finished sending the request.
  //   * If HasTrailers(), the response ends with trailing HEADERS.
  //   * If HasRstStream(), the response is followed by a RST_STREAM NO_ERROR,
  //     as the HTTP/2 spec recommends.
  TestFrameSequence response;
  response.ServerPreface()
      .Headers(1, {{":status", "200"}, {"content-length", "2"}},
               /*fin=*/false)
      .Data(1, "hi", /*fin=*/!HasTrailers(), /*padding_length=*/10);
  if (HasTrailers()) {
    response.Headers(1, {{"my-weird-trailer", "has a value"}}, /*fin=*/true);
  }
  if (HasRstStream()) {
    response.RstStream(1, Http2ErrorCode::HTTP2_NO_ERROR);
  }
  const std::string stream_frames = response.Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // HEADERS for stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "content-length", "2"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  // DATA frame with padding for stream 1
  EXPECT_CALL(visitor,
              OnFrameHeader(1, 2 + 10, DATA, HasTrailers() ? 0x8 : 0x9));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 2 + 10));
  EXPECT_CALL(visitor, OnDataPaddingLength(1, 10));
  EXPECT_CALL(visitor, OnDataForStream(1, "hi"));
  if (HasTrailers()) {
    // Trailers for stream 1
    EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
    EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
    EXPECT_CALL(visitor,
                OnHeaderForStream(1, "my-weird-trailer", "has a value"));
    EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  }
  // END_STREAM for stream 1
  EXPECT_CALL(visitor, OnEndStream(1));
  if (HasRstStream()) {
    EXPECT_CALL(visitor, OnFrameHeader(1, _, RST_STREAM, 0));
    EXPECT_CALL(visitor, OnRstStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
    EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
  }

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({
                                  SpdyFrameType::SETTINGS,
                              }));

  // Stream 1 is done in the request direction.
  if (!HasRstStream()) {
    visitor.AppendPayloadForStream(1, "final fragment");
  }
  visitor.SetEndData(1, true);
  adapter->ResumeStream(1);

  if (!HasRstStream()) {
    EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, END_STREAM_FLAG, 0));
    // The codec reports Stream 1 as closed.
    EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
  }

  result = adapter->Send();
  EXPECT_EQ(0, result);
}

TEST(OgHttp2AdapterTest, ClientHandles204WithContent) {
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
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "204"}, {"content-length", "2"}},
                   /*fin=*/false)
          .Data(1, "hi")
          .Headers(3, {{":status", "204"}}, /*fin=*/false)
          .Data(3, "hi")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "204"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":status", "204"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 2));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::RST_STREAM,
                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ClientHandles304WithContent) {
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ClientHandles304WithContentLength) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  ASSERT_GT(stream_id, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0,
```
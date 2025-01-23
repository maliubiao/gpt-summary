Response:
The user wants a summary of the functionality of the C++ code file `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc`. This file contains unit tests for the `OgHttp2Adapter` class, which is likely an adapter for a specific HTTP/2 implementation (oghttp2) within the Chromium network stack.

Here's a plan to generate the summary:

1. **Identify the core purpose:** The file tests the `OgHttp2Adapter`.
2. **Analyze individual test cases:**  Each test case focuses on a specific aspect of the adapter's behavior. I need to categorize these functionalities.
3. **Look for JavaScript relevance:**  Consider if any of the tested functionalities directly relate to how JavaScript interacts with HTTP/2 in a browser context.
4. **Examine test logic for assumptions and outputs:** Note down the setup (input), expected behavior, and assertions (output) for some representative tests.
5. **Identify common usage errors:** See if any tests highlight potential mistakes developers might make when using the adapter.
6. **Trace user actions to reach the code:** Think about the sequence of user interactions in a browser that could lead to the execution of this adapter code.
7. **Synthesize the information into a concise summary, keeping in mind this is part 5 of 12.**
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc` 文件的第五部分，该文件主要包含了一系列针对 `OgHttp2Adapter` 类的单元测试。`OgHttp2Adapter` 作为一个适配器，很可能是为了将底层的 HTTP/2 实现（此处可能是 oghttp2）适配到 Chromium 网络栈的更高层接口。

根据提供的代码片段，可以归纳出以下功能：

**已测试的功能点（基于提供的代码片段）:**

* **处理初始窗口设置导致的溢出 (客户端):** 测试当服务器发送一个非常大的 `INITIAL_WINDOW_SIZE` 设置，导致客户端流的流量控制窗口超出可接受范围时，客户端的处理行为，预期是发送 `RST_STREAM` 帧。
* **发送连接序言失败处理:** 测试当发送连接序言（包括 `SETTINGS` 帧）时发生写错误时，`OgHttp2Adapter` 的行为，预期会触发 `OnConnectionError` 回调。
* **`MAX_FRAME_SIZE` 设置生效时机:**  测试客户端发送 `MAX_FRAME_SIZE` 设置后，在收到服务器的 ACK 之前和之后，服务器发送的大 `DATA` 帧是否会被正确处理。
    * **ACK 前:**  如果服务器发送大于默认帧大小的 `DATA` 帧，客户端会因为违反帧大小限制而报告连接错误。
    * **ACK 后:** 如果服务器发送的 `DATA` 帧大小在新的 `MAX_FRAME_SIZE` 限制内，客户端应该能够正常处理。
* **客户端禁止 PUSH_PROMISE 帧:** 测试当客户端作为端点时，接收到服务器发送的 `PUSH_PROMISE` 帧时的处理行为，预期会报告连接错误。
* **客户端禁止接收推送流:** 测试当客户端作为端点时，接收到服务器主动发起的新的请求流（非通过 `PUSH_PROMISE`）时的处理行为，预期会报告连接错误。
* **处理发送 HEADERS 帧时发生写阻塞:** 测试当客户端发送请求头时遇到写阻塞的情况，`OgHttp2Adapter` 如何处理，包括重试发送。
* **接收已关闭流的数据:** 测试客户端主动关闭一个流（发送 `RST_STREAM`）后，仍然收到服务器发来的该流的数据帧时的处理行为，预期是会通知 Visitor，但不做进一步处理。
* **客户端遇到流量控制阻塞:** 测试客户端同时发送多个请求，并且数据量超过初始流量控制窗口时，发送行为如何被阻塞，以及接收到服务器的 `WINDOW_UPDATE` 帧后如何继续发送。
* **客户端在流量控制阻塞后发送尾部 (Trailers):** 测试客户端发送请求体数据受流量控制阻塞后，尝试发送尾部帧的行为。
* **客户端请求排队:** 测试客户端在 `MAX_CONCURRENT_STREAMS` 限制下发起多个请求时的排队机制，以及当 `MAX_CONCURRENT_STREAMS` 更新后，排队的请求如何被发送。

**与 JavaScript 功能的关系:**

这些底层 HTTP/2 适配器的测试与 JavaScript 的功能有密切关系，因为现代 Web 应用中，JavaScript 发起的网络请求 (例如通过 `fetch` API 或 `XMLHttpRequest`) 很大程度上依赖于 HTTP/2 协议。

* **初始窗口设置和流量控制:**  JavaScript 感知不到底层的流量控制细节，但流量控制的正确性直接影响到数据传输的速度和效率，最终影响 Web 应用的加载速度和用户体验。如果服务器设置了很大的初始窗口，而客户端没有正确处理，可能会导致连接不稳定或错误，最终导致 JavaScript 请求失败。
* **`MAX_FRAME_SIZE` 设置:**  虽然 JavaScript 代码不会直接操作帧大小，但浏览器会根据协商的 `MAX_FRAME_SIZE` 来处理接收到的数据。如果适配器未能正确处理 `MAX_FRAME_SIZE` 的变更，可能导致浏览器无法正确解析服务器响应，JavaScript 代码也无法获取到完整的数据。
* **PUSH_PROMISE 和推送流:**  如果服务器支持 HTTP/2 Server Push，浏览器会接收服务器主动推送的资源。这些测试确保了当客户端明确禁用 Server Push 时，适配器能够正确地拒绝 `PUSH_PROMISE` 和推送流，防止潜在的安全问题或资源滥用。虽然 JavaScript 代码可以直接使用推送的资源，但它本身不会直接控制是否启用 Server Push。
* **请求排队:**  `MAX_CONCURRENT_STREAMS` 限制了客户端可以同时发起的请求数量。这些测试保证了当并发请求达到限制时，后续的请求会被正确地排队，避免资源竞争和连接过载，从而保证 JavaScript 发起的多个请求能够有序地执行。

**逻辑推理的假设输入与输出:**

以 `TEST(OggHttp2AdapterClientTest, InitialWindowSettingCausesOverflow)` 为例：

* **假设输入:**
    * 客户端发送一个请求。
    * 服务器响应请求头。
    * 服务器发送一个 `WINDOW_UPDATE` 帧，增加流的窗口大小。
    * 服务器发送一个 `SETTINGS` 帧，将 `INITIAL_WINDOW_SIZE` 设置为一个非常大的值 (接近 2^31 - 1)。
* **预期输出:**
    * 客户端接收到 `SETTINGS` 帧后，发现流的有效窗口大小超出了限制。
    * 客户端发送一个 `RST_STREAM` 帧，错误码为 `FLOW_CONTROL_ERROR`。
    * 客户端关闭该流。

**用户或编程常见的使用错误:**

* **没有正确处理流量控制:**  开发者可能会在服务器端发送大量数据，而没有考虑到客户端的流量控制窗口，导致客户端连接被 RST。
* **错误地假设 `MAX_FRAME_SIZE` 立即生效:**  开发者可能在客户端发送设置 `MAX_FRAME_SIZE` 后，立即发送大于默认大小的帧，导致连接错误。正确的做法是等待服务器的 ACK。
* **在客户端启用 Server Push 的情况下，服务端错误地发送 PUSH_PROMISE 或推送流:** 虽然通常是服务器端的配置错误，但如果客户端没有正确处理这些帧，可能会导致程序崩溃或安全漏洞。
* **在流已经关闭后，仍然尝试在该流上发送或接收数据:** 这会导致未定义的行为，适配器需要正确处理这种情况。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个网站:**  例如，输入 URL 或点击链接。
2. **浏览器发起 HTTP/2 连接:** 浏览器与服务器建立 HTTP/2 连接。
3. **浏览器发送请求:** JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 发起一个或多个 HTTP 请求。
4. **`OgHttp2Adapter` 处理请求和响应:**  `OgHttp2Adapter` 负责将浏览器的请求转换为 HTTP/2 帧，并将服务器的 HTTP/2 帧转换回浏览器可以理解的数据。
5. **特定的 HTTP/2 场景触发测试用例:**  例如：
    * 服务器发送了包含 `INITIAL_WINDOW_SIZE` 的 `SETTINGS` 帧，触发了 `InitialWindowSettingCausesOverflow` 测试。
    * 网络环境不稳定导致发送数据时出现阻塞，可能触发了 `ClientSubmitRequestWithDataProviderAndWriteBlock` 测试。
    * 服务器尝试推送资源，触发了 `ClientForbidsPushPromise` 或 `ClientForbidsPushStream` 测试。
    * 服务器发送的数据帧大小超过了客户端已知的 `MAX_FRAME_SIZE`，触发了 `MaxFrameSizeSettingNotAppliedBeforeAck` 测试。

**归纳其功能 (作为第 5 部分，共 12 部分):**

这部分测试主要关注 `OgHttp2Adapter` 在作为 **客户端** 时的行为，特别是针对以下几个关键方面：

* **流量控制:**  包括对初始窗口大小的处理、发送和接收数据时的流量控制阻塞和恢复。
* **设置帧 (SETTINGS):**  包括对 `INITIAL_WINDOW_SIZE` 和 `MAX_FRAME_SIZE` 等设置的处理和生效时机。
* **Server Push 的处理:**  验证客户端作为接收方时，如何拒绝或处理来自服务器的推送请求。
* **连接管理:**  包括连接序言的发送、连接错误的报告和处理。
* **请求管理:**  包括请求的提交、排队以及在写阻塞时的处理。
* **流的生命周期管理:**  包括处理已关闭流上的数据。

总的来说，这部分测试旨在确保 `OgHttp2Adapter` 作为客户端能够正确、健壮地处理各种 HTTP/2 协议相关的场景和潜在的错误情况，保证了 Chromium 网络栈在作为 HTTP/2 客户端时的稳定性和可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
itial_frames.size(), static_cast<size_t>(initial_result));

  // Session will want to write a GOAWAY.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(GOAWAY, 0, _, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));

  int64_t result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
  visitor.Clear();
}

TEST(OggHttp2AdapterClientTest, InitialWindowSettingCausesOverflow) {
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
  int64_t write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  visitor.Clear();

  const uint32_t kLargeInitialWindow = (1u << 31) - 1;
  const std::string frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(stream_id, {{":status", "200"}}, /*fin=*/false)
          .WindowUpdate(stream_id, 65536u)
          .Settings({{INITIAL_WINDOW_SIZE, kLargeInitialWindow}})
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 0x4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, ":status", "200"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id));

  EXPECT_CALL(visitor, OnFrameHeader(stream_id, 4, WINDOW_UPDATE, 0x0));
  EXPECT_CALL(visitor, OnWindowUpdate(stream_id, 65536));

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{INITIAL_WINDOW_SIZE,
                                              kLargeInitialWindow}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  // The stream window update plus the SETTINGS frame with INITIAL_WINDOW_SIZE
  // pushes the stream's flow control window outside of the acceptable range.
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id, 4, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(RST_STREAM, stream_id, 4, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, FailureSendingConnectionPreface) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  visitor.set_has_write_error();
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kSendError));

  int result = adapter->Send();
  EXPECT_LT(result, 0);
}

TEST(OgHttp2AdapterTest, MaxFrameSizeSettingNotAppliedBeforeAck) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const uint32_t large_frame_size = kDefaultFramePayloadSizeLimit + 42;
  adapter->SubmitSettings({{MAX_FRAME_SIZE, large_frame_size}});
  const int32_t stream_id = adapter->SubmitRequest(
      ToHeaders({{":method", "GET"},
                 {":scheme", "https"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      /*data_source=*/nullptr, true, /*user_data=*/nullptr);
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(adapter->want_write());

  testing::InSequence s;

  // Client preface (SETTINGS with MAX_FRAME_SIZE) and request HEADERS
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string server_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "200"}}, /*fin=*/false)
          .Data(1, std::string(large_frame_size, 'a'))
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // Response HEADERS. Because the SETTINGS with MAX_FRAME_SIZE was not
  // acknowledged, the large DATA is treated as a connection error. Note that
  // oghttp2 delivers the DATA frame header and connection error events.
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, large_frame_size, DATA, 0x0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t process_result = adapter->ProcessBytes(server_frames);
  EXPECT_EQ(server_frames.size(), static_cast<size_t>(process_result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::FRAME_SIZE_ERROR)));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, MaxFrameSizeSettingAppliedAfterAck) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const uint32_t large_frame_size = kDefaultFramePayloadSizeLimit + 42;
  adapter->SubmitSettings({{MAX_FRAME_SIZE, large_frame_size}});
  const int32_t stream_id = adapter->SubmitRequest(
      ToHeaders({{":method", "GET"},
                 {":scheme", "https"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      /*data_source=*/nullptr, true, /*user_data=*/nullptr);
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(adapter->want_write());

  testing::InSequence s;

  // Client preface (SETTINGS with MAX_FRAME_SIZE) and request HEADERS
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string server_frames =
      TestFrameSequence()
          .ServerPreface()
          .SettingsAck()
          .Headers(1, {{":status", "200"}}, /*fin=*/false)
          .Data(1, std::string(large_frame_size, 'a'))
          .Serialize();

  // Server preface (empty SETTINGS) and ack of SETTINGS.
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck());

  // Response HEADERS and DATA. Because the SETTINGS with MAX_FRAME_SIZE was
  // acknowledged, the large DATA is accepted without any error.
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, large_frame_size, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, large_frame_size));
  EXPECT_CALL(visitor, OnDataForStream(1, _));

  const int64_t process_result = adapter->ProcessBytes(server_frames);
  EXPECT_EQ(server_frames.size(), static_cast<size_t>(process_result));

  // Client ack of SETTINGS.
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, ClientForbidsPushPromise) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));

  visitor.Clear();

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  ASSERT_GT(stream_id, 0);
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::vector<Header> push_headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/push"}});
  const std::string frames = TestFrameSequence()
                                 .ServerPreface()
                                 .SettingsAck()
                                 .PushPromise(stream_id, 2, push_headers)
                                 .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // SETTINGS ack (to acknowledge PUSH_ENABLED=0, though this is not explicitly
  // required for OgHttp2: should it be?)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck);

  // The PUSH_PROMISE is treated as an invalid frame.
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, PUSH_PROMISE, _));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidPushPromise));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ClientForbidsPushStream) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));

  visitor.Clear();

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  ASSERT_GT(stream_id, 0);
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string frames =
      TestFrameSequence()
          .ServerPreface()
          .SettingsAck()
          .Headers(2,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // SETTINGS ack (to acknowledge PUSH_ENABLED=0, though this is not explicitly
  // required for OgHttp2: should it be?)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck);

  // The push HEADERS are invalid.
  EXPECT_CALL(visitor, OnFrameHeader(2, _, HEADERS, _));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidNewStreamId));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

// This test verifies how oghttp2 behaves when a connection becomes
// write-blocked while sending HEADERS.
TEST(OgHttp2AdapterTest, ClientSubmitRequestWithDataProviderAndWriteBlock) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  // Flushes the connection preface.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const absl::string_view kBody = "This is an example request body.";

  std::unique_ptr<DataFrameSource> frame_source =
      std::make_unique<VisitorDataSource>(visitor, 1);
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, true);
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
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
  EXPECT_TRUE(adapter->want_write());

  // BUG: OnBeforeFrameSent() called twice.
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  visitor.set_is_write_blocked(false);
  result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterTest, ClientReceivesDataOnClosedStream) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Client SETTINGS ack
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

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
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

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
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR));

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

  // The visitor gets notified about the HEADERS frame and DATA frame for the
  // closed stream with no further processing on either frame.
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 0x4));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, DATA, END_STREAM_FLAG));

  const int64_t response_result = adapter->ProcessBytes(response_frames);
  EXPECT_EQ(response_frames.size(), static_cast<size_t>(response_result));

  EXPECT_FALSE(adapter->want_write());
}

TEST_P(OgHttp2AdapterDataTest, ClientEncountersFlowControlBlock) {
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

  const std::string kBody = std::string(100 * 1024, 'a');
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);

  const int32_t stream_id1 = adapter->SubmitRequest(
      headers1, GetParam() ? nullptr : std::move(body1), false, nullptr);
  ASSERT_GT(stream_id1, 0);

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});

  visitor.AppendPayloadForStream(3, kBody);
  visitor.SetEndData(3, false);
  auto body2 = std::make_unique<VisitorDataSource>(visitor, 3);

  const int32_t stream_id2 = adapter->SubmitRequest(
      headers2, GetParam() ? nullptr : std::move(body2), false, nullptr);
  ASSERT_EQ(stream_id2, 3);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _, 0x4, 0));
  // 4 DATA frames should saturate the default 64kB stream/connection flow
  // control window.
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id1, _, 0x0, 0)).Times(4);

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_EQ(0, adapter->GetSendWindowSize());

  const std::string stream_frames = TestFrameSequence()
                                        .ServerPreface()
                                        .WindowUpdate(0, 80000)
                                        .WindowUpdate(stream_id1, 20000)
                                        .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 80000));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 20000));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id2, _, 0x0, 0))
      .Times(testing::AtLeast(1));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id1, _, 0x0, 0))
      .Times(testing::AtLeast(1));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
}

TEST_P(OgHttp2AdapterDataTest, ClientSendsTrailersAfterFlowControlBlock) {
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

  visitor.AppendPayloadForStream(1, "Really small body.");
  visitor.SetEndData(1, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);

  const int32_t stream_id1 = adapter->SubmitRequest(
      headers1, GetParam() ? nullptr : std::move(body1), false, nullptr);
  ASSERT_GT(stream_id1, 0);

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});

  const std::string kBody = std::string(100 * 1024, 'a');
  visitor.AppendPayloadForStream(3, kBody);
  visitor.SetEndData(3, false);
  auto body2 = std::make_unique<VisitorDataSource>(visitor, 3);

  const int32_t stream_id2 = adapter->SubmitRequest(
      headers2, GetParam() ? nullptr : std::move(body2), false, nullptr);
  ASSERT_GT(stream_id2, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id1, _, 0x0, 0)).Times(1);
  // 4 DATA frames should saturate the default 64kB stream/connection flow
  // control window.
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id2, _, 0x0, 0)).Times(4);

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_FALSE(adapter->want_write());
  EXPECT_EQ(0, adapter->GetSendWindowSize());

  const std::vector<Header> trailers1 =
      ToHeaders({{"extra-info", "Trailers are weird but good?"}});
  adapter->SubmitTrailer(stream_id1, trailers1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
}

TEST(OgHttp2AdapterTest, ClientQueuesRequests) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

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
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[0], _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[0], _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[1], _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[1], _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[2], _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[2], _,
                                   END_STREAM_FLA
```
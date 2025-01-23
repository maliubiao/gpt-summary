Response:
The user wants to understand the functionality of the C++ source code file `nghttp2_adapter_test.cc`. This file is part of Chromium's network stack, specifically within the QUIC implementation's HTTP/2 adapter. Since this is part 10 of 11, I should focus on summarizing the overall purpose as well.

Here's a breakdown of the thinking process to answer the user's request:

1. **Identify the core purpose:** The filename strongly suggests this is a test file. The `_test.cc` suffix is a common convention for unit tests. The "adapter" part indicates it's testing the `NgHttp2Adapter` class.

2. **Analyze the structure:**  The code is organized into `TEST` macros. This confirms it's using a testing framework (likely Google Test, given the Chromium context and the syntax). Each `TEST` block likely focuses on a specific aspect of the `NgHttp2Adapter`'s behavior.

3. **Scan the test names:** The names like `StreamMetadataBeforeReset`, `ServerStartsShutdown`, `ServerDoesNotSendFramesAfterImmediateGoAway`, `ServerHandlesContentLength`, etc., provide clear hints about the functionalities being tested.

4. **Examine the test logic:** Within each `TEST` block:
    * **Setup:**  Often involves creating an `NgHttp2Adapter` instance (either server or client) and a `TestVisitor`. The `TestVisitor` is a mock object used to observe the calls made by the `NgHttp2Adapter`.
    * **Actions:**  The tests simulate various HTTP/2 interactions by calling methods on the `NgHttp2Adapter`, like `ProcessBytes`, `SubmitResponse`, `SubmitShutdownNotice`, `SubmitMetadata`, etc. They also manipulate the `TestVisitor`'s data.
    * **Assertions:**  The tests use `EXPECT_CALL` to verify that the `NgHttp2Adapter` interacts with its visitor in the expected way (e.g., sending specific frames). They also use `EXPECT_EQ` and `EXPECT_THAT` to check the state of the adapter and the data received by the visitor.

5. **Infer functionalities based on test names and logic:** By combining the test names and the actions performed within the tests, I can list the functionalities being tested. For instance, `StreamMetadataBeforeReset` clearly tests the behavior of metadata submission when a stream is reset.

6. **Check for JavaScript relevance:** HTTP/2 is the underlying protocol for web communication. While this C++ code doesn't directly interact with JavaScript, its correct functioning is crucial for how JavaScript running in a browser interacts with web servers. I need to explain this indirect relationship.

7. **Generate examples for logic and common errors:**  For tests that involve processing bytes (like handling content length), I can create hypothetical input HTTP/2 frame sequences and predict the adapter's behavior (output frames, visitor calls). For common errors, I can point to scenarios where a user might provide incorrect data (like a mismatched content length) and explain how the adapter handles it.

8. **Explain user actions leading to this code:** Since this is part of the network stack, typical user interactions like browsing a website, making API calls, etc., can trigger the execution of this code. The key is to trace the path from user action to the handling of HTTP/2 frames.

9. **Summarize the overall function (for part 10 of 11):**  Given that this is a test file, the primary function is to ensure the `NgHttp2Adapter` works correctly. Since it's a later part of the series, I should emphasize that it builds upon the foundational aspects tested in earlier parts.

10. **Review and refine:** Ensure the explanation is clear, concise, and accurately reflects the code's purpose and functionality. Make sure to address all parts of the user's request. For example, ensure the output for logical reasoning examples is clearly linked to the input.

By following these steps, I can generate a comprehensive answer that addresses all aspects of the user's request and provides valuable insights into the functionality of the provided code snippet.
这个C++源代码文件 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc` 是 Chromium 网络栈中 QUIC 协议 HTTP/2 适配器 `NgHttp2Adapter` 的单元测试文件。它使用 Google Test 框架来验证 `NgHttp2Adapter` 类的各种功能和行为。

**主要功能归纳:**

1. **测试 `NgHttp2Adapter` 作为 HTTP/2 服务器和客户端的功能:**  文件中包含了针对服务器模式和客户端模式下 `NgHttp2Adapter` 的测试用例。

2. **测试 HTTP/2 帧的处理:**  测试了 `NgHttp2Adapter` 如何处理各种 HTTP/2 帧，例如：
    * `SETTINGS` (设置)
    * `HEADERS` (首部)
    * `DATA` (数据)
    * `RST_STREAM` (重置流)
    * `GOAWAY` (停止连接)
    * `WINDOW_UPDATE` (窗口更新)
    * `PING` (心跳)
    * 自定义的 `kMetadataFrameType` (元数据帧)

3. **测试流的管理:**  测试了 `NgHttp2Adapter` 如何创建、管理和关闭 HTTP/2 流，包括处理流的生命周期事件，例如流的开始和结束。

4. **测试首部和数据的处理:**  验证了 `NgHttp2Adapter` 如何正确解析和传递首部和数据给上层应用。这包括测试各种首部字段，例如 `:method`, `:scheme`, `:authority`, `:path`, `content-length`, `te`, `connection` 等。

5. **测试错误处理:**  测试了 `NgHttp2Adapter` 如何处理各种错误情况，例如：
    * 无效的帧
    * 协议错误 (例如无效的首部字段，内容长度不匹配)
    * 连接错误
    * 流被重置

6. **测试连接关闭和终止:**  验证了 `NgHttp2Adapter` 如何发起和处理连接关闭以及 `GOAWAY` 帧。

7. **测试元数据 (Metadata) 的处理:**  测试了 `NgHttp2Adapter` 如何提交和发送元数据帧。

**与 JavaScript 功能的关系 (间接关系):**

虽然此 C++ 文件本身不包含 JavaScript 代码，但它测试的网络协议 (HTTP/2) 是现代 Web 应用的基础。JavaScript 在浏览器中发起网络请求时，底层会使用 HTTP/2 (如果服务器支持)。`NgHttp2Adapter` 的正确性直接影响到 JavaScript 发起的请求是否能够成功发送和接收数据。

**举例说明:**

假设一个 JavaScript 代码发起一个带有特定首部的 HTTP/2 GET 请求：

```javascript
fetch('https://example.com/data', {
  headers: {
    'X-Custom-Header': 'some-value'
  }
});
```

`nghttp2_adapter_test.cc` 中的测试用例会验证 `NgHttp2Adapter` 是否能够正确地将 JavaScript 代码设置的 `X-Custom-Header` 包含在发送给服务器的 HTTP/2 `HEADERS` 帧中，并且能够正确处理服务器返回的 `HEADERS` 帧和 `DATA` 帧。

**逻辑推理 (假设输入与输出):**

**假设输入:**  `NgHttp2Adapter` 接收到一个包含 `content-length: 5` 首部和一个长度为 3 的数据帧的 HTTP/2 请求。

**输出:** `NgHttp2Adapter` 会检测到内容长度不匹配，可能会调用 `TestVisitor` 的 `OnInvalidFrame` 方法，并可能发送一个 `RST_STREAM` 帧来终止该流，并带有 `PROTOCOL_ERROR` 错误码。

**用户或编程常见的使用错误 (举例说明):**

1. **发送不符合 HTTP/2 规范的首部:** 用户或程序员可能会在客户端或服务器端设置无效的首部字段名或值。例如，发送包含空格的首部字段名。测试用例会验证 `NgHttp2Adapter` 是否能够检测到这些错误并采取适当的行动 (例如，发送 `RST_STREAM`)。

   ```c++
   TEST(NgHttp2AdapterTest, ServerHandlesInvalidHeaders) {
     // ...
     const std::string stream_frames =
         TestFrameSequence()
             .ClientPreface()
             .Headers(1,
                      {{":method", "GET"},
                       {":scheme", "https"},
                       {":authority", "example.com"},
                       {"Invalid Header Name", "value"}}, // 错误：首部名包含空格
                      /*fin=*/true)
             .Serialize();
     // ...
   }
   ```

2. **内容长度不匹配:** 程序员可能在发送数据时错误地设置了 `content-length` 首部，使其与实际发送的数据长度不符。测试用例会验证 `NgHttp2Adapter` 是否能够检测到这种不一致并进行处理。

   ```c++
   TEST(NgHttp2AdapterTest, ServerHandlesContentLengthMismatch) {
     // ...
     const std::string stream_frames =
         TestFrameSequence()
             .ClientPreface()
             .Headers(1, {{"content-length", "2"}})
             .Data(1, "h", /*fin=*/true) // 实际数据长度为 1，但 content-length 为 2
             .Serialize();
     // ...
   }
   ```

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入网址并访问一个 HTTPS 网站。**
2. **浏览器发起一个 HTTP/2 连接到服务器。**
3. **浏览器使用 JavaScript (或其他方式) 发起一个网络请求 (例如，通过 `fetch` API)。**
4. **浏览器网络栈中的代码会将该请求转换为 HTTP/2 帧。**
5. **`NgHttp2Adapter` 类负责处理这些 HTTP/2 帧的创建和解析。**
6. **如果在处理过程中出现任何问题，例如接收到无效的帧或遇到协议错误，那么相关的错误处理逻辑就会被触发，这部分逻辑正是 `nghttp2_adapter_test.cc` 所测试的。**

在调试网络问题时，如果怀疑是 HTTP/2 协议层的问题，开发者可能会查看 `NgHttp2Adapter` 的日志或使用网络抓包工具 (例如 Wireshark) 来分析实际发送和接收的 HTTP/2 帧，从而定位问题可能发生在 `NgHttp2Adapter` 的哪个环节。`nghttp2_adapter_test.cc` 中覆盖的各种测试用例可以帮助开发者理解 `NgHttp2Adapter` 在不同场景下的行为，从而更好地排查问题。

**作为第 10 部分，共 11 部分，它的功能归纳:**

作为单元测试套件的一部分，这个特定的文件 (`nghttp2_adapter_test.cc`) 的功能是**对 `NgHttp2Adapter` 类进行全面的功能测试，涵盖了其在作为 HTTP/2 服务器处理各种复杂场景的能力**。由于是接近尾声的部分，它可能侧重于测试一些更精细或特定的边缘情况，以及确保在集成更多功能后，核心的 HTTP/2 协议处理逻辑依然正确。它与其他测试文件一起，共同确保 `NgHttp2Adapter` 的稳定性和可靠性，为 Chromium 网络栈的 HTTP/2 功能提供保障。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
Stream(1, Http2ErrorCode::CANCEL));
  adapter->ProcessBytes(reset_frame);

  source = std::make_unique<TestMetadataSource>(
      ToHeaderBlock(ToHeaders({{"really-important", "information!"}})));
  adapter->SubmitMetadata(1, 16384u, std::move(source));

  EXPECT_EQ(1, adapter->stream_metadata_size());
  EXPECT_EQ(2, adapter->pending_metadata_count(1));

  // Server initial SETTINGS and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  // nghttp2 apparently allows extension frames to be sent on reset streams.
  // The response HEADERS, DATA and WINDOW_UPDATE are all discarded.
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS,
                            static_cast<SpdyFrameType>(kMetadataFrameType),
                            static_cast<SpdyFrameType>(kMetadataFrameType)}));

  EXPECT_EQ(0, adapter->stream_metadata_size());
  EXPECT_EQ(0, adapter->pending_metadata_count(1));
}

TEST(NgHttp2AdapterTest, ServerStartsShutdown) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  EXPECT_FALSE(adapter->want_write());

  adapter->SubmitShutdownNotice();
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(GOAWAY, 0, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(NgHttp2AdapterTest, ServerStartsShutdownAfterGoaway) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  EXPECT_FALSE(adapter->want_write());

  adapter->SubmitGoAway(1, Http2ErrorCode::HTTP2_NO_ERROR,
                        "and don't come back!");
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(GOAWAY, 0, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));

  // No-op, since a GOAWAY has previously been enqueued.
  adapter->SubmitShutdownNotice();
  EXPECT_FALSE(adapter->want_write());
}

// Verifies that a connection-level processing error results in repeatedly
// returning a positive value for ProcessBytes() to mark all data as consumed.
TEST(NgHttp2AdapterTest, ConnectionErrorWithBlackholeSinkingData) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames =
      TestFrameSequence().ClientPreface().WindowUpdate(1, 42).Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnInvalidFrame(1, _));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  // Ask the connection to process more bytes. Because the option is enabled,
  // the data should be marked as consumed.
  const std::string next_frame = TestFrameSequence().Ping(42).Serialize();
  const int64_t next_result = adapter->ProcessBytes(next_frame);
  EXPECT_EQ(static_cast<size_t>(next_result), next_frame.size());
}

TEST_P(NgHttp2AdapterDataTest, ServerDoesNotSendFramesAfterImmediateGoAway) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  // Submit a custom initial SETTINGS frame with one setting.
  adapter->SubmitSettings({{HEADER_TABLE_SIZE, 100u}});

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  // Submit a response for the stream.
  visitor.AppendPayloadForStream(1, "This data is doomed to never be written.");
  auto body = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}),
                              GetParam() ? nullptr : std::move(body), false);
  ASSERT_EQ(0, submit_result);

  // Submit a WINDOW_UPDATE frame.
  adapter->SubmitWindowUpdate(kConnectionStreamId, 42);

  // Submit another SETTINGS frame.
  adapter->SubmitSettings({});

  // Submit some metadata.
  auto source = std::make_unique<TestMetadataSource>(ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}})));
  adapter->SubmitMetadata(1, 16384u, std::move(source));

  EXPECT_TRUE(adapter->want_write());

  // Trigger a connection error. Only the response headers will be written.
  const std::string connection_error_frames =
      TestFrameSequence().WindowUpdate(3, 42).Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(3, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnInvalidFrame(3, _));

  const int64_t result = adapter->ProcessBytes(connection_error_frames);
  EXPECT_EQ(static_cast<size_t>(result), connection_error_frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // The GOAWAY apparently causes the other frames to be dropped except for the
  // non-ack SETTINGS frames; nghttp2 sends non-ack SETTINGS frames because they
  // could be the initial SETTINGS frame. However, nghttp2 still allows sending
  // multiple non-ack SETTINGS, which feels non-ideal.
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::GOAWAY}));
  visitor.Clear();

  // Try to submit more frames for writing. They should not be written.
  adapter->SubmitPing(42);
  EXPECT_FALSE(adapter->want_write());
  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
}

TEST(NgHttp2AdapterTest, ServerHandlesContentLength) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  testing::InSequence s;

  const std::string stream_frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1, {{":method", "GET"},
                       {":scheme", "https"},
                       {":authority", "example.com"},
                       {":path", "/this/is/request/one"},
                       {"content-length", "2"}})
          .Data(1, "hi", /*fin=*/true)
          .Headers(3,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/two"},
                    {"content-length", "nan"}},
                   /*fin=*/true)
          .Serialize();

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // Stream 1: content-length is correct
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 2));
  EXPECT_CALL(visitor, OnDataForStream(1, "hi"));
  EXPECT_CALL(visitor, OnEndStream(1));

  // Stream 3: content-length is not a number
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 3, name: [content-length], value: [nan]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ServerHandlesContentLengthMismatch) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  testing::InSequence s;

  const std::string stream_frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1, {{":method", "GET"},
                       {":scheme", "https"},
                       {":authority", "example.com"},
                       {":path", "/this/is/request/two"},
                       {"content-length", "2"}})
          .Data(1, "h", /*fin=*/true)
          .Headers(3, {{":method", "GET"},
                       {":scheme", "https"},
                       {":authority", "example.com"},
                       {":path", "/this/is/request/three"},
                       {"content-length", "2"}})
          .Data(3, "howdy", /*fin=*/true)
          .Headers(5,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/four"},
                    {"content-length", "2"}},
                   /*fin=*/true)
          .Headers(7,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/four"},
                    {"content-length", "2"}},
                   /*fin=*/false)
          .Data(7, "h", /*fin=*/false)
          .Headers(7, {{"extra-info", "Trailers with content-length mismatch"}},
                   /*fin=*/true)
          .Serialize();

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // Stream 1: content-length is larger than actual data
  // All data is delivered to the visitor, but OnInvalidFrame() is not.
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 1));
  EXPECT_CALL(visitor, OnDataForStream(1, "h"));

  // Stream 3: content-length is smaller than actual data
  // The beginning of data is delivered to the visitor, but not the actual data,
  // and neither is OnInvalidFrame().
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 5));

  // Stream 5: content-length is invalid and HEADERS ends the stream
  // When the stream ends with HEADERS, nghttp2 invokes OnInvalidFrame().
  EXPECT_CALL(visitor, OnFrameHeader(5, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(5));
  EXPECT_CALL(visitor, OnHeaderForStream(5, _, _)).Times(5);
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  5, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  // Stream 7: content-length is invalid and trailers end the stream
  // When the stream ends with trailers, nghttp2 invokes OnInvalidFrame().
  EXPECT_CALL(visitor, OnFrameHeader(7, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(7));
  EXPECT_CALL(visitor, OnHeaderForStream(7, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(7));
  EXPECT_CALL(visitor, OnFrameHeader(7, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(7, 1));
  EXPECT_CALL(visitor, OnDataForStream(7, "h"));
  EXPECT_CALL(visitor, OnFrameHeader(7, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(7));
  EXPECT_CALL(visitor, OnHeaderForStream(7, _, _));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  7, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 5, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 5, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 7, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 7, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(7, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::RST_STREAM,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM,
                    SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ServerHandlesAsteriskPathForOptions) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  testing::InSequence s;

  const std::string stream_frames = TestFrameSequence()
                                        .ClientPreface()
                                        .Headers(1,
                                                 {{":scheme", "https"},
                                                  {":authority", "example.com"},
                                                  {":path", "*"},
                                                  {":method", "OPTIONS"}},
                                                 /*fin=*/true)
                                        .Serialize();

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ServerHandlesInvalidPath) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  testing::InSequence s;

  const std::string stream_frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "*"},
                    {":method", "GET"}},
                   /*fin=*/true)
          .Headers(3,
                   {{":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "other/non/slash/starter"},
                    {":method", "GET"}},
                   /*fin=*/true)
          .Headers(5,
                   {{":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", ""},
                    {":method", "GET"}},
                   /*fin=*/true)
          .Serialize();

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  1, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(4);
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  3, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  EXPECT_CALL(visitor, OnFrameHeader(5, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(5));
  EXPECT_CALL(visitor, OnHeaderForStream(5, _, _)).Times(2);
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 5, name: [:path], value: []"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(5, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 5, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 5, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::RST_STREAM,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ServerHandlesTeHeader) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  testing::InSequence s;

  const std::string stream_frames = TestFrameSequence()
                                        .ClientPreface()
                                        .Headers(1,
                                                 {{":scheme", "https"},
                                                  {":authority", "example.com"},
                                                  {":path", "/"},
                                                  {":method", "GET"},
                                                  {"te", "trailers"}},
                                                 /*fin=*/true)
                                        .Headers(3,
                                                 {{":scheme", "https"},
                                                  {":authority", "example.com"},
                                                  {":path", "/"},
                                                  {":method", "GET"},
                                                  {"te", "trailers, deflate"}},
                                                 /*fin=*/true)
                                        .Serialize();

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // Stream 1: TE: trailers should be allowed.
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  // Stream 3: TE: <non-trailers> should be rejected.
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 3, name: [te], value: [trailers, deflate]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ServerHandlesConnectionSpecificHeaders) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  testing::InSequence s;

  const std::string stream_frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/"},
                    {":method", "GET"},
                    {"connection", "keep-alive"}},
                   /*fin=*/true)
          .Headers(3,
                   {{":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/"},
                    {":method", "GET"},
                    {"proxy-connection", "keep-alive"}},
                   /*fin=*/true)
          .Headers(5,
                   {{":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/"},
                    {":method", "GET"},
                    {"keep-alive", "timeout=42"}},
                   /*fin=*/true)
          .Headers(7,
                   {{":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/"},
                    {":method", "GET"},
                    {"transfer-encoding", "chunked"}},
                   /*fin=*/true)
          .Headers(9,
                   {{":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/"},
                    {":method", "GET"},
                    {"upgrade", "h2c"}},
                   /*fin=*/true)
          .Serialize();

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // All streams contain a connection-specific header and should be rejected.
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 1, name: [connection], value: [keep-alive]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 3, name: [proxy-connection], value: [keep-alive]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(5, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(5));
  EXPECT_CALL(visitor, OnHeaderForStream(5, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 5, name: [keep-alive], value: [timeout=42]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(5, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(7, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(7));
  EXPECT_CALL(visitor, OnHeaderForStream(7, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 7, name: [transfer-encoding], value: [chunked]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(7, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(9, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(9));
  EXPECT_CALL(visitor, OnHeaderForStream(9, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 9, name: [upgrade], value: [h2c]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(9, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 5, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 5, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 7, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 7, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(7, Http2ErrorCode::PROTOCOL_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 9, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 9, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(9, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::RST_STREAM,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerConsumesDataWithPadding) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  TestFrameSequence seq = std::move(TestFrameSequence().ClientPreface().Headers(
      1,
      {{":method", "POST"},
       {":scheme", "https"},
       {":authority", "example.com"},
       {":path", "/this/is/request/one"}},
      /*fin=*/false));
  // Generates a bunch of DATA frames, with the bulk of the payloads consisting
  // of padding.
  size_t total_size = 0;
  while (total_size < 62 * 1024) {
    seq.Data(1, "a", /*fin=*/false, /*padding=*/254);
    total_size += 255;
  }
  const std::string frames = seq.Serialize();

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0x8))
      .Times(testing::AtLeast(1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _)).Times(testing::AtLeast(1));
  EXPECT_CALL(visitor, OnDataForStream(1, "a")).Times(testing::AtLeast(1));
  EXPECT_CALL(visitor, OnDataPaddingLength(1, _)).Times(testing::AtLeast(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(result, frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  // Sin
```
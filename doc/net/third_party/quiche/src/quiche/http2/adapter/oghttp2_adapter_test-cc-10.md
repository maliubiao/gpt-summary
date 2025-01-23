Response:
The user wants to understand the functionality of the C++ source code file `oghttp2_adapter_test.cc`. This file appears to be a unit test file for an HTTP/2 adapter within the Chromium network stack.

Here's a breakdown of how to address the user's request:

1. **High-Level Functionality:** Summarize the main purpose of the file, which is to test the `OgHttp2Adapter`.

2. **Relationship with JavaScript:** Determine if the adapter or its tests directly interact with JavaScript. Given its location in the network stack and the nature of HTTP/2 adapters, the interaction is likely indirect.

3. **Logical Reasoning (Tests):**  Analyze the provided code snippets, which are individual test cases. For each test, identify the setup, input (HTTP/2 frames), expected behavior (visitor calls), and assertions. Provide examples of input and expected output based on the test logic.

4. **Common Usage Errors:** Think about common mistakes developers might make when using or implementing HTTP/2 adapters or handling HTTP/2 communication.

5. **User Operations (Debugging):** Consider how a user's interaction with a web browser could lead to the execution of this code during debugging.

6. **File Summary (Part 11 of 12):**  Given that this is part 11, it's likely this file contains various test cases covering different aspects of the adapter's functionality.

**Mental Walkthrough of the Code Snippets:**

* **`ConnectionErrorWithBlackholingData` and `ConnectionErrorWithoutBlackholingData`:** These tests focus on how the adapter handles connection-level errors, specifically the `kWrongFrameSequence` error. They explore the behavior with and without the `blackhole_data_on_connection_error` option. The input is a client preface followed by an invalid `WINDOW_UPDATE` frame. The expected output is a connection error reported to the visitor.

* **`ServerDoesNotSendFramesAfterImmediateGoAway`:** This test simulates a scenario where the server sends a `GOAWAY` frame immediately after encountering an error. It checks that the adapter stops sending further frames after sending the `GOAWAY`. The input includes a valid request followed by an invalid `WINDOW_UPDATE` that triggers the error.

* **`ServerHandlesContentLength` and `ServerHandlesContentLengthMismatch`:** These tests verify how the server-side adapter deals with the `content-length` header. They check scenarios with correct lengths, incorrect numeric formats, and mismatches between the declared length and the actual data sent. The input involves different combinations of `HEADERS` and `DATA` frames with varying `content-length` values.

* **`ServerHandlesAsteriskPathForOptions`:** This test checks if the server correctly handles a request with an asterisk (`*`) in the `:path` pseudo-header for the `OPTIONS` method.

* **`ServerHandlesInvalidPath`:** This test checks how the server handles various invalid values in the `:path` pseudo-header.

* **`ServerHandlesTeHeader`:** This test verifies the server's handling of the `te` header, specifically if it allows "trailers" but rejects other values.

* **`ServerHandlesConnectionSpecificHeaders`:** This test examines how the server rejects requests containing HTTP/1.1 connection-specific headers like "connection", "proxy-connection", "keep-alive", "transfer-encoding", and "upgrade".

* **`ServerUsesCustomWindowUpdateStrategy`:** This test demonstrates the use of a custom function to decide when to send `WINDOW_UPDATE` frames.

* **`ServerConsumesDataWithPadding`:** This test (partially shown) likely examines how the server-side adapter processes `DATA` frames that include padding.

By analyzing these tests, I can deduce the file's overall purpose and provide specific examples related to each test case.
这个文件是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc` 的源代码文件，它主要的功能是 **测试 `OgHttp2Adapter` 类**。

`OgHttp2Adapter` 是一个 HTTP/2 协议的适配器，它的作用是在底层的 HTTP/2 协议实现（可能是 `nghttp2` 或者其他类似的库）和上层 Chromium 网络栈之间提供一个抽象层。这个适配器负责处理 HTTP/2 帧的接收、解析、生成和发送，以及管理 HTTP/2 连接的状态。

**主要功能归纳:**

* **单元测试:** 该文件包含了大量的单元测试用例，用于验证 `OgHttp2Adapter` 类的各种功能和边界情况。
* **协议状态机测试:** 测试适配器在不同 HTTP/2 协议状态下的行为，例如连接建立、流的创建和关闭、错误处理等。
* **帧处理测试:** 测试适配器如何处理各种类型的 HTTP/2 帧，例如 `SETTINGS`、`HEADERS`、`DATA`、`WINDOW_UPDATE`、`RST_STREAM`、`GOAWAY` 等。
* **错误处理测试:** 测试适配器在遇到协议错误或不符合规范的帧时如何处理，例如发送 `RST_STREAM` 或 `GOAWAY` 帧。
* **选项配置测试:** 测试 `OgHttp2Adapter` 的各种选项配置是否生效，例如是否启用黑洞模式、是否使用自定义的窗口更新策略等。
* **服务器和客户端视角测试:**  测试用例涵盖了作为服务器和客户端两种角色时 `OgHttp2Adapter` 的行为。
* **HTTP语义测试:** 测试适配器是否正确处理 HTTP 的语义，例如 `content-length` 头的处理、特殊路径的处理、连接特定头的处理等。

**与 JavaScript 的关系:**

`OgHttp2Adapter` 本身是用 C++ 编写的，直接与 JavaScript 没有直接的交互。然而，它所处理的 HTTP/2 协议是 Web 浏览器（通常使用 JavaScript 编写的 Web 应用）与服务器通信的基础。

**举例说明:**

假设一个 JavaScript Web 应用通过浏览器发起一个 HTTP/2 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，浏览器内部的网络栈会使用类似 `OgHttp2Adapter` 的组件来处理底层的 HTTP/2 通信。

* **JavaScript 发起请求:** `fetch()` 函数在 JavaScript 中被调用。
* **浏览器处理请求:** 浏览器会将这个请求转换为一系列的 HTTP/2 帧，例如 `HEADERS` 帧（包含请求方法、URL、头部等）。
* **`OgHttp2Adapter` 处理发送:**  `OgHttp2Adapter`（或类似的组件）负责将这些帧序列化并通过 TCP 连接发送到服务器。
* **`OgHttp2Adapter` 处理接收:**  当服务器返回响应时，`OgHttp2Adapter` 接收来自服务器的 HTTP/2 帧（例如 `HEADERS` 帧包含状态码和响应头，`DATA` 帧包含响应体）。
* **传递给上层:**  `OgHttp2Adapter` 解析这些帧，并将解析后的数据传递给浏览器网络栈的上层。
* **JavaScript 接收响应:** 浏览器最终将响应传递给 JavaScript 的 `fetch()` API 的 `then()` 回调函数。

**逻辑推理与假设输入/输出:**

**测试用例示例 (基于提供的代码片段):**

**测试用例:** `ConnectionErrorWithBlackholingData`

* **假设输入:**  一个包含客户端序言和一个错误的 `WINDOW_UPDATE` 帧的字节流。
  ```
  frames = TestFrameSequence().ClientPreface().WindowUpdate(1, 4).Serialize();
  ```
  这代表客户端发送了连接序言（`SETTINGS` 帧），然后发送了一个针对 Stream 1 的 `WINDOW_UPDATE` 帧，但是这个帧在连接的这个阶段是不应该出现的。

* **预期输出:**
    * `visitor.OnFrameHeader(0, 0, SETTINGS, 0)`: 收到客户端的 `SETTINGS` 帧头。
    * `visitor.OnSettingsStart()`: 开始处理 `SETTINGS` 帧。
    * `visitor.OnSettingsEnd()`: 完成处理 `SETTINGS` 帧。
    * `visitor.OnFrameHeader(1, 4, WINDOW_UPDATE, 0)`: 收到错误的 `WINDOW_UPDATE` 帧头。
    * `visitor.OnConnectionError(ConnectionError::kWrongFrameSequence)`:  `OgHttp2Adapter` 检测到错误的帧序列，通知 Visitor 发生了连接错误。
    * `adapter->ProcessBytes(frames)` 返回值等于 `frames.size()`，表示所有字节都被“黑洞”吸收，没有进一步处理。
    * 后续的有效 `PING` 帧也被成功“黑洞”吸收。

**测试用例:** `ServerHandlesContentLength`

* **假设输入:**  一个包含客户端序言、一个带有正确 `content-length` 的请求帧和一个带有非数字 `content-length` 的请求帧的字节流。
  ```
  stream_frames = TestFrameSequence()
      .ClientPreface()
      .Headers(1, ..., {"content-length", "2"})
      .Data(1, "hi", /*fin=*/true)
      .Headers(3, ..., {"content-length", "nan"}, /*fin=*/true)
      .Serialize();
  ```

* **预期输出:**
    * **Stream 1 (content-length: 2):**
        * 正常解析 `HEADERS` 和 `DATA` 帧。
        * 调用 `visitor.OnBeginDataForStream(1, 2)`，表示期望接收 2 字节的数据。
    * **Stream 3 (content-length: nan):**
        * 解析 `HEADERS` 帧时，检测到 `content-length` 不是数字。
        * 调用 `visitor.OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader)`，通知 Visitor 帧无效。
    * 后续会发送 `RST_STREAM` 帧来关闭 Stream 3。

**用户或编程常见的使用错误:**

* **在连接的错误状态下继续发送数据:**  例如，在收到 `GOAWAY` 帧后，仍然尝试发送新的请求。`OgHttp2Adapter` 的测试用例 `ServerDoesNotSendFramesAfterImmediateGoAway` 就验证了适配器在遇到连接错误后会停止发送新的帧。
* **错误地设置或解析 `content-length`:**  例如，服务端发送的 `DATA` 帧的长度与 `content-length` 头不匹配。测试用例 `ServerHandlesContentLengthMismatch` 检查了这种情况。
* **发送不符合 HTTP/2 规范的帧序列:** 例如，在没有打开流的情况下发送与流相关的帧。测试用例 `ConnectionErrorWithBlackholingData` 和 `ConnectionErrorWithoutBlackholingData` 模拟了这种情况。
* **不正确地处理 HTTP 语义:**  例如，在请求中包含被禁止的头部（如连接特定头部）。测试用例 `ServerHandlesConnectionSpecificHeaders` 检查了这种情况。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个使用 HTTPS 的网站。**
2. **浏览器与服务器建立 TCP 连接。**
3. **浏览器和服务器进行 TLS 握手以建立安全连接。**
4. **浏览器和服务器进行 HTTP/2 协商（通常在 TLS 握手期间通过 ALPN 扩展）。**
5. **浏览器发送 HTTP/2 连接序言（`SETTINGS` 帧）。**
6. **用户在网页上进行操作，例如点击链接或提交表单，触发新的 HTTP 请求。**
7. **浏览器将这些请求转换为 HTTP/2 帧（例如 `HEADERS`, `DATA` 帧）。**
8. **Chromium 的网络栈中的 `OgHttp2Adapter` (或类似的组件)  处理这些帧的序列化和发送。**
9. **在调试过程中，开发者可能会设置断点在 `OgHttp2Adapter::ProcessBytes()` 或相关的处理函数中，以观察接收到的帧和适配器的状态。**
10. **如果发生错误，例如服务器发送了不合法的帧，或者客户端发送了错误序列的帧，`OgHttp2Adapter` 的错误处理逻辑会被触发，这可能对应于测试用例中 `OnConnectionError` 或 `OnInvalidFrame` 的调用。**

**作为第 11 部分，共 12 部分，其功能归纳:**

考虑到这是一个测试文件的第 11 部分，它很可能 **集中测试了 `OgHttp2Adapter` 在服务器角色下处理各种客户端请求和错误情况的能力**。前面的部分可能侧重于客户端行为、连接建立、或更基础的帧处理，而这部分可能涵盖了更复杂的 HTTP 语义和错误处理场景，例如 `content-length` 的处理、特殊路径、连接特定头部、以及自定义的窗口更新策略等。最后一部分很可能包含一些收尾的测试或更高级的集成测试。

总而言之，`oghttp2_adapter_test.cc` 是一个至关重要的测试文件，用于确保 `OgHttp2Adapter` 能够正确、健壮地处理 HTTP/2 协议，保障 Chromium 网络栈的稳定性和可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
XPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kWrongFrameSequence));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  // Ask the connection to process more bytes. Because the option is enabled,
  // the data should be marked as consumed.
  const std::string next_frame = TestFrameSequence().Ping(42).Serialize();
  const int64_t next_result = adapter->ProcessBytes(next_frame);
  EXPECT_EQ(static_cast<size_t>(next_result), next_frame.size());
}

// Verifies that a connection-level processing error results in returning a
// negative value for ProcessBytes() when the blackhole option is disabled.
TEST(OgHttp2AdapterTest, ConnectionErrorWithoutBlackholingData) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.blackhole_data_on_connection_error = false;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface().WindowUpdate(1, 42).Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kWrongFrameSequence));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  // Ask the connection to process more bytes. Because the option is disabled,
  // ProcessBytes() should continue to return an error.
  const std::string next_frame = TestFrameSequence().Ping(42).Serialize();
  const int64_t next_result = adapter->ProcessBytes(next_frame);
  EXPECT_LT(next_result, 0);
}

TEST_P(OgHttp2AdapterDataTest, ServerDoesNotSendFramesAfterImmediateGoAway) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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
  EXPECT_CALL(visitor,
              OnFrameHeader(1, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
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
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kWrongFrameSequence));

  const int64_t result = adapter->ProcessBytes(connection_error_frames);
  EXPECT_EQ(static_cast<size_t>(result), connection_error_frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
  visitor.Clear();

  // Try to submit more frames for writing. They should not be written.
  adapter->SubmitPing(42);
  // TODO(diannahu): Enable the below expectation.
  // EXPECT_FALSE(adapter->want_write());
  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
}

TEST(OgHttp2AdapterTest, ServerHandlesContentLength) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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
                    {":path", "/this/is/request/three"},
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
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerHandlesContentLengthMismatch) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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
  // All data is delivered to the visitor. Note that neither oghttp2 nor
  // nghttp2 delivers OnInvalidFrame().
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 1));
  EXPECT_CALL(visitor, OnDataForStream(1, "h"));

  // Stream 3: content-length is smaller than actual data
  // The beginning of data is delivered to the visitor, but not the actual data.
  // Again, neither oghttp2 nor nghttp2 delivers OnInvalidFrame().
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 5));

  // Stream 5: content-length is invalid and HEADERS ends the stream
  // Only oghttp2 invokes OnEndHeadersForStream(). Both invoke
  // OnInvalidFrame().
  EXPECT_CALL(visitor, OnFrameHeader(5, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(5));
  EXPECT_CALL(visitor, OnHeaderForStream(5, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(5));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  5, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  // Stream 7: content-length is invalid and trailers end the stream
  // Only oghttp2 invokes OnEndHeadersForStream(). Both invoke
  // OnInvalidFrame().
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
  EXPECT_CALL(visitor, OnEndHeadersForStream(7));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  7, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
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
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 5, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 5, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::HTTP2_NO_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 7, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 7, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(7, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerHandlesAsteriskPathForOptions) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, ServerHandlesInvalidPath) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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
      OnInvalidFrame(5, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
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
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 5, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 5, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM,
                    SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerHandlesTeHeader) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerHandlesConnectionSpecificHeaders) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(5, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(5));
  EXPECT_CALL(visitor, OnHeaderForStream(5, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(5, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(7, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(7));
  EXPECT_CALL(visitor, OnHeaderForStream(7, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(7, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(9, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(9));
  EXPECT_CALL(visitor, OnHeaderForStream(9, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(9, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
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
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 5, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 5, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::HTTP2_NO_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 7, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 7, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(7, Http2ErrorCode::HTTP2_NO_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 9, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 9, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(9, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM,
                    SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerUsesCustomWindowUpdateStrategy) {
  // Test the use of a custom WINDOW_UPDATE strategy.
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.should_window_update_fn = [](int64_t /*limit*/, int64_t /*size*/,
                                       int64_t /*delta*/) { return true; };
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Data(1, "This is the request body.",
                                       /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, END_STREAM_FLAG));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<int64_t>(frames.size()), result);

  // Mark a small number of bytes for the stream as consumed. Because of the
  // custom WINDOW_UPDATE strategy, the session should send WINDOW_UPDATEs.
  adapter->MarkDataConsumedForStream(1, 5);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 1, 4, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 0, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 0, 4, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::WINDOW_UPDATE,
                            SpdyFrameType::WINDOW_UPDATE}));
}

TEST(OgHttp2AdapterTest, ServerConsumesDataWithPadding) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  TestFrameSequence seq = std::move(TestFrameSequence().ClientPreface().Headers(
      1,
      {{":method", "POST"},
       {":scheme", "https"},
       {":authority", "example.com"},
       {":path", "/this/is/request/one"}},
      /*fin=*/false));
  // Generates a bunch of DATA frames, with the bulk of the payloads co
```
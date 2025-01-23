Response:
The user wants a summary of the functionality of the provided C++ code, which is part of Chromium's network stack and deals with HTTP/2 protocol adaptation.

Here's a breakdown of how to approach this:

1. **Identify the core class:** The code heavily uses `OgHttp2Adapter` and `TestVisitor`. This suggests the primary function is adapting an underlying HTTP/2 implementation (`oghttp2`) for use within Chromium's networking framework. `TestVisitor` is likely a mock object for testing the interactions.

2. **Analyze the test cases:** The names of the test cases are highly descriptive and reveal key functionalities being tested. These include:
    * Sending and receiving headers, data, settings, window updates, and GOAWAY frames.
    * Handling client and server perspectives.
    * Managing stream concurrency limits.
    * Dealing with various error conditions (e.g., receiving multiple GOAWAYs, invalid settings, rejecting 101 responses).
    * Flow control mechanisms.

3. **Look for specific interactions:** The `EXPECT_CALL` statements indicate expected interactions between the `OgHttp2Adapter` and the `TestVisitor`. These calls demonstrate the adapter's behavior in response to different events (e.g., `OnBeforeFrameSent`, `OnFrameSent`, `OnFrameHeader`, `OnSettingsStart`, `OnGoAway`, `OnCloseStream`).

4. **Infer relationships with JavaScript (if any):**  HTTP/2 is the underlying protocol for web communication. While this C++ code itself doesn't directly execute JavaScript, it plays a crucial role in how the browser handles network requests initiated by JavaScript.

5. **Consider input and output:** For each test case, think about the input to the `OgHttp2Adapter` (e.g., frames received via `ProcessBytes`, requests submitted via `SubmitRequest`) and the expected output (frames sent via `Send`, callbacks to the `TestVisitor`).

6. **Identify potential user errors:** Think about common mistakes developers or the underlying HTTP/2 implementation might make that this adapter needs to handle or protect against.

7. **Trace user actions:**  How does a user's action in the browser (e.g., clicking a link, submitting a form) lead to the execution of this code?

8. **Synthesize the information:** Combine the observations from the test cases and the `EXPECT_CALL` statements to create a concise summary of the file's functionality.

**Specific considerations for this "part 4 of 12"**: The provided code snippet is a continuation of tests for `OgHttp2Adapter`. Focus on the functionalities demonstrated within this specific section.

**Plan for the response:**

* Start with a general summary of the file's purpose.
* List the specific functionalities demonstrated in this part.
* Explain the potential relationship to JavaScript.
* Provide an example of logical reasoning with input and output.
* Give an example of a user/programming error.
* Describe the user actions leading to this code.
* Conclude with a summary of the functionality covered in this part.
这个C++源代码文件 `oghttp2_adapter_test.cc` 是 Chromium 网络栈中 `quiche` 库的一部分，专门用于测试 `OgHttp2Adapter` 类的功能。 `OgHttp2Adapter` 的作用是将底层的 HTTP/2 实现 (`oghttp2`) 适配到 Chromium 的网络栈接口。

**主要功能归纳 (基于提供的第 4 部分代码片段):**

从这段代码片段来看，主要测试了 `OgHttp2Adapter` 在客户端模式下处理以下 HTTP/2 场景的能力：

1. **处理服务端发送的 GOAWAY 帧:**
   - 测试客户端接收到 GOAWAY 帧后，是否会正确关闭相关的流。
   - 测试客户端接收到 GOAWAY 帧后，是否会取消尚未发送的挂起请求。
   - 测试客户端接收到多个 GOAWAY 帧的情况，包括 last_stream_id 不断增加的异常情况。
   - 测试客户端接收到 GOAWAY 帧后，即使 `MAX_CONCURRENT_STREAMS` 设置允许发送新请求，也不应该发送。
   - 测试客户端在接收到 GOAWAY 帧后，如果处理 GOAWAY 帧的回调返回错误，是否会触发连接错误并发送自身的 GOAWAY 帧。

2. **拒绝服务端发送的 101 (Switching Protocols) 响应:**
   - 测试客户端接收到 101 响应时，是否会认为这是一个无效的帧，并发送 RST_STREAM 帧关闭连接。

3. **遵守 `MAX_CONCURRENT_STREAMS` 设置:**
   - 测试客户端在接收到服务端发送的 `SETTINGS` 帧，设置了 `MAX_CONCURRENT_STREAMS` 后，是否会限制并发发送的请求数量，将超出限制的请求置于挂起状态。
   - 测试当一个流结束后，挂起的请求是否会被发送。

4. **处理服务端发送的 `INITIAL_WINDOW_SIZE` 设置:**
   - 测试客户端接收到服务端发送的 `SETTINGS` 帧，设置了 `INITIAL_WINDOW_SIZE` 后，是否会更新本地的流控窗口大小。
   - 测试在流开始后接收到 `INITIAL_WINDOW_SIZE` 设置的情况，验证流控是否正确应用。
   - 测试接收到过大的 `INITIAL_WINDOW_SIZE` 设置时，是否会触发错误。

5. **处理服务端发送的 WINDOW_UPDATE 帧:**
    - 虽然在这个片段中没有直接的测试用例明确展示对接收 `WINDOW_UPDATE` 的处理，但在与其他帧的交互中可以看到 `OnWindowUpdate` 的预期调用。

**与 JavaScript 的功能关系：**

虽然这段 C++ 代码本身不包含 JavaScript 代码，但它直接影响着浏览器中 JavaScript 发起的网络请求的行为。

* **场景举例:** 当 JavaScript 代码使用 `fetch` API 发起一个 HTTP/2 请求时，Chromium 的网络栈会使用 `OgHttp2Adapter` 来处理与服务器的 HTTP/2 通信。如果服务器在响应过程中发送了一个 GOAWAY 帧 (例如，服务器要维护或过载)，`OgHttp2Adapter` 的逻辑会确保这个 GOAWAY 帧被正确处理，可能导致 JavaScript 的 `fetch` Promise 被 reject，或者触发重试机制（如果配置了）。
* **流控:** JavaScript 发送大量数据时，`OgHttp2Adapter` 会根据接收到的 `INITIAL_WINDOW_SIZE` 和 `WINDOW_UPDATE` 帧来限制发送速率，防止客户端或服务器过载。这直接影响着 JavaScript 中上传大文件的效率和稳定性。

**逻辑推理示例：**

**假设输入:** 客户端已发送一个 HTTP/2 请求（stream_id=1），服务器发送一个 GOAWAY 帧，`last_stream_id` 为 1，错误码为 `INTERNAL_ERROR`。之后，客户端尝试发送一个针对 stream_id=3 的 WINDOW_UPDATE 帧。

**预期输出:**
- `OgHttp2Adapter` 会调用 `visitor.OnGoAway(1, Http2ErrorCode::INTERNAL_ERROR, "")` 来通知上层接收到 GOAWAY 帧。
- 由于 GOAWAY 的 `last_stream_id` 为 1，所有 stream_id > 1 的活跃流都会被关闭。
- 因此，针对 stream_id=3 的 WINDOW_UPDATE 帧**不会**被发送，因为它对应的流已经被 GOAWAY 帧关闭（或拒绝）。

**用户或编程常见的使用错误：**

* **客户端错误地处理 GOAWAY 帧:**  如果客户端没有正确处理服务端发送的 GOAWAY 帧，例如，在接收到 GOAWAY 后仍然尝试发送新的请求到受影响的服务器，这会导致不必要的网络请求失败和性能问题。`OgHttp2Adapter` 的测试确保了在这种情况下能够正确关闭连接和拒绝新的请求。
* **服务端错误地发送 GOAWAY 帧:** 服务端发送的 GOAWAY 帧的 `last_stream_id` 应该是不大于当前已成功处理的最大流 ID。如果服务端发送了一个 `last_stream_id` 比实际处理过的流 ID 更小的 GOAWAY 帧，这违反了 HTTP/2 协议。`OgHttp2Adapter` 的测试用例 `ClientReceivesMultipleGoAwaysWithIncreasingStreamId` 模拟了这种情况，并验证了客户端会正确地检测到协议错误。

**用户操作到达这里的调试线索：**

1. **用户在浏览器中访问一个使用了 HTTP/2 协议的网站。**
2. **浏览器 (Chromium) 的网络栈尝试与服务器建立 HTTP/2 连接。**
3. **在连接建立后，用户执行某些操作 (例如点击链接，提交表单)，导致浏览器需要发送 HTTP/2 请求到服务器。**
4. **如果服务器由于某些原因 (例如过载、维护) 决定关闭连接或者指示客户端停止使用旧的流，它会发送一个 GOAWAY 帧。**
5. **Chromium 网络栈接收到 GOAWAY 帧后，会调用 `OgHttp2Adapter::ProcessBytes` 来处理这个帧。**
6. **`OgHttp2Adapter` 会根据 GOAWAY 帧的内容更新内部状态，并通知 `TestVisitor` (在测试环境中) 或者实际的网络栈回调接口，指示连接或流需要被关闭。**
7. **开发者在调试网络问题时，可能会查看网络日志或使用抓包工具 (如 Wireshark) 来分析 HTTP/2 的帧交互，从而定位到 GOAWAY 帧的发送和接收，并可能深入到 `OgHttp2Adapter` 的代码中查看其处理逻辑。**

**第 4 部分功能归纳：**

这部分代码主要测试了 `OgHttp2Adapter` 在客户端模式下处理服务端发送的 GOAWAY 帧、101 响应以及 `INITIAL_WINDOW_SIZE` 设置的能力，并验证了客户端是否能够正确地遵守 `MAX_CONCURRENT_STREAMS` 的限制。 这些测试确保了客户端在接收到服务端的控制帧时，能够做出符合 HTTP/2 协议规范的反应，保证了网络连接的稳定性和可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
D_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS,
                            SpdyFrameType::HEADERS}));
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
  // Currently, oghttp2 does not pass the opaque data to the visitor.
  EXPECT_CALL(visitor, OnGoAway(1, Http2ErrorCode::INTERNAL_ERROR, ""));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::REFUSED_STREAM));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 42));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, ClientReceivesMultipleGoAways) {
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
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
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
  // Currently, oghttp2 does not pass the opaque data to the visitor.
  EXPECT_CALL(visitor,
              OnGoAway(kMaxStreamId, Http2ErrorCode::INTERNAL_ERROR, ""));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Submit a WINDOW_UPDATE for the open stream. Because the stream is below the
  // GOAWAY's last_stream_id, it should be sent.
  adapter->SubmitWindowUpdate(1, 42);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
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
  // Currently, oghttp2 does not pass the opaque data to the visitor.
  EXPECT_CALL(visitor, OnGoAway(0, Http2ErrorCode::INTERNAL_ERROR, ""));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::REFUSED_STREAM));

  const int64_t final_result = adapter->ProcessBytes(final_frames);
  EXPECT_EQ(final_frames.size(), static_cast<size_t>(final_result));

  EXPECT_FALSE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
}

TEST(OgHttp2AdapterTest, ClientReceivesMultipleGoAwaysWithIncreasingStreamId) {
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
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  visitor.Clear();

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
  // The oghttp2 stack also signals the error via OnConnectionError().
  EXPECT_CALL(visitor,
              OnConnectionError(ConnectionError::kInvalidGoAwayLastStreamId));

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

TEST(OgHttp2AdapterTest, ClientReceivesGoAwayWithPendingStreams) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

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
      TestFrameSequence()
          .ServerPreface({{MAX_CONCURRENT_STREAMS, 1}})
          .Serialize();

  // Server preface (SETTINGS with MAX_CONCURRENT_STREAMS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting);
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

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
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

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
  EXPECT_CALL(visitor,
              OnGoAway(kMaxStreamId, Http2ErrorCode::INTERNAL_ERROR, ""));
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{MAX_CONCURRENT_STREAMS, 42u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  // We close the pending stream on the next write attempt.
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

  // We close the pending stream on the next write attempt.
  EXPECT_CALL(visitor, OnCloseStream(5, Http2ErrorCode::REFUSED_STREAM));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterTest, ClientFailsOnGoAway) {
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
  // TODO(birenroy): Pass the GOAWAY opaque data through the oghttp2 stack.
  EXPECT_CALL(visitor, OnGoAway(1, Http2ErrorCode::INTERNAL_ERROR, ""))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

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

TEST(OgHttp2AdapterTest, ClientRejects101Response) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(static_cast<int64_t>(stream_frames.size()), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(RST_STREAM, 1, 4, 0x0,
                  static_cast<uint32_t>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST_P(OgHttp2AdapterDataTest, ClientObeysMaxConcurrentStreams) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_FALSE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  // Even though the user has not queued any frames for the session, it should
  // still send the connection preface.
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  // Initial SETTINGS.
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
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
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Session will want to write a SETTINGS ack.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string kBody = "This is an example request body.";
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  const int stream_id = adapter->SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      GetParam() ? nullptr : std::move(body1), false, nullptr);
  ASSERT_EQ(stream_id, 1);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor,
              OnBeforeFrameSent(HEADERS, stream_id, _, END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, END_STREAM_FLAG, 0));

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
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, 26, DATA, END_STREAM_FLAG));
  EXPECT_CALL(visitor, OnBeginDataForStream(stream_id, 26));
  EXPECT_CALL(visitor,
              OnDataForStream(stream_id, "This is the response body."));
  EXPECT_CALL(visitor, OnEndStream(stream_id));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR));

  // The first stream should close, which should make the session want to write
  // the next stream.
  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, next_stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, next_stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());
}

TEST_P(OgHttp2AdapterDataTest, ClientReceivesInitialWindowSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  int64_t result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string kLongBody = std::string(81000, 'c');
  visitor.AppendPayloadForStream(1, kLongBody);
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

TEST_P(OgHttp2AdapterDataTest,
       ClientReceivesInitialWindowSettingAfterStreamStart) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().WindowUpdate(0, 65536).Serialize();
  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 65536));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Session will want to write a SETTINGS ack.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  int64_t result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string kLongBody = std::string(81000, 'c');
  visitor.AppendPayloadForStream(1, kLongBody);
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
  // The client can only send 65535 bytes of data, as the stream window has not
  // yet been increased.
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, 16384, 0x0, 0)).Times(3);
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, 16383, 0x0, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA,
                            SpdyFrameType::DATA, SpdyFrameType::DATA,
                            SpdyFrameType::DATA}));
  visitor.Clear();

  // Can't write any more due to flow control.
  EXPECT_FALSE(adapter->want_write());

  const std::string settings_frame =
      TestFrameSequence().Settings({{INITIAL_WINDOW_SIZE, 80000u}}).Serialize();
  // SETTINGS with INITIAL_STREAM_WINDOW
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{INITIAL_WINDOW_SIZE, 80000u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t settings_result = adapter->ProcessBytes(settings_frame);
  EXPECT_EQ(settings_frame.size(), static_cast<size_t>(settings_result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  // The client can write more after receiving the INITIAL_WINDOW_SIZE setting.
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, 14465, 0x0, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::DATA}));
}

TEST(OgHttp2AdapterTest, InvalidInitialWindowSetting) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const uint32_t kTooLargeInitialWindow = 1u << 31;
  const std::string initial_frames =
      TestFrameSequence()
          .Settings({{INITIAL_WINDOW_SIZE, kTooLargeInitialWindow}})
          .Serialize();
  // Server preface (SETTINGS with INITIAL_STREAM_WINDOW)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  0, Http2VisitorInterface::InvalidFrameError::kFlowControl));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kFlowControlError));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(in
```
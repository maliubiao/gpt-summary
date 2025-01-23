Response:
The user wants to understand the functionality of a specific C++ source code file within the Chromium network stack, `nghttp2_adapter_test.cc`. This file is part of the quiche library, which implements HTTP/2 and HTTP/3. Since this is part 5 of 11, the user likely wants a summary of the functionalities demonstrated in this specific snippet.

Here's a breakdown of the tasks:

1. **List functionalities:** Analyze the code snippets and identify the HTTP/2 features being tested. This involves looking at the sequence of operations, the frames being sent and received, and the expected visitor callbacks.
2. **Relate to JavaScript (if applicable):**  Consider if the tested functionalities have direct equivalents or impact on how JavaScript interacts with HTTP/2 in a browser environment.
3. **Hypothesize input and output:** For code segments demonstrating a specific interaction, infer the likely input (data sent to the adapter) and the expected output (visitor callbacks and data sent by the adapter).
4. **Identify common usage errors:** Look for test cases that highlight potential errors developers might make when using the `NgHttp2Adapter`.
5. **Explain user actions leading to the code:**  Describe how a user's interaction with a web page might trigger the HTTP/2 communication patterns being tested.
6. **Summarize the functionality of this part:**  Provide a concise overview of the HTTP/2 features and scenarios covered in this specific code snippet.

**Mental Sandbox:**

* **Scanning for HTTP/2 frame types:** I see `SETTINGS`, `WINDOW_UPDATE`, `HEADERS`, `DATA`, `GOAWAY`, `RST_STREAM`, `PUSH_PROMISE`, and `PING`. These are the core building blocks of HTTP/2 communication, so the tests are likely focusing on how the adapter handles these frames.
* **Role of `NgHttp2Adapter` and `TestVisitor`:** The `NgHttp2Adapter` seems to be the central component under test, and `TestVisitor` acts as a mock object to observe the interactions with the adapter. The `EXPECT_CALL` macros indicate the expected sequence of events.
* **Client vs. Server:** Some tests explicitly create either a client or server adapter, indicating different testing scenarios for each role.
* **Flow Control:** Several tests involve `WINDOW_UPDATE` and checks for `want_write()`, suggesting a focus on HTTP/2 flow control mechanisms.
* **Settings:**  Tests involving `INITIAL_WINDOW_SIZE` and `MAX_FRAME_SIZE` demonstrate how the adapter handles HTTP/2 settings.
* **Push:** Tests related to `ENABLE_PUSH` and `PUSH_PROMISE` explore the server push functionality and how clients can disable it.
* **Error Handling:** Tests involving `GOAWAY` and `RST_STREAM` indicate testing of error scenarios and how the adapter reacts to invalid or problematic frames.
* **JavaScript Connection:**  JavaScript's `fetch` API is the primary way web pages initiate HTTP requests. The tested scenarios likely mirror interactions triggered by JavaScript making requests, receiving responses, and potentially encountering server push.

**Constraint Checklist & Confidence Score:**

*列举一下它的功能: Yes
*如果它与javascript的功能有关系，请做出对应的举例说明: Yes
*如果做了逻辑推理，请给出假设输入与输出: Yes
*如果涉及用户或者编程常见的使用错误，请举例说明: Yes
*说明用户操作是如何一步步的到达这里，作为调试线索: Yes
*这是第5部分，共11部分，请归纳一下它的功能: Yes

Confidence Score: 5/5 - I am confident I can address all aspects of the prompt.

Strategizing complete. I will now proceed with generating the response based on the analysis and mental sandbox exploration.
这个C++源代码文件 `nghttp2_adapter_test.cc` 的第 5 部分主要测试了 `NgHttp2Adapter` 类在处理 HTTP/2 连接建立、流量控制、SETTINGS 帧以及与服务器推送相关的行为。以下是更详细的功能列举：

**主要功能：**

1. **客户端连接建立和前导帧处理：**
   - 测试客户端发送连接前导（Connection Preface），包括空的 SETTINGS 帧。
   - 测试客户端处理服务器发送的连接前导，包括空的 SETTINGS 帧和 WINDOW_UPDATE 帧。
   - 验证客户端在收到服务器前导后，会发送 SETTINGS ACK 帧。

2. **基本请求发送和流量控制：**
   - 测试客户端发送带有请求头的请求。
   - 测试在初始窗口大小限制下，客户端如何分片发送请求体数据。
   - 验证客户端在流量控制限制下，不会继续发送数据。

3. **处理服务器发送的 SETTINGS 帧：**
   - 测试客户端接收和处理服务器发送的包含 `INITIAL_WINDOW_SIZE` 设置的 SETTINGS 帧。
   - 验证客户端在收到增大窗口大小的 SETTINGS 帧后，可以继续发送数据。

4. **处理无效的初始窗口大小设置：**
   - 测试客户端接收到服务器发送的过大的 `INITIAL_WINDOW_SIZE` 设置时的行为。
   - 验证客户端会发送 GOAWAY 帧，并携带 `FLOW_CONTROL_ERROR` 错误码。

5. **初始窗口设置导致的溢出：**
   - 测试在客户端发送请求后，服务器发送一个很大的 `INITIAL_WINDOW_SIZE` 设置，加上之前的 WINDOW_UPDATE 可能导致流控窗口溢出的情况。
   - 验证客户端会发送 RST_STREAM 帧，并携带 `FLOW_CONTROL_ERROR` 错误码关闭该流。

6. **客户端禁止服务器推送：**
   - 测试客户端发送 `ENABLE_PUSH = 0` 的 SETTINGS 帧来禁止服务器推送。
   - 验证客户端在禁止推送后，接收到 PUSH_PROMISE 帧或推送流的 HEADERS 帧时，会将其视为无效帧并发送 GOAWAY 帧，携带 `PROTOCOL_ERROR` 错误码。

7. **发送连接前导失败处理：**
   - 测试在发送连接前导时发生写入错误的情况。
   - 验证适配器会调用 `OnConnectionError` 回调函数。

8. **MAX_FRAME_SIZE 设置的处理（未 ACK 前）：**
   - 测试客户端发送包含 `MAX_FRAME_SIZE` 设置的 SETTINGS 帧。
   - 验证在服务器尚未 ACK 这个 SETTINGS 帧之前，客户端接收到超过默认帧大小的数据帧时，会视为连接错误并发送 GOAWAY 帧，携带 `FRAME_SIZE_ERROR` 错误码。

9. **MAX_FRAME_SIZE 设置的处理（已 ACK 后）：**
   - 测试客户端发送包含 `MAX_FRAME_SIZE` 设置的 SETTINGS 帧。
   - 验证在服务器 ACK 这个 SETTINGS 帧之后，客户端可以正常接收超过默认帧大小的数据帧。

10. **WINDOW_UPDATE 帧提高流量控制窗口限制：**
    - 测试服务器端发送 WINDOW_UPDATE 帧来增加连接和流的流量控制窗口。
    - 验证服务器端在发送 WINDOW_UPDATE 后，可以接收更多的数据。

11. **控制帧发送错误导致连接错误：**
    - 测试服务器端在发送控制帧（例如 SETTINGS ACK 或 PING）时发生写入错误的情况。
    - 验证适配器会调用 `OnConnectionError` 回调函数，并且 nghttp2 可能会重试发送失败的帧。

12. **数据帧发送错误导致连接错误：**
    - 测试服务器端在发送数据帧时发生写入错误的情况。
    - 验证适配器会调用 `OnConnectionError` 回调函数，并且 nghttp2 可能会重试发送失败的帧。

13. **服务器端适配器的构造：**
    - 测试服务器端 `NgHttp2Adapter` 对象的创建。
    - 验证服务器端适配器初始状态为想要读取数据，不想要写入数据。

14. **服务器端处理接收到的帧：**
    - 测试服务器端接收各种客户端发送的帧，例如 PING、WINDOW_UPDATE、HEADERS、DATA、RST_STREAM。
    - 验证服务器端正确解析和处理这些帧，并调用相应的 visitor 回调函数。
    - 测试服务器端设置和获取流的用户数据。
    - 验证服务器端在接收到数据后，会更新接收窗口大小。

15. **服务器端 visitor 拒绝 HEADERS 帧：**
    - 测试服务器端 visitor 在处理 HEADERS 帧时返回拒绝的情况（代码片段未完全展示，但可以推测其功能）。

**与 JavaScript 的关系举例：**

* **流量控制：** 当 JavaScript 使用 `fetch` API 发送大型请求体时，浏览器底层的 HTTP/2 实现（可能基于类似 `NgHttp2Adapter` 的组件）会根据服务器的流量控制窗口大小来分片发送数据。如果服务器的窗口很小，JavaScript 发送的数据会被分成多个小的 DATA 帧。
* **SETTINGS 帧和初始窗口大小：**  JavaScript 发起的 HTTP/2 连接，浏览器会处理服务器发送的 SETTINGS 帧，其中包括 `INITIAL_WINDOW_SIZE`。这会影响浏览器可以为该连接上的新流分配多少初始接收窗口，进而影响数据接收的速度。
* **服务器推送：**  如果服务器支持 HTTP/2 推送，并且客户端（浏览器）没有禁用推送，那么服务器可以在 JavaScript 发起请求之前主动推送资源。浏览器接收到 PUSH_PROMISE 帧后，会创建一个“承诺”的请求，当服务器发送实际的推送资源时，JavaScript 可以通过相应的 API（例如 Service Worker 的 `push` 事件）来处理。
* **禁用推送：**  如果 JavaScript 应用知道自己不需要服务器推送的资源，它可以通知浏览器在 HTTP/2 连接建立时发送 `ENABLE_PUSH = 0` 的 SETTINGS 帧，如同本文件中测试的那样。
* **MAX_FRAME_SIZE：** 服务器发送的 `MAX_FRAME_SIZE` 设置会影响浏览器接收单个 HTTP/2 数据帧的最大大小。这可能会间接影响 JavaScript 处理大型响应体的效率。

**逻辑推理的假设输入与输出：**

**示例 1：客户端发送请求和服务器响应 SETTINGS**

* **假设输入 (客户端角度):**
   - 用户在浏览器中访问一个页面，JavaScript 发起一个 POST 请求，带有一定大小的请求体。

* **预期输出 (本测试用例中 `TestVisitor` 的回调):**
   - `OnFrameHeader` (SETTINGS, ...)
   - `OnSettingsStart`
   - `OnSettingsEnd`
   - `OnFrameHeader` (WINDOW_UPDATE, ...)
   - `OnWindowUpdate`
   - `OnBeforeFrameSent` (SETTINGS, ...)
   - `OnFrameSent` (SETTINGS, ...)
   - `OnBeforeFrameSent` (HEADERS, ...)
   - `OnFrameSent` (HEADERS, ...)
   - 多个 `OnFrameSent` (DATA, ...) （根据流量控制分片）
   - `OnFrameHeader` (SETTINGS, ...) (来自服务器)
   - `OnSettingsStart`
   - `OnSetting` (INITIAL_WINDOW_SIZE, 80000)
   - `OnSettingsEnd`
   - `OnBeforeFrameSent` (SETTINGS, ...)
   - `OnFrameSent` (SETTINGS, ...)
   - `OnBeforeFrameSent` (DATA, ...)
   - `OnFrameSent` (DATA, ...)

**示例 2：服务器发送过大的 INITIAL_WINDOW_SIZE**

* **假设输入 (客户端角度):**
   - 客户端连接到一个恶意或配置错误的 HTTP/2 服务器。
   - 服务器在连接建立时发送一个 `INITIAL_WINDOW_SIZE` 设置为 `(1u << 31)` 的 SETTINGS 帧。

* **预期输出 (本测试用例中 `TestVisitor` 的回调):**
   - `OnFrameHeader` (SETTINGS, ...)
   - `OnInvalidFrame` (0, `kFlowControl`)
   - `OnBeforeFrameSent` (GOAWAY, ...)
   - `OnFrameSent` (GOAWAY, ..., `FLOW_CONTROL_ERROR`)

**涉及用户或编程常见的使用错误：**

1. **客户端未正确处理服务器发送的流量控制更新：** 开发者实现的 HTTP/2 客户端如果忽略或错误处理服务器发送的 WINDOW_UPDATE 帧，可能导致发送过多的数据，违反流量控制协议，导致连接中断。
2. **服务器发送了超出客户端处理能力的帧大小：** 如果服务器发送的帧大小超过了客户端声明的 MAX_FRAME_SIZE（或默认限制），客户端可能会断开连接。本文件中的测试用例就涵盖了这种情况。
3. **在客户端禁用推送后，服务器仍然尝试推送：**  开发者实现的 HTTP/2 服务器需要遵守客户端的 SETTINGS。如果客户端明确禁用了推送，服务器不应发送 PUSH_PROMISE 或推送流的 HEADERS 帧。
4. **错误配置的初始窗口大小：**  服务端或客户端配置的初始窗口大小过大可能会导致流量控制计算溢出，如同测试用例 `InitialWindowSettingCausesOverflow` 中所示。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器地址栏输入 URL 或点击链接：** 这会触发浏览器发起 HTTP/2 连接请求。
2. **浏览器与服务器进行 TCP 握手和 TLS 握手：**  建立安全的 TCP 连接。
3. **浏览器发送 HTTP/2 连接前导：**  包括魔术字符串和 SETTINGS 帧。相关的测试用例是 `Sequence().ServerPreface().WindowUpdate(0, 65536).Serialize();` 开头的测试。
4. **服务器发送 HTTP/2 连接前导：**  也包括 SETTINGS 帧，可能包含 `INITIAL_WINDOW_SIZE` 等设置。相关的测试用例是测试客户端处理服务器前导帧的部分。
5. **用户在网页上执行操作，例如提交表单、上传文件：**  这会导致 JavaScript 代码使用 `fetch` API 发送 POST 请求，其中可能包含请求体数据。相关的测试用例是测试客户端发送带请求体的请求的部分。
6. **服务器发送 SETTINGS 帧更新客户端的窗口大小：**  服务器可能会根据需要动态调整客户端的流量控制窗口。相关的测试用例是测试客户端处理服务器发送的包含 `INITIAL_WINDOW_SIZE` 设置的 SETTINGS 帧的部分。
7. **服务器尝试推送资源：** 如果服务器支持推送，并且客户端没有禁用，服务器可能会发送 PUSH_PROMISE 帧。相关的测试用例是测试客户端禁止服务器推送的部分。
8. **发生网络错误或服务器行为异常：** 例如，服务器发送了无效的帧或违反了 HTTP/2 协议，这可能会触发测试用例中模拟的各种错误场景。

**第 5 部分的功能归纳：**

这部分 `nghttp2_adapter_test.cc` 主要集中测试了 `NgHttp2Adapter` 类在 **HTTP/2 连接建立的初期阶段**和 **基础的请求/响应交互**中，如何处理各种 **SETTINGS 帧**（包括初始窗口大小、最大帧大小、推送使能）以及如何进行 **基本的流量控制**。此外，它也覆盖了客户端如何 **拒绝服务器推送**以及在遇到 **无效帧或错误** 时的反应，为理解 HTTP/2 连接的初始化和基本数据传输流程提供了重要的测试覆盖。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
Sequence().ServerPreface().WindowUpdate(0, 65536).Serialize();
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  // The client can write more after receiving the INITIAL_WINDOW_SIZE setting.
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, 14465, 0x0, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::DATA}));
}

TEST(NgHttp2AdapterTest, InvalidInitialWindowSetting) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  const uint32_t kTooLargeInitialWindow = 1u << 31;
  const std::string initial_frames =
      TestFrameSequence()
          .Settings({{INITIAL_WINDOW_SIZE, kTooLargeInitialWindow}})
          .Serialize();
  // Server preface (SETTINGS with INITIAL_STREAM_WINDOW)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  0, Http2VisitorInterface::InvalidFrameError::kFlowControl));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Session will want to write a GOAWAY.
  EXPECT_TRUE(adapter->want_write());

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
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::GOAWAY}));
  visitor.Clear();
}

TEST(NgHttp2AdapterTest, InitialWindowSettingCausesOverflow) {
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
  int64_t write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({SpdyFrameType::HEADERS}));
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  // The stream window update plus the SETTINGS frame with INITIAL_WINDOW_SIZE
  // pushes the stream's flow control window outside of the acceptable range.
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id, 4, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(RST_STREAM, stream_id, 4, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::FLOW_CONTROL_ERROR));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ClientForbidsPushPromise) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);
  adapter->SubmitSettings({{ENABLE_PUSH, 0}});

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

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
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));
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

  // SETTINGS ack (to acknowledge PUSH_ENABLED=0)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck);

  // The PUSH_PROMISE is now treated as an invalid frame.
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, PUSH_PROMISE, _));
  EXPECT_CALL(visitor, OnInvalidFrame(stream_id, _));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), read_result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(GOAWAY, 0, _, 0x0,
                  static_cast<int32_t>(Http2ErrorCode::PROTOCOL_ERROR)));

  write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
}

TEST(NgHttp2AdapterTest, ClientForbidsPushStream) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);
  adapter->SubmitSettings({{ENABLE_PUSH, 0}});

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

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
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));
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

  // SETTINGS ack (to acknowledge PUSH_ENABLED=0)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck);

  // The push HEADERS are invalid.
  EXPECT_CALL(visitor, OnFrameHeader(2, _, HEADERS, _));
  EXPECT_CALL(visitor, OnInvalidFrame(2, _));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), read_result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(GOAWAY, 0, _, 0x0,
                  static_cast<int32_t>(Http2ErrorCode::PROTOCOL_ERROR)));

  write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
}

TEST(NgHttp2AdapterTest, FailureSendingConnectionPreface) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

  visitor.set_has_write_error();
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kSendError));

  int result = adapter->Send();
  EXPECT_EQ(result, NGHTTP2_ERR_CALLBACK_FAILURE);
}

TEST(NgHttp2AdapterTest, MaxFrameSizeSettingNotAppliedBeforeAck) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

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
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

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
  // nghttp2 does not deliver any DATA or connection error events.
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

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

TEST(NgHttp2AdapterTest, MaxFrameSizeSettingAppliedAfterAck) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateClientAdapter(visitor);

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
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

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
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
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
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, WindowUpdateRaisesFlowControlWindowLimit) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string data_chunk(kDefaultFramePayloadSizeLimit, 'a');
  const std::string request = TestFrameSequence()
                                  .ClientPreface()
                                  .Headers(1,
                                           {{":method", "GET"},
                                            {":scheme", "https"},
                                            {":authority", "example.com"},
                                            {":path", "/"}},
                                           /*fin=*/false)
                                  .Serialize();

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  adapter->ProcessBytes(request);

  // Updates the advertised window for the connection and stream 1.
  adapter->SubmitWindowUpdate(0, 2 * kDefaultFramePayloadSizeLimit);
  adapter->SubmitWindowUpdate(1, 2 * kDefaultFramePayloadSizeLimit);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 0, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 0, 4, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 1, 4, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);

  // Verifies the advertised window.
  EXPECT_EQ(kInitialFlowControlWindowSize + 2 * kDefaultFramePayloadSizeLimit,
            adapter->GetReceiveWindowSize());
  EXPECT_EQ(kInitialFlowControlWindowSize + 2 * kDefaultFramePayloadSizeLimit,
            adapter->GetStreamReceiveWindowSize(1));

  const std::string request_body = TestFrameSequence()
                                       .Data(1, data_chunk)
                                       .Data(1, data_chunk)
                                       .Data(1, data_chunk)
                                       .Data(1, data_chunk)
                                       .Data(1, data_chunk)
                                       .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0)).Times(5);
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _)).Times(5);
  EXPECT_CALL(visitor, OnDataForStream(1, _)).Times(5);

  // DATA frames on stream 1 consume most of the window.
  adapter->ProcessBytes(request_body);
  EXPECT_EQ(kInitialFlowControlWindowSize - 3 * kDefaultFramePayloadSizeLimit,
            adapter->GetReceiveWindowSize());
  EXPECT_EQ(kInitialFlowControlWindowSize - 3 * kDefaultFramePayloadSizeLimit,
            adapter->GetStreamReceiveWindowSize(1));

  // Marking the data consumed should result in an advertised window larger than
  // the initial window.
  adapter->MarkDataConsumedForStream(1, 4 * kDefaultFramePayloadSizeLimit);
  EXPECT_GT(adapter->GetReceiveWindowSize(), kInitialFlowControlWindowSize);
  EXPECT_GT(adapter->GetStreamReceiveWindowSize(1),
            kInitialFlowControlWindowSize);
}

TEST(NgHttp2AdapterTest, ConnectionErrorOnControlFrameSent) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames =
      TestFrameSequence().ClientPreface().Ping(42).Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // PING
  EXPECT_CALL(visitor, OnFrameHeader(0, _, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0))
      .WillOnce(testing::Return(-902));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kSendError));

  int send_result = adapter->Send();
  EXPECT_LT(send_result, 0);

  // Apparently nghttp2 retries sending the frames that had failed before.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x1, 0));
  send_result = adapter->Send();
  EXPECT_EQ(send_result, 0);

  EXPECT_FALSE(adapter->want_write());
}

TEST_P(NgHttp2AdapterDataTest, ConnectionErrorOnDataFrameSent) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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

  auto body = std::make_unique<VisitorDataSource>(visitor, 1);
  visitor.AppendPayloadForStream(
      1, "Here is some data, which will lead to a fatal error");
  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}),
                              GetParam() ? nullptr : std::move(body), false);
  ASSERT_EQ(0, submit_result);

  EXPECT_TRUE(adapter->want_write());

  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  // Stream 1, with doomed DATA
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0))
      .WillOnce(testing::Return(-902));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kSendError));

  int send_result = adapter->Send();
  EXPECT_LT(send_result, 0);

  // Apparently nghttp2 retries sending the frames that had failed before.
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  send_result = adapter->Send();
  EXPECT_EQ(send_result, 0);

  EXPECT_FALSE(adapter->want_write());
}

TEST(NgHttp2AdapterTest, ServerConstruction) {
  testing::StrictMock<MockHttp2Visitor> visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  ASSERT_NE(nullptr, adapter);
  EXPECT_TRUE(adapter->want_read());
  EXPECT_FALSE(adapter->want_write());
  EXPECT_TRUE(adapter->IsServerSession());
}

TEST(NgHttp2AdapterTest, ServerHandlesFrames) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());
  EXPECT_EQ(0, adapter->GetHpackDecoderDynamicTableSize());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Ping(42)
                                 .WindowUpdate(0, 1000)
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "http"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/true)
                                 .RstStream(3, Http2ErrorCode::CANCEL)
                                 .Ping(47)
                                 .Serialize();
  testing::InSequence s;

  const char* kSentinel1 = "arbitrary pointer 1";

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 1000));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1))
      .WillOnce(testing::InvokeWithoutArgs([&adapter, kSentinel1]() {
        adapter->SetStreamUserData(1, const_cast<char*>(kSentinel1));
        return true;
      }));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
  EXPECT_CALL(visitor, OnFrameHeader(1, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 25));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "http"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/this/is/request/two"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(47, false));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_EQ(kSentinel1, adapter->GetStreamUserData(1));

  EXPECT_GT(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowSize(1));
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(1),
            adapter->GetReceiveWindowSize());
  // Upper bound should still be the original value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            adapter->GetStreamReceiveWindowLimit(1));

  EXPECT_GT(adapter->GetHpackDecoderDynamicTableSize(), 0);

  // Because stream 3 has already been closed, it's not possible to set user
  // data.
  const char* kSentinel3 = "another arbitrary pointer";
  adapter->SetStreamUserData(3, const_cast<char*>(kSentinel3));
  EXPECT_EQ(nullptr, adapter->GetStreamUserData(3));

  EXPECT_EQ(3, adapter->GetHighestReceivedStreamId());

  EXPECT_EQ(adapter->GetSendWindowSize(), kInitialFlowControlWindowSize + 1000);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, 8, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, 8, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, 8, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, 8, 0x1, 0));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack, two PING acks.
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PING,
                            SpdyFrameType::PING}));
}

TEST(NgHttp2AdapterTest, ServerVisitorRejectsHeaders) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"},
                    {"header1", "ok"},
                    {"header2", "rejected"},
                    {"header3", "not processed"},  // CONTINUATION starts here
                    {"header4", "not processed
```
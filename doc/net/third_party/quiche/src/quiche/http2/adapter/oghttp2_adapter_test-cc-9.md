Response:
The user wants to understand the functionality of the C++ source code file `oghttp2_adapter_test.cc` within the Chromium network stack. This is part 10 of a 12-part analysis.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The file name `oghttp2_adapter_test.cc` strongly suggests this is a test file for the `OgHttp2Adapter`. The `_test.cc` suffix is a common convention for test files in C++.

2. **Analyze the Structure:** The code consists primarily of `TEST` macros. This confirms it's a Google Test-based test suite. Each `TEST` function focuses on a specific aspect of the `OgHttp2Adapter`'s behavior.

3. **Categorize the Tests:**  Read through the names and content of the individual tests to identify recurring themes and functionalities being tested. Key areas emerge:
    * **Basic Client-Server Interaction:** Tests involving sending requests and receiving responses.
    * **Header Handling:** Tests specifically checking how headers (including repeated headers and cookies) are processed.
    * **Error Handling:** Tests that verify the adapter's behavior when encountering invalid or out-of-order frames, exceeding stream limits, or other protocol violations.
    * **State Transitions:**  Tests involving connection shutdown and `GOAWAY` frames.
    * **CONNECT method and `:protocol` header:** Tests related to the handling of the HTTP/2 CONNECT method.
    * **Data Handling:** Tests around sending and receiving request/response bodies.

4. **Relate to Javascript (If Applicable):** Consider how the tested HTTP/2 functionalities manifest in a web browser's interaction with Javascript. Think about browser APIs like `fetch` or `XMLHttpRequest`. These APIs internally rely on the network stack, including HTTP/2 implementations.

5. **Infer Logical Reasoning (Input/Output):** For each test, consider the input (the sequence of HTTP/2 frames being processed or the actions taken by the adapter) and the expected output (the calls made to the `TestVisitor` mock object, the frames sent by the adapter, or the internal state changes). While the tests use mocks for verification, abstracting to a more user-centric view is helpful.

6. **Identify Common Usage Errors:** Think about the common mistakes a developer or even a browser might make when interacting with HTTP/2. This includes sending frames in the wrong order, exceeding limits, or using unsupported features.

7. **Trace User Operations (Debugging Context):** Imagine how a user's action in a browser could lead to the execution of this code. Focus on network requests initiated by Javascript or browser features.

8. **Synthesize and Summarize (Part 10 of 12):**  Given this is part 10, the summary should reflect the accumulation of knowledge from the previous parts and the specific focus of this section. Emphasize the testing aspect and the types of scenarios covered.

9. **Structure the Response:** Organize the information logically with clear headings and bullet points for readability. Use examples and concrete scenarios where possible.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus solely on the technical details of the HTTP/2 protocol.
* **Correction:** Realize the prompt asks for connections to Javascript and user behavior. Broaden the scope to include these aspects.
* **Initial thought:** List every single test case and its specific details.
* **Correction:** Group tests by functionality to provide a higher-level overview. Mention individual test names for clarity but avoid excessive detail.
* **Initial thought:** Assume deep technical knowledge of HTTP/2.
* **Correction:** Explain concepts like `GOAWAY`, `SETTINGS`, and stream IDs briefly for better understanding by a wider audience.
这个文件 `oghttp2_adapter_test.cc` 是 Chromium 网络栈中 `quiche` 库的一部分，专门用于测试 `OgHttp2Adapter` 类的功能。 `OgHttp2Adapter`  是 HTTP/2 协议的适配器实现，它在 `quiche` 库中扮演着关键角色，负责处理 HTTP/2 帧的发送和接收，并与上层应用逻辑进行交互。

**主要功能归纳：**

这个测试文件主要用于验证 `OgHttp2Adapter` 在各种场景下的行为是否符合预期，涵盖了以下核心功能：

1. **基本的客户端-服务器交互：** 测试客户端发起请求，服务器响应的正常流程，包括发送 HEADERS 帧（包含请求头）和 DATA 帧（包含请求体）。
2. **处理不同类型的 HTTP/2 帧：**  测试对 SETTINGS、HEADERS、DATA、WINDOW_UPDATE、RST_STREAM 和 GOAWAY 等关键帧的处理逻辑。
3. **管理 HTTP/2 连接状态：**  测试连接的建立、流的创建和关闭、连接错误处理以及连接关闭流程。
4. **处理 HTTP/2 特性：**  测试诸如流的并发控制（MAX_CONCURRENT_STREAMS）、`CONNECT` 方法和 `:protocol` 伪头部的处理。
5. **错误处理和协议违规检测：**  测试当接收到无效帧、顺序错误的帧、违反协议规则的帧时，`OgHttp2Adapter` 是否能够正确地检测并采取相应的措施，例如发送 GOAWAY 或 RST_STREAM 帧。
6. **处理重复的头部和 Cookie：** 测试对于具有相同名称的头部以及 Cookie 头部进行正确合并和处理。
7. **测试服务器发起的关闭流程：**  测试服务器如何通过发送 GOAWAY 帧来启动连接关闭。
8. **测试对已拒绝流的处理：**  验证当服务器拒绝一个流后，是否会忽略该流后续发送的帧。

**与 Javascript 的关系 (举例说明)：**

虽然 `oghttp2_adapter_test.cc` 是 C++ 代码，直接与 Javascript 没有代码级别的交互，但它测试的 `OgHttp2Adapter` 组件是浏览器网络栈的核心部分，直接影响着 Javascript 中网络请求的行为。

**举例：**

* **`fetch` API 发起 HTTP/2 请求:**  当 Javascript 代码使用 `fetch` API 发起一个到支持 HTTP/2 的服务器的请求时，浏览器底层的网络栈会使用 `OgHttp2Adapter` 来处理与服务器的 HTTP/2 通信。例如，`client_adapter->SubmitRequest` 方法模拟了 Javascript 发起请求的过程，而测试用例验证了这个请求是否被正确地编码成 HTTP/2 HEADERS 帧。
* **接收 HTTP/2 响应:** 当服务器响应时，`OgHttp2Adapter` 会解析接收到的 HTTP/2 帧，并将响应头和响应体传递给浏览器的上层，最终 Javascript 可以通过 `fetch` API 的 `response` 对象访问这些信息。测试用例中对 `server_visitor` 的 `OnHeaderForStream` 和 `OnDataForStream` 的 `EXPECT_CALL` 就是在模拟服务器响应的解析过程。
* **处理 HTTP/2 的错误:** 如果服务器返回一个 HTTP/2 错误（例如通过 RST_STREAM 或 GOAWAY 帧），`OgHttp2Adapter` 会捕获这些错误，并将其转换为浏览器可以理解的网络错误，Javascript 代码可能会捕获到 `fetch` API 抛出的异常或得到一个表示错误状态的 `response` 对象。测试用例中对 `OnConnectionError` 的调用模拟了这种错误处理。

**逻辑推理 (假设输入与输出)：**

**测试用例：`ClientServerInteractionRepeatedHeaderNames`**

* **假设输入 (客户端行为):**
    * 客户端创建一个 `OgHttp2Adapter` 并提交一个带有重复头部 "accept" 的请求。
    * 客户端调用 `Send()` 发送数据。
* **预期输出 (服务器行为):**
    * 服务器接收到客户端的 SETTINGS 帧（空的 preface）。
    * 服务器接收到客户端的 HEADERS 帧，并按照接收顺序调用 `OnHeaderForStream` 来处理每个头部，包括两次 "accept" 头部。
    * 服务器最终调用 `OnEndStream` 表示请求结束。

**测试用例：`ServerForbidsNewStreamBelowWatermark`**

* **假设输入 (客户端行为):**
    * 客户端发送一个有效的 HEADERS 帧 (Stream ID 3)。
    * 客户端发送该流的 DATA 帧。
    * 客户端**错误地**发送一个 Stream ID 更小的 HEADERS 帧 (Stream ID 1)。
* **预期输出 (服务器行为):**
    * 服务器接收到 Stream ID 3 的 HEADERS 帧并处理。
    * 服务器接收到 Stream ID 3 的 DATA 帧并处理。
    * 当接收到 Stream ID 1 的 HEADERS 帧时，服务器检测到 Stream ID 小于已接收到的最大 Stream ID，违反了 HTTP/2 协议，因此调用 `OnConnectionError` 并准备发送 GOAWAY 帧。

**用户或编程常见的使用错误 (举例说明)：**

* **客户端在连接建立前发送数据帧：** HTTP/2 要求先发送 HEADERS 帧才能发送 DATA 帧。如果客户端在没有发送 HEADERS 的情况下就发送 DATA 帧，`OgHttp2Adapter` (在服务器端) 会检测到 `ConnectionError::kWrongFrameSequence` 并关闭连接。测试用例 `ServerForbidsDataOnIdleStream` 就是在测试这种情况。
    * **用户操作：**  在某些极端情况下，可能是由于程序错误或者网络抖动导致数据包乱序，导致服务器先收到 DATA 帧。
* **客户端尝试创建 Stream ID 小于或等于服务器已处理的 Stream ID 的新流：** HTTP/2 的 Stream ID 必须是单调递增的。如果客户端尝试创建一个 Stream ID 较小的流，`OgHttp2Adapter` (在服务器端) 会检测到 `ConnectionError::kInvalidNewStreamId`。测试用例 `ServerForbidsNewStreamBelowWatermark` 模拟了这种情况。
    * **用户操作：**  这通常是编程错误，例如在实现自定义 HTTP/2 客户端时，没有正确管理 Stream ID。
* **服务器在未收到客户端 SETTINGS ACK 的情况下发送需要客户端 ACK 的 SETTINGS：** 虽然服务器可以立即发送 SETTINGS 帧，但如果其中包含了需要客户端 ACK 的参数（例如 MAX_CONCURRENT_STREAMS），服务器需要等待客户端的 SETTINGS ACK 帧。如果在收到 ACK 前就假设客户端已经生效了这些设置并进行操作，可能会导致问题。测试用例 `OgHttp2AdapterTest, ServerRstStreamsNewStreamAboveStreamLimitBeforeAck` 涵盖了相关场景。
    * **用户操作：** 这通常与服务器端的实现逻辑有关，如果服务器在处理客户端请求时过早地应用了还未被客户端确认的设置，就可能发生。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并访问一个 HTTPS 网站。**
2. **浏览器首先进行 DNS 查询解析域名对应的 IP 地址。**
3. **浏览器与服务器建立 TCP 连接。**
4. **浏览器与服务器进行 TLS 握手，协商加密参数。**
5. **在 TLS 握手过程中，如果双方都支持 HTTP/2 协议，会进行 ALPN (Application-Layer Protocol Negotiation) 协商，选择使用 HTTP/2。**
6. **一旦确定使用 HTTP/2，浏览器会发送 HTTP/2 的连接前导 (connection preface)，这是一个包含特定字符串和 SETTINGS 帧的序列。**  测试用例中的 `TestFrameSequence().ClientPreface()` 就是模拟这一步。
7. **浏览器根据用户请求生成 HTTP 请求头 (例如 Method, Path, Headers)。**
8. **浏览器使用 `OgHttp2Adapter` 将请求头编码成 HTTP/2 的 HEADERS 帧。**  测试用例中的 `client_adapter->SubmitRequest()` 和 `client_adapter->Send()` 模拟了这个过程。
9. **如果请求有请求体 (例如 POST 请求)，浏览器会将请求体数据编码成 HTTP/2 的 DATA 帧。**
10. **`OgHttp2Adapter` 将这些帧发送到服务器。**
11. **服务器端的 `OgHttp2Adapter` 接收并解析这些帧，并调用 `TestVisitor` 模拟的上层接口 (例如 `OnBeginHeadersForStream`, `OnHeaderForStream`, `OnDataForStream`) 来通知上层应用。** 测试用例中对 `server_visitor` 的 `EXPECT_CALL` 就是在验证这些回调是否被正确调用。

如果在这个过程中出现问题，例如服务器返回了协议错误，或者客户端发送了不符合协议的帧，`OgHttp2Adapter` 会进行相应的错误处理，并可能触发测试用例中验证的各种 `OnConnectionError` 或 `OnInvalidFrame` 的回调。调试时，查看这些回调被触发的情况，以及发送和接收到的具体帧内容，可以帮助定位问题。

**这是第 10 部分，共 12 部分，请归纳一下它的功能:**

作为第 10 部分，这个文件 `oghttp2_adapter_test.cc` 的主要功能是**通过大量的单元测试，详细验证 `OgHttp2Adapter` 组件在各种正常的和异常的 HTTP/2 通信场景下的行为是否符合预期。**  它深入测试了帧的发送和接收、连接状态管理、错误处理、特定 HTTP/2 特性的支持以及服务器发起的关闭流程。  考虑到这是系列测试的后期部分，它可能侧重于更复杂或边界情况的测试，确保 `OgHttp2Adapter` 的健壮性和可靠性。 它的存在是保证 Chromium 网络栈中 HTTP/2 实现正确性的关键环节。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共12部分，请归纳一下它的功能

"""
tream(_))
      .WillRepeatedly([&client_adapter,
                       &client_visitor](Http2StreamId stream_id) {
        if (stream_id < 10) {
          const Http2StreamId new_stream_id = stream_id + 2;
          client_visitor.AppendPayloadForStream(
              new_stream_id, "This is an example request body.");
          client_visitor.SetEndData(new_stream_id, true);
          auto body = std::make_unique<VisitorDataSource>(client_visitor,
                                                          new_stream_id);
          const int created_stream_id = client_adapter->SubmitRequest(
              ToHeaders({{":method", "GET"},
                         {":scheme", "http"},
                         {":authority", "example.com"},
                         {":path",
                          absl::StrCat("/this/is/request/", new_stream_id)}}),
              GetParam() ? nullptr : std::move(body), false, nullptr);
          EXPECT_EQ(new_stream_id, created_stream_id);
          client_adapter->Send();
        }
        return true;
      });

  // Submit a request to ensure the first stream is created.
  int stream_id = client_adapter->SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      nullptr, true, nullptr);
  EXPECT_EQ(stream_id, 1);

  client_adapter->Send();
}

TEST(OgHttp2AdapterInteractionTest,
     ClientServerInteractionRepeatedHeaderNames) {
  TestVisitor client_visitor;
  OgHttp2Adapter::Options client_options;
  client_options.perspective = Perspective::kClient;
  auto client_adapter = OgHttp2Adapter::Create(client_visitor, client_options);

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"},
                 {"accept", "text/plain"},
                 {"accept", "text/html"}});

  const int32_t stream_id1 =
      client_adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(client_visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(client_visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(client_visitor,
              OnBeforeFrameSent(HEADERS, stream_id1, _,
                                END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(client_visitor,
              OnFrameSent(HEADERS, stream_id1, _,
                          END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  int send_result = client_adapter->Send();
  EXPECT_EQ(0, send_result);

  TestVisitor server_visitor;
  OgHttp2Adapter::Options server_options;
  server_options.perspective = Perspective::kServer;
  auto server_adapter = OgHttp2Adapter::Create(server_visitor, server_options);

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(server_visitor, OnFrameHeader(0, _, SETTINGS, 0));
  EXPECT_CALL(server_visitor, OnSettingsStart());
  EXPECT_CALL(server_visitor, OnSetting).Times(testing::AnyNumber());
  EXPECT_CALL(server_visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(server_visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(server_visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(server_visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(server_visitor, OnHeaderForStream(1, ":scheme", "http"));
  EXPECT_CALL(server_visitor,
              OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(server_visitor,
              OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(server_visitor, OnHeaderForStream(1, "accept", "text/plain"));
  EXPECT_CALL(server_visitor, OnHeaderForStream(1, "accept", "text/html"));
  EXPECT_CALL(server_visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(server_visitor, OnEndStream(1));

  int64_t result = server_adapter->ProcessBytes(client_visitor.data());
  EXPECT_EQ(client_visitor.data().size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterInteractionTest, ClientServerInteractionWithCookies) {
  TestVisitor client_visitor;
  OgHttp2Adapter::Options client_options;
  client_options.perspective = Perspective::kClient;
  auto client_adapter = OgHttp2Adapter::Create(client_visitor, client_options);

  // The Cookie header field value will be consolidated during HEADERS frame
  // serialization.
  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"},
                 {"cookie", "a; b=2; c"},
                 {"cookie", "d=e, f, g; h"}});

  const int32_t stream_id1 =
      client_adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(client_visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(client_visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(client_visitor,
              OnBeforeFrameSent(HEADERS, stream_id1, _,
                                END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(client_visitor,
              OnFrameSent(HEADERS, stream_id1, _,
                          END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  int send_result = client_adapter->Send();
  EXPECT_EQ(0, send_result);

  TestVisitor server_visitor;
  OgHttp2Adapter::Options server_options;
  server_options.perspective = Perspective::kServer;
  auto server_adapter = OgHttp2Adapter::Create(server_visitor, server_options);

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(server_visitor, OnFrameHeader(0, _, SETTINGS, 0));
  EXPECT_CALL(server_visitor, OnSettingsStart());
  EXPECT_CALL(server_visitor, OnSetting).Times(testing::AnyNumber());
  EXPECT_CALL(server_visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(server_visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(server_visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(server_visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(server_visitor, OnHeaderForStream(1, ":scheme", "http"));
  EXPECT_CALL(server_visitor,
              OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(server_visitor,
              OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(server_visitor,
              OnHeaderForStream(1, "cookie", "a; b=2; c; d=e, f, g; h"));
  EXPECT_CALL(server_visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(server_visitor, OnEndStream(1));

  int64_t result = server_adapter->ProcessBytes(client_visitor.data());
  EXPECT_EQ(client_visitor.data().size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterTest, ServerForbidsNewStreamBelowWatermark) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(3,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Data(3, "This is the request body.")
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "http"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 25));
  EXPECT_CALL(visitor, OnDataForStream(3, "This is the request body."));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidNewStreamId));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  EXPECT_EQ(3, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerForbidsWindowUpdateOnIdleStream) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

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
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  EXPECT_EQ(1, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerForbidsDataOnIdleStream) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Data(1, "Sorry, out of order")
                                 .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kWrongFrameSequence));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  EXPECT_EQ(1, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerForbidsRstStreamOnIdleStream) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .RstStream(1, Http2ErrorCode::ENHANCE_YOUR_CALM)
          .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kWrongFrameSequence));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  EXPECT_EQ(1, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerForbidsNewStreamAboveStreamLimit) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  adapter->SubmitSettings({{MAX_CONCURRENT_STREAMS, 1}});

  const std::string initial_frames =
      TestFrameSequence().ClientPreface().Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(static_cast<size_t>(initial_result), initial_frames.size());

  EXPECT_TRUE(adapter->want_write());

  // Server initial SETTINGS (with MAX_CONCURRENT_STREAMS) and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // Let the client send a SETTINGS ack and then attempt to open more than the
  // advertised number of streams. The overflow stream should be rejected.
  const std::string stream_frames =
      TestFrameSequence()
          .SettingsAck()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/true)
          .Headers(3,
                   {{":method", "GET"},
                    {":scheme", "http"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/two"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor,
              OnFrameHeader(1, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor,
              OnFrameHeader(3, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kProtocol));
  // The oghttp2 stack also signals the error via OnConnectionError().
  EXPECT_CALL(visitor, OnConnectionError(
                           ConnectionError::kExceededMaxConcurrentStreams));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(static_cast<size_t>(stream_result), stream_frames.size());

  // The server should send a GOAWAY for this error, even though
  // OnInvalidFrame() returns true.
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerRstStreamsNewStreamAboveStreamLimitBeforeAck) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  adapter->SubmitSettings({{MAX_CONCURRENT_STREAMS, 1}});

  const std::string initial_frames =
      TestFrameSequence().ClientPreface().Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(static_cast<size_t>(initial_result), initial_frames.size());

  EXPECT_TRUE(adapter->want_write());

  // Server initial SETTINGS (with MAX_CONCURRENT_STREAMS) and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // Let the client avoid sending a SETTINGS ack and attempt to open more than
  // the advertised number of streams. The server should still reject the
  // overflow stream, albeit with RST_STREAM REFUSED_STREAM instead of GOAWAY.
  const std::string stream_frames =
      TestFrameSequence()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/true)
          .Headers(3,
                   {{":method", "GET"},
                    {":scheme", "http"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/two"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor,
              OnFrameHeader(1, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor,
              OnFrameHeader(3, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  3, Http2VisitorInterface::InvalidFrameError::kRefusedStream));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(static_cast<size_t>(stream_result), stream_frames.size());

  // The server sends a RST_STREAM for the offending stream.
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::REFUSED_STREAM)));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerForbidsProtocolPseudoheaderBeforeAck) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.allow_extended_connect = false;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string initial_frames =
      TestFrameSequence().ClientPreface().Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(static_cast<size_t>(initial_result), initial_frames.size());

  // The client attempts to send a CONNECT request with the `:protocol`
  // pseudoheader before receiving the server's SETTINGS frame.
  const std::string stream1_frames =
      TestFrameSequence()
          .Headers(1,
                   {{":method", "CONNECT"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"},
                    {":protocol", "websocket"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor,
              OnFrameHeader(1, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(5);
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  1, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  int64_t stream_result = adapter->ProcessBytes(stream1_frames);
  EXPECT_EQ(static_cast<size_t>(stream_result), stream1_frames.size());

  // Server initial SETTINGS and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  // The server sends a RST_STREAM for the offending stream.
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  // Server settings with ENABLE_CONNECT_PROTOCOL.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  adapter->SubmitSettings({{ENABLE_CONNECT_PROTOCOL, 1}});
  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // The client attempts to send a CONNECT request with the `:protocol`
  // pseudoheader before acking the server's SETTINGS frame.
  const std::string stream3_frames =
      TestFrameSequence()
          .Headers(3,
                   {{":method", "CONNECT"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/two"},
                    {":protocol", "websocket"}},
                   /*fin=*/true)
          .Serialize();

  // After sending SETTINGS with `ENABLE_CONNECT_PROTOCOL`, oghttp2 matches
  // nghttp2 in allowing this, even though the `allow_extended_connect` option
  // is false.
  EXPECT_CALL(visitor,
              OnFrameHeader(3, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  stream_result = adapter->ProcessBytes(stream3_frames);
  EXPECT_EQ(static_cast<size_t>(stream_result), stream3_frames.size());

  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterTest, ServerAllowsProtocolPseudoheaderAfterAck) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  adapter->SubmitSettings({{ENABLE_CONNECT_PROTOCOL, 1}});

  const std::string initial_frames =
      TestFrameSequence().ClientPreface().Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(static_cast<size_t>(initial_result), initial_frames.size());

  // Server initial SETTINGS (with ENABLE_CONNECT_PROTOCOL) and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  visitor.Clear();

  // The client attempts to send a CONNECT request with the `:protocol`
  // pseudoheader after acking the server's SETTINGS frame.
  const std::string stream_frames =
      TestFrameSequence()
          .SettingsAck()
          .Headers(1,
                   {{":method", "CONNECT"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"},
                    {":protocol", "websocket"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, _, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor,
              OnFrameHeader(1, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(static_cast<size_t>(stream_result), stream_frames.size());

  EXPECT_FALSE(adapter->want_write());
}

TEST_P(OgHttp2AdapterDataTest, SkipsSendingFramesForRejectedStream) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string initial_frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "http"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/true)
          .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor,
              OnFrameHeader(1, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(static_cast<size_t>(initial_result), initial_frames.size());

  visitor.AppendPayloadForStream(
      1, "Here is some data, which will be completely ignored!");
  auto body = std::make_unique<VisitorDataSource>(visitor, 1);

  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}),
                              GetParam() ? nullptr : std::move(body), false);
  ASSERT_EQ(0, submit_result);

  auto source = std::make_unique<TestMetadataSource>(ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}})));
  adapter->SubmitMetadata(1, 16384u, std::move(source));

  adapter->SubmitWindowUpdate(1, 1024);
  adapter->SubmitRst(1, Http2ErrorCode::INTERNAL_ERROR);

  // Server initial SETTINGS and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  // The server sends a RST_STREAM for the offending stream.
  // The response HEADERS, DATA and WINDOW_UPDATE are all ignored.
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttpAdapterServerTest, ServerStartsShutdown) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_FALSE(adapter->want_write());

  adapter->SubmitShutdownNotice();
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(GOAWAY, 0, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerStartsShutdownAfterGoaway) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_FALSE(adapter->want_write());

  adapter->SubmitGoAway(1, Http2ErrorCode::HTTP2_NO_ERROR,
                        "and don't come back!");
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(GOAWAY, 0, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));

  // No-op, since a GOAWAY has previously been enqueued.
  adapter->SubmitShutdownNotice();
  EXPECT_FALSE(adapter->want_write());
}

// Verifies that a connection-level processing error results in repeatedly
// returning a positive value for ProcessBytes() to mark all data as consumed
// when the blackhole option is enabled.
TEST(OgHttp2AdapterTest, ConnectionErrorWithBlackholingData) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.blackhole_data_on_connection_error = true;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface().WindowUpdate(1, 42).Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  E
"""


```
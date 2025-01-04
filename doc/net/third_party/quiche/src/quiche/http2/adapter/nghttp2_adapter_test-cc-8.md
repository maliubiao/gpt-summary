Response:
My thought process for analyzing the provided C++ test file and generating the response involved the following steps:

1. **Identify the Core Functionality:** The filename `nghttp2_adapter_test.cc` immediately suggests that this file contains unit tests for the `NgHttp2Adapter` class. The `NgHttp2Adapter` likely serves as a bridge or wrapper around the `nghttp2` library, adapting its API for use within the Chromium networking stack. The "adapter" naming convention reinforces this.

2. **Scan for Key Test Categories:**  I quickly scanned the test names (the `TEST` macros) to identify the major areas being tested. Keywords like "Interaction," "Settings," "Cookies," "Idle Stream," "Stream Limit," "Ping," "Invalid," "Protocol Pseudoheader," "Rejected Stream," and "Queued Metadata" stood out. These provide a high-level overview of the file's coverage.

3. **Analyze Individual Tests (Focused Reading):**  I then examined a few individual tests in more detail to understand the specific scenarios being validated. I looked for:
    * **Setup:** How are the `NgHttp2Adapter` instances (client and server) created? What initial settings are configured?
    * **Actions:** What methods of the `NgHttp2Adapter` are being called (e.g., `SubmitSettings`, `SubmitRequest`, `Send`, `ProcessBytes`, `SubmitResponse`, `SubmitMetadata`, `SubmitWindowUpdate`, `SubmitRst`)?
    * **Expectations (using `EXPECT_CALL`):** What interactions with the `TestVisitor` are anticipated? This reveals the expected behavior of the adapter in response to certain inputs and actions. I paid attention to the frame types (SETTINGS, HEADERS, DATA, RST_STREAM, GOAWAY, PING, WINDOW_UPDATE) and their flags.
    * **Assertions (`ASSERT_EQ`, `EXPECT_EQ`, `EXPECT_THAT`):** What specific conditions are being checked (e.g., return values of methods, the content of the `visitor.data()`, the highest received stream ID)?

4. **Infer Functionality Based on Tests:**  Based on the analyzed tests, I started to list the functionalities being tested:
    * Handling basic client-server interactions.
    * Processing and generating HTTP/2 frames (SETTINGS, HEADERS, DATA, etc.).
    * Managing settings, including `MAX_CONCURRENT_STREAMS` and `ENABLE_CONNECT_PROTOCOL`.
    * Handling repeated headers and cookies.
    * Enforcing HTTP/2 protocol rules (e.g., disallowing certain frames on idle streams, respecting stream limits).
    * Handling PING frames and automatic PING acknowledgments.
    * Validating settings values.
    * Managing metadata frames.
    * Dealing with stream resets.

5. **Identify Relationships with JavaScript:** I considered how the tested HTTP/2 functionalities relate to JavaScript in a browser context. The key connection is the `fetch` API and other network-related browser APIs that rely on HTTP. I focused on aspects like:
    * How JavaScript initiates HTTP/2 requests (headers, methods, paths).
    * How cookies set in JavaScript are transmitted in HTTP/2 headers.
    * How server push (though not explicitly shown in *this* snippet, the presence of `ENABLE_PUSH` suggests it's relevant in other parts of the code) could be related to JavaScript's ability to receive pushed resources.
    * How error handling in HTTP/2 might surface as network errors in JavaScript.

6. **Develop Hypothetical Scenarios (Input/Output):** For a few key tests, I constructed simple scenarios to illustrate the input to the `NgHttp2Adapter` and the expected output (as observed through the `TestVisitor`). This helps solidify understanding of the test's purpose.

7. **Identify Potential Usage Errors:** I looked for tests that explicitly check for invalid input or protocol violations. These highlight common mistakes developers might make when interacting with an HTTP/2 library.

8. **Trace User Operations (Debugging Context):** I considered how a user action in a browser (e.g., clicking a link, submitting a form) could lead to the execution of this code. This provides context for debugging.

9. **Synthesize the Summary:**  Finally, I synthesized the information gathered into a concise summary of the file's purpose, emphasizing its role in testing the `NgHttp2Adapter` and its coverage of various HTTP/2 protocol aspects. I also noted the file's position in the larger sequence of test files.

**Self-Correction/Refinement During the Process:**

* **Initial Overestimation:** I might initially think a test covers a broader area than it actually does. Closer inspection of the `EXPECT_CALL`s helps to narrow down the precise functionality being tested.
* **Focus on the Adapter:** I made sure to keep the focus on the `NgHttp2Adapter` and its behavior, even though the tests involve a `TestVisitor`. The visitor is a tool for observing the adapter's actions.
* **Connecting to JavaScript:**  I initially considered more complex JavaScript scenarios but decided to focus on the most direct and relevant connections to keep the explanation clear.
* **Iterative Refinement of Explanations:** I mentally rephrased explanations to ensure clarity and accuracy. For instance, instead of just saying "handles settings," I elaborated on the types of settings being handled.

By following this systematic approach, I aimed to provide a comprehensive and insightful analysis of the provided C++ test file.
这是一个 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc` 文件的第 9 部分，该文件主要用于测试 `NgHttp2Adapter` 类的功能。`NgHttp2Adapter` 的作用是将底层的 `nghttp2` 库适配到 Chromium 的 HTTP/2 接口。

**本部分（第 9 部分）的功能归纳:**

这部分代码主要测试了 `NgHttp2Adapter` 在处理各种异常和边界情况时的行为，特别是作为服务器端时：

* **禁止在空闲流上发送 WINDOW_UPDATE 帧:**  测试服务器是否会正确拒绝客户端在未建立的流上发送的窗口更新请求，并发送 `GOAWAY` 帧。
* **禁止在空闲流上发送 DATA 帧:** 测试服务器是否会正确拒绝客户端在未建立的流上发送的数据帧，并发送 `GOAWAY` 帧。
* **禁止在空闲流上发送 RST_STREAM 帧:** 测试服务器是否会正确拒绝客户端在未建立的流上发送的 RST_STREAM 帧，并发送 `GOAWAY` 帧。
* **禁止创建超过并发流限制的新流:** 测试服务器在设置了最大并发流数量后，是否会正确拒绝客户端创建超出限制的新流，并发送 `GOAWAY` 帧。
* **在收到 ACK 之前拒绝超过流限制的新流，并发送 RST_STREAM:**  测试服务器在尚未收到客户端对其 `MAX_CONCURRENT_STREAMS` 设置的确认时，如果客户端尝试创建超出限制的流，服务器是否会发送 `RST_STREAM` 帧来拒绝该流。
* **自动发送 SETTINGS 和 PING ACK:** 测试服务器是否会自动响应客户端的 `SETTINGS` 帧（发送 `SETTINGS ACK`）和 `PING` 帧（发送 `PING ACK`）。
* **禁用自动发送 PING ACK:** 测试在禁用自动 PING ACK 功能后，服务器是否不再自动响应客户端的 `PING` 帧。
* **处理无效的 MAX_FRAME_SIZE 设置:** 测试服务器是否会正确处理客户端发送的无效 `MAX_FRAME_SIZE` 设置，并发送 `GOAWAY` 帧。
* **处理无效的 PUSH 设置:** 测试服务器是否会正确处理客户端发送的无效 `ENABLE_PUSH` 设置，并发送 `GOAWAY` 帧。
* **处理无效的 CONNECT 协议设置:** 测试服务器是否会正确处理客户端发送的无效 `ENABLE_CONNECT_PROTOCOL` 设置，并发送 `GOAWAY` 帧。同时也测试了在收到客户端的 `ENABLE_CONNECT_PROTOCOL` 设置后，服务器是否允许客户端后续修改该设置 (尽管 RFC 不允许)。
* **在收到 ACK 之前禁止发送协议伪头:** 测试服务器在尚未收到客户端对其 `ENABLE_CONNECT_PROTOCOL` 设置的确认时，如果客户端发送包含 `:protocol` 伪头的 `CONNECT` 请求，服务器是否会拒绝该请求并发送 `RST_STREAM`。
* **在收到 ACK 之后允许发送协议伪头:** 测试服务器在收到客户端对其 `ENABLE_CONNECT_PROTOCOL` 设置的确认后，是否允许客户端发送包含 `:protocol` 伪头的 `CONNECT` 请求。
* **跳过发送已拒绝流的帧:** 测试服务器在拒绝一个流 (通过 `RST_STREAM`) 后，是否会跳过发送该流的响应头、数据和窗口更新等帧。但同时也注意到 `nghttp2` 似乎允许在已重置的流上发送扩展帧 (如 METADATA)。
* **在流重置时排队 Metadata:** 测试服务器在接收到客户端的流重置请求后，是否仍然可以排队并发送与该流相关的 Metadata 帧。

**与 JavaScript 的关系 (举例说明):**

这些测试直接关系到浏览器中 JavaScript 发起的 HTTP/2 请求的行为。例如：

* **`ClientServerInteractionRepeatedHeaderNames` 和 `ClientServerInteractionWithCookies`:**  当 JavaScript 使用 `fetch` API 发起请求，并且请求包含重复的头部字段 (例如，多个 `Accept` 或 `Cookie`) 时，这些测试确保了 `NgHttp2Adapter` 能正确处理这些头部信息，并将其传递给底层的 `nghttp2` 库，最终发送给服务器。服务器端也需要正确解析这些头部，这会影响到服务器端 JavaScript 或后端逻辑如何处理请求。
    * **假设输入:** JavaScript 代码执行 `fetch('/api', { headers: { 'Accept': 'text/plain', 'Accept': 'text/html' } })` 或设置了多个 `document.cookie`。
    * **输出:**  `NgHttp2Adapter` 将会生成包含两个 `accept` 头部字段的 HTTP/2 HEADERS 帧。服务器端的 `OnHeaderForStream` 回调会被调用两次，分别接收到 "text/plain" 和 "text/html"。
* **`ServerForbidsNewStreamAboveStreamLimit`:** 浏览器中的 JavaScript 可以并发发起多个请求。这个测试确保了当服务器设置了最大并发流限制后，`NgHttp2Adapter` 能正确处理超出限制的请求，并告知客户端。这会影响到 JavaScript 中 `fetch` 请求的并发执行行为，浏览器可能需要排队或取消超出限制的请求。
    * **假设输入:**  服务器发送了 `MAX_CONCURRENT_STREAMS = 1` 的 SETTINGS 帧。JavaScript 代码尝试几乎同时发起两个 `fetch` 请求。
    * **输出:** 第一个请求会被正常处理。当第二个请求到达服务器时，服务器会发送一个 `GOAWAY` 帧，指示发生了协议错误，或者发送 `RST_STREAM` 给第二个请求的流。浏览器中的 JavaScript 可能会收到一个网络错误。
* **`ServerAllowsProtocolPseudoheaderAfterAck`:**  当 JavaScript 使用 `fetch` API 发起一个 CONNECT 请求，并设置了 `:protocol` 伪头 (用于 WebSocket 等协议升级) 时，这个测试确保了只有在客户端收到并确认了服务器的 `ENABLE_CONNECT_PROTOCOL` 设置后，服务器才会接受这个请求。
    * **假设输入:** JavaScript 代码执行 `fetch('wss://example.com', { method: 'CONNECT', headers: { ':protocol': 'websocket' } })` 在服务器发送 `ENABLE_CONNECT_PROTOCOL` 的 SETTINGS 帧并被客户端确认后。
    * **输出:** `NgHttp2Adapter` 将会生成包含 `:method`, `:scheme`, `:authority`, `:path` 和 `:protocol` 伪头的 HTTP/2 HEADERS 帧。服务器端的 `OnHeaderForStream` 回调会被调用，包含 `:protocol` 头部。

**逻辑推理的假设输入与输出:**

以 `ServerForbidsWindowUpdateOnIdleStream` 为例：

* **假设输入:**
    * 服务器端 `NgHttp2Adapter` 实例已创建，但尚未接收到任何来自客户端的流相关的帧。
    * 客户端发送一个针对流 ID 1 的 `WINDOW_UPDATE` 帧，增加窗口大小 42。
* **输出:**
    * 服务器端的 `OnFrameHeader` 回调会被调用，接收到针对流 1 的 `WINDOW_UPDATE` 帧。
    * 服务器端的 `OnInvalidFrame` 回调会被调用，指示这是一个无效帧。
    * 服务器端的 `want_write()` 返回 `true`，表示需要发送数据。
    * 服务器会发送一个 `GOAWAY` 帧，错误代码为 `PROTOCOL_ERROR`。

**用户或编程常见的使用错误 (举例说明):**

* **客户端在连接建立初期 (未收到服务器 SETTINGS) 就发送依赖特定设置的帧:** 例如，在服务器允许 `CONNECT` 方法之前就发送包含 `:protocol` 伪头的 `CONNECT` 请求 (如 `ServerForbidsProtocolPseudoheaderBeforeAck` 测试所示)。这是一个常见的编程错误，开发者可能没有正确处理 HTTP/2 的握手和设置协商过程。
* **客户端尝试在未建立的流上发送数据或窗口更新:**  这违反了 HTTP/2 协议，`NgHttp2Adapter` 的测试确保了服务器能够正确处理这种情况，防止潜在的崩溃或安全问题。用户不太可能直接触发这种情况，但可能是由于客户端代码的错误逻辑导致。
* **服务器端设置了过小的 `MAX_CONCURRENT_STREAMS`，导致客户端请求被拒绝:**  这可能导致用户在浏览器中看到页面加载缓慢或部分资源加载失败。这是服务器配置错误，而不是用户操作错误。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在浏览器中访问一个使用了 HTTP/2 的网站，并且该网站的服务器配置了 `MAX_CONCURRENT_STREAMS` 为 1。

1. **用户在地址栏输入网址并回车，或者点击了一个链接。**
2. **浏览器开始与服务器建立 TCP 连接。**
3. **建立 TCP 连接后，浏览器和服务器进行 TLS 握手。**
4. **在 TLS 握手完成后，浏览器发送 HTTP/2 连接前导 (`PRI * HTTP/2.0\r\n\r\n`) 和初始的 SETTINGS 帧。**
5. **服务器接收到连接前导和 SETTINGS 帧，并返回自己的 SETTINGS 帧，其中包含 `MAX_CONCURRENT_STREAMS = 1`。**
6. **浏览器接收到服务器的 SETTINGS 帧并进行处理。**
7. **假设页面需要加载多个资源 (例如，CSS, JavaScript, 图片)。浏览器会尝试并发地请求这些资源。**
8. **浏览器会为每个资源创建一个 HTTP/2 流。**
9. **当浏览器尝试创建第二个流时，`NgHttp2Adapter` (作为服务器端的实现) 会检测到已达到 `MAX_CONCURRENT_STREAMS` 限制。**
10. **`ServerForbidsNewStreamAboveStreamLimit` 测试模拟的就是这个场景。**
11. **服务器会发送一个 `GOAWAY` 帧，指示发生了协议错误 (或发送 `RST_STREAM` 给超出限制的流)。**
12. **浏览器接收到 `GOAWAY` 帧，可能会取消后续的请求，并向用户显示部分加载的页面或错误信息。**

在调试过程中，开发者可能会查看网络请求日志，看到服务器发送的 `GOAWAY` 帧，并注意到错误代码指示了协议错误。这会引导开发者去检查服务器的 HTTP/2 配置，例如 `MAX_CONCURRENT_STREAMS` 的设置。

**总结来说，这个代码文件的第 9 部分主要关注 `NgHttp2Adapter` 作为 HTTP/2 服务器时，对各种非法或超出协议限制的客户端行为的处理，以及一些特定的协议细节 (如自动 PING ACK 和协议伪头)。这些测试确保了 Chromium 的 HTTP/2 实现的健壮性和符合标准。**

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共11部分，请归纳一下它的功能

"""
T_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterInteractionTest,
     ClientServerInteractionRepeatedHeaderNames) {
  TestVisitor client_visitor;
  auto client_adapter = NgHttp2Adapter::CreateClientAdapter(client_visitor);

  client_adapter->SubmitSettings({});

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
  EXPECT_CALL(client_visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(client_visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));
  int send_result = client_adapter->Send();
  EXPECT_EQ(0, send_result);

  TestVisitor server_visitor;
  auto server_adapter = NgHttp2Adapter::CreateServerAdapter(server_visitor);

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(server_visitor, OnFrameHeader(0, _, SETTINGS, 0));
  EXPECT_CALL(server_visitor, OnSettingsStart());
  EXPECT_CALL(server_visitor, OnSetting(_)).Times(testing::AnyNumber());
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

TEST(NgHttp2AdapterInteractionTest, ClientServerInteractionWithCookies) {
  TestVisitor client_visitor;
  auto client_adapter = NgHttp2Adapter::CreateClientAdapter(client_visitor);

  client_adapter->SubmitSettings({});

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
  auto server_adapter = NgHttp2Adapter::CreateServerAdapter(server_visitor);

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
  // Cookie values are preserved verbatim.
  EXPECT_CALL(server_visitor, OnHeaderForStream(1, "cookie", "a; b=2; c"));
  EXPECT_CALL(server_visitor, OnHeaderForStream(1, "cookie", "d=e, f, g; h"));
  EXPECT_CALL(server_visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(server_visitor, OnEndStream(1));

  int64_t result = server_adapter->ProcessBytes(client_visitor.data());
  EXPECT_EQ(client_visitor.data().size(), static_cast<size_t>(result));
}

TEST(NgHttp2AdapterTest, ServerForbidsWindowUpdateOnIdleStream) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

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
  EXPECT_EQ(frames.size(), result);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // The GOAWAY apparently causes the SETTINGS ack to be dropped.
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(NgHttp2AdapterTest, ServerForbidsDataOnIdleStream) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  // In this case, nghttp2 goes straight to GOAWAY and does not invoke the
  // invalid frame callback.
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // The GOAWAY apparently causes the SETTINGS ack to be dropped.
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(NgHttp2AdapterTest, ServerForbidsRstStreamOnIdleStream) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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
  EXPECT_CALL(visitor, OnInvalidFrame(1, _));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // The GOAWAY apparently causes the SETTINGS ack to be dropped.
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(NgHttp2AdapterTest, ServerForbidsNewStreamAboveStreamLimit) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  adapter->SubmitSettings({{MAX_CONCURRENT_STREAMS, 1}});

  const std::string initial_frames =
      TestFrameSequence().ClientPreface().Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_TRUE(adapter->want_write());

  // Server initial SETTINGS (with MAX_CONCURRENT_STREAMS) and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

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

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 0x5));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kProtocol));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

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

TEST(NgHttp2AdapterTest, ServerRstStreamsNewStreamAboveStreamLimitBeforeAck) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
  adapter->SubmitSettings({{MAX_CONCURRENT_STREAMS, 1}});

  const std::string initial_frames =
      TestFrameSequence().ClientPreface().Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_TRUE(adapter->want_write());

  // Server initial SETTINGS (with MAX_CONCURRENT_STREAMS) and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

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

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 0x5));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  3, Http2VisitorInterface::InvalidFrameError::kRefusedStream));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_result, stream_frames.size());

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

TEST(NgHttp2AdapterTest, AutomaticSettingsAndPingAcks) {
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

  // Server preface does not appear to include the mandatory SETTINGS frame.
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  // PING ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PING}));
}

TEST(NgHttp2AdapterTest, AutomaticPingAcksDisabled) {
  TestVisitor visitor;
  nghttp2_option* options;
  nghttp2_option_new(&options);
  nghttp2_option_set_no_auto_ping_ack(options, 1);
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor, options);
  nghttp2_option_del(options);

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

  // Server preface does not appear to include the mandatory SETTINGS frame.
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  // No PING ack expected because automatic PING acks are disabled.

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, InvalidMaxFrameSizeSetting) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames =
      TestFrameSequence().ClientPreface({{MAX_FRAME_SIZE, 3u}}).Serialize();
  testing::InSequence s;

  // Client preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, InvalidPushSetting) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames =
      TestFrameSequence().ClientPreface({{ENABLE_PUSH, 3u}}).Serialize();
  testing::InSequence s;

  // Client preface
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnInvalidFrame(0, _));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(NgHttp2AdapterTest, InvalidConnectProtocolSetting) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface({{ENABLE_CONNECT_PROTOCOL, 3u}})
                                 .Serialize();
  testing::InSequence s;

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(0, Http2VisitorInterface::InvalidFrameError::kProtocol));

  int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));

  auto adapter2 = NgHttp2Adapter::CreateServerAdapter(visitor);
  const std::string frames2 = TestFrameSequence()
                                  .ClientPreface({{ENABLE_CONNECT_PROTOCOL, 1}})
                                  .Settings({{ENABLE_CONNECT_PROTOCOL, 0}})
                                  .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{ENABLE_CONNECT_PROTOCOL, 1u}));
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  // Surprisingly, nghttp2 allows this behavior, which is prohibited in RFC
  // 8441.
  EXPECT_CALL(visitor, OnSetting(Http2Setting{ENABLE_CONNECT_PROTOCOL, 0u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  read_result = adapter2->ProcessBytes(frames2);
  EXPECT_EQ(static_cast<size_t>(read_result), frames2.size());

  EXPECT_TRUE(adapter2->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  adapter2->Send();
}

TEST(NgHttp2AdapterTest, ServerForbidsProtocolPseudoheaderBeforeAck) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(
      visitor,
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 1, name: [:protocol], value: [websocket]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  int64_t stream_result = adapter->ProcessBytes(stream1_frames);
  EXPECT_EQ(static_cast<size_t>(stream_result), stream1_frames.size());

  // Server sends a SETTINGS ack and initial SETTINGS (with
  // ENABLE_CONNECT_PROTOCOL).
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  // The server sends a RST_STREAM for the offending stream.
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  adapter->SubmitSettings({{ENABLE_CONNECT_PROTOCOL, 1}});
  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
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

  // Surprisingly, nghttp2 is okay with this.
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 0x5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  stream_result = adapter->ProcessBytes(stream3_frames);
  EXPECT_EQ(static_cast<size_t>(stream_result), stream3_frames.size());

  EXPECT_FALSE(adapter->want_write());
}

TEST(NgHttp2AdapterTest, ServerAllowsProtocolPseudoheaderAfterAck) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
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
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

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

  EXPECT_CALL(visitor, OnFrameHeader(0, _, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(static_cast<size_t>(stream_result), stream_frames.size());

  EXPECT_FALSE(adapter->want_write());
}

TEST_P(NgHttp2AdapterDataTest, SkipsSendingFramesForRejectedStream) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x5));
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
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  // nghttp2 apparently allows extension frames to be sent on reset streams.
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  // The server sends a RST_STREAM for the offending stream.
  // The response HEADERS, DATA and WINDOW_UPDATE are all ignored.
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS,
                            static_cast<SpdyFrameType>(kMetadataFrameType),
                            SpdyFrameType::RST_STREAM}));
}

TEST_P(NgHttp2AdapterDataTest, ServerQueuesMetadataWithStreamReset) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string initial_frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "http"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/false)
          .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

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

  const std::string reset_frame =
      TestFrameSequence().RstStream(1, Http2ErrorCode::CANCEL).Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(1, _, RST_STREAM, 0x0));
  EXPECT_CALL(visitor, OnRstStream(1, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnClose
"""


```
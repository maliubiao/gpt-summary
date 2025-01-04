Response:
The user wants a summary of the functionality of the provided C++ source code file.
The file is a test suite for `OgHttp2Adapter`, which is likely an HTTP/2 adapter implementation within the Chromium network stack.
The tests cover various scenarios of HTTP/2 communication, including:
- Handling valid and invalid frames.
- Server and client perspectives.
- Error handling.
- Interaction between client and server.
- Flow control.
- Header processing.
- Sending and receiving data.

The user also has specific requests:
- Identify relationships with Javascript (unlikely in a low-level networking component test).
- Provide example inputs and outputs for logical inferences (the tests themselves serve as examples).
- Highlight common usage errors (the tests cover error scenarios).
- Explain how a user operation might lead to this code (debugging context).
- Summarize the file's overall functionality as part 9 of 12.

Plan:
1. Summarize the primary function of the test file: verifying the behavior of `OgHttp2Adapter`.
2. Analyze the individual test cases to extract specific functionalities being tested.
3. Address the relationship with Javascript (likely none directly).
4. Point out that the tests themselves illustrate input/output behavior.
5. Identify test cases that simulate common usage errors.
6. Describe the role of such tests in debugging and how user actions can trigger these code paths.
7. Provide a concise summary of the file's purpose based on the analyzed test cases, considering it's part 9 of a larger series.
ThisC++源代码文件 `oghttp2_adapter_test.cc` 是 Chromium 网络栈中 `OgHttp2Adapter` 组件的单元测试文件。`OgHttp2Adapter` 看起来是一个 HTTP/2 协议的适配器实现。

**主要功能:**

这个文件的主要功能是**验证 `OgHttp2Adapter` 组件在各种场景下的正确行为**。它通过创建 `OgHttp2Adapter` 的实例，并模拟 HTTP/2 通信中的各种事件和帧序列，然后使用 Google Test 框架 (EXPECT_CALL, EXPECT_EQ, EXPECT_TRUE 等) 来断言 `OgHttp2Adapter` 的行为是否符合预期。

以下是根据提供的代码片段归纳的一些具体测试功能：

* **处理SETTINGS帧:**  测试了客户端和服务端接收和发送 SETTINGS 帧的行为，包括处理 ACK 标志。例如，`ServerIgnoresSettingThatLowersWindow` 和 `ServerIgnoresSettingThatRaisesMaxHeaderListSize` 测试了服务端如何处理特定的 SETTINGS 参数。
* **处理RST_STREAM帧:** 测试了服务端在处理错误时发送 RST_STREAM 帧的行为，以及客户端接收 RST_STREAM 帧的行为。例如，`ServerConnectionErrorWhileHandlingHeaders` 测试了服务端在处理头部时遇到错误发送 RST_STREAM。
* **处理HEADERS帧:** 测试了服务端接收和解析客户端发送的 HEADERS 帧，以及客户端接收服务端发送的 HEADERS 帧。例如，`ServerErrorAfterHandlingHeaders` 测试了服务端在处理完头部后发生错误的情况。
* **处理DATA帧:** 测试了服务端接收和处理客户端发送的 DATA 帧的行为。例如，`ServerRejectsBeginningOfData` 测试了服务端拒绝接收 DATA 帧的情况。
* **处理GOAWAY帧:** 测试了服务端接收客户端发送的 GOAWAY 帧后的行为。例如，`ServerReceivesGoAway` 测试了服务端收到 GOAWAY 后仍然能够发送响应。
* **处理PING帧:**  虽然提供的片段中没有直接测试 PING 帧，但在 `ServerRejectsFrameHeader` 测试中，PING 帧被用作一个被拒绝的帧头示例。
* **处理窗口更新 (WINDOW_UPDATE) 帧:** 虽然在提供的片段中没有显式测试，但在一些场景中使用了 `WindowUpdate` 帧来模拟流量控制。
* **错误处理:** 测试了各种错误场景，例如无效的头部字段、过大的头部、接收到无法处理的帧等。例如，`ServerConnectionErrorWhileHandlingHeaders` 和 `ServerErrorAfterHandlingHeaders` 测试了不同的服务端错误场景。
* **客户端和服务端交互:**  `ClientServerInteractionTest` 测试了一个简单的客户端和服务端之间的交互，模拟了请求和响应的过程。
* **流的管理:** 测试了流的创建、关闭和重置等操作。
* **HPACK 编码:**  `ServerSubmitResponse` 测试了响应头部的 HPACK 编码大小。
* **用户数据关联:**  `ServerSubmitResponse` 测试了如何为流设置和获取用户数据。

**与 Javascript 的关系:**

这个文件是 C++ 代码，直接与 Javascript 没有关系。`OgHttp2Adapter` 作为网络栈的一部分，负责底层的 HTTP/2 协议处理。Javascript 通常通过浏览器提供的 Web API (如 `fetch` 或 `XMLHttpRequest`)  来发起 HTTP 请求，而这些 API 的底层实现会涉及到像 `OgHttp2Adapter` 这样的组件来处理具体的协议细节。

**举例说明:**

当 Javascript 代码使用 `fetch` 发起一个 HTTP/2 请求时，浏览器的网络栈会创建相应的 HTTP/2 连接，并使用 `OgHttp2Adapter` 将请求头和数据序列化成 HTTP/2 帧。

**假设输入与输出 (逻辑推理):**

以 `ServerReceivesInvalidAuthority` 测试为例：

* **假设输入:** 客户端发送一个包含无效 `:authority` 头部字段的 HEADERS 帧，例如 `":authority", "ex|ample.com"`。
* **预期输出:** 服务端 `OgHttp2Adapter` 检测到无效的 authority，调用 `visitor` 的 `OnInvalidFrame` 回调，然后发送一个 RST_STREAM 帧来关闭该流，并可能发送一个 GOAWAY 帧来关闭连接。

**用户或编程常见的使用错误:**

这些测试实际上是在模拟各种可能的用户或编程错误，例如：

* **发送格式错误的 HTTP/2 帧:** 例如，发送带有非法字符的头部字段，如 `ServerReceivesInvalidAuthority` 所示。
* **违反 HTTP/2 协议规范:** 例如，发送过大的头部，如 `ServerReceivesTooLargeHeader` 所示。
* **在连接的不同状态下发送不合法的帧:**  虽然此代码片段未直接展示，但其他测试文件中可能会有此类测试。
* **服务器端逻辑错误导致无法正确处理请求:** 例如，`ServerErrorAfterHandlingHeaders` 模拟了服务端在接收到完整的头部后由于自身错误而关闭连接。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入 URL 或点击链接，发起一个 HTTPS 请求。**
2. **浏览器首先进行 DNS 查询，解析域名对应的 IP 地址。**
3. **浏览器与服务器建立 TCP 连接。**
4. **如果服务器支持 HTTP/2，浏览器和服务器会进行 TLS 握手，并在 ALPN (Application-Layer Protocol Negotiation) 阶段协商使用 HTTP/2 协议。**
5. **一旦确定使用 HTTP/2，浏览器会使用其内部的 HTTP/2 实现（可能包含 `OgHttp2Adapter`）来将请求头和数据组织成 HTTP/2 帧。**
6. **`OgHttp2Adapter` 负责将这些帧序列化成字节流，并通过底层的 Socket 发送给服务器。**
7. **在服务器端，也会有类似的 HTTP/2 适配器来接收和解析这些帧。**

如果在调试过程中发现 HTTP/2 连接存在问题，例如连接被意外关闭、请求失败等，开发者可能会查看网络栈的日志或者使用网络抓包工具 (如 Wireshark) 来分析 HTTP/2 帧的交互过程。如果怀疑是 `OgHttp2Adapter` 的问题，开发者可能会参考这些单元测试来理解 `OgHttp2Adapter` 在各种情况下的预期行为，从而定位问题。

**作为第 9 部分的功能归纳:**

作为系列测试的第 9 部分，这个文件继续深入测试 `OgHttp2Adapter` 的服务端行为，特别是**服务端在接收到客户端请求后的处理逻辑和错误处理机制**。它涵盖了服务端如何解析各种类型的帧，如何处理错误，以及如何在不同的情况下发送响应或错误指示。 这一部分可能侧重于服务端作为接收方时，对客户端行为的健壮性处理。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共12部分，请归纳一下它的功能

"""
          }),
                               testing::Return(true)));
  // The rest of the metadata is not delivered to the visitor.

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::REFUSED_STREAM)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerConnectionErrorWhileHandlingHeaders) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"Accept", "uppercase, oh boy!"}},
                                          /*fin=*/false)
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .WindowUpdate(0, 2000)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kHeaderError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::RST_STREAM,
                            SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerErrorAfterHandlingHeaders) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
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
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .WindowUpdate(0, 2000)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

// Exercises the case when a visitor chooses to reject a frame based solely on
// the frame header, which is a fatal error for the connection.
TEST(OgHttp2AdapterTest, ServerRejectsFrameHeader) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Ping(64)
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .WindowUpdate(0, 2000)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerRejectsBeginningOfData) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
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

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 25))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ServerReceivesTooLargeHeader) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.max_header_list_bytes = 64 * 1024;
  options.max_header_field_size = 64 * 1024;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  // Due to configuration, the library will accept a maximum of 64kB of huffman
  // encoded data per header field.
  const std::string too_large_value = std::string(80 * 1024, 'q');
  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"x-toobig", too_large_value}},
                                          /*fin=*/true)
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, END_STREAM_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, CONTINUATION, 0)).Times(3);
  EXPECT_CALL(visitor, OnFrameHeader(1, _, CONTINUATION, END_HEADERS_FLAG));
  // Further header processing is skipped, as the header field is too large.

  EXPECT_CALL(visitor,
              OnFrameHeader(3, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<int64_t>(frames.size()), result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerReceivesInvalidAuthority) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "ex|ample.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<int64_t>(frames.size()), result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0x0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0x0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttpAdapterTest, ServerReceivesGoAway) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/true)
                                 .GoAway(0, Http2ErrorCode::HTTP2_NO_ERROR, "")
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
  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0x0));
  EXPECT_CALL(visitor, OnGoAway(0, Http2ErrorCode::HTTP2_NO_ERROR, ""));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<int64_t>(frames.size()), result);

  // The server should still be able to send a response after receiving a GOAWAY
  // with a lower last-stream-ID field, as the stream was client-initiated.
  const int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}),
                              /*data_source=*/nullptr, true);
  ASSERT_EQ(0, submit_result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0x0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0x0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS}));
}

TEST_P(OgHttp2AdapterDataTest, ServerSubmitResponse) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

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

  const char* kSentinel1 = "arbitrary pointer 1";

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1))
      .WillOnce(testing::InvokeWithoutArgs([&adapter, kSentinel1]() {
        adapter->SetStreamUserData(1, const_cast<char*>(kSentinel1));
        return true;
      }));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_EQ(1, adapter->GetHighestReceivedStreamId());

  // Server will want to send a SETTINGS and a SETTINGS ack.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_EQ(0, adapter->GetHpackEncoderDynamicTableSize());

  EXPECT_FALSE(adapter->want_write());
  const absl::string_view kBody = "This is an example response body.";
  // A data fin is not sent so that the stream remains open, and the flow
  // control state can be verified.
  visitor.AppendPayloadForStream(1, kBody);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result = adapter->SubmitResponse(
      1,
      ToHeaders({{":status", "404"},
                 {"x-comment", "I have no idea what you're talking about."}}),
      GetParam() ? nullptr : std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  // Stream user data should have been set successfully after receiving headers.
  EXPECT_EQ(kSentinel1, adapter->GetStreamUserData(1));
  adapter->SetStreamUserData(1, nullptr);
  EXPECT_EQ(nullptr, adapter->GetStreamUserData(1));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);

  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  EXPECT_FALSE(adapter->want_write());

  // Some data was sent, so the remaining send window size should be less than
  // the default.
  EXPECT_LT(adapter->GetStreamSendWindowSize(1), kInitialFlowControlWindowSize);
  EXPECT_GT(adapter->GetStreamSendWindowSize(1), 0);
  // Send window for a nonexistent stream is not available.
  EXPECT_EQ(adapter->GetStreamSendWindowSize(3), -1);

  EXPECT_GT(adapter->GetHpackEncoderDynamicTableSize(), 0);
}

TEST_P(OgHttp2AdapterDataTest, ServerSubmitResponseWithResetFromClient) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

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
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_EQ(1, adapter->GetHighestReceivedStreamId());

  // Server will want to send a SETTINGS and a SETTINGS ack.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(adapter->want_write());
  const absl::string_view kBody = "This is an example response body.";
  visitor.AppendPayloadForStream(1, kBody);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result = adapter->SubmitResponse(
      1,
      ToHeaders({{":status", "404"},
                 {"x-comment", "I have no idea what you're talking about."}}),
      GetParam() ? nullptr : std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  // Client resets the stream before the server can send the response.
  const std::string reset =
      TestFrameSequence().RstStream(1, Http2ErrorCode::CANCEL).Serialize();
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(1, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::CANCEL));
  const int64_t reset_result = adapter->ProcessBytes(reset);
  EXPECT_EQ(reset.size(), static_cast<size_t>(reset_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, _)).Times(0);
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, _, _)).Times(0);
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, _, _)).Times(0);

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);

  EXPECT_THAT(visitor.data(), testing::IsEmpty());
}

TEST(OgHttp2AdapterTest, ServerRejectsStreamData) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
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

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 25));
  EXPECT_CALL(visitor, OnDataForStream(1, _)).WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

using OgHttp2AdapterInteractionDataTest = OgHttp2AdapterDataTest;

INSTANTIATE_TEST_SUITE_P(BothValues, OgHttp2AdapterInteractionDataTest,
                         testing::Bool());
// Exercises a naive mutually recursive test client and server. This test fails
// without recursion guards in OgHttp2Session.
TEST_P(OgHttp2AdapterInteractionDataTest, ClientServerInteractionTest) {
  TestVisitor client_visitor;
  OgHttp2Adapter::Options client_options;
  client_options.perspective = Perspective::kClient;
  auto client_adapter = OgHttp2Adapter::Create(client_visitor, client_options);
  TestVisitor server_visitor;
  OgHttp2Adapter::Options server_options;
  server_options.perspective = Perspective::kServer;
  auto server_adapter = OgHttp2Adapter::Create(server_visitor, server_options);

  EXPECT_CALL(client_visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(client_visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0x0));
  EXPECT_CALL(client_visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(client_visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0x0));
  // Feeds bytes sent from the client into the server's ProcessBytes.
  EXPECT_CALL(client_visitor, OnReadyToSend(_))
      .WillRepeatedly(
          testing::Invoke(server_adapter.get(), &OgHttp2Adapter::ProcessBytes));
  // Feeds bytes sent from the server into the client's ProcessBytes.
  EXPECT_CALL(server_visitor, OnReadyToSend(_))
      .WillRepeatedly(
          testing::Invoke(client_adapter.get(), &OgHttp2Adapter::ProcessBytes));
  // Sets up the server to respond automatically to a request from a client.
  EXPECT_CALL(server_visitor, OnEndHeadersForStream(_))
      .WillRepeatedly([&server_adapter](Http2StreamId stream_id) {
        server_adapter->SubmitResponse(
            stream_id, ToHeaders({{":status", "200"}}), nullptr, true);
        server_adapter->Send();
        return true;
      });
  // Sets up the client to create a new stream automatically when receiving a
  // response.
  EXPECT_CALL(client_visitor, OnEndHeadersForS
"""


```
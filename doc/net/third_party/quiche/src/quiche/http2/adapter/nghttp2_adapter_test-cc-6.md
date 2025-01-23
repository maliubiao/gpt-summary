Response:
The user wants to understand the functionality of the `nghttp2_adapter_test.cc` file in the Chromium network stack. They are interested in:

1. **General functionality:** What does this file do?
2. **Relationship to JavaScript:** Does it have any connection to JavaScript?
3. **Logic and examples:**  Provide examples with assumed inputs and outputs.
4. **Common user errors:**  Highlight common mistakes.
5. **Debugging steps:** How does a user's action lead to this code?
6. **Summary:**  Provide a concise overview of the file's purpose, considering this is part 7 of 11.

**Thinking Process:**

1. **Identify the core purpose:** The file name strongly suggests it's a test file (`_test.cc`) for the `NgHttp2Adapter`. This adapter likely bridges Chromium's HTTP/2 implementation with the `nghttp2` library.

2. **Analyze the test cases:** Scan the provided code snippets. The tests are named descriptively (e.g., `ServerErrorWhileHandlingHeadersDropsFrames`). They use `TestVisitor` and `TestFrameSequence`, indicating they are simulating HTTP/2 interactions and verifying the adapter's behavior.

3. **JavaScript relationship:** HTTP/2 is a transport protocol used by web browsers (which execute JavaScript). While this C++ file *implements* part of that protocol, it doesn't directly interact with JavaScript code. The connection is indirect – JavaScript makes network requests that eventually rely on this C++ code for the HTTP/2 handling.

4. **Logic and Examples:** The tests themselves are examples. Each `TEST` block sets up an input (a sequence of HTTP/2 frames) and defines expected outputs (calls to the `TestVisitor` mock object). I can rephrase one of these as a user scenario and describe the expected internal behavior of the adapter.

5. **Common User Errors:** Since this is low-level network code, "user errors" in the traditional sense are less relevant. Instead, focus on *programming errors* that developers working with this code or its abstractions might make. Misinterpreting HTTP/2 specifications or incorrectly using the `NgHttp2Adapter` API are possibilities.

6. **Debugging Steps:**  Think about how a network request initiated from a web page (triggered by JavaScript) would travel through the Chromium stack. It would involve layers like the network service, socket handling, and finally, the HTTP/2 implementation. A network issue or unexpected server behavior might lead a developer to debug within the HTTP/2 adapter.

7. **Summarize for Part 7:**  Given the context of a test file, its primary role is verification. It ensures the `NgHttp2Adapter` behaves correctly under various conditions. Since it's part 7, earlier parts likely defined the adapter itself, and later parts might cover other aspects of HTTP/2 implementation.

**Pre-computation/Analysis (based on the code snippets):**

* **Key Classes:** `NgHttp2Adapter`, `TestVisitor`, `TestFrameSequence`.
* **Testing Focus:** Handling various HTTP/2 frame types (HEADERS, DATA, WINDOW_UPDATE, RST_STREAM, SETTINGS, GOAWAY, PING, METADATA) and error conditions.
* **Visitor Pattern:** The `TestVisitor` acts as a mock to observe the adapter's actions.
* **Frame Serialization:** `TestFrameSequence` helps create byte sequences representing HTTP/2 frames.
* **Error Handling:** The tests cover scenarios where the adapter encounters errors and how it reacts.

**Confidence Score:** 5/5 - I'm confident I can address all aspects of the user's request based on the provided information and my understanding of software testing and network protocols.
这是Chromium网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc` 文件的第 7 部分，它主要用于测试 `NgHttp2Adapter` 类的功能。`NgHttp2Adapter` 的作用是在 Chromium 的网络栈和 `nghttp2` 库之间提供一个适配层，`nghttp2` 是一个实现了 HTTP/2 协议的 C 库。

**功能归纳 (基于提供的代码片段和上下文):**

这部分测试主要关注 `NgHttp2Adapter` 作为 **服务器端** 的行为，特别是当客户端发送请求时，适配器如何处理各种异常和错误情况，以及如何响应客户端的请求。具体来说，测试了以下方面：

1. **处理头部时的错误 (Server Error While Handling Headers Drops Frames):**
   - 验证当服务器在处理客户端发送的头部时遇到错误（例如，由于 `accept` 头部的值无效而返回 `Http2VisitorInterface::HEADER_RST_STREAM`）时，适配器会正确地发送 `RST_STREAM` 帧来终止该流，并丢弃该流后续的帧（例如 DATA 帧）。
   - 测试了即使在错误发生后，适配器仍然能够处理后续的连接级别的帧（例如 WINDOW_UPDATE）和其他流的帧（例如 HEADERS 和 METADATA）。

2. **处理头部时的连接错误 (Server Connection Error While Handling Headers):**
   - 测试当服务器在处理客户端发送的头部时遇到更严重的错误（例如，接收到大小写不正确的头部 "Accept"）时，适配器会发送 `RST_STREAM` 帧来终止该流，并报告连接级别的错误。

3. **处理头部后的错误 (ServerError After Handling Headers):**
   - 验证当服务器在成功处理完头部后遇到错误（例如，`OnEndHeadersForStream` 返回 `false`）时，适配器会报告连接级别的错误。

4. **拒绝帧头部 (Server Rejects Frame Header):**
   - 测试当服务器决定基于帧头部拒绝接收该帧时（例如，`OnFrameHeader` 返回 `false`），适配器会报告连接级别的错误。

5. **拒绝数据帧的开始或数据 (Server Rejects Beginning Of Data, Server Rejects Stream Data):**
   - 验证当服务器拒绝接收数据帧的开始部分或数据内容时（例如，`OnBeginDataForStream` 或 `OnDataForStream` 返回 `false`），适配器会报告连接级别的错误。

6. **接收过大的头部 (Server Receives Too Large Header):**
   - 测试当服务器接收到超过允许大小的头部字段时，适配器会发送 `GOAWAY` 帧并关闭连接。

7. **接收无效的 Authority 头部 (Server Receives Invalid Authority):**
   - 验证当服务器接收到无效的 `:authority` 头部时，适配器会发送 `RST_STREAM` 帧来终止该流。

8. **接收 GOAWAY 帧 (Server Receives GoAway):**
   - 测试服务器在接收到客户端发送的 `GOAWAY` 帧后，仍然可以处理之前客户端发起的流，并发送响应。

9. **提交响应 (ServerSubmitResponse, ServerSubmitResponseWithResetFromClient):**
   - 验证服务器如何使用 `SubmitResponse` 方法来发送响应头部和数据。
   - 测试在服务器准备发送响应时，客户端发送 `RST_STREAM` 帧取消请求的情况，确保适配器能够正确处理。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能直接影响着使用 HTTP/2 协议的 JavaScript 代码的行为。

**举例说明：**

假设一个 JavaScript 应用发起了一个 HTTP/2 POST 请求，并在请求头中设置了一个无效的 `accept` 值（例如，`accept: some bogus value!`）。

1. **用户操作：** 用户在浏览器中执行 JavaScript 代码，该代码使用 `fetch` 或 `XMLHttpRequest` 发送 HTTP/2 请求。
2. **网络栈处理：** Chromium 的网络栈会构建 HTTP/2 帧，其中包含请求头信息。
3. **`nghttp2_adapter_test.cc` 中的测试场景：** 上述代码片段中的 `ServerErrorWhileHandlingHeadersDropsFrames` 测试了这种情况。当 `NgHttp2Adapter` 处理到这个无效的 `accept` 头部时，`TestVisitor` 被配置为返回 `Http2VisitorInterface::HEADER_RST_STREAM`，模拟服务器端决定终止这个流。
4. **适配器行为：** `NgHttp2Adapter` 会生成并发送一个 `RST_STREAM` 帧给客户端，通知客户端该请求被终止。
5. **JavaScript 观察：**  JavaScript 代码会收到一个网络错误，表明请求失败。具体的错误信息可能因浏览器和错误处理方式而异，但通常会指示连接被重置或中断。

**逻辑推理、假设输入与输出：**

**假设输入 (基于 `ServerErrorWhileHandlingHeadersDropsFrames` 测试):**

```
Client Preface (SETTINGS 帧)
HEADERS 帧 (Stream ID 1, 包含无效的 "accept" 头部)
WINDOW_UPDATE 帧 (Stream ID 1)
DATA 帧 (Stream ID 1, 请求体)
WINDOW_UPDATE 帧 (Stream ID 0, 连接级别)
```

**预期输出 (通过 `TestVisitor` 的回调验证):**

```
OnFrameHeader(0, 0, SETTINGS, 0)  // 接收到客户端的 SETTINGS 帧
OnSettingsStart()
OnSettingsEnd()
OnFrameHeader(1, _, HEADERS, 4)   // 接收到 HEADERS 帧
OnBeginHeadersForStream(1)
OnHeaderForStream(1, ":method", "POST")
OnHeaderForStream(1, ":scheme", "https")
OnHeaderForStream(1, ":authority", "example.com")
OnHeaderForStream(1, ":path", "/this/is/request/one")
OnHeaderForStream(1, "accept", "some bogus value!") // 处理到无效头部
// 由于 visitor 返回 HEADER_RST_STREAM，后续的 DATA 帧不会被传递
OnFrameHeader(1, 4, WINDOW_UPDATE, 0) // 接收到 Stream ID 1 的 WINDOW_UPDATE
OnWindowUpdate(1, 2000)
OnFrameHeader(0, 4, WINDOW_UPDATE, 0) // 接收到 Stream ID 0 的 WINDOW_UPDATE
OnWindowUpdate(0, 2000)
// 发送服务器的 SETTINGS ACK
OnBeforeFrameSent(SETTINGS, 0, 0, 0x1)
OnFrameSent(SETTINGS, 0, 0, 0x1, 0)
// 发送 RST_STREAM 帧
OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0)
OnFrameSent(RST_STREAM, 1, 4, 0x0, static_cast<int>(Http2ErrorCode::INTERNAL_ERROR))
OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR)
```

**用户或编程常见的使用错误：**

1. **服务器端配置错误：**  例如，服务器没有正确配置支持的 HTTP/2 头部，导致收到客户端发送的有效头部时却无法处理。测试中的无效 `accept` 头部就是一个例子，实际应用中可能是服务器不支持客户端要求的某种内容类型。
2. **客户端发送了不符合 HTTP/2 规范的请求：**  例如，发送大小写错误的头部（如 "Accept" 而不是 "accept"）。测试中的 `Server Connection Error While Handling Headers` 覆盖了这种情况。
3. **对 `NgHttp2Adapter` API 的错误使用：** 如果开发者直接使用 `NgHttp2Adapter` (虽然通常是在 Chromium 内部使用)，可能会错误地调用其方法或错误地处理回调，导致与 `nghttp2` 库的交互不正确。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器中访问一个网站或执行 JavaScript 代码。**
2. **JavaScript 代码发起一个 HTTP/2 请求。**
3. **Chromium 网络栈开始处理该请求。**
4. **请求被传递到 HTTP/2 处理模块。**
5. **`NgHttp2Adapter` 负责将 Chromium 的表示转换为 `nghttp2` 库可以理解的格式，并处理来自 `nghttp2` 的事件。**
6. **如果请求存在问题（例如，无效的头部），`NgHttp2Adapter` 的服务器端处理逻辑会被触发，这正是这部分测试所覆盖的场景。**
7. **在调试过程中，开发者可能会在 `NgHttp2Adapter` 的相关代码中设置断点，以查看请求处理的细节以及错误发生的原因。** 这部分测试文件中的断言 (`EXPECT_CALL`) 可以帮助开发者理解期望的行为与实际行为是否一致。

**总结作为第 7 部分的功能：**

作为 `nghttp2_adapter_test.cc` 的第 7 部分，这组测试专注于验证 `NgHttp2Adapter` 作为 HTTP/2 **服务器端** 在接收到客户端请求时，对于各种错误和异常情况的处理逻辑。它确保了当客户端发送不符合规范或服务器无法处理的请求时，适配器能够正确地报告错误、终止连接或流，并保持自身的稳定性。这对于保障 Chromium 网络栈的健壮性和与各种不良客户端行为的互操作性至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
= NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"accept", "some bogus value!"}},
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
  EXPECT_CALL(visitor, OnHeaderForStream(1, "accept", "some bogus value!"))
      .WillOnce(testing::Return(Http2VisitorInterface::HEADER_RST_STREAM));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
  // DATA frame is not delivered to the visitor.
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 2000));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ServerErrorWhileHandlingHeadersDropsFrames) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"accept", "some bogus value!"}},
                                          /*fin=*/false)
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .Metadata(1, "This is the request metadata.")
                                 .RstStream(1, Http2ErrorCode::CANCEL)
                                 .WindowUpdate(0, 2000)
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/false)
                                 .Metadata(3, "This is the request metadata.",
                                           /*multiple_frames=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnHeaderForStream(1, "accept", "some bogus value!"))
      .WillOnce(testing::Return(Http2VisitorInterface::HEADER_RST_STREAM));
  // For the RST_STREAM-marked stream, the control frames and METADATA frame but
  // not the DATA frame are delivered to the visitor.
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(1, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 2000));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, kMetadataFrameType, 0));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(3, _));
  EXPECT_CALL(visitor, OnMetadataForStream(3, "This is the re"))
      .WillOnce(testing::DoAll(testing::InvokeWithoutArgs([&adapter]() {
                                 adapter->SubmitRst(
                                     3, Http2ErrorCode::REFUSED_STREAM);
                               }),
                               testing::Return(true)));
  // The rest of the metadata is still delivered to the visitor.
  EXPECT_CALL(visitor, OnFrameHeader(3, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(3, _));
  EXPECT_CALL(visitor, OnMetadataForStream(3, "quest metadata."));
  EXPECT_CALL(visitor, OnMetadataEndForStream(3));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::REFUSED_STREAM)));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::REFUSED_STREAM));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::RST_STREAM,
                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ServerConnectionErrorWhileHandlingHeaders) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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
  EXPECT_CALL(visitor, OnErrorDebug);
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader))
      .WillOnce(testing::Return(false));
  // Translation to nghttp2 treats this error as a general parsing error.
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(result, NGHTTP2_ERR_CALLBACK_FAILURE);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack and RST_STREAM
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ServerErrorAfterHandlingHeaders) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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
  EXPECT_EQ(-902, result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

// Exercises the case when a visitor chooses to reject a frame based solely on
// the frame header, which is a fatal error for the connection.
TEST(NgHttp2AdapterTest, ServerRejectsFrameHeader) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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
  EXPECT_EQ(-902, result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ServerRejectsBeginningOfData) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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
  EXPECT_EQ(NGHTTP2_ERR_CALLBACK_FAILURE, result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack.
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ServerRejectsStreamData) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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
  EXPECT_EQ(NGHTTP2_ERR_CALLBACK_FAILURE, result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack.
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ServerReceivesTooLargeHeader) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  // nghttp2 will accept a maximum of 64kB of huffman encoded data per header
  // field.
  const std::string too_large_value = std::string(80 * 1024, 'q');
  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"x-toobig", too_large_value}},
                                          /*fin=*/false)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  // Further header processing is skipped, as the header field is too large.

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_TRUE(adapter->want_write());

  // Since nghttp2 opted not to process the header, it generates a GOAWAY with
  // error code COMPRESSION_ERROR.
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, 8, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, 8, 0x0,
                          static_cast<int>(Http2ErrorCode::COMPRESSION_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // GOAWAY.
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(NgHttp2AdapterTest, ServerReceivesInvalidAuthority) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

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
      OnErrorDebug("Invalid HTTP header field was received: frame type: 1, "
                   "stream: 1, name: [:authority], value: [ex|ample.com]"));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0x0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(NgHttpAdapterTest, ServerReceivesGoAway) {
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
                                 .GoAway(0, Http2ErrorCode::HTTP2_NO_ERROR, "")
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0x0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
}

TEST_P(NgHttp2AdapterDataTest, ServerSubmitResponse) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
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

  // Server will want to send a SETTINGS ack.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
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

TEST_P(NgHttp2AdapterDataTest, ServerSubmitResponseWithResetFromClient) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);
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

  // Server will want to send a SETTINGS ack.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
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
  EXPECT_EQ(adapter->sources_size(), GetParam() ? 0 : 1);

  // Client resets the stream before the server can send the response.
  const std::string reset =
      TestFrameSequence().RstStream(1, Http2ErrorCode::CANCEL).Serialize();
  EXPECT_CALL(visitor,
```
Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of the Chromium network stack for testing the nghttp2 adapter. I need to analyze the test cases present in the code to summarize the functionalities being tested.

The code seems to be testing how the `NgHttp2Adapter` handles various HTTP/2 frame sequences, especially around header processing, data handling, flow control, and error conditions.

Here's a breakdown of the test cases and their implied functionalities:

- **`HeaderValuesWithObsTextAllowed`**: Tests if the adapter correctly handles header values containing obsolete text.
- **`ServerHandlesDataWithPadding`**: Checks if the server adapter can process DATA frames with padding.
- **`ServerHandlesHostHeader`**: Verifies how the server adapter deals with the `Host` header (and its interaction with `:authority`).
- **`ServerSubmitsTrailersWhileDataDeferred`**: Tests the scenario where the server sends trailers while the data transmission is ongoing but paused.
- **`ServerSubmitsTrailersWithDataEndStream`**: Checks if the server can correctly send trailers when the data transmission ends with the `END_STREAM` flag.
- **`ServerSubmitsTrailersWithDataEndStreamAndDeferral`**: Tests the scenario where trailers are submitted and the data stream ends, but the actual data sending is deferred.
- **`ClientDisobeysConnectionFlowControl`**: Examines the adapter's behavior when the client sends more data than allowed by the connection flow control window.
- **`ClientDisobeysConnectionFlowControlWithOneDataFrame`**: Similar to the previous one, but with a single DATA frame exceeding the limit.
- **`ClientDisobeysConnectionFlowControlAcrossReads`**: Tests flow control violation when the data is received in multiple chunks.
- **`ClientDisobeysStreamFlowControl`**: Checks how the adapter reacts when the client violates the stream-level flow control.
- **`ServerErrorWhileHandlingHeaders`**:  Likely tests a scenario where an error occurs during header processing.

Regarding the user's requests:

- **Functionality Listing**: I will list the functionalities based on the test cases.
- **Relationship with JavaScript**: HTTP/2 is the underlying protocol for many web interactions, including those initiated by JavaScript. This adapter plays a crucial role in how Chromium handles these interactions. I can provide examples of how JavaScript might trigger these scenarios.
- **Logic Inference (Input/Output)**: For test cases, the "input" is the sequence of HTTP/2 frames, and the "output" is the expected behavior of the `NgHttp2Adapter` and the calls made to the `Http2VisitorInterface`. I will infer these from the `EXPECT_CALL` statements.
- **User/Programming Errors**:  I can identify common errors that might lead to the tested scenarios, such as incorrect flow control management or malformed header construction.
- **User Operation to Reach Here**: I will describe the user actions that would lead to the browser processing these specific frame sequences.
- **Summary of Functionality (Part 6/11)**:  I will summarize the functionality covered in this specific part of the file.
这是Chromium网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc` 文件的第 6 部分，主要功能是 **测试 `NgHttp2Adapter` 类在处理各种客户端发送的 HTTP/2 帧时的行为，特别是涉及到头部处理、数据处理、流量控制以及错误处理的场景**。

以下是根据提供的代码片段列举的功能点：

1. **处理包含 OBS-text 的头部值：** 测试服务器端 `NgHttp2Adapter` 是否允许并正确处理包含过时文本（OBS-text）的头部值。
    - **假设输入：** 客户端发送一个包含包含 OBS-text 的自定义头部（例如 `"name": "val\xa1ue"`）的 HEADERS 帧。
    - **预期输出：** 服务器端的 `Http2VisitorInterface` 接收到该头部，`OnHeaderForStream` 会被调用，且头部值包含 OBS-text。

2. **处理带有填充的数据帧：** 测试服务器端 `NgHttp2Adapter` 是否能正确解析和处理带有填充（padding）的 DATA 帧。
    - **假设输入：** 客户端发送一个带有填充的 DATA 帧。
    - **预期输出：** 服务器端的 `Http2VisitorInterface` 能够正确解析数据内容，并通过 `OnDataPaddingLength` 回调报告填充长度。

3. **处理 `Host` 头部：** 测试服务器端 `NgHttp2Adapter` 如何处理 `Host` 头部，并验证其与 `:authority` 伪头部的交互。
    - **假设输入：** 客户端发送包含 `Host` 头部的请求，可能同时包含或不包含 `:authority` 头部。
    - **预期输出：** 服务器端的 `Http2VisitorInterface` 能够正确接收和处理 `Host` 头部。

4. **在数据传输被延迟时提交尾部（Trailers）：** 测试服务器端 `NgHttp2Adapter` 在响应体数据发送被延迟的情况下，是否可以先提交尾部帧。
    - **假设输入：** 客户端发送请求，服务器开始发送响应头和部分响应体，但数据发送被暂停（例如，由于流量控制窗口限制），此时服务器尝试提交尾部。
    - **预期输出：** 服务器端的 `NgHttp2Adapter` 能够成功提交尾部，并生成 HEADERS 帧（带有 `END_STREAM` 标志）。

5. **在数据流结束时提交尾部：** 测试服务器端 `NgHttp2Adapter` 在响应数据传输以 `END_STREAM` 标志结束时，是否可以提交尾部。
    - **假设输入：** 客户端发送请求，服务器发送响应头，并计划发送带有 `END_STREAM` 标志的响应体，同时提交尾部。
    - **预期输出：** 服务器端的 `NgHttp2Adapter` 会发送响应头，然后发送带有 `END_STREAM` 标志的尾部 HEADERS 帧，而不是响应体。

6. **在数据流结束且被延迟时提交尾部：**  测试服务器端 `NgHttp2Adapter` 在响应数据流即将结束但数据发送被延迟的情况下提交尾部的行为。
    - **假设输入：** 客户端发送请求，服务器发送响应头，并计划发送带有 `END_STREAM` 标志的响应体，但数据发送被延迟。此时服务器尝试提交尾部。
    - **预期输出：** 服务器端的 `NgHttp2Adapter` 会发送响应头和部分数据，然后发送带有 `END_STREAM` 标志的尾部 HEADERS 帧。

7. **客户端违反连接级流量控制：** 测试服务器端 `NgHttp2Adapter` 如何处理客户端发送的数据量超过连接级流量控制窗口的情况。
    - **假设输入：** 客户端发送的数据帧总大小超过了服务器允许的连接级流量控制窗口。
    - **预期输出：** 服务器端的 `NgHttp2Adapter` 会发送一个 GOAWAY 帧，错误码为 `FLOW_CONTROL_ERROR`。

8. **客户端使用单个数据帧违反连接级流量控制：**  与上一点类似，但客户端使用一个单独的 DATA 帧就超过了连接级流量控制窗口。
    - **假设输入：** 客户端发送一个大小超过服务器连接级流量控制窗口的 DATA 帧。
    - **预期输出：** 服务器端的 `NgHttp2Adapter` 会发送一个 GOAWAY 帧，错误码为 `FLOW_CONTROL_ERROR`。

9. **客户端跨多次读取违反连接级流量控制：** 测试当客户端发送的数据跨越多个读取操作，但总量仍然超过连接级流量控制窗口时，服务器端的 `NgHttp2Adapter` 的行为。
    - **假设输入：** 客户端分多次发送数据，累计超过服务器的连接级流量控制窗口。
    - **预期输出：** 服务器端的 `NgHttp2Adapter` 最终会识别出流量控制错误，并可能发送 WINDOW_UPDATE 帧来尝试缓解，或者发送 GOAWAY 帧。 (注意，代码中提到这是一个 nghttp2 的 bug，应该直接发送 GOAWAY)。

10. **客户端违反流级流量控制：** 测试服务器端 `NgHttp2Adapter` 如何处理客户端发送的数据量超过特定流的流量控制窗口的情况。
    - **假设输入：** 客户端在某个流上发送的数据量超过了该流的流量控制窗口。
    - **预期输出：** 服务器端的 `NgHttp2Adapter` 会发送一个 RST_STREAM 帧，错误码为 `FLOW_CONTROL_ERROR`，以终止该流。

11. **处理头部时发生服务器错误：**  测试当处理客户端发送的头部时发生服务器内部错误时，`NgHttp2Adapter` 的行为。
    - **假设输入：** 客户端发送包含特定头部（例如，`header2`）的 HEADERS 帧，服务器端的 `Http2VisitorInterface` 在处理该头部时返回 `HEADER_RST_STREAM`。
    - **预期输出：** 服务器端的 `NgHttp2Adapter` 会发送一个 RST_STREAM 帧，错误码为 `INTERNAL_ERROR`，以终止该流。

**与 JavaScript 的关系举例说明：**

HTTP/2 是现代 Web 的基础协议，JavaScript 发起的网络请求通常会使用 HTTP/2（如果浏览器和服务器都支持）。以下是一些与上述功能相关的 JavaScript 场景：

- **OBS-text in headers:**  虽然不推荐，但服务器可能会返回包含 OBS-text 的自定义头部。JavaScript 的 `fetch` API 或 `XMLHttpRequest` 对象接收到这些头部时，需要能够正确解析。
- **Data with padding:**  在某些优化场景下，服务器可能会发送带有填充的 HTTP/2 数据帧。JavaScript 不直接处理填充，但这会影响底层网络层的处理。
- **`Host` header:**  当 JavaScript 使用 `fetch` 或 `XMLHttpRequest` 向服务器发起请求时，浏览器会自动处理 `:authority` 伪头部。但在某些特殊情况下，可能会设置 `Host` 头部。理解服务器如何处理 `Host` 头部对于调试网络问题至关重要。
- **Trailers:**  JavaScript 的 `fetch` API 提供了访问响应尾部的机制 (`response.trailers`)。上述测试确保了服务器端正确生成和发送尾部，以便 JavaScript 可以正确接收。
- **Flow Control:** 虽然 JavaScript 代码本身不直接控制 HTTP/2 的流量控制，但如果服务器实现或客户端实现（浏览器）的流量控制逻辑有误，会导致请求失败或性能问题，这会直接影响 JavaScript 应用的运行。例如，如果服务器因为客户端违反流量控制而发送 GOAWAY 或 RST_STREAM，JavaScript 的 `fetch` 请求会失败。

**用户或编程常见的使用错误举例说明：**

- **流量控制错误：** 客户端或服务器在发送大量数据时，如果没有正确管理流量控制窗口，可能会导致对方发送 GOAWAY 或 RST_STREAM 帧。例如，一个错误的客户端实现可能会在没有收到足够 WINDOW_UPDATE 帧的情况下发送大量数据。
- **头部格式错误：**  尝试发送包含非法字符或格式错误的头部可能会导致服务器返回错误。例如，尝试发送包含控制字符的头部。
- **尾部使用不当：**  在不应该发送尾部的时候发送尾部，或者尾部的内容格式错误，都可能导致错误。例如，在非分块传输的响应中发送尾部。

**用户操作如何一步步的到达这里 (作为调试线索)：**

1. **用户在浏览器地址栏输入 URL 或点击链接**，浏览器开始与服务器建立连接。
2. **浏览器和服务器进行 HTTP/2 协商**，确定使用 HTTP/2 协议。
3. **用户在网页上执行某些操作（例如，提交表单、上传文件）**，导致浏览器发送包含头部和数据的 HTTP/2 请求帧。
4. **如果服务器在处理请求过程中遇到需要发送尾部的情况（例如，响应体数据生成需要时间，但有一些元数据可以先发送）**，或者如果客户端发送的数据违反了流量控制，就会涉及到这里测试的场景。
5. **开发者可以使用浏览器的开发者工具（Network 标签）** 来查看发送和接收的 HTTP/2 帧，以诊断问题。
6. **如果服务器端使用了 `NgHttp2Adapter` 作为 HTTP/2 的实现**，那么在调试网络问题时，理解 `NgHttp2Adapter` 的行为非常重要。这些测试用例可以帮助开发者理解在各种情况下 `NgHttp2Adapter` 的预期行为。

**归纳功能 (第 6 部分)：**

这部分代码主要测试了 `NgHttp2Adapter` 在处理客户端发送的各种复杂 HTTP/2 帧序列时的鲁棒性和正确性，特别是关注在头部处理（包括特殊头部如 `Host` 和包含 OBS-text 的头部）、数据处理（包括带有填充的数据）以及流量控制方面。此外，还测试了在发生错误情况时，`NgHttp2Adapter` 如何发送适当的错误帧（如 RST_STREAM 和 GOAWAY）。这些测试确保了 Chromium 的 HTTP/2 实现能够正确、安全地处理各种客户端行为和错误情况。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
"},
                    {"header5", "not processed"},
                    {"header6", "not processed"},
                    {"header7", "not processed"},
                    {"header8", "not processed"}},
                   /*fin=*/false, /*add_continuation=*/true)
          .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x0));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(5);
  EXPECT_CALL(visitor, OnHeaderForStream(1, "header2", _))
      .WillOnce(testing::Return(Http2VisitorInterface::HEADER_RST_STREAM));
  // The CONTINUATION frame header and header fields are not processed.

  int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, HeaderValuesWithObsTextAllowed) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"},
                                           {"name", "val\xa1ue"}},
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
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "name", "val\xa1ue"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(NgHttp2AdapterTest, ServerHandlesDataWithPadding) {
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
                                 .Data(1, "This is the request body.",
                                       /*fin=*/true, /*padding_length=*/39)
                                 .Headers(3,
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

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 25 + 39, DATA, 0x9));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 25 + 39));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
  // Note: nghttp2 passes padding information after the actual data.
  EXPECT_CALL(visitor, OnDataPaddingLength(1, 39));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(NgHttp2AdapterTest, ServerHandlesHostHeader) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":path", "/this/is/request/one"},
                                           {"host", "example.com"}},
                                          /*fin=*/true)
                                 .Headers(3,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"host", "example.com"}},
                                          /*fin=*/true)
                                 .Headers(5,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "foo.com"},
                                           {":path", "/this/is/request/one"},
                                           {"host", "bar.com"}},
                                          /*fin=*/true)
                                 .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));

  EXPECT_CALL(visitor, OnFrameHeader(5, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(5));
  EXPECT_CALL(visitor, OnHeaderForStream(5, _, _)).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(5));
  EXPECT_CALL(visitor, OnEndStream(5));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  visitor.Clear();
}

// Tests the case where the response body is in the progress of being sent while
// trailers are queued.
TEST_P(NgHttp2AdapterDataTest, ServerSubmitsTrailersWhileDataDeferred) {
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
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 2000));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  visitor.Clear();

  const absl::string_view kBody = "This is an example response body.";

  // The body source must indicate that the end of the body is not the end of
  // the stream.
  visitor.AppendPayloadForStream(1, kBody);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result = adapter->SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      GetParam() ? nullptr : std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{"final-status", "a-ok"}}));
  ASSERT_EQ(trailer_result, 0);

  // Even though the data source has not finished sending data, nghttp2 will
  // write the trailers anyway.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
  visitor.Clear();

  // Resuming the stream results in the library wanting to write again.
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, true);
  adapter->ResumeStream(1);
  EXPECT_TRUE(adapter->want_write());

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);

  // But no data is written for the stream.
  EXPECT_THAT(visitor.data(), testing::IsEmpty());
  EXPECT_FALSE(adapter->want_write());
}

TEST_P(NgHttp2AdapterDataTest, ServerSubmitsTrailersWithDataEndStream) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1, {{":method", "GET"},
                       {":scheme", "https"},
                       {":authority", "example.com"},
                       {":path", "/this/is/request/one"}})
          .Data(1, "Example data, woohoo.")
          .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, _));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  // Send a body that will end with the END_STREAM flag.
  const absl::string_view kBody = "This is an example response body.";
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, true);
  auto body = std::make_unique<VisitorDataSource>(visitor, 1);

  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}),
                              GetParam() ? nullptr : std::move(body), false);
  ASSERT_EQ(submit_result, 0);

  const std::vector<Header> trailers =
      ToHeaders({{"extra-info", "Trailers are weird but good?"}});
  submit_result = adapter->SubmitTrailer(1, trailers);
  ASSERT_EQ(submit_result, 0);

  // It looks like nghttp2 drops the response body altogether and goes straight
  // to writing the trailers.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                         END_HEADERS_FLAG | END_STREAM_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                   END_HEADERS_FLAG | END_STREAM_FLAG, 0));

  const int send_result = adapter->Send();
  EXPECT_EQ(send_result, 0);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS,
                            SpdyFrameType::HEADERS}));
}

TEST_P(NgHttp2AdapterDataTest,
       ServerSubmitsTrailersWithDataEndStreamAndDeferral) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1, {{":method", "GET"},
                       {":scheme", "https"},
                       {":authority", "example.com"},
                       {":path", "/this/is/request/one"}})
          .Data(1, "Example data, woohoo.")
          .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, _));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(result), frames.size());

  // Send a body that will end with the END_STREAM flag. Don't end the body here
  // so that more body can be added later.
  const absl::string_view kBody = "This is an example response body.";
  visitor.AppendPayloadForStream(1, kBody);
  auto body = std::make_unique<VisitorDataSource>(visitor, 1);

  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}),
                              GetParam() ? nullptr : std::move(body), false);
  ASSERT_EQ(submit_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS,
                            SpdyFrameType::DATA}));
  visitor.Clear();

  const std::vector<Header> trailers =
      ToHeaders({{"extra-info", "Trailers are weird but good?"}});
  submit_result = adapter->SubmitTrailer(1, trailers);
  ASSERT_EQ(submit_result, 0);

  // Add more body and signal the end of data. Resuming the stream should allow
  // the new body to be sent, though nghttp2 does not send the body.
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, false);
  adapter->ResumeStream(1);

  // For some reason, nghttp2 drops the new body and goes straight to writing
  // the trailers.
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                         END_HEADERS_FLAG | END_STREAM_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                   END_HEADERS_FLAG | END_STREAM_FLAG, 0));

  send_result = adapter->Send();
  EXPECT_EQ(send_result, 0);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
}

TEST(NgHttp2AdapterTest, ClientDisobeysConnectionFlowControl) {
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
                                 // 70000 bytes of data
                                 .Data(1, std::string(16384, 'a'))
                                 .Data(1, std::string(16384, 'a'))
                                 .Data(1, std::string(16384, 'a'))
                                 .Data(1, std::string(16384, 'a'))
                                 .Data(1, std::string(4464, 'a'))
                                 .Serialize();

  testing::InSequence s;
  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 16384, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 16384));
  EXPECT_CALL(visitor, OnDataForStream(1, _));
  EXPECT_CALL(visitor, OnFrameHeader(1, 16384, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 16384));
  EXPECT_CALL(visitor, OnDataForStream(1, _));
  EXPECT_CALL(visitor, OnFrameHeader(1, 16384, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 16384));
  EXPECT_CALL(visitor, OnDataForStream(1, _));
  EXPECT_CALL(visitor, OnFrameHeader(1, 16384, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 16384));
  // No further frame data or headers are delivered.

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  // No SETTINGS ack is written.
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(GOAWAY, 0, _, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(NgHttp2AdapterTest, ClientDisobeysConnectionFlowControlWithOneDataFrame) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  // Allow the client to send a DATA frame that exceeds the connection flow
  // control window.
  const uint32_t window_overflow_bytes = kInitialFlowControlWindowSize + 1;
  adapter->SubmitSettings({{MAX_FRAME_SIZE, window_overflow_bytes}});

  const std::string initial_frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "POST"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
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
  EXPECT_CALL(visitor, OnHeaderForStream).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  int64_t process_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(process_result));

  EXPECT_TRUE(adapter->want_write());

  // Outbound SETTINGS containing MAX_FRAME_SIZE.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  // Ack of client's initial settings.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // Now let the client ack the MAX_FRAME_SIZE SETTINGS and send a DATA frame to
  // overflow the connection-level window. The result should be a GOAWAY.
  const std::string overflow_frames =
      TestFrameSequence()
          .SettingsAck()
          .Data(1, std::string(window_overflow_bytes, 'a'))
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor, OnFrameHeader(1, window_overflow_bytes, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, window_overflow_bytes));
  // No further frame data is delivered.

  process_result = adapter->ProcessBytes(overflow_frames);
  EXPECT_EQ(overflow_frames.size(), static_cast<size_t>(process_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(GOAWAY, 0, _, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(NgHttp2AdapterTest, ClientDisobeysConnectionFlowControlAcrossReads) {
  TestVisitor visitor;
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  // Allow the client to send a DATA frame that exceeds the connection flow
  // control window.
  const uint32_t window_overflow_bytes = kInitialFlowControlWindowSize + 1;
  adapter->SubmitSettings({{MAX_FRAME_SIZE, window_overflow_bytes}});

  const std::string initial_frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "POST"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
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
  EXPECT_CALL(visitor, OnHeaderForStream).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  int64_t process_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(process_result));

  EXPECT_TRUE(adapter->want_write());

  // Outbound SETTINGS containing MAX_FRAME_SIZE.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  // Ack of client's initial settings.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // Now let the client ack the MAX_FRAME_SIZE SETTINGS and send a DATA frame to
  // overflow the connection-level window. The result should be a GOAWAY, but
  // because the processing is split across several calls, nghttp2 instead
  // delivers the data payloads (which the visitor then consumes). This is a bug
  // in nghttp2, which should recognize the flow control error.
  const std::string overflow_frames =
      TestFrameSequence()
          .SettingsAck()
          .Data(1, std::string(window_overflow_bytes, 'a'))
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor, OnFrameHeader(1, window_overflow_bytes, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, window_overflow_bytes));
  // BUG: The visitor should not have received the data.
  EXPECT_CALL(visitor, OnDataForStream(1, _))
      .WillRepeatedly(
          [&adapter](Http2StreamId stream_id, absl::string_view data) {
            adapter->MarkDataConsumedForStream(stream_id, data.size());
            return true;
          });

  const size_t chunk_length = 16384;
  ASSERT_GE(overflow_frames.size(), chunk_length);
  absl::string_view remaining = overflow_frames;
  while (!remaining.empty()) {
    absl::string_view chunk = remaining.substr(0, chunk_length);
    process_result = adapter->ProcessBytes(chunk);
    EXPECT_EQ(chunk.length(), static_cast<size_t>(process_result));

    remaining.remove_prefix(chunk.length());
  }

  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 0, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 0, 4, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 1, 4, 0x0, 0));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::WINDOW_UPDATE,
                                            SpdyFrameType::WINDOW_UPDATE}));
}

TEST(NgHttp2AdapterTest, ClientDisobeysStreamFlowControl) {
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
                                 .Serialize();
  const std::string more_frames = TestFrameSequence()
                                      // 70000 bytes of data
                                      .Data(1, std::string(16384, 'a'))
                                      .Data(1, std::string(16384, 'a'))
                                      .Data(1, std::string(16384, 'a'))
                                      .Data(1, std::string(16384, 'a'))
                                      .Data(1, std::string(4464, 'a'))
                                      .Serialize();

  testing::InSequence s;
  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream).Times(5);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  adapter->SubmitWindowUpdate(0, 20000);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 0, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 0, 4, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS,
                                            SpdyFrameType::WINDOW_UPDATE}));
  visitor.Clear();

  EXPECT_CALL(visitor, OnFrameHeader(1, 16384, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 16384));
  EXPECT_CALL(visitor, OnDataForStream(1, _));
  EXPECT_CALL(visitor, OnFrameHeader(1, 16384, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 16384));
  EXPECT_CALL(visitor, OnDataForStream(1, _));
  EXPECT_CALL(visitor, OnFrameHeader(1, 16384, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 16384));
  EXPECT_CALL(visitor, OnDataForStream(1, _));
  EXPECT_CALL(visitor, OnFrameHeader(1, 16384, DATA, 0x0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 16384));
  EXPECT_CALL(visitor, OnDataForStream(1, _));
  // No further frame data or headers for stream 1 are delivered.

  result = adapter->ProcessBytes(more_frames);
  EXPECT_EQ(more_frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(RST_STREAM, 1, 4, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::FLOW_CONTROL_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::RST_STREAM}));
}

TEST(NgHttp2AdapterTest, ServerErrorWhileHandlingHeaders) {
  TestVisitor visitor;
  auto adapter
```
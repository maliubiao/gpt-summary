Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive explanation.

**1. Initial Understanding of the Task:**

The core task is to analyze a C++ test file (`oghttp2_adapter_test.cc`) within Chromium's network stack (specifically the QUICHE/HTTP2 adapter). The analysis needs to cover functionality, potential JavaScript relevance, logical inference (input/output), common usage errors, debugging steps, and a summary of the current part.

**2. Examining the Code Structure and Content:**

* **Headers:** The presence of `#include` directives points to the dependencies of the test file (gtest, memory management, etc.). These aren't directly functional to *this* file's purpose, but they are essential for its compilation and execution.
* **Test Fixtures:**  The use of `TEST` and `TEST_P` macros immediately signals that this file contains unit tests using Google Test. The names of the test cases (`OgHttp2AdapterTest`, `OgHttp2AdapterDataTest`) give a high-level idea of what's being tested.
* **`TestVisitor` Class:** This is a mock object. Its purpose is to verify the interactions between the `OgHttp2Adapter` and its client. The `EXPECT_CALL` macros within the tests define the expected sequence of calls to the `TestVisitor` methods with specific arguments. This is the *key* to understanding what the adapter *does*.
* **`OgHttp2Adapter` Class:** This is the class being tested. The tests create instances of this class and drive its behavior.
* **Frame Types (HEADERS, DATA, SETTINGS, etc.):**  The tests manipulate and verify the sending and receiving of HTTP/2 frames. This indicates the adapter's role in handling the low-level details of the HTTP/2 protocol.
* **`Perspective` Enum:** The tests differentiate between client and server perspectives, highlighting that the adapter handles both sides of an HTTP/2 connection.
* **`Serialize()` Method of `TestFrameSequence`:** This suggests a utility for constructing sequences of HTTP/2 frames for testing purposes.
* **`Submit...` Methods of `OgHttp2Adapter`:** Methods like `SubmitRequest`, `SubmitResponse`, `SubmitSettings`, etc., reveal the adapter's API for initiating actions (sending requests, responses, settings).
* **Error Handling (e.g., `Http2ErrorCode`):** The tests check how the adapter handles various HTTP/2 error conditions.
* **Flow Control (Window Updates):** Several tests focus on flow control mechanisms, indicating this is a critical aspect of the adapter's functionality.

**3. Deduction of Functionality:**

By analyzing the test names and the `EXPECT_CALL` sequences, the core functionalities of `OgHttp2Adapter` become apparent:

* **HTTP/2 Frame Handling:** Sending and receiving various frame types (HEADERS, DATA, SETTINGS, PING, GOAWAY, RST_STREAM, WINDOW_UPDATE, PRIORITY, CONTINUATION).
* **Client and Server Roles:**  Supporting both client-side (request submission) and server-side (response handling) behavior.
* **Header Processing:** Handling header encoding and decoding, including handling repeated headers and large header lists.
* **Data Handling:** Sending and receiving data payloads, including handling trailers.
* **Flow Control:** Implementing HTTP/2 flow control mechanisms using window updates.
* **Error Handling:** Managing various HTTP/2 error conditions.
* **Settings Management:**  Handling HTTP/2 settings.
* **Stream Management:** Creating and managing HTTP/2 streams.

**4. JavaScript Relevance (and Lack Thereof):**

Given the low-level nature of the HTTP/2 protocol and the C++ implementation, direct interaction with JavaScript is unlikely. JavaScript in a browser would interact with a higher-level API that *uses* something like this adapter internally. The connection is indirect.

**5. Logical Inference (Input/Output):**

For the input/output examples, focus on concrete test cases:

* **`ClientAcceptsHeadResponseWithContentLength`:** Input: Client sends a HEAD request. Server sends a HEAD response with `content-length`. Output:  The adapter correctly processes this and doesn't expect a body.
* **`WindowUpdateZeroDelta`:** Input: Client sends a WINDOW_UPDATE with a zero delta. Output: Server detects this as an error and sends a RST_STREAM.

**6. Common Usage Errors:**

Think about how a programmer might misuse the adapter based on the tests:

* **Incorrect Frame Sequences:** Sending frames in the wrong order.
* **Ignoring Flow Control:** Sending more data than the peer's window allows.
* **Submitting Invalid Headers:**  Violating HTTP/2 header rules.
* **Mismanaging Stream States:**  Trying to send data on a closed stream.

**7. Debugging Steps:**

Trace the flow of a typical test case:

1. Set breakpoints in the `OgHttp2Adapter` code.
2. Examine the state of the adapter's internal data structures (e.g., stream states, flow control windows).
3. Observe the frames being sent and received.
4. Use logging or debugging tools to inspect the header lists.

**8. Summarizing Functionality (Part 6):**

Focus on the tests present in this specific snippet:

* Tests for client-side behavior (handling HEAD responses).
* Tests for flow control mechanisms (window updates, handling overflow).
* Tests for how the adapter serializes outgoing frames (SETTINGS, PRIORITY, RST_STREAM, PING, GOAWAY, WINDOW_UPDATE).
* Tests for handling partial serialization when write limits are imposed.
* Tests related to dynamic initial window size updates via SETTINGS frames.
* Tests for error handling during frame sending.
* Tests for handling CONTINUATION frames.
* Tests for handling repeated header names.
* Tests for handling server responses with trailers.
* A test for handling cases where the received header list exceeds the configured maximum size.

**9. Refinement and Organization:**

Structure the explanation logically using headings and bullet points. Provide clear and concise explanations for each aspect of the request. Use examples where appropriate.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus on *all* the functionalities hinted at by the directory structure.
* **Correction:** The prompt specifically asks about *this* file. Focus on the tests *within this snippet*.
* **Initial thought:** Try to find direct JavaScript equivalents for everything.
* **Correction:** Recognize that the connection is often indirect. Focus on how the *concepts* relate, even if the implementation is different.
* **Initial thought:**  List every single `EXPECT_CALL`.
* **Correction:**  Summarize the *purpose* of the test cases rather than just transcribing the mock expectations.

By following this structured approach, analyzing the code, and refining the understanding, a comprehensive and accurate explanation can be generated.
这是第6部分，继续分析 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc` 文件。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能延续：HTTP/2 适配器单元测试**

这个代码片段仍然是 `OgHttp2Adapter` 类的单元测试，专注于测试其在各种HTTP/2场景下的行为。它使用 Google Test 框架来定义和执行测试用例，并使用模拟对象 `TestVisitor` 来验证 `OgHttp2Adapter` 的行为是否符合预期。

**具体测试的功能点：**

1. **客户端接收带 Content-Length 的 HEAD 响应:**
   - 测试客户端在发送 HEAD 请求后，能否正确处理服务端返回的带有 `content-length` 头的响应。这验证了适配器对于 HEAD 请求的特殊处理，即不需要接收响应体。

2. **获取发送窗口大小:**
   - 测试 `GetSendWindowSize()` 方法，验证它返回的初始发送窗口大小是否正确 (通常是 `kInitialFlowControlWindowSize`)。

3. **窗口更新（零增量）：**
   - 测试接收到窗口更新帧，但增量为零的情况。HTTP/2 协议规定这种情况下是协议错误。测试验证适配器是否会正确处理并关闭连接。

4. **窗口更新导致窗口溢出:**
   - 测试接收到窗口更新帧，导致接收窗口大小溢出的情况。HTTP/2 协议规定这种情况下是流控制错误。测试验证适配器是否会正确处理并关闭连接。

5. **窗口更新提升流控制窗口限制:**
   - 测试通过 `SubmitWindowUpdate()` 方法主动提交窗口更新，并验证本地和对端的窗口大小是否得到正确更新。也测试了在窗口更新后，接收大量数据是否正常工作，以及 `MarkDataConsumedForStream` 是否能正确增加窗口大小。

6. **标记已消耗数据（针对不存在的流）：**
   - 测试调用 `MarkDataConsumedForStream()` 方法，但传入一个不存在的流 ID，验证适配器是否能够安全地处理这种情况，避免崩溃或其他异常。

7. **完整序列化:**
   - 测试 `Send()` 方法在多种控制帧等待发送时，能否将它们完整地序列化并发送出去。测试验证了 `want_write()` 的状态以及发送帧的顺序。

8. **部分序列化:**
   - 测试在设置了发送限制的情况下，`Send()` 方法能否正确地进行部分序列化，并在后续调用中继续发送剩余的帧。这涉及到 `want_write()` 的状态管理。

9. **流初始窗口大小更新:**
   - 测试通过发送 SETTINGS 帧来更新对端流的初始窗口大小。验证窗口大小更新的时机，即在接收到 SETTINGS ACK 之后生效。

10. **发送控制帧时发生连接错误:**
    - 模拟在发送控制帧（如 SETTINGS）时发生错误的情况，验证适配器是否会正确处理并触发 `OnConnectionError` 回调。

11. **发送数据帧时发生连接错误 (Parameterized Test):**
    - 使用参数化测试 `OgHttp2AdapterDataTest` 模拟在发送数据帧时发生错误的情况，验证适配器是否会正确处理并触发 `OnConnectionError` 回调。

12. **客户端发送 CONTINUATION 帧:**
    - 测试客户端发送头部帧时，如果头部太大，会使用 CONTINUATION 帧进行分片发送。验证服务端适配器能否正确处理 HEADERS 帧和后续的 CONTINUATION 帧。

13. **重复的头部名称 (Parameterized Test):**
    - 使用参数化测试 `OgHttp2AdapterDataTest` 测试适配器如何处理带有重复头部名称的请求和响应。验证适配器是否能正确解析和传递这些头部。

14. **服务端响应请求带 Trailers (Parameterized Test):**
    - 使用参数化测试 `OgHttp2AdapterDataTest` 测试服务端发送带有 Trailers (尾部) 的响应。验证适配器能否正确处理 DATA 帧和后续的 HEADERS 帧 (作为 Trailers)。

15. **服务端接收的头部字节数超过配置:**
    - 测试服务端接收的头部字节数超过配置的 `max_header_list_bytes` 限制时，适配器是否会正确处理并发送错误。

**与 JavaScript 功能的关系：**

这个 C++ 代码是 Chromium 网络栈的底层实现，直接与 JavaScript 没有交互。然而，它所实现的功能是支撑浏览器中 JavaScript 发起 HTTP/2 请求的基础。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` API 发起一个 HTTP/2 请求，并且服务端返回了一个带有 Trailers 的响应：

```javascript
fetch('https://example.com/data', {
  // ... 其他选项
})
.then(response => {
  console.log(response.headers.get('content-type')); // 获取响应头
  const reader = response.body.getReader();
  return new ReadableStream({
    start(controller) {
      function push() {
        reader.read().then(({ done, value }) => {
          if (done) {
            // 当响应体读取完毕后，可以尝试获取 Trailers
            response.trailer.then(trailers => {
              console.log("Trailers:", trailers.get('extra-info'));
            });
            controller.close();
            return;
          }
          controller.enqueue(value);
          push();
        });
      }
      push();
    }
  });
})
.then(stream => new Response(stream))
.then(response => response.text())
.then(result => console.log(result));
```

在这个例子中：

- 当 JavaScript 发起请求时，Chromium 的网络栈会使用 `OgHttp2Adapter` (或类似的组件) 来将请求转换为 HTTP/2 帧并通过网络发送。
- 当服务端发送响应头和数据时，`OgHttp2Adapter` 会解析这些帧，并将头部信息传递给上层 JavaScript 代码，例如通过 `response.headers` 访问。
- 当服务端发送 Trailers 时，`OgHttp2Adapter` 会解析包含 Trailers 的 HEADERS 帧，并将其存储起来，以便 JavaScript 可以通过 `response.trailer` Promise 来访问。

**逻辑推理与假设输入输出：**

**示例：窗口更新（零增量）测试**

**假设输入 (服务端接收到的帧序列):**

```
[SETTINGS frame ...]  // 客户端 preface
[HEADERS frame stream_id=1 ...] // 客户端请求头
[WINDOW_UPDATE frame stream_id=1 increment=0]
```

**预期输出 (TestVisitor 的回调):**

```
OnFrameHeader(0, _, SETTINGS, 0)
OnSettingsStart()
OnSettingsEnd()
OnFrameHeader(1, _, HEADERS, 4)
OnBeginHeadersForStream(1)
OnHeaderForStream(1, ...)
OnHeaderForStream(1, ...)
OnHeaderForStream(1, ...)
OnHeaderForStream(1, ...)
OnEndHeadersForStream(1)
OnFrameHeader(1, 4, WINDOW_UPDATE, 0)
OnBeforeFrameSent(SETTINGS, 0, 6, 0x0)
OnFrameSent(SETTINGS, 0, 6, 0x0, 0)
OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG)
OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0)
OnBeforeFrameSent(RST_STREAM, 1, _, 0x0)
OnFrameSent(RST_STREAM, 1, _, 0x0, static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR))
OnCloseStream(1, _)
OnBeforeFrameSent(GOAWAY, 0, _, 0x0)
OnFrameSent(GOAWAY, 0, _, 0x0, static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR))
```

**用户或编程常见的使用错误：**

1. **错误地处理窗口更新:** 开发者可能会忘记在接收到 DATA 帧后调用 `MarkDataConsumedForStream` 来告知适配器已经处理了数据，导致发送窗口无法增加，最终阻塞数据发送。

   ```c++
   // 错误示例：忘记标记数据已消耗
   void MyVisitor::OnDataForStream(Http2StreamId stream_id, absl::string_view data) {
     // 处理数据...
     // 忘记调用 adapter_->MarkDataConsumedForStream(stream_id, data.size());
   }
   ```

2. **在流关闭后尝试发送数据:** 开发者可能会在调用 `OnEndStream` 或 `OnCloseStream` 表明流已结束之后，仍然尝试调用 `SubmitResponse` 或 `SendData`，导致未定义的行为或错误。

3. **不正确地处理 Trailers:**  开发者可能在接收到 `OnEndStream` 回调后，没有正确地处理可能存在的 Trailers，导致信息丢失。

**用户操作如何一步步到达这里（调试线索）：**

假设用户在使用 Chrome 浏览器访问一个支持 HTTP/2 的网站，并且服务端发送了带有 Trailers 的响应。

1. **用户在地址栏输入 URL 并回车，或者点击一个链接。**
2. **Chrome 浏览器开始建立与服务器的连接，并进行 HTTP/2 协商。**
3. **浏览器发送 HTTP/2 HEADERS 帧请求资源。**
4. **服务器开始发送响应头 (HEADERS 帧)。** `OgHttp2Adapter` 的 `ProcessBytes` 方法会处理这些帧，并调用 `TestVisitor` 的相应回调。
5. **服务器发送响应体 (DATA 帧)。** `OgHttp2Adapter` 继续处理，调用 `OnBeginDataForStream` 和 `OnDataForStream`。
6. **服务器发送包含 Trailers 的 HEADERS 帧，并设置 END_STREAM 标志。**  这是本测试用例关注的关键点。 `OgHttp2Adapter` 的 `ProcessBytes` 方法会接收到这个帧，并调用 `OnFrameHeader`，`OnBeginHeadersForStream`，`OnHeaderForStream` (针对每个 Trailer 头)，和 `OnEndHeadersForStream`，最后调用 `OnEndStream`。
7. **如果开发者在 `TestVisitor` 中设置了断点，或者在 `OgHttp2Adapter` 的 `ProcessBytes` 方法中设置了断点，那么当执行到处理 Trailers 的逻辑时，调试器就会停在这里。**  开发者可以通过查看调用栈、局部变量等信息，来理解 HTTP/2 帧的处理流程。

**第 6 部分功能归纳：**

第 6 部分的测试用例主要关注 `OgHttp2Adapter` 在以下方面的功能：

- **更细致的 HTTP/2 功能处理:** 包括对 HEAD 请求、Trailers、CONTINUATION 帧的处理。
- **流控制的边界情况和错误处理:**  测试了窗口更新的各种异常情况 (零增量、溢出) 以及相应的错误处理机制。
- **数据发送和接收的错误处理:** 模拟了发送数据帧和控制帧时发生错误的情况。
- **连接建立和设置的更新:**  测试了初始窗口大小更新的流程。
- **序列化和部分序列化:**  验证了在不同限制下，适配器发送 HTTP/2 帧的能力。
- **对非法或不符合协议行为的健壮性:**  测试了处理重复头部、超大头部列表以及针对不存在的流的操作。

总的来说，这部分测试更加深入地验证了 `OgHttp2Adapter` 对 HTTP/2 协议细节的处理能力以及其在各种异常情况下的健壮性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
G | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[3], _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[3], _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_ids[4], _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_ids[4], _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  // Header frames should all have been sent in order, regardless of any
  // queuing.

  adapter->Send();
}

TEST(OgHttp2AdapterTest, ClientAcceptsHeadResponseWithContentLength) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::vector<Header> headers = ToHeaders({{":method", "HEAD"},
                                                 {":scheme", "http"},
                                                 {":authority", "example.com"},
                                                 {":path", "/"}});
  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  adapter->Send();

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface()
          .SettingsAck()
          .Headers(stream_id, {{":status", "200"}, {"content-length", "101"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, _, SETTINGS, 0x0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnHeaderForStream).Times(2);
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnEndStream(stream_id));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR));

  adapter->ProcessBytes(initial_frames);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  adapter->Send();
}

TEST(OgHttp2AdapterTest, GetSendWindowSize) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const int peer_window = adapter->GetSendWindowSize();
  EXPECT_EQ(peer_window, kInitialFlowControlWindowSize);
}

TEST(OgHttp2AdapterTest, WindowUpdateZeroDelta) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string data_chunk(kDefaultFramePayloadSizeLimit, 'a');
  const std::string request =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/"}},
                   /*fin=*/false)
          .WindowUpdate(1, 0)
          .Data(1, "Subsequent frames on stream 1 are not delivered.")
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

  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));

  adapter->ProcessBytes(request);

  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, _));

  adapter->Send();

  const std::string window_update =
      TestFrameSequence().WindowUpdate(0, 0).Serialize();
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kFlowControlError));
  adapter->ProcessBytes(window_update);

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));
  adapter->Send();
}

TEST(OgHttp2AdapterTest, WindowUpdateCausesWindowOverflow) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string data_chunk(kDefaultFramePayloadSizeLimit, 'a');
  const std::string request =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/"}},
                   /*fin=*/false)
          .WindowUpdate(1, std::numeric_limits<int>::max())
          .Data(1, "Subsequent frames on stream 1 are not delivered.")
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

  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));

  adapter->ProcessBytes(request);

  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(RST_STREAM, 1, _, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, _));

  adapter->Send();

  const std::string window_update =
      TestFrameSequence()
          .WindowUpdate(0, std::numeric_limits<int>::max())
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kFlowControlError));
  adapter->ProcessBytes(window_update);

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(GOAWAY, 0, _, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));
  adapter->Send();
}

TEST(OgHttp2AdapterTest, WindowUpdateRaisesFlowControlWindowLimit) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
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

TEST(OgHttp2AdapterTest, MarkDataConsumedForNonexistentStream) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  // Send some data on stream 1 so the connection window manager doesn't
  // underflow later.
  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Data(1, "Some data on stream 1")
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
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, _));

  adapter->ProcessBytes(frames);

  // This should not cause a crash or QUICHE_BUG.
  adapter->MarkDataConsumedForStream(3, 11);
}

TEST(OgHttp2AdapterTest, TestSerialize) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_TRUE(adapter->want_read());
  EXPECT_FALSE(adapter->want_write());

  adapter->SubmitSettings(
      {{HEADER_TABLE_SIZE, 128}, {MAX_FRAME_SIZE, 128 << 10}});
  EXPECT_TRUE(adapter->want_write());

  const Http2StreamId accepted_stream = 3;
  const Http2StreamId rejected_stream = 7;
  adapter->SubmitPriorityForStream(accepted_stream, 1, 255, true);
  adapter->SubmitRst(rejected_stream, Http2ErrorCode::CANCEL);
  adapter->SubmitPing(42);
  adapter->SubmitGoAway(13, Http2ErrorCode::HTTP2_NO_ERROR, "");
  adapter->SubmitWindowUpdate(accepted_stream, 127);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PRIORITY, accepted_stream, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(PRIORITY, accepted_stream, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, rejected_stream, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, rejected_stream, _, 0x0, 0x8));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(GOAWAY, 0, _, 0x0, 0));
  EXPECT_CALL(visitor,
              OnBeforeFrameSent(WINDOW_UPDATE, accepted_stream, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, accepted_stream, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(
      visitor.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PRIORITY,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::PING,
                    SpdyFrameType::GOAWAY, SpdyFrameType::WINDOW_UPDATE}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterTest, TestPartialSerialize) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_FALSE(adapter->want_write());

  adapter->SubmitSettings(
      {{HEADER_TABLE_SIZE, 128}, {MAX_FRAME_SIZE, 128 << 10}});
  adapter->SubmitGoAway(13, Http2ErrorCode::HTTP2_NO_ERROR,
                        "And don't come back!");
  adapter->SubmitPing(42);
  EXPECT_TRUE(adapter->want_write());

  visitor.set_send_limit(20);
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(GOAWAY, 0, _, 0x0, 0));
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x0, 0));
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_FALSE(adapter->want_write());
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY,
                            SpdyFrameType::PING}));
}

TEST(OgHttp2AdapterTest, TestStreamInitialWindowSizeUpdates) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  adapter->SubmitSettings({{INITIAL_WINDOW_SIZE, 80000}});
  EXPECT_TRUE(adapter->want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
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
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  // New stream window size has not yet been applied.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(1), 65535);

  // Server initial SETTINGS
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  int result = adapter->Send();
  EXPECT_EQ(0, result);

  // New stream window size has still not been applied.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(1), 65535);

  const std::string ack = TestFrameSequence().SettingsAck().Serialize();
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck());
  adapter->ProcessBytes(ack);

  // New stream window size has finally been applied upon SETTINGS ack.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(1), 80000);

  // Update the stream window size again.
  adapter->SubmitSettings({{INITIAL_WINDOW_SIZE, 90000}});
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  result = adapter->Send();
  EXPECT_EQ(0, result);

  // New stream window size has not yet been applied.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(1), 80000);

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck());
  adapter->ProcessBytes(ack);

  // New stream window size is applied after the ack.
  EXPECT_EQ(adapter->GetStreamReceiveWindowSize(1), 90000);
}

TEST(OgHttp2AdapterTest, ConnectionErrorOnControlFrameSent) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0))
      .WillOnce(testing::Return(-902));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kSendError));

  int send_result = adapter->Send();
  EXPECT_LT(send_result, 0);

  EXPECT_FALSE(adapter->want_write());

  send_result = adapter->Send();
  EXPECT_LT(send_result, 0);
}

TEST_P(OgHttp2AdapterDataTest, ConnectionErrorOnDataFrameSent) {
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

  visitor.AppendPayloadForStream(
      1, "Here is some data, which will lead to a fatal error");
  auto body = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}),
                              GetParam() ? nullptr : std::move(body), false);
  ASSERT_EQ(0, submit_result);

  EXPECT_TRUE(adapter->want_write());

  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  // Stream 1, with doomed DATA
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0))
      .WillOnce(testing::Return(-902));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kSendError));

  int send_result = adapter->Send();
  EXPECT_LT(send_result, 0);

  visitor.AppendPayloadForStream(
      1, "After the fatal error, data will be sent no more");

  EXPECT_FALSE(adapter->want_write());

  send_result = adapter->Send();
  EXPECT_LT(send_result, 0);
}

TEST(OgHttp2AdapterTest, ClientSendsContinuation) {
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
                                          /*fin=*/true,
                                          /*add_continuation=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 1));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, CONTINUATION, 4));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST_P(OgHttp2AdapterDataTest, RepeatedHeaderNames) {
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
                                           {":path", "/this/is/request/one"},
                                           {"accept", "text/plain"},
                                           {"accept", "text/html"}},
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
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "accept", "text/plain"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "accept", "text/html"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  const std::vector<Header> headers1 = ToHeaders(
      {{":status", "200"}, {"content-length", "10"}, {"content-length", "10"}});
  visitor.AppendPayloadForStream(1, "perfection");
  visitor.SetEndData(1, true);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);

  int submit_result = adapter->SubmitResponse(
      1, headers1, GetParam() ? nullptr : std::move(body1), false);
  ASSERT_EQ(0, submit_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, 10, END_STREAM, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
}

TEST_P(OgHttp2AdapterDataTest, ServerRespondsToRequestWithTrailers) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

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
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, _));

  int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  const std::vector<Header> headers1 = ToHeaders({{":status", "200"}});
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);

  int submit_result = adapter->SubmitResponse(
      1, headers1, GetParam() ? nullptr : std::move(body1), false);
  ASSERT_EQ(0, submit_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string more_frames =
      TestFrameSequence()
          .Headers(1, {{"extra-info", "Trailers are weird but good?"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "extra-info",
                                         "Trailers are weird but good?"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  result = adapter->ProcessBytes(more_frames);
  EXPECT_EQ(more_frames.size(), static_cast<size_t>(result));

  visitor.SetEndData(1, true);
  EXPECT_EQ(true, adapter->ResumeStream(1));

  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, 0, END_STREAM, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
}

TEST(OgHttp2AdapterTest, ServerReceivesMoreHeaderBytesThanConfigured) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.max_header_list_bytes = 42;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"},
                    {"from-douglas-de-fermat",
                     "I have discovered a truly marvelous answer to the life, "
                     "the universe, and everything that the header setting is "
                     "too narrow to contain."}},
                   /*fin=*/true)
```
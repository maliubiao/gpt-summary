Response:
My thinking process to analyze the provided C++ code snippet and generate the detailed response involved several steps:

1. **Understanding the Goal:** The primary goal is to analyze a specific C++ test file (`oghttp2_adapter_test.cc`) within the Chromium network stack, focusing on its functionality, relationships with JavaScript, logic inference, potential errors, debugging context, and summarizing its overall purpose within a larger series of files.

2. **Initial Code Scan and Keyword Identification:** I started by quickly scanning the code, looking for key HTTP/2 concepts and keywords. Terms like `HEADERS`, `DATA`, `SETTINGS`, `WINDOW_UPDATE`, `GOAWAY`, `RST_STREAM`, `trailer`, `flow control`, `SubmitResponse`, `SubmitTrailer`, `ProcessBytes`, `Send`, `visitor`, `adapter`, and `Perspective::kServer` jumped out. These keywords provided initial clues about the code's purpose.

3. **Identifying the Core Class Under Test:** The filename `oghttp2_adapter_test.cc` and the repeated use of `OgHttp2Adapter` and `TestVisitor` clearly indicated that the code is testing the `OgHttp2Adapter` class, likely a component responsible for handling HTTP/2 communication. The `TestVisitor` class serves as a mock or stub to observe the actions of the `OgHttp2Adapter`.

4. **Analyzing Individual Test Cases:** I examined each `TEST_P` and `TEST` function individually. The names of these tests were highly informative:
    * `ServerSubmitsTrailers...`:  Indicates testing of server-side trailer submission.
    * `...WithFlowControlBlockage`: Highlights tests dealing with flow control scenarios.
    * `...WithDataEndStream`: Focuses on cases where the DATA frame signals the end of the stream.
    * `ClientDisobeys...`:  Points to tests where the client violates HTTP/2 protocol rules.
    * `ServerErrorWhileHandlingHeaders`: Examines error scenarios during header processing.

5. **Mapping Test Cases to Functionality:** Based on the test names and the sequence of calls to `adapter` and `visitor`, I started mapping the test cases to specific functionalities of the `OgHttp2Adapter`. For example, tests involving `SubmitResponse` and `SubmitTrailer` demonstrate the adapter's ability to send responses with headers, body, and trailers. Tests using `ProcessBytes` simulate receiving data from the client. Tests using `Send` trigger the adapter to send frames.

6. **Focusing on Interactions and Expectations:**  The `EXPECT_CALL` statements with the `visitor` were crucial. They revealed the expected sequence of frame generation and visitor method calls for different scenarios. This allowed me to understand *what* the adapter was doing internally and *how* it interacted with its visitor.

7. **Identifying Flow Control and Error Handling:** The tests with "flow control" in their names clearly targeted the adapter's behavior when either the client or server violates flow control rules. The tests with "ServerError" focused on how the adapter handles errors during header processing.

8. **Considering the Server Perspective:** The `options.perspective = Perspective::kServer;` line in many tests indicated that the tests primarily focused on the server-side behavior of the adapter.

9. **Addressing the JavaScript Relationship:** I considered the role of HTTP/2 in web browsers and how JavaScript interacts with it. While this C++ code itself doesn't *directly* involve JavaScript, it underpins the network communication that JavaScript relies on. I explained this indirect relationship by highlighting how this code helps browsers (and potentially Node.js servers) communicate using HTTP/2.

10. **Generating Logic Inference Examples:** For the logic inference examples, I selected a relatively straightforward test case (`ServerSubmitsTrailers`) and created a simplified scenario with clear inputs (client request) and outputs (server responses). This involved tracing the calls to `ProcessBytes`, `SubmitResponse`, `SubmitTrailer`, and `Send`.

11. **Identifying User/Programming Errors:** I analyzed the tests that explicitly checked for erroneous behavior (e.g., `ClientDisobeysFlowControl`) to identify potential user or programming errors. These included violating flow control limits and submitting trailers after indicating the end of the stream in the data.

12. **Tracing User Actions to the Code:** To explain how a user might reach this code, I created a simple user interaction scenario (visiting a website) and traced the steps down to the HTTP/2 layer and the potential involvement of this adapter code.

13. **Summarizing the Functionality (Part 8 of 12):**  Given that this was stated to be part 8 of 12, I inferred that the earlier parts likely covered basic request/response handling, and the later parts might deal with more advanced features or error scenarios. Therefore, I summarized this part as focusing on server-side response handling, particularly the complexities of trailers and flow control.

14. **Iterative Refinement:** Throughout the process, I reviewed and refined my understanding and explanations. I ensured that the response addressed all aspects of the prompt and was clear, concise, and accurate. I also paid attention to formatting and organization to make the information easily digestible.

By following these steps, I was able to systematically analyze the code snippet and generate a comprehensive and informative response that addressed all the requirements of the prompt.
好的，让我们分析一下 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc` 文件的第 8 部分代码的功能。

**功能归纳（基于提供的代码片段）：**

这部分代码主要关注 `OgHttp2Adapter` 作为 HTTP/2 服务器，在处理数据传输，特别是 **Trailer（尾部）** 以及 **流控（Flow Control）** 相关的场景下的行为和正确性。具体来说，它测试了以下功能：

1. **服务器提交 Trailer (尾部)**：
   - 测试了服务器在发送完响应体后，能够正确地提交和发送 Trailer。
   - 包括了在有和没有响应体的情况下提交 Trailer 的情况。
   - 验证了即使在数据源尚未完全发送完数据时，Adapter 也能优先发送 Trailer。

2. **服务器提交 Trailer 并遇到流控阻塞**：
   - 模拟了响应体和 Trailer 由于流控限制而被阻塞的情况。
   - 验证了 Adapter 在流控限制下，仍然能够正确处理 Trailer 的提交和发送。
   - 测试了在流控恢复后，Adapter 能否继续发送剩余的数据和 Trailer。

3. **服务器在 DATA 帧中设置 END_STREAM 标志后提交 Trailer 的情况**：
   - 测试了当服务器在发送 DATA 帧时设置了 `END_STREAM` 标志，表明数据流结束，此时再提交 Trailer 会发生什么。
   - 预期行为是，由于数据流已经结束，发送 Trailer 是不正确的，Adapter 应该关闭流并发出错误。

4. **客户端违反连接级和流级流控**：
   - 模拟了客户端发送超过服务器声明的连接级和流级流控窗口大小的数据的情况。
   - 验证了服务器能够检测到这种违反行为，并采取相应的措施，例如发送 `GOAWAY` 帧（针对连接级错误）或 `RST_STREAM` 帧（针对流级错误）来关闭连接或流。

5. **处理头部时发生服务器错误**：
   - 模拟了在处理客户端发送的头部时，服务器内部发生错误的情况（通过 Visitor 返回 `HEADER_RST_STREAM` 来模拟）。
   - 验证了服务器能够正确处理这种错误，并发送 `RST_STREAM` 帧来关闭相应的流。
   - 同时测试了在这种错误发生后，后续收到的属于该流的帧是否会被丢弃。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它作为 Chromium 网络栈的一部分，直接影响着基于 JavaScript 的 Web 应用的行为。

**举例说明：**

* **Trailer 的支持：**  如果这段代码测试的 Trailer 功能正常工作，那么当一个 JavaScript 应用（例如使用 `fetch` API）向服务器发起请求，服务器返回带有 Trailer 的响应时，浏览器能够正确地接收和处理这些 Trailer。JavaScript 可以通过特定的 API（例如 `Headers` 对象的迭代器）来访问这些 Trailer 信息。

   ```javascript
   fetch('/resource-with-trailer')
     .then(response => {
       console.log('Response status:', response.status);
       const trailerHeaders = response.headers.get('Trailer');
       console.log('Trailer headers to expect:', trailerHeaders); // 例如: 'final-status'
       return response.text();
     })
     .then(body => {
       console.log('Response body:', body);
       // 获取 Trailer (并非所有浏览器都支持直接访问)
       // 一些实验性 API 可能允许访问
       // 或者需要在 response 完成后检查特定的属性
     });
   ```

* **流控的影响：**  这段代码测试的流控机制直接影响着浏览器和服务器之间数据传输的效率和稳定性。如果流控实现不正确，可能会导致浏览器接收数据缓慢，或者因为客户端发送过多数据而导致连接中断。JavaScript 应用的性能会受到这些底层网络行为的影响。

**逻辑推理，假设输入与输出：**

**场景：服务器提交 Trailer 并遇到流控阻塞**

**假设输入（模拟客户端行为）：**

1. **客户端发送连接前言（Client Preface）。**
2. **客户端发送一个 HEADERS 帧，发起一个 ID 为 1 的请求。**
3. **客户端发送一个 WINDOW_UPDATE 帧，增加连接级的流控窗口。**

**Adapter 接收到这些输入后，内部状态和 Visitor 的调用序列（部分）：**

1. **`OnFrameHeader(0, 0, SETTINGS, 0)`**: 接收到客户端的 SETTINGS 帧。
2. **`OnSettingsStart()`**, **`OnSettingsEnd()`**: 处理客户端的 SETTINGS。
3. **`OnFrameHeader(1, _, HEADERS, 4)`**: 接收到客户端的 HEADERS 帧。
4. **`OnBeginHeadersForStream(1)`**, **`OnHeaderForStream(1, _, _)` (多次)**, **`OnEndHeadersForStream(1)`**:  处理请求头部。
5. **`OnFrameHeader(0, 4, WINDOW_UPDATE, 0)`**: 接收到客户端的 WINDOW_UPDATE 帧。
6. **`OnWindowUpdate(0, 2000)`**: 更新连接级流控窗口。

**假设服务器的输出（Adapter 调用 Visitor 发送的帧）：**

1. **发送服务器的 SETTINGS 帧。**
2. **发送对客户端 SETTINGS 的 ACK 帧。**
3. **发送响应头部 (HEADERS 帧)。**
4. **发送部分响应体 (DATA 帧，可能因为流控被分割成多个)。**

**此时，如果提交的 Trailer 由于流控阻塞，预期的后续行为是：**

1. **`SubmitTrailer` 调用返回成功 (0)。**
2. **`want_write()` 返回 `true`，表明需要写入数据。**
3. **在流控窗口允许的情况下，`Send()` 调用会发送更多的数据 (DATA 帧)。**
4. **当流控窗口允许发送 Trailer 时，`Send()` 调用会发送带有 `END_STREAM` 和 `END_HEADERS` 标志的 HEADERS 帧。**
5. **相应的 Visitor 方法会被调用，例如 `OnBeforeFrameSent(HEADERS, 1, _, END_STREAM_FLAG | END_HEADERS_FLAG)` 和 `OnFrameSent(...)`。**

**用户或编程常见的使用错误：**

1. **在 DATA 帧设置了 `END_STREAM` 后尝试提交 Trailer：**  这是代码中明确测试的错误场景。开发者可能会错误地认为在发送完所有数据后可以再添加 Trailer，但 HTTP/2 协议规定，当 DATA 帧带有 `END_STREAM` 标志时，表示流的结束，不能再发送 Trailer。

   ```c++
   // 错误示例
   visitor.AppendPayloadForStream(1, kBody);
   visitor.SetEndData(1, true); // 错误地设置了 END_STREAM
   auto body = std::make_unique<VisitorDataSource>(visitor, 1);
   adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}), std::move(body), false);
   adapter->SubmitTrailer(1, ToHeaders({{"final-status", "oops"}})); // 错误地尝试提交 Trailer
   ```
   **预期行为：**  Adapter 会检测到这种不一致，并可能关闭流或连接。

2. **客户端发送数据超过流控窗口：**  客户端应该尊重服务器声明的流控窗口大小，避免发送过多的数据。如果客户端违反流控，服务器可能会发送 `RST_STREAM` 或 `GOAWAY` 帧。

   ```c++
   // 客户端代码（伪代码，表示概念）
   sendData(streamId, largeAmountOfData); // 超过服务器允许的窗口大小
   ```
   **预期行为：** 服务器端的 `OgHttp2Adapter` 会检测到流量控制错误，并采取措施关闭流或连接。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个支持 HTTP/2 的网站，并且该网站的服务器在响应中使用了 Trailer。

1. **用户在 Chrome 浏览器的地址栏中输入网址并按下回车键。**
2. **Chrome 浏览器的渲染进程发起网络请求。**
3. **网络请求被传递到 Chrome 的网络服务 (Network Service)。**
4. **网络服务检测到服务器支持 HTTP/2，并建立 HTTP/2 连接。**
5. **网络服务构建 HTTP/2 HEADERS 帧并发送给服务器。**
6. **服务器处理请求，生成响应头和响应体。**
7. **服务器决定在响应的末尾添加 Trailer。**
8. **服务器的网络栈（可能使用了基于 `quiche` 的 HTTP/2 实现）调用 `OgHttp2Adapter` 的相关方法来发送响应头、响应体和 Trailer。**
9. **如果此时涉及到流控，`OgHttp2Adapter` 内部的逻辑会处理流控窗口的限制，并可能将数据分段发送。**
10. **开发者在调试服务器端的 HTTP/2 实现时，可能会遇到与 Trailer 或流控相关的 Bug。**
11. **为了重现和修复 Bug，开发者会编写类似 `oghttp2_adapter_test.cc` 中的测试用例，来模拟各种场景，包括发送 Trailer、遇到流控阻塞、客户端违反流控等。**
12. **开发者可以通过运行这些测试用例，观察 `OgHttp2Adapter` 的行为，例如检查 Visitor 的调用顺序、发送的帧内容等，来定位和修复问题。**

**总结第 8 部分的功能：**

总而言之，`oghttp2_adapter_test.cc` 的第 8 部分专注于测试 `OgHttp2Adapter` 作为 HTTP/2 服务器在处理数据传输中的关键特性，特别是 **Trailer 的发送和处理**，以及 **流控机制的正确性**。它涵盖了服务器正确发送 Trailer 的各种情况，以及在遇到流控限制和客户端违反流控时的处理方式，并测试了在处理头部时发生错误时的容错能力。这些测试对于确保 Chromium 网络栈中 HTTP/2 服务器实现的稳定性和符合协议规范至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
, 0, 0, ACK_FLAG));
    EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

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
    EXPECT_EQ(0, send_result);
    visitor.Clear();
    EXPECT_FALSE(adapter->want_write());

    if (add_more_body_data) {
      visitor.AppendPayloadForStream(1, " More body! This is ignored.");
    }
    int trailer_result =
        adapter->SubmitTrailer(1, ToHeaders({{"final-status", "a-ok"}}));
    ASSERT_EQ(trailer_result, 0);
    // Even though the data source has not finished sending data, the library
    // will write the trailers anyway.
    EXPECT_TRUE(adapter->want_write());

    EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                           END_STREAM_FLAG | END_HEADERS_FLAG));
    EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                     END_STREAM_FLAG | END_HEADERS_FLAG, 0));

    send_result = adapter->Send();
    EXPECT_EQ(0, send_result);
    EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
    EXPECT_FALSE(adapter->want_write());
  }
}

// Tests the case where the response body and trailers become blocked by flow
// control while the stream is writing. Regression test for
// https://github.com/envoyproxy/envoy/issues/31710
TEST_P(OgHttp2AdapterDataTest, ServerSubmitsTrailersWithFlowControlBlockage) {
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
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 2000));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  visitor.Clear();

  EXPECT_EQ(kInitialFlowControlWindowSize, adapter->GetStreamSendWindowSize(1));

  const std::string kBody(60000, 'a');

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
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0)).Times(4);

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA,
                            SpdyFrameType::DATA, SpdyFrameType::DATA,
                            SpdyFrameType::DATA}));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  visitor.AppendPayloadForStream(1, std::string(6000, 'b'));
  // The next response body data payload is larger than the available stream
  // flow control window.
  EXPECT_LT(adapter->GetStreamSendWindowSize(1), 6000);
  // There is more than enough connection flow control window.
  EXPECT_GT(adapter->GetSendWindowSize(), 6000);

  adapter->ResumeStream(1);
  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{"final-status", "a-ok"}}));
  ASSERT_EQ(trailer_result, 0);

  EXPECT_TRUE(adapter->want_write());
  // This will send data but not trailers, because the data source hasn't
  // finished sending.
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));
  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
  visitor.Clear();

  // Stream flow control window is exhausted.
  EXPECT_EQ(adapter->GetStreamSendWindowSize(1), 0);
  // Connection flow control window is available.
  EXPECT_GT(adapter->GetSendWindowSize(), 0);

  // After a window update, the adapter will send the last data, followed by
  // trailers.
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
  adapter->ProcessBytes(TestFrameSequence().WindowUpdate(1, 2000).Serialize());

  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::DATA, SpdyFrameType::HEADERS}));
  EXPECT_FALSE(adapter->want_write());
}

TEST_P(OgHttp2AdapterDataTest, ServerSubmitsTrailersWithDataEndStream) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  // The data should be sent, but because it has END_STREAM, it would not be
  // correct to send trailers afterward. The stream should be closed.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, END_STREAM_FLAG, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR));

  const int send_result = adapter->Send();
  EXPECT_EQ(send_result, 0);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
}

TEST_P(OgHttp2AdapterDataTest,
       ServerSubmitsTrailersWithDataEndStreamAndDeferral) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(send_result, 0);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  visitor.Clear();

  const std::vector<Header> trailers =
      ToHeaders({{"extra-info", "Trailers are weird but good?"}});
  submit_result = adapter->SubmitTrailer(1, trailers);
  ASSERT_EQ(submit_result, 0);

  // Add more body and signal the end of data. Resuming the stream should allow
  // the new body to be sent.
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, true);
  adapter->ResumeStream(1);

  // The new body should be sent, but because it has END_STREAM, it would not be
  // correct to send trailers afterward. The stream should be closed.
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, END_STREAM_FLAG, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(send_result, 0);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
}

TEST(OgHttp2AdapterTest, ClientDisobeysConnectionFlowControl) {
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
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kFlowControlError));
  // No further frame data or headers are delivered.

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(GOAWAY, 0, _, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ClientDisobeysConnectionFlowControlWithOneDataFrame) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

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

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor, OnFrameHeader(1, window_overflow_bytes, DATA, 0x0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kFlowControlError));
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

TEST(OgHttp2AdapterTest, ClientDisobeysConnectionFlowControlAcrossReads) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

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
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

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

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor, OnFrameHeader(1, window_overflow_bytes, DATA, 0x0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kFlowControlError));

  const size_t chunk_length = 16384;
  ASSERT_GE(overflow_frames.size(), chunk_length);
  process_result =
      adapter->ProcessBytes(overflow_frames.substr(0, chunk_length));
  EXPECT_EQ(chunk_length, static_cast<size_t>(process_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(GOAWAY, 0, _, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ClientDisobeysStreamFlowControl) {
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

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 0, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 0, 4, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
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
  // No further frame data or headers are delivered.

  result = adapter->ProcessBytes(more_frames);
  EXPECT_EQ(more_frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(RST_STREAM, 1, 4, 0x0,
                  static_cast<int>(Http2ErrorCode::FLOW_CONTROL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerErrorWhileHandlingHeaders) {
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
  // Stream WINDOW_UPDATE and DATA frames are not delivered to the visitor.
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 2000));

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

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterTest, ServerErrorWhileHandlingHeadersDropsFrames) {
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
  // Frames for the RST_STREAM-marked stream are not delivered to the visitor.
  // Note: nghttp2 still delivers control frames and metadata for the stream.
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
```
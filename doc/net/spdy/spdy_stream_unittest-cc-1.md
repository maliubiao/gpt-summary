Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/spdy/spdy_stream_unittest.cc`. This is part 2 of 2, implying a continuation of tests related to `SpdyStream`.

Here's a breakdown of how to address the request:

1. **Overall Functionality:** Summarize the main purpose of this code block within the larger context of the unit test file. It's focused on testing the behavior of `SpdyStream` in various scenarios, especially regarding header handling, timing, flow control, and error conditions.

2. **Relationship with JavaScript:** Determine if any of the tested functionalities directly relate to how JavaScript interacts with network requests in a browser. This will likely involve concepts like Early Hints and how timing information is exposed to web pages.

3. **Logical Reasoning (Input/Output):** Identify specific test cases that demonstrate a logical flow with clear input conditions (e.g., specific SPDY frames received) and expected output (e.g., delegate callbacks, error codes).

4. **Common Usage Errors:** Pinpoint test cases that simulate incorrect server behavior or situations that a user or developer might encounter, leading to errors.

5. **User Operation to Reach Here (Debugging):**  Describe a high-level user interaction in a browser that could trigger the network events being tested. This helps establish a context for debugging.

6. **Part 2 Summary:** Condense the functionalities covered in this specific part of the code.

**Mental Sandbox:**

* **JavaScript Connection:**  The "Early Hints" test immediately stands out as relevant to JavaScript. Browsers use this information to preload resources, improving page load performance. The `LoadTimingInfo` also ties into JavaScript's performance APIs.

* **Input/Output:** The tests with `AddRead` and `AddWrite` are perfect examples of defined input (simulated network data) and expected output (assertions on delegate state, error codes).

* **Usage Errors:** Tests involving invalid `:status` headers directly simulate server-side errors that a browser needs to handle.

* **Debugging:** A simple navigation to a website that uses HTTP/2 and potentially Early Hints is the most direct way a user's action leads to this code being relevant.

* **Part 2 Focus:** This part appears to focus heavily on error handling for invalid responses, flow control mechanisms, and the accurate reporting of received data and timing information, including the handling of Early Hints.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果它与javascript的功能有关系，请做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 这是第2部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

Strategizing complete. Proceeding with response generation.

这是 `net/spdy/spdy_stream_unittest.cc` 文件内容的第二部分，延续了对 Chromium 网络栈中 `SpdyStream` 类的单元测试。结合第一部分，这部分着重测试了 `SpdyStream` 在处理接收到的数据和特定场景下的行为，包括：

**主要功能归纳 (Part 2):**

* **接收时序信息 (Load Timing Info):**  测试了在接收响应头和 Early Hints 时，`SpdyStream` 如何准确记录时间戳，并通过 `LoadTimingInfo` 提供给上层。
* **Early Hints (103 状态码) 处理:** 详细测试了 `SpdyStream` 如何解析和处理 103 Early Hints 响应，包括多次 Early Hints 的情况，以及如何将这些信息通过 delegate 回调传递给上层。
* **非法的 HTTP 状态码处理:** 测试了当接收到不符合 HTTP/2 规范的状态码时（例如，非数字、包含额外文本、缺少状态码），`SpdyStream` 如何检测到错误并关闭连接。
* **发送窗口大小控制 (Flow Control):** 测试了 `SpdyStream` 在发送数据时如何处理发送窗口大小，包括处理溢出的情况，以及在发送窗口被阻塞后如何恢复发送。
* **流的阻塞和恢复 (Stalling and Unstalling):**  测试了当发送窗口被阻塞（例如，由于流量控制）后，`SpdyStream` 如何暂停发送，并在发送窗口增大后如何恢复发送，分别针对 Request/Response 类型的流和双向流进行了测试。
* **接收到的字节数统计:**  测试了 `SpdyStream` 如何准确记录从网络接收到的原始字节数。
* **半关闭状态下的数据处理:**  测试了在流被半关闭（发送端或接收端已发送 FIN）后，如果继续接收到数据，`SpdyStream` 如何处理。
* **EOF (End of File) 通知:**  测试了当底层连接关闭时，`SpdyStream` 如何通知 delegate。
* **流量控制中的慢速读取:**  测试了在接收数据较慢的情况下，`SpdyStream` 如何管理接收窗口更新，并避免频繁发送窗口更新。

**与 JavaScript 功能的关系 (及举例说明):**

* **Early Hints:**  这部分测试直接关联到浏览器中提升页面加载性能的 Early Hints 功能。当服务器发送 103 状态码的响应时，其中包含的 `Link` 头部可以指示浏览器预加载一些资源（例如，CSS、JavaScript、图片）。`SpdyStream` 负责解析这些头部信息，并通过 delegate 将其传递给上层，最终浏览器可以利用这些信息来提前发起请求，从而加速页面渲染。
    * **举例说明:**  假设一个网站的 HTML 中引用了一个 CSS 文件 `<link rel="stylesheet" href="style.css">`。服务器可以先发送一个包含 `Link: </style.css>; rel=preload; as=stylesheet` 的 103 Early Hints 响应。`SpdyStream` 解析到这个信息后，浏览器就可以在接收到完整的 HTML 之前就开始下载 `style.css`，从而减少用户感知到的加载时间。
* **Load Timing Info:**  `SpdyStream` 收集的 `receive_headers_start` 和 `receive_non_informational_headers_start` 等时间信息，最终会通过浏览器的 Performance API (例如 `performance.getEntriesByType("resource")`) 暴露给 JavaScript。开发者可以通过这些 API 了解资源的加载时序，用于性能分析和优化。
    * **举例说明:** JavaScript 代码可以使用 `performance.getEntriesByType("resource")` 获取到某个网络请求的详细 timing 信息，其中包括了接收到响应头的开始时间。这可以帮助开发者判断网络延迟发生在哪里。

**逻辑推理 (假设输入与输出):**

* **测试用例: `EarlyHints`**
    * **假设输入:**  客户端发送一个 GET 请求。服务器先发送两个包含 `Link` 头部的 103 响应，然后发送一个 200 响应和响应体。
    * **预期输出:**  `delegate().early_hints()` 会包含两个 `HttpHeaderBlock`，分别对应两个 103 响应的头部信息，包括 `link` 头部。`load_timing_info.first_early_hints_time` 会记录第一个 103 响应头部到达的时间。最终会成功接收到 200 响应和响应体。
* **测试用例: `StatusMustBeNumber`**
    * **假设输入:** 客户端发送一个 GET 请求。服务器发送一个包含非数字状态码 (例如 "nan") 的响应头。
    * **预期输出:** `SpdyStream` 会检测到协议错误，发送一个 RST_STREAM 帧关闭流，并且 delegate 的 `WaitForClose()` 方法会返回 `ERR_HTTP2_PROTOCOL_ERROR`。

**用户或编程常见的使用错误 (及举例说明):**

* **服务端返回错误的 HTTP 状态码:**  `StatusMustBeNumber`, `StatusCannotHaveExtraText`, `StatusMustBePresent` 等测试用例模拟了服务端在 HTTP/2 协议下返回不符合规范的状态码的情况。这可能是服务端程序逻辑错误或者配置错误导致的。
    * **举例说明:**  一个服务端程序在处理请求时，错误地将状态码设置为字符串 "OK" 而不是数字 "200"。浏览器 (通过 `SpdyStream`) 会检测到这个错误并中断连接。
* **流量控制不当导致发送阻塞:** 虽然这不是用户的直接错误，但开发者在实现网络应用时，需要理解流量控制机制。如果服务端没有及时更新客户端的发送窗口，客户端可能会因为发送窗口为零而阻塞。
    * **举例说明:**  一个实现了自定义 HTTP/2 客户端的应用，在发送大量数据时，如果服务端没有发送 WINDOW_UPDATE 帧来增加客户端的发送窗口，客户端的 `SpdyStream` 会被阻塞，直到收到窗口更新。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 URL 并回车，或者点击一个链接。**
2. **浏览器解析 URL，并判断需要建立网络连接。**
3. **如果目标网站支持 HTTP/2 协议，并且浏览器与服务器之间建立了 HTTP/2 连接。**
4. **浏览器根据请求信息构建 HTTP 请求头。**
5. **`SpdyStream` 将请求头序列化为 SPDY 帧并通过底层的 Socket 发送出去。**
6. **服务器处理请求，并构建 HTTP 响应头和响应体。**
7. **服务器将响应头（可能包含 Early Hints 的 103 响应，最终的 200 响应等）序列化为 SPDY 的 HEADERS 帧，并将响应体序列化为 DATA 帧，通过 Socket 发送给浏览器。**
8. **浏览器接收到来自服务器的 SPDY 帧，`SpdyStream` 负责解析这些帧。**
9. **这部分测试代码模拟了步骤 8 中 `SpdyStream` 解析接收到的 HEADERS 帧和 DATA 帧的各种场景，例如：**
    * 接收到 103 Early Hints 响应，`EarlyHints` 测试会覆盖这种情况。
    * 接收到包含非法状态码的响应头，`StatusMustBeNumber` 等测试会覆盖这种情况。
    * 接收到正常的数据帧，`ReceivedBytes` 测试会覆盖这种情况。
10. **如果出现网络问题或者服务端返回错误，`SpdyStream` 的错误处理逻辑会被触发，例如发送 RST_STREAM 帧关闭流。**

在调试网络请求时，如果发现与 HTTP/2 协议相关的行为异常（例如，Early Hints 没有生效，或者出现协议错误），就可以参考 `net/spdy/spdy_stream_unittest.cc` 中的测试用例，理解 `SpdyStream` 在各种情况下的预期行为，从而帮助定位问题。例如，可以通过抓包工具查看浏览器和服务器之间的 SPDY 帧交互，对照测试用例中的模拟数据，分析 `SpdyStream` 的行为是否符合预期。

**总结 Part 2 的功能:**

总的来说，这部分 `SpdyStream` 的单元测试主要关注于测试 `SpdyStream` **接收数据和处理错误**的能力。它验证了 `SpdyStream` 是否能够正确解析和处理各种类型的响应头部（包括 Early Hints），处理非法的 HTTP 状态码，管理流量控制，并在各种异常情况下做出正确的反应，例如连接关闭或接收到错误的数据。 这些测试确保了 `SpdyStream` 能够可靠地与符合 HTTP/2 协议的服务器进行通信，并为上层（例如 Chrome 浏览器）提供准确的网络数据和状态信息。

Prompt: 
```
这是目录为net/spdy/spdy_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
received.
  EXPECT_EQ(load_timing_info.receive_headers_start,
            expected_receive_headers_start_time);
  // The non-informational response start time should be captured at the time
  // the first header fragment of the non-informational response is received.
  EXPECT_EQ(load_timing_info.receive_non_informational_headers_start,
            expected_receive_non_informational_headers_start_time);
  // The first response start time should be earlier than the non-informational
  // response start time.
  EXPECT_LT(load_timing_info.receive_headers_start,
            load_timing_info.receive_non_informational_headers_start);
}

// Tests that timing information of 103 Eary Hints responses are collected and
// callbacks are called as expected.
TEST_F(SpdyStreamTestWithMockClock, EarlyHints) {
  // Set up the request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  // Set up two early hints response headers.
  const char kLinkHeaderValue1[] = "</image.jpg>; rel=preload; as=image";
  quiche::HttpHeaderBlock informational_headers1;
  informational_headers1[":status"] = "103";
  informational_headers1["link"] = kLinkHeaderValue1;
  spdy::SpdySerializedFrame informational_response1(
      spdy_util_.ConstructSpdyResponseHeaders(
          1, std::move(informational_headers1), false));

  const char kLinkHeaderValue2[] = "</style.css>; rel=preload; as=stylesheet";
  quiche::HttpHeaderBlock informational_headers2;
  informational_headers2[":status"] = "103";
  informational_headers2["link"] = kLinkHeaderValue2;
  spdy::SpdySerializedFrame informational_response2(
      spdy_util_.ConstructSpdyResponseHeaders(
          1, std::move(informational_headers2), false));

  // Add the headers to make sure that multiple informational responses don't
  // confuse the timing information.
  const int kNumberOfInformationalResponses = 2;
  // Separate the headers into 2 fragments and add pauses between the
  // fragments so that the test runner can advance the mock clock to test
  // timing information.
  AddMockRead(ReadFrameExceptForLastByte(informational_response1));
  AddReadPause();
  AddMockRead(LastByteOfReadFrame(informational_response1));
  AddReadPause();

  AddMockRead(ReadFrameExceptForLastByte(informational_response2));
  AddReadPause();
  AddMockRead(LastByteOfReadFrame(informational_response2));
  AddReadPause();

  // Set up the non-informational response headers and body.
  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);
  AddReadPause();
  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddRead(body);
  AddReadEOF();

  // Set up the sequenced socket data and the spdy stream.
  Initialize();

  // Send a request.
  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream()->SendRequestHeaders(std::move(headers),
                                                         NO_MORE_DATA_TO_SEND));
  AdvanceClock(base::Seconds(1));

  // The receive headers start time should be captured at this time.
  base::TimeTicks expected_receive_headers_start_time = base::TimeTicks::Now();

  // Read the header fragments of the informational responses.
  for (int i = 0; i < kNumberOfInformationalResponses; ++i) {
    RunUntilNextPause();
    AdvanceClock(base::Seconds(1));
    RunUntilNextPause();
    AdvanceClock(base::Seconds(1));
  }

  // Check the callback was called twice with 103 status code.
  const std::vector<quiche::HttpHeaderBlock>& early_hints =
      delegate().early_hints();
  EXPECT_EQ(early_hints.size(),
            static_cast<size_t>(kNumberOfInformationalResponses));
  {
    const quiche::HttpHeaderBlock& hint = delegate().early_hints()[0];
    quiche::HttpHeaderBlock::const_iterator status_iterator =
        hint.find(spdy::kHttp2StatusHeader);
    ASSERT_TRUE(status_iterator != hint.end());
    EXPECT_EQ(status_iterator->second, "103");

    quiche::HttpHeaderBlock::const_iterator link_header_iterator =
        hint.find("link");
    ASSERT_TRUE(link_header_iterator != hint.end());
    EXPECT_EQ(link_header_iterator->second, kLinkHeaderValue1);
  }
  {
    const quiche::HttpHeaderBlock& hint = delegate().early_hints()[1];
    quiche::HttpHeaderBlock::const_iterator status_iterator =
        hint.find(spdy::kHttp2StatusHeader);
    ASSERT_TRUE(status_iterator != hint.end());
    EXPECT_EQ(status_iterator->second, "103");

    quiche::HttpHeaderBlock::const_iterator link_header_iterator =
        hint.find("link");
    ASSERT_TRUE(link_header_iterator != hint.end());
    EXPECT_EQ(link_header_iterator->second, kLinkHeaderValue2);
  }

  // The receive non-informational headers start time should be captured at this
  // time.
  base::TimeTicks expected_receive_non_informational_headers_start_time =
      base::TimeTicks::Now();

  // Read the non-informational response headers.
  RunUntilNextPause();
  AdvanceClock(base::Seconds(1));
  EXPECT_EQ("200", delegate().GetResponseHeaderValue(spdy::kHttp2StatusHeader));

  // Read the response body.
  EXPECT_THAT(RunUntilClose(), IsOk());
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate().TakeReceivedData());

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(data().AllWriteDataConsumed());
  EXPECT_TRUE(data().AllReadDataConsumed());

  const LoadTimingInfo& load_timing_info = delegate().GetLoadTimingInfo();
  // The response start time should be captured at the time the first header
  // fragment of the first informational response is received.
  EXPECT_EQ(load_timing_info.receive_headers_start,
            expected_receive_headers_start_time);
  // The first early hints time should be recorded as well.
  EXPECT_EQ(load_timing_info.first_early_hints_time,
            expected_receive_headers_start_time);
  // The non-informational response start time should be captured at the time
  // the first header fragment of the non-informational response is received.
  EXPECT_EQ(load_timing_info.receive_non_informational_headers_start,
            expected_receive_non_informational_headers_start_time);
  // The response start time should be earlier than the non-informational
  // response start time.
  EXPECT_LT(load_timing_info.receive_headers_start,
            load_timing_info.receive_non_informational_headers_start);
}

TEST_F(SpdyStreamTest, StatusMustBeNumber) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  quiche::HttpHeaderBlock incorrect_headers;
  incorrect_headers[":status"] = "nan";
  spdy::SpdySerializedFrame reply(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(incorrect_headers), false));
  AddRead(reply);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, StatusCannotHaveExtraText) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  quiche::HttpHeaderBlock headers_with_status_text;
  headers_with_status_text[":status"] =
      "200 Some random extra text describing status";
  spdy::SpdySerializedFrame reply(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(headers_with_status_text), false));
  AddRead(reply);

  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddRead(body);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, StatusMustBePresent) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  quiche::HttpHeaderBlock headers_without_status;
  spdy::SpdySerializedFrame reply(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(headers_without_status), false));
  AddRead(reply);

  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddRead(body);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_PROTOCOL_ERROR));

  // Finish async network reads and writes.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Call IncreaseSendWindowSize on a stream with a large enough delta to overflow
// an int32_t. The SpdyStream should handle that case gracefully.
TEST_F(SpdyStreamTest, IncreaseSendWindowSizeOverflow) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  AddReadPause();

  // Triggered by the overflowing call to IncreaseSendWindowSize
  // below.
  spdy::SpdySerializedFrame rst(spdy_util_.ConstructSpdyRstStream(
      1, spdy::ERROR_CODE_FLOW_CONTROL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST,
      NetLogWithSource::Make(NetLogSourceType::NONE));
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  data.RunUntilPaused();

  int32_t old_send_window_size = stream->send_window_size();
  ASSERT_GT(old_send_window_size, 0);
  int32_t delta_window_size =
      std::numeric_limits<int32_t>::max() - old_send_window_size + 1;
  stream->IncreaseSendWindowSize(delta_window_size);
  EXPECT_FALSE(stream);

  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_FLOW_CONTROL_ERROR));
}

// Functions used with
// RunResumeAfterUnstall{RequestResponse,Bidirectional}Test().

void StallStream(const base::WeakPtr<SpdyStream>& stream) {
  // Reduce the send window size to 0 to stall.
  while (stream->send_window_size() > 0) {
    stream->DecreaseSendWindowSize(
        std::min(kMaxSpdyFrameChunkSize, stream->send_window_size()));
  }
}

void IncreaseStreamSendWindowSize(const base::WeakPtr<SpdyStream>& stream,
                                  int32_t delta_window_size) {
  EXPECT_TRUE(stream->send_stalled_by_flow_control());
  stream->IncreaseSendWindowSize(delta_window_size);
  EXPECT_FALSE(stream->send_stalled_by_flow_control());
}

void AdjustStreamSendWindowSize(const base::WeakPtr<SpdyStream>& stream,
                                int32_t delta_window_size) {
  // Make sure that negative adjustments are handled properly.
  EXPECT_TRUE(stream->send_stalled_by_flow_control());
  EXPECT_TRUE(stream->AdjustSendWindowSize(-delta_window_size));
  EXPECT_TRUE(stream->send_stalled_by_flow_control());
  EXPECT_TRUE(stream->AdjustSendWindowSize(+delta_window_size));
  EXPECT_TRUE(stream->send_stalled_by_flow_control());
  EXPECT_TRUE(stream->AdjustSendWindowSize(+delta_window_size));
  EXPECT_FALSE(stream->send_stalled_by_flow_control());
}

// Given an unstall function, runs a test to make sure that a
// request/response (i.e., an HTTP-like) stream resumes after a stall
// and unstall.
void SpdyStreamTest::RunResumeAfterUnstallRequestResponseTest(
    UnstallFunction unstall_function) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddWrite(body);

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(resp);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateWithBody delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  StallStream(stream);

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream->send_stalled_by_flow_control());

  std::move(unstall_function).Run(stream, kPostBodyLength);

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, ResumeAfterSendWindowSizeIncreaseRequestResponse) {
  RunResumeAfterUnstallRequestResponseTest(
      base::BindOnce(&IncreaseStreamSendWindowSize));
}

TEST_F(SpdyStreamTest, ResumeAfterSendWindowSizeAdjustRequestResponse) {
  RunResumeAfterUnstallRequestResponseTest(
      base::BindOnce(&AdjustStreamSendWindowSize));
}

// Given an unstall function, runs a test to make sure that a bidirectional
// (i.e., non-HTTP-like) stream resumes after a stall and unstall.
void SpdyStreamTest::RunResumeAfterUnstallBidirectionalTest(
    UnstallFunction unstall_function) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  AddReadPause();

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(resp);

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddWrite(msg);

  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(echo);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  data.RunUntilPaused();

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  StallStream(stream);

  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream->send_stalled_by_flow_control());

  std::move(unstall_function).Run(stream, kPostBodyLength);

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, ResumeAfterSendWindowSizeIncreaseBidirectional) {
  RunResumeAfterUnstallBidirectionalTest(
      base::BindOnce(&IncreaseStreamSendWindowSize));
}

TEST_F(SpdyStreamTest, ResumeAfterSendWindowSizeAdjustBidirectional) {
  RunResumeAfterUnstallBidirectionalTest(
      base::BindOnce(&AdjustStreamSendWindowSize));
}

// Test calculation of amount of bytes received from network.
TEST_F(SpdyStreamTest, ReceivedBytes) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  AddReadPause();

  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  AddReadPause();

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(msg);

  AddReadPause();

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));

  int64_t reply_frame_len = reply.size();
  int64_t data_header_len = spdy::kDataFrameMinimumSize;
  int64_t data_frame_len = data_header_len + kPostBodyLength;
  int64_t response_len = reply_frame_len + data_frame_len;

  EXPECT_EQ(0, stream->raw_received_bytes());

  // REQUEST
  data.RunUntilPaused();
  EXPECT_EQ(0, stream->raw_received_bytes());

  // REPLY
  data.Resume();
  data.RunUntilPaused();
  EXPECT_EQ(reply_frame_len, stream->raw_received_bytes());

  // DATA
  data.Resume();
  data.RunUntilPaused();
  EXPECT_EQ(response_len, stream->raw_received_bytes());

  // FIN
  data.Resume();
  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
}

// Regression test for https://crbug.com/810763.
TEST_F(SpdyStreamTest, DataOnHalfClosedRemoveStream) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  quiche::HttpHeaderBlock response_headers;
  response_headers[spdy::kHttp2StatusHeader] = "200";
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(response_headers), /* fin = */ true));
  AddRead(resp);

  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddRead(data_frame);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_STREAM_CLOSED));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_HTTP2_STREAM_CLOSED));

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, DelegateIsInformedOfEOF) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  quiche::HttpHeaderBlock response_headers;
  response_headers[spdy::kHttp2StatusHeader] = "200";
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(response_headers), /* fin = */ true));
  AddRead(resp);

  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, true));
  AddRead(data_frame);

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_STREAM_CLOSED));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateDetectEOF delegate(stream);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(delegate.eof_detected());

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// A small read should trigger sending a receive window update and dropping the
// count of unacknowledged bytes to zero only after
// kDefaultTimeToBufferSmallWindowUpdates time has passed.
TEST_F(SpdyStreamTestWithMockClock, FlowControlSlowReads) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  AddWrite(req);

  AddReadPause();

  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  AddReadPause();

  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBodyStringPiece, false));
  AddRead(msg);

  AddReadPause();

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());
  session->SetTimeToBufferSmallWindowUpdates(
      kDefaultTimeToBufferSmallWindowUpdates);

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  StreamDelegateConsumeData delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_EQ(0, unacked_recv_window_bytes(stream));

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));

  // REQUEST
  data.RunUntilPaused();

  // REPLY
  data.Resume();
  data.RunUntilPaused();

  // Delay long enough for the receive window to send an update on read,
  // draining the unacked_recv_window_bytes back to zero.
  AdvanceClock(kDefaultTimeToBufferSmallWindowUpdates);

  // DATA
  data.Resume();
  data.RunUntilPaused();

  EXPECT_EQ(0, unacked_recv_window_bytes(stream));

  // FIN
  data.Resume();
  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
}

}  // namespace net::test

"""


```
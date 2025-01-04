Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for `QuicSpdyStream` in the Chromium network stack.

Here's a breakdown of the thought process:

1. **Identify the Core Class Under Test:** The code snippet uses `QuicSpdyStreamTest`, indicating that the primary focus is testing the `QuicSpdyStream` class.

2. **Recognize the Testing Framework:**  The use of `TEST_P`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_CALL`, `EXPECT_QUIC_BUG`, and `EXPECT_THAT` points to Google Test. This means the code consists of individual test cases for different aspects of `QuicSpdyStream`'s behavior.

3. **Analyze Individual Test Cases:** Go through each `TEST_P` block and summarize its purpose. Look for the actions being performed on the `stream_` object and the expectations being set.

    * **`WriteTrailersFailsIfFinSent`:** Checks that attempting to write trailers after sending a FIN (end-of-stream) results in a specific error.
    * **`HeaderStreamNotiferCorrespondingSpdyStream`:**  Tests the interaction between the headers stream and regular data streams, specifically focusing on acknowledgement (ACK) and retransmission of data. It seems to verify that ACKs for headers and data on different streams are handled correctly.
    * **`OnPriorityFrame`:** Verifies that setting the stream priority using `OnPriorityFrame` updates the internal priority representation.
    * **`OnPriorityFrameAfterSendingData`:** Similar to the previous test, but checks if setting priority after sending data works correctly.
    * **`SetPriorityBeforeUpdateStreamPriority`:** This test delves into the internal mechanism of how priority changes are propagated to the session. It involves setting up a mock session and verifying that `SetPriority` on the stream eventually calls `UpdateStreamPriority` on the session.
    * **`StreamWaitsForAcks`:**  Checks the logic for tracking whether the stream is waiting for acknowledgements of sent data, and how sending and acknowledging data and FIN affect this state.
    * **`StreamDataGetAckedMultipleTimes`:**  Tests the scenario where different segments of the same sent data are acknowledged at different times, ensuring correct handling of acknowledgements.
    * **`HeadersAckNotReportedWriteOrBufferBody` (HTTP/3 only):** For HTTP/3, this checks that when using `WriteOrBufferBody`, acknowledgements are based on the data frame, not the preceding headers frame.
    * **`HeadersAckNotReportedWriteBodySlices` (HTTP/3 only):** Similar to the previous test but uses `WriteBodySlices`.
    * **`HeaderBytesNotReportedOnRetransmission` (HTTP/3 only):**  For HTTP/3, verifies that when retransmitting data, only the data payload length is reported, not the headers frame overhead.
    * **`HeadersFrameOnRequestStream` (HTTP/3 only):** Tests receiving a stream frame containing headers, data, and trailers, and verifies they are correctly parsed.
    * **`ProcessBodyAfterTrailers` (HTTP/3 only):** Checks the scenario where data is processed after trailers have been received and consumed, ensuring buffer management is correct.
    * **`MalformedHeadersStopHttpDecoder` (HTTP/3 only):**  Tests how the stream handles malformed headers, expecting the connection to be closed with a specific error.
    * **`DoNotMarkConsumedAfterQpackDecodingError` (HTTP/3 only):** Checks that if a QPACK decoding error occurs during header processing, the sequencer's consumed pointer isn't incorrectly advanced.
    * **`ImmediateHeaderDecodingWithDynamicTableEntries` (HTTP/3 only):** Tests immediate decoding of headers and trailers when the referenced dynamic table entries are already available.
    * **`BlockedHeaderDecoding` (HTTP/3 only):** Tests the scenario where header decoding is blocked because a referenced dynamic table entry is not yet available, and verifies the decoding happens correctly once the entry arrives.
    * **`BlockedHeaderDecodingAndStopReading` (HTTP/3 only):** Checks what happens when header decoding is blocked and the stream is stopped from reading further. It seems to test different behaviors based on a reloadable flag.
    * **`AsyncErrorDecodingHeaders` (HTTP/3 only):** Tests a scenario where a header decoding error occurs asynchronously after the full header block is received, due to an incorrect Required Insert Count.
    * **`BlockedHeaderDecodingUnblockedWithBufferedError` (HTTP/3 only):**  Tests a scenario where a decoding error is buffered, and the arrival of a dynamic table entry triggers the error handling.
    * **`AsyncErrorDecodingTrailers` (HTTP/3 only):** Similar to `AsyncErrorDecodingHeaders`, but for trailers.

4. **Identify Common Themes and Functionality:** Group the individual test cases based on the aspects of `QuicSpdyStream` they are testing. This leads to identifying the following functionalities:

    * **Sending and Receiving Data:** Including handling of FIN, trailers, and buffering.
    * **Header and Trailer Processing (HTTP/3 Specific):**  Focusing on QPACK encoding and decoding, including immediate and blocked decoding, and error handling.
    * **Stream Prioritization:** Setting and propagating stream priorities.
    * **Acknowledgement and Retransmission Handling:**  Tracking which data has been acknowledged and handling retransmissions.
    * **Error Handling:**  Specifically related to malformed headers and QPACK decoding errors.

5. **Address Specific Questions:**

    * **Relationship with JavaScript:**  Since this is low-level network code in C++, it doesn't directly interact with JavaScript in the browser's rendering engine. However, it's a crucial part of the underlying network stack that enables JavaScript to make HTTP requests. Example: A `fetch()` call in JavaScript triggers network requests handled by this kind of code.
    * **Logical Reasoning (Input/Output):** For tests involving data sending and receiving, the input is the data written to the stream, and the expected output is the behavior of the stream (e.g., whether it's waiting for ACKs). For error scenarios, the input is malformed data, and the expected output is a connection closure or stream reset.
    * **User/Programming Errors:** Examples include trying to write trailers after sending FIN, or providing malformed header data.
    * **User Operations and Debugging:** User actions like browsing a website trigger HTTP requests, which eventually lead to this code being executed. Debugging might involve inspecting stream states, frame contents, and QPACK decoder states.

6. **Synthesize the Summary:** Combine the identified functionalities and address the specific questions in a concise summary, keeping in mind that this is part 3 of a 5-part file. Since this part heavily focuses on more advanced features like trailers, priority, and especially HTTP/3 header/trailer handling with QPACK, highlight these aspects. Acknowledge the earlier parts likely covered basic stream operations.
这是Chromium网络栈中 `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream_test.cc` 文件的第三部分，它主要专注于测试 `QuicSpdyStream` 类的更高级功能，尤其是在 HTTP/3 上下文中的行为。 基于提供的代码片段，我们可以归纳出以下功能：

**核心功能归纳 (基于提供的第3部分代码片段):**

* **测试 Trailers 的发送限制:** 验证在已经发送 FIN (表示流结束) 之后，尝试发送 Trailers 会失败并触发断言 (BUG)。
* **测试 Headers Stream 的通知机制:**  在非 HTTP/3 的情况下，测试当主请求流 (Spdy Stream) 发送数据时，关联的 Headers Stream 也会收到通知，并且 ACK 机制可以正确地追踪两个流的数据包。这部分测试了不同流之间的协作和依赖关系。
* **测试优先级帧 (Priority Frame) 的处理:** 验证 `QuicSpdyStream` 可以正确处理 `PRIORITY` 帧，并更新其内部的优先级表示。同时测试在发送数据后接收到优先级帧的情况。
* **测试设置优先级与会话更新的交互:** 验证在 `QuicSpdyStream` 中设置优先级会最终调用会话的 `UpdateStreamPriority` 方法，并确保在 `UpdateStreamPriority` 调用期间查询流的优先级能返回更新后的值。
* **测试流等待 ACK 的状态管理:** 验证 `QuicSpdyStream` 能正确跟踪发送的数据是否已被对端 ACK。测试了发送数据、FIN 以及数据包重传和 ACK 的场景，确保 `IsWaitingForAcks()` 方法返回正确的状态。
* **测试数据包被多次 ACK 的处理:**  验证即使同一段数据被多次确认，`QuicSpdyStream` 也能正确处理 ACK 信息，并更新已确认的数据范围。
* **(HTTP/3 Only) 测试 `WriteOrBufferBody` 不报告头部 ACK:** 在 HTTP/3 下，测试使用 `WriteOrBufferBody` 发送数据时，ACK 是基于 Data Frame 的，而不是之前的 Headers Frame。
* **(HTTP/3 Only) 测试 `WriteBodySlices` 不报告头部 ACK:** 类似于上一个测试，但使用 `WriteBodySlices` 方法发送数据。
* **(HTTP/3 Only) 测试重传时不报告头部字节:** 验证在 HTTP/3 中，当数据包重传时，只报告数据负载的长度，不包含头部帧的长度。
* **(HTTP/3 Only) 测试请求流上的 HEADERS 帧:** 验证 `QuicSpdyStream` 可以正确处理包含 Headers Frame、Data Frame 和 Trailers Frame 的单个 Stream Frame。
* **(HTTP/3 Only) 测试在 Trailers 之后处理 Body:** 测试在接收并消费 Trailers 后，仍然可以处理后续的 Body 数据，验证了流处理的完整性。
* **(HTTP/3 Only) 测试畸形头部导致 HTTP 解码器停止处理:** 验证当接收到包含畸形头部数据的 Stream Frame 时，HTTP 解码器会停止处理，并导致连接关闭。
* **(HTTP/3 Only) 测试 QPACK 解码错误后不标记为已消费:** 这是一个回归测试，确保在 QPACK 解码头部失败导致连接关闭时，`QuicStreamSequencer::MarkConsumed()` 不会被错误地调用。
* **(HTTP/3 Only) 测试使用动态表项立即解码头部:** 验证当 QPACK 动态表中存在被引用的条目时，`QuicSpdyStream` 可以立即解码收到的头部。
* **(HTTP/3 Only) 测试阻塞的头部解码:** 验证当收到的头部引用了尚未收到的 QPACK 动态表条目时，头部解码会被阻塞，并在收到相应的动态表条目后恢复解码。
* **(HTTP/3 Only) 测试阻塞的头部解码和停止读取:** 测试在头部解码被阻塞的情况下调用 `StopReading()` 会发生什么。根据 `quic_stop_reading_also_stops_header_decompression` 这个 reloadable flag 的设置，可能会或可能不会继续解码。
* **(HTTP/3 Only) 测试异步错误解码头部:** 验证即使完整的头部块已经收到，但由于 `Required Insert Count` 的不匹配，头部解码仍然会异步失败并导致连接关闭。
* **(HTTP/3 Only) 测试阻塞的头部解码被缓冲错误解除阻塞:** 测试当一个头部解码错误被缓冲时，收到一个 QPACK 动态表条目会导致错误被触发。
* **(HTTP/3 Only) 测试异步错误解码 Trailers:** 类似于异步错误解码头部，但针对的是 Trailers 的解码。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的网络栈功能是 Web 浏览器与服务器进行 HTTP/3 通信的基础。当 JavaScript 代码 (例如使用 `fetch` API) 发起网络请求时，底层的 Chromium 网络栈会使用 `QuicSpdyStream` 来处理这些请求和响应的 HTTP/3 流。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` 发送一个带有自定义头部和 Trailer 的 HTTP/3 请求：

```javascript
fetch('https://example.com/data', {
  headers: {
    'X-Custom-Header': 'value1'
  },
  // ... 其他 fetch 参数
}).then(response => {
  console.log(response.headers.get('X-Custom-Header')); // 获取头部
  return response.text();
}).then(data => {
  console.log(data); // 获取 body 数据
  return response.trailer.get('X-Custom-Trailer'); // 获取 trailer (需要浏览器支持)
}).then(trailerValue => {
  console.log(trailerValue);
});
```

在这个过程中，`QuicSpdyStream` 的功能会被用于：

1. **发送请求头部:**  JavaScript 的 `headers` 对象会被转换为 HTTP/3 的 HEADERS 帧，由 `QuicSpdyStream` 发送。相关的测试例如 `HeadersFrameOnRequestStream` 验证了接收端对这些帧的解析。
2. **发送请求体:** 如果请求包含 body，会被分割成 DATA 帧，由 `QuicSpdyStream` 发送。
3. **发送 Trailers:**  虽然 `fetch` API 对发送 Trailers 的支持可能有限，但如果支持，`QuicSpdyStream` 会负责将其转换为 HTTP/3 的 HEADERS 帧发送。 `WriteTrailersFailsIfFinSent` 等测试了 Trailers 的发送限制。
4. **接收响应头部:** 服务器发送的 HTTP/3 HEADERS 帧会被 `QuicSpdyStream` 接收并解析，最终通过 `response.headers` 提供给 JavaScript。`ImmediateHeaderDecodingWithDynamicTableEntries` 和 `BlockedHeaderDecoding` 等测试了头部解码的各种情况。
5. **接收响应体:** 服务器发送的 DATA 帧会被 `QuicSpdyStream` 接收，并通过 `response.text()` 或 `response.blob()` 等方法提供给 JavaScript。
6. **接收 Trailers:** 服务器发送的 Trailers (HTTP/3 HEADERS 帧) 会被 `QuicSpdyStream` 接收并解析，虽然目前 JavaScript 的 `fetch` API 对 Trailer 的支持还在发展中。 `AsyncErrorDecodingTrailers` 等测试了 Trailer 解码的错误处理。
7. **处理优先级:**  浏览器可能会根据资源的类型设置 HTTP/3 流的优先级，`OnPriorityFrame` 相关的测试验证了 `QuicSpdyStream` 对优先级帧的处理。

**逻辑推理 (假设输入与输出):**

**例子 1: `WriteTrailersFailsIfFinSent`**

* **假设输入:**  一个 `QuicSpdyStream` 对象已经发送了 FIN 帧。
* **预期输出:** 调用 `WriteTrailers` 方法会触发一个 `EXPECT_QUIC_BUG` 断言，表明 Trailers 无法在 FIN 之后发送。

**例子 2: `StreamWaitsForAcks`**

* **假设输入:**  一个 `QuicSpdyStream` 对象发送了一段数据 "FooAndBar"。
* **预期输出:** `IsWaitingForAcks()` 方法返回 `true`，因为数据正在等待对端的 ACK。当收到对该数据的 ACK 后，`IsWaitingForAcks()` 应该返回 `false`。

**用户或编程常见的使用错误:**

* **在发送 FIN 后尝试发送 Trailers:**  这是一个常见的编程错误，因为 HTTP 协议规定 Trailers 必须在 Body 之后、FIN 之前发送。`WriteTrailersFailsIfFinSent` 测试就覆盖了这种情况。
* **提供格式错误的头部数据:**  如果服务器或客户端生成了不符合 HTTP/3 或 QPACK 规范的头部数据，会导致解码错误，如 `MalformedHeadersStopHttpDecoder` 和相关的 QPACK 解码错误测试所覆盖的情况。
* **依赖于头部 ACK 而不是数据 ACK (HTTP/3):** 在 HTTP/3 中，ACK 主要针对 Data Frame。如果代码逻辑错误地期望 Headers Frame 被单独 ACK，可能会导致问题。`HeadersAckNotReportedWriteOrBufferBody` 测试强调了这一点。

**用户操作如何到达这里 (调试线索):**

1. **用户在浏览器中访问一个支持 HTTP/3 的网站。**
2. **浏览器发起 HTTP/3 连接并创建一个 `QuicSession` 对象。**
3. **当需要发送 HTTP 请求时 (例如加载网页上的资源)，会创建一个 `QuicSpdyStream` 对象。**
4. **如果请求包含自定义头部或需要发送 Trailers，相关的头部和 Trailer 数据会被传递给 `QuicSpdyStream` 进行处理。**
5. **如果服务端返回的响应包含头部、Body 和 Trailers，`QuicSpdyStream` 会负责接收和解析这些数据。**
6. **如果在这个过程中，接收到的头部数据格式错误，或者发生了 QPACK 解码错误，就会触发 `MalformedHeadersStopHttpDecoder` 或相关的错误处理逻辑。**
7. **调试时，可以检查 `QuicSpdyStream` 的状态，例如是否正在等待 ACK，已发送和接收的数据量，以及 QPACK 解码器的状态。** 可以通过 Chromium 提供的网络调试工具 (例如 `net-internals`) 查看 HTTP/3 连接的详细信息，包括帧的发送和接收。

**总结第3部分的功能:**

这部分 `QuicSpdyStreamTest` 文件主要集中在测试 `QuicSpdyStream` 类在处理 **HTTP/3 特有的功能** 以及更**高级的流控制和数据确认机制**方面的行为。它涵盖了 Trailers 的发送限制、与 Headers Stream 的交互、优先级处理、数据 ACK 跟踪的各种场景，以及对 HTTP/3 中头部和 Trailers 进行编码和解码的各种情况，包括成功的解码、阻塞的解码以及发生错误时的处理。特别是对 QPACK 编码和解码的测试占据了很大的篇幅。 这部分测试对于确保 HTTP/3 连接的可靠性和正确性至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
LL(*stream_, WriteHeadersMock(true));
  stream_->WriteHeaders(HttpHeaderBlock(), /*fin=*/true, nullptr);
  EXPECT_TRUE(stream_->fin_sent());

  // Writing Trailers should fail, as the FIN has already been sent.
  // populated with the number of body bytes written.
  EXPECT_QUIC_BUG(stream_->WriteTrailers(HttpHeaderBlock(), nullptr),
                  "Trailers cannot be sent after a FIN");
}

TEST_P(QuicSpdyStreamTest, HeaderStreamNotiferCorrespondingSpdyStream) {
  // There is no headers stream if QPACK is used.
  if (UsesHttp3()) {
    return;
  }

  const char kHeader1[] = "Header1";
  const char kHeader2[] = "Header2";
  const char kBody1[] = "Test1";
  const char kBody2[] = "Test2";

  Initialize(kShouldProcessData);
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(AtLeast(1));
  testing::InSequence s;
  quiche::QuicheReferenceCountedPointer<MockAckListener> ack_listener1(
      new MockAckListener());
  quiche::QuicheReferenceCountedPointer<MockAckListener> ack_listener2(
      new MockAckListener());
  stream_->set_ack_listener(ack_listener1);
  stream2_->set_ack_listener(ack_listener2);

  session_->headers_stream()->WriteOrBufferData(kHeader1, false, ack_listener1);
  stream_->WriteOrBufferBody(kBody1, true);

  session_->headers_stream()->WriteOrBufferData(kHeader2, false, ack_listener2);
  stream2_->WriteOrBufferBody(kBody2, false);

  QuicStreamFrame frame1(
      QuicUtils::GetHeadersStreamId(connection_->transport_version()), false, 0,
      kHeader1);

  std::string data1 = UsesHttp3() ? DataFrame(kBody1) : kBody1;
  QuicStreamFrame frame2(stream_->id(), true, 0, data1);
  QuicStreamFrame frame3(
      QuicUtils::GetHeadersStreamId(connection_->transport_version()), false, 7,
      kHeader2);
  std::string data2 = UsesHttp3() ? DataFrame(kBody2) : kBody2;
  QuicStreamFrame frame4(stream2_->id(), false, 0, data2);

  EXPECT_CALL(*ack_listener1, OnPacketRetransmitted(7));
  session_->OnStreamFrameRetransmitted(frame1);

  EXPECT_CALL(*ack_listener1, OnPacketAcked(7, _));
  EXPECT_TRUE(session_->OnFrameAcked(QuicFrame(frame1), QuicTime::Delta::Zero(),
                                     QuicTime::Zero()));
  EXPECT_CALL(*ack_listener1, OnPacketAcked(5, _));
  EXPECT_TRUE(session_->OnFrameAcked(QuicFrame(frame2), QuicTime::Delta::Zero(),
                                     QuicTime::Zero()));
  EXPECT_CALL(*ack_listener2, OnPacketAcked(7, _));
  EXPECT_TRUE(session_->OnFrameAcked(QuicFrame(frame3), QuicTime::Delta::Zero(),
                                     QuicTime::Zero()));
  EXPECT_CALL(*ack_listener2, OnPacketAcked(5, _));
  EXPECT_TRUE(session_->OnFrameAcked(QuicFrame(frame4), QuicTime::Delta::Zero(),
                                     QuicTime::Zero()));
}

TEST_P(QuicSpdyStreamTest, OnPriorityFrame) {
  Initialize(kShouldProcessData);
  stream_->OnPriorityFrame(spdy::SpdyStreamPrecedence(kV3HighestPriority));
  EXPECT_EQ(QuicStreamPriority(HttpStreamPriority{
                kV3HighestPriority, HttpStreamPriority::kDefaultIncremental}),
            stream_->priority());
}

TEST_P(QuicSpdyStreamTest, OnPriorityFrameAfterSendingData) {
  Initialize(kShouldProcessData);
  testing::InSequence seq;

  if (UsesHttp3()) {
    EXPECT_CALL(*session_, WritevData(_, 2, _, NO_FIN, _, _));
  }
  EXPECT_CALL(*session_, WritevData(_, 4, _, FIN, _, _));
  stream_->WriteOrBufferBody("data", true);
  stream_->OnPriorityFrame(spdy::SpdyStreamPrecedence(kV3HighestPriority));
  EXPECT_EQ(QuicStreamPriority(HttpStreamPriority{
                kV3HighestPriority, HttpStreamPriority::kDefaultIncremental}),
            stream_->priority());
}

TEST_P(QuicSpdyStreamTest, SetPriorityBeforeUpdateStreamPriority) {
  MockQuicConnection* connection = new StrictMock<MockQuicConnection>(
      &helper_, &alarm_factory_, Perspective::IS_SERVER,
      SupportedVersions(GetParam()));
  std::unique_ptr<TestMockUpdateStreamSession> session(
      new StrictMock<TestMockUpdateStreamSession>(connection));
  auto stream =
      new StrictMock<TestStream>(GetNthClientInitiatedBidirectionalStreamId(
                                     session->transport_version(), 0),
                                 session.get(),
                                 /*should_process_data=*/true);
  session->ActivateStream(absl::WrapUnique(stream));

  // QuicSpdyStream::SetPriority() should eventually call UpdateStreamPriority()
  // on the session. Make sure stream->priority() returns the updated priority
  // if called within UpdateStreamPriority(). This expectation is enforced in
  // TestMockUpdateStreamSession::UpdateStreamPriority().
  session->SetExpectedStream(stream);
  session->SetExpectedPriority(HttpStreamPriority{kV3HighestPriority});
  stream->SetPriority(
      QuicStreamPriority(HttpStreamPriority{kV3HighestPriority}));

  session->SetExpectedPriority(HttpStreamPriority{kV3LowestPriority});
  stream->SetPriority(
      QuicStreamPriority(HttpStreamPriority{kV3LowestPriority}));
}

TEST_P(QuicSpdyStreamTest, StreamWaitsForAcks) {
  Initialize(kShouldProcessData);
  quiche::QuicheReferenceCountedPointer<MockAckListener> mock_ack_listener(
      new StrictMock<MockAckListener>);
  stream_->set_ack_listener(mock_ack_listener);
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(AtLeast(1));
  // Stream is not waiting for acks initially.
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());

  // Send kData1.
  stream_->WriteOrBufferData("FooAndBar", false, nullptr);
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(9, _));
  QuicByteCount newly_acked_length = 0;
  EXPECT_TRUE(stream_->OnStreamFrameAcked(0, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  // Stream is not waiting for acks as all sent data is acked.
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());

  // Send kData2.
  stream_->WriteOrBufferData("FooAndBar", false, nullptr);
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  // Send FIN.
  stream_->WriteOrBufferData("", true, nullptr);
  // Fin only frame is not stored in send buffer.
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());

  // kData2 is retransmitted.
  EXPECT_CALL(*mock_ack_listener, OnPacketRetransmitted(9));
  stream_->OnStreamFrameRetransmitted(9, 9, false);

  // kData2 is acked.
  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(9, _));
  EXPECT_TRUE(stream_->OnStreamFrameAcked(9, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  // Stream is waiting for acks as FIN is not acked.
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());

  // FIN is acked.
  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(0, _));
  EXPECT_TRUE(stream_->OnStreamFrameAcked(18, 0, true, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
}

TEST_P(QuicSpdyStreamTest, StreamDataGetAckedMultipleTimes) {
  Initialize(kShouldProcessData);
  quiche::QuicheReferenceCountedPointer<MockAckListener> mock_ack_listener(
      new StrictMock<MockAckListener>);
  stream_->set_ack_listener(mock_ack_listener);
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(AtLeast(1));
  // Send [0, 27) and fin.
  stream_->WriteOrBufferData("FooAndBar", false, nullptr);
  stream_->WriteOrBufferData("FooAndBar", false, nullptr);
  stream_->WriteOrBufferData("FooAndBar", true, nullptr);

  // Ack [0, 9), [5, 22) and [18, 26)
  // Verify [0, 9) 9 bytes are acked.
  QuicByteCount newly_acked_length = 0;
  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(9, _));
  EXPECT_TRUE(stream_->OnStreamFrameAcked(0, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(2u, QuicStreamPeer::SendBuffer(stream_).size());
  // Verify [9, 22) 13 bytes are acked.
  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(13, _));
  EXPECT_TRUE(stream_->OnStreamFrameAcked(5, 17, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  // Verify [22, 26) 4 bytes are acked.
  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(4, _));
  EXPECT_TRUE(stream_->OnStreamFrameAcked(18, 8, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->IsWaitingForAcks());

  // Ack [0, 27).
  // Verify [26, 27) 1 byte is acked.
  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(1, _));
  EXPECT_TRUE(stream_->OnStreamFrameAcked(26, 1, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->IsWaitingForAcks());

  // Ack Fin. Verify OnPacketAcked is called.
  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(0, _));
  EXPECT_TRUE(stream_->OnStreamFrameAcked(27, 0, true, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_FALSE(stream_->IsWaitingForAcks());

  // Ack [10, 27) and fin.
  // No new data is acked, verify OnPacketAcked is not called.
  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(_, _)).Times(0);
  EXPECT_FALSE(
      stream_->OnStreamFrameAcked(10, 17, true, QuicTime::Delta::Zero(),
                                  QuicTime::Zero(), &newly_acked_length));
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_FALSE(stream_->IsWaitingForAcks());
}

// HTTP/3 only.
TEST_P(QuicSpdyStreamTest, HeadersAckNotReportedWriteOrBufferBody) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  quiche::QuicheReferenceCountedPointer<MockAckListener> mock_ack_listener(
      new StrictMock<MockAckListener>);
  stream_->set_ack_listener(mock_ack_listener);
  std::string body = "Test1";
  std::string body2(100, 'x');

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(AtLeast(1));
  stream_->WriteOrBufferBody(body, false);
  stream_->WriteOrBufferBody(body2, true);

  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body.length(), quiche::SimpleBufferAllocator::Get());
  quiche::QuicheBuffer header2 = HttpEncoder::SerializeDataFrameHeader(
      body2.length(), quiche::SimpleBufferAllocator::Get());

  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(body.length(), _));
  QuicStreamFrame frame(stream_->id(), false, 0,
                        absl::StrCat(header.AsStringView(), body));
  EXPECT_TRUE(session_->OnFrameAcked(QuicFrame(frame), QuicTime::Delta::Zero(),
                                     QuicTime::Zero()));

  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(0, _));
  QuicStreamFrame frame2(stream_->id(), false, header.size() + body.length(),
                         header2.AsStringView());
  EXPECT_TRUE(session_->OnFrameAcked(QuicFrame(frame2), QuicTime::Delta::Zero(),
                                     QuicTime::Zero()));

  EXPECT_CALL(*mock_ack_listener, OnPacketAcked(body2.length(), _));
  QuicStreamFrame frame3(stream_->id(), true,
                         header.size() + body.length() + header2.size(), body2);
  EXPECT_TRUE(session_->OnFrameAcked(QuicFrame(frame3), QuicTime::Delta::Zero(),
                                     QuicTime::Zero()));

  EXPECT_TRUE(
      QuicSpdyStreamPeer::unacked_frame_headers_offsets(stream_).Empty());
}

// HTTP/3 only.
TEST_P(QuicSpdyStreamTest, HeadersAckNotReportedWriteBodySlices) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  quiche::QuicheReferenceCountedPointer<MockAckListener> mock_ack_listener(
      new StrictMock<MockAckListener>);
  stream_->set_ack_listener(mock_ack_listener);
  std::string body1 = "Test1";
  std::string body2(100, 'x');
  struct iovec body1_iov = {const_cast<char*>(body1.data()), body1.length()};
  struct iovec body2_iov = {const_cast<char*>(body2.data()), body2.length()};
  quiche::QuicheMemSliceStorage storage(
      &body1_iov, 1, helper_.GetStreamSendBufferAllocator(), 1024);
  quiche::QuicheMemSliceStorage storage2(
      &body2_iov, 1, helper_.GetStreamSendBufferAllocator(), 1024);
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(AtLeast(1));
  stream_->WriteBodySlices(storage.ToSpan(), false);
  stream_->WriteBodySlices(storage2.ToSpan(), true);

  std::string data1 = DataFrame(body1);
  std::string data2 = DataFrame(body2);

  EXPECT_CALL(*mock_ack_listener,
              OnPacketAcked(body1.length() + body2.length(), _));
  QuicStreamFrame frame(stream_->id(), true, 0, data1 + data2);
  EXPECT_TRUE(session_->OnFrameAcked(QuicFrame(frame), QuicTime::Delta::Zero(),
                                     QuicTime::Zero()));

  EXPECT_TRUE(
      QuicSpdyStreamPeer::unacked_frame_headers_offsets(stream_).Empty());
}

// HTTP/3 only.
TEST_P(QuicSpdyStreamTest, HeaderBytesNotReportedOnRetransmission) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  quiche::QuicheReferenceCountedPointer<MockAckListener> mock_ack_listener(
      new StrictMock<MockAckListener>);
  stream_->set_ack_listener(mock_ack_listener);
  std::string body1 = "Test1";
  std::string body2(100, 'x');

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(AtLeast(1));
  stream_->WriteOrBufferBody(body1, false);
  stream_->WriteOrBufferBody(body2, true);

  std::string data1 = DataFrame(body1);
  std::string data2 = DataFrame(body2);

  EXPECT_CALL(*mock_ack_listener, OnPacketRetransmitted(body1.length()));
  QuicStreamFrame frame(stream_->id(), false, 0, data1);
  session_->OnStreamFrameRetransmitted(frame);

  EXPECT_CALL(*mock_ack_listener, OnPacketRetransmitted(body2.length()));
  QuicStreamFrame frame2(stream_->id(), true, data1.length(), data2);
  session_->OnStreamFrameRetransmitted(frame2);

  EXPECT_FALSE(
      QuicSpdyStreamPeer::unacked_frame_headers_offsets(stream_).Empty());
}

TEST_P(QuicSpdyStreamTest, HeadersFrameOnRequestStream) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);

  std::string headers = HeadersFrame({std::make_pair("foo", "bar")});
  std::string data = DataFrame(kDataFramePayload);
  std::string trailers =
      HeadersFrame({std::make_pair("custom-key", "custom-value")});

  std::string stream_frame_payload = absl::StrCat(headers, data, trailers);
  QuicStreamFrame frame(stream_->id(), false, 0, stream_frame_payload);
  stream_->OnStreamFrame(frame);

  EXPECT_THAT(stream_->header_list(), ElementsAre(Pair("foo", "bar")));

  // QuicSpdyStream only calls OnBodyAvailable()
  // after the header list has been consumed.
  EXPECT_EQ("", stream_->data());
  stream_->ConsumeHeaderList();
  EXPECT_EQ(kDataFramePayload, stream_->data());

  EXPECT_THAT(stream_->received_trailers(),
              ElementsAre(Pair("custom-key", "custom-value")));
}

TEST_P(QuicSpdyStreamTest, ProcessBodyAfterTrailers) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(!kShouldProcessData);

  std::string headers = HeadersFrame({std::make_pair("foo", "bar")});
  std::string data = DataFrame(kDataFramePayload);

  // A header block that will take more than one block of sequencer buffer.
  // This ensures that when the trailers are consumed, some buffer buckets will
  // be freed.
  HttpHeaderBlock trailers_block;
  trailers_block["key1"] = std::string(10000, 'x');
  std::string trailers = HeadersFrame(trailers_block);

  // Feed all three HTTP/3 frames in a single stream frame.
  std::string stream_frame_payload = absl::StrCat(headers, data, trailers);
  QuicStreamFrame frame(stream_->id(), false, 0, stream_frame_payload);
  stream_->OnStreamFrame(frame);

  stream_->ConsumeHeaderList();
  stream_->MarkTrailersConsumed();

  EXPECT_TRUE(stream_->trailers_decompressed());
  EXPECT_EQ(trailers_block, stream_->received_trailers());

  EXPECT_TRUE(stream_->HasBytesToRead());

  // Consume data.
  char buffer[2048];
  struct iovec vec;
  vec.iov_base = buffer;
  vec.iov_len = ABSL_ARRAYSIZE(buffer);
  size_t bytes_read = stream_->Readv(&vec, 1);
  EXPECT_EQ(kDataFramePayload, absl::string_view(buffer, bytes_read));

  EXPECT_FALSE(stream_->HasBytesToRead());
}

// The test stream will receive a stream frame containing malformed headers and
// normal body. Make sure the http decoder stops processing body after the
// connection shuts down.
TEST_P(QuicSpdyStreamTest, MalformedHeadersStopHttpDecoder) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  testing::InSequence s;
  connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));

  // Random bad headers.
  std::string headers_bytes;
  ASSERT_TRUE(absl::HexStringToBytes("00002a94e7036261", &headers_bytes));
  std::string headers = HeadersFrame(headers_bytes);
  std::string data = DataFrame(kDataFramePayload);

  std::string stream_frame_payload = absl::StrCat(headers, data);
  QuicStreamFrame frame(stream_->id(), false, 0, stream_frame_payload);

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_QPACK_DECOMPRESSION_FAILED,
                      MatchesRegex("Error decoding headers on stream \\d+: "
                                   "Incomplete header block."),
                      _))
      .WillOnce(
          (Invoke([this](QuicErrorCode error, const std::string& error_details,
                         ConnectionCloseBehavior connection_close_behavior) {
            connection_->ReallyCloseConnection(error, error_details,
                                               connection_close_behavior);
          })));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
  EXPECT_CALL(*session_, OnConnectionClosed(_, _))
      .WillOnce(Invoke([this](const QuicConnectionCloseFrame& frame,
                              ConnectionCloseSource source) {
        session_->ReallyOnConnectionClosed(frame, source);
      }));
  EXPECT_CALL(*session_, MaybeSendRstStreamFrame(_, _, _)).Times(2);
  stream_->OnStreamFrame(frame);
}

// Regression test for https://crbug.com/1027895: a HEADERS frame triggers an
// error in QuicSpdyStream::OnHeadersFramePayload().  This closes the
// connection, freeing the buffer of QuicStreamSequencer.  Therefore
// QuicStreamSequencer::MarkConsumed() must not be called from
// QuicSpdyStream::OnHeadersFramePayload().
TEST_P(QuicSpdyStreamTest, DoNotMarkConsumedAfterQpackDecodingError) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));

  {
    testing::InSequence s;
    EXPECT_CALL(
        *connection_,
        CloseConnection(QUIC_QPACK_DECOMPRESSION_FAILED,
                        MatchesRegex("Error decoding headers on stream \\d+: "
                                     "Invalid relative index."),
                        _))
        .WillOnce((
            Invoke([this](QuicErrorCode error, const std::string& error_details,
                          ConnectionCloseBehavior connection_close_behavior) {
              connection_->ReallyCloseConnection(error, error_details,
                                                 connection_close_behavior);
            })));
    EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
    EXPECT_CALL(*session_, OnConnectionClosed(_, _))
        .WillOnce(Invoke([this](const QuicConnectionCloseFrame& frame,
                                ConnectionCloseSource source) {
          session_->ReallyOnConnectionClosed(frame, source);
        }));
  }
  EXPECT_CALL(*session_, MaybeSendRstStreamFrame(stream_->id(), _, _));
  EXPECT_CALL(*session_, MaybeSendRstStreamFrame(stream2_->id(), _, _));

  // Invalid headers: Required Insert Count is zero, but the header block
  // contains a dynamic table reference.
  std::string headers_bytes;
  ASSERT_TRUE(absl::HexStringToBytes("000080", &headers_bytes));
  std::string headers = HeadersFrame(headers_bytes);
  QuicStreamFrame frame(stream_->id(), false, 0, headers);
  stream_->OnStreamFrame(frame);
}

TEST_P(QuicSpdyStreamTest, ImmediateHeaderDecodingWithDynamicTableEntries) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  testing::InSequence s;
  session_->qpack_decoder()->OnSetDynamicTableCapacity(1024);
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  // Deliver dynamic table entry to decoder.
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");

  EXPECT_EQ(std::nullopt, stream_->header_decoding_delay());

  // HEADERS frame referencing first dynamic table entry.
  std::string encoded_headers;
  ASSERT_TRUE(absl::HexStringToBytes("020080", &encoded_headers));
  std::string headers = HeadersFrame(encoded_headers);
  EXPECT_CALL(debug_visitor,
              OnHeadersFrameReceived(stream_->id(), encoded_headers.length()));
  EXPECT_CALL(debug_visitor, OnHeadersDecoded(stream_->id(), _));
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 0, headers));

  // Headers can be decoded immediately.
  EXPECT_TRUE(stream_->headers_decompressed());

  // Verify headers.
  EXPECT_THAT(stream_->header_list(), ElementsAre(Pair("foo", "bar")));
  stream_->ConsumeHeaderList();

  EXPECT_THAT(stream_->header_decoding_delay(),
              Optional(QuicTime::Delta::Zero()));

  // DATA frame.
  std::string data = DataFrame(kDataFramePayload);
  EXPECT_CALL(debug_visitor,
              OnDataFrameReceived(stream_->id(), kDataFramePayload.length()));
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, /* offset = */
                                         headers.length(), data));
  EXPECT_EQ(kDataFramePayload, stream_->data());

  // Deliver second dynamic table entry to decoder.
  session_->qpack_decoder()->OnInsertWithoutNameReference("trailing", "foobar");

  // Trailing HEADERS frame referencing second dynamic table entry.
  std::string encoded_trailers;
  ASSERT_TRUE(absl::HexStringToBytes("030080", &encoded_trailers));
  std::string trailers = HeadersFrame(encoded_trailers);
  EXPECT_CALL(debug_visitor,
              OnHeadersFrameReceived(stream_->id(), encoded_trailers.length()));
  // Header acknowledgement.
  EXPECT_CALL(debug_visitor, OnHeadersDecoded(stream_->id(), _));
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), true, /* offset = */
                                         headers.length() + data.length(),
                                         trailers));

  // Trailers can be decoded immediately.
  EXPECT_TRUE(stream_->trailers_decompressed());

  // Verify trailers.
  EXPECT_THAT(stream_->received_trailers(),
              ElementsAre(Pair("trailing", "foobar")));
  stream_->MarkTrailersConsumed();
}

TEST_P(QuicSpdyStreamTest, BlockedHeaderDecoding) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  testing::InSequence s;
  session_->qpack_decoder()->OnSetDynamicTableCapacity(1024);
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  // HEADERS frame referencing first dynamic table entry.
  std::string encoded_headers;
  ASSERT_TRUE(absl::HexStringToBytes("020080", &encoded_headers));
  std::string headers = HeadersFrame(encoded_headers);
  EXPECT_CALL(debug_visitor,
              OnHeadersFrameReceived(stream_->id(), encoded_headers.length()));
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 0, headers));

  // Decoding is blocked because dynamic table entry has not been received yet.
  EXPECT_FALSE(stream_->headers_decompressed());
  EXPECT_EQ(std::nullopt, stream_->header_decoding_delay());

  EXPECT_CALL(debug_visitor, OnHeadersDecoded(stream_->id(), _));

  const QuicTime::Delta delay = QuicTime::Delta::FromSeconds(1);
  helper_.GetClock()->AdvanceTime(delay);

  // Deliver dynamic table entry to decoder.
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");
  EXPECT_TRUE(stream_->headers_decompressed());

  // Verify headers.
  EXPECT_THAT(stream_->header_list(), ElementsAre(Pair("foo", "bar")));
  stream_->ConsumeHeaderList();

  EXPECT_THAT(stream_->header_decoding_delay(), Optional(delay));

  // DATA frame.
  std::string data = DataFrame(kDataFramePayload);
  EXPECT_CALL(debug_visitor,
              OnDataFrameReceived(stream_->id(), kDataFramePayload.length()));
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, /* offset = */
                                         headers.length(), data));
  EXPECT_EQ(kDataFramePayload, stream_->data());

  // Trailing HEADERS frame referencing second dynamic table entry.
  std::string encoded_trailers;
  ASSERT_TRUE(absl::HexStringToBytes("030080", &encoded_trailers));
  std::string trailers = HeadersFrame(encoded_trailers);
  EXPECT_CALL(debug_visitor,
              OnHeadersFrameReceived(stream_->id(), encoded_trailers.length()));
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), true, /* offset = */
                                         headers.length() + data.length(),
                                         trailers));

  // Decoding is blocked because dynamic table entry has not been received yet.
  EXPECT_FALSE(stream_->trailers_decompressed());

  EXPECT_CALL(debug_visitor, OnHeadersDecoded(stream_->id(), _));
  // Deliver second dynamic table entry to decoder.
  session_->qpack_decoder()->OnInsertWithoutNameReference("trailing", "foobar");
  EXPECT_TRUE(stream_->trailers_decompressed());

  // Verify trailers.
  EXPECT_THAT(stream_->received_trailers(),
              ElementsAre(Pair("trailing", "foobar")));
  stream_->MarkTrailersConsumed();
}

TEST_P(QuicSpdyStreamTest, BlockedHeaderDecodingAndStopReading) {
  if (!UsesHttp3()) {
    return;
  }
  Initialize(kShouldProcessData);
  testing::InSequence s;
  session_->qpack_decoder()->OnSetDynamicTableCapacity(1024);
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  // HEADERS frame referencing first dynamic table entry.
  std::string encoded_headers;
  ASSERT_TRUE(absl::HexStringToBytes("020080", &encoded_headers));
  std::string headers = HeadersFrame(encoded_headers);
  EXPECT_CALL(debug_visitor,
              OnHeadersFrameReceived(stream_->id(), encoded_headers.length()));
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 0, headers));

  // Decoding is blocked because dynamic table entry has not been received yet.
  EXPECT_FALSE(stream_->headers_decompressed());

  if (GetQuicReloadableFlag(
          quic_stop_reading_also_stops_header_decompression)) {
    EXPECT_CALL(debug_visitor, OnHeadersDecoded(stream_->id(), _)).Times(0);
  }
  // Stop reading from now on. Any buffered compressed headers shouldn't be
  // decompressed and delivered up.
  stream_->StopReading();

  if (!GetQuicReloadableFlag(
          quic_stop_reading_also_stops_header_decompression)) {
    EXPECT_CALL(debug_visitor, OnHeadersDecoded(stream_->id(), _));
  }
  // Deliver dynamic table entry to decoder.
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");
  EXPECT_NE(
      GetQuicReloadableFlag(quic_stop_reading_also_stops_header_decompression),
      stream_->headers_decompressed());
}

TEST_P(QuicSpdyStreamTest, AsyncErrorDecodingHeaders) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  session_->qpack_decoder()->OnSetDynamicTableCapacity(1024);

  // HEADERS frame only referencing entry with absolute index 0 but with
  // Required Insert Count = 2, which is incorrect.
  std::string headers_bytes;
  ASSERT_TRUE(absl::HexStringToBytes("030081", &headers_bytes));
  std::string headers = HeadersFrame(headers_bytes);
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 0, headers));

  // Even though entire header block is received and every referenced entry is
  // available, decoding is blocked until insert count reaches the Required
  // Insert Count value advertised in the header block prefix.
  EXPECT_FALSE(stream_->headers_decompressed());

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_QPACK_DECOMPRESSION_FAILED,
                      MatchesRegex("Error decoding headers on stream \\d+: "
                                   "Required Insert Count too large."),
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));

  // Deliver two dynamic table entries to decoder
  // to trigger decoding of header block.
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");
}

// Regression test for https://crbug.com/1024263 and for
// https://crbug.com/1025209#c11.
TEST_P(QuicSpdyStreamTest, BlockedHeaderDecodingUnblockedWithBufferedError) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  session_->qpack_decoder()->OnSetDynamicTableCapacity(1024);

  // Relative index 2 is invalid because it is larger than or equal to the Base.
  std::string headers_bytes;
  ASSERT_TRUE(absl::HexStringToBytes("020082", &headers_bytes));
  std::string headers = HeadersFrame(headers_bytes);
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 0, headers));

  // Decoding is blocked.
  EXPECT_FALSE(stream_->headers_decompressed());

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_QPACK_DECOMPRESSION_FAILED,
                      MatchesRegex("Error decoding headers on stream \\d+: "
                                   "Invalid relative index."),
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));

  // Deliver one dynamic table entry to decoder
  // to trigger decoding of header block.
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");
}

TEST_P(QuicSpdyStreamTest, AsyncErrorDecodingTrailers) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  testing::InSequence s;
  session_->qpack_decoder()->OnSetDynamicTableCapacity(1024);

  // HEADERS frame referencing first dynamic table entry.
  std::string headers_bytes;
  ASSERT_TRUE(absl::HexStringToBytes("020080", &headers_bytes));
  std::string headers = HeadersFrame(headers_bytes);
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 0, headers));

  // Decoding is blocked because dynamic table entry has not been received yet.
  EXPECT_FALSE(stream_->headers_decompressed());

  // Deliver dynamic table entry to decoder.
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");
  EXPECT_TRUE(stream_->headers_decompressed());

  // Verify headers.
  EXPECT_THAT(stream_->header_list(), ElementsAre(Pair("foo", "bar")));
  stream_->ConsumeHeaderList();

  // DATA frame.
  std::string data = DataFrame(kDataFramePayload);
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, /* offset = */
                                         headers.length(), data));
  EXPECT_EQ(kDataFramePayload, stream_->data());

  // Trailing HEADERS frame only referencing entry with absolute index 0 but
  // with Required Insert Count = 2, which is incorrect.
  std::string trailers_bytes;
  ASSERT_TRUE(absl::HexStringToBytes("030081", &trailers_bytes));
  std::string trailers = HeadersFrame(trailers_bytes);
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), true, /* offset = */
                                         headers.length() + data.length(),
                                         trailers));

  // Even though entire header block is received and every referenced entry is
  // available, decoding is blocked until insert count reaches the Required
  // Insert Count value advertised in the header block prefix.
  EXPECT_FALSE(stream_->trailers_decompressed());

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_QPACK_DECOMPRESSION_FAILED,
                      MatchesRegex("Error decoding trailers on stream \\d+: "
                                   "Required Insert Count too large."),
            
"""


```
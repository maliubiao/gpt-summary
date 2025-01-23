Response:
The user wants me to analyze a C++ source code file related to the Chromium network stack, specifically `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream_test.cc`. They are asking for:

1. **Functionality:** A description of what the code does.
2. **Relation to JavaScript:** Whether the code interacts with JavaScript and how.
3. **Logic Reasoning:** Examples of input and output if the code performs logical operations.
4. **Common Usage Errors:** Examples of mistakes users or programmers might make when interacting with this code.
5. **User Journey for Debugging:**  A step-by-step explanation of how a user's actions might lead to this code being executed during debugging.
6. **Summary of Functionality (Part 4 of 5):** A concise summary of the code's purpose, considering it's part 4 of a larger analysis.

Let's break down the code section provided. This part of the test file focuses on:

- **Header Decoding Behavior:** Tests scenarios where header decoding is blocked due to missing dynamic table entries and how stream closure or resets affect this.
- **Incremental Data Consumption:**  Examines how the `QuicSpdyStream` consumes data incrementally, especially when dealing with different HTTP/3 frame types (HEADERS, DATA, unknown frames, METADATA). It tests how bytes are marked as consumed and how reading from the stream interacts with this process.
- **Error Handling:**  Tests how the stream handles invalid frame sequences (DATA before HEADERS, trailers after trailers, DATA after trailers) by closing the connection.
- **Connection Closure on Invalid Frames:** Tests the connection closing behavior when an unexpected SETTINGS frame is received on a bidirectional stream.
- **Stream Cancellation:** Verifies that stream cancellation instructions are sent to the QPACK decoder stream when a stream is reset (locally or remotely).
- **WriteHeaders Return Value:** Checks the return value of the `WriteHeaders` function.
- **Handling Multiple RST_STREAM Frames:** Tests how the stream reacts to receiving multiple RST_STREAM frames.
- **WebTransport Support:** Tests the handling of WebTransport headers (both incoming and outgoing) and the reception of WebTransport stream frames, including error handling for unsupported scenarios or padding.
- **HTTP Datagram Support:** Tests the reception and sending of HTTP datagrams, including registering and unregistering datagram visitors.

Considering this is part 4 of 5, it's likely focusing on more advanced or specific aspects of `QuicSpdyStream`'s behavior, building upon foundational concepts covered in earlier parts.

**Plan:**

1. Summarize the core functionalities demonstrated in this code block.
2. Address the JavaScript relationship - likely minimal to none directly.
3. Provide examples for logical reasoning if applicable.
4. Identify common usage errors in the context of this code.
5. Outline a potential user journey that leads to this code being relevant.
6. Synthesize a summary for part 4.
这是 `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream_test.cc` 文件的第四部分，主要测试 `QuicSpdyStream` 类在处理 HTTP/3 特有帧和一些复杂场景下的行为。以下是该部分代码的功能归纳：

**功能归纳：**

这部分测试主要关注以下几个方面：

1. **头部解码的阻塞和解除：**
   - 测试当收到引用 QPACK 动态表的 HEADERS 帧，但对应的动态表项尚未到达时，头部解码会被阻塞。
   - 测试在这种阻塞状态下，如果流被本地重置（例如，由于取消），或者收到对端的 RST_STREAM 帧，解码会被中止。
   - 测试当所需的动态表项最终到达时，头部解码可以被解除阻塞。

2. **数据帧的增量消费：**
   - 测试 `QuicSpdyStream` 如何逐步消费接收到的数据，特别是当涉及到不同类型的 HTTP/3 帧（HEADERS, DATA, Unknown Frame, METADATA Frame）时。
   - 验证在不同帧接收不完整的情况下，哪些字节会被立即标记为已消费，哪些需要等待。
   - 测试读取流数据 (`Readv`) 的操作如何触发数据的消费。

3. **处理未知帧和元数据帧：**
   - 测试当接收到未知类型的帧时，`QuicSpdyStream` 的行为，并通知调试访问器。
   - 测试当接收到不支持的元数据帧时，将其视为未知帧处理。
   - 测试当接收到支持的元数据帧时，调用注册的 `MetadataVisitor` 进行处理。
   - 测试在接收多个元数据帧的过程中，如果流被重置，处理流程是否正确。

4. **处理帧序列错误：**
   - 测试如果先收到 DATA 帧，后收到 HEADERS 帧，连接会被关闭。
   - 测试如果在发送完 Trailers 后又收到 HEADERS 帧，连接会被关闭。
   - 测试如果在发送完 Trailers 后又收到 DATA 帧，连接会被关闭。

5. **连接关闭时的行为：**
   - 测试如果在 HTTP/3 双向流上收到 SETTINGS 帧，连接会被关闭，并且后续的数据不会被处理。

6. **流取消时的行为：**
   - 测试当流被本地重置或者收到对端的 RST_STREAM 帧时，会向 QPACK 解码器流发送流取消指令。

7. **`WriteHeaders` 的返回值：**
   - 测试 `WriteHeaders` 方法的返回值，并验证其与实际写入的字节数的关系。

8. **处理多个 RST_STREAM 帧：**
   - 测试接收到多个 RST_STREAM 帧时的行为，特别是当第二个 RST_STREAM 帧的错误码为 `QUIC_STREAM_NO_ERROR` 时，不应该有特殊处理。

9. **WebTransport 支持：**
   - 测试处理外发的 WebTransport 头部（":method: CONNECT", ":protocol: webtransport"）。
   - 测试处理收到的 WebTransport 头部，并创建 `WebTransport` 对象。
   - 测试当对端不支持 WebTransport 时，收到 WebTransport 流帧的处理。
   - 测试接收到 WebTransport 流帧时，创建新的流。
   - 测试不同版本的 WebTransport 流帧格式（带 Padding）。

10. **HTTP Datagram 支持：**
    - 测试接收 HTTP Datagram 的功能，并将数据传递给注册的 `Http3DatagramVisitor`。
    - 测试发送 HTTP Datagram 的功能。
    - 测试在本地不支持 HTTP Datagram 的情况下尝试发送时的行为（会触发断言）。

**与 JavaScript 的关系：**

这个 C++ 文件本身与 JavaScript 没有直接的功能关系。但是，它测试的网络协议（HTTP/3 和 QUIC）是 Web 技术的基础，JavaScript 运行在浏览器环境中，会通过浏览器提供的 API（例如 `fetch` API，WebTransport API）来发起 HTTP/3 请求或建立 WebTransport 连接。

**举例说明：**

- 当 JavaScript 代码使用 `fetch` 发起一个 HTTP/3 请求时，浏览器底层会使用 QUIC 协议来传输数据。`QuicSpdyStream` 类负责处理这个请求对应的 QUIC 流上的 HTTP/3 帧。
- 当 JavaScript 代码使用 WebTransport API 建立连接时，`QuicSpdyStream` 会被用来处理 WebTransport 连接和相关的流。

**逻辑推理的假设输入与输出：**

**场景：头部解码被阻塞，然后接收到动态表项**

**假设输入：**

1. 收到一个 HEADERS 帧，其中编码的头部引用了 QPACK 动态表中的第一个条目（索引 64）。
2. 此时 QPACK 解码器的动态表为空，或者没有索引为 64 的条目。
3. 随后，收到 QPACK 编码器流发送的指令，向动态表中插入了一个新的条目 "foo: bar"，该条目正好对应之前 HEADERS 帧引用的索引。

**预期输出：**

1. 在收到 HEADERS 帧时，`stream_->headers_decompressed()` 返回 `false`，表明头部解码被阻塞。
2. 在收到 QPACK 动态表更新指令后，`stream_->headers_decompressed()` 返回 `true`，表明头部解码成功完成。

**用户或编程常见的使用错误：**

1. **错误地假设帧的到达顺序：** 程序员可能错误地认为 HEADERS 帧总是在 DATA 帧之前到达，而没有处理 DATA 帧先到的情况，这会导致连接错误。
   - **例子：**  服务器端实现中，在没有检查是否已经接收到 HEADERS 帧的情况下，就尝试处理接收到的 DATA 帧内容。

2. **未正确处理 Trailers：** 程序员可能在处理完 initial headers 和 data 后，忘记处理 trailing headers，或者假设不会有 trailing headers。
   - **例子：**  客户端代码在接收到 response body 后就认为请求完成，没有处理可能随之而来的 trailers。

3. **在不支持的协议上发送特定帧：** 程序员可能在非 HTTP/3 的 QUIC 连接上发送 HTTP/3 特有的帧（例如 METADATA 帧），或者在未启用 WebTransport 的连接上发送 WebTransport 相关的帧。
   - **例子：**  尝试在标准的 HTTP/2 over QUIC 连接上发送 METADATA 帧。

4. **对 QPACK 的理解不足：**  程序员可能不理解 QPACK 动态表的工作原理，导致在测试或实现中出现头部解码阻塞的问题，或者错误地发送或接收 QPACK 编码的头部。
   - **例子：**  手动构造 QPACK 编码的头部时，错误地引用了不存在的动态表条目。

**用户操作到达此代码的调试线索：**

假设用户在使用 Chrome 浏览器访问一个支持 HTTP/3 和 WebTransport 的网站：

1. **用户在地址栏输入网站 URL 并回车。**  浏览器会尝试与服务器建立 QUIC 连接并升级到 HTTP/3。
2. **浏览器发送 HTTP 请求。** 这会导致 `QuicSpdyStream` 对象被创建，并开始发送 HEADERS 帧。相关的测试用例（例如测试 `WriteHeaders` 返回值）可能会被触发。
3. **服务器返回包含 QPACK 编码的响应头。** 如果响应头引用了动态表项，而这些条目尚未到达，测试用例 `HeaderDecodingUnblockedAfterStreamClosed` 或 `HeaderDecodingUnblockedAfterResetReceived` 可能会被涉及。
4. **网站使用了 HTTP/3 的 Trailers 发送额外的头部。** 测试用例 `TrailersAfterTrailers` 或 `DataAfterTrailers` 可能会被触发，特别是当出现帧序列错误时。
5. **网站使用了 WebTransport 技术，并且用户通过 JavaScript 代码建立了 WebTransport 连接。** 测试用例 `ProcessOutgoingWebTransportHeaders` 或 `ProcessIncomingWebTransportHeaders` 会被执行。
6. **在 WebTransport 连接上，网站发送或接收数据报。**  测试用例 `ReceiveHttpDatagram` 或 `SendHttpDatagram` 将会被触发。
7. **如果连接过程中出现错误（例如，接收到意外的帧），连接会被关闭。**  测试用例 `DataBeforeHeaders` 或 `StopProcessingIfConnectionClosed` 模拟了这些场景。

**总结：**

作为第五部分的前一部分，这部分代码深入测试了 `QuicSpdyStream` 在处理 HTTP/3 特有的帧类型、处理帧序列错误、与 QPACK 的交互、以及对 WebTransport 和 HTTP Datagram 的支持等方面的复杂逻辑和错误处理机制。它确保了 `QuicSpdyStream` 在各种异常和正常情况下都能正确地管理 HTTP/3 流的状态和数据传输。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));

  // Deliver second dynamic table entry to decoder
  // to trigger decoding of trailing header block.
  session_->qpack_decoder()->OnInsertWithoutNameReference("trailing", "foobar");
}

// Regression test for b/132603592: QPACK decoding unblocked after stream is
// closed.
TEST_P(QuicSpdyStreamTest, HeaderDecodingUnblockedAfterStreamClosed) {
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

  // Reset stream by this endpoint, for example, due to stream cancellation.
  EXPECT_CALL(*session_, MaybeSendStopSendingFrame(
                             stream_->id(), QuicResetStreamError::FromInternal(
                                                QUIC_STREAM_CANCELLED)));
  EXPECT_CALL(
      *session_,
      MaybeSendRstStreamFrame(
          stream_->id(),
          QuicResetStreamError::FromInternal(QUIC_STREAM_CANCELLED), _));
  stream_->Reset(QUIC_STREAM_CANCELLED);

  // Deliver dynamic table entry to decoder.
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");

  EXPECT_FALSE(stream_->headers_decompressed());
}

TEST_P(QuicSpdyStreamTest, HeaderDecodingUnblockedAfterResetReceived) {
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

  // OnStreamReset() is called when RESET_STREAM frame is received from peer.
  // This aborts header decompression.
  stream_->OnStreamReset(QuicRstStreamFrame(
      kInvalidControlFrameId, stream_->id(), QUIC_STREAM_CANCELLED, 0));

  // Deliver dynamic table entry to decoder.
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");
  EXPECT_FALSE(stream_->headers_decompressed());
}

class QuicSpdyStreamIncrementalConsumptionTest : public QuicSpdyStreamTest {
 protected:
  QuicSpdyStreamIncrementalConsumptionTest() : offset_(0), consumed_bytes_(0) {}
  ~QuicSpdyStreamIncrementalConsumptionTest() override = default;

  // Create QuicStreamFrame with |payload|
  // and pass it to stream_->OnStreamFrame().
  void OnStreamFrame(absl::string_view payload) {
    QuicStreamFrame frame(stream_->id(), /* fin = */ false, offset_, payload);
    stream_->OnStreamFrame(frame);
    offset_ += payload.size();
  }

  // Return number of bytes marked consumed with sequencer
  // since last NewlyConsumedBytes() call.
  QuicStreamOffset NewlyConsumedBytes() {
    QuicStreamOffset previously_consumed_bytes = consumed_bytes_;
    consumed_bytes_ = stream_->sequencer()->NumBytesConsumed();
    return consumed_bytes_ - previously_consumed_bytes;
  }

  // Read |size| bytes from the stream.
  std::string ReadFromStream(QuicByteCount size) {
    std::string buffer;
    buffer.resize(size);

    struct iovec vec;
    vec.iov_base = const_cast<char*>(buffer.data());
    vec.iov_len = size;

    size_t bytes_read = stream_->Readv(&vec, 1);
    EXPECT_EQ(bytes_read, size);

    return buffer;
  }

 private:
  QuicStreamOffset offset_;
  QuicStreamOffset consumed_bytes_;
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicSpdyStreamIncrementalConsumptionTest,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

// Test that stream bytes are consumed (by calling
// sequencer()->MarkConsumed()) incrementally, as soon as possible.
TEST_P(QuicSpdyStreamIncrementalConsumptionTest, OnlyKnownFrames) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(!kShouldProcessData);

  std::string headers = HeadersFrame({std::make_pair("foo", "bar")});

  // All HEADERS frame bytes are consumed even if the frame is not received
  // completely.
  OnStreamFrame(absl::string_view(headers).substr(0, headers.size() - 1));
  EXPECT_EQ(headers.size() - 1, NewlyConsumedBytes());

  // The rest of the HEADERS frame is also consumed immediately.
  OnStreamFrame(absl::string_view(headers).substr(headers.size() - 1));
  EXPECT_EQ(1u, NewlyConsumedBytes());

  // Verify headers.
  EXPECT_THAT(stream_->header_list(), ElementsAre(Pair("foo", "bar")));
  stream_->ConsumeHeaderList();

  // DATA frame.
  absl::string_view data_payload(kDataFramePayload);
  std::string data_frame = DataFrame(data_payload);
  QuicByteCount data_frame_header_length =
      data_frame.size() - data_payload.size();

  // DATA frame header is consumed.
  // DATA frame payload is not consumed because payload has to be buffered.
  OnStreamFrame(data_frame);
  EXPECT_EQ(data_frame_header_length, NewlyConsumedBytes());

  // Consume all but last byte of data.
  EXPECT_EQ(data_payload.substr(0, data_payload.size() - 1),
            ReadFromStream(data_payload.size() - 1));
  EXPECT_EQ(data_payload.size() - 1, NewlyConsumedBytes());

  std::string trailers =
      HeadersFrame({std::make_pair("custom-key", "custom-value")});

  // No bytes are consumed, because last byte of DATA payload is still buffered.
  OnStreamFrame(absl::string_view(trailers).substr(0, trailers.size() - 1));
  EXPECT_EQ(0u, NewlyConsumedBytes());

  // Reading last byte of DATA payload triggers consumption of all data received
  // so far, even though last HEADERS frame has not been received completely.
  EXPECT_EQ(data_payload.substr(data_payload.size() - 1), ReadFromStream(1));
  EXPECT_EQ(1 + trailers.size() - 1, NewlyConsumedBytes());

  // Last byte of trailers is immediately consumed.
  OnStreamFrame(absl::string_view(trailers).substr(trailers.size() - 1));
  EXPECT_EQ(1u, NewlyConsumedBytes());

  // Verify trailers.
  EXPECT_THAT(stream_->received_trailers(),
              ElementsAre(Pair("custom-key", "custom-value")));
}

TEST_P(QuicSpdyStreamIncrementalConsumptionTest, ReceiveUnknownFrame) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  EXPECT_CALL(debug_visitor,
              OnUnknownFrameReceived(stream_->id(), /* frame_type = */ 0x21,
                                     /* payload_length = */ 3));
  std::string unknown_frame = UnknownFrame(0x21, "foo");
  OnStreamFrame(unknown_frame);
}

TEST_P(QuicSpdyStreamIncrementalConsumptionTest,
       ReceiveUnsupportedMetadataFrame) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  quiche::HttpHeaderBlock headers;
  headers.AppendValueOrAddHeader("key1", "val1");
  headers.AppendValueOrAddHeader("key2", "val2");
  NoopDecoderStreamErrorDelegate delegate;
  QpackEncoder qpack_encoder(&delegate, HuffmanEncoding::kDisabled,
                             CookieCrumbling::kEnabled);
  std::string metadata_frame_payload = qpack_encoder.EncodeHeaderList(
      stream_->id(), headers,
      /* encoder_stream_sent_byte_count = */ nullptr);
  std::string metadata_frame_header =
      HttpEncoder::SerializeMetadataFrameHeader(metadata_frame_payload.size());
  std::string metadata_frame = metadata_frame_header + metadata_frame_payload;

  EXPECT_CALL(debug_visitor,
              OnUnknownFrameReceived(
                  stream_->id(), /* frame_type = */ 0x4d,
                  /* payload_length = */ metadata_frame_payload.length()));
  OnStreamFrame(metadata_frame);
}

class MockMetadataVisitor : public QuicSpdyStream::MetadataVisitor {
 public:
  ~MockMetadataVisitor() override = default;
  MOCK_METHOD(void, OnMetadataComplete,
              (size_t frame_len, const QuicHeaderList& header_list),
              (override));
};

TEST_P(QuicSpdyStreamIncrementalConsumptionTest, ReceiveMetadataFrame) {
  if (!UsesHttp3()) {
    return;
  }
  StrictMock<MockMetadataVisitor> metadata_visitor;
  Initialize(kShouldProcessData);
  stream_->RegisterMetadataVisitor(&metadata_visitor);
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  quiche::HttpHeaderBlock headers;
  headers.AppendValueOrAddHeader("key1", "val1");
  headers.AppendValueOrAddHeader("key2", "val2");
  NoopDecoderStreamErrorDelegate delegate;
  QpackEncoder qpack_encoder(&delegate, HuffmanEncoding::kDisabled,
                             CookieCrumbling::kEnabled);
  std::string metadata_frame_payload = qpack_encoder.EncodeHeaderList(
      stream_->id(), headers,
      /* encoder_stream_sent_byte_count = */ nullptr);
  std::string metadata_frame_header =
      HttpEncoder::SerializeMetadataFrameHeader(metadata_frame_payload.size());
  std::string metadata_frame = metadata_frame_header + metadata_frame_payload;

  EXPECT_CALL(metadata_visitor, OnMetadataComplete(metadata_frame.size(), _))
      .WillOnce(testing::WithArgs<1>(
          Invoke([&headers](const QuicHeaderList& header_list) {
            quiche::HttpHeaderBlock actual_headers;
            for (const auto& header : header_list) {
              actual_headers.AppendValueOrAddHeader(header.first,
                                                    header.second);
            }
            EXPECT_EQ(headers, actual_headers);
          })));
  OnStreamFrame(metadata_frame);
}

TEST_P(QuicSpdyStreamIncrementalConsumptionTest,
       ResetDuringMultipleMetadataFrames) {
  if (!UsesHttp3()) {
    return;
  }
  StrictMock<MockMetadataVisitor> metadata_visitor;
  Initialize(kShouldProcessData);
  stream_->RegisterMetadataVisitor(&metadata_visitor);
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  quiche::HttpHeaderBlock headers;
  headers.AppendValueOrAddHeader("key1", "val1");
  headers.AppendValueOrAddHeader("key2", "val2");
  NoopDecoderStreamErrorDelegate delegate;
  QpackEncoder qpack_encoder(&delegate, HuffmanEncoding::kDisabled,
                             CookieCrumbling::kEnabled);
  std::string metadata_frame_payload = qpack_encoder.EncodeHeaderList(
      stream_->id(), headers,
      /* encoder_stream_sent_byte_count = */ nullptr);
  std::string metadata_frame_header =
      HttpEncoder::SerializeMetadataFrameHeader(metadata_frame_payload.size());
  std::string metadata_frame = metadata_frame_header + metadata_frame_payload;

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(AnyNumber());
  EXPECT_CALL(*session_, MaybeSendStopSendingFrame(_, _));
  EXPECT_CALL(*session_, MaybeSendRstStreamFrame(_, _, _));
  // Reset the stream while processing the first frame and do not
  // receive a callback about the second.
  EXPECT_CALL(metadata_visitor, OnMetadataComplete(metadata_frame.size(), _))
      .WillOnce(testing::WithArgs<1>(
          Invoke([&headers, this](const QuicHeaderList& header_list) {
            quiche::HttpHeaderBlock actual_headers;
            for (const auto& header : header_list) {
              actual_headers.AppendValueOrAddHeader(header.first,
                                                    header.second);
            }
            EXPECT_EQ(headers, actual_headers);
            stream_->Reset(QUIC_STREAM_CANCELLED);
          })));
  std::string data = metadata_frame + metadata_frame;
  OnStreamFrame(data);
}

TEST_P(QuicSpdyStreamIncrementalConsumptionTest, UnknownFramesInterleaved) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(!kShouldProcessData);

  // Unknown frame of reserved type before HEADERS is consumed immediately.
  std::string unknown_frame1 = UnknownFrame(0x21, "foo");
  OnStreamFrame(unknown_frame1);
  EXPECT_EQ(unknown_frame1.size(), NewlyConsumedBytes());

  std::string headers = HeadersFrame({std::make_pair("foo", "bar")});

  // All HEADERS frame bytes are consumed even if the frame is not received
  // completely.
  OnStreamFrame(absl::string_view(headers).substr(0, headers.size() - 1));
  EXPECT_EQ(headers.size() - 1, NewlyConsumedBytes());

  // The rest of the HEADERS frame is also consumed immediately.
  OnStreamFrame(absl::string_view(headers).substr(headers.size() - 1));
  EXPECT_EQ(1u, NewlyConsumedBytes());

  // Verify headers.
  EXPECT_THAT(stream_->header_list(), ElementsAre(Pair("foo", "bar")));
  stream_->ConsumeHeaderList();

  // Frame of unknown, not reserved type between HEADERS and DATA is consumed
  // immediately.
  std::string unknown_frame2 = UnknownFrame(0x3a, "");
  OnStreamFrame(unknown_frame2);
  EXPECT_EQ(unknown_frame2.size(), NewlyConsumedBytes());

  // DATA frame.
  absl::string_view data_payload(kDataFramePayload);
  std::string data_frame = DataFrame(data_payload);
  QuicByteCount data_frame_header_length =
      data_frame.size() - data_payload.size();

  // DATA frame header is consumed.
  // DATA frame payload is not consumed because payload has to be buffered.
  OnStreamFrame(data_frame);
  EXPECT_EQ(data_frame_header_length, NewlyConsumedBytes());

  // Frame of unknown, not reserved type is not consumed because DATA payload is
  // still buffered.
  std::string unknown_frame3 = UnknownFrame(0x39, "bar");
  OnStreamFrame(unknown_frame3);
  EXPECT_EQ(0u, NewlyConsumedBytes());

  // Consume all but last byte of data.
  EXPECT_EQ(data_payload.substr(0, data_payload.size() - 1),
            ReadFromStream(data_payload.size() - 1));
  EXPECT_EQ(data_payload.size() - 1, NewlyConsumedBytes());

  std::string trailers =
      HeadersFrame({std::make_pair("custom-key", "custom-value")});

  // No bytes are consumed, because last byte of DATA payload is still buffered.
  OnStreamFrame(absl::string_view(trailers).substr(0, trailers.size() - 1));
  EXPECT_EQ(0u, NewlyConsumedBytes());

  // Reading last byte of DATA payload triggers consumption of all data received
  // so far, even though last HEADERS frame has not been received completely.
  EXPECT_EQ(data_payload.substr(data_payload.size() - 1), ReadFromStream(1));
  EXPECT_EQ(1 + unknown_frame3.size() + trailers.size() - 1,
            NewlyConsumedBytes());

  // Last byte of trailers is immediately consumed.
  OnStreamFrame(absl::string_view(trailers).substr(trailers.size() - 1));
  EXPECT_EQ(1u, NewlyConsumedBytes());

  // Verify trailers.
  EXPECT_THAT(stream_->received_trailers(),
              ElementsAre(Pair("custom-key", "custom-value")));

  // Unknown frame of reserved type after trailers is consumed immediately.
  std::string unknown_frame4 = UnknownFrame(0x40, "");
  OnStreamFrame(unknown_frame4);
  EXPECT_EQ(unknown_frame4.size(), NewlyConsumedBytes());
}

// Close connection if a DATA frame is received before a HEADERS frame.
TEST_P(QuicSpdyStreamTest, DataBeforeHeaders) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);

  // Closing the connection is mocked out in tests.  Instead, simply stop
  // reading data at the stream level to prevent QuicSpdyStream from blowing up.
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM,
                      "Unexpected DATA frame received.",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET))
      .WillOnce(InvokeWithoutArgs([this]() { stream_->StopReading(); }));

  std::string data = DataFrame(kDataFramePayload);
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 0, data));
}

// Close connection if a HEADERS frame is received after the trailing HEADERS.
TEST_P(QuicSpdyStreamTest, TrailersAfterTrailers) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);

  // Receive and consume headers.
  std::string headers = HeadersFrame({std::make_pair("foo", "bar")});
  QuicStreamOffset offset = 0;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, offset, headers));
  offset += headers.size();

  EXPECT_THAT(stream_->header_list(), ElementsAre(Pair("foo", "bar")));
  stream_->ConsumeHeaderList();

  // Receive data.  It is consumed by TestStream.
  std::string data = DataFrame(kDataFramePayload);
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, offset, data));
  offset += data.size();

  EXPECT_EQ(kDataFramePayload, stream_->data());

  // Receive and consume trailers.
  std::string trailers1 =
      HeadersFrame({std::make_pair("custom-key", "custom-value")});
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, offset, trailers1));
  offset += trailers1.size();

  EXPECT_TRUE(stream_->trailers_decompressed());
  EXPECT_THAT(stream_->received_trailers(),
              ElementsAre(Pair("custom-key", "custom-value")));

  // Closing the connection is mocked out in tests.  Instead, simply stop
  // reading data at the stream level to prevent QuicSpdyStream from blowing up.
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM,
                      "HEADERS frame received after trailing HEADERS.",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET))
      .WillOnce(InvokeWithoutArgs([this]() { stream_->StopReading(); }));

  // Receive another HEADERS frame, with no header fields.
  std::string trailers2 = HeadersFrame(HttpHeaderBlock());
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, offset, trailers2));
}

// Regression test for https://crbug.com/978733.
// Close connection if a DATA frame is received after the trailing HEADERS.
TEST_P(QuicSpdyStreamTest, DataAfterTrailers) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);

  // Receive and consume headers.
  std::string headers = HeadersFrame({std::make_pair("foo", "bar")});
  QuicStreamOffset offset = 0;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, offset, headers));
  offset += headers.size();

  EXPECT_THAT(stream_->header_list(), ElementsAre(Pair("foo", "bar")));
  stream_->ConsumeHeaderList();

  // Receive data.  It is consumed by TestStream.
  std::string data1 = DataFrame(kDataFramePayload);
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, offset, data1));
  offset += data1.size();
  EXPECT_EQ(kDataFramePayload, stream_->data());

  // Receive trailers, with single header field "custom-key: custom-value".
  std::string trailers =
      HeadersFrame({std::make_pair("custom-key", "custom-value")});
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, offset, trailers));
  offset += trailers.size();

  EXPECT_THAT(stream_->received_trailers(),
              ElementsAre(Pair("custom-key", "custom-value")));

  // Closing the connection is mocked out in tests.  Instead, simply stop
  // reading data at the stream level to prevent QuicSpdyStream from blowing up.
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM,
                      "Unexpected DATA frame received.",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET))
      .WillOnce(InvokeWithoutArgs([this]() { stream_->StopReading(); }));

  // Receive more data.
  std::string data2 = DataFrame("This payload should not be processed.");
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, offset, data2));
}

// SETTINGS frames are invalid on bidirectional streams.  If one is received,
// the connection is closed.  No more data should be processed.
TEST_P(QuicSpdyStreamTest, StopProcessingIfConnectionClosed) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);

  // SETTINGS frame with empty payload.
  std::string settings;
  ASSERT_TRUE(absl::HexStringToBytes("0400", &settings));

  // HEADERS frame.
  // Since it arrives after a SETTINGS frame, it should never be read.
  std::string headers = HeadersFrame({std::make_pair("foo", "bar")});

  // Combine the two frames to make sure they are processed in a single
  // QuicSpdyStream::OnDataAvailable() call.
  std::string frames = absl::StrCat(settings, headers);

  EXPECT_EQ(0u, stream_->sequencer()->NumBytesConsumed());

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_FRAME_UNEXPECTED_ON_SPDY_STREAM, _, _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
  EXPECT_CALL(*session_, OnConnectionClosed(_, _));

  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), /* fin = */ false,
                                         /* offset = */ 0, frames));

  EXPECT_EQ(0u, stream_->sequencer()->NumBytesConsumed());
}

// Stream Cancellation instruction is sent on QPACK decoder stream
// when stream is reset.
TEST_P(QuicSpdyStreamTest, StreamCancellationWhenStreamReset) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);

  EXPECT_CALL(*session_, MaybeSendStopSendingFrame(
                             stream_->id(), QuicResetStreamError::FromInternal(
                                                QUIC_STREAM_CANCELLED)));
  EXPECT_CALL(
      *session_,
      MaybeSendRstStreamFrame(
          stream_->id(),
          QuicResetStreamError::FromInternal(QUIC_STREAM_CANCELLED), _));

  stream_->Reset(QUIC_STREAM_CANCELLED);
}

// Stream Cancellation instruction is sent on QPACK decoder stream
// when RESET_STREAM frame is received.
TEST_P(QuicSpdyStreamTest, StreamCancellationOnResetReceived) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);

  stream_->OnStreamReset(QuicRstStreamFrame(
      kInvalidControlFrameId, stream_->id(), QUIC_STREAM_CANCELLED, 0));
}

TEST_P(QuicSpdyStreamTest, WriteHeadersReturnValue) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  testing::InSequence s;

  // Enable QPACK dynamic table.
  session_->OnSetting(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 1024);
  session_->OnSetting(SETTINGS_QPACK_BLOCKED_STREAMS, 1);

  EXPECT_CALL(*stream_, WriteHeadersMock(true));

  QpackSendStream* encoder_stream =
      QuicSpdySessionPeer::GetQpackEncoderSendStream(session_.get());
  EXPECT_CALL(*session_, WritevData(encoder_stream->id(), _, _, _, _, _))
      .Times(AnyNumber());

  size_t bytes_written = 0;
  EXPECT_CALL(*session_,
              WritevData(stream_->id(), _, /* offset = */ 0, _, _, _))
      .WillOnce(
          DoAll(SaveArg<1>(&bytes_written),
                Invoke(session_.get(), &MockQuicSpdySession::ConsumeData)));

  HttpHeaderBlock request_headers;
  request_headers["foo"] = "bar";
  size_t write_headers_return_value =
      stream_->WriteHeaders(std::move(request_headers), /*fin=*/true, nullptr);
  EXPECT_TRUE(stream_->fin_sent());
  // bytes_written includes HEADERS frame header.
  EXPECT_GT(bytes_written, write_headers_return_value);
}

// Regression test for https://crbug.com/1177662.
// RESET_STREAM with QUIC_STREAM_NO_ERROR should not be treated in a special
// way: it should close the read side but not the write side.
TEST_P(QuicSpdyStreamTest, TwoResetStreamFrames) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(AnyNumber());

  QuicRstStreamFrame rst_frame1(kInvalidControlFrameId, stream_->id(),
                                QUIC_STREAM_CANCELLED, /* bytes_written = */ 0);
  stream_->OnStreamReset(rst_frame1);
  EXPECT_TRUE(stream_->read_side_closed());
  EXPECT_FALSE(stream_->write_side_closed());

  QuicRstStreamFrame rst_frame2(kInvalidControlFrameId, stream_->id(),
                                QUIC_STREAM_NO_ERROR, /* bytes_written = */ 0);
  stream_->OnStreamReset(rst_frame2);
  EXPECT_TRUE(stream_->read_side_closed());
  EXPECT_FALSE(stream_->write_side_closed());
}

TEST_P(QuicSpdyStreamTest, ProcessOutgoingWebTransportHeaders) {
  if (!UsesHttp3()) {
    return;
  }

  InitializeWithPerspective(kShouldProcessData, Perspective::IS_CLIENT);
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  session_->EnableWebTransport();
  session_->OnSetting(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1);
  QuicSpdySessionPeer::EnableWebTransport(session_.get());
  QuicSpdySessionPeer::SetHttpDatagramSupport(session_.get(),
                                              HttpDatagramSupport::kRfc);

  EXPECT_CALL(*stream_, WriteHeadersMock(false));
  EXPECT_CALL(*session_, WritevData(stream_->id(), _, _, _, _, _))
      .Times(AnyNumber());

  quiche::HttpHeaderBlock headers;
  headers[":method"] = "CONNECT";
  headers[":protocol"] = "webtransport";
  stream_->WriteHeaders(std::move(headers), /*fin=*/false, nullptr);
  ASSERT_TRUE(stream_->web_transport() != nullptr);
  EXPECT_EQ(stream_->id(), stream_->web_transport()->id());
}

TEST_P(QuicSpdyStreamTest, ProcessIncomingWebTransportHeaders) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  session_->EnableWebTransport();
  QuicSpdySessionPeer::EnableWebTransport(session_.get());
  QuicSpdySessionPeer::SetHttpDatagramSupport(session_.get(),
                                              HttpDatagramSupport::kRfc);

  headers_[":method"] = "CONNECT";
  headers_[":protocol"] = "webtransport";

  stream_->OnStreamHeadersPriority(
      spdy::SpdyStreamPrecedence(kV3HighestPriority));
  ProcessHeaders(false, headers_);
  EXPECT_EQ("", stream_->data());
  EXPECT_FALSE(stream_->header_list().empty());
  EXPECT_FALSE(stream_->IsDoneReading());
  ASSERT_TRUE(stream_->web_transport() != nullptr);
  EXPECT_EQ(stream_->id(), stream_->web_transport()->id());
}

TEST_P(QuicSpdyStreamTest, IncomingWebTransportStreamWhenUnsupported) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  // Support WebTransport locally, but not by the peer.
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  session_->EnableWebTransport();
  session_->OnSettingsFrame(SettingsFrame());

  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  std::string webtransport_stream_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("40410400000000", &webtransport_stream_frame));
  QuicStreamFrame stream_frame(stream_->id(), /* fin = */ false,
                               /* offset = */ 0, webtransport_stream_frame);

  EXPECT_CALL(debug_visitor, OnUnknownFrameReceived(stream_->id(), 0x41, 4));
  stream_->OnStreamFrame(stream_frame);
  EXPECT_TRUE(stream_->web_transport_stream() == nullptr);
}

TEST_P(QuicSpdyStreamTest, IncomingWebTransportStream) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  session_->EnableWebTransport();
  SettingsFrame settings;
  settings.values[SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07] = 10;
  settings.values[SETTINGS_H3_DATAGRAM] = 1;
  session_->OnSettingsFrame(settings);

  std::string webtransport_stream_frame;
  ASSERT_TRUE(absl::HexStringToBytes("404110", &webtransport_stream_frame));
  QuicStreamFrame stream_frame(stream_->id(), /* fin = */ false,
                               /* offset = */ 0, webtransport_stream_frame);

  EXPECT_CALL(*session_, CreateIncomingStream(0x10));
  stream_->OnStreamFrame(stream_frame);
  EXPECT_TRUE(stream_->web_transport_stream() != nullptr);
}

TEST_P(QuicSpdyStreamTest, IncomingWebTransportStreamWithPaddingDraft02) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  session_->EnableWebTransport();
  SettingsFrame settings;
  settings.values[SETTINGS_WEBTRANS_DRAFT00] = 1;
  settings.values[SETTINGS_H3_DATAGRAM] = 1;
  session_->OnSettingsFrame(settings);

  std::string webtransport_stream_frame;
  ASSERT_TRUE(absl::HexStringToBytes("2100404110", &webtransport_stream_frame));
  QuicStreamFrame stream_frame(stream_->id(), /* fin = */ false,
                               /* offset = */ 0, webtransport_stream_frame);

  EXPECT_CALL(*session_, CreateIncomingStream(0x10));
  stream_->OnStreamFrame(stream_frame);
  EXPECT_TRUE(stream_->web_transport_stream() != nullptr);
}

TEST_P(QuicSpdyStreamTest, IncomingWebTransportStreamWithPaddingDraft07) {
  if (!UsesHttp3()) {
    return;
  }

  Initialize(kShouldProcessData);
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  session_->EnableWebTransport();
  SettingsFrame settings;
  settings.values[SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07] = 10;
  settings.values[SETTINGS_H3_DATAGRAM] = 1;
  session_->OnSettingsFrame(settings);

  std::string webtransport_stream_frame;
  ASSERT_TRUE(absl::HexStringToBytes("2100404110", &webtransport_stream_frame));
  QuicStreamFrame stream_frame(stream_->id(), /* fin = */ false,
                               /* offset = */ 0, webtransport_stream_frame);

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_SPDY_STREAM,
                              HasSubstr("non-zero offset"), _));
  stream_->OnStreamFrame(stream_frame);
  EXPECT_TRUE(stream_->web_transport_stream() == nullptr);
}

TEST_P(QuicSpdyStreamTest, ReceiveHttpDatagram) {
  if (!UsesHttp3()) {
    return;
  }
  InitializeWithPerspective(kShouldProcessData, Perspective::IS_CLIENT);
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  QuicSpdySessionPeer::SetHttpDatagramSupport(session_.get(),
                                              HttpDatagramSupport::kRfc);
  headers_[":method"] = "CONNECT";
  headers_[":protocol"] = "webtransport";
  ProcessHeaders(false, headers_);
  SavingHttp3DatagramVisitor h3_datagram_visitor;
  ASSERT_EQ(QuicDataWriter::GetVarInt62Len(stream_->id()), 1);
  std::array<char, 256> datagram;
  datagram[0] = stream_->id();
  for (size_t i = 1; i < datagram.size(); i++) {
    datagram[i] = i;
  }

  stream_->RegisterHttp3DatagramVisitor(&h3_datagram_visitor);
  session_->OnMessageReceived(
      absl::string_view(datagram.data(), datagram.size()));
  EXPECT_THAT(
      h3_datagram_visitor.received_h3_datagrams(),
      ElementsAre(SavingHttp3DatagramVisitor::SavedHttp3Datagram{
          stream_->id(), std::string(&datagram[1], datagram.size() - 1)}));
  // Test move.
  SavingHttp3DatagramVisitor h3_datagram_visitor2;
  stream_->ReplaceHttp3DatagramVisitor(&h3_datagram_visitor2);
  EXPECT_TRUE(h3_datagram_visitor2.received_h3_datagrams().empty());
  session_->OnMessageReceived(
      absl::string_view(datagram.data(), datagram.size()));
  EXPECT_THAT(
      h3_datagram_visitor2.received_h3_datagrams(),
      ElementsAre(SavingHttp3DatagramVisitor::SavedHttp3Datagram{
          stream_->id(), std::string(&datagram[1], datagram.size() - 1)}));
  // Cleanup.
  stream_->UnregisterHttp3DatagramVisitor();
}

TEST_P(QuicSpdyStreamTest, SendHttpDatagram) {
  if (!UsesHttp3()) {
    return;
  }
  Initialize(kShouldProcessData);
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  QuicSpdySessionPeer::SetHttpDatagramSupport(session_.get(),
                                              HttpDatagramSupport::kRfc);
  std::string http_datagram_payload = {1, 2, 3, 4, 5, 6};
  EXPECT_CALL(*connection_, SendMessage(1, _, false))
      .WillOnce(Return(MESSAGE_STATUS_SUCCESS));
  EXPECT_EQ(stream_->SendHttp3Datagram(http_datagram_payload),
            MESSAGE_STATUS_SUCCESS);
}

TEST_P(QuicSpdyStreamTest, SendHttpDatagramWithoutLocalSupport) {
  if (!UsesHttp3()) {
    return;
  }
  Initialize(kShouldProcessData);
  session_->set_local_http_datagram_support(HttpDatagramSupport::kNone);
  std::string http_datagram_payload = {1, 2, 3, 4, 5, 6};
  EXPECT_QUIC_BUG(stream_->SendHttp3Datagram(http_datagram_payload),
                  "Cannot send HTTP
```
Response:
The user wants to understand the functionality of the provided C++ code snippet from `quic_packet_creator_test.cc`. This file seems to contain unit tests for the `QuicPacketCreator` class. I need to analyze the test cases and describe the functionality they are testing.

Here's a breakdown of the tasks:

1. **Identify the core functionality being tested:** The file name and the test names suggest it's about creating and managing QUIC packets.
2. **Summarize the test cases:** Each `TEST_F` function represents a specific scenario for testing packet creation. I'll describe what each test is doing.
3. **Look for JavaScript relevance:**  QUIC is a transport protocol, and JavaScript running in web browsers interacts with it. I need to think about how these packet creation scenarios relate to browser-based QUIC communication.
4. **Identify logical inferences:** Some tests might have explicit input and expected output. I'll try to extract these.
5. **Spot common usage errors:**  The tests often set up specific conditions and check the outcomes. These conditions might reveal common mistakes developers could make when using `QuicPacketCreator`.
6. **Describe user operations leading to this code:**  I need to consider the steps a user might take in a web browser that would eventually trigger the execution of code involving `QuicPacketCreator`.
7. **Summarize the overall functionality of this part (part 5 of 6).**

**Mental Sandbox:**

* **Test Case Analysis:** I'll go through each `TEST_F` block and understand its purpose. For example, `ConsumeDataNotEnoughRoomForFin` tests what happens when there's not enough space for a FIN flag in a packet.
* **JavaScript Connection:** The `ConsumeData` and `AddMessageFrame` functions seem related to sending data. In a browser, this could be triggered by loading a web page or sending data through a WebSocket or WebTransport connection using QUIC.
* **Input/Output:**  For tests like `ConsumeData`, the input is data, stream ID, offset, and FIN flag. The output is the consumed data information and whether a packet was created.
* **Usage Errors:**  For instance, not checking if the `QuicPacketCreator` can write before calling `ConsumeData` could be a usage error.
* **User Steps:** A user clicking a link, typing in a URL, or interacting with a web application could lead to data being sent using QUIC.

**Constraint Checklist:**

* 列举功能: Yes
* JavaScript关系: Yes
* 举例说明: Yes
* 逻辑推理: Yes
* 假设输入输出: Yes
* 常见错误: Yes
* 举例说明: Yes
* 用户操作: Yes
* 调试线索: Yes
* 归纳功能: Yes

Confidence Score: 5/5  I'm confident I can address all aspects of the prompt.

Strategizing complete. I will now generate the response by systematically addressing each requirement based on my analysis.
这个C++源代码文件 `quic_packet_creator_test.cc` 是 Chromium QUIC 库中 `QuicPacketCreator` 类的单元测试。`QuicPacketCreator` 的主要职责是构建和序列化 QUIC 数据包。这个测试文件旨在验证 `QuicPacketCreator` 在各种场景下的正确行为。

**这个代码片段（第5部分）主要测试了以下功能：**

1. **`ConsumeDataFastPath`**: 测试 `ConsumeDataFastPath` 函数，这是一个优化路径，用于快速消费大量数据并放入一个或多个数据包中。
2. **`ConsumeDataLarge`**: 测试当要发送的数据量很大时，`ConsumeData` 函数是否能正确地将数据分割成多个数据包。
3. **`ConsumeDataLargeSendAckFalse` 和 `ConsumeDataLargeSendAckTrue`**: 测试在 `QuicPacketCreator` 无法立即写入（`SetCanNotWrite()`）时，调用 `ConsumeData` 的行为，以及后续恢复写入能力后的数据包发送。特别关注是否需要捆绑 ACK 帧。
4. **`NotWritableThenBatchOperations` 和 `NotWritableThenBatchOperations2`**: 测试在 `QuicPacketCreator` 初始状态不可写时，先缓存多个帧，然后在变为可写后，将这些帧打包到一个或多个数据包中发送。这涉及到控制帧（如 `RST_STREAM`，`GOAWAY`）和数据帧的组合。
5. **`PacketTransmissionType`**: 测试在连续调用 `ConsumeData` 时，如果中间改变了数据包的传输类型（例如从普通传输到重传），最终生成的数据包是否使用了第一次 `ConsumeData` 设置的传输类型。
6. **`TestConnectionIdLength`**: 测试设置服务器连接 ID 长度对数据包创建器的影响，特别是目标连接 ID 长度的获取。
7. **`SetMaxPacketLength_Initial`**: 测试在初始状态下通过 `SetMaxPacketLength` 设置最大数据包长度后，发送大量数据是否会按照新的最大长度进行分包。
8. **`SetMaxPacketLength_Middle`**: 测试在已经发送了一些数据后，修改最大数据包长度，后续发送的数据是否会按照新的长度进行分包。
9. **`SetMaxPacketLength_MidpacketFlush`**: 测试在批量处理数据过程中，强制刷新当前数据包并修改最大数据包长度，后续的数据是否会按照新的长度进行分包。
10. **`GenerateConnectivityProbingPacket`**: 测试生成用于探测网络连通性的数据包，包括旧版本 QUIC 的 PING 帧和新版本 QUIC 的 PATH_CHALLENGE 帧。
11. **`GenerateMtuDiscoveryPacket_Simple`**: 测试生成 MTU (Maximum Transmission Unit) 发现数据包，即一个填充到目标 MTU 大小的数据包。
12. **`GenerateMtuDiscoveryPacket_SurroundedByData`**: 测试在发送 MTU 发现数据包前后发送普通数据，以确保 MTU 探测不会影响其他数据包的发送。
13. **`ConnectionCloseFrameLargerThanPacketSize`**: 测试当连接关闭帧的大小超过最大数据包长度时，`QuicPacketCreator` 的处理方式。
14. **`RandomPaddingAfterFinSingleStreamSinglePacket`**: 测试在单个流的最后一个数据帧设置 `FIN_AND_PADDING` 标志后，是否会在单个数据包中添加随机填充。
15. **`RandomPaddingAfterFinSingleStreamMultiplePackets`**: 测试在单个流的最后一个数据帧设置 `FIN_AND_PADDING` 标志后，如果需要多个数据包，是否会添加随机填充。
16. **`RandomPaddingAfterFinMultipleStreamsMultiplePackets`**: 测试在多个流的最后数据帧设置 `FIN_AND_PADDING` 标志后，在多个数据包中添加随机填充的情况。
17. **`AddMessageFrame`**: 测试 `AddMessageFrame` 函数，用于添加 QUIC 消息帧（用于 WebTransport 等协议），以及添加大消息导致数据包刷新的情况。

**与 JavaScript 的功能关系及举例说明：**

QUIC 协议是 HTTP/3 和 WebTransport 等现代网络协议的基础。JavaScript 在浏览器环境中通过这些协议与服务器进行通信。`QuicPacketCreator` 负责将要发送的数据（包括 HTTP 请求、WebSocket 消息、WebTransport 数据报等）封装成 QUIC 数据包。

* **`ConsumeData` 对应于 JavaScript 中发送数据：** 当 JavaScript 代码使用 `fetch` API 发送 HTTP/3 请求，或者通过 WebTransport 的 `send()` 方法发送数据时，浏览器底层会调用 QUIC 库来处理数据发送。`ConsumeData` 函数就是将这些 JavaScript 产生的数据放入 QUIC 数据包的过程。
    * **例子：**  JavaScript 代码 `fetch('https://example.com/data', { method: 'POST', body: 'some data' })`  会导致浏览器创建一个 HTTP/3 请求，其中 'some data' 这个字符串会被传递到类似 `ConsumeData` 的函数中，以便封装成 QUIC STREAM 帧。
* **`AddMessageFrame` 对应于 JavaScript 中发送 WebTransport 消息：** WebTransport 允许在 QUIC 连接上发送可靠的消息。JavaScript 通过 WebTransport 的 `send()` 方法发送的消息会被封装成 QUIC MESSAGE 帧。 `AddMessageFrame` 就是负责创建这种帧。
    * **例子：** JavaScript 代码 `transport.send(new Uint8Array([0, 1, 2]))` 会导致 `AddMessageFrame` 被调用，将 `[0, 1, 2]` 封装成一个 QUIC MESSAGE 帧。

**逻辑推理、假设输入与输出：**

以 `ConsumeDataNotEnoughRoomForFin` 测试为例：

* **假设输入：**
    * `creator_` 的最大数据包长度很小，只够容纳 "foo" 这个字符串，但不足以容纳 "bar" 加上之前的 "foo" 和 FIN 标志。
    * 先调用 `creator_.ConsumeData` 传入 "foo"，`offset` 为 0，`NO_FIN`。
    * 后调用 `creator_.ConsumeData` 传入 "bar"，`offset` 为 3，`FIN`。
* **逻辑推理：**
    1. 第一个 `ConsumeData` 会成功将 "foo" 放入当前的数据包。
    2. 第二个 `ConsumeData` 发现当前数据包无法容纳 "bar" 和 FIN 标志。
    3. 因此，当前数据包会被刷新（发送），然后 "bar" 会被放入一个新的数据包中。
* **预期输出：**
    * 第一个 `ConsumeData` 返回 `bytes_consumed = 3`，`fin_consumed = false`，且 `creator_` 有挂起的帧。
    * 第二个 `ConsumeData` 返回 `bytes_consumed = 3`，`fin_consumed = true`，且 `creator_` 有挂起的帧。
    * 调用 `FlushCurrentPacket()` 后，会生成两个数据包，分别包含 "foo" 和 "bar"（带 FIN）。

**用户或编程常见的使用错误：**

* **未检查写入能力：**  在调用 `ConsumeData` 或 `AddMessageFrame` 之前，没有检查 `QuicPacketCreator` 是否可以写入数据（例如，网络连接是否正常，拥塞控制是否允许发送）。如果 `delegate_.CanWrite()` 返回 false，则调用这些函数可能会导致数据丢失或无法发送。
    * **例子：**  在网络状况很差的情况下，如果 JavaScript 代码尝试发送大量数据而没有合适的重试或错误处理机制，可能会导致数据发送失败。
* **错误估计数据包大小：**  没有考虑到 QUIC 协议头的开销，以及其他控制帧可能占用的空间，导致实际发送的数据超过了路径 MTU，从而导致分片或丢包。
    * **例子：**  在 JavaScript 中创建了一个很大的字符串并通过 WebTransport 发送，但没有考虑到 QUIC 协议头的开销，导致底层生成的数据包过大。
* **过早或过晚调用 `Flush`：**  没有在适当的时机调用 `Flush` 方法，可能导致数据包没有及时发送。
    * **例子：**  JavaScript 代码连续发送了几个小消息，但没有等待它们发送完毕就关闭了连接，可能导致部分消息没有成功发送到服务器。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中输入网址或点击链接：**  浏览器开始与服务器建立 QUIC 连接。
2. **JavaScript 代码发起网络请求：**  例如，使用 `fetch` API 请求网页资源或发送 POST 请求。
3. **浏览器网络栈处理请求：**  浏览器会创建 HTTP/3 请求，并将请求数据传递给 QUIC 协议栈。
4. **`QuicSession` (或类似组件) 将数据交给 `QuicPacketCreator`：**  `QuicSession` 负责管理连接状态，它会调用 `QuicPacketCreator` 的 `ConsumeData` 方法来将请求数据封装成 QUIC 数据包。
5. **单元测试模拟这些过程：**  `quic_packet_creator_test.cc` 中的测试用例通过模拟 `QuicSessionDelegate` 的行为，以及直接调用 `QuicPacketCreator` 的方法，来验证其在各种场景下的行为。

**调试线索：** 如果在网络通信中遇到数据发送问题，例如数据丢失、延迟高等，可以考虑以下调试线索：

* **检查 `QuicPacketCreator` 的状态：**  查看是否有挂起的帧，当前的数据包大小，最大数据包长度等。
* **查看 `delegate_` 的行为：**  确认 `CanWrite()` 的返回值，以及 `OnSerializedPacket()` 何时被调用，以及调用时的数据包内容。
* **分析网络抓包：**  使用 Wireshark 等工具抓取网络数据包，查看实际发送的 QUIC 数据包内容，包括帧类型、大小等，与预期进行对比。
* **查看 QUIC 连接的拥塞控制状态：**  确认是否因为拥塞导致数据发送受限。

**归纳一下它的功能 (第5部分):**

这部分测试主要集中在验证 `QuicPacketCreator` 在处理各种数据发送场景下的正确性，特别是涉及到：

* **快速路径数据消费 (`ConsumeDataFastPath`)**
* **大数据量分割成多个数据包 (`ConsumeDataLarge`)**
* **在写入能力受限时的帧缓存和批量发送 (`ConsumeDataLargeSendAckFalse/True`, `NotWritableThenBatchOperations`)**
* **数据包传输类型的管理 (`PacketTransmissionType`)**
* **最大数据包长度的动态调整 (`SetMaxPacketLength_Initial/Middle/MidpacketFlush`)**
* **特殊类型数据包的生成 (探测包 `GenerateConnectivityProbingPacket`, MTU 发现包 `GenerateMtuDiscoveryPacket`)**
* **处理超过数据包大小的控制帧 (`ConnectionCloseFrameLargerThanPacketSize`)**
* **在流结束时添加随机填充 (`RandomPaddingAfterFin...`)**
* **添加和处理 QUIC 消息帧 (`AddMessageFrame`)**

总之，这部分测试覆盖了 `QuicPacketCreator` 在数据发送和包大小控制方面的重要功能，确保其能可靠高效地将数据封装成 QUIC 数据包。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_packet_creator_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
ata to prevent a stream frame with a non-zero offset from
  // fitting.
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      "foo", 0, NO_FIN);
  EXPECT_EQ(3u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());

  // This frame will not fit with the existing frame, causing the queued frame
  // to be serialized, and it will be added to a new open packet.
  consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      "bar", 3, FIN);
  EXPECT_EQ(3u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());

  creator_.FlushCurrentPacket();
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  PacketContents contents;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
  CheckPacketContains(contents, 1);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, ConsumeDataFastPath) {
  delegate_.SetCanWriteAnything();
  creator_.SetTransmissionType(LOSS_RETRANSMISSION);

  const std::string data(10000, '?');
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  QuicConsumedData consumed = creator_.ConsumeDataFastPath(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      data);
  EXPECT_EQ(10000u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  PacketContents contents;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
  EXPECT_FALSE(packets_.empty());
  SerializedPacket& packet = packets_.back();
  EXPECT_TRUE(!packet.retransmittable_frames.empty());
  EXPECT_EQ(LOSS_RETRANSMISSION, packet.transmission_type);
  EXPECT_EQ(STREAM_FRAME, packet.retransmittable_frames.front().type);
  const QuicStreamFrame& stream_frame =
      packet.retransmittable_frames.front().stream_frame;
  EXPECT_EQ(10000u, stream_frame.data_length + stream_frame.offset);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, ConsumeDataLarge) {
  delegate_.SetCanWriteAnything();

  const std::string data(10000, '?');
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      data, 0, FIN);
  EXPECT_EQ(10000u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  PacketContents contents;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
  EXPECT_FALSE(packets_.empty());
  SerializedPacket& packet = packets_.back();
  EXPECT_TRUE(!packet.retransmittable_frames.empty());
  EXPECT_EQ(STREAM_FRAME, packet.retransmittable_frames.front().type);
  const QuicStreamFrame& stream_frame =
      packet.retransmittable_frames.front().stream_frame;
  EXPECT_EQ(10000u, stream_frame.data_length + stream_frame.offset);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, ConsumeDataLargeSendAckFalse) {
  delegate_.SetCanNotWrite();

  QuicRstStreamFrame* rst_frame = CreateRstStreamFrame();
  const bool success =
      creator_.ConsumeRetransmittableControlFrame(QuicFrame(rst_frame),
                                                  /*bundle_ack=*/true);
  EXPECT_FALSE(success);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  delegate_.SetCanWriteAnything();

  creator_.ConsumeRetransmittableControlFrame(QuicFrame(rst_frame),
                                              /*bundle_ack=*/false);

  const std::string data(10000, '?');
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  creator_.ConsumeRetransmittableControlFrame(QuicFrame(CreateRstStreamFrame()),
                                              /*bundle_ack=*/true);
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      data, 0, FIN);
  creator_.Flush();

  EXPECT_EQ(10000u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  EXPECT_FALSE(packets_.empty());
  SerializedPacket& packet = packets_.back();
  EXPECT_TRUE(!packet.retransmittable_frames.empty());
  EXPECT_EQ(STREAM_FRAME, packet.retransmittable_frames.front().type);
  const QuicStreamFrame& stream_frame =
      packet.retransmittable_frames.front().stream_frame;
  EXPECT_EQ(10000u, stream_frame.data_length + stream_frame.offset);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, ConsumeDataLargeSendAckTrue) {
  delegate_.SetCanNotWrite();
  delegate_.SetCanWriteAnything();

  const std::string data(10000, '?');
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      data, 0, FIN);
  creator_.Flush();

  EXPECT_EQ(10000u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  EXPECT_FALSE(packets_.empty());
  SerializedPacket& packet = packets_.back();
  EXPECT_TRUE(!packet.retransmittable_frames.empty());
  EXPECT_EQ(STREAM_FRAME, packet.retransmittable_frames.front().type);
  const QuicStreamFrame& stream_frame =
      packet.retransmittable_frames.front().stream_frame;
  EXPECT_EQ(10000u, stream_frame.data_length + stream_frame.offset);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, NotWritableThenBatchOperations) {
  delegate_.SetCanNotWrite();

  QuicRstStreamFrame* rst_frame = CreateRstStreamFrame();
  const bool consumed =
      creator_.ConsumeRetransmittableControlFrame(QuicFrame(rst_frame),
                                                  /*bundle_ack=*/true);
  EXPECT_FALSE(consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());
  EXPECT_FALSE(creator_.HasPendingStreamFramesOfStream(3));

  delegate_.SetCanWriteAnything();

  EXPECT_TRUE(
      creator_.ConsumeRetransmittableControlFrame(QuicFrame(rst_frame),
                                                  /*bundle_ack=*/false));
  // Send some data and a control frame
  creator_.ConsumeData(3, "quux", 0, NO_FIN);
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    creator_.ConsumeRetransmittableControlFrame(QuicFrame(CreateGoAwayFrame()),
                                                /*bundle_ack=*/false);
  }
  EXPECT_TRUE(creator_.HasPendingStreamFramesOfStream(3));

  // All five frames will be flushed out in a single packet.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  creator_.Flush();
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());
  EXPECT_FALSE(creator_.HasPendingStreamFramesOfStream(3));

  PacketContents contents;
  // ACK will be flushed by connection.
  contents.num_ack_frames = 0;
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    contents.num_goaway_frames = 1;
  } else {
    contents.num_goaway_frames = 0;
  }
  contents.num_rst_stream_frames = 1;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, NotWritableThenBatchOperations2) {
  delegate_.SetCanNotWrite();

  QuicRstStreamFrame* rst_frame = CreateRstStreamFrame();
  const bool success =
      creator_.ConsumeRetransmittableControlFrame(QuicFrame(rst_frame),
                                                  /*bundle_ack=*/true);
  EXPECT_FALSE(success);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  delegate_.SetCanWriteAnything();

  {
    InSequence dummy;
    // All five frames will be flushed out in a single packet
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(
            Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(
            Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  }
  EXPECT_TRUE(
      creator_.ConsumeRetransmittableControlFrame(QuicFrame(rst_frame),
                                                  /*bundle_ack=*/false));
  // Send enough data to exceed one packet
  size_t data_len = kDefaultMaxPacketSize + 100;
  const std::string data(data_len, '?');
  QuicConsumedData consumed = creator_.ConsumeData(3, data, 0, FIN);
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    creator_.ConsumeRetransmittableControlFrame(QuicFrame(CreateGoAwayFrame()),
                                                /*bundle_ack=*/false);
  }

  creator_.Flush();
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  // The first packet should have the queued data and part of the stream data.
  PacketContents contents;
  // ACK will be sent by connection.
  contents.num_ack_frames = 0;
  contents.num_rst_stream_frames = 1;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);

  // The second should have the remainder of the stream data.
  PacketContents contents2;
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    contents2.num_goaway_frames = 1;
  } else {
    contents2.num_goaway_frames = 0;
  }
  contents2.num_stream_frames = 1;
  CheckPacketContains(contents2, 1);
}

// Regression test of b/120493795.
TEST_F(QuicPacketCreatorMultiplePacketsTest, PacketTransmissionType) {
  delegate_.SetCanWriteAnything();

  // The first ConsumeData will fill the packet without flush.
  creator_.SetTransmissionType(LOSS_RETRANSMISSION);

  size_t data_len = 1220;
  const std::string data(data_len, '?');
  QuicStreamId stream1_id = QuicUtils::GetFirstBidirectionalStreamId(
      framer_.transport_version(), Perspective::IS_CLIENT);
  QuicConsumedData consumed = creator_.ConsumeData(stream1_id, data, 0, NO_FIN);
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  ASSERT_EQ(0u, creator_.BytesFree())
      << "Test setup failed: Please increase data_len to "
      << data_len + creator_.BytesFree() << " bytes.";

  // The second ConsumeData can not be added to the packet and will flush.
  creator_.SetTransmissionType(NOT_RETRANSMISSION);

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));

  QuicStreamId stream2_id = stream1_id + 4;

  consumed = creator_.ConsumeData(stream2_id, data, 0, NO_FIN);
  EXPECT_EQ(data_len, consumed.bytes_consumed);

  // Ensure the packet is successfully created.
  ASSERT_EQ(1u, packets_.size());
  ASSERT_TRUE(packets_[0].encrypted_buffer);
  ASSERT_EQ(1u, packets_[0].retransmittable_frames.size());
  EXPECT_EQ(stream1_id,
            packets_[0].retransmittable_frames[0].stream_frame.stream_id);

  // Since the second frame was not added, the packet's transmission type
  // should be the first frame's type.
  EXPECT_EQ(packets_[0].transmission_type, LOSS_RETRANSMISSION);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, TestConnectionIdLength) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  creator_.SetServerConnectionIdLength(0);
  EXPECT_EQ(0, creator_.GetDestinationConnectionIdLength());

  for (size_t i = 1; i < 10; i++) {
    creator_.SetServerConnectionIdLength(i);
    EXPECT_EQ(0, creator_.GetDestinationConnectionIdLength());
  }
}

// Test whether SetMaxPacketLength() works in the situation when the queue is
// empty, and we send three packets worth of data.
TEST_F(QuicPacketCreatorMultiplePacketsTest, SetMaxPacketLength_Initial) {
  delegate_.SetCanWriteAnything();

  // Send enough data for three packets.
  size_t data_len = 3 * kDefaultMaxPacketSize + 1;
  size_t packet_len = kDefaultMaxPacketSize + 100;
  ASSERT_LE(packet_len, kMaxOutgoingPacketSize);
  creator_.SetMaxPacketLength(packet_len);
  EXPECT_EQ(packet_len, creator_.max_packet_length());

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .Times(3)
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  const std::string data(data_len, '?');
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      data,
      /*offset=*/0, FIN);
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  // We expect three packets, and first two of them have to be of packet_len
  // size.  We check multiple packets (instead of just one) because we want to
  // ensure that |max_packet_length_| does not get changed incorrectly by the
  // creator after first packet is serialized.
  ASSERT_EQ(3u, packets_.size());
  EXPECT_EQ(packet_len, packets_[0].encrypted_length);
  EXPECT_EQ(packet_len, packets_[1].encrypted_length);
  CheckAllPacketsHaveSingleStreamFrame();
}

// Test whether SetMaxPacketLength() works in the situation when we first write
// data, then change packet size, then write data again.
TEST_F(QuicPacketCreatorMultiplePacketsTest, SetMaxPacketLength_Middle) {
  delegate_.SetCanWriteAnything();

  // We send enough data to overflow default packet length, but not the altered
  // one.
  size_t data_len = kDefaultMaxPacketSize;
  size_t packet_len = kDefaultMaxPacketSize + 100;
  ASSERT_LE(packet_len, kMaxOutgoingPacketSize);

  // We expect to see three packets in total.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .Times(3)
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));

  // Send two packets before packet size change.
  const std::string data(data_len, '?');
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      data,
      /*offset=*/0, NO_FIN);
  creator_.Flush();
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  // Make sure we already have two packets.
  ASSERT_EQ(2u, packets_.size());

  // Increase packet size.
  creator_.SetMaxPacketLength(packet_len);
  EXPECT_EQ(packet_len, creator_.max_packet_length());

  // Send a packet after packet size change.
  creator_.AttachPacketFlusher();
  consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      data, data_len, FIN);
  creator_.Flush();
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  // We expect first data chunk to get fragmented, but the second one to fit
  // into a single packet.
  ASSERT_EQ(3u, packets_.size());
  EXPECT_EQ(kDefaultMaxPacketSize, packets_[0].encrypted_length);
  EXPECT_LE(kDefaultMaxPacketSize, packets_[2].encrypted_length);
  CheckAllPacketsHaveSingleStreamFrame();
}

// Test whether SetMaxPacketLength() works correctly when we force the change of
// the packet size in the middle of the batched packet.
TEST_F(QuicPacketCreatorMultiplePacketsTest,
       SetMaxPacketLength_MidpacketFlush) {
  delegate_.SetCanWriteAnything();

  size_t first_write_len = kDefaultMaxPacketSize / 2;
  size_t packet_len = kDefaultMaxPacketSize + 100;
  size_t second_write_len = packet_len + 1;
  ASSERT_LE(packet_len, kMaxOutgoingPacketSize);

  // First send half of the packet worth of data.  We are in the batch mode, so
  // should not cause packet serialization.
  const std::string first_write(first_write_len, '?');
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      first_write,
      /*offset=*/0, NO_FIN);
  EXPECT_EQ(first_write_len, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());

  // Make sure we have no packets so far.
  ASSERT_EQ(0u, packets_.size());

  // Expect a packet to be flushed.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));

  // Increase packet size after flushing all frames.
  // Ensure it's immediately enacted.
  creator_.FlushCurrentPacket();
  creator_.SetMaxPacketLength(packet_len);
  EXPECT_EQ(packet_len, creator_.max_packet_length());
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  // We expect to see exactly one packet serialized after that, because we send
  // a value somewhat exceeding new max packet size, and the tail data does not
  // get serialized because we are still in the batch mode.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));

  // Send a more than a packet worth of data to the same stream.  This should
  // trigger serialization of one packet, and queue another one.
  const std::string second_write(second_write_len, '?');
  consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      second_write,
      /*offset=*/first_write_len, FIN);
  EXPECT_EQ(second_write_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());

  // We expect the first packet to be underfilled, and the second packet be up
  // to the new max packet size.
  ASSERT_EQ(2u, packets_.size());
  EXPECT_GT(kDefaultMaxPacketSize, packets_[0].encrypted_length);
  EXPECT_EQ(packet_len, packets_[1].encrypted_length);

  CheckAllPacketsHaveSingleStreamFrame();
}

// Test sending a connectivity probing packet.
TEST_F(QuicPacketCreatorMultiplePacketsTest,
       GenerateConnectivityProbingPacket) {
  delegate_.SetCanWriteAnything();

  std::unique_ptr<SerializedPacket> probing_packet;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    QuicPathFrameBuffer payload = {
        {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xfe}};
    probing_packet =
        creator_.SerializePathChallengeConnectivityProbingPacket(payload);
  } else {
    probing_packet = creator_.SerializeConnectivityProbingPacket();
  }

  ASSERT_TRUE(simple_framer_.ProcessPacket(QuicEncryptedPacket(
      probing_packet->encrypted_buffer, probing_packet->encrypted_length)));

  EXPECT_EQ(2u, simple_framer_.num_frames());
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    EXPECT_EQ(1u, simple_framer_.path_challenge_frames().size());
  } else {
    EXPECT_EQ(1u, simple_framer_.ping_frames().size());
  }
  EXPECT_EQ(1u, simple_framer_.padding_frames().size());
}

// Test sending an MTU probe, without any surrounding data.
TEST_F(QuicPacketCreatorMultiplePacketsTest,
       GenerateMtuDiscoveryPacket_Simple) {
  delegate_.SetCanWriteAnything();

  const size_t target_mtu = kDefaultMaxPacketSize + 100;
  static_assert(target_mtu < kMaxOutgoingPacketSize,
                "The MTU probe used by the test exceeds maximum packet size");

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));

  creator_.GenerateMtuDiscoveryPacket(target_mtu);

  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());
  ASSERT_EQ(1u, packets_.size());
  EXPECT_EQ(target_mtu, packets_[0].encrypted_length);

  PacketContents contents;
  contents.num_mtu_discovery_frames = 1;
  contents.num_padding_frames = 1;
  CheckPacketContains(contents, 0);
}

// Test sending an MTU probe.  Surround it with data, to ensure that it resets
// the MTU to the value before the probe was sent.
TEST_F(QuicPacketCreatorMultiplePacketsTest,
       GenerateMtuDiscoveryPacket_SurroundedByData) {
  delegate_.SetCanWriteAnything();

  const size_t target_mtu = kDefaultMaxPacketSize + 100;
  static_assert(target_mtu < kMaxOutgoingPacketSize,
                "The MTU probe used by the test exceeds maximum packet size");

  // Send enough data so it would always cause two packets to be sent.
  const size_t data_len = target_mtu + 1;

  // Send a total of five packets: two packets before the probe, the probe
  // itself, and two packets after the probe.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .Times(5)
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));

  // Send data before the MTU probe.
  const std::string data(data_len, '?');
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      data,
      /*offset=*/0, NO_FIN);
  creator_.Flush();
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  // Send the MTU probe.
  creator_.GenerateMtuDiscoveryPacket(target_mtu);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  // Send data after the MTU probe.
  creator_.AttachPacketFlusher();
  consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      data,
      /*offset=*/data_len, FIN);
  creator_.Flush();
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  ASSERT_EQ(5u, packets_.size());
  EXPECT_EQ(kDefaultMaxPacketSize, packets_[0].encrypted_length);
  EXPECT_EQ(target_mtu, packets_[2].encrypted_length);
  EXPECT_EQ(kDefaultMaxPacketSize, packets_[3].encrypted_length);

  PacketContents probe_contents;
  probe_contents.num_mtu_discovery_frames = 1;
  probe_contents.num_padding_frames = 1;

  CheckPacketHasSingleStreamFrame(0);
  CheckPacketHasSingleStreamFrame(1);
  CheckPacketContains(probe_contents, 2);
  CheckPacketHasSingleStreamFrame(3);
  CheckPacketHasSingleStreamFrame(4);
}

// Regression test for b/31486443.
TEST_F(QuicPacketCreatorMultiplePacketsTest,
       ConnectionCloseFrameLargerThanPacketSize) {
  delegate_.SetCanWriteAnything();
  char buf[2000] = {};
  absl::string_view error_details(buf, 2000);
  const QuicErrorCode kQuicErrorCode = QUIC_PACKET_WRITE_ERROR;

  QuicConnectionCloseFrame* frame = new QuicConnectionCloseFrame(
      framer_.transport_version(), kQuicErrorCode, NO_IETF_QUIC_ERROR,
      std::string(error_details),
      /*transport_close_frame_type=*/0);
  creator_.ConsumeRetransmittableControlFrame(QuicFrame(frame),
                                              /*bundle_ack=*/false);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       RandomPaddingAfterFinSingleStreamSinglePacket) {
  const QuicByteCount kStreamFramePayloadSize = 100u;
  char buf[kStreamFramePayloadSize] = {};
  const QuicStreamId kDataStreamId = 5;
  // Set the packet size be enough for one stream frame with 0 stream offset and
  // max size of random padding.
  size_t length =
      TaggingEncrypter(0x00).GetCiphertextSize(0) +
      GetPacketHeaderSize(
          framer_.transport_version(),
          creator_.GetDestinationConnectionIdLength(),
          creator_.GetSourceConnectionIdLength(),
          QuicPacketCreatorPeer::SendVersionInPacket(&creator_),
          !kIncludeDiversificationNonce,
          QuicPacketCreatorPeer::GetPacketNumberLength(&creator_),
          QuicPacketCreatorPeer::GetRetryTokenLengthLength(&creator_), 0,
          QuicPacketCreatorPeer::GetLengthLength(&creator_)) +
      QuicFramer::GetMinStreamFrameSize(
          framer_.transport_version(), kDataStreamId, 0,
          /*last_frame_in_packet=*/false,
          kStreamFramePayloadSize + kMaxNumRandomPaddingBytes) +
      kStreamFramePayloadSize + kMaxNumRandomPaddingBytes;
  creator_.SetMaxPacketLength(length);
  delegate_.SetCanWriteAnything();
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  QuicConsumedData consumed = creator_.ConsumeData(
      kDataStreamId, absl::string_view(buf, kStreamFramePayloadSize), 0,
      FIN_AND_PADDING);
  creator_.Flush();
  EXPECT_EQ(kStreamFramePayloadSize, consumed.bytes_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  EXPECT_EQ(1u, packets_.size());
  PacketContents contents;
  // The packet has both stream and padding frames.
  contents.num_padding_frames = 1;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       RandomPaddingAfterFinSingleStreamMultiplePackets) {
  const QuicByteCount kStreamFramePayloadSize = 100u;
  char buf[kStreamFramePayloadSize] = {};
  const QuicStreamId kDataStreamId = 5;
  // Set the packet size be enough for one stream frame with 0 stream offset +
  // 1. One or more packets will accommodate.
  size_t length =
      TaggingEncrypter(0x00).GetCiphertextSize(0) +
      GetPacketHeaderSize(
          framer_.transport_version(),
          creator_.GetDestinationConnectionIdLength(),
          creator_.GetSourceConnectionIdLength(),
          QuicPacketCreatorPeer::SendVersionInPacket(&creator_),
          !kIncludeDiversificationNonce,
          QuicPacketCreatorPeer::GetPacketNumberLength(&creator_),
          QuicPacketCreatorPeer::GetRetryTokenLengthLength(&creator_), 0,
          QuicPacketCreatorPeer::GetLengthLength(&creator_)) +
      QuicFramer::GetMinStreamFrameSize(
          framer_.transport_version(), kDataStreamId, 0,
          /*last_frame_in_packet=*/false, kStreamFramePayloadSize + 1) +
      kStreamFramePayloadSize + 1;
  creator_.SetMaxPacketLength(length);
  delegate_.SetCanWriteAnything();
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  QuicConsumedData consumed = creator_.ConsumeData(
      kDataStreamId, absl::string_view(buf, kStreamFramePayloadSize), 0,
      FIN_AND_PADDING);
  creator_.Flush();
  EXPECT_EQ(kStreamFramePayloadSize, consumed.bytes_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  EXPECT_LE(1u, packets_.size());
  PacketContents contents;
  // The first packet has both stream and padding frames.
  contents.num_stream_frames = 1;
  contents.num_padding_frames = 1;
  CheckPacketContains(contents, 0);

  for (size_t i = 1; i < packets_.size(); ++i) {
    // Following packets only have paddings.
    contents.num_stream_frames = 0;
    contents.num_padding_frames = 1;
    CheckPacketContains(contents, i);
  }
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       RandomPaddingAfterFinMultipleStreamsMultiplePackets) {
  const QuicByteCount kStreamFramePayloadSize = 100u;
  char buf[kStreamFramePayloadSize] = {};
  const QuicStreamId kDataStreamId1 = 5;
  const QuicStreamId kDataStreamId2 = 6;
  // Set the packet size be enough for first frame with 0 stream offset + second
  // frame + 1 byte payload. two or more packets will accommodate.
  size_t length =
      TaggingEncrypter(0x00).GetCiphertextSize(0) +
      GetPacketHeaderSize(
          framer_.transport_version(),
          creator_.GetDestinationConnectionIdLength(),
          creator_.GetSourceConnectionIdLength(),
          QuicPacketCreatorPeer::SendVersionInPacket(&creator_),
          !kIncludeDiversificationNonce,
          QuicPacketCreatorPeer::GetPacketNumberLength(&creator_),
          QuicPacketCreatorPeer::GetRetryTokenLengthLength(&creator_), 0,
          QuicPacketCreatorPeer::GetLengthLength(&creator_)) +
      QuicFramer::GetMinStreamFrameSize(
          framer_.transport_version(), kDataStreamId1, 0,
          /*last_frame_in_packet=*/false, kStreamFramePayloadSize) +
      kStreamFramePayloadSize +
      QuicFramer::GetMinStreamFrameSize(framer_.transport_version(),
                                        kDataStreamId1, 0,
                                        /*last_frame_in_packet=*/false, 1) +
      1;
  creator_.SetMaxPacketLength(length);
  delegate_.SetCanWriteAnything();
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  QuicConsumedData consumed = creator_.ConsumeData(
      kDataStreamId1, absl::string_view(buf, kStreamFramePayloadSize), 0,
      FIN_AND_PADDING);
  EXPECT_EQ(kStreamFramePayloadSize, consumed.bytes_consumed);
  consumed = creator_.ConsumeData(
      kDataStreamId2, absl::string_view(buf, kStreamFramePayloadSize), 0,
      FIN_AND_PADDING);
  EXPECT_EQ(kStreamFramePayloadSize, consumed.bytes_consumed);
  creator_.Flush();
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  EXPECT_LE(2u, packets_.size());
  PacketContents contents;
  // The first packet has two stream frames.
  contents.num_stream_frames = 2;
  CheckPacketContains(contents, 0);

  // The second packet has one stream frame and padding frames.
  contents.num_stream_frames = 1;
  contents.num_padding_frames = 1;
  CheckPacketContains(contents, 1);

  for (size_t i = 2; i < packets_.size(); ++i) {
    // Following packets only have paddings.
    contents.num_stream_frames = 0;
    contents.num_padding_frames = 1;
    CheckPacketContains(contents, i);
  }
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, AddMessageFrame) {
  if (framer_.version().UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  delegate_.SetCanWriteAnything();
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));

  creator_.ConsumeData(QuicUtils::GetFirstBidirectionalStreamId(
                           framer_.transport_version(), Perspective::IS_CLIENT),
                       "foo", 0, FIN);
  EXPECT_EQ(MESSAGE_STATUS_SUCCESS,
            creator_.AddMessageFrame(1, MemSliceFromString("message")));
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());

  // Add a message which causes the flush of current packet.
  EXPECT_EQ(MESSAGE_STATUS_SUCCESS,
            creator_.AddMessageFrame(
                2, MemSliceFromString(std::string(
                       creator_.GetCurrentLargestMessagePayload(), 'a'))));
  EXPECT_
"""


```
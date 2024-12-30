Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the provided C++ code snippet, which is part of a larger file (`quic_framer_test.cc`). They also want to know its relation to JavaScript (if any), see examples of logical reasoning with inputs and outputs, identify potential user errors, understand debugging steps, and finally, summarize the overall function of this specific section. The request explicitly mentions it's part 8 of 16.

2. **Identify the File's Purpose:** The filename `quic_framer_test.cc` strongly suggests this file contains unit tests for the `QuicFramer` class. The `QuicFramer` is likely responsible for taking raw bytes and parsing them into QUIC protocol frames, and vice-versa. The `_test.cc` suffix is a common convention for test files.

3. **Analyze the Code Snippet:** I scan the provided C++ code for patterns and keywords:
    * **`TEST_P(QuicFramerTest, ...)`:** This is a Google Test macro indicating parameterized tests within the `QuicFramerTest` test fixture. This tells me the code is about testing specific aspects of the `QuicFramer`.
    * **`QuicFramerPeer::SetPerspective(...)`:** This suggests the tests are exercising the `QuicFramer` from both client and server perspectives.
    * **`BuildDataPacket(...)` and `EncryptPacketWithTagAndPhase(...)`:** These functions likely create and encrypt QUIC packets for testing the framer's ability to process them.
    * **`ProcessPacket(...)`:** This is the core function being tested. It takes an encrypted packet and attempts to parse it.
    * **`EXPECT_TRUE(...)`, `EXPECT_THAT(...)`, `ASSERT_TRUE(...)`, `EXPECT_QUIC_BUG(...)`:** These are Google Test assertion macros. They check if the actual behavior of the code matches the expected behavior.
    * **`QuicAckFrame`, `QuicRstStreamFrame`, `QuicConnectionCloseFrame`:** These are QUIC frame types. The tests focus on how the `QuicFramer` handles these specific frame types.
    * **`ack_frame.received_packet_times`:** This field relates to ACK frames and the timestamps of received packets.
    * **`VersionHasIetfQuicFrames(...)`:** This conditional logic indicates the tests are designed to handle both older and newer (IETF) versions of the QUIC protocol.
    * **Hexadecimal byte arrays:** These are used to define expected packet structures for comparison.

4. **Deduce Functionality Based on Tests:**  By looking at the test names and the assertions, I can infer the functionalities being tested:
    * **`AckReceiveTimestamps`:** Tests how the framer processes timestamps in ACK frames. There are variations for handling timestamps, out-of-order packets, and truncation.
    * **`BuildAckFramePacket...`:**  Tests the framer's ability to *construct* ACK frames with different numbers of ACK blocks.
    * **`BuildRstFramePacketQuic`:** Tests the construction of RST_STREAM frames.
    * **`BuildCloseFramePacket...`:** Tests the construction of CONNECTION_CLOSE frames.

5. **Address JavaScript Relationship:**  QUIC is a transport layer protocol. While JavaScript running in a web browser might *use* QUIC for network communication, this specific C++ code is part of the *implementation* of the QUIC protocol itself. It doesn't directly interact with JavaScript code. I need to explain this distinction.

6. **Construct Logical Reasoning Examples:** For each test case, I can create a simplified "input" (the intention of the test, e.g., sending an ACK with specific timestamps) and "output" (the expected behavior, e.g., the framer correctly parses the timestamps and stores them). The hexadecimal byte arrays serve as concrete examples of the input/output data.

7. **Identify User/Programming Errors:**  Common errors when working with network protocols and framing include:
    * Incorrectly formatting frames.
    * Providing invalid data in frame fields.
    * Mismatched protocol versions.
    * Errors in encryption/decryption.

8. **Explain Debugging Steps:**  To reach this code during debugging, a developer would typically be investigating issues related to QUIC packet processing, specifically the handling of ACK, RST_STREAM, or CONNECTION_CLOSE frames. Breakpoints could be set in the `ProcessPacket` function or within the frame-specific parsing logic.

9. **Summarize the Section's Function:**  This specific section of the test file focuses on verifying the `QuicFramer`'s ability to correctly process and construct ACK frames, as well as construct RST_STREAM and CONNECTION_CLOSE frames. It covers different scenarios, including handling timestamps and varying numbers of ACK blocks, and considers both older and newer QUIC versions.

10. **Consider the "Part 8 of 16" Context:** Since this is part 8 of a larger test file, the overall file likely covers a broader range of `QuicFramer` functionalities and different QUIC frame types. This section focuses specifically on control frames related to acknowledgement and connection management.

By following these steps, I can generate a comprehensive and informative answer that addresses all aspects of the user's request. The key is to combine the information gleaned from the code itself with an understanding of the purpose of unit tests and the QUIC protocol.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 文件的第 8 部分的功能。

**功能归纳**

这部分代码主要集中在测试 `QuicFramer` 类处理和构建以下 QUIC 帧的能力：

* **ACK 帧 (Acknowledgement Frame):**  测试接收和发送带有不同配置的 ACK 帧，包括：
    * 接收带时间戳的 ACK 帧。
    * 处理乱序接收时间戳的情况。
    * 在空间不足时截断时间戳。
    * 构建包含一个或多个 ACK 块的 ACK 帧。
    * 构建包含最大数量 ACK 块的 ACK 帧。
* **RST_STREAM 帧 (Reset Stream Frame):** 测试构建 RST_STREAM 帧。
* **CONNECTION_CLOSE 帧 (Connection Close Frame):** 测试构建 CONNECTION_CLOSE 帧，包括携带扩展信息的情况。

**与 JavaScript 的关系**

直接来说，这段 C++ 代码与 JavaScript 没有直接的功能关系。这段代码是 Chromium 网络栈中 QUIC 协议的具体实现部分，负责底层的帧解析和构建。

然而，从更宏观的角度来看，QUIC 协议是现代 Web 技术的重要组成部分。JavaScript 在浏览器环境中发起网络请求，这些请求很可能通过 QUIC 协议进行传输。

**举例说明:**

假设一个用户在浏览器中使用 JavaScript 发起一个 HTTP/3 请求 (HTTP/3 基于 QUIC)。

1. **JavaScript 发起请求:**  JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 对象向服务器发送请求。
2. **浏览器处理:** 浏览器网络栈会处理这个请求，并决定使用 QUIC 协议进行传输。
3. **QUIC 协议栈处理:** 浏览器底层的 QUIC 协议栈会根据请求内容构建 QUIC 数据包。
4. **服务器响应:** 服务器收到请求后，会发送 HTTP/3 响应，同样通过 QUIC 协议。
5. **ACK 帧的作用:** 当浏览器接收到服务器发送的数据包后，它会生成一个 ACK 帧，告知服务器哪些数据包已经被成功接收。  `quic_framer_test.cc` 中测试的 ACK 帧处理逻辑，就是确保浏览器能够正确地解析服务器发送的 ACK 帧，以及浏览器能够正确地构建并发送 ACK 帧给服务器。
6. **关闭连接:**  如果连接需要关闭，浏览器或服务器会发送 CONNECTION_CLOSE 帧，其中包含关闭的原因。`quic_framer_test.cc` 中测试的 CONNECTION_CLOSE 帧构建逻辑，就是确保连接关闭帧能够被正确创建。
7. **RST_STREAM 帧的作用:** 如果某个 HTTP/3 流出现错误需要被终止，会发送 RST_STREAM 帧。`quic_framer_test.cc` 中测试的 RST_STREAM 帧构建逻辑，就是确保流重置帧能够被正确创建。

**逻辑推理 (假设输入与输出)**

**示例 1: `TEST_P(QuicFramerTest, AckReceiveTimestamps)`**

* **假设输入:**  `QuicFramer` 设置为服务器模式，接收到一个客户端发送的加密数据包。该数据包包含一个 ACK 帧，其中包含以下已接收数据包的时间戳信息：
    * 包号 kSmallLargestObserved - 2，接收时间 CreationTimePlus((0x29ff << 3))
    * 包号 kSmallLargestObserved - 3，接收时间 CreationTimePlus((0x29ff << 3))
    * 包号 kSmallLargestObserved - 4，接收时间 CreationTimePlus((0x29ff << 3))
    * 包号 kSmallLargestObserved - 5，接收时间 CreationTimePlus((0x29ff << 3))
* **预期输出:** `QuicFramer` 成功解析数据包，并将 ACK 帧中的接收时间戳信息存储在 `visitor_.ack_frames_[0]->received_packet_times` 中，且顺序与发送端一致。断言会验证存储的时间戳是否与预期一致。

**示例 2: `TEST_P(QuicFramerTest, BuildAckFramePacketMultipleAckBlocks)`**

* **假设输入:**  `QuicFramer` 设置为客户端模式，需要构建一个包含多个 ACK 块的 ACK 帧，确认接收了以下包号范围：[1, 5], [10, 500], [900, kSmallMissingPacket], [kSmallMissingPacket + 1, kSmallLargestObserved + 1]。
* **预期输出:** `QuicFramer` 构建出一个包含正确格式的 ACK 帧的数据包。断言会将构建的数据包与预期的字节数组进行比较，验证其结构和内容是否正确。

**用户或编程常见的使用错误**

* **构建错误的 ACK 帧:**  编程时，如果手动构建 ACK 帧，可能会因为计算错误的 Gap 或 Block Length，导致构建的帧格式不正确，无法被接收端正确解析。 例如，在计算两个 ACK 块之间的 Gap 时出现错误。
* **时间戳精度问题:** 在处理接收时间戳时，如果时间戳的精度或单位不一致，可能会导致接收端对延迟时间的计算出现偏差。
* **错误的帧类型:** 在构建数据包时，指定了错误的帧类型，导致接收端无法正确识别和处理。例如，将 RST_STREAM 帧的类型标识错误地设置为 ACK 帧的类型。
* **连接 ID 错误:** 在构建或解析数据包时，使用了错误的连接 ID，导致数据包无法被正确路由到相应的连接。

**用户操作如何一步步到达这里 (调试线索)**

假设开发者在调试一个与 QUIC 连接质量或可靠性相关的问题，例如，数据包丢失或延迟过高。他们可能会采取以下步骤：

1. **观察到网络问题:** 用户报告网页加载缓慢或连接不稳定。
2. **检查网络连接:** 开发者会首先检查用户的网络连接是否正常。
3. **分析 QUIC 连接:** 如果确定问题与 QUIC 连接有关，开发者可能会使用网络抓包工具（如 Wireshark）捕获网络数据包，查看 QUIC 握手过程、数据传输以及 ACK 帧的交互情况。
4. **定位 ACK 帧问题:** 如果怀疑 ACK 帧的处理存在问题，例如，发送的 ACK 没有被服务器正确理解，或者接收到的 ACK 帧信息不完整，开发者可能会深入分析 ACK 帧的结构和内容。
5. **查看 QUIC 协议栈代码:** 为了理解 ACK 帧的处理逻辑，开发者可能会查看 Chromium 网络栈中与 QUIC ACK 帧相关的代码，例如 `quic_framer.cc` 和 `quic_ack_frame.cc`。
6. **查看测试代码:** 为了验证 ACK 帧的处理逻辑是否正确，以及查找可能存在的 bug，开发者可能会查看相关的测试代码，比如 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc`。他们可能会重点关注与 `AckReceiveTimestamps` 和 `BuildAckFramePacket` 相关的测试用例，来理解代码的预期行为和实际行为。
7. **设置断点:** 开发者可能会在 `quic_framer_test.cc` 中的相关测试用例中设置断点，例如在 `framer_.ProcessPacket(*encrypted)` 处，来单步执行代码，观察变量的值，从而理解 ACK 帧是如何被解析和处理的。

**总结第 8 部分的功能**

总而言之，`net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 文件的第 8 部分主要负责测试 `QuicFramer` 类处理和构建关键的 QUIC 控制帧，特别是 ACK 帧，以及 RST_STREAM 和 CONNECTION_CLOSE 帧。这些测试覆盖了不同的场景和配置，确保 `QuicFramer` 能够正确地解析接收到的帧，并能构建出符合协议规范的帧，从而保证 QUIC 协议的可靠性和正确性。 这部分测试对于确保 Chromium 网络栈中 QUIC 协议实现的健壮性至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共16部分，请归纳一下它的功能

"""
ationTimePlus((0x2995 << 3) + 3)},
      {kSmallLargestObserved - 2, CreationTimePlus((0x2995 << 3) + 4)},
  };
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  QuicFrames frames = {QuicFrame(&ack_frame)};

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 0, false));
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());

  const QuicAckFrame& frame = *visitor_.ack_frames_[0];
  EXPECT_THAT(frame.received_packet_times,
              ContainerEq(PacketTimeVector{
                  {kSmallLargestObserved - 2, CreationTimePlus(0x2996 << 3)},
                  {kSmallLargestObserved - 3, CreationTimePlus(0x2996 << 3)},
                  {kSmallLargestObserved - 6, CreationTimePlus(0x2996 << 3)},
                  {kSmallLargestObserved - 7, CreationTimePlus(0x2996 << 3)},
                  {kSmallLargestObserved - 8, CreationTimePlus(0x2995 << 3)},
                  {kSmallLargestObserved - 9, CreationTimePlus(0x2995 << 3)},
                  {kSmallLargestObserved - 10, CreationTimePlus(0x1002 << 3)},
              }));
}

TEST_P(QuicFramerTest, AckReceiveTimestamps) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);
  framer_.set_process_timestamps(true);
  framer_.set_max_receive_timestamps_per_ack(8);
  framer_.set_receive_timestamps_exponent(3);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Use kSmallLargestObserved to make this test finished in a short time.
  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
  ack_frame.received_packet_times = PacketTimeVector{
      {kSmallLargestObserved - 5, CreationTimePlus((0x29ff << 3))},
      {kSmallLargestObserved - 4, CreationTimePlus((0x29ff << 3))},
      {kSmallLargestObserved - 3, CreationTimePlus((0x29ff << 3))},
      {kSmallLargestObserved - 2, CreationTimePlus((0x29ff << 3))},
  };
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  QuicFrames frames = {QuicFrame(&ack_frame)};

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 0, false));
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());

  const QuicAckFrame& frame = *visitor_.ack_frames_[0];
  EXPECT_THAT(frame.received_packet_times,
              ContainerEq(PacketTimeVector{
                  {kSmallLargestObserved - 2, CreationTimePlus(0x29ff << 3)},
                  {kSmallLargestObserved - 3, CreationTimePlus(0x29ff << 3)},
                  {kSmallLargestObserved - 4, CreationTimePlus(0x29ff << 3)},
                  {kSmallLargestObserved - 5, CreationTimePlus(0x29ff << 3)},
              }));
}

TEST_P(QuicFramerTest, AckReceiveTimestampsPacketOutOfOrder) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);
  framer_.set_process_timestamps(true);
  framer_.set_max_receive_timestamps_per_ack(8);
  framer_.set_receive_timestamps_exponent(3);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Use kSmallLargestObserved to make this test finished in a short time.
  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);

  // The packet numbers below are out of order, this is impossible because we
  // don't record out of order packets in received_packet_times. The test is
  // intended to ensure this error is raised when it happens.
  ack_frame.received_packet_times = PacketTimeVector{
      {kSmallLargestObserved - 5, CreationTimePlus((0x29ff << 3))},
      {kSmallLargestObserved - 2, CreationTimePlus((0x29ff << 3))},
      {kSmallLargestObserved - 4, CreationTimePlus((0x29ff << 3))},
      {kSmallLargestObserved - 3, CreationTimePlus((0x29ff << 3))},
  };
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  QuicFrames frames = {QuicFrame(&ack_frame)};

  EXPECT_QUIC_BUG(BuildDataPacket(header, frames),
                  "Packet number and/or receive time not in order.");
}

// If there's insufficient room for IETF ack receive timestamps, don't write any
// timestamp ranges.
TEST_P(QuicFramerTest, IetfAckReceiveTimestampsTruncate) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);
  framer_.set_process_timestamps(true);
  framer_.set_max_receive_timestamps_per_ack(8192);
  framer_.set_receive_timestamps_exponent(3);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Use kSmallLargestObserved to make this test finished in a short time.
  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
  for (QuicPacketNumber i(1); i <= kSmallLargestObserved; i += 2) {
    ack_frame.received_packet_times.push_back(
        {i, CreationTimePlus((0x29ff << 3))});
  }

  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  QuicFrames frames = {QuicFrame(&ack_frame)};

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 0, false));
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());

  const QuicAckFrame& frame = *visitor_.ack_frames_[0];
  EXPECT_TRUE(frame.received_packet_times.empty());
}

// If there are too many ack ranges, they will be truncated to make room for a
// timestamp range count of 0.
TEST_P(QuicFramerTest, IetfAckReceiveTimestampsAckRangeTruncation) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  framer_.set_process_timestamps(true);
  framer_.set_max_receive_timestamps_per_ack(8);
  framer_.set_receive_timestamps_exponent(3);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame;
  // Create a packet with just the ack.
  ack_frame = MakeAckFrameWithGaps(/*gap_size=*/0xffffffff,
                                   /*max_num_gaps=*/200,
                                   /*largest_acked=*/kMaxIetfVarInt);
  ack_frame.received_packet_times = PacketTimeVector{
      {QuicPacketNumber(kMaxIetfVarInt) - 2, CreationTimePlus((0x29ff << 3))},
  };
  QuicFrames frames = {QuicFrame(&ack_frame)};
  // Build an ACK packet.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> raw_ack_packet(BuildDataPacket(header, frames));
  ASSERT_TRUE(raw_ack_packet != nullptr);
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length =
      framer_.EncryptPayload(ENCRYPTION_INITIAL, header.packet_number,
                             *raw_ack_packet, buffer, kMaxOutgoingPacketSize);
  ASSERT_NE(0u, encrypted_length);
  // Now make sure we can turn our ack packet back into an ack frame.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  ASSERT_TRUE(framer_.ProcessPacket(
      QuicEncryptedPacket(buffer, encrypted_length, false)));
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  QuicAckFrame& processed_ack_frame = *visitor_.ack_frames_[0];
  EXPECT_EQ(QuicPacketNumber(kMaxIetfVarInt),
            LargestAcked(processed_ack_frame));
  // Verify ACK ranges in the frame gets truncated.
  ASSERT_LT(processed_ack_frame.packets.NumPacketsSlow(),
            ack_frame.packets.NumIntervals());
  EXPECT_EQ(158u, processed_ack_frame.packets.NumPacketsSlow());
  EXPECT_LT(processed_ack_frame.packets.NumIntervals(),
            ack_frame.packets.NumIntervals());
  EXPECT_EQ(QuicPacketNumber(kMaxIetfVarInt),
            processed_ack_frame.packets.Max());
  // But the receive timestamps are not truncated because they are small.
  EXPECT_FALSE(processed_ack_frame.received_packet_times.empty());
}

TEST_P(QuicFramerTest, BuildAckFramePacketOneAckBlockMaxLength) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame = InitAckFrame(kPacketNumber);
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();

  QuicFrames frames = {QuicFrame(&ack_frame)};

  // clang-format off
  unsigned char packet[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // frame type (ack frame)
      // (no ack blocks, 4 byte largest observed, 4 byte block length)
      0x4A,
      // largest acked
      0x12, 0x34, 0x56, 0x78,
      // Zero delta time.
      0x00, 0x00,
      // first ack block length.
      0x12, 0x34, 0x56, 0x78,
      // num timestamps.
      0x00,
  };


  unsigned char packet_ietf[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // frame type (IETF_ACK frame)
      0x02,
      // largest acked
      kVarInt62FourBytes + 0x12, 0x34, 0x56, 0x78,
      // Zero delta time.
      kVarInt62OneByte + 0x00,
      // Nr. of additional ack blocks
      kVarInt62OneByte + 0x00,
      // first ack block length.
      kVarInt62FourBytes + 0x12, 0x34, 0x56, 0x77,
  };
  // clang-format on
  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p), p_size);
}

TEST_P(QuicFramerTest, BuildAckFramePacketMultipleAckBlocks) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Use kSmallLargestObserved to make this test finished in a short time.
  QuicAckFrame ack_frame =
      InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(5)},
                    {QuicPacketNumber(10), QuicPacketNumber(500)},
                    {QuicPacketNumber(900), kSmallMissingPacket},
                    {kSmallMissingPacket + 1, kSmallLargestObserved + 1}});
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();

  QuicFrames frames = {QuicFrame(&ack_frame)};

  // clang-format off
  unsigned char packet[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // frame type (ack frame)
      // (has ack blocks, 2 byte largest observed, 2 byte block length)
      0x65,
      // largest acked
      0x12, 0x34,
      // Zero delta time.
      0x00, 0x00,
      // num ack blocks ranges.
      0x04,
      // first ack block length.
      0x00, 0x01,
      // gap to next block.
      0x01,
      // ack block length.
      0x0e, 0xaf,
      // gap to next block.
      0xff,
      // ack block length.
      0x00, 0x00,
      // gap to next block.
      0x91,
      // ack block length.
      0x01, 0xea,
      // gap to next block.
      0x05,
      // ack block length.
      0x00, 0x04,
      // num timestamps.
      0x00,
  };

  unsigned char packet_ietf[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // frame type (IETF_ACK frame)
      0x02,
      // largest acked
      kVarInt62TwoBytes + 0x12, 0x34,
      // Zero delta time.
      kVarInt62OneByte + 0x00,
      // num additional ack blocks.
      kVarInt62OneByte + 0x03,
      // first ack block length.
      kVarInt62OneByte + 0x00,

      // gap to next block.
      kVarInt62OneByte + 0x00,
      // ack block length.
      kVarInt62TwoBytes + 0x0e, 0xae,

      // gap to next block.
      kVarInt62TwoBytes + 0x01, 0x8f,
      // ack block length.
      kVarInt62TwoBytes + 0x01, 0xe9,

      // gap to next block.
      kVarInt62OneByte + 0x04,
      // ack block length.
      kVarInt62OneByte + 0x03,
  };
  // clang-format on
  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p), p_size);
}

TEST_P(QuicFramerTest, BuildAckFramePacketMaxAckBlocks) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Use kSmallLargestObservedto make this test finished in a short time.
  QuicAckFrame ack_frame;
  ack_frame.largest_acked = kSmallLargestObserved;
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  // 300 ack blocks.
  for (size_t i = 2; i < 2 * 300; i += 2) {
    ack_frame.packets.Add(QuicPacketNumber(i));
  }
  ack_frame.packets.AddRange(QuicPacketNumber(600), kSmallLargestObserved + 1);

  QuicFrames frames = {QuicFrame(&ack_frame)};

  // clang-format off
  unsigned char packet[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (ack frame)
      // (has ack blocks, 2 byte largest observed, 2 byte block length)
      0x65,
      // largest acked
      0x12, 0x34,
      // Zero delta time.
      0x00, 0x00,
      // num ack blocks ranges.
      0xff,
      // first ack block length.
      0x0f, 0xdd,
      // 255 = 4 * 63 + 3
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,

      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,

      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,

      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,

      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,

      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,

      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
      // num timestamps.
      0x00,
  };

  unsigned char packet_ietf[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (IETF_ACK frame)
      0x02,
      // largest acked
      kVarInt62TwoBytes + 0x12, 0x34,
      // Zero delta time.
      kVarInt62OneByte + 0x00,
      // num ack blocks ranges.
      kVarInt62TwoBytes + 0x01, 0x2b,
      // first ack block length.
      kVarInt62TwoBytes + 0x0f, 0xdc,
      // 255 added blocks of gap_size == 1, ack_size == 1
#define V99AddedBLOCK kVarInt62OneByte + 0x00, kVarInt62OneByte + 0x00
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,

      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,

      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,
      V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK, V99AddedBLOCK,

#undef V99AddedBLOCK
  };
  // clang-format on
  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p), p_size);
}

TEST_P(QuicFramerTest, BuildRstFramePacketQuic) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicRstStreamFrame rst_frame;
  rst_frame.stream_id = kStreamId;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    rst_frame.ietf_error_code = 0x01;
  } else {
    rst_frame.error_code = static_cast<QuicRstStreamErrorCode>(0x05060708);
  }
  rst_frame.byte_offset = 0x0807060504030201;

  // clang-format off
  unsigned char packet[] = {
    // type (short packet, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (rst stream frame)
    0x01,
    // stream id
    0x01, 0x02, 0x03, 0x04,
    // sent byte offset
    0x08, 0x07, 0x06, 0x05,
    0x04, 0x03, 0x02, 0x01,
    // error code
    0x05, 0x06, 0x07, 0x08,
  };

  unsigned char packet_ietf[] = {
    // type (short packet, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_RST_STREAM frame)
    0x04,
    // stream id
    kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04,
    // error code
    kVarInt62OneByte + 0x01,
    // sent byte offset
    kVarInt62EightBytes + 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
  };
  // clang-format on

  QuicFrames frames = {QuicFrame(&rst_frame)};

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }
  QuicEncryptedPacket encrypted(AsChars(p), p_size, false);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p), p_size);
}

TEST_P(QuicFramerTest, BuildCloseFramePacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicConnectionCloseFrame close_frame(framer_.transport_version(),
                                       QUIC_INTERNAL_ERROR, NO_IETF_QUIC_ERROR,
                                       "because I can", 0x05);
  QuicFrames frames = {QuicFrame(&close_frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (connection close frame)
    0x02,
    // error code
    0x00, 0x00, 0x00, 0x01,
    // error details length
    0x00, 0x0d,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',
  };

  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_CONNECTION_CLOSE frame)
    0x1c,
    // error code
    kVarInt62OneByte + 0x01,
    // Frame type within the CONNECTION_CLOSE frame
    kVarInt62OneByte + 0x05,
    // error details length
    kVarInt62OneByte + 0x0f,
    // error details
    '1',  ':',  'b',  'e',
    'c',  'a',  'u',  's',
    'e',  ' ',  'I',  ' ',
    'c',  'a',  'n',
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p), p_size);
}

TEST_P(QuicFramerTest, BuildCloseFramePacketExtendedInfo) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicConnectionCloseFrame close_frame(
      framer_.transport_version(),
      static_cast<QuicErrorCode>(
          VersionHasIetfQuicFrames(framer_.transport_version()) ? 0x01
                                                                : 0x05060708),
      NO_IETF_QUIC_ERROR, "because I can", 0x05);
  // Set this so that it is "there" for both Google QUIC and IETF QUIC
  // framing. It better not show up for Google QUIC!
  close_frame.quic_error_code = static_cast<QuicErrorCode>(0x4567);

  QuicFrames frames = {QuicFrame(&close_frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (connection close frame)
    0x02,
    // error code
    0x05, 0x06, 0x07, 0x08,
    // error details length
    0x00, 0x0d,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',
  };

  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_CONNECTION_CLOSE frame)
    0x1c,
    // 
"""


```
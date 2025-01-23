Response:
The user is asking for an analysis of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc`. They want to know its functionality, its relation to Javascript (if any), logical inferences with examples, common usage errors, and debugging information. Finally, they want a summary of the file's purpose based on the provided snippet, which is the 13th of 16 parts.

Here's a breakdown of how to address each point:

1. **Functionality:** Analyze the test cases within the provided code snippet. Each `TEST_P` function represents a specific aspect of the `QuicFramer`'s behavior under test. Look for patterns in the setup (e.g., creating `QuicFramer`, `QuicPacketHeader`), the actions performed (e.g., `framer_.ProcessPacket`, `BuildDataPacket`), and the assertions made (e.g., `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE`).

2. **Relation to Javascript:**  Consider how network protocols and packet framing, which are the focus of this code, might relate to Javascript. Javascript running in a browser interacts with network requests. QUIC is a transport protocol, and browsers use it. Think about where the connection points might be (e.g., browser APIs for network requests, underlying network stacks).

3. **Logical Inferences:**  Identify test cases that involve processing or building network packets. For these, formulate a hypothesis about the input (the raw byte representation of the packet) and the expected output (how the `QuicFramer` will interpret the packet, represented by the state of the `visitor_` object).

4. **Common Usage Errors:**  Look for test cases that explicitly check for error conditions (e.g., `EXPECT_FALSE` for `framer_.ProcessPacket`). These often indicate scenarios where incorrect packet formatting or unexpected data leads to processing failures.

5. **User Operation and Debugging:**  Consider the lifecycle of a network request in a browser. How does a user's action translate into network packets?  Trace the path from a user action (like clicking a link) down to the point where the `QuicFramer` might be involved in processing the received data.

6. **Summary of Functionality (Part 13 of 16):** Based on the analysis of the current snippet, identify the recurring themes and types of tests being performed. Consider how this part contributes to the overall testing of the `QuicFramer`.

**Pre-computation/Analysis of the Snippet:**

* **Retire Connection ID Frame Tests:** The code includes tests for building and processing `RETIRE_CONNECTION_ID` frames. This relates to connection migration and management in QUIC.
* **ACK Frame Error Tests:**  Several tests focus on invalid `ACK` frames, specifically around the `largest_observed` and ack block lengths. This indicates the importance of correctly formatted acknowledgment information.
* **Coalesced Packet Tests:** Tests for processing coalesced packets (multiple QUIC packets within a single UDP datagram) are present. This is a key feature of QUIC for reducing overhead. These tests examine scenarios with padding and different versions.
* **Undecryptable Packet Tests:**  Tests cover the behavior of the `QuicFramer` when encountering packets it cannot decrypt. These tests explore cases with and without a matching decrypter and in the context of coalesced packets.

**Overall Theme of the Snippet:**  This section of the test file seems to focus on testing the `QuicFramer`'s ability to handle various frame types, including control frames like `RETIRE_CONNECTION_ID` and `ACK`, as well as its robustness when encountering invalid or undecryptable packets, including complex scenarios like coalesced packets.
好的，让我们来分析一下这个 `quic_framer_test.cc` 文件的功能。

**文件功能概览:**

这个 `quic_framer_test.cc` 文件是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `QuicFramer` 类的功能。`QuicFramer` 的核心职责是将原始的网络数据包（字节流）解析成 QUIC 协议定义的帧（Frames），并将帧组装成网络数据包。

基于提供的代码片段，我们可以更具体地归纳出以下测试的功能：

1. **测试 `RETIRE_CONNECTION_ID` 帧的解析和构建:**  `TEST_P(QuicFramerTest, ProcessRetireConnectionIdFramePacket)` 和 `TEST_P(QuicFramerTest, BuildRetireConnectionIdFramePacket)`  分别测试了 `QuicFramer`  解析包含 `RETIRE_CONNECTION_ID` 帧的数据包的能力，以及构建包含 `RETIRE_CONNECTION_ID` 帧的数据包的能力。`RETIRE_CONNECTION_ID` 帧用于通知对端某个连接 ID 不再使用。

2. **测试 `ACK` 帧的错误处理:**  `TEST_P(QuicFramerTest, AckFrameWithInvalidLargestObserved)`, `TEST_P(QuicFramerTest, FirstAckBlockJustUnderFlow)`, 和 `TEST_P(QuicFramerTest, ThirdAckBlockJustUnderflow)`  测试了当接收到格式错误的 `ACK` 帧时，`QuicFramer` 的错误处理机制。这些错误场景包括 `largest_observed` 字段为 0，以及 ACK 块长度导致下溢的情况。`ACK` 帧用于确认接收到的数据包。

3. **测试合并包（Coalesced Packet）的处理:** `TEST_P(QuicFramerTest, CoalescedPacket)` 和 `TEST_P(QuicFramerTest, CoalescedPacketWithUdpPadding)` 测试了 `QuicFramer` 处理包含多个 QUIC 数据包的 UDP 数据报的能力。这包括处理带填充的合并包。合并包是 QUIC 的一个重要特性，可以减少连接建立时的延迟。

4. **测试不同版本号的合并包处理:** `TEST_P(QuicFramerTest, CoalescedPacketWithDifferentVersion)` 测试了当合并包中的第二个数据包具有不同的 QUIC 版本号时，`QuicFramer` 的处理方式。

5. **测试无法解密的包的处理:** `TEST_P(QuicFramerTest, UndecryptablePacketWithoutDecrypter)` 和 `TEST_P(QuicFramerTest, UndecryptablePacketWithDecrypter)` 测试了当 `QuicFramer` 接收到无法使用当前解密器解密的包时的行为。这包括在没有解密器和有错误解密器的情况下。

6. **测试无法解密的合并包处理:** `TEST_P(QuicFramerTest, UndecryptableCoalescedPacket)` 测试了当合并包中的第一个数据包无法解密时，`QuicFramer` 的处理方式。

**与 Javascript 的关系:**

虽然这个 C++ 文件本身不包含 Javascript 代码，但它所测试的 QUIC 协议与 Javascript 的功能有密切关系。

**举例说明:**

* **浏览器发起 HTTPS 请求:** 当用户在浏览器地址栏输入 `https://example.com` 并回车时，浏览器会尝试与服务器建立 HTTPS 连接。如果浏览器和服务器都支持 QUIC，它们可能会使用 QUIC 协议进行数据传输。
* **Fetch API 和 WebSocket API:**  Javascript 中的 `fetch` API 和 `WebSocket` API 底层可能会使用 QUIC 协议进行数据传输，尤其是在 Chrome 浏览器中。
* **Service Worker:**  Service Workers 可以拦截网络请求，并且也可能涉及到 QUIC 协议的处理。

在这个场景下，`QuicFramer` 的作用就是在浏览器（或服务器）的网络栈中，负责解析接收到的 QUIC 数据包，提取出其中的帧（例如，包含网页数据的 STREAM 帧），并将这些数据传递给上层 Javascript 代码（例如，渲染引擎）。同样，当 Javascript 代码需要发送数据时，`QuicFramer` 负责将 Javascript 提供的数据封装成 QUIC 帧并构建成网络数据包发送出去。

**逻辑推理 (假设输入与输出):**

**场景:** 测试解析 `RETIRE_CONNECTION_ID` 帧。

**假设输入 (packet_ietf 数组):**
```
unsigned char packet_ietf[] = {
  // type (short header, 4 byte packet number)
  0x43,
  // connection_id
  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
  // packet number
  0x12, 0x34, 0x56, 0x78,

  // frame type (IETF_RETIRE_CONNECTION_ID frame)
  0x19,
  // sequence number
  kVarInt62TwoBytes + 0x11, 0x22
};
```

**预期输出 (visitor_ 成员的状态):**

* `visitor_.retire_connection_id_.sequence_number` 等于 `0x1122u`。
* `visitor_.error()` 返回 `QuicNoError()`。
* `visitor_.header_` 不为空。
* `visitor_.stream_frames_` 的大小为 0。
* `visitor_.ack_frames_` 的大小为 0。

**用户或编程常见的使用错误:**

1. **构建错误的帧:**  开发者在手动构建 QUIC 数据包时，可能会错误地设置帧的类型、长度或字段，导致 `QuicFramer` 解析失败。
    * **示例:** 构建 `ACK` 帧时，`largest_observed` 设置为 0，如 `TEST_P(QuicFramerTest, AckFrameWithInvalidLargestObserved)`  测试所示。
2. **不正确的解密配置:**  当接收到加密的 QUIC 数据包时，如果 `QuicFramer` 没有配置正确的解密器，会导致解密失败。
    * **示例:** 接收到需要 `ENCRYPTION_HANDSHAKE` 解密的包，但 `QuicFramer` 没有安装对应的解密器，如 `TEST_P(QuicFramerTest, UndecryptablePacketWithoutDecrypter)` 测试所示。
3. **处理合并包时的版本不匹配:** 在处理合并包时，如果不同的包使用了不兼容的 QUIC 版本，可能会导致处理错误。
    * **示例:** 合并包中的第二个包使用了不同的版本号，如 `TEST_P(QuicFramerTest, CoalescedPacketWithDifferentVersion)` 测试所示。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在 Chrome 浏览器中访问一个使用 QUIC 协议的网站：

1. **用户在地址栏输入 URL 并回车。**
2. **Chrome 浏览器的网络栈开始建立与服务器的连接。** 这可能包括 DNS 查询、TLS 握手（如果初始连接未使用 QUIC）等步骤。
3. **如果确定使用 QUIC 协议，浏览器会发送 QUIC 连接建立请求。**
4. **服务器响应 QUIC 连接建立响应。**
5. **在连接建立后，浏览器和服务器之间的数据传输会使用 QUIC 数据包。**
6. **当浏览器接收到来自服务器的 QUIC 数据包时，网络栈会将这些原始字节流传递给 `QuicFramer`。**
7. **`QuicFramer` 根据 QUIC 协议的格式解析这些字节流，识别出其中的帧。**  例如，如果服务器发送了一个包含网页数据的 STREAM 帧，`QuicFramer` 会提取出流 ID、偏移量和数据内容。
8. **在测试场景中，我们人为构造各种 QUIC 数据包（例如，包含 `RETIRE_CONNECTION_ID` 帧、错误的 `ACK` 帧或合并包），并将它们传递给 `QuicFramer` 的 `ProcessPacket` 方法进行测试。**  测试的目标是验证 `QuicFramer` 在各种情况下是否能正确解析数据包，处理错误，或者按预期构建数据包。

**作为第 13 部分，共 16 部分的功能归纳:**

从提供的代码片段来看，第 13 部分的测试主要集中在以下几个方面：

* **控制帧处理的健壮性:**  特别是 `RETIRE_CONNECTION_ID` 帧和 `ACK` 帧的处理，包括正确解析和错误处理。
* **QUIC 的关键特性测试:**  合并包的处理是 QUIC 的一个重要优化，这部分测试验证了 `QuicFramer` 对合并包的解析能力，包括不同场景下的处理（例如，带填充、版本不匹配）。
* **错误处理和安全性:**  测试无法解密的包的处理，确保 `QuicFramer` 在遇到异常情况时能够正确处理，避免崩溃或安全漏洞。

总的来说，第 13 部分的测试旨在验证 `QuicFramer` 在处理各种类型的 QUIC 数据包（包括正常情况和异常情况）时的正确性和健壮性，确保其能够可靠地解析网络数据，为上层 QUIC 协议逻辑提供准确的帧信息。这对于保障 QUIC 连接的稳定性和安全性至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第13部分，共16部分，请归纳一下它的功能
```

### 源代码
```cpp
QuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());

  EXPECT_EQ(0x1122u, visitor_.retire_connection_id_.sequence_number);

  ASSERT_EQ(0u, visitor_.ack_frames_.size());

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_RETIRE_CONNECTION_ID_DATA);
}

TEST_P(QuicFramerTest, BuildRetireConnectionIdFramePacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for version 99.
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicRetireConnectionIdFrame frame;
  frame.sequence_number = 0x1122;

  QuicFrames frames = {QuicFrame(&frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_RETIRE_CONNECTION_ID frame)
    0x19,
    // sequence number
    kVarInt62TwoBytes + 0x11, 0x22
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, AckFrameWithInvalidLargestObserved) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (ack frame)
    0x45,
    // largest observed
    0x00, 0x00,
    // Zero delta time.
    0x00, 0x00,
    // first ack block length.
    0x00, 0x00,
    // num timestamps.
    0x00
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
    // Largest acked
    kVarInt62OneByte + 0x00,
    // Zero delta time.
    kVarInt62OneByte + 0x00,
    // Ack block count 0
    kVarInt62OneByte + 0x00,
    // First ack block length
    kVarInt62OneByte + 0x00,
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_size, false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(framer_.detailed_error(), "Largest acked is 0.");
}

TEST_P(QuicFramerTest, FirstAckBlockJustUnderFlow) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (ack frame)
    0x45,
    // largest observed
    0x00, 0x02,
    // Zero delta time.
    0x00, 0x00,
    // first ack block length.
    0x00, 0x03,
    // num timestamps.
    0x00
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
    // Largest acked
    kVarInt62OneByte + 0x02,
    // Zero delta time.
    kVarInt62OneByte + 0x00,
    // Ack block count 0
    kVarInt62OneByte + 0x00,
    // First ack block length
    kVarInt62OneByte + 0x02,
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_size, false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(framer_.detailed_error(),
            "Underflow with first ack block length 3 largest acked is 2.");
}

TEST_P(QuicFramerTest, ThirdAckBlockJustUnderflow) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (ack frame)
    0x60,
    // largest observed
    0x0A,
    // Zero delta time.
    0x00, 0x00,
    // Num of ack blocks
    0x02,
    // first ack block length.
    0x02,
    // gap to next block
    0x01,
    // ack block length
    0x01,
    // gap to next block
    0x01,
    // ack block length
    0x06,
    // num timestamps.
    0x00
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
    // Largest acked
    kVarInt62OneByte + 0x0A,
    // Zero delta time.
    kVarInt62OneByte + 0x00,
    // Ack block count 2
    kVarInt62OneByte + 0x02,
    // First ack block length
    kVarInt62OneByte + 0x01,
    // gap to next block length
    kVarInt62OneByte + 0x00,
    // ack block length
    kVarInt62OneByte + 0x00,
    // gap to next block length
    kVarInt62OneByte + 0x00,
    // ack block length
    kVarInt62OneByte + 0x05,
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_size, false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    EXPECT_EQ(framer_.detailed_error(),
              "Underflow with ack block length 6 latest ack block end is 5.");
  } else {
    EXPECT_EQ(framer_.detailed_error(),
              "Underflow with ack block length 6, end of block is 6.");
  }
}

TEST_P(QuicFramerTest, CoalescedPacket) {
  if (!QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  unsigned char packet[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x79,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'H',  'E',  'L',  'L',
      'O',  '_',  'W',  'O',
      'R',  'L',  'D',  '?',
  };
  unsigned char packet_ietf[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x79,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'H',  'E',  'L',  'L',
      'O',  '_',  'W',  'O',
      'R',  'L',  'D',  '?',
  };
  // clang-format on
  const size_t first_packet_ietf_size = 46;
  // If the first packet changes, the attempt to fix the first byte of the
  // second packet will fail.
  EXPECT_EQ(packet_ietf[first_packet_ietf_size], 0xD3);

  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasIetfQuicFrames()) {
    ReviseFirstByteByVersion(packet_ietf);
    ReviseFirstByteByVersion(&packet_ietf[first_packet_ietf_size]);
    p = packet_ietf;
    p_length = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());

  // Stream ID should be the last 3 bytes of kStreamId.
  EXPECT_EQ(0x00FFFFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  ASSERT_EQ(visitor_.coalesced_packets_.size(), 1u);
  EXPECT_TRUE(framer_.ProcessPacket(*visitor_.coalesced_packets_[0].get()));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());

  ASSERT_EQ(2u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());

  // Stream ID should be the last 3 bytes of kStreamId.
  EXPECT_EQ(0x00FFFFFF & kStreamId, visitor_.stream_frames_[1]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[1]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[1]->offset);
  CheckStreamFrameData("HELLO_WORLD?", visitor_.stream_frames_[1].get());
}

TEST_P(QuicFramerTest, CoalescedPacketWithUdpPadding) {
  if (!framer_.version().HasLongHeaderLengths()) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  unsigned char packet[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // padding
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
  };
  unsigned char packet_ietf[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
      // padding
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasIetfQuicFrames()) {
    ReviseFirstByteByVersion(packet_ietf);
    p = packet_ietf;
    p_length = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());

  // Stream ID should be the last 3 bytes of kStreamId.
  EXPECT_EQ(0x00FFFFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  EXPECT_EQ(visitor_.coalesced_packets_.size(), 0u);
}

TEST_P(QuicFramerTest, CoalescedPacketWithDifferentVersion) {
  if (!QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  unsigned char packet[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // garbage version
      'G', 'A', 'B', 'G',
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x79,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'H',  'E',  'L',  'L',
      'O',  '_',  'W',  'O',
      'R',  'L',  'D',  '?',
  };
  unsigned char packet_ietf[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // garbage version
      'G', 'A', 'B', 'G',
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x79,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'H',  'E',  'L',  'L',
      'O',  '_',  'W',  'O',
      'R',  'L',  'D',  '?',
  };
  // clang-format on
  const size_t first_packet_ietf_size = 46;
  // If the first packet changes, the attempt to fix the first byte of the
  // second packet will fail.
  EXPECT_EQ(packet_ietf[first_packet_ietf_size], 0xD3);

  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasIetfQuicFrames()) {
    ReviseFirstByteByVersion(packet_ietf);
    ReviseFirstByteByVersion(&packet_ietf[first_packet_ietf_size]);
    p = packet_ietf;
    p_length = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());

  // Stream ID should be the last 3 bytes of kStreamId.
  EXPECT_EQ(0x00FFFFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  ASSERT_EQ(visitor_.coalesced_packets_.size(), 1u);
  EXPECT_TRUE(framer_.ProcessPacket(*visitor_.coalesced_packets_[0].get()));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  // Verify version mismatch gets reported.
  EXPECT_EQ(1, visitor_.version_mismatch_);
}

TEST_P(QuicFramerTest, UndecryptablePacketWithoutDecrypter) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  if (!framer_.version().KnowsWhichDecrypterToUse()) {
    // We create a bad client decrypter by using initial encryption with a
    // bogus connection ID; it should fail to decrypt everything.
    QuicConnectionId bogus_connection_id = TestConnectionId(0xbad);
    CrypterPair bogus_crypters;
    CryptoUtils::CreateInitialObfuscators(Perspective::IS_CLIENT,
                                          framer_.version(),
                                          bogus_connection_id, &bogus_crypters);
    // This removes all other decrypters.
    framer_.SetDecrypter(ENCRYPTION_FORWARD_SECURE,
                         std::move(bogus_crypters.decrypter));
  }

  // clang-format off
  unsigned char packet[] = {
    // public flags (long header with packet type HANDSHAKE and
    // 4-byte packet number)
    0xE3,
    // version
    QUIC_VERSION_BYTES,
    // connection ID lengths
    0x05,
    // source connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // long header packet length
    0x05,
    // packet number
    0x12, 0x34, 0x56, 0x00,
    // padding frames
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  unsigned char packet49[] = {
    // public flags (long header with packet type HANDSHAKE and
    // 4-byte packet number)
    0xE3,
    // version
    QUIC_VERSION_BYTES,
    // destination connection ID length
    0x00,
    // source connection ID length
    0x08,
    // source connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // long header packet length
    0x24,
    // packet number
    0x12, 0x34, 0x56, 0x00,
    // padding frames
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  // clang-format on
  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasLongHeaderLengths()) {
    ReviseFirstByteByVersion(packet49);
    p = packet49;
    p_length = ABSL_ARRAYSIZE(packet49);
  }
  // First attempt decryption without the handshake crypter.
  EXPECT_FALSE(
      framer_.ProcessPacket(QuicEncryptedPacket(AsChars(p), p_length, false)));
  EXPECT_THAT(framer_.error(), IsError(QUIC_DECRYPTION_FAILURE));
  ASSERT_EQ(1u, visitor_.undecryptable_packets_.size());
  ASSERT_EQ(1u, visitor_.undecryptable_decryption_levels_.size());
  ASSERT_EQ(1u, visitor_.undecryptable_has_decryption_keys_.size());
  quiche::test::CompareCharArraysWithHexError(
      "undecryptable packet", visitor_.undecryptable_packets_[0]->data(),
      visitor_.undecryptable_packets_[0]->length(), AsChars(p), p_length);
  if (framer_.version().KnowsWhichDecrypterToUse()) {
    EXPECT_EQ(ENCRYPTION_HANDSHAKE,
              visitor_.undecryptable_decryption_levels_[0]);
  }
  EXPECT_FALSE(visitor_.undecryptable_has_decryption_keys_[0]);
}

TEST_P(QuicFramerTest, UndecryptablePacketWithDecrypter) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  // We create a bad client decrypter by using initial encryption with a
  // bogus connection ID; it should fail to decrypt everything.
  QuicConnectionId bogus_connection_id = TestConnectionId(0xbad);
  CrypterPair bad_handshake_crypters;
  CryptoUtils::CreateInitialObfuscators(Perspective::IS_CLIENT,
                                        framer_.version(), bogus_connection_id,
                                        &bad_handshake_crypters);
  if (framer_.version().KnowsWhichDecrypterToUse()) {
    framer_.InstallDecrypter(ENCRYPTION_HANDSHAKE,
                             std::move(bad_handshake_crypters.decrypter));
  } else {
    framer_.SetDecrypter(ENCRYPTION_HANDSHAKE,
                         std::move(bad_handshake_crypters.decrypter));
  }

  // clang-format off
  unsigned char packet[] = {
    // public flags (long header with packet type HANDSHAKE and
    // 4-byte packet number)
    0xE3,
    // version
    QUIC_VERSION_BYTES,
    // connection ID lengths
    0x05,
    // source connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // long header packet length
    0x05,
    // packet number
    0x12, 0x34, 0x56, 0x00,
    // padding frames
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  unsigned char packet49[] = {
    // public flags (long header with packet type HANDSHAKE and
    // 4-byte packet number)
    0xE3,
    // version
    QUIC_VERSION_BYTES,
    // destination connection ID length
    0x00,
    // source connection ID length
    0x08,
    // source connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // long header packet length
    0x24,
    // packet number
    0x12, 0x34, 0x56, 0x00,
    // padding frames
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  // clang-format on
  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasLongHeaderLengths()) {
    ReviseFirstByteByVersion(packet49);
    p = packet49;
    p_length = ABSL_ARRAYSIZE(packet49);
  }

  EXPECT_FALSE(
      framer_.ProcessPacket(QuicEncryptedPacket(AsChars(p), p_length, false)));
  EXPECT_THAT(framer_.error(), IsError(QUIC_DECRYPTION_FAILURE));
  ASSERT_EQ(1u, visitor_.undecryptable_packets_.size());
  ASSERT_EQ(1u, visitor_.undecryptable_decryption_levels_.size());
  ASSERT_EQ(1u, visitor_.undecryptable_has_decryption_keys_.size());
  quiche::test::CompareCharArraysWithHexError(
      "undecryptable packet", visitor_.undecryptable_packets_[0]->data(),
      visitor_.undecryptable_packets_[0]->length(), AsChars(p), p_length);
  if (framer_.version().KnowsWhichDecrypterToUse()) {
    EXPECT_EQ(ENCRYPTION_HANDSHAKE,
              visitor_.undecryptable_decryption_levels_[0]);
  }
  EXPECT_EQ(framer_.version().KnowsWhichDecrypterToUse(),
            visitor_.undecryptable_has_decryption_keys_[0]);
}

TEST_P(QuicFramerTest, UndecryptableCoalescedPacket) {
  if (!QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // We create a bad client decrypter by using initial encryption with a
  // bogus connection ID; it should fail to decrypt everything.
  QuicConnectionId bogus_connection_id = TestConnectionId(0xbad);
  CrypterPair bad_handshake_crypters;
  CryptoUtils::CreateInitialObfuscators(Perspective::IS_CLIENT,
                                        framer_.version(), bogus_connection_id,
                                        &bad_handshake_crypters);
  framer_.InstallDecrypter(ENCRYPTION_HANDSHAKE,
                           std::move(bad_handshake_crypters.decrypter));
  // clang-format off
  unsigned char packet[] = {
    // first coalesced packet
      // public flags (long header with packet type HANDSHAKE and
      // 4-byte packet number)
      0xE3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x79,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'H',  'E',  'L',  'L',
      'O',  '_',  'W',  'O',
      'R',  'L',  'D',  '?',
  };
  unsigned char packet_ietf[] = {
    // first coalesced packet
      // public flags (long header with packet type HANDSHAKE and
      // 4-byte packet number)
      0xE3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x79,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'H',  'E',  'L',  'L',
      'O',  '_',  'W',  'O',
      'R',  'L',  'D',  '?',
  };
  // clang-format on
  const size_t length_of_first_coalesced_packet = 46;
  // If the first packet changes, the attempt to fix the first byte of the
  // second packet will fail.
  EXPECT_EQ(packet_ietf[length_of_first_coalesced_packet], 0xD3);

  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasIetfQuicFrames()) {
    ReviseFirstByteByVersion(packet_ietf);
    ReviseFirstByteByVersion(&packet_ietf[length_of_first_coalesced_packet]);
    p = packet_ietf;
    p_length = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);

  EXPECT_FALSE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsError(QUIC_DECRYPTION_FAILURE));

  ASSERT_EQ(1u, visitor_.undecryptable_packets_.size());
  ASSERT_EQ(1u, visitor_.undecryptable_decryption_levels_.size());
  ASSERT_EQ(1u, visitor_.undecryptable_has_decryption_keys_.size());
  // Make sure we only receive the first undecryptable packet and not the
  // full packet including the second coalesced packet.
  quiche::test::CompareCharArraysWithHexError(
      "undecryptable packet", visitor_.undecryptable_packets_[0]->data(),
      visitor_.undecryptable_packets_[0]->length(), AsChars(p),
      length_of_first_coalesced_packet);
  EXPECT_EQ(ENCRYPTION_HANDSHAKE, visitor_.undecryptable_decryption_levels_[0]);
  EXPECT_TRUE(visitor_.undecryptable_has_decryption_keys_[0]);

  // Make sure the second coalesced pa
```
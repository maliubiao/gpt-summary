Response:
The user wants a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc`.

Specifically, the user is asking for:
1. **Functionality:** What does the code do?
2. **Relation to Javascript:**  Is there a connection to Javascript?
3. **Logical Reasoning (with examples):** Provide input/output scenarios for logical deductions.
4. **Common Usage Errors:**  Illustrate typical mistakes users or programmers might make.
5. **User Steps to Reach Here (Debugging):** How might a user's actions lead to this code being executed?
6. **Summary of Functionality (Part 5 of 16):**  A concise overview of the covered functionality in this specific section.

Let's break down the provided code snippet:

- **Test Structure:** The code uses Google Test (`TEST_P`) to define various test cases for the `QuicFramer`.
- **Frame Processing:** The tests focus on processing different types of QUIC frames received in encrypted packets.
- **Error Handling:** Many tests verify that the `QuicFramer` correctly identifies and reports errors when encountering invalid frame data.
- **IETF QUIC Support:** The code differentiates between Google QUIC and IETF QUIC frame formats using `VersionHasIetfQuicFrames`.
- **Specific Frame Types Tested in This Snippet:**
    - ACK with receive timestamps (including error conditions)
    - ACK with legacy timestamps (including error conditions)
    - STOP_WAITING (Google QUIC only)
    - RST_STREAM
    - CONNECTION_CLOSE (both transport and application variants)
    - GOAWAY (Google QUIC only)
    - WINDOW_UPDATE (Google QUIC only)
    - MAX_DATA (IETF QUIC only)
    - MAX_STREAM_DATA (IETF QUIC only)

**Plan:**
1. Summarize the overall functionality of the file.
2. Analyze the specific tests in the provided snippet to identify the covered functionalities.
3. Determine if there's a direct relationship with Javascript (likely not, but need to confirm).
4. Create hypothetical input/output examples for some of the error scenarios.
5. Provide examples of common usage errors related to QUIC frame construction or interpretation.
6. Outline how user actions in a web browser could lead to this code being involved.
7. Summarize the functionality covered in this specific part (focusing on the frame types).
这是位于 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 的 Chromium 网络栈源代码文件的一部分，它主要的功能是**测试 QUIC 协议帧的解析和处理逻辑**。更具体地说，这部分代码专注于测试 `QuicFramer` 类在处理各种类型的 QUIC 帧时是否能够正确地识别、解析帧的内容，并在遇到错误时进行相应的处理。

**功能归纳 (针对提供的代码片段):**

这段代码主要测试了 `QuicFramer` 类在处理以下几种 QUIC 帧时的行为：

* **ACK 帧 (包含接收时间戳):** 测试了带有接收时间戳的 ACK 帧的解析，包括了接收时间戳计数过多和时间戳增量过大的错误情况。
* **ACK 帧 (旧格式时间戳):**  测试了旧格式的 ACK 帧（非 IETF QUIC）中时间戳增量过大的错误情况。
* **STOP_WAITING 帧:**  测试了对 `STOP_WAITING` 帧的解析（仅在 Google QUIC 中存在）。同时测试了无效的 `STOP_WAITING` 帧数据。
* **RST_STREAM 帧:** 测试了对 `RST_STREAM` 帧的解析，包括 Google QUIC 和 IETF QUIC 的不同格式。
* **CONNECTION_CLOSE 帧:** 测试了对 `CONNECTION_CLOSE` 帧的解析，包括了 Google QUIC 和 IETF QUIC 的传输层和应用层关闭帧，以及处理未知错误码的情况。
* **GOAWAY 帧:** 测试了对 `GOAWAY` 帧的解析（仅在 Google QUIC 中存在），包括处理未知错误码的情况。
* **WINDOW_UPDATE 帧:** 测试了对 `WINDOW_UPDATE` 帧的解析（仅在 Google QUIC 中存在）。
* **MAX_DATA 帧:** 测试了对 IETF QUIC 的 `MAX_DATA` 帧的解析。
* **MAX_STREAM_DATA 帧:** 测试了对 IETF QUIC 的 `MAX_STREAM_DATA` 帧的解析。

**与 Javascript 的关系:**

QUIC 协议是 HTTP/3 的底层传输协议，而 HTTP/3 是 Web 技术的一部分，因此与 Javascript 在宏观上存在关联。然而，`quic_framer_test.cc` 是 C++ 代码，专注于 QUIC 协议本身的实现细节。它**不直接与 Javascript 代码交互**。

虽然这段 C++ 代码不直接涉及 Javascript，但其正确性直接影响到基于浏览器的 Web 应用（使用 Javascript 开发）的性能和稳定性。如果 QUIC 帧的解析出现错误，可能会导致网络连接中断、数据传输失败等问题，最终影响用户在浏览器中的体验。

**举例说明:**

假设一个 Javascript 应用通过 HTTP/3 发送了一个请求，服务器返回一个包含 `CONNECTION_CLOSE` 帧的响应，指示连接需要关闭。

* **假设输入:**  一个包含以下内容的 `QuicEncryptedPacket` (对应 `TEST_P(QuicFramerTest, ConnectionCloseFrame)` 中的 `packet_ietf`)：
    ```
    { 0x43 }, // type (short header, 4 byte packet number)
    { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 }, // connection_id
    { 0x12, 0x34, 0x56, 0x78 }, // packet number
    { 0x1c }, // frame type (IETF Transport CONNECTION_CLOSE frame)
    { kVarInt62TwoBytes + 0x00, 0x11 }, // error code (17)
    { kVarInt62TwoBytes + 0x12, 0x34 }, // frame type
    { kVarInt62OneByte + 0x11, '1',  '1',  '5',  ':', 'b',  'e',  'c',  'a', 'u',  's',  'e',  ' ', 'I',  ' ',  'c',  'a', 'n' } // error details
    ```
* **逻辑推理:** `QuicFramer::ProcessPacket` 函数会解析这个数据包，识别出 `CONNECTION_CLOSE` 帧，提取出错误码 (0x11) 和错误详情 ("115:because I can")，并通知 `visitor_` (一个模拟的帧处理器)。
* **预期输出:** `visitor_.connection_close_frame_.wire_error_code` 将是 `0x11`， `visitor_.connection_close_frame_.error_details` 将是 `"because I can"`， `visitor_.connection_close_frame_.quic_error_code` 将是 `115`，`visitor_.connection_close_frame_.transport_close_frame_type` 将是 `0x1234`。

**用户或编程常见的使用错误:**

* **构造错误的帧数据:** 程序员在实现 QUIC 协议时，可能会错误地构造帧数据，例如，设置了超出范围的时间戳增量 (`TEST_P(QuicFramerTest, AckFrameReceiveTimestampDeltaTooHigh)`)，或者提供了无效的停止等待帧数据 (`TEST_P(QuicFramerTest, InvalidNewStopWaitingFrame)`)。
* **错误地处理帧类型:**  接收端可能会错误地判断接收到的帧类型，导致使用错误的解析逻辑。虽然这不是这个测试文件直接测试的内容，但 `QuicFramer` 的正确解析是避免这类错误的基础。
* **忽略错误状态:**  开发者可能没有正确检查 `QuicFramer::ProcessPacket` 的返回值或 `framer_.error()`，从而忽略了帧解析过程中发生的错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个使用 HTTP/3 的网站。**
2. **浏览器与服务器建立 QUIC 连接。**
3. **在连接过程中，服务器可能因为某些原因（例如，达到连接限制、发生内部错误）决定关闭连接。**
4. **服务器会发送一个包含 `CONNECTION_CLOSE` 帧的 QUIC 数据包给浏览器。**
5. **浏览器接收到这个加密的数据包。**
6. **浏览器的 QUIC 实现会解密数据包，并调用 `QuicFramer::ProcessPacket` 来解析其中的帧。**
7. **如果 `CONNECTION_CLOSE` 帧的格式不正确，`QuicFramer` 可能会检测到错误，如 `QUIC_INVALID_CONNECTION_CLOSE_DATA`。**
8. **开发者在调试时，可能会查看 `framer_.detailed_error()` 的输出，例如 "Unable to read connection close error code."，从而定位到帧解析失败的原因，并最终可能追溯到 `quic_framer_test.cc` 中相应的测试用例。**

**这段代码的功能归纳 (第 5 部分，共 16 部分):**

作为测试套件的一部分，这第 5 部分主要集中在 **验证 `QuicFramer` 类正确解析和处理多种控制帧（ACK、STOP_WAITING、RST_STREAM、CONNECTION_CLOSE、GOAWAY、WINDOW_UPDATE、MAX_DATA、MAX_STREAM_DATA）的能力，并覆盖了在解析这些帧时可能出现的各种错误场景。** 这些测试确保了 `QuicFramer` 能够可靠地识别和提取帧中的关键信息，为 QUIC 连接的稳定运行奠定了基础。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共16部分，请归纳一下它的功能

"""
ramerTest, AckFrameReceiveTimestampCountTooHigh) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       { 0x43 }},
      // connection_id
      {"",
       { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 }},
      // packet number
      {"",
       { 0x12, 0x34, 0x56, 0x78 }},

      // frame type (IETF_ACK_RECEIVE_TIMESTAMPS frame)
      {"",
       { 0x22 }},
       // largest acked
       {"Unable to read largest acked.",
        { kVarInt62TwoBytes + 0x12, 0x34 }},   // = 4660
       // Zero delta time.
       {"Unable to read ack delay time.",
        { kVarInt62OneByte + 0x00 }},
       // number of additional ack blocks
       {"Unable to read ack block count.",
        { kVarInt62OneByte + 0x00 }},
       // first ack block length.
       {"Unable to read first ack block length.",
        { kVarInt62OneByte + 0x00 }},  // 1st block length = 1

       // Receive Timestamps.
       { "Unable to read receive timestamp range count.",
         { kVarInt62OneByte + 0x01 }},
       { "Unable to read receive timestamp gap.",
         { kVarInt62OneByte + 0x02 }},
       { "Unable to read receive timestamp count.",
         { kVarInt62OneByte + 0x02 }},
       { "Unable to read receive timestamp delta.",
         { kVarInt62OneByte + 0x0a}},
       { "Unable to read receive timestamp delta.",
         { kVarInt62OneByte + 0x0b}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));

  framer_.set_process_timestamps(true);
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_TRUE(absl::StartsWith(framer_.detailed_error(),
                               "Receive timestamp delta too high."));
}

TEST_P(QuicFramerTest, AckFrameReceiveTimestampDeltaTooHigh) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       { 0x43 }},
      // connection_id
      {"",
       { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 }},
      // packet number
      {"",
       { 0x12, 0x34, 0x56, 0x78 }},

      // frame type (IETF_ACK_RECEIVE_TIMESTAMPS frame)
      {"",
       { 0x22 }},
       // largest acked
       {"Unable to read largest acked.",
        { kVarInt62TwoBytes + 0x12, 0x34 }},   // = 4660
       // Zero delta time.
       {"Unable to read ack delay time.",
        { kVarInt62OneByte + 0x00 }},
       // number of additional ack blocks
       {"Unable to read ack block count.",
        { kVarInt62OneByte + 0x00 }},
       // first ack block length.
       {"Unable to read first ack block length.",
        { kVarInt62OneByte + 0x00 }},  // 1st block length = 1

       // Receive Timestamps.
       { "Unable to read receive timestamp range count.",
         { kVarInt62OneByte + 0x01 }},
       { "Unable to read receive timestamp gap.",
         { kVarInt62OneByte + 0x02 }},
       { "Unable to read receive timestamp count.",
         { kVarInt62FourBytes + 0x12, 0x34, 0x56, 0x77 }},
       { "Unable to read receive timestamp delta.",
         { kVarInt62TwoBytes + 0x29, 0xff}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));

  framer_.set_process_timestamps(true);
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_TRUE(absl::StartsWith(framer_.detailed_error(),
                               "Receive timestamp count too high."));
}

TEST_P(QuicFramerTest, AckFrameTimeStampDeltaTooHigh) {
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
      // (no ack blocks, 1 byte largest observed, 1 byte block length)
      0x40,
      // largest acked
      0x01,
      // Zero delta time.
      0x00, 0x00,
      // first ack block length.
      0x01,
      // num timestamps.
      0x01,
      // Delta from largest observed.
      0x01,
      // Delta time.
      0x10, 0x32, 0x54, 0x76,
  };
  // clang-format on
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // ACK Timestamp is not a feature of IETF QUIC.
    return;
  }
  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_TRUE(absl::StartsWith(framer_.detailed_error(),
                               "delta_from_largest_observed too high"));
}

TEST_P(QuicFramerTest, AckFrameTimeStampSecondDeltaTooHigh) {
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
      // (no ack blocks, 1 byte largest observed, 1 byte block length)
      0x40,
      // largest acked
      0x03,
      // Zero delta time.
      0x00, 0x00,
      // first ack block length.
      0x03,
      // num timestamps.
      0x02,
      // Delta from largest observed.
      0x01,
      // Delta time.
      0x10, 0x32, 0x54, 0x76,
      // Delta from largest observed.
      0x03,
      // Delta time.
      0x10, 0x32,
  };
  // clang-format on
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // ACK Timestamp is not a feature of IETF QUIC.
    return;
  }
  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_TRUE(absl::StartsWith(framer_.detailed_error(),
                               "delta_from_largest_observed too high"));
}

TEST_P(QuicFramerTest, NewStopWaitingFrame) {
  if (VersionHasIetfQuicFrames(version_.transport_version)) {
    // The Stop Waiting frame is not in IETF QUIC
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (stop waiting frame)
      {"",
       {0x06}},
      // least packet number awaiting an ack, delta from packet number.
      {"Unable to read least unacked delta.",
        {0x00, 0x00, 0x00, 0x08}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  ASSERT_EQ(1u, visitor_.stop_waiting_frames_.size());
  const QuicStopWaitingFrame& frame = *visitor_.stop_waiting_frames_[0];
  EXPECT_EQ(kLeastUnacked, frame.least_unacked);

  CheckFramingBoundaries(packet, QUIC_INVALID_STOP_WAITING_DATA);
}

TEST_P(QuicFramerTest, InvalidNewStopWaitingFrame) {
  // The Stop Waiting frame is not in IETF QUIC
  if (VersionHasIetfQuicFrames(version_.transport_version)) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,
    // frame type (stop waiting frame)
    0x06,
    // least packet number awaiting an ack, delta from packet number.
    0x57, 0x78, 0x9A, 0xA8,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_STOP_WAITING_DATA));
  EXPECT_EQ("Invalid unacked delta.", framer_.detailed_error());
}

TEST_P(QuicFramerTest, RstStreamFrame) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (rst stream frame)
      {"",
       {0x01}},
      // stream id
      {"Unable to read stream_id.",
       {0x01, 0x02, 0x03, 0x04}},
      // sent byte offset
      {"Unable to read rst stream sent byte offset.",
       {0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      // error code QUIC_STREAM_CANCELLED
      {"Unable to read rst stream error code.",
       {0x00, 0x00, 0x00, 0x06}}
  };

  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (IETF_RST_STREAM frame)
      {"",
       {0x04}},
      // stream id
      {"Unable to read IETF_RST_STREAM frame stream id/count.",
       {kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04}},
      // application error code H3_REQUEST_CANCELLED gets translated to
      // QuicRstStreamErrorCode::QUIC_STREAM_CANCELLED.
      {"Unable to read rst stream error code.",
       {kVarInt62TwoBytes + 0x01, 0x0c}},
      // Final Offset
      {"Unable to read rst stream sent byte offset.",
       {kVarInt62EightBytes + 0x3a, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54}}
  };
  // clang-format on

  PacketFragments& fragments =
      VersionHasIetfQuicFrames(framer_.transport_version()) ? packet_ietf
                                                            : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(kStreamId, visitor_.rst_stream_frame_.stream_id);
  EXPECT_EQ(QUIC_STREAM_CANCELLED, visitor_.rst_stream_frame_.error_code);
  EXPECT_EQ(kStreamOffset, visitor_.rst_stream_frame_.byte_offset);
  CheckFramingBoundaries(fragments, QUIC_INVALID_RST_STREAM_DATA);
}

TEST_P(QuicFramerTest, ConnectionCloseFrame) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (connection close frame)
      {"",
       {0x02}},
      // error code
      {"Unable to read connection close error code.",
       {0x00, 0x00, 0x00, 0x11}},
      {"Unable to read connection close error details.",
       {
         // error details length
         0x0, 0x0d,
         // error details
         'b',  'e',  'c',  'a',
         'u',  's',  'e',  ' ',
         'I',  ' ',  'c',  'a',
         'n'}
      }
  };

  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (IETF Transport CONNECTION_CLOSE frame)
      {"",
       {0x1c}},
      // error code
      {"Unable to read connection close error code.",
       {kVarInt62TwoBytes + 0x00, 0x11}},
      {"Unable to read connection close frame type.",
       {kVarInt62TwoBytes + 0x12, 0x34 }},
      {"Unable to read connection close error details.",
       {
         // error details length
         kVarInt62OneByte + 0x11,
         // error details with QuicErrorCode serialized
         '1',  '1',  '5',  ':',
         'b',  'e',  'c',  'a',
         'u',  's',  'e',  ' ',
         'I',  ' ',  'c',  'a',
         'n'}
      }
  };
  // clang-format on

  PacketFragments& fragments =
      VersionHasIetfQuicFrames(framer_.transport_version()) ? packet_ietf
                                                            : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  EXPECT_EQ(0x11u, static_cast<unsigned>(
                       visitor_.connection_close_frame_.wire_error_code));
  EXPECT_EQ("because I can", visitor_.connection_close_frame_.error_details);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    EXPECT_EQ(0x1234u,
              visitor_.connection_close_frame_.transport_close_frame_type);
    EXPECT_EQ(115u, visitor_.connection_close_frame_.quic_error_code);
  } else {
    // For Google QUIC frame, |quic_error_code| and |wire_error_code| has the
    // same value.
    EXPECT_EQ(0x11u, static_cast<unsigned>(
                         visitor_.connection_close_frame_.quic_error_code));
  }

  ASSERT_EQ(0u, visitor_.ack_frames_.size());

  CheckFramingBoundaries(fragments, QUIC_INVALID_CONNECTION_CLOSE_DATA);
}

TEST_P(QuicFramerTest, ConnectionCloseFrameWithUnknownErrorCode) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (connection close frame)
      {"",
       {0x02}},
      // error code larger than QUIC_LAST_ERROR
      {"Unable to read connection close error code.",
       {0x00, 0x00, 0xC0, 0xDE}},
      {"Unable to read connection close error details.",
       {
         // error details length
         0x0, 0x0d,
         // error details
         'b',  'e',  'c',  'a',
         'u',  's',  'e',  ' ',
         'I',  ' ',  'c',  'a',
         'n'}
      }
  };

  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (IETF Transport CONNECTION_CLOSE frame)
      {"",
       {0x1c}},
      // error code
      {"Unable to read connection close error code.",
       {kVarInt62FourBytes + 0x00, 0x00, 0xC0, 0xDE}},
      {"Unable to read connection close frame type.",
       {kVarInt62TwoBytes + 0x12, 0x34 }},
      {"Unable to read connection close error details.",
       {
         // error details length
         kVarInt62OneByte + 0x11,
         // error details with QuicErrorCode larger than QUIC_LAST_ERROR
         '8',  '4',  '9',  ':',
         'b',  'e',  'c',  'a',
         'u',  's',  'e',  ' ',
         'I',  ' ',  'c',  'a',
         'n'}
      }
  };
  // clang-format on

  PacketFragments& fragments =
      VersionHasIetfQuicFrames(framer_.transport_version()) ? packet_ietf
                                                            : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  EXPECT_EQ("because I can", visitor_.connection_close_frame_.error_details);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    EXPECT_EQ(0x1234u,
              visitor_.connection_close_frame_.transport_close_frame_type);
    EXPECT_EQ(0xC0DEu, visitor_.connection_close_frame_.wire_error_code);
    EXPECT_EQ(849u, visitor_.connection_close_frame_.quic_error_code);
  } else {
    // For Google QUIC frame, |quic_error_code| and |wire_error_code| has the
    // same value.
    EXPECT_EQ(0xC0DEu, visitor_.connection_close_frame_.wire_error_code);
    EXPECT_EQ(0xC0DEu, visitor_.connection_close_frame_.quic_error_code);
  }

  ASSERT_EQ(0u, visitor_.ack_frames_.size());

  CheckFramingBoundaries(fragments, QUIC_INVALID_CONNECTION_CLOSE_DATA);
}

// As above, but checks that for Google-QUIC, if there happens
// to be an ErrorCode string at the start of the details, it is
// NOT extracted/parsed/folded/spindled/and/mutilated.
TEST_P(QuicFramerTest, ConnectionCloseFrameWithExtractedInfoIgnoreGCuic) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet = {
    // type (short header, 4 byte packet number)
    {"",
     {0x43}},
    // connection_id
    {"",
     {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
    // packet number
    {"",
     {0x12, 0x34, 0x56, 0x78}},
    // frame type (connection close frame)
    {"",
     {0x02}},
    // error code
    {"Unable to read connection close error code.",
     {0x00, 0x00, 0x00, 0x11}},
    {"Unable to read connection close error details.",
     {
       // error details length
       0x0, 0x13,
       // error details
      '1',  '7',  '7',  '6',
      '7',  ':',  'b',  'e',
      'c',  'a',  'u',  's',
      'e',  ' ',  'I',  ' ',
      'c',  'a',  'n'}
    }
  };

  PacketFragments packet_ietf = {
    // type (short header, 4 byte packet number)
    {"",
     {0x43}},
    // connection_id
    {"",
     {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
    // packet number
    {"",
     {0x12, 0x34, 0x56, 0x78}},
    // frame type (IETF Transport CONNECTION_CLOSE frame)
    {"",
     {0x1c}},
    // error code
    {"Unable to read connection close error code.",
     {kVarInt62OneByte + 0x11}},
    {"Unable to read connection close frame type.",
     {kVarInt62TwoBytes + 0x12, 0x34 }},
    {"Unable to read connection close error details.",
     {
       // error details length
       kVarInt62OneByte + 0x13,
       // error details
      '1',  '7',  '7',  '6',
      '7',  ':',  'b',  'e',
      'c',  'a',  'u',  's',
      'e',  ' ',  'I',  ' ',
      'c',  'a',  'n'}
    }
  };
  // clang-format on

  PacketFragments& fragments =
      VersionHasIetfQuicFrames(framer_.transport_version()) ? packet_ietf
                                                            : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  EXPECT_EQ(0x11u, static_cast<unsigned>(
                       visitor_.connection_close_frame_.wire_error_code));

  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    EXPECT_EQ(0x1234u,
              visitor_.connection_close_frame_.transport_close_frame_type);
    EXPECT_EQ(17767u, visitor_.connection_close_frame_.quic_error_code);
    EXPECT_EQ("because I can", visitor_.connection_close_frame_.error_details);
  } else {
    EXPECT_EQ(0x11u, visitor_.connection_close_frame_.quic_error_code);
    // Error code is not prepended in GQUIC, so it is not removed and should
    // remain in the reason phrase.
    EXPECT_EQ("17767:because I can",
              visitor_.connection_close_frame_.error_details);
  }

  ASSERT_EQ(0u, visitor_.ack_frames_.size());

  CheckFramingBoundaries(fragments, QUIC_INVALID_CONNECTION_CLOSE_DATA);
}

// Test the CONNECTION_CLOSE/Application variant.
TEST_P(QuicFramerTest, ApplicationCloseFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only in IETF QUIC.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (IETF_CONNECTION_CLOSE/Application frame)
      {"",
       {0x1d}},
      // error code
      {"Unable to read connection close error code.",
       {kVarInt62TwoBytes + 0x00, 0x11}},
      {"Unable to read connection close error details.",
       {
         // error details length
         kVarInt62OneByte + 0x0d,
         // error details
         'b',  'e',  'c',  'a',
         'u',  's',  'e',  ' ',
         'I',  ' ',  'c',  'a',
         'n'}
      }
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());

  EXPECT_EQ(IETF_QUIC_APPLICATION_CONNECTION_CLOSE,
            visitor_.connection_close_frame_.close_type);
  EXPECT_EQ(122u, visitor_.connection_close_frame_.quic_error_code);
  EXPECT_EQ(0x11u, visitor_.connection_close_frame_.wire_error_code);
  EXPECT_EQ("because I can", visitor_.connection_close_frame_.error_details);

  ASSERT_EQ(0u, visitor_.ack_frames_.size());

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_CONNECTION_CLOSE_DATA);
}

// Check that we can extract an error code from an application close.
TEST_P(QuicFramerTest, ApplicationCloseFrameExtract) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only in IETF QUIC.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (IETF_CONNECTION_CLOSE/Application frame)
      {"",
       {0x1d}},
      // error code
      {"Unable to read connection close error code.",
       {kVarInt62OneByte + 0x11}},
      {"Unable to read connection close error details.",
       {
       // error details length
       kVarInt62OneByte + 0x13,
       // error details
       '1',  '7',  '7',  '6',
       '7',  ':',  'b',  'e',
       'c',  'a',  'u',  's',
       'e',  ' ',  'I',  ' ',
       'c',  'a',  'n'}
      }
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());

  EXPECT_EQ(IETF_QUIC_APPLICATION_CONNECTION_CLOSE,
            visitor_.connection_close_frame_.close_type);
  EXPECT_EQ(17767u, visitor_.connection_close_frame_.quic_error_code);
  EXPECT_EQ(0x11u, visitor_.connection_close_frame_.wire_error_code);
  EXPECT_EQ("because I can", visitor_.connection_close_frame_.error_details);

  ASSERT_EQ(0u, visitor_.ack_frames_.size());

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_CONNECTION_CLOSE_DATA);
}

TEST_P(QuicFramerTest, GoAwayFrame) {
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is not in IETF QUIC.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (go away frame)
      {"",
       {0x03}},
      // error code
      {"Unable to read go away error code.",
       {0x00, 0x00, 0x00, 0x09}},
      // stream id
      {"Unable to read last good stream id.",
       {0x01, 0x02, 0x03, 0x04}},
      // stream id
      {"Unable to read goaway reason.",
       {
         // error details length
         0x0, 0x0d,
         // error details
         'b',  'e',  'c',  'a',
         'u',  's',  'e',  ' ',
         'I',  ' ',  'c',  'a',
         'n'}
      }
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(kStreamId, visitor_.goaway_frame_.last_good_stream_id);
  EXPECT_EQ(0x9u, visitor_.goaway_frame_.error_code);
  EXPECT_EQ("because I can", visitor_.goaway_frame_.reason_phrase);

  CheckFramingBoundaries(packet, QUIC_INVALID_GOAWAY_DATA);
}

TEST_P(QuicFramerTest, GoAwayFrameWithUnknownErrorCode) {
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is not in IETF QUIC.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (go away frame)
      {"",
       {0x03}},
      // error code larger than QUIC_LAST_ERROR
      {"Unable to read go away error code.",
       {0x00, 0x00, 0xC0, 0xDE}},
      // stream id
      {"Unable to read last good stream id.",
       {0x01, 0x02, 0x03, 0x04}},
      // stream id
      {"Unable to read goaway reason.",
       {
         // error details length
         0x0, 0x0d,
         // error details
         'b',  'e',  'c',  'a',
         'u',  's',  'e',  ' ',
         'I',  ' ',  'c',  'a',
         'n'}
      }
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(kStreamId, visitor_.goaway_frame_.last_good_stream_id);
  EXPECT_EQ(0xC0DE, visitor_.goaway_frame_.error_code);
  EXPECT_EQ("because I can", visitor_.goaway_frame_.reason_phrase);

  CheckFramingBoundaries(packet, QUIC_INVALID_GOAWAY_DATA);
}

TEST_P(QuicFramerTest, WindowUpdateFrame) {
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is not in IETF QUIC, see MaxDataFrame and MaxStreamDataFrame
    // for IETF QUIC equivalents.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (window update frame)
      {"",
       {0x04}},
      // stream id
      {"Unable to read stream_id.",
       {0x01, 0x02, 0x03, 0x04}},
      // byte offset
      {"Unable to read window byte_offset.",
       {0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
  };

  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(kStreamId, visitor_.window_update_frame_.stream_id);
  EXPECT_EQ(kStreamOffset, visitor_.window_update_frame_.max_data);

  CheckFramingBoundaries(packet, QUIC_INVALID_WINDOW_UPDATE_DATA);
}

TEST_P(QuicFramerTest, MaxDataFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is available only in IETF QUIC.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (IETF_MAX_DATA frame)
      {"",
       {0x10}},
      // byte offset
      {"Can not read MAX_DATA byte-offset",
       {kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(QuicUtils::GetInvalidStreamId(framer_.transport_version()),
            visitor_.window_update_frame_.stream_id);
  EXPECT_EQ(kStreamOffset, visitor_.window_update_frame_.max_data);

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_MAX_DATA_FRAME_DATA);
}

TEST_P(QuicFramerTest, MaxStreamDataFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame available only in IETF QUIC.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (IETF_MAX_STREAM_DATA frame)
      {"",
       {0x11}},
      // stream id
      {"Unable to read IETF_MAX_STREAM_DATA frame stream id/count.",
       {kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04}},
      // byte offset
      {"Can not read MAX_STREAM_DATA byte-count",
       {kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(kStreamId, visitor_.window_update_frame_.stream_id);
  EXPECT_EQ(kStreamOffset, visitor_.window_update_frame_.max_data);

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_MAX_STREAM_DATA_FRAME_DATA);
}

TEST_P(QuicFramerTest, BlockedFrame) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-form
"""


```
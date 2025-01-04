Response:
The user is asking for a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc`, based on a provided code snippet. I need to identify the key operations performed in the code and explain its purpose. The user also has specific requests: check for relationships with JavaScript, provide examples with assumed inputs and outputs, point out potential usage errors, and explain how a user might reach this code during debugging.

**Code Analysis:**

The provided code snippet contains a series of C++ unit tests using the Google Test framework. Each `TEST_P` function focuses on parsing and handling different types of QUIC frames and packets. Keywords like `EXPECT_TRUE`, `EXPECT_EQ`, `ASSERT_TRUE`, `EXPECT_THAT` indicate assertions that verify the correct behavior of the `QuicFramer` class. The tests involve:

* **Packet Assembly:** Creating raw byte sequences representing QUIC packets with specific frame types (BLOCKED, PING, HANDSHAKE_DONE, ACK_FREQUENCY, RESET_STREAM_AT, MESSAGE, STATELESS_RESET, VERSION_NEGOTIATION, RETRY, PADDING, STREAM).
* **Packet Processing:** Using `framer_.ProcessPacket()` to simulate the parsing of these packets by the `QuicFramer`.
* **Verification:** Checking the internal state of a mock visitor (`visitor_`) to ensure that the `QuicFramer` correctly identifies and extracts the information from the frames. This includes checking for specific frame types, values within the frames (like stream IDs, offsets, error codes), and packet header information.
* **Error Handling:** Testing scenarios where malformed packets are processed and verifying that the `QuicFramer` correctly identifies errors.
* **Version Handling:** The code uses `VersionHasIetfQuicFrames` and similar checks, suggesting the tests cover different QUIC versions and their respective frame formats.
* **Encryption:**  The tests involve setting encryption levels and checking decryption results.
* **Packet Building:** Some tests use `BuildDataPacket` to construct outgoing packets and verify their byte-level representation.

**Functionality Summary:**

The primary function of this file is to test the `QuicFramer` class, which is responsible for parsing and interpreting incoming QUIC packets and constructing outgoing QUIC packets. It ensures that the `QuicFramer` correctly handles various QUIC frame types and packet formats according to different QUIC versions.

**Relationship to JavaScript:**

QUIC is a transport layer protocol often used in web browsers. JavaScript running in a browser might interact with QUIC indirectly through browser APIs (like `fetch` or `XMLHttpRequest` using HTTP/3, which relies on QUIC). This test file, being a low-level implementation detail of the QUIC stack, doesn't directly interact with JavaScript code. However, the correctness of the `QuicFramer` is crucial for the reliable functioning of QUIC connections initiated by JavaScript code in a browser.

**Example with Assumptions:**

* **Assume Input:** A QUIC packet arrives with a PING frame (IETF version). The raw bytes of the packet are represented by `packet_ietf` in the `PingFrame` test.
* **Expected Output:** After `framer_.ProcessPacket(encrypted)` is called, the `visitor_.ping_frames_` vector will contain one entry, indicating that the PING frame was correctly parsed. `framer_.error()` should be `IsQuicNoError()`.

**Common Usage Errors:**

A common programming error related to packet framing is constructing packets with incorrect frame structures or invalid field values. For example, in the `ParseInvalidResetStreamAtFrame` test, an invalid `reliable_offset` value is intentionally included in the packet. When the `QuicFramer` processes this packet, it should detect the inconsistency and return an error (`QUIC_INVALID_FRAME_DATA`).

**User Operation and Debugging:**

A user's action, like clicking a link or submitting a form on a website using HTTP/3, might trigger the browser to establish a QUIC connection. During the connection, the browser's QUIC implementation will use the `QuicFramer` to process incoming packets from the server. If there's an issue with packet parsing (e.g., a server sends a malformed frame), a developer debugging the browser's network stack might step into the `QuicFramer::ProcessPacket` function. The tests in this file provide specific scenarios and assertions that can help pinpoint the cause of parsing errors.

**Summary of Functionality (Part 6 of 16):**

This specific part of the `QuicFramerTest` file focuses on testing the parsing and handling of several QUIC frame types, including:

* **BLOCKED frames:** Used to signal flow control blocking.
* **PING frames:**  Simple keep-alive or round-trip time measurement.
* **HANDSHAKE_DONE frames:** Indicates the completion of the handshake process.
* **ACK_FREQUENCY frames:**  Negotiates acknowledgement frequency.
* **RESET_STREAM_AT frames:**  Indicates a stream is being reset at a specific offset.
* **MESSAGE frames:** Carries application-level data.
* **Stateless Reset Packets:**  Used to abruptly terminate a connection without state.
* **Version Negotiation Packets:** Exchanged during connection establishment to agree on a QUIC version.
* **RETRY Packets:**  Used during connection establishment to mitigate amplification attacks.
* **PADDING frames:**  Used to pad packets to a certain size.
* **STREAM frames:** Carries user data within a stream.

The tests cover both parsing incoming packets and building outgoing packets with these frame types. They also consider different QUIC versions and error conditions.

这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 文件的第 6 部分，该文件的主要功能是**测试 `QuicFramer` 类的正确性**。`QuicFramer` 负责 QUIC 协议中数据包的**解析（parsing）**和**构建（framing）**。

以下是该文件（特别是提供的代码片段）的具体功能归纳：

**主要功能:**

* **测试帧的解析:**  验证 `QuicFramer` 是否能够正确解析各种类型的 QUIC 帧，包括：
    * `BLOCKED_FRAME` (流被阻塞帧) / `IETF_STREAM_BLOCKED_FRAME`
    * `PING_FRAME`
    * `HANDSHAKE_DONE_FRAME`
    * `ACK_FREQUENCY_FRAME`
    * `RESET_STREAM_AT_FRAME`
    * `MESSAGE_FRAME`
* **测试数据包的解析:** 验证 `QuicFramer` 是否能够正确解析不同类型的 QUIC 数据包，包括：
    *  包含上述帧的数据包
    *  `STATELESS_RESET_PACKET` (无状态重置包)
    *  `VERSION_NEGOTIATION_PACKET` (版本协商包)
    *  `RETRY_PACKET` (重试包)
* **测试数据包的构建:** 验证 `QuicFramer` 是否能够正确构建包含特定帧的数据包，例如：
    * 包含 `PADDING_FRAME` 的数据包
    * 包含 `STREAM_FRAME` 和 `PADDING_FRAME` 的数据包
* **错误处理测试:** 验证 `QuicFramer` 在遇到格式错误的数据包时是否能够正确检测并报告错误。
* **版本兼容性测试:** 通过 `VersionHasIetfQuicFrames` 等函数，测试 `QuicFramer` 对不同 QUIC 版本的处理。
* **加密和解密测试:**  涉及到数据包的加密和解密过程的验证 (`SetDecrypterLevel`, `CheckDecryption`)。

**与 JavaScript 的关系:**

`QuicFramer` 本身是用 C++ 编写的，直接与 JavaScript 没有交互。然而，JavaScript 在浏览器中可以通过 Fetch API 或 WebSocket 等接口发起网络请求，这些请求可能会使用 HTTP/3 协议，而 HTTP/3 的底层传输协议正是 QUIC。

* **举例说明:** 当一个网页上的 JavaScript 代码使用 `fetch('https://example.com')` 发起一个 HTTPS 请求时，如果浏览器和服务器协商使用了 HTTP/3，那么浏览器底层的 QUIC 实现会使用 `QuicFramer` 来处理接收到的 QUIC 数据包。这些数据包中可能包含 HTTP/3 的帧，最终会被传递给 JavaScript 的回调函数。

**逻辑推理、假设输入与输出:**

**例子 1: `BlockedFrame` 测试**

* **假设输入:** 一个短头部 QUIC 数据包，包含一个 `BLOCKED_FRAME` (或 `IETF_STREAM_BLOCKED_FRAME`，取决于 QUIC 版本)。数据包的字节表示形式如下（来自代码片段）：
    ```c++
    unsigned char packet[] = {
       // type (short header, 4 byte packet number)
       0x43,
       // connection_id
       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
       // packet number
       0x12, 0x34, 0x56, 0x78,
       // frame type (blocked frame)
       0x05,
       // stream id
       0x01, 0x02, 0x03, 0x04,
    };
    ```
* **预期输出:** `framer_.ProcessPacket(*encrypted)` 返回 `true` (处理成功)。 `visitor_.error()` 为 `IsQuicNoError()`。`visitor_.header_` 不为空。`visitor_.blocked_frame_.stream_id` 等于 `kStreamId` (0x04030201)。如果使用 IETF QUIC 帧，`visitor_.blocked_frame_.offset` 将等于 `kStreamOffset`。

**例子 2: `PingFrame` 测试**

* **假设输入:** 一个短头部 QUIC 数据包，包含一个 `PING_FRAME` (或 `IETF_PING_FRAME`)。
* **预期输出:** `visitor_.ping_frames_.size()` 等于 1。

**用户或编程常见的使用错误:**

* **错误构建 QUIC 数据包:** 程序员在手动构建 QUIC 数据包时，可能会错误地设置帧类型、长度字段或校验和等。例如，在 `ParseInvalidResetStreamAtFrame` 测试中，故意设置了 `reliable_offset` 大于 `final_offset`，这是一个无效的情况。`QuicFramer` 应该能够检测到这种错误并返回 `QUIC_INVALID_FRAME_DATA`。
* **QUIC 版本不匹配:**  如果发送方和接收方使用的 QUIC 版本不一致，可能会导致帧格式不兼容，`QuicFramer` 可能会解析失败。
* **加密配置错误:** 如果解密器的配置不正确，`QuicFramer` 可能会无法正确解密数据包。

**用户操作到达此处的调试线索:**

1. **用户在浏览器中访问使用 HTTP/3 的网站:**  用户的这个操作会触发浏览器建立 QUIC 连接。
2. **网络数据包到达浏览器:**  服务器发送的 QUIC 数据包会到达用户的浏览器。
3. **浏览器网络栈处理数据包:** 浏览器的网络栈会接收到这些数据包，并交给 QUIC 协议栈处理。
4. **`QuicFramer` 进行解析:** QUIC 协议栈中的 `QuicFramer::ProcessPacket` 函数会被调用来解析这些数据包，提取其中的帧信息。
5. **调试:** 如果在数据包解析过程中出现问题，例如数据包格式错误或无法识别的帧类型，开发人员可能会在 `QuicFramer::ProcessPacket` 函数中设置断点进行调试，查看数据包的内容和 `QuicFramer` 的状态，从而定位问题所在。测试文件 `quic_framer_test.cc` 中的各种测试用例模拟了这些不同的数据包场景，帮助开发人员验证 `QuicFramer` 的正确性。

**第 6 部分功能归纳:**

第 6 部分的测试用例集中验证了 `QuicFramer` 对多种关键 QUIC 帧和数据包的处理能力，包括：流控制、保持连接、握手完成、确认频率、流重置、应用层消息、无状态重置、版本协商和重试机制。此外，还测试了构建包含填充帧和流数据帧的数据包的功能，以及对不同长度数据包序列号的处理。这部分测试是确保 `QuicFramer` 能够正确处理 QUIC 协议中各种关键交互的基础。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共16部分，请归纳一下它的功能

"""
at off
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
      // frame type (blocked frame)
      {"",
       {0x05}},
      // stream id
      {"Unable to read stream_id.",
       {0x01, 0x02, 0x03, 0x04}},
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
      // frame type (IETF_STREAM_BLOCKED frame)
      {"",
       {0x15}},
      // stream id
      {"Unable to read IETF_STREAM_DATA_BLOCKED frame stream id/count.",
       {kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04}},
      // Offset
      {"Can not read stream blocked offset.",
       {kVarInt62EightBytes + 0x3a, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54}},
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

  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    EXPECT_EQ(kStreamOffset, visitor_.blocked_frame_.offset);
  } else {
    EXPECT_EQ(0u, visitor_.blocked_frame_.offset);
  }
  EXPECT_EQ(kStreamId, visitor_.blocked_frame_.stream_id);

  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    CheckFramingBoundaries(fragments, QUIC_INVALID_STREAM_BLOCKED_DATA);
  } else {
    CheckFramingBoundaries(fragments, QUIC_INVALID_BLOCKED_DATA);
  }
}

TEST_P(QuicFramerTest, PingFrame) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
     // type (short header, 4 byte packet number)
     0x43,
     // connection_id
     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
     // packet number
     0x12, 0x34, 0x56, 0x78,

     // frame type
     0x07,
    };

  unsigned char packet_ietf[] = {
     // type (short header, 4 byte packet number)
     0x43,
     // connection_id
     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
     // packet number
     0x12, 0x34, 0x56, 0x78,

     // frame type (IETF_PING frame)
     0x01,
    };
  // clang-format on

  QuicEncryptedPacket encrypted(
      AsChars(VersionHasIetfQuicFrames(framer_.transport_version())
                  ? packet_ietf
                  : packet),
      VersionHasIetfQuicFrames(framer_.transport_version())
          ? ABSL_ARRAYSIZE(packet_ietf)
          : ABSL_ARRAYSIZE(packet),
      false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(1u, visitor_.ping_frames_.size());

  // No need to check the PING frame boundaries because it has no payload.
}

TEST_P(QuicFramerTest, HandshakeDoneFrame) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
     // type (short header, 4 byte packet number)
     0x43,
     // connection_id
     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
     // packet number
     0x12, 0x34, 0x56, 0x78,

     // frame type (Handshake done frame)
     0x1e,
    };
  // clang-format on

  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(1u, visitor_.handshake_done_frames_.size());
}

TEST_P(QuicFramerTest, ParseAckFrequencyFrame) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
     // type (short header, 4 byte packet number)
     0x43,
     // connection_id
     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
     // packet number
     0x12, 0x34, 0x56, 0x78,

     // ack frequency frame type (which needs two bytes as it is > 0x3F)
     0x40, 0xAF,
     // sequence_number
     0x11,
     // packet_tolerance
     0x02,
     // max_ack_delay_us = 2'5000 us
     0x80, 0x00, 0x61, 0xA8,
     // ignore_order
     0x01
  };
  // clang-format on

  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  ASSERT_EQ(1u, visitor_.ack_frequency_frames_.size());
  const auto& frame = visitor_.ack_frequency_frames_.front();
  EXPECT_EQ(17u, frame->sequence_number);
  EXPECT_EQ(2u, frame->packet_tolerance);
  EXPECT_EQ(2'5000u, frame->max_ack_delay.ToMicroseconds());
  EXPECT_EQ(true, frame->ignore_order);
}

TEST_P(QuicFramerTest, ParseResetStreamAtFrame) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // type = RESET_STREAM_AT
      0x24,
      // stream ID
      0x00,
      // application error code
      0x1e,
      // final size
      0x20,
      // reliable size
      0x10,
  };
  // clang-format on

  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  framer_.set_process_reset_stream_at(true);

  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  ASSERT_EQ(visitor_.reset_stream_at_frames_.size(), 1);
  const QuicResetStreamAtFrame& frame = *visitor_.reset_stream_at_frames_[0];
  EXPECT_EQ(frame.stream_id, 0x00);
  EXPECT_EQ(frame.error, 0x1e);
  EXPECT_EQ(frame.final_offset, 0x20);
  EXPECT_EQ(frame.reliable_offset, 0x10);
}

TEST_P(QuicFramerTest, ParseInvalidResetStreamAtFrame) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // type = RESET_STREAM_AT
      0x24,
      // stream ID
      0x00,
      // application error code
      0x1e,
      // final size
      0x20,
      // reliable size
      0x30,
  };
  // clang-format on

  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  framer_.set_process_reset_stream_at(true);

  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(framer_.error(), QUIC_INVALID_FRAME_DATA);
  EXPECT_EQ(visitor_.reset_stream_at_frames_.size(), 0);
}

TEST_P(QuicFramerTest, MessageFrame) {
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
       // message frame type.
       {"",
        { 0x21 }},
       // message length
       {"Unable to read message length",
        {0x07}},
       // message data
       {"Unable to read message data",
        {'m', 'e', 's', 's', 'a', 'g', 'e'}},
        // message frame no length.
        {"",
         { 0x20 }},
        // message data
        {{},
         {'m', 'e', 's', 's', 'a', 'g', 'e', '2'}},
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
       // message frame type.
       {"",
        { 0x31 }},
       // message length
       {"Unable to read message length",
        {0x07}},
       // message data
       {"Unable to read message data",
        {'m', 'e', 's', 's', 'a', 'g', 'e'}},
        // message frame no length.
        {"",
         { 0x30 }},
        // message data
        {{},
         {'m', 'e', 's', 's', 'a', 'g', 'e', '2'}},
   };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    encrypted = AssemblePacketFromFragments(packet_ietf);
  } else {
    encrypted = AssemblePacketFromFragments(packet);
  }
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  ASSERT_EQ(2u, visitor_.message_frames_.size());
  EXPECT_EQ(7u, visitor_.message_frames_[0]->message_length);
  EXPECT_EQ(8u, visitor_.message_frames_[1]->message_length);

  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    CheckFramingBoundaries(packet_ietf, QUIC_INVALID_MESSAGE_DATA);
  } else {
    CheckFramingBoundaries(packet, QUIC_INVALID_MESSAGE_DATA);
  }
}

TEST_P(QuicFramerTest, IetfStatelessResetPacket) {
  // clang-format off
  unsigned char packet[] = {
      // type (short packet, 1 byte packet number)
      0x50,
      // Random bytes
      0x01, 0x11, 0x02, 0x22, 0x03, 0x33, 0x04, 0x44,
      0x01, 0x11, 0x02, 0x22, 0x03, 0x33, 0x04, 0x44,
      0x01, 0x11, 0x02, 0x22, 0x03, 0x33, 0x04, 0x44,
      0x01, 0x11, 0x02, 0x22, 0x03, 0x33, 0x04, 0x44,
      // stateless reset token
      0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
  };
  // clang-format on
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicFramerPeer::SetLastSerializedServerConnectionId(&framer_,
                                                      TestConnectionId(0x33));
  decrypter_ = new test::TestDecrypter();
  if (framer_.version().KnowsWhichDecrypterToUse()) {
    framer_.InstallDecrypter(
        ENCRYPTION_INITIAL,
        std::make_unique<NullDecrypter>(Perspective::IS_CLIENT));
    framer_.InstallDecrypter(ENCRYPTION_ZERO_RTT,
                             std::unique_ptr<QuicDecrypter>(decrypter_));
  } else {
    framer_.SetDecrypter(ENCRYPTION_INITIAL, std::make_unique<NullDecrypter>(
                                                 Perspective::IS_CLIENT));
    framer_.SetAlternativeDecrypter(
        ENCRYPTION_ZERO_RTT, std::unique_ptr<QuicDecrypter>(decrypter_), false);
  }
  // This packet cannot be decrypted because diversification nonce is missing.
  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.stateless_reset_packet_.get());
  EXPECT_EQ(kTestStatelessResetToken,
            visitor_.stateless_reset_packet_->stateless_reset_token);
}

TEST_P(QuicFramerTest, IetfStatelessResetPacketInvalidStatelessResetToken) {
  // clang-format off
  unsigned char packet[] = {
      // type (short packet, 1 byte packet number)
      0x50,
      // Random bytes
      0x01, 0x11, 0x02, 0x22, 0x03, 0x33, 0x04, 0x44,
      0x01, 0x11, 0x02, 0x22, 0x03, 0x33, 0x04, 0x44,
      0x01, 0x11, 0x02, 0x22, 0x03, 0x33, 0x04, 0x44,
      0x01, 0x11, 0x02, 0x22, 0x03, 0x33, 0x04, 0x44,
      // stateless reset token
      0xB6, 0x69, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  // clang-format on
  QuicFramerPeer::SetLastSerializedServerConnectionId(&framer_,
                                                      TestConnectionId(0x33));
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  decrypter_ = new test::TestDecrypter();
  if (framer_.version().KnowsWhichDecrypterToUse()) {
    framer_.InstallDecrypter(
        ENCRYPTION_INITIAL,
        std::make_unique<NullDecrypter>(Perspective::IS_CLIENT));
    framer_.InstallDecrypter(ENCRYPTION_ZERO_RTT,
                             std::unique_ptr<QuicDecrypter>(decrypter_));
  } else {
    framer_.SetDecrypter(ENCRYPTION_INITIAL, std::make_unique<NullDecrypter>(
                                                 Perspective::IS_CLIENT));
    framer_.SetAlternativeDecrypter(
        ENCRYPTION_ZERO_RTT, std::unique_ptr<QuicDecrypter>(decrypter_), false);
  }
  // This packet cannot be decrypted because diversification nonce is missing.
  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_DECRYPTION_FAILURE));
  ASSERT_FALSE(visitor_.stateless_reset_packet_);
}

TEST_P(QuicFramerTest, VersionNegotiationPacketClient) {
  // clang-format off
  PacketFragments packet = {
      // type (long header)
      {"",
       {0x8F}},
      // version tag
      {"",
       {0x00, 0x00, 0x00, 0x00}},
      {"",
       {0x05}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // Supported versions
      {"Unable to read supported version in negotiation.",
       {QUIC_VERSION_BYTES,
        'Q', '2', '.', '0'}},
  };

  PacketFragments packet49 = {
      // type (long header)
      {"",
       {0x8F}},
      // version tag
      {"",
       {0x00, 0x00, 0x00, 0x00}},
      {"",
       {0x08}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      {"",
       {0x00}},
      // Supported versions
      {"Unable to read supported version in negotiation.",
       {QUIC_VERSION_BYTES,
        'Q', '2', '.', '0'}},
  };
  // clang-format on

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  PacketFragments& fragments =
      framer_.version().HasLongHeaderLengths() ? packet49 : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  ASSERT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.version_negotiation_packet_.get());
  EXPECT_EQ(1u, visitor_.version_negotiation_packet_->versions.size());
  EXPECT_EQ(GetParam(), visitor_.version_negotiation_packet_->versions[0]);

  // Remove the last version from the packet so that every truncated
  // version of the packet is invalid, otherwise checking boundaries
  // is annoyingly complicated.
  for (size_t i = 0; i < 4; ++i) {
    fragments.back().fragment.pop_back();
  }
  CheckFramingBoundaries(fragments, QUIC_INVALID_VERSION_NEGOTIATION_PACKET);
}

TEST_P(QuicFramerTest, VersionNegotiationPacketServer) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // clang-format off
  unsigned char packet[] = {
      // public flags (long header with all ignored bits set)
      0xFF,
      // version
      0x00, 0x00, 0x00, 0x00,
      // connection ID lengths
      0x50,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
      // supported versions
      QUIC_VERSION_BYTES,
      'Q', '2', '.', '0',
  };
  unsigned char packet2[] = {
      // public flags (long header with all ignored bits set)
      0xFF,
      // version
      0x00, 0x00, 0x00, 0x00,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
      // source connection ID length
      0x00,
      // supported versions
      QUIC_VERSION_BYTES,
      'Q', '2', '.', '0',
  };
  // clang-format on
  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasLengthPrefixedConnectionIds()) {
    p = packet2;
    p_length = ABSL_ARRAYSIZE(packet2);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(),
              IsError(QUIC_INVALID_VERSION_NEGOTIATION_PACKET));
  EXPECT_EQ("Server received version negotiation packet.",
            framer_.detailed_error());
  EXPECT_FALSE(visitor_.version_negotiation_packet_.get());
}

TEST_P(QuicFramerTest, ParseIetfRetryPacket) {
  if (!framer_.version().SupportsRetry()) {
    return;
  }
  // IETF RETRY is only sent from client to server.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  // clang-format off
  unsigned char packet[] = {
      // public flags (long header with packet type RETRY and ODCIL=8)
      0xF5,
      // version
      QUIC_VERSION_BYTES,
      // connection ID lengths
      0x05,
      // source connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
      // original destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // retry token
      'H', 'e', 'l', 'l', 'o', ' ', 't', 'h', 'i', 's',
      ' ', 'i', 's', ' ', 'R', 'E', 'T', 'R', 'Y', '!',
  };
  unsigned char packet49[] = {
      // public flags (long header with packet type RETRY)
      0xF0,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x00,
      // source connection ID length
      0x08,
      // source connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
      // original destination connection ID length
      0x08,
      // original destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // retry token
      'H', 'e', 'l', 'l', 'o', ' ', 't', 'h', 'i', 's',
      ' ', 'i', 's', ' ', 'R', 'E', 'T', 'R', 'Y', '!',
  };
  unsigned char packet_with_tag[] = {
      // public flags (long header with packet type RETRY)
      0xF0,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x00,
      // source connection ID length
      0x08,
      // source connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
      // retry token
      'H', 'e', 'l', 'l', 'o', ' ', 't', 'h', 'i', 's',
      ' ', 'i', 's', ' ', 'R', 'E', 'T', 'R', 'Y', '!',
      // retry token integrity tag
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().UsesTls()) {
    ReviseFirstByteByVersion(packet_with_tag);
    p = packet_with_tag;
    p_length = ABSL_ARRAYSIZE(packet_with_tag);
  } else if (framer_.version().HasLongHeaderLengths()) {
    p = packet49;
    p_length = ABSL_ARRAYSIZE(packet49);
  }
  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());

  ASSERT_TRUE(visitor_.on_retry_packet_called_);
  ASSERT_TRUE(visitor_.retry_new_connection_id_.get());
  ASSERT_TRUE(visitor_.retry_token_.get());

  if (framer_.version().UsesTls()) {
    ASSERT_TRUE(visitor_.retry_token_integrity_tag_.get());
    static const unsigned char expected_integrity_tag[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    quiche::test::CompareCharArraysWithHexError(
        "retry integrity tag", visitor_.retry_token_integrity_tag_->data(),
        visitor_.retry_token_integrity_tag_->length(),
        reinterpret_cast<const char*>(expected_integrity_tag),
        ABSL_ARRAYSIZE(expected_integrity_tag));
    ASSERT_TRUE(visitor_.retry_without_tag_.get());
    quiche::test::CompareCharArraysWithHexError(
        "retry without tag", visitor_.retry_without_tag_->data(),
        visitor_.retry_without_tag_->length(),
        reinterpret_cast<const char*>(packet_with_tag), 35);
  } else {
    ASSERT_TRUE(visitor_.retry_original_connection_id_.get());
    EXPECT_EQ(FramerTestConnectionId(),
              *visitor_.retry_original_connection_id_.get());
  }

  EXPECT_EQ(FramerTestConnectionIdPlusOne(),
            *visitor_.retry_new_connection_id_.get());
  EXPECT_EQ("Hello this is RETRY!", *visitor_.retry_token_.get());

  // IETF RETRY is only sent from client to server, the rest of this test
  // ensures that the server correctly drops them without acting on them.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Reset our visitor state to default settings.
  visitor_.retry_original_connection_id_.reset();
  visitor_.retry_new_connection_id_.reset();
  visitor_.retry_token_.reset();
  visitor_.retry_token_integrity_tag_.reset();
  visitor_.retry_without_tag_.reset();
  visitor_.on_retry_packet_called_ = false;

  EXPECT_FALSE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_PACKET_HEADER));
  EXPECT_EQ("Client-initiated RETRY is invalid.", framer_.detailed_error());

  EXPECT_FALSE(visitor_.on_retry_packet_called_);
  EXPECT_FALSE(visitor_.retry_new_connection_id_.get());
  EXPECT_FALSE(visitor_.retry_token_.get());
  EXPECT_FALSE(visitor_.retry_token_integrity_tag_.get());
  EXPECT_FALSE(visitor_.retry_without_tag_.get());
}

TEST_P(QuicFramerTest, BuildPaddingFramePacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // clang-format off
  unsigned char packet[kMaxOutgoingPacketSize] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };

  unsigned char packet_ietf[kMaxOutgoingPacketSize] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  unsigned char* p = packet;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
  }

  uint64_t header_size = GetPacketHeaderSize(
      framer_.transport_version(), kPacket8ByteConnectionId,
      kPacket0ByteConnectionId, !kIncludeVersion, !kIncludeDiversificationNonce,
      PACKET_4BYTE_PACKET_NUMBER, quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0);
  memset(p + header_size + 1, 0x00, kMaxOutgoingPacketSize - header_size - 1);

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildStreamFramePacketWithNewPaddingFrame) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;
  QuicStreamFrame stream_frame(kStreamId, true, kStreamOffset,
                               absl::string_view("hello world!"));
  QuicPaddingFrame padding_frame(2);
  QuicFrames frames = {QuicFrame(padding_frame), QuicFrame(stream_frame),
                       QuicFrame(padding_frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // paddings
    0x00, 0x00,
    // frame type (stream frame with fin)
    0xFF,
    // stream id
    0x01, 0x02, 0x03, 0x04,
    // offset
    0x3A, 0x98, 0xFE, 0xDC,
    0x32, 0x10, 0x76, 0x54,
    // data length
    0x00, 0x0c,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
    // paddings
    0x00, 0x00,
  };

  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // paddings
    0x00, 0x00,
    // frame type (IETF_STREAM with FIN, LEN, and OFFSET bits set)
    0x08 | 0x01 | 0x02 | 0x04,
    // stream id
    kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04,
    // offset
    kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
    0x32, 0x10, 0x76, 0x54,
    // data length
    kVarInt62OneByte + 0x0c,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
    // paddings
    0x00, 0x00,
  };
  // clang-format on

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

TEST_P(QuicFramerTest, Build4ByteSequenceNumberPaddingFramePacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number_length = PACKET_4BYTE_PACKET_NUMBER;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // clang-format off
  unsigned char packet[kMaxOutgoingPacketSize] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };

  unsigned char packet_ietf[kMaxOutgoingPacketSize] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  unsigned char* p = packet;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
  }

  uint64_t header_size = GetPacketHeaderSize(
      framer_.transport_version(), kPacket8ByteConnectionId,
      kPacket0ByteConnectionId, !kIncludeVersion, !kIncludeDiversificationNonce,
      PACKET_4BYTE_PACKET_NUMBER, quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0);
  memset(p + header_size + 1, 0x00, kMaxOutgoingPacketSize - header_size - 1);

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, Build2ByteSequenceNumberPaddingFramePacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number_length = PACKET_2BYTE_PACKET_NUMBER;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // clang-format off
  unsigned char packet[kMaxOutgoingPacketSize] = {
    // type (short header, 2 byte packet number)
    0x41,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x56, 0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };

  unsigned char packet_ietf[kMaxOutgoingPacketSize] = {
    // type (short header, 2 byte packet number)
    0x41,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x56, 0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  unsigned char* p = packet;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
  }

  uint64_t header_size = GetPacketHeaderSize(
      framer_.transport_version(), kPacket8ByteConnectionId,
      kPacket0ByteConnectionId, !kIncludeVersion, !kIncludeDiversificationNonce,
      PACKET_2BYTE_PACKET_NUMBER, quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0);
  memset(p + header_size + 1, 0x00, kMaxOutgoingPacketSize - header_size - 1);

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, Build1ByteSequenceNumberPaddingFramePacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // clang-format off
  unsigned char packet[kMaxOutgoingPacketSize] = {
    // type (short header, 1 byte packet number)
    0x40,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };

  unsigned char packet_ietf[kMaxOutgoingPacketSize] = {
    // type (short header, 1 byte packet number)
    0x40,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  unsigned char* p = packet;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
  }

  uint64_t header_size = GetPacketHeaderSize(
      framer_.transport_version(), kPacket8ByteConnectionId,
      kPacket0ByteConnectionId, !kIncludeVersion, !kIncludeDiversificationNonce,
      PACKET_1BYTE_PACKET_NUMBER, quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0);
  memset(p + header_size + 1, 0x00, kMaxOutgoingPacketSize - header_size - 1);

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildStreamFramePacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;
  if (QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  }

  QuicStreamFrame stream_frame(kStr
"""


```
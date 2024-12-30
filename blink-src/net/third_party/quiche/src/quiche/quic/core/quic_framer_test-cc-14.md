Response:
The user wants to understand the functionality of the `quic_framer_test.cc` file in the Chromium network stack. They are particularly interested in:

1. **Functionality of the file:** What does this test file do?
2. **Relationship with JavaScript:** Does this C++ code interact with JavaScript in any way?
3. **Logical reasoning:** Can we infer input and output scenarios from the provided code snippet?
4. **Common user errors:** Are there any typical mistakes a user or programmer might make that would lead to these tests failing?
5. **Debugging:** How would a user end up in this part of the code during debugging?
6. **File completion:** This is part 15 of 16, so what is the overall purpose of this file?

Let's break down the code snippet and address each of these points.

**Code Analysis:**

The provided code snippet contains several test cases within the `QuicFramerTest` class. These test cases focus on parsing and processing various QUIC packets, especially:

* **Initial packets:** Parsing and decrypting the initial handshake packets.
* **Coalesced packets:** Handling multiple packets bundled together.
* **Version negotiation:** Testing the logic for handling version negotiation packets.
* **Connection ID handling:** Verifying the correct processing of connection IDs in different scenarios.
* **Error code parsing:** Testing the extraction of extended error codes.
* **ACK frames:** Checking the handling of ACK frames, including cases with large ack delay values.
* **Key updates:**  Testing the key update mechanism in QUIC.

**Addressing the User's Questions:**

1. **Functionality of the file:** This file contains unit tests for the `QuicFramer` class. The `QuicFramer` is responsible for taking raw byte streams (QUIC packets) and parsing them into structured data, and also for the reverse process of serializing structured data into raw byte streams. The tests cover various aspects of packet parsing, decryption, and handling of different QUIC features.

2. **Relationship with JavaScript:**  While this C++ code is part of Chromium's network stack, which *is* used by the browser (and thus indirectly related to JavaScript running in web pages), **this specific test file has no direct, runtime interaction with JavaScript.**  The network stack handles the underlying communication protocols. JavaScript uses higher-level APIs (like `fetch` or WebSockets) which eventually utilize the network stack. The connection is indirect:
    * A JavaScript application initiates a network request.
    * The browser's network stack, which includes this QUIC implementation, handles the QUIC protocol.
    * This C++ test file ensures the QUIC implementation is working correctly.

3. **Logical reasoning:** Let's take the `DispatcherParseClientInitialPacketNumberFromCoalescedPacket` test as an example:
    * **Hypothetical Input:** A raw byte array representing two coalesced QUIC initial packets. The first packet has a packet number of `0x12345678`, and the second has `0x12345679`. The server is attempting to parse this received data.
    * **Expected Output:** The test verifies that the `ParsePublicHeaderDispatcherShortHeaderLengthUnknown` function correctly identifies the packet as a long header initial packet, extracts the destination connection ID, and that `TryDecryptInitialPacketDispatcher` correctly decrypts the first initial packet and extracts its packet number as `0x12345678`. The test focuses on the *first* packet in the coalesced set in this scenario.

4. **Common user errors:**  Since this is a unit test file, the "user" in this context is primarily a developer working on the QUIC implementation. Common errors that would cause these tests to fail include:
    * **Incorrect packet construction:**  Manually creating packets with wrong header fields, incorrect lengths, or invalid frame structures. For example, setting the wrong version number or connection ID length. The `DispatcherParseClientInitialPacketNumberFromCoalescedPacket` test explicitly checks for correct length encoding. If a developer incorrectly calculates the packet length, this test would fail.
    * **Flawed decryption logic:** Errors in the decryption process, such as using the wrong decryption key or algorithm. The tests involving `TryDecryptInitialPacketDispatcher` would catch these.
    * **Incorrect state management:**  Failing to handle different connection states or key phases correctly. The `KeyUpdate` tests are designed to verify the key update logic.
    * **Version incompatibility:** Attempting to process packets with an unsupported QUIC version. The version negotiation tests are crucial for this.

5. **Debugging:** A developer might reach this code while debugging various network-related issues:
    * **Connection establishment problems:** If a QUIC connection fails to establish, stepping through the packet parsing logic in `QuicFramer::ProcessPacket` and related functions would lead to these tests. The `DispatcherParseClientInitialPacketNumberFromCoalescedPacket` test is relevant here, as the initial handshake is crucial for connection setup.
    * **Packet processing errors:** If packets are being dropped or interpreted incorrectly, debugging the parsing and decryption steps in `QuicFramer` is necessary.
    * **Key update failures:**  If the encryption keys are not being updated correctly, the `KeyUpdate` tests are directly relevant.
    * **Investigating interoperability issues:** When a Chromium client fails to communicate with a different QUIC implementation, examining the packet formatting and parsing logic becomes important.

    **User Operation Steps (as a debugging scenario):**
    1. A user reports a website failing to load or experiencing connection issues in Chrome.
    2. A network engineer or developer investigates the issue and suspects a problem with the QUIC protocol.
    3. They might use internal Chrome debugging tools or network packet capture tools (like Wireshark) to examine the raw network traffic.
    4. If QUIC packets appear malformed or are not being processed correctly, they might set breakpoints in the `quiche/quic/core/quic_framer.cc` and step through the `ProcessPacket` function.
    5. To understand the specific parsing of different packet types, they might then look at the unit tests in `quic_framer_test.cc` to understand the expected behavior and to reproduce the issue in a controlled environment.

6. **File completion:** Being the 15th out of 16 parts suggests that this file covers a significant portion of the `QuicFramer`'s functionality. Given the content, it likely covers the core packet parsing and processing logic, including initial handshake, version negotiation, connection ID handling, and key updates. The remaining part (part 16) might cover less frequent or more specialized scenarios, or potentially focus on error handling and edge cases. This file, as a whole, provides a comprehensive set of tests to ensure the robustness and correctness of the QUIC packet parsing and processing implementation in Chromium.
这是 chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 文件的第 15 部分，它主要包含以下功能：

**核心功能：测试 QUIC 帧的解析和处理，特别是针对特定场景和边缘情况的测试。**

从提供的代码片段来看，这一部分主要关注以下方面的测试：

* **Dispatcher 解析客户端 Initial 数据包的包号 (Packet Number) 从 Coalesced Packet 中:** 测试当多个 QUIC 数据包被合并在一起发送时，Dispatcher 是否能正确解析出客户端 Initial 数据包的包号。
* **解析服务端 Version Negotiation Probe 响应:** 测试解析服务端发送的用于探测版本协商的响应包。
* **解析客户端 Version Negotiation Probe 数据包:** 测试解析客户端发送的用于探测版本协商的数据包。
* **写入服务端 Version Negotiation Probe 响应:** 测试写入服务端发送的用于探测版本协商的响应包。
* **客户端从长头 (Long Header) 数据包获取连接 ID (Connection ID) (To Client 和 To Server):** 测试客户端作为接收方和发送方时，如何从长头数据包中提取连接 ID。这包括对不同版本 QUIC 中连接 ID 长度的处理。
* **处理和验证 IETF 连接 ID 长度 (Client 和 Server):** 测试在 IETF QUIC 版本中，客户端和服务器如何处理和验证连接 ID 的长度字段。
* **测试扩展错误码解析器:** 测试从连接关闭帧 (ConnectionCloseFrame) 的错误详情中解析出扩展的 QUIC 错误码的逻辑。
* **处理过大的 ACK 延迟 (Ack Delay):** 测试当接收到 ACK 帧中包含过大的 ACK 延迟时间时，Framer 的处理行为。
* **密钥更新 (Key Update):**  详细测试了 QUIC+TLS 中的密钥更新机制，包括：
    * 正常密钥更新流程的测试。
    * 接收到密钥更新后旧密钥加密的数据包的处理。
    * 在丢弃旧的 1-RTT 密钥后接收到旧密钥加密数据包的处理。
    * 乱序接收到密钥更新后的数据包的处理。

**与 JavaScript 的关系：**

这个 C++ 文件是 Chromium 网络栈的一部分，负责处理底层的 QUIC 协议。虽然它本身不包含 JavaScript 代码，但它对于浏览器与服务器之间使用 QUIC 协议进行通信至关重要。当一个网页 (运行 JavaScript) 发起网络请求时，如果协议协商选择了 QUIC，那么这里的 C++ 代码就会被用来解析和处理 QUIC 数据包。

**举例说明：**

假设一个网页使用 `fetch()` API 向支持 QUIC 的服务器发送了一个请求。

1. **JavaScript (`fetch()`):** JavaScript 代码调用 `fetch('https://example.com')`。
2. **Chromium 网络栈 (C++):** Chromium 的网络栈会尝试与 `example.com` 建立 QUIC 连接。
3. **Initial 数据包解析 (本文件测试的功能):**  客户端会发送一个 Initial 数据包。服务器收到后，`QuicFramer` 的相关代码 (经过本文件测试) 会解析这个 Initial 数据包的头部，包括版本信息、连接 ID 等。`DispatcherParseClientInitialPacketNumberFromCoalescedPacket` 这样的测试确保了即使这个 Initial 数据包和其它数据包合并发送，也能正确解析。
4. **密钥协商和更新 (本文件测试的功能):**  在连接建立过程中，会进行密钥协商。建立连接后，如果服务器发起密钥更新，`KeyUpdate` 相关的测试确保了 `QuicFramer` 能正确处理密钥更新信息，并能正确解密使用新密钥加密的数据包。

**逻辑推理 (假设输入与输出):**

**以 `DispatcherParseClientInitialPacketNumberFromCoalescedPacket` 测试为例：**

* **假设输入:**  一个包含两个合并的 QUIC Initial 数据包的字节流。第一个数据包的包号是 `0x12345678`，第二个数据包的包号是 `0x12345679`。
* **预期输出:** `QuicFramer::ParsePublicHeaderDispatcherShortHeaderLengthUnknown` 函数能够正确解析出这是一个长头数据包，并识别出是 Initial 类型。`QuicFramer::TryDecryptInitialPacketDispatcher` 函数能够成功解密第一个 Initial 数据包，并提取出其包号 `0x12345678`。

**用户或编程常见的使用错误：**

* **错误地构造 QUIC 数据包:**  程序员在手动构造 QUIC 数据包进行测试时，可能会错误地设置头部字段，例如错误的连接 ID 长度、错误的包类型，或者遗漏必要的字段。例如，在早期的 QUIC 版本中，连接 ID 的长度是固定的，如果开发者在使用不允许变长连接 ID 的版本时，构造了变长连接 ID 的数据包，`ClientConnectionIdFromLongHeaderToClient` 和 `ClientConnectionIdFromLongHeaderToServer` 的相关测试就会失败。
* **不正确的密钥管理:** 在 QUIC+TLS 中，密钥的管理非常重要。如果服务器或客户端在密钥更新后，仍然使用旧的密钥加密数据，或者在收到密钥更新信号后没有及时更新密钥，`KeyUpdate` 相关的测试会失败。
* **版本不匹配:**  如果客户端和服务端配置的 QUIC 版本不一致，会导致握手失败。`ParseServerVersionNegotiationProbeResponse` 和 `ParseClientVersionNegotiationProbePacket` 等测试确保了版本协商机制的正确性。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户报告网络问题:** 用户在使用 Chrome 浏览器访问某个网站时遇到连接失败、加载缓慢等问题。
2. **开发者介入调试:**  开发者怀疑是 QUIC 协议层的问题。
3. **抓包分析:** 开发者可能会使用 Wireshark 等工具抓取网络包，观察 QUIC 数据包的格式和内容。
4. **代码调试:** 开发者可能会设置断点在 `quiche/quic/core/quic_framer.cc` 的 `ProcessPacket` 函数中，逐步分析数据包的解析过程。
5. **进入测试用例:** 为了重现问题或理解特定场景下的处理逻辑，开发者会查看 `quic_framer_test.cc` 中的相关测试用例，例如，如果怀疑是密钥更新导致的问题，会重点查看 `KeyUpdate` 相关的测试。
6. **单步执行测试:** 开发者可以在 IDE 中运行这些测试用例，并单步执行，观察 `QuicFramer` 的行为，确认是否与预期一致。

**归纳其功能 (作为第 15 部分):**

作为 16 个测试文件中的第 15 个，这个文件深入测试了 `QuicFramer` 在处理各种复杂和特定的 QUIC 数据包场景下的功能。它涵盖了：

* **Coalesced Packet 的处理:** 确保能正确解析合并发送的数据包。
* **版本协商的细节:** 验证版本协商机制的正确性。
* **连接 ID 处理的复杂性:** 测试在不同版本和不同角色下连接 ID 的处理逻辑。
* **错误处理机制:** 验证扩展错误码的解析。
* **高级特性测试:** 例如过大的 ACK 延迟和关键的密钥更新机制。

这表明在整个 `quic_framer_test.cc` 文件中，前面的部分可能覆盖了更基础的帧解析和处理，而这一部分则专注于更精细、更具挑战性的场景，确保 `QuicFramer` 在各种情况下都能稳定可靠地工作。 剩下的第 16 部分可能涵盖一些边缘情况、错误处理的更深入测试，或者是一些不常用的帧类型或特性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第15部分，共16部分，请归纳一下它的功能

"""
tionIdGenerator generator;
  EXPECT_CALL(generator, ConnectionIdLength(_)).Times(0);
  EXPECT_EQ(QUIC_NO_ERROR,
            QuicFramer::ParsePublicHeaderDispatcherShortHeaderLengthUnknown(
                *encrypted, &format, &long_packet_type, &version_flag,
                &use_length_prefix, &version_label, &parsed_version,
                &destination_connection_id, &source_connection_id, &retry_token,
                &detailed_error, generator));
  EXPECT_EQ(parsed_version, version_);
  if (parsed_version != ParsedQuicVersion::RFCv1() &&
      parsed_version != ParsedQuicVersion::Draft29()) {
    return;
  }
  EXPECT_EQ(format, IETF_QUIC_LONG_HEADER_PACKET);
  EXPECT_EQ(destination_connection_id.length(), 8);
  EXPECT_EQ(long_packet_type, INITIAL);
  EXPECT_TRUE(version_flag);
  EXPECT_TRUE(use_length_prefix);
  EXPECT_EQ(version_label, CreateQuicVersionLabel(version_));

  EXPECT_EQ(source_connection_id.length(), 0);
  EXPECT_TRUE(retry_token.value_or("").empty());
  EXPECT_EQ(detailed_error, "");

  std::optional<uint64_t> packet_number;
  EXPECT_EQ(QUIC_NO_ERROR,
            QuicFramer::TryDecryptInitialPacketDispatcher(
                *encrypted, parsed_version, format, long_packet_type,
                destination_connection_id, source_connection_id, retry_token,
                /*largest_decrypted_inital_packet_number=*/QuicPacketNumber(),
                *decrypter_, &packet_number));
  EXPECT_THAT(packet_number, Optional(2));
}

TEST_P(QuicFramerTest,
       DispatcherParseClientInitialPacketNumberFromCoalescedPacket) {
  if (!QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_INITIAL);
  // clang-format off
  unsigned char packet[] = {
    // first coalesced packet
      // Type (Long header, INITIAL, 4B packet number)
      0xC3,
      // Version
      QUIC_VERSION_BYTES,
      // Destination connection ID length
      0x08,
      // Destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // Source connection ID length
      0x00,
      // Retry token
      0x00,
      // Packet length
      0x1E,
      // Packet number
      0x12, 0x34, 0x56, 0x78,
      // Frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // Stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // Offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // Data length
      kVarInt62OneByte + 0x0c,
      // Data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // Type (Long header, ZERO_RTT_PROTECTED, 4B packet number)
      0xD3,
      // Version
      QUIC_VERSION_BYTES,
      // Destination connection ID length
      0x08,
      // Destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // Source connection ID length
      0x00,
      // Packet length
      0x1E,
      // Packet number
      0x12, 0x34, 0x56, 0x79,
      // Frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // Stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // Offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // Data length
      kVarInt62OneByte + 0x0c,
      // Data
      'H',  'E',  'L',  'L',
      'O',  '_',  'W',  'O',
      'R',  'L',  'D',  '?',
  };
  // clang-format on
  const size_t first_packet_size = 47;
  // If the first packet changes, the attempt to fix the first byte of the
  // second packet will fail.
  ASSERT_EQ(packet[first_packet_size], 0xD3);

  ReviseFirstByteByVersion(packet);
  ReviseFirstByteByVersion(&packet[first_packet_size]);
  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);

  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);
  PacketHeaderFormat format;
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  bool version_flag;
  bool use_length_prefix;
  QuicVersionLabel version_label;
  std::optional<absl::string_view> retry_token;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  QuicConnectionId destination_connection_id, source_connection_id;
  std::string detailed_error;
  MockConnectionIdGenerator generator;
  EXPECT_CALL(generator, ConnectionIdLength(_)).Times(0);
  EXPECT_EQ(QUIC_NO_ERROR,
            QuicFramer::ParsePublicHeaderDispatcherShortHeaderLengthUnknown(
                encrypted, &format, &long_packet_type, &version_flag,
                &use_length_prefix, &version_label, &parsed_version,
                &destination_connection_id, &source_connection_id, &retry_token,
                &detailed_error, generator));
  EXPECT_EQ(parsed_version, version_);
  if (parsed_version != ParsedQuicVersion::RFCv1() &&
      parsed_version != ParsedQuicVersion::Draft29()) {
    return;
  }
  EXPECT_EQ(format, IETF_QUIC_LONG_HEADER_PACKET);
  EXPECT_EQ(destination_connection_id.length(), 8);
  EXPECT_EQ(long_packet_type, INITIAL);
  EXPECT_TRUE(version_flag);
  EXPECT_TRUE(use_length_prefix);
  EXPECT_EQ(version_label, CreateQuicVersionLabel(version_));

  EXPECT_EQ(source_connection_id.length(), 0);
  EXPECT_TRUE(retry_token.value_or("").empty());
  EXPECT_EQ(detailed_error, "");

  std::optional<uint64_t> packet_number;
  EXPECT_EQ(QUIC_NO_ERROR,
            QuicFramer::TryDecryptInitialPacketDispatcher(
                encrypted, parsed_version, format, long_packet_type,
                destination_connection_id, source_connection_id, retry_token,
                /*largest_decrypted_inital_packet_number=*/QuicPacketNumber(),
                *decrypter_, &packet_number));
  EXPECT_THAT(packet_number, Optional(0x12345678));
}

TEST_P(QuicFramerTest, ParseServerVersionNegotiationProbeResponse) {
  // clang-format off
  const uint8_t packet[] = {
    // IETF long header with fixed bit set, type initial, all-0 encrypted bits.
    0xc0,
    // Version of 0, indicating version negotiation.
    0x00, 0x00, 0x00, 0x00,
    // Destination connection ID length 0, source connection ID length 8.
    0x00, 0x08,
    // 8-byte source connection ID.
    0x56, 0x4e, 0x20, 0x70, 0x6c, 0x7a, 0x20, 0x21,
    // A few supported versions.
    0xaa, 0xaa, 0xaa, 0xaa,
    QUIC_VERSION_BYTES,
  };
  // clang-format on
  char probe_payload_bytes[] = {0x56, 0x4e, 0x20, 0x70, 0x6c, 0x7a, 0x20, 0x21};
  char parsed_probe_payload_bytes[255] = {};
  uint8_t parsed_probe_payload_length = sizeof(parsed_probe_payload_bytes);
  std::string parse_detailed_error = "";
  EXPECT_TRUE(QuicFramer::ParseServerVersionNegotiationProbeResponse(
      reinterpret_cast<const char*>(packet), sizeof(packet),
      reinterpret_cast<char*>(parsed_probe_payload_bytes),
      &parsed_probe_payload_length, &parse_detailed_error));
  EXPECT_EQ("", parse_detailed_error);
  quiche::test::CompareCharArraysWithHexError(
      "parsed probe", parsed_probe_payload_bytes, parsed_probe_payload_length,
      probe_payload_bytes, sizeof(probe_payload_bytes));
}

TEST_P(QuicFramerTest, ParseClientVersionNegotiationProbePacket) {
  char packet[1200];
  char input_destination_connection_id_bytes[] = {0x56, 0x4e, 0x20, 0x70,
                                                  0x6c, 0x7a, 0x20, 0x21};
  ASSERT_TRUE(QuicFramer::WriteClientVersionNegotiationProbePacket(
      packet, sizeof(packet), input_destination_connection_id_bytes,
      sizeof(input_destination_connection_id_bytes)));
  char parsed_destination_connection_id_bytes[255] = {0};
  uint8_t parsed_destination_connection_id_length =
      sizeof(parsed_destination_connection_id_bytes);
  ASSERT_TRUE(ParseClientVersionNegotiationProbePacket(
      packet, sizeof(packet), parsed_destination_connection_id_bytes,
      &parsed_destination_connection_id_length));
  quiche::test::CompareCharArraysWithHexError(
      "parsed destination connection ID",
      parsed_destination_connection_id_bytes,
      parsed_destination_connection_id_length,
      input_destination_connection_id_bytes,
      sizeof(input_destination_connection_id_bytes));
}

TEST_P(QuicFramerTest, WriteServerVersionNegotiationProbeResponse) {
  char packet[1200];
  size_t packet_length = sizeof(packet);
  char input_source_connection_id_bytes[] = {0x56, 0x4e, 0x20, 0x70,
                                             0x6c, 0x7a, 0x20, 0x21};
  ASSERT_TRUE(WriteServerVersionNegotiationProbeResponse(
      packet, &packet_length, input_source_connection_id_bytes,
      sizeof(input_source_connection_id_bytes)));
  char parsed_source_connection_id_bytes[255] = {0};
  uint8_t parsed_source_connection_id_length =
      sizeof(parsed_source_connection_id_bytes);
  std::string detailed_error;
  ASSERT_TRUE(QuicFramer::ParseServerVersionNegotiationProbeResponse(
      packet, packet_length, parsed_source_connection_id_bytes,
      &parsed_source_connection_id_length, &detailed_error))
      << detailed_error;
  quiche::test::CompareCharArraysWithHexError(
      "parsed destination connection ID", parsed_source_connection_id_bytes,
      parsed_source_connection_id_length, input_source_connection_id_bytes,
      sizeof(input_source_connection_id_bytes));
}

TEST_P(QuicFramerTest, ClientConnectionIdFromLongHeaderToClient) {
  SetDecrypterLevel(ENCRYPTION_HANDSHAKE);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  // clang-format off
  unsigned char packet[] = {
    // public flags (long header with packet type HANDSHAKE and
    // 4-byte packet number)
    0xE3,
    // version
    QUIC_VERSION_BYTES,
    // connection ID lengths
    0x50,
    // destination connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // long header packet length
    0x05,
    // packet number
    0x12, 0x34, 0x56, 0x00,
    // padding frame
    0x00,
  };
  unsigned char packet49[] = {
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
    0x05,
    // packet number
    0x12, 0x34, 0x56, 0x00,
    // padding frame
    0x00,
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasLongHeaderLengths()) {
    ReviseFirstByteByVersion(packet49);
    p = packet49;
    p_length = ABSL_ARRAYSIZE(packet49);
  }
  const bool parse_success =
      framer_.ProcessPacket(QuicEncryptedPacket(AsChars(p), p_length, false));
  if (!framer_.version().AllowsVariableLengthConnectionIds()) {
    EXPECT_FALSE(parse_success);
    EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_PACKET_HEADER));
    EXPECT_EQ("Invalid ConnectionId length.", framer_.detailed_error());
    return;
  }
  EXPECT_TRUE(parse_success);
  EXPECT_THAT(framer_.error(), IsQuicNoError());
  EXPECT_EQ("", framer_.detailed_error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_.get()->destination_connection_id);
}

TEST_P(QuicFramerTest, ClientConnectionIdFromLongHeaderToServer) {
  SetDecrypterLevel(ENCRYPTION_HANDSHAKE);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
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
    // padding frame
    0x00,
  };
  unsigned char packet49[] = {
    // public flags (long header with packet type HANDSHAKE and
    // 4-byte packet number)
    0xE3,
    // version
    QUIC_VERSION_BYTES,
    // connection ID lengths
    0x00, 0x08,
    // source connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // long header packet length
    0x05,
    // packet number
    0x12, 0x34, 0x56, 0x00,
    // padding frame
    0x00,
  };
  // clang-format on
  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasLongHeaderLengths()) {
    ReviseFirstByteByVersion(packet49);
    p = packet49;
    p_length = ABSL_ARRAYSIZE(packet49);
  }
  const bool parse_success =
      framer_.ProcessPacket(QuicEncryptedPacket(AsChars(p), p_length, false));
  if (!framer_.version().AllowsVariableLengthConnectionIds()) {
    EXPECT_FALSE(parse_success);
    EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_PACKET_HEADER));
    EXPECT_EQ("Invalid ConnectionId length.", framer_.detailed_error());
    return;
  }
  if (!framer_.version().SupportsClientConnectionIds()) {
    EXPECT_FALSE(parse_success);
    EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_PACKET_HEADER));
    EXPECT_EQ("Client connection ID not supported in this version.",
              framer_.detailed_error());
    return;
  }
  EXPECT_TRUE(parse_success);
  EXPECT_THAT(framer_.error(), IsQuicNoError());
  EXPECT_EQ("", framer_.detailed_error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_.get()->source_connection_id);
}

TEST_P(QuicFramerTest, ProcessAndValidateIetfConnectionIdLengthClient) {
  char connection_id_lengths = 0x05;
  QuicDataReader reader(&connection_id_lengths, 1);

  bool should_update_expected_server_connection_id_length = false;
  uint8_t expected_server_connection_id_length = 8;
  uint8_t destination_connection_id_length = 0;
  uint8_t source_connection_id_length = 8;
  std::string detailed_error = "";

  EXPECT_TRUE(QuicFramerPeer::ProcessAndValidateIetfConnectionIdLength(
      &reader, framer_.version(), Perspective::IS_CLIENT,
      should_update_expected_server_connection_id_length,
      &expected_server_connection_id_length, &destination_connection_id_length,
      &source_connection_id_length, &detailed_error));
  EXPECT_EQ(8, expected_server_connection_id_length);
  EXPECT_EQ(0, destination_connection_id_length);
  EXPECT_EQ(8, source_connection_id_length);
  EXPECT_EQ("", detailed_error);

  QuicDataReader reader2(&connection_id_lengths, 1);
  should_update_expected_server_connection_id_length = true;
  expected_server_connection_id_length = 33;
  EXPECT_TRUE(QuicFramerPeer::ProcessAndValidateIetfConnectionIdLength(
      &reader2, framer_.version(), Perspective::IS_CLIENT,
      should_update_expected_server_connection_id_length,
      &expected_server_connection_id_length, &destination_connection_id_length,
      &source_connection_id_length, &detailed_error));
  EXPECT_EQ(8, expected_server_connection_id_length);
  EXPECT_EQ(0, destination_connection_id_length);
  EXPECT_EQ(8, source_connection_id_length);
  EXPECT_EQ("", detailed_error);
}

TEST_P(QuicFramerTest, ProcessAndValidateIetfConnectionIdLengthServer) {
  char connection_id_lengths = 0x50;
  QuicDataReader reader(&connection_id_lengths, 1);

  bool should_update_expected_server_connection_id_length = false;
  uint8_t expected_server_connection_id_length = 8;
  uint8_t destination_connection_id_length = 8;
  uint8_t source_connection_id_length = 0;
  std::string detailed_error = "";

  EXPECT_TRUE(QuicFramerPeer::ProcessAndValidateIetfConnectionIdLength(
      &reader, framer_.version(), Perspective::IS_SERVER,
      should_update_expected_server_connection_id_length,
      &expected_server_connection_id_length, &destination_connection_id_length,
      &source_connection_id_length, &detailed_error));
  EXPECT_EQ(8, expected_server_connection_id_length);
  EXPECT_EQ(8, destination_connection_id_length);
  EXPECT_EQ(0, source_connection_id_length);
  EXPECT_EQ("", detailed_error);

  QuicDataReader reader2(&connection_id_lengths, 1);
  should_update_expected_server_connection_id_length = true;
  expected_server_connection_id_length = 33;
  EXPECT_TRUE(QuicFramerPeer::ProcessAndValidateIetfConnectionIdLength(
      &reader2, framer_.version(), Perspective::IS_SERVER,
      should_update_expected_server_connection_id_length,
      &expected_server_connection_id_length, &destination_connection_id_length,
      &source_connection_id_length, &detailed_error));
  EXPECT_EQ(8, expected_server_connection_id_length);
  EXPECT_EQ(8, destination_connection_id_length);
  EXPECT_EQ(0, source_connection_id_length);
  EXPECT_EQ("", detailed_error);
}

TEST_P(QuicFramerTest, TestExtendedErrorCodeParser) {
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Extended error codes only in IETF QUIC
    return;
  }
  QuicConnectionCloseFrame frame;

  frame.error_details = "this has no error code info in it";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(frame.quic_error_code, IsError(QUIC_IETF_GQUIC_ERROR_MISSING));
  EXPECT_EQ("this has no error code info in it", frame.error_details);

  frame.error_details = "1234this does not have the colon in it";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(frame.quic_error_code, IsError(QUIC_IETF_GQUIC_ERROR_MISSING));
  EXPECT_EQ("1234this does not have the colon in it", frame.error_details);

  frame.error_details = "1a234:this has a colon, but a malformed error number";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(frame.quic_error_code, IsError(QUIC_IETF_GQUIC_ERROR_MISSING));
  EXPECT_EQ("1a234:this has a colon, but a malformed error number",
            frame.error_details);

  frame.error_details = "1234:this is good";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_EQ(1234u, frame.quic_error_code);
  EXPECT_EQ("this is good", frame.error_details);

  frame.error_details =
      "1234 :this is not good, space between last digit and colon";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(frame.quic_error_code, IsError(QUIC_IETF_GQUIC_ERROR_MISSING));
  EXPECT_EQ("1234 :this is not good, space between last digit and colon",
            frame.error_details);

  frame.error_details = "123456789";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(
      frame.quic_error_code,
      IsError(QUIC_IETF_GQUIC_ERROR_MISSING));  // Not good, all numbers, no :
  EXPECT_EQ("123456789", frame.error_details);

  frame.error_details = "1234:";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_EQ(1234u,
            frame.quic_error_code);  // corner case.
  EXPECT_EQ("", frame.error_details);

  frame.error_details = "1234:5678";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_EQ(1234u,
            frame.quic_error_code);  // another corner case.
  EXPECT_EQ("5678", frame.error_details);

  frame.error_details = "12345 6789:";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(frame.quic_error_code,
              IsError(QUIC_IETF_GQUIC_ERROR_MISSING));  // Not good
  EXPECT_EQ("12345 6789:", frame.error_details);

  frame.error_details = ":no numbers, is not good";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(frame.quic_error_code, IsError(QUIC_IETF_GQUIC_ERROR_MISSING));
  EXPECT_EQ(":no numbers, is not good", frame.error_details);

  frame.error_details = "qwer:also no numbers, is not good";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(frame.quic_error_code, IsError(QUIC_IETF_GQUIC_ERROR_MISSING));
  EXPECT_EQ("qwer:also no numbers, is not good", frame.error_details);

  frame.error_details = " 1234:this is not good, space before first digit";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(frame.quic_error_code, IsError(QUIC_IETF_GQUIC_ERROR_MISSING));
  EXPECT_EQ(" 1234:this is not good, space before first digit",
            frame.error_details);

  frame.error_details = "1234:";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_EQ(1234u,
            frame.quic_error_code);  // this is good
  EXPECT_EQ("", frame.error_details);

  // Value does not fit in uint32_t.
  frame.error_details = "12345678901:";
  MaybeExtractQuicErrorCode(&frame);
  EXPECT_THAT(frame.quic_error_code, IsError(QUIC_IETF_GQUIC_ERROR_MISSING));
  EXPECT_EQ("12345678901:", frame.error_details);
}

// Regression test for crbug/1029636.
TEST_P(QuicFramerTest, OverlyLargeAckDelay) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
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
    // ack delay time.
    kVarInt62EightBytes + 0x31, 0x00, 0x00, 0x00, 0xF3, 0xA0, 0x81, 0xE0,
    // Nr. of additional ack blocks
    kVarInt62OneByte + 0x00,
    // first ack block length.
    kVarInt62FourBytes + 0x12, 0x34, 0x56, 0x77,
  };
  // clang-format on

  framer_.ProcessPacket(QuicEncryptedPacket(
      AsChars(packet_ietf), ABSL_ARRAYSIZE(packet_ietf), false));
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  // Verify ack_delay_time is set correctly.
  EXPECT_EQ(QuicTime::Delta::Infinite(),
            visitor_.ack_frames_[0]->ack_delay_time);
}

TEST_P(QuicFramerTest, KeyUpdate) {
  if (!framer_.version().UsesTls()) {
    // Key update is only used in QUIC+TLS.
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  // Doesn't use SetDecrypterLevel since we want to use StrictTaggingDecrypter
  // instead of TestDecrypter.
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 0, false));
  ASSERT_TRUE(encrypted);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  // Processed valid packet with phase=0, key=1: no key update.
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(0, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);

  header.packet_number += 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 1, true);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  // Processed valid packet with phase=1, key=2: key update should have
  // occurred.
  ASSERT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(KeyUpdateReason::kRemote, visitor_.key_update_reasons_[0]);
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(2, visitor_.decrypted_first_packet_in_key_phase_count_);

  header.packet_number += 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 1, true);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  // Processed another valid packet with phase=1, key=2: no key update.
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(2, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process another key update.
  header.packet_number += 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 2, false);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  ASSERT_EQ(2u, visitor_.key_update_count());
  EXPECT_EQ(KeyUpdateReason::kRemote, visitor_.key_update_reasons_[1]);
  EXPECT_EQ(2, visitor_.derive_next_key_count_);
  EXPECT_EQ(3, visitor_.decrypted_first_packet_in_key_phase_count_);
}

TEST_P(QuicFramerTest, KeyUpdateOldPacketAfterUpdate) {
  if (!framer_.version().UsesTls()) {
    // Key update is only used in QUIC+TLS.
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  // Doesn't use SetDecrypterLevel since we want to use StrictTaggingDecrypter
  // instead of TestDecrypter.
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // Process packet N with phase 0.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 0, false));
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(0, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process packet N+2 with phase 1.
  header.packet_number = kPacketNumber + 2;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 1, true);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(2, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process packet N+1 with phase 0. (Receiving packet from previous phase
  // after packet from new phase was received.)
  header.packet_number = kPacketNumber + 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 0, false);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet should decrypt and key update count should not change.
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(2, visitor_.decrypted_first_packet_in_key_phase_count_);
}

TEST_P(QuicFramerTest, KeyUpdateOldPacketAfterDiscardPreviousOneRttKeys) {
  if (!framer_.version().UsesTls()) {
    // Key update is only used in QUIC+TLS.
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  // Doesn't use SetDecrypterLevel since we want to use StrictTaggingDecrypter
  // instead of TestDecrypter.
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // Process packet N with phase 0.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 0, false));
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(0, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process packet N+2 with phase 1.
  header.packet_number = kPacketNumber + 2;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 1, true);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(2, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Discard keys for previous key phase.
  framer_.DiscardPreviousOneRttKeys();

  // Process packet N+1 with phase 0. (Receiving packet from previous phase
  // after packet from new phase was received.)
  header.packet_number = kPacketNumber + 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 0, false);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet should not decrypt and key update count should not change.
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(2, visitor_.decrypted_first_packet_in_key_phase_count_);
}

TEST_P(QuicFramerTest, KeyUpdatePacketsOutOfOrder) {
  if (!framer_.version().UsesTls()) {
    // Key update is only used in QUIC+TLS.
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  // Doesn't use SetDecrypterLevel since we want to use StrictTaggingDecrypter
  // instead of TestDecrypter.
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // Process packet N with phase 0.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 0, false));
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(0, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process packet N+2 with phase 1.
  header.packet_number = kPacketNumber + 2;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 1, true);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(2, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process packet N+1 with phase 1. (Receiving packet from new phase out of
  // order.)
  header.packet_number = kPacketNumber + 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 1, true);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet should decrypt and key update count should not change.
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_coun
"""


```
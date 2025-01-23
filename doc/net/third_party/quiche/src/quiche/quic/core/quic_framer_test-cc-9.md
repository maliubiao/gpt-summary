Response:
The user wants to understand the functionality of the `quic_framer_test.cc` file in the Chromium network stack.
I need to:
1. **Summarize the file's purpose**: Based on the name and the provided code snippets, this file contains unit tests for the `QuicFramer` class. The `QuicFramer` is responsible for handling the framing of QUIC packets, including building, parsing, encrypting, and decrypting them.
2. **Check for Javascript relevance**: QUIC is a transport layer protocol, and while it facilitates faster and more reliable web connections used by Javascript applications, this specific test file doesn't directly interact with Javascript code.
3. **Provide examples of logical reasoning**: The tests often involve building a QUIC packet with specific characteristics and then verifying that the `QuicFramer` processes it correctly. I can provide examples with assumed inputs and expected outputs.
4. **Illustrate common user/programming errors**:  Errors might occur when constructing invalid QUIC packets or when the `QuicFramer` encounters malformed data. I can provide examples of such scenarios.
5. **Describe user actions leading to this code**:  This file is part of the internal implementation of the QUIC protocol in Chromium. Users don't directly interact with this code. However, developers working on the QUIC implementation or debugging network issues might need to refer to these tests.
6. **Summarize the functionality of the provided code snippets**: The provided snippets focus on testing the `QuicFramer`'s ability to build and process various types of QUIC packets, including public reset packets, stateless reset packets, and data packets with various frames like ACK, stream, and blocked frames. The code also includes tests for encryption and decryption.
7. **Acknowledge the part number**: Note that this is part 10 of 16.
这是Chromium网络栈中`net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc`文件的第10部分，该文件是`QuicFramer`类的单元测试集合。`QuicFramer`是QUIC协议栈中负责QUIC数据包的**构建、解析、加密和解密**的关键组件。

**该部分代码的功能归纳如下：**

本部分的代码主要集中在测试 `QuicFramer` 类构建和处理各种类型的QUIC数据包的能力，以及进行数据包的加密和解密操作。 具体功能点包括：

1. **构建和解析 Public Reset 数据包**: 测试了构建不同变体的 Public Reset 数据包，并验证构建的数据包内容是否与预期一致。
2. **构建和解析 IETF Stateless Reset 数据包**: 测试了构建最小长度和带随机数的 IETF Stateless Reset 数据包，并验证了数据包的格式和内容，包括状态重置令牌。
3. **加密数据包**: 测试了 `EncryptPayload` 函数，用于加密 QUIC 数据包的负载，包括带有版本标志的数据包。
4. **处理和验证 ACK 帧截断**: 测试了当 ACK 帧包含大量确认信息时，`QuicFramer` 如何进行截断，并确保在接收端能够正确解析截断后的 ACK 帧。这包括针对旧版本 QUIC 和 IETF QUIC 的不同处理方式。
5. **停止数据包处理**: 测试了当 `FramerVisitor` 返回 `false` 时，`QuicFramer` 如何停止对数据包的进一步处理。
6. **构建和解析加密数据包**: 测试了使用辅助函数 `ConstructEncryptedPacket` 构建加密数据包，并验证 `QuicFramer` 能否正确解析这些数据包。
7. **构建和解析错误格式的加密数据包**: 测试了使用 `ConstructMisFramedEncryptedPacket` 构建故意错误格式的数据包，并验证 `QuicFramer` 能否检测到错误。
8. **构建和解析 IETF Blocked 帧**: 测试了构建和解析 IETF QUIC 特有的 `DATA_BLOCKED` 和 `STREAM_DATA_BLOCKED` 帧。
9. **构建和解析 IETF Max Streams 帧**: 测试了构建和解析 IETF QUIC 特有的 `MAX_STREAMS` 帧，包括双向和单向流。

**与 JavaScript 的功能关系：**

`quic_framer_test.cc` 本身是用 C++ 编写的测试代码，并不直接与 JavaScript 代码交互。 然而，它测试的 `QuicFramer` 组件是 Chromium 网络栈的核心部分，负责处理底层的 QUIC 协议。

JavaScript 代码（例如，在浏览器中运行的 Web 应用）通过浏览器提供的 Web API (如 `fetch` 或 `XMLHttpRequest`) 发起网络请求。 如果浏览器和服务器之间协商使用 QUIC 协议，那么 `QuicFramer` 就会参与到这些请求和响应的底层处理中。

**举例说明：**

假设一个 JavaScript Web 应用使用 `fetch` API 向支持 QUIC 的服务器发送了一个请求。

1. **JavaScript 发起请求:**  JavaScript 代码调用 `fetch('https://example.com')`。
2. **浏览器处理:** 浏览器内核的网络栈会处理这个请求，并可能协商使用 QUIC 协议。
3. **构建 QUIC 数据包:**  如果使用了 QUIC，当需要发送 HTTP 请求数据时，Chromium 网络栈会使用 `QuicFramer` 来构建包含 HTTP/3 数据的 QUIC 数据包。 本部分测试代码中针对各种帧（如 Stream 帧）的构建测试就模拟了这个过程。
4. **发送数据包:** 构建好的 QUIC 数据包会被发送到服务器。
5. **接收和解析数据包 (服务器端):** 服务器端的 QUIC 实现会接收并解析这个数据包。
6. **接收和解析数据包 (客户端):** 当服务器响应时，浏览器会接收到 QUIC 数据包。  `QuicFramer` 会被用来解析这些数据包，提取出 HTTP/3 响应数据。 本部分测试代码中针对各种帧的解析测试就模拟了这个过程。
7. **JavaScript 接收响应:**  解析出的 HTTP 响应数据最终会传递给 JavaScript 的 `fetch` API 的 Promise 回调。

虽然 JavaScript 代码不直接调用 `QuicFramer`，但 `QuicFramer` 的正确性和功能是保证基于 QUIC 的 Web 应用正常运行的基础。

**逻辑推理的假设输入与输出：**

**示例 1：`BuildPublicResetPacket` 测试**

*   **假设输入:** 一个 `QuicPublicResetPacket` 对象，其中包含连接 ID、nonce proof 和 endpoint ID 等信息。
*   **预期输出:** 一个 `QuicEncryptedPacket` 对象，其内容是按照 QUIC 协议规范格式化好的 Public Reset 数据包的二进制表示，并且与预定义的 `packet_variant1` 或 `packet_variant2` 之一匹配。

**示例 2：`EncryptPacket` 测试**

*   **假设输入:** 一个包含一些负载数据的 `QuicPacket` 对象，以及当前的加密级别 `ENCRYPTION_INITIAL` 和数据包序列号。
*   **预期输出:** 一个加密后的数据包，其长度非零，并且加密后的数据包可以通过相应的解密器解密。  测试代码中 `CheckEncryption` 函数会验证加密过程。

**用户或编程常见的使用错误举例说明：**

1. **构建无效的 QUIC 数据包头:** 程序员可能错误地设置数据包头部的标志位或连接 ID 长度，导致 `QuicFramer` 在解析时出错。 例如，设置了错误的连接 ID 长度，导致后续读取连接 ID 时越界。 本部分测试中错误格式数据包的测试 (`ConstructMisFramedEncryptedPacket`) 就在模拟这种情况。
2. **计算错误的帧长度:** 在构建包含帧的数据包时，如果计算的帧长度与实际数据长度不符，会导致接收端解析失败。
3. **使用错误的加密级别进行加密或解密:** QUIC 使用不同的加密级别，如果发送方和接收方使用的加密级别不一致，会导致解密失败。 测试代码中会显式设置加密级别 (`SetDecrypterLevel`) 并进行加密和解密测试，以避免这种错误。
4. **ACK 帧信息不一致:**  构建 ACK 帧时，如果确认的包序列号范围存在逻辑错误，例如确认了一个尚未发送的包，或者确认范围有重叠，会导致通信错误。 本部分测试中针对 ACK 帧截断的测试旨在验证在复杂场景下 ACK 帧的构建和解析的正确性。

**用户操作是如何一步步的到达这里，作为调试线索：**

作为开发者，在以下情况下可能会查看或调试到 `quic_framer_test.cc` 中的代码：

1. **QUIC 协议实现开发:** 当开发或修改 Chromium 的 QUIC 协议实现时，需要编写和运行这些单元测试来验证代码的正确性。
2. **网络性能调试:** 如果发现基于 QUIC 的网络连接出现问题，例如连接失败、数据传输错误或性能下降，开发者可能会查看 `QuicFramer` 的相关代码，包括测试代码，以了解数据包的构建、解析和处理流程，从而定位问题。
3. **安全漏洞排查:** QUIC 的安全特性很大程度上依赖于数据包的正确加密和解密。 如果怀疑存在与 QUIC 协议相关的安全漏洞，开发者可能会分析 `QuicFramer` 的加密和解密逻辑，并参考测试代码来验证其安全性。
4. **排查特定帧类型的问题:** 如果在处理特定类型的 QUIC 帧（如 ACK 帧、Stream 帧或 Blocked 帧）时遇到错误，开发者会查看 `quic_framer_test.cc` 中针对该帧类型的测试用例，来理解预期的行为和验证自己的代码。

**总结该部分的功能 (第 10 部分):**

该部分主要集中测试 `QuicFramer` 构建和解析各种控制类型和数据类型的 QUIC 数据包的能力，包括 Public Reset、Stateless Reset、以及包含不同帧（如 ACK、Stream、Blocked 和 Max Streams）的数据包。 此外，还测试了数据包的加密和在特定情况下 ACK 帧的截断处理。 这些测试确保了 `QuicFramer` 能够正确地处理各种QUIC协议场景，是保证Chromium QUIC 实现正确性的重要组成部分。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共16部分，请归纳一下它的功能
```

### 源代码
```cpp
clang-format off
  unsigned char packet_variant1[] = {
      // public flags (public reset, 8 byte ConnectionId)
      0x0E,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98,
      0x76, 0x54, 0x32, 0x10,
      // message tag (kPRST)
      'P', 'R', 'S', 'T',
      // num_entries (2) + padding
      0x02, 0x00, 0x00, 0x00,
      // tag kRNON
      'R', 'N', 'O', 'N',
      // end offset 8
      0x08, 0x00, 0x00, 0x00,
      // tag kEPID
      'E', 'P', 'I', 'D',
      // end offset 20
      0x14, 0x00, 0x00, 0x00,
      // nonce proof
      0x89, 0x67, 0x45, 0x23,
      0x01, 0xEF, 0xCD, 0xAB,
      // Endpoint ID
      'F', 'a', 'k', 'e', 'S', 'e', 'r', 'v', 'e', 'r', 'I', 'd',
  };
  unsigned char packet_variant2[] = {
      // public flags (public reset, 8 byte ConnectionId)
      0x0E,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98,
      0x76, 0x54, 0x32, 0x10,
      // message tag (kPRST)
      'P', 'R', 'S', 'T',
      // num_entries (2) + padding
      0x02, 0x00, 0x00, 0x00,
      // tag kEPID
      'E', 'P', 'I', 'D',
      // end offset 12
      0x0C, 0x00, 0x00, 0x00,
      // tag kRNON
      'R', 'N', 'O', 'N',
      // end offset 20
      0x14, 0x00, 0x00, 0x00,
      // Endpoint ID
      'F', 'a', 'k', 'e', 'S', 'e', 'r', 'v', 'e', 'r', 'I', 'd',
      // nonce proof
      0x89, 0x67, 0x45, 0x23,
      0x01, 0xEF, 0xCD, 0xAB,
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> data(
      framer_.BuildPublicResetPacket(reset_packet));
  ASSERT_TRUE(data != nullptr);

  // Variant 1 ends with char 'd'. Variant 1 ends with char 0xAB.
  if ('d' == data->data()[data->length() - 1]) {
    quiche::test::CompareCharArraysWithHexError(
        "constructed packet", data->data(), data->length(),
        AsChars(packet_variant1), ABSL_ARRAYSIZE(packet_variant1));
  } else {
    quiche::test::CompareCharArraysWithHexError(
        "constructed packet", data->data(), data->length(),
        AsChars(packet_variant2), ABSL_ARRAYSIZE(packet_variant2));
  }
}

TEST_P(QuicFramerTest, BuildIetfStatelessResetPacket) {
  // clang-format off
    unsigned char packet[] = {
      // 1st byte 01XX XXXX
      0x40,
      // At least 4 bytes of random bytes.
      0x00, 0x00, 0x00, 0x00,
      // stateless reset token
      0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f
    };
  // clang-format on

  // Build the minimal stateless reset packet.
  std::unique_ptr<QuicEncryptedPacket> data(
      framer_.BuildIetfStatelessResetPacket(
          FramerTestConnectionId(),
          QuicFramer::GetMinStatelessResetPacketLength() + 1,
          kTestStatelessResetToken));
  ASSERT_TRUE(data);
  EXPECT_EQ(QuicFramer::GetMinStatelessResetPacketLength(), data->length());
  // Verify the first 2 bits are 01.
  EXPECT_FALSE(data->data()[0] & FLAGS_LONG_HEADER);
  EXPECT_TRUE(data->data()[0] & FLAGS_FIXED_BIT);
  // Verify stateless reset token.
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet",
      data->data() + data->length() - kStatelessResetTokenLength,
      kStatelessResetTokenLength,
      AsChars(packet) + ABSL_ARRAYSIZE(packet) - kStatelessResetTokenLength,
      kStatelessResetTokenLength);

  // Packets with length <= minimal stateless reset does not trigger stateless
  // reset.
  std::unique_ptr<QuicEncryptedPacket> data2(
      framer_.BuildIetfStatelessResetPacket(
          FramerTestConnectionId(),
          QuicFramer::GetMinStatelessResetPacketLength(),
          kTestStatelessResetToken));
  ASSERT_FALSE(data2);

  // Do not send stateless reset >= minimal stateless reset + 1 + max
  // connection ID length.
  std::unique_ptr<QuicEncryptedPacket> data3(
      framer_.BuildIetfStatelessResetPacket(FramerTestConnectionId(), 1000,
                                            kTestStatelessResetToken));
  ASSERT_TRUE(data3);
  EXPECT_EQ(QuicFramer::GetMinStatelessResetPacketLength() + 1 +
                kQuicMaxConnectionIdWithLengthPrefixLength,
            data3->length());
}

TEST_P(QuicFramerTest, BuildIetfStatelessResetPacketCallerProvidedRandomBytes) {
  // clang-format off
    unsigned char packet[] = {
      // 1st byte 01XX XXXX
      0x7c,
      // Random bytes
      0x7c, 0x7c, 0x7c, 0x7c,
      // stateless reset token
      0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f
    };
  // clang-format on

  // Build the minimal stateless reset packet with caller-provided random bytes.
  MockRandom random;
  auto generate_random_bytes = [](void* data, size_t len) {
    std::string bytes(len, 0x7c);
    memcpy(data, bytes.data(), bytes.size());
  };
  EXPECT_CALL(random, InsecureRandBytes(_, _))
      .WillOnce(testing::Invoke(generate_random_bytes));
  std::unique_ptr<QuicEncryptedPacket> data(
      framer_.BuildIetfStatelessResetPacket(
          FramerTestConnectionId(),
          QuicFramer::GetMinStatelessResetPacketLength() + 1,
          kTestStatelessResetToken, &random));
  ASSERT_TRUE(data);
  EXPECT_EQ(QuicFramer::GetMinStatelessResetPacketLength(), data->length());
  // Verify the first 2 bits are 01.
  EXPECT_FALSE(data->data()[0] & FLAGS_LONG_HEADER);
  EXPECT_TRUE(data->data()[0] & FLAGS_FIXED_BIT);
  // Verify the entire packet.
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, EncryptPacket) {
  QuicPacketNumber packet_number = kPacketNumber;
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
  };

  unsigned char packet50[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
    'q',  'r',  's',  't',
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasHeaderProtection()) {
    p = packet50;
    p_size = ABSL_ARRAYSIZE(packet50);
  }

  std::unique_ptr<QuicPacket> raw(new QuicPacket(
      AsChars(p), p_size, false, kPacket8ByteConnectionId,
      kPacket0ByteConnectionId, !kIncludeVersion, !kIncludeDiversificationNonce,
      PACKET_4BYTE_PACKET_NUMBER, quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0));
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_INITIAL, packet_number, *raw, buffer, kMaxOutgoingPacketSize);

  ASSERT_NE(0u, encrypted_length);
  EXPECT_TRUE(CheckEncryption(packet_number, raw.get()));
}

// Regression test for b/158014497.
TEST_P(QuicFramerTest, EncryptEmptyPacket) {
  auto packet = std::make_unique<QuicPacket>(
      new char[100], 0, true, kPacket8ByteConnectionId,
      kPacket0ByteConnectionId,
      /*includes_version=*/true,
      /*includes_diversification_nonce=*/true, PACKET_1BYTE_PACKET_NUMBER,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0,
      /*retry_token_length=*/0, quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0);
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length = 1;
  EXPECT_QUIC_BUG(
      {
        encrypted_length =
            framer_.EncryptPayload(ENCRYPTION_INITIAL, kPacketNumber, *packet,
                                   buffer, kMaxOutgoingPacketSize);
        EXPECT_EQ(0u, encrypted_length);
      },
      "packet is shorter than associated data length");
}

TEST_P(QuicFramerTest, EncryptPacketWithVersionFlag) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketNumber packet_number = kPacketNumber;
  // clang-format off
  unsigned char packet[] = {
    // type (long header with packet type ZERO_RTT_PROTECTED)
    0xD3,
    // version tag
    'Q', '.', '1', '0',
    // connection_id length
    0x50,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
  };

  unsigned char packet50[] = {
    // type (long header with packet type ZERO_RTT_PROTECTED)
    0xD3,
    // version tag
    'Q', '.', '1', '0',
    // destination connection ID length
    0x08,
    // destination connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // source connection ID length
    0x00,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
    'q',  'r',  's',  't',
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  // TODO(ianswett): see todo in previous test.
  if (framer_.version().HasHeaderProtection()) {
    p = packet50;
    p_size = ABSL_ARRAYSIZE(packet50);
  }

  std::unique_ptr<QuicPacket> raw(new QuicPacket(
      AsChars(p), p_size, false, kPacket8ByteConnectionId,
      kPacket0ByteConnectionId, kIncludeVersion, !kIncludeDiversificationNonce,
      PACKET_4BYTE_PACKET_NUMBER, quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0));
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_INITIAL, packet_number, *raw, buffer, kMaxOutgoingPacketSize);

  ASSERT_NE(0u, encrypted_length);
  EXPECT_TRUE(CheckEncryption(packet_number, raw.get()));
}

TEST_P(QuicFramerTest, AckTruncationLargePacket) {
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This test is not applicable to this version; the range count is
    // effectively unlimited
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame;
  // Create a packet with just the ack.
  ack_frame = MakeAckFrameWithAckBlocks(300, 0u);
  QuicFrames frames = {QuicFrame(&ack_frame)};

  // Build an ack packet with truncation due to limit in number of nack ranges.
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
  EXPECT_EQ(QuicPacketNumber(600u), LargestAcked(processed_ack_frame));
  ASSERT_EQ(256u, processed_ack_frame.packets.NumPacketsSlow());
  EXPECT_EQ(QuicPacketNumber(90u), processed_ack_frame.packets.Min());
  EXPECT_EQ(QuicPacketNumber(600u), processed_ack_frame.packets.Max());
}

// Regression test for b/150386368.
TEST_P(QuicFramerTest, IetfAckFrameTruncation) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

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
  ack_frame.ecn_counters = QuicEcnCounts(100, 10000, 1000000);
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
  // Verify ACK frame gets truncated.
  ASSERT_LT(processed_ack_frame.packets.NumPacketsSlow(),
            ack_frame.packets.NumIntervals());
  EXPECT_EQ(157u, processed_ack_frame.packets.NumPacketsSlow());
  EXPECT_LT(processed_ack_frame.packets.NumIntervals(),
            ack_frame.packets.NumIntervals());
  EXPECT_EQ(QuicPacketNumber(kMaxIetfVarInt),
            processed_ack_frame.packets.Max());
}

TEST_P(QuicFramerTest, AckTruncationSmallPacket) {
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This test is not applicable to this version; the range count is
    // effectively unlimited
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Create a packet with just the ack.
  QuicAckFrame ack_frame;
  ack_frame = MakeAckFrameWithAckBlocks(300, 0u);
  QuicFrames frames = {QuicFrame(&ack_frame)};

  // Build an ack packet with truncation due to limit in number of nack ranges.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> raw_ack_packet(
      BuildDataPacket(header, frames, 500));
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
  EXPECT_EQ(QuicPacketNumber(600u), LargestAcked(processed_ack_frame));
  ASSERT_EQ(240u, processed_ack_frame.packets.NumPacketsSlow());
  EXPECT_EQ(QuicPacketNumber(122u), processed_ack_frame.packets.Min());
  EXPECT_EQ(QuicPacketNumber(600u), processed_ack_frame.packets.Max());
}

TEST_P(QuicFramerTest, CleanTruncation) {
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This test is not applicable to this version; the range count is
    // effectively unlimited
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame = InitAckFrame(201);

  // Create a packet with just the ack.
  QuicFrames frames = {QuicFrame(&ack_frame)};
  if (framer_.version().HasHeaderProtection()) {
    frames.push_back(QuicFrame(QuicPaddingFrame(12)));
  }
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

  // Test for clean truncation of the ack by comparing the length of the
  // original packets to the re-serialized packets.
  frames.clear();
  frames.push_back(QuicFrame(visitor_.ack_frames_[0].get()));
  if (framer_.version().HasHeaderProtection()) {
    frames.push_back(QuicFrame(*visitor_.padding_frames_[0].get()));
  }

  size_t original_raw_length = raw_ack_packet->length();
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  raw_ack_packet = BuildDataPacket(header, frames);
  ASSERT_TRUE(raw_ack_packet != nullptr);
  EXPECT_EQ(original_raw_length, raw_ack_packet->length());
  ASSERT_TRUE(raw_ack_packet != nullptr);
}

TEST_P(QuicFramerTest, StopPacketProcessing) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

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

    // frame type (ack frame)
    0x40,
    // least packet number awaiting an ack
    0x12, 0x34, 0x56, 0x78,
    0x9A, 0xA0,
    // largest observed packet number
    0x12, 0x34, 0x56, 0x78,
    0x9A, 0xBF,
    // num missing packets
    0x01,
    // missing packet
    0x12, 0x34, 0x56, 0x78,
    0x9A, 0xBE,
  };

  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_STREAM frame with fin, length, and offset bits set)
    0x08 | 0x01 | 0x02 | 0x04,
    // stream id
    kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04,
    // offset
    kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
    0x32, 0x10, 0x76, 0x54,
    // data length
    kVarInt62TwoBytes + 0x00, 0x0c,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',

    // frame type (ack frame)
    0x0d,
    // largest observed packet number
    kVarInt62FourBytes + 0x12, 0x34, 0x56, 0x78,
    // Delta time
    kVarInt62OneByte + 0x00,
    // Ack Block count
    kVarInt62OneByte + 0x01,
    // First block size (one packet)
    kVarInt62OneByte + 0x00,

    // Next gap size & ack. Missing all preceding packets
    kVarInt62FourBytes + 0x12, 0x34, 0x56, 0x77,
    kVarInt62OneByte + 0x00,
  };
  // clang-format on

  MockFramerVisitor visitor;
  framer_.set_visitor(&visitor);
  EXPECT_CALL(visitor, OnPacket());
  EXPECT_CALL(visitor, OnPacketHeader(_));
  EXPECT_CALL(visitor, OnStreamFrame(_)).WillOnce(Return(false));
  EXPECT_CALL(visitor, OnPacketComplete());
  EXPECT_CALL(visitor, OnUnauthenticatedPublicHeader(_)).WillOnce(Return(true));
  EXPECT_CALL(visitor, OnUnauthenticatedHeader(_)).WillOnce(Return(true));
  EXPECT_CALL(visitor, OnDecryptedPacket(_, _));

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }
  QuicEncryptedPacket encrypted(AsChars(p), p_size, false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());
}

static char kTestString[] = "At least 20 characters.";
static QuicStreamId kTestQuicStreamId = 1;

MATCHER_P(ExpectedStreamFrame, version, "") {
  return (arg.stream_id == kTestQuicStreamId ||
          QuicUtils::IsCryptoStreamId(version.transport_version,
                                      arg.stream_id)) &&
         !arg.fin && arg.offset == 0 &&
         std::string(arg.data_buffer, arg.data_length) == kTestString;
  // FIN is hard-coded false in ConstructEncryptedPacket.
  // Offset 0 is hard-coded in ConstructEncryptedPacket.
}

// Verify that the packet returned by ConstructEncryptedPacket() can be properly
// parsed by the framer.
TEST_P(QuicFramerTest, ConstructEncryptedPacket) {
  // Since we are using ConstructEncryptedPacket, we have to set the framer's
  // crypto to be Null.
  if (framer_.version().KnowsWhichDecrypterToUse()) {
    framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                             std::make_unique<StrictTaggingDecrypter>(
                                 (uint8_t)ENCRYPTION_FORWARD_SECURE));
  } else {
    framer_.SetDecrypter(ENCRYPTION_FORWARD_SECURE,
                         std::make_unique<StrictTaggingDecrypter>(
                             (uint8_t)ENCRYPTION_FORWARD_SECURE));
  }
  ParsedQuicVersionVector versions;
  versions.push_back(framer_.version());
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructEncryptedPacket(
      TestConnectionId(), EmptyQuicConnectionId(), false, false,
      kTestQuicStreamId, kTestString, CONNECTION_ID_PRESENT,
      CONNECTION_ID_ABSENT, PACKET_4BYTE_PACKET_NUMBER, &versions));

  MockFramerVisitor visitor;
  framer_.set_visitor(&visitor);
  EXPECT_CALL(visitor, OnPacket()).Times(1);
  EXPECT_CALL(visitor, OnUnauthenticatedPublicHeader(_))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_CALL(visitor, OnUnauthenticatedHeader(_))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_CALL(visitor, OnPacketHeader(_)).Times(1).WillOnce(Return(true));
  EXPECT_CALL(visitor, OnDecryptedPacket(_, _)).Times(1);
  EXPECT_CALL(visitor, OnError(_)).Times(0);
  EXPECT_CALL(visitor, OnStreamFrame(_)).Times(0);
  if (!QuicVersionUsesCryptoFrames(framer_.version().transport_version)) {
    EXPECT_CALL(visitor, OnStreamFrame(ExpectedStreamFrame(framer_.version())))
        .Times(1);
  } else {
    EXPECT_CALL(visitor, OnCryptoFrame(_)).Times(1);
  }
  EXPECT_CALL(visitor, OnPacketComplete()).Times(1);

  EXPECT_TRUE(framer_.ProcessPacket(*packet));
  EXPECT_THAT(framer_.error(), IsQuicNoError());
}

// Verify that the packet returned by ConstructMisFramedEncryptedPacket()
// does cause the framer to return an error.
TEST_P(QuicFramerTest, ConstructMisFramedEncryptedPacket) {
  // Since we are using ConstructEncryptedPacket, we have to set the framer's
  // crypto to be Null.
  if (framer_.version().KnowsWhichDecrypterToUse()) {
    framer_.InstallDecrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  }
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructMisFramedEncryptedPacket(
      TestConnectionId(), EmptyQuicConnectionId(), false, false,
      kTestQuicStreamId, kTestString, CONNECTION_ID_PRESENT,
      CONNECTION_ID_ABSENT, PACKET_4BYTE_PACKET_NUMBER, framer_.version(),
      Perspective::IS_CLIENT));

  MockFramerVisitor visitor;
  framer_.set_visitor(&visitor);
  EXPECT_CALL(visitor, OnPacket()).Times(1);
  EXPECT_CALL(visitor, OnUnauthenticatedPublicHeader(_))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_CALL(visitor, OnUnauthenticatedHeader(_))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_CALL(visitor, OnPacketHeader(_)).Times(1);
  EXPECT_CALL(visitor, OnDecryptedPacket(_, _)).Times(1);
  EXPECT_CALL(visitor, OnError(_)).Times(1);
  EXPECT_CALL(visitor, OnStreamFrame(_)).Times(0);
  EXPECT_CALL(visitor, OnPacketComplete()).Times(0);

  EXPECT_FALSE(framer_.ProcessPacket(*packet));
  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_FRAME_DATA));
}

TEST_P(QuicFramerTest, IetfBlockedFrame) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
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
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (IETF_DATA_BLOCKED)
      {"",
       {0x14}},
      // blocked offset
      {"Can not read blocked offset.",
       {kVarInt62EightBytes + 0x3a, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54}},
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

  EXPECT_EQ(kStreamOffset, visitor_.blocked_frame_.offset);

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_BLOCKED_DATA);
}

TEST_P(QuicFramerTest, BuildIetfBlockedPacket) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicBlockedFrame frame;
  frame.stream_id = QuicUtils::GetInvalidStreamId(framer_.transport_version());
  frame.offset = kStreamOffset;
  QuicFrames frames = {QuicFrame(frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_DATA_BLOCKED)
    0x14,
    // Offset
    kVarInt62EightBytes + 0x3a, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, IetfStreamBlockedFrame) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
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
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (IETF_STREAM_DATA_BLOCKED)
      {"",
       {0x15}},
      // blocked offset
      {"Unable to read IETF_STREAM_DATA_BLOCKED frame stream id/count.",
       {kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04}},
      {"Can not read stream blocked offset.",
       {kVarInt62EightBytes + 0x3a, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54}},
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

  EXPECT_EQ(kStreamId, visitor_.blocked_frame_.stream_id);
  EXPECT_EQ(kStreamOffset, visitor_.blocked_frame_.offset);

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_STREAM_BLOCKED_DATA);
}

TEST_P(QuicFramerTest, BuildIetfStreamBlockedPacket) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicBlockedFrame frame;
  frame.stream_id = kStreamId;
  frame.offset = kStreamOffset;
  QuicFrames frames = {QuicFrame(frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_STREAM_DATA_BLOCKED)
    0x15,
    // Stream ID
    kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04,
    // Offset
    kVarInt62EightBytes + 0x3a, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BiDiMaxStreamsFrame) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
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
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (IETF_MAX_STREAMS_BIDIRECTIONAL)
      {"",
       {0x12}},
      // max. streams
      {"Unable to read IETF_MAX_STREAMS_BIDIRECTIONAL frame stream id/count.",
       {kVarInt62OneByte + 0x03}},
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

  EXPECT_EQ(3u, visitor_.max_streams_frame_.stream_count);
  EXPECT_FALSE(visitor_.max_streams_frame_.unidirectional);
  CheckFramingBoundaries(packet_ietf, QUIC_MAX_STREAMS_DATA);
}

TEST_P(QuicFramerTest, UniDiMaxStreamsFrame) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // Test runs in client mode, no connection id
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (IETF_MAX_STREAMS_UNIDIRECTIONAL)
      {"",
       {0x13}},
      // max. streams
      {"Unable to read IETF_MAX_STREAMS_UNIDIRECTIONAL frame stream id/count.",
       {kVarInt62OneByte + 0x03}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket0ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(3u, visitor_.max_streams_frame_.stream_count);
  EXPECT_TRUE(visitor_.max_streams_frame_.unidirectional);
  CheckFramingBoundaries(packet_ietf, QUIC_MAX_STREAMS_DATA);
}

TEST_P(QuicFramerTest, ServerUniDiMaxStreamsFrame) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
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
       {0xFE, 0xDC
```
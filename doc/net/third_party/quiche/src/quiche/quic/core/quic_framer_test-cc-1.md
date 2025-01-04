Response:
The user wants to understand the functionality of the provided C++ code snippet from `quic_framer_test.cc`. This is part 2 of 16. I need to:

1. **Summarize the functionality of this specific code block.** This involves looking at the methods and data members defined within the `QuicFramerTest` class.
2. **Identify any relationships to JavaScript.**  This will likely involve understanding how QUIC (the underlying protocol being tested) interacts with web browsers and potentially how JavaScript might use QUIC.
3. **Provide examples of logical reasoning with input/output.**  This means picking a function and demonstrating how it transforms input to output.
4. **Highlight common user/programming errors.** This requires thinking about how someone might misuse the functionalities provided in the code.
5. **Describe the user steps leading to this code (debugging context).** This involves imagining a scenario where a developer would be interacting with this test code.
6. **Since this is part 2 of 16, I should focus on the functionality introduced in *this specific chunk* of code, building on the likely context from part 1 (which I don't have, so I'll make reasonable assumptions).**

**Functionality Breakdown of the Snippet:**

* **`CheckFramingBoundaries`:** This function seems to be a core testing utility. It takes a set of packet fragments and checks how the `QuicFramer` handles incomplete packets. It iterates through various prefixes of the assembled packet and expects specific errors for incomplete parts.
* **`CheckProcessingFails` (two overloads):** These functions directly test the `ProcessPacket` method of the `QuicFramer` with incomplete packets and verify the expected error codes and detailed error messages.
* **`CheckStreamFrameData`:** This utility function compares the data within a `QuicStreamFrame` against an expected string.
* **`CheckCalculatePacketNumber`:** This function tests the logic of calculating the full packet number from a wire representation, given the last seen packet number. This is crucial for handling packet number wrapping.
* **`BuildDataPacket` (two overloads):** These functions seem to be helpers for constructing `QuicPacket` objects for testing purposes.
* **`GetNthStreamid`:**  This function calculates the stream ID for a given stream number, considering the QUIC transport version, perspective (client/server), and stream directionality.
* **`CreationTimePlus`:** This utility adds a time delta to the framer's creation time.
* **Data Members:** The code declares data members that are likely initialized in the test fixture setup: `encrypter_`, `decrypter_`, `version_`, `start_`, `framer_`, `visitor_`, `allocator_`. These represent the components needed to test the framing logic.
* **`QUIC_VERSION_BYTES` macro:** This macro converts the QUIC version number into a byte sequence.

**JavaScript Relationship:**

QUIC is a transport protocol often used in web browsers. While this C++ code is for testing the QUIC implementation, the functionalities it tests directly impact how JavaScript running in a browser interacts with a QUIC-enabled server.

**Logical Reasoning Examples:**

Let's take `CheckCalculatePacketNumber`:

* **Hypothesis:** If the last packet number seen is near the epoch boundary and a small wire packet number is received, the calculated packet number should wrap around to the next epoch.
* **Input:** `last_packet_number = kEpoch - 1`, `wire_packet_number = 0`
* **Output:** `calculated_packet_number = kEpoch`

Let's take `GetNthStreamid`:

* **Hypothesis:** For a client, bidirectional stream IDs start at a specific value and increment by a defined delta.
* **Input:** `transport_version = GetParam()`, `perspective = Perspective::IS_CLIENT`, `bidirectional = true`, `n = 2`
* **Output:** `QuicUtils::GetFirstBidirectionalStreamId(GetParam(), Perspective::IS_CLIENT) + QuicUtils::StreamIdDelta(GetParam())`

**Common User/Programming Errors:**

* **Incorrect packet construction:**  Manually creating packet byte arrays for testing is prone to errors. For example, calculating the packet length incorrectly, using the wrong byte order, or omitting required fields. The `AssemblePacketFromFragments` function tries to mitigate this, but the initial `PacketFragments` could be wrong.
* **Mismatched encryption levels:** If the test expects a packet to be encrypted at a certain level (e.g., forward-secure), but the decrypter is set to a lower level, processing will fail.
* **Incorrectly setting expectations in the visitor:** The `visitor_` object is used to verify the parsed packet header and frames. Failing to set the correct expectations on the visitor will lead to incorrect test results.

**User Steps for Debugging:**

1. **A developer notices a bug related to packet framing.** This could manifest as connection errors, incorrect data transmission, or crashes.
2. **They suspect the `QuicFramer` is not correctly parsing packets.**
3. **They might run specific unit tests within `quic_framer_test.cc`** that exercise the problematic framing logic.
4. **If a test fails, they would step through the code in a debugger.**  They would set breakpoints in functions like `ProcessPacket`, `ParsePublicHeader`, or the utility functions like `CheckFramingBoundaries`.
5. **They would inspect the packet bytes, the internal state of the `QuicFramer`, and the values in the `visitor_` object.**  This would help them identify where the parsing logic deviates from the expected behavior.
6. **They might modify the test case or add new test cases** to isolate the bug and ensure a fix works correctly. They might create specific `PacketFragments` that trigger the bug.

**Summary of Functionality in Part 2:**

This section of `quic_framer_test.cc` defines several utility functions within the `QuicFramerTest` class to facilitate testing the packet processing logic of the `QuicFramer`. These functions include:
* **Boundary checking:** Verifying error handling for incomplete packets.
* **Stream frame data verification:** Comparing stream frame contents.
* **Packet number calculation testing:** Ensuring correct handling of packet number wrapping.
* **Packet construction helpers:** Simplifying the creation of test packets.
* **Stream ID generation:**  Creating stream IDs based on context.
* **Time manipulation:**  Adjusting timestamps for testing.

These utilities are essential for writing comprehensive tests that cover various edge cases and potential error scenarios in QUIC packet framing.

这是文件 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 的第二部分，它延续了对 Chromium 网络栈中 QUIC 协议帧处理器的测试。本部分主要定义了一些辅助测试的工具函数，以及一些针对特定场景的测试用例。

**本部分的主要功能归纳如下：**

1. **辅助测试工具函数：**
   - `CheckFramingBoundaries`:  用于测试 `QuicFramer` 处理不完整数据包边界情况的能力。它会截断数据包的不同部分，并验证是否会产生预期的错误。
   - `CheckProcessingFails`:  用于断言 `QuicFramer::ProcessPacket` 在给定长度的数据包上处理失败，并检查是否输出了预期的错误信息和错误代码。
   - `CheckStreamFrameData`: 用于验证 `QuicStreamFrame` 中的数据是否与预期字符串一致。
   - `CheckCalculatePacketNumber`:  用于测试从线路上读取的包序号计算出完整包序号的逻辑，尤其关注包序号回绕的情况。
   - `BuildDataPacket`:  用于构建包含指定头部和帧的 `QuicPacket` 对象，方便测试用例使用。
   - `GetNthStreamid`:  根据传输版本、视角（客户端/服务器）、是否双向以及流的序号，计算出对应的流ID。
   - `CreationTimePlus`:  在 `QuicFramer` 的创建时间上增加一个偏移量，用于模拟不同的时间点。

2. **包序号计算逻辑的测试用例：**
   - `CalculatePacketNumberFromWireNearEpochStart`: 测试在最后接收到的包序号接近纪元开始时，计算新包序号的逻辑。
   - `CalculatePacketNumberFromWireNearEpochEnd`: 测试在最后接收到的包序号接近纪元结束时，计算新包序号的逻辑。
   - `CalculatePacketNumberFromWireNearPrevEpoch`: 测试在最后接收到的包序号接近前一个纪元时，计算新包序号的逻辑。
   - `CalculatePacketNumberFromWireNearNextEpoch`: 测试在最后接收到的包序号接近下一个纪元时，计算新包序号的逻辑。
   - `CalculatePacketNumberFromWireNearNextMax`: 测试在最后接收到的包序号接近最大值时，计算新包序号的逻辑。

3. **基本的包处理测试用例：**
   - `EmptyPacket`: 测试处理空数据包的情况，预期会失败并返回 `QUIC_INVALID_PACKET_HEADER` 错误。
   - `LargePacket`: 测试处理超过最大允许大小的数据包的情况，预期会失败并返回 `QUIC_PACKET_TOO_LARGE` 错误。

**与 JavaScript 功能的关系：**

QUIC 协议是 HTTP/3 的底层传输协议，因此与 JavaScript 在 Web 开发中使用的 `fetch` API 和 WebSocket API 有间接关系。当 JavaScript 代码通过这些 API 发起网络请求时，如果浏览器和服务器之间协商使用 QUIC，那么这些请求的数据就会被封装成 QUIC 数据包进行传输。

例如：

- 当 JavaScript 使用 `fetch` 发送一个请求时，浏览器会将请求头、请求体等数据封装成 QUIC 的 STREAM 帧。`QuicStreamFrame` 的数据部分就包含了这些信息。`CheckStreamFrameData` 这个测试函数就模拟了验证接收到的 STREAM 帧的数据内容是否符合预期。
- 包序号的计算逻辑 (通过 `CalculatePacketNumberFromWire...` 测试用例测试) 确保了数据包的可靠传输和按序接收，这对于 JavaScript 发起的请求能否正确响应至关重要。

**逻辑推理举例：**

**假设输入:**

- 在 `CalculatePacketNumberFromWireNearEpochStart` 测试用例中，`last_packet_number` 为 0，接收到的 `wire_packet_number` 也为 0。
- 在 `GetNthStreamid` 函数中，`transport_version` 为某个支持的版本，`perspective` 为 `Perspective::IS_CLIENT`，`bidirectional` 为 `true`，`n` 为 3。

**预期输出:**

- 对于 `CalculatePacketNumberFromWireNearEpochStart`，根据包序号计算逻辑，预期计算出的完整包序号应该为 0。
- 对于 `GetNthStreamid`，预期计算出的流 ID 将是客户端第一个双向流 ID 加上两个流 ID 的增量。例如，如果第一个双向流 ID 是 0，增量是 4，那么结果应该是 8。

**用户或编程常见的使用错误举例：**

- **手动构建数据包时，包头字段填写错误：** 比如在构建测试用的字节数组时，错误地设置了连接 ID 的长度、包序号的长度或者版本号。这会导致 `QuicFramer::ProcessPacket` 解析失败，并且可能触发 `CheckFramingBoundaries` 中定义的错误检查。
- **在测试用例中，对 `visitor_` 的预期设置不正确：** `visitor_` 对象用于记录 `QuicFramer` 解析数据包的结果。如果测试用例中对 `visitor_` 成员的预期值设置错误，即使 `QuicFramer` 的行为是正确的，测试也会失败。
- **不理解包序号回绕的机制：** 在编写处理 QUIC 数据包的逻辑时，如果没有正确理解包序号的回绕机制，可能会导致重复接收或丢失数据包。`CalculatePacketNumberFromWire...` 这些测试用例就是为了验证这种回绕机制的正确性。

**用户操作如何一步步到达这里作为调试线索：**

假设开发者在测试或调试基于 Chromium 网络栈的 QUIC 实现时遇到了数据包解析相关的问题，例如：

1. **网络请求失败或行为异常：** 用户可能在使用基于 Chromium 的浏览器或应用程序时遇到网络请求卡住、数据传输不完整或者连接意外断开的情况。
2. **怀疑是 QUIC 帧处理器的 bug：** 开发者可能会怀疑是 QUIC 协议的帧处理器 (`QuicFramer`) 在解析或处理数据包时出现了错误。
3. **运行相关的单元测试：** 开发者可能会运行 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 中的单元测试，特别是那些与包头解析、包序号计算或不完整数据包处理相关的测试用例。
4. **定位到失败的测试用例：** 如果某个测试用例失败了，比如 `EmptyPacket` 或 `LargePacket` 测试失败，开发者就会开始分析这个测试用例的代码。
5. **分析辅助测试函数：** 开发者会查看 `CheckFramingBoundaries`、`CheckProcessingFails` 等辅助函数，理解测试用例是如何验证 `QuicFramer` 的行为的。
6. **检查数据包的构造和预期结果：** 开发者会仔细检查测试用例中构建的测试数据包的字节数组，以及预期 `QuicFramer` 产生的错误信息和错误代码，从而找到问题所在。

总而言之，这部分代码是 QUIC 协议帧处理器单元测试的核心组成部分，它通过定义一系列辅助函数和测试用例，来确保 `QuicFramer` 能够正确地解析和处理各种 QUIC 数据包，包括异常和边界情况。这对于保证基于 QUIC 协议的网络连接的稳定性和可靠性至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共16部分，请归纳一下它的功能

"""
                 << " associated data: "
                      << absl::BytesToHexString(associated_data);
      return false;
    }
    return true;
  }

  char* AsChars(unsigned char* data) { return reinterpret_cast<char*>(data); }

  // Creates a new QuicEncryptedPacket by concatenating the various
  // packet fragments in |fragments|.
  std::unique_ptr<QuicEncryptedPacket> AssemblePacketFromFragments(
      const PacketFragments& fragments) {
    char* buffer = new char[kMaxOutgoingPacketSize + 1];
    size_t len = 0;
    for (const auto& fragment : fragments) {
      memcpy(buffer + len, fragment.fragment.data(), fragment.fragment.size());
      len += fragment.fragment.size();
    }
    return std::make_unique<QuicEncryptedPacket>(buffer, len, true);
  }

  void CheckFramingBoundaries(const PacketFragments& fragments,
                              QuicErrorCode error_code) {
    std::unique_ptr<QuicEncryptedPacket> packet(
        AssemblePacketFromFragments(fragments));
    // Check all the various prefixes of |packet| for the expected
    // parse error and error code.
    for (size_t i = 0; i < packet->length(); ++i) {
      std::string expected_error;
      size_t len = 0;
      for (const auto& fragment : fragments) {
        len += fragment.fragment.size();
        if (i < len) {
          expected_error = fragment.error_if_missing;
          break;
        }
      }

      if (expected_error.empty()) continue;

      CheckProcessingFails(*packet, i, expected_error, error_code);
    }
  }

  void CheckProcessingFails(const QuicEncryptedPacket& packet, size_t len,
                            std::string expected_error,
                            QuicErrorCode error_code) {
    QuicEncryptedPacket encrypted(packet.data(), len, false);
    EXPECT_FALSE(framer_.ProcessPacket(encrypted)) << "len: " << len;
    EXPECT_EQ(expected_error, framer_.detailed_error()) << "len: " << len;
    EXPECT_EQ(error_code, framer_.error()) << "len: " << len;
  }

  void CheckProcessingFails(unsigned char* packet, size_t len,
                            std::string expected_error,
                            QuicErrorCode error_code) {
    QuicEncryptedPacket encrypted(AsChars(packet), len, false);
    EXPECT_FALSE(framer_.ProcessPacket(encrypted)) << "len: " << len;
    EXPECT_EQ(expected_error, framer_.detailed_error()) << "len: " << len;
    EXPECT_EQ(error_code, framer_.error()) << "len: " << len;
  }

  // Checks if the supplied string matches data in the supplied StreamFrame.
  void CheckStreamFrameData(std::string str, QuicStreamFrame* frame) {
    EXPECT_EQ(str, std::string(frame->data_buffer, frame->data_length));
  }

  void CheckCalculatePacketNumber(uint64_t expected_packet_number,
                                  QuicPacketNumber last_packet_number) {
    uint64_t wire_packet_number = expected_packet_number & kMask;
    EXPECT_EQ(expected_packet_number,
              QuicFramerPeer::CalculatePacketNumberFromWire(
                  &framer_, PACKET_4BYTE_PACKET_NUMBER, last_packet_number,
                  wire_packet_number))
        << "last_packet_number: " << last_packet_number
        << " wire_packet_number: " << wire_packet_number;
  }

  std::unique_ptr<QuicPacket> BuildDataPacket(const QuicPacketHeader& header,
                                              const QuicFrames& frames) {
    return BuildUnsizedDataPacket(&framer_, header, frames);
  }

  std::unique_ptr<QuicPacket> BuildDataPacket(const QuicPacketHeader& header,
                                              const QuicFrames& frames,
                                              size_t packet_size) {
    return BuildUnsizedDataPacket(&framer_, header, frames, packet_size);
  }

  // N starts at 1.
  QuicStreamId GetNthStreamid(QuicTransportVersion transport_version,
                              Perspective perspective, bool bidirectional,
                              int n) {
    if (bidirectional) {
      return QuicUtils::GetFirstBidirectionalStreamId(transport_version,
                                                      perspective) +
             ((n - 1) * QuicUtils::StreamIdDelta(transport_version));
    }
    // Unidirectional
    return QuicUtils::GetFirstUnidirectionalStreamId(transport_version,
                                                     perspective) +
           ((n - 1) * QuicUtils::StreamIdDelta(transport_version));
  }

  QuicTime CreationTimePlus(uint64_t offset_us) {
    return framer_.creation_time() +
           QuicTime::Delta::FromMicroseconds(offset_us);
  }

  test::TestEncrypter* encrypter_;
  test::TestDecrypter* decrypter_;
  ParsedQuicVersion version_;
  QuicTime start_;
  QuicFramer framer_;
  test::TestQuicVisitor visitor_;
  quiche::SimpleBufferAllocator allocator_;
};

// Multiple test cases of QuicFramerTest use byte arrays to define packets for
// testing, and these byte arrays contain the QUIC version. This macro explodes
// the 32-bit version into four bytes in network order. Since it uses methods of
// QuicFramerTest, it is only valid to use this in a QuicFramerTest.
#define QUIC_VERSION_BYTES                                             \
  GetQuicVersionByte(0), GetQuicVersionByte(1), GetQuicVersionByte(2), \
      GetQuicVersionByte(3)

// Run all framer tests with all supported versions of QUIC.
INSTANTIATE_TEST_SUITE_P(QuicFramerTests, QuicFramerTest,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearEpochStart) {
  // A few quick manual sanity checks.
  CheckCalculatePacketNumber(UINT64_C(1), QuicPacketNumber());
  CheckCalculatePacketNumber(kEpoch + 1, QuicPacketNumber(kMask));
  CheckCalculatePacketNumber(kEpoch, QuicPacketNumber(kMask));
  for (uint64_t j = 0; j < 10; j++) {
    CheckCalculatePacketNumber(j, QuicPacketNumber());
    CheckCalculatePacketNumber(kEpoch - 1 - j, QuicPacketNumber());
  }

  // Cases where the last number was close to the start of the range.
  for (QuicPacketNumber last = QuicPacketNumber(1); last < QuicPacketNumber(10);
       last++) {
    // Small numbers should not wrap (even if they're out of order).
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(j, last);
    }

    // Large numbers should not wrap either (because we're near 0 already).
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(kEpoch - 1 - j, last);
    }
  }
}

TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearEpochEnd) {
  // Cases where the last number was close to the end of the range
  for (uint64_t i = 0; i < 10; i++) {
    QuicPacketNumber last = QuicPacketNumber(kEpoch - i);

    // Small numbers should wrap.
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(kEpoch + j, last);
    }

    // Large numbers should not (even if they're out of order).
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(kEpoch - 1 - j, last);
    }
  }
}

// Next check where we're in a non-zero epoch to verify we handle
// reverse wrapping, too.
TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearPrevEpoch) {
  const uint64_t prev_epoch = 1 * kEpoch;
  const uint64_t cur_epoch = 2 * kEpoch;
  // Cases where the last number was close to the start of the range
  for (uint64_t i = 0; i < 10; i++) {
    QuicPacketNumber last = QuicPacketNumber(cur_epoch + i);
    // Small number should not wrap (even if they're out of order).
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(cur_epoch + j, last);
    }

    // But large numbers should reverse wrap.
    for (uint64_t j = 0; j < 10; j++) {
      uint64_t num = kEpoch - 1 - j;
      CheckCalculatePacketNumber(prev_epoch + num, last);
    }
  }
}

TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearNextEpoch) {
  const uint64_t cur_epoch = 2 * kEpoch;
  const uint64_t next_epoch = 3 * kEpoch;
  // Cases where the last number was close to the end of the range
  for (uint64_t i = 0; i < 10; i++) {
    QuicPacketNumber last = QuicPacketNumber(next_epoch - 1 - i);

    // Small numbers should wrap.
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(next_epoch + j, last);
    }

    // but large numbers should not (even if they're out of order).
    for (uint64_t j = 0; j < 10; j++) {
      uint64_t num = kEpoch - 1 - j;
      CheckCalculatePacketNumber(cur_epoch + num, last);
    }
  }
}

TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearNextMax) {
  const uint64_t max_number = std::numeric_limits<uint64_t>::max();
  const uint64_t max_epoch = max_number & ~kMask;

  // Cases where the last number was close to the end of the range
  for (uint64_t i = 0; i < 10; i++) {
    // Subtract 1, because the expected next packet number is 1 more than the
    // last packet number.
    QuicPacketNumber last = QuicPacketNumber(max_number - i - 1);

    // Small numbers should not wrap, because they have nowhere to go.
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(max_epoch + j, last);
    }

    // Large numbers should not wrap either.
    for (uint64_t j = 0; j < 10; j++) {
      uint64_t num = kEpoch - 1 - j;
      CheckCalculatePacketNumber(max_epoch + num, last);
    }
  }
}

TEST_P(QuicFramerTest, EmptyPacket) {
  char packet[] = {0x00};
  QuicEncryptedPacket encrypted(packet, 0, false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_PACKET_HEADER));
}

TEST_P(QuicFramerTest, LargePacket) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[kMaxIncomingPacketSize + 1] = {
    // type (short header 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x78, 0x56, 0x34, 0x12,
  };
  // clang-format on

  const size_t header_size = GetPacketHeaderSize(
      framer_.transport_version(), kPacket8ByteConnectionId,
      kPacket0ByteConnectionId, !kIncludeVersion, !kIncludeDiversificationNonce,
      PACKET_4BYTE_PACKET_NUMBER, quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0);

  memset(packet + header_size, 0, kMaxIncomingPacketSize - header_size);

  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));

  ASSERT_TRUE(visitor_.header_.get());
  // Make sure we've parsed the packet header, so we can send an error.
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
  // Make sure the correct error is propagated.
  EXPECT_THAT(framer_.error(), IsError(QUIC_PACKET_TOO_LARGE));
  EXPECT_EQ("Packet too large.", framer_.detailed_error());
  // Make sure the packet wasn't visited.
  EXPECT_EQ(0, visitor_.packet_count_);
}

TEST_P(QuicFramerTest, LongPacketHeader) {
  // clang-format off
  PacketFragments packet = {
    // type (long header with packet type ZERO_RTT)
    {"Unable to read first byte.",
     {0xD3}},
    // version tag
    {"Unable to read protocol version.",
     {QUIC_VERSION_BYTES}},
    // connection_id length
    {"Unable to read ConnectionId length.",
     {0x50}},
    // connection_id
    {"Unable to read destination connection ID.",
     {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
    // packet number
    {"Unable to read packet number.",
     {0x12, 0x34, 0x56, 0x78}},
  };
  // clang-format on

  if (QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    return;
  }

  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_MISSING_PAYLOAD));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
  EXPECT_FALSE(visitor_.header_->reset_flag);
  EXPECT_TRUE(visitor_.header_->version_flag);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  CheckFramingBoundaries(packet, QUIC_INVALID_PACKET_HEADER);

  PacketHeaderFormat format;
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  bool version_flag;
  QuicConnectionId destination_connection_id, source_connection_id;
  QuicVersionLabel version_label;
  std::string detailed_error;
  bool use_length_prefix;
  std::optional<absl::string_view> retry_token;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  const QuicErrorCode error_code = QuicFramer::ParsePublicHeaderDispatcher(
      *encrypted, kQuicDefaultConnectionIdLength, &format, &long_packet_type,
      &version_flag, &use_length_prefix, &version_label, &parsed_version,
      &destination_connection_id, &source_connection_id, &retry_token,
      &detailed_error);
  EXPECT_THAT(error_code, IsQuicNoError());
  EXPECT_EQ("", detailed_error);
  EXPECT_FALSE(retry_token.has_value());
  EXPECT_FALSE(use_length_prefix);
  EXPECT_EQ(IETF_QUIC_LONG_HEADER_PACKET, format);
  EXPECT_TRUE(version_flag);
  EXPECT_EQ(kQuicDefaultConnectionIdLength, destination_connection_id.length());
  EXPECT_EQ(FramerTestConnectionId(), destination_connection_id);
  EXPECT_EQ(EmptyQuicConnectionId(), source_connection_id);
}

TEST_P(QuicFramerTest, LongPacketHeaderWithBothConnectionIds) {
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  unsigned char packet[] = {
    // public flags (long header with packet type ZERO_RTT_PROTECTED and
    // 4-byte packet number)
    0xD3,
    // version
    QUIC_VERSION_BYTES,
    // connection ID lengths
    0x55,
    // destination connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // source connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
    // packet number
    0x12, 0x34, 0x56, 0x00,
    // padding frame
    0x00,
  };
  unsigned char packet49[] = {
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
    0x08,
    // source connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
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

  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);
  PacketHeaderFormat format = GOOGLE_QUIC_PACKET;
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  bool version_flag = false;
  QuicConnectionId destination_connection_id, source_connection_id;
  QuicVersionLabel version_label = 0;
  std::string detailed_error = "";
  bool use_length_prefix;
  std::optional<absl::string_view> retry_token;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  const QuicErrorCode error_code = QuicFramer::ParsePublicHeaderDispatcher(
      encrypted, kQuicDefaultConnectionIdLength, &format, &long_packet_type,
      &version_flag, &use_length_prefix, &version_label, &parsed_version,
      &destination_connection_id, &source_connection_id, &retry_token,
      &detailed_error);
  EXPECT_THAT(error_code, IsQuicNoError());
  EXPECT_FALSE(retry_token.has_value());
  EXPECT_EQ(framer_.version().HasLengthPrefixedConnectionIds(),
            use_length_prefix);
  EXPECT_EQ("", detailed_error);
  EXPECT_EQ(IETF_QUIC_LONG_HEADER_PACKET, format);
  EXPECT_TRUE(version_flag);
  EXPECT_EQ(FramerTestConnectionId(), destination_connection_id);
  EXPECT_EQ(FramerTestConnectionIdPlusOne(), source_connection_id);
}

TEST_P(QuicFramerTest, AllZeroPacketParsingFails) {
  unsigned char packet[1200] = {};
  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  PacketHeaderFormat format = GOOGLE_QUIC_PACKET;
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  bool version_flag = false;
  QuicConnectionId destination_connection_id, source_connection_id;
  QuicVersionLabel version_label = 0;
  std::string detailed_error = "";
  bool use_length_prefix;
  std::optional<absl::string_view> retry_token;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  const QuicErrorCode error_code = QuicFramer::ParsePublicHeaderDispatcher(
      encrypted, kQuicDefaultConnectionIdLength, &format, &long_packet_type,
      &version_flag, &use_length_prefix, &version_label, &parsed_version,
      &destination_connection_id, &source_connection_id, &retry_token,
      &detailed_error);
  EXPECT_EQ(error_code, QUIC_INVALID_PACKET_HEADER);
  EXPECT_EQ(detailed_error, "Invalid flags.");
}

TEST_P(QuicFramerTest, ParsePublicHeader) {
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
      0x12, 0x34, 0x56, 0x78,
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
    0x12, 0x34, 0x56, 0x78,
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

  uint8_t first_byte = 0x33;
  PacketHeaderFormat format = GOOGLE_QUIC_PACKET;
  bool version_present = false, has_length_prefix = false;
  QuicVersionLabel version_label = 0;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  QuicConnectionId destination_connection_id = EmptyQuicConnectionId(),
                   source_connection_id = EmptyQuicConnectionId();
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  quiche::QuicheVariableLengthIntegerLength retry_token_length_length =
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_4;
  absl::string_view retry_token;
  std::string detailed_error = "foobar";

  QuicDataReader reader(AsChars(p), p_length);
  const QuicErrorCode parse_error = QuicFramer::ParsePublicHeader(
      &reader, kQuicDefaultConnectionIdLength, /*ietf_format=*/true,
      &first_byte, &format, &version_present, &has_length_prefix,
      &version_label, &parsed_version, &destination_connection_id,
      &source_connection_id, &long_packet_type, &retry_token_length_length,
      &retry_token, &detailed_error);
  EXPECT_THAT(parse_error, IsQuicNoError());
  EXPECT_EQ("", detailed_error);
  EXPECT_EQ(p[0], first_byte);
  EXPECT_TRUE(version_present);
  EXPECT_EQ(framer_.version().HasLengthPrefixedConnectionIds(),
            has_length_prefix);
  EXPECT_EQ(CreateQuicVersionLabel(framer_.version()), version_label);
  EXPECT_EQ(framer_.version(), parsed_version);
  EXPECT_EQ(FramerTestConnectionId(), destination_connection_id);
  EXPECT_EQ(EmptyQuicConnectionId(), source_connection_id);
  EXPECT_EQ(quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0,
            retry_token_length_length);
  EXPECT_EQ(absl::string_view(), retry_token);
  EXPECT_EQ(IETF_QUIC_LONG_HEADER_PACKET, format);
  EXPECT_EQ(HANDSHAKE, long_packet_type);
}

TEST_P(QuicFramerTest, ParsePublicHeaderProxBadSourceConnectionIdLength) {
  if (!framer_.version().HasLengthPrefixedConnectionIds()) {
    return;
  }
  // clang-format off
  unsigned char packet[] = {
    // public flags (long header with packet type HANDSHAKE and
    // 4-byte packet number)
    0xE3,
    // version
    'P', 'R', 'O', 'X',
    // destination connection ID length
    0x08,
    // destination connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // source connection ID length (bogus)
    0xEE,
    // long header packet length
    0x05,
    // packet number
    0x12, 0x34, 0x56, 0x78,
    // padding frame
    0x00,
  };
  // clang-format on
  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);

  uint8_t first_byte = 0x33;
  PacketHeaderFormat format = GOOGLE_QUIC_PACKET;
  bool version_present = false, has_length_prefix = false;
  QuicVersionLabel version_label = 0;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  QuicConnectionId destination_connection_id = EmptyQuicConnectionId(),
                   source_connection_id = EmptyQuicConnectionId();
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  quiche::QuicheVariableLengthIntegerLength retry_token_length_length =
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_4;
  absl::string_view retry_token;
  std::string detailed_error = "foobar";

  QuicDataReader reader(AsChars(p), p_length);
  const QuicErrorCode parse_error = QuicFramer::ParsePublicHeader(
      &reader, kQuicDefaultConnectionIdLength,
      /*ietf_format=*/true, &first_byte, &format, &version_present,
      &has_length_prefix, &version_label, &parsed_version,
      &destination_connection_id, &source_connection_id, &long_packet_type,
      &retry_token_length_length, &retry_token, &detailed_error);
  EXPECT_THAT(parse_error, IsQuicNoError());
  EXPECT_EQ("", detailed_error);
  EXPECT_EQ(p[0], first_byte);
  EXPECT_TRUE(version_present);
  EXPECT_TRUE(has_length_prefix);
  EXPECT_EQ(0x50524F58u, version_label);  // "PROX"
  EXPECT_EQ(UnsupportedQuicVersion(), parsed_version);
  EXPECT_EQ(FramerTestConnectionId(), destination_connection_id);
  EXPECT_EQ(EmptyQuicConnectionId(), source_connection_id);
  EXPECT_EQ(quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0,
            retry_token_length_length);
  EXPECT_EQ(absl::string_view(), retry_token);
  EXPECT_EQ(IETF_QUIC_LONG_HEADER_PACKET, format);
}

TEST_P(QuicFramerTest, ClientConnectionIdFromShortHeaderToClient) {
  if (!framer_.version().SupportsClientConnectionIds()) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  QuicFramerPeer::SetLastSerializedServerConnectionId(&framer_,
                                                      TestConnectionId(0x33));
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  framer_.SetExpectedClientConnectionIdLength(kQuicDefaultConnectionIdLength);
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x13, 0x37, 0x42, 0x33,
    // padding frame
    0x00,
  };
  // clang-format on
  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());
  EXPECT_EQ("", framer_.detailed_error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
}

// In short header packets from client to server, the client connection ID
// is omitted, but the framer adds it to the header struct using its
// last serialized client connection ID. This test ensures that this
// mechanism behaves as expected.
TEST_P(QuicFramerTest, ClientConnectionIdFromShortHeaderToServer) {
  if (!framer_.version().SupportsClientConnectionIds()) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x13, 0x37, 0x42, 0x33,
    // padding frame
    0x00,
  };
  // clang-format on
  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());
  EXPECT_EQ("", framer_.detailed_error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
}

TEST_P(QuicFramerTest, PacketHeaderWith0ByteConnectionId) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  QuicFramerPeer::SetLastSerializedServerConnectionId(&framer_,
                                                      FramerTestConnectionId());
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  // clang-format off
  PacketFragments packet = {
        // type (short header, 4 byte packet number)
        {"Unable to read first byte.",
         {0x43}},
        // connection_id
        // packet number
        {"Unable to read packet number.",
         {0x12, 0x34, 0x56, 0x78}},
   };

  PacketFragments packet_hp = {
        // type (short header, 4 byte packet number)
        {"Unable to read first byte.",
         {0x43}},
        // connection_id
        // packet number
        {"",
         {0x12, 0x34, 0x56, 0x78}},
   };
  // clang-format on

  PacketFragments& fragments =
      framer_.version().HasHeaderProtection() ? packet_hp : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_MISSING_PAYLOAD));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_FALSE(visitor_.header_->reset_flag);
  EXPECT_FALSE(visitor_.header_->version_flag);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  CheckFramingBoundaries(fragments, QUIC_INVALID_PACKET_HEADER);
}

TEST_P(QuicFramerTest, PacketHeaderWithVersionFlag) {
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  PacketFragments packet = {
      // type (long header with packet type ZERO_RTT_PROTECTED and 4 bytes
      // packet number)
      {"Unable to read first byte.",
       {0xD3}},
      // version tag
      {"Unable to read protocol version.",
       {QUIC_VERSION_BYTES}},
      // connection_id length
      {"Unable to read ConnectionId length.",
       {0x50}},
      // connection_id
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"Unable to read packet number.",
       {0x12, 0x34, 0x56, 0x78}},
  };

  PacketFragments packet49 = {
      // type (long header with packet type ZERO_RTT_PROTECTED and 4 bytes
      // packet number)
      {"Unable to read first byte.",
       {0xD3}},
      // version tag
      {"Unable to read protocol version.",
       {QUIC_VERSION_BYTES}},
      // destination connection ID length
      {"Unable to read destination connection ID.",
       {0x08}},
      // destination connection ID
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // source connection ID length
      {"Unable to read source connection ID.",
       {0x00}},
      // long header packet length
      {"Unable to read long header payload length.",
       {0x04}},
      // packet number
      {"Long header payload length longer than packet.",
       {0x12, 0x34, 0x56, 0x78}},
  };
  // clang-format on

  ReviseFirstByteByVersion(packet49);
  PacketFragments& fragments =
      framer_.version().HasLongHeaderLengths() ? packet49 : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_MISSING_PAYLOAD));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
  EXPECT_FALSE(visitor_.header_->reset_flag);
  EXPECT_TRUE(visitor_.header_->version_flag);
  EXPECT_EQ(GetParam(), visitor_.header_->version);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  CheckFramingBoundaries(fragments, QUIC_INVALID_PACKET_HEADER);
}

TEST_P(QuicFramerTest, PacketHeaderWith4BytePacketNumber) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  QuicFramerPeer::SetLargestPacketNumber(&framer_, kPacketNumber - 2);

  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"Unable to read first byte.",
       {0x43}},
      // connection_id
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"Unable to read packet number.",
       {0x12, 0x34, 0x56, 0x78}},
  };

  PacketFragments packet_hp = {
      // type (short header, 4 byte packet number)
      {"Unable to read first byte.",
       {0x43}},
      // connection_id
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
  };
  // clang-format on

  PacketFragments& fragments =
      framer_.version().HasHeaderProtection() ? packet_hp : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_MISSING_PAYLOAD));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
  EXPECT_FALSE(visitor_.header_->reset_flag);
  EXPECT_FALSE(visitor_.header_->version_flag);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  CheckFramingBoundaries(fragments, QUIC_INVALID_PACKET_HEADER);
}

TEST_P(QuicFramerTest, PacketHeaderWith2BytePacketNumber) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  QuicFramerPeer::SetLargestPacketNumber(&framer_, kPacketNumber - 2);

  // clang-format off
  PacketFragments packet = {
      // type (short header, 2 byte packet number)
      {"Unable to read first byte.",
       {0x41}},
      // connection_id
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"Unable to read packet number.",
       {0x56, 0x78}},
  };

  PacketFragments packet_hp = {
      // type (short header, 2 byte packet number)
      {"Unable to read first byte.",
       {0x41}},
      // connection_id
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x56, 0x78}},
      // padding
      {"", {0x00, 0x00}},
  };
  // clang-format on

  PacketFragments& fragments =
      framer_.version().HasHeaderProtection() ? packet_hp : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  if (framer_.version().HasHeaderProtection()) {
    EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
    EXPECT_THAT(framer_.error(), IsQuicNoError());
  } else {
    EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
    EXPECT_THAT(framer_.error(), IsError(QUIC_MISSING_PAYLOAD));
  }
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
  EXPECT_FALSE(visitor_.header_->reset_flag);
  EXPECT_FALSE(visitor_.header_->version_flag);
  EXPECT_EQ(PACKET_2BYTE_PACKET_NUMBER, visitor_.header_->packet_number_length);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  CheckFramingBoundaries(fragments, QUIC_INVALID_PACKET_HEADER);
}

TEST_P(QuicFramerTest, PacketHeaderWith1BytePacketNumber) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  QuicFramerPeer::SetLargestPacketNumber(&framer_, kPacketNumber - 2);

  // clang-format off
  PacketFragments packet = {
      // type (8 byte connection_id and 1 byte packet number)
      {"Unable to read first byte.",
       {0x40}},
      // connection_id
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"Unable to read packet number.",
       {0x78}},
  };

  PacketFragments packet_hp = {
      // type (8 byte connection_id and 1 byte packet number)
      {"Unable to read first byte.",
       {0x40}},
      //
"""


```
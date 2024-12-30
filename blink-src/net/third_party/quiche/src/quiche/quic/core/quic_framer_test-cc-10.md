Response:
The user wants to understand the functionality of the `quic_framer_test.cc` file in the Chromium network stack.

Here's a breakdown of the user's request and a plan to address it:

1. **List the functions of the file:** The core purpose is to test the `QuicFramer` class. This involves verifying its ability to correctly parse and interpret QUIC packets and frames, as well as its ability to generate valid QUIC packets.

2. **Relate to JavaScript (if applicable):**  QUIC is a transport protocol. While JavaScript itself doesn't directly handle the low-level parsing of QUIC packets, it interacts with QUIC through higher-level APIs in web browsers or Node.js. The browser's network stack (written in C++, which includes this code) handles the QUIC protocol details. I need to explain this indirect relationship.

3. **Provide examples with assumed input and output:** For the test cases shown, the input is a sequence of bytes representing a QUIC packet fragment, and the output is the interpretation of that packet by the `QuicFramer` (e.g., specific frame types and their values being extracted). I can use the provided test cases as examples.

4. **Highlight common user/programming errors:**  These tests often check for error conditions. Common errors when working with QUIC include malformed packets, incorrect frame structures, or violating protocol rules. I can extract examples of such error cases from the tests.

5. **Explain how a user reaches this code (debugging context):**  This involves tracing a typical user interaction (e.g., browsing a website) down to the network stack and the role of the `QuicFramer`.

6. **Summarize the function of this part (part 11 of 16):** Based on the code provided in this excerpt, this section focuses on testing the parsing and handling of specific QUIC IETF frames related to stream management (MAX_STREAMS, STREAMS_BLOCKED) and connection management (NEW_CONNECTION_ID, NEW_TOKEN).

**Mental Sandbox/Pre-computation:**

* **JavaScript relationship:**  JavaScript uses browser APIs (like `fetch`) which, under the hood, can use QUIC. The browser's network stack, containing `quic_framer_test.cc`, implements the QUIC protocol that enables these APIs.
* **Input/Output:** I'll focus on the `TEST_P` functions. Each test sets up `packet_ietf` (input) and then checks `visitor_` members (output).
* **Common errors:** The tests with `EXPECT_FALSE(framer_.ProcessPacket(*encrypted))` are good examples of testing error conditions.
* **User path:** User types URL -> Browser's network request -> QUIC connection setup (if applicable) -> Packet processing by `QuicFramer`.
* **Part summary:** Scan the test names in the provided code block to identify the key features being tested.

**Confidence Score:** 5/5 - I'm confident I can address all the user's requests based on the provided code snippet.
这个C++源代码文件 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `QuicFramer` 类的功能。`QuicFramer` 的主要职责是 **解析和序列化 QUIC 数据包和帧**。

**这个文件的主要功能包括：**

1. **数据包解析测试:** 验证 `QuicFramer` 是否能正确地解析各种类型的 QUIC 数据包，包括：
    * 不同类型的头部（短头部、长头部）
    * 不同版本的 QUIC 协议
    * 包含各种不同帧的包
    * 包含错误格式的包

2. **帧解析测试:**  详细测试 `QuicFramer` 解析各种 QUIC 帧的能力，包括：
    * **流相关的帧:** `MAX_STREAMS` (限制对端可以创建的最大流数量), `STREAMS_BLOCKED` (告知对端由于流限制而无法创建新的流)
    * **连接管理帧:** `NEW_CONNECTION_ID` (用于连接迁移), `NEW_TOKEN` (用于恢复连接)
    * 其他类型的帧 (虽然这段代码中没有完全展示，但整个测试文件会覆盖更多)

3. **边界条件测试:** 测试 `QuicFramer` 在处理边界情况时的行为，例如：
    * 数据包或帧不完整
    * 数据包或帧过长
    * 使用无效的值

4. **错误处理测试:** 验证 `QuicFramer` 在遇到错误时是否能正确地检测并报告错误。

5. **数据包构建测试:** 验证 `QuicFramer` 是否能够正确地构建各种类型的 QUIC 数据包。

**与 JavaScript 的关系：**

QUIC 协议是网络传输层协议，通常由浏览器或服务器的底层网络库实现（例如 Chromium 的网络栈）。 **JavaScript 本身并不直接处理 QUIC 协议的解析和序列化**。

然而，JavaScript 可以通过浏览器提供的 API（例如 `fetch` API 或 WebSocket API）来发起网络请求，这些请求在底层可能会使用 QUIC 协议进行传输。 当浏览器使用 QUIC 进行通信时，浏览器底层的 C++ 代码（包括 `quic_framer_test.cc` 所测试的 `QuicFramer` 类）会负责处理 QUIC 数据包的解析和生成。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch` API 向一个支持 QUIC 的服务器发送请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中：

1. JavaScript 调用 `fetch`，浏览器网络栈开始处理这个请求。
2. 如果浏览器和服务器协商使用 QUIC 协议，那么在 TCP 连接建立之后（或者直接建立 UDP 连接，取决于 QUIC 版本），后续的数据传输将通过 QUIC 数据包进行。
3. 当浏览器接收到来自服务器的 QUIC 数据包时，`QuicFramer` 类（经过 `quic_framer_test.cc` 的测试）会被用来解析这些数据包，提取出 HTTP 响应数据。
4. 解析出的 HTTP 响应数据最终会被传递给 JavaScript 的 `fetch` API 的 `response` 对象。

所以，虽然 JavaScript 不直接操作 `QuicFramer`，但 `QuicFramer` 的正确性对于使用 QUIC 的 JavaScript 应用至关重要。如果 `QuicFramer` 解析错误，JavaScript 应用可能无法正确接收或发送数据。

**逻辑推理的假设输入与输出：**

**示例 1: `TEST_P(QuicFramerTest, ServerUniDiMaxStreamsFrame)`**

* **假设输入 (packet_ietf):**  一个表示包含 `MAX_STREAMS` 帧（单向流）的 QUIC 数据包的字节序列。例如：
    ```
    {0x43}, // 短头部，4字节包序号
    {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}, // 连接ID
    {0x12, 0x34, 0x9A, 0xBC}, // 包序号
    {0x13}, // MAX_STREAMS_UNIDIRECTIONAL 帧类型
    {0x83}  // max. streams (VarInt 编码的 3)
    ```
* **预期输出 (visitor_.max_streams_frame_):** `QuicFramerVisitor` 会记录解析出的 `MAX_STREAMS` 帧的信息：
    * `stream_count`: 3
    * `unidirectional`: true

**示例 2: `TEST_P(QuicFramerTest, StreamsBlockedFrameTooBig)`**

* **假设输入 (packet_ietf):** 一个表示包含 `STREAMS_BLOCKED` 帧（双向流）的 QUIC 数据包的字节序列，其中流数量超过了实现限制。例如：
    ```
    {0x43}, // 短头部，4字节包序号
    {0x12, 0x34, 0x9A, 0xBC}, // 包序号
    {0x16}, // STREAMS_BLOCKED_BIDIRECTIONAL 帧类型
    {0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x01} // stream count (VarInt 编码的 0x40000001)
    ```
* **预期输出:** `framer_.ProcessPacket` 返回 `false`，表示解析失败，并且 `framer_.error()` 返回 `QUIC_STREAMS_BLOCKED_DATA` 错误码， `framer_.detailed_error()` 包含错误描述 "STREAMS_BLOCKED stream count exceeds implementation limit."

**涉及用户或编程常见的使用错误：**

1. **构造错误的 QUIC 数据包:**  程序员在实现 QUIC 协议时，可能会错误地构造数据包，例如：
    * 使用错误的帧类型 ID
    * 帧的长度字段与实际数据不符
    * 关键字段缺失或顺序错误

    **测试用例示例:**  测试用例中经常会有构造不完整或包含错误数据的 `packet_ietf` 的情况，例如缺少必要的长度字段，或者帧类型 ID 不正确。 这些测试用例旨在验证 `QuicFramer` 能否正确地识别并处理这些错误。

2. **误解 QUIC 协议规范:**  开发者可能对 QUIC 协议的某些细节理解有误，导致生成的帧或数据包不符合规范。

    **测试用例示例:**  `TEST_P(QuicFramerTest, InvalidLongNewConnectionIdFrame)` 测试了 `NEW_CONNECTION_ID` 帧中连接 ID 长度超过允许的最大值的情况。 这模拟了开发者可能错误地设置了过长的连接 ID。

**用户操作如何一步步到达这里 (调试线索)：**

假设用户在使用 Chrome 浏览器访问一个使用 QUIC 协议的网站：

1. **用户在地址栏输入 URL 并回车，或者点击一个链接。**
2. **Chrome 浏览器的网络栈开始处理这个请求。** 它会尝试与服务器建立连接，并协商使用 QUIC 协议（如果服务器支持）。
3. **如果协商成功，浏览器和服务器之间会建立一个 QUIC 连接。**
4. **在连接建立后，浏览器会向服务器发送 HTTP 请求。** 这个 HTTP 请求会被封装成一个或多个 QUIC 数据包。
5. **浏览器底层的 QUIC 实现（包括 `QuicFramer`）负责将这些 HTTP 数据封装成符合 QUIC 协议规范的数据包。**
6. **当服务器响应时，服务器会将 HTTP 响应封装成 QUIC 数据包发送回浏览器。**
7. **浏览器接收到这些 QUIC 数据包。**
8. **`QuicFramer` 类会被调用来解析这些接收到的 QUIC 数据包，提取出 HTTP 响应数据。**
9. **如果 `QuicFramer` 在解析过程中遇到错误（例如，服务器发送了格式错误的 QUIC 数据包），可能会触发断言或错误处理逻辑，最终可能导致网络请求失败或页面加载异常。**

在调试网络问题时，开发者可能会：

* 使用网络抓包工具（如 Wireshark）捕获浏览器和服务器之间的 QUIC 数据包。
* 分析捕获到的数据包，查看其结构和内容是否符合 QUIC 协议规范。
* 如果怀疑是 QUIC 数据包解析的问题，可能会深入到 Chromium 的网络栈代码中，查看 `QuicFramer` 类的实现，并可能参考 `quic_framer_test.cc` 中的测试用例来理解 `QuicFramer` 的预期行为。

**第 11 部分功能归纳：**

根据提供的代码片段，第 11 部分的 `quic_framer_test.cc` 主要关注以下 QUIC IETF 帧的 **解析和构建** 测试：

* **`MAX_STREAMS` 帧:**  测试服务端和客户端发送的 `MAX_STREAMS` 帧（双向和单向），包括正常情况、流数量过大以及流数量为零的情况。
* **`STREAMS_BLOCKED` 帧:** 测试服务端和客户端发送的 `STREAMS_BLOCKED` 帧（双向和单向），包括正常情况、流数量过大的错误情况以及流数量为零的情况。
* **`NEW_CONNECTION_ID` 帧:** 测试 `NEW_CONNECTION_ID` 帧的解析，包括变长连接 ID 的情况，以及连接 ID 长度过长和 `retire_prior_to` 值无效的错误情况。同时测试了构建 `NEW_CONNECTION_ID` 帧的能力。
* **`NEW_TOKEN` 帧:** 测试 `NEW_TOKEN` 帧的解析。

总而言之，这部分测试集中验证了 `QuicFramer` 处理与 **流控制** 和 **连接管理** 相关的关键 IETF QUIC 帧的能力，确保了 Chromium 的 QUIC 实现能够正确地理解和生成这些重要的控制信息。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共16部分，请归纳一下它的功能

"""
, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
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
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(3u, visitor_.max_streams_frame_.stream_count);
  EXPECT_TRUE(visitor_.max_streams_frame_.unidirectional);
  CheckFramingBoundaries(packet_ietf, QUIC_MAX_STREAMS_DATA);
}

TEST_P(QuicFramerTest, ClientUniDiMaxStreamsFrame) {
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

// The following four tests ensure that the framer can deserialize a stream
// count that is large enough to cause the resulting stream ID to exceed the
// current implementation limit(32 bits). The intent is that when this happens,
// the stream limit is pegged to the maximum supported value. There are four
// tests, for the four combinations of uni- and bi-directional, server- and
// client- initiated.
TEST_P(QuicFramerTest, BiDiMaxStreamsFrameTooBig) {
  // This frame is only for IETF QUIC.
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
    0x12, 0x34, 0x9A, 0xBC,
    // frame type (IETF_MAX_STREAMS_BIDIRECTIONAL)
    0x12,

    // max. streams. Max stream ID allowed is 0xffffffff
    // This encodes a count of 0x40000000, leading to stream
    // IDs in the range 0x1 00000000 to 0x1 00000003.
    kVarInt62EightBytes + 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet_ietf),
                                ABSL_ARRAYSIZE(packet_ietf), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0x40000000u, visitor_.max_streams_frame_.stream_count);
  EXPECT_FALSE(visitor_.max_streams_frame_.unidirectional);
}

TEST_P(QuicFramerTest, ClientBiDiMaxStreamsFrameTooBig) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // Test runs in client mode, no connection id
    // packet number
    0x12, 0x34, 0x9A, 0xBC,
    // frame type (IETF_MAX_STREAMS_BIDIRECTIONAL)
    0x12,

    // max. streams. Max stream ID allowed is 0xffffffff
    // This encodes a count of 0x40000000, leading to stream
    // IDs in the range 0x1 00000000 to 0x1 00000003.
    kVarInt62EightBytes + 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet_ietf),
                                ABSL_ARRAYSIZE(packet_ietf), false);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket0ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0x40000000u, visitor_.max_streams_frame_.stream_count);
  EXPECT_FALSE(visitor_.max_streams_frame_.unidirectional);
}

TEST_P(QuicFramerTest, ServerUniDiMaxStreamsFrameTooBig) {
  // This frame is only for IETF QUIC.
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
    0x12, 0x34, 0x9A, 0xBC,
    // frame type (IETF_MAX_STREAMS_UNIDIRECTIONAL)
    0x13,

    // max. streams. Max stream ID allowed is 0xffffffff
    // This encodes a count of 0x40000000, leading to stream
    // IDs in the range 0x1 00000000 to 0x1 00000003.
    kVarInt62EightBytes + 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet_ietf),
                                ABSL_ARRAYSIZE(packet_ietf), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0x40000000u, visitor_.max_streams_frame_.stream_count);
  EXPECT_TRUE(visitor_.max_streams_frame_.unidirectional);
}

TEST_P(QuicFramerTest, ClientUniDiMaxStreamsFrameTooBig) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // Test runs in client mode, no connection id
    // packet number
    0x12, 0x34, 0x9A, 0xBC,
    // frame type (IETF_MAX_STREAMS_UNDIRECTIONAL)
    0x13,

    // max. streams. Max stream ID allowed is 0xffffffff
    // This encodes a count of 0x40000000, leading to stream
    // IDs in the range 0x1 00000000 to 0x1 00000003.
    kVarInt62EightBytes + 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet_ietf),
                                ABSL_ARRAYSIZE(packet_ietf), false);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket0ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0x40000000u, visitor_.max_streams_frame_.stream_count);
  EXPECT_TRUE(visitor_.max_streams_frame_.unidirectional);
}

// Specifically test that count==0 is accepted.
TEST_P(QuicFramerTest, MaxStreamsFrameZeroCount) {
  // This frame is only for IETF QUIC.
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
    0x12, 0x34, 0x9A, 0xBC,
    // frame type (IETF_MAX_STREAMS_BIDIRECTIONAL)
    0x12,
    // max. streams == 0.
    kVarInt62OneByte + 0x00
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet_ietf),
                                ABSL_ARRAYSIZE(packet_ietf), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
}

TEST_P(QuicFramerTest, ServerBiDiStreamsBlockedFrame) {
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
      // frame type (IETF_MAX_STREAMS_UNIDIRECTIONAL frame)
      {"",
       {0x13}},
      // stream count
      {"Unable to read IETF_MAX_STREAMS_UNIDIRECTIONAL frame stream id/count.",
       {kVarInt62OneByte + 0x00}},
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

  EXPECT_EQ(0u, visitor_.max_streams_frame_.stream_count);
  EXPECT_TRUE(visitor_.max_streams_frame_.unidirectional);

  CheckFramingBoundaries(packet_ietf, QUIC_MAX_STREAMS_DATA);
}

TEST_P(QuicFramerTest, BiDiStreamsBlockedFrame) {
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
      // frame type (IETF_STREAMS_BLOCKED_BIDIRECTIONAL frame)
      {"",
       {0x16}},
      // stream id
      {"Unable to read IETF_STREAMS_BLOCKED_BIDIRECTIONAL "
       "frame stream id/count.",
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

  EXPECT_EQ(3u, visitor_.streams_blocked_frame_.stream_count);
  EXPECT_FALSE(visitor_.streams_blocked_frame_.unidirectional);

  CheckFramingBoundaries(packet_ietf, QUIC_STREAMS_BLOCKED_DATA);
}

TEST_P(QuicFramerTest, UniDiStreamsBlockedFrame) {
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
      // frame type (IETF_STREAMS_BLOCKED_UNIDIRECTIONAL frame)
      {"",
       {0x17}},
      // stream id
      {"Unable to read IETF_STREAMS_BLOCKED_UNIDIRECTIONAL "
       "frame stream id/count.",
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

  EXPECT_EQ(3u, visitor_.streams_blocked_frame_.stream_count);
  EXPECT_TRUE(visitor_.streams_blocked_frame_.unidirectional);
  CheckFramingBoundaries(packet_ietf, QUIC_STREAMS_BLOCKED_DATA);
}

TEST_P(QuicFramerTest, ClientUniDiStreamsBlockedFrame) {
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
      // frame type (IETF_STREAMS_BLOCKED_UNIDIRECTIONAL frame)
      {"",
       {0x17}},
      // stream id
      {"Unable to read IETF_STREAMS_BLOCKED_UNIDIRECTIONAL "
       "frame stream id/count.",
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

  EXPECT_EQ(3u, visitor_.streams_blocked_frame_.stream_count);
  EXPECT_TRUE(visitor_.streams_blocked_frame_.unidirectional);
  CheckFramingBoundaries(packet_ietf, QUIC_STREAMS_BLOCKED_DATA);
}

// Check that when we get a STREAMS_BLOCKED frame that specifies too large
// a stream count, we reject with an appropriate error. There is no need to
// check for different combinations of Uni/Bi directional and client/server
// initiated; the logic does not take these into account.
TEST_P(QuicFramerTest, StreamsBlockedFrameTooBig) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // Test runs in client mode, no connection id
    // packet number
    0x12, 0x34, 0x9A, 0xBC,
    // frame type (IETF_STREAMS_BLOCKED_BIDIRECTIONAL)
    0x16,

    // max. streams. Max stream ID allowed is 0xffffffff
    // This encodes a count of 0x40000000, leading to stream
    // IDs in the range 0x1 00000000 to 0x1 00000003.
    kVarInt62EightBytes + 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x01
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet_ietf),
                                ABSL_ARRAYSIZE(packet_ietf), false);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsError(QUIC_STREAMS_BLOCKED_DATA));
  EXPECT_EQ(framer_.detailed_error(),
            "STREAMS_BLOCKED stream count exceeds implementation limit.");
}

// Specifically test that count==0 is accepted.
TEST_P(QuicFramerTest, StreamsBlockedFrameZeroCount) {
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
      // frame type (IETF_STREAMS_BLOCKED_UNIDIRECTIONAL frame)
      {"",
       {0x17}},
      // stream id
      {"Unable to read IETF_STREAMS_BLOCKED_UNIDIRECTIONAL "
       "frame stream id/count.",
       {kVarInt62OneByte + 0x00}},
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

  EXPECT_EQ(0u, visitor_.streams_blocked_frame_.stream_count);
  EXPECT_TRUE(visitor_.streams_blocked_frame_.unidirectional);

  CheckFramingBoundaries(packet_ietf, QUIC_STREAMS_BLOCKED_DATA);
}

TEST_P(QuicFramerTest, BuildBiDiStreamsBlockedPacket) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicStreamsBlockedFrame frame;
  frame.stream_count = 3;
  frame.unidirectional = false;

  QuicFrames frames = {QuicFrame(frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_STREAMS_BLOCKED_BIDIRECTIONAL frame)
    0x16,
    // Stream count
    kVarInt62OneByte + 0x03
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildUniStreamsBlockedPacket) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicStreamsBlockedFrame frame;
  frame.stream_count = 3;
  frame.unidirectional = true;

  QuicFrames frames = {QuicFrame(frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_STREAMS_BLOCKED_UNIDIRECTIONAL frame)
    0x17,
    // Stream count
    kVarInt62OneByte + 0x03
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildBiDiMaxStreamsPacket) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicMaxStreamsFrame frame;
  frame.stream_count = 3;
  frame.unidirectional = false;

  QuicFrames frames = {QuicFrame(frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_MAX_STREAMS_BIDIRECTIONAL frame)
    0x12,
    // Stream count
    kVarInt62OneByte + 0x03
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildUniDiMaxStreamsPacket) {
  // This frame is only for IETF QUIC.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  // This test runs in client mode.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicMaxStreamsFrame frame;
  frame.stream_count = 3;
  frame.unidirectional = true;

  QuicFrames frames = {QuicFrame(frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_MAX_STREAMS_UNIDIRECTIONAL frame)
    0x13,
    // Stream count
    kVarInt62OneByte + 0x03
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, NewConnectionIdFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC.
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
      // frame type (IETF_NEW_CONNECTION_ID frame)
      {"",
       {0x18}},
      // error code
      {"Unable to read new connection ID frame sequence number.",
       {kVarInt62OneByte + 0x11}},
      {"Unable to read new connection ID frame retire_prior_to.",
       {kVarInt62OneByte + 0x09}},
      {"Unable to read new connection ID frame connection id.",
       {0x08}},  // connection ID length
      {"Unable to read new connection ID frame connection id.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11}},
      {"Can not read new connection ID frame reset token.",
       {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}}
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

  EXPECT_EQ(FramerTestConnectionIdPlusOne(),
            visitor_.new_connection_id_.connection_id);
  EXPECT_EQ(0x11u, visitor_.new_connection_id_.sequence_number);
  EXPECT_EQ(0x09u, visitor_.new_connection_id_.retire_prior_to);
  EXPECT_EQ(kTestStatelessResetToken,
            visitor_.new_connection_id_.stateless_reset_token);

  ASSERT_EQ(0u, visitor_.ack_frames_.size());

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_NEW_CONNECTION_ID_DATA);
}

TEST_P(QuicFramerTest, NewConnectionIdFrameVariableLength) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC.
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
      // frame type (IETF_NEW_CONNECTION_ID frame)
      {"",
       {0x18}},
      // error code
      {"Unable to read new connection ID frame sequence number.",
       {kVarInt62OneByte + 0x11}},
      {"Unable to read new connection ID frame retire_prior_to.",
       {kVarInt62OneByte + 0x0a}},
      {"Unable to read new connection ID frame connection id.",
       {0x09}},  // connection ID length
      {"Unable to read new connection ID frame connection id.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x42}},
      {"Can not read new connection ID frame reset token.",
       {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}}
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

  EXPECT_EQ(FramerTestConnectionIdNineBytes(),
            visitor_.new_connection_id_.connection_id);
  EXPECT_EQ(0x11u, visitor_.new_connection_id_.sequence_number);
  EXPECT_EQ(0x0au, visitor_.new_connection_id_.retire_prior_to);
  EXPECT_EQ(kTestStatelessResetToken,
            visitor_.new_connection_id_.stateless_reset_token);

  ASSERT_EQ(0u, visitor_.ack_frames_.size());

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_NEW_CONNECTION_ID_DATA);
}

// Verifies that parsing a NEW_CONNECTION_ID frame with a length above the
// specified maximum fails.
TEST_P(QuicFramerTest, InvalidLongNewConnectionIdFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // The NEW_CONNECTION_ID frame is only for IETF QUIC.
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
      // frame type (IETF_NEW_CONNECTION_ID frame)
      {"",
       {0x18}},
      // error code
      {"Unable to read new connection ID frame sequence number.",
       {kVarInt62OneByte + 0x11}},
      {"Unable to read new connection ID frame retire_prior_to.",
       {kVarInt62OneByte + 0x0b}},
      {"Unable to read new connection ID frame connection id.",
       {0x40}},  // connection ID length
      {"Unable to read new connection ID frame connection id.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xF0, 0xD2, 0xB4, 0x96, 0x78, 0x5A, 0x3C, 0x1E,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xF0, 0xD2, 0xB4, 0x96, 0x78, 0x5A, 0x3C, 0x1E,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xF0, 0xD2, 0xB4, 0x96, 0x78, 0x5A, 0x3C, 0x1E,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xF0, 0xD2, 0xB4, 0x96, 0x78, 0x5A, 0x3C, 0x1E}},
      {"Can not read new connection ID frame reset token.",
       {0xb5, 0x69, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_NEW_CONNECTION_ID_DATA));
  EXPECT_EQ("Invalid new connection ID length for version.",
            framer_.detailed_error());
}

// Verifies that parsing a NEW_CONNECTION_ID frame with an invalid
// retire-prior-to fails.
TEST_P(QuicFramerTest, InvalidRetirePriorToNewConnectionIdFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC only.
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
      // frame type (IETF_NEW_CONNECTION_ID frame)
      {"",
       {0x18}},
      // sequence number
      {"Unable to read new connection ID frame sequence number.",
       {kVarInt62OneByte + 0x11}},
      {"Unable to read new connection ID frame retire_prior_to.",
       {kVarInt62OneByte + 0x1b}},
      {"Unable to read new connection ID frame connection id length.",
       {0x08}},  // connection ID length
      {"Unable to read new connection ID frame connection id.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11}},
      {"Can not read new connection ID frame reset token.",
       {0xb5, 0x69, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_NEW_CONNECTION_ID_DATA));
  EXPECT_EQ("Retire_prior_to > sequence_number.", framer_.detailed_error());
}

TEST_P(QuicFramerTest, BuildNewConnectionIdFramePacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC only.
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicNewConnectionIdFrame frame;
  frame.sequence_number = 0x11;
  frame.retire_prior_to = 0x0c;
  // Use this value to force a 4-byte encoded variable length connection ID
  // in the frame.
  frame.connection_id = FramerTestConnectionIdPlusOne();
  frame.stateless_reset_token = kTestStatelessResetToken;

  QuicFrames frames = {QuicFrame(&frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_NEW_CONNECTION_ID frame)
    0x18,
    // sequence number
    kVarInt62OneByte + 0x11,
    // retire_prior_to
    kVarInt62OneByte + 0x0c,
    // new connection id length
    0x08,
    // new connection id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
    // stateless reset token
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, NewTokenFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC only.
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
      // frame type (IETF_NEW_TOKEN frame)
      {"",
       {0x07}},
      // Length
      {"Unable to read new token length.",
       {kVarInt62OneByte + 0x08}},
      {"Unable to read new token data.",
       {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}}
  };
  // clang-format on
  uint8_t expected_token_value[] = {0x00, 0x01, 0x02, 
"""


```
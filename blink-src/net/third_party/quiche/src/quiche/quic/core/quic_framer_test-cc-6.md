Response:
The user is asking for a breakdown of the C++ source file `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc`.

I need to:

1. **Determine the primary function of this file:** Given the name `quic_framer_test.cc`, it's highly likely that this file contains unit tests for the `QuicFramer` class. The `QuicFramer` is responsible for encoding and decoding QUIC packets and frames.

2. **List the functionalities tested:**  By examining the test cases (the `TEST_P` and `TEST` macros), I can identify the specific aspects of the `QuicFramer` being tested. These likely include:
    - Building different types of QUIC packets (data packets, version negotiation packets, etc.).
    - Building different types of QUIC frames (stream frames, ACK frames, crypto frames, etc.).
    - Handling different QUIC versions and their specific features.
    - Testing error conditions and boundary cases.
    - Testing the processing of received packets and frames.

3. **Analyze the relationship with JavaScript (if any):**  QUIC is a transport protocol used in web browsers (which execute JavaScript) to improve HTTP/3 performance. While this C++ file doesn't directly execute JavaScript code, it tests the underlying network stack components that a browser would use. I can provide examples of how JavaScript in a browser might indirectly trigger the functionality tested here, such as making an HTTP/3 request.

4. **Provide examples of logical reasoning with input and output:**  For specific test cases, I can analyze the provided input (e.g., a set of frames to be encoded) and the expected output (the byte representation of the encoded packet).

5. **Identify common user/programming errors:**  Based on the nature of the tests, I can infer potential mistakes developers might make when working with the `QuicFramer` or related QUIC components. This could involve incorrect frame construction, improper handling of QUIC versions, or issues with packet parsing.

6. **Explain user actions leading to this code:**  Since this is a testing file, it's not directly executed by a user. However, I can describe the developer workflow where these tests would be run (e.g., during development, during continuous integration).

7. **Summarize the file's function as part 7 of 16:**  Knowing the context within a larger set of files helps to understand its specific contribution. As part of a testing suite for the QUIC implementation, this file focuses on the correct behavior of the packet framing logic.

**Mental Sandbox:**

- Scan the code for keywords like "TEST_P", "TEST", "Build...", "Process...", "Frame", "Packet". This helps quickly identify the core functionalities being tested.
- Notice the use of `ASSERT_TRUE` and `EXPECT_THAT`. These are common testing macros.
- Pay attention to the specific frame types being constructed and processed (e.g., `QuicStreamFrame`, `QuicAckFrame`, `QuicCryptoFrame`).
- Look for version-specific logic (`VersionHasIetfQuicFrames`, `QuicVersionHasLongHeaderLengths`).
- Consider how a browser initiating a QUIC connection would eventually lead to the encoding and decoding of these packet and frame types.

Planning complete. I will now generate the response based on these steps.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 文件的第 7 部分，总共 16 部分。根据其文件名，我们可以判断这个文件主要用于 **测试 `QuicFramer` 类的功能**。`QuicFramer` 类在 QUIC 协议中负责将 QUIC 数据帧组合成数据包，以及将接收到的数据包解析成帧。

**该文件的主要功能包括：**

1. **构建各种类型的 QUIC 数据包：**  该文件包含了多个测试用例，用于验证 `QuicFramer` 是否能正确地构建不同类型的 QUIC 数据包。例如：
    - 包含 `STREAM` 帧的数据包 (例如 `BuildStreamFramePacket`)
    - 包含 `CRYPTO` 帧的数据包 (例如 `BuildCryptoFramePacket`)
    - 版本协商数据包 (例如 `BuildVersionNegotiationPacket`)
    - 包含 `ACK` 帧的数据包 (例如 `BuildAckFramePacketOneAckBlock`)
    - 包含带接收时间戳的 `ACK` 帧的数据包 (例如 `BuildAckReceiveTimestampsFrameMultipleRanges`)

2. **测试不同 QUIC 版本下的数据包构建：** 许多测试用例会根据不同的 QUIC 版本 (例如使用 IETF QUIC 帧格式的版本) 来构建不同的数据包结构，以确保 `QuicFramer` 能够处理各种版本。

3. **测试带有各种标志的数据包构建：**  例如，测试构建带有 `VERSION_FLAG` 的数据包 (`BuildStreamFramePacketWithVersionFlag`)。

4. **测试 `CRYPTO` 帧的构建和处理：**  专门针对 `CRYPTO` 帧进行了构建 (`BuildCryptoFramePacket`) 和解析 (`CryptoFrame`) 的测试。

5. **测试旧版本协商数据包的构建：**  确保能构建旧格式的版本协商包 (`BuildOldVersionNegotiationPacket`)。

6. **测试带客户端连接 ID 的版本协商数据包构建：**  验证在支持客户端连接 ID 的情况下版本协商包的构建 (`BuildVersionNegotiationPacketWithClientConnectionId`)。

7. **测试 `ACK` 帧的构建，包括接收时间戳：**  详细测试了构建包含不同数量的 ACK 块和接收时间戳的 ACK 帧，以及处理最大接收时间戳数量的情况。

8. **测试 `ACK` 帧接收时间戳的指数编码：**  验证了使用指数编码来压缩接收时间戳的功能。

9. **构建并处理带有接收时间戳的 `ACK` 帧：**  测试了构建包含接收时间戳的 ACK 帧，并验证了 `QuicFramer` 能正确解析这些时间戳。

**与 JavaScript 的关系：**

QUIC 协议是下一代 HTTP 协议 (HTTP/3) 的底层传输协议，而 HTTP/3 在现代 Web 浏览器中被广泛支持。JavaScript 代码通常运行在浏览器环境中，它可以通过浏览器的 API (例如 `fetch` API 或 `XMLHttpRequest` API) 发起 HTTP 请求。

虽然这个 C++ 测试文件本身不包含或执行 JavaScript 代码，但它测试了浏览器网络栈中负责处理 QUIC 协议的关键组件 (`QuicFramer`) 的正确性。

**举例说明：**

当一个 JavaScript 应用使用 `fetch` API 向一个支持 HTTP/3 的服务器发起请求时，浏览器底层的网络栈会使用 QUIC 协议与服务器建立连接并传输数据。在这个过程中：

1. **JavaScript 发起请求:** `fetch('https://example.com')`
2. **浏览器处理请求:** 浏览器会解析 URL，确定需要使用 HTTPS 和 HTTP/3。
3. **QUIC 连接建立:** 浏览器会尝试与服务器建立 QUIC 连接。这可能涉及到发送版本协商数据包 (类似于这里测试的 `BuildVersionNegotiationPacket`)。
4. **数据包构建:** 当需要发送 HTTP 请求数据时，浏览器底层的 QUIC 实现会使用类似 `QuicFramer` 的组件将 HTTP/3 头部和数据封装到 QUIC `STREAM` 帧中，然后构建成 QUIC 数据包 (类似于这里测试的 `BuildStreamFramePacket`)。
5. **数据包发送和接收:** 构建好的 QUIC 数据包会被发送到服务器。服务器收到数据包后，也会使用类似的 `QuicFramer` 组件解析数据包，提取出 `STREAM` 帧中的 HTTP 请求信息。
6. **ACK 机制:**  为了保证可靠性，接收方会发送 `ACK` 帧来确认收到了数据包 (类似于这里测试的 `BuildAckFramePacketOneAckBlock` 和 `BuildAckReceiveTimestampsFrameMultipleRanges`)。

因此，虽然 JavaScript 代码不直接操作 `QuicFramer`，但 `QuicFramer` 的正确性直接影响到基于 JavaScript 的 Web 应用使用 HTTP/3 的性能和可靠性。

**逻辑推理、假设输入与输出：**

**示例 1: `BuildStreamFramePacket` 测试**

**假设输入:**
- `stream_id`:  `kStreamId` (假设值为 100)
- `fin`: `true` (表示这是流的最后一个数据帧)
- `offset`: `kStreamOffset` (假设值为 0)
- `data`: `"hello world!"`

**预期输出 (部分):**  构建出的数据包应该包含以下字节序列 (基于 `packet_ietf` 数组)：
- `0x08 | 0x01 | 0x04`:  IETF_STREAM 帧类型，包含 FIN 和 OFFSET 标志。
- `kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04`:  流 ID (假设 `kStreamId` 编码为 4 字节的 VarInt)。
- `kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54`: 偏移量 (假设 `kStreamOffset` 编码为 8 字节的 VarInt)。
- `'h',  'e',  'l',  'l', 'o',  ' ',  'w',  'o', 'r',  'l',  'd',  '!'`:  数据内容。

**示例 2: `BuildVersionNegotiationPacket` 测试**

**假设输入:**
- `connection_id`: `FramerTestConnectionId()` (假设值为 `0xFEDCBA9876543210`)
- `ietf_quic`: `true` (构建 IETF QUIC 格式的版本协商包)
- `SupportedVersions(GetParam())`:  支持的 QUIC 版本列表 (取决于测试参数 `GetParam()`).

**预期输出 (部分):** 构建出的版本协商包应该包含以下字节序列 (基于 `packet` 或 `packet49` 数组)：
- `0xC0`:  长头部类型。
- `0x00, 0x00, 0x00, 0x00`:  版本号 (对于版本协商包为 0)。
- 连接 ID 长度和连接 ID。
- 支持的 QUIC 版本列表 (例如 `0xDA, 0x5A, 0x3A, 0x3A, QUIC_VERSION_BYTES`).

**用户或编程常见的使用错误：**

1. **错误的帧类型或标志位设置：**  开发者可能错误地设置了帧的类型或标志位，导致接收方无法正确解析。例如，在发送 `STREAM` 帧时忘记设置 `FIN` 标志，导致接收方认为还有更多数据要接收。

2. **不正确的连接 ID 或数据包编号：**  在构建数据包时，如果使用了错误的连接 ID 或数据包编号，接收方可能无法将其关联到正确的 QUIC 连接。

3. **版本不匹配：**  在连接建立阶段，如果客户端和服务端支持的 QUIC 版本不一致，可能会导致连接失败。`QuicFramer` 需要能够正确处理版本协商过程。

4. **VarInt 编码错误：**  QUIC 广泛使用变长整数 (VarInt) 编码。如果开发者在手动构建帧或解析帧时，VarInt 的编码或解码出现错误，会导致数据解析失败。

5. **接收时间戳处理错误：**  在处理带有接收时间戳的 ACK 帧时，如果开发者没有正确配置 `QuicFramer` 或没有正确理解时间戳的编码方式，可能会导致时间戳信息丢失或错误。

**用户操作如何一步步到达这里（调试线索）：**

这个文件是单元测试代码，用户通常不会直接 "到达" 这里。但是，当用户在使用基于 Chromium 内核的浏览器（例如 Chrome）访问使用 QUIC 协议的网站时，如果出现网络问题，开发者可能会使用以下步骤来调试并最终可能涉及到 `quic_framer_test.cc`：

1. **用户报告网络问题：** 用户可能会遇到网页加载缓慢、连接中断等问题。
2. **开发者收集信息：** 开发者可能会查看浏览器的网络日志 (chrome://net-export/)，抓包 (Wireshark)，或者查看 Chrome 的内部 QUIC 状态 (chrome://webrtc-internals/)。
3. **定位到 QUIC 层问题：**  通过分析日志或抓包，开发者可能会发现问题与 QUIC 协议相关，例如数据包丢失、ACK 丢失、连接迁移问题等。
4. **深入 QUIC 代码调试：**  为了进一步诊断问题，开发者可能需要查看 Chromium 的 QUIC 代码。他们可能会从网络栈的入口点开始，逐步跟踪代码执行流程，例如：
    - 数据包的接收和发送路径
    - `QuicFramer` 的调用，查看数据包是如何被解析或构建的
    - ACK 帧的处理逻辑
    - 拥塞控制和流量控制逻辑
5. **运行单元测试：**  为了验证某个特定模块（例如 `QuicFramer`）的行为是否正确，开发者会运行相关的单元测试。如果怀疑 `QuicFramer` 在构建或解析特定类型的帧时存在问题，他们可能会运行 `quic_framer_test.cc` 中的相关测试用例，例如测试构建 ACK 帧的测试 (`BuildAckFramePacketOneAckBlock` 等) 或测试处理 CRYPTO 帧的测试 (`CryptoFrame`)。

因此，虽然用户操作不会直接跳转到这个测试文件，但当用户的网络体验受到 QUIC 相关问题影响时，开发者可能会使用这个文件中的测试用例作为调试工具，来验证和修复底层的 QUIC 实现。

**作为第 7 部分的功能归纳：**

作为整个 `quic_framer_test.cc` 文件的一部分，这第 7 部分主要专注于 **测试 `QuicFramer` 构建和处理各种类型 QUIC 数据包和帧的能力，特别是针对 `STREAM` 帧、`CRYPTO` 帧以及各种 `ACK` 帧（包括带有接收时间戳的 ACK 帧）的构建和解析**。它涵盖了不同 QUIC 版本下的数据包结构，并验证了在不同场景下 `QuicFramer` 的正确行为，例如处理版本协商和带客户端连接 ID 的情况。 这部分测试对于确保 QUIC 协议实现的正确性和可靠性至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共16部分，请归纳一下它的功能

"""
eamId, true, kStreamOffset,
                               absl::string_view("hello world!"));

  QuicFrames frames = {QuicFrame(stream_frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (stream frame with fin and no length)
    0xDF,
    // stream id
    0x01, 0x02, 0x03, 0x04,
    // offset
    0x3A, 0x98, 0xFE, 0xDC,
    0x32, 0x10, 0x76, 0x54,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };

  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_STREAM frame with FIN and OFFSET, no length)
    0x08 | 0x01 | 0x04,
    // stream id
    kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04,
    // offset
    kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
    0x32, 0x10, 0x76, 0x54,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
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
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p), p_size);
}

TEST_P(QuicFramerTest, BuildStreamFramePacketWithVersionFlag) {
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = true;
  header.long_packet_type = ZERO_RTT_PROTECTED;
  header.packet_number = kPacketNumber;
  if (QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  }

  QuicStreamFrame stream_frame(kStreamId, true, kStreamOffset,
                               absl::string_view("hello world!"));
  QuicFrames frames = {QuicFrame(stream_frame)};

  // clang-format off
  unsigned char packet[] = {
      // type (long header with packet type ZERO_RTT_PROTECTED)
      0xD3,
      // version tag
      QUIC_VERSION_BYTES,
      // connection_id length
      0x50,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // frame type (stream frame with fin and no length)
      0xDF,
      // stream id
      0x01, 0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data
      'h',  'e',  'l',  'l',  'o',  ' ',  'w',  'o',  'r', 'l', 'd', '!',
  };

  unsigned char packet49[] = {
      // type (long header with packet type ZERO_RTT_PROTECTED)
      0xD3,
      // version tag
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // length
      0x40, 0x1D,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // frame type (stream frame with fin and no length)
      0xDF,
      // stream id
      0x01, 0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data
      'h',  'e',  'l',  'l',  'o',  ' ',  'w',  'o',  'r', 'l', 'd', '!',
  };

  unsigned char packet_ietf[] = {
      // type (long header with packet type ZERO_RTT_PROTECTED)
      0xD3,
      // version tag
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // length
      0x40, 0x1D,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // frame type (IETF_STREAM frame with fin and offset, no length)
      0x08 | 0x01 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data
      'h',  'e',  'l',  'l',  'o',  ' ',  'w',  'o',  'r', 'l', 'd', '!',
  };
  // clang-format on

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    ReviseFirstByteByVersion(packet_ietf);
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  } else if (framer_.version().HasLongHeaderLengths()) {
    p = packet49;
    p_size = ABSL_ARRAYSIZE(packet49);
  }
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p), p_size);
}

TEST_P(QuicFramerTest, BuildCryptoFramePacket) {
  if (!QuicVersionUsesCryptoFrames(framer_.transport_version())) {
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  SimpleDataProducer data_producer;
  framer_.set_data_producer(&data_producer);

  absl::string_view crypto_frame_contents("hello world!");
  QuicCryptoFrame crypto_frame(ENCRYPTION_INITIAL, kStreamOffset,
                               crypto_frame_contents.length());
  data_producer.SaveCryptoData(ENCRYPTION_INITIAL, kStreamOffset,
                               crypto_frame_contents);

  QuicFrames frames = {QuicFrame(&crypto_frame)};

  // clang-format off
  unsigned char packet48[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (QuicFrameType CRYPTO_FRAME)
    0x08,
    // offset
    kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
    0x32, 0x10, 0x76, 0x54,
    // length
    kVarInt62OneByte + 12,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };

  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_CRYPTO frame)
    0x06,
    // offset
    kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
    0x32, 0x10, 0x76, 0x54,
    // length
    kVarInt62OneByte + 12,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  unsigned char* packet = packet48;
  size_t packet_size = ABSL_ARRAYSIZE(packet48);
  if (framer_.version().HasIetfQuicFrames()) {
    packet = packet_ietf;
    packet_size = ABSL_ARRAYSIZE(packet_ietf);
  }

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  quiche::test::CompareCharArraysWithHexError("constructed packet",
                                              data->data(), data->length(),
                                              AsChars(packet), packet_size);
}

TEST_P(QuicFramerTest, CryptoFrame) {
  if (!QuicVersionUsesCryptoFrames(framer_.transport_version())) {
    // CRYPTO frames aren't supported prior to v48.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet48 = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (QuicFrameType CRYPTO_FRAME)
      {"",
       {0x08}},
      // offset
      {"",
       {kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      // data length
      {"Invalid data length.",
       {kVarInt62OneByte + 12}},
      // data
      {"Unable to read frame data.",
       {'h',  'e',  'l',  'l',
        'o',  ' ',  'w',  'o',
        'r',  'l',  'd',  '!'}},
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
      // frame type (IETF_CRYPTO frame)
      {"",
       {0x06}},
      // offset
      {"",
       {kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      // data length
      {"Invalid data length.",
       {kVarInt62OneByte + 12}},
      // data
      {"Unable to read frame data.",
       {'h',  'e',  'l',  'l',
        'o',  ' ',  'w',  'o',
        'r',  'l',  'd',  '!'}},
  };
  // clang-format on

  PacketFragments& fragments =
      framer_.version().HasIetfQuicFrames() ? packet_ietf : packet48;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));
  ASSERT_EQ(1u, visitor_.crypto_frames_.size());
  QuicCryptoFrame* frame = visitor_.crypto_frames_[0].get();
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, frame->level);
  EXPECT_EQ(kStreamOffset, frame->offset);
  EXPECT_EQ("hello world!",
            std::string(frame->data_buffer, frame->data_length));

  CheckFramingBoundaries(fragments, QUIC_INVALID_FRAME_DATA);
}

TEST_P(QuicFramerTest, BuildOldVersionNegotiationPacket) {
  SetQuicFlag(quic_disable_version_negotiation_grease_randomness, true);
  // clang-format off
  unsigned char packet[] = {
      // public flags (version, 8 byte connection_id)
      0x0D,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // supported versions
      0xDA, 0x5A, 0x3A, 0x3A,
      QUIC_VERSION_BYTES,
  };
  QuicConnectionId connection_id = FramerTestConnectionId();
  std::unique_ptr<QuicEncryptedPacket> data(
      QuicFramer::BuildVersionNegotiationPacket(
          connection_id, EmptyQuicConnectionId(), /*ietf_quic=*/false,
          /*use_length_prefix=*/false,
          SupportedVersions(GetParam())));
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildVersionNegotiationPacket) {
  SetQuicFlag(quic_disable_version_negotiation_grease_randomness, true);
  // clang-format off
  unsigned char packet[] = {
      // type (long header)
      0xC0,
      // version tag
      0x00, 0x00, 0x00, 0x00,
      // connection_id length
      0x05,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // supported versions
      0xDA, 0x5A, 0x3A, 0x3A,
      QUIC_VERSION_BYTES,
  };
  unsigned char packet49[] = {
      // type (long header)
      0xC0,
      // version tag
      0x00, 0x00, 0x00, 0x00,
      // destination connection ID length
      0x00,
      // source connection ID length
      0x08,
      // source connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // supported versions
      0xDA, 0x5A, 0x3A, 0x3A,
      QUIC_VERSION_BYTES,
  };
  // clang-format on
  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasLongHeaderLengths()) {
    p = packet49;
    p_size = ABSL_ARRAYSIZE(packet49);
  }

  QuicConnectionId connection_id = FramerTestConnectionId();
  std::unique_ptr<QuicEncryptedPacket> data(
      QuicFramer::BuildVersionNegotiationPacket(
          connection_id, EmptyQuicConnectionId(), /*ietf_quic=*/true,
          framer_.version().HasLengthPrefixedConnectionIds(),
          SupportedVersions(GetParam())));
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p), p_size);
}

TEST_P(QuicFramerTest, BuildVersionNegotiationPacketWithClientConnectionId) {
  if (!framer_.version().SupportsClientConnectionIds()) {
    return;
  }

  SetQuicFlag(quic_disable_version_negotiation_grease_randomness, true);

  // clang-format off
  unsigned char packet[] = {
      // type (long header)
      0xC0,
      // version tag
      0x00, 0x00, 0x00, 0x00,
      // client/destination connection ID
      0x08,
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
      // server/source connection ID
      0x08,
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // supported versions
      0xDA, 0x5A, 0x3A, 0x3A,
      QUIC_VERSION_BYTES,
  };
  // clang-format on

  QuicConnectionId server_connection_id = FramerTestConnectionId();
  QuicConnectionId client_connection_id = FramerTestConnectionIdPlusOne();
  std::unique_ptr<QuicEncryptedPacket> data(
      QuicFramer::BuildVersionNegotiationPacket(
          server_connection_id, client_connection_id, true, true,
          SupportedVersions(GetParam())));
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildAckFramePacketOneAckBlock) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Use kSmallLargestObserved to make this test finished in a short time.
  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
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
      // (no ack blocks, 2 byte largest observed, 2 byte block length)
      0x45,
      // largest acked
      0x12, 0x34,
      // Zero delta time.
      0x00, 0x00,
      // first ack block length.
      0x12, 0x34,
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
      // Number of additional ack blocks.
      kVarInt62OneByte + 0x00,
      // first ack block length.
      kVarInt62TwoBytes + 0x12, 0x33,
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

TEST_P(QuicFramerTest, BuildAckReceiveTimestampsFrameMultipleRanges) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
  ack_frame.received_packet_times = PacketTimeVector{
      // Timestamp Range 3.
      {kSmallLargestObserved - 22, CreationTimePlus(0x29ffdddd)},
      {kSmallLargestObserved - 21, CreationTimePlus(0x29ffdedd)},
      // Timestamp Range 2.
      {kSmallLargestObserved - 11, CreationTimePlus(0x29ffdeed)},
      // Timestamp Range 1.
      {kSmallLargestObserved - 4, CreationTimePlus(0x29ffeeed)},
      {kSmallLargestObserved - 3, CreationTimePlus(0x29ffeeee)},
      {kSmallLargestObserved - 2, CreationTimePlus(0x29ffffff)},
  };
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  QuicFrames frames = {QuicFrame(&ack_frame)};

  unsigned char packet_ietf[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE,
      0xDC,
      0xBA,
      0x98,
      0x76,
      0x54,
      0x32,
      0x10,
      // packet number
      0x12,
      0x34,
      0x56,
      0x78,

      // frame type (IETF_ACK_RECEIVE_TIMESTAMPS frame)
      0x22,
      // largest acked
      kVarInt62TwoBytes + 0x12,
      0x34,  // = 4660
      // Zero delta time.
      kVarInt62OneByte + 0x00,
      // number of additional ack blocks
      kVarInt62OneByte + 0x00,
      // first ack block length.
      kVarInt62TwoBytes + 0x12,
      0x33,

      // Receive Timestamps.

      // Timestamp Range Count
      kVarInt62OneByte + 0x03,

      // Timestamp range 1 (three packets).
      // Gap
      kVarInt62OneByte + 0x02,
      // Timestamp Range Count
      kVarInt62OneByte + 0x03,
      // Timestamp Delta
      kVarInt62FourBytes + 0x29,
      0xff,
      0xff,
      0xff,
      // Timestamp Delta
      kVarInt62TwoBytes + 0x11,
      0x11,
      // Timestamp Delta
      kVarInt62OneByte + 0x01,

      // Timestamp range 2 (one packet).
      // Gap
      kVarInt62OneByte + 0x05,
      // Timestamp Range Count
      kVarInt62OneByte + 0x01,
      // Timestamp Delta
      kVarInt62TwoBytes + 0x10,
      0x00,

      // Timestamp range 3 (two packets).
      // Gap
      kVarInt62OneByte + 0x08,
      // Timestamp Range Count
      kVarInt62OneByte + 0x02,
      // Timestamp Delta
      kVarInt62OneByte + 0x10,
      // Timestamp Delta
      kVarInt62TwoBytes + 0x01,
      0x00,
  };
  // clang-format on

  framer_.set_process_timestamps(true);
  framer_.set_max_receive_timestamps_per_ack(8);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildAckReceiveTimestampsFrameExceedsMaxTimestamps) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
  ack_frame.received_packet_times = PacketTimeVector{
      // Timestamp Range 3 (not included because max receive timestamps = 4).
      {kSmallLargestObserved - 20, CreationTimePlus(0x29ffdddd)},
      // Timestamp Range 2.
      {kSmallLargestObserved - 10, CreationTimePlus(0x29ffdedd)},
      {kSmallLargestObserved - 9, CreationTimePlus(0x29ffdeed)},
      // Timestamp Range 1.
      {kSmallLargestObserved - 2, CreationTimePlus(0x29ffeeed)},
      {kSmallLargestObserved - 1, CreationTimePlus(0x29ffeeee)},
      {kSmallLargestObserved, CreationTimePlus(0x29ffffff)},
  };
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  QuicFrames frames = {QuicFrame(&ack_frame)};

  unsigned char packet_ietf[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE,
      0xDC,
      0xBA,
      0x98,
      0x76,
      0x54,
      0x32,
      0x10,
      // packet number
      0x12,
      0x34,
      0x56,
      0x78,

      // frame type (IETF_ACK_RECEIVE_TIMESTAMPS frame)
      0x22,
      // largest acked
      kVarInt62TwoBytes + 0x12,
      0x34,  // = 4660
      // Zero delta time.
      kVarInt62OneByte + 0x00,
      // number of additional ack blocks
      kVarInt62OneByte + 0x00,
      // first ack block length.
      kVarInt62TwoBytes + 0x12,
      0x33,

      // Receive Timestamps.

      // Timestamp Range Count
      kVarInt62OneByte + 0x02,

      // Timestamp range 1 (three packets).
      // Gap
      kVarInt62OneByte + 0x00,
      // Timestamp Range Count
      kVarInt62OneByte + 0x03,
      // Timestamp Delta
      kVarInt62FourBytes + 0x29,
      0xff,
      0xff,
      0xff,
      // Timestamp Delta
      kVarInt62TwoBytes + 0x11,
      0x11,
      // Timestamp Delta
      kVarInt62OneByte + 0x01,

      // Timestamp range 2 (one packet).
      // Gap
      kVarInt62OneByte + 0x05,
      // Timestamp Range Count
      kVarInt62OneByte + 0x01,
      // Timestamp Delta
      kVarInt62TwoBytes + 0x10,
      0x00,
  };
  // clang-format on

  framer_.set_process_timestamps(true);
  framer_.set_max_receive_timestamps_per_ack(4);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildAckReceiveTimestampsFrameWithExponentEncoding) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
  ack_frame.received_packet_times = PacketTimeVector{
      // Timestamp Range 2.
      {kSmallLargestObserved - 12, CreationTimePlus((0x06c00 << 3) + 0x03)},
      {kSmallLargestObserved - 11, CreationTimePlus((0x28e00 << 3) + 0x00)},
      // Timestamp Range 1.
      {kSmallLargestObserved - 5, CreationTimePlus((0x29f00 << 3) + 0x00)},
      {kSmallLargestObserved - 4, CreationTimePlus((0x29f00 << 3) + 0x01)},
      {kSmallLargestObserved - 3, CreationTimePlus((0x29f00 << 3) + 0x02)},
      {kSmallLargestObserved - 2, CreationTimePlus((0x29f00 << 3) + 0x03)},
  };
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();

  QuicFrames frames = {QuicFrame(&ack_frame)};

  unsigned char packet_ietf[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE,
      0xDC,
      0xBA,
      0x98,
      0x76,
      0x54,
      0x32,
      0x10,
      // packet number
      0x12,
      0x34,
      0x56,
      0x78,

      // frame type (IETF_ACK_RECEIVE_TIMESTAMPS frame)
      0x22,
      // largest acked
      kVarInt62TwoBytes + 0x12,
      0x34,  // = 4660
      // Zero delta time.
      kVarInt62OneByte + 0x00,
      // number of additional ack blocks
      kVarInt62OneByte + 0x00,
      // first ack block length.
      kVarInt62TwoBytes + 0x12,
      0x33,

      // Receive Timestamps.

      // Timestamp Range Count
      kVarInt62OneByte + 0x02,

      // Timestamp range 1 (three packets).
      // Gap
      kVarInt62OneByte + 0x02,
      // Timestamp Range Count
      kVarInt62OneByte + 0x04,
      // Timestamp Delta
      kVarInt62FourBytes + 0x00,
      0x02,
      0x9f,
      0x01,  // round up
      // Timestamp Delta
      kVarInt62OneByte + 0x00,
      // Timestamp Delta
      kVarInt62OneByte + 0x00,
      // Timestamp Delta
      kVarInt62OneByte + 0x01,

      // Timestamp range 2 (one packet).
      // Gap
      kVarInt62OneByte + 0x04,
      // Timestamp Range Count
      kVarInt62OneByte + 0x02,
      // Timestamp Delta
      kVarInt62TwoBytes + 0x11,
      0x00,
      // Timestamp Delta
      kVarInt62FourBytes + 0x00,
      0x02,
      0x21,
      0xff,
  };
  // clang-format on

  framer_.set_process_timestamps(true);
  framer_.set_max_receive_timestamps_per_ack(8);
  framer_.set_receive_timestamps_exponent(3);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildAndProcessAckReceiveTimestampsWithMultipleRanges) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);
  framer_.set_process_timestamps(true);
  framer_.set_max_receive_timestamps_per_ack(8);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
  ack_frame.received_packet_times = PacketTimeVector{
      {kSmallLargestObserved - 1201, CreationTimePlus(0x8bcaef234)},
      {kSmallLargestObserved - 1200, CreationTimePlus(0x8bcdef123)},
      {kSmallLargestObserved - 1000, CreationTimePlus(0xaacdef123)},
      {kSmallLargestObserved - 4, CreationTimePlus(0xabcdea125)},
      {kSmallLargestObserved - 2, CreationTimePlus(0xabcdee124)},
      {kSmallLargestObserved - 1, CreationTimePlus(0xabcdef123)},
      {kSmallLargestObserved, CreationTimePlus(0xabcdef123)},
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
                  {kSmallLargestObserved, CreationTimePlus(0xabcdef123)},
                  {kSmallLargestObserved - 1, CreationTimePlus(0xabcdef123)},
                  {kSmallLargestObserved - 2, CreationTimePlus(0xabcdee124)},
                  {kSmallLargestObserved - 4, CreationTimePlus(0xabcdea125)},
                  {kSmallLargestObserved - 1000, CreationTimePlus(0xaacdef123)},
                  {kSmallLargestObserved - 1200, CreationTimePlus(0x8bcdef123)},
                  {kSmallLargestObserved - 1201, CreationTimePlus(0x8bcaef234)},
              }));
}

TEST_P(QuicFramerTest,
       BuildAndProcessAckReceiveTimestampsExceedsMaxTimestamps) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);
  framer_.set_process_timestamps(true);
  framer_.set_max_receive_timestamps_per_ack(2);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
  ack_frame.received_packet_times = PacketTimeVector{
      {kSmallLargestObserved - 1201, CreationTimePlus(0x8bcaef234)},
      {kSmallLargestObserved - 1200, CreationTimePlus(0x8bcdef123)},
      {kSmallLargestObserved - 1000, CreationTimePlus(0xaacdef123)},
      {kSmallLargestObserved - 5, CreationTimePlus(0xabcdea125)},
      {kSmallLargestObserved - 3, CreationTimePlus(0xabcded124)},
      {kSmallLargestObserved - 2, CreationTimePlus(0xabcdee124)},
      {kSmallLargestObserved - 1, CreationTimePlus(0xabcdef123)},
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
                  {kSmallLargestObserved - 1, CreationTimePlus(0xabcdef123)},
                  {kSmallLargestObserved - 2, CreationTimePlus(0xabcdee124)},
              }));
}

TEST_P(QuicFramerTest,
       BuildAndProcessAckReceiveTimestampsWithExponentNoTruncation) {
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

  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
  ack_frame.received_packet_times = PacketTimeVector{
      {kSmallLargestObserved - 8, CreationTimePlus(0x1add << 3)},
      {kSmallLargestObserved - 7, CreationTimePlus(0x29ed << 3)},
      {kSmallLargestObserved - 3, CreationTimePlus(0x29fe << 3)},
      {kSmallLargestObserved - 2, CreationTimePlus(0x29ff << 3)},
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
                  {kSmallLargestObserved - 3, CreationTimePlus(0x29fe << 3)},
                  {kSmallLargestObserved - 7, CreationTimePlus(0x29ed << 3)},
                  {kSmallLargestObserved - 8, CreationTimePlus(0x1add << 3)},
              }));
}

TEST_P(QuicFramerTest,
       BuildAndProcessAckReceiveTimestampsWithExponentTruncation) {
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

  QuicAckFrame ack_frame = InitAckFrame(kSmallLargestObserved);
  ack_frame.received_packet_times = PacketTimeVector{
      {kSmallLargestObserved - 10, CreationTimePlus((0x1001 << 3) + 1)},
      {kSmallLargestObserved - 9, CreationTimePlus((0x2995 << 3) - 1)},
      {kSmallLargestObserved - 8, CreationTimePlus((0x2995 << 3) + 0)},
      {kSmallLargestObserved - 7, CreationTimePlus((0x2995 << 3) + 1)},
      {kSmallLargestObserved - 6, CreationTimePlus((0x2995 << 3) + 2)},
      {kSmallLargestObserved - 3, Cre
"""


```
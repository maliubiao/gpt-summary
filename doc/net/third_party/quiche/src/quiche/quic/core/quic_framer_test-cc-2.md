Response:
The user wants me to analyze a C++ source code file related to network packet processing in Chromium's QUIC implementation. Specifically, it's the third part of a 16-part analysis.

Here's a breakdown of how to address each part of the request:

1. **Functionality:** I need to examine the provided code snippets (which are test cases) and infer the general purpose of the `quic_framer_test.cc` file. It seems to be testing the `QuicFramer` class, which is responsible for parsing and processing QUIC packets.

2. **Relationship to JavaScript:** I need to consider if any of the tested functionalities have direct counterparts or implications for JavaScript in a web browser context. This will likely involve thinking about how network data is handled on the client-side.

3. **Logical Reasoning (Input/Output):** For the provided test cases, I can analyze the setup (packet fragments) and the assertions to determine the expected input and output of the `QuicFramer::ProcessPacket` method.

4. **Common User/Programming Errors:** I need to identify potential mistakes developers might make when working with a QUIC framer or when constructing QUIC packets, based on the error conditions checked in the tests.

5. **User Operations and Debugging:** I need to think about how a user's actions in a browser could lead to the QUIC framer being invoked and how the information in these tests might be relevant for debugging network issues.

6. **Summary of Functionality (Part 3):** Based on the analysis of this specific part, I need to provide a concise summary of the functionalities covered in these code snippets.

**Mental Walkthrough of the Code:**

* The code consists of several test cases (`TEST_P`) within the `QuicFramerTest` class.
* Each test case sets up a scenario involving the creation of a QUIC packet (often using `PacketFragments`) and then uses `framer_.ProcessPacket()` to parse it.
* Assertions (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_THAT`) are used to verify the outcome of the parsing, such as:
    * Whether the packet was processed successfully.
    * The values of fields in the parsed header (`visitor_.header_`).
    * The presence and content of parsed frames (e.g., `visitor_.stream_frames_`, `visitor_.padding_frames_`).
    * Error conditions (`framer_.error()`).
* Some tests involve header protection and different encryption levels.
* Several tests cover different types of QUIC frames (PADDING, STREAM, ACK).
* The tests also consider different QUIC versions (indicated by `VersionHasIetfQuicFrames`).

**Connecting to JavaScript:**

* JavaScript in a browser interacts with the network stack through APIs like `fetch` or WebSockets.
* The browser's network stack (including the QUIC implementation) handles the low-level details of packet construction and parsing.
* While JavaScript doesn't directly manipulate QUIC frames, its behavior is affected by how these frames are processed. For example, if a stream frame carrying data for a `fetch` request is malformed, the JavaScript application might receive an error.

**Drafting the Response (Iterative Process):**

I'll go through each test case, identify its purpose, and then generalize the functionality being tested. I'll look for connections to JavaScript concepts and common error scenarios. Finally, I'll synthesize a summary for this part.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 文件的第三部分，主要包含以下功能测试：

**本部分的功能归纳：**

本部分主要测试 `QuicFramer` 类在处理不同类型的 QUIC 数据包和帧时的解析能力，涵盖了以下几个方面：

* **处理包头不完整的情况：** 测试当数据包头部信息不完整时，`QuicFramer` 的处理行为。
* **处理乱序的数据包序号：** 测试当接收到的数据包序号先减小后增大时，`QuicFramer` 的序号处理逻辑。
* **处理包含 Diversification Nonce 的数据包：** 测试 `QuicFramer` 解析包含用于抵抗重放攻击的 `Diversification Nonce` 的数据包的能力。
* **处理版本不匹配的大 Public Flag 数据包：** 测试当接收到版本不匹配的数据包时，`QuicFramer` 的错误处理机制。
* **处理填充帧 (Padding Frame)：** 测试 `QuicFramer` 解析填充帧的能力，以及填充帧与其它帧的组合。
* **处理流帧 (Stream Frame)：** 测试 `QuicFramer` 解析携带用户数据的流帧的能力，包括不同长度的 Stream ID 以及是否包含 FIN 标志。
* **处理缺失 Diversification Nonce 的情况：** 测试当期望存在 `Diversification Nonce` 但实际缺失时，`QuicFramer` 的处理行为。
* **处理不同 Stream ID 长度的流帧：** 测试 `QuicFramer` 处理 1 字节、2 字节和 3 字节 Stream ID 的流帧的能力。
* **处理带有版本信息的流帧：** 测试 `QuicFramer` 解析带有版本信息的长头部数据包中的流帧的能力。
* **拒绝处理数据包：** 测试通过设置 `visitor_` 的标志来模拟拒绝处理整个数据包的情况。
* **拒绝处理包头：** 测试通过设置 `visitor_` 的标志来模拟拒绝处理数据包头部的情况。
* **处理确认帧 (ACK Frame)：** 测试 `QuicFramer` 解析包含单个 ACK 块的确认帧的能力。

**与 JavaScript 的功能关系及举例说明：**

虽然此 C++ 文件直接操作的是网络协议的底层细节，JavaScript 代码本身并不直接参与 QUIC 数据包的构建和解析，但 `QuicFramer` 的正确性直接影响着基于 QUIC 协议构建的上层应用，包括浏览器中的 JavaScript 代码。

举例来说：

1. **数据接收与解析：** 当浏览器使用 QUIC 加载网页资源时，服务器会将数据封装成 QUIC 数据包发送给浏览器。`QuicFramer` 负责解析这些数据包，提取出其中的 HTTP/3 帧（或 QUIC 的流数据）。如果 `QuicFramer` 解析流帧（Stream Frame）失败，JavaScript 代码可能就无法接收到完整的网页内容，导致页面加载失败或显示不完整。

   * **假设输入：**  一个包含流帧的 QUIC 数据包，该流帧携带了部分 HTML 代码。
   * **`QuicFramer` 的输出：** 成功解析出流帧，并将 HTML 数据传递给上层处理模块。
   * **JavaScript 的表现：**  浏览器接收到完整的 HTML 代码，并渲染出网页。
   * **错误情况：** 如果流帧的长度字段错误，`QuicFramer` 可能解析失败，导致 JavaScript 无法获得完整的 HTML，页面显示错乱。

2. **QUIC 连接管理：**  QUIC 协议中的连接建立、流控制、拥塞控制等机制都依赖于数据包的正确解析。例如，ACK 帧用于确认数据包的接收。如果 `QuicFramer` 无法正确解析 ACK 帧，发送端可能无法确认数据是否送达，导致重传甚至连接中断。这会直接影响到 JavaScript 中发起网络请求的可靠性。

   * **假设输入：**  一个包含 ACK 帧的 QUIC 数据包，确认了之前发送的数据包。
   * **`QuicFramer` 的输出：** 成功解析出 ACK 帧，并提取出确认的包序号。
   * **底层 QUIC 栈的行为：**  发送端收到 ACK 后，知道之前发送的数据已成功送达，可以继续发送新的数据。
   * **JavaScript 的表现：**  JavaScript 发起的 `fetch` 请求或 WebSocket 连接能够稳定地传输数据。
   * **错误情况：** 如果 ACK 帧的格式错误，`QuicFramer` 可能无法解析，发送端会认为数据丢失，可能触发不必要的重传，降低网络效率，间接影响 JavaScript 的性能。

3. **安全性：**  `Diversification Nonce` 用于增强 QUIC 的安全性，防止重放攻击。`QuicFramer` 必须正确处理包含或缺失 `Diversification Nonce` 的数据包。如果处理不当，可能会导致安全漏洞，影响用户数据安全。

   * **假设输入：**  一个包含有效 `Diversification Nonce` 的 0-RTT 数据包。
   * **`QuicFramer` 的输出：** 成功解析出 `Diversification Nonce` 并传递给安全模块进行验证。
   * **底层 QUIC 栈的行为：**  验证 `Diversification Nonce` 的有效性，确保数据包不是重放的。
   * **JavaScript 的表现：**  用户可以安全地访问需要 0-RTT 连接的资源。
   * **错误情况：** 如果 `QuicFramer` 无法正确解析 `Diversification Nonce`，可能会错误地拒绝合法的 0-RTT 数据包，或者接受重放的攻击数据包。

**逻辑推理、假设输入与输出：**

以下以其中一个测试用例 `TEST_P(QuicFramerTest, PacketWithDiversificationNonce)` 为例进行说明：

* **假设输入：** 一个构造好的 QUIC 数据包，其头部包含 `Diversification Nonce` 字段。根据测试代码，这个数据包可能是 QUIC-Crypto 握手协议中的 0-RTT 数据包。
* **`framer_.ProcessPacket(encrypted)` 的执行：** `QuicFramer` 尝试解析 `encrypted` 数据包。
* **预期输出：**
    * `framer_.ProcessPacket()` 返回 `true`，表示数据包解析成功。
    * `visitor_.header_->nonce` 不为空 (`ASSERT_TRUE(visitor_.header_->nonce != nullptr);`)。
    * `visitor_.header_->nonce` 的内容与预期的 `Diversification Nonce` 值一致 (`EXPECT_EQ(i, (*visitor_.header_->nonce)[static_cast<size_t>(i)]);`)。
    * `visitor_.padding_frames_` 包含一个填充帧 (`EXPECT_EQ(1u, visitor_.padding_frames_.size());`)。
    * 填充帧的填充字节数为 5 (`EXPECT_EQ(5, visitor_.padding_frames_[0]->num_padding_bytes);`)。

**用户或编程常见的使用错误及举例说明：**

1. **构建数据包时头部信息错误：** 程序员在手动构建 QUIC 数据包时，可能会错误地设置连接 ID 长度、包序号长度等头部字段。这会导致 `QuicFramer` 解析失败。

   * **错误示例：**  将连接 ID 长度字段设置为错误的值，导致 `QuicFramer` 尝试读取错误长度的连接 ID，从而报错。测试用例 `TEST_P(QuicFramerTest, ShortHeaderMissingDestinationConnectionId)`  模拟了这种情况。

2. **加密和解密配置不匹配：**  如果发送端和接收端使用的加密密钥或算法不一致，`QuicFramer` 在解密数据包内容时会失败。

   * **错误示例：**  发送端使用 `ENCRYPTION_FORWARD_SECURE` 加密，但接收端尝试使用 `ENCRYPTION_INITIAL` 解密，会导致解密失败。虽然本测试文件主要关注解析，但解密失败也会导致后续的帧解析无法进行。

3. **处理乱序数据包时状态管理错误：** QUIC 允许乱序数据包，接收端需要维护状态来正确处理这些数据包。如果状态管理不当，可能会导致重复处理或丢失数据。测试用例 `TEST_P(QuicFramerTest, PacketNumberDecreasesThenIncreases)` 旨在测试 `QuicFramer` 在处理乱序包序号时的正确性，反过来也暗示了错误处理可能导致的问题。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个支持 QUIC 协议的网站：

1. **用户在地址栏输入网址并回车，或者点击一个链接。**
2. **浏览器发起网络请求。**  如果服务器支持 QUIC 并且浏览器配置允许，浏览器会尝试建立 QUIC 连接。
3. **QUIC 连接建立过程：**  浏览器和服务器之间会进行 QUIC 握手，交换初始数据包，协商连接参数，包括加密密钥。
4. **数据传输：** 连接建立后，浏览器向服务器请求网页资源（例如 HTML、CSS、JavaScript、图片）。
5. **服务器响应：** 服务器将请求的资源数据分割成多个 QUIC 数据包，并通过网络发送给浏览器。
6. **浏览器接收数据包：** 浏览器底层的网络栈接收到这些 QUIC 数据包。
7. **`QuicFramer` 的调用：**  对于接收到的每个 QUIC 数据包，网络栈会调用 `QuicFramer::ProcessPacket()` 来解析数据包的头部和帧。
8. **测试用例的关联：**
   * 如果接收到的数据包头部不完整，可能会触发类似于 `TEST_P(QuicFramerTest, ShortHeaderMissingDestinationConnectionId)` 测试用例中检查的错误。
   * 如果接收到包含网页内容的流帧，会触发 `QuicFramer` 解析流帧，类似于 `TEST_P(QuicFramerTest, StreamFrame)` 测试用例所覆盖的场景。
   * 如果涉及到 0-RTT 连接，会涉及到 `Diversification Nonce` 的处理，类似于 `TEST_P(QuicFramerTest, PacketWithDiversificationNonce)` 的测试场景。

**作为调试线索：**

* **网络抓包：** 使用 Wireshark 等工具抓取网络数据包，可以查看浏览器接收到的原始 QUIC 数据包内容，与测试用例中构造的数据包进行对比，判断是否是数据包本身的问题。
* **QUIC 连接日志：** Chrome 浏览器内部有 QUIC 连接的日志，可以查看连接建立过程、数据包的发送和接收情况、错误信息等。这些日志可以帮助定位 `QuicFramer` 是否解析失败以及失败的原因。
* **断点调试：** 如果是开发者调试 Chromium 自身，可以在 `QuicFramer::ProcessPacket()` 函数内部设置断点，单步执行，查看解析过程中的变量值，帮助理解为什么解析会出错。
* **对比测试用例：** 当遇到 `QuicFramer` 解析错误时，可以查找类似的测试用例，了解正确的解析流程和期望的输出，帮助分析错误原因。例如，如果发现 `Diversification Nonce` 处理有问题，可以参考 `TEST_P(QuicFramerTest, PacketWithDiversificationNonce)` 和 `TEST_P(QuicFramerTest, MissingDiversificationNonce)` 来理解正确和错误的场景。

总而言之，`net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 文件的这一部分，通过大量的测试用例，详细验证了 `QuicFramer` 类在各种边界条件和异常情况下的数据包解析能力，确保了 QUIC 协议在 Chromium 中的正确实现，这对保障基于 QUIC 的网络连接的可靠性、性能和安全性至关重要，并间接影响着浏览器中 JavaScript 代码的网络行为。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共16部分，请归纳一下它的功能
```

### 源代码
```cpp
connection_id
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x78}},
      // padding
      {"", {0x00, 0x00, 0x00}},
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
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER, visitor_.header_->packet_number_length);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  CheckFramingBoundaries(fragments, QUIC_INVALID_PACKET_HEADER);
}

TEST_P(QuicFramerTest, PacketNumberDecreasesThenIncreases) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // Test the case when a packet is received from the past and future packet
  // numbers are still calculated relative to the largest received packet.
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber - 2;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  QuicEncryptedPacket encrypted(data->data(), data->length(), false);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
  EXPECT_EQ(PACKET_4BYTE_PACKET_NUMBER, visitor_.header_->packet_number_length);
  EXPECT_EQ(kPacketNumber - 2, visitor_.header_->packet_number);

  // Receive a 1 byte packet number.
  header.packet_number = kPacketNumber;
  header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  QuicEncryptedPacket encrypted1(data->data(), data->length(), false);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted1));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER, visitor_.header_->packet_number_length);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Process a 2 byte packet number 256 packets ago.
  header.packet_number = kPacketNumber - 256;
  header.packet_number_length = PACKET_2BYTE_PACKET_NUMBER;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  QuicEncryptedPacket encrypted2(data->data(), data->length(), false);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted2));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
  EXPECT_EQ(PACKET_2BYTE_PACKET_NUMBER, visitor_.header_->packet_number_length);
  EXPECT_EQ(kPacketNumber - 256, visitor_.header_->packet_number);

  // Process another 1 byte packet number and ensure it works.
  header.packet_number = kPacketNumber - 1;
  header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  QuicEncryptedPacket encrypted3(data->data(), data->length(), false);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted3));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(FramerTestConnectionId(),
            visitor_.header_->destination_connection_id);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER, visitor_.header_->packet_number_length);
  EXPECT_EQ(kPacketNumber - 1, visitor_.header_->packet_number);
}

TEST_P(QuicFramerTest, PacketWithDiversificationNonce) {
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  unsigned char packet[] = {
    // type: Long header with packet type ZERO_RTT_PROTECTED and 1 byte packet
    // number.
    0xD0,
    // version tag
    QUIC_VERSION_BYTES,
    // connection_id length
    0x05,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x78,
    // nonce
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,

    // frame type (padding)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };

  unsigned char packet49[] = {
    // type: Long header with packet type ZERO_RTT_PROTECTED and 1 byte packet
    // number.
    0xD0,
    // version tag
    QUIC_VERSION_BYTES,
    // destination connection ID length
    0x00,
    // source connection ID length
    0x08,
    // source connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // long header packet length
    0x26,
    // packet number
    0x78,
    // nonce
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,

    // frame type (padding)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  if (framer_.version().handshake_protocol != PROTOCOL_QUIC_CRYPTO) {
    return;
  }

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasLongHeaderLengths()) {
    p = packet49;
    p_size = ABSL_ARRAYSIZE(packet49);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_size, false);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_TRUE(visitor_.header_->nonce != nullptr);
  for (char i = 0; i < 32; ++i) {
    EXPECT_EQ(i, (*visitor_.header_->nonce)[static_cast<size_t>(i)]);
  }
  EXPECT_EQ(1u, visitor_.padding_frames_.size());
  EXPECT_EQ(5, visitor_.padding_frames_[0]->num_padding_bytes);
}

TEST_P(QuicFramerTest, LargePublicFlagWithMismatchedVersions) {
  // clang-format off
  unsigned char packet[] = {
    // type (long header, ZERO_RTT_PROTECTED, 4-byte packet number)
    0xD3,
    // version tag
    'Q', '0', '0', '0',
    // connection_id length
    0x50,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };

  unsigned char packet49[] = {
    // type (long header, ZERO_RTT_PROTECTED, 4-byte packet number)
    0xD3,
    // version tag
    'Q', '0', '0', '0',
    // destination connection ID length
    0x08,
    // destination connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // source connection ID length
    0x00,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasLongHeaderLengths()) {
    p = packet49;
    p_size = ABSL_ARRAYSIZE(packet49);
  }
  QuicEncryptedPacket encrypted(AsChars(p), p_size, false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(0, visitor_.frame_count_);
  EXPECT_EQ(1, visitor_.version_mismatch_);
}

TEST_P(QuicFramerTest, PaddingFrame) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
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
    // frame type - IETF_STREAM with FIN, LEN, and OFFSET bits set.
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

  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
    p_size = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_size, false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  EXPECT_EQ(2u, visitor_.padding_frames_.size());
  EXPECT_EQ(2, visitor_.padding_frames_[0]->num_padding_bytes);
  EXPECT_EQ(2, visitor_.padding_frames_[1]->num_padding_bytes);
  EXPECT_EQ(kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());
}

TEST_P(QuicFramerTest, StreamFrame) {
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
      // frame type (stream frame with fin)
      {"",
       {0xFF}},
      // stream id
      {"Unable to read stream_id.",
       {0x01, 0x02, 0x03, 0x04}},
      // offset
      {"Unable to read offset.",
       {0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      {"Unable to read frame data.",
       {
         // data length
         0x00, 0x0c,
         // data
         'h',  'e',  'l',  'l',
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
      // frame type - IETF_STREAM with FIN, LEN, and OFFSET bits set.
      {"",
       { 0x08 | 0x01 | 0x02 | 0x04 }},
      // stream id
      {"Unable to read IETF_STREAM frame stream id/count.",
       {kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04}},
      // offset
      {"Unable to read stream data offset.",
       {kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      // data length
      {"Unable to read stream data length.",
       {kVarInt62OneByte + 0x0c}},
      // data
      {"Unable to read frame data.",
       { 'h',  'e',  'l',  'l',
         'o',  ' ',  'w',  'o',
         'r',  'l',  'd',  '!'}},
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

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  EXPECT_EQ(kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  CheckFramingBoundaries(fragments, QUIC_INVALID_STREAM_DATA);
}

// Test an empty (no data) stream frame.
TEST_P(QuicFramerTest, EmptyStreamFrame) {
  // Only the IETF QUIC spec explicitly says that empty
  // stream frames are supported.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
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
      // frame type - IETF_STREAM with FIN, LEN, and OFFSET bits set.
      {"",
       { 0x08 | 0x01 | 0x02 | 0x04 }},
      // stream id
      {"Unable to read IETF_STREAM frame stream id/count.",
       {kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04}},
      // offset
      {"Unable to read stream data offset.",
       {kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      // data length
      {"Unable to read stream data length.",
       {kVarInt62OneByte + 0x00}},
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

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  EXPECT_EQ(kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  EXPECT_EQ(visitor_.stream_frames_[0].get()->data_length, 0u);

  CheckFramingBoundaries(packet, QUIC_INVALID_STREAM_DATA);
}

TEST_P(QuicFramerTest, MissingDiversificationNonce) {
  if (framer_.version().handshake_protocol != PROTOCOL_QUIC_CRYPTO) {
    // TLS does not use diversification nonces.
    return;
  }
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

  // clang-format off
  unsigned char packet[] = {
        // type (long header, ZERO_RTT_PROTECTED, 4-byte packet number)
        0xD3,
        // version tag
        QUIC_VERSION_BYTES,
        // connection_id length
        0x05,
        // connection_id
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        // packet number
        0x12, 0x34, 0x56, 0x78,
        // padding frame
        0x00,
    };

  unsigned char packet49[] = {
        // type (long header, ZERO_RTT_PROTECTED, 4-byte packet number)
        0xD3,
        // version tag
        QUIC_VERSION_BYTES,
        // destination connection ID length
        0x00,
        // source connection ID length
        0x08,
        // source connection ID
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        // IETF long header payload length
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
    p = packet49;
    p_length = ABSL_ARRAYSIZE(packet49);
  }
  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  if (framer_.version().HasHeaderProtection()) {
    EXPECT_THAT(framer_.error(), IsError(QUIC_DECRYPTION_FAILURE));
    EXPECT_EQ("Unable to decrypt ENCRYPTION_ZERO_RTT header protection.",
              framer_.detailed_error());
  } else {
    // Cannot read diversification nonce.
    EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_PACKET_HEADER));
    EXPECT_EQ("Unable to read nonce.", framer_.detailed_error());
  }
}

TEST_P(QuicFramerTest, StreamFrame2ByteStreamId) {
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
       // frame type (stream frame with fin)
       {"",
        {0xFD}},
       // stream id
       {"Unable to read stream_id.",
        {0x03, 0x04}},
       // offset
       {"Unable to read offset.",
        {0x3A, 0x98, 0xFE, 0xDC,
         0x32, 0x10, 0x76, 0x54}},
       {"Unable to read frame data.",
        {
          // data length
          0x00, 0x0c,
          // data
          'h',  'e',  'l',  'l',
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
      // frame type (IETF_STREAM frame with LEN, FIN, and OFFSET bits set)
      {"",
       {0x08 | 0x01 | 0x02 | 0x04}},
      // stream id
      {"Unable to read IETF_STREAM frame stream id/count.",
       {kVarInt62TwoBytes + 0x03, 0x04}},
      // offset
      {"Unable to read stream data offset.",
       {kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      // data length
      {"Unable to read stream data length.",
       {kVarInt62OneByte + 0x0c}},
      // data
      {"Unable to read frame data.",
       { 'h',  'e',  'l',  'l',
         'o',  ' ',  'w',  'o',
         'r',  'l',  'd',  '!'}},
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

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  // Stream ID should be the last 2 bytes of kStreamId.
  EXPECT_EQ(0x0000FFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  CheckFramingBoundaries(fragments, QUIC_INVALID_STREAM_DATA);
}

TEST_P(QuicFramerTest, StreamFrame1ByteStreamId) {
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
      // frame type (stream frame with fin)
      {"",
       {0xFC}},
      // stream id
      {"Unable to read stream_id.",
       {0x04}},
      // offset
      {"Unable to read offset.",
       {0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      {"Unable to read frame data.",
       {
         // data length
         0x00, 0x0c,
         // data
         'h',  'e',  'l',  'l',
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
      // frame type (IETF_STREAM frame with LEN, FIN, and OFFSET bits set)
      {"",
       {0x08 | 0x01 | 0x02 | 0x04}},
      // stream id
      {"Unable to read IETF_STREAM frame stream id/count.",
       {kVarInt62OneByte + 0x04}},
      // offset
      {"Unable to read stream data offset.",
       {kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      // data length
      {"Unable to read stream data length.",
       {kVarInt62OneByte + 0x0c}},
      // data
      {"Unable to read frame data.",
       { 'h',  'e',  'l',  'l',
         'o',  ' ',  'w',  'o',
         'r',  'l',  'd',  '!'}},
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

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  // Stream ID should be the last 1 byte of kStreamId.
  EXPECT_EQ(0x000000FF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  CheckFramingBoundaries(fragments, QUIC_INVALID_STREAM_DATA);
}

TEST_P(QuicFramerTest, StreamFrameWithVersion) {
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  PacketFragments packet = {
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      {"",
       {0xD3}},
      // version tag
      {"",
       {QUIC_VERSION_BYTES}},
      // connection_id length
      {"",
       {0x50}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (stream frame with fin)
      {"",
       {0xFE}},
      // stream id
      {"Unable to read stream_id.",
       {0x02, 0x03, 0x04}},
      // offset
      {"Unable to read offset.",
       {0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      {"Unable to read frame data.",
       {
         // data length
         0x00, 0x0c,
         // data
         'h',  'e',  'l',  'l',
         'o',  ' ',  'w',  'o',
         'r',  'l',  'd',  '!'}},
  };

  PacketFragments packet49 = {
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      {"",
       {0xD3}},
      // version tag
      {"",
       {QUIC_VERSION_BYTES}},
      // destination connection ID length
      {"",
       {0x08}},
      // destination connection ID
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // source connection ID length
      {"",
       {0x00}},
      // long header packet length
      {"",
       {0x1E}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (stream frame with fin)
      {"",
       {0xFE}},
      // stream id
      {"Long header payload length longer than packet.",
       {0x02, 0x03, 0x04}},
      // offset
      {"Long header payload length longer than packet.",
       {0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      {"Long header payload length longer than packet.",
       {
         // data length
         0x00, 0x0c,
         // data
         'h',  'e',  'l',  'l',
         'o',  ' ',  'w',  'o',
         'r',  'l',  'd',  '!'}},
  };

  PacketFragments packet_ietf = {
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      {"",
       {0xD3}},
      // version tag
      {"",
       {QUIC_VERSION_BYTES}},
      // destination connection ID length
      {"",
       {0x08}},
      // destination connection ID
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // source connection ID length
      {"",
       {0x00}},
      // long header packet length
      {"",
       {0x1E}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      {"",
       {0x08 | 0x01 | 0x02 | 0x04}},
      // stream id
      {"Long header payload length longer than packet.",
       {kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04}},
      // offset
      {"Long header payload length longer than packet.",
       {kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
        0x32, 0x10, 0x76, 0x54}},
      // data length
      {"Long header payload length longer than packet.",
       {kVarInt62OneByte + 0x0c}},
      // data
      {"Long header payload length longer than packet.",
       { 'h',  'e',  'l',  'l',
         'o',  ' ',  'w',  'o',
         'r',  'l',  'd',  '!'}},
  };
  // clang-format on

  quiche::QuicheVariableLengthIntegerLength retry_token_length_length =
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0;
  size_t retry_token_length = 0;
  quiche::QuicheVariableLengthIntegerLength length_length =
      QuicVersionHasLongHeaderLengths(framer_.transport_version())
          ? quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1
          : quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0;

  ReviseFirstByteByVersion(packet_ietf);
  PacketFragments& fragments =
      VersionHasIetfQuicFrames(framer_.transport_version())
          ? packet_ietf
          : (framer_.version().HasLongHeaderLengths() ? packet49 : packet);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId,
      retry_token_length_length, retry_token_length, length_length));

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  // Stream ID should be the last 3 bytes of kStreamId.
  EXPECT_EQ(0x00FFFFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  CheckFramingBoundaries(fragments, framer_.version().HasLongHeaderLengths()
                                        ? QUIC_INVALID_PACKET_HEADER
                                        : QUIC_INVALID_STREAM_DATA);
}

TEST_P(QuicFramerTest, RejectPacket) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  visitor_.accept_packet_ = false;

  // clang-format off
  unsigned char packet[] = {
      // type (short header, 4 byte packet number)
      0x43,
      // connection_id
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // packet number
      0x12, 0x34, 0x56, 0x78,

      // frame type (STREAM Frame with FIN, LEN, and OFFSET bits set)
      0x10 | 0x01 | 0x02 | 0x04,
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
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  ASSERT_EQ(0u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
}

TEST_P(QuicFramerTest, RejectPublicHeader) {
  visitor_.accept_public_header_ = false;

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 1 byte packet number)
    0x40,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x01,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_FALSE(visitor_.header_->packet_number.IsInitialized());
}

TEST_P(QuicFramerTest, AckFrameOneAckBlock) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short packet, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (ack frame)
      // (one ack block, 2 byte largest observed, 2 byte block length)
      {"",
       {0x45}},
      // largest acked
      {"Unable to read largest acked.",
       {0x12, 0x34}},
      // Zero delta time.
      {"Unable to read ack delay time.",
       {0x00, 0x00}},
      // first ack block length.
      {"Unable to read first ack block length.",
       {0x12, 0x34}},
      // num timestamps.
      {"Unable to read num received packets.",
       {0x00}}
  };

  PacketFragments packet_ietf = {
      // type (short packet, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
       // frame type (IETF_ACK)
       // (one ack block, 2 byte largest observed, 2 byte block length)
       // IETF-Quic ignores the bit-fields in the ack type, all of
       // that information is encoded elsewhere in the frame.
       {"",
        {0x02}},
       // largest acked
       {"Unable to read largest acked.",
        {kVarInt62TwoBytes  + 0x12, 0x34}},
       // Zero delta time.
       {"Unable to read ack delay time.",
        {kVarInt62OneByte + 0x00}},
      // Ack block count (0 -- no blocks after the first)
      {"Unable to read ack block count.",
       {kVarInt62OneByte + 0x00}},
       // first ack block length - 1.
       // IETF Quic defines the ack block's value as the "number of
       // packets that preceed the largest packet number in the block"
       // which for the 1st ack block is the largest acked field,
       // above. Thi
```
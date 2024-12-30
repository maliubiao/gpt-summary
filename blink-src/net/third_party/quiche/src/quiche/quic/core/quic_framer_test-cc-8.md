Response:
The user wants a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc`.
This file seems to contain unit tests for the `QuicFramer` class in the Chromium network stack. The tests focus on verifying the correct construction of various QUIC packets.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The file name `quic_framer_test.cc` strongly suggests that it's a test file for `QuicFramer`. The presence of `TEST_P` macros confirms this is a parameterized unit test.

2. **Analyze the test names:**  The test names like `BuildCloseFramePacket`, `BuildTruncatedCloseFramePacket`, `BuildGoAwayPacket`, `BuildWindowUpdatePacket`, etc., clearly indicate the file's primary function: testing the packet construction logic of `QuicFramer`. Specifically, it tests the ability of `QuicFramer` to build packets containing different types of QUIC frames.

3. **Categorize the tests:** Grouping the tests by the type of QUIC frame they are testing provides a good structural overview. The code explicitly tests building packets for:
    * CONNECTION_CLOSE (both regular and truncated)
    * APPLICATION_CLOSE (both regular and truncated, IETF specific)
    * GOAWAY (both regular and truncated, Google QUIC specific)
    * WINDOW_UPDATE (and its IETF equivalent MAX_STREAM_DATA)
    * MAX_DATA (IETF specific)
    * BLOCKED (and its IETF equivalent DATA_BLOCKED)
    * PING
    * HANDSHAKE_DONE (IETF specific)
    * ACK_FREQUENCY (IETF specific)
    * RESET_STREAM_AT (IETF specific)
    * MESSAGE
    * MTU Discovery (which is essentially a PING)
    * PUBLIC_RESET (with and without client address/endpoint ID)

4. **Address JavaScript relevance:**  QUIC is a transport layer protocol, and its core logic is typically implemented in languages like C++. JavaScript, being primarily a frontend language, doesn't directly handle QUIC framing. However, JavaScript in a browser interacts with QUIC through browser APIs. Therefore, it's important to highlight this indirect relationship. Examples of browser APIs using QUIC would be relevant.

5. **Illustrate logical reasoning with examples:** The tests demonstrate logical reasoning by constructing a specific packet using `QuicFramer` and then comparing the generated output with a pre-defined byte array representing the expected packet structure. A good example would be selecting a specific test case (like `BuildCloseFramePacket`) and showing the assumed input (the `QuicConnectionCloseFrame` and `QuicPacketHeader`) and the expected output (the `packet` array).

6. **Identify potential usage errors:** Common errors in using a framer would involve providing incorrect frame data, incorrect header information, or not handling different QUIC versions correctly. Examples should demonstrate these scenarios.

7. **Describe the debugging context:** Explain how a developer might end up inspecting this file during debugging. This usually involves issues with packet construction, transmission, or reception, leading to the need to examine the framing logic. Tracing network activity and then looking at the framer code to understand packet structure is a typical scenario.

8. **Summarize the functionality (for part 9 of 16):** Based on the analysis so far, summarize the key capabilities demonstrated in this specific section of the test file. Since this is part 9, focus on the types of frames covered in these tests.

9. **Review and refine:** Ensure the language is clear, concise, and accurate. Check for any logical inconsistencies or missing information. For example, ensure that the explanation of IETF vs. Google QUIC is clear where applicable. Also, ensure that the examples are easy to understand and directly relate to the code snippets.

This systematic approach allows for a comprehensive and accurate analysis of the provided source code.
这是一个名为 `quic_framer_test.cc` 的 C++ 源代码文件，属于 Chromium 网络栈中 QUIC 协议的实现部分。它的主要功能是**对 `QuicFramer` 类进行单元测试，验证其构建和解析 QUIC 数据包的功能是否正确**。

具体来说，从你提供的代码片段来看，这个文件的第 9 部分主要集中在测试 `QuicFramer` 构建特定类型控制帧（Connection Close, Application Close, GoAway, Window Update/Max Stream Data, Max Data, Blocked, Ping, Handshake Done, Ack Frequency, Reset Stream At, Message, MTU Discovery, Public Reset）的数据包的能力。

**功能归纳 (第 9 部分):**

这个部分主要测试了 `QuicFramer` 类**构建各种 QUIC 控制帧数据包**的功能，包括：

* **CONNECTION_CLOSE 帧:**  测试构建携带连接关闭帧的数据包，包括正常大小和截断的版本。针对 Google QUIC 和 IETF QUIC 两种不同的格式都进行了测试。
* **APPLICATION_CLOSE 帧:** 测试构建携带应用层连接关闭帧的数据包，包括正常大小和截断的版本，这部分是针对 IETF QUIC 的。
* **GOAWAY 帧:** 测试构建携带 GOAWAY 帧的数据包，包括正常大小和截断的版本，这部分是针对 Google QUIC 的。
* **WINDOW_UPDATE 帧 (Google QUIC) / MAX_STREAM_DATA 帧 (IETF QUIC):** 测试构建携带窗口更新帧的数据包。
* **MAX_DATA 帧 (IETF QUIC):** 测试构建携带最大数据限制帧的数据包。
* **BLOCKED 帧 (Google QUIC) / DATA_BLOCKED 帧 (IETF QUIC):** 测试构建携带阻塞帧的数据包。
* **PING 帧:** 测试构建携带 PING 帧的数据包。
* **HANDSHAKE_DONE 帧 (IETF QUIC):** 测试构建携带握手完成帧的数据包。
* **ACK_FREQUENCY 帧 (IETF QUIC):** 测试构建携带确认频率帧的数据包。
* **RESET_STREAM_AT 帧 (IETF QUIC):** 测试构建携带重置流在特定偏移量帧的数据包。
* **MESSAGE 帧:** 测试构建携带消息帧的数据包。
* **MTU Discovery 帧:** 测试构建 MTU 发现帧的数据包，实际上是作为一个 PING 包发送。
* **PUBLIC_RESET 数据包:** 测试构建公共重置数据包，包括携带客户端地址和 Endpoint ID 的情况。

**与 JavaScript 的关系：**

QUIC 协议主要在网络层和传输层实现，JavaScript 通常不直接处理 QUIC 数据包的构建和解析。但是，JavaScript 在浏览器环境中与 QUIC 有间接关系：

* **Fetch API 和 WebSocket API:** 浏览器中的 `fetch` API 和 WebSocket API 可以使用 HTTP/3 (基于 QUIC)。当 JavaScript 代码发起网络请求或建立 WebSocket 连接时，底层的浏览器网络栈可能会使用 QUIC 进行数据传输。
* **浏览器开发者工具:** 开发者可以使用浏览器的开发者工具（例如 Chrome 的 "Network" 面板）来查看使用 QUIC 的连接信息和数据包。虽然 JavaScript 不直接操作 QUIC 数据包，但它可以通过浏览器提供的接口来触发 QUIC 连接和观察其行为。

**举例说明:**

假设一个网页使用 `fetch` API 向服务器请求数据：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

如果 `example.com` 服务器支持 HTTP/3 并且浏览器启用了 QUIC，那么底层的网络连接会使用 QUIC。`quic_framer_test.cc` 中测试的 `QuicFramer` 类就负责构建和解析这个 QUIC 连接中传输的数据包，例如，当服务器需要关闭连接时，就会构建一个 CONNECTION_CLOSE 帧的数据包，其构建过程就可能被这个测试文件中的相关测试覆盖。

**逻辑推理 (假设输入与输出):**

以 `TEST_P(QuicFramerTest, BuildCloseFramePacket)` 这个测试为例：

**假设输入:**

* `framer_` 实例的传输版本 (`framer_.transport_version()`) 决定了使用 Google QUIC 还是 IETF QUIC 的帧格式。
* `QuicPacketHeader` 结构体包含了数据包的头部信息，如连接 ID 和包序号。
* `QuicConnectionCloseFrame` 结构体包含了连接关闭帧的具体信息，如错误码和错误详情。
* `frames` 变量包含了要构建的帧列表。

**预期输出:**

* `BuildDataPacket(header, frames)` 函数应该返回一个 `QuicPacket` 对象，其数据部分（`data->data()`）应该与预定义的 `packet` 或 `packet_ietf` 数组的内容完全一致。这两个数组分别代表了使用 Google QUIC 和 IETF QUIC 格式构建的 CONNECTION_CLOSE 帧数据包的字节表示。

**用户或编程常见的使用错误：**

* **错误地设置帧的参数:**  例如，在构建 `QuicConnectionCloseFrame` 时，提供了错误的错误码或错误详情，导致构建的数据包不符合协议规范。
* **不匹配的 QUIC 版本处理:** 如果代码没有根据协商的 QUIC 版本正确地构建或解析帧（例如，使用 Google QUIC 的帧格式发送到只支持 IETF QUIC 的对端），会导致连接失败或数据解析错误。
* **缓冲区溢出或不足:** 在手动构建数据包时，如果计算的缓冲区大小不正确，可能会导致数据溢出或写入不足，`QuicFramer` 可以避免这类问题，但如果开发者直接操作底层字节流，则容易出错。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在使用 Chrome 浏览器访问网站时遇到连接问题:**  例如，网页加载缓慢、连接中断或出现特定的 QUIC 相关错误。
2. **网络工程师或 Chromium 开发者开始调查问题:** 他们可能会使用抓包工具（如 Wireshark）捕获网络数据包，发现存在格式错误的 QUIC 数据包，例如接收到了一个无法正确解析的 CONNECTION_CLOSE 帧。
3. **开发者怀疑是数据包构建或解析的问题:**  他们会查看 Chromium 的 QUIC 代码，特别是 `QuicFramer` 相关的代码。
4. **定位到 `quic_framer_test.cc` 文件:**  为了验证 `QuicFramer` 的行为是否正确，开发者会运行这个测试文件中的相关测试用例，例如 `BuildCloseFramePacket` 和相关的解析测试。
5. **检查测试用例和代码:** 开发者会仔细阅读测试用例的代码，理解其输入和预期的输出，并对比实际的网络数据包内容，从而找到 `QuicFramer` 代码中可能存在的 bug。例如，如果实际抓到的 CONNECTION_CLOSE 包的字节序列与测试用例中预期的不一致，那么就可能意味着 `QuicFramer` 在构建该帧时存在错误。

总而言之，`net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 的这个部分是 QUIC 协议实现中非常重要的单元测试，它确保了 `QuicFramer` 能够正确地构建各种控制帧的数据包，为 QUIC 连接的稳定性和可靠性提供了保障。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共16部分，请归纳一下它的功能

"""
IETF error code INTERNAL_ERROR = 0x01 corresponding to
    // QuicErrorCode::QUIC_INTERNAL_ERROR = 0x01.
    kVarInt62OneByte + 0x01,
    // Frame type within the CONNECTION_CLOSE frame
    kVarInt62OneByte + 0x05,
    // error details length
    kVarInt62OneByte + 0x13,
    // error details
    '1',  '7',  '7',  '6',
    '7',  ':',  'b',  'e',
    'c',  'a',  'u',  's',
    'e',  ' ',  'I',  ' ',
    'c',  'a',  'n'
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

TEST_P(QuicFramerTest, BuildTruncatedCloseFramePacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicConnectionCloseFrame close_frame(framer_.transport_version(),
                                       QUIC_INTERNAL_ERROR, NO_IETF_QUIC_ERROR,
                                       std::string(2048, 'A'), 0x05);
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
    0x01, 0x00,
    // error details (truncated to 256 bytes)
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
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
    kVarInt62TwoBytes + 0x01, 0x00,
    // error details (truncated to 256 bytes)
    '1',  ':',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
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

TEST_P(QuicFramerTest, BuildApplicationCloseFramePacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC.
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicConnectionCloseFrame app_close_frame;
  app_close_frame.wire_error_code = 0x11;
  app_close_frame.error_details = "because I can";
  app_close_frame.close_type = IETF_QUIC_APPLICATION_CONNECTION_CLOSE;

  QuicFrames frames = {QuicFrame(&app_close_frame)};

  // clang-format off

  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_APPLICATION_CLOSE frame)
    0x1d,
    // error code
    kVarInt62OneByte + 0x11,
    // error details length
    kVarInt62OneByte + 0x0f,
    // error details, note that it includes an extended error code.
    '0',  ':',  'b',  'e',
    'c',  'a',  'u',  's',
    'e',  ' ',  'I',  ' ',
    'c',  'a',  'n',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildTruncatedApplicationCloseFramePacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC.
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicConnectionCloseFrame app_close_frame;
  app_close_frame.wire_error_code = 0x11;
  app_close_frame.error_details = std::string(2048, 'A');
  app_close_frame.close_type = IETF_QUIC_APPLICATION_CONNECTION_CLOSE;
  // Setting to missing ensures that if it is missing, the extended
  // code is not added to the text message.
  app_close_frame.quic_error_code = QUIC_IETF_GQUIC_ERROR_MISSING;

  QuicFrames frames = {QuicFrame(&app_close_frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_APPLICATION_CLOSE frame)
    0x1d,
    // error code
    kVarInt62OneByte + 0x11,
    // error details length
    kVarInt62TwoBytes + 0x01, 0x00,
    // error details (truncated to 256 bytes)
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildGoAwayPacket) {
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for Google QUIC.
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicGoAwayFrame goaway_frame;
  goaway_frame.error_code = static_cast<QuicErrorCode>(0x05060708);
  goaway_frame.last_good_stream_id = kStreamId;
  goaway_frame.reason_phrase = "because I can";

  QuicFrames frames = {QuicFrame(&goaway_frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (go away frame)
    0x03,
    // error code
    0x05, 0x06, 0x07, 0x08,
    // stream id
    0x01, 0x02, 0x03, 0x04,
    // error details length
    0x00, 0x0d,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',
  };

  // clang-format on
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildTruncatedGoAwayPacket) {
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for Google QUIC.
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicGoAwayFrame goaway_frame;
  goaway_frame.error_code = static_cast<QuicErrorCode>(0x05060708);
  goaway_frame.last_good_stream_id = kStreamId;
  goaway_frame.reason_phrase = std::string(2048, 'A');

  QuicFrames frames = {QuicFrame(&goaway_frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (go away frame)
    0x03,
    // error code
    0x05, 0x06, 0x07, 0x08,
    // stream id
    0x01, 0x02, 0x03, 0x04,
    // error details length
    0x01, 0x00,
    // error details (truncated to 256 bytes)
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
    'A',  'A',  'A',  'A',  'A',  'A',  'A',  'A',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildWindowUpdatePacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicWindowUpdateFrame window_update_frame;
  window_update_frame.stream_id = kStreamId;
  window_update_frame.max_data = 0x1122334455667788;

  QuicFrames frames = {QuicFrame(window_update_frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (window update frame)
    0x04,
    // stream id
    0x01, 0x02, 0x03, 0x04,
    // byte offset
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
  };

  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_MAX_STREAM_DATA frame)
    0x11,
    // stream id
    kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04,
    // byte offset
    kVarInt62EightBytes + 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
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

TEST_P(QuicFramerTest, BuildMaxStreamDataPacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC.
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicWindowUpdateFrame window_update_frame;
  window_update_frame.stream_id = kStreamId;
  window_update_frame.max_data = 0x1122334455667788;

  QuicFrames frames = {QuicFrame(window_update_frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_MAX_STREAM_DATA frame)
    0x11,
    // stream id
    kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04,
    // byte offset
    kVarInt62EightBytes + 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildMaxDataPacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC.
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicWindowUpdateFrame window_update_frame;
  window_update_frame.stream_id =
      QuicUtils::GetInvalidStreamId(framer_.transport_version());
  window_update_frame.max_data = 0x1122334455667788;

  QuicFrames frames = {QuicFrame(window_update_frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_MAX_DATA frame)
    0x10,
    // byte offset
    kVarInt62EightBytes + 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, BuildBlockedPacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicBlockedFrame blocked_frame;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    // For IETF QUIC, the stream ID must be <invalid> for the frame
    // to be a BLOCKED frame. if it's valid, it will be a
    // STREAM_BLOCKED frame.
    blocked_frame.stream_id =
        QuicUtils::GetInvalidStreamId(framer_.transport_version());
  } else {
    blocked_frame.stream_id = kStreamId;
  }
  blocked_frame.offset = kStreamOffset;

  QuicFrames frames = {QuicFrame(blocked_frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short packet, 4 byte packet number)
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

  unsigned char packet_ietf[] = {
    // type (short packet, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_DATA_BLOCKED frame)
    0x14,
    // Offset
    kVarInt62EightBytes + 0x3a, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54
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

TEST_P(QuicFramerTest, BuildPingPacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPingFrame())};

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

  unsigned char* p = packet;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
  }

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildHandshakeDonePacket) {
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicHandshakeDoneFrame())};

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

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildAckFrequencyPacket) {
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrequencyFrame ack_frequency_frame;
  ack_frequency_frame.sequence_number = 3;
  ack_frequency_frame.packet_tolerance = 5;
  ack_frequency_frame.max_ack_delay = QuicTime::Delta::FromMicroseconds(0x3fff);
  ack_frequency_frame.ignore_order = false;
  QuicFrames frames = {QuicFrame(&ack_frequency_frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (Ack Frequency frame)
    0x40, 0xaf,
    // sequence number
    0x03,
    // packet tolerance
    0x05,
    // max_ack_delay_us
    0x7f, 0xff,
    // ignore_oder
    0x00
  };
  // clang-format on
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildResetStreamAtPacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicResetStreamAtFrame frame;
  frame.stream_id = 0x00;
  frame.error = 0x1e;
  frame.final_offset = 0x20;
  frame.reliable_offset = 0x10;
  QuicFrames frames = {QuicFrame(&frame)};

  framer_.set_process_reset_stream_at(true);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

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

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildMessagePacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicMessageFrame frame(1, MemSliceFromString("message"));
  QuicMessageFrame frame2(2, MemSliceFromString("message2"));
  QuicFrames frames = {QuicFrame(&frame), QuicFrame(&frame2)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (message frame)
    0x21,
    // Length
    0x07,
    // Message Data
    'm', 'e', 's', 's', 'a', 'g', 'e',
    // frame type (message frame no length)
    0x20,
    // Message Data
    'm', 'e', 's', 's', 'a', 'g', 'e', '2'
  };

  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_MESSAGE frame)
    0x31,
    // Length
    0x07,
    // Message Data
    'm', 'e', 's', 's', 'a', 'g', 'e',
    // frame type (message frame no length)
    0x30,
    // Message Data
    'm', 'e', 's', 's', 'a', 'g', 'e', '2'
  };
  // clang-format on

  unsigned char* p = packet;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
  }

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p),
      ABSL_ARRAYSIZE(packet));
}

// Test that the MTU discovery packet is serialized correctly as a PING packet.
TEST_P(QuicFramerTest, BuildMtuDiscoveryPacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicMtuDiscoveryFrame())};

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

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  unsigned char* p = packet;
  if (VersionHasIetfQuicFrames(framer_.transport_version())) {
    p = packet_ietf;
  }

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(p),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildPublicResetPacket) {
  QuicPublicResetPacket reset_packet;
  reset_packet.connection_id = FramerTestConnectionId();
  reset_packet.nonce_proof = kNonceProof;

  // clang-format off
  unsigned char packet[] = {
    // public flags (public reset, 8 byte ConnectionId)
    0x0E,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (1) + padding
    0x01, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> data(
      framer_.BuildPublicResetPacket(reset_packet));
  ASSERT_TRUE(data != nullptr);
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildPublicResetPacketWithClientAddress) {
  QuicPublicResetPacket reset_packet;
  reset_packet.connection_id = FramerTestConnectionId();
  reset_packet.nonce_proof = kNonceProof;
  reset_packet.client_address =
      QuicSocketAddress(QuicIpAddress::Loopback4(), 0x1234);

  // clang-format off
  unsigned char packet[] = {
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
      // tag kCADR
      'C', 'A', 'D', 'R',
      // end offset 16
      0x10, 0x00, 0x00, 0x00,
      // nonce proof
      0x89, 0x67, 0x45, 0x23,
      0x01, 0xEF, 0xCD, 0xAB,
      // client address
      0x02, 0x00,
      0x7F, 0x00, 0x00, 0x01,
      0x34, 0x12,
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> data(
      framer_.BuildPublicResetPacket(reset_packet));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, BuildPublicResetPacketWithEndpointId) {
  QuicPublicResetPacket reset_packet;
  reset_packet.connection_id = FramerTestConnectionId();
  reset_packet.nonce_proof = kNonceProof;
  reset_packet.endpoint_id = "FakeServerId";

  // The tag value map in CryptoHandshakeMessage is a std::map, so the two tags
  // in the packet, kRNON and kEPID, have unspecified ordering w.r.t each other.
  //
"""


```
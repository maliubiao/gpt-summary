Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The request asks for an explanation of a C++ test file's functionality, its relation to JavaScript (if any), logical inferences, common user errors, and how users might trigger this code. This requires understanding what the code *does* and *why*.

**2. Initial Scan and Keyword Spotting:**

First, I'd quickly scan the file, looking for recognizable keywords and patterns.

* **`websocket_frame_parser_test.cc`:**  Immediately tells me this is a test file related to parsing WebSocket frames.
* **`#include "net/websockets/websocket_frame_parser.h"`:** Confirms the subject of the tests.
* **`testing/gtest/include/gtest/gtest.h`:**  Indicates the use of Google Test framework. This means the file contains test cases using `TEST()` macros.
* **`namespace net {`:** Shows this code belongs to the `net` namespace, likely within Chromium's network stack.
* **`TEST(WebSocketFrameParserTest, ...)`:**  These are the individual test case declarations. Their names (`DecodeNormalFrame`, `DecodeMaskedFrame`, etc.) hint at what each test is verifying.
* **`constexpr`:** Suggests constant test data for various frame header scenarios.
* **`EXPECT_TRUE`, `EXPECT_EQ`, `ASSERT_EQ`:**  These are Google Test assertions, confirming expected behavior.
* **`MaskWebSocketFramePayload`:**  A function call indicating frame unmasking.

**3. Deeper Dive into Test Cases:**

Next, I'd examine individual test cases to grasp their specific purpose:

* **`DecodeNormalFrame`:**  Checks parsing of an unmasked "Hello, world!" frame. It verifies header fields (final bit, op-code, length) and the payload content.
* **`DecodeMaskedFrame`:** Similar to the above, but for a masked frame, and it explicitly unmasks the payload to verify the content.
* **`DecodeManyFrames`:** Tests the parser's ability to handle a sequence of consecutive frames.
* **`DecodePartialFrame` and `DecodePartialMaskedFrame`:**  Crucially, these test the parser's behavior when it receives data in chunks, simulating real-world network conditions. They check how the parser handles incomplete frames and reassembles them.
* **`DecodeFramesOfVariousLengths`:** Tests different payload length encodings (short, extended 16-bit, extended 64-bit) and verifies error handling for oversized payloads.
* **`DecodePartialHeader`:**  Focuses specifically on how the parser handles receiving the header in fragments.
* **`InvalidLengthEncoding`:** Checks for proper error handling when encountering invalid length encodings.
* **`FrameTypes`:** Verifies the parser correctly identifies different WebSocket frame opcodes (text, binary, close, ping, pong, etc.).
* **`FinalBitAndReservedBits`:** Tests the parsing of the final fragment bit and the reserved bits in the header.

**4. Identifying Functionality:**

Based on the test cases, I can deduce the primary function of `websocket_frame_parser_test.cc`:

* **Verifying the `WebSocketFrameParser`:**  The file's core purpose is to thoroughly test the `WebSocketFrameParser` class.
* **Testing Header Parsing:**  It checks the correct extraction of information from the WebSocket frame header (final bit, reserved bits, opcode, masking flag, payload length).
* **Testing Payload Handling:** It verifies the correct extraction and unmasking of the payload.
* **Testing Fragmentation Handling:**  It ensures the parser can handle frames sent in multiple chunks.
* **Testing Error Handling:** It checks the parser's ability to detect and report various errors (e.g., invalid length encodings, oversized payloads).
* **Testing Different Frame Types:**  It validates the parsing of different WebSocket control and data frames.

**5. Connecting to JavaScript:**

I consider how WebSockets work in a browser. JavaScript uses the WebSocket API to establish and communicate over WebSocket connections. The browser's underlying network stack (which includes this C++ code) handles the actual low-level frame parsing.

* **Direct JavaScript Interaction:**  JavaScript doesn't directly interact with this C++ file.
* **Indirect Relationship:** The C++ parser is *essential* for the JavaScript WebSocket API to function correctly. When a JavaScript application sends or receives WebSocket messages, the browser uses code like this to encode and decode the underlying frames.

**6. Logical Inferences (Assumptions and Outputs):**

For each test case, I can identify the intended input and the expected output based on the assertions. This is where the "if input X, then output Y" logic comes in.

* **Example:**  For `DecodeNormalFrame`, the input is `kHelloFrame`, and the expected output is a `WebSocketFrameChunk` with the correct header values and the unmasked "Hello, world!" payload.

**7. Identifying User/Programming Errors:**

I consider what mistakes developers might make when using WebSockets that could lead to these parsing scenarios:

* **Incorrect Server-Side Implementation:** A buggy WebSocket server might send malformed frames.
* **Network Issues:** Data corruption during transmission could lead to invalid frames.
* **Incorrect Manual Frame Construction (rare in typical use):** If someone tries to manually build WebSocket frames (instead of using a library), they could make mistakes in the header or masking.

**8. Tracing User Operations:**

This involves understanding the high-level user actions that eventually trigger the low-level parsing code.

* **Opening a WebSocket Connection:**  A user navigates to a web page or a JavaScript application initiates a WebSocket connection.
* **Sending a Message:** The JavaScript application uses `websocket.send()` to send data. The browser's network stack will format this data into one or more WebSocket frames.
* **Receiving a Message:**  The server sends a WebSocket message. The browser receives the raw bytes and uses the `WebSocketFrameParser` to interpret the incoming frames.

**9. Structuring the Answer:**

Finally, I organize the information into the requested categories: functionality, JavaScript relation, logical inferences, user errors, and debugging. I use clear language and provide specific examples from the code. I also make sure to explain *why* the tests are important (ensuring correct WebSocket communication).

This structured approach allows me to analyze the code systematically and extract the relevant information to address the user's request comprehensively.
这个文件 `net/websockets/websocket_frame_parser_test.cc` 是 Chromium 网络栈中用于测试 `WebSocketFrameParser` 类的单元测试文件。它的主要功能是验证 `WebSocketFrameParser` 类是否能够正确地解析各种合法的和非法的 WebSocket 数据帧。

**以下是它的具体功能列表:**

1. **解码正常帧 (DecodeNormalFrame):** 测试解析一个未经过掩码处理的完整文本数据帧。
2. **解码掩码帧 (DecodeMaskedFrame):** 测试解析一个经过掩码处理的完整文本数据帧，并验证掩码是否被正确移除。
3. **解码多个帧 (DecodeManyFrames):** 测试连续解码多个完整的数据帧。
4. **解码部分帧 (DecodePartialFrame):** 测试分片接收数据帧的情况，验证 `WebSocketFrameParser` 是否能正确处理不完整的帧头和载荷。
5. **解码部分掩码帧 (DecodePartialMaskedFrame):**  测试分片接收掩码处理的数据帧的情况。
6. **解码不同长度的帧 (DecodeFramesOfVariousLengths):** 测试解析不同载荷长度的数据帧，包括需要扩展长度字段的帧。
7. **解码部分帧头 (DecodePartialHeader):** 测试分片接收帧头的情况，验证 `WebSocketFrameParser` 是否能正确处理不完整的帧头。
8. **无效长度编码 (InvalidLengthEncoding):** 测试当接收到无效的载荷长度编码时，`WebSocketFrameParser` 是否能正确检测并报告错误。
9. **帧类型 (FrameTypes):** 测试解析不同类型的 WebSocket 帧（例如，文本帧、二进制帧、关闭帧、Ping 帧、Pong 帧）。
10. **Final 位和保留位 (FinalBitAndReservedBits):** 测试解析帧头中的 Final 位和保留位，验证它们是否被正确解析。

**与 JavaScript 功能的关系:**

这个 C++ 文件本身不直接与 JavaScript 代码交互。但是，它测试的 `WebSocketFrameParser` 类是浏览器网络栈的核心组件，负责处理通过 WebSocket 连接接收到的二进制数据。

当 JavaScript 代码使用 `WebSocket` API 发送或接收数据时，浏览器底层的网络栈会使用类似于 `WebSocketFrameParser` 这样的类来将 JavaScript 的数据转换为 WebSocket 帧（发送时）或将接收到的 WebSocket 帧解析为 JavaScript 可以理解的数据（接收时）。

**举例说明:**

* **JavaScript 发送数据:** 当 JavaScript 代码执行 `websocket.send("Hello")` 时，浏览器网络栈会将字符串 "Hello" 封装成一个 WebSocket 数据帧，可能类似 `\x81\x05Hello` (假设是文本帧且未掩码)。这个过程虽然不涉及 `WebSocketFrameParser`，但与之对应的发送端的帧构建逻辑会影响接收端 `WebSocketFrameParser` 的工作。
* **JavaScript 接收数据:** 当浏览器通过 WebSocket 连接接收到类似 `\x81\x0DHello, world!` 的二进制数据时，`WebSocketFrameParser` 会解析这个数据，提取帧头信息（例如，opcode 为文本，载荷长度为 13），并提取出载荷 "Hello, world!"。然后，这个载荷会被传递给 JavaScript 的 `WebSocket` 对象的 `onmessage` 事件处理函数。

**逻辑推理 (假设输入与输出):**

以下是一些基于测试用例的逻辑推理示例：

* **假设输入 (DecodeNormalFrame):**
    * 输入的二进制数据为 `\x81\x0DHello, world!`
    * **预期输出:** `WebSocketFrameParser` 会成功解析，并产生一个 `WebSocketFrameChunk` 对象，其中：
        * `header->final` 为 true
        * `header->opcode` 为 `WebSocketFrameHeader::kOpCodeText`
        * `header->masked` 为 false
        * `header->payload_length` 为 13
        * `payload` 的内容为 "Hello, world!"

* **假设输入 (DecodeMaskedFrame):**
    * 输入的二进制数据为 `\x81\x8D\xDE\xAD\xBE\xEF\x96\xC8\xD2\x83\xB1\x81\x9E\x98\xB1\xDF\xD2\x8B\xFF`
    * **预期输出:** `WebSocketFrameParser` 会成功解析，并产生一个 `WebSocketFrameChunk` 对象，其中：
        * `header->masked` 为 true
        * `header->masking_key` 为 `\xDE\xAD\xBE\xEF`
        * `payload` 的内容经过解掩码后为 "Hello, world!"

* **假设输入 (InvalidLengthEncoding):**
    * 输入的二进制数据为 `\x81\x7E\x00\x00` (表示长度为 0，但使用了扩展长度字段)
    * **预期输出:** `WebSocketFrameParser` 的 `Decode` 方法返回 false，并且 `websocket_error()` 返回 `kWebSocketErrorProtocolError`。

**用户或编程常见的使用错误 (举例说明):**

由于 `WebSocketFrameParser` 是在浏览器内部使用的，普通用户不会直接与之交互。编程错误主要发生在 WebSocket 服务端或客户端实现中，导致发送了格式错误的帧。

* **服务端发送未掩码的帧到客户端:** WebSocket 协议规定，客户端发送到服务端的数据帧必须进行掩码处理，而服务端发送到客户端的数据帧不能进行掩码处理。如果服务端错误地对发送到客户端的帧进行了掩码处理，`WebSocketFrameParser` 在接收到这样的帧时可能会报错或者解析出错误的数据。
    * **调试线索:** 在浏览器开发者工具的网络面板中，检查 WebSocket 帧的内容，如果发现服务端发送的帧的第二个字节的高位为 1 (表示设置了掩码位)，则可能是服务端实现错误。

* **客户端发送未掩码的帧到服务端:**  虽然 `WebSocketFrameParserTest` 主要测试接收端的解析，但如果客户端代码错误地发送了未掩码的帧到服务端，服务端可能会拒绝连接或报错。
    * **调试线索:** 检查客户端发送的 WebSocket 帧的第二个字节，如果高位为 0，但期望发送到服务端，则可能是客户端实现错误。

* **发送的帧载荷长度与帧头声明的长度不一致:** 如果构建 WebSocket 帧的代码错误地计算了载荷长度，导致帧头声明的长度与实际载荷的长度不符，`WebSocketFrameParser` 在尝试读取指定长度的载荷时可能会出错。
    * **调试线索:** 比对接收到的帧的帧头中声明的长度和实际接收到的载荷长度。

**用户操作是如何一步步的到达这里 (作为调试线索):**

虽然用户不直接操作 `WebSocketFrameParser`，但用户的操作会触发网络请求和 WebSocket 连接，最终导致数据流经这个解析器。以下是一个典型的流程：

1. **用户在浏览器中访问一个网页，该网页使用了 WebSocket 连接。**
2. **网页中的 JavaScript 代码创建了一个 `WebSocket` 对象，并连接到 WebSocket 服务器。**
3. **WebSocket 服务器向浏览器发送数据。** 这可能是由于服务器端某些事件的发生，或者响应客户端发送的消息。
4. **浏览器接收到来自服务器的 TCP 数据包。**
5. **浏览器的网络栈负责处理这些 TCP 数据包，并将属于 WebSocket 连接的数据提取出来。**
6. **提取出的 WebSocket 数据被传递给 `WebSocketFrameParser` 进行解析。**
7. **`WebSocketFrameParser` 根据帧头信息解析帧的类型、载荷长度、是否掩码等。**
8. **如果帧是掩码的，`WebSocketFrameParser` 会使用掩码密钥对载荷进行解掩码。**
9. **解析后的数据（payload）会被传递给 JavaScript 的 `WebSocket` 对象的 `onmessage` 事件处理函数。**

**作为调试线索:**

* **网络面板 (Chrome DevTools):** 当 WebSocket 连接出现问题时，开发者可以使用 Chrome 开发者工具的 "网络" 面板，并筛选 "WS" (WebSocket) 连接，查看浏览器发送和接收的原始 WebSocket 帧数据。这可以帮助判断是客户端发送的帧有问题，还是服务端发送的帧有问题。
* **断点调试:**  如果怀疑 `WebSocketFrameParser` 存在解析错误，开发者可以将 Chromium 代码拉取到本地，设置断点在 `WebSocketFrameParser::Decode` 方法中，逐步跟踪代码的执行流程，查看解析过程中的变量值，从而定位问题。
* **日志输出:**  在 Chromium 的开发版本中，可能会有相关的日志输出，记录 WebSocket 帧的解析过程。通过查看这些日志，可以了解 `WebSocketFrameParser` 的工作状态。

总而言之，`net/websockets/websocket_frame_parser_test.cc` 通过各种测试用例，确保了 `WebSocketFrameParser` 类的健壮性和正确性，这对于保证浏览器能够可靠地处理 WebSocket 通信至关重要。虽然普通用户和 JavaScript 开发者不直接使用这个类，但它是 WebSocket 功能正常运行的基础。

Prompt: 
```
这是目录为net/websockets/websocket_frame_parser_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/websockets/websocket_frame_parser.h"

#include <stdint.h>

#include <algorithm>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "base/containers/span.h"
#include "base/containers/to_vector.h"
#include "net/websockets/websocket_frame.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

constexpr char kHello[] = "Hello, world!";
constexpr uint64_t kHelloLength = std::size(kHello) - 1;
constexpr char kHelloFrame[] = "\x81\x0DHello, world!";
constexpr char kMaskedHelloFrame[] =
    "\x81\x8D\xDE\xAD\xBE\xEF"
    "\x96\xC8\xD2\x83\xB1\x81\x9E\x98\xB1\xDF\xD2\x8B\xFF";

std::vector<uint8_t> ConvertToUint8Vector(std::string_view input) {
  return base::ToVector(input, [](char c) { return static_cast<uint8_t>(c); });
}

struct FrameHeaderTestCase {
  const std::string_view frame_header;
  uint64_t frame_length;
  WebSocketError error_code;
};

constexpr FrameHeaderTestCase kFrameHeaderTests[] = {
    {{"\x81\x00", 2}, UINT64_C(0), kWebSocketNormalClosure},
    {{"\x81\x7D", 2}, UINT64_C(125), kWebSocketNormalClosure},
    {{"\x81\x7E\x00\x7E", 4}, UINT64_C(126), kWebSocketNormalClosure},
    {{"\x81\x7E\xFF\xFF", 4}, UINT64_C(0xFFFF), kWebSocketNormalClosure},
    {{"\x81\x7F\x00\x00\x00\x00\x00\x01\x00\x00", 10},
     UINT64_C(0x10000),
     kWebSocketNormalClosure},
    {{"\x81\x7F\x00\x00\x00\x00\x7F\xFF\xFF\xFF", 10},
     UINT64_C(0x7FFFFFFF),
     kWebSocketNormalClosure},
    {{"\x81\x7F\x00\x00\x00\x00\x80\x00\x00\x00", 10},
     UINT64_C(0x80000000),
     kWebSocketErrorMessageTooBig},
    {{"\x81\x7F\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 10},
     UINT64_C(0x7FFFFFFFFFFFFFFF),
     kWebSocketErrorMessageTooBig}};
constexpr int kNumFrameHeaderTests = std::size(kFrameHeaderTests);

TEST(WebSocketFrameParserTest, DecodeNormalFrame) {
  WebSocketFrameParser parser;

  std::vector<std::unique_ptr<WebSocketFrameChunk>> frames;

  auto frame_data = ConvertToUint8Vector(kHelloFrame);
  EXPECT_TRUE(parser.Decode(frame_data, &frames));
  EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
  ASSERT_EQ(1u, frames.size());
  WebSocketFrameChunk* frame = frames[0].get();
  ASSERT_TRUE(frame != nullptr);
  const WebSocketFrameHeader* header = frame->header.get();
  EXPECT_TRUE(header != nullptr);
  if (header) {
    EXPECT_TRUE(header->final);
    EXPECT_FALSE(header->reserved1);
    EXPECT_FALSE(header->reserved2);
    EXPECT_FALSE(header->reserved3);
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, header->opcode);
    EXPECT_FALSE(header->masked);
    EXPECT_EQ(kHelloLength, header->payload_length);
  }
  EXPECT_TRUE(frame->final_chunk);

  ASSERT_EQ(static_cast<size_t>(kHelloLength), frame->payload.size());
  EXPECT_TRUE(std::equal(kHello, kHello + kHelloLength, frame->payload.data()));
}

TEST(WebSocketFrameParserTest, DecodeMaskedFrame) {
  WebSocketFrameParser parser;

  std::vector<std::unique_ptr<WebSocketFrameChunk>> frames;

  auto frame_data = ConvertToUint8Vector(kMaskedHelloFrame);
  EXPECT_TRUE(parser.Decode(frame_data, &frames));
  EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
  ASSERT_EQ(1u, frames.size());
  WebSocketFrameChunk* frame = frames[0].get();
  ASSERT_TRUE(frame != nullptr);
  const WebSocketFrameHeader* header = frame->header.get();
  EXPECT_TRUE(header != nullptr);
  if (header) {
    EXPECT_TRUE(header->final);
    EXPECT_FALSE(header->reserved1);
    EXPECT_FALSE(header->reserved2);
    EXPECT_FALSE(header->reserved3);
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, header->opcode);
    EXPECT_TRUE(header->masked);
    EXPECT_EQ(kHelloLength, header->payload_length);
  }
  EXPECT_TRUE(frame->final_chunk);

  ASSERT_EQ(static_cast<size_t>(kHelloLength), frame->payload.size());

  std::string payload(frame->payload.data(), frame->payload.size());
  MaskWebSocketFramePayload(header->masking_key, 0,
                            base::as_writable_byte_span(payload));
  EXPECT_EQ(payload, kHello);
}

TEST(WebSocketFrameParserTest, DecodeManyFrames) {
  struct Input {
    const char* frame;
    size_t frame_length;
    const char* expected_payload;
    size_t expected_payload_length;
  };
  static constexpr Input kInputs[] = {
      // Each |frame| data is split into two string literals because C++ lexers
      // consume unlimited number of hex characters in a hex character escape
      // (e.g. "\x05F" is not treated as { '\x5', 'F', '\0' } but as
      // { '\x5F', '\0' }).
      {"\x81\x05"
       "First",
       7, "First", 5},
      {"\x81\x06"
       "Second",
       8, "Second", 6},
      {"\x81\x05"
       "Third",
       7, "Third", 5},
      {"\x81\x06"
       "Fourth",
       8, "Fourth", 6},
      {"\x81\x05"
       "Fifth",
       7, "Fifth", 5},
      {"\x81\x05"
       "Sixth",
       7, "Sixth", 5},
      {"\x81\x07"
       "Seventh",
       9, "Seventh", 7},
      {"\x81\x06"
       "Eighth",
       8, "Eighth", 6},
      {"\x81\x05"
       "Ninth",
       7, "Ninth", 5},
      {"\x81\x05"
       "Tenth",
       7, "Tenth", 5}};
  static constexpr int kNumInputs = std::size(kInputs);

  std::vector<uint8_t> input;
  // Concatenate all frames.
  for (const auto& data : kInputs) {
    input.insert(input.end(), data.frame, data.frame + data.frame_length);
  }

  WebSocketFrameParser parser;

  std::vector<std::unique_ptr<WebSocketFrameChunk>> frames;
  EXPECT_TRUE(parser.Decode(input, &frames));
  EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
  ASSERT_EQ(static_cast<size_t>(kNumInputs), frames.size());

  for (int i = 0; i < kNumInputs; ++i) {
    WebSocketFrameChunk* frame = frames[i].get();
    EXPECT_TRUE(frame != nullptr);
    if (!frame)
      continue;
    EXPECT_TRUE(frame->final_chunk);
    ASSERT_EQ(kInputs[i].expected_payload_length,
              static_cast<uint64_t>(frame->payload.size()));
    EXPECT_TRUE(std::equal(
        kInputs[i].expected_payload,
        kInputs[i].expected_payload + kInputs[i].expected_payload_length,
        frame->payload.data()));

    const WebSocketFrameHeader* header = frame->header.get();
    EXPECT_TRUE(header != nullptr);
    if (!header)
      continue;
    EXPECT_TRUE(header->final);
    EXPECT_FALSE(header->reserved1);
    EXPECT_FALSE(header->reserved2);
    EXPECT_FALSE(header->reserved3);
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, header->opcode);
    EXPECT_FALSE(header->masked);
    EXPECT_EQ(kInputs[i].expected_payload_length, header->payload_length);
  }
}

TEST(WebSocketFrameParserTest, DecodePartialFrame) {
  static constexpr size_t kFrameHeaderSize = 2;

  std::vector<uint8_t> hello_frame_data = ConvertToUint8Vector(kHelloFrame);

  for (size_t cutting_pos = 0; cutting_pos < kHelloLength; ++cutting_pos) {
    auto [input1, input2] =
        base::span(hello_frame_data).split_at(kFrameHeaderSize + cutting_pos);

    std::vector<char> expected1(kHello, kHello + cutting_pos);
    std::vector<char> expected2(kHello + cutting_pos, kHello + kHelloLength);

    WebSocketFrameParser parser;

    std::vector<std::unique_ptr<WebSocketFrameChunk>> frames1;
    EXPECT_TRUE(parser.Decode(input1, &frames1));
    EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
    EXPECT_EQ(1u, frames1.size());
    if (frames1.size() != 1u)
      continue;
    WebSocketFrameChunk* frame1 = frames1[0].get();
    EXPECT_TRUE(frame1 != nullptr);
    if (!frame1)
      continue;
    EXPECT_FALSE(frame1->final_chunk);
    if (expected1.size() == 0) {
      EXPECT_EQ(nullptr, frame1->payload.data());
    } else {
      ASSERT_EQ(cutting_pos, static_cast<size_t>(frame1->payload.size()));
      EXPECT_TRUE(std::equal(expected1.begin(), expected1.end(),
                             frame1->payload.data()));
    }
    const WebSocketFrameHeader* header1 = frame1->header.get();
    EXPECT_TRUE(header1 != nullptr);
    if (!header1)
      continue;
    EXPECT_TRUE(header1->final);
    EXPECT_FALSE(header1->reserved1);
    EXPECT_FALSE(header1->reserved2);
    EXPECT_FALSE(header1->reserved3);
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, header1->opcode);
    EXPECT_FALSE(header1->masked);
    EXPECT_EQ(kHelloLength, header1->payload_length);

    std::vector<std::unique_ptr<WebSocketFrameChunk>> frames2;
    EXPECT_TRUE(parser.Decode(input2, &frames2));
    EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
    EXPECT_EQ(1u, frames2.size());
    if (frames2.size() != 1u)
      continue;
    WebSocketFrameChunk* frame2 = frames2[0].get();
    EXPECT_TRUE(frame2 != nullptr);
    if (!frame2)
      continue;
    EXPECT_TRUE(frame2->final_chunk);
    if (expected2.size() == 0) {
      EXPECT_EQ(nullptr, frame2->payload.data());
    } else {
      ASSERT_EQ(expected2.size(),
                static_cast<uint64_t>(frame2->payload.size()));
      EXPECT_TRUE(std::equal(expected2.begin(), expected2.end(),
                             frame2->payload.data()));
    }
    const WebSocketFrameHeader* header2 = frame2->header.get();
    EXPECT_TRUE(header2 == nullptr);
  }
}

TEST(WebSocketFrameParserTest, DecodePartialMaskedFrame) {
  static constexpr size_t kFrameHeaderSize = 6;

  std::vector<uint8_t> masked_hello_frame_data =
      ConvertToUint8Vector(kMaskedHelloFrame);

  for (size_t cutting_pos = 0; cutting_pos < kHelloLength; ++cutting_pos) {
    auto [input1, input2] = base::span(masked_hello_frame_data)
                                .split_at(kFrameHeaderSize + cutting_pos);

    std::vector<char> expected1(kHello, kHello + cutting_pos);
    std::vector<char> expected2(kHello + cutting_pos, kHello + kHelloLength);

    WebSocketFrameParser parser;

    std::vector<std::unique_ptr<WebSocketFrameChunk>> frames1;
    EXPECT_TRUE(parser.Decode(input1, &frames1));
    EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
    EXPECT_EQ(1u, frames1.size());
    if (frames1.size() != 1u)
      continue;
    WebSocketFrameChunk* frame1 = frames1[0].get();
    EXPECT_TRUE(frame1 != nullptr);
    if (!frame1)
      continue;
    EXPECT_FALSE(frame1->final_chunk);
    const WebSocketFrameHeader* header1 = frame1->header.get();
    EXPECT_TRUE(header1 != nullptr);
    if (!header1)
      continue;
    if (expected1.size() == 0) {
      EXPECT_EQ(nullptr, frame1->payload.data());
    } else {
      ASSERT_EQ(expected1.size(),
                static_cast<uint64_t>(frame1->payload.size()));
      std::vector<char> payload1(
          frame1->payload.data(),
          frame1->payload.data() + frame1->payload.size());
      MaskWebSocketFramePayload(header1->masking_key, 0,
                                base::as_writable_byte_span(payload1));
      EXPECT_EQ(expected1, payload1);
    }
    EXPECT_TRUE(header1->final);
    EXPECT_FALSE(header1->reserved1);
    EXPECT_FALSE(header1->reserved2);
    EXPECT_FALSE(header1->reserved3);
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, header1->opcode);
    EXPECT_TRUE(header1->masked);
    EXPECT_EQ(kHelloLength, header1->payload_length);

    std::vector<std::unique_ptr<WebSocketFrameChunk>> frames2;
    EXPECT_TRUE(parser.Decode(input2, &frames2));
    EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
    EXPECT_EQ(1u, frames2.size());
    if (frames2.size() != 1u)
      continue;
    WebSocketFrameChunk* frame2 = frames2[0].get();
    EXPECT_TRUE(frame2 != nullptr);
    if (!frame2)
      continue;
    EXPECT_TRUE(frame2->final_chunk);
    if (expected2.size() == 0) {
      EXPECT_EQ(nullptr, frame2->payload.data());
    } else {
      ASSERT_EQ(expected2.size(),
                static_cast<uint64_t>(frame2->payload.size()));
      std::vector<char> payload2(
          frame2->payload.data(),
          frame2->payload.data() + frame2->payload.size());
      MaskWebSocketFramePayload(header1->masking_key, cutting_pos,
                                base::as_writable_byte_span(payload2));
      EXPECT_EQ(expected2, payload2);
    }
    const WebSocketFrameHeader* header2 = frame2->header.get();
    EXPECT_TRUE(header2 == nullptr);
  }
}

TEST(WebSocketFrameParserTest, DecodeFramesOfVariousLengths) {
  for (const auto& test : kFrameHeaderTests) {
    auto frame_header = ConvertToUint8Vector(test.frame_header);
    uint64_t frame_length = test.frame_length;

    std::vector<uint8_t> input(frame_header);
    static constexpr uint64_t kMaxPayloadSize = 200;
    uint64_t input_payload_size = std::min(frame_length, kMaxPayloadSize);
    input.insert(input.end(), input_payload_size, 'a');

    WebSocketFrameParser parser;

    std::vector<std::unique_ptr<WebSocketFrameChunk>> frames;
    EXPECT_EQ(test.error_code == kWebSocketNormalClosure,
              parser.Decode(input, &frames));
    EXPECT_EQ(test.error_code, parser.websocket_error());
    if (test.error_code != kWebSocketNormalClosure) {
      EXPECT_EQ(0u, frames.size());
    } else {
      EXPECT_EQ(1u, frames.size());
    }
    if (frames.size() != 1u)
      continue;
    WebSocketFrameChunk* frame = frames[0].get();
    EXPECT_TRUE(frame != nullptr);
    if (!frame)
      continue;
    if (frame_length == input_payload_size) {
      EXPECT_TRUE(frame->final_chunk);
    } else {
      EXPECT_FALSE(frame->final_chunk);
    }
    std::vector<char> expected_payload(input_payload_size, 'a');
    if (expected_payload.size() == 0) {
      EXPECT_EQ(nullptr, frame->payload.data());
    } else {
      ASSERT_EQ(expected_payload.size(),
                static_cast<uint64_t>(frame->payload.size()));
      EXPECT_TRUE(std::equal(expected_payload.begin(), expected_payload.end(),
                             frame->payload.data()));
    }
    const WebSocketFrameHeader* header = frame->header.get();
    EXPECT_TRUE(header != nullptr);
    if (!header)
      continue;
    EXPECT_TRUE(header->final);
    EXPECT_FALSE(header->reserved1);
    EXPECT_FALSE(header->reserved2);
    EXPECT_FALSE(header->reserved3);
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, header->opcode);
    EXPECT_FALSE(header->masked);
    EXPECT_EQ(frame_length, header->payload_length);
  }
}

TEST(WebSocketFrameParserTest, DecodePartialHeader) {
  for (int i = 0; i < kNumFrameHeaderTests; ++i) {
    auto frame_header = ConvertToUint8Vector(kFrameHeaderTests[i].frame_header);
    size_t frame_header_length = frame_header.size();
    uint64_t frame_length = kFrameHeaderTests[i].frame_length;

    WebSocketFrameParser parser;

    std::vector<std::unique_ptr<WebSocketFrameChunk>> frames;
    // Feed each byte to the parser to see if the parser behaves correctly
    // when it receives partial frame header.
    size_t last_byte_offset = frame_header_length - 1;
    for (size_t j = 0; j < frame_header_length; ++j) {
      bool failed =
          kFrameHeaderTests[i].error_code != kWebSocketNormalClosure &&
          j == last_byte_offset;
      EXPECT_EQ(!failed, parser.Decode(base::span(frame_header).subspan(j, 1u),
                                       &frames));
      if (failed) {
        EXPECT_EQ(kFrameHeaderTests[i].error_code, parser.websocket_error());
      } else {
        EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
      }
      if (kFrameHeaderTests[i].error_code == kWebSocketNormalClosure &&
          j == last_byte_offset) {
        EXPECT_EQ(1u, frames.size()) << "i=" << i << ", j=" << j;
      } else {
        EXPECT_EQ(0u, frames.size()) << "i=" << i << ", j=" << j;
      }
    }
    if (frames.size() != 1u)
      continue;
    WebSocketFrameChunk* frame = frames[0].get();
    EXPECT_TRUE(frame != nullptr);
    if (!frame)
      continue;
    if (frame_length == 0u) {
      EXPECT_TRUE(frame->final_chunk);
    } else {
      EXPECT_FALSE(frame->final_chunk);
    }
    EXPECT_EQ(nullptr, frame->payload.data());
    const WebSocketFrameHeader* header = frame->header.get();
    EXPECT_TRUE(header != nullptr);
    if (!header)
      continue;
    EXPECT_TRUE(header->final);
    EXPECT_FALSE(header->reserved1);
    EXPECT_FALSE(header->reserved2);
    EXPECT_FALSE(header->reserved3);
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, header->opcode);
    EXPECT_FALSE(header->masked);
    EXPECT_EQ(frame_length, header->payload_length);
  }
}

TEST(WebSocketFrameParserTest, InvalidLengthEncoding) {
  struct TestCase {
    const std::string_view frame_header;
  };
  static constexpr TestCase kTests[] = {
      // For frames with two-byte extended length field, the payload length
      // should be 126 (0x7E) bytes or more.
      {{"\x81\x7E\x00\x00", 4}},
      {{"\x81\x7E\x00\x7D", 4}},
      // For frames with eight-byte extended length field, the payload length
      // should be 0x10000 bytes or more.
      {{"\x81\x7F\x00\x00\x00\x00\x00\x00\x00\x00", 10}},
      {{"\x81\x7E\x00\x00\x00\x00\x00\x00\xFF\xFF", 10}},
  };

  for (const auto& test : kTests) {
    auto frame_header = ConvertToUint8Vector(test.frame_header);

    WebSocketFrameParser parser;

    std::vector<std::unique_ptr<WebSocketFrameChunk>> frames;
    EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
    EXPECT_FALSE(parser.Decode(frame_header, &frames));
    EXPECT_EQ(kWebSocketErrorProtocolError, parser.websocket_error());
    EXPECT_EQ(0u, frames.size());

    std::vector<uint8_t> empty_frame_data;
    EXPECT_FALSE(parser.Decode(empty_frame_data, &frames));
    EXPECT_EQ(kWebSocketErrorProtocolError, parser.websocket_error());
    EXPECT_EQ(0u, frames.size());
  }
}

TEST(WebSocketFrameParserTest, FrameTypes) {
  struct TestCase {
    const std::string_view frame_header;
    WebSocketFrameHeader::OpCode opcode;
  };
  static constexpr TestCase kTests[] = {
      {{"\x80\x00", 2}, WebSocketFrameHeader::kOpCodeContinuation},
      {{"\x81\x00", 2}, WebSocketFrameHeader::kOpCodeText},
      {{"\x82\x00", 2}, WebSocketFrameHeader::kOpCodeBinary},
      {{"\x83\x00", 2}, WebSocketFrameHeader::kOpCodeDataUnused3},
      {{"\x84\x00", 2}, WebSocketFrameHeader::kOpCodeDataUnused4},
      {{"\x85\x00", 2}, WebSocketFrameHeader::kOpCodeDataUnused5},
      {{"\x86\x00", 2}, WebSocketFrameHeader::kOpCodeDataUnused6},
      {{"\x87\x00", 2}, WebSocketFrameHeader::kOpCodeDataUnused7},
      {{"\x88\x00", 2}, WebSocketFrameHeader::kOpCodeClose},
      {{"\x89\x00", 2}, WebSocketFrameHeader::kOpCodePing},
      {{"\x8A\x00", 2}, WebSocketFrameHeader::kOpCodePong},
      {{"\x8B\x00", 2}, WebSocketFrameHeader::kOpCodeControlUnusedB},
      {{"\x8C\x00", 2}, WebSocketFrameHeader::kOpCodeControlUnusedC},
      {{"\x8D\x00", 2}, WebSocketFrameHeader::kOpCodeControlUnusedD},
      {{"\x8E\x00", 2}, WebSocketFrameHeader::kOpCodeControlUnusedE},
      {{"\x8F\x00", 2}, WebSocketFrameHeader::kOpCodeControlUnusedF},
  };

  for (const auto& test : kTests) {
    auto frame_header = ConvertToUint8Vector(test.frame_header);

    WebSocketFrameHeader::OpCode opcode = test.opcode;

    WebSocketFrameParser parser;

    std::vector<std::unique_ptr<WebSocketFrameChunk>> frames;
    EXPECT_TRUE(parser.Decode(frame_header, &frames));
    EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
    EXPECT_EQ(1u, frames.size());
    if (frames.size() != 1u)
      continue;
    WebSocketFrameChunk* frame = frames[0].get();
    EXPECT_TRUE(frame != nullptr);
    if (!frame)
      continue;
    EXPECT_TRUE(frame->final_chunk);
    EXPECT_EQ(nullptr, frame->payload.data());
    const WebSocketFrameHeader* header = frame->header.get();
    EXPECT_TRUE(header != nullptr);
    if (!header)
      continue;
    EXPECT_TRUE(header->final);
    EXPECT_FALSE(header->reserved1);
    EXPECT_FALSE(header->reserved2);
    EXPECT_FALSE(header->reserved3);
    EXPECT_EQ(opcode, header->opcode);
    EXPECT_FALSE(header->masked);
    EXPECT_EQ(0u, header->payload_length);
  }
}

TEST(WebSocketFrameParserTest, FinalBitAndReservedBits) {
  struct TestCase {
    const std::string_view frame_header;
    bool final;
    bool reserved1;
    bool reserved2;
    bool reserved3;
  };
  static constexpr TestCase kTests[] = {
      {{"\x81\x00", 2}, true, false, false, false},
      {{"\x01\x00", 2}, false, false, false, false},
      {{"\xC1\x00", 2}, true, true, false, false},
      {{"\xA1\x00", 2}, true, false, true, false},
      {{"\x91\x00", 2}, true, false, false, true},
      {{"\x71\x00", 2}, false, true, true, true},
      {{"\xF1\x00", 2}, true, true, true, true}};

  for (const auto& test : kTests) {
    auto frame_header = ConvertToUint8Vector(test.frame_header);

    bool final = test.final;
    bool reserved1 = test.reserved1;
    bool reserved2 = test.reserved2;
    bool reserved3 = test.reserved3;

    WebSocketFrameParser parser;

    std::vector<std::unique_ptr<WebSocketFrameChunk>> frames;
    EXPECT_TRUE(parser.Decode(frame_header, &frames));
    EXPECT_EQ(kWebSocketNormalClosure, parser.websocket_error());
    EXPECT_EQ(1u, frames.size());
    if (frames.size() != 1u)
      continue;
    WebSocketFrameChunk* frame = frames[0].get();
    EXPECT_TRUE(frame != nullptr);
    if (!frame)
      continue;
    EXPECT_TRUE(frame->final_chunk);
    EXPECT_EQ(nullptr, frame->payload.data());
    const WebSocketFrameHeader* header = frame->header.get();
    EXPECT_TRUE(header != nullptr);
    if (!header)
      continue;
    EXPECT_EQ(final, header->final);
    EXPECT_EQ(reserved1, header->reserved1);
    EXPECT_EQ(reserved2, header->reserved2);
    EXPECT_EQ(reserved3, header->reserved3);
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, header->opcode);
    EXPECT_FALSE(header->masked);
    EXPECT_EQ(0u, header->payload_length);
  }
}

}  // Unnamed namespace

}  // namespace net

"""

```
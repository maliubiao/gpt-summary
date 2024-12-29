Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Core Request:**

The user wants to know the functionality of `net/server/web_socket_encoder.cc` in Chromium's network stack. They're particularly interested in its relationship to JavaScript, any logical inferences possible, common usage errors, and how a user action might lead to this code being executed (debugging context).

**2. Initial Code Scan and Keyword Spotting:**

I'd quickly scan the code for keywords and structure to get a high-level understanding. I'd look for:

* **Namespaces:** `net` confirms it's related to networking.
* **Class Name:** `WebSocketEncoder` is the central focus.
* **Includes:**  `net/websockets/*`, `net/base/*`, `base/*` suggest network functionality, WebSocket specifics, and general Chromium utilities. The `#ifdef UNSAFE_BUFFERS_BUILD` is a compiler flag worth noting but probably not central to the core functionality.
* **Constants:**  `kClientExtensions`, `kInflaterChunkSize`, `kFinalBit`, etc. These define important parameters and flags related to the WebSocket protocol.
* **Functions:**  `CreateServer`, `CreateClient`, `DecodeFrame`, `EncodeTextFrame`, `EncodeCloseFrame`, `EncodePongFrame`, `Inflate`, `Deflate`. These are the main operations the class performs.
* **Data Members:** `type_`, `deflater_`, `inflater_`. These represent the state of the encoder. The presence of `deflater_` and `inflater_` strongly suggests compression/decompression capabilities.
* **`NET_EXPORT`:** Indicates this class is part of the public API of the `net` library.

**3. Identifying Core Functionality:**

Based on the keywords and function names, the core functionality becomes clear:

* **Encoding and Decoding WebSocket Frames:**  The `Encode*Frame` and `DecodeFrame` functions are the primary interface for converting data to and from WebSocket frame format.
* **Handling Compression (permessage-deflate):** The presence of `WebSocketDeflater` and `WebSocketInflater`, along with the logic in `CreateServer` and `CreateClient` that parses extensions and initializes these objects, points to support for the `permessage-deflate` extension.
* **Server and Client Roles:** The `CreateServer` and `CreateClient` static methods clearly distinguish between the encoder's usage on the server and client side.
* **Hybi-17 Protocol:** The function names `DecodeFrameHybi17` and `EncodeFrameHybi17` explicitly indicate the supported WebSocket protocol version.

**4. Addressing Specific User Questions:**

* **Functionality:** I would summarize the core functionalities identified above.
* **Relationship to JavaScript:** This requires understanding how WebSockets work in a browser. JavaScript uses the `WebSocket` API to establish connections and send/receive data. The `WebSocketEncoder` is *behind the scenes* in the browser's network stack, handling the low-level details of formatting and parsing the data. I'd provide an example of a simple JavaScript `WebSocket` send and explain how the C++ encoder comes into play.
* **Logical Inference (Input/Output):** I'd focus on the key encoding and decoding functions. For encoding, an uncompressed text message would be the input, and a properly formatted WebSocket frame (with headers, masking if client-side, etc.) would be the output. For decoding, a raw WebSocket frame would be the input, and the unmasked, potentially decompressed payload would be the output. I'd give a simple example to illustrate this.
* **Common Usage Errors:** These errors are typically related to protocol violations. I'd look for checks within the code that indicate potential problems: incorrect masking, unsupported opcodes, invalid frame formats, issues with extensions. I'd provide examples based on these checks.
* **User Operation as Debugging Clue:** This requires thinking about the user's perspective. What actions would trigger a WebSocket communication? Opening a web page that uses WebSockets, interacting with a web application that relies on WebSockets (e.g., chat, online games). I'd then explain how these actions lead to the JavaScript `WebSocket` API being used and how the browser's network stack (including this encoder) handles the actual communication.

**5. Structuring the Answer:**

I'd organize the answer logically, addressing each of the user's questions clearly and providing concrete examples where possible. I'd start with a general overview of the encoder's function and then delve into the specifics. Using headings and bullet points helps with readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the bitwise operations in the `DecodeFrameHybi17` and `EncodeFrameHybi17` functions.
* **Correction:** While important for understanding the protocol details, for the user's high-level understanding, it's better to focus on *what* these functions do (encode/decode) rather than *how* they do it at the bit level, unless specifically asked.
* **Initial thought:**  Only focus on the `permessage-deflate` extension.
* **Correction:**  Mention that the encoder *can* work without compression as well, and explain how that's handled in the code.
* **Initial thought:**  Assume the user is a seasoned C++ developer.
* **Correction:**  Explain concepts in a way that is understandable to someone with a general understanding of web technologies and programming, not necessarily low-level networking. Explain the JavaScript connection clearly.

By following this structured thought process, analyzing the code, and considering the user's specific questions, I can generate a comprehensive and helpful answer like the example provided in the prompt.
这个文件 `net/server/web_socket_encoder.cc` 是 Chromium 网络栈中用于 **编码和解码 WebSocket 帧** 的关键组件。它负责将要发送的 WebSocket 消息转换成符合 WebSocket 协议规范的二进制帧，以及将接收到的二进制帧解析成可用的消息。

以下是它的主要功能：

**1. WebSocket 帧的编码 (Encoding):**

* **将消息数据封装成 WebSocket 帧:**  它接收应用程序要发送的消息数据（文本或二进制），并根据 WebSocket 协议（主要是 Hybi-17）将其封装成二进制帧。这包括添加帧头信息，如：
    * **Fin 位:** 指示是否是消息的最后一个分片。
    * **RSV1, RSV2, RSV3 位:** 用于扩展，例如用于压缩。
    * **Opcode:**  指示帧的类型（文本、二进制、关闭连接、Ping、Pong 等）。
    * **Mask 位:**  指示有效载荷是否被掩码（客户端发送的帧必须被掩码）。
    * **有效载荷长度:**  指示有效载荷的长度。
    * **掩码密钥 (Masking Key):** 如果 Mask 位被设置，则包含用于掩码有效载荷的 4 字节密钥。
    * **有效载荷数据 (Payload Data):** 实际的消息内容。
* **处理消息分片 (Fragmentation):** 如果消息太大，它可以将其分成多个帧进行发送。
* **支持 permessage-deflate 压缩扩展:** 如果 WebSocket 连接协商了 `permessage-deflate` 扩展，它可以对消息数据进行压缩后再进行帧封装。
* **根据客户端或服务器角色进行不同的编码:**  客户端发送的帧需要进行掩码，而服务器发送的帧则不需要。

**2. WebSocket 帧的解码 (Decoding):**

* **解析接收到的二进制帧:** 它接收从网络接收到的二进制数据，并解析出其中的 WebSocket 帧结构。这包括提取帧头信息和有效载荷数据。
* **校验帧的有效性:** 它会检查接收到的帧是否符合 WebSocket 协议规范，例如检查 Mask 位是否符合客户端/服务器角色，以及一些保留位是否被正确设置。
* **处理消息分片重组 (Defragmentation):** 如果接收到的消息被分片发送，它会将多个分片帧的数据组合成完整的消息。
* **支持 permessage-deflate 解压缩:** 如果帧被标记为压缩，它会对有效载荷数据进行解压缩。
* **区分不同类型的帧:** 它能够识别不同类型的帧，例如文本帧、二进制帧、关闭帧、Ping 帧和 Pong 帧。

**与 JavaScript 功能的关系及举例说明:**

`net/server/web_socket_encoder.cc` 的功能与 JavaScript 的 `WebSocket` API 密切相关。当 JavaScript 代码在浏览器中创建一个 `WebSocket` 对象并发送数据时，浏览器底层的网络栈会使用 `WebSocketEncoder` 将 JavaScript 提供的字符串或二进制数据编码成符合 WebSocket 协议的帧，并通过网络发送出去。

**举例说明:**

假设 JavaScript 代码如下：

```javascript
const ws = new WebSocket('ws://example.com/socket');

ws.onopen = () => {
  ws.send('Hello, WebSocket!');
};
```

当 `ws.send('Hello, WebSocket!')` 被调用时，浏览器内部会进行以下操作，其中涉及到 `WebSocketEncoder`：

1. JavaScript 引擎将字符串 `'Hello, WebSocket!'` 传递给浏览器的网络组件。
2. 网络组件根据当前 WebSocket 连接的状态和协商的扩展，调用 `WebSocketEncoder` 的 `EncodeTextFrame` 方法。
3. `EncodeTextFrame` 方法将字符串 `'Hello, WebSocket!'` 封装成一个 WebSocket 文本帧。如果启用了 `permessage-deflate` 扩展，可能会先进行压缩。帧头会包含 Opcode 指示这是一个文本帧，并根据客户端的角色设置 Mask 位和生成 Masking Key。
4. 编码后的二进制帧数据通过网络发送到服务器。

反过来，当服务器发送 WebSocket 帧到浏览器时，浏览器接收到数据后，会使用 `WebSocketEncoder` 的 `DecodeFrame` 方法进行解析，将接收到的二进制帧解码成 JavaScript 可以处理的字符串或二进制数据，并通过 `ws.onmessage` 事件传递给 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

**假设输入（编码 - 客户端发送文本消息）：**

* `message`: "This is a test message."
* `masking_key`: 一个随机的 32 位整数，例如 `1234567890`.
* `compressed`: `false` (假设未启用压缩)
* `op_code`: `WebSocketFrameHeader::OpCodeEnum::kOpCodeText`

**输出（编码）：**

一个二进制字符串，表示编码后的 WebSocket 帧，结构可能如下 (简化表示，实际是二进制)：

```
[Fin=1, RSV1=0, RSV2=0, RSV3=0, Opcode=0x1 (Text)]
[Mask=1, Payload Length=26 (单字节表示)]
[Masking Key: 0x499602d2 (1234567890 的十六进制)]
[Masked Payload: (每个字节与 Masking Key 对应字节异或)]
```

**假设输入（解码 - 服务器发送文本消息）：**

一个接收到的二进制 WebSocket 帧，例如：

```
\x81\x1aThis is a test message from server.
```

（假设未压缩，未掩码，0x81 表示 Fin=1, Opcode=0x1，0x1a 表示 Payload Length=26）

**输出（解码）：**

* `bytes_consumed`: 帧的长度，这里是 28 字节。
* `output`: "This is a test message from server."
* `compressed`: `false`

**涉及用户或编程常见的使用错误及举例说明:**

1. **客户端忘记掩码 (仅限客户端):**  WebSocket 协议要求客户端发送的帧必须进行掩码。如果客户端代码（或者底层的实现有问题）发送未掩码的帧，`WebSocketEncoder` 在解码时会返回 `WebSocketParseResult::FRAME_ERROR`。

   **用户操作:** 用户可能使用了错误的 WebSocket 客户端库，或者自己实现了 WebSocket 客户端但没有遵循协议规范。

   **调试线索:** 在服务器端，会收到一个格式错误的帧，`DecodeFrameHybi17` 函数会检查 `masked` 标志，如果客户端帧的 `masked` 为 false，则会返回错误。

2. **发送无效的 Opcode:** 用户或程序尝试发送一个 WebSocket 协议中未定义的 Opcode。

   **用户操作/编程错误:** 错误的逻辑导致发送了错误的 Opcode 值。

   **调试线索:**  `DecodeFrameHybi17` 函数的 `switch (op_code)` 语句会检测到未知的 Opcode 并返回 `WebSocketParseResult::FRAME_ERROR`。

3. **处理压缩协商不一致:**  客户端和服务器对于是否启用 `permessage-deflate` 扩展的理解不一致，导致一方认为数据被压缩了，而另一方认为没有。

   **用户操作/编程错误:**  服务器或客户端的扩展协商逻辑存在错误。

   **调试线索:** 如果服务器认为发送了压缩数据，但客户端的 `WebSocketEncoder` 没有配置解压缩器，或者解压缩失败，会导致解码后的消息乱码或出错。反之亦然。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

以下是一个用户操作导致 `net/server/web_socket_encoder.cc` 被使用的典型流程：

1. **用户在浏览器中打开一个网页，该网页使用了 WebSocket 技术。** 例如，一个在线聊天应用或者一个实时游戏。
2. **网页中的 JavaScript 代码创建一个 `WebSocket` 对象，并连接到服务器。** 这通常涉及到 `new WebSocket('ws://...')` 的调用。
3. **用户在网页上执行某些操作，导致 JavaScript 代码调用 `websocket.send(data)` 发送数据到服务器。**  例如，在聊天框中输入消息并发送。
4. **浏览器捕获到 `send()` 调用，并将数据传递给网络栈。**
5. **网络栈中的 WebSocket 实现组件开始处理发送请求。**
6. **`net/server/web_socket_encoder.cc` 中的 `EncodeTextFrame` 或 `EncodeBinaryFrame` 等函数被调用，将 JavaScript 传递的数据编码成符合 WebSocket 协议的二进制帧。**  这包括添加必要的帧头，进行掩码（如果是在客户端），并可能进行压缩。
7. **编码后的二进制帧数据被发送到服务器。**

**作为调试线索:**

当需要调试 WebSocket 通信问题时，例如消息发送失败、消息内容错误、连接不稳定等，可以关注以下几点：

* **在浏览器开发者工具的网络面板中查看 WebSocket 帧的详细信息。** 这可以显示发送和接收的原始帧数据，包括帧头信息，可以判断是否符合预期。
* **在 Chromium 源代码中设置断点到 `net/server/web_socket_encoder.cc` 的编码和解码函数中。**  可以查看编码前后的数据，以及解码过程中提取的帧头信息，帮助理解数据是如何被处理的。
* **检查 WebSocket 连接的扩展协商结果。**  确认客户端和服务器是否都正确地启用了 `permessage-deflate` 或其他扩展。
* **对比客户端和服务器的 WebSocket 实现代码。**  确保双方都遵循了相同的 WebSocket 协议规范和扩展规范。

总而言之，`net/server/web_socket_encoder.cc` 是 Chromium 网络栈中处理 WebSocket 协议底层细节的关键部分，它负责将高级的消息数据转换成网络传输的二进制帧，并反之亦然，是实现 WebSocket 通信的基础。

Prompt: 
```
这是目录为net/server/web_socket_encoder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/server/web_socket_encoder.h"

#include <limits>
#include <string_view>
#include <utility>

#include "base/check.h"
#include "base/memory/ptr_util.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "net/base/io_buffer.h"
#include "net/base/net_export.h"
#include "net/websockets/websocket_deflate_parameters.h"
#include "net/websockets/websocket_extension.h"
#include "net/websockets/websocket_extension_parser.h"
#include "net/websockets/websocket_frame.h"

namespace net {

NET_EXPORT
const char WebSocketEncoder::kClientExtensions[] =
    "permessage-deflate; client_max_window_bits";

namespace {

const int kInflaterChunkSize = 16 * 1024;

// Constants for hybi-10 frame format.

const unsigned char kFinalBit = 0x80;
const unsigned char kReserved1Bit = 0x40;
const unsigned char kReserved2Bit = 0x20;
const unsigned char kReserved3Bit = 0x10;
const unsigned char kOpCodeMask = 0xF;
const unsigned char kMaskBit = 0x80;
const unsigned char kPayloadLengthMask = 0x7F;

const size_t kMaxSingleBytePayloadLength = 125;
const size_t kTwoBytePayloadLengthField = 126;
const size_t kEightBytePayloadLengthField = 127;
const size_t kMaskingKeyWidthInBytes = 4;

WebSocketParseResult DecodeFrameHybi17(std::string_view frame,
                                       bool client_frame,
                                       int* bytes_consumed,
                                       std::string* output,
                                       bool* compressed) {
  size_t data_length = frame.length();
  if (data_length < 2)
    return WebSocketParseResult::FRAME_INCOMPLETE;

  const char* buffer_begin = const_cast<char*>(frame.data());
  const char* p = buffer_begin;
  const char* buffer_end = p + data_length;

  unsigned char first_byte = *p++;
  unsigned char second_byte = *p++;

  bool final = (first_byte & kFinalBit) != 0;
  bool reserved1 = (first_byte & kReserved1Bit) != 0;
  bool reserved2 = (first_byte & kReserved2Bit) != 0;
  bool reserved3 = (first_byte & kReserved3Bit) != 0;
  int op_code = first_byte & kOpCodeMask;
  bool masked = (second_byte & kMaskBit) != 0;
  *compressed = reserved1;
  if (reserved2 || reserved3)
    return WebSocketParseResult::FRAME_ERROR;  // Only compression extension is
                                               // supported.

  bool closed = false;
  switch (op_code) {
    case WebSocketFrameHeader::OpCodeEnum::kOpCodeClose:
      closed = true;
      break;

    case WebSocketFrameHeader::OpCodeEnum::kOpCodeText:
    case WebSocketFrameHeader::OpCodeEnum::
        kOpCodeContinuation:  // Treated in the same as kOpCodeText.
    case WebSocketFrameHeader::OpCodeEnum::kOpCodePing:
    case WebSocketFrameHeader::OpCodeEnum::kOpCodePong:
      break;

    case WebSocketFrameHeader::OpCodeEnum::kOpCodeBinary:  // We don't support
                                                           // binary frames yet.
    default:
      return WebSocketParseResult::FRAME_ERROR;
  }

  if (client_frame && !masked)  // In Hybi-17 spec client MUST mask its frame.
    return WebSocketParseResult::FRAME_ERROR;

  uint64_t payload_length64 = second_byte & kPayloadLengthMask;
  if (payload_length64 > kMaxSingleBytePayloadLength) {
    int extended_payload_length_size;
    if (payload_length64 == kTwoBytePayloadLengthField) {
      extended_payload_length_size = 2;
    } else {
      DCHECK(payload_length64 == kEightBytePayloadLengthField);
      extended_payload_length_size = 8;
    }
    if (buffer_end - p < extended_payload_length_size)
      return WebSocketParseResult::FRAME_INCOMPLETE;
    payload_length64 = 0;
    for (int i = 0; i < extended_payload_length_size; ++i) {
      payload_length64 <<= 8;
      payload_length64 |= static_cast<unsigned char>(*p++);
    }
  }

  size_t actual_masking_key_length = masked ? kMaskingKeyWidthInBytes : 0;
  static const uint64_t max_payload_length = 0x7FFFFFFFFFFFFFFFull;
  static size_t max_length = std::numeric_limits<size_t>::max();
  if (payload_length64 > max_payload_length ||
      payload_length64 + actual_masking_key_length > max_length) {
    // WebSocket frame length too large.
    return WebSocketParseResult::FRAME_ERROR;
  }
  size_t payload_length = static_cast<size_t>(payload_length64);

  size_t total_length = actual_masking_key_length + payload_length;
  if (static_cast<size_t>(buffer_end - p) < total_length)
    return WebSocketParseResult::FRAME_INCOMPLETE;

  if (masked) {
    output->resize(payload_length);
    const char* masking_key = p;
    char* payload = const_cast<char*>(p + kMaskingKeyWidthInBytes);
    for (size_t i = 0; i < payload_length; ++i)  // Unmask the payload.
      (*output)[i] = payload[i] ^ masking_key[i % kMaskingKeyWidthInBytes];
  } else {
    output->assign(p, p + payload_length);
  }

  size_t pos = p + actual_masking_key_length + payload_length - buffer_begin;
  *bytes_consumed = pos;

  if (op_code == WebSocketFrameHeader::OpCodeEnum::kOpCodePing)
    return WebSocketParseResult::FRAME_PING;

  if (op_code == WebSocketFrameHeader::OpCodeEnum::kOpCodePong)
    return WebSocketParseResult::FRAME_PONG;

  if (closed)
    return WebSocketParseResult::FRAME_CLOSE;

  return final ? WebSocketParseResult::FRAME_OK_FINAL
               : WebSocketParseResult::FRAME_OK_MIDDLE;
}

void EncodeFrameHybi17(std::string_view message,
                       int masking_key,
                       bool compressed,
                       WebSocketFrameHeader::OpCodeEnum op_code,
                       std::string* output) {
  std::vector<char> frame;
  size_t data_length = message.length();

  int reserved1 = compressed ? kReserved1Bit : 0;
  frame.push_back(kFinalBit | op_code | reserved1);
  char mask_key_bit = masking_key != 0 ? kMaskBit : 0;
  if (data_length <= kMaxSingleBytePayloadLength) {
    frame.push_back(static_cast<char>(data_length) | mask_key_bit);
  } else if (data_length <= 0xFFFF) {
    frame.push_back(kTwoBytePayloadLengthField | mask_key_bit);
    frame.push_back((data_length & 0xFF00) >> 8);
    frame.push_back(data_length & 0xFF);
  } else {
    frame.push_back(kEightBytePayloadLengthField | mask_key_bit);
    char extended_payload_length[8];
    size_t remaining = data_length;
    // Fill the length into extended_payload_length in the network byte order.
    for (int i = 0; i < 8; ++i) {
      extended_payload_length[7 - i] = remaining & 0xFF;
      remaining >>= 8;
    }
    frame.insert(frame.end(), extended_payload_length,
                 extended_payload_length + 8);
    DCHECK(!remaining);
  }

  const char* data = const_cast<char*>(message.data());
  if (masking_key != 0) {
    const char* mask_bytes = reinterpret_cast<char*>(&masking_key);
    frame.insert(frame.end(), mask_bytes, mask_bytes + 4);
    for (size_t i = 0; i < data_length; ++i)  // Mask the payload.
      frame.push_back(data[i] ^ mask_bytes[i % kMaskingKeyWidthInBytes]);
  } else {
    frame.insert(frame.end(), data, data + data_length);
  }
  *output = std::string(frame.data(), frame.size());
}

}  // anonymous namespace

// static
std::unique_ptr<WebSocketEncoder> WebSocketEncoder::CreateServer() {
  return base::WrapUnique(new WebSocketEncoder(FOR_SERVER, nullptr, nullptr));
}

// static
std::unique_ptr<WebSocketEncoder> WebSocketEncoder::CreateServer(
    const std::string& extensions,
    WebSocketDeflateParameters* deflate_parameters) {
  WebSocketExtensionParser parser;
  if (!parser.Parse(extensions)) {
    // Failed to parse Sec-WebSocket-Extensions header. We MUST fail the
    // connection.
    return nullptr;
  }

  for (const auto& extension : parser.extensions()) {
    std::string failure_message;
    WebSocketDeflateParameters offer;
    if (!offer.Initialize(extension, &failure_message) ||
        !offer.IsValidAsRequest(&failure_message)) {
      // We decline unknown / malformed extensions.
      continue;
    }

    WebSocketDeflateParameters response = offer;
    if (offer.is_client_max_window_bits_specified() &&
        !offer.has_client_max_window_bits_value()) {
      // We need to choose one value for the response.
      response.SetClientMaxWindowBits(15);
    }
    DCHECK(response.IsValidAsResponse());
    DCHECK(offer.IsCompatibleWith(response));
    auto deflater = std::make_unique<WebSocketDeflater>(
        response.server_context_take_over_mode());
    auto inflater = std::make_unique<WebSocketInflater>(kInflaterChunkSize,
                                                        kInflaterChunkSize);
    if (!deflater->Initialize(response.PermissiveServerMaxWindowBits()) ||
        !inflater->Initialize(response.PermissiveClientMaxWindowBits())) {
      // For some reason we cannot accept the parameters.
      continue;
    }
    *deflate_parameters = response;
    return base::WrapUnique(new WebSocketEncoder(
        FOR_SERVER, std::move(deflater), std::move(inflater)));
  }

  // We cannot find an acceptable offer.
  return base::WrapUnique(new WebSocketEncoder(FOR_SERVER, nullptr, nullptr));
}

// static
std::unique_ptr<WebSocketEncoder> WebSocketEncoder::CreateClient(
    const std::string& response_extensions) {
  // TODO(yhirano): Add a way to return an error.

  WebSocketExtensionParser parser;
  if (!parser.Parse(response_extensions)) {
    // Parse error. Note that there are two cases here.
    // 1) There is no Sec-WebSocket-Extensions header.
    // 2) There is a malformed Sec-WebSocketExtensions header.
    // We should return a deflate-disabled encoder for the former case and
    // fail the connection for the latter case.
    return base::WrapUnique(new WebSocketEncoder(FOR_CLIENT, nullptr, nullptr));
  }
  if (parser.extensions().size() != 1) {
    // Only permessage-deflate extension is supported.
    // TODO (yhirano): Fail the connection.
    return base::WrapUnique(new WebSocketEncoder(FOR_CLIENT, nullptr, nullptr));
  }
  const auto& extension = parser.extensions()[0];
  WebSocketDeflateParameters params;
  std::string failure_message;
  if (!params.Initialize(extension, &failure_message) ||
      !params.IsValidAsResponse(&failure_message)) {
    // TODO (yhirano): Fail the connection.
    return base::WrapUnique(new WebSocketEncoder(FOR_CLIENT, nullptr, nullptr));
  }

  auto deflater = std::make_unique<WebSocketDeflater>(
      params.client_context_take_over_mode());
  auto inflater = std::make_unique<WebSocketInflater>(kInflaterChunkSize,
                                                      kInflaterChunkSize);
  if (!deflater->Initialize(params.PermissiveClientMaxWindowBits()) ||
      !inflater->Initialize(params.PermissiveServerMaxWindowBits())) {
    // TODO (yhirano): Fail the connection.
    return base::WrapUnique(new WebSocketEncoder(FOR_CLIENT, nullptr, nullptr));
  }

  return base::WrapUnique(new WebSocketEncoder(FOR_CLIENT, std::move(deflater),
                                               std::move(inflater)));
}

WebSocketEncoder::WebSocketEncoder(Type type,
                                   std::unique_ptr<WebSocketDeflater> deflater,
                                   std::unique_ptr<WebSocketInflater> inflater)
    : type_(type),
      deflater_(std::move(deflater)),
      inflater_(std::move(inflater)) {}

WebSocketEncoder::~WebSocketEncoder() = default;

WebSocketParseResult WebSocketEncoder::DecodeFrame(std::string_view frame,
                                                   int* bytes_consumed,
                                                   std::string* output) {
  bool compressed;
  std::string current_output;
  WebSocketParseResult result = DecodeFrameHybi17(
      frame, type_ == FOR_SERVER, bytes_consumed, &current_output, &compressed);
  switch (result) {
    case WebSocketParseResult::FRAME_OK_FINAL:
    case WebSocketParseResult::FRAME_OK_MIDDLE: {
      if (continuation_message_frames_.empty())
        is_current_message_compressed_ = compressed;
      continuation_message_frames_.push_back(current_output);

      if (result == WebSocketParseResult::FRAME_OK_FINAL) {
        *output = base::StrCat(continuation_message_frames_);
        continuation_message_frames_.clear();
        if (is_current_message_compressed_ && !Inflate(output)) {
          return WebSocketParseResult::FRAME_ERROR;
        }
      }
      break;
    }

    case WebSocketParseResult::FRAME_PING:
      *output = current_output;
      break;

    default:
      // This function doesn't need special handling for other parse results.
      break;
  }

  return result;
}

void WebSocketEncoder::EncodeTextFrame(std::string_view frame,
                                       int masking_key,
                                       std::string* output) {
  std::string compressed;
  constexpr auto op_code = WebSocketFrameHeader::OpCodeEnum::kOpCodeText;
  if (Deflate(frame, &compressed))
    EncodeFrameHybi17(compressed, masking_key, true, op_code, output);
  else
    EncodeFrameHybi17(frame, masking_key, false, op_code, output);
}

void WebSocketEncoder::EncodeCloseFrame(std::string_view frame,
                                        int masking_key,
                                        std::string* output) {
  constexpr auto op_code = WebSocketFrameHeader::OpCodeEnum::kOpCodeClose;
  EncodeFrameHybi17(frame, masking_key, false, op_code, output);
}

void WebSocketEncoder::EncodePongFrame(std::string_view frame,
                                       int masking_key,
                                       std::string* output) {
  constexpr auto op_code = WebSocketFrameHeader::OpCodeEnum::kOpCodePong;
  EncodeFrameHybi17(frame, masking_key, false, op_code, output);
}

bool WebSocketEncoder::Inflate(std::string* message) {
  if (!inflater_)
    return false;
  if (!inflater_->AddBytes(message->data(), message->length()))
    return false;
  if (!inflater_->Finish())
    return false;

  std::vector<char> output;
  while (inflater_->CurrentOutputSize() > 0) {
    scoped_refptr<IOBufferWithSize> chunk =
        inflater_->GetOutput(inflater_->CurrentOutputSize());
    if (!chunk.get())
      return false;
    output.insert(output.end(), chunk->data(), chunk->data() + chunk->size());
  }

  *message =
      output.size() ? std::string(output.data(), output.size()) : std::string();
  return true;
}

bool WebSocketEncoder::Deflate(std::string_view message, std::string* output) {
  if (!deflater_)
    return false;
  if (!deflater_->AddBytes(message.data(), message.length())) {
    deflater_->Finish();
    return false;
  }
  if (!deflater_->Finish())
    return false;
  scoped_refptr<IOBufferWithSize> buffer =
      deflater_->GetOutput(deflater_->CurrentOutputSize());
  if (!buffer.get())
    return false;
  *output = std::string(buffer->data(), buffer->size());
  return true;
}

}  // namespace net

"""

```
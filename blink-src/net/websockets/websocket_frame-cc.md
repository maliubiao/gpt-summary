Response:
Let's break down the thought process for analyzing this C++ code file and answering the user's request.

**1. Understanding the Goal:**

The user wants to understand the functionality of `websocket_frame.cc` within the Chromium networking stack, particularly regarding its relationship with JavaScript, its internal logic, potential user errors, and how a user action might lead to this code being executed.

**2. Initial Code Scan & Keyword Identification:**

My first step is to quickly scan the code for key terms and structures that indicate its purpose. I see:

* `#include "net/websockets/websocket_frame.h"`:  This immediately tells me the file deals with WebSocket frames.
* `WebSocketFrameHeader`, `WebSocketFrame`, `WebSocketFrameChunk`: These are likely the core data structures.
* `WriteWebSocketFrameHeader`, `MaskWebSocketFramePayload`, `ParseCloseFrame`: These are clearly functions performing specific operations on WebSocket frames.
* `kFinalBit`, `kOpCodeMask`, `kMaskBit`, etc.: These are constants related to the WebSocket protocol's frame structure.
* `GenerateWebSocketMaskingKey`:  This hints at the masking process.
* `base::span`, `base::containers`: These indicate the use of modern C++ for memory management and data structures.

**3. Deciphering Core Functionality:**

Based on the keywords, I start to piece together the primary responsibilities:

* **Frame Structure:** The file defines how WebSocket frames are represented in memory (`WebSocketFrameHeader`, `WebSocketFrame`). This involves flags (final, reserved, opcode), masking, and payload length.
* **Header Handling:** `WriteWebSocketFrameHeader` is responsible for serializing the header information into a byte buffer according to the WebSocket protocol. `GetWebSocketFrameHeaderSize` calculates the required header size.
* **Payload Masking/Unmasking:**  `MaskWebSocketFramePayload` implements the XOR masking required by the WebSocket protocol for client-to-server messages. `GenerateWebSocketMaskingKey` creates the random masking key.
* **Close Frame Parsing:** `ParseCloseFrame` specifically handles the interpretation of WebSocket close frames, including the status code and optional reason.

**4. Connecting to JavaScript (Conceptual Link):**

Now I need to think about how this C++ code relates to JavaScript. JavaScript in a web browser uses the `WebSocket` API. This API abstracts away the low-level details of frame construction and parsing. The C++ code in `websocket_frame.cc` is the *implementation* behind that API.

* **Sending Data:** When JavaScript uses `websocket.send(data)`, the browser's networking stack (including this C++ code) will take the `data`, construct a WebSocket frame (using `WriteWebSocketFrameHeader` and potentially masking the payload), and send it over the network.
* **Receiving Data:** When the browser receives a WebSocket frame, this C++ code (or related parsing logic) will interpret the header, unmask the payload (if necessary), and pass the data up to the JavaScript `onmessage` event.
* **Closing Connection:** When JavaScript initiates a close (e.g., `websocket.close()`), the browser will construct and send a close frame (handled by this C++ code). When a close frame is received, `ParseCloseFrame` will process it, and the information will be used to inform the JavaScript code (e.g., through the `onclose` event).

**5. Logical Reasoning (Hypothetical Input/Output):**

To illustrate the logic, I need a concrete example. Let's pick sending a simple text message:

* **Hypothetical Input:**  JavaScript calls `websocket.send("Hello")`.
* **C++ Processing:**
    * `WriteWebSocketFrameHeader` is called with `final=true`, `opcode=TEXT_FRAME`, `masked=true` (for client-to-server), and `payload_length=5`. A random masking key is generated.
    * The header bytes are constructed according to the WebSocket protocol.
    * The payload "Hello" is masked using the generated key.
* **Hypothetical Output (Header Bytes):** The output would be a sequence of bytes representing the constructed header, such as `0x81` (final bit set, text opcode), followed by the length and masking information. The exact bytes depend on the masking key.

**6. Identifying Common Errors:**

Thinking about how developers use WebSockets, I can identify potential misuse scenarios that might lead to errors handled by this C++ code or related parts of the networking stack:

* **Incorrect Close Code:**  A server might send an invalid close code (outside the allowed range), which `ParseCloseFrame` would detect.
* **Invalid UTF-8 in Close Reason:**  A server sending a close frame might include a reason string that's not valid UTF-8, which `ParseCloseFrame` checks.
* **Sending Too Much Data:** While not directly handled in this file, trying to send excessively large messages could lead to fragmentation or other issues.

**7. Tracing User Operations (Debugging Clues):**

To understand how a user action reaches this code, I follow the flow:

1. **User Action:** The user interacts with a web page (e.g., clicks a button, types in a chat).
2. **JavaScript Interaction:**  The web page's JavaScript code uses the `WebSocket` API to send or receive data.
3. **Browser's Networking Stack:** The browser's networking implementation (including `websocket_frame.cc`) takes over to handle the low-level details of WebSocket communication.
4. **Frame Construction/Parsing:**  This C++ file plays a crucial role in building outgoing frames and interpreting incoming frames.

**8. Structuring the Answer:**

Finally, I organize the information into clear sections, mirroring the user's request:

* **Functionality:**  A concise overview of the file's purpose.
* **Relationship with JavaScript:**  Explaining the connection through the `WebSocket` API.
* **Logical Reasoning:** Providing a concrete example with input and output.
* **Common Usage Errors:** Listing potential developer mistakes.
* **User Operation Trace:** Describing how a user action leads to this code.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  I might initially focus too heavily on the bit manipulation.
* **Correction:** I realize the user needs a higher-level understanding, so I shift the focus to the overall purpose and connection to JavaScript.
* **Refinement:**  I ensure the examples are clear and relate directly to the functions within the code. I also ensure I'm addressing all aspects of the user's request.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive and helpful answer to the user's question.
This C++ source code file, `websocket_frame.cc`, located in the `net/websockets` directory of Chromium's network stack, is responsible for **handling the structure and manipulation of WebSocket frames**. It defines how WebSocket messages are formatted, masked, and parsed at a low level.

Here's a breakdown of its functionalities:

**1. Defining WebSocket Frame Structures:**

* **`WebSocketFrameHeader`:**  This struct represents the header of a WebSocket frame. It stores information like:
    * `final`:  A boolean indicating if this is the last frame in a fragmented message.
    * `reserved1`, `reserved2`, `reserved3`:  Reserved bits for future use in the WebSocket protocol.
    * `opcode`:  An enumeration (`OpCode`) indicating the type of the frame (e.g., text, binary, close, ping, pong).
    * `masked`:  A boolean indicating if the payload is masked (always true for client-to-server messages).
    * `masking_key`:  A 4-byte key used for masking the payload.
    * `payload_length`: The length of the frame's payload.
* **`WebSocketFrame`:** This class represents a complete WebSocket frame, containing a `header` and the `payload` (as a `std::vector<char>`).
* **`WebSocketFrameChunk`:**  This class represents a chunk of a WebSocket frame, potentially used for handling large or fragmented messages.

**2. Functions for Manipulating Frame Headers:**

* **`GetWebSocketFrameHeaderSize(const WebSocketFrameHeader& header)`:** Calculates the size of the WebSocket frame header based on the payload length (which determines if an extended length field is needed) and whether the frame is masked.
* **`WriteWebSocketFrameHeader(const WebSocketFrameHeader& header, const WebSocketMaskingKey* masking_key, base::span<uint8_t> buffer)`:**  This function takes a `WebSocketFrameHeader` and writes its binary representation into a provided buffer. It handles:
    * Setting the flag bits (final, reserved, opcode).
    * Encoding the payload length (using 1, 3, or 9 bytes depending on the length).
    * Writing the masking key if the `masked` flag is set.

**3. Functions for Payload Masking/Unmasking:**

* **`GenerateWebSocketMaskingKey()`:** Generates a cryptographically secure random 4-byte masking key. This key is essential for masking payloads sent from clients to servers.
* **`MaskWebSocketFramePayload(const WebSocketMaskingKey& masking_key, uint64_t frame_offset, base::span<uint8_t> data)`:**  This is the core function for applying or removing the masking to the payload data. It uses the XOR operation with the masking key. The `frame_offset` is important for handling fragmented messages where the masking needs to continue correctly across chunks. It includes optimized versions using vector instructions for performance.
* **`MaskWebSocketFramePayloadByBytes(...)`:** A byte-by-byte implementation of the masking logic, used for smaller payloads or unaligned memory regions.

**4. Function for Parsing Close Frames:**

* **`ParseCloseFrame(base::span<const char> payload)`:**  Specifically handles the parsing of WebSocket close frames. It extracts the close status code and the optional close reason from the payload, performing validation:
    * Checks for invalid payload sizes (0 or 1 byte).
    * Validates the status code (ensuring it's not a reserved value).
    * Checks if the close reason is valid UTF-8.

**Relationship with JavaScript:**

This C++ code is the underlying implementation that supports the `WebSocket` API available in JavaScript within web browsers. Here's how they relate:

* **Sending Data:** When JavaScript code uses `websocket.send(data)`, the browser's network stack, including this `websocket_frame.cc` file, is responsible for:
    * Creating a `WebSocketFrameHeader` with the appropriate opcode (e.g., TEXT_FRAME for a string).
    * Setting the `masked` flag to `true` since it's a client-to-server message.
    * Generating a masking key using `GenerateWebSocketMaskingKey()`.
    * Calling `WriteWebSocketFrameHeader()` to serialize the header.
    * Calling `MaskWebSocketFramePayload()` to mask the `data`.
    * Sending the combined header and masked payload over the network.
* **Receiving Data:** When the browser receives a WebSocket frame from a server:
    * Code in `websocket_frame.cc` (or related parsing logic) is used to interpret the incoming bytes, extracting the header and payload.
    * If the frame is masked (which is typical for server-to-client messages in some scenarios or extensions), the masking is removed using `MaskWebSocketFramePayload()` with the server-provided masking key (if present and applicable).
    * The unmasked payload is then made available to the JavaScript `WebSocket` object, triggering the `onmessage` event.
* **Closing Connection:** When JavaScript calls `websocket.close(code, reason)`, the browser will construct a close frame using this C++ code:
    * The `code` and `reason` are formatted into the payload of a close frame.
    * A `WebSocketFrameHeader` with the CLOSE_FRAME opcode is created.
    * `WriteWebSocketFrameHeader()` is used to serialize the header.
    * The close frame is sent to the server.
* **Receiving Close Frame:** When a close frame is received, `ParseCloseFrame()` is used to interpret the status code and reason, which is then passed back to the JavaScript `WebSocket` object, triggering the `onclose` event.

**Example of Logical Reasoning (Hypothetical Input and Output):**

**Scenario:** JavaScript calls `websocket.send("Hello")`.

**Hypothetical Input to `WriteWebSocketFrameHeader` and `MaskWebSocketFramePayload`:**

* **`WebSocketFrameHeader` (for a text message):**
    * `final = true`
    * `reserved1 = false`, `reserved2 = false`, `reserved3 = false`
    * `opcode = TEXT_FRAME` (assuming an enum value, let's say `0x1`)
    * `masked = true`
    * `payload_length = 5`
* **`masking_key` (generated by `GenerateWebSocketMaskingKey`):**  Let's assume it's `[0x11, 0x22, 0x33, 0x44]`
* **`payload` (for masking):**  The byte representation of "Hello", which is `[0x48, 0x65, 0x6c, 0x6c, 0x6f]`

**Hypothetical Output from `WriteWebSocketFrameHeader` (into a buffer):**

* **First byte:** `0b10000001` (0x81) - Final bit set, Text opcode.
* **Second byte:** `0b10000101` (0x85) - Mask bit set, Payload length is 5.
* **Masking key:** `0x11`, `0x22`, `0x33`, `0x44`

**Hypothetical Output from `MaskWebSocketFramePayload` (masked payload):**

The payload is XORed with the masking key, cycling through the key bytes:

* `H` (0x48) XOR `0x11` = `0x59`
* `e` (0x65) XOR `0x22` = `0x47`
* `l` (0x6c) XOR `0x33` = `0x5f`
* `l` (0x6c) XOR `0x44` = `0x28`
* `o` (0x6f) XOR `0x11` = `0x7e`

So the masked payload would be `[0x59, 0x47, 0x5f, 0x28, 0x7e]`

**The complete sent frame would be:** `0x81 0x85 0x11 0x22 0x33 0x44 0x59 0x47 0x5f 0x28 0x7e`

**Common User or Programming Errors and Examples:**

1. **Incorrectly Handling Masking on the Server-Side:**
   * **Error:** A server might forget to unmask the payload sent by the client.
   * **Example:** A developer implements a WebSocket server but doesn't realize that client-sent messages are always masked according to the WebSocket protocol. They try to directly interpret the raw bytes of the payload, leading to garbled data.

2. **Sending Unmasked Data from the Client:**
   * **Error:**  A client-side implementation (perhaps a non-browser implementation trying to bypass the standard) might attempt to send data without masking.
   * **Example:** A custom WebSocket client written in Python accidentally omits the masking step. The browser (if acting as the server) or a standard-compliant server will likely reject the connection or the message due to a protocol violation.

3. **Using Invalid Close Status Codes:**
   * **Error:**  A developer might use a reserved or out-of-range close status code when closing the connection.
   * **Example:** JavaScript code uses `websocket.close(1004, "Something went wrong")`. The status code 1004 is reserved (`kWebSocketErrorReservedForFutureUse`). When the receiving end parses this close frame using `ParseCloseFrame`, it will likely result in a protocol error.

4. **Sending a Close Reason that is Not Valid UTF-8:**
   * **Error:**  A developer might include non-UTF-8 characters in the close reason.
   * **Example:** JavaScript code uses `websocket.close(1000, "Invalid characters: \xff")`. The `ParseCloseFrame` function will detect the invalid UTF-8 sequence and report a protocol error.

**User Operations and Debugging Clues:**

Let's consider a scenario where a user reports that WebSocket messages are not being displayed correctly in a web application. Here's how their actions might lead to this code being involved, serving as debugging clues:

1. **User Action:** The user types a message in a chat application within their browser and hits "Send".
2. **JavaScript Interaction:** The JavaScript code handling the chat application uses the `websocket.send(message)` API.
3. **Frame Construction in Chromium:**
   * The browser's network stack needs to construct the WebSocket frame.
   * `WebSocketFrameHeader` is populated with the appropriate opcode (TEXT_FRAME), and the `masked` flag is set to `true`.
   * `GenerateWebSocketMaskingKey()` is called to get a masking key.
   * `WriteWebSocketFrameHeader()` writes the header bytes.
   * `MaskWebSocketFramePayload()` XORs the message payload with the masking key.
4. **Network Transmission:** The masked frame is sent over the network to the server.

**Debugging Clues:**

* **If the server is receiving garbled data:** This could indicate an issue with the client-side masking logic in `MaskWebSocketFramePayload()` or a mismatch in understanding the masking requirement. Network inspection tools can show the raw bytes sent.
* **If the server is reporting a protocol error related to masking:** This suggests the client might be sending unmasked data, or the masking is being applied incorrectly.
* **If the issue is with receiving data from the server:**
    * When the server sends a message, Chromium receives the frame.
    * The header is parsed. If the `masked` bit is set, the browser expects a masking key (though server-to-client masking is less common in typical scenarios without extensions).
    * `MaskWebSocketFramePayload()` would be used to *unmask* the payload. An error here could lead to incorrectly interpreted messages in JavaScript.
* **If the user reports issues with the connection closing unexpectedly:**
    * JavaScript might call `websocket.close()`.
    * A close frame is constructed using this code, and `ParseCloseFrame()` is used on the receiving end.
    * Examining the close status code and reason (if any) using browser developer tools or server logs can provide clues about why the connection closed. If `ParseCloseFrame()` reports an error, it suggests a problem with the format of the close frame.

By understanding the role of `websocket_frame.cc`, developers can better diagnose issues related to WebSocket communication by inspecting network traffic, examining JavaScript WebSocket API calls, and understanding the underlying frame structure and masking mechanisms.

Prompt: 
```
这是目录为net/websockets/websocket_frame.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_frame.h"

#include <stddef.h>
#include <string.h>

#include <ostream>

#include "base/check.h"
#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/containers/span_writer.h"
#include "base/numerics/safe_conversions.h"
#include "base/rand_util.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "net/base/net_errors.h"
#include "net/websockets/websocket_errors.h"

namespace net {

namespace {

// GCC (and Clang) can transparently use vector ops. Only try to do this on
// architectures where we know it works, otherwise gcc will attempt to emulate
// the vector ops, which is unlikely to be efficient.
#if defined(COMPILER_GCC) && \
    (defined(ARCH_CPU_X86_FAMILY) || defined(ARCH_CPU_ARM_FAMILY))

using PackedMaskType = uint32_t __attribute__((vector_size(16)));

#else

using PackedMaskType = size_t;

#endif  // defined(COMPILER_GCC) &&
        // (defined(ARCH_CPU_X86_FAMILY) || defined(ARCH_CPU_ARM_FAMILY))

constexpr size_t kWebSocketCloseCodeLength = 2;

constexpr uint8_t kFinalBit = 0x80;
constexpr uint8_t kReserved1Bit = 0x40;
constexpr uint8_t kReserved2Bit = 0x20;
constexpr uint8_t kReserved3Bit = 0x10;
constexpr uint8_t kOpCodeMask = 0xF;
constexpr uint8_t kMaskBit = 0x80;
constexpr uint64_t kMaxPayloadLengthWithoutExtendedLengthField = 125;
constexpr uint64_t kPayloadLengthWithTwoByteExtendedLengthField = 126;
constexpr uint64_t kPayloadLengthWithEightByteExtendedLengthField = 127;

inline void MaskWebSocketFramePayloadByBytes(
    const WebSocketMaskingKey& masking_key,
    size_t masking_key_offset,
    const base::span<uint8_t> payload) {
  uint8_t* data = payload.data();
  const size_t size = payload.size();
  for (size_t i = 0; i < size; ++i) {
    // SAFETY: Performance sensitive. `data` is within `payload` bounds.
    UNSAFE_BUFFERS(data[i]) ^=
        masking_key.key[masking_key_offset++ %
                        WebSocketFrameHeader::kMaskingKeyLength];
  }
}

}  // namespace

std::unique_ptr<WebSocketFrameHeader> WebSocketFrameHeader::Clone() const {
  auto ret = std::make_unique<WebSocketFrameHeader>(opcode);
  ret->CopyFrom(*this);
  return ret;
}

void WebSocketFrameHeader::CopyFrom(const WebSocketFrameHeader& source) {
  final = source.final;
  reserved1 = source.reserved1;
  reserved2 = source.reserved2;
  reserved3 = source.reserved3;
  opcode = source.opcode;
  masked = source.masked;
  masking_key = source.masking_key;
  payload_length = source.payload_length;
}

WebSocketFrame::WebSocketFrame(WebSocketFrameHeader::OpCode opcode)
    : header(opcode) {}

WebSocketFrame::~WebSocketFrame() = default;

WebSocketFrameChunk::WebSocketFrameChunk() = default;

WebSocketFrameChunk::~WebSocketFrameChunk() = default;

size_t GetWebSocketFrameHeaderSize(const WebSocketFrameHeader& header) {
  size_t extended_length_size = 0u;
  if (header.payload_length > kMaxPayloadLengthWithoutExtendedLengthField &&
      header.payload_length <= UINT16_MAX) {
    extended_length_size = 2u;
  } else if (header.payload_length > UINT16_MAX) {
    extended_length_size = 8u;
  }

  return (WebSocketFrameHeader::kBaseHeaderSize + extended_length_size +
          (header.masked ? WebSocketFrameHeader::kMaskingKeyLength : 0u));
}

int WriteWebSocketFrameHeader(const WebSocketFrameHeader& header,
                              const WebSocketMaskingKey* masking_key,
                              base::span<uint8_t> buffer) {
  DCHECK((header.opcode & kOpCodeMask) == header.opcode)
      << "header.opcode must fit to kOpCodeMask.";
  DCHECK(header.payload_length <= static_cast<uint64_t>(INT64_MAX))
      << "WebSocket specification doesn't allow a frame longer than "
      << "INT64_MAX (0x7FFFFFFFFFFFFFFF) bytes.";

  // WebSocket frame format is as follows:
  // - Common header (2 bytes)
  // - Optional extended payload length
  //   (2 or 8 bytes, present if actual payload length is more than 125 bytes)
  // - Optional masking key (4 bytes, present if MASK bit is on)
  // - Actual payload (XOR masked with masking key if MASK bit is on)
  //
  // This function constructs frame header (the first three in the list
  // above).

  size_t header_size = GetWebSocketFrameHeaderSize(header);
  if (header_size > buffer.size()) {
    return ERR_INVALID_ARGUMENT;
  }

  base::SpanWriter writer(buffer);

  uint8_t first_byte = 0u;
  first_byte |= header.final ? kFinalBit : 0u;
  first_byte |= header.reserved1 ? kReserved1Bit : 0u;
  first_byte |= header.reserved2 ? kReserved2Bit : 0u;
  first_byte |= header.reserved3 ? kReserved3Bit : 0u;
  first_byte |= header.opcode & kOpCodeMask;
  writer.WriteU8BigEndian(first_byte);

  int extended_length_size = 0;
  uint8_t second_byte = 0u;
  second_byte |= header.masked ? kMaskBit : 0u;
  if (header.payload_length <= kMaxPayloadLengthWithoutExtendedLengthField) {
    second_byte |= header.payload_length;
  } else if (header.payload_length <= UINT16_MAX) {
    second_byte |= kPayloadLengthWithTwoByteExtendedLengthField;
    extended_length_size = 2;
  } else {
    second_byte |= kPayloadLengthWithEightByteExtendedLengthField;
    extended_length_size = 8;
  }
  writer.WriteU8BigEndian(second_byte);

  // Writes "extended payload length" field.
  if (extended_length_size == 2) {
    writer.WriteU16BigEndian(static_cast<uint16_t>(header.payload_length));
  } else if (extended_length_size == 8) {
    writer.WriteU64BigEndian(header.payload_length);
  }

  // Writes "masking key" field, if needed.
  if (header.masked) {
    DCHECK(masking_key);
    writer.Write(masking_key->key);
  } else {
    DCHECK(!masking_key);
  }

  // Verify we wrote the expected number of bytes.
  DCHECK_EQ(header_size, writer.num_written());
  return header_size;
}

WebSocketMaskingKey GenerateWebSocketMaskingKey() {
  // Masking keys should be generated from a cryptographically secure random
  // number generator, which means web application authors should not be able
  // to guess the next value of masking key.
  WebSocketMaskingKey masking_key;
  base::RandBytes(masking_key.key);
  return masking_key;
}

void MaskWebSocketFramePayload(const WebSocketMaskingKey& masking_key,
                               uint64_t frame_offset,
                               base::span<uint8_t> data) {
  static constexpr size_t kMaskingKeyLength =
      WebSocketFrameHeader::kMaskingKeyLength;

  // Most of the masking is done in chunks of sizeof(PackedMaskType), except for
  // the beginning and the end of the buffer which may be unaligned.
  // PackedMaskType must be a multiple of kMaskingKeyLength in size.
  PackedMaskType packed_mask_key;
  static constexpr size_t kPackedMaskKeySize = sizeof(packed_mask_key);
  static_assert((kPackedMaskKeySize >= kMaskingKeyLength &&
                 kPackedMaskKeySize % kMaskingKeyLength == 0),
                "PackedMaskType size is not a multiple of mask length");
  // If the buffer is too small for the vectorised version to be useful, revert
  // to the byte-at-a-time implementation early.
  if (data.size() <= kPackedMaskKeySize * 2) {
    MaskWebSocketFramePayloadByBytes(masking_key,
                                     frame_offset % kMaskingKeyLength, data);
    return;
  }
  const size_t data_modulus =
      reinterpret_cast<size_t>(data.data()) % kPackedMaskKeySize;
  auto [before_aligned, remaining] = data.split_at(
      data_modulus == 0 ? 0 : (kPackedMaskKeySize - data_modulus));
  auto [aligned, after_aligned] = remaining.split_at(
      remaining.size() - remaining.size() % kPackedMaskKeySize);
  MaskWebSocketFramePayloadByBytes(
      masking_key, frame_offset % kMaskingKeyLength, before_aligned);

  // Create a version of the mask which is rotated by the appropriate offset
  // for our alignment. The "trick" here is that 0 XORed with the mask will
  // give the value of the mask for the appropriate byte.
  std::array<uint8_t, kMaskingKeyLength> realigned_mask = {};
  MaskWebSocketFramePayloadByBytes(
      masking_key, (frame_offset + before_aligned.size()) % kMaskingKeyLength,
      base::as_writable_byte_span(realigned_mask));

  base::span<uint8_t> packed_span = base::byte_span_from_ref(packed_mask_key);
  while (!packed_span.empty()) {
    packed_span.copy_prefix_from(realigned_mask);
    packed_span = packed_span.subspan(realigned_mask.size());
  }

  // The main loop.
  while (!aligned.empty()) {
    // This is not quite standard-compliant C++. However, the standard-compliant
    // equivalent (using memcpy()) compiles to slower code using g++. In
    // practice, this will work for the compilers and architectures currently
    // supported by Chromium, and the tests are extremely unlikely to pass if a
    // future compiler/architecture breaks it.
    *reinterpret_cast<PackedMaskType*>(aligned.data()) ^= packed_mask_key;
    aligned = aligned.subspan(kPackedMaskKeySize);
  }

  MaskWebSocketFramePayloadByBytes(
      masking_key,
      (frame_offset + (data.size() - after_aligned.size())) % kMaskingKeyLength,
      after_aligned);
}

ParseCloseFrameResult ParseCloseFrame(base::span<const char> payload) {
  const uint64_t size = static_cast<uint64_t>(payload.size());

  // Payload size is 0 -> No status received
  if (size == 0U) {
    return ParseCloseFrameResult(kWebSocketErrorNoStatusReceived,
                                 std::string_view());
  }

  // Payload size is 1 -> Protocol error (invalid size)
  if (size == 1U) {
    return ParseCloseFrameResult(
        kWebSocketErrorProtocolError, std::string_view(),
        "Received a broken close frame with an invalid size of 1 byte.");
  }

  // Get the status code from the first 2 bytes
  const uint16_t unchecked_code =
      base::U16FromBigEndian(base::as_byte_span(payload).first<2>());

  // Invalid or reserved status codes
  if (unchecked_code == kWebSocketErrorNoStatusReceived ||
      unchecked_code == kWebSocketErrorAbnormalClosure ||
      unchecked_code == kWebSocketErrorTlsHandshake) {
    return ParseCloseFrameResult(kWebSocketErrorProtocolError,
                                 std::string_view(),
                                 "Received a broken close frame containing a "
                                 "reserved status code.");
  }

  // If size is exactly 2, return the code without a reason
  if (size == 2U) {
    return ParseCloseFrameResult(unchecked_code, std::string_view());
  }

  const base::span<const char> reason_span =
      payload.subspan(kWebSocketCloseCodeLength);
  const auto reason = base::as_string_view(reason_span);

  if (base::IsStringUTF8AllowingNoncharacters(reason)) {
    return ParseCloseFrameResult(unchecked_code, reason);
  }

  return ParseCloseFrameResult(
      kWebSocketErrorProtocolError,
      std::string_view("Invalid UTF-8 in Close frame"),
      "Received a broken close frame containing invalid UTF-8.");
}

}  // namespace net

"""

```
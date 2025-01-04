Response:
Let's break down the thought process for analyzing this C++ test file for WebSocket frames.

**1. Understanding the Goal:**

The request asks for the functionality of the `websocket_frame_test.cc` file, its relation to JavaScript, logical reasoning with examples, common user/programming errors, and how a user might reach this code (debugging).

**2. Initial Code Scan and High-Level Functionality:**

A quick scan of the `#include` statements reveals that the file is testing `net/websockets/websocket_frame.h`. This immediately tells us the core purpose: to test the functionality related to WebSocket frame handling. The presence of `testing/gtest/include/gtest/gtest.h` confirms it's a unit test file using the Google Test framework.

**3. Deconstructing the Tests:**

The file is structured as a series of `TEST` macros. Each test focuses on a specific aspect of WebSocket frame manipulation. I'd go through each test case conceptually:

* **`WebSocketFrameHeaderTest, FrameLengths`:**  Testing the correct encoding and writing of the frame header for different payload lengths (small, medium, large).
* **`WebSocketFrameHeaderTest, FrameLengthsWithMasking`:** Similar to the above, but with masking enabled, verifying the inclusion and correct encoding of the masking key.
* **`WebSocketFrameHeaderTest, FrameOpCodes`:** Checking the encoding of different WebSocket opcodes (text, binary, close, ping, pong, and even undefined ones).
* **`WebSocketFrameHeaderTest, FinalBitAndReservedBits`:** Examining the encoding of the FIN bit and the reserved bits in the frame header.
* **`WebSocketFrameHeaderTest, InsufficientBufferSize`:**  Testing error handling when the provided buffer for writing the header is too small.
* **`WebSocketFrameTest, MaskPayload`:**  Verifying the correctness of the payload masking/unmasking logic with different masking keys and offsets.
* **`WebSocketFrameTest, MaskPayloadAlignment`:** A more rigorous test ensuring payload masking works correctly regardless of memory alignment and chunk sizes, likely to catch issues with SIMD optimizations.
* **`WebSocketFrameHeaderTest, IsKnownDataOpCode`:** Testing a utility function to check if an opcode is a data opcode.
* **`WebSocketFrameHeaderTest, IsKnownControlOpCode`:**  Testing a utility function to check if an opcode is a control opcode.
* **`WebSocketFrameHeaderTest, IsReservedDataOpCode`:** Testing a function to identify reserved data opcodes.
* **`WebSocketFrameHeaderTest, IsReservedControlOpCode`:** Testing a function to identify reserved control opcodes.

**4. Identifying Key Functions and Concepts:**

From the test names and the code within them, I can identify the core functions being tested:

* `WriteWebSocketFrameHeader`:  Writes the WebSocket frame header to a buffer.
* `MaskWebSocketFramePayload`: Applies the masking logic to the payload.
* `WebSocketFrameHeader::IsKnownDataOpCode`: Checks if an opcode is a data opcode.
* `WebSocketFrameHeader::IsKnownControlOpCode`: Checks if an opcode is a control opcode.
* `WebSocketFrameHeader::IsReservedDataOpCode`: Checks if an opcode is a reserved data opcode.
* `WebSocketFrameHeader::IsReservedControlOpCode`: Checks if an opcode is a reserved control opcode.

And the key concepts:

* **Frame Header Structure:**  The format of the initial bytes of a WebSocket frame, including opcode, FIN bit, reserved bits, and payload length.
* **Payload Length Encoding:** The variable-length encoding scheme for the payload length.
* **Masking:** The process of XORing the payload with a masking key.
* **Opcodes:**  Codes indicating the type of data in the frame (text, binary, control messages).
* **Control Frames:** Special frames for managing the WebSocket connection (close, ping, pong).
* **Data Frames:** Frames carrying the actual application data.
* **Reserved Bits/Opcodes:**  Parts of the protocol reserved for future use.

**5. Connecting to JavaScript:**

The crucial link to JavaScript lies in the fact that JavaScript running in a browser is what initiates and interacts with WebSockets. The browser's networking stack (including Chromium's code) handles the underlying WebSocket protocol details.

* **Sending Data:** When JavaScript uses the `send()` method on a WebSocket object, the browser's implementation (potentially involving this C++ code) constructs the WebSocket frame to be sent over the network. If the data is a string, it will likely be sent as a text frame (opcode `0x1`). If it's binary data (like an `ArrayBuffer`), it will be sent as a binary frame (opcode `0x2`).
* **Receiving Data:** When the browser receives a WebSocket frame, this C++ code parses the frame header to determine the type of data and its length. The payload is then extracted and passed up to the JavaScript WebSocket API, triggering the `onmessage` event.
* **Closing Connection:**  When JavaScript calls `close()`, a close frame (opcode `0x8`) is constructed and sent.
* **Pings and Pongs:** The WebSocket API might automatically handle or allow JavaScript to initiate ping/pong frames (opcodes `0x9` and `0xA`) for maintaining the connection.

**6. Logical Reasoning and Examples:**

For logical reasoning, focus on how the code transforms input to output based on the WebSocket protocol.

* **Assumption:** A JavaScript client wants to send a text message "Hello".
* **Input:** The JavaScript `send("Hello")` call.
* **Processing (Conceptual):** The C++ code needs to construct a frame. The opcode will be `0x1` (text). The FIN bit will be set (assuming it's the final fragment of the message). The payload length is 5. No masking is applied by default from the browser to the server.
* **Output (Hypothetical Frame Header):** `\x81\x05` (FIN bit set, text opcode, payload length 5). Followed by the payload "Hello".

For masked frames, the logic involves XORing the payload with the masking key.

* **Assumption:** A client (not necessarily browser, could be a WebSocket library) sends a masked text frame with payload "Data". Masking key is `\xDE\xAD\xBE\xEF`.
* **Input:** Payload "Data" (bytes `\x44\x61\x74\x61`), Masking key `\xDE\xAD\xBE\xEF`, Frame offset 0.
* **Processing:** Each byte of the payload is XORed with a byte from the masking key, cycling through the key.
* **Output:**
    * `\x44` XOR `\xDE` = `\x9A`
    * `\x61` XOR `\xAD` = `\xCC`
    * `\x74` XOR `\xBE` = `\xC2`
    * `\x61` XOR `\xEF` = `\x8E`
    * Masked payload: `\x9A\xCC\xC2\x8E`

**7. Common User/Programming Errors:**

Think about what mistakes developers might make when working with WebSockets, especially if they were trying to implement the protocol manually (which is usually not recommended for security and complexity reasons).

* **Incorrect Masking:** Forgetting to mask frames sent from the client to the server is a security vulnerability. The server will likely reject unmasked frames.
* **Incorrect Payload Length:** Providing an incorrect payload length in the header will cause parsing errors on the receiving end.
* **Using Reserved Opcodes:**  Attempting to use opcodes marked as "reserved" can lead to interoperability issues and unexpected behavior.
* **Incorrect Handling of Control Frames:** Not responding to ping frames or sending control frames with incorrect payload lengths can cause connection issues.
* **Buffer Overflow:** When writing or reading frame headers, not ensuring sufficient buffer size can lead to crashes or security vulnerabilities.

**8. Debugging Scenario:**

Consider a situation where a WebSocket connection isn't working as expected.

* **User Action:** A user visits a website that uses WebSockets. The JavaScript code attempts to send a message.
* **Possible Issue:** The server isn't receiving the message correctly.
* **Debugging Steps:**
    1. **Browser Developer Tools:** Inspect the "Network" tab, looking at the WebSocket frames being sent and received. Are the frames being sent? Are there any errors?
    2. **Server-Side Logs:** Check the WebSocket server logs for any errors during frame processing.
    3. **Deeper Dive (if necessary):** If the issue isn't clear, a developer might need to examine the browser's source code or use network packet capture tools (like Wireshark) to inspect the raw bytes of the WebSocket frames. This is where understanding the structure tested by `websocket_frame_test.cc` becomes crucial. The developer might be looking for incorrect opcode values, incorrect payload lengths, or masking issues.

This detailed thought process, going from a high-level understanding to specific details and considering the broader context of JavaScript interaction and debugging, helps in generating a comprehensive and accurate answer to the request.
This C++ source code file, `websocket_frame_test.cc`, is a **unit test file** within the Chromium project's networking stack. Its primary function is to **test the correctness of the `net/websockets/websocket_frame.h` code**, which deals with the structure and manipulation of WebSocket frames.

Here's a breakdown of its functionalities:

**Core Functionality: Testing WebSocket Frame Handling**

The file contains various test cases using the Google Test framework (`testing/gtest/include/gtest/gtest.h`). These tests focus on different aspects of WebSocket frame construction and manipulation:

* **`WebSocketFrameHeaderTest, FrameLengths`:** Tests the correct encoding of the payload length in the WebSocket frame header for unmasked frames. It verifies that different payload sizes (0, small, medium, large) are encoded into the header correctly.
* **`WebSocketFrameHeaderTest, FrameLengthsWithMasking`:** Similar to the above, but specifically tests the encoding of payload length when the frame is masked (as required for client-to-server messages). It ensures the masking bit is set and the masking key is included in the header.
* **`WebSocketFrameHeaderTest, FrameOpCodes`:** Verifies the correct encoding of different WebSocket opcodes (Text, Binary, Close, Ping, Pong, and even undefined opcodes) in the frame header. The opcode indicates the type of data being transmitted.
* **`WebSocketFrameHeaderTest, FinalBitAndReservedBits`:** Checks if the FIN (Final) bit and the reserved bits (RSV1, RSV2, RSV3) in the frame header are set and encoded correctly. These bits have specific meanings in WebSocket framing.
* **`WebSocketFrameHeaderTest, InsufficientBufferSize`:** Tests the error handling when attempting to write a WebSocket frame header into a buffer that is too small to accommodate it. This ensures the code gracefully handles insufficient buffer situations.
* **`WebSocketFrameTest, MaskPayload`:**  Tests the core masking/unmasking logic for the WebSocket frame payload. It uses different masking keys and frame offsets to ensure the XOR operation is performed correctly.
* **`WebSocketFrameTest, MaskPayloadAlignment`:** This is a more rigorous test for the payload masking logic, focusing on memory alignment and chunk sizes. It's designed to catch potential issues related to optimizations or vectorization that might depend on specific memory layouts.
* **`WebSocketFrameHeaderTest, IsKnownDataOpCode`:** Tests a helper function that determines if a given opcode is a valid data frame opcode (Continuation, Text, Binary).
* **`WebSocketFrameHeaderTest, IsKnownControlOpCode`:** Tests a helper function that determines if a given opcode is a valid control frame opcode (Close, Ping, Pong).
* **`WebSocketFrameHeaderTest, IsReservedDataOpCode`:** Tests a helper function to identify if an opcode is in the range reserved for future data frame opcodes.
* **`WebSocketFrameHeaderTest, IsReservedControlOpCode`:** Tests a helper function to identify if an opcode is in the range reserved for future control frame opcodes.

**Relationship with JavaScript Functionality**

This C++ code is part of the **browser's networking implementation**. When JavaScript code in a web page uses the WebSocket API, the browser's underlying C++ networking stack handles the actual communication with the WebSocket server.

Here's how it relates:

* **Sending Data (JavaScript `send()`):** When JavaScript calls `websocket.send(data)`, the browser needs to construct a WebSocket frame to send over the network. The `WriteWebSocketFrameHeader` function (tested here) is responsible for creating the header of that frame, setting the opcode (text or binary based on the `data` type), and encoding the payload length. The `MaskWebSocketFramePayload` function (tested here) is responsible for applying the masking to the payload if the message is sent from the client.
* **Receiving Data (JavaScript `onmessage`):** When the browser receives data from a WebSocket connection, the networking stack (including code related to `websocket_frame.h`) parses the incoming WebSocket frame. It reads the header to determine the opcode and payload length. The `MaskWebSocketFramePayload` function would be used to unmask the payload if the frame was masked. The payload is then delivered to the JavaScript `onmessage` handler.
* **Closing Connection (JavaScript `close()`):** When JavaScript calls `websocket.close()`, the browser sends a WebSocket close frame. The header of this frame will have the close opcode (0x8).
* **Pings and Pongs:** The WebSocket API allows for sending and receiving ping and pong frames for keep-alive and network health checks. The code tested here is responsible for constructing and parsing these frames as well.

**Example of Relationship:**

Let's say a JavaScript client sends a text message "Hello, world!".

1. **JavaScript:** `websocket.send("Hello, world!");`
2. **Chromium (C++):**
   - The `WriteWebSocketFrameHeader` function (being tested) would be used to create a header like `\x81\x0d\xXX\xXX\xXX\xXX` (assuming masking is enabled), where:
     - `\x81` indicates a final text frame.
     - `\x0d` indicates the payload length is 13 (after considering the masking bit).
     - `\xXX\xXX\xXX\xXX` is the 4-byte masking key.
   - The `MaskWebSocketFramePayload` function (being tested) would XOR the bytes of "Hello, world!" with the masking key.
3. **Network:** The constructed masked WebSocket frame is sent to the server.

**Logical Reasoning with Assumptions, Inputs, and Outputs**

**Scenario 1: Testing Payload Length Encoding (Unmasked)**

* **Assumption:** We are testing the encoding of an unmasked frame with a payload length of 126 bytes.
* **Input (Conceptual):** A `WebSocketFrameHeader` object is created with `final = true`, `masked = false`, `opcode = kOpCodeText`, and `payload_length = 126`.
* **Function Called:** `WriteWebSocketFrameHeader(header, nullptr, output_buffer)`
* **Expected Output (from `kTests` in the code):** The first 4 bytes of the `output_buffer` should be `\x81\x7E\x00\x7E`.
    - `\x81`: Final bit set, text opcode.
    - `\x7E`: Indicates the following two bytes represent the payload length.
    - `\x00\x7E`: Represents the payload length 126 in big-endian order.

**Scenario 2: Testing Payload Masking**

* **Assumption:** We are testing the masking of the payload "FooBar" with the masking key `\xDE\xAD\xBE\xEF` and a frame offset of 0.
* **Input:** `masking_key = "\xDE\xAD\xBE\xEF"`, `frame_offset = 0`, `payload = "FooBar"` (bytes: `0x46 0x6F 0x6F 0x42 0x61 0x72`).
* **Function Called:** `MaskWebSocketFramePayload(masking_key, frame_offset, payload_buffer)`
* **Processing (XOR operation):**
    - 'F' (0x46) XOR 0xDE = 0x98
    - 'o' (0x6F) XOR 0xAD = 0xC2
    - 'o' (0x6F) XOR 0xBE = 0xD1
    - 'B' (0x42) XOR 0xEF = 0xAD
    - 'a' (0x61) XOR 0xDE = 0xBF
    - 'r' (0x72) XOR 0xAD = 0xDF
* **Expected Output (from `kTests` in the code):** The `payload_buffer` should be modified to contain `"\x98\xC2\xD1\xAD\xBF\xDF"`.

**User or Programming Common Usage Errors and Examples**

This test file indirectly helps prevent common errors by ensuring the underlying implementation is correct. However, here are some errors that developers (writing WebSocket client or server code) might make, and how this test file relates:

* **Incorrectly Encoding Payload Length:** A developer might try to manually construct a WebSocket frame and get the payload length encoding wrong (e.g., using a single byte for a length greater than 125). The `FrameLengths` tests in this file ensure the `WriteWebSocketFrameHeader` function handles this correctly, so if a browser uses this code, it will generate valid headers.
* **Forgetting to Mask Client-to-Server Messages:** The WebSocket protocol requires clients to mask their messages to the server. If a client implementation forgets to do this, the server will likely reject the connection. The `FrameLengthsWithMasking` and `MaskPayload` tests ensure the browser's implementation correctly handles masking when sending data.
* **Using Reserved Opcodes:** Developers might accidentally use opcodes that are reserved for future use. The `FrameOpCodes`, `IsReservedDataOpCode`, and `IsReservedControlOpCode` tests verify that the code correctly handles known opcodes and can identify reserved ones, helping to ensure interoperability.
* **Incorrectly Implementing Masking:**  A manual implementation of the masking algorithm might have errors in the XOR operation or the way the masking key is applied. The `MaskPayload` and `MaskPayloadAlignment` tests are crucial for catching such errors in the browser's implementation.
* **Insufficient Buffer Size:**  When writing frame headers, providing a buffer that is too small can lead to crashes or data corruption. The `InsufficientBufferSize` test ensures that the code handles this case gracefully and returns an error.

**User Operation and Debugging Lines**

While end-users don't directly interact with this C++ code, their actions in a web browser can lead to this code being executed. Here's a step-by-step scenario and how it might lead to needing these tests for debugging:

1. **User Action:** A user opens a web page that establishes a WebSocket connection to a server.
2. **JavaScript Execution:** The web page's JavaScript code creates a `WebSocket` object and uses the `send()` method to send a message.
3. **Browser Processing (Triggering the tested code):**
   - The browser's networking stack receives the `send()` call.
   - The code related to `net/websockets/websocket_frame.h` (and functions like `WriteWebSocketFrameHeader` and `MaskWebSocketFramePayload`) is invoked to construct the WebSocket frame to be sent.
4. **Network Transmission:** The constructed frame is sent over the network to the WebSocket server.
5. **Potential Issue:** The WebSocket server fails to process the message correctly.

**Debugging Scenario:**

To debug why the server isn't receiving or processing the message correctly, developers might:

1. **Use Browser Developer Tools:** They would inspect the "Network" tab and look at the WebSocket frames being sent. They might see an error or notice that the frame doesn't look as expected.
2. **Server-Side Logs:** They would check the WebSocket server logs for any errors related to frame parsing or validation.
3. **Deep Dive (If Necessary):** If the issue is still unclear, developers might need to examine the browser's source code or use network packet capture tools (like Wireshark) to inspect the raw bytes of the WebSocket frame being sent. This is where the knowledge of the WebSocket frame structure and the functionality tested in `websocket_frame_test.cc` becomes crucial.

**As a debugger, you might use the information from this test file to:**

* **Verify Header Structure:** Confirm that the frame header being sent by the browser matches the expected format (opcode, payload length encoding, masking bit, masking key if present). The `FrameLengths`, `FrameLengthsWithMasking`, `FrameOpCodes`, and `FinalBitAndReservedBits` tests provide the ground truth for these structures.
* **Check Masking Logic:** If the issue seems related to corrupted data, you would verify that the masking logic is implemented correctly by comparing the masked payload with the expected output from the `MaskPayload` tests.
* **Ensure Correct Opcodes:**  Confirm that the correct opcode is being used for the type of data being sent (text, binary, control messages). The `FrameOpCodes` test helps define the valid opcode values.
* **Investigate Buffer Issues:** If crashes or errors related to buffer sizes occur, the `InsufficientBufferSize` test highlights how the code is expected to handle these situations.

In essence, `websocket_frame_test.cc` acts as a comprehensive set of checks to ensure the correctness of the core WebSocket frame handling logic within the Chromium browser. When things go wrong in WebSocket communication, understanding these tests can provide valuable insights into potential issues within the browser's implementation.

Prompt: 
```
这是目录为net/websockets/websocket_frame_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/websockets/websocket_frame.h"

#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "base/containers/span.h"
#include "base/memory/aligned_memory.h"
#include "base/ranges/algorithm.h"
#include "net/base/net_errors.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

TEST(WebSocketFrameHeaderTest, FrameLengths) {
  struct TestCase {
    const std::string_view frame_header;
    uint64_t frame_length;
  };
  static constexpr TestCase kTests[] = {
      {{"\x81\x00", 2}, UINT64_C(0)},
      {{"\x81\x7D", 2}, UINT64_C(125)},
      {{"\x81\x7E\x00\x7E", 4}, UINT64_C(126)},
      {{"\x81\x7E\xFF\xFF", 4}, UINT64_C(0xFFFF)},
      {{"\x81\x7F\x00\x00\x00\x00\x00\x01\x00\x00", 10}, UINT64_C(0x10000)},
      {{"\x81\x7F\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 10},
       UINT64_C(0x7FFFFFFFFFFFFFFF)}};

  for (const auto& test : kTests) {
    WebSocketFrameHeader header(WebSocketFrameHeader::kOpCodeText);
    header.final = true;
    header.payload_length = test.frame_length;

    std::vector<char> expected_output(test.frame_header.begin(),
                                      test.frame_header.end());
    std::vector<char> output(expected_output.size());
    EXPECT_EQ(static_cast<int>(expected_output.size()),
              WriteWebSocketFrameHeader(header, nullptr,
                                        base::as_writable_byte_span(output)));
    EXPECT_EQ(expected_output, output);
  }
}

TEST(WebSocketFrameHeaderTest, FrameLengthsWithMasking) {
  static constexpr std::string_view kMaskingKey = "\xDE\xAD\xBE\xEF";
  static_assert(kMaskingKey.size() == WebSocketFrameHeader::kMaskingKeyLength,
                "incorrect masking key size");

  struct TestCase {
    const std::string_view frame_header;
    uint64_t frame_length;
  };
  static constexpr TestCase kTests[] = {
      {{"\x81\x80\xDE\xAD\xBE\xEF", 6}, UINT64_C(0)},
      {{"\x81\xFD\xDE\xAD\xBE\xEF", 6}, UINT64_C(125)},
      {{"\x81\xFE\x00\x7E\xDE\xAD\xBE\xEF", 8}, UINT64_C(126)},
      {{"\x81\xFE\xFF\xFF\xDE\xAD\xBE\xEF", 8}, UINT64_C(0xFFFF)},
      {{"\x81\xFF\x00\x00\x00\x00\x00\x01\x00\x00\xDE\xAD\xBE\xEF", 14},
       UINT64_C(0x10000)},
      {{"\x81\xFF\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xDE\xAD\xBE\xEF", 14},
       UINT64_C(0x7FFFFFFFFFFFFFFF)}};

  WebSocketMaskingKey masking_key;
  base::as_writable_byte_span(masking_key.key)
      .copy_from(base::as_byte_span(kMaskingKey));

  for (const auto& test : kTests) {
    WebSocketFrameHeader header(WebSocketFrameHeader::kOpCodeText);
    header.final = true;
    header.masked = true;
    header.payload_length = test.frame_length;

    std::vector<char> expected_output(test.frame_header.begin(),
                                      test.frame_header.end());
    std::vector<char> output(expected_output.size());
    EXPECT_EQ(static_cast<int>(expected_output.size()),
              WriteWebSocketFrameHeader(header, &masking_key,
                                        base::as_writable_byte_span(output)));
    EXPECT_EQ(expected_output, output);
  }
}

TEST(WebSocketFrameHeaderTest, FrameOpCodes) {
  struct TestCase {
    const std::string_view frame_header;
    WebSocketFrameHeader::OpCode opcode;
  };
  static constexpr TestCase kTests[] = {
      {{"\x80\x00", 2}, WebSocketFrameHeader::kOpCodeContinuation},
      {{"\x81\x00", 2}, WebSocketFrameHeader::kOpCodeText},
      {{"\x82\x00", 2}, WebSocketFrameHeader::kOpCodeBinary},
      {{"\x88\x00", 2}, WebSocketFrameHeader::kOpCodeClose},
      {{"\x89\x00", 2}, WebSocketFrameHeader::kOpCodePing},
      {{"\x8A\x00", 2}, WebSocketFrameHeader::kOpCodePong},
      // These are undefined opcodes, but the builder should accept them anyway.
      {{"\x83\x00", 2}, 0x3},
      {{"\x84\x00", 2}, 0x4},
      {{"\x85\x00", 2}, 0x5},
      {{"\x86\x00", 2}, 0x6},
      {{"\x87\x00", 2}, 0x7},
      {{"\x8B\x00", 2}, 0xB},
      {{"\x8C\x00", 2}, 0xC},
      {{"\x8D\x00", 2}, 0xD},
      {{"\x8E\x00", 2}, 0xE},
      {{"\x8F\x00", 2}, 0xF}};

  for (const auto& test : kTests) {
    WebSocketFrameHeader header(test.opcode);
    header.final = true;
    header.payload_length = 0;

    std::vector<char> expected_output(test.frame_header.begin(),
                                      test.frame_header.end());
    std::vector<char> output(expected_output.size());
    EXPECT_EQ(static_cast<int>(expected_output.size()),
              WriteWebSocketFrameHeader(header, nullptr,
                                        base::as_writable_byte_span(output)));
    EXPECT_EQ(expected_output, output);
  }
}

TEST(WebSocketFrameHeaderTest, FinalBitAndReservedBits) {
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
    WebSocketFrameHeader header(WebSocketFrameHeader::kOpCodeText);
    header.final = test.final;
    header.reserved1 = test.reserved1;
    header.reserved2 = test.reserved2;
    header.reserved3 = test.reserved3;
    header.payload_length = 0;

    std::vector<char> expected_output(test.frame_header.begin(),
                                      test.frame_header.end());
    std::vector<char> output(expected_output.size());
    EXPECT_EQ(static_cast<int>(expected_output.size()),
              WriteWebSocketFrameHeader(header, nullptr,
                                        base::as_writable_byte_span(output)));
    EXPECT_EQ(expected_output, output);
  }
}

TEST(WebSocketFrameHeaderTest, InsufficientBufferSize) {
  struct TestCase {
    uint64_t payload_length;
    bool masked;
    size_t expected_header_size;
  };
  static constexpr TestCase kTests[] = {
      {UINT64_C(0), false, 2u},
      {UINT64_C(125), false, 2u},
      {UINT64_C(126), false, 4u},
      {UINT64_C(0xFFFF), false, 4u},
      {UINT64_C(0x10000), false, 10u},
      {UINT64_C(0x7FFFFFFFFFFFFFFF), false, 10u},
      {UINT64_C(0), true, 6u},
      {UINT64_C(125), true, 6u},
      {UINT64_C(126), true, 8u},
      {UINT64_C(0xFFFF), true, 8u},
      {UINT64_C(0x10000), true, 14u},
      {UINT64_C(0x7FFFFFFFFFFFFFFF), true, 14u}};

  for (const auto& test : kTests) {
    WebSocketFrameHeader header(WebSocketFrameHeader::kOpCodeText);
    header.final = true;
    header.opcode = WebSocketFrameHeader::kOpCodeText;
    header.masked = test.masked;
    header.payload_length = test.payload_length;

    std::array<uint8_t, 14> dummy_buffer;
    // Set an insufficient size to |buffer_size|.
    EXPECT_EQ(
        ERR_INVALID_ARGUMENT,
        WriteWebSocketFrameHeader(
            header, nullptr,
            base::span(dummy_buffer).first(test.expected_header_size - 1)));
  }
}

TEST(WebSocketFrameTest, MaskPayload) {
  struct TestCase {
    const std::string_view masking_key;
    uint64_t frame_offset;
    const char* input;
    const char* output;
    size_t data_length;
  };
  static constexpr TestCase kTests[] = {
      {"\xDE\xAD\xBE\xEF", 0, "FooBar", "\x98\xC2\xD1\xAD\xBF\xDF", 6},
      {"\xDE\xAD\xBE\xEF", 1, "FooBar", "\xEB\xD1\x80\x9C\xCC\xCC", 6},
      {"\xDE\xAD\xBE\xEF", 2, "FooBar", "\xF8\x80\xB1\xEF\xDF\x9D", 6},
      {"\xDE\xAD\xBE\xEF", 3, "FooBar", "\xA9\xB1\xC2\xFC\x8E\xAC", 6},
      {"\xDE\xAD\xBE\xEF", 4, "FooBar", "\x98\xC2\xD1\xAD\xBF\xDF", 6},
      {"\xDE\xAD\xBE\xEF", 42, "FooBar", "\xF8\x80\xB1\xEF\xDF\x9D", 6},
      {"\xDE\xAD\xBE\xEF", 0, "", "", 0},
      {"\xDE\xAD\xBE\xEF", 0, "\xDE\xAD\xBE\xEF", "\x00\x00\x00\x00", 4},
      {"\xDE\xAD\xBE\xEF", 0, "\x00\x00\x00\x00", "\xDE\xAD\xBE\xEF", 4},
      {{"\x00\x00\x00\x00", WebSocketFrameHeader::kMaskingKeyLength},
       0,
       "FooBar",
       "FooBar",
       6},
      {"\xFF\xFF\xFF\xFF", 0, "FooBar", "\xB9\x90\x90\xBD\x9E\x8D", 6},
  };

  for (const auto& test : kTests) {
    WebSocketMaskingKey masking_key;
    base::as_writable_byte_span(masking_key.key)
        .copy_from(base::as_byte_span(test.masking_key));
    std::vector<char> frame_data(test.input, test.input + test.data_length);
    std::vector<char> expected_output(test.output,
                                      test.output + test.data_length);
    MaskWebSocketFramePayload(masking_key, test.frame_offset,
                              base::as_writable_byte_span(frame_data));
    EXPECT_EQ(expected_output, frame_data);
  }
}

// Check that all combinations of alignment, frame offset and chunk size work
// correctly for MaskWebSocketFramePayload(). This is mainly used to ensure that
// vectorisation optimisations don't break anything. We could take a "white box"
// approach and only test the edge cases, but since the exhaustive "black box"
// approach runs in acceptable time, we don't have to take the risk of being
// clever.
//
// This brute-force approach runs in O(N^3) time where N is the size of the
// maximum vector size we want to test again. This might need reconsidering if
// MaskWebSocketFramePayload() is ever optimised for a dedicated vector
// architecture.
TEST(WebSocketFrameTest, MaskPayloadAlignment) {
  // This reflects what might be implemented in the future, rather than
  // the current implementation. FMA3 and FMA4 support 256-bit vector ops.
  static constexpr size_t kMaxVectorSizeInBits = 256;
  static constexpr size_t kMaxVectorSize = kMaxVectorSizeInBits / 8;
  static constexpr size_t kMaxVectorAlignment = kMaxVectorSize;
  static constexpr size_t kMaskingKeyLength =
      WebSocketFrameHeader::kMaskingKeyLength;
  static constexpr size_t kScratchBufferSize =
      kMaxVectorAlignment + kMaxVectorSize * 2;
  static constexpr std::string_view kTestMask = "\xd2\xba\x5a\xbe";
  // We use 786 bits of random input to reduce the risk of correlated errors.
  static constexpr char kTestInput[] = {
      "\x3d\x77\x1d\x1b\x19\x8c\x48\xa3\x19\x6d\xf7\xcc\x39\xe7\x57\x0b"
      "\x69\x8c\xda\x4b\xfc\xac\x2c\xd3\x49\x96\x6e\x8a\x7b\x5a\x32\x76"
      "\xd0\x11\x43\xa0\x89\xfc\x76\x2b\x10\x2f\x4c\x7b\x4f\xa6\xdd\xe4"
      "\xfc\x8e\xd8\x72\xcf\x7e\x37\xcd\x31\xcd\xc1\xc0\x89\x0c\xa7\x4c"
      "\xda\xa8\x4b\x75\xa1\xcb\xa9\x77\x19\x4d\x6e\xdf\xc8\x08\x1c\xb6"
      "\x6d\xfb\x38\x04\x44\xd5\xba\x57\x9f\x76\xb0\x2e\x07\x91\xe6\xa8"};
  static constexpr size_t kTestInputSize = std::size(kTestInput) - 1;
  static constexpr char kTestOutput[] = {
      "\xef\xcd\x47\xa5\xcb\x36\x12\x1d\xcb\xd7\xad\x72\xeb\x5d\x0d\xb5"
      "\xbb\x36\x80\xf5\x2e\x16\x76\x6d\x9b\x2c\x34\x34\xa9\xe0\x68\xc8"
      "\x02\xab\x19\x1e\x5b\x46\x2c\x95\xc2\x95\x16\xc5\x9d\x1c\x87\x5a"
      "\x2e\x34\x82\xcc\x1d\xc4\x6d\x73\xe3\x77\x9b\x7e\x5b\xb6\xfd\xf2"
      "\x08\x12\x11\xcb\x73\x71\xf3\xc9\xcb\xf7\x34\x61\x1a\xb2\x46\x08"
      "\xbf\x41\x62\xba\x96\x6f\xe0\xe9\x4d\xcc\xea\x90\xd5\x2b\xbc\x16"};
  static_assert(std::size(kTestInput) == std::size(kTestOutput),
                "output and input arrays should have the same length");
  std::unique_ptr<char, base::AlignedFreeDeleter> scratch(static_cast<char*>(
      base::AlignedAlloc(kScratchBufferSize, kMaxVectorAlignment)));
  WebSocketMaskingKey masking_key;
  base::as_writable_byte_span(masking_key.key)
      .copy_from(base::as_byte_span(kTestMask));
  for (size_t frame_offset = 0; frame_offset < kMaskingKeyLength;
       ++frame_offset) {
    for (size_t alignment = 0; alignment < kMaxVectorAlignment; ++alignment) {
      char* const aligned_scratch = scratch.get() + alignment;
      const size_t aligned_len = std::min(kScratchBufferSize - alignment,
                                          kTestInputSize - frame_offset);
      for (size_t chunk_size = 1; chunk_size < kMaxVectorSize; ++chunk_size) {
        memcpy(aligned_scratch, kTestInput + frame_offset, aligned_len);
        for (size_t chunk_start = 0; chunk_start < aligned_len;
             chunk_start += chunk_size) {
          const size_t this_chunk_size =
              std::min(chunk_size, aligned_len - chunk_start);
          MaskWebSocketFramePayload(
              masking_key, frame_offset + chunk_start,
              base::as_writable_bytes(base::make_span(
                  aligned_scratch + chunk_start, this_chunk_size)));
        }
        // Stop the test if it fails, since we don't want to spew thousands of
        // failures.
        ASSERT_TRUE(std::equal(aligned_scratch,
                               aligned_scratch + aligned_len,
                               kTestOutput + frame_offset))
            << "Output failed to match for frame_offset=" << frame_offset
            << ", alignment=" << alignment << ", chunk_size=" << chunk_size;
      }
    }
  }
}

// "IsKnownDataOpCode" is currently implemented in an "obviously correct"
// manner, but we test is anyway in case it changes to a more complex
// implementation in future.
TEST(WebSocketFrameHeaderTest, IsKnownDataOpCode) {
  // Make the test less verbose.
  using Frame = WebSocketFrameHeader;

  // Known opcode, is used for data frames
  EXPECT_TRUE(Frame::IsKnownDataOpCode(Frame::kOpCodeContinuation));
  EXPECT_TRUE(Frame::IsKnownDataOpCode(Frame::kOpCodeText));
  EXPECT_TRUE(Frame::IsKnownDataOpCode(Frame::kOpCodeBinary));

  // Known opcode, is used for control frames
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeClose));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodePing));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodePong));

  // Check that unused opcodes return false
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeDataUnused3));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeDataUnused4));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeDataUnused5));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeDataUnused6));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeDataUnused7));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeControlUnusedB));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeControlUnusedC));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeControlUnusedD));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeControlUnusedE));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(Frame::kOpCodeControlUnusedF));

  // Check that out-of-range opcodes return false
  EXPECT_FALSE(Frame::IsKnownDataOpCode(-1));
  EXPECT_FALSE(Frame::IsKnownDataOpCode(0xFF));
}

// "IsKnownControlOpCode" is implemented in an "obviously correct" manner but
// might be optimised in future.
TEST(WebSocketFrameHeaderTest, IsKnownControlOpCode) {
  // Make the test less verbose.
  using Frame = WebSocketFrameHeader;

  // Known opcode, is used for data frames
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeContinuation));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeText));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeBinary));

  // Known opcode, is used for control frames
  EXPECT_TRUE(Frame::IsKnownControlOpCode(Frame::kOpCodeClose));
  EXPECT_TRUE(Frame::IsKnownControlOpCode(Frame::kOpCodePing));
  EXPECT_TRUE(Frame::IsKnownControlOpCode(Frame::kOpCodePong));

  // Check that unused opcodes return false
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeDataUnused3));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeDataUnused4));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeDataUnused5));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeDataUnused6));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeDataUnused7));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeControlUnusedB));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeControlUnusedC));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeControlUnusedD));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeControlUnusedE));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(Frame::kOpCodeControlUnusedF));

  // Check that out-of-range opcodes return false
  EXPECT_FALSE(Frame::IsKnownControlOpCode(-1));
  EXPECT_FALSE(Frame::IsKnownControlOpCode(0xFF));
}

// Test for reserved data opcodes.
TEST(WebSocketFrameHeaderTest, IsReservedDataOpCode) {
  using Frame = WebSocketFrameHeader;

  // Known opcodes for data frames should not be reserved.
  EXPECT_FALSE(Frame::IsReservedDataOpCode(Frame::kOpCodeContinuation));
  EXPECT_FALSE(Frame::IsReservedDataOpCode(Frame::kOpCodeText));
  EXPECT_FALSE(Frame::IsReservedDataOpCode(Frame::kOpCodeBinary));

  // Unused opcodes in the data frame range should be considered reserved.
  EXPECT_TRUE(Frame::IsReservedDataOpCode(Frame::kOpCodeDataUnused3));
  EXPECT_TRUE(Frame::IsReservedDataOpCode(Frame::kOpCodeDataUnused4));
  EXPECT_TRUE(Frame::IsReservedDataOpCode(Frame::kOpCodeDataUnused5));
  EXPECT_TRUE(Frame::IsReservedDataOpCode(Frame::kOpCodeDataUnused6));
  EXPECT_TRUE(Frame::IsReservedDataOpCode(Frame::kOpCodeDataUnused7));

  // Known opcodes for control frames should not be considered reserved data
  // opcodes.
  EXPECT_FALSE(Frame::IsReservedDataOpCode(Frame::kOpCodeClose));
  EXPECT_FALSE(Frame::IsReservedDataOpCode(Frame::kOpCodePing));
  EXPECT_FALSE(Frame::IsReservedDataOpCode(Frame::kOpCodePong));

  // Out-of-range opcodes should not be considered reserved data opcodes.
  EXPECT_FALSE(Frame::IsReservedDataOpCode(-1));
  EXPECT_FALSE(Frame::IsReservedDataOpCode(0xFF));
}

// Test for reserved control opcodes.
TEST(WebSocketFrameHeaderTest, IsReservedControlOpCode) {
  using Frame = WebSocketFrameHeader;

  // Known opcodes for data frames should not be reserved control opcodes.
  EXPECT_FALSE(Frame::IsReservedControlOpCode(Frame::kOpCodeContinuation));
  EXPECT_FALSE(Frame::IsReservedControlOpCode(Frame::kOpCodeText));
  EXPECT_FALSE(Frame::IsReservedControlOpCode(Frame::kOpCodeBinary));

  // Known opcodes for control frames should not be reserved.
  EXPECT_FALSE(Frame::IsReservedControlOpCode(Frame::kOpCodeClose));
  EXPECT_FALSE(Frame::IsReservedControlOpCode(Frame::kOpCodePing));
  EXPECT_FALSE(Frame::IsReservedControlOpCode(Frame::kOpCodePong));

  // Unused opcodes in the control frame range should be considered reserved.
  EXPECT_TRUE(Frame::IsReservedControlOpCode(Frame::kOpCodeControlUnusedB));
  EXPECT_TRUE(Frame::IsReservedControlOpCode(Frame::kOpCodeControlUnusedC));
  EXPECT_TRUE(Frame::IsReservedControlOpCode(Frame::kOpCodeControlUnusedD));
  EXPECT_TRUE(Frame::IsReservedControlOpCode(Frame::kOpCodeControlUnusedE));
  EXPECT_TRUE(Frame::IsReservedControlOpCode(Frame::kOpCodeControlUnusedF));

  // Out-of-range opcodes should not be considered reserved control opcodes.
  EXPECT_FALSE(Frame::IsReservedControlOpCode(-1));
  EXPECT_FALSE(Frame::IsReservedControlOpCode(0xFF));
}

}  // namespace

}  // namespace net

"""

```
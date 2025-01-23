Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Understanding - What is this file about?**

The filename `web_socket_encoder_unittest.cc` immediately signals that this is a unit test file. The `web_socket_encoder` part tells us it's testing something related to encoding WebSocket messages. The `net` namespace confirms it's part of the networking stack.

**2. Examining the Includes:**

The included headers provide key insights:

* `#include "net/server/web_socket_encoder.h"`: This is the header file for the class being tested. So, the core functionality revolves around `WebSocketEncoder`.
* `<stddef.h>`, `"base/strings/strcat.h"`: Standard utility headers. `strcat` suggests string manipulation is involved.
* `"net/websockets/websocket_deflate_parameters.h"`: This points to handling the permessage-deflate extension for WebSocket compression.
* `"net/websockets/websocket_extension.h"`:  More general WebSocket extension handling.
* `"net/websockets/websocket_frame.h"`: Dealing with the structure of WebSocket frames (headers, payload, etc.).
* `"testing/gtest/include/gtest/gtest.h"`:  Confirms this is using Google Test as the testing framework.

**3. Analyzing the Test Structure (using GTest conventions):**

* `TEST(TestSuiteName, TestName)`:  This is the basic structure of a GTest test case.
* `EXPECT_...` and `ASSERT_...`: These are GTest assertion macros. `ASSERT_` will stop the test if the condition is false, while `EXPECT_` will continue the test but mark it as failed.

**4. Categorizing the Tests:**

Reading through the tests, clear categories emerge:

* **Handshake Tests (`WebSocketEncoderHandshakeTest`):** These tests focus on the server-side handling of the initial WebSocket handshake, specifically the `permessage-deflate` extension. They check how the server parses and chooses an extension based on the client's request.
* **General Encoder/Decoder Tests (`WebSocketEncoderTest`):** These tests cover the basic encoding and decoding of WebSocket frames, both text and potentially other types (though the examples are mostly text). They test both client-to-server and server-to-client scenarios, with and without masking. Fragmentation is also covered.
* **Compression Tests (`WebSocketEncoderCompressionTest`):** These tests specifically examine the behavior of the encoder and decoder when compression is enabled (`permessage-deflate`). They check if messages are compressed and correctly decompressed. They also include tests to ensure certain control frames (Pong and Close) are *not* compressed.

**5. Identifying Core Functionality by Observing Tests:**

By examining what the tests are *doing*, we can infer the core functions of `WebSocketEncoder`:

* `CreateServer()`: Creates a server-side encoder, possibly taking extension parameters.
* `CreateClient()`: Creates a client-side encoder, possibly taking accepted extension parameters.
* `deflate_enabled()`:  Indicates if compression is enabled for this encoder.
* `EncodeTextFrame()`:  Encodes a text payload into a WebSocket frame, handling masking.
* `DecodeFrame()`: Decodes a received WebSocket frame, returning the payload and status.
* `EncodePongFrame()`: Encodes a Pong control frame.
* `EncodeCloseFrame()`: Encodes a Close control frame.

**6. Looking for JavaScript Relevance:**

WebSocket is inherently tied to JavaScript in web browsers. The key connection is the `WebSocket` API in JavaScript. The C++ code in this file is part of the *server-side implementation* (or potentially a testing utility that simulates a server). Therefore, the JavaScript interaction occurs when a browser (running JavaScript) connects to a server using the WebSocket protocol.

**7. Logical Reasoning (Assumptions and Outputs):**

For the handshake tests, the input is the `Sec-WebSocket-Extensions` header value (simulated in the test). The output is the chosen extension string and whether compression is enabled. For encoding/decoding tests, the input is a string and a mask (for client-side encoding). The output is the encoded frame, and in the decoding tests, the decoded string and the number of bytes consumed.

**8. Identifying Common Usage Errors:**

The tests themselves highlight potential errors. For example, the `EmptyRequestShouldBeRejected` test shows that providing an empty string for server creation is an error. The fragmentation tests show the importance of handling intermediate frames correctly. A common user error on the JavaScript side would be sending malformed data or not handling fragmented messages correctly. On the C++ side, an error might be incorrectly implementing the extension negotiation logic.

**9. Tracing User Operations (Debugging Clues):**

This requires thinking about how a user interacting with a web application triggers WebSocket communication:

* **User Action in Browser:** The user might click a button, submit a form, or the page might automatically try to establish a WebSocket connection on load.
* **JavaScript `WebSocket` API:** The JavaScript code uses the `WebSocket` API to initiate the connection to a server.
* **Handshake:** The browser sends an HTTP Upgrade request with WebSocket-specific headers, including `Sec-WebSocket-Extensions`. The server (where this C++ code runs) processes this request. The handshake tests simulate this server-side processing of the `Sec-WebSocket-Extensions` header.
* **Data Transmission:** After the handshake, JavaScript uses `websocket.send()` to send data. This data gets encoded by the browser's WebSocket implementation. On the server, the `WebSocketEncoder::DecodeFrame` function (being tested here) processes the incoming data.
* **Server Response:** The server might send data back using its own `WebSocketEncoder` to encode the data before sending it. The browser's WebSocket API receives and decodes this data.

**Self-Correction/Refinement during the Process:**

* Initially, I might focus too much on just the encoding/decoding aspects. However, the "Handshake" tests clearly indicate a significant part of the functionality is about the initial connection setup and extension negotiation.
* When considering JavaScript relevance, it's crucial to distinguish between the *server-side* C++ code and the *client-side* JavaScript API. The C++ code *implements* the server logic that the JavaScript code interacts with.
* When thinking about user errors, it's helpful to consider errors on *both* the client (JavaScript) side and the server (C++) side.

By following these steps, analyzing the code structure, the test cases, and connecting it to the broader context of WebSocket communication, we can arrive at a comprehensive understanding of the file's functionality and its role in the Chromium networking stack.
这个文件 `net/server/web_socket_encoder_unittest.cc` 是 Chromium 网络栈中用于测试 `WebSocketEncoder` 类的单元测试文件。它的主要功能是验证 `WebSocketEncoder` 类的各种功能是否按预期工作，包括：

**1. WebSocket 握手（Handshake）时的扩展协商：**

* **功能:** 测试服务器端 `WebSocketEncoder::CreateServer()` 方法在处理 `Sec-WebSocket-Extensions` 头部时的行为。这包括解析客户端请求的扩展列表，选择合适的扩展，并将其配置到 `WebSocketDeflateParameters` 中。
* **与 JavaScript 的关系:** 当 JavaScript 代码使用 `WebSocket` API 连接到服务器时，可以通过 `options` 参数设置 `protocols` 和 `extensions`。`extensions` 数组会被转换成 `Sec-WebSocket-Extensions` 头部发送给服务器。
* **举例说明:**
    * **假设输入 (客户端发送的 Sec-WebSocket-Extensions):**  `permessage-deflate; client_max_window_bits, another-extension`
    * **假设输出 (服务器选择的扩展):**  `permessage-deflate; client_max_window_bits=15` (假设服务器支持并选择了 `permessage-deflate` 扩展)
* **逻辑推理:** 测试会模拟服务器接收到不同的 `Sec-WebSocket-Extensions` 头部，验证服务器是否能正确解析并选择第一个有效的 `permessage-deflate` 扩展及其参数。如果客户端请求了多个 `permessage-deflate` 扩展，服务器应该选择第一个它支持的。
* **用户/编程常见错误:**  客户端 JavaScript 可能请求了服务器不支持的扩展，或者扩展参数格式错误。服务器端可能无法正确解析客户端发送的扩展列表。

**2. WebSocket 帧的编码与解码：**

* **功能:** 测试 `WebSocketEncoder` 类的 `EncodeTextFrame()` 方法用于将文本数据编码成 WebSocket 帧，以及 `DecodeFrame()` 方法用于解码接收到的 WebSocket 帧。测试涵盖了客户端到服务器和服务器到客户端的通信，包括是否使用掩码（mask）。
* **与 JavaScript 的关系:**
    * **编码:** 当 JavaScript 代码调用 `websocket.send(data)` 发送数据时，浏览器内部的 WebSocket 实现会负责将 `data` 编码成 WebSocket 帧，其中对于客户端发送的帧会添加掩码。
    * **解码:** 当浏览器接收到来自服务器的 WebSocket 帧时，浏览器的 WebSocket 实现会负责解码帧数据，并将有效载荷传递给 JavaScript 的 `onmessage` 事件。
* **举例说明:**
    * **假设输入 (客户端编码):**  `frame = "Hello"`，`mask = 123456`
    * **假设输出 (编码后的帧):**  一个包含 WebSocket 头部、掩码和加密后 "Hello" 的二进制字符串。
    * **假设输入 (服务器解码):**  上面编码后的帧
    * **假设输出 (解码后的数据):**  `decoded = "Hello"`， `bytes_consumed = 编码后帧的长度`
* **逻辑推理:** 测试会创建客户端和服务器端的 `WebSocketEncoder` 实例，分别进行编码和解码操作，验证解码后的数据是否与原始数据一致，以及 `DecodeFrame()` 方法是否能正确处理完整和不完整的帧。
* **用户/编程常见错误:**
    * **客户端:**  忘记在发送帧时添加掩码（虽然浏览器会自动处理，但在某些底层实现或手动构建帧的场景下可能发生）。
    * **服务器:**  未能正确解码客户端发送的带有掩码的帧。
    * **双方:**  在处理分片消息时出现逻辑错误，导致消息丢失或顺序错乱。

**3. WebSocket 消息分片（Fragmentation）的处理：**

* **功能:** 测试 `WebSocketEncoder` 类处理分片消息的能力。WebSocket 允许将一个大的消息分割成多个小的帧进行发送，接收端需要将这些帧重新组装成完整的消息。
* **与 JavaScript 的关系:**  JavaScript 的 `WebSocket` API 会透明地处理消息分片。开发者无需手动分割或组装帧。当发送大数据时，浏览器可能会自动将其分片；当接收到分片消息时，`onmessage` 事件会在所有分片都到达后触发，并提供完整的消息数据。
* **举例说明:**
    * **假设输入 (客户端分片发送):**  将字符串 "abcdefghijklmnop" 分成两个帧发送。
    * **假设输出 (服务器解码):**  `DecodeFrame()` 先对第一个帧返回 `FRAME_OK_MIDDLE`，解码后的数据为空；然后对第二个帧返回 `FRAME_OK_FINAL`，解码后的数据为 "abcdefghijklmnop"。
* **逻辑推理:** 测试会生成分片的 WebSocket 帧，并按顺序传递给解码器，验证解码器是否能正确识别中间帧和最终帧，并将它们组装成原始消息。
* **用户/编程常见错误:**  在手动实现 WebSocket 协议时，可能没有正确设置帧头部的 FIN 比特和操作码，导致接收端无法正确识别分片消息。

**4. WebSocket 压缩 (permessage-deflate) 的处理：**

* **功能:** 测试当启用 `permessage-deflate` 扩展时，`WebSocketEncoder` 类的压缩和解压缩功能。
* **与 JavaScript 的关系:**  如果客户端和服务器都支持 `permessage-deflate` 扩展，并且在握手阶段协商成功，那么后续的数据帧可以进行压缩以减少网络传输量。JavaScript 的 `WebSocket` API 会自动处理压缩和解压缩，开发者无需关心细节。
* **举例说明:**
    * **假设输入 (客户端压缩编码):**  `frame = "Long string to compress"`
    * **假设输出 (编码后的帧):**  一个长度小于原始字符串的二进制帧，表示数据被压缩了。
    * **假设输入 (服务器解压缩解码):**  上面压缩后的帧
    * **假设输出 (解码后的数据):**  `decoded = "Long string to compress"`
* **逻辑推理:** 测试会创建启用压缩的 `WebSocketEncoder` 实例，发送较长的文本数据，验证编码后的帧长度是否小于原始数据长度，以及解码后数据是否与原始数据一致。
* **用户/编程常见错误:**  客户端或服务器的配置问题导致压缩协商失败，从而无法使用压缩功能。服务器端可能无法正确解压缩客户端发送的压缩数据。

**5. 控制帧的处理 (例如 Pong 和 Close)：**

* **功能:** 测试 `WebSocketEncoder` 类对控制帧的编码，并验证某些控制帧是否按照规范不应该被压缩。
* **与 JavaScript 的关系:**  JavaScript 的 `WebSocket` API 提供 `send()` 方法发送数据帧，但对于控制帧（如 Ping 和 Close），浏览器会自动处理。开发者可以使用 `send()` 发送数据，但无法直接发送底层的控制帧。浏览器会自动响应服务器发送的 Ping 帧，并提供 `close()` 方法来发起关闭连接。
* **举例说明:**  测试会编码一个 Pong 帧和一个 Close 帧，并断言它们的压缩位没有被设置。
* **逻辑推理:**  根据 WebSocket 协议规范，某些控制帧（如 Pong 和 Close）不应该被压缩。测试会验证 `WebSocketEncoder` 在编码这些帧时是否遵循了这个规定。
* **用户/编程常见错误:**  在手动实现 WebSocket 协议时，可能错误地压缩了控制帧，导致通信异常。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个支持 WebSocket 的网页。**
2. **网页中的 JavaScript 代码创建了一个 `WebSocket` 对象，并尝试连接到服务器。** 这会触发浏览器的网络栈发起 WebSocket 握手请求。
3. **浏览器将 JavaScript 代码设置的 `extensions` 选项（如果有）添加到 `Sec-WebSocket-Extensions` 头部中。**
4. **Chromium 的网络栈接收到服务器的握手响应，并创建一个 `WebSocketEncoder` 实例。** 如果服务器在 `Sec-WebSocket-Extensions` 头部中声明支持 `permessage-deflate`，那么创建的 `WebSocketEncoder` 可能会启用压缩。相关的测试用例就是 `WebSocketEncoderHandshakeTest` 中的测试。
5. **当 JavaScript 代码调用 `websocket.send(data)` 发送数据时，浏览器会调用 `WebSocketEncoder::EncodeTextFrame()` (或其他编码方法) 将数据编码成 WebSocket 帧。** 如果启用了压缩，编码过程会包含压缩步骤。相关的测试用例是 `WebSocketEncoderTest` 和 `WebSocketEncoderCompressionTest` 中测试编码功能的用例。
6. **编码后的帧通过网络发送到服务器。**
7. **服务器接收到 WebSocket 帧，并使用 `WebSocketEncoder::DecodeFrame()` 方法进行解码。** 解码过程可能包含解压缩步骤。相关的测试用例是 `WebSocketEncoderTest` 和 `WebSocketEncoderCompressionTest` 中测试解码功能的用例。
8. **如果消息被分片发送，服务器的 `DecodeFrame()` 方法会多次被调用，直到接收到完整的消息。** 相关的测试用例是 `WebSocketEncoderTest` 和 `WebSocketEncoderCompressionTest` 中测试分片消息处理的用例。

**调试线索:**

如果在使用 WebSocket 的过程中出现问题，例如握手失败、消息无法正确发送或接收、数据损坏等，可以查看以下信息作为调试线索：

* **网络请求和响应头部:**  检查 `Sec-WebSocket-Extensions` 头部的值，确认客户端和服务器协商的扩展是否符合预期。
* **WebSocket 帧的内容:**  可以使用网络抓包工具（如 Wireshark）查看实际发送和接收的 WebSocket 帧的内容，包括帧头部的各个比特位、掩码和有效载荷。
* **浏览器开发者工具:**  浏览器的开发者工具通常会提供 WebSocket 连接的详细信息，包括发送和接收的消息内容。
* **服务器日志:**  服务器端的日志可能会记录 WebSocket 连接的状态、接收到的帧信息以及发生的错误。
* **单元测试:**  查看 `web_socket_encoder_unittest.cc` 中的测试用例，可以了解 `WebSocketEncoder` 类的预期行为，并作为排查问题的参考。例如，如果怀疑是压缩功能导致的问题，可以参考 `WebSocketEncoderCompressionTest` 中的测试用例。

总而言之，`net/server/web_socket_encoder_unittest.cc` 是一个关键的测试文件，它确保了 Chromium 网络栈中 WebSocket 编码器功能的正确性，涵盖了握手、编码、解码、分片和压缩等核心方面，对于理解和调试 WebSocket 相关问题非常有帮助。

### 提示词
```
这是目录为net/server/web_socket_encoder_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/server/web_socket_encoder.h"

#include <stddef.h>

#include "base/strings/strcat.h"
#include "net/websockets/websocket_deflate_parameters.h"
#include "net/websockets/websocket_extension.h"
#include "net/websockets/websocket_frame.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

TEST(WebSocketEncoderHandshakeTest, EmptyRequestShouldBeRejected) {
  WebSocketDeflateParameters params;
  std::unique_ptr<WebSocketEncoder> server =
      WebSocketEncoder::CreateServer("", &params);

  EXPECT_FALSE(server);
}

TEST(WebSocketEncoderHandshakeTest,
     CreateServerWithoutClientMaxWindowBitsParameter) {
  WebSocketDeflateParameters params;
  std::unique_ptr<WebSocketEncoder> server =
      WebSocketEncoder::CreateServer("permessage-deflate", &params);

  ASSERT_TRUE(server);
  EXPECT_TRUE(server->deflate_enabled());
  EXPECT_EQ("permessage-deflate", params.AsExtension().ToString());
}

TEST(WebSocketEncoderHandshakeTest,
     CreateServerWithServerNoContextTakeoverParameter) {
  WebSocketDeflateParameters params;
  std::unique_ptr<WebSocketEncoder> server = WebSocketEncoder::CreateServer(
      "permessage-deflate; server_no_context_takeover", &params);
  ASSERT_TRUE(server);
  EXPECT_TRUE(server->deflate_enabled());
  EXPECT_EQ("permessage-deflate; server_no_context_takeover",
            params.AsExtension().ToString());
}

TEST(WebSocketEncoderHandshakeTest, FirstExtensionShouldBeChosen) {
  WebSocketDeflateParameters params;
  std::unique_ptr<WebSocketEncoder> server = WebSocketEncoder::CreateServer(
      "permessage-deflate; server_no_context_takeover,"
      "permessage-deflate; server_max_window_bits=15",
      &params);

  ASSERT_TRUE(server);
  EXPECT_TRUE(server->deflate_enabled());
  EXPECT_EQ("permessage-deflate; server_no_context_takeover",
            params.AsExtension().ToString());
}

TEST(WebSocketEncoderHandshakeTest, FirstValidExtensionShouldBeChosen) {
  WebSocketDeflateParameters params;
  std::unique_ptr<WebSocketEncoder> server = WebSocketEncoder::CreateServer(
      "permessage-deflate; Xserver_no_context_takeover,"
      "permessage-deflate; server_max_window_bits=15",
      &params);

  ASSERT_TRUE(server);
  EXPECT_TRUE(server->deflate_enabled());
  EXPECT_EQ("permessage-deflate; server_max_window_bits=15",
            params.AsExtension().ToString());
}

TEST(WebSocketEncoderHandshakeTest, AllExtensionsAreUnknownOrMalformed) {
  WebSocketDeflateParameters params;
  std::unique_ptr<WebSocketEncoder> server =
      WebSocketEncoder::CreateServer("unknown, permessage-deflate; x", &params);

  ASSERT_TRUE(server);
  EXPECT_FALSE(server->deflate_enabled());
}

class WebSocketEncoderTest : public testing::Test {
 public:
  WebSocketEncoderTest() = default;

  void SetUp() override {
    std::string response_extensions;
    server_ = WebSocketEncoder::CreateServer();
    EXPECT_EQ(std::string(), response_extensions);
    client_ = WebSocketEncoder::CreateClient("");
  }

  // Generate deflated and continuous frames from original text.
  // The length of `original_text` must be longer than 4*partitions.
  std::vector<std::string> GenerateFragmentedFrames(std::string original_text,
                                                    int mask,
                                                    int partitions,
                                                    bool compressed) {
    constexpr uint8_t kFinalBit = 0x80;
    constexpr uint8_t kReserved1Bit = 0x40;
    constexpr uint8_t kMaskBit = 0x80;

    // A frame consists of 3 or 2 parts: header, (mask) and payload.
    // The first two bytes of `encoded` are the header of the frame.
    // If there is a mask, the four bytes of the mask is inserted after the
    // header. Finally, message contents come.
    std::string encoded;
    int num_mask_header;
    char mask_key_bit;
    std::string mask_bytes;

    if (mask == 0) {
      server_->EncodeTextFrame(original_text, mask, &encoded);
      num_mask_header = 0;
      mask_key_bit = 0;
    } else {
      client_->EncodeTextFrame(original_text, mask, &encoded);
      num_mask_header = 4;
      mask_key_bit = kMaskBit;
      mask_bytes = encoded.substr(2, 4);
    }
    int divide_length =
        (static_cast<int>(encoded.length()) - 2 - num_mask_header) / partitions;
    divide_length -= divide_length % 4;
    std::vector<std::string> encoded_frames(partitions);
    std::string payload;
    std::string header;

    for (int i = 0; i < partitions; ++i) {
      char first_byte = 0;
      if (i == 0)
        first_byte |= WebSocketFrameHeader::OpCodeEnum::kOpCodeText;
      else
        first_byte |= WebSocketFrameHeader::OpCodeEnum::kOpCodeContinuation;
      if (i == partitions - 1)
        first_byte |= kFinalBit;
      if (compressed)
        first_byte |= kReserved1Bit;

      const int position = 2 + num_mask_header + i * divide_length;
      const int length =
          i < partitions - 1 ? divide_length : encoded.length() - position;
      payload = encoded.substr(position, length);
      header = {first_byte, static_cast<char>(payload.length() | mask_key_bit)};
      encoded_frames[i] += header + mask_bytes + payload;
    }

    return encoded_frames;
  }

 protected:
  std::unique_ptr<WebSocketEncoder> server_;
  std::unique_ptr<WebSocketEncoder> client_;
};

class WebSocketEncoderCompressionTest : public WebSocketEncoderTest {
 public:
  WebSocketEncoderCompressionTest() : WebSocketEncoderTest() {}

  void SetUp() override {
    WebSocketDeflateParameters params;
    server_ = WebSocketEncoder::CreateServer(
        "permessage-deflate; client_max_window_bits", &params);
    ASSERT_TRUE(server_);
    EXPECT_TRUE(server_->deflate_enabled());
    EXPECT_EQ("permessage-deflate; client_max_window_bits=15",
              params.AsExtension().ToString());
    client_ = WebSocketEncoder::CreateClient(params.AsExtension().ToString());
  }
};

TEST_F(WebSocketEncoderTest, DeflateDisabledEncoder) {
  std::unique_ptr<WebSocketEncoder> server = WebSocketEncoder::CreateServer();
  std::unique_ptr<WebSocketEncoder> client = WebSocketEncoder::CreateClient("");

  ASSERT_TRUE(server);
  ASSERT_TRUE(client);

  EXPECT_FALSE(server->deflate_enabled());
  EXPECT_FALSE(client->deflate_enabled());
}

TEST_F(WebSocketEncoderTest, ClientToServer) {
  std::string frame("ClientToServer");
  int mask = 123456;
  std::string encoded;
  int bytes_consumed;
  std::string decoded;

  client_->EncodeTextFrame(frame, mask, &encoded);
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            server_->DecodeFrame(encoded, &bytes_consumed, &decoded));
  EXPECT_EQ("ClientToServer", decoded);
  EXPECT_EQ((int)encoded.length(), bytes_consumed);

  std::string partial = encoded.substr(0, encoded.length() - 2);
  EXPECT_EQ(WebSocketParseResult::FRAME_INCOMPLETE,
            server_->DecodeFrame(partial, &bytes_consumed, &decoded));

  std::string extra = encoded + "more stuff";
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            server_->DecodeFrame(extra, &bytes_consumed, &decoded));
  EXPECT_EQ("ClientToServer", decoded);
  EXPECT_EQ((int)encoded.length(), bytes_consumed);

  EXPECT_EQ(
      WebSocketParseResult::FRAME_ERROR,
      server_->DecodeFrame(std::string("abcde"), &bytes_consumed, &decoded));
}

TEST_F(WebSocketEncoderTest, ServerToClient) {
  std::string frame("ServerToClient");
  int mask = 0;
  std::string encoded;
  int bytes_consumed;
  std::string decoded;

  server_->EncodeTextFrame(frame, mask, &encoded);
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            client_->DecodeFrame(encoded, &bytes_consumed, &decoded));
  EXPECT_EQ("ServerToClient", decoded);
  EXPECT_EQ((int)encoded.length(), bytes_consumed);

  std::string partial = encoded.substr(0, encoded.length() - 2);
  EXPECT_EQ(WebSocketParseResult::FRAME_INCOMPLETE,
            client_->DecodeFrame(partial, &bytes_consumed, &decoded));

  std::string extra = encoded + "more stuff";
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            client_->DecodeFrame(extra, &bytes_consumed, &decoded));
  EXPECT_EQ("ServerToClient", decoded);
  EXPECT_EQ((int)encoded.length(), bytes_consumed);

  EXPECT_EQ(
      WebSocketParseResult::FRAME_ERROR,
      client_->DecodeFrame(std::string("abcde"), &bytes_consumed, &decoded));
}

TEST_F(WebSocketEncoderTest, DecodeFragmentedMessageClientToServerDivided2) {
  const std::string kOriginalText = "abcdefghijklmnop";
  constexpr int kMask = 123456;
  constexpr bool kCompressed = false;
  constexpr int kPartitions = 2;
  ASSERT_GT(static_cast<int>(kOriginalText.length()), 4 * kPartitions);
  std::vector<std::string> encoded_frames =
      GenerateFragmentedFrames(kOriginalText, kMask, kPartitions, kCompressed);
  ASSERT_EQ(kPartitions, static_cast<int>(encoded_frames.size()));

  const std::string& kEncodedFirstFrame = encoded_frames[0];
  const std::string& kEncodedLastFrame = encoded_frames[1];

  int bytes_consumed;
  std::string decoded;

  // kEncodedFirstFrame -> kEncodedLastFrame
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      server_->DecodeFrame(kEncodedFirstFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedFirstFrame.length()), bytes_consumed);
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            server_->DecodeFrame(kEncodedLastFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("abcdefghijklmnop", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedLastFrame.length()), bytes_consumed);
}

TEST_F(WebSocketEncoderTest, DecodeFragmentedMessageClientToServerDivided3) {
  const std::string kOriginalText = "abcdefghijklmnop";
  constexpr int kMask = 123456;
  constexpr bool kCompressed = false;
  constexpr int kPartitions = 3;
  ASSERT_GT(static_cast<int>(kOriginalText.length()), 4 * kPartitions);
  std::vector<std::string> encoded_frames =
      GenerateFragmentedFrames(kOriginalText, kMask, kPartitions, kCompressed);
  ASSERT_EQ(kPartitions, static_cast<int>(encoded_frames.size()));

  const std::string& kEncodedFirstFrame = encoded_frames[0];
  const std::string& kEncodedSecondFrame = encoded_frames[1];
  const std::string& kEncodedLastFrame = encoded_frames[2];

  int bytes_consumed;
  std::string decoded;

  // kEncodedFirstFrame -> kEncodedSecondFrame -> kEncodedLastFrame
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      server_->DecodeFrame(kEncodedFirstFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedFirstFrame.length()), bytes_consumed);
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      server_->DecodeFrame(kEncodedSecondFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedSecondFrame.length()), bytes_consumed);
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            server_->DecodeFrame(kEncodedLastFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("abcdefghijklmnop", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedLastFrame.length()), bytes_consumed);
}

TEST_F(WebSocketEncoderTest, DecodeFragmentedMessageServerToClientDivided2) {
  const std::string kOriginalText = "abcdefghijklmnop";
  constexpr int kMask = 0;
  constexpr bool kCompressed = false;

  constexpr int kPartitions = 2;
  ASSERT_GT(static_cast<int>(kOriginalText.length()), 4 * kPartitions);
  std::vector<std::string> encoded_frames =
      GenerateFragmentedFrames(kOriginalText, kMask, kPartitions, kCompressed);
  ASSERT_EQ(kPartitions, static_cast<int>(encoded_frames.size()));

  const std::string& kEncodedFirstFrame = encoded_frames[0];
  const std::string& kEncodedLastFrame = encoded_frames[1];

  int bytes_consumed;
  std::string decoded;

  // kEncodedFirstFrame -> kEncodedLastFrame
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      client_->DecodeFrame(kEncodedFirstFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedFirstFrame.length()), bytes_consumed);
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            client_->DecodeFrame(kEncodedLastFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("abcdefghijklmnop", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedLastFrame.length()), bytes_consumed);
}

TEST_F(WebSocketEncoderTest, DecodeFragmentedMessageServerToClientDivided3) {
  const std::string kOriginalText = "abcdefghijklmnop";
  constexpr int kMask = 0;
  constexpr bool kCompressed = false;

  constexpr int kPartitions = 3;
  ASSERT_GT(static_cast<int>(kOriginalText.length()), 4 * kPartitions);
  std::vector<std::string> encoded_frames =
      GenerateFragmentedFrames(kOriginalText, kMask, kPartitions, kCompressed);
  ASSERT_EQ(kPartitions, static_cast<int>(encoded_frames.size()));

  const std::string& kEncodedFirstFrame = encoded_frames[0];
  const std::string& kEncodedSecondFrame = encoded_frames[1];
  const std::string& kEncodedLastFrame = encoded_frames[2];

  int bytes_consumed;
  std::string decoded;

  // kEncodedFirstFrame -> kEncodedSecondFrame -> kEncodedLastFrame
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      client_->DecodeFrame(kEncodedFirstFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedFirstFrame.length()), bytes_consumed);
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      client_->DecodeFrame(kEncodedSecondFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedSecondFrame.length()), bytes_consumed);
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            client_->DecodeFrame(kEncodedLastFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("abcdefghijklmnop", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedLastFrame.length()), bytes_consumed);
}

TEST_F(WebSocketEncoderCompressionTest, ClientToServer) {
  std::string frame("CompressionCompressionCompressionCompression");
  int mask = 654321;
  std::string encoded;
  int bytes_consumed;
  std::string decoded;

  client_->EncodeTextFrame(frame, mask, &encoded);
  EXPECT_LT(encoded.length(), frame.length());
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            server_->DecodeFrame(encoded, &bytes_consumed, &decoded));
  EXPECT_EQ(frame, decoded);
  EXPECT_EQ((int)encoded.length(), bytes_consumed);
}

TEST_F(WebSocketEncoderCompressionTest, ServerToClient) {
  std::string frame("CompressionCompressionCompressionCompression");
  int mask = 0;
  std::string encoded;
  int bytes_consumed;
  std::string decoded;

  server_->EncodeTextFrame(frame, mask, &encoded);
  EXPECT_LT(encoded.length(), frame.length());
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            client_->DecodeFrame(encoded, &bytes_consumed, &decoded));
  EXPECT_EQ(frame, decoded);
  EXPECT_EQ((int)encoded.length(), bytes_consumed);
}

TEST_F(WebSocketEncoderCompressionTest, LongFrame) {
  int length = 1000000;
  std::string temp;
  temp.reserve(length);
  for (int i = 0; i < length; ++i)
    temp += (char)('a' + (i % 26));

  std::string frame;
  frame.reserve(length);
  for (int i = 0; i < length; ++i) {
    int64_t j = i;
    frame += temp[(j * j) % length];
  }

  int mask = 0;
  std::string encoded;
  int bytes_consumed;
  std::string decoded;

  server_->EncodeTextFrame(frame, mask, &encoded);
  EXPECT_LT(encoded.length(), frame.length());
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            client_->DecodeFrame(encoded, &bytes_consumed, &decoded));
  EXPECT_EQ(frame, decoded);
  EXPECT_EQ((int)encoded.length(), bytes_consumed);
}

TEST_F(WebSocketEncoderCompressionTest, DecodeFragmentedMessageClientToServer) {
  const std::string kOriginalText = "abcdefghijklmnop";
  constexpr int kMask = 123456;

  constexpr int kPartitions = 3;
  constexpr bool kCompressed = true;
  ASSERT_GT(static_cast<int>(kOriginalText.length()), 4 * kPartitions);
  std::vector<std::string> encoded_frames =
      GenerateFragmentedFrames(kOriginalText, kMask, kPartitions, kCompressed);
  ASSERT_EQ(kPartitions, static_cast<int>(encoded_frames.size()));

  const std::string& kEncodedFirstFrame = encoded_frames[0];
  const std::string& kEncodedSecondFrame = encoded_frames[1];
  const std::string& kEncodedLastFrame = encoded_frames[2];

  int bytes_consumed;
  std::string decoded;

  // kEncodedFirstFrame -> kEncodedSecondFrame -> kEncodedLastFrame
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      server_->DecodeFrame(kEncodedFirstFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedFirstFrame.length()), bytes_consumed);
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      server_->DecodeFrame(kEncodedSecondFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedSecondFrame.length()), bytes_consumed);
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            server_->DecodeFrame(kEncodedLastFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("abcdefghijklmnop", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedLastFrame.length()), bytes_consumed);
}

TEST_F(WebSocketEncoderCompressionTest, DecodeFragmentedMessageServerToClient) {
  const std::string kOriginalText = "abcdefghijklmnop";
  constexpr int kMask = 0;

  constexpr int kPartitions = 3;
  constexpr bool kCompressed = true;
  ASSERT_GT(static_cast<int>(kOriginalText.length()), 4 * kPartitions);
  std::vector<std::string> encoded_frames =
      GenerateFragmentedFrames(kOriginalText, kMask, kPartitions, kCompressed);
  ASSERT_EQ(kPartitions, static_cast<int>(encoded_frames.size()));

  const std::string& kEncodedFirstFrame = encoded_frames[0];
  const std::string& kEncodedSecondFrame = encoded_frames[1];
  const std::string& kEncodedLastFrame = encoded_frames[2];

  int bytes_consumed;
  std::string decoded;

  // kEncodedFirstFrame -> kEncodedSecondFrame -> kEncodedLastFrame
  decoded.clear();
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      client_->DecodeFrame(kEncodedFirstFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedFirstFrame.length()), bytes_consumed);
  EXPECT_EQ(
      WebSocketParseResult::FRAME_OK_MIDDLE,
      client_->DecodeFrame(kEncodedSecondFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedSecondFrame.length()), bytes_consumed);
  EXPECT_EQ(WebSocketParseResult::FRAME_OK_FINAL,
            client_->DecodeFrame(kEncodedLastFrame, &bytes_consumed, &decoded));
  EXPECT_EQ("abcdefghijklmnop", decoded);
  EXPECT_EQ(static_cast<int>(kEncodedLastFrame.length()), bytes_consumed);
}

TEST_F(WebSocketEncoderCompressionTest, CheckPongFrameNotCompressed) {
  constexpr uint8_t kReserved1Bit = 0x40;
  const std::string kOriginalText = "abcdefghijklmnop";
  constexpr int kMask = 0;
  std::string encoded;

  server_->EncodePongFrame(kOriginalText, kMask, &encoded);
  EXPECT_FALSE(encoded[1] & kReserved1Bit);
  EXPECT_EQ(kOriginalText, encoded.substr(2));
}

TEST_F(WebSocketEncoderCompressionTest, CheckCloseFrameNotCompressed) {
  constexpr uint8_t kReserved1Bit = 0x40;
  const std::string kOriginalText = "\x03\xe8";
  constexpr int kMask = 0;
  std::string encoded;

  server_->EncodeCloseFrame(kOriginalText, kMask, &encoded);
  EXPECT_FALSE(encoded[1] & kReserved1Bit);
  EXPECT_EQ(kOriginalText, encoded.substr(2));
}

}  // namespace net
```
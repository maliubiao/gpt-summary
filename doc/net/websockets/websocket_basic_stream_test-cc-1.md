Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `websocket_basic_stream_test.cc` file. This is the second part of a two-part request.

I need to:

1. **Summarize the functionality** of the provided code. Since this is the second part, I should focus on the tests included here and build upon the summary from the first part (which I don't have, but can infer).
2. **Identify connections to JavaScript functionality.** WebSocket is a browser API, so there should be connections. I'll need to explain how the tested C++ code relates to the JavaScript WebSocket API.
3. **Provide examples of logical reasoning with inputs and outputs.**  This likely means explaining how the test cases work, what input (mocked network data) is given, and what output (expected errors or successful frame processing) is verified.
4. **Give examples of common user/programming errors.** I'll need to think about what could go wrong when using WebSockets from a developer's perspective and how these tests might catch those errors.
5. **Explain how a user's actions might lead to this code being executed (debugging context).**  This involves tracing the path from a user interacting with a web page to the underlying network code.

**Plan for Part 2:**

* **Functionality:**  Focus on the test cases for handling invalid WebSocket frames (synchronous and asynchronous), control frames (invalid FIN, overlong), fragmented control frames, multiple control frames in one read, control frame assembly (sync and async), handling large data frames, reserved flags, and writing frames (at once, asynchronously, in bits, with null/non-null masks). Also cover getting extensions/subprotocol and read buffer size management.
* **JavaScript Connection:** Explain how these tests relate to handling invalid WebSocket messages or ensuring correct sending/receiving of data from a JavaScript WebSocket object.
* **Logical Reasoning:** For each test case, describe the mocked input and expected output (e.g., `kInvalidFrame` input leads to `ERR_WS_PROTOCOL_ERROR`).
* **User/Programming Errors:**  Examples include sending malformed WebSocket data from JavaScript or misinterpreting WebSocket protocol rules.
* **User Actions/Debugging:** Explain how actions like opening a WebSocket connection, sending/receiving messages, or encountering network issues could lead to these tests being relevant.
这是对 `net/websockets/websocket_basic_stream_test.cc` 文件功能的第二部分归纳。基于你提供的代码片段，可以总结出以下功能：

**功能归纳 (第二部分):**

这部分测试主要关注 `WebSocketBasicStream` 类在处理**接收和发送 WebSocket 帧**时的各种边界情况和错误处理，以及相关的辅助功能测试。具体来说，它测试了以下方面：

1. **处理无效的 WebSocket 帧:**
   - 测试同步和异步读取时，接收到格式错误的帧（`kInvalidFrame`）时是否能正确返回 `ERR_WS_PROTOCOL_ERROR`。
   - 验证了无效帧不会传递到更高层。

2. **处理不合规的控制帧:**
   - 测试接收到没有 FIN 标志的控制帧（`kPingFrameWithoutFin`）时，是否会返回 `ERR_WS_PROTOCOL_ERROR` 并且不会将该帧传递到上层。
   - 测试接收到超过 125 字节的控制帧（`k126BytePong`）时，无论是否分片，都会返回 `ERR_WS_PROTOCOL_ERROR`。这符合 RFC6455 协议规定。

3. **处理分片的控制帧:**
   - 验证了即使控制帧被分成多个数据块接收，如果其总长度超过 125 字节，也会被正确拒绝并返回 `ERR_WS_PROTOCOL_ERROR`。
   - 测试了同步和异步两种分片接收场景。

4. **处理一次读取多个控制帧的情况:**
   - 验证了 `ReadFrames` 方法可以一次性处理多个完整的控制帧，并正确解析出每个帧的内容。

5. **控制帧的组装:**
   - 测试了在同步读取情况下，`ReadFrames` 会在整个控制帧组装完成后才返回。
   - 测试了在异步读取情况下，只有当控制帧完全组装好后，回调函数才会被调用。

6. **处理大数据帧 (分片读取):**
   - 测试了接收一个 1MB 的大数据帧，该帧需要分片读取，验证了每个分片都被正确处理，最终能接收到完整的帧数据。
   - 验证了分片读取时，每个分片的有效载荷长度是否符合预期。

7. **处理带有保留标志的帧:**
   - 测试了当一个带有保留标志的帧被分片接收时，只有第一个分片会设置保留标志，后续分片的保留标志会被清除。

8. **发送 WebSocket 帧:**
   - 测试了一次性写入整个 WebSocket 帧的场景。
   - 测试了完全异步写入 WebSocket 帧的场景。
   - 测试了当内核缓冲区非常满时，将帧分成多个小块写入的场景，并确保回调只在所有数据写入完成后才被调用。
   - 测试了发送带有空有效载荷的 Pong 帧的情况。
   - 测试了发送带有非空掩码密钥的帧的情况，并验证了掩码操作的正确性。

9. **获取 WebSocket 扩展和子协议:**
   - 测试了 `GetExtensions()` 方法能够正确返回协商好的扩展。
   - 测试了 `GetSubProtocol()` 方法能够正确返回协商好的子协议。

10. **动态调整读取缓冲区大小:**
    - 测试了初始读取缓冲区大小的设置。
    - 测试了在零耗时读取的情况下缓冲区大小的调整。
    - 测试了在高吞吐量连接下，读取缓冲区大小是否能动态切换到更大的值。

**与 JavaScript 功能的关系:**

这些测试直接关联到 JavaScript WebSocket API 的底层实现。当 JavaScript 代码使用 `new WebSocket()` 创建连接，并通过 `send()` 发送数据或通过 `onmessage` 接收数据时，底层的 C++ 网络栈（包括 `WebSocketBasicStream`）负责实际的网络通信和协议处理。

* **无效帧和不合规控制帧的处理:**  这些测试确保了当远程 WebSocket 端点发送不符合协议的帧时，Chromium 能够正确地检测并断开连接，防止潜在的安全问题或程序崩溃。这对应于 JavaScript 中 `onerror` 事件的触发，表明连接遇到了错误。
* **分片消息处理:** JavaScript WebSocket API 可以发送和接收大于单个网络包的消息。这些测试确保了 C++ 层能够正确地组装分片的消息，并在 JavaScript 中作为一个完整的消息传递。
* **发送帧:** 当 JavaScript 调用 `websocket.send(data)` 时，数据会被封装成 WebSocket 帧并通过 `WebSocketBasicStream::WriteFrames` 发送。这些测试验证了不同写入场景下的正确性。
* **扩展和子协议:** JavaScript 中可以通过检查 `websocket.extensions` 和 `websocket.protocol` 属性来获取协商好的扩展和子协议。这些 C++ 测试确保了这些信息的正确提取和存储。
* **读取缓冲区大小调整:** 虽然 JavaScript 开发者通常不直接控制底层的缓冲区大小，但这种优化影响着 WebSocket 连接的性能。更智能的缓冲区管理可以提高数据传输效率，从而提升 JavaScript 应用的性能。

**逻辑推理、假设输入与输出:**

以下举例说明部分测试的逻辑推理：

* **测试 `SyncInvalidFrame`:**
    * **假设输入:**  模拟从网络接收到一个格式错误的 WebSocket 帧，例如帧头部的某个标志位设置错误。具体的数据可能是 `kInvalidFrame` 中定义的内容。
    * **预期输出:**  `stream_->ReadFrames` 方法应该同步返回 `ERR_WS_PROTOCOL_ERROR`，表示协议错误。

* **测试 `ControlFrameWithoutFin`:**
    * **假设输入:** 模拟接收到一个控制帧（例如 Ping 帧），但其 FIN (Final) 标志位未设置，表明这不是该控制消息的最后一个分片（虽然控制帧不允许分片）。具体数据是 `kPingFrameWithoutFin`。
    * **预期输出:** `stream_->ReadFrames` 方法应该同步返回 `ERR_WS_PROTOCOL_ERROR`，因为控制帧不允许分片。`frames` 向量应该为空，因为无效的帧不应该被传递。

* **测试 `WriteAtOnce`:**
    * **假设输入:**  创建一个包含一个数据帧的 `frames_` 向量，该帧的数据由 `kWriteFrame` 定义。
    * **预期输出:** `stream_->WriteFrames` 方法应该同步返回 `IsOk()`，表示帧已成功写入。模拟的 `MockWrite` 应该接收到 `kWriteFrame` 的内容。

**用户或编程常见的使用错误:**

* **发送不符合协议的帧:**  开发者可能错误地构造 WebSocket 帧并尝试发送。例如，尝试发送一个超过 125 字节的未分片的控制帧。这些测试可以帮助捕获这类错误。
* **服务端发送了无效的帧:**  如果 WebSocket 服务端实现有误，可能会发送格式错误的帧。客户端的这些测试可以确保能正确处理这些错误，避免程序崩溃。
* **没有正确处理分片消息:**  虽然底层处理了分片，但如果开发者在更高层错误地假设消息都是一次性到达，可能会导致逻辑错误。
* **误解 WebSocket 协议规则:**  例如，开发者可能不知道控制帧不能分片或有效载荷长度限制。这些测试反映了协议的强制性要求。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个网页，该网页使用了 WebSocket 技术。**
2. **网页中的 JavaScript 代码创建了一个 `WebSocket` 对象，尝试连接到 WebSocket 服务器。**
3. **浏览器网络栈开始进行 WebSocket 握手。**
4. **一旦握手成功，WebSocket 连接建立。**
5. **如果 JavaScript 代码调用 `websocket.send(data)` 发送数据，或者 WebSocket 服务器向客户端发送数据，那么 `WebSocketBasicStream` 的 `WriteFrames` 或 `ReadFrames` 方法会被调用。**
6. **如果接收到的数据帧格式错误（例如，不合法的帧头），或者违反了协议规则（例如，过长的控制帧），那么 `ReadFrames` 方法在解析帧头时会检测到错误，并可能触发相应的错误处理逻辑，这正是这些测试所覆盖的场景。**
7. **在开发或调试过程中，如果怀疑 WebSocket 连接有问题，开发者可能会查看浏览器的网络面板，检查 WebSocket 帧的发送和接收情况。**
8. **如果涉及到网络层的更深层次调试，Chromium 的开发者可能会运行这些单元测试，以验证 `WebSocketBasicStream` 类的行为是否符合预期，特别是在处理各种边界情况和错误时。**

总而言之，这部分测试深入验证了 `WebSocketBasicStream` 类在处理 WebSocket 帧的接收和发送时的健壮性和合规性，确保了 Chromium 能够正确可靠地处理各种 WebSocket 通信场景，并能有效地应对潜在的错误或不合规的数据。

### 提示词
```
这是目录为net/websockets/websocket_basic_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
or.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncInvalidFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(SYNCHRONOUS, kInvalidFrame, kInvalidFrameSize));

  EXPECT_EQ(ERR_WS_PROTOCOL_ERROR,
            stream_->ReadFrames(&frames, cb_.callback()));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncInvalidFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(ASYNC, kInvalidFrame, kInvalidFrameSize));

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_WS_PROTOCOL_ERROR));
}

// A control frame without a FIN flag is invalid and should not be passed
// through to higher layers. RFC6455 5.5 "All control frames ... MUST NOT be
// fragmented."
TEST_F(WebSocketBasicStreamSocketSingleReadTest, ControlFrameWithoutFin) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(
      MockRead(SYNCHRONOUS, kPingFrameWithoutFin, kPingFrameWithoutFinSize));

  EXPECT_EQ(ERR_WS_PROTOCOL_ERROR,
            stream_->ReadFrames(&frames, cb_.callback()));
  EXPECT_TRUE(frames.empty());
}

// A control frame over 125 characters is invalid. RFC6455 5.5 "All control
// frames MUST have a payload length of 125 bytes or less". Since we use a
// 125-byte buffer to assemble fragmented control frames, we need to detect this
// error before attempting to assemble the fragments.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, OverlongControlFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(SYNCHRONOUS, k126BytePong, k126BytePongSize));

  EXPECT_EQ(ERR_WS_PROTOCOL_ERROR,
            stream_->ReadFrames(&frames, cb_.callback()));
  EXPECT_TRUE(frames.empty());
}

// A control frame over 125 characters should still be rejected if it is split
// into multiple chunks.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, SplitOverlongControlFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  constexpr size_t kFirstChunkSize = 16;
  expect_all_io_to_complete_ = false;
  CreateChunkedRead(SYNCHRONOUS, k126BytePong, k126BytePongSize,
                    kFirstChunkSize, 2, LAST_FRAME_BIG);

  EXPECT_EQ(ERR_WS_PROTOCOL_ERROR,
            stream_->ReadFrames(&frames, cb_.callback()));
  EXPECT_TRUE(frames.empty());
}

TEST_F(WebSocketBasicStreamSocketChunkedReadTest,
       AsyncSplitOverlongControlFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  constexpr size_t kFirstChunkSize = 16;
  expect_all_io_to_complete_ = false;
  CreateChunkedRead(ASYNC, k126BytePong, k126BytePongSize, kFirstChunkSize, 2,
                    LAST_FRAME_BIG);

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_WS_PROTOCOL_ERROR));
  // The caller should not call ReadFrames() again after receiving an error
  // other than ERR_IO_PENDING.
  EXPECT_TRUE(frames.empty());
}

// Test to ensure multiple control frames with different payloads are handled
// properly.
TEST_F(WebSocketBasicStreamSocketTest, MultipleControlFramesInOneRead) {
  const char kMultiplePongFrames[] = {
      '\x8A', '\x05', 'P', 'o', 'n', 'g', '1',  // "Pong1".
      '\x8A', '\x05', 'P', 'o', 'n', 'g', '2'   // "Pong2".
  };

  constexpr size_t kMultiplePongFramesSize = sizeof(kMultiplePongFrames);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kMultiplePongFrames, kMultiplePongFramesSize)};
  CreateStream(reads, base::span<MockWrite>());

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(2U, frames.size());

  EXPECT_EQ(WebSocketFrameHeader::kOpCodePong, frames[0]->header.opcode);
  EXPECT_EQ(5U, frames[0]->header.payload_length);
  EXPECT_EQ(base::as_string_view(frames[0]->payload), "Pong1");

  EXPECT_EQ(WebSocketFrameHeader::kOpCodePong, frames[1]->header.opcode);
  EXPECT_EQ(5U, frames[1]->header.payload_length);
  EXPECT_EQ(base::as_string_view(frames[1]->payload), "Pong2");
}

// In the synchronous case, ReadFrames assembles the whole control frame before
// returning.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, SyncControlFrameAssembly) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  constexpr size_t kChunkSize = 3;
  CreateChunkedRead(SYNCHRONOUS, kCloseFrame, kCloseFrameSize, kChunkSize, 3,
                    LAST_FRAME_BIG);

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeClose, frames[0]->header.opcode);
}

// In the asynchronous case, the callback is not called until the control frame
// has been completely assembled.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, AsyncControlFrameAssembly) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  constexpr size_t kChunkSize = 3;
  CreateChunkedRead(ASYNC, kCloseFrame, kCloseFrameSize, kChunkSize, 3,
                    LAST_FRAME_BIG);

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeClose, frames[0]->header.opcode);
}

// A frame with a 1MB payload that has to be read in chunks.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, OneMegFrame) {
  // This should be equal to the definition of kSmallReadBufferFrame in
  // websocket_basic_stream.cc.
  constexpr int kReadBufferSize = 1000;
  constexpr uint64_t kPayloadSize = 1 << 20;
  constexpr size_t kWireSize = kPayloadSize + kLargeFrameHeaderSize;
  constexpr size_t kExpectedFrameCount =
      (kWireSize + kReadBufferSize - 1) / kReadBufferSize;
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  auto big_frame = base::HeapArray<uint8_t>::WithSize(kWireSize);
  auto [extended_header, payload] =
      big_frame.as_span().split_at(kLargeFrameHeaderSize);

  {
    auto [header, extended_payload_length] = extended_header.split_at<2u>();
    header.copy_from(base::as_byte_span({'\x81', '\x7F'}));
    extended_payload_length.copy_from(base::U64ToBigEndian(kPayloadSize));
  }

  std::ranges::fill(payload, 'A');

  CreateChunkedRead(ASYNC, reinterpret_cast<char*>(big_frame.data()),
                    big_frame.size(), kReadBufferSize, kExpectedFrameCount,
                    LAST_FRAME_BIG);

  for (size_t frame = 0; frame < kExpectedFrameCount; ++frame) {
    frames.clear();
    ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
                IsError(ERR_IO_PENDING));
    EXPECT_THAT(cb_.WaitForResult(), IsOk());
    ASSERT_EQ(1U, frames.size());
    size_t expected_payload_size = kReadBufferSize;
    if (frame == 0) {
      expected_payload_size = kReadBufferSize - kLargeFrameHeaderSize;
    } else if (frame == kExpectedFrameCount - 1) {
      expected_payload_size =
          kWireSize - kReadBufferSize * (kExpectedFrameCount - 1);
    }
    EXPECT_EQ(expected_payload_size, frames[0]->header.payload_length);
  }
}

// A frame with reserved flag(s) set that arrives in chunks should only have the
// reserved flag(s) set on the first chunk when split.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, ReservedFlagCleared) {
  static constexpr char kReservedFlagFrame[] = "\x41\x05Hello";
  constexpr size_t kReservedFlagFrameSize = std::size(kReservedFlagFrame) - 1;
  constexpr size_t kChunkSize = 5;
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  CreateChunkedRead(ASYNC, kReservedFlagFrame, kReservedFlagFrameSize,
                    kChunkSize, 2, LAST_FRAME_BIG);

  TestCompletionCallback cb[2];
  ASSERT_THAT(stream_->ReadFrames(&frames, cb[0].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[0].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_TRUE(frames[0]->header.reserved1);

  frames.clear();
  ASSERT_THAT(stream_->ReadFrames(&frames, cb[1].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[1].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_FALSE(frames[0]->header.reserved1);
}

// Check that writing a frame all at once works.
TEST_F(WebSocketBasicStreamSocketWriteTest, WriteAtOnce) {
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, kWriteFrame, kWriteFrameSize)};
  CreateStream(base::span<MockRead>(), writes);

  EXPECT_THAT(stream_->WriteFrames(&frames_, cb_.callback()), IsOk());
}

// Check that completely async writing works.
TEST_F(WebSocketBasicStreamSocketWriteTest, AsyncWriteAtOnce) {
  MockWrite writes[] = {MockWrite(ASYNC, kWriteFrame, kWriteFrameSize)};
  CreateStream(base::span<MockRead>(), writes);

  ASSERT_THAT(stream_->WriteFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
}

// Check that writing a frame to an extremely full kernel buffer (so that it
// ends up being sent in bits) works. The WriteFrames() callback should not be
// called until all parts have been written.
TEST_F(WebSocketBasicStreamSocketWriteTest, WriteInBits) {
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, kWriteFrame, 4),
                        MockWrite(ASYNC, kWriteFrame + 4, 4),
                        MockWrite(ASYNC, kWriteFrame + 8, kWriteFrameSize - 8)};
  CreateStream(base::span<MockRead>(), writes);

  ASSERT_THAT(stream_->WriteFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
}

// Check that writing a Pong frame with a nullptr body works.
TEST_F(WebSocketBasicStreamSocketWriteTest, WriteNullptrPong) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kMaskedEmptyPong, kMaskedEmptyPongSize)};
  CreateStream(base::span<MockRead>(), writes);

  auto frame =
      std::make_unique<WebSocketFrame>(WebSocketFrameHeader::kOpCodePong);
  WebSocketFrameHeader& header = frame->header;
  header.final = true;
  header.masked = true;
  header.payload_length = 0;
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  frames.push_back(std::move(frame));
  EXPECT_THAT(stream_->WriteFrames(&frames, cb_.callback()), IsOk());
}

// Check that writing with a non-nullptr mask works correctly.
TEST_F(WebSocketBasicStreamSocketTest, WriteNonNulMask) {
  std::string masked_frame = std::string("\x81\x88");
  masked_frame += std::string(std::begin(kNonNulMaskingKey.key),
                              std::end(kNonNulMaskingKey.key));
  masked_frame += "jiggered";
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, masked_frame.data(), masked_frame.size())};
  generator_ = &GenerateNonNulMaskingKey;
  CreateStream(base::span<MockRead>(), writes);

  auto frame =
      std::make_unique<WebSocketFrame>(WebSocketFrameHeader::kOpCodeText);
  const std::string unmasked_payload = "graphics";
  const size_t payload_size = unmasked_payload.size();
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(payload_size);
  buffer->span().copy_from(base::as_byte_span(unmasked_payload));
  frame->payload = buffer->span();
  WebSocketFrameHeader& header = frame->header;
  header.final = true;
  header.masked = true;
  header.payload_length = payload_size;

  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  frames.push_back(std::move(frame));

  EXPECT_THAT(stream_->WriteFrames(&frames, cb_.callback()), IsOk());
}

TEST_F(WebSocketBasicStreamSocketTest, GetExtensionsWorks) {
  extensions_ = "inflate-uuencode";
  CreateStream(base::span<MockRead>(), base::span<MockWrite>());

  EXPECT_EQ("inflate-uuencode", stream_->GetExtensions());
}

TEST_F(WebSocketBasicStreamSocketTest, GetSubProtocolWorks) {
  sub_protocol_ = "cyberchat";
  CreateStream(base::span<MockRead>(), base::span<MockWrite>());

  EXPECT_EQ("cyberchat", stream_->GetSubProtocol());
}

// Check that the read buffer size initialization works correctly.
TEST_F(WebSocketBasicStreamSwitchTest, GetInitialReadBufferSize) {
  EXPECT_EQ(buffer_size_manager_.buffer_size(),
            WebSocketBasicStream::BufferSize::kSmall);
  buffer_size_manager_.OnRead(MicrosecondsFromStart(0));
  EXPECT_EQ(buffer_size_manager_.buffer_size(),
            WebSocketBasicStream::BufferSize::kSmall);
}

// Check that the case where the start time and the end time are the same.
TEST_F(WebSocketBasicStreamSwitchTest, ZeroSecondRead) {
  buffer_size_manager_.set_window_for_test(1);
  buffer_size_manager_.OnRead(MicrosecondsFromStart(0));
  buffer_size_manager_.OnReadComplete(MicrosecondsFromStart(0), 1000);
  EXPECT_EQ(buffer_size_manager_.buffer_size(),
            WebSocketBasicStream::BufferSize::kLarge);
}

// Check that the read buffer size is switched for high throughput connection.
TEST_F(WebSocketBasicStreamSwitchTest, CheckSwitch) {
  buffer_size_manager_.set_window_for_test(4);
  // It tests the case where 4000 bytes data is read in 2000 ms. In this case,
  // the read buffer size should be switched to the large one.
  buffer_size_manager_.OnRead(MicrosecondsFromStart(0));
  buffer_size_manager_.OnReadComplete(MicrosecondsFromStart(200), 1000);
  buffer_size_manager_.OnRead(MicrosecondsFromStart(800));
  buffer_size_manager_.OnReadComplete(MicrosecondsFromStart(1000), 1000);
  buffer_size_manager_.OnRead(MicrosecondsFromStart(1300));
  buffer_size_manager_.OnReadComplete(MicrosecondsFromStart(1500), 1000);
  buffer_size_manager_.OnRead(MicrosecondsFromStart(1800));
  buffer_size_manager_.OnReadComplete(MicrosecondsFromStart(2000), 1000);
  EXPECT_EQ(buffer_size_manager_.buffer_size(),
            WebSocketBasicStream::BufferSize::kLarge);
}

}  // namespace
}  // namespace net
```
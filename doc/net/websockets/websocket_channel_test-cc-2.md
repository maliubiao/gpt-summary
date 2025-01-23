Response:
The user wants a summary of the functionality of the provided C++ code snippet from `websocket_channel_test.cc`. I need to analyze the test cases to understand what aspects of the `WebSocketChannel` class are being tested. I should also identify any relationships to JavaScript functionality, common user/programming errors, and how a user's actions might lead to this code being executed.

**Plan:**
1. Read through each test case and identify the functionality being tested.
2. Look for connections to JavaScript concepts or APIs related to WebSockets.
3. Analyze the test logic to infer input and output scenarios.
4. Identify potential user or programming errors that these tests cover.
5. Consider how a user interacting with a web page might trigger the WebSocket code paths being tested.
6. Summarize the overall functionality demonstrated by the tests in this specific part of the file.
```c++
// Receiving an invalid UTF-8 payload in a Close frame causes us to fail the
// connection.
TEST_F(WebSocketChannelStreamTest, CloseFrameInvalidUtf8) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED, CLOSE_DATA(NORMAL_CLOSURE, "\xFF")}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED, CLOSE_DATA(PROTOCOL_ERROR, "Invalid UTF-8 in Close frame")}};
  NetLogWithSource net_log_with_source;

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, Close());

  CreateChannelAndConnectSuccessfully();
}

// RFC6455 5.5.2 "Upon receipt of a Ping frame, an endpoint MUST send a Pong
// frame in response"
// 5.5.3 "A Pong frame sent in response to a Ping frame must have identical
// "Application data" as found in the message body of the Ping frame being
// replied to."
TEST_F(WebSocketChannelStreamTest, PingRepliedWithPong) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePing,
       NOT_MASKED,  "Application data"}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePong,
       MASKED,      "Application data"}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));

  CreateChannelAndConnectSuccessfully();
}

// A ping with a null payload should be responded to with a Pong with a null
// payload.
TEST_F(WebSocketChannelStreamTest, NullPingRepliedWithNullPong) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePing, NOT_MASKED, nullptr}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePong, MASKED, nullptr}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));

  CreateChannelAndConnectSuccessfully();
}

TEST_F(WebSocketChannelStreamTest, PongInTheMiddleOfDataMessage) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePing,
       NOT_MASKED,  "Application data"}};
  static const InitFrame expected1[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "Hello "}};
  static const InitFrame expected2[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePong,
       MASKED,      "Application data"}};
  static const InitFrame expected3[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       MASKED,      "World"}};
  std::vector<std::unique_ptr<WebSocketFrame>>* read_frames;
  CompletionOnceCallback read_callback;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce([&](auto frames, auto cb) {
        read_frames = std::move(frames);
        read_callback = std::move(cb);
        return ERR_IO_PENDING;
      })
      .WillRepeatedly(Return(ERR_IO_PENDING));
  {
    InSequence s;

    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected1), _))
        .WillOnce(Return(OK));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected2), _))
        .WillOnce(Return(OK));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected3), _))
        .WillOnce(Return(OK));
  }

  CreateChannelAndConnectSuccessfully();
  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("Hello "), 6U),
            WebSocketChannel::CHANNEL_ALIVE);
  *read_frames = CreateFrameVector(frames, &result_frame_data_);
  std::move(read_callback).Run(OK);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("World"), 5U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// WriteFrames() may not be called until the previous write has completed.
// WebSocketChannel must buffer writes that happen in the meantime.
TEST_F(WebSocketChannelStreamTest, WriteFramesOneAtATime) {
  static const InitFrame expected1[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "Hello "}};
  static const InitFrame expected2[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "World"}};
  CompletionOnceCallback write_callback;
  Checkpoint checkpoint;

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));
  {
    InSequence s;
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected1), _))
        .WillOnce([&](auto, auto cb) {
          write_callback = std::move(cb);
          return ERR_IO_PENDING;
        });
    EXPECT_CALL(checkpoint, Call(2));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected2), _))
        .WillOnce(Return(ERR_IO_PENDING));
    EXPECT_CALL(checkpoint, Call(3));
  }

  CreateChannelAndConnectSuccessfully();
  checkpoint.Call(1);
  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("Hello "), 6U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("World"), 5U),
            WebSocketChannel::CHANNEL_ALIVE);
  checkpoint.Call(2);
  std::move(write_callback).Run(OK);
  checkpoint.Call(3);
}

// WebSocketChannel must buffer frames while it is waiting for a write to
// complete, and then send them in a single batch. The batching behaviour is
// important to get good throughput in the "many small messages" case.
TEST_F(WebSocketChannelStreamTest, WaitingMessagesAreBatched) {
  static const char input_letters[] = "Hello";
  static const InitFrame expected1[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "H"}};
  static const InitFrame expected2[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "e"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "l"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "l"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "o"}};
  CompletionOnceCallback write_callback;

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected1), _))
        .WillOnce([&](auto, auto cb) {
          write_callback = std::move(cb);
          return ERR_IO_PENDING;
        });
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected2), _))
        .WillOnce(Return(ERR_IO_PENDING));
  }

  CreateChannelAndConnectSuccessfully();
  for (size_t i = 0; i < strlen(input_letters); ++i) {
    EXPECT_EQ(
        channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                            AsIOBuffer(std::string(1, input_letters[i])), 1U),
        WebSocketChannel::CHANNEL_ALIVE);
  }
  std::move(write_callback).Run(OK);
}

// For convenience, most of these tests use Text frames. However, the WebSocket
// protocol also has Binary frames and those need to be 8-bit clean. For the
// sake of completeness, this test verifies that they are.
TEST_F(WebSocketChannelStreamTest, WrittenBinaryFramesAre8BitClean) {
  std::vector<std::unique_ptr<WebSocketFrame>>* frames = nullptr;

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(_, _))
      .WillOnce(DoAll(SaveArg<0>(&frames), Return(ERR_IO_PENDING)));

  CreateChannelAndConnectSuccessfully();
  EXPECT_EQ(
      channel_->SendFrame(
          true, WebSocketFrameHeader::kOpCodeBinary,
          AsIOBuffer(std::string(kBinaryBlob, kBinaryBlob + kBinaryBlobSize)),
          kBinaryBlobSize),
      WebSocketChannel::CHANNEL_ALIVE);
  ASSERT_TRUE(frames != nullptr);
  ASSERT_EQ(1U, frames->size());
  const WebSocketFrame* out_frame = (*frames)[0].get();
  EXPECT_EQ(kBinaryBlobSize, out_frame->header.payload_length);
  ASSERT_FALSE(out_frame->payload.empty());
  EXPECT_EQ(std::string_view(kBinaryBlob, kBinaryBlobSize),
            base::as_string_view(out_frame->payload));
}

// Test the read path for 8-bit cleanliness as well.
TEST_F(WebSocketChannelEventInterfaceTest, ReadBinaryFramesAre8BitClean) {
  auto frame =
      std::make_unique<WebSocketFrame>(WebSocketFrameHeader::kOpCodeBinary);
  WebSocketFrameHeader& frame_header = frame->header;
  frame_header.final = true;
  frame_header.payload_length = kBinaryBlobSize;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(kBinaryBlobSize);
  memcpy(buffer->data(), kBinaryBlob, kBinaryBlobSize);
  frame->payload = buffer->span();
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  frames.push_back(std::move(frame));
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  stream->PrepareRawReadFrames(ReadableFakeWebSocketStream::SYNC, OK,
                               std::move(frames));
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(
      *event_interface_,
      OnDataFrameVector(
          true, WebSocketFrameHeader::kOpCodeBinary,
          std::vector<char>(kBinaryBlob, kBinaryBlob + kBinaryBlobSize)));

  CreateChannelAndConnectSuccessfully();
}

// Invalid UTF-8 is not permitted in Text frames.
TEST_F(WebSocketChannelSendUtf8Test, InvalidUtf8Rejected) {
  EXPECT_CALL(*event_interface_,
              OnFailChannel(
                  "Browser sent a text frame containing invalid UTF-8", _, _));

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xff"), 1U),
            WebSocketChannel::CHANNEL_DELETED);
}

// A Text message cannot end with a partial UTF-8 character.
TEST_F(WebSocketChannelSendUtf8Test, IncompleteCharacterInFinalFrame) {
  EXPECT_CALL(*event_interface_,
              OnFailChannel(
                  "Browser sent a text frame containing invalid UTF-8", _, _));

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xc2"), 1U),
            WebSocketChannel::CHANNEL_DELETED);
}

// A non-final Text frame may end with a partial UTF-8 character (compare to
// previous test).
TEST_F(WebSocketChannelSendUtf8Test, IncompleteCharacterInNonFinalFrame) {
  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xc2"), 1U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// UTF-8 parsing context must be retained between frames.
TEST_F(WebSocketChannelSendUtf8Test, ValidCharacterSplitBetweenFrames) {
  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xf1"), 1U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("\x80\xa0\xbf"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// Similarly, an invalid character should be detected even if split.
TEST_F(WebSocketChannelSendUtf8Test, InvalidCharacterSplit) {
  EXPECT_CALL(*event_interface_,
              OnFailChannel(
                  "Browser sent a text frame containing invalid UTF-8", _, _));

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xe1"), 1U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("\x80\xa0\xbf"), 3U),
            WebSocketChannel::CHANNEL_DELETED);
}

// An invalid character must be detected in continuation frames.
TEST_F(WebSocketChannelSendUtf8Test, InvalidByteInContinuation) {
  EXPECT_CALL(*event_interface_,
              OnFailChannel(
                  "Browser sent a text frame containing invalid UTF-8", _, _));

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("foo"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(
      channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeContinuation,
                          AsIOBuffer("bar"), 3U),
      WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("\xff"), 1U),
            WebSocketChannel::CHANNEL_DELETED);
}

// However, continuation frames of a Binary frame will not be tested for UTF-8
// validity.
TEST_F(WebSocketChannelSendUtf8Test, BinaryContinuationNotChecked) {
  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeBinary,
                                AsIOBuffer("foo"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(
      channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeContinuation,
                          AsIOBuffer("bar"), 3U),
      WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("\xff"), 1U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// Multiple text messages can be validated without the validation state getting
// confused.
TEST_F(WebSocketChannelSendUtf8Test, ValidateMultipleTextMessages) {
  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("foo"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("bar"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// UTF-8 validation is enforced on received Text frames.
TEST_F(WebSocketChannelEventInterfaceTest, ReceivedInvalidUtf8) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "\xff"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));

  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(*event_interface_,
              OnFailChannel("Could not decode a text frame as UTF-8.", _, _));

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// Invalid UTF-8 is not sent over the network.
TEST_F(WebSocketChannelStreamTest, InvalidUtf8TextFrameNotSent) {
  static const InitFrame expected[] = {{FINAL_FRAME,
                                        WebSocketFrameHeader::kOpCodeClose,
                                        MASKED, CLOSE_DATA(GOING_AWAY, "")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, Close()).Times(1);

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xff"), 1U),
            WebSocketChannel::CHANNEL_DELETED);
}

// The rest of the tests for receiving invalid UTF-8 test the communication with
// the server. Since there is only one code path, it would be redundant to
// perform the same tests on th
```

这是`net/websockets/websocket_channel_test.cc`文件的第3部分，主要测试了`WebSocketChannel`处理接收和发送数据帧，以及UTF-8编码的逻辑。以下是功能的归纳：

**功能归纳:**

1. **处理接收到的 Close 帧中的无效 UTF-8 数据:**
    *   验证当接收到包含无效 UTF-8 数据的 Close 帧时，连接会失败，并发送包含 "Invalid UTF-8 in Close frame" 原因的 Close 帧作为响应。

    *   **与 JavaScript 的关系:**  当 JavaScript 的 `WebSocket` 接收到包含无效 UTF-8 的 Close 帧时，`onerror` 事件会被触发，并且 `readyState` 会变为 `CLOSED`。

    *   **假设输入与输出:**
        *   **假设输入:** 接收到一个 Close 帧，其 payload 为无法解析为 UTF-8 的字节序列 (例如 `\xFF`)。
        *   **假设输出:**  发送一个 Close 帧作为响应，状态码可能为 `PROTOCOL_ERROR`，reason 包含 "Invalid UTF-8 in Close frame"。同时，WebSocket 连接会被关闭。

    *   **用户或编程常见的使用错误:** 后端服务器在发送 Close 帧时错误地使用了非 UTF-8 编码。

    *   **调试线索：用户操作 -> 到达这里的步骤:**
        1. 用户与一个使用 WebSocket 的网页交互。
        2. WebSocket 连接保持打开状态。
        3. 远程服务器决定关闭连接，并发送一个 Close 帧。
        4. 服务器在构造 Close 帧的 reason 时，错误地使用了非 UTF-8 编码的字符串。
        5. `WebSocketChannel` 接收到这个 Close 帧，并进行解析和验证。
        6. 由于 reason 部分无法解析为有效的 UTF-8，触发了此测试覆盖的逻辑。

2. **处理 Ping 和 Pong 帧:**
    *   验证当接收到 Ping 帧时，`WebSocketChannel` 会发送一个包含相同应用数据的 Pong 帧作为响应。
    *   验证当接收到带有空 payload 的 Ping 帧时，会发送一个带有空 payload 的 Pong 帧作为响应。
    *   验证在发送数据帧的过程中接收到 Ping 帧时，会先发送正在发送的数据帧，然后发送 Pong 帧。

    *   **与 JavaScript 的关系:** JavaScript 的 `WebSocket` API 提供了 `send()` 方法用于发送数据，以及监听 `message` 事件接收数据。Ping/Pong 帧的处理通常是在底层完成的，应用程序无需显式处理，但可以通过浏览器提供的 API (例如，某些浏览器开发者工具) 观察到这些帧的交互。

    *   **假设输入与输出:**
        *   **假设输入:** 接收到一个 Ping 帧，payload 为 "Application data"。
        *   **假设输出:** 发送一个 Pong 帧，payload 也为 "Application data"。

    *   **用户或编程常见的使用错误:**  虽然用户代码不直接操作 Ping/Pong，但服务器端可能未正确实现 Ping/Pong 机制，导致客户端断开连接或性能下降。

    *   **调试线索：用户操作 -> 到达这里的步骤:**
        1. 用户与一个使用 WebSocket 的网页交互。
        2. WebSocket 连接保持打开状态。
        3. 远程服务器为了保持连接活跃或者测试连接状态，发送一个 Ping 帧。
        4. `WebSocketChannel` 接收到 Ping 帧，并触发发送 Pong 帧的逻辑。

3. **管理发送帧的顺序和缓冲:**
    *   验证 `WebSocketChannel` 在前一个写操作完成之前，会缓冲待发送的帧，并确保写操作是串行的。
    *   验证 `WebSocketChannel` 会将多个待发送的小消息帧缓冲起来，然后批量发送，以提高效率。

    *   **与 JavaScript 的关系:** 当 JavaScript 代码多次调用 `websocket.send()` 方法发送消息时，这些消息可能会被 `WebSocketChannel` 缓冲并批量发送。

    *   **假设输入与输出:**
        *   **假设输入:** 连续调用 `channel_->SendFrame` 发送多个数据帧。
        *   **假设输出:**  对 `mock_stream_->WriteFrames` 的调用会被排序，并且小的消息会被合并到一个 `WriteFrames` 调用中。

    *   **用户或编程常见的使用错误:**  用户代码频繁发送小消息，如果没有适当的缓冲和批量发送机制，可能会导致网络性能下降。

    *   **调试线索：用户操作 -> 到达这里的步骤:**
        1. 用户在一个网页上进行操作，例如在一个聊天应用中快速输入多个字符。
        2. JavaScript 代码捕捉用户的输入，并调用 `websocket.send()` 方法发送每个字符或者较小的文本片段。
        3. `WebSocketChannel` 接收到这些待发送的消息，并放入缓冲区。
        4. 当网络连接空闲或者缓冲区达到一定大小时，`WebSocketChannel` 将缓冲的消息批量发送。

4. **处理二进制帧:**
    *   验证发送和接收的二进制帧是 8-bit clean，即可以正确处理所有可能的字节值。

    *   **与 JavaScript 的关系:** JavaScript 的 `WebSocket` API 可以发送和接收二进制数据，通过 `ArrayBuffer` 或 `Blob` 对象。

    *   **假设输入与输出:**
        *   **假设输入:**  通过 `channel_->SendFrame` 发送一个包含所有可能字节值的二进制数据。或者接收到一个包含所有可能字节值的二进制帧。
        *   **假设输出:** 发送出去的帧和接收到的帧的二进制数据保持不变。

    *   **用户或编程常见的使用错误:**  在处理二进制数据时，没有正确处理字节序或者编码问题，导致数据损坏。

    *   **调试线索：用户操作 -> 到达这里的步骤:**
        1. 用户在一个需要上传文件或者进行实时音视频通信的网页上进行操作。
        2. JavaScript 代码将文件或者音视频数据编码成二进制数据，并通过 `websocket.send()` 发送。
        3. `WebSocketChannel` 处理这些二进制数据帧。

5. **UTF-8 编码验证（发送和接收）:**
    *   验证发送的 Text 帧必须是有效的 UTF-8 编码。如果包含无效的 UTF-8 字符，发送操作会失败，并且连接会被关闭。
    *   验证接收到的 Text 帧必须是有效的 UTF-8 编码。如果包含无效的 UTF-8 字符，连接会失败。
    *   验证 UTF-8 的解析状态会在连续的 Text 帧之间保留。
    *   验证二进制帧的 continuation 帧不会进行 UTF-8 验证。

    *   **与 JavaScript 的关系:** JavaScript 字符串通常使用 UTF-16 编码，当通过 WebSocket 发送文本数据时，会自动转换为 UTF-8。接收到的 UTF-8 数据会被转换为 JavaScript 字符串。

    *   **假设输入与输出:**
        *   **发送无效 UTF-8:** 调用 `channel_->SendFrame` 发送包含无效 UTF-8 字符的文本数据 (例如 `\xff`)。输出是发送操作失败，连接被标记为 `CHANNEL_DELETED`，并且可能发送一个 Close 帧。
        *   **接收无效 UTF-8:**  接收到一个包含无效 UTF-8 字符的 Text 帧。输出是连接失败，并且触发 `OnFailChannel` 事件。

    *   **用户或编程常见的使用错误:**
        *   JavaScript 代码尝试发送非 UTF-8 编码的数据作为文本消息。
        *   后端服务器发送了非 UTF-8 编码的文本消息。

    *   **调试线索：用户操作 -> 到达这里的步骤:**
        1. 用户在一个网页的输入框中输入了非 UTF-8 的字符，或者粘贴了包含非 UTF-8 字符的文本。
        2. JavaScript 代码尝试将这些字符通过 WebSocket 发送出去。
        3. `WebSocketChannel` 在发送前进行 UTF-8 验证，如果验证失败则阻止发送。
        4. 或者，远程服务器发送了一个包含无效 UTF-8 字符的文本消息，`WebSocketChannel` 在接收时检测到错误。

**总结来说，这部分代码主要测试了 `WebSocketChannel` 在处理数据帧（包括控制帧和数据帧）时的正确性，以及对 UTF-8 编码的强制执行。它涵盖了发送和接收两个方向的逻辑，并确保了 WebSocket 协议规范的正确实现。**

### 提示词
```
这是目录为net/websockets/websocket_channel_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
OnFailChannel(
          "Received a broken close frame containing a reserved status code.", _,
          _));

  CreateChannelAndConnectSuccessfully();
}

// A Close frame with invalid UTF-8 also elicits a specific console error
// message.
TEST_F(WebSocketChannelEventInterfaceTest, ClosePayloadInvalidReason) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED,  CLOSE_DATA(NORMAL_CLOSURE, "\xFF")}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(
      *event_interface_,
      OnFailChannel("Received a broken close frame containing invalid UTF-8.",
                    _, _));

  CreateChannelAndConnectSuccessfully();
}

// The reserved bits must all be clear on received frames. Extensions should
// clear the bits when they are set correctly before passing on the frame.
TEST_F(WebSocketChannelEventInterfaceTest, ReservedBitsMustNotBeSet) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText,
       NOT_MASKED,  "sakana"}};
  // It is not worth adding support for reserved bits to InitFrame just for this
  // one test, so set the bit manually.
  std::vector<std::unique_ptr<WebSocketFrame>> raw_frames =
      CreateFrameVector(frames, &result_frame_data_);
  raw_frames[0]->header.reserved1 = true;
  stream->PrepareRawReadFrames(ReadableFakeWebSocketStream::SYNC, OK,
                               std::move(raw_frames));
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(*event_interface_,
              OnFailChannel("One or more reserved bits are on: reserved1 = 1, "
                            "reserved2 = 0, reserved3 = 0",
                            _, _));

  CreateChannelAndConnectSuccessfully();
}

// The closing handshake times out and sends an OnDropChannel event if no
// response to the client Close message is received.
TEST_F(WebSocketChannelEventInterfaceTest,
       ClientInitiatedClosingHandshakeTimesOut) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::SYNC,
                                 ERR_IO_PENDING);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  // This checkpoint object verifies that the OnDropChannel message comes after
  // the timeout.
  Checkpoint checkpoint;
  TestClosure completion;
  {
    InSequence s;
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*event_interface_,
                OnDropChannel(false, kWebSocketErrorAbnormalClosure, _))
        .WillOnce(InvokeClosure(&completion));
  }
  CreateChannelAndConnectSuccessfully();
  // OneShotTimer is not very friendly to testing; there is no apparent way to
  // set an expectation on it. Instead the tests need to infer that the timeout
  // was fired by the behaviour of the WebSocketChannel object.
  channel_->SetClosingHandshakeTimeoutForTesting(
      base::Milliseconds(kVeryTinyTimeoutMillis));
  channel_->SetUnderlyingConnectionCloseTimeoutForTesting(
      base::Milliseconds(kVeryBigTimeoutMillis));
  ASSERT_EQ(CHANNEL_ALIVE,
            channel_->StartClosingHandshake(kWebSocketNormalClosure, ""));
  checkpoint.Call(1);
  completion.WaitForResult();
}

// The closing handshake times out and sends an OnDropChannel event if a Close
// message is received but the connection isn't closed by the remote host.
TEST_F(WebSocketChannelEventInterfaceTest,
       ServerInitiatedClosingHandshakeTimesOut) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED,  CLOSE_DATA(NORMAL_CLOSURE, "OK")}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  Checkpoint checkpoint;
  TestClosure completion;
  {
    InSequence s;
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*event_interface_, OnClosingHandshake());
    EXPECT_CALL(*event_interface_,
                OnDropChannel(true, kWebSocketNormalClosure, _))
        .WillOnce(InvokeClosure(&completion));
  }
  CreateChannelAndConnectSuccessfully();
  channel_->SetClosingHandshakeTimeoutForTesting(
      base::Milliseconds(kVeryBigTimeoutMillis));
  channel_->SetUnderlyingConnectionCloseTimeoutForTesting(
      base::Milliseconds(kVeryTinyTimeoutMillis));
  checkpoint.Call(1);
  completion.WaitForResult();
}

// We should stop calling ReadFrames() when data frames are pending.
TEST_F(WebSocketChannelStreamTest, PendingDataFrameStopsReadFrames) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "FOUR"}};
  Checkpoint checkpoint;

  {
    InSequence s;
    EXPECT_CALL(*event_interface_, HasPendingDataFrames())
        .WillOnce(Return(false));
    EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
        .WillOnce(ReturnFrames(&frames, &result_frame_data_));
    EXPECT_CALL(*event_interface_, HasPendingDataFrames())
        .WillOnce(Return(true));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*event_interface_, HasPendingDataFrames())
        .WillOnce(Return(true));
    EXPECT_CALL(checkpoint, Call(2));
    EXPECT_CALL(*event_interface_, HasPendingDataFrames())
        .WillOnce(Return(false));
    EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
        .WillOnce(Return(ERR_IO_PENDING));
  }

  CreateChannelAndConnectSuccessfully();
  checkpoint.Call(1);
  ASSERT_EQ(CHANNEL_ALIVE, channel_->ReadFrames());
  checkpoint.Call(2);
  ASSERT_EQ(CHANNEL_ALIVE, channel_->ReadFrames());
}

TEST_F(WebSocketChannelEventInterfaceTest, SingleFrameMessage) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "FOUR"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("FOUR")));
  }

  CreateChannelAndConnectSuccessfully();
  ASSERT_EQ(CHANNEL_ALIVE, channel_->ReadFrames());
}

TEST_F(WebSocketChannelEventInterfaceTest, EmptyMessage) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED,
       "FIRST MESSAGE"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, nullptr},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED,
       "THIRD MESSAGE"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("FIRST MESSAGE")));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("")));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("THIRD MESSAGE")));
  }

  CreateChannelAndConnectSuccessfully();
  ASSERT_EQ(CHANNEL_ALIVE, channel_->ReadFrames());
}

// A close frame should not overtake data frames.
TEST_F(WebSocketChannelEventInterfaceTest,
       CloseFrameShouldNotOvertakeDataFrames) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED,
       "FIRST "},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation, NOT_MASKED,
       "MESSAGE"},
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED,
       "SECOND "},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, NOT_MASKED,
       CLOSE_DATA(NORMAL_CLOSURE, "GOOD BYE")},
  };
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));
  Checkpoint checkpoint;
  InSequence s;
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(*event_interface_, HasPendingDataFrames()).WillOnce(Return(true));
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*event_interface_, HasPendingDataFrames())
      .WillOnce(Return(false));
  EXPECT_CALL(*event_interface_,
              OnDataFrameVector(false, WebSocketFrameHeader::kOpCodeText,
                                AsVector("FIRST ")));
  EXPECT_CALL(*event_interface_,
              OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsVector("MESSAGE")));
  EXPECT_CALL(*event_interface_,
              OnDataFrameVector(false, WebSocketFrameHeader::kOpCodeText,
                                AsVector("SECOND ")));
  EXPECT_CALL(*event_interface_, OnClosingHandshake());

  CreateChannelAndConnectSuccessfully();
  checkpoint.Call(1);
  ASSERT_EQ(CHANNEL_ALIVE, channel_->ReadFrames());
}

// RFC6455 5.1 "a client MUST mask all frames that it sends to the server".
// WebSocketChannel actually only sets the mask bit in the header, it doesn't
// perform masking itself (not all transports actually use masking).
TEST_F(WebSocketChannelStreamTest, SentFramesAreMasked) {
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText,
       MASKED,      "NEEDS MASKING"}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));

  CreateChannelAndConnectSuccessfully();
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("NEEDS MASKING"), 13U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// RFC6455 5.5.1 "The application MUST NOT send any more data frames after
// sending a Close frame."
TEST_F(WebSocketChannelStreamTest, NothingIsSentAfterClose) {
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(NORMAL_CLOSURE, "Success")}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));

  CreateChannelAndConnectSuccessfully();
  ASSERT_EQ(CHANNEL_ALIVE, channel_->StartClosingHandshake(1000, "Success"));
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("SHOULD  BE IGNORED"), 18U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// RFC6455 5.5.1 "If an endpoint receives a Close frame and did not previously
// send a Close frame, the endpoint MUST send a Close frame in response."
TEST_F(WebSocketChannelStreamTest, CloseIsEchoedBack) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED,  CLOSE_DATA(NORMAL_CLOSURE, "Close")}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(NORMAL_CLOSURE, "Close")}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));

  CreateChannelAndConnectSuccessfully();
}

// The converse of the above case; after sending a Close frame, we should not
// send another one.
TEST_F(WebSocketChannelStreamTest, CloseOnlySentOnce) {
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(NORMAL_CLOSURE, "Close")}};
  static const InitFrame frames_init[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED,  CLOSE_DATA(NORMAL_CLOSURE, "Close")}};

  // We store the parameters that were passed to ReadFrames() so that we can
  // call them explicitly later.
  CompletionOnceCallback read_callback;
  std::vector<std::unique_ptr<WebSocketFrame>>* frames = nullptr;

  // Use a checkpoint to make the ordering of events clearer.
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce([&](auto f, auto cb) {
      frames = f;
      read_callback = std::move(cb);
      return ERR_IO_PENDING;
    });
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
        .WillOnce(Return(OK));
    EXPECT_CALL(checkpoint, Call(2));
    EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
        .WillOnce(Return(ERR_IO_PENDING));
    EXPECT_CALL(checkpoint, Call(3));
    // WriteFrames() must not be called again. GoogleMock will ensure that the
    // test fails if it is.
  }

  CreateChannelAndConnectSuccessfully();
  checkpoint.Call(1);
  ASSERT_EQ(CHANNEL_ALIVE,
            channel_->StartClosingHandshake(kWebSocketNormalClosure, "Close"));
  checkpoint.Call(2);
  ASSERT_TRUE(frames);
  *frames = CreateFrameVector(frames_init, &result_frame_data_);
  std::move(read_callback).Run(OK);
  checkpoint.Call(3);
}

// Invalid close status codes should not be sent on the network.
TEST_F(WebSocketChannelStreamTest, InvalidCloseStatusCodeNotSent) {
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(SERVER_ERROR, "")}};

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));

  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _));

  CreateChannelAndConnectSuccessfully();
  ASSERT_EQ(CHANNEL_ALIVE, channel_->StartClosingHandshake(999, ""));
}

// A Close frame with a reason longer than 123 bytes cannot be sent on the
// network.
TEST_F(WebSocketChannelStreamTest, LongCloseReasonNotSent) {
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(SERVER_ERROR, "")}};

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));

  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _));

  CreateChannelAndConnectSuccessfully();
  ASSERT_EQ(CHANNEL_ALIVE,
            channel_->StartClosingHandshake(1000, std::string(124, 'A')));
}

// We generate code 1005, kWebSocketErrorNoStatusReceived, when there is no
// status in the Close message from the other side. Code 1005 is not allowed to
// appear on the wire, so we should not echo it back. See test
// CloseWithNoPayloadGivesStatus1005, above, for confirmation that code 1005 is
// correctly generated internally.
TEST_F(WebSocketChannelStreamTest, Code1005IsNotEchoed) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, NOT_MASKED, ""}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, MASKED, ""}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));

  CreateChannelAndConnectSuccessfully();
}

TEST_F(WebSocketChannelStreamTest, Code1005IsNotEchoedNull) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, NOT_MASKED, nullptr}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, MASKED, ""}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));

  CreateChannelAndConnectSuccessfully();
}

// Receiving an invalid UTF-8 payload in a Close frame causes us to fail the
// connection.
TEST_F(WebSocketChannelStreamTest, CloseFrameInvalidUtf8) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED, CLOSE_DATA(NORMAL_CLOSURE, "\xFF")}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED, CLOSE_DATA(PROTOCOL_ERROR, "Invalid UTF-8 in Close frame")}};
  NetLogWithSource net_log_with_source;

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, Close());

  CreateChannelAndConnectSuccessfully();
}

// RFC6455 5.5.2 "Upon receipt of a Ping frame, an endpoint MUST send a Pong
// frame in response"
// 5.5.3 "A Pong frame sent in response to a Ping frame must have identical
// "Application data" as found in the message body of the Ping frame being
// replied to."
TEST_F(WebSocketChannelStreamTest, PingRepliedWithPong) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePing,
       NOT_MASKED,  "Application data"}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePong,
       MASKED,      "Application data"}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));

  CreateChannelAndConnectSuccessfully();
}

// A ping with a null payload should be responded to with a Pong with a null
// payload.
TEST_F(WebSocketChannelStreamTest, NullPingRepliedWithNullPong) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePing, NOT_MASKED, nullptr}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePong, MASKED, nullptr}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));

  CreateChannelAndConnectSuccessfully();
}

TEST_F(WebSocketChannelStreamTest, PongInTheMiddleOfDataMessage) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePing,
       NOT_MASKED,  "Application data"}};
  static const InitFrame expected1[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "Hello "}};
  static const InitFrame expected2[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePong,
       MASKED,      "Application data"}};
  static const InitFrame expected3[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       MASKED,      "World"}};
  std::vector<std::unique_ptr<WebSocketFrame>>* read_frames;
  CompletionOnceCallback read_callback;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce([&](auto frames, auto cb) {
        read_frames = std::move(frames);
        read_callback = std::move(cb);
        return ERR_IO_PENDING;
      })
      .WillRepeatedly(Return(ERR_IO_PENDING));
  {
    InSequence s;

    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected1), _))
        .WillOnce(Return(OK));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected2), _))
        .WillOnce(Return(OK));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected3), _))
        .WillOnce(Return(OK));
  }

  CreateChannelAndConnectSuccessfully();
  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("Hello "), 6U),
            WebSocketChannel::CHANNEL_ALIVE);
  *read_frames = CreateFrameVector(frames, &result_frame_data_);
  std::move(read_callback).Run(OK);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("World"), 5U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// WriteFrames() may not be called until the previous write has completed.
// WebSocketChannel must buffer writes that happen in the meantime.
TEST_F(WebSocketChannelStreamTest, WriteFramesOneAtATime) {
  static const InitFrame expected1[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "Hello "}};
  static const InitFrame expected2[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "World"}};
  CompletionOnceCallback write_callback;
  Checkpoint checkpoint;

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));
  {
    InSequence s;
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected1), _))
        .WillOnce([&](auto, auto cb) {
          write_callback = std::move(cb);
          return ERR_IO_PENDING;
        });
    EXPECT_CALL(checkpoint, Call(2));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected2), _))
        .WillOnce(Return(ERR_IO_PENDING));
    EXPECT_CALL(checkpoint, Call(3));
  }

  CreateChannelAndConnectSuccessfully();
  checkpoint.Call(1);
  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("Hello "), 6U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("World"), 5U),
            WebSocketChannel::CHANNEL_ALIVE);
  checkpoint.Call(2);
  std::move(write_callback).Run(OK);
  checkpoint.Call(3);
}

// WebSocketChannel must buffer frames while it is waiting for a write to
// complete, and then send them in a single batch. The batching behaviour is
// important to get good throughput in the "many small messages" case.
TEST_F(WebSocketChannelStreamTest, WaitingMessagesAreBatched) {
  static const char input_letters[] = "Hello";
  static const InitFrame expected1[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "H"}};
  static const InitFrame expected2[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "e"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "l"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "l"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "o"}};
  CompletionOnceCallback write_callback;

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected1), _))
        .WillOnce([&](auto, auto cb) {
          write_callback = std::move(cb);
          return ERR_IO_PENDING;
        });
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected2), _))
        .WillOnce(Return(ERR_IO_PENDING));
  }

  CreateChannelAndConnectSuccessfully();
  for (size_t i = 0; i < strlen(input_letters); ++i) {
    EXPECT_EQ(
        channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                            AsIOBuffer(std::string(1, input_letters[i])), 1U),
        WebSocketChannel::CHANNEL_ALIVE);
  }
  std::move(write_callback).Run(OK);
}

// For convenience, most of these tests use Text frames. However, the WebSocket
// protocol also has Binary frames and those need to be 8-bit clean. For the
// sake of completeness, this test verifies that they are.
TEST_F(WebSocketChannelStreamTest, WrittenBinaryFramesAre8BitClean) {
  std::vector<std::unique_ptr<WebSocketFrame>>* frames = nullptr;

  EXPECT_CALL(*mock_stream_, ReadFrames(_, _)).WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(_, _))
      .WillOnce(DoAll(SaveArg<0>(&frames), Return(ERR_IO_PENDING)));

  CreateChannelAndConnectSuccessfully();
  EXPECT_EQ(
      channel_->SendFrame(
          true, WebSocketFrameHeader::kOpCodeBinary,
          AsIOBuffer(std::string(kBinaryBlob, kBinaryBlob + kBinaryBlobSize)),
          kBinaryBlobSize),
      WebSocketChannel::CHANNEL_ALIVE);
  ASSERT_TRUE(frames != nullptr);
  ASSERT_EQ(1U, frames->size());
  const WebSocketFrame* out_frame = (*frames)[0].get();
  EXPECT_EQ(kBinaryBlobSize, out_frame->header.payload_length);
  ASSERT_FALSE(out_frame->payload.empty());
  EXPECT_EQ(std::string_view(kBinaryBlob, kBinaryBlobSize),
            base::as_string_view(out_frame->payload));
}

// Test the read path for 8-bit cleanliness as well.
TEST_F(WebSocketChannelEventInterfaceTest, ReadBinaryFramesAre8BitClean) {
  auto frame =
      std::make_unique<WebSocketFrame>(WebSocketFrameHeader::kOpCodeBinary);
  WebSocketFrameHeader& frame_header = frame->header;
  frame_header.final = true;
  frame_header.payload_length = kBinaryBlobSize;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(kBinaryBlobSize);
  memcpy(buffer->data(), kBinaryBlob, kBinaryBlobSize);
  frame->payload = buffer->span();
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  frames.push_back(std::move(frame));
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  stream->PrepareRawReadFrames(ReadableFakeWebSocketStream::SYNC, OK,
                               std::move(frames));
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(
      *event_interface_,
      OnDataFrameVector(
          true, WebSocketFrameHeader::kOpCodeBinary,
          std::vector<char>(kBinaryBlob, kBinaryBlob + kBinaryBlobSize)));

  CreateChannelAndConnectSuccessfully();
}

// Invalid UTF-8 is not permitted in Text frames.
TEST_F(WebSocketChannelSendUtf8Test, InvalidUtf8Rejected) {
  EXPECT_CALL(*event_interface_,
              OnFailChannel(
                  "Browser sent a text frame containing invalid UTF-8", _, _));

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xff"), 1U),
            WebSocketChannel::CHANNEL_DELETED);
}

// A Text message cannot end with a partial UTF-8 character.
TEST_F(WebSocketChannelSendUtf8Test, IncompleteCharacterInFinalFrame) {
  EXPECT_CALL(*event_interface_,
              OnFailChannel(
                  "Browser sent a text frame containing invalid UTF-8", _, _));

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xc2"), 1U),
            WebSocketChannel::CHANNEL_DELETED);
}

// A non-final Text frame may end with a partial UTF-8 character (compare to
// previous test).
TEST_F(WebSocketChannelSendUtf8Test, IncompleteCharacterInNonFinalFrame) {
  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xc2"), 1U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// UTF-8 parsing context must be retained between frames.
TEST_F(WebSocketChannelSendUtf8Test, ValidCharacterSplitBetweenFrames) {
  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xf1"), 1U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("\x80\xa0\xbf"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// Similarly, an invalid character should be detected even if split.
TEST_F(WebSocketChannelSendUtf8Test, InvalidCharacterSplit) {
  EXPECT_CALL(*event_interface_,
              OnFailChannel(
                  "Browser sent a text frame containing invalid UTF-8", _, _));

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xe1"), 1U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("\x80\xa0\xbf"), 3U),
            WebSocketChannel::CHANNEL_DELETED);
}

// An invalid character must be detected in continuation frames.
TEST_F(WebSocketChannelSendUtf8Test, InvalidByteInContinuation) {
  EXPECT_CALL(*event_interface_,
              OnFailChannel(
                  "Browser sent a text frame containing invalid UTF-8", _, _));

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("foo"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(
      channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeContinuation,
                          AsIOBuffer("bar"), 3U),
      WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("\xff"), 1U),
            WebSocketChannel::CHANNEL_DELETED);
}

// However, continuation frames of a Binary frame will not be tested for UTF-8
// validity.
TEST_F(WebSocketChannelSendUtf8Test, BinaryContinuationNotChecked) {
  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeBinary,
                                AsIOBuffer("foo"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(
      channel_->SendFrame(false, WebSocketFrameHeader::kOpCodeContinuation,
                          AsIOBuffer("bar"), 3U),
      WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeContinuation,
                                AsIOBuffer("\xff"), 1U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// Multiple text messages can be validated without the validation state getting
// confused.
TEST_F(WebSocketChannelSendUtf8Test, ValidateMultipleTextMessages) {
  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("foo"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("bar"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
}

// UTF-8 validation is enforced on received Text frames.
TEST_F(WebSocketChannelEventInterfaceTest, ReceivedInvalidUtf8) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "\xff"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));

  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(*event_interface_,
              OnFailChannel("Could not decode a text frame as UTF-8.", _, _));

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// Invalid UTF-8 is not sent over the network.
TEST_F(WebSocketChannelStreamTest, InvalidUtf8TextFrameNotSent) {
  static const InitFrame expected[] = {{FINAL_FRAME,
                                        WebSocketFrameHeader::kOpCodeClose,
                                        MASKED, CLOSE_DATA(GOING_AWAY, "")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, Close()).Times(1);

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("\xff"), 1U),
            WebSocketChannel::CHANNEL_DELETED);
}

// The rest of the tests for receiving invalid UTF-8 test the communication with
// the server. Since there is only one code path, it would be redundant to
// perform the same tests on th
```
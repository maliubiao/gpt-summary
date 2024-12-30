Response:
Let's break down the thought process to analyze the provided C++ code snippet for `websocket_channel_test.cc`.

1. **Understand the Goal:** The request asks for the *functionality* of this specific part of the test file, its relation to JavaScript, examples of logical reasoning, common user errors, debugging information, and a summary of its purpose within the larger file. It's the *fourth* part, suggesting previous parts established some context.

2. **Initial Scan for Clues:** Quickly read through the code, paying attention to:
    * **File name:** `websocket_channel_test.cc`. This immediately tells us it's a test file for WebSocket functionality within the Chromium networking stack.
    * **Class names:** `WebSocketChannelReceiveUtf8Test`, `WebSocketChannelEventInterfaceTest`, `WebSocketChannelStreamTest`, `WebSocketChannelStreamTimeoutTest`. These names clearly indicate the focus of the tests: receiving UTF-8 data, the `EventInterface`, general stream behavior, and timeout scenarios.
    * **Keywords:** `TEST_F`, `EXPECT_CALL`, `Return`, `ReturnFrames`, `CreateChannelAndConnectSuccessfully`. These are typical Google Test (gtest/gmock) constructs. `TEST_F` defines test cases within a test fixture. `EXPECT_CALL` sets up expectations for interactions with mock objects. `Return` specifies the return value of mock methods. `ReturnFrames` seems specific to this test setup, likely returning pre-defined WebSocket frames.
    * **Specific checks:** Look for patterns in the assertions and expected behavior. Notice tests related to invalid UTF-8, incomplete UTF-8 sequences, handling continuation frames, checking for protocol errors, and handling timeouts during the closing handshake.

3. **Categorize Functionality by Test Fixture:**  The test fixtures naturally group the tests by area of focus:

    * **`WebSocketChannelReceiveUtf8Test`:** This section is clearly focused on verifying correct handling of UTF-8 encoding in received WebSocket text frames. It tests scenarios with invalid UTF-8, partial characters, and the behavior of continuation frames in relation to UTF-8 validation.

    * **`WebSocketChannelEventInterfaceTest`:** This section tests the interaction between `WebSocketChannel` and its `EventInterface`. It checks if events are correctly passed to the interface (e.g., `OnAddChannelResponse`, `OnDataFrameVector`, `OnFailChannel`, `OnSSLCertificateErrorCalled`, `OnAuthRequiredCalled`). This indicates how the core WebSocket logic communicates with higher-level components.

    * **`WebSocketChannelStreamTest`:** This section appears to test fundamental stream-level behavior. The "PingAfterCloseIsRejected" test checks the handling of frames received after a close handshake. The "ProtocolError" test checks how the channel reacts to a generic WebSocket protocol error.

    * **`WebSocketChannelStreamTimeoutTest`:** This section specifically tests timeout scenarios during the WebSocket closing handshake, both when the server initiates the close and when the client initiates it.

4. **Analyze Individual Test Cases:** For each test case, try to understand:
    * **The scenario:** What specific condition or sequence of events is being tested? (Read the test name and look at the `frames` array if present.)
    * **The expected outcome:** What should the `WebSocketChannel` do in this scenario? (Look for `EXPECT_CALL`s on the mock stream and event interface, and the `expected` frames for close messages).
    * **How the test is set up:**  How are the mock objects configured? What input frames are provided?

5. **Relate to JavaScript (if applicable):**  Think about how these low-level behaviors manifest in a JavaScript WebSocket API:
    * **UTF-8 tests:** Directly relate to the `message` event on a `WebSocket` object. JavaScript expects valid UTF-8 for text messages.
    * **EventInterface tests:**  Connect to the different events the JavaScript `WebSocket` object provides: `open`, `message`, `close`, `error`. The `OnSSLCertificateErrorCalled` and `OnAuthRequiredCalled` have less direct JavaScript equivalents but relate to the underlying connection establishment.
    * **Stream and Timeout tests:** These are more about the underlying connection management and protocol handling, less directly exposed in JavaScript but impact the reliability and behavior of the `WebSocket`.

6. **Identify Logical Reasoning and Input/Output:** Focus on tests where an *input* (received frame) leads to a specific *output* (sending a close frame, failing the channel). The `InvalidTextFrameRejected` and similar UTF-8 tests are good examples. The input is an invalid UTF-8 frame, and the expected output is sending a close frame with a specific error code.

7. **Consider User/Programming Errors:** Think about what mistakes developers might make when using WebSockets that these tests are designed to catch:
    * Sending or receiving invalid UTF-8 in text messages.
    * Sending control frames (like Ping) after initiating a close.
    * Relying on specific timeout behaviors.

8. **Trace User Actions (Debugging):**  Imagine a user interaction that leads to these code paths. A user browsing a webpage that uses WebSockets, receiving data, or experiencing connection issues would be relevant. The tests simulate the *server's* perspective (receiving frames), so user actions that trigger server responses are key.

9. **Synthesize and Summarize:**  Combine the individual observations into a coherent description of the file's purpose. Focus on the main areas being tested and the overall goal of ensuring correct and robust WebSocket behavior.

10. **Address the "Part 4" Aspect:** Since it's the fourth part, assume previous parts covered basic connection setup and sending data. This part seems to focus on *receiving* data, handling errors, and managing the closing handshake.

**Self-Correction/Refinement during the process:**

* **Initially, I might focus too much on the gtest syntax.**  Realize that the *purpose* of the tests is more important than the exact gmock details.
* **The connection to JavaScript might not be immediately obvious for all tests.**  Think harder about how the underlying protocol behavior affects the JavaScript API.
* **The "user error" aspect requires thinking from the perspective of a *developer* using the WebSocket API, not an end-user directly.**
* **Ensure the summary accurately reflects the balance of topics covered in this specific part of the file.**

By following these steps and refining the analysis iteratively, we can arrive at a comprehensive understanding of the provided code snippet.
这是 `net/websockets/websocket_channel_test.cc` 文件的第四部分，主要关注 `WebSocketChannel` 在接收数据时的 UTF-8 校验，以及与 `EventInterface` 的交互，还有一些关于连接关闭和超时的测试。

**功能归纳 (基于提供的第四部分):**

这部分测试主要集中在以下几个方面：

1. **接收 UTF-8 文本帧的校验:**
   - 验证 `WebSocketChannel` 能否正确检测并拒绝包含无效 UTF-8 字符的文本帧。
   - 验证 `WebSocketChannel` 能否正确处理文本帧末尾的 UTF-8 部分字符，并判断是否构成错误。
   - 验证 `WebSocketChannel` 能否跨帧保留 UTF-8 解析上下文，正确解析分片发送的 UTF-8 文本消息。
   - 验证对于二进制帧的延续帧，不会进行 UTF-8 校验。
   - 验证可以正确处理连续接收的多个 UTF-8 文本消息。

2. **与 `EventInterface` 的交互:**
   - 测试当接收到非法的 Continuation 帧时，`WebSocketChannel` 如何通过 `EventInterface` 通知上层。
   - 测试发送给渲染器的 Data 帧必须是非空或者设置了 final 位。
   - 测试 `OnSSLCertificateError()` 和 `OnAuthRequired()` 等事件能够正确地传递给 `EventInterface`。

3. **连接关闭相关的测试:**
   - 测试在已经发送 Close 帧之后，如果收到新的帧（例如 Ping），`WebSocketChannel` 会拒绝并关闭连接。
   - 测试当底层 stream 报告协议错误时，`WebSocketChannel` 会发送 Close 帧并关闭连接。

4. **连接超时相关的测试 (在 `WebSocketChannelStreamTimeoutTest` fixture 中):**
   - 测试当服务端发起关闭握手后，如果服务端不关闭 TCP 连接，客户端会因为超时而主动关闭连接。
   - 测试当客户端发起关闭握手后，如果服务端不响应 Close 帧，客户端会因为超时而主动关闭连接。
   - 测试当客户端发起关闭握手，服务端响应 Close 帧后，如果服务端不关闭 TCP 连接，客户端会因为超时而主动关闭连接。

**与 Javascript 的功能关系及举例说明:**

这部分测试的功能直接关系到 JavaScript WebSocket API 的行为。当 JavaScript 代码通过 `new WebSocket()` 创建一个 WebSocket 连接并接收数据时，底层的 Chromium 网络栈就会用到 `WebSocketChannel` 来处理接收到的帧。

* **UTF-8 校验:**  如果 JavaScript 代码尝试接收一个包含无效 UTF-8 字符的文本消息，根据这些测试，`WebSocketChannel` 会检测到错误并关闭连接。这会导致 JavaScript 的 `WebSocket` 对象的 `onerror` 事件被触发，并且 `onclose` 事件的 `code` 属性可能是 1002 (Protocol Error)。

   **举例说明:**

   **假设输入 (服务端发送):**  一个包含无效 UTF-8 字符的文本帧，例如 `\xff`。

   **逻辑推理:** `WebSocketChannel` 检测到 `\xff` 不是有效的 UTF-8 序列，触发错误处理逻辑。

   **预期输出 (客户端行为):** `WebSocketChannel` 发送一个 Close 帧，状态码为 1002，并关闭底层连接。JavaScript 端会触发 `onerror` 和 `onclose` 事件。

* **接收到非法 Continuation 帧:** 如果服务端发送了一个以 Continuation 帧开始的消息，或者在一个消息中间插入了一个新的起始帧，`WebSocketChannel` 会判断为协议错误并关闭连接。这也会导致 JavaScript 的 `onerror` 和 `onclose` 事件被触发。

   **举例说明:**

   **假设输入 (服务端发送):** 一个 OpCode 为 Continuation 的帧，但之前没有收到起始帧。

   **逻辑推理:** `WebSocketChannel` 发现接收到了一个意外的 Continuation 帧，违反了协议。

   **预期输出 (客户端行为):** `WebSocketChannel` 发送一个 Close 帧并关闭连接。JavaScript 端会收到错误通知。

**逻辑推理的假设输入与输出:**

以下列举一些测试用例中的逻辑推理：

* **假设输入 (服务端发送):** 一个 Final 标志位为 false 的 Text 帧，内容为 `\xc2` (一个双字节 UTF-8 字符的第一个字节)。
   **逻辑推理:** `WebSocketChannel` 允许非最终帧以部分 UTF-8 字符结尾，因为它可能在后续的 Continuation 帧中补全。
   **预期输出 (客户端行为):** `WebSocketChannel` 接收并缓存这部分数据，等待后续的 Continuation 帧。

* **假设输入 (服务端发送):**  先发送一个 Final 标志位为 false 的 Text 帧，内容为 `\xc2`，然后发送一个 Final 标志位为 true 的 Continuation 帧，内容为空。
   **逻辑推理:**  虽然第一个帧以部分 UTF-8 字符结尾，但后续的最终 Continuation 帧没有提供剩余的字节来完成 UTF-8 字符，因此整个消息是无效的 UTF-8。
   **预期输出 (客户端行为):** `WebSocketChannel` 发送 Close 帧，状态码为 1002，并关闭连接。

* **假设输入 (服务端发送):** 在发送一个 Close 帧之后，又发送了一个 Ping 帧。
   **逻辑推理:**  一旦连接进入关闭握手阶段，不应该再接收到新的非关闭帧。
   **预期输出 (客户端行为):** `WebSocketChannel` 忽略 Ping 帧，并可能直接关闭底层连接（因为已经发送了 Close）。

**涉及用户或编程常见的使用错误及举例说明:**

虽然这些是底层网络栈的测试，但它们反映了用户或开发者在使用 WebSocket 时可能遇到的问题：

* **服务端发送无效的 UTF-8 数据:**  如果服务端代码在发送文本消息时没有正确进行 UTF-8 编码，客户端的 `WebSocketChannel` 会检测到并关闭连接。这会导致客户端 JavaScript 代码收到错误，用户可能会看到连接断开的提示。

   **举例:** 服务端使用错误的编码方式（例如 ISO-8859-1）发送包含非 ASCII 字符的文本消息，而不是 UTF-8。

* **客户端或服务端没有正确处理关闭握手:** 如果一方在应该响应 Close 帧的时候没有响应，或者在已经发送 Close 后仍然尝试发送数据，就可能触发这里的超时或协议错误处理。

   **举例:**  一个 WebSocket 服务端实现有 bug，在收到客户端的 Close 帧后没有发送自己的 Close 帧，导致客户端超时关闭连接。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户在浏览器中访问一个使用 WebSocket 的网页时，以下步骤可能会导致代码执行到 `net/websockets/websocket_channel_test.cc` 中测试的逻辑：

1. **用户打开网页:** 浏览器加载网页，网页中的 JavaScript 代码尝试创建一个 WebSocket 连接，例如 `ws = new WebSocket("wss://example.com")`。
2. **建立连接:**  Chromium 网络栈会处理 WebSocket 的握手过程。
3. **接收数据:** 一旦连接建立，服务端可能会向客户端发送数据。
4. **数据帧到达 `WebSocketChannel`:**  接收到的 WebSocket 数据帧会被传递到 `WebSocketChannel` 进行处理。
5. **UTF-8 校验 (对于文本帧):** 如果接收到的是文本帧，`WebSocketChannel` 会根据这里的测试逻辑进行 UTF-8 校验。如果数据包含无效的 UTF-8 字符，就会触发相应的错误处理流程。
6. **事件传递:**  `WebSocketChannel` 通过 `EventInterface` 将接收到的数据或错误事件通知给上层，最终会影响到 JavaScript 的 `WebSocket` 对象的事件回调（`onmessage`, `onerror`, `onclose`）。
7. **连接关闭:** 如果服务端或客户端发起关闭连接，或者因为协议错误需要关闭连接，就会涉及到这里的连接关闭和超时测试的逻辑。

**调试线索:**

如果开发者在调试 WebSocket 相关问题，例如：

* **`onerror` 事件被触发，但是不知道原因:** 可以检查服务端发送的数据是否符合 UTF-8 编码规范。查看 Chromium 的 NetLog (chrome://net-internals/#log) 可以提供更详细的网络层信息，包括 WebSocket 帧的内容和错误信息。
* **连接意外断开:** 可以检查服务端和客户端的关闭握手逻辑是否正确实现，是否存在超时的情况。NetLog 也能提供关于连接关闭原因的信息。
* **接收到的数据乱码:**  可能是服务端没有使用 UTF-8 编码发送文本消息，或者客户端解码时出现了问题，但这部分测试主要关注的是 `WebSocketChannel` *识别* 无效 UTF-8 的能力。

总而言之，`net/websockets/websocket_channel_test.cc` 的这第四部分主要测试了 `WebSocketChannel` 在接收数据时，特别是处理 UTF-8 文本帧时的正确性和健壮性，以及在连接关闭和超时场景下的行为，确保了 Chromium 的 WebSocket 实现能够可靠地与服务端进行通信。

Prompt: 
```
这是目录为net/websockets/websocket_channel_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
e EventInterface as well.

// If invalid UTF-8 is received in a Text frame, the connection is failed.
TEST_F(WebSocketChannelReceiveUtf8Test, InvalidTextFrameRejected) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "\xff"}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, MASKED,
       CLOSE_DATA(PROTOCOL_ERROR, "Invalid UTF-8 in text frame")}};
  NetLogWithSource net_log_with_source;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
        .WillOnce(ReturnFrames(&frames, &result_frame_data_))
        .WillRepeatedly(Return(ERR_IO_PENDING));
    EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
        .WillOnce(ReturnRef(net_log_with_source));
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
        .WillOnce(Return(OK));
    EXPECT_CALL(*mock_stream_, Close()).Times(1);
  }

  CreateChannelAndConnectSuccessfully();
}

// A received Text message is not permitted to end with a partial UTF-8
// character.
TEST_F(WebSocketChannelReceiveUtf8Test, IncompleteCharacterReceived) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "\xc2"}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, MASKED,
       CLOSE_DATA(PROTOCOL_ERROR, "Invalid UTF-8 in text frame")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, Close()).Times(1);

  CreateChannelAndConnectSuccessfully();
}

// However, a non-final Text frame may end with a partial UTF-8 character.
TEST_F(WebSocketChannelReceiveUtf8Test, IncompleteCharacterIncompleteMessage) {
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "\xc2"}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));

  CreateChannelAndConnectSuccessfully();
}

// However, it will become an error if it is followed by an empty final frame.
TEST_F(WebSocketChannelReceiveUtf8Test, TricksyIncompleteCharacter) {
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "\xc2"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation, NOT_MASKED, ""}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, MASKED,
       CLOSE_DATA(PROTOCOL_ERROR, "Invalid UTF-8 in text frame")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, Close()).Times(1);

  CreateChannelAndConnectSuccessfully();
}

// UTF-8 parsing context must be retained between received frames of the same
// message.
TEST_F(WebSocketChannelReceiveUtf8Test, ReceivedParsingContextRetained) {
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "\xf1"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,  "\x80\xa0\xbf"}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));

  CreateChannelAndConnectSuccessfully();
}

// An invalid character must be detected even if split between frames.
TEST_F(WebSocketChannelReceiveUtf8Test, SplitInvalidCharacterReceived) {
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "\xe1"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,  "\x80\xa0\xbf"}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, MASKED,
       CLOSE_DATA(PROTOCOL_ERROR, "Invalid UTF-8 in text frame")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, Close()).Times(1);

  CreateChannelAndConnectSuccessfully();
}

// An invalid character received in a continuation frame must be detected.
TEST_F(WebSocketChannelReceiveUtf8Test, InvalidReceivedIncontinuation) {
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "foo"},
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,      "bar"},
      {FINAL_FRAME,     WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,      "\xff"}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, MASKED,
       CLOSE_DATA(PROTOCOL_ERROR, "Invalid UTF-8 in text frame")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, Close()).Times(1);

  CreateChannelAndConnectSuccessfully();
}

// Continuations of binary frames must not be tested for UTF-8 validity.
TEST_F(WebSocketChannelReceiveUtf8Test, ReceivedBinaryNotUtf8Tested) {
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeBinary, NOT_MASKED, "foo"},
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,      "bar"},
      {FINAL_FRAME,     WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,      "\xff"}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));

  CreateChannelAndConnectSuccessfully();
}

// Multiple Text messages can be validated.
TEST_F(WebSocketChannelReceiveUtf8Test, ValidateMultipleReceived) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "foo"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "bar"}};
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));

  CreateChannelAndConnectSuccessfully();
}

// A new data message cannot start in the middle of another data message.
TEST_F(WebSocketChannelEventInterfaceTest, BogusContinuation) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeBinary,
       NOT_MASKED, "frame1"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText,
       NOT_MASKED, "frame2"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));

  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(*event_interface_,
              OnDataFrameVector(false, WebSocketFrameHeader::kOpCodeBinary,
                                AsVector("frame1")));
  EXPECT_CALL(
      *event_interface_,
      OnFailChannel(
          "Received start of new message but previous message is unfinished.",
          _, _));

  CreateChannelAndConnectSuccessfully();
}

// A new message cannot start with a Continuation frame.
TEST_F(WebSocketChannelEventInterfaceTest, MessageStartingWithContinuation) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED, "continuation"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));

  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(*event_interface_,
              OnFailChannel("Received unexpected continuation frame.", _, _));

  CreateChannelAndConnectSuccessfully();
}

// A frame passed to the renderer must be either non-empty or have the final bit
// set.
TEST_F(WebSocketChannelEventInterfaceTest, DataFramesNonEmptyOrFinal) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, ""},
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED, ""},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation, NOT_MASKED, ""}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));

  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(
      *event_interface_,
      OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText, AsVector("")));

  CreateChannelAndConnectSuccessfully();
}

// Calls to OnSSLCertificateError() must be passed through to the event
// interface with the correct URL attached.
TEST_F(WebSocketChannelEventInterfaceTest, OnSSLCertificateErrorCalled) {
  const GURL wss_url("wss://example.com/sslerror");
  connect_data_.socket_url = wss_url;
  const SSLInfo ssl_info;
  const bool fatal = true;
  auto fake_callbacks = std::make_unique<FakeSSLErrorCallbacks>();

  EXPECT_CALL(*event_interface_,
              OnSSLCertificateErrorCalled(NotNull(), wss_url, _, fatal));

  CreateChannelAndConnect();
  connect_data_.argument_saver.connect_delegate->OnSSLCertificateError(
      std::move(fake_callbacks), net::ERR_CERT_DATE_INVALID, ssl_info, fatal);
}

// Calls to OnAuthRequired() must be passed through to the event interface.
TEST_F(WebSocketChannelEventInterfaceTest, OnAuthRequiredCalled) {
  const GURL wss_url("wss://example.com/on_auth_required");
  connect_data_.socket_url = wss_url;
  AuthChallengeInfo auth_info;
  std::optional<AuthCredentials> credentials;
  auto response_headers =
      base::MakeRefCounted<HttpResponseHeaders>("HTTP/1.1 200 OK");
  IPEndPoint remote_endpoint(net::IPAddress(127, 0, 0, 1), 80);

  EXPECT_CALL(*event_interface_,
              OnAuthRequiredCalled(_, response_headers, _, &credentials))
      .WillOnce(Return(OK));

  CreateChannelAndConnect();
  connect_data_.argument_saver.connect_delegate->OnAuthRequired(
      auth_info, response_headers, remote_endpoint, {}, &credentials);
}

// If we receive another frame after Close, it is not valid. It is not
// completely clear what behaviour is required from the standard in this case,
// but the current implementation fails the connection. Since a Close has
// already been sent, this just means closing the connection.
TEST_F(WebSocketChannelStreamTest, PingAfterCloseIsRejected) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED,  CLOSE_DATA(NORMAL_CLOSURE, "OK")},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePing,
       NOT_MASKED,  "Ping body"}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(NORMAL_CLOSURE, "OK")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  {
    // We only need to verify the relative order of WriteFrames() and
    // Close(). The current implementation calls WriteFrames() for the Close
    // frame before calling ReadFrames() again, but that is an implementation
    // detail and better not to consider required behaviour.
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
        .WillOnce(Return(OK));
    EXPECT_CALL(*mock_stream_, Close()).Times(1);
  }

  CreateChannelAndConnectSuccessfully();
}

// A protocol error from the remote server should result in a close frame with
// status 1002, followed by the connection closing.
TEST_F(WebSocketChannelStreamTest, ProtocolError) {
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(PROTOCOL_ERROR, "WebSocket Protocol Error")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(Return(ERR_WS_PROTOCOL_ERROR));
  EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
      .WillOnce(Return(OK));
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, Close());

  CreateChannelAndConnectSuccessfully();
}

// Set the closing handshake timeout to a very tiny value before connecting.
class WebSocketChannelStreamTimeoutTest : public WebSocketChannelStreamTest {
 protected:
  WebSocketChannelStreamTimeoutTest() = default;

  void CreateChannelAndConnectSuccessfully() override {
    set_stream(std::move(mock_stream_));
    CreateChannelAndConnect();
    channel_->SetClosingHandshakeTimeoutForTesting(
        base::Milliseconds(kVeryTinyTimeoutMillis));
    channel_->SetUnderlyingConnectionCloseTimeoutForTesting(
        base::Milliseconds(kVeryTinyTimeoutMillis));
    connect_data_.argument_saver.connect_delegate->OnSuccess(
        std::move(stream_), std::make_unique<WebSocketHandshakeResponseInfo>(
                                GURL(), nullptr, IPEndPoint(), base::Time()));
    std::ignore = channel_->ReadFrames();
  }
};

// In this case the server initiates the closing handshake with a Close
// message. WebSocketChannel responds with a matching Close message, and waits
// for the server to close the TCP/IP connection. The server never closes the
// connection, so the closing handshake times out and WebSocketChannel closes
// the connection itself.
TEST_F(WebSocketChannelStreamTimeoutTest, ServerInitiatedCloseTimesOut) {
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED,  CLOSE_DATA(NORMAL_CLOSURE, "OK")}};
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(NORMAL_CLOSURE, "OK")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, GetSubProtocol()).Times(AnyNumber());
  EXPECT_CALL(*mock_stream_, GetExtensions()).Times(AnyNumber());
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillOnce(ReturnFrames(&frames, &result_frame_data_))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  Checkpoint checkpoint;
  TestClosure completion;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
        .WillOnce(Return(OK));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*mock_stream_, Close()).WillOnce(InvokeClosure(&completion));
  }

  CreateChannelAndConnectSuccessfully();
  checkpoint.Call(1);
  completion.WaitForResult();
}

// In this case the client initiates the closing handshake by sending a Close
// message. WebSocketChannel waits for a Close message in response from the
// server. The server never responds to the Close message, so the closing
// handshake times out and WebSocketChannel closes the connection.
TEST_F(WebSocketChannelStreamTimeoutTest, ClientInitiatedCloseTimesOut) {
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(NORMAL_CLOSURE, "OK")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, GetSubProtocol()).Times(AnyNumber());
  EXPECT_CALL(*mock_stream_, GetExtensions()).Times(AnyNumber());
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
      .WillRepeatedly(Return(ERR_IO_PENDING));
  TestClosure completion;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
        .WillOnce(Return(OK));
    EXPECT_CALL(*mock_stream_, Close()).WillOnce(InvokeClosure(&completion));
  }

  CreateChannelAndConnectSuccessfully();
  ASSERT_EQ(CHANNEL_ALIVE,
            channel_->StartClosingHandshake(kWebSocketNormalClosure, "OK"));
  completion.WaitForResult();
}

// In this case the client initiates the closing handshake and the server
// responds with a matching Close message. WebSocketChannel waits for the server
// to close the TCP/IP connection, but it never does. The closing handshake
// times out and WebSocketChannel closes the connection.
TEST_F(WebSocketChannelStreamTimeoutTest, ConnectionCloseTimesOut) {
  static const InitFrame expected[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       MASKED,      CLOSE_DATA(NORMAL_CLOSURE, "OK")}};
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED,  CLOSE_DATA(NORMAL_CLOSURE, "OK")}};
  NetLogWithSource net_log_with_source;
  EXPECT_CALL(*mock_stream_, GetSubProtocol()).Times(AnyNumber());
  EXPECT_CALL(*mock_stream_, GetExtensions()).Times(AnyNumber());
  EXPECT_CALL(*mock_stream_, GetNetLogWithSource())
      .WillOnce(ReturnRef(net_log_with_source));
  TestClosure completion;
  std::vector<std::unique_ptr<WebSocketFrame>>* read_frames = nullptr;
  CompletionOnceCallback read_callback;
  {
    InSequence s;
    // Copy the arguments to ReadFrames so that the test can call the callback
    // after it has send the close message.
    EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
        .WillOnce([&](auto frames, auto cb) {
          read_frames = frames;
          read_callback = std::move(cb);
          return ERR_IO_PENDING;
        });

    // The first real event that happens is the client sending the Close
    // message.
    EXPECT_CALL(*mock_stream_, WriteFrames(EqualsFrames(expected), _))
        .WillOnce(Return(OK));
    // The |read_frames| callback is called (from this test case) at this
    // point. ReadFrames is called again by WebSocketChannel, waiting for
    // ERR_CONNECTION_CLOSED.
    EXPECT_CALL(*mock_stream_, ReadFrames(_, _))
        .WillOnce(Return(ERR_IO_PENDING));
    // The timeout happens and so WebSocketChannel closes the stream.
    EXPECT_CALL(*mock_stream_, Close()).WillOnce(InvokeClosure(&completion));
  }

  CreateChannelAndConnectSuccessfully();
  ASSERT_EQ(CHANNEL_ALIVE,
            channel_->StartClosingHandshake(kWebSocketNormalClosure, "OK"));
  ASSERT_TRUE(read_frames);
  // Provide the "Close" message from the server.
  *read_frames = CreateFrameVector(frames, &result_frame_data_);
  std::move(read_callback).Run(OK);
  completion.WaitForResult();
}

}  // namespace
}  // namespace net

"""


```
Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a test file for `WebSocketDeflateStream` in Chromium's networking stack. I need to explain what this test file does, how it relates to JavaScript (if it does), provide examples with hypothetical inputs and outputs, discuss common usage errors, and explain how a user's actions might lead to this code being executed for debugging. Finally, I need to summarize the overall function of this second part of the file.

Here's a breakdown of how to address each point:

1. **Functionality:** The file tests the `WebSocketDeflateStream` class. This class is responsible for compressing and decompressing WebSocket messages using the DEFLATE algorithm (specifically, the permessage-deflate extension). The tests cover various scenarios, including:
    * Reading compressed and uncompressed messages.
    * Writing compressed and uncompressed messages.
    * Handling empty messages.
    * Handling asynchronous operations.
    * Handling control frames within data frames.
    * Splitting large compressed frames.
    * Testing different window bits configurations for the DEFLATE algorithm.
    * Testing scenarios where the DEFLATE context is and isn't taken over between messages.

2. **Relationship to JavaScript:**  JavaScript running in a web browser uses the WebSocket API to establish and communicate over WebSocket connections. The `WebSocketDeflateStream` class is part of the browser's underlying implementation of this API. When a JavaScript application sends or receives data over a WebSocket connection that has the `permessage-deflate` extension negotiated, this C++ code will be involved in compressing and decompressing the data.

3. **Logic and Examples:**  I can pick specific test cases and illustrate the logic. For example, the `ReadCompressedMessage` test shows that when the input frame has the `reserved1` bit set, the `WebSocketDeflateStream` attempts to decompress it. I can provide a sample compressed payload and show the expected uncompressed output. Similarly, for writing, I can show an uncompressed input and the expected compressed output.

4. **User/Programming Errors:**  Common errors could involve:
    * Incorrectly setting the `reserved1` bit in the WebSocket frame header, leading to unexpected compression/decompression behavior.
    * Not handling asynchronous operations correctly when reading or writing frames, which the tests cover.
    * Sending or receiving data that cannot be properly compressed or decompressed.

5. **User Operation to Reach Here:**  To trigger this code, a user would interact with a web page that uses WebSockets and the `permessage-deflate` extension. The steps would involve:
    * A user opens a web page.
    * The JavaScript on the page establishes a WebSocket connection to a server, including the `permessage-deflate` extension in the handshake.
    * The server accepts the extension.
    * The JavaScript sends or receives data via the WebSocket. This triggers the compression/decompression logic in `WebSocketDeflateStream`. A developer debugging network issues might set breakpoints in this code to inspect the frame processing.

6. **Summary of Functionality (Part 2):**  This second part of the test file continues to examine the `WebSocketDeflateStream`'s ability to handle writing compressed and uncompressed WebSocket messages in various scenarios. It specifically focuses on ensuring that the class correctly compresses outgoing data, handles different compression settings (like window bits), and manages the state of the DEFLATE context between messages. It builds upon the foundation laid in the first part, likely focusing more on the writing/compression side and more complex scenarios.

Planning complete. I will now generate the response based on these points.
这是对 Chromium 网络栈中 `net/websockets/websocket_deflate_stream_test.cc` 文件功能的第二部分分析。

**本部分的功能归纳:**

这部分测试文件主要集中在测试 `WebSocketDeflateStream` 类在**写入（发送）WebSocket 消息时的压缩功能**。 它涵盖了多种场景，确保 `WebSocketDeflateStream` 能够正确地压缩和发送数据，并且能处理各种边缘情况。

具体来说，这部分测试涵盖了以下几个方面：

1. **写入空消息:** 验证当要发送的消息为空时，`WebSocketDeflateStream` 能否正确处理，并不会尝试进行压缩。

2. **写入立即失败的情况:** 模拟底层 `mock_stream_` 的 `WriteFrames` 操作立即返回错误的情况，验证 `WebSocketDeflateStream` 能否正确地将错误传递出去。

3. **立即写入帧:** 测试最基本的情况，即要发送的消息可以立即被压缩并写入底层流。 验证压缩后的帧头是否正确设置了 `reserved1` 标志位，并且压缩后的数据内容符合预期。

4. **异步写入帧:**  模拟底层 `mock_stream_` 的 `WriteFrames` 操作异步完成的情况，验证 `WebSocketDeflateStream` 能否正确处理异步操作，并在操作完成后调用回调。

5. **在数据帧之间写入控制帧:**  测试在发送由多个帧组成的数据消息时，插入控制帧（如 Ping 帧）的情况。 验证 `WebSocketDeflateStream` 能否正确地将控制帧直接发送，并对数据帧进行压缩处理。

6. **写入未压缩的消息:**  测试在指定不进行压缩的情况下发送消息。 验证 `WebSocketDeflateStream` 能否按照指示不进行压缩，并正确设置帧头的 `reserved1` 标志位。

7. **拆分大型压缩帧:**  验证当压缩后的数据超过一定大小时，`WebSocketDeflateStream` 能否正确地将其拆分成多个连续的帧进行发送，并正确设置连续帧的帧头。

8. **写入多个消息:**  测试连续发送多个独立消息的情况，验证 `WebSocketDeflateStream` 能否正确地对每个消息进行独立的压缩处理。

9. **不接管上下文的情况:** 使用 `WebSocketDeflateStreamWithDoNotTakeOverContextTest` 测试，当配置为不接管压缩上下文时，每个消息的压缩都是独立的，不会利用之前消息的上下文。

10. **可能压缩的消息:**  使用 `WebSocketDeflateStreamWithDoNotTakeOverContextTest` 测试，验证在可能进行压缩的情况下，对于不同的消息，`WebSocketDeflateStream` 是否能够根据配置选择是否进行压缩。

11. **不同的窗口位:** 使用 `WebSocketDeflateStreamWithClientWindowBitsTest` 测试，验证配置不同的 DEFLATE 窗口位 (`window_bits`) 时，`WebSocketDeflateStream` 是否能够生成符合预期的压缩结果。这展示了对压缩级别配置的支持。

**与 JavaScript 的关系及举例说明:**

这些测试直接关系到在浏览器中使用 JavaScript 的 WebSocket API 发送数据时的压缩行为。

**举例说明:**

假设一个 JavaScript 应用程序通过 WebSocket 发送一个字符串 "Hello" 到服务器，并且在 WebSocket 握手阶段协商了 `permessage-deflate` 扩展。

```javascript
const websocket = new WebSocket('ws://example.com', ['permessage-deflate']);

websocket.onopen = () => {
  websocket.send("Hello");
};
```

当 `websocket.send("Hello")` 被调用时，浏览器底层的网络栈就会使用 `WebSocketDeflateStream` 来处理这个消息。 如果启用了压缩，并且 `WebSocketDeflateStream` 认为压缩是有效的，那么它就会将 "Hello" 压缩成类似于 `\xf2\x48\xcd\xc9\xc9\x07\x00` 这样的字节序列，并将 `reserved1` 标志位设置为 true，指示这是一个压缩帧。 服务器端接收到这个压缩帧后，会使用相应的解压机制进行解压，还原出原始的 "Hello" 字符串。

**逻辑推理的假设输入与输出:**

**测试用例:** `TEST_F(WebSocketDeflateStreamTest, WriteFrameImmediately)`

**假设输入:**

*   要发送的 WebSocket 文本帧，Payload 为 "Hello"，`final` 标志位为 true。

**逻辑推理:**

*   `WebSocketDeflateStream` 会尝试对 "Hello" 进行 DEFLATE 压缩。
*   压缩后的数据预期为 `\xf2\x48\xcd\xc9\xc9\x07\x00`。
*   输出的帧头的 `reserved1` 标志位应该被设置为 true，表示已压缩。

**预期输出:**

*   发送到 `mock_stream_` 的 WebSocket 文本帧，Payload 为 `\xf2\x48\xcd\xc9\xc9\x07\x00`，`final` 标志位为 true，`reserved1` 标志位为 true。

**用户或编程常见的使用错误:**

1. **手动设置了压缩标志位但没有实际压缩数据:**  开发者可能错误地设置了 WebSocket 帧头的 `reserved1` 标志位为 true，但实际发送的 payload 并没有经过 DEFLATE 压缩。 这会导致接收端尝试解压非压缩数据而失败。

    **示例 (错误用法):**  开发者可能直接构造了一个帧，设置了 `header.reserved1 = true;`，但 payload 仍然是原始的未压缩数据。

2. **没有正确处理异步操作:**  在真实的 WebSocket 通信中，`WriteFrames` 操作可能是异步的。 如果应用程序没有正确地使用回调函数来处理发送完成的事件，可能会导致数据丢失或发送顺序错乱。  这些测试中的 `WriteFrameAsync` 测试就模拟了这种情况。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户打开一个网页，该网页使用了 WebSocket 与服务器进行通信。**
2. **网页中的 JavaScript 代码创建了一个 WebSocket 对象，并在构造函数中指定了 `'permessage-deflate'` 子协议，或者服务器在握手阶段提议并最终协商使用了这个扩展。**
3. **JavaScript 代码调用 `websocket.send(data)` 发送数据。**
4. **浏览器网络栈接收到要发送的数据。**
5. **由于协商了 `permessage-deflate` 扩展，数据会被传递给 `WebSocketDeflateStream` 进行处理。**
6. **`WebSocketDeflateStream` 会根据配置（是否接管上下文等）对数据进行压缩，并生成一个或多个 WebSocket 帧。**
7. **`WebSocketDeflateStream` 调用底层的 TCP 连接相关的代码 (模拟为 `mock_stream_`) 将这些帧发送出去。**

**调试线索:** 如果开发者发现通过 WebSocket 发送的数据在网络上是压缩的，或者遇到了与压缩相关的问题（例如，接收端无法正确解压），那么他们可能会查看 `net/websockets/websocket_deflate_stream.cc` 相关的代码，设置断点，来分析压缩过程是否正确，压缩后的数据是否符合预期，以及帧头的标志位是否设置正确。  这些测试用例本身就提供了各种场景的验证，可以帮助开发者理解和排查问题。 例如，如果怀疑是异步写入导致的问题，可能会关注 `WriteFrameAsync` 这个测试用例。

Prompt: 
```
这是目录为net/websockets/websocket_deflate_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
etFrameHeader::kOpCodeText,
           kFinal | kReserved1,
           std::string(
               "\x4a\xce\xcf\x2d\x28\x4a\x2d\x2e\x4e\x4d\x01\x00", 12));
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal,
           "uncompressed");
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(2u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("compressed", ToString(frames[0]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[1]->header.opcode);
  EXPECT_TRUE(frames[1]->header.final);
  EXPECT_FALSE(frames[1]->header.reserved1);
  EXPECT_EQ("uncompressed", ToString(frames[1]));
}

TEST_F(WebSocketDeflateStreamTest,
       ReadUncompressedMessageThenCompressedMessage) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal,
           "uncompressed");
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal | kReserved1,
           std::string(
               "\x4a\xce\xcf\x2d\x28\x4a\x2d\x2e\x4e\x4d\x01\x00", 12));
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(2u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("uncompressed", ToString(frames[0]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[1]->header.opcode);
  EXPECT_TRUE(frames[1]->header.final);
  EXPECT_FALSE(frames[1]->header.reserved1);
  EXPECT_EQ("compressed", ToString(frames[1]));
}

// This is a regression test for crbug.com/343506.
TEST_F(WebSocketDeflateStreamTest, ReadEmptyAsyncFrame) {
  std::vector<std::unique_ptr<ReadFramesStub>> stub_vector;
  stub_vector.push_back(std::make_unique<ReadFramesStub>(ERR_IO_PENDING));
  stub_vector.push_back(std::make_unique<ReadFramesStub>(ERR_IO_PENDING));
  base::MockCallback<CompletionOnceCallback> mock_callback;
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(stub_vector[0].get(), &ReadFramesStub::Call));

    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(stub_vector[1].get(), &ReadFramesStub::Call));

    EXPECT_CALL(mock_callback, Run(OK));
  }

  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, mock_callback.Get()),
              IsError(ERR_IO_PENDING));
  AppendTo(stub_vector[0]->frames_passed(),
           WebSocketFrameHeader::kOpCodeText,
           kReserved1,
           std::string());
  std::move(stub_vector[0]->callback()).Run(OK);
  AppendTo(stub_vector[1]->frames_passed(),
           WebSocketFrameHeader::kOpCodeContinuation,
           kFinal,
           std::string("\x02\x00"));
  std::move(stub_vector[1]->callback()).Run(OK);
  ASSERT_EQ(1u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_EQ("", ToString(frames[0]));
}

TEST_F(WebSocketDeflateStreamTest, WriteEmpty) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(&frames, _)).Times(0);
  }
  EXPECT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
              IsOk());
}

TEST_F(WebSocketDeflateStreamTest, WriteFailedImmediately) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(&frames, _))
        .WillOnce(Return(ERR_FAILED));
  }

  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kFinal, "hello");
  predictor_->AddFramesToBeInput(frames);
  EXPECT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
              IsError(ERR_FAILED));
  predictor_->Clear();
}

TEST_F(WebSocketDeflateStreamTest, WriteFrameImmediately) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  WriteFramesStub stub(predictor_, OK);
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kFinal, "Hello");
  predictor_->AddFramesToBeInput(frames);
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(_, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
              IsOk());
  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(1u, frames_passed.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[0]->header.opcode);
  EXPECT_TRUE(frames_passed[0]->header.final);
  EXPECT_TRUE(frames_passed[0]->header.reserved1);
  EXPECT_EQ(std::string("\xf2\x48\xcd\xc9\xc9\x07\x00", 7),
            ToString(frames_passed[0]));
}

TEST_F(WebSocketDeflateStreamTest, WriteFrameAsync) {
  WriteFramesStub stub(predictor_, ERR_IO_PENDING);
  base::MockCallback<CompletionOnceCallback> mock_callback;
  base::MockCallback<base::OnceClosure> checkpoint;
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(&frames, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
    EXPECT_CALL(checkpoint, Run());
    EXPECT_CALL(mock_callback, Run(OK));
  }
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kFinal, "Hello");
  predictor_->AddFramesToBeInput(frames);
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames, mock_callback.Get()),
              IsError(ERR_IO_PENDING));

  checkpoint.Run();
  std::move(stub.callback()).Run(OK);

  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(1u, frames_passed.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[0]->header.opcode);
  EXPECT_TRUE(frames_passed[0]->header.final);
  EXPECT_TRUE(frames_passed[0]->header.reserved1);
  EXPECT_EQ(std::string("\xf2\x48\xcd\xc9\xc9\x07\x00", 7),
            ToString(frames_passed[0]));
}

TEST_F(WebSocketDeflateStreamTest, WriteControlFrameBetweenDataFrames) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kNoFlag, "Hel");
  AppendTo(&frames, WebSocketFrameHeader::kOpCodePing, kFinal);
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeContinuation, kFinal, "lo");
  predictor_->AddFramesToBeInput(frames);
  WriteFramesStub stub(predictor_, OK);

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(&frames, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
              IsOk());
  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(2u, frames_passed.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodePing, frames_passed[0]->header.opcode);
  EXPECT_TRUE(frames_passed[0]->header.final);
  EXPECT_FALSE(frames_passed[0]->header.reserved1);
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[1]->header.opcode);
  EXPECT_TRUE(frames_passed[1]->header.final);
  EXPECT_TRUE(frames_passed[1]->header.reserved1);
  EXPECT_EQ(std::string("\xf2\x48\xcd\xc9\xc9\x07\x00", 7),
            ToString(frames_passed[1]));
}

TEST_F(WebSocketDeflateStreamTest, WriteEmptyMessage) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kFinal);
  predictor_->AddFramesToBeInput(frames);
  WriteFramesStub stub(predictor_, OK);

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(&frames, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
              IsOk());
  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(1u, frames_passed.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[0]->header.opcode);
  EXPECT_TRUE(frames_passed[0]->header.final);
  EXPECT_TRUE(frames_passed[0]->header.reserved1);
  EXPECT_EQ(std::string("\x00", 1), ToString(frames_passed[0]));
}

TEST_F(WebSocketDeflateStreamTest, WriteUncompressedMessage) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kNoFlag, "AAAA");
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeContinuation, kFinal, "AAA");
  predictor_->AddFramesToBeInput(frames);
  WriteFramesStub stub(predictor_, OK);

  predictor_->set_result(WebSocketDeflatePredictor::DO_NOT_DEFLATE);

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(&frames, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
              IsOk());
  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(2u, frames_passed.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[0]->header.opcode);
  EXPECT_FALSE(frames_passed[0]->header.final);
  EXPECT_FALSE(frames_passed[0]->header.reserved1);
  EXPECT_EQ("AAAA", ToString(frames_passed[0]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames_passed[1]->header.opcode);
  EXPECT_TRUE(frames_passed[1]->header.final);
  EXPECT_FALSE(frames_passed[1]->header.reserved1);
  EXPECT_EQ("AAA", ToString(frames_passed[1]));
}

TEST_F(WebSocketDeflateStreamTest, LargeDeflatedFramesShouldBeSplit) {
  WebSocketDeflater deflater(WebSocketDeflater::TAKE_OVER_CONTEXT);
  LinearCongruentialGenerator lcg(133);
  WriteFramesStub stub(predictor_, OK);
  constexpr size_t kSize = 1024;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(_, _))
        .WillRepeatedly(Invoke(&stub, &WriteFramesStub::Call));
  }
  std::vector<std::unique_ptr<WebSocketFrame>> total_compressed_frames;
  std::vector<std::string> buffers;

  deflater.Initialize(kWindowBits);
  while (true) {
    bool is_final = (total_compressed_frames.size() >= 2);
    std::vector<std::unique_ptr<WebSocketFrame>> frames;
    std::string data;
    data.reserve(kSize);
    for (size_t i = 0; i < kSize; ++i) {
      data += static_cast<char>(lcg.Generate());
    }
    deflater.AddBytes(data.data(), data.size());
    FrameFlag flag = is_final ? kFinal : kNoFlag;
    AppendTo(&frames, WebSocketFrameHeader::kOpCodeBinary, flag, data);
    predictor_->AddFramesToBeInput(frames);
    ASSERT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
                IsOk());
    for (auto& frame : *stub.frames()) {
      buffers.emplace_back(base::as_string_view(frame->payload));
      frame->payload = base::as_byte_span(buffers.back());
    }
    total_compressed_frames.insert(
        total_compressed_frames.end(),
        std::make_move_iterator(stub.frames()->begin()),
        std::make_move_iterator(stub.frames()->end()));
    stub.frames()->clear();
    if (is_final)
      break;
  }
  deflater.Finish();
  std::string total_deflated;
  for (size_t i = 0; i < total_compressed_frames.size(); ++i) {
    WebSocketFrame* frame = total_compressed_frames[i].get();
    const WebSocketFrameHeader& header = frame->header;
    if (i > 0) {
      EXPECT_EQ(header.kOpCodeContinuation, header.opcode);
      EXPECT_FALSE(header.reserved1);
    } else {
      EXPECT_EQ(header.kOpCodeBinary, header.opcode);
      EXPECT_TRUE(header.reserved1);
    }
    const bool is_final_frame = (i + 1 == total_compressed_frames.size());
    EXPECT_EQ(is_final_frame, header.final);
    if (!is_final_frame)
      EXPECT_GT(header.payload_length, 0ul);
    total_deflated += ToString(frame);
  }
  EXPECT_EQ(total_deflated,
            ToString(deflater.GetOutput(deflater.CurrentOutputSize())));
}

TEST_F(WebSocketDeflateStreamTest, WriteMultipleMessages) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kFinal, "Hello");
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kFinal, "Hello");
  predictor_->AddFramesToBeInput(frames);
  WriteFramesStub stub(predictor_, OK);

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(&frames, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
              IsOk());
  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(2u, frames_passed.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[0]->header.opcode);
  EXPECT_TRUE(frames_passed[0]->header.final);
  EXPECT_TRUE(frames_passed[0]->header.reserved1);
  EXPECT_EQ(std::string("\xf2\x48\xcd\xc9\xc9\x07\x00", 7),
            ToString(frames_passed[0]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[1]->header.opcode);
  EXPECT_TRUE(frames_passed[1]->header.final);
  EXPECT_TRUE(frames_passed[1]->header.reserved1);
  EXPECT_EQ(std::string("\xf2\x00\x11\x00\x00", 5), ToString(frames_passed[1]));
}

TEST_F(WebSocketDeflateStreamWithDoNotTakeOverContextTest,
       WriteMultipleMessages) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kFinal, "Hello");
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kFinal, "Hello");
  predictor_->AddFramesToBeInput(frames);
  WriteFramesStub stub(predictor_, OK);

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(&frames, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
              IsOk());
  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(2u, frames_passed.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[0]->header.opcode);
  EXPECT_TRUE(frames_passed[0]->header.final);
  EXPECT_TRUE(frames_passed[0]->header.reserved1);
  EXPECT_EQ(std::string("\xf2\x48\xcd\xc9\xc9\x07\x00", 7),
            ToString(frames_passed[0]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[1]->header.opcode);
  EXPECT_TRUE(frames_passed[1]->header.final);
  EXPECT_TRUE(frames_passed[1]->header.reserved1);
  EXPECT_EQ(std::string("\xf2\x48\xcd\xc9\xc9\x07\x00", 7),
            ToString(frames_passed[1]));
}

// In order to check the stream works correctly for multiple
// "PossiblyCompressedMessage"s, we test various messages at one test case.
TEST_F(WebSocketDeflateStreamWithDoNotTakeOverContextTest,
       WritePossiblyCompressMessages) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kNoFlag, "He");
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeContinuation, kFinal, "llo");
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kNoFlag, "AAAAAAAAAA");
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeContinuation, kFinal, "AA");
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeText, kNoFlag, "XX");
  AppendTo(&frames, WebSocketFrameHeader::kOpCodeContinuation, kFinal, "YY");
  predictor_->AddFramesToBeInput(frames);
  WriteFramesStub stub(predictor_, OK);
  predictor_->set_result(WebSocketDeflatePredictor::TRY_DEFLATE);

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(&frames, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames, CompletionOnceCallback()),
              IsOk());
  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(5u, frames_passed.size());

  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[0]->header.opcode);
  EXPECT_FALSE(frames_passed[0]->header.final);
  EXPECT_FALSE(frames_passed[0]->header.reserved1);
  EXPECT_EQ("He", ToString(frames_passed[0]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames_passed[1]->header.opcode);
  EXPECT_TRUE(frames_passed[1]->header.final);
  EXPECT_FALSE(frames_passed[1]->header.reserved1);
  EXPECT_EQ("llo", ToString(frames_passed[1]));

  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[2]->header.opcode);
  EXPECT_TRUE(frames_passed[2]->header.final);
  EXPECT_TRUE(frames_passed[2]->header.reserved1);
  EXPECT_EQ(std::string("\x72\x74\x44\x00\x00\x00", 6),
            ToString(frames_passed[2]));

  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_passed[3]->header.opcode);
  EXPECT_FALSE(frames_passed[3]->header.final);
  EXPECT_FALSE(frames_passed[3]->header.reserved1);
  EXPECT_EQ("XX", ToString(frames_passed[3]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames_passed[4]->header.opcode);
  EXPECT_TRUE(frames_passed[4]->header.final);
  EXPECT_FALSE(frames_passed[4]->header.reserved1);
  EXPECT_EQ("YY", ToString(frames_passed[4]));
}

// This is based on the similar test from websocket_deflater_test.cc
TEST_F(WebSocketDeflateStreamWithClientWindowBitsTest, WindowBits8) {
  SetUpWithWindowBits(8);
  AddCompressibleFrameString();
  WriteFramesStub stub(predictor_, OK);
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(_, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames_, CompletionOnceCallback()),
              IsOk());
  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(1u, frames_passed.size());
  EXPECT_EQ(std::string("r\xce(\xca\xcf\xcd,\xcdM\x1c\xe1\xc0\x39\xa3"
                        "(?7\xb3\x34\x17\x00", 21),
            ToString(frames_passed[0]));
}

// The same input with window_bits=10 returns smaller output.
TEST_F(WebSocketDeflateStreamWithClientWindowBitsTest, WindowBits10) {
  SetUpWithWindowBits(10);
  AddCompressibleFrameString();
  WriteFramesStub stub(predictor_, OK);
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, WriteFrames(_, _))
        .WillOnce(Invoke(&stub, &WriteFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->WriteFrames(&frames_, CompletionOnceCallback()),
              IsOk());
  const std::vector<std::unique_ptr<WebSocketFrame>>& frames_passed =
      *stub.frames();
  ASSERT_EQ(1u, frames_passed.size());
  EXPECT_EQ(
      std::string("r\xce(\xca\xcf\xcd,\xcdM\x1c\xe1\xc0\x19\x1a\x0e\0\0", 17),
      ToString(frames_passed[0]));
}

}  // namespace

}  // namespace net

"""


```
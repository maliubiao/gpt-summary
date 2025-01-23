Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part 2 of a test file for `WebSocketChannelImpl` in the Chromium Blink engine.

To achieve this, I need to:

1. **Identify the main purpose of the code:**  It consists of several test cases (`TEST_F`) for the `WebSocketChannelImpl` class.
2. **Summarize the functionality of each test case:** Focus on what aspects of WebSocket communication each test is validating.
3. **Relate the tests to WebSocket features:** Connect the test scenarios to concepts like receiving text and binary data, handling continuations, closing connections, and managing connection limits.
4. **Note any interactions with JavaScript, HTML, or CSS:** Although not directly evident in the test code, consider the role of WebSockets in web development.
5. **Infer potential user errors or debugging steps:** Based on the test scenarios, think about common issues developers might face when using WebSockets.
这是对 `blink/renderer/modules/websockets/websocket_channel_impl_test.cc` 文件部分代码的功能归纳，延续了之前部分的分析。

**主要功能归纳:**

这部分代码主要集中在测试 `WebSocketChannelImpl` 类在接收和处理 WebSocket 消息以及管理连接关闭方面的功能。具体来说，它测试了以下场景：

1. **接收文本消息：**
   - 接收完整的 UTF-8 文本消息。
   - 接收分片的 UTF-8 文本消息（使用 continuation 帧）。
   - 接收包含非 Latin-1 字符的文本消息。
   - 接收分片的包含非 Latin-1 字符的文本消息。

2. **接收二进制消息：**
   - 接收完整的二进制消息。
   - 接收分片的二进制消息（使用 continuation 帧）。
   - 接收包含 null 字节的二进制消息。
   - 接收包含非 UTF-8 字符的二进制消息。
   - 接收包含 UTF-8 编码的非 Latin-1 字符的二进制消息。
   - 接收分片的包含 UTF-8 编码的非 Latin-1 字符的二进制消息。

3. **显式背压控制：** 测试在接收消息时应用和移除背压的功能，模拟网络拥塞或接收方处理能力不足的情况。

4. **小数据包写入场景：** 测试在底层数据管道写入少量数据时，如何正确接收和组装完整的 WebSocket 消息。

5. **连接关闭：**
   - 测试服务端主动发起连接关闭握手流程。
   - 测试客户端主动发起连接关闭流程。
   - 测试由于底层 Mojo 连接错误导致的连接关闭。
   - 测试客户端通过 `Fail()` 方法主动触发连接失败和关闭。

6. **握手节流（Handshake Throttling）：**
   - 测试握手节流成功的情况，包括节流器先完成和握手先完成两种情况。
   - 测试在握手节流过程中发生错误或连接关闭的情况。
   - 测试在握手节流期间断开连接的情况。
   - 测试握手节流器报告错误的情况。
   - 测试在握手节流之前连接失败的情况。

7. **发送过程中远程连接关闭：**  测试在消息发送过程中，如果远程服务器发起连接关闭，是否能正常处理，避免崩溃。

8. **连接数限制：** 测试 `WebSocketChannelImpl` 对每个渲染进程允许的最大 WebSocket 连接数的限制。

**与 JavaScript, HTML, CSS 的关系：**

虽然此测试文件是 C++ 代码，但它直接测试了 WebSocket API 的底层实现，而 WebSocket API 是 JavaScript 可以直接调用的。

* **JavaScript `WebSocket` API:**  这些测试模拟了服务器向客户端发送不同类型的 WebSocket 消息（文本和二进制），以及客户端和服务器之间如何协商关闭连接。JavaScript 中的 `WebSocket` 对象会接收这些消息，并通过 `onmessage` 事件处理程序暴露给开发者。例如，`ReceiveText` 和 `ReceiveBinary` 等测试就直接关系到 JavaScript 中 `WebSocket.onmessage` 事件接收到的数据。
* **HTML：** HTML 可以通过 `<script>` 标签引入 JavaScript 代码，而这些 JavaScript 代码可能会使用 `WebSocket` API。因此，这些测试间接地与 HTML 相关。例如，一个 HTML 页面可能包含一个使用 WebSocket 连接到服务器以进行实时更新的脚本。
* **CSS：** CSS 与 WebSocket 的功能没有直接关系。

**逻辑推理、假设输入与输出：**

这些测试用例本质上是单元测试，针对 `WebSocketChannelImpl` 的特定行为进行验证。

**例如，对于 `ReceiveText` 测试：**

* **假设输入：**
    * 服务端发送一个包含 "FOO" 的文本 WebSocket 帧 (fin=true, opcode=TEXT, payload="FOO")。
* **预期输出：**
    * `ChannelClient()` 接收到 `DidConnect` 回调，表示连接已建立。
    * `ChannelClient()` 接收到 `DidReceiveTextMessage` 回调，参数为 "FOO"。

**再例如，对于 `ConnectionCloseInitiatedByServer` 测试：**

* **假设输入：**
    * 服务端发送一个关闭握手帧。
    * 客户端调用 `Channel()->Close()` 发起关闭。
    * 服务端发送一个关闭连接的帧。
* **预期输出：**
    * `ChannelClient()` 接收到 `DidConnect` 回调。
    * `ChannelClient()` 接收到 `DidStartClosingHandshake` 回调。
    * `ChannelClient()` 接收到 `DidClose` 回调，状态码为 `kCloseEventCodeNormalClosure`，原因为 "close reason"。

**用户或编程常见的使用错误：**

虽然这个测试文件主要关注引擎内部实现，但可以推断出一些用户或编程中常见的 WebSocket 使用错误，这些错误可能会导致代码执行到 `WebSocketChannelImpl` 的相关逻辑：

* **未正确处理分片消息：** 开发者可能假设 `onmessage` 事件每次接收到的是完整的消息，而没有考虑到消息可能被分片发送。`ReceiveTextContinuation` 和 `ReceiveBinaryContinuation` 等测试就涵盖了这种情况。
* **字符编码问题：**  发送或接收非 UTF-8 编码的文本数据可能导致乱码。`ReceiveTextNonLatin1` 等测试关注了字符编码的处理。
* **连接管理不当：**  在连接建立之前或关闭之后尝试发送或接收数据会导致错误。`ConnectionCloseInitiatedByServer` 和 `ConnectionCloseInitiatedByClient` 等测试验证了连接关闭的流程。
* **服务端未正确处理关闭握手：**  如果服务端没有正确响应客户端的关闭请求，可能导致连接异常关闭。
* **超过连接数限制：**  尝试在一个页面中创建过多的 WebSocket 连接可能会被浏览器限制，`ConnectionLimit` 测试就模拟了这种情况。

**用户操作如何到达这里作为调试线索：**

作为调试线索，当开发者在使用 JavaScript 的 `WebSocket` API 时遇到问题，例如：

1. **消息接收不完整或乱码：**  如果 JavaScript 代码中 `onmessage` 事件处理程序接收到的数据不符合预期，开发者可能会怀疑是服务端分片发送消息的问题或字符编码不一致。此时，可以查看浏览器开发者工具的网络面板中 WebSocket 帧的详细信息，确认消息是否被分片，以及消息的 payload 是否是预期的编码。引擎开发者则可能需要调试 `WebSocketChannelImpl` 中处理分片和字符编码转换的逻辑。
2. **连接意外断开：**  如果 WebSocket 连接突然断开，开发者可能会检查网络状况，并查看浏览器控制台是否有错误信息。引擎开发者可能需要调试 `WebSocketChannelImpl` 中处理连接关闭的逻辑，包括服务端或客户端主动关闭，以及底层连接错误导致的关闭。
3. **无法建立连接：**  如果 JavaScript 代码尝试创建 WebSocket 连接失败，开发者可能会检查 WebSocket URL 是否正确，以及服务端是否正常运行。引擎开发者可能需要调试 `WebSocketChannelImpl` 中建立连接和处理握手节流的逻辑。

总之，这个测试文件通过各种场景验证了 `WebSocketChannelImpl` 接收消息、处理连接关闭和管理连接限制的正确性，这些功能直接影响了 JavaScript `WebSocket` API 的行为和开发者在使用 WebSocket 进行实时通信的体验。

### 提示词
```
这是目录为blink/renderer/modules/websockets/websocket_channel_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  size_t actually_written_bytes = 0;
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::byte_span_from_cstring("BAZ"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 3u);

  client->OnDataFrame(false, WebSocketMessageType::TEXT, 1);
  client->OnDataFrame(false, WebSocketMessageType::CONTINUATION, 1);
  client->OnDataFrame(true, WebSocketMessageType::CONTINUATION, 1);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ReceiveTextNonLatin1) {
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    UChar non_latin1_string[] = {0x72d0, 0x0914, 0x0000};
    EXPECT_CALL(*ChannelClient(),
                DidReceiveTextMessage(String(non_latin1_string)));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  size_t actually_written_bytes = 0;
  ASSERT_EQ(MOJO_RESULT_OK,
            writable->WriteData(
                base::byte_span_from_cstring("\xe7\x8b\x90\xe0\xa4\x94"),
                MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 6u);

  client->OnDataFrame(true, WebSocketMessageType::TEXT, 6);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ReceiveTextNonLatin1Continuation) {
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    UChar non_latin1_string[] = {0x72d0, 0x0914, 0x0000};
    EXPECT_CALL(*ChannelClient(),
                DidReceiveTextMessage(String(non_latin1_string)));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  size_t actually_written_bytes = 0;
  ASSERT_EQ(MOJO_RESULT_OK,
            writable->WriteData(
                base::byte_span_from_cstring("\xe7\x8b\x90\xe0\xa4\x94"),
                MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 6u);

  client->OnDataFrame(false, WebSocketMessageType::TEXT, 2);
  client->OnDataFrame(false, WebSocketMessageType::CONTINUATION, 2);
  client->OnDataFrame(false, WebSocketMessageType::CONTINUATION, 1);
  client->OnDataFrame(true, WebSocketMessageType::CONTINUATION, 1);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ReceiveBinary) {
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(*ChannelClient(),
                DidReceiveBinaryMessageMock((Vector<char>{'F', 'O', 'O'})));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  size_t actually_written_bytes = 0;
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::byte_span_from_cstring("FOO"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 3u);

  client->OnDataFrame(true, WebSocketMessageType::BINARY, 3);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ReceiveBinaryContinuation) {
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(*ChannelClient(),
                DidReceiveBinaryMessageMock((Vector<char>{'B', 'A', 'Z'})));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  size_t actually_written_bytes = 0;
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::byte_span_from_cstring("BAZ"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 3u);

  client->OnDataFrame(false, WebSocketMessageType::BINARY, 1);
  client->OnDataFrame(false, WebSocketMessageType::CONTINUATION, 1);
  client->OnDataFrame(true, WebSocketMessageType::CONTINUATION, 1);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ReceiveBinaryWithNullBytes) {
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(*ChannelClient(),
                DidReceiveBinaryMessageMock((Vector<char>{'\0', 'A', '3'})));
    EXPECT_CALL(*ChannelClient(),
                DidReceiveBinaryMessageMock((Vector<char>{'B', '\0', 'Z'})));
    EXPECT_CALL(*ChannelClient(),
                DidReceiveBinaryMessageMock((Vector<char>{'Q', 'U', '\0'})));
    EXPECT_CALL(*ChannelClient(),
                DidReceiveBinaryMessageMock((Vector<char>{'\0', '\0', '\0'})));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  using std::string_view_literals::operator""sv;  // For NUL characters.
  size_t actually_written_bytes = 0;
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::as_byte_span("\0A3B\0ZQU\0\0\0\0"sv),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 12u);

  client->OnDataFrame(true, WebSocketMessageType::BINARY, 3);
  client->OnDataFrame(true, WebSocketMessageType::BINARY, 3);
  client->OnDataFrame(true, WebSocketMessageType::BINARY, 3);
  client->OnDataFrame(true, WebSocketMessageType::BINARY, 3);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ReceiveBinaryNonLatin1UTF8) {
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(*ChannelClient(),
                DidReceiveBinaryMessageMock((Vector<char>{
                    '\xe7', '\x8b', '\x90', '\xe0', '\xa4', '\x94'})));
  }
  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  size_t actually_written_bytes = 0;
  ASSERT_EQ(MOJO_RESULT_OK,
            writable->WriteData(
                base::byte_span_from_cstring("\xe7\x8b\x90\xe0\xa4\x94"),
                MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 6u);

  client->OnDataFrame(true, WebSocketMessageType::BINARY, 6);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ReceiveBinaryNonLatin1UTF8Continuation) {
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(*ChannelClient(),
                DidReceiveBinaryMessageMock((Vector<char>{
                    '\xe7', '\x8b', '\x90', '\xe0', '\xa4', '\x94'})));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  size_t actually_written_bytes = 0;
  ASSERT_EQ(MOJO_RESULT_OK,
            writable->WriteData(
                base::byte_span_from_cstring("\xe7\x8b\x90\xe0\xa4\x94"),
                MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 6u);

  client->OnDataFrame(false, WebSocketMessageType::BINARY, 2);
  client->OnDataFrame(false, WebSocketMessageType::CONTINUATION, 2);
  client->OnDataFrame(false, WebSocketMessageType::CONTINUATION, 1);
  client->OnDataFrame(true, WebSocketMessageType::CONTINUATION, 1);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ReceiveBinaryNonUTF8) {
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(*ChannelClient(),
                DidReceiveBinaryMessageMock((Vector<char>{'\x80', '\xff'})));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  size_t actually_written_bytes = 0;
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::byte_span_from_cstring("\x80\xff"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 2u);

  client->OnDataFrame(true, WebSocketMessageType::BINARY, 2);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ReceiveWithExplicitBackpressure) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*ChannelClient(), DidReceiveTextMessage(String("abc")));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  size_t actually_written_bytes = 0;
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::byte_span_from_cstring("abc"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 3u);

  Channel()->ApplyBackpressure();

  client->OnDataFrame(true, WebSocketMessageType::TEXT, 3);
  test::RunPendingTasks();

  checkpoint.Call(1);
  Channel()->RemoveBackpressure();
}

TEST_F(WebSocketChannelImplTest,
       ReceiveMultipleMessagesWithSmallDataPipeWrites) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(checkpoint, Call(2));
    EXPECT_CALL(*ChannelClient(), DidReceiveTextMessage(String("abc")));
    EXPECT_CALL(*ChannelClient(), DidReceiveTextMessage(String("")));
    EXPECT_CALL(*ChannelClient(), DidReceiveTextMessage(String("")));
    EXPECT_CALL(checkpoint, Call(3));
    EXPECT_CALL(*ChannelClient(), DidReceiveTextMessage(String("de")));
    EXPECT_CALL(checkpoint, Call(4));
    EXPECT_CALL(*ChannelClient(), DidReceiveTextMessage(String("")));
    EXPECT_CALL(checkpoint, Call(5));
    EXPECT_CALL(checkpoint, Call(6));
    EXPECT_CALL(*ChannelClient(), DidReceiveTextMessage(String("fghijkl")));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  client->OnDataFrame(true, WebSocketMessageType::TEXT, 3);
  client->OnDataFrame(true, WebSocketMessageType::TEXT, 0);
  client->OnDataFrame(true, WebSocketMessageType::TEXT, 0);
  client->OnDataFrame(true, WebSocketMessageType::TEXT, 2);
  test::RunPendingTasks();

  checkpoint.Call(1);
  size_t actually_written_bytes = 0;
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::byte_span_from_cstring("ab"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 2u);
  test::RunPendingTasks();

  checkpoint.Call(2);
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::byte_span_from_cstring("cd"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 2u);
  test::RunPendingTasks();

  checkpoint.Call(3);
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::byte_span_from_cstring("efgh"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 4u);
  test::RunPendingTasks();

  checkpoint.Call(4);
  client->OnDataFrame(true, WebSocketMessageType::TEXT, 0);
  client->OnDataFrame(false, WebSocketMessageType::TEXT, 1);
  test::RunPendingTasks();

  checkpoint.Call(5);
  client->OnDataFrame(false, WebSocketMessageType::CONTINUATION, 1);
  client->OnDataFrame(true, WebSocketMessageType::CONTINUATION, 5);
  test::RunPendingTasks();

  checkpoint.Call(6);
  ASSERT_EQ(
      MOJO_RESULT_OK,
      writable->WriteData(base::byte_span_from_cstring("ijkl"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes));
  EXPECT_EQ(actually_written_bytes, 4u);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ConnectionCloseInitiatedByServer) {
  Checkpoint checkpoint;
  {
    InSequence s;

    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(*ChannelClient(), DidStartClosingHandshake());
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(checkpoint, Call(2));

    EXPECT_CALL(*ChannelClient(),
                DidClose(WebSocketChannelClient::kClosingHandshakeComplete,
                         WebSocketChannel::kCloseEventCodeNormalClosure,
                         String("close reason")));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  client->OnClosingHandshake();
  test::RunPendingTasks();

  EXPECT_FALSE(websocket->IsStartClosingHandshakeCalled());

  checkpoint.Call(1);
  Channel()->Close(WebSocketChannel::kCloseEventCodeNormalClosure,
                   "close reason");
  test::RunPendingTasks();

  EXPECT_TRUE(websocket->IsStartClosingHandshakeCalled());
  EXPECT_EQ(websocket->GetClosingCode(),
            WebSocketChannel::kCloseEventCodeNormalClosure);
  EXPECT_EQ(websocket->GetClosingReason(), "close reason");

  checkpoint.Call(2);
  client->OnDropChannel(true, WebSocketChannel::kCloseEventCodeNormalClosure,
                        "close reason");
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, ConnectionCloseInitiatedByClient) {
  Checkpoint checkpoint;
  {
    InSequence s;

    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*ChannelClient(),
                DidClose(WebSocketChannelClient::kClosingHandshakeComplete,
                         WebSocketChannel::kCloseEventCodeNormalClosure,
                         String("close reason")));
    EXPECT_CALL(checkpoint, Call(2));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  EXPECT_FALSE(websocket->IsStartClosingHandshakeCalled());
  Channel()->Close(WebSocketChannel::kCloseEventCodeNormalClosure,
                   "close reason");
  test::RunPendingTasks();
  EXPECT_TRUE(websocket->IsStartClosingHandshakeCalled());
  EXPECT_EQ(websocket->GetClosingCode(),
            WebSocketChannel::kCloseEventCodeNormalClosure);
  EXPECT_EQ(websocket->GetClosingReason(), "close reason");

  checkpoint.Call(1);
  client->OnDropChannel(true, WebSocketChannel::kCloseEventCodeNormalClosure,
                        "close reason");
  test::RunPendingTasks();
  checkpoint.Call(2);
}

TEST_F(WebSocketChannelImplTest, MojoConnectionError) {
  Checkpoint checkpoint;
  {
    InSequence s;

    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*ChannelClient(), DidError());
    EXPECT_CALL(
        *ChannelClient(),
        DidClose(WebSocketChannelClient::kClosingHandshakeIncomplete,
                 WebSocketChannel::kCloseEventCodeAbnormalClosure, String()));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  // Send a frame so that the WebSocketChannelImpl try to read the data pipe.
  client->OnDataFrame(true, WebSocketMessageType::TEXT, 1024);

  // We shouldn't detect a connection error on data pipes and mojom::WebSocket.
  writable.reset();
  websocket = nullptr;
  test::RunPendingTasks();

  // We should detect a connection error on the client.
  checkpoint.Call(1);
  client.reset();
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, FailFromClient) {
  Checkpoint checkpoint;
  {
    InSequence s;

    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*ChannelClient(), DidError());
    EXPECT_CALL(
        *ChannelClient(),
        DidClose(WebSocketChannelClient::kClosingHandshakeIncomplete,
                 WebSocketChannel::kCloseEventCodeAbnormalClosure, String()));
    EXPECT_CALL(checkpoint, Call(2));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  Channel()->Fail(
      "fail message from WebSocket", mojom::ConsoleMessageLevel::kError,
      std::make_unique<SourceLocation>(String(), String(), 0, 0, nullptr));
  checkpoint.Call(1);

  test::RunPendingTasks();
  checkpoint.Call(2);
}

class WebSocketChannelImplHandshakeThrottleTest
    : public WebSocketChannelImplTest {
 public:
  WebSocketChannelImplHandshakeThrottleTest()
      : WebSocketChannelImplTest(
            std::make_unique<StrictMock<MockWebSocketHandshakeThrottle>>()) {}

  static KURL url() { return KURL("ws://localhost/"); }
};

TEST_F(WebSocketChannelImplHandshakeThrottleTest, ThrottleSucceedsFirst) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*raw_handshake_throttle_, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*raw_handshake_throttle_, Destructor());
    EXPECT_CALL(checkpoint, Call(2));
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
  }

  ASSERT_TRUE(Channel()->Connect(url(), ""));
  test::RunPendingTasks();

  auto connect_args = connector_.TakeConnectArgs();

  ASSERT_EQ(1u, connect_args.size());

  mojo::Remote<network::mojom::blink::WebSocketHandshakeClient>
      handshake_client(std::move(connect_args[0].handshake_client));
  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  ASSERT_EQ(CreateDataPipe(32, &writable, &readable), MOJO_RESULT_OK);

  mojo::ScopedDataPipeProducerHandle outgoing_writable;
  mojo::ScopedDataPipeConsumerHandle outgoing_readable;
  ASSERT_EQ(CreateDataPipe(32, &outgoing_writable, &outgoing_readable),
            MOJO_RESULT_OK);

  mojo::Remote<network::mojom::blink::WebSocketClient> client;

  checkpoint.Call(1);
  test::RunPendingTasks();

  Channel()->OnCompletion(std::nullopt);
  checkpoint.Call(2);

  auto websocket =
      EstablishConnection(handshake_client.get(), "", "", std::move(readable),
                          std::move(outgoing_writable), &client);
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplHandshakeThrottleTest, HandshakeSucceedsFirst) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*raw_handshake_throttle_, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(checkpoint, Call(2));
    EXPECT_CALL(*raw_handshake_throttle_, Destructor());
    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;

  checkpoint.Call(1);
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  checkpoint.Call(2);
  Channel()->OnCompletion(std::nullopt);
}

// This happens if JS code calls close() during the handshake.
TEST_F(WebSocketChannelImplHandshakeThrottleTest, FailDuringThrottle) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*raw_handshake_throttle_, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*ChannelClient(), DidError());
    EXPECT_CALL(*ChannelClient(), DidClose(_, _, _));
    EXPECT_CALL(*raw_handshake_throttle_, Destructor());
    EXPECT_CALL(checkpoint, Call(2));
  }

  Channel()->Connect(url(), "");
  Channel()->Fail(
      "close during handshake", mojom::ConsoleMessageLevel::kWarning,
      std::make_unique<SourceLocation>(String(), String(), 0, 0, nullptr));
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
}

// It makes no difference to the behaviour if the WebSocketHandle has actually
// connected.
TEST_F(WebSocketChannelImplHandshakeThrottleTest,
       FailDuringThrottleAfterConnect) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*raw_handshake_throttle_, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*ChannelClient(), DidError());
    EXPECT_CALL(*ChannelClient(), DidClose(_, _, _));
    EXPECT_CALL(*raw_handshake_throttle_, Destructor());
    EXPECT_CALL(checkpoint, Call(2));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  Channel()->Fail(
      "close during handshake", mojom::ConsoleMessageLevel::kWarning,
      std::make_unique<SourceLocation>(String(), String(), 0, 0, nullptr));
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
}

TEST_F(WebSocketChannelImplHandshakeThrottleTest, DisconnectDuringThrottle) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*raw_handshake_throttle_, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(*raw_handshake_throttle_, Destructor());
    EXPECT_CALL(checkpoint, Call(1));
  }

  Channel()->Connect(url(), "");
  test::RunPendingTasks();

  Channel()->Disconnect();
  checkpoint.Call(1);

  auto connect_args = connector_.TakeConnectArgs();
  ASSERT_EQ(1u, connect_args.size());

  mojo::Remote<network::mojom::blink::WebSocketHandshakeClient>
      handshake_client(std::move(connect_args[0].handshake_client));

  CallTrackingClosure closure;
  handshake_client.set_disconnect_handler(closure.Closure());
  EXPECT_FALSE(closure.WasCalled());

  test::RunPendingTasks();

  EXPECT_TRUE(closure.WasCalled());
}

TEST_F(WebSocketChannelImplHandshakeThrottleTest,
       DisconnectDuringThrottleAfterConnect) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*raw_handshake_throttle_, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(*raw_handshake_throttle_, Destructor());
    EXPECT_CALL(checkpoint, Call(1));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  Channel()->Disconnect();
  checkpoint.Call(1);

  CallTrackingClosure closure;
  client.set_disconnect_handler(closure.Closure());
  EXPECT_FALSE(closure.WasCalled());

  test::RunPendingTasks();

  EXPECT_TRUE(closure.WasCalled());
}

TEST_F(WebSocketChannelImplHandshakeThrottleTest,
       ThrottleReportsErrorBeforeConnect) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*raw_handshake_throttle_, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*raw_handshake_throttle_, Destructor());
    EXPECT_CALL(checkpoint, Call(2));
    EXPECT_CALL(*ChannelClient(), DidError());
    EXPECT_CALL(*ChannelClient(), DidClose(_, _, _));
    EXPECT_CALL(checkpoint, Call(3));
  }

  Channel()->Connect(url(), "");

  test::RunPendingTasks();
  checkpoint.Call(1);

  Channel()->OnCompletion("Connection blocked by throttle");
  checkpoint.Call(2);

  test::RunPendingTasks();
  checkpoint.Call(3);
}

TEST_F(WebSocketChannelImplHandshakeThrottleTest,
       ThrottleReportsErrorAfterConnect) {
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*raw_handshake_throttle_, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(*raw_handshake_throttle_, Destructor());
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*ChannelClient(), DidError());
    EXPECT_CALL(*ChannelClient(), DidClose(_, _, _));
    EXPECT_CALL(checkpoint, Call(2));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  Channel()->OnCompletion("Connection blocked by throttle");
  checkpoint.Call(1);

  test::RunPendingTasks();
  checkpoint.Call(2);
}

TEST_F(WebSocketChannelImplHandshakeThrottleTest, ConnectFailBeforeThrottle) {
  {
    InSequence s;
    EXPECT_CALL(*raw_handshake_throttle_, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(*ChannelClient(), DidError());
    EXPECT_CALL(*ChannelClient(), DidClose(_, _, _));
    EXPECT_CALL(*raw_handshake_throttle_, Destructor());
  }

  ASSERT_TRUE(Channel()->Connect(url(), ""));
  test::RunPendingTasks();

  auto connect_args = connector_.TakeConnectArgs();

  ASSERT_EQ(1u, connect_args.size());

  connect_args.clear();
  test::RunPendingTasks();
}

TEST_F(WebSocketChannelImplTest, RemoteConnectionCloseDuringSend) {
  {
    InSequence s;

    EXPECT_CALL(*ChannelClient(), DidConnect(_, _));
    EXPECT_CALL(*ChannelClient(), DidConsumeBufferedAmount(_));
    EXPECT_CALL(*ChannelClient(), DidStartClosingHandshake());
    EXPECT_CALL(*ChannelClient(), DidClose(_, _, _));
  }

  mojo::ScopedDataPipeProducerHandle writable;
  mojo::ScopedDataPipeConsumerHandle readable;
  mojo::Remote<network::mojom::blink::WebSocketClient> client;
  auto websocket = Connect(4 * 1024, &writable, &readable, &client);
  ASSERT_TRUE(websocket);

  // The message must be larger than the data pipe.
  std::string message(16 * 1024, 'a');
  Channel()->Send(message, base::OnceClosure());

  client->OnClosingHandshake();
  test::RunPendingTasks();

  client->OnDropChannel(true, WebSocketChannel::kCloseEventCodeNormalClosure,
                        "");

  // The test passes if this doesn't crash.
  test::RunPendingTasks();
}

class MockWebSocketConnector : public mojom::blink::WebSocketConnector {
 public:
  MOCK_METHOD(
      void,
      Connect,
      (const KURL&,
       const Vector<String>&,
       const net::SiteForCookies&,
       const String&,
       net::StorageAccessApiStatus,
       mojo::PendingRemote<network::mojom::blink::WebSocketHandshakeClient>,
       const std::optional<base::UnguessableToken>&));
};

// This can't use WebSocketChannelImplTest because it requires multiple
// WebSocketChannels to be connected.
class WebSocketChannelImplMultipleTest : public WebSocketChannelImplTestBase {
 public:
  base::WeakPtr<WebSocketChannelImplTestBase> GetWeakPtr() override {
    return weak_ptr_factory_.GetWeakPtr();
  }

  void BindWebSocketConnector(mojo::ScopedMessagePipeHandle handle) override {
    connector_receiver_set_.Add(
        &connector_, mojo::PendingReceiver<mojom::blink::WebSocketConnector>(
                         std::move(handle)));
  }

 protected:
  mojo::ReceiverSet<mojom::blink::WebSocketConnector> connector_receiver_set_;
  StrictMock<MockWebSocketConnector> connector_;

  base::WeakPtrFactory<WebSocketChannelImplMultipleTest> weak_ptr_factory_{
      this};
};

TEST_F(WebSocketChannelImplMultipleTest, ConnectionLimit) {
  Checkpoint checkpoint;

  // We need to keep the handshake clients alive otherwise they will cause
  // connection failures.
  mojo::RemoteSet<network::mojom::blink::WebSocketHandshakeClient>
      handshake_clients;
  auto handshake_client_add_action =
      [&handshake_clients](
          Unused, Unused, Unused, Unused, Unused,
          mojo::PendingRemote<network::mojom::blink::WebSocketHandshakeClient>
              handshake_client,
          Unused) { handshake_clients.Add(std::move(handshake_client)); };

  auto failure_handshake_throttle =
      std::make_unique<StrictMock<MockWebSocketHandshakeThrottle>>();
  auto* failure_channel_client = MockWebSocketChannelClient::Create();

  auto successful_handshake_throttle =
      std::make_unique<StrictMock<MockWebSocketHandshakeThrottle>>();
  auto* successful_channel_client = MockWebSocketChannelClient::Create();

  auto url = KURL("ws://localhost/");

  {
    InSequence s;
    EXPECT_CALL(connector_, Connect(_, _, _, _, _, _, _))
        .Times(WebSocketChannelImpl::kMaxWebSocketsPerRenderProcess)
        .WillRepeatedly(handshake_client_add_action);

    EXPECT_CALL(checkpoint, Call(1));

    EXPECT_CALL(*failure_channel_client, DidError());
    EXPECT_CALL(
        *failure_channel_client,
        DidClose(WebSocketChannelClient::kClosingHandshakeIncomplete,
                 WebSocketChannel::kCloseEventCodeAbnormalClosure, String()));
    EXPECT_CALL(*failure_handshake_throttle, Destructor());

    EXPECT_CALL(checkpoint, Call(2));

    EXPECT_CALL(*successful_handshake_throttle, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(connector_, Connect(_, _, _, _, _, _, _))
        .WillOnce(handshake_client_add_action);
    EXPECT_CALL(*successful_handshake_throttle, Destructor());
  }

  WebSocketChannelImpl*
      channels[WebSocketChannelImpl::kMaxWebSocketsPerRenderProcess] = {};
  for (WebSocketChannelImpl*& channel : channels) {
    auto handshake_throttle =
        std::make_unique<StrictMock<MockWebSocketHandshakeThrottle>>();
    EXPECT_CALL(*handshake_throttle, ThrottleHandshake(_, _, _, _));
    EXPECT_CALL(*handshake_throttle, Destructor());

    // This is kept alive by WebSocketChannelImpl so we don't need to retain
    // our own reference.
    auto* channel_client = MockWebSocketChannelClient::Create();

    channel = WebSocketChannelImpl::CreateForTesting(
        GetFrame().DomWindow(), channel_client, CaptureSourceLocation(),
        std::move(handshake_throttle));
    channel->Connect(url, "");
  }

  // Connect() is called via mojo and so asynchronously.
  test::RunPendingTasks();

  auto* failing_channel = WebSocketChannelImpl::CreateForTesting(
      GetFrame().DomWindow(), failure_channel_client, CaptureSourceLocation(),
      std::move(failure_handshake_throttle));
  failing_channel->Connect(url, "");

  checkpoint.Call(1);

  // Give DidClose() a chance to be called.
  test::RunPendingTasks();

  // Abort all the pending connections to permit more to be created.
  for (auto* channel : channels) {
    channel->Disconnect();
  }

  checkpoint.Call(2);

  auto* successful_channel = WebSocketChannelImpl::CreateForTesting(
      GetFrame().DomWindow(), successful_channel_client,
      CaptureSourceLocation(), std::move(successful_handshake_throttle));
  successful_channel->Connect(url, "");

  // Let the connect be passed through mojo.
  test::RunPendingTasks();

  // Destroy the channel to stop it interfering with other tests.
  successful_channel->Disconnect();
}

}  // namespace blink
```
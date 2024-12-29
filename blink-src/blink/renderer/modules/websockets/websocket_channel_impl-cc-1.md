Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `WebSocketChannelImpl` class in Chromium's Blink rendering engine. I need to go through the code and identify the key actions and responsibilities of this class, especially focusing on how it handles WebSocket communication.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file name and class name clearly indicate this is the implementation of a WebSocket channel. This means it's responsible for managing the lifecycle and communication of a single WebSocket connection.

2. **Analyze Key Methods:**  I'll look for methods that handle sending and receiving data, managing the connection state, and dealing with errors.

3. **Examine Member Variables:**  The member variables will give clues about the state and resources managed by the class. For example, `messages_`, `websocket_`, `readable_`, `writable_`.

4. **Look for Interactions with Other Components:** The code interacts with Mojo for inter-process communication, and likely with JavaScript APIs related to WebSockets.

5. **Address Specific Questions:** The prompt asks about relationships to JavaScript, HTML, CSS, logical inference (with examples), common usage errors, and debugging.

6. **Structure the Summary:** I'll organize the summary logically, starting with the core functionality and then addressing the specific points raised in the prompt.

**Detailed Analysis of the Code Snippet:**

* **`Message` Inner Class:** This class encapsulates a message to be sent over the WebSocket. It holds the message type, payload, and a completion callback.
* **`ConnectionCountTrackerHandle` Inner Class:** This seems to manage the number of active WebSocket connections to prevent resource exhaustion.
* **`IncrementAndCheckStatus` and `Decrement`:** These methods control the connection count.
* **`MaybeSendSynchronously`:**  Handles sending messages immediately if the send queue is empty.
* **`ProcessSendQueue`:** Iterates through the message queue and sends messages, handling different message types (text, binary, blob, close). It interacts with `websocket_->SendMessage` and `websocket_->StartClosingHandshake`.
* **`SendMessageData`:**  Actually sends the data over the `writable_` data pipe. It handles backpressure if the pipe is full.
* **`AbortAsyncOperations`:** Cancels any ongoing asynchronous operations, like blob loading.
* **`HandleDidClose`:**  Called when the WebSocket connection closes, notifying the client.
* **`OnCompletion`:**  Handles the completion of the initial WebSocket handshake.
* **`DidFinishLoadingBlob`, `BlobTooLarge`, `DidFailLoadingBlob`:** Methods for handling the asynchronous loading of Blob data for sending.
* **`TearDownFailedConnection`:** Handles error scenarios by closing the connection.
* **`ShouldDisallowConnection`:**  Checks with the `SubresourceFilter` if the connection should be allowed based on the URL.
* **`GetBaseFetchContext`:** Retrieves the fetch context.
* **`OnReadable` and `ConsumePendingDataFrames`:** Handle incoming data from the `readable_` data pipe.
* **`ConsumeDataFrame`:** Processes individual data frames, handling different message types (text, binary, continuation). It interacts with `client_->DidReceiveTextMessage` and `client_->DidReceiveBinaryMessage`.
* **`OnWritable`:**  Notified when the `writable_` data pipe is ready for more data.
* **`ProduceData`:** Writes data to the `writable_` data pipe.
* **`GetTextMessage`:**  Decodes a sequence of data chunks into a UTF-8 string.
* **`OnConnectionError`:**  Handles connection errors reported by the network service.
* **`Dispose`:**  Releases resources associated with the WebSocket connection.

**Addressing the Specific Questions:**

* **JavaScript, HTML, CSS:**  WebSockets are initiated from JavaScript. HTML provides the structure for web pages that might use WebSockets. CSS is not directly involved in WebSocket communication.
* **Logical Inference:** I can create examples of how the code handles different message types and connection states.
* **Common Usage Errors:** I can think about scenarios where developers might misuse the WebSocket API.
* **User Operation to Reach Here:** I need to describe the sequence of actions a user might take in a web browser that would lead to this code being executed.
* **Debugging:** I can point out the logging and tracing statements that would be helpful during debugging.

**Finalizing the Summary:** I will now synthesize the information gathered into a clear and concise summary addressing all aspects of the prompt.
好的，这是第二部分，让我们继续归纳 `blink/renderer/modules/websockets/websocket_channel_impl.cc` 文件的功能。

**WebSocketChannelImpl 的功能归纳 (第 2 部分):**

这部分代码主要关注 `WebSocketChannelImpl` 类在 WebSocket 连接打开后的数据处理、错误处理、以及资源清理等方面。以下是具体功能的归纳：

1. **接收数据处理:**
    *   **`OnReadable` 和 `ConsumePendingDataFrames`:** 负责监听和读取底层 Mojo 数据管道 (`readable_`) 中的数据。当有数据到达时，`OnReadable` 被触发，然后调用 `ConsumePendingDataFrames` 来实际读取数据帧。
    *   **`ConsumeDataFrame`:**  处理读取到的数据帧。它根据帧的类型（文本、二进制、延续帧）将数据传递给 `WebSocketChannelClient` 进行进一步处理（通过 `DidReceiveTextMessage` 或 `DidReceiveBinaryMessage`）。它还负责管理消息的组装，特别是对于分片发送的消息。
    *   **消息分片处理:**  当接收到非最终帧 (`fin` 为 false) 时，它会将数据暂存到 `message_chunks_` 中，直到接收到最终帧再进行完整消息的处理。
    *   **文本消息解码:** 使用 `GetTextMessage` 将接收到的文本消息数据解码为 UTF-8 字符串。

2. **发送数据处理:**
    *   **`OnWritable`:**  监听底层 Mojo 数据管道 (`writable_`) 的可写状态。当管道变为可写时，`OnWritable` 被触发，然后调用 `ProcessSendQueue` 来发送等待发送的消息。
    *   **`ProduceData`:** 将数据写入到 Mojo 数据管道 (`writable_`) 中进行发送。它处理管道可能被填满的情况。

3. **Blob 数据处理:**
    *   **`DidFinishLoadingBlob`:**  当 Blob 数据加载完成后被调用，将加载的 Blob 数据替换到发送队列中的对应消息，并继续处理发送队列。
    *   **`BlobTooLarge` 和 `DidFailLoadingBlob`:** 处理 Blob 数据加载失败的情况，例如 Blob 过大或加载过程中发生错误。

4. **连接关闭和错误处理:**
    *   **`HandleDidClose`:** 当 WebSocket 连接关闭时被调用，通知 `WebSocketChannelClient` 连接已关闭，并提供关闭状态、代码和原因。
    *   **`TearDownFailedConnection`:**  处理连接建立或运行过程中发生的错误，通知 `WebSocketChannelClient` 发生了错误，并尝试关闭连接。
    *   **`OnConnectionError`:**  当底层网络连接发生错误时被调用，获取错误信息并调用 `FailAsError` 来通知客户端。
    *   **`FailAsError` (虽然未在代码片段中，但此处可以推断出其作用):**  一个用于处理错误并通知客户端的函数，可能还会记录错误信息。

5. **资源管理和清理:**
    *   **`Dispose`:**  释放 `WebSocketChannelImpl` 对象所持有的资源，例如取消 Mojo 管道的监听、重置成员变量、释放 Mojo 接口等。

6. **连接限制:**
    *   **`ConnectionCountTrackerHandle`:**  用于跟踪当前渲染进程中 WebSocket 连接的数量，并防止超过预设的限制 (`kMaxWebSocketsPerRenderProcess`)。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript:**
    *   当 JavaScript 代码调用 `new WebSocket('ws://example.com')` 创建一个新的 WebSocket 连接时，Blink 引擎会创建 `WebSocketChannelImpl` 的实例来管理这个连接。
    *   JavaScript 中使用 `websocket.send('message')` 发送数据时，数据最终会被封装成 `Message` 对象并添加到 `WebSocketChannelImpl` 的发送队列中，然后通过 `ProcessSendQueue` 和 `SendMessageData` 发送出去。
    *   当 WebSocket 连接接收到数据时，`ConsumeDataFrame` 处理后，会调用 `client_->DidReceiveTextMessage` 或 `client_->DidReceiveBinaryMessage`，最终将数据传递回 JavaScript 的 `onmessage` 事件处理函数。
    *   JavaScript 中调用 `websocket.close()` 时，`WebSocketChannelImpl` 会调用 `websocket_->StartClosingHandshake` 发起关闭握手。

*   **HTML:**  HTML 中通过 `<script>` 标签引入 JavaScript 代码，而这些 JavaScript 代码可以创建和使用 WebSocket 连接。HTML 结构本身不直接参与 WebSocket 的通信过程。

*   **CSS:** CSS 负责网页的样式和布局，与 WebSocket 的通信过程没有直接关系。

**逻辑推理的假设输入与输出举例:**

**假设输入:**

1. **场景:**  WebSocket 连接已建立 (`GetState() == State::kOpen`)。
2. **接收到数据帧:**  `OnReadable` 被触发，`readable_` 数据管道中有 100 字节的文本数据，且 `fin` 为 `true` (这是消息的最后一个分片)。
3. **`ConsumePendingDataFrames` 被调用。**

**输出:**

1. `ConsumePendingDataFrames` 从 `readable_` 读取 100 字节的数据。
2. `ConsumeDataFrame` 被调用，`fin` 为 `true`，数据类型为 `network::mojom::blink::WebSocketMessageType::TEXT`。
3. `GetTextMessage` 将这 100 字节的数据解码为 UTF-8 字符串。
4. `client_->DidReceiveTextMessage` 被调用，将解码后的字符串传递给客户端（通常是 JavaScript 层的 WebSocket 对象）。

**假设输入:**

1. **场景:** WebSocket 连接已建立 (`GetState() == State::kOpen`)。
2. **发送队列中有消息:** `messages_` 不为空，包含一个文本消息 "Hello"。
3. **`OnWritable` 被触发，`writable_` 数据管道可写。**

**输出:**

1. `ProcessSendQueue` 从 `messages_` 中取出消息。
2. `websocket_->SendMessage` 被调用，告知底层发送消息类型和大小。
3. `SendMessageData` 被调用，将 "Hello" 的数据写入到 `writable_` 数据管道。
4. 如果写入成功，消息从 `messages_` 中移除，并且如果定义了完成回调，则执行该回调。

**用户或编程常见的使用错误举例:**

1. **在连接关闭后尝试发送数据:**  如果 JavaScript 代码在 WebSocket 的 `onclose` 事件触发后仍然尝试调用 `websocket.send()`，那么 `ProcessSendQueue` 可能会被调用，但由于连接已关闭，数据将无法发送，并且可能会触发断言失败或错误处理逻辑。

2. **发送过大的消息:** 如果 JavaScript 尝试发送一个非常大的字符串或二进制数据，可能会导致 `ProduceData` 在写入 Mojo 管道时遇到问题，或者超出浏览器的内存限制。

3. **不处理 `onclose` 事件:**  如果开发者没有正确处理 WebSocket 的 `onclose` 事件，可能会导致程序在连接意外断开后无法做出适当的响应。

4. **在 `onopen` 之前发送消息:**  如果在 WebSocket 的 `onopen` 事件触发之前就尝试发送消息，消息可能会被缓冲，但最佳实践是在连接建立后才开始发送数据。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个网址，该网页包含使用 WebSocket 的 JavaScript 代码。**
2. **浏览器加载 HTML、CSS 和 JavaScript 资源。**
3. **JavaScript 代码执行，创建了一个 `WebSocket` 对象，例如 `var ws = new WebSocket('ws://example.com');`。**
4. **Blink 引擎接收到创建 WebSocket 连接的请求，并创建 `WebSocketChannelImpl` 的实例。**
5. **`WebSocketChannelImpl` 发起与服务器的握手过程。**
6. **如果握手成功，`WebSocketChannelImpl` 的状态变为 `State::kOpen`，并且可以开始发送和接收数据。**
7. **当 JavaScript 调用 `ws.send('some data')` 时，数据会被添加到 `WebSocketChannelImpl` 的发送队列。**
8. **当有数据从 WebSocket 服务器到达时，Mojo 管道会接收到数据，并触发 `WebSocketChannelImpl::OnReadable`。**
9. **在调试过程中，可以通过在 `OnReadable`, `ConsumePendingDataFrames`, `ConsumeDataFrame`, `OnWritable`, `ProcessSendQueue`, `SendMessageData` 等关键方法中设置断点来观察数据的流动和状态变化。**
10. 可以查看 `messages_` 队列的内容，以及 `readable_` 和 `writable_` Mojo 管道的状态。

希望这个更全面的归纳能够帮助你更好地理解 `WebSocketChannelImpl` 的功能！

Prompt: 
```
这是目录为blink/renderer/modules/websockets/websocket_channel_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
essage::Reason() const {
  return reason_;
}

base::OnceClosure WebSocketChannelImpl::Message::CompletionCallback() {
  return std::move(completion_callback_);
}

// This could be done directly in WebSocketChannelImpl, but is a separate class
// to make it easier to verify correctness.
WebSocketChannelImpl::ConnectionCountTrackerHandle::CountStatus
WebSocketChannelImpl::ConnectionCountTrackerHandle::IncrementAndCheckStatus() {
  DCHECK(!incremented_);
  incremented_ = true;
  const size_t old_count =
      g_connection_count.fetch_add(1, std::memory_order_relaxed);
  return old_count >= kMaxWebSocketsPerRenderProcess
             ? CountStatus::kShouldNotConnect
             : CountStatus::kOkayToConnect;
}

void WebSocketChannelImpl::ConnectionCountTrackerHandle::Decrement() {
  if (incremented_) {
    incremented_ = false;
    const size_t old_count =
        g_connection_count.fetch_sub(1, std::memory_order_relaxed);
    DCHECK_NE(old_count, 0u);
  }
}

bool WebSocketChannelImpl::MaybeSendSynchronously(
    network::mojom::blink::WebSocketMessageType frame_type,
    base::span<const char>* data) {
  DCHECK(messages_.empty());
  DCHECK(!wait_for_writable_);

  websocket_->SendMessage(frame_type, data->size());
  return SendMessageData(data);
}

void WebSocketChannelImpl::ProcessSendQueue() {
  // TODO(yhirano): This should be DCHECK_EQ(GetState(), State::kOpen).
  DCHECK(GetState() == State::kOpen || GetState() == State::kConnecting);
  DCHECK(!execution_context_->IsContextDestroyed());
  while (!messages_.empty() && !blob_loader_ && !wait_for_writable_) {
    Message& message = messages_.front();
    network::mojom::blink::WebSocketMessageType message_type =
        network::mojom::blink::WebSocketMessageType::BINARY;
    switch (message.Type()) {
      case kMessageTypeText:
        message_type = network::mojom::blink::WebSocketMessageType::TEXT;
        [[fallthrough]];
      case kMessageTypeArrayBuffer: {
        base::span<const char>& data_frame = message.MutablePendingPayload();
        if (!message.GetDidCallSendMessage()) {
          websocket_->SendMessage(message_type, data_frame.size());
          message.SetDidCallSendMessage(Message::DidCallSendMessage(true));
        }
        if (!SendMessageData(&data_frame))
          return;
        base::OnceClosure completion_callback =
            messages_.front().CompletionCallback();
        if (!completion_callback.is_null())
          std::move(completion_callback).Run();
        messages_.pop_front();
        break;
      }
      case kMessageTypeBlob:
        CHECK(!blob_loader_);
        CHECK(message.GetBlobDataHandle());
        blob_loader_ = MakeGarbageCollected<BlobLoader>(
            message.GetBlobDataHandle(), this, file_reading_task_runner_);
        break;
      case kMessageTypeClose: {
        // No message should be sent from now on.
        DCHECK_EQ(messages_.size(), 1u);
        DCHECK_EQ(sent_size_of_top_message_, 0u);
        handshake_throttle_.reset();
        websocket_->StartClosingHandshake(
            message.Code(),
            message.Reason().IsNull() ? g_empty_string : message.Reason());
        messages_.pop_front();
        break;
      }
    }
  }
}

bool WebSocketChannelImpl::SendMessageData(base::span<const char>* data) {
  if (data->size() > 0) {
    uint64_t consumed_buffered_amount = 0;
    ProduceData(data, &consumed_buffered_amount);
    if (client_ && consumed_buffered_amount > 0)
      client_->DidConsumeBufferedAmount(consumed_buffered_amount);
    if (data->size() > 0) {
      // The |writable_| datapipe is full.
      wait_for_writable_ = true;
      if (writable_) {
        writable_watcher_.ArmOrNotify();
      } else {
        // This is to maintain backwards compatibility with the legacy
        // code, where it requires Send to be complete even if the
        // datapipe is closed. To overcome this, call
        // DidConsumeBufferedAmount() and ack as the message is correctly
        // passed on to the network service.
        //
        // The corresponding bug for this is
        // https://bugs.chromium.org/p/chromium/issues/detail?id=937790
        // The corresponding test case is
        // browser_tests WebRequestApiTest.WebSocketCleanClose.
        if (client_) {
          client_->DidConsumeBufferedAmount(data->size());
        }
      }
      return false;
    }
  }
  return true;
}

void WebSocketChannelImpl::AbortAsyncOperations() {
  if (blob_loader_) {
    blob_loader_->Cancel();
    blob_loader_.Clear();
  }
}

void WebSocketChannelImpl::HandleDidClose(bool was_clean,
                                          uint16_t code,
                                          const String& reason) {
  DCHECK_NE(GetState(), State::kDisconnected);
  WebSocketChannelClient::ClosingHandshakeCompletionStatus status =
      was_clean ? WebSocketChannelClient::kClosingHandshakeComplete
                : WebSocketChannelClient::kClosingHandshakeIncomplete;
  client_->DidClose(status, code, reason);
  AbortAsyncOperations();
  Dispose();
}

void WebSocketChannelImpl::OnCompletion(
    const std::optional<WebString>& console_message) {
  DCHECK(!throttle_passed_);
  DCHECK(handshake_throttle_);
  handshake_throttle_ = nullptr;

  if (GetState() == State::kDisconnected) {
    return;
  }
  DCHECK_EQ(GetState(), State::kConnecting);
  if (console_message) {
    FailAsError(*console_message);
    return;
  }

  throttle_passed_ = true;
  if (connect_info_) {
    websocket_->StartReceiving();
    client_->DidConnect(std::move(connect_info_->selected_protocol),
                        std::move(connect_info_->extensions));
    connect_info_.reset();
    DCHECK_EQ(GetState(), State::kOpen);
  }
}

void WebSocketChannelImpl::DidFinishLoadingBlob(MessageData data, size_t size) {
  DCHECK_EQ(GetState(), State::kOpen);

  blob_loader_.Clear();
  // The loaded blob is always placed on |messages_[0]|.
  DCHECK_GT(messages_.size(), 0u);
  DCHECK_EQ(messages_.front().Type(), kMessageTypeBlob);

  // We replace it with the loaded blob.
  messages_.front() = Message(std::move(data), size);

  ProcessSendQueue();
}

void WebSocketChannelImpl::BlobTooLarge() {
  DCHECK_EQ(GetState(), State::kOpen);

  blob_loader_.Clear();

  FailAsError("Blob too large: cannot load into memory");
}

void WebSocketChannelImpl::DidFailLoadingBlob(FileErrorCode error_code) {
  DCHECK_EQ(GetState(), State::kOpen);

  blob_loader_.Clear();
  if (error_code == FileErrorCode::kAbortErr) {
    // The error is caused by cancel().
    return;
  }
  // FIXME: Generate human-friendly reason message.
  FailAsError("Failed to load Blob: error code = " +
              String::Number(static_cast<unsigned>(error_code)));
}

void WebSocketChannelImpl::TearDownFailedConnection() {
  if (GetState() == State::kDisconnected) {
    return;
  }
  client_->DidError();
  if (GetState() == State::kDisconnected) {
    return;
  }
  HandleDidClose(false, kCloseEventCodeAbnormalClosure, String());
}

bool WebSocketChannelImpl::ShouldDisallowConnection(const KURL& url) {
  SubresourceFilter* subresource_filter =
      GetBaseFetchContext()->GetSubresourceFilter();
  if (!subresource_filter)
    return false;
  return !subresource_filter->AllowWebSocketConnection(url);
}

BaseFetchContext* WebSocketChannelImpl::GetBaseFetchContext() const {
  ResourceFetcher* resource_fetcher = execution_context_->Fetcher();
  return static_cast<BaseFetchContext*>(&resource_fetcher->Context());
}

void WebSocketChannelImpl::OnReadable(MojoResult result,
                                      const mojo::HandleSignalsState& state) {
  DCHECK_EQ(GetState(), State::kOpen);
  DVLOG(2) << this << " OnReadable mojo_result=" << result;
  if (result != MOJO_RESULT_OK) {
    // We don't detect mojo errors on data pipe. Mojo connection errors will
    // be detected via |client_receiver_|.
    return;
  }
  ConsumePendingDataFrames();
}

void WebSocketChannelImpl::ConsumePendingDataFrames() {
  DCHECK_EQ(GetState(), State::kOpen);
  while (!pending_data_frames_.empty() && !backpressure_ &&
         GetState() == State::kOpen) {
    DataFrame& data_frame = pending_data_frames_.front();
    DVLOG(2) << " ConsumePendingDataFrame frame=(" << data_frame.fin << ", "
             << data_frame.type << ", (data_length = " << data_frame.data_length
             << "))";
    if (data_frame.data_length == 0) {
      ConsumeDataFrame(data_frame.fin, data_frame.type, nullptr, 0);
      pending_data_frames_.pop_front();
      continue;
    }

    base::span<const uint8_t> buffer;
    const MojoResult begin_result =
        readable_->BeginReadData(MOJO_READ_DATA_FLAG_NONE, buffer);
    if (begin_result == MOJO_RESULT_SHOULD_WAIT) {
      readable_watcher_.ArmOrNotify();
      return;
    }
    if (begin_result == MOJO_RESULT_FAILED_PRECONDITION) {
      // |client_receiver_| will catch the connection error.
      return;
    }
    DCHECK_EQ(begin_result, MOJO_RESULT_OK);

    std::string_view chars = base::as_string_view(buffer);
    if (buffer.size() >= data_frame.data_length) {
      ConsumeDataFrame(data_frame.fin, data_frame.type, chars.data(),
                       data_frame.data_length);
      const MojoResult end_result =
          readable_->EndReadData(data_frame.data_length);
      DCHECK_EQ(end_result, MOJO_RESULT_OK);
      pending_data_frames_.pop_front();
      continue;
    }

    DCHECK_LT(chars.size(), data_frame.data_length);
    ConsumeDataFrame(false, data_frame.type, chars.data(), chars.size());
    const MojoResult end_result = readable_->EndReadData(buffer.size());
    DCHECK_EQ(end_result, MOJO_RESULT_OK);
    data_frame.type = network::mojom::blink::WebSocketMessageType::CONTINUATION;
    data_frame.data_length -= chars.size();
  }
}

void WebSocketChannelImpl::ConsumeDataFrame(
    bool fin,
    network::mojom::blink::WebSocketMessageType type,
    const char* data,
    size_t size) {
  DCHECK_EQ(GetState(), State::kOpen);
  DCHECK(!backpressure_);
  // Non-final frames cannot be empty.
  DCHECK(fin || size > 0);

  switch (type) {
    case network::mojom::blink::WebSocketMessageType::CONTINUATION:
      break;
    case network::mojom::blink::WebSocketMessageType::TEXT:
      DCHECK_EQ(message_chunks_->GetSize(), 0u);
      receiving_message_type_is_text_ = true;
      break;
    case network::mojom::blink::WebSocketMessageType::BINARY:
      DCHECK_EQ(message_chunks_->GetSize(), 0u);
      receiving_message_type_is_text_ = false;
      break;
  }

  const size_t message_size_so_far = message_chunks_->GetSize();
  if (message_size_so_far > std::numeric_limits<wtf_size_t>::max()) {
    message_chunks_->Clear();
    FailAsError("Message size is too large.");
    return;
  }

  // TODO(yoichio): Do this after EndReadData by reading |message_chunks_|
  // instead.
  if (receiving_message_type_is_text_ && received_text_is_all_ascii_) {
    for (size_t i = 0; i < size; i++) {
      if (!IsASCII(data[i])) {
        received_text_is_all_ascii_ = false;
        break;
      }
    }
  }

  if (!fin) {
    message_chunks_->Append(base::make_span(data, size));
    return;
  }

  Vector<base::span<const char>> chunks = message_chunks_->GetView();
  if (size > 0) {
    chunks.push_back(base::make_span(data, size));
  }
  auto opcode = receiving_message_type_is_text_
                    ? WebSocketOpCode::kOpCodeText
                    : WebSocketOpCode::kOpCodeBinary;
  probe::DidReceiveWebSocketMessage(execution_context_, identifier_, opcode,
                                    false, chunks);
  DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT(
    "WebSocketReceive", InspectorWebSocketTransferEvent::Data,
    execution_context_.Get(), identifier_, size);
  if (receiving_message_type_is_text_) {
    String message = GetTextMessage(
        chunks, static_cast<wtf_size_t>(message_size_so_far + size));
    if (message.IsNull()) {
      FailAsError("Could not decode a text frame as UTF-8.");
    } else {
      client_->DidReceiveTextMessage(message);
    }
  } else {
    client_->DidReceiveBinaryMessage(chunks);
  }
  message_chunks_->Clear();
  received_text_is_all_ascii_ = true;
}

void WebSocketChannelImpl::OnWritable(MojoResult result,
                                      const mojo::HandleSignalsState& state) {
  DCHECK_EQ(GetState(), State::kOpen);
  DVLOG(2) << this << " OnWritable mojo_result=" << result;
  if (result != MOJO_RESULT_OK) {
    // We don't detect mojo errors on data pipe. Mojo connection errors will
    // be detected via |client_receiver_|.
    return;
  }
  wait_for_writable_ = false;
  ProcessSendQueue();
}

MojoResult WebSocketChannelImpl::ProduceData(
    base::span<const char>* data,
    uint64_t* consumed_buffered_amount) {
  MojoResult begin_result = MOJO_RESULT_OK;
  base::span<uint8_t> buffer;
  while (!data->empty() && (begin_result = writable_->BeginWriteData(
                                data->size(), MOJO_WRITE_DATA_FLAG_NONE,
                                buffer)) == MOJO_RESULT_OK) {
    const size_t size_to_write = std::min(buffer.size(), data->size());
    DCHECK_GT(size_to_write, 0u);

    base::as_writable_chars(buffer).copy_prefix_from(
        data->first(size_to_write));
    *data = data->subspan(size_to_write);

    const MojoResult end_result = writable_->EndWriteData(size_to_write);
    DCHECK_EQ(end_result, MOJO_RESULT_OK);
    *consumed_buffered_amount += size_to_write;
  }
  if (begin_result != MOJO_RESULT_OK &&
      begin_result != MOJO_RESULT_SHOULD_WAIT) {
    DVLOG(1) << "WebSocket::OnWritable mojo error=" << begin_result;
    DCHECK_EQ(begin_result, MOJO_RESULT_FAILED_PRECONDITION);
    writable_.reset();
  }
  return begin_result;
}

String WebSocketChannelImpl::GetTextMessage(
    const Vector<base::span<const char>>& chunks,
    wtf_size_t size) {
  DCHECK(receiving_message_type_is_text_);

  if (size == 0) {
    return g_empty_string;
  }

  // We can skip UTF8 encoding if received text contains only ASCII.
  // We do this in order to avoid constructing a temporary buffer.
  if (received_text_is_all_ascii_) {
    StringBuffer<LChar> ascii_string_buffer(size);
    auto ascii_buffer = base::as_writable_chars(ascii_string_buffer.Span());
    for (const auto& chunk : chunks) {
      auto [copy_dest, rest] = ascii_buffer.split_at(chunk.size());
      copy_dest.copy_from(chunk);
      ascii_buffer = rest;
    }
    DCHECK(ascii_buffer.empty());
    return String(ascii_string_buffer.Release());
  }

  Vector<char> flatten;
  base::span<const char> span;
  if (chunks.size() > 1) {
    flatten.reserve(size);
    for (const auto& chunk : chunks) {
      flatten.AppendSpan(chunk);
    }
    span = base::span(flatten);
  } else if (chunks.size() == 1) {
    span = chunks[0];
  }
  DCHECK_EQ(span.size(), size);
  return String::FromUTF8(base::as_bytes(span));
}

void WebSocketChannelImpl::OnConnectionError(const base::Location& set_from,
                                             uint32_t custom_reason,
                                             const std::string& description) {
  DCHECK_NE(GetState(), State::kDisconnected);
  DVLOG(1) << " OnConnectionError("
           << ", description:" << description
           << ", failure_message:" << failure_message_
           << "), set_from:" << set_from.ToString();
  String message;
  if (description.empty()) {
    message = failure_message_;
  } else {
    message = String::FromUTF8(description);
  }

  // This function is called when the implementation in the network service is
  // required to fail the WebSocket connection. Hence we fail this channel by
  // calling FailAsError function.
  FailAsError(message);
}

void WebSocketChannelImpl::Dispose() {
  connection_count_tracker_handle_.Decrement();
  message_chunks_->Reset();
  has_initiated_opening_handshake_ = true;
  feature_handle_for_scheduler_.reset();
  handshake_throttle_.reset();
  websocket_.reset();
  readable_watcher_.Cancel();
  writable_watcher_.Cancel();
  handshake_client_receiver_.reset();
  client_receiver_.reset();
  identifier_ = 0;
}

std::ostream& operator<<(std::ostream& ostream,
                         const WebSocketChannelImpl* channel) {
  return ostream << "WebSocketChannelImpl "
                 << static_cast<const void*>(channel);
}

}  // namespace blink

"""


```
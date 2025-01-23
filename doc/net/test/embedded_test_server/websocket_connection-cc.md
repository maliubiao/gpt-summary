Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Initial Skim and Understanding the Core Purpose:**

The first step is always to quickly read through the code, paying attention to class names, key function names, and included headers. This gives a high-level understanding of what the code is doing.

* **`WebSocketConnection`:**  This is clearly the central class.
* **`StreamSocket`:** Indicates network communication.
* **`WebSocketHandler`:**  Suggests this class handles incoming WebSocket messages.
* **`WebSocketFrameParser`, `WebSocketMessageAssembler`:** Point towards WebSocket protocol handling.
* **`EmbeddedTestServer`:**  Indicates this is for testing purposes.

From this initial skim, the core purpose becomes clear: This class represents a WebSocket connection within an embedded test server. It handles the low-level details of sending and receiving WebSocket frames.

**2. Identifying Key Functionalities:**

Next, we examine the public methods of the `WebSocketConnection` class. These are the primary actions it can perform:

* **Constructor/Destructor:**  Setting up and tearing down the connection.
* **`SetResponseHeader`:** Modifying HTTP headers for the handshake response.
* **`SendTextMessage`, `SendBinaryMessage`:** Sending data.
* **`StartClosingHandshake`, `RespondToCloseFrame`:** Managing the closing handshake.
* **`SendPing`, `SendPong`:**  Sending control frames.
* **`DisconnectAfterAnyWritesDone`, `DisconnectImmediately`:**  Closing the connection.
* **`SendRaw`:**  Sending raw bytes (useful for the initial handshake).
* **`SetHandler`:**  Associating a handler for incoming messages.

This helps us create a list of the core functionalities.

**3. Looking for Interactions with JavaScript:**

The prompt specifically asks about JavaScript interaction. WebSockets are inherently about browser-server communication. Therefore, the *entire purpose* of this code is to interact with JavaScript running in a browser.

The connection is established from JavaScript using the `WebSocket` API. The server-side code (`WebSocketConnection`) needs to handle the initial handshake initiated by the JavaScript client and then process the messages sent back and forth.

* **Handshake:**  The constructor and `SendHandshakeResponse` directly handle the server's part of the WebSocket handshake, responding to the browser's upgrade request.
* **Sending/Receiving Messages:** `SendTextMessage`, `SendBinaryMessage` send data to the JavaScript client. The `Read` and `OnReadComplete` methods receive data sent by the JavaScript client.
* **Closing Handshake:** `StartClosingHandshake` and `RespondToCloseFrame` manage the server-initiated and client-initiated close sequences.
* **Ping/Pong:** `SendPing` and `SendPong` correspond to the WebSocket keep-alive mechanism, often initiated from the server but handled by the browser's WebSocket implementation.

**4. Thinking about Logical Reasoning and Assumptions:**

When analyzing code, it's important to consider the expected flow of execution and make assumptions about inputs and outputs.

* **Handshake:**  *Assumption:* The client sends a valid WebSocket handshake request. *Output:* The server sends a "101 Switching Protocols" response with the correct `Sec-WebSocket-Accept` header.
* **Sending Text Message:** *Assumption:* The `message` passed to `SendTextMessage` is valid UTF-8. *Output:* A WebSocket frame with opcode `0x1` (Text) containing the message.
* **Receiving a Text Message:** *Assumption:* The client sends a valid text frame. *Output:* The `WebSocketHandler`'s `OnTextMessage` method is called with the message content.
* **Closing Handshake (Server Initiated):** *Assumption:* `StartClosingHandshake` is called. *Output:* A close frame is sent to the client, and the connection state changes to `kWaitingForClientClose`.

**5. Identifying Potential User/Programming Errors:**

Based on the code and the WebSocket protocol, we can identify common pitfalls:

* **Sending Non-UTF-8 Text:** The code checks for valid UTF-8 for text messages. Sending invalid UTF-8 would lead to protocol errors.
* **Incorrect Handshake:**  If the `sec_websocket_key` is not handled correctly, the handshake will fail.
* **Sending Data Before Handshake:** The code has checks to queue messages if the handshake isn't complete. Trying to send data too early could lead to unexpected behavior if these checks weren't in place.
* **Not Handling Close Frames:** If the `WebSocketHandler` doesn't properly respond to close frames, the connection might linger or not close cleanly.
* **Protocol Errors:** Sending malformed frames or violating the WebSocket protocol will lead to errors and likely connection closure.

**6. Tracing User Actions and Debugging:**

To understand how a user might reach this code, we consider typical WebSocket usage in a browser and how the test server is involved:

1. **JavaScript `WebSocket` API:** The user's JavaScript code creates a `WebSocket` object, specifying the URL of the embedded test server.
2. **Browser Sends Handshake:** The browser automatically sends an HTTP Upgrade request to the server.
3. **`EmbeddedTestServer` Accepts Connection:** The test server receives the connection.
4. **`WebSocketConnection` is Created:** The server creates a `WebSocketConnection` object to handle this specific connection.
5. **Handshake Processing:**  The `WebSocketConnection` processes the incoming handshake request.
6. **JavaScript Sends/Receives Messages:** The JavaScript code uses `websocket.send()` to send messages, and the `onmessage` event handler receives messages. These correspond to the `Send...Message` and `OnReadComplete`/`HandleFrame` methods in the C++ code.
7. **Closing Connection:** The JavaScript code might call `websocket.close()`, which triggers the closing handshake handled by both the JavaScript WebSocket API and the C++ `WebSocketConnection` class.

For debugging, a developer might:

* **Set Breakpoints:**  Put breakpoints in `OnReadComplete`, `HandleFrame`, `SendInternal` to inspect the flow of data.
* **Inspect Network Traffic:** Use browser developer tools (Network tab) or tools like Wireshark to examine the raw WebSocket frames being exchanged.
* **Examine Server Logs:** The `DVLOG` statements in the C++ code provide logging information that can be helpful.

**7. Structuring the Answer:**

Finally, the gathered information needs to be organized into a clear and comprehensive answer, addressing each part of the prompt:

* **Functionality:** List the key methods and their roles.
* **Relationship to JavaScript:** Explain how the code facilitates communication with JavaScript WebSocket API, providing concrete examples for handshake, sending/receiving data, and closing.
* **Logical Reasoning:** Give specific examples of assumed inputs and expected outputs for different scenarios.
* **Common Errors:**  List potential mistakes users or programmers might make.
* **User Operations and Debugging:** Describe the typical user flow that leads to this code being executed and suggest debugging techniques.
这个文件 `net/test/embedded_test_server/websocket_connection.cc` 是 Chromium 网络栈中用于 **嵌入式测试服务器** 的一部分，专门负责处理 **WebSocket 连接**。 它的主要功能是：

**核心功能：**

1. **管理单个 WebSocket 连接的生命周期:**  从连接建立（在嵌入式测试服务器接受客户端连接后创建）到连接断开。
2. **处理 WebSocket 握手:**  接收客户端的握手请求，并发送符合 WebSocket 协议的握手响应 (HTTP 101 Switching Protocols)。
3. **发送 WebSocket 消息:**  提供发送文本消息、二进制消息、关闭帧、Ping 帧和 Pong 帧的功能。
4. **接收 WebSocket 消息:**  从底层的 socket 读取数据，解析 WebSocket 帧，并将解析后的消息传递给注册的 `WebSocketHandler` 进行处理。
5. **处理 WebSocket 控制帧:**  解析和响应 Ping 和 Pong 帧，并处理关闭帧。
6. **实现 WebSocket 关闭握手:**  允许服务器发起或响应客户端发起的关闭握手。
7. **提供发送原始数据的功能:**  允许发送未经 WebSocket 帧封装的原始字节流，主要用于发送握手响应。
8. **使用 `WebSocketHandler` 处理接收到的消息:**  这是一个抽象类，具体的处理逻辑由外部提供。

**与 JavaScript 功能的关系：**

这个 C++ 代码直接对应于 JavaScript 中 `WebSocket` API 的服务端实现。当 JavaScript 代码创建一个 `WebSocket` 对象并连接到嵌入式测试服务器时，这个 C++ 文件中的代码就会被用来处理这个连接。

**举例说明：**

* **JavaScript 发起连接:**
  ```javascript
  const websocket = new WebSocket('ws://localhost:8080/my-websocket');
  ```
  * **C++ 端的动作:**  `EmbeddedTestServer` 接受连接后，会创建一个 `WebSocketConnection` 对象，它的构造函数会被调用。构造函数会存储底层的 socket，并准备发送握手响应。

* **JavaScript 发送文本消息:**
  ```javascript
  websocket.send('Hello, server!');
  ```
  * **C++ 端的动作:**  `WebSocketConnection::SendTextMessage` 方法会被调用，将 JavaScript 发送的字符串封装成 WebSocket 文本帧，并通过底层的 socket 发送出去。

* **JavaScript 接收文本消息:**
  ```javascript
  websocket.onmessage = (event) => {
    console.log('Received message:', event.data);
  };
  ```
  * **C++ 端的动作:**  `WebSocketConnection::OnReadComplete` 方法会读取 socket 数据，`WebSocketFrameParser` 会解析成帧，`WebSocketMessageAssembler` 会将帧组装成完整的消息，然后调用注册的 `WebSocketHandler` 的 `OnTextMessage` 方法，将消息内容传递给处理函数。

* **JavaScript 关闭连接:**
  ```javascript
  websocket.close();
  ```
  * **C++ 端的动作:**  JavaScript 发送一个关闭帧，`WebSocketConnection::OnReadComplete` 和 `WebSocketConnection::HandleFrame` 会处理这个关闭帧，并可能调用 `WebSocketConnection::RespondToCloseFrame` 发送关闭响应。

**逻辑推理与假设输入/输出：**

**假设输入：** 客户端发送一个符合 WebSocket 协议的文本消息帧，包含 "Hello"。

**C++ 端的处理过程：**

1. **`OnReadComplete`**: 从 socket 读取到包含 WebSocket 帧的数据。
2. **`WebSocketFrameParser::Decode`**: 解析读取到的数据，识别出这是一个文本帧。
3. **`chunk_assembler_.HandleChunk`**: 将帧数据传递给消息片段组装器。如果这是一个完整的消息帧，组装器会返回一个完整的 `WebSocketFrame` 对象。
4. **`HandleFrame`**: 根据帧的 opcode (文本帧)，调用 `message_assembler_.HandleFrame`。
5. **`message_assembler_.HandleFrame`**: 将帧内容组装成完整的消息。
6. **`handler_->OnTextMessage`**: 调用注册的 `WebSocketHandler` 的 `OnTextMessage` 方法，并将 "Hello" 作为参数传递进去。

**输出：** 注册的 `WebSocketHandler` 的 `OnTextMessage` 方法被调用，参数为 "Hello"。

**假设输入：** 客户端发送一个 Ping 帧，payload 为 `[0x01, 0x02, 0x03]`。

**C++ 端的处理过程：**

1. **`OnReadComplete`**: 从 socket 读取到 Ping 帧的数据。
2. **`WebSocketFrameParser::Decode`**: 解析识别出这是一个 Ping 帧。
3. **`chunk_assembler_.HandleChunk`**: 处理 Ping 帧。
4. **`HandleFrame`**: 根据帧的 opcode (Ping 帧)，调用 `handler_->OnPing` 方法。

**输出：** 注册的 `WebSocketHandler` 的 `OnPing` 方法被调用，参数为 `base::span<const uint8_t>`，内容为 `[0x01, 0x02, 0x03]`。

**用户或编程常见的使用错误：**

1. **未设置 `WebSocketHandler`:** 如果在连接建立后，没有通过 `SetHandler` 方法设置 `WebSocketHandler`，那么接收到的消息会被忽略，因为 `OnReadComplete` 中有 `if (!handler_)` 的检查。这会导致服务端无法处理客户端发送的消息。
   ```c++
   // 错误示例：忘记设置 handler
   WebSocketConnection connection = ...;
   connection.Read(); // 开始读取，但没有设置 handler
   ```

2. **在握手完成前发送数据:**  虽然代码中通过 `pending_messages_` 实现了在握手完成前发送的数据的排队，但如果逻辑上期望数据在握手后立即发送，过早地调用 `SendTextMessage` 或 `SendBinaryMessage` 可能会导致一些时序问题，或者依赖于内部的排队机制。

3. **错误处理关闭握手:**  `WebSocketHandler` 需要正确处理 `OnClosingHandshake` 回调，并可能调用 `RespondToCloseFrame` 来响应客户端的关闭请求。如果处理不当，可能会导致连接无法正常关闭。

4. **发送非 UTF-8 文本消息:**  `SendTextMessage` 方法内部会检查消息是否是 UTF-8 编码。如果发送非 UTF-8 的字符串，`CHECK(base::IsStringUTF8AllowingNoncharacters(message));` 会触发断言失败。

5. **手动构造错误的 WebSocket 帧:**  如果直接使用 `SendRaw` 发送数据，并且构造的帧不符合 WebSocket 协议规范，会导致客户端解析错误或连接断开。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问了一个网页，这个网页通过 JavaScript 代码建立了一个到嵌入式测试服务器的 WebSocket 连接。

1. **用户在浏览器地址栏输入 URL 并访问网页。**
2. **网页加载完成后，JavaScript 代码执行，创建 `WebSocket` 对象:**
   ```javascript
   const ws = new WebSocket('ws://localhost:8080/');
   ```
3. **浏览器发送 HTTP Upgrade 请求到 `localhost:8080`。**
4. **嵌入式测试服务器监听 `localhost:8080`，接收到连接请求。**
5. **服务器代码检测到这是一个 WebSocket 升级请求，创建一个 `WebSocketConnection` 对象来处理这个连接。**  `WebSocketConnection` 的构造函数被调用。
6. **`WebSocketConnection::SendHandshakeResponse` 被调用，发送 HTTP 101 响应。**
7. **JavaScript `WebSocket` 对象的 `onopen` 事件被触发，连接建立成功。**
8. **用户在网页上执行某些操作，触发 JavaScript 代码通过 `ws.send()` 发送消息。**
9. **`WebSocketConnection::SendTextMessage` 或 `WebSocketConnection::SendBinaryMessage` 被调用，将消息发送到 socket。**
10. **服务器端可能需要向客户端发送消息，调用 `WebSocketConnection::SendTextMessage` 或 `WebSocketConnection::SendBinaryMessage`。**
11. **客户端发送的消息到达服务器，`WebSocketConnection::OnReadComplete` 读取数据。**
12. **`WebSocketFrameParser` 解析接收到的数据。**
13. **`WebSocketConnection::HandleFrame` 根据帧类型调用相应的处理逻辑 (例如 `handler_->OnTextMessage`)。**
14. **用户关闭网页或 JavaScript 代码调用 `ws.close()`。**
15. **客户端发送关闭帧，`WebSocketConnection::OnReadComplete` 和 `HandleFrame` 处理关闭帧。**
16. **服务器可能发送关闭响应帧 (`WebSocketConnection::RespondToCloseFrame`)。**
17. **`WebSocketConnection` 对象最终被销毁。**

**调试线索：**

* **网络抓包 (如 Wireshark):** 可以查看客户端和服务器之间交互的原始 WebSocket 帧，确认握手过程是否正确，消息格式是否符合协议。
* **服务器端日志:**  在 `WebSocketConnection` 的关键方法中添加日志输出 (`DVLOG`)，可以追踪消息的接收、发送和处理过程。
* **浏览器开发者工具:**  Network 标签可以查看 WebSocket 连接的详细信息，包括发送和接收的消息。
* **断点调试:** 在 `WebSocketConnection` 的关键方法中设置断点，可以单步执行代码，查看变量的值，理解代码的执行流程。例如，在 `OnReadComplete`、`HandleFrame`、`SendInternal` 等方法中设置断点。

通过以上分析，我们可以清晰地理解 `net/test/embedded_test_server/websocket_connection.cc` 文件的功能，它与 JavaScript 的关系，以及在实际使用和调试过程中可能遇到的问题。

### 提示词
```
这是目录为net/test/embedded_test_server/websocket_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/embedded_test_server/websocket_connection.h"

#include <stdint.h>

#include "base/compiler_specific.h"
#include "base/containers/extend.h"
#include "base/containers/span.h"
#include "base/containers/span_writer.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/numerics/byte_conversions.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/strcat.h"
#include "net/base/net_errors.h"
#include "net/socket/socket.h"
#include "net/socket/stream_socket.h"
#include "net/test/embedded_test_server/websocket_handler.h"
#include "net/test/embedded_test_server/websocket_message_assembler.h"
#include "net/websockets/websocket_frame.h"
#include "net/websockets/websocket_frame_parser.h"
#include "net/websockets/websocket_handshake_challenge.h"

namespace net::test_server {

WebSocketConnection::WebSocketConnection(std::unique_ptr<StreamSocket> socket,
                                         std::string_view sec_websocket_key,
                                         EmbeddedTestServer* server)
    : stream_socket_(std::move(socket)),
      // Register a shutdown closure to safely disconnect this connection when
      // the
      // server shuts down. base::Unretained is safe here because:
      // 1. The shutdown closure is registered during the construction of the
      //    WebSocketConnection object, ensuring `this` is fully initialized.
      // 2. The lifetime of the closure is tied to the `WebSocketConnection`
      //    object via `shutdown_subscription_`, which ensures that the closure
      //    is automatically unregistered when the object is destroyed.
      // 3. DisconnectImmediately() ensures safe cleanup by resetting the socket
      //    and marking the connection state as closed.
      shutdown_subscription_(server->RegisterShutdownClosure(
          base::BindOnce(&WebSocketConnection::DisconnectImmediately,
                         base::Unretained(this)))) {
  CHECK(stream_socket_);

  response_headers_.emplace_back("Upgrade", "websocket");
  response_headers_.emplace_back("Connection", "Upgrade");
  response_headers_.emplace_back(
      "Sec-WebSocket-Accept",
      ComputeSecWebSocketAccept(std::string(sec_websocket_key)));
}

WebSocketConnection::~WebSocketConnection() {
  DisconnectImmediately();
}

void WebSocketConnection::SetResponseHeader(std::string_view name,
                                            std::string_view value) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(stream_socket_);
  for (auto& header : response_headers_) {
    if (header.first == name) {
      header.second = value;
      return;
    }
  }
  response_headers_.emplace_back(name, value);
}

void WebSocketConnection::SendTextMessage(std::string_view message) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(stream_socket_);
  CHECK(base::IsStringUTF8AllowingNoncharacters(message));
  scoped_refptr<IOBufferWithSize> frame = CreateTextFrame(message);

  SendInternal(std::move(frame), /*wait_for_handshake=*/true);
}

void WebSocketConnection::SendBinaryMessage(base::span<const uint8_t> message) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(stream_socket_);
  scoped_refptr<IOBufferWithSize> frame = CreateBinaryFrame(message);
  SendInternal(std::move(frame), /*wait_for_handshake=*/true);
}

void WebSocketConnection::StartClosingHandshake(std::optional<uint16_t> code,
                                                std::string_view message) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!stream_socket_) {
    DVLOG(2) << "Attempted to start closing handshake, but socket is null.";
    return;
  }

  DVLOG(3) << "Starting closing handshake. Code: "
           << (code ? base::NumberToString(*code) : "none")
           << ", Message: " << message;

  if (!code) {
    CHECK(base::IsStringUTF8AllowingNoncharacters(message));
    SendInternal(BuildWebSocketFrame(base::span<const uint8_t>(),
                                     WebSocketFrameHeader::kOpCodeClose),
                 /*wait_for_handshake=*/true);
    state_ = WebSocketState::kWaitingForClientClose;
    return;
  }

  scoped_refptr<IOBufferWithSize> close_frame = CreateCloseFrame(code, message);
  SendInternal(std::move(close_frame), /*wait_for_handshake=*/true);

  state_ = WebSocketState::kWaitingForClientClose;
}

void WebSocketConnection::RespondToCloseFrame(std::optional<uint16_t> code,
                                              std::string_view message) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (state_ == WebSocketState::kClosed) {
    DVLOG(2) << "Attempted to respond to close frame, but connection is "
                "already closed.";
    return;
  }

  CHECK(base::IsStringUTF8AllowingNoncharacters(message));
  scoped_refptr<IOBufferWithSize> close_frame = CreateCloseFrame(code, message);
  SendInternal(std::move(close_frame), /*wait_for_handshake=*/false);
  DisconnectAfterAnyWritesDone();
}

void WebSocketConnection::SendPing(base::span<const uint8_t> payload) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  scoped_refptr<IOBufferWithSize> ping_frame = CreatePingFrame(payload);
  SendInternal(std::move(ping_frame), /*wait_for_handshake=*/true);
}

void WebSocketConnection::SendPong(base::span<const uint8_t> payload) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  scoped_refptr<IOBufferWithSize> pong_frame = CreatePongFrame(payload);
  SendInternal(std::move(pong_frame), /*wait_for_handshake=*/true);
}

void WebSocketConnection::DisconnectAfterAnyWritesDone() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!stream_socket_) {
    DVLOG(3) << "Socket is already disconnected.";
    return;
  }

  if (!pending_buffer_) {
    DisconnectImmediately();
    return;
  }

  should_disconnect_after_write_ = true;
  state_ = WebSocketState::kDisconnectingSoon;
  handler_.reset();
}

void WebSocketConnection::DisconnectImmediately() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!stream_socket_) {
    DVLOG(3) << "Socket is already disconnected.";
    handler_.reset();
    return;
  }

  // Intentionally not calling Disconnect(), as it doesn't work with
  // SSLServerSocket. Resetting the socket here is sufficient to disconnect.
  ResetStreamSocket();
  handler_.reset();
}

void WebSocketConnection::ResetStreamSocket() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (stream_socket_) {
    stream_socket_.reset();
    state_ = WebSocketState::kClosed;
  }
  // `this` may be deleted here.
}

void WebSocketConnection::SendRaw(base::span<const uint8_t> bytes) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  scoped_refptr<IOBufferWithSize> buffer =
      base::MakeRefCounted<IOBufferWithSize>(bytes.size());
  buffer->span().copy_from(bytes);
  SendInternal(std::move(buffer), /*wait_for_handshake=*/false);
}

void WebSocketConnection::SendInternal(scoped_refptr<IOBufferWithSize> buffer,
                                       bool wait_for_handshake) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if ((wait_for_handshake && state_ != WebSocketState::kOpen) ||
      pending_buffer_) {
    pending_messages_.emplace(std::move(buffer));
    return;
  }

  const size_t buffer_size = buffer->size();
  pending_buffer_ =
      base::MakeRefCounted<DrainableIOBuffer>(std::move(buffer), buffer_size);

  PerformWrite();
}

void WebSocketConnection::SetHandler(
    std::unique_ptr<WebSocketHandler> handler) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  handler_ = std::move(handler);
}

void WebSocketConnection::PerformWrite()
    VALID_CONTEXT_REQUIRED(sequence_checker_) {
  const int result = stream_socket_->Write(
      pending_buffer_.get(), pending_buffer_->BytesRemaining(),
      base::BindOnce(&WebSocketConnection::OnWriteComplete,
                     base::WrapRefCounted(this)),
      DefineNetworkTrafficAnnotation(
          "test", "Traffic annotation for unit, browser and other tests"));

  if (result != ERR_IO_PENDING) {
    OnWriteComplete(result);
  }
}

void WebSocketConnection::OnWriteComplete(int result)
    VALID_CONTEXT_REQUIRED(sequence_checker_) {
  if (result < 0) {
    DVLOG(1) << "Failed to write to WebSocket connection, error: " << result;
    DisconnectImmediately();
    return;
  }

  pending_buffer_->DidConsume(result);

  if (pending_buffer_->BytesRemaining() > 0) {
    PerformWrite();
    return;
  }

  pending_buffer_ = nullptr;

  if (!pending_messages_.empty()) {
    scoped_refptr<IOBufferWithSize> next_message =
        std::move(pending_messages_.front());
    pending_messages_.pop();
    SendInternal(std::move(next_message), /*wait_for_handshake=*/false);
    return;
  }

  if (should_disconnect_after_write_) {
    DisconnectImmediately();
  }
}

void WebSocketConnection::Read() VALID_CONTEXT_REQUIRED(sequence_checker_) {
  read_buffer_ = base::MakeRefCounted<IOBufferWithSize>(4096);

  const int result =
      stream_socket_->Read(read_buffer_.get(), read_buffer_->size(),
                           base::BindOnce(&WebSocketConnection::OnReadComplete,
                                          base::WrapRefCounted(this)));
  if (result != ERR_IO_PENDING) {
    OnReadComplete(result);
  }
}

void WebSocketConnection::OnReadComplete(int result)
    VALID_CONTEXT_REQUIRED(sequence_checker_) {
  if (result <= 0) {
    DVLOG(1) << "Failed to read from WebSocket connection, error: " << result;
    DisconnectImmediately();
    return;
  }

  if (!handler_) {
    DVLOG(1) << "No handler set, ignoring read.";
    return;
  }

  base::span<uint8_t> data_span =
      read_buffer_->span().first(static_cast<size_t>(result));

  WebSocketFrameParser parser;
  std::vector<std::unique_ptr<WebSocketFrameChunk>> frame_chunks;
  parser.Decode(data_span, &frame_chunks);

  for (auto& chunk : frame_chunks) {
    auto assemble_result = chunk_assembler_.HandleChunk(std::move(chunk));

    if (assemble_result.has_value()) {
      std::unique_ptr<WebSocketFrame> assembled_frame =
          std::move(assemble_result).value();
      HandleFrame(assembled_frame->header.opcode,
                  base::as_chars(assembled_frame->payload),
                  assembled_frame->header.final);
      continue;
    }

    if (assemble_result.error() == ERR_WS_PROTOCOL_ERROR) {
      DVLOG(1) << "Protocol error while handling frame.";
      StartClosingHandshake(1002, "Protocol error");
      DisconnectAfterAnyWritesDone();
      return;
    }
  }

  if (stream_socket_) {
    Read();
  }
}

void WebSocketConnection::HandleFrame(WebSocketFrameHeader::OpCode opcode,
                                      base::span<const char> payload,
                                      bool is_final)
    VALID_CONTEXT_REQUIRED(sequence_checker_) {
  CHECK(handler_) << "No handler set for WebSocket connection.";

  switch (opcode) {
    case WebSocketFrameHeader::kOpCodeText:
    case WebSocketFrameHeader::kOpCodeBinary:
    case WebSocketFrameHeader::kOpCodeContinuation: {
      auto message_result =
          message_assembler_.HandleFrame(is_final, opcode, payload);

      if (message_result.has_value()) {
        if (message_result->is_text_message) {
          handler_->OnTextMessage(base::as_string_view(message_result->body));
        } else {
          handler_->OnBinaryMessage(message_result->body);
        }
      } else if (message_result.error() == ERR_WS_PROTOCOL_ERROR) {
        StartClosingHandshake(1002, "Protocol error");
        DisconnectAfterAnyWritesDone();
      }

      break;
    }
    case WebSocketFrameHeader::kOpCodeClose: {
      auto parse_close_frame_result = ParseCloseFrame(payload);
      if (parse_close_frame_result.error.has_value()) {
        DVLOG(1) << "Failed to parse close frame: "
                 << parse_close_frame_result.error.value();
        StartClosingHandshake(1002, "Protocol error");
        DisconnectAfterAnyWritesDone();
      } else {
        handler_->OnClosingHandshake(parse_close_frame_result.code,
                                     parse_close_frame_result.reason);
      }
      break;
    }
    case WebSocketFrameHeader::kOpCodePing:
      handler_->OnPing(base::as_bytes(payload));
      break;
    case WebSocketFrameHeader::kOpCodePong:
      handler_->OnPong(base::as_bytes(payload));
      break;
    default:
      DVLOG(2) << "Unknown frame opcode: " << opcode;
      StartClosingHandshake(1002, "Protocol error");
      DisconnectAfterAnyWritesDone();
      break;
  }
}

void WebSocketConnection::SendHandshakeResponse() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!stream_socket_) {
    DVLOG(2) << "Stream socket is already null. Returning early.";
    return;
  }

  std::string response_text = "HTTP/1.1 101 Switching Protocols\r\n";
  for (const auto& header : response_headers_) {
    base::StrAppend(&response_text,
                    {header.first, ": ", header.second, "\r\n"});
  }
  base::StrAppend(&response_text, {"\r\n"});

  SendRaw(base::as_byte_span(response_text));

  state_ = WebSocketState::kOpen;

  Read();

  // A nullptr check is performed because the connection may have been closed
  // within Read().
  if (handler_) {
    handler_->OnHandshakeComplete();
  } else {
    DVLOG(2)
        << "Handler is null after starting Read. Connection likely closed.";
  }
}

scoped_refptr<IOBufferWithSize> CreateTextFrame(std::string_view message) {
  return BuildWebSocketFrame(base::as_byte_span(message),
                             WebSocketFrameHeader::kOpCodeText);
}

scoped_refptr<IOBufferWithSize> CreateBinaryFrame(
    base::span<const uint8_t> message) {
  return BuildWebSocketFrame(message, WebSocketFrameHeader::kOpCodeBinary);
}

scoped_refptr<IOBufferWithSize> CreateCloseFrame(std::optional<uint16_t> code,
                                                 std::string_view message) {
  DVLOG(3) << "Creating close frame with code: "
           << (code ? base::NumberToString(*code) : "none")
           << ", Message: " << message;
  CHECK(message.empty() || code);
  CHECK(base::IsStringUTF8AllowingNoncharacters(message));

  if (!code) {
    return BuildWebSocketFrame(base::span<const uint8_t>(),
                               WebSocketFrameHeader::kOpCodeClose);
  }

  auto payload =
      base::HeapArray<uint8_t>::Uninit(sizeof(uint16_t) + message.size());
  base::SpanWriter<uint8_t> writer{payload};
  writer.WriteU16BigEndian(code.value());
  writer.Write(base::as_byte_span(message));

  return BuildWebSocketFrame(payload, WebSocketFrameHeader::kOpCodeClose);
}

scoped_refptr<IOBufferWithSize> CreatePingFrame(
    base::span<const uint8_t> payload) {
  return BuildWebSocketFrame(payload, WebSocketFrameHeader::kOpCodePing);
}

scoped_refptr<IOBufferWithSize> CreatePongFrame(
    base::span<const uint8_t> payload) {
  return BuildWebSocketFrame(payload, WebSocketFrameHeader::kOpCodePong);
}

scoped_refptr<IOBufferWithSize> BuildWebSocketFrame(
    base::span<const uint8_t> payload,
    WebSocketFrameHeader::OpCode op_code) {
  WebSocketFrameHeader header(op_code);
  header.final = true;
  header.payload_length = payload.size();

  const size_t header_size = GetWebSocketFrameHeaderSize(header);

  scoped_refptr<IOBufferWithSize> buffer =
      base::MakeRefCounted<IOBufferWithSize>(header_size + payload.size());

  const int written_header_size =
      WriteWebSocketFrameHeader(header, nullptr, buffer->span());
  base::span<uint8_t> buffer_span = buffer->span().subspan(
      base::checked_cast<size_t>(written_header_size), payload.size());
  buffer_span.copy_from(payload);

  return buffer;
}

}  // namespace net::test_server
```
Response:
Let's break down the thought process for analyzing this `http_server.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to JavaScript, examples of logical reasoning, common user/programming errors, and debugging information. This means a comprehensive analysis is needed.

2. **Initial Scan and Identification of Key Components:** Quickly read through the code to get a high-level understanding. Look for class names, important methods, and included headers.

    * Class Name: `HttpServer` - This is the central piece.
    * Key Methods: `DoAcceptLoop`, `DoReadLoop`, `DoWriteLoop`, `Send...` methods, `AcceptWebSocket`, `SendOverWebSocket`, `Close`, `ParseHeaders`. These suggest the core responsibilities.
    * Included Headers:  Headers like `<string_view>`, `<utility>`, `<functional>`, `<logging>`, `<strings/...>`, `net/...`, `base/...`  provide clues about dependencies and functionalities. Notably, `net/server/...` suggests this is part of a network server implementation. The absence of direct JavaScript-related headers is also a clue.

3. **Deconstruct Functionality by Analyzing Key Methods:**  Go through the most important methods and describe their purpose.

    * **Constructor & `DoAcceptLoop`:** Focus on the server socket, the delegate, and the asynchronous acceptance of connections.
    * **`DoReadLoop` & `HandleReadResult`:**  Pay attention to how data is read from the socket, the parsing of HTTP requests (and WebSocket messages), and the interaction with the `delegate_`. Note the handling of different message types and the closing of connections.
    * **`DoWriteLoop` & `HandleWriteResult`:** Focus on sending data back to the client, the use of a write buffer, and the asynchronous nature of writing.
    * **`Send...` Methods:** Group these together. They demonstrate how different HTTP responses are constructed and sent.
    * **WebSocket Methods:**  Highlight the specific methods for handling WebSocket connections and messages.
    * **`Close`:**  Explain the connection closing process and the use of `PostTask` for delayed destruction.
    * **`ParseHeaders`:**  Recognize this as a crucial part of the HTTP server logic, but also note the warnings about its limitations.

4. **Analyze JavaScript Relationship:**  Based on the identified functionalities, determine the connection to JavaScript.

    * **Indirect Relationship:** The server handles HTTP and WebSockets, which are the communication protocols used by web browsers (running JavaScript). The server doesn't *execute* JavaScript but *serves* content and handles requests from it.
    * **Examples:** Provide concrete examples of how JavaScript running in a browser would interact with this server (making HTTP requests, establishing WebSocket connections).

5. **Logical Reasoning (Input/Output):**  Select a specific scenario to illustrate the server's behavior.

    * **Choose a Common Scenario:**  A simple GET request is a good starting point.
    * **Define the Input:**  Provide a well-formed HTTP GET request string.
    * **Trace the Execution (Mentally):**  Imagine the server receiving this request, parsing the headers, and calling the delegate.
    * **Define the Output:** Describe the expected response from the server.
    * **Highlight Key Steps:** Explain the process involved (parsing, delegate call, sending the response).

6. **Common Errors:** Think about typical mistakes users or programmers might make when interacting with or using this server.

    * **User Errors:**  Focus on how a user might trigger errors through their browser (e.g., incorrect URLs, failing to handle redirects if the server implements them, although this server seems basic).
    * **Programming Errors:** Concentrate on mistakes when *using* the `HttpServer` class (e.g., incorrect delegate implementation, forgetting to handle WebSocket messages, sending malformed responses).

7. **Debugging Information (User Journey):**  Describe how a user action leads to the execution of this code.

    * **Start with a User Action:**  A user typing a URL in the browser is a natural starting point.
    * **Trace the Network Request:** Explain the process of DNS resolution, TCP connection establishment, and the browser sending the HTTP request.
    * **Focus on the Server's Role:** Describe how the `HttpServer` receives the connection, reads data, parses the request, and calls the delegate.
    * **Connect the Dots:** Show how the user's action directly triggers the code within `http_server.cc`.

8. **Review and Refine:**  Read through the entire analysis to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. Ensure all parts of the original request are addressed. For example, double-check the limitations of the header parser are mentioned.

**Self-Correction/Refinement during the process:**

* **Initial Thought:** "This file implements an HTTP server."  **Refinement:**  Be more specific. It's a *component* of a network stack, handling connection management, request parsing, and response sending.
* **Initial Thought:** "JavaScript interacts with this server directly." **Refinement:** JavaScript interacts through HTTP and WebSockets. The server doesn't "know" about JavaScript code specifically.
* **Considering Input/Output:**  Initially, I might think of complex scenarios. **Refinement:** Start with a simple, representative example (like a basic GET request) to clearly illustrate the flow.
* **Thinking about Errors:** Initially focus on server-side bugs. **Refinement:** Also consider user-side actions that lead to errors the server needs to handle (like 404s).
* **Debugging Section:**  Make sure the steps are logical and easy to follow, starting from the user's perspective and moving towards the server-side code.

By following this structured approach and engaging in self-correction, a comprehensive and accurate analysis of the `http_server.cc` file can be generated.
好的，我们来分析一下 `net/server/http_server.cc` 这个 Chromium 网络栈的源代码文件。

**功能列举:**

该文件定义了 `HttpServer` 类，它是一个简单的、单线程的 HTTP/1.1 服务器的实现。其核心功能包括：

1. **监听连接:**  `HttpServer` 接收传入的 TCP 连接请求 (`DoAcceptLoop`, `OnAcceptCompleted`, `HandleAcceptResult`)。
2. **管理连接:**  维护一个活跃连接的列表 (`id_to_connection_`)，并为每个连接创建一个 `HttpConnection` 对象。
3. **读取请求:**  从客户端读取 HTTP 请求数据 (`DoReadLoop`, `OnReadCompleted`, `HandleReadResult`)。
4. **解析请求:**  解析 HTTP 请求头 (`ParseHeaders`)，提取方法、路径、协议和头部信息。
5. **处理 HTTP 请求:**  将解析后的 HTTP 请求信息传递给 `delegate_` (`OnHttpRequest`) 进行处理。
6. **WebSocket 支持:**
    * 升级到 WebSocket 连接 (`OnWebSocketRequest`)。
    * 接收和解析 WebSocket 消息 (`OnWebSocketMessage`)。
    * 发送 WebSocket 消息 (`SendOverWebSocket`)。
    * 接受 WebSocket 连接 (`AcceptWebSocket`)。
7. **发送响应:**
    * 发送各种 HTTP 响应，包括成功 (200)、未找到 (404)、服务器错误 (500) 等 (`Send`, `Send200`, `Send404`, `Send500`).
    * 支持发送原始数据 (`SendRaw`).
    * 允许设置响应头 (`HttpServerResponseInfo`).
8. **关闭连接:**  关闭指定的客户端连接 (`Close`)，并在下一个事件循环中销毁连接对象 (`DestroyClosedConnections`).
9. **设置缓冲区大小:**  允许为连接设置接收和发送缓冲区的大小 (`SetReceiveBufferSize`, `SetSendBufferSize`).
10. **获取本地地址:**  获取服务器监听的本地地址 (`GetLocalAddress`).

**与 JavaScript 的关系及举例说明:**

`HttpServer` 本身是用 C++ 编写的，并不直接包含 JavaScript 代码或执行 JavaScript。然而，它与 JavaScript 的功能有密切关系，因为它是一个 **JavaScript 运行环境（通常是浏览器或 Node.js）** 可以与之通信的服务器。

* **HTTP 请求:** JavaScript 代码可以使用 `fetch` API 或 `XMLHttpRequest` 对象向 `HttpServer` 发送 HTTP 请求。
    * **举例:**  如果 `HttpServer` 运行在本地的 8080 端口，一个 JavaScript 应用可以发送一个 GET 请求：
      ```javascript
      fetch('http://localhost:8080/data')
        .then(response => response.json())
        .then(data => console.log(data));
      ```
      在这个例子中，`HttpServer` 的 `DoReadLoop`、`HandleReadResult` 和 `ParseHeaders` 会负责接收和解析这个请求。`delegate_->OnHttpRequest` 会被调用，允许服务器端的 C++ 代码处理这个请求并生成响应。

* **WebSocket 连接:** JavaScript 代码可以使用 `WebSocket` API 与 `HttpServer` 建立持久的双向通信连接。
    * **举例:**
      ```javascript
      const websocket = new WebSocket('ws://localhost:8080/socket');

      websocket.onopen = () => {
        console.log('WebSocket connection opened');
        websocket.send('Hello from JavaScript!');
      };

      websocket.onmessage = (event) => {
        console.log('Message from server:', event.data);
      };

      websocket.onclose = () => {
        console.log('WebSocket connection closed');
      };
      ```
      当 JavaScript 代码创建 `WebSocket` 对象时，`HttpServer` 的 `HandleReadResult` 会检测到 "Upgrade: websocket" 头部，并调用 `delegate_->OnWebSocketRequest`。之后，JavaScript 可以通过 `websocket.send()` 发送消息，`HttpServer` 的 `DoReadLoop` 和 `HandleReadResult` 会接收并触发 `delegate_->OnWebSocketMessage`。服务器可以使用 `SendOverWebSocket` 方法向 JavaScript 发送消息。

**逻辑推理 (假设输入与输出):**

假设输入的是一个 HTTP GET 请求，请求路径为 `/index.html`，没有请求体。

**假设输入:**

```
GET /index.html HTTP/1.1
Host: localhost:8080
User-Agent: MyBrowser
Connection: keep-alive

```

**逻辑推理过程:**

1. **接收连接:** `HttpServer` 的 `DoAcceptLoop` 接受了一个新的 TCP 连接。
2. **读取数据:** `DoReadLoop` 从连接的 socket 读取数据，直到读取到完整的请求头。
3. **解析头部:** `ParseHeaders` 函数会被调用，解析输入的数据：
   * `info->method` 将被设置为 "GET"。
   * `info->path` 将被设置为 "/index.html"。
   * `info->headers` 将包含 "host: localhost:8080" 和 "user-agent: MyBrowser" 等键值对。
4. **调用委托:** `delegate_->OnHttpRequest` 会被调用，并将解析后的 `HttpServerRequestInfo` 对象传递给委托对象。

**假设输出:**

取决于 `delegate_` 的实现。如果委托对象实现了返回 `/index.html` 内容的逻辑，那么 `HttpServer` 可能会调用 `Send200` 方法发送以下响应：

```
HTTP/1.1 200 OK
Content-Length: [index.html 内容的长度]
Content-Type: text/html

[index.html 的内容]
```

如果委托对象没有找到 `/index.html` 对应的资源，它可能会指示 `HttpServer` 发送 404 响应：

```
HTTP/1.1 404 Not Found
Content-Length: 9
Content-Type: text/plain

Not Found
```

**用户或编程常见的使用错误:**

1. **用户错误 - 请求了不存在的资源:** 用户在浏览器中输入了错误的 URL，导致 `HttpServer` 接收到一个指向不存在资源的请求。`delegate_` 如果没有处理该路径的逻辑，通常会返回 404 错误。
   * **例子:** 用户在浏览器中输入 `http://localhost:8080/nonexistent.html`，但服务器上没有 `nonexistent.html` 文件。`HttpServer` 会调用 `delegate_->OnHttpRequest`，如果 `delegate_` 找不到该资源，它可能会调用 `Send404`。

2. **编程错误 - Delegate 未正确实现:** 开发者在使用 `HttpServer` 时，可能没有正确实现 `HttpServer::Delegate` 接口，导致请求无法被正确处理或响应。
   * **例子:** `delegate_` 的 `OnHttpRequest` 方法没有实现任何逻辑，或者抛出异常，或者没有调用 `Send...` 方法发送响应，导致客户端连接超时或收到意外的响应。

3. **编程错误 - WebSocket 处理不当:**  开发者可能在 `delegate_` 中没有正确处理 WebSocket 升级请求或消息，导致 WebSocket 连接失败或消息丢失。
   * **例子:**  `delegate_` 的 `OnWebSocketRequest` 方法没有调用 `AcceptWebSocket`，导致 WebSocket 握手失败。或者在 `OnWebSocketMessage` 中没有正确处理接收到的消息。

4. **编程错误 - 发送不符合 HTTP 规范的响应:**  开发者可能手动调用 `SendRaw` 发送数据，但没有构造符合 HTTP 规范的响应头，导致浏览器解析错误。
   * **例子:**  只发送了 HTML 内容，但没有发送 `Content-Type: text/html` 头部。

5. **编程错误 - 忘记处理连接关闭:** 开发者可能在 `delegate_` 中处理请求时，没有考虑到连接可能被客户端关闭的情况，导致资源泄露或其他问题。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览器中访问 `http://localhost:8080/index.html`。以下是可能发生的步骤：

1. **用户输入 URL 并按下 Enter 键:**  浏览器开始解析 URL。
2. **DNS 解析 (如果需要):** 如果 URL 中的主机名不是 `localhost` 或 IP 地址，浏览器会进行 DNS 查询以获取服务器的 IP 地址。
3. **建立 TCP 连接:** 浏览器与 `localhost:8080` 建立 TCP 连接。操作系统的网络栈会处理底层的 TCP 握手过程。
4. **`HttpServer` 监听连接:**  `HttpServer` 对象在创建时，其内部的 `ServerSocket` 开始监听 8080 端口。
5. **`DoAcceptLoop` 接受连接:** 当浏览器发起连接时，`HttpServer` 的 `DoAcceptLoop` 方法会调用 `server_socket_->Accept`，接受这个新的连接。
6. **创建 `HttpConnection`:** `HandleAcceptResult` 方法会被调用，创建一个新的 `HttpConnection` 对象来处理这个客户端连接。
7. **浏览器发送 HTTP 请求:** 浏览器构建 HTTP 请求报文，并通过建立的 TCP 连接发送到服务器。
8. **`DoReadLoop` 读取数据:** `HttpServer` 的 `DoReadLoop` 方法开始从连接的 socket 读取数据。
9. **`HandleReadResult` 处理读取结果:** 当有数据到达时，`OnReadCompleted` 被调用，然后调用 `HandleReadResult`。
10. **`ParseHeaders` 解析请求头:**  `HandleReadResult` 调用 `ParseHeaders` 函数来解析接收到的 HTTP 请求头。
11. **`delegate_->OnHttpRequest` 被调用:** 解析成功后，`HttpServer` 调用其 `delegate_` 的 `OnHttpRequest` 方法，将解析后的请求信息传递给委托对象。
12. **`delegate_` 处理请求并发送响应:** `delegate_` 的实现根据请求的路径 `/index.html` 执行相应的逻辑，并可能调用 `Send200` 等方法将响应数据发送回客户端。
13. **`DoWriteLoop` 发送响应:** `Send...` 方法会将响应数据添加到 `HttpConnection` 的写缓冲区，并调用 `DoWriteLoop` 开始将数据写回 socket。
14. **浏览器接收响应并渲染:** 浏览器接收到服务器发送的 HTTP 响应，解析响应头和响应体，并根据内容（例如 HTML）渲染页面。

**调试线索:**

如果在调试过程中发现问题，例如浏览器页面加载失败或显示错误，可以按照以下步骤进行排查：

1. **确认 `HttpServer` 是否正在运行并监听正确的端口 (8080)。**
2. **使用网络抓包工具 (如 Wireshark) 查看浏览器发送的请求和服务器返回的响应。**  可以查看请求头是否正确，响应状态码是否符合预期，以及响应体的内容。
3. **在 `HttpServer` 的关键方法 (如 `DoAcceptLoop`, `DoReadLoop`, `ParseHeaders`, `Send...`) 中添加日志输出，打印接收到的请求数据、解析后的头部信息、以及发送的响应数据。** 这可以帮助确定请求处理的哪个阶段出现了问题。
4. **检查 `HttpServer::Delegate` 的实现。**  确认 `OnHttpRequest` 等方法是否被正确调用，并且逻辑是否正确。在 `delegate_` 的实现中添加日志输出也是很有帮助的。
5. **如果涉及到 WebSocket，检查 WebSocket 的握手过程和消息传递过程。**  确认客户端和服务器端都遵循 WebSocket 协议。

希望以上分析能够帮助你理解 `net/server/http_server.cc` 文件的功能和它在 Chromium 网络栈中的作用。

Prompt: 
```
这是目录为net/server/http_server.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/server/http_server.h"

#include <string_view>
#include <utility>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/sys_byteorder.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "net/base/net_errors.h"
#include "net/server/http_connection.h"
#include "net/server/http_server_request_info.h"
#include "net/server/http_server_response_info.h"
#include "net/server/web_socket.h"
#include "net/server/web_socket_parse_result.h"
#include "net/socket/server_socket.h"
#include "net/socket/stream_socket.h"
#include "net/socket/tcp_server_socket.h"
#include "third_party/abseil-cpp/absl/cleanup/cleanup.h"

namespace net {

namespace {

constexpr NetworkTrafficAnnotationTag
    kHttpServerErrorResponseTrafficAnnotation =
        DefineNetworkTrafficAnnotation("http_server_error_response",
                                       R"(
      semantics {
        sender: "HTTP Server"
        description: "Error response from the built-in HTTP server."
        trigger: "Sending a request to the HTTP server that it can't handle."
        data: "A 500 error code."
        destination: OTHER
        destination_other: "Any destination the consumer selects."
      }
      policy {
        cookies_allowed: NO
        setting:
          "This request cannot be disabled in settings. However it will never "
          "be made unless user activates an HTTP server."
        policy_exception_justification:
          "Not implemented, not used if HTTP Server is not activated."
      })");

}  // namespace

HttpServer::HttpServer(std::unique_ptr<ServerSocket> server_socket,
                       HttpServer::Delegate* delegate)
    : server_socket_(std::move(server_socket)), delegate_(delegate) {
  DCHECK(server_socket_);
  // Start accepting connections in next run loop in case when delegate is not
  // ready to get callbacks.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&HttpServer::DoAcceptLoop,
                                weak_ptr_factory_.GetWeakPtr()));
}

HttpServer::~HttpServer() = default;

void HttpServer::AcceptWebSocket(
    int connection_id,
    const HttpServerRequestInfo& request,
    NetworkTrafficAnnotationTag traffic_annotation) {
  HttpConnection* connection = FindConnection(connection_id);
  if (connection == nullptr)
    return;
  DCHECK(connection->web_socket());
  connection->web_socket()->Accept(request, traffic_annotation);
}

void HttpServer::SendOverWebSocket(
    int connection_id,
    std::string_view data,
    NetworkTrafficAnnotationTag traffic_annotation) {
  HttpConnection* connection = FindConnection(connection_id);
  if (connection == nullptr)
    return;
  DCHECK(connection->web_socket());
  connection->web_socket()->Send(
      data, WebSocketFrameHeader::OpCodeEnum::kOpCodeText, traffic_annotation);
}

void HttpServer::SendRaw(int connection_id,
                         const std::string& data,
                         NetworkTrafficAnnotationTag traffic_annotation) {
  HttpConnection* connection = FindConnection(connection_id);
  if (connection == nullptr)
    return;

  bool writing_in_progress = !connection->write_buf()->IsEmpty();
  if (connection->write_buf()->Append(data) && !writing_in_progress)
    DoWriteLoop(connection, traffic_annotation);
}

void HttpServer::SendResponse(int connection_id,
                              const HttpServerResponseInfo& response,
                              NetworkTrafficAnnotationTag traffic_annotation) {
  SendRaw(connection_id, response.Serialize(), traffic_annotation);
}

void HttpServer::Send(int connection_id,
                      HttpStatusCode status_code,
                      const std::string& data,
                      const std::string& content_type,
                      NetworkTrafficAnnotationTag traffic_annotation) {
  HttpServerResponseInfo response(status_code);
  response.SetContentHeaders(data.size(), content_type);
  SendResponse(connection_id, response, traffic_annotation);
  SendRaw(connection_id, data, traffic_annotation);
}

void HttpServer::Send200(int connection_id,
                         const std::string& data,
                         const std::string& content_type,
                         NetworkTrafficAnnotationTag traffic_annotation) {
  Send(connection_id, HTTP_OK, data, content_type, traffic_annotation);
}

void HttpServer::Send404(int connection_id,
                         NetworkTrafficAnnotationTag traffic_annotation) {
  SendResponse(connection_id, HttpServerResponseInfo::CreateFor404(),
               traffic_annotation);
}

void HttpServer::Send500(int connection_id,
                         const std::string& message,
                         NetworkTrafficAnnotationTag traffic_annotation) {
  SendResponse(connection_id, HttpServerResponseInfo::CreateFor500(message),
               traffic_annotation);
}

void HttpServer::Close(int connection_id) {
  auto it = id_to_connection_.find(connection_id);
  if (it == id_to_connection_.end())
    return;

  closed_connections_.emplace_back(std::move(it->second));
  id_to_connection_.erase(it);
  delegate_->OnClose(connection_id);

  // The call stack might have callbacks which still have the pointer of
  // connection. Instead of referencing connection with ID all the time,
  // destroys the connection in next run loop to make sure any pending
  // callbacks in the call stack return. List of closed Connections is owned
  // by `this` in case `this` is destroyed before the task runs. Connections may
  // not outlive `this`.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&HttpServer::DestroyClosedConnections,
                                weak_ptr_factory_.GetWeakPtr()));
}

int HttpServer::GetLocalAddress(IPEndPoint* address) {
  return server_socket_->GetLocalAddress(address);
}

void HttpServer::SetReceiveBufferSize(int connection_id, int32_t size) {
  HttpConnection* connection = FindConnection(connection_id);
  if (connection)
    connection->read_buf()->set_max_buffer_size(size);
}

void HttpServer::SetSendBufferSize(int connection_id, int32_t size) {
  HttpConnection* connection = FindConnection(connection_id);
  if (connection)
    connection->write_buf()->set_max_buffer_size(size);
}

void HttpServer::DoAcceptLoop() {
  int rv;
  do {
    rv = server_socket_->Accept(&accepted_socket_,
                                base::BindOnce(&HttpServer::OnAcceptCompleted,
                                               weak_ptr_factory_.GetWeakPtr()));
    if (rv == ERR_IO_PENDING)
      return;
    rv = HandleAcceptResult(rv);
  } while (rv == OK);
}

void HttpServer::OnAcceptCompleted(int rv) {
  if (HandleAcceptResult(rv) == OK)
    DoAcceptLoop();
}

int HttpServer::HandleAcceptResult(int rv) {
  if (rv < 0) {
    LOG(ERROR) << "Accept error: rv=" << rv;
    return rv;
  }

  std::unique_ptr<HttpConnection> connection_ptr =
      std::make_unique<HttpConnection>(++last_id_, std::move(accepted_socket_));
  HttpConnection* connection = connection_ptr.get();
  id_to_connection_[connection->id()] = std::move(connection_ptr);
  delegate_->OnConnect(connection->id());
  if (!HasClosedConnection(connection))
    DoReadLoop(connection);
  return OK;
}

void HttpServer::DoReadLoop(HttpConnection* connection) {
  int rv;
  do {
    HttpConnection::ReadIOBuffer* read_buf = connection->read_buf();
    // Increases read buffer size if necessary.
    if (read_buf->RemainingCapacity() == 0 && !read_buf->IncreaseCapacity()) {
      Close(connection->id());
      return;
    }

    rv = connection->socket()->Read(
        read_buf, read_buf->RemainingCapacity(),
        base::BindOnce(&HttpServer::OnReadCompleted,
                       weak_ptr_factory_.GetWeakPtr(), connection->id()));
    if (rv == ERR_IO_PENDING)
      return;
    rv = HandleReadResult(connection, rv);
  } while (rv == OK);
}

void HttpServer::OnReadCompleted(int connection_id, int rv) {
  HttpConnection* connection = FindConnection(connection_id);
  if (!connection)  // It might be closed right before by write error.
    return;

  if (HandleReadResult(connection, rv) == OK)
    DoReadLoop(connection);
}

int HttpServer::HandleReadResult(HttpConnection* connection, int rv) {
  if (rv <= 0) {
    Close(connection->id());
    return rv == 0 ? ERR_CONNECTION_CLOSED : rv;
  }

  HttpConnection::ReadIOBuffer* read_buf = connection->read_buf();
  read_buf->DidRead(rv);

  // Handles http requests or websocket messages.
  while (read_buf->GetSize() > 0) {
    if (connection->web_socket()) {
      std::string message;
      WebSocketParseResult result = connection->web_socket()->Read(&message);
      if (result == WebSocketParseResult::FRAME_INCOMPLETE) {
        break;
      }

      if (result == WebSocketParseResult::FRAME_CLOSE ||
          result == WebSocketParseResult::FRAME_ERROR) {
        Close(connection->id());
        return ERR_CONNECTION_CLOSED;
      }
      if (result == WebSocketParseResult::FRAME_OK_FINAL) {
        delegate_->OnWebSocketMessage(connection->id(), std::move(message));
      }
      if (HasClosedConnection(connection))
        return ERR_CONNECTION_CLOSED;
      continue;
    }

    // The headers are reparsed from the beginning every time a packet is
    // received. This only really matters if something tries to upload a large
    // request body.
    HttpServerRequestInfo request;
    size_t pos = 0;
    if (!ParseHeaders(read_buf->StartOfBuffer(), read_buf->GetSize(),
                      &request, &pos)) {
      // An error has occured. Close the connection.
      Close(connection->id());
      return ERR_CONNECTION_CLOSED;
    } else if (!pos) {
      // If pos is 0, all the data in read_buf has been consumed, but the
      // headers have not been fully parsed yet. Continue parsing when more data
      // rolls in.
      break;
    }

    // Sets peer address if exists.
    connection->socket()->GetPeerAddress(&request.peer);

    if (request.HasHeaderValue("connection", "upgrade") &&
        request.HasHeaderValue("upgrade", "websocket")) {
      connection->SetWebSocket(std::make_unique<WebSocket>(this, connection));
      read_buf->DidConsume(pos);
      delegate_->OnWebSocketRequest(connection->id(), request);
      if (HasClosedConnection(connection))
        return ERR_CONNECTION_CLOSED;
      continue;
    }

    const char kContentLength[] = "content-length";
    if (request.headers.count(kContentLength) > 0) {
      size_t content_length = 0;
      const size_t kMaxBodySize = 100 << 20;
      if (!base::StringToSizeT(request.GetHeaderValue(kContentLength),
                               &content_length) ||
          content_length > kMaxBodySize) {
        SendResponse(connection->id(),
                     HttpServerResponseInfo::CreateFor500(
                         "request content-length too big or unknown."),
                     kHttpServerErrorResponseTrafficAnnotation);
        Close(connection->id());
        return ERR_CONNECTION_CLOSED;
      }

      if (read_buf->GetSize() - pos < content_length)
        break;  // Not enough data was received yet.
      request.data.assign(read_buf->StartOfBuffer() + pos, content_length);
      pos += content_length;
    }

    read_buf->DidConsume(pos);
    delegate_->OnHttpRequest(connection->id(), request);
    if (HasClosedConnection(connection))
      return ERR_CONNECTION_CLOSED;
  }

  return OK;
}

void HttpServer::DoWriteLoop(HttpConnection* connection,
                             NetworkTrafficAnnotationTag traffic_annotation) {
  int rv = OK;
  HttpConnection::QueuedWriteIOBuffer* write_buf = connection->write_buf();
  while (rv == OK && write_buf->GetSizeToWrite() > 0) {
    rv = connection->socket()->Write(
        write_buf, write_buf->GetSizeToWrite(),
        base::BindOnce(&HttpServer::OnWriteCompleted,
                       weak_ptr_factory_.GetWeakPtr(), connection->id(),
                       traffic_annotation),
        traffic_annotation);
    if (rv == ERR_IO_PENDING || rv == OK)
      return;
    rv = HandleWriteResult(connection, rv);
  }
}

void HttpServer::OnWriteCompleted(
    int connection_id,
    NetworkTrafficAnnotationTag traffic_annotation,
    int rv) {
  HttpConnection* connection = FindConnection(connection_id);
  if (!connection)  // It might be closed right before by read error.
    return;

  if (HandleWriteResult(connection, rv) == OK)
    DoWriteLoop(connection, traffic_annotation);
}

int HttpServer::HandleWriteResult(HttpConnection* connection, int rv) {
  if (rv < 0) {
    Close(connection->id());
    return rv;
  }

  connection->write_buf()->DidConsume(rv);
  return OK;
}

namespace {

//
// HTTP Request Parser
// This HTTP request parser uses a simple state machine to quickly parse
// through the headers.  The parser is not 100% complete, as it is designed
// for use in this simple test driver.
//
// Known issues:
//   - does not handle whitespace on first HTTP line correctly.  Expects
//     a single space between the method/url and url/protocol.

// Input character types.
enum HeaderParseInputs {
  INPUT_LWS,
  INPUT_CR,
  INPUT_LF,
  INPUT_COLON,
  INPUT_DEFAULT,
  MAX_INPUTS,
};

// Parser states.
enum HeaderParseStates {
  ST_METHOD,     // Receiving the method
  ST_URL,        // Receiving the URL
  ST_PROTO,      // Receiving the protocol
  ST_HEADER,     // Starting a Request Header
  ST_NAME,       // Receiving a request header name
  ST_SEPARATOR,  // Receiving the separator between header name and value
  ST_VALUE,      // Receiving a request header value
  ST_DONE,       // Parsing is complete and successful
  ST_ERR,        // Parsing encountered invalid syntax.
  MAX_STATES
};

// This state machine has a number of bugs, for example it considers
// "HTTP/1.1 200 OK\r\n"
// "Foo\r\n"
// to be a correctly terminated set of request headers. It also accepts "\n"
// between header lines but requires "\r\n" at the end of the headers.
// TODO(crbug): Consider using a different request parser. Maybe balsa headers
// from QUICHE, if it doesn't increase the binary size too much.

// State transition table
constexpr int kParserState[MAX_STATES][MAX_INPUTS] = {
    /* METHOD    */ {ST_URL, ST_ERR, ST_ERR, ST_ERR, ST_METHOD},
    /* URL       */ {ST_PROTO, ST_ERR, ST_ERR, ST_URL, ST_URL},
    /* PROTOCOL  */ {ST_ERR, ST_HEADER, ST_NAME, ST_ERR, ST_PROTO},
    /* HEADER    */ {ST_ERR, ST_ERR, ST_NAME, ST_ERR, ST_ERR},
    /* NAME      */ {ST_SEPARATOR, ST_DONE, ST_ERR, ST_VALUE, ST_NAME},
    /* SEPARATOR */ {ST_SEPARATOR, ST_ERR, ST_ERR, ST_VALUE, ST_ERR},
    /* VALUE     */ {ST_VALUE, ST_HEADER, ST_NAME, ST_VALUE, ST_VALUE},
    /* DONE      */ {ST_ERR, ST_ERR, ST_DONE, ST_ERR, ST_ERR},
    /* ERR       */ {ST_ERR, ST_ERR, ST_ERR, ST_ERR, ST_ERR}};

// Convert an input character to the parser's input token.
int CharToInputType(char ch) {
  switch (ch) {
    case ' ':
    case '\t':
      return INPUT_LWS;
    case '\r':
      return INPUT_CR;
    case '\n':
      return INPUT_LF;
    case ':':
      return INPUT_COLON;
  }
  return INPUT_DEFAULT;
}

}  // namespace

bool HttpServer::ParseHeaders(const char* data,
                              size_t data_len,
                              HttpServerRequestInfo* info,
                              size_t* ppos) {
  // Copy *ppos to avoid the compiler having to think about pointer aliasing.
  size_t pos = *ppos;
  // Make sure `pos` is always written back to `ppos` even if an extra return is
  // added to the function.
  absl::Cleanup set_ppos = [&pos, ppos]() { *ppos = pos; };
  int state = ST_METHOD;
  // Technically a base::span<const uint8_t> would be more correct, but using a
  // std::string_view makes integration with the rest of the code easier.
  const std::string_view data_view(data, data_len);
  size_t token_start = pos;
  std::string header_name;
  for (; pos < data_len; ++pos) {
    const char ch = data[pos];
    if (ch == '\0') {
      // Lots of code assumes strings don't contain null characters, so disallow
      // them to be on the safe side.
      return false;
    }
    const int input = CharToInputType(ch);
    const int next_state = kParserState[state][input];
    if (next_state == ST_ERR) {
      // No point in continuing.
      return false;
    }

    const bool transition = (next_state != state);
    if (transition) {
      const std::string_view token =
          data_view.substr(token_start, pos - token_start);
      token_start = pos + 1;  // Skip the whitespace or separator.
      // Do any actions based on state transitions.
      switch (state) {
        case ST_METHOD:
          info->method = std::string(token);
          break;
        case ST_URL:
          info->path = std::string(token);
          break;
        case ST_PROTO:
          if (token != "HTTP/1.1") {
            LOG(ERROR) << "Cannot handle request with protocol: " << token;
            return false;
          }
          break;
        case ST_NAME:
          header_name = base::ToLowerASCII(token);
          break;
        case ST_VALUE: {
          std::string_view header_value =
              base::TrimWhitespaceASCII(token, base::TRIM_LEADING);
          // See the second paragraph ("A sender MUST NOT generate multiple
          // header fields...") of tools.ietf.org/html/rfc7230#section-3.2.2.
          auto [it, inserted] = info->headers.try_emplace(
              std::move(header_name), std::move(header_value));
          header_name.clear();  // Avoid use-after-move lint error.
          if (!inserted) {
            // Since the insertion did not happen, try_emplace() did not move
            // the contents of `header_value` and we can still use it.
            std::string& value = it->second;
            value.reserve(value.size() + 1 + header_value.size());
            value.push_back(',');
            value.append(header_value);
          }
          break;
        }
      }
      state = next_state;
    } else {
      // Do any actions based on current state
      if (state == ST_DONE) {
        ++pos;  // Point to the first byte of the body.
        return true;
      }
    }
  }
  // No more characters, but we haven't finished parsing yet. Signal this to
  // the caller by setting |pos| to zero.
  pos = 0;
  return true;
}

HttpConnection* HttpServer::FindConnection(int connection_id) {
  auto it = id_to_connection_.find(connection_id);
  if (it == id_to_connection_.end())
    return nullptr;
  return it->second.get();
}

// This is called after any delegate callbacks are called to check if Close()
// has been called during callback processing. Using the pointer of connection,
// |connection| is safe here because Close() deletes the connection in next run
// loop.
bool HttpServer::HasClosedConnection(HttpConnection* connection) {
  return FindConnection(connection->id()) != connection;
}

void HttpServer::DestroyClosedConnections() {
  closed_connections_.clear();
}

}  // namespace net

"""

```
Response:
Let's break down the thought process for analyzing the `tcp_socket.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of the `TCPSocket` class in the provided code, its relationship with web technologies, logical reasoning with input/output examples, common usage errors, and debugging information.

2. **Initial Code Scan and Class Identification:** The first step is to read through the code and identify the main class: `TCPSocket`. Recognize the `#include` statements to understand the dependencies (networking, streams, bindings, etc.). This gives a high-level idea of what the class interacts with.

3. **Core Functionalities - Methods are Key:** The primary way to understand what a class *does* is by examining its methods. Go through each public and significant private method:

    * **`Create` (static):**  Indicates how to create an instance of the class. Notice the parameters (`remoteAddress`, `remotePort`, `options`) suggesting it's for initiating a connection. The `CheckContextAndPermissions` call hints at security considerations.

    * **`CreateFromAcceptedConnection` (static):**  This suggests the class can also represent an *incoming* connection, not just an outgoing one. The parameters (`tcp_socket`, `socket_observer`, etc.) point towards handling an already established connection.

    * **Constructor (`TCPSocket`) and Destructor (`~TCPSocket`):**  Initialization and cleanup. The constructor sets up internal members like `tcp_socket_`, `socket_observer_`, and the `opened_` promise.

    * **`opened`:** Returns a Promise. Promises usually represent asynchronous operations. The type `TCPSocketOpenInfo` suggests information about the opened socket.

    * **`close`:**  Closes the socket. The checks for `kOpening` state and locked streams are important for understanding usage constraints. The cancellation and aborting of streams are part of the closing process.

    * **`Open`:** The core method for establishing an outgoing connection. It calls `CreateTCPSocketOptions` and then interacts with a service (`GetServiceRemote()->OpenTCPSocket`).

    * **`OnTCPSocketOpened`:**  A callback function. Callbacks are typical in asynchronous operations. It handles the result of the connection attempt (success or failure), updates the state, and resolves/rejects the `opened_` promise.

    * **`FinishOpenOrAccept`:**  Common logic for both outgoing and accepted connections. It sets up the streams and resolves the `opened_` promise.

    * **`OnSocketConnectionError`:** Handles errors *after* the connection is established.

    * **`OnServiceConnectionError`:** Handles errors when the underlying service connection fails.

    * **`ReleaseResources`:** Cleans up resources, especially important in C++.

    * **`OnReadError`, `OnWriteError`:** Handles errors during data transfer.

    * **`Trace`:**  For debugging and memory management.

    * **`HasPendingActivity`:**  Indicates if there's ongoing write activity.

    * **`ContextDestroyed`:**  Handles the destruction of the associated context.

    * **`OnBothStreamsClosed`:**  A callback when both the readable and writable streams are closed. It updates the socket's state and the `closed` promise.

4. **Identify Relationships with Web Technologies:**

    * **JavaScript:** The presence of `ScriptState`, `ScriptPromise`, `IDLUndefined`, and the use of `ExceptionState` strongly indicate interaction with JavaScript. The `Create` method being called from JavaScript is a key connection.

    * **HTML:** While the code itself doesn't directly manipulate HTML, the fact that it's part of the Blink renderer suggests that JavaScript running in an HTML page would be the initiator of socket creation.

    * **CSS:** No direct relationship. TCP sockets are about network communication, not visual presentation.

5. **Logical Reasoning (Input/Output):**

    * **Successful Connection:** Consider the happy path. What inputs to `Create` lead to a successful connection and what outputs result?
    * **Failed Connection:** Think about scenarios where the connection fails (incorrect address, port, network issues). How does the code handle these failures?

6. **Common Usage Errors:** Look for error checks and potential pitfalls in how the API is used:

    * Invalid options (buffer sizes, keep-alive).
    * Calling `close` on a socket that's still opening.
    * Calling `close` when streams are locked.

7. **Debugging Information (User Operations):**  Trace the steps a user might take to trigger the code:

    * User opens a webpage.
    * JavaScript on the page uses the Direct Sockets API (e.g., `new TCPSocket(...)`).
    * This JavaScript call eventually leads to the C++ `TCPSocket::Create` method being invoked.

8. **Structure and Refine:** Organize the findings into clear categories (Functionalities, Relationship to Web Technologies, etc.). Use bullet points and code snippets to illustrate the points. Ensure the language is clear and concise. For example, instead of just saying "handles errors," specify *what kind* of errors.

9. **Review and Iterate:** Read through the generated explanation. Does it accurately reflect the code? Are there any missing details or areas that need clarification?  For instance, initially, I might have focused too much on individual method details. The review process would help to synthesize these details into a higher-level understanding of the class's purpose and workflow. Realize that the `opened_` and `closed_` properties as promises are critical for the asynchronous nature of network operations.

This iterative process of reading, analyzing, connecting, and refining is crucial for understanding complex code like this.
好的，让我们详细分析一下 `blink/renderer/modules/direct_sockets/tcp_socket.cc` 文件的功能。

**文件功能概览**

`tcp_socket.cc` 文件定义了 Chromium Blink 引擎中用于创建和管理 TCP 套接字的 `TCPSocket` 类。 这个类允许网页上的 JavaScript 代码通过 TCP 协议与服务器建立网络连接，并进行数据的发送和接收。

**核心功能点：**

1. **创建 TCP 连接:**
   - 提供了静态方法 `Create`，用于从 JavaScript 代码中创建 `TCPSocket` 实例。
   - 接收远程服务器的地址 (`remoteAddress`)、端口 (`remotePort`) 以及可选的套接字选项 (`TCPSocketOptions`) 作为参数。
   - 内部通过 Mojo IPC 与浏览器进程中的网络服务进行通信，请求创建一个 TCP 连接。

2. **处理连接状态:**
   - 维护套接字的状态（例如：`kOpening`，`kOpen`，`kClosed`，`kAborted`）。
   - 使用 Promise (`opened_`) 来通知 JavaScript 代码连接是否成功建立。
   - 使用 Promise (`closed_`) 来通知 JavaScript 代码连接已关闭。

3. **数据传输:**
   - 使用 `ReadableStream` 和 `WritableStream` 对象来提供数据读取和写入的接口，这与 WHATWG Streams API 兼容，方便 JavaScript 使用。
   - 内部通过 Mojo DataPipe 来进行实际的数据传输。

4. **套接字选项配置:**
   - 支持配置多种 TCP 套接字选项，例如：
     - `noDelay`: 是否禁用 Nagle 算法。
     - `keepAliveDelay`:  保持连接活跃的探测间隔。
     - `sendBufferSize`: 发送缓冲区大小。
     - `receiveBufferSize`: 接收缓冲区大小。
     - `dnsQueryType`:  DNS 查询类型 (IPv4 或 IPv6)。

5. **处理连接关闭:**
   - 提供 `close` 方法，允许 JavaScript 代码主动关闭连接。
   - 内部会取消相关的流，并断开与网络服务的连接。

6. **处理错误:**
   - 监听来自网络服务的连接错误和数据传输错误。
   - 将错误信息转换为 `DOMException` 对象，并通知 JavaScript 代码。

7. **从已接受的连接创建:**
   - 提供了静态方法 `CreateFromAcceptedConnection`，用于处理通过 `TCPServerSocket` 接受的传入连接。

**与 JavaScript, HTML, CSS 的关系：**

`TCPSocket` 类是 JavaScript API 的一部分，它使得网页上的 JavaScript 代码能够进行底层的网络通信。

* **JavaScript:**
   - **创建套接字:** JavaScript 代码可以使用 `new TCPSocket(remoteAddress, remotePort, options)` 来创建 TCP 套接字实例。
     ```javascript
     let socket = new TCPSocket('example.com', 8080, { noDelay: true });
     socket.opened.then(info => {
       console.log('Socket opened:', info);
       // 开始读写数据
     }).catch(error => {
       console.error('Failed to open socket:', error);
     });
     ```
   - **发送数据:**  通过 `writable` 属性获取 `WritableStream`，并使用其 `getWriter()` 方法写入数据。
     ```javascript
     let writer = socket.writable.getWriter();
     writer.write(new TextEncoder().encode('Hello, server!'));
     writer.close();
     ```
   - **接收数据:** 通过 `readable` 属性获取 `ReadableStream`，并使用其 `getReader()` 方法读取数据。
     ```javascript
     let reader = socket.readable.getReader();
     while (true) {
       const { done, value } = await reader.read();
       if (done) {
         break;
       }
       console.log('Received:', new TextDecoder().decode(value));
     }
     reader.releaseLock();
     ```
   - **关闭连接:** 调用 `socket.close()` 方法关闭连接。
     ```javascript
     socket.close();
     ```
* **HTML:**
   - HTML 文件中通过 `<script>` 标签引入的 JavaScript 代码可以使用 `TCPSocket` API。

* **CSS:**
   - CSS 与 `TCPSocket` 的功能没有直接关系。CSS 负责网页的样式和布局，而 `TCPSocket` 负责网络通信。

**逻辑推理、假设输入与输出：**

**场景：尝试连接到不存在的服务器**

* **假设输入 (JavaScript):**
  ```javascript
  let socket = new TCPSocket('nonexistent.example.com', 12345);
  socket.opened.catch(error => {
    console.error('Connection failed:', error);
  });
  ```

* **内部逻辑推理 (C++):**
   1. `TCPSocket::Create` 被调用，创建一个 `TCPSocket` 对象。
   2. `Open` 方法调用 `GetServiceRemote()->OpenTCPSocket` 向网络服务发送连接请求。
   3. 网络服务尝试解析 `nonexistent.example.com` 并建立连接。
   4. 由于服务器不存在或端口未开放，连接尝试失败。
   5. 网络服务通过 Mojo IPC 通知 Blink 进程连接失败，返回一个负数的 `net_error` 代码（例如 `net::ERR_NAME_NOT_RESOLVED` 或 `net::ERR_CONNECTION_REFUSED`）。
   6. `TCPSocket::OnTCPSocketOpened` 接收到错误码。
   7. `base::UmaHistogramSparse` 记录网络错误。
   8. 创建一个 `DOMException` 对象，描述连接失败的原因。
   9. `opened_->Reject(exception)` 拒绝 `opened` Promise。
   10. `GetClosedProperty().Reject(...)` 也会拒绝 `closed` Promise，因为连接从未成功建立。
   11. 套接字状态设置为 `kAborted`。

* **预期输出 (JavaScript):**
  ```
  Connection failed: DOMException: Failed to open a socket.
  ```
  （具体的错误消息可能因浏览器和网络环境而异）

**用户或编程常见的使用错误：**

1. **未处理 `opened` Promise 的 rejection:**
   - **错误:**  JavaScript 代码创建了 `TCPSocket`，但没有使用 `.then()` 或 `.catch()` 来处理 `opened` Promise 的结果。如果连接失败，错误将不会被捕获，可能导致程序行为异常。
   - **示例:**
     ```javascript
     let socket = new TCPSocket('invalid-address', 9999); // 缺少错误处理
     ```

2. **在 `opened` Promise resolve 之前尝试发送数据:**
   - **错误:**  在连接成功建立之前，`socket.writable` 可能尚未就绪。尝试在其上写入数据可能会导致错误。
   - **示例:**
     ```javascript
     let socket = new TCPSocket('example.com', 80);
     socket.writable.getWriter().write(new TextEncoder().encode('立即发送')); // 可能过早
     socket.opened.then(() => {
       console.log('连接已建立');
     });
     ```

3. **忘记关闭套接字:**
   - **错误:**  如果 `TCPSocket` 对象不再需要，但没有调用 `close()` 方法，可能会导致资源泄漏。
   - **示例:**
     ```javascript
     function connectAndDoSomething() {
       let socket = new TCPSocket('example.com', 80);
       socket.opened.then(() => {
         // ... 进行一些操作 ...
         // 忘记调用 socket.close()
       });
     }
     connectAndDoSomething();
     ```

4. **在流被锁定的时候调用 `close`:**
   - **错误:** 如果 `ReadableStream` 或 `WritableStream` 已经被获取了 reader 或 writer 并处于活动状态（锁定），则调用 `close` 会抛出 `InvalidStateError`。
   - **示例:**
     ```javascript
     let socket = new TCPSocket('example.com', 80);
     socket.opened.then(async () => {
       const reader = socket.readable.getReader();
       // ... 正在读取数据 ...
       socket.close(); // 错误：流已锁定
     });
     ```

5. **提供无效的套接字选项值:**
   - **错误:**  例如，`sendBufferSize` 或 `receiveBufferSize` 设置为 0，或者 `keepAliveDelay` 小于 1000 毫秒。
   - **示例:**
     ```javascript
     let socket = new TCPSocket('example.com', 80, { sendBufferSize: 0 }); // 错误
     ```
   - 在 C++ 代码中，`CheckSendReceiveBufferSize` 函数会检查这些错误并抛出 `TypeError`。

**用户操作如何一步步到达这里，作为调试线索：**

假设用户在浏览器中访问了一个网页，该网页使用了 Direct Sockets API 来建立 TCP 连接：

1. **用户打开网页:** 用户在浏览器地址栏输入网址或点击链接。
2. **浏览器加载 HTML:** 浏览器解析 HTML 文档。
3. **执行 JavaScript 代码:**  HTML 中包含的 `<script>` 标签中的 JavaScript 代码开始执行。
4. **创建 TCPSocket 对象:**  JavaScript 代码中调用了 `new TCPSocket('example.com', 8080, options)`。
5. **调用 `TCPSocket::Create` (C++):**  Blink 引擎接收到 JavaScript 的请求，调用 `tcp_socket.cc` 中的静态方法 `TCPSocket::Create`。
6. **权限检查:** `Socket::CheckContextAndPermissions` 检查当前上下文是否允许创建套接字。
7. **创建 `TCPSocket` 实例:**  在 C++ 中创建 `TCPSocket` 对象。
8. **调用 `TCPSocket::Open` (C++):** `Create` 方法内部调用 `Open` 方法来启动连接过程。
9. **创建套接字选项:** `CreateTCPSocketOptions` 函数根据 JavaScript 传递的 `options` 创建 `DirectTCPSocketOptionsPtr` 对象。
10. **Mojo IPC 调用:** `GetServiceRemote()->OpenTCPSocket` 通过 Mojo IPC 向浏览器进程的网络服务发送请求，携带远程地址、端口和套接字选项。
11. **网络服务处理:** 浏览器进程的网络服务接收到请求，尝试建立 TCP 连接。
12. **连接结果返回:** 网络服务将连接结果（成功或失败，以及相关的 `net_error` 代码）通过 Mojo IPC 返回给 Blink 进程。
13. **调用 `TCPSocket::OnTCPSocketOpened` (C++):** Blink 进程接收到结果，调用 `OnTCPSocketOpened` 回调函数。
14. **处理连接结果:**
   - **成功:** `FinishOpenOrAccept` 被调用，创建 `ReadableStream` 和 `WritableStream`，并 resolve `opened_` Promise。
   - **失败:**  记录错误，创建 `DOMException`，并 reject `opened_` 和 `closed_` Promise。
15. **JavaScript 接收结果:** JavaScript 代码中 `opened` Promise 的 `.then()` 或 `.catch()` 方法被调用，处理连接结果。

**调试线索：**

在调试过程中，可以通过以下方式追踪到 `tcp_socket.cc`：

* **JavaScript 断点:** 在 JavaScript 代码中设置断点，查看 `TCPSocket` 对象的创建和操作。
* **C++ 断点:** 在 `tcp_socket.cc` 中的关键方法（如 `Create`, `Open`, `OnTCPSocketOpened`）设置断点，查看 C++ 层的执行流程和变量值。
* **Mojo 日志:** 查看 Mojo IPC 的通信日志，了解 Blink 进程和网络服务之间的交互。
* **网络日志:**  查看浏览器 Network 面板中的请求，虽然 Direct Sockets 不会显示为传统的 HTTP 请求，但可以观察到是否有其他网络活动。
* **`chrome://net-internals/#sockets`:**  Chrome 提供的网络内部工具，可以查看底层的 socket 连接状态。

通过以上分析，我们可以清晰地理解 `blink/renderer/modules/direct_sockets/tcp_socket.cc` 文件的功能以及它在 Chromium Blink 引擎中的作用。它充当了 JavaScript Direct Sockets API 和底层网络实现之间的桥梁。

Prompt: 
```
这是目录为blink/renderer/modules/direct_sockets/tcp_socket.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/direct_sockets/tcp_socket.h"

#include "base/barrier_callback.h"
#include "base/metrics/histogram_functions.h"
#include "net/base/net_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_socket_dns_query_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_tcp_socket_open_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_tcp_socket_options.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/modules/direct_sockets/stream_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

constexpr char kTCPNetworkFailuresHistogramName[] =
    "DirectSockets.TCPNetworkFailures";

bool CheckSendReceiveBufferSize(const TCPSocketOptions* options,
                                ExceptionState& exception_state) {
  if (options->hasSendBufferSize() && options->sendBufferSize() == 0) {
    exception_state.ThrowTypeError("sendBufferSize must be greater than zero.");
    return false;
  }
  if (options->hasReceiveBufferSize() && options->receiveBufferSize() == 0) {
    exception_state.ThrowTypeError(
        "receiverBufferSize must be greater than zero.");
    return false;
  }
  return true;
}

mojom::blink::DirectTCPSocketOptionsPtr CreateTCPSocketOptions(
    const String& remote_address,
    const uint16_t remote_port,
    const TCPSocketOptions* options,
    ExceptionState& exception_state) {
  auto socket_options = mojom::blink::DirectTCPSocketOptions::New();

  socket_options->remote_addr =
      net::HostPortPair(remote_address.Utf8(), remote_port);

  if (!CheckSendReceiveBufferSize(options, exception_state)) {
    return {};
  }

  if (options->hasKeepAliveDelay() &&
      base::Milliseconds(options->keepAliveDelay()) < base::Seconds(1)) {
    exception_state.ThrowTypeError(
        "keepAliveDelay must be no less than 1,000 milliseconds.");
    return {};
  }

  // noDelay has a default value specified, therefore it's safe to call
  // ->noDelay() without checking ->hasNoDelay() first.
  socket_options->no_delay = options->noDelay();

  socket_options->keep_alive_options =
      network::mojom::blink::TCPKeepAliveOptions::New(
          /*enable=*/options->hasKeepAliveDelay() ? true : false,
          /*delay=*/options->hasKeepAliveDelay()
              ? base::Milliseconds(options->keepAliveDelay()).InSeconds()
              : 0);

  if (options->hasSendBufferSize()) {
    socket_options->send_buffer_size = options->sendBufferSize();
  }
  if (options->hasReceiveBufferSize()) {
    socket_options->receive_buffer_size = options->receiveBufferSize();
  }

  if (options->hasDnsQueryType()) {
    switch (options->dnsQueryType().AsEnum()) {
      case V8SocketDnsQueryType::Enum::kIpv4:
        socket_options->dns_query_type = net::DnsQueryType::A;
        break;
      case V8SocketDnsQueryType::Enum::kIpv6:
        socket_options->dns_query_type = net::DnsQueryType::AAAA;
        break;
    }
  }

  return socket_options;
}

}  // namespace

// static
TCPSocket* TCPSocket::Create(ScriptState* script_state,
                             const String& remoteAddress,
                             const uint16_t remotePort,
                             const TCPSocketOptions* options,
                             ExceptionState& exception_state) {
  if (!Socket::CheckContextAndPermissions(script_state, exception_state)) {
    return nullptr;
  }

  auto* socket = MakeGarbageCollected<TCPSocket>(script_state);
  if (!socket->Open(remoteAddress, remotePort, options, exception_state)) {
    return nullptr;
  }
  return socket;
}

// static
TCPSocket* TCPSocket::CreateFromAcceptedConnection(
    ScriptState* script_state,
    mojo::PendingRemote<network::mojom::blink::TCPConnectedSocket> tcp_socket,
    mojo::PendingReceiver<network::mojom::blink::SocketObserver>
        socket_observer,
    const net::IPEndPoint& peer_addr,
    mojo::ScopedDataPipeConsumerHandle receive_stream,
    mojo::ScopedDataPipeProducerHandle send_stream) {
  auto* socket = MakeGarbageCollected<TCPSocket>(script_state);
  // TODO(crbug.com/1417998): support local_addr for accepted sockets.
  socket->FinishOpenOrAccept(std::move(tcp_socket), std::move(socket_observer),
                             peer_addr, /*local_addr=*/std::nullopt,
                             std::move(receive_stream), std::move(send_stream));
  DCHECK_EQ(socket->GetState(), State::kOpen);
  return socket;
}

TCPSocket::TCPSocket(ScriptState* script_state)
    : Socket(script_state),
      ActiveScriptWrappable<TCPSocket>({}),
      tcp_socket_{GetExecutionContext()},
      socket_observer_{this, GetExecutionContext()},
      opened_(MakeGarbageCollected<
              ScriptPromiseProperty<TCPSocketOpenInfo, DOMException>>(
          GetExecutionContext())) {}

TCPSocket::~TCPSocket() = default;

ScriptPromise<TCPSocketOpenInfo> TCPSocket::opened(
    ScriptState* script_state) const {
  return opened_->Promise(script_state->World());
}

ScriptPromise<IDLUndefined> TCPSocket::close(ScriptState*,
                                             ExceptionState& exception_state) {
  if (GetState() == State::kOpening) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Socket is not properly initialized.");
    return EmptyPromise();
  }

  auto* script_state = GetScriptState();
  if (GetState() != State::kOpen) {
    return closed(script_state);
  }

  if (readable_stream_wrapper_->Locked() ||
      writable_stream_wrapper_->Locked()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Close called on locked streams.");
    return EmptyPromise();
  }

  auto* reason = MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kAbortError, "Stream closed.");

  auto readable_cancel = readable_stream_wrapper_->Readable()->cancel(
      script_state, ScriptValue::From(script_state, reason),
      ASSERT_NO_EXCEPTION);
  readable_cancel.MarkAsHandled();

  auto writable_abort = writable_stream_wrapper_->Writable()->abort(
      script_state, ScriptValue::From(script_state, reason),
      ASSERT_NO_EXCEPTION);
  writable_abort.MarkAsHandled();

  return closed(script_state);
}

bool TCPSocket::Open(const String& remote_address,
                     const uint16_t remote_port,
                     const TCPSocketOptions* options,
                     ExceptionState& exception_state) {
  auto open_tcp_socket_options = CreateTCPSocketOptions(
      remote_address, remote_port, options, exception_state);

  if (exception_state.HadException()) {
    return false;
  }

  mojo::PendingReceiver<network::mojom::blink::TCPConnectedSocket>
      socket_receiver;
  mojo::PendingRemote<network::mojom::blink::SocketObserver> observer_remote;

  auto callback =
      WTF::BindOnce(&TCPSocket::OnTCPSocketOpened, WrapPersistent(this),
                    socket_receiver.InitWithNewPipeAndPassRemote(),
                    observer_remote.InitWithNewPipeAndPassReceiver());
  GetServiceRemote()->OpenTCPSocket(
      std::move(open_tcp_socket_options), std::move(socket_receiver),
      std::move(observer_remote), std::move(callback));
  return true;
}

void TCPSocket::OnTCPSocketOpened(
    mojo::PendingRemote<network::mojom::blink::TCPConnectedSocket> tcp_socket,
    mojo::PendingReceiver<network::mojom::blink::SocketObserver>
        socket_observer,
    int32_t result,
    const std::optional<net::IPEndPoint>& local_addr,
    const std::optional<net::IPEndPoint>& peer_addr,
    mojo::ScopedDataPipeConsumerHandle receive_stream,
    mojo::ScopedDataPipeProducerHandle send_stream) {
  if (result == net::OK) {
    DCHECK(peer_addr);
    FinishOpenOrAccept(std::move(tcp_socket), std::move(socket_observer),
                       *peer_addr, local_addr, std::move(receive_stream),
                       std::move(send_stream));
  } else {
    // Error codes are negative.
    base::UmaHistogramSparse(kTCPNetworkFailuresHistogramName, -result);
    ReleaseResources();

    ScriptState::Scope scope(GetScriptState());
    auto* exception = CreateDOMExceptionFromNetErrorCode(result);
    opened_->Reject(exception);
    GetClosedProperty().Reject(ScriptValue(GetScriptState()->GetIsolate(),
                                           exception->ToV8(GetScriptState())));

    SetState(State::kAborted);
  }

  DCHECK_NE(GetState(), State::kOpening);
}

void TCPSocket::FinishOpenOrAccept(
    mojo::PendingRemote<network::mojom::blink::TCPConnectedSocket> tcp_socket,
    mojo::PendingReceiver<network::mojom::blink::SocketObserver>
        socket_observer,
    const net::IPEndPoint& peer_addr,
    const std::optional<net::IPEndPoint>& local_addr,
    mojo::ScopedDataPipeConsumerHandle receive_stream,
    mojo::ScopedDataPipeProducerHandle send_stream) {
  tcp_socket_.Bind(std::move(tcp_socket),
                   GetExecutionContext()->GetTaskRunner(TaskType::kNetworking));
  socket_observer_.Bind(
      std::move(socket_observer),
      GetExecutionContext()->GetTaskRunner(TaskType::kNetworking));
  socket_observer_.set_disconnect_handler(
      WTF::BindOnce(&TCPSocket::OnSocketConnectionError, WrapPersistent(this)));

  auto close_callback = base::BarrierCallback<ScriptValue>(
      /*num_callbacks=*/2,
      WTF::BindOnce(&TCPSocket::OnBothStreamsClosed, WrapWeakPersistent(this)));

  readable_stream_wrapper_ = MakeGarbageCollected<TCPReadableStreamWrapper>(
      GetScriptState(), close_callback, std::move(receive_stream));
  writable_stream_wrapper_ = MakeGarbageCollected<TCPWritableStreamWrapper>(
      GetScriptState(), close_callback, std::move(send_stream));

  auto* open_info = TCPSocketOpenInfo::Create();

  open_info->setReadable(readable_stream_wrapper_->Readable());
  open_info->setWritable(writable_stream_wrapper_->Writable());

  open_info->setRemoteAddress(String{peer_addr.ToStringWithoutPort()});
  open_info->setRemotePort(peer_addr.port());

  if (local_addr) {
    open_info->setLocalAddress(String{local_addr->ToStringWithoutPort()});
    open_info->setLocalPort(local_addr->port());
  }

  opened_->Resolve(open_info);
  SetState(State::kOpen);
}

void TCPSocket::OnSocketConnectionError() {
  DCHECK_EQ(GetState(), State::kOpen);
  readable_stream_wrapper_->ErrorStream(net::ERR_CONNECTION_ABORTED);
  writable_stream_wrapper_->ErrorStream(net::ERR_CONNECTION_ABORTED);
}

void TCPSocket::OnServiceConnectionError() {
  if (GetState() == State::kOpening) {
    OnTCPSocketOpened(mojo::NullRemote(), mojo::NullReceiver(),
                      net::ERR_CONTEXT_SHUT_DOWN, std::nullopt, std::nullopt,
                      mojo::ScopedDataPipeConsumerHandle(),
                      mojo::ScopedDataPipeProducerHandle());
  }
}

void TCPSocket::ReleaseResources() {
  ResetServiceAndFeatureHandle();
  tcp_socket_.reset();
  socket_observer_.reset();
}

void TCPSocket::OnReadError(int32_t net_error) {
  // |net_error| equal to net::OK means EOF -- in this case the
  // stream is not really errored but rather closed gracefully.
  DCHECK_EQ(GetState(), State::kOpen);
  readable_stream_wrapper_->ErrorStream(net_error);
}

void TCPSocket::OnWriteError(int32_t net_error) {
  DCHECK_EQ(GetState(), State::kOpen);
  writable_stream_wrapper_->ErrorStream(net_error);
}

void TCPSocket::Trace(Visitor* visitor) const {
  visitor->Trace(tcp_socket_);
  visitor->Trace(socket_observer_);
  visitor->Trace(opened_);
  visitor->Trace(readable_stream_wrapper_);
  visitor->Trace(writable_stream_wrapper_);

  ScriptWrappable::Trace(visitor);
  Socket::Trace(visitor);
  ActiveScriptWrappable::Trace(visitor);
}

bool TCPSocket::HasPendingActivity() const {
  if (GetState() != State::kOpen) {
    return false;
  }
  return writable_stream_wrapper_->HasPendingWrite();
}

void TCPSocket::ContextDestroyed() {
  ReleaseResources();
}

void TCPSocket::OnBothStreamsClosed(std::vector<ScriptValue> args) {
  DCHECK_EQ(GetState(), State::kOpen);
  DCHECK_EQ(args.size(), 2U);

  // Finds first actual exception and rejects |closed| with it.
  // If neither stream was errored, resolves |closed|.
  if (auto it = base::ranges::find_if_not(args, &ScriptValue::IsEmpty);
      it != args.end()) {
    GetClosedProperty().Reject(*it);
    SetState(State::kAborted);
  } else {
    GetClosedProperty().ResolveWithUndefined();
    SetState(State::kClosed);
  }
  ReleaseResources();

  DCHECK_NE(GetState(), State::kOpen);
}

}  // namespace blink

"""

```
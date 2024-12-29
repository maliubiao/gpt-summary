Response:
Let's break down the thought process for analyzing this `tcp_server_socket.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of this specific Chromium Blink file, relate it to web technologies (JavaScript, HTML, CSS), provide logical reasoning with examples, highlight potential user/programming errors, and explain how a user's actions might lead to this code being executed.

2. **Initial Scan for Keywords and Structure:**  First, I'd quickly scan the code for important keywords and structural elements:
    * `#include`:  This tells us about dependencies. Look for things like `v8`, `streams`, `mojom`, `net`, which hint at interactions with JavaScript, streams API, inter-process communication, and networking.
    * `namespace blink`: This confirms we're in the Blink rendering engine.
    * `class TCPServerSocket`: The core class of this file. Focus on its methods.
    * `Create`, `Open`, `close`, `opened`: These look like the main lifecycle and control functions.
    * `ScriptPromise`:  Indicates asynchronous operations and interaction with JavaScript Promises.
    * `TCPServerSocketOptions`, `TCPServerSocketOpenInfo`: Data structures related to configuring and reporting the server socket.
    * `ReadableStream`: Connects to the Streams API in JavaScript.
    * `mojo`: Signals inter-process communication within Chromium.
    * Error handling: Look for `ExceptionState`, `ThrowTypeError`, `DOMExceptionCode`, `base::UmaHistogramSparse`.

3. **Identify Core Functionality:**  Based on the keywords and method names, the primary function is clearly managing a TCP server socket. Key aspects are:
    * **Creation:**  `Create` is the entry point, likely called from JavaScript.
    * **Opening:** `Open` initiates the server socket setup with the operating system.
    * **Listening:** While not explicitly a method, the `ReadableStream` suggests listening for incoming connections.
    * **Closing:** `close` shuts down the server socket.
    * **Reporting Status:**  `opened` provides a Promise that resolves when the socket is ready.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The presence of `ScriptState`, `ScriptPromise`, and the data structures passed to and from the class (`TCPServerSocketOptions`, `TCPServerSocketOpenInfo`) strongly suggest a JavaScript API is involved. The likely API is the *Direct Sockets API* (though the specific name isn't in the code, the module path `direct_sockets` is a strong clue).
    * **HTML:** No direct connection to HTML or CSS is immediately apparent in this *backend* C++ code. However, the *trigger* for using this API would likely originate from JavaScript within an HTML page or a service worker.
    * **CSS:**  No direct connection.

5. **Logical Reasoning and Examples:**  Consider the flow of operations and potential scenarios:
    * **Successful Opening:**  Input: Valid IP address and port. Output: `opened` Promise resolves with local address and port.
    * **Invalid IP Address:** Input:  Invalid IP string. Output: `TypeError` in JavaScript.
    * **Port 0:** Input: `localPort` set to 0. Output: OS assigns a port, which is returned in the `opened` Promise.
    * **`ipv6Only` Restriction:** Input: `ipv6Only` true but local address is not `::`. Output: `TypeError`.
    * **Closing and Locking:** Input: Call `close` while the readable stream is locked. Output: `InvalidStateError`.

6. **User/Programming Errors:** Focus on the error checks within the C++ code:
    * Invalid IP address format.
    * `localPort` being 0 when it shouldn't be.
    * `backlog` being 0.
    * Incorrect use of `ipv6Only`.
    * Attempting to close a socket in the wrong state.
    * Closing a socket with a locked stream.

7. **User Actions and Debugging:**  Think about how a developer would use this API:
    * **JavaScript code:** A user would write JavaScript code to create and manage the `TCPServerSocket`. This is the starting point.
    * **API Calls:** The JavaScript code would call methods like `create`, `opened`, and `close`.
    * **Error Handling:**  If something goes wrong, JavaScript exceptions would be thrown, providing initial debugging clues.
    * **Network Inspection:** Browser developer tools could be used to inspect network traffic (though direct sockets might bypass some traditional HTTP inspection).
    * **Debugging within Chromium:** For deeper issues, a developer working on Chromium itself might need to step through the C++ code in files like this one. The steps would involve identifying the JavaScript call that triggered the issue and tracing it down to the C++ implementation. Logging and breakpoints would be crucial.

8. **Structure the Answer:** Organize the findings into logical sections as requested: functionality, relationship to web tech, logical reasoning, errors, and user actions/debugging. Use clear and concise language. Use code snippets where helpful (even if they are hypothetical JavaScript examples).

9. **Refine and Review:** After drafting the answer, review it for clarity, accuracy, and completeness. Ensure all parts of the original request have been addressed. For instance, double-check that the examples make sense and the error explanations are accurate. Ensure the connection between user action and the C++ code is clear. Initially, I might have focused too much on the technical details of the C++ code and not enough on the *user's* perspective. The review step helps correct this.
好的，让我们来分析一下 `blink/renderer/modules/direct_sockets/tcp_server_socket.cc` 这个 Chromium Blink 引擎源代码文件。

**文件功能概述：**

`tcp_server_socket.cc` 文件的主要功能是实现了 **TCP 服务器套接字** 的核心逻辑。它为 JavaScript 提供了一个接口，允许网页或 Service Worker 创建并管理一个 TCP 服务器，监听指定地址和端口上的连接请求。

具体来说，这个文件负责：

1. **创建和初始化 TCP 服务器套接字：**  `TCPServerSocket::Create` 方法是创建 `TCPServerSocket` 对象的入口。它会检查运行环境和权限，并调用 `Open` 方法进行进一步的初始化。
2. **打开监听端口：** `TCPServerSocket::Open` 方法调用底层的网络服务（通过 Mojo IPC）来实际打开指定的本地地址和端口，开始监听连接。它还会处理用户提供的 `TCPServerSocketOptions`，例如 `localPort`（本地端口）、`backlog`（等待队列长度）和 `ipv6Only`（是否仅使用 IPv6）。
3. **管理服务器状态：**  维护服务器套接字的状态，例如 `kOpening`（正在打开）、`kOpen`（已打开）、`kClosed`（已关闭）和 `kAborted`（已中止）。
4. **处理打开结果：** `TCPServerSocket::OnTCPServerSocketOpened` 方法接收来自底层网络服务的打开结果。如果成功，它会创建一个 `ReadableStream` 来表示接受到的连接，并将服务器信息（本地地址和端口）传递给 JavaScript。如果失败，它会记录错误，拒绝打开的 Promise，并更新服务器状态。
5. **提供 ReadableStream 接口：**  服务器套接字的核心功能是接受新的连接。每当有新的连接建立时，都会创建一个新的 `TCPReadableStreamWrapper`（在 `tcp_server_readable_stream_wrapper.h` 中定义），并通过一个 `ReadableStream` 对象暴露给 JavaScript。这个 `ReadableStream` 允许 JavaScript 代码读取新连接的数据。
6. **关闭服务器套接字：** `TCPServerSocket::close` 方法用于关闭服务器套接字，停止监听新的连接。它会取消相关的 `ReadableStream`，并通知底层网络服务关闭套接字。
7. **错误处理：**  在创建和打开过程中，会进行参数校验，并使用 `ExceptionState` 向 JavaScript 抛出类型错误 (`TypeError`)。网络操作失败时，会记录指标并通过 Promise 的 reject 回调将错误信息传递给 JavaScript。
8. **生命周期管理：** 通过 `ContextDestroyed` 和 `ReleaseResources` 方法处理对象销毁和资源释放。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件本身不直接涉及 HTML 或 CSS 的渲染逻辑。它的主要作用是为 JavaScript 提供底层的网络功能。

**与 JavaScript 的关系：**

* **Direct Sockets API:**  这个文件是 Chromium 中 **Direct Sockets API** 的一部分。这个 API 允许 JavaScript 代码直接创建和管理 TCP 或 UDP 套接字，而无需通过传统的 HTTP 或 WebSocket 协议。
* **JavaScript API 映射：**  `TCPServerSocket` 类的方法（如 `create`, `opened`, `close`）以及相关的选项 (`TCPServerSocketOptions`) 和信息 (`TCPServerSocketOpenInfo`) 都对应着 JavaScript 中可用的 API。
* **Promise 的使用：**  异步操作（如打开和关闭套接字）的结果通过 JavaScript 的 `Promise` 对象传递给 JavaScript 代码。`opened()` 方法返回一个在服务器成功打开后 resolve 的 Promise，`closed()` 方法返回一个在服务器关闭后 resolve 的 Promise。
* **ReadableStream 的暴露：**  通过 `readable()` 方法返回的 `ReadableStream` 对象，JavaScript 可以监听并读取新接受连接的数据。

**举例说明：**

假设以下 JavaScript 代码尝试创建一个 TCP 服务器：

```javascript
const options = {
  localAddress: "127.0.0.1",
  localPort: 8080,
  backlog: 5
};

try {
  const serverSocket = await navigator.directSockets.createServerSocket(options);
  const { readable, localAddress, localPort } = await serverSocket.opened;
  console.log(`Server listening on ${localAddress}:${localPort}`);

  const reader = readable.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    console.log("Received:", new TextDecoder().decode(value));
  }

  await serverSocket.close();
} catch (error) {
  console.error("Error creating server socket:", error);
}
```

在这个例子中：

1. `navigator.directSockets.createServerSocket(options)`  在 JavaScript 中调用会最终触发 `TCPServerSocket::Create` 方法在 C++ 中的执行。`options` 对象中的属性会被映射到 `TCPServerSocketOptions` 对象。
2. `serverSocket.opened` 返回的 Promise 会在 `TCPServerSocket::OnTCPServerSocketOpened` 成功时 resolve，并将 `TCPServerSocketOpenInfo` 传递给 JavaScript，其中包含服务器的本地地址和端口以及用于接收连接的 `ReadableStream`。
3. JavaScript 代码可以通过 `readable.getReader().read()` 来读取新连接的数据，这背后是由 `TCPServerReadableStreamWrapper` 管理的。
4. `serverSocket.close()` 会调用 `TCPServerSocket::close` 方法来关闭服务器。

**与 HTML 和 CSS 的关系：**

Direct Sockets API 主要用于网络通信，与 HTML 的结构和 CSS 的样式没有直接关系。然而，触发 Direct Sockets API 调用的 JavaScript 代码通常会嵌入在 HTML 文件中的 `<script>` 标签内，或者在 Service Worker 中运行。

**逻辑推理与假设输入输出：**

**假设输入：**

JavaScript 代码尝试创建一个 TCP 服务器，并提供以下选项：

```javascript
const options = {
  localAddress: "0.0.0.0", // 监听所有 IPv4 地址
  localPort: 0,           // 让操作系统自动选择端口
  backlog: 10,
  ipv6Only: false
};
```

**`TCPServerSocket::CreateTCPServerSocketOptions` 函数的逻辑推理：**

1. **`localAddress` 处理：**  输入 `"0.0.0.0"`，`net::IPAddress::AssignFromIPLiteral("0.0.0.0")` 会成功解析为一个 IPv4 地址。
2. **`localPort` 处理：** 输入 `0`，条件 `options->hasLocalPort() && options->localPort() == 0` 为真，但不会抛出错误，因为端口 0 是允许的，表示让操作系统选择。
3. **创建 `net::IPEndPoint`：**  创建一个 `net::IPEndPoint` 对象，地址为解析后的 IPv4 地址，端口为 `0U`。
4. **`backlog` 处理：** 输入 `10`，`options->hasBacklog()` 为真，且 `options->backlog()` 大于 0，`socket_options->backlog` 被设置为 10。
5. **`ipv6Only` 处理：** 输入 `false`，`options->hasIpv6Only()` 为真，但由于本地地址不是 `::`，所以不会进入 `if` 块，`socket_options->ipv6_only` 不会被设置，保持默认值（通常为 `false`）。
6. **输出：**  返回一个 `mojom::blink::DirectTCPServerSocketOptionsPtr`，其中包含解析后的本地地址、端口（0）、backlog (10) 和 ipv6Only (默认 false)。

**假设输出：**

`CreateTCPServerSocketOptions` 函数会返回一个 `mojom::blink::DirectTCPServerSocketOptionsPtr`，其内容大致如下：

```
local_addr: { address: "0.0.0.0", port: 0 }
backlog: 10
ipv6_only: false
```

当 `TCPServerSocket::OnTCPServerSocketOpened` 被调用且 `result` 为 `net::OK` 时，`local_addr` 参数会包含操作系统实际分配的端口号。

**用户或编程常见的使用错误：**

1. **无效的 `localAddress`：** 用户可能提供一个无效的 IP 地址字符串，例如 `"invalid-ip"`。这会导致 `CreateTCPServerSocketOptions` 中的 `address.AssignFromIPLiteral` 返回 false，并抛出一个 `TypeError`，提示 "localAddress must be a valid IP address."。

   **示例 JavaScript 代码：**
   ```javascript
   const options = { localAddress: "invalid-ip", localPort: 8080 };
   navigator.directSockets.createServerSocket(options); // 会抛出错误
   ```

2. **`localPort` 为 0 的错误使用：** 用户可能错误地认为将 `localPort` 设置为 0 会禁用端口监听，而不是让操作系统自动选择。代码中已经做了校验，如果明确设置 `localPort` 为 0 会抛出错误。

   **示例 JavaScript 代码：**
   ```javascript
   const options = { localAddress: "127.0.0.1", localPort: 0 };
   navigator.directSockets.createServerSocket(options); // 会抛出错误
   ```

3. **`backlog` 为 0：** 用户可能将 `backlog` 设置为 0，这在逻辑上是不合理的。代码中会检查这种情况并抛出 `TypeError`。

   **示例 JavaScript 代码：**
   ```javascript
   const options = { localAddress: "127.0.0.1", localPort: 8080, backlog: 0 };
   navigator.directSockets.createServerSocket(options); // 会抛出错误
   ```

4. **`ipv6Only` 与 `localAddress` 不匹配：** 用户可能设置 `ipv6Only` 为 `true`，但提供的 `localAddress` 不是 IPv6 的通配地址 `::` 或其等价形式。这会导致 `CreateTCPServerSocketOptions` 抛出 `TypeError`。

   **示例 JavaScript 代码：**
   ```javascript
   const options = { localAddress: "127.0.0.1", localPort: 8080, ipv6Only: true };
   navigator.directSockets.createServerSocket(options); // 会抛出错误
   ```

5. **在流被锁定时关闭服务器：**  如果 JavaScript 代码获取了服务器 `readable` 流的 reader 并锁定了它，然后尝试调用 `serverSocket.close()`，会抛出一个 `InvalidStateError`。

   **示例 JavaScript 代码：**
   ```javascript
   const serverSocket = await navigator.directSockets.createServerSocket({ localAddress: "127.0.0.1", localPort: 8080 });
   const { readable } = await serverSocket.opened;
   const reader = readable.getReader();
   reader.read(); // 锁定 readable 流
   await serverSocket.close(); // 抛出 InvalidStateError
   ```

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在网页或 Service Worker 中编写 JavaScript 代码，使用了 Direct Sockets API 的 `createServerSocket` 方法。** 例如：
   ```javascript
   navigator.directSockets.createServerSocket({ localAddress: "127.0.0.1", localPort: 8080 });
   ```
2. **浏览器接收到这段 JavaScript 代码并开始执行。**
3. **JavaScript 引擎执行到 `createServerSocket` 方法调用时，会触发 Blink 渲染引擎中对应的 C++ 代码。** 具体来说，可能会经过 JavaScript 绑定层，最终调用到 `third_party/blink/renderer/modules/direct_sockets/direct_sockets.cc` 中的 `createTCPServerSocket` 方法。
4. **`createTCPServerSocket` 方法会创建 `TCPServerSocket` 对象，并调用其 `Open` 方法。**
5. **`TCPServerSocket::Open` 方法会调用 `CreateTCPServerSocketOptions` 来处理用户提供的选项。** 如果选项有误，这里会抛出 JavaScript 异常。
6. **如果选项正确，`Open` 方法会通过 Mojo IPC 向 Browser 进程的 Network Service 发送请求，要求打开 TCP 服务器套接字。**
7. **Network Service 处理请求，并尝试在操作系统层面打开套接字。**
8. **Network Service 将操作结果（成功或失败）通过 Mojo IPC 发送回 Renderer 进程。**
9. **Renderer 进程的 `TCPServerSocket::OnTCPServerSocketOpened` 方法接收到结果。**
10. **如果成功，`OnTCPServerSocketOpened` 会 resolve `opened` Promise，并创建一个 `ReadableStream`。**
11. **如果失败，`OnTCPServerSocketOpened` 会 reject `opened` Promise，并将错误信息传递给 JavaScript。**

**调试线索：**

* **查看 JavaScript 控制台的错误信息：**  如果 JavaScript 代码抛出异常，控制台会显示错误类型和消息，这可以帮助定位问题是发生在参数校验阶段还是网络操作阶段。
* **使用 Chrome 的 `chrome://inspect/#all` 或开发者工具的 "Network" 选项卡：** 虽然 Direct Sockets 不会像 HTTP 请求那样显示在 Network 选项卡中，但如果有网络层面的问题，可能可以在这里看到一些端倪，例如连接被拒绝等。
* **在 Blink 渲染引擎代码中设置断点：** 如果需要深入调试，可以在 `tcp_server_socket.cc` 中的关键方法（如 `Create`, `Open`, `OnTCPServerSocketOpened`) 设置断点，查看代码执行流程和变量值。这需要编译 Chromium 并使用调试器。
* **查看 `chrome://net-internals/#sockets`：**  这个 Chrome 内部页面可以提供关于套接字的详细信息，包括 Direct Sockets 创建的套接字的状态。
* **使用 `base::UmaHistogramSparse` 记录的指标：**  代码中使用了 `base::UmaHistogramSparse("DirectSockets.TCPServerNetworkFailures", -result)` 来记录网络失败的错误码。可以在 Chrome 的 Telemetry 仪表盘中查找这些指标，以了解常见的错误类型。

希望以上分析能够帮助你理解 `blink/renderer/modules/direct_sockets/tcp_server_socket.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/modules/direct_sockets/tcp_server_socket.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/direct_sockets/tcp_server_socket.h"

#include "base/functional/callback_helpers.h"
#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_tcp_server_socket_open_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_tcp_server_socket_options.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/modules/direct_sockets/tcp_server_readable_stream_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"

namespace blink {

namespace {

mojom::blink::DirectTCPServerSocketOptionsPtr CreateTCPServerSocketOptions(
    const String& local_address,
    const TCPServerSocketOptions* options,
    ExceptionState& exception_state) {
  auto socket_options = mojom::blink::DirectTCPServerSocketOptions::New();

  net::IPAddress address;
  if (!address.AssignFromIPLiteral(local_address.Utf8())) {
    exception_state.ThrowTypeError("localAddress must be a valid IP address.");
    return {};
  }

  if (options->hasLocalPort() && options->localPort() == 0) {
    exception_state.ThrowTypeError(
        "localPort must be greater than zero. Leave this field unassigned to "
        "allow the OS to pick a port on its own.");
    return {};
  }

  // Port 0 allows the OS to pick an available port on its own.
  net::IPEndPoint local_addr = net::IPEndPoint(
      std::move(address), options->hasLocalPort() ? options->localPort() : 0U);

  if (options->hasBacklog()) {
    if (options->backlog() == 0) {
      exception_state.ThrowTypeError("backlog must be greater than zero.");
      return {};
    }
    socket_options->backlog = options->backlog();
  }

  if (options->hasIpv6Only()) {
    if (local_addr.address() != net::IPAddress::IPv6AllZeros()) {
      exception_state.ThrowTypeError(
          "ipv6Only can only be specified when localAddress is [::] or "
          "equivalent.");
      return {};
    }
    socket_options->ipv6_only = options->ipv6Only();
  }

  socket_options->local_addr = std::move(local_addr);
  return socket_options;
}

}  // namespace

TCPServerSocket::TCPServerSocket(ScriptState* script_state)
    : Socket(script_state),
      opened_(MakeGarbageCollected<
              ScriptPromiseProperty<TCPServerSocketOpenInfo, DOMException>>(
          GetExecutionContext())) {}

TCPServerSocket::~TCPServerSocket() = default;

// static
TCPServerSocket* TCPServerSocket::Create(ScriptState* script_state,
                                         const String& local_address,
                                         const TCPServerSocketOptions* options,
                                         ExceptionState& exception_state) {
  if (!Socket::CheckContextAndPermissions(script_state, exception_state)) {
    return nullptr;
  }

  auto* socket = MakeGarbageCollected<TCPServerSocket>(script_state);
  if (!socket->Open(local_address, options, exception_state)) {
    return nullptr;
  }
  return socket;
}

ScriptPromise<TCPServerSocketOpenInfo> TCPServerSocket::opened(
    ScriptState* script_state) const {
  return opened_->Promise(script_state->World());
}

ScriptPromise<IDLUndefined> TCPServerSocket::close(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (GetState() == State::kOpening) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Socket is not properly initialized.");
    return EmptyPromise();
  }

  if (GetState() != State::kOpen) {
    return closed(script_state);
  }

  if (readable_stream_wrapper_->Locked()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Close called on locked streams.");
    return EmptyPromise();
  }

  auto* reason = MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kAbortError, "Stream closed.");

  auto readable_cancel = readable_stream_wrapper_->Readable()->cancel(
      script_state, ScriptValue::From(script_state, reason), exception_state);
  DCHECK(!exception_state.HadException());
  readable_cancel.MarkAsHandled();

  return closed(script_state);
}

bool TCPServerSocket::Open(const String& local_addr,
                           const TCPServerSocketOptions* options,
                           ExceptionState& exception_state) {
  auto open_tcp_server_socket_options =
      CreateTCPServerSocketOptions(local_addr, options, exception_state);

  if (exception_state.HadException()) {
    return false;
  }

  mojo::PendingRemote<network::mojom::blink::TCPServerSocket> tcp_server_remote;
  mojo::PendingReceiver<network::mojom::blink::TCPServerSocket>
      tcp_server_receiver = tcp_server_remote.InitWithNewPipeAndPassReceiver();

  GetServiceRemote()->OpenTCPServerSocket(
      std::move(open_tcp_server_socket_options), std::move(tcp_server_receiver),
      WTF::BindOnce(&TCPServerSocket::OnTCPServerSocketOpened,
                    WrapPersistent(this), std::move(tcp_server_remote)));
  return true;
}

void TCPServerSocket::OnTCPServerSocketOpened(
    mojo::PendingRemote<network::mojom::blink::TCPServerSocket>
        tcp_server_remote,
    int32_t result,
    const std::optional<net::IPEndPoint>& local_addr) {
  if (result == net::OK) {
    DCHECK(local_addr);
    readable_stream_wrapper_ =
        MakeGarbageCollected<TCPServerReadableStreamWrapper>(
            GetScriptState(),
            WTF::BindOnce(&TCPServerSocket::OnReadableStreamClosed,
                          WrapPersistent(this)),
            std::move(tcp_server_remote));

    auto* open_info = TCPServerSocketOpenInfo::Create();
    open_info->setReadable(readable_stream_wrapper_->Readable());
    open_info->setLocalAddress(String{local_addr->ToStringWithoutPort()});
    open_info->setLocalPort(local_addr->port());

    opened_->Resolve(open_info);

    SetState(State::kOpen);
  } else {
    // Error codes are negative.
    base::UmaHistogramSparse("DirectSockets.TCPServerNetworkFailures", -result);
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

void TCPServerSocket::Trace(Visitor* visitor) const {
  visitor->Trace(opened_);
  visitor->Trace(readable_stream_wrapper_);

  ScriptWrappable::Trace(visitor);
  Socket::Trace(visitor);
}

void TCPServerSocket::ContextDestroyed() {
  // Release resources as quickly as possible.
  ReleaseResources();
}

void TCPServerSocket::ReleaseResources() {
  ResetServiceAndFeatureHandle();
  readable_stream_wrapper_.Clear();
}

void TCPServerSocket::OnReadableStreamClosed(ScriptValue exception) {
  DCHECK_EQ(GetState(), State::kOpen);

  if (!exception.IsEmpty()) {
    GetClosedProperty().Reject(exception);
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
Response:
Let's break down the thought process for analyzing the `udp_socket.cc` file and generating the comprehensive explanation.

**1. Understanding the Request:**

The request asks for a functional breakdown of a Chromium Blink engine source file (`udp_socket.cc`). Key aspects to cover include:

* **Functionality:** What does this code *do*?
* **Relation to web technologies:** How does it interact with JavaScript, HTML, and CSS?
* **Logic and examples:** Illustrate functionality with hypothetical inputs and outputs.
* **Common user errors:** Identify potential pitfalls for developers using this API.
* **Debugging context:** Explain how a user might trigger this code and how it fits into a debugging workflow.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code, looking for key terms and patterns. This helps establish the core purpose. Notable keywords in this file include:

* `UDPSocket`:  The central class, suggesting network communication using UDP.
* `Open`, `Close`, `Send`, `Receive` (implicitly through streams):  Fundamental socket operations.
* `ScriptPromise`: Indicates asynchronous operations and interaction with JavaScript.
* `ReadableStream`, `WritableStream`:  Suggests the use of the Streams API for data handling.
* `UDPSocketOptions`:  Configuration parameters for the socket.
* `mojom::blink::`:  Indicates interaction with the Chromium Mojo IPC system for communicating with other processes.
* `ExceptionState`:  Mechanism for reporting errors to JavaScript.
* `kUDPNetworkFailuresHistogramName`:  Suggests metrics tracking.
* `remoteAddress`, `remotePort`, `localAddress`, `localPort`: Network addressing concepts.

From this initial scan, it's clear this file implements the browser-side logic for UDP sockets exposed to JavaScript.

**3. Deeper Dive into Functionality (Method-by-Method):**

Next, systematically go through the major methods and understand their roles:

* **`Create()`:**  Entry point for creating a `UDPSocket` instance from JavaScript. Handles permission checks.
* **Constructor (`UDPSocket()`):** Initializes internal state, including Mojo remotes and promises.
* **`opened()`:** Returns a promise that resolves when the socket is successfully opened.
* **`close()`:**  Initiates the closing process, handling locked streams and rejecting the `closed` promise.
* **`Open()`:**  The core logic for establishing the UDP connection. It parses options, determines the socket mode (connected or bound), and uses Mojo to communicate with the network service. This is a critical function to understand in detail.
* **`FinishOpen()`:**  Called when the Mojo call to open the socket returns. It sets up the readable and writable streams and resolves or rejects the `opened` promise.
* **`OnConnectedUDPSocketOpened()`, `OnBoundUDPSocketOpened()`:** Specific callbacks for connected and bound socket opening scenarios.
* **`FailOpenWith()`:** Handles errors during the opening process, recording metrics and rejecting promises.
* **`GetUDPSocketReceiver()`:**  Sets up the Mojo receiver for the `RestrictedUDPSocket` interface.
* **`HasPendingActivity()`:** Checks if there are pending writes on the writable stream.
* **`ContextDestroyed()`:**  Releases resources when the associated browsing context is destroyed.
* **`OnServiceConnectionError()`:** Handles errors in the Mojo connection to the network service.
* **`CloseOnError()`:**  Called when the underlying Mojo connection to the socket is closed unexpectedly.
* **`ReleaseResources()`:**  Cleans up Mojo resources.
* **`OnBothStreamsClosed()`:**  Called when both the readable and writable streams are closed. Resolves or rejects the `closed` promise.

**4. Connecting to Web Technologies:**

Now, consider how these methods relate to JavaScript, HTML, and CSS:

* **JavaScript:** The primary interface. The `UDPSocket` class is exposed to JavaScript, and methods like `open()`, `close()`, `readable`, and `writable` are directly callable. Promises are used for asynchronous operations, a key JavaScript feature.
* **HTML:**  While not directly interacting with HTML elements, the `UDPSocket` API could be used in JavaScript code triggered by user interactions on an HTML page (e.g., a button click to send data).
* **CSS:**  No direct relation to CSS.

**5. Logic and Examples:**

For each significant function, think about example scenarios:

* **`Open()`:**  Consider the different options (`remoteAddress`, `remotePort`, `localAddress`, `localPort`) and how they determine the socket mode. Illustrate with specific IP addresses and ports.
* **Error Handling:**  Think about what could go wrong during opening (e.g., invalid IP address, port already in use, network issues).

**6. Common User Errors:**

Based on the code and the API design, identify potential mistakes developers might make:

* Incorrectly specifying IP addresses or ports.
* Trying to close a locked stream.
* Not handling the promises returned by `open()` and `close()`.
* Security and permission issues.

**7. Debugging Context:**

Trace the steps a user might take to trigger the code:

1. Write JavaScript code using the `UDPSocket` API.
2. Open a web page containing this JavaScript.
3. The browser executes the JavaScript, leading to the creation and interaction with the `UDPSocket` object.
4. Errors or unexpected behavior in the socket communication might lead a developer to inspect this `udp_socket.cc` file as part of debugging.

**8. Structuring the Explanation:**

Organize the findings into logical sections:

* **Core Functionality:** A high-level summary.
* **Detailed Functionality:** Breakdown by key methods.
* **Relationship to Web Technologies:**  Explain the connections.
* **Logic and Examples:** Concrete scenarios.
* **Common User Errors:** Practical advice for developers.
* **Debugging Context:** How this code fits into the development lifecycle.

**9. Refinement and Clarity:**

Review the generated explanation for clarity, accuracy, and completeness. Ensure that technical terms are explained appropriately and that the examples are easy to understand. Use formatting (like bullet points and code blocks) to improve readability. For example, explicitly mentioning the `Direct Sockets API` in the initial summary adds crucial context.

By following this structured approach, one can effectively analyze a source code file like `udp_socket.cc` and generate a comprehensive and informative explanation. The key is to combine code reading with an understanding of the broader system (Chromium, web standards) and the developer's perspective.
好的，让我们详细分析一下 `blink/renderer/modules/direct_sockets/udp_socket.cc` 这个文件。

**核心功能：**

这个文件实现了 Chromium Blink 引擎中用于创建和管理 UDP (User Datagram Protocol) 套接字的 `UDPSocket` 类。它提供了 JavaScript 可以调用的接口，用于执行以下操作：

1. **创建 UDP 套接字：**  允许网页 JavaScript 代码创建一个新的 UDP 套接字实例。
2. **打开连接：** 根据提供的选项（本地地址、本地端口、远程地址、远程端口等）打开 UDP 套接字。这可能创建一个已连接的 UDP 套接字（与特定远程地址和端口关联）或一个绑定的 UDP 套接字（监听特定本地地址和端口）。
3. **发送数据：** 通过 `WritableStream` 接口向远程地址发送 UDP 数据报。
4. **接收数据：** 通过 `ReadableStream` 接口接收来自远程地址的 UDP 数据报。
5. **关闭连接：** 关闭 UDP 套接字，释放相关资源。
6. **管理套接字选项：**  允许设置和查询套接字的各种选项，例如发送和接收缓冲区大小，是否只允许 IPv6 连接等。

**与 JavaScript, HTML, CSS 的关系：**

这个文件是 Blink 渲染引擎的一部分，负责将底层的网络功能暴露给 JavaScript。

* **JavaScript:** `UDPSocket` 类直接与 JavaScript 中的 `UDPSocket` API 相对应。网页开发者可以使用 JavaScript 代码来创建、配置和操作 UDP 套接字。例如：

```javascript
const socket = new UDPSocket({ remoteAddress: '192.168.1.100', remotePort: 53 }); // 创建连接到 DNS 服务器的套接字

socket.opened.then(() => {
  const writer = socket.writable.getWriter();
  const encoder = new TextEncoder();
  const data = encoder.encode("example.com");
  writer.write(data);
  writer.close();
});

socket.readable.getReader().read().then(({ value, done }) => {
  if (done) {
    return;
  }
  const decoder = new TextDecoder();
  console.log("Received:", decoder.decode(value));
});

socket.close();
```

* **HTML:** HTML 本身不直接涉及 UDP 套接字的操作。但是，HTML 页面中的 JavaScript 代码可以使用 `UDPSocket` API 来执行网络通信。例如，一个网页可能包含一个按钮，点击后会使用 UDP 套接字向服务器发送数据。

* **CSS:** CSS 与 UDP 套接字的功能没有直接关系。CSS 负责网页的样式和布局，而 UDP 套接字处理网络数据传输。

**逻辑推理和假设输入输出：**

**场景 1：打开一个连接的 UDP 套接字**

* **假设输入 (JavaScript):**
  ```javascript
  const socket = new UDPSocket({ remoteAddress: '8.8.8.8', remotePort: 53, dnsQueryType: 'ipv4' });
  ```
* **逻辑推理 (C++):**
    * `InferUDPSocketMode` 函数会根据 `remoteAddress` 和 `remotePort` 的存在推断出模式为 `CONNECTED`。
    * `CreateConnectedUDPSocketOptions` 函数会创建 `DirectConnectedUDPSocketOptionsPtr`，包含远程地址、端口，以及 `dns_query_type` 设置为 `net::DnsQueryType::A` (因为 JavaScript 中指定了 `'ipv4'`)。
    * `GetServiceRemote()->OpenConnectedUDPSocket` 会被调用，将这些选项传递给网络进程。
* **可能输出 (取决于网络进程的响应):**
    * **成功:**  `OnConnectedUDPSocketOpened` 被调用，`result` 为 `net::OK`，`local_addr` 和 `peer_addr` 被设置。`opened` promise 被解析，包含可读和可写流。
    * **失败:** `OnConnectedUDPSocketOpened` 被调用，`result` 为一个错误代码 (例如 `net::ERR_CONNECTION_REFUSED`)。 `FailOpenWith` 被调用，记录错误并拒绝 `opened` promise。

**场景 2：打开一个绑定的 UDP 套接字**

* **假设输入 (JavaScript):**
  ```javascript
  const socket = new UDPSocket({ localAddress: '127.0.0.1', localPort: 8080 });
  ```
* **逻辑推理 (C++):**
    * `InferUDPSocketMode` 函数会根据 `localAddress` 的存在推断出模式为 `BOUND`。
    * `CreateBoundUDPSocketOptions` 函数会创建 `DirectBoundUDPSocketOptionsPtr`，包含本地 IP 地址和端口。
    * `GetServiceRemote()->OpenBoundUDPSocket` 会被调用。
* **可能输出:**
    * **成功:** `OnBoundUDPSocketOpened` 被调用，`result` 为 `net::OK`，`local_addr` 被设置。`opened` promise 被解析。
    * **失败:** `OnBoundUDPSocketOpened` 被调用，`result` 为一个错误代码 (例如 `net::ERR_ADDRESS_IN_USE`)。 `FailOpenWith` 被调用。

**用户或编程常见的使用错误：**

1. **未提供必要的地址信息：**
   * 错误示例：`const socket = new UDPSocket();` (既没有 `remoteAddress`/`remotePort`，也没有 `localAddress`/`localPort`)
   * 异常：`TypeError: neither remoteAddress nor localAddress specified.`

2. **`remoteAddress` 和 `remotePort` 不一致：**
   * 错误示例：`const socket = new UDPSocket({ remoteAddress: '8.8.8.8' });` (只提供了 `remoteAddress`，没有 `remotePort`)
   * 异常：`TypeError: remoteAddress and remotePort should either be specified together or not specified at all.`

3. **在已连接模式下指定 `ipv6Only`：**
   * 错误示例：`const socket = new UDPSocket({ remoteAddress: '...', remotePort: ..., ipv6Only: true });`
   * 异常：`TypeError: ipv6Only can only be specified with localAddress.`

4. **`localPort` 为 0，但不是期望操作系统分配端口的情况：**
   * 错误示例：可能在某些内部逻辑中错误地设置了 `localPort` 为 0，而不是让用户不指定或显式允许操作系统分配。
   * 异常：`TypeError: localPort must be greater than zero. Leave this field unassigned to allow the OS to pick a port on its own.`

5. **尝试在流被锁定时关闭套接字：**
   * 错误示例：如果在读取或写入流的过程中调用了 `socket.close()`，并且流的 reader 或 writer 已经被锁定。
   * 异常：`DOMException: Close called on locked streams.`

**用户操作如何一步步到达这里 (调试线索)：**

1. **编写 JavaScript 代码：** 开发者编写使用 `UDPSocket` API 的 JavaScript 代码。
2. **加载网页：** 用户在浏览器中加载包含这段 JavaScript 代码的网页。
3. **执行 JavaScript：** 浏览器解析并执行 JavaScript 代码。
4. **创建 `UDPSocket` 实例：** 当 JavaScript 代码中 `new UDPSocket(options)` 被执行时，Blink 引擎会调用 `UDPSocket::Create` 函数。
5. **打开连接：** 调用 `socket.opened` 或尝试发送/接收数据会触发 `UDPSocket::Open` 函数。
6. **Mojo 通信：** `UDPSocket` 类通过 Mojo 与浏览器进程中的网络服务进行通信。相关的 Mojo 接口定义在 `third_party/blink/public/mojom/direct_sockets/direct_sockets.mojom-blink.h` 中。
7. **网络操作：** 网络服务会执行实际的 UDP 套接字创建和连接操作。
8. **回调：** 网络操作的结果会通过 Mojo 回调到 `UDPSocket` 类中的 `OnConnectedUDPSocketOpened` 或 `OnBoundUDPSocketOpened` 等函数。
9. **流的创建：** 如果连接成功，`FinishOpen` 函数会创建可读和可写流的包装器 (`UDPReadableStreamWrapper` 和 `UDPWritableStreamWrapper`)。
10. **数据传输：**  通过可读和可写流进行数据发送和接收。
11. **关闭连接：** 调用 `socket.close()` 会触发 `UDPSocket::close` 函数，并通知网络服务关闭套接字。

**调试线索:**

* **断点：** 在 `UDPSocket::Create`, `UDPSocket::Open`, `OnConnectedUDPSocketOpened`, `OnBoundUDPSocketOpened`, `FailOpenWith` 等关键函数设置断点可以帮助理解套接字创建和连接的过程。
* **Mojo 日志：** 查看 Mojo 通信的日志可以了解 Blink 引擎和网络服务之间的交互。
* **网络面板：** 浏览器的开发者工具中的网络面板可能不会直接显示 UDP 数据包，但可以显示一些与 Direct Sockets API 相关的事件和错误。
* **控制台输出：**  使用 `console.log` 输出 JavaScript 中的状态和错误信息。
* **异常堆栈：** 当出现异常时，查看异常堆栈可以帮助定位问题代码。

总而言之，`udp_socket.cc` 文件是 Blink 引擎中实现 Web UDP 套接字功能的核心组件，它负责处理 JavaScript 的请求，并通过 Mojo 与网络服务进行交互，管理底层的 UDP 连接，并提供用于发送和接收数据的流接口。 理解这个文件的工作原理对于调试和理解 Web UDP 套接字 API 的行为至关重要。

### 提示词
```
这是目录为blink/renderer/modules/direct_sockets/udp_socket.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/direct_sockets/udp_socket.h"

#include "base/barrier_callback.h"
#include "base/metrics/histogram_functions.h"
#include "base/ranges/algorithm.h"
#include "net/base/net_errors.h"
#include "third_party/blink/public/mojom/direct_sockets/direct_sockets.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_socket_dns_query_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_udp_socket_open_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_udp_socket_options.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/modules/direct_sockets/stream_wrapper.h"
#include "third_party/blink/renderer/modules/direct_sockets/udp_readable_stream_wrapper.h"
#include "third_party/blink/renderer/modules/direct_sockets/udp_writable_stream_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

constexpr char kUDPNetworkFailuresHistogramName[] =
    "DirectSockets.UDPNetworkFailures";

bool CheckSendReceiveBufferSize(const UDPSocketOptions* options,
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

std::optional<network::mojom::blink::RestrictedUDPSocketMode>
InferUDPSocketMode(const UDPSocketOptions* options,
                   ExceptionState& exception_state) {
  std::optional<network::mojom::blink::RestrictedUDPSocketMode> mode;
  if (options->hasRemoteAddress() && options->hasRemotePort()) {
    mode = network::mojom::RestrictedUDPSocketMode::CONNECTED;
  } else if (options->hasRemoteAddress() || options->hasRemotePort()) {
    exception_state.ThrowTypeError(
        "remoteAddress and remotePort should either be specified together or "
        "not specified at all.");
    return {};
  }

  if (options->hasLocalAddress()) {
    if (mode) {
      exception_state.ThrowTypeError(
          "remoteAddress and localAddress cannot be specified at the same "
          "time.");
      return {};
    }

    mode = network::mojom::blink::RestrictedUDPSocketMode::BOUND;
  } else if (options->hasLocalPort()) {
    exception_state.ThrowTypeError(
        "localPort cannot be specified without localAddress.");
    return {};
  }

  if (!mode) {
    exception_state.ThrowTypeError(
        "neither remoteAddress nor localAddress specified.");
    return {};
  }

  return mode;
}

mojom::blink::DirectConnectedUDPSocketOptionsPtr
CreateConnectedUDPSocketOptions(const UDPSocketOptions* options,
                                ExceptionState& exception_state) {
  DCHECK(options->hasRemoteAddress() && options->hasRemotePort());

  if (options->hasIpv6Only()) {
    exception_state.ThrowTypeError(
        "ipv6Only can only be specified with localAddress.");
    return {};
  }

  if (!CheckSendReceiveBufferSize(options, exception_state)) {
    return {};
  }

  auto socket_options = mojom::blink::DirectConnectedUDPSocketOptions::New();

  socket_options->remote_addr =
      net::HostPortPair(options->remoteAddress().Utf8(), options->remotePort());
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

  if (options->hasReceiveBufferSize()) {
    socket_options->receive_buffer_size = options->receiveBufferSize();
  }
  if (options->hasSendBufferSize()) {
    socket_options->send_buffer_size = options->sendBufferSize();
  }

  return socket_options;
}

mojom::blink::DirectBoundUDPSocketOptionsPtr CreateBoundUDPSocketOptions(
    const UDPSocketOptions* options,
    ExceptionState& exception_state) {
  DCHECK(options->hasLocalAddress());
  auto socket_options = mojom::blink::DirectBoundUDPSocketOptions::New();

  auto local_ip = net::IPAddress::FromIPLiteral(options->localAddress().Utf8());
  if (!local_ip) {
    exception_state.ThrowTypeError("localAddress must be a valid IP address.");
    return {};
  }

  if (options->hasLocalPort() && options->localPort() == 0) {
    exception_state.ThrowTypeError(
        "localPort must be greater than zero. Leave this field unassigned to "
        "allow the OS to pick a port on its own.");
    return {};
  }

  if (options->hasDnsQueryType()) {
    exception_state.ThrowTypeError(
        "dnsQueryType is only relevant when remoteAddress is specified.");
    return {};
  }

  if (!CheckSendReceiveBufferSize(options, exception_state)) {
    return {};
  }

  if (options->hasIpv6Only()) {
    if (local_ip != net::IPAddress::IPv6AllZeros()) {
      exception_state.ThrowTypeError(
          "ipv6Only can only be specified when localAddress is [::] or "
          "equivalent.");
      return {};
    }
    socket_options->ipv6_only = options->ipv6Only();
  }

  socket_options->local_addr =
      net::IPEndPoint(std::move(*local_ip),
                      options->hasLocalPort() ? options->localPort() : 0U);

  if (options->hasReceiveBufferSize()) {
    socket_options->receive_buffer_size = options->receiveBufferSize();
  }
  if (options->hasSendBufferSize()) {
    socket_options->send_buffer_size = options->sendBufferSize();
  }

  return socket_options;
}

}  // namespace

// static
UDPSocket* UDPSocket::Create(ScriptState* script_state,
                             const UDPSocketOptions* options,
                             ExceptionState& exception_state) {
  if (!Socket::CheckContextAndPermissions(script_state, exception_state)) {
    return nullptr;
  }

  auto* socket = MakeGarbageCollected<UDPSocket>(script_state);
  if (!socket->Open(options, exception_state)) {
    return nullptr;
  }
  return socket;
}

UDPSocket::UDPSocket(ScriptState* script_state)
    : Socket(script_state),
      ActiveScriptWrappable<UDPSocket>({}),
      udp_socket_(
          MakeGarbageCollected<UDPSocketMojoRemote>(GetExecutionContext())),
      opened_(MakeGarbageCollected<
              ScriptPromiseProperty<UDPSocketOpenInfo, DOMException>>(
          GetExecutionContext())) {}

UDPSocket::~UDPSocket() = default;

ScriptPromise<UDPSocketOpenInfo> UDPSocket::opened(
    ScriptState* script_state) const {
  return opened_->Promise(script_state->World());
}

ScriptPromise<IDLUndefined> UDPSocket::close(ScriptState*,
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

bool UDPSocket::Open(const UDPSocketOptions* options,
                     ExceptionState& exception_state) {
  auto mode = InferUDPSocketMode(options, exception_state);
  if (!mode) {
    return false;
  }

  mojo::PendingReceiver<network::mojom::blink::UDPSocketListener>
      socket_listener;
  auto socket_listener_remote = socket_listener.InitWithNewPipeAndPassRemote();

  switch (*mode) {
    case network::mojom::blink::RestrictedUDPSocketMode::CONNECTED: {
      auto connected_options =
          CreateConnectedUDPSocketOptions(options, exception_state);
      if (exception_state.HadException()) {
        return false;
      }
      GetServiceRemote()->OpenConnectedUDPSocket(
          std::move(connected_options), GetUDPSocketReceiver(),
          std::move(socket_listener_remote),
          WTF::BindOnce(&UDPSocket::OnConnectedUDPSocketOpened,
                        WrapPersistent(this), std::move(socket_listener)));
      return true;
    }
    case network::mojom::blink::RestrictedUDPSocketMode::BOUND: {
      auto bound_options =
          CreateBoundUDPSocketOptions(options, exception_state);
      if (exception_state.HadException()) {
        return false;
      }
      GetServiceRemote()->OpenBoundUDPSocket(
          std::move(bound_options), GetUDPSocketReceiver(),
          std::move(socket_listener_remote),
          WTF::BindOnce(&UDPSocket::OnBoundUDPSocketOpened,
                        WrapPersistent(this), std::move(socket_listener)));
      return true;
    }
  }
}

void UDPSocket::FinishOpen(
    network::mojom::RestrictedUDPSocketMode mode,
    mojo::PendingReceiver<network::mojom::blink::UDPSocketListener>
        socket_listener,
    int32_t result,
    const std::optional<net::IPEndPoint>& local_addr,
    const std::optional<net::IPEndPoint>& peer_addr) {
  if (result == net::OK) {
    auto close_callback = base::BarrierCallback<ScriptValue>(
        /*num_callbacks=*/2, WTF::BindOnce(&UDPSocket::OnBothStreamsClosed,
                                           WrapWeakPersistent(this)));

    auto* script_state = GetScriptState();
    readable_stream_wrapper_ = MakeGarbageCollected<UDPReadableStreamWrapper>(
        script_state, close_callback, udp_socket_, std::move(socket_listener));
    // |peer_addr| is populated only in CONNECTED mode.
    writable_stream_wrapper_ = MakeGarbageCollected<UDPWritableStreamWrapper>(
        script_state, close_callback, udp_socket_, mode);

    auto* open_info = UDPSocketOpenInfo::Create();

    open_info->setReadable(readable_stream_wrapper_->Readable());
    open_info->setWritable(writable_stream_wrapper_->Writable());

    if (peer_addr) {
      open_info->setRemoteAddress(String{peer_addr->ToStringWithoutPort()});
      open_info->setRemotePort(peer_addr->port());
    }

    open_info->setLocalAddress(String{local_addr->ToStringWithoutPort()});
    open_info->setLocalPort(local_addr->port());

    opened_->Resolve(open_info);

    SetState(State::kOpen);
  } else {
    FailOpenWith(result);
    SetState(State::kAborted);
  }

  DCHECK_NE(GetState(), State::kOpening);
}

void UDPSocket::OnConnectedUDPSocketOpened(
    mojo::PendingReceiver<network::mojom::blink::UDPSocketListener>
        socket_listener,
    int32_t result,
    const std::optional<net::IPEndPoint>& local_addr,
    const std::optional<net::IPEndPoint>& peer_addr) {
  FinishOpen(network::mojom::RestrictedUDPSocketMode::CONNECTED,
             std::move(socket_listener), result, local_addr, peer_addr);
}

void UDPSocket::OnBoundUDPSocketOpened(
    mojo::PendingReceiver<network::mojom::blink::UDPSocketListener>
        socket_listener,
    int32_t result,
    const std::optional<net::IPEndPoint>& local_addr) {
  FinishOpen(network::mojom::RestrictedUDPSocketMode::BOUND,
             std::move(socket_listener), result, local_addr,
             /*peer_addr=*/std::nullopt);
}

void UDPSocket::FailOpenWith(int32_t error) {
  // Error codes are negative.
  base::UmaHistogramSparse(kUDPNetworkFailuresHistogramName, -error);
  ReleaseResources();

  ScriptState::Scope scope(GetScriptState());
  auto* exception = CreateDOMExceptionFromNetErrorCode(error);
  opened_->Reject(exception);
  GetClosedProperty().Reject(ScriptValue(GetScriptState()->GetIsolate(),
                                         exception->ToV8(GetScriptState())));
}

mojo::PendingReceiver<network::mojom::blink::RestrictedUDPSocket>
UDPSocket::GetUDPSocketReceiver() {
  auto pending_receiver = udp_socket_->get().BindNewPipeAndPassReceiver(
      GetExecutionContext()->GetTaskRunner(TaskType::kNetworking));
  udp_socket_->get().set_disconnect_handler(
      WTF::BindOnce(&UDPSocket::CloseOnError, WrapWeakPersistent(this)));
  return pending_receiver;
}

bool UDPSocket::HasPendingActivity() const {
  if (GetState() != State::kOpen) {
    return false;
  }
  return writable_stream_wrapper_->HasPendingWrite();
}

void UDPSocket::ContextDestroyed() {
  // Release resources as quickly as possible.
  ReleaseResources();
}

void UDPSocket::Trace(Visitor* visitor) const {
  visitor->Trace(udp_socket_);
  visitor->Trace(opened_);
  visitor->Trace(readable_stream_wrapper_);
  visitor->Trace(writable_stream_wrapper_);

  ScriptWrappable::Trace(visitor);
  Socket::Trace(visitor);
  ActiveScriptWrappable::Trace(visitor);
}

void UDPSocket::OnServiceConnectionError() {
  if (GetState() == State::kOpening) {
    FailOpenWith(net::ERR_CONNECTION_FAILED);
    SetState(State::kAborted);
  }
}

void UDPSocket::CloseOnError() {
  DCHECK_EQ(GetState(), State::kOpen);
  readable_stream_wrapper_->ErrorStream(net::ERR_CONNECTION_ABORTED);
  writable_stream_wrapper_->ErrorStream(net::ERR_CONNECTION_ABORTED);
}

void UDPSocket::ReleaseResources() {
  ResetServiceAndFeatureHandle();
  udp_socket_->Close();
}

void UDPSocket::OnBothStreamsClosed(std::vector<ScriptValue> args) {
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
```
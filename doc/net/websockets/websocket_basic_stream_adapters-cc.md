Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to JavaScript, examples of logical reasoning, common errors, and debugging tips. This means we need to understand what the code *does*, *how it fits into a larger context*, and *potential pitfalls*.

2. **High-Level Overview (Skimming):** First, quickly skim the code to get a general idea of its purpose. Keywords like "WebSocket," "StreamSocket," "SpdyStream," and "Quic" jump out. The presence of "Adapter" in the class names suggests that this code is about adapting different underlying stream types to a common interface. The `#include` directives confirm the dependencies.

3. **Identify Core Components (Classes):**  Focus on the classes defined in the file:
    * `WebSocketClientSocketHandleAdapter`: Deals with `StreamSocketHandle`.
    * `WebSocketSpdyStreamAdapter`: Deals with `SpdyStream`.
    * `WebSocketQuicStreamAdapter`: Deals with `WebSocketQuicSpdyStream`.

4. **Analyze Each Class Individually:**  For each class, examine its methods and members:

    * **Constructor/Destructor:**  What are the initialization steps?  What resources are cleaned up? This often reveals the core purpose of the class.
    * **`Read()` and `Write()`:**  These are fundamental for any stream adapter. How does each adapter handle reading and writing data?  Look for differences in how they interact with the underlying stream types.
    * **`Disconnect()`:** How is the connection closed for each type?
    * **`is_initialized()`:**  Is there a concept of initialization for these adapters?
    * **Delegate Methods:**  The `WebSocketSpdyStreamAdapter` and `WebSocketQuicStreamAdapter` have delegate patterns. Understanding the delegate methods (`OnHeadersSent`, `OnHeadersReceived`, `OnDataReceived`, `OnDataSent`, `OnClose`, etc.) is crucial for understanding the event-driven nature of these streams.
    * **Data Buffering:** Notice the `read_data_` member in `WebSocketSpdyStreamAdapter`. This suggests internal buffering of data.
    * **Error Handling:** Look for how errors are managed (`stream_error_`, return values like `ERR_IO_PENDING`).

5. **Infer Functionality:** Based on the analysis of the classes, deduce the file's overall purpose: It provides adapters to unify the interface for different types of underlying network streams used by WebSockets (TCP sockets, SPDY streams, and QUIC streams). This allows higher-level WebSocket code to interact with these different stream types without needing to know the specifics of each.

6. **Relationship to JavaScript:** Consider how WebSockets work in a browser. JavaScript uses the `WebSocket` API. This C++ code is part of the *browser's* networking stack. The connection is: JavaScript API -> Browser's WebSocket implementation (potentially using this code) -> Network. Therefore, this code is *behind the scenes*, enabling the functionality that JavaScript exposes. Focus on the core concepts of sending and receiving data, opening and closing connections, and headers.

7. **Logical Reasoning (Hypothetical Input/Output):** Choose a specific scenario (like reading data with `WebSocketSpdyStreamAdapter`). Trace the execution flow. What happens when `Read()` is called? What are the possible outcomes (data available immediately, needs to wait)? What are the inputs (buffer, length, callback) and possible outputs (number of bytes read, error code)?

8. **Common User/Programming Errors:** Think about how someone might misuse these adapters *from the perspective of the higher-level WebSocket implementation*. Not calling `Read()` after data arrives, calling `Read()` with a zero-length buffer, or writing after the connection is closed are potential errors. Consider errors related to the asynchronous nature of I/O.

9. **Debugging Steps:**  Imagine you're trying to debug a WebSocket connection issue. How would you arrive at this code? Start with user actions (opening a WebSocket in the browser). Trace the path through the browser's network stack. Mention tools like network inspectors. Highlight the asynchronous nature and the role of callbacks.

10. **Structure and Refine:** Organize the findings into the requested categories: Functionality, JavaScript relationship, logical reasoning, errors, and debugging. Use clear and concise language. Provide specific code snippets as examples where relevant. Review and refine the explanations for clarity and accuracy.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file *directly* handles WebSocket protocol details.
* **Correction:** The presence of "Adapter" strongly suggests it's about abstracting underlying transport mechanisms. The delegate pattern further reinforces this.
* **Initial thought:** Focus heavily on the low-level socket details.
* **Correction:** While sockets are involved, the adapters are higher-level abstractions. Focus on the interaction between the adapters and the `SpdyStream`/`WebSocketQuicSpdyStream` objects.
* **Initial thought:**  Overcomplicate the JavaScript relationship.
* **Correction:** Keep the JavaScript explanation focused on the basic connection between the browser's API and the underlying network stack.

By following this systematic approach, breaking down the code into smaller pieces, and thinking about the broader context, we can effectively analyze and explain the functionality of this C++ source file.
这个文件 `net/websockets/websocket_basic_stream_adapters.cc` 在 Chromium 的网络栈中扮演着关键的角色，它定义了一些适配器类，用于将不同类型的底层网络流抽象成一个统一的 `WebSocketBasicStream` 接口。这使得 WebSocket 的上层逻辑可以与各种不同的底层传输机制（例如传统的 TCP socket、SPDY stream 和 QUIC stream）进行交互，而无需关心它们的具体实现细节。

**功能列举:**

1. **抽象底层网络流:**  该文件定义了三个主要的适配器类：
    * `WebSocketClientSocketHandleAdapter`: 封装了传统的 `StreamSocketHandle`，用于基于 TCP 的 WebSocket 连接。
    * `WebSocketSpdyStreamAdapter`: 封装了 `SpdyStream`，用于基于 SPDY (HTTP/2 的前身) 的 WebSocket 连接。
    * `WebSocketQuicStreamAdapter`: 封装了 `WebSocketQuicSpdyStream` (基于 QUIC 的 SPDY 流)，用于基于 QUIC (HTTP/3 的基础) 的 WebSocket 连接。

2. **提供统一的 `WebSocketBasicStream` 接口:** 虽然 `WebSocketBasicStream` 接口本身没有在这个文件中定义（它很可能是一个抽象基类或接口），但这三个适配器都旨在实现或符合这个接口。这个统一的接口可能包含诸如 `Read()`, `Write()`, `Disconnect()`, `is_initialized()` 等方法，用于进行数据的读取、写入、断开连接等操作。

3. **处理特定传输协议的细节:** 每个适配器类都负责处理其底层流的具体细节。例如，`WebSocketSpdyStreamAdapter` 需要处理 SPDY 帧的发送和接收，以及与 `SpdyStream::Delegate` 的交互。`WebSocketQuicStreamAdapter` 则需要与 `WebSocketQuicSpdyStream` 交互，处理 QUIC 特有的头部信息和流控制。

4. **作为 WebSocket 实现与底层网络层的桥梁:** 这些适配器充当了 WebSocket 协议实现和 Chromium 网络栈底层流处理之间的桥梁。上层的 WebSocket 逻辑可以通过这些适配器来发送和接收数据，而无需关心底层是 TCP、SPDY 还是 QUIC。

**与 JavaScript 功能的关系及举例说明:**

这个文件中的 C++ 代码直接支撑着浏览器中 JavaScript WebSocket API 的功能。当 JavaScript 代码使用 `new WebSocket('ws://...')` 或 `new WebSocket('wss://...')` 创建 WebSocket 连接时，Chromium 的网络栈会根据协商的协议选择合适的适配器来处理底层的网络通信。

**举例说明:**

假设一个网页的 JavaScript 代码创建了一个 WebSocket 连接到 `wss://example.com/socket`。

1. **JavaScript 发起连接:**  JavaScript 调用 `new WebSocket(...)`。
2. **浏览器解析 URL:** 浏览器解析 URL，确定需要建立安全 (wss) 的 WebSocket 连接。
3. **协商协议:** 浏览器与服务器进行协议协商，可能协商使用 HTTP/2 (SPDY) 或 HTTP/3 (QUIC)。
4. **选择适配器:**
    * 如果协商结果是 HTTP/2，Chromium 的网络栈会使用 `WebSocketSpdyStreamAdapter` 来处理这个连接。
    * 如果协商结果是 HTTP/3，则会使用 `WebSocketQuicStreamAdapter`。
    * 如果是传统的 `ws://` 连接，则可能使用 `WebSocketClientSocketHandleAdapter`。
5. **数据传输:**
    * 当 JavaScript 代码调用 `websocket.send('hello')` 时，这个字符串数据最终会通过选定的适配器的 `Write()` 方法发送到底层网络。例如，如果使用的是 `WebSocketSpdyStreamAdapter`，`Write()` 方法会调用 `SpdyStream::SendData()` 来发送 SPDY 数据帧。
    * 当服务器向客户端发送数据时，底层网络流接收到数据后，会通过适配器的 Delegate 方法（例如 `WebSocketSpdyStreamAdapter::OnDataReceived()` 或 `WebSocketQuicStreamAdapter::OnBodyAvailable()`）将数据传递给上层的 WebSocket 实现，最终触发 JavaScript 的 `websocket.onmessage` 事件。

**逻辑推理 (假设输入与输出):**

**场景：使用 `WebSocketSpdyStreamAdapter` 读取数据**

* **假设输入:**
    * `WebSocketSpdyStreamAdapter` 已经成功建立连接并接收到一部分数据，这些数据存储在 `read_data_` 内部缓冲区中。
    * JavaScript 代码调用了 `websocket.onmessage` 对应的处理函数，该函数内部需要读取 WebSocket 接收到的数据。
    * 上层的 WebSocket 实现调用 `WebSocketSpdyStreamAdapter` 的 `Read()` 方法，传入一个 `IOBuffer* buf` 指向一块大小为 `buf_len` 的内存，以及一个 `CompletionOnceCallback callback`。
    * 假设 `read_data_` 缓冲区中存在 `N` 字节的数据，且 `N <= buf_len`。

* **逻辑推理:**
    1. `WebSocketSpdyStreamAdapter::Read()` 方法首先检查 `read_data_` 是否为空。在本例中，`read_data_` 不为空。
    2. 调用 `CopySavedReadDataIntoBuffer()` 方法将 `read_data_` 中的数据拷贝到 `buf` 指向的内存中。
    3. `CopySavedReadDataIntoBuffer()` 返回实际拷贝的字节数，即 `N`。
    4. `Read()` 方法立即返回 `N`，表示成功读取了 `N` 字节的数据。
    5. `CompletionOnceCallback` 不会被调用，因为数据已经就绪，不需要等待 I/O。

* **假设输出:** `Read()` 方法返回 `N` (拷贝的字节数)。

**涉及用户或编程常见的使用错误 (举例说明):**

1. **在未建立连接时尝试发送数据:** 用户或编程者可能会在 `websocket.readyState` 状态不是 `OPEN` 的时候调用 `websocket.send()`。虽然 JavaScript 层会进行一些检查，但底层适配器可能会收到尝试写入但连接未建立的请求，导致错误。例如，如果底层使用的是 `WebSocketClientSocketHandleAdapter` 且连接尚未建立，调用 `Write()` 会导致错误，因为底层的 socket 未连接。

2. **在 `Read()` 操作未完成时再次调用 `Read()`:**  适配器的 `Read()` 方法是异步的。如果上层逻辑在 `Read()` 返回 `ERR_IO_PENDING` 后，并且回调尚未执行时，再次调用 `Read()`，可能会导致状态混乱或数据丢失。例如，在 `WebSocketSpdyStreamAdapter` 中，`read_callback_` 会被覆盖，导致之前的读取操作的回调丢失。

3. **忽略 `Write()` 的回调:** `Write()` 操作通常也是异步的，并通过回调通知发送完成或发生错误。如果编程者忽略了这个回调，可能无法正确处理发送失败的情况，例如网络中断。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问了一个使用 WebSocket 的网页，并且遇到了 WebSocket 连接问题。以下是用户操作可能如何一步步地触发到 `websocket_basic_stream_adapters.cc` 中的代码执行，以及作为调试线索的思路：

1. **用户打开网页:** 用户在浏览器地址栏输入网址或点击链接打开网页。
2. **网页加载 JavaScript 代码:** 浏览器下载并执行网页中的 JavaScript 代码。
3. **JavaScript 创建 WebSocket 连接:** JavaScript 代码中使用 `new WebSocket('wss://...')` 创建 WebSocket 对象。
4. **浏览器发起连接请求:**  浏览器网络栈开始处理 WebSocket 连接请求。这涉及到 DNS 解析、TCP 连接建立（如果是基于 TCP 的 WebSocket）、TLS 握手（如果是 `wss://`）。
5. **协议协商:** 浏览器与服务器进行 WebSocket 握手和协议协商，确定使用的子协议和底层传输协议（例如 HTTP/2 或 HTTP/3）。
6. **选择适配器:** 根据协商结果，Chromium 网络栈选择合适的适配器类，例如 `WebSocketSpdyStreamAdapter` 或 `WebSocketQuicStreamAdapter`，来处理这个 WebSocket 连接的底层数据流。
7. **数据发送和接收:**
    * 当 JavaScript 调用 `websocket.send()` 发送数据时，数据会通过选定的适配器的 `Write()` 方法发送。
    * 当服务器发送数据时，底层网络层接收到数据，并调用适配器的 Delegate 方法 (例如 `OnDataReceived` 或 `OnBodyAvailable`) 通知上层。
8. **调试线索:**
    * **网络面板:** 开发者可以使用浏览器的开发者工具中的 "Network" (网络) 面板来查看 WebSocket 连接的状态、发送和接收的帧。这可以帮助确定连接是否成功建立，以及是否有数据传输。
    * **日志记录:** Chromium 网络栈有详细的日志记录机制。通过启用网络相关的日志（例如使用 `--enable-logging --v=1` 启动 Chromium），可以查看更底层的网络事件，包括适配器的创建、`Read()` 和 `Write()` 的调用、以及错误信息。
    * **断点调试:** 如果可以获取到 Chromium 的源代码并进行编译，开发者可以在 `websocket_basic_stream_adapters.cc` 中的关键方法上设置断点，例如 `Read()`, `Write()`, `OnDataReceived()`, `OnBodyAvailable()` 等，来跟踪代码的执行流程，查看变量的值，从而定位问题。例如，如果发现 `OnDataReceived()` 没有被调用，可能表示底层网络连接有问题，或者 SPDY 流存在错误。如果 `Read()` 调用后回调没有被执行，可能表示数据没有到达或者上层逻辑处理存在问题。
    * **检查错误码:**  适配器的 `Read()` 和 `Write()` 方法会返回错误码。例如，返回 `ERR_CONNECTION_CLOSED` 表示连接已关闭。这些错误码可以帮助定位问题的根源。

总而言之，`websocket_basic_stream_adapters.cc` 文件是 Chromium 网络栈中实现 WebSocket 功能的关键组成部分，它通过提供适配器模式，使得 WebSocket 的上层逻辑可以更加灵活地与不同的底层网络传输机制进行交互。 理解这个文件的功能和工作原理，对于调试 WebSocket 相关的网络问题至关重要。

### 提示词
```
这是目录为net/websockets/websocket_basic_stream_adapters.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_basic_stream_adapters.h"

#include <cstring>
#include <ostream>
#include <utility>

#include "base/check.h"
#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/io_buffer.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/stream_socket.h"
#include "net/socket/stream_socket_handle.h"
#include "net/spdy/spdy_buffer.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/quic_header_list.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_ack_listener_interface.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_error_codes.h"
#include "net/websockets/websocket_quic_spdy_stream.h"

namespace net {
struct NetworkTrafficAnnotationTag;

WebSocketClientSocketHandleAdapter::WebSocketClientSocketHandleAdapter(
    std::unique_ptr<StreamSocketHandle> connection)
    : connection_(std::move(connection)) {}

WebSocketClientSocketHandleAdapter::~WebSocketClientSocketHandleAdapter() =
    default;

int WebSocketClientSocketHandleAdapter::Read(IOBuffer* buf,
                                             int buf_len,
                                             CompletionOnceCallback callback) {
  return connection_->socket()->Read(buf, buf_len, std::move(callback));
}

int WebSocketClientSocketHandleAdapter::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  return connection_->socket()->Write(buf, buf_len, std::move(callback),
                                      traffic_annotation);
}

void WebSocketClientSocketHandleAdapter::Disconnect() {
  connection_->socket()->Disconnect();
}

bool WebSocketClientSocketHandleAdapter::is_initialized() const {
  return connection_->is_initialized();
}

WebSocketSpdyStreamAdapter::WebSocketSpdyStreamAdapter(
    base::WeakPtr<SpdyStream> stream,
    Delegate* delegate,
    NetLogWithSource net_log)
    : stream_(stream), delegate_(delegate), net_log_(net_log) {
  stream_->SetDelegate(this);
}

WebSocketSpdyStreamAdapter::~WebSocketSpdyStreamAdapter() {
  if (stream_) {
    // DetachDelegate() also cancels the stream.
    stream_->DetachDelegate();
  }
}

void WebSocketSpdyStreamAdapter::DetachDelegate() {
  delegate_ = nullptr;
}

int WebSocketSpdyStreamAdapter::Read(IOBuffer* buf,
                                     int buf_len,
                                     CompletionOnceCallback callback) {
  DCHECK(!read_callback_);
  DCHECK_LT(0, buf_len);

  DCHECK(!read_buffer_);
  read_buffer_ = buf;
  // |read_length_| is size_t and |buf_len| is a non-negative int, therefore
  // conversion is always valid.
  DCHECK(!read_length_);
  read_length_ = buf_len;

  if (!read_data_.IsEmpty())
    return CopySavedReadDataIntoBuffer();

  if (!stream_)
    return stream_error_;

  read_callback_ = std::move(callback);
  return ERR_IO_PENDING;
}

int WebSocketSpdyStreamAdapter::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  CHECK(headers_sent_);
  DCHECK(!write_callback_);
  DCHECK(callback);
  DCHECK_LT(0, buf_len);

  if (!stream_)
    return stream_error_;

  stream_->SendData(buf, buf_len, MORE_DATA_TO_SEND);
  write_callback_ = std::move(callback);
  write_length_ = buf_len;
  return ERR_IO_PENDING;
}

void WebSocketSpdyStreamAdapter::Disconnect() {
  if (stream_) {
    stream_->DetachDelegate();
    stream_ = nullptr;
  }
}

bool WebSocketSpdyStreamAdapter::is_initialized() const {
  return true;
}

// SpdyStream::Delegate methods.
void WebSocketSpdyStreamAdapter::OnHeadersSent() {
  headers_sent_ = true;
  if (delegate_)
    delegate_->OnHeadersSent();
}

void WebSocketSpdyStreamAdapter::OnEarlyHintsReceived(
    const quiche::HttpHeaderBlock& headers) {
  // This callback should not be called for a WebSocket handshake.
  NOTREACHED();
}

void WebSocketSpdyStreamAdapter::OnHeadersReceived(
    const quiche::HttpHeaderBlock& response_headers) {
  if (delegate_)
    delegate_->OnHeadersReceived(response_headers);
}

void WebSocketSpdyStreamAdapter::OnDataReceived(
    std::unique_ptr<SpdyBuffer> buffer) {
  if (!buffer) {
    // This is slightly wrong semantically, as it's still possible to write to
    // the stream at this point. However, if the server closes the stream
    // without waiting for a close frame from us, that means it is not
    // interested in a clean shutdown. In which case we don't need to worry
    // about sending any remaining data we might have buffered. This results in
    // a call to OnClose() which then informs our delegate.
    stream_->Close();
    return;
  }

  read_data_.Enqueue(std::move(buffer));
  if (read_callback_)
    std::move(read_callback_).Run(CopySavedReadDataIntoBuffer());
}

void WebSocketSpdyStreamAdapter::OnDataSent() {
  DCHECK(write_callback_);

  std::move(write_callback_).Run(write_length_);
}

void WebSocketSpdyStreamAdapter::OnTrailers(
    const quiche::HttpHeaderBlock& trailers) {}

void WebSocketSpdyStreamAdapter::OnClose(int status) {
  DCHECK_NE(ERR_IO_PENDING, status);
  DCHECK_LE(status, 0);

  if (status == OK) {
    status = ERR_CONNECTION_CLOSED;
  }

  stream_error_ = status;
  stream_ = nullptr;

  auto self = weak_factory_.GetWeakPtr();

  if (read_callback_) {
    DCHECK(read_data_.IsEmpty());
    // Might destroy |this|.
    std::move(read_callback_).Run(status);
    if (!self)
      return;
  }
  if (write_callback_) {
    // Might destroy |this|.
    std::move(write_callback_).Run(status);
    if (!self)
      return;
  }

  // Delay calling delegate_->OnClose() until all buffered data are read.
  if (read_data_.IsEmpty() && delegate_) {
    // Might destroy |this|.
    delegate_->OnClose(status);
  }
}

bool WebSocketSpdyStreamAdapter::CanGreaseFrameType() const {
  return false;
}

NetLogSource WebSocketSpdyStreamAdapter::source_dependency() const {
  return net_log_.source();
}

int WebSocketSpdyStreamAdapter::CopySavedReadDataIntoBuffer() {
  DCHECK(read_buffer_);
  DCHECK(read_length_);
  int rv = read_data_.Dequeue(read_buffer_->data(), read_length_);
  read_buffer_ = nullptr;
  read_length_ = 0u;

  // Stream has been destroyed earlier but delegate_->OnClose() call was
  // delayed until all buffered data are read.  PostTask so that Read() can
  // return beforehand.
  if (!stream_ && delegate_ && read_data_.IsEmpty()) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&WebSocketSpdyStreamAdapter::CallDelegateOnClose,
                       weak_factory_.GetWeakPtr()));
  }

  return rv;
}

void WebSocketSpdyStreamAdapter::CallDelegateOnClose() {
  if (delegate_)
    delegate_->OnClose(stream_error_);
}

WebSocketQuicStreamAdapter::WebSocketQuicStreamAdapter(
    WebSocketQuicSpdyStream* websocket_quic_spdy_stream,
    Delegate* delegate)
    : websocket_quic_spdy_stream_(websocket_quic_spdy_stream),
      delegate_(delegate) {
  websocket_quic_spdy_stream_->set_delegate(this);
}

WebSocketQuicStreamAdapter::~WebSocketQuicStreamAdapter() {
  if (websocket_quic_spdy_stream_) {
    websocket_quic_spdy_stream_->set_delegate(nullptr);
  }
}

size_t WebSocketQuicStreamAdapter::WriteHeaders(
    quiche::HttpHeaderBlock header_block,
    bool fin) {
  return websocket_quic_spdy_stream_->WriteHeaders(std::move(header_block), fin,
                                                   nullptr);
}

// WebSocketBasicStream::Adapter methods.
int WebSocketQuicStreamAdapter::Read(IOBuffer* buf,
                                     int buf_len,
                                     CompletionOnceCallback callback) {
  if (!websocket_quic_spdy_stream_) {
    return ERR_UNEXPECTED;
  }

  int rv = websocket_quic_spdy_stream_->Read(buf, buf_len);
  if (rv != ERR_IO_PENDING) {
    return rv;
  }

  read_callback_ = std::move(callback);
  read_buffer_ = buf;
  read_length_ = buf_len;
  return ERR_IO_PENDING;
}

int WebSocketQuicStreamAdapter::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  // TODO(momoka): Write implementation.
  return OK;
}

void WebSocketQuicStreamAdapter::Disconnect() {
  if (websocket_quic_spdy_stream_) {
    websocket_quic_spdy_stream_->Reset(quic::QUIC_STREAM_CANCELLED);
  }
}

bool WebSocketQuicStreamAdapter::is_initialized() const {
  return true;
}

// WebSocketQuicSpdyStream::Delegate methods.

void WebSocketQuicStreamAdapter::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const quic::QuicHeaderList& quic_header_list) {
  quiche::HttpHeaderBlock response_headers;
  if (!quic::SpdyUtils::CopyAndValidateHeaders(quic_header_list, nullptr,
                                               &response_headers)) {
    DLOG(ERROR) << "Failed to parse header list: "
                << quic_header_list.DebugString();
    websocket_quic_spdy_stream_->ConsumeHeaderList();
    websocket_quic_spdy_stream_->Reset(quic::QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }
  websocket_quic_spdy_stream_->ConsumeHeaderList();
  delegate_->OnHeadersReceived(response_headers);
}

void WebSocketQuicStreamAdapter::OnBodyAvailable() {
  if (!websocket_quic_spdy_stream_->FinishedReadingHeaders()) {
    // Buffer the data in the sequencer until the headers have been read.
    return;
  }

  if (!websocket_quic_spdy_stream_->HasBytesToRead()) {
    return;
  }

  if (!read_callback_) {
    // Wait for Read() to be called.
    return;
  }

  DCHECK(read_buffer_);
  DCHECK_GT(read_length_, 0);

  int rv = websocket_quic_spdy_stream_->Read(read_buffer_, read_length_);

  if (rv == ERR_IO_PENDING) {
    return;
  }

  read_buffer_ = nullptr;
  read_length_ = 0;
  std::move(read_callback_).Run(rv);
}

void WebSocketQuicStreamAdapter::ClearStream() {
  if (websocket_quic_spdy_stream_) {
    websocket_quic_spdy_stream_ = nullptr;
  }
}

}  // namespace net
```
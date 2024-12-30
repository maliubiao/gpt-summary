Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The core request is to analyze the functionality of `BidirectionalStreamQuicImpl.cc`, identify its relationship with JavaScript (if any), infer logic with input/output examples, point out potential user errors, and trace how a user might reach this code.

2. **High-Level Overview:**  Start by reading the header comments and the class name. "BidirectionalStreamQuicImpl" strongly suggests this class implements a bidirectional communication stream using the QUIC protocol. The "Impl" suffix often indicates an implementation detail within a larger system.

3. **Key Dependencies:** Look at the `#include` directives. This tells us what other components this code interacts with:
    * `<utility>`: Standard C++ utilities.
    * `base/functional/bind.h`, `base/location.h`, `base/logging.h`, `base/memory/raw_ptr.h`, `base/task/single_thread_task_runner.h`, `base/timer/timer.h`: Chromium base library components for functionality like callbacks, logging, memory management, threading, and timers.
    * `net/http/bidirectional_stream_request_info.h`, `net/http/http_util.h`:  HTTP-related structures and utilities.
    * `net/socket/next_proto.h`:  For negotiating protocols (like HTTP/3 via QUIC).
    * `net/spdy/spdy_http_utils.h`:  Utilities for converting HTTP headers to the SPDY/HTTP/2 format (which QUIC borrows from).
    * `net/third_party/quiche/src/quiche/quic/core/quic_connection.h`: The core QUIC library interface.
    * `quic_http_stream.h`: Likely a Chromium-specific wrapper around the core QUIC functionality.

4. **Core Class Functionality (Public Interface):** Examine the public methods of `BidirectionalStreamQuicImpl`:
    * `BidirectionalStreamQuicImpl()`: Constructor. Takes a `QuicChromiumClientSession::Handle`. This immediately suggests it's associated with an existing QUIC session.
    * `~BidirectionalStreamQuicImpl()`: Destructor. Handles cleanup, notably resetting the QUIC stream if it exists.
    * `Start()`: Initiates the stream. Takes request information, a delegate (for callbacks), and other parameters. This is a crucial entry point.
    * `SendRequestHeaders()`:  Explicitly sends the request headers.
    * `WriteHeaders()`: (Private, but important):  The actual logic to format and send headers.
    * `ReadData()`: Reads data from the stream. Uses asynchronous callbacks.
    * `SendvData()`: Sends data on the stream. Supports sending data in chunks.
    * `GetProtocol()`: Returns the negotiated protocol.
    * `GetTotalReceivedBytes()`, `GetTotalSentBytes()`:  Metrics about the stream.
    * `GetLoadTimingInfo()`: Provides timing information relevant to network requests.
    * `PopulateNetErrorDetails()`:  Fills in details about network errors.

5. **Internal Mechanics (Private Methods and Members):** Look at the private parts:
    * `delegate_`:  A pointer to a `BidirectionalStreamImpl::Delegate`. This is the mechanism for informing the higher layers about events (data received, errors, etc.).
    * `stream_`:  A `QuicHttpStream*`. This is the core QUIC stream object.
    * `request_info_`:  Stores information about the HTTP request.
    * `OnStreamReady()`, `OnSendDataComplete()`, `OnReadDataComplete()`, etc.: These are callback methods triggered by the `QuicHttpStream` when events occur.
    * `NotifyError()`, `NotifyFailure()`: Handle error reporting.
    * `ScopedBoolSaver`: A helper class to temporarily change a boolean value and restore it. This is used to control when callbacks are allowed.

6. **JavaScript Relationship:**  Consider how this C++ code might be used in a browser context. JavaScript in a web page doesn't directly call this C++ code. Instead, JavaScript interacts with browser APIs (like `fetch` or `XMLHttpRequest`). These APIs are implemented in C++ and might eventually utilize code like this for QUIC connections. The connection is *indirect*.

7. **Logic Inference and Examples:**  Pick a key function like `Start()` and trace its execution flow. Consider different scenarios:
    * **Successful Start:** The session is connected, `RequestStream` returns `OK`, `OnStreamReady` is called, headers are read, etc.
    * **Error During Start:** `RequestStream` returns an error (e.g., connection refused), `NotifyError` is called.
    * **Sending Data:** `SendvData` is called, headers might be sent first, data is written to the stream.
    * **Receiving Data:** `ReadData` is called, data arrives, `OnReadDataComplete` is invoked.

8. **User/Programming Errors:** Think about common mistakes when using network APIs:
    * Trying to send data before the stream is ready.
    * Providing invalid buffers to `ReadData` or `SendvData`.
    * Not handling errors reported by the delegate.
    * Incorrectly configuring request headers.

9. **User Actions and Debugging:**  How does a user's action trigger this code? A user clicks a link, submits a form, or a website uses JavaScript to make an API call. Debugging involves examining network logs, using browser developer tools, and potentially stepping through the C++ code.

10. **Structure and Refine:** Organize the findings into clear sections as requested: Functionality, JavaScript relationship, logic examples, user errors, and debugging. Use precise language and code references where appropriate.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe JavaScript directly calls this."  **Correction:** Realized the interaction is through browser APIs.
* **Initial thought:** "Focus only on public methods." **Correction:**  Recognized the importance of understanding private methods and callbacks to fully grasp the implementation.
* **While tracing `Start()`:**  Initially missed the early data optimization. Went back and added that detail.
* **Reviewing error handling:**  Ensured the explanations covered both synchronous and asynchronous error reporting.

By following this structured approach, combining code reading with conceptual understanding, and considering different perspectives (user, programmer, debugger), a comprehensive analysis like the example provided can be developed.
好的，让我们来分析一下 `net/quic/bidirectional_stream_quic_impl.cc` 这个文件。

**功能概述**

`BidirectionalStreamQuicImpl` 类是 Chromium 网络栈中用于实现基于 QUIC 协议的双向流的核心组件。它负责处理客户端发起的双向 QUIC 流的生命周期，包括：

1. **流的建立和管理:**
   -  与 `QuicChromiumClientSession` 建立关联，管理 QUIC 会话中的单个流。
   -  处理流的创建、打开和关闭。
   -  维护流的状态信息，如是否已发送/接收头部，发送/接收的字节数等。

2. **发送请求头:**
   -  将 `BidirectionalStreamRequestInfo` 中包含的 HTTP 请求信息转换为 QUIC 的头部格式（通常是 SPDY 格式）。
   -  通过底层的 `QuicHttpStream` 发送请求头。
   -  支持自动发送请求头或手动触发发送。

3. **发送和接收数据:**
   -  提供 `SendvData` 方法用于发送数据，支持分段发送。
   -  提供 `ReadData` 方法用于接收数据，使用回调机制异步处理。

4. **处理头部和尾部:**
   -  异步读取服务器响应的初始头部和尾部（trailers）。
   -  通过委托 (`Delegate`) 通知上层接收到的头部和尾部信息。

5. **错误处理:**
   -  处理流过程中发生的各种错误，例如连接关闭、流被取消等。
   -  通过委托通知上层发生的错误。

6. **提供性能指标:**
   -  记录已发送和接收的字节数。
   -  获取连接相关的性能信息，如连接时间。

7. **集成 NetLog:**
   -  使用 Chromium 的 NetLog 机制记录关键事件，用于调试和性能分析。

**与 JavaScript 的关系**

`BidirectionalStreamQuicImpl` 本身是用 C++ 编写的，JavaScript 代码无法直接调用它。但是，它在浏览器网络栈中扮演着重要的角色，支持着由 JavaScript 发起的网络请求。以下是它们之间的间接关系：

**举例说明：**

假设你在网页中使用 `fetch` API 发起一个使用了 HTTP/3 (基于 QUIC) 的双向流请求：

```javascript
fetch('https://example.com/api/stream', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ message: 'Hello from JavaScript' }),
  duplex: 'half' //  表示这是一个双向流
})
.then(response => {
  const reader = response.body.getReader();
  return new ReadableStream({
    start(controller) {
      function push() {
        reader.read().then(({ done, value }) => {
          if (done) {
            controller.close();
            return;
          }
          controller.enqueue(value);
          push();
        });
      }
      push();
    }
  })
})
.then(stream => new Response(stream))
.then(response => response.text())
.then(result => console.log('Response:', result))
.catch(error => console.error('Error:', error));

// 同时，你可能也会通过 response.body.getWriter() 向服务器发送数据
```

在这个过程中，以下步骤会间接涉及到 `BidirectionalStreamQuicImpl`：

1. **`fetch` API 调用:** JavaScript 的 `fetch` 调用会被浏览器内核的网络层处理。
2. **协议协商:**  如果服务器支持 HTTP/3，浏览器会尝试与服务器建立 QUIC 连接。
3. **创建 QUIC 流:** 一旦 QUIC 连接建立，当需要发起请求时，Chromium 网络栈会创建 `BidirectionalStreamQuicImpl` 的实例来处理这个双向流。
4. **发送请求头:**  `BidirectionalStreamQuicImpl` 会将 `fetch` 请求中的 `method`、`headers` 等信息转换为 QUIC 可以理解的格式，并通过 `WriteHeaders` 发送出去。
5. **发送请求体:**  `fetch` 的 `body` 中的数据会通过 `SendvData` 发送到服务器。
6. **接收响应头:** 服务器的响应头会被 `BidirectionalStreamQuicImpl` 接收并解析，然后传递给 JavaScript 的 `response` 对象。
7. **接收响应体:**  服务器发送的响应数据会通过 `ReadData` 接收，并通过 `ReadableStream` 传递给 JavaScript。
8. **错误处理:** 如果请求过程中发生错误（例如网络中断），`BidirectionalStreamQuicImpl` 会捕获错误并通过其 `Delegate` 通知上层，最终可能导致 `fetch` 的 Promise 被 reject。

**逻辑推理和假设输入/输出**

**场景：成功发送和接收数据**

**假设输入：**

- `BidirectionalStreamRequestInfo`:  包含请求的 URL、方法 (POST)、头部信息 (`Content-Type: application/json`) 等。
- 要发送的数据 (JavaScript 的 `body`):  `"{\"key\": \"value\"}"`
- 服务器返回的数据: `"{\"status\": \"ok\"}"`

**执行流程（简化）：**

1. `Start` 被调用，初始化流。
2. `SendRequestHeaders` 或 `WriteHeaders` 被调用，发送请求头。
   - **输出 (发送到网络):** 包含请求方法、URL 和头部信息的 QUIC 帧。
3. `SendvData` 被调用，发送请求体。
   - **输出 (发送到网络):** 包含 `"{\"key\": \"value\"}"` 的 QUIC 帧。
4. 服务器处理请求并发送响应。
5. `ReadInitialHeadersComplete` 被调用，解析响应头。
   - **输出 (传递给 Delegate):**  HTTP 响应头，例如 `status: 200 OK`, `Content-Type: application/json`。
6. `ReadData` 被调用，开始接收响应体。
7. `OnReadDataComplete` 被多次调用，接收到数据片段。
   - **输出 (传递给 Delegate):**  `"{\"status\": \"ok\"}"` 的数据块。
8. 流关闭。

**场景：发送请求头时发生错误**

**假设输入：**

- `BidirectionalStreamRequestInfo`:  包含一个无效的头部值。
- 网络连接正常。

**执行流程（简化）：**

1. `Start` 被调用。
2. `SendRequestHeaders` 或 `WriteHeaders` 被调用。
3. `WriteHeaders` 在尝试创建 QUIC 头部时遇到错误（例如，头部值过长）。
   - **输出 (返回值):** 负的错误码，例如 `ERR_INVALID_ARGUMENT`。
4. `NotifyError` 被调用，通知错误。
   - **输出 (调用 Delegate 的方法):** `OnFailed` 方法被调用，传递相应的错误码。

**用户或编程常见的使用错误**

1. **在流未就绪前发送数据:**  用户或上层代码可能在 `OnStreamReady` 回调之前就尝试调用 `SendvData`。这会导致错误，因为底层的 QUIC 流可能尚未建立完成。
   - **错误示例:** 在 `Start` 方法返回后立即调用 `SendvData`，而没有等待 `delegate_->OnStreamReady()` 被调用。

2. **多次调用 `SendRequestHeaders`:**  `SendRequestHeaders` 应该只被调用一次。多次调用可能会导致不可预测的行为或错误。
   - **错误示例:** 在 `send_request_headers_automatically_` 为 `false` 的情况下，用户手动调用 `SendRequestHeaders`，然后又在其他地方错误地再次调用。

3. **提供的缓冲区无效:**  传递给 `ReadData` 或 `SendvData` 的 `IOBuffer` 可能为空或大小不正确。
   - **错误示例:** `ReadData(nullptr, 1024)` 或 `SendvData({buffer}, {0}, false)`.

4. **未正确处理 Delegate 的回调:**  上层代码可能没有正确实现 `BidirectionalStreamImpl::Delegate` 接口，导致无法处理接收到的数据或错误。
   - **错误示例:** `OnDataRead` 方法没有实际读取 `buffer` 中的数据。

5. **尝试在流关闭后进行操作:**  在流已经关闭后（例如，接收到 FIN 或发生错误），仍然尝试发送或接收数据。
   - **错误示例:** 在 `OnClosed` 回调之后调用 `SendvData`。

**用户操作如何一步步到达这里（作为调试线索）**

1. **用户在浏览器中输入 URL 并访问一个使用 HTTP/3 的网站。**
   - 浏览器会尝试与服务器建立 QUIC 连接。
2. **用户点击网页上的一个链接或提交一个表单，触发一个新的网络请求。**
   - 如果已建立 QUIC 连接，浏览器会尝试复用该连接。
3. **JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个请求。**
   -  `fetch` 的 `duplex: 'half'` 或 `'full'` 选项可能会指示需要双向流。
4. **Chromium 网络栈根据请求信息，选择使用 QUIC 协议，并创建一个 `BidirectionalStreamQuicImpl` 实例。**
   - 构造函数会接收一个 `QuicChromiumClientSession::Handle`。
5. **调用 `Start` 方法，传递请求信息和 Delegate。**
6. **根据 `send_request_headers_automatically_` 的值，可能会自动或等待手动调用 `SendRequestHeaders`。**
7. **如果需要发送数据（例如 POST 请求），JavaScript 代码会将数据传递给 C++ 层，最终调用 `SendvData`。**
8. **服务器的响应数据通过 QUIC 连接到达，`BidirectionalStreamQuicImpl` 的回调方法会被触发 (`OnReadInitialHeadersComplete`, `OnDataReadComplete`)。**
9. **Delegate 的相应方法被调用，将数据或事件传递回上层 C++ 代码，最终可能传递到渲染进程，供 JavaScript 使用。**
10. **如果过程中发生错误，例如服务器拒绝连接或发送无效数据，`NotifyError` 会被调用，并通过 Delegate 通知错误。**

**调试线索:**

- **NetLog:**  启用 Chromium 的 NetLog (chrome://net-export/) 可以详细记录网络请求的各个阶段，包括 QUIC 连接和流的建立、数据发送接收、错误信息等。在 NetLog 中搜索与该请求相关的事件，可以查看是否成功创建了 QUIC 流，以及在哪个阶段发生了问题。
- **断点调试:**  在 `BidirectionalStreamQuicImpl` 的关键方法（如 `Start`, `WriteHeaders`, `SendvData`, `ReadData`, 以及各种回调方法）设置断点，可以单步跟踪代码执行流程，查看变量的值，分析逻辑是否正确。
- **QUIC 连接和流 ID:**  在调试信息中关注 QUIC 连接 ID 和流 ID，可以帮助你将特定的操作关联到特定的 QUIC 连接和流。
- **错误码:**  注意观察 Delegate 回调中传递的错误码，这能提供关于错误的线索。例如，`ERR_QUIC_PROTOCOL_ERROR` 表示 QUIC 协议层面的错误。

希望这个详细的分析能够帮助你理解 `BidirectionalStreamQuicImpl` 的功能和在 Chromium 网络栈中的作用。

Prompt: 
```
这是目录为net/quic/bidirectional_stream_quic_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/bidirectional_stream_quic_impl.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/timer/timer.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/http/http_util.h"
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_connection.h"
#include "quic_http_stream.h"

namespace net {
namespace {
// Sets a boolean to a value, and restores it to the previous value once
// the saver goes out of scope.
class ScopedBoolSaver {
 public:
  ScopedBoolSaver(bool* var, bool new_val) : var_(var), old_val_(*var) {
    *var_ = new_val;
  }

  ~ScopedBoolSaver() { *var_ = old_val_; }

 private:
  raw_ptr<bool> var_;
  bool old_val_;
};
}  // namespace

BidirectionalStreamQuicImpl::BidirectionalStreamQuicImpl(
    std::unique_ptr<QuicChromiumClientSession::Handle> session)
    : session_(std::move(session)) {}

BidirectionalStreamQuicImpl::~BidirectionalStreamQuicImpl() {
  if (stream_) {
    delegate_ = nullptr;
    stream_->Reset(quic::QUIC_STREAM_CANCELLED);
  }
}

void BidirectionalStreamQuicImpl::Start(
    const BidirectionalStreamRequestInfo* request_info,
    const NetLogWithSource& net_log,
    bool send_request_headers_automatically,
    BidirectionalStreamImpl::Delegate* delegate,
    std::unique_ptr<base::OneShotTimer> timer,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  ScopedBoolSaver saver(&may_invoke_callbacks_, false);
  DCHECK(!stream_);
  CHECK(delegate);
  DLOG_IF(WARNING, !session_->IsConnected())
      << "Trying to start request headers after session has been closed.";

  net_log.AddEventReferencingSource(
      NetLogEventType::BIDIRECTIONAL_STREAM_BOUND_TO_QUIC_SESSION,
      session_->net_log().source());

  send_request_headers_automatically_ = send_request_headers_automatically;
  delegate_ = delegate;
  request_info_ = request_info;

  // Only allow SAFE methods to use early data, unless overridden by the caller.
  bool use_early_data = HttpUtil::IsMethodSafe(request_info_->method);
  use_early_data |= request_info_->allow_early_data_override;

  int rv = session_->RequestStream(
      !use_early_data,
      base::BindOnce(&BidirectionalStreamQuicImpl::OnStreamReady,
                     weak_factory_.GetWeakPtr()),
      traffic_annotation);
  if (rv == ERR_IO_PENDING)
    return;

  if (rv != OK) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &BidirectionalStreamQuicImpl::NotifyError,
            weak_factory_.GetWeakPtr(),
            session_->OneRttKeysAvailable() ? rv : ERR_QUIC_HANDSHAKE_FAILED));
    return;
  }

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&BidirectionalStreamQuicImpl::OnStreamReady,
                                weak_factory_.GetWeakPtr(), rv));
}

void BidirectionalStreamQuicImpl::SendRequestHeaders() {
  ScopedBoolSaver saver(&may_invoke_callbacks_, false);
  int rv = WriteHeaders();
  if (rv < 0) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&BidirectionalStreamQuicImpl::NotifyError,
                                  weak_factory_.GetWeakPtr(), rv));
  }
}

int BidirectionalStreamQuicImpl::WriteHeaders() {
  DCHECK(!has_sent_headers_);

  quiche::HttpHeaderBlock headers;
  HttpRequestInfo http_request_info;
  http_request_info.url = request_info_->url;
  http_request_info.method = request_info_->method;
  http_request_info.extra_headers = request_info_->extra_headers;

  CreateSpdyHeadersFromHttpRequest(http_request_info, std::nullopt,
                                   http_request_info.extra_headers, &headers);
  int rv = stream_->WriteHeaders(std::move(headers),
                                 request_info_->end_stream_on_headers, nullptr);
  if (rv >= 0) {
    headers_bytes_sent_ += rv;
    has_sent_headers_ = true;
  }
  return rv;
}

int BidirectionalStreamQuicImpl::ReadData(IOBuffer* buffer, int buffer_len) {
  ScopedBoolSaver saver(&may_invoke_callbacks_, false);
  DCHECK(buffer);
  DCHECK(buffer_len);

  int rv = stream_->ReadBody(
      buffer, buffer_len,
      base::BindOnce(&BidirectionalStreamQuicImpl::OnReadDataComplete,
                     weak_factory_.GetWeakPtr()));
  if (rv == ERR_IO_PENDING) {
    read_buffer_ = buffer;
    read_buffer_len_ = buffer_len;
    return ERR_IO_PENDING;
  }

  if (rv < 0)
    return rv;

  // If the write side is closed, OnFinRead() will call
  // BidirectionalStreamQuicImpl::OnClose().
  if (stream_->IsDoneReading())
    stream_->OnFinRead();

  return rv;
}

void BidirectionalStreamQuicImpl::SendvData(
    const std::vector<scoped_refptr<IOBuffer>>& buffers,
    const std::vector<int>& lengths,
    bool end_stream) {
  ScopedBoolSaver saver(&may_invoke_callbacks_, false);
  DCHECK_EQ(buffers.size(), lengths.size());

  if (!stream_->IsOpen()) {
    LOG(ERROR) << "Trying to send data after stream has been closed.";
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&BidirectionalStreamQuicImpl::NotifyError,
                                  weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
    return;
  }

  std::unique_ptr<quic::QuicConnection::ScopedPacketFlusher> bundler(
      session_->CreatePacketBundler());
  if (!has_sent_headers_) {
    DCHECK(!send_request_headers_automatically_);
    int rv = WriteHeaders();
    if (rv < 0) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&BidirectionalStreamQuicImpl::NotifyError,
                                    weak_factory_.GetWeakPtr(), rv));
      return;
    }
  }

  int rv = stream_->WritevStreamData(
      buffers, lengths, end_stream,
      base::BindOnce(&BidirectionalStreamQuicImpl::OnSendDataComplete,
                     weak_factory_.GetWeakPtr()));

  if (rv != ERR_IO_PENDING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&BidirectionalStreamQuicImpl::OnSendDataComplete,
                       weak_factory_.GetWeakPtr(), rv));
  }
}

NextProto BidirectionalStreamQuicImpl::GetProtocol() const {
  return negotiated_protocol_;
}

int64_t BidirectionalStreamQuicImpl::GetTotalReceivedBytes() const {
  if (stream_) {
    DCHECK_LE(stream_->NumBytesConsumed(), stream_->stream_bytes_read());
    // Only count the uniquely received bytes.
    return stream_->NumBytesConsumed();
  }
  return closed_stream_received_bytes_;
}

int64_t BidirectionalStreamQuicImpl::GetTotalSentBytes() const {
  if (stream_) {
    return stream_->stream_bytes_written();
  }
  return closed_stream_sent_bytes_;
}

bool BidirectionalStreamQuicImpl::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  bool is_first_stream = closed_is_first_stream_;
  if (stream_)
    is_first_stream = stream_->IsFirstStream();
  if (is_first_stream) {
    load_timing_info->socket_reused = false;
    load_timing_info->connect_timing = connect_timing_;
  } else {
    load_timing_info->socket_reused = true;
  }
  return true;
}

void BidirectionalStreamQuicImpl::PopulateNetErrorDetails(
    NetErrorDetails* details) {
  DCHECK(details);
  details->connection_info =
      QuicHttpStream::ConnectionInfoFromQuicVersion(session_->GetQuicVersion());
  session_->PopulateNetErrorDetails(details);
  if (session_->OneRttKeysAvailable() && stream_)
    details->quic_connection_error = stream_->connection_error();
}

void BidirectionalStreamQuicImpl::OnStreamReady(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  DCHECK(!stream_);
  if (rv != OK) {
    NotifyError(rv);
    return;
  }

  stream_ = session_->ReleaseStream();
  DCHECK(stream_);

  if (!stream_->IsOpen()) {
    NotifyError(ERR_CONNECTION_CLOSED);
    return;
  }

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&BidirectionalStreamQuicImpl::ReadInitialHeaders,
                     weak_factory_.GetWeakPtr()));

  NotifyStreamReady();
}

void BidirectionalStreamQuicImpl::OnSendDataComplete(int rv) {
  CHECK(may_invoke_callbacks_);
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (rv < 0) {
    NotifyError(rv);
    return;
  }

  if (delegate_)
    delegate_->OnDataSent();
}

void BidirectionalStreamQuicImpl::OnReadInitialHeadersComplete(int rv) {
  CHECK(may_invoke_callbacks_);
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (rv < 0) {
    NotifyError(rv);
    return;
  }

  headers_bytes_received_ += rv;
  negotiated_protocol_ = kProtoQUIC;
  connect_timing_ = session_->GetConnectTiming();
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&BidirectionalStreamQuicImpl::ReadTrailingHeaders,
                     weak_factory_.GetWeakPtr()));
  if (delegate_)
    delegate_->OnHeadersReceived(initial_headers_);
}

void BidirectionalStreamQuicImpl::ReadInitialHeaders() {
  int rv = stream_->ReadInitialHeaders(
      &initial_headers_,
      base::BindOnce(&BidirectionalStreamQuicImpl::OnReadInitialHeadersComplete,
                     weak_factory_.GetWeakPtr()));

  if (rv != ERR_IO_PENDING)
    OnReadInitialHeadersComplete(rv);
}

void BidirectionalStreamQuicImpl::ReadTrailingHeaders() {
  int rv = stream_->ReadTrailingHeaders(
      &trailing_headers_,
      base::BindOnce(
          &BidirectionalStreamQuicImpl::OnReadTrailingHeadersComplete,
          weak_factory_.GetWeakPtr()));

  if (rv != ERR_IO_PENDING)
    OnReadTrailingHeadersComplete(rv);
}

void BidirectionalStreamQuicImpl::OnReadTrailingHeadersComplete(int rv) {
  CHECK(may_invoke_callbacks_);
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (rv < 0) {
    NotifyError(rv);
    return;
  }

  headers_bytes_received_ += rv;

  if (delegate_)
    delegate_->OnTrailersReceived(trailing_headers_);
}

void BidirectionalStreamQuicImpl::OnReadDataComplete(int rv) {
  CHECK(may_invoke_callbacks_);

  read_buffer_ = nullptr;
  read_buffer_len_ = 0;

  // If the write side is closed, OnFinRead() will call
  // BidirectionalStreamQuicImpl::OnClose().
  if (stream_->IsDoneReading())
    stream_->OnFinRead();

  if (!delegate_)
    return;

  if (rv < 0)
    NotifyError(rv);
  else
    delegate_->OnDataRead(rv);
}

void BidirectionalStreamQuicImpl::NotifyError(int error) {
  NotifyErrorImpl(error, /*notify_delegate_later*/ false);
}

void BidirectionalStreamQuicImpl::NotifyErrorImpl(int error,
                                                  bool notify_delegate_later) {
  DCHECK_NE(OK, error);
  DCHECK_NE(ERR_IO_PENDING, error);

  ResetStream();
  if (delegate_) {
    response_status_ = error;
    BidirectionalStreamImpl::Delegate* delegate = delegate_;
    delegate_ = nullptr;
    // Cancel any pending callback.
    weak_factory_.InvalidateWeakPtrs();
    if (notify_delegate_later) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(&BidirectionalStreamQuicImpl::NotifyFailure,
                         weak_factory_.GetWeakPtr(), delegate, error));
    } else {
      NotifyFailure(delegate, error);
      // |this| might be destroyed at this point.
    }
  }
}

void BidirectionalStreamQuicImpl::NotifyFailure(
    BidirectionalStreamImpl::Delegate* delegate,
    int error) {
  CHECK(may_invoke_callbacks_);
  delegate->OnFailed(error);
  // |this| might be destroyed at this point.
}

void BidirectionalStreamQuicImpl::NotifyStreamReady() {
  CHECK(may_invoke_callbacks_);
  if (send_request_headers_automatically_) {
    int rv = WriteHeaders();
    if (rv < 0) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&BidirectionalStreamQuicImpl::NotifyError,
                                    weak_factory_.GetWeakPtr(), rv));
      return;
    }
  }

  if (delegate_)
    delegate_->OnStreamReady(has_sent_headers_);
}

void BidirectionalStreamQuicImpl::ResetStream() {
  if (!stream_)
    return;
  closed_stream_received_bytes_ = stream_->stream_bytes_read();
  closed_stream_sent_bytes_ = stream_->stream_bytes_written();
  closed_is_first_stream_ = stream_->IsFirstStream();
}

}  // namespace net

"""

```
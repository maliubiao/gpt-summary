Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive explanation.

**1. Understanding the Goal:**

The request asks for a breakdown of the `BidirectionalStreamSpdyImpl` class in Chromium's network stack. Specifically, it wants to know its functionality, its relationship to JavaScript (if any), logical deductions with input/output examples, common user errors, and debugging context.

**2. Initial Code Scan and High-Level Understanding:**

* **File Name and Namespace:** The file `bidirectional_stream_spdy_impl.cc` and the `net` namespace immediately suggest this is related to network communication, specifically using the SPDY protocol. The "bidirectional" aspect hints at full-duplex communication.
* **Includes:** The included headers provide clues about the class's dependencies:
    * `base/functional/bind.h`, `base/location.h`, etc.: Core Chromium utilities for tasks, logging, and time management.
    * `net/http/bidirectional_stream_request_info.h`:  Indicates the class handles bidirectional HTTP streams.
    * `net/spdy/spdy_buffer.h`, `net/spdy/spdy_http_utils.h`, `net/spdy/spdy_stream.h`:  Confirms the SPDY protocol is central.
* **Class Declaration:** `class BidirectionalStreamSpdyImpl : public BidirectionalStreamImpl::Delegate, public SpdyStream::Delegate`. This confirms it implements interfaces for both generic bidirectional streams and SPDY-specific streams.
* **Constructor/Destructor:** The constructor takes a `SpdySession` and `NetLogSource`, suggesting it's associated with an existing SPDY connection. The destructor handles resetting the stream.

**3. Analyzing Key Methods and Functionality:**

* **`Start()`:**  This is the entry point for initiating a bidirectional stream. It sets up the delegate, timers, and uses `SpdyStreamRequest` to request a SPDY stream. The `OnStreamInitialized` callback is crucial.
* **`SendRequestHeaders()`:**  The `NOTREACHED()` indicates that headers are sent automatically in this implementation.
* **`ReadData()`:**  Implements reading data from the stream. It uses a buffer (`read_data_queue_`) for efficient handling of data chunks and asynchronous reads.
* **`SendvData()`:**  Handles sending data to the stream. It combines data from multiple buffers and uses `SpdyStream::SendData`. It also manages the "end of stream" flag.
* **Event Handlers (`OnHeadersSent`, `OnEarlyHintsReceived`, `OnHeadersReceived`, `OnDataReceived`, `OnDataSent`, `OnTrailers`, `OnClose`):** These methods are callbacks from the underlying `SpdyStream`. They handle different stages of the stream lifecycle and relay events to the `BidirectionalStreamImpl::Delegate`. `OnDataReceived` and `OnClose` are particularly important for handling incoming data and stream termination.
* **Error Handling (`NotifyError`, `ResetStream`):** These methods handle errors during stream operation, notifying the delegate and cleaning up resources.
* **Buffering Logic (`ScheduleBufferedRead`, `DoBufferedRead`):** The code uses a timer to buffer incoming data before notifying the delegate, optimizing for performance by reducing the number of callbacks.

**4. Identifying Connections to JavaScript:**

This requires understanding how Chromium's network stack interacts with the rendering engine (Blink, which executes JavaScript). The key connection is the `BidirectionalStreamImpl::Delegate`. This delegate is the abstraction point where the network stack informs higher-level components (including those accessible from JavaScript) about stream events. Looking for methods in the delegate (like `OnStreamReady`, `OnHeadersReceived`, `OnDataRead`, `OnTrailersReceived`, `OnFailed`) helps identify these interaction points.

**5. Constructing Logical Deduction Examples:**

To illustrate the flow, pick key methods and trace potential inputs and outputs.

* **`ReadData()`:** Focus on the buffering behavior. Consider cases with small and large amounts of data arriving quickly or slowly.
* **`SendvData()`:** Consider sending data before and after the stream is closed, and with and without the `end_stream` flag.

**6. Identifying Common User Errors:**

Think about how a developer using a higher-level API (which might internally use this class) could misuse it. Common errors relate to the stream lifecycle:

* Sending data after closing the stream.
* Reading data after the stream has ended.

**7. Creating Debugging Scenarios:**

Consider the typical steps a developer would take when encountering an issue with a bidirectional stream. This involves:

* Initiating the request.
* Sending data.
* Receiving data.
* Observing the stream closing.

Connect these steps back to the methods in the code. For instance, if data isn't being sent, the debugger would step through `SendvData` and `SpdyStream::SendData`.

**8. Structuring the Explanation:**

Organize the information logically:

* Start with a high-level overview of the class's purpose.
* Detail the functionality of key methods.
* Explain the JavaScript connection.
* Provide concrete examples for logical deductions and user errors.
* Describe debugging scenarios.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe directly look for JavaScript code.
* **Correction:** Realize the interaction is through the delegate interface, so focus on that.
* **Initial thought:**  Focus solely on individual methods in isolation.
* **Correction:** Consider the interactions between methods, especially the asynchronous nature of reads and writes.
* **Initial thought:**  Provide very technical details about SPDY framing.
* **Correction:** Keep the explanation at a level understandable to someone familiar with network concepts but not necessarily a SPDY expert. Focus on the *functionality* exposed by the class.

By following these steps, iterating through the code, and thinking about its role in a larger system, it's possible to generate a comprehensive and informative explanation like the example provided in the prompt.
好的，让我们来详细分析一下 `net/spdy/bidirectional_stream_spdy_impl.cc` 这个文件。

**功能概述:**

`BidirectionalStreamSpdyImpl` 类是 Chromium 网络栈中用于实现基于 SPDY 协议的双向数据流的核心组件。 它负责管理一个 SPDY 流的生命周期，并提供与该流进行数据收发的接口。 具体来说，它的主要功能包括：

1. **流的初始化和管理:**
   - 接收 `SpdySession` 对象，表示该双向流将建立在哪个 SPDY 会话之上。
   - 使用 `SpdyStreamRequest` 发起建立 SPDY 流的请求。
   - 管理 `SpdyStream` 对象，该对象代表实际的 SPDY 流。
   - 在析构时或发生错误时，发送 RST_STREAM 帧来重置流。

2. **发送请求头:**
   - 将 `BidirectionalStreamRequestInfo` 中的信息转换为 SPDY 格式的请求头。
   - 通过 `SpdyStream::SendRequestHeaders` 发送请求头。

3. **发送数据:**
   - 提供 `SendvData` 方法，允许将多个 `IOBuffer` 中的数据发送到远端。
   - 支持发送流的结束标志 (end_stream)。
   - 处理在流关闭后尝试发送数据的情况。

4. **接收数据:**
   - 通过 `SpdyStream` 的回调 `OnDataReceived` 接收来自远端的数据。
   - 使用 `read_data_queue_` 缓存接收到的数据块，以提高效率，避免频繁地通知上层。
   - 使用定时器 `timer_` 来延迟通知上层接收到数据，实现批量通知。

5. **接收响应头和尾部 (trailers):**
   - 通过 `SpdyStream` 的回调 `OnHeadersReceived` 接收响应头。
   - 通过 `SpdyStream` 的回调 `OnTrailers` 接收尾部。

6. **流的关闭和错误处理:**
   - 通过 `SpdyStream` 的回调 `OnClose` 接收流关闭的通知。
   - 处理正常关闭和错误关闭的情况。
   - 通过 `NotifyError` 方法通知上层发生了错误。

7. **协议协商:**
   - 记录协商后的协议版本 (`negotiated_protocol_`)，在本例中固定为 HTTP/2。

8. **统计信息:**
   - 提供方法获取已接收和已发送的总字节数 (`GetTotalReceivedBytes`, `GetTotalSentBytes`)。
   - 提供方法获取加载时间信息 (`GetLoadTimingInfo`)。

**与 JavaScript 的关系:**

`BidirectionalStreamSpdyImpl` 本身是用 C++ 编写的，直接与 JavaScript 没有交互。 然而，它所实现的功能是 Web 平台的基础，并被 JavaScript 通过浏览器提供的 API 间接使用。

**举例说明:**

假设一个 JavaScript 代码使用 `fetch` API 发起一个使用了 HTTP/2 协议的请求（因为 `BidirectionalStreamSpdyImpl` 处理 SPDY，而 SPDY 是 HTTP/2 的底层协议）：

```javascript
fetch('https://example.com/api/data', {
  method: 'POST',
  body: JSON.stringify({ key: 'value' }),
  headers: {
    'Content-Type': 'application/json'
  }
})
.then(response => response.json())
.then(data => console.log(data));
```

当浏览器执行这段 JavaScript 代码时，网络栈会经历以下步骤，最终涉及到 `BidirectionalStreamSpdyImpl`:

1. **请求创建:**  JavaScript 的 `fetch` 调用会被传递到浏览器内核。
2. **协议选择:** 浏览器会判断与 `example.com` 的连接是否可以使用 HTTP/2 (SPDY)。如果可以，则会选择 HTTP/2。
3. **连接复用:** 如果已经存在与 `example.com` 的 SPDY 会话，则会复用该会话。否则，会建立新的 SPDY 会话。
4. **流的创建:**  `BidirectionalStreamSpdyImpl` 的实例会被创建，并与相应的 `SpdySession` 关联。
5. **发送请求头:** `BidirectionalStreamSpdyImpl::Start` 和 `BidirectionalStreamSpdyImpl::SendRequestHeadersHelper` 会被调用，将 JavaScript 中指定的 `method`、`headers` 等信息转换为 SPDY HEADERS 帧发送出去。
6. **发送请求体:** `JSON.stringify` 的结果会通过 `BidirectionalStreamSpdyImpl::SendvData` 发送出去，封装成 SPDY DATA 帧。
7. **接收响应头:**  服务器返回的 SPDY HEADERS 帧会被 `SpdyStream` 接收，然后调用 `BidirectionalStreamSpdyImpl::OnHeadersReceived`，最终传递给 JavaScript 的 `response` 对象。
8. **接收响应体:** 服务器返回的 SPDY DATA 帧会被 `SpdyStream` 接收，然后调用 `BidirectionalStreamSpdyImpl::OnDataReceived`，缓存后通过 `delegate_->OnDataRead` 传递给上层，最终被 JavaScript 的 `response.json()` 处理。
9. **流的关闭:**  当数据传输完成，SPDY 流会被关闭，`BidirectionalStreamSpdyImpl::OnClose` 会被调用。

**逻辑推理 (假设输入与输出):**

**场景:**  客户端发送一个小的 POST 请求，然后接收到一个小的 JSON 响应。

**假设输入:**

* **`BidirectionalStreamRequestInfo`:**
    * `url`: "https://example.com/api/data"
    * `method`: "POST"
    * `extra_headers`:  包含 "Content-Type: application/json"
    * `end_stream_on_headers`: false
* **发送数据 (通过 `SendvData`)**: 一个包含 `{"key": "value"}` 字符串的 `IOBuffer`。

**预期输出 (回调给 `BidirectionalStreamImpl::Delegate`):**

1. **`OnStreamReady(true)`:**  当请求头发送成功后调用。
2. **`OnDataSent()`:** 当请求体数据发送成功后调用。
3. **`OnHeadersReceived`:** 接收到包含响应状态码 (例如 200) 和其他响应头的 `quiche::HttpHeaderBlock`。
4. **`OnDataRead`:**  接收到包含响应 JSON 数据的 `IOBuffer`，例如 `{"status": "ok"}`。
5. **`OnTrailersReceived`:**  如果服务器发送了尾部，则会接收到尾部的 `quiche::HttpHeaderBlock`。
6. **`OnClose(OK)`:**  当流正常关闭时调用。

**用户或编程常见的使用错误:**

1. **在流关闭后尝试发送数据:**  如果在 `OnClose` 回调发生后，或者在 `SendvData` 中指定 `end_stream` 为 true 后，仍然调用 `SendvData`，会导致错误。

   ```c++
   // 假设 stream_ 已经关闭或者 written_end_of_stream_ 为 true
   std::vector<scoped_refptr<IOBuffer>> buffers;
   std::vector<int> lengths;
   // ... 初始化 buffers 和 lengths ...
   SendvData(buffers, lengths, false); // 错误：尝试在流关闭后发送数据
   ```

   **现象:**  `SendvData` 中的 `DCHECK(!write_pending_)` 或 `if (written_end_of_stream_)` 会触发，导致程序崩溃或调用 `NotifyError`。

2. **在未调用 `ReadData` 的情况下期望接收到数据:**  `BidirectionalStreamSpdyImpl` 使用 `ReadData` 来启动接收数据的流程。 如果没有调用 `ReadData`，即使远端发送了数据，`delegate_->OnDataRead` 也不会被调用。

   **现象:**  数据被缓存在 `read_data_queue_` 中，但上层没有收到通知。

3. **过早地释放 `BidirectionalStreamImpl::Delegate`:**  如果在流的生命周期结束之前释放了 `delegate_`，当 `BidirectionalStreamSpdyImpl` 尝试回调 `delegate_` 的方法时，会导致野指针访问。

   **现象:**  程序崩溃。

**用户操作如何一步步地到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器访问一个支持 HTTP/2 的网站，并进行了一些操作导致网络请求出现问题。以下是一些可能触发 `BidirectionalStreamSpdyImpl` 相关代码的场景，以及如何利用调试信息定位到这里：

1. **用户发起了一个 HTTP/2 请求:**
   - **操作:** 用户在浏览器地址栏输入 URL 并回车，或者点击了一个链接，或者网页上的 JavaScript 代码发起了 `fetch` 请求。
   - **调试线索:**  在 Chrome 的 `net-internals` (chrome://net-internals/#events) 中，可以查看到与该请求相关的事件，例如 "HTTP2_SESSION_STREAM_REQUEST"、"HTTP2_STREAM_SEND_HEADERS"、"HTTP2_STREAM_RECV_DATA" 等。通过这些事件，可以找到与该请求关联的 `SpdySession` 和 `SpdyStream`。`BidirectionalStreamSpdyImpl` 通常是 `SpdyStream` 的委托 (delegate)。

2. **发送 POST 请求:**
   - **操作:** 用户填写了一个表单并提交，网页上的 JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 发送了一个包含请求体的 POST 请求。
   - **调试线索:**  在 `net-internals` 中，可以看到 "HTTP2_STREAM_SEND_DATA" 事件，表明数据正在通过 SPDY 流发送。可以查看发送的数据内容和大小。在 `BidirectionalStreamSpdyImpl::SendvData` 中设置断点，可以观察数据的发送过程。

3. **接收大数据流:**
   - **操作:** 用户访问的网页需要下载大量数据，例如视频、大型文件等。
   - **调试线索:**  在 `net-internals` 中，可以看到大量的 "HTTP2_STREAM_RECV_DATA" 事件。可以观察接收到的数据块的大小和频率。在 `BidirectionalStreamSpdyImpl::OnDataReceived` 和 `BidirectionalStreamSpdyImpl::DoBufferedRead` 中设置断点，可以分析数据的接收和缓存逻辑。

4. **网络连接中断或服务器错误:**
   - **操作:** 网络不稳定导致连接中断，或者服务器返回错误状态码。
   - **调试线索:**  在 `net-internals` 中，可能会看到 "SOCKET_CLOSED"、"HTTP2_SESSION_CLOSE" 等事件。如果服务器返回错误，可以看到 "HTTP2_STREAM_RST_SENT" 或 "HTTP2_STREAM_RST_RECEIVED" 事件，表示流被重置。在 `BidirectionalStreamSpdyImpl::OnClose` 和 `BidirectionalStreamSpdyImpl::NotifyError` 中设置断点，可以分析错误处理流程。

**总结:**

`BidirectionalStreamSpdyImpl` 是 Chromium 网络栈中处理 SPDY 双向数据流的关键组件，负责流的生命周期管理、数据收发和错误处理。虽然它本身不与 JavaScript 直接交互，但它是实现 Web 平台网络功能的基础，并被 JavaScript 通过浏览器提供的 API 间接使用。理解其功能和内部逻辑对于调试网络相关的问题至关重要。

Prompt: 
```
这是目录为net/spdy/bidirectional_stream_spdy_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/bidirectional_stream_spdy_impl.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/spdy/spdy_buffer.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_stream.h"

namespace net {

namespace {

// Time to wait in millisecond to notify |delegate_| of data received.
// Handing small chunks of data to the caller creates measurable overhead.
// So buffer data in short time-spans and send a single read notification.
const int kBufferTimeMs = 1;

}  // namespace

BidirectionalStreamSpdyImpl::BidirectionalStreamSpdyImpl(
    const base::WeakPtr<SpdySession>& spdy_session,
    NetLogSource source_dependency)
    : spdy_session_(spdy_session), source_dependency_(source_dependency) {}

BidirectionalStreamSpdyImpl::~BidirectionalStreamSpdyImpl() {
  // Sends a RST to the remote if the stream is destroyed before it completes.
  ResetStream();
}

void BidirectionalStreamSpdyImpl::Start(
    const BidirectionalStreamRequestInfo* request_info,
    const NetLogWithSource& net_log,
    bool /*send_request_headers_automatically*/,
    BidirectionalStreamImpl::Delegate* delegate,
    std::unique_ptr<base::OneShotTimer> timer,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(!stream_);
  DCHECK(timer);

  delegate_ = delegate;
  timer_ = std::move(timer);

  if (!spdy_session_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&BidirectionalStreamSpdyImpl::NotifyError,
                       weak_factory_.GetWeakPtr(), ERR_CONNECTION_CLOSED));
    return;
  }

  request_info_ = request_info;

  int rv = stream_request_.StartRequest(
      SPDY_BIDIRECTIONAL_STREAM, spdy_session_, request_info_->url,
      false /* no early data */, request_info_->priority,
      request_info_->socket_tag, net_log,
      base::BindOnce(&BidirectionalStreamSpdyImpl::OnStreamInitialized,
                     weak_factory_.GetWeakPtr()),
      traffic_annotation, request_info_->detect_broken_connection,
      request_info_->heartbeat_interval);
  if (rv != ERR_IO_PENDING)
    OnStreamInitialized(rv);
}

void BidirectionalStreamSpdyImpl::SendRequestHeaders() {
  // Request headers will be sent automatically.
  NOTREACHED();
}

int BidirectionalStreamSpdyImpl::ReadData(IOBuffer* buf, int buf_len) {
  if (stream_)
    DCHECK(!stream_->IsIdle());

  DCHECK(buf);
  DCHECK(buf_len);
  DCHECK(!timer_->IsRunning()) << "There should be only one ReadData in flight";

  // If there is data buffered, complete the IO immediately.
  if (!read_data_queue_.IsEmpty()) {
    return read_data_queue_.Dequeue(buf->data(), buf_len);
  } else if (stream_closed_) {
    return closed_stream_status_;
  }
  // Read will complete asynchronously and Delegate::OnReadCompleted will be
  // called upon completion.
  read_buffer_ = buf;
  read_buffer_len_ = buf_len;
  return ERR_IO_PENDING;
}

void BidirectionalStreamSpdyImpl::SendvData(
    const std::vector<scoped_refptr<IOBuffer>>& buffers,
    const std::vector<int>& lengths,
    bool end_stream) {
  DCHECK_EQ(buffers.size(), lengths.size());
  DCHECK(!write_pending_);

  if (written_end_of_stream_) {
    LOG(ERROR) << "Writing after end of stream is written.";
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&BidirectionalStreamSpdyImpl::NotifyError,
                                  weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
    return;
  }

  write_pending_ = true;
  written_end_of_stream_ = end_stream;
  if (MaybeHandleStreamClosedInSendData())
    return;

  DCHECK(!stream_closed_);
  int total_len = 0;
  for (int len : lengths) {
    total_len += len;
  }

  if (buffers.size() == 1) {
    pending_combined_buffer_ = buffers[0];
  } else {
    pending_combined_buffer_ =
        base::MakeRefCounted<net::IOBufferWithSize>(total_len);
    int len = 0;
    // TODO(xunjieli): Get rid of extra copy. Coalesce headers and data frames.
    for (size_t i = 0; i < buffers.size(); ++i) {
      memcpy(pending_combined_buffer_->data() + len, buffers[i]->data(),
             lengths[i]);
      len += lengths[i];
    }
  }
  stream_->SendData(pending_combined_buffer_.get(), total_len,
                    end_stream ? NO_MORE_DATA_TO_SEND : MORE_DATA_TO_SEND);
}

NextProto BidirectionalStreamSpdyImpl::GetProtocol() const {
  return negotiated_protocol_;
}

int64_t BidirectionalStreamSpdyImpl::GetTotalReceivedBytes() const {
  if (stream_closed_)
    return closed_stream_received_bytes_;

  if (!stream_)
    return 0;

  return stream_->raw_received_bytes();
}

int64_t BidirectionalStreamSpdyImpl::GetTotalSentBytes() const {
  if (stream_closed_)
    return closed_stream_sent_bytes_;

  if (!stream_)
    return 0;

  return stream_->raw_sent_bytes();
}

bool BidirectionalStreamSpdyImpl::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  if (stream_closed_) {
    if (!closed_has_load_timing_info_)
      return false;
    *load_timing_info = closed_load_timing_info_;
    return true;
  }

  // If |stream_| isn't created or has ID 0, return false. This is to match
  // the implementation in SpdyHttpStream.
  if (!stream_ || stream_->stream_id() == 0)
    return false;

  return stream_->GetLoadTimingInfo(load_timing_info);
}

void BidirectionalStreamSpdyImpl::PopulateNetErrorDetails(
    NetErrorDetails* details) {}

void BidirectionalStreamSpdyImpl::OnHeadersSent() {
  DCHECK(stream_);

  negotiated_protocol_ = kProtoHTTP2;
  if (delegate_)
    delegate_->OnStreamReady(/*request_headers_sent=*/true);
}

void BidirectionalStreamSpdyImpl::OnEarlyHintsReceived(
    const quiche::HttpHeaderBlock& headers) {
  DCHECK(stream_);
  // TODO(crbug.com/40496584): Plumb Early Hints to `delegate_` if needed.
}

void BidirectionalStreamSpdyImpl::OnHeadersReceived(
    const quiche::HttpHeaderBlock& response_headers) {
  DCHECK(stream_);

  if (delegate_)
    delegate_->OnHeadersReceived(response_headers);
}

void BidirectionalStreamSpdyImpl::OnDataReceived(
    std::unique_ptr<SpdyBuffer> buffer) {
  DCHECK(stream_);
  DCHECK(!stream_closed_);

  // If |buffer| is null, BidirectionalStreamSpdyImpl::OnClose will be invoked
  // by SpdyStream to indicate the end of stream.
  if (!buffer)
    return;

  // When buffer is consumed, SpdyStream::OnReadBufferConsumed will adjust
  // recv window size accordingly.
  read_data_queue_.Enqueue(std::move(buffer));
  if (read_buffer_) {
    // Handing small chunks of data to the caller creates measurable overhead.
    // So buffer data in short time-spans and send a single read notification.
    ScheduleBufferedRead();
  }
}

void BidirectionalStreamSpdyImpl::OnDataSent() {
  DCHECK(write_pending_);

  pending_combined_buffer_ = nullptr;
  write_pending_ = false;

  if (delegate_)
    delegate_->OnDataSent();
}

void BidirectionalStreamSpdyImpl::OnTrailers(
    const quiche::HttpHeaderBlock& trailers) {
  DCHECK(stream_);
  DCHECK(!stream_closed_);

  if (delegate_)
    delegate_->OnTrailersReceived(trailers);
}

void BidirectionalStreamSpdyImpl::OnClose(int status) {
  DCHECK(stream_);

  stream_closed_ = true;
  closed_stream_status_ = status;
  closed_stream_received_bytes_ = stream_->raw_received_bytes();
  closed_stream_sent_bytes_ = stream_->raw_sent_bytes();
  closed_has_load_timing_info_ =
      stream_->GetLoadTimingInfo(&closed_load_timing_info_);

  if (status != OK) {
    NotifyError(status);
    return;
  }
  ResetStream();
  // Complete any remaining read, as all data has been buffered.
  // If user has not called ReadData (i.e |read_buffer_| is nullptr), this will
  // do nothing.
  timer_->Stop();

  // |this| might get destroyed after calling into |delegate_| in
  // DoBufferedRead().
  auto weak_this = weak_factory_.GetWeakPtr();
  DoBufferedRead();
  if (weak_this.get() && write_pending_)
    OnDataSent();
}

bool BidirectionalStreamSpdyImpl::CanGreaseFrameType() const {
  return false;
}

NetLogSource BidirectionalStreamSpdyImpl::source_dependency() const {
  return source_dependency_;
}

int BidirectionalStreamSpdyImpl::SendRequestHeadersHelper() {
  quiche::HttpHeaderBlock headers;
  HttpRequestInfo http_request_info;
  http_request_info.url = request_info_->url;
  http_request_info.method = request_info_->method;
  http_request_info.extra_headers = request_info_->extra_headers;

  CreateSpdyHeadersFromHttpRequest(http_request_info, std::nullopt,
                                   http_request_info.extra_headers, &headers);
  written_end_of_stream_ = request_info_->end_stream_on_headers;
  return stream_->SendRequestHeaders(std::move(headers),
                                     request_info_->end_stream_on_headers
                                         ? NO_MORE_DATA_TO_SEND
                                         : MORE_DATA_TO_SEND);
}

void BidirectionalStreamSpdyImpl::OnStreamInitialized(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (rv == OK) {
    stream_ = stream_request_.ReleaseStream();
    stream_->SetDelegate(this);
    rv = SendRequestHeadersHelper();
    if (rv == OK) {
      OnHeadersSent();
      return;
    } else if (rv == ERR_IO_PENDING) {
      return;
    }
  }
  NotifyError(rv);
}

void BidirectionalStreamSpdyImpl::NotifyError(int rv) {
  ResetStream();
  write_pending_ = false;
  if (delegate_) {
    BidirectionalStreamImpl::Delegate* delegate = delegate_;
    delegate_ = nullptr;
    // Cancel any pending callback.
    weak_factory_.InvalidateWeakPtrs();
    delegate->OnFailed(rv);
    // |this| can be null when returned from delegate.
  }
}

void BidirectionalStreamSpdyImpl::ResetStream() {
  if (!stream_)
    return;
  if (!stream_->IsClosed()) {
    // This sends a RST to the remote.
    stream_->DetachDelegate();
    DCHECK(!stream_);
  } else {
    // Stream is already closed, so it is not legal to call DetachDelegate.
    stream_.reset();
  }
}

void BidirectionalStreamSpdyImpl::ScheduleBufferedRead() {
  // If there is already a scheduled DoBufferedRead, don't issue
  // another one. Mark that we have received more data and return.
  if (timer_->IsRunning()) {
    more_read_data_pending_ = true;
    return;
  }

  more_read_data_pending_ = false;
  timer_->Start(FROM_HERE, base::Milliseconds(kBufferTimeMs),
                base::BindOnce(&BidirectionalStreamSpdyImpl::DoBufferedRead,
                               weak_factory_.GetWeakPtr()));
}

void BidirectionalStreamSpdyImpl::DoBufferedRead() {
  DCHECK(!timer_->IsRunning());
  // Check to see that the stream has not errored out.
  DCHECK(stream_ || stream_closed_);
  DCHECK(!stream_closed_ || closed_stream_status_ == OK);

  // When |more_read_data_pending_| is true, it means that more data has arrived
  // since started waiting. Wait a little longer and continue to buffer.
  if (more_read_data_pending_ && ShouldWaitForMoreBufferedData()) {
    ScheduleBufferedRead();
    return;
  }

  int rv = 0;
  if (read_buffer_) {
    rv = ReadData(read_buffer_.get(), read_buffer_len_);
    DCHECK_NE(ERR_IO_PENDING, rv);
    read_buffer_ = nullptr;
    read_buffer_len_ = 0;
    if (delegate_)
      delegate_->OnDataRead(rv);
  }
}

bool BidirectionalStreamSpdyImpl::ShouldWaitForMoreBufferedData() const {
  if (stream_closed_)
    return false;
  DCHECK_GT(read_buffer_len_, 0);
  return read_data_queue_.GetTotalSize() <
         static_cast<size_t>(read_buffer_len_);
}

bool BidirectionalStreamSpdyImpl::MaybeHandleStreamClosedInSendData() {
  if (stream_)
    return false;
  // If |stream_| is closed without an error before client half closes,
  // blackhole any pending write data. crbug.com/650438.
  if (stream_closed_ && closed_stream_status_ == OK) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&BidirectionalStreamSpdyImpl::OnDataSent,
                                  weak_factory_.GetWeakPtr()));
    return true;
  }
  LOG(ERROR) << "Trying to send data after stream has been destroyed.";
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&BidirectionalStreamSpdyImpl::NotifyError,
                                weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
  return true;
}

}  // namespace net

"""

```
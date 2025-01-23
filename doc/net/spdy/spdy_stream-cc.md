Response:
Let's break down the thought process for analyzing the `net/spdy/spdy_stream.cc` file and generating the comprehensive response.

**1. Understanding the Request:**

The core of the request is to understand the functionality of `spdy_stream.cc` within Chromium's network stack, specifically looking for:

* **Primary Functions:** What does this code *do*?
* **JavaScript Relevance:** How does it relate to the browser's interaction with web pages and JavaScript?
* **Logical Reasoning:**  What can we infer about inputs and outputs based on the code?
* **Common Usage Errors:** What mistakes might developers or the system make when using this code?
* **User Path:** How does a user action eventually lead to this code being executed?

**2. Initial Code Scan and High-Level Understanding:**

My first step would be to quickly scan the file, paying attention to:

* **Includes:**  These provide clues about dependencies and what the class interacts with (e.g., `net/spdy/*`, `net/http/*`, `net/log/*`, `base/*`). This immediately tells me it's related to the SPDY/HTTP/2 protocol handling within the networking layer.
* **Class Definition (`SpdyStream`):** This is the central entity. I'd look at its member variables and methods to get a sense of its responsibilities. Keywords like "send window," "receive window," "headers," "data," "delegate," and "session" jump out.
* **Namespaces:** The `net` namespace confirms it's part of the network stack.
* **Comments:**  The initial copyright notice and other comments provide context.
* **Helper Functions:**  Functions like `NetLogSpdyStreamErrorParams`, `NetLogSpdyStreamWindowUpdateParams`, and `NetLogSpdyDataParams` suggest logging and debugging are important aspects.

**3. Deeper Dive into Functionality (Method by Method):**

Next, I'd go through the methods of the `SpdyStream` class, group them by function, and try to understand their individual roles:

* **Construction and Initialization:** `SpdyStream`'s constructor initializes key variables like window sizes, priority, and associates the stream with a `SpdySession`.
* **Delegate Management:** `SetDelegate` and `DetachDelegate` indicate an observer pattern where a `Delegate` (presumably in a higher layer) receives events from the `SpdyStream`.
* **Request Sending:** `SendRequestHeaders`, `SendData`, `ProduceHeadersFrame` deal with preparing and sending HTTP/2 requests. The concept of `SpdyBufferProducer` is important here – it's an abstraction for creating the data to be sent.
* **Response Handling:** `OnHeadersReceived`, `OnDataReceived`, `OnTrailers` handle incoming HTTP/2 responses. The different `response_state_` values are crucial for tracking the progression of the response.
* **Flow Control:** `AdjustSendWindowSize`, `IncreaseSendWindowSize`, `DecreaseSendWindowSize`, `IncreaseRecvWindowSize`, `DecreaseRecvWindowSize` are clearly related to managing the flow of data to avoid overwhelming the sender or receiver. The `unacked_recv_window_bytes_` variable is key to understanding how the receiver informs the sender about available buffer space.
* **Stream State Management:** Methods like `OnClose`, `Cancel`, `Close`, `IsClosed`, `IsLocallyClosed`, `IsOpen`, `IsIdle` manage the lifecycle of the SPDY stream.
* **Logging and Debugging:** The numerous `net_log_.AddEvent` calls indicate a strong emphasis on logging for debugging and analysis. The helper functions for creating log parameters reinforce this.
* **Priority:** `SetPriority` and mentions of `priority_` highlight the support for HTTP/2's prioritization feature.
* **SSL Information:** `GetSSLInfo` indicates interaction with the SSL/TLS layer.
* **Load Timing:** `GetLoadTimingInfo` shows the collection of performance metrics related to the stream.
* **Greased Frames:** The mention of "greased frames" points to techniques used to improve HTTP/2 interoperability by sending unexpected frames.

**4. Identifying JavaScript Relevance:**

This is where I would connect the low-level networking details to the browser's interaction with web pages. I'd think about:

* **Fetching Resources:** JavaScript often uses `fetch` or `XMLHttpRequest` to retrieve data. These APIs rely on the underlying network stack. `SpdyStream` is a part of that stack for HTTP/2 connections.
* **WebSockets:**  The handling of HTTP 101 (Switching Protocols) suggests a connection to WebSocket upgrades.
* **Resource Hints (Early Hints):** The `OnEarlyHintsReceived` method directly links to the "103 Early Hints" HTTP status code, a feature used to improve page load performance by preloading resources.
* **Performance Monitoring:** The `LoadTimingInfo` is eventually exposed to JavaScript through APIs like `performance.timing` or the Navigation Timing API.

**5. Logical Reasoning (Input/Output):**

For this, I'd choose specific methods and think about what happens given certain inputs:

* **`IncreaseSendWindowSize`:**  Input: a positive delta. Output: The send window increases. *Potential issue:* What if the delta is too large? The code explicitly checks for overflow and resets the stream if necessary.
* **`OnDataReceived`:** Input: A `SpdyBuffer` containing data. Output: The data is passed to the delegate. *Edge Case:* What if data arrives before headers? The code handles this as a protocol error. What if `buffer` is null (FIN)? The stream state transitions.

**6. Identifying Common Usage Errors:**

This involves thinking about how things could go wrong, either from a programming perspective or due to unexpected network conditions:

* **Incorrect State Transitions:**  Calling methods in the wrong order (e.g., sending data before headers are sent). The code has checks for these scenarios.
* **Flow Control Violations:** Sending more data than the peer's advertised window size. While `SpdyStream` helps manage this, a higher layer might make mistakes.
* **Resource Management:**  Failing to consume data or close the stream properly.
* **Server Errors:** The server sending invalid HTTP/2 frames or violating the protocol. The error handling within `SpdyStream` addresses this.

**7. Tracing the User Path:**

This requires thinking about the sequence of events from a user's action to the execution of `spdy_stream.cc` code:

* **Basic Navigation:** User types a URL or clicks a link. This triggers a network request.
* **Fetching Resources:** JavaScript on a page might initiate a `fetch` request.
* **WebSocket Connection:** A JavaScript application might establish a WebSocket connection.
* **Resource Hints:** The browser might preload resources based on Early Hints received for a previous navigation.

In each case, the browser needs to establish a connection (potentially using HTTP/2), send requests, and receive responses. `SpdyStream` plays a crucial role in managing the individual streams within an HTTP/2 connection.

**8. Structuring the Response:**

Finally, I would organize the information into a clear and structured format, using headings and bullet points to make it easy to read and understand. I'd start with a summary, then delve into the details of functionality, JavaScript relevance, logical reasoning, errors, and the user path. I'd also include specific code examples where appropriate.

By following these steps, I can effectively analyze the given source code and provide a comprehensive and informative response that addresses all aspects of the user's request. The key is to move from a high-level understanding to a more detailed analysis, connecting the technical details to the broader context of web browsing and JavaScript interactions.
好的，让我们来详细分析一下 `net/spdy/spdy_stream.cc` 这个 Chromium 网络栈的源代码文件。

**功能概要:**

`spdy_stream.cc` 文件定义了 `SpdyStream` 类，它是 Chromium 中处理 SPDY/HTTP/2 连接上单个流的核心组件。其主要功能包括：

1. **管理 HTTP/2 流的状态:**  跟踪流的生命周期，例如空闲 (IDLE)、打开 (OPEN)、半关闭 (本地或远程) 和关闭 (CLOSED)。
2. **处理 HTTP 请求和响应头:**  存储和处理发送的请求头以及接收到的响应头和尾部（trailers）。
3. **管理数据传输:**  控制流的数据发送和接收，包括数据的缓冲和传递给上层。
4. **实现 HTTP/2 流控:**  管理发送窗口 (send window) 和接收窗口 (receive window)，确保数据传输不会压垮发送方或接收方。
5. **处理流优先级:**  支持 HTTP/2 的流优先级功能，允许客户端指示哪些流更重要。
6. **集成网络日志:**  使用 Chromium 的 `NetLog` 系统记录流的各种事件，用于调试和监控。
7. **与 `SpdySession` 交互:**  作为 `SpdySession` 的一部分，依赖于 `SpdySession` 来发送和接收帧，管理连接状态等。
8. **与上层 Delegate 交互:**  通过 `Delegate` 接口与更高层次的网络组件（例如 HTTP 事务）进行通信，通知事件（如头已发送、数据已接收、流已关闭等）。
9. **支持 Early Hints:**  处理 HTTP 103 Early Hints 响应，提前向 delegate 通知可能的资源。
10. **收集性能指标:** 记录流的开始时间、接收到首字节时间等，用于性能分析。

**与 JavaScript 功能的关系及举例说明:**

`SpdyStream` 本身并不直接与 JavaScript 代码交互，它是浏览器网络栈的底层实现。但是，它通过处理 HTTP/2 协议，为 JavaScript 发起的网络请求提供支持。

**举例说明:**

1. **`fetch()` API:**  当 JavaScript 代码使用 `fetch()` API 发起一个 HTTP 请求时，如果浏览器与服务器之间使用 HTTP/2 协议，那么会创建一个 `SpdyStream` 对象来处理这个请求。
    * JavaScript 调用 `fetch('/api/data')`.
    * 网络栈会创建 `SpdyStream`。
    * `SpdyStream` 的 `SendRequestHeaders` 方法会被调用，将请求头（包括 URL、方法、自定义头等）序列化成 HTTP/2 HEADERS 帧发送给服务器。
    * 服务器响应后，`SpdyStream` 的 `OnHeadersReceived` 和 `OnDataReceived` 方法会被调用来处理响应头和数据。
    * 最终，数据会通过 `fetch()` API 的 Promise 返回给 JavaScript 代码。

2. **WebSocket 连接升级:**  当 JavaScript 代码尝试使用 WebSocket 建立连接时，初始的握手是一个 HTTP 请求。如果使用 HTTP/2，则会创建一个 `SpdyStream` 来处理这个握手请求。
    * JavaScript 创建一个 `WebSocket('wss://example.com/socket')` 对象。
    * 网络栈会创建一个 `SpdyStream` 来发送升级请求。
    * 如果服务器响应 101 Switching Protocols，`SpdyStream` 会处理这个响应，并将流交给 WebSocket 相关的处理逻辑。

3. **Resource Hints (Early Hints):** 当服务器发送 HTTP 103 Early Hints 响应时，`SpdyStream` 的 `OnEarlyHintsReceived` 方法会被调用。
    * 服务器在发送主响应之前，先发送包含 `Link` 头的 103 响应，指示浏览器预加载某些资源。
    * `SpdyStream` 解析这些头，并通过 delegate 通知浏览器可以提前开始请求这些资源，从而加速页面加载。虽然 JavaScript 不直接参与 Early Hints 的处理，但这是浏览器优化页面加载性能的关键机制。

**逻辑推理及假设输入与输出:**

假设输入：一个已经建立的 HTTP/2 连接上的新请求。

1. **假设输入:**
   * `SpdySession` 对象已存在。
   * JavaScript 发起了一个对 `https://example.com/resource` 的 GET 请求。
   * 请求头包含 `User-Agent: MyBrowser` 和 `Accept: application/json`。

2. **逻辑推理:**
   * 网络栈会创建一个新的 `SpdyStream` 对象。
   * `SendRequestHeaders` 方法会被调用，传入包含请求头信息的 `quiche::HttpHeaderBlock`。
   * `ProduceHeadersFrame` 方法会被调用，将请求头序列化成 HTTP/2 HEADERS 帧。
   * 这个 HEADERS 帧会被发送到服务器。

3. **假设输出:**
   * 服务器会收到一个包含 `:method: GET`, `:path: /resource`, `:scheme: https`, `:authority: example.com`, `user-agent: MyBrowser`, `accept: application/json` 等头的 HTTP/2 HEADERS 帧。

假设输入：服务器返回响应头。

1. **假设输入:**
   * 服务器发送了一个包含 `:status: 200`, `Content-Type: application/json`, `Content-Length: 123` 的 HTTP/2 HEADERS 帧。

2. **逻辑推理:**
   * `SpdyStream` 的 `OnHeadersReceived` 方法会被调用，传入接收到的头信息。
   * 状态码 (200) 会被记录到性能指标中。
   * 响应头会被存储在 `response_headers_` 成员变量中。
   * `delegate_->OnHeadersReceived` 方法会被调用，通知上层组件响应头已接收。

3. **假设输出:**
   * 上层组件（例如 HTTP 事务）会接收到包含状态码和响应头的通知。

**用户或编程常见的使用错误及举例说明:**

1. **在未发送请求头之前尝试发送数据:**  `SpdyStream` 的状态管理要求先发送 HEADERS 帧，再发送 DATA 帧。如果在 `STATE_IDLE` 状态下调用 `SendData`，会导致错误。
   * **错误示例:**  编程逻辑错误，过早调用了发送数据的方法。
   * **调试线索:** 检查调用 `SendData` 时的 `io_state_` 是否为 `STATE_OPEN` 或 `STATE_HALF_CLOSED_REMOTE`。

2. **违反流控:** 尽管 `SpdyStream` 负责管理流控，但如果上层逻辑错误地尝试发送超过发送窗口大小的数据，可能会导致问题。
   * **错误示例:**  上层组件没有正确地等待发送窗口更新就发送了大量数据。
   * **调试线索:**  检查发送数据的速率是否过快，对比当前的 `send_window_size_`。

3. **未正确处理流关闭事件:** 上层 Delegate 需要实现 `OnClose` 方法来处理流的关闭事件，包括正常关闭和错误关闭。如果 Delegate 没有正确处理，可能会导致资源泄漏或其他问题。
   * **错误示例:**  Delegate 没有释放与流相关的资源。
   * **调试线索:**  查看 `OnClose` 方法的实现，确保所有必要的清理工作都已完成。

4. **服务端发送不符合协议的帧:**  `SpdyStream` 内部有对协议的检查。如果服务端发送了不符合 HTTP/2 规范的帧（例如在发送数据前没有发送头），`SpdyStream` 会检测到并重置流。
   * **错误示例:**  服务端实现错误，违反了 HTTP/2 协议。
   * **调试线索:**  查看 `NetLog` 中记录的错误事件，通常会包含错误描述和错误码。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接:**
   * 浏览器解析 URL，确定协议（例如 HTTPS）。
   * 如果目标域名已经存在 HTTP/2 连接，则会尝试复用连接。否则，会建立新的 TCP 连接和 TLS 握手。
   * 在 TLS 握手完成后，会进行 HTTP/2 的连接协商（通过 ALPN 扩展）。
   * 如果协商成功，会创建一个 `SpdySession` 对象来管理与服务器的 HTTP/2 连接。
   * 当开始请求资源时，会创建一个 `SpdyStream` 对象，关联到这个 `SpdySession`。
   * `SpdyStream` 会将请求头序列化成 HEADERS 帧发送给服务器。

2. **JavaScript 发起 `fetch()` 请求:**
   * JavaScript 代码调用 `fetch('/api/data')`。
   * 浏览器网络栈接收到这个请求。
   * 如果存在与目标域名匹配的 HTTP/2 连接，则会创建一个新的 `SpdyStream` 对象来处理这个请求，并将其关联到现有的 `SpdySession`。
   * `SpdyStream` 负责发送请求头和数据，并处理服务器的响应。

3. **网页尝试建立 WebSocket 连接:**
   * JavaScript 代码创建一个 `WebSocket` 对象。
   * 浏览器网络栈会发送一个 HTTP Upgrade 请求到服务器。
   * 如果使用 HTTP/2，会创建一个 `SpdyStream` 对象来发送这个请求。
   * 如果服务器返回 101 Switching Protocols 响应，`SpdyStream` 会进行相应的处理，并将流的状态转换为 WebSocket 连接。

**调试线索:**

* **NetLog:**  Chromium 的 `NetLog` 是调试网络问题的强大工具。你可以通过 `chrome://net-export/` 导出网络日志，查看与特定请求或连接相关的事件，包括 `SpdyStream` 的创建、状态变化、发送和接收的帧、错误信息等。
* **断点调试:**  在 `spdy_stream.cc` 中设置断点，可以跟踪代码的执行流程，查看关键变量的值，例如 `io_state_`、`send_window_size_`、接收到的头信息等。
* **条件断点:**  可以使用条件断点来在特定条件下暂停执行，例如当某个特定流 ID 的事件发生时。
* **查看 `SpdySession` 的状态:**  `SpdyStream` 依赖于 `SpdySession`，因此查看 `SpdySession` 的状态也有助于理解问题，例如连接是否正常、是否存在拥塞等。
* **对比 HTTP/1.1 的行为:**  如果怀疑是 HTTP/2 特有的问题，可以尝试禁用 HTTP/2，强制使用 HTTP/1.1，对比行为差异。

总而言之，`net/spdy/spdy_stream.cc` 是 Chromium 网络栈中处理 HTTP/2 流的核心组件，它负责管理流的生命周期、数据传输、流控等关键功能，并与上层组件和 `SpdySession` 紧密配合，最终支持浏览器与服务器之间的 HTTP/2 通信。 理解 `SpdyStream` 的工作原理对于调试 HTTP/2 相关的问题至关重要。

### 提示词
```
这是目录为net/spdy/spdy_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_stream.h"

#include <algorithm>
#include <limits>
#include <string_view>
#include <utility>

#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "base/values.h"
#include "net/base/load_timing_info.h"
#include "net/http/http_status_code.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/spdy/spdy_buffer_producer.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_log_util.h"
#include "net/spdy/spdy_session.h"

namespace net {

namespace {

base::Value::Dict NetLogSpdyStreamErrorParams(spdy::SpdyStreamId stream_id,
                                              int net_error,
                                              std::string_view description) {
  return base::Value::Dict()
      .Set("stream_id", static_cast<int>(stream_id))
      .Set("net_error", ErrorToShortString(net_error))
      .Set("description", description);
}

base::Value::Dict NetLogSpdyStreamWindowUpdateParams(
    spdy::SpdyStreamId stream_id,
    int32_t delta,
    int32_t window_size) {
  return base::Value::Dict()
      .Set("stream_id", static_cast<int>(stream_id))
      .Set("delta", delta)
      .Set("window_size", window_size);
}

base::Value::Dict NetLogSpdyDataParams(spdy::SpdyStreamId stream_id,
                                       int size,
                                       bool fin) {
  return base::Value::Dict()
      .Set("stream_id", static_cast<int>(stream_id))
      .Set("size", size)
      .Set("fin", fin);
}

}  // namespace

// A wrapper around a stream that calls into ProduceHeadersFrame().
class SpdyStream::HeadersBufferProducer : public SpdyBufferProducer {
 public:
  explicit HeadersBufferProducer(const base::WeakPtr<SpdyStream>& stream)
      : stream_(stream) {
    DCHECK(stream_.get());
  }

  ~HeadersBufferProducer() override = default;

  std::unique_ptr<SpdyBuffer> ProduceBuffer() override {
    if (!stream_.get()) {
      NOTREACHED();
    }
    DCHECK_GT(stream_->stream_id(), 0u);
    return std::make_unique<SpdyBuffer>(stream_->ProduceHeadersFrame());
  }

 private:
  const base::WeakPtr<SpdyStream> stream_;
};

SpdyStream::SpdyStream(SpdyStreamType type,
                       const base::WeakPtr<SpdySession>& session,
                       const GURL& url,
                       RequestPriority priority,
                       int32_t initial_send_window_size,
                       int32_t max_recv_window_size,
                       const NetLogWithSource& net_log,
                       const NetworkTrafficAnnotationTag& traffic_annotation,
                       bool detect_broken_connection)
    : type_(type),
      url_(url),
      priority_(priority),
      send_window_size_(initial_send_window_size),
      max_recv_window_size_(max_recv_window_size),
      recv_window_size_(max_recv_window_size),
      last_recv_window_update_(base::TimeTicks::Now()),
      session_(session),
      request_time_(base::Time::Now()),
      net_log_(net_log),
      traffic_annotation_(traffic_annotation),
      detect_broken_connection_(detect_broken_connection) {
  CHECK(type_ == SPDY_BIDIRECTIONAL_STREAM ||
        type_ == SPDY_REQUEST_RESPONSE_STREAM);
  CHECK_GE(priority_, MINIMUM_PRIORITY);
  CHECK_LE(priority_, MAXIMUM_PRIORITY);
}

SpdyStream::~SpdyStream() {
  CHECK(!write_handler_guard_);
}

void SpdyStream::SetDelegate(Delegate* delegate) {
  CHECK(!delegate_);
  CHECK(delegate);
  delegate_ = delegate;

  CHECK(io_state_ == STATE_IDLE || io_state_ == STATE_RESERVED_REMOTE);
}

std::unique_ptr<spdy::SpdySerializedFrame> SpdyStream::ProduceHeadersFrame() {
  CHECK_EQ(io_state_, STATE_IDLE);
  CHECK(request_headers_valid_);
  CHECK_GT(stream_id_, 0u);

  spdy::SpdyControlFlags flags = (pending_send_status_ == NO_MORE_DATA_TO_SEND)
                                     ? spdy::CONTROL_FLAG_FIN
                                     : spdy::CONTROL_FLAG_NONE;
  std::unique_ptr<spdy::SpdySerializedFrame> frame(session_->CreateHeaders(
      stream_id_, priority_, flags, std::move(request_headers_),
      delegate_->source_dependency()));
  request_headers_valid_ = false;
  send_time_ = base::TimeTicks::Now();
  return frame;
}

void SpdyStream::DetachDelegate() {
  DCHECK(!IsClosed());
  delegate_ = nullptr;
  Cancel(ERR_ABORTED);
}

void SpdyStream::SetPriority(RequestPriority priority) {
  if (priority_ == priority) {
    return;
  }

  session_->UpdateStreamPriority(this, /* old_priority = */ priority_,
                                 /* new_priority = */ priority);

  priority_ = priority;
}

bool SpdyStream::AdjustSendWindowSize(int32_t delta_window_size) {
  if (IsClosed())
    return true;

  if (delta_window_size > 0) {
    if (send_window_size_ >
        std::numeric_limits<int32_t>::max() - delta_window_size) {
      return false;
    }
  } else {
    // Minimum allowed value for spdy::SETTINGS_INITIAL_WINDOW_SIZE is 0 and
    // maximum is 2^31-1.  Data are not sent when |send_window_size_ < 0|, that
    // is, |send_window_size_ | can only decrease by a change in
    // spdy::SETTINGS_INITIAL_WINDOW_SIZE.  Therefore |send_window_size_| should
    // never be able to become less than -(2^31-1).
    DCHECK_LE(std::numeric_limits<int32_t>::min() - delta_window_size,
              send_window_size_);
  }

  send_window_size_ += delta_window_size;

  net_log_.AddEvent(NetLogEventType::HTTP2_STREAM_UPDATE_SEND_WINDOW, [&] {
    return NetLogSpdyStreamWindowUpdateParams(stream_id_, delta_window_size,
                                              send_window_size_);
  });

  PossiblyResumeIfSendStalled();
  return true;
}

void SpdyStream::OnWriteBufferConsumed(
    size_t frame_payload_size,
    size_t consume_size,
    SpdyBuffer::ConsumeSource consume_source) {
  if (consume_source == SpdyBuffer::DISCARD) {
    // If we're discarding a frame or part of it, increase the send
    // window by the number of discarded bytes. (Although if we're
    // discarding part of a frame, it's probably because of a write
    // error and we'll be tearing down the stream soon.)
    size_t remaining_payload_bytes = std::min(consume_size, frame_payload_size);
    DCHECK_GT(remaining_payload_bytes, 0u);
    IncreaseSendWindowSize(static_cast<int32_t>(remaining_payload_bytes));
  }
  // For consumed bytes, the send window is increased when we receive
  // a WINDOW_UPDATE frame.
}

void SpdyStream::IncreaseSendWindowSize(int32_t delta_window_size) {
  DCHECK_GE(delta_window_size, 1);

  if (!AdjustSendWindowSize(delta_window_size)) {
    std::string desc = base::StringPrintf(
        "Received WINDOW_UPDATE [delta: %d] for stream %d overflows "
        "send_window_size_ [current: %d]",
        delta_window_size, stream_id_, send_window_size_);
    session_->ResetStream(stream_id_, ERR_HTTP2_FLOW_CONTROL_ERROR, desc);
  }
}

void SpdyStream::DecreaseSendWindowSize(int32_t delta_window_size) {
  if (IsClosed())
    return;

  // We only call this method when sending a frame. Therefore,
  // |delta_window_size| should be within the valid frame size range.
  DCHECK_GE(delta_window_size, 1);
  DCHECK_LE(delta_window_size, kMaxSpdyFrameChunkSize);

  // |send_window_size_| should have been at least |delta_window_size| for
  // this call to happen.
  DCHECK_GE(send_window_size_, delta_window_size);

  send_window_size_ -= delta_window_size;

  net_log_.AddEvent(NetLogEventType::HTTP2_STREAM_UPDATE_SEND_WINDOW, [&] {
    return NetLogSpdyStreamWindowUpdateParams(stream_id_, -delta_window_size,
                                              send_window_size_);
  });
}

void SpdyStream::OnReadBufferConsumed(
    size_t consume_size,
    SpdyBuffer::ConsumeSource consume_source) {
  DCHECK_GE(consume_size, 1u);
  DCHECK_LE(consume_size,
            static_cast<size_t>(std::numeric_limits<int32_t>::max()));
  IncreaseRecvWindowSize(static_cast<int32_t>(consume_size));
}

void SpdyStream::IncreaseRecvWindowSize(int32_t delta_window_size) {
  // By the time a read is processed by the delegate, this stream may
  // already be inactive.
  if (!session_->IsStreamActive(stream_id_))
    return;

  DCHECK_GE(unacked_recv_window_bytes_, 0);
  DCHECK_GE(recv_window_size_, unacked_recv_window_bytes_);
  DCHECK_GE(delta_window_size, 1);
  // Check for overflow.
  DCHECK_LE(delta_window_size,
            std::numeric_limits<int32_t>::max() - recv_window_size_);

  recv_window_size_ += delta_window_size;
  net_log_.AddEvent(NetLogEventType::HTTP2_STREAM_UPDATE_RECV_WINDOW, [&] {
    return NetLogSpdyStreamWindowUpdateParams(stream_id_, delta_window_size,
                                              recv_window_size_);
  });

  // Update the receive window once half of the buffer is ready to be acked
  // to prevent excessive window updates on fast downloads. Also send an update
  // if too much time has elapsed since the last update to deal with
  // slow-reading clients so the server doesn't think the stream is idle.
  unacked_recv_window_bytes_ += delta_window_size;
  const base::TimeDelta elapsed =
      base::TimeTicks::Now() - last_recv_window_update_;
  if (unacked_recv_window_bytes_ > max_recv_window_size_ / 2 ||
      elapsed >= session_->TimeToBufferSmallWindowUpdates()) {
    last_recv_window_update_ = base::TimeTicks::Now();
    session_->SendStreamWindowUpdate(
        stream_id_, static_cast<uint32_t>(unacked_recv_window_bytes_));
    unacked_recv_window_bytes_ = 0;
  }
}

void SpdyStream::DecreaseRecvWindowSize(int32_t delta_window_size) {
  DCHECK(session_->IsStreamActive(stream_id_));
  DCHECK_GE(delta_window_size, 1);

  // The receiving window size as the peer knows it is
  // |recv_window_size_ - unacked_recv_window_bytes_|, if more data are sent by
  // the peer, that means that the receive window is not being respected.
  if (delta_window_size > recv_window_size_ - unacked_recv_window_bytes_) {
    session_->ResetStream(
        stream_id_, ERR_HTTP2_FLOW_CONTROL_ERROR,
        "delta_window_size is " + base::NumberToString(delta_window_size) +
            " in DecreaseRecvWindowSize, which is larger than the receive " +
            "window size of " + base::NumberToString(recv_window_size_));
    return;
  }

  recv_window_size_ -= delta_window_size;
  net_log_.AddEvent(NetLogEventType::HTTP2_STREAM_UPDATE_RECV_WINDOW, [&] {
    return NetLogSpdyStreamWindowUpdateParams(stream_id_, -delta_window_size,
                                              recv_window_size_);
  });
}

int SpdyStream::GetPeerAddress(IPEndPoint* address) const {
  return session_->GetPeerAddress(address);
}

int SpdyStream::GetLocalAddress(IPEndPoint* address) const {
  return session_->GetLocalAddress(address);
}

bool SpdyStream::WasEverUsed() const {
  return session_->WasEverUsed();
}

base::Time SpdyStream::GetRequestTime() const {
  return request_time_;
}

void SpdyStream::SetRequestTime(base::Time t) {
  request_time_ = t;
}

void SpdyStream::OnHeadersReceived(
    const quiche::HttpHeaderBlock& response_headers,
    base::Time response_time,
    base::TimeTicks recv_first_byte_time) {
  switch (response_state_) {
    case READY_FOR_HEADERS: {
      // No header block has been received yet.
      DCHECK(response_headers_.empty());

      quiche::HttpHeaderBlock::const_iterator it =
          response_headers.find(spdy::kHttp2StatusHeader);
      if (it == response_headers.end()) {
        const std::string error("Response headers do not include :status.");
        LogStreamError(ERR_HTTP2_PROTOCOL_ERROR, error);
        session_->ResetStream(stream_id_, ERR_HTTP2_PROTOCOL_ERROR, error);
        return;
      }

      int status;
      if (!base::StringToInt(it->second, &status)) {
        const std::string error("Cannot parse :status.");
        LogStreamError(ERR_HTTP2_PROTOCOL_ERROR, error);
        session_->ResetStream(stream_id_, ERR_HTTP2_PROTOCOL_ERROR, error);
        return;
      }

      base::UmaHistogramSparse("Net.SpdyResponseCode", status);

      // Include informational responses (1xx) in the TTFB as per the resource
      // timing spec for responseStart.
      if (recv_first_byte_time_.is_null())
        recv_first_byte_time_ = recv_first_byte_time;
      // Also record the TTFB of non-informational responses.
      if (status / 100 != 1) {
        DCHECK(recv_first_byte_time_for_non_informational_response_.is_null());
        recv_first_byte_time_for_non_informational_response_ =
            recv_first_byte_time;
      }

      // Handle informational responses (1xx):
      // * Pass through 101 Switching Protocols, because broken servers might
      //   send this as a response to a WebSocket request, in which case it
      //   needs to pass through so that the WebSocket layer can signal an
      //   error.
      // * Plumb 103 Early Hints to the delegate.
      // * Ignore other informational responses.
      if (status / 100 == 1 && status != HTTP_SWITCHING_PROTOCOLS) {
        if (status == HTTP_EARLY_HINTS)
          OnEarlyHintsReceived(response_headers, recv_first_byte_time);
        return;
      }

      response_state_ = READY_FOR_DATA_OR_TRAILERS;

      switch (type_) {
        case SPDY_BIDIRECTIONAL_STREAM:
        case SPDY_REQUEST_RESPONSE_STREAM:
          // A bidirectional stream or a request/response stream is ready for
          // the response headers only after request headers are sent.
          if (io_state_ == STATE_IDLE) {
            const std::string error("Response received before request sent.");
            LogStreamError(ERR_HTTP2_PROTOCOL_ERROR, error);
            session_->ResetStream(stream_id_, ERR_HTTP2_PROTOCOL_ERROR, error);
            return;
          }
          break;
      }

      DCHECK_NE(io_state_, STATE_IDLE);

      response_time_ = response_time;
      SaveResponseHeaders(response_headers, status);

      break;
    }
    case READY_FOR_DATA_OR_TRAILERS:
      // Second header block is trailers.
      response_state_ = TRAILERS_RECEIVED;
      delegate_->OnTrailers(response_headers);
      break;

    case TRAILERS_RECEIVED:
      // No further header blocks are allowed after trailers.
      const std::string error("Header block received after trailers.");
      LogStreamError(ERR_HTTP2_PROTOCOL_ERROR, error);
      session_->ResetStream(stream_id_, ERR_HTTP2_PROTOCOL_ERROR, error);
      break;
  }
}

void SpdyStream::OnDataReceived(std::unique_ptr<SpdyBuffer> buffer) {
  DCHECK(session_->IsStreamActive(stream_id_));

  if (response_state_ == READY_FOR_HEADERS) {
    const std::string error("DATA received before headers.");
    LogStreamError(ERR_HTTP2_PROTOCOL_ERROR, error);
    session_->ResetStream(stream_id_, ERR_HTTP2_PROTOCOL_ERROR, error);
    return;
  }

  if (response_state_ == TRAILERS_RECEIVED && buffer) {
    const std::string error("DATA received after trailers.");
    LogStreamError(ERR_HTTP2_PROTOCOL_ERROR, error);
    session_->ResetStream(stream_id_, ERR_HTTP2_PROTOCOL_ERROR, error);
    return;
  }

  if (io_state_ == STATE_HALF_CLOSED_REMOTE) {
    const std::string error("DATA received on half-closed (remove) stream.");
    LogStreamError(ERR_HTTP2_STREAM_CLOSED, error);
    session_->ResetStream(stream_id_, ERR_HTTP2_STREAM_CLOSED, error);
    return;
  }

  // Track our bandwidth.
  recv_bytes_ += buffer ? buffer->GetRemainingSize() : 0;
  recv_last_byte_time_ = base::TimeTicks::Now();

  CHECK(!IsClosed());

  if (!buffer) {
    if (io_state_ == STATE_OPEN) {
      io_state_ = STATE_HALF_CLOSED_REMOTE;
      // Inform the delegate of EOF. This may delete |this|.
      delegate_->OnDataReceived(nullptr);
    } else if (io_state_ == STATE_HALF_CLOSED_LOCAL) {
      io_state_ = STATE_CLOSED;
      // Deletes |this|.
      session_->CloseActiveStream(stream_id_, OK);
    } else {
      NOTREACHED() << io_state_;
    }
    return;
  }

  size_t length = buffer->GetRemainingSize();
  DCHECK_LE(length, spdy::kHttp2DefaultFramePayloadLimit);
  base::WeakPtr<SpdyStream> weak_this = GetWeakPtr();
  // May close the stream.
  DecreaseRecvWindowSize(static_cast<int32_t>(length));
  if (!weak_this)
    return;
  buffer->AddConsumeCallback(
      base::BindRepeating(&SpdyStream::OnReadBufferConsumed, GetWeakPtr()));

  // May close |this|.
  delegate_->OnDataReceived(std::move(buffer));
}

void SpdyStream::OnPaddingConsumed(size_t len) {
  // Decrease window size because padding bytes are received.
  // Increase window size because padding bytes are consumed (by discarding).
  // Net result: |unacked_recv_window_bytes_| increases by |len|,
  // |recv_window_size_| does not change.
  base::WeakPtr<SpdyStream> weak_this = GetWeakPtr();
  // May close the stream.
  DecreaseRecvWindowSize(static_cast<int32_t>(len));
  if (!weak_this)
    return;
  IncreaseRecvWindowSize(static_cast<int32_t>(len));
}

void SpdyStream::OnFrameWriteComplete(spdy::SpdyFrameType frame_type,
                                      size_t frame_size) {
  if (frame_type != spdy::SpdyFrameType::HEADERS &&
      frame_type != spdy::SpdyFrameType::DATA) {
    return;
  }

  int result = (frame_type == spdy::SpdyFrameType::HEADERS)
                   ? OnHeadersSent()
                   : OnDataSent(frame_size);
  if (result == ERR_IO_PENDING) {
    // The write operation hasn't completed yet.
    return;
  }

  if (pending_send_status_ == NO_MORE_DATA_TO_SEND) {
    if (io_state_ == STATE_OPEN) {
      io_state_ = STATE_HALF_CLOSED_LOCAL;
    } else if (io_state_ == STATE_HALF_CLOSED_REMOTE) {
      io_state_ = STATE_CLOSED;
    } else {
      NOTREACHED() << io_state_;
    }
  }
  // Notify delegate of write completion. Must not destroy |this|.
  CHECK(delegate_);
  {
    base::WeakPtr<SpdyStream> weak_this = GetWeakPtr();
    write_handler_guard_ = true;
    if (frame_type == spdy::SpdyFrameType::HEADERS) {
      delegate_->OnHeadersSent();
    } else {
      delegate_->OnDataSent();
    }
    CHECK(weak_this);
    write_handler_guard_ = false;
  }

  if (io_state_ == STATE_CLOSED) {
    // Deletes |this|.
    session_->CloseActiveStream(stream_id_, OK);
  }
}

int SpdyStream::OnHeadersSent() {
  CHECK_EQ(io_state_, STATE_IDLE);
  CHECK_NE(stream_id_, 0u);

  io_state_ = STATE_OPEN;
  return OK;
}

int SpdyStream::OnDataSent(size_t frame_size) {
  CHECK(io_state_ == STATE_OPEN ||
        io_state_ == STATE_HALF_CLOSED_REMOTE) << io_state_;

  size_t frame_payload_size = frame_size - spdy::kDataFrameMinimumSize;

  CHECK_GE(frame_size, spdy::kDataFrameMinimumSize);
  CHECK_LE(frame_payload_size, spdy::kHttp2DefaultFramePayloadLimit);

  // If more data is available to send, dispatch it and
  // return that the write operation is still ongoing.
  pending_send_data_->DidConsume(frame_payload_size);
  if (pending_send_data_->BytesRemaining() > 0) {
    QueueNextDataFrame();
    return ERR_IO_PENDING;
  } else {
    pending_send_data_ = nullptr;
    return OK;
  }
}

void SpdyStream::LogStreamError(int error, std::string_view description) {
  net_log_.AddEvent(NetLogEventType::HTTP2_STREAM_ERROR, [&] {
    return NetLogSpdyStreamErrorParams(stream_id_, error, description);
  });
}

void SpdyStream::OnClose(int status) {
  // In most cases, the stream should already be CLOSED. The exception is when a
  // SpdySession is shutting down while the stream is in an intermediate state.
  io_state_ = STATE_CLOSED;
  if (status == ERR_HTTP2_RST_STREAM_NO_ERROR_RECEIVED) {
    if (response_state_ == READY_FOR_HEADERS) {
      status = ERR_HTTP2_PROTOCOL_ERROR;
    } else {
      status = OK;
    }
  }
  Delegate* delegate = delegate_;
  delegate_ = nullptr;
  if (delegate)
    delegate->OnClose(status);
  // Unset |stream_id_| last so that the delegate can look it up.
  stream_id_ = 0;
}

void SpdyStream::Cancel(int error) {
  // We may be called again from a delegate's OnClose().
  if (io_state_ == STATE_CLOSED)
    return;

  if (stream_id_ != 0) {
    session_->ResetStream(stream_id_, error, std::string());
  } else {
    session_->CloseCreatedStream(GetWeakPtr(), error);
  }
  // |this| is invalid at this point.
}

void SpdyStream::Close() {
  // We may be called again from a delegate's OnClose().
  if (io_state_ == STATE_CLOSED)
    return;

  if (stream_id_ != 0) {
    session_->CloseActiveStream(stream_id_, OK);
  } else {
    session_->CloseCreatedStream(GetWeakPtr(), OK);
  }
  // |this| is invalid at this point.
}

base::WeakPtr<SpdyStream> SpdyStream::GetWeakPtr() {
  return weak_ptr_factory_.GetWeakPtr();
}

int SpdyStream::SendRequestHeaders(quiche::HttpHeaderBlock request_headers,
                                   SpdySendStatus send_status) {
  net_log_.AddEvent(
      NetLogEventType::HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS,
      [&](NetLogCaptureMode capture_mode) {
        return HttpHeaderBlockNetLogParams(&request_headers, capture_mode);
      });
  CHECK_EQ(pending_send_status_, MORE_DATA_TO_SEND);
  CHECK(!request_headers_valid_);
  CHECK(!pending_send_data_.get());
  CHECK_EQ(io_state_, STATE_IDLE);
  request_headers_ = std::move(request_headers);
  request_headers_valid_ = true;
  pending_send_status_ = send_status;
  session_->EnqueueStreamWrite(
      GetWeakPtr(), spdy::SpdyFrameType::HEADERS,
      std::make_unique<HeadersBufferProducer>(GetWeakPtr()));
  return ERR_IO_PENDING;
}

void SpdyStream::SendData(IOBuffer* data,
                          int length,
                          SpdySendStatus send_status) {
  CHECK_EQ(pending_send_status_, MORE_DATA_TO_SEND);
  CHECK(io_state_ == STATE_OPEN ||
        io_state_ == STATE_HALF_CLOSED_REMOTE) << io_state_;
  CHECK(!pending_send_data_.get());
  pending_send_data_ = base::MakeRefCounted<DrainableIOBuffer>(data, length);
  pending_send_status_ = send_status;
  QueueNextDataFrame();
}

bool SpdyStream::GetSSLInfo(SSLInfo* ssl_info) const {
  return session_->GetSSLInfo(ssl_info);
}

NextProto SpdyStream::GetNegotiatedProtocol() const {
  return session_->GetNegotiatedProtocol();
}

SpdyStream::ShouldRequeueStream SpdyStream::PossiblyResumeIfSendStalled() {
  if (IsLocallyClosed() || !send_stalled_by_flow_control_)
    return DoNotRequeue;
  if (session_->IsSendStalled() || send_window_size_ <= 0) {
    return Requeue;
  }
  net_log_.AddEventWithIntParams(
      NetLogEventType::HTTP2_STREAM_FLOW_CONTROL_UNSTALLED, "stream_id",
      stream_id_);
  send_stalled_by_flow_control_ = false;
  QueueNextDataFrame();
  return DoNotRequeue;
}

bool SpdyStream::IsClosed() const {
  return io_state_ == STATE_CLOSED;
}

bool SpdyStream::IsLocallyClosed() const {
  return io_state_ == STATE_HALF_CLOSED_LOCAL || io_state_ == STATE_CLOSED;
}

bool SpdyStream::IsIdle() const {
  return io_state_ == STATE_IDLE;
}

bool SpdyStream::IsOpen() const {
  return io_state_ == STATE_OPEN;
}

bool SpdyStream::IsReservedRemote() const {
  return io_state_ == STATE_RESERVED_REMOTE;
}

void SpdyStream::AddRawReceivedBytes(size_t received_bytes) {
  raw_received_bytes_ += received_bytes;
}

void SpdyStream::AddRawSentBytes(size_t sent_bytes) {
  raw_sent_bytes_ += sent_bytes;
}

bool SpdyStream::GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
  if (stream_id_ == 0)
    return false;
  bool result = session_->GetLoadTimingInfo(stream_id_, load_timing_info);
  // TODO(acomminos): recv_first_byte_time_ is actually the time after all
  // headers have been parsed. We should add support for reporting the time the
  // first bytes of the HEADERS frame were received to BufferedSpdyFramer
  // (https://crbug.com/568024).
  load_timing_info->receive_headers_start = recv_first_byte_time_;
  load_timing_info->receive_non_informational_headers_start =
      recv_first_byte_time_for_non_informational_response_;
  load_timing_info->first_early_hints_time = first_early_hints_time_;
  return result;
}

void SpdyStream::QueueNextDataFrame() {
  // Until the request has been completely sent, we cannot be sure
  // that our stream_id is correct.
  CHECK(io_state_ == STATE_OPEN ||
        io_state_ == STATE_HALF_CLOSED_REMOTE) << io_state_;
  CHECK_GT(stream_id_, 0u);
  CHECK(pending_send_data_.get());
  // Only the final fame may have a length of 0.
  if (pending_send_status_ == NO_MORE_DATA_TO_SEND) {
    CHECK_GE(pending_send_data_->BytesRemaining(), 0);
  } else {
    CHECK_GT(pending_send_data_->BytesRemaining(), 0);
  }

  spdy::SpdyDataFlags flags = (pending_send_status_ == NO_MORE_DATA_TO_SEND)
                                  ? spdy::DATA_FLAG_FIN
                                  : spdy::DATA_FLAG_NONE;
  int effective_len;
  bool end_stream;
  std::unique_ptr<SpdyBuffer> data_buffer(
      session_->CreateDataBuffer(stream_id_, pending_send_data_.get(),
                                 pending_send_data_->BytesRemaining(), flags,
                                 &effective_len, &end_stream));
  // We'll get called again by PossiblyResumeIfSendStalled().
  if (!data_buffer)
    return;

  DCHECK_GE(data_buffer->GetRemainingSize(), spdy::kDataFrameMinimumSize);
  size_t payload_size =
      data_buffer->GetRemainingSize() - spdy::kDataFrameMinimumSize;
  DCHECK_LE(payload_size, spdy::kHttp2DefaultFramePayloadLimit);

  // Send window size is based on payload size, so nothing to do if this is
  // just a FIN with no payload.
  if (payload_size != 0) {
    DecreaseSendWindowSize(static_cast<int32_t>(payload_size));
    // This currently isn't strictly needed, since write frames are
    // discarded only if the stream is about to be closed. But have it
    // here anyway just in case this changes.
    data_buffer->AddConsumeCallback(base::BindRepeating(
        &SpdyStream::OnWriteBufferConsumed, GetWeakPtr(), payload_size));
  }

  if (session_->GreasedFramesEnabled() && delegate_ &&
      delegate_->CanGreaseFrameType()) {
    session_->EnqueueGreasedFrame(GetWeakPtr());
  }

  session_->net_log().AddEvent(NetLogEventType::HTTP2_SESSION_SEND_DATA, [&] {
    return NetLogSpdyDataParams(stream_id_, effective_len, end_stream);
  });

  session_->EnqueueStreamWrite(
      GetWeakPtr(), spdy::SpdyFrameType::DATA,
      std::make_unique<SimpleBufferProducer>(std::move(data_buffer)));
}

void SpdyStream::OnEarlyHintsReceived(
    const quiche::HttpHeaderBlock& response_headers,
    base::TimeTicks recv_first_byte_time) {
  // Record the timing of the 103 Early Hints response for the experiment
  // (https://crbug.com/1093693).
  if (first_early_hints_time_.is_null())
    first_early_hints_time_ = recv_first_byte_time;

  // Transfer-encoding is a connection specific header.
  if (response_headers.find("transfer-encoding") != response_headers.end()) {
    const char error[] = "Received transfer-encoding header";
    LogStreamError(ERR_HTTP2_PROTOCOL_ERROR, error);
    session_->ResetStream(stream_id_, ERR_HTTP2_PROTOCOL_ERROR, error);
    return;
  }

  if (type_ != SPDY_REQUEST_RESPONSE_STREAM || io_state_ == STATE_IDLE) {
    const char error[] = "Early Hints received before request sent.";
    LogStreamError(ERR_HTTP2_PROTOCOL_ERROR, error);
    session_->ResetStream(stream_id_, ERR_HTTP2_PROTOCOL_ERROR, error);
    return;
  }

  // `delegate_` must be attached at this point when `type_` is
  // SPDY_REQUEST_RESPONSE_STREAM.
  CHECK(delegate_);
  delegate_->OnEarlyHintsReceived(response_headers);
}

void SpdyStream::SaveResponseHeaders(
    const quiche::HttpHeaderBlock& response_headers,
    int status) {
  if (response_headers.contains("transfer-encoding")) {
    session_->ResetStream(stream_id_, ERR_HTTP2_PROTOCOL_ERROR,
                          "Received transfer-encoding header");
    return;
  }

  DCHECK(response_headers_.empty());
  response_headers_ = response_headers.Clone();

  // If delegate is not yet attached, OnHeadersReceived() will be called after
  // the delegate gets attached to the stream.
  if (!delegate_)
    return;

  delegate_->OnHeadersReceived(response_headers_);
}

#define STATE_CASE(s)                                       \
  case s:                                                   \
    description = base::StringPrintf("%s (0x%08X)", #s, s); \
    break

std::string SpdyStream::DescribeState(State state) {
  std::string description;
  switch (state) {
    STATE_CASE(STATE_IDLE);
    STATE_CASE(STATE_OPEN);
    STATE_CASE(STATE_HALF_CLOSED_LOCAL);
    STATE_CASE(STATE_CLOSED);
    default:
      description =
          base::StringPrintf("Unknown state 0x%08X (%u)", state, state);
      break;
  }
  return description;
}

#undef STATE_CASE

}  // namespace net
```
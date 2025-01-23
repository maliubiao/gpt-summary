Response:
Let's break down the thought process for analyzing this `bidirectional_stream.cc` file.

**1. Understanding the Core Purpose:**

The filename itself, "bidirectional_stream.cc," strongly suggests its function: handling bidirectional communication over HTTP. Reading the initial comments confirms this, stating it's for "exchanging data with a server on behalf of an RPC API."  This immediately tells me it's designed for scenarios where the client *and* server can send data independently and potentially simultaneously.

**2. Identifying Key Components and their Roles:**

I start scanning the code for classes, methods, and data members that seem important.

* **`BidirectionalStream` class:** This is the central class. Its methods (`SendRequestHeaders`, `ReadData`, `SendvData`, etc.) represent the API for using a bidirectional stream.
* **`Delegate` nested class:**  This is a classic delegation pattern. The `BidirectionalStream` informs its delegate about important events (`OnStreamReady`, `OnHeadersReceived`, `OnDataRead`, etc.). This decouples the core logic from the specific actions the user wants to take on these events.
* **`BidirectionalStreamRequestInfo`:** This struct likely holds the initial configuration for the stream (URL, method, headers, etc.).
* **`HttpNetworkSession`:**  This is clearly the entry point into the Chromium networking stack. The `BidirectionalStream` needs a session to work.
* **`HttpStreamFactory`:** The `StartRequest()` method uses the session's `HttpStreamFactory` to create the underlying stream implementation. This hints at the possibility of different underlying protocols (like HTTP/2 or QUIC).
* **`BidirectionalStreamImpl`:**  This is the *actual* implementation of the bidirectional stream, likely handling the low-level network communication. The `BidirectionalStream` acts as a higher-level abstraction.
* **NetLog integration:**  The numerous `net_log_` calls indicate that this class is instrumented for debugging and performance analysis within Chromium.
* **Load Timing Information (`LoadTimingInfo`):**  The tracking of start times, connect times, send/receive times suggests a focus on performance measurement.

**3. Tracing the Request Flow (Mental Execution):**

I mentally follow the lifecycle of a `BidirectionalStream`:

1. **Construction:**  A `BidirectionalStream` object is created, taking request info and a delegate. It immediately checks the URL scheme (must be HTTPS).
2. **`StartRequest()`:** This initiates the underlying stream creation via the `HttpStreamFactory`.
3. **`OnBidirectionalStreamImplReady()`:**  The `HttpStreamFactory` (asynchronously) provides the concrete `BidirectionalStreamImpl`.
4. **Sending Data (`SendvData()`):** Data is passed to the underlying `BidirectionalStreamImpl`.
5. **Receiving Data (`ReadData()`):**  Data is read from the underlying stream.
6. **Callbacks to Delegate:** Events like headers received, data read, data sent, and failure are reported to the delegate.
7. **Destruction:**  Resources are cleaned up.

**4. Identifying Potential JavaScript Interaction:**

I consider how a browser might use this. JavaScript doesn't directly manipulate these C++ classes. The connection is through higher-level browser APIs. The most likely candidate is the Fetch API, particularly its `Request` and `Response` objects, and potentially WebSockets (though this file seems more focused on HTTP-like bidirectional streams). I look for concepts that align with Fetch, such as headers, request methods, and the idea of sending and receiving data.

**5. Looking for Logic and Assumptions:**

I examine specific methods:

* **`OnHeadersReceived()`:**  The conversion of `SpdyHeadersToHttpResponse` suggests support for HTTP/2 (SPDY). The processing of alternative services is another network optimization feature.
* **`OnFailed()` and `NotifyFailed()`:**  These handle error reporting, which is crucial.
* **`SendRequestHeaders()`:**  The existence of this method, along with the `send_request_headers_automatically_` flag, indicates flexibility in when headers are sent.

**6. Considering User/Programmer Errors:**

I think about common mistakes someone might make when using this functionality (through the higher-level JavaScript APIs):

* **Incorrect URL Scheme:** The explicit check for HTTPS is a potential source of error.
* **Sending Data Before Ready:**  While not directly enforced in *this* class, a poorly written application might try to send data before the `OnStreamReady` callback.
* **Mismatched Send/Receive:**  While bidirectional, applications still need to manage the flow of data and avoid deadlocks.
* **Ignoring Errors:**  Failing to handle the `OnFailed()` callback is a common programming error.

**7. Thinking About Debugging:**

The NetLog integration is a huge clue for debugging. I imagine scenarios where a developer might need to track the lifecycle of a bidirectional stream, see the headers exchanged, or diagnose network errors. The step-by-step user actions leading to this code would involve making a fetch request (or similar) that triggers the creation of a bidirectional stream.

**8. Structuring the Output:**

Finally, I organize the information into the requested categories:

* **Functionality:** Summarize the core purpose and key features.
* **JavaScript Relationship:**  Explain how this C++ code relates to browser APIs like Fetch.
* **Logic and Assumptions:** Provide examples with hypothetical inputs and outputs for key methods.
* **User/Programming Errors:** Illustrate common mistakes.
* **Debugging:** Describe the user actions leading to this code and how to use the provided tools (NetLog).

This iterative process of reading, identifying components, tracing the flow, connecting to higher-level concepts, and considering potential errors allows for a comprehensive understanding of the `bidirectional_stream.cc` file.This C++ source code file, `bidirectional_stream.cc`, located in the `net/http` directory of the Chromium network stack, implements the **`BidirectionalStream`** class. This class provides an interface for establishing and managing **bidirectional communication channels over HTTP**, primarily intended for use cases like gRPC or other RPC-like APIs where both the client and server need to send data independently and concurrently.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Abstraction over Underlying HTTP Streams:** It acts as a higher-level abstraction, hiding the complexities of the underlying HTTP/2 or QUIC streams used for bidirectional communication.

2. **Initiating a Bidirectional Stream:** It allows initiating a bidirectional stream request to a server, encapsulating the necessary request information like URL, HTTP method, and headers.

3. **Sending Request Headers (Optional):** It provides a mechanism to send request headers to the server. This can be done automatically upon stream creation or manually later.

4. **Sending Data:** It offers methods (`SendvData`) to send data to the server in chunks (IOBuffers).

5. **Receiving Data:** It provides a method (`ReadData`) to read data sent by the server.

6. **Handling Response Headers and Trailers:** It handles the reception of HTTP response headers and trailers from the server.

7. **Error Handling:** It includes mechanisms for reporting errors that occur during the stream lifecycle.

8. **Load Timing Information:** It collects and exposes timing information about the stream's connection and data transfer phases, useful for performance analysis.

9. **NetLog Integration:** It heavily utilizes the Chromium NetLog system to log events and data related to the bidirectional stream, aiding in debugging and network analysis.

**Relationship with JavaScript Functionality:**

The `BidirectionalStream` class in C++ is **not directly accessible or manipulated by JavaScript code**. Instead, it serves as a foundational building block for higher-level browser APIs that JavaScript *can* interact with.

Here's how it relates:

* **Fetch API:** While the standard Fetch API is primarily designed for request-response interactions, extensions or modifications might leverage `BidirectionalStream` internally for more advanced scenarios. For example, a custom `DuplexStream` implementation in JavaScript (part of the Streams API) could potentially be backed by a `BidirectionalStream` in the browser's networking layer.

* **gRPC-Web:**  gRPC-Web, a technology that allows web browsers to communicate with gRPC services, heavily relies on bidirectional streaming. The browser's implementation of gRPC-Web would likely use classes like `BidirectionalStream` under the hood to manage the underlying HTTP/2 connections and data flow.

**Example of Potential Indirect Interaction (Hypothetical):**

Imagine a JavaScript application using a gRPC-Web client library.

```javascript
// JavaScript code using a hypothetical gRPC-Web client
const client = new MyGrpcServiceClient("https://example.com/grpc");
const call = client.myBidirectionalMethod();

call.on('data', (message) => {
  console.log("Received:", message);
});

call.on('end', () => {
  console.log("Stream ended.");
});

call.write({ request_data: "some data" });
call.write({ request_data: "more data" });
call.end();
```

In this scenario, when `client.myBidirectionalMethod()` is called, the underlying gRPC-Web client library in the browser (implemented in C++) would likely:

1. Create a `BidirectionalStreamRequestInfo` object with the appropriate gRPC endpoint and headers.
2. Instantiate a `BidirectionalStream` object using the request info and the browser's `HttpNetworkSession`.
3. Call `SendRequestHeaders()` if necessary.
4. When `call.write()` is called in JavaScript, the data would be passed down to the C++ layer and eventually sent using `BidirectionalStream::SendvData()`.
5. When the server sends data, it would be received by the `BidirectionalStream` and the `Delegate::OnDataRead()` callback would be triggered, eventually propagating the data back to the JavaScript `call.on('data', ...)` handler.

**Logic and Assumptions (with Hypothetical Input/Output):**

Let's consider the `ReadData` method:

**Assumption:** The underlying HTTP/2 or QUIC stream has received data from the server.

**Hypothetical Input:**

* `buf`: An `IOBuffer` with a size of 1024 bytes allocated in the JavaScript layer (via some browser API).
* `buf_len`: 1024.

**Hypothetical Output:**

* **Scenario 1 (Data Available):** If the underlying stream has 500 bytes of data available, `ReadData` would copy those 500 bytes into `buf` and return `500`. The `delegate_->OnDataRead(500)` callback would be invoked.
* **Scenario 2 (No Data Available):** If no data is immediately available, `ReadData` would return `ERR_IO_PENDING`. The `read_buffer_` would be set to `buf`. When data arrives later, the underlying stream implementation would call `OnDataRead` with the number of bytes read.
* **Scenario 3 (Error):** If an error occurs on the underlying stream (e.g., connection closed prematurely), `ReadData` might return a negative error code like `ERR_CONNECTION_RESET`. The `delegate_->OnFailed()` callback would be invoked.

**User or Programming Common Usage Errors (and how they might lead here):**

1. **Using an Insecure URL (HTTP instead of HTTPS):**

   * **User Action:** A JavaScript application attempts to create a bidirectional stream to an `http://` URL.
   * **Path to this code:** The `BidirectionalStream` constructor checks the URL scheme. If it's not HTTPS, it will synchronously post a task to call `NotifyFailed` with `ERR_DISALLOWED_URL_SCHEME`.
   * **Example:**
     ```javascript
     // JavaScript (error scenario)
     const xhr = new XMLHttpRequest();
     xhr.open('POST', 'http://insecure.example.com/bidirectional'); // Likely a simplified example, actual API would be different
     // ... rest of the setup
     ```
   * **Result:** The `Delegate::OnFailed(ERR_DISALLOWED_URL_SCHEME)` callback would be invoked, informing the JavaScript layer of the error.

2. **Attempting to Send Data Before the Stream is Ready:**

   * **User Action:** A JavaScript application (or the underlying gRPC-Web client) tries to send data using the bidirectional stream API before the `OnStreamReady` callback has been received.
   * **Path to this code:**  While `BidirectionalStream::SendvData` has a `DCHECK(stream_impl_)`, the higher-level APIs should ideally prevent this. If they don't, calling `SendvData` before `stream_impl_` is set would lead to a crash due to a null pointer dereference.
   * **Example (Conceptual):**
     ```javascript
     // JavaScript (potential error if not handled properly by the higher-level API)
     const stream = createBidirectionalStream("https://example.com/bidirectional");
     stream.send("early data"); // Might fail if the underlying stream isn't ready yet
     stream.onReady(() => {
       stream.send("later data");
     });
     ```
   * **Result:** Depending on the implementation of the higher-level API, this might result in an error, data loss, or a crash.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User visits a webpage or runs a web application.**
2. **The JavaScript code on the page or application initiates a communication that requires a bidirectional stream.** This could be:
   * Making a gRPC-Web call.
   * Using a custom API that leverages bidirectional communication.
   * Potentially using a modified Fetch API or a Streams API implementation that utilizes bidirectional streams.
3. **The browser's networking stack receives this request.**
4. **The browser determines that a bidirectional stream is needed.** This decision is made based on the protocol and headers of the request.
5. **An instance of `BidirectionalStream` is created in the C++ networking layer.**
6. **The `StartRequest()` method is called, initiating the connection process.**
7. **The `HttpStreamFactory` finds or creates an appropriate underlying HTTP/2 or QUIC stream.**
8. **The `OnBidirectionalStreamImplReady()` callback is invoked, providing the concrete stream implementation.**
9. **Data is sent and received using the `SendvData` and `ReadData` methods.**
10. **Events like headers received, data read, and stream closure trigger the corresponding `Delegate` methods.**

**Debugging Clues:**

* **NetLog:** The most valuable tool for debugging issues related to `BidirectionalStream`. By capturing a NetLog, developers can see the sequence of events, headers exchanged, data transfer, and any errors that occur during the stream's lifetime. Look for `BIDIRECTIONAL_STREAM_*` events in the NetLog.
* **Breakpoints:** Setting breakpoints in the `BidirectionalStream` class methods (e.g., `SendvData`, `ReadData`, `OnDataRead`, `OnFailed`) allows developers to inspect the state of the stream and the data being transferred.
* **Higher-Level API Debugging:** Debugging the JavaScript code or the gRPC-Web client library can help pinpoint where the request for a bidirectional stream originates and how data is being sent and received.

In summary, `bidirectional_stream.cc` is a crucial component of Chromium's networking stack, providing the foundation for efficient and flexible bidirectional communication over HTTP, often used indirectly by JavaScript through higher-level APIs like gRPC-Web or potentially extended Fetch implementations. Understanding its functionality is essential for diagnosing network-related issues in these scenarios.

### 提示词
```
这是目录为net/http/bidirectional_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/bidirectional_stream.h"

#include <string>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "base/timer/timer.h"
#include "base/values.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/http/http_network_session.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_stream.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_values.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_log_util.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "url/gurl.h"

namespace net {

namespace {

base::Value::Dict NetLogHeadersParams(const quiche::HttpHeaderBlock* headers,
                                      NetLogCaptureMode capture_mode) {
  base::Value::Dict dict;
  dict.Set("headers", ElideHttpHeaderBlockForNetLog(*headers, capture_mode));
  return dict;
}

base::Value::Dict NetLogParams(const GURL& url,
                               const std::string& method,
                               const HttpRequestHeaders* headers,
                               NetLogCaptureMode capture_mode) {
  base::Value::Dict dict;
  dict.Set("url", url.possibly_invalid_spec());
  dict.Set("method", method);
  base::Value headers_param(
      headers->NetLogParams(/*request_line=*/std::string(), capture_mode));
  dict.Set("headers", std::move(headers_param));
  return dict;
}

}  // namespace

BidirectionalStream::Delegate::Delegate() = default;

BidirectionalStream::Delegate::~Delegate() = default;

BidirectionalStream::BidirectionalStream(
    std::unique_ptr<BidirectionalStreamRequestInfo> request_info,
    HttpNetworkSession* session,
    bool send_request_headers_automatically,
    Delegate* delegate)
    : BidirectionalStream(std::move(request_info),
                          session,
                          send_request_headers_automatically,
                          delegate,
                          std::make_unique<base::OneShotTimer>()) {}

BidirectionalStream::BidirectionalStream(
    std::unique_ptr<BidirectionalStreamRequestInfo> request_info,
    HttpNetworkSession* session,
    bool send_request_headers_automatically,
    Delegate* delegate,
    std::unique_ptr<base::OneShotTimer> timer)
    : request_info_(std::move(request_info)),
      net_log_(NetLogWithSource::Make(session->net_log(),
                                      NetLogSourceType::BIDIRECTIONAL_STREAM)),
      session_(session),
      send_request_headers_automatically_(send_request_headers_automatically),
      delegate_(delegate),
      timer_(std::move(timer)) {
  DCHECK(delegate_);
  DCHECK(request_info_);

  // Start time should be measured before connect.
  load_timing_info_.request_start_time = base::Time::Now();
  load_timing_info_.request_start = base::TimeTicks::Now();

  if (net_log_.IsCapturing()) {
    net_log_.BeginEvent(NetLogEventType::BIDIRECTIONAL_STREAM_ALIVE,
                        [&](NetLogCaptureMode capture_mode) {
                          return NetLogParams(
                              request_info_->url, request_info_->method,
                              &request_info_->extra_headers, capture_mode);
                        });
  }

  if (!request_info_->url.SchemeIs(url::kHttpsScheme)) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&BidirectionalStream::NotifyFailed,
                       weak_factory_.GetWeakPtr(), ERR_DISALLOWED_URL_SCHEME));
    return;
  }

  StartRequest();
}

BidirectionalStream::~BidirectionalStream() {
  if (net_log_.IsCapturing()) {
    net_log_.EndEvent(NetLogEventType::BIDIRECTIONAL_STREAM_ALIVE);
  }
}

void BidirectionalStream::SendRequestHeaders() {
  DCHECK(stream_impl_);
  DCHECK(!request_headers_sent_);
  DCHECK(!send_request_headers_automatically_);

  stream_impl_->SendRequestHeaders();
}

int BidirectionalStream::ReadData(IOBuffer* buf, int buf_len) {
  DCHECK(stream_impl_);

  int rv = stream_impl_->ReadData(buf, buf_len);
  if (rv > 0) {
    read_end_time_ = base::TimeTicks::Now();
    net_log_.AddByteTransferEvent(
        NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_RECEIVED, rv, buf->data());
  } else if (rv == ERR_IO_PENDING) {
    read_buffer_ = buf;
    // Bytes will be logged in OnDataRead().
  }
  if (net_log_.IsCapturing()) {
    net_log_.AddEventWithIntParams(
        NetLogEventType::BIDIRECTIONAL_STREAM_READ_DATA, "rv", rv);
  }
  return rv;
}

void BidirectionalStream::SendvData(
    const std::vector<scoped_refptr<IOBuffer>>& buffers,
    const std::vector<int>& lengths,
    bool end_stream) {
  DCHECK(stream_impl_);
  DCHECK_EQ(buffers.size(), lengths.size());
  DCHECK(write_buffer_list_.empty());
  DCHECK(write_buffer_len_list_.empty());

  if (net_log_.IsCapturing()) {
    net_log_.AddEventWithIntParams(
        NetLogEventType::BIDIRECTIONAL_STREAM_SENDV_DATA, "num_buffers",
        buffers.size());
  }
  stream_impl_->SendvData(buffers, lengths, end_stream);
  for (size_t i = 0; i < buffers.size(); ++i) {
    write_buffer_list_.push_back(buffers[i]);
    write_buffer_len_list_.push_back(lengths[i]);
  }
}

NextProto BidirectionalStream::GetProtocol() const {
  if (!stream_impl_)
    return kProtoUnknown;

  return stream_impl_->GetProtocol();
}

int64_t BidirectionalStream::GetTotalReceivedBytes() const {
  if (!stream_impl_)
    return 0;

  return stream_impl_->GetTotalReceivedBytes();
}

int64_t BidirectionalStream::GetTotalSentBytes() const {
  if (!stream_impl_)
    return 0;

  return stream_impl_->GetTotalSentBytes();
}

void BidirectionalStream::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  *load_timing_info = load_timing_info_;
}

void BidirectionalStream::PopulateNetErrorDetails(NetErrorDetails* details) {
  DCHECK(details);
  if (stream_impl_)
    stream_impl_->PopulateNetErrorDetails(details);
}

void BidirectionalStream::StartRequest() {
  DCHECK(!stream_request_);
  HttpRequestInfo http_request_info;
  http_request_info.url = request_info_->url;
  http_request_info.method = request_info_->method;
  http_request_info.extra_headers = request_info_->extra_headers;
  http_request_info.socket_tag = request_info_->socket_tag;
  stream_request_ =
      session_->http_stream_factory()->RequestBidirectionalStreamImpl(
          http_request_info, request_info_->priority, /*allowed_bad_certs=*/{},
          this, /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, net_log_);
  // Check that this call does not fail.
  DCHECK(stream_request_);
  // Check that HttpStreamFactory does not invoke OnBidirectionalStreamImplReady
  // synchronously.
  DCHECK(!stream_impl_);
}

void BidirectionalStream::OnStreamReady(bool request_headers_sent) {
  request_headers_sent_ = request_headers_sent;
  if (net_log_.IsCapturing()) {
    net_log_.AddEntryWithBoolParams(
        NetLogEventType::BIDIRECTIONAL_STREAM_READY, NetLogEventPhase::NONE,
        "request_headers_sent", request_headers_sent);
  }
  load_timing_info_.send_start = base::TimeTicks::Now();
  load_timing_info_.send_end = load_timing_info_.send_start;
  delegate_->OnStreamReady(request_headers_sent);
}

void BidirectionalStream::OnHeadersReceived(
    const quiche::HttpHeaderBlock& response_headers) {
  HttpResponseInfo response_info;
  if (SpdyHeadersToHttpResponse(response_headers, &response_info) != OK) {
    DLOG(WARNING) << "Invalid headers";
    NotifyFailed(ERR_FAILED);
    return;
  }
  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(NetLogEventType::BIDIRECTIONAL_STREAM_RECV_HEADERS,
                      [&](NetLogCaptureMode capture_mode) {
                        return NetLogHeadersParams(&response_headers,
                                                   capture_mode);
                      });
  }
  // Impl should only provide |connect_timing| and |socket_reused| info,
  // so use a copy to get these information only.
  LoadTimingInfo impl_load_timing_info;
  bool has_load_timing =
      stream_impl_->GetLoadTimingInfo(&impl_load_timing_info);
  if (has_load_timing) {
    load_timing_info_.connect_timing = impl_load_timing_info.connect_timing;
    load_timing_info_.socket_reused = impl_load_timing_info.socket_reused;
  }
  load_timing_info_.receive_headers_end = base::TimeTicks::Now();
  read_end_time_ = load_timing_info_.receive_headers_end;
  session_->http_stream_factory()->ProcessAlternativeServices(
      session_, NetworkAnonymizationKey(), response_info.headers.get(),
      url::SchemeHostPort(request_info_->url));
  delegate_->OnHeadersReceived(response_headers);
}

void BidirectionalStream::OnDataRead(int bytes_read) {
  DCHECK(read_buffer_);

  if (net_log_.IsCapturing()) {
    net_log_.AddByteTransferEvent(
        NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_RECEIVED, bytes_read,
        read_buffer_->data());
  }
  read_end_time_ = base::TimeTicks::Now();
  read_buffer_ = nullptr;
  delegate_->OnDataRead(bytes_read);
}

void BidirectionalStream::OnDataSent() {
  DCHECK(!write_buffer_list_.empty());
  DCHECK_EQ(write_buffer_list_.size(), write_buffer_len_list_.size());

  if (net_log_.IsCapturing()) {
    if (write_buffer_list_.size() > 1) {
      net_log_.BeginEvent(
          NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED, [&] {
            return NetLogParamsWithInt("num_buffers_coalesced",
                                       write_buffer_list_.size());
          });
    }
    for (size_t i = 0; i < write_buffer_list_.size(); ++i) {
      net_log_.AddByteTransferEvent(
          NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT,
          write_buffer_len_list_[i], write_buffer_list_[i]->data());
    }
    if (write_buffer_list_.size() > 1) {
      net_log_.EndEvent(
          NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED);
    }
  }
  load_timing_info_.send_end = base::TimeTicks::Now();
  write_buffer_list_.clear();
  write_buffer_len_list_.clear();
  delegate_->OnDataSent();
}

void BidirectionalStream::OnTrailersReceived(
    const quiche::HttpHeaderBlock& trailers) {
  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(NetLogEventType::BIDIRECTIONAL_STREAM_RECV_TRAILERS,
                      [&](NetLogCaptureMode capture_mode) {
                        return NetLogHeadersParams(&trailers, capture_mode);
                      });
  }
  read_end_time_ = base::TimeTicks::Now();
  delegate_->OnTrailersReceived(trailers);
}

void BidirectionalStream::OnFailed(int status) {
  if (net_log_.IsCapturing()) {
    net_log_.AddEventWithIntParams(NetLogEventType::BIDIRECTIONAL_STREAM_FAILED,
                                   "net_error", status);
  }
  NotifyFailed(status);
}

void BidirectionalStream::OnStreamReady(const ProxyInfo& used_proxy_info,
                                        std::unique_ptr<HttpStream> stream) {
  NOTREACHED();
}

void BidirectionalStream::OnBidirectionalStreamImplReady(
    const ProxyInfo& used_proxy_info,
    std::unique_ptr<BidirectionalStreamImpl> stream) {
  DCHECK(!stream_impl_);

  NetworkTrafficAnnotationTag traffic_annotation =
      DefineNetworkTrafficAnnotation("bidirectional_stream", R"(
        semantics {
          sender: "Bidirectional Stream"
          description:
            "Bidirectional stream is used to exchange data with a server on "
            "behalf of an RPC API."
          trigger:
            "When an application makes an RPC to the server."
          data:
            "Any arbitrary data."
          destination: OTHER
          destination_other:
            "Any destination that the application chooses."
        }
        policy {
          cookies_allowed: NO
          setting: "This feature is not used in Chrome."
          policy_exception_justification:
            "This feature is not used in Chrome."
        }
    )");

  stream_request_.reset();
  stream_impl_ = std::move(stream);
  stream_impl_->Start(request_info_.get(), net_log_,
                      send_request_headers_automatically_, this,
                      std::move(timer_), traffic_annotation);
}

void BidirectionalStream::OnWebSocketHandshakeStreamReady(
    const ProxyInfo& used_proxy_info,
    std::unique_ptr<WebSocketHandshakeStreamBase> stream) {
  NOTREACHED();
}

void BidirectionalStream::OnStreamFailed(
    int result,
    const NetErrorDetails& net_error_details,
    const ProxyInfo& used_proxy_info,
    ResolveErrorInfo resolve_error_info) {
  DCHECK_LT(result, 0);
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK(stream_request_);

  NotifyFailed(result);
}

void BidirectionalStream::OnCertificateError(int result,
                                             const SSLInfo& ssl_info) {
  DCHECK_LT(result, 0);
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK(stream_request_);

  NotifyFailed(result);
}

void BidirectionalStream::OnNeedsProxyAuth(
    const HttpResponseInfo& proxy_response,
    const ProxyInfo& used_proxy_info,
    HttpAuthController* auth_controller) {
  DCHECK(stream_request_);

  NotifyFailed(ERR_PROXY_AUTH_REQUESTED);
}

void BidirectionalStream::OnNeedsClientAuth(SSLCertRequestInfo* cert_info) {
  DCHECK(stream_request_);

  // BidirectionalStream doesn't support client auth. It ignores client auth
  // requests with null client cert and key.
  session_->ssl_client_context()->SetClientCertificate(cert_info->host_and_port,
                                                       nullptr, nullptr);
  stream_request_ = nullptr;
  StartRequest();
}

void BidirectionalStream::OnQuicBroken() {}

void BidirectionalStream::OnSwitchesToHttpStreamPool(
    HttpStreamPoolRequestInfo request_info) {
  NOTREACHED();
}

void BidirectionalStream::NotifyFailed(int error) {
  delegate_->OnFailed(error);
}

}  // namespace net
```
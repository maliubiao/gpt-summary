Response:
Let's break down the thought process for analyzing the `QuicHttpStream.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific Chromium networking stack file, its relationship to JavaScript, how it handles logic, potential errors, and how a user's actions might lead to its execution.

2. **Initial Skim for Core Functionality:**  Read through the file quickly to get a high-level understanding. Keywords like `HttpStream`, `QuicSession`, `SendRequest`, `ReadResponse`, `Close`, `priority`, and `headers` stand out. This suggests the file manages HTTP streams over the QUIC protocol.

3. **Identify Key Classes and Methods:** Focus on the class definition (`QuicHttpStream`) and its public methods. These are the entry points for interaction and reveal the main responsibilities of the class. List them out:
    * Constructor/Destructor
    * `ConnectionInfoFromQuicVersion`
    * `RegisterRequest`
    * `InitializeStream`
    * `SendRequest`
    * `ReadResponseHeaders`
    * `ReadResponseBody`
    * `Close`
    * `IsResponseBodyComplete`
    * `IsConnectionReused`
    * `GetTotalReceivedBytes`
    * `GetTotalSentBytes`
    * `GetLoadTimingInfo`
    * `GetAlternativeService`
    * `PopulateNetErrorDetails`
    * `SetPriority`
    * `GetDnsAliases`
    * `GetAcceptChViaAlps`
    * `GetQuicErrorDetails`
    * `SetRequestIdempotency`

4. **Analyze Each Method's Purpose:**  Go through each method and try to deduce its function based on its name, parameters, and internal logic. Look for patterns like:
    * **Initialization:** Methods like `InitializeStream` suggest setting up the stream.
    * **Sending Data:** Methods like `SendRequest` and internal methods calling `stream_->Write...` indicate sending data.
    * **Receiving Data:** Methods like `ReadResponseHeaders` and `ReadResponseBody` and internal methods calling `stream_->Read...` indicate receiving data.
    * **State Management:** The presence of a `DoLoop` and `next_state_` suggests a state machine managing the stream lifecycle.
    * **Error Handling:** Look for `ERR_` constants and methods like `MapStreamError` and `GetResponseStatus`.
    * **Data Structures:** Pay attention to the types of data being handled (e.g., `HttpRequestHeaders`, `HttpResponseInfo`, `IOBuffer`).

5. **Trace the Request/Response Flow:**  Imagine a typical HTTP request. How would the methods in this class be involved?
    * `RegisterRequest`: Stores information about the request.
    * `InitializeStream`: Establishes the QUIC stream.
    * `SendRequest`: Sends the request headers and body.
    * `ReadResponseHeaders`: Receives the response headers.
    * `ReadResponseBody`: Receives the response body.
    * `Close`: Tears down the stream.

6. **Identify Interactions with Other Components:**  Note the use of `QuicChromiumClientSession`, `HttpRequestInfo`, `HttpResponseInfo`, and the QUIC core library (`quiche`). This reveals the file's role within a larger system.

7. **Consider the JavaScript Connection:**  Think about how JavaScript in a browser might initiate a network request that eventually uses this code. The Fetch API or `XMLHttpRequest` are the key interfaces. Realize that JavaScript doesn't directly interact with this C++ code. Instead, the browser's network stack (which includes this code) handles the low-level details on behalf of the JavaScript. Focus on *how* the actions initiated by JavaScript *manifest* in this C++ code (e.g., a `fetch()` triggers a request that this code handles).

8. **Look for Logic and Decision Points:**  The `DoLoop` is a prime example of logical flow control. Analyze the different states and how the code transitions between them. Identify conditions that trigger different actions.

9. **Think About Potential Errors:**  Consider common network errors (connection failures, timeouts, protocol errors) and how this code might handle them. Look for error codes being returned and how they are mapped.

10. **Consider User Actions and Debugging:** How would a user's actions lead to this code being executed?  Opening a webpage, clicking a link, submitting a form—these all trigger network requests. How can a developer debug issues related to this code? Network logs are key.

11. **Structure the Explanation:**  Organize the findings into logical sections as requested by the prompt:
    * Functionality: Summarize the core responsibilities.
    * Relationship to JavaScript: Explain the indirect connection.
    * Logical Reasoning: Provide examples of input and output for key methods.
    * Common Errors: List potential user/programming errors.
    * User Actions and Debugging: Describe the user's path and debugging strategies.

12. **Refine and Elaborate:** Go back through each section and add more detail and specific examples. For instance, when explaining the JavaScript connection, mention the Fetch API and how headers are set. When discussing errors, provide concrete examples like "incorrect headers from the server."

13. **Self-Critique and Review:** Read through the explanation to ensure it is clear, accurate, and addresses all aspects of the prompt. Are there any ambiguities?  Are the examples helpful?

This iterative process of skimming, identifying key components, analyzing methods, tracing the flow, considering connections, and structuring the explanation helps to thoroughly understand the functionality and role of a complex source code file like `QuicHttpStream.cc`.
This C++ source code file, `net/quic/quic_http_stream.cc`, is a crucial part of Chromium's network stack, specifically responsible for handling HTTP requests and responses over the QUIC protocol. Let's break down its functionalities:

**Core Functionalities of `QuicHttpStream.cc`:**

1. **Manages HTTP Streams over QUIC:**  The primary purpose is to implement the logic for a single HTTP request/response exchange over a QUIC connection. It acts as the intermediary between the higher-level HTTP logic and the lower-level QUIC session.

2. **Stream Lifecycle Management:** It handles the entire lifecycle of a QUIC stream dedicated to an HTTP transaction, from its creation and initialization to sending the request, receiving the response, and closing the stream.

3. **Request Handling:**
   - **Initialization:**  `InitializeStream` sets up the stream, associating it with a QUIC session and preparing it for sending the request.
   - **Sending Headers:** `SendRequest` serializes HTTP request headers into the QUIC format (likely SPDY or HTTP/3 headers) and sends them over the stream.
   - **Sending Body:**  If the request has a body, it reads the data from the `request_body_stream_` and sends it in QUIC data frames.
   - **Request Priority:** It handles setting the priority of the QUIC stream based on the request's priority.

4. **Response Handling:**
   - **Receiving Headers:** `ReadResponseHeaders` reads and parses the initial response headers sent by the server over the QUIC stream.
   - **Receiving Body:** `ReadResponseBody` reads the response body data arriving in QUIC data frames.
   - **Trailing Headers:** It handles reading trailing headers (if present) after the response body.

5. **Error Handling and Connection Management:**
   - **Error Mapping:** `MapStreamError` translates low-level QUIC errors into higher-level `net::Error` codes that the HTTP layer understands.
   - **Connection Information:** It provides information about the underlying QUIC connection, such as the QUIC version used.
   - **Stream Resetting:**  It handles resetting the QUIC stream in case of errors or cancellations.
   - **Session Association:** It holds a handle to the `QuicChromiumClientSession`, allowing it to interact with the underlying QUIC connection.

6. **Performance and Metrics:**
   - **Load Timing Information:**  It collects timing information about the request/response flow, contributing to performance metrics.
   - **Byte Counting:** It tracks the number of bytes sent and received on the stream.

7. **Net Logging:** It uses Chromium's `NetLog` system to log events related to the HTTP stream, aiding in debugging and analysis.

**Relationship to JavaScript Functionality:**

`QuicHttpStream.cc` doesn't directly interact with JavaScript code. Instead, it operates within the browser's network stack, which is written in C++. However, it plays a crucial role in fulfilling network requests initiated by JavaScript.

Here's how it relates:

1. **Fetch API and `XMLHttpRequest`:** When JavaScript code in a web page uses the Fetch API or `XMLHttpRequest` to make an HTTP request, the browser's networking layer takes over. If the browser decides to use QUIC for that connection, a `QuicHttpStream` object will be created to handle the request.

2. **Indirect Interaction:**  JavaScript specifies the URL, headers, and body of the request. This information is passed down through the network stack and eventually used by `QuicHttpStream` to construct and send the QUIC messages.

3. **Response Delivery:**  When the server sends back the response, `QuicHttpStream` parses the headers and body and passes the data back up the network stack. Eventually, this response data reaches the JavaScript code that initiated the request (e.g., through the `then()` callback of a Fetch promise or the `onload` event of an `XMLHttpRequest`).

**Example:**

Imagine this JavaScript code:

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

Here's a simplified sequence of how `QuicHttpStream.cc` might be involved:

1. The JavaScript `fetch()` call initiates a network request.
2. Chromium's network stack checks if a QUIC connection to `example.com` exists or needs to be established.
3. A `QuicHttpStream` object is created and associated with an existing or newly created QUIC stream.
4. `RegisterRequest` is called to store information about the request (URL, method, etc.).
5. `InitializeStream` sets up the stream.
6. `SendRequest` is called, which in turn calls internal methods to format the HTTP request headers into QUIC frames and send them.
7. The server sends back the response over the QUIC stream.
8. `ReadResponseHeaders` is called to parse the HTTP response headers.
9. `ReadResponseBody` is called to read the response body data.
10. The parsed response data is passed back up the network stack.
11. Finally, the JavaScript `then(response => ...)` callback receives the `response` object containing the data fetched by `QuicHttpStream`.

**Logical Reasoning with Hypothetical Input and Output:**

Let's consider the `SendRequest` method:

**Hypothetical Input:**

* `request_headers`: An `HttpRequestHeaders` object containing:
  ```
  GET /index.html HTTP/1.1
  Host: example.com
  User-Agent: Chrome
  ```
* `response`: An empty `HttpResponseInfo` object.
* `callback`: A function to be called when the send operation is complete.

**Internal Processing in `SendRequest` (simplified):**

1. The method checks if the QUIC stream is valid and the session is connected.
2. It uses `CreateSpdyHeadersFromHttpRequest` to convert the `HttpRequestHeaders` into a `quiche::HttpHeaderBlock` (the QUIC representation of headers).
3. It stores the request body stream if present.
4. It updates the `response_info_` with the peer's address.
5. It transitions to the `STATE_SET_REQUEST_PRIORITY` state in the state machine.
6. It calls `DoLoop(OK)` to begin the asynchronous operation of sending headers.

**Hypothetical Output (asynchronous):**

* Eventually, the `callback` function will be called with a result indicating success (`OK`) or failure (e.g., `ERR_CONNECTION_CLOSED`).
* The `response` object will start to be populated (asynchronously) with information like the remote endpoint.

**Common User or Programming Errors and Examples:**

1. **Incorrect Server Configuration:**
   - **Error:** If the server doesn't support QUIC or has a misconfigured QUIC setup, the connection might fail, leading to errors within `QuicHttpStream`.
   - **User Action:** User tries to access a website that isn't properly configured for QUIC.
   - **Debugging:** Network logs would show connection errors or handshake failures.

2. **Firewall Blocking QUIC:**
   - **Error:** Firewalls might block UDP traffic on the ports used by QUIC (typically 443 or a higher port), preventing the connection.
   - **User Action:** User is behind a restrictive firewall.
   - **Debugging:** Network logs would indicate connection timeouts or refusals.

3. **Proxy Issues:**
   - **Error:** Some proxies might not correctly handle QUIC traffic.
   - **User Action:** User is connecting through a proxy that doesn't support QUIC.
   - **Debugging:** Network logs might show errors related to proxy negotiation or connection failures.

4. **Browser Bugs:**
   - **Error:**  While less common, bugs in the `QuicHttpStream` implementation itself could lead to unexpected behavior.
   - **Programming Error:** Incorrectly handling state transitions, failing to parse headers correctly, or issues in managing the underlying QUIC stream.
   - **Debugging:** Requires inspecting the source code, using debuggers, and analyzing detailed network logs.

**User Operations Leading to This Code (Debugging Clues):**

To reach this code during debugging, a user would typically perform actions that initiate network requests using a browser that supports QUIC:

1. **Typing a URL in the Address Bar and Hitting Enter:** If the website supports QUIC and the browser is configured to use it, `QuicHttpStream` will likely be involved.

2. **Clicking on a Link:** Similar to typing a URL, clicking a link can trigger a QUIC-based request.

3. **Web Page Making API Calls (Fetch, XMLHttpRequest):** JavaScript code within a loaded web page can make network requests that utilize QUIC.

4. **Opening a Web Application:** Modern web applications often make numerous background requests, many of which might use QUIC.

**Debugging Steps to Reach `QuicHttpStream.cc`:**

1. **Enable Network Logging:**  Chromium has detailed network logging capabilities. Running Chrome with the `--log-net-log=filename.json` flag will capture all network events.

2. **Inspect the Network Log:** Open the `filename.json` file in the `chrome://net-export/` tool. Filter for events related to the specific request you're investigating.

3. **Look for QUIC-Specific Events:**  Search for events containing "QUIC" or related to the domain you're accessing. You'll see events indicating the creation of a QUIC session and streams.

4. **Trace Stream Creation:** When a new HTTP request is initiated over QUIC, you'll likely see an event indicating the creation of a `QuicHttpStream`. The event might contain the stream ID and other relevant information.

5. **Set Breakpoints:** If you have the Chromium source code, you can set breakpoints in `QuicHttpStream.cc` (e.g., in `InitializeStream`, `SendRequest`, `ReadResponseHeaders`) and then reproduce the user action that triggers the request. When the breakpoint is hit, you can inspect the state of the `QuicHttpStream` object and the associated QUIC session.

6. **Analyze State Transitions:** The `DoLoop` method and the `next_state_` variable are crucial for understanding the flow of execution. Watch how the state changes during the request/response lifecycle.

By combining user actions with detailed network logging and debugging tools, developers can trace the path of a network request and pinpoint where `QuicHttpStream.cc` is involved and identify potential issues.

### 提示词
```
这是目录为net/quic/quic_http_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/quic/quic_http_stream.h"

#include <set>
#include <string_view>
#include <utility>

#include "base/auto_reset.h"
#include "base/functional/bind.h"
#include "base/metrics/histogram_functions.h"
#include "base/strings/string_split.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/features.h"
#include "net/base/ip_endpoint.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_status_code.h"
#include "net/http/http_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/quic/quic_http_utils.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/ssl/ssl_info.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_frame_builder.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_framer.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_stream_sequencer.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "url/origin.h"
#include "url/scheme_host_port.h"

namespace net {

QuicHttpStream::QuicHttpStream(
    std::unique_ptr<QuicChromiumClientSession::Handle> session,
    std::set<std::string> dns_aliases)
    : MultiplexedHttpStream(std::move(session)),
      dns_aliases_(std::move(dns_aliases)) {}

QuicHttpStream::~QuicHttpStream() {
  CHECK(!in_loop_);
  Close(false);
}

HttpConnectionInfo QuicHttpStream::ConnectionInfoFromQuicVersion(
    quic::ParsedQuicVersion quic_version) {
  switch (quic_version.transport_version) {
    case quic::QUIC_VERSION_UNSUPPORTED:
      return HttpConnectionInfo::kQUIC_UNKNOWN_VERSION;
    case quic::QUIC_VERSION_46:
      return HttpConnectionInfo::kQUIC_46;
    case quic::QUIC_VERSION_IETF_DRAFT_29:
      DCHECK(quic_version.UsesTls());
      return HttpConnectionInfo::kQUIC_DRAFT_29;
    case quic::QUIC_VERSION_IETF_RFC_V1:
      DCHECK(quic_version.UsesTls());
      return HttpConnectionInfo::kQUIC_RFC_V1;
    case quic::QUIC_VERSION_RESERVED_FOR_NEGOTIATION:
      return HttpConnectionInfo::kQUIC_999;
    case quic::QUIC_VERSION_IETF_RFC_V2:
      DCHECK(quic_version.UsesTls());
      return HttpConnectionInfo::kQUIC_2_DRAFT_8;
  }
  NOTREACHED();
}

void QuicHttpStream::RegisterRequest(const HttpRequestInfo* request_info) {
  DCHECK(request_info);
  DCHECK(request_info->traffic_annotation.is_valid());
  request_info_ = request_info;
}

int QuicHttpStream::InitializeStream(bool can_send_early,
                                     RequestPriority priority,
                                     const NetLogWithSource& stream_net_log,
                                     CompletionOnceCallback callback) {
  CHECK(callback_.is_null());
  DCHECK(request_info_);
  DCHECK(!stream_);

  // HttpNetworkTransaction will retry any request that fails with
  // ERR_QUIC_HANDSHAKE_FAILED. It will retry any request with
  // ERR_CONNECTION_CLOSED so long as the connection has been used for other
  // streams first and headers have not yet been received.
  if (!quic_session()->IsConnected()) {
    return GetResponseStatus();
  }

  stream_net_log.AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION,
      quic_session()->net_log().source());
  stream_net_log.AddEventWithIntParams(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_MODE,
      "connection_migration_mode",
      static_cast<int>(quic_session()->connection_migration_mode()));

  stream_net_log_ = stream_net_log;
  can_send_early_ = can_send_early;
  request_time_ = base::Time::Now();
  priority_ = priority;

  SaveSSLInfo();

  next_state_ = STATE_REQUEST_STREAM;
  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING) {
    callback_ = std::move(callback);
  }

  return MapStreamError(rv);
}

int QuicHttpStream::SendRequest(const HttpRequestHeaders& request_headers,
                                HttpResponseInfo* response,
                                CompletionOnceCallback callback) {
  CHECK(!request_body_stream_);
  CHECK(!response_info_);
  CHECK(callback_.is_null());
  CHECK(!callback.is_null());
  CHECK(response);

  if (!stream_ || !quic_session()->IsConnected()) {
    return GetResponseStatus();
  }

  // Store the serialized request headers.
  CreateSpdyHeadersFromHttpRequest(*request_info_, priority_, request_headers,
                                   &request_headers_);

  // Store the request body.
  request_body_stream_ = request_info_->upload_data_stream;
  if (request_body_stream_) {
    // TODO(rch): Can we be more precise about when to allocate
    // raw_request_body_buf_. Removed the following check. DoReadRequestBody()
    // was being called even if we didn't yet allocate raw_request_body_buf_.
    //   && (request_body_stream_->size() ||
    //       request_body_stream_->is_chunked()))
    // Set the body buffer size to be the size of the body clamped
    // into the range [10 * quic::kMaxOutgoingPacketSize, 256 *
    // quic::kMaxOutgoingPacketSize]. With larger bodies, larger buffers reduce
    // CPU usage.
    raw_request_body_buf_ =
        base::MakeRefCounted<IOBufferWithSize>(static_cast<size_t>(
            std::max(10 * quic::kMaxOutgoingPacketSize,
                     std::min(request_body_stream_->size(),
                              256 * quic::kMaxOutgoingPacketSize))));
    // The request body buffer is empty at first.
    request_body_buf_ =
        base::MakeRefCounted<DrainableIOBuffer>(raw_request_body_buf_, 0);
  }

  // Store the response info.
  response_info_ = response;

  // Put the peer's IP address and port into the response.
  IPEndPoint address;
  int rv = quic_session()->GetPeerAddress(&address);
  if (rv != OK) {
    return rv;
  }
  response_info_->remote_endpoint = address;

  next_state_ = STATE_SET_REQUEST_PRIORITY;
  rv = DoLoop(OK);

  if (rv == ERR_IO_PENDING) {
    callback_ = std::move(callback);
  }

  return rv > 0 ? OK : MapStreamError(rv);
}

int QuicHttpStream::ReadResponseHeaders(CompletionOnceCallback callback) {
  CHECK(callback_.is_null());
  CHECK(!callback.is_null());

  int rv = stream_->ReadInitialHeaders(
      &response_header_block_,
      base::BindOnce(&QuicHttpStream::OnReadResponseHeadersComplete,
                     weak_factory_.GetWeakPtr()));

  if (rv == ERR_IO_PENDING) {
    // Still waiting for the response, return IO_PENDING.
    CHECK(callback_.is_null());
    callback_ = std::move(callback);
    return ERR_IO_PENDING;
  }

  if (rv < 0) {
    return MapStreamError(rv);
  }

  // Check if we already have the response headers. If so, return synchronously.
  if (response_headers_received_) {
    return OK;
  }

  headers_bytes_received_ += rv;
  return ProcessResponseHeaders(response_header_block_);
}

int QuicHttpStream::ReadResponseBody(IOBuffer* buf,
                                     int buf_len,
                                     CompletionOnceCallback callback) {
  CHECK(callback_.is_null());
  CHECK(!callback.is_null());
  CHECK(!user_buffer_.get());
  CHECK_EQ(0, user_buffer_len_);

  // Invalidate HttpRequestInfo pointer. This is to allow the stream to be
  // shared across multiple transactions which might require this
  // stream to outlive the request_info_'s owner.
  // Only allowed when Read state machine starts. It is safe to reset it at
  // this point since request_info_->upload_data_stream is also not needed
  // anymore.
  request_info_ = nullptr;

  // If the stream is already closed, there is no body to read.
  if (stream_->IsDoneReading()) {
    return HandleReadComplete(OK);
  }

  int rv = stream_->ReadBody(buf, buf_len,
                             base::BindOnce(&QuicHttpStream::OnReadBodyComplete,
                                            weak_factory_.GetWeakPtr()));
  if (rv == ERR_IO_PENDING) {
    callback_ = std::move(callback);
    user_buffer_ = buf;
    user_buffer_len_ = buf_len;
    return ERR_IO_PENDING;
  }

  if (rv < 0) {
    return MapStreamError(rv);
  }

  return HandleReadComplete(rv);
}

void QuicHttpStream::Close(bool /*not_reusable*/) {
  session_error_ = ERR_ABORTED;
  SaveResponseStatus();
  // Note: the not_reusable flag has no meaning for QUIC streams.
  if (stream_) {
    stream_->Reset(quic::QUIC_STREAM_CANCELLED);
  }
  ResetStream();
}

bool QuicHttpStream::IsResponseBodyComplete() const {
  return next_state_ == STATE_OPEN && stream_->IsDoneReading();
}

bool QuicHttpStream::IsConnectionReused() const {
  // TODO(rch): do something smarter here.
  return stream_ && stream_->id() > 1;
}

int64_t QuicHttpStream::GetTotalReceivedBytes() const {
  if (stream_) {
    DCHECK_LE(stream_->NumBytesConsumed(), stream_->stream_bytes_read());
    // Only count the uniquely received bytes.
    return stream_->NumBytesConsumed();
  }
  return closed_stream_received_bytes_;
}

int64_t QuicHttpStream::GetTotalSentBytes() const {
  if (stream_) {
    return stream_->stream_bytes_written();
  }
  return closed_stream_sent_bytes_;
}

bool QuicHttpStream::GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
  bool is_first_stream = closed_is_first_stream_;
  if (stream_) {
    load_timing_info->socket_log_id = stream_->net_log().source().id;
    is_first_stream = stream_->IsFirstStream();
    load_timing_info->first_early_hints_time =
        stream_->first_early_hints_time();
    load_timing_info->receive_non_informational_headers_start =
        stream_->headers_received_start_time();
    load_timing_info->receive_headers_start =
        load_timing_info->first_early_hints_time.is_null()
            ? load_timing_info->receive_non_informational_headers_start
            : load_timing_info->first_early_hints_time;
  }

  if (is_first_stream) {
    load_timing_info->socket_reused = false;
    load_timing_info->connect_timing = connect_timing_;
  } else {
    load_timing_info->socket_reused = true;
  }
  return true;
}

bool QuicHttpStream::GetAlternativeService(
    AlternativeService* alternative_service) const {
  alternative_service->protocol = kProtoQUIC;
  const url::SchemeHostPort& destination = quic_session()->destination();
  alternative_service->host = destination.host();
  alternative_service->port = destination.port();
  return true;
}

void QuicHttpStream::PopulateNetErrorDetails(NetErrorDetails* details) {
  details->connection_info =
      ConnectionInfoFromQuicVersion(quic_session()->GetQuicVersion());
  quic_session()->PopulateNetErrorDetails(details);
  if (quic_session()->OneRttKeysAvailable() && stream_ &&
      stream_->connection_error() != quic::QUIC_NO_ERROR) {
    details->quic_connection_error = stream_->connection_error();
  }
}

void QuicHttpStream::SetPriority(RequestPriority priority) {
  priority_ = priority;
}

void QuicHttpStream::OnReadResponseHeadersComplete(int rv) {
  DCHECK(callback_);
  DCHECK(!response_headers_received_);
  if (rv > 0) {
    headers_bytes_received_ += rv;
    rv = ProcessResponseHeaders(response_header_block_);
  }
  if (rv != ERR_IO_PENDING && !callback_.is_null()) {
    DoCallback(rv);
  }
}

const std::set<std::string>& QuicHttpStream::GetDnsAliases() const {
  return dns_aliases_;
}

std::string_view QuicHttpStream::GetAcceptChViaAlps() const {
  if (!request_info_) {
    return {};
  }

  return session()->GetAcceptChViaAlps(url::SchemeHostPort(request_info_->url));
}

std::optional<HttpStream::QuicErrorDetails>
QuicHttpStream::GetQuicErrorDetails() const {
  QuicErrorDetails details;
  if (stream_) {
    details.connection_error = stream_->connection_error();
    details.stream_error = stream_->stream_error();
    details.connection_wire_error = stream_->connection_wire_error();
    details.ietf_application_error = stream_->ietf_application_error();
  } else {
    details.connection_error = connection_error_;
    details.stream_error = stream_error_;
    details.connection_wire_error = connection_wire_error_;
    details.ietf_application_error = ietf_application_error_;
  }
  return details;
}

void QuicHttpStream::ReadTrailingHeaders() {
  int rv = stream_->ReadTrailingHeaders(
      &trailing_header_block_,
      base::BindOnce(&QuicHttpStream::OnReadTrailingHeadersComplete,
                     weak_factory_.GetWeakPtr()));

  if (rv != ERR_IO_PENDING) {
    OnReadTrailingHeadersComplete(rv);
  }
}

void QuicHttpStream::OnReadTrailingHeadersComplete(int rv) {
  DCHECK(response_headers_received_);
  if (rv > 0) {
    headers_bytes_received_ += rv;
  }

  // QuicHttpStream ignores trailers.
  if (stream_->IsDoneReading()) {
    // Close the read side. If the write side has been closed, this will
    // invoke QuicHttpStream::OnClose to reset the stream.
    stream_->OnFinRead();
    SetResponseStatus(OK);
  }
}

void QuicHttpStream::OnIOComplete(int rv) {
  rv = DoLoop(rv);

  if (rv != ERR_IO_PENDING && !callback_.is_null()) {
    DoCallback(rv);
  }
}

void QuicHttpStream::DoCallback(int rv) {
  CHECK_NE(rv, ERR_IO_PENDING);
  CHECK(!callback_.is_null());
  CHECK(!in_loop_);

  // The client callback can do anything, including destroying this class,
  // so any pending callback must be issued after everything else is done.
  std::move(callback_).Run(MapStreamError(rv));
}

int QuicHttpStream::DoLoop(int rv) {
  CHECK(!in_loop_);
  base::AutoReset<bool> auto_reset_in_loop(&in_loop_, true);
  std::unique_ptr<quic::QuicConnection::ScopedPacketFlusher> packet_flusher =
      quic_session()->CreatePacketBundler();
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_REQUEST_STREAM:
        CHECK_EQ(OK, rv);
        rv = DoRequestStream();
        break;
      case STATE_REQUEST_STREAM_COMPLETE:
        rv = DoRequestStreamComplete(rv);
        break;
      case STATE_SET_REQUEST_PRIORITY:
        CHECK_EQ(OK, rv);
        rv = DoSetRequestPriority();
        break;
      case STATE_SEND_HEADERS:
        CHECK_EQ(OK, rv);
        rv = DoSendHeaders();
        break;
      case STATE_SEND_HEADERS_COMPLETE:
        rv = DoSendHeadersComplete(rv);
        break;
      case STATE_READ_REQUEST_BODY:
        CHECK_EQ(OK, rv);
        rv = DoReadRequestBody();
        break;
      case STATE_READ_REQUEST_BODY_COMPLETE:
        rv = DoReadRequestBodyComplete(rv);
        break;
      case STATE_SEND_BODY:
        CHECK_EQ(OK, rv);
        rv = DoSendBody();
        break;
      case STATE_SEND_BODY_COMPLETE:
        rv = DoSendBodyComplete(rv);
        break;
      case STATE_OPEN:
        CHECK_EQ(OK, rv);
        break;
      default:
        NOTREACHED() << "next_state_: " << next_state_;
    }
  } while (next_state_ != STATE_NONE && next_state_ != STATE_OPEN &&
           rv != ERR_IO_PENDING);

  return rv;
}

int QuicHttpStream::DoRequestStream() {
  next_state_ = STATE_REQUEST_STREAM_COMPLETE;

  return quic_session()->RequestStream(
      !can_send_early_,
      base::BindOnce(&QuicHttpStream::OnIOComplete, weak_factory_.GetWeakPtr()),
      NetworkTrafficAnnotationTag(request_info_->traffic_annotation));
}

int QuicHttpStream::DoRequestStreamComplete(int rv) {
  DCHECK(rv == OK || !stream_);
  if (rv != OK) {
    session_error_ = rv;
    return GetResponseStatus();
  }

  stream_ = quic_session()->ReleaseStream();
  DCHECK(stream_);
  if (!stream_->IsOpen()) {
    session_error_ = ERR_CONNECTION_CLOSED;
    return GetResponseStatus();
  }

  if (request_info_->load_flags &
      LOAD_DISABLE_CONNECTION_MIGRATION_TO_CELLULAR) {
    stream_->DisableConnectionMigrationToCellularNetwork();
  }

  DCHECK(response_info_ == nullptr);

  return OK;
}

int QuicHttpStream::DoSetRequestPriority() {
  // Set priority according to request
  DCHECK(stream_);
  DCHECK(response_info_);
  DCHECK(request_info_);

  uint8_t urgency = ConvertRequestPriorityToQuicPriority(priority_);
  bool incremental = request_info_->priority_incremental;
  stream_->SetPriority(
      quic::QuicStreamPriority(quic::HttpStreamPriority{urgency, incremental}));
  next_state_ = STATE_SEND_HEADERS;
  return OK;
}

int QuicHttpStream::DoSendHeaders() {
  uint8_t urgency = ConvertRequestPriorityToQuicPriority(priority_);
  bool incremental = request_info_->priority_incremental;
  quic::QuicStreamPriority priority(
      quic::HttpStreamPriority{urgency, incremental});
  // Log the actual request with the URL Request's net log.
  stream_net_log_.AddEvent(
      NetLogEventType::HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS,
      [&](NetLogCaptureMode capture_mode) {
        return QuicRequestNetLogParams(stream_->id(), &request_headers_,
                                       priority, capture_mode);
      });
  DispatchRequestHeadersCallback(request_headers_);
  bool has_upload_data = request_body_stream_ != nullptr;

  next_state_ = STATE_SEND_HEADERS_COMPLETE;
  int rv = stream_->WriteHeaders(std::move(request_headers_), !has_upload_data,
                                 nullptr);
  if (rv > 0) {
    headers_bytes_sent_ += rv;
  }

  request_headers_ = quiche::HttpHeaderBlock();
  return rv;
}

int QuicHttpStream::DoSendHeadersComplete(int rv) {
  if (rv < 0) {
    return rv;
  }

  next_state_ = request_body_stream_ ? STATE_READ_REQUEST_BODY : STATE_OPEN;

  return OK;
}

int QuicHttpStream::DoReadRequestBody() {
  next_state_ = STATE_READ_REQUEST_BODY_COMPLETE;
  return request_body_stream_->Read(
      raw_request_body_buf_.get(), raw_request_body_buf_->size(),
      base::BindOnce(&QuicHttpStream::OnIOComplete,
                     weak_factory_.GetWeakPtr()));
}

int QuicHttpStream::DoReadRequestBodyComplete(int rv) {
  // |rv| is the result of read from the request body from the last call to
  // DoSendBody().
  if (rv < 0) {
    stream_->Reset(quic::QUIC_ERROR_PROCESSING_STREAM);
    ResetStream();
    return rv;
  }

  request_body_buf_ =
      base::MakeRefCounted<DrainableIOBuffer>(raw_request_body_buf_, rv);
  if (rv == 0) {  // Reached the end.
    DCHECK(request_body_stream_->IsEOF());
  }

  next_state_ = STATE_SEND_BODY;
  return OK;
}

int QuicHttpStream::DoSendBody() {
  CHECK(request_body_stream_);
  CHECK(request_body_buf_.get());
  const bool eof = request_body_stream_->IsEOF();
  int len = request_body_buf_->BytesRemaining();
  if (len > 0 || eof) {
    next_state_ = STATE_SEND_BODY_COMPLETE;
    std::string_view data(request_body_buf_->data(), len);
    return stream_->WriteStreamData(
        data, eof,
        base::BindOnce(&QuicHttpStream::OnIOComplete,
                       weak_factory_.GetWeakPtr()));
  }

  next_state_ = STATE_OPEN;
  return OK;
}

int QuicHttpStream::DoSendBodyComplete(int rv) {
  if (rv < 0) {
    return rv;
  }

  request_body_buf_->DidConsume(request_body_buf_->BytesRemaining());

  if (!request_body_stream_->IsEOF()) {
    next_state_ = STATE_READ_REQUEST_BODY;
    return OK;
  }

  next_state_ = STATE_OPEN;
  return OK;
}

int QuicHttpStream::ProcessResponseHeaders(
    const quiche::HttpHeaderBlock& headers) {
  const int rv = SpdyHeadersToHttpResponse(headers, response_info_);
  base::UmaHistogramBoolean("Net.QuicHttpStream.ProcessResponseHeaderSuccess",
                            rv == OK);
  if (rv != OK) {
    DLOG(WARNING) << "Invalid headers";
    return ERR_QUIC_PROTOCOL_ERROR;
  }

  if (response_info_->headers->response_code() == HTTP_EARLY_HINTS) {
    DCHECK(!response_headers_received_);
    headers_bytes_received_ = 0;
    return OK;
  }

  response_info_->connection_info =
      ConnectionInfoFromQuicVersion(quic_session()->GetQuicVersion());
  response_info_->was_alpn_negotiated = true;
  response_info_->alpn_negotiated_protocol =
      HttpConnectionInfoToString(response_info_->connection_info);
  response_info_->response_time = response_info_->original_response_time =
      base::Time::Now();
  response_info_->request_time = request_time_;
  response_headers_received_ = true;

  // Populate |connect_timing_| when response headers are received. This should
  // take care of 0-RTT where request is sent before handshake is confirmed.
  connect_timing_ = quic_session()->GetConnectTiming();

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&QuicHttpStream::ReadTrailingHeaders,
                                weak_factory_.GetWeakPtr()));

  if (stream_->IsDoneReading()) {
    session_error_ = OK;
    SaveResponseStatus();
    stream_->OnFinRead();
  }

  return OK;
}

void QuicHttpStream::OnReadBodyComplete(int rv) {
  CHECK(callback_);
  user_buffer_ = nullptr;
  user_buffer_len_ = 0;
  rv = HandleReadComplete(rv);
  DoCallback(rv);
}

int QuicHttpStream::HandleReadComplete(int rv) {
  if (stream_->IsDoneReading()) {
    stream_->OnFinRead();
    SetResponseStatus(OK);
    ResetStream();
  }
  return rv;
}

void QuicHttpStream::ResetStream() {
  // If |request_body_stream_| is non-NULL, Reset it, to abort any in progress
  // read.
  if (request_body_stream_) {
    request_body_stream_->Reset();
  }

  if (!stream_) {
    return;
  }

  DCHECK_LE(stream_->NumBytesConsumed(), stream_->stream_bytes_read());
  // Only count the uniquely received bytes.
  closed_stream_received_bytes_ = stream_->NumBytesConsumed();
  closed_stream_sent_bytes_ = stream_->stream_bytes_written();
  closed_is_first_stream_ = stream_->IsFirstStream();
  connection_error_ = stream_->connection_error();
  stream_error_ = stream_->stream_error();
  connection_wire_error_ = stream_->connection_wire_error();
  ietf_application_error_ = stream_->ietf_application_error();
}

int QuicHttpStream::MapStreamError(int rv) {
  if (rv == ERR_QUIC_PROTOCOL_ERROR && !quic_session()->OneRttKeysAvailable()) {
    return ERR_QUIC_HANDSHAKE_FAILED;
  }
  return rv;
}

int QuicHttpStream::GetResponseStatus() {
  SaveResponseStatus();
  return response_status_;
}

void QuicHttpStream::SaveResponseStatus() {
  if (!has_response_status_) {
    SetResponseStatus(ComputeResponseStatus());
  }
}

void QuicHttpStream::SetResponseStatus(int response_status) {
  has_response_status_ = true;
  response_status_ = response_status;
}

int QuicHttpStream::ComputeResponseStatus() const {
  DCHECK(!has_response_status_);

  // If the handshake has failed this will be handled by the QuicSessionPool
  // and HttpStreamFactory to mark QUIC as broken if TCP is actually working.
  if (!quic_session()->OneRttKeysAvailable()) {
    return ERR_QUIC_HANDSHAKE_FAILED;
  }

  // If the session was aborted by a higher layer, simply use that error code.
  if (session_error_ != ERR_UNEXPECTED) {
    return session_error_;
  }

  // If |response_info_| is null then the request has not been sent, so
  // return ERR_CONNECTION_CLOSED to permit HttpNetworkTransaction to
  // retry the request.
  if (!response_info_) {
    return ERR_CONNECTION_CLOSED;
  }

  base::UmaHistogramEnumeration("Net.QuicHttpStream.ResponseStatus",
                                stream_->stream_error(),
                                quic::QUIC_STREAM_LAST_ERROR);

  return ERR_QUIC_PROTOCOL_ERROR;
}

void QuicHttpStream::SetRequestIdempotency(Idempotency idempotency) {
  if (stream_ == nullptr) {
    return;
  }
  stream_->SetRequestIdempotency(idempotency);
}

}  // namespace net
```
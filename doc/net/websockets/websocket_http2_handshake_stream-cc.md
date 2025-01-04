Response:
Let's break down the thought process for analyzing this Chromium source code file.

1. **Identify the Core Purpose:** The filename `websocket_http2_handshake_stream.cc` immediately suggests this code deals with the WebSocket handshake process *over HTTP/2*. The `HandshakeStream` part tells us it's responsible for the initial negotiation phase of the WebSocket connection. The `http2` specifies the underlying transport protocol.

2. **Examine Includes:** The included headers provide valuable clues:
    * `net/websockets/*`:  Confirms it's part of the WebSocket implementation.
    * `net/http/*`:  Indicates interaction with HTTP concepts (headers, requests, responses).
    * `net/spdy/*`:  Strongly suggests interaction with the SPDY protocol, which is the precursor to HTTP/2 and shares many concepts. This reinforces the HTTP/2 aspect.
    * `base/*`:  General Chromium base utilities (strings, callbacks, memory management).
    *  `net/traffic_annotation/*`:  Relates to network traffic analysis and policy.

3. **Analyze the Class Declaration:** The class `WebSocketHttp2HandshakeStream` is the central piece. Its inheritance (or lack thereof in this snippet) isn't shown, but the methods declared within it are key.

4. **Method-by-Method Analysis (High-Level):**  Go through each public method and understand its general role:
    * **Constructor/Destructor:**  Initialization and cleanup of resources.
    * **`RegisterRequest`:** Associates HTTP request information.
    * **`InitializeStream`:**  Initial setup (potentially related to prioritization).
    * **`SendRequest`:**  Sends the initial WebSocket handshake request over HTTP/2. *Crucially, look for how HTTP/2 specifics are handled here.*  The presence of `CreateSpdyHeadersFromHttpRequestForWebSocket` is a strong indicator.
    * **`ReadResponseHeaders`:**  Handles reading the HTTP response headers during the handshake.
    * **`ReadResponseBody`:**  **NOTREACHED()** is a major clue. This confirms that the HTTP/2 handshake stream is *only* concerned with the initial negotiation, not the subsequent WebSocket data frames.
    * **`Close`:**  Cleanly shuts down the handshake stream.
    * **`IsResponseBodyComplete`, `IsConnectionReused`, `CanReuseConnection`, `GetTotalReceivedBytes`, `GetTotalSentBytes`, `GetAlternativeService`, `GetLoadTimingInfo`, `GetSSLInfo`, `GetRemoteEndpoint`, `PopulateNetErrorDetails`, `Drain`, `SetPriority`, `RenewStreamForAuth`, `GetDnsAliases`, `GetAcceptChViaAlps`:** These are standard `HttpStream` interface methods, providing information about the underlying connection or lifecycle management.
    * **`Upgrade`:**  The critical method that transforms the handshake stream into a usable `WebSocketStream`. This involves creating `WebSocketBasicStream` and potentially `WebSocketDeflateStream`.
    * **`CanReadFromStream`:** Checks if the underlying stream is ready.
    * **`GetWeakPtr`:**  Standard Chromium pattern for managing object lifetimes.
    * **`OnHeadersSent`, `OnHeadersReceived`, `OnClose`:** These are callbacks from the underlying `SpdyStream` (HTTP/2 stream).

5. **Identify Key Interactions and Data Flow:**
    * The class takes a `SpdySession` as input, showing its direct dependency on HTTP/2.
    * It interacts with a `WebSocketStream::ConnectDelegate` to inform about the handshake process.
    * It uses `SpdyStreamRequest` to initiate the HTTP/2 stream.
    * It manages HTTP request and response headers (`HttpRequestHeaders`, `HttpResponseInfo`).
    * The `Upgrade()` method is the transition point to the actual WebSocket communication.

6. **Look for JavaScript Relevance:**  Think about how WebSockets are used in JavaScript: the `WebSocket` API. The handshake process initiated by JavaScript's `new WebSocket()` ultimately leads to this kind of code being executed in the browser's network stack. The exchange of headers, subprotocols, and extensions are all part of the negotiation initiated from JavaScript.

7. **Analyze Specific Logic and Edge Cases:**
    * **Header Validation:** The checks for required headers in `SendRequest`.
    * **Status Code Handling:** The `ValidateResponse` method and its handling of different HTTP status codes (success, authentication, errors).
    * **Extension and Subprotocol Negotiation:** The `ValidateSubProtocol` and `ValidateExtensions` functions (though their implementation isn't in this file) are crucial.
    * **Error Handling:**  The `OnFailure` method and how errors are propagated.

8. **Consider User Errors and Debugging:**
    * **Incorrect URLs/Ports:** Leading to connection failures.
    * **Server Misconfiguration:**  Incorrectly responding to the handshake.
    * **Firewall Issues:** Blocking the connection.
    * **Browser Developer Tools:** The "Network" tab is the primary tool for observing the handshake process.

9. **Structure the Explanation:**  Organize the findings into logical categories: functionality, JavaScript relationship, logical reasoning (input/output), user errors, and debugging. Use clear and concise language.

10. **Refine and Review:** Read through the explanation to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For example, explicitly mentioning the HTTP/1.1 200 status check in `ValidateStatus`.

Self-Correction Example during the process:  Initially, I might have overlooked the significance of the `NOTREACHED()` in `ReadResponseBody`. Realizing that WebSocket data transfer happens on a different stream and this class is solely for the *handshake* is a crucial insight that requires careful examination of the code. Similarly, paying attention to how HTTP/2 headers are constructed (`CreateSpdyHeadersFromHttpRequestForWebSocket`) is essential for understanding the HTTP/2 specific aspects.
This source code file, `websocket_http2_handshake_stream.cc`, within the Chromium network stack, implements the **client-side WebSocket handshake process over an HTTP/2 connection**. Essentially, it handles the initial negotiation required to establish a WebSocket connection when the underlying transport protocol is HTTP/2.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Initiating the Handshake Request:**
   - It takes a `SpdySession` (representing the HTTP/2 session) and builds the necessary HTTP/2 headers for the WebSocket handshake request.
   - It utilizes the `CONNECT` method in HTTP/2, which is specifically designed for establishing tunnel-like connections like WebSockets.
   - It includes the necessary WebSocket-specific headers like `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, and potentially `Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions`.

2. **Managing the HTTP/2 Stream:**
   - It creates and manages a `SpdyStream` within the existing `SpdySession` for the handshake.
   - It sends the handshake request headers over this stream.

3. **Processing the Handshake Response:**
   - It receives and parses the HTTP/2 response headers from the server.
   - It validates the response headers to ensure the server accepted the WebSocket upgrade request. This includes checking:
     - The HTTP status code is `200 OK`.
     - The presence of required headers like `Upgrade: websocket` and `Connection: Upgrade`.
     - The `Sec-WebSocket-Accept` header, verifying the server's acceptance of the handshake.
     - The negotiated subprotocol (if any) in the `Sec-WebSocket-Protocol` header.
     - The negotiated extensions (if any) in the `Sec-WebSocket-Extensions` header.

4. **Upgrading to a WebSocket Stream:**
   - If the handshake is successful, it transitions from the `WebSocketHttp2HandshakeStream` to a `WebSocketStream` (specifically `WebSocketBasicStream` and potentially `WebSocketDeflateStream` if extensions are negotiated).
   - It transfers the ownership of the underlying `SpdyStream` to the new `WebSocketStream` for subsequent WebSocket frame communication.

5. **Handling Errors:**
   - If the handshake fails at any point (e.g., invalid response status code, missing headers, incorrect `Sec-WebSocket-Accept`), it reports the error to the `WebSocketStreamRequestAPI` and cleans up resources.

**Relationship with JavaScript Functionality:**

This code is directly related to the JavaScript `WebSocket` API. When a JavaScript application creates a new `WebSocket` object (e.g., `new WebSocket("wss://example.com")`), the browser's network stack initiates the WebSocket handshake. If the connection is over HTTPS and the server supports HTTP/2, this `WebSocketHttp2HandshakeStream` class is responsible for performing the handshake.

**Example:**

```javascript
// In a web page's JavaScript:
const websocket = new WebSocket("wss://example.com/socket");

websocket.onopen = () => {
  console.log("WebSocket connection opened!");
  websocket.send("Hello from JavaScript!");
};

websocket.onmessage = (event) => {
  console.log("Received message:", event.data);
};

websocket.onerror = (error) => {
  console.error("WebSocket error:", error);
};

websocket.onclose = () => {
  console.log("WebSocket connection closed.");
};
```

When this JavaScript code executes, and the browser determines that `example.com` supports HTTP/2 for secure connections, the network stack will use `WebSocketHttp2HandshakeStream` to:

1. Construct and send an HTTP/2 `CONNECT` request with the necessary WebSocket headers.
2. Receive and validate the HTTP/2 response from the server.
3. If successful, upgrade the connection to a WebSocket and allow the JavaScript code to send and receive WebSocket messages.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input:**

- **`SpdySession`:** A valid, established HTTP/2 session with the target server.
- **`HttpRequestInfo`:** Contains the WebSocket URL (`wss://example.com/socket`), origin, and other relevant information.
- **`HttpRequestHeaders`:**  Initial headers provided by the caller (e.g., Origin).
- **Requested Subprotocols:**  `["chat", "superchat"]` (from JavaScript's `protocols` argument in `new WebSocket()`).
- **Requested Extensions:** `["permessage-deflate"]` (from JavaScript).

**Hypothetical Output (Successful Handshake):**

- The `SpdyStream` associated with this handshake will be successfully upgraded to a `WebSocketStream`.
- The `connect_delegate_` will be notified of the successful handshake.
- The `WebSocketStream` will have the negotiated subprotocol (e.g., "chat") and extensions (e.g., "permessage-deflate") set.

**Hypothetical Output (Failed Handshake):**

- The `connect_delegate_` will be notified of the failure with an error code (e.g., `ERR_INVALID_RESPONSE`).
- The `WebSocketStreamRequestAPI` will be notified of the failure with a descriptive message.
- No `WebSocketStream` will be created.

**User or Programming Common Usage Errors:**

1. **Incorrect WebSocket URL:** Providing an invalid or non-WebSocket URL will likely result in a connection failure before reaching this stage or during the initial HTTP/2 connection establishment.

2. **Server Misconfiguration:** If the server is not configured to handle WebSocket connections over HTTP/2, it might return an unexpected HTTP status code or missing headers, causing the handshake to fail in `ValidateResponse` or `ValidateUpgradeResponse`. For example, the server might return a 400 Bad Request or a 500 Internal Server Error.

   ```
   // Example of a server misconfiguration leading to failure:
   // Server responds with a 400 status code:
   // HTTP/2 400 Bad Request
   // ... other headers ...
   ```
   In this case, `ValidateResponse` would detect the non-200 status and report an error.

3. **Mismatched Subprotocols or Extensions:** If the client requests specific subprotocols or extensions, and the server does not support or accept them, the handshake will fail in `ValidateSubProtocol` or `ValidateExtensions`.

   ```
   // Example: Client requests "chat", server doesn't support it.
   // Server response might omit the Sec-WebSocket-Protocol header or send a different one.
   ```
   `ValidateSubProtocol` would detect this mismatch and report an error.

**User Operation Steps to Reach Here (as a Debugging线索):**

1. **User opens a web page in Chrome.**
2. **The web page's JavaScript code executes `new WebSocket("wss://example.com/socket");`.**
3. **Chrome's network stack resolves the hostname `example.com`.**
4. **Chrome establishes a secure (HTTPS) connection to `example.com` on port 443.**
5. **During the TLS handshake, ALPN (Application-Layer Protocol Negotiation) might indicate that the server supports HTTP/2.**
6. **If HTTP/2 is negotiated, Chrome establishes an HTTP/2 session (`SpdySession`).**
7. **The `WebSocket` API in Chrome triggers the WebSocket handshake process.**
8. **Because the underlying connection is HTTP/2, the `WebSocketHttp2HandshakeStream` class is instantiated to handle the handshake.**
9. **`SendRequest` is called to send the initial handshake request over the HTTP/2 session.**
10. **The server responds, and `OnHeadersReceived` is called to process the response headers.**
11. **`ValidateResponse` and `ValidateUpgradeResponse` are called to verify the server's response.**
12. **If successful, `Upgrade` is called to create the `WebSocketStream`. If not, `OnFailure` is called to report the error.**

**Debugging Clues:**

- **Network Tab in Developer Tools:**  Inspecting the network requests in Chrome's Developer Tools will show the initial HTTP/2 `CONNECT` request for the WebSocket handshake and the corresponding response headers. This can reveal issues like incorrect status codes, missing headers, or unexpected values.
- **`chrome://net-internals/#spdy`:** This internal page in Chrome provides detailed information about SPDY (and HTTP/2) sessions, including stream creation, header exchange, and errors. It can be helpful to diagnose low-level HTTP/2 issues.
- **Logging:** Chromium's network stack has extensive logging capabilities. Enabling network logging can provide more detailed information about the handshake process, including header values and error messages. Look for logs related to "WebSocket" or "Spdy".

By understanding the role of `websocket_http2_handshake_stream.cc` and the steps involved in establishing a WebSocket connection over HTTP/2, developers can better diagnose and resolve network-related issues in their web applications.

Prompt: 
```
这是目录为net/websockets/websocket_http2_handshake_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_http2_handshake_stream.h"

#include <set>
#include <string_view>
#include <utility>

#include "base/check.h"
#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/strings/strcat.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_stream.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/websockets/websocket_basic_stream.h"
#include "net/websockets/websocket_deflate_predictor_impl.h"
#include "net/websockets/websocket_deflate_stream.h"
#include "net/websockets/websocket_handshake_constants.h"
#include "net/websockets/websocket_handshake_request_info.h"

namespace net {

namespace {

bool ValidateStatus(const HttpResponseHeaders* headers) {
  return headers->GetStatusLine() == "HTTP/1.1 200";
}

}  // namespace

WebSocketHttp2HandshakeStream::WebSocketHttp2HandshakeStream(
    base::WeakPtr<SpdySession> session,
    WebSocketStream::ConnectDelegate* connect_delegate,
    std::vector<std::string> requested_sub_protocols,
    std::vector<std::string> requested_extensions,
    WebSocketStreamRequestAPI* request,
    std::set<std::string> dns_aliases)
    : session_(session),
      connect_delegate_(connect_delegate),
      requested_sub_protocols_(requested_sub_protocols),
      requested_extensions_(requested_extensions),
      stream_request_(request),
      dns_aliases_(std::move(dns_aliases)) {
  DCHECK(connect_delegate);
  DCHECK(request);
}

WebSocketHttp2HandshakeStream::~WebSocketHttp2HandshakeStream() {
  spdy_stream_request_.reset();
  RecordHandshakeResult(result_);
}

void WebSocketHttp2HandshakeStream::RegisterRequest(
    const HttpRequestInfo* request_info) {
  DCHECK(request_info);
  DCHECK(request_info->traffic_annotation.is_valid());
  request_info_ = request_info;
}

int WebSocketHttp2HandshakeStream::InitializeStream(
    bool can_send_early,
    RequestPriority priority,
    const NetLogWithSource& net_log,
    CompletionOnceCallback callback) {
  priority_ = priority;
  net_log_ = net_log;
  return OK;
}

int WebSocketHttp2HandshakeStream::SendRequest(
    const HttpRequestHeaders& headers,
    HttpResponseInfo* response,
    CompletionOnceCallback callback) {
  DCHECK(!headers.HasHeader(websockets::kSecWebSocketKey));
  DCHECK(!headers.HasHeader(websockets::kSecWebSocketProtocol));
  DCHECK(!headers.HasHeader(websockets::kSecWebSocketExtensions));
  DCHECK(headers.HasHeader(HttpRequestHeaders::kOrigin));
  DCHECK(headers.HasHeader(websockets::kUpgrade));
  DCHECK(headers.HasHeader(HttpRequestHeaders::kConnection));
  DCHECK(headers.HasHeader(websockets::kSecWebSocketVersion));

  if (!session_) {
    const int rv = ERR_CONNECTION_CLOSED;
    OnFailure("Connection closed before sending request.", rv, std::nullopt);
    return rv;
  }

  http_response_info_ = response;

  IPEndPoint address;
  int result = session_->GetPeerAddress(&address);
  if (result != OK) {
    OnFailure("Error getting IP address.", result, std::nullopt);
    return result;
  }
  http_response_info_->remote_endpoint = address;

  auto request = std::make_unique<WebSocketHandshakeRequestInfo>(
      request_info_->url, base::Time::Now());
  request->headers = headers;

  AddVectorHeaders(requested_extensions_, requested_sub_protocols_,
                   &request->headers);

  CreateSpdyHeadersFromHttpRequestForWebSocket(
      request_info_->url, request->headers, &http2_request_headers_);

  connect_delegate_->OnStartOpeningHandshake(std::move(request));

  callback_ = std::move(callback);
  spdy_stream_request_ = std::make_unique<SpdyStreamRequest>();
  // The initial request for the WebSocket is a CONNECT, so there is no need to
  // call ConfirmHandshake().
  int rv = spdy_stream_request_->StartRequest(
      SPDY_BIDIRECTIONAL_STREAM, session_, request_info_->url, true, priority_,
      request_info_->socket_tag, net_log_,
      base::BindOnce(&WebSocketHttp2HandshakeStream::StartRequestCallback,
                     base::Unretained(this)),
      NetworkTrafficAnnotationTag(request_info_->traffic_annotation));
  if (rv == OK) {
    StartRequestCallback(rv);
    return ERR_IO_PENDING;
  }
  return rv;
}

int WebSocketHttp2HandshakeStream::ReadResponseHeaders(
    CompletionOnceCallback callback) {
  if (stream_closed_)
    return stream_error_;

  if (response_headers_complete_)
    return ValidateResponse();

  callback_ = std::move(callback);
  return ERR_IO_PENDING;
}

int WebSocketHttp2HandshakeStream::ReadResponseBody(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback) {
  // Callers should instead call Upgrade() to get a WebSocketStream
  // and call ReadFrames() on that.
  NOTREACHED();
}

void WebSocketHttp2HandshakeStream::Close(bool not_reusable) {
  spdy_stream_request_.reset();
  if (stream_) {
    stream_ = nullptr;
    stream_closed_ = true;
    stream_error_ = ERR_CONNECTION_CLOSED;
  }
  stream_adapter_.reset();
}

bool WebSocketHttp2HandshakeStream::IsResponseBodyComplete() const {
  return false;
}

bool WebSocketHttp2HandshakeStream::IsConnectionReused() const {
  return true;
}

void WebSocketHttp2HandshakeStream::SetConnectionReused() {}

bool WebSocketHttp2HandshakeStream::CanReuseConnection() const {
  return false;
}

int64_t WebSocketHttp2HandshakeStream::GetTotalReceivedBytes() const {
  return stream_ ? stream_->raw_received_bytes() : 0;
}

int64_t WebSocketHttp2HandshakeStream::GetTotalSentBytes() const {
  return stream_ ? stream_->raw_sent_bytes() : 0;
}

bool WebSocketHttp2HandshakeStream::GetAlternativeService(
    AlternativeService* alternative_service) const {
  return false;
}

bool WebSocketHttp2HandshakeStream::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  return stream_ && stream_->GetLoadTimingInfo(load_timing_info);
}

void WebSocketHttp2HandshakeStream::GetSSLInfo(SSLInfo* ssl_info) {
  if (stream_)
    stream_->GetSSLInfo(ssl_info);
}

int WebSocketHttp2HandshakeStream::GetRemoteEndpoint(IPEndPoint* endpoint) {
  if (!session_)
    return ERR_SOCKET_NOT_CONNECTED;

  return session_->GetRemoteEndpoint(endpoint);
}

void WebSocketHttp2HandshakeStream::PopulateNetErrorDetails(
    NetErrorDetails* /*details*/) {
  return;
}

void WebSocketHttp2HandshakeStream::Drain(HttpNetworkSession* session) {
  Close(true /* not_reusable */);
}

void WebSocketHttp2HandshakeStream::SetPriority(RequestPriority priority) {
  priority_ = priority;
  if (stream_)
    stream_->SetPriority(priority_);
}

std::unique_ptr<HttpStream>
WebSocketHttp2HandshakeStream::RenewStreamForAuth() {
  // Renewing the stream is not supported.
  return nullptr;
}

const std::set<std::string>& WebSocketHttp2HandshakeStream::GetDnsAliases()
    const {
  return dns_aliases_;
}

std::string_view WebSocketHttp2HandshakeStream::GetAcceptChViaAlps() const {
  return {};
}

std::unique_ptr<WebSocketStream> WebSocketHttp2HandshakeStream::Upgrade() {
  DCHECK(extension_params_.get());

  stream_adapter_->DetachDelegate();
  std::unique_ptr<WebSocketStream> basic_stream =
      std::make_unique<WebSocketBasicStream>(std::move(stream_adapter_),
                                             nullptr, sub_protocol_,
                                             extensions_, net_log_);

  if (!extension_params_->deflate_enabled)
    return basic_stream;

  return std::make_unique<WebSocketDeflateStream>(
      std::move(basic_stream), extension_params_->deflate_parameters,
      std::make_unique<WebSocketDeflatePredictorImpl>());
}

bool WebSocketHttp2HandshakeStream::CanReadFromStream() const {
  return stream_adapter_ && stream_adapter_->is_initialized();
}

base::WeakPtr<WebSocketHandshakeStreamBase>
WebSocketHttp2HandshakeStream::GetWeakPtr() {
  return weak_ptr_factory_.GetWeakPtr();
}

void WebSocketHttp2HandshakeStream::OnHeadersSent() {
  std::move(callback_).Run(OK);
}

void WebSocketHttp2HandshakeStream::OnHeadersReceived(
    const quiche::HttpHeaderBlock& response_headers) {
  DCHECK(!response_headers_complete_);
  DCHECK(http_response_info_);

  response_headers_complete_ = true;

  const int rv =
      SpdyHeadersToHttpResponse(response_headers, http_response_info_);
  DCHECK_NE(rv, ERR_INCOMPLETE_HTTP2_HEADERS);

  http_response_info_->response_time =
      http_response_info_->original_response_time = stream_->response_time();
  // Do not store SSLInfo in the response here, HttpNetworkTransaction will take
  // care of that part.
  http_response_info_->was_alpn_negotiated = true;
  http_response_info_->request_time = stream_->GetRequestTime();
  http_response_info_->connection_info = HttpConnectionInfo::kHTTP2;
  http_response_info_->alpn_negotiated_protocol =
      HttpConnectionInfoToString(http_response_info_->connection_info);

  if (callback_)
    std::move(callback_).Run(ValidateResponse());
}

void WebSocketHttp2HandshakeStream::OnClose(int status) {
  DCHECK(stream_adapter_);
  DCHECK_GT(ERR_IO_PENDING, status);

  stream_closed_ = true;
  stream_error_ = status;
  stream_ = nullptr;

  stream_adapter_.reset();

  // If response headers have already been received,
  // then ValidateResponse() sets |result_|.
  if (!response_headers_complete_)
    result_ = HandshakeResult::HTTP2_FAILED;

  OnFailure(base::StrCat({"Stream closed with error: ", ErrorToString(status)}),
            status, std::nullopt);

  if (callback_)
    std::move(callback_).Run(status);
}

void WebSocketHttp2HandshakeStream::StartRequestCallback(int rv) {
  DCHECK(callback_);
  if (rv != OK) {
    spdy_stream_request_.reset();
    std::move(callback_).Run(rv);
    return;
  }
  stream_ = spdy_stream_request_->ReleaseStream();
  spdy_stream_request_.reset();
  stream_adapter_ =
      std::make_unique<WebSocketSpdyStreamAdapter>(stream_, this, net_log_);
  rv = stream_->SendRequestHeaders(std::move(http2_request_headers_),
                                   MORE_DATA_TO_SEND);
  // SendRequestHeaders() always returns asynchronously,
  // and instead of taking a callback, it calls OnHeadersSent().
  DCHECK_EQ(ERR_IO_PENDING, rv);
}

int WebSocketHttp2HandshakeStream::ValidateResponse() {
  DCHECK(http_response_info_);
  const HttpResponseHeaders* headers = http_response_info_->headers.get();
  const int response_code = headers->response_code();
  switch (response_code) {
    case HTTP_OK:
      return ValidateUpgradeResponse(headers);

    // We need to pass these through for authentication to work.
    case HTTP_UNAUTHORIZED:
    case HTTP_PROXY_AUTHENTICATION_REQUIRED:
      return OK;

    // Other status codes are potentially risky (see the warnings in the
    // WHATWG WebSocket API spec) and so are dropped by default.
    default:
      OnFailure(
          base::StringPrintf(
              "Error during WebSocket handshake: Unexpected response code: %d",
              headers->response_code()),
          ERR_FAILED, headers->response_code());
      result_ = HandshakeResult::HTTP2_INVALID_STATUS;
      return ERR_INVALID_RESPONSE;
  }
}

int WebSocketHttp2HandshakeStream::ValidateUpgradeResponse(
    const HttpResponseHeaders* headers) {
  extension_params_ = std::make_unique<WebSocketExtensionParams>();
  std::string failure_message;
  if (!ValidateStatus(headers)) {
    result_ = HandshakeResult::HTTP2_INVALID_STATUS;
  } else if (!ValidateSubProtocol(headers, requested_sub_protocols_,
                                  &sub_protocol_, &failure_message)) {
    result_ = HandshakeResult::HTTP2_FAILED_SUBPROTO;
  } else if (!ValidateExtensions(headers, &extensions_, &failure_message,
                                 extension_params_.get())) {
    result_ = HandshakeResult::HTTP2_FAILED_EXTENSIONS;
  } else {
    result_ = HandshakeResult::HTTP2_CONNECTED;
    return OK;
  }

  const int rv = ERR_INVALID_RESPONSE;
  OnFailure("Error during WebSocket handshake: " + failure_message, rv,
            std::nullopt);
  return rv;
}

void WebSocketHttp2HandshakeStream::OnFailure(
    const std::string& message,
    int net_error,
    std::optional<int> response_code) {
  stream_request_->OnFailure(message, net_error, response_code);
}

}  // namespace net

"""

```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `http_network_transaction.cc`. They are also interested in the relationship between this code and JavaScript, examples of logical reasoning with input/output, common user/programming errors, and debugging tips.

Plan:
1. Read through the code and identify the main functions and their purpose.
2. Analyze how the code manages the lifecycle of an HTTP transaction.
3. Look for interactions with other parts of the Chromium networking stack.
4. Determine if there's a direct relationship with JavaScript.
5. Identify potential user/programming errors.
6. Outline a typical user interaction flow leading to this code.这是 Chromium 网络栈中 `net/http/http_network_transaction.cc` 文件的部分源代码，主要负责处理 HTTP 网络事务的生命周期中的连接建立和初始化的阶段。这是该文件的第二部分，专注于建立 HTTP 连接、初始化流，以及处理认证相关的逻辑。

**归纳一下它的功能:**

这段代码主要负责以下功能：

1. **创建网络流 (Create Stream):**
   - 根据请求类型（普通 HTTP 或 WebSocket）和配置（是否启用 IP based pooling, Alternative Services）向 `HttpStreamFactory` 请求创建一个网络流 (`HttpStream`).
   - 记录创建流的开始时间，用于性能统计。
   - 如果收到 `421 Misdirected Request` 错误后的重试，会禁用 IP based pooling 和 Alternative Services。

2. **完成创建网络流 (Create Stream Complete):**
   - 从 `HttpStreamRequest` 中复制连接尝试信息。
   - 如果流创建成功，记录创建流的耗时，并准备进行连接后的回调。
   - 如果遇到 `ERR_HTTP_1_1_REQUIRED` 或 `ERR_PROXY_HTTP_1_1_REQUIRED`，会调用 `HandleHttp11Required` 进行处理，这通常意味着需要切换到 HTTP/1.1 协议。
   - 处理 SSL 客户端认证错误。
   - 清理 `HttpStreamRequest` 对象。

3. **初始化网络流 (Init Stream):**
   - 调用 `HttpStream` 的 `InitializeStream` 方法，进行更底层的初始化，例如设置优先级。
   - 记录 `InitializeStream` 是否被阻塞，用于性能分析。

4. **完成初始化网络流 (Init Stream Complete):**
   - 如果初始化失败，会调用 `HandleIOError` 处理错误，并缓存网络错误详情，重置网络流。

5. **连接回调 (Connected Callback):**
   - 在网络流成功建立连接后执行。
   - 将 `HttpRequestInfo` 对象注册到 `HttpStream` 上。
   - 获取远程端点信息。
   - 如果设置了连接成功的回调函数 (`connected_callback_`)，则执行该回调，通知上层连接已建立。回调函数会携带连接类型、远程地址、ALPS 协商的 Accept-CH 值、是否由已知根证书颁发机构签发以及协商的 ALPN 协议等信息。

6. **完成连接回调 (Connected Callback Complete):**
   - 处理连接回调的结果，如果失败则关闭网络流。

7. **生成代理认证令牌 (Generate Proxy Auth Token):**
   - 如果需要进行代理认证 (`ShouldApplyProxyAuth`)，则调用 `HttpAuthController` 生成代理认证令牌。
   - 记录生成令牌是否被阻塞，用于性能分析。

8. **完成生成代理认证令牌 (Generate Proxy Auth Token Complete):**
   - 处理代理认证令牌生成的结果。

9. **生成服务器认证令牌 (Generate Server Auth Token):**
   - 如果需要进行服务器认证 (`ShouldApplyServerAuth`)，则调用 `HttpAuthController` 生成服务器认证令牌。
   - 记录生成令牌是否被阻塞，用于性能分析。

10. **完成生成服务器认证令牌 (Generate Server Auth Token Complete):**
    - 处理服务器认证令牌生成的结果。

**它与 JavaScript 的功能关系:**

这段 C++ 代码位于浏览器网络栈的底层，负责实际的网络通信。JavaScript 代码（例如通过 `fetch` API 或 `XMLHttpRequest`）发起的网络请求最终会通过浏览器引擎传递到这个网络栈进行处理。

**举例说明:**

假设一个 JavaScript 脚本使用 `fetch` API 发起一个 HTTPS 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这个 `fetch` 请求被发起后，浏览器会创建相应的 `HttpNetworkTransaction` 对象。这段 C++ 代码会负责以下步骤：

1. **`DoCreateStream`**: 根据请求的 URL (`https://example.com/data`)，以及是否使用代理等信息，向 `HttpStreamFactory` 请求创建一个安全的网络流 (很可能是基于 TLS/SSL 的)。
2. **`DoCreateStreamComplete`**: 当网络流创建完成后，会得到结果。
3. **`DoInitStream`**: 初始化创建的流，建立 TCP 连接并进行 TLS 握手。
4. **`DoConnectedCallback`**: TLS 握手成功后，会执行连接成功的回调，通知上层可以开始发送请求了。

**逻辑推理 (假设输入与输出):**

**假设输入:**

- `request_->url`: `https://api.example.com/resource`
- `priority_`: `MEDIUM`
- `enable_ip_based_pooling_`: `true`
- `enable_alternative_services_`: `true`
- 请求不需要代理认证或服务器认证。

**预期输出 (在 `DoStart` 和 `DoCreateStreamComplete` 之间):**

- 调用 `session_->http_stream_factory()->RequestStream(...)`，请求创建一个用于 `https://api.example.com/resource` 的 HTTP 流。
- `stream_request_` 将被赋值为一个指向 `HttpStreamRequest` 对象的智能指针。
- 如果流创建成功，`DoCreateStreamComplete` 的 `result` 参数为 `OK`。
- `next_state_` 将被设置为 `STATE_CONNECTED_CALLBACK`。
- 创建流的耗时将被记录到 UMA 统计中。

**用户或编程常见的使用错误 (举例说明):**

1. **配置错误导致连接失败:** 用户可能配置了错误的代理服务器地址或端口，导致 `HttpStreamFactory` 无法创建连接，最终 `DoCreateStreamComplete` 的 `result` 可能为 `ERR_PROXY_CONNECTION_FAILED`。
2. **HTTPS 站点证书问题:** 如果访问的 HTTPS 站点证书无效（例如过期、自签名），`HttpStreamFactory` 在建立 TLS 连接时会失败，`DoCreateStreamComplete` 的 `result` 可能为 `ERR_CERT_AUTHORITY_INVALID` 或其他证书相关的错误。
3. **WebSocket 连接错误:** 如果 JavaScript 代码尝试建立 WebSocket 连接到一个不支持 WebSocket 协议的服务器，`RequestWebSocketHandshakeStream` 可能会返回错误，导致握手失败。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:**  这将触发一个网络请求。
2. **浏览器解析 URL:** 确定请求的协议、域名、端口等信息。
3. **网络栈开始处理请求:**  `HttpNetworkTransaction` 对象被创建。
4. **进入 `DoStart` 状态:**  这是 `HttpNetworkTransaction` 的起始状态。
5. **进入 `DoCreateStream` 状态:**  根据请求信息，决定是请求普通的 HTTP 流还是 WebSocket 流。
6. **`HttpStreamFactory` 尝试创建连接:** 这可能涉及 DNS 解析、TCP 连接建立、TLS 握手等步骤。
7. **连接结果返回到 `DoCreateStreamComplete`:**  指示连接是否成功。

**调试线索:**

- **网络日志 (net-internals):**  Chromium 提供了 `chrome://net-internals` 页面，可以查看详细的网络请求日志，包括连接尝试、错误信息等，可以帮助定位问题发生在哪个阶段。
- **断点调试:**  在 `http_network_transaction.cc` 中设置断点，可以逐步跟踪代码执行流程，查看变量的值，了解连接建立过程中的具体细节。
- **错误码分析:**  `DoCreateStreamComplete` 等函数返回的错误码可以提供关于连接失败原因的重要线索。

总而言之，这段代码是 Chromium 网络栈中处理 HTTP 连接建立和初始化阶段的核心部分，它与 JavaScript 发起的网络请求紧密相关，并通过一系列状态管理来确保网络事务的正确执行。理解这段代码的功能对于调试网络问题至关重要。

### 提示词
```
这是目录为net/http/http_network_transaction.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ed on a retry after 421 Misdirected Request
  // is received. Alternative Services are also disabled in this case (though
  // they can also be disabled when retrying after a QUIC error).
  if (!enable_ip_based_pooling_)
    DCHECK(!enable_alternative_services_);

  create_stream_start_time_ = base::TimeTicks::Now();
  if (ForWebSocketHandshake()) {
    stream_request_ =
        session_->http_stream_factory()->RequestWebSocketHandshakeStream(
            *request_, priority_, /*allowed_bad_certs=*/observed_bad_certs_,
            this, websocket_handshake_stream_base_create_helper_,
            enable_ip_based_pooling_, enable_alternative_services_, net_log_);
  } else {
    stream_request_ = session_->http_stream_factory()->RequestStream(
        *request_, priority_, /*allowed_bad_certs=*/observed_bad_certs_, this,
        enable_ip_based_pooling_, enable_alternative_services_, net_log_);
  }
  DCHECK(stream_request_.get());
  return ERR_IO_PENDING;
}

int HttpNetworkTransaction::DoCreateStreamComplete(int result) {
  CopyConnectionAttemptsFromStreamRequest();
  if (result == OK) {
    next_state_ = STATE_CONNECTED_CALLBACK;
    DCHECK(stream_.get());
    CHECK(!create_stream_start_time_.is_null());
    base::UmaHistogramTimes(
        base::StrCat(
            {"Net.NetworkTransaction.Create",
             (ForWebSocketHandshake() ? "WebSocketStreamTime."
                                      : "HttpStreamTime."),
             (IsGoogleHostWithAlpnH3(url_.host()) ? "GoogleHost." : ""),
             NegotiatedProtocolToHistogramSuffix(response_)}),
        base::TimeTicks::Now() - create_stream_start_time_);
  } else if (result == ERR_HTTP_1_1_REQUIRED ||
             result == ERR_PROXY_HTTP_1_1_REQUIRED) {
    return HandleHttp11Required(result);
  } else {
    // Handle possible client certificate errors that may have occurred if the
    // stream used SSL for one or more of the layers.
    result = HandleSSLClientAuthError(result);
  }

  // At this point we are done with the stream_request_.
  stream_request_.reset();
  return result;
}

int HttpNetworkTransaction::DoInitStream() {
  DCHECK(stream_.get());
  next_state_ = STATE_INIT_STREAM_COMPLETE;

  base::TimeTicks now = base::TimeTicks::Now();
  int rv = stream_->InitializeStream(can_send_early_data_, priority_, net_log_,
                                     io_callback_);

  // TODO(crbug.com/359404121): Remove this histogram after the investigation
  // completes.
  bool blocked = rv == ERR_IO_PENDING;
  if (blocked) {
    blocked_initialize_stream_start_time_ = now;
  }
  base::UmaHistogramBoolean(
      base::StrCat({"Net.NetworkTransaction.InitializeStreamBlocked",
                    IsGoogleHostWithAlpnH3(url_.host()) ? "GoogleHost." : ".",
                    NegotiatedProtocolToHistogramSuffix(response_)}),
      blocked);
  return rv;
}

int HttpNetworkTransaction::DoInitStreamComplete(int result) {
  // TODO(crbug.com/359404121): Remove this histogram after the investigation
  // completes.
  if (!blocked_initialize_stream_start_time_.is_null()) {
    base::UmaHistogramTimes(
        base::StrCat({"Net.NetworkTransaction.InitializeStreamBlockTime",
                      IsGoogleHostWithAlpnH3(url_.host()) ? "GoogleHost." : ".",
                      NegotiatedProtocolToHistogramSuffix(response_)}),
        base::TimeTicks::Now() - blocked_initialize_stream_start_time_);
  }

  if (result != OK) {
    if (result < 0)
      result = HandleIOError(result);

    // The stream initialization failed, so this stream will never be useful.
    if (stream_) {
      total_received_bytes_ += stream_->GetTotalReceivedBytes();
      total_sent_bytes_ += stream_->GetTotalSentBytes();
    }
    CacheNetErrorDetailsAndResetStream();

    return result;
  }

  next_state_ = STATE_GENERATE_PROXY_AUTH_TOKEN;
  return result;
}

int HttpNetworkTransaction::DoConnectedCallback() {
  // Register the HttpRequestInfo object on the stream here so that it's
  // available when invoking the `connected_callback_`, as
  // HttpStream::GetAcceptChViaAlps() needs the HttpRequestInfo to retrieve
  // the ACCEPT_CH frame payload.
  stream_->RegisterRequest(request_);
  next_state_ = STATE_CONNECTED_CALLBACK_COMPLETE;

  int result = stream_->GetRemoteEndpoint(&remote_endpoint_);
  if (result != OK) {
    // `GetRemoteEndpoint()` fails when the underlying socket is not connected
    // anymore, even though the peer's address is known. This can happen when
    // we picked a socket from socket pools while it was still connected, but
    // the remote side closes it before we get a chance to send our request.
    // See if we should retry the request based on the error code we got.
    return HandleIOError(result);
  }

  if (connected_callback_.is_null()) {
    return OK;
  }

  // Fire off notification that we have successfully connected.
  TransportType type = TransportType::kDirect;
  if (!proxy_info_.is_direct()) {
    type = TransportType::kProxied;
  }

  bool is_issued_by_known_root = false;
  if (IsSecureRequest()) {
    SSLInfo ssl_info;
    CHECK(stream_);
    stream_->GetSSLInfo(&ssl_info);
    is_issued_by_known_root = ssl_info.is_issued_by_known_root;
  }

  return connected_callback_.Run(
      TransportInfo(type, remote_endpoint_,
                    std::string{stream_->GetAcceptChViaAlps()},
                    is_issued_by_known_root,
                    NextProtoFromString(response_.alpn_negotiated_protocol)),
      base::BindOnce(&HttpNetworkTransaction::ResumeAfterConnected,
                     base::Unretained(this)));
}

int HttpNetworkTransaction::DoConnectedCallbackComplete(int result) {
  if (result != OK) {
    if (stream_) {
      stream_->Close(/*not_reusable=*/false);
    }

    // Stop the state machine here if the call failed.
    return result;
  }

  next_state_ = STATE_INIT_STREAM;
  return OK;
}

int HttpNetworkTransaction::DoGenerateProxyAuthToken() {
  next_state_ = STATE_GENERATE_PROXY_AUTH_TOKEN_COMPLETE;
  if (!ShouldApplyProxyAuth())
    return OK;
  HttpAuth::Target target = HttpAuth::AUTH_PROXY;
  if (!auth_controllers_[target].get())
    auth_controllers_[target] = base::MakeRefCounted<HttpAuthController>(
        target, AuthURL(target), request_->network_anonymization_key,
        session_->http_auth_cache(), session_->http_auth_handler_factory(),
        session_->host_resolver());
  int rv = auth_controllers_[target]->MaybeGenerateAuthToken(
      request_, io_callback_, net_log_);
  // TODO(crbug.com/359404121): Remove this histogram after the investigation
  // completes.
  const bool blocked = rv == ERR_IO_PENDING;
  if (blocked) {
    blocked_generate_proxy_auth_token_start_time_ = base::TimeTicks::Now();
  }
  base::UmaHistogramBoolean(
      base::StrCat({"Net.NetworkTransaction.GenerateProxyAuthTokenBlocked",
                    IsGoogleHostWithAlpnH3(url_.host()) ? "GoogleHost." : ".",
                    NegotiatedProtocolToHistogramSuffix(response_)}),
      blocked);
  return rv;
}

int HttpNetworkTransaction::DoGenerateProxyAuthTokenComplete(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  // TODO(crbug.com/359404121): Remove this histogram after the investigation
  // completes.
  if (!blocked_generate_proxy_auth_token_start_time_.is_null()) {
    base::UmaHistogramTimes(
        base::StrCat({"Net.NetworkTransaction.GenerateProxyAuthTokenBlockTime",
                      IsGoogleHostWithAlpnH3(url_.host()) ? "GoogleHost." : ".",
                      NegotiatedProtocolToHistogramSuffix(response_)}),
        base::TimeTicks::Now() - blocked_generate_proxy_auth_token_start_time_);
  }
  if (rv == OK)
    next_state_ = STATE_GENERATE_SERVER_AUTH_TOKEN;
  return rv;
}

int HttpNetworkTransaction::DoGenerateServerAuthToken() {
  next_state_ = STATE_GENERATE_SERVER_AUTH_TOKEN_COMPLETE;
  HttpAuth::Target target = HttpAuth::AUTH_SERVER;
  if (!auth_controllers_[target].get()) {
    auth_controllers_[target] = base::MakeRefCounted<HttpAuthController>(
        target, AuthURL(target), request_->network_anonymization_key,
        session_->http_auth_cache(), session_->http_auth_handler_factory(),
        session_->host_resolver());
    if (request_->load_flags & LOAD_DO_NOT_USE_EMBEDDED_IDENTITY)
      auth_controllers_[target]->DisableEmbeddedIdentity();
  }
  if (!ShouldApplyServerAuth())
    return OK;
  int rv = auth_controllers_[target]->MaybeGenerateAuthToken(
      request_, io_callback_, net_log_);
  // TODO(crbug.com/359404121): Remove this histogram after the investigation
  // completes.
  const bool blocked = rv == ERR_IO_PENDING;
  if (blocked) {
    blocked_generate_server_auth_token_start_time_ = base::TimeTicks::Now();
  }
  base::UmaHistogramBoolean(
      base::StrCat({"Net.NetworkTransaction.GenerateServerAuthTokenBlocked",
                    IsGoogleHostWithAlpnH3(url_.host()) ? "GoogleHost." : ".",
                    NegotiatedProtocolToHistogramSuffix(response_)}),
      blocked);
  return rv;
}

int HttpNetworkTransaction::DoGenerateServerAuthTokenComplete(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  // TODO(crbug.com/359404121): Remove this histogram after the investigation
  // completes.
  if (!blocked_generate_server_auth_token_start_time_.is_null()) {
    base::UmaHistogramTimes(
        base::StrCat({"Net.NetworkTransaction.GenerateServerAuthTokenBlockTime",
                      IsGoogleHostWithAlpnH3(url_.host()) ? "GoogleHost." : ".",
                      NegotiatedProtocolToHistogramSuffix(response_)}),
        base::TimeTicks::Now() -
            blocked_generate_server_auth_token_start_time_);
  }
  if (rv == OK)
    next_state_ = STATE_INIT_REQUEST_BODY;
  return rv;
}

int HttpNetworkTransaction::BuildRequestHeaders(
    bool using_http_proxy_without_tunnel) {
  request_headers_.SetHeader(HttpRequestHeaders::kHost,
                             GetHostAndOptionalPort(request_->url));

  // For compat with HTTP/1.0 servers and proxies:
  if (using_http_proxy_without_tunnel) {
    request_headers_.SetHeader(HttpRequestHeaders::kProxyConnection,
                               "keep-alive");
  } else {
    request_headers_.SetHeader(HttpRequestHeaders::kConnection, "keep-alive");
  }

  // Add a content length header?
  if (request_->upload_data_stream) {
    if (request_->upload_data_stream->is_chunked()) {
      request_headers_.SetHeader(
          HttpRequestHeaders::kTransferEncoding, "chunked");
    } else {
      request_headers_.SetHeader(
          HttpRequestHeaders::kContentLength,
          base::NumberToString(request_->upload_data_stream->size()));
    }
  } else if (request_->method == "POST" || request_->method == "PUT") {
    // An empty POST/PUT request still needs a content length.  As for HEAD,
    // IE and Safari also add a content length header.  Presumably it is to
    // support sending a HEAD request to an URL that only expects to be sent a
    // POST or some other method that normally would have a message body.
    // Firefox (40.0) does not send the header, and RFC 7230 & 7231
    // specify that it should not be sent due to undefined behavior.
    request_headers_.SetHeader(HttpRequestHeaders::kContentLength, "0");
  }

  // Honor load flags that impact proxy caches.
  if (request_->load_flags & LOAD_BYPASS_CACHE) {
    request_headers_.SetHeader(HttpRequestHeaders::kPragma, "no-cache");
    request_headers_.SetHeader(HttpRequestHeaders::kCacheControl, "no-cache");
  } else if (request_->load_flags & LOAD_VALIDATE_CACHE) {
    request_headers_.SetHeader(HttpRequestHeaders::kCacheControl, "max-age=0");
  }

  if (ShouldApplyProxyAuth() && HaveAuth(HttpAuth::AUTH_PROXY))
    auth_controllers_[HttpAuth::AUTH_PROXY]->AddAuthorizationHeader(
        &request_headers_);
  if (ShouldApplyServerAuth() && HaveAuth(HttpAuth::AUTH_SERVER))
    auth_controllers_[HttpAuth::AUTH_SERVER]->AddAuthorizationHeader(
        &request_headers_);

  if (features::kIpPrivacyAddHeaderToProxiedRequests.Get() &&
      proxy_info_.is_for_ip_protection()) {
    CHECK(!proxy_info_.is_direct() || features::kIpPrivacyDirectOnly.Get());
    if (!proxy_info_.is_direct()) {
      request_headers_.SetHeader("IP-Protection", "1");
    }
  }

  request_headers_.MergeFrom(request_->extra_headers);

  if (modify_headers_callbacks_) {
    modify_headers_callbacks_.Run(&request_headers_);
  }

  response_.did_use_http_auth =
      request_headers_.HasHeader(HttpRequestHeaders::kAuthorization) ||
      request_headers_.HasHeader(HttpRequestHeaders::kProxyAuthorization);
  return OK;
}

int HttpNetworkTransaction::DoInitRequestBody() {
  next_state_ = STATE_INIT_REQUEST_BODY_COMPLETE;
  int rv = OK;
  if (request_->upload_data_stream)
    rv = request_->upload_data_stream->Init(
        base::BindOnce(&HttpNetworkTransaction::OnIOComplete,
                       base::Unretained(this)),
        net_log_);
  return rv;
}

int HttpNetworkTransaction::DoInitRequestBodyComplete(int result) {
  if (result == OK)
    next_state_ = STATE_BUILD_REQUEST;
  return result;
}

int HttpNetworkTransaction::DoBuildRequest() {
  next_state_ = STATE_BUILD_REQUEST_COMPLETE;
  headers_valid_ = false;

  // This is constructed lazily (instead of within our Start method), so that
  // we have proxy info available.
  if (request_headers_.IsEmpty()) {
    bool using_http_proxy_without_tunnel = UsingHttpProxyWithoutTunnel();
    return BuildRequestHeaders(using_http_proxy_without_tunnel);
  }

  return OK;
}

int HttpNetworkTransaction::DoBuildRequestComplete(int result) {
  if (result == OK)
    next_state_ = STATE_SEND_REQUEST;
  return result;
}

int HttpNetworkTransaction::DoSendRequest() {
  send_start_time_ = base::TimeTicks::Now();
  next_state_ = STATE_SEND_REQUEST_COMPLETE;

  stream_->SetRequestIdempotency(request_->idempotency);
  return stream_->SendRequest(request_headers_, &response_, io_callback_);
}

int HttpNetworkTransaction::DoSendRequestComplete(int result) {
  send_end_time_ = base::TimeTicks::Now();

  if (result == ERR_HTTP_1_1_REQUIRED ||
      result == ERR_PROXY_HTTP_1_1_REQUIRED) {
    return HandleHttp11Required(result);
  }

  if (result < 0)
    return HandleIOError(result);
  next_state_ = STATE_READ_HEADERS;
  return OK;
}

int HttpNetworkTransaction::DoReadHeaders() {
  next_state_ = STATE_READ_HEADERS_COMPLETE;
  return stream_->ReadResponseHeaders(io_callback_);
}

int HttpNetworkTransaction::DoReadHeadersComplete(int result) {
  // We can get a ERR_SSL_CLIENT_AUTH_CERT_NEEDED here due to SSL renegotiation.
  // Server certificate errors are impossible. Rather than reverify the new
  // server certificate, BoringSSL forbids server certificates from changing.
  DCHECK(!IsCertificateError(result));
  if (result == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
    DCHECK(stream_.get());
    DCHECK(IsSecureRequest());
    // Should only reach this code when there's a certificate request.
    CHECK(response_.cert_request_info);

    total_received_bytes_ += stream_->GetTotalReceivedBytes();
    total_sent_bytes_ += stream_->GetTotalSentBytes();
    stream_->Close(true);
    CacheNetErrorDetailsAndResetStream();
  }

  if (result == ERR_HTTP_1_1_REQUIRED ||
      result == ERR_PROXY_HTTP_1_1_REQUIRED) {
    return HandleHttp11Required(result);
  }

  // ERR_CONNECTION_CLOSED is treated differently at this point; if partial
  // response headers were received, we do the best we can to make sense of it
  // and send it back up the stack.
  //
  // TODO(davidben): Consider moving this to HttpBasicStream, It's a little
  // bizarre for SPDY. Assuming this logic is useful at all.
  // TODO(davidben): Bubble the error code up so we do not cache?
  if (result == ERR_CONNECTION_CLOSED && response_.headers.get())
    result = OK;

  if (ForWebSocketHandshake()) {
    RecordWebSocketFallbackResult(
        result, http_1_1_was_required_,
        HttpConnectionInfoToCoarse(response_.connection_info));
  }

  if (result < 0)
    return HandleIOError(result);

  DCHECK(response_.headers.get());

  // Check for a 103 Early Hints response.
  if (response_.headers->response_code() == HTTP_EARLY_HINTS) {
    NetLogResponseHeaders(
        net_log_,
        NetLogEventType::HTTP_TRANSACTION_READ_EARLY_HINTS_RESPONSE_HEADERS,
        response_.headers.get());

    // Early Hints does not make sense for a WebSocket handshake.
    if (ForWebSocketHandshake()) {
      return ERR_FAILED;
    }

    // TODO(crbug.com/40496584): Validate headers?  "Content-Encoding" etc
    // should not appear since informational responses can't contain content.
    // https://www.rfc-editor.org/rfc/rfc9110#name-informational-1xx

    if (EarlyHintsAreAllowedOn(response_.connection_info) &&
        early_response_headers_callback_) {
      early_response_headers_callback_.Run(std::move(response_.headers));
    }

    // Reset response headers for the final response.
    response_.headers =
        base::MakeRefCounted<HttpResponseHeaders>(std::string());
    next_state_ = STATE_READ_HEADERS;
    return OK;
  }

  if (!ContentEncodingsValid())
    return ERR_CONTENT_DECODING_FAILED;

  // On a 408 response from the server ("Request Timeout") on a stale socket,
  // retry the request for HTTP/1.1 but not HTTP/2 or QUIC because those
  // multiplex requests and have no need for 408.
  if (response_.headers->response_code() == HTTP_REQUEST_TIMEOUT &&
      HttpConnectionInfoToCoarse(response_.connection_info) ==
          HttpConnectionInfoCoarse::kHTTP1 &&
      stream_->IsConnectionReused()) {
#if BUILDFLAG(ENABLE_REPORTING)
    GenerateNetworkErrorLoggingReport(OK);
#endif  // BUILDFLAG(ENABLE_REPORTING)
    net_log_.AddEventWithNetErrorCode(
        NetLogEventType::HTTP_TRANSACTION_RESTART_AFTER_ERROR,
        response_.headers->response_code());
    // This will close the socket - it would be weird to try and reuse it, even
    // if the server doesn't actually close it.
    ResetConnectionAndRequestForResend(RetryReason::kHttpRequestTimeout);
    return OK;
  }

  NetLogResponseHeaders(net_log_,
                        NetLogEventType::HTTP_TRANSACTION_READ_RESPONSE_HEADERS,
                        response_.headers.get());
  if (response_headers_callback_)
    response_headers_callback_.Run(response_.headers);

  if (response_.headers->GetHttpVersion() < HttpVersion(1, 0)) {
    // HTTP/0.9 doesn't support the PUT method, so lack of response headers
    // indicates a buggy server.  See:
    // https://bugzilla.mozilla.org/show_bug.cgi?id=193921
    if (request_->method == "PUT")
      return ERR_METHOD_NOT_SUPPORTED;
  }

  if (can_send_early_data_ &&
      response_.headers->response_code() == HTTP_TOO_EARLY) {
    return HandleIOError(ERR_EARLY_DATA_REJECTED);
  }

  // Check for an intermediate 100 Continue response.  An origin server is
  // allowed to send this response even if we didn't ask for it, so we just
  // need to skip over it.
  // We treat any other 1xx in this same way unless:
  //  * The response is 103, which is already handled above
  //  * This is a WebSocket request, in which case we pass it on up.
  if (response_.headers->response_code() / 100 == 1 &&
      !ForWebSocketHandshake()) {
    response_.headers =
        base::MakeRefCounted<HttpResponseHeaders>(std::string());
    next_state_ = STATE_READ_HEADERS;
    return OK;
  }

  const bool has_body_with_null_source =
      request_->upload_data_stream &&
      request_->upload_data_stream->has_null_source();
  if (response_.headers->response_code() == 421 &&
      (enable_ip_based_pooling_ || enable_alternative_services_) &&
      !has_body_with_null_source) {
#if BUILDFLAG(ENABLE_REPORTING)
    GenerateNetworkErrorLoggingReport(OK);
#endif  // BUILDFLAG(ENABLE_REPORTING)
    // Retry the request with both IP based pooling and Alternative Services
    // disabled.
    enable_ip_based_pooling_ = false;
    enable_alternative_services_ = false;
    net_log_.AddEvent(
        NetLogEventType::HTTP_TRANSACTION_RESTART_MISDIRECTED_REQUEST);
    ResetConnectionAndRequestForResend(RetryReason::kHttpMisdirectedRequest);
    return OK;
  }

  if (IsSecureRequest()) {
    stream_->GetSSLInfo(&response_.ssl_info);
    if (response_.ssl_info.is_valid() &&
        !IsCertStatusError(response_.ssl_info.cert_status)) {
      session_->http_stream_factory()->ProcessAlternativeServices(
          session_, network_anonymization_key_, response_.headers.get(),
          url::SchemeHostPort(request_->url));
    }
  }

  int rv = HandleAuthChallenge();
  if (rv != OK)
    return rv;

#if BUILDFLAG(ENABLE_REPORTING)
  // Note: This just handles the legacy Report-To header, which is still
  // required for NEL. The newer Reporting-Endpoints header is processed in
  // network::PopulateParsedHeaders().
  ProcessReportToHeader();

  // Note: Unless there is a pre-existing NEL policy for this origin, any NEL
  // reports generated before the NEL header is processed here will just be
  // dropped by the NetworkErrorLoggingService.
  ProcessNetworkErrorLoggingHeader();

  // Generate NEL report here if we have to report an HTTP error (4xx or 5xx
  // code), or if the response body will not be read, or on a redirect.
  // Note: This will report a success for a redirect even if an error is
  // encountered later while draining the body.
  int response_code = response_.headers->response_code();
  if ((response_code >= 400 && response_code < 600) ||
      response_code == HTTP_NO_CONTENT || response_code == HTTP_RESET_CONTENT ||
      response_code == HTTP_NOT_MODIFIED || request_->method == "HEAD" ||
      response_.headers->GetContentLength() == 0 ||
      response_.headers->IsRedirect(nullptr /* location */)) {
    GenerateNetworkErrorLoggingReport(OK);
  }
#endif  // BUILDFLAG(ENABLE_REPORTING)

  headers_valid_ = true;

  // We have reached the end of Start state machine, set the RequestInfo to
  // null.
  // RequestInfo is a member of the HttpTransaction's consumer and is useful
  // only until the final response headers are received. Clearing it will ensure
  // that HttpRequestInfo is only used up until final response headers are
  // received. Clearing is allowed so that the transaction can be disassociated
  // from its creating consumer in cases where it is shared for writing to the
  // cache. It is also safe to set it to null at this point since
  // upload_data_stream is also not used in the Read state machine.
  if (pending_auth_target_ == HttpAuth::AUTH_NONE)
    request_ = nullptr;

  return OK;
}

int HttpNetworkTransaction::DoReadBody() {
  DCHECK(read_buf_.get());
  DCHECK_GT(read_buf_len_, 0);
  DCHECK(stream_ != nullptr);

  next_state_ = STATE_READ_BODY_COMPLETE;
  return stream_->ReadResponseBody(
      read_buf_.get(), read_buf_len_, io_callback_);
}

int HttpNetworkTransaction::DoReadBodyComplete(int result) {
  // We are done with the Read call.
  bool done = false;
  if (result <= 0) {
    DCHECK_NE(ERR_IO_PENDING, result);
    done = true;
  } else {
    received_body_bytes_ += result;
  }

  // Clean up connection if we are done.
  if (done) {
    // Note: Just because IsResponseBodyComplete is true, we're not
    // necessarily "done".  We're only "done" when it is the last
    // read on this HttpNetworkTransaction, which will be signified
    // by a zero-length read.
    // TODO(mbelshe): The keep-alive property is really a property of
    //    the stream.  No need to compute it here just to pass back
    //    to the stream's Close function.
    bool keep_alive =
        stream_->IsResponseBodyComplete() && stream_->CanReuseConnection();

    stream_->Close(!keep_alive);
    // Note: we don't reset the stream here.  We've closed it, but we still
    // need it around so that callers can call methods such as
    // GetUploadProgress() and have them be meaningful.
    // TODO(mbelshe): This means we closed the stream here, and we close it
    // again in ~HttpNetworkTransaction.  Clean that up.

    // The next Read call will return 0 (EOF).

    // This transaction was successful. If it had been retried because of an
    // error with an alternative service, mark that alternative service broken.
    if (!enable_alternative_services_ &&
        retried_alternative_service_.protocol != kProtoUnknown) {
      HistogramBrokenAlternateProtocolLocation(
          BROKEN_ALTERNATE_PROTOCOL_LOCATION_HTTP_NETWORK_TRANSACTION);
      session_->http_server_properties()->MarkAlternativeServiceBroken(
          retried_alternative_service_, network_anonymization_key_);
    }

#if BUILDFLAG(ENABLE_REPORTING)
    GenerateNetworkErrorLoggingReport(result);
#endif  // BUILDFLAG(ENABLE_REPORTING)
  }

  // Clear these to avoid leaving around old state.
  read_buf_ = nullptr;
  read_buf_len_ = 0;

  return result;
}

int HttpNetworkTransaction::DoDrainBodyForAuthRestart() {
  // This method differs from DoReadBody only in the next_state_.  So we just
  // call DoReadBody and override the next_state_.  Perhaps there is a more
  // elegant way for these two methods to share code.
  int rv = DoReadBody();
  DCHECK(next_state_ == STATE_READ_BODY_COMPLETE);
  next_state_ = STATE_DRAIN_BODY_FOR_AUTH_RESTART_COMPLETE;
  return rv;
}

// TODO(wtc): This method and the DoReadBodyComplete method are almost
// the same.  Figure out a good way for these two methods to share code.
int HttpNetworkTransaction::DoDrainBodyForAuthRestartComplete(int result) {
  // keep_alive defaults to true because the very reason we're draining the
  // response body is to reuse the connection for auth restart.
  bool done = false, keep_alive = true;
  if (result < 0) {
    // Error or closed connection while reading the socket.
    // Note: No Network Error Logging report is generated here because a report
    // will have already been generated for the original request due to the auth
    // challenge, so a second report is not generated for the same request here.
    done = true;
    keep_alive = false;
  } else if (stream_->IsResponseBodyComplete()) {
    done = true;
  }

  if (done) {
    DidDrainBodyForAuthRestart(keep_alive);
  } else {
    // Keep draining.
    next_state_ = STATE_DRAIN_BODY_FOR_AUTH_RESTART;
  }

  return OK;
}

#if BUILDFLAG(ENABLE_REPORTING)
void HttpNetworkTransaction::ProcessReportToHeader() {
  std::optional<std::string> value =
      response_.headers->GetNormalizedHeader("Report-To");
  if (!value) {
    return;
  }

  ReportingService* reporting_service = session_->reporting_service();
  if (!reporting_service)
    return;

  // Only accept Report-To headers on HTTPS connections that have no
  // certificate errors.
  if (!response_.ssl_info.is_valid())
    return;
  if (IsCertStatusError(response_.ssl_info.cert_status))
    return;

  reporting_service->ProcessReportToHeader(url::Origin::Create(url_),
                                           network_anonymization_key_, *value);
}

void HttpNetworkTransaction::ProcessNetworkErrorLoggingHeader() {
  std::optional<std::string> value = response_.headers->GetNormalizedHeader(
      NetworkErrorLoggingService::kHeaderName);
  if (!value) {
    return;
  }

  NetworkErrorLoggingService* network_error_logging_service =
      session_->network_error_logging_service();
  if (!network_error_logging_service)
    return;

  // Don't accept NEL headers received via a proxy, because the IP address of
  // the destination server is not known.
  if (response_.WasFetchedViaProxy()) {
    return;
  }

  // Only accept NEL headers on HTTPS connections that have no certificate
  // errors.
  if (!response_.ssl_info.is_valid() ||
      IsCertStatusError(response_.ssl_info.cert_status)) {
    return;
  }

  if (remote_endpoint_.address().empty())
    return;

  network_error_logging_service->OnHeader(network_anonymization_key_,
                                          url::Origin::Create(url_),
                                          remote_endpoint_.address(), *value);
}

void HttpNetworkTransaction::GenerateNetworkErrorLoggingReportIfError(int rv) {
  if (rv < 0 && rv != ERR_IO_PENDING)
    GenerateNetworkErrorLoggingReport(rv);
}

void HttpNetworkTransaction::GenerateNetworkErrorLoggingReport(int rv) {
  // |rv| should be a valid Error
  DCHECK_NE(rv, ERR_IO_PENDING);
  DCHECK_LE(rv, 0);

  if (network_error_logging_report_generated_)
    return;
  network_error_logging_report_generated_ = true;

  NetworkErrorLoggingService* service =
      session_->network_error_logging_service();
  if (!service)
    return;

  // Don't report on proxy auth challenges.
  if (response_.headers && response_.headers->response_code() ==
                               HTTP_PROXY_AUTHENTICATION_REQUIRED) {
    return;
  }

  // Don't generate NEL reports if we are behind a proxy, to avoid leaking
  // internal network details.
  if (response_.WasFetchedViaProxy()) {
    return;
  }

  // Ignore errors from non-HTTPS origins.
  if (!url_.SchemeIsCryptographic())
    return;

  NetworkErrorLoggingService::RequestDetails details;

  details.network_anonymization_key = network_anonymization_key_;
  details.uri = url_;
  if (!request_referrer_.empty())
    details.referrer = GURL(request_referrer_);
  details.user_agent = request_user_agent_;
  if (!remote_endpoint_.address().empty()) {
    details.server_ip = remote_endpoint_.address();
  } else if (!connection_attempts_.empty()) {
    // When we failed to connect to the server, `remote_endpoint_` is not set.
    // In such case, we use the last endpoint address of `connection_attempts_`
    // for the NEL report. This address information is important for the
    // downgrade step to protect against port scan attack.
    // https://www.w3.org/TR/network-error-logging/#generate-a-network-error-report
    details.server_ip = connection_attempts_.back().endpoint.address();
  } else {
    details.server_ip = IPAddress();
  }
  // HttpResponseHeaders::response_code() returns 0 if response code couldn't
  // be parsed, which is also how NEL represents the same.
  if (response_.headers) {
    details.status_code = response_.headers->response_code();
  } else {
    details.status_code = 0;
  }
  // If we got response headers, assume that the connection used HTTP/1.1
  // unless ALPN negotiation tells us otherwise (handled below).
  if (response_.was_alpn_negotiated) {
    details.protocol = response_.alpn_negotiated_protocol;
  } else {
    details.protocol = "http/1.1";
  }
  details.method = request_method_;
  details.elapsed_time = base::TimeTicks::Now() - start_timeticks_;
  details.type = static_cast<Error>(rv);
  details.reporting_upload_depth = request_reporting_upload_depth_;

  service->OnRequest(std::move(details));
}
#endif  // BUILDFLAG(ENABLE_REPORTING)

int HttpNetworkTransaction::HandleHttp11Required(int error) {
  DCHECK(error == ERR_HTTP_1_1_REQUIRED ||
         error == ERR_PROXY_HTTP_1_1_REQUIRED);

  http_1_1_was_required_ = true;

  // HttpServerProperties should have been updated, so when the request is sent
  // again, it will automatically use HTTP/1.1.
  ResetConnectionAndRequestForResend(RetryReason::kHttp11Required);
  return OK;
}

int HttpNetworkTransaction::HandleSSLClientAuthError(int error) {
  // Client certificate errors may come from either the origin server or the
  // proxy.
  //
  // Origin errors are handled here, while most proxy errors are handled in the
  // HttpStreamFactory and below, while handshaking with the proxy. However, in
  // TLS 1.2 with False Start, or TLS 1.3, client certificate errors are
  // reported immediately after the handshake. The error will then surface out
  // of the first Read() rather than Connect().
  //
  // If the request is tunneled (i.e. the origin is HTTPS), this first Read()
  // occurs while establishing the tunnel and HttpStreamFactory handles the
  // proxy error. However, if the request is not tunneled (i.e. the origin is
  // HTTP), this first Read() happens late and is ultimately surfaced out of
  // DoReadHeadersComplete(). This method will then be responsible for both
  // origin and proxy errors.
  //
  // See https://crbug.com/828965.
  if (error != ERR_SSL_PROTOCOL_ERROR && !IsClientCertificateError(error)) {
    return error;
  }

  bool is_server = !UsingHttpProxyWithoutTunnel();
  HostPortPair host_port_pair;
  // TODO(crbug.com/40284947): Remove check and return error when
  // multi-proxy chain.
  if (is_server) {
    host_port_pair = HostPortPair::FromURL(request_->url);
  } else {
    CHECK(proxy_info_.proxy_chain().is_single_proxy());
    host_port_pair = proxy_info_.proxy_chain().First().host_port_pair();
  }

  // Check that something in the proxy chain or endpoint are using HTTPS.
  if (DCHECK_IS_ON()) {
    bool server_using_tls = IsSecureRequest();
    bool proxy_using_tls = proxy_info_.AnyProxyInChain(
        [](const ProxyServer& s) { return s
```
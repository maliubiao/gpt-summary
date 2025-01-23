Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze the `HttpStreamFactory::Job` class in `http_stream_factory_job.cc`. I need to identify its functions, relate it to JavaScript (if possible), provide logical examples, highlight potential user errors, outline the user journey to reach this code, and finally, summarize its functionality. The fact that this is "part 2" suggests a preceding part focused on a broader context, likely the `HttpStreamFactory` itself.

2. **Break Down the Code Snippet:**  I'll go through the provided code section by section, focusing on the methods within the `HttpStreamFactory::Job` class. For each method, I'll ask:
    * What is its purpose?
    * What are its inputs and outputs (even if it's internal state changes)?
    * Does it interact with other classes or components?

3. **Identify Key Functionalities:** From the method analysis, I can group related methods to identify the major functionalities of the `Job` class. I see actions related to:
    * Connection establishment (initialization, completion, handling errors).
    * Protocol negotiation (HTTP/1.1, HTTP/2, HTTP/3/QUIC).
    * Stream creation (basic, SPDY, WebSocket, bidirectional).
    * Interaction with proxies (including handling failures and fallbacks).
    * Spdy session management (finding and creating sessions).
    * Preconnect functionality.
    * Error handling and reporting.

4. **Address JavaScript Relationship:** This requires thinking about how the network stack interacts with the browser's rendering engine and JavaScript. The key connection point is the `HttpStream` (or its variations like `SpdyHttpStream`, `QuicHttpStream`, `WebSocketHandshakeStream`) which is eventually used to send and receive data for a web request initiated by JavaScript. I need to illustrate how JavaScript actions lead to the creation of these streams via the `HttpStreamFactory::Job`.

5. **Construct Logical Examples (Input/Output):**  For scenarios like connection completion or stream creation, I need to define plausible inputs (e.g., a successful or failed connection attempt, the desired protocol) and the expected outputs or state changes within the `Job` object. This demonstrates how the code handles different situations.

6. **Identify User/Programming Errors:**  This involves thinking about common mistakes users or developers might make that would interact with the network stack. Incorrect proxy configurations, server-side protocol misconfigurations, or attempting unsupported actions are good examples. I need to show how these errors might manifest in the context of the `Job` class.

7. **Outline User Journey (Debugging):** This requires stepping back and tracing the typical steps a user takes that would eventually trigger the creation and execution of an `HttpStreamFactory::Job`. Starting from a user action in the browser (typing a URL, clicking a link) and progressing through DNS resolution, proxy resolution, connection establishment, and finally stream creation is crucial.

8. **Synthesize the Summary:** Based on the detailed analysis, I'll create a concise summary of the `HttpStreamFactory::Job`'s overall purpose and responsibilities. This should encapsulate the main functionalities identified earlier.

9. **Review and Refine:**  After drafting the answer, I'll review it for clarity, accuracy, and completeness. I'll ensure that the explanations are easy to understand and that the examples are relevant. I'll double-check that all parts of the original request have been addressed.

**Self-Correction Example During the Process:**

Initially, I might focus too much on the low-level details of each method. Then, I realize that the prompt asks for a higher-level understanding of the *functionality*. So, I need to shift my focus from just describing what each line of code does to explaining the *purpose* of each method within the larger context of establishing network connections. I also need to make sure the connection to JavaScript is clear and not just a technical description. I might also initially miss the significance of the "part 2" and need to infer that "part 1" likely dealt with the factory itself, and this part is about the individual connection attempts. This helps frame the answer better.
这是 `net/http/http_stream_factory_job.cc` 文件中 `HttpStreamFactory::Job` 类的代码片段，是第二部分，让我们归纳一下它的功能：

**HttpStreamFactory::Job 的核心功能归纳 (基于提供的第二部分代码):**

延续第一部分的分析，`HttpStreamFactory::Job` 的主要职责是 **管理建立 HTTP 或 QUIC 连接并创建网络流的过程**。这部分代码主要集中在连接建立完成后的处理、协议协商、流的创建以及错误处理和重试机制。

**具体功能点归纳：**

1. **处理连接初始化完成:** `DoInitConnectionComplete(int result)` 方法是关键，它在底层连接（TCP 或 QUIC）建立完成后被调用。
    * **协议协商判断:**  根据连接结果和是否使用 SSL/QUIC，确定最终使用的协议 (HTTP/1.1, HTTP/2, HTTP/3/QUIC)。记录协商的协议。
    * **处理不同连接类型:**  区分直接连接和通过代理的连接，以及是否使用了 QUIC。
    * **处理预连接:** 对于预连接请求，如果成功建立连接，则完成预连接过程。
    * **处理 WebSocket:** 检查 WebSocket 在 HTTP/2 上的支持情况。
    * **错误处理:**  根据连接结果判断是否需要重试代理或返回错误。`ReconsiderProxyAfterError(int error)` 方法处理代理错误后的回退逻辑。
    * **QUIC 流创建:** 如果使用 QUIC，则创建 `BidirectionalStreamQuicImpl` 或 `QuicHttpStream`。

2. **处理用户操作等待:** `DoWaitingUserAction(int result)`  表明当前请求处于等待用户操作的状态，例如等待代理认证信息。

3. **创建 SPDY (HTTP/2) 流:** `SetSpdyHttpStreamOrBidirectionalStreamImpl(base::WeakPtr<SpdySession> session)`  用于在已有的或新建立的 HTTP/2 会话上创建 `SpdyHttpStream` 或 `BidirectionalStreamSpdyImpl`。
    * **WebSocket 支持:**  处理在 HTTP/2 连接上创建 WebSocket 流的情况。

4. **创建基础 HTTP/1.1 流:** `DoCreateStream()` 方法负责创建实际的网络流对象。
    * **选择流类型:**  根据是否使用 SPDY、是否是 WebSocket 等因素，创建 `HttpBasicStream` 或调用 WebSocket 相关的创建方法。
    * **处理已存在的 HTTP/2 会话:**  如果已经有可用的 HTTP/2 会话，则直接使用，无需创建新的连接。
    * **创建新的 HTTP/2 会话:** 如果没有可用的 HTTP/2 会话，则尝试基于已建立的连接创建一个新的 HTTP/2 会话。
    * **关闭空闲连接:** 在切换到 HTTP/2 会话时，关闭组内的空闲连接。

5. **处理流创建完成:** `DoCreateStreamComplete(int result)` 在流创建完成后被调用，报告代理解析的成功。

6. **处理可用的 SPDY 会话:** `OnSpdySessionAvailable(base::WeakPtr<SpdySession> spdy_session)` 当有新的 SPDY 会话可用时被调用。
    * **复用已有会话:**  如果请求可以复用现有的 SPDY 会话，则取消当前连接的建立，并使用已有的会话。
    * **处理预连接:** 如果是预连接请求，则完成预连接。

7. **代理错误回退:** `ReconsiderProxyAfterError(int error)` 判断是否可以回退到下一个代理。

8. **复制连接尝试信息:** `MaybeCopyConnectionAttemptsFromHandle()` 将连接尝试信息传递给委托方。

9. **Job 工厂:** `JobFactory` 类用于创建 `HttpStreamFactory::Job` 对象。

10. **连接节流 (Throttling):** `ShouldThrottleConnectForSpdy()` 判断是否应该为了 SPDY 连接而节流当前连接尝试。

11. **记录预连接指标:** `RecordPreconnectHistograms(int result)` 记录与 Google 主机预连接相关的指标。

**总结来说，这部分代码集中处理了连接建立后的关键步骤，包括协议协商、根据协商结果创建不同类型的网络流（HTTP/1.1, HTTP/2, QUIC, WebSocket），以及处理连接和流创建过程中可能出现的错误和重试机制。它确保了在合适的协议上创建相应的网络流，并管理 HTTP/2 会话的复用和创建。**

由于代码片段主要涉及网络连接和协议处理的底层逻辑，与 JavaScript 的直接关系较少。JavaScript 通过浏览器提供的 Web API (例如 `fetch`, `XMLHttpRequest`, `WebSocket`) 发起网络请求，这些 API 底层会调用 Chromium 的网络栈，最终会涉及到 `HttpStreamFactory::Job` 的执行。

**与 JavaScript 功能的关系举例说明：**

当 JavaScript 代码使用 `fetch` API 发起一个 HTTPS 请求时，`HttpStreamFactory::Job` 的工作流程可能如下：

1. **DNS 解析:**  首先进行域名解析，找到服务器的 IP 地址。
2. **代理解析:**  确定是否需要使用代理服务器。
3. **建立连接:**  根据目标地址和代理设置，建立 TCP 连接或 QUIC 连接。`DoInitConnectionComplete` 在连接建立后被调用。
4. **协议协商:**  如果目标服务器支持 HTTP/2 或 HTTP/3，则进行 TLS 握手和 ALPN 协商。`DoInitConnectionComplete` 中的逻辑会判断协商结果。
5. **创建流:**  如果协商成功，则会创建 `SpdyHttpStream` 或 `QuicHttpStream`；否则，创建 `HttpBasicStream`。`DoCreateStream` 负责创建流对象。
6. **发送请求:** 创建的流对象会用于发送 JavaScript 发起的 HTTP 请求。

**逻辑推理示例（假设输入与输出）：**

**假设输入:**

* `DoInitConnectionComplete` 被调用，`result` 为 `OK`，表示 TCP 连接建立成功。
* `using_ssl_` 为 `true`，表示使用了 HTTPS。
* 服务器支持 HTTP/2。

**输出:**

* `negotiated_protocol_` 被设置为 `kProtoHTTP2`。
* `next_state_` 被设置为 `STATE_CREATE_STREAM`。

**假设输入:**

* `DoInitConnectionComplete` 被调用，`result` 为一个负数错误码，例如 `ERR_CONNECTION_REFUSED`。

**输出:**

* 如果可以回退到下一个代理，则 `should_reconsider_proxy_` 被设置为 `true`，返回原始的错误码。
* 否则，直接返回原始的错误码。

**用户或编程常见的使用错误举例说明：**

1. **错误的代理配置:** 用户在操作系统或浏览器中配置了错误的代理服务器地址或端口。当 `HttpStreamFactory::Job` 尝试连接代理时，可能会失败，导致 `DoInitConnectionComplete` 的 `result` 为错误码，并且可能触发 `ReconsiderProxyAfterError` 尝试连接其他代理。

2. **服务器不支持请求的协议:**  JavaScript 代码尝试通过 HTTPS 连接到只支持 HTTP 的服务器，或者期望使用 HTTP/2 但服务器不支持。`DoInitConnectionComplete` 中的协议协商逻辑会识别这种情况，并可能返回 `ERR_ALPN_NEGOTIATION_FAILED`。

3. **WebSocket over HTTP/2 的服务端配置问题:**  如果服务端没有正确配置以支持 WebSocket over HTTP/2，`SetSpdyHttpStreamOrBidirectionalStreamImpl` 中可能会返回 `ERR_NOT_IMPLEMENTED`。

**用户操作如何一步步的到达这里（作为调试线索）：**

1. **用户在浏览器地址栏输入 HTTPS 网址并回车，或者点击一个 HTTPS 链接。**
2. **浏览器解析 URL，确定目标主机名和端口。**
3. **浏览器检查本地缓存，看是否已经存在到该主机的可用连接。**
4. **如果不存在可用连接，网络栈开始建立连接的过程。**
5. **DNS 解析器查找目标主机的 IP 地址。**
6. **代理解析器根据配置确定是否需要使用代理，并找到代理服务器的地址。**
7. **`HttpStreamFactory` 创建一个 `HttpStreamFactory::Job` 对象来处理这个连接请求。**
8. **`Job` 对象开始尝试建立到目标主机或代理服务器的 TCP 或 QUIC 连接。**
9. **一旦连接建立成功或失败，`DoInitConnectionComplete` 方法会被调用，传入连接结果。**
10. **在 `DoInitConnectionComplete` 中，会进行协议协商，确定最终使用的协议。**
11. **根据协商结果，`DoCreateStream` 方法会被调用，创建相应的 `HttpStream` 对象（例如 `HttpBasicStream`, `SpdyHttpStream`, `QuicHttpStream`）。**

在调试网络请求问题时，如果断点设置在 `DoInitConnectionComplete` 或 `DoCreateStream` 中，可以观察连接建立的结果、协议协商的过程以及最终创建的流类型，从而定位问题所在。例如，如果发现连接建立失败，需要检查 DNS 解析和代理配置；如果协议协商失败，可能是服务器不支持请求的协议。

### 提示词
```
这是目录为net/http/http_stream_factory_job.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ailedOnDefaultNetwork(this);
}

int HttpStreamFactory::Job::DoInitConnectionComplete(int result) {
  net_log_.EndEvent(NetLogEventType::HTTP_STREAM_JOB_INIT_CONNECTION);

  establishing_tunnel_ = false;

  // No need to continue waiting for a session, once a connection is
  // established.
  spdy_session_request_.reset();

  if ((job_type_ == PRECONNECT) || (job_type_ == PRECONNECT_DNS_ALPN_H3)) {
    if (using_quic_) {
      return result;
    }
    DCHECK_EQ(OK, result);
    return OK;
  }

  resolve_error_info_ = connection_->resolve_error_info();

  // Determine the protocol (HTTP/1.1, HTTP/2, or HTTP/3). This covers both the
  // origin and some proxy cases. First, if the URL is HTTPS (or WSS), we may
  // negotiate HTTP/2 or HTTP/3 with the origin. Second, non-tunneled requests
  // (i.e. HTTP URLs) through an HTTPS or QUIC proxy work by sending the request
  // to the proxy directly. In that case, this logic also handles the proxy's
  // negotiated protocol. HTTPS requests are always tunneled, so at most one of
  // these applies.
  //
  // Tunneled requests may also negotiate ALPN at the proxy, but
  // HttpProxyConnectJob handles ALPN. The resulting StreamSocket will not
  // report an ALPN protocol.
  if (result == OK) {
    if (using_quic_) {
      // TODO(davidben): Record these values consistently between QUIC and TCP
      // below. In the QUIC case, we only record it for origin connections. In
      // the TCP case, we also record it for non-tunneled, proxied requests.
      if (using_ssl_) {
        negotiated_protocol_ = kProtoQUIC;
      }
    } else if (connection_->socket()->GetNegotiatedProtocol() !=
               kProtoUnknown) {
      // Only connections that use TLS (either to the origin or via a GET to a
      // secure proxy) can negotiate ALPN.
      bool get_to_secure_proxy =
          IsGetToProxy(proxy_info_.proxy_chain(), origin_url_) &&
          proxy_info_.proxy_chain().Last().is_secure_http_like();
      DCHECK(using_ssl_ || get_to_secure_proxy);
      negotiated_protocol_ = connection_->socket()->GetNegotiatedProtocol();
      net_log_.AddEvent(NetLogEventType::HTTP_STREAM_REQUEST_PROTO, [&] {
        return NetLogHttpStreamProtoParams(negotiated_protocol_);
      });
      if (using_spdy()) {
        if (is_websocket_) {
          // WebSocket is not supported over a fresh HTTP/2 connection. This
          // should not be reachable. For the origin, we do not request HTTP/2
          // on fresh WebSockets connections, because not all HTTP/2 servers
          // implement RFC 8441. For proxies, WebSockets are always tunneled.
          //
          // TODO(davidben): This isn't a CHECK() because, previously, it was
          // reachable in https://crbug.com/828865. However, if reachable, it
          // means a bug in the socket pools. The socket pools have since been
          // cleaned up, so this may no longer be reachable. Restore the CHECK
          // and see if this is still needed.
          return ERR_NOT_IMPLEMENTED;
        }
      }
    }
  }

  if (using_quic_ && result < 0 && !proxy_info_.is_direct() &&
      proxy_info_.proxy_chain().Last().is_quic()) {
    return ReconsiderProxyAfterError(result);
  }

  if (expect_spdy_ && !using_spdy()) {
    return ERR_ALPN_NEGOTIATION_FAILED;
  }

  // |result| may be the result of any of the stacked protocols. The following
  // logic is used when determining how to interpret an error.
  // If |result| < 0:
  //   and connection_->socket() != NULL, then the SSL handshake ran and it
  //     is a potentially recoverable error.
  //   and connection_->socket == NULL and connection_->is_ssl_error() is true,
  //     then the SSL handshake ran with an unrecoverable error.
  //   otherwise, the error came from one of the other protocols.
  bool ssl_started = using_ssl_ && (result == OK || connection_->socket() ||
                                    connection_->is_ssl_error());
  if (!ssl_started && result < 0 && (expect_spdy_ || using_quic_)) {
    return result;
  }

  if (using_quic_) {
    if (result < 0) {
      return result;
    }

    if (stream_type_ == HttpStreamRequest::BIDIRECTIONAL_STREAM) {
      std::unique_ptr<QuicChromiumClientSession::Handle> session =
          quic_request_.ReleaseSessionHandle();
      if (!session) {
        // Quic session is closed before stream can be created.
        return ERR_CONNECTION_CLOSED;
      }
      bidirectional_stream_impl_ =
          std::make_unique<BidirectionalStreamQuicImpl>(std::move(session));
    } else {
      std::unique_ptr<QuicChromiumClientSession::Handle> session =
          quic_request_.ReleaseSessionHandle();
      if (!session) {
        // Quic session is closed before stream can be created.
        return ERR_CONNECTION_CLOSED;
      }
      auto dns_aliases =
          session->GetDnsAliasesForSessionKey(quic_request_.session_key());
      stream_ = std::make_unique<QuicHttpStream>(std::move(session),
                                                 std::move(dns_aliases));
    }
    next_state_ = STATE_CREATE_STREAM_COMPLETE;
    return OK;
  }

  if (result < 0) {
    if (!ssl_started) {
      return ReconsiderProxyAfterError(result);
    }
    return result;
  }

  next_state_ = STATE_CREATE_STREAM;
  return OK;
}

int HttpStreamFactory::Job::DoWaitingUserAction(int result) {
  // This state indicates that the stream request is in a partially
  // completed state, and we've called back to the delegate for more
  // information.

  // We're always waiting here for the delegate to call us back.
  return ERR_IO_PENDING;
}

int HttpStreamFactory::Job::SetSpdyHttpStreamOrBidirectionalStreamImpl(
    base::WeakPtr<SpdySession> session) {
  DCHECK(using_spdy());
  auto dns_aliases = session_->spdy_session_pool()->GetDnsAliasesForSessionKey(
      spdy_session_key_);

  if (is_websocket_) {
    DCHECK_NE(job_type_, PRECONNECT);
    DCHECK_NE(job_type_, PRECONNECT_DNS_ALPN_H3);
    DCHECK(delegate_->websocket_handshake_stream_create_helper());

    if (!try_websocket_over_http2_) {
      // TODO(davidben): Is this reachable? We shouldn't receive a SpdySession
      // if not requested.
      return ERR_NOT_IMPLEMENTED;
    }

    websocket_stream_ =
        delegate_->websocket_handshake_stream_create_helper()
            ->CreateHttp2Stream(session, std::move(dns_aliases));
    return OK;
  }
  if (stream_type_ == HttpStreamRequest::BIDIRECTIONAL_STREAM) {
    bidirectional_stream_impl_ = std::make_unique<BidirectionalStreamSpdyImpl>(
        session, net_log_.source());
    return OK;
  }

  // TODO(willchan): Delete this code, because eventually, the HttpStreamFactory
  // will be creating all the SpdyHttpStreams, since it will know when
  // SpdySessions become available.

  stream_ = std::make_unique<SpdyHttpStream>(session, net_log_.source(),
                                             std::move(dns_aliases));
  return OK;
}

int HttpStreamFactory::Job::DoCreateStream() {
  DCHECK(connection_->socket() || existing_spdy_session_.get());
  DCHECK(!using_quic_);

  next_state_ = STATE_CREATE_STREAM_COMPLETE;

  if (!using_spdy()) {
    DCHECK(!expect_spdy_);
    bool is_for_get_to_http_proxy = UsingHttpProxyWithoutTunnel();
    if (is_websocket_) {
      DCHECK_NE(job_type_, PRECONNECT);
      DCHECK_NE(job_type_, PRECONNECT_DNS_ALPN_H3);
      DCHECK(delegate_->websocket_handshake_stream_create_helper());
      websocket_stream_ =
          delegate_->websocket_handshake_stream_create_helper()
              ->CreateBasicStream(std::move(connection_),
                                  is_for_get_to_http_proxy,
                                  session_->websocket_endpoint_lock_manager());
    } else {
      if (!request_info_.is_http1_allowed) {
        return ERR_H2_OR_QUIC_REQUIRED;
      }
      stream_ = std::make_unique<HttpBasicStream>(std::move(connection_),
                                                  is_for_get_to_http_proxy);
    }
    return OK;
  }

  CHECK(!stream_.get());

  // It is also possible that an HTTP/2 connection has been established since
  // last time Job checked above.
  if (!existing_spdy_session_) {
    // WebSocket over HTTP/2 is only allowed to use existing HTTP/2 connections.
    // Therefore `using_spdy()` could not have been set unless a connection had
    // already been found.
    DCHECK(!is_websocket_);

    existing_spdy_session_ =
        session_->spdy_session_pool()->FindAvailableSession(
            spdy_session_key_, enable_ip_based_pooling_,
            /* is_websocket = */ false, net_log_);
  }
  if (existing_spdy_session_) {
    // We picked up an existing session, so we don't need our socket.
    if (connection_->socket()) {
      connection_->socket()->Disconnect();
    }
    connection_->Reset();

    int set_result =
        SetSpdyHttpStreamOrBidirectionalStreamImpl(existing_spdy_session_);
    existing_spdy_session_.reset();
    return set_result;
  }

  // Close idle sockets in this group, since subsequent requests will go over
  // |spdy_session|.
  if (connection_->socket()->IsConnected()) {
    connection_->CloseIdleSocketsInGroup("Switching to HTTP2 session");
  }

  auto initiator =
      (job_type_ == PRECONNECT || job_type_ == PRECONNECT_DNS_ALPN_H3)
          ? MultiplexedSessionCreationInitiator::kPreconnect
          : MultiplexedSessionCreationInitiator::kUnknown;

  base::WeakPtr<SpdySession> spdy_session;
  int rv =
      session_->spdy_session_pool()->CreateAvailableSessionFromSocketHandle(
          spdy_session_key_, std::move(connection_), net_log_, initiator,
          &spdy_session);

  if (rv != OK) {
    return rv;
  }

  url::SchemeHostPort scheme_host_port(
      using_ssl_ ? url::kHttpsScheme : url::kHttpScheme,
      spdy_session_key_.host_port_pair().host(),
      spdy_session_key_.host_port_pair().port());

  HttpServerProperties* http_server_properties =
      session_->http_server_properties();
  if (http_server_properties) {
    http_server_properties->SetSupportsSpdy(
        scheme_host_port, request_info_.network_anonymization_key,
        true /* supports_spdy */);
  }

  // Create a SpdyHttpStream or a BidirectionalStreamImpl attached to the
  // session.
  return SetSpdyHttpStreamOrBidirectionalStreamImpl(spdy_session);
}

int HttpStreamFactory::Job::DoCreateStreamComplete(int result) {
  if (result < 0) {
    return result;
  }

  session_->proxy_resolution_service()->ReportSuccess(proxy_info_);
  next_state_ = STATE_NONE;
  return OK;
}

void HttpStreamFactory::Job::OnSpdySessionAvailable(
    base::WeakPtr<SpdySession> spdy_session) {
  DCHECK(spdy_session);

  // No need for the connection any more, since |spdy_session| can be used
  // instead, and there's no benefit from keeping the old ConnectJob in the
  // socket pool.
  if (connection_) {
    connection_->ResetAndCloseSocket();
  }

  // Once a connection is initialized, or if there's any out-of-band callback,
  // like proxy auth challenge, the SpdySessionRequest is cancelled.
  DCHECK(next_state_ == STATE_INIT_CONNECTION ||
         next_state_ == STATE_INIT_CONNECTION_COMPLETE);

  // Ignore calls to ResumeInitConnection() from either the timer or the
  // SpdySessionPool.
  init_connection_already_resumed_ = true;

  // If this is a preconnect, nothing left do to.
  if (job_type_ == PRECONNECT) {
    OnPreconnectsComplete(OK);
    return;
  }

  negotiated_protocol_ = kProtoHTTP2;
  existing_spdy_session_ = spdy_session;
  next_state_ = STATE_CREATE_STREAM;

  // This will synchronously close |connection_|, so no need to worry about it
  // calling back into |this|.
  RunLoop(OK);
}

int HttpStreamFactory::Job::ReconsiderProxyAfterError(int error) {
  // Check if the error was a proxy failure.
  if (!CanFalloverToNextProxy(proxy_info_.proxy_chain(), error, &error,
                              proxy_info_.is_for_ip_protection())) {
    return error;
  }

  should_reconsider_proxy_ = true;
  return error;
}

void HttpStreamFactory::Job::MaybeCopyConnectionAttemptsFromHandle() {
  if (!connection_) {
    return;
  }

  delegate_->AddConnectionAttemptsToRequest(this,
                                            connection_->connection_attempts());
}

HttpStreamFactory::JobFactory::JobFactory() = default;

HttpStreamFactory::JobFactory::~JobFactory() = default;

std::unique_ptr<HttpStreamFactory::Job>
HttpStreamFactory::JobFactory::CreateJob(
    HttpStreamFactory::Job::Delegate* delegate,
    HttpStreamFactory::JobType job_type,
    HttpNetworkSession* session,
    const StreamRequestInfo& request_info,
    RequestPriority priority,
    const ProxyInfo& proxy_info,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    url::SchemeHostPort destination,
    GURL origin_url,
    bool is_websocket,
    bool enable_ip_based_pooling,
    NetLog* net_log,
    NextProto alternative_protocol,
    quic::ParsedQuicVersion quic_version) {
  return std::make_unique<HttpStreamFactory::Job>(
      delegate, job_type, session, request_info, priority, proxy_info,
      allowed_bad_certs, std::move(destination), origin_url,
      alternative_protocol, quic_version, is_websocket, enable_ip_based_pooling,
      net_log);
}

bool HttpStreamFactory::Job::ShouldThrottleConnectForSpdy() const {
  DCHECK(!using_quic_);
  DCHECK(!spdy_session_request_);

  // If the job has previously been throttled, don't throttle it again.
  if (init_connection_already_resumed_) {
    return false;
  }

  url::SchemeHostPort scheme_host_port(
      using_ssl_ ? url::kHttpsScheme : url::kHttpScheme,
      spdy_session_key_.host_port_pair().host(),
      spdy_session_key_.host_port_pair().port());
  // Only throttle the request if the server is believed to support H2.
  return session_->http_server_properties()->GetSupportsSpdy(
      scheme_host_port, request_info_.network_anonymization_key);
}

void HttpStreamFactory::Job::RecordPreconnectHistograms(int result) {
  if (!IsGoogleHost(destination_.host())) {
    return;
  }
  if (using_quic_) {
    // TODO(crbug.com/376304027): Expand this to non-Quic as well. Currently,
    // H1 and H2 does not return precise failure reason.
    base::UmaHistogramSparse(
        "Net.SessionCreate.GoogleSearch.Preconnect.Quic.CompletionResult",
        -result);
  }
}

}  // namespace net
```
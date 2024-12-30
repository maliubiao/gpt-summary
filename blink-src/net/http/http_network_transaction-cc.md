Response:
My thinking process to analyze the given C++ code snippet and answer the user's request goes like this:

1. **Understand the Request:** The user wants to understand the functionality of `http_network_transaction.cc` in the Chromium networking stack. They specifically ask for:
    * A summary of its functions.
    * Connections to JavaScript (if any).
    * Logical reasoning examples (input/output).
    * Common usage errors.
    * Steps leading to this code during debugging.
    * A summary of the functionality of *this specific part* (the first part of three).

2. **Initial Code Scan - High-Level Understanding:**  I quickly scan the code for keywords, class names, and included headers to get a general idea. I see:
    * `#include` directives for various networking components (`net/http`, `net/base`, `net/socket`, `url`). This confirms it's a core networking file.
    * Class name `HttpNetworkTransaction`. This is the central class this file defines.
    * Member variables like `stream_`, `request_`, `response_`, `callback_`, `next_state_`. These suggest it manages the lifecycle of an HTTP transaction.
    * Methods like `Start`, `Restart...`, `Read`, `DoLoop`, `OnStreamReady`, `OnIOComplete`. These indicate the main actions and state transitions.
    * Usage of `net::CompletionOnceCallback`, `net::IOBuffer`,  suggesting asynchronous operations.
    * Mentions of authentication (`RestartWithAuth`, `OnNeedsProxyAuth`, `OnNeedsClientAuth`).
    * Error handling (`ERR_...`).

3. **Focus on the Core Class - `HttpNetworkTransaction`:**  I recognize this is the central point. The goal is to understand what this class *does*. I look at the public methods as the main interface.

4. **Analyze Public Methods:**
    * `Start()`: Initiates an HTTP transaction. The parameters (`HttpRequestInfo`, `CompletionOnceCallback`) tell me it takes request details and a callback. The `LOAD_ONLY_FROM_CACHE` check and setting up of `net_log_`, `request_`, `url_` are important.
    * `RestartIgnoringLastError()`, `RestartWithCertificate()`, `RestartWithAuth()`:  These methods indicate the transaction can be restarted under different circumstances (ignoring errors, providing certificates, or providing authentication credentials). The `CheckMaxRestarts()` call suggests a retry mechanism.
    * `Read()`:  Reads the response body. It takes a buffer and a callback. The checks for tunnel establishment and the `STATE_READ_BODY` setting are key.
    * `GetTotalReceivedBytes()`, `GetTotalSentBytes()`, `GetReceivedBodyBytes()`: Provide metrics about the data transfer.
    * `GetResponseInfo()`: Returns information about the response.
    * `GetLoadState()`:  Indicates the current state of the transaction. The `switch` statement mapping states to `LOAD_STATE_...` is important.
    * `SetPriority()`, `SetWebSocketHandshakeStreamCreateHelper()`, `SetBeforeNetworkStartCallback()`, `SetConnectedCallback()`, `SetRequestHeadersCallback()`, `SetResponseHeadersCallback()`, `SetModifyRequestHeadersCallback()`:  These are setter methods, allowing customization and interaction with the transaction. The comments about when they can be called are crucial.
    * `ResumeNetworkStart()`, `ResumeAfterConnected()`:  Methods to resume asynchronous operations.
    * `CloseConnectionOnDestruction()`: Controls connection closing behavior.

5. **Analyze Private Methods (Especially the `DoLoop`):** The `DoLoop()` method is the heart of the state machine. I examine the `switch` statement and the actions performed in each state. This reveals the sequential steps of an HTTP transaction (creating a stream, initializing it, sending the request, reading headers, reading the body, handling authentication, etc.).

6. **Address Specific Questions:**

    * **Functionality:** Based on the analysis above, I can summarize the main functions: managing the lifecycle of an HTTP(S) transaction, handling restarts, authentication, reading data, tracking metrics, and interacting with other networking components.

    * **JavaScript Relationship:** I look for interactions with JavaScript APIs or concepts. While this C++ code doesn't directly *call* JavaScript, it's part of the browser's networking layer, which is *used by* JavaScript. Fetching resources using `fetch()` or `XMLHttpRequest` in JavaScript will eventually lead to this C++ code. The `request_info` contains data originating from JavaScript. The callbacks will eventually return data back to the browser process, potentially reaching JavaScript.

    * **Logical Reasoning (Input/Output):** I think about what inputs would lead to specific outputs. For example, `Start()` with a URL requiring authentication will likely lead to a `RestartWithAuth()` call later. A request with `LOAD_ONLY_FROM_CACHE` results in `ERR_CACHE_MISS`. A successful transaction will eventually lead to data being available in the `Read()` call.

    * **User/Programming Errors:** I consider common mistakes that could lead to issues within this code. Incorrectly setting headers, not handling authentication challenges, or canceling requests prematurely are examples. The code itself has checks for things like maximum restarts, which indicates potential errors.

    * **User Steps to Reach Here:** I trace a typical web request initiated by a user: typing a URL, clicking a link, or JavaScript making a request. These actions trigger the browser's networking stack, eventually creating an `HttpNetworkTransaction`.

    * **Summary of Part 1:** I focus on the code *provided* in the snippet. It covers the initial setup of the transaction, the state machine, and the early stages of creating and initializing the network stream. It lays the groundwork for sending the request and receiving the response.

7. **Structure the Answer:** I organize the findings logically, addressing each part of the user's request clearly and concisely. I use bullet points and code snippets where appropriate to illustrate my points. I try to explain the technical concepts in a way that is understandable.

8. **Review and Refine:** I reread my answer to ensure accuracy, completeness, and clarity. I check that I've addressed all aspects of the user's request.

This iterative process of scanning, analyzing key components, and addressing specific questions allows me to develop a comprehensive understanding of the code and provide a helpful answer to the user.

好的，这是对 `net/http/http_network_transaction.cc` 文件第一部分的分析和功能归纳：

**文件功能总览 (基于第一部分代码):**

`HttpNetworkTransaction` 类是 Chromium 网络栈中处理单个 HTTP 或 HTTPS 网络请求的核心类。 它的主要职责是管理一个 HTTP 请求的整个生命周期，从发起请求到接收响应，并处理各种中间状态和错误情况。

**具体功能列表 (基于第一部分代码):**

1. **请求生命周期管理:**
   - 负责启动 (`Start`)、重启 (`RestartIgnoringLastError`, `RestartWithCertificate`, `RestartWithAuth`) 和取消 HTTP 请求。
   - 通过状态机 (`DoLoop`) 管理请求的不同阶段，例如创建连接、发送请求、接收头部和接收 body。
   - 在析构时清理资源，包括关闭不再需要的连接。

2. **连接管理:**
   - 负责创建和管理底层的 `HttpStream` 对象，用于实际的网络通信。
   - 可以处理连接失败、连接重用等情况。
   - 涉及到与 `HttpStreamFactory` 和 `HttpStreamPool` 的交互，以获取或创建合适的连接。

3. **认证处理:**
   - 支持 HTTP 代理认证和服务器认证 (`RestartWithAuth`)。
   - 处理接收到的认证质询 (`OnNeedsProxyAuth`)，并管理 `HttpAuthController` 来获取认证信息。
   - 支持客户端证书认证 (`RestartWithCertificate`, `OnNeedsClientAuth`)。

4. **数据传输:**
   - 负责发送请求头和 body。
   - 负责接收响应头和 body (`Read`)。
   - 跟踪已发送和接收的字节数 (`GetTotalSentBytes`, `GetTotalReceivedBytes`)。

5. **错误处理和重试:**
   - 处理各种网络错误，并通过重试机制尝试恢复 (`kMaxRetryAttempts`, `kMaxRestarts`)。
   - 针对 SSL 证书错误和认证失败等情况提供特定的重启方法。

6. **代理处理:**
   - 处理通过 HTTP 代理建立连接的情况 (`proxy_info_`)。
   - 在建立隧道时处理代理认证。

7. **Early Hints 支持:**
   - 检查当前协议是否支持 Early Hints (`EarlyHintsAreAllowedOn`)。

8. **WebSocket Fallback 统计:**
   - 记录 WebSocket 握手失败后回退到 HTTP/1.1 的结果 (`RecordWebSocketFallbackResult`)。

9. **性能监控和日志:**
   - 记录网络事件到 NetLog (`net_log_`)，用于调试和分析。
   - 获取和报告加载时间信息 (`GetLoadTimingInfo`)。
   - 使用 UMA 记录各种指标，例如 WebSocket 回退结果。

10. **请求优先级:**
    - 支持设置请求优先级 (`SetPriority`)，并将其传递给底层的 `HttpStream`。

11. **拦截和回调:**
    - 提供各种回调接口，允许外部观察和修改请求过程，例如 `BeforeNetworkStartCallback`, `ConnectedCallback`, `RequestHeadersCallback`, `ResponseHeadersCallback`, `ModifyRequestHeadersCallback`。

**与 JavaScript 的关系举例:**

虽然 `HttpNetworkTransaction` 是 C++ 代码，但它是浏览器网络栈的核心部分，直接服务于 JavaScript 发起的网络请求。

* **`fetch()` API 和 `XMLHttpRequest`:** 当 JavaScript 代码中使用 `fetch()` 或 `XMLHttpRequest` 发起一个 HTTP 请求时，浏览器底层会创建一个 `HttpNetworkTransaction` 对象来处理这个请求。
* **请求头和负载:** JavaScript 代码中设置的请求头 (例如 `headers` 选项在 `fetch()` 中) 和请求体 (例如 `body` 选项) 会被传递到 `HttpNetworkTransaction` 对象中，用于构建实际的网络请求。
* **响应数据:**  `HttpNetworkTransaction` 接收到的响应头和 body 数据最终会传递回 JavaScript，供 `fetch()` 的 Promise 解析或 `XMLHttpRequest` 的回调函数处理。
* **跨域请求 (CORS):**  `HttpNetworkTransaction` 也会处理与 CORS 相关的逻辑，例如检查 `Origin` 头和 `Access-Control-Allow-Origin` 头。
* **Service Workers:** 当 Service Worker 拦截到一个 `fetch` 请求时，它可以自定义如何处理该请求，这可能涉及到创建一个新的 `HttpNetworkTransaction` 或重用现有的连接。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. 用户在浏览器地址栏输入 `https://example.com`.
2. 该域名之前没有被访问过，没有缓存的连接。
3. 服务器 `example.com` 需要客户端提供证书进行认证。

**逻辑推理与输出:**

1. **`Start()` 被调用:**  创建一个 `HttpNetworkTransaction` 对象，`next_state_` 被设置为 `STATE_NOTIFY_BEFORE_CREATE_STREAM`。
2. **`DoLoop()` 进入 `STATE_CREATE_STREAM`:**  尝试创建一个到 `example.com` 的 HTTPS 连接。由于是 HTTPS 且之前没有连接，需要进行 TLS 握手。
3. **TLS 握手过程中:** 服务器发送 `CertificateRequest`，要求客户端提供证书。
4. **`OnNeedsClientAuth()` 被调用:**  `next_state_` 保持在 `STATE_CREATE_STREAM_COMPLETE`，并将 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 传递给回调函数。
5. **假设用户选择了证书并提供了:** 调用 `RestartWithCertificate()`，传入用户选择的证书和私钥。
6. **`RestartWithCertificate()`:**  将证书信息添加到 SSL 客户端上下文缓存，`next_state_` 被设置为 `STATE_CREATE_STREAM`。
7. **`DoLoop()` 再次进入 `STATE_CREATE_STREAM`:** 重新尝试创建连接，这次 TLS 握手会包含客户端提供的证书。
8. **如果证书验证成功:**  `OnStreamReady()` 被调用，`next_state_` 变为 `STATE_INIT_STREAM`，开始发送请求。

**用户或编程常见的使用错误举例:**

1. **未正确处理认证质询:**  如果服务器或代理返回 401 或 407 状态码，而代码没有调用 `RestartWithAuth()` 提供正确的用户名和密码，请求将失败。
   ```c++
   // 错误示例: 收到认证质询后直接放弃请求
   void HttpNetworkTransaction::OnNeedsProxyAuth(...) {
       DoCallback(ERR_PROXY_AUTH_UNSUPPORTED);
   }
   ```

2. **在不恰当的时机设置回调:**  例如，在 `Start()` 调用后，并且在 `DoLoop()` 运行到需要该回调的状态之前，修改某些回调可能会导致意外行为或崩溃。`DCHECK(!stream_);` 这样的断言就是为了防止这种情况。

3. **错误地处理重定向:** 虽然 `HttpNetworkTransaction` 本身不直接处理重定向，但其使用者 (例如 `HttpCache`) 需要根据响应码和 `Location` 头来决定是否需要发起新的请求。如果处理不当，可能会导致重定向循环。

4. **取消请求后未清理资源:**  如果在请求进行中途取消，但没有正确释放 `IOBuffer` 或关闭 `HttpStream`，可能会导致内存泄漏或其他资源问题。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在 Chrome 浏览器中访问一个需要客户端证书认证的 HTTPS 网站：

1. **用户在地址栏输入 URL 并回车:** 浏览器 UI 进程接收到请求。
2. **UI 进程通知 Render 进程:** 如果是新的标签页或导航，UI 进程会通知相应的渲染进程。
3. **Render 进程发起网络请求:**  渲染进程中的 JavaScript 代码 (或者浏览器内部逻辑) 会创建一个网络请求。
4. **请求传递到网络进程:** 渲染进程通过 IPC 将网络请求发送到网络进程。
5. **网络进程创建 `HttpNetworkTransaction`:** 网络进程接收到请求后，会创建一个 `HttpNetworkTransaction` 对象来处理该 HTTPS 请求。
6. **`Start()` 方法被调用:**  开始执行请求的生命周期。
7. **连接建立:** `DoLoop()` 进入 `STATE_CREATE_STREAM`，尝试建立到服务器的 TCP 连接和 TLS 连接。
8. **服务器请求客户端证书:** 在 TLS 握手过程中，服务器发送 `CertificateRequest` 消息。
9. **`OnNeedsClientAuth()` 被调用:**  `HttpNetworkTransaction` 接收到服务器的请求，并调用 `OnNeedsClientAuth()` 方法。此时，调试器可能会停在这个函数内部。
10. **浏览器显示证书选择对话框:** Chrome 会弹出对话框，让用户选择要使用的客户端证书。

**本部分功能归纳:**

代码的第一部分主要负责 `HttpNetworkTransaction` 对象的初始化和启动，以及处理连接建立过程中的一些初始状态。  它涵盖了：

* **类的基本结构和成员变量的定义。**
* **`Start()` 方法的实现，用于初始化请求并启动状态机。**
* **各种 `Restart...()` 方法的实现，用于在出现错误或需要认证时重新启动请求。**
* **处理客户端证书认证的逻辑 (`RestartWithCertificate`, `OnNeedsClientAuth`)。**
* **一些辅助函数，例如 `EarlyHintsAreAllowedOn` 和 `RecordWebSocketFallbackResult`。**

总而言之，这部分代码是 `HttpNetworkTransaction` 的起点，负责接收请求信息，建立网络连接，并处理一些早期的认证流程。后续的代码将处理请求的发送、响应的接收和数据的读取。

Prompt: 
```
这是目录为net/http/http_network_transaction.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_network_transaction.h"

#include <set>
#include <utility>
#include <vector>

#include "base/base64url.h"
#include "base/compiler_specific.h"
#include "base/feature_list.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/notreached.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/auth.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_errors.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/transport_info.h"
#include "net/base/upload_data_stream.h"
#include "net/base/url_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/filter/filter_source_stream.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/http/http_auth.h"
#include "net/http/http_auth_controller.h"
#include "net/http/http_auth_handler.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_basic_stream.h"
#include "net/http/http_chunked_decoder.h"
#include "net/http/http_connection_info.h"
#include "net/http/http_log_util.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_status_code.h"
#include "net/http/http_stream.h"
#include "net/http/http_stream_factory.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_util.h"
#include "net/http/transport_security_state.h"
#include "net/http/url_security_manager.h"
#include "net/log/net_log_event_type.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/next_proto.h"
#include "net/socket/transport_client_socket_pool.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_private_key.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/scheme_host_port.h"
#include "url/url_canon.h"

#if BUILDFLAG(ENABLE_REPORTING)
#include "net/network_error_logging/network_error_logging_service.h"
#include "net/reporting/reporting_header_parser.h"
#include "net/reporting/reporting_service.h"
#endif  // BUILDFLAG(ENABLE_REPORTING)

namespace net {

namespace {

// Max number of |retry_attempts| (excluding the initial request) after which
// we give up and show an error page.
const size_t kMaxRetryAttempts = 2;

// Max number of calls to RestartWith* allowed for a single connection. A single
// HttpNetworkTransaction should not signal very many restartable errors, but it
// may occur due to a bug (e.g. https://crbug.com/823387 or
// https://crbug.com/488043) or simply if the server or proxy requests
// authentication repeatedly. Although these calls are often associated with a
// user prompt, in other scenarios (remembered preferences, extensions,
// multi-leg authentication), they may be triggered automatically. To avoid
// looping forever, bound the number of restarts.
const size_t kMaxRestarts = 32;

// Returns true when Early Hints are allowed on the given protocol.
bool EarlyHintsAreAllowedOn(HttpConnectionInfo connection_info) {
  switch (connection_info) {
    case HttpConnectionInfo::kHTTP0_9:
    case HttpConnectionInfo::kHTTP1_0:
      return false;
    case HttpConnectionInfo::kHTTP1_1:
      return base::FeatureList::IsEnabled(features::kEnableEarlyHintsOnHttp11);
    default:
      // Implicitly allow HttpConnectionInfo::kUNKNOWN because this is the
      // default value and ConnectionInfo isn't always set.
      return true;
  }
}

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class WebSocketFallbackResult {
  kSuccessHttp11 = 0,
  kSuccessHttp2,
  kSuccessHttp11AfterFallback,
  kFailure,
  kFailureAfterFallback,
  kMaxValue = kFailureAfterFallback,
};

WebSocketFallbackResult CalculateWebSocketFallbackResult(
    int result,
    bool http_1_1_was_required,
    HttpConnectionInfoCoarse connection_info) {
  if (result == OK) {
    if (connection_info == HttpConnectionInfoCoarse::kHTTP2) {
      return WebSocketFallbackResult::kSuccessHttp2;
    }
    return http_1_1_was_required
               ? WebSocketFallbackResult::kSuccessHttp11AfterFallback
               : WebSocketFallbackResult::kSuccessHttp11;
  }

  return http_1_1_was_required ? WebSocketFallbackResult::kFailureAfterFallback
                               : WebSocketFallbackResult::kFailure;
}

void RecordWebSocketFallbackResult(int result,
                                   bool http_1_1_was_required,
                                   HttpConnectionInfoCoarse connection_info) {
  CHECK_NE(connection_info, HttpConnectionInfoCoarse::kQUIC);

  // `connection_info` could be kOTHER in tests.
  if (connection_info == HttpConnectionInfoCoarse::kOTHER) {
    return;
  }

  base::UmaHistogramEnumeration(
      "Net.WebSocket.FallbackResult",
      CalculateWebSocketFallbackResult(result, http_1_1_was_required,
                                       connection_info));
}

const std::string_view NegotiatedProtocolToHistogramSuffix(
    const HttpResponseInfo& response) {
  NextProto next_proto = NextProtoFromString(response.alpn_negotiated_protocol);
  switch (next_proto) {
    case kProtoHTTP11:
      return "H1";
    case kProtoHTTP2:
      return "H2";
    case kProtoQUIC:
      return "H3";
    case kProtoUnknown:
      return "Unknown";
  }
}

}  // namespace

const int HttpNetworkTransaction::kDrainBodyBufferSize;

HttpNetworkTransaction::HttpNetworkTransaction(RequestPriority priority,
                                               HttpNetworkSession* session)
    : io_callback_(base::BindRepeating(&HttpNetworkTransaction::OnIOComplete,
                                       base::Unretained(this))),
      session_(session),
      priority_(priority) {}

HttpNetworkTransaction::~HttpNetworkTransaction() {
#if BUILDFLAG(ENABLE_REPORTING)
  // If no error or success report has been generated yet at this point, then
  // this network transaction was prematurely cancelled.
  GenerateNetworkErrorLoggingReport(ERR_ABORTED);
#endif  // BUILDFLAG(ENABLE_REPORTING)

  if (stream_.get()) {
    // TODO(mbelshe): The stream_ should be able to compute whether or not the
    //                stream should be kept alive.  No reason to compute here
    //                and pass it in.
    if (!stream_->CanReuseConnection() || next_state_ != STATE_NONE ||
        close_connection_on_destruction_) {
      stream_->Close(true /* not reusable */);
    } else if (stream_->IsResponseBodyComplete()) {
      // If the response body is complete, we can just reuse the socket.
      stream_->Close(false /* reusable */);
    } else {
      // Otherwise, we try to drain the response body.
      HttpStream* stream = stream_.release();
      stream->Drain(session_);
    }
  }
  if (request_ && request_->upload_data_stream)
    request_->upload_data_stream->Reset();  // Invalidate pending callbacks.
}

int HttpNetworkTransaction::Start(const HttpRequestInfo* request_info,
                                  CompletionOnceCallback callback,
                                  const NetLogWithSource& net_log) {
  if (request_info->load_flags & LOAD_ONLY_FROM_CACHE)
    return ERR_CACHE_MISS;

  DCHECK(request_info->traffic_annotation.is_valid());
  DCHECK(request_info->IsConsistent());
  net_log_ = net_log;
  request_ = request_info;
  url_ = request_->url;
  network_anonymization_key_ = request_->network_anonymization_key;
#if BUILDFLAG(ENABLE_REPORTING)
  // Store values for later use in NEL report generation.
  request_method_ = request_->method;
  if (std::optional<std::string> header =
          request_->extra_headers.GetHeader(HttpRequestHeaders::kReferer);
      header) {
    request_referrer_.swap(header.value());
  }
  if (std::optional<std::string> header =
          request_->extra_headers.GetHeader(HttpRequestHeaders::kUserAgent);
      header) {
    request_user_agent_.swap(header.value());
  }
  request_reporting_upload_depth_ = request_->reporting_upload_depth;
  start_timeticks_ = base::TimeTicks::Now();
#endif  // BUILDFLAG(ENABLE_REPORTING)

  if (request_->idempotency == IDEMPOTENT ||
      (request_->idempotency == DEFAULT_IDEMPOTENCY &&
       HttpUtil::IsMethodSafe(request_info->method))) {
    can_send_early_data_ = true;
  }

  if (request_->load_flags & LOAD_PREFETCH) {
    response_.unused_since_prefetch = true;
  }

  if (request_->load_flags & LOAD_RESTRICTED_PREFETCH_FOR_MAIN_FRAME) {
    DCHECK(response_.unused_since_prefetch);
    response_.restricted_prefetch = true;
  }

  next_state_ = STATE_NOTIFY_BEFORE_CREATE_STREAM;
  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING)
    callback_ = std::move(callback);

  // This always returns ERR_IO_PENDING because DoCreateStream() does, but
  // GenerateNetworkErrorLoggingReportIfError() should be called here if any
  // other Error can be returned.
  DCHECK_EQ(rv, ERR_IO_PENDING);
  return rv;
}

int HttpNetworkTransaction::RestartIgnoringLastError(
    CompletionOnceCallback callback) {
  DCHECK(!stream_.get());
  DCHECK(!stream_request_.get());
  DCHECK_EQ(STATE_NONE, next_state_);

  if (!CheckMaxRestarts())
    return ERR_TOO_MANY_RETRIES;

  next_state_ = STATE_CREATE_STREAM;

  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING)
    callback_ = std::move(callback);

  // This always returns ERR_IO_PENDING because DoCreateStream() does, but
  // GenerateNetworkErrorLoggingReportIfError() should be called here if any
  // other Error can be returned.
  DCHECK_EQ(rv, ERR_IO_PENDING);
  return rv;
}

int HttpNetworkTransaction::RestartWithCertificate(
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> client_private_key,
    CompletionOnceCallback callback) {
  // When we receive ERR_SSL_CLIENT_AUTH_CERT_NEEDED, we always tear down
  // existing streams and stream requests to force a new connection.
  DCHECK(!stream_request_.get());
  DCHECK(!stream_.get());
  DCHECK_EQ(STATE_NONE, next_state_);

  if (!CheckMaxRestarts())
    return ERR_TOO_MANY_RETRIES;

  // Add the credentials to the client auth cache. The next stream request will
  // then pick them up.
  session_->ssl_client_context()->SetClientCertificate(
      response_.cert_request_info->host_and_port, std::move(client_cert),
      std::move(client_private_key));

  if (!response_.cert_request_info->is_proxy)
    configured_client_cert_for_server_ = true;

  // Reset the other member variables.
  // Note: this is necessary only with SSL renegotiation.
  ResetStateForRestart();
  next_state_ = STATE_CREATE_STREAM;
  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING)
    callback_ = std::move(callback);

  // This always returns ERR_IO_PENDING because DoCreateStream() does, but
  // GenerateNetworkErrorLoggingReportIfError() should be called here if any
  // other Error can be returned.
  DCHECK_EQ(rv, ERR_IO_PENDING);
  return rv;
}

int HttpNetworkTransaction::RestartWithAuth(const AuthCredentials& credentials,
                                            CompletionOnceCallback callback) {
  if (!CheckMaxRestarts())
    return ERR_TOO_MANY_RETRIES;

  HttpAuth::Target target = pending_auth_target_;
  if (target == HttpAuth::AUTH_NONE) {
    NOTREACHED();
  }
  pending_auth_target_ = HttpAuth::AUTH_NONE;

  auth_controllers_[target]->ResetAuth(credentials);

  DCHECK(callback_.is_null());

  int rv = OK;
  if (target == HttpAuth::AUTH_PROXY && establishing_tunnel_) {
    // In this case, we've gathered credentials for use with proxy
    // authentication of a tunnel.
    DCHECK_EQ(STATE_CREATE_STREAM_COMPLETE, next_state_);
    DCHECK(stream_request_ != nullptr);
    auth_controllers_[target] = nullptr;
    ResetStateForRestart();
    rv = stream_request_->RestartTunnelWithProxyAuth();
  } else {
    // In this case, we've gathered credentials for the server or the proxy
    // but it is not during the tunneling phase.
    DCHECK(stream_request_ == nullptr);
    PrepareForAuthRestart(target);
    rv = DoLoop(OK);
    // Note: If an error is encountered while draining the old response body, no
    // Network Error Logging report will be generated, because the error was
    // with the old request, which will already have had a NEL report generated
    // for it due to the auth challenge (so we don't report a second error for
    // that request).
  }

  if (rv == ERR_IO_PENDING)
    callback_ = std::move(callback);
  return rv;
}

void HttpNetworkTransaction::PrepareForAuthRestart(HttpAuth::Target target) {
  DCHECK(HaveAuth(target));
  DCHECK(!stream_request_.get());

  // Authorization schemes incompatible with HTTP/2 are unsupported for proxies.
  if (target == HttpAuth::AUTH_SERVER &&
      auth_controllers_[target]->NeedsHTTP11()) {
    // SetHTTP11Requited requires URLs be rewritten first, if there are any
    // applicable rules.
    GURL rewritten_url = request_->url;
    session_->params().host_mapping_rules.RewriteUrl(rewritten_url);

    session_->http_server_properties()->SetHTTP11Required(
        url::SchemeHostPort(rewritten_url), network_anonymization_key_);
  }

  bool keep_alive = false;
  // Even if the server says the connection is keep-alive, we have to be
  // able to find the end of each response in order to reuse the connection.
  if (stream_->CanReuseConnection()) {
    // If the response body hasn't been completely read, we need to drain
    // it first.
    if (!stream_->IsResponseBodyComplete()) {
      next_state_ = STATE_DRAIN_BODY_FOR_AUTH_RESTART;
      read_buf_ = base::MakeRefCounted<IOBufferWithSize>(
          kDrainBodyBufferSize);  // A bit bucket.
      read_buf_len_ = kDrainBodyBufferSize;
      return;
    }
    keep_alive = true;
  }

  // We don't need to drain the response body, so we act as if we had drained
  // the response body.
  DidDrainBodyForAuthRestart(keep_alive);
}

void HttpNetworkTransaction::DidDrainBodyForAuthRestart(bool keep_alive) {
  DCHECK(!stream_request_.get());

  if (stream_.get()) {
    total_received_bytes_ += stream_->GetTotalReceivedBytes();
    total_sent_bytes_ += stream_->GetTotalSentBytes();
    std::unique_ptr<HttpStream> new_stream;
    if (keep_alive && stream_->CanReuseConnection()) {
      // We should call connection_->set_idle_time(), but this doesn't occur
      // often enough to be worth the trouble.
      stream_->SetConnectionReused();
      new_stream = stream_->RenewStreamForAuth();
    }

    if (!new_stream) {
      // Close the stream and mark it as not_reusable.  Even in the
      // keep_alive case, we've determined that the stream_ is not
      // reusable if new_stream is NULL.
      stream_->Close(true);
      next_state_ = STATE_CREATE_STREAM;
    } else {
      // Renewed streams shouldn't carry over sent or received bytes.
      DCHECK_EQ(0, new_stream->GetTotalReceivedBytes());
      DCHECK_EQ(0, new_stream->GetTotalSentBytes());
      next_state_ = STATE_CONNECTED_CALLBACK;
    }
    stream_ = std::move(new_stream);
  }

  // Reset the other member variables.
  ResetStateForAuthRestart();
}

bool HttpNetworkTransaction::IsReadyToRestartForAuth() {
  return pending_auth_target_ != HttpAuth::AUTH_NONE &&
      HaveAuth(pending_auth_target_);
}

int HttpNetworkTransaction::Read(IOBuffer* buf,
                                 int buf_len,
                                 CompletionOnceCallback callback) {
  DCHECK(buf);
  DCHECK_LT(0, buf_len);

  scoped_refptr<HttpResponseHeaders> headers(GetResponseHeaders());
  if (headers_valid_ && headers.get() && stream_request_.get()) {
    // We're trying to read the body of the response but we're still trying
    // to establish an SSL tunnel through an HTTP proxy.  We can't read these
    // bytes when establishing a tunnel because they might be controlled by
    // an active network attacker.  We don't worry about this for HTTP
    // because an active network attacker can already control HTTP sessions.
    // We reach this case when the user cancels a 407 proxy auth prompt.  We
    // also don't worry about this for an HTTPS Proxy, because the
    // communication with the proxy is secure.
    // See http://crbug.com/8473.
    DCHECK(proxy_info_.AnyProxyInChain(
        [](const ProxyServer& s) { return s.is_http_like(); }));
    DCHECK_EQ(headers->response_code(), HTTP_PROXY_AUTHENTICATION_REQUIRED);
    return ERR_TUNNEL_CONNECTION_FAILED;
  }

  // Are we using SPDY or HTTP?
  next_state_ = STATE_READ_BODY;

  read_buf_ = buf;
  read_buf_len_ = buf_len;

  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING)
    callback_ = std::move(callback);
  return rv;
}

void HttpNetworkTransaction::StopCaching() {}

int64_t HttpNetworkTransaction::GetTotalReceivedBytes() const {
  int64_t total_received_bytes = total_received_bytes_;
  if (stream_)
    total_received_bytes += stream_->GetTotalReceivedBytes();
  return total_received_bytes;
}

int64_t HttpNetworkTransaction::GetTotalSentBytes() const {
  int64_t total_sent_bytes = total_sent_bytes_;
  if (stream_)
    total_sent_bytes += stream_->GetTotalSentBytes();
  return total_sent_bytes;
}

int64_t HttpNetworkTransaction::GetReceivedBodyBytes() const {
  return received_body_bytes_;
}

void HttpNetworkTransaction::DoneReading() {}

const HttpResponseInfo* HttpNetworkTransaction::GetResponseInfo() const {
  return &response_;
}

LoadState HttpNetworkTransaction::GetLoadState() const {
  // TODO(wtc): Define a new LoadState value for the
  // STATE_INIT_CONNECTION_COMPLETE state, which delays the HTTP request.
  switch (next_state_) {
    case STATE_CREATE_STREAM:
      return LOAD_STATE_WAITING_FOR_DELEGATE;
    case STATE_CREATE_STREAM_COMPLETE:
      return stream_request_->GetLoadState();
    case STATE_GENERATE_PROXY_AUTH_TOKEN_COMPLETE:
    case STATE_GENERATE_SERVER_AUTH_TOKEN_COMPLETE:
    case STATE_SEND_REQUEST_COMPLETE:
      return LOAD_STATE_SENDING_REQUEST;
    case STATE_READ_HEADERS_COMPLETE:
      return LOAD_STATE_WAITING_FOR_RESPONSE;
    case STATE_READ_BODY_COMPLETE:
      return LOAD_STATE_READING_RESPONSE;
    default:
      return LOAD_STATE_IDLE;
  }
}

void HttpNetworkTransaction::SetQuicServerInfo(
    QuicServerInfo* quic_server_info) {}

bool HttpNetworkTransaction::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  if (!stream_ || !stream_->GetLoadTimingInfo(load_timing_info))
    return false;

  // If `dns_resolution_{start/end}_time_override_` are set, and they are older
  // than `domain_lookup_{start/end}` of the `stream_`, use the overrides.
  // TODO(crbug.com/40812426): Remove this when we launch Happy Eyeballs v3.
  if (!dns_resolution_start_time_override_.is_null() &&
      !dns_resolution_end_time_override_.is_null() &&
      (dns_resolution_start_time_override_ <
       load_timing_info->connect_timing.domain_lookup_start) &&
      (dns_resolution_end_time_override_ <
       load_timing_info->connect_timing.domain_lookup_end)) {
    load_timing_info->connect_timing.domain_lookup_start =
        dns_resolution_start_time_override_;
    load_timing_info->connect_timing.domain_lookup_end =
        dns_resolution_end_time_override_;
  }

  load_timing_info->proxy_resolve_start =
      proxy_info_.proxy_resolve_start_time();
  load_timing_info->proxy_resolve_end = proxy_info_.proxy_resolve_end_time();
  load_timing_info->send_start = send_start_time_;
  load_timing_info->send_end = send_end_time_;
  return true;
}

bool HttpNetworkTransaction::GetRemoteEndpoint(IPEndPoint* endpoint) const {
  if (remote_endpoint_.address().empty())
    return false;

  *endpoint = remote_endpoint_;
  return true;
}

void HttpNetworkTransaction::PopulateNetErrorDetails(
    NetErrorDetails* details) const {
  *details = net_error_details_;
  if (stream_)
    stream_->PopulateNetErrorDetails(details);
}

void HttpNetworkTransaction::SetPriority(RequestPriority priority) {
  priority_ = priority;

  if (stream_request_)
    stream_request_->SetPriority(priority);
  if (stream_)
    stream_->SetPriority(priority);

  // The above call may have resulted in deleting |*this|.
}

void HttpNetworkTransaction::SetWebSocketHandshakeStreamCreateHelper(
    WebSocketHandshakeStreamBase::CreateHelper* create_helper) {
  websocket_handshake_stream_base_create_helper_ = create_helper;
}

void HttpNetworkTransaction::SetBeforeNetworkStartCallback(
    BeforeNetworkStartCallback callback) {
  before_network_start_callback_ = std::move(callback);
}

void HttpNetworkTransaction::SetConnectedCallback(
    const ConnectedCallback& callback) {
  connected_callback_ = callback;
}

void HttpNetworkTransaction::SetRequestHeadersCallback(
    RequestHeadersCallback callback) {
  DCHECK(!stream_);
  request_headers_callback_ = std::move(callback);
}

void HttpNetworkTransaction::SetEarlyResponseHeadersCallback(
    ResponseHeadersCallback callback) {
  DCHECK(!stream_);
  early_response_headers_callback_ = std::move(callback);
}

void HttpNetworkTransaction::SetResponseHeadersCallback(
    ResponseHeadersCallback callback) {
  DCHECK(!stream_);
  response_headers_callback_ = std::move(callback);
}

void HttpNetworkTransaction::SetModifyRequestHeadersCallback(
    base::RepeatingCallback<void(HttpRequestHeaders*)> callback) {
  modify_headers_callbacks_ = std::move(callback);
}

void HttpNetworkTransaction::SetIsSharedDictionaryReadAllowedCallback(
    base::RepeatingCallback<bool()> callback) {
  // This method should not be called for this class.
  NOTREACHED();
}

int HttpNetworkTransaction::ResumeNetworkStart() {
  DCHECK_EQ(next_state_, STATE_CREATE_STREAM);
  return DoLoop(OK);
}

void HttpNetworkTransaction::ResumeAfterConnected(int result) {
  DCHECK_EQ(next_state_, STATE_CONNECTED_CALLBACK_COMPLETE);
  OnIOComplete(result);
}

void HttpNetworkTransaction::CloseConnectionOnDestruction() {
  close_connection_on_destruction_ = true;
}

bool HttpNetworkTransaction::IsMdlMatchForMetrics() const {
  return proxy_info_.is_mdl_match();
}

void HttpNetworkTransaction::OnStreamReady(const ProxyInfo& used_proxy_info,
                                           std::unique_ptr<HttpStream> stream) {
  DCHECK_EQ(STATE_CREATE_STREAM_COMPLETE, next_state_);
  DCHECK(stream_request_.get());

  if (stream_) {
    total_received_bytes_ += stream_->GetTotalReceivedBytes();
    total_sent_bytes_ += stream_->GetTotalSentBytes();
  }
  stream_ = std::move(stream);
  stream_->SetRequestHeadersCallback(request_headers_callback_);
  proxy_info_ = used_proxy_info;
  // TODO(crbug.com/40473589): Remove `was_alpn_negotiated` when we remove
  // chrome.loadTimes API.
  response_.was_alpn_negotiated =
      stream_request_->negotiated_protocol() != kProtoUnknown;
  response_.alpn_negotiated_protocol =
      NextProtoToString(stream_request_->negotiated_protocol());
  response_.alternate_protocol_usage =
      stream_request_->alternate_protocol_usage();
  // TODO(crbug.com/40815866): Stop using `was_fetched_via_spdy`.
  response_.was_fetched_via_spdy =
      stream_request_->negotiated_protocol() == kProtoHTTP2;
  response_.dns_aliases = stream_->GetDnsAliases();

  dns_resolution_start_time_override_ =
      stream_request_->dns_resolution_start_time_override();
  dns_resolution_end_time_override_ =
      stream_request_->dns_resolution_end_time_override();

  SetProxyInfoInResponse(used_proxy_info, &response_);
  OnIOComplete(OK);
}

void HttpNetworkTransaction::OnBidirectionalStreamImplReady(
    const ProxyInfo& used_proxy_info,
    std::unique_ptr<BidirectionalStreamImpl> stream) {
  NOTREACHED();
}

void HttpNetworkTransaction::OnWebSocketHandshakeStreamReady(
    const ProxyInfo& used_proxy_info,
    std::unique_ptr<WebSocketHandshakeStreamBase> stream) {
  OnStreamReady(used_proxy_info, std::move(stream));
}

void HttpNetworkTransaction::OnStreamFailed(
    int result,
    const NetErrorDetails& net_error_details,
    const ProxyInfo& used_proxy_info,
    ResolveErrorInfo resolve_error_info) {
  DCHECK_EQ(STATE_CREATE_STREAM_COMPLETE, next_state_);
  DCHECK_NE(OK, result);
  DCHECK(stream_request_.get());
  DCHECK(!stream_.get());
  net_error_details_ = net_error_details;
  proxy_info_ = used_proxy_info;
  SetProxyInfoInResponse(used_proxy_info, &response_);
  response_.resolve_error_info = resolve_error_info;

  OnIOComplete(result);
}

void HttpNetworkTransaction::OnCertificateError(int result,
                                                const SSLInfo& ssl_info) {
  DCHECK_EQ(STATE_CREATE_STREAM_COMPLETE, next_state_);
  DCHECK_NE(OK, result);
  DCHECK(stream_request_.get());
  DCHECK(!stream_.get());

  response_.ssl_info = ssl_info;
  if (ssl_info.cert) {
    observed_bad_certs_.emplace_back(ssl_info.cert, ssl_info.cert_status);
  }

  // TODO(mbelshe):  For now, we're going to pass the error through, and that
  // will close the stream_request in all cases.  This means that we're always
  // going to restart an entire STATE_CREATE_STREAM, even if the connection is
  // good and the user chooses to ignore the error.  This is not ideal, but not
  // the end of the world either.

  OnIOComplete(result);
}

void HttpNetworkTransaction::OnNeedsProxyAuth(
    const HttpResponseInfo& proxy_response,
    const ProxyInfo& used_proxy_info,
    HttpAuthController* auth_controller) {
  DCHECK(stream_request_.get());
  DCHECK_EQ(STATE_CREATE_STREAM_COMPLETE, next_state_);

  establishing_tunnel_ = true;
  response_.headers = proxy_response.headers;
  response_.auth_challenge = proxy_response.auth_challenge;
  response_.did_use_http_auth = proxy_response.did_use_http_auth;
  SetProxyInfoInResponse(used_proxy_info, &response_);

  if (!ContentEncodingsValid()) {
    DoCallback(ERR_CONTENT_DECODING_FAILED);
    return;
  }

  headers_valid_ = true;
  proxy_info_ = used_proxy_info;

  auth_controllers_[HttpAuth::AUTH_PROXY] = auth_controller;
  pending_auth_target_ = HttpAuth::AUTH_PROXY;

  DoCallback(OK);
}

void HttpNetworkTransaction::OnNeedsClientAuth(SSLCertRequestInfo* cert_info) {
  DCHECK_EQ(STATE_CREATE_STREAM_COMPLETE, next_state_);

  response_.cert_request_info = cert_info;
  OnIOComplete(ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
}

void HttpNetworkTransaction::OnQuicBroken() {
  net_error_details_.quic_broken = true;
}

void HttpNetworkTransaction::OnSwitchesToHttpStreamPool(
    HttpStreamPoolRequestInfo request_info) {
  CHECK_EQ(STATE_CREATE_STREAM_COMPLETE, next_state_);
  CHECK(stream_request_);
  stream_request_.reset();

  stream_request_ = session_->http_stream_pool()->RequestStream(
      this, std::move(request_info), priority_,
      /*allowed_bad_certs=*/observed_bad_certs_, enable_ip_based_pooling_,
      enable_alternative_services_, net_log_);
  CHECK(!stream_request_->completed());
  // No IO completion yet.
}

ConnectionAttempts HttpNetworkTransaction::GetConnectionAttempts() const {
  return connection_attempts_;
}

bool HttpNetworkTransaction::IsSecureRequest() const {
  return request_->url.SchemeIsCryptographic();
}

bool HttpNetworkTransaction::UsingHttpProxyWithoutTunnel() const {
  return proxy_info_.proxy_chain().is_get_to_proxy_allowed() &&
         request_->url.SchemeIs("http");
}

void HttpNetworkTransaction::DoCallback(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  DCHECK(!callback_.is_null());

#if BUILDFLAG(ENABLE_REPORTING)
  // Just before invoking the caller's completion callback, generate a NEL
  // report about this network request if the result was an error.
  GenerateNetworkErrorLoggingReportIfError(rv);
#endif  // BUILDFLAG(ENABLE_REPORTING)

  // Since Run may result in Read being called, clear user_callback_ up front.
  std::move(callback_).Run(rv);
}

void HttpNetworkTransaction::OnIOComplete(int result) {
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING)
    DoCallback(rv);
}

int HttpNetworkTransaction::DoLoop(int result) {
  DCHECK(next_state_ != STATE_NONE);

  int rv = result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_NOTIFY_BEFORE_CREATE_STREAM:
        DCHECK_EQ(OK, rv);
        rv = DoNotifyBeforeCreateStream();
        break;
      case STATE_CREATE_STREAM:
        DCHECK_EQ(OK, rv);
        rv = DoCreateStream();
        break;
      case STATE_CREATE_STREAM_COMPLETE:
        rv = DoCreateStreamComplete(rv);
        break;
      case STATE_INIT_STREAM:
        DCHECK_EQ(OK, rv);
        rv = DoInitStream();
        break;
      case STATE_INIT_STREAM_COMPLETE:
        rv = DoInitStreamComplete(rv);
        break;
      case STATE_CONNECTED_CALLBACK:
        rv = DoConnectedCallback();
        break;
      case STATE_CONNECTED_CALLBACK_COMPLETE:
        rv = DoConnectedCallbackComplete(rv);
        break;
      case STATE_GENERATE_PROXY_AUTH_TOKEN:
        DCHECK_EQ(OK, rv);
        rv = DoGenerateProxyAuthToken();
        break;
      case STATE_GENERATE_PROXY_AUTH_TOKEN_COMPLETE:
        rv = DoGenerateProxyAuthTokenComplete(rv);
        break;
      case STATE_GENERATE_SERVER_AUTH_TOKEN:
        DCHECK_EQ(OK, rv);
        rv = DoGenerateServerAuthToken();
        break;
      case STATE_GENERATE_SERVER_AUTH_TOKEN_COMPLETE:
        rv = DoGenerateServerAuthTokenComplete(rv);
        break;
      case STATE_INIT_REQUEST_BODY:
        DCHECK_EQ(OK, rv);
        rv = DoInitRequestBody();
        break;
      case STATE_INIT_REQUEST_BODY_COMPLETE:
        rv = DoInitRequestBodyComplete(rv);
        break;
      case STATE_BUILD_REQUEST:
        DCHECK_EQ(OK, rv);
        net_log_.BeginEvent(NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST);
        rv = DoBuildRequest();
        break;
      case STATE_BUILD_REQUEST_COMPLETE:
        rv = DoBuildRequestComplete(rv);
        break;
      case STATE_SEND_REQUEST:
        DCHECK_EQ(OK, rv);
        rv = DoSendRequest();
        break;
      case STATE_SEND_REQUEST_COMPLETE:
        rv = DoSendRequestComplete(rv);
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST, rv);
        break;
      case STATE_READ_HEADERS:
        DCHECK_EQ(OK, rv);
        net_log_.BeginEvent(NetLogEventType::HTTP_TRANSACTION_READ_HEADERS);
        rv = DoReadHeaders();
        break;
      case STATE_READ_HEADERS_COMPLETE:
        rv = DoReadHeadersComplete(rv);
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::HTTP_TRANSACTION_READ_HEADERS, rv);
        break;
      case STATE_READ_BODY:
        DCHECK_EQ(OK, rv);
        net_log_.BeginEvent(NetLogEventType::HTTP_TRANSACTION_READ_BODY);
        rv = DoReadBody();
        break;
      case STATE_READ_BODY_COMPLETE:
        rv = DoReadBodyComplete(rv);
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::HTTP_TRANSACTION_READ_BODY, rv);
        break;
      case STATE_DRAIN_BODY_FOR_AUTH_RESTART:
        DCHECK_EQ(OK, rv);
        net_log_.BeginEvent(
            NetLogEventType::HTTP_TRANSACTION_DRAIN_BODY_FOR_AUTH_RESTART);
        rv = DoDrainBodyForAuthRestart();
        break;
      case STATE_DRAIN_BODY_FOR_AUTH_RESTART_COMPLETE:
        rv = DoDrainBodyForAuthRestartComplete(rv);
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::HTTP_TRANSACTION_DRAIN_BODY_FOR_AUTH_RESTART, rv);
        break;
      default:
        NOTREACHED() << "bad state";
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

  return rv;
}

int HttpNetworkTransaction::DoNotifyBeforeCreateStream() {
  next_state_ = STATE_CREATE_STREAM;
  bool defer = false;
  if (!before_network_start_callback_.is_null())
    std::move(before_network_start_callback_).Run(&defer);
  if (!defer)
    return OK;
  return ERR_IO_PENDING;
}

int HttpNetworkTransaction::DoCreateStream() {
  response_.network_accessed = true;

  next_state_ = STATE_CREATE_STREAM_COMPLETE;
  // IP based pooling is only enabl
"""


```
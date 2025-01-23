Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understanding the Core Request:** The primary goal is to understand the functionality of `http_stream_factory.cc`, its relationship to JavaScript (if any), logical deductions with input/output examples, common user/programming errors, and debugging steps.

2. **Initial Code Scan and Keyword Identification:**  First, I'd quickly scan the code for prominent keywords and patterns. This includes:
    * `#include`:  Identifies dependencies, giving hints about related functionalities (e.g., `net/http/http_network_session.h`, `net/quic/quic_http_utils.h`, `url/gurl.h`).
    * Class name: `HttpStreamFactory`.
    * Method names: `RequestStream`, `PreconnectStreams`, `ProcessAlternativeServices`, `GetSpdySessionKey`. These immediately suggest core responsibilities.
    * Data structures: `StreamRequestInfo`, `SpdySessionKey`, `JobController`.
    * Concepts: "stream," "session," "proxy," "QUIC," "HTTP/2," "preconnect," "alternative services."

3. **Deconstructing Functionality - Method by Method:**  The most effective way to understand the code is to analyze each public method and some key private ones:

    * **`GetSpdySessionKey`:**  Focus on what data it uses to construct the key. The logic for handling proxy scenarios and the conditions for using a proxy Spdy session are important. Note the `CHECK` statement – this highlights a potential error condition.

    * **`IsGetToProxy`:** Identify the conditions for considering a request as a "GET to proxy." The restrictions related to QUIC and HTTPS are crucial.

    * **`StreamRequestInfo`:**  Recognize this as a data structure holding information needed for stream creation.

    * **`HttpStreamFactory` (constructor/destructor):**  Simple initialization and cleanup.

    * **`ProcessAlternativeServices`:** Understand how it parses the `Alt-Svc` header and updates the `HttpServerProperties`. The interaction with `SpdyAltSvcWireFormat` is key.

    * **`RewriteHost`:**  Note the use of `HostMappingRules` – this is a mechanism for redirecting traffic.

    * **`RequestStream` (various overloads):**  These are the primary entry points for requesting HTTP streams. Pay attention to the different types of streams (`HTTP_STREAM`, `BIDIRECTIONAL_STREAM`, WebSocket). The creation of `JobController` is significant.

    * **`RequestStreamInternal`:**  This is the core logic for initiating stream requests. The instantiation of `JobController` and its `Start` method are crucial.

    * **`PreconnectStreams`:** Understand its purpose (opening connections proactively) and how it uses `JobController`. The error handling for invalid URLs is a good detail.

    * **`GetHostMappingRules`:**  Simple accessor.

    * **`OnJobControllerComplete`:**  Manages the lifecycle of `JobController` instances.

4. **Identifying Relationships with JavaScript:** This requires understanding how web browsers work. JavaScript interacts with the network through APIs like `fetch()` and `XMLHttpRequest`. These APIs eventually trigger network requests within the browser's networking stack. The `HttpStreamFactory` is a component *within* that stack, responsible for establishing the underlying connections. Therefore, the relationship is indirect but fundamental. Illustrative examples are essential here, showing how a JavaScript `fetch()` call leads to the use of this C++ code.

5. **Logical Deductions and Examples:**  For key functions like `GetSpdySessionKey` and `IsGetToProxy`, create hypothetical inputs and trace the code to predict the outputs. This solidifies understanding of the logic. Consider edge cases and different scenarios (e.g., HTTP vs. HTTPS, with and without proxies).

6. **Common Errors:**  Think about typical mistakes developers or users might make that could involve this code. Examples include:
    * Incorrect proxy configurations.
    * Problems with TLS/SSL certificates.
    * Network connectivity issues.
    * Server-side misconfigurations (e.g., invalid `Alt-Svc` headers).

7. **Debugging Steps:** Imagine you're a developer trying to track down a network issue. What steps would lead you to this code? This involves understanding the browser's architecture and debugging tools. Highlighting network logs and potentially stepping through the code are key.

8. **Structuring the Explanation:**  Organize the information logically:

    * **Overview:** Start with a high-level summary of the file's purpose.
    * **Detailed Functionality:**  Explain each key method and concept.
    * **JavaScript Relationship:** Clearly articulate the connection.
    * **Logical Deductions:** Provide concrete examples.
    * **Common Errors:** Give practical examples of issues.
    * **Debugging:**  Outline steps to reach this code.

9. **Refinement and Clarity:** Review the explanation for clarity and accuracy. Use precise language and avoid jargon where possible. Ensure the examples are easy to understand. For instance, when explaining `GetSpdySessionKey`, explicitly state *why* the key is important (for connection reuse).

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus too much on individual lines of code. **Correction:** Shift focus to the higher-level functionality of each method and how they interact.
* **Realization:** The connection to JavaScript isn't direct function calls. **Correction:** Explain the indirect relationship through browser APIs and the network stack.
* **Concern:**  Logical deductions might become too complex. **Correction:** Simplify the examples and focus on demonstrating the core logic of specific functions.
* **Awareness:**  Debugging steps need to be practical and actionable for a developer. **Correction:** Emphasize using browser developer tools and network logs.

By following these steps, and constantly refining the understanding and explanation, one can produce a comprehensive and accurate analysis of the provided C++ code.
这个 `net/http/http_stream_factory.cc` 文件是 Chromium 网络栈中一个非常核心的组件，它负责创建和管理 HTTP(S) 连接和流。以下是它的详细功能列表和相关说明：

**主要功能:**

1. **HTTP(S) 流的创建工厂:**  `HttpStreamFactory` 是一个工厂类，用于创建各种类型的 HTTP(S) 流，包括：
    * 普通的 HTTP/1.1 或 HTTP/2 流。
    * WebSocket 连接的流。
    * 双向流 (Bidirectional Streams，例如 HTTP/3 的双向流)。

2. **连接的复用和池化:**  它管理着已建立的连接池 (SpdySessionPool 等)，并尝试复用现有的连接来处理新的请求，以提高性能并减少延迟。

3. **代理处理:**  它处理通过 HTTP 或 HTTPS 代理服务器建立连接的逻辑，包括 `CONNECT` 方法和代理身份验证。

4. **QUIC 协议集成:**  它负责创建和管理基于 QUIC 协议的连接和流。

5. **HTTP/2 和 Alt-Svc 支持:**  它处理 HTTP/2 的连接建立和流管理，并解析和应用 `Alt-Svc` (Alternative Services) 头信息，以便在后续请求中尝试使用更优的连接方式 (例如从 HTTP/1.1 升级到 HTTP/2 或 QUIC)。

6. **预连接 (Preconnect):**  它支持预先建立连接，以减少用户发起实际请求时的延迟。

7. **Host Mapping 规则应用:**  它会应用配置的 Host Mapping 规则，将请求重定向到不同的主机或端口。

8. **网络隔离键 (Network Isolation Key) 和网络匿名化键 (Network Anonymization Key) 的处理:**  它使用这些键来管理连接的隔离，以增强隐私和安全性。

9. **安全 DNS 策略 (Secure DNS Policy) 的考虑:**  在建立连接时，它会考虑配置的安全 DNS 策略。

10. **TLS/SSL 配置:** 它与 `SSLConfig` 交互，以获取 TLS/SSL 连接所需的配置信息。

11. **请求优先级处理:** 它接受请求的优先级信息，并可能在连接建立和资源分配时考虑这些优先级。

**与 JavaScript 的关系 (间接但重要):**

JavaScript 代码（通常在网页中运行）使用浏览器提供的 Web API (例如 `fetch`, `XMLHttpRequest`) 发起 HTTP(S) 请求。 当 JavaScript 发起一个网络请求时，浏览器内部的网络栈会接管这个请求，而 `HttpStreamFactory` 正是这个网络栈中的关键组件之一。

**举例说明:**

假设你在一个网页的 JavaScript 中使用 `fetch` API 发起一个 HTTPS 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这段 JavaScript 代码执行时，浏览器会经历以下大致步骤，其中 `HttpStreamFactory` 会发挥关键作用：

1. **JavaScript 发起请求:** `fetch` API 调用启动网络请求。
2. **网络栈处理请求:** 浏览器网络栈接收到请求信息 (URL, 方法, 头部等)。
3. **HttpStreamFactory 介入:** `HttpStreamFactory` 根据请求的 URL、代理设置、协议偏好等信息，决定如何建立连接。
    * 如果存在到 `example.com` 的可用且可复用的 HTTPS 连接，`HttpStreamFactory` 会尝试复用它。
    * 如果没有可用连接，`HttpStreamFactory` 会创建一个新的 `HttpStreamFactory::JobController` 来负责建立连接。
    * 连接建立过程可能涉及 DNS 查询、TCP 连接建立、TLS 握手等步骤。
    * 如果服务器支持 HTTP/2 或 QUIC，并且浏览器配置允许，`HttpStreamFactory` 可能会尝试建立 HTTP/2 或 QUIC 连接。
4. **创建 HTTP 流:** 一旦连接建立，`HttpStreamFactory` 会创建一个与该连接关联的 HTTP 流 (例如 `SpdyHttpStream` 或基于 socket 的流) 来发送和接收数据。
5. **数据传输:** 数据通过创建的流发送到服务器，服务器的响应数据通过相同的流返回。
6. **JavaScript 接收响应:** 浏览器网络栈将接收到的数据传递回 JavaScript 的 `fetch` API，最终触发 `.then` 回调。

**逻辑推理与假设输入/输出:**

**场景:**  JavaScript 发起一个到 `https://example.com` 的 HTTPS GET 请求，并且服务器在响应头中包含了 `Alt-Svc: h2=":443"; ma=86400`。

**假设输入:**

* `request_info.url`: `https://example.com/some/path`
* `request_info.method`: "GET"
* `response_headers` (来自 `https://example.com`): 包含 `Alt-Svc: h2=":443"; ma=86400`

**HttpStreamFactory 的处理:**

1. **`ProcessAlternativeServices` 调用:** 当收到来自 `example.com` 的响应时，`HttpStreamFactory::ProcessAlternativeServices` 方法会被调用。
2. **解析 `Alt-Svc`:** 该方法会解析 `Alt-Svc` 头，发现服务器声明它支持 HTTP/2 (h2) 在相同的 host 和端口 (443) 上，有效期为 86400 秒。
3. **存储 Alternative Service 信息:**  `HttpStreamFactory` 会将这个信息存储在 `HttpServerProperties` 中，与 `example.com` 相关联。

**假设输出 (后续请求):**

* **后续请求到 `https://example.com`:**  当下一次 JavaScript 代码发起到 `https://example.com` 的请求时，`HttpStreamFactory` 会查询 `HttpServerProperties`，发现服务器声明了支持 HTTP/2。
* **尝试 HTTP/2 连接:** `HttpStreamFactory` 会优先尝试建立到 `example.com:443` 的 HTTP/2 连接，而不是传统的 HTTP/1.1 连接 (假设浏览器和服务器都支持 HTTP/2)。

**用户或编程常见的使用错误:**

1. **错误配置代理:**  如果用户的系统代理配置不正确，或者 JavaScript 代码中显式配置了错误的代理，`HttpStreamFactory` 可能无法正确建立连接。 例如，配置了一个不存在或无法访问的代理服务器。 这会导致连接超时或连接被拒绝的错误。

2. **TLS/SSL 相关问题:**
    * **服务器证书无效:** 如果服务器的 TLS 证书过期、自签名或无法被信任，`HttpStreamFactory` 会阻止建立连接，并抛出安全错误。用户通常会在浏览器中看到证书错误警告。
    * **客户端 TLS 配置错误:**  虽然不常见，但如果浏览器的 TLS 配置有问题，也可能导致连接失败。

3. **阻止或干扰网络连接的软件:**  防火墙、杀毒软件或其他网络安全软件可能会阻止 `HttpStreamFactory` 尝试建立连接，导致请求失败。

4. **服务器端配置错误:**
    * **`Alt-Svc` 头配置错误:** 如果服务器发送了格式错误或无效的 `Alt-Svc` 头，`HttpStreamFactory` 可能无法正确解析，或者尝试建立无效的连接。
    * **HTTP/2 或 QUIC 未正确配置:** 如果服务器声明支持 HTTP/2 或 QUIC，但实际上没有正确配置，`HttpStreamFactory` 的连接尝试可能会失败。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览网页时遇到了网络连接问题，想要调试，以下是一些可能到达 `http_stream_factory.cc` 的线索：

1. **用户在浏览器中输入 URL 并访问网页:** 这是最常见的入口点。 用户在地址栏输入 `https://example.com` 并按下 Enter 键。浏览器开始加载网页资源。

2. **网页加载资源失败或缓慢:**  如果网页中的某些资源加载失败（例如图片、CSS、JavaScript 文件），或者加载速度异常缓慢，这可能表明网络连接存在问题。

3. **打开浏览器的开发者工具 (DevTools):** 用户按下 F12 键或通过菜单打开开发者工具。

4. **查看 "Network" (网络) 面板:**  在开发者工具的 "Network" 面板中，用户可以看到浏览器发出的所有网络请求。

5. **检查请求的状态:** 用户可以查看每个请求的状态码（例如 200 OK, 404 Not Found, 500 Internal Server Error），以及请求的 "Timing" (耗时) 信息。

6. **查看连接信息:**  现代浏览器在 "Network" 面板中通常会提供更详细的连接信息，例如使用的协议 (HTTP/1.1, HTTP/2, h3-Qxx)，连接是否被复用等。

7. **使用 `chrome://net-internals/#events`:**  在 Chrome 浏览器中，用户可以访问 `chrome://net-internals/#events` 页面，这是一个强大的网络调试工具，可以查看更底层的网络事件。

8. **在 `chrome://net-internals/#events` 中过滤事件:** 用户可以根据主机名、URL 或其他条件过滤事件，以查找与特定请求相关的事件。

9. **查找与 `HttpStreamFactory` 相关的事件:**  在事件列表中，用户可能会看到与 `HttpStreamFactory` 创建连接、选择协议、处理代理等相关的事件。 例如，可能会看到 "HTTP_STREAM_REQUEST" 事件，表示 `HttpStreamFactory` 正在尝试创建一个新的 HTTP 流。

10. **查看错误信息:** 如果连接建立失败，`chrome://net-internals/#events` 中通常会包含详细的错误信息，这些信息可以帮助定位问题。 例如，可能会看到 TLS 握手失败、连接超时等错误。

11. **结合日志和代码分析:**  对于开发者来说，如果需要深入调查问题，可能会查看 Chromium 的网络日志 (如果已启用) 并结合 `http_stream_factory.cc` 的源代码进行分析，以理解连接建立的详细过程和可能出错的地方。

总而言之，`http_stream_factory.cc` 是 Chromium 网络栈中至关重要的一个环节，它直接影响着网页加载的性能、安全性和稳定性。 理解它的功能对于进行网络相关的调试和性能优化至关重要。

### 提示词
```
这是目录为net/http/http_stream_factory.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/http/http_stream_factory.h"

#include <cstddef>
#include <tuple>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "net/base/host_mapping_rules.h"
#include "net/base/host_port_pair.h"
#include "net/base/load_flags.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_isolation_key.h"
#include "net/base/parse_number.h"
#include "net/base/port_util.h"
#include "net/base/privacy_mode.h"
#include "net/base/upload_data_stream.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_network_session.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream_factory_job.h"
#include "net/http/http_stream_factory_job_controller.h"
#include "net/http/transport_security_state.h"
#include "net/quic/quic_http_utils.h"
#include "net/socket/socket_tag.h"
#include "net/spdy/bidirectional_stream_spdy_impl.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/ssl/ssl_config.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_alt_svc_wire_format.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_server_id.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {

namespace {
const char kAlternativeServiceHeader[] = "Alt-Svc";

}  // namespace

// static
SpdySessionKey HttpStreamFactory::GetSpdySessionKey(
    const ProxyChain& proxy_chain,
    const GURL& origin_url,
    const StreamRequestInfo& request_info) {
  // In the case that we'll be sending a GET request to the proxy, look for an
  // HTTP/2 proxy session *to* the proxy, instead of to the origin server. The
  // way HTTP over HTTPS proxies work is that the ConnectJob makes a SpdyProxy,
  // and then the HttpStreamFactory detects it when it's added to the
  // SpdySession pool, and uses it directly (completely ignoring the result of
  // the ConnectJob, and in fact cancelling it). So we need to create the same
  // key used by the HttpProxyConnectJob for the last proxy in the chain.
  if (IsGetToProxy(proxy_chain, origin_url)) {
    // For this to work as expected, the whole chain should be HTTPS.
    for (const auto& proxy_server : proxy_chain.proxy_servers()) {
      CHECK(proxy_server.is_https());
    }
    auto [last_proxy_partial_chain, last_proxy_server] =
        proxy_chain.SplitLast();
    const auto& last_proxy_host_port_pair = last_proxy_server.host_port_pair();
    // Note that `disable_cert_network_fetches` must be true for proxies to
    // avoid deadlock. See comment on
    // `SSLConfig::disable_cert_verification_network_fetches`.
    return SpdySessionKey(
        last_proxy_host_port_pair, PRIVACY_MODE_DISABLED,
        last_proxy_partial_chain, SessionUsage::kProxy, request_info.socket_tag,
        request_info.network_anonymization_key, request_info.secure_dns_policy,
        /*disable_cert_network_fetches=*/true);
  }
  return SpdySessionKey(
      HostPortPair::FromURL(origin_url), request_info.privacy_mode, proxy_chain,
      SessionUsage::kDestination, request_info.socket_tag,
      request_info.network_anonymization_key, request_info.secure_dns_policy,
      request_info.load_flags & LOAD_DISABLE_CERT_NETWORK_FETCHES);
}

// static
bool HttpStreamFactory::IsGetToProxy(const ProxyChain& proxy_chain,
                                     const GURL& origin_url) {
  // Sending proxied GET requests to the last proxy server in the chain is no
  // longer supported for QUIC.
  return proxy_chain.is_get_to_proxy_allowed() &&
         proxy_chain.Last().is_https() && origin_url.SchemeIs(url::kHttpScheme);
}

HttpStreamFactory::StreamRequestInfo::StreamRequestInfo() = default;

HttpStreamFactory::StreamRequestInfo::StreamRequestInfo(
    const HttpRequestInfo& http_request_info)
    : method(http_request_info.method),
      network_anonymization_key(http_request_info.network_anonymization_key),
      is_http1_allowed(!http_request_info.upload_data_stream ||
                       http_request_info.upload_data_stream->AllowHTTP1()),
      load_flags(http_request_info.load_flags),
      privacy_mode(http_request_info.privacy_mode),
      secure_dns_policy(http_request_info.secure_dns_policy),
      socket_tag(http_request_info.socket_tag) {}

HttpStreamFactory::StreamRequestInfo::StreamRequestInfo(
    const StreamRequestInfo& other) = default;
HttpStreamFactory::StreamRequestInfo&
HttpStreamFactory::StreamRequestInfo::operator=(
    const StreamRequestInfo& other) = default;
HttpStreamFactory::StreamRequestInfo::StreamRequestInfo(
    StreamRequestInfo&& other) = default;
HttpStreamFactory::StreamRequestInfo&
HttpStreamFactory::StreamRequestInfo::operator=(StreamRequestInfo&& other) =
    default;

HttpStreamFactory::StreamRequestInfo::~StreamRequestInfo() = default;

HttpStreamFactory::HttpStreamFactory(HttpNetworkSession* session)
    : session_(session), job_factory_(std::make_unique<JobFactory>()) {}

HttpStreamFactory::~HttpStreamFactory() = default;

void HttpStreamFactory::ProcessAlternativeServices(
    HttpNetworkSession* session,
    const NetworkAnonymizationKey& network_anonymization_key,
    const HttpResponseHeaders* headers,
    const url::SchemeHostPort& http_server) {
  if (!headers->HasHeader(kAlternativeServiceHeader))
    return;

  std::string alternative_service_str =
      headers->GetNormalizedHeader(kAlternativeServiceHeader)
          .value_or(std::string());
  spdy::SpdyAltSvcWireFormat::AlternativeServiceVector
      alternative_service_vector;
  if (!spdy::SpdyAltSvcWireFormat::ParseHeaderFieldValue(
          alternative_service_str, &alternative_service_vector)) {
    return;
  }

  session->http_server_properties()->SetAlternativeServices(
      RewriteHost(http_server), network_anonymization_key,
      net::ProcessAlternativeServices(
          alternative_service_vector, session->params().enable_http2,
          session->params().enable_quic,
          session->context().quic_context->params()->supported_versions));
}

url::SchemeHostPort HttpStreamFactory::RewriteHost(
    const url::SchemeHostPort& server) {
  HostPortPair host_port_pair(server.host(), server.port());
  const HostMappingRules* mapping_rules = GetHostMappingRules();
  if (mapping_rules)
    mapping_rules->RewriteHost(&host_port_pair);
  return url::SchemeHostPort(server.scheme(), host_port_pair.host(),
                             host_port_pair.port());
}

std::unique_ptr<HttpStreamRequest> HttpStreamFactory::RequestStream(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    HttpStreamRequest::Delegate* delegate,
    bool enable_ip_based_pooling,
    bool enable_alternative_services,
    const NetLogWithSource& net_log) {
  return RequestStreamInternal(request_info, priority, allowed_bad_certs,
                               delegate, nullptr,
                               HttpStreamRequest::HTTP_STREAM,
                               /*is_websocket=*/false, enable_ip_based_pooling,
                               enable_alternative_services, net_log);
}

std::unique_ptr<HttpStreamRequest>
HttpStreamFactory::RequestWebSocketHandshakeStream(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper* create_helper,
    bool enable_ip_based_pooling,
    bool enable_alternative_services,
    const NetLogWithSource& net_log) {
  DCHECK(create_helper);
  return RequestStreamInternal(request_info, priority, allowed_bad_certs,
                               delegate, create_helper,
                               HttpStreamRequest::HTTP_STREAM,
                               /*is_websocket=*/true, enable_ip_based_pooling,
                               enable_alternative_services, net_log);
}

std::unique_ptr<HttpStreamRequest>
HttpStreamFactory::RequestBidirectionalStreamImpl(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    HttpStreamRequest::Delegate* delegate,
    bool enable_ip_based_pooling,
    bool enable_alternative_services,
    const NetLogWithSource& net_log) {
  DCHECK(request_info.url.SchemeIs(url::kHttpsScheme));

  return RequestStreamInternal(request_info, priority, allowed_bad_certs,
                               delegate, nullptr,
                               HttpStreamRequest::BIDIRECTIONAL_STREAM,
                               /*is_websocket=*/false, enable_ip_based_pooling,
                               enable_alternative_services, net_log);
}

std::unique_ptr<HttpStreamRequest> HttpStreamFactory::RequestStreamInternal(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper*
        websocket_handshake_stream_create_helper,
    HttpStreamRequest::StreamType stream_type,
    bool is_websocket,
    bool enable_ip_based_pooling,
    bool enable_alternative_services,
    const NetLogWithSource& net_log) {
  // This is only needed in the non-preconnect path, as preconnects do not
  // require a NetworkIsolationKey.
  DCHECK(request_info.IsConsistent());

  auto job_controller = std::make_unique<JobController>(
      this, delegate, session_, job_factory_.get(), request_info,
      /* is_preconnect = */ false, is_websocket, enable_ip_based_pooling,
      enable_alternative_services,
      session_->context()
          .quic_context->params()
          ->delay_main_job_with_available_spdy_session,
      allowed_bad_certs);
  JobController* job_controller_raw_ptr = job_controller.get();
  job_controller_set_.insert(std::move(job_controller));
  return job_controller_raw_ptr->Start(delegate,
                                       websocket_handshake_stream_create_helper,
                                       net_log, stream_type, priority);
}

void HttpStreamFactory::PreconnectStreams(int num_streams,
                                          HttpRequestInfo& request_info) {
  // Ignore invalid URLs. This matches the behavior of
  // URLRequestJobFactory::CreateJob(). Passing very long valid GURLs over Mojo
  // can result in invalid URLs, so can't rely on callers sending only valid
  // URLs.
  if (!request_info.url.is_valid()) {
    OnPreconnectsCompleteInternal();
    return;
  }

  auto job_controller = std::make_unique<JobController>(
      this, nullptr, session_, job_factory_.get(), request_info,
      /*is_preconnect=*/true,
      /*is_websocket=*/false,
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true,
      session_->context()
          .quic_context->params()
          ->delay_main_job_with_available_spdy_session,
      /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
  JobController* job_controller_raw_ptr = job_controller.get();
  job_controller_set_.insert(std::move(job_controller));
  job_controller_raw_ptr->Preconnect(num_streams);
}

const HostMappingRules* HttpStreamFactory::GetHostMappingRules() const {
  return &session_->params().host_mapping_rules;
}

void HttpStreamFactory::OnJobControllerComplete(JobController* controller) {
  auto it = job_controller_set_.find(controller);
  if (it != job_controller_set_.end()) {
    job_controller_set_.erase(it);
  } else {
    NOTREACHED();
  }
}

}  // namespace net
```
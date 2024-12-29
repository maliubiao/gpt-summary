Response:
Let's break down the thought process for analyzing this C++ Chromium code snippet.

1. **Understanding the Goal:** The request asks for the functionality of the `client_socket_pool_manager.cc` file, its relation to JavaScript, logical reasoning examples, common user errors, and debugging steps.

2. **Initial Code Scan (Keywords and Structure):**  I first scanned the code for key terms:
    * `#include`:  Shows dependencies on other Chromium components (like `net/socket/client_socket_pool.h`, `net/http/http_stream_factory.h`). This hints at the file's role in managing network connections.
    * `namespace net`:  Confirms this is part of the Chromium networking stack.
    * `ClientSocketPoolManager`: The central class. The name strongly suggests it manages pools of client sockets.
    * `g_max_sockets_per_pool`, `g_max_sockets_per_group`, `g_max_sockets_per_proxy_chain`: These are global variables defining limits, indicating resource management.
    * `InitSocketHandleForHttpRequest`, `InitSocketHandleForWebSocketRequest`, `PreconnectSocketsForHttpRequest`: These function names clearly point to establishing connections for different types of requests.
    * `HttpNetworkSession`:  A crucial class likely responsible for managing the overall network session.
    * `ClientSocketPool`:  The entity holding the pooled sockets.
    * `ClientSocketHandle`:  A handle representing a single socket.
    * `ProxyInfo`: Deals with proxy server information.
    * `SSLConfig`:  Handles SSL/TLS configuration.
    * `CompletionOnceCallback`:  Indicates asynchronous operations.

3. **Inferring Core Functionality:** Based on the keywords and structure, I deduced the primary function: **Managing and pooling client sockets for HTTP and WebSocket connections.** This involves:
    * **Resource Management:** Limiting the number of sockets per pool, group, and proxy chain to prevent resource exhaustion and adhere to best practices.
    * **Connection Establishment:**  Providing functions to initiate socket connections for different request types, considering proxies, SSL, and security policies.
    * **Connection Reuse:**  The "pool" aspect suggests reusing existing connections to improve performance.
    * **Preconnection:**  Optimizing by proactively establishing connections.

4. **JavaScript Relationship (Connecting the Dots):** Now, I considered how this backend code relates to frontend JavaScript:
    * **`fetch()` API:**  The most common way for JavaScript to make network requests. This C++ code is part of the underlying implementation when a `fetch()` request is made.
    * **`WebSocket` API:**  Directly mentioned in the code. The functions `InitSocketHandleForWebSocketRequest` are explicitly for WebSocket connections initiated from JavaScript.
    * **User Actions:**  User actions in the browser (clicking links, submitting forms, etc.) often trigger network requests, ultimately utilizing this socket pooling mechanism.

5. **Logical Reasoning (Input/Output):** To illustrate logical reasoning, I considered the `InitSocketHandleForHttpRequest` function:
    * **Input:**  A URL, request flags, session information, proxy details, etc.
    * **Process:** The function determines the correct socket pool, checks for existing connections, potentially creates a new connection, and returns a result (success or error).
    * **Output:** A `ClientSocketHandle` if successful, or an error code if it fails.

6. **Common User Errors:** I thought about what users or developers might do that could interact with or expose potential issues related to socket pooling:
    * **Too many concurrent requests:** Exceeding the connection limits.
    * **Incorrect proxy settings:** Causing connection failures.
    * **SSL certificate issues:** Leading to connection errors.
    * **Website misconfiguration:**  Server-side issues can manifest as connection problems.

7. **Debugging Steps (User Journey):** I traced a hypothetical user action leading to this code:
    1. User enters a URL or clicks a link.
    2. Browser needs to fetch resources.
    3. The `HttpStreamFactory` (mentioned as an include) is involved in creating HTTP streams.
    4. `ClientSocketPoolManager` is consulted to get a socket.
    5. The relevant `InitSocketHandleFor...` function is called.

8. **Refining and Structuring the Answer:** Finally, I organized the information into logical sections: Functionality, JavaScript relationship with examples, logical reasoning with input/output, common errors, and debugging steps. I used clear and concise language, explaining technical terms where necessary. I also made sure to explicitly mention the relevant JavaScript APIs and how user actions trigger the underlying network operations.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file directly handles socket creation.
* **Correction:** The code uses `ClientSocketPool`, indicating it *manages* existing sockets rather than directly creating them in most cases. It requests sockets from the pool.
* **Initial thought:** Focus heavily on the low-level socket details.
* **Correction:** While socket management is the core, it's important to explain the *purpose* – enabling network requests from the browser – and its connection to higher-level APIs like `fetch()` and `WebSocket`.
* **Ensuring clarity on "logical reasoning":**  The prompt asks for this. Providing a simple input/output example of a key function clarifies how the code works on a functional level.

By following this structured thought process, I was able to dissect the C++ code and address all aspects of the request effectively.
这个文件 `net/socket/client_socket_pool_manager.cc` 是 Chromium 网络栈中负责管理客户端套接字池的核心组件。它的主要功能是：

**核心功能：管理和复用客户端套接字连接**

1. **维护不同类型的套接字池:**  它管理着不同类型的套接字池，目前主要包括 `NORMAL_SOCKET_POOL` (用于普通的 HTTP/HTTPS 请求) 和 `WEBSOCKET_SOCKET_POOL` (用于 WebSocket 连接)。
2. **限制连接数量:**  它定义并管理着各种连接数量的限制，以防止资源耗尽，包括：
    * `g_max_sockets_per_pool`:  每个套接字池允许的最大连接数。
    * `g_max_sockets_per_group`:  对于同一个目标（scheme, host, port），允许的最大连接数。
    * `g_max_sockets_per_proxy_chain`: 对于相同的代理链，允许的最大连接数。
3. **初始化套接字连接:**  它提供了 `InitSocketHandleForHttpRequest` 和 `InitSocketHandleForWebSocketRequest` 等函数，用于初始化一个新的客户端套接字连接。这些函数负责：
    * 确定目标服务器和代理。
    * 选择合适的套接字池。
    * 从套接字池中获取一个可用的连接，或者创建一个新的连接。
    * 处理 SSL/TLS 配置。
    * 处理代理认证。
4. **支持预连接:**  `PreconnectSocketsForHttpRequest` 函数允许预先建立一些连接，以减少后续请求的延迟。
5. **管理空闲连接:**  通过 `unused_idle_socket_timeout` 来管理空闲连接的超时时间，超时的连接会被关闭以释放资源。
6. **处理请求优先级:**  在初始化连接时考虑请求的优先级 (`RequestPriority`)。
7. **处理隐私模式和网络匿名化:**  考虑隐私模式 (`PrivacyMode`) 和网络匿名化密钥 (`NetworkAnonymizationKey`) 来隔离连接。
8. **处理安全 DNS 策略:**  考虑安全 DNS 策略 (`SecureDnsPolicy`)。
9. **关联网络流量注解标签:**  为连接关联网络流量注解标签 (`NetworkTrafficAnnotationTag`)。

**与 JavaScript 的关系及举例说明：**

该文件直接位于网络栈的底层，JavaScript 无法直接访问或操作它。但是，当 JavaScript 发起网络请求时（例如使用 `fetch()` API 或 `WebSocket` API），这些请求最终会通过 Chromium 的网络栈，并会涉及到 `ClientSocketPoolManager` 来管理底层的 TCP 连接。

**举例：**

1. **`fetch()` API:**  当 JavaScript 代码执行 `fetch('https://www.example.com/data')` 时，这个请求会被传递到浏览器内核的网络层。网络层会查找或创建一个到 `www.example.com` 的 HTTPS 连接。`ClientSocketPoolManager` 会参与到这个过程中，检查是否已经有到 `www.example.com` 的空闲连接可以复用，如果没有，它会创建一个新的连接并将其添加到连接池中。
2. **`WebSocket` API:** 当 JavaScript 代码执行 `const ws = new WebSocket('wss://echo.websocket.org');` 时，浏览器会尝试建立一个 WebSocket 连接。`InitSocketHandleForWebSocketRequest` 函数会被调用来处理这个请求，并从 `WEBSOCKET_SOCKET_POOL` 中获取或创建一个连接。

**逻辑推理 (假设输入与输出)：**

**假设输入：**

* 用户在浏览器中访问 `https://example.com/page.html`，页面内包含多个请求：
    * 一个主文档请求：`https://example.com/page.html`
    * 两个图片请求：`https://example.com/image1.png` 和 `https://example.com/image2.png`
* 假设 `g_max_sockets_per_group` 设置为 6。
* 假设套接字池中没有到 `example.com` 的可用连接。

**逻辑推理过程：**

1. **主文档请求：**
   * `InitSocketHandleForHttpRequest` 被调用。
   * 因为没有可用连接，会创建一个新的 TCP 连接到 `example.com:443`。
   * 这个连接被添加到 `NORMAL_SOCKET_POOL` 中，并且计入到 `example.com` 这个 group 的连接数。
2. **第一个图片请求：**
   * `InitSocketHandleForHttpRequest` 被调用。
   * 检查 `NORMAL_SOCKET_POOL` 中是否有到 `example.com` 的空闲连接。
   * 如果主文档的连接仍然空闲，则可能会复用该连接。
   * 如果主文档的连接正在使用，则会创建一个新的连接。
   *  `example.com` 这个 group 的连接数会增加。
3. **第二个图片请求：**
   * `InitSocketHandleForHttpRequest` 被调用。
   * 再次检查 `NORMAL_SOCKET_POOL` 中是否有到 `example.com` 的空闲连接。
   * 如果之前的连接空闲，则复用。
   * 如果所有连接都在使用，且 `example.com` 的连接数尚未达到 `g_max_sockets_per_group` (6)，则会创建一个新的连接。
   * 如果已达到限制，则该请求可能需要等待，直到有连接被释放。

**假设输出：**

* 最终，可能会建立 1 到 3 个到 `example.com` 的 TCP 连接，具体取决于请求的并发性和连接的空闲状态。
* `NORMAL_SOCKET_POOL` 中会包含这些连接。
* `example.com` 这个 group 的连接数不会超过 6。

**用户或编程常见的使用错误及举例说明：**

1. **发起过多并发请求而不进行复用：**  如果 JavaScript 代码没有合理地组织请求，或者服务器端没有正确设置 HTTP 头部（如 `Connection: keep-alive`），可能导致浏览器无法复用连接，从而触发创建大量新的连接，可能超出限制。
   * **例子：**  在一个循环中并行 `fetch()` 大量独立的资源，而没有考虑连接复用。
2. **代理配置错误：**  如果用户或程序配置了错误的代理服务器，`ClientSocketPoolManager` 尝试连接代理时可能会失败，导致网络请求失败。
   * **例子：** 用户在系统设置中配置了一个不存在或不可用的代理服务器。
3. **SSL 证书问题：**  如果目标网站的 SSL 证书无效或存在问题，连接建立过程会失败。
   * **例子：**  访问一个使用了过期或自签名 SSL 证书的网站。
4. **网络环境不稳定：**  不稳定的网络连接可能导致连接频繁断开和重建，增加了 `ClientSocketPoolManager` 的工作负担。
   * **例子：** 用户在移动网络信号弱的地方浏览网页。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并按下回车，或者点击了一个链接。**
2. **浏览器解析 URL，确定目标服务器的地址和端口。**
3. **浏览器的网络栈开始处理这个请求。**
4. **如果是一个 HTTP/HTTPS 请求，`HttpStreamFactory` 会被调用来创建 HTTP 流。**
5. **`HttpStreamFactory` 需要一个底层的 TCP 连接。**
6. **`ClientSocketPoolManager` 被调用，根据目标服务器和代理信息，尝试从相应的套接字池中获取一个可用的 `ClientSocketHandle`。**
7. **如果套接字池中没有合适的空闲连接，并且未达到连接限制，`ClientSocketPoolManager` 会创建一个新的 `ConnectJob` 来建立新的 TCP 连接。**
8. **连接建立成功后，`ClientSocketHandle` 被返回，`HttpStreamFactory` 可以利用这个连接发送 HTTP 请求。**
9. **如果是 WebSocket 连接，当 JavaScript 代码执行 `new WebSocket(...)` 时，会直接调用 `InitSocketHandleForWebSocketRequest`。**

**调试线索：**

* **网络面板：**  开发者工具的网络面板可以显示请求的状态、连接时间、是否使用了缓存等信息，可以初步判断是否是连接问题。
* **`net-internals` (chrome://net-internals/#sockets)：**  这是一个强大的 Chromium 内置工具，可以查看当前所有的套接字连接状态，包括连接到哪个服务器、是否空闲、何时创建等。通过观察 `net-internals` 的输出，可以详细了解 `ClientSocketPoolManager` 的工作状态，例如：
    * 是否有大量的连接处于 `IDLE` 状态。
    * 是否有连接建立失败。
    * 特定目标服务器的连接数是否达到了限制。
* **NetLog：**  Chromium 的 NetLog 功能可以记录详细的网络事件，包括套接字连接的创建、复用、关闭等。分析 NetLog 可以深入了解 `ClientSocketPoolManager` 的行为和决策过程。
* **断点调试：**  如果需要更深入地了解代码执行流程，可以在 `client_socket_pool_manager.cc` 中的关键函数（如 `InitSocketHandleForHttpRequest`、`RequestSockets` 等）设置断点，并逐步跟踪代码执行过程。

总而言之，`client_socket_pool_manager.cc` 是 Chromium 网络栈中一个至关重要的组件，它负责高效地管理和复用客户端套接字连接，从而优化网络性能并节省资源。理解它的功能对于诊断和解决网络连接问题至关重要。

Prompt: 
```
这是目录为net/socket/client_socket_pool_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/socket/client_socket_pool_manager.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/check_op.h"
#include "base/metrics/field_trial_params.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/load_flags.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_stream_factory.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/connect_job.h"
#include "net/ssl/ssl_config.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {

namespace {

// Limit of sockets of each socket pool.
int g_max_sockets_per_pool[] = {
  256,  // NORMAL_SOCKET_POOL
  256   // WEBSOCKET_SOCKET_POOL
};

static_assert(std::size(g_max_sockets_per_pool) ==
                  HttpNetworkSession::NUM_SOCKET_POOL_TYPES,
              "max sockets per pool length mismatch");

// Default to allow up to 6 connections per host. Experiment and tuning may
// try other values (greater than 0).  Too large may cause many problems, such
// as home routers blocking the connections!?!?  See http://crbug.com/12066.
//
// WebSocket connections are long-lived, and should be treated differently
// than normal other connections. Use a limit of 255, so the limit for wss will
// be the same as the limit for ws. Also note that Firefox uses a limit of 200.
// See http://crbug.com/486800
int g_max_sockets_per_group[] = {
    6,   // NORMAL_SOCKET_POOL
    255  // WEBSOCKET_SOCKET_POOL
};

static_assert(std::size(g_max_sockets_per_group) ==
                  HttpNetworkSession::NUM_SOCKET_POOL_TYPES,
              "max sockets per group length mismatch");

// The max number of sockets to allow per proxy chain.  This applies both to
// http and SOCKS proxies.  See http://crbug.com/12066 and
// http://crbug.com/44501 for details about proxy chain connection limits.
int g_max_sockets_per_proxy_chain[] = {
    kDefaultMaxSocketsPerProxyChain,  // NORMAL_SOCKET_POOL
    kDefaultMaxSocketsPerProxyChain   // WEBSOCKET_SOCKET_POOL
};

static_assert(std::size(g_max_sockets_per_proxy_chain) ==
                  HttpNetworkSession::NUM_SOCKET_POOL_TYPES,
              "max sockets per proxy chain length mismatch");

// TODO(crbug.com/40609237) In order to resolve longstanding issues
// related to pooling distinguishable sockets together, get rid of SocketParams
// entirely.
scoped_refptr<ClientSocketPool::SocketParams> CreateSocketParams(
    const ClientSocketPool::GroupId& group_id,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs) {
  bool using_ssl = GURL::SchemeIsCryptographic(group_id.destination().scheme());
  return base::MakeRefCounted<ClientSocketPool::SocketParams>(
      using_ssl ? allowed_bad_certs : std::vector<SSLConfig::CertAndStatus>());
}

int InitSocketPoolHelper(
    url::SchemeHostPort endpoint,
    int request_load_flags,
    RequestPriority request_priority,
    HttpNetworkSession* session,
    const ProxyInfo& proxy_info,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    PrivacyMode privacy_mode,
    NetworkAnonymizationKey network_anonymization_key,
    SecureDnsPolicy secure_dns_policy,
    const SocketTag& socket_tag,
    const NetLogWithSource& net_log,
    int num_preconnect_streams,
    ClientSocketHandle* socket_handle,
    HttpNetworkSession::SocketPoolType socket_pool_type,
    CompletionOnceCallback callback,
    const ClientSocketPool::ProxyAuthCallback& proxy_auth_callback) {
  DCHECK(endpoint.IsValid());

  bool using_ssl = GURL::SchemeIsCryptographic(endpoint.scheme());
  if (!using_ssl && session->params().testing_fixed_http_port != 0) {
    endpoint = url::SchemeHostPort(endpoint.scheme(), endpoint.host(),
                                   session->params().testing_fixed_http_port);
  } else if (using_ssl && session->params().testing_fixed_https_port != 0) {
    endpoint = url::SchemeHostPort(endpoint.scheme(), endpoint.host(),
                                   session->params().testing_fixed_https_port);
  }

  bool disable_cert_network_fetches =
      !!(request_load_flags & LOAD_DISABLE_CERT_NETWORK_FETCHES);
  ClientSocketPool::GroupId connection_group(
      std::move(endpoint), privacy_mode, std::move(network_anonymization_key),
      secure_dns_policy, disable_cert_network_fetches);
  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      CreateSocketParams(connection_group, allowed_bad_certs);

  ClientSocketPool* pool =
      session->GetSocketPool(socket_pool_type, proxy_info.proxy_chain());
  ClientSocketPool::RespectLimits respect_limits =
      ClientSocketPool::RespectLimits::ENABLED;
  if ((request_load_flags & LOAD_IGNORE_LIMITS) != 0)
    respect_limits = ClientSocketPool::RespectLimits::DISABLED;

  std::optional<NetworkTrafficAnnotationTag> proxy_annotation =
      proxy_info.is_direct() ? std::nullopt
                             : std::optional<NetworkTrafficAnnotationTag>(
                                   proxy_info.traffic_annotation());
  if (num_preconnect_streams) {
    return pool->RequestSockets(connection_group, std::move(socket_params),
                                proxy_annotation, num_preconnect_streams,
                                std::move(callback), net_log);
  }

  return socket_handle->Init(connection_group, std::move(socket_params),
                             proxy_annotation, request_priority, socket_tag,
                             respect_limits, std::move(callback),
                             proxy_auth_callback, pool, net_log);
}

}  // namespace

ClientSocketPoolManager::ClientSocketPoolManager() = default;
ClientSocketPoolManager::~ClientSocketPoolManager() = default;

// static
int ClientSocketPoolManager::max_sockets_per_pool(
    HttpNetworkSession::SocketPoolType pool_type) {
  DCHECK_LT(pool_type, HttpNetworkSession::NUM_SOCKET_POOL_TYPES);
  return g_max_sockets_per_pool[pool_type];
}

// static
void ClientSocketPoolManager::set_max_sockets_per_pool(
    HttpNetworkSession::SocketPoolType pool_type,
    int socket_count) {
  DCHECK_LT(0, socket_count);
  DCHECK_GT(1000, socket_count);  // Sanity check.
  DCHECK_LT(pool_type, HttpNetworkSession::NUM_SOCKET_POOL_TYPES);
  g_max_sockets_per_pool[pool_type] = socket_count;
  DCHECK_GE(g_max_sockets_per_pool[pool_type],
            g_max_sockets_per_group[pool_type]);
}

// static
int ClientSocketPoolManager::max_sockets_per_group(
    HttpNetworkSession::SocketPoolType pool_type) {
  DCHECK_LT(pool_type, HttpNetworkSession::NUM_SOCKET_POOL_TYPES);
  return g_max_sockets_per_group[pool_type];
}

// static
void ClientSocketPoolManager::set_max_sockets_per_group(
    HttpNetworkSession::SocketPoolType pool_type,
    int socket_count) {
  DCHECK_LT(0, socket_count);
  // The following is a sanity check... but we should NEVER be near this value.
  DCHECK_GT(100, socket_count);
  DCHECK_LT(pool_type, HttpNetworkSession::NUM_SOCKET_POOL_TYPES);
  g_max_sockets_per_group[pool_type] = socket_count;

  DCHECK_GE(g_max_sockets_per_pool[pool_type],
            g_max_sockets_per_group[pool_type]);
  DCHECK_GE(g_max_sockets_per_proxy_chain[pool_type],
            g_max_sockets_per_group[pool_type]);
}

// static
int ClientSocketPoolManager::max_sockets_per_proxy_chain(
    HttpNetworkSession::SocketPoolType pool_type) {
  DCHECK_LT(pool_type, HttpNetworkSession::NUM_SOCKET_POOL_TYPES);
  return g_max_sockets_per_proxy_chain[pool_type];
}

// static
void ClientSocketPoolManager::set_max_sockets_per_proxy_chain(
    HttpNetworkSession::SocketPoolType pool_type,
    int socket_count) {
  DCHECK_LT(0, socket_count);
  DCHECK_GT(100, socket_count);  // Sanity check.
  DCHECK_LT(pool_type, HttpNetworkSession::NUM_SOCKET_POOL_TYPES);
  // Assert this case early on. The max number of sockets per group cannot
  // exceed the max number of sockets per proxy chain.
  DCHECK_LE(g_max_sockets_per_group[pool_type], socket_count);
  g_max_sockets_per_proxy_chain[pool_type] = socket_count;
}

// static
base::TimeDelta ClientSocketPoolManager::unused_idle_socket_timeout(
    HttpNetworkSession::SocketPoolType pool_type) {
  return base::Seconds(base::GetFieldTrialParamByFeatureAsInt(
      net::features::kNetUnusedIdleSocketTimeout,
      "unused_idle_socket_timeout_seconds", 60));
}

int InitSocketHandleForHttpRequest(
    url::SchemeHostPort endpoint,
    int request_load_flags,
    RequestPriority request_priority,
    HttpNetworkSession* session,
    const ProxyInfo& proxy_info,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    PrivacyMode privacy_mode,
    NetworkAnonymizationKey network_anonymization_key,
    SecureDnsPolicy secure_dns_policy,
    const SocketTag& socket_tag,
    const NetLogWithSource& net_log,
    ClientSocketHandle* socket_handle,
    CompletionOnceCallback callback,
    const ClientSocketPool::ProxyAuthCallback& proxy_auth_callback) {
  DCHECK(socket_handle);
  return InitSocketPoolHelper(
      std::move(endpoint), request_load_flags, request_priority, session,
      proxy_info, allowed_bad_certs, privacy_mode,
      std::move(network_anonymization_key), secure_dns_policy, socket_tag,
      net_log, 0, socket_handle, HttpNetworkSession::NORMAL_SOCKET_POOL,
      std::move(callback), proxy_auth_callback);
}

int InitSocketHandleForWebSocketRequest(
    url::SchemeHostPort endpoint,
    int request_load_flags,
    RequestPriority request_priority,
    HttpNetworkSession* session,
    const ProxyInfo& proxy_info,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    PrivacyMode privacy_mode,
    NetworkAnonymizationKey network_anonymization_key,
    const NetLogWithSource& net_log,
    ClientSocketHandle* socket_handle,
    CompletionOnceCallback callback,
    const ClientSocketPool::ProxyAuthCallback& proxy_auth_callback) {
  DCHECK(socket_handle);

  // QUIC proxies are currently not supported through this method.
  DCHECK(proxy_info.is_direct() || !proxy_info.proxy_chain().Last().is_quic());

  // Expect websocket schemes (ws and wss) to be converted to the http(s)
  // equivalent.
  DCHECK(endpoint.scheme() == url::kHttpScheme ||
         endpoint.scheme() == url::kHttpsScheme);

  return InitSocketPoolHelper(
      std::move(endpoint), request_load_flags, request_priority, session,
      proxy_info, allowed_bad_certs, privacy_mode,
      std::move(network_anonymization_key), SecureDnsPolicy::kAllow,
      SocketTag(), net_log, 0, socket_handle,
      HttpNetworkSession::WEBSOCKET_SOCKET_POOL, std::move(callback),
      proxy_auth_callback);
}

int PreconnectSocketsForHttpRequest(
    url::SchemeHostPort endpoint,
    int request_load_flags,
    RequestPriority request_priority,
    HttpNetworkSession* session,
    const ProxyInfo& proxy_info,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    PrivacyMode privacy_mode,
    NetworkAnonymizationKey network_anonymization_key,
    SecureDnsPolicy secure_dns_policy,
    const NetLogWithSource& net_log,
    int num_preconnect_streams,
    CompletionOnceCallback callback) {
  // Expect websocket schemes (ws and wss) to be converted to the http(s)
  // equivalent.
  DCHECK(endpoint.scheme() == url::kHttpScheme ||
         endpoint.scheme() == url::kHttpsScheme);

  return InitSocketPoolHelper(
      std::move(endpoint), request_load_flags, request_priority, session,
      proxy_info, allowed_bad_certs, privacy_mode,
      std::move(network_anonymization_key), secure_dns_policy, SocketTag(),
      net_log, num_preconnect_streams, nullptr,
      HttpNetworkSession::NORMAL_SOCKET_POOL, std::move(callback),
      ClientSocketPool::ProxyAuthCallback());
}

}  // namespace net

"""

```
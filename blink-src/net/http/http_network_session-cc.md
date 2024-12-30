Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive response.

1. **Understand the Core Request:** The request asks for the functionality of `http_network_session.cc`, its relation to JavaScript, examples of logical reasoning, common user errors, and how a user's actions might lead to this code being executed.

2. **Initial Code Scan and High-Level Understanding:**  Read through the code, noting key classes, members, and includes. The filename itself, `http_network_session.cc`, suggests it's central to managing network sessions for HTTP. The includes point to various network components like sockets, DNS, proxies, QUIC, and SPDY (HTTP/2). This gives a high-level idea of its role as a coordinator.

3. **Identify Key Responsibilities (Functional Breakdown):**  Go through the code section by section, focusing on the purpose of each class and its methods. Look for patterns and groupings of related functionality. This leads to identifying areas like:

    * **Session Management:** Creating, managing, and closing network sessions (HTTP/1.1, HTTP/2, QUIC). This is the core function.
    * **Socket Pooling:** Managing pools of reusable sockets to improve performance. Note the separation for normal and WebSocket sockets.
    * **Protocol Handling:** Supporting different HTTP versions (1.1, 2) and QUIC. Look for related configuration parameters and logic.
    * **Proxy Handling:** Integrating with the proxy resolution service.
    * **Security:**  Involving TLS/SSL through `ssl_client_context_` and related components.
    * **QUIC Integration:** Managing QUIC sessions through `quic_session_pool_`. Pay attention to QUIC-specific parameters.
    * **HTTP/2 (SPDY) Integration:** Managing HTTP/2 sessions through `spdy_session_pool_`. Note the settings and parameters.
    * **Resource Management:** Handling memory pressure and closing idle connections.
    * **Configuration:**  Using `HttpNetworkSessionParams` and `HttpNetworkSessionContext` to configure the session.
    * **Metrics and Debugging:**  Providing information through `SocketPoolInfoToValue`, `SpdySessionPoolInfoToValue`, and `QuicInfoToValue`.

4. **Analyze Interactions and Dependencies:** Consider how this class interacts with other parts of the Chromium networking stack. The included headers provide clues. For example, `HostResolver`, `ProxyResolutionService`, `HttpStreamFactory`, `QuicSessionPool`, `SpdySessionPool` are clearly important collaborators.

5. **JavaScript Relationship (If Any):** Think about how network requests initiated from JavaScript in a web browser would flow through the Chromium architecture. JavaScript uses browser APIs like `fetch` or `XMLHttpRequest`. These APIs delegate to the networking stack. While `http_network_session.cc` itself isn't directly manipulated by JavaScript, it's a *crucial component in fulfilling those JavaScript-initiated network requests*. The connection isn't direct manipulation, but rather being a foundational piece.

6. **Logical Reasoning Examples:**  Identify areas where the code makes decisions based on input or state.

    * **QUIC Enabling:**  The `ShouldForceQuic` function demonstrates a clear logical flow: check if QUIC is enabled, if it's not a WebSocket, if proxies allow it, and if the destination is on the force-QUIC list. Define concrete inputs and the expected output based on these conditions.
    * **HTTP/2 Settings:** The `AddDefaultHttp2Settings` function provides another example. The logic is to add default values only if they aren't already present.

7. **Common User/Programming Errors:**  Consider how misconfigurations or incorrect usage *outside* of this specific file could lead to issues manifested here. Examples include:

    * **Incorrect Proxy Settings:** This would affect the proxy resolution and how connections are established.
    * **Firewall Issues:**  Firewalls blocking ports would prevent connections.
    * **Outdated Browser:**  Older browsers might not support certain protocols or features configured here.
    * **Server-Side Issues:**  Problems on the server (e.g., protocol mismatches) can also surface through this code.

8. **User Actions and Debugging:**  Trace the steps a user might take that would eventually involve this code. Think about common web browsing actions:

    * Typing a URL and pressing Enter.
    * Clicking a link.
    * JavaScript code making a network request.
    * Browser automatically updating.

    Then, consider how a developer might investigate issues related to network connectivity:

    * Using the browser's developer tools (Network tab).
    * Looking at `chrome://net-internals`.
    * Examining error messages.

9. **Structure the Response:** Organize the information logically using headings and bullet points to make it easy to read and understand. Start with a summary, then delve into specific aspects.

10. **Refine and Elaborate:**  Review the generated response for clarity, accuracy, and completeness. Add more detail to explanations where needed. For instance, when explaining the JavaScript relationship, emphasize the "behind-the-scenes" nature of `http_network_session.cc`. Ensure the examples are concrete and easy to follow. Make sure to address all parts of the original request.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Focus heavily on the internal workings of the class.
* **Correction:** Realize the importance of connecting it to the broader context of web browsing and JavaScript interactions.
* **Initial Thought:**  Provide very technical explanations of each member variable.
* **Correction:**  Focus on the *functionality* they enable rather than just their names.
* **Initial Thought:**  List every possible error.
* **Correction:** Focus on *common* user and programming errors that are relevant to the functionality of this component.
* **Initial Thought:** Assume deep technical knowledge on the part of the reader.
* **Correction:** Explain concepts in a way that is accessible to someone with a general understanding of networking.

By following this structured approach, the goal is to create a comprehensive and insightful answer that addresses all aspects of the request.
这个`net/http/http_network_session.cc` 文件是 Chromium 网络栈的核心组件之一，它负责管理和维护 HTTP 网络会话。 可以将其视为一个中央协调器，用于处理所有与 HTTP(S) 连接相关的活动。

以下是其主要功能：

**核心功能：**

1. **会话管理:**
    *   创建和管理 HTTP/1.1, HTTP/2 (SPDY), 和 QUIC 会话。
    *   维护着用于不同协议的会话池 (`SpdySessionPool`, `QuicSessionPool`)，用于复用连接，提高性能。
    *   负责会话的生命周期管理，包括创建、复用、关闭等。

2. **连接管理:**
    *   通过 `ClientSocketPoolManagerImpl` 管理底层的 TCP 和 TLS 连接池，区分普通连接和 WebSocket 连接。
    *   处理连接的建立、复用和关闭。
    *   根据代理设置选择合适的连接方式。

3. **协议支持:**
    *   支持 HTTP/1.1 和 HTTP/2 协议，并通过 `SpdySessionPool` 处理 HTTP/2 连接。
    *   支持 QUIC 协议，并通过 `QuicSessionPool` 处理 QUIC 连接。
    *   根据服务器支持的协议和客户端配置，协商使用哪个协议。

4. **代理支持:**
    *   与 `ProxyResolutionService` 交互，获取代理服务器信息。
    *   根据代理配置选择合适的连接和协议。

5. **安全连接:**
    *   使用 `ssl_client_context_` 管理 TLS 连接，包括证书验证和会话缓存。
    *   处理 HTTPS 连接的建立。

6. **HTTP 服务器属性:**
    *   使用 `HttpServerProperties` 存储和检索服务器的特定属性，例如支持的协议、备用服务等，用于优化后续连接。

7. **QUIC 特定功能:**
    *   管理 QUIC 会话池，并根据配置决定是否强制使用 QUIC。
    *   处理 QUIC 连接的迁移和重试。
    *   读取和应用 QUIC 相关的配置参数。

8. **HTTP/2 (SPDY) 特定功能:**
    *   管理 HTTP/2 会话池，并处理 HTTP/2 的设置帧。
    *   支持 HTTP/2 服务器推送（尽管代码中 `kSpdyDisablePush` 表明当前版本禁用了）。

9. **性能优化:**
    *   通过连接池复用连接，减少连接建立的开销。
    *   使用 HTTP/2 和 QUIC 等更高效的协议。
    *   监听内存压力，并在内存不足时关闭空闲连接。
    *   支持 Happy Eyeballs V3 (如果启用)，加速连接建立。

10. **调试和监控:**
    *   提供方法 (`SocketPoolInfoToValue`, `SpdySessionPoolInfoToValue`, `QuicInfoToValue`) 将内部状态信息转换为可用于调试和监控的 `base::Value` 对象。

**与 JavaScript 的关系：**

虽然 `http_network_session.cc` 是 C++ 代码，JavaScript 代码本身并不能直接调用或操作它。 然而，它在 JavaScript 发起的网络请求中扮演着至关重要的角色。

当网页中的 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTP(S) 请求时，浏览器底层的网络栈就会开始工作。 `HttpNetworkSession` 就是这个过程中的关键参与者：

1. **JavaScript 发起请求:** JavaScript 代码调用 `fetch` 或 `XMLHttpRequest`。
2. **请求传递到网络栈:** 浏览器内核将请求信息传递给网络栈。
3. **`HttpNetworkSession` 处理:** `HttpNetworkSession` 负责选择合适的连接（可能从连接池中复用现有连接，或者建立新连接），选择合适的协议（HTTP/1.1, HTTP/2, QUIC），处理代理和安全连接等。
4. **数据传输:** 底层 socket 进行数据的传输。
5. **响应处理:** 网络栈接收到响应后，会将响应数据传递回 JavaScript。

**举例说明:**

假设 JavaScript 代码发起一个 `fetch('https://www.example.com')` 请求：

1. JavaScript 调用 `fetch`。
2. 浏览器网络栈接收到请求，目标 URL 是 `https://www.example.com`。
3. `HttpNetworkSession` 会检查是否已经有到 `www.example.com` 的可用 HTTPS 连接。
    *   如果有，并且协议匹配（例如，现有连接是 HTTP/2），则可能会复用该连接。
    *   如果没有，或者需要使用 QUIC，`HttpNetworkSession` 将会指示 `ClientSocketPoolManagerImpl` 或 `QuicSessionPool` 建立新的连接。
4. 如果需要建立新连接，会涉及 DNS 解析、TCP 连接建立、TLS 握手等过程。 `HttpNetworkSession` 会参与管理这些过程。
5. 一旦连接建立，HTTP 请求将被发送到服务器。
6. 服务器的响应被接收，并最终传递回 JavaScript 的 `fetch` API。

**逻辑推理示例：**

**假设输入：**

*   `HttpNetworkSession` 接收到一个请求连接到 `https://www.example.com`.
*   `HttpServerProperties` 中记录了 `www.example.com` 支持 HTTP/2 和 QUIC。
*   `params_.enable_quic` 为 `true` (QUIC 已启用)。
*   没有可复用的 HTTP/2 连接。
*   代理设置为直连。

**逻辑推理和输出：**

*   `HttpNetworkSession::ShouldForceQuic()` 会被调用。
*   `ShouldForceQuic()` 会检查 QUIC 是否启用 (`params_.enable_quic` 为 true)。
*   `ShouldForceQuic()` 会检查是否是 WebSocket 请求（不是）。
*   `ShouldForceQuic()` 会检查代理是否是直连或 QUIC 代理（是直连）。
*   `ShouldForceQuic()` 会检查 `origins_to_force_quic_on` 中是否包含 `www.example.com`。
*   **如果 `origins_to_force_quic_on` 中包含 `www.example.com`：**
    *   `ShouldForceQuic()` 返回 `true`。
    *   `HttpNetworkSession` 会尝试建立一个 QUIC 连接到 `www.example.com`。
*   **如果 `origins_to_force_quic_on` 中不包含 `www.example.com`：**
    *   `ShouldForceQuic()` 返回 `false`。
    *   `HttpNetworkSession` 会尝试建立一个 HTTP/2 连接到 `www.example.com` (因为 `HttpServerProperties` 中记录了支持)。 如果 HTTP/2 连接失败，可能会回退到 HTTP/1.1。

**用户或编程常见的使用错误：**

1. **配置错误的代理设置:** 用户在操作系统或浏览器中配置了错误的代理服务器地址或端口，导致连接无法建立。 这可能会导致 `HttpNetworkSession` 在尝试连接代理时失败。
    *   **例子:** 用户配置了一个不存在的代理服务器地址 `invalid.proxy.com:8080`。 当浏览器尝试通过这个代理连接时，`HttpNetworkSession` 会尝试连接该地址，但会因为连接超时或无法找到主机而失败。

2. **防火墙阻止连接:** 用户的防火墙软件阻止了浏览器与目标服务器或代理服务器建立连接。
    *   **例子:** 用户安装的防火墙阻止了浏览器发送到特定端口（例如 HTTPS 的 443 端口）的出站连接。 这会导致 `HttpNetworkSession` 无法建立 TCP 连接。

3. **证书错误:**  对于 HTTPS 连接，如果服务器提供的 SSL 证书无效（例如，过期、域名不匹配），`HttpNetworkSession` 中的证书验证过程会失败。
    *   **例子:**  用户访问一个使用自签名证书的 HTTPS 网站。 浏览器会因为无法信任该证书而阻止连接，`HttpNetworkSession` 会报告证书错误。

4. **网络连接问题:** 用户的网络连接不稳定或断开，导致无法建立或维持网络连接。
    *   **例子:**  用户的 Wi-Fi 连接断开，导致 `HttpNetworkSession` 尝试发送请求时失败。

5. **服务器端配置错误:** 目标服务器配置错误，例如不支持客户端尝试使用的协议，或者端口未开放。
    *   **例子:**  客户端尝试使用 HTTP/2 连接到一台只支持 HTTP/1.1 的服务器。 `HttpNetworkSession` 在尝试 HTTP/2 协商后可能会回退到 HTTP/1.1，或者直接连接失败。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏中输入一个 HTTPS URL 并按下回车键。**
    *   这将触发浏览器尝试加载该 URL 的网页。
    *   网络栈开始工作，`HttpNetworkSession` 负责处理这个 HTTPS 请求。

2. **用户点击网页上的一个 HTTPS 链接。**
    *   与上述类似，浏览器会尝试获取链接指向的资源，`HttpNetworkSession` 负责处理。

3. **网页上的 JavaScript 代码使用 `fetch` API 发起一个跨域的 HTTPS 请求。**
    *   浏览器会执行 CORS 预检请求，`HttpNetworkSession` 负责发送 OPTIONS 请求并处理响应。
    *   如果预检通过，`HttpNetworkSession` 负责发送实际的请求。

4. **浏览器需要更新其组件或下载新的扩展程序，这些操作通常涉及 HTTPS 连接。**
    *   后台的更新机制会使用网络栈，`HttpNetworkSession` 负责建立和管理这些连接。

**作为调试线索:**

当网络请求出现问题时，开发者或高级用户可以使用 Chromium 提供的调试工具 (`chrome://net-internals`) 来查看网络请求的详细信息。 这些信息会揭示 `HttpNetworkSession` 在处理请求时采取的具体步骤，例如：

*   **连接池状态:** 查看是否有可用的连接，以及连接的协议类型。
*   **DNS 解析结果:** 确认域名解析是否成功。
*   **代理协商过程:** 如果使用了代理，可以查看代理协商的细节。
*   **TLS 握手过程:** 对于 HTTPS 请求，可以查看证书验证的步骤和结果。
*   **QUIC 或 HTTP/2 会话信息:** 查看是否成功建立了 QUIC 或 HTTP/2 会话。
*   **错误信息:**  网络栈会记录详细的错误信息，帮助定位问题。

通过 `chrome://net-internals` 的事件日志，可以追踪一个特定网络请求的生命周期，观察 `HttpNetworkSession` 在每个阶段的行为，例如建立连接、发送请求头、接收响应头等。 这对于诊断网络连接问题，例如连接失败、延迟高、协议不匹配等非常有帮助。

总而言之，`net/http/http_network_session.cc` 是 Chromium 网络栈中至关重要的组成部分，它协调和管理着各种 HTTP(S) 连接，是理解浏览器如何进行网络通信的关键。

Prompt: 
```
这是目录为net/http/http_network_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_network_session.h"

#include <inttypes.h>

#include <utility>

#include "base/atomic_sequence_num.h"
#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/notreached.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_response_body_drainer.h"
#include "net/http/http_stream_factory.h"
#include "net/http/http_stream_pool.h"
#include "net/http/url_security_manager.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_crypto_client_stream_factory.h"
#include "net/quic/quic_session_pool.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/client_socket_pool_manager_impl.h"
#include "net/socket/next_proto.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_random.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_tag.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "url/scheme_host_port.h"

namespace net {

// The maximum receive window sizes for HTTP/2 sessions and streams.
const int32_t kSpdySessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
const int32_t kSpdyStreamMaxRecvWindowSize = 6 * 1024 * 1024;    //  6 MB

// Value of SETTINGS_ENABLE_PUSH reflecting that server push is not supported.
const uint32_t kSpdyDisablePush = 0;

namespace {

// Keep all HTTP2 parameters in |http2_settings|, even the ones that are not
// implemented, to be sent to the server.
// Set default values for settings that |http2_settings| does not specify.
spdy::SettingsMap AddDefaultHttp2Settings(spdy::SettingsMap http2_settings) {
  // Server push is not supported.
  http2_settings[spdy::SETTINGS_ENABLE_PUSH] = kSpdyDisablePush;

  // For other setting parameters, set default values only if |http2_settings|
  // does not have a value set for given setting.
  auto it = http2_settings.find(spdy::SETTINGS_HEADER_TABLE_SIZE);
  if (it == http2_settings.end()) {
    http2_settings[spdy::SETTINGS_HEADER_TABLE_SIZE] = kSpdyMaxHeaderTableSize;
  }

  it = http2_settings.find(spdy::SETTINGS_INITIAL_WINDOW_SIZE);
  if (it == http2_settings.end()) {
    http2_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] =
        kSpdyStreamMaxRecvWindowSize;
  }

  it = http2_settings.find(spdy::SETTINGS_MAX_HEADER_LIST_SIZE);
  if (it == http2_settings.end()) {
    http2_settings[spdy::SETTINGS_MAX_HEADER_LIST_SIZE] =
        kSpdyMaxHeaderListSize;
  }

  return http2_settings;
}

bool OriginToForceQuicOnInternal(const QuicParams& quic_params,
                                 const url::SchemeHostPort& destination) {
  // TODO(crbug.com/40181080): Consider converting `origins_to_force_quic_on` to
  // use url::SchemeHostPort.
  return (
      base::Contains(quic_params.origins_to_force_quic_on, HostPortPair()) ||
      base::Contains(quic_params.origins_to_force_quic_on,
                     HostPortPair::FromSchemeHostPort(destination)));
}

}  // unnamed namespace

HttpNetworkSessionParams::HttpNetworkSessionParams()
    : spdy_session_max_recv_window_size(kSpdySessionMaxRecvWindowSize),
      spdy_session_max_queued_capped_frames(kSpdySessionMaxQueuedCappedFrames),
      time_func(&base::TimeTicks::Now) {
  enable_early_data =
      base::FeatureList::IsEnabled(features::kEnableTLS13EarlyData);
  use_dns_https_svcb_alpn =
      base::FeatureList::IsEnabled(features::kUseDnsHttpsSvcbAlpn);
}

HttpNetworkSessionParams::HttpNetworkSessionParams(
    const HttpNetworkSessionParams& other) = default;

HttpNetworkSessionParams::~HttpNetworkSessionParams() = default;

HttpNetworkSessionContext::HttpNetworkSessionContext()
    : client_socket_factory(nullptr),
      host_resolver(nullptr),
      cert_verifier(nullptr),
      transport_security_state(nullptr),
      sct_auditing_delegate(nullptr),
      proxy_resolution_service(nullptr),
      proxy_delegate(nullptr),
      http_user_agent_settings(nullptr),
      ssl_config_service(nullptr),
      http_auth_handler_factory(nullptr),
      net_log(nullptr),
      socket_performance_watcher_factory(nullptr),
      network_quality_estimator(nullptr),
      quic_context(nullptr),
#if BUILDFLAG(ENABLE_REPORTING)
      reporting_service(nullptr),
      network_error_logging_service(nullptr),
#endif
      quic_crypto_client_stream_factory(
          QuicCryptoClientStreamFactory::GetDefaultFactory()) {
}

HttpNetworkSessionContext::HttpNetworkSessionContext(
    const HttpNetworkSessionContext& other) = default;

HttpNetworkSessionContext::~HttpNetworkSessionContext() = default;

// TODO(mbelshe): Move the socket factories into HttpStreamFactory.
HttpNetworkSession::HttpNetworkSession(const HttpNetworkSessionParams& params,
                                       const HttpNetworkSessionContext& context)
    : net_log_(context.net_log),
      http_server_properties_(context.http_server_properties),
      cert_verifier_(context.cert_verifier),
      http_auth_handler_factory_(context.http_auth_handler_factory),
      host_resolver_(context.host_resolver),
#if BUILDFLAG(ENABLE_REPORTING)
      reporting_service_(context.reporting_service),
      network_error_logging_service_(context.network_error_logging_service),
#endif
      proxy_resolution_service_(context.proxy_resolution_service),
      ssl_config_service_(context.ssl_config_service),
      http_auth_cache_(
          params.key_auth_cache_server_entries_by_network_anonymization_key),
      ssl_client_session_cache_(SSLClientSessionCache::Config()),
      ssl_client_context_(context.ssl_config_service,
                          context.cert_verifier,
                          context.transport_security_state,
                          &ssl_client_session_cache_,
                          context.sct_auditing_delegate),
      quic_session_pool_(context.net_log,
                         context.host_resolver,
                         context.ssl_config_service,
                         context.client_socket_factory,
                         context.http_server_properties,
                         context.cert_verifier,
                         context.transport_security_state,
                         context.proxy_delegate,
                         context.sct_auditing_delegate,
                         context.socket_performance_watcher_factory,
                         context.quic_crypto_client_stream_factory,
                         context.quic_context),
      spdy_session_pool_(context.host_resolver,
                         &ssl_client_context_,
                         context.http_server_properties,
                         context.transport_security_state,
                         context.quic_context->params()->supported_versions,
                         params.enable_spdy_ping_based_connection_checking,
                         params.enable_http2,
                         params.enable_quic,
                         params.spdy_session_max_recv_window_size,
                         params.spdy_session_max_queued_capped_frames,
                         AddDefaultHttp2Settings(params.http2_settings),
                         params.enable_http2_settings_grease,
                         params.greased_http2_frame,
                         params.http2_end_stream_with_data_frame,
                         params.enable_priority_update,
                         params.spdy_go_away_on_ip_change,
                         params.time_func,
                         context.network_quality_estimator,
                         // cleanup_sessions_on_ip_address_changed
                         !params.ignore_ip_address_changes),
      http_stream_factory_(std::make_unique<HttpStreamFactory>(this)),
      params_(params),
      context_(context) {
  DCHECK(proxy_resolution_service_);
  DCHECK(ssl_config_service_);
  CHECK(http_server_properties_);
  DCHECK(context_.client_socket_factory);

  normal_socket_pool_manager_ = std::make_unique<ClientSocketPoolManagerImpl>(
      CreateCommonConnectJobParams(false /* for_websockets */),
      CreateCommonConnectJobParams(true /* for_websockets */),
      NORMAL_SOCKET_POOL,
      // cleanup_on_ip_address_change
      !params.ignore_ip_address_changes);
  websocket_socket_pool_manager_ =
      std::make_unique<ClientSocketPoolManagerImpl>(
          CreateCommonConnectJobParams(false /* for_websockets */),
          CreateCommonConnectJobParams(true /* for_websockets */),
          WEBSOCKET_SOCKET_POOL,
          // cleanup_on_ip_address_change
          !params.ignore_ip_address_changes);

  if (params_.enable_http2) {
    next_protos_.push_back(kProtoHTTP2);
    if (base::FeatureList::IsEnabled(features::kAlpsForHttp2)) {
      // Enable ALPS for HTTP/2 with empty data.
      application_settings_[kProtoHTTP2] = {};
    }
  }

  next_protos_.push_back(kProtoHTTP11);

  http_server_properties_->SetMaxServerConfigsStoredInProperties(
      context.quic_context->params()->max_server_configs_stored_in_properties);
  http_server_properties_->SetBrokenAlternativeServicesDelayParams(
      context.quic_context->params()
          ->initial_delay_for_broken_alternative_service,
      context.quic_context->params()->exponential_backoff_on_initial_delay);

  if (!params_.disable_idle_sockets_close_on_memory_pressure) {
    memory_pressure_listener_ = std::make_unique<base::MemoryPressureListener>(
        FROM_HERE, base::BindRepeating(&HttpNetworkSession::OnMemoryPressure,
                                       base::Unretained(this)));
  }

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    http_stream_pool_ = std::make_unique<HttpStreamPool>(
        this,
        /*cleanup_on_ip_address_change=*/!params.ignore_ip_address_changes);
  }
}

HttpNetworkSession::~HttpNetworkSession() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (http_stream_pool_) {
    http_stream_pool_->OnShuttingDown();
  }
  response_drainers_.clear();
  // TODO(bnc): CloseAllSessions() is also called in SpdySessionPool destructor,
  // one of the two calls should be removed.
  spdy_session_pool_.CloseAllSessions();
}

void HttpNetworkSession::StartResponseDrainer(
    std::unique_ptr<HttpResponseBodyDrainer> drainer) {
  DCHECK(!base::Contains(response_drainers_, drainer.get()));
  HttpResponseBodyDrainer* drainer_ptr = drainer.get();
  response_drainers_.insert(std::move(drainer));
  drainer_ptr->Start(this);
}

void HttpNetworkSession::RemoveResponseDrainer(
    HttpResponseBodyDrainer* drainer) {
  DCHECK(base::Contains(response_drainers_, drainer));

  response_drainers_.erase(response_drainers_.find(drainer));
}

ClientSocketPool* HttpNetworkSession::GetSocketPool(
    SocketPoolType pool_type,
    const ProxyChain& proxy_chain) {
  return GetSocketPoolManager(pool_type)->GetSocketPool(proxy_chain);
}

base::Value HttpNetworkSession::SocketPoolInfoToValue() const {
  // TODO(yutak): Should merge values from normal pools and WebSocket pools.
  return normal_socket_pool_manager_->SocketPoolInfoToValue();
}

std::unique_ptr<base::Value> HttpNetworkSession::SpdySessionPoolInfoToValue()
    const {
  return spdy_session_pool_.SpdySessionPoolInfoToValue();
}

base::Value HttpNetworkSession::QuicInfoToValue() const {
  base::Value::Dict dict;
  dict.Set("sessions", quic_session_pool_.QuicSessionPoolInfoToValue());
  dict.Set("quic_enabled", IsQuicEnabled());

  const QuicParams* quic_params = context_.quic_context->params();

  base::Value::List connection_options;
  for (const auto& option : quic_params->connection_options) {
    connection_options.Append(quic::QuicTagToString(option));
  }
  dict.Set("connection_options", std::move(connection_options));

  base::Value::List supported_versions;
  for (const auto& version : quic_params->supported_versions) {
    supported_versions.Append(ParsedQuicVersionToString(version));
  }
  dict.Set("supported_versions", std::move(supported_versions));

  base::Value::List origins_to_force_quic_on;
  for (const auto& origin : quic_params->origins_to_force_quic_on) {
    origins_to_force_quic_on.Append(origin.ToString());
  }
  dict.Set("origins_to_force_quic_on", std::move(origins_to_force_quic_on));

  dict.Set("max_packet_length",
           static_cast<int>(quic_params->max_packet_length));
  dict.Set(
      "max_server_configs_stored_in_properties",
      static_cast<int>(quic_params->max_server_configs_stored_in_properties));
  dict.Set("idle_connection_timeout_seconds",
           static_cast<int>(quic_params->idle_connection_timeout.InSeconds()));
  dict.Set("reduced_ping_timeout_seconds",
           static_cast<int>(quic_params->reduced_ping_timeout.InSeconds()));
  dict.Set("retry_without_alt_svc_on_quic_errors",
           quic_params->retry_without_alt_svc_on_quic_errors);
  dict.Set("close_sessions_on_ip_change",
           quic_params->close_sessions_on_ip_change);
  dict.Set("goaway_sessions_on_ip_change",
           quic_params->goaway_sessions_on_ip_change);
  dict.Set("migrate_sessions_on_network_change_v2",
           quic_params->migrate_sessions_on_network_change_v2);
  dict.Set("migrate_sessions_early_v2", quic_params->migrate_sessions_early_v2);
  dict.Set("retransmittable_on_wire_timeout_milliseconds",
           static_cast<int>(
               quic_params->retransmittable_on_wire_timeout.InMilliseconds()));
  dict.Set("retry_on_alternate_network_before_handshake",
           quic_params->retry_on_alternate_network_before_handshake);
  dict.Set("migrate_idle_sessions", quic_params->migrate_idle_sessions);
  dict.Set(
      "idle_session_migration_period_seconds",
      static_cast<int>(quic_params->idle_session_migration_period.InSeconds()));
  dict.Set("max_time_on_non_default_network_seconds",
           static_cast<int>(
               quic_params->max_time_on_non_default_network.InSeconds()));
  dict.Set("max_num_migrations_to_non_default_network_on_write_error",
           quic_params->max_migrations_to_non_default_network_on_write_error);
  dict.Set(
      "max_num_migrations_to_non_default_network_on_path_degrading",
      quic_params->max_migrations_to_non_default_network_on_path_degrading);
  dict.Set("allow_server_migration", quic_params->allow_server_migration);
  dict.Set("estimate_initial_rtt", quic_params->estimate_initial_rtt);
  dict.Set("initial_rtt_for_handshake_milliseconds",
           static_cast<int>(
               quic_params->initial_rtt_for_handshake.InMilliseconds()));

  return base::Value(std::move(dict));
}

void HttpNetworkSession::CloseAllConnections(int net_error,
                                             const char* net_log_reason_utf8) {
  normal_socket_pool_manager_->FlushSocketPoolsWithError(net_error,
                                                         net_log_reason_utf8);
  websocket_socket_pool_manager_->FlushSocketPoolsWithError(
      net_error, net_log_reason_utf8);
  if (http_stream_pool_) {
    http_stream_pool_->FlushWithError(net_error, net_log_reason_utf8);
  }
  spdy_session_pool_.CloseCurrentSessions(static_cast<Error>(net_error));
  quic_session_pool_.CloseAllSessions(net_error, quic::QUIC_PEER_GOING_AWAY);
}

void HttpNetworkSession::CloseIdleConnections(const char* net_log_reason_utf8) {
  normal_socket_pool_manager_->CloseIdleSockets(net_log_reason_utf8);
  websocket_socket_pool_manager_->CloseIdleSockets(net_log_reason_utf8);
  if (http_stream_pool_) {
    http_stream_pool_->CloseIdleStreams(net_log_reason_utf8);
  }
  spdy_session_pool_.CloseCurrentIdleSessions(net_log_reason_utf8);
}

bool HttpNetworkSession::IsQuicEnabled() const {
  return params_.enable_quic;
}

void HttpNetworkSession::DisableQuic() {
  params_.enable_quic = false;
}

bool HttpNetworkSession::ShouldForceQuic(const url::SchemeHostPort& destination,
                                         const ProxyInfo& proxy_info,
                                         bool is_websocket) {
  if (!IsQuicEnabled()) {
    return false;
  }
  if (is_websocket) {
    return false;
  }
  // If a proxy is being used, the last proxy in the chain must be QUIC if we
  // are to use QUIC on top of it.
  if (!proxy_info.is_direct() && !proxy_info.proxy_chain().Last().is_quic()) {
    return false;
  }
  return OriginToForceQuicOnInternal(*context_.quic_context->params(),
                                     destination) &&
         GURL::SchemeIsCryptographic(destination.scheme());
}

void HttpNetworkSession::IgnoreCertificateErrorsForTesting() {
  params_.ignore_certificate_errors = true;
}

void HttpNetworkSession::ClearSSLSessionCache() {
  ssl_client_session_cache_.Flush();
}

CommonConnectJobParams HttpNetworkSession::CreateCommonConnectJobParams(
    bool for_websockets) {
  // Use null websocket_endpoint_lock_manager, which is only set for WebSockets,
  // and only when not using a proxy.
  return CommonConnectJobParams(
      context_.client_socket_factory, context_.host_resolver, &http_auth_cache_,
      context_.http_auth_handler_factory, &spdy_session_pool_,
      &context_.quic_context->params()->supported_versions, &quic_session_pool_,
      context_.proxy_delegate, context_.http_user_agent_settings,
      &ssl_client_context_, context_.socket_performance_watcher_factory,
      context_.network_quality_estimator, context_.net_log,
      for_websockets ? &websocket_endpoint_lock_manager_ : nullptr,
      context_.http_server_properties, &next_protos_, &application_settings_,
      &params_.ignore_certificate_errors, &params_.enable_early_data);
}

ClientSocketPoolManager* HttpNetworkSession::GetSocketPoolManager(
    SocketPoolType pool_type) {
  switch (pool_type) {
    case NORMAL_SOCKET_POOL:
      return normal_socket_pool_manager_.get();
    case WEBSOCKET_SOCKET_POOL:
      return websocket_socket_pool_manager_.get();
    default:
      NOTREACHED();
  }
}

void HttpNetworkSession::OnMemoryPressure(
    base::MemoryPressureListener::MemoryPressureLevel memory_pressure_level) {
  DCHECK(!params_.disable_idle_sockets_close_on_memory_pressure);

  switch (memory_pressure_level) {
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE:
      break;

    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE:
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL:
      CloseIdleConnections("Low memory");
      break;
  }
}

}  // namespace net

"""

```
Response:
The user wants to understand the functionality of the `http_server_properties.cc` file in Chromium's networking stack. They are particularly interested in:

1. **Core functionalities:** What does this file do?
2. **Relationship to JavaScript:** Does it interact with JavaScript, and if so, how?
3. **Logical Reasoning:** Examples of input and output based on the code's logic.
4. **Common Errors:**  Potential user or programming errors related to this code.
5. **Debugging:** How a user's action might lead to this code being executed.
6. **Summary:** A concise overview of the file's purpose, based on the provided first part of the code.

Let's break down the code to address each point:

**1. Core Functionalities (Based on the provided snippet):**

* **Storing Server Properties:** The file is responsible for storing and managing properties associated with HTTP servers. This includes:
    * Whether a server supports SPDY (an older version of HTTP/2).
    * Alternative services (e.g., using a different host/port or protocol like HTTP/2 or QUIC).
    * Network statistics for servers.
    * Information related to QUIC protocol support.
    * Which alternative services are currently considered "broken".
* **Persistence:** It interacts with a `PrefDelegate` (likely through `HttpServerPropertiesManager`) to persist these properties, likely to disk. This allows Chromium to remember these settings across sessions.
* **Normalization:** It normalizes `url::SchemeHostPort` objects, especially for WebSocket schemes (ws:// and wss://), converting them to their HTTP/HTTPS equivalents for internal storage.
* **Caching:** It uses LRU caches (`ServerInfoMap`, `QuicServerInfoMap`) to store server properties in memory for quick access.
* **Broken Alternative Services Tracking:** It keeps track of broken alternative services to avoid trying them repeatedly.
* **Network Anonymization Key Handling:** It considers network partitioning (using `NetworkAnonymizationKey`) when storing and retrieving server properties.

**2. Relationship to JavaScript:**

While the C++ code itself doesn't directly interact with JavaScript, the information it manages *indirectly* affects JavaScript's network requests. Here's how:

* **Faster Connections:**  By knowing that a server supports HTTP/2 or QUIC, or by knowing alternative service endpoints, Chromium can establish faster and more efficient connections. This translates to faster page load times and better user experience for websites accessed through JavaScript.
* **Security:**  Information about alternative services and protocol support can influence which protocols and ports are attempted for secure connections.
* **Developer Tools:** Developers might use browser developer tools (which are often implemented with JavaScript) to inspect the stored HTTP server properties for debugging network issues.

**Example:**

* **Scenario:** A website (`example.com`) supports HTTP/2. The first time a user visits, the browser might negotiate the protocol. The `HttpServerProperties` would store this information.
* **JavaScript Impact:**  On subsequent visits initiated by JavaScript (e.g., `fetch()` calls), the browser can directly attempt an HTTP/2 connection based on the stored property, making the request faster.

**3. Logical Reasoning (Hypothetical):**

**Assumption:**  The `SetSupportsSpdy` function is called.

**Input:**

* `server`: `https://www.example.com:443`
* `network_anonymization_key`: (Let's assume an empty key for simplicity)
* `supports_spdy`: `true`

**Output:**

* The `server_info_map_` will have an entry for `https://www.example.com:443` with its `supports_spdy` field set to `true`.
* The `MaybeQueueWriteProperties()` function will likely be called, potentially scheduling a write to persistent storage.

**Assumption:** The `GetAlternativeServiceInfos` function is called.

**Input:**

* `origin`: `https://www.example.com:443`
* `network_anonymization_key`: (Empty key)

**Scenario 1: Alternative services are known and valid.**

* **Assume `server_info_map_` contains an entry for `https://www.example.com:443` with an alternative service: `h2://alt.example.com:443` (with a future expiration).**
* **Output:**  The function will return a vector containing an `AlternativeServiceInfo` object representing `h2://alt.example.com:443`.

**Scenario 2: Alternative services are expired.**

* **Assume `server_info_map_` contains an entry for `https://www.example.com:443` with an alternative service: `h2://alt.example.com:443` (with an expiration in the past).**
* **Output:** The function will return an empty vector, and the expired alternative service will be removed from `server_info_map_`.

**4. Common Errors:**

* **Incorrect Host/Port:**  If a program incorrectly provides the host or port when setting or getting server properties, the information might not be stored or retrieved correctly. For example, using `http://example.com:80` when the server is accessed via `https://example.com:443`.
* **Forgetting Network Partitioning:** In scenarios where network partitioning is enabled, failing to provide the correct `NetworkAnonymizationKey` will lead to incorrect property lookups.
* **Incorrect Protocol Handling:**  Mistakes in normalizing or checking the protocol scheme could lead to properties not being associated with the correct server. The code has explicit normalization for WebSocket schemes, but errors could occur if other less common protocols are not handled correctly.
* **Premature Optimization/Caching Issues:** Incorrectly assuming server properties remain static can lead to issues if server configurations change. The caching mechanism helps, but relying on outdated information can cause problems.

**5. User Actions and Debugging:**

A user's actions can lead to this code being executed in various ways. Here's a step-by-step example:

1. **User types `https://www.example.com` in the address bar and presses Enter.**
2. **Chromium's network stack initiates a connection to `www.example.com`.**
3. **During the connection establishment (e.g., TLS handshake), the server might indicate support for HTTP/2 or provide alternative service information in the HTTP headers (e.g., `Alt-Svc`).**
4. **The code in `http_server_properties.cc` would be called to store this information using functions like `SetSupportsSpdyInternal` or `SetAlternativeServicesInternal`.**
5. **If the connection fails using a specific alternative service, functions like `MarkAlternativeServiceBroken` would be called.**
6. **On subsequent requests to `www.example.com`, the code would be consulted using functions like `GetSupportsSpdy` or `GetAlternativeServiceInfos` to optimize the connection.**

**Debugging:**

* **Network Logging:** Chromium's NetLog (accessible via `chrome://net-export/`) can provide detailed information about network events, including when server properties are being accessed and updated. This can help trace the execution flow.
* **Developer Tools:** The "Network" tab in Chrome's Developer Tools shows the protocols used for connections and any alternative service information received.
* **Internal Inspection Tools:** Chromium has internal debugging pages (like `chrome://net-internals/#httpServerProperties`) that might show the currently stored server properties.

**6. Summary of Functionality (Part 1):**

Based on the provided code snippet, the primary function of `net/http/http_server_properties.cc` is to **manage and cache HTTP server properties, including support for modern protocols like HTTP/2 and QUIC, alternative service configurations, and tracking of broken alternative services.** It acts as a central repository for this information within Chromium's networking stack, enabling optimizations and influencing connection establishment decisions. The code also demonstrates awareness of network partitioning through the use of `NetworkAnonymizationKey`.

这是 `net/http/http_server_properties.cc` 文件的第一部分，其主要功能是**管理和缓存 HTTP 服务器的属性，包括对 SPDY、HTTP/2 和 QUIC 等协议的支持信息，以及服务器提供的备用服务信息。**  这个文件维护了一个本地的服务器属性数据库，以便浏览器能够记住之前与服务器的交互信息，从而优化后续的连接过程。

以下是基于代码的更详细的功能归纳：

**核心功能:**

1. **存储服务器协议支持:**  记录服务器是否支持 SPDY (已过时但代码中仍有提及) 和 HTTP/2。
2. **存储备用服务信息 (Alternative Services):**  记录服务器声明的备用连接方式，例如在不同的主机名、端口或使用不同的协议 (如 HTTP/2 或 QUIC) 进行连接。
3. **记录已损坏的备用服务:**  维护一个列表，记录哪些备用服务在过去被检测为不可用，以便在一段时间内避免再次尝试连接。
4. **处理网络分区 (Network Anonymization Key):**  考虑网络分区，为不同的网络分区存储不同的服务器属性，以增强隐私性。
5. **使用 LRU 缓存:**  使用最近最少使用 (LRU) 缓存策略来管理内存中的服务器属性，以便高效地访问常用服务器的信息。
6. **与持久化存储交互:**  通过 `HttpServerPropertiesManager` 与持久化存储 (例如，浏览器配置文件) 交互，以便在浏览器重启后保留服务器属性。
7. **规范化服务器标识:**  对 `url::SchemeHostPort` 进行规范化处理，例如将 WebSocket 的 scheme (`ws://`, `wss://`) 转换为对应的 HTTP/HTTPS scheme。
8. **管理 QUIC 服务器信息:**  专门管理与 QUIC 协议相关的服务器信息，例如 QUIC 配置。
9. **记录 QUIC 工作时的本地地址:**  存储上次 QUIC 连接成功时的本地 IP 地址，用于某些优化场景。
10. **处理服务器网络统计信息:**  存储和管理服务器的网络统计信息。

**与 JavaScript 的关系 (间接):**

此 C++ 代码本身不直接与 JavaScript 交互。然而，它所管理的信息会**间接地影响** JavaScript 发起的网络请求的行为：

* **加速连接:**  通过记住服务器支持 HTTP/2 或 QUIC，浏览器可以直接尝试使用这些更高效的协议，加速 JavaScript 发起的 `fetch()` 或 `XMLHttpRequest` 请求。
* **选择备用服务:**  如果 JavaScript 请求的目标服务器声明了备用服务，浏览器可以根据这里存储的信息尝试连接到备用服务，可能获得更快的连接速度或更好的网络路径。
* **避免连接失败:**  通过记住哪些备用服务已损坏，浏览器可以避免尝试连接到这些已知的不可用服务，减少连接失败的可能性。

**举例说明 (假设输入与输出):**

**假设输入:**  浏览器接收到来自 `https://www.example.com` 的 HTTP 响应头，其中包含以下 `Alt-Svc` 头信息: `h2=":443", hq=":443"` (表示支持 HTTP/2 和 QUIC)。

**逻辑推理:**

1. `SetAlternativeServicesInternal` 函数会被调用，参数包括 `https://www.example.com:443` 和解析后的备用服务信息。
2. 这些备用服务信息会被存储在 `server_info_map_` 中，与 `https://www.example.com:443` 关联。
3. `MaybeQueueWriteProperties()` 函数会被调用，将这些信息排队写入持久化存储。

**输出:**

* 下次访问 `https://www.example.com` 时，`GetAlternativeServiceInfos` 函数会返回之前存储的备用服务信息，JavaScript 发起的请求可能会尝试连接到 `h2://www.example.com:443` 或 `hq://www.example.com:443`。

**用户或编程常见的使用错误 (举例说明):**

* **错误地假设服务器支持特定协议:**  如果开发者在 JavaScript 代码中强制使用 HTTP/2，但 `HttpServerProperties` 中没有记录该服务器支持 HTTP/2，则连接可能会失败或回退到 HTTP/1.1。
* **忽略网络分区:**  如果应用程序没有正确处理网络分区，可能会在不同的网络环境下获取到错误的服务器属性，导致连接异常。例如，在移动网络和 Wi-Fi 网络下，服务器的备用服务可能不同。
* **清理浏览器数据导致重新学习:**  用户清理浏览器缓存或网络设置会清除 `HttpServerProperties` 中存储的信息，导致浏览器需要重新“学习”服务器的属性，最初的连接可能会稍慢。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在地址栏输入 URL 并访问网站 (例如 `https://www.example.com`).**
2. **浏览器发起连接请求。**
3. **服务器在响应头中声明对 HTTP/2 或 QUIC 的支持 (或提供备用服务信息)。**
4. **网络栈解析这些头信息。**
5. **`SetSupportsSpdyInternal` 或 `SetAlternativeServicesInternal` 等函数被调用，将这些信息存储到 `HttpServerProperties` 中。**
6. **后续用户再次访问该网站时，网络栈会查询 `HttpServerProperties`，以决定最优的连接方式。**
7. **如果连接到备用服务失败，`MarkAlternativeServiceBroken` 等函数会被调用。**

**总结 (功能归纳):**

`net/http/http_server_properties.cc` 文件的主要职责是**在 Chromium 浏览器中维护和管理 HTTP 服务器的连接属性，以便优化后续的网络连接。** 它缓存了服务器的协议支持信息、备用服务信息以及已损坏的备用服务，并考虑了网络分区的影响。这个组件是浏览器网络栈中用于提升性能和效率的关键部分。

### 提示词
```
这是目录为net/http/http_server_properties.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties.h"

#include "base/check_op.h"
#include "base/containers/adapters.h"
#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_clock.h"
#include "base/time/default_tick_clock.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/url_util.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties_manager.h"
#include "net/socket/ssl_client_socket.h"
#include "net/ssl/ssl_config.h"

namespace net {

namespace {

// Time to wait before starting an update the preferences from the
// http_server_properties_impl_ cache. Scheduling another update during this
// period will be a no-op.
constexpr base::TimeDelta kUpdatePrefsDelay = base::Seconds(60);

url::SchemeHostPort NormalizeSchemeHostPort(
    const url::SchemeHostPort& scheme_host_port) {
  if (scheme_host_port.scheme() == url::kWssScheme) {
    return url::SchemeHostPort(url::kHttpsScheme, scheme_host_port.host(),
                               scheme_host_port.port());
  }
  if (scheme_host_port.scheme() == url::kWsScheme) {
    return url::SchemeHostPort(url::kHttpScheme, scheme_host_port.host(),
                               scheme_host_port.port());
  }
  return scheme_host_port;
}

}  // namespace

HttpServerProperties::PrefDelegate::~PrefDelegate() = default;

HttpServerProperties::ServerInfo::ServerInfo() = default;
HttpServerProperties::ServerInfo::ServerInfo(const ServerInfo& server_info) =
    default;
HttpServerProperties::ServerInfo::ServerInfo(ServerInfo&& server_info) =
    default;
HttpServerProperties::ServerInfo::~ServerInfo() = default;

bool HttpServerProperties::ServerInfo::empty() const {
  return !supports_spdy.has_value() && !alternative_services.has_value() &&
         !server_network_stats.has_value();
}

bool HttpServerProperties::ServerInfo::operator==(
    const ServerInfo& other) const {
  return supports_spdy == other.supports_spdy &&
         alternative_services == other.alternative_services &&
         server_network_stats == other.server_network_stats;
}

HttpServerProperties::ServerInfoMapKey::ServerInfoMapKey(
    url::SchemeHostPort server,
    const NetworkAnonymizationKey& network_anonymization_key,
    bool use_network_anonymization_key)
    : server(std::move(server)),
      network_anonymization_key(use_network_anonymization_key
                                    ? network_anonymization_key
                                    : NetworkAnonymizationKey()) {
  // Scheme should have been normalized before this method was called.
  DCHECK_NE(this->server.scheme(), url::kWsScheme);
  DCHECK_NE(this->server.scheme(), url::kWssScheme);
}

HttpServerProperties::ServerInfoMapKey::~ServerInfoMapKey() = default;

bool HttpServerProperties::ServerInfoMapKey::operator<(
    const ServerInfoMapKey& other) const {
  return std::tie(server, network_anonymization_key) <
         std::tie(other.server, other.network_anonymization_key);
}

HttpServerProperties::QuicServerInfoMapKey::QuicServerInfoMapKey(
    const quic::QuicServerId& server_id,
    PrivacyMode privacy_mode,
    const NetworkAnonymizationKey& network_anonymization_key,
    bool use_network_anonymization_key)
    : server_id(server_id),
      privacy_mode(privacy_mode),
      network_anonymization_key(use_network_anonymization_key
                                    ? network_anonymization_key
                                    : NetworkAnonymizationKey()) {}

HttpServerProperties::QuicServerInfoMapKey::~QuicServerInfoMapKey() = default;

bool HttpServerProperties::QuicServerInfoMapKey::operator<(
    const QuicServerInfoMapKey& other) const {
  return std::tie(server_id, privacy_mode, network_anonymization_key) <
         std::tie(other.server_id, other.privacy_mode,
                  other.network_anonymization_key);
}

// Used in tests.
bool HttpServerProperties::QuicServerInfoMapKey::operator==(
    const QuicServerInfoMapKey& other) const {
  return std::tie(server_id, privacy_mode, network_anonymization_key) ==
         std::tie(other.server_id, other.privacy_mode,
                  other.network_anonymization_key);
}

HttpServerProperties::ServerInfoMap::ServerInfoMap()
    : base::LRUCache<ServerInfoMapKey, ServerInfo>(kMaxServerInfoEntries) {}

HttpServerProperties::ServerInfoMap::iterator
HttpServerProperties::ServerInfoMap::GetOrPut(const ServerInfoMapKey& key) {
  auto it = Get(key);
  if (it != end())
    return it;
  return Put(key, ServerInfo());
}

HttpServerProperties::ServerInfoMap::iterator
HttpServerProperties::ServerInfoMap::EraseIfEmpty(iterator server_info_it) {
  if (server_info_it->second.empty())
    return Erase(server_info_it);
  return ++server_info_it;
}

HttpServerProperties::HttpServerProperties(
    std::unique_ptr<PrefDelegate> pref_delegate,
    NetLog* net_log,
    const base::TickClock* tick_clock,
    base::Clock* clock)
    : tick_clock_(tick_clock ? tick_clock
                             : base::DefaultTickClock::GetInstance()),
      clock_(clock ? clock : base::DefaultClock::GetInstance()),
      use_network_anonymization_key_(
          NetworkAnonymizationKey::IsPartitioningEnabled()),
      is_initialized_(pref_delegate.get() == nullptr),
      properties_manager_(
          pref_delegate
              ? std::make_unique<HttpServerPropertiesManager>(
                    std::move(pref_delegate),
                    base::BindOnce(&HttpServerProperties::OnPrefsLoaded,
                                   base::Unretained(this)),
                    kDefaultMaxQuicServerEntries,
                    net_log,
                    tick_clock_)
              : nullptr),
      broken_alternative_services_(kMaxRecentlyBrokenAlternativeServiceEntries,
                                   this,
                                   tick_clock_),
      canonical_suffixes_({".ggpht.com", ".c.youtube.com", ".googlevideo.com",
                           ".googleusercontent.com", ".gvt1.com"}),
      quic_server_info_map_(kDefaultMaxQuicServerEntries),
      max_server_configs_stored_in_properties_(kDefaultMaxQuicServerEntries) {}

HttpServerProperties::~HttpServerProperties() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (properties_manager_) {
    // Stop waiting for initial settings.
    is_initialized_ = true;

    // Stop the timer if it's running, since this will write to the properties
    // file immediately.
    prefs_update_timer_.Stop();

    WriteProperties(base::OnceClosure());
  }
}

void HttpServerProperties::Clear(base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  server_info_map_.Clear();
  broken_alternative_services_.Clear();
  canonical_alt_svc_map_.clear();
  last_local_address_when_quic_worked_ = IPAddress();
  quic_server_info_map_.Clear();
  canonical_server_info_map_.clear();

  if (properties_manager_) {
    // Stop waiting for initial settings.
    is_initialized_ = true;
    // Leaving this as-is doesn't actually have any effect, if it's true, but
    // seems best to be safe.
    queue_write_on_load_ = false;

    // Stop the timer if it's running, since this will write to the properties
    // file immediately.
    prefs_update_timer_.Stop();
    WriteProperties(std::move(callback));
  } else if (callback) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(callback));
  }
}

bool HttpServerProperties::SupportsRequestPriority(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (server.host().empty())
    return false;

  if (GetSupportsSpdy(server, network_anonymization_key))
    return true;
  const AlternativeServiceInfoVector alternative_service_info_vector =
      GetAlternativeServiceInfos(server, network_anonymization_key);
  for (const AlternativeServiceInfo& alternative_service_info :
       alternative_service_info_vector) {
    if (alternative_service_info.alternative_service().protocol == kProtoQUIC) {
      return true;
    }
  }
  return false;
}

bool HttpServerProperties::GetSupportsSpdy(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return GetSupportsSpdyInternal(NormalizeSchemeHostPort(server),
                                 network_anonymization_key);
}

void HttpServerProperties::SetSupportsSpdy(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key,
    bool supports_spdy) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SetSupportsSpdyInternal(NormalizeSchemeHostPort(server),
                          network_anonymization_key, supports_spdy);
}

bool HttpServerProperties::RequiresHTTP11(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return RequiresHTTP11Internal(NormalizeSchemeHostPort(server),
                                network_anonymization_key);
}

void HttpServerProperties::SetHTTP11Required(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SetHTTP11RequiredInternal(NormalizeSchemeHostPort(server),
                            network_anonymization_key);
}

void HttpServerProperties::MaybeForceHTTP11(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key,
    SSLConfig* ssl_config) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  MaybeForceHTTP11Internal(NormalizeSchemeHostPort(server),
                           network_anonymization_key, ssl_config);
}

AlternativeServiceInfoVector HttpServerProperties::GetAlternativeServiceInfos(
    const url::SchemeHostPort& origin,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return GetAlternativeServiceInfosInternal(NormalizeSchemeHostPort(origin),
                                            network_anonymization_key);
}

void HttpServerProperties::SetHttp2AlternativeService(
    const url::SchemeHostPort& origin,
    const NetworkAnonymizationKey& network_anonymization_key,
    const AlternativeService& alternative_service,
    base::Time expiration) {
  DCHECK_EQ(alternative_service.protocol, kProtoHTTP2);

  SetAlternativeServices(
      origin, network_anonymization_key,
      AlternativeServiceInfoVector(
          /*size=*/1, AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
                          alternative_service, expiration)));
}

void HttpServerProperties::SetQuicAlternativeService(
    const url::SchemeHostPort& origin,
    const NetworkAnonymizationKey& network_anonymization_key,
    const AlternativeService& alternative_service,
    base::Time expiration,
    const quic::ParsedQuicVersionVector& advertised_versions) {
  DCHECK(alternative_service.protocol == kProtoQUIC);

  SetAlternativeServices(
      origin, network_anonymization_key,
      AlternativeServiceInfoVector(
          /*size=*/1,
          AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
              alternative_service, expiration, advertised_versions)));
}

void HttpServerProperties::SetAlternativeServices(
    const url::SchemeHostPort& origin,
    const NetworkAnonymizationKey& network_anonymization_key,
    const AlternativeServiceInfoVector& alternative_service_info_vector) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SetAlternativeServicesInternal(NormalizeSchemeHostPort(origin),
                                 network_anonymization_key,
                                 alternative_service_info_vector);
}

void HttpServerProperties::MarkAlternativeServiceBroken(
    const AlternativeService& alternative_service,
    const NetworkAnonymizationKey& network_anonymization_key) {
  broken_alternative_services_.MarkBroken(
      BrokenAlternativeService(alternative_service, network_anonymization_key,
                               use_network_anonymization_key_));
  MaybeQueueWriteProperties();
}

void HttpServerProperties::
    MarkAlternativeServiceBrokenUntilDefaultNetworkChanges(
        const AlternativeService& alternative_service,
        const NetworkAnonymizationKey& network_anonymization_key) {
  broken_alternative_services_.MarkBrokenUntilDefaultNetworkChanges(
      BrokenAlternativeService(alternative_service, network_anonymization_key,
                               use_network_anonymization_key_));
  MaybeQueueWriteProperties();
}

void HttpServerProperties::MarkAlternativeServiceRecentlyBroken(
    const AlternativeService& alternative_service,
    const NetworkAnonymizationKey& network_anonymization_key) {
  broken_alternative_services_.MarkRecentlyBroken(
      BrokenAlternativeService(alternative_service, network_anonymization_key,
                               use_network_anonymization_key_));
  MaybeQueueWriteProperties();
}

bool HttpServerProperties::IsAlternativeServiceBroken(
    const AlternativeService& alternative_service,
    const NetworkAnonymizationKey& network_anonymization_key) const {
  return broken_alternative_services_.IsBroken(
      BrokenAlternativeService(alternative_service, network_anonymization_key,
                               use_network_anonymization_key_));
}

bool HttpServerProperties::WasAlternativeServiceRecentlyBroken(
    const AlternativeService& alternative_service,
    const NetworkAnonymizationKey& network_anonymization_key) {
  return broken_alternative_services_.WasRecentlyBroken(
      BrokenAlternativeService(alternative_service, network_anonymization_key,
                               use_network_anonymization_key_));
}

void HttpServerProperties::ConfirmAlternativeService(
    const AlternativeService& alternative_service,
    const NetworkAnonymizationKey& network_anonymization_key) {
  bool old_value = IsAlternativeServiceBroken(alternative_service,
                                              network_anonymization_key);
  broken_alternative_services_.Confirm(
      BrokenAlternativeService(alternative_service, network_anonymization_key,
                               use_network_anonymization_key_));
  bool new_value = IsAlternativeServiceBroken(alternative_service,
                                              network_anonymization_key);

  // For persisting, we only care about the value returned by
  // IsAlternativeServiceBroken. If that value changes, then call persist.
  if (old_value != new_value)
    MaybeQueueWriteProperties();
}

void HttpServerProperties::OnDefaultNetworkChanged() {
  bool changed = broken_alternative_services_.OnDefaultNetworkChanged();
  if (changed)
    MaybeQueueWriteProperties();
}

base::Value HttpServerProperties::GetAlternativeServiceInfoAsValue() const {
  const base::Time now = clock_->Now();
  const base::TimeTicks now_ticks = tick_clock_->NowTicks();
  base::Value::List dict_list;
  for (const auto& server_info : server_info_map_) {
    if (!server_info.second.alternative_services.has_value())
      continue;
    base::Value::List alternative_service_list;
    const ServerInfoMapKey& key = server_info.first;
    for (const AlternativeServiceInfo& alternative_service_info :
         server_info.second.alternative_services.value()) {
      std::string alternative_service_string(
          alternative_service_info.ToString());
      AlternativeService alternative_service(
          alternative_service_info.alternative_service());
      if (alternative_service.host.empty()) {
        alternative_service.host = key.server.host();
      }
      base::TimeTicks brokenness_expiration_ticks;
      if (broken_alternative_services_.IsBroken(
              BrokenAlternativeService(
                  alternative_service,
                  server_info.first.network_anonymization_key,
                  use_network_anonymization_key_),
              &brokenness_expiration_ticks)) {
        // Convert |brokenness_expiration| from TimeTicks to Time.
        //
        // Note: Cannot use `base::UnlocalizedTimeFormatWithPattern()` since
        // `net/DEPS` disallows `base/i18n`.
        base::Time brokenness_expiration =
            now + (brokenness_expiration_ticks - now_ticks);
        base::Time::Exploded exploded;
        brokenness_expiration.LocalExplode(&exploded);
        std::string broken_info_string =
            " (broken until " +
            base::StringPrintf("%04d-%02d-%02d %0d:%0d:%0d", exploded.year,
                               exploded.month, exploded.day_of_month,
                               exploded.hour, exploded.minute,
                               exploded.second) +
            ")";
        alternative_service_string.append(broken_info_string);
      }
      alternative_service_list.Append(std::move(alternative_service_string));
    }
    if (alternative_service_list.empty())
      continue;
    base::Value::Dict dict;
    dict.Set("server", key.server.Serialize());
    dict.Set("network_anonymization_key",
             key.network_anonymization_key.ToDebugString());
    dict.Set("alternative_service", std::move(alternative_service_list));
    dict_list.Append(std::move(dict));
  }
  return base::Value(std::move(dict_list));
}

bool HttpServerProperties::WasLastLocalAddressWhenQuicWorked(
    const IPAddress& local_address) const {
  return !last_local_address_when_quic_worked_.empty() &&
         last_local_address_when_quic_worked_ == local_address;
}

bool HttpServerProperties::HasLastLocalAddressWhenQuicWorked() const {
  return !last_local_address_when_quic_worked_.empty();
}

void HttpServerProperties::SetLastLocalAddressWhenQuicWorked(
    IPAddress last_local_address_when_quic_worked) {
  DCHECK(!last_local_address_when_quic_worked.empty());
  if (last_local_address_when_quic_worked_ ==
      last_local_address_when_quic_worked) {
    return;
  }

  last_local_address_when_quic_worked_ = last_local_address_when_quic_worked;
  MaybeQueueWriteProperties();
}

void HttpServerProperties::ClearLastLocalAddressWhenQuicWorked() {
  if (last_local_address_when_quic_worked_.empty())
    return;

  last_local_address_when_quic_worked_ = IPAddress();
  MaybeQueueWriteProperties();
}

void HttpServerProperties::SetServerNetworkStats(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key,
    ServerNetworkStats stats) {
  SetServerNetworkStatsInternal(NormalizeSchemeHostPort(server),
                                network_anonymization_key, std::move(stats));
}

void HttpServerProperties::ClearServerNetworkStats(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  ClearServerNetworkStatsInternal(NormalizeSchemeHostPort(server),
                                  network_anonymization_key);
}

const ServerNetworkStats* HttpServerProperties::GetServerNetworkStats(
    const url::SchemeHostPort& server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  return GetServerNetworkStatsInternal(NormalizeSchemeHostPort(server),
                                       network_anonymization_key);
}

void HttpServerProperties::SetQuicServerInfo(
    const quic::QuicServerId& server_id,
    PrivacyMode privacy_mode,
    const NetworkAnonymizationKey& network_anonymization_key,
    const std::string& server_info) {
  QuicServerInfoMapKey key = CreateQuicServerInfoKey(server_id, privacy_mode,
                                                     network_anonymization_key);
  auto it = quic_server_info_map_.Peek(key);
  bool changed =
      (it == quic_server_info_map_.end() || it->second != server_info);
  quic_server_info_map_.Put(key, server_info);
  UpdateCanonicalServerInfoMap(key);
  if (changed)
    MaybeQueueWriteProperties();
}

const std::string* HttpServerProperties::GetQuicServerInfo(
    const quic::QuicServerId& server_id,
    PrivacyMode privacy_mode,
    const NetworkAnonymizationKey& network_anonymization_key) {
  QuicServerInfoMapKey key = CreateQuicServerInfoKey(server_id, privacy_mode,
                                                     network_anonymization_key);
  auto it = quic_server_info_map_.Get(key);
  if (it != quic_server_info_map_.end()) {
    // Since |canonical_server_info_map_| should always map to the most
    // recent host, update it with the one that became MRU in
    // |quic_server_info_map_|.
    UpdateCanonicalServerInfoMap(key);
    return &it->second;
  }

  // If the exact match for |server_id| wasn't found, check
  // |canonical_server_info_map_| whether there is server info for a host with
  // the same canonical host suffix.
  auto canonical_itr = GetCanonicalServerInfoHost(key);
  if (canonical_itr == canonical_server_info_map_.end())
    return nullptr;

  // When search in |quic_server_info_map_|, do not change the MRU order.
  it = quic_server_info_map_.Peek(CreateQuicServerInfoKey(
      canonical_itr->second, privacy_mode, network_anonymization_key));
  if (it != quic_server_info_map_.end())
    return &it->second;

  return nullptr;
}

const HttpServerProperties::QuicServerInfoMap&
HttpServerProperties::quic_server_info_map() const {
  return quic_server_info_map_;
}

size_t HttpServerProperties::max_server_configs_stored_in_properties() const {
  return max_server_configs_stored_in_properties_;
}

void HttpServerProperties::SetMaxServerConfigsStoredInProperties(
    size_t max_server_configs_stored_in_properties) {
  // Do nothing if the new size is the same as the old one.
  if (max_server_configs_stored_in_properties_ ==
      max_server_configs_stored_in_properties) {
    return;
  }

  max_server_configs_stored_in_properties_ =
      max_server_configs_stored_in_properties;

  // LRUCache doesn't allow the capacity of the cache to be changed. Thus create
  // a new map with the new size and add current elements and swap the new map.
  quic_server_info_map_.ShrinkToSize(max_server_configs_stored_in_properties_);
  QuicServerInfoMap temp_map(max_server_configs_stored_in_properties_);
  // Update the |canonical_server_info_map_| as well, so it stays in sync with
  // |quic_server_info_map_|.
  canonical_server_info_map_ = QuicCanonicalMap();
  for (const auto& [key, server_info] : base::Reversed(quic_server_info_map_)) {
    temp_map.Put(key, server_info);
    UpdateCanonicalServerInfoMap(key);
  }

  quic_server_info_map_.Swap(temp_map);
  if (properties_manager_) {
    properties_manager_->set_max_server_configs_stored_in_properties(
        max_server_configs_stored_in_properties);
  }
}

void HttpServerProperties::SetBrokenAlternativeServicesDelayParams(
    std::optional<base::TimeDelta> initial_delay,
    std::optional<bool> exponential_backoff_on_initial_delay) {
  broken_alternative_services_.SetDelayParams(
      initial_delay, exponential_backoff_on_initial_delay);
}

bool HttpServerProperties::IsInitialized() const {
  return is_initialized_;
}

void HttpServerProperties::OnExpireBrokenAlternativeService(
    const AlternativeService& expired_alternative_service,
    const NetworkAnonymizationKey& network_anonymization_key) {
  // Remove every occurrence of |expired_alternative_service| from
  // |alternative_service_map_|.
  for (auto map_it = server_info_map_.begin();
       map_it != server_info_map_.end();) {
    if (!map_it->second.alternative_services.has_value() ||
        map_it->first.network_anonymization_key != network_anonymization_key) {
      ++map_it;
      continue;
    }
    AlternativeServiceInfoVector* service_info =
        &map_it->second.alternative_services.value();
    for (auto it = service_info->begin(); it != service_info->end();) {
      AlternativeService alternative_service(it->alternative_service());
      // Empty hostname in map means hostname of key: substitute before
      // comparing to |expired_alternative_service|.
      if (alternative_service.host.empty()) {
        alternative_service.host = map_it->first.server.host();
      }
      if (alternative_service == expired_alternative_service) {
        it = service_info->erase(it);
        continue;
      }
      ++it;
    }
    // If an origin has an empty list of alternative services, then remove it
    // from both |canonical_alt_svc_map_| and
    // |alternative_service_map_|.
    if (service_info->empty()) {
      RemoveAltSvcCanonicalHost(map_it->first.server,
                                network_anonymization_key);
      map_it->second.alternative_services.reset();
      map_it = server_info_map_.EraseIfEmpty(map_it);
      continue;
    }
    ++map_it;
  }
}

base::TimeDelta HttpServerProperties::GetUpdatePrefsDelayForTesting() {
  return kUpdatePrefsDelay;
}

bool HttpServerProperties::GetSupportsSpdyInternal(
    url::SchemeHostPort server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(server.scheme(), url::kWsScheme);
  DCHECK_NE(server.scheme(), url::kWssScheme);
  if (server.host().empty())
    return false;

  auto server_info = server_info_map_.Get(
      CreateServerInfoKey(std::move(server), network_anonymization_key));
  return server_info != server_info_map_.end() &&
         server_info->second.supports_spdy.value_or(false);
}

void HttpServerProperties::SetSupportsSpdyInternal(
    url::SchemeHostPort server,
    const NetworkAnonymizationKey& network_anonymization_key,
    bool supports_spdy) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(server.scheme(), url::kWsScheme);
  DCHECK_NE(server.scheme(), url::kWssScheme);
  if (server.host().empty())
    return;

  auto server_info = server_info_map_.GetOrPut(
      CreateServerInfoKey(std::move(server), network_anonymization_key));
  // If value is already the same as |supports_spdy|, or value is unset and
  // |supports_spdy| is false, don't queue a write.
  bool queue_write =
      server_info->second.supports_spdy.value_or(false) != supports_spdy;
  server_info->second.supports_spdy = supports_spdy;

  if (queue_write)
    MaybeQueueWriteProperties();
}

bool HttpServerProperties::RequiresHTTP11Internal(
    url::SchemeHostPort server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(server.scheme(), url::kWsScheme);
  DCHECK_NE(server.scheme(), url::kWssScheme);
  if (server.host().empty())
    return false;

  auto spdy_info = server_info_map_.Get(
      CreateServerInfoKey(std::move(server), network_anonymization_key));
  return spdy_info != server_info_map_.end() &&
         spdy_info->second.requires_http11.value_or(false);
}

void HttpServerProperties::SetHTTP11RequiredInternal(
    url::SchemeHostPort server,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(server.scheme(), url::kWsScheme);
  DCHECK_NE(server.scheme(), url::kWssScheme);
  if (server.host().empty())
    return;

  server_info_map_
      .GetOrPut(
          CreateServerInfoKey(std::move(server), network_anonymization_key))
      ->second.requires_http11 = true;
  // No need to call MaybeQueueWriteProperties(), as this information is not
  // persisted to preferences.
}

void HttpServerProperties::MaybeForceHTTP11Internal(
    url::SchemeHostPort server,
    const NetworkAnonymizationKey& network_anonymization_key,
    SSLConfig* ssl_config) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(server.scheme(), url::kWsScheme);
  DCHECK_NE(server.scheme(), url::kWssScheme);
  if (RequiresHTTP11(std::move(server), network_anonymization_key)) {
    ssl_config->alpn_protos.clear();
    ssl_config->alpn_protos.push_back(kProtoHTTP11);
  }
}

AlternativeServiceInfoVector
HttpServerProperties::GetAlternativeServiceInfosInternal(
    const url::SchemeHostPort& origin,
    const NetworkAnonymizationKey& network_anonymization_key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(origin.scheme(), url::kWsScheme);
  DCHECK_NE(origin.scheme(), url::kWssScheme);

  // Copy valid alternative service infos into
  // |valid_alternative_service_infos|.
  AlternativeServiceInfoVector valid_alternative_service_infos;
  const base::Time now = clock_->Now();
  auto map_it = server_info_map_.Get(
      CreateServerInfoKey(origin, network_anonymization_key));
  if (map_it != server_info_map_.end() &&
      map_it->second.alternative_services.has_value()) {
    AlternativeServiceInfoVector* service_info =
        &map_it->second.alternative_services.value();
    HostPortPair host_port_pair(origin.host(), origin.port());
    for (auto it = service_info->begin(); it != service_info->end();) {
      if (it->expiration() < now) {
        it = service_info->erase(it);
        continue;
      }
      AlternativeService alternative_service(it->alternative_service());
      if (alternative_service.host.empty()) {
        alternative_service.host = origin.host();
      }
      // If the alternative service is equivalent to the origin (same host, same
      // port, and both TCP), skip it.
      if (host_port_pair.Equals(alternative_service.host_port_pair()) &&
          alternative_service.protocol == kProtoHTTP2) {
        ++it;
        continue;
      }
      if (alternative_service.protocol == kProtoQUIC) {
        valid_alternative_service_infos.push_back(
            AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
                alternative_service, it->expiration(),
                it->advertised_versions()));
      } else {
        valid_alternative_service_infos.push_back(
            AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
                alternative_service, it->expiration()));
      }
      ++it;
    }
    if (service_info->empty()) {
      map_it->second.alternative_services.reset();
      server_info_map_.EraseIfEmpty(map_it);
    }
    return valid_alternative_service_infos;
  }

  auto canonical = GetCanonicalAltSvcHost(origin, network_anonymization_key);
  if (canonical == canonical_alt_svc_map_.end()) {
    return AlternativeServiceInfoVector();
  }
  map_it = server_info_map_.Get(
      CreateServerInfoKey(canonical->second, network_anonymization_key));
  if (map_it == server_info_map_.end() ||
      !map_it->second.alternative_services.has_value()) {
    return AlternativeServiceInfoVector();
  }
  AlternativeServiceInfoVector* service_info =
      &map_it->second.alternative_services.value();
  for (auto it = service_info->begin(); it != service_info->end();) {
    if (it->expiration() < now) {
      it = service_info->erase(it);
      continue;
    }
    AlternativeService alternative_service(it->alternative_service());
    if (alternative_service.host.empty()) {
      alternative_service.host = canonical->second.host();
      if (IsAlternativeServiceBroken(alternative_service,
                                     network_anonymization_key)) {
        ++it;
        continue;
      }
      alternative_service.host = origin.host();
    } else if (IsAlternativeServiceBroken(alternative_service,
                                          network_anonymization_key)) {
      ++it;
      continue;
    }
    if (alternative_service.protocol == kProtoQUIC) {
      valid_alternative_service_infos.push_back(
          AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
              alternative_service, it->expiration(),
              it->advertised_versions()));
    } else {
      valid_alternative_service_infos.push_back(
          AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
              alternative_service, it->expiration()));
    }
    ++it;
  }
  if (service_info->empty())
    server_info_map_.EraseIfEmpty(map_it);
  return valid_alternative_service_infos;
}

void HttpServerProperties::SetAlternativeServicesInternal(
    const url::SchemeHostPort& origin,
    const NetworkAnonymizationKey& network_anonymization_key,
    const AlternativeServiceInfoVector& alternative_service_info_vector) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(origin.scheme(), url::kWsScheme);
  DCHECK_NE(origin.scheme(), url::kWssScheme);

  if (alternative_service_info_vector.empty()) {
    RemoveAltSvcCanonicalHost(origin, n
```
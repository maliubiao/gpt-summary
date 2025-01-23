Response:
Let's break down the thought process to analyze the `URLRequestContextBuilder.cc` file.

**1. Understanding the Core Purpose:**

The first step is to read the file and understand its name and the surrounding context (Chromium networking stack). The name "URLRequestContextBuilder" strongly suggests that this class is responsible for *creating* `URLRequestContext` objects. The `...Builder` suffix is a common pattern for builder classes. `URLRequestContext` is likely a central object holding configuration for making network requests.

**2. Identifying Key Functionalities:**

Next, I'd scan the file for methods and member variables. I'd look for patterns and keywords that suggest specific responsibilities.

* **`Set...` methods:**  These immediately stand out. Methods like `SetHttpNetworkSessionComponents`, `set_accept_language`, `EnableHttpCache`, `SetCertVerifier`, `SetCookieStore`, `set_host_resolver`, `set_proxy_delegate`, etc., all indicate configuration options for the `URLRequestContext`. Each `Set...` method likely corresponds to a specific aspect of the networking stack.

* **Member variables:**  These also provide clues. Variables like `accept_language_`, `user_agent_`, `http_cache_enabled_`, `cert_verifier_`, `cookie_store_`, `host_resolver_`, `proxy_delegate_` directly correlate with the `Set...` methods.

* **`Build()` method:** This is the crucial method. It's where the actual `URLRequestContext` object is created and configured using the previously set parameters. I'd analyze the code within this method carefully.

* **Conditional compilation (`#if BUILDFLAG(...)`):**  These indicate optional features or platform-specific behavior. I'd note these and understand their implications (e.g., reporting, device-bound sessions).

**3. Grouping Functionalities and Forming a High-Level Understanding:**

Based on the identified methods and variables, I can start grouping related functionalities:

* **HTTP Session Configuration:**  `SetHttpNetworkSessionComponents`, `SetSpdyAndQuicEnabled`, related member variables.
* **User Agent:** `set_accept_language`, `set_user_agent`, `set_http_user_agent_settings`.
* **Caching:** `EnableHttpCache`, `DisableHttpCache`, `HttpCacheParams`.
* **Security:** `SetCertVerifier`, `set_sct_auditing_delegate`, `TransportSecurityState`.
* **Cookies:** `SetCookieStore`.
* **DNS Resolution:** `set_host_resolver`, `set_host_mapping_rules`, `set_host_resolver_manager`, `set_host_resolver_factory`.
* **Proxy:** `set_proxy_delegate`.
* **Authentication:** `SetHttpAuthHandlerFactory`.
* **QUIC:** `set_quic_context`.
* **Reporting/NEL:**  The `#if BUILDFLAG(ENABLE_REPORTING)` block.
* **Device-Bound Sessions:** The `#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)` block.
* **Network Binding:** `BindToNetwork`.
* **Protocol Handlers:** `SetProtocolHandler`.

This grouping helps to understand the overall scope of the builder.

**4. Examining Relationships with JavaScript (and Browsers):**

Now, I'd consider how these networking functionalities relate to what happens in a web browser and how JavaScript interacts with it.

* **Fetching Resources:**  The core purpose of the networking stack is to fetch resources requested by the browser (including JavaScript). Therefore, all the configurations managed by this builder influence how those fetches occur.
* **`fetch()` API:**  The `fetch()` API in JavaScript directly triggers these underlying networking mechanisms. Headers set in `fetch()` options (like `Accept-Language`, `User-Agent`) are directly related to the builder's methods.
* **Cookies:** JavaScript's `document.cookie` interacts with the `CookieStore` managed by the builder.
* **Caching:**  The browser's caching behavior, which JavaScript can sometimes influence, is configured here.
* **Security (HTTPS):**  The certificate verification and transport security settings are crucial for secure connections initiated by JavaScript.
* **Proxies:**  If a user configures a proxy, it will be used for requests made by JavaScript.

**5. Logical Reasoning and Examples:**

For each functionality, I'd try to come up with simple scenarios:

* **User Agent:**  If the builder sets a specific `User-Agent` string, every request made using this `URLRequestContext` will include that header.
* **Caching:** If HTTP caching is enabled, subsequent requests for the same resource might be served from the cache, affecting how JavaScript code behaves.
* **Protocol Handlers:**  Registering a custom protocol handler can allow JavaScript to interact with non-standard protocols.

**6. Common Usage Errors and Debugging:**

I'd think about potential mistakes developers might make when using this builder:

* **Conflicting settings:** Setting both `set_host_resolver` and `set_host_resolver_manager`. The code itself has `DCHECK` statements to catch some of these.
* **Incorrect cache parameters:** Specifying an invalid cache path or size.
* **Not understanding the implications of certain settings:** For instance, disabling caching might lead to performance issues.

For debugging, I'd trace how user actions (like typing a URL, clicking a link, JavaScript making a `fetch()` call) eventually lead to the creation and use of a `URLRequestContext` built by this class.

**7. Structuring the Answer:**

Finally, I'd organize the information logically, covering:

* **Core functionality:**  Clearly state the main purpose of the class.
* **Detailed functionalities:** List and explain each of the configurable aspects.
* **Relationship with JavaScript:** Provide concrete examples of how the builder's settings affect JavaScript's network requests.
* **Logical reasoning:**  Give simple input/output scenarios.
* **Common errors:**  Highlight potential pitfalls.
* **Debugging:** Explain how user actions lead to this code.

This systematic approach allows for a comprehensive analysis of the code and its role within the larger system. It involves understanding the code's structure, its purpose, and its interactions with other components, including those exposed to developers (like JavaScript APIs).
这个文件 `net/url_request/url_request_context_builder.cc` 的主要功能是**构建 `URLRequestContext` 对象**。`URLRequestContext` 是 Chromium 网络栈中的一个核心类，它包含了发起和处理网络请求所需的所有配置信息。`URLRequestContextBuilder` 提供了一种便捷的方式来配置和创建这个复杂的对象。

以下是该文件更详细的功能列表：

**核心功能：构建 URLRequestContext**

* **提供流畅的构建接口：**  通过一系列 `Set...` 方法，允许开发者逐步配置 `URLRequestContext` 的各个方面。
* **管理各种网络组件的生命周期和设置：**  包括但不限于：
    * **HTTP 网络会话 (`HttpNetworkSession`)：** 配置 HTTP/2、QUIC 等协议的支持。
    * **缓存 (`HttpCache`)：** 启用或禁用 HTTP 缓存，并配置缓存类型、路径、大小等参数。
    * **Cookie 管理 (`CookieStore`)：** 设置自定义的 Cookie 存储。
    * **DNS 解析 (`HostResolver`)：**  配置 DNS 解析器，包括主机名映射规则。
    * **代理服务器 (`ProxyResolutionService`)：** 配置代理服务器的使用。
    * **SSL 配置 (`SSLConfigService`)：** 配置 SSL/TLS 相关参数。
    * **认证处理 (`HttpAuthHandlerFactory`)：** 设置 HTTP 认证方式。
    * **证书验证 (`CertVerifier`)：** 配置证书验证器。
    * **网络委托 (`NetworkDelegate`)：**  允许自定义网络事件的处理。
    * **用户代理 (`HttpUserAgentSettings`)：** 设置 `User-Agent` 和 `Accept-Language` 头部。
    * **QUIC 上下文 (`QuicContext`)：** 配置 QUIC 协议相关参数。
    * **报告服务 (`ReportingService`) 和网络错误日志 (`NetworkErrorLoggingService`)：** 配置网络监控和错误报告。
    * **设备绑定会话 (`device_bound_sessions::SessionService`)：** 管理与特定设备绑定的网络会话。
    * **网络质量估计 (`NetworkQualityEstimator`)：**  集成网络质量评估功能。
* **提供默认配置：**  如果没有显式设置某些选项，`URLRequestContextBuilder` 会提供合理的默认值。
* **处理依赖关系：** 确保各个组件之间的依赖关系得到正确处理，例如，`HttpNetworkSession` 的创建需要 `HostResolver`、`CertVerifier` 等。

**与 JavaScript 的关系**

`URLRequestContextBuilder` 本身不直接涉及 JavaScript 代码的执行。 然而，它构建的 `URLRequestContext` 对象是浏览器发起所有网络请求的基础，包括由 JavaScript 发起的请求，例如：

* **`fetch()` API:** 当 JavaScript 代码使用 `fetch()` API 发起网络请求时，浏览器内部会使用一个 `URLRequestContext` 对象来处理这个请求。`URLRequestContextBuilder` 负责创建和配置这个对象，因此会影响 `fetch()` 请求的行为。
* **`XMLHttpRequest` (XHR):**  与 `fetch()` 类似，XHR 对象发起的请求也依赖于 `URLRequestContext`。
* **加载图片、样式表、脚本等资源:**  浏览器加载网页上的各种资源时，也会使用 `URLRequestContext`。

**举例说明:**

假设 JavaScript 代码使用 `fetch()` 发起一个请求：

```javascript
fetch('https://example.com/data.json', {
  headers: {
    'Custom-Header': 'value'
  }
});
```

当浏览器处理这个 `fetch` 请求时，它会使用一个已经构建好的 `URLRequestContext` 对象。`URLRequestContextBuilder` 在创建这个对象时可能已经配置了：

* **代理服务器：** 如果 `URLRequestContextBuilder` 配置了代理，那么这个 `fetch` 请求将会通过配置的代理服务器发送。
* **缓存策略：** 如果启用了 HTTP 缓存，并且 `https://example.com/data.json` 之前被访问过且符合缓存策略，那么浏览器可能会直接从缓存中返回数据，而不会真正发起网络请求。
* **Cookie：** 如果 `URLRequestContextBuilder` 配置了 Cookie 存储，那么浏览器会自动将与 `example.com` 相关的 Cookie 包含在 `fetch` 请求的头部中。
* **用户代理：**  `fetch` 请求的 `User-Agent` 头部将由 `URLRequestContextBuilder` 中设置的值决定（如果没有显式设置，则使用默认值）。
* **证书验证：**  对于 HTTPS 请求，`URLRequestContext` 中配置的 `CertVerifier` 将会验证 `example.com` 的 SSL 证书。

**逻辑推理：假设输入与输出**

**假设输入：**

```c++
URLRequestContextBuilder builder;
builder.set_user_agent("MyCustomUserAgent");
builder.EnableHttpCache({URLRequestContextBuilder::HttpCacheParams::DISK,
                         base::FilePath(FILE_PATH_LITERAL("/my/cache/path")),
                         10 * 1024 * 1024}); // 10MB cache
std::unique_ptr<URLRequestContext> context = builder.Build();
```

**输出：**

创建的 `URLRequestContext` 对象将具有以下特性：

* **用户代理：**  所有通过此 `URLRequestContext` 发起的请求的 `User-Agent` 头部将是 "MyCustomUserAgent"。
* **HTTP 缓存：**  启用了基于磁盘的 HTTP 缓存，缓存路径为 `/my/cache/path`，最大大小为 10MB。

**涉及用户或编程常见的使用错误**

1. **重复设置相互冲突的选项：** 例如，同时使用 `set_host_resolver` 和 `set_host_resolver_manager`，这会导致程序行为不确定或崩溃（通常会有 `DCHECK` 断言来防止这种情况）。

   ```c++
   URLRequestContextBuilder builder;
   auto resolver1 = HostResolver::CreateDefault();
   auto resolver2 = HostResolver::CreateDefault();
   builder.set_host_resolver(std::move(resolver1));
   // 错误：已经设置了 host_resolver
   // builder.set_host_resolver(std::move(resolver2));
   ```

2. **在不应该的时候禁用关键功能：**  例如，禁用 HTTP 缓存可能会导致性能下降，尤其是在移动设备上。

   ```c++
   URLRequestContextBuilder builder;
   builder.DisableHttpCache(); // 可能会影响性能
   ```

3. **忘记设置必要的参数：**  例如，如果需要使用特定的代理服务器，但忘记配置 `proxy_resolution_service_`。

4. **不理解各个选项的含义：**  盲目地复制粘贴配置代码，而不理解每个选项的作用，可能导致意外的网络行为。

5. **在 `Build()` 之后修改 Builder 的状态：**  `Build()` 方法会创建并返回 `URLRequestContext` 对象。在调用 `Build()` 之后再修改 Builder 的状态不会影响已经创建的对象。

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户在浏览器中访问一个网页 `https://example.com`，以下步骤可能涉及到 `URLRequestContextBuilder`：

1. **用户在地址栏输入 URL 并按下回车，或者点击一个链接。**
2. **浏览器进程 (Browser Process) 接收到用户的请求。**
3. **浏览器进程需要决定如何加载这个 URL。** 这通常涉及到创建一个新的网络请求。
4. **为了发起网络请求，浏览器需要一个 `URLRequestContext` 对象。**  浏览器通常会维护一个或多个 `URLRequestContext` 对象，例如，用于常规浏览、隐身模式等。
5. **如果需要创建一个新的 `URLRequestContext` (例如，首次启动浏览器或进入隐身模式)，则会使用 `URLRequestContextBuilder`。**
6. **在创建 `URLRequestContext` 的过程中，会调用 `URLRequestContextBuilder` 的各种 `Set...` 方法来配置网络栈的各个方面。**  这些配置可能来源于：
    * **用户设置：** 例如，用户在浏览器设置中配置的代理服务器、Cookie 策略等。
    * **命令行参数：**  启动浏览器时传递的命令行参数可能会影响网络配置。
    * **默认配置：**  Chromium 代码中预设的默认值。
    * **扩展程序或插件：** 某些浏览器扩展程序可能会影响网络请求的行为。
7. **最后，调用 `URLRequestContextBuilder::Build()` 方法来创建 `URLRequestContext` 对象。**
8. **创建的 `URLRequestContext` 对象将被用于发起对 `https://example.com` 的网络请求。**

**调试线索:**

* **断点：** 在 `URLRequestContextBuilder` 的 `Build()` 方法和各种 `Set...` 方法上设置断点，可以观察到在创建 `URLRequestContext` 时哪些配置被设置了，以及设置的值是什么。
* **网络日志 (net-internals):**  Chromium 提供了 `chrome://net-internals` 页面，可以查看详细的网络请求日志，包括使用的 `URLRequestContext` 的配置信息。
* **源码分析：**  跟踪浏览器创建 `URLRequestContext` 的代码路径，了解在哪些场景下会使用 `URLRequestContextBuilder`，以及如何配置它。
* **检查用户设置和命令行参数：**  用户的浏览器设置和启动参数可能会影响 `URLRequestContext` 的配置。

总而言之，`URLRequestContextBuilder` 是 Chromium 网络栈中一个至关重要的类，它负责构建用于处理所有网络请求的核心配置对象，并间接地影响着 JavaScript 发起的网络操作的行为。理解它的功能有助于深入理解 Chromium 的网络架构。

### 提示词
```
这是目录为net/url_request/url_request_context_builder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/url_request/url_request_context_builder.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/notreached.h"
#include "base/strings/string_util.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/types/pass_key.h"
#include "build/build_config.h"
#include "net/base/cache_type.h"
#include "net/base/net_errors.h"
#include "net/base/network_delegate_impl.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/cert/sct_auditing_delegate.h"
#include "net/cookies/cookie_monster.h"
#include "net/dns/context_host_resolver.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_manager.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_cache.h"
#include "net/http/http_network_layer.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_server_properties_manager.h"
#include "net/http/transport_security_persister.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/net_buildflags.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_session_pool.h"
#include "net/shared_dictionary/shared_dictionary_network_transaction_factory.h"
#include "net/socket/network_binding_client_socket_factory.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_job_factory.h"
#include "url/url_constants.h"

#if BUILDFLAG(ENABLE_REPORTING)
#include "net/network_error_logging/network_error_logging_service.h"
#include "net/network_error_logging/persistent_reporting_and_nel_store.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_service.h"
#endif  // BUILDFLAG(ENABLE_REPORTING)

#if BUILDFLAG(IS_ANDROID)
#include "base/android/build_info.h"
#endif  // BUILDFLAG(IS_ANDROID)

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
#include "net/device_bound_sessions/session_service.h"
#include "net/device_bound_sessions/session_store.h"
#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

namespace net {

URLRequestContextBuilder::HttpCacheParams::HttpCacheParams() = default;
URLRequestContextBuilder::HttpCacheParams::~HttpCacheParams() = default;

URLRequestContextBuilder::URLRequestContextBuilder() = default;

URLRequestContextBuilder::~URLRequestContextBuilder() = default;

void URLRequestContextBuilder::SetHttpNetworkSessionComponents(
    const URLRequestContext* request_context,
    HttpNetworkSessionContext* session_context,
    bool suppress_setting_socket_performance_watcher_factory,
    ClientSocketFactory* client_socket_factory) {
  session_context->client_socket_factory =
      client_socket_factory ? client_socket_factory
                            : ClientSocketFactory::GetDefaultFactory();
  session_context->host_resolver = request_context->host_resolver();
  session_context->cert_verifier = request_context->cert_verifier();
  session_context->transport_security_state =
      request_context->transport_security_state();
  session_context->sct_auditing_delegate =
      request_context->sct_auditing_delegate();
  session_context->proxy_resolution_service =
      request_context->proxy_resolution_service();
  session_context->proxy_delegate = request_context->proxy_delegate();
  session_context->http_user_agent_settings =
      request_context->http_user_agent_settings();
  session_context->ssl_config_service = request_context->ssl_config_service();
  session_context->http_auth_handler_factory =
      request_context->http_auth_handler_factory();
  session_context->http_server_properties =
      request_context->http_server_properties();
  session_context->quic_context = request_context->quic_context();
  session_context->net_log = request_context->net_log();
  session_context->network_quality_estimator =
      request_context->network_quality_estimator();
  if (request_context->network_quality_estimator() &&
      !suppress_setting_socket_performance_watcher_factory) {
    session_context->socket_performance_watcher_factory =
        request_context->network_quality_estimator()
            ->GetSocketPerformanceWatcherFactory();
  }
#if BUILDFLAG(ENABLE_REPORTING)
  session_context->reporting_service = request_context->reporting_service();
  session_context->network_error_logging_service =
      request_context->network_error_logging_service();
#endif
}

void URLRequestContextBuilder::set_accept_language(
    const std::string& accept_language) {
  DCHECK(!http_user_agent_settings_);
  accept_language_ = accept_language;
}
void URLRequestContextBuilder::set_user_agent(const std::string& user_agent) {
  DCHECK(!http_user_agent_settings_);
  user_agent_ = user_agent;
}

void URLRequestContextBuilder::set_http_user_agent_settings(
    std::unique_ptr<HttpUserAgentSettings> http_user_agent_settings) {
  http_user_agent_settings_ = std::move(http_user_agent_settings);
}

void URLRequestContextBuilder::EnableHttpCache(const HttpCacheParams& params) {
  http_cache_enabled_ = true;
  http_cache_params_ = params;
}

void URLRequestContextBuilder::DisableHttpCache() {
  http_cache_enabled_ = false;
  http_cache_params_ = HttpCacheParams();
}

void URLRequestContextBuilder::SetSpdyAndQuicEnabled(bool spdy_enabled,
                                                     bool quic_enabled) {
  http_network_session_params_.enable_http2 = spdy_enabled;
  http_network_session_params_.enable_quic = quic_enabled;
}

void URLRequestContextBuilder::set_sct_auditing_delegate(
    std::unique_ptr<SCTAuditingDelegate> sct_auditing_delegate) {
  sct_auditing_delegate_ = std::move(sct_auditing_delegate);
}

void URLRequestContextBuilder::set_quic_context(
    std::unique_ptr<QuicContext> quic_context) {
  quic_context_ = std::move(quic_context);
}

void URLRequestContextBuilder::SetCertVerifier(
    std::unique_ptr<CertVerifier> cert_verifier) {
  cert_verifier_ = std::move(cert_verifier);
}

#if BUILDFLAG(ENABLE_REPORTING)
void URLRequestContextBuilder::set_reporting_policy(
    std::unique_ptr<ReportingPolicy> reporting_policy) {
  reporting_policy_ = std::move(reporting_policy);
}

void URLRequestContextBuilder::set_reporting_service(
    std::unique_ptr<ReportingService> reporting_service) {
  reporting_service_ = std::move(reporting_service);
}

void URLRequestContextBuilder::set_persistent_reporting_and_nel_store(
    std::unique_ptr<PersistentReportingAndNelStore>
        persistent_reporting_and_nel_store) {
  persistent_reporting_and_nel_store_ =
      std::move(persistent_reporting_and_nel_store);
}

void URLRequestContextBuilder::set_enterprise_reporting_endpoints(
    const base::flat_map<std::string, GURL>& enterprise_reporting_endpoints) {
  enterprise_reporting_endpoints_ = enterprise_reporting_endpoints;
}
#endif  // BUILDFLAG(ENABLE_REPORTING)

void URLRequestContextBuilder::SetCookieStore(
    std::unique_ptr<CookieStore> cookie_store) {
  cookie_store_set_by_client_ = true;
  cookie_store_ = std::move(cookie_store);
}

void URLRequestContextBuilder::SetProtocolHandler(
    const std::string& scheme,
    std::unique_ptr<URLRequestJobFactory::ProtocolHandler> protocol_handler) {
  DCHECK(protocol_handler);
  // If a consumer sets a ProtocolHandler and then overwrites it with another,
  // it's probably a bug.
  DCHECK_EQ(0u, protocol_handlers_.count(scheme));
  protocol_handlers_[scheme] = std::move(protocol_handler);
}

void URLRequestContextBuilder::set_host_resolver(
    std::unique_ptr<HostResolver> host_resolver) {
  DCHECK(!host_resolver_manager_);
  DCHECK(host_mapping_rules_.empty());
  DCHECK(!host_resolver_factory_);
  host_resolver_ = std::move(host_resolver);
}

void URLRequestContextBuilder::set_host_mapping_rules(
    std::string host_mapping_rules) {
  DCHECK(!host_resolver_);
  host_mapping_rules_ = std::move(host_mapping_rules);
}

void URLRequestContextBuilder::set_host_resolver_manager(
    HostResolverManager* manager) {
  DCHECK(!host_resolver_);
  host_resolver_manager_ = manager;
}

void URLRequestContextBuilder::set_host_resolver_factory(
    HostResolver::Factory* factory) {
  DCHECK(!host_resolver_);
  host_resolver_factory_ = factory;
}

void URLRequestContextBuilder::set_proxy_delegate(
    std::unique_ptr<ProxyDelegate> proxy_delegate) {
  proxy_delegate_ = std::move(proxy_delegate);
}

void URLRequestContextBuilder::SetHttpAuthHandlerFactory(
    std::unique_ptr<HttpAuthHandlerFactory> factory) {
  http_auth_handler_factory_ = std::move(factory);
}

void URLRequestContextBuilder::SetHttpServerProperties(
    std::unique_ptr<HttpServerProperties> http_server_properties) {
  http_server_properties_ = std::move(http_server_properties);
}

void URLRequestContextBuilder::SetCreateHttpTransactionFactoryCallback(
    CreateHttpTransactionFactoryCallback
        create_http_network_transaction_factory) {
  http_transaction_factory_.reset();
  create_http_network_transaction_factory_ =
      std::move(create_http_network_transaction_factory);
}

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
void URLRequestContextBuilder::set_device_bound_session_service(
    std::unique_ptr<device_bound_sessions::SessionService>
        device_bound_session_service) {
  device_bound_session_service_ = std::move(device_bound_session_service);
}
#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

void URLRequestContextBuilder::BindToNetwork(
    handles::NetworkHandle network,
    std::optional<HostResolver::ManagerOptions> options) {
#if BUILDFLAG(IS_ANDROID)
  DCHECK(NetworkChangeNotifier::AreNetworkHandlesSupported());
  // DNS lookups for this context will need to target `network`. NDK to do that
  // has been introduced in Android Marshmallow
  // (https://developer.android.com/ndk/reference/group/networking#android_getaddrinfofornetwork)
  // This is also checked later on in the codepath (at lookup time), but
  // failing here should be preferred to return a more intuitive crash path.
  CHECK(base::android::BuildInfo::GetInstance()->sdk_int() >=
        base::android::SDK_VERSION_MARSHMALLOW);
  bound_network_ = network;
  manager_options_ = options.value_or(manager_options_);
#else
  NOTIMPLEMENTED();
#endif  // BUILDFLAG(IS_ANDROID)
}

std::unique_ptr<URLRequestContext> URLRequestContextBuilder::Build() {
  auto context = std::make_unique<URLRequestContext>(
      base::PassKey<URLRequestContextBuilder>());

  context->set_enable_brotli(enable_brotli_);
  context->set_enable_zstd(enable_zstd_);
  context->set_check_cleartext_permitted(check_cleartext_permitted_);
  context->set_require_network_anonymization_key(
      require_network_anonymization_key_);
  context->set_network_quality_estimator(network_quality_estimator_);

  if (http_user_agent_settings_) {
    context->set_http_user_agent_settings(std::move(http_user_agent_settings_));
  } else {
    context->set_http_user_agent_settings(
        std::make_unique<StaticHttpUserAgentSettings>(accept_language_,
                                                      user_agent_));
  }

  if (!network_delegate_) {
    network_delegate_ = std::make_unique<NetworkDelegateImpl>();
  }
  context->set_network_delegate(std::move(network_delegate_));

  if (net_log_) {
    // Unlike the other builder parameters, |net_log_| is not owned by the
    // builder or resulting context.
    context->set_net_log(net_log_);
  } else {
    context->set_net_log(NetLog::Get());
  }

  if (bound_network_ != handles::kInvalidNetworkHandle) {
    DCHECK(!client_socket_factory_raw_);
    DCHECK(!host_resolver_);
    DCHECK(!host_resolver_manager_);
    DCHECK(!host_resolver_factory_);

    context->set_bound_network(bound_network_);

    // All sockets created for this context will need to be bound to
    // `bound_network_`.
    auto client_socket_factory =
        std::make_unique<NetworkBindingClientSocketFactory>(bound_network_);
    set_client_socket_factory(client_socket_factory.get());
    context->set_client_socket_factory(std::move(client_socket_factory));

    host_resolver_ = HostResolver::CreateStandaloneNetworkBoundResolver(
        context->net_log(), bound_network_, manager_options_);

    if (!quic_context_) {
      set_quic_context(std::make_unique<QuicContext>());
    }
    auto* quic_params = quic_context_->params();
    // QUIC sessions for this context should not be closed (or go away) after a
    // network change.
    quic_params->close_sessions_on_ip_change = false;
    quic_params->goaway_sessions_on_ip_change = false;

    // QUIC connection migration should not be enabled when binding a context
    // to a network.
    quic_params->migrate_sessions_on_network_change_v2 = false;

    // Objects used by network sessions for this context shouldn't listen to
    // network changes.
    http_network_session_params_.ignore_ip_address_changes = true;
  }

  if (client_socket_factory_) {
    context->set_client_socket_factory(std::move(client_socket_factory_));
  }

  if (host_resolver_) {
    DCHECK(host_mapping_rules_.empty());
    DCHECK(!host_resolver_manager_);
    DCHECK(!host_resolver_factory_);
  } else if (host_resolver_manager_) {
    if (host_resolver_factory_) {
      host_resolver_ = host_resolver_factory_->CreateResolver(
          host_resolver_manager_, host_mapping_rules_,
          true /* enable_caching */);
    } else {
      host_resolver_ = HostResolver::CreateResolver(host_resolver_manager_,
                                                    host_mapping_rules_,
                                                    true /* enable_caching */);
    }
  } else {
    if (host_resolver_factory_) {
      host_resolver_ = host_resolver_factory_->CreateStandaloneResolver(
          context->net_log(), HostResolver::ManagerOptions(),
          host_mapping_rules_, true /* enable_caching */);
    } else {
      host_resolver_ = HostResolver::CreateStandaloneResolver(
          context->net_log(), HostResolver::ManagerOptions(),
          host_mapping_rules_, true /* enable_caching */);
    }
  }
  host_resolver_->SetRequestContext(context.get());
  context->set_host_resolver(std::move(host_resolver_));

  if (ssl_config_service_) {
    context->set_ssl_config_service(std::move(ssl_config_service_));
  } else {
    context->set_ssl_config_service(
        std::make_unique<SSLConfigServiceDefaults>());
  }

  if (http_auth_handler_factory_) {
    context->set_http_auth_handler_factory(
        std::move(http_auth_handler_factory_));
  } else {
    context->set_http_auth_handler_factory(
        HttpAuthHandlerRegistryFactory::CreateDefault());
  }

  if (cookie_store_set_by_client_) {
    context->set_cookie_store(std::move(cookie_store_));
  } else {
    auto cookie_store = std::make_unique<CookieMonster>(nullptr /* store */,
                                                        context->net_log());
    context->set_cookie_store(std::move(cookie_store));
  }

  context->set_transport_security_state(
      std::make_unique<TransportSecurityState>(hsts_policy_bypass_list_));
  if (!transport_security_persister_file_path_.empty()) {
    // Use a low priority because saving this should not block anything
    // user-visible. Block shutdown to ensure it does get persisted to disk,
    // since it contains security-relevant information.
    scoped_refptr<base::SequencedTaskRunner> task_runner(
        base::ThreadPool::CreateSequencedTaskRunner(
            {base::MayBlock(), base::TaskPriority::BEST_EFFORT,
             base::TaskShutdownBehavior::BLOCK_SHUTDOWN}));

    context->set_transport_security_persister(
        std::make_unique<TransportSecurityPersister>(
            context->transport_security_state(), task_runner,
            transport_security_persister_file_path_));
  }

  if (http_server_properties_) {
    context->set_http_server_properties(std::move(http_server_properties_));
  } else {
    context->set_http_server_properties(
        std::make_unique<HttpServerProperties>());
  }

  if (cert_verifier_) {
    context->set_cert_verifier(std::move(cert_verifier_));
  } else {
    // TODO(mattm): Should URLRequestContextBuilder create a CertNetFetcher?
    context->set_cert_verifier(
        CertVerifier::CreateDefault(/*cert_net_fetcher=*/nullptr));
  }

  if (sct_auditing_delegate_) {
    context->set_sct_auditing_delegate(std::move(sct_auditing_delegate_));
  }

  if (quic_context_) {
    context->set_quic_context(std::move(quic_context_));
  } else {
    context->set_quic_context(std::make_unique<QuicContext>());
  }

  if (!proxy_resolution_service_) {
#if !BUILDFLAG(IS_LINUX) && !BUILDFLAG(IS_CHROMEOS) && !BUILDFLAG(IS_ANDROID)
    // TODO(willchan): Switch to using this code when
    // ProxyConfigService::CreateSystemProxyConfigService()'s
    // signature doesn't suck.
    if (!proxy_config_service_) {
      proxy_config_service_ =
          ProxyConfigService::CreateSystemProxyConfigService(
              base::SingleThreadTaskRunner::GetCurrentDefault().get());
    }
#endif  // !BUILDFLAG(IS_LINUX) && !BUILDFLAG(IS_CHROMEOS) &&
        // !BUILDFLAG(IS_ANDROID)
    proxy_resolution_service_ = CreateProxyResolutionService(
        std::move(proxy_config_service_), context.get(),
        context->host_resolver(), context->network_delegate(),
        context->net_log(), pac_quick_check_enabled_);
  }
  ProxyResolutionService* proxy_resolution_service =
      proxy_resolution_service_.get();
  context->set_proxy_resolution_service(std::move(proxy_resolution_service_));

  if (proxy_delegate_) {
    ProxyDelegate* proxy_delegate = proxy_delegate_.get();
    context->set_proxy_delegate(std::move(proxy_delegate_));

    proxy_resolution_service->SetProxyDelegate(proxy_delegate);
    proxy_delegate->SetProxyResolutionService(proxy_resolution_service);
  }

#if BUILDFLAG(ENABLE_REPORTING)
  // Note: ReportingService::Create and NetworkErrorLoggingService::Create can
  // both return nullptr if the corresponding base::Feature is disabled.

  if (reporting_service_) {
    context->set_reporting_service(std::move(reporting_service_));
  } else if (reporting_policy_) {
    context->set_reporting_service(
        ReportingService::Create(*reporting_policy_, context.get(),
                                 persistent_reporting_and_nel_store_.get(),
                                 enterprise_reporting_endpoints_));
  }

  if (network_error_logging_enabled_) {
    if (!network_error_logging_service_) {
      network_error_logging_service_ = NetworkErrorLoggingService::Create(
          persistent_reporting_and_nel_store_.get());
    }
    context->set_network_error_logging_service(
        std::move(network_error_logging_service_));
  }

  if (persistent_reporting_and_nel_store_) {
    context->set_persistent_reporting_and_nel_store(
        std::move(persistent_reporting_and_nel_store_));
  }

  // If both Reporting and Network Error Logging are actually enabled, then
  // connect them so Network Error Logging can use Reporting to deliver error
  // reports.
  if (context->reporting_service() &&
      context->network_error_logging_service()) {
    context->network_error_logging_service()->SetReportingService(
        context->reporting_service());
  }
#endif  // BUILDFLAG(ENABLE_REPORTING)

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
  if (has_device_bound_session_service_) {
    if (!device_bound_sessions_file_path_.empty()) {
      context->set_device_bound_session_store(
          device_bound_sessions::SessionStore::Create(
              device_bound_sessions_file_path_));
    }
    context->set_device_bound_session_service(
        device_bound_sessions::SessionService::Create(context.get()));
  } else {
    if (device_bound_session_service_) {
      context->set_device_bound_session_service(
          std::move(device_bound_session_service_));
    }
  }
#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

  HttpNetworkSessionContext network_session_context;
  // Unlike the other fields of HttpNetworkSession::Context,
  // |client_socket_factory| is not mirrored in URLRequestContext.
  SetHttpNetworkSessionComponents(
      context.get(), &network_session_context,
      suppress_setting_socket_performance_watcher_factory_for_testing_,
      client_socket_factory_raw_);

  context->set_http_network_session(std::make_unique<HttpNetworkSession>(
      http_network_session_params_, network_session_context));

  std::unique_ptr<HttpTransactionFactory> http_transaction_factory;
  if (http_transaction_factory_) {
    http_transaction_factory = std::move(http_transaction_factory_);
  } else if (!create_http_network_transaction_factory_.is_null()) {
    http_transaction_factory =
        std::move(create_http_network_transaction_factory_)
            .Run(context->http_network_session());
  } else {
    http_transaction_factory =
        std::make_unique<HttpNetworkLayer>(context->http_network_session());
  }

  if (enable_shared_dictionary_) {
    http_transaction_factory =
        std::make_unique<SharedDictionaryNetworkTransactionFactory>(
            std::move(http_transaction_factory), enable_shared_zstd_);
  }

  if (http_cache_enabled_) {
    std::unique_ptr<HttpCache::BackendFactory> http_cache_backend;
    if (http_cache_params_.type != HttpCacheParams::IN_MEMORY) {
      // TODO(mmenke): Maybe merge BackendType and HttpCacheParams::Type? The
      // first doesn't include in memory, so may require some work.
      BackendType backend_type = CACHE_BACKEND_DEFAULT;
      switch (http_cache_params_.type) {
        case HttpCacheParams::DISK:
          backend_type = CACHE_BACKEND_DEFAULT;
          break;
        case HttpCacheParams::DISK_BLOCKFILE:
          backend_type = CACHE_BACKEND_BLOCKFILE;
          break;
        case HttpCacheParams::DISK_SIMPLE:
          backend_type = CACHE_BACKEND_SIMPLE;
          break;
        case HttpCacheParams::IN_MEMORY:
          NOTREACHED();
      }
      http_cache_backend = std::make_unique<HttpCache::DefaultBackend>(
          DISK_CACHE, backend_type, http_cache_params_.file_operations_factory,
          http_cache_params_.path, http_cache_params_.max_size,
          http_cache_params_.reset_cache);
    } else {
      http_cache_backend =
          HttpCache::DefaultBackend::InMemory(http_cache_params_.max_size);
    }
#if BUILDFLAG(IS_ANDROID)
    http_cache_backend->SetAppStatusListenerGetter(
        http_cache_params_.app_status_listener_getter);
#endif

    http_transaction_factory = std::make_unique<HttpCache>(
        std::move(http_transaction_factory), std::move(http_cache_backend));
  }
  context->set_http_transaction_factory(std::move(http_transaction_factory));

  std::unique_ptr<URLRequestJobFactory> job_factory =
      std::make_unique<URLRequestJobFactory>();
  for (auto& scheme_handler : protocol_handlers_) {
    job_factory->SetProtocolHandler(scheme_handler.first,
                                    std::move(scheme_handler.second));
  }
  protocol_handlers_.clear();

  context->set_job_factory(std::move(job_factory));

  if (cookie_deprecation_label_.has_value()) {
    context->set_cookie_deprecation_label(*cookie_deprecation_label_);
  }

  return context;
}

std::unique_ptr<ProxyResolutionService>
URLRequestContextBuilder::CreateProxyResolutionService(
    std::unique_ptr<ProxyConfigService> proxy_config_service,
    URLRequestContext* url_request_context,
    HostResolver* host_resolver,
    NetworkDelegate* network_delegate,
    NetLog* net_log,
    bool pac_quick_check_enabled) {
  return ConfiguredProxyResolutionService::CreateUsingSystemProxyResolver(
      std::move(proxy_config_service), net_log, pac_quick_check_enabled);
}

}  // namespace net
```
Response:
Let's break down the thought process for analyzing the `url_request_context.cc` file.

**1. Initial Understanding of the File's Role:**

The filename itself, `url_request_context.cc`, strongly suggests this file is about managing the context in which URL requests are made. The `.cc` extension indicates it's a C++ source file, part of the Chromium project. The inclusion of `<net/url_request/url_request_context.h>` further confirms its central role in the URL request system.

**2. Scanning for Key Data Members:**

The next step is to scan the class definition (`class URLRequestContext`) for its member variables. These members represent the state and dependencies of a `URLRequestContext` object. I looked for pointers and unique pointers, as these often indicate important components. I started noting down the types of these members:

* `std::unique_ptr<std::set<raw_ptr<const URLRequest, SetExperimental>>> url_requests_`:  This immediately suggests tracking active URL requests.
* `NetLog* net_log_`:  Likely for logging network events.
* `std::unique_ptr<HostResolver> host_resolver_`:  For resolving domain names to IP addresses.
* `std::unique_ptr<CertVerifier> cert_verifier_`:  For verifying SSL certificates.
* `std::unique_ptr<ProxyResolutionService> proxy_resolution_service_`:  For handling proxy configurations.
* And so on...

As I listed these, I started forming hypotheses about their roles. For instance, "host resolver" is pretty self-explanatory.

**3. Examining Public Methods:**

After understanding the data members, I looked at the public methods of the `URLRequestContext` class. These methods define the interface for interacting with the object. Key methods that stood out were:

* `URLRequestContext(base::PassKey<URLRequestContextBuilder> pass_key)`: The constructor. The `PassKey` idiom suggests it's meant to be constructed in a controlled manner (likely through a builder).
* `~URLRequestContext()`: The destructor. The code inside it is crucial for understanding cleanup and shutdown procedures.
* `CreateRequest(...)`: This is a core function, indicating the context is responsible for creating `URLRequest` objects.
* `AssertNoURLRequests()`:  A debugging/assertion function to check for resource leaks.
* The `set_...` methods: These are setters for the various member variables, indicating how dependencies are injected.
* `GetNetworkSessionParams()` and `GetNetworkSessionContext()`: Methods for accessing underlying network session information.

**4. Analyzing the Destructor (`~URLRequestContext()`):**

The destructor's code is particularly important. It reveals the order in which components are shut down and what cleanup actions are performed. The comments within the destructor provided valuable insights into the reasoning behind the shutdown order, especially concerning `ReportingService` and `ProxyResolutionService`.

**5. Connecting to JavaScript (and Web Browsing):**

At this point, I started thinking about how these components relate to the user's web browsing experience and how JavaScript interacts with them.

* **`CreateRequest`:** This is the fundamental action that triggers network activity. JavaScript in a web page (or in a service worker, etc.) initiates network requests using APIs like `fetch` or `XMLHttpRequest`. These APIs, at a lower level within the browser, will eventually lead to the creation of `URLRequest` objects using this `URLRequestContext`.
* **Cookies (`CookieStore`)**: JavaScript can access and manipulate cookies through the `document.cookie` API. The `URLRequestContext` manages the `CookieStore`, which stores and retrieves cookies for these requests.
* **Caching (`HttpCache`, `HttpNetworkSession`)**:  When JavaScript fetches a resource, the browser often caches it to improve performance. The `URLRequestContext` is involved in managing the HTTP cache.
* **Security (`CertVerifier`, `TransportSecurityState`)**: When a JavaScript application makes an HTTPS request, the browser uses the `CertVerifier` to check the server's certificate and the `TransportSecurityState` to enforce HSTS (HTTP Strict Transport Security).
* **Proxies (`ProxyResolutionService`, `ProxyDelegate`)**: If the user has configured a proxy, the `URLRequestContext` uses the `ProxyResolutionService` to determine how to route the request.
* **DNS (`HostResolver`)**: When a JavaScript application makes a request to a domain name, the browser uses the `HostResolver` to look up the IP address.

**6. Formulating Examples and Scenarios:**

To illustrate the connections and potential issues, I started thinking of concrete scenarios:

* **JavaScript `fetch()`:**  A simple `fetch("https://example.com")` call in JavaScript would trigger the creation of a `URLRequest` within the relevant `URLRequestContext`.
* **Cookie manipulation:**  `document.cookie = "mycookie=value"` would interact with the `CookieStore` managed by the context.
* **HTTPS errors:**  An invalid SSL certificate on a server accessed by JavaScript would involve the `CertVerifier` and might lead to an error displayed in the browser.
* **Proxy issues:**  Incorrect proxy settings could cause network requests initiated by JavaScript to fail.

**7. Considering User/Programming Errors:**

I considered common mistakes developers or users might make:

* **Leaking `URLRequest` objects:**  If JavaScript code initiates a request but doesn't properly handle the response or cancel the request, it could lead to leaks, which the `AssertNoURLRequests()` function is designed to detect.
* **Incorrect proxy configuration:** Users might enter the wrong proxy settings, preventing network access.
* **Misunderstanding caching behavior:**  Developers might not understand how the browser cache works, leading to unexpected behavior.

**8. Debugging and User Actions:**

Finally, I considered how a user's actions could lead to the execution of code within this file and how debugging might involve it:

* **Typing a URL in the address bar:** This is a primary way to initiate network requests.
* **Clicking on a link:**  Similar to typing a URL.
* **JavaScript code making requests:**  As discussed above.
* **Browser settings:**  Changing proxy settings, clearing browsing data (including cookies and cache), etc.

For debugging, knowing that `URLRequestContext` manages key network components is crucial. If a network request is failing, a developer might investigate the state of the `HostResolver`, `ProxyResolutionService`, `CertVerifier`, or `CookieStore` associated with the relevant `URLRequestContext`. Network logs (`NetLog`) would be an invaluable tool for tracing the execution flow and identifying issues.

This iterative process of examining the code, understanding its purpose, connecting it to real-world scenarios, and considering potential issues allowed me to generate the detailed explanation provided in the initial prompt.
好的，我们来分析一下 `net/url_request/url_request_context.cc` 这个文件，它在 Chromium 网络栈中扮演着核心角色。

**功能概述：**

`URLRequestContext` 是 Chromium 中管理所有与特定“上下文”相关的网络请求的关键类。你可以把它想象成一个容器或环境，其中包含了发起和处理网络请求所需的所有配置和状态。 它的主要功能包括：

1. **管理网络会话 (Network Session Management):**  它拥有和管理 `HttpNetworkSession` 对象，后者负责维护 HTTP 连接池、处理 HTTP 协议相关的逻辑（如 Keep-Alive、HTTP/2 等）。
2. **管理网络配置 (Network Configuration Management):** 它聚合了各种网络相关的配置信息，例如：
    * **HostResolver:** 用于将域名解析为 IP 地址。
    * **ProxyResolutionService:** 用于确定请求是否需要通过代理服务器，以及使用哪个代理。
    * **SSLConfigService:** 用于管理 SSL/TLS 连接的配置。
    * **CookieStore:** 用于存储和管理 Cookie。
    * **HttpServerProperties:** 用于存储 HTTP 服务器的属性，例如支持的协议、QUIC 信息等，以优化后续连接。
    * **TransportSecurityState:** 用于存储和管理 HSTS (HTTP Strict Transport Security) 和 HPKP (HTTP Public Key Pinning) 策略。
3. **创建 URLRequest (URLRequest Creation):** 它提供了创建 `URLRequest` 对象的接口。`URLRequest` 代表一个具体的网络请求。
4. **管理网络委托 (Network Delegate Management):** 它持有一个 `NetworkDelegate` 对象，该对象允许观察和修改网络请求的生命周期，例如拦截请求、修改请求头、处理重定向等。
5. **管理各种网络服务 (Network Service Management):**  根据编译选项，它可能管理：
    * **ReportingService 和 NetworkErrorLoggingService:** 用于收集和报告网络错误和安全策略违规。
    * **DeviceBoundSessionService:** 用于管理与设备绑定的会话（如果启用）。
6. **生命周期管理 (Lifecycle Management):**  它负责各个组件的初始化和销毁，确保在不再需要时正确释放资源。
7. **提供 NetLog 支持 (NetLog Support):** 它关联一个 `NetLog` 对象，用于记录网络事件，方便调试和分析。
8. **断言无未完成请求 (Assert No Pending Requests):**  在析构函数中会检查是否还有未完成的 `URLRequest`，帮助发现潜在的资源泄漏。

**与 JavaScript 的关系及举例：**

JavaScript 代码无法直接操作 `URLRequestContext` 对象，但用户的 JavaScript 代码发起的网络请求会间接地依赖于 `URLRequestContext` 提供的功能。

**举例说明：**

假设一个网页上的 JavaScript 代码使用 `fetch` API 发起一个 HTTPS 请求：

```javascript
fetch('https://www.example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这段 JavaScript 代码执行时，浏览器内部会发生以下与 `URLRequestContext` 相关的操作：

1. **URLRequest 创建:**  浏览器会创建一个与该 `fetch` 请求对应的 `URLRequest` 对象。这个创建过程会调用 `URLRequestContext::CreateRequest` 方法。
    * **假设输入:** `url = https://www.example.com/data.json`, `priority = MEDIUM`, `delegate = ... (处理响应的委托对象)`
    * **假设输出:** 一个指向新创建的 `URLRequest` 对象的指针。

2. **DNS 解析:** 在发起 TCP 连接之前，需要知道 `www.example.com` 的 IP 地址。`URLRequestContext` 会使用其 `HostResolver` 进行 DNS 查询。
    * **假设输入:**  域名 `www.example.com`
    * **假设输出:**  对应的 IP 地址（例如 `93.184.216.34`）。

3. **代理查找 (如果需要):**  如果用户配置了代理，`URLRequestContext` 会使用 `ProxyResolutionService` 来确定是否需要使用代理以及使用哪个代理服务器。
    * **假设输入:**  目标 URL `https://www.example.com/data.json`
    * **假设输出:**  `DIRECT` (表示直连) 或代理服务器的地址和端口 (例如 `PROXY proxy.example.com:8080`)。

4. **SSL/TLS 连接建立:**  由于是 HTTPS 请求，需要建立安全的 TLS 连接。`URLRequestContext` 会使用其 `SSLConfigService` 获取 SSL 配置，并使用 `CertVerifier` 验证服务器的证书。
    * **假设输入:**  服务器提供的 SSL 证书
    * **假设输出:**  证书验证成功或失败。

5. **Cookie 管理:**  浏览器会检查 `URLRequestContext` 的 `CookieStore` 中是否有与 `www.example.com` 相关的 Cookie，并将这些 Cookie 添加到请求头中。服务器返回的 `Set-Cookie` 响应头也会被 `CookieStore` 处理并存储。
    * **假设输入:**  目标 URL `https://www.example.com/data.json`
    * **假设输出:**  要添加到请求头的 Cookie 字符串。

6. **HTTP 会话管理:**  请求会通过 `URLRequestContext` 管理的 `HttpNetworkSession` 发送。`HttpNetworkSession` 负责连接的复用、HTTP/2 或 QUIC 协议的处理等。

7. **网络委托介入:** 在请求的各个阶段，`URLRequestContext` 的 `NetworkDelegate` 可以被调用，例如在请求发送前修改请求头，或者在接收到响应后进行一些处理。

**逻辑推理的假设输入与输出：**

上面的例子中已经包含了一些逻辑推理的假设输入和输出。再举一个更具体的例子：

**场景：**  JavaScript 代码发起一个请求，目标服务器在 HSTS 列表中。

* **假设输入:**
    * JavaScript 发起请求到 `https://secure.example.com/resource`。
    * `URLRequestContext` 的 `TransportSecurityState` 中记录了 `secure.example.com` 的 HSTS 策略。
* **逻辑推理:** `URLRequestContext` 会检查 `TransportSecurityState`，发现 `secure.example.com` 启用了 HSTS。
* **假设输出:**  即使 JavaScript 代码尝试使用 `http://secure.example.com/resource`，`URLRequestContext` 也会强制将其升级为 `https://secure.example.com/resource`，并在内部发起对 HTTPS 地址的请求。

**用户或编程常见的使用错误及举例：**

1. **泄漏 `URLRequest` 对象:** 如果编程时创建了 `URLRequest` 对象，但没有正确地启动和释放它，可能会导致资源泄漏。虽然 JavaScript 代码通常不直接操作 `URLRequest`，但在 C++ 的网络栈内部开发中可能会出现这种错误。
    * **错误示例 (C++):** 创建了一个 `URLRequest` 对象，但忘记调用 `Start()` 或在完成时释放。
    * **调试线索:** `URLRequestContext` 的析构函数中的 `AssertNoURLRequests()` 会触发断言，提示有未完成的请求，并打印泄漏的 URL。

2. **错误的代理配置:** 用户在操作系统或浏览器中配置了错误的代理服务器地址或端口，导致网络请求失败。
    * **用户操作:** 在浏览器设置中输入错误的代理地址。
    * **到达 `URLRequestContext` 的过程:** 当 JavaScript 发起网络请求时，`ProxyResolutionService` 会根据配置尝试连接到错误的代理，导致连接失败。
    * **调试线索:**  可以在 NetLog 中看到代理解析和连接尝试的详细信息，包括连接错误。

3. **Cookie 设置错误:**  JavaScript 代码错误地设置或清除了 Cookie，导致服务器端认证或状态管理出现问题。
    * **用户操作:**  JavaScript 代码使用 `document.cookie` 设置了错误的 Cookie 值或过期时间。
    * **到达 `URLRequestContext` 的过程:**  后续的网络请求会携带这些错误的 Cookie，服务器可能会返回错误或未授权的响应。`URLRequestContext` 的 `CookieStore` 负责存储和提供 Cookie。
    * **调试线索:**  可以在开发者工具的网络面板中查看请求头中的 Cookie 信息，以及服务器返回的 `Set-Cookie` 响应头。

4. **HTTPS 连接问题:**  服务器的 SSL 证书无效或配置错误，导致 HTTPS 连接失败。
    * **用户操作:**  访问一个使用了过期或自签名证书的 HTTPS 网站。
    * **到达 `URLRequestContext` 的过程:**  `CertVerifier` 在验证服务器证书时会失败，导致连接中断。
    * **调试线索:**  浏览器会显示安全警告，NetLog 中会记录证书验证失败的详细信息。

**用户操作如何一步步地到达这里，作为调试线索：**

以用户在浏览器中访问一个网页为例：

1. **用户在地址栏输入 URL 并按下回车，或点击一个链接。**
2. **浏览器进程接收到导航请求。**
3. **浏览器进程创建一个新的渲染器进程（如果需要）来加载网页。**
4. **渲染器进程开始解析 HTML，遇到需要加载的资源（例如图片、CSS、JavaScript 文件）。**
5. **渲染器进程中的 JavaScript 代码可能使用 `fetch` 或 `XMLHttpRequest` 发起额外的网络请求。**
6. **对于每个需要加载的资源，渲染器进程会通过 IPC (进程间通信) 向浏览器进程的网络服务发起请求。**
7. **浏览器进程的网络服务层会创建一个与该请求对应的 `URLRequest` 对象。**
8. **`URLRequestContext` 作为管理网络请求的核心组件，会被用来处理这个 `URLRequest`。** 这包括：
    * 使用 `HostResolver` 进行 DNS 解析。
    * 使用 `ProxyResolutionService` 确定代理。
    * 如果是 HTTPS 请求，使用 `CertVerifier` 验证证书，使用 `SSLConfigService` 获取 SSL 配置。
    * 从 `CookieStore` 获取相关的 Cookie 并添加到请求头。
    * 通过 `HttpNetworkSession` 发送请求。
    * `NetworkDelegate` 可以观察和修改请求过程。
9. **服务器返回响应后，`URLRequestContext` 会处理响应头中的 Cookie，并将响应数据传递回渲染器进程。**
10. **渲染器进程接收到响应数据，并继续渲染网页或执行 JavaScript 代码。**

**调试线索：**

当网络请求出现问题时，可以利用以下线索来定位问题：

* **浏览器开发者工具 (Network 面板):** 查看请求的状态、请求头、响应头、Cookie 信息、耗时等。
* **`chrome://net-export/` (NetLog):**  记录 Chromium 网络栈的详细事件，包括 DNS 解析、代理查找、连接建立、SSL 握手、HTTP 事务等。通过 NetLog 可以追踪请求的整个生命周期，并查看 `URLRequestContext` 及其关联组件的行为。
* **`chrome://flags/`:** 某些网络相关的实验性功能可以通过 flags 进行调整，可能会影响 `URLRequestContext` 的行为。
* **操作系统网络配置:**  检查操作系统的代理设置、DNS 设置等，这些会影响 `URLRequestContext` 的决策。

总而言之，`URLRequestContext` 是 Chromium 网络栈中至关重要的一个类，它协调和管理着网络请求的各个方面，与 JavaScript 的网络 API 有着紧密的联系，尽管 JavaScript 代码无法直接访问它。理解其功能对于调试网络问题至关重要。

### 提示词
```
这是目录为net/url_request/url_request_context.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/url_request/url_request_context.h"

#include <inttypes.h>
#include <stdint.h>

#include "base/compiler_specific.h"
#include "base/debug/alias.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "base/types/pass_key.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "net/base/http_user_agent_settings.h"
#include "net/base/network_delegate.h"
#include "net/base/proxy_delegate.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/sct_auditing_delegate.h"
#include "net/cookies/cookie_store.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_cache.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_transaction_factory.h"
#include "net/http/transport_security_persister.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_source.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/quic/quic_context.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/ssl_client_socket_impl.h"
#include "net/ssl/ssl_config_service.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_job_factory.h"

#if BUILDFLAG(ENABLE_REPORTING)
#include "net/network_error_logging/network_error_logging_service.h"
#include "net/network_error_logging/persistent_reporting_and_nel_store.h"
#include "net/reporting/reporting_service.h"
#endif  // BUILDFLAG(ENABLE_REPORTING)

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
#include "net/device_bound_sessions/session_service.h"
#include "net/device_bound_sessions/session_store.h"
#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

namespace net {

URLRequestContext::URLRequestContext(
    base::PassKey<URLRequestContextBuilder> pass_key)
    : url_requests_(std::make_unique<
                    std::set<raw_ptr<const URLRequest, SetExperimental>>>()),
      bound_network_(handles::kInvalidNetworkHandle) {}

URLRequestContext::~URLRequestContext() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
#if BUILDFLAG(ENABLE_REPORTING)
  // Shut down the NetworkErrorLoggingService so that destroying the
  // ReportingService (which might abort in-flight URLRequests, generating
  // network errors) won't recursively try to queue more network error
  // reports.
  if (network_error_logging_service())
    network_error_logging_service()->OnShutdown();

  // Shut down the ReportingService before the rest of the URLRequestContext,
  // so it cancels any pending requests it may have.
  if (reporting_service())
    reporting_service()->OnShutdown();
#endif  // BUILDFLAG(ENABLE_REPORTING)

  // Shut down the ProxyResolutionService, as it may have pending URLRequests
  // using this context. Since this cancels requests, it's not safe to
  // subclass this, as some parts of the URLRequestContext may then be torn
  // down before this cancels the ProxyResolutionService's URLRequests.
  proxy_resolution_service()->OnShutdown();

  // If a ProxyDelegate is set then the builder gave it a pointer to the
  // ProxyResolutionService, so clear that here to avoid having a dangling
  // pointer. There's no need to clear the ProxyResolutionService's pointer to
  // ProxyDelegate because the member destruction order ensures that
  // ProxyResolutionService is destroyed first.
  if (proxy_delegate()) {
    proxy_delegate()->SetProxyResolutionService(nullptr);
  }

  DCHECK(host_resolver());
  host_resolver()->OnShutdown();

  AssertNoURLRequests();
}

const HttpNetworkSessionParams* URLRequestContext::GetNetworkSessionParams()
    const {
  HttpTransactionFactory* transaction_factory = http_transaction_factory();
  if (!transaction_factory)
    return nullptr;
  HttpNetworkSession* network_session = transaction_factory->GetSession();
  if (!network_session)
    return nullptr;
  return &network_session->params();
}

const HttpNetworkSessionContext* URLRequestContext::GetNetworkSessionContext()
    const {
  HttpTransactionFactory* transaction_factory = http_transaction_factory();
  if (!transaction_factory)
    return nullptr;
  HttpNetworkSession* network_session = transaction_factory->GetSession();
  if (!network_session)
    return nullptr;
  return &network_session->context();
}

// TODO(crbug.com/40118868): Revisit once build flag switch of lacros-chrome is
// complete.
#if !BUILDFLAG(IS_WIN) && \
    !(BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS_LACROS))
std::unique_ptr<URLRequest> URLRequestContext::CreateRequest(
    const GURL& url,
    RequestPriority priority,
    URLRequest::Delegate* delegate) const {
  return CreateRequest(url, priority, delegate, MISSING_TRAFFIC_ANNOTATION,
                       /*is_for_websockets=*/false);
}
#endif

std::unique_ptr<URLRequest> URLRequestContext::CreateRequest(
    const GURL& url,
    RequestPriority priority,
    URLRequest::Delegate* delegate,
    NetworkTrafficAnnotationTag traffic_annotation,
    bool is_for_websockets,
    const std::optional<net::NetLogSource> net_log_source) const {
  return std::make_unique<URLRequest>(
      base::PassKey<URLRequestContext>(), url, priority, delegate, this,
      traffic_annotation, is_for_websockets, net_log_source);
}

void URLRequestContext::AssertNoURLRequests() const {
  int num_requests = url_requests_->size();
  if (num_requests != 0) {
    // We're leaking URLRequests :( Dump the URL of the first one and record how
    // many we leaked so we have an idea of how bad it is.
    const URLRequest* request = *url_requests_->begin();
    int load_flags = request->load_flags();
    DEBUG_ALIAS_FOR_GURL(url_buf, request->url());
    base::debug::Alias(&num_requests);
    base::debug::Alias(&load_flags);
    CHECK(false) << "Leaked " << num_requests << " URLRequest(s). First URL: "
                 << request->url().spec().c_str() << ".";
  }
}

void URLRequestContext::set_net_log(NetLog* net_log) {
  net_log_ = net_log;
}
void URLRequestContext::set_host_resolver(
    std::unique_ptr<HostResolver> host_resolver) {
  DCHECK(host_resolver.get());
  host_resolver_ = std::move(host_resolver);
}
void URLRequestContext::set_cert_verifier(
    std::unique_ptr<CertVerifier> cert_verifier) {
  cert_verifier_ = std::move(cert_verifier);
}
void URLRequestContext::set_proxy_resolution_service(
    std::unique_ptr<ProxyResolutionService> proxy_resolution_service) {
  proxy_resolution_service_ = std::move(proxy_resolution_service);
}
void URLRequestContext::set_proxy_delegate(
    std::unique_ptr<ProxyDelegate> proxy_delegate) {
  proxy_delegate_ = std::move(proxy_delegate);
}
void URLRequestContext::set_ssl_config_service(
    std::unique_ptr<SSLConfigService> service) {
  ssl_config_service_ = std::move(service);
}
void URLRequestContext::set_http_auth_handler_factory(
    std::unique_ptr<HttpAuthHandlerFactory> factory) {
  http_auth_handler_factory_ = std::move(factory);
}
void URLRequestContext::set_http_network_session(
    std::unique_ptr<HttpNetworkSession> http_network_session) {
  http_network_session_ = std::move(http_network_session);
}
void URLRequestContext::set_http_transaction_factory(
    std::unique_ptr<HttpTransactionFactory> factory) {
  http_transaction_factory_ = std::move(factory);
}
void URLRequestContext::set_network_delegate(
    std::unique_ptr<NetworkDelegate> network_delegate) {
  network_delegate_ = std::move(network_delegate);
}
void URLRequestContext::set_http_server_properties(
    std::unique_ptr<HttpServerProperties> http_server_properties) {
  http_server_properties_ = std::move(http_server_properties);
}
void URLRequestContext::set_cookie_store(
    std::unique_ptr<CookieStore> cookie_store) {
  cookie_store_ = std::move(cookie_store);
}
void URLRequestContext::set_transport_security_state(
    std::unique_ptr<TransportSecurityState> state) {
  transport_security_state_ = std::move(state);
}
void URLRequestContext::set_sct_auditing_delegate(
    std::unique_ptr<SCTAuditingDelegate> delegate) {
  sct_auditing_delegate_ = std::move(delegate);
}
void URLRequestContext::set_job_factory(
    std::unique_ptr<const URLRequestJobFactory> job_factory) {
  job_factory_storage_ = std::move(job_factory);
  job_factory_ = job_factory_storage_.get();
}
void URLRequestContext::set_quic_context(
    std::unique_ptr<QuicContext> quic_context) {
  quic_context_ = std::move(quic_context);
}
void URLRequestContext::set_http_user_agent_settings(
    std::unique_ptr<const HttpUserAgentSettings> http_user_agent_settings) {
  http_user_agent_settings_ = std::move(http_user_agent_settings);
}
void URLRequestContext::set_network_quality_estimator(
    NetworkQualityEstimator* network_quality_estimator) {
  network_quality_estimator_ = network_quality_estimator;
}
void URLRequestContext::set_client_socket_factory(
    std::unique_ptr<ClientSocketFactory> client_socket_factory) {
  client_socket_factory_ = std::move(client_socket_factory);
}
#if BUILDFLAG(ENABLE_REPORTING)
void URLRequestContext::set_persistent_reporting_and_nel_store(
    std::unique_ptr<PersistentReportingAndNelStore>
        persistent_reporting_and_nel_store) {
  persistent_reporting_and_nel_store_ =
      std::move(persistent_reporting_and_nel_store);
}
void URLRequestContext::set_reporting_service(
    std::unique_ptr<ReportingService> reporting_service) {
  reporting_service_ = std::move(reporting_service);
}
void URLRequestContext::set_network_error_logging_service(
    std::unique_ptr<NetworkErrorLoggingService> network_error_logging_service) {
  network_error_logging_service_ = std::move(network_error_logging_service);
}
#endif  // BUILDFLAG(ENABLE_REPORTING)

void URLRequestContext::set_transport_security_persister(
    std::unique_ptr<TransportSecurityPersister> transport_security_persister) {
  transport_security_persister_ = std::move(transport_security_persister);
}

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
void URLRequestContext::set_device_bound_session_service(
    std::unique_ptr<device_bound_sessions::SessionService>
        device_bound_session_service) {
  device_bound_session_service_ = std::move(device_bound_session_service);
}
void URLRequestContext::set_device_bound_session_store(
    std::unique_ptr<device_bound_sessions::SessionStore>
        device_bound_session_store) {
  device_bound_session_store_ = std::move(device_bound_session_store);
}
#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

}  // namespace net
```
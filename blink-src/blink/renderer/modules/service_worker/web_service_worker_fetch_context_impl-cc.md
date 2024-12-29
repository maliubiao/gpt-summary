Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

**1. Initial Understanding of the Request:**

The request asks for the functionality of the given C++ file (`web_service_worker_fetch_context_impl.cc`), its relation to web technologies (JavaScript, HTML, CSS), logical reasoning examples, common errors, and debugging tips.

**2. Core Purpose Identification:**

The file name itself, `web_service_worker_fetch_context_impl.cc`, strongly suggests it's an implementation related to handling network requests within a Service Worker context in the Blink rendering engine. The `FetchContext` part points to managing the fetching of resources.

**3. Analyzing the Includes:**

The included header files provide crucial clues about the file's responsibilities:

*   `web_service_worker_fetch_context_impl.h`:  The corresponding header file, likely containing the class declaration.
*   `base/metrics/histogram_functions.h`:  Indicates the file records metrics, likely for performance analysis.
*   `base/numerics/safe_conversions.h`:  Suggests careful type casting to prevent overflows.
*   `base/ranges/algorithm.h`:  Utilizes range-based algorithms for data manipulation.
*   `base/synchronization/waitable_event.h`:  Deals with thread synchronization, suggesting asynchronous operations.
*   `base/task/single_thread_task_runner.h`:  Handles tasks on a single thread, common in browser UI and rendering.
*   `mojo/public/cpp/bindings/pending_remote.h`:  Uses Mojo for inter-process communication.
*   `net/cookies/site_for_cookies.h`:  Manages cookie settings and site isolation.
*   `services/network/public/cpp/wrapper_shared_url_loader_factory.h`, `services/network/public/mojom/fetch_api.mojom-shared.h`:  Interacts with the Chromium network service for fetching resources.
*   `third_party/blink/public/common/loader/loader_constants.h`:  Defines constants related to resource loading.
*   `third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h`:  Deals with the structure of fetch requests.
*   `third_party/blink/public/platform/url_loader_throttle_provider.h`, `third_party/blink/public/platform/web_url_request_extra_data.h`, `third_party/blink/public/platform/websocket_handshake_throttle_provider.h`: Handles request modification and control (throttling, extra data for requests, websocket handshakes).
*   `third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h`, `third_party/blink/renderer/platform/loader/internet_disconnected_url_loader.h`: Creates factories for loading URLs, including a special one for offline scenarios.

**4. Analyzing the Class Structure and Methods:**

*   **`WebServiceWorkerFetchContext::Create`:**  A static factory method. This hints at a specific creation process, likely involving dependency injection. The parameters reveal key dependencies: loader factories, throttle providers, preference watchers, etc.
*   **Constructor (`WebServiceWorkerFetchContextImpl`)**: Initializes member variables with the provided dependencies.
*   **`SetTerminateSyncLoadEvent`**:  Deals with synchronization, likely for interrupting long-running loads.
*   **`InitializeOnWorkerThread`**: Sets up the object on the service worker's thread, binding Mojo interfaces and creating `URLLoaderFactory` instances.
*   **`GetURLLoaderFactory`**:  Provides access to the appropriate `URLLoaderFactory`, switching to the offline factory when needed.
*   **`WrapURLLoaderFactory`**: Creates a `URLLoaderFactory` from a Mojo remote.
*   **`GetScriptLoaderFactory`**:  Provides a factory specifically for loading scripts.
*   **`FinalizeRequest`**: Modifies a `WebURLRequest` before it's sent, adding headers (like "Do-Not-Track") and setting referrer policy.
*   **`CreateThrottles`**:  Creates a list of `URLLoaderThrottle` objects to modify or delay requests. It handles a special case for the initial service worker script load.
*   **`GetControllerServiceWorkerMode`**:  Returns the control mode (likely indicating if a controlling service worker is active).
*   **`SiteForCookies`**:  Determines the appropriate site context for cookie management.
*   **`TopFrameOrigin`**:  Returns the origin of the top-level frame (absent in service workers).
*   **`CreateWebSocketHandshakeThrottle`**: Creates a throttle for WebSocket handshakes.
*   **`UpdateSubresourceLoaderFactories`**:  Updates the `URLLoaderFactory` with new factories, possibly after a service worker update.
*   **`NotifyUpdate`**:  Handles preference updates, specifically for accept languages.
*   **`GetAcceptLanguages`**:  Returns the current accept languages setting.
*   **`SetIsOfflineMode`**:  Switches the context to offline mode.

**5. Identifying Connections to Web Technologies:**

*   **JavaScript:** Service Workers are written in JavaScript. This class is fundamental to how a service worker fetches resources initiated by JavaScript code (e.g., `fetch()`).
*   **HTML:**  While not directly manipulating HTML, this class is involved when a service worker intercepts requests for resources referenced in HTML (e.g., `<script>`, `<img>`, `<link>`).
*   **CSS:** Similar to HTML, when a service worker intercepts requests for CSS files, this class manages the fetching process.

**6. Constructing Logical Reasoning Examples:**

Think about how the methods interact. For example, when a `fetch()` call is made in a service worker:

*   **Input:** A `WebURLRequest` object representing the fetch.
*   **Process:**  `FinalizeRequest` might add the "Do-Not-Track" header. `CreateThrottles` might apply delays or modifications. `GetURLLoaderFactory` provides the factory to initiate the actual network request.
*   **Output:** A network request sent using the appropriate `URLLoaderFactory`, potentially with modified headers and subject to throttling.

**7. Identifying Potential User/Programming Errors:**

Consider common mistakes developers make with Service Workers:

*   **CORS Issues:** If the `cors_exempt_header_list` is not configured correctly, a service worker might be unable to fetch cross-origin resources.
*   **Offline Mode Mismanagement:**  Incorrectly setting or checking `is_offline_mode_` could lead to unexpected behavior.
*   **Throttling Issues:** Overly aggressive throttling might prevent resources from loading.

**8. Tracing User Actions (Debugging Clues):**

Consider the steps a user might take that would lead to this code being executed:

*   A user navigates to a website with an active service worker.
*   The service worker intercepts a network request (e.g., for an image, script, or data).
*   The browser creates an instance of `WebServiceWorkerFetchContextImpl` to manage this fetch.
*   Methods like `GetURLLoaderFactory`, `CreateThrottles`, and `FinalizeRequest` are called to process the request.

**9. Structuring the Response:**

Organize the information logically, using clear headings and bullet points. Provide concrete examples and avoid overly technical jargon where possible. Start with a high-level summary and then delve into details. Ensure all parts of the request are addressed.

**Self-Correction/Refinement during the Process:**

*   **Initial thought:**  Focus solely on network requests.
*   **Correction:** Realize the importance of preference handling (`RendererPreferences`, accept languages) and the separate handling of script loading.
*   **Initial thought:**  Provide only generic examples.
*   **Refinement:**  Provide more specific examples related to JavaScript `fetch()`, HTML tags, and CSS `@import`.
*   **Initial thought:** Focus only on the positive functionality.
*   **Correction:**  Actively look for potential error scenarios and debugging clues.

By following this structured analysis and self-correction process, we can generate a comprehensive and accurate response that addresses all aspects of the user's request.
好的，我们来详细分析一下 `blink/renderer/modules/service_worker/web_service_worker_fetch_context_impl.cc` 文件的功能。

**核心功能：为 Service Worker 提供网络请求上下文**

这个文件实现了 `WebServiceWorkerFetchContextImpl` 类，它是 `WebServiceWorkerFetchContext` 接口的具体实现。其核心职责是 **为 Service Worker 内部发起的网络请求提供必要的上下文和配置信息**。  可以将其理解为 Service Worker 在进行网络请求时的“环境管理器”。

**具体功能点：**

1. **创建 URLLoaderFactory:**
    *   `InitializeOnWorkerThread` 方法中会创建 `URLLoaderFactory` 的实例 `url_loader_factory_` 和 `web_script_loader_factory_`。
    *   `URLLoaderFactory` 是 Blink 中用于创建和管理网络请求的核心组件。
    *   `url_loader_factory_` 用于处理 Service Worker 发起的**普通资源请求**（如图片、数据等）。
    *   `web_script_loader_factory_` 专门用于加载 Service Worker 的**脚本文件**。
    *   可以根据是否处于离线模式切换到 `internet_disconnected_url_loader_factory_`，用于模拟断网环境。
    *   `WrapURLLoaderFactory` 允许从 Mojo Remote 创建 `URLLoaderFactory`，用于跨进程通信。

2. **处理请求 Header:**
    *   `FinalizeRequest` 方法用于在请求发送前对 `WebURLRequest` 对象进行最后的配置。
    *   根据用户设置（`renderer_preferences_`），会添加或修改请求头，例如：
        *   添加 "DNT" (Do Not Track) 头。
        *   移除 Referrer 头信息。
    *   设置 `WebURLRequestExtraData`，标记该请求起源于 Service Worker。

3. **提供请求拦截和修改机制 (Throttling):**
    *   `CreateThrottles` 方法负责创建 `URLLoaderThrottle` 列表。
    *   `URLLoaderThrottle` 允许在请求发送前拦截和修改请求，例如添加自定义 Header、延迟请求等。
    *   该方法会检查是否需要跳过对特定脚本 URL 的 throttling（通常是 Service Worker 脚本自身），以避免循环依赖问题。
    *   如果提供了 `throttle_provider_`，则会委托给它来创建 throttles。

4. **管理 Cookie 上下文:**
    *   `SiteForCookies` 方法根据当前上下文（是否为第三方 context）返回合适的 `net::SiteForCookies` 对象，用于确定 Cookie 的作用域。

5. **处理 WebSocket Handshake:**
    *   `CreateWebSocketHandshakeThrottle` 方法用于创建 `WebSocketHandshakeThrottle`，允许在 WebSocket 握手阶段进行拦截和修改。

6. **处理 Renderer 偏好设置:**
    *   构造函数接收 `RendererPreferences`，存储渲染器的偏好设置。
    *   `NotifyUpdate` 方法用于接收 Renderer 偏好设置的更新，并通知相关的监听器（如 `AcceptLanguagesWatcher`）。
    *   `GetAcceptLanguages` 方法返回当前的 Accept-Language 设置。

7. **管理离线模式:**
    *   `SetIsOfflineMode` 方法用于设置 Service Worker 是否处于离线模式。
    *   `GetURLLoaderFactory` 会根据离线模式返回不同的 `URLLoaderFactory`。

8. **处理 CORS Exempt Header:**
    *   构造函数接收 `cors_exempt_header_list`，用于指定不需要进行 CORS 检查的 Header 列表。这个列表在创建 `URLLoaderFactory` 时会被使用。

**与 JavaScript, HTML, CSS 的关系：**

`WebServiceWorkerFetchContextImpl` 处于 Blink 渲染引擎的底层，直接与 JavaScript Service Worker API 交互，并间接地影响 HTML 和 CSS 资源的加载。

*   **JavaScript:**
    *   当 Service Worker 的 JavaScript 代码中使用 `fetch()` API 发起网络请求时，Blink 引擎会使用 `WebServiceWorkerFetchContextImpl` 提供的上下文来执行该请求。
    *   **举例：**  在 Service Worker 的 `fetch` 事件处理函数中，如果执行 `fetch('/api/data')`，那么 `WebServiceWorkerFetchContextImpl` 将负责创建和配置这个请求。它会检查是否需要添加 "DNT" 头，应用 throttling 策略，并使用合适的 `URLLoaderFactory` 发送请求。

*   **HTML:**
    *   当浏览器解析 HTML 页面时，如果遇到需要加载的资源（如 `<img src="...">`, `<script src="...">`, `<link rel="stylesheet" href="...">`），而当前页面有活动的 Service Worker，那么 Service Worker 可以拦截这些请求。
    *   **举例：**  如果 HTML 中有 `<img src="/images/logo.png">`，Service Worker 的 `fetch` 事件被触发，`WebServiceWorkerFetchContextImpl` 就参与到加载 `/images/logo.png` 的过程中。它会决定使用哪个 `URLLoaderFactory`，并应用相应的配置。

*   **CSS:**
    *   与 HTML 类似，当浏览器加载 CSS 文件（通过 `<link>` 标签或 `@import` 规则）时，Service Worker 也可以拦截这些请求。
    *   **举例：**  如果 CSS 文件中包含 `@import url("style.css");`，Service Worker 拦截该请求后，`WebServiceWorkerFetchContextImpl` 会参与处理 `style.css` 的加载。

**逻辑推理、假设输入与输出：**

**假设输入：**

*   Service Worker JavaScript 代码执行 `fetch('https://example.com/data.json', { mode: 'cors' })`。
*   用户在浏览器设置中启用了 "不跟踪"。
*   `cors_exempt_header_list` 为空。

**逻辑推理：**

1. 当 `fetch()` 调用发生时，Blink 会创建一个 `WebURLRequest` 对象，目标 URL 为 `https://example.com/data.json`。
2. `WebServiceWorkerFetchContextImpl::FinalizeRequest` 被调用。
3. 由于用户启用了 "不跟踪"，`request.SetHttpHeaderField(WebString::FromUTF8(kDoNotTrackHeader), "1")` 会被执行，请求头中会添加 `DNT: 1`。
4. `WebServiceWorkerFetchContextImpl::CreateThrottles` 被调用，根据配置可能会创建一些 throttles。
5. `WebServiceWorkerFetchContextImpl::GetURLLoaderFactory` 返回用于发送请求的 `URLLoaderFactory`。
6. 由于 `mode` 为 `'cors'` 且 `cors_exempt_header_list` 为空，浏览器会按照 CORS 规范进行跨域请求。

**输出：**

*   发送到 `https://example.com/data.json` 的 HTTP 请求头中包含 `DNT: 1`。
*   浏览器会按照 CORS 规范处理该请求，服务端需要返回正确的 CORS 响应头。

**用户或编程常见的使用错误：**

1. **CORS 配置错误：**  如果 Service Worker 需要请求跨域资源，但 `cors_exempt_header_list` 没有正确配置，或者服务端没有返回正确的 CORS 头，会导致请求失败。
    *   **例子：** Service Worker 尝试 `fetch('https://api.example.net/data')`，但 `api.example.net` 没有设置 `Access-Control-Allow-Origin` 头，且该域名不在 CORS 白名单中，请求会被浏览器阻止。

2. **Throttling 配置不当：**  如果自定义的 `URLLoaderThrottleProvider` 实现了过于严格的 throttling 策略，可能会导致资源加载缓慢甚至失败。
    *   **例子：**  一个错误的 throttle 可能会对所有请求施加 5 秒的延迟，导致用户体验极差。

3. **离线模式状态管理错误：**  在需要离线访问的场景下，如果没有正确设置 `is_offline_mode_`，可能会导致请求发送到网络，而不是从缓存中读取。
    *   **例子：**  用户明明处于离线状态，但 Service Worker 仍然尝试从网络 `fetch` 资源，导致请求失败。

4. **修改请求头的错误理解：**  开发者可能会错误地认为可以在 `FinalizeRequest` 中随意修改所有请求头，但某些关键的请求头（如 `Host`）是受浏览器保护的，不能被随意修改。

**用户操作是如何一步步到达这里（调试线索）：**

1. **用户访问一个注册了 Service Worker 的网站。** 浏览器会下载并安装该网站的 Service Worker。
2. **用户执行某些操作，触发 Service Worker 的 `fetch` 事件。**  这可能是页面加载资源、用户点击链接、或者 JavaScript 代码发起网络请求。
3. **在 Service Worker 的 `fetch` 事件处理函数中，调用了 `fetch()` API 或者返回了一个 `Response` 对象（该对象可能需要发起新的请求）。**
4. **Blink 渲染引擎接收到 Service Worker 发起的网络请求。**
5. **Blink 创建 `WebServiceWorkerFetchContextImpl` 的实例，用于管理这次请求的上下文。**  创建时会传入相关的配置信息，如 Renderer 偏好设置、loader factory 等。
6. **`WebServiceWorkerFetchContextImpl` 的方法被依次调用：**
    *   `FinalizeRequest`：添加或修改请求头。
    *   `CreateThrottles`：应用 throttling 策略。
    *   `GetURLLoaderFactory`：获取用于发送请求的 `URLLoaderFactory`。
    *   `URLLoaderFactory` 创建实际的 `URLLoader` 并发送网络请求。

**调试线索：**

*   **Service Worker 的生命周期事件：**  检查 Service Worker 的安装（`install`）和激活（`activate`）事件是否正常执行。
*   **`fetch` 事件处理函数：**  在 `fetch` 事件处理函数中添加 `console.log` 语句，查看请求的 URL、请求头等信息。
*   **Network 面板：**  使用 Chrome 开发者工具的 Network 面板，查看 Service Worker 发起的请求状态、请求头、响应头等信息。
*   **Service Worker 面板：**  使用 Chrome 开发者工具的 Application -> Service Workers 面板，查看 Service Worker 的状态、更新情况等。
*   **Blink 调试：**  如果需要深入调试 Blink 引擎，可以使用 gdb 等调试器，设置断点在 `WebServiceWorkerFetchContextImpl` 的相关方法中，例如 `FinalizeRequest`、`CreateThrottles`、`GetURLLoaderFactory` 等，跟踪请求的处理流程。
*   **Mojo 接口监控：**  如果涉及到跨进程通信，可以使用 Mojo 的调试工具来监控 Mojo 接口的调用情况。

希望以上分析能够帮助你理解 `web_service_worker_fetch_context_impl.cc` 文件的功能。

Prompt: 
```
这是目录为blink/renderer/modules/service_worker/web_service_worker_fetch_context_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/service_worker/web_service_worker_fetch_context_impl.h"

#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "net/cookies/site_for_cookies.h"
#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/fetch_api.mojom-shared.h"
#include "third_party/blink/public/common/loader/loader_constants.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/url_loader_throttle_provider.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/public/platform/websocket_handshake_throttle_provider.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h"
#include "third_party/blink/renderer/platform/loader/internet_disconnected_url_loader.h"

namespace blink {

// static
scoped_refptr<WebServiceWorkerFetchContext>
WebServiceWorkerFetchContext::Create(
    const RendererPreferences& renderer_preferences,
    const WebURL& worker_script_url,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_url_loader_factory,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_script_loader_factory,
    const WebURL& script_url_to_skip_throttling,
    std::unique_ptr<URLLoaderThrottleProvider> throttle_provider,
    std::unique_ptr<WebSocketHandshakeThrottleProvider>
        websocket_handshake_throttle_provider,
    CrossVariantMojoReceiver<
        mojom::blink::RendererPreferenceWatcherInterfaceBase>
        preference_watcher_receiver,
    CrossVariantMojoReceiver<
        mojom::blink::SubresourceLoaderUpdaterInterfaceBase>
        pending_subresource_loader_updater,
    const WebVector<WebString>& web_cors_exempt_header_list,
    const bool is_third_party_context) {
  base::UmaHistogramCounts100(
      "ServiceWorker.CorsExemptHeaderListSize",
      base::saturated_cast<int>(web_cors_exempt_header_list.size()));

  Vector<String> cors_exempt_header_list(
      base::checked_cast<wtf_size_t>(web_cors_exempt_header_list.size()));
  base::ranges::transform(web_cors_exempt_header_list,
                          cors_exempt_header_list.begin(),
                          &WebString::operator WTF::String);
  return base::MakeRefCounted<WebServiceWorkerFetchContextImpl>(
      renderer_preferences, KURL(worker_script_url.GetString()),
      std::move(pending_url_loader_factory),
      std::move(pending_script_loader_factory),
      KURL(script_url_to_skip_throttling.GetString()),
      std::move(throttle_provider),
      std::move(websocket_handshake_throttle_provider),
      std::move(preference_watcher_receiver),
      std::move(pending_subresource_loader_updater),
      std::move(cors_exempt_header_list), is_third_party_context);
}

WebServiceWorkerFetchContextImpl::WebServiceWorkerFetchContextImpl(
    const RendererPreferences& renderer_preferences,
    const KURL& worker_script_url,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_url_loader_factory,
    std::unique_ptr<network::PendingSharedURLLoaderFactory>
        pending_script_loader_factory,
    const KURL& script_url_to_skip_throttling,
    std::unique_ptr<URLLoaderThrottleProvider> throttle_provider,
    std::unique_ptr<WebSocketHandshakeThrottleProvider>
        websocket_handshake_throttle_provider,
    mojo::PendingReceiver<mojom::blink::RendererPreferenceWatcher>
        preference_watcher_receiver,
    mojo::PendingReceiver<mojom::blink::SubresourceLoaderUpdater>
        pending_subresource_loader_updater,
    Vector<String> cors_exempt_header_list,
    const bool is_third_party_context)
    : renderer_preferences_(renderer_preferences),
      worker_script_url_(worker_script_url),
      pending_url_loader_factory_(std::move(pending_url_loader_factory)),
      pending_script_loader_factory_(std::move(pending_script_loader_factory)),
      script_url_to_skip_throttling_(script_url_to_skip_throttling),
      throttle_provider_(std::move(throttle_provider)),
      websocket_handshake_throttle_provider_(
          std::move(websocket_handshake_throttle_provider)),
      preference_watcher_pending_receiver_(
          std::move(preference_watcher_receiver)),
      pending_subresource_loader_updater_(
          std::move(pending_subresource_loader_updater)),
      cors_exempt_header_list_(std::move(cors_exempt_header_list)),
      is_third_party_context_(is_third_party_context) {}

WebServiceWorkerFetchContextImpl::~WebServiceWorkerFetchContextImpl() = default;

void WebServiceWorkerFetchContextImpl::SetTerminateSyncLoadEvent(
    base::WaitableEvent* terminate_sync_load_event) {
  DCHECK(!terminate_sync_load_event_);
  terminate_sync_load_event_ = terminate_sync_load_event;
}

void WebServiceWorkerFetchContextImpl::InitializeOnWorkerThread(
    AcceptLanguagesWatcher* watcher) {
  preference_watcher_receiver_.Bind(
      std::move(preference_watcher_pending_receiver_));
  subresource_loader_updater_.Bind(
      std::move(pending_subresource_loader_updater_));

  url_loader_factory_ = std::make_unique<URLLoaderFactory>(
      network::SharedURLLoaderFactory::Create(
          std::move(pending_url_loader_factory_)),
      cors_exempt_header_list_, terminate_sync_load_event_);

  internet_disconnected_url_loader_factory_ =
      std::make_unique<InternetDisconnectedURLLoaderFactory>();

  if (pending_script_loader_factory_) {
    web_script_loader_factory_ = std::make_unique<URLLoaderFactory>(
        network::SharedURLLoaderFactory::Create(
            std::move(pending_script_loader_factory_)),
        cors_exempt_header_list_, terminate_sync_load_event_);
  }

  accept_languages_watcher_ = watcher;
}

URLLoaderFactory* WebServiceWorkerFetchContextImpl::GetURLLoaderFactory() {
  if (is_offline_mode_)
    return internet_disconnected_url_loader_factory_.get();
  return url_loader_factory_.get();
}

std::unique_ptr<URLLoaderFactory>
WebServiceWorkerFetchContextImpl::WrapURLLoaderFactory(
    CrossVariantMojoRemote<network::mojom::URLLoaderFactoryInterfaceBase>
        url_loader_factory) {
  return std::make_unique<URLLoaderFactory>(
      base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
          std::move(url_loader_factory)),
      cors_exempt_header_list_, terminate_sync_load_event_);
}

URLLoaderFactory* WebServiceWorkerFetchContextImpl::GetScriptLoaderFactory() {
  return web_script_loader_factory_.get();
}

void WebServiceWorkerFetchContextImpl::FinalizeRequest(WebURLRequest& request) {
  if (renderer_preferences_.enable_do_not_track) {
    request.SetHttpHeaderField(WebString::FromUTF8(kDoNotTrackHeader), "1");
  }
  auto url_request_extra_data = base::MakeRefCounted<WebURLRequestExtraData>();
  url_request_extra_data->set_originated_from_service_worker(true);

  request.SetURLRequestExtraData(std::move(url_request_extra_data));

  if (!renderer_preferences_.enable_referrers) {
    request.SetReferrerString(WebString());
    request.SetReferrerPolicy(network::mojom::ReferrerPolicy::kNever);
  }
}

WebVector<std::unique_ptr<URLLoaderThrottle>>
WebServiceWorkerFetchContextImpl::CreateThrottles(
    const network::ResourceRequest& request) {
  const bool needs_to_skip_throttling =
      KURL(request.url) == script_url_to_skip_throttling_ &&
      (request.destination ==
           network::mojom::RequestDestination::kServiceWorker ||
       request.destination == network::mojom::RequestDestination::kScript);
  if (needs_to_skip_throttling) {
    // Throttling is needed when the skipped script is loaded again because it's
    // served from ServiceWorkerInstalledScriptLoader after the second time,
    // while at the first time the script comes from
    // ServiceWorkerUpdatedScriptLoader which uses ThrottlingURLLoader in the
    // browser process. See also comments at
    // EmbeddedWorkerStartParams::script_url_to_skip_throttling.
    // TODO(https://crbug.com/993641): need to simplify throttling for service
    // worker scripts.
    script_url_to_skip_throttling_ = KURL();
  } else if (throttle_provider_) {
    return throttle_provider_->CreateThrottles(std::nullopt, request);
  }
  return {};
}

mojom::ControllerServiceWorkerMode
WebServiceWorkerFetchContextImpl::GetControllerServiceWorkerMode() const {
  return mojom::ControllerServiceWorkerMode::kNoController;
}

net::SiteForCookies WebServiceWorkerFetchContextImpl::SiteForCookies() const {
  if (is_third_party_context_) {
    return net::SiteForCookies();
  }
  return net::SiteForCookies::FromUrl(GURL(worker_script_url_));
}

std::optional<WebSecurityOrigin>
WebServiceWorkerFetchContextImpl::TopFrameOrigin() const {
  return std::nullopt;
}

std::unique_ptr<WebSocketHandshakeThrottle>
WebServiceWorkerFetchContextImpl::CreateWebSocketHandshakeThrottle(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  if (!websocket_handshake_throttle_provider_)
    return nullptr;
  return websocket_handshake_throttle_provider_->CreateThrottle(
      std::nullopt, std::move(task_runner));
}

void WebServiceWorkerFetchContextImpl::UpdateSubresourceLoaderFactories(
    std::unique_ptr<PendingURLLoaderFactoryBundle>
        subresource_loader_factories) {
  url_loader_factory_ = std::make_unique<URLLoaderFactory>(
      network::SharedURLLoaderFactory::Create(
          std::move(subresource_loader_factories)),
      cors_exempt_header_list_, terminate_sync_load_event_);
}

void WebServiceWorkerFetchContextImpl::NotifyUpdate(
    const RendererPreferences& new_prefs) {
  DCHECK(accept_languages_watcher_);
  if (renderer_preferences_.accept_languages != new_prefs.accept_languages)
    accept_languages_watcher_->NotifyUpdate();
  renderer_preferences_ = new_prefs;
}

WebString WebServiceWorkerFetchContextImpl::GetAcceptLanguages() const {
  return WebString::FromUTF8(renderer_preferences_.accept_languages);
}

void WebServiceWorkerFetchContextImpl::SetIsOfflineMode(bool is_offline_mode) {
  is_offline_mode_ = is_offline_mode;
}

}  // namespace blink

"""

```
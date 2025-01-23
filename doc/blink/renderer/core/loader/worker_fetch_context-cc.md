Response:
My thinking process to answer the request about `worker_fetch_context.cc` went through these stages:

1. **Understand the Core Request:** The request asks for the functionality of the `WorkerFetchContext` class, its relation to web technologies, illustrative examples, logic inference, common errors, and a debugging path.

2. **Initial Code Scan and Keyword Identification:** I quickly scanned the provided code, looking for key terms and patterns. I noticed:
    * `WorkerFetchContext` as the central class.
    * Inclusion of headers like `WebWorkerFetchContext`, `FetchAPIRequest`, `ResourceRequest`, `ContentSecurityPolicy`, `SubresourceFilter`, `WorkerGlobalScope`. These immediately suggested its role in handling network requests within the context of a web worker.
    * Methods like `PrepareRequest`, `WillSendRequest`, `ShouldBlockRequestByInspector`, `ShouldBlockFetchByMixedContentCheck`, `GetContentSecurityPolicy`. These point to request lifecycle management, security checks, and policy enforcement.
    * References to `UseCounter` and `Deprecation`, indicating tracking of feature usage and deprecation.

3. **Identify the Core Responsibility:** Based on the keywords and included classes, I deduced the primary function: `WorkerFetchContext` manages the fetching of resources initiated by a web worker. This involves handling network requests, applying security policies, and interacting with the browser's fetch infrastructure.

4. **Categorize Functionality:** To organize the response, I categorized the functionalities into logical groups:
    * **Request Management:** Preparing, modifying, and finalizing requests.
    * **Security:** Enforcing CSP, handling mixed content, checking for insecure content.
    * **Context and Settings:**  Providing access to the worker's global scope, settings, and security origin.
    * **Instrumentation:**  Tracking usage and deprecation.
    * **Delegation:**  Interacting with the browser's `WebWorkerFetchContext`.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  I considered how the functionalities directly impact web development:
    * **JavaScript:** The Fetch API used within workers relies on this class. Importing scripts, fetching data, and making network calls from workers go through this context.
    * **HTML:** Workers are often initiated from HTML (e.g., `<script type="module" worker>`). The `WorkerFetchContext` handles requests made by these workers, including fetching resources linked in the HTML indirectly.
    * **CSS:** While workers don't directly manipulate the DOM or apply CSS, they might fetch CSS files or other resources related to styling if instructed by JavaScript.

6. **Develop Examples:**  For each relationship with web technologies, I crafted simple illustrative examples:
    * **JavaScript:**  Using `fetch()` in a worker.
    * **HTML:**  Starting a worker that fetches a script.
    * **CSS:** A worker fetching a CSS file (though less common).

7. **Consider Logic Inference (Assumptions and Outputs):** I looked for methods that performed checks or transformations based on input:
    * `ShouldBlockFetchByMixedContentCheck`:  Input: request type, target address space, URL. Output: boolean (block or not).
    * `ShouldBlockRequestByInspector`: Input: URL. Output: boolean (block or not).
    * `PrepareRequest`: Input: `ResourceRequest`. Output: Modified `ResourceRequest`.

8. **Identify Common Usage Errors:** I thought about common mistakes developers make when working with workers and network requests:
    * Mixed content errors.
    * CSP violations.
    * Incorrectly handling credentials.

9. **Construct a Debugging Scenario:** I imagined a typical scenario where a developer encounters an issue related to worker fetching and traced the steps to potentially reach this code:
    * Developer creates a worker.
    * Worker attempts to fetch a resource.
    * Browser's network stack eventually interacts with the `WorkerFetchContext` to handle the request.

10. **Structure and Refine the Answer:** I organized the information into clear sections with headings. I used bullet points for lists of functionalities and examples for better readability. I ensured the language was clear and concise. I also added a summary to reinforce the key takeaways.

11. **Review and Verify:**  I reread the code and my answer to make sure they were consistent and accurate. I double-checked the examples and the debugging scenario for logical flow.

By following these steps, I aimed to provide a comprehensive and informative answer that addresses all aspects of the original request. The process involved code analysis, logical reasoning, and an understanding of web development concepts.
好的，我们来详细分析 `blink/renderer/core/loader/worker_fetch_context.cc` 文件的功能。

**文件功能概览**

`WorkerFetchContext` 类是 Blink 渲染引擎中负责处理 Service Workers 和 Dedicated Workers 发起的资源请求的核心组件。 它的主要功能是：

1. **作为 Worker 全局作用域的资源获取上下文:**  它为 worker 提供了进行网络请求所需的环境和配置信息。
2. **处理和修改资源请求:**  在请求发送到网络层之前，对请求进行必要的处理，例如添加头部信息、应用安全策略、进行混合内容检查等。
3. **实施安全策略:**  它负责执行内容安全策略 (CSP)、混合内容阻止策略等安全机制，确保 worker 的网络请求符合安全规范。
4. **集成浏览器功能:**  它与浏览器的其他组件（例如内容设置、子资源过滤器、网络状态通知器等）进行交互，以完成资源获取过程。
5. **提供性能监控数据:** 它收集资源加载时间信息，用于性能分析。
6. **处理开发者工具的拦截:**  它允许开发者工具拦截和修改 worker 的请求。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`WorkerFetchContext` 虽然不是直接处理 JavaScript, HTML, CSS 代码的解析和渲染，但它在 Worker 环境下资源的获取中扮演着关键角色，因此与它们存在着密切的关系。

* **JavaScript:**
    * **`fetch()` API:**  Worker 中使用的 `fetch()` API  最终会通过 `WorkerFetchContext` 来发起网络请求。例如，在 Service Worker 中拦截到页面的 fetch 请求后，可以使用 `fetch(event.request)` 重新发起请求，这个过程会涉及到 `WorkerFetchContext`。
    ```javascript
    // Service Worker 中拦截 fetch 请求
    self.addEventListener('fetch', event => {
      if (event.request.url.endsWith('.json')) {
        event.respondWith(fetch(event.request)); // 这里的 fetch 就使用了 WorkerFetchContext
      }
    });

    // Dedicated Worker 中使用 fetch
    fetch('/api/data').then(response => response.json()).then(data => console.log(data));
    ```
    * **`importScripts()`:**  在 Worker 中使用 `importScripts()` 加载外部 JavaScript 文件时，`WorkerFetchContext` 会负责下载这些脚本。
    ```javascript
    // 在 Worker 中导入脚本
    importScripts('utils.js'); // WorkerFetchContext 负责下载 utils.js
    ```

* **HTML:**
    * **`<script type="module" worker>`:**  HTML 中通过这种方式创建的 Worker，其内部的资源请求由 `WorkerFetchContext` 处理。例如，worker 内部使用 `fetch` 请求数据。
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Worker Example</title>
    </head>
    <body>
      <script type="module">
        const worker = new Worker('worker.js', { type: 'module' });
      </script>
    </body>
    </html>

    // worker.js
    fetch('/data.json').then(r => r.json()).then(data => console.log(data));
    ```

* **CSS:**
    * 虽然 Worker 本身不能直接渲染 CSS，但它可以请求 CSS 文件，例如用于分析或者作为数据处理。`WorkerFetchContext` 负责获取这些 CSS 文件。
    ```javascript
    // 在 Worker 中获取 CSS 文件
    fetch('/styles.css').then(response => response.text()).then(cssText => {
      // 对 CSS 文本进行处理
      console.log(cssText);
    });
    ```

**逻辑推理 (假设输入与输出)**

让我们看几个 `WorkerFetchContext` 中的方法，并进行逻辑推理：

**1. `ShouldBlockFetchByMixedContentCheck()`:**

* **假设输入:**
    * `request_context`: `mojom::blink::RequestContextType::IMAGE` (请求的是图片资源)
    * `target_address_space`: `network::mojom::blink::IPAddressSpace::kPublic` (目标地址是公共网络)
    * `redirect_info`: `std::nullopt` (没有重定向)
    * `url`: `https://insecure.example.com/image.png` (HTTPS 页面请求 HTTP 图片)
    * `reporting_disposition`: `ReportingDisposition::kReport` (需要上报混合内容错误)
    * `devtools_id`: ""

* **逻辑推理:**  由于 HTTPS 页面加载 HTTP 图片属于混合内容，且 `global_scope_->IsWorkletGlobalScope()` 通常为 `false` (对于 Service Worker 和 Dedicated Worker)，`MixedContentChecker::ShouldBlockFetchOnWorker()` 会返回 `true`。

* **输出:** `true` (该请求会被阻止)

**2. `PrepareRequest()`:**

* **假设输入:**
    * `request.Url()`: `https://example.com/api/data`
    * `options`:  一些加载选项，例如 `credentials: 'include'`
    * Worker 的 User-Agent 字符串

* **逻辑推理:**
    * 该方法会设置请求的 UKM Source ID。
    * 它会设置 `HTTPUserAgent` 头部为 Worker 的 User-Agent 字符串。
    * 如果启用了压缩字典传输，会设置 `SharedDictionaryWriterEnabled`。
    * 它会调用 `web_context_->WillSendRequest()`，这可能被浏览器扩展或 DevTools 拦截并修改 URL。
    * 它会调用 `web_context_->FinalizeRequest()`，允许平台层对请求进行最终修改。
    * 如果是 WorkerGlobalScope，还会创建虚拟时间暂停器。

* **输出:** 修改后的 `ResourceRequest` 对象，可能包含设置的 User-Agent、修改后的 URL 等。

**用户或编程常见的使用错误**

1. **混合内容错误:**  在 HTTPS 的 Worker 中请求 HTTP 资源，浏览器会阻止该请求。
    * **用户操作:** 用户访问了一个使用 HTTPS 的网页，该网页启动了一个 Worker，Worker 尝试 `fetch('http://insecure.example.com/data')`。
    * **错误:**  由于混合内容策略，请求会被阻止，控制台会显示混合内容错误。

2. **CSP 违规:** Worker 请求的资源违反了页面或 Worker 本身的 CSP 策略。
    * **用户操作:** 用户访问了一个设置了严格 CSP 的网页，该网页启动了一个 Worker，Worker 尝试 `fetch('https://cdn.evil.com/malicious.js')`，但 CSP 中没有允许从 `cdn.evil.com` 加载脚本。
    * **错误:** 请求会被阻止，控制台会显示 CSP 违规错误。

3. **CORS 错误:** Worker 请求跨域资源，但目标服务器没有设置正确的 CORS 头部。
    * **用户操作:** 用户访问了一个域名为 `example.com` 的网页，该网页启动了一个 Worker，Worker 尝试 `fetch('https://api.otherdomain.com/data')`，但 `api.otherdomain.com` 的响应头中缺少 `Access-Control-Allow-Origin` 或该头部没有包含 `example.com`。
    * **错误:**  请求会被阻止，控制台会显示 CORS 错误。

4. **在不需要凭据时错误地发送凭据:**  `ShouldBlockFetchAsCredentialedSubresource()` 方法会检查是否在不必要的请求中包含了用户名和密码。
    * **编程错误:**  开发者在调用 `fetch` 时，URL 中包含了用户名和密码 (例如 `fetch('https://user:password@example.com/data')`)，但该请求不是 XMLHttpRequest。
    * **错误:** 该方法会返回 `true`，阻止请求，并记录一个废弃警告 (`CountDeprecation(WebFeature::kRequestedSubresourceWithEmbeddedCredentials)`)。

**用户操作如何一步步到达这里 (作为调试线索)**

假设开发者在 Service Worker 中发起了一个网络请求，但请求失败了，想要调试 `WorkerFetchContext` 的代码：

1. **用户访问网页:** 用户在浏览器中打开一个网页（例如 `https://example.com`）。
2. **网页注册 Service Worker:**  网页的 JavaScript 代码注册了一个 Service Worker。
3. **Service Worker 拦截请求:** 当网页发起一个符合 Service Worker 拦截范围的请求时（例如，加载图片 `https://example.com/image.png`），Service Worker 的 `fetch` 事件监听器会被触发。
4. **Service Worker 发起新的请求:**  在 `fetch` 事件处理函数中，Service Worker 可能会使用 `fetch(event.request)` 或 `fetch('/another-resource')` 发起新的网络请求。
5. **进入 `WorkerFetchContext`:**  当 Service Worker 调用 `fetch()` 时，Blink 引擎会创建或使用一个 `WorkerFetchContext` 实例来处理这个请求。
6. **执行 `PrepareRequest()`:**  在请求真正发送之前，`PrepareRequest()` 方法会被调用，进行诸如设置 User-Agent、应用虚拟时间等操作。
7. **执行安全策略检查:**  `ShouldBlockFetchByMixedContentCheck()`, `GetContentSecurityPolicy()`, `GetSubresourceFilter()` 等方法会被调用，以确保请求符合安全策略。
8. **调用 `web_context_->WillSendRequest()` 和 `web_context_->FinalizeRequest()`:**  允许浏览器层面和平台层面干预请求。
9. **发送请求:**  最终，请求会被传递到网络层进行发送。

**调试线索:**

* **断点:** 开发者可以在 `WorkerFetchContext.cc` 中相关的方法上设置断点，例如 `PrepareRequest()`, `ShouldBlockFetchByMixedContentCheck()`, `WillSendRequest()` 等，来观察请求是如何被处理的。
* **控制台输出:**  查看浏览器的开发者工具控制台，是否有混合内容错误、CSP 违规、CORS 错误等信息，这些错误通常与 `WorkerFetchContext` 的安全策略检查相关。
* **网络面板:**  使用开发者工具的网络面板，查看请求的详细信息，例如请求头、响应头、状态码等，可以帮助理解请求是否被阻止以及阻止的原因。
* **Service Worker 的生命周期:**  了解 Service Worker 的生命周期，以及 `fetch` 事件是如何被触发的，有助于理解请求的来源和上下文。
* **`chrome://inspect/#service-workers`:**  在 Chrome 浏览器中，可以通过这个地址查看已注册的 Service Worker，并进行调试。

希望以上分析能够帮助你理解 `blink/renderer/core/loader/worker_fetch_context.cc` 的功能和它在 Blink 引擎中的作用。

### 提示词
```
这是目录为blink/renderer/core/loader/worker_fetch_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/worker_fetch_context.h"

#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_worker_fetch_context.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/loader/subresource_filter.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/timing/worker_global_scope_performance.h"
#include "third_party/blink/renderer/core/workers/worker_clients.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_request.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h"
#include "third_party/blink/renderer/platform/loader/fetch/worker_resource_timing_notifier.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/virtual_time_controller.h"
#include "third_party/blink/renderer/platform/supplementable.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"

namespace blink {

WorkerFetchContext::~WorkerFetchContext() = default;

WorkerFetchContext::WorkerFetchContext(
    const DetachableResourceFetcherProperties& properties,
    WorkerOrWorkletGlobalScope& global_scope,
    scoped_refptr<WebWorkerFetchContext> web_context,
    SubresourceFilter* subresource_filter,
    ContentSecurityPolicy& content_security_policy,
    WorkerResourceTimingNotifier& resource_timing_notifier)
    : BaseFetchContext(
          properties,
          MakeGarbageCollected<DetachableConsoleLogger>(&global_scope)),
      global_scope_(global_scope),
      web_context_(std::move(web_context)),
      subresource_filter_(subresource_filter),
      content_security_policy_(&content_security_policy),
      content_security_notifier_(&global_scope),
      resource_timing_notifier_(&resource_timing_notifier),
      save_data_enabled_(GetNetworkStateNotifier().SaveDataEnabled()) {
  DCHECK(global_scope.IsContextThread());
  DCHECK(web_context_);
}

net::SiteForCookies WorkerFetchContext::GetSiteForCookies() const {
  return web_context_->SiteForCookies();
}

scoped_refptr<const SecurityOrigin> WorkerFetchContext::GetTopFrameOrigin()
    const {
  std::optional<WebSecurityOrigin> top_frame_origin =
      web_context_->TopFrameOrigin();

  // The top frame origin of shared and service workers is null.
  if (!top_frame_origin) {
    DCHECK(global_scope_->IsSharedWorkerGlobalScope() ||
           global_scope_->IsServiceWorkerGlobalScope());
    return scoped_refptr<const SecurityOrigin>();
  }

  return *top_frame_origin;
}

SubresourceFilter* WorkerFetchContext::GetSubresourceFilter() const {
  return subresource_filter_.Get();
}

bool WorkerFetchContext::AllowScript() const {
  // Script is always allowed in worker fetch contexts, since the fact that
  // they're running is already evidence that script is allowed.
  return true;
}

bool WorkerFetchContext::ShouldBlockRequestByInspector(const KURL& url) const {
  bool should_block_request = false;
  probe::ShouldBlockRequest(Probe(), url, &should_block_request);
  return should_block_request;
}

void WorkerFetchContext::DispatchDidBlockRequest(
    const ResourceRequest& resource_request,
    const ResourceLoaderOptions& options,
    ResourceRequestBlockedReason blocked_reason,
    ResourceType resource_type) const {
  probe::DidBlockRequest(Probe(), resource_request, nullptr, Url(), options,
                         blocked_reason, resource_type);
}

ContentSecurityPolicy* WorkerFetchContext::GetContentSecurityPolicyForWorld(
    const DOMWrapperWorld* world) const {
  // Worker threads don't support per-world CSP. Hence just return the default
  // CSP.
  return GetContentSecurityPolicy();
}

bool WorkerFetchContext::IsIsolatedSVGChromeClient() const {
  return false;
}

void WorkerFetchContext::CountUsage(WebFeature feature) const {
  UseCounter::Count(global_scope_, feature);
}

void WorkerFetchContext::CountDeprecation(WebFeature feature) const {
  Deprecation::CountDeprecation(global_scope_, feature);
}

CoreProbeSink* WorkerFetchContext::Probe() const {
  return probe::ToCoreProbeSink(static_cast<ExecutionContext*>(global_scope_));
}

bool WorkerFetchContext::ShouldBlockWebSocketByMixedContentCheck(
    const KURL& url) const {
  // Worklets don't support WebSocket.
  DCHECK(global_scope_->IsWorkerGlobalScope());
  return !MixedContentChecker::IsWebSocketAllowed(
      *const_cast<WorkerFetchContext*>(this), url);
}

std::unique_ptr<WebSocketHandshakeThrottle>
WorkerFetchContext::CreateWebSocketHandshakeThrottle() {
  return web_context_->CreateWebSocketHandshakeThrottle(
      global_scope_->GetTaskRunner(blink::TaskType::kNetworking));
}

bool WorkerFetchContext::ShouldBlockFetchByMixedContentCheck(
    mojom::blink::RequestContextType request_context,
    network::mojom::blink::IPAddressSpace target_address_space,
    base::optional_ref<const ResourceRequest::RedirectInfo> redirect_info,
    const KURL& url,
    ReportingDisposition reporting_disposition,
    const String& devtools_id) const {
  RedirectStatus redirect_status = redirect_info.has_value()
                                       ? RedirectStatus::kFollowedRedirect
                                       : RedirectStatus::kNoRedirect;
  const KURL& url_before_redirects =
      redirect_info.has_value() ? redirect_info->original_url : url;
  return MixedContentChecker::ShouldBlockFetchOnWorker(
      *const_cast<WorkerFetchContext*>(this), request_context,
      url_before_redirects, redirect_status, url, reporting_disposition,
      global_scope_->IsWorkletGlobalScope());
}

bool WorkerFetchContext::ShouldBlockFetchAsCredentialedSubresource(
    const ResourceRequest& resource_request,
    const KURL& url) const {
  if ((!url.User().empty() || !url.Pass().empty()) &&
      resource_request.GetRequestContext() !=
          mojom::blink::RequestContextType::XML_HTTP_REQUEST) {
    if (Url().User() != url.User() || Url().Pass() != url.Pass()) {
      CountDeprecation(
          WebFeature::kRequestedSubresourceWithEmbeddedCredentials);

      return true;
    }
  }
  return false;
}

const KURL& WorkerFetchContext::Url() const {
  return GetResourceFetcherProperties()
      .GetFetchClientSettingsObject()
      .GlobalObjectUrl();
}

ContentSecurityPolicy* WorkerFetchContext::GetContentSecurityPolicy() const {
  return content_security_policy_.Get();
}

void WorkerFetchContext::PrepareRequest(
    ResourceRequest& request,
    ResourceLoaderOptions& options,
    WebScopedVirtualTimePauser& virtual_time_pauser,
    ResourceType resource_type) {
  request.SetUkmSourceId(GetExecutionContext()->UkmSourceID());

  String user_agent = global_scope_->UserAgent();
  probe::ApplyUserAgentOverride(Probe(), &user_agent);
  DCHECK(!user_agent.IsNull());
  request.SetHTTPUserAgent(AtomicString(user_agent));
  request.SetSharedDictionaryWriterEnabled(
      RuntimeEnabledFeatures::CompressionDictionaryTransportEnabled(
          GetExecutionContext()));

  request.SetStorageAccessApiStatus(
      GetExecutionContext()->GetStorageAccessApiStatus());

  if (!RuntimeEnabledFeatures::
          MinimimalResourceRequestPrepBeforeCacheLookupEnabled()) {
    std::optional<WebURL> overriden_url =
        web_context_->WillSendRequest(request.Url());
    if (overriden_url.has_value()) {
      request.SetUrl(*overriden_url);
    }
  }
  WrappedResourceRequest webreq(request);
  web_context_->FinalizeRequest(webreq);
  if (auto* worker_scope = DynamicTo<WorkerGlobalScope>(*global_scope_)) {
    virtual_time_pauser =
        worker_scope->GetScheduler()
            ->GetVirtualTimeController()
            ->CreateWebScopedVirtualTimePauser(
                request.Url().GetString(),
                WebScopedVirtualTimePauser::VirtualTaskDuration::kNonInstant);
  }

  probe::PrepareRequest(Probe(), nullptr, request, options, resource_type);
}

void WorkerFetchContext::AddAdditionalRequestHeaders(ResourceRequest& request) {
  // The remaining modifications are only necessary for HTTP and HTTPS.
  if (!request.Url().IsEmpty() && !request.Url().ProtocolIsInHTTPFamily())
    return;

  // TODO(crbug.com/1315612): WARNING: This bypasses the permissions policy.
  // Unfortunately, workers lack a permissions policy and to derive proper hints
  // https://github.com/w3c/webappsec-permissions-policy/issues/207.
  // Save-Data was previously included in hints for workers, thus we cannot
  // remove it for the time being. If you're reading this, consider building
  // permissions policies for workers and/or deprecating this inclusion.
  if (save_data_enabled_)
    request.SetHttpHeaderField(http_names::kSaveData, AtomicString("on"));
}

void WorkerFetchContext::AddResourceTiming(
    mojom::blink::ResourceTimingInfoPtr info,
    const AtomicString& initiator_type) {
  resource_timing_notifier_->AddResourceTiming(std::move(info), initiator_type);
}

void WorkerFetchContext::PopulateResourceRequestBeforeCacheAccess(
    const ResourceLoaderOptions& options,
    ResourceRequest& request) {
  DCHECK(RuntimeEnabledFeatures::
             MinimimalResourceRequestPrepBeforeCacheLookupEnabled());

  MixedContentChecker::UpgradeInsecureRequest(
      request, &GetResourceFetcherProperties().GetFetchClientSettingsObject(),
      global_scope_, mojom::RequestContextFrameType::kNone,
      global_scope_->ContentSettingsClient());
}

void WorkerFetchContext::WillSendRequest(ResourceRequest& request) {
  std::optional<WebURL> overriden_url =
      web_context_->WillSendRequest(request.Url());
  if (overriden_url.has_value()) {
    request.SetUrl(*overriden_url);
  }
}

void WorkerFetchContext::UpgradeResourceRequestForLoader(
    ResourceType type,
    const std::optional<float> resource_width,
    ResourceRequest& out_request,
    const ResourceLoaderOptions& options) {
  if (!GetResourceFetcherProperties().IsDetached())
    probe::SetDevToolsIds(Probe(), out_request, options.initiator_info);
  if (!RuntimeEnabledFeatures::
          MinimimalResourceRequestPrepBeforeCacheLookupEnabled()) {
    MixedContentChecker::UpgradeInsecureRequest(
        out_request,
        &GetResourceFetcherProperties().GetFetchClientSettingsObject(),
        global_scope_, mojom::RequestContextFrameType::kNone,
        global_scope_->ContentSettingsClient());
  }
  SetFirstPartyCookie(out_request);
  if (!out_request.TopFrameOrigin())
    out_request.SetTopFrameOrigin(GetTopFrameOrigin());
}

std::unique_ptr<ResourceLoadInfoNotifierWrapper>
WorkerFetchContext::CreateResourceLoadInfoNotifierWrapper() {
  return web_context_->CreateResourceLoadInfoNotifierWrapper();
}

void WorkerFetchContext::SetFirstPartyCookie(ResourceRequest& out_request) {
  if (out_request.SiteForCookies().IsNull())
    out_request.SetSiteForCookies(GetSiteForCookies());
}

WorkerSettings* WorkerFetchContext::GetWorkerSettings() const {
  auto* scope = DynamicTo<WorkerGlobalScope>(*global_scope_);
  return scope ? scope->GetWorkerSettings() : nullptr;
}

bool WorkerFetchContext::AllowRunningInsecureContent(
    bool enabled_per_settings,
    const KURL& url) const {
  if (!global_scope_->ContentSettingsClient())
    return enabled_per_settings;
  return global_scope_->ContentSettingsClient()->AllowRunningInsecureContent(
      enabled_per_settings, url);
}

mojom::blink::ContentSecurityNotifier&
WorkerFetchContext::GetContentSecurityNotifier() {
  if (!content_security_notifier_.is_bound()) {
    global_scope_->GetBrowserInterfaceBroker().GetInterface(
        content_security_notifier_.BindNewPipeAndPassReceiver(
            global_scope_->GetTaskRunner(TaskType::kInternalLoading)));
  }
  return *content_security_notifier_.get();
}

ExecutionContext* WorkerFetchContext::GetExecutionContext() const {
  return global_scope_.Get();
}

void WorkerFetchContext::Trace(Visitor* visitor) const {
  visitor->Trace(global_scope_);
  visitor->Trace(subresource_filter_);
  visitor->Trace(content_security_policy_);
  visitor->Trace(content_security_notifier_);
  BaseFetchContext::Trace(visitor);
}

}  // namespace blink
```
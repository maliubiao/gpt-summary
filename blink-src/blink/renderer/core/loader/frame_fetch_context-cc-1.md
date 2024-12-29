Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the second part of the `frame_fetch_context.cc` file in the Chromium Blink engine. I need to analyze the code and identify its key responsibilities. Specifically, I should look for:

1. **Core functions:** What are the main actions this code performs?
2. **Relationship to web technologies:** How does this code interact with JavaScript, HTML, and CSS?  I should look for examples of this interaction.
3. **Logical reasoning:** Are there conditional code paths or decision-making processes? I need to identify potential inputs and outputs for these.
4. **Potential user/developer errors:** Are there any situations where incorrect usage could lead to issues?
5. **User actions leading here:** What user interactions in a web browser could trigger this code?
6. **Function summarization:** Provide a concise overview of the code's purpose.

Based on a quick scan, this part of the code seems to focus on modifying and preparing `ResourceRequest` objects before they are sent to fetch resources. It also handles aspects related to security policies, client hints, and interactions with other browser components.

Here's a breakdown of the code blocks and their apparent functions:

*   **`AddClientHintsIfNecessary`:** Adds HTTP client hints to the request, based on device pixel ratio, viewport size, and resource width. This relates to CSS media queries and responsive design.
*   **`AddReducedAcceptLanguageIfNecessary`:** Adds a reduced `Accept-Language` header to the request. This relates to HTML localization and internationalization.
*   **`WillSendRequest`:** Allows the client to modify the request URL before it's sent. This could be related to JavaScript interception of requests.
*   **`PopulateResourceRequestBeforeCacheAccess`:**  Prepares the request before checking the cache, potentially involving CSP modifications and setting first-party cookies. This relates to web security and caching mechanisms.
*   **`UpgradeResourceRequestForLoader`:**  Similar to `PopulateResourceRequestBeforeCacheAccess`, but seemingly called at a later stage.
*   **`StartSpeculativeImageDecode`:** Initiates decoding an image resource, possibly for performance optimization. This relates to HTML `<img>` tags and image loading.
*   **`IsPrerendering`:** Checks if the frame is in a prerendering state. This is related to browser preloading techniques.
*   **`DoesLCPPHaveAnyHintData` and `DoesLCPPHaveLcpElementLocatorHintData`:** Checks for data related to the Largest Contentful Paint (LCP) performance metric.
*   **`SetFirstPartyCookie`:** Sets the `Site-For-Cookies` attribute on the request. This relates to cookie management and web security.
*   **`AllowScript`:** Checks if scripts are allowed in the current context. This directly relates to JavaScript execution.
*   **`IsFirstPartyOrigin`:** Checks if a given origin is the same as the top-level frame's origin. This relates to web security and the same-origin policy.
*   **`ShouldBlockRequestByInspector` and `DispatchDidBlockRequest`:**  Handles blocking requests based on DevTools settings. This is a debugging and development feature.
*   **`GetContentSecurityPolicyForWorld`:** Retrieves the Content Security Policy for a given JavaScript world. This relates to web security and CSP directives.
*   **`IsIsolatedSVGChromeClient`:** Checks if the frame is using an isolated SVG renderer. This is an internal browser implementation detail.
*   **`CountUsage` and `CountDeprecation`:** Tracks usage of web features and their deprecation. This is for browser telemetry and developer feedback.
*   **`ShouldBlockWebSocketByMixedContentCheck` and `CreateWebSocketHandshakeThrottle`:** Handles mixed content checks for WebSockets. This relates to web security and the secure context requirement.
*   **`ShouldBlockFetchByMixedContentCheck`:** Handles mixed content checks for other fetch requests. This relates to web security and the secure context requirement.
*   **`ShouldBlockFetchAsCredentialedSubresource`:** Blocks requests for subresources that include credentials when they shouldn't. This relates to web security and preventing credential leakage.
*   **Getter methods:** Functions like `Url()`, `GetContentSecurityPolicy()`, `GetSettings()`, `GetUserAgent()`, `GetPermissionsPolicy()`, `GetClientHintsPreferences()`, `GetReducedAcceptLanguage()`, `GetDevicePixelRatio()` provide access to various frame properties.
*   **`Detach()`:**  Detaches the `FrameFetchContext` from its associated document. This is likely part of a lifecycle management process.
*   **`Trace()`:** For debugging and memory management.
*   **`CalculateIfAdSubresource`:** Determines if a resource is an ad.
*   **`DidObserveLoadingBehavior`:**  Records loading behavior.
*   **`CreateResourceLoadInfoNotifierWrapper`:** Creates a wrapper for resource load information.
*   **`GetContentSecurityNotifier()`:** Returns the content security policy notifier.
*   **`GetExecutionContext()`:** Returns the execution context.
*   **`CanRequest()`:** Determines if a request can be made, considering factors like freezing and CSP.
*   **`Probe()`:** Returns a probe object for instrumentation.
*   **`UpdateSubresourceLoadMetrics()`:** Updates metrics related to subresource loading.

Now I can synthesize this information into a comprehensive summary addressing the user's specific points.
这是 `blink/renderer/core/loader/frame_fetch_context.cc` 文件的第二部分，它延续了第一部分的功能，主要负责在 Blink 渲染引擎中处理与资源获取相关的上下文信息和操作，特别是与 `LocalFrame` 关联的资源请求的准备和管理。

以下是该部分代码功能的归纳：

**主要功能归纳：**

1. **添加客户端提示 (Client Hints)：**
    *   根据设备像素比 (DPR)、视口宽度和高度，以及资源宽度等信息，决定是否需要将相应的客户端提示 HTTP 头部添加到资源请求中。
    *   区分了已弃用 (`_DEPRECATED`) 和最新的客户端提示头部。
    *   **与 CSS/HTML 的关系：**  客户端提示允许浏览器向服务器提供有关设备和网络状况的信息，以便服务器可以提供优化的资源。这与响应式设计 (`<meta viewport>`) 和 CSS 媒体查询有关，服务器可以根据 `dpr`、`viewport-width` 等信息提供不同分辨率的图片或调整样式。
    *   **假设输入与输出：**
        *   **假设输入：**  `dpr = 2`, `viewport_width = 800`, `resource_width = 400`,  客户端提示策略允许发送这些提示。
        *   **输出：**  资源请求的 HTTP 头部会包含 `DPR: 2`, `Viewport-Width: 800`, `Resource-Width: 800` (400 \* 2 并向上取整)。
    *   **用户操作如何到达这里：** 用户访问一个使用了响应式设计的网页，浏览器在发起资源请求时需要根据当前的视口大小和设备像素比来决定是否发送客户端提示。

2. **添加精简的 Accept-Language 头部：**
    *   如果启用了 `kReduceAcceptLanguage` 特性，并且请求是 HTTP 或 HTTPS，则会添加精简的 `Accept-Language` 头部，前提是请求中尚未设置该头部。
    *   **与 HTML 的关系：**  `Accept-Language` 头部用于告知服务器用户期望的语言。精简的 `Accept-Language` 头部可以减少发送的数据量。
    *   **假设输入与输出：**
        *   **假设输入：** 用户浏览器设置的语言偏好为 `en-US,zh-CN;q=0.9,en;q=0.8`，`kReduceAcceptLanguage` 特性已启用。
        *   **输出：**  资源请求的 HTTP 头部会包含 `Accept-Language: en-US,zh-CN`.
    *   **用户操作如何到达这里：** 用户在浏览器设置中配置了语言偏好，当浏览器发起网络请求时，`FrameFetchContext` 会根据配置添加 `Accept-Language` 头部。

3. **在发送请求前处理：**
    *   调用 `GetLocalFrameClient()->DispatchWillSendRequest` 允许客户端（例如扩展或开发者工具）拦截并修改请求的 URL。
    *   **与 JavaScript 的关系：** 一些 JavaScript API 或浏览器扩展可以监听网络请求事件并修改请求参数。
    *   **假设输入与输出：**
        *   **假设输入：**  一个浏览器扩展注册了一个监听器，当请求的 URL 包含特定字符串时，将其替换为另一个 URL。资源请求的原始 URL 为 `http://example.com/old_resource`。
        *   **输出：**  实际发送的请求的 URL 可能被修改为 `http://example.com/new_resource`。

4. **在访问缓存前填充资源请求：**
    *   在访问 HTTP 缓存之前，进行一些请求的预处理，例如：
        *   设置 DevTools ID (如果 DevTools 已连接)。
        *   根据内容安全策略 (CSP) 修改请求 URL。
        *   设置 first-party cookie 信息。
        *   如果启用了 Inspector Emulation 或 Network Agent，则设置 `RequiresUpgradeForLoader` 标志。
        *   如果 `DocumentLoader` 强制使用特定的缓存模式，则设置请求的缓存模式。
        *   设置归因报告支持。
    *   **与 JavaScript/HTML/CSS 的关系：** CSP 由 HTML 的 `<meta>` 标签或 HTTP 头部定义，影响资源的加载。First-party cookies 与 JavaScript 的 `document.cookie` API 相关。
    *   **用户操作如何到达这里：**  用户访问的网页设置了 CSP 规则，或者 JavaScript 代码尝试读取或设置 cookie。

5. **为加载器升级资源请求：**
    *   在某些情况下（非最小化资源请求准备），会进行额外的请求升级操作，例如添加客户端提示和精简的 `Accept-Language` 头部。

6. **启动推测性图片解码：**
    *   对于图片资源，可以提前启动解码，以提高渲染性能。
    *   **与 HTML 的关系：**  当浏览器遇到 `<img>` 标签时，可能会触发此操作。
    *   **用户操作如何到达这里：** 用户访问包含图片的网页，浏览器可能会选择提前解码图片。

7. **判断是否为预渲染状态：**
    *   检查当前帧是否处于预渲染状态。
    *   **用户操作如何到达这里：** 浏览器在后台提前渲染用户可能访问的页面。

8. **检查 LCP 预测器是否有提示数据：**
    *   检查 Largest Contentful Paint (LCP) 关键路径预测器是否有任何提示数据，或者是否有 LCP 元素定位器提示数据。
    *   **与 HTML 的关系：** LCP 是衡量页面加载性能的关键指标，与页面上的主要内容元素相关。

9. **设置 first-party cookie：**
    *   如果尚未设置，则为请求设置 first-party cookie 的上下文。

10. **判断是否允许执行脚本：**
    *   检查当前帧是否允许执行 JavaScript。如果不允许，会通知 `WebContentSettingsClient`。
    *   **与 JavaScript 的关系：**  直接控制 JavaScript 的执行。
    *   **用户常见的使用错误：** 用户可能在浏览器设置中禁用了 JavaScript，导致 `AllowScript()` 返回 `false`。

11. **判断是否为同源：**
    *   判断给定源是否与顶层帧的源相同。
    *   **与 JavaScript/HTML 的关系：**  与浏览器的同源策略相关，影响跨域资源的访问。

12. **根据 Inspector 阻止请求：**
    *   如果开发者工具设置了阻止特定 URL 的请求，则会阻止该请求。
    *   **用户操作如何到达这里：** 开发者在 Chrome DevTools 的 Network 面板中设置了 Request Blocking 规则。

13. **分发请求被阻止的事件：**
    *   当请求被阻止时，通知相关的观察者。

14. **获取特定 World 的 CSP：**
    *   获取与特定 JavaScript World 关联的 Content Security Policy。
    *   **与 JavaScript 的关系：**  不同的 JavaScript World 可以有不同的安全策略。

15. **判断是否为隔离的 SVG ChromeClient：**
    *   判断当前帧是否使用了隔离的 SVG 渲染进程。

16. **统计功能使用和废弃：**
    *   记录 Web 平台的特性使用情况和废弃情况。

17. **根据混合内容检查阻止 WebSocket 请求：**
    *   根据混合内容策略，判断是否应该阻止通过 HTTPS 页面发起的到 HTTP WebSocket 服务器的连接。
    *   **用户常见的使用错误：** 用户在 HTTPS 页面尝试连接到 HTTP 的 WebSocket 服务器，浏览器会阻止该连接并可能在控制台输出错误。

18. **创建 WebSocket 握手节流器：**
    *   为 WebSocket 连接创建握手节流器。

19. **根据混合内容检查阻止 Fetch 请求：**
    *   根据混合内容策略，判断是否应该阻止通过 HTTPS 页面发起的到 HTTP 服务器的 Fetch 请求。
    *   **用户常见的使用错误：** 用户在 HTTPS 页面尝试通过 `fetch` 或 `XMLHttpRequest` 请求 HTTP 资源，浏览器会阻止该请求并可能在控制台输出错误。

20. **阻止带有嵌入凭据的子资源请求：**
    *   对于某些类型的子资源请求（非 `XMLHttpRequest`），如果 URL 中包含用户名和密码等凭据，可能会被阻止。
    *   **用户常见的使用错误：**  开发者在 `<img>` 标签的 `src` 属性或 `<script>` 标签的 `src` 属性中嵌入了用户名和密码（例如 `https://user:password@example.com/image.jpg`）。

21. **获取各种属性：**
    *   提供获取当前 URL、Content Security Policy、WebContentSettingsClient、Settings、User-Agent、Permissions Policy、Client Hints Preferences、Reduced Accept-Language、Device Pixel Ratio 等信息的方法。

22. **分离 FetchContext：**
    *   将 `FrameFetchContext` 与其关联的 `DocumentLoader` 和 `Document` 分离，创建一个 `FrozenState` 对象来保存关键的上下文信息。这通常发生在页面被冻结或进入后台时。

23. **跟踪对象：**
    *   用于垃圾回收和调试目的。

24. **计算是否为广告子资源：**
    *   通过 `BaseFetchContext` 和 `AdTracker` 共同判断资源是否为广告。

25. **记录加载行为：**
    *   记录观察到的加载行为。

26. **创建资源加载信息通知器包装器：**
    *   用于通知资源加载的相关信息。

27. **获取内容安全通知器：**
    *   用于报告 CSP 违规等事件。

28. **获取执行上下文：**
    *   返回与此 `FrameFetchContext` 关联的执行上下文。

29. **判断是否可以发起请求：**
    *   在实际发起请求之前，进行最后的检查，例如在页面冻结期间只允许 `keepalive` 请求。
    *   **用户操作如何到达这里：**  用户刷新页面或点击链接，导致浏览器发起新的资源请求。

30. **获取 CoreProbeSink：**
    *   用于性能分析和调试。

31. **更新子资源加载指标：**
    *   记录和更新子资源的加载性能指标。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户访问一个包含图片的网页，并且该网页使用了响应式设计：

1. **用户在地址栏输入网址并回车，或点击一个链接。**
2. 浏览器开始解析 HTML，遇到 `<img>` 标签。
3. Blink 渲染引擎创建一个资源请求 (`ResourceRequest`) 来获取图片资源。
4. `FrameFetchContext` 的实例被用来处理这个请求。
5. **`AddClientHintsIfNecessary()`** 被调用，根据用户的设备像素比和视口大小，以及页面指定的资源宽度，决定是否添加 `DPR`、`Viewport-Width` 和 `Resource-Width` 等客户端提示头部。
6. **`AddReducedAcceptLanguageIfNecessary()`** 被调用，可能会添加精简的 `Accept-Language` 头部。
7. **`WillSendRequest()`** 被调用，允许浏览器扩展或开发者工具拦截并修改请求的 URL。
8. **`PopulateResourceRequestBeforeCacheAccess()`** 被调用，在请求被发送到网络层之前，会进行缓存相关的准备工作，例如检查 CSP 并设置 first-party cookie。
9. 如果图片加载需要跨域，并且页面设置了 CSP，则会调用 `GetContentSecurityPolicy()` 来获取策略并进行检查。
10. 如果开发者打开了 Chrome DevTools 并设置了 Request Blocking 规则，**`ShouldBlockRequestByInspector()`** 可能会被调用。
11. 如果图片资源需要进行混合内容检查（例如 HTTPS 页面加载 HTTP 图片），则会调用 **`ShouldBlockFetchByMixedContentCheck()`**。
12. 最终，准备好的 `ResourceRequest` 被发送到网络层去获取图片资源。

在调试过程中，可以通过断点设置在这些关键函数上，查看请求的头部信息、URL 变化、CSP 策略等，来追踪资源加载的流程和问题。例如，如果发现图片加载失败，可以检查是否是因为 CSP 阻止了请求，或者客户端提示设置不正确导致服务器返回了错误的资源。

Prompt: 
```
这是目录为blink/renderer/core/loader/frame_fetch_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
g(String::Number(dpr)));
  }

  if (LocalFrameView* frame_view = GetFrame()->View()) {
    const int viewport_width = frame_view->ViewportWidth();
    const int viewport_height = frame_view->ViewportHeight();
    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kViewportWidth_DEPRECATED,
                             hints_preferences)) {
      request.SetHttpHeaderField(http_names::kViewportWidth_DEPRECATED,
                                 AtomicString(String::Number(viewport_width)));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kViewportWidth,
                             hints_preferences)) {
      request.SetHttpHeaderField(http_names::kViewportWidth,
                                 AtomicString(String::Number(viewport_width)));
    }

    if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                             WebClientHintsType::kViewportHeight,
                             hints_preferences)) {
      request.SetHttpHeaderField(http_names::kViewportHeight,
                                 AtomicString(String::Number(viewport_height)));
    }

    if (resource_width) {
      if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                               WebClientHintsType::kResourceWidth_DEPRECATED,
                               hints_preferences)) {
        float physical_width = resource_width.value() * dpr;
        request.SetHttpHeaderField(
            http_names::kResourceWidth_DEPRECATED,
            AtomicString(String::Number(ceil(physical_width))));
      }

      if (ShouldSendClientHint(*policy, resource_origin, is_1p_origin,
                               WebClientHintsType::kResourceWidth,
                               hints_preferences)) {
        float physical_width = resource_width.value() * dpr;
        request.SetHttpHeaderField(
            http_names::kResourceWidth,
            AtomicString(String::Number(ceil(physical_width))));
      }
    }
  }
}

void FrameFetchContext::AddReducedAcceptLanguageIfNecessary(
    ResourceRequest& request) {
  // If the feature is enabled, then reduce accept language are allowed only on
  // http and https.
  if (!base::FeatureList::IsEnabled(network::features::kReduceAcceptLanguage)) {
    return;
  }

  if (!request.Url().ProtocolIsInHTTPFamily())
    return;

  const String& reduced_accept_language = GetReducedAcceptLanguage();
  if (!reduced_accept_language.empty() &&
      request.HttpHeaderField(http_names::kAcceptLanguage).empty()) {
    request.SetHttpHeaderField(
        http_names::kAcceptLanguage,
        AtomicString(reduced_accept_language.Ascii().c_str()));
  }
}

void FrameFetchContext::WillSendRequest(ResourceRequest& resource_request) {
  // Set upstream url based on the request's redirect info.
  KURL upstream_url;
  if (resource_request.GetRedirectInfo().has_value()) {
    upstream_url = KURL(resource_request.GetRedirectInfo()->previous_url);
  }
  std::optional<KURL> overriden_url =
      GetLocalFrameClient()->DispatchWillSendRequest(
          resource_request.Url(), resource_request.RequestorOrigin(),
          resource_request.SiteForCookies(),
          resource_request.GetRedirectInfo().has_value(), upstream_url);
  if (overriden_url.has_value()) {
    resource_request.SetUrl(overriden_url.value());
  }
}

void FrameFetchContext::PopulateResourceRequestBeforeCacheAccess(
    const ResourceLoaderOptions& options,
    ResourceRequest& request) {
  DCHECK(RuntimeEnabledFeatures::
             MinimimalResourceRequestPrepBeforeCacheLookupEnabled());
  if (!GetResourceFetcherProperties().IsDetached()) {
    probe::SetDevToolsIds(Probe(), request, options.initiator_info);
  }

  // CSP may change the url.
  ModifyRequestForCSP(request);
  if (!request.Url().IsValid()) {
    return;
  }
  SetFirstPartyCookie(request);
  if (CoreProbeSink::HasAgentsGlobal(CoreProbeSink::kInspectorEmulationAgent |
                                     CoreProbeSink::kInspectorNetworkAgent)) {
    request.SetRequiresUpgradeForLoader();
  }
  if (document_loader_->ForceFetchCacheMode()) {
    request.SetCacheMode(*document_loader_->ForceFetchCacheMode());
  }
  // ResourceFetcher::DidLoadResourceFromMemoryCache() may call out in such a
  // way that the AttributionSupport is needed.
  if (const AttributionSrcLoader* attribution_src_loader =
          GetFrame()->GetAttributionSrcLoader()) {
    request.SetAttributionReportingSupport(
        attribution_src_loader->GetSupport());
  }
}

void FrameFetchContext::UpgradeResourceRequestForLoader(
    ResourceType type,
    const std::optional<float> resource_width,
    ResourceRequest& request,
    const ResourceLoaderOptions& options) {
  if (!RuntimeEnabledFeatures::
          MinimimalResourceRequestPrepBeforeCacheLookupEnabled()) {
    if (!GetResourceFetcherProperties().IsDetached()) {
      probe::SetDevToolsIds(Probe(), request, options.initiator_info);
    }
    ModifyRequestForCSP(request);
  }
  AddClientHintsIfNecessary(resource_width, request);
  AddReducedAcceptLanguageIfNecessary(request);
}

void FrameFetchContext::StartSpeculativeImageDecode(
    Resource* resource,
    base::OnceClosure callback) {
  CHECK(resource->GetType() == ResourceType::kImage);
  if (!document_ || !document_->GetFrame()) {
    std::move(callback).Run();
    return;
  }
  ImageResource* image_resource = To<ImageResource>(resource);
  Image* image = image_resource->GetContent()->GetImage();
  if (IsA<SVGImage>(image)) {
    std::move(callback).Run();
    return;
  }
  document_->GetFrame()->GetChromeClient().RequestDecode(
      document_->GetFrame(), image->PaintImageForCurrentFrame(),
      WTF::BindOnce([](base::OnceClosure cb, bool) { std::move(cb).Run(); },
                    std::move(callback)));
}

bool FrameFetchContext::IsPrerendering() const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->is_prerendering;
  return document_->IsPrerendering();
}

bool FrameFetchContext::DoesLCPPHaveAnyHintData() {
  if (GetResourceFetcherProperties().IsDetached()) {
    return false;
  }

  LCPCriticalPathPredictor* lcpp = GetFrame()->GetLCPP();
  if (!lcpp) {
    return false;
  }
  return lcpp->HasAnyHintData();
}

bool FrameFetchContext::DoesLCPPHaveLcpElementLocatorHintData() {
  if (GetResourceFetcherProperties().IsDetached()) {
    return false;
  }

  LCPCriticalPathPredictor* lcpp = GetFrame()->GetLCPP();
  if (!lcpp) {
    return false;
  }
  return !lcpp->lcp_element_locators().empty();
}

void FrameFetchContext::SetFirstPartyCookie(ResourceRequest& request) {
  // Set the first party for cookies url if it has not been set yet (new
  // requests). This value will be updated during redirects, consistent with
  // https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00#section-2.1.1?
  if (!request.SiteForCookiesSet())
    request.SetSiteForCookies(GetSiteForCookies());
}

bool FrameFetchContext::AllowScript() const {
  bool script_enabled = GetFrame()->ScriptEnabled();
  if (!script_enabled) {
    WebContentSettingsClient* settings_client = GetContentSettingsClient();
    if (settings_client) {
      settings_client->DidNotAllowScript();
    }
  }
  return script_enabled;
}

bool FrameFetchContext::IsFirstPartyOrigin(
    const SecurityOrigin* resource_origin) const {
  if (GetResourceFetcherProperties().IsDetached())
    return false;

  return GetFrame()
      ->Tree()
      .Top()
      .GetSecurityContext()
      ->GetSecurityOrigin()
      ->IsSameOriginWith(resource_origin);
}

bool FrameFetchContext::ShouldBlockRequestByInspector(const KURL& url) const {
  if (GetResourceFetcherProperties().IsDetached())
    return false;
  bool should_block_request = false;
  probe::ShouldBlockRequest(Probe(), url, &should_block_request);
  return should_block_request;
}

void FrameFetchContext::DispatchDidBlockRequest(
    const ResourceRequest& resource_request,
    const ResourceLoaderOptions& options,
    ResourceRequestBlockedReason blocked_reason,
    ResourceType resource_type) const {
  if (GetResourceFetcherProperties().IsDetached())
    return;
  probe::DidBlockRequest(Probe(), resource_request, document_loader_, Url(),
                         options, blocked_reason, resource_type);
}

ContentSecurityPolicy* FrameFetchContext::GetContentSecurityPolicyForWorld(
    const DOMWrapperWorld* world) const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->content_security_policy.Get();

  return document_->GetExecutionContext()->GetContentSecurityPolicyForWorld(
      world);
}

bool FrameFetchContext::IsIsolatedSVGChromeClient() const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->is_isolated_svg_chrome_client;

  return GetFrame()->GetChromeClient().IsIsolatedSVGChromeClient();
}

void FrameFetchContext::CountUsage(WebFeature feature) const {
  if (GetResourceFetcherProperties().IsDetached())
    return;
  document_loader_->GetUseCounter().Count(feature, GetFrame());
}

void FrameFetchContext::CountDeprecation(WebFeature feature) const {
  if (GetResourceFetcherProperties().IsDetached())
    return;
  Deprecation::CountDeprecation(document_->domWindow(), feature);
}

bool FrameFetchContext::ShouldBlockWebSocketByMixedContentCheck(
    const KURL& url) const {
  if (GetResourceFetcherProperties().IsDetached()) {
    // TODO(yhirano): Implement the detached case.
    return false;
  }
  return !MixedContentChecker::IsWebSocketAllowed(*this, GetFrame(), url);
}

std::unique_ptr<WebSocketHandshakeThrottle>
FrameFetchContext::CreateWebSocketHandshakeThrottle() {
  if (GetResourceFetcherProperties().IsDetached()) {
    // TODO(yhirano): Implement the detached case.
    return nullptr;
  }
  if (!GetFrame())
    return nullptr;
  return WebFrame::FromCoreFrame(GetFrame())
      ->ToWebLocalFrame()
      ->Client()
      ->CreateWebSocketHandshakeThrottle();
}

bool FrameFetchContext::ShouldBlockFetchByMixedContentCheck(
    mojom::blink::RequestContextType request_context,
    network::mojom::blink::IPAddressSpace target_address_space,
    base::optional_ref<const ResourceRequest::RedirectInfo> redirect_info,
    const KURL& url,
    ReportingDisposition reporting_disposition,
    const String& devtools_id) const {
  if (GetResourceFetcherProperties().IsDetached()) {
    // TODO(yhirano): Implement the detached case.
    return false;
  }
  const KURL& url_before_redirects =
      redirect_info.has_value() ? redirect_info->original_url : url;
  ResourceRequest::RedirectStatus redirect_status =
      redirect_info.has_value() ? RedirectStatus::kFollowedRedirect
                                : RedirectStatus::kNoRedirect;
  return MixedContentChecker::ShouldBlockFetch(
      GetFrame(), request_context, target_address_space, url_before_redirects,
      redirect_status, url, devtools_id, reporting_disposition,
      document_loader_->GetContentSecurityNotifier());
}

bool FrameFetchContext::ShouldBlockFetchAsCredentialedSubresource(
    const ResourceRequest& resource_request,
    const KURL& url) const {
  // URLs with no embedded credentials should load correctly.
  if (url.User().empty() && url.Pass().empty())
    return false;

  if (resource_request.GetRequestContext() ==
      mojom::blink::RequestContextType::XML_HTTP_REQUEST) {
    return false;
  }

  // Relative URLs on top-level pages that were loaded with embedded credentials
  // should load correctly.
  // TODO(mkwst): This doesn't work when the subresource is an iframe.
  // See https://crbug.com/756846.
  if (Url().User() == url.User() && Url().Pass() == url.Pass() &&
      SecurityOrigin::Create(url)->IsSameOriginWith(
          GetResourceFetcherProperties()
              .GetFetchClientSettingsObject()
              .GetSecurityOrigin())) {
    return false;
  }

  CountDeprecation(WebFeature::kRequestedSubresourceWithEmbeddedCredentials);

  return true;
}

const KURL& FrameFetchContext::Url() const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->url;
  return document_->Url();
}

ContentSecurityPolicy* FrameFetchContext::GetContentSecurityPolicy() const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->content_security_policy.Get();
  return document_->domWindow()->GetContentSecurityPolicy();
}

WebContentSettingsClient* FrameFetchContext::GetContentSettingsClient() const {
  if (GetResourceFetcherProperties().IsDetached())
    return nullptr;
  return GetFrame()->GetContentSettingsClient();
}

Settings* FrameFetchContext::GetSettings() const {
  if (GetResourceFetcherProperties().IsDetached())
    return nullptr;
  DCHECK(GetFrame());
  return GetFrame()->GetSettings();
}

String FrameFetchContext::GetUserAgent() const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->user_agent;
  return GetFrame()->Loader().UserAgent();
}

std::optional<UserAgentMetadata> FrameFetchContext::GetUserAgentMetadata()
    const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->user_agent_metadata;
  return GetLocalFrameClient()->UserAgentMetadata();
}

const PermissionsPolicy* FrameFetchContext::GetPermissionsPolicy() const {
  return document_ ? document_->domWindow()
                         ->GetSecurityContext()
                         .GetPermissionsPolicy()
                   : nullptr;
}

const ClientHintsPreferences FrameFetchContext::GetClientHintsPreferences()
    const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->client_hints_preferences;
  LocalFrame* frame = document_->GetFrame();
  DCHECK(frame);
  return frame->GetClientHintsPreferences();
}

String FrameFetchContext::GetReducedAcceptLanguage() const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->reduced_accept_language;
  LocalFrame* frame = document_->GetFrame();
  DCHECK(frame);
  // If accept language override from inspector emulation, set Accept-Language
  // header as the overridden value.
  String override_accept_language;
  probe::ApplyAcceptLanguageOverride(Probe(), &override_accept_language);
  if (override_accept_language.empty()) {
    String expanded_language = network_utils::ExpandLanguageList(
        frame->GetReducedAcceptLanguage().GetString());
    return network_utils::GenerateAcceptLanguageHeader(expanded_language);
  }
  return network_utils::GenerateAcceptLanguageHeader(override_accept_language);
}

float FrameFetchContext::GetDevicePixelRatio() const {
  if (GetResourceFetcherProperties().IsDetached())
    return frozen_state_->device_pixel_ratio;
  return document_->DevicePixelRatio();
}

FetchContext* FrameFetchContext::Detach() {
  if (GetResourceFetcherProperties().IsDetached())
    return this;

  // As we completed the reduction in the user-agent, the reduced User-Agent
  // string returns from GetUserAgent() should also be set on the User-Agent
  // request header.
  const ClientHintsPreferences& client_hints_prefs =
      GetClientHintsPreferences();
  frozen_state_ = MakeGarbageCollected<FrozenState>(
      Url(), GetContentSecurityPolicy(), GetSiteForCookies(),
      GetTopFrameOrigin(), client_hints_prefs, GetDevicePixelRatio(),
      GetUserAgent(), GetUserAgentMetadata(), IsIsolatedSVGChromeClient(),
      IsPrerendering(), GetReducedAcceptLanguage());
  document_loader_ = nullptr;
  document_ = nullptr;
  return this;
}

void FrameFetchContext::Trace(Visitor* visitor) const {
  visitor->Trace(document_loader_);
  visitor->Trace(document_);
  visitor->Trace(frozen_state_);
  BaseFetchContext::Trace(visitor);
}

bool FrameFetchContext::CalculateIfAdSubresource(
    const ResourceRequestHead& resource_request,
    base::optional_ref<const KURL> alias_url,
    ResourceType type,
    const FetchInitiatorInfo& initiator_info) {
  // Mark the resource as an Ad if the BaseFetchContext thinks it's an ad.
  bool known_ad = BaseFetchContext::CalculateIfAdSubresource(
      resource_request, alias_url, type, initiator_info);
  if (GetResourceFetcherProperties().IsDetached() ||
      !GetFrame()->GetAdTracker()) {
    return known_ad;
  }

  // The AdTracker needs to know about the request as well, and may also mark it
  // as an ad.
  const KURL& url =
      alias_url.has_value() ? alias_url.value() : resource_request.Url();
  return GetFrame()->GetAdTracker()->CalculateIfAdSubresource(
      document_->domWindow(), url, type, initiator_info, known_ad);
}

void FrameFetchContext::DidObserveLoadingBehavior(
    LoadingBehaviorFlag behavior) {
  if (GetResourceFetcherProperties().IsDetached())
    return;
  GetFrame()->Loader().GetDocumentLoader()->DidObserveLoadingBehavior(behavior);
}

std::unique_ptr<ResourceLoadInfoNotifierWrapper>
FrameFetchContext::CreateResourceLoadInfoNotifierWrapper() {
  if (GetResourceFetcherProperties().IsDetached())
    return nullptr;
  return GetLocalFrameClient()->CreateResourceLoadInfoNotifierWrapper();
}

mojom::blink::ContentSecurityNotifier&
FrameFetchContext::GetContentSecurityNotifier() const {
  DCHECK(!GetResourceFetcherProperties().IsDetached());
  return document_loader_->GetContentSecurityNotifier();
}

ExecutionContext* FrameFetchContext::GetExecutionContext() const {
  return document_->GetExecutionContext();
}

std::optional<ResourceRequestBlockedReason> FrameFetchContext::CanRequest(
    ResourceType type,
    const ResourceRequest& resource_request,
    const KURL& url,
    const ResourceLoaderOptions& options,
    ReportingDisposition reporting_disposition,
    base::optional_ref<const ResourceRequest::RedirectInfo> redirect_info)
    const {
  const bool detached = GetResourceFetcherProperties().IsDetached();
  if (!detached && document_->IsFreezingInProgress() &&
      !resource_request.GetKeepalive()) {
    GetDetachableConsoleLogger().AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kJavaScript,
            mojom::ConsoleMessageLevel::kError,
            "Only fetch keepalive is allowed during onfreeze: " +
                url.GetString()));
    return ResourceRequestBlockedReason::kOther;
  }
  std::optional<ResourceRequestBlockedReason> blocked_reason =
      BaseFetchContext::CanRequest(type, resource_request, url, options,
                                   reporting_disposition, redirect_info);
  if (blocked_reason) {
    return blocked_reason;
  }
  if (detached || !RuntimeEnabledFeatures::
                      MinimimalResourceRequestPrepBeforeCacheLookupEnabled()) {
    return std::nullopt;
  }
  if (!resource_request.Url().IsValid()) {
    return ResourceRequestBlockedReason::kOther;
  }
  return std::nullopt;
}

CoreProbeSink* FrameFetchContext::Probe() const {
  return probe::ToCoreProbeSink(GetFrame()->GetDocument());
}

void FrameFetchContext::UpdateSubresourceLoadMetrics(
    const SubresourceLoadMetrics& subresource_load_metrics) {
  document_loader_->UpdateSubresourceLoadMetrics(subresource_load_metrics);
}

}  // namespace blink

"""


```
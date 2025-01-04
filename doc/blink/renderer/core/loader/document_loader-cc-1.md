Response:
The user wants me to analyze a code snippet from `blink/renderer/core/loader/document_loader.cc`. This is part 2 of a 6-part series, so I should focus on the functionality within this specific chunk. The requested functionalities include:
1. Listing the functions of the code.
2. Identifying relationships with JavaScript, HTML, and CSS and providing examples.
3. Describing any logical reasoning and providing input/output examples.
4. Pointing out common user or programming errors.
5. Explaining how a user might reach this code through their actions.
6. Summarizing the overall functionality of this specific part of the code.

Let's break down the code snippet section by section and address each of these points.
这是 `blink/renderer/core/loader/document_loader.cc` 文件的第二部分，主要负责以下功能：

**1. 初始化 DocumentLoader 和设置帧属性:**

*   `DocumentLoader::DidCreate()`:  这是 `DocumentLoader` 对象创建后的初始化函数。
    *   它接收 `WebDocumentParams` 参数，这些参数包含了创建文档加载器所需的信息，例如 URL、referrer、安全上下文等。
    *   它会根据 `params_` 中的信息设置 `DocumentLoader` 的各种属性，例如：
        *   `service_worker_initial_controller_mode_`: 获取 Service Worker 的控制模式。
        *   `fenced_frame_properties_`: 处理与 Fenced Frames 相关的属性。
        *   调用 `frame_->SetAncestorOrSelfHasCSPEE()` 设置 CSP 报告组。
        *   调用 `frame_->Client()->DidCreateDocumentLoader(this)` 通知 `LocalFrameClient` 文档加载器已创建。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:**  Service Worker 是 JavaScript 的功能，用于在浏览器后台运行脚本，拦截和处理网络请求。`service_worker_network_provider_` 和 `service_worker_initial_controller_mode_` 的设置直接关系到 JavaScript Service Worker 的运作。
    *   **例子:** 当网页注册了一个 Service Worker，并且该 Service Worker 控制了当前页面时，`service_worker_network_provider_` 会被设置，并且 `GetControllerServiceWorkerMode()` 会返回 Service Worker 的控制状态。
*   **HTML:** Fenced Frames (`fenced_frame_properties_`) 是 HTML 的一种特性，用于隔离嵌入的内容。此处的代码处理与 Fenced Frames 相关的属性设置。
    *   **例子:** 当 HTML 中包含 `<fencedframe>` 标签时，浏览器会创建相应的 `DocumentLoader`，并且 `params_->fenced_frame_properties` 会包含该 Fenced Frame 的属性。`frame_->GetPage()->SetDeprecatedFencedFrameMode()` 会根据 Fenced Frame 的模式设置页面状态。
*   **CSS:**  CSP (Content Security Policy) 是一种安全机制，可以通过 HTTP 头部或 HTML `<meta>` 标签来定义。 `frame_->SetAncestorOrSelfHasCSPEE()`  的设置与 CSP 报告组有关，影响浏览器如何处理违反 CSP 策略的行为。虽然此处没有直接操作 CSS，但 CSP 可以限制 CSS 的加载和执行。
    *   **例子:** 如果一个网页设置了 CSP 策略，禁止加载来自特定域名的 CSS 文件，那么 `frame_->SetAncestorOrSelfHasCSPEE()` 的设置会影响浏览器是否以及如何报告此类违规行为。

**2. 创建克隆文档的导航参数:**

*   `DocumentLoader::CreateWebNavigationParamsToCloneDocument()`:  此函数创建一个 `WebNavigationParams` 对象，用于克隆当前的 `DocumentLoader`。这通常发生在执行 JavaScript URL 或处理 XSLT 文档时。
    *   它会复制当前 `DocumentLoader` 的许多属性到新的 `WebNavigationParams` 中，以便新加载的文档能够继承相同的上下文和状态。
    *   注释中详细列出了哪些属性会被复制，以及哪些属性不会被复制以及原因。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:** 当执行 `javascript:` URL 时，浏览器会创建一个新的文档加载器来处理执行结果。此函数用于创建新文档加载器的导航参数。
    *   **假设输入:** 用户在地址栏输入 `javascript:alert('hello');` 并回车。
    *   **输出:**  `CreateWebNavigationParamsToCloneDocument()` 会被调用，创建一个包含当前文档上下文信息（例如安全 origin、referrer 等）的 `WebNavigationParams` 对象。
*   **HTML:**  当 JavaScript 操作 (例如通过 `document.open()`) 创建新的 HTML 内容时，也可能需要克隆 `DocumentLoader`。
    *   **假设输入:** JavaScript 代码执行 `document.open(); document.write('<h1>New Document</h1>'); document.close();`
    *   **输出:**  可能会调用此函数创建新的导航参数，以便正确加载和显示新的 HTML 内容.
*   **CSS:**  虽然此函数不直接处理 CSS，但克隆文档的导航参数会影响新文档加载时 CSS 的处理方式，例如继承相同的安全策略和 origin 信息。

**3. 获取 FrameLoader 和 LocalFrameClient:**

*   `DocumentLoader::GetFrameLoader()`: 返回与此 `DocumentLoader` 关联的 `FrameLoader` 对象。
*   `DocumentLoader::GetLocalFrameClient()`: 返回与此 `DocumentLoader` 关联的 `LocalFrameClient` 对象。`LocalFrameClient` 是一个接口，用于与渲染进程的其他部分（例如浏览器进程）进行通信。

**4. 析构函数:**

*   `DocumentLoader::~DocumentLoader()`:  `DocumentLoader` 对象的析构函数。
    *   它会检查 `state_` 是否为 `kSentDidFinishLoad`，表示加载已完成。
    *   它断言 `frame_` 和 `body_loader_` 为空，表示 `DocumentLoader` 已从 `Frame` 分离并且已停止加载。

**5. 追踪 (Tracing):**

*   `DocumentLoader::Trace()`:  用于 Chromium 的垃圾回收和调试机制，标记 `DocumentLoader` 拥有的重要对象，防止它们被过早回收。

**6. 获取文档加载器的各种属性:**

*   `DocumentLoader::MainResourceIdentifier()`: 返回主资源的标识符。
*   `DocumentLoader::OriginalReferrer()`: 返回原始的 referrer。
*   `DocumentLoader::Url()`: 返回当前文档的 URL。
*   `DocumentLoader::HttpMethod()`: 返回请求方法 (GET, POST 等)。
*   `DocumentLoader::GetReferrer()`: 返回 referrer。
*   `DocumentLoader::GetRequestorOrigin()`: 返回请求者的 Origin。

**7. 设置 Service Worker 网络提供器:**

*   `DocumentLoader::SetServiceWorkerNetworkProvider()`:  设置与此文档加载器关联的 Service Worker 网络提供器。

**8. 分发 Link 头部预加载指令:**

*   `DocumentLoader::DispatchLinkHeaderPreloads()`:  解析 HTTP 响应头部的 `Link` 字段，并根据其中的 `preload` 指令预加载资源。
*   `DocumentLoader::DispatchLcppFontPreloads()`:  专门针对 LCP (Largest Contentful Paint) 优化，预加载关键字体资源。

**与 JavaScript, HTML, CSS 的关系:**

*   **HTML:**  `<link rel="preload">` 是 HTML 中用于声明预加载资源的标签。`DispatchLinkHeaderPreloads` 处理的是通过 HTTP 头部声明的预加载。
    *   **例子:** 服务器发送的 HTTP 头部包含 `Link: <style.css>; rel=preload; as=style`，`DispatchLinkHeaderPreloads` 会解析这个头部，并指示浏览器预先加载 `style.css` 文件。
*   **CSS:**  预加载 CSS 文件 (`as=style`) 可以提高页面加载速度，避免渲染阻塞。`DispatchLinkHeaderPreloads` 可以预加载 CSS 文件。`DispatchLcppFontPreloads` 专门预加载字体，这对于优化文本渲染至关重要。
*   **JavaScript:**  预加载也可以用于 JavaScript 文件 (`as=script`)。

**9. 通知性能时间变化:**

*   `DocumentLoader::DidChangePerformanceTiming()`:  通知 `LocalFrameClient` 性能时间发生了变化，这会触发相关的性能指标更新。

**10. 观察加载行为:**

*   `DocumentLoader::DidObserveLoadingBehavior()`:  记录观察到的加载行为标志。

**11. 观察 JavaScript 框架:**

*   `DocumentLoader::DidObserveJavaScriptFrameworks()`:  接收并处理检测到的 JavaScript 框架信息。
*   `DocumentLoader::InjectAutoSpeculationRules()`:  根据检测到的 JavaScript 框架，注入自动推测规则 (AutoSpeculation Rules)，用于提前预加载或预连接资源。
*   `DocumentLoader::InjectSpeculationRulesFromString()`:  从字符串中解析并注入推测规则。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:**  此功能与 JavaScript 框架的检测密切相关。浏览器可以检测页面使用了哪些 JavaScript 框架 (例如 React, Angular, Vue)，并根据这些信息进行优化。
*   **HTML:**  推测规则可以用于预加载 HTML 文档。
*   **CSS:** 推测规则可以用于预加载 CSS 样式表。
    *   **假设输入:** 页面使用了 React 框架，并且服务器配置了相应的自动推测规则。
    *   **输出:** `DidObserveJavaScriptFrameworks` 会检测到 React，`InjectAutoSpeculationRules` 会根据配置的规则，例如预加载与 React 组件相关的 JavaScript 或 CSS 文件。

**12. 转换加载类型为提交类型:**

*   `DocumentLoader::LoadTypeToCommitType()`:  将 `WebFrameLoadType` 枚举值转换为 `WebHistoryCommitType` 枚举值，用于表示历史记录的提交类型。

**13. 运行 URL 和历史记录更新步骤:**

*   `DocumentLoader::RunURLAndHistoryUpdateSteps()`:  在同文档导航发生时，更新 URL 和历史记录状态。
*   `DocumentLoader::UpdateForSameDocumentNavigation()`:  执行同文档导航的更新逻辑。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:** 当 JavaScript 使用 `history.pushState()` 或 `history.replaceState()` 修改 URL 时，会触发同文档导航。
    *   **假设输入:** JavaScript 代码执行 `history.pushState({page: 1}, "title 1", "?page=1");`
    *   **输出:** `RunURLAndHistoryUpdateSteps` 或 `UpdateForSameDocumentNavigation` 会被调用，更新文档的 URL 和历史记录状态，但不会重新加载整个文档。
*   **HTML:**  锚点链接 (`<a href="#section">`) 也会导致同文档导航。
    *   **假设输入:** 用户点击了一个指向页面内部锚点的链接。
    *   **输出:**  `RunURLAndHistoryUpdateSteps` 或 `UpdateForSameDocumentNavigation` 会更新 URL 的 hash 部分。

**14. 获取用于历史记录的 URL:**

*   `DocumentLoader::UrlForHistory()`: 返回用于历史记录的 URL，如果存在不可达的 URL，则返回不可达的 URL，否则返回当前 URL。

**15. 文档输入流打开:**

*   `DocumentLoader::DidOpenDocumentInputStream()`:  当使用 `document.open()` 打开文档输入流时被调用，更新文档的 URL 并通知 `LocalFrameClient`。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:**  `document.open()` 是 JavaScript 中用于创建或替换当前文档的方法。
    *   **假设输入:** JavaScript 代码执行 `document.open();`
    *   **输出:** `DidOpenDocumentInputStream` 会被调用，更新文档的 URL。

**16. 设置提交时的历史记录项状态:**

*   `DocumentLoader::SetHistoryItemStateForCommit()`:  设置将要提交到历史记录的 `HistoryItem` 的状态，包括 URL、referrer、表单数据等。

**17. 接收 Body 数据:**

*   `DocumentLoader::BodyDataReceived()`:  接收原始的 Body 数据。
*   `DocumentLoader::DecodedBodyDataReceived()`: 接收解码后的 Body 数据。
*   `DocumentLoader::TakeProcessBackgroundDataCallback()`: 获取用于后台处理数据的回调。
*   `DocumentLoader::BodyDataReceivedImpl()`:  实际处理接收到的 Body 数据，更新加载进度，并将数据传递给解析器。

**与 JavaScript, HTML, CSS 的关系:**

*   **HTML:**  接收到的 Body 数据通常是 HTML 内容。`BodyDataReceivedImpl` 会将这些数据传递给 HTML 解析器进行解析。
*   **CSS:**  如果加载的是 CSS 文件，那么接收到的 Body 数据就是 CSS 代码。
*   **JavaScript:**  如果加载的是 JavaScript 文件，接收到的 Body 数据就是 JavaScript 代码.

**18. Body 加载完成:**

*   `DocumentLoader::BodyLoadingFinished()`:  当 Body 数据加载完成后被调用，更新加载进度，记录性能指标，并通知 `LocalFrameClient` 加载已完成。

**19. 加载失败:**

*   `DocumentLoader::LoadFailed()`:  当加载过程中发生错误时被调用，通知 `LocalFrameClient` 加载失败。

**20. 加载完成:**

*   `DocumentLoader::FinishedLoading()`:  当文档加载成功完成时被调用，执行清理工作。

**常见用户或编程使用错误:**

*   **JavaScript 操作历史记录的错误:**  不正确地使用 `history.pushState()` 或 `history.replaceState()` 可能导致 URL 和历史记录状态不一致，影响用户的浏览体验。例如，忘记提供 state 对象或 title。
*   **错误配置预加载:**  在 `Link` 头部或 HTML 中声明了错误的预加载资源路径或类型，会导致浏览器浪费资源加载无用的文件。
*   **CSP 配置错误:**  配置了过于严格或错误的 CSP 策略，可能会阻止 legitimate 资源的加载，导致页面功能异常。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在地址栏输入 URL 并按下回车键:** 这会触发一个新的导航，创建 `DocumentLoader` 对象，并调用 `DidCreate()` 进行初始化。
2. **用户点击页面上的链接:**  如果链接是同域名的，并且指向页面内部的锚点 (`#fragment`)，可能会触发同文档导航，调用 `RunURLAndHistoryUpdateSteps()` 或 `UpdateForSameDocumentNavigation()`。
3. **用户使用浏览器的前进/后退按钮:** 这会触发历史记录导航，可能会调用 `SetHistoryItemStateForCommit()` 来设置历史记录状态。
4. **网页执行 JavaScript 代码修改 URL (例如 `history.pushState()`):**  这同样会触发同文档导航，调用 `RunURLAndHistoryUpdateSteps()` 或 `UpdateForSameDocumentNavigation()`。
5. **网页使用了 `<link rel="preload">` 标签或服务器发送了包含 `preload` 指令的 `Link` 头部:**  浏览器会解析这些指令，调用 `DispatchLinkHeaderPreloads()` 来预加载资源。
6. **网页注册并使用了 Service Worker:**  `DidCreate()` 中会初始化与 Service Worker 相关的属性。
7. **网络请求返回 HTML、CSS 或 JavaScript 数据:**  `BodyDataReceived()` 或 `DecodedBodyDataReceived()` 会被调用来接收和处理这些数据。
8. **文档加载完成或失败:** `BodyLoadingFinished()`, `FinishedLoading()`, 或 `LoadFailed()` 会在加载过程结束时被调用。

**此部分功能归纳:**

此部分代码主要负责 `DocumentLoader` 对象的初始化、创建克隆文档的导航参数、管理与 Frame 的关系、处理预加载指令、观察 JavaScript 框架、以及处理同文档导航相关的 URL 和历史记录更新。它涵盖了文档加载过程中的关键初始化和上下文设置环节，并与 JavaScript、HTML 和 CSS 的特性紧密相关。

Prompt: 
```
这是目录为blink/renderer/core/loader/document_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
 }

  if (service_worker_network_provider_) {
    service_worker_initial_controller_mode_ =
        service_worker_network_provider_->GetControllerServiceWorkerMode();
  }

  if (params_->fenced_frame_properties) {
    fenced_frame_properties_ = std::move(params_->fenced_frame_properties);
    if (frame_->GetPage()) {
      frame_->GetPage()->SetDeprecatedFencedFrameMode(
          fenced_frame_properties_->mode());
    }
  }

  frame_->SetAncestorOrSelfHasCSPEE(params_->ancestor_or_self_has_cspee);
  frame_->Client()->DidCreateDocumentLoader(this);
}

std::unique_ptr<WebNavigationParams>
DocumentLoader::CreateWebNavigationParamsToCloneDocument() {
  // From the browser process point of view, committing the result of evaluating
  // a javascript URL or an XSLT document are all a no-op. Since we will use the
  // resulting |params| to create a clone of this DocumentLoader, many
  // attributes of DocumentLoader should be copied/inherited to the new
  // DocumentLoader's WebNavigationParams. The current heuristic is largely
  // based on copying fields that are populated in the DocumentLoader
  // constructor. Some exclusions:
  // |history_item_| is set in SetHistoryItemStateForCommit().
  // |response_| will use the newly committed response.
  // |load_type_| will use default kStandard value.
  // |replaces_current_history_item_| will be false.
  // |permissions_policy_| and |document_policy_| are set in CommitNavigation(),
  // with the sandbox flags set in CalculateSandboxFlags().
  // |is_client_redirect_| is not copied since future same-document navigations
  // will reset the state anyways.
  // |archive_| and other states might need to be copied, but we need to add
  // fields to WebNavigationParams and create WebMHTMLArchive, etc.
  // TODO(https://crbug.com/1151954): Copy |archive_| and other attributes.
  auto params = std::make_unique<WebNavigationParams>();
  LocalDOMWindow* window = frame_->DomWindow();
  params->document_token = frame_->GetDocument()->Token();
  params->url = window->Url();
  params->fallback_base_url = fallback_base_url_;
  params->unreachable_url = unreachable_url_;
  params->referrer = referrer_;
  // All the security properties of the document must be preserved. Note that
  // sandbox flags and various policies are copied separately during commit in
  // CommitNavigation() and CalculateSandboxFlags().
  params->storage_key = window->GetStorageKey();
  params->origin_agent_cluster = origin_agent_cluster_;
  params->origin_agent_cluster_left_as_default =
      origin_agent_cluster_left_as_default_;
  params->grant_load_local_resources = grant_load_local_resources_;
  // Various attributes that relates to the last "real" navigation that is known
  // by the browser must be carried over.
  params->http_method = http_method_;
  params->http_status_code = GetResponse().HttpStatusCode();
  params->http_body = http_body_;
  params->pre_redirect_url_for_failed_navigations =
      pre_redirect_url_for_failed_navigations_;
  params->force_fetch_cache_mode = force_fetch_cache_mode_;
  params->service_worker_network_provider =
      std::move(service_worker_network_provider_);
  params->devtools_navigation_token = devtools_navigation_token_;
  params->base_auction_nonce = base_auction_nonce_;
  params->is_user_activated = had_sticky_activation_;
  params->had_transient_user_activation =
      last_navigation_had_transient_user_activation_;
  params->is_browser_initiated = is_browser_initiated_;
  params->was_discarded = was_discarded_;
  params->document_ukm_source_id = ukm_source_id_;
  params->is_cross_site_cross_browsing_context_group =
      is_cross_site_cross_browsing_context_group_;
  // Required for javascript: URL commits to propagate sticky user activation.
  params->should_have_sticky_user_activation =
      frame_->HasStickyUserActivation() && !frame_->IsMainFrame();
  params->has_text_fragment_token = has_text_fragment_token_;
  // Origin trials must still work on the cloned document.
  params->initiator_origin_trial_features =
      CopyInitiatorOriginTrials(initiator_origin_trial_features_);
  params->force_enabled_origin_trials =
      CopyForceEnabledOriginTrials(force_enabled_origin_trials_);
  for (const auto& pair : early_hints_preloaded_resources_)
    params->early_hints_preloaded_resources.push_back(pair.key);
  if (ad_auction_components_) {
    params->ad_auction_components.emplace();
    for (const KURL& url : *ad_auction_components_) {
      params->ad_auction_components->emplace_back(KURL(url));
    }
  }
  params->reduced_accept_language = reduced_accept_language_;
  params->navigation_delivery_type = navigation_delivery_type_;
  params->load_with_storage_access = storage_access_api_status_;
  params->modified_runtime_features = modified_runtime_features_;
  params->cookie_deprecation_label = cookie_deprecation_label_;
  params->visited_link_salt = visited_link_salt_;
  params->content_settings = content_settings_->Clone();

  if (RuntimeEnabledFeatures::PermissionElementEnabled(
          frame_->DomWindow()->GetExecutionContext())) {
    params->initial_permission_statuses =
        ConvertPermissionStatusHashMapToFlatMap(
            CachedPermissionStatus::From(frame_->DomWindow())
                ->GetPermissionStatusMap());
  }
  return params;
}

FrameLoader& DocumentLoader::GetFrameLoader() const {
  DCHECK(frame_);
  return frame_->Loader();
}

LocalFrameClient& DocumentLoader::GetLocalFrameClient() const {
  DCHECK(frame_);
  LocalFrameClient* client = frame_->Client();
  // LocalFrame clears its |m_client| only after detaching all DocumentLoaders
  // (i.e. calls detachFromFrame() which clears |frame_|) owned by the
  // LocalFrame's FrameLoader. So, if |frame_| is non nullptr, |client| is
  // also non nullptr.
  DCHECK(client);
  return *client;
}

DocumentLoader::~DocumentLoader() {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::~DocumentLoader",
                         TRACE_ID_LOCAL(this), TRACE_EVENT_FLAG_FLOW_IN);
  DCHECK_EQ(state_, kSentDidFinishLoad);

  // Before being collected by the GC, it is expected the DocumentLoader to be
  // detached from the frame, and it should have stopped loading.
  //
  // Note that the WebNavigationBodyLoader implementation is not a GCed class
  // and it could call `this` back. It is important it gets removed before
  // collecting `this`.
  DCHECK(!frame_);
  DCHECK(!body_loader_);
}

void DocumentLoader::Trace(Visitor* visitor) const {
  visitor->Trace(archive_);
  visitor->Trace(frame_);
  visitor->Trace(history_item_);
  visitor->Trace(parser_);
  visitor->Trace(subresource_filter_);
  visitor->Trace(content_security_notifier_);
  visitor->Trace(document_load_timing_);
  visitor->Trace(prefetched_signed_exchange_manager_);
  visitor->Trace(use_counter_);
  visitor->Trace(navigation_api_previous_entry_);
}

uint64_t DocumentLoader::MainResourceIdentifier() const {
  return main_resource_identifier_;
}

WebString DocumentLoader::OriginalReferrer() const {
  return original_referrer_;
}

const KURL& DocumentLoader::Url() const {
  return url_;
}

WebString DocumentLoader::HttpMethod() const {
  return http_method_;
}

const AtomicString& DocumentLoader::GetReferrer() const {
  return referrer_;
}

const SecurityOrigin* DocumentLoader::GetRequestorOrigin() const {
  return requestor_origin_.get();
}

void DocumentLoader::SetServiceWorkerNetworkProvider(
    std::unique_ptr<WebServiceWorkerNetworkProvider> provider) {
  service_worker_network_provider_ = std::move(provider);
}

void DocumentLoader::DispatchLinkHeaderPreloads(
    const ViewportDescription* viewport,
    PreloadHelper::LoadLinksFromHeaderMode mode) {
  DCHECK_GE(state_, kCommitted);
  PreloadHelper::LoadLinksFromHeader(
      GetResponse().HttpHeaderField(http_names::kLink),
      GetResponse().CurrentRequestUrl(), *frame_, frame_->GetDocument(), mode,
      viewport, nullptr /* alternate_resource_info */,
      nullptr /* recursive_prefetch_token */);
}

void DocumentLoader::DispatchLcppFontPreloads(
    const ViewportDescription* viewport,
    PreloadHelper::LoadLinksFromHeaderMode mode) {
  DCHECK_GE(state_, kCommitted);
  StringBuilder fonts_link;
  LCPCriticalPathPredictor* lcpp = frame_->GetLCPP();
  if (!lcpp) {
    return;
  }
  // Generate link header for fonts.
  for (const auto& font : lcpp->fetched_fonts()) {
    if (!fonts_link.empty()) {
      fonts_link.Append(",");
    }
    fonts_link.Append("<");
    fonts_link.Append(font.GetString());
    fonts_link.Append(">; rel=\"preload\"; as=\"font\"");
  }
  PreloadHelper::LoadLinksFromHeader(fonts_link.ToString(),
                                     GetResponse().CurrentRequestUrl(), *frame_,
                                     frame_->GetDocument(), mode, viewport,
                                     nullptr /* alternate_resource_info */,
                                     nullptr /* recursive_prefetch_token */);
  base::UmaHistogramCounts1000("Blink.LCPP.PreloadedFontCount",
                               lcpp->fetched_fonts().size());
}

void DocumentLoader::DidChangePerformanceTiming() {
  if (frame_ && state_ >= kCommitted) {
    GetLocalFrameClient().DidChangePerformanceTiming();
  }
}

void DocumentLoader::DidObserveLoadingBehavior(LoadingBehaviorFlag behavior) {
  if (frame_) {
    DCHECK_GE(state_, kCommitted);
    GetLocalFrameClient().DidObserveLoadingBehavior(behavior);
  }
}

void DocumentLoader::DidObserveJavaScriptFrameworks(
    const JavaScriptFrameworkDetectionResult& result) {
  if (frame_) {
    DCHECK_GE(state_, kCommitted);
    GetLocalFrameClient().DidObserveJavaScriptFrameworks(result);
    InjectAutoSpeculationRules(result);
  }
}

void DocumentLoader::InjectAutoSpeculationRules(
    const JavaScriptFrameworkDetectionResult& result) {
  if (!base::FeatureList::IsEnabled(features::kAutoSpeculationRules)) {
    return;
  }

  const auto& config = AutoSpeculationRulesConfig::GetInstance();

  const Vector<std::pair<String, BrowserInjectedSpeculationRuleOptOut>>
      from_url_speculation_rules = config.ForUrl(Url());
  for (const auto& speculation_rules : from_url_speculation_rules) {
    InjectSpeculationRulesFromString(speculation_rules.first,
                                     speculation_rules.second);
  }

  for (const auto& detected_version : result.detected_versions) {
    if (String speculation_rules =
            config.ForFramework(detected_version.first)) {
      InjectSpeculationRulesFromString(
          speculation_rules, BrowserInjectedSpeculationRuleOptOut::kRespect);
    }
  }
}

void DocumentLoader::InjectSpeculationRulesFromString(
    const String& string,
    BrowserInjectedSpeculationRuleOptOut opt_out) {
  auto* source =
      SpeculationRuleSet::Source::FromBrowserInjected(string, Url(), opt_out);
  auto* rule_set = SpeculationRuleSet::Parse(source, frame_->DomWindow());
  CHECK(rule_set);

  // The JSON string in speculation_rules comes from a potentially-fallible
  // remote config, so this should not be a CHECK failure.
  if (rule_set->HasError()) {
    LOG(ERROR) << "Failed to parse auto speculation rules " << string;
    return;
  }

  DocumentSpeculationRules::From(*frame_->GetDocument()).AddRuleSet(rule_set);
}

// static
WebHistoryCommitType LoadTypeToCommitType(WebFrameLoadType type) {
  switch (type) {
    case WebFrameLoadType::kStandard:
      return kWebStandardCommit;
    case WebFrameLoadType::kBackForward:
    case WebFrameLoadType::kRestore:
      return kWebBackForwardCommit;
    case WebFrameLoadType::kReload:
    case WebFrameLoadType::kReplaceCurrentItem:
    case WebFrameLoadType::kReloadBypassingCache:
      return kWebHistoryInertCommit;
  }
  NOTREACHED();
}

void DocumentLoader::RunURLAndHistoryUpdateSteps(
    const KURL& new_url,
    HistoryItem* history_item,
    mojom::blink::SameDocumentNavigationType same_document_navigation_type,
    scoped_refptr<SerializedScriptValue> data,
    WebFrameLoadType type,
    FirePopstate fire_popstate,
    bool is_browser_initiated,
    bool is_synchronously_committed,
    std::optional<scheduler::TaskAttributionId>
        soft_navigation_heuristics_task_id) {
  // We use the security origin of this frame since callers of this method must
  // already have performed same origin checks.
  // is_browser_initiated is false and is_synchronously_committed is true
  // because anything invoking this algorithm is a renderer-initiated navigation
  // in this process.
  UpdateForSameDocumentNavigation(
      new_url, history_item, same_document_navigation_type, std::move(data),
      type, fire_popstate, frame_->DomWindow()->GetSecurityOrigin(),
      is_browser_initiated, is_synchronously_committed,
      soft_navigation_heuristics_task_id);
}

void DocumentLoader::UpdateForSameDocumentNavigation(
    const KURL& new_url,
    HistoryItem* history_item,
    mojom::blink::SameDocumentNavigationType same_document_navigation_type,
    scoped_refptr<SerializedScriptValue> data,
    WebFrameLoadType type,
    FirePopstate fire_popstate,
    const SecurityOrigin* initiator_origin,
    bool is_browser_initiated,
    bool is_synchronously_committed,
    std::optional<scheduler::TaskAttributionId>
        soft_navigation_heuristics_task_id) {
  CHECK_EQ(IsBackForwardOrRestore(type), !!history_item);

  TRACE_EVENT1("blink", "FrameLoader::updateForSameDocumentNavigation", "url",
               new_url.GetString().Ascii());

  bool same_item_sequence_number =
      history_item_ && history_item &&
      history_item_->ItemSequenceNumber() == history_item->ItemSequenceNumber();
  if (history_item)
    history_item_ = history_item;

  // Spec "URL and history update steps", step 4 [1]:
  // " If document's is initial about:blank is true, then set historyHandling to
  // 'replace'."
  // [1]: https://html.spec.whatwg.org/C/#url-and-history-update-steps
  if (type == WebFrameLoadType::kStandard &&
      GetFrameLoader().IsOnInitialEmptyDocument()) {
    type = WebFrameLoadType::kReplaceCurrentItem;
  }

  // Generate start and stop notifications only when loader is completed so that
  // we don't fire them for fragment redirection that happens in window.onload
  // handler. See https://bugs.webkit.org/show_bug.cgi?id=31838
  // Do not fire the notifications if the frame is concurrently navigating away
  // from the document, since a new document is already loading.
  bool was_loading = frame_->IsLoading();
  if (!was_loading) {
    GetFrameLoader().Progress().ProgressStarted();
  }

  // Update the data source's request with the new URL to fake the URL change
  frame_->GetDocument()->SetURL(new_url);

  KURL old_url = url_;
  url_ = new_url;
  replaces_current_history_item_ = type != WebFrameLoadType::kStandard;
  bool is_history_api_or_app_history_navigation =
      (same_document_navigation_type !=
       mojom::blink::SameDocumentNavigationType::kFragment);
  if (is_history_api_or_app_history_navigation) {
    // See spec:
    // https://html.spec.whatwg.org/multipage/history.html#url-and-history-update-steps
    http_method_ = http_names::kGET;
    http_body_ = nullptr;
  }

  last_navigation_had_trusted_initiator_ =
      initiator_origin ? initiator_origin->IsSameOriginWith(
                             frame_->DomWindow()->GetSecurityOrigin()) &&
                             Url().ProtocolIsInHTTPFamily()
                       : true;

  // We want to allow same-document text fragment navigations if they're coming
  // from the browser or same-origin. Do this only on a standard navigation so
  // that we don't unintentionally clear the token when we reach here from the
  // history API.
  if (type == WebFrameLoadType::kStandard ||
      same_document_navigation_type ==
          mojom::blink::SameDocumentNavigationType::kFragment) {
    has_text_fragment_token_ =
        TextFragmentAnchor::GenerateNewTokenForSameDocument(
            *this, type, same_document_navigation_type);
  }

  SetHistoryItemStateForCommit(history_item_.Get(), type,
                               is_history_api_or_app_history_navigation
                                   ? HistoryNavigationType::kHistoryApi
                                   : HistoryNavigationType::kFragment,
                               CommitReason::kRegular);
  history_item_->SetDocumentState(frame_->GetDocument()->GetDocumentState());
  if (is_history_api_or_app_history_navigation)
    history_item_->SetStateObject(std::move(data));

  WebHistoryCommitType commit_type = LoadTypeToCommitType(type);
  frame_->GetFrameScheduler()->DidCommitProvisionalLoad(
      commit_type == kWebHistoryInertCommit,
      FrameScheduler::NavigationType::kSameDocument);

  GetLocalFrameClient().DidFinishSameDocumentNavigation(
      commit_type, is_synchronously_committed, same_document_navigation_type,
      is_client_redirect_, is_browser_initiated);
  probe::DidNavigateWithinDocument(frame_, same_document_navigation_type);

  // If intercept() was called during this same-document navigation's
  // NavigateEvent, the navigation will finish asynchronously, so
  // don't immediately call DidStopLoading() in that case.
  bool should_send_stop_notification =
      !was_loading &&
      same_document_navigation_type !=
          mojom::blink::SameDocumentNavigationType::kNavigationApiIntercept;
  if (should_send_stop_notification)
    GetFrameLoader().Progress().ProgressCompleted();

  if (!same_item_sequence_number) {
    // If the item sequence number didn't change, there's no need to update any
    // Navigation API state or fire associated events. It's possible to get a
    // same-document navigation to a same ISN when a  history navigation targets
    // a frame that no longer exists (https://crbug.com/705550).
    frame_->DomWindow()->navigation()->UpdateForNavigation(*history_item_,
                                                           type);
  }

  if (!frame_)
    return;

  std::optional<SoftNavigationHeuristics::EventScope>
      soft_navigation_event_scope;
  SoftNavigationHeuristics* heuristics =
      SoftNavigationHeuristics::From(*frame_->DomWindow());
  if (heuristics && is_browser_initiated) {
    if (auto* script_state = ToScriptStateForMainWorld(frame_->DomWindow())) {
      // For browser-initiated navigations, we never started the soft
      // navigation (as this is the first we hear of it in the renderer). We
      // need to do that now.
      soft_navigation_event_scope =
          heuristics->CreateNavigationEventScope(script_state);
    }
  }

  scheduler::TaskAttributionInfo* navigation_task_state = nullptr;
  if (heuristics) {
    // If `heuristics` exists, it means we're in an outermost main frame.
    if (auto* tracker = scheduler::TaskAttributionTracker::From(
            frame_->DomWindow()->GetIsolate())) {
      // There are three cases where the commit should be associated with a
      // `SoftNavigationContext`:
      //
      //  1. `soft_navigation_heuristics_task_id` exists. This means the task
      //  state being propagated was captured in a main world history API call.
      //  The relevant context is the one captured when the navigation started,
      //  which is is stored in `tracker` along with the id.
      //
      //  2. Browser-initiated navigations. In this case a new context would
      //  have been created when the `EventScope` was created above, and the
      //  relevant context will be stored in the current task state.
      //
      //  3. Synchronous navigations. In this case the context isn't registered
      //  when the navigation started, but the relevant context is part of the
      //  current task state.
      navigation_task_state =
          soft_navigation_heuristics_task_id
              ? tracker->CommitSameDocumentNavigation(
                    soft_navigation_heuristics_task_id.value())
              : tracker->RunningTask();
    }
  }

  // Anything except a history.pushState/replaceState is considered a new
  // navigation that resets whether the user has scrolled and fires popstate.
  // A history.pushState/replaceState intercepted via the navigation API should
  // also not fire popstate.
  if (fire_popstate == FirePopstate::kYes) {
    initial_scroll_state_.was_scrolled_by_user = false;

    // If the item sequence number didn't change, there's no need to trigger
    // popstate. It's possible to get a same-document navigation
    // to a same ISN when a history navigation targets a frame that no longer
    // exists (https://crbug.com/705550).
    if (!same_item_sequence_number) {
      scoped_refptr<SerializedScriptValue> state_object =
          history_item ? history_item->StateObject()
                       : SerializedScriptValue::NullValue();
      frame_->DomWindow()->DispatchPopstateEvent(std::move(state_object),
                                                 navigation_task_state);
    }
  }

  SoftNavigationContext* soft_navigation_context =
      navigation_task_state ? navigation_task_state->GetSoftNavigationContext()
                            : nullptr;
  if (heuristics && new_url != old_url &&
      type != WebFrameLoadType::kReplaceCurrentItem) {
    // if `heuristics` exists it means we're in an outermost main frame.
    //
    // TODO(crbug.com/1521100): `heuristics` existing does not imply this
    // navigation was initiated in the main world.
    heuristics->SameDocumentNavigationCommitted(new_url,
                                                soft_navigation_context);
  }
}

const KURL& DocumentLoader::UrlForHistory() const {
  return UnreachableURL().IsEmpty() ? Url() : UnreachableURL();
}

void DocumentLoader::DidOpenDocumentInputStream(const KURL& url) {
  url_ = url;
  // Let the browser know that we have done a document.open().
  GetLocalFrameClient().DispatchDidOpenDocumentInputStream(url_);
}

void DocumentLoader::SetHistoryItemStateForCommit(
    HistoryItem* old_item,
    WebFrameLoadType load_type,
    HistoryNavigationType navigation_type,
    CommitReason commit_reason) {
  if (!history_item_ || !IsBackForwardOrRestore(load_type)) {
    history_item_ = MakeGarbageCollected<HistoryItem>();
  }

  history_item_->SetURL(UrlForHistory());
  history_item_->SetReferrer(referrer_.GetString());
  if (EqualIgnoringASCIICase(http_method_, "POST")) {
    // FIXME: Eventually we have to make this smart enough to handle the case
    // where we have a stream for the body to handle the "data interspersed with
    // files" feature.
    history_item_->SetFormData(http_body_);
    history_item_->SetFormContentType(http_content_type_);
  } else {
    history_item_->SetFormData(nullptr);
    history_item_->SetFormContentType(g_null_atom);
  }

  // Don't propagate state from the old item to the new item if there isn't an
  // old item (obviously), or if this is a back/forward navigation, since we
  // explicitly want to restore the state we just committed.
  if (!old_item || IsBackForwardOrRestore(load_type)) {
    return;
  }

  // The navigation API key corresponds to a "slot" in the back/forward list,
  // and should be shared for all replacing navigations so long as the
  // navigation isn't cross-origin.
  WebHistoryCommitType history_commit_type = LoadTypeToCommitType(load_type);
  if (history_commit_type == kWebHistoryInertCommit &&
      SecurityOrigin::Create(old_item->Url())
          ->CanAccess(SecurityOrigin::Create(history_item_->Url()).get())) {
    history_item_->SetNavigationApiKey(old_item->GetNavigationApiKey());
  }

  // The navigation API id corresponds to a "session history entry", and so
  // should be carried over across reloads.
  if (IsReloadLoadType(load_type))
    history_item_->SetNavigationApiId(old_item->GetNavigationApiId());

  // The navigation API's state is stickier than the legacy History state. It
  // always propagates by default to a same-document navigation.
  if (navigation_type == HistoryNavigationType::kFragment ||
      IsReloadLoadType(load_type)) {
    history_item_->SetNavigationApiState(old_item->GetNavigationApiState());
  }

  // Don't propagate state from the old item if this is a different-document
  // navigation, unless the before and after pages are logically related. This
  // means they have the same url (ignoring fragment) and the new item was
  // loaded via reload or client redirect.
  if (navigation_type == HistoryNavigationType::kDifferentDocument &&
      (history_commit_type != kWebHistoryInertCommit ||
       !EqualIgnoringFragmentIdentifier(old_item->Url(), history_item_->Url())))
    return;
  history_item_->SetDocumentSequenceNumber(old_item->DocumentSequenceNumber());

  history_item_->CopyViewStateFrom(old_item);
  history_item_->SetScrollRestorationType(old_item->ScrollRestorationType());

  // The item sequence number determines whether items are "the same", such
  // back/forward navigation between items with the same item sequence number is
  // a no-op. Only treat this as identical if the navigation did not create a
  // back/forward entry and the url is identical or it was loaded via
  // history.replaceState().
  if (history_commit_type == kWebHistoryInertCommit &&
      (navigation_type == HistoryNavigationType::kHistoryApi ||
       old_item->Url() == history_item_->Url())) {
    history_item_->SetStateObject(old_item->StateObject());
    history_item_->SetItemSequenceNumber(old_item->ItemSequenceNumber());
  }
}

void DocumentLoader::BodyDataReceived(base::span<const char> data) {
  EncodedBodyData body_data(data);
  BodyDataReceivedImpl(body_data);
}

void DocumentLoader::DecodedBodyDataReceived(
    const WebString& data,
    const WebEncodingData& encoding_data,
    base::SpanOrSize<const char> encoded_data) {
  // Decoding has already happened, we don't need the decoder anymore.
  parser_->SetDecoder(nullptr);
  DecodedBodyData body_data(data, DocumentEncodingData(encoding_data),
                            encoded_data);
  BodyDataReceivedImpl(body_data);
}

DocumentLoader::ProcessBackgroundDataCallback
DocumentLoader::TakeProcessBackgroundDataCallback() {
  auto callback = parser_->TakeBackgroundScanCallback();
  if (!callback)
    return ProcessBackgroundDataCallback();
  return CrossThreadBindRepeating(
      [](const DocumentParser::BackgroundScanCallback& callback,
         const WebString& data) { callback.Run(data); },
      std::move(callback));
}

void DocumentLoader::BodyDataReceivedImpl(BodyData& data) {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::BodyDataReceivedImpl",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  base::SpanOrSize<const char> encoded_data = data.EncodedData();
  if (encoded_data.size()) {
    if (response_.WasFetchedViaServiceWorker()) {
      total_body_size_from_service_worker_ += encoded_data.size();
    }
    GetFrameLoader().Progress().IncrementProgress(main_resource_identifier_,
                                                  encoded_data.size());
    probe::DidReceiveData(probe::ToCoreProbeSink(GetFrame()),
                          main_resource_identifier_, this, encoded_data);
  }

  TRACE_EVENT_WITH_FLOW1("loading", "DocumentLoader::HandleData",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "length", encoded_data.size());

  DCHECK(!frame_->GetPage()->Paused());
  time_of_last_data_received_ = clock_->NowTicks();

  if (loading_main_document_from_mhtml_archive_) {
    // 1) Ftp directory listings accumulate data buffer and transform it later
    //    to the actual document content.
    // 2) Mhtml archives accumulate data buffer and parse it as mhtml later
    //    to retrieve the actual document content.
    data.Buffer(this);
    return;
  }

  ProcessDataBuffer(&data);
}

void DocumentLoader::BodyLoadingFinished(
    base::TimeTicks completion_time,
    int64_t total_encoded_data_length,
    int64_t total_encoded_body_length,
    int64_t total_decoded_body_length,
    const std::optional<WebURLError>& error) {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::BodyLoadingFinished",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

  DCHECK(frame_);
  if (!error) {
    GetFrameLoader().Progress().CompleteProgress(main_resource_identifier_);
    probe::DidFinishLoading(
        probe::ToCoreProbeSink(GetFrame()), main_resource_identifier_, this,
        completion_time, total_encoded_data_length, total_decoded_body_length);

    if (response_.WasFetchedViaServiceWorker()) {
      // See https://w3c.github.io/ServiceWorker/#dom-fetchevent-respondwith
      // in "chunk steps": there is no difference between encoded/decoded body
      // size, as encoding is handled inside the service worker.
      total_encoded_body_length = total_body_size_from_service_worker_;
      total_decoded_body_length = total_body_size_from_service_worker_;
    }

    DOMWindowPerformance::performance(*frame_->DomWindow())
        ->OnBodyLoadFinished(total_encoded_body_length,
                             total_decoded_body_length);

    if (resource_timing_info_for_parent_) {
      // Note that we already checked for Timing-Allow-Origin, otherwise we
      // wouldn't have a resource_timing_info_for_parent_ in the first place
      // and we would resort to fallback timing.
      if (!RuntimeEnabledFeatures::ResourceTimingUseCORSForBodySizesEnabled() ||
          (IsSameOriginInitiator() &&
           !document_load_timing_.HasCrossOriginRedirect())) {
        resource_timing_info_for_parent_->encoded_body_size =
            total_encoded_body_length;
        resource_timing_info_for_parent_->decoded_body_size =
            total_decoded_body_length;
      }

      // Note that we currently lose timing info for empty documents,
      // which will be fixed with synchronous commit.
      // Main resource timing information is reported through the owner
      // to be passed to the parent frame, if appropriate.
      resource_timing_info_for_parent_->response_end = completion_time;
      frame_->Owner()->AddResourceTiming(
          std::move(resource_timing_info_for_parent_));
    }
    FinishedLoading(completion_time);
    return;
  }

  ResourceError resource_error(*error);
  if (network_utils::IsCertificateTransparencyRequiredError(
          resource_error.ErrorCode())) {
    CountUse(WebFeature::kCertificateTransparencyRequiredErrorOnResourceLoad);
  }
  GetFrameLoader().Progress().CompleteProgress(main_resource_identifier_);
  probe::DidFailLoading(probe::ToCoreProbeSink(GetFrame()),
                        main_resource_identifier_, this, resource_error,
                        frame_->GetDevToolsFrameToken());
  GetFrame()->Console().DidFailLoading(this, main_resource_identifier_,
                                       resource_error);
  LoadFailed(resource_error);
}

void DocumentLoader::LoadFailed(const ResourceError& error) {
  TRACE_EVENT1("navigation,rail", "DocumentLoader::LoadFailed", "error",
               error.ErrorCode());
  body_loader_.reset();
  virtual_time_pauser_.UnpauseVirtualTime();

  // `LoadFailed()` should never be called for a navigation failure in a frame
  // owned by <object>. Browser-side navigation must handle these (whether
  // network errors, blocked by CSP/XFO, or otherwise) and never delegate to the
  // renderer.
  //
  // `LoadFailed()` *can* be called for a frame owned by <object> if the
  // navigation body load is cancelled, e.g.:
  // - `StartLoadingResponse()` calls `StopLoading()` when loading a
  //   `MediaDocument`.
  // - `LocalFrame::Detach()` calls `StopLoading()`.
  // - `window.stop()` calls `StopAllLoaders()` which calls `StopLoading()`.
  DCHECK(!IsA<HTMLObjectElement>(frame_->Owner()) || error.IsCancellation());

  WebHistoryCommitType history_commit_type = LoadTypeToCommitType(load_type_);
  DCHECK_EQ(kCommitted, state_);
  if (frame_->GetDocument()->Parser())
    frame_->GetDocument()->Parser()->StopParsing();
  state_ = kSentDidFinishLoad;
  GetLocalFrameClient().DispatchDidFailLoad(error, history_commit_type);
  GetFrameLoader().DidFinishNavigation(
      FrameLoader::NavigationFinishState::kFailure);
  DCHECK_EQ(kSentDidFinishLoad, state_);
  params_ = nullptr;
}

void DocumentLoader::FinishedLoading(base::TimeTicks finish_time) {
  TRACE_EVENT_WITH_FLOW0("loading", "DocumentLoader::FinishedLoading",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  body_loader_.reset();
  virtual_time_pauser_.UnpauseVirtualTime();

  DCHECK(commit_reason_ == CommitReason::kInitialization ||
         !frame_->GetPage()->Paused() ||
         MainThreadDebugge
"""


```
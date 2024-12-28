Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_local_frame_impl.cc`. I need to identify the key actions and responsibilities of this code. Specifically, I should look for interactions with:

*   **Frame creation and management:**  Creating fenced frames, getting frame objects.
*   **Rendering and display:** Handling content size changes, managing DevTools overlays, creating the frame view.
*   **Navigation and loading:** Committing navigations, handling load states, managing provisional loads.
*   **User interaction:** Hit testing, context menus, input method controller.
*   **Developer tools:**  Integration with DevTools.
*   **Security and isolation:**  Handling fenced frames, setting origins.
*   **Performance optimization:**  Warming up the compositor.
*   **JavaScript interaction (indirect):**  The code manages the frame, which hosts JavaScript.
*   **HTML and CSS interaction (indirect):** The frame displays HTML and styles it with CSS.

I will go through each method and identify its purpose. Then I will group them by functionality and provide examples if the functionality relates to JavaScript, HTML, or CSS.
这是 `blink/renderer/core/frame/web_local_frame_impl.cc` 文件代码片段的第四部分，主要负责以下功能：

**1. 创建和管理 Fenced Frames (隔离的帧):**

*   `CreateFencedFrame(mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame> receiver, std::unique_ptr<blink::ReplicatedCrossOriginOpenerPolicy> initial_replicated_state, scoped_refptr< blink::FencedFrameURLMapping> fenced_frame)`:  此函数用于创建一个隔离的 fenced frame。它创建了必要的 Mojo 接口用于与浏览器进程通信，并通知父 frame 创建一个 fenced frame。
    *   **与 HTML 的关系:** Fenced frames 是 HTML 的一个特性，用于嵌入独立的、隔离的内容。这个函数负责在渲染器进程中创建和初始化这样的帧。
    *   **假设输入:** 一个用于接收 `RemoteFrame` 接口的 `receiver`，一个描述初始跨域策略的 `initial_replicated_state`，以及一个 `fenced_frame` 对象，其中可能包含有关要加载的 URL 的信息。
    *   **假设输出:** 返回新创建的 `WebRemoteFrameImpl` 关联的 `WebFrame*`。

**2. 跟踪内容大小变化:**

*   `DidChangeContentsSize(const gfx::Size& size)`: 当 frame 的内容大小发生变化时被调用。当前实现中，如果启用了文本查找且有匹配项，则会增加查找标记的版本，可能用于更新查找高亮显示。
    *   **与 HTML/CSS/JavaScript 的关系:**  HTML 内容的增加或删除，CSS 样式的变化（例如，改变字体大小或元素尺寸），以及 JavaScript 对 DOM 的操作都可能导致内容大小变化。

**3. 管理 DevTools 覆盖层:**

*   `HasDevToolsOverlays() const`: 检查是否启用了 DevTools 覆盖层。
*   `UpdateDevToolsOverlaysPrePaint()`: 在绘制前更新 DevTools 覆盖层的信息。
*   `PaintDevToolsOverlays(GraphicsContext& context)`: 在指定的图形上下文中绘制 DevTools 覆盖层。
    *   **与 JavaScript/HTML/CSS 的关系:** DevTools 覆盖层可以用于高亮显示 DOM 元素、显示布局信息、调试 CSS 样式等，这些都与页面的 HTML 结构、CSS 样式和 JavaScript 行为密切相关。

**4. 创建 FrameView:**

*   `CreateFrameView()`: 创建与 `WebLocalFrameImpl` 关联的 `FrameView` 对象，负责内容的布局和渲染。
    *   **与 HTML/CSS 的关系:** `FrameView` 基于 HTML 结构和 CSS 样式来计算元素的位置和大小，并最终呈现到屏幕上。

**5. 从 LocalFrame 获取 WebLocalFrameImpl:**

*   多个 `FromFrame` 重载函数，用于在 `LocalFrame` 和 `WebLocalFrameImpl` 之间进行转换。这是 Blink 内部在不同抽象层之间进行交互的常见模式。

**6. 预渲染优化 (Compositor Warm-up):**

*   `ShouldWarmUpCompositorOnPrerenderFromThisPoint(...)`:  判断是否应该在预渲染期间预热 Compositor，以提高后续页面加载的性能。
*   `DidCommitLoad()`, `DidDispatchDOMContentLoadedEvent()`, `DidFinish()`: 在不同的页面加载阶段，如果满足预渲染条件，则会触发 Compositor 预热。
    *   **性能优化:**  Compositor 负责页面的合成和绘制，预热可以减少首次渲染的时间。

**7. 处理加载失败:**

*   `DidFailLoad(const ResourceError& error, WebHistoryCommitType web_commit_type)`: 当页面加载失败时调用，通知插件 (如果存在) 和远程的 FrameHost。

**8. 处理加载完成:**

*   `DidFinish()`: 当页面加载完成时调用，通知插件 (如果存在) 和客户端。
*   `DidFinishLoadForPrinting()`: 当为打印完成加载时调用，通知客户端。

**9. 命中测试 (Hit Testing):**

*   `HitTestResultForVisualViewportPos(const gfx::Point& pos_in_viewport)`:  在可视视口中的指定位置执行命中测试，确定该位置下的元素。
    *   **与 HTML/CSS/JavaScript 的关系:** 命中测试用于确定用户点击或触摸屏幕上的哪个 HTML 元素，这对于事件处理 (JavaScript) 和样式应用 (CSS) 非常重要。
    *   **假设输入:**  可视视口中的一个 `gfx::Point`。
    *   **假设输出:**  一个 `HitTestResult` 对象，包含有关被命中的元素的信息。

**10. 设置和获取 Autofill 客户端:**

*   `SetAutofillClient(WebAutofillClient* autofill_client)`
*   `AutofillClient()`
    *   **与 HTML 的关系:** Autofill 用于自动填充 HTML 表单字段。

**11. 设置和获取 Content Capture 客户端:**

*   `SetContentCaptureClient(WebContentCaptureClient* content_capture_client)`
*   `ContentCaptureClient() const`
    *   **与 HTML 的关系:** Content Capture 可能用于分析和提取 HTML 页面中的内容。

**12. 判断是否为 Provisional Frame:**

*   `IsProvisional() const`:  判断当前 frame 是否是临时的 (provisional)，通常在页面导航期间创建。

**13. 获取 Local Root Frame:**

*   `LocalRoot()`: 获取当前 frame 树的根 frame。

**14. 通过名称查找 Frame:**

*   `FindFrameByName(const WebString& name)`:  在 frame 树中查找具有指定名称的 frame。
    *   **与 HTML 的关系:** HTML `<iframe>` 标签可以设置 `name` 属性。

**15. 设置 Embedding Token:**

*   `SetEmbeddingToken(const base::UnguessableToken& embedding_token)`: 设置用于标识 frame 嵌入上下文的 token。

**16. 判断是否在 Fenced Frame 树中:**

*   `IsInFencedFrameTree() const`: 判断当前 frame 是否属于 fenced frame 树。

**17. 获取 Embedding Token:**

*   `GetEmbeddingToken() const`: 获取当前 frame 的 embedding token。

**18. 发送 Ping:**

*   `SendPings(const WebURL& destination_url)`:  发送 HTML `<a>` 标签中定义的 ping。
    *   **与 HTML 的关系:**  `<a ping="...">` 属性用于在用户点击链接时向服务器发送通知。

**19. 处理 BeforeUnload 事件:**

*   `DispatchBeforeUnloadEvent(bool is_reload)`:  分发 `beforeunload` 事件，允许页面在即将卸载时执行一些清理操作或提示用户。
    *   **与 JavaScript 的关系:**  `beforeunload` 是一个 JavaScript 事件。
    *   **假设输入:** 一个布尔值 `is_reload`，指示是否为页面重载。
    *   **假设输出:** 一个布尔值，指示是否允许页面卸载（`true` 表示允许）。
    *   **用户常见错误:**  在 `beforeunload` 事件处理程序中执行耗时的同步操作可能会导致浏览器无响应。

**20. 提交导航:**

*   `CommitNavigation(std::unique_ptr<WebNavigationParams> navigation_params, std::unique_ptr<WebDocumentLoader::ExtraData> extra_data)`:  提交一个主文档导航。
    *   **与 JavaScript/HTML 的关系:** 当用户点击链接、提交表单或 JavaScript 代码触发页面跳转时会发生导航。
    *   **假设输入:**  包含导航参数的 `WebNavigationParams` 对象和额外的 `WebDocumentLoader::ExtraData`。
    *   **用户常见错误:**  在 JavaScript 中使用不正确的 URL 或试图导航到不允许访问的资源。

*   `CommitSameDocumentNavigation(const WebURL& url, WebFrameLoadType web_frame_load_type, const WebHistoryItem& item, bool is_client_redirect, bool has_transient_user_activation, const WebSecurityOrigin& initiator_origin, bool is_browser_initiated, bool has_ua_visual_transition, std::optional<scheduler::TaskAttributionId> soft_navigation_heuristics_task_id)`: 提交一个同文档导航 (例如，hashchange)。
    *   **与 JavaScript 的关系:**  同文档导航通常由 JavaScript 操作 URL 的 hash 部分触发。

**归纳一下它的功能:**

这段代码是 `WebLocalFrameImpl` 的一部分，负责管理和控制渲染器进程中的一个本地 frame 的生命周期和行为。它处理 frame 的创建、加载、渲染、用户交互以及与浏览器进程和 DevTools 的通信。它连接了 Blink 渲染引擎的核心概念 (如 `LocalFrame`, `Document`) 和 Chromium 的 Web API (以 `Web` 开头的类)。 这部分代码特别关注 fenced frame 的创建，DevTools 的集成，以及页面加载的不同阶段的事件处理和优化。它还处理了与导航相关的操作，包括主文档导航和同文档导航。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_local_frame_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
_replicated_state->origin = SecurityOrigin::CreateUniqueOpaque();
  RemoteFrameToken frame_token;
  base::UnguessableToken devtools_frame_token =
      base::UnguessableToken::Create();
  auto remote_frame_interfaces =
      mojom::blink::RemoteFrameInterfacesFromRenderer::New();
  mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>
      remote_frame_host = remote_frame_interfaces->frame_host_receiver
                              .InitWithNewEndpointAndPassRemote();
  mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame>
      remote_frame_receiver =
          remote_frame_interfaces->frame.InitWithNewEndpointAndPassReceiver();

  GetFrame()->GetLocalFrameHostRemote().CreateFencedFrame(
      std::move(receiver), std::move(remote_frame_interfaces), frame_token,
      devtools_frame_token);

  DCHECK(initial_replicated_state->origin->IsOpaque());

  WebRemoteFrameImpl* remote_frame = WebRemoteFrameImpl::CreateForFencedFrame(
      mojom::blink::TreeScopeType::kDocument, frame_token, devtools_frame_token,
      fenced_frame, std::move(remote_frame_host),
      std::move(remote_frame_receiver), std::move(initial_replicated_state));

  client_->DidCreateFencedFrame(frame_token);
  return remote_frame->GetFrame();
}

void WebLocalFrameImpl::DidChangeContentsSize(const gfx::Size& size) {
  if (GetTextFinder() && GetTextFinder()->TotalMatchCount() > 0)
    GetTextFinder()->IncreaseMarkerVersion();
}

bool WebLocalFrameImpl::HasDevToolsOverlays() const {
  return dev_tools_agent_ && dev_tools_agent_->HasOverlays();
}

void WebLocalFrameImpl::UpdateDevToolsOverlaysPrePaint() {
  if (dev_tools_agent_)
    dev_tools_agent_->UpdateOverlaysPrePaint();
}

void WebLocalFrameImpl::PaintDevToolsOverlays(GraphicsContext& context) {
  if (dev_tools_agent_)
    dev_tools_agent_->PaintOverlays(context);
}

void WebLocalFrameImpl::CreateFrameView() {
  TRACE_EVENT0("blink", "WebLocalFrameImpl::createFrameView");

  DCHECK(GetFrame());  // If frame() doesn't exist, we probably didn't init
                       // properly.

  WebViewImpl* web_view = ViewImpl();

  // Check if we're shutting down.
  if (!web_view->GetPage())
    return;

  bool is_main_frame = !Parent();
  // TODO(dcheng): Can this be better abstracted away? It's pretty ugly that
  // only local roots are special-cased here.
  gfx::Size initial_size = (is_main_frame || !frame_widget_)
                               ? web_view->MainFrameSize()
                               : frame_widget_->Size();
  Color base_background_color = web_view->BaseBackgroundColor();
  if (!is_main_frame && Parent()->IsWebRemoteFrame())
    base_background_color = Color::kTransparent;

  GetFrame()->CreateView(initial_size, base_background_color);
  if (web_view->ShouldAutoResize() && GetFrame()->IsLocalRoot()) {
    GetFrame()->View()->EnableAutoSizeMode(web_view->MinAutoSize(),
                                           web_view->MaxAutoSize());
  }

  if (frame_widget_)
    frame_widget_->DidCreateLocalRootView();
}

WebLocalFrameImpl* WebLocalFrameImpl::FromFrame(LocalFrame* frame) {
  if (!frame)
    return nullptr;
  return FromFrame(*frame);
}

std::string WebLocalFrameImpl::GetNullFrameReasonForBug1139104(
    LocalFrame* frame) {
  LocalFrameClient* client = frame->Client();
  if (!client)
    return "WebLocalFrameImpl::client";
  if (!client->IsLocalFrameClientImpl())
    return "WebLocalFrameImpl::client-not-local";
  WebLocalFrame* web_frame = client->GetWebFrame();
  if (!web_frame)
    return "WebLocalFrameImpl::web_frame";
  return "not-null";
}

WebLocalFrameImpl* WebLocalFrameImpl::FromFrame(LocalFrame& frame) {
  LocalFrameClient* client = frame.Client();
  if (!client || !client->IsLocalFrameClientImpl())
    return nullptr;
  return To<WebLocalFrameImpl>(client->GetWebFrame());
}

WebViewImpl* WebLocalFrameImpl::ViewImpl() const {
  if (!GetFrame())
    return nullptr;
  return GetFrame()->GetPage()->GetChromeClient().GetWebView();
}

bool WebLocalFrameImpl::ShouldWarmUpCompositorOnPrerenderFromThisPoint(
    features::Prerender2WarmUpCompositorTriggerPoint trigger_point) {
  static const bool is_warm_up_compositor_enabled =
      base::FeatureList::IsEnabled(::features::kWarmUpCompositor);
  if (!is_warm_up_compositor_enabled) {
    return false;
  }

  if (!GetFrame()->IsOutermostMainFrame()) {
    return false;
  }

  if (!GetFrame()->GetPage() || !GetFrame()->GetPage()->IsPrerendering() ||
      !GetFrame()->GetPage()->ShouldWarmUpCompositorOnPrerender()) {
    return false;
  }

  static const bool is_prerender2_warm_up_compositor_enabled =
      base::FeatureList::IsEnabled(features::kPrerender2WarmUpCompositor);
  // TODO(crbug.com/41496019): Seek the best point to start warm-up.
  static const auto prerender2_warm_up_compositor_trigger_point =
      features::kPrerender2WarmUpCompositorTriggerPoint.Get();
  if (!is_prerender2_warm_up_compositor_enabled ||
      prerender2_warm_up_compositor_trigger_point != trigger_point) {
    return false;
  }

  return true;
}

void WebLocalFrameImpl::DidCommitLoad() {
  if (frame_widget_ &&
      ShouldWarmUpCompositorOnPrerenderFromThisPoint(
          features::Prerender2WarmUpCompositorTriggerPoint::kDidCommitLoad)) {
    frame_widget_->WarmUpCompositor();
  }
}

void WebLocalFrameImpl::DidDispatchDOMContentLoadedEvent() {
  if (frame_widget_ && ShouldWarmUpCompositorOnPrerenderFromThisPoint(
                           features::Prerender2WarmUpCompositorTriggerPoint::
                               kDidDispatchDOMContentLoadedEvent)) {
    frame_widget_->WarmUpCompositor();
  }
}

void WebLocalFrameImpl::DidFailLoad(const ResourceError& error,
                                    WebHistoryCommitType web_commit_type) {
  if (WebPluginContainerImpl* plugin = GetFrame()->GetWebPluginContainer())
    plugin->DidFailLoading(error);
  WebDocumentLoader* document_loader = GetDocumentLoader();
  DCHECK(document_loader);
  GetFrame()->GetLocalFrameHostRemote().DidFailLoadWithError(
      document_loader->GetUrl(), error.ErrorCode());
}

void WebLocalFrameImpl::DidFinish() {
  if (!Client())
    return;

  if (frame_widget_ &&
      ShouldWarmUpCompositorOnPrerenderFromThisPoint(
          features::Prerender2WarmUpCompositorTriggerPoint::kDidFinishLoad)) {
    frame_widget_->WarmUpCompositor();
  }

  if (WebPluginContainerImpl* plugin = GetFrame()->GetWebPluginContainer())
    plugin->DidFinishLoading();

  Client()->DidFinishLoad();
}

void WebLocalFrameImpl::DidFinishLoadForPrinting() {
  Client()->DidFinishLoadForPrinting();
}

HitTestResult WebLocalFrameImpl::HitTestResultForVisualViewportPos(
    const gfx::Point& pos_in_viewport) {
  gfx::Point root_frame_point(
      GetFrame()->GetPage()->GetVisualViewport().ViewportToRootFrame(
          pos_in_viewport));
  HitTestLocation location(
      GetFrame()->View()->ConvertFromRootFrame(root_frame_point));
  HitTestResult result = GetFrame()->GetEventHandler().HitTestResultAtLocation(
      location, HitTestRequest::kReadOnly | HitTestRequest::kActive);
  result.SetToShadowHostIfInUAShadowRoot();
  return result;
}

void WebLocalFrameImpl::SetAutofillClient(WebAutofillClient* autofill_client) {
  autofill_client_ = autofill_client;
}

WebAutofillClient* WebLocalFrameImpl::AutofillClient() {
  return autofill_client_;
}

void WebLocalFrameImpl::SetContentCaptureClient(
    WebContentCaptureClient* content_capture_client) {
  content_capture_client_ = content_capture_client;
}

WebContentCaptureClient* WebLocalFrameImpl::ContentCaptureClient() const {
  return content_capture_client_;
}

bool WebLocalFrameImpl::IsProvisional() const {
  return frame_->IsProvisional();
}

WebLocalFrameImpl* WebLocalFrameImpl::LocalRoot() {
  DCHECK(GetFrame());
  auto* result = FromFrame(GetFrame()->LocalFrameRoot());
  DCHECK(result);
  return result;
}

WebFrame* WebLocalFrameImpl::FindFrameByName(const WebString& name) {
  return WebFrame::FromCoreFrame(GetFrame()->Tree().FindFrameByName(name));
}

void WebLocalFrameImpl::SetEmbeddingToken(
    const base::UnguessableToken& embedding_token) {
  frame_->SetEmbeddingToken(embedding_token);
}

bool WebLocalFrameImpl::IsInFencedFrameTree() const {
  bool result = frame_->IsInFencedFrameTree();
  DCHECK(!result || blink::features::IsFencedFramesEnabled());
  return result;
}

const std::optional<base::UnguessableToken>&
WebLocalFrameImpl::GetEmbeddingToken() const {
  return frame_->GetEmbeddingToken();
}

void WebLocalFrameImpl::SendPings(const WebURL& destination_url) {
  DCHECK(GetFrame());
  if (Node* node = ContextMenuNodeInner()) {
    Element* anchor = node->EnclosingLinkEventParentOrSelf();
    // TODO(crbug.com/369219144): Should this be
    // DynamicTo<HTMLAnchorElementBase>?
    if (auto* html_anchor = DynamicTo<HTMLAnchorElement>(anchor))
      html_anchor->SendPings(destination_url);
  }
}

bool WebLocalFrameImpl::DispatchBeforeUnloadEvent(bool is_reload) {
  if (!GetFrame())
    return true;

  return GetFrame()->Loader().ShouldClose(is_reload);
}

void WebLocalFrameImpl::CommitNavigation(
    std::unique_ptr<WebNavigationParams> navigation_params,
    std::unique_ptr<WebDocumentLoader::ExtraData> extra_data) {
  DCHECK(GetFrame());
  DCHECK(!navigation_params->url.ProtocolIs("javascript"));
  if (navigation_params->is_synchronous_commit_for_bug_778318) {
    DCHECK(WebDocumentLoader::WillLoadUrlAsEmpty(navigation_params->url));
    navigation_params->storage_key = GetFrame()->DomWindow()->GetStorageKey();
    navigation_params->document_ukm_source_id =
        GetFrame()->DomWindow()->UkmSourceID();

    // This corresponds to step 8 of
    // https://html.spec.whatwg.org/multipage/browsers.html#creating-a-new-browsing-context.
    // Most of these steps are handled in the caller
    // (RenderFrameImpl::SynchronouslyCommitAboutBlankForBug778318) but the
    // caller doesn't have access to the core frame (LocalFrame).
    // The actual agent is determined downstream, but here we need to request
    // whether an origin-keyed agent is needed. Since this case is only
    // for about:blank navigations this reduces to copying the agent flag from
    // the current document.
    navigation_params->origin_agent_cluster =
        GetFrame()->GetDocument()->GetAgent().IsOriginKeyedForInheritance();

    KURL url = navigation_params->url;
    if (navigation_params->is_synchronous_commit_for_bug_778318 &&
        // Explicitly check for about:blank or about:srcdoc to prevent things
        // like about:mumble propagating the base url.
        (url.IsAboutBlankURL() || url.IsAboutSrcdocURL())) {
      navigation_params->fallback_base_url =
          GetFrame()->GetDocument()->BaseURL();
    }
  }
  if (GetTextFinder())
    GetTextFinder()->ClearActiveFindMatch();
  GetFrame()->Loader().CommitNavigation(std::move(navigation_params),
                                        std::move(extra_data));
}

blink::mojom::CommitResult WebLocalFrameImpl::CommitSameDocumentNavigation(
    const WebURL& url,
    WebFrameLoadType web_frame_load_type,
    const WebHistoryItem& item,
    bool is_client_redirect,
    bool has_transient_user_activation,
    const WebSecurityOrigin& initiator_origin,
    bool is_browser_initiated,
    bool has_ua_visual_transition,
    std::optional<scheduler::TaskAttributionId>
        soft_navigation_heuristics_task_id) {
  DCHECK(GetFrame());
  DCHECK(!url.ProtocolIs("javascript"));

  HistoryItem* history_item = item;
  return GetFrame()->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      url, web_frame_load_type, history_item,
      is_client_redirect ? ClientRedirectPolicy::kClientRedirect
                         : ClientRedirectPolicy::kNotClientRedirect,
      has_transient_user_activation, initiator_origin.Get(),
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent, is_browser_initiated,
      has_ua_visual_transition, soft_navigation_heuristics_task_id);
}

bool WebLocalFrameImpl::IsLoading() const {
  if (!GetFrame() || !GetFrame()->GetDocument())
    return false;
  return GetFrame()->GetDocument()->IsInitialEmptyDocument() ||
         GetFrame()->Loader().HasProvisionalNavigation() ||
         !GetFrame()->GetDocument()->LoadEventFinished();
}

bool WebLocalFrameImpl::IsNavigationScheduledWithin(
    base::TimeDelta interval) const {
  if (!GetFrame())
    return false;
  return GetFrame()->Loader().HasProvisionalNavigation() ||
         GetFrame()->GetDocument()->IsHttpRefreshScheduledWithin(interval);
}

void WebLocalFrameImpl::SetIsNotOnInitialEmptyDocument() {
  DCHECK(GetFrame());
  GetFrame()->GetDocument()->OverrideIsInitialEmptyDocument();
  GetFrame()->Loader().SetIsNotOnInitialEmptyDocument();
}

bool WebLocalFrameImpl::IsOnInitialEmptyDocument() {
  DCHECK(GetFrame());
  return GetFrame()->GetDocument()->IsInitialEmptyDocument();
}

void WebLocalFrameImpl::BlinkFeatureUsageReport(
    blink::mojom::WebFeature feature) {
  UseCounter::Count(GetFrame()->GetDocument(), feature);
}

void WebLocalFrameImpl::DidDropNavigation() {
  GetFrame()->Loader().DidDropNavigation();
}

void WebLocalFrameImpl::DownloadURL(
    const WebURLRequest& request,
    network::mojom::blink::RedirectMode cross_origin_redirect_behavior,
    CrossVariantMojoRemote<mojom::blink::BlobURLTokenInterfaceBase>
        blob_url_token) {
  GetFrame()->DownloadURL(request.ToResourceRequest(),
                          cross_origin_redirect_behavior,
                          std::move(blob_url_token));
}

WebFrame* WebLocalFrameImpl::GetProvisionalOwnerFrame() {
  return GetFrame()->IsProvisional()
             ? WebFrame::FromCoreFrame(GetFrame()->GetProvisionalOwnerFrame())
             : nullptr;
}

void WebLocalFrameImpl::MaybeStartOutermostMainFrameNavigation(
    const WebVector<WebURL>& urls) const {
  Vector<KURL> kurls;
  std::move(urls.begin(), urls.end(), std::back_inserter(kurls));
  GetFrame()->MaybeStartOutermostMainFrameNavigation(std::move(kurls));
}

bool WebLocalFrameImpl::WillStartNavigation(const WebNavigationInfo& info) {
  DCHECK(!info.url_request.IsNull());
  DCHECK(!info.url_request.Url().ProtocolIs("javascript"));
  return GetFrame()->Loader().WillStartNavigation(info);
}

void WebLocalFrameImpl::SendOrientationChangeEvent() {
  // Speculative fix for https://crbug.com/1143380.
  // TODO(https://crbug.com/838348): It's a logic bug that this function is
  // being called when either the LocalFrame or LocalDOMWindow are null, but
  // there is a bug where the browser can inadvertently detach the main frame of
  // a WebView that is still active.
  if (!GetFrame() || !GetFrame()->DomWindow())
    return;

  // Screen Orientation API
  CoreInitializer::GetInstance().NotifyOrientationChanged(*GetFrame());

  // Legacy window.orientation API
  if (RuntimeEnabledFeatures::OrientationEventEnabled())
    GetFrame()->DomWindow()->SendOrientationChangeEvent();
}

WebNode WebLocalFrameImpl::ContextMenuNode() const {
  return ContextMenuNodeInner();
}

WebNode WebLocalFrameImpl::ContextMenuImageNode() const {
  return ContextMenuImageNodeInner();
}

void WebLocalFrameImpl::WillBeDetached() {
  if (frame_->IsMainFrame())
    ViewImpl()->DidDetachLocalMainFrame();
  if (dev_tools_agent_)
    dev_tools_agent_->WillBeDestroyed();
  if (find_in_page_)
    find_in_page_->Dispose();
  if (print_client_)
    print_client_->WillBeDestroyed();

  for (auto& observer : observers_)
    observer.WebLocalFrameDetached();
}

void WebLocalFrameImpl::WillDetachParent() {
  // Do not expect string scoping results from any frames that got detached
  // in the middle of the operation.
  if (GetTextFinder() && GetTextFinder()->ScopingInProgress()) {
    // There is a possibility that the frame being detached was the only
    // pending one. We need to make sure final replies can be sent.
    GetTextFinder()->FlushCurrentScoping();

    GetTextFinder()->CancelPendingScopingEffort();
  }
}

void WebLocalFrameImpl::CreateFrameWidgetInternal(
    base::PassKey<WebLocalFrame> pass_key,
    CrossVariantMojoAssociatedRemote<mojom::blink::FrameWidgetHostInterfaceBase>
        mojo_frame_widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::FrameWidgetInterfaceBase>
        mojo_frame_widget,
    CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
        mojo_widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
        mojo_widget,
    const viz::FrameSinkId& frame_sink_id,
    bool is_for_nested_main_frame,
    bool is_for_scalable_page,
    bool hidden) {
  DCHECK(!frame_widget_);
  DCHECK(frame_->IsLocalRoot());
  bool is_for_child_local_root = Parent();

  // Check that if this is for a child local root |is_for_nested_main_frame|
  // is false.
  DCHECK(!is_for_child_local_root || !is_for_nested_main_frame);

  bool never_composited = ViewImpl()->widgets_never_composited();

  if (g_create_web_frame_widget) {
    // It is safe to cast to WebFrameWidgetImpl because the only concrete
    // subclass of WebFrameWidget that is allowed is WebFrameWidgetImpl. This
    // is enforced via a private constructor (and friend class) on
    // WebFrameWidget.
    frame_widget_ =
        static_cast<WebFrameWidgetImpl*>(g_create_web_frame_widget->Run(
            std::move(pass_key), std::move(mojo_frame_widget_host),
            std::move(mojo_frame_widget), std::move(mojo_widget_host),
            std::move(mojo_widget),
            Scheduler()->GetAgentGroupScheduler()->DefaultTaskRunner(),
            frame_sink_id, hidden, never_composited, is_for_child_local_root,
            is_for_nested_main_frame, is_for_scalable_page));
  } else {
    frame_widget_ = MakeGarbageCollected<WebFrameWidgetImpl>(
        std::move(pass_key), std::move(mojo_frame_widget_host),
        std::move(mojo_frame_widget), std::move(mojo_widget_host),
        std::move(mojo_widget),
        Scheduler()->GetAgentGroupScheduler()->DefaultTaskRunner(),
        frame_sink_id, hidden, never_composited, is_for_child_local_root,
        is_for_nested_main_frame, is_for_scalable_page);
  }
  frame_widget_->BindLocalRoot(*this);

  // If this is for a main frame grab the associated WebViewImpl and
  // assign this widget as the main frame widget.
  // Note: this can't DCHECK that the view's main frame points to
  // |this|, as provisional frames violate this precondition.
  if (!is_for_child_local_root) {
    DCHECK(ViewImpl());
    ViewImpl()->SetMainFrameViewWidget(frame_widget_);
  }
}

WebFrameWidget* WebLocalFrameImpl::FrameWidget() const {
  return frame_widget_.Get();
}

void WebLocalFrameImpl::CopyImageAtForTesting(
    const gfx::Point& pos_in_viewport) {
  GetFrame()->CopyImageAtViewportPoint(pos_in_viewport);
}

void WebLocalFrameImpl::ShowContextMenuFromExternal(
    const UntrustworthyContextMenuParams& params,
    CrossVariantMojoAssociatedRemote<
        mojom::blink::ContextMenuClientInterfaceBase> context_menu_client) {
  GetFrame()->GetLocalFrameHostRemote().ShowContextMenu(
      std::move(context_menu_client), params);
}

void WebLocalFrameImpl::ShowContextMenu(
    mojo::PendingAssociatedRemote<mojom::blink::ContextMenuClient> client,
    const blink::ContextMenuData& data,
    const std::optional<gfx::Point>& host_context_menu_location) {
  UntrustworthyContextMenuParams params =
      blink::ContextMenuParamsBuilder::Build(data);
  if (host_context_menu_location.has_value()) {
    // If the context menu request came from the browser, it came with a
    // position that was stored on blink::WebFrameWidgetImpl and is relative to
    // the WindowScreenRect.
    params.x = host_context_menu_location.value().x();
    params.y = host_context_menu_location.value().y();
  } else {
    // If the context menu request came from the renderer, the position in
    // |params| is real, but they come in blink viewport coordinates, which
    // include the device scale factor, but not emulation scale. Here we convert
    // them to DIP coordinates relative to the WindowScreenRect.
    // TODO(crbug.com/1093904): This essentially is a floor of the coordinates.
    // Determine if rounding is more appropriate.
    gfx::Rect position_in_dips =
        LocalRootFrameWidget()->BlinkSpaceToEnclosedDIPs(
            gfx::Rect(params.x, params.y, 0, 0));

    const float scale = LocalRootFrameWidget()->GetEmulatorScale();
    params.x = position_in_dips.x() * scale;
    params.y = position_in_dips.y() * scale;
  }

  // Serializing a GURL longer than kMaxURLChars will fail, so don't do
  // it.  We replace it with an empty GURL so the appropriate items are disabled
  // in the context menu.
  // TODO(jcivelli): http://crbug.com/45160 This prevents us from saving large
  //                 data encoded images.  We should have a way to save them.
  if (params.src_url.spec().size() > url::kMaxURLChars)
    params.src_url = GURL();

  params.selection_rect =
      LocalRootFrameWidget()->BlinkSpaceToEnclosedDIPs(data.selection_rect);

  if (!GetFrame())
    return;
  GetFrame()->GetLocalFrameHostRemote().ShowContextMenu(std::move(client),
                                                        params);

  if (Client())
    Client()->UpdateContextMenuDataForTesting(data, host_context_menu_location);
}

bool WebLocalFrameImpl::IsAllowedToDownload() const {
  if (!GetFrame())
    return true;

  return (GetFrame()->Loader().PendingEffectiveSandboxFlags() &
          network::mojom::blink::WebSandboxFlags::kDownloads) ==
         network::mojom::blink::WebSandboxFlags::kNone;
}

bool WebLocalFrameImpl::IsCrossOriginToOutermostMainFrame() const {
  return GetFrame()->IsCrossOriginToOutermostMainFrame();
}

void WebLocalFrameImpl::UsageCountChromeLoadTimes(const WebString& metric) {
  WebFeature feature = WebFeature::kChromeLoadTimesUnknown;
  if (metric == "requestTime") {
    feature = WebFeature::kChromeLoadTimesRequestTime;
  } else if (metric == "startLoadTime") {
    feature = WebFeature::kChromeLoadTimesStartLoadTime;
  } else if (metric == "commitLoadTime") {
    feature = WebFeature::kChromeLoadTimesCommitLoadTime;
  } else if (metric == "finishDocumentLoadTime") {
    feature = WebFeature::kChromeLoadTimesFinishDocumentLoadTime;
  } else if (metric == "finishLoadTime") {
    feature = WebFeature::kChromeLoadTimesFinishLoadTime;
  } else if (metric == "firstPaintTime") {
    feature = WebFeature::kChromeLoadTimesFirstPaintTime;
  } else if (metric == "firstPaintAfterLoadTime") {
    feature = WebFeature::kChromeLoadTimesFirstPaintAfterLoadTime;
  } else if (metric == "navigationType") {
    feature = WebFeature::kChromeLoadTimesNavigationType;
  } else if (metric == "wasFetchedViaSpdy") {
    feature = WebFeature::kChromeLoadTimesWasFetchedViaSpdy;
  } else if (metric == "wasNpnNegotiated") {
    feature = WebFeature::kChromeLoadTimesWasNpnNegotiated;
  } else if (metric == "npnNegotiatedProtocol") {
    feature = WebFeature::kChromeLoadTimesNpnNegotiatedProtocol;
  } else if (metric == "wasAlternateProtocolAvailable") {
    feature = WebFeature::kChromeLoadTimesWasAlternateProtocolAvailable;
  } else if (metric == "connectionInfo") {
    feature = WebFeature::kChromeLoadTimesConnectionInfo;
  }
  Deprecation::CountDeprecation(GetFrame()->DomWindow(), feature);
}

void WebLocalFrameImpl::UsageCountChromeCSI(const WebString& metric) {
  CHECK(GetFrame());
  WebFeature feature = WebFeature::kChromeCSIUnknown;
  if (metric == "onloadT") {
    feature = WebFeature::kChromeCSIOnloadT;
  } else if (metric == "pageT") {
    feature = WebFeature::kChromeCSIPageT;
  } else if (metric == "startE") {
    feature = WebFeature::kChromeCSIStartE;
  } else if (metric == "tran") {
    feature = WebFeature::kChromeCSITran;
  }
  GetFrame()->DomWindow()->CountUse(feature);
}

FrameScheduler* WebLocalFrameImpl::Scheduler() const {
  return GetFrame()->GetFrameScheduler();
}

scheduler::WebAgentGroupScheduler* WebLocalFrameImpl::GetAgentGroupScheduler()
    const {
  return &ViewImpl()->GetWebAgentGroupScheduler();
}

scoped_refptr<base::SingleThreadTaskRunner> WebLocalFrameImpl::GetTaskRunner(
    TaskType task_type) {
  return GetFrame()->GetTaskRunner(task_type);
}

WebInputMethodController* WebLocalFrameImpl::GetInputMethodController() {
  return &input_method_controller_;
}

bool WebLocalFrameImpl::ShouldSuppressKeyboardForFocusedElement() {
  if (!autofill_client_)
    return false;

  DCHECK(GetFrame()->GetDocument());
  auto* focused_form_control_element = DynamicTo<HTMLFormControlElement>(
      GetFrame()->GetDocument()->FocusedElement());
  return focused_form_control_element &&
         autofill_client_->ShouldSuppressKeyboard(focused_form_control_element);
}

void WebLocalFrameImpl::AddMessageToConsoleImpl(
    const WebConsoleMessage& message,
    bool discard_duplicates) {
  DCHECK(GetFrame());
  GetFrame()->GetDocument()->AddConsoleMessage(
      MakeGarbageCollected<ConsoleMessage>(message, GetFrame()),
      discard_duplicates);
}

// This is only triggered by test_runner.cc
void WebLocalFrameImpl::AddInspectorIssueImpl(
    mojom::blink::InspectorIssueCode code) {
  DCHECK(GetFrame());
  auto info = mojom::blink::InspectorIssueInfo::New(
      code, mojom::blink::InspectorIssueDetails::New());
  GetFrame()->AddInspectorIssue(
      AuditsIssue(ConvertInspectorIssueToProtocolFormat(
          InspectorIssue::Create(std::move(info)))));
}

void WebLocalFrameImpl::AddGenericIssueImpl(
    mojom::blink::GenericIssueErrorType error_type,
    int violating_node_id) {
  DCHECK(GetFrame());
  AuditsIssue::ReportGenericIssue(GetFrame(), error_type, violating_node_id);
}

void WebLocalFrameImpl::AddGenericIssueImpl(
    mojom::blink::GenericIssueErrorType error_type,
    int violating_node_id,
    const WebString& violating_node_attribute) {
  DCHECK(GetFrame());
  AuditsIssue::ReportGenericIssue(GetFrame(), error_type, violating_node_id,
                                  violating_node_attribute);
}

void WebLocalFrameImpl::SetTextCheckClient(
    WebTextCheckClient* text_check_client) {
  text_check_client_ = text_check_client;
}

void WebLocalFrameImpl::SetSpellCheckPanelHostClient(
    WebSpellCheckPanelHostClient* spell_check_panel_host_client) {
  spell_check_panel_host_client_ = spell_check_panel_host_client;
}

WebFrameWidgetImpl* WebLocalFrameImpl::LocalRootFrameWidget() {
  CHECK(LocalRoot());
  return LocalRoot()->FrameWidgetImpl();
}

Node* WebLocalFrameImpl::ContextMenuNodeInner() const {
  if (!ViewImpl() || !ViewImpl()->GetPage())
    return nullptr;
  return ViewImpl()
      ->GetPage()
      ->GetContextMenuController()
      .ContextMenuNodeForFrame(GetFrame());
}

Node* WebLocalFrameImpl::ContextMenuImageNodeInner() const {
  if (!ViewImpl() || !ViewImpl()->GetPage())
    return nullptr;
  return ViewImpl()
      ->GetPage()
      ->GetContextMenuController()
      .ContextMenuImageNodeForFrame(GetFrame());
}

void WebLocalFrameImpl::WaitForDebuggerWhenShown() {
  DCHECK(frame_->IsLocalRoot());
  DevToolsAgentImpl(/*create_if_necessary=*/true)->WaitForDebuggerWhenShown();
}

WebDevToolsAgentImpl* WebLocalFrameImpl::DevToolsAgentImpl(
    bool create_if_necessary) {
  if (!frame_->IsLocalRoot()) {
    return nullptr;
  }
  if (!dev_tools_agent_ && create_if_necessary) {
    dev_tools_agent_ = WebDevToolsAgentImpl::CreateForFrame(this);
  }
  return dev_tools_agent_.Get();
}

void WebLocalFrameImpl::WasHidden() {
  if (frame_)
    frame_->WasHidden();
}

void WebLocalFrameImpl::WasShown() {
  if (frame_)
    frame_->WasShown();
}

void WebLocalFrameImpl::SetAllowsCrossBrowsingInstanceFrameLookup() {
  DCHECK(GetFrame());

  // Allow the frame's security origin to access other SecurityOrigins
  // that match everything except the agent cluster check. This is needed
  // for embedders that hand out frame references outside of a browsing
  // instance, for example extensions and webview tag.
  auto* window = GetFrame()->DomWindow();
  window->GetMutableSecurityOrigin()->GrantCrossAgentClusterAccess();
}

WebHistoryItem WebLocalFrameImpl::GetCurrentHistoryItem() const {
  return WebHistoryItem(current_history_item_);
}

void WebLocalFrameImpl::SetLocalStorageArea(
    CrossVariantMojoRemote<mojom::StorageAreaInterfaceBase>
        local_storage_area) {
  CoreInitializer::GetInstance().SetLocalStorageArea(
      *GetFrame(), std::move(local_storage_area));
}

void WebLocalFrameImpl::SetSessionStorageArea(
    CrossVariantMojoRemote<mojom::StorageAreaInterfaceBase>
        session_storage_area) {
  CoreInitializer::GetInstance().SetSessionStorageArea(
      *GetFrame(), std::move(session_storage_area));
}

void WebLocalFrameImpl::SetNotRestoredReasons(
    const mojom::BackForwardCacheNotRestoredReasonsPtr& not_restored_reasons) {
  GetFrame()->SetNotRestoredReasons(
      ConvertNotRestoredReasons(not_restored_reasons));
}

const mojom::blink::BackForwardCacheNotRestoredReasonsPtr&
WebLocalFrameImpl::GetNotRestoredReasons() {
  return GetFrame()->GetNotRestoredReasons();
}

mojom::blink::BackForwardCacheNotRestoredReasonsPtr
WebLocalFrameImpl::ConvertNotRestoredReasons(
    const mojom::BackForwardCacheNotRestoredReasonsPtr& reasons_to_copy) {
  mojom::blink::BackForwardCacheNotRestoredReasonsPtr not_restored_reasons;
  if (!reasons_to_copy.is_null()) {
    not_restored_reasons =
        mojom::blink::BackForwardCacheNotRestoredReasons::New();
    if (reasons_to_copy->id) {
      not_restored_reasons->id = reasons_to_copy->id.value().c_str();
    }
    if (reasons_to_copy->name) {
      not_restored_reasons->name = reasons_to_copy->name.value().c_str();
    }
    if (reasons_to_copy->src) {
      not_restored_reasons->src = reasons_to_copy->src.value().c_str();
    }
    for (const auto& reason_to_copy : reasons_to_copy->reasons) {
      mojom::blink::BFCacheBlockingDetailedReasonPtr reason =
          mojom::blink::BFCacheBlockingDetailedReason::New();
      reason->name = WTF::String(reason_to_copy->name);
      if (reason_to_copy->source) {
        CHECK_GT(reason_to_copy->source->line_number, 0U);
        CHECK_GT(reason_to_copy->source->column_number, 0U);
        mojom::blink::ScriptSourceLocationPtr source_location =
            mojom::blink::ScriptSourceLocation::New(
                KURL(reason_to_copy->source->url),
                WTF::String(reason_to_copy->source->function_name),
                reason_to_copy->source->line_number,
                reason_to_copy->source->column_number);
        reason->source = std::move(source_location);
      }
      not_restored_reasons->reasons.push_back(std::move(reason));
    }
    if (reasons_to_copy->same_origin_details) {
      auto details = mojom::blink::SameOriginBfcacheNotRestoredDetails::New();
      details->url = KURL(reasons_to_copy->same_origin_details->url);
      for (const auto& child : reasons_to_copy->same_origin_details->children) {
        details->children.push_back(ConvertNotRestoredReasons(child));
      }
      not_restored_reasons->same_origin_details = std::move(details);
    }
  }
  return not_restored_reasons;
}

void WebLocalFrameImpl::SetLCPPHint(
    const mojom::LCPCriticalPathPredictorNavigationTimeHintPtr& hint) {
  LocalFrame* frame = GetFrame();
  if (!frame) {
    return;
  }

  LCPCriticalPathPredictor* lcpp = frame->GetLCPP();
  if (!lcpp) {
    return;
  }

  lcpp->Reset();

  if (!hint) {
    return;
  }

  lcpp->set_lcp_element_locators(hint->lcp_element_locators);

  HashSet<KURL> lcp_influencer_scripts;
  for (auto& url : hint->lcp_influencer_scripts) {
    lcp_influencer_scripts.insert(KURL(url));
  }
  lcpp->set_lcp_influencer_scripts(std::move(lcp_influencer_scripts));

  Vector<KURL> fetched_fonts;
  fetched_fonts.reserve(
      base::checked_cast<wtf_size_t>(hint->fetched_fonts.size()));
  for (const auto& url : hint->fetched_fonts) {
    fetched_fonts.emplace_back(url);
  }
  lcpp->set_fetched_fonts(std::move(fetched_fonts));

  Vector<url::Origin> preconnect_origins;
  preconnect_origins.reserve(
      base::checked_cast<wtf_size_t>(hint->preconnect_origins.size()));
  for (const auto& origin_url : hint->preconnect_origins) {
    preconnect_origins.emplace_back(url::Origin::Create(origin_url));
  }
  lcpp->set_preconnected_origins(preconnect_origins);

  Vector<KURL> unused_preloads;
  unused_preloads.reserve(
      base::checked_cast<wtf_size_t>(hint->unused_preloads.size()));
  for (const auto& url : hint->unused_preloads) {
    unused_preloads.emplace_back(url);
  }
  lcpp->set_unused_preloads(std::move(unused_preloads));
}

bool WebLocalFrameImpl::IsFeatureEnabled(
    const mojom::blink::PermissionsPolicyFeature& feature) const {
  return GetFrame()->DomWindow()->IsFeatureEnabled(feature);
}

void WebLocalFrameImpl::AddHitTestOnTouchStartCal
"""


```
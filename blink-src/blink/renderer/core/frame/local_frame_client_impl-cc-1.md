Response:
The user wants a summary of the functionality of the `LocalFrameClientImpl.cc` file, focusing on its relationships with Javascript, HTML, and CSS. I also need to identify any logical inferences, common usage errors, and provide examples. Since this is the second part of the request, I will synthesize the information from both parts.

Here's a breakdown of the functionalities and how they relate to the web technologies:

**Core Functionality (Based on method names and logic):**

*   **Navigation Management:**  Starting, committing, and aborting navigations, handling back/forward navigation.
*   **Loading Status:** Tracking start and stop of loading.
*   **Form Submission:** Dispatching events related to form submissions.
*   **Performance Monitoring:**  Tracking performance timings, CPU usage, user interaction timings, layout shifts.
*   **Feature Usage Tracking:** Observing the usage of browser features and Javascript frameworks.
*   **Subresource Loading:** Observing the loading of subresources.
*   **User Agent Management:** Providing the user agent string and metadata.
*   **Frame Creation:** Creating child frames (including fenced frames).
*   **Plugin Handling:** Creating and managing plugins.
*   **Media Player Creation:** Creating and managing media players.
*   **Service Worker Provider:** Creating service worker providers.
*   **Content Settings:** Accessing content settings.
*   **DevTools Integration:** Providing hooks for DevTools.
*   **Spellchecking:** Interfacing with the spellchecker.
*   **Resource Loading:** Creating and managing URL loaders.
*   **Selection Management:** Tracking changes in text selection.
*   **Focus Management:** Tracking changes in focused elements.
*   **Intersection and Viewport Observation:** Monitoring the intersection and viewport of the main frame.
*   **Ad Detection:**  Reporting the detection of overlay popup and large sticky ads.
*   **Worker Context Creation:** Creating fetch contexts and content settings clients for workers.
*   **Mouse Capture:** Managing mouse capture.
*   **Autoscroll:** Notifying about autoscroll.
*   **DOM Storage:** Checking if DOM storage is disabled.

**Relationships with Javascript, HTML, and CSS:**

*   **Javascript:**
    *   `DidObserveJavaScriptFrameworks`: Directly related to detecting and reporting Javascript frameworks used on a page.
    *   `CreateWebMediaPlayer`: Javascript often interacts with media elements.
    *   `CreateServiceWorkerProvider`: Service workers are written in Javascript.
    *   `evaluateInInspectorOverlayForTesting`:  Executes Javascript code in the DevTools overlay.
    *   `GetScriptableObject`: Provides a Javascript object for a plugin.
    *   Callbacks like `DidObserveUserInteraction` can be triggered by Javascript events.
*   **HTML:**
    *   `BeginNavigation`, `DidStartLoading`, `DidStopLoading`:  Reflect the loading of HTML documents.
    *   `DispatchWillSendSubmitEvent`: Handles form submissions initiated by HTML forms.
    *   `CreateFrame`, `CreateFencedFrame`: Creates `<iframe>` and `<fencedframe>` elements.
    *   `CreatePlugin`: Handles `<embed>` and `<object>` elements.
    *   `CreateWebMediaPlayer`: Handles `<video>` and `<audio>` elements.
    *   `DidChangeName`: Reflects changes to the `name` attribute of a frame.
    *   `FocusedElementChanged`: Reports when an HTML element gains focus.
    *   `IsPluginHandledExternally`: Checks if a plugin for an HTML element is handled externally.
*   **CSS:**
    *   `DidObserveLayoutShift`:  Tracks changes in the layout of the page, often caused by CSS changes.
    *   `SelectorMatchChanged`:  Reports when CSS selectors start or stop matching elements.

**Logical Inferences (Hypothetical):**

*   **Input:** A user clicks a link (`<a>` tag).
    *   **Output:** `BeginNavigation` would be called, potentially followed by `DidStartLoading` and `DidStopLoading`.
*   **Input:** Javascript code calls `window.history.back()`.
    *   **Output:** `NavigateBackForward` would be called with a negative offset.
*   **Input:** A form with `method="post"` is submitted.
    *   **Output:** `DispatchWillSendSubmitEvent` would be called.

**Common Usage Errors (Potential):**

*   **Incorrectly assuming synchronous behavior:** Some methods might trigger asynchronous operations. For example, calling a navigation method doesn't mean the new page is immediately loaded.
*   **Mismatched assumptions about frame hierarchy:**  Operations on frames need to respect the parent-child relationship. Trying to access a sibling frame incorrectly could lead to errors.
*   **Not handling potential null pointers:**  Many methods check if `web_frame_->Client()` is valid. Failing to handle cases where it's null could lead to crashes.

**Synthesis of both parts:**

Combining the functionalities described in both parts of the file, `LocalFrameClientImpl` acts as a crucial intermediary between the core rendering engine (Blink) and the embedder (e.g., Chromium). It translates Blink's internal events and requests into actions that the embedder can understand and handle. This includes managing the lifecycle of a frame, handling user interactions, tracking performance, and providing hooks for various browser features. The implementation heavily relies on delegation to a `WebLocalFrameImpl` and its client interface, indicating a clear separation of concerns between the core rendering logic and the embedder-specific implementation.
好的，这是对 `blink/renderer/core/frame/local_frame_client_impl.cc` 文件第二部分的归纳总结，并结合第一部分进行整体的功能概述。

**整体功能归纳：**

`LocalFrameClientImpl` 类是 Blink 渲染引擎中负责连接核心渲染逻辑（`LocalFrame`）和外部嵌入器（例如 Chromium 的 `RenderFrameImpl`）的关键组件。 它实现了 `LocalFrameClient` 接口，充当了 **LocalFrame 的策略提供者和事件通知者**。

**主要功能包括：**

1. **导航管理：** 负责发起、控制和监控 frame 的导航过程，包括新的导航、回退/前进导航等。
2. **加载状态管理：**  通知嵌入器 frame 的加载开始和结束状态。
3. **用户交互处理：**  捕捉和传递用户的交互行为，例如点击、键盘输入等。
4. **性能监控：**  收集和上报各种性能指标，例如加载时间、CPU 占用、布局偏移等。
5. **特性使用跟踪：**  记录页面使用的浏览器新特性和 JavaScript 框架。
6. **子资源加载监控：**  跟踪页面加载的子资源信息。
7. **用户代理管理：**  提供和管理 frame 的用户代理字符串。
8. **Frame 创建：**  负责创建子 frame，包括普通的 iframe 和隔离的 fenced frame。
9. **插件处理：**  创建和管理嵌入到页面中的插件。
10. **媒体播放器创建：**  负责创建和管理 HTML5 媒体播放器。
11. **Service Worker 管理：**  创建和管理与 frame 关联的 Service Worker。
12. **内容设置访问：**  提供访问 frame 内容设置的接口。
13. **DevTools 集成：**  为开发者工具提供必要的接口和功能。
14. **拼写检查支持：**  集成拼写检查功能。
15. **资源加载管理：**  创建和管理网络资源的加载器。
16. **选择管理：**  监听和通知文本选择的变化。
17. **焦点管理：**  跟踪页面焦点的变化。
18. **可视区域和交叉区域监控：** 监控主 frame 的可视区域和交叉区域变化。
19. **广告检测：**  报告检测到的覆盖式弹窗广告和大型粘性广告。
20. **Worker 上下文创建：**  为 Web Worker 创建特定的上下文环境。
21. **鼠标捕获：**  控制鼠标捕获状态。
22. **自动滚动通知：**  通知主 frame 关于选择内容的自动滚动行为。
23. **DOM 存储状态：**  查询 DOM 存储是否被禁用。

**与 Javascript, HTML, CSS 的关系举例说明：**

*   **Javascript:**
    *   `DidObserveJavaScriptFrameworks`:  当页面加载并执行 JavaScript 代码时，`LocalFrameClientImpl` 会检测使用的 JavaScript 框架，并将结果通知给嵌入器。
    *   `CreateWebMediaPlayer`: 当 HTML 中存在 `<video>` 或 `<audio>` 标签，并且 JavaScript 代码尝试与之交互时，会调用此方法创建媒体播放器对象。
    *   `DidObserveUserInteraction`:  当用户与页面进行交互（例如点击按钮），触发 JavaScript 事件时，`LocalFrameClientImpl` 会记录这些交互行为。
    *   `evaluateInInspectorOverlayForTesting`:  这是一个测试接口，允许在 DevTools 的覆盖层中执行 JavaScript 代码。
*   **HTML:**
    *   `BeginNavigation`: 当用户点击链接 (`<a>` 标签) 或通过 JavaScript 修改 `window.location` 时，会触发导航，并调用此方法。
    *   `DispatchWillSendSubmitEvent`:  当用户提交 HTML 表单 (`<form>`) 时，会调用此方法通知嵌入器即将发送表单数据。
    *   `CreateFrame`: 当 HTML 中包含 `<iframe>` 标签时，会调用此方法创建新的 frame 对象。
    *   `CreatePlugin`: 当 HTML 中包含 `<embed>` 或 `<object>` 标签时，会调用此方法创建相应的插件对象。
    *   `FocusedElementChanged`: 当 HTML 元素获得或失去焦点时，会调用此方法通知嵌入器。
*   **CSS:**
    *   `DidObserveLayoutShift`: 当 CSS 样式发生变化，导致页面布局发生偏移时，会调用此方法记录布局偏移的分数和是否在用户输入或滚动之后发生。
    *   `SelectorMatchChanged`: 当 CSS 选择器开始或停止匹配某些 HTML 元素时，会调用此方法通知嵌入器匹配的 CSS 选择器。

**逻辑推理的假设输入与输出：**

*   **假设输入:** 用户点击了一个链接，该链接指向一个新的 URL。
    *   **输出:** `BeginNavigation` 方法会被调用，参数包含新的 URL 和相关的导航信息。接着，可能会调用 `DidStartLoading`，并在页面加载完成后调用 `DidStopLoading`。
*   **假设输入:**  JavaScript 代码调用了 `history.back()`。
    *   **输出:** `NavigateBackForward` 方法会被调用，参数 `offset` 为负数，表示回退的步数。

**涉及用户或编程常见的使用错误举例说明：**

*   **错误地假设导航是同步的:**  开发者可能会错误地认为调用导航相关的方法后，新的页面会立即加载完成。实际上，导航是异步的，需要通过加载状态的回调来判断加载是否完成。
*   **在没有检查 `web_frame_->Client()` 的情况下调用其方法:**  在 `LocalFrameClientImpl` 的许多方法中，都首先检查了 `web_frame_->Client()` 是否为空。如果开发者在其他地方直接使用 `WebLocalFrameImpl` 的客户端，而没有进行空指针检查，可能会导致程序崩溃。
*   **混淆 Frame 的生命周期:**  开发者可能会在 Frame 已经被销毁后尝试访问或操作它，导致未定义的行为。`LocalFrameClientImpl` 负责管理 Frame 的生命周期，嵌入器需要正确地与之配合。

总而言之，`LocalFrameClientImpl` 是 Blink 渲染引擎中至关重要的一个组件，它连接了核心渲染逻辑和外部环境，负责处理各种与页面加载、用户交互、性能监控等方面相关的事件和操作。理解其功能对于深入理解 Blink 渲染引擎的工作原理至关重要。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_frame_client_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
 owner ? owner->GetFramePolicy() : FramePolicy();

  // navigation_info->frame_policy is only used for the synchronous
  // re-navigation to about:blank. See:
  // - |RenderFrameImpl::SynchronouslyCommitAboutBlankForBug778318| and
  // - |WebNavigationParams::CreateFromInfo|
  //
  // |owner->GetFramePolicy()| above only contains the sandbox flags defined by
  // the <iframe> element. It doesn't take into account inheritance from the
  // parent or the opener. The synchronous re-navigation to about:blank and the
  // initial empty document must both have the same sandbox flags. Make a copy:
  navigation_info->frame_policy.sandbox_flags = web_frame_->GetFrame()
                                                    ->DomWindow()
                                                    ->GetSecurityContext()
                                                    .GetSandboxFlags();

  navigation_info->href_translate = href_translate;
  navigation_info->is_container_initiated = is_container_initiated;

  web_frame_->Client()->BeginNavigation(std::move(navigation_info));
}

void LocalFrameClientImpl::DispatchWillSendSubmitEvent(HTMLFormElement* form) {
  web_frame_->WillSendSubmitEvent(WebFormElement(form));
}

void LocalFrameClientImpl::DidStartLoading() {
  if (web_frame_->Client()) {
    web_frame_->Client()->DidStartLoading();
  }
}

void LocalFrameClientImpl::DidStopLoading() {
  if (web_frame_->Client())
    web_frame_->Client()->DidStopLoading();
}

bool LocalFrameClientImpl::NavigateBackForward(
    int offset,
    std::optional<scheduler::TaskAttributionId>
        soft_navigation_heuristics_task_id) const {
  WebViewImpl* webview = web_frame_->ViewImpl();
  DCHECK(webview->Client());
  DCHECK(web_frame_->Client());

  DCHECK(offset);
  if (offset > webview->HistoryForwardListCount())
    return false;
  if (offset < -webview->HistoryBackListCount())
    return false;

  bool has_user_gesture =
      LocalFrame::HasTransientUserActivation(web_frame_->GetFrame());
  web_frame_->GetFrame()->GetLocalFrameHostRemote().GoToEntryAtOffset(
      offset, has_user_gesture, soft_navigation_heuristics_task_id);
  return true;
}

void LocalFrameClientImpl::DidDispatchPingLoader(const KURL& url) {
  if (web_frame_->Client())
    web_frame_->Client()->DidDispatchPingLoader(url);
}

void LocalFrameClientImpl::DidChangePerformanceTiming() {
  if (web_frame_->Client())
    web_frame_->Client()->DidChangePerformanceTiming();
}

void LocalFrameClientImpl::DidObserveUserInteraction(
    base::TimeTicks max_event_start,
    base::TimeTicks max_event_queued_main_thread,
    base::TimeTicks max_event_commit_finish,
    base::TimeTicks max_event_end,
    UserInteractionType interaction_type,
    uint64_t interaction_offset) {
  web_frame_->Client()->DidObserveUserInteraction(
      max_event_start, max_event_queued_main_thread, max_event_commit_finish,
      max_event_end, interaction_type, interaction_offset);
}

void LocalFrameClientImpl::DidChangeCpuTiming(base::TimeDelta time) {
  if (web_frame_->Client())
    web_frame_->Client()->DidChangeCpuTiming(time);
}

void LocalFrameClientImpl::DidObserveLoadingBehavior(
    LoadingBehaviorFlag behavior) {
  if (web_frame_->Client())
    web_frame_->Client()->DidObserveLoadingBehavior(behavior);
}

void LocalFrameClientImpl::DidObserveJavaScriptFrameworks(
    const JavaScriptFrameworkDetectionResult& result) {
  web_frame_->Client()->DidObserveJavaScriptFrameworks(result);
}

void LocalFrameClientImpl::DidObserveSubresourceLoad(
    const SubresourceLoadMetrics& subresource_load_metrics) {
  if (web_frame_->Client()) {
    web_frame_->Client()->DidObserveSubresourceLoad(subresource_load_metrics);
  }
}

void LocalFrameClientImpl::DidObserveNewFeatureUsage(
    const UseCounterFeature& feature) {
  if (web_frame_->Client())
    web_frame_->Client()->DidObserveNewFeatureUsage(feature);
}

// A new soft navigation was observed.
void LocalFrameClientImpl::DidObserveSoftNavigation(
    SoftNavigationMetrics metrics) {
  if (WebLocalFrameClient* client = web_frame_->Client()) {
    client->DidObserveSoftNavigation(metrics);
  }
}

void LocalFrameClientImpl::DidObserveLayoutShift(double score,
                                                 bool after_input_or_scroll) {
  if (WebLocalFrameClient* client = web_frame_->Client())
    client->DidObserveLayoutShift(score, after_input_or_scroll);
}

void LocalFrameClientImpl::SelectorMatchChanged(
    const Vector<String>& added_selectors,
    const Vector<String>& removed_selectors) {
  if (WebLocalFrameClient* client = web_frame_->Client()) {
    client->DidMatchCSS(WebVector<WebString>(added_selectors),
                        WebVector<WebString>(removed_selectors));
  }
}

void LocalFrameClientImpl::DidCreateDocumentLoader(
    DocumentLoader* document_loader) {
  web_frame_->Client()->DidCreateDocumentLoader(document_loader);
}

String LocalFrameClientImpl::UserAgentOverride() {
  return web_frame_->Client()
             ? String(web_frame_->Client()->UserAgentOverride())
             : g_empty_string;
}

String LocalFrameClientImpl::UserAgent() {
  String override = UserAgentOverride();
  if (!override.empty()) {
    return override;
  }

  if (user_agent_.empty())
    user_agent_ = Platform::Current()->UserAgent();
  return user_agent_;
}

std::optional<UserAgentMetadata> LocalFrameClientImpl::UserAgentMetadata() {
  bool ua_override_on = web_frame_->Client() &&
                        !web_frame_->Client()->UserAgentOverride().IsEmpty();
  std::optional<blink::UserAgentMetadata> user_agent_metadata =
      ua_override_on ? web_frame_->Client()->UserAgentMetadataOverride()
                     : Platform::Current()->UserAgentMetadata();

  Document* document = web_frame_->GetDocument();
  probe::ApplyUserAgentMetadataOverride(probe::ToCoreProbeSink(document),
                                        &user_agent_metadata);

  return user_agent_metadata;
}

String LocalFrameClientImpl::DoNotTrackValue() {
  if (web_frame_->View()->GetRendererPreferences().enable_do_not_track)
    return "1";
  return String();
}

// Called when the FrameLoader goes into a state in which a new page load
// will occur.
void LocalFrameClientImpl::TransitionToCommittedForNewPage() {
  web_frame_->CreateFrameView();
}

LocalFrame* LocalFrameClientImpl::CreateFrame(
    const AtomicString& name,
    HTMLFrameOwnerElement* owner_element) {
  return web_frame_->CreateChildFrame(name, owner_element);
}

RemoteFrame* LocalFrameClientImpl::CreateFencedFrame(
    HTMLFencedFrameElement* fenced_frame,
    mojo::PendingAssociatedReceiver<mojom::blink::FencedFrameOwnerHost>
        receiver) {
  return web_frame_->CreateFencedFrame(fenced_frame, std::move(receiver));
}

WebPluginContainerImpl* LocalFrameClientImpl::CreatePlugin(
    HTMLPlugInElement& element,
    const KURL& url,
    const Vector<String>& param_names,
    const Vector<String>& param_values,
    const String& mime_type,
    bool load_manually) {
  if (!web_frame_->Client())
    return nullptr;

  WebPluginParams params;
  params.url = url;
  params.mime_type = mime_type;
  params.attribute_names = param_names;
  params.attribute_values = param_values;
  params.load_manually = load_manually;

  WebPlugin* web_plugin = web_frame_->Client()->CreatePlugin(params);
  if (!web_plugin)
    return nullptr;

  // The container takes ownership of the WebPlugin.
  auto* container =
      MakeGarbageCollected<WebPluginContainerImpl>(element, web_plugin);

  if (!web_plugin->Initialize(container))
    return nullptr;

  if (!element.GetLayoutObject())
    return nullptr;

  return container;
}

std::unique_ptr<WebMediaPlayer> LocalFrameClientImpl::CreateWebMediaPlayer(
    HTMLMediaElement& html_media_element,
    const WebMediaPlayerSource& source,
    WebMediaPlayerClient* client) {
  LocalFrame* local_frame = html_media_element.LocalFrameForPlayer();
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(local_frame);

  if (!web_frame || !web_frame->Client())
    return nullptr;

  return CoreInitializer::GetInstance().CreateWebMediaPlayer(
      web_frame->Client(), html_media_element, source, client);
}

RemotePlaybackClient* LocalFrameClientImpl::CreateRemotePlaybackClient(
    HTMLMediaElement& html_media_element) {
  return CoreInitializer::GetInstance().CreateRemotePlaybackClient(
      html_media_element);
}

void LocalFrameClientImpl::DidChangeName(const String& name) {
  if (!web_frame_->Client())
    return;
  web_frame_->Client()->DidChangeName(name);
}

std::unique_ptr<WebServiceWorkerProvider>
LocalFrameClientImpl::CreateServiceWorkerProvider() {
  if (!web_frame_->Client())
    return nullptr;
  return web_frame_->Client()->CreateServiceWorkerProvider();
}

WebContentSettingsClient* LocalFrameClientImpl::GetContentSettingsClient() {
  return web_frame_->GetContentSettingsClient();
}

void LocalFrameClientImpl::DispatchDidChangeManifest() {
  CoreInitializer::GetInstance().DidChangeManifest(*web_frame_->GetFrame());
}

unsigned LocalFrameClientImpl::BackForwardLength() {
  WebViewImpl* webview = web_frame_->ViewImpl();
  return webview ? webview->HistoryListLength() : 0;
}

WebDevToolsAgentImpl* LocalFrameClientImpl::DevToolsAgent(
    bool create_if_necessary) {
  return WebLocalFrameImpl::FromFrame(web_frame_->GetFrame()->LocalFrameRoot())
      ->DevToolsAgentImpl(create_if_necessary);
}

KURL LocalFrameClientImpl::OverrideFlashEmbedWithHTML(const KURL& url) {
  return web_frame_->Client()->OverrideFlashEmbedWithHTML(WebURL(url));
}

void LocalFrameClientImpl::NotifyUserActivation() {
  if (WebAutofillClient* autofill_client = web_frame_->AutofillClient())
    autofill_client->UserGestureObserved();
}

void LocalFrameClientImpl::AbortClientNavigation(bool for_new_navigation) {
  if (web_frame_->Client()) {
    web_frame_->Client()->AbortClientNavigation(for_new_navigation);
  }
}

WebSpellCheckPanelHostClient* LocalFrameClientImpl::SpellCheckPanelHostClient()
    const {
  return web_frame_->SpellCheckPanelHostClient();
}

WebTextCheckClient* LocalFrameClientImpl::GetTextCheckerClient() const {
  return web_frame_->GetTextCheckerClient();
}

scoped_refptr<network::SharedURLLoaderFactory>
LocalFrameClientImpl::GetURLLoaderFactory() {
  return web_frame_->Client()->GetURLLoaderFactory();
}

std::unique_ptr<URLLoader> LocalFrameClientImpl::CreateURLLoaderForTesting() {
  return web_frame_->Client()->CreateURLLoaderForTesting();
}

blink::ChildURLLoaderFactoryBundle*
LocalFrameClientImpl::GetLoaderFactoryBundle() {
  return web_frame_->Client()->GetLoaderFactoryBundle();
}

scoped_refptr<WebBackgroundResourceFetchAssets>
LocalFrameClientImpl::MaybeGetBackgroundResourceFetchAssets() {
  return web_frame_->Client()->MaybeGetBackgroundResourceFetchAssets();
}

AssociatedInterfaceProvider*
LocalFrameClientImpl::GetRemoteNavigationAssociatedInterfaces() {
  return web_frame_->Client()->GetRemoteNavigationAssociatedInterfaces();
}

base::UnguessableToken LocalFrameClientImpl::GetDevToolsFrameToken() const {
  return web_frame_->Client()->GetDevToolsFrameToken();
}

String LocalFrameClientImpl::evaluateInInspectorOverlayForTesting(
    const String& script) {
  if (WebDevToolsAgentImpl* devtools =
          DevToolsAgent(/*create_if_necessary=*/true)) {
    return devtools->EvaluateInOverlayForTesting(script);
  }
  return g_empty_string;
}

bool LocalFrameClientImpl::HandleCurrentKeyboardEvent() {
  return web_frame_->LocalRoot()
      ->FrameWidgetImpl()
      ->HandleCurrentKeyboardEvent();
}

void LocalFrameClientImpl::DidChangeSelection(bool is_selection_empty,
                                              blink::SyncCondition force_sync) {
  if (web_frame_->Client())
    web_frame_->Client()->DidChangeSelection(is_selection_empty, force_sync);
}

void LocalFrameClientImpl::DidChangeContents() {
  if (web_frame_->Client())
    web_frame_->Client()->DidChangeContents();
}

Frame* LocalFrameClientImpl::FindFrame(const AtomicString& name) const {
  DCHECK(web_frame_->Client());
  return ToCoreFrame(web_frame_->Client()->FindFrame(name));
}

void LocalFrameClientImpl::FocusedElementChanged(Element* element) {
  DCHECK(web_frame_->Client());
  web_frame_->ResetHasScrolledFocusedEditableIntoView();
  web_frame_->Client()->FocusedElementChanged(element);
}

void LocalFrameClientImpl::OnMainFrameIntersectionChanged(
    const gfx::Rect& main_frame_intersection_rect) {
  DCHECK(web_frame_->Client());
  web_frame_->Client()->OnMainFrameIntersectionChanged(
      main_frame_intersection_rect);
}

void LocalFrameClientImpl::OnMainFrameViewportRectangleChanged(
    const gfx::Rect& main_frame_viewport_rect) {
  DCHECK(web_frame_->Client());
  web_frame_->Client()->OnMainFrameViewportRectangleChanged(
      main_frame_viewport_rect);
}

void LocalFrameClientImpl::OnMainFrameImageAdRectangleChanged(
    DOMNodeId element_id,
    const gfx::Rect& image_ad_rect) {
  DCHECK(web_frame_->Client());
  web_frame_->Client()->OnMainFrameImageAdRectangleChanged(element_id,
                                                           image_ad_rect);
}

void LocalFrameClientImpl::OnOverlayPopupAdDetected() {
  DCHECK(web_frame_->Client());
  web_frame_->Client()->OnOverlayPopupAdDetected();
}

void LocalFrameClientImpl::OnLargeStickyAdDetected() {
  DCHECK(web_frame_->Client());
  web_frame_->Client()->OnLargeStickyAdDetected();
}

bool LocalFrameClientImpl::IsPluginHandledExternally(
    HTMLPlugInElement& plugin_element,
    const KURL& resource_url,
    const String& suggesed_mime_type) {
  return web_frame_->Client()->IsPluginHandledExternally(
      &plugin_element, resource_url, suggesed_mime_type);
}

v8::Local<v8::Object> LocalFrameClientImpl::GetScriptableObject(
    HTMLPlugInElement& plugin_element,
    v8::Isolate* isolate) {
  return web_frame_->Client()->GetScriptableObject(&plugin_element, isolate);
}

scoped_refptr<WebWorkerFetchContext>
LocalFrameClientImpl::CreateWorkerFetchContext() {
  DCHECK(web_frame_->Client());
  return web_frame_->Client()->CreateWorkerFetchContext();
}

scoped_refptr<WebWorkerFetchContext>
LocalFrameClientImpl::CreateWorkerFetchContextForPlzDedicatedWorker(
    WebDedicatedWorkerHostFactoryClient* factory_client) {
  DCHECK(web_frame_->Client());
  return web_frame_->Client()->CreateWorkerFetchContextForPlzDedicatedWorker(
      factory_client);
}

std::unique_ptr<WebContentSettingsClient>
LocalFrameClientImpl::CreateWorkerContentSettingsClient() {
  DCHECK(web_frame_->Client());
  return web_frame_->Client()->CreateWorkerContentSettingsClient();
}

void LocalFrameClientImpl::SetMouseCapture(bool capture) {
  web_frame_->LocalRoot()->FrameWidgetImpl()->SetMouseCapture(capture);
}

void LocalFrameClientImpl::NotifyAutoscrollForSelectionInMainFrame(
    bool autoscroll_selection) {
  web_frame_->LocalRoot()
      ->FrameWidgetImpl()
      ->NotifyAutoscrollForSelectionInMainFrame(autoscroll_selection);
}

std::unique_ptr<blink::ResourceLoadInfoNotifierWrapper>
LocalFrameClientImpl::CreateResourceLoadInfoNotifierWrapper() {
  DCHECK(web_frame_->Client());
  return web_frame_->Client()->CreateResourceLoadInfoNotifierWrapper();
}

void LocalFrameClientImpl::BindDevToolsAgent(
    mojo::PendingAssociatedRemote<mojom::blink::DevToolsAgentHost> host,
    mojo::PendingAssociatedReceiver<mojom::blink::DevToolsAgent> receiver) {
  if (WebDevToolsAgentImpl* devtools =
          DevToolsAgent(/*create_if_necessary=*/true)) {
    devtools->BindReceiver(std::move(host), std::move(receiver));
  }
}

bool LocalFrameClientImpl::IsDomStorageDisabled() const {
  return web_frame_->Client()->IsDomStorageDisabled();
}

}  // namespace blink

"""


```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `inspector_page_agent.cc`. I need to identify the key actions and responsibilities of this code. Specifically, I need to:

1. **List the functions and their purpose.**
2. **Identify connections to Javascript, HTML, and CSS.**
3. **Provide examples of logical reasoning with input/output.**
4. **Give examples of common user/programming errors.**
5. **Summarize the overall functionality of this part of the code.**

Based on the function names and operations, the code seems to be responsible for:

- **Searching within resources:** `searchInResource`, `SearchContentAfterResourcesContentLoaded`
- **Modifying frame settings:** `setBypassCSP`
- **Retrieving permissions policy information:** `getPermissionsPolicyState`, `CreatePermissionsPolicyBlockLocator`
- **Setting document content:** `setDocumentContent`
- **Handling navigation within documents:** `DidNavigateWithinDocument`, `NavigationTypeToProtocolString`
- **Managing isolated Javascript worlds:** `EnsureDOMWrapperWorld`, `DidCreateMainWorldContext`, `EvaluateScriptOnNewDocument`
- **Handling lifecycle events:** `DomContentLoadedEventFired`, `LoadEventFired`, `WillCommitLoad`, `DidRestoreFromBackForwardCache`, `DidOpenDocument`, `LifecycleEvent`, `PaintTiming`
- **Managing frame attachment/detachment:** `FrameAttachedToParent`, `FrameDetachedFromParent`, `FrameSubtreeWillBeDetached`
- **Indicating loading status:** `FrameStoppedLoading`
- **Handling navigation requests:** `FrameRequestedNavigation`, `FrameScheduledNavigation`, `FrameClearedScheduledNavigation`
- **Flushing frontend messages:** `WillRunJavaScriptDialog`, `DidRunJavaScriptDialog`
- **Handling resizing:** `DidResizeMainFrame`, `DidChangeViewport`, `PageLayoutInvalidated`
- **Handling window opening:** `WindowOpen`
- **Providing context information:** `CreateProtocolSecureContextType`, `CreateProtocolCrossOriginIsolatedContextType`, `CreateGatedAPIFeaturesArray`, `CreateOriginTrialTokenStatus`, `CreateOriginTrialStatus`, `CreateOriginTrialUsageRestriction`, `CreateOriginTrialToken`, `CreateOriginTrialTokenWithStatus`, `CreateOriginTrial`, `CreateOriginTrials`, `BuildAdFrameType`, `BuildAdFrameStatus`
- **Building protocol objects for frames:** `BuildObjectForFrame`, `BuildObjectForFrameTree`, `BuildObjectForResourceTree`
- **Managing screencasting:** `startScreencast`, `stopScreencast`
- **Getting layout metrics:** `getLayoutMetrics`

Now, I can structure the response based on these identified functionalities.
这是`blink/renderer/core/inspector/inspector_page_agent.cc`文件的第二部分代码，延续了其作为 Chromium Blink 引擎中负责页面检查功能的代理的角色。 这部分代码主要关注以下功能：

**1. 资源内容搜索功能：**

*   **`searchInResource(const String& frame_id, const String& url, const String& query, bool case_sensitive, bool is_regex, std::unique_ptr<SearchInResourceCallback> callback)`:**
    *   **功能:** 在指定的 frame 的特定 URL 资源中搜索给定的查询字符串。
    *   **与 Javascript, HTML, CSS 的关系:**  该功能可以用于搜索网页加载的任何资源，包括 Javascript 文件 (.js)、HTML 文件 (.html, .htm) 和 CSS 文件 (.css)。
    *   **举例说明:**
        *   **假设输入:**  `frame_id = "1"`, `url = "https://example.com/script.js"`, `query = "console.log"`, `case_sensitive = false`, `is_regex = false`
        *   **可能输出:** 返回一个包含匹配项的数组，每个匹配项会指出在 `script.js` 文件中 `console.log` 出现的位置和上下文。
*   **`searchInResource(const String& frame_id, const String& url, const String& query, Maybe<bool> optional_case_sensitive, Maybe<bool> optional_is_regex, std::unique_ptr<SearchInResourceCallback> callback)`:**
    *   **功能:**  是上述函数的重载版本，允许省略 `case_sensitive` 和 `is_regex` 参数，默认为大小写不敏感和非正则表达式搜索。
    *   **与 Javascript, HTML, CSS 的关系:** 同样适用于搜索 Javascript、HTML 和 CSS 文件等资源。

**2. CSP (Content Security Policy) 绕过设置：**

*   **`setBypassCSP(bool enabled)`:**
    *   **功能:** 设置是否绕过指定主框架的 CSP 策略。这通常用于调试目的，允许开发者在检查器中执行被 CSP 阻止的操作。
    *   **与 Javascript, HTML, CSS 的关系:** CSP 策略直接影响浏览器如何加载和执行 Javascript 代码、HTML 中的内联脚本和样式，以及外部样式表的加载。 启用 `setBypassCSP` 可以允许加载和执行原本会被 CSP 阻止的资源或代码。
    *   **用户或编程常见的使用错误:**  在生产环境中启用 `setBypassCSP` 将会带来安全风险，因为它会移除 CSP 提供的保护，使得页面更容易受到跨站脚本攻击（XSS）等威胁。

**3. 权限策略 (Permissions Policy) 状态获取：**

*   **`getPermissionsPolicyState(const String& frame_id, std::unique_ptr<protocol::Array<protocol::Page::PermissionsPolicyFeatureState>>* states)`:**
    *   **功能:** 获取指定 frame 的权限策略状态，例如哪些功能被允许或阻止，以及阻止的原因。
    *   **与 Javascript, HTML, CSS 的关系:** 权限策略控制着网页可以使用的各种浏览器功能，例如地理位置、摄像头、麦克风等。这些策略通常通过 HTTP 头部或 iframe 属性进行设置，影响着 Javascript 代码的功能，也可能限制某些 HTML 和 CSS 特性的使用。
    *   **举例说明:**
        *   **假设输入:** `frame_id = "2"`
        *   **可能输出:** 返回一个数组，其中可能包含以下信息：
            *   `{ feature: "camera", allowed: false, locator: { frameId: "2", blockReason: "IframeAttribute" } }`  (表示摄像头功能被 iframe 的某个属性阻止了)
            *   `{ feature: "geolocation", allowed: true }` (表示地理位置功能被允许)
*   **`CreatePermissionsPolicyBlockLocator(const blink::PermissionsPolicyBlockLocator& locator)`:**
    *   **功能:**  将 Blink 内部的权限策略阻止定位器对象转换为用于检查器协议的对象。

**4. 设置文档内容：**

*   **`setDocumentContent(const String& frame_id, const String& html)`:**
    *   **功能:**  替换指定 frame 的文档内容为给定的 HTML 字符串。
    *   **与 Javascript, HTML, CSS 的关系:**  直接操作 HTML 内容。这个操作会触发浏览器的重新渲染，并可能影响到页面上运行的 Javascript 代码和应用的 CSS 样式。
    *   **假设输入:** `frame_id = "3"`, `html = "<h1>New Content</h1>"`
    *   **可能输出:**  `frame_id` 为 "3" 的框架的内容会被替换为 "<h1>New Content</h1>"。
    *   **用户或编程常见的使用错误:**  提供的 HTML 字符串可能格式不正确，导致页面渲染错误或 Javascript 代码执行异常。

**5. 文档内导航处理：**

*   **`DidNavigateWithinDocument(LocalFrame* frame, mojom::blink::SameDocumentNavigationType navigation_type)`:**
    *   **功能:** 当文档内部发生导航（例如，通过 hashchange 或 History API）时被调用，向检查器前端发送通知。
    *   **与 Javascript, HTML, CSS 的关系:**  与 Javascript 使用 History API 或修改 URL hash 进行页面内导航的行为相关。
*   **`NavigationTypeToProtocolString(mojom::blink::SameDocumentNavigationType navigation_type)`:**
    *   **功能:**  将 Blink 内部的导航类型枚举转换为检查器协议使用的字符串表示。

**6. 隔离的 JavaScript World 管理：**

*   **`EnsureDOMWrapperWorld(LocalFrame* frame, const String& world_name, bool grant_universal_access)`:**
    *   **功能:**  为指定的 frame 创建或获取一个隔离的 JavaScript world。隔离的 world 允许注入脚本，这些脚本可以访问页面的 DOM，但与页面自身的 JavaScript 运行在不同的上下文中。
    *   **与 Javascript 的关系:**  这是检查器用来执行和调试注入到页面的 JavaScript 代码的关键机制。
*   **`DidCreateMainWorldContext(LocalFrame* frame)`:**
    *   **功能:** 当主 JavaScript 上下文被创建时调用，用于处理待处理的隔离 world 请求和执行需要在页面加载时运行的脚本。
*   **`EvaluateScriptOnNewDocument(LocalFrame& frame, const String& script_identifier)`:**
    *   **功能:**  在新的文档中执行预先注册的脚本。这些脚本可以在页面加载的早期阶段运行，甚至在主脚本执行之前。
    *   **与 Javascript 的关系:**  允许在页面加载的特定时机执行自定义的 JavaScript 代码，用于监控或修改页面行为。
    *   **假设输入:**  一个预先注册的脚本 `script_identifier = "123"` 对应着 `scripts_to_evaluate_on_load_` 中的一段 Javascript 代码。
    *   **可能输出:**  这段 Javascript 代码将在指定的 `frame` 中执行。

**7. 生命周期事件处理：**

*   **`DomContentLoadedEventFired(LocalFrame* frame)`:**
    *   **功能:** 当 DOMContentLoaded 事件触发时调用，通知检查器前端。
    *   **与 Javascript, HTML, CSS 的关系:**  DOMContentLoaded 事件标志着 HTML 文档被完全加载和解析完成。
*   **`LoadEventFired(LocalFrame* frame)`:**
    *   **功能:** 当 load 事件触发时调用，通知检查器前端。
    *   **与 Javascript, HTML, CSS 的关系:** load 事件标志着包括所有外部资源（如图片、样式表）在内的页面都已加载完成。
*   **`WillCommitLoad(LocalFrame*, DocumentLoader* loader)`:**
    *   **功能:** 在即将提交加载新页面或导航时调用，用于发送帧导航事件到前端。
*   **`DidRestoreFromBackForwardCache(LocalFrame* frame)`:**
    *   **功能:** 当页面从浏览器的后退/前进缓存恢复时调用，通知检查器前端。
*   **`DidOpenDocument(LocalFrame* frame, DocumentLoader* loader)`:**
    *   **功能:**  当一个新的文档被打开时调用，通知检查器前端。
*   **`LifecycleEvent(LocalFrame* frame, DocumentLoader* loader, const char* name, double timestamp)`:**
    *   **功能:**  用于向检查器前端发送通用的生命周期事件。
*   **`PaintTiming(Document* document, const char* name, double timestamp)`:**
    *   **功能:**  报告页面渲染相关的性能指标（Paint Timing），例如首次内容绘制 (FCP) 和最大内容绘制 (LCP)。
    *   **与 CSS 的关系:** 渲染性能直接受到 CSS 样式的影响。

**8. 帧的附加和分离处理：**

*   **`FrameAttachedToParent(LocalFrame* frame, const std::optional<AdScriptIdentifier>& ad_script_on_stack)`:**
    *   **功能:** 当一个 frame 被附加到其父 frame 时调用，通知检查器前端。
*   **`FrameDetachedFromParent(LocalFrame* frame, FrameDetachType type)`:**
    *   **功能:** 当一个 frame 从其父 frame 分离时调用，通知检查器前端。
*   **`FrameSubtreeWillBeDetached(Frame* frame)`:**
    *   **功能:** 在一个 frame 的子树即将被分离时调用，通知检查器前端。

**9. 加载状态指示：**

*   **`FrameStoppedLoading(LocalFrame* frame)`:**
    *   **功能:** 当一个 frame 停止加载时调用，通知检查器前端。

**10. 导航请求处理：**

*   **`FrameRequestedNavigation(Frame* target_frame, const KURL& url, ClientNavigationReason reason, NavigationPolicy policy)`:**
    *   **功能:** 当一个 frame 请求导航到新的 URL 时调用，通知检查器前端。
*   **`FrameScheduledNavigation(LocalFrame* frame, const KURL& url, base::TimeDelta delay, ClientNavigationReason reason)`:**
    *   **功能:** 当一个 frame 计划在延迟后导航到新的 URL 时调用，通知检查器前端。
*   **`FrameClearedScheduledNavigation(LocalFrame* frame)`:**
    *   **功能:** 当一个 frame 取消了计划的导航时调用，通知检查器前端。

**11. JavaScript 对话框处理：**

*   **`WillRunJavaScriptDialog()`:**
    *   **功能:** 在即将显示 JavaScript 对话框（例如 `alert`, `confirm`, `prompt`）时调用，刷新前端。
*   **`DidRunJavaScriptDialog()`:**
    *   **功能:** 在 JavaScript 对话框显示完毕后调用，刷新前端。

**12. 尺寸调整处理：**

*   **`DidResizeMainFrame()`:**
    *   **功能:** 当主框架尺寸改变时调用，通知检查器前端。
*   **`DidChangeViewport()`:**
    *   **功能:** 当视口 (viewport) 发生改变时调用。
*   **`PageLayoutInvalidated(bool resized)`:**
    *   **功能:**  通知客户端页面布局失效。

**13. 窗口打开处理：**

*   **`WindowOpen(const KURL& url, const AtomicString& window_name, const WebWindowFeatures& window_features, bool user_gesture)`:**
    *   **功能:** 当通过 JavaScript 的 `window.open()` 方法打开新窗口时调用，通知检查器前端。
    *   **与 Javascript 的关系:**  直接关联到 `window.open()` API 的使用。

**14. 上下文信息构建：**

*   **`CreateProtocolSecureContextType(SecureContextModeExplanation explanation)`:**
    *   **功能:** 将 Blink 内部的安全上下文类型解释转换为检查器协议的表示。
*   **`CreateProtocolCrossOriginIsolatedContextType(ExecutionContext* context)`:**
    *   **功能:** 将 Blink 内部的跨域隔离上下文类型转换为检查器协议的表示。
*   **`CreateGatedAPIFeaturesArray(LocalDOMWindow* window)`:**
    *   **功能:** 创建一个数组，表示当前上下文中启用的受限制的 API 功能（例如 SharedArrayBuffers）。
*   **`CreateOriginTrialTokenStatus(...)`, `CreateOriginTrialStatus(...)`, `CreateOriginTrialUsageRestriction(...)`, `CreateOriginTrialToken(...)`, `CreateOriginTrialTokenWithStatus(...)`, `CreateOriginTrial(...)`, `CreateOriginTrials(...)`:**
    *   **功能:**  将 Blink 内部的 Origin Trial (源试用) 相关信息转换为检查器协议的表示，用于在开发者工具中展示 Origin Trial 的状态和详细信息。
    *   **与 Javascript, HTML 的关系:** Origin Trial 允许开发者在生产环境中试用新的 Web 平台特性，通常通过 HTTP 头部或 meta 标签声明，影响着 Javascript API 的可用性和 HTML 特性的行为。
*   **`BuildAdFrameType(LocalFrame* frame)`, `BuildAdFrameStatus(LocalFrame* frame)`:**
    *   **功能:** 构建关于 frame 是否被认为是广告 frame 及其状态的信息。

**15. 构建 Frame 和 FrameTree 对象：**

*   **`BuildObjectForFrame(LocalFrame* frame)`:**
    *   **功能:**  创建一个表示 frame 的检查器协议对象，包含 frame 的 ID、URL、安全上下文等信息。
    *   **与 Javascript, HTML 的关系:**  frame 是网页结构的基础组成部分，包含 HTML 文档和可能运行的 Javascript 代码。
*   **`BuildObjectForFrameTree(LocalFrame* frame)`:**
    *   **功能:**  递归地创建一个表示 frame 树的检查器协议对象，包含当前 frame 及其所有子 frame 的信息。
*   **`BuildObjectForResourceTree(LocalFrame* frame)`:**
    *   **功能:** 创建一个表示 frame 及其加载的资源（例如脚本、样式表、图片）的树状结构的检查器协议对象.
    *   **与 Javascript, HTML, CSS 的关系:**  关联到页面加载的各种资源，包括 Javascript 文件、HTML 文件和 CSS 文件。

**16. 屏幕录制功能：**

*   **`startScreencast(Maybe<String> format, Maybe<int> quality, Maybe<int> max_width, Maybe<int> max_height, Maybe<int> every_nth_frame)`:**
    *   **功能:**  启动屏幕录制功能，允许开发者工具捕获页面渲染的内容。
*   **`stopScreencast()`:**
    *   **功能:**  停止屏幕录制功能。

**17. 获取布局指标：**

*   **`getLayoutMetrics(...)`:**
    *   **功能:**  获取页面的布局指标，例如布局视口 (layout viewport)、视觉视口 (visual viewport) 和内容大小。
    *   **与 CSS 的关系:**  布局指标直接受到 CSS 样式的控制和影响。

**总结来说，这部分 `InspectorPageAgent` 的代码主要负责以下功能：**

*   **提供资源搜索能力，允许开发者在网页加载的各种资源中查找特定内容。**
*   **允许在调试环境下绕过 CSP 策略。**
*   **暴露页面的权限策略状态，帮助开发者理解哪些浏览器功能被允许或阻止。**
*   **支持动态修改页面内容，方便调试和测试。**
*   **处理页面内部的导航事件，并通知开发者工具。**
*   **管理隔离的 JavaScript 上下文，用于注入和执行调试脚本。**
*   **捕获和报告关键的页面生命周期事件，例如 DOMContentLoaded 和 load。**
*   **跟踪和报告 frame 的附加和分离，以及加载状态和导航请求。**
*   **处理 JavaScript 对话框的显示。**
*   **监控页面和视口的尺寸变化。**
*   **报告通过 `window.open()` 打开新窗口的事件。**
*   **构建和提供关于 frame 结构、加载的资源、安全上下文以及 Origin Trial 状态的详细信息。**
*   **支持屏幕录制功能。**
*   **提供页面的布局指标信息。**

总而言之，这部分代码是 `InspectorPageAgent` 中非常核心的一部分，它提供了丰富的接口，使得开发者工具能够深入了解和操控页面的各种状态和行为，从而实现强大的调试和检查功能。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_page_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
 url,
    const String& query,
    bool case_sensitive,
    bool is_regex,
    std::unique_ptr<SearchInResourceCallback> callback) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);
  if (!frame) {
    callback->sendFailure(
        protocol::Response::ServerError("No frame for given id found"));
    return;
  }
  String content;
  bool base64_encoded;
  if (!InspectorPageAgent::CachedResourceContent(
          CachedResource(frame, KURL(url), inspector_resource_content_loader_),
          &content, &base64_encoded)) {
    callback->sendFailure(
        protocol::Response::ServerError("No resource with given URL found"));
    return;
  }

  auto matches = v8_session_->searchInTextByLines(
      ToV8InspectorStringView(content), ToV8InspectorStringView(query),
      case_sensitive, is_regex);
  callback->sendSuccess(
      std::make_unique<
          protocol::Array<v8_inspector::protocol::Debugger::API::SearchMatch>>(
          std::move(matches)));
}

void InspectorPageAgent::searchInResource(
    const String& frame_id,
    const String& url,
    const String& query,
    Maybe<bool> optional_case_sensitive,
    Maybe<bool> optional_is_regex,
    std::unique_ptr<SearchInResourceCallback> callback) {
  if (!enabled_.Get()) {
    callback->sendFailure(
        protocol::Response::ServerError("Agent is not enabled."));
    return;
  }
  inspector_resource_content_loader_->EnsureResourcesContentLoaded(
      resource_content_loader_client_id_,
      WTF::BindOnce(
          &InspectorPageAgent::SearchContentAfterResourcesContentLoaded,
          WrapPersistent(this), frame_id, url, query,
          optional_case_sensitive.value_or(false),
          optional_is_regex.value_or(false), std::move(callback)));
}

protocol::Response InspectorPageAgent::setBypassCSP(bool enabled) {
  LocalFrame* frame = inspected_frames_->Root();
  frame->GetSettings()->SetBypassCSP(enabled);
  bypass_csp_enabled_.Set(enabled);
  return protocol::Response::Success();
}

namespace {

std::unique_ptr<protocol::Page::PermissionsPolicyBlockLocator>
CreatePermissionsPolicyBlockLocator(
    const blink::PermissionsPolicyBlockLocator& locator) {
  protocol::Page::PermissionsPolicyBlockReason reason;
  switch (locator.reason) {
    case blink::PermissionsPolicyBlockReason::kHeader:
      reason = protocol::Page::PermissionsPolicyBlockReasonEnum::Header;
      break;
    case blink::PermissionsPolicyBlockReason::kIframeAttribute:
      reason =
          protocol::Page::PermissionsPolicyBlockReasonEnum::IframeAttribute;
      break;
    case blink::PermissionsPolicyBlockReason::kInFencedFrameTree:
      reason =
          protocol::Page::PermissionsPolicyBlockReasonEnum::InFencedFrameTree;
      break;
    case blink::PermissionsPolicyBlockReason::kInIsolatedApp:
      reason = protocol::Page::PermissionsPolicyBlockReasonEnum::InIsolatedApp;
      break;
  }

  return protocol::Page::PermissionsPolicyBlockLocator::create()
      .setFrameId(locator.frame_id)
      .setBlockReason(reason)
      .build();
}
}  // namespace

protocol::Response InspectorPageAgent::getPermissionsPolicyState(
    const String& frame_id,
    std::unique_ptr<
        protocol::Array<protocol::Page::PermissionsPolicyFeatureState>>*
        states) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);

  if (!frame) {
    return protocol::Response::ServerError(
        "No frame for given id found in this target");
  }

  const blink::PermissionsPolicy* permissions_policy =
      frame->GetSecurityContext()->GetPermissionsPolicy();

  if (!permissions_policy)
    return protocol::Response::ServerError("Frame not ready");

  auto feature_states = std::make_unique<
      protocol::Array<protocol::Page::PermissionsPolicyFeatureState>>();

  bool is_isolated_context =
      frame->DomWindow() && frame->DomWindow()->IsIsolatedContext();
  for (const auto& entry :
       blink::GetDefaultFeatureNameMap(is_isolated_context)) {
    const String& feature_name = entry.key;
    const mojom::blink::PermissionsPolicyFeature feature = entry.value;

    if (blink::DisabledByOriginTrial(feature_name, frame->DomWindow()))
      continue;

    std::optional<blink::PermissionsPolicyBlockLocator> locator =
        blink::TracePermissionsPolicyBlockSource(frame, feature);

    std::unique_ptr<protocol::Page::PermissionsPolicyFeatureState>
        feature_state =
            protocol::Page::PermissionsPolicyFeatureState::create()
                .setFeature(blink::PermissionsPolicyFeatureToProtocol(
                    feature, frame->DomWindow()))
                .setAllowed(!locator.has_value())
                .build();

    if (locator.has_value())
      feature_state->setLocator(CreatePermissionsPolicyBlockLocator(*locator));

    feature_states->push_back(std::move(feature_state));
  }

  *states = std::move(feature_states);
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::setDocumentContent(
    const String& frame_id,
    const String& html) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);
  if (!frame)
    return protocol::Response::ServerError("No frame for given id found");

  Document* document = frame->GetDocument();
  if (!document) {
    return protocol::Response::ServerError(
        "No Document instance to set HTML for");
  }
  document->SetContent(html);
  return protocol::Response::Success();
}

namespace {
const char* NavigationTypeToProtocolString(
    mojom::blink::SameDocumentNavigationType navigation_type) {
  switch (navigation_type) {
    case mojom::blink::SameDocumentNavigationType::kFragment:
      return protocol::Page::NavigatedWithinDocument::NavigationTypeEnum::
          Fragment;
    case mojom::blink::SameDocumentNavigationType::kHistoryApi:
      return protocol::Page::NavigatedWithinDocument::NavigationTypeEnum::
          HistoryApi;
    case mojom::blink::SameDocumentNavigationType::kNavigationApiIntercept:
    case mojom::blink::SameDocumentNavigationType::
        kPrerenderNoVarySearchActivation:
      return protocol::Page::NavigatedWithinDocument::NavigationTypeEnum::Other;
  }
}
}  // namespace

void InspectorPageAgent::DidNavigateWithinDocument(
    LocalFrame* frame,
    mojom::blink::SameDocumentNavigationType navigation_type) {
  Document* document = frame->GetDocument();
  if (document) {
    return GetFrontend()->navigatedWithinDocument(
        IdentifiersFactory::FrameId(frame), document->Url(),
        NavigationTypeToProtocolString(navigation_type));
  }
}

DOMWrapperWorld* InspectorPageAgent::EnsureDOMWrapperWorld(
    LocalFrame* frame,
    const String& world_name,
    bool grant_universal_access) {
  if (!isolated_worlds_.Contains(frame))
    isolated_worlds_.Set(frame, MakeGarbageCollected<FrameIsolatedWorlds>());
  FrameIsolatedWorlds& frame_worlds = *isolated_worlds_.find(frame)->value;

  auto world_it = frame_worlds.find(world_name);
  if (world_it != frame_worlds.end())
    return world_it->value;
  LocalDOMWindow* window = frame->DomWindow();
  DOMWrapperWorld* world =
      window->GetScriptController().CreateNewInspectorIsolatedWorld(world_name);
  if (!world)
    return nullptr;
  frame_worlds.Set(world_name, world);
  scoped_refptr<SecurityOrigin> security_origin =
      window->GetSecurityOrigin()->IsolatedCopy();
  if (grant_universal_access)
    security_origin->GrantUniversalAccess();
  DOMWrapperWorld::SetIsolatedWorldSecurityOrigin(world->GetWorldId(),
                                                  security_origin);
  return world;
}

void InspectorPageAgent::DidCreateMainWorldContext(LocalFrame* frame) {
  if (!GetFrontend())
    return;

  for (auto& request : pending_isolated_worlds_.Take(frame)) {
    CreateIsolatedWorldImpl(*frame, request.world_name,
                            request.grant_universal_access,
                            std::move(request.callback));
  }
  Vector<WTF::String> keys = scripts_to_evaluate_on_load_.Keys();
  std::sort(keys.begin(), keys.end(),
            [](const WTF::String& a, const WTF::String& b) {
              return Decimal::FromString(a) < Decimal::FromString(b);
            });

  for (const WTF::String& key : keys) {
    EvaluateScriptOnNewDocument(*frame, key);
  }

  String script = script_injection_on_load_.GetScriptForInjection(
      frame->Loader().GetDocumentLoader()->Url());
  if (script.empty()) {
    return;
  }
  ScriptState* script_state = ToScriptStateForMainWorld(frame);
  if (!script_state || !v8_session_) {
    return;
  }

  v8_session_->evaluate(script_state->GetContext(),
                        ToV8InspectorStringView(script));
}

void InspectorPageAgent::EvaluateScriptOnNewDocument(
    LocalFrame& frame,
    const String& script_identifier) {
  auto* window = frame.DomWindow();
  v8::HandleScope handle_scope(window->GetIsolate());

  ScriptState* script_state = nullptr;
  const String world_name = worlds_to_evaluate_on_load_.Get(script_identifier);
  if (world_name.empty()) {
    script_state = ToScriptStateForMainWorld(window->GetFrame());
  } else if (DOMWrapperWorld* world = EnsureDOMWrapperWorld(
                 &frame, world_name, true /* grant_universal_access */)) {
    script_state =
        ToScriptState(window->GetFrame(),
                      *DOMWrapperWorld::EnsureIsolatedWorld(
                          ToIsolate(window->GetFrame()), world->GetWorldId()));
  }
  if (!script_state || !v8_session_) {
    return;
  }

  v8_session_->evaluate(
      script_state->GetContext(),
      ToV8InspectorStringView(
          scripts_to_evaluate_on_load_.Get(script_identifier)),
      include_command_line_api_for_scripts_to_evaluate_on_load_.Get(
          script_identifier));
}

void InspectorPageAgent::DomContentLoadedEventFired(LocalFrame* frame) {
  double timestamp = base::TimeTicks::Now().since_origin().InSecondsF();
  if (frame == inspected_frames_->Root())
    GetFrontend()->domContentEventFired(timestamp);
  DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  LifecycleEvent(frame, loader, "DOMContentLoaded", timestamp);
}

void InspectorPageAgent::LoadEventFired(LocalFrame* frame) {
  double timestamp = base::TimeTicks::Now().since_origin().InSecondsF();
  if (frame == inspected_frames_->Root())
    GetFrontend()->loadEventFired(timestamp);
  DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  LifecycleEvent(frame, loader, "load", timestamp);
}

void InspectorPageAgent::WillCommitLoad(LocalFrame*, DocumentLoader* loader) {
  if (loader->GetFrame() == inspected_frames_->Root()) {
    script_injection_on_load_.PromoteToLoadOnce();
  }
  GetFrontend()->frameNavigated(BuildObjectForFrame(loader->GetFrame()),
                                protocol::Page::NavigationTypeEnum::Navigation);
  GetFrontend()->flush();
}

void InspectorPageAgent::DidRestoreFromBackForwardCache(LocalFrame* frame) {
  GetFrontend()->frameNavigated(
      BuildObjectForFrame(frame),
      protocol::Page::NavigationTypeEnum::BackForwardCacheRestore);
}

void InspectorPageAgent::DidOpenDocument(LocalFrame* frame,
                                         DocumentLoader* loader) {
  GetFrontend()->documentOpened(BuildObjectForFrame(loader->GetFrame()));
  LifecycleEvent(frame, loader, "init",
                 base::TimeTicks::Now().since_origin().InSecondsF());
}

void InspectorPageAgent::FrameAttachedToParent(
    LocalFrame* frame,
    const std::optional<AdScriptIdentifier>& ad_script_on_stack) {
  // TODO(crbug.com/1217041): If an ad script on the stack caused this frame to
  // be tagged as an ad, send the script's ID to the frontend.
  Frame* parent_frame = frame->Tree().Parent();
  std::unique_ptr<SourceLocation> location =
      SourceLocation::CaptureWithFullStackTrace();
  if (ad_script_on_stack.has_value()) {
    ad_script_identifiers_.Set(
        IdentifiersFactory::FrameId(frame),
        std::make_unique<AdScriptIdentifier>(ad_script_on_stack.value()));
  }
  GetFrontend()->frameAttached(
      IdentifiersFactory::FrameId(frame),
      IdentifiersFactory::FrameId(parent_frame),
      location ? location->BuildInspectorObject() : nullptr);
  // Some network events referencing this frame will be reported from the
  // browser, so make sure to deliver FrameAttached without buffering,
  // so it gets to the front-end first.
  GetFrontend()->flush();
}

void InspectorPageAgent::FrameDetachedFromParent(LocalFrame* frame,
                                                 FrameDetachType type) {
  // If the frame is swapped, we still maintain the ad script id for it.
  if (type == FrameDetachType::kRemove)
    ad_script_identifiers_.erase(IdentifiersFactory::FrameId(frame));

  GetFrontend()->frameDetached(IdentifiersFactory::FrameId(frame),
                               FrameDetachTypeToProtocol(type));
}

void InspectorPageAgent::FrameSubtreeWillBeDetached(Frame* frame) {
  GetFrontend()->frameSubtreeWillBeDetached(IdentifiersFactory::FrameId(frame));
  GetFrontend()->flush();
}

bool InspectorPageAgent::ScreencastEnabled() {
  return enabled_.Get() && screencast_enabled_.Get();
}

void InspectorPageAgent::FrameStoppedLoading(LocalFrame* frame) {
  // The actual event is reported by the browser, but let's make sure
  // earlier events from the commit make their way to client first.
  GetFrontend()->flush();
}

void InspectorPageAgent::FrameRequestedNavigation(Frame* target_frame,
                                                  const KURL& url,
                                                  ClientNavigationReason reason,
                                                  NavigationPolicy policy) {
  // TODO(b:303396822): Support Link Preview
  if (policy == kNavigationPolicyLinkPreview) {
    return;
  }

  GetFrontend()->frameRequestedNavigation(
      IdentifiersFactory::FrameId(target_frame),
      ClientNavigationReasonToProtocol(reason), url.GetString(),
      NavigationPolicyToProtocol(policy));
  GetFrontend()->flush();
}

void InspectorPageAgent::FrameScheduledNavigation(
    LocalFrame* frame,
    const KURL& url,
    base::TimeDelta delay,
    ClientNavigationReason reason) {
  GetFrontend()->frameScheduledNavigation(
      IdentifiersFactory::FrameId(frame), delay.InSecondsF(),
      ClientNavigationReasonToProtocol(reason), url.GetString());
  GetFrontend()->flush();
}

void InspectorPageAgent::FrameClearedScheduledNavigation(LocalFrame* frame) {
  GetFrontend()->frameClearedScheduledNavigation(
      IdentifiersFactory::FrameId(frame));
  GetFrontend()->flush();
}

void InspectorPageAgent::WillRunJavaScriptDialog() {
  GetFrontend()->flush();
}

void InspectorPageAgent::DidRunJavaScriptDialog() {
  GetFrontend()->flush();
}

void InspectorPageAgent::DidResizeMainFrame() {
  if (!inspected_frames_->Root()->IsOutermostMainFrame())
    return;
#if !BUILDFLAG(IS_ANDROID)
  PageLayoutInvalidated(true);
#endif
  GetFrontend()->frameResized();
}

void InspectorPageAgent::DidChangeViewport() {
  PageLayoutInvalidated(false);
}

void InspectorPageAgent::LifecycleEvent(LocalFrame* frame,
                                        DocumentLoader* loader,
                                        const char* name,
                                        double timestamp) {
  if (!loader || !lifecycle_events_enabled_.Get())
    return;
  GetFrontend()->lifecycleEvent(IdentifiersFactory::FrameId(frame),
                                IdentifiersFactory::LoaderId(loader), name,
                                timestamp);
  GetFrontend()->flush();
}

void InspectorPageAgent::PaintTiming(Document* document,
                                     const char* name,
                                     double timestamp) {
  LocalFrame* frame = document->GetFrame();
  DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  LifecycleEvent(frame, loader, name, timestamp);
}

void InspectorPageAgent::Will(const probe::UpdateLayout&) {}

void InspectorPageAgent::Did(const probe::UpdateLayout&) {
  PageLayoutInvalidated(false);
}

void InspectorPageAgent::Will(const probe::RecalculateStyle&) {}

void InspectorPageAgent::Did(const probe::RecalculateStyle&) {
  PageLayoutInvalidated(false);
}

void InspectorPageAgent::PageLayoutInvalidated(bool resized) {
  if (enabled_.Get() && client_)
    client_->PageLayoutInvalidated(resized);
}

void InspectorPageAgent::WindowOpen(const KURL& url,
                                    const AtomicString& window_name,
                                    const WebWindowFeatures& window_features,
                                    bool user_gesture) {
  GetFrontend()->windowOpen(url.IsEmpty() ? BlankURL() : url, window_name,
                            GetEnabledWindowFeatures(window_features),
                            user_gesture);
  GetFrontend()->flush();
}

namespace {
protocol::Page::SecureContextType CreateProtocolSecureContextType(
    SecureContextModeExplanation explanation) {
  switch (explanation) {
    case SecureContextModeExplanation::kSecure:
      return protocol::Page::SecureContextTypeEnum::Secure;
    case SecureContextModeExplanation::kInsecureAncestor:
      return protocol::Page::SecureContextTypeEnum::InsecureAncestor;
    case SecureContextModeExplanation::kInsecureScheme:
      return protocol::Page::SecureContextTypeEnum::InsecureScheme;
    case SecureContextModeExplanation::kSecureLocalhost:
      return protocol::Page::SecureContextTypeEnum::SecureLocalhost;
  }
}
protocol::Page::CrossOriginIsolatedContextType
CreateProtocolCrossOriginIsolatedContextType(ExecutionContext* context) {
  if (context->CrossOriginIsolatedCapability()) {
    return protocol::Page::CrossOriginIsolatedContextTypeEnum::Isolated;
  } else if (context->IsFeatureEnabled(mojom::blink::PermissionsPolicyFeature::
                                           kCrossOriginIsolated)) {
    return protocol::Page::CrossOriginIsolatedContextTypeEnum::NotIsolated;
  }
  return protocol::Page::CrossOriginIsolatedContextTypeEnum::
      NotIsolatedFeatureDisabled;
}
std::unique_ptr<std::vector<protocol::Page::GatedAPIFeatures>>
CreateGatedAPIFeaturesArray(LocalDOMWindow* window) {
  auto features =
      std::make_unique<std::vector<protocol::Page::GatedAPIFeatures>>();
  // SABs are available if at least one of the following is true:
  //  - features::kWebAssemblyThreads enabled
  //  - features::kSharedArrayBuffer enabled
  //  - agent has the cross-origin isolated bit (but not necessarily the
  //    capability)
  if (RuntimeEnabledFeatures::SharedArrayBufferEnabled(window) ||
      Agent::IsCrossOriginIsolated()) {
    features->push_back(
        protocol::Page::GatedAPIFeaturesEnum::SharedArrayBuffers);
  }
  if (window->SharedArrayBufferTransferAllowed()) {
    features->push_back(protocol::Page::GatedAPIFeaturesEnum::
                            SharedArrayBuffersTransferAllowed);
  }
  // TODO(chromium:1139899): Report availablility of performance.measureMemory()
  // and performance.profile() once they are gated/available, respectively.
  return features;
}

protocol::Page::OriginTrialTokenStatus CreateOriginTrialTokenStatus(
    blink::OriginTrialTokenStatus status) {
  switch (status) {
    case blink::OriginTrialTokenStatus::kSuccess:
      return protocol::Page::OriginTrialTokenStatusEnum::Success;
    case blink::OriginTrialTokenStatus::kNotSupported:
      return protocol::Page::OriginTrialTokenStatusEnum::NotSupported;
    case blink::OriginTrialTokenStatus::kInsecure:
      return protocol::Page::OriginTrialTokenStatusEnum::Insecure;
    case blink::OriginTrialTokenStatus::kExpired:
      return protocol::Page::OriginTrialTokenStatusEnum::Expired;
    case blink::OriginTrialTokenStatus::kWrongOrigin:
      return protocol::Page::OriginTrialTokenStatusEnum::WrongOrigin;
    case blink::OriginTrialTokenStatus::kInvalidSignature:
      return protocol::Page::OriginTrialTokenStatusEnum::InvalidSignature;
    case blink::OriginTrialTokenStatus::kMalformed:
      return protocol::Page::OriginTrialTokenStatusEnum::Malformed;
    case blink::OriginTrialTokenStatus::kWrongVersion:
      return protocol::Page::OriginTrialTokenStatusEnum::WrongVersion;
    case blink::OriginTrialTokenStatus::kFeatureDisabled:
      return protocol::Page::OriginTrialTokenStatusEnum::FeatureDisabled;
    case blink::OriginTrialTokenStatus::kTokenDisabled:
      return protocol::Page::OriginTrialTokenStatusEnum::TokenDisabled;
    case blink::OriginTrialTokenStatus::kFeatureDisabledForUser:
      return protocol::Page::OriginTrialTokenStatusEnum::FeatureDisabledForUser;
    case blink::OriginTrialTokenStatus::kUnknownTrial:
      return protocol::Page::OriginTrialTokenStatusEnum::UnknownTrial;
  }
}

protocol::Page::OriginTrialStatus CreateOriginTrialStatus(
    blink::OriginTrialStatus status) {
  switch (status) {
    case blink::OriginTrialStatus::kEnabled:
      return protocol::Page::OriginTrialStatusEnum::Enabled;
    case blink::OriginTrialStatus::kValidTokenNotProvided:
      return protocol::Page::OriginTrialStatusEnum::ValidTokenNotProvided;
    case blink::OriginTrialStatus::kOSNotSupported:
      return protocol::Page::OriginTrialStatusEnum::OSNotSupported;
    case blink::OriginTrialStatus::kTrialNotAllowed:
      return protocol::Page::OriginTrialStatusEnum::TrialNotAllowed;
  }
}

protocol::Page::OriginTrialUsageRestriction CreateOriginTrialUsageRestriction(
    blink::TrialToken::UsageRestriction blink_restriction) {
  switch (blink_restriction) {
    case blink::TrialToken::UsageRestriction::kNone:
      return protocol::Page::OriginTrialUsageRestrictionEnum::None;
    case blink::TrialToken::UsageRestriction::kSubset:
      return protocol::Page::OriginTrialUsageRestrictionEnum::Subset;
  }
}

std::unique_ptr<protocol::Page::OriginTrialToken> CreateOriginTrialToken(
    const blink::TrialToken& blink_trial_token) {
  return protocol::Page::OriginTrialToken::create()
      .setOrigin(SecurityOrigin::CreateFromUrlOrigin(blink_trial_token.origin())
                     ->ToRawString())
      .setIsThirdParty(blink_trial_token.is_third_party())
      .setMatchSubDomains(blink_trial_token.match_subdomains())
      .setExpiryTime(blink_trial_token.expiry_time().InSecondsFSinceUnixEpoch())
      .setTrialName(blink_trial_token.feature_name().c_str())
      .setUsageRestriction(CreateOriginTrialUsageRestriction(
          blink_trial_token.usage_restriction()))
      .build();
}

std::unique_ptr<protocol::Page::OriginTrialTokenWithStatus>
CreateOriginTrialTokenWithStatus(
    const blink::OriginTrialTokenResult& blink_token_result) {
  auto result =
      protocol::Page::OriginTrialTokenWithStatus::create()
          .setRawTokenText(blink_token_result.raw_token)
          .setStatus(CreateOriginTrialTokenStatus(blink_token_result.status))
          .build();

  if (blink_token_result.parsed_token.has_value()) {
    result->setParsedToken(
        CreateOriginTrialToken(*blink_token_result.parsed_token));
  }
  return result;
}

std::unique_ptr<protocol::Page::OriginTrial> CreateOriginTrial(
    const blink::OriginTrialResult& blink_trial_result) {
  auto tokens_with_status = std::make_unique<
      protocol::Array<protocol::Page::OriginTrialTokenWithStatus>>();

  for (const auto& blink_token_result : blink_trial_result.token_results) {
    tokens_with_status->push_back(
        CreateOriginTrialTokenWithStatus(blink_token_result));
  }

  return protocol::Page::OriginTrial::create()
      .setTrialName(blink_trial_result.trial_name)
      .setStatus(CreateOriginTrialStatus(blink_trial_result.status))
      .setTokensWithStatus(std::move(tokens_with_status))
      .build();
}

std::unique_ptr<protocol::Array<protocol::Page::OriginTrial>>
CreateOriginTrials(LocalDOMWindow* window) {
  auto trials =
      std::make_unique<protocol::Array<protocol::Page::OriginTrial>>();
  // Note: `blink::OriginTrialContext` is initialized when
  // `blink::ExecutionContext` is created. `GetOriginTrialContext()` should
  // not return nullptr.
  const blink::OriginTrialContext* context = window->GetOriginTrialContext();
  DCHECK(context);
  for (const auto& entry : context->GetOriginTrialResultsForDevtools()) {
    trials->push_back(CreateOriginTrial(entry.value));
  }
  return trials;
}

protocol::Page::AdFrameType BuildAdFrameType(LocalFrame* frame) {
  if (frame->IsAdRoot())
    return protocol::Page::AdFrameTypeEnum::Root;
  if (frame->IsAdFrame())
    return protocol::Page::AdFrameTypeEnum::Child;
  return protocol::Page::AdFrameTypeEnum::None;
}

std::unique_ptr<protocol::Page::AdFrameStatus> BuildAdFrameStatus(
    LocalFrame* frame) {
  if (!frame->AdEvidence() || !frame->AdEvidence()->is_complete()) {
    return protocol::Page::AdFrameStatus::create()
        .setAdFrameType(protocol::Page::AdFrameTypeEnum::None)
        .build();
  }
  const FrameAdEvidence& evidence = *frame->AdEvidence();
  auto explanations =
      std::make_unique<protocol::Array<protocol::Page::AdFrameExplanation>>();
  if (evidence.parent_is_ad()) {
    explanations->push_back(protocol::Page::AdFrameExplanationEnum::ParentIsAd);
  }
  if (evidence.created_by_ad_script() ==
      mojom::blink::FrameCreationStackEvidence::kCreatedByAdScript) {
    explanations->push_back(
        protocol::Page::AdFrameExplanationEnum::CreatedByAdScript);
  }
  if (evidence.most_restrictive_filter_list_result() ==
      mojom::blink::FilterListResult::kMatchedBlockingRule) {
    explanations->push_back(
        protocol::Page::AdFrameExplanationEnum::MatchedBlockingRule);
  }
  return protocol::Page::AdFrameStatus::create()
      .setAdFrameType(BuildAdFrameType(frame))
      .setExplanations(std::move(explanations))
      .build();
}

}  // namespace

std::unique_ptr<protocol::Page::Frame> InspectorPageAgent::BuildObjectForFrame(
    LocalFrame* frame) {
  DocumentLoader* loader = frame->Loader().GetDocumentLoader();
  // There are some rare cases where no DocumentLoader is set. We use an empty
  // Url and MimeType in those cases. See e.g. https://crbug.com/1270184.
  const KURL url = loader ? loader->Url() : KURL();
  const String mime_type = loader ? loader->MimeType() : String();
  std::unique_ptr<protocol::Page::Frame> frame_object =
      protocol::Page::Frame::create()
          .setId(IdentifiersFactory::FrameId(frame))
          .setLoaderId(IdentifiersFactory::LoaderId(loader))
          .setUrl(UrlWithoutFragment(url).GetString())
          .setDomainAndRegistry(blink::network_utils::GetDomainAndRegistry(
              url.Host(), blink::network_utils::PrivateRegistryFilter::
                              kIncludePrivateRegistries))
          .setMimeType(mime_type)
          .setSecurityOrigin(SecurityOrigin::Create(url)->ToRawString())
          .setSecureContextType(CreateProtocolSecureContextType(
              frame->DomWindow()
                  ->GetSecurityContext()
                  .GetSecureContextModeExplanation()))
          .setCrossOriginIsolatedContextType(
              CreateProtocolCrossOriginIsolatedContextType(frame->DomWindow()))
          .setGatedAPIFeatures(CreateGatedAPIFeaturesArray(frame->DomWindow()))
          .build();
  if (url.HasFragmentIdentifier())
    frame_object->setUrlFragment("#" + url.FragmentIdentifier());
  Frame* parent_frame = frame->Tree().Parent();
  if (parent_frame) {
    frame_object->setParentId(IdentifiersFactory::FrameId(parent_frame));
    AtomicString name = frame->Tree().GetName();
    if (name.empty() && frame->DeprecatedLocalOwner()) {
      name =
          frame->DeprecatedLocalOwner()->FastGetAttribute(html_names::kIdAttr);
    }
    frame_object->setName(name);
  }
  if (loader && !loader->UnreachableURL().IsEmpty())
    frame_object->setUnreachableUrl(loader->UnreachableURL().GetString());
  frame_object->setAdFrameStatus(BuildAdFrameStatus(frame));
  return frame_object;
}

std::unique_ptr<protocol::Page::FrameTree>
InspectorPageAgent::BuildObjectForFrameTree(LocalFrame* frame) {
  std::unique_ptr<protocol::Page::FrameTree> result =
      protocol::Page::FrameTree::create()
          .setFrame(BuildObjectForFrame(frame))
          .build();

  std::unique_ptr<protocol::Array<protocol::Page::FrameTree>> children_array;
  for (Frame* child = frame->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    auto* child_local_frame = DynamicTo<LocalFrame>(child);
    if (!child_local_frame)
      continue;
    if (!children_array) {
      children_array =
          std::make_unique<protocol::Array<protocol::Page::FrameTree>>();
    }
    children_array->emplace_back(BuildObjectForFrameTree(child_local_frame));
  }
  result->setChildFrames(std::move(children_array));
  return result;
}

std::unique_ptr<protocol::Page::FrameResourceTree>
InspectorPageAgent::BuildObjectForResourceTree(LocalFrame* frame) {
  std::unique_ptr<protocol::Page::Frame> frame_object =
      BuildObjectForFrame(frame);
  auto subresources =
      std::make_unique<protocol::Array<protocol::Page::FrameResource>>();

  HeapVector<Member<Resource>> all_resources =
      CachedResourcesForFrame(frame, true);
  for (Resource* cached_resource : all_resources) {
    std::unique_ptr<protocol::Page::FrameResource> resource_object =
        protocol::Page::FrameResource::create()
            .setUrl(UrlWithoutFragment(cached_resource->Url()).GetString())
            .setType(CachedResourceTypeJson(*cached_resource))
            .setMimeType(cached_resource->GetResponse().MimeType())
            .setContentSize(cached_resource->GetResponse().DecodedBodyLength())
            .build();
    std::optional<base::Time> last_modified =
        cached_resource->GetResponse().LastModified(*frame->GetDocument());
    if (last_modified) {
      resource_object->setLastModified(
          last_modified.value().InSecondsFSinceUnixEpoch());
    }
    if (cached_resource->WasCanceled())
      resource_object->setCanceled(true);
    else if (cached_resource->GetStatus() == ResourceStatus::kLoadError)
      resource_object->setFailed(true);
    subresources->emplace_back(std::move(resource_object));
  }

  std::unique_ptr<protocol::Page::FrameResourceTree> result =
      protocol::Page::FrameResourceTree::create()
          .setFrame(std::move(frame_object))
          .setResources(std::move(subresources))
          .build();

  std::unique_ptr<protocol::Array<protocol::Page::FrameResourceTree>>
      children_array;
  for (Frame* child = frame->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    auto* child_local_frame = DynamicTo<LocalFrame>(child);
    if (!child_local_frame)
      continue;
    if (!children_array) {
      children_array = std::make_unique<
          protocol::Array<protocol::Page::FrameResourceTree>>();
    }
    children_array->emplace_back(BuildObjectForResourceTree(child_local_frame));
  }
  result->setChildFrames(std::move(children_array));
  return result;
}

protocol::Response InspectorPageAgent::startScreencast(
    Maybe<String> format,
    Maybe<int> quality,
    Maybe<int> max_width,
    Maybe<int> max_height,
    Maybe<int> every_nth_frame) {
  screencast_enabled_.Set(true);
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::stopScreencast() {
  screencast_enabled_.Set(false);
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::getLayoutMetrics(
    std::unique_ptr<protocol::Page::LayoutViewport>* out_layout_viewport,
    std::unique_ptr<protocol::Page::VisualViewport>* out_visual_viewport,
    std::unique_ptr<protocol::DOM::Rect>* out_content_size,
    std::unique_ptr<protocol::Page::LayoutViewport>* out_css_layout_viewport,
    std::unique_ptr<protocol::Page::VisualViewport>* out_css_visual_viewport,
    std::unique_ptr<protocol::DOM::Rect>* out_css_content_size) {
  LocalFrame* main_frame = inspected_frames_->Root();
  VisualViewport& visual_viewport = main_frame->GetPage()->GetVisualViewport();

  main_frame->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kInspector);

  gfx::Rect visible_contents =
      main_frame->View()->LayoutViewport()->VisibleContentRect();
  *out_layout_viewport = protocol::Page::LayoutViewport::create()
                             .setPageX(visible_contents.x())
                             .setPageY(visible_contents.y())
                             .setClientWidth(visible_contents.width())
                             .setClientHeight(visible_contents.height())
                             .build();

  // LayoutZoomFactor takes CSS pixels to device/physical pixels. It includes
  // both browser ctrl+/- zoom as well as the device scale factor for screen
  // density. Note: we don't account for pinch-zoom, even though it scales a
  // CSS pixel, since "d
"""


```
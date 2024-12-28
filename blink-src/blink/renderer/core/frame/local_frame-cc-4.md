Response:
My thinking process to summarize the provided code snippet goes through these stages:

1. **Understand the Request:** The core request is to summarize the functionality of the provided C++ code snippet from `local_frame.cc` in Chromium's Blink engine. Specifically, I need to identify what it *does*, and relate it to web technologies (JavaScript, HTML, CSS) if applicable, provide examples if there's logical reasoning or potential user/programming errors, and importantly, to note that this is part 5 of a 6-part file.

2. **Initial Scan and Keyword Spotting:** I first quickly scan the code, looking for recognizable function names, variable names, and patterns. Keywords like `SecurityOrigin`, `FinishedLoading`, `FaviconURL`, `Clipboard`, `BackForwardCache`, `ScaleFactor`, `HitTest`, `DownloadURL`, `PostMessageEvent`, `SmartClip`, `SpellChecker`, etc., immediately jump out. These give me initial clues about the areas of functionality covered in this snippet.

3. **Section-by-Section Analysis:**  I then go through the code more deliberately, function by function (or logical block), trying to understand the purpose of each section.

    * **Security Checks:** The initial `CheckCrossOrigin` function clearly deals with verifying if frames have permission to interact based on their origin. I look for how it determines "cross-origin" and what the consequences are (using `UseCounter`).

    * **Loading and Favicon:**  `FinishedLoading` is straightforward, delegating to `DomWindow`. `UpdateFaviconURL` is also clear, retrieving favicon URLs and communicating them to the browser process. This relates directly to HTML's `<link rel="icon">` tag.

    * **Media Capture:** `SetIsCapturingMediaCallback` and `IsCapturingMedia` deal with tracking media capture status. This relates to JavaScript APIs for accessing the camera and microphone.

    * **Clipboard:** `GetSystemClipboard` manages access to the system clipboard. This ties into JavaScript's clipboard API.

    * **Back/Forward Cache:**  Functions like `EvictFromBackForwardCache` and `DidBufferLoadWhileInBackForwardCache` are about managing the browser's back/forward navigation cache for performance.

    * **Zoom/Scale:** `SetScaleFactor` manipulates the page's zoom level, directly impacting CSS layout and rendering.

    * **Focus:** `SetInitialFocus` deals with setting the initial focus on the page, relevant for accessibility and user interaction.

    * **Hit Testing:**  Several functions like `GetCharacterIndexAtPoint` and `HitTestResultForVisualViewportPos` are about determining what element is at a specific point on the screen, crucial for event handling (JavaScript) and context menus.

    * **Window Controls Overlay:** The `#if !BUILDFLAG(IS_ANDROID)` block deals with the window controls overlay on desktop platforms, affecting how much of the webpage is visible and how CSS can style the title bar area. This relates to CSS environment variables.

    * **Prescient Networking:** `PrescientNetworking` seems to be about pre-fetching or optimizing network requests, potentially based on user behavior.

    * **User Activation:** `NotifyUserActivation` is about tracking user interaction for security and feature gating.

    * **Virtual Keyboard Overlay:**  The observer pattern for `virtual_keyboard_overlay_changed_observers_` handles updates to the virtual keyboard's position.

    * **Inspector Integration:** `AddInspectorIssue` allows reporting issues to the browser's developer tools.

    * **Media Actions:** A significant chunk of the code focuses on handling actions on media elements (`HTMLVideoElement`, `HTMLAudioElement`) like copying frames, saving video, and picture-in-picture. These directly relate to HTML5 media elements and their JavaScript API.

    * **Downloads:** `DownloadURL` handles initiating downloads, relating to user initiated downloads or programmatic downloads via JavaScript.

    * **Focus and IME:** `AdvanceFocusForIME` deals with moving focus in the context of Input Method Editors.

    * **`postMessage`:** `PostMessageEvent` implements the cross-document messaging mechanism in web browsers, a key part of web application architecture.

    * **Download Throttling:** `ShouldThrottleDownload` is a performance mechanism to prevent excessive download requests.

    * **Smart Clip:** `ExtractSmartClipDataInternal` is about extracting content (text and HTML) for copy/paste functionality, potentially enhanced with smart selection.

    * **Text Fragments:** The `TextFragmentHandler` and related functions are for handling navigation to specific text within a page, as specified in the URL.

    * **Accessibility and Input:**  `GetSpellChecker`, `GetInputMethodController`, and `GetTextSuggestionController` provide access to browser features for spellchecking, input methods, and text suggestions.

    * **Tracing:** `WriteIntoTrace` is for performance monitoring and debugging.

    * **Blob URLs:** `GetBlobUrlStorePendingRemote` deals with managing Blob URLs.

    * **Back/Forward Cache (again):** `SetNotRestoredReasons` provides information about why a page couldn't be restored from the back/forward cache.

    * **Navigation Confidence:** `SetNavigationConfidence` is likely related to speculative loading or pre-rendering.

    * **Scroll Snapshots:** The section on `scroll_snapshot_clients_` deals with tracking and managing scroll positions, important for features like anchor links and potentially back/forward cache restoration.

    * **Settings and Features:** `ImagesEnabled` and `ScriptEnabled` check if images and JavaScript are enabled based on settings and content policies.

    * **Printing:** `GetPrintParams` retrieves printing parameters.

    * **Keep-Alive:** `IssueKeepAliveHandle` is related to keeping navigations alive.

    * **Link Preview:** The `link_preview_triggerer_` section handles link previews on touch devices.

    * **Storage Access:** `AllowStorageAccessAndNotify` deals with requesting permission to access storage APIs.

4. **Identify Relationships with Web Technologies:** As I analyze each section, I specifically consider how it interacts with JavaScript, HTML, and CSS. This involves thinking about:

    * **JavaScript APIs:** Which JavaScript APIs rely on this functionality? (e.g., `navigator.clipboard`, `window.postMessage`, media element APIs, etc.)
    * **HTML Elements and Attributes:** Which HTML elements or attributes are affected? (e.g., `<img>`, `<video>`, `<link rel="icon">`, etc.)
    * **CSS Properties and Features:** Does this code relate to any CSS properties or features? (e.g., zoom, viewport, environment variables for title bar overlay).

5. **Consider Logical Reasoning and Examples:** Where there's a clear logical flow or decision-making process in the code (like the cross-origin checks), I try to create simple "if-then" scenarios to illustrate the logic. For instance: "If a frame's origin is different from the top-level frame's origin AND it's not in a fenced frame, THEN access will be blocked."

6. **Think About Potential Errors:** I consider what common mistakes a user or programmer might make that would trigger this code or expose its behavior. Examples include: trying to access cross-origin iframes without proper permissions, attempting to download too many files at once, or misusing the `postMessage` API.

7. **Synthesize the Summary:** Finally, I organize my findings into a concise summary, grouping related functionalities together. I use clear and understandable language, avoiding overly technical jargon where possible. I make sure to address all parts of the original request, including the part number.

8. **Review and Refine:** I reread the summary to ensure accuracy, clarity, and completeness. I check if the examples are helpful and if the connections to web technologies are well-explained. I also make sure to incorporate the "Part 5 of 6" information.

By following this structured approach, I can systematically break down the code snippet and generate a comprehensive and informative summary that addresses all aspects of the request.
这是对 `blink/renderer/core/frame/local_frame.cc` 文件代码片段的分析，是第 5 部分，总共 6 部分。 基于此片段，我们可以归纳出以下功能：

**核心功能归纳 (基于此代码片段):**

这个代码片段主要负责 `LocalFrame` 对象的一些核心生命周期管理、安全策略执行、与外部交互以及特定功能实现。  它涵盖了以下几个关键方面：

* **安全性与跨域访问控制:**  检查帧是否允许访问顶层框架的资源，基于同源策略和权限策略。
* **加载完成通知:**  通知 `DomWindow` 框架加载完成。
* **Favicon 管理:**  获取和更新页面的 Favicon URL，并通知浏览器进程。
* **媒体捕获状态管理:**  维护和查询框架是否正在捕获媒体（摄像头、麦克风）。
* **系统剪贴板访问:** 提供访问系统剪贴板的功能。
* **Back/Forward 缓存管理:** 涉及将当前框架从 Back/Forward 缓存中移除，以及记录缓存状态下的加载行为。
* **页面缩放控制:**  允许设置主框架的缩放比例。
* **测试支持:** 提供用于测试目的的关闭页面的接口。
* **焦点管理:**  允许设置初始焦点。
* **Hit Testing (命中测试):**  提供基于屏幕坐标查找元素的机制，用于事件处理和上下文菜单等功能。
* **窗口控制条覆盖 (非 Android):**  处理桌面平台窗口控制条覆盖层的相关逻辑，并通知渲染引擎。
* **Prescient Networking (预知网络):**  提供预先进行网络请求的能力，以提升性能。
* **用户激活通知:**  通知框架发生了用户激活事件。
* **虚拟键盘覆盖通知:**  当虚拟键盘覆盖区域发生变化时通知观察者。
* **Inspector 集成:**  允许向开发者工具报告问题。
* **媒体操作 (例如，复制图片、保存图片、视频控制):**  提供基于屏幕坐标对媒体元素进行操作的功能。
* **下载管理:**  提供下载 URL 的功能，包括处理 data URL。
* **IME 焦点前进:**  辅助输入法编辑器 (IME) 进行焦点管理。
* **`postMessage` 事件处理:**  处理跨域或同域的 `postMessage` 事件。
* **下载节流:**  限制短时间内发起的下载请求数量，以防止滥用。
* **智能剪贴板数据提取:**  提取指定矩形区域的文本和 HTML 内容。
* **文本片段处理:**  管理文本片段识别和滚动到指定文本的功能。
* **拼写检查、输入法和文本建议:**  提供访问拼写检查、输入法和文本建议控制器的接口。
* **性能追踪:**  提供将 `LocalFrame` 的信息写入性能追踪的功能。
* **Blob URL 管理:**  获取用于创建 Blob URL 的接口。
* **窗口控制条区域 CSS 变量 (非 Android):** 设置与窗口控制条覆盖区域相关的 CSS 环境变量。
* **Back/Forward 缓存未恢复原因:**  记录和获取框架无法从 Back/Forward 缓存恢复的原因。
* **导航置信度:** 设置导航操作的置信度。
* **滚动快照客户端管理:**  管理依赖滚动快照的客户端。
* **图像和脚本启用状态检查:**  检查图像和脚本是否已启用。
* **打印参数获取:**  获取打印相关的参数。
* **Keep-Alive 句柄:**  发放用于保持导航状态的句柄。
* **链接预览触发器:**  管理链接预览的触发。
* **存储访问授权通知:**  处理存储访问权限请求的回调。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    * **`window.postMessage()`:** `PostMessageEvent` 函数直接处理来自 JavaScript 的 `postMessage` 调用，允许不同源的页面之间安全地传递信息。
        * **假设输入:**  一个来自 `http://example.com` 的 iframe 调用 `parent.postMessage("hello", "http://main.com")`。
        * **输出:** `LocalFrame::PostMessageEvent` 将接收到消息内容 "hello"、源 origin `http://example.com`、目标 origin `http://main.com`，并创建一个 `MessageEvent` 派发到主框架的 `DomWindow`。
    * **`navigator.clipboard`:** `GetSystemClipboard()` 用于获取系统剪贴板对象，这是 JavaScript 访问剪贴板 API 的基础。
    * **Media API (`<video>`, `<audio>`):** `MediaPlayerActionAtViewportPoint` 处理对视频和音频元素的操作，如循环播放、显示/隐藏控制栏、保存视频帧等，这些都是 JavaScript 可以控制的媒体元素属性和方法。
    * **`document.querySelector()` 和事件处理:** `HitTestResultForVisualViewportPos` 用于查找特定坐标的元素，这对于 JavaScript 事件处理至关重要，例如点击事件发生时需要知道点击了哪个元素。
    * **`requestAnimationFrame` (间接):** `ScheduleNextServiceForScrollSnapshotClients` 中调用 `View()->ScheduleAnimation()`，最终会触发 `requestAnimationFrame` 回调，用于处理滚动相关的动画或更新。
    * **`TextFragment` API:** `BindTextFragmentReceiver` 和 `TextFragmentHandler` 与浏览器处理 URL 中的文本片段标识符 (例如 `#:~:text=some,text`) 相关，允许直接滚动到页面上的特定文本。

* **HTML:**
    * **`<link rel="icon">`:** `UpdateFaviconURL`  根据 HTML 中 `<link>` 标签定义的 favicon URL 更新浏览器的标签页图标。
    * **`<img>` 和 `<canvas>`:** `CopyImageAtViewportPoint` 和 `SaveImageAt` 处理复制和保存图片的操作，这些图片可能来自 `<img>` 标签或 `<canvas>` 元素。
    * **`<video>` 和 `<audio>`:**  如上所述，`MediaPlayerActionAtViewportPoint` 直接操作这些 HTML5 媒体元素。

* **CSS:**
    * **Viewport 和缩放:** `SetScaleFactor` 直接影响页面的布局和渲染，与 CSS 的 viewport 元标签和缩放属性相关。
    * **CSS 环境变量:**  `SetTitlebarAreaDocumentStyleEnvironmentVariables` (非 Android) 设置了可以被 CSS 使用的与窗口控制条覆盖区域相关的环境变量，允许开发者根据窗口状态调整样式。 例如，可以使用 `env(titlebar-area-x)` 获取窗口控制条的 X 坐标。

**逻辑推理的假设输入与输出:**

* **假设输入 (CheckCrossOrigin):**
    * 当前框架的 `SecurityOrigin` 为 `http://sub.example.com`。
    * 顶层框架的 `SecurityOrigin` 为 `http://example.com`。
    * 当前框架不在 fenced frame 树中。
* **输出 (CheckCrossOrigin):** 函数不会提前返回，因为子域可以访问父域（在没有更严格的策略干预的情况下）。

* **假设输入 (ShouldThrottleDownload):**  用户在 0.5 秒内尝试下载 6 个文件。 `kBurstDownloadLimit` 假设为 5。
* **输出 (ShouldThrottleDownload):**  前 5 个下载请求将返回 `false` (不节流)，第 6 个下载请求将返回 `true` (节流)。

**用户或编程常见的使用错误举例:**

* **跨域 `postMessage` 错误:**  开发者在调用 `postMessage` 时指定了错误的目标 origin，导致消息无法送达。例如，iframe 来自 `http://iframe.com`，主框架是 `http://main.com`，iframe 调用 `parent.postMessage("data", "http://wrong.com")`，主框架将无法收到消息。
* **未检查图像加载完成就尝试复制:** 开发者可能在 JavaScript 中尝试复制一个尚未完全加载的图片，导致 `CopyImageAtViewportPoint` 中获取到的图片数据不完整或为空。
* **频繁下载导致节流:** 用户或恶意脚本在短时间内发起大量下载请求，可能会触发 `ShouldThrottleDownload` 的节流机制，导致后续下载被延迟或阻止，这可能会让用户感到困惑。开发者应该注意避免在短时间内发起过多的下载请求。
* **错误地假设 Back/Forward 缓存总是可用:** 开发者可能会依赖 Back/Forward 缓存来恢复页面状态，但由于各种原因（例如，页面使用了 `no-store` 缓存指令，或者被 `EvictFromBackForwardCache` 移除），缓存可能不可用，导致页面重新加载，状态丢失。

**总结此部分的功能:**

总的来说，这个代码片段主要集中在 `LocalFrame` 的安全性和与浏览器其他部分（如浏览器进程、开发者工具）的集成，以及一些核心的功能实现，例如页面加载完成通知、Favicon 管理、媒体操作、下载管理和跨域消息传递。 它也处理了一些与用户交互相关的功能，如焦点管理和剪贴板访问。 这部分代码是 `LocalFrame` 类功能实现的重要组成部分，负责维护框架的基本行为和与其他组件的协作。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
ityContext()->GetSecurityOrigin();

  // Check if this frame is same-origin with the top-level or is in
  // a fenced frame tree.
  if (!GetSecurityContext()->GetSecurityOrigin()->CanAccess(topOrigin) ||
      IsInFencedFrameTree()) {
    // This frame is cross-origin with the top-level frame, and so would be
    // blocked without a permissions policy.
    UseCounter::Count(GetDocument(), blocked_cross_origin);
    return;
  }

  // Walk up the frame tree looking for any cross-origin embeds. Even if this
  // frame is same-origin with the top-level, if it is embedded by a cross-
  // origin frame (like A->B->A) it would be blocked without a permissions
  // policy.
  const Frame* f = this;
  while (!f->IsMainFrame()) {
    if (!f->GetSecurityContext()->GetSecurityOrigin()->CanAccess(topOrigin)) {
      UseCounter::Count(GetDocument(), blocked_same_origin);
      return;
    }
    f = f->Tree().Parent();
  }
}

void LocalFrame::FinishedLoading(FrameLoader::NavigationFinishState state) {
  DomWindow()->FinishedLoading(state);
}

void LocalFrame::UpdateFaviconURL() {
  if (!IsMainFrame())
    return;

  // The URL to the icon may be in the header. As such, only
  // ask the loader for the icon if it's finished loading.
  if (!GetDocument()->LoadEventFinished())
    return;

  int icon_types_mask =
      1 << static_cast<int>(mojom::blink::FaviconIconType::kFavicon) |
      1 << static_cast<int>(mojom::blink::FaviconIconType::kTouchIcon) |
      1 << static_cast<int>(
          mojom::blink::FaviconIconType::kTouchPrecomposedIcon);
  Vector<IconURL> icon_urls = GetDocument()->IconURLs(icon_types_mask);
  if (icon_urls.empty())
    return;

  Vector<mojom::blink::FaviconURLPtr> urls;
  urls.reserve(icon_urls.size());
  for (const auto& icon_url : icon_urls) {
    urls.push_back(mojom::blink::FaviconURL::New(
        icon_url.icon_url_, icon_url.icon_type_, icon_url.sizes_,
        icon_url.is_default_icon_));
  }
  DCHECK_EQ(icon_urls.size(), urls.size());

  GetLocalFrameHostRemote().UpdateFaviconURL(std::move(urls));

  if (GetPage())
    GetPage()->GetPageScheduler()->OnTitleOrFaviconUpdated();
}

void LocalFrame::SetIsCapturingMediaCallback(
    IsCapturingMediaCallback callback) {
  is_capturing_media_callback_ = std::move(callback);
}

bool LocalFrame::IsCapturingMedia() const {
  return is_capturing_media_callback_ ? is_capturing_media_callback_.Run()
                                      : false;
}

SystemClipboard* LocalFrame::GetSystemClipboard() {
  if (!system_clipboard_)
    system_clipboard_ = MakeGarbageCollected<SystemClipboard>(this);

  return system_clipboard_.Get();
}

void LocalFrame::WasAttachedAsLocalMainFrame() {
  mojo_handler_->WasAttachedAsLocalMainFrame();
}

void LocalFrame::EvictFromBackForwardCache(
    mojom::blink::RendererEvictionReason reason,
    std::unique_ptr<SourceLocation> source_location) {
  if (!GetPage()->GetPageScheduler()->IsInBackForwardCache())
    return;
  UMA_HISTOGRAM_ENUMERATION("BackForwardCache.Eviction.Renderer", reason);
  mojom::blink::ScriptSourceLocationPtr source = nullptr;
  if (source_location) {
    source = mojom::blink::ScriptSourceLocation::New(
        source_location->Url() ? KURL(source_location->Url()) : KURL(),
        source_location->Function() ? source_location->Function() : "",
        source_location->LineNumber(), source_location->ColumnNumber());
  }
  GetBackForwardCacheControllerHostRemote().EvictFromBackForwardCache(
      std::move(reason), std::move(source));
}

void LocalFrame::DidBufferLoadWhileInBackForwardCache(
    bool update_process_wide_count,
    size_t num_bytes) {
  DomWindow()->DidBufferLoadWhileInBackForwardCache(update_process_wide_count,
                                                    num_bytes);
}

void LocalFrame::SetScaleFactor(float scale_factor) {
  DCHECK(!GetDocument() || !GetDocument()->Printing());
  DCHECK(IsMainFrame());

  const PageScaleConstraints& constraints =
      GetPage()->GetPageScaleConstraintsSet().FinalConstraints();
  scale_factor = constraints.ClampToConstraints(scale_factor);
  if (scale_factor == GetPage()->GetVisualViewport().Scale())
    return;
  GetPage()->GetVisualViewport().SetScale(scale_factor);
}

void LocalFrame::ClosePageForTesting() {
  mojo_handler_->ClosePageForTesting();
}

void LocalFrame::SetInitialFocus(bool reverse) {
  GetDocument()->ClearFocusedElement();
  GetPage()->GetFocusController().SetInitialFocus(
      reverse ? mojom::blink::FocusType::kBackward
              : mojom::blink::FocusType::kForward);
}

#if BUILDFLAG(IS_MAC)
void LocalFrame::GetCharacterIndexAtPoint(const gfx::Point& point) {
  HitTestLocation location(View()->ViewportToFrame(gfx::Point(point)));
  HitTestResult result = GetEventHandler().HitTestResultAtLocation(
      location, HitTestRequest::kReadOnly | HitTestRequest::kActive);
  uint32_t index =
      Selection().CharacterIndexForPoint(result.RoundedPointInInnerNodeFrame());
  mojo_handler_->TextInputHost().GotCharacterIndexAtPoint(index);
}
#endif

#if !BUILDFLAG(IS_ANDROID)
void LocalFrame::UpdateWindowControlsOverlay(
    const gfx::Rect& bounding_rect_in_dips) {
  // The rect passed to us from content is in DIP screen space, relative to the
  // main frame, and needs to move to CSS space. This doesn't take the page's
  // zoom factor into account so we must scale by the inverse of the page zoom
  // in order to get correct CSS space coordinates. Note that when
  // use-zoom-for-dsf is enabled, WindowToViewportScalar will be the true device
  // scale factor, and LayoutZoomFactor will be the combination of the device
  // scale factor and the zoom percent of the page. It is preferable to compute
  // a rect that is slightly larger than one that would render smaller than the
  // window control overlay.
  LocalFrame& local_frame_root = LocalFrameRoot();
  const float window_to_viewport_factor =
      GetPage()->GetChromeClient().WindowToViewportScalar(&local_frame_root,
                                                          1.0f);
  const float zoom_factor = local_frame_root.LayoutZoomFactor();
  const float scale_factor = zoom_factor / window_to_viewport_factor;
  gfx::Rect window_controls_overlay_rect =
      gfx::ScaleToEnclosingRect(bounding_rect_in_dips, 1.0f / scale_factor);

  bool fire_event =
      (window_controls_overlay_rect != window_controls_overlay_rect_);
  is_window_controls_overlay_visible_ = !window_controls_overlay_rect.IsEmpty();
  window_controls_overlay_rect_ = window_controls_overlay_rect;
  window_controls_overlay_rect_in_dips_ = bounding_rect_in_dips;

  DocumentStyleEnvironmentVariables& vars =
      GetDocument()->GetStyleEngine().EnsureEnvironmentVariables();

  if (is_window_controls_overlay_visible_) {
    SetTitlebarAreaDocumentStyleEnvironmentVariables();
  } else {
    const UADefinedVariable vars_to_remove[] = {
        UADefinedVariable::kTitlebarAreaX,
        UADefinedVariable::kTitlebarAreaY,
        UADefinedVariable::kTitlebarAreaWidth,
        UADefinedVariable::kTitlebarAreaHeight,
    };
    for (auto var_to_remove : vars_to_remove) {
      vars.RemoveVariable(var_to_remove);
    }
  }

  if (fire_event && window_controls_overlay_changed_delegate_) {
    window_controls_overlay_changed_delegate_->WindowControlsOverlayChanged(
        window_controls_overlay_rect_);
  }
}

void LocalFrame::RegisterWindowControlsOverlayChangedDelegate(
    WindowControlsOverlayChangedDelegate* delegate) {
  window_controls_overlay_changed_delegate_ = delegate;
}
#endif

HitTestResult LocalFrame::HitTestResultForVisualViewportPos(
    const gfx::Point& pos_in_viewport) {
  gfx::Point root_frame_point(
      GetPage()->GetVisualViewport().ViewportToRootFrame(pos_in_viewport));
  HitTestLocation location(View()->ConvertFromRootFrame(root_frame_point));
  HitTestResult result = GetEventHandler().HitTestResultAtLocation(
      location, HitTestRequest::kReadOnly | HitTestRequest::kActive);
  result.SetToShadowHostIfInUAShadowRoot();
  return result;
}

void LocalFrame::DidChangeVisibleToHitTesting() {
  // LayoutEmbeddedContent does not propagate style updates to descendants.
  // Need to update the field manually.
  for (Frame* child = Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    child->UpdateVisibleToHitTesting();
  }

  // The transform property tree node depends on visibility.
  if (auto* view = View()->GetLayoutView()) {
    view->SetNeedsPaintPropertyUpdate();
  }
}

WebPrescientNetworking* LocalFrame::PrescientNetworking() {
  if (!prescient_networking_) {
    WebLocalFrameImpl* web_local_frame = WebLocalFrameImpl::FromFrame(this);
    // There is no valid WebLocalFrame, return a nullptr to ignore pre* hints.
    if (!web_local_frame)
      return nullptr;
    prescient_networking_ =
        web_local_frame->Client()->CreatePrescientNetworking();
  }
  return prescient_networking_.get();
}

void LocalFrame::SetPrescientNetworkingForTesting(
    std::unique_ptr<WebPrescientNetworking> prescient_networking) {
  prescient_networking_ = std::move(prescient_networking);
}

mojom::blink::LocalFrameHost& LocalFrame::GetLocalFrameHostRemote() const {
  return mojo_handler_->LocalFrameHostRemote();
}

mojom::blink::BackForwardCacheControllerHost&
LocalFrame::GetBackForwardCacheControllerHostRemote() {
  return mojo_handler_->BackForwardCacheControllerHostRemote();
}

void LocalFrame::NotifyUserActivation(
    mojom::blink::UserActivationNotificationType notification_type) {
  NotifyUserActivation(notification_type, false);
}

void LocalFrame::RegisterVirtualKeyboardOverlayChangedObserver(
    VirtualKeyboardOverlayChangedObserver* observer) {
  virtual_keyboard_overlay_changed_observers_.insert(observer);
}

void LocalFrame::NotifyVirtualKeyboardOverlayRectObservers(
    const gfx::Rect& rect) const {
  HeapVector<Member<VirtualKeyboardOverlayChangedObserver>, 32> observers(
      virtual_keyboard_overlay_changed_observers_);
  for (VirtualKeyboardOverlayChangedObserver* observer : observers)
    observer->VirtualKeyboardOverlayChanged(rect);
}

void LocalFrame::AddInspectorIssue(AuditsIssue info) {
  if (GetPage()) {
    GetPage()->GetInspectorIssueStorage().AddInspectorIssue(DomWindow(),
                                                            std::move(info));
  }
}

void LocalFrame::CopyImageAtViewportPoint(const gfx::Point& viewport_point) {
  HitTestResult result = HitTestResultForVisualViewportPos(viewport_point);
  if (!IsA<HTMLCanvasElement>(result.InnerNodeOrImageMapImage()) &&
      result.AbsoluteImageURL().IsEmpty()) {
    // There isn't actually an image at these coordinates.  Might be because
    // the window scrolled while the context menu was open or because the page
    // changed itself between when we thought there was an image here and when
    // we actually tried to retrieve the image.
    //
    // FIXME: implement a cache of the most recent HitTestResult to avoid having
    //        to do two hit tests.
    return;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  GetEditor().CopyImage(result);
}

void LocalFrame::SaveImageAt(const gfx::Point& window_point) {
  gfx::Point viewport_position =
      GetWidgetForLocalRoot()->DIPsToRoundedBlinkSpace(window_point);
  Node* node = HitTestResultForVisualViewportPos(viewport_position)
                   .InnerNodeOrImageMapImage();
  if (!node || !(IsA<HTMLCanvasElement>(*node) || IsA<HTMLImageElement>(*node)))
    return;

  String url = To<Element>(*node).ImageSourceURL();
  if (!KURL(NullURL(), url).ProtocolIsData())
    return;

  auto params = mojom::blink::DownloadURLParams::New();
  params->is_context_menu_save = true;
  params->data_url_blob = DataURLToBlob(url);
  GetLocalFrameHostRemote().DownloadURL(std::move(params));
}

void LocalFrame::MediaPlayerActionAtViewportPoint(
    const gfx::Point& viewport_position,
    const mojom::blink::MediaPlayerActionType type,
    bool enable) {
  HitTestResult result = HitTestResultForVisualViewportPos(viewport_position);
  Node* node = result.InnerNode();
  if (!IsA<HTMLVideoElement>(*node) && !IsA<HTMLAudioElement>(*node))
    return;

  auto* media_element = To<HTMLMediaElement>(node);
  switch (type) {
    case mojom::blink::MediaPlayerActionType::kLoop:
      media_element->SetLoop(enable);
      break;
    case mojom::blink::MediaPlayerActionType::kControls:
      media_element->SetUserWantsControlsVisible(enable);
      break;
    case mojom::blink::MediaPlayerActionType::kSaveVideoFrameAs:
      if (auto* video = DynamicTo<HTMLVideoElement>(media_element); video) {
        auto image = video->CreateStaticBitmapImage();
        if (!image) {
          return;
        }
        auto data_buffer = ImageDataBuffer::Create(image);
        if (!data_buffer) {
          return;
        }

        ImageEncodingMimeType encoding_mime_type =
            ImageEncoderUtils::ToEncodingMimeType(
                "image/png", ImageEncoderUtils::kEncodeReasonToDataURL);
        String data_url =
            data_buffer->ToDataURL(encoding_mime_type, /*quality=*/0);

        auto params = mojom::blink::DownloadURLParams::New();
        params->is_context_menu_save = true;
        // Suggested name always starts with "videoframe_", plus the timestamp
        // of the video frame in milliseconds.
        auto timestamp_ms = base::saturated_cast<uint32_t>(
            media_element->currentTime() * base::Time::kMillisecondsPerSecond);
        params->suggested_name = "videoframe_" + String::Number(timestamp_ms);
        params->data_url_blob = DataURLToBlob(data_url);
        GetLocalFrameHostRemote().DownloadURL(std::move(params));
      }
      break;
    case mojom::blink::MediaPlayerActionType::kCopyVideoFrame:
      if (auto* video = DynamicTo<HTMLVideoElement>(media_element); video) {
        auto image = video->CreateStaticBitmapImage();
        if (image) {
          GetEditor().CopyImage(result, image);
        }
      }
      break;
    case mojom::blink::MediaPlayerActionType::kPictureInPicture:
      if (auto* video = DynamicTo<HTMLVideoElement>(media_element); video) {
        if (enable) {
          PictureInPictureController::From(node->GetDocument())
              .EnterPictureInPicture(video, /*promise=*/nullptr);
        } else {
          PictureInPictureController::From(node->GetDocument())
              .ExitPictureInPicture(video, nullptr);
        }
      }
      break;
  }
}

void LocalFrame::RequestVideoFrameAtWithBoundsHint(
    const gfx::Point& viewport_position,
    const gfx::Size& max_size,
    int max_area,
    base::OnceCallback<void(const SkBitmap&, const gfx::Rect&)> callback) {
  HitTestResult result = HitTestResultForVisualViewportPos(viewport_position);
  Node* node = result.InnerNode();
  auto* video = DynamicTo<HTMLVideoElement>(node);

  if (!video) {
    std::move(callback).Run(SkBitmap(), gfx::Rect());
    return;
  }

  // Scale to match the max dimensions if needed, to reduce data sent over IPC.
  // This is to match the algorithm in gfx::ResizedImageForMaxDimensions().
  // TODO(crbug.com/1508722): Revisit to see whether we need both `max_size` and
  // `max_area`, which seems redundant.
  auto size = video->BitmapSourceSize();
  if ((size.width() > max_size.width() || size.height() > max_size.height()) &&
      size.GetArea() > max_area) {
    double scale =
        std::min(static_cast<double>(max_size.width()) / size.width(),
                 static_cast<double>(max_size.height()) / size.height());
    int width = std::clamp<int>(scale * size.width(), 1, max_size.width());
    int height = std::clamp<int>(scale * size.height(), 1, max_size.height());
    size = gfx::Size(width, height);
  }

  auto image =
      video->CreateStaticBitmapImage(/*allow_accelerated_images=*/true, size);
  if (!image) {
    std::move(callback).Run(SkBitmap(), gfx::Rect());
    return;
  }

  auto bitmap = image->AsSkBitmapForCurrentFrame(kRespectImageOrientation);

  // Only kN32_SkColorType bitmaps can be sent across IPC, so convert if
  // necessary.
  SkBitmap converted_bitmap;
  if (bitmap.colorType() == kN32_SkColorType) {
    converted_bitmap = bitmap;
  } else {
    SkImageInfo info = bitmap.info().makeColorType(kN32_SkColorType);
    if (converted_bitmap.tryAllocPixels(info)) {
      bitmap.readPixels(info, converted_bitmap.getPixels(),
                        converted_bitmap.rowBytes(), 0, 0);
    }
  }

  // Get the bounds of the video element.
  WebNode web_node(node);
  WebElement web_element = web_node.To<WebElement>();
  auto bounds = web_element.BoundsInWidget();

  std::move(callback).Run(converted_bitmap, bounds);
}

void LocalFrame::DownloadURL(
    const ResourceRequest& request,
    network::mojom::blink::RedirectMode cross_origin_redirect_behavior) {
  mojo::PendingRemote<mojom::blink::BlobURLToken> blob_url_token;
  if (request.Url().ProtocolIs("blob")) {
    DomWindow()->GetPublicURLManager().Resolve(
        request.Url(), blob_url_token.InitWithNewPipeAndPassReceiver());
  }

  DownloadURL(request, cross_origin_redirect_behavior,
              std::move(blob_url_token));
}

void LocalFrame::DownloadURL(
    const ResourceRequest& request,
    network::mojom::blink::RedirectMode cross_origin_redirect_behavior,
    mojo::PendingRemote<mojom::blink::BlobURLToken> blob_url_token) {
  if (ShouldThrottleDownload())
    return;

  auto params = mojom::blink::DownloadURLParams::New();
  const KURL& url = request.Url();
  // Pass data URL through blob.
  if (url.ProtocolIs("data")) {
    params->url = KURL();
    params->data_url_blob = DataURLToBlob(url.GetString());
  } else {
    params->url = url;
  }

  params->referrer = mojom::blink::Referrer::New();
  params->referrer->url = KURL(request.ReferrerString());
  params->referrer->policy = request.GetReferrerPolicy();
  params->initiator_origin = request.RequestorOrigin();
  if (request.GetSuggestedFilename().has_value())
    params->suggested_name = *request.GetSuggestedFilename();
  params->cross_origin_redirects = cross_origin_redirect_behavior;
  params->blob_url_token = std::move(blob_url_token);
  params->has_user_gesture = request.HasUserGesture();

  GetLocalFrameHostRemote().DownloadURL(std::move(params));
}

void LocalFrame::AdvanceFocusForIME(mojom::blink::FocusType focus_type) {
  auto* focused_frame = GetPage()->GetFocusController().FocusedFrame();
  if (focused_frame != this)
    return;

  DCHECK(GetDocument());
  Element* element = GetDocument()->FocusedElement();
  if (!element)
    return;

  Element* next_element =
      GetPage()->GetFocusController().NextFocusableElementForImeAndAutofill(
          element, focus_type);
  if (!next_element)
    return;

  next_element->scrollIntoViewIfNeeded(true /*centerIfNeeded*/);
  next_element->Focus(FocusParams(FocusTrigger::kUserGesture));
}

void LocalFrame::PostMessageEvent(
    const std::optional<RemoteFrameToken>& source_frame_token,
    const String& source_origin,
    const String& target_origin,
    BlinkTransferableMessage message) {
  TRACE_EVENT0("blink", "LocalFrame::PostMessageEvent");
  RemoteFrame* source_frame = SourceFrameForOptionalToken(source_frame_token);

  // We must pass in the target_origin to do the security check on this side,
  // since it may have changed since the original postMessage call was made.
  scoped_refptr<SecurityOrigin> target_security_origin;
  if (!target_origin.empty()) {
    target_security_origin = SecurityOrigin::CreateFromString(target_origin);
  }

  // Preparation of the MessageEvent.
  MessageEvent* message_event = MessageEvent::Create();
  DOMWindow* window = nullptr;
  if (source_frame)
    window = source_frame->DomWindow();
  MessagePortArray* ports = nullptr;
  if (GetDocument()) {
    ports = MessagePort::EntanglePorts(*GetDocument()->GetExecutionContext(),
                                       std::move(message.ports));
  }

  // The |message.user_activation| only conveys the sender |Frame|'s user
  // activation state to receiver JS.  This is never used for activating the
  // receiver (or any other) |Frame|.
  UserActivation* user_activation = nullptr;
  if (message.user_activation) {
    user_activation = MakeGarbageCollected<UserActivation>(
        message.user_activation->has_been_active,
        message.user_activation->was_active);
  }

  message_event->initMessageEvent(
      event_type_names::kMessage, false, false, std::move(message.message),
      source_origin, "" /*lastEventId*/, window, ports, user_activation,
      message.delegated_capability);

  // If the agent cluster id had a value it means this was locked when it
  // was serialized.
  if (message.locked_to_sender_agent_cluster)
    message_event->LockToAgentCluster();

  // Finally dispatch the message to the DOM Window.
  DomWindow()->DispatchMessageEventWithOriginCheck(
      target_security_origin.get(), message_event,
      std::make_unique<SourceLocation>(String(), String(), 0, 0, nullptr),
      message.sender_agent_cluster_id);
}

bool LocalFrame::ShouldThrottleDownload() {
  const auto now = base::TimeTicks::Now();
  if (num_burst_download_requests_ == 0) {
    burst_download_start_time_ = now;
  } else if (num_burst_download_requests_ >= kBurstDownloadLimit) {
    static constexpr auto kBurstDownloadLimitResetInterval = base::Seconds(1);
    if (now - burst_download_start_time_ > kBurstDownloadLimitResetInterval) {
      num_burst_download_requests_ = 1;
      burst_download_start_time_ = now;
      return false;
    }
    return true;
  }

  num_burst_download_requests_++;
  return false;
}

#if BUILDFLAG(IS_MAC)
void LocalFrame::ResetTextInputHostForTesting() {
  mojo_handler_->ResetTextInputHostForTesting();
}

void LocalFrame::RebindTextInputHostForTesting() {
  mojo_handler_->RebindTextInputHostForTesting();
}
#endif

Frame* LocalFrame::GetProvisionalOwnerFrame() {
  DCHECK(IsProvisional());
  if (Owner()) {
    // Since `this` is a provisional frame, its owner's `ContentFrame()` will
    // be the old LocalFrame.
    return Owner()->ContentFrame();
  }
  return GetPage()->MainFrame();
}

namespace {

// TODO(editing-dev): We should move |CreateMarkupInRect()| to
// "core/editing/serializers/Serialization.cpp".
String CreateMarkupInRect(LocalFrame* frame,
                          const gfx::Point& start_point,
                          const gfx::Point& end_point) {
  VisiblePosition start_visible_position = CreateVisiblePosition(
      PositionForContentsPointRespectingEditingBoundary(start_point, frame));
  VisiblePosition end_visible_position = CreateVisiblePosition(
      PositionForContentsPointRespectingEditingBoundary(end_point, frame));

  Position start_position = start_visible_position.DeepEquivalent();
  Position end_position = end_visible_position.DeepEquivalent();

  // document() will return null if -webkit-user-select is set to none.
  if (!start_position.GetDocument() || !end_position.GetDocument())
    return String();

  const CreateMarkupOptions create_markup_options =
      CreateMarkupOptions::Builder()
          .SetShouldAnnotateForInterchange(true)
          .SetShouldResolveURLs(kResolveNonLocalURLs)
          .Build();
  if (start_position.CompareTo(end_position) <= 0) {
    return CreateMarkup(start_position, end_position, create_markup_options);
  }
  return CreateMarkup(end_position, start_position, create_markup_options);
}

}  // namespace

void LocalFrame::ExtractSmartClipDataInternal(const gfx::Rect& rect_in_viewport,
                                              String& clip_text,
                                              String& clip_html,
                                              gfx::Rect& clip_rect) {
  // TODO(mahesh.ma): Check clip_data even after use-zoom-for-dsf is enabled.
  SmartClipData clip_data = SmartClip(this).DataForRect(rect_in_viewport);
  clip_text = clip_data.ClipData();
  clip_rect = clip_data.RectInViewport();

  gfx::Point start_point(rect_in_viewport.x(), rect_in_viewport.y());
  gfx::Point end_point(rect_in_viewport.x() + rect_in_viewport.width(),
                       rect_in_viewport.y() + rect_in_viewport.height());
  clip_html = CreateMarkupInRect(this, View()->ViewportToFrame(start_point),
                                 View()->ViewportToFrame(end_point));
}

void LocalFrame::CreateTextFragmentHandler() {
  text_fragment_handler_ = MakeGarbageCollected<TextFragmentHandler>(this);
}

void LocalFrame::BindTextFragmentReceiver(
    mojo::PendingReceiver<mojom::blink::TextFragmentReceiver> receiver) {
  if (IsDetached())
    return;

  if (!text_fragment_handler_)
    CreateTextFragmentHandler();

  text_fragment_handler_->BindTextFragmentReceiver(std::move(receiver));
}

SpellChecker& LocalFrame::GetSpellChecker() const {
  DCHECK(DomWindow());
  return DomWindow()->GetSpellChecker();
}

InputMethodController& LocalFrame::GetInputMethodController() const {
  DCHECK(DomWindow());
  return DomWindow()->GetInputMethodController();
}

TextSuggestionController& LocalFrame::GetTextSuggestionController() const {
  DCHECK(DomWindow());
  return DomWindow()->GetTextSuggestionController();
}

void LocalFrame::WriteIntoTrace(perfetto::TracedValue ctx) const {
  perfetto::TracedDictionary dict = std::move(ctx).WriteDictionary();
  dict.Add("document", GetDocument());
  dict.Add("is_main_frame", IsMainFrame());
  dict.Add("is_outermost_main_frame", IsOutermostMainFrame());
  dict.Add("is_cross_origin_to_parent", IsCrossOriginToParentOrOuterDocument());
  dict.Add("is_cross_origin_to_outermost_main_frame",
           IsCrossOriginToOutermostMainFrame());
}

mojo::PendingRemote<mojom::blink::BlobURLStore>
LocalFrame::GetBlobUrlStorePendingRemote() {
  mojo::PendingRemote<mojom::blink::BlobURLStore> pending_remote;
  GetBrowserInterfaceBroker().GetInterface(
      pending_remote.InitWithNewPipeAndPassReceiver());
  return pending_remote;
}

#if !BUILDFLAG(IS_ANDROID)
void LocalFrame::SetTitlebarAreaDocumentStyleEnvironmentVariables() const {
  DCHECK(is_window_controls_overlay_visible_);
  DocumentStyleEnvironmentVariables& vars =
      GetDocument()->GetStyleEngine().EnsureEnvironmentVariables();
  vars.SetVariable(
      UADefinedVariable::kTitlebarAreaX,
      StyleEnvironmentVariables::FormatPx(window_controls_overlay_rect_.x()));
  vars.SetVariable(
      UADefinedVariable::kTitlebarAreaY,
      StyleEnvironmentVariables::FormatPx(window_controls_overlay_rect_.y()));
  vars.SetVariable(UADefinedVariable::kTitlebarAreaWidth,
                   StyleEnvironmentVariables::FormatPx(
                       window_controls_overlay_rect_.width()));
  vars.SetVariable(UADefinedVariable::kTitlebarAreaHeight,
                   StyleEnvironmentVariables::FormatPx(
                       window_controls_overlay_rect_.height()));
}

void LocalFrame::MaybeUpdateWindowControlsOverlayWithNewZoomLevel() {
  // |window_controls_overlay_rect_| is only set for local root.
  if (!is_window_controls_overlay_visible_ || !IsLocalRoot())
    return;

  DCHECK(!window_controls_overlay_rect_in_dips_.IsEmpty());

  UpdateWindowControlsOverlay(window_controls_overlay_rect_in_dips_);
}
#endif  // !BUILDFLAG(IS_ANDROID)

void LocalFrame::SetNotRestoredReasons(
    mojom::blink::BackForwardCacheNotRestoredReasonsPtr not_restored_reasons) {
  // Back/forward cache is only enabled for outermost main frame.
  DCHECK(IsOutermostMainFrame());
  not_restored_reasons_ = mojo::Clone(not_restored_reasons);
}

const mojom::blink::BackForwardCacheNotRestoredReasonsPtr&
LocalFrame::GetNotRestoredReasons() {
  // Back/forward cache is only enabled for the outermost main frames, and the
  // web exposed API returns non-null values only for the outermost main frames.
  DCHECK(IsOutermostMainFrame());
  return not_restored_reasons_;
}

void LocalFrame::SetNavigationConfidence(
    double randomized_trigger_rate,
    mojom::blink::ConfidenceLevel confidence) {
  DCHECK(IsOutermostMainFrame());
  loader_.GetDocumentLoader()->GetTiming().SetRandomizedConfidence(
      std::make_pair(randomized_trigger_rate, confidence));
}

void LocalFrame::AddScrollSnapshotClient(ScrollSnapshotClient& client) {
  scroll_snapshot_clients_.insert(&client);
}

void LocalFrame::UpdateScrollSnapshots() {
  // TODO(xiaochengh): Can we DCHECK that is is done at the beginning of a frame
  // and is done exactly once?
  for (auto& client : scroll_snapshot_clients_)
    client->UpdateSnapshot();
}

bool LocalFrame::ValidateScrollSnapshotClients() {
  bool valid = true;
  for (auto& client : scroll_snapshot_clients_) {
    valid &= client->ValidateSnapshot();
  }
  return valid;
}

void LocalFrame::ClearScrollSnapshotClients() {
  scroll_snapshot_clients_.clear();
}

void LocalFrame::ScheduleNextServiceForScrollSnapshotClients() {
  for (auto& client : scroll_snapshot_clients_) {
    if (client->ShouldScheduleNextService()) {
      View()->ScheduleAnimation();
      return;
    }
  }
}

void LocalFrame::CheckPositionAnchorsForCssVisibilityChanges() {
  for (auto& client : scroll_snapshot_clients_) {
    if (AnchorPositionScrollData* scroll_data =
            DynamicTo<AnchorPositionScrollData>(client.Get())) {
      if (auto* observer = scroll_data->GetAnchorPositionVisibilityObserver()) {
        observer->UpdateForCssAnchorVisibility();
      }
    }
  }
}

void LocalFrame::CheckPositionAnchorsForChainedVisibilityChanges() {
  AnchorPositionVisibilityObserver::UpdateForChainedAnchorVisibility(
      scroll_snapshot_clients_);
}

bool LocalFrame::IsSameOrigin() {
  const SecurityOrigin* security_origin =
      GetSecurityContext()->GetSecurityOrigin();
  const SecurityOrigin* top_security_origin =
      Tree().Top().GetSecurityContext()->GetSecurityOrigin();

  return security_origin->IsSameOriginWith(top_security_origin);
}

bool LocalFrame::ImagesEnabled() {
  DCHECK(!IsDetached());
  // If this is called in the middle of detach, GetDocumentLoader() might
  // already be nullptr.
  if (!loader_.GetDocumentLoader()) {
    return false;
  }
  bool allow_image_renderer = GetSettings()->GetImagesEnabled();
  bool allow_image_content_setting =
      loader_.GetDocumentLoader()->GetContentSettings()->allow_image;
  return allow_image_renderer && allow_image_content_setting;
}

bool LocalFrame::ScriptEnabled() {
  DCHECK(!IsDetached());
  // If this is called in the middle of detach, GetDocumentLoader() might
  // already be nullptr.
  if (!loader_.GetDocumentLoader()) {
    return false;
  }
  bool allow_script_renderer = GetSettings()->GetScriptEnabled();
  bool allow_script_content_setting =
      loader_.GetDocumentLoader()->GetContentSettings()->allow_script;
  return allow_script_renderer && allow_script_content_setting;
}

const WebPrintParams& LocalFrame::GetPrintParams() const {
  // If this fails, it's probably because nobody called StartPrinting().
  DCHECK(GetDocument()->Printing());

  return print_params_;
}

mojo::PendingRemote<mojom::blink::NavigationStateKeepAliveHandle>
LocalFrame::IssueKeepAliveHandle() {
  mojo::PendingRemote<mojom::blink::NavigationStateKeepAliveHandle>
      keep_alive_remote;
  GetLocalFrameHostRemote().IssueKeepAliveHandle(
      keep_alive_remote.InitWithNewPipeAndPassReceiver());
  return keep_alive_remote;
}

WebLinkPreviewTriggerer* LocalFrame::GetOrCreateLinkPreviewTriggerer() {
  EnsureLinkPreviewTriggererInitialized();
  return link_preview_triggerer_.get();
}

void LocalFrame::EnsureLinkPreviewTriggererInitialized() {
  if (is_link_preivew_triggerer_initialized_) {
    return;
  }

  CHECK(!link_preview_triggerer_);

  WebLocalFrameImpl* web_local_frame = WebLocalFrameImpl::FromFrame(this);
  if (!web_local_frame) {
    return;
  }

  link_preview_triggerer_ =
      web_local_frame->Client()->CreateLinkPreviewTriggerer();
  is_link_preivew_triggerer_initialized_ = true;
}

void LocalFrame::SetLinkPreviewTriggererForTesting(
    std::unique_ptr<WebLinkPreviewTriggerer> trigger) {
  link_preview_triggerer_ = std::move(trigger);
  is_link_preivew_triggerer_initialized_ = true;
}

void LocalFrame::AllowStorageAccessAndNotify(
    blink::WebContentSettingsClient::StorageType storage_type,
    base::OnceCallback<void(bool)> callback) {
  mojom::blink::StorageTypeAccessed mojo_storage_type =
      ToMojoStorageType(storage_type);
  auto wrapped_callback = WTF::BindOnce(&LocalFrame::OnStorageAccessCallback,
                                        WrapWeakPersistent(this),
                                        std::move(callback), mojo_storage_type);
  if (WebContentSettingsClient* content_settings_client =
          GetContentSettingsClient()) {
    content_settings_client->AllowStorageAccess(storage_type,
       
"""


```
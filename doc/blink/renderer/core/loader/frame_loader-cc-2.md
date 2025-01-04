Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive response.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of `FrameLoader` in Blink, specifically focusing on its interactions with JavaScript, HTML, and CSS, common errors, debugging clues, and a general summary. The fact that this is part 3 of 3 indicates that we've likely seen other parts related to the loading process.

**2. Initial Code Scan and Keyword Identification:**

First, I'd quickly scan the code for prominent keywords and method names. This helps to identify key areas of responsibility. Some initial observations:

* **`Detach()`:** Suggests cleanup and resource release.
* **`ShouldPerformFragmentNavigation()`:** Deals with URL fragments (the part after the `#`).
* **`ProcessFragment()`:**  Handles the actual scrolling/processing of fragments.
* **`ShouldClose()`:**  Likely involves `beforeunload` events and navigation prevention.
* **`DidDropNavigation()`:** Handles cases where navigation is aborted.
* **`CancelProvisionalLoaderForNewNavigation()`:** Manages the cancellation of loading when a new navigation starts.
* **`ClearClientNavigation()`/`CancelClientNavigation()`:** Seems related to client-initiated navigations (e.g., JavaScript `window.location.href`).
* **`DispatchDocumentElementAvailable()`/`RunScriptsAtDocumentElementAvailable()`:**  Relates to the document structure being ready and script execution.
* **`DispatchDidClearDocumentOfWindowObject()`/`DispatchDidClearWindowObjectInMainWorld()`:**  Suggests actions taken when a document is being replaced in a frame.
* **`PendingEffectiveSandboxFlags()`:** Deals with security sandboxing.
* **`ModifyRequestForCSP()`:** Modifies network requests based on Content Security Policy.
* **`WriteIntoTrace()`/`TakeObjectSnapshot()`:** Likely for debugging and performance tracing.
* **`CreateWorkerCodeCacheHost()`:**  Related to code caching for workers.

**3. Categorizing Functionality:**

Based on these keywords, I can start to group the functionalities into broader categories:

* **Navigation Management:** (`ShouldPerformFragmentNavigation`, `ProcessFragment`, `ShouldClose`, `DidDropNavigation`, `CancelProvisionalLoaderForNewNavigation`, `ClearClientNavigation`, `CancelClientNavigation`). This seems like a core responsibility.
* **Document Lifecycle:** (`DispatchDocumentElementAvailable`, `RunScriptsAtDocumentElementAvailable`, `DispatchDidClearDocumentOfWindowObject`, `DispatchDidClearWindowObjectInMainWorld`). These functions appear to be hooks at different stages of document loading and unloading.
* **Security and Policies:** (`PendingEffectiveSandboxFlags`, `ModifyRequestForCSP`). These are clearly related to security features.
* **Resource Management:** (`Detach`, `CreateWorkerCodeCacheHost`). Handling resources and cleanup.
* **Debugging and Tracing:** (`WriteIntoTrace`, `TakeObjectSnapshot`).
* **User Agent Information:** (`UserAgentMetadata`). Providing browser identification.

**4. Analyzing Interactions with JavaScript, HTML, and CSS:**

Now, I examine each function in more detail to identify how it relates to the web's core technologies:

* **JavaScript:** Functions like `ShouldClose` (handling `beforeunload`), `DispatchDidClearDocumentOfWindowObject` (affecting the global `window` object), and the mention of `ScriptForbiddenScope` directly point to JavaScript interactions. The `Client()->DispatchDidClearWindowObjectInMainWorld` call clearly involves communication with the JavaScript engine.
* **HTML:**  `ShouldPerformFragmentNavigation` deals with fragment identifiers in URLs, a fundamental HTML concept. `DispatchDocumentElementAvailable` signifies a key point in HTML parsing. The discussion of framesets in `ShouldPerformFragmentNavigation` is also directly related to HTML.
* **CSS:**  While not as explicitly mentioned as JavaScript and HTML, the handling of URL fragments and scrolling behavior (`ProcessFragment`) can indirectly affect how CSS is applied (e.g., :target selector). The concept of layout and rendering, which CSS influences heavily, is the *result* of many of these loading processes.

**5. Constructing Examples and Scenarios:**

To solidify understanding and illustrate potential issues, I create hypothetical scenarios:

* **Fragment Navigation:**  Imagine clicking a link with a `#section` in the URL. This directly tests `ShouldPerformFragmentNavigation` and `ProcessFragment`.
* **BeforeUnload:**  Consider a user trying to close a tab or navigate away while a JavaScript `beforeunload` handler is present. This highlights `ShouldClose`.
* **Canceled Navigation:**  Think of a user typing a new URL in the address bar while a previous page is still loading. This can lead to `CancelProvisionalLoaderForNewNavigation` and `DidDropNavigation`.
* **Security:**  Consider iframes with `sandbox` attributes or sites using HTTPS and the `Upgrade-Insecure-Requests` header – these tie into `PendingEffectiveSandboxFlags` and `ModifyRequestForCSP`.

**6. Tracing User Actions (Debugging Clues):**

I consider the steps a user might take that would lead to these functions being executed. This is essential for debugging:

* Typing a URL and pressing Enter.
* Clicking a link.
* Using the browser's back/forward buttons.
* Submitting a form.
* Closing a tab or window.
* JavaScript code calling `window.location.href` or `window.close()`.

**7. Logic and Assumptions (Hypothetical Inputs/Outputs):**

For functions with conditional logic, I create simple "if-then" scenarios:

* **`ShouldPerformFragmentNavigation`:** *Input:* A click on `<a href="#section">`. *Output:* `true` (assuming conditions are met). *Input:*  Submitting a POST form with a fragment. *Output:* `false`.
* **`ShouldClose`:** *Input:* User tries to close a tab with a `beforeunload` that returns a string. *Output:* `false` (the close is prevented). *Input:*  No `beforeunload` handler. *Output:* `true`.

**8. Identifying Common Errors:**

I think about common mistakes developers or users might make that could involve these functions:

* **Misusing `beforeunload`:**  Overly aggressive or annoying `beforeunload` handlers.
* **Incorrectly handling fragment navigation:**  JavaScript code that interferes with the browser's default fragment scrolling.
* **Security issues:**  Serving mixed content on HTTPS sites, triggering CSP blocks.

**9. Structuring the Response:**

Finally, I organize the information logically, using clear headings and bullet points to make it easy to read and understand. I address each part of the original request:

* **Functionality Listing:**  A concise summary of each method's purpose.
* **JavaScript/HTML/CSS Relationships:**  Detailed explanations with examples.
* **Logic and Assumptions:**  Illustrative "if-then" scenarios.
* **User/Programming Errors:**  Practical examples of mistakes.
* **Debugging Clues:**  User actions leading to the code.
* **Overall Summary:**  A brief recap of the `FrameLoader`'s role.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on network requests. *Correction:* Realize that `FrameLoader` manages more than just network loading; it handles document lifecycle and navigation within a frame.
* **Initial thought:** Treat each function in isolation. *Correction:*  Emphasize how these functions work together in the overall navigation and loading process.
* **Ensuring Clarity:**  Use clear and concise language, avoiding overly technical jargon where possible. Provide concrete examples instead of abstract descriptions.

By following this structured approach, I can thoroughly analyze the code snippet and generate a comprehensive and informative response that addresses all aspects of the original request.
这是 `blink/renderer/core/loader/frame_loader.cc` 文件的第三部分，主要包含以下功能：

**核心功能归纳:**

总体来说，这部分 `FrameLoader` 的代码主要负责处理以下几个方面的功能，与网页的加载和导航息息相关：

* **处理用户代理元数据:**  提供访问用户代理信息的能力。
* **帧的卸载和分离:**  处理帧的卸载和从页面树中分离的过程，包括取消解析、清理导航状态等。
* **同文档导航 (Fragment Navigation):**  判断和处理页面内部的锚点跳转（`#` 后的部分）。
* **页面关闭前的处理 (`beforeunload`):**  在页面即将关闭或卸载时，触发 `beforeunload` 事件，允许页面脚本阻止关闭。
* **取消导航:**  处理导航被取消的情况，例如用户停止加载或发生了错误。
* **通知渲染流程的关键事件:**  例如通知浏览器主文档元素可用，以及清除窗口对象。
* **处理安全策略:**  例如获取有效的沙箱标记，以及根据内容安全策略 (CSP) 修改请求头。
* **调试和追踪:**  提供将 `FrameLoader` 状态写入追踪信息的功能。
* **创建 Worker 代码缓存 Host:**  为 Worker 创建代码缓存相关的接口。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **JavaScript:**
   * **`ShouldClose()` 和 `DispatchBeforeUnloadEvent()`:**  直接与 JavaScript 的 `beforeunload` 事件相关。当用户尝试关闭页面或离开页面时，浏览器会触发 `beforeunload` 事件。`FrameLoader` 中的 `ShouldClose()` 方法会调用 `DispatchBeforeUnloadEvent()`，执行页面上的 JavaScript 代码。如果 JavaScript 返回一个非空字符串，浏览器会弹出一个确认对话框询问用户是否要离开。
     * **假设输入:** 用户点击浏览器关闭按钮。
     * **输出:** 如果页面 JavaScript 中有 `window.onbeforeunload = function() { return "确认离开？"; };`，则会弹出包含 "确认离开？" 信息的对话框。

   * **`DispatchDidClearDocumentOfWindowObject()` 和 `DispatchDidClearWindowObjectInMainWorld()`:**  这些方法在文档被替换或重新加载时调用，会通知 JavaScript 环境，可能导致 JavaScript 代码重新初始化或执行。这对于框架页面的重新加载或单页应用的路由切换非常重要。

   * **`ProcessFragment()`:** 当 URL 中包含锚点时，例如 `index.html#section2`，此方法会被调用，最终会调用 JavaScript API 来滚动到对应的元素。

2. **HTML:**
   * **`ShouldPerformFragmentNavigation()`:**  此方法判断是否应该进行同文档的锚点跳转。它会检查 URL 是否包含 `#`，以及是否是相同的文档等条件。这直接关联到 HTML 中 `<a>` 标签的 `href` 属性包含 `#` 的情况。
     * **假设输入:** 用户点击了 `<a href="#subsection">跳转到子章节</a>`。
     * **输出:** 如果当前页面存在 id 为 "subsection" 的元素，浏览器会滚动到该元素。

   * **`DispatchDocumentElementAvailable()`:**  当 HTML 文档的根元素（通常是 `<html>`）被解析完成后，此方法会被调用，标志着文档结构的基本完成，可以进行后续的渲染和脚本执行。

3. **CSS:**
   * **`ProcessFragment()`:** 虽然不直接操作 CSS，但锚点跳转可能会影响 CSS 的 `:target` 选择器。当 URL 的 hash 值与页面中某个元素的 ID 匹配时，`:target` 选择器可以选中该元素并应用特定的样式。

**逻辑推理 (假设输入与输出):**

* **`ShouldPerformFragmentNavigation(false, "GET", WebFrameLoadType::kStandard, "https://example.com/page#section")`:**
    * **假设输入:** 非表单提交，HTTP 方法为 GET，标准加载类型，URL 包含锚点。
    * **输出:** `true` (如果其他条件也满足，例如不是 frameset 且不在 provisional 状态)。

* **`ShouldPerformFragmentNavigation(true, "POST", WebFrameLoadType::kStandard, "https://example.com/page#section")`:**
    * **假设输入:** 表单提交，HTTP 方法为 POST，URL 包含锚点。
    * **输出:** `false` (因为 HTTP 方法不是 GET)。

**用户或编程常见的使用错误举例说明:**

* **滥用 `beforeunload` 事件:**  开发者可能会在 `beforeunload` 事件处理函数中返回过于复杂或不友好的提示信息，导致用户体验下降。一些恶意网站可能会滥用此功能阻止用户离开页面。

* **错误地处理片段导航:**  JavaScript 代码可能会阻止浏览器的默认锚点滚动行为，或者在单页应用中没有正确处理 URL hash 的变化，导致页面状态不一致。

* **未考虑沙箱限制:**  在嵌入 `<iframe>` 时，开发者可能没有正确设置 `sandbox` 属性，导致安全风险或功能异常。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在地址栏输入包含锚点的 URL 并回车:** 这会触发导航，`FrameLoader` 会判断是否进行片段导航。
2. **用户点击页面内的链接，链接的 `href` 属性包含 `#`:**  同样会触发片段导航的判断和处理。
3. **用户尝试关闭标签页或浏览器窗口:**  这会触发 `ShouldClose()`，进而调用 JavaScript 的 `beforeunload` 事件。
4. **用户通过 JavaScript 代码调用 `window.location.href` 或 `window.location.hash` 修改 URL:**  可能触发片段导航或完整的页面加载。
5. **浏览器内部进行页面刷新或前进/后退操作:** 这些操作也可能涉及到 `FrameLoader` 对导航状态的管理和 `beforeunload` 事件的处理。
6. **JavaScript 代码动态创建或移除 `<iframe>` 元素:** 这会导致子帧的加载和卸载，涉及到 `Detach()` 等方法。

**总结 (归纳功能):**

这部分 `FrameLoader` 代码的核心职责在于管理和协调帧的生命周期中的关键阶段，特别是与用户导航、页面卸载、同文档导航以及与 JavaScript 环境的交互。它确保了在各种导航场景下，`beforeunload` 事件能够正确触发，同文档锚点跳转能够顺利进行，并且在页面卸载时进行必要的清理工作。此外，它还涉及到一些安全策略和调试追踪的功能。

Prompt: 
```
这是目录为blink/renderer/core/loader/frame_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
Loader::UserAgentMetadata() const {
  return Client()->UserAgentMetadata();
}

void FrameLoader::Detach() {
  frame_->GetDocument()->CancelParsing();
  DetachDocumentLoader(document_loader_);
  ClearClientNavigation();
  committing_navigation_ = false;
  DidFinishNavigation(FrameLoader::NavigationFinishState::kSuccess);

  if (progress_tracker_) {
    progress_tracker_->Dispose();
    progress_tracker_.Clear();
  }

  TRACE_EVENT_OBJECT_DELETED_WITH_ID("loading", "FrameLoader", this);
  state_ = State::kDetached;
  virtual_time_pauser_.UnpauseVirtualTime();
}

bool FrameLoader::ShouldPerformFragmentNavigation(bool is_form_submission,
                                                  const String& http_method,
                                                  WebFrameLoadType load_type,
                                                  const KURL& url) {
  // We don't do this if we are submitting a form with method other than "GET",
  // explicitly reloading, currently displaying a frameset, or if the URL does
  // not have a fragment.
  return EqualIgnoringASCIICase(http_method, http_names::kGET) &&
         !IsReloadLoadType(load_type) && !IsBackForwardOrRestore(load_type) &&
         url.HasFragmentIdentifier() &&
         // For provisional LocalFrame, there is no real document loaded and
         // the initial empty document should not be considered, so there is
         // no way to get a same-document load in this case.
         !frame_->IsProvisional() &&
         EqualIgnoringFragmentIdentifier(frame_->GetDocument()->Url(), url)
         // We don't want to just scroll if a link from within a frameset is
         // trying to reload the frameset into _top.
         && !frame_->GetDocument()->IsFrameSet();
}

void FrameLoader::ProcessFragment(const KURL& url,
                                  WebFrameLoadType frame_load_type,
                                  LoadStartType load_start_type) {
  LocalFrameView* view = frame_->View();
  if (!view)
    return;

  const bool is_same_document_navigation =
      load_start_type == kNavigationWithinSameDocument;

  // Pages can opt-in to manual scroll restoration so the page will handle
  // restoring the past scroll offset during a history navigation. In these
  // cases we assume the scroll was restored from history (by the page).
  const bool uses_manual_scroll_restoration =
      IsBackForwardOrRestore(frame_load_type) &&
      GetDocumentLoader()->GetHistoryItem() &&
      GetDocumentLoader()->GetHistoryItem()->ScrollRestorationType() ==
          mojom::blink::ScrollRestorationType::kManual;

  // If we restored a scroll position from history, we shouldn't clobber it
  // with the fragment.
  const bool will_restore_scroll_from_history =
      GetDocumentLoader()->GetInitialScrollState().did_restore_from_history ||
      uses_manual_scroll_restoration;

  // Scrolling at load can be blocked by document policy. This policy applies
  // only to cross-document navigations.
  const bool blocked_by_policy =
      !is_same_document_navigation &&
      !GetDocumentLoader()->NavigationScrollAllowed();

  // We should avoid scrolling the fragment if it would clobber a history
  // restored scroll state but still allow it on same document navigations
  // after (i.e. if we navigate back and restore the scroll position, the user
  // should still be able to click on a same-document fragment link and have it
  // jump to the anchor).
  const bool is_same_document_non_history_nav =
      is_same_document_navigation && !IsBackForwardOrRestore(frame_load_type);

  const bool block_fragment_scroll =
      blocked_by_policy ||
      (will_restore_scroll_from_history && !is_same_document_non_history_nav);

  view->ProcessUrlFragment(url, is_same_document_navigation,
                           !block_fragment_scroll);
}

bool FrameLoader::ShouldClose(bool is_reload) {
  TRACE_EVENT1("loading", "FrameLoader::ShouldClose", "is_reload", is_reload);
  const base::TimeTicks before_unload_events_start = base::TimeTicks::Now();

  Page* page = frame_->GetPage();
  if (!page || !page->GetChromeClient().CanOpenBeforeUnloadConfirmPanel())
    return true;

  HeapVector<Member<LocalFrame>> descendant_frames;
  for (Frame* child = frame_->Tree().FirstChild(); child;
       child = child->Tree().TraverseNext(frame_.Get())) {
    // FIXME: There is not yet any way to dispatch events to out-of-process
    // frames.
    if (auto* child_local_frame = DynamicTo<LocalFrame>(child))
      descendant_frames.push_back(child_local_frame);
  }

  {
    FrameNavigationDisabler navigation_disabler(*frame_);
    bool did_allow_navigation = false;

    // https://html.spec.whatwg.org/C/browsing-the-web.html#prompt-to-unload-a-document

    // First deal with this frame.
    IgnoreOpensDuringUnloadCountIncrementer ignore_opens_during_unload(
        frame_->GetDocument());
    if (!frame_->GetDocument()->DispatchBeforeUnloadEvent(
            &page->GetChromeClient(), is_reload, did_allow_navigation)) {
      frame_->DomWindow()->navigation()->InformAboutCanceledNavigation();
      return false;
    }

    // Then deal with descendent frames.
    for (Member<LocalFrame>& descendant_frame : descendant_frames) {
      if (!descendant_frame->Tree().IsDescendantOf(frame_.Get())) {
        continue;
      }

      // There is some confusion in the spec around what counters should be
      // incremented for a descendant browsing context:
      // https://github.com/whatwg/html/issues/3899
      //
      // Here for implementation ease, we use the current spec behavior, which
      // is to increment only the counter of the Document on which this is
      // called, and that of the Document we are firing the beforeunload event
      // on -- not any intermediate Documents that may be the parent of the
      // frame being unloaded but is not root Document.
      IgnoreOpensDuringUnloadCountIncrementer
          ignore_opens_during_unload_descendant(
              descendant_frame->GetDocument());
      if (!descendant_frame->GetDocument()->DispatchBeforeUnloadEvent(
              &page->GetChromeClient(), is_reload, did_allow_navigation)) {
        frame_->DomWindow()->navigation()->InformAboutCanceledNavigation();
        return false;
      }
    }
  }

  // Now that none of the unloading frames canceled the BeforeUnload, tell each
  // of them so they can advance to the appropriate load state.
  frame_->GetDocument()->BeforeUnloadDoneWillUnload();
  for (Member<LocalFrame>& descendant_frame : descendant_frames) {
    if (!descendant_frame->Tree().IsDescendantOf(frame_.Get())) {
      continue;
    }
    descendant_frame->GetDocument()->BeforeUnloadDoneWillUnload();
  }

  if (!frame_->IsDetached() && frame_->IsOutermostMainFrame() &&
      base::FeatureList::IsEnabled(features::kMemoryCacheStrongReference)) {
    MemoryCache::Get()->SavePageResourceStrongReferences(
        frame_->AllResourcesUnderFrame());
  }

  if (!is_reload) {
    // Records only when a non-reload navigation occurs.
    base::UmaHistogramMediumTimes(
        "Navigation.OnBeforeUnloadTotalTime",
        base::TimeTicks::Now() - before_unload_events_start);
  }

  return true;
}

void FrameLoader::DidDropNavigation() {
  if (!client_navigation_)
    return;
  // TODO(dgozman): should we ClearClientNavigation instead and not
  // notify the client in response to its own call?
  CancelClientNavigation(CancelNavigationReason::kDropped);
  DidFinishNavigation(FrameLoader::NavigationFinishState::kSuccess);

  // Forcibly instantiate WindowProxy for initial frame document.
  // This is only required when frame navigation is aborted, e.g. due to
  // mixed content.
  // TODO(lushnikov): this should be done in Init for initial empty doc, but
  // that breaks extensions abusing SetForceMainWorldInitialization setting
  // and relying on the number of created window proxies.
  Settings* settings = frame_->GetSettings();
  if (settings && settings->GetForceMainWorldInitialization()) {
    auto* window = frame_->DomWindow();
    // Forcibly instantiate WindowProxy.
    window->GetScriptController().WindowProxy(
        DOMWrapperWorld::MainWorld(window->GetIsolate()));
  }
  frame_->GetIdlenessDetector()->DidDropNavigation();
}

bool FrameLoader::CancelProvisionalLoaderForNewNavigation() {
  // This seems to correspond to step 9 of the specification:
  // "9. Abort the active document of browsingContext."
  // https://html.spec.whatwg.org/C/#navigate
  frame_->GetDocument()->Abort();
  // document.onreadystatechange can fire in Abort(), which can:
  // 1) Detach this frame.
  // 2) Stop the provisional DocumentLoader (i.e window.stop()).
  if (!frame_->GetPage())
    return false;

  // For client navigations, don't send failure callbacks when simply
  // replacing client navigation with a DocumentLoader.
  ClearClientNavigation();

  // Cancel pending form submissions so they don't take precedence over this.
  frame_->CancelFormSubmission();

  return true;
}

void FrameLoader::ClearClientNavigation() {
  if (!client_navigation_)
    return;
  client_navigation_.reset();
  probe::DidFailProvisionalLoad(frame_.Get());
  virtual_time_pauser_.UnpauseVirtualTime();
}

void FrameLoader::CancelClientNavigation(CancelNavigationReason reason) {
  if (!client_navigation_)
    return;

  frame_->DomWindow()->navigation()->InformAboutCanceledNavigation(reason);

  ResourceError error = ResourceError::CancelledError(client_navigation_->url);
  ClearClientNavigation();
  if (WebPluginContainerImpl* plugin = frame_->GetWebPluginContainer())
    plugin->DidFailLoading(error);
  Client()->AbortClientNavigation(reason ==
                                  CancelNavigationReason::kNewNavigation);
}

void FrameLoader::DispatchDocumentElementAvailable() {
  ScriptForbiddenScope forbid_scripts;

  // Notify the browser about documents loading in the top frame.
  if (frame_->GetDocument()->Url().IsValid() && frame_->IsMainFrame()) {
    // For now, don't remember plugin zoom values.  We don't want to mix them
    // with normal web content (i.e. a fixed layout plugin would usually want
    // them different).
    frame_->GetLocalFrameHostRemote().MainDocumentElementAvailable(
        frame_->GetDocument()->IsPluginDocument());
  }

  Client()->DocumentElementAvailable();
}

void FrameLoader::RunScriptsAtDocumentElementAvailable() {
  Client()->RunScriptsAtDocumentElementAvailable();
  // The frame might be detached at this point.
}

void FrameLoader::DispatchDidClearDocumentOfWindowObject() {
  if (state_ == State::kUninitialized)
    return;

  Settings* settings = frame_->GetSettings();
  LocalDOMWindow* window = frame_->DomWindow();
  if (settings && settings->GetForceMainWorldInitialization()) {
    // Forcibly instantiate WindowProxy, even if script is disabled.
    window->GetScriptController().WindowProxy(
        DOMWrapperWorld::MainWorld(window->GetIsolate()));
  }
  probe::DidClearDocumentOfWindowObject(frame_.Get());
  if (!window->CanExecuteScripts(kNotAboutToExecuteScript))
    return;

  if (dispatching_did_clear_window_object_in_main_world_)
    return;
  base::AutoReset<bool> in_did_clear_window_object(
      &dispatching_did_clear_window_object_in_main_world_, true);
  // We just cleared the document, not the entire window object, but for the
  // embedder that's close enough.
  Client()->DispatchDidClearWindowObjectInMainWorld(
      window->GetIsolate(), window->GetMicrotaskQueue());
}

void FrameLoader::DispatchDidClearWindowObjectInMainWorld() {
  LocalDOMWindow* window = frame_->DomWindow();
  if (!window->CanExecuteScripts(kNotAboutToExecuteScript))
    return;

  if (dispatching_did_clear_window_object_in_main_world_)
    return;
  base::AutoReset<bool> in_did_clear_window_object(
      &dispatching_did_clear_window_object_in_main_world_, true);
  Client()->DispatchDidClearWindowObjectInMainWorld(
      window->GetIsolate(), window->GetMicrotaskQueue());
}

network::mojom::blink::WebSandboxFlags
FrameLoader::PendingEffectiveSandboxFlags() const {
  if (Frame* parent = frame_->Tree().Parent()) {
    return parent->GetSecurityContext()->GetSandboxFlags() |
           frame_->Owner()->GetFramePolicy().sandbox_flags;
  } else {
    return frame_->OpenerSandboxFlags();
  }
}

void FrameLoader::ModifyRequestForCSP(
    ResourceRequest& resource_request,
    const FetchClientSettingsObject* fetch_client_settings_object,
    LocalDOMWindow* window_for_logging,
    mojom::RequestContextFrameType frame_type) const {
  // Tack an 'Upgrade-Insecure-Requests' header to outgoing navigational
  // requests, as described in
  // https://w3c.github.io/webappsec-upgrade-insecure-requests/#feature-detect
  if (frame_type != mojom::RequestContextFrameType::kNone) {
    // Early return if the request has already been upgraded.
    if (!resource_request.HttpHeaderField(http_names::kUpgradeInsecureRequests)
             .IsNull()) {
      return;
    }

    resource_request.SetHttpHeaderField(http_names::kUpgradeInsecureRequests,
                                        AtomicString("1"));
  }

  MixedContentChecker::UpgradeInsecureRequest(
      resource_request, fetch_client_settings_object, window_for_logging,
      frame_type, frame_->GetContentSettingsClient());
}

void FrameLoader::WriteIntoTrace(perfetto::TracedValue context) const {
  auto dict = std::move(context).WriteDictionary();
  {
    auto frame_dict = dict.AddDictionary("frame");
    frame_dict.Add("id_ref", IdentifiersFactory::FrameId(frame_.Get()));
  }
  dict.Add("isLoadingMainFrame", frame_->IsMainFrame());
  dict.Add("isOutermostMainFrame", frame_->IsOutermostMainFrame());
  dict.Add("documentLoaderURL",
           document_loader_ ? document_loader_->Url().GetString() : String());
}

inline void FrameLoader::TakeObjectSnapshot() const {
  if (state_ == State::kDetached) {
    // We already logged TRACE_EVENT_OBJECT_DELETED_WITH_ID in detach().
    return;
  }
  TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID("loading", "FrameLoader", this, this);
}

mojo::PendingRemote<mojom::blink::CodeCacheHost>
FrameLoader::CreateWorkerCodeCacheHost() {
  if (!document_loader_)
    return mojo::NullRemote();
  return document_loader_->CreateWorkerCodeCacheHost();
}

}  // namespace blink

"""


```
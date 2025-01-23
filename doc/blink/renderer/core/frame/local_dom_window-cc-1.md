Response:
Let's break down the thought process for analyzing this code snippet of `LocalDOMWindow.cc`.

**1. Initial Understanding of the File's Purpose (Based on the Path):**

The path `blink/renderer/core/frame/local_dom_window.cc` immediately tells us this file is part of the Blink rendering engine, specifically dealing with the `LocalDOMWindow`. The name "LocalDOMWindow" strongly suggests it represents the JavaScript `window` object for a specific frame (or tab/window in a browser). The ".cc" extension indicates it's a C++ source file.

**2. Goal of the Analysis:**

The request asks for a summary of the functionality within the provided code snippet, focusing on its relationship with JavaScript, HTML, CSS, and common usage errors. It's also the second part of a three-part analysis, implying we should focus on the code within this specific excerpt.

**3. Strategy for Analyzing the Code Snippet:**

The most effective approach is to go through the code function by function (or sometimes logically grouped sections of related functions). For each function, consider:

* **What does it do?** (Core functionality)
* **How does it relate to web technologies?** (JavaScript, HTML, CSS)
* **Are there any implicit assumptions or dependencies?** (E.g., the existence of a `Frame`, `Document`, etc.)
* **Can this lead to common errors?** (Especially for web developers)
* **Are there any interesting internal mechanisms or optimizations?** (Less important for a basic summary, but good to note if obvious)

**4. Function-by-Function Analysis (Mental Walkthrough and Note-Taking):**

* **`AddInspectorIssue`:**  This is clearly related to developer tools. It likely sends information about issues (errors, warnings, etc.) to the browser's inspector. *Relationship: DevTools, indirectly JavaScript/HTML/CSS issues.*

* **`CountUse` & `CountWebDXFeature`:** These functions seem to be for internal usage tracking/metrics. They count the usage of specific features. *Relationship: None directly visible to web developers, but reflects underlying browser feature usage.*

* **`CountPermissionsPolicyUsage`:** This is directly related to the Permissions Policy, a web standard. It counts how often specific permissions policy features are used. *Relationship: Permissions Policy (part of HTML), indirectly JavaScript (for triggering features).*

* **`CountUseOnlyIn...Iframe`:**  These functions are variations of `CountUse`, but are conditional based on the iframe's origin (same-origin, cross-origin, cross-site). This highlights the importance of security and isolation between frames. *Relationship: HTML (iframes), security implications for JavaScript.*

* **`HasInsecureContextInAncestors`:** This checks the security context of parent frames. It's crucial for features that require a secure context (HTTPS). *Relationship: Security (HTTPS), relevant to JavaScript APIs that require secure contexts.*

* **`InstallNewDocument`:**  This is a core function for creating and associating a new `Document` object with the `LocalDOMWindow`. It's deeply intertwined with the document loading process. *Relationship: HTML (the document), JavaScript (the document object), CSS (ultimately applies to the document).*  The DCHECKs are important for internal correctness but not directly user-facing.

* **`EnqueueWindowEvent` & `EnqueueDocumentEvent`:** These functions add events to a queue for later processing. This is part of the browser's event loop mechanism. *Relationship: JavaScript events, fundamental to web interactivity.*

* **`DispatchWindowLoadEvent`:** This handles the crucial `load` event for the window. The delay mechanism mentioned is a good example of internal workarounds for complex scenarios. *Relationship: JavaScript `load` event, critical for page lifecycle.*

* **`DocumentWasClosed`:** This function is called when a document is closed. It triggers actions like form restoration and firing the `pageshow` event. *Relationship: HTML, JavaScript `pageshow` event, browser history management.*

* **`EnqueueNonPersistedPageshowEvent` & `DispatchPersistedPageshowEvent`:**  These functions handle the `pageshow` event, distinguishing between regular navigation and restoring from the back/forward cache. The asynchronous nature is important. *Relationship: JavaScript `pageshow` event, browser history/caching.*

* **`DispatchPagehideEvent`:** Handles the `pagehide` event, related to navigating away from a page or putting it in the back/forward cache. The checks for prerendering and unload status are interesting. *Relationship: JavaScript `pagehide` event, browser history/caching.*

* **`EnqueueHashchangeEvent`:**  Handles the `hashchange` event when the URL fragment changes. *Relationship: JavaScript `hashchange` event, URL manipulation.*

* **`DispatchPopstateEvent`:** Handles the `popstate` event, triggered by navigating through history using the back/forward buttons. The task attribution is an internal mechanism. *Relationship: JavaScript `popstate` event, browser history API.*

* **`~LocalDOMWindow` & `Dispose`:**  Destructor and cleanup. The note about Oilpan (Blink's garbage collector) and event listener removal is important for understanding memory management. *Relationship: Internal browser mechanisms, indirectly affects how JavaScript objects are managed.*

* **`GetExecutionContext` & `ToLocalDOMWindow`:** Basic type casting and accessors.

* **`matchMedia`:** Implements the `window.matchMedia()` JavaScript API for media queries. *Relationship: CSS media queries, JavaScript API.*

* **`FrameDestroyed`:**  Handles frame destruction, including shutting down the document, detaching from agents, and notifying debuggers. *Relationship: Internal browser mechanisms, tied to the lifecycle of a frame and its associated document.*

* **`RegisterEventListenerObserver`:** Allows registering observers for event listeners, likely for internal monitoring or debugging.

* **`Reset`:** Resets the state of the `LocalDOMWindow`, often used during navigation or tab reuse. *Relationship: Internal browser mechanisms, part of the navigation process.*

* **`SendOrientationChangeEvent` & `orientation`:** Implement the `orientationchange` event and the `window.orientation` property, related to device orientation. *Relationship: JavaScript `orientationchange` event, `window.orientation` property.*

* **`screen`, `history`, `locationbar`, etc.:** These are getters for various properties of the `window` object, like `window.screen`, `window.history`, etc. They instantiate these objects lazily. *Relationship: Core JavaScript `window` object properties.*

* **`GetFrameConsole`:** Provides access to the console for the frame, used for logging messages (including errors). *Relationship: JavaScript console API, developer tools.*

* **`navigator` & `navigation`:** Getters for the `window.navigator` and `window.navigation` (Navigation API) objects. *Relationship: JavaScript `navigator` and Navigation APIs.*

* **`SchedulePostMessage` & `DispatchPostMessage` & `DispatchMessageEventWithOriginCheck`:** These handle the `postMessage` API, enabling cross-origin communication. The origin checks are crucial for security. *Relationship: JavaScript `postMessage` API, security, cross-origin communication.*

* **`getSelection`:** Implements `window.getSelection()` for getting the current text selection. *Relationship: JavaScript `window.getSelection()` API, text selection.*

* **`frameElement`:** Returns the HTML element that contains the current frame (e.g., `<iframe>`). *Relationship: HTML (iframes), JavaScript access to the containing element.*

* **`print`, `stop`, `alert`, `confirm`, `prompt`:** Implement the corresponding JavaScript `window` methods. The sandboxing checks and microtask checks are interesting implementation details. *Relationship: Core JavaScript `window` methods for interacting with the user.*

* **`find`:** Implements the `window.find()` method for searching within the page. The need for an up-to-date layout is important. *Relationship: JavaScript `window.find()` API, text searching.*

* **`offscreenBuffering`:**  Indicates whether offscreen buffering is enabled (always true here).

* **`outerHeight`, `outerWidth`, `innerHeight`, `innerWidth`, `screenX`, `screenY`, `scrollX`, `scrollY`:** These implement the corresponding JavaScript `window` properties related to window and viewport dimensions and scrolling. The adjustments for zoom and device scale factor are notable. *Relationship: JavaScript `window` properties related to dimensions and scrolling.*

* **`viewport` & `visualViewport`:** Getters for the `DOMViewport` and `DOMVisualViewport` objects, related to viewport handling. *Relationship: JavaScript Viewport API.*

* **`name`, `setName`, `setStatus`, `setDefaultStatus`, `origin`:** Implement the corresponding JavaScript `window` properties. *Relationship: Core JavaScript `window` object properties.*

**5. Synthesizing the Information and Forming the Summary:**

After analyzing each function, group related functionalities and summarize them in the context of the original request. Focus on the high-level purpose and the connections to web technologies. Pay attention to potential developer errors and the security implications.

**6. Review and Refine:**

Read through the generated summary to ensure accuracy, clarity, and completeness. Check if it addresses all the points raised in the request. For instance, the request specifically asks for examples of relationships with JavaScript, HTML, and CSS, so make sure those are included. The request also mentions logical reasoning (input/output), which is less applicable here for individual functions but can be implicitly seen in how events are enqueued and dispatched. Ensure the summary for Part 2 specifically addresses the code provided in this part.
这是 `blink/renderer/core/frame/local_dom_window.cc` 文件的一部分代码，主要负责以下功能：

**核心功能归纳:**

这段代码主要集中在 **事件处理、页面生命周期管理、以及一些与浏览器交互和状态查询相关的操作**。具体来说：

1. **上报浏览器特性使用情况:** 提供了多个 `CountUse` 和 `CountWebDXFeature` 函数，用于记录特定浏览器特性 (WebFeature, WebDXFeature) 的使用情况。这些计数通常用于数据分析和决策，以了解开发者对不同特性的采用程度。
2. **上报权限策略使用情况:** `CountPermissionsPolicyUsage` 用于记录开发者如何使用权限策略 (Permissions Policy)。
3. **判断安全上下文:** `HasInsecureContextInAncestors` 检查当前窗口的父级 frame 是否处于不安全的上下文中 (例如，非 HTTPS)。
4. **安装新的文档:** `InstallNewDocument` 负责为一个 `LocalDOMWindow` 创建并关联新的 `Document` 对象。这是页面加载的核心步骤之一。
5. **事件的入队和分发:** 提供了 `EnqueueWindowEvent`, `EnqueueDocumentEvent`, `DispatchWindowLoadEvent`, `DocumentWasClosed`, `EnqueueNonPersistedPageshowEvent`, `DispatchPersistedPageshowEvent`, `DispatchPagehideEvent`, `EnqueueHashchangeEvent`, `DispatchPopstateEvent` 等一系列函数，用于管理各种窗口和文档相关的事件，包括页面加载、卸载、历史记录改变等。
6. **`postMessage` 的调度和分发:** `SchedulePostMessage`, `DispatchPostMessage`, `DispatchMessageEventWithOriginCheck`  处理跨域消息传递机制 `postMessage`。包括消息的排队、目标域名的校验以及最终的分发。
7. **与浏览器交互:** 涉及与浏览器进行交互的函数，例如 `print` (打印), `stop` (停止加载), `alert`, `confirm`, `prompt` (模态对话框)。
8. **获取窗口和页面属性:** 提供获取窗口大小、位置、滚动位置等属性的方法，如 `outerHeight`, `outerWidth`, `innerHeight`, `innerWidth`, `screenX`, `screenY`, `scrollX`, `scrollY`。
9. **管理窗口名称和状态:** 提供了设置和获取窗口名称 (`name`, `setName`) 和状态栏信息 (`setStatus`, `setDefaultStatus`) 的功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **事件处理:**  这段代码的核心功能是管理和分发各种 JavaScript 事件。例如，`DispatchWindowLoadEvent` 最终会触发 JavaScript 中的 `window.onload` 事件。`EnqueueHashchangeEvent` 用于触发 `window.onhashchange` 事件。`DispatchPopstateEvent` 触发 `window.onpopstate` 事件。
    * **`postMessage`:**  `SchedulePostMessage` 和相关函数直接对应 JavaScript 的 `window.postMessage()` API。
        * **假设输入 (JavaScript):**  在一个 iframe 中执行 `window.parent.postMessage('hello', 'https://example.com');`
        * **对应输出 (C++):**  `SchedulePostMessage` 会接收到消息内容 'hello'，目标 origin 'https://example.com'，以及发送者的 `LocalDOMWindow`。
    * **窗口属性和方法:**  `outerHeight`, `innerWidth`, `print`, `alert` 等函数直接对应 JavaScript `window` 对象的属性和方法。
        * **假设输入 (JavaScript):** `console.log(window.innerWidth);`
        * **对应输出 (C++):** `innerWidth()` 函数会被调用，计算并返回视口的宽度。
    * **Permissions Policy:** `CountPermissionsPolicyUsage` 关联着 JavaScript 中通过 HTML 的 `Permissions-Policy` header 或 iframe 的 `allow` 属性设置的权限策略。

* **HTML:**
    * **`InstallNewDocument`:** 当浏览器解析 HTML 并创建一个新的文档时，会调用此函数来初始化 `Document` 对象。
    * **iframe:** `CountUseOnlyInCrossOriginIframe` 等函数涉及到 iframe 的跨域情况，这直接关联到 HTML 的 `<iframe>` 标签。
    * **事件:** 代码中处理的很多事件 (load, pageshow, pagehide, hashchange, popstate) 都与 HTML 页面的生命周期和用户交互相关。

* **CSS:**
    * **`matchMedia`:**  虽然这段代码本身没有直接操作 CSS，但 `matchMedia` 函数是 JavaScript 中用于匹配 CSS 媒体查询的 API。它背后的实现会涉及到 Blink 引擎对 CSS 的解析和评估。
        * **假设输入 (JavaScript):** `window.matchMedia('(max-width: 600px)').matches;`
        * **对应输出 (C++):** `matchMedia` 函数会被调用，根据传入的媒体查询字符串 `(max-width: 600px)`，结合当前的视口宽度，返回匹配结果。
    * **窗口尺寸:** `outerHeight`, `innerWidth` 等属性的值会受到 CSS 布局的影响。

**逻辑推理的假设输入与输出:**

* **假设输入 (导航到新页面):** 用户在地址栏输入新的 URL 并回车。
* **对应输出 (C++ 函数调用序列):**  可能会触发以下函数调用序列：
    1. `FrameDestroyed()` (如果当前页面被替换)
    2. `InstallNewDocument()` (创建新的 `Document` 对象)
    3. 一系列 `EnqueueDocumentEvent` 和 `EnqueueWindowEvent` (处理DOMContentLoaded等事件)
    4. `DispatchWindowLoadEvent()` (触发 `window.onload`)

* **假设输入 (JavaScript 调用 `history.pushState()`):**  JavaScript 代码执行 `history.pushState({page: 1}, "title 1", "?page=1");`
* **对应输出 (C++ 函数调用):**  会触发 `EnqueuePopstateEvent` 或 `DispatchPopstateEvent`，并将状态对象传递给事件处理程序。

**用户或编程常见的使用错误举例说明:**

* **跨域 `postMessage` 错误:**  开发者可能会错误地使用 `postMessage`，例如目标 origin 写错，或者没有正确校验接收到的消息的 origin，导致安全漏洞。这段代码中的 `DispatchMessageEventWithOriginCheck` 就是为了防止这类错误。
    * **错误示例 (JavaScript):**  在 `https://example.com` 上的页面向 `https://evil.com` 发送敏感信息，但目标 origin 却写成了 `'*'`.
* **事件监听器泄漏:**  如果开发者在卸载页面前没有正确移除事件监听器，可能导致内存泄漏。虽然 `LocalDOMWindow` 有 `RemoveAllEventListeners` 方法，但开发者自身的代码也需要注意。
* **误用同步 API 导致 UI 阻塞:**  一些 JavaScript API 的同步操作可能会阻塞 UI 渲染。尽管这更多是 JavaScript 层面的问题，但 Blink 引擎的事件循环和任务调度也会受到影响。

**总结这段代码的功能 (基于提供的部分):**

这段 `LocalDOMWindow.cc` 的代码片段主要负责 **管理和协调与页面生命周期、事件处理、跨域通信以及与浏览器交互相关的底层操作**。它扮演着连接 Blink 渲染引擎和 JavaScript 环境的关键角色，确保各种 Web 技术能够协同工作，并提供必要的安全性和功能保障。它处理了很多用户不可见的幕后工作，使得 JavaScript 能够控制浏览器行为，响应用户操作，并与其他页面或服务进行通信。

### 提示词
```
这是目录为blink/renderer/core/frame/local_dom_window.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
tFrame()) {
    GetFrame()->GetPage()->GetInspectorIssueStorage().AddInspectorIssue(
        this, std::move(issue));
  }
}

void LocalDOMWindow::CountUse(mojom::WebFeature feature) {
  if (!GetFrame())
    return;
  if (auto* loader = GetFrame()->Loader().GetDocumentLoader())
    loader->CountUse(feature);
}

void LocalDOMWindow::CountWebDXFeature(mojom::blink::WebDXFeature feature) {
  if (!GetFrame()) {
    return;
  }
  if (auto* loader = GetFrame()->Loader().GetDocumentLoader()) {
    loader->CountWebDXFeature(feature);
  }
}

void LocalDOMWindow::CountPermissionsPolicyUsage(
    mojom::blink::PermissionsPolicyFeature feature,
    UseCounterImpl::PermissionsPolicyUsageType type) {
  if (!GetFrame())
    return;
  if (auto* loader = GetFrame()->Loader().GetDocumentLoader()) {
    loader->GetUseCounter().CountPermissionsPolicyUsage(feature, type,
                                                        *GetFrame());
  }
}

void LocalDOMWindow::CountUseOnlyInCrossOriginIframe(
    mojom::blink::WebFeature feature) {
  if (GetFrame() && GetFrame()->IsCrossOriginToOutermostMainFrame())
    CountUse(feature);
}

void LocalDOMWindow::CountUseOnlyInSameOriginIframe(
    mojom::blink::WebFeature feature) {
  if (GetFrame() && !GetFrame()->IsOutermostMainFrame() &&
      !GetFrame()->IsCrossOriginToOutermostMainFrame()) {
    CountUse(feature);
  }
}

void LocalDOMWindow::CountUseOnlyInCrossSiteIframe(
    mojom::blink::WebFeature feature) {
  if (IsCrossSiteSubframeIncludingScheme())
    CountUse(feature);
}

bool LocalDOMWindow::HasInsecureContextInAncestors() const {
  for (Frame* parent = GetFrame()->Tree().Parent(); parent;
       parent = parent->Tree().Parent()) {
    auto* origin = parent->GetSecurityContext()->GetSecurityOrigin();
    if (!origin->IsPotentiallyTrustworthy())
      return true;
  }
  return false;
}

Document* LocalDOMWindow::InstallNewDocument(const DocumentInit& init) {
  // Blink should never attempt to install a new Document to a LocalDOMWindow
  // that's not attached to a LocalFrame.
  DCHECK(GetFrame());
  // Either:
  // - `this` should be a new LocalDOMWindow, that has never had a Document
  //   associated with it or
  // - `this` is being reused, and the previous Document has been disassociated
  //   via `ClearForReuse()`.
  DCHECK(!document_);
  DCHECK_EQ(init.GetWindow(), this);

  document_ = init.CreateDocument();
  document_->Initialize();

  document_->GetViewportData().UpdateViewportDescription();

  auto* frame_scheduler = GetFrame()->GetFrameScheduler();
  frame_scheduler->TraceUrlChange(document_->Url().GetString());
  frame_scheduler->SetCrossOriginToNearestMainFrame(
      GetFrame()->IsCrossOriginToNearestMainFrame());

  GetFrame()->GetPage()->GetChromeClient().InstallSupplements(*GetFrame());

  UpdateEventListenerCountsToDocumentForReuseIfNeeded();

  return document_.Get();
}

void LocalDOMWindow::EnqueueWindowEvent(Event& event, TaskType task_type) {
  EnqueueEvent(event, task_type);
}

void LocalDOMWindow::EnqueueDocumentEvent(Event& event, TaskType task_type) {
  if (document_)
    document_->EnqueueEvent(event, task_type);
}

void LocalDOMWindow::DispatchWindowLoadEvent() {
#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  // Delay 'load' event if we are in EventQueueScope.  This is a short-term
  // workaround to avoid Editing code crashes.  We should always dispatch
  // 'load' event asynchronously.  crbug.com/569511.
  if (ScopedEventQueue::Instance()->ShouldQueueEvents() && document_) {
    document_->GetTaskRunner(TaskType::kNetworking)
        ->PostTask(FROM_HERE, WTF::BindOnce(&LocalDOMWindow::DispatchLoadEvent,
                                            WrapPersistent(this)));
    return;
  }
  DispatchLoadEvent();
}

void LocalDOMWindow::DocumentWasClosed() {
  DispatchWindowLoadEvent();

  // An extension to step 4.5. or a part of step 4.6.3. of
  // https://html.spec.whatwg.org/C/#traverse-the-history .
  //
  // 4.5. ..., invoke the reset algorithm of each of those elements.
  // 4.6.3. Run any session history document visibility change steps ...
  if (document_) {
    document_->GetFormController().RestoreImmediately();
  }

  // 4.6.4. Fire an event named pageshow at the Document object's relevant
  // global object, ...
  EnqueueNonPersistedPageshowEvent();
}

void LocalDOMWindow::EnqueueNonPersistedPageshowEvent() {
  // FIXME: https://bugs.webkit.org/show_bug.cgi?id=36334 Pageshow event needs
  // to fire asynchronously.  As per spec pageshow must be triggered
  // asynchronously.  However to be compatible with other browsers blink fires
  // pageshow synchronously unless we are in EventQueueScope.
  if (ScopedEventQueue::Instance()->ShouldQueueEvents() && document_) {
    // The task source should be kDOMManipulation, but the spec doesn't say
    // anything about this.
    EnqueueWindowEvent(*PageTransitionEvent::Create(event_type_names::kPageshow,
                                                    false /* persisted */),
                       TaskType::kMiscPlatformAPI);
  } else {
    DispatchEvent(*PageTransitionEvent::Create(event_type_names::kPageshow,
                                               false /* persisted */),
                  document_.Get());
  }
}

void LocalDOMWindow::DispatchPersistedPageshowEvent(
    base::TimeTicks navigation_start) {
  // Persisted pageshow events are dispatched for pages that are restored from
  // the back forward cache, and the event's timestamp should reflect the
  // |navigation_start| time of the back navigation.
  DispatchEvent(*PageTransitionEvent::CreatePersistedPageshow(navigation_start),
                document_.Get());
}

void LocalDOMWindow::DispatchPagehideEvent(
    PageTransitionEventPersistence persistence) {
  if (document_->IsPrerendering()) {
    // Do not dispatch the event while prerendering.
    return;
  }
  if (document_->UnloadStarted()) {
    // We've already dispatched pagehide (since it's the first thing we do when
    // starting unload) and shouldn't dispatch it again. We might get here on
    // a document that is already unloading/has unloaded but still part of the
    // FrameTree.
    // TODO(crbug.com/1119291): Investigate whether this is possible or not.
    return;
  }

  DispatchEvent(
      *PageTransitionEvent::Create(event_type_names::kPagehide, persistence),
      document_.Get());
}

void LocalDOMWindow::EnqueueHashchangeEvent(const String& old_url,
                                            const String& new_url) {
  // https://html.spec.whatwg.org/C/#history-traversal
  EnqueueWindowEvent(*HashChangeEvent::Create(old_url, new_url),
                     TaskType::kDOMManipulation);
}

void LocalDOMWindow::DispatchPopstateEvent(
    scoped_refptr<SerializedScriptValue> state_object,
    scheduler::TaskAttributionInfo* parent_task) {
  DCHECK(GetFrame());
  std::optional<scheduler::TaskAttributionTracker::TaskScope>
      task_attribution_scope;
  if (parent_task) {
    auto* tracker = scheduler::TaskAttributionTracker::From(GetIsolate());
    ScriptState* script_state = ToScriptStateForMainWorld(GetFrame());
    if (script_state && tracker) {
      task_attribution_scope = tracker->CreateTaskScope(
          script_state, parent_task,
          scheduler::TaskAttributionTracker::TaskScopeType::kPopState);
    }
  }
  DispatchEvent(*PopStateEvent::Create(std::move(state_object), history()));
}

LocalDOMWindow::~LocalDOMWindow() = default;

void LocalDOMWindow::Dispose() {
  BackForwardCacheBufferLimitTracker::Get()
      .DidRemoveFrameOrWorkerFromBackForwardCache(
          total_bytes_buffered_while_in_back_forward_cache_);
  total_bytes_buffered_while_in_back_forward_cache_ = 0;

  // Oilpan: should the LocalDOMWindow be GCed along with its LocalFrame without
  // the frame having first notified its observers of imminent destruction, the
  // LocalDOMWindow will not have had an opportunity to remove event listeners.
  //
  // Arrange for that removal to happen using a prefinalizer action. Making
  // LocalDOMWindow eager finalizable is problematic as other eagerly finalized
  // objects may well want to access their associated LocalDOMWindow from their
  // destructors.
  if (!GetFrame())
    return;

  RemoveAllEventListeners();
}

ExecutionContext* LocalDOMWindow::GetExecutionContext() const {
  return const_cast<LocalDOMWindow*>(this);
}

const LocalDOMWindow* LocalDOMWindow::ToLocalDOMWindow() const {
  return this;
}

LocalDOMWindow* LocalDOMWindow::ToLocalDOMWindow() {
  return this;
}

MediaQueryList* LocalDOMWindow::matchMedia(const String& media) {
  return document()->GetMediaQueryMatcher().MatchMedia(media);
}

void LocalDOMWindow::FrameDestroyed() {
  TRACE_EVENT0("navigation", "LocalDOMWindow::FrameDestroyed");
  base::ScopedUmaHistogramTimer histogram_timer(
      "Navigation.LocalDOMWindow.FrameDestroyed");
  BackForwardCacheBufferLimitTracker::Get()
      .DidRemoveFrameOrWorkerFromBackForwardCache(
          total_bytes_buffered_while_in_back_forward_cache_);
  total_bytes_buffered_while_in_back_forward_cache_ = 0;

  // Some unit tests manually call FrameDestroyed(). Don't run it a second time.
  if (!GetFrame())
    return;
  // In the Reset() case, this Document::Shutdown() early-exits because it was
  // already called earlier in the commit process.
  // TODO(japhet): Can we merge this function and Reset()? At least, this
  // function should be renamed to Detach(), since in the Reset() case the frame
  // is not being destroyed.
  document()->Shutdown();
  document()->RemoveAllEventListenersRecursively();
  GetAgent()->DetachContext(this);
  NotifyContextDestroyed();
  RemoveAllEventListeners();
  MainThreadDebugger::Instance(GetIsolate())
      ->DidClearContextsForFrame(GetFrame());
  DisconnectFromFrame();
}

void LocalDOMWindow::RegisterEventListenerObserver(
    EventListenerObserver* event_listener_observer) {
  event_listener_observers_.insert(event_listener_observer);
}

void LocalDOMWindow::Reset() {
  DCHECK(document());
  FrameDestroyed();

  screen_ = nullptr;
  history_ = nullptr;
  locationbar_ = nullptr;
  menubar_ = nullptr;
  personalbar_ = nullptr;
  scrollbars_ = nullptr;
  statusbar_ = nullptr;
  toolbar_ = nullptr;
  navigator_ = nullptr;
  media_ = nullptr;
  custom_elements_ = nullptr;
  trusted_types_map_.clear();
}

void LocalDOMWindow::SendOrientationChangeEvent() {
  DCHECK(RuntimeEnabledFeatures::OrientationEventEnabled());
  DCHECK(GetFrame()->IsLocalRoot());

  // Before dispatching the event, build a list of all frames in the page
  // to send the event to, to mitigate side effects from event handlers
  // potentially interfering with others.
  HeapVector<Member<LocalFrame>> frames;
  frames.push_back(GetFrame());
  for (wtf_size_t i = 0; i < frames.size(); i++) {
    for (Frame* child = frames[i]->Tree().FirstChild(); child;
         child = child->Tree().NextSibling()) {
      if (auto* child_local_frame = DynamicTo<LocalFrame>(child))
        frames.push_back(child_local_frame);
    }
  }

  for (LocalFrame* frame : frames) {
    frame->DomWindow()->DispatchEvent(
        *Event::Create(event_type_names::kOrientationchange));
  }
}

int LocalDOMWindow::orientation() const {
  DCHECK(RuntimeEnabledFeatures::OrientationEventEnabled());

  LocalFrame* frame = GetFrame();
  if (!frame)
    return 0;

  ChromeClient& chrome_client = frame->GetChromeClient();
  int orientation = chrome_client.GetScreenInfo(*frame).orientation_angle;
  // For backward compatibility, we want to return a value in the range of
  // [-90; 180] instead of [0; 360[ because window.orientation used to behave
  // like that in WebKit (this is a WebKit proprietary API).
  if (orientation == 270)
    return -90;
  return orientation;
}

Screen* LocalDOMWindow::screen() {
  if (!screen_) {
    LocalFrame* frame = GetFrame();
    int64_t display_id =
        frame ? frame->GetChromeClient().GetScreenInfo(*frame).display_id
              : Screen::kInvalidDisplayId;
    screen_ = MakeGarbageCollected<Screen>(this, display_id);
  }
  return screen_.Get();
}

History* LocalDOMWindow::history() {
  if (!history_)
    history_ = MakeGarbageCollected<History>(this);
  return history_.Get();
}

BarProp* LocalDOMWindow::locationbar() {
  if (!locationbar_) {
    locationbar_ = MakeGarbageCollected<BarProp>(this);
  }
  return locationbar_.Get();
}

BarProp* LocalDOMWindow::menubar() {
  if (!menubar_)
    menubar_ = MakeGarbageCollected<BarProp>(this);
  return menubar_.Get();
}

BarProp* LocalDOMWindow::personalbar() {
  if (!personalbar_) {
    personalbar_ = MakeGarbageCollected<BarProp>(this);
  }
  return personalbar_.Get();
}

BarProp* LocalDOMWindow::scrollbars() {
  if (!scrollbars_) {
    scrollbars_ = MakeGarbageCollected<BarProp>(this);
  }
  return scrollbars_.Get();
}

BarProp* LocalDOMWindow::statusbar() {
  if (!statusbar_)
    statusbar_ = MakeGarbageCollected<BarProp>(this);
  return statusbar_.Get();
}

BarProp* LocalDOMWindow::toolbar() {
  if (!toolbar_)
    toolbar_ = MakeGarbageCollected<BarProp>(this);
  return toolbar_.Get();
}

FrameConsole* LocalDOMWindow::GetFrameConsole() const {
  if (!IsCurrentlyDisplayedInFrame())
    return nullptr;
  return &GetFrame()->Console();
}

Navigator* LocalDOMWindow::navigator() {
  if (!navigator_)
    navigator_ = MakeGarbageCollected<Navigator>(this);
  return navigator_.Get();
}

NavigationApi* LocalDOMWindow::navigation() {
  if (!navigation_)
    navigation_ = MakeGarbageCollected<NavigationApi>(this);
  return navigation_.Get();
}

void LocalDOMWindow::SchedulePostMessage(PostedMessage* posted_message) {
  LocalDOMWindow* source = posted_message->source;

  // Notify the host if the message contained a delegated capability. That state
  // should be tracked by the browser, and messages from remote hosts already
  // signal the browser via RemoteFrameHost's RouteMessageEvent.
  if (posted_message->delegated_capability !=
      mojom::blink::DelegatedCapability::kNone) {
    GetFrame()->GetLocalFrameHostRemote().ReceivedDelegatedCapability(
        posted_message->delegated_capability);
  }

  // Convert the posted message to a MessageEvent so it can be unpacked for
  // local dispatch.
  MessageEvent* event = MessageEvent::Create(
      std::move(posted_message->channels), std::move(posted_message->data),
      posted_message->source_origin->ToString(), String(),
      posted_message->source, posted_message->user_activation,
      posted_message->delegated_capability);

  // Allowing unbounded amounts of messages to build up for a suspended context
  // is problematic; consider imposing a limit or other restriction if this
  // surfaces often as a problem (see crbug.com/587012).
  std::unique_ptr<SourceLocation> location = CaptureSourceLocation(source);
  GetTaskRunner(TaskType::kPostedMessage)
      ->PostTask(
          FROM_HERE,
          WTF::BindOnce(&LocalDOMWindow::DispatchPostMessage,
                        WrapPersistent(this), WrapPersistent(event),
                        std::move(posted_message->target_origin),
                        std::move(location), source->GetAgent()->cluster_id()));
  event->async_task_context()->Schedule(this, "postMessage");
  uint64_t trace_id = base::trace_event::GetNextGlobalTraceId();
  event->SetTraceId(trace_id);
  TRACE_EVENT_INSTANT(
      "devtools.timeline", "SchedulePostMessage", "data",
      [&](perfetto::TracedValue context) {
        inspector_schedule_post_message_event::Data(
            std::move(context), GetExecutionContext(), trace_id);
      },
      perfetto::Flow::Global(trace_id));
}

void LocalDOMWindow::DispatchPostMessage(
    MessageEvent* event,
    scoped_refptr<const SecurityOrigin> intended_target_origin,
    std::unique_ptr<SourceLocation> location,
    const base::UnguessableToken& source_agent_cluster_id) {
  // Do not report postMessage tasks to the ad tracker. This allows non-ad
  // script to perform operations in response to events created by ad frames.
  probe::AsyncTask async_task(this, event->async_task_context(),
                              nullptr /* step */, true /* enabled */,
                              probe::AsyncTask::AdTrackingType::kIgnore);
  if (!IsCurrentlyDisplayedInFrame())
    return;

  event->EntangleMessagePorts(this);

  TRACE_EVENT(
      "devtools.timeline", "HandlePostMessage", "data",
      [&](perfetto::TracedValue context) {
        inspector_handle_post_message_event::Data(
            std::move(context), GetExecutionContext(), *event);
      },
      perfetto::Flow::Global(event->GetTraceId()));

  DispatchMessageEventWithOriginCheck(intended_target_origin.get(), event,
                                      std::move(location),
                                      source_agent_cluster_id);
}

void LocalDOMWindow::DispatchMessageEventWithOriginCheck(
    const SecurityOrigin* intended_target_origin,
    MessageEvent* event,
    std::unique_ptr<SourceLocation> location,
    const base::UnguessableToken& source_agent_cluster_id) {
  TRACE_EVENT0("blink", "LocalDOMWindow::DispatchMessageEventWithOriginCheck");
  if (intended_target_origin) {
    bool valid_target =
        intended_target_origin->IsSameOriginWith(GetSecurityOrigin());

    if (!valid_target) {
      String message = ExceptionMessages::FailedToExecute(
          "postMessage", "DOMWindow",
          "The target origin provided ('" + intended_target_origin->ToString() +
              "') does not match the recipient window's origin ('" +
              GetSecurityOrigin()->ToString() + "').");
      auto* console_message = MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kSecurity,
          mojom::ConsoleMessageLevel::kWarning, message, std::move(location));
      GetFrameConsole()->AddMessage(console_message);
      return;
    }
  }

  KURL sender(event->origin());
  if (!GetContentSecurityPolicy()->AllowConnectToSource(
          sender, sender, RedirectStatus::kNoRedirect,
          ReportingDisposition::kSuppressReporting)) {
    UseCounter::Count(
        this, WebFeature::kPostMessageIncomingWouldBeBlockedByConnectSrc);
  }

  if (event->IsOriginCheckRequiredToAccessData()) {
    scoped_refptr<SecurityOrigin> sender_security_origin =
        SecurityOrigin::Create(sender);
    if (!sender_security_origin->IsSameOriginWith(GetSecurityOrigin())) {
      event = MessageEvent::CreateError(event->origin(), event->source());
    }
  }
  if (event->IsLockedToAgentCluster()) {
    if (!IsSameAgentCluster(source_agent_cluster_id)) {
      UseCounter::Count(
          this,
          WebFeature::kMessageEventSharedArrayBufferDifferentAgentCluster);
      event = MessageEvent::CreateError(event->origin(), event->source());
    } else {
      scoped_refptr<SecurityOrigin> sender_origin =
          SecurityOrigin::Create(sender);
      if (!sender_origin->IsSameOriginWith(GetSecurityOrigin())) {
        UseCounter::Count(
            this, WebFeature::kMessageEventSharedArrayBufferSameAgentCluster);
      } else {
        UseCounter::Count(this,
                          WebFeature::kMessageEventSharedArrayBufferSameOrigin);
      }
    }
  }

  if (!event->CanDeserializeIn(this)) {
    event = MessageEvent::CreateError(event->origin(), event->source());
  }

  if (event->delegatedCapability() ==
      mojom::blink::DelegatedCapability::kPaymentRequest) {
    UseCounter::Count(this, WebFeature::kCapabilityDelegationOfPaymentRequest);
    payment_request_token_.Activate();
  }

  if (event->delegatedCapability() ==
      mojom::blink::DelegatedCapability::kFullscreenRequest) {
    UseCounter::Count(this,
                      WebFeature::kCapabilityDelegationOfFullscreenRequest);
    fullscreen_request_token_.Activate();
  }
  if (RuntimeEnabledFeatures::CapabilityDelegationDisplayCaptureRequestEnabled(
          this) &&
      event->delegatedCapability() ==
          mojom::blink::DelegatedCapability::kDisplayCaptureRequest) {
    // TODO(crbug.com/1412770): Add use counter.
    display_capture_request_token_.Activate();
  }

  if (GetFrame() &&
      GetFrame()->GetPage()->GetPageScheduler()->IsInBackForwardCache()) {
    // Enqueue the event when the page is in back/forward cache, so that it
    // would not cause JavaScript execution. The event will be dispatched upon
    // restore.
    EnqueueEvent(*event, TaskType::kInternalDefault);
  } else {
    DispatchEvent(*event);
  }
}

DOMSelection* LocalDOMWindow::getSelection() {
  if (!IsCurrentlyDisplayedInFrame())
    return nullptr;

  return document()->GetSelection();
}

Element* LocalDOMWindow::frameElement() const {
  if (!GetFrame())
    return nullptr;

  return DynamicTo<HTMLFrameOwnerElement>(GetFrame()->Owner());
}

void LocalDOMWindow::print(ScriptState* script_state) {
  // Don't try to print if there's no frame attached anymore.
  if (!GetFrame())
    return;

  if (script_state && IsRunningMicrotasks(script_state)) {
    UseCounter::Count(this, WebFeature::kDuring_Microtask_Print);
  }

  if (GetFrame()->IsLoading()) {
    should_print_when_finished_loading_ = true;
    return;
  }

  CountUseOnlyInSameOriginIframe(WebFeature::kSameOriginIframeWindowPrint);
  CountUseOnlyInCrossOriginIframe(WebFeature::kCrossOriginWindowPrint);

  should_print_when_finished_loading_ = false;
  GetFrame()->GetPage()->GetChromeClient().Print(GetFrame());
}

void LocalDOMWindow::stop() {
  if (!GetFrame())
    return;
  GetFrame()->Loader().StopAllLoaders(/*abort_client=*/true);
}

void LocalDOMWindow::alert(ScriptState* script_state, const String& message) {
  if (!GetFrame())
    return;

  if (IsSandboxed(network::mojom::blink::WebSandboxFlags::kModals)) {
    UseCounter::Count(this, WebFeature::kDialogInSandboxedContext);
    GetFrameConsole()->AddMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kSecurity,
        mojom::blink::ConsoleMessageLevel::kError,
        GetFrame()->IsInFencedFrameTree()
            ? "Ignored call to 'alert()'. The document is in a fenced frame "
              "tree."
            : "Ignored call to 'alert()'. The document is sandboxed, and the "
              "'allow-modals' keyword is not set."));
    return;
  }

  if (IsRunningMicrotasks(script_state)) {
    UseCounter::Count(this, WebFeature::kDuring_Microtask_Alert);
  }

  document()->UpdateStyleAndLayoutTree();

  Page* page = GetFrame()->GetPage();
  if (!page)
    return;

  CountUseOnlyInSameOriginIframe(WebFeature::kSameOriginIframeWindowAlert);
  Deprecation::CountDeprecationCrossOriginIframe(
      this, WebFeature::kCrossOriginWindowAlert);

  page->GetChromeClient().OpenJavaScriptAlert(GetFrame(), message);
}

bool LocalDOMWindow::confirm(ScriptState* script_state, const String& message) {
  if (!GetFrame())
    return false;

  if (IsSandboxed(network::mojom::blink::WebSandboxFlags::kModals)) {
    UseCounter::Count(this, WebFeature::kDialogInSandboxedContext);
    GetFrameConsole()->AddMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kSecurity,
        mojom::blink::ConsoleMessageLevel::kError,
        GetFrame()->IsInFencedFrameTree()
            ? "Ignored call to 'confirm()'. The document is in a fenced frame "
              "tree."
            : "Ignored call to 'confirm()'. The document is sandboxed, and the "
              "'allow-modals' keyword is not set."));
    return false;
  }

  if (IsRunningMicrotasks(script_state)) {
    UseCounter::Count(this, WebFeature::kDuring_Microtask_Confirm);
  }

  document()->UpdateStyleAndLayoutTree();

  Page* page = GetFrame()->GetPage();
  if (!page)
    return false;

  CountUseOnlyInSameOriginIframe(WebFeature::kSameOriginIframeWindowConfirm);
  Deprecation::CountDeprecationCrossOriginIframe(
      this, WebFeature::kCrossOriginWindowConfirm);

  return page->GetChromeClient().OpenJavaScriptConfirm(GetFrame(), message);
}

String LocalDOMWindow::prompt(ScriptState* script_state,
                              const String& message,
                              const String& default_value) {
  if (!GetFrame())
    return String();

  if (IsSandboxed(network::mojom::blink::WebSandboxFlags::kModals)) {
    UseCounter::Count(this, WebFeature::kDialogInSandboxedContext);
    GetFrameConsole()->AddMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kSecurity,
        mojom::blink::ConsoleMessageLevel::kError,
        GetFrame()->IsInFencedFrameTree()
            ? "Ignored call to 'prompt()'. The document is in a fenced frame "
              "tree."
            : "Ignored call to 'prompt()'. The document is sandboxed, and the "
              "'allow-modals' keyword is not set."));
    return String();
  }

  if (IsRunningMicrotasks(script_state)) {
    UseCounter::Count(this, WebFeature::kDuring_Microtask_Prompt);
  }

  document()->UpdateStyleAndLayoutTree();

  Page* page = GetFrame()->GetPage();
  if (!page)
    return String();

  String return_value;
  if (page->GetChromeClient().OpenJavaScriptPrompt(GetFrame(), message,
                                                   default_value, return_value))
    return return_value;

  CountUseOnlyInSameOriginIframe(WebFeature::kSameOriginIframeWindowPrompt);
  Deprecation::CountDeprecationCrossOriginIframe(
      this, WebFeature::kCrossOriginWindowAlert);

  return String();
}

bool LocalDOMWindow::find(const String& string,
                          bool case_sensitive,
                          bool backwards,
                          bool wrap,
                          bool whole_word,
                          bool /*searchInFrames*/,
                          bool /*showDialog*/) const {
  auto forced_activatable_locks = document()
                                      ->GetDisplayLockDocumentState()
                                      .GetScopedForceActivatableLocks();

  if (!IsCurrentlyDisplayedInFrame())
    return false;

  // Up-to-date, clean tree is required for finding text in page, since it
  // relies on TextIterator to look over the text.
  document()->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);

  // FIXME (13016): Support searchInFrames and showDialog
  FindOptions options = FindOptions()
                            .SetBackwards(backwards)
                            .SetCaseInsensitive(!case_sensitive)
                            .SetWrappingAround(wrap)
                            .SetWholeWord(whole_word);
  return Editor::FindString(*GetFrame(), string, options);
}

bool LocalDOMWindow::offscreenBuffering() const {
  return true;
}

int LocalDOMWindow::outerHeight() const {
  if (!GetFrame())
    return 0;

  LocalFrame* frame = GetFrame();

  // FencedFrames should return innerHeight to prevent passing
  // arbitrary data through the window height.
  if (frame->IsInFencedFrameTree()) {
    return innerHeight();
  }

  Page* page = frame->GetPage();
  if (!page)
    return 0;

  ChromeClient& chrome_client = page->GetChromeClient();
  if (page->GetSettings().GetReportScreenSizeInPhysicalPixelsQuirk()) {
    return static_cast<int>(
        lroundf(chrome_client.RootWindowRect(*frame).height() *
                chrome_client.GetScreenInfo(*frame).device_scale_factor));
  }
  return chrome_client.RootWindowRect(*frame).height();
}

int LocalDOMWindow::outerWidth() const {
  if (!GetFrame())
    return 0;

  LocalFrame* frame = GetFrame();

  // FencedFrames should return innerWidth to prevent passing
  // arbitrary data through the window width.
  if (frame->IsInFencedFrameTree()) {
    return innerWidth();
  }

  Page* page = frame->GetPage();
  if (!page)
    return 0;

  ChromeClient& chrome_client = page->GetChromeClient();
  if (page->GetSettings().GetReportScreenSizeInPhysicalPixelsQuirk()) {
    return static_cast<int>(
        lroundf(chrome_client.RootWindowRect(*frame).width() *
                chrome_client.GetScreenInfo(*frame).device_scale_factor));
  }
  return chrome_client.RootWindowRect(*frame).width();
}

gfx::Size LocalDOMWindow::GetViewportSize() const {
  LocalFrameView* view = GetFrame()->View();
  if (!view)
    return gfx::Size();

  Page* page = GetFrame()->GetPage();
  if (!page)
    return gfx::Size();

  // The main frame's viewport size depends on the page scale. If viewport is
  // enabled, the initial page scale depends on the content width and is set
  // after a layout, perform one now so queries during page load will use the
  // up to date viewport.
  if (page->GetSettings().GetViewportEnabled() && GetFrame()->IsMainFrame()) {
    document()->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  }

  // FIXME: This is potentially too much work. We really only need to know the
  // dimensions of the parent frame's layoutObject.
  if (Frame* parent = GetFrame()->Tree().Parent()) {
    if (auto* parent_local_frame = DynamicTo<LocalFrame>(parent)) {
      parent_local_frame->GetDocument()->UpdateStyleAndLayout(
          DocumentUpdateReason::kJavaScript);
    }
  }

  return document()->View()->Size();
}

int LocalDOMWindow::innerHeight() const {
  if (!GetFrame())
    return 0;

  return AdjustForAbsoluteZoom::AdjustInt(GetViewportSize().height(),
                                          GetFrame()->LayoutZoomFactor());
}

int LocalDOMWindow::innerWidth() const {
  if (!GetFrame())
    return 0;

  return AdjustForAbsoluteZoom::AdjustInt(GetViewportSize().width(),
                                          GetFrame()->LayoutZoomFactor());
}

int LocalDOMWindow::screenX() const {
  LocalFrame* frame = GetFrame();
  if (!frame)
    return 0;

  Page* page = frame->GetPage();
  if (!page)
    return 0;

  ChromeClient& chrome_client = page->GetChromeClient();
  if (page->GetSettings().GetReportScreenSizeInPhysicalPixelsQuirk()) {
    return static_cast<int>(
        lroundf(chrome_client.RootWindowRect(*frame).x() *
                chrome_client.GetScreenInfo(*frame).device_scale_factor));
  }
  return chrome_client.RootWindowRect(*frame).x();
}

int LocalDOMWindow::screenY() const {
  LocalFrame* frame = GetFrame();
  if (!frame)
    return 0;

  Page* page = frame->GetPage();
  if (!page)
    return 0;

  ChromeClient& chrome_client = page->GetChromeClient();
  if (page->GetSettings().GetReportScreenSizeInPhysicalPixelsQuirk()) {
    return static_cast<int>(
        lroundf(chrome_client.RootWindowRect(*frame).y() *
                chrome_client.GetScreenInfo(*frame).device_scale_factor));
  }
  return chrome_client.RootWindowRect(*frame).y();
}

double LocalDOMWindow::scrollX() const {
  if (!GetFrame() || !GetFrame()->GetPage())
    return 0;

  LocalFrameView* view = GetFrame()->View();
  if (!view)
    return 0;

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidAccessScrollOffset();

  document()->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);

  // TODO(bokan): This is wrong when the document.rootScroller is non-default.
  // crbug.com/505516.
  double viewport_x = view->LayoutViewport()->GetWebExposedScrollOffset().x();
  return AdjustForAbsoluteZoom::AdjustScroll(viewport_x,
                                             GetFrame()->LayoutZoomFactor());
}

double LocalDOMWindow::scrollY() const {
  if (!GetFrame() || !GetFrame()->GetPage())
    return 0;

  LocalFrameView* view = GetFrame()->View();
  if (!view)
    return 0;

  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidAccessScrollOffset();

  document()->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);

  // TODO(bokan): This is wrong when the document.rootScroller is non-default.
  // crbug.com/505516.
  double viewport_y = view->LayoutViewport()->GetWebExposedScrollOffset().y();
  return AdjustForAbsoluteZoom::AdjustScroll(viewport_y,
                                             GetFrame()->LayoutZoomFactor());
}

DOMViewport* LocalDOMWindow::viewport() {
  return viewport_.Get();
}

DOMVisualViewport* LocalDOMWindow::visualViewport() {
  return visualViewport_.Get();
}

const AtomicString& LocalDOMWindow::name() const {
  if (!IsCurrentlyDisplayedInFrame())
    return g_null_atom;

  return GetFrame()->Tree().GetName();
}

void LocalDOMWindow::setName(const AtomicString& name) {
  if (!IsCurrentlyDisplayedInFrame())
    return;

  GetFrame()->Tree().SetName(name, FrameTree::kReplicate);
}

void LocalDOMWindow::setStatus(const String& string) {
  status_ = string;
}

void LocalDOMWindow::setDefaultStatus(const String& string) {
  DCHECK(RuntimeEnabledFeatures::WindowDefaultStatusEnabled());
  default_status_ = string;
}

String LocalDOMWindow::origin() cons
```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `local_frame.cc`. This is the second part of a larger file. The summary should include:

1. **Core functions:** What are the main actions this part of the code performs?
2. **Relationship to web technologies:** How does this code interact with JavaScript, HTML, and CSS? Provide examples.
3. **Logic and data flow:**  Identify any logical steps and data transformations, including hypothetical inputs and outputs.
4. **Potential errors:** Highlight common usage or programming errors that might occur in this context.

**Plan:**

1. **Read through the code:** Understand the purpose of each function in the provided snippet.
2. **Identify core functionalities:** Group related functions and their actions. Focus on the high-level goals.
3. **Analyze web technology connections:** Look for interactions with DOM elements, events, styling, and scripting.
4. **Trace logic and data:**  Examine conditional statements, data modifications, and function calls to infer the logical flow. Create hypothetical examples where needed.
5. **Consider error scenarios:**  Think about situations where things might go wrong, particularly related to object lifetimes, state management, and user interactions.
6. **Synthesize a summary:**  Combine the findings into a concise description of the code's role.
这是 `blink/renderer/core/frame/local_frame.cc` 文件第二部分的功能归纳：

**核心功能：**

这部分代码主要关注 `LocalFrame` 对象的生命周期管理和特定状态下的行为，特别是在页面卸载、打印和捕获时的处理。具体来说，它涵盖了以下几个关键领域：

1. **`DetachImpl` 方法：**  实现了 `LocalFrame` 对象的卸载逻辑，这是一个复杂的过程，需要保证线程安全和防止重入。它负责停止加载、触发 `unload` 事件、断开子框架、禁用脚本执行、清理各种资源（如性能监控器、绘图生成器、事件监听器等），并通知客户端即将被卸载。
2. **打印相关功能：**  提供了开始和结束打印的支持 (`StartPrinting`, `EndPrinting`)，并处理主框架和子框架的不同打印模式。它涉及到调整媒体类型、强制布局以适应页面大小、以及在打印过程中禁用资源验证。
3. **捕获相关功能：**  支持开始和结束捕获 (`StartPaintPreview`, `EndPaintPreview`)，这可能与创建页面快照或进行视觉调试有关。
4. **其他生命周期和状态管理：**  包括检查页面是否加载完成 (`CheckCompleted`)，获取绘图相关的生成器对象（用于背景色、阴影、裁剪路径的动画或效果），管理 BackForwardCache 的缓存和驱逐机制，处理框架的激活状态，以及更新突然终止状态。
5. **事件处理和消息传递：**  涉及到处理滚动事件的气泡传递，更新主题颜色和背景颜色，并与父框架或外部通信以进行同步。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    * **`DetachImpl` 中的 `loader_.DispatchUnloadEventAndFillOldDocumentInfoIfNeeded()`:**  在框架卸载时，会触发 JavaScript 的 `unload` 事件处理函数。JavaScript 代码可能会在此时执行清理操作。
    * **BackForwardCache 驱逐:** 当 JavaScript 在缓存中的页面执行时，会触发驱逐机制，防止页面状态被修改。
    * **`UpdateSuddenTerminationStatus`:** 当 JavaScript 代码添加或移除 `beforeunload`, `unload`, `pagehide`, `visibilitychange` 事件监听器时，会影响浏览器的突然终止行为，这些事件主要由 JavaScript 注册和处理。
    * **假设输入与输出 (BackForwardCache 驱逐):**
        * **假设输入:** 用户通过浏览器的前进/后退按钮尝试导航到一个缓存中的页面，且该页面注册了 `unload` 事件监听器。
        * **输出:**  在页面恢复前，如果尝试执行任何 JavaScript 代码，`SetAbortScriptExecution` 注册的回调函数会被调用，从而触发页面从 BackForwardCache 中被驱逐。
* **HTML:**
    * **`DetachChildren()`:**  在框架卸载时，会断开所有子框架，这直接操作了 DOM 树的结构，移除了 HTML 元素 `<frame>` 或 `<iframe>`。
    * **`DidAttachDocument()`:** 当一个新的 HTML 文档被附加到框架时，会执行一些初始化操作，例如清除编辑器状态和事件处理程序。
* **CSS:**
    * **`DidChangeThemeColor()` 和 `DidChangeBackgroundColor()`:**  这些函数会通知浏览器渲染进程主题颜色和背景颜色的变化，这些颜色可能由 HTML 的 `<meta name="theme-color">` 标签或 CSS 样式定义。
    * **`View()->AdjustMediaTypeForPrinting(printing)`:**  在开始打印时，会切换文档的媒体类型到 "print"，这会影响 CSS 规则的解析和应用，使得 `@media print` 中定义的样式生效。
    * **`ShouldUsePaginatedLayout()` 和打印布局:**  打印功能会根据需要强制布局以适应页面大小，这会影响 CSS 布局模型的计算。

**逻辑推理与假设输入输出：**

* **`ShouldMaintainTrivialSessionHistory()`:**
    * **假设输入 1:**  当前框架正在进行预渲染 (`GetDocument()->IsPrerendering()` 返回 `true`)。
    * **输出 1:**  函数返回 `true`，表示应该维护简单的会话历史。
    * **假设输入 2:** 当前框架不在预渲染且不在 Fenced Frame 树中 (`IsInFencedFrameTree()` 返回 `false`)。
    * **输出 2:** 函数返回 `false`。
* **`ShouldClose()`:**  该函数调用 `loader_.ShouldClose()`，这涉及到检查是否有 `beforeunload` 事件监听器阻止页面关闭。
    * **假设输入:**  页面注册了 `beforeunload` 事件监听器并返回了一个非空字符串。
    * **输出:** `loader_.ShouldClose()` 返回 `true` (根据 `beforeunload` 的逻辑)，`LocalFrame::ShouldClose()` 也返回 `true`。
* **`OnFirstPaint()`:**  根据首次绘制的文本或图像的背景色来推断文档的配色方案。
    * **假设输入:**  首次绘制的元素的背景色是深色（例如，HSL 中的 L 值小于 0.5）。
    * **输出:** 调用 `GetLocalFrameHostRemote().DidInferColorScheme(mojom::blink::PreferredColorScheme::kDark)`，通知浏览器渲染进程推断的配色方案为深色。

**用户或编程常见的使用错误：**

* **在 `DetachImpl` 的重入安全区域外执行可能触发脚本的代码:**  如果开发者在 `END REENTRANCY SAFE BLOCK` 之后执行了可能导致 JavaScript 运行的代码（例如，删除一个包含事件监听器的 DOM 节点），则可能导致程序崩溃或未定义的行为，因为此时框架的状态可能正在被清理。代码中通过 `DCHECK(!IsDetached())` 来进行断言检查。
* **在框架卸载后访问其资源:**  一旦 `DetachImpl` 完成，`LocalFrame` 对象及其关联的文档和资源都应该被视为无效。尝试访问这些资源会导致错误。
* **错误地配置打印参数:**  例如，为子框架设置 `use_paginated_layout` 为 `true` 是没有意义的，因为只有根框架才能进行分页布局。代码中通过 `ShouldUsePaginatedLayout()` 的逻辑来避免这种情况。
* **忘记移除事件监听器导致 BackForwardCache 失效:**  如果开发者在页面中注册了 `beforeunload` 等事件监听器，但没有在不需要时移除，可能会意外地阻止页面进入 BackForwardCache，影响导航性能。代码中 `UpdateSuddenTerminationStatus` 跟踪了这些监听器的状态。

**总结：**

这部分 `LocalFrame` 的代码主要负责管理框架在卸载、打印和捕获等关键生命周期阶段的行为。它与 JavaScript、HTML 和 CSS 紧密相关，通过触发事件、操作 DOM 结构、调整样式和媒体类型等方式进行交互。代码中包含了对线程安全、重入问题以及资源清理的考虑，并提供了一些机制来处理与用户交互和性能优化相关的任务，例如 BackForwardCache 的管理和事件处理。

### 提示词
```
这是目录为blink/renderer/core/frame/local_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
n() ==
          ClientNavigationReason::kAnchorClick) {
    return false;
  }
  return true;
}

bool LocalFrame::ShouldMaintainTrivialSessionHistory() const {
  // This should be kept in sync with
  // NavigationControllerImpl::ShouldMaintainTrivialSessionHistory.
  return GetDocument()->IsPrerendering() || IsInFencedFrameTree();
}

bool LocalFrame::DetachImpl(FrameDetachType type) {
  TRACE_EVENT1("navigation", "LocalFrame::DetachImpl", "detach_type",
               static_cast<int>(type));
  std::string_view histogram_suffix =
      (type == FrameDetachType::kRemove) ? "Remove" : "Swap";
  base::ScopedUmaHistogramTimer histogram_timer(
      base::StrCat({"Navigation.LocalFrame.DetachImpl.", histogram_suffix}));
  absl::Cleanup check_post_condition = [this] {
    // This method must shutdown objects associated with it (such as
    // the `PerformanceMonitor` for local roots).
    CHECK(did_run_detach_impl_);
  };

  // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  // BEGIN REENTRANCY SAFE BLOCK
  // Starting here, the code must be safe against reentrancy. Dispatching
  // events, et cetera can run Javascript, which can reenter Detach().
  //
  // Most cleanup code should *not* be in inside the reentrancy safe block.
  // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

  if (IsProvisional()) {
    Frame* provisional_owner = GetProvisionalOwnerFrame();
    // Having multiple provisional frames somehow associated with the same frame
    // to potentially replace is a logic error.
    DCHECK_EQ(provisional_owner->ProvisionalFrame(), this);
    provisional_owner->SetProvisionalFrame(nullptr);
  }

  PluginScriptForbiddenScope forbid_plugin_destructor_scripting;
  // In a kSwap detach, if we have a navigation going, its moved to the frame
  // being swapped in, so we don't need to notify the client about the
  // navigation stopping here. That will be up to the provisional frame being
  // swapped in, which knows the actual state of the navigation.
  loader_.StopAllLoaders(/*abort_client=*/type == FrameDetachType::kRemove);
  // Don't allow any new child frames to load in this frame: attaching a new
  // child frame during or after detaching children results in an attached
  // frame on a detached DOM tree, which is bad.
  SubframeLoadingDisabler disabler(*GetDocument());
  // https://html.spec.whatwg.org/C/browsing-the-web.html#unload-a-document
  // The ignore-opens-during-unload counter of a Document must be incremented
  // both when unloading itself and when unloading its descendants.
  IgnoreOpensDuringUnloadCountIncrementer ignore_opens_during_unload(
      GetDocument());

  loader_.DispatchUnloadEventAndFillOldDocumentInfoIfNeeded(
      type == FrameDetachType::kSwap);
  if (evict_cached_session_storage_on_freeze_or_unload_) {
    // Evicts the cached data of Session Storage to avoid reusing old data in
    // the cache after the session storage has been modified by another renderer
    // process.
    CoreInitializer::GetInstance().EvictSessionStorageCachedData(
        GetDocument()->GetPage());
  }
  if (!Client())
    return false;

  if (!DetachChildren())
    return false;

  // Detach() needs to be called after detachChildren(), because
  // detachChildren() will trigger the unload event handlers of any child
  // frames, and those event handlers might start a new subresource load in this
  // frame which should be stopped by Detach.
  loader_.Detach();
  DomWindow()->FrameDestroyed();

  // Verify here that any LocalFrameView has been detached by now.
  if (view_ && view_->IsAttached()) {
    DCHECK(DeprecatedLocalOwner());
    DCHECK(DeprecatedLocalOwner()->OwnedEmbeddedContentView());
    DCHECK_EQ(view_, DeprecatedLocalOwner()->OwnedEmbeddedContentView());
  }
  DCHECK(!view_ || !view_->IsAttached());

  // This is the earliest that scripting can be disabled:
  // - FrameLoader::Detach() can fire XHR abort events
  // - Document::Shutdown() can dispose plugins which can run script.
  ScriptForbiddenScope forbid_script;
  if (!Client())
    return false;

  // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  // END REENTRANCY SAFE BLOCK
  // Past this point, no script should be executed. If this method was
  // reentered, then a check for a null Client() above should have already
  // returned false.
  // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  DCHECK(!IsDetached());

  if (frame_color_overlay_)
    frame_color_overlay_.Release()->Destroy();

  if (IsLocalRoot()) {
    performance_monitor_->Shutdown();

    if (ad_tracker_)
      ad_tracker_->Shutdown();
    // Unregister only if this is LocalRoot because the paint_image_generator_
    // was created on LocalRoot.
    if (background_color_paint_image_generator_)
      background_color_paint_image_generator_->Shutdown();
    if (box_shadow_paint_image_generator_)
      box_shadow_paint_image_generator_->Shutdown();
    if (clip_path_paint_image_generator_)
      clip_path_paint_image_generator_->Shutdown();
    if (script_observer_) {
      script_observer_->Shutdown();
    }
  }
  idleness_detector_->Shutdown();
  if (inspector_issue_reporter_)
    probe_sink_->RemoveInspectorIssueReporter(inspector_issue_reporter_);
  if (inspector_trace_events_)
    probe_sink_->RemoveInspectorTraceEvents(inspector_trace_events_);
  inspector_task_runner_->Dispose();

  if (content_capture_manager_) {
    content_capture_manager_->Shutdown();
    content_capture_manager_ = nullptr;
  }

  if (text_fragment_handler_)
    text_fragment_handler_->DidDetachDocumentOrFrame();

  not_restored_reasons_.reset();

  DCHECK(!view_->IsAttached());
  Client()->WillBeDetached();

  // TODO(crbug.com/729196): Trace why LocalFrameView::DetachFromLayout crashes.
  CHECK(!view_->IsAttached());
  SetView(nullptr);

  GetEventHandlerRegistry().DidRemoveAllEventHandlers(*DomWindow());

  probe::FrameDetachedFromParent(this, type);

  supplements_.clear();
  frame_scheduler_.reset();
  mojo_handler_->DidDetachFrame();
  WeakIdentifierMap<LocalFrame>::NotifyObjectDestroyed(this);

  did_run_detach_impl_ = true;
  return true;
}

bool LocalFrame::DetachDocument() {
  return Loader().DetachDocument();
}

void LocalFrame::CheckCompleted() {
  GetDocument()->CheckCompleted();
}

BackgroundColorPaintImageGenerator*
LocalFrame::GetBackgroundColorPaintImageGenerator() {
  LocalFrame& local_root = LocalFrameRoot();
  // One background color paint worklet per root frame.
  // There is no compositor thread in certain testing environment, and we
  // should not composite background color animation in those cases.
  if (Thread::CompositorThread() &&
      !local_root.background_color_paint_image_generator_) {
    local_root.background_color_paint_image_generator_ =
        BackgroundColorPaintImageGenerator::Create(local_root);
  }
  return local_root.background_color_paint_image_generator_.Get();
}

void LocalFrame::SetBackgroundColorPaintImageGeneratorForTesting(
    BackgroundColorPaintImageGenerator* generator_for_testing) {
  LocalFrame& local_root = LocalFrameRoot();
  local_root.background_color_paint_image_generator_ = generator_for_testing;
}

BoxShadowPaintImageGenerator* LocalFrame::GetBoxShadowPaintImageGenerator() {
  // There is no compositor thread in certain testing environment, and we should
  // not composite background color animation in those cases.
  if (!Thread::CompositorThread())
    return nullptr;
  LocalFrame& local_root = LocalFrameRoot();
  // One box shadow paint worklet per root frame.
  if (!local_root.box_shadow_paint_image_generator_) {
    local_root.box_shadow_paint_image_generator_ =
        BoxShadowPaintImageGenerator::Create(local_root);
  }
  return local_root.box_shadow_paint_image_generator_.Get();
}

ClipPathPaintImageGenerator* LocalFrame::GetClipPathPaintImageGenerator() {
  LocalFrame& local_root = LocalFrameRoot();
  // One clip path paint worklet per root frame.
  if (!local_root.clip_path_paint_image_generator_) {
    local_root.clip_path_paint_image_generator_ =
        ClipPathPaintImageGenerator::Create(local_root);
  }
  return local_root.clip_path_paint_image_generator_.Get();
}

void LocalFrame::SetClipPathPaintImageGeneratorForTesting(
    ClipPathPaintImageGenerator* generator) {
  LocalFrame& local_root = LocalFrameRoot();
  local_root.clip_path_paint_image_generator_ = generator;
}

LCPCriticalPathPredictor* LocalFrame::GetLCPP() {
  if (!LcppEnabled()) {
    return nullptr;
  }

  // For now, we only attach LCPP to the outermost main frames.
  if (!IsOutermostMainFrame()) {
    return nullptr;
  }

  if (!lcpp_) {
    lcpp_ = MakeGarbageCollected<LCPCriticalPathPredictor>(*this);
  }
  return lcpp_.Get();
}

const SecurityContext* LocalFrame::GetSecurityContext() const {
  return DomWindow() ? &DomWindow()->GetSecurityContext() : nullptr;
}

// Provides a string description of the Frame as either its URL or origin if
// remote.
static String FrameDescription(const Frame& frame) {
  // URLs aren't available for RemoteFrames, so the error message uses their
  // origin instead.
  const LocalFrame* local_frame = DynamicTo<LocalFrame>(&frame);
  return local_frame
             ? "with URL '" +
                   local_frame->GetDocument()->Url().GetString().GetString() +
                   "'"
             : "with origin '" +
                   frame.GetSecurityContext()->GetSecurityOrigin()->ToString() +
                   "'";
}

void LocalFrame::PrintNavigationErrorMessage(const Frame& target_frame,
                                             const String& reason) {
  String message = "Unsafe attempt to initiate navigation for frame " +
                   FrameDescription(target_frame) + " from frame with URL '" +
                   GetDocument()->Url().GetString() + "'. " + reason + "\n";

  DomWindow()->PrintErrorMessage(message);
}

void LocalFrame::PrintNavigationWarning(const String& message) {
  console_->AddMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kWarning, message));
}

bool LocalFrame::ShouldClose() {
  // TODO(crbug.com/1407078): This should be fixed to dispatch beforeunload
  // events to both local and remote frames.
  return loader_.ShouldClose();
}

bool LocalFrame::DetachChildren() {
  DCHECK(GetDocument());
  ChildFrameDisconnector(
      *GetDocument(),
      ChildFrameDisconnector::DisconnectReason::kDisconnectParent)
      .Disconnect();
  return !!Client();
}

void LocalFrame::DidAttachDocument() {
  Document* document = GetDocument();
  DCHECK(document);
  GetEditor().Clear();
  // Clearing the event handler clears many events, but notably can ensure that
  // for a drag started on an element in a frame that was moved (likely via
  // appendChild()), the drag source will detach and stop firing drag events
  // even after the frame reattaches.
  GetEventHandler().Clear();
  Selection().DidAttachDocument(document);
  notified_color_scheme_ = false;

  smooth_scroll_sequencer_.Clear();

#if !BUILDFLAG(IS_ANDROID)
  // For PWAs with display_override "window-controls-overlay", titlebar area
  // rect bounds sent from the browser need to persist on navigation to keep the
  // UI consistent. The titlebar area rect values are set in |LocalFrame| before
  // the new document is attached. The css environment variables are needed to
  // be set for the new document.
  if (is_window_controls_overlay_visible_) {
    DocumentStyleEnvironmentVariables& vars =
        GetDocument()->GetStyleEngine().EnsureEnvironmentVariables();
    DCHECK(!vars.ResolveVariable(
        StyleEnvironmentVariables::GetVariableName(
            UADefinedVariable::kTitlebarAreaX, document->GetExecutionContext()),
        {}, false /* record_metrics */));
    SetTitlebarAreaDocumentStyleEnvironmentVariables();
  }
#endif
}

void LocalFrame::OnFirstPaint(bool text_painted, bool image_painted) {
  if (notified_color_scheme_)
    return;

  if (text_painted || image_painted) {
    // Infer the document's color scheme according to the background color, this
    // approach assumes that the background won't be changed after the first
    // text or image is painted, otherwise, the document will have a jarring
    // flash which should be avoid by most pages.
    double h, s, l;
    View()->DocumentBackgroundColor().GetHSL(h, s, l);
    GetLocalFrameHostRemote().DidInferColorScheme(
        l < 0.5 ? mojom::blink::PreferredColorScheme::kDark
                : mojom::blink::PreferredColorScheme::kLight);
    notified_color_scheme_ = true;
  }
}

void LocalFrame::OnFirstContentfulPaint() {
  if (IsOutermostMainFrame()) {
    GetPage()->GetChromeClient().OnFirstContentfulPaint();
  }
}

bool LocalFrame::CanAccessEvent(
    const WebInputEventAttribution& attribution) const {
  switch (attribution.type()) {
    case WebInputEventAttribution::kTargetedFrame: {
      auto* frame_document = GetDocument();
      if (!frame_document)
        return false;

      Document* target_document = nullptr;
      if (auto* page = frame_document->GetPage()) {
        auto& pointer_lock_controller = page->GetPointerLockController();
        if (auto* element = pointer_lock_controller.GetElement()) {
          // If a pointer lock is held, we can expect all events to be
          // dispatched to the frame containing the locked element.
          target_document = &element->GetDocument();
        } else if (cc::ElementId element_id = attribution.target_frame_id()) {
          DOMNodeId target_document_id =
              DOMNodeIdFromCompositorElementId(element_id);
          target_document =
              DynamicTo<Document>(DOMNodeIds::NodeForId(target_document_id));
        }
      }

      if (!target_document || !target_document->domWindow())
        return false;

      return GetSecurityContext()->GetSecurityOrigin()->CanAccess(
          target_document->domWindow()->GetSecurityOrigin());
    }
    case WebInputEventAttribution::kFocusedFrame:
      return GetPage() ? GetPage()->GetFocusController().FocusedFrame() == this
                       : false;
    case WebInputEventAttribution::kUnknown:
      return false;
  }
}

void LocalFrame::Reload(WebFrameLoadType load_type) {
  DCHECK(IsReloadLoadType(load_type));
  if (!loader_.GetDocumentLoader()->GetHistoryItem())
    return;
  TRACE_EVENT1("navigation", "LocalFrame::Reload", "load_type",
               static_cast<int>(load_type));

  FrameLoadRequest request(
      DomWindow(), loader_.ResourceRequestForReload(
                       load_type, ClientRedirectPolicy::kClientRedirect));
  request.SetClientNavigationReason(ClientNavigationReason::kReload);
  probe::FrameScheduledNavigation(this, request.GetResourceRequest().Url(),
                                  base::TimeDelta(),
                                  ClientNavigationReason::kReload);
  loader_.StartNavigation(request, load_type);
  probe::FrameClearedScheduledNavigation(this);
}

LocalWindowProxy* LocalFrame::WindowProxy(DOMWrapperWorld& world) {
  return To<LocalWindowProxy>(Frame::GetWindowProxy(world));
}

LocalWindowProxy* LocalFrame::WindowProxyMaybeUninitialized(
    DOMWrapperWorld& world) {
  return To<LocalWindowProxy>(Frame::GetWindowProxyMaybeUninitialized(world));
}

LocalDOMWindow* LocalFrame::DomWindow() {
  return To<LocalDOMWindow>(dom_window_.Get());
}

const LocalDOMWindow* LocalFrame::DomWindow() const {
  return To<LocalDOMWindow>(dom_window_.Get());
}

void LocalFrame::SetDOMWindow(LocalDOMWindow* dom_window) {
  DCHECK(dom_window);
  if (DomWindow()) {
    DomWindow()->Reset();
    // SystemClipboard uses HeapMojo wrappers. HeapMojo
    // wrappers uses LocalDOMWindow (ExecutionContext) to reset the mojo
    // objects when the ExecutionContext was destroyed. So when new
    // LocalDOMWindow was set, we need to create new SystemClipboard.
    system_clipboard_ = nullptr;
  }
  GetWindowProxyManager()->ClearForNavigation();
  dom_window_ = dom_window;
  dom_window->Initialize();
  GetFrameScheduler()->SetAgentClusterId(GetAgentClusterId());
}

Document* LocalFrame::GetDocument() const {
  return DomWindow() ? DomWindow()->document() : nullptr;
}

void LocalFrame::DocumentDetached() {
  // Resets WebLinkPreviewTrigerer when the document detached as
  // WebLinkPreviewInitiator depends on document.
  is_link_preivew_triggerer_initialized_ = false;
  link_preview_triggerer_.reset();

  if (LocalFrameView* view = View()) {
    // Pagination layout may hold on to layout objects that are not part of the
    // Document's DOM. Destroy them now.
    view->DestroyPaginationLayout();
  }
}

void LocalFrame::SetPagePopupOwner(Element& owner) {
  page_popup_owner_ = &owner;
}

LayoutView* LocalFrame::ContentLayoutObject() const {
  return GetDocument() ? GetDocument()->GetLayoutView() : nullptr;
}

void LocalFrame::DidChangeVisibilityState() {
  if (GetDocument())
    GetDocument()->DidChangeVisibilityState();

  Frame::DidChangeVisibilityState();
}

void LocalFrame::AddWidgetCreationObserver(WidgetCreationObserver* observer) {
  CHECK(IsLocalRoot());
  CHECK(!GetWidgetForLocalRoot());

  widget_creation_observers_.insert(observer);
}

void LocalFrame::NotifyFrameWidgetCreated() {
  CHECK(IsLocalRoot());
  CHECK(GetWidgetForLocalRoot());

  // No need to copy `widget_creation_observers_` since we don't permit adding
  // new observers after this point.
  for (WidgetCreationObserver* observer : widget_creation_observers_) {
    observer->OnLocalRootWidgetCreated();
  }

  widget_creation_observers_.clear();
}

bool LocalFrame::IsCaretBrowsingEnabled() const {
  return GetSettings() ? GetSettings()->GetCaretBrowsingEnabled() : false;
}

void LocalFrame::HookBackForwardCacheEviction() {
  TRACE_EVENT0("blink", "LocalFrame::HookBackForwardCacheEviction");
  // Register a callback dispatched when JavaScript is executed on the frame.
  // The callback evicts the frame. If a frame is frozen by BackForwardCache,
  // the frame must not be mutated e.g., by JavaScript execution, then the
  // frame must be evicted in such cases.
  DCHECK(RuntimeEnabledFeatures::BackForwardCacheEnabled());
  static_cast<LocalWindowProxyManager*>(GetWindowProxyManager())
      ->SetAbortScriptExecution(
          [](v8::Isolate* isolate, v8::Local<v8::Context> context) {
            ScriptState* script_state = ScriptState::From(isolate, context);
            LocalDOMWindow* window = LocalDOMWindow::From(script_state);
            DCHECK(window);
            LocalFrame* frame = window->GetFrame();
            if (frame) {
              std::unique_ptr<SourceLocation> source_location = nullptr;
              if (base::FeatureList::IsEnabled(
                      features::kCaptureJSExecutionLocation)) {
                // Capture the source location of the JS execution if the flag
                // is enabled.
                source_location = CaptureSourceLocation();
              }
              frame->EvictFromBackForwardCache(
                  mojom::blink::RendererEvictionReason::kJavaScriptExecution,
                  std::move(source_location));
              if (base::FeatureList::IsEnabled(
                      features::kBackForwardCacheDWCOnJavaScriptExecution)) {
                // Adding |DumpWithoutCrashing()| here to make sure this is not
                // happening in any tests, except for when this is expected.
                base::debug::DumpWithoutCrashing();
              }
            }
          });
}

void LocalFrame::RemoveBackForwardCacheEviction() {
  TRACE_EVENT0("blink", "LocalFrame::RemoveBackForwardCacheEviction");
  DCHECK(RuntimeEnabledFeatures::BackForwardCacheEnabled());
  static_cast<LocalWindowProxyManager*>(GetWindowProxyManager())
      ->SetAbortScriptExecution(nullptr);

  // The page is being restored, and from this point eviction should not happen
  // for any reason. Change the deferring state from |kBufferIncoming| to
  // |kStrict| so that network related eviction cannot happen.
  GetDocument()->Fetcher()->SetDefersLoading(LoaderFreezeMode::kStrict);
}

void LocalFrame::SetTextDirection(base::i18n::TextDirection direction) {
  // The Editor::SetBaseWritingDirection() function checks if we can change
  // the text direction of the selected node and updates its DOM "dir"
  // attribute and its CSS "direction" property.
  // So, we just call the function as Safari does.
  Editor& editor = GetEditor();
  if (!editor.CanEdit())
    return;

  switch (direction) {
    case base::i18n::TextDirection::UNKNOWN_DIRECTION:
      editor.SetBaseWritingDirection(
          mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION);
      break;

    case base::i18n::TextDirection::LEFT_TO_RIGHT:
      editor.SetBaseWritingDirection(
          mojo_base::mojom::blink::TextDirection::LEFT_TO_RIGHT);
      break;

    case base::i18n::TextDirection::RIGHT_TO_LEFT:
      editor.SetBaseWritingDirection(
          mojo_base::mojom::blink::TextDirection::RIGHT_TO_LEFT);
      break;

    default:
      NOTIMPLEMENTED();
      break;
  }
}

void LocalFrame::SetIsInert(bool inert) {
  if (is_inert_ == inert)
    return;
  is_inert_ = inert;

  // Propagate inert to child frames
  for (Frame* child = Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    child->UpdateInertIfPossible();
  }

  // Nodes all over the accessibility tree can change inertness which means they
  // must be added or removed from the tree.
  if (GetDocument()) {
    GetDocument()->RefreshAccessibilityTree();
  }
}

void LocalFrame::SetInheritedEffectiveTouchAction(TouchAction touch_action) {
  if (inherited_effective_touch_action_ == touch_action)
    return;
  inherited_effective_touch_action_ = touch_action;
  GetDocument()->GetStyleEngine().MarkAllElementsForStyleRecalc(
      StyleChangeReasonForTracing::Create(
          style_change_reason::kInheritedStyleChangeFromParentFrame));
}

bool LocalFrame::BubbleLogicalScrollInParentFrame(
    mojom::blink::ScrollDirection direction,
    ui::ScrollGranularity granularity) {
  bool is_embedded_main_frame = IsMainFrame() && !IsOutermostMainFrame();
  if (is_embedded_main_frame || IsA<RemoteFrame>(Parent())) {
    GetLocalFrameHostRemote().BubbleLogicalScrollInParentFrame(direction,
                                                               granularity);
    return false;
  } else if (auto* local_parent = DynamicTo<LocalFrame>(Parent())) {
    return local_parent->BubbleLogicalScrollFromChildFrame(direction,
                                                           granularity, this);
  }

  DCHECK(IsOutermostMainFrame());
  return false;
}

bool LocalFrame::BubbleLogicalScrollFromChildFrame(
    mojom::blink::ScrollDirection direction,
    ui::ScrollGranularity granularity,
    Frame* child) {
  FrameOwner* owner = child->Owner();
  auto* owner_element = DynamicTo<HTMLFrameOwnerElement>(owner);
  DCHECK(owner_element);

  return GetEventHandler().BubblingScroll(direction, granularity,
                                          owner_element);
}

mojom::blink::SuddenTerminationDisablerType
SuddenTerminationDisablerTypeForEventType(const AtomicString& event_type) {
  if (event_type == event_type_names::kUnload) {
    return mojom::blink::SuddenTerminationDisablerType::kUnloadHandler;
  }
  if (event_type == event_type_names::kBeforeunload) {
    return mojom::blink::SuddenTerminationDisablerType::kBeforeUnloadHandler;
  }
  if (event_type == event_type_names::kPagehide) {
    return mojom::blink::SuddenTerminationDisablerType::kPageHideHandler;
  }
  if (event_type == event_type_names::kVisibilitychange) {
    return mojom::blink::SuddenTerminationDisablerType::
        kVisibilityChangeHandler;
  }
  NOTREACHED();
}

int NumberOfSuddenTerminationEventListeners(const EventTarget& event_target,
                                            const AtomicString& event_type) {
  if (event_type != event_type_names::kVisibilitychange)
    return event_target.NumberOfEventListeners(event_type);
  // For visibilitychange, we need to count the number of event listeners that
  // are registered on the document and the window, as the event is initially
  // dispatched on the document but might bubble up to the window.
  // The other events (beforeunload, unload, pagehide) are dispatched on the
  // window and won't bubble up anywhere, so we don't need to check for
  // listeners the document for those events.
  int total_listeners_count = event_target.NumberOfEventListeners(event_type);
  if (auto* dom_window = event_target.ToLocalDOMWindow()) {
    // |event_target| is the window, so get the count for listeners registered
    // on the document.
    total_listeners_count +=
        dom_window->document()->NumberOfEventListeners(event_type);
  } else {
    auto* node = const_cast<EventTarget*>(&event_target)->ToNode();
    DCHECK(node);
    DCHECK(node->IsDocumentNode());
    DCHECK(node->GetDocument().domWindow());
    // |event_target| is the document, so get the count for listeners registered
    // on the window.
    total_listeners_count +=
        node->GetDocument().domWindow()->NumberOfEventListeners(event_type);
  }
  return total_listeners_count;
}

void LocalFrame::UpdateSuddenTerminationStatus(
    bool added_listener,
    mojom::blink::SuddenTerminationDisablerType disabler_type) {
  Platform::Current()->SuddenTerminationChanged(!added_listener);
  if (features::IsUnloadBlocklisted()) {
    // Block BFCache for using the unload handler. Originally unload handler was
    // not a blocklisted feature, but we make them blocklisted so the source
    // location will be captured. See https://crbug.com/1513120 for details.
    if (disabler_type ==
        mojom::blink::SuddenTerminationDisablerType::kUnloadHandler) {
      if (added_listener) {
        if (feature_handle_for_scheduler_) {
          return;
        }
        feature_handle_for_scheduler_ = GetFrameScheduler()->RegisterFeature(
            SchedulingPolicy::Feature::kUnloadHandler,
            {SchedulingPolicy::DisableBackForwardCache()});
      } else {
        feature_handle_for_scheduler_.reset();
      }
    }
  }
  GetLocalFrameHostRemote().SuddenTerminationDisablerChanged(added_listener,
                                                             disabler_type);
}

void LocalFrame::AddedSuddenTerminationDisablerListener(
    const EventTarget& event_target,
    const AtomicString& event_type) {
  if (NumberOfSuddenTerminationEventListeners(event_target, event_type) == 1) {
    // The first handler of this type was added.
    UpdateSuddenTerminationStatus(
        true, SuddenTerminationDisablerTypeForEventType(event_type));
  }
}

void LocalFrame::RemovedSuddenTerminationDisablerListener(
    const EventTarget& event_target,
    const AtomicString& event_type) {
  if (NumberOfSuddenTerminationEventListeners(event_target, event_type) == 0) {
    // The last handler of this type was removed.
    UpdateSuddenTerminationStatus(
        false, SuddenTerminationDisablerTypeForEventType(event_type));
  }
}

void LocalFrame::DidFocus() {
  GetLocalFrameHostRemote().DidFocusFrame();
}

void LocalFrame::DidChangeThemeColor(bool update_theme_color_cache) {
  if (Tree().Parent())
    return;

  if (update_theme_color_cache)
    GetDocument()->UpdateThemeColorCache();

  std::optional<Color> color = GetDocument()->ThemeColor();
  std::optional<SkColor> sk_color;
  if (color)
    sk_color = color->Rgb();

  GetLocalFrameHostRemote().DidChangeThemeColor(sk_color);
}

void LocalFrame::DidChangeBackgroundColor(SkColor4f background_color,
                                          bool color_adjust) {
  DCHECK(!Tree().Parent());
  GetLocalFrameHostRemote().DidChangeBackgroundColor(background_color,
                                                     color_adjust);
}

LocalFrame& LocalFrame::LocalFrameRoot() const {
  const LocalFrame* cur_frame = this;
  while (cur_frame && IsA<LocalFrame>(cur_frame->Parent()))
    cur_frame = To<LocalFrame>(cur_frame->Parent());

  return const_cast<LocalFrame&>(*cur_frame);
}

scoped_refptr<InspectorTaskRunner> LocalFrame::GetInspectorTaskRunner() {
  return inspector_task_runner_;
}

void LocalFrame::StartPrinting(const WebPrintParams& print_params,
                               float maximum_shrink_ratio) {
  DCHECK(!saved_scroll_offsets_);
  print_params_ = print_params;

  if (!print_params_.use_paginated_layout) {
    // Not laying out for pagination (e.g. this is a subframe, or a special
    // headers/footers document, which is generated once per page). Just set the
    // initial containing block to the default page size from print parameters.
    if (LayoutView* layout_view = View()->GetLayoutView()) {
      auto size = PhysicalSize::FromSizeFRound(
          print_params_.default_page_description.size);
      layout_view->SetInitialContainingBlockSizeForPrinting(size);
    }
  }

  SetPrinting(true, maximum_shrink_ratio);
}

void LocalFrame::StartPrintingSubLocalFrame() {
  gfx::SizeF page_size;
  // This is a subframe. Use the non-printing layout size as "pagination" size.
  if (const LayoutView* layout_view = View()->GetLayoutView()) {
    page_size =
        gfx::SizeF(layout_view->GetNonPrintingLayoutSize(kIncludeScrollbars));
  }
  WebPrintParams print_params(page_size);

  // Only the root frame is paginated.
  print_params.use_paginated_layout = false;

  StartPrinting(print_params);
}

void LocalFrame::EndPrinting() {
  RestoreScrollOffsets();
  SetPrinting(false, 0);
}

void LocalFrame::SetPrinting(bool printing, float maximum_shrink_ratio) {
  // In setting printing, we should not validate resources already cached for
  // the document.  See https://bugs.webkit.org/show_bug.cgi?id=43704
  ResourceCacheValidationSuppressor validation_suppressor(
      GetDocument()->Fetcher());

  GetDocument()->SetPrinting(printing ? Document::kPrinting
                                      : Document::kFinishingPrinting);
  View()->AdjustMediaTypeForPrinting(printing);

  if (TextAutosizer* text_autosizer = GetDocument()->GetTextAutosizer())
    text_autosizer->UpdatePageInfo();

  if (ShouldUsePaginatedLayout()) {
    View()->ForceLayoutForPagination(maximum_shrink_ratio);
  } else {
    if (LayoutView* layout_view = View()->GetLayoutView()) {
      layout_view->SetIntrinsicLogicalWidthsDirty();
      layout_view->SetNeedsLayout(layout_invalidation_reason::kPrintingChanged);
      layout_view->InvalidatePaintForViewAndDescendants();
    }
    GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kPrinting);
    View()->AdjustViewSize();

    View()->DestroyPaginationLayout();
  }

  // Subframes of the one we're printing don't lay out to the page size.
  for (Frame* child = Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    if (auto* child_local_frame = DynamicTo<LocalFrame>(child)) {
      if (printing) {
        child_local_frame->StartPrintingSubLocalFrame();
      } else {
        child_local_frame->EndPrinting();
      }
    }
  }

  if (auto* layout_view = View()->GetLayoutView()) {
    layout_view->AddSubtreePaintPropertyUpdateReason(
        SubtreePaintPropertyUpdateReason::kPrinting);
  }

  if (!printing)
    GetDocument()->SetPrinting(Document::kNotPrinting);
}

bool LocalFrame::ShouldUsePaginatedLayout() const {
  if (!GetDocument()->Printing())
    return false;

  // Only the top frame being printed may be fitted to page size.
  // Subframes should be constrained by parents only.
  // This function considers the following two kinds of frames as top frames:
  // -- frame with no parent;
  // -- frame's parent is not in printing mode.
  // For the second type, it is a bit complicated when its parent is a remote
  // frame. In such case, we can not check its document or other internal
  // status. However, if the parent is in printing mode, this frame's printing
  // must have started with |use_paginated_layout| as false in print context.
  if (auto* local_parent = DynamicTo<LocalFrame>(Tree().Parent())) {
    return !local_parent->GetDocument()->Printing();
  }
  return print_params_.use_paginated_layout;
}

void LocalFrame::StartPaintPreview() {
  SetInvalidationForCapture(true);
}

void LocalFrame::EndPaintPreview() {
  SetInvalidationForCapture(false);
}

void LocalFrame::SetInvalidationForCapture(bool capturing) {
  if (!capturing)
    RestoreScrollOffsets();

  ResourceCacheValidationSuppressor validation_suppressor(
      GetDocument()->Fetcher());

  // Subframes of the captured content should be updated.
  for (Frame* child = Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    if (auto* child_local_frame = DynamicTo<LocalFrame>(child)) {
```
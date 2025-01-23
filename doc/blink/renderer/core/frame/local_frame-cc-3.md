Response:
My thinking process to analyze the provided code snippet went through these stages:

1. **Identify the Core Class:** The code is explicitly stated to be from `blink/renderer/core/frame/local_frame.cc`. This immediately tells me the central entity is `LocalFrame`.

2. **Scan for Public Methods:** I quickly scanned the code for function definitions that are not clearly marked as internal helpers or callbacks (e.g., those starting with `Was`, `Set`, `Get`, `Force`, etc.). These public methods are the primary interface of the `LocalFrame` and hint at its main functionalities.

3. **Categorize Functionalities by Method Names:** I grouped the methods based on their apparent purpose. For example:
    * **Visibility/Occlusion:**  `WasShown`, `WasHidden`, `GetOcclusionState`, `NeedsOcclusionTracking`, `SetViewportIntersectionFromParent`.
    * **Content Clipping:** `ClipsContent`.
    * **Frame Relationships:** `SetOpener`, `IsAdFrame`, `IsAdRoot`, `SetAdEvidence`.
    * **Scrolling:** `CreateNewSmoothScrollSequence`, `ReinstateSmoothScrollSequence`, `FinishedScrollSequence`, `GetSmoothScrollSequencer`.
    * **Resource Loading:** `PauseSubresourceLoading`, `ResumeSubresourceLoading`.
    * **JavaScript Execution:** `LoadJavaScriptURL`, `RequestExecuteScript`.
    * **Lifecycle:** `DidFreeze`, `DidResume`, `OnPageLifecycleStateUpdated`, `SetContextPaused`.
    * **User Interaction:** `NotifyUserActivation`, `ConsumeTransientUserActivation`, `ConsumeHistoryUserActivation`, `SetHadUserInteraction`.
    * **Overlays:** `SetMainFrameColorOverlay`, `SetSubframeColorOverlay`, `UpdateFrameColorOverlayPrePaint`, `PaintFrameColorOverlay`.
    * **Memory Management:** `ForciblyPurgeV8Memory`.
    * **Navigation/Swapping:** `SwapIn`, `Discard`, `GetPreviousLocalFrameForLocalSwap`.
    * **Metrics/Tracking:** `GetUkmRecorder`, `GetUkmSourceId`, `UpdateTaskTime`.
    * **Back/Forward Cache:** `UpdateBackForwardCacheDisablingFeatures`, `SetEvictCachedSessionStorageOnFreezeOrUnload`.

4. **Analyze Individual Methods for Details:** I then looked more closely at the implementation of key methods to understand *how* they achieve their purpose and their connections to web technologies:

    * **Occlusion/Visibility:** I noticed the interaction with `IntersectionObserverController` and the use of `ForceUpdateViewportIntersections`. This clearly links to the Intersection Observer API in JavaScript. The handling of `hidden_` and `ScheduleAnimation` relates to browser rendering optimizations.
    * **Clipping:** The checks for paint previews and paginated layout show how `LocalFrame` influences content rendering. The `GetSettings()->GetMainFrameClipsContent()` highlights a configurable aspect affecting layout.
    * **Ad Frames:** The `IsAdFrame` and `SetAdEvidence` methods, along with `UpdateAdHighlight`, directly relate to how the browser identifies and potentially highlights advertisement content, a feature often relevant to user experience and content blocking.
    * **Smooth Scrolling:** The `SmoothScrollSequencer` methods point to the implementation of smooth scrolling behavior, which can be triggered by JavaScript APIs like `scrollTo()` or `scrollIntoView()`.
    * **JavaScript Execution:** `LoadJavaScriptURL` demonstrates how JavaScript code embedded in URLs is handled. `RequestExecuteScript` is a more general mechanism for injecting and running JavaScript, often used internally but also relevant to browser extensions or developer tools.
    * **Lifecycle:** `DidFreeze` and `DidResume` are crucial for implementing features like the back/forward cache and tab freezing, impacting performance and user experience. They involve dispatching events that JavaScript can listen for.
    * **User Activation:**  The methods related to user activation are fundamental to preventing unwanted actions (like popup windows) without explicit user interaction. This directly impacts JavaScript's ability to trigger certain behaviors.
    * **Overlays:**  The color overlay functionality is likely used for debugging or highlighting specific frames, which could be useful for developers working with iframes.

5. **Identify Connections to JavaScript, HTML, and CSS:** Based on the method analysis, I explicitly noted the relationships:

    * **JavaScript:**  Intersection Observer API, smooth scrolling APIs, user activation constraints, JavaScript URL execution, programmatic script injection, and event listeners for lifecycle events (freeze, resume).
    * **HTML:**  The concept of frames and iframes is central. The clipping behavior relates to how content within a frame is rendered. The ad frame detection is relevant to the structure and content of web pages.
    * **CSS:** While not directly manipulating CSS properties here, the clipping and rendering behavior are influenced by CSS layout and overflow properties. The color overlays affect how the frame visually appears, which is related to styling.

6. **Look for Logical Inferences (and examples):** I considered scenarios where the code's behavior could be inferred:

    * **Occlusion:** If a frame is completely covered by another, the `kPossiblyOccluded` state might prevent unnecessary rendering work.
    * **Viewport Intersection:** When a frame scrolls into view, the Intersection Observer logic will trigger, potentially loading resources or performing actions.
    * **Ad Frame Detection:**  Setting the `ad_evidence_` based on certain criteria will change the behavior of the frame (e.g., potential highlighting).

7. **Consider User/Programming Errors:**  I thought about common mistakes:

    * **Incorrect Opener:**  Setting the opener to a frame that doesn't exist or is inappropriate can lead to unexpected behavior.
    * **Misunderstanding User Activation:** Trying to perform actions requiring user activation without a valid user gesture will be blocked.
    * **Back/Forward Cache Issues:**  Code that prevents pages from being cached can degrade performance.

8. **Synthesize the Overall Function:** Finally, I summarized the key responsibilities of `LocalFrame` based on the analyzed methods and connections. This involves managing the lifecycle, visibility, content, and interactions of a frame within the rendering engine.

By following these steps, I could systematically break down the code snippet, understand its individual parts, and then synthesize a comprehensive description of its functionalities and relationships to the broader web platform.
这是对 `blink/renderer/core/frame/local_frame.cc` 文件代码片段的功能归纳总结，基于提供的第 4 部分内容：

**核心功能归纳:**

这段代码主要关注 `LocalFrame` 对象的以下核心功能：

1. **视图和遮挡状态管理:**
   - **隐藏/显示状态:**  处理 `WasHidden()` 和 `WasShown()` 事件，更新内部的 `hidden_` 状态，并触发动画调度和内容捕获管理器的更新。
   - **内容裁剪:**  `ClipsContent()` 方法决定框架是否应该裁剪其内容到视口边界。这个行为受到诸如画前预览、分页布局和是否为主框架设置的影响。
   - **视口交叉状态:** `SetViewportIntersectionFromParent()` 方法接收来自父框架的视口交叉信息，包括交叉区域、变换和遮挡状态。它基于这些信息更新自身的 `intersection_state_`，并可能触发动画调度和 `IntersectionObserver` 的更新。
   - **遮挡状态获取:** `GetOcclusionState()` 方法返回框架的遮挡状态，考虑了框架是否隐藏以及其是否是根框架。
   - **遮挡追踪需求:** `NeedsOcclusionTracking()` 检查文档中是否存在需要遮挡追踪的 `IntersectionObserver`。

2. **框架生命周期和状态:**
   - **opener 设定:** `SetOpener()` 方法允许设置框架的 opener 框架，并通知浏览器进程。
   - **是否为临时框架:** `IsProvisional()` 方法判断框架是否为临时框架，这通常发生在导航过程中。
   - **是否为广告框架:** `IsAdFrame()` 和 `IsAdRoot()` 方法判断框架是否被认为是广告框架及其是否是广告根框架。
   - **广告证据管理:** `SetAdEvidence()` 方法用于设置框架的广告证据信息，包括是否由广告脚本创建，并更新相关的状态和高亮。
   - **暂停/恢复子资源加载:** `PauseSubresourceLoading()` 和 `ResumeSubresourceLoading()` 允许暂停和恢复框架内的子资源加载。

3. **平滑滚动管理:**
   - **平滑滚动序列:** `CreateNewSmoothScrollSequence()`, `ReinstateSmoothScrollSequence()`, `FinishedScrollSequence()`, `GetSmoothScrollSequencer()` 这些方法用于管理平滑滚动动画的执行顺序。

4. **性能和指标:**
   - **UKM 集成:** `GetUkmRecorder()` 和 `GetUkmSourceId()` 用于获取用户体验指标 (UKM) 记录器和源 ID。
   - **CPU 计时更新:** `UpdateTaskTime()` 用于更新框架的 CPU 消耗时间。

5. **后退/前进缓存 (BFCache) 控制:**
   - **禁用特性更新:** `UpdateBackForwardCacheDisablingFeatures()` 方法将阻止页面进入 BFCache 的特性信息发送给浏览器进程。
   - **冻结/卸载时清除 SessionStorage 缓存:** `SetEvictCachedSessionStorageOnFreezeOrUnload()` 标记在页面冻结或卸载时是否需要清除 SessionStorage 的缓存。

6. **用户激活状态管理:**
   - **通知用户激活:** `NotifyUserActivation()` 方法通知框架发生了用户激活事件，并可能需要浏览器验证。
   - **检查/消耗用户激活:** `HasTransientUserActivation()` 和 `ConsumeTransientUserActivation()` 用于检查和消耗临时的用户激活状态。
   - **消耗历史用户激活:** `ConsumeHistoryUserActivation()` 用于消耗历史的用户激活状态。
   - **设置用户交互状态:** `SetHadUserInteraction()` 记录框架是否发生了用户交互。

7. **框架颜色叠加层:**
   - **设置/更新颜色叠加:** `SetMainFrameColorOverlay()`, `SetSubframeColorOverlay()`, `SetFrameColorOverlay()`, `UpdateFrameColorOverlayPrePaint()`, `PaintFrameColorOverlay()`  用于在框架上绘制颜色叠加层，常用于调试或高亮显示。

8. **内存管理:**
   - **强制回收 V8 内存:** `ForciblyPurgeV8Memory()` 方法用于强制清除与框架关联的 V8 内存。

9. **页面生命周期事件处理:**
   - **页面生命周期状态更新:** `OnPageLifecycleStateUpdated()` 方法响应页面生命周期状态的变化 (例如，冻结、恢复、暂停)，并更新框架的相应状态。
   - **设置上下文暂停状态:** `SetContextPaused()` 用于设置框架的上下文暂停状态，影响资源加载和调度。
   - **冻结/恢复事件分发:** `DidFreeze()` 和 `DidResume()` 方法在框架冻结和恢复时分发相应的事件。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript 和视口交叉:** `SetViewportIntersectionFromParent()` 中对 `NeedsOcclusionTracking()` 的检查以及可能的 `View()->ForceUpdateViewportIntersections()` 调用，直接关联到 **JavaScript 的 Intersection Observer API**。 当 JavaScript 代码使用 Intersection Observer 监听元素是否进入视口时，Blink 引擎会使用这里的逻辑来判断和触发回调。
    * **假设输入:** 一个包含 `IntersectionObserver` 的网页，当监听的元素滚动到视口内时。
    * **逻辑推理:** `LocalFrame` 会接收到视口交叉状态的更新，如果 `NeedsOcclusionTracking()` 为真，则会强制更新视口交叉信息，最终触发 JavaScript 中定义的 Intersection Observer 回调。

* **HTML 和框架结构:** `IsAdFrame()` 和 `IsAdRoot()` 的判断与 **HTML 中 `<iframe>` 标签**的使用方式以及其加载的内容有关。浏览器需要判断一个 `<iframe>` 是否用于展示广告。
    * **假设输入:** 一个 HTML 页面包含一个 `<iframe>`，该 `<iframe>` 的内容被识别为广告。
    * **逻辑推理:**  Blink 引擎会根据一定的规则（可能基于 URL、内容等）判断该 `<iframe>` 是否为广告框架，并设置 `ad_evidence_` 属性。

* **CSS 和内容裁剪:** `ClipsContent()` 方法的返回值会影响框架内容的渲染方式，这与 **CSS 的 `overflow` 属性**密切相关。如果 `ClipsContent()` 返回 true，超出框架视口的内容可能会被裁剪，这和 CSS 中设置 `overflow: hidden` 的效果类似。
    * **假设输入:** 一个嵌套的 `<iframe>`，其父框架的 `ClipsContent()` 返回 true。
    * **逻辑推理:**  子框架超出父框架视口的部分将被裁剪，除非有特殊的 CSS 样式覆盖了这种行为。

* **JavaScript 和用户激活:** `NotifyUserActivation()` 和 `ConsumeTransientUserActivation()` 机制是为了防止恶意网页在用户没有明确交互的情况下执行某些操作（例如弹出窗口），这与 **JavaScript 中需要用户手势触发的 API** (例如 `window.open()` 在某些情况下) 密切相关。
    * **假设输入:** JavaScript 代码尝试在没有用户交互的情况下调用 `window.open()`。
    * **逻辑推理:**  `LocalFrame` 会检查当前是否有有效的用户激活状态。如果没有，`window.open()` 的调用可能会被阻止。

**用户或编程常见的使用错误举例说明:**

* **错误地设置 Opener:**  开发者可能在 JavaScript 中使用 `window.open()` 创建一个新窗口，并错误地假设可以随意访问 opener 窗口的对象，而忽略了跨域安全限制。`SetOpener()` 内部的检查可以帮助诊断这类问题。
    * **假设场景:** 一个在 `example.com` 上的页面通过 `window.open('malicious.com')` 打开了一个新窗口，并尝试从新窗口访问 opener 窗口的敏感数据。
    * **可能结果:**  浏览器会阻止这种跨域访问，并可能在控制台中抛出错误。`SetOpener()` 方法内部的 `DCHECK` 或相关逻辑可以帮助开发者理解这种限制。

* **误解用户激活的要求:**  开发者可能编写 JavaScript 代码，期望在页面加载后立即弹出广告窗口，而没有理解浏览器对用户激活的限制。
    * **假设场景:** 页面加载完成后，JavaScript 代码立即调用 `window.open()` 尝试打开一个广告窗口。
    * **可能结果:**  浏览器会阻止这个弹出窗口，因为没有有效的用户激活。开发者需要理解，某些操作必须由用户的显式操作触发。

**总结：**

`LocalFrame` 的这段代码负责管理渲染引擎中一个本地框架的诸多关键方面，包括其视图状态、生命周期、与父框架的关系、资源加载、性能指标以及用户交互状态。它在 Blink 引擎中扮演着核心角色，并与 JavaScript、HTML 和 CSS 的功能紧密结合，共同构建了 Web 页面的渲染和交互体验。理解 `LocalFrame` 的功能对于深入理解浏览器的工作原理至关重要。

### 提示词
```
这是目录为blink/renderer/core/frame/local_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
jom::blink::FrameOcclusionState::kPossiblyOccluded) {
    return;
  }

  Document* document = GetDocument();
  if (frame_view && document && document->IsActive()) {
    if (auto* controller = GetDocument()->GetIntersectionObserverController()) {
      if (controller->NeedsOcclusionTracking()) {
        View()->ForceUpdateViewportIntersections();
      }
    }
  }
}

void LocalFrame::WasShown() {
  if (!hidden_)
    return;
  hidden_ = false;
  if (LocalFrameView* frame_view = View())
    frame_view->ScheduleAnimation();

  if (auto* content_capture_manager = GetOrResetContentCaptureManager()) {
    content_capture_manager->OnFrameWasShown();
  }
}

bool LocalFrame::ClipsContent() const {
  // A paint preview shouldn't clip to the viewport. Each frame paints to a
  // separate canvas in full to allow scrolling.
  if (GetDocument()->GetPaintPreviewState() != Document::kNotPaintingPreview) {
    return false;
  }

  if (ShouldUsePaginatedLayout()) {
    return false;
  }

  if (IsOutermostMainFrame()) {
    return GetSettings()->GetMainFrameClipsContent();
  }
  // By default clip to viewport.
  return true;
}

void LocalFrame::SetViewportIntersectionFromParent(
    const mojom::blink::ViewportIntersectionState& intersection_state) {
  DCHECK(IsLocalRoot());
  DCHECK(!IsOutermostMainFrame());
  // Notify the render frame observers when the main frame intersection or the
  // transform changes.
  if (intersection_state_.main_frame_intersection !=
          intersection_state.main_frame_intersection ||
      intersection_state_.main_frame_transform !=
          intersection_state.main_frame_transform) {
    gfx::Rect rect = intersection_state.main_frame_transform.MapRect(
        intersection_state.main_frame_intersection);

    // Return <0, 0, 0, 0> if there is no area.
    if (rect.IsEmpty())
      rect.set_origin(gfx::Point(0, 0));
    Client()->OnMainFrameIntersectionChanged(rect);
  }

  // Viewport intersection state needs to be updated when remote ancestor
  // frames and their respective scroll positions, clips, etc change.
  if (intersection_state_.viewport_intersection !=
          intersection_state.viewport_intersection ||
      intersection_state_.outermost_main_frame_size !=
          intersection_state.outermost_main_frame_size) {
    int viewport_intersect_area =
        intersection_state.viewport_intersection.size()
            .GetCheckedArea()
            .ValueOrDefault(INT_MAX);
    int outermost_main_frame_area =
        intersection_state.outermost_main_frame_size.GetCheckedArea()
            .ValueOrDefault(INT_MAX);
    float ratio = 1.0f * viewport_intersect_area / outermost_main_frame_area;
    const float ratio_threshold =
        1.0f * features::kLargeFrameSizePercentThreshold.Get() / 100;
    GetFrameScheduler()->SetVisibleAreaLarge(ratio > ratio_threshold);
  }

  // We only schedule an update if the viewport intersection or occlusion state
  // has changed; neither the viewport offset nor the compositing bounds will
  // affect IntersectionObserver.
  bool needs_update =
      intersection_state_.viewport_intersection !=
          intersection_state.viewport_intersection ||
      intersection_state_.occlusion_state != intersection_state.occlusion_state;
  intersection_state_ = intersection_state;
  if (needs_update) {
    if (LocalFrameView* frame_view = View()) {
      frame_view->SetIntersectionObservationState(LocalFrameView::kRequired);
      frame_view->ScheduleAnimation();
    }
  }
}

gfx::Size LocalFrame::GetOutermostMainFrameSize() const {
  LocalFrame& local_root = LocalFrameRoot();
  return local_root.IsOutermostMainFrame()
             ? local_root.View()->LayoutViewport()->VisibleContentRect().size()
             : local_root.intersection_state_.outermost_main_frame_size;
}

gfx::Point LocalFrame::GetOutermostMainFrameScrollPosition() const {
  LocalFrame& local_root = LocalFrameRoot();
  return local_root.IsOutermostMainFrame()
             ? gfx::ToFlooredPoint(
                   local_root.View()->LayoutViewport()->ScrollPosition())
             : local_root.intersection_state_
                   .outermost_main_frame_scroll_position;
}

void LocalFrame::SetOpener(Frame* opener_frame) {
  // Only a local frame should be able to update another frame's opener.
  DCHECK(!opener_frame || opener_frame->IsLocalFrame());

  auto* web_frame = WebFrame::FromCoreFrame(this);
  if (web_frame && Opener() != opener_frame) {
    GetLocalFrameHostRemote().DidChangeOpener(
        opener_frame
            ? std::optional<blink::LocalFrameToken>(
                  opener_frame->GetFrameToken().GetAs<LocalFrameToken>())
            : std::nullopt);
  }
  SetOpenerDoNotNotify(opener_frame);
}

mojom::blink::FrameOcclusionState LocalFrame::GetOcclusionState() const {
  if (hidden_)
    return mojom::blink::FrameOcclusionState::kPossiblyOccluded;
  if (IsLocalRoot())
    return intersection_state_.occlusion_state;
  return LocalFrameRoot().GetOcclusionState();
}

bool LocalFrame::NeedsOcclusionTracking() const {
  if (Document* document = GetDocument()) {
    if (IntersectionObserverController* controller =
            document->GetIntersectionObserverController()) {
      return controller->NeedsOcclusionTracking();
    }
  }
  return false;
}

void LocalFrame::ForceSynchronousDocumentInstall(const AtomicString& mime_type,
                                                 const SegmentedBuffer& data) {
  CHECK(GetDocument()->IsInitialEmptyDocument());
  DCHECK(!Client()->IsLocalFrameClientImpl());
  DCHECK(GetPage());

  // Any Document requires Shutdown() before detach, even the initial empty
  // document.
  GetDocument()->Shutdown();
  DomWindow()->ClearForReuse();

  Document* document = DomWindow()->InstallNewDocument(
      DocumentInit::Create()
          .WithWindow(DomWindow(), nullptr)
          .WithTypeFrom(mime_type)
          .ForPrerendering(GetPage()->IsPrerendering()));
  DCHECK_EQ(document, GetDocument());
  DocumentParser* parser = document->OpenForNavigation(
      kForceSynchronousParsing, mime_type, AtomicString("UTF-8"));

  if (RuntimeEnabledFeatures::DocumentInstallChunkingEnabled()) {
    // Some code creates a very large number of tiny chunks that show up in
    // |data|, such as InternalPopupMenu. Calling parser->AppendBytes() with
    // each tiny piece dramatically slows down document loading. By combining
    // these chunks in a Vector before passing it to parser->AppendBytes() gets
    // around this problem.
    Vector<char> current_chunk;
    for (const auto& segment : data) {
      current_chunk.AppendSpan(base::span(segment));
      if (current_chunk.size() > kMaxDocumentChunkSize) {
        parser->AppendBytes(base::as_byte_span(current_chunk));
        current_chunk.clear();
      }
    }
    parser->AppendBytes(base::as_byte_span(current_chunk));
    current_chunk.clear();
  } else {
    for (const auto& segment : data) {
      parser->AppendBytes(base::as_bytes(segment));
    }
  }

  parser->Finish();

  // Upon loading of SVGImages, log PageVisits in UseCounter if we did not
  // replace the document in `parser->Finish()`, which may happen when XSLT
  // finishes processing.
  // Do not track PageVisits for inspector, web page popups, and validation
  // message overlays (the other callers of this method).
  if (document == GetDocument() && document->IsSVGDocument())
    loader_.GetDocumentLoader()->GetUseCounter().DidCommitLoad(this);
}

bool LocalFrame::IsProvisional() const {
  // Calling this after the frame is marked as completely detached is a bug, as
  // this state can no longer be accurately calculated.
  CHECK(!IsDetached());

  if (IsMainFrame()) {
    return GetPage()->MainFrame() != this;
  }

  DCHECK(Owner());
  return Owner()->ContentFrame() != this;
}

bool LocalFrame::IsAdFrame() const {
  return ad_evidence_ && ad_evidence_->IndicatesAdFrame();
}

bool LocalFrame::IsAdRoot() const {
  return IsAdFrame() && !ad_evidence_->parent_is_ad();
}

void LocalFrame::SetAdEvidence(const FrameAdEvidence& ad_evidence) {
  DCHECK(!IsMainFrame() || IsInFencedFrameTree());
  DCHECK(ad_evidence.is_complete());

  // Once set, `is_frame_created_by_ad_script_` should not be unset.
  DCHECK(!is_frame_created_by_ad_script_ ||
         ad_evidence.created_by_ad_script() ==
             blink::mojom::FrameCreationStackEvidence::kCreatedByAdScript);
  is_frame_created_by_ad_script_ =
      ad_evidence.created_by_ad_script() ==
      blink::mojom::FrameCreationStackEvidence::kCreatedByAdScript;

  if (ad_evidence_.has_value()) {
    // Check that replacing with the new ad evidence doesn't violate invariants.
    // The parent frame's ad status should not change as it can only change due
    // to a cross-document commit, which would remove this child frame.
    DCHECK_EQ(ad_evidence_->parent_is_ad(), ad_evidence.parent_is_ad());

    // The most restrictive filter list result cannot become less restrictive,
    // by definition.
    DCHECK_LE(ad_evidence_->most_restrictive_filter_list_result(),
              ad_evidence.most_restrictive_filter_list_result());
  }

  bool was_ad_frame = IsAdFrame();
  bool is_ad_frame = ad_evidence.IndicatesAdFrame();
  ad_evidence_ = ad_evidence;

  if (was_ad_frame == is_ad_frame)
    return;

  if (auto* document = GetDocument()) {
    // TODO(fdoray): It is possible for the document not to be installed when
    // this method is called. Consider inheriting frame bit in the graph instead
    // of sending an IPC.
    auto* document_resource_coordinator = document->GetResourceCoordinator();
    if (document_resource_coordinator)
      document_resource_coordinator->SetIsAdFrame(is_ad_frame);
  }

  UpdateAdHighlight();
  frame_scheduler_->SetIsAdFrame(is_ad_frame);

  if (is_ad_frame) {
    UseCounter::Count(DomWindow(), WebFeature::kAdFrameDetected);
    InstanceCounters::IncrementCounter(InstanceCounters::kAdSubframeCounter);
  } else {
    InstanceCounters::DecrementCounter(InstanceCounters::kAdSubframeCounter);
  }
}

bool LocalFrame::IsAdScriptInStack() const {
  return ad_tracker_ &&
         ad_tracker_->IsAdScriptInStack(AdTracker::StackType::kBottomAndTop);
}

void LocalFrame::UpdateAdHighlight() {
  if (IsMainFrame() && !IsInFencedFrameTree())
    return;

  // TODO(bokan): Fenced frames may need some work to propagate the ad
  // highlighting setting to the inner tree.
  if (IsAdRoot() && GetPage()->GetSettings().GetHighlightAds())
    SetSubframeColorOverlay(SkColorSetARGB(128, 255, 0, 0));
  else
    SetSubframeColorOverlay(SK_ColorTRANSPARENT);
}

void LocalFrame::PauseSubresourceLoading(
    mojo::PendingReceiver<mojom::blink::PauseSubresourceLoadingHandle>
        receiver) {
  auto handle = GetFrameScheduler()->GetPauseSubresourceLoadingHandle();
  if (!handle)
    return;
  pause_handle_receivers_.Add(std::move(handle), std::move(receiver),
                              GetTaskRunner(blink::TaskType::kInternalDefault));
}

void LocalFrame::ResumeSubresourceLoading() {
  pause_handle_receivers_.Clear();
}

SmoothScrollSequencer* LocalFrame::CreateNewSmoothScrollSequence() {
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, we run smooth scrolls in
    // parallel, not in sequence.
    return nullptr;
  }
  if (!IsLocalRoot()) {
    return LocalFrameRoot().CreateNewSmoothScrollSequence();
  }

  SmoothScrollSequencer* old_sequencer = smooth_scroll_sequencer_;
  smooth_scroll_sequencer_ = MakeGarbageCollected<SmoothScrollSequencer>(*this);
  return old_sequencer;
}

void LocalFrame::ReinstateSmoothScrollSequence(
    SmoothScrollSequencer* sequencer) {
  if (!IsLocalRoot()) {
    LocalFrameRoot().ReinstateSmoothScrollSequence(sequencer);
    return;
  }

  smooth_scroll_sequencer_ = sequencer;
}

void LocalFrame::FinishedScrollSequence() {
  if (!IsLocalRoot()) {
    LocalFrameRoot().FinishedScrollSequence();
    return;
  }

  smooth_scroll_sequencer_.Clear();
}

SmoothScrollSequencer* LocalFrame::GetSmoothScrollSequencer() const {
  if (!IsLocalRoot())
    return LocalFrameRoot().GetSmoothScrollSequencer();
  return smooth_scroll_sequencer_.Get();
}

ukm::UkmRecorder* LocalFrame::GetUkmRecorder() {
  Document* document = GetDocument();
  if (!document)
    return nullptr;
  return document->UkmRecorder();
}

int64_t LocalFrame::GetUkmSourceId() {
  Document* document = GetDocument();
  if (!document)
    return ukm::kInvalidSourceId;
  return document->UkmSourceID();
}

void LocalFrame::UpdateTaskTime(base::TimeDelta time) {
  Client()->DidChangeCpuTiming(time);
}

void LocalFrame::UpdateBackForwardCacheDisablingFeatures(
    BlockingDetails details) {
  auto mojom_details = ConvertFeatureAndLocationToMojomStruct(
      *details.non_sticky_features_and_js_locations,
      *details.sticky_features_and_js_locations);
  GetBackForwardCacheControllerHostRemote()
      .DidChangeBackForwardCacheDisablingFeatures(std::move(mojom_details));
}

using BlockingDetailsList = Vector<mojom::blink::BlockingDetailsPtr>;
BlockingDetailsList LocalFrame::ConvertFeatureAndLocationToMojomStruct(
    const BFCacheBlockingFeatureAndLocations& non_sticky,
    const BFCacheBlockingFeatureAndLocations& sticky) {
  BlockingDetailsList blocking_details_list;
  for (auto feature : non_sticky.details_list) {
    auto blocking_details = CreateBlockingDetailsMojom(feature);
    blocking_details_list.push_back(std::move(blocking_details));
  }
  for (auto feature : sticky.details_list) {
    auto blocking_details = CreateBlockingDetailsMojom(feature);
    blocking_details_list.push_back(std::move(blocking_details));
  }
  return blocking_details_list;
}

const base::UnguessableToken& LocalFrame::GetAgentClusterId() const {
  if (const LocalDOMWindow* window = DomWindow()) {
    return window->GetAgentClusterID();
  }
  return base::UnguessableToken::Null();
}

void LocalFrame::OnTaskCompleted(base::TimeTicks start_time,
                                 base::TimeTicks end_time) {
  if (FrameWidget* widget = GetWidgetForLocalRoot()) {
    widget->OnTaskCompletedForFrame(start_time, end_time, this);
  }
}

void LocalFrame::MainFrameInteractive() {
  if (Page* page = GetPage()) {
    page->GetV8CrowdsourcedCompileHintsProducer().GenerateData();
  }
  constexpr bool kIsFinalData = true;
  v8_local_compile_hints_producer_->GenerateData(kIsFinalData);

  V8HistogramAccumulator::GetInstance()->GenerateDataInteractive();
}

void LocalFrame::MainFrameFirstMeaningfulPaint() {
  // Generate local compile hints early (the user might navigate away before the
  // page turns interactive). If we still reach interactive, we replace the
  // compile hints with new data.
  constexpr bool kIsFinalData = false;
  v8_local_compile_hints_producer_->GenerateData(kIsFinalData);
}

DocumentResourceCoordinator* LocalFrame::GetDocumentResourceCoordinator() {
  return CHECK_DEREF(GetDocument()).GetResourceCoordinator();
}

mojom::blink::ReportingServiceProxy* LocalFrame::GetReportingService() {
  return mojo_handler_->ReportingService();
}

mojom::blink::DevicePostureProvider* LocalFrame::GetDevicePostureProvider() {
  return mojo_handler_->DevicePostureProvider();
}

// static
void LocalFrame::NotifyUserActivation(
    LocalFrame* frame,
    mojom::blink::UserActivationNotificationType notification_type,
    bool need_browser_verification) {
  if (frame) {
    frame->NotifyUserActivation(notification_type, need_browser_verification);
  }
}

// static
bool LocalFrame::HasTransientUserActivation(LocalFrame* frame) {
  return frame ? frame->Frame::HasTransientUserActivation() : false;
}

// static
bool LocalFrame::ConsumeTransientUserActivation(
    LocalFrame* frame,
    UserActivationUpdateSource update_source) {
  return frame ? frame->ConsumeTransientUserActivation(update_source) : false;
}

void LocalFrame::NotifyUserActivation(
    mojom::blink::UserActivationNotificationType notification_type,
    bool need_browser_verification) {
  mojom::blink::UserActivationUpdateType update_type =
      need_browser_verification
          ? mojom::blink::UserActivationUpdateType::
                kNotifyActivationPendingBrowserVerification
          : mojom::blink::UserActivationUpdateType::kNotifyActivation;

  GetLocalFrameHostRemote().UpdateUserActivationState(update_type,
                                                      notification_type);
  Client()->NotifyUserActivation();
  NotifyUserActivationInFrameTree(notification_type);
}

bool LocalFrame::ConsumeTransientUserActivation(
    UserActivationUpdateSource update_source) {
  if (update_source == UserActivationUpdateSource::kRenderer) {
    GetLocalFrameHostRemote().UpdateUserActivationState(
        mojom::blink::UserActivationUpdateType::kConsumeTransientActivation,
        mojom::blink::UserActivationNotificationType::kNone);
  }
  return ConsumeTransientUserActivationInFrameTree();
}

void LocalFrame::ConsumeHistoryUserActivation() {
  // Notify the frame in the browser process, which will consume the activation
  // in all frames of the page (consistent with the loop below).
  GetLocalFrameHostRemote().DidConsumeHistoryUserActivation();
  for (Frame* node = &Tree().Top(); node; node = node->Tree().TraverseNext()) {
    if (LocalFrame* local_frame_node = DynamicTo<LocalFrame>(node)) {
      local_frame_node->history_user_activation_state_.Consume();
    }
  }
}

void LocalFrame::SetHadUserInteraction(bool had_user_interaction) {
  if (had_user_interaction) {
    history_user_activation_state_.Activate();
  } else {
    history_user_activation_state_.Clear();
  }

  DomWindow()->closewatcher_stack()->SetHadUserInteraction(
      had_user_interaction);

  GetFrameScheduler()->SetHadUserActivation(had_user_interaction);
}

namespace {

class FrameColorOverlay final : public FrameOverlay::Delegate {
 public:
  explicit FrameColorOverlay(LocalFrame* frame, SkColor color)
      : color_(color), frame_(frame) {}
  SkColor GetColorForTesting() const { return color_; }

 private:
  void PaintFrameOverlay(const FrameOverlay& frame_overlay,
                         GraphicsContext& graphics_context,
                         const gfx::Size&) const override {
    const auto* view = frame_->View();
    DCHECK(view);
    if (view->Width() == 0 || view->Height() == 0)
      return;
    ScopedPaintChunkProperties properties(
        graphics_context.GetPaintController(),
        view->GetLayoutView()->FirstFragment().LocalBorderBoxProperties(),
        frame_overlay, DisplayItem::kFrameOverlay);
    if (DrawingRecorder::UseCachedDrawingIfPossible(
            graphics_context, frame_overlay, DisplayItem::kFrameOverlay))
      return;
    DrawingRecorder recorder(graphics_context, frame_overlay,
                             DisplayItem::kFrameOverlay,
                             gfx::Rect(view->Size()));
    gfx::RectF rect(0, 0, view->Width(), view->Height());
    graphics_context.FillRect(
        rect, Color::FromSkColor(color_),
        PaintAutoDarkMode(view->GetLayoutView()->StyleRef(),
                          DarkModeFilter::ElementRole::kBackground));
  }

  // TODO(https://crbug.com/1351544): This should be an SkColor4f or a Color.
  SkColor color_;
  Persistent<LocalFrame> frame_;
};

}  // namespace

void LocalFrame::SetReducedAcceptLanguage(
    const AtomicString& reduced_accept_language) {
  reduced_accept_language_ = reduced_accept_language;
}

template <>
struct DowncastTraits<FrameColorOverlay> {
  static bool AllowFrom(const FrameOverlay::Delegate& frame_overlay) {
    return true;
  }
};

std::optional<SkColor> LocalFrame::GetFrameOverlayColorForTesting() const {
  if (!frame_color_overlay_)
    return std::nullopt;
  return DynamicTo<FrameColorOverlay>(frame_color_overlay_->GetDelegate())
      ->GetColorForTesting();
}

void LocalFrame::SetMainFrameColorOverlay(SkColor color) {
  DCHECK(IsMainFrame() && !IsInFencedFrameTree());
  SetFrameColorOverlay(color);
}

void LocalFrame::SetSubframeColorOverlay(SkColor color) {
  DCHECK(!IsMainFrame() || IsInFencedFrameTree());
  SetFrameColorOverlay(color);
}

void LocalFrame::SetFrameColorOverlay(SkColor color) {
  if (frame_color_overlay_)
    frame_color_overlay_.Release()->Destroy();

  if (color == SK_ColorTRANSPARENT)
    return;

  frame_color_overlay_ = MakeGarbageCollected<FrameOverlay>(
      this, std::make_unique<FrameColorOverlay>(this, color));
}

void LocalFrame::UpdateFrameColorOverlayPrePaint() {
  if (frame_color_overlay_)
    frame_color_overlay_->UpdatePrePaint();
}

void LocalFrame::PaintFrameColorOverlay(GraphicsContext& context) {
  if (frame_color_overlay_)
    frame_color_overlay_->Paint(context);
}

void LocalFrame::ForciblyPurgeV8Memory() {
  DomWindow()->NotifyContextDestroyed();

  WindowProxyManager* window_proxy_manager = GetWindowProxyManager();
  window_proxy_manager->ClearForV8MemoryPurge();
  Loader().StopAllLoaders(/*abort_client=*/true);
}

void LocalFrame::OnPageLifecycleStateUpdated() {
  if (frozen_ != GetPage()->Frozen()) {
    frozen_ = GetPage()->Frozen();
    if (frozen_) {
      DidFreeze();
    } else {
      DidResume();
    }
    // The event handlers might have detached the frame.
    if (!IsAttached())
      return;
  }
  SetContextPaused(GetPage()->Paused());

  mojom::blink::FrameLifecycleState frame_lifecycle_state =
      mojom::blink::FrameLifecycleState::kRunning;
  if (GetPage()->Paused()) {
    frame_lifecycle_state = mojom::blink::FrameLifecycleState::kPaused;
  } else if (GetPage()->Frozen()) {
    frame_lifecycle_state = mojom::blink::FrameLifecycleState::kFrozen;
  }

  DomWindow()->SetLifecycleState(frame_lifecycle_state);
}

void LocalFrame::SetContextPaused(bool is_paused) {
  TRACE_EVENT0("blink", "LocalFrame::SetContextPaused");
  if (is_paused == paused_)
    return;
  paused_ = is_paused;

  if (IsLocalRoot() && (!is_paused || GetPage()->ShowPausedHudOverlay())) {
    auto* widget = GetWidgetForLocalRoot();
    if (widget) {
      const auto* debug_state = widget->GetLayerTreeDebugState();
      if (debug_state) {
        cc::LayerTreeDebugState new_debug_state = *debug_state;
        new_debug_state.debugger_paused = is_paused;
        widget->SetLayerTreeDebugState(new_debug_state);
      }
    }
  }

  GetDocument()->Fetcher()->SetDefersLoading(GetLoaderFreezeMode());
  Loader().SetDefersLoading(GetLoaderFreezeMode());
  // TODO(altimin): Move this to PageScheduler level.
  GetFrameScheduler()->SetPaused(is_paused);
}

LocalFrame* LocalFrame::GetPreviousLocalFrameForLocalSwap() {
  CHECK(IsProvisional());
  if (auto* previous_main_frame =
          GetPage()->GetPreviousMainFrameForLocalSwap()) {
    return previous_main_frame;
  }
  return DynamicTo<LocalFrame>(GetProvisionalOwnerFrame());
}

bool LocalFrame::SwapIn() {
  TRACE_EVENT0("navigation", "LocalFrame::SwapIn");
  base::ScopedUmaHistogramTimer histogram_timer("Navigation.LocalFrame.SwapIn");
  DCHECK(IsProvisional());
  WebLocalFrameClient* client = Client()->GetWebFrame()->Client();
  // Swap in `this`, which is a provisional frame to an existing frame.
  Frame* provisional_owner_frame = GetProvisionalOwnerFrame();


  // First, check if there's a previous main frame to be used for a main frame
  // LocalFrame <-> LocalFrame swap.
  Frame* previous_local_main_frame =
      GetPage()->GetPreviousMainFrameForLocalSwap();
  if (previous_local_main_frame && !previous_local_main_frame->IsDetached()) {
    // We're about to do a LocalFrame <-> LocalFrame swap for a provisional
    // main frame, where the previous main frame and the provisional main frame
    // are in different Pages. The provisional frame's owner is set to the
    // placeholder main RemoteFrame for the new Page, but we should trigger the
    // swapping out of the previous Page's main frame instead here.
    // This is because we want to preserve the behavior before RenderDocument,
    // where we would unload the previous document before the next document on
    // same-LocalFrame cross-document navigation, and also transfer some state
    // from the previous document to the new one.
    // The placeholder main RemoteFrame for the new Page will also get detached
    // so that the new main LocalFrame can be swapped in, but that will be done
    // a bit later on in `Frame::SwapImpl()`, as we don't need to transfer any
    // data from the placeholder RemoteFrame.
    CHECK(IsMainFrame());
    CHECK(previous_local_main_frame->IsLocalFrame());
    CHECK_NE(previous_local_main_frame->GetPage(), GetPage());
    CHECK(provisional_owner_frame->IsRemoteFrame());
    CHECK(!DynamicTo<RemoteFrame>(provisional_owner_frame)
               ->IsRemoteFrameHostRemoteBound());
    GetPage()->SetPreviousMainFrameForLocalSwap(nullptr);
    return client->SwapIn(WebFrame::FromCoreFrame(previous_local_main_frame));
  }

  // In all other cases, the LocalFrame would be swapped in with the provisional
  // owner frame which belongs to the same Page as `this`. The provisional owner
  // frame can be a RemoteFrame or a LocalFrame (for non-main frame
  // LocalFrame <-> LocalFrame swap cases).
  CHECK_EQ(provisional_owner_frame->GetPage(), GetPage());

  // When creating a provisional LocalFrame, a new provisional probe sink is
  // created. Whether that probe sink is going to be used differs depending
  // on the situation:
  // - For local roots, that provisional probe sink should be used, as
  //   local roots needs new probe sinks. So nothing needs to be done here.
  // - For non-local-root LocalFrame <-> LocalFrame swap, reuse the previous
  //   LocalFrame's probe sink.
  // - For other cases, reuse the local root's probe sink.
  // Note that the probes dispatched to provisional sink are lost, so no
  // events are sent before swap in or after swap out.
  if (!IsLocalRoot()) {
    if (auto* local_provisional_owner =
            DynamicTo<LocalFrame>(provisional_owner_frame)) {
      // This is doing a LocalFrame <-> LocalFrame swap, so reuse the previous
      // LocalFrame's probe sink through swapping below. The detaching/unloading
      // of the previous document is done before we swap the probe sinks. This
      // is to ensure that resources from the old document won't stay around and
      // thus won't be be captured in the newly committed document's probe sink.
      bool swap_result =
          client->SwapIn(WebFrame::FromCoreFrame(provisional_owner_frame));
      std::swap(probe_sink_, local_provisional_owner->probe_sink_);
      return swap_result;
    }

    // This is a remote -> local swap, so just use the local root's probe sink.
    probe_sink_ = LocalFrameRoot().probe_sink_;
    // For remote -> local swap, Send a frameAttached event to keep the legacy
    // behavior where we fire the frameAttached event on cross-site navigations.
    probe::FrameAttachedToParent(this, ad_script_from_frame_creation_stack_);
  }

  return client->SwapIn(WebFrame::FromCoreFrame(provisional_owner_frame));
}

void LocalFrame::Discard() {
  DomWindow()->GetScriptController().DiscardFrame();
}

void LocalFrame::LoadJavaScriptURL(const KURL& url) {
  // Protect privileged pages against bookmarklets and other JavaScript
  // manipulations.
  if (SchemeRegistry::ShouldTreatURLSchemeAsNotAllowingJavascriptURLs(
          GetSecurityContext()
              ->GetSecurityOrigin()
              ->GetOriginOrPrecursorOriginIfOpaque()
              ->Protocol())) {
    return;
  }

  // TODO(mustaq): This is called only through the user typing a javascript URL
  // into the omnibox.  See https://crbug.com/1082900
  NotifyUserActivation(
      mojom::blink::UserActivationNotificationType::kInteraction, false);
  auto* window = DomWindow();
  window->GetScriptController().ExecuteJavaScriptURL(
      url, network::mojom::CSPDisposition::DO_NOT_CHECK,
      &DOMWrapperWorld::MainWorld(window->GetIsolate()));
}

void LocalFrame::RequestExecuteScript(
    int32_t world_id,
    base::span<const WebScriptSource> sources,
    mojom::blink::UserActivationOption user_gesture,
    mojom::blink::EvaluationTiming evaluation_timing,
    mojom::blink::LoadEventBlockingOption blocking_option,
    WebScriptExecutionCallback callback,
    BackForwardCacheAware back_forward_cache_aware,
    mojom::blink::WantResultOption want_result_option,
    mojom::blink::PromiseResultOption promise_behavior) {
  DOMWrapperWorld* world;
  ExecuteScriptPolicy execute_script_policy;
  CHECK(!IsProvisional());
  if (world_id == DOMWrapperWorld::kMainWorldId) {
    world = &DOMWrapperWorld::MainWorld(ToIsolate(this));
    execute_script_policy =
        ExecuteScriptPolicy::kDoNotExecuteScriptWhenScriptsDisabled;
  } else {
    world = DOMWrapperWorld::EnsureIsolatedWorld(ToIsolate(this), world_id);

    // This is to preserve the existing behavior.
    execute_script_policy =
        ExecuteScriptPolicy::kExecuteScriptWhenScriptsDisabled;
  }

  if (back_forward_cache_aware == BackForwardCacheAware::kPossiblyDisallow) {
    GetFrameScheduler()->RegisterStickyFeature(
        SchedulingPolicy::Feature::kInjectedJavascript,
        {SchedulingPolicy::DisableBackForwardCache()});
  }

  Vector<WebScriptSource> script_sources;
  script_sources.AppendSpan(sources);

  ScriptState* script_state = ToScriptState(this, *world);
  CHECK(script_state);
  PausableScriptExecutor::CreateAndRun(
      script_state, std::move(script_sources), execute_script_policy,
      user_gesture, evaluation_timing, blocking_option, want_result_option,
      promise_behavior, std::move(callback));
}

void LocalFrame::SetEvictCachedSessionStorageOnFreezeOrUnload() {
  DCHECK(RuntimeEnabledFeatures::Prerender2Enabled(
      GetDocument()->GetExecutionContext()));
  evict_cached_session_storage_on_freeze_or_unload_ = true;
}

LocalFrameToken LocalFrame::GetLocalFrameToken() const {
  return GetFrameToken().GetAs<LocalFrameToken>();
}

LoaderFreezeMode LocalFrame::GetLoaderFreezeMode() {
  if (paused_ || frozen_) {
    if (GetPage()->GetPageScheduler()->IsInBackForwardCache() &&
        IsInflightNetworkRequestBackForwardCacheSupportEnabled()) {
      return LoaderFreezeMode::kBufferIncoming;
    }
    return LoaderFreezeMode::kStrict;
  }
  return LoaderFreezeMode::kNone;
}

void LocalFrame::DidFreeze() {
  TRACE_EVENT0("blink", "LocalFrame::DidFreeze");
  DCHECK(IsAttached());
  GetDocument()->DispatchFreezeEvent();
  if (evict_cached_session_storage_on_freeze_or_unload_) {
    // Evicts the cached data of Session Storage to avoid reusing old data in
    // the cache after the session storage has been modified by another renderer
    // process.
    CoreInitializer::GetInstance().EvictSessionStorageCachedData(
        GetDocument()->GetPage());
  }
  // DispatchFreezeEvent dispatches JS events, which may detach |this|.
  if (!IsAttached())
    return;
  // TODO(fmeawad): Move the following logic to the page once we have a
  // PageResourceCoordinator in Blink. http://crbug.com/838415
  if (auto* document_resource_coordinator =
          GetDocument()->GetResourceCoordinator()) {
    document_resource_coordinator->SetLifecycleState(
        performance_manager::mojom::LifecycleState::kFrozen);
  }

  if (GetPage()->GetPageScheduler()->IsInBackForwardCache()) {
    DomWindow()->SetIsInBackForwardCache(true);
  }

  LoaderFreezeMode freeze_mode = GetLoaderFreezeMode();
  GetDocument()->Fetcher()->SetDefersLoading(freeze_mode);
  Loader().SetDefersLoading(freeze_mode);
}

void LocalFrame::DidResume() {
  TRACE_EVENT0("blink", "LocalFrame::DidResume");
  DCHECK(IsAttached());
  // Before doing anything, set the "is in BFCache" state to false. This might
  // affect calculations of other states triggered by the code below, e.g. the
  // LoaderFreezeMode.
  DomWindow()->SetIsInBackForwardCache(false);

  // TODO(yuzus): Figure out if we should call GetLoaderFreezeMode().
  GetDocument()->Fetcher()->SetDefersLoading(LoaderFreezeMode::kNone);
  Loader().SetDefersLoading(LoaderFreezeMode::kNone);

  GetDocument()->DispatchEvent(*Event::Create(event_type_names::kResume));
  // TODO(fmeawad): Move the following logic to the page once we have a
  // PageResourceCoordinator in Blink
  if (auto* document_resource_coordinator =
          GetDocument()->GetResourceCoordinator()) {
    document_resource_coordinator->SetLifecycleState(
        performance_manager::mojom::LifecycleState::kRunning);
  }

  // TODO(yuzus): Figure out where these calls should really belong.
  GetDocument()->DispatchHandleLoadStart();
  GetDocument()->DispatchHandleLoadComplete();
}

void LocalFrame::CountUseIfFeatureWouldBeBlockedByPermissionsPolicy(
    mojom::WebFeature blocked_cross_origin,
    mojom::WebFeature blocked_same_origin) {
  // Get the origin of the top-level document
  const SecurityOrigin* topOrigin =
      Tree().Top().GetSecur
```
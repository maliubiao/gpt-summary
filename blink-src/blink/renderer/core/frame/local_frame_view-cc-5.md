Response:
The user wants to understand the functionality of the `LocalFrameView` class in the Chromium Blink rendering engine, based on the provided source code snippet. I need to analyze the code and identify its responsibilities, focusing on its relationship with Javascript, HTML, and CSS, providing examples and highlighting potential usage errors. Finally, I need to summarize the overall purpose of the class based on the provided snippet, considering this is the last part of a larger file.

Here's a breakdown of how to approach this:

1. **Identify Core Responsibilities:** Read through the method names and logic to understand the primary functions of `LocalFrameView`. Look for keywords and patterns that indicate specific areas of responsibility.

2. **Analyze Relationships with Web Technologies:**
    * **Javascript:** Look for interactions with Javascript execution, event handling (like taps), and APIs (like Intersection Observer).
    * **HTML:** Identify connections to HTML elements (like `HTMLFencedFrameElement`, `HTMLVideoElement`), frame structures, and document lifecycle.
    * **CSS:**  See how `LocalFrameView` relates to layout, painting, rendering, and visual properties (like opacity, transforms, scrolling).

3. **Provide Concrete Examples:** For each identified relationship, construct simple scenarios demonstrating the interaction. This makes the explanation easier to grasp.

4. **Infer Logical Reasoning (Hypothetical Inputs/Outputs):**  For methods that perform calculations or state management (like `ShouldThrottleRendering`), consider what inputs would lead to specific outputs. This will illustrate the decision-making process within the class.

5. **Identify Potential Usage Errors:**  Think about common mistakes developers might make when interacting with the concepts managed by `LocalFrameView`. Focus on misinterpretations or incorrect assumptions about how rendering works.

6. **Synthesize the Summary:** Based on the identified responsibilities and relationships, create a concise summary of the `LocalFrameView`'s role, emphasizing its connection to the rendering pipeline and frame management. Since this is the last part, the summary should aim to capture the overall essence of the class as presented in the provided code.

**Mental Sandbox/Pre-computation:**

* **Rendering Pipeline:** The code heavily deals with layout, painting, compositing, and throttling – key aspects of the rendering pipeline.
* **Frame Management:** The class is clearly responsible for managing the view associated with a `LocalFrame`, handling things like visibility, intersection, and throttling within that frame.
* **Intersection Observer:** The methods related to intersection observations are prominent. I need to explain how `LocalFrameView` facilitates this API.
* **Throttling:** The numerous methods related to throttling suggest this is a crucial function for performance optimization. I need to clarify the conditions and consequences of throttling.
* **Lifecycle:** Methods like `BeginLifecycleUpdates` indicate involvement in the document lifecycle management.

**Key Observations from the Code Snippet:**

* Handles intersection observations and notifications.
* Manages rendering throttling based on visibility, cross-origin status, and other factors.
* Updates compositing inputs.
* Sets viewport intersection information.
* Handles visibility changes.
* Manages the paint lifecycle and triggers repaints.
* Coordinates with `FrameScheduler`.
* Interacts with the browser's chrome client for lifecycle events and commit deferral.
* Tracks scrolling and updates intersection states on scroll.
* Manages paint artifacts and compositing.
* Provides debugging information for painting.
* Implements features like dark mode, sticky positioning, and scroll snapping.
* Tracks pending updates (transforms, opacity, sticky elements, snap points).
* Collects performance metrics via `LocalFrameUkmAggregator`.

By systematically addressing these points and considering the provided code, I can generate a comprehensive and accurate answer to the user's request.
`LocalFrameView::cc` 是 Chromium Blink 引擎中负责管理和控制**本地帧 (LocalFrame)** 视图的核心类。 它是 `FrameView` 的子类，专门处理渲染进程内的帧视图。由于这是第 6 部分，也是最后一部分，我们可以归纳其功能是关于**高级渲染控制、优化以及一些特定功能的支持**。

以下是根据提供的代码片段列举的一些关键功能，以及它们与 JavaScript、HTML 和 CSS 的关系：

**1. Intersection Observer API 支持与优化:**

* **功能:**  `LocalFrameView` 负责管理和传递 Intersection Observer API 的通知。它跟踪帧的可见性，以及与其他帧和视口的交叉情况。
* **与 JavaScript 的关系:** JavaScript 代码可以使用 Intersection Observer API 来监听元素何时进入或离开视口。`LocalFrameView` 的方法如 `UpdateViewportIntersectionsForSubtree`, `DeliverSynchronousIntersectionObservations`, `SetViewportIntersection`, `SetIntersectionObservationState`, `UpdateIntersectionObservationStateOnScroll` 等都是为了支持这个 API 的正常运行和性能优化。
* **举例:**  一个网页使用 Intersection Observer 来实现懒加载图片。当图片元素进入视口时，JavaScript 代码会收到通知，然后加载实际的图片资源。`LocalFrameView` 确保了这个通知的准确及时传递。
* **假设输入与输出:**
    * **假设输入:**  页面滚动导致一个 `iframe` 元素进入主文档的视口。
    * **输出:** `LocalFrameView::UpdateViewportIntersectionsForSubtree` 检测到交叉，并可能调用 `IntersectionObserverController::DeliverNotifications`，最终导致注册到该 `iframe` 的 Intersection Observer 的 JavaScript 回调函数被执行。

**2. 渲染节流 (Rendering Throttling) 控制:**

* **功能:** `LocalFrameView` 实现了渲染节流的逻辑，用于优化性能，特别是针对隐藏或跨域的 `iframe`。它可以暂停不必要的渲染更新。
* **与 JavaScript、HTML、CSS 的关系:**
    * **HTML:**  `iframe` 元素的 `hidden` 属性会影响渲染节流。
    * **CSS:**  CSS 的 `visibility: hidden` 也可能触发渲染节流。
    * **JavaScript:**  JavaScript 可能会动态改变元素的可见性，从而间接影响渲染节流。
* **举例:**  一个广告 `iframe` 被滚动到屏幕外，并且是跨域的。`LocalFrameView` 可以将其渲染更新节流，直到它重新进入视口，从而节省 CPU 和 GPU 资源。
* **假设输入与输出:**
    * **假设输入:**  一个跨域 `iframe` 的 `hidden` 属性被设置为 `true`。
    * **输出:** `LocalFrameView::UpdateRenderThrottlingStatus` 检测到变化，并可能调用 `RenderThrottlingStatusChanged` 来暂停该 `iframe` 的渲染更新。

**3. 帧的生命周期管理和同步:**

* **功能:** `LocalFrameView` 参与管理帧的生命周期，例如开始生命周期更新 (`BeginLifecycleUpdates`)，并与其他帧同步一些状态变化 (`CrossOriginToNearestMainFrameChanged`, `CrossOriginToParentFrameChanged`)。
* **与 JavaScript、HTML 的关系:**
    * **HTML:**  帧的加载和卸载触发生命周期事件。
    * **JavaScript:**  JavaScript 可以通过脚本操作触发布局和渲染，从而影响帧的生命周期。
* **举例:**  当一个 `iframe` 的跨域状态发生变化时，`LocalFrameView::CrossOriginToNearestMainFrameChanged` 会被调用，并可能触发渲染节流状态的更新。
* **假设输入与输出:**
    * **假设输入:** 一个 `iframe` 从同源变为跨域。
    * **输出:** `LocalFrameView::CrossOriginToNearestMainFrameChanged` 被调用，根据 `IsHiddenForThrottling` 等条件，可能会调用 `RenderThrottlingStatusChanged` 来调整渲染节流状态。

**4. 视口交叉状态管理:**

* **功能:** `LocalFrameView` 接收并存储视口交叉状态信息 (`SetViewportIntersection`)，并根据交叉比例判断帧是否“大”，这可能影响帧调度。
* **与 JavaScript 的关系:** 虽然不是直接的 JavaScript API，但视口交叉信息是 Intersection Observer API 的基础。
* **举例:** 浏览器会计算一个 `iframe` 占据主文档视口的比例。如果比例很高，`LocalFrameView` 会通知 `FrameScheduler`，这可能影响该 `iframe` 的渲染优先级。

**5. 可见性变化处理:**

* **功能:** `LocalFrameView` 响应帧的可见性变化 (`VisibilityChanged`, `VisibilityForThrottlingChanged`)，并通知相关的组件。
* **与 JavaScript 的关系:** JavaScript 可以通过 `document.hidden` 或监听 `visibilitychange` 事件来了解页面的可见性状态，这会间接影响 `LocalFrameView` 的行为。
* **举例:** 当浏览器标签页被切换到后台时，`LocalFrameView::VisibilityChanged` 会被调用，通知渲染进程该帧不再可见。

**6. 强制执行生命周期阶段 (在特定情况下):**

* **功能:** 在渲染节流的情况下，为了确保 Intersection Observer 可以正常工作，`LocalFrameView` 可能会强制执行绘制生命周期阶段 (`RunPaintLifecyclePhase`)。
* **与 JavaScript 的关系:** 这确保了即使帧被节流，Intersection Observer 的回调也能在适当的时候被触发。

**7. Paint Artifact Compositor 的更新:**

* **功能:** `LocalFrameView` 负责触发 Paint Artifact Compositor 的更新 (`SetPaintArtifactCompositorNeedsUpdate`)，这涉及到将绘制操作转化为可以被合成器处理的格式。
* **与 CSS 的关系:** CSS 样式的变化会触发重新绘制，进而需要更新 Paint Artifact Compositor。

**8. 滚动相关的优化:**

* **功能:** `LocalFrameView` 跟踪滚动增量 (`UpdateIntersectionObservationStateOnScroll`)，并可能根据滚动情况更新 Intersection Observer 的状态，进行性能优化。

**9. 主线程滚动原因分析:**

* **功能:**  `MainThreadScrollingReasonsAsText` 方法用于获取帧在主线程上滚动的具体原因，这对于性能调试很有用。

**10. 坐标映射:**

* **功能:**  `MapToVisualRectInRemoteRootFrame`, `MapLocalToRemoteMainFrame` 等方法用于在不同帧之间进行坐标映射，这对于处理 `iframe` 等场景非常重要。

**11. 其他功能:**

* **CaretWidth:** 获取光标宽度。
* **RegisterTapEvent:** 注册点击事件，用于处理触摸事件。
* **UkmAggregator:** 用于收集性能指标。
* **Paint Holding for FCP:**  支持首帧内容绘制 (First Contentful Paint) 的延迟提交优化。
* **DarkModeFilter:** 支持暗黑模式。
* **Pending Updates:** 管理待处理的变换 (transform) 和透明度 (opacity) 更新，以及粘性定位 (sticky) 和滚动吸附 (snap) 的更新。
* **RunPaintBenchmark:** 用于运行绘制性能基准测试。

**常见的用户或编程使用错误 (可能与 `LocalFrameView` 间接相关):**

* **过度依赖 Intersection Observer 触发昂贵的 JavaScript 计算:**  如果在 Intersection Observer 的回调函数中执行了大量的计算，可能会导致性能问题，尤其是在快速滚动时。虽然 `LocalFrameView` 负责通知，但开发者需要注意回调函数的性能。
* **不理解渲染节流机制导致的意外行为:**  开发者可能会假设隐藏的 `iframe` 会持续更新，但实际上它可能被节流。这可能导致在重新显示 `iframe` 时出现短暂的延迟或内容不一致。
* **在不合适的时机进行布局或样式更改:**  在滚动处理函数中强制进行同步布局可能会导致性能问题。`LocalFrameView` 可能会因此更频繁地触发渲染更新。

**总结 (基于第 6 部分):**

作为 `LocalFrameView` 的最后一部分，这段代码主要关注**高级渲染控制和优化功能**。它深入处理了如何有效地管理帧的渲染生命周期，特别是针对 `iframe` 和跨域场景。 核心功能包括：

* **精细化的 Intersection Observer 管理和优化:** 确保高效且准确地传递交叉事件。
* **复杂的渲染节流策略:**  根据帧的可见性、跨域状态等条件进行智能的渲染暂停和恢复。
* **针对特定场景的性能优化:** 例如，延迟提交以优化首帧内容绘制。
* **支持新的 Web 功能:**  例如暗黑模式、粘性定位和滚动吸附。
* **提供调试和性能分析工具:** 例如，获取主线程滚动原因和运行绘制基准测试。

总的来说，`LocalFrameView` 不仅仅是一个简单的视图管理类，它还是 Blink 引擎中一个重要的**渲染策略执行和优化中心**，旨在在保证用户体验的前提下，最大程度地提升渲染性能和资源利用率，特别是在处理复杂的页面结构和跨域内容时。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_frame_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
 context);
  }

  if (DocumentFencedFrames* fenced_frames =
          DocumentFencedFrames::Get(*frame_->GetDocument())) {
    for (HTMLFencedFrameElement* fenced_frame :
         fenced_frames->GetFencedFrames()) {
      if (Frame* frame = fenced_frame->ContentFrame()) {
        needs_occlusion_tracking |=
            frame->View()->UpdateViewportIntersectionsForSubtree(flags,
                                                                 context);
      }
    }
  }

  return needs_occlusion_tracking;
}

void LocalFrameView::DeliverSynchronousIntersectionObservations() {
  if (IntersectionObserverController* controller =
          GetFrame().GetDocument()->GetIntersectionObserverController()) {
    controller->DeliverNotifications(
        IntersectionObserver::kDeliverDuringPostLifecycleSteps);
  }
  ForAllChildLocalFrameViews([](LocalFrameView& frame_view) {
    frame_view.DeliverSynchronousIntersectionObservations();
  });
}

void LocalFrameView::CrossOriginToNearestMainFrameChanged() {
  // If any of these conditions hold, then a change in cross-origin status does
  // not affect throttling.
  if (lifecycle_updates_throttled_ || IsSubtreeThrottled() ||
      IsDisplayLocked() || !IsHiddenForThrottling()) {
    return;
  }
  RenderThrottlingStatusChanged();
  // Immediately propagate changes to children.
  UpdateRenderThrottlingStatus(IsHiddenForThrottling(), IsSubtreeThrottled(),
                               IsDisplayLocked(), true);
}

void LocalFrameView::CrossOriginToParentFrameChanged() {
  if (LayoutView* layout_view = GetLayoutView()) {
    if (PaintLayer* root_layer = layout_view->Layer())
      root_layer->SetNeedsCompositingInputsUpdate();
  }
}

void LocalFrameView::SetViewportIntersection(
    const mojom::blink::ViewportIntersectionState& intersection_state) {
  if (!last_intersection_state_.Equals(intersection_state)) {
    last_intersection_state_ = intersection_state;
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
    if (FrameScheduler* frame_scheduler = frame_->GetFrameScheduler()) {
      frame_scheduler->SetVisibleAreaLarge(ratio > ratio_threshold);
    }
  }
}

void LocalFrameView::VisibilityForThrottlingChanged() {
  if (FrameScheduler* frame_scheduler = frame_->GetFrameScheduler()) {
    // TODO(szager): Per crbug.com/994443, maybe this should be:
    //   SetFrameVisible(IsHiddenForThrottling() || IsSubtreeThrottled());
    frame_scheduler->SetFrameVisible(!IsHiddenForThrottling());
  }
}

void LocalFrameView::VisibilityChanged(
    blink::mojom::FrameVisibility visibility) {
  frame_->GetLocalFrameHostRemote().VisibilityChanged(visibility);

  // LocalFrameClient member may not be valid in some tests.
  if (frame_->Client() && frame_->Client()->GetWebFrame() &&
      frame_->Client()->GetWebFrame()->Client()) {
    frame_->Client()->GetWebFrame()->Client()->OnFrameVisibilityChanged(
        visibility);
  }
}

void LocalFrameView::RenderThrottlingStatusChanged() {
  TRACE_EVENT0("blink", "LocalFrameView::RenderThrottlingStatusChanged");
  DCHECK(!IsInPerformLayout());
  DCHECK(!frame_->GetDocument() || !frame_->GetDocument()->InStyleRecalc());

  // When a frame is throttled, we delete its previous painted output, so it
  // will need to be repainted, even if nothing else has changed.
  if (LayoutView* layout_view = GetLayoutView()) {
    layout_view->Layer()->SetNeedsRepaint();
  }
  // The painted output of the frame may be included in a cached subsequence
  // associated with the embedding document, so invalidate the owner.
  if (auto* owner = GetFrame().OwnerLayoutObject()) {
    if (PaintLayer* owner_layer = owner->Layer()) {
      owner_layer->SetNeedsRepaint();
    }
  }

  if (!CanThrottleRendering()) {
    // Start ticking animation frames again if necessary.
    if (GetPage())
      GetPage()->Animator().ScheduleVisualUpdate(frame_.Get());
    // Ensure we'll recompute viewport intersection for the frame subtree during
    // the scheduled visual update.
    SetIntersectionObservationState(kRequired);
  } else if (GetFrame().IsLocalRoot()) {
    DCHECK(!IsUpdatingLifecycle());
    ForceThrottlingScope force_throttling(*this);
    // TODO(https://crbug.com/1196853): Switch to ScriptForbiddenScope once
    // failures are fixed.
    BlinkLifecycleScopeWillBeScriptForbidden forbid_script;
    RunPaintLifecyclePhase(PaintBenchmarkMode::kNormal);
  }

#if DCHECK_IS_ON()
  // Make sure we never have an unthrottled frame inside a throttled one.
  LocalFrameView* parent = ParentFrameView();
  while (parent) {
    DCHECK(CanThrottleRendering() || !parent->CanThrottleRendering());
    parent = parent->ParentFrameView();
  }
#endif
}

void LocalFrameView::SetIntersectionObservationState(
    IntersectionObservationState state) {
  if (intersection_observation_state_ >= state)
    return;
  intersection_observation_state_ = state;

  // If an intersection observation is required, force all ancestors to update.
  // Otherwise, an update could stop at a throttled frame before reaching this.
  if (state == kRequired) {
    Frame* parent_frame = frame_->Tree().Parent();
    if (auto* parent_local_frame = DynamicTo<LocalFrame>(parent_frame)) {
      if (parent_local_frame->View())
        parent_local_frame->View()->SetIntersectionObservationState(kRequired);
    }
  }
}

void LocalFrameView::UpdateIntersectionObservationStateOnScroll(
    gfx::Vector2dF scroll_delta) {
  accumulated_scroll_delta_since_last_intersection_update_ +=
      gfx::Vector2dF(std::abs(scroll_delta.x()), std::abs(scroll_delta.y()));
  SetIntersectionObservationState(kScrollAndVisibilityOnly);
}

void LocalFrameView::SetVisualViewportOrOverlayNeedsRepaint() {
  if (LocalFrameView* root = GetFrame().LocalFrameRoot().View())
    root->visual_viewport_or_overlay_needs_repaint_ = true;
}

bool LocalFrameView::VisualViewportOrOverlayNeedsRepaintForTesting() const {
  DCHECK(GetFrame().IsLocalRoot());
  return visual_viewport_or_overlay_needs_repaint_;
}

void LocalFrameView::SetPaintArtifactCompositorNeedsUpdate() {
  LocalFrameView* root = GetFrame().LocalFrameRoot().View();
  if (root && root->paint_artifact_compositor_)
    root->paint_artifact_compositor_->SetNeedsUpdate();
}

PaintArtifactCompositor* LocalFrameView::GetPaintArtifactCompositor() const {
  LocalFrameView* root = GetFrame().LocalFrameRoot().View();
  return root ? root->paint_artifact_compositor_.Get() : nullptr;
}

unsigned LocalFrameView::GetIntersectionObservationFlags(
    unsigned parent_flags) const {
  unsigned flags = 0;

  const LocalFrame& target_frame = GetFrame();
  const Frame& root_frame = target_frame.Tree().Top();
  if (&root_frame == &target_frame ||
      target_frame.GetSecurityContext()->GetSecurityOrigin()->CanAccess(
          root_frame.GetSecurityContext()->GetSecurityOrigin())) {
    flags |= IntersectionObservation::kReportImplicitRootBounds;
  }

  if (!target_frame.IsLocalRoot() && !target_frame.OwnerLayoutObject())
    flags |= IntersectionObservation::kAncestorFrameIsDetachedFromLayout;

  // Observers with explicit roots only need to be checked on the same frame,
  // since in this case target and root must be in the same document.
  if (intersection_observation_state_ != kNotNeeded) {
    flags |= (IntersectionObservation::kExplicitRootObserversNeedUpdate |
              IntersectionObservation::kImplicitRootObserversNeedUpdate);
    if (intersection_observation_state_ == kScrollAndVisibilityOnly) {
      flags |= IntersectionObservation::kScrollAndVisibilityOnly;
    }
  }

  // For observers with implicit roots, we need to check state on the whole
  // local frame tree, as passed down from the parent.
  flags |= (parent_flags &
            IntersectionObservation::kImplicitRootObserversNeedUpdate);

  // The kIgnoreDelay parameter is used to force computation in an OOPIF which
  // is hidden in the parent document, thus not running lifecycle updates. It
  // applies to the entire frame tree.
  flags |= (parent_flags & IntersectionObservation::kIgnoreDelay);

  return flags;
}

bool LocalFrameView::ShouldThrottleRendering() const {
  if (LocalFrameTreeForcesThrottling())
    return true;
  bool throttled_for_global_reasons = LocalFrameTreeAllowsThrottling() &&
                                      CanThrottleRendering() &&
                                      frame_->GetDocument();
  if (!throttled_for_global_reasons)
    return false;

  // If we're currently running a lifecycle update, and we are required to run
  // the IntersectionObserver steps at the end of the update, then there are two
  // courses of action, depending on whether this frame is display locked by its
  // parent frame:
  //
  //   - If it is NOT display locked, then we suppress throttling to force the
  // lifecycle update to proceed up to the state required to run
  // IntersectionObserver.
  //
  //   - If it IS display locked, then we still need IntersectionObserver to
  // run; but the display lock status will short-circuit the
  // IntersectionObserver algorithm and create degenerate "not intersecting"
  // notifications. Hence, we don't need to force lifecycle phases to run,
  // because IntersectionObserver will not need access to up-to-date
  // geometry. So there is no point in suppressing throttling here.
  auto* local_frame_root_view = GetFrame().LocalFrameRoot().View();
  if (local_frame_root_view->IsUpdatingLifecycle() &&
      intersection_observation_state_ == kRequired && !IsDisplayLocked()) {
    return Lifecycle().GetState() >= DocumentLifecycle::kPrePaintClean;
  }

  return true;
}

bool LocalFrameView::ShouldThrottleRenderingForTest() const {
  AllowThrottlingScope allow_throttling(*this);
  return ShouldThrottleRendering();
}

bool LocalFrameView::CanThrottleRendering() const {
  if (lifecycle_updates_throttled_ || IsSubtreeThrottled() ||
      IsDisplayLocked() || throttled_for_view_transition_) {
    return true;
  }
  // We only throttle hidden cross-origin frames. This is to avoid a situation
  // where an ancestor frame directly depends on the pipeline timing of a
  // descendant and breaks as a result of throttling. The rationale is that
  // cross-origin frames must already communicate with asynchronous messages,
  // so they should be able to tolerate some delay in receiving replies from a
  // throttled peer.
  return IsHiddenForThrottling() && frame_->IsCrossOriginToNearestMainFrame();
}

void LocalFrameView::UpdateRenderThrottlingStatus(bool hidden_for_throttling,
                                                  bool subtree_throttled,
                                                  bool display_locked,
                                                  bool recurse) {
  bool was_throttled = CanThrottleRendering();
  FrameView::UpdateRenderThrottlingStatus(
      hidden_for_throttling, subtree_throttled, display_locked, recurse);
  if (was_throttled != CanThrottleRendering())
    RenderThrottlingStatusChanged();
}

void LocalFrameView::SetThrottledForViewTransition(bool throttled) {
  if (throttled_for_view_transition_ == throttled) {
    return;
  }

  bool was_throttled = CanThrottleRendering();
  throttled_for_view_transition_ = throttled;

  // Invalidating paint here will cause the iframe to draw with no content
  // instead of showing old content. This will be fixed by paint holding for
  // local iframes.
  if (RuntimeEnabledFeatures::PaintHoldingForLocalIframesEnabled() &&
      was_throttled != CanThrottleRendering()) {
    RenderThrottlingStatusChanged();
  }
}

void LocalFrameView::BeginLifecycleUpdates() {
  TRACE_EVENT("blink", "LocalFrameView::BeginLifecycleUpdates");
  lifecycle_updates_throttled_ = false;

  LayoutView* layout_view = GetLayoutView();
  bool layout_view_is_empty = layout_view && !layout_view->FirstChild();
  if (layout_view_is_empty && !DidFirstLayout() && !NeedsLayout()) {
    // Make sure a display:none iframe gets an initial layout pass.
    layout_view->SetNeedsLayout(layout_invalidation_reason::kAddedToLayout,
                                kMarkOnlyThis);
  }

  ScheduleAnimation();
  SetIntersectionObservationState(kRequired);

  // Do not report paint timing for the initially empty document.
  if (GetFrame().GetDocument()->IsInitialEmptyDocument())
    MarkIneligibleToPaint();

  // Non-main-frame lifecycle and commit deferral are controlled by their
  // main frame.
  if (!GetFrame().IsMainFrame())
    return;

  ChromeClient& chrome_client = GetFrame().GetPage()->GetChromeClient();

  // Determine if we want to defer commits to the compositor once lifecycle
  // updates start. Doing so allows us to update the page lifecycle but not
  // present the results to screen until we see first contentful paint is
  // available or until a timer expires.
  // This is enabled only when the document loading is regular HTML served
  // over HTTP/HTTPs. And only defer commits once. This method gets called
  // multiple times, and we do not want to defer a second time if we have
  // already done so once and resumed commits already.
  if (WillDoPaintHoldingForFCP()) {
    have_deferred_main_frame_commits_ = true;
    chrome_client.StartDeferringCommits(
        GetFrame(), base::Milliseconds(kCommitDelayDefaultInMs),
        cc::PaintHoldingReason::kFirstContentfulPaint);
  }

  chrome_client.BeginLifecycleUpdates(GetFrame());
}

bool LocalFrameView::WillDoPaintHoldingForFCP() const {
  Document* document = GetFrame().GetDocument();
  return document && document->DeferredCompositorCommitIsAllowed() &&
         !have_deferred_main_frame_commits_ &&
         GetFrame().IsOutermostMainFrame();
}

String LocalFrameView::MainThreadScrollingReasonsAsText() {
  MainThreadScrollingReasons reasons = 0;
  DCHECK_GE(Lifecycle().GetState(), DocumentLifecycle::kPaintClean);
  const auto* properties = GetLayoutView()->FirstFragment().PaintProperties();
  if (properties && properties->Scroll()) {
    const auto* compositor =
        GetFrame().LocalFrameRoot().View()->paint_artifact_compositor_.Get();
    CHECK(compositor);
    reasons = compositor->GetMainThreadRepaintReasons(*properties->Scroll());
  }
  return String(cc::MainThreadScrollingReason::AsText(reasons).c_str());
}

bool LocalFrameView::MapToVisualRectInRemoteRootFrame(
    PhysicalRect& rect,
    bool apply_overflow_clip) {
  DCHECK(frame_->IsLocalRoot());
  // This is the top-level frame, so no mapping necessary.
  if (frame_->IsOutermostMainFrame())
    return true;
  bool result = rect.InclusiveIntersect(PhysicalRect(
      apply_overflow_clip ? frame_->RemoteViewportIntersection()
                          : frame_->RemoteMainFrameIntersection()));
  if (result) {
    if (LayoutView* layout_view = GetLayoutView()) {
      rect = layout_view->LocalToAncestorRect(
          rect, nullptr,
          kTraverseDocumentBoundaries | kApplyRemoteMainFrameTransform);
    }
  }
  return result;
}

void LocalFrameView::MapLocalToRemoteMainFrame(
    TransformState& transform_state) {
  DCHECK(frame_->IsLocalRoot());
  // This is the top-level frame, so no mapping necessary.
  if (frame_->IsOutermostMainFrame())
    return;
  transform_state.ApplyTransform(GetFrame().RemoteMainFrameTransform(),
                                 TransformState::kAccumulateTransform);
}

LayoutUnit LocalFrameView::CaretWidth() const {
  return LayoutUnit(std::max<float>(
      1.0f, GetChromeClient()->WindowToViewportScalar(&GetFrame(), 1.0f)));
}

void LocalFrameView::RegisterTapEvent(Element* target) {
  if (tap_friendliness_checker_) {
    tap_friendliness_checker_->RegisterTapEvent(target);
  }
}

LocalFrameUkmAggregator* LocalFrameView::GetUkmAggregator() {
  DCHECK(frame_->IsLocalRoot() || !ukm_aggregator_);
  LocalFrameView* local_root = frame_->LocalFrameRoot().View();

  // TODO(crbug.com/1392462): Avoid checking whether we need to create the
  // aggregator on every access.
  if (!local_root->ukm_aggregator_) {
    if (!local_root->frame_->GetChromeClient().IsIsolatedSVGChromeClient()) {
      local_root->ukm_aggregator_ =
          base::MakeRefCounted<LocalFrameUkmAggregator>();
    }
  }
  return local_root->ukm_aggregator_.get();
}

void LocalFrameView::ResetUkmAggregatorForTesting() {
  ukm_aggregator_.reset();
}

void LocalFrameView::OnFirstContentfulPaint() {
  if (frame_->IsMainFrame()) {
    // Restart commits that may have been deferred.
    GetPage()->GetChromeClient().StopDeferringCommits(
        *frame_, cc::PaintHoldingCommitTrigger::kFirstContentfulPaint);
    if (frame_->GetDocument()->ShouldMarkFontPerformance())
      FontPerformance::MarkFirstContentfulPaint();
  }

  if (auto* metrics_aggregator = GetUkmAggregator())
    metrics_aggregator->DidReachFirstContentfulPaint();
}

void LocalFrameView::RegisterForLifecycleNotifications(
    LifecycleNotificationObserver* observer) {
  lifecycle_observers_.insert(observer);
}

void LocalFrameView::UnregisterFromLifecycleNotifications(
    LifecycleNotificationObserver* observer) {
  lifecycle_observers_.erase(observer);
}

void LocalFrameView::EnqueueStartOfLifecycleTask(base::OnceClosure closure) {
  start_of_lifecycle_tasks_.push_back(std::move(closure));
}

void LocalFrameView::NotifyVideoIsDominantVisibleStatus(
    HTMLVideoElement* element,
    bool is_dominant) {
  if (is_dominant) {
    fullscreen_video_elements_.insert(element);
    return;
  }

  fullscreen_video_elements_.erase(element);
}

bool LocalFrameView::HasDominantVideoElement() const {
  return !fullscreen_video_elements_.empty();
}

#if DCHECK_IS_ON()
LocalFrameView::DisallowLayoutInvalidationScope::
    DisallowLayoutInvalidationScope(LocalFrameView* view)
    : local_frame_view_(view) {
  local_frame_view_->allows_layout_invalidation_after_layout_clean_ = false;
  local_frame_view_->ForAllChildLocalFrameViews([](LocalFrameView& frame_view) {
    if (!frame_view.ShouldThrottleRendering())
      frame_view.CheckDoesNotNeedLayout();
    frame_view.allows_layout_invalidation_after_layout_clean_ = false;
  });
}

LocalFrameView::DisallowLayoutInvalidationScope::
    ~DisallowLayoutInvalidationScope() {
  local_frame_view_->allows_layout_invalidation_after_layout_clean_ = true;
  local_frame_view_->ForAllChildLocalFrameViews([](LocalFrameView& frame_view) {
    if (!frame_view.ShouldThrottleRendering())
      frame_view.CheckDoesNotNeedLayout();
    frame_view.allows_layout_invalidation_after_layout_clean_ = true;
  });
}

#endif

bool LocalFrameView::UpdatePaintDebugInfoEnabled() {
  DCHECK(frame_->IsLocalRoot());
#if DCHECK_IS_ON()
  DCHECK(paint_debug_info_enabled_);
#else
  bool should_enable =
      cc::frame_viewer_instrumentation::IsTracingLayerTreeSnapshots() ||
      RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled() ||
      WebTestSupport::IsRunningWebTest() ||
      CoreProbeSink::HasAgentsGlobal(CoreProbeSink::kInspectorLayerTreeAgent);
  if (should_enable != paint_debug_info_enabled_) {
    paint_debug_info_enabled_ = should_enable;
    SetPaintArtifactCompositorNeedsUpdate();
    return true;
  }
#endif
  return false;
}

OverlayInterstitialAdDetector&
LocalFrameView::EnsureOverlayInterstitialAdDetector() {
  if (!overlay_interstitial_ad_detector_) {
    overlay_interstitial_ad_detector_ =
        std::make_unique<OverlayInterstitialAdDetector>();
  }
  return *overlay_interstitial_ad_detector_.get();
}

StickyAdDetector& LocalFrameView::EnsureStickyAdDetector() {
  if (!sticky_ad_detector_) {
    sticky_ad_detector_ = std::make_unique<StickyAdDetector>();
  }
  return *sticky_ad_detector_.get();
}

static PaintLayer* GetXrOverlayLayer(Document& document) {
  // immersive-ar DOM overlay mode is very similar to fullscreen video, using
  // the AR camera image instead of a video element as a background that's
  // separately composited in the browser. The fullscreened DOM content is shown
  // on top of that, same as HTML video controls.
  if (!document.IsXrOverlay())
    return nullptr;

  // When DOM overlay mode is active in iframe content, the parent frame's
  // document will also be marked as being in DOM overlay mode, with the iframe
  // element being in fullscreen mode. Find the innermost reachable fullscreen
  // element to use as the XR overlay layer. This is the overlay element for
  // same-process iframes, or an iframe element for OOPIF if the overlay element
  // is in another process.
  Document* content_document = &document;
  Element* fullscreen_element =
      Fullscreen::FullscreenElementFrom(*content_document);
  while (auto* frame_owner =
             DynamicTo<HTMLFrameOwnerElement>(fullscreen_element)) {
    content_document = frame_owner->contentDocument();
    if (!content_document) {
      // This is an OOPIF iframe, treat it as the fullscreen element.
      break;
    }
    fullscreen_element = Fullscreen::FullscreenElementFrom(*content_document);
  }

  if (!fullscreen_element)
    return nullptr;

  const auto* object = fullscreen_element->GetLayoutBoxModelObject();
  if (!object) {
    // Currently, only HTML fullscreen elements are supported for this mode,
    // not others such as SVG or MathML.
    DVLOG(1) << "no LayoutBoxModelObject for element " << fullscreen_element;
    return nullptr;
  }

  return object->Layer();
}

PaintLayer* LocalFrameView::GetXROverlayLayer() const {
  Document* doc = frame_->GetDocument();
  DCHECK(doc);

  // For WebXR DOM Overlay, the fullscreen overlay layer comes from either the
  // overlay element itself, or from an iframe element if the overlay element is
  // in an OOPIF. This layer is needed even for non-main-frame scenarios to
  // ensure the background remains transparent.
  if (doc->IsXrOverlay())
    return GetXrOverlayLayer(*doc);

  return nullptr;
}

void LocalFrameView::SetCullRectNeedsUpdateForFrames(bool disable_expansion) {
  ForAllNonThrottledLocalFrameViews(
      [disable_expansion](LocalFrameView& frame_view) {
        // Propagate child frame PaintLayer NeedsCullRectUpdate flag into the
        // owner frame.
        if (auto* frame_layout_view = frame_view.GetLayoutView()) {
          if (auto* owner = frame_view.GetFrame().OwnerLayoutObject()) {
            PaintLayer* frame_root_layer = frame_layout_view->Layer();
            DCHECK(frame_root_layer);
            DCHECK(owner->Layer());
            if (frame_root_layer->NeedsCullRectUpdate() ||
                frame_root_layer->DescendantNeedsCullRectUpdate()) {
              owner->Layer()->SetDescendantNeedsCullRectUpdate();
            }
          }
        }
        // If we disable cull rect expansion in a OverriddenCullRectScope,
        // invalidate cull rects for user scrollable areas. This may not
        // invalidate all cull rects affected by disable_expansion but it
        // doesn't affect correctness.
        if (disable_expansion) {
          for (const auto& area : frame_view.ScrollableAreas().Values()) {
            area->Layer()->SetNeedsCullRectUpdate();
          }
        }
      },
      // Use post-order to ensure correct flag propagation for nested frames.
      kPostOrder);
}

void LocalFrameView::RunPaintBenchmark(int repeat_count,
                                       cc::PaintBenchmarkResult& result) {
  DCHECK_EQ(Lifecycle().GetState(), DocumentLifecycle::kPaintClean);
  DCHECK(GetFrame().IsLocalRoot());
  AllowThrottlingScope allow_throttling(*this);

  auto run_benchmark = [&](PaintBenchmarkMode mode) -> double {
    constexpr int kTimeCheckInterval = 1;
    constexpr int kWarmupRuns = 0;
    constexpr base::TimeDelta kTimeLimit = base::Milliseconds(1);

    base::TimeDelta min_time = base::TimeDelta::Max();
    for (int i = 0; i < repeat_count; i++) {
      // Run for a minimum amount of time to avoid problems with timer
      // quantization when the time is very small.
      base::LapTimer timer(kWarmupRuns, kTimeLimit, kTimeCheckInterval);
      do {
        // TODO(https://crbug.com/1196853): Switch to ScriptForbiddenScope once
        // failures are fixed.
        BlinkLifecycleScopeWillBeScriptForbidden forbid_script;
        RunPaintLifecyclePhase(mode);
        timer.NextLap();
      } while (!timer.HasTimeLimitExpired());

      base::TimeDelta duration = timer.TimePerLap();
      if (duration < min_time)
        min_time = duration;
    }
    return min_time.InMillisecondsF();
  };

  result.record_time_ms = run_benchmark(PaintBenchmarkMode::kForcePaint);
  result.record_time_caching_disabled_ms =
      run_benchmark(PaintBenchmarkMode::kCachingDisabled);
  result.record_time_subsequence_caching_disabled_ms =
      run_benchmark(PaintBenchmarkMode::kSubsequenceCachingDisabled);
  result.raster_invalidation_and_convert_time_ms =
      run_benchmark(PaintBenchmarkMode::kForceRasterInvalidationAndConvert);
  result.paint_artifact_compositor_update_time_ms =
      run_benchmark(PaintBenchmarkMode::kForcePaintArtifactCompositorUpdate);

  result.painter_memory_usage = 0;
  if (paint_controller_persistent_data_) {
    result.painter_memory_usage +=
        paint_controller_persistent_data_->ApproximateUnsharedMemoryUsage();
  }
  if (paint_artifact_compositor_) {
    result.painter_memory_usage +=
        paint_artifact_compositor_->ApproximateUnsharedMemoryUsage();
  }
}

DarkModeFilter& LocalFrameView::EnsureDarkModeFilter() {
  if (!dark_mode_filter_) {
    dark_mode_filter_ =
        std::make_unique<DarkModeFilter>(GetCurrentDarkModeSettings());
  }
  return *dark_mode_filter_;
}

void LocalFrameView::AddPendingTransformUpdate(LayoutObject& object) {
  if (!pending_transform_updates_) {
    pending_transform_updates_ =
        MakeGarbageCollected<HeapHashSet<Member<LayoutObject>>>();
  }
  pending_transform_updates_->insert(&object);
}

bool LocalFrameView::RemovePendingTransformUpdate(const LayoutObject& object) {
  if (!pending_transform_updates_)
    return false;
  auto it =
      pending_transform_updates_->find(const_cast<LayoutObject*>(&object));
  if (it == pending_transform_updates_->end())
    return false;
  pending_transform_updates_->erase(it);
  return true;
}

void LocalFrameView::AddPendingOpacityUpdate(LayoutObject& object) {
  if (!pending_opacity_updates_) {
    pending_opacity_updates_ =
        MakeGarbageCollected<HeapHashSet<Member<LayoutObject>>>();
  }
  pending_opacity_updates_->insert(&object);
}

bool LocalFrameView::RemovePendingOpacityUpdate(const LayoutObject& object) {
  if (!pending_opacity_updates_)
    return false;
  auto it = pending_opacity_updates_->find(const_cast<LayoutObject*>(&object));
  if (it == pending_opacity_updates_->end())
    return false;
  pending_opacity_updates_->erase(it);
  return true;
}

bool LocalFrameView::ExecuteAllPendingUpdates() {
  DCHECK(GetFrame().IsLocalRoot() || !IsAttached());
  bool updated = false;
  ForAllNonThrottledLocalFrameViews([&updated](LocalFrameView& frame_view) {
    if (frame_view.pending_opacity_updates_ &&
        !frame_view.pending_opacity_updates_->empty()) {
      for (LayoutObject* object : *frame_view.pending_opacity_updates_) {
        DCHECK(
            !DisplayLockUtilities::LockedAncestorPreventingPrePaint(*object));
        PaintPropertyTreeBuilder::DirectlyUpdateOpacityValue(*object);
      }
      updated = true;
      frame_view.pending_opacity_updates_->clear();
    }
    if (frame_view.pending_transform_updates_ &&
        !frame_view.pending_transform_updates_->empty()) {
      for (LayoutObject* object : *frame_view.pending_transform_updates_) {
        DCHECK(
            !DisplayLockUtilities::LockedAncestorPreventingPrePaint(*object));
        PaintPropertyTreeBuilder::DirectlyUpdateTransformMatrix(*object);
      }
      updated = true;
      frame_view.SetIntersectionObservationState(kDesired);
      frame_view.pending_transform_updates_->clear();
    }
  });
  return updated;
}

void LocalFrameView::RemoveAllPendingUpdates() {
  if (pending_opacity_updates_) {
    for (LayoutObject* object : *pending_opacity_updates_) {
      object->SetNeedsPaintPropertyUpdate();
    }
    pending_opacity_updates_->clear();
  }
  if (pending_transform_updates_) {
    for (LayoutObject* object : *pending_transform_updates_) {
      object->SetNeedsPaintPropertyUpdate();
    }
    pending_transform_updates_->clear();
  }
}

void LocalFrameView::AddPendingStickyUpdate(PaintLayerScrollableArea* object) {
  if (!pending_sticky_updates_) {
    pending_sticky_updates_ =
        MakeGarbageCollected<HeapHashSet<Member<PaintLayerScrollableArea>>>();
  }
  pending_sticky_updates_->insert(object);
}

bool LocalFrameView::HasPendingStickyUpdate(
    PaintLayerScrollableArea* object) const {
  if (pending_sticky_updates_) {
    return pending_sticky_updates_->Contains(object);
  }
  return false;
}

void LocalFrameView::ExecutePendingStickyUpdates() {
  if (pending_sticky_updates_) {
    UseCounter::Count(frame_->GetDocument(), WebFeature::kPositionSticky);

    // Iteration order of the scrollable-areas doesn't matter as
    // sticky-positioned objects are contained within each scrollable-area.
    for (PaintLayerScrollableArea* scrollable_area : *pending_sticky_updates_) {
      scrollable_area->UpdateAllStickyConstraints();
    }
    pending_sticky_updates_->clear();
  }
}

void LocalFrameView::AddPendingSnapUpdate(PaintLayerScrollableArea* object) {
  if (!pending_snap_updates_) {
    pending_snap_updates_ =
        MakeGarbageCollected<HeapHashSet<Member<PaintLayerScrollableArea>>>();
  }
  pending_snap_updates_->insert(object);
}

void LocalFrameView::RemovePendingSnapUpdate(PaintLayerScrollableArea* object) {
  if (pending_snap_updates_) {
    pending_snap_updates_->erase(object);
  }
}

void LocalFrameView::ExecutePendingSnapUpdates() {
  if (pending_snap_updates_) {
    // Iteration order of the objects doesn't matter as the snap-areas are
    // contained within each scroll-container.
    for (PaintLayerScrollableArea* scrollable_area : *pending_snap_updates_) {
      auto* snap_container = scrollable_area->GetLayoutBox();
      DCHECK(snap_container->IsScrollContainer());
      if (SnapCoordinator::UpdateSnapContainerData(*snap_container)) {
        if (!pending_perform_snap_) {
          pending_perform_snap_ = MakeGarbageCollected<
              HeapHashSet<Member<PaintLayerScrollableArea>>>();
        }
        pending_perform_snap_->insert(scrollable_area);
      }
    }
    pending_snap_updates_->clear();
  }

  if (pending_perform_snap_ && !ShouldDeferLayoutSnap()) {
    for (PaintLayerScrollableArea* scrollable_area : *pending_perform_snap_) {
      scrollable_area->SnapAfterLayout();
    }
    pending_perform_snap_->clear();
  }
}

void LocalFrameView::NotifyElementWithRememberedSizeDisconnected(
    Element* element) {
  disconnected_elements_with_remembered_size_.insert(element);
}

bool LocalFrameView::UpdateLastSuccessfulPositionFallbacks() {
  return GetFrame()
      .GetDocument()
      ->GetStyleEngine()
      .UpdateLastSuccessfulPositionFallbacks();
}

}  // namespace blink

"""


```
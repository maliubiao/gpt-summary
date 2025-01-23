Response:
The user wants a summary of the functionalities of the `LocalFrameView` class in the provided C++ code snippet. The summary should include:
1. Listing the functionalities.
2. Explaining the relationship with Javascript, HTML, and CSS, with examples.
3. Providing examples of logical reasoning with hypothetical inputs and outputs.
4. Illustrating common user or programming errors.

Based on the provided code, `LocalFrameView` seems to be heavily involved in the layout and rendering process of a frame within a web page.

**Functionalities observed in the code:**

*   Performing layout (`PerformLayout`, `UpdateLayout`).
*   Managing layout invalidation and scheduling (`ScheduleRelayout`, `ScheduleRelayoutOfSubtree`, `SetNeedsLayout`).
*   Handling subtree layouts.
*   Managing the document lifecycle.
*   Updating plugins (`UpdatePlugins`, `ScheduleUpdatePluginsIfNecessary`).
*   Managing background attachment fixed objects.
*   Handling viewport size changes.
*   Managing intersection observers.
*   Processing URL fragments and fragment anchors.
*   Managing media types.
*   Handling forced layouts.
*   Managing paint invalidation.
*   Providing viewport size information for various purposes.
*   Managing background color and color adjust settings.
*   Performing hit testing.
*   Managing auto-sizing.

Let's break down each point with the required details.
这是 `blink/renderer/core/frame/local_frame_view.cc` 源代码文件的第二部分，主要负责 **执行布局 (performing layout)** 以及相关的生命周期管理、插件更新、以及和渲染相关的其他任务。

以下是该部分代码的功能归纳：

**核心布局执行与管理:**

*   **`PerformLayout()`**:  执行实际的布局计算。
    *   **功能:**  遍历需要布局的子树根节点，并调用 `LayoutFromRootObject` 进行布局。
    *   **与 CSS 的关系:**  布局过程会根据 CSS 样式计算元素的位置和大小。例如，CSS 的 `width`, `height`, `margin`, `padding`, `position` 等属性会直接影响布局结果。
        *   **举例:** 假设一个 `<div>` 元素的 CSS 样式为 `width: 100px; height: 50px; margin: 10px;`，`PerformLayout` 会计算出该 `<div>` 在其父元素中的具体位置 (考虑 margin) 和尺寸 (100x50)。
    *   **与 HTML 的关系:**  布局的对象是 HTML 元素构成的布局树。HTML 的结构决定了布局的层级关系。
        *   **举例:**  `<div><span>text</span></div>`，布局时 `<span>` 会作为 `<div>` 的子节点进行布局。
    *   **逻辑推理:**
        *   **假设输入:** `layout_subtree_root_list_` 包含一个需要布局的 `LayoutObject`，其对应一个 `<div>` 元素。该 `<div>` 的 CSS 样式设置了 `float: left;`。
        *   **输出:** `PerformLayout` 会将该 `<div>` 元素放置在其容器内靠左的位置，后续的元素会围绕它进行布局。
    *   **用户/编程错误:**  修改 CSS 样式后没有触发重新布局，导致页面显示与预期不符。例如，通过 JavaScript 修改了元素的 `display` 属性，但没有调用相应的 API 来触发布局更新。
*   **`UpdateLayout()`**:  入口函数，用于触发布局更新。
    *   **功能:**  准备布局所需的环境，设置性能追踪，调用 `PerformLayout()` 执行布局，并更新文档生命周期状态。
*   **布局调度与优化:**
    *   管理需要进行子树布局的根节点列表 `layout_subtree_root_list_`。
    *   使用 `fragment_tree_spines` 来优化分片树的重建。
    *   检查是否需要重建分片树 (`should_rebuild_fragments`)。
*   **文档生命周期管理:**
    *   在布局前后更新文档的生命周期状态 (`Lifecycle().AdvanceTo`)。
    *   在布局开始前确保文档状态至少为 `kStyleClean`。
*   **性能监控:**
    *   使用 `TRACE_EVENT` 记录布局的开始和结束，用于性能分析。
    *   使用 `FirstMeaningfulPaintDetector` 标记有意义的绘制时刻。
*   **视口相关:**
    *   在布局后，如果视口大小改变，会调用 `InvalidateLayoutForViewportConstrainedObjects()` 来标记需要针对视口约束对象进行布局更新。

**强制布局追踪:**

*   **`WillStartForcedLayout()`**:  记录强制布局开始的时间。
*   **`DidFinishForcedLayout()`**: 记录强制布局结束的时间。
    *   **功能:**  用于性能分析，跟踪强制布局的耗时。强制布局通常由 JavaScript 触发，例如获取某些布局信息的操作。

**渲染提示:**

*   **`MarkFirstEligibleToPaint()`**: 标记首次符合绘制的条件。
*   **`MarkIneligibleToPaint()`**: 标记不符合绘制的条件。
*   **`SetNeedsPaintPropertyUpdate()`**: 通知需要更新绘制属性。

**视口尺寸信息:**

*   提供多种获取视口尺寸的方法，用于不同的场景，例如媒体查询和视口单位 (`vw`, `vh`) 的计算。
    *   **`SmallViewportSizeForViewportUnits()`**: 获取用于视口单位的小视口尺寸。
    *   **`LargeViewportSizeForViewportUnits()`**: 获取用于视口单位的大视口尺寸。
    *   **`ViewportSizeForMediaQueries()`**: 获取用于媒体查询的视口尺寸。
    *   **`DynamicViewportSizeForViewportUnits()`**:  根据浏览器控件的状态动态获取视口尺寸。
    *   **与 CSS 的关系:** 这些方法计算的尺寸直接影响 CSS 视口单位的解析结果。例如，`100vw` 将会根据这些方法返回的宽度进行计算。

**生命周期步骤后续处理:**

*   **`RunPostLifecycleSteps()`**: 在生命周期步骤完成后执行额外的任务。
    *   运行可访问性相关的步骤 (`RunAccessibilitySteps()`).
    *   运行 Intersection Observer 相关的步骤 (`RunIntersectionObserverSteps()`).
    *   更新远程 frame 视图的合成缩放因子。
*   **`RunIntersectionObserverSteps()`**: 处理 Intersection Observer 的逻辑。
    *   **功能:**  计算元素与视口的相交情况，并触发相应的回调。
    *   **与 Javascript 的关系:**  Intersection Observer API 是 JavaScript 提供的，用于监听元素何时进入或离开视口。这个函数是 Blink 引擎中处理该 API 的一部分。
        *   **假设输入:**  一个页面包含一个注册了 Intersection Observer 的 `<div>` 元素，用户滚动页面使得该 `<div>` 进入视口。
        *   **输出:**  `RunIntersectionObserverSteps` 会检测到该相交事件，并触发 JavaScript 中注册的回调函数。
*   **`ForceUpdateViewportIntersections()`**:  强制更新视口相交信息。

**嵌入内容处理:**

*   **`EmbeddedReplacedContent()`**: 获取嵌入的替换内容（例如 SVG）。
*   **`GetIntrinsicSizingInfo()`**: 获取嵌入内容的固有尺寸信息。
*   **`HasIntrinsicSizingInfo()`**:  检查是否存在固有尺寸信息。
*   **`UpdateGeometry()`**: 更新嵌入内容的几何信息。

**插件更新:**

*   **`AddPartToUpdate()`**:  将需要更新的插件添加到更新集合中。
    *   **功能:**  标记需要更新的插件对象。通常在布局过程中被调用。
    *   **用户/编程错误:**  插件没有按预期更新，可能是因为没有正确调用 `AddPartToUpdate` 或者更新条件不满足。
*   **`SetMediaType()`**: 设置当前的媒体类型（例如 "screen", "print"）。
    *   **与 CSS 的关系:**  媒体类型会影响 CSS 媒体查询的匹配结果，从而影响页面的样式。
        *   **举例:**  CSS 中定义了 `@media print { ... }` 的样式，当媒体类型设置为 "print" 时，这些样式才会被应用。
*   **`MediaType()`**: 获取当前的媒体类型。
*   **`AdjustMediaTypeForPrinting()`**:  根据是否打印调整媒体类型。

**背景附件固定元素处理:**

*   **`AddBackgroundAttachmentFixedObject()`**:  添加背景附件固定的布局对象。
*   **`RemoveBackgroundAttachmentFixedObject()`**: 移除背景附件固定的布局对象。
*   **`RequiresMainThreadScrollingForBackgroundAttachmentFixed()`**:  检查背景附件固定的元素是否需要主线程滚动。
*   **`UpdateCanCompositeBackgroundAttachmentFixed()`**:  更新是否可以合成背景附件固定的元素。
*   **`InvalidateBackgroundAttachmentFixedDescendantsOnScroll()`**:  使滚动容器中背景附件固定的后代失效。
    *   **与 CSS 的关系:**  处理 CSS 属性 `background-attachment: fixed;` 的元素。

**视口大小变化处理:**

*   **`ViewportSizeChanged()`**:  处理视口大小变化事件。
    *   **功能:**  当浏览器窗口大小或设备方向改变时被调用，触发必要的布局和绘制更新。
    *   **与 Javascript 的关系:**  `window.resize` 事件在 JavaScript 中触发，最终会调用到这个函数。
*   **`InvalidateLayoutForViewportConstrainedObjects()`**:  使视口约束对象失效，触发重新布局。
*   **`DynamicViewportUnitsChanged()`**:  通知文档动态视口单位已更改。

**光标设置:**

*   **`ShouldSetCursor()`**:  判断是否应该设置光标。

**命中测试:**

*   **`HitTestWithThrottlingAllowed()`**:  执行命中测试，允许节流。

**URL 片段处理:**

*   **`ProcessUrlFragment()`**:  处理 URL 中的片段标识符（例如 `#anchor`）。
    *   **功能:**  创建和管理 `FragmentAnchor` 对象，用于滚动到页面内的特定位置。
    *   **与 HTML 的关系:**  与 HTML 锚点 `<a name="anchor">` 或 `<div id="anchor">` 配合使用。
    *   **与 Javascript 的关系:**  可以通过 JavaScript 修改 `window.location.hash` 来触发片段导航。
    *   **假设输入:** 用户访问 `https://example.com/page.html#section2`。
    *   **输出:** `ProcessUrlFragment` 会尝试找到 ID 或 name 为 "section2" 的元素，并滚动到该位置。
*   **`InvokeFragmentAnchor()`**:  执行片段锚点的跳转。
*   **`ClearFragmentAnchor()`**:  清除片段锚点。

**布局尺寸管理:**

*   **`SetLayoutSize()`**:  设置布局尺寸。
*   **`SetLayoutSizeFixedToFrameSize()`**:  设置布局尺寸是否固定为 frame 的尺寸。

**其他:**

*   **`GetChromeClient()`**: 获取 `ChromeClient` 对象。
*   **`HandleLoadCompleted()`**:  处理加载完成事件。
*   **`ClearLayoutSubtreeRoot()`**:  清除子树布局根节点。
*   **`ClearLayoutSubtreeRootsAndMarkContainingBlocks()`**:  清除子树布局根节点并标记包含块。
*   **`CheckLayoutInvalidationIsAllowed()`**:  检查是否允许布局失效。
*   **`RunPostLayoutIntersectionObserverSteps()`**:  在布局后运行 Intersection Observer 步骤。
*   **`ComputePostLayoutIntersections()`**:  计算布局后的相交情况。
*   **`ScheduleRelayout()`**: 调度重新布局。
*   **`ScheduleRelayoutOfSubtree()`**: 调度子树重新布局。
*   **`LayoutPending()`**:  检查是否有等待执行的布局。
*   **`IsInPerformLayout()`**:  检查是否正在执行布局。
*   **`NeedsLayout()`**:  检查是否需要布局。
*   **`CheckDoesNotNeedLayout()`**:  断言不需要布局。
*   **`SetNeedsLayout()`**:  标记需要布局。
*   **`ShouldUseColorAdjustBackground()`**:  判断是否应该调整背景颜色。
    *   **与 CSS 的关系:**  与 CSS 属性 `color-scheme` 相关。
*   **`BaseBackgroundColor()`**:  获取基础背景颜色。
*   **`SetBaseBackgroundColor()`**:  设置基础背景颜色。
*   **`SetUseColorAdjustBackground()`**:  设置是否使用颜色调整背景。
*   **`ShouldPaintBaseBackgroundColor()`**:  判断是否应该绘制基础背景颜色。
*   **`UpdateBaseBackgroundColorRecursively()`**:  递归更新基础背景颜色。
*   **`UpdatePlugins()`**: 更新插件。
*   **`UpdatePluginsTimerFired()`**: 插件更新定时器触发。
*   **`FlushAnyPendingPostLayoutTasks()`**:  刷新所有待处理的布局后任务。
*   **`ScheduleUpdatePluginsIfNecessary()`**:  如有必要，调度插件更新。
*   **`PerformPostLayoutTasks()`**:  执行布局后的任务。

总而言之，`LocalFrameView::PerformLayout` 和 `LocalFrameView::UpdateLayout` 是该部分代码的核心，它们负责执行实际的布局计算。其他函数则围绕着布局的调度、优化、以及与渲染流程的集成。该部分代码与 HTML 结构、CSS 样式以及 JavaScript 提供的相关 API (如 Intersection Observer) 紧密相关。

### 提示词
```
这是目录为blink/renderer/core/frame/local_frame_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ayoutObject& root_layout_object = *root;
        LayoutBox* container_box = root->ContainingNGBox();
        if (container_box) {
          auto it = fragment_tree_spines.find(container_box);
          DCHECK(it == fragment_tree_spines.end() || it->value > 0);
          // Ensure fragment-tree consistency just after all the cb's
          // descendants have completed their subtree layout.
          should_rebuild_fragments =
              it != fragment_tree_spines.end() && --it->value == 0;
        }

        if (!LayoutFromRootObject(*root))
          continue;

        if (should_rebuild_fragments)
          container_box->RebuildFragmentTreeSpine();

        // We need to ensure that we mark up all layoutObjects up to the
        // LayoutView for paint invalidation. This simplifies our code as we
        // just always do a full tree walk.
        if (LayoutObject* container = root_layout_object.Container())
          container->SetShouldCheckForPaintInvalidation();
      }
      layout_subtree_root_list_.Clear();
#if DCHECK_IS_ON()
      // Ensure fragment-tree consistency after a subtree layout.
      for (const auto& p : fragment_tree_spines) {
        p.key->AssertFragmentTree();
        DCHECK_EQ(p.value, 0u);
      }
#endif
      fragment_tree_spines.clear();
    } else {
      GetLayoutView()->LayoutRoot();
    }
  }

  Lifecycle().AdvanceTo(DocumentLifecycle::kAfterPerformLayout);

  TRACE_EVENT_END0(PERFORM_LAYOUT_TRACE_CATEGORIES,
                   "LocalFrameView::performLayout");
  FirstMeaningfulPaintDetector::From(*document)
      .MarkNextPaintAsMeaningfulIfNeeded(
          layout_object_counter_, contents_height_before_layout,
          GetLayoutView()->DocumentRect().Height(), Height());

  if (old_size != Size()) {
    InvalidateLayoutForViewportConstrainedObjects();
  }

  if (frame_->IsMainFrame()) {
    if (auto* text_autosizer = document->GetTextAutosizer()) {
      if (text_autosizer->HasLayoutInlineSizeChanged())
        text_autosizer->UpdatePageInfoInAllFrames(frame_);
    }
  }
#if EXPENSIVE_DCHECKS_ARE_ON()
  DCHECK(!Lifecycle().LifecyclePostponed() && !ShouldThrottleRendering());
  document->AssertLayoutTreeUpdatedAfterLayout();
#endif
}

void LocalFrameView::UpdateLayout() {
  // We should never layout a Document which is not in a LocalFrame.
  DCHECK(frame_);
  DCHECK_EQ(frame_->View(), this);
  DCHECK(frame_->GetPage());

  Lifecycle().EnsureStateAtMost(DocumentLifecycle::kStyleClean);

  std::optional<RuntimeCallTimerScope> rcs_scope;
  probe::UpdateLayout probe(frame_->GetDocument());
  HeapVector<LayoutObjectWithDepth> layout_roots;

  v8::Isolate* isolate = frame_->GetPage()->GetAgentGroupScheduler().Isolate();
  ENTER_EMBEDDER_STATE(isolate, frame_, BlinkState::LAYOUT);
  TRACE_EVENT_BEGIN0("blink,benchmark", "LocalFrameView::layout");
  if (RuntimeEnabledFeatures::BlinkRuntimeCallStatsEnabled()) [[unlikely]] {
    rcs_scope.emplace(RuntimeCallStats::From(isolate),
                      RuntimeCallStats::CounterId::kUpdateLayout);
  }
  layout_roots = layout_subtree_root_list_.Ordered();
  if (layout_roots.empty())
    layout_roots.push_back(LayoutObjectWithDepth(GetLayoutView()));
  TRACE_EVENT_BEGIN1("devtools.timeline", "Layout", "beginData",
                     [&](perfetto::TracedValue context) {
                       inspector_layout_event::BeginData(std::move(context),
                                                         this);
                     });

  PerformLayout();
  Lifecycle().AdvanceTo(DocumentLifecycle::kLayoutClean);

  TRACE_EVENT_END0("blink,benchmark", "LocalFrameView::layout");

  TRACE_EVENT_END1("devtools.timeline", "Layout", "endData",
                   [&](perfetto::TracedValue context) {
                     inspector_layout_event::EndData(std::move(context),
                                                     layout_roots);
                   });
  probe::DidChangeViewport(frame_.Get());
}

void LocalFrameView::WillStartForcedLayout(DocumentUpdateReason reason) {
  if (!base::TimeTicks::IsHighResolution()) {
    return;
  }

  // UpdateLayout is re-entrant for auto-sizing and plugins. So keep
  // track of stack depth to include all the time in the top-level call.
  forced_layout_stack_depth_++;
  if (forced_layout_stack_depth_ > 1)
    return;
  if (auto* metrics_aggregator = GetUkmAggregator()) {
    DCHECK(!forced_layout_timer_.has_value());
    forced_layout_timer_ =
        metrics_aggregator->GetScopedForcedLayoutTimer(reason);
  }
}

void LocalFrameView::DidFinishForcedLayout() {
  if (!base::TimeTicks::IsHighResolution()) {
    return;
  }

  CHECK_GT(forced_layout_stack_depth_, (unsigned)0);
  forced_layout_stack_depth_--;
  if (!forced_layout_stack_depth_) {
    forced_layout_timer_.reset();
  }
}

void LocalFrameView::MarkFirstEligibleToPaint() {
  if (frame_ && frame_->GetDocument()) {
    PaintTiming& timing = PaintTiming::From(*frame_->GetDocument());
    timing.MarkFirstEligibleToPaint();
  }
}

void LocalFrameView::MarkIneligibleToPaint() {
  if (frame_ && frame_->GetDocument()) {
    PaintTiming& timing = PaintTiming::From(*frame_->GetDocument());
    timing.MarkIneligibleToPaint();
  }
}

void LocalFrameView::SetNeedsPaintPropertyUpdate() {
  if (auto* layout_view = GetLayoutView())
    layout_view->SetNeedsPaintPropertyUpdate();
}

gfx::SizeF LocalFrameView::SmallViewportSizeForViewportUnits() const {
  float zoom = 1;
  if (!frame_->GetDocument() || !frame_->GetDocument()->Printing())
    zoom = GetFrame().LayoutZoomFactor();

  auto* layout_view = GetLayoutView();
  if (!layout_view)
    return gfx::SizeF();

  gfx::SizeF layout_size;
  layout_size.set_width(layout_view->ViewWidth(kIncludeScrollbars) / zoom);
  layout_size.set_height(layout_view->ViewHeight(kIncludeScrollbars) / zoom);

  return layout_size;
}

gfx::SizeF LocalFrameView::LargeViewportSizeForViewportUnits() const {
  auto* layout_view = GetLayoutView();
  if (!layout_view)
    return gfx::SizeF();

  gfx::SizeF layout_size = SmallViewportSizeForViewportUnits();

  BrowserControls& browser_controls = frame_->GetPage()->GetBrowserControls();
  if (browser_controls.PermittedState() != cc::BrowserControlsState::kHidden) {
    // We use the layoutSize rather than frameRect to calculate viewport units
    // so that we get correct results on mobile where the page is laid out into
    // a rect that may be larger than the viewport (e.g. the 980px fallback
    // width for desktop pages). Since the layout height is statically set to
    // be the viewport with browser controls showing, we add the browser
    // controls height, compensating for page scale as well, since we want to
    // use the viewport with browser controls hidden for vh (to match Safari).
    int viewport_width = frame_->GetPage()->GetVisualViewport().Size().width();
    if (frame_->IsOutermostMainFrame() && layout_size.width() &&
        viewport_width) {
      float layout_to_viewport_width_scale_factor =
          viewport_width / layout_size.width();
      layout_size.Enlarge(0, (browser_controls.TotalHeight() -
                              browser_controls.TotalMinHeight()) /
                                 layout_to_viewport_width_scale_factor);
    }
  }

  return layout_size;
}

gfx::SizeF LocalFrameView::ViewportSizeForMediaQueries() const {
  if (!frame_->GetDocument()) {
    return gfx::SizeF(layout_size_);
  }
  if (frame_->ShouldUsePaginatedLayout()) {
    if (const LayoutView* layout_view = GetLayoutView()) {
      return layout_view->DefaultPageAreaSize();
    }
  }
  gfx::SizeF viewport_size(layout_size_);
  if (!frame_->GetDocument()->Printing()) {
    viewport_size.Scale(1 / GetFrame().LayoutZoomFactor());
  }
  return viewport_size;
}

gfx::SizeF LocalFrameView::DynamicViewportSizeForViewportUnits() const {
  BrowserControls& browser_controls = frame_->GetPage()->GetBrowserControls();
  return browser_controls.ShrinkViewport()
             ? SmallViewportSizeForViewportUnits()
             : LargeViewportSizeForViewportUnits();
}

DocumentLifecycle& LocalFrameView::Lifecycle() const {
  DCHECK(frame_);
  DCHECK(frame_->GetDocument());
  return frame_->GetDocument()->Lifecycle();
}

bool LocalFrameView::InvalidationDisallowed() const {
  return GetFrame().LocalFrameRoot().View()->invalidation_disallowed_;
}

void LocalFrameView::RunPostLifecycleSteps() {
  InvalidationDisallowedScope invalidation_disallowed(*this);
  AllowThrottlingScope allow_throttling(*this);
  RunAccessibilitySteps();
  RunIntersectionObserverSteps();
  if (mobile_friendliness_checker_)
    mobile_friendliness_checker_->MaybeRecompute();

  ForAllRemoteFrameViews([](RemoteFrameView& frame_view) {
    frame_view.UpdateCompositingScaleFactor();
  });
}

void LocalFrameView::RunIntersectionObserverSteps() {
#if DCHECK_IS_ON()
  bool was_dirty = NeedsLayout();
#endif
  if ((intersection_observation_state_ < kRequired &&
       ShouldThrottleRendering()) ||
      Lifecycle().LifecyclePostponed() || !frame_->GetDocument()->IsActive()) {
    return;
  }

  if (frame_->IsOutermostMainFrame()) {
    EnsureOverlayInterstitialAdDetector().MaybeFireDetection(frame_.Get());
    EnsureStickyAdDetector().MaybeFireDetection(frame_.Get());

    // Report the main frame's document intersection with itself.
    LayoutObject* layout_object = GetLayoutView();
    gfx::Rect main_frame_dimensions(ToRoundedSize(
        To<LayoutBox>(layout_object)->ScrollableOverflowRect().size));
    GetFrame().Client()->OnMainFrameIntersectionChanged(main_frame_dimensions);
    GetFrame().Client()->OnMainFrameViewportRectangleChanged(
        gfx::Rect(frame_->GetOutermostMainFrameScrollPosition(),
                  frame_->GetOutermostMainFrameSize()));
  }

  TRACE_EVENT0("blink,benchmark",
               "LocalFrameView::UpdateViewportIntersectionsForSubtree");
  SCOPED_UMA_AND_UKM_TIMER(GetUkmAggregator(),
                           LocalFrameUkmAggregator::kIntersectionObservation);

  ComputeIntersectionsContext context;
  bool needs_occlusion_tracking =
      UpdateViewportIntersectionsForSubtree(0, context);
  if (FrameOwner* owner = frame_->Owner())
    owner->SetNeedsOcclusionTracking(needs_occlusion_tracking);
#if DCHECK_IS_ON()
  DCHECK(was_dirty || !NeedsLayout());
#endif
  DeliverSynchronousIntersectionObservations();
}

void LocalFrameView::ForceUpdateViewportIntersections() {
  // IntersectionObserver targets in this frame (and its frame tree) need to
  // update; but we can't wait for a lifecycle update to run them, because a
  // hidden frame won't run lifecycle updates. Force layout and run them now.
  DisallowThrottlingScope disallow_throttling(*this);
  UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kIntersectionObservation);
  ComputeIntersectionsContext context;
  UpdateViewportIntersectionsForSubtree(
      IntersectionObservation::kImplicitRootObserversNeedUpdate |
          IntersectionObservation::kIgnoreDelay,
      context);
}

LayoutSVGRoot* LocalFrameView::EmbeddedReplacedContent() const {
  auto* layout_view = GetLayoutView();
  if (!layout_view)
    return nullptr;

  LayoutObject* first_child = layout_view->FirstChild();
  if (!first_child || !first_child->IsBox())
    return nullptr;

  // Currently only embedded SVG documents participate in the size-negotiation
  // logic.
  return DynamicTo<LayoutSVGRoot>(first_child);
}

bool LocalFrameView::GetIntrinsicSizingInfo(
    IntrinsicSizingInfo& intrinsic_sizing_info) const {
  if (LayoutSVGRoot* content_layout_object = EmbeddedReplacedContent()) {
    content_layout_object->UnscaledIntrinsicSizingInfo(intrinsic_sizing_info);
    return true;
  }
  return false;
}

bool LocalFrameView::HasIntrinsicSizingInfo() const {
  return EmbeddedReplacedContent();
}

void LocalFrameView::UpdateGeometry() {
  LayoutEmbeddedContent* layout = GetLayoutEmbeddedContent();
  if (!layout)
    return;

  PhysicalRect new_frame = layout->ReplacedContentRect();
#if DCHECK_IS_ON()
  if (new_frame.Width() != LayoutUnit::Max().RawValue() &&
      new_frame.Height() != LayoutUnit::Max().RawValue())
    DCHECK(!new_frame.size.HasFraction());
#endif
  bool bounds_will_change = PhysicalSize(Size()) != new_frame.size;

  // If frame bounds are changing mark the view for layout. Also check the
  // frame's page to make sure that the frame isn't in the process of being
  // destroyed. If iframe scrollbars needs reconstruction from native to custom
  // scrollbar, then also we need to layout the frameview.
  if (bounds_will_change)
    SetNeedsLayout();

  layout->UpdateGeometry(*this);
}

void LocalFrameView::AddPartToUpdate(LayoutEmbeddedObject& object) {
  // This is typically called during layout to ensure we update plugins.
  // However, if layout is blocked (e.g. by content-visibility), we can add the
  // part to update during layout tree attachment (which is a part of style
  // recalc).
  DCHECK(IsInPerformLayout() ||
         (DisplayLockUtilities::LockedAncestorPreventingLayout(object) &&
          frame_->GetDocument()->InStyleRecalc()));

  // Tell the DOM element that it needs a Plugin update.
  Node* node = object.GetNode();
  DCHECK(node);
  if (IsA<HTMLObjectElement>(*node) || IsA<HTMLEmbedElement>(*node))
    To<HTMLPlugInElement>(node)->SetNeedsPluginUpdate(true);

  part_update_set_.insert(&object);
}

void LocalFrameView::SetMediaType(const AtomicString& media_type) {
  DCHECK(frame_->GetDocument());
  media_type_ = media_type;
  frame_->GetDocument()->MediaQueryAffectingValueChanged(
      MediaValueChange::kOther);
}

AtomicString LocalFrameView::MediaType() const {
  // See if we have an override type.
  if (frame_->GetSettings() &&
      !frame_->GetSettings()->GetMediaTypeOverride().empty())
    return AtomicString(frame_->GetSettings()->GetMediaTypeOverride());
  return media_type_;
}

void LocalFrameView::AdjustMediaTypeForPrinting(bool printing) {
  if (printing) {
    if (media_type_when_not_printing_.IsNull())
      media_type_when_not_printing_ = media_type_;
    SetMediaType(media_type_names::kPrint);
  } else {
    if (!media_type_when_not_printing_.IsNull())
      SetMediaType(media_type_when_not_printing_);
    media_type_when_not_printing_ = g_null_atom;
  }
}

void LocalFrameView::AddBackgroundAttachmentFixedObject(
    LayoutBoxModelObject& object) {
  DCHECK(!background_attachment_fixed_objects_.Contains(&object));
  background_attachment_fixed_objects_.insert(&object);
  SetNeedsPaintPropertyUpdate();
}

void LocalFrameView::RemoveBackgroundAttachmentFixedObject(
    LayoutBoxModelObject& object) {
  background_attachment_fixed_objects_.erase(&object);
  SetNeedsPaintPropertyUpdate();
}

static bool BackgroundAttachmentFixedNeedsRepaintOnScroll(
    const LayoutObject& object) {
  // We should not add such object in the background_attachment_fixed_objects_.
  DCHECK(!To<LayoutBoxModelObject>(object).BackgroundTransfersToView());
  // The background doesn't need repaint if it's the viewport background and it
  // paints onto the border box space only.
  if (const auto* view = DynamicTo<LayoutView>(object)) {
    if (view->GetBackgroundPaintLocation() ==
        kBackgroundPaintInBorderBoxSpace) {
      return false;
    }
  }
  return !object.CanCompositeBackgroundAttachmentFixed();
}

bool LocalFrameView::RequiresMainThreadScrollingForBackgroundAttachmentFixed()
    const {
  for (const auto& object : background_attachment_fixed_objects_) {
    if (BackgroundAttachmentFixedNeedsRepaintOnScroll(*object)) {
      return true;
    }
  }
  return false;
}

void LocalFrameView::ViewportSizeChanged() {
  DCHECK(frame_->GetPage());
  if (frame_->GetDocument() &&
      frame_->GetDocument()->Lifecycle().LifecyclePostponed())
    return;

  if (frame_->IsOutermostMainFrame())
    layout_shift_tracker_->NotifyViewportSizeChanged();

  auto* layout_view = GetLayoutView();
  if (layout_view) {
    // If this is the outermost main frame, we might have got here by
    // hiding/showing the top controls. In that case, layout might not be
    // triggered, so some things that normally hook into layout need to be
    // specially notified.
    if (GetFrame().IsOutermostMainFrame()) {
      if (auto* scrollable_area = layout_view->GetScrollableArea()) {
        scrollable_area->ClampScrollOffsetAfterOverflowChange();
        scrollable_area->EnqueueForSnapUpdateIfNeeded();
      }
    }

    layout_view->Layer()->SetNeedsCompositingInputsUpdate();
  }

  if (GetFrame().GetDocument())
    GetFrame().GetDocument()->GetRootScrollerController().DidResizeFrameView();

  // Change of viewport size after browser controls showing/hiding may affect
  // painting of the background.
  if (layout_view && frame_->IsMainFrame() &&
      frame_->GetPage()->GetBrowserControls().TotalHeight())
    layout_view->SetShouldCheckForPaintInvalidation();

  if (GetFrame().GetDocument() && !IsInPerformLayout()) {
    InvalidateLayoutForViewportConstrainedObjects();
  }

  if (GetPaintTimingDetector().Visualizer())
    GetPaintTimingDetector().Visualizer()->OnViewportChanged();
}

void LocalFrameView::InvalidateLayoutForViewportConstrainedObjects() {
  auto* layout_view = GetLayoutView();
  if (layout_view && !layout_view->NeedsLayout()) {
    for (const auto& fragment : layout_view->PhysicalFragments()) {
      if (fragment.StickyDescendants()) {
        layout_view->SetNeedsSimplifiedLayout();
        return;
      }
      if (!fragment.HasOutOfFlowFragmentChild()) {
        continue;
      }
      for (const auto& fragment_child : fragment.Children()) {
        if (fragment_child->IsFixedPositioned()) {
          layout_view->SetNeedsSimplifiedLayout();
          return;
        }
      }
    }
  }
}

void LocalFrameView::DynamicViewportUnitsChanged() {
  if (GetFrame().GetDocument())
    GetFrame().GetDocument()->DynamicViewportUnitsChanged();
}

bool LocalFrameView::ShouldSetCursor() const {
  Page* page = GetFrame().GetPage();
  return page && page->IsPageVisible() &&
         !frame_->GetEventHandler().IsMousePositionUnknown() &&
         page->GetFocusController().IsActive();
}

void LocalFrameView::UpdateCanCompositeBackgroundAttachmentFixed() {
  // Too many composited background-attachment:fixed hurt performance, so we
  // want to avoid that with this heuristic (which doesn't need to be accurate
  // so we simply check the number of all background-attachment:fixed objects).
  constexpr wtf_size_t kMaxCompositedBackgroundAttachmentFixed = 8;
  bool enable_composited_background_attachment_fixed =
      background_attachment_fixed_objects_.size() <=
      kMaxCompositedBackgroundAttachmentFixed;
  for (const auto& object : background_attachment_fixed_objects_) {
    object->UpdateCanCompositeBackgroundAttachmentFixed(
        enable_composited_background_attachment_fixed);
  }
}

void LocalFrameView::InvalidateBackgroundAttachmentFixedDescendantsOnScroll(
    const LayoutBox& scroller) {
  for (const auto& layout_object : background_attachment_fixed_objects_) {
    if (scroller != GetLayoutView() &&
        !layout_object->IsDescendantOf(&scroller)) {
      continue;
    }
    if (BackgroundAttachmentFixedNeedsRepaintOnScroll(*layout_object)) {
      layout_object->SetBackgroundNeedsFullPaintInvalidation();
    }
  }
}

HitTestResult LocalFrameView::HitTestWithThrottlingAllowed(
    const HitTestLocation& location,
    HitTestRequest::HitTestRequestType request_type) const {
  AllowThrottlingScope allow_throttling(*this);
  return GetFrame().GetEventHandler().HitTestResultAtLocation(location,
                                                              request_type);
}

void LocalFrameView::ProcessUrlFragment(const KURL& url,
                                        bool same_document_navigation,
                                        bool should_scroll) {
  // We want to create the anchor even if we don't need to scroll. This ensures
  // all the side effects like setting CSS :target are correctly set.
  FragmentAnchor* anchor =
      FragmentAnchor::TryCreate(url, *frame_, should_scroll);

  if (anchor) {
    fragment_anchor_ = anchor;
    fragment_anchor_->Installed();
    // Post-load, same-document navigations need to schedule a frame in which
    // the fragment anchor will be invoked. It will be done after layout as
    // part of the lifecycle.
    if (same_document_navigation)
      ScheduleAnimation();
  }
}

void LocalFrameView::SetLayoutSize(const gfx::Size& size) {
  DCHECK(!LayoutSizeFixedToFrameSize());
  if (frame_->GetDocument() &&
      frame_->GetDocument()->Lifecycle().LifecyclePostponed())
    return;

  SetLayoutSizeInternal(size);
}

void LocalFrameView::SetLayoutSizeFixedToFrameSize(bool is_fixed) {
  if (layout_size_fixed_to_frame_size_ == is_fixed)
    return;

  layout_size_fixed_to_frame_size_ = is_fixed;
  if (is_fixed)
    SetLayoutSizeInternal(Size());
}

ChromeClient* LocalFrameView::GetChromeClient() const {
  Page* page = GetFrame().GetPage();
  if (!page)
    return nullptr;
  return &page->GetChromeClient();
}

void LocalFrameView::HandleLoadCompleted() {
  TRACE_EVENT1("blink", "LocalFrameView::HandleLoadCompleted",
               "has_auto_size_info", !!auto_size_info_);

  // Once loading has completed, allow autoSize one last opportunity to
  // reduce the size of the frame.
  if (auto_size_info_)
    UpdateStyleAndLayout();
}

void LocalFrameView::ClearLayoutSubtreeRoot(const LayoutObject& root) {
  layout_subtree_root_list_.Remove(const_cast<LayoutObject&>(root));
}

void LocalFrameView::ClearLayoutSubtreeRootsAndMarkContainingBlocks() {
  layout_subtree_root_list_.ClearAndMarkContainingBlocksForLayout();
}

bool LocalFrameView::CheckLayoutInvalidationIsAllowed() const {
#if DCHECK_IS_ON()
  if (allows_layout_invalidation_after_layout_clean_)
    return true;

  // If we are updating all lifecycle phases beyond LayoutClean, we don't expect
  // dirty layout after LayoutClean.
  CHECK_FOR_DIRTY_LAYOUT(Lifecycle().GetState() <
                         DocumentLifecycle::kLayoutClean);

#endif
  return true;
}

bool LocalFrameView::RunPostLayoutIntersectionObserverSteps() {
  DCHECK(frame_->IsLocalRoot());
  DCHECK(Lifecycle().GetState() >= DocumentLifecycle::kPrePaintClean);

  ComputeIntersectionsContext context;
  ComputePostLayoutIntersections(0, context);

  bool needs_more_lifecycle_steps = false;
  ForAllNonThrottledLocalFrameViews(
      [&needs_more_lifecycle_steps](LocalFrameView& frame_view) {
        if (auto* controller = frame_view.GetFrame()
                                   .GetDocument()
                                   ->GetIntersectionObserverController()) {
          controller->DeliverNotifications(
              IntersectionObserver::kDeliverDuringPostLayoutSteps);
        }
        // If the lifecycle state changed as a result of the notifications, we
        // should run the lifecycle again.
        needs_more_lifecycle_steps |= frame_view.Lifecycle().GetState() <
                                          DocumentLifecycle::kPrePaintClean ||
                                      frame_view.NeedsLayout();
      });

  return needs_more_lifecycle_steps;
}

void LocalFrameView::ComputePostLayoutIntersections(
    unsigned parent_flags,
    ComputeIntersectionsContext& context) {
  if (ShouldThrottleRendering())
    return;

  unsigned flags = GetIntersectionObservationFlags(parent_flags) |
                   IntersectionObservation::kPostLayoutDeliveryOnly;

  if (auto* controller =
          GetFrame().GetDocument()->GetIntersectionObserverController()) {
    controller->ComputeIntersections(
        flags, *this, accumulated_scroll_delta_since_last_intersection_update_,
        context);
    accumulated_scroll_delta_since_last_intersection_update_ = gfx::Vector2dF();
  }

  for (Frame* child = frame_->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    auto* child_local_frame = DynamicTo<LocalFrame>(child);
    if (!child_local_frame)
      continue;
    if (LocalFrameView* child_view = child_local_frame->View())
      child_view->ComputePostLayoutIntersections(flags, context);
  }
}

void LocalFrameView::ScheduleRelayout() {
  DCHECK(frame_->View() == this);

  if (!layout_scheduling_enabled_)
    return;
  // TODO(crbug.com/590856): It's still broken when we choose not to crash when
  // the check fails.
  if (!CheckLayoutInvalidationIsAllowed())
    return;
  if (!NeedsLayout())
    return;
  if (!frame_->GetDocument()->ShouldScheduleLayout())
    return;
  DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT_WITH_CATEGORIES(
      TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), "InvalidateLayout",
      inspector_invalidate_layout_event::Data, frame_.Get(),
      GetLayoutView()->OwnerNodeId());

  ClearLayoutSubtreeRootsAndMarkContainingBlocks();

  if (has_pending_layout_)
    return;
  has_pending_layout_ = true;

  if (!ShouldThrottleRendering())
    GetPage()->Animator().ScheduleVisualUpdate(frame_.Get());
}

void LocalFrameView::ScheduleRelayoutOfSubtree(LayoutObject* relayout_root) {
  DCHECK(frame_->View() == this);
  DCHECK(relayout_root->IsBox());

  // TODO(crbug.com/590856): It's still broken when we choose not to crash when
  // the check fails.
  if (!CheckLayoutInvalidationIsAllowed())
    return;

  // FIXME: Should this call shouldScheduleLayout instead?
  if (!frame_->GetDocument()->IsActive())
    return;

  LayoutView* layout_view = GetLayoutView();
  if (layout_view && layout_view->NeedsLayout()) {
    if (relayout_root)
      relayout_root->MarkContainerChainForLayout(false);
    return;
  }

  if (relayout_root == layout_view)
    layout_subtree_root_list_.ClearAndMarkContainingBlocksForLayout();
  else
    layout_subtree_root_list_.Add(*relayout_root);

  if (layout_scheduling_enabled_) {
    has_pending_layout_ = true;

    if (!ShouldThrottleRendering())
      GetPage()->Animator().ScheduleVisualUpdate(frame_.Get());

    if (GetPage()->Animator().IsServicingAnimations())
      Lifecycle().EnsureStateAtMost(DocumentLifecycle::kStyleClean);
  }
  DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT_WITH_CATEGORIES(
      TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), "InvalidateLayout",
      inspector_invalidate_layout_event::Data, frame_.Get(),
      relayout_root->OwnerNodeId());
}

bool LocalFrameView::LayoutPending() const {
  // FIXME: This should check Document::lifecycle instead.
  return has_pending_layout_;
}

bool LocalFrameView::IsInPerformLayout() const {
  return Lifecycle().GetState() == DocumentLifecycle::kInPerformLayout;
}

bool LocalFrameView::NeedsLayout() const {
  // This can return true in cases where the document does not have a body yet.
  // Document::shouldScheduleLayout takes care of preventing us from scheduling
  // layout in that case.

  auto* layout_view = GetLayoutView();
  return LayoutPending() || (layout_view && layout_view->NeedsLayout()) ||
         IsSubtreeLayout();
}

NOINLINE bool LocalFrameView::CheckDoesNotNeedLayout() const {
  CHECK_FOR_DIRTY_LAYOUT(!LayoutPending());
  CHECK_FOR_DIRTY_LAYOUT(!GetLayoutView() || !GetLayoutView()->NeedsLayout());
  CHECK_FOR_DIRTY_LAYOUT(!IsSubtreeLayout());
  return true;
}

void LocalFrameView::SetNeedsLayout() {
  auto* layout_view = GetLayoutView();
  if (!layout_view)
    return;
  // TODO(crbug.com/590856): It's still broken if we choose not to crash when
  // the check fails.
  if (!CheckLayoutInvalidationIsAllowed())
    return;
  layout_view->SetNeedsLayout(layout_invalidation_reason::kUnknown);
}

bool LocalFrameView::ShouldUseColorAdjustBackground() const {
  return use_color_adjust_background_ == UseColorAdjustBackground::kYes ||
         (use_color_adjust_background_ ==
              UseColorAdjustBackground::kIfBaseNotTransparent &&
          base_background_color_ != Color::kTransparent);
}

Color LocalFrameView::BaseBackgroundColor() const {
  if (ShouldUseColorAdjustBackground()) {
    DCHECK(frame_->GetDocument());
    return frame_->GetDocument()->GetStyleEngine().ColorAdjustBackgroundColor();
  }
  return base_background_color_;
}

void LocalFrameView::SetBaseBackgroundColor(const Color& background_color) {
  if (base_background_color_ == background_color)
    return;

  base_background_color_ = background_color;

  if (auto* layout_view = GetLayoutView())
    layout_view->SetBackgroundNeedsFullPaintInvalidation();

  if (!ShouldThrottleRendering())
    GetPage()->Animator().ScheduleVisualUpdate(frame_.Get());
}

void LocalFrameView::SetUseColorAdjustBackground(UseColorAdjustBackground use,
                                                 bool color_scheme_changed) {
  if (use_color_adjust_background_ == use && !color_scheme_changed)
    return;

  if (!frame_->GetDocument())
    return;

  use_color_adjust_background_ = use;

  if (GetFrame().IsMainFrame() && ShouldUseColorAdjustBackground()) {
    // Pass the dark color-scheme background to the browser process to paint a
    // dark background in the browser tab while rendering is blocked in order to
    // avoid flashing the white background in between loading documents. If we
    // perform a navigation within the same renderer process, we keep the
    // content background from the previous page while rendering is blocked in
    // the new page, but for cross process navigations we would paint the
    // default background (typically white) while the rendering is blocked.
    GetFrame().DidChangeBackgroundColor(BaseBackgroundColor().toSkColor4f(),
                                        true /* color_adjust */);
  }

  if (auto* layout_view = GetLayoutView())
    layout_view->SetBackgroundNeedsFullPaintInvalidation();
}

bool LocalFrameView::ShouldPaintBaseBackgroundColor() const {
  return ShouldUseColorAdjustBackground() ||
         frame_->GetDocument()->IsInMainFrame();
}

void LocalFrameView::UpdateBaseBackgroundColorRecursively(
    const Color& base_background_color) {
  ForAllNonThrottledLocalFrameViews(
      [base_background_color](LocalFrameView& frame_view) {
        frame_view.SetBaseBackgroundColor(base_background_color);
      });
}

void LocalFrameView::InvokeFragmentAnchor() {
  if (!fragment_anchor_)
    return;

  if (!fragment_anchor_->Invoke())
    fragment_anchor_ = nullptr;
}

void LocalFrameView::ClearFragmentAnchor() {
  fragment_anchor_ = nullptr;
}

bool LocalFrameView::UpdatePlugins() {
  // This is always called from UpdatePluginsTimerFired.
  // update_plugins_timer should only be scheduled if we have FrameViews to
  // update. Thus I believe we can stop checking isEmpty here, and just ASSERT
  // isEmpty:
  // FIXME: This assert has been temporarily removed due to
  // https://crbug.com/430344
  if (part_update_set_.empty())
    return true;

  // Need to swap because script will run inside the below loop and invalidate
  // the iterator.
  EmbeddedObjectSet objects;
  objects.swap(part_update_set_);

  for (const auto& embedded_object : objects) {
    LayoutEmbeddedObject& object = *embedded_object;

#if DCHECK_IS_ON()
    if (object.is_destroyed_)
      continue;
#endif

    auto* element = To<HTMLPlugInElement>(object.GetNode());

    // The object may have already been destroyed (thus node cleared).
    if (!element)
      continue;

    // No need to update if it's already crashed or known to be missing.
    if (object.ShowsUnavailablePluginIndicator())
      continue;

    if (element->NeedsPluginUpdate() && element->GetLayoutObject())
      element->UpdatePlugin();
    if (EmbeddedContentView* view = element->OwnedEmbeddedContentView())
      view->UpdateGeometry();

    // Prevent plugins from causing infinite updates of themselves.
    // FIXME: Do we really need to prevent this?
    part_update_set_.erase(&object);
  }

  return part_update_set_.empty();
}

void LocalFrameView::UpdatePluginsTimerFired(TimerBase*) {
  DCHECK(!IsInPerformLayout());
  for (unsigned i = 0; i < kMaxUpdatePluginsIterations; ++i) {
    if (UpdatePlugins())
      return;
  }
}

void LocalFrameView::FlushAnyPendingPostLayoutTasks() {
  DCHECK(!IsInPerformLayout());
  if (update_plugins_timer_.IsActive()) {
    update_plugins_timer_.Stop();
    UpdatePluginsTimerFired(nullptr);
  }
}

void LocalFrameView::ScheduleUpdatePluginsIfNecessary() {
  DCHECK(!IsInPerformLayout());
  if (update_plugins_timer_.IsActive() || part_update_set_.empty())
    return;
  update_plugins_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void LocalFrameView::PerformPostLayoutTasks(bool visual_viewport_size_changed) {
  // FIXME: We can reach here, even when the page is not active!
  // http/tests/inspector/elements/html-link-import.html and many other
  // tests hit that case.
  // We should DCHECK(isActive()); or at least return early if we can!

  // Always called before or after performLayout(), part of the highest-level
  // layou
```
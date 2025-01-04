Response:
The user wants a summary of the functionality of the provided C++ code snippet from `local_frame_view.cc`. I need to identify the key actions and responsibilities of this code.

Based on the function names, it seems like this code is involved in:
- Managing the lifecycle of a frame view (layout, compositing, pre-paint, paint, accessibility).
- Handling scrolling and scroll anchoring.
- Managing paint artifacts and pushing them to the compositor.
- Updating style and layout.
- Supporting auto-sizing and pagination.
- Converting coordinates between different coordinate spaces.

I will go through each function and summarize its purpose.
这是 `blink/renderer/core/frame/local_frame_view.cc` 源代码文件的第 4 部分，主要关注以下功能：

**1. 文档生命周期管理 (Document Lifecycle Management):**

*   **`RunCompositingInputsLifecyclePhase(DocumentLifecycle::LifecycleState target_state)`:**
    *   **功能:**  执行合成输入（compositing inputs）生命周期阶段。这个阶段主要处理影响合成的输入变化，例如高亮标记、选择等。
    *   **与 JavaScript/HTML/CSS 的关系:**
        *   **JavaScript:**  JavaScript 可以通过 Selection API 修改文本选择，这会触发此阶段来更新合成。
        *   **HTML:**  HTML 元素的选择状态会影响此阶段。
        *   **CSS:**  CSS 伪类，如 `::selection`，会影响此阶段。
    *   **假设输入与输出:**
        *   **假设输入:**  用户通过鼠标或键盘选中了一段文本。
        *   **输出:**  此函数会更新与选择相关的合成层属性，以便正确渲染选中文本的高亮。
*   **`RunPrePaintLifecyclePhase(DocumentLifecycle::LifecycleState target_state)`:**
    *   **功能:** 执行预绘制（pre-paint）生命周期阶段。此阶段在实际绘制之前，用于传播需要绘制更新的标志，并执行一些预绘制的更新操作，例如更新链接高亮、检查 CSS 可见性变化等。
    *   **与 JavaScript/HTML/CSS 的关系:**
        *   **JavaScript:**  JavaScript 可以通过 DOM 操作或修改 CSS 来触发元素的显示/隐藏，从而影响预绘制阶段对 CSS 可见性的检查。
        *   **HTML:**  HTML 元素的属性变化，例如 `hidden` 属性，会影响预绘制阶段。
        *   **CSS:**  CSS 属性，如 `visibility` 和 `display`，以及 CSS 动画和过渡效果，会触发预绘制阶段的更新。
    *   **假设输入与输出:**
        *   **假设输入:**  通过 JavaScript 修改了一个元素的 `display` 属性从 `none` 变为 `block`。
        *   **输出:**  此函数会将该变化传播到父框架，并标记需要进行绘制的区域。
*   **`AnyFrameIsPrintingOrPaintingPreview()`:**
    *   **功能:**  检查是否有任何非节流的（non-throttled）框架正在打印或进行绘制预览。
    *   **与 JavaScript/HTML/CSS 的关系:**  打印和绘制预览通常由浏览器发起，但可以通过 JavaScript API（如 `window.print()`）触发。
*   **`RunPaintLifecyclePhase(PaintBenchmarkMode benchmark_mode)`:**
    *   **功能:** 执行绘制（paint）生命周期阶段。此阶段负责将渲染树绘制到屏幕或用于其他目的（例如打印）。
    *   **与 JavaScript/HTML/CSS 的关系:**
        *   **JavaScript:**  JavaScript 可以通过修改 DOM 结构或 CSS 样式来触发重绘。JavaScript 动画也会驱动绘制过程。
        *   **HTML:**  HTML 结构决定了渲染树的构建，从而影响绘制的内容。
        *   **CSS:**  CSS 样式决定了元素的视觉外观，是绘制的核心。
    *   **假设输入与输出:**
        *   **假设输入:**  CSS 动画改变了一个元素的背景颜色。
        *   **输出:**  此函数会重新绘制该元素，使其背景颜色发生变化。
*   **`RunAccessibilitySteps()`:**
    *   **功能:** 执行可访问性（accessibility）相关的步骤，例如提交 ARIA 属性更新到辅助技术。
    *   **与 JavaScript/HTML/CSS 的关系:**
        *   **JavaScript:**  JavaScript 可以动态修改 ARIA 属性，例如 `aria-label`，这会触发可访问性更新。
        *   **HTML:**  HTML 元素的 ARIA 属性直接影响可访问性树的构建。
        *   **CSS:**  CSS 的 `content` 属性在某些情况下可以用于可访问性，例如生成的内容。
    *   **假设输入与输出:**
        *   **假设输入:**  通过 JavaScript 设置了一个按钮的 `aria-label` 属性。
        *   **输出:**  此函数会将更新后的 `aria-label` 信息同步到浏览器的可访问性树。

**2. 滚动和滚动锚定 (Scrolling and Scroll Anchoring):**

*   **`EnqueueScrollAnchoringAdjustment(ScrollableArea* scrollable_area)`:**
    *   **功能:** 将一个可滚动区域加入到滚动锚定调整队列中。
*   **`DequeueScrollAnchoringAdjustment(ScrollableArea* scrollable_area)`:**
    *   **功能:** 从滚动锚定调整队列中移除一个可滚动区域。
*   **`SetNeedsEnqueueScrollEvent(PaintLayerScrollableArea* scrollable_area)`:**
    *   **功能:**  标记一个可滚动区域需要加入到滚动事件队列中。
*   **`PerformScrollAnchoringAdjustments()`:**
    *   **功能:** 执行所有待处理的滚动锚定调整。滚动锚定是一种机制，用于在内容加载或布局变化时，尽量保持用户在页面上的相对滚动位置。
    *   **与 JavaScript/HTML/CSS 的关系:**  当 JavaScript 动态添加内容或 CSS 样式导致布局变化时，滚动锚定会尝试调整滚动位置。CSS 的 `scroll-start` 属性会影响滚动锚定的行为。
    *   **假设输入与输出:**
        *   **假设输入:**  一个页面加载完成后，顶部插入了一段新的内容，导致原有内容向下移动。
        *   **输出:**  此函数会调整滚动位置，使得用户在插入内容之前的可见部分仍然可见。
*   **`EnqueueScrollEvents()`:**
    *   **功能:**  将待处理的滚动事件放入队列中。

**3. 绘制树 (Paint Tree):**

*   **`PaintTree(PaintBenchmarkMode benchmark_mode, std::optional<PaintController>& paint_controller)`:**
    *   **功能:**  执行绘制树的遍历和记录，用于生成绘制指令。
    *   **与 JavaScript/HTML/CSS 的关系:**  绘制树的构建和绘制过程直接受到 HTML 结构和 CSS 样式的影响。JavaScript 可以通过修改 DOM 和 CSS 来触发绘制树的重建和重绘。
*   **`RootCcLayer()`:**
    *   **功能:**  获取根 compositor layer。
*   **`CreatePaintTimelineEvents()`:**
    *   **功能:**  创建绘制相关的 DevTools Timeline 事件。
*   **`PushPaintArtifactToCompositor(bool repainted)`:**
    *   **功能:**  将绘制产物（paint artifact）推送到 compositor，以便进行合成和最终的屏幕渲染。
    *   **与 JavaScript/HTML/CSS 的关系:**  所有影响元素视觉呈现的 JavaScript、HTML 和 CSS 最终都会通过绘制过程转化为绘制产物，并被推送到 compositor 进行渲染。
*   **`AppendViewTransitionRequests(WTF::Vector<std::unique_ptr<ViewTransitionRequest>>& requests)`:**
    *   **功能:**  添加视图转换请求。
    *   **与 JavaScript/HTML/CSS 的关系:**  视图转换 API 允许在 DOM 更改时创建平滑的视觉过渡效果。

**4. 样式和布局更新 (Style and Layout Updates):**

*   **`UpdateStyleAndLayoutIfNeededRecursive()`:**
    *   **功能:**  递归地更新当前帧及其子帧的样式和布局，如果需要的话。
    *   **与 JavaScript/HTML/CSS 的关系:**  当 JavaScript 修改 DOM 结构或 CSS 样式时，需要调用此函数来重新计算样式和布局。HTML 结构和 CSS 样式是样式和布局计算的输入。
*   **`UpdateStyleAndLayout()`:**
    *   **功能:**  更新当前帧的样式和布局。
*   **`UpdateStyleAndLayoutInternal()`:**
    *   **功能:**  执行样式和布局更新的内部逻辑。
*   **`EnableAutoSizeMode(const gfx::Size& min_size, const gfx::Size& max_size)`:**
    *   **功能:**  启用自动调整大小模式。
    *   **与 JavaScript/HTML/CSS 的关系:**  此功能可能与 iframe 或插件的尺寸调整有关。
*   **`DisableAutoSizeMode()`:**
    *   **功能:**  禁用自动调整大小模式。
*   **`ForceLayoutForPagination(float maximum_shrink_factor)`:**
    *   **功能:**  为了分页强制进行布局。
    *   **与 JavaScript/HTML/CSS 的关系:**  用于打印或生成 PDF 等场景，需要根据页面大小进行布局。CSS 的分页相关属性（如 `break-before`，`break-after`）会影响此过程。
*   **`DestroyPaginationLayout()`:**
    *   **功能:**  销毁分页布局。

**5. 坐标转换 (Coordinate Conversion):**

*   **`RootFrameToDocument(const gfx::Rect& rect_in_root_frame)`**
*   **`RootFrameToDocument(const gfx::Point& point_in_root_frame)`**
*   **`RootFrameToDocument(const gfx::PointF& point_in_root_frame)`**
    *   **功能:** 将根框架坐标系下的坐标转换为文档坐标系下的坐标。
    *   **与 JavaScript/HTML/CSS 的关系:**  在处理鼠标事件、元素定位等场景时，需要在不同的坐标系之间进行转换。JavaScript 可以获取元素的屏幕坐标或视口坐标，这些坐标需要转换为文档坐标才能进行进一步的处理。
*   **`DocumentToFrame(const gfx::Rect& rect_in_document) const`**
*   **`DocumentToFrame(const gfx::Point& point_in_document) const`**
    *   **功能:** 将文档坐标系下的坐标转换为当前框架坐标系下的坐标。

**用户或编程常见的使用错误举例:**

*   **未正确处理异步操作导致的布局抖动:**  在 JavaScript 中连续进行多次 DOM 修改和样式更改，如果没有合理地批处理这些操作，可能导致浏览器多次进行布局和绘制，影响性能。例如，在一个循环中，每次迭代都修改元素的样式，可能会触发多次不必要的布局。
*   **过度使用 JavaScript 操作样式:**  直接通过 JavaScript 操作元素的 `style` 属性可能会绕过 CSS 的优化，导致性能问题。应该尽量使用 CSS 类来管理样式变化。
*   **错误地假设滚动位置:**  在 JavaScript 中操作滚动位置时，如果没有考虑到滚动锚定等机制，可能会导致滚动位置的意外变化。
*   **在绘制过程中修改 DOM 或样式:**  在绘制生命周期阶段执行会触发重排或重绘的操作会导致性能问题，应该避免。

**本部分功能归纳:**

这部分 `LocalFrameView` 的代码主要负责 **管理和执行渲染流程中的关键阶段，包括合成输入处理、预绘制准备、实际绘制以及可访问性更新。** 它还涉及到 **滚动相关的操作（滚动锚定和事件排队）** 以及 **绘制产物的管理和向 compositor 的推送。** 此外，还包括了 **样式和布局更新的关键步骤** 以及 **不同坐标系之间的转换**。 这些功能共同确保了 Web 内容能够被正确地渲染和呈现给用户，并保证了页面的交互性和可访问性。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_frame_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
w& frame_view) {
    frame_view.PerformScrollAnchoringAdjustments();
  });

  ExecutePendingSnapUpdates();

  // Fire scrollsnapchanging events based on the new layout if necessary.
  EnqueueScrollSnapChangingFromImplIfNecessary();

  EnqueueScrollEvents();

  frame_->GetPage()->GetValidationMessageClient().LayoutOverlay();

  if (target_state == DocumentLifecycle::kPaintClean) {
    ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
      frame_view.NotifyFrameRectsChangedIfNeeded();
    });
  }

  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    auto lifecycle_observers = frame_view.lifecycle_observers_;
    for (auto& observer : lifecycle_observers) {
      observer->DidFinishLayout();
    }
  });

  return Lifecycle().GetState() >= DocumentLifecycle::kLayoutClean;
}

bool LocalFrameView::RunCompositingInputsLifecyclePhase(
    DocumentLifecycle::LifecycleState target_state) {
  TRACE_EVENT0("blink,benchmark",
               "LocalFrameView::RunCompositingInputsLifecyclePhase");
  auto* layout_view = GetLayoutView();
  DCHECK(layout_view);

  SCOPED_UMA_AND_UKM_TIMER(GetUkmAggregator(),
                           LocalFrameUkmAggregator::kCompositingInputs);
  // TODO(pdr): This descendant dependent treewalk should be integrated into
  // the prepaint tree walk.
  {
#if DCHECK_IS_ON()
    SetIsUpdatingDescendantDependentFlags(true);
#endif
    ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
      frame_view.Lifecycle().AdvanceTo(
          DocumentLifecycle::kInCompositingInputsUpdate);

      // Validate all HighlightMarkers of all non-throttled LocalFrameViews
      // before compositing inputs phase so the nodes affected by markers
      // removed/added are invalidated (for both visual overflow and repaint)
      // and then painted during this lifecycle.
      if (LocalDOMWindow* window = frame_view.GetFrame().DomWindow()) {
        if (HighlightRegistry* highlight_registry =
                window->Supplementable<LocalDOMWindow>::RequireSupplement<
                    HighlightRegistry>()) {
          highlight_registry->ValidateHighlightMarkers();
        }
      }

      frame_view.GetLayoutView()->CommitPendingSelection();
      frame_view.GetLayoutView()->Layer()->UpdateDescendantDependentFlags();
    });
#if DCHECK_IS_ON()
    SetIsUpdatingDescendantDependentFlags(false);
#endif
  }

  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    frame_view.Lifecycle().AdvanceTo(
        DocumentLifecycle::kCompositingInputsClean);
  });

  return target_state > DocumentLifecycle::kCompositingInputsClean;
}

bool LocalFrameView::RunPrePaintLifecyclePhase(
    DocumentLifecycle::LifecycleState target_state) {
  TRACE_EVENT0("blink,benchmark", "LocalFrameView::RunPrePaintLifecyclePhase");

  ForAllNonThrottledLocalFrameViews(
      [](LocalFrameView& frame_view) {
        frame_view.Lifecycle().AdvanceTo(DocumentLifecycle::kInPrePaint);

        // Propagate dirty bits in the frame into the parent frame so that
        // pre-paint reaches into this frame.
        if (LayoutView* layout_view = frame_view.GetLayoutView()) {
          if (auto* owner = frame_view.GetFrame().OwnerLayoutObject()) {
            if (layout_view->NeedsPaintPropertyUpdate() ||
                layout_view->DescendantNeedsPaintPropertyUpdate()) {
              owner->SetDescendantNeedsPaintPropertyUpdate();
            }
            if (layout_view->ShouldCheckForPaintInvalidation()) {
              owner->SetShouldCheckForPaintInvalidation();
            }
            if (layout_view->EffectiveAllowedTouchActionChanged() ||
                layout_view->DescendantEffectiveAllowedTouchActionChanged()) {
              owner->MarkDescendantEffectiveAllowedTouchActionChanged();
            }
            if (layout_view->BlockingWheelEventHandlerChanged() ||
                layout_view->DescendantBlockingWheelEventHandlerChanged()) {
              owner->MarkDescendantBlockingWheelEventHandlerChanged();
            }
          }
        }
      },
      // Use post-order to ensure correct flag propagation for nested frames.
      kPostOrder);

  {
    SCOPED_UMA_AND_UKM_TIMER(GetUkmAggregator(),
                             LocalFrameUkmAggregator::kPrePaint);

    GetPage()->GetLinkHighlight().UpdateBeforePrePaint();
    PrePaintTreeWalk().WalkTree(*this);
    GetPage()->GetLinkHighlight().UpdateAfterPrePaint();

    frame_->GetPage()->GetValidationMessageClient().UpdatePrePaint();
    ForAllNonThrottledLocalFrameViews([](LocalFrameView& view) {
      view.frame_->UpdateFrameColorOverlayPrePaint();
      view.frame_->CheckPositionAnchorsForCssVisibilityChanges();
    });
    if (auto* web_local_frame_impl = WebLocalFrameImpl::FromFrame(frame_))
      web_local_frame_impl->UpdateDevToolsOverlaysPrePaint();
  }

  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    frame_view.Lifecycle().AdvanceTo(DocumentLifecycle::kPrePaintClean);
  });

  return target_state > DocumentLifecycle::kPrePaintClean;
}

bool LocalFrameView::AnyFrameIsPrintingOrPaintingPreview() {
  bool any_frame_is_printing_or_painting_preview = false;
  ForAllNonThrottledLocalFrameViews(
      [&any_frame_is_printing_or_painting_preview](LocalFrameView& frame_view) {
        if (frame_view.GetFrame().GetDocument()->IsPrintingOrPaintingPreview())
          any_frame_is_printing_or_painting_preview = true;
      });
  return any_frame_is_printing_or_painting_preview;
}

void LocalFrameView::RunPaintLifecyclePhase(PaintBenchmarkMode benchmark_mode) {
  DCHECK(ScriptForbiddenScope::WillBeScriptForbidden());
  DCHECK(LocalFrameTreeAllowsThrottling());
  TRACE_EVENT0("blink,benchmark", "LocalFrameView::RunPaintLifecyclePhase");
  // While printing or capturing a paint preview of a document, the paint walk
  // is done into a special canvas. There is no point doing a normal paint step
  // (or animations update) when in this mode.
  if (AnyFrameIsPrintingOrPaintingPreview())
    return;

  bool needed_update;
  {
    // paint_controller will be constructed when PaintTree repaints, and will
    // be destructed after PushPaintArtifactToCompositor.
    std::optional<PaintController> paint_controller;
    PaintTree(benchmark_mode, paint_controller);

    if (paint_artifact_compositor_ &&
        benchmark_mode ==
            PaintBenchmarkMode::kForcePaintArtifactCompositorUpdate) {
      paint_artifact_compositor_->SetNeedsUpdate();
    }
    needed_update = !paint_artifact_compositor_ ||
                    paint_artifact_compositor_->NeedsUpdate();
    PushPaintArtifactToCompositor(paint_controller.has_value());
  }

  size_t total_animations_count = 0;
  ForAllNonThrottledLocalFrameViews(
      [this, needed_update,
       &total_animations_count](LocalFrameView& frame_view) {
        if (auto* scrollable_area = frame_view.GetScrollableArea())
          scrollable_area->UpdateCompositorScrollAnimations();
        if (const auto* animating_scrollable_areas =
                frame_view.AnimatingScrollableAreas()) {
          for (PaintLayerScrollableArea* area : *animating_scrollable_areas)
            area->UpdateCompositorScrollAnimations();
        }
        frame_view.GetPage()->GetLinkHighlight().UpdateAfterPaint(
            paint_artifact_compositor_.Get());
        Document& document = frame_view.GetLayoutView()->GetDocument();
        // Attach the compositor timeline during the commit as it blocks on
        // the previous commit completion.
        document.AttachCompositorTimeline(
            document.Timeline().CompositorTimeline());
        {
          // Updating animations can notify ready promises which could mutate
          // the DOM. We should delay these until we have finished the lifecycle
          // update. https://crbug.com/1196781
          ScriptForbiddenScope forbid_script;
          document.GetDocumentAnimations().UpdateAnimations(
              DocumentLifecycle::kPaintClean, paint_artifact_compositor_.Get(),
              needed_update);
        }
        total_animations_count +=
            document.GetDocumentAnimations().GetAnimationsCount();
      });

  // If this is a throttled local root, then we shouldn't run animation steps
  // below, because the cc animation data structures might not even exist.
  if (frame_->IsLocalRoot() && ShouldThrottleRendering())
    return;

  if (auto* animation_host = GetCompositorAnimationHost()) {
    animation_host->SetAnimationCounts(total_animations_count);
  }

  // Initialize animation properties in the newly created paint property
  // nodes according to the current animation state. This is mainly for
  // the running composited animations which didn't change state during
  // above UpdateAnimations() but associated with new paint property nodes.
  if (needed_update) {
    auto* root_layer = RootCcLayer();
    if (root_layer && root_layer->layer_tree_host()) {
      root_layer->layer_tree_host()->mutator_host()->InitClientAnimationState();
    }
  }

  if (GetPage())
    GetPage()->Animator().ReportFrameAnimations(GetCompositorAnimationHost());
}

void LocalFrameView::RunAccessibilitySteps() {
  TRACE_EVENT0("blink,benchmark", "LocalFrameView::RunAccessibilitySteps");

  SCOPED_UMA_AND_UKM_TIMER(GetUkmAggregator(),
                           LocalFrameUkmAggregator::kAccessibility);

  // Reduce redundant ancestor chain walking for display lock computations.
  auto display_lock_memoization_scope =
      DisplayLockUtilities::CreateLockCheckMemoizationScope();

  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    if (AXObjectCache* cache = frame_view.ExistingAXObjectCache()) {
      cache->CommitAXUpdates(*frame_view.GetFrame().GetDocument(),
                             /*force=*/false);
    }
  });
}

void LocalFrameView::EnqueueScrollAnchoringAdjustment(
    ScrollableArea* scrollable_area) {
  anchoring_adjustment_queue_.insert(scrollable_area);
}

void LocalFrameView::DequeueScrollAnchoringAdjustment(
    ScrollableArea* scrollable_area) {
  anchoring_adjustment_queue_.erase(scrollable_area);
}

void LocalFrameView::SetNeedsEnqueueScrollEvent(
    PaintLayerScrollableArea* scrollable_area) {
  scroll_event_queue_.insert(scrollable_area);
  GetPage()->Animator().ScheduleVisualUpdate(frame_.Get());
}

void LocalFrameView::PerformScrollAnchoringAdjustments() {
  // Adjust() will cause a scroll which could end up causing a layout and
  // reentering this method. Copy and clear the queue so we don't modify it
  // during iteration.
  AnchoringAdjustmentQueue queue_copy = anchoring_adjustment_queue_;
  anchoring_adjustment_queue_.clear();

  for (const WeakMember<ScrollableArea>& scroller : queue_copy) {
    if (scroller) {
      DCHECK(scroller->GetScrollAnchor());
      // The CSS scroll-start property should take precedence over scroll
      // anchoring.
      if (scroller->IsApplyingScrollStart()) {
        scroller->GetScrollAnchor()->CancelAdjustment();
        continue;
      }
      scroller->GetScrollAnchor()->Adjust();
    }
  }
}

void LocalFrameView::EnqueueScrollEvents() {
  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    for (const WeakMember<PaintLayerScrollableArea>& scroller :
         frame_view.scroll_event_queue_) {
      if (scroller)
        scroller->EnqueueScrollEventIfNeeded();
    }
    frame_view.scroll_event_queue_.clear();
  });
}

void LocalFrameView::PaintTree(
    PaintBenchmarkMode benchmark_mode,
    std::optional<PaintController>& paint_controller) {
  SCOPED_UMA_AND_UKM_TIMER(GetUkmAggregator(), LocalFrameUkmAggregator::kPaint);

  DCHECK(GetFrame().IsLocalRoot());

  std::optional<MobileFriendlinessChecker::PaintScope> mf_scope;
  if (mobile_friendliness_checker_)
    mf_scope.emplace(*mobile_friendliness_checker_);

  auto* layout_view = GetLayoutView();
  DCHECK(layout_view);

  CullRectUpdater(*layout_view->Layer()).Update();

  bool debug_info_newly_enabled =
      UpdatePaintDebugInfoEnabled() && PaintDebugInfoEnabled();

  paint_frame_count_++;
  ForAllNonThrottledLocalFrameViews(
      [debug_info_newly_enabled](LocalFrameView& frame_view) {
        frame_view.MarkFirstEligibleToPaint();
        frame_view.Lifecycle().AdvanceTo(DocumentLifecycle::kInPaint);
        // Propagate child frame PaintLayer NeedsRepaint flag into the owner
        // frame.
        if (auto* frame_layout_view = frame_view.GetLayoutView()) {
          if (auto* owner = frame_view.GetFrame().OwnerLayoutObject()) {
            PaintLayer* frame_root_layer = frame_layout_view->Layer();
            DCHECK(frame_root_layer);
            DCHECK(owner->Layer());
            if (frame_root_layer->SelfOrDescendantNeedsRepaint())
              owner->Layer()->SetDescendantNeedsRepaint();
          }
          // If debug info was just enabled, then the paint cache won't have any
          // debug info; we need to force a full repaint to generate it.
          if (debug_info_newly_enabled)
            frame_layout_view->InvalidatePaintForViewAndDescendants();
        }
      },
      // Use post-order to ensure correct flag propagation for nested frames.
      kPostOrder);

  ForAllThrottledLocalFrameViews(
      [](LocalFrameView& frame_view) { frame_view.MarkIneligibleToPaint(); });

  bool needs_clear_repaint_flags = false;

  if (benchmark_mode >= PaintBenchmarkMode::kForcePaint ||
      !paint_controller_persistent_data_ ||
      GetLayoutView()->Layer()->SelfOrDescendantNeedsRepaint() ||
      visual_viewport_or_overlay_needs_repaint_) {
    const PaintArtifact& previous_artifact =
        EnsurePaintControllerPersistentData().GetPaintArtifact();
    paint_controller.emplace(PaintDebugInfoEnabled(),
                             paint_controller_persistent_data_.Get(),
                             benchmark_mode);
    GraphicsContext graphics_context(*paint_controller);

    // Draw the WebXR DOM overlay if present.
    if (PaintLayer* full_screen_layer = GetXROverlayLayer()) {
      PaintLayerPainter(*full_screen_layer).Paint(graphics_context);
    } else {
      PaintFrame(graphics_context);

      GetPage()->GetValidationMessageClient().PaintOverlay(graphics_context);
      ForAllNonThrottledLocalFrameViews(
          [&graphics_context](LocalFrameView& view) {
            view.frame_->PaintFrameColorOverlay(graphics_context);
          });

      // Devtools overlays query the inspected page's paint data so this
      // update needs to be after other paintings.
      if (auto* web_local_frame_impl = WebLocalFrameImpl::FromFrame(frame_))
        web_local_frame_impl->PaintDevToolsOverlays(graphics_context);

      if (frame_->IsMainFrame())
        GetPage()->GetVisualViewport().Paint(graphics_context);
    }

    // Link highlights paint after all other paintings.
    GetPage()->GetLinkHighlight().Paint(graphics_context);

    paint_controller->CommitNewDisplayItems();

    needs_clear_repaint_flags = true;
    if (paint_artifact_compositor_) {
      paint_artifact_compositor_->SetNeedsFullUpdateAfterPaintIfNeeded(
          previous_artifact,
          paint_controller_persistent_data_->GetPaintArtifact());
    }
  }

  visual_viewport_or_overlay_needs_repaint_ = false;

  ForAllNonThrottledLocalFrameViews(
      [needs_clear_repaint_flags](LocalFrameView& frame_view) {
        frame_view.Lifecycle().AdvanceTo(DocumentLifecycle::kPaintClean);
        if (needs_clear_repaint_flags) {
          if (auto* layout_view = frame_view.GetLayoutView())
            layout_view->Layer()->ClearNeedsRepaintRecursively();
        }
        frame_view.GetPaintTimingDetector().NotifyPaintFinished();
      });
}

cc::Layer* LocalFrameView::RootCcLayer() {
  return paint_artifact_compositor_ ? paint_artifact_compositor_->RootLayer()
                                    : nullptr;
}

const cc::Layer* LocalFrameView::RootCcLayer() const {
  return const_cast<LocalFrameView*>(this)->RootCcLayer();
}

void LocalFrameView::CreatePaintTimelineEvents() {
  if (const cc::Layer* root_layer = paint_artifact_compositor_->RootLayer()) {
    for (const auto& layer : root_layer->children()) {
      if (!layer->update_rect().IsEmpty()) {
        DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT_WITH_CATEGORIES(
            "devtools.timeline,rail", "Paint", inspector_paint_event::Data,
            &GetFrame(), /*layout_object=*/nullptr,
            GetQuadForTimelinePaintEvent(layer), layer->id());
      }
    }
  }
}

void LocalFrameView::PushPaintArtifactToCompositor(bool repainted) {
  TRACE_EVENT0("blink", "LocalFrameView::pushPaintArtifactToCompositor");
  if (!frame_->GetSettings()->GetAcceleratedCompositingEnabled()) {
    if (paint_artifact_compositor_) {
      paint_artifact_compositor_->WillBeRemovedFromFrame();
      paint_artifact_compositor_ = nullptr;
    }
    return;
  }

  Page* page = GetFrame().GetPage();
  if (!page)
    return;

  if (!paint_artifact_compositor_) {
    paint_artifact_compositor_ = MakeGarbageCollected<PaintArtifactCompositor>(
        page->GetScrollingCoordinator()->GetScrollCallbacks());
    page->GetChromeClient().AttachRootLayer(
        paint_artifact_compositor_->RootLayer(), &GetFrame());
  }

  paint_artifact_compositor_->SetLCDTextPreference(
      page->GetSettings().GetLCDTextPreference());

  SCOPED_UMA_AND_UKM_TIMER(GetUkmAggregator(),
                           LocalFrameUkmAggregator::kCompositingCommit);
  DEVTOOLS_TIMELINE_TRACE_EVENT("Layerize", inspector_layerize_event::Data,
                                frame_.Get());

  // Skip updating property trees, pushing cc::Layers, and issuing raster
  // invalidations if possible.
  if (!paint_artifact_compositor_->NeedsUpdate()) {
    if (repainted) {
      paint_artifact_compositor_->UpdateRepaintedLayers(
          paint_controller_persistent_data_->GetPaintArtifact());
      CreatePaintTimelineEvents();
    }
    // TODO(pdr): Should we clear the property tree state change bits (
    // |PaintArtifactCompositor::ClearPropertyTreeChangedState|)?
    return;
  }

  paint_artifact_compositor_->SetLayerDebugInfoEnabled(
      paint_debug_info_enabled_);

  PaintArtifactCompositor::ViewportProperties viewport_properties;
  if (const auto& viewport = page->GetVisualViewport();
      GetFrame().IsMainFrame() && viewport.IsActiveViewport()) {
    viewport_properties.overscroll_elasticity_transform =
        viewport.GetOverscrollElasticityTransformNode();
    viewport_properties.page_scale = viewport.GetPageScaleNode();

    if (const auto* root_scroller =
            GetPage()->GlobalRootScrollerController().GlobalRootScroller()) {
      if (const auto* layout_object = root_scroller->GetLayoutObject()) {
        if (const auto* paint_properties =
                layout_object->FirstFragment().PaintProperties()) {
          if (paint_properties->Scroll()) {
            viewport_properties.outer_clip = paint_properties->OverflowClip();
            viewport_properties.outer_scroll_translation =
                paint_properties->ScrollTranslation();
            viewport_properties.inner_scroll_translation =
                viewport.GetScrollTranslationNode();
          }
        }
      }
    }
  }

  PaintArtifactCompositor::StackScrollTranslationVector
      scroll_translation_nodes;
  ForAllNonThrottledLocalFrameViews(
      [&scroll_translation_nodes](LocalFrameView& frame_view) {
        for (const auto& area : frame_view.ScrollableAreas().Values()) {
          const auto* paint_properties =
              area->GetLayoutBox()->FirstFragment().PaintProperties();
          if (paint_properties && paint_properties->Scroll()) {
            scroll_translation_nodes.push_back(
                paint_properties->ScrollTranslation());
          }
        }
      });

  WTF::Vector<std::unique_ptr<ViewTransitionRequest>> view_transition_requests;
  AppendViewTransitionRequests(view_transition_requests);

  paint_artifact_compositor_->Update(
      paint_controller_persistent_data_->GetPaintArtifact(),
      viewport_properties, scroll_translation_nodes,
      std::move(view_transition_requests));

  CreatePaintTimelineEvents();
}

void LocalFrameView::AppendViewTransitionRequests(
    WTF::Vector<std::unique_ptr<ViewTransitionRequest>>& requests) {
  DCHECK(frame_ && frame_->GetDocument());
  DCHECK(frame_->IsLocalRoot());

  ForAllNonThrottledLocalFrameViews([&requests](LocalFrameView& frame_view) {
    if (!frame_view.GetFrame().GetDocument())
      return;

    auto pending_requests = ViewTransitionUtils::GetPendingRequests(
        *frame_view.GetFrame().GetDocument());
    for (auto& pending_request : pending_requests)
      requests.push_back(std::move(pending_request));
  });
}

std::unique_ptr<JSONObject> LocalFrameView::CompositedLayersAsJSON(
    LayerTreeFlags flags) {
  auto* root_frame_view = GetFrame().LocalFrameRoot().View();
  if (root_frame_view->paint_artifact_compositor_)
    return root_frame_view->paint_artifact_compositor_->GetLayersAsJSON(flags);
  return std::make_unique<JSONObject>();
}

void LocalFrameView::UpdateStyleAndLayoutIfNeededRecursive() {
  if (ShouldThrottleRendering() || !frame_->GetDocument()->IsActive())
    return;

  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
               "LocalFrameView::updateStyleAndLayoutIfNeededRecursive");

  UpdateStyleAndLayout();

  // WebView plugins need to update regardless of whether the
  // LayoutEmbeddedObject that owns them needed layout.
  // TODO(rendering-core) This currently runs the entire lifecycle on plugin
  // WebViews. We should have a way to only run these other Documents to the
  // same lifecycle stage as this frame.
  for (const auto& plugin : plugins_) {
    plugin->UpdateAllLifecyclePhases();
  }
  CheckDoesNotNeedLayout();

  // FIXME: Calling layout() shouldn't trigger script execution or have any
  // observable effects on the frame tree but we're not quite there yet.
  HeapVector<Member<LocalFrameView>> frame_views;
  for (Frame* child = frame_->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    auto* child_local_frame = DynamicTo<LocalFrame>(child);
    if (!child_local_frame)
      continue;
    if (LocalFrameView* view = child_local_frame->View())
      frame_views.push_back(view);
  }

  for (const auto& frame_view : frame_views)
    frame_view->UpdateStyleAndLayoutIfNeededRecursive();

  // These asserts ensure that parent frames are clean, when child frames
  // finished updating layout and style.
  // TODO(szager): this is the last call to CheckDoesNotNeedLayout during the
  // lifecycle code, but it can happen that NeedsLayout() becomes true after
  // this point, even while the document lifecycle proceeds to kLayoutClean
  // and beyond. Figure out how this happens, and do something sensible.
  CheckDoesNotNeedLayout();
#if DCHECK_IS_ON()
  frame_->GetDocument()->GetLayoutView()->AssertLaidOut();
  frame_->GetDocument()->GetLayoutView()->AssertFragmentTree();
#endif

  if (Lifecycle().GetState() < DocumentLifecycle::kLayoutClean)
    Lifecycle().AdvanceTo(DocumentLifecycle::kLayoutClean);

  // If we're restoring a scroll position from history, that takes precedence
  // over scrolling to the anchor in the URL.
  frame_->GetDocument()->ApplyScrollRestorationLogic();

  // Ensure that we become visually non-empty eventually.
  // TODO(esprehn): This should check isRenderingReady() instead.
  if (GetFrame().GetDocument()->HasFinishedParsing() &&
      !GetFrame().GetDocument()->IsInitialEmptyDocument())
    is_visually_non_empty_ = true;

  GetFrame().Selection().UpdateStyleAndLayoutIfNeeded();
  GetFrame().GetPage()->GetDragCaret().UpdateStyleAndLayoutIfNeeded();
}

void LocalFrameView::UpdateStyleAndLayout() {
#if DCHECK_IS_ON()
  DCHECK(!is_updating_layout_);
  base::AutoReset<bool> is_updating_layout(&is_updating_layout_, true);
#endif
  TRACE_EVENT("blink", "LocalFrameView::UpdateStyleAndLayout");

  if (IsInPerformLayout() || ShouldThrottleRendering() ||
      !frame_->GetDocument()->IsActive() || frame_->IsProvisional() ||
      Lifecycle().LifecyclePostponed()) {
    return;
  }

  gfx::Size visual_viewport_size =
      GetScrollableArea()->VisibleContentRect().size();

  bool did_layout = false;
  {
    // Script is allowed during the initial style and layout as we will rerun
    // at least once more if anything was invalidated.
    ScriptForbiddenScope::AllowUserAgentScript allow_script;
    did_layout = UpdateStyleAndLayoutInternal();
  }

  // Update counters after layout since counters may be added during layout for
  // generated ::scroll-markers.
  frame_->GetDocument()->GetStyleEngine().UpdateCounters();

  // Second pass: run autosize until it stabilizes
  if (auto_size_info_) {
    while (auto_size_info_->AutoSizeIfNeeded())
      did_layout |= UpdateStyleAndLayoutInternal();
    auto_size_info_->Clear();
  }

  // Third pass: if layout hasn't stabilized, don't update layout viewport size
  // based on content size.
  if (NeedsLayout()) {
    base::AutoReset<bool> suppress(&suppress_adjust_view_size_, true);
    did_layout |= UpdateStyleAndLayoutInternal();
  }

#if DCHECK_IS_ON()
  if (!Lifecycle().LifecyclePostponed() && !ShouldThrottleRendering()) {
    DCHECK(!frame_->GetDocument()->NeedsLayoutTreeUpdate());
    CheckDoesNotNeedLayout();
    DCHECK(layout_subtree_root_list_.IsEmpty());
    if (did_layout)
      GetLayoutView()->AssertSubtreeIsLaidOut();
  }
#endif

  // Once all of the layout is finished, update the focused element. This
  // shouldn't be done before since focusability check sometimes requires an
  // layout update, which would recurse into this function. This update is only
  // required if we still need layout though, which should be cleared already.
  frame_->GetDocument()->ClearFocusedElementIfNeeded();

  if (did_layout) {
    gfx::Size new_visual_viewport_size =
        GetScrollableArea()->VisibleContentRect().size();
    bool visual_viewport_size_changed =
        (new_visual_viewport_size != visual_viewport_size);
    SetNeedsUpdateGeometries();
    PerformPostLayoutTasks(visual_viewport_size_changed);
    GetFrame().GetDocument()->LayoutUpdated();
  }
  UpdateGeometriesIfNeeded();
}

bool LocalFrameView::UpdateStyleAndLayoutInternal() {
  PostStyleUpdateScope post_style_update_scope(*frame_->GetDocument());

  bool layout_updated = false;

  do {
    {
      frame_->GetDocument()->UpdateStyleAndLayoutTreeForThisDocument();

      // Update style for all embedded SVG documents underneath this frame, so
      // that intrinsic size computation for any embedded objects has up-to-date
      // information before layout.
      ForAllChildLocalFrameViews([](LocalFrameView& view) {
        Document& document = *view.GetFrame().GetDocument();
        if (document.IsSVGDocument()) {
          document.UpdateStyleAndLayoutTreeForThisDocument();
        }
      });
    }

    UpdateCanCompositeBackgroundAttachmentFixed();

    if (NeedsLayout()) {
      SCOPED_UMA_AND_UKM_TIMER(GetUkmAggregator(),
                               LocalFrameUkmAggregator::kLayout);
      UpdateLayout();
      layout_updated = true;
    }
  } while (post_style_update_scope.Apply());

  return layout_updated;
}

void LocalFrameView::EnableAutoSizeMode(const gfx::Size& min_size,
                                        const gfx::Size& max_size) {
  if (!auto_size_info_)
    auto_size_info_ = MakeGarbageCollected<FrameViewAutoSizeInfo>(this);

  auto_size_info_->ConfigureAutoSizeMode(min_size, max_size);
  SetLayoutSizeFixedToFrameSize(true);
  SetNeedsLayout();
  ScheduleRelayout();
}

void LocalFrameView::DisableAutoSizeMode() {
  if (!auto_size_info_)
    return;

  SetLayoutSizeFixedToFrameSize(false);
  SetNeedsLayout();
  ScheduleRelayout();

  // Since autosize mode forces the scrollbar mode, change them to being auto.
  GetLayoutView()->SetAutosizeScrollbarModes(
      mojom::blink::ScrollbarMode::kAuto, mojom::blink::ScrollbarMode::kAuto);
  auto_size_info_.Clear();
}

void LocalFrameView::ForceLayoutForPagination(float maximum_shrink_factor) {
  pagination_state_ = MakeGarbageCollected<PaginationState>();

  LayoutView* layout_view = GetLayoutView();
  if (!layout_view) {
    return;
  }

  Document& document = *frame_->GetDocument();
  auto LayoutForPrinting = [&layout_view, &document]() {
    document.GetStyleEngine().UpdateViewportSize();
    document.MarkViewportUnitsDirty();
    layout_view->SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
        layout_invalidation_reason::kPrintingChanged);
    document.UpdateStyleAndLayout(DocumentUpdateReason::kPrinting);
  };

  // Need to update computed style before we can set the initial containing
  // block size. A zoom factor may have been set, and it shouldn't be applied
  // when printing, e.g. when resolving @page margins.
  document.UpdateStyleAndLayoutTree();

  // Set up the initial containing block size for pagination. This is defined as
  // the page area size of the *first* page. [1] The size of the first page may
  // not be fully known yet, e.g. if the first page is named [2] and given a
  // specific size. Page names are resolved during layout. For now, set an
  // initial containing block size based on the information that's currently
  // available. If this turns out to be wrong, we need to set a new size and lay
  // out again. See below.
  //
  // [1] https://www.w3.org/TR/css-page-3/#page-model
  // [2] https://www.w3.org/TR/css-page-3/#using-named-pages
  PhysicalSize initial_containing_block_size =
      CalculateInitialContainingBlockSizeForPagination(document);
  layout_view->SetInitialContainingBlockSizeForPrinting(
      initial_containing_block_size);

  LayoutForPrinting();

  PhysicalSize new_initial_containing_block_size =
      CalculateInitialContainingBlockSizeForPagination(document);
  if (new_initial_containing_block_size != initial_containing_block_size) {
    // If the first page was named (this isn't something we can detect without
    // laying out first), and the size of the first page is different from what
    // we got above, the initial containing block used was wrong (which affects
    // e.g. elements with viewport units). Set a new size and lay out again.
    layout_view->SetInitialContainingBlockSizeForPrinting(
        new_initial_containing_block_size);

    LayoutForPrinting();
  }

  // If we don't fit in the given page width, we'll lay out again. If we don't
  // fit in the page width when shrunk, we will lay out at maximum shrink and
  // clip extra content.
  // FIXME: We are assuming a shrink-to-fit printing implementation. A cropping
  // implementation should not do this!
  float overall_scale_factor =
      CalculateOverflowShrinkForPrinting(*layout_view, maximum_shrink_factor);

  if (overall_scale_factor > 1.0) {
    // Re-layout and apply the same scale factor to all pages.
    // PaginationScaleFactor() has already been set to honor any scale factor
    // from print settings. That has to be included as well.
    layout_view->SetPaginationScaleFactor(layout_view->PaginationScaleFactor() *
                                          overall_scale_factor);
    PhysicalSize new_size =
        CalculateInitialContainingBlockSizeForPagination(document);
    layout_view->SetInitialContainingBlockSizeForPrinting(new_size);
    LayoutForPrinting();
  }

  if (TextAutosizer* text_autosizer = document.GetTextAutosizer()) {
    text_autosizer->UpdatePageInfo();
  }
  AdjustViewSize();
  UpdateStyleAndLayout();
}

void LocalFrameView::DestroyPaginationLayout() {
  if (!pagination_state_) {
    return;
  }
  pagination_state_->DestroyAnonymousPageLayoutObjects();
  pagination_state_ = nullptr;
}

gfx::Rect LocalFrameView::RootFrameToDocument(
    const gfx::Rect& rect_in_root_frame) {
  gfx::Point offset = RootFrameToDocument(rect_in_root_frame.origin());
  gfx::Rect local_rect = rect_in_root_frame;
  local_rect.set_origin(offset);
  return local_rect;
}

gfx::Point LocalFrameView::RootFrameToDocument(
    const gfx::Point& point_in_root_frame) {
  return gfx::ToFlooredPoint(
      RootFrameToDocument(gfx::PointF(point_in_root_frame)));
}

gfx::PointF LocalFrameView::RootFrameToDocument(
    const gfx::PointF& point_in_root_frame) {
  ScrollableArea* layout_viewport = LayoutViewport();
  if (!layout_viewport)
    return point_in_root_frame;

  gfx::PointF local_frame = ConvertFromRootFrame(point_in_root_frame);
  return local_frame + layout_viewport->GetScrollOffset();
}

gfx::Rect LocalFrameView::DocumentToFrame(
    const gfx::Rect& rect_in_document) const {
  gfx::Rect rect_in_frame = rect_in_document;
  rect_in_frame.set_origin(DocumentToFrame(rect_in_document.origin()));
  return rect_in_frame;
}

gfx::Point LocalFrameView::DocumentToFrame(
   
"""


```
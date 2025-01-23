Response:
The user wants me to analyze the provided C++ code snippet from Chromium's Blink rendering engine. This is part 2 of a 5-part code analysis task. I need to:

1. **Summarize the functionality** of the code.
2. **Explain its relation to Javascript, HTML, and CSS**, providing examples.
3. **Illustrate logical reasoning** with hypothetical inputs and outputs.
4. **Give examples of common user/programming errors.**
5. **Describe how a user's actions can lead to this code being executed** as a debugging guide.

Based on the code, the `PaintLayerScrollableArea` class seems to be responsible for managing scrollable areas within a paint layer. It handles things like:

*   Determining if scrollbars should be visible.
*   Updating scrollbar properties (position, size, enabled state).
*   Handling programmatic scrolling and user input scrolling.
*   Interacting with the layout of the associated `LayoutBox`.
*   Dealing with scroll anchoring and scroll start behavior.
*   Managing the visual aspects of scrolling, such as updating paint properties.

I'll go through the code section by section to solidify my understanding and address each of the user's requests.
```
功能归纳:

PaintLayerScrollableArea 类是 Chromium Blink 引擎中负责管理可滚动区域绘制的组件。这部分代码主要关注以下功能：

1. **更新和管理滚动条的状态和属性:**
   - 检查滚动条是否可以激活 (`ScrollbarsCanBeActive`)。
   - 判断是否允许用户通过交互进行滚动 (`UserInputScrollable`)。
   - 决定垂直滚动条应该放置在左侧还是右侧 (`ShouldPlaceVerticalScrollbarOnLeft`)。
   - 计算页面步进值 (`PageStep`)，用于按页滚动。
   - 更新滚动原点 (`UpdateScrollOrigin`) 和滚动尺寸 (`UpdateScrollDimensions`)。
   - 更新滚动条的启用状态 (`UpdateScrollbarEnabledState`) 和比例 (`UpdateScrollbarProportions`)。
   - 在布局后更新滚动区域，包括可能的滚动条重建、尺寸更新、启用状态更新等 (`UpdateAfterLayout`)。
   - 判断是否需要重建滚动条 (`NeedsScrollbarReconstruction`)。

2. **处理动画相关的注册和注销:**
   - 注册可滚动区域以进行动画 (`RegisterForAnimation`)。
   - 注销可滚动区域的动画 (`DeregisterForAnimation`)。

3. **处理滚动偏移:**
   - 无条件地设置滚动偏移 (`SetScrollOffsetUnconditionally`)。
   - 在溢出改变后进行延迟或立即的滚动偏移校正 (`DelayableClampScrollOffsetAfterOverflowChange`, `ClampScrollOffsetAfterOverflowChange`, `ClampScrollOffsetAfterOverflowChangeInternal`)。

4. **与布局和绘制相关联:**
   - 获取关联的 `LayoutBox` 和 `PaintLayer` (`GetLayoutBox`, `Layer`)。
   - 判断是否是根布局视口 (`IsRootFrameLayoutViewport`)。
   - 获取可滚动区域的大小 (`Size`)、滚动宽度 (`ScrollWidth`) 和滚动高度 (`ScrollHeight`)。
   - 设置是否需要检查绘制失效 (`SetShouldCheckForPaintInvalidation`)。

5. **处理滚动锚定和滚动起始位置:**
   - 判断是否正在应用滚动起始位置 (`IsApplyingScrollStart`)。
   - 停止应用滚动起始位置 (`StopApplyingScrollStart`)。
   - 获取用于滚动起始位置的元素 (`GetElementForScrollStart`)。

6. **处理全局根滚动器变化:**
   - 当成为全局根滚动器时进行相应的更新 (`DidChangeGlobalRootScroller`)。

7. **处理滚动锚定:**
   - 判断是否应该执行滚动锚定 (`ShouldPerformScrollAnchoring`)。
   - 恢复滚动锚点 (`RestoreScrollAnchor`)。

8. **坐标映射:**
   - 将局部坐标转换为可见内容坐标 (`LocalToVisibleContentQuad`)。

9. **获取任务运行器:**
   - 获取定时器任务运行器 (`GetTimerTaskRunner`)。

10. **处理滚动行为和配色方案:**
    - 获取滚动行为样式 (`ScrollBehaviorStyle`)。
    - 获取用于滚动条的配色方案 (`UsedColorSchemeScrollbars`)。
    - 判断用于滚动条的配色方案是否已更改 (`UsedColorSchemeScrollbarsChanged`)。
    - 判断是否是全局根非覆盖滚动器 (`IsGlobalRootNonOverlayScroller`)。

11. **判断是否存在溢出:**
    - 判断是否存在水平溢出 (`HasHorizontalOverflow`)。
    - 判断是否存在垂直溢出 (`HasVerticalOverflow`)。

12. **处理样式改变后的更新:**
    - 在样式更改后进行更新 (`UpdateAfterStyleChange`)。

13. **处理溢出重新计算后的更新:**
    - 在溢出重新计算后进行更新 (`UpdateAfterOverflowRecalc`)。

14. **计算滚动条的矩形区域和起始位置:**
    - 获取水平滚动条的矩形区域 (`RectForHorizontalScrollbar`)。
    - 获取垂直滚动条的矩形区域 (`RectForVerticalScrollbar`)。
    - 获取垂直滚动条的起始位置 (`VerticalScrollbarStart`)。
    - 获取水平滚动条的起始位置 (`HorizontalScrollbarStart`)。
    - 获取滚动条的偏移量 (`ScrollbarOffset`)。

15. **计算假设的滚动条厚度:**
    - 获取假设的滚动条厚度 (`HypotheticalScrollbarThickness`)。
    - 判断是否需要计算假设的滚动条厚度 (`NeedsHypotheticalScrollbarThickness`)。
    - 计算假设的滚动条厚度 (`ComputeHypotheticalScrollbarThickness`)。

总而言之，这部分代码主要负责 `PaintLayerScrollableArea` 对象的内部状态管理、滚动条的视觉呈现和行为控制，以及与布局和绘制过程的协同工作。
```
### 提示词
```
这是目录为blink/renderer/core/paint/paint_layer_scrollable_area.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
t crash.
    GetLayoutBox()
        ->GetMutableForPainting()
        .SetOnlyThisNeedsPaintPropertyUpdate();
    return;
  }

  GetLayoutBox()->SetNeedsPaintPropertyUpdate();
}

bool PaintLayerScrollableArea::ScrollbarsCanBeActive() const {
  LayoutView* view = GetLayoutBox()->View();
  if (!view)
    return false;

  // TODO(szager): This conditional is weird and likely obsolete. Originally
  // added in commit eb0d49caaee2b275ff524d3945a74e8d9180eb7d.
  LocalFrameView* frame_view = view->GetFrameView();
  if (frame_view != frame_view->GetFrame().View())
    return false;

  return !!frame_view->GetFrame().GetDocument();
}

void PaintLayerScrollableArea::RegisterForAnimation() {
  if (HasBeenDisposed())
    return;
  if (LocalFrame* frame = GetLayoutBox()->GetFrame()) {
    if (LocalFrameView* frame_view = frame->View())
      frame_view->AddAnimatingScrollableArea(this);
  }
}

void PaintLayerScrollableArea::DeregisterForAnimation() {
  if (HasBeenDisposed())
    return;
  if (LocalFrame* frame = GetLayoutBox()->GetFrame()) {
    if (LocalFrameView* frame_view = frame->View())
      frame_view->RemoveAnimatingScrollableArea(this);
  }
}

bool PaintLayerScrollableArea::UserInputScrollable(
    ScrollbarOrientation orientation) const {
  if (orientation == kVerticalScrollbar &&
      GetLayoutBox()->GetDocument().IsVerticalScrollEnforced()) {
    return false;
  }

  if (IsA<LayoutView>(GetLayoutBox())) {
    Document& document = GetLayoutBox()->GetDocument();
    Element* fullscreen_element = Fullscreen::FullscreenElementFrom(document);
    if (fullscreen_element && fullscreen_element != document.documentElement())
      return false;

    mojom::blink::ScrollbarMode h_mode;
    mojom::blink::ScrollbarMode v_mode;
    To<LayoutView>(GetLayoutBox())->CalculateScrollbarModes(h_mode, v_mode);
    mojom::blink::ScrollbarMode mode =
        (orientation == kHorizontalScrollbar) ? h_mode : v_mode;
    return mode == mojom::blink::ScrollbarMode::kAuto ||
           mode == mojom::blink::ScrollbarMode::kAlwaysOn;
  }

  EOverflow overflow_style = (orientation == kHorizontalScrollbar)
                                 ? GetLayoutBox()->StyleRef().OverflowX()
                                 : GetLayoutBox()->StyleRef().OverflowY();
  return (overflow_style == EOverflow::kScroll ||
          overflow_style == EOverflow::kAuto ||
          overflow_style == EOverflow::kOverlay);
}

bool PaintLayerScrollableArea::ShouldPlaceVerticalScrollbarOnLeft() const {
  return GetLayoutBox()->ShouldPlaceBlockDirectionScrollbarOnLogicalLeft();
}

int PaintLayerScrollableArea::PageStep(ScrollbarOrientation orientation) const {
  // Paging scroll operations should take scroll-padding into account [1]. So we
  // use the snapport rect to calculate the page step instead of the visible
  // rect.
  // [1] https://drafts.csswg.org/css-scroll-snap/#scroll-padding
  gfx::Size snapport_size = VisibleScrollSnapportRect().PixelSnappedSize();
  int length = (orientation == kHorizontalScrollbar) ? snapport_size.width()
                                                     : snapport_size.height();
  int min_page_step = static_cast<float>(length) *
                      ScrollableArea::MinFractionToStepWhenPaging();
  int page_step = max(min_page_step, length - MaxOverlapBetweenPages());
  return max(page_step, 1);
}

bool PaintLayerScrollableArea::IsRootFrameLayoutViewport() const {
  LocalFrame* frame = GetLayoutBox()->GetFrame();
  if (!frame || !frame->View())
    return false;

  RootFrameViewport* root_frame_viewport =
      frame->View()->GetRootFrameViewport();
  if (!root_frame_viewport)
    return false;

  return &root_frame_viewport->LayoutViewport() == this;
}

LayoutBox* PaintLayerScrollableArea::GetLayoutBox() const {
  return layer_ ? layer_->GetLayoutBox() : nullptr;
}

PaintLayer* PaintLayerScrollableArea::Layer() const {
  return layer_.Get();
}

PhysicalSize PaintLayerScrollableArea::Size() const {
  return layer_->IsRootLayer()
             ? PhysicalSize(GetLayoutBox()->GetFrameView()->Size())
             : GetLayoutBox()->Size();
}

LayoutUnit PaintLayerScrollableArea::ScrollWidth() const {
  return overflow_rect_.Width();
}

LayoutUnit PaintLayerScrollableArea::ScrollHeight() const {
  return overflow_rect_.Height();
}

void PaintLayerScrollableArea::UpdateScrollOrigin() {
  // This should do nothing prior to first layout; the if-clause will catch
  // that.
  if (overflow_rect_.IsEmpty())
    return;
  PhysicalRect scrollable_overflow = overflow_rect_;
  scrollable_overflow.Move(-PhysicalOffset(GetLayoutBox()->BorderLeft(),
                                           GetLayoutBox()->BorderTop()));
  gfx::Point new_origin = ToFlooredPoint(-scrollable_overflow.offset) +
                          GetLayoutBox()->OriginAdjustmentForScrollbars();
  if (new_origin != scroll_origin_) {
    scroll_origin_changed_ = true;
    // ScrollOrigin affects paint offsets of the scrolling contents.
    GetLayoutBox()->SetSubtreeShouldCheckForPaintInvalidation();
  }
  scroll_origin_ = new_origin;
}

void PaintLayerScrollableArea::UpdateScrollDimensions() {
  PhysicalRect new_overflow_rect = GetLayoutBox()->ScrollableOverflowRect();

  // The layout viewport can be larger than the document's scrollable overflow
  // when top controls are hidden.  Expand the overflow here to ensure that our
  // contents size >= visible size.
  new_overflow_rect.Unite(PhysicalRect(
      new_overflow_rect.offset, LayoutContentRect(kExcludeScrollbars).size));

  bool resized = overflow_rect_.size != new_overflow_rect.size;
  overflow_rect_ = new_overflow_rect;
  if (resized)
    ContentsResized();
  UpdateScrollOrigin();
}

void PaintLayerScrollableArea::UpdateScrollbarEnabledState(
    bool is_horizontal_scrollbar_frozen,
    bool is_vertical_scrollbar_frozen) {
  bool force_disable =
      GetPageScrollbarTheme().ShouldDisableInvisibleScrollbars() &&
      ScrollbarsHiddenIfOverlay();

  // Don't update the enabled state of a custom scrollbar if that scrollbar
  // is frozen. Otherwise re-running the style cascade with the change in
  // :disabled pseudo state matching for custom scrollbars can cause infinite
  // loops in layout.
  if (Scrollbar* horizontal_scrollbar = HorizontalScrollbar()) {
    if (!horizontal_scrollbar->IsCustomScrollbar() ||
        !is_horizontal_scrollbar_frozen) {
      horizontal_scrollbar->SetEnabled(HasHorizontalOverflow() &&
                                       !force_disable);
    }
  }

  if (Scrollbar* vertical_scrollbar = VerticalScrollbar()) {
    if (!vertical_scrollbar->IsCustomScrollbar() ||
        !is_vertical_scrollbar_frozen) {
      vertical_scrollbar->SetEnabled(HasVerticalOverflow() && !force_disable);
    }
  }
}

void PaintLayerScrollableArea::UpdateScrollbarProportions() {
  if (Scrollbar* horizontal_scrollbar = HorizontalScrollbar())
    horizontal_scrollbar->SetProportion(VisibleWidth(), ContentsSize().width());
  if (Scrollbar* vertical_scrollbar = VerticalScrollbar())
    vertical_scrollbar->SetProportion(VisibleHeight(), ContentsSize().height());
}

void PaintLayerScrollableArea::SetScrollOffsetUnconditionally(
    const ScrollOffset& offset,
    mojom::blink::ScrollType scroll_type) {
  CancelScrollAnimation();
  ScrollOffsetChanged(offset, scroll_type);
}

void PaintLayerScrollableArea::UpdateAfterLayout() {
  EnqueueForSnapUpdateIfNeeded();
  EnqueueForStickyUpdateIfNeeded();

  bool is_horizontal_scrollbar_frozen = IsHorizontalScrollbarFrozen();
  bool is_vertical_scrollbar_frozen = IsVerticalScrollbarFrozen();

  if (NeedsScrollbarReconstruction()) {
    RemoveScrollbarsForReconstruction();
    // In case that DelayScrollOffsetClampScope prevented destruction of the
    // scrollbars.
    scrollbar_manager_.DestroyDetachedScrollbars();
  }

  UpdateScrollDimensions();

  bool has_resizer = GetLayoutBox()->CanResize();
  bool resizer_will_change = had_resizer_before_relayout_ != has_resizer;
  had_resizer_before_relayout_ = has_resizer;

  bool had_horizontal_scrollbar = HasHorizontalScrollbar();
  bool had_vertical_scrollbar = HasVerticalScrollbar();

  bool needs_horizontal_scrollbar;
  bool needs_vertical_scrollbar;
  ComputeScrollbarExistence(needs_horizontal_scrollbar,
                            needs_vertical_scrollbar);

  if (!is_horizontal_scrollbar_frozen && !is_vertical_scrollbar_frozen &&
      TryRemovingAutoScrollbars(needs_horizontal_scrollbar,
                                needs_vertical_scrollbar)) {
    needs_horizontal_scrollbar = needs_vertical_scrollbar = false;
  }

  bool horizontal_scrollbar_should_change =
      needs_horizontal_scrollbar != had_horizontal_scrollbar;
  bool vertical_scrollbar_should_change =
      needs_vertical_scrollbar != had_vertical_scrollbar;

  bool scrollbars_will_change =
      (horizontal_scrollbar_should_change && !is_horizontal_scrollbar_frozen) ||
      (vertical_scrollbar_should_change && !is_vertical_scrollbar_frozen);
  if (scrollbars_will_change) {
    SetHasHorizontalScrollbar(needs_horizontal_scrollbar);
    SetHasVerticalScrollbar(needs_vertical_scrollbar);

    // If we change scrollbars on the layout viewport, the visual viewport
    // needs to update paint properties to account for the correct
    // scrollbounds.
    if (LocalFrameView* frame_view = GetLayoutBox()->GetFrameView()) {
      VisualViewport& visual_viewport =
          GetLayoutBox()->GetFrame()->GetPage()->GetVisualViewport();
      if (this == frame_view->LayoutViewport() &&
          visual_viewport.IsActiveViewport()) {
        visual_viewport.SetNeedsPaintPropertyUpdate();
      }
    }

    UpdateScrollCornerStyle();

    Layer()->UpdateSelfPaintingLayer();

    // Force an update since we know the scrollbars have changed things.
    if (GetLayoutBox()->GetDocument().HasDraggableRegions()) {
      GetLayoutBox()->GetDocument().SetDraggableRegionsDirty(true);
    }

    // Our proprietary overflow: overlay value doesn't trigger a layout.
    if (((horizontal_scrollbar_should_change &&
          GetLayoutBox()->StyleRef().OverflowX() != EOverflow::kOverlay) ||
         (vertical_scrollbar_should_change &&
          GetLayoutBox()->StyleRef().OverflowY() != EOverflow::kOverlay))) {
      if ((vertical_scrollbar_should_change &&
           GetLayoutBox()->IsHorizontalWritingMode()) ||
          (horizontal_scrollbar_should_change &&
           !GetLayoutBox()->IsHorizontalWritingMode())) {
        GetLayoutBox()->SetIntrinsicLogicalWidthsDirty();
      }
      // Just update the rectangles, in case scrollbars were added or
      // removed. The calling code on the layout side has its own scrollbar
      // change detection mechanism.
      UpdateScrollDimensions();
    }
  } else if (!HasScrollbar() && resizer_will_change) {
    Layer()->DirtyStackingContextZOrderLists();
  }

  {
    UpdateScrollbarEnabledState(is_horizontal_scrollbar_frozen,
                                is_vertical_scrollbar_frozen);

    UpdateScrollbarProportions();
  }

  hypothetical_horizontal_scrollbar_thickness_ = 0;
  if (NeedsHypotheticalScrollbarThickness(kHorizontalScrollbar)) {
    hypothetical_horizontal_scrollbar_thickness_ =
        ComputeHypotheticalScrollbarThickness(kHorizontalScrollbar, true);
  }
  hypothetical_vertical_scrollbar_thickness_ = 0;
  if (NeedsHypotheticalScrollbarThickness(kVerticalScrollbar)) {
    hypothetical_vertical_scrollbar_thickness_ =
        ComputeHypotheticalScrollbarThickness(kVerticalScrollbar, true);
  }

  DelayableClampScrollOffsetAfterOverflowChange();

  if (!is_horizontal_scrollbar_frozen || !is_vertical_scrollbar_frozen)
    UpdateScrollableAreaSet();

  PositionOverflowControls();

  if (IsApplyingScrollStart()) {
    ApplyScrollStart();
  }

  UpdateScrollMarkers();
}

Element* PaintLayerScrollableArea::GetElementForScrollStart() const {
  if (!GetLayoutBox()) {
    return nullptr;
  }

  const LayoutBox* box = GetLayoutBox();
  if (auto* element = DynamicTo<Element>(box->GetNode())) {
    return element;
  }

  Node* node = box->GetNode();
  if (!node && box->Parent() && box->Parent()->IsFieldset()) {
    return DynamicTo<Element>(box->Parent()->GetNode());
  }

  if (node && node->IsDocumentNode()) {
    return GetLayoutBox()->GetDocument().documentElement();
  }

  return nullptr;
}

void PaintLayerScrollableArea::SetShouldCheckForPaintInvalidation() {
  LayoutBox& box = *GetLayoutBox();
  // This function may be called during pre-paint, and in such cases we cannot
  // mark the ancestry for paint invalidation checking, since we may already be
  // done with those objects, and never get to visit them again.
  if (GetLayoutBox()->GetDocument().Lifecycle().GetState() ==
      DocumentLifecycle::DocumentLifecycle::kInPrePaint) {
    box.GetMutableForPainting().SetShouldCheckForPaintInvalidation();
  } else {
    box.SetShouldCheckForPaintInvalidation();
  }
}

bool PaintLayerScrollableArea::IsApplyingScrollStart() const {
  if (Element* element = GetElementForScrollStart()) {
    if (element->HasBeenExplicitlyScrolled()) {
      return false;
    }
    if (RuntimeEnabledFeatures::CSSScrollStartTargetEnabled() &&
        GetScrollStartTarget()) {
      return true;
    }
    return RuntimeEnabledFeatures::CSSScrollStartEnabled() &&
           !ScrollStartIsDefault();
  }
  return false;
}

void PaintLayerScrollableArea::StopApplyingScrollStart() {
  if (Element* element = GetElementForScrollStart()) {
    element->SetHasBeenExplicitlyScrolled();
  }
}

void PaintLayerScrollableArea::DelayableClampScrollOffsetAfterOverflowChange() {
  if (HasBeenDisposed())
    return;
  if (DelayScrollOffsetClampScope::ClampingIsDelayed()) {
    DelayScrollOffsetClampScope::SetNeedsClamp(this);
    return;
  }
  ClampScrollOffsetAfterOverflowChangeInternal();
}

void PaintLayerScrollableArea::ClampScrollOffsetAfterOverflowChange() {
  ClampScrollOffsetAfterOverflowChangeInternal();
}

void PaintLayerScrollableArea::ClampScrollOffsetAfterOverflowChangeInternal() {
  if (HasBeenDisposed())
    return;

  // If a vertical scrollbar was removed, the min/max scroll offsets may have
  // changed, so the scroll offsets needs to be clamped.  If the scroll offset
  // did not change, but the scroll origin *did* change, we still need to notify
  // the scrollbars to update their dimensions.

  const Document& document = GetLayoutBox()->GetDocument();
  if (document.IsPrintingOrPaintingPreview()) {
    // Scrollable elements may change size when generating layout for printing,
    // which may require them to change the scroll position in order to keep the
    // same content within view. In vertical-rl writing-mode, even the root
    // frame may be attempted scrolled, because a viewport size change may
    // affect scroll origin. Save all scroll offsets before clamping, so that
    // everything can be restored the way it was after printing.
    if (Node* node = EventTargetNode())
      document.GetFrame()->EnsureSaveScrollOffset(*node);
  }

  UpdateScrollDimensions();
  if (ScrollOriginChanged()) {
    SetScrollOffsetUnconditionally(ClampScrollOffset(GetScrollOffset()));
  } else {
    ScrollableArea::SetScrollOffset(GetScrollOffset(),
                                    mojom::blink::ScrollType::kClamping);
  }

  SetNeedsScrollOffsetClamp(false);
  ResetScrollOriginChanged();
  scrollbar_manager_.DestroyDetachedScrollbars();
}

void PaintLayerScrollableArea::DidChangeGlobalRootScroller() {
  // Being the global root scroller will affect clipping size due to browser
  // controls behavior so we need to update compositing based on updated clip
  // geometry.
  Layer()->SetNeedsCompositingInputsUpdate();
  GetLayoutBox()->SetNeedsPaintPropertyUpdate();

  // On Android, where the VisualViewport supplies scrollbars, we need to
  // remove the PLSA's scrollbars if we become the global root scroller.
  // In general, this would be problematic as that can cause layout but this
  // should only ever apply with overlay scrollbars.
  if (GetLayoutBox()->GetFrame()->GetSettings() &&
      GetLayoutBox()->GetFrame()->GetSettings()->GetViewportEnabled()) {
    bool needs_horizontal_scrollbar;
    bool needs_vertical_scrollbar;
    ComputeScrollbarExistence(needs_horizontal_scrollbar,
                              needs_vertical_scrollbar);
    SetHasHorizontalScrollbar(needs_horizontal_scrollbar);
    SetHasVerticalScrollbar(needs_vertical_scrollbar);
  }

  // Recalculate the snap container data since the scrolling behaviour for this
  // layout box changed (i.e. it either became the layout viewport or it
  // is no longer the layout viewport).
  if (!GetLayoutBox()->NeedsLayout()) {
    EnqueueForSnapUpdateIfNeeded();
  }
}

bool PaintLayerScrollableArea::ShouldPerformScrollAnchoring() const {
  return scroll_anchor_.HasScroller() && GetLayoutBox() &&
         GetLayoutBox()->StyleRef().OverflowAnchor() !=
             EOverflowAnchor::kNone &&
         !GetLayoutBox()->GetDocument().FinishingOrIsPrinting();
}

bool PaintLayerScrollableArea::RestoreScrollAnchor(
    const SerializedAnchor& serialized_anchor) {
  return ShouldPerformScrollAnchoring() &&
         scroll_anchor_.RestoreAnchor(serialized_anchor);
}

gfx::QuadF PaintLayerScrollableArea::LocalToVisibleContentQuad(
    const gfx::QuadF& quad,
    const LayoutObject* local_object,
    MapCoordinatesFlags flags) const {
  LayoutBox* box = GetLayoutBox();
  if (!box)
    return quad;
  DCHECK(local_object);
  return local_object->LocalToAncestorQuad(quad, box, flags);
}

scoped_refptr<base::SingleThreadTaskRunner>
PaintLayerScrollableArea::GetTimerTaskRunner() const {
  return GetLayoutBox()->GetFrame()->GetTaskRunner(TaskType::kInternalDefault);
}

mojom::blink::ScrollBehavior PaintLayerScrollableArea::ScrollBehaviorStyle()
    const {
  return GetLayoutBox()->StyleRef().GetScrollBehavior();
}

mojom::blink::ColorScheme PaintLayerScrollableArea::UsedColorSchemeScrollbars()
    const {
  const auto* layout_box = GetLayoutBox();
  CHECK(layout_box);

  // Use dark color scheme for root non-overlay scrollbars if all of the
  // following conditions are met:
  //   - color scheme flags are normal (including cases when flags are not
  //     specified),
  //   - the preferred color scheme is dark (OS-based),
  //   - the browser preferred color scheme is dark.
  //   - there is no custom browser theme active
  //   - there is no color-picked browser theme active
  //     (both theme conditions are embedded into
  //        `GetPreferredRootScrollbarColorScheme()`)
  if (IsGlobalRootNonOverlayScroller() &&
      layout_box->StyleRef().ColorSchemeFlagsIsNormal()) {
    const auto& document = layout_box->GetDocument();
    if (document.GetPreferredColorScheme() ==
            mojom::blink::PreferredColorScheme::kDark &&
        document.GetSettings()->GetPreferredRootScrollbarColorScheme() ==
            mojom::blink::PreferredColorScheme::kDark) {
      UseCounter::Count(GetLayoutBox()->GetDocument(),
                        WebFeature::kUsedColorSchemeRootScrollbarsDark);
      return mojom::blink::ColorScheme::kDark;
    }
  }

  return GetLayoutBox()->StyleRef().UsedColorScheme();
}

bool PaintLayerScrollableArea::UsedColorSchemeScrollbarsChanged(
    const ComputedStyle* old_style) const {
  if (!old_style) {
    return false;
  }

  if (old_style->UsedColorScheme() !=
      GetLayoutBox()->StyleRef().UsedColorScheme()) {
    return true;
  }

  // Root scrollbars will be invalidated on preferred color scheme change
  // so here we only check for the changes in color scheme flags.
  if (IsGlobalRootNonOverlayScroller() &&
      old_style->ColorSchemeFlagsIsNormal() !=
          GetLayoutBox()->StyleRef().ColorSchemeFlagsIsNormal()) {
    return true;
  }

  return false;
}

bool PaintLayerScrollableArea::IsGlobalRootNonOverlayScroller() const {
  return GetLayoutBox()->IsGlobalRootScroller() &&
         !GetPageScrollbarTheme().UsesOverlayScrollbars();
}

bool PaintLayerScrollableArea::HasHorizontalOverflow() const {
  // TODO(szager): Make the algorithm for adding/subtracting overflow:auto
  // scrollbars memoryless (crbug.com/625300).  This client_width hack will
  // prevent the spurious horizontal scrollbar, but it can cause a converse
  // problem: it can leave a sliver of horizontal overflow hidden behind the
  // vertical scrollbar without creating a horizontal scrollbar.  This
  // converse problem seems to happen much less frequently in practice, so we
  // bias the logic towards preventing unwanted horizontal scrollbars, which
  // are more common and annoying.
  LayoutUnit client_width = LayoutContentRect(kIncludeScrollbars).Width() -
                            VerticalScrollbarWidth(kIgnoreOverlayScrollbarSize);
  if (NeedsRelayout() && !HadVerticalScrollbarBeforeRelayout())
    client_width += VerticalScrollbarWidth();
  return ScrollWidth().Round() > client_width.Round();
}

bool PaintLayerScrollableArea::HasVerticalOverflow() const {
  LayoutUnit client_height =
      LayoutContentRect(kIncludeScrollbars).Height() -
      HorizontalScrollbarHeight(kIgnoreOverlayScrollbarSize);
  return ScrollHeight().Round() > client_height.Round();
}

// This function returns true if the given box requires overflow scrollbars (as
// opposed to the viewport scrollbars managed by VisualViewport).
static bool CanHaveOverflowScrollbars(const LayoutBox& box) {
  return box.GetDocument().ViewportDefiningElement() != box.GetNode();
}

void PaintLayerScrollableArea::UpdateAfterStyleChange(
    const ComputedStyle* old_style) {
  // Don't do this on first style recalc, before layout has ever happened.
  if (!overflow_rect_.size.IsZero())
    UpdateScrollableAreaSet();

  UpdateResizerStyle(old_style);

  // The scrollbar overlay color theme depends on styles such as the background
  // color and the used color scheme.
  RecalculateOverlayScrollbarColorScheme();

  if (NeedsScrollbarReconstruction()) {
    RemoveScrollbarsForReconstruction();
    return;
  }

  bool needs_horizontal_scrollbar;
  bool needs_vertical_scrollbar;
  ComputeScrollbarExistence(needs_horizontal_scrollbar,
                            needs_vertical_scrollbar, kOverflowIndependent);

  // Avoid some unnecessary computation if there were and will be no scrollbars.
  if (!HasScrollbar() && !needs_horizontal_scrollbar &&
      !needs_vertical_scrollbar)
    return;

  SetHasHorizontalScrollbar(needs_horizontal_scrollbar);
  SetHasVerticalScrollbar(needs_vertical_scrollbar);

  if (HorizontalScrollbar())
    HorizontalScrollbar()->StyleChanged();
  if (VerticalScrollbar())
    VerticalScrollbar()->StyleChanged();

  UpdateScrollCornerStyle();

  if (!old_style || UsedColorSchemeScrollbarsChanged(old_style) ||
      old_style->ScrollbarThumbColorResolved() !=
          GetLayoutBox()->StyleRef().ScrollbarThumbColorResolved() ||
      old_style->ScrollbarTrackColorResolved() !=
          GetLayoutBox()->StyleRef().ScrollbarTrackColorResolved()) {
    SetScrollControlsNeedFullPaintInvalidation();
  }
}

void PaintLayerScrollableArea::UpdateAfterOverflowRecalc() {
  UpdateScrollDimensions();
  UpdateScrollbarProportions();
  UpdateScrollbarEnabledState();

  bool needs_horizontal_scrollbar;
  bool needs_vertical_scrollbar;
  ComputeScrollbarExistence(needs_horizontal_scrollbar,
                            needs_vertical_scrollbar);

  bool horizontal_scrollbar_should_change =
      needs_horizontal_scrollbar != HasHorizontalScrollbar();
  bool vertical_scrollbar_should_change =
      needs_vertical_scrollbar != HasVerticalScrollbar();

  if ((GetLayoutBox()->HasAutoHorizontalScrollbar() &&
       horizontal_scrollbar_should_change) ||
      (GetLayoutBox()->HasAutoVerticalScrollbar() &&
       vertical_scrollbar_should_change)) {
    GetLayoutBox()->SetNeedsLayoutAndFullPaintInvalidation(
        layout_invalidation_reason::kUnknown);
  }

  ClampScrollOffsetAfterOverflowChange();
  UpdateScrollableAreaSet();
}

gfx::Rect PaintLayerScrollableArea::RectForHorizontalScrollbar() const {
  if (!HasHorizontalScrollbar())
    return gfx::Rect();

  const gfx::Rect& scroll_corner = ScrollCornerRect();
  gfx::Size border_box_size = PixelSnappedBorderBoxSize();
  return gfx::Rect(
      HorizontalScrollbarStart(),
      border_box_size.height() - GetLayoutBox()->BorderBottom().ToInt() -
          HorizontalScrollbar()->ScrollbarThickness(),
      border_box_size.width() -
          (GetLayoutBox()->BorderLeft() + GetLayoutBox()->BorderRight())
              .ToInt() -
          scroll_corner.width(),
      HorizontalScrollbar()->ScrollbarThickness());
}

gfx::Rect PaintLayerScrollableArea::RectForVerticalScrollbar() const {
  if (!HasVerticalScrollbar())
    return gfx::Rect();

  const gfx::Rect& scroll_corner = ScrollCornerRect();
  return gfx::Rect(
      VerticalScrollbarStart(), GetLayoutBox()->BorderTop().ToInt(),
      VerticalScrollbar()->ScrollbarThickness(),
      PixelSnappedBorderBoxSize().height() -
          (GetLayoutBox()->BorderTop() + GetLayoutBox()->BorderBottom())
              .ToInt() -
          scroll_corner.height());
}

int PaintLayerScrollableArea::VerticalScrollbarStart() const {
  if (GetLayoutBox()->ShouldPlaceBlockDirectionScrollbarOnLogicalLeft())
    return GetLayoutBox()->BorderLeft().ToInt();
  return PixelSnappedBorderBoxSize().width() -
         GetLayoutBox()->BorderRight().ToInt() -
         VerticalScrollbar()->ScrollbarThickness();
}

int PaintLayerScrollableArea::HorizontalScrollbarStart() const {
  int x = GetLayoutBox()->BorderLeft().ToInt();
  if (GetLayoutBox()->ShouldPlaceBlockDirectionScrollbarOnLogicalLeft()) {
    x += HasVerticalScrollbar() ? VerticalScrollbar()->ScrollbarThickness()
                                : ResizerCornerRect(kResizerForPointer).width();
  }
  return x;
}

gfx::Vector2d PaintLayerScrollableArea::ScrollbarOffset(
    const Scrollbar& scrollbar) const {
  // TODO(szager): Factor out vertical offset calculation into other methods,
  // for symmetry with *ScrollbarStart methods for horizontal offset.
  if (&scrollbar == VerticalScrollbar()) {
    return gfx::Vector2d(VerticalScrollbarStart(),
                         GetLayoutBox()->BorderTop().ToInt());
  }

  if (&scrollbar == HorizontalScrollbar()) {
    return gfx::Vector2d(HorizontalScrollbarStart(),
                         GetLayoutBox()->BorderTop().ToInt() +
                             VisibleContentRect(kIncludeScrollbars).height() -
                             HorizontalScrollbar()->ScrollbarThickness());
  }

  NOTREACHED();
}

static inline const LayoutObject& ScrollbarStyleSource(
    const LayoutBox& layout_box) {
  if (IsA<LayoutView>(layout_box)) {
    Document& doc = layout_box.GetDocument();

    // If the layout box uses standard scrollbar styles use it as the style
    // source.
    if (layout_box.StyleRef().UsesStandardScrollbarStyle()) {
      return layout_box;
    }

    // Legacy custom scrollbar styles on the document element or the <body> may
    // apply to the viewport scrollbars. We don't propagate these styles to
    // LayoutView in StyleResolver like we do for the standard CSS scrollbar
    // styles because some conditions can only be checked here.
    if (Settings* settings = doc.GetSettings()) {
      LocalFrame* frame = layout_box.GetFrame();
      DCHECK(frame);
      DCHECK(frame->GetPage());

      VisualViewport& viewport = frame->GetPage()->GetVisualViewport();
      if (!settings->GetAllowCustomScrollbarInMainFrame() &&
          frame->IsMainFrame() && viewport.IsActiveViewport()) {
        return layout_box;
      }
    }

    // Try the <body> element as a scrollbar source, but only if the body
    // can scroll.
    Element* body = doc.body();
    if (body && body->GetLayoutObject() && body->GetLayoutObject()->IsBox() &&
        body->GetLayoutObject()->StyleRef().HasCustomScrollbarStyle(body)) {
      return *body->GetLayoutObject();
    }

    // If the <body> didn't have a custom style, then the root element might.
    Element* doc_element = doc.documentElement();
    if (doc_element && doc_element->GetLayoutObject() &&
        doc_element->GetLayoutObject()->StyleRef().HasCustomScrollbarStyle(
            doc_element) &&
        !layout_box.StyleRef().UsesStandardScrollbarStyle()) {
      return *doc_element->GetLayoutObject();
    }
  } else if (!layout_box.GetNode() && layout_box.Parent()) {
    return *layout_box.Parent();
  }

  return layout_box;
}

int PaintLayerScrollableArea::HypotheticalScrollbarThickness(
    ScrollbarOrientation orientation,
    bool should_include_overlay_thickness) const {
  DCHECK(NeedsHypotheticalScrollbarThickness(orientation));
  // The cached values are updated after layout, use them if we're layout clean.
  if (should_include_overlay_thickness &&
      GetLayoutBox()->GetDocument().Lifecycle().GetState() >=
          DocumentLifecycle::kLayoutClean) {
    return orientation == kHorizontalScrollbar
               ? hypothetical_horizontal_scrollbar_thickness_
               : hypothetical_vertical_scrollbar_thickness_;
  }
  return ComputeHypotheticalScrollbarThickness(
      orientation, should_include_overlay_thickness);
}

// Hypothetical scrollbar thickness is computed and cached during layout, but
// only as needed to avoid a performance penalty. It is needed for every
// LayoutView, to support frame view auto-sizing; and it's needed whenever CSS
// scrollbar-gutter requires it.
bool PaintLayerScrollableArea::NeedsHypotheticalScrollbarThickness(
    ScrollbarOrientation orientation) const {
  return GetLayoutBox()->IsLayoutView() ||
         GetLayoutBox()->HasScrollbarGutters(orientation);
}

int PaintLayerScrollableArea::ComputeHypotheticalScrollbarThickness(
    ScrollbarOrientation orientation,
    bool should_include_overlay_thickness) const {
  Scrollbar* scrollbar = orientation == kHorizontalScrollbar
                             ? HorizontalScrollbar()
                             : VerticalScrollbar();
  if (scrollbar)
    return scrollbar->ScrollbarThickness();

  const LayoutObject& style_source = ScrollbarStyleSource(*GetLayoutBox());
  if (style_source.StyleRef().HasCustomScrollbarStyle(
          GetElementForScrollStart())) {
    return CustomScrollbar::HypotheticalScrollbarThickness(this, orientation,
                                                           &style_source);
  }

  ScrollbarTheme& theme = GetPageScrollbarTheme();
  if (theme.UsesOverlayScrollbars() && !should_include_overlay_thickness)
    return 0;
  return theme.ScrollbarThickness(ScaleFromDIP(),
                                  style_source.StyleRef().UsedScrollbarWidth());
}

bool PaintLayerScrollableArea::NeedsScrollbarReconstruction() const {
  if (!HasScrollbar())
    return false;

  const LayoutObject& style_source = ScrollbarStyleSource(*GetLayoutBox());
  bool needs_custom =
      style_source.IsBox() && style_source.StyleRef().HasCustomScrollbarStyle(
                                  GetElementForScrollStart());

  Scrollbar* scrollbars[] = {HorizontalScrollbar(), VerticalScrollbar()};

  for (Scrollbar* scrollbar : scrollbars) {
    if (!scrollbar)
      continue;

    // We have a native scrollbar that should be custom, or vice versa.
    if (scrollbar->IsCustomScrollbar() != needs_custom)
      return true;

    // We have a scrollbar with a stale style source.
    if (scrollbar->StyleSource() != style_source) {
      return true;
    }

    if (needs_custom) {
      // Should use custom scrollbar and nothing should change.
      continue;
    }

    // Check if native scrollbar should change.
    Page* page = GetLayoutBox()->GetFrame()->LocalFrameRoot().GetPage();
    DCHECK(page);
    ScrollbarTheme* current_theme = &page->GetScrollbarTheme();

    if (current_theme != &scrollbar->GetTheme())
      return true;

    EScrollbarWidth current_width = scrollbar->CSSScrollbarWidth();
    if (current_width != style_source.StyleRef().UsedScrollbarWidth()) {
      return true;
    }
  }
  return false;
}

void PaintLayerScrollableArea::ComputeScrollbarExistence(
    bool& needs_horizontal_scrollbar,
    bool& needs_vertical_scrollbar,
    ComputeScrollbarExistenceOption option) const {
  // Scrollbars may be hidden or provided by visual viewport or frame instead.
  DCHECK(GetLayoutBox()->GetFrame()->GetSettings());
  if (VisualViewportSuppliesScrollbars() ||
      !CanHaveOverflowScrollbars(*GetLayoutBox()) ||
      GetLayoutBox()->GetFrame()->GetSettings()->GetHideScrollbars() ||
      GetLayoutBox()->IsFieldset() || GetLayoutBox()->IsFrameSet() ||
      GetLayoutBox()->StyleRef().UsedScrollbarWidth() ==
          EScrollbarWidth::kNone) {
    needs_horizontal_scrollbar = false;
    needs_vertical_scrollbar = false;
    return;
  }

  mojom::blink::ScrollbarMode h_mode = mojom::bl
```
Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `paint_layer_scrollable_area.cc`. I need to identify the main purpose of the code and how it relates to web page rendering.

Here's a breakdown of the code's functionality:

1. **Scrollbar Visibility Determination:** The code determines whether horizontal and vertical scrollbars should be visible based on CSS `overflow` properties and browser settings.
2. **Overlay Scrollbar Handling:** It specifically handles overlay scrollbars (the type that fade in/out) and ensures they are not set to "always on" when there's no overflow.
3. **Scrollbar Management:** The code interacts with a `scrollbar_manager_` to enable or disable scrollbars.
4. **Scroll Corner Management:** It deals with the scroll corner, the empty space at the intersection of the scrollbars.
5. **Snap Points:** The code includes logic for CSS Scroll Snap, allowing the browser to snap to specific points when scrolling.
6. **Resizing:** It handles resizing of elements via a resize corner.
7. **Scrolling into View:** The code contains logic for scrolling an element into the visible area.
8. **Sticky Positioning:** There's code related to sticky positioning of elements.
9. **Hit Testing:**  It determines if a mouse click or touch event falls within the scrollbars or resize controls.

Now, I'll formulate the summary based on these observations, relating them to JavaScript, HTML, and CSS where applicable, providing examples, and addressing potential errors.
这是对 `blink/renderer/core/paint/paint_layer_scrollable_area.cc` 文件中一部分代码的分析和功能归纳。

**功能归纳：**

这段代码的主要功能是**根据元素的样式属性（特别是 `overflow-x` 和 `overflow-y`），以及浏览器设置，来决定是否需要显示水平和垂直滚动条。** 它还处理了覆盖型滚动条（overlay scrollbars）的特殊情况，并确保在没有内容溢出的情况下不会强制显示它们。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **CSS 的 `overflow-x` 和 `overflow-y` 属性:**
   - 这段代码直接读取和解析了元素的 `overflow-x` 和 `overflow-y` 样式属性。
   - **HTML 示例:**
     ```html
     <div style="width: 100px; height: 50px; overflow-x: scroll; overflow-y: hidden;">
       This is some long text that will overflow horizontally.
     </div>
     ```
   - **功能说明:**  当 `overflow-x` 设置为 `scroll` 时，无论内容是否溢出，都会显示水平滚动条 (`h_mode = mojom::blink::ScrollbarMode::kAlwaysOn`)。当 `overflow-y` 设置为 `hidden` 时，垂直滚动条永远不会显示 (`v_mode = mojom::blink::ScrollbarMode::kAlwaysOff`)。

2. **覆盖型滚动条 (Overlay Scrollbars):**
   - 代码检查浏览器是否使用覆盖型滚动条 (`GetPageScrollbarTheme().UsesOverlayScrollbars()`)，并判断是否存在自定义滚动条样式 (`HasCustomScrollbarStyle`)。
   - **CSS 示例:**
     ```css
     /* 某些浏览器/操作系统默认使用覆盖型滚动条 */
     div {
       width: 200px;
       height: 100px;
       overflow: auto; /* 或 overflow: scroll */
     }

     /* 自定义滚动条样式 */
     ::-webkit-scrollbar {
       width: 10px;
     }
     ```
   - **功能说明:** 如果浏览器使用覆盖型滚动条且没有自定义样式，当 `overflow-x` 或 `overflow-y` 设置为 `scroll` 时，代码会将其转换为 `auto` (`h_mode = mojom::blink::ScrollbarMode::kAuto`, `v_mode = mojom::blink::ScrollbarMode::kAuto`)，这意味着滚动条只在内容溢出时才出现。

3. **JavaScript 的影响 (间接):**
   - JavaScript 可以动态修改元素的样式，包括 `overflow-x` 和 `overflow-y` 属性。
   - **JavaScript 示例:**
     ```javascript
     const myDiv = document.getElementById('myDiv');
     myDiv.style.overflowY = 'scroll'; // 强制显示垂直滚动条
     ```
   - **功能说明:**  当 JavaScript 修改了这些样式后，Blink 引擎会重新计算布局和绘制，这段代码会被再次执行，以根据新的样式决定滚动条的显示状态.

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

- HTML:
  ```html
  <div style="width: 50px; height: 50px; overflow: auto;">
    Short content.
  </div>
  ```
- 当前滚动条状态: `needs_horizontal_scrollbar = false`, `needs_vertical_scrollbar = false`

**输出 1:**

- `h_mode = mojom::blink::ScrollbarMode::kAuto`
- `v_mode = mojom::blink::ScrollbarMode::kAuto`
- `needs_horizontal_scrollbar = false` (因为内容没有水平溢出)
- `needs_vertical_scrollbar = false` (因为内容没有垂直溢出)

**假设输入 2:**

- HTML:
  ```html
  <div style="width: 50px; height: 50px; overflow: auto;">
    Very long content that overflows both horizontally and vertically. Very long content that overflows both horizontally and vertically.
  </div>
  ```
- 当前滚动条状态: `needs_horizontal_scrollbar = false`, `needs_vertical_scrollbar = false`

**输出 2:**

- `h_mode = mojom::blink::ScrollbarMode::kAuto`
- `v_mode = mojom::blink::ScrollbarMode::kAuto`
- `needs_horizontal_scrollbar = true` (因为内容有水平溢出)
- `needs_vertical_scrollbar = true` (因为内容有垂直溢出)

**用户或编程常见的使用错误及举例说明：**

1. **错误地假设 `overflow: scroll` 会始终显示覆盖型滚动条:**
   - **错误示例:** 用户认为设置了 `overflow: scroll` 就一定会看到细的、悬浮的覆盖型滚动条。
   - **说明:**  如果浏览器本身没有启用覆盖型滚动条，或者元素有自定义滚动条样式，`overflow: scroll` 会显示传统的、占据空间的滚动条。这段代码确保了覆盖型滚动条的行为符合预期，即在没有自定义样式时，`overflow: scroll` 表现得像 `overflow: auto`。

2. **在 JavaScript 中频繁切换 `overflow` 属性可能导致不必要的滚动条闪烁或布局抖动:**
   - **错误示例:**  JavaScript 代码根据用户的鼠标位置不断地切换元素的 `overflow-y` 属性，例如在 `auto` 和 `hidden` 之间切换。
   - **说明:**  每次 `overflow` 属性改变，浏览器都需要重新计算滚动条的显示状态，这可能会导致性能问题和用户体验不佳。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户加载包含可滚动元素的网页:** 当用户打开一个网页，浏览器开始解析 HTML 和 CSS。
2. **Blink 引擎创建布局树 (Layout Tree):** Blink 引擎根据 HTML 和 CSS 构建布局树，其中包含了元素的尺寸、位置和样式信息。
3. **创建绘制层 (Paint Layer):** 对于需要独立绘制的元素（例如，拥有滚动条的元素），Blink 引擎会创建绘制层 (`PaintLayerScrollableArea`)。
4. **计算滚动条模式:**  在布局和绘制过程中，这段代码会被调用，根据元素的 `overflow` 属性以及其他因素，计算出水平和垂直滚动条的显示模式 (`h_mode`, `v_mode`)。
5. **决定是否需要滚动条:** 根据计算出的滚动条模式和元素的实际内容溢出情况，最终确定是否需要显示滚动条 (`needs_horizontal_scrollbar`, `needs_vertical_scrollbar`)。
6. **绘制滚动条:** 如果需要显示滚动条，Blink 引擎会创建相应的滚动条对象，并在屏幕上绘制出来。

**作为调试线索:** 如果在调试过程中发现滚动条的显示行为与预期不符，可以检查以下几点：

- **元素的 `overflow-x` 和 `overflow-y` 属性是否设置正确。**
- **浏览器是否启用了覆盖型滚动条。**
- **是否存在自定义的滚动条样式影响了默认行为。**
- **JavaScript 代码是否动态修改了相关的样式属性。**

总而言之，这段代码是 Blink 引擎中负责管理滚动条显示逻辑的关键部分，它将 CSS 样式声明转换为浏览器实际渲染的滚动条行为。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_layer_scrollable_area.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ink::ScrollbarMode::kAuto;
  mojom::blink::ScrollbarMode v_mode = mojom::blink::ScrollbarMode::kAuto;

  // First, determine what behavior the scrollbars say they should have.
  {
    if (auto* layout_view = DynamicTo<LayoutView>(GetLayoutBox())) {
      // LayoutView is special as there's various quirks and settings that
      // style doesn't account for.
      layout_view->CalculateScrollbarModes(h_mode, v_mode);
    } else {
      auto overflow_x = GetLayoutBox()->StyleRef().OverflowX();
      if (overflow_x == EOverflow::kScroll) {
        h_mode = mojom::blink::ScrollbarMode::kAlwaysOn;
      } else if (overflow_x == EOverflow::kHidden ||
                 overflow_x == EOverflow::kVisible) {
        h_mode = mojom::blink::ScrollbarMode::kAlwaysOff;
      }

      auto overflow_y = GetLayoutBox()->StyleRef().OverflowY();
      if (overflow_y == EOverflow::kScroll) {
        v_mode = mojom::blink::ScrollbarMode::kAlwaysOn;
      } else if (overflow_y == EOverflow::kHidden ||
                 overflow_y == EOverflow::kVisible) {
        v_mode = mojom::blink::ScrollbarMode::kAlwaysOff;
      }
    }

    // Since overlay scrollbars (the fade-in/out kind, not overflow: overlay)
    // only appear when scrolling, we don't create them if there isn't overflow
    // to scroll. Thus, overlay scrollbars can't be "always on". i.e.
    // |overlay:scroll| behaves like |overlay:auto|.
    bool has_custom_scrollbar_style =
        ScrollbarStyleSource(*GetLayoutBox())
            .StyleRef()
            .HasCustomScrollbarStyle(GetElementForScrollStart());
    bool will_be_overlay = GetPageScrollbarTheme().UsesOverlayScrollbars() &&
                           !has_custom_scrollbar_style;
    if (will_be_overlay) {
      if (h_mode == mojom::blink::ScrollbarMode::kAlwaysOn)
        h_mode = mojom::blink::ScrollbarMode::kAuto;
      if (v_mode == mojom::blink::ScrollbarMode::kAlwaysOn)
        v_mode = mojom::blink::ScrollbarMode::kAuto;
    }
  }

  // By default, don't make any changes.
  needs_horizontal_scrollbar = HasHorizontalScrollbar();
  needs_vertical_scrollbar = HasVerticalScrollbar();

  // If the behavior doesn't depend on overflow or any other information, we
  // can set it now.
  {
    if (h_mode == mojom::blink::ScrollbarMode::kAlwaysOn)
      needs_horizontal_scrollbar = true;
    else if (h_mode == mojom::blink::ScrollbarMode::kAlwaysOff)
      needs_horizontal_scrollbar = false;

    if (v_mode == mojom::blink::ScrollbarMode::kAlwaysOn)
      needs_vertical_scrollbar = true;
    else if (v_mode == mojom::blink::ScrollbarMode::kAlwaysOff)
      needs_vertical_scrollbar = false;
  }

  // If this is being performed before layout, we want to only update scrollbar
  // existence if its based on purely style based reasons.
  if (option == kOverflowIndependent) {
    return;
  }

  // If we have clean layout, we can make a decision on any scrollbars that
  // depend on overflow.
  {
    if (h_mode == mojom::blink::ScrollbarMode::kAuto) {
      // Don't add auto scrollbars if the box contents aren't visible.
      needs_horizontal_scrollbar =
          GetLayoutBox()->IsRooted() && HasHorizontalOverflow() &&
          VisibleContentRect(kIncludeScrollbars).height();
    }
    if (v_mode == mojom::blink::ScrollbarMode::kAuto) {
      needs_vertical_scrollbar = GetLayoutBox()->IsRooted() &&
                                 HasVerticalOverflow() &&
                                 VisibleContentRect(kIncludeScrollbars).width();
    }
  }
}

bool PaintLayerScrollableArea::TryRemovingAutoScrollbars(
    const bool& needs_horizontal_scrollbar,
    const bool& needs_vertical_scrollbar) {
  if (!needs_horizontal_scrollbar && !needs_vertical_scrollbar)
    return false;

  if (auto* layout_view = DynamicTo<LayoutView>(GetLayoutBox())) {
    mojom::blink::ScrollbarMode h_mode;
    mojom::blink::ScrollbarMode v_mode;
    layout_view->CalculateScrollbarModes(h_mode, v_mode);
    if (h_mode != mojom::blink::ScrollbarMode::kAuto ||
        v_mode != mojom::blink::ScrollbarMode::kAuto)
      return false;

    gfx::Size visible_size_with_scrollbars =
        VisibleContentRect(kIncludeScrollbars).size();
    if (ScrollWidth() <= visible_size_with_scrollbars.width() &&
        ScrollHeight() <= visible_size_with_scrollbars.height()) {
      return true;
    }
  } else {
    if (!GetLayoutBox()->HasAutoVerticalScrollbar() ||
        !GetLayoutBox()->HasAutoHorizontalScrollbar())
      return false;

    PhysicalSize client_size_with_scrollbars =
        LayoutContentRect(kIncludeScrollbars).size;
    if (ScrollWidth() <= client_size_with_scrollbars.width &&
        ScrollHeight() <= client_size_with_scrollbars.height) {
      return true;
    }
  }

  return false;
}

void PaintLayerScrollableArea::RemoveScrollbarsForReconstruction() {
  if (!HasHorizontalScrollbar() && !HasVerticalScrollbar())
    return;
  if (HasHorizontalScrollbar()) {
    SetScrollbarNeedsPaintInvalidation(kHorizontalScrollbar);
    scrollbar_manager_.SetHasHorizontalScrollbar(false);
  }
  if (HasVerticalScrollbar()) {
    SetScrollbarNeedsPaintInvalidation(kVerticalScrollbar);
    scrollbar_manager_.SetHasVerticalScrollbar(false);
  }
  UpdateScrollCornerStyle();
  UpdateScrollOrigin();

  // Force an update since we know the scrollbars have changed things.
  if (GetLayoutBox()->GetDocument().HasDraggableRegions()) {
    GetLayoutBox()->GetDocument().SetDraggableRegionsDirty(true);
  }
}

CompositorElementId PaintLayerScrollableArea::GetScrollCornerElementId() const {
  CompositorElementId scrollable_element_id = GetScrollElementId();
  DCHECK(scrollable_element_id);
  return CompositorElementIdWithNamespace(
      scrollable_element_id, CompositorElementIdNamespace::kScrollCorner);
}

void PaintLayerScrollableArea::SetHasHorizontalScrollbar(bool has_scrollbar) {
  if (IsHorizontalScrollbarFrozen())
    return;

  if (has_scrollbar == HasHorizontalScrollbar())
    return;

  SetScrollbarNeedsPaintInvalidation(kHorizontalScrollbar);

  scrollbar_manager_.SetHasHorizontalScrollbar(has_scrollbar);

  UpdateScrollOrigin();

  // Destroying or creating one bar can cause our scrollbar corner to come and
  // go. We need to update the opposite scrollbar's style.
  if (HasHorizontalScrollbar())
    HorizontalScrollbar()->StyleChanged();
  if (HasVerticalScrollbar())
    VerticalScrollbar()->StyleChanged();

  SetScrollCornerNeedsPaintInvalidation();

  // Force an update since we know the scrollbars have changed things.
  if (GetLayoutBox()->GetDocument().HasDraggableRegions()) {
    GetLayoutBox()->GetDocument().SetDraggableRegionsDirty(true);
  }
}

void PaintLayerScrollableArea::SetHasVerticalScrollbar(bool has_scrollbar) {
  if (IsVerticalScrollbarFrozen())
    return;

  if (GetLayoutBox()->GetDocument().IsVerticalScrollEnforced()) {
    // When the policy is enforced the contents of document cannot be scrolled.
    // This would make rendering a scrollbar look strange
    // (https://crbug.com/898151).
    return;
  }

  if (has_scrollbar == HasVerticalScrollbar())
    return;

  SetScrollbarNeedsPaintInvalidation(kVerticalScrollbar);

  scrollbar_manager_.SetHasVerticalScrollbar(has_scrollbar);

  UpdateScrollOrigin();

  // Destroying or creating one bar can cause our scrollbar corner to come and
  // go. We need to update the opposite scrollbar's style.
  if (HasHorizontalScrollbar())
    HorizontalScrollbar()->StyleChanged();
  if (HasVerticalScrollbar())
    VerticalScrollbar()->StyleChanged();

  SetScrollCornerNeedsPaintInvalidation();

  // Force an update since we know the scrollbars have changed things.
  if (GetLayoutBox()->GetDocument().HasDraggableRegions()) {
    GetLayoutBox()->GetDocument().SetDraggableRegionsDirty(true);
  }
}

int PaintLayerScrollableArea::VerticalScrollbarWidth(
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior) const {
  if (!HasVerticalScrollbar())
    return 0;
  if (overlay_scrollbar_clip_behavior == kIgnoreOverlayScrollbarSize &&
      GetLayoutBox()->StyleRef().OverflowY() == EOverflow::kOverlay) {
    return 0;
  }
  if ((overlay_scrollbar_clip_behavior == kIgnoreOverlayScrollbarSize ||
       !VerticalScrollbar()->ShouldParticipateInHitTesting()) &&
      VerticalScrollbar()->IsOverlayScrollbar()) {
    return 0;
  }
  return VerticalScrollbar()->ScrollbarThickness();
}

int PaintLayerScrollableArea::HorizontalScrollbarHeight(
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior) const {
  if (!HasHorizontalScrollbar())
    return 0;
  if (overlay_scrollbar_clip_behavior == kIgnoreOverlayScrollbarSize &&
      GetLayoutBox()->StyleRef().OverflowX() == EOverflow::kOverlay) {
    return 0;
  }
  if ((overlay_scrollbar_clip_behavior == kIgnoreOverlayScrollbarSize ||
       !HorizontalScrollbar()->ShouldParticipateInHitTesting()) &&
      HorizontalScrollbar()->IsOverlayScrollbar()) {
    return 0;
  }
  return HorizontalScrollbar()->ScrollbarThickness();
}

const cc::SnapContainerData* PaintLayerScrollableArea::GetSnapContainerData()
    const {
  return RareData() && RareData()->snap_container_data_
             ? &RareData()->snap_container_data_.value()
             : nullptr;
}

void PaintLayerScrollableArea::SetSnapContainerData(
    std::optional<cc::SnapContainerData> data) {
  EnsureRareData().snap_container_data_ = data;
}

bool PaintLayerScrollableArea::SetTargetSnapAreaElementIds(
    cc::TargetSnapAreaElementIds snap_target_ids) {
  if (!RareData() || !RareData()->snap_container_data_)
    return false;
  if (RareData()->snap_container_data_.value().SetTargetSnapAreaElementIds(
          snap_target_ids)) {
    GetLayoutBox()->SetNeedsPaintPropertyUpdate();
    return true;
  }
  return false;
}

void PaintLayerScrollableArea::UpdateFocusDataForSnapAreas() {
  LayoutBox* layout_box = GetLayoutBox();
  if (!layout_box) {
    return;
  }
  if (!RareData() || !RareData()->snap_container_data_) {
    return;
  }
  std::optional<cc::SnapContainerData>& container_data =
      RareData()->snap_container_data_;
  std::map<cc::ElementId, size_t> id_to_index;
  for (size_t i = 0; i < container_data->size(); i++) {
    id_to_index.emplace(container_data->at(i).element_id, i);
  }

  for (auto& fragment : layout_box->PhysicalFragments()) {
    if (auto* snap_areas = fragment.SnapAreas()) {
      for (Element* snap_area : *snap_areas) {
        cc::ElementId element_id =
            CompositorElementIdFromDOMNodeId(snap_area->GetDomNodeId());
        container_data->UpdateSnapAreaFocus(id_to_index.at(element_id),
                                            snap_area->HasFocusWithin());
      }
    }
  }
}

std::optional<cc::TargetSnapAreaElementIds>
PaintLayerScrollableArea::GetScrollsnapchangingTargetIds() const {
  return RareData() ? RareData()->scrollsnapchanging_target_ids_ : std::nullopt;
}

const cc::SnapSelectionStrategy* PaintLayerScrollableArea::GetImplSnapStrategy()
    const {
  return RareData() ? RareData()->impl_snap_strategy_.get() : nullptr;
}

void PaintLayerScrollableArea::SetImplSnapStrategy(
    std::unique_ptr<cc::SnapSelectionStrategy> strategy) {
  EnsureRareData().impl_snap_strategy_ = std::move(strategy);
}

std::optional<gfx::PointF>
PaintLayerScrollableArea::GetSnapPositionAndSetTarget(
    const cc::SnapSelectionStrategy& strategy) {
  if (!RareData() || !RareData()->snap_container_data_)
    return std::nullopt;

  cc::SnapContainerData& data = RareData()->snap_container_data_.value();
  if (!data.size())
    return std::nullopt;

  std::optional<gfx::PointF> snap_point;
  cc::SnapPositionData snap = data.FindSnapPosition(strategy);
  if (snap.type != cc::SnapPositionData::Type::kNone) {
    snap_point = gfx::PointF(snap.position.x(), snap.position.y());
  }

  if (data.SetTargetSnapAreaElementIds(snap.target_element_ids)) {
    GetLayoutBox()->SetNeedsPaintPropertyUpdate();
  }

  return snap_point;
}

bool PaintLayerScrollableArea::HasOverflowControls() const {
  // We do not need to check for ScrollCorner because it only exists iff there
  // are scrollbars, see: |ScrollCornerRect| and |UpdateScrollCornerStyle|.
  DCHECK(!ScrollCorner() || HasScrollbar());
  return HasScrollbar() || GetLayoutBox()->CanResize();
}

bool PaintLayerScrollableArea::HasOverlayOverflowControls() const {
  if (HasOverlayScrollbars())
    return true;
  if (!HasScrollbar() && GetLayoutBox()->CanResize())
    return true;
  if (GetLayoutBox()->StyleRef().OverflowX() == EOverflow::kOverlay ||
      GetLayoutBox()->StyleRef().OverflowY() == EOverflow::kOverlay)
    return true;
  return false;
}

bool PaintLayerScrollableArea::NeedsScrollCorner() const {
  // This is one of the differences between platform overlay scrollbars and
  // overflow:overlay scrollbars: the former don't need scroll corner, while
  // the latter do. HasOverlayScrollbars doesn't include overflow:overlay.
  return HasScrollbar() && !HasOverlayScrollbars();
}

bool PaintLayerScrollableArea::ShouldOverflowControlsPaintAsOverlay() const {
  if (HasOverlayOverflowControls())
    return true;

  // Frame and global root scroller (which can be a non-frame) scrollbars and
  // corner also paint as overlay so that they appear on top of all content
  // within their viewport. This is important for global root scrollers since
  // these scrollbars' transform state is
  // VisualViewport::TransformNodeForViewportScrollbars().
  return layer_->IsRootLayer() ||
         (GetLayoutBox() && GetLayoutBox()->IsGlobalRootScroller());
}

void PaintLayerScrollableArea::PositionOverflowControls() {
  if (!HasOverflowControls())
    return;

  if (Scrollbar* vertical_scrollbar = VerticalScrollbar()) {
    vertical_scrollbar->SetFrameRect(RectForVerticalScrollbar());
    if (auto* custom_scrollbar = DynamicTo<CustomScrollbar>(vertical_scrollbar))
      custom_scrollbar->PositionScrollbarParts();
  }

  if (Scrollbar* horizontal_scrollbar = HorizontalScrollbar()) {
    horizontal_scrollbar->SetFrameRect(RectForHorizontalScrollbar());
    if (auto* custom_scrollbar =
            DynamicTo<CustomScrollbar>(horizontal_scrollbar))
      custom_scrollbar->PositionScrollbarParts();
  }

  if (scroll_corner_) {
    PhysicalRect rect(ScrollCornerRect());
    scroll_corner_->SetOverriddenSize(rect.size);
    // TODO(crbug.com/1020913): This should be part of PaintPropertyTreeBuilder
    // when we support subpixel layout of overflow controls.
    scroll_corner_->GetMutableForPainting().FirstFragment().SetPaintOffset(
        rect.offset);
  }

  if (resizer_) {
    PhysicalRect rect(ResizerCornerRect(kResizerForPointer));
    resizer_->SetOverriddenSize(rect.size);
    // TODO(crbug.com/1020913): This should be part of PaintPropertyTreeBuilder
    // when we support subpixel layout of overflow controls.
    resizer_->GetMutableForPainting().FirstFragment().SetPaintOffset(
        rect.offset);
  }
}

void PaintLayerScrollableArea::UpdateScrollCornerStyle() {
  if (!NeedsScrollCorner()) {
    if (scroll_corner_) {
      scroll_corner_->Destroy();
      scroll_corner_ = nullptr;
    }
    return;
  }
  const LayoutObject& style_source = ScrollbarStyleSource(*GetLayoutBox());
  bool uses_standard_scrollbar_style =
      style_source.StyleRef().UsesStandardScrollbarStyle();
  const ComputedStyle* corner =
      (GetLayoutBox()->IsScrollContainer() && !uses_standard_scrollbar_style)
          ? style_source.GetUncachedPseudoElementStyle(
                StyleRequest(kPseudoIdScrollbarCorner, style_source.Style()))
          : nullptr;
  if (corner) {
    if (!scroll_corner_) {
      scroll_corner_ = LayoutCustomScrollbarPart::CreateAnonymous(
          &GetLayoutBox()->GetDocument(), this);
    }
    scroll_corner_->SetStyle(std::move(corner));
  } else if (scroll_corner_) {
    scroll_corner_->Destroy();
    scroll_corner_ = nullptr;
  }
}

bool PaintLayerScrollableArea::HitTestOverflowControls(
    HitTestResult& result,
    const gfx::Point& local_point) {
  if (!HasOverflowControls())
    return false;

  gfx::Rect resize_control_rect;
  if (GetLayoutBox()->CanResize()) {
    resize_control_rect = ResizerCornerRect(kResizerForPointer);
    if (resize_control_rect.Contains(local_point)) {
      result.SetIsOverResizer(true);
      return true;
    }
  }
  int resize_control_size = max(resize_control_rect.height(), 0);

  gfx::Rect visible_rect = VisibleContentRect(kIncludeScrollbars);

  if (HasVerticalScrollbar() &&
      VerticalScrollbar()->ShouldParticipateInHitTesting()) {
    gfx::Rect v_bar_rect(VerticalScrollbarStart(),
                         GetLayoutBox()->BorderTop().ToInt(),
                         VerticalScrollbar()->ScrollbarThickness(),
                         visible_rect.height() -
                             (HasHorizontalScrollbar()
                                  ? HorizontalScrollbar()->ScrollbarThickness()
                                  : resize_control_size));
    if (v_bar_rect.Contains(local_point)) {
      result.SetScrollbar(VerticalScrollbar());
      return true;
    }
  }

  resize_control_size = max(resize_control_rect.width(), 0);
  if (HasHorizontalScrollbar() &&
      HorizontalScrollbar()->ShouldParticipateInHitTesting()) {
    // TODO(crbug.com/638981): Are the conversions to int intentional?
    int h_scrollbar_thickness = HorizontalScrollbar()->ScrollbarThickness();
    gfx::Rect h_bar_rect(
        HorizontalScrollbarStart(),
        GetLayoutBox()->BorderTop().ToInt() + visible_rect.height() -
            h_scrollbar_thickness,
        visible_rect.width() - (HasVerticalScrollbar()
                                    ? VerticalScrollbar()->ScrollbarThickness()
                                    : resize_control_size),
        h_scrollbar_thickness);
    if (h_bar_rect.Contains(local_point)) {
      result.SetScrollbar(HorizontalScrollbar());
      return true;
    }
  }

  if (scroll_corner_ && ScrollCornerRect().Contains(local_point)) {
    if (GetLayoutBox() && GetLayoutBox()->GetFrame()) {
      base::debug::CrashKeyString* crash_key =
          GetLayoutBox()->GetFrame()->GetEventHandler().CrashKeyForBug1519197();
      base::debug::SetCrashKeyString(crash_key,
                                     GetLayoutBox()->DebugName().Utf8());
    }
    result.SetIsOverScrollCorner(true);
    return true;
  }
  return false;
}

gfx::Rect PaintLayerScrollableArea::ResizerCornerRect(
    ResizerHitTestType resizer_hit_test_type) const {
  if (!GetLayoutBox()->CanResize())
    return gfx::Rect();
  gfx::Rect corner = CornerRect();

  if (resizer_hit_test_type == kResizerForTouch) {
    // We make the resizer virtually larger for touch hit testing. With the
    // expanding ratio k = ResizerControlExpandRatioForTouch, we first move
    // the resizer rect (of width w & height h), by (-w * (k-1), -h * (k-1)),
    // then expand the rect by new_w/h = w/h * k.
    corner.Offset(-corner.width() * (kResizerControlExpandRatioForTouch - 1),
                  -corner.height() * (kResizerControlExpandRatioForTouch - 1));
    corner.set_size(
        gfx::Size(corner.width() * kResizerControlExpandRatioForTouch,
                  corner.height() * kResizerControlExpandRatioForTouch));
  }

  return corner;
}

gfx::Rect PaintLayerScrollableArea::ScrollCornerAndResizerRect() const {
  gfx::Rect scroll_corner_and_resizer = ScrollCornerRect();
  if (scroll_corner_and_resizer.IsEmpty())
    return ResizerCornerRect(kResizerForPointer);
  return scroll_corner_and_resizer;
}

bool PaintLayerScrollableArea::IsAbsolutePointInResizeControl(
    const gfx::Point& absolute_point,
    ResizerHitTestType resizer_hit_test_type) const {
  if (GetLayoutBox()->StyleRef().Visibility() != EVisibility::kVisible ||
      !GetLayoutBox()->CanResize()) {
    return false;
  }

  gfx::Point local_point = ToRoundedPoint(
      GetLayoutBox()->AbsoluteToLocalPoint(PhysicalOffset(absolute_point)));
  return ResizerCornerRect(resizer_hit_test_type).Contains(local_point);
}

bool PaintLayerScrollableArea::IsLocalPointInResizeControl(
    const gfx::Point& local_point,
    ResizerHitTestType resizer_hit_test_type) const {
  if (GetLayoutBox()->StyleRef().Visibility() != EVisibility::kVisible ||
      !GetLayoutBox()->CanResize()) {
    return false;
  }

  return ResizerCornerRect(resizer_hit_test_type).Contains(local_point);
}

void PaintLayerScrollableArea::UpdateResizerStyle(
    const ComputedStyle* old_style) {
  // Change of resizer status affects HasOverlayOverflowControls(). Invalid
  // z-order lists to refresh overflow control painting order.
  bool had_resizer = old_style && old_style->HasResize();
  bool needs_resizer = GetLayoutBox()->CanResize();
  if (had_resizer != needs_resizer)
    layer_->DirtyStackingContextZOrderLists();

  if (!resizer_ && !needs_resizer)
    return;

  // Update custom resizer style.
  const LayoutObject& style_source = ScrollbarStyleSource(*GetLayoutBox());
  const ComputedStyle* resizer =
      GetLayoutBox()->IsScrollContainer()
          ? style_source.GetUncachedPseudoElementStyle(
                StyleRequest(kPseudoIdResizer, style_source.Style()))
          : nullptr;
  if (resizer) {
    if (!resizer_) {
      resizer_ = LayoutCustomScrollbarPart::CreateAnonymous(
          &GetLayoutBox()->GetDocument(), this);
    }
    resizer_->SetStyle(std::move(resizer));
  } else if (resizer_) {
    resizer_->Destroy();
    resizer_ = nullptr;
  }
}

void PaintLayerScrollableArea::EnqueueForSnapUpdateIfNeeded() {
  auto* box = GetLayoutBox();
  // Not all PLSAs are scroll containers!
  if (!box->IsScrollContainer()) {
    return;
  }

  // Enqueue ourselves for a snap update if we have any snap-areas, or if we
  // currently have snap-data (and it needs to be cleared).
  for (const auto& fragment : box->PhysicalFragments()) {
    if (fragment.SnapAreas() || GetSnapContainerData()) {
      box->GetFrameView()->AddPendingSnapUpdate(this);
      break;
    }
  }
}

void PaintLayerScrollableArea::UpdateAllStickyConstraints() {
  for (const auto& fragment : GetLayoutBox()->PhysicalFragments()) {
    if (auto* sticky_descendants = fragment.StickyDescendants()) {
      for (auto& sticky_descendant : *sticky_descendants) {
        auto* constraints =
            sticky_descendant->ComputeStickyPositionConstraints();
        constraints->ComputeStickyOffset(ScrollPosition());
        sticky_descendant->SetStickyConstraints(constraints);
      }
    }
  }
}

void PaintLayerScrollableArea::EnqueueForStickyUpdateIfNeeded() {
  // Enqueue ourselves for a sticky update if we have any sticky descendants.
  const auto* box = GetLayoutBox();
  for (const auto& fragment : box->PhysicalFragments()) {
    if (fragment.StickyDescendants()) {
      box->GetFrameView()->AddPendingStickyUpdate(this);
      break;
    }
  }
}

void PaintLayerScrollableArea::InvalidatePaintForStickyDescendants() {
  // Only allow access to the fragments if we are layout-clean.
  const auto* box = GetLayoutBox();
  if (box->NeedsLayout()) {
    return;
  }

  // We might already be enqueued for a sticky update once layout is complete,
  // skip updating the sticky constraints as they may not exist yet.
  if (box->GetFrameView()->HasPendingStickyUpdate(this)) {
    return;
  }

  for (const auto& fragment : GetLayoutBox()->PhysicalFragments()) {
    if (auto* sticky_descendants = fragment.StickyDescendants()) {
      for (auto& sticky_descendant : *sticky_descendants) {
        sticky_descendant->SetNeedsPaintPropertyUpdate();
        DCHECK(sticky_descendant->StickyConstraints());
        sticky_descendant->StickyConstraints()->ComputeStickyOffset(
            ScrollPosition());
      }
    }
  }
}

gfx::Vector2d PaintLayerScrollableArea::OffsetFromResizeCorner(
    const gfx::Point& absolute_point) const {
  // Currently the resize corner is either the bottom right corner or the bottom
  // left corner.
  // FIXME: This assumes the location is 0, 0. Is this guaranteed to always be
  // the case?
  gfx::Size element_size = PixelSnappedBorderBoxSize();
  if (GetLayoutBox()->ShouldPlaceBlockDirectionScrollbarOnLogicalLeft())
    element_size.set_width(0);
  gfx::Point local_point = ToRoundedPoint(
      GetLayoutBox()->AbsoluteToLocalPoint(PhysicalOffset(absolute_point)));
  return gfx::Vector2d(local_point.x() - element_size.width(),
                       local_point.y() - element_size.height());
}

void PaintLayerScrollableArea::Resize(const gfx::Point& pos,
                                      const gfx::Vector2d& old_offset) {
  // FIXME: This should be possible on generated content but is not right now.
  if (!InResizeMode() || !GetLayoutBox()->CanResize() ||
      !GetLayoutBox()->GetNode())
    return;

  DCHECK(GetLayoutBox()->GetNode()->IsElementNode());
  auto* element = To<Element>(GetLayoutBox()->GetNode());

  Document& document = element->GetDocument();

  float zoom_factor = GetLayoutBox()->StyleRef().EffectiveZoom();

  gfx::Vector2d new_offset =
      OffsetFromResizeCorner(document.View()->ConvertFromRootFrame(pos));
  new_offset.set_x(new_offset.x() / zoom_factor);
  new_offset.set_y(new_offset.y() / zoom_factor);

  PhysicalSize current_size = GetLayoutBox()->Size();
  current_size.Scale(1 / zoom_factor);

  PhysicalOffset adjusted_old_offset(old_offset);
  adjusted_old_offset.Scale(1.f / zoom_factor);
  if (GetLayoutBox()->ShouldPlaceBlockDirectionScrollbarOnLogicalLeft()) {
    new_offset.set_x(-new_offset.x());
    adjusted_old_offset.left = -adjusted_old_offset.left;
  }

  PhysicalOffset offset = PhysicalOffset(new_offset) - adjusted_old_offset;
  PhysicalSize new_size(current_size.width + offset.left,
                        current_size.height + offset.top);

  // Ensure the new size is at least as large as the resize corner.
  gfx::SizeF corner_rect(CornerRect().size());
  corner_rect.InvScale(zoom_factor);
  new_size.width = std::max(new_size.width, LayoutUnit(corner_rect.width()));
  new_size.height = std::max(new_size.height, LayoutUnit(corner_rect.height()));

  PhysicalSize difference(new_size - current_size);

  bool is_box_sizing_border =
      GetLayoutBox()->StyleRef().BoxSizing() == EBoxSizing::kBorderBox;

  EResize resize = GetLayoutBox()->StyleRef().UsedResize();
  if (resize != EResize::kVertical && difference.width) {
    LayoutUnit base_width =
        GetLayoutBox()->Size().width -
        (is_box_sizing_border ? LayoutUnit()
                              : GetLayoutBox()->BorderAndPaddingWidth());
    base_width = LayoutUnit(base_width / zoom_factor);
    element->SetInlineStyleProperty(CSSPropertyID::kWidth,
                                    RoundToInt(base_width + difference.width),
                                    CSSPrimitiveValue::UnitType::kPixels);
  }

  if (resize != EResize::kHorizontal && difference.height) {
    LayoutUnit base_height =
        GetLayoutBox()->Size().height -
        (is_box_sizing_border ? LayoutUnit()
                              : GetLayoutBox()->BorderAndPaddingHeight());
    base_height = LayoutUnit(base_height / zoom_factor);
    element->SetInlineStyleProperty(CSSPropertyID::kHeight,
                                    RoundToInt(base_height + difference.height),
                                    CSSPrimitiveValue::UnitType::kPixels);
  }

  document.UpdateStyleAndLayout(DocumentUpdateReason::kSizeChange);

  // FIXME: We should also autoscroll the window as necessary to
  // keep the point under the cursor in view.
}

PhysicalOffset PaintLayerScrollableArea::LocalToScrollOriginOffset() const {
  PhysicalOffset border_origin_to_scroll_origin(-GetLayoutBox()->BorderLeft(),
                                                -GetLayoutBox()->BorderTop());
  // There might be scroll bar between border_origin and scroll_origin.
  gfx::Vector2d scroll_bar_adjustment =
      GetLayoutBox()->OriginAdjustmentForScrollbars();
  border_origin_to_scroll_origin.left -= scroll_bar_adjustment.x();
  border_origin_to_scroll_origin.top -= scroll_bar_adjustment.y();
  border_origin_to_scroll_origin +=
      PhysicalOffset::FromVector2dFFloor(GetScrollOffset());
  return border_origin_to_scroll_origin;
}

PhysicalRect PaintLayerScrollableArea::ScrollIntoView(
    const PhysicalRect& absolute_rect,
    const PhysicalBoxStrut& scroll_margin,
    const mojom::blink::ScrollIntoViewParamsPtr& params) {
  // Ignore sticky position offsets for the purposes of scrolling elements into
  // view. See https://www.w3.org/TR/css-position-3/#stickypos-scroll for
  // details
  const MapCoordinatesFlags flag =
      (RuntimeEnabledFeatures::CSSPositionStickyStaticScrollPositionEnabled())
          ? kIgnoreStickyOffset
          : 0;

  PhysicalRect local_expose_rect =
      GetLayoutBox()->AbsoluteToLocalRect(absolute_rect);
  ScrollOffset target_offset = scroll_into_view_util::GetScrollOffsetToExpose(
      *this, local_expose_rect, scroll_margin, *params->align_x.get(),
      *params->align_y.get());
  ScrollOffset new_scroll_offset(
      ClampScrollOffset(gfx::ToRoundedVector2d(target_offset)));

  ScrollOffset old_scroll_offset = GetScrollOffset();
  if (params->type == mojom::blink::ScrollType::kUser) {
    if (!UserInputScrollable(kHorizontalScrollbar))
      new_scroll_offset.set_x(old_scroll_offset.x());
    if (!UserInputScrollable(kVerticalScrollbar))
      new_scroll_offset.set_y(old_scroll_offset.y());
  }

  gfx::PointF end_point = ScrollOffsetToPosition(new_scroll_offset);
  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForEndPosition(end_point, true, true);
  end_point = GetSnapPositionAndSetTarget(*strategy).value_or(end_point);
  new_scroll_offset = ScrollPositionToOffset(end_point);

  if (params->is_for_scroll_sequence) {
    mojom::blink::ScrollBehavior behavior = DetermineScrollBehavior(
        params->behavior, GetLayoutBox()->StyleRef().GetScrollBehavior());
    if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
      SetScrollOffset(new_scroll_offset, params->type, behavior);
    } else {
      CHECK(GetSmoothScrollSequencer());
      DCHECK(params->type == mojom::blink::ScrollType::kProgrammatic ||
             params->type == mojom::blink::ScrollType::kUser);
      GetSmoothScrollSequencer()->QueueAnimation(this, new_scroll_offset,
                                                 behavior);
    }
  } else {
    SetScrollOffset(new_scroll_offset, params->type,
                    mojom::blink::ScrollBehavior::kInstant);
  }
  ScrollOffset scroll_offset_difference = new_scroll_offset - old_scroll_offset;
  // The container hasn't performed the scroll yet if it's for scroll sequence.
  // To calculate the result from the scroll, we move the |local_expose_rect| to
  // the will-be-scrolled location.
  local_expose_rect.Move(
      -PhysicalOffset::FromVector2dFRound(scroll_offset_difference));

  // Represent the rects in the container's border-box coordinate.
  PhysicalRect scroll_snapport_rect =
      VisibleScrollSnapportRect() - LocalToScrollOriginOffset();
  PhysicalRect intersect =
      Intersection(scroll_snapport_rect, local_expose_rect);

  if (intersect.IsEmpty() && !scroll_snapport_rect.IsEmpty() &&
      !local_expose_rect.IsEmpty()) {
    return GetLayoutBox()->LocalToAbsoluteRect(local_expose_rect, flag);
  }
  intersect = GetLayoutBox()->LocalToAbsoluteRect(intersect, flag);

  return intersect;
}

void PaintLayerScrollableArea::UpdateScrollableAreaSet() {
  LocalFrame* frame = GetLayoutBox()->GetFrame();
  if (!frame)
    return;

  LocalFrameView* frame_view = frame->View();
  if (!frame_view)
    return;

  const bool has_horizontal_overflow = HasHorizontalOverflow();
  const bool has_vertical_overflow = HasVerticalOverflow();
  bool has_overflow =
      !GetLayoutBox()->Size().IsZero() &&
      ((has_horizontal_overflow && GetLayoutBox()->ScrollsOverflowX()) ||
       (has_vertical_overflow && GetLayoutBox()->ScrollsOverflowY()));

  bool overflows_in_block_direction = GetLayoutBox()->IsHorizontalWritingMode()
                                          ? has_vertical_overflow
                                          : has_horizontal_overflow;

  if (overflows_in_block_direction) {
    DCHECK(CanHaveOverflowScrollbars(*GetLayoutBox()));
    frame_view->AddScrollAnchoringScrollableArea(this);
  } else {
    frame_view->RemoveScrollAnchoringScrollableArea(this);
  }

  bool is_visible =
      GetLayoutBox()->StyleRef().Visibility() == EVisibility::kVisible;
  bool did_scroll_overflow = scrolls_overflow_;
  if (auto* layout_view = DynamicTo<LayoutView>(GetLayoutBox())) {
    mojom::blink::ScrollbarMode h_mode;
    mojom::blink::ScrollbarMode v_mode;
    layout_view->CalculateScrollbarModes(h_mode, v_mode);
    if (h_mode == mojom::blink::ScrollbarMode::kAlwaysOff &&
        v_mode == mojom::blink::ScrollbarMode::k
```
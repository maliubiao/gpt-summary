Response:
The user wants a summary of the functionality of the `paint_layer_scrollable_area.cc` file in the Chromium Blink engine. They also want to know how it relates to web technologies like JavaScript, HTML, and CSS, along with examples, logical assumptions, common user/programming errors, and debugging tips. This is the first part of a five-part request, so the focus should be on a general overview of the file's responsibilities.

**Plan:**

1. **Identify Core Functionality:**  Based on the file name, includes, and class name (`PaintLayerScrollableArea`), the core functionality revolves around managing scrollable areas associated with paint layers. This likely involves handling scrolling, scrollbars, and related visual aspects.
2. **Analyze Key Responsibilities:** Scan the code for major actions and data members to understand the specific tasks performed. Look for interactions with other parts of the engine.
3. **Relate to Web Technologies:** Consider how the functionality directly corresponds to user interactions and web development concepts related to scrolling and visual layout.
4. **Identify Potential Errors/Debugging:** Think about common issues users or developers might encounter related to scrolling and how this file's functionality might be involved.
5. **Formulate a Concise Summary:**  Synthesize the findings into a clear and concise overview of the file's purpose.
这是 `blink/renderer/core/paint/paint_layer_scrollable_area.cc` 文件的第一部分，其主要功能是**管理与渲染层（PaintLayer）关联的可滚动区域的行为和属性**。

**核心功能归纳:**

1. **表示和管理滚动区域:**  `PaintLayerScrollableArea` 类负责表示一个可滚动的区域，它与一个 `PaintLayer` 对象关联。这包括存储和管理滚动偏移量、最大/最小滚动范围等信息。
2. **处理滚动事件:**  该文件中的代码处理用户或程序触发的滚动事件，并更新滚动偏移量。这涉及到与浏览器的滚动机制（例如平滑滚动）交互。
3. **管理滚动条:**  它负责创建、更新和管理与滚动区域关联的滚动条（包括传统滚动条和覆盖滚动条）。这包括确定滚动条的可见性、位置和大小。
4. **处理 Resizer (调整大小控件):** 如果滚动区域支持调整大小，该文件也会管理相关的调整大小控件的行为。
5. **与渲染流程集成:**  该类是渲染流程的一部分，负责在绘制阶段提供必要的滚动信息，以便正确渲染滚动内容和滚动条。
6. **与合成器交互:**  它与 Chromium 的合成器 (Compositor) 交互，以便实现硬件加速滚动和其他合成效果。
7. **处理视图状态恢复:**  该文件还负责在页面导航时恢复之前的滚动位置。
8. **提供坐标转换:**  提供各种坐标系之间的转换方法，例如从滚动条坐标到内容坐标的转换。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **HTML:**  当 HTML 元素（例如 `<div>`）的 CSS 属性 `overflow` 设置为 `auto`、`scroll` 或 `hidden` 时，并且其内容超出其尺寸时，就会创建一个可滚动区域，并可能最终关联到 `PaintLayerScrollableArea` 对象。
    ```html
    <div style="width: 200px; height: 100px; overflow: auto;">
      这是一个很长的内容，会导致滚动条出现。
    </div>
    ```
*   **CSS:**
    *   `overflow`:  决定是否以及如何显示滚动条。`PaintLayerScrollableArea` 会根据 `overflow` 的值来决定是否创建滚动条。
    *   `scroll-behavior: smooth;`:  指定滚动行为是否平滑。`PaintLayerScrollableArea` 会与平滑滚动机制交互。
    *   `scrollbar-width`, `scrollbar-color`, `scrollbar-gutter`:  这些 CSS 属性用于自定义滚动条的样式。`PaintLayerScrollableArea` 会考虑这些样式来渲染滚动条。
    *   `-webkit-overflow-scrolling: touch;`: 在 iOS 等触摸设备上启用惯性滚动。`PaintLayerScrollableArea` 需要处理这种类型的滚动。
    *   `resize`:  允许用户调整元素的大小，与 `PaintLayerScrollableArea` 中对 Resizer 的管理相关。
*   **JavaScript:**
    *   `element.scrollTo(x, y)` 或 `element.scrollLeft = x; element.scrollTop = y;`: JavaScript 代码可以编程方式地滚动元素。这些操作会触发 `PaintLayerScrollableArea` 中的滚动处理逻辑。
        ```javascript
        const element = document.getElementById('myDiv');
        element.scrollTo({ top: 100, behavior: 'smooth' });
        ```
    *   `element.scrollBy(deltaX, deltaY)`:  按相对量滚动元素，也会触发 `PaintLayerScrollableArea` 的处理。
    *   `element.addEventListener('scroll', function() { ... });`:  JavaScript 可以监听元素的 `scroll` 事件。当 `PaintLayerScrollableArea` 中的滚动偏移量发生变化时，会触发这些事件。

**逻辑推理的假设输入与输出:**

假设输入：用户通过鼠标滚轮向下滚动一个 `overflow: auto` 的 `<div>` 元素。

*   **假设：**
    1. 该 `<div>` 元素的内容高度大于其容器高度，因此存在垂直滚动条。
    2. 该 `<div>` 元素关联了一个 `PaintLayerScrollableArea` 对象。
    3. 浏览器的滚动事件监听器捕获了鼠标滚轮事件。
*   **输出：**
    1. `PaintLayerScrollableArea` 对象接收到滚动事件的通知。
    2. 根据滚轮的滚动量，计算出新的滚动偏移量。
    3. 更新内部的滚动偏移量状态。
    4. 如果启用了平滑滚动，则启动平滑滚动动画。
    5. 通知合成器进行相应的滚动更新。
    6. 触发该 `<div>` 元素的 `scroll` JavaScript 事件。
    7. 重新绘制受影响的区域，包括滚动条位置的更新。

**涉及用户或编程常见的使用错误，举例说明:**

1. **忘记设置 `overflow` 属性:** 用户可能期望一个元素可以滚动，但是忘记在 CSS 中设置 `overflow: auto` 或 `overflow: scroll`，导致内容溢出但不出现滚动条。`PaintLayerScrollableArea` 不会在没有明确指定可滚动性的情况下创建。
2. **过度依赖 JavaScript 滚动操作而不考虑性能:**  频繁地使用 JavaScript 来滚动一个包含大量内容的元素可能会导致性能问题。理解 `PaintLayerScrollableArea` 如何与合成器交互，可以帮助开发者更好地利用硬件加速滚动。
3. **错误地理解滚动事件的触发时机:**  开发者可能期望在每次像素级别的滚动变化时都触发 `scroll` 事件，但实际上出于性能考虑，事件可能会被合并或延迟触发。了解 `PaintLayerScrollableArea` 如何和何时触发 `scroll` 事件有助于避免此类误解。
4. **自定义滚动条样式与浏览器兼容性问题:**  过度依赖非标准的 CSS 属性来自定义滚动条样式可能导致跨浏览器兼容性问题。了解 `PaintLayerScrollableArea` 如何处理不同的滚动条渲染方式有助于解决这些问题。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载网页:** 用户在浏览器中打开一个包含可滚动内容的网页。
2. **浏览器解析 HTML 和 CSS:**  浏览器解析 HTML 结构和 CSS 样式。
3. **创建布局树:**  根据 HTML 和 CSS，浏览器构建布局树（Layout Tree），其中包含元素的几何信息和渲染属性。
4. **创建渲染层树 (Paint Tree):**  基于布局树，浏览器构建渲染层树。对于设置了 `overflow` 属性且内容溢出的元素，会创建对应的 `PaintLayer` 对象，并且可能会关联一个 `PaintLayerScrollableArea` 对象。
5. **用户执行滚动操作:** 用户使用鼠标滚轮、拖动滚动条、使用键盘方向键或触摸手势来滚动页面或特定的可滚动元素。
6. **事件处理:** 浏览器的事件处理机制捕获这些滚动操作。
7. **滚动更新:**  这些事件最终会触发 `PaintLayerScrollableArea` 对象中的方法，例如 `UpdateScrollOffset`，来更新滚动状态。
8. **渲染更新:**  滚动状态的改变会导致浏览器重新绘制或合成受影响的区域，以反映新的滚动位置。

**调试线索:**

当调试与滚动相关的问题时，可以关注以下几点：

*   **检查 HTML 结构和 CSS 样式:** 确保相关的元素设置了正确的 `overflow` 属性。
*   **断点调试 JavaScript 代码:** 如果使用了 JavaScript 滚动，可以在相关的滚动代码处设置断点，查看滚动操作是否按预期执行。
*   **使用浏览器开发者工具:**
    *   **Elements 面板:** 检查元素的 CSS 属性，确认 `overflow` 等属性的设置。
    *   **Performance 面板:**  分析滚动过程中的性能瓶颈，例如是否有过多的重绘或重排。
    *   **Layers 面板:** 查看渲染层结构，确认是否存在预期的 `PaintLayer` 和 `PaintLayerScrollableArea` 对象。
*   **Blink 内部调试工具:**  可以使用 Blink 提供的内部调试工具（例如 `chrome://tracing`）来更深入地了解滚动事件的处理流程和合成器的行为。

总而言之，`blink/renderer/core/paint/paint_layer_scrollable_area.cc` 是 Blink 渲染引擎中一个核心的文件，负责管理网页中可滚动区域的各种行为和属性，并与 HTML、CSS 和 JavaScript 的滚动相关功能紧密相连。理解其功能有助于开发者更好地理解浏览器如何处理滚动，并避免常见的错误。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_layer_scrollable_area.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2012 Apple Inc. All rights
 * reserved.
 *
 * Portions are Copyright (C) 1998 Netscape Communications Corporation.
 *
 * Other contributors:
 *   Robert O'Callahan <roc+@cs.cmu.edu>
 *   David Baron <dbaron@dbaron.org>
 *   Christian Biesinger <cbiesinger@gmail.com>
 *   Randall Jesup <rjesup@wgate.com>
 *   Roland Mainz <roland.mainz@informatik.med.uni-giessen.de>
 *   Josh Soref <timeless@mac.com>
 *   Boris Zbarsky <bzbarsky@mit.edu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Alternatively, the contents of this file may be used under the terms
 * of either the Mozilla Public License Version 1.1, found at
 * http://www.mozilla.org/MPL/ (the "MPL") or the GNU General Public
 * License Version 2.0, found at http://www.fsf.org/copyleft/gpl.html
 * (the "GPL"), in which case the provisions of the MPL or the GPL are
 * applicable instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of one of those two
 * licenses (the MPL or the GPL) and not to allow others to use your
 * version of this file under the LGPL, indicate your decision by
 * deletingthe provisions above and replace them with the notice and
 * other provisions required by the MPL or the GPL, as the case may be.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under any of the LGPL, the MPL or the GPL.
 */

#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"

#include <utility>

#include "base/numerics/checked_math.h"
#include "base/task/single_thread_task_runner.h"
#include "cc/animation/animation_timeline.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/input/snap_selection_strategy.h"
#include "cc/layers/picture_layer.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scrollbar_mode.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline.h"
#include "third_party/blink/renderer/core/content_capture/content_capture_manager.h"
#include "third_party/blink/renderer/core/core_probes_inl.h"
#include "third_party/blink/renderer/core/css/color_scheme_flags.h"
#include "third_party/blink/renderer/core/css/container_query_evaluator.h"
#include "third_party/blink/renderer/core/css/snapped_query_scroll_snapshot.h"
#include "third_party/blink/renderer/core/css/style_request.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_group_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/layout/layout_custom_scrollbar_part.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/legacy_layout_tree_walking.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/fragment_anchor.h"
#include "third_party/blink/renderer/core/page/scrolling/root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/sticky_position_scrolling_constraints.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/compositing/compositing_reason_finder.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_fragment.h"
#include "third_party/blink/renderer/core/scroll/programmatic_scroll_animator.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/event_timing.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/geometry/point_conversions.h"

namespace blink {

PaintLayerScrollableAreaRareData::PaintLayerScrollableAreaRareData() = default;

void PaintLayerScrollableAreaRareData::Trace(Visitor* visitor) const {
  visitor->Trace(snapped_query_snapshot_);
}

const int kResizerControlExpandRatioForTouch = 2;

PaintLayerScrollableArea::PaintLayerScrollableArea(PaintLayer& layer)
    : ScrollableArea(layer.GetLayoutBox()
                         ->GetDocument()
                         .GetPage()
                         ->GetAgentGroupScheduler()
                         .CompositorTaskRunner()),
      layer_(&layer),
      in_resize_mode_(false),
      scrolls_overflow_(false),
      needs_scroll_offset_clamp_(false),
      needs_relayout_(false),
      had_horizontal_scrollbar_before_relayout_(false),
      had_vertical_scrollbar_before_relayout_(false),
      had_resizer_before_relayout_(false),
      scroll_origin_changed_(false),
      is_scrollbar_freeze_root_(false),
      is_horizontal_scrollbar_frozen_(false),
      is_vertical_scrollbar_frozen_(false),
      scrollbar_manager_(*this),
      has_last_committed_scroll_offset_(false),
      scroll_corner_(nullptr),
      resizer_(nullptr),
      scroll_anchor_(this) {
  if (auto* element = DynamicTo<Element>(GetLayoutBox()->GetNode())) {
    // We save and restore only the scrollOffset as the other scroll values are
    // recalculated.
    scroll_offset_ = element->SavedLayerScrollOffset();
    if (!scroll_offset_.IsZero())
      GetScrollAnimator().SetCurrentOffset(scroll_offset_);
    element->SetSavedLayerScrollOffset(ScrollOffset());
  }

  if (RuntimeEnabledFeatures::UnifiedScrollableAreasEnabled()) {
    if (LocalFrameView* frame_view = GetLayoutBox()->GetFrameView()) {
      frame_view->AddScrollableArea(*this);
    }
  }
}

PaintLayerScrollableArea::~PaintLayerScrollableArea() {
  CHECK(HasBeenDisposed());
}

PaintLayerScrollableArea* PaintLayerScrollableArea::FromNode(const Node& node) {
  const LayoutBox* box = node.GetLayoutBox();
  return box ? box->GetScrollableArea() : nullptr;
}

void PaintLayerScrollableArea::DidCompositorScroll(
    const gfx::PointF& position) {
  ScrollableArea::DidCompositorScroll(position);
  // This should be alive if it receives composited scroll callbacks.
  CHECK(!HasBeenDisposed());
}

void PaintLayerScrollableArea::DisposeImpl() {
  rare_data_.Clear();

  if (InResizeMode() && !GetLayoutBox()->DocumentBeingDestroyed()) {
    if (LocalFrame* frame = GetLayoutBox()->GetFrame())
      frame->GetEventHandler().ResizeScrollableAreaDestroyed();
  }

  if (LocalFrameView* frame_view = GetLayoutBox()->GetFrameView()) {
    frame_view->RemoveScrollableArea(*this);
    probe::UpdateScrollableFlag(GetLayoutBox()->GetNode(), false);
  }

  if (!GetLayoutBox()->DocumentBeingDestroyed()) {
    if (auto* element = DynamicTo<Element>(GetLayoutBox()->GetNode()))
      element->SetSavedLayerScrollOffset(scroll_offset_);
  }

  // Note: it is not safe to call ScrollAnchor::clear if the document is being
  // destroyed, because LayoutObjectChildList::removeChildNode skips the call to
  // willBeRemovedFromTree,
  // leaving the ScrollAnchor with a stale LayoutObject pointer.
  scroll_anchor_.Dispose();

  GetLayoutBox()
      ->GetDocument()
      .GetPage()
      ->GlobalRootScrollerController()
      .DidDisposeScrollableArea(*this);

  scrollbar_manager_.Dispose();

  if (scroll_corner_)
    scroll_corner_->Destroy();
  if (resizer_)
    resizer_->Destroy();

  ClearScrollableArea();

  if (SmoothScrollSequencer* sequencer = GetSmoothScrollSequencer()) {
    sequencer->DidDisposeScrollableArea(*this);
  }

  RunScrollCompleteCallbacks(ScrollableArea::ScrollCompletionMode::kFinished);

  layer_ = nullptr;
}

void PaintLayerScrollableArea::ApplyPendingHistoryRestoreScrollOffset() {
  if (!pending_view_state_)
    return;

  // TODO(pnoland): attempt to restore the anchor in more places than this.
  // Anchor-based restore should allow for earlier restoration.
  bool did_restore = RestoreScrollAnchor(
      {pending_view_state_->state.scroll_anchor_data_, *this});
  if (!did_restore) {
    SetScrollOffset(pending_view_state_->state.scroll_offset_,
                    mojom::blink::ScrollType::kProgrammatic,
                    pending_view_state_->scroll_behavior);
  }

  pending_view_state_.reset();
}

void PaintLayerScrollableArea::SetTickmarksOverride(
    Vector<gfx::Rect> tickmarks) {
  EnsureRareData().tickmarks_override_ = std::move(tickmarks);
}

void PaintLayerScrollableArea::Trace(Visitor* visitor) const {
  visitor->Trace(scrollbar_manager_);
  visitor->Trace(scroll_corner_);
  visitor->Trace(resizer_);
  visitor->Trace(scroll_anchor_);
  visitor->Trace(scrolling_background_display_item_client_);
  visitor->Trace(scroll_corner_display_item_client_);
  visitor->Trace(layer_);
  visitor->Trace(rare_data_);
  ScrollableArea::Trace(visitor);
}

bool PaintLayerScrollableArea::IsThrottled() const {
  return GetLayoutBox()->GetFrame()->ShouldThrottleRendering();
}

ChromeClient* PaintLayerScrollableArea::GetChromeClient() const {
  if (HasBeenDisposed())
    return nullptr;
  if (Page* page = GetLayoutBox()->GetFrame()->GetPage())
    return &page->GetChromeClient();
  return nullptr;
}

SmoothScrollSequencer* PaintLayerScrollableArea::GetSmoothScrollSequencer()
    const {
  if (HasBeenDisposed())
    return nullptr;

  return GetLayoutBox()->GetFrame()->GetSmoothScrollSequencer();
}

bool PaintLayerScrollableArea::IsActive() const {
  Page* page = GetLayoutBox()->GetFrame()->GetPage();
  return page && page->GetFocusController().IsActive();
}

bool PaintLayerScrollableArea::IsScrollCornerVisible() const {
  return !ScrollCornerRect().IsEmpty();
}

static int CornerStart(const LayoutBox& box,
                       int min_x,
                       int max_x,
                       int thickness) {
  if (box.ShouldPlaceBlockDirectionScrollbarOnLogicalLeft())
    return min_x + box.StyleRef().BorderLeftWidth();
  return max_x - thickness - box.StyleRef().BorderRightWidth();
}

gfx::Rect PaintLayerScrollableArea::CornerRect() const {
  int horizontal_thickness;
  int vertical_thickness;
  if (!VerticalScrollbar() && !HorizontalScrollbar()) {
    // We need to know the thickness of custom scrollbars even when they don't
    // exist in order to set the resizer square size properly.
    horizontal_thickness = GetPageScrollbarTheme().ScrollbarThickness(
        ScaleFromDIP(), EScrollbarWidth::kAuto);
    vertical_thickness = horizontal_thickness;
  } else if (VerticalScrollbar() && !HorizontalScrollbar()) {
    horizontal_thickness = VerticalScrollbar()->ScrollbarThickness();
    vertical_thickness = horizontal_thickness;
  } else if (HorizontalScrollbar() && !VerticalScrollbar()) {
    vertical_thickness = HorizontalScrollbar()->ScrollbarThickness();
    horizontal_thickness = vertical_thickness;
  } else {
    horizontal_thickness = VerticalScrollbar()->ScrollbarThickness();
    vertical_thickness = HorizontalScrollbar()->ScrollbarThickness();
  }
  gfx::Size border_box_size = PixelSnappedBorderBoxSize();
  return gfx::Rect(CornerStart(*GetLayoutBox(), 0, border_box_size.width(),
                               horizontal_thickness),
                   border_box_size.height() - vertical_thickness -
                       GetLayoutBox()->StyleRef().BorderBottomWidth(),
                   horizontal_thickness, vertical_thickness);
}

gfx::Rect PaintLayerScrollableArea::ScrollCornerRect() const {
  // We have a scrollbar corner when a scrollbar is visible and not filling the
  // entire length of the box.
  // This happens when:
  // (a) A resizer is present and at least one scrollbar is present
  // (b) Both scrollbars are present.
  bool has_horizontal_bar = HorizontalScrollbar();
  bool has_vertical_bar = VerticalScrollbar();
  bool has_resizer = GetLayoutBox()->CanResize();
  if ((has_horizontal_bar && has_vertical_bar) ||
      (has_resizer && (has_horizontal_bar || has_vertical_bar))) {
    return CornerRect();
  }
  return gfx::Rect();
}

void PaintLayerScrollableArea::SetScrollCornerNeedsPaintInvalidation() {
  ScrollableArea::SetScrollCornerNeedsPaintInvalidation();
}

gfx::Rect
PaintLayerScrollableArea::ConvertFromScrollbarToContainingEmbeddedContentView(
    const Scrollbar& scrollbar,
    const gfx::Rect& scrollbar_rect) const {
  LayoutView* view = GetLayoutBox()->View();
  if (!view)
    return scrollbar_rect;

  gfx::Rect rect = scrollbar_rect;
  rect.Offset(ScrollbarOffset(scrollbar));
  return ToPixelSnappedRect(
      GetLayoutBox()->LocalToAbsoluteRect(PhysicalRect(rect)));
}

gfx::Point
PaintLayerScrollableArea::ConvertFromScrollbarToContainingEmbeddedContentView(
    const Scrollbar& scrollbar,
    const gfx::Point& scrollbar_point) const {
  LayoutView* view = GetLayoutBox()->View();
  if (!view)
    return scrollbar_point;

  gfx::Point point = scrollbar_point + ScrollbarOffset(scrollbar);
  return ToRoundedPoint(
      GetLayoutBox()->LocalToAbsolutePoint(PhysicalOffset(point)));
}

gfx::Point
PaintLayerScrollableArea::ConvertFromContainingEmbeddedContentViewToScrollbar(
    const Scrollbar& scrollbar,
    const gfx::Point& parent_point) const {
  LayoutView* view = GetLayoutBox()->View();
  if (!view)
    return parent_point;

  gfx::Point point = ToRoundedPoint(
      GetLayoutBox()->AbsoluteToLocalPoint(PhysicalOffset(parent_point)));
  point -= ScrollbarOffset(scrollbar);
  return point;
}

gfx::Point PaintLayerScrollableArea::ConvertFromRootFrame(
    const gfx::Point& point_in_root_frame) const {
  LayoutView* view = GetLayoutBox()->View();
  if (!view)
    return point_in_root_frame;

  return view->GetFrameView()->ConvertFromRootFrame(point_in_root_frame);
}

gfx::Point PaintLayerScrollableArea::ConvertFromRootFrameToVisualViewport(
    const gfx::Point& point_in_root_frame) const {
  LocalFrameView* frame_view = GetLayoutBox()->GetFrameView();
  DCHECK(frame_view);
  const auto* page = frame_view->GetPage();
  const auto& viewport = page->GetVisualViewport();
  return viewport.RootFrameToViewport(point_in_root_frame);
}

int PaintLayerScrollableArea::ScrollSize(
    ScrollbarOrientation orientation) const {
  gfx::Vector2d scroll_dimensions =
      MaximumScrollOffsetInt() - MinimumScrollOffsetInt();
  return (orientation == kHorizontalScrollbar) ? scroll_dimensions.x()
                                               : scroll_dimensions.y();
}

void PaintLayerScrollableArea::UpdateScrollOffset(
    const ScrollOffset& new_offset,
    mojom::blink::ScrollType scroll_type) {
  if (HasBeenDisposed() || GetScrollOffset() == new_offset)
    return;

  TRACE_EVENT2("blink", "PaintLayerScrollableArea::UpdateScrollOffset", "x",
               new_offset.x(), "y", new_offset.y());
  TRACE_EVENT_INSTANT1("blink", "Type", TRACE_EVENT_SCOPE_THREAD, "type",
                       scroll_type);

  LocalFrameView* frame_view = GetLayoutBox()->GetFrameView();
  CHECK(frame_view);

  // The ScrollOffsetTranslation paint property depends on the scroll offset.
  // (see: PaintPropertyTreeBuilder::UpdateScrollAndScrollTranslation).
  GetLayoutBox()->SetNeedsPaintPropertyUpdate();
  frame_view->UpdateIntersectionObservationStateOnScroll(new_offset -
                                                         scroll_offset_);

  scroll_offset_ = new_offset;

  LocalFrame* frame = GetLayoutBox()->GetFrame();
  DCHECK(frame);

  bool is_root_layer = Layer()->IsRootLayer();

  DEVTOOLS_TIMELINE_TRACE_EVENT(
      "ScrollLayer", inspector_scroll_layer_event::Data, GetLayoutBox());

  // Update the positions of our child layers (if needed as only fixed layers
  // should be impacted by a scroll).
  if (!frame_view->IsInPerformLayout()) {
    // Update regions, scrolling may change the clip of a particular region.
    frame_view->UpdateDocumentDraggableRegions();

    // As a performance optimization, the scroll offset of the root layer is
    // not included in EmbeddedContentView's stored frame rect, so there is no
    // reason to mark the FrameView as needing a geometry update here.
    if (is_root_layer)
      frame_view->SetRootLayerDidScroll();
    else
      frame_view->SetNeedsUpdateGeometries();
  }

  if (auto* scrolling_coordinator = GetScrollingCoordinator()) {
    if (!scrolling_coordinator->UpdateCompositorScrollOffset(*frame, *this)) {
      GetLayoutBox()->GetFrameView()->SetPaintArtifactCompositorNeedsUpdate();
    }
  }

  if (scroll_type == mojom::blink::ScrollType::kUser ||
      scroll_type == mojom::blink::ScrollType::kCompositor) {
    Page* page = frame->GetPage();
    if (page)
      page->GetChromeClient().ClearToolTip(*frame);
  }

  InvalidatePaintForScrollOffsetChange();

  // Don't enqueue a scroll event yet for scroll reasons that are not about
  // explicit changes to scroll. Instead, only do so at the time of the next
  // lifecycle update, to avoid scroll events that are out of date or don't
  // result in an actual scroll that is visible to the user. These scroll events
  // will then be dispatched at the *subsequent* animation frame, because
  // they happen after layout and therefore the next opportunity to fire the
  // events is at the next lifecycle update (*).
  //
  // (*) https://html.spec.whatwg.org/C/#update-the-rendering steps
  if (scroll_type == mojom::blink::ScrollType::kClamping ||
      scroll_type == mojom::blink::ScrollType::kAnchoring) {
    if (GetLayoutBox()->GetNode())
      frame_view->SetNeedsEnqueueScrollEvent(this);
  } else {
    EnqueueScrollEventIfNeeded();
  }

  GetLayoutBox()->View()->ClearHitTestCache();

  if (LocalDOMWindow* current_window = frame->DomWindow()) {
    WindowPerformance* window_performance =
        DOMWindowPerformance::performance(*current_window);
    window_performance->OnPageScroll();
  }

  // Inform the FrameLoader of the new scroll position, so it can be restored
  // when navigating back.
  if (is_root_layer) {
    frame_view->GetFrame().Loader().SaveScrollState();
    frame_view->DidChangeScrollOffset();
    if (scroll_type == mojom::blink::ScrollType::kCompositor ||
        scroll_type == mojom::blink::ScrollType::kUser) {
      if (DocumentLoader* document_loader = frame->Loader().GetDocumentLoader())
        document_loader->GetInitialScrollState().was_scrolled_by_user = true;
    }
  }

  if (FragmentAnchor* anchor = frame_view->GetFragmentAnchor())
    anchor->DidScroll(scroll_type);

  if (IsExplicitScrollType(scroll_type) ||
      scroll_type == mojom::blink::ScrollType::kScrollStart) {
    ShowNonMacOverlayScrollbars();
    GetScrollAnchor()->Clear();
  }
  if (ContentCaptureManager* manager = frame_view->GetFrame()
                                           .LocalFrameRoot()
                                           .GetOrResetContentCaptureManager()) {
    manager->OnScrollPositionChanged();
  }
  if (AXObjectCache* cache =
          GetLayoutBox()->GetDocument().ExistingAXObjectCache())
    cache->HandleScrollPositionChanged(GetLayoutBox());
}

void PaintLayerScrollableArea::InvalidatePaintForScrollOffsetChange() {
  InvalidatePaintForStickyDescendants();

  auto* box = GetLayoutBox();
  auto* frame_view = box->GetFrameView();
  frame_view->InvalidateBackgroundAttachmentFixedDescendantsOnScroll(*box);
  if (!box->BackgroundNeedsFullPaintInvalidation() &&
      BackgroundNeedsRepaintOnScroll()) {
    box->SetBackgroundNeedsFullPaintInvalidation();
  }

  if (auto* compositor = frame_view->GetPaintArtifactCompositor()) {
    if (compositor->ShouldAlwaysUpdateOnScroll()) {
      compositor->SetNeedsUpdate();
    }
  }
}

// See the comment in .h about background-attachment:fixed.
bool PaintLayerScrollableArea::BackgroundNeedsRepaintOnScroll() const {
  const auto* box = GetLayoutBox();
  auto background_paint_location = box->GetBackgroundPaintLocation();
  bool background_paint_in_border_box =
      background_paint_location & kBackgroundPaintInBorderBoxSpace;
  bool background_paint_in_scrolling_contents =
      background_paint_location & kBackgroundPaintInContentsSpace;

  const auto& background_layers = box->StyleRef().BackgroundLayers();
  if (background_layers.AnyLayerHasLocalAttachmentImage() &&
      background_paint_in_border_box) {
    // Local-attachment background image scrolls, so needs invalidation if it
    // paints in non-scrolling space.
    return true;
  }
  if (background_layers.AnyLayerHasDefaultAttachmentImage() &&
      background_paint_in_scrolling_contents) {
    // Normal attachment background image doesn't scroll, so needs
    // invalidation if it paints in scrolling contents.
    return true;
  }
  if (background_layers.AnyLayerHasLocalAttachment() &&
      background_layers.AnyLayerUsesContentBox() &&
      background_paint_in_border_box &&
      (box->PaddingLeft() || box->PaddingTop() || box->PaddingRight() ||
       box->PaddingBottom())) {
    // Local attachment content box background needs invalidation if there is
    // padding because the content area can change on scroll (e.g. the top
    // padding can disappear when the box scrolls to the bottom).
    return true;
  }
  return false;
}

gfx::Vector2d PaintLayerScrollableArea::ScrollOffsetInt() const {
  return SnapScrollOffsetToPhysicalPixels(scroll_offset_);
}

ScrollOffset PaintLayerScrollableArea::GetScrollOffset() const {
  return scroll_offset_;
}

void PaintLayerScrollableArea::EnqueueScrollEventIfNeeded() {
  if (scroll_offset_ == last_committed_scroll_offset_ &&
      has_last_committed_scroll_offset_)
    return;
  last_committed_scroll_offset_ = scroll_offset_;
  has_last_committed_scroll_offset_ = true;
  if (HasBeenDisposed())
    return;
  // Schedule the scroll DOM event.
  if (auto* node = EventTargetNode())
    node->GetDocument().EnqueueScrollEventForNode(node);
}

gfx::Vector2d PaintLayerScrollableArea::MinimumScrollOffsetInt() const {
  return -ScrollOrigin().OffsetFromOrigin();
}

gfx::Vector2d PaintLayerScrollableArea::MaximumScrollOffsetInt() const {
  if (!GetLayoutBox() || !GetLayoutBox()->IsScrollContainer())
    return -ScrollOrigin().OffsetFromOrigin();

  gfx::Size content_size = ContentsSize();

  Page* page = GetLayoutBox()->GetDocument().GetPage();
  DCHECK(page);
  TopDocumentRootScrollerController& controller =
      page->GlobalRootScrollerController();

  // The global root scroller should be clipped by the top LocalFrameView rather
  // than it's overflow clipping box. This is to ensure that content exposed by
  // hiding the URL bar at the bottom of the screen is visible.
  gfx::Size visible_size;
  if (this == controller.RootScrollerArea()) {
    visible_size = controller.RootScrollerVisibleArea();
  } else {
    visible_size = ToRoundedSize(
        GetLayoutBox()
            ->OverflowClipRect(PhysicalOffset(), kIgnoreOverlayScrollbarSize)
            .size);
  }

  // TODO(skobes): We should really ASSERT that contentSize >= visibleSize
  // when we are not the root layer, but we can't because contentSize is
  // based on stale scrollable overflow data (http://crbug.com/576933).
  content_size.SetToMax(visible_size);

  return -ScrollOrigin().OffsetFromOrigin() +
         gfx::Vector2d(content_size.width() - visible_size.width(),
                       content_size.height() - visible_size.height());
}

void PaintLayerScrollableArea::VisibleSizeChanged() {
  ShowNonMacOverlayScrollbars();
}

PhysicalRect PaintLayerScrollableArea::LayoutContentRect(
    IncludeScrollbarsInRect scrollbar_inclusion) const {
  // LayoutContentRect is conceptually the same as the box's client rect.
  PhysicalSize layer_size = Size();
  LayoutUnit border_width = GetLayoutBox()->BorderWidth();
  LayoutUnit border_height = GetLayoutBox()->BorderHeight();
  PhysicalBoxStrut scrollbars;
  if (scrollbar_inclusion == kExcludeScrollbars)
    scrollbars = GetLayoutBox()->ComputeScrollbars();

  PhysicalSize size(
      layer_size.width - border_width - scrollbars.HorizontalSum(),
      layer_size.height - border_height - scrollbars.VerticalSum());
  size.ClampNegativeToZero();
  return PhysicalRect(PhysicalOffset::FromPointFRound(ScrollPosition()), size);
}

gfx::Rect PaintLayerScrollableArea::VisibleContentRect(
    IncludeScrollbarsInRect scrollbar_inclusion) const {
  PhysicalRect layout_content_rect(LayoutContentRect(scrollbar_inclusion));
  // TODO(szager): It's not clear that Floor() is the right thing to do here;
  // what is the correct behavior for fractional scroll offsets?
  gfx::Size size = ToRoundedSize(layout_content_rect.size);
  return gfx::Rect(ToFlooredPoint(layout_content_rect.offset), size);
}

PhysicalRect PaintLayerScrollableArea::VisibleScrollSnapportRect(
    IncludeScrollbarsInRect scrollbar_inclusion) const {
  const ComputedStyle* style = GetLayoutBox()->Style();
  PhysicalRect layout_content_rect(LayoutContentRect(scrollbar_inclusion));
  layout_content_rect.Move(PhysicalOffset(-ScrollOrigin().OffsetFromOrigin()));
  PhysicalBoxStrut padding(MinimumValueForLength(style->ScrollPaddingTop(),
                                                 layout_content_rect.Height()),
                           MinimumValueForLength(style->ScrollPaddingRight(),
                                                 layout_content_rect.Width()),
                           MinimumValueForLength(style->ScrollPaddingBottom(),
                                                 layout_content_rect.Height()),
                           MinimumValueForLength(style->ScrollPaddingLeft(),
                                                 layout_content_rect.Width()));
  layout_content_rect.Contract(padding);
  return layout_content_rect;
}

gfx::Size PaintLayerScrollableArea::ContentsSize() const {
  // We need to take into account of ClientLeft and ClientTop  for
  // PaintLayerScrollableAreaTest.NotScrollsOverflowWithScrollableScrollbar.
  PhysicalOffset offset(GetLayoutBox()->ClientLeft(),
                        GetLayoutBox()->ClientTop());
  // TODO(crbug.com/962299): The pixel snapping is incorrect in some cases.
  return PixelSnappedContentsSize(offset);
}

gfx::Size PaintLayerScrollableArea::PixelSnappedContentsSize(
    const PhysicalOffset& paint_offset) const {
  PhysicalSize size = overflow_rect_.size;

  // If we're capturing a transition snapshot, ensure the content size is
  // considered at least as large as the container. Otherwise, the snapshot
  // will be clipped by PendingLayer to the content size.
  if (IsA<LayoutView>(GetLayoutBox())) {
    if (auto* transition =
            ViewTransitionUtils::GetTransition(GetLayoutBox()->GetDocument());
        transition && transition->IsRootTransitioning()) {
      PhysicalSize container_size(transition->GetSnapshotRootSize());
      size.width = std::max(container_size.width, size.width);
      size.height = std::max(container_size.height, size.height);
    }
  }

  return ToPixelSnappedRect(PhysicalRect(paint_offset, size)).size();
}

void PaintLayerScrollableArea::ContentsResized() {
  ScrollableArea::ContentsResized();
  // Need to update the bounds of the scroll property.
  GetLayoutBox()->SetNeedsPaintPropertyUpdate();
  Layer()->SetNeedsCompositingInputsUpdate();
  GetLayoutBox()->GetFrameView()->SetIntersectionObservationState(
      LocalFrameView::kDesired);
}

gfx::Point PaintLayerScrollableArea::LastKnownMousePosition() const {
  return GetLayoutBox()->GetFrame()
             ? gfx::ToFlooredPoint(GetLayoutBox()
                                       ->GetFrame()
                                       ->GetEventHandler()
                                       .LastKnownMousePositionInRootFrame())
             : gfx::Point();
}

bool PaintLayerScrollableArea::ScrollAnimatorEnabled() const {
  if (HasBeenDisposed())
    return false;
  if (Settings* settings = GetLayoutBox()->GetFrame()->GetSettings())
    return settings->GetScrollAnimatorEnabled();
  return false;
}

bool PaintLayerScrollableArea::ShouldSuspendScrollAnimations() const {
  if (HasBeenDisposed())
    return true;
  LayoutView* view = GetLayoutBox()->View();
  if (!view)
    return true;
  return !GetLayoutBox()->GetDocument().LoadEventFinished();
}

void PaintLayerScrollableArea::ScrollbarVisibilityChanged() {
  UpdateScrollbarEnabledState();

  // Paint properties need to be updated, because clip rects
  // are affected by overlay scrollbars.
  layer_->GetLayoutObject().SetNeedsPaintPropertyUpdate();

  if (LayoutView* view = GetLayoutBox()->View())
    view->ClearHitTestCache();
}

void PaintLayerScrollableArea::ScrollbarFrameRectChanged() {
  // TODO(crbug.com/1020913): This should be called only from layout once the
  // bug is fixed.

  // Size of non-overlay scrollbar affects overflow clip rect. size of overlay
  // scrollbar effects hit testing rect excluding overlay scrollbars.
  if (GetDocument()->Lifecycle().GetState() == DocumentLifecycle::kInPrePaint) {
    // In pre-paint we avoid marking the ancestor chain as this might cause
    // problems, see https://crbug.com/1377634. Note that we do not have
    // automated test case for this, so if you when modifying this code, please
    // verify that the test cases on the bug do no
```
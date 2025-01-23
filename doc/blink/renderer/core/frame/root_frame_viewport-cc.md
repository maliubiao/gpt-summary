Response:
Let's break down the thought process for analyzing this C++ source code file. The request asks for the file's functions, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning with examples, and common usage errors.

**1. Initial Understanding - Skimming and Identifying Key Components:**

The first step is to quickly skim the code, looking for keywords and structural elements. I see:

* **Copyright and Includes:** Standard C++ header. Indicates the file's ownership and dependencies. The includes give hints about the file's purpose (e.g., `ScrollableArea`, `VisualViewport`, `LayoutBox`).
* **Namespace `blink`:** This clearly identifies the file's context within the Chromium Blink rendering engine.
* **Class `RootFrameViewport`:** This is the core of the file. I note its inheritance (`ScrollableArea`) and member variables (`visual_viewport_`, `layout_viewport_`). This suggests the class manages the viewport at the root of a frame.
* **Methods:**  I start scanning for public methods. Names like `SetLayoutViewport`, `ScrollIntoView`, `SetScrollOffset`, `UserScroll`, and `VisibleContentRect` immediately stand out as related to viewport and scrolling operations.
* **Internal Namespace:** The anonymous namespace contains helper functions like `GetUserScrollableRect` and `MakeViewportScrollCompletion`. These seem like utility functions for internal calculations and callbacks related to scrolling.

**2. Deeper Analysis - Function by Function (Conceptual Grouping):**

Instead of meticulously going line by line, I start grouping methods based on their apparent purpose. This allows for a more organized understanding:

* **Initialization and Setup:**  `RootFrameViewport` (constructor), `SetLayoutViewport`. These set up the relationship between the `RootFrameViewport` and its associated `VisualViewport` and `LayoutViewport`.
* **Coordinate Transformations:** `RootContentsToLayoutViewportContents`, `LocalToVisibleContentQuad`. These handle the conversion of coordinates between different coordinate spaces within the rendering pipeline. This is crucial for correctly positioning and rendering content.
* **Scrolling Control:**  `SetScrollOffset`, `DistributeScrollBetweenViewports`, `UserScroll`, `ScrollIntoView`, `RestoreToAnchor`. These are the core functions for manipulating the scroll position of the viewport. I notice the distinction between user-initiated scrolls and programmatic scrolls. The `DistributeScrollBetweenViewports` method is particularly interesting, indicating how scrolling is coordinated between the visual and layout viewports.
* **Viewport Information:** `VisibleContentRect`, `VisibleScrollSnapportRect`, `ScrollSize`, `IsScrollCornerVisible`, `ScrollCornerRect`, `GetScrollOffset`, `MinimumScrollOffsetInt`, `MaximumScrollOffsetInt`, `ContentsSize`. These methods provide information about the current state and dimensions of the viewport.
* **Scrolling Behavior and Configuration:** `ShouldUseIntegerScrollOffset`, `ScrollBehaviorStyle`, `UsedColorSchemeScrollbars`, `ClampToUserScrollableOffset`. These control aspects of the scrolling experience, such as whether to use integer offsets, the default scroll behavior (smooth or instant), and scrollbar styling.
* **Scroll Restoration:** `ApplyPendingHistoryRestoreScrollOffset`. This function is related to navigating back and forth in the browser history and restoring the previous scroll position.
* **Integration with Compositor:**  Methods like `UsesCompositedScrolling`, `ShouldScrollOnMainThread`, `LayerForHorizontalScrollbar`, `LayerForVerticalScrollbar`, `UpdateCompositorScrollAnimations`, `DropCompositorScrollDeltaNextCommit`. These indicate the interaction with the compositor thread for smoother scrolling and rendering.
* **Scroll Snapping:**  Methods related to `SnapContainerData`, `SetTargetSnapAreaElementIds`, `GetSnapPositionAndSetTarget`, and related `cc::SnapSelectionStrategy` usage. This highlights the implementation of CSS scroll snapping features.
* **Event Handling (Implicit):** While not explicit event handlers, methods like `DidUpdateVisualViewport` and the callbacks in `SetScrollOffset` and `UserScroll` suggest that this class plays a role in responding to viewport changes and scroll events.

**3. Connecting to Web Technologies (HTML, CSS, JavaScript):**

Now, I consider how the functionality of `RootFrameViewport` relates to the user-facing aspects of web development:

* **HTML:** The structure defined in HTML affects the content that needs to be scrolled. The dimensions and layout of elements in the HTML DOM influence the scrollable area. The `ScrollIntoView` method directly relates to the JavaScript `element.scrollIntoView()` API.
* **CSS:** CSS properties like `overflow`, `scroll-behavior`, `scroll-padding`, and scroll snapping properties (`scroll-snap-type`, `scroll-snap-align`) directly influence the behavior managed by `RootFrameViewport`. The class checks and applies these styles.
* **JavaScript:** JavaScript can directly interact with the viewport through APIs like `window.scrollTo()`, `window.scrollBy()`, and `element.scrollIntoView()`. Event listeners for `scroll` events are also relevant. `RootFrameViewport` is the underlying implementation that makes these APIs work.

**4. Logical Reasoning and Examples:**

I try to think of scenarios and how the code would behave:

* **Assumption:** User tries to scroll beyond the content boundaries.
    * **Input:** A large scroll delta in `UserScroll`.
    * **Processing:** `ClampScrollOffset` and `ClampToUserScrollableOffset` would limit the scroll amount.
    * **Output:** The viewport scrolls only to the maximum/minimum allowed position.
* **Assumption:** JavaScript calls `element.scrollIntoView()`.
    * **Input:** A target element within the HTML.
    * **Processing:** `ScrollIntoView` calculates the necessary scroll offset based on the element's position and the specified alignment.
    * **Output:** The viewport scrolls so the target element is visible.
* **Assumption:** CSS `scroll-behavior: smooth` is applied.
    * **Processing:**  `SetScrollOffset` would use the `SmoothScrollSequencer` to animate the scroll transition.
    * **Output:** A smooth scrolling animation instead of an immediate jump.

**5. Common Usage Errors (from a developer's perspective):**

I consider potential pitfalls when interacting with the concepts this code represents:

* **Incorrectly calculating scroll offsets in JavaScript:**  Developers might make errors when manually calculating scroll positions, leading to unexpected scrolling behavior. Understanding the different coordinate spaces is crucial.
* **Conflicting CSS scroll settings:**  Applying contradictory scroll-related CSS properties could lead to undefined behavior.
* **Not accounting for viewport size changes:**  If the viewport size changes (e.g., window resize), hardcoded scroll offsets might become invalid.
* **Over-reliance on instant scrolling:**  Using `scroll-behavior: auto` (which might default to instant) when smooth scrolling is desired can create a jarring user experience.
* **Misunderstanding the interaction between visual and layout viewport:**  Developers might not fully grasp how scrolling is distributed between these two, leading to unexpected behavior when manipulating scroll positions.

**6. Refinement and Structuring the Answer:**

Finally, I organize the information into the requested categories: functions, relationship to web technologies, logical reasoning, and common errors. I use clear language and provide concrete examples to illustrate the concepts. I ensure the answer directly addresses all parts of the prompt.
好的，我们来分析一下 `blink/renderer/core/frame/root_frame_viewport.cc` 这个文件。

**主要功能:**

`RootFrameViewport` 类在 Chromium Blink 渲染引擎中扮演着管理**根框架（main frame）的视口（viewport）**的关键角色。它主要负责以下功能：

1. **管理和协调视觉视口（VisualViewport）和布局视口（LayoutViewport）：**  `RootFrameViewport` 自身继承自 `ScrollableArea`，并且组合了 `VisualViewport` 和 `LayoutViewport` 两个 `ScrollableArea` 实例。它负责在两者之间协调滚动和缩放操作。
    * **布局视口 (LayoutViewport):**  代表了页面的完整内容区域，即使某些内容当前不可见。它的尺寸由页面的布局决定。
    * **视觉视口 (VisualViewport):** 代表了用户在屏幕上实际看到的内容区域。用户可以通过缩放（pinch-zoom）来改变视觉视口的大小和位置。

2. **处理和分发滚动事件：** 接收来自用户或程序触发的滚动请求，并决定如何分配到视觉视口和布局视口。例如，用户滚动可能主要影响视觉视口，而 JavaScript 代码的 `scrollTo` 操作可能需要同时调整两者。

3. **处理缩放操作：**  与 `VisualViewport` 协同工作，处理用户的捏合缩放手势，并更新视觉视口的缩放比例和位置。

4. **实现 `scrollIntoView` 功能：**  当 JavaScript 调用 `element.scrollIntoView()` 时，`RootFrameViewport` 负责计算需要滚动的偏移量，并将目标元素滚动到可见区域。

5. **处理历史记录的滚动恢复：**  当用户在浏览历史记录中前进或后退时，`RootFrameViewport` 负责恢复到之前的滚动位置和缩放级别。

6. **提供视口相关的各种信息：**  例如，可见内容区域的大小、滚动范围、当前滚动偏移量等。

7. **处理滚动吸附 (Scroll Snapping):**  支持 CSS 的滚动吸附特性，确保滚动停止在预定义的吸附点上。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`RootFrameViewport` 的功能与 JavaScript, HTML, 和 CSS 都有着密切的关系：

* **JavaScript:**
    * **`window.scrollTo(x, y)` 和 `window.scrollBy(dx, dy)`:**  当 JavaScript 调用这些方法时，最终会触发 `RootFrameViewport::SetScrollOffset` 来更新视口的滚动位置。
        * **假设输入：** JavaScript 代码执行 `window.scrollTo(100, 200)`。
        * **输出：** `RootFrameViewport` 会尝试将视口滚动到 x=100, y=200 的位置。
    * **`element.scrollIntoView()`:**  此方法直接依赖于 `RootFrameViewport::ScrollIntoView` 的实现。
        * **假设输入：** JavaScript 代码执行 `document.getElementById('targetElement').scrollIntoView({ behavior: 'smooth', block: 'center' })`。
        * **输出：** `RootFrameViewport` 会计算必要的滚动偏移，并可能执行平滑滚动动画，使 `targetElement` 在视口中间可见。
    * **`window.visualViewport` API:** JavaScript 可以通过 `window.visualViewport` API 获取和监听视觉视口的变化事件（例如 `scroll` 和 `resize`）。这些事件的触发和视口状态的更新都与 `RootFrameViewport` 的操作相关。

* **HTML:**
    * **`<iframe>` 元素：** 每个 `<iframe>` 元素都有自己的 `RootFrameViewport` 实例，负责管理其内部文档的视口。
    * **页面的内容结构：** HTML 定义了页面的内容和布局，这决定了布局视口的大小和滚动范围，进而影响 `RootFrameViewport` 的行为。

* **CSS:**
    * **`overflow: auto` 或 `overflow: scroll`：**  这些 CSS 属性会影响元素是否可以滚动，以及是否显示滚动条。`RootFrameViewport` 会考虑这些属性来确定视口的滚动行为。
    * **`scroll-behavior: smooth`：**  当 CSS 设置了平滑滚动时，`RootFrameViewport` 会使用 `SmoothScrollSequencer` 来实现动画效果。
        * **假设输入：** CSS 样式包含 `html { scroll-behavior: smooth; }`。
        * **输出：** 当用户滚动或 JavaScript 调用滚动方法时，`RootFrameViewport` 会执行平滑的滚动动画。
    * **滚动吸附相关的 CSS 属性 (`scroll-snap-type`, `scroll-snap-align` 等)：** `RootFrameViewport` 会解析这些 CSS 属性，并在用户滚动结束时，将视口调整到最近的吸附点。
    * **`scroll-padding`：** CSS 的 `scroll-padding` 属性会影响 `scrollIntoView` 等操作的计算，`RootFrameViewport::VisibleScrollSnapportRect` 中就使用了 `scroll-padding` 来计算有效的滚动吸附区域。

**逻辑推理与假设输入输出:**

* **假设输入：** 用户通过触摸屏向上滑动。
* **处理流程：**
    1. 触摸事件被转换为滚动事件。
    2. `RootFrameViewport::UserScroll` 被调用，接收滚动的 `delta`。
    3. `UserScroll` 方法会考虑视觉视口和布局视口当前的滚动状态，以及是否启用了平滑滚动。
    4. 如果启用了平滑滚动，`UserScroll` 可能会将滚动请求传递给 `ScrollAnimator` 进行动画处理。
    5. 最终，视觉视口和/或布局视口的滚动偏移量会被更新。
* **输出：** 页面内容向上滚动，视觉上呈现新的内容。

* **假设输入：** JavaScript 代码调用 `window.scrollTo(0, document.body.scrollHeight)`，尝试滚动到页面底部。
* **处理流程：**
    1. `RootFrameViewport::SetScrollOffset` 被调用，目标偏移量为 `(0, document.body.scrollHeight)`。
    2. `SetScrollOffset` 会调用 `ClampScrollOffset` 来确保目标偏移量在有效范围内。
    3. `DistributeScrollBetweenViewports` 方法可能会被调用，以协调视觉视口和布局视口的滚动。
    4. 最终，视口滚动到接近页面底部的位置。
* **输出：** 页面滚动到接近底部的状态。

**用户或编程常见的使用错误:**

1. **在 JavaScript 中直接操作内部的 `VisualViewport` 或 `LayoutViewport` 对象（如果可以访问的话）：**  这可能会绕过 `RootFrameViewport` 的协调逻辑，导致不一致的视口状态或意外的行为。应该始终通过 `window` 对象提供的 API 来操作视口。

2. **不理解视觉视口和布局视口的区别，导致滚动行为的困惑：** 例如，在缩放的情况下，布局视口的大小不变，但视觉视口的大小和偏移会变化。开发者需要在 JavaScript 中正确处理这两种视口的关系。

3. **错误地计算滚动偏移量：** 在 JavaScript 中手动计算滚动偏移量时，可能会出现错误，导致滚动到错误的位置。应该尽量使用浏览器提供的 API，并理解不同坐标系之间的转换。

4. **过度依赖即时滚动，忽略平滑滚动带来的用户体验提升：**  在需要更流畅的交互时，应该考虑使用 CSS 的 `scroll-behavior: smooth` 或 JavaScript 的 `scrollIntoView` 方法的 `behavior: 'smooth'` 选项。

5. **在处理滚动事件时，没有考虑到滚动吸附的影响：** 如果页面启用了滚动吸附，滚动停止的位置可能与预期的略有不同。开发者在处理滚动完成后的逻辑时，需要注意这一点。

总而言之，`RootFrameViewport` 是 Blink 渲染引擎中负责管理和协调根框架视口的核心组件，它直接影响着用户与网页的交互体验，并与 JavaScript, HTML, 和 CSS 的各种特性紧密相关。理解它的功能对于开发高性能和用户体验良好的 Web 应用至关重要。

### 提示词
```
这是目录为blink/renderer/core/frame/root_frame_viewport.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"

#include "base/barrier_callback.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/task/single_thread_task_runner.h"
#include "cc/input/snap_selection_strategy.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/scroll_anchor.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {
namespace {
// Computes the rect of valid scroll offsets reachable by user scrolls for the
// scrollable area.
gfx::RectF GetUserScrollableRect(const ScrollableArea& area) {
  gfx::RectF user_scrollable_rect;
  ScrollOffset scrollable_size =
      area.MaximumScrollOffset() - area.MinimumScrollOffset();
  if (area.UserInputScrollable(kHorizontalScrollbar)) {
    user_scrollable_rect.set_x(area.MinimumScrollOffset().x());
    user_scrollable_rect.set_width(scrollable_size.x());
  } else {
    user_scrollable_rect.set_x(area.GetScrollOffset().x());
    user_scrollable_rect.set_width(0);
  }

  if (area.UserInputScrollable(kVerticalScrollbar)) {
    user_scrollable_rect.set_y(area.MinimumScrollOffset().y());
    user_scrollable_rect.set_height(scrollable_size.y());
  } else {
    user_scrollable_rect.set_y(area.GetScrollOffset().y());
    user_scrollable_rect.set_height(0);
  }
  return user_scrollable_rect;
}

static base::RepeatingCallback<void(ScrollableArea::ScrollCompletionMode)>
MakeViewportScrollCompletion(ScrollableArea::ScrollCallback callback) {
  return callback
             ? base::BarrierCallback<ScrollableArea::ScrollCompletionMode>(
                   2, WTF::BindOnce(
                          [](ScrollableArea::ScrollCallback on_finish,
                             const std::vector<
                                 ScrollableArea::ScrollCompletionMode>
                                 completion_modes) {
                            auto completion_mode =
                                ScrollableArea::ScrollCompletionMode::kFinished;
                            for (auto mode : completion_modes) {
                              if (mode == ScrollableArea::ScrollCompletionMode::
                                              kInterruptedByScroll) {
                                completion_mode = ScrollableArea::
                                    ScrollCompletionMode::kInterruptedByScroll;
                              }
                            }
                            std::move(on_finish).Run(completion_mode);
                          },
                          std::move(callback)))
             : base::RepeatingCallback<void(
                   ScrollableArea::ScrollCompletionMode)>();
}

}  // namespace
RootFrameViewport::RootFrameViewport(ScrollableArea& visual_viewport,
                                     ScrollableArea& layout_viewport)
    : ScrollableArea(visual_viewport.GetCompositorTaskRunner()),
      visual_viewport_(visual_viewport),
      should_restore_scroll_(false) {
  SetLayoutViewport(layout_viewport);
}

void RootFrameViewport::SetLayoutViewport(ScrollableArea& new_layout_viewport) {
  if (layout_viewport_.Get() == &new_layout_viewport)
    return;

  if (layout_viewport_ && layout_viewport_->GetScrollAnchor())
    layout_viewport_->GetScrollAnchor()->SetScroller(layout_viewport_.Get());

  layout_viewport_ = &new_layout_viewport;

  if (layout_viewport_->GetScrollAnchor())
    layout_viewport_->GetScrollAnchor()->SetScroller(this);
}

ScrollableArea& RootFrameViewport::LayoutViewport() const {
  DCHECK(layout_viewport_);
  return *layout_viewport_;
}

PhysicalRect RootFrameViewport::RootContentsToLayoutViewportContents(
    LocalFrameView& root_frame_view,
    const PhysicalRect& rect) const {
  PhysicalRect ret = rect;

  // If the root LocalFrameView is the layout viewport then coordinates in the
  // root LocalFrameView's content space are already in the layout viewport's
  // content space.
  if (root_frame_view.LayoutViewport() == &LayoutViewport())
    return ret;

  // Make the given rect relative to the top of the layout viewport's content
  // by adding the scroll position.
  // TODO(bokan): This will have to be revisited if we ever remove the
  // restriction that a root scroller must be exactly screen filling.
  ret.Move(
      PhysicalOffset::FromVector2dFRound(LayoutViewport().GetScrollOffset()));

  return ret;
}

void RootFrameViewport::RestoreToAnchor(const ScrollOffset& target_offset) {
  // Clamp the scroll offset of each viewport now so that we force any invalid
  // offsets to become valid so we can compute the correct deltas.
  GetVisualViewport().SetScrollOffset(GetVisualViewport().GetScrollOffset(),
                                      mojom::blink::ScrollType::kAnchoring);
  LayoutViewport().SetScrollOffset(LayoutViewport().GetScrollOffset(),
                                   mojom::blink::ScrollType::kAnchoring);

  ScrollOffset delta = target_offset - GetScrollOffset();

  GetVisualViewport().SetScrollOffset(
      GetVisualViewport().GetScrollOffset() + delta,
      mojom::blink::ScrollType::kAnchoring);

  delta = target_offset - GetScrollOffset();

  if (RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled()) {
    LayoutViewport().SetScrollOffset(LayoutViewport().GetScrollOffset() + delta,
                                     mojom::blink::ScrollType::kAnchoring);
  } else {
    gfx::Vector2d layout_delta(
        delta.x() < 0 ? floor(delta.x()) : ceil(delta.x()),
        delta.y() < 0 ? floor(delta.y()) : ceil(delta.y()));

    LayoutViewport().SetScrollOffset(
        ScrollOffset(LayoutViewport().ScrollOffsetInt() + layout_delta),
        mojom::blink::ScrollType::kAnchoring);
  }

  delta = target_offset - GetScrollOffset();
  GetVisualViewport().SetScrollOffset(
      GetVisualViewport().GetScrollOffset() + delta,
      mojom::blink::ScrollType::kAnchoring);
}

void RootFrameViewport::DidUpdateVisualViewport() {
  if (ScrollAnchor* anchor = LayoutViewport().GetScrollAnchor())
    anchor->Clear();
}

LayoutBox* RootFrameViewport::GetLayoutBox() const {
  return LayoutViewport().GetLayoutBox();
}

gfx::QuadF RootFrameViewport::LocalToVisibleContentQuad(
    const gfx::QuadF& quad,
    const LayoutObject* local_object,
    unsigned flags) const {
  if (!layout_viewport_)
    return quad;
  gfx::QuadF viewport_quad =
      layout_viewport_->LocalToVisibleContentQuad(quad, local_object, flags);
  if (visual_viewport_) {
    viewport_quad = visual_viewport_->LocalToVisibleContentQuad(
        viewport_quad, local_object, flags);
  }
  return viewport_quad;
}

scoped_refptr<base::SingleThreadTaskRunner>
RootFrameViewport::GetTimerTaskRunner() const {
  return LayoutViewport().GetTimerTaskRunner();
}

int RootFrameViewport::HorizontalScrollbarHeight(
    OverlayScrollbarClipBehavior behavior) const {
  return LayoutViewport().HorizontalScrollbarHeight(behavior);
}

int RootFrameViewport::VerticalScrollbarWidth(
    OverlayScrollbarClipBehavior behavior) const {
  return LayoutViewport().VerticalScrollbarWidth(behavior);
}

void RootFrameViewport::UpdateScrollAnimator() {
  GetScrollAnimator().SetCurrentOffset(ScrollOffsetFromScrollAnimators());
}

ScrollOffset RootFrameViewport::ScrollOffsetFromScrollAnimators() const {
  return GetVisualViewport().GetScrollAnimator().CurrentOffset() +
         LayoutViewport().GetScrollAnimator().CurrentOffset();
}

gfx::Rect RootFrameViewport::VisibleContentRect(
    IncludeScrollbarsInRect scrollbar_inclusion) const {
  return gfx::Rect(
      gfx::PointAtOffsetFromOrigin(ScrollOffsetInt()),
      GetVisualViewport().VisibleContentRect(scrollbar_inclusion).size());
}

PhysicalRect RootFrameViewport::VisibleScrollSnapportRect(
    IncludeScrollbarsInRect scrollbar_inclusion) const {
  // The effective viewport is the intersection of the visual viewport with the
  // layout viewport.
  PhysicalRect frame_rect_in_content(
      PhysicalOffset::FromVector2dFRound(LayoutViewport().GetScrollOffset()),
      PhysicalSize(
          LayoutViewport().VisibleContentRect(scrollbar_inclusion).size()));
  PhysicalRect visual_rect_in_content(
      PhysicalOffset::FromVector2dFRound(
          LayoutViewport().GetScrollOffset() +
          GetVisualViewport().GetScrollAnimator().CurrentOffset()),
      PhysicalSize(
          GetVisualViewport().VisibleContentRect(scrollbar_inclusion).size()));

  PhysicalRect visible_scroll_snapport =
      Intersection(visual_rect_in_content, frame_rect_in_content);
  if (!LayoutViewport().GetLayoutBox())
    return visible_scroll_snapport;

  const ComputedStyle* style = LayoutViewport().GetLayoutBox()->Style();
  visible_scroll_snapport.ContractEdges(
      MinimumValueForLength(style->ScrollPaddingTop(),
                            visible_scroll_snapport.Height()),
      MinimumValueForLength(style->ScrollPaddingRight(),
                            visible_scroll_snapport.Width()),
      MinimumValueForLength(style->ScrollPaddingBottom(),
                            visible_scroll_snapport.Height()),
      MinimumValueForLength(style->ScrollPaddingLeft(),
                            visible_scroll_snapport.Width()));

  return visible_scroll_snapport;
}

bool RootFrameViewport::ShouldUseIntegerScrollOffset() const {
  // Fractionals are floored in the ScrollAnimatorBase but it's important that
  // the ScrollAnimators of the visual and layout viewports get the precise
  // fractional number so never use integer scrolling for RootFrameViewport,
  // we'll let the truncation happen in the subviewports.
  return false;
}

bool RootFrameViewport::IsActive() const {
  return LayoutViewport().IsActive();
}

int RootFrameViewport::ScrollSize(ScrollbarOrientation orientation) const {
  gfx::Vector2d scroll_dimensions =
      MaximumScrollOffsetInt() - MinimumScrollOffsetInt();
  return (orientation == kHorizontalScrollbar) ? scroll_dimensions.x()
                                               : scroll_dimensions.y();
}

bool RootFrameViewport::IsScrollCornerVisible() const {
  return LayoutViewport().IsScrollCornerVisible();
}

gfx::Rect RootFrameViewport::ScrollCornerRect() const {
  return LayoutViewport().ScrollCornerRect();
}

void RootFrameViewport::ApplyPendingHistoryRestoreScrollOffset() {
  if (!pending_view_state_)
    return;

  bool should_restore_scale = pending_view_state_->page_scale_factor_;

  // For main frame restore scale and visual viewport position
  ScrollOffset visual_viewport_offset(
      pending_view_state_->visual_viewport_scroll_offset_);

  // If the visual viewport's offset is (-1, -1) it means the history item
  // is an old version of HistoryItem so distribute the scroll between
  // the main frame and the visual viewport as best as we can.
  if (visual_viewport_offset.x() == -1 && visual_viewport_offset.y() == -1) {
    visual_viewport_offset = pending_view_state_->scroll_offset_ -
                             LayoutViewport().GetScrollOffset();
  }

  auto* visual_viewport = static_cast<VisualViewport*>(&GetVisualViewport());
  if (should_restore_scale && should_restore_scroll_) {
    visual_viewport->SetScaleAndLocation(
        pending_view_state_->page_scale_factor_,
        visual_viewport->IsPinchGestureActive(),
        gfx::PointAtOffsetFromOrigin(visual_viewport_offset));
  } else if (should_restore_scale) {
    visual_viewport->SetScale(pending_view_state_->page_scale_factor_);
  } else if (should_restore_scroll_) {
    visual_viewport->SetLocation(
        gfx::PointAtOffsetFromOrigin(visual_viewport_offset));
  }

  should_restore_scroll_ = false;

  pending_view_state_.reset();
}

bool RootFrameViewport::SetScrollOffset(
    const ScrollOffset& offset,
    mojom::blink::ScrollType scroll_type,
    mojom::blink::ScrollBehavior scroll_behavior,
    ScrollCallback on_finish) {
  UpdateScrollAnimator();

  if (scroll_behavior == mojom::blink::ScrollBehavior::kAuto)
    scroll_behavior = ScrollBehaviorStyle();

  if (scroll_type == mojom::blink::ScrollType::kAnchoring) {
    return DistributeScrollBetweenViewports(offset, scroll_type,
                                            scroll_behavior, kLayoutViewport,
                                            std::move(on_finish));
  }

  if (scroll_behavior == mojom::blink::ScrollBehavior::kSmooth) {
    return DistributeScrollBetweenViewports(offset, scroll_type,
                                            scroll_behavior, kVisualViewport,
                                            std::move(on_finish));
  }

  ScrollOffset clamped_offset = ClampScrollOffset(offset);
  return ScrollableArea::SetScrollOffset(clamped_offset, scroll_type,
                                         scroll_behavior, std::move(on_finish));
}

mojom::blink::ScrollBehavior RootFrameViewport::ScrollBehaviorStyle() const {
  return LayoutViewport().ScrollBehaviorStyle();
}

mojom::blink::ColorScheme RootFrameViewport::UsedColorSchemeScrollbars() const {
  return LayoutViewport().UsedColorSchemeScrollbars();
}

ScrollOffset RootFrameViewport::ClampToUserScrollableOffset(
    const ScrollOffset& offset) const {
  ScrollOffset scroll_offset = offset;
  gfx::RectF layout_scrollable = GetUserScrollableRect(LayoutViewport());
  gfx::RectF visual_scrollable = GetUserScrollableRect(GetVisualViewport());
  gfx::RectF user_scrollable(
      layout_scrollable.origin() + visual_scrollable.OffsetFromOrigin(),
      layout_scrollable.size() + visual_scrollable.size());
  scroll_offset.set_x(
      ClampTo(scroll_offset.x(), user_scrollable.x(), user_scrollable.right()));
  scroll_offset.set_y(ClampTo(scroll_offset.y(), user_scrollable.y(),
                              user_scrollable.bottom()));
  return scroll_offset;
}

PhysicalOffset RootFrameViewport::LocalToScrollOriginOffset() const {
  if (GetLayoutBox() &&
      RuntimeEnabledFeatures::ScrollIntoViewRootFrameViewportBugFixEnabled()) {
    return LayoutViewport().LocalToScrollOriginOffset();
  }
  return PhysicalOffset::FromVector2dFFloor(LayoutViewport().GetScrollOffset());
}

PhysicalRect RootFrameViewport::ScrollIntoView(
    const PhysicalRect& rect_in_absolute,
    const PhysicalBoxStrut& scroll_margin,
    const mojom::blink::ScrollIntoViewParamsPtr& params) {
  ScrollOffset new_scroll_offset =
      ClampScrollOffset(scroll_into_view_util::GetScrollOffsetToExpose(
          *this, rect_in_absolute, scroll_margin, *params->align_x.get(),
          *params->align_y.get()));
  if (params->type == mojom::blink::ScrollType::kUser)
    new_scroll_offset = ClampToUserScrollableOffset(new_scroll_offset);

  gfx::PointF end_point = ScrollOffsetToPosition(new_scroll_offset);
  std::unique_ptr<cc::SnapSelectionStrategy> strategy =
      cc::SnapSelectionStrategy::CreateForEndPosition(end_point, true, true);
  if (GetLayoutBox()) {
    end_point = GetSnapPositionAndSetTarget(*strategy).value_or(end_point);
    new_scroll_offset = ScrollPositionToOffset(end_point);
  }

  if (new_scroll_offset != GetScrollOffset()) {
    if (params->is_for_scroll_sequence) {
      mojom::blink::ScrollBehavior behavior = DetermineScrollBehavior(
          params->behavior, GetLayoutBox()->StyleRef().GetScrollBehavior());
      if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
        ScrollableArea::SetScrollOffset(new_scroll_offset, params->type,
                                        behavior);
      } else {
        CHECK(GetSmoothScrollSequencer());
        DCHECK(params->type == mojom::blink::ScrollType::kProgrammatic ||
               params->type == mojom::blink::ScrollType::kUser);
        GetSmoothScrollSequencer()->QueueAnimation(this, new_scroll_offset,
                                                   behavior);
      }
    } else {
      ScrollableArea::SetScrollOffset(new_scroll_offset, params->type);
    }
  }

  // Return the newly moved rect to absolute coordinates.
  // TODO(szager): PaintLayerScrollableArea::ScrollIntoView clips the return
  // value to the visible content rect, but this does not.
  // TODO(bokan): This returns an unchanged rect for scroll sequences (the PLSA
  // version correctly computes what the rect will be when the sequence is
  // executed) and we can't just adjust by `new_scroll_offset` since, to get to
  // absolute coordinates, we must offset by only the layout viewport's scroll.
  return rect_in_absolute;
}

void RootFrameViewport::UpdateScrollOffset(
    const ScrollOffset& offset,
    mojom::blink::ScrollType scroll_type) {
  DistributeScrollBetweenViewports(offset, scroll_type,
                                   mojom::blink::ScrollBehavior::kInstant,
                                   kVisualViewport);
}

bool RootFrameViewport::DistributeScrollBetweenViewports(
    const ScrollOffset& offset,
    mojom::blink::ScrollType scroll_type,
    mojom::blink::ScrollBehavior behavior,
    ViewportToScrollFirst scroll_first,
    ScrollCallback on_finish) {
  // Make sure we use the scroll offsets as reported by each viewport's
  // ScrollAnimatorBase, since its ScrollableArea's offset may have the
  // fractional part truncated off.
  // TODO(szager): Now that scroll offsets are stored as floats, can we take the
  // scroll offset directly from the ScrollableArea's rather than the animators?
  ScrollOffset old_offset = ScrollOffsetFromScrollAnimators();

  ScrollOffset delta = offset - old_offset;

  if (delta.IsZero()) {
    if (on_finish) {
      std::move(on_finish).Run(
          ScrollableArea::ScrollCompletionMode::kZeroDelta);
    }
    return false;
  }

  ScrollableArea& primary =
      scroll_first == kVisualViewport ? GetVisualViewport() : LayoutViewport();
  ScrollableArea& secondary =
      scroll_first == kVisualViewport ? LayoutViewport() : GetVisualViewport();

  // Compute the clamped offsets for both viewports before performing any
  // scrolling since the order of distribution can vary (and is typically
  // visualViewport-first) but, per-spec, if we scroll both viewports the
  // scroll event must be sent to the DOMWindow first, then to the
  // VisualViewport. Thus, we'll always perform the scrolls in that order,
  // regardless of the order of distribution.
  ScrollOffset primary_offset = primary.ClampScrollOffset(
      primary.GetScrollAnimator().CurrentOffset() + delta);
  ScrollOffset unconsumed_by_primary =
      (primary.GetScrollAnimator().CurrentOffset() + delta) - primary_offset;
  ScrollOffset secondary_offset = secondary.ClampScrollOffset(
      secondary.GetScrollAnimator().CurrentOffset() + unconsumed_by_primary);

  auto all_done = MakeViewportScrollCompletion(std::move(on_finish));

  // DistributeScrollBetweenViewports can be called from SetScrollOffset,
  // so we assume that aborting sequenced smooth scrolls has been handled.
  // It can also be called from inside an animation to set the offset in
  // each frame. In that case, we shouldn't abort sequenced smooth scrolls.

  // Actually apply the scroll the layout viewport first so that the DOM event
  // is dispatched to the DOMWindow before the VisualViewport.
  bool did_scroll = LayoutViewport().SetScrollOffset(
      scroll_first == kLayoutViewport ? primary_offset : secondary_offset,
      scroll_type, behavior, all_done);
  did_scroll |= GetVisualViewport().SetScrollOffset(
      scroll_first == kVisualViewport ? primary_offset : secondary_offset,
      scroll_type, behavior, all_done);
  return did_scroll;
}

gfx::Vector2d RootFrameViewport::ScrollOffsetInt() const {
  return SnapScrollOffsetToPhysicalPixels(GetScrollOffset());
}

ScrollOffset RootFrameViewport::GetScrollOffset() const {
  return LayoutViewport().GetScrollOffset() +
         GetVisualViewport().GetScrollOffset();
}

gfx::Vector2d RootFrameViewport::MinimumScrollOffsetInt() const {
  return LayoutViewport().MinimumScrollOffsetInt() +
         GetVisualViewport().MinimumScrollOffsetInt();
}

gfx::Vector2d RootFrameViewport::MaximumScrollOffsetInt() const {
  return LayoutViewport().MaximumScrollOffsetInt() +
         GetVisualViewport().MaximumScrollOffsetInt();
}

ScrollOffset RootFrameViewport::MaximumScrollOffset() const {
  return LayoutViewport().MaximumScrollOffset() +
         GetVisualViewport().MaximumScrollOffset();
}

gfx::Size RootFrameViewport::ContentsSize() const {
  return LayoutViewport().ContentsSize();
}

bool RootFrameViewport::UsesCompositedScrolling() const {
  return LayoutViewport().UsesCompositedScrolling();
}

bool RootFrameViewport::ShouldScrollOnMainThread() const {
  return LayoutViewport().ShouldScrollOnMainThread();
}

bool RootFrameViewport::ScrollbarsCanBeActive() const {
  return LayoutViewport().ScrollbarsCanBeActive();
}

bool RootFrameViewport::UserInputScrollable(
    ScrollbarOrientation orientation) const {
  return GetVisualViewport().UserInputScrollable(orientation) ||
         LayoutViewport().UserInputScrollable(orientation);
}

bool RootFrameViewport::ShouldPlaceVerticalScrollbarOnLeft() const {
  return LayoutViewport().ShouldPlaceVerticalScrollbarOnLeft();
}

void RootFrameViewport::ScrollControlWasSetNeedsPaintInvalidation() {
  LayoutViewport().ScrollControlWasSetNeedsPaintInvalidation();
}

cc::Layer* RootFrameViewport::LayerForHorizontalScrollbar() const {
  return LayoutViewport().LayerForHorizontalScrollbar();
}

cc::Layer* RootFrameViewport::LayerForVerticalScrollbar() const {
  return LayoutViewport().LayerForVerticalScrollbar();
}

cc::Layer* RootFrameViewport::LayerForScrollCorner() const {
  return LayoutViewport().LayerForScrollCorner();
}

// This method distributes the scroll between the visual and layout viewport.
ScrollResult RootFrameViewport::UserScroll(
    ui::ScrollGranularity granularity,
    const ScrollOffset& delta,
    ScrollableArea::ScrollCallback on_finish) {
  // TODO(bokan/ymalik): Once smooth scrolling is permanently enabled we
  // should be able to remove this method override and use the base class
  // version: ScrollableArea::userScroll.

  UpdateScrollAnimator();

  ScrollOffset pixel_delta = ResolveScrollDelta(granularity, delta);

  // Precompute the amount of possible scrolling since, when animated,
  // ScrollAnimator::userScroll will report having consumed the total given
  // scroll delta, regardless of how much will actually scroll, but we need to
  // know how much to leave for the layout viewport.
  ScrollOffset visual_consumed_delta =
      GetVisualViewport().GetScrollAnimator().ComputeDeltaToConsume(
          pixel_delta);

  // Split the remaining delta between scrollable and unscrollable axes of the
  // layout viewport. We only pass a delta to the scrollable axes and remember
  // how much was held back so we can add it to the unused delta in the
  // result.
  ScrollOffset layout_delta = pixel_delta - visual_consumed_delta;
  ScrollOffset scrollable_axis_delta(
      LayoutViewport().UserInputScrollable(kHorizontalScrollbar)
          ? layout_delta.x()
          : 0,
      LayoutViewport().UserInputScrollable(kVerticalScrollbar)
          ? layout_delta.y()
          : 0);
  ScrollOffset layout_consumed_delta =
      LayoutViewport().GetScrollAnimator().ComputeDeltaToConsume(
          scrollable_axis_delta);

  if (ScrollAnimatorEnabled()) {
    bool visual_viewport_has_running_animation =
        GetVisualViewport().GetScrollAnimator().HasRunningAnimation();
    bool layout_viewport_has_running_animation =
        LayoutViewport().GetScrollAnimator().HasRunningAnimation();
    // We reset |user_scroll_sequence_affects_layout_viewport_| only if this
    // UserScroll is not a continuation of a longer sequence because an earlier
    // UserScroll in the sequence may have already affected the layout
    // viewport.
    if (!visual_viewport_has_running_animation &&
        !layout_viewport_has_running_animation) {
      user_scroll_sequence_affects_layout_viewport_ = false;
    }
  }

  // If there won't be any scrolling, bail early so we don't produce any side
  // effects like cancelling existing animations.
  if (visual_consumed_delta.IsZero() && layout_consumed_delta.IsZero()) {
    if (on_finish) {
      std::move(on_finish).Run(
          ScrollableArea::ScrollCompletionMode::kZeroDelta);
    }
    return ScrollResult(false, false, pixel_delta.x(), pixel_delta.y());
  }

  CancelProgrammaticScrollAnimation();
  if (SmoothScrollSequencer* sequencer = GetSmoothScrollSequencer())
    sequencer->AbortAnimations();

  // TODO(bokan): Why do we call userScroll on the animators directly and
  // not through the ScrollableAreas?
  if (visual_consumed_delta == pixel_delta) {
    ScrollResult visual_result =
        GetVisualViewport().GetScrollAnimator().UserScroll(
            granularity, visual_consumed_delta, std::move(on_finish));
    return visual_result;
  }

  if (!layout_consumed_delta.IsZero()) {
    user_scroll_sequence_affects_layout_viewport_ = true;
  }

  if (layout_consumed_delta == pixel_delta) {
    ScrollResult layout_result =
        LayoutViewport().GetScrollAnimator().UserScroll(
            granularity, scrollable_axis_delta, std::move(on_finish));
    return layout_result;
  }

  auto all_done = MakeViewportScrollCompletion(std::move(on_finish));

  ScrollResult visual_result =
      GetVisualViewport().GetScrollAnimator().UserScroll(
          granularity, visual_consumed_delta, all_done);

  ScrollResult layout_result = LayoutViewport().GetScrollAnimator().UserScroll(
      granularity, scrollable_axis_delta, all_done);

  // Remember to add any delta not used because of !userInputScrollable to the
  // unusedScrollDelta in the result.
  ScrollOffset unscrollable_axis_delta = layout_delta - scrollable_axis_delta;

  return ScrollResult(
      visual_result.did_scroll_x || layout_result.did_scroll_x,
      visual_result.did_scroll_y || layout_result.did_scroll_y,
      layout_result.unused_scroll_delta_x + unscrollable_axis_delta.x(),
      layout_result.unused_scroll_delta_y + unscrollable_axis_delta.y());
}

bool RootFrameViewport::ScrollAnimatorEnabled() const {
  return LayoutViewport().ScrollAnimatorEnabled();
}

CompositorElementId RootFrameViewport::GetScrollElementId() const {
  return LayoutViewport().GetScrollElementId();
}

CompositorElementId RootFrameViewport::GetScrollbarElementId(
    ScrollbarOrientation orientation) {
  return GetVisualViewport().VisualViewportSuppliesScrollbars()
             ? GetVisualViewport().GetScrollbarElementId(orientation)
             : LayoutViewport().GetScrollbarElementId(orientation);
}

ChromeClient* RootFrameViewport::GetChromeClient() const {
  return LayoutViewport().GetChromeClient();
}

SmoothScrollSequencer* RootFrameViewport::GetSmoothScrollSequencer() const {
  return LayoutViewport().GetSmoothScrollSequencer();
}

void RootFrameViewport::ServiceScrollAnimations(double monotonic_time) {
  ScrollableArea::ServiceScrollAnimations(monotonic_time);
  LayoutViewport().ServiceScrollAnimations(monotonic_time);
  GetVisualViewport().ServiceScrollAnimations(monotonic_time);
}

void RootFrameViewport::UpdateCompositorScrollAnimations() {
  ScrollableArea::UpdateCompositorScrollAnimations();
  LayoutViewport().UpdateCompositorScrollAnimations();
  GetVisualViewport().UpdateCompositorScrollAnimations();
}

void RootFrameViewport::CancelProgrammaticScrollAnimation() {
  ScrollableArea::CancelProgrammaticScrollAnimation();
  LayoutViewport().CancelProgrammaticScrollAnimation();
  GetVisualViewport().CancelProgrammaticScrollAnimation();
}

void RootFrameViewport::ClearScrollableArea() {
  ScrollableArea::ClearScrollableArea();
  LayoutViewport().ClearScrollableArea();
  GetVisualViewport().ClearScrollableArea();
}

ScrollbarTheme& RootFrameViewport::GetPageScrollbarTheme() const {
  return LayoutViewport().GetPageScrollbarTheme();
}

const cc::SnapContainerData* RootFrameViewport::GetSnapContainerData() const {
  return LayoutViewport().GetSnapContainerData();
}

void RootFrameViewport::SetSnapContainerData(
    std::optional<cc::SnapContainerData> data) {
  LayoutViewport().SetSnapContainerData(data);
}

bool RootFrameViewport::SetTargetSnapAreaElementIds(
    cc::TargetSnapAreaElementIds snap_target_ids) {
  return LayoutViewport().SetTargetSnapAreaElementIds(snap_target_ids);
}

void RootFrameViewport::DropCompositorScrollDeltaNextCommit() {
  LayoutViewport().DropCompositorScrollDeltaNextCommit();
  GetVisualViewport().DropCompositorScrollDeltaNextCommit();
}

bool RootFrameViewport::SnapContainerDataNeedsUpdate() const {
  return LayoutViewport().SnapContainerDataNeedsUpdate();
}

void RootFrameViewport::SetSnapContainerDataNeedsUpdate(bool needs_update) {
  LayoutViewport().SetSnapContainerDataNeedsUpdate(needs_update);
}

std::optional<gfx::PointF> RootFrameViewport::GetSnapPositionAndSetTarget(
    const cc::SnapSelectionStrategy& strategy) {
  return LayoutViewport().GetSnapPositionAndSetTarget(strategy);
}

gfx::PointF RootFrameViewport::ScrollOffsetToPosition(
    const ScrollOffset& offset) const {
  return LayoutViewport().ScrollOffsetToPosition(offset);
}

ScrollOffset RootFrameViewport::ScrollPositionToOffset(
    const gfx::PointF& position) const {
  return LayoutViewport().ScrollPositionToOffset(position);
}

void RootFrameViewport::Trace(Visitor* visitor) const {
  visitor->Trace(visual_viewport_);
  visitor->Trace(layout_viewport_);
  ScrollableArea::Trace(visitor);
}

void RootFrameViewport::UpdateSnappedTargetsAndEnqueueScrollSnapChange() {
  LayoutViewport().UpdateSnappedTargetsAndEnqueueScrollSnapChange();
}

std::optional<cc::TargetSnapAreaElementIds>
RootFrameViewport::GetScrollsnapchangingTargetIds() const {
  return LayoutViewport().GetScrollsnapchangingTargetIds();
}

void RootFrameViewport::SetScrollsnapchangingTargetIds(
    std::optional<cc::TargetSnapAreaElementIds> new_target_ids) {
  LayoutViewport().SetScrollsnapchangingTargetIds(new_target_ids);
}

void RootFrameViewport::SetScrollsnapchangeTargetIds(
    std::optional<cc::TargetSnapAreaElementIds> new_target_ids) {
  LayoutViewport().SetScrollsnapchangeTargetIds(new_target_ids);
}

void RootFrameViewport::
    UpdateScrollSnapChangingTargetsAndEnqueueScrollSnapChanging(
        const cc::TargetSnapAreaElementIds& new_target_ids) {
  LayoutViewport().UpdateScrollSnapChangingTargetsAndEnqueueScrollSnapChanging(
      new_target_ids);
}

const cc::SnapSelectionStrategy* RootFrameViewport::GetImplSnapStrategy()
    const {
  return LayoutViewport().GetImplSnapStrategy();
}

void RootFrameViewport::SetImplSnapStrategy(
    std::unique_ptr<cc::SnapSelectionStrategy> strategy) {
  LayoutViewport().SetImplSnapStrategy(std::move(strategy));
}

void RootFrameViewport::EnqueueScrollSnapChangingEventFromImplIfNeeded() {
  LayoutViewport().EnqueueScrollSnapChangingEventFromImplIfNeeded();
}

std::optional<cc::ElementId> RootFrameViewport::GetTargetedSnapAreaId() {
  return LayoutViewport().GetTargetedSnapAreaId();
}

void RootFrameViewport::SetTargetedSnapAreaId(
    const std::optional<cc::ElementId>& id) {
  LayoutViewport().SetTargetedSnapAreaId(id);
}

void RootFrameViewport::SetSnappedQueryTargetIds(
    std::optional<cc::TargetSnapAreaElementIds> new_target_ids) {
  LayoutViewport().SetSnappedQueryTargetIds(new_target_ids);
}

}  // namespace blink
```
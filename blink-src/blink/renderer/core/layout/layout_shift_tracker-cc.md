Response:
My thinking process to answer the request about `layout_shift_tracker.cc` went something like this:

1. **Understand the Core Purpose:** The file name itself is highly suggestive: "layout_shift_tracker."  Immediately, I know its primary function is related to tracking layout shifts within the Blink rendering engine.

2. **Scan the Includes:**  The included headers provide valuable context. I see references to:
    * `cc/layers`:  Indicates interaction with the Chromium Compositor, suggesting the tracking is related to rendering and layer management.
    * `third_party/blink/public/common/features.h`:  Points to feature flags, suggesting the functionality might be conditionally enabled.
    * `third_party/blink/public/common/input/web_pointer_event.h`:  Implies the tracker interacts with user input events.
    * `third_party/blink/renderer/core/dom/*`:  Shows interaction with the Document Object Model (DOM).
    * `third_party/blink/renderer/core/frame/*`: Indicates involvement with frame management (main frame, subframes).
    * `third_party/blink/renderer/core/layout/*`: Confirms the core functionality is within the layout system.
    * `third_party/blink/renderer/core/page/*`:  Suggests involvement at the page level.
    * `third_party/blink/renderer/core/timing/*`: Points to interaction with performance metrics and timing.
    * `third_party/blink/renderer/platform/graphics/paint/*`: Implies involvement during the painting stage.
    * `ui/gfx/geometry/*`: Shows the use of geometric primitives for tracking positions and sizes.

3. **Identify Key Data Structures and Methods (Quick Skim):**  I would quickly scan the class definition for prominent members and methods. Things that jump out:
    * `is_active_`: A boolean flag indicating if tracking is enabled.
    * `score_`, `weighted_score_`: Variables likely storing the cumulative layout shift score.
    * `timer_`:  Suggests a delay or debouncing mechanism.
    * `NeedsToTrack()`:  A function determining if an object should be tracked. This is crucial.
    * `ObjectShifted()`: The core logic for handling layout shifts.
    * `NotifyBoxPrePaint()`, `NotifyTextPrePaint()`:  Methods called before painting, triggering shift detection.
    * `NotifyPrePaintFinished()`:  Logic executed after painting, likely calculating and reporting the shift.
    * `NotifyInput()`, `NotifyScroll()`:  Handling user interaction events.
    * `SubmitPerformanceEntry()`:  Reporting the layout shift as a performance metric.

4. **Infer Functionality Based on Names and Interactions:** Based on the above, I can start to infer the core functionality:
    * **Tracking Eligibility:** The tracker decides which elements to monitor for shifts (`NeedsToTrack()`). This likely involves filtering out certain elements (e.g., invisible elements, SVG elements).
    * **Shift Detection:**  When a tracked element moves during layout (`ObjectShifted()`), the tracker calculates the magnitude of the shift. This involves comparing the old and new positions and sizes.
    * **Scoring:** The tracker accumulates a "layout shift score" (`score_`, `weighted_score_`) based on the detected shifts. The "weighted" score likely accounts for factors like the size of the shift and the viewport area.
    * **Input Interaction:**  User input events (`NotifyInput()`) can influence how layout shifts are scored or reported. There's likely a mechanism to exclude shifts happening immediately after user interaction (to avoid penalizing expected layout changes).
    * **Performance Reporting:** The tracker contributes to performance metrics by submitting `LayoutShift` entries.
    * **Visualization (HUD):** The code mentions sending layout shift rectangles to a "HUD layer," suggesting a debugging or visualization feature.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Now I can start making connections to the frontend technologies:
    * **HTML:** The structure of the HTML directly influences the layout. Elements moving in the HTML will be detected by the tracker. Examples: Inserting an `<img>` that causes content below it to shift, a dynamically added `<div>`.
    * **CSS:** CSS properties are the primary driver of layout and styling. Changes in CSS (either initial styling or dynamic updates via JavaScript) can cause layout shifts. Examples: Changing `width` or `height`, altering `position` (especially `absolute` or `relative`), modifying margins/padding.
    * **JavaScript:** JavaScript is often used to dynamically manipulate the DOM and CSS, leading to layout changes. Examples: Inserting or removing elements, updating element styles, animating elements.

6. **Consider Logic and Edge Cases:**
    * **Thresholds:** The `kMovementThreshold` constant indicates a minimum movement required to register as a significant shift. This prevents minor pixel adjustments from being counted.
    * **Viewport Clipping:** The tracker considers whether the shifted element is within the visible viewport. Shifts outside the viewport might be ignored or weighted differently.
    * **Input Debouncing:** The `timer_` suggests a delay mechanism to avoid immediately penalizing layout shifts that happen as a direct result of user interaction.
    * **Subframes:** The `SubframeWeightingFactor()` indicates that layout shifts in subframes are weighted differently based on their visibility within the main frame.

7. **Think About Potential Errors:**  What common mistakes could developers make that would be captured by this tracker?
    * **Missing Dimensions on Images/Videos:**  If images or videos load without predefined dimensions, they can cause significant content reflow once they load.
    * **Ads Injecting Content:**  Dynamically loaded advertisements are a common cause of layout shifts.
    * **Font Loading:**  If web fonts take time to load, the fallback font might have different metrics, causing text to reflow when the custom font is applied.
    * **Animations Without Reserving Space:** Animations that move elements without the parent container reserving the maximum space the element will occupy can cause surrounding content to shift.

8. **Structure the Answer:** Finally, I'd organize my findings into a clear and logical structure, covering the requested aspects: functionality, relationships to web technologies (with examples), logical inferences (with hypothetical input/output), common errors, and a concise summary for Part 1.

By following these steps, I can dissect the provided code snippet and provide a comprehensive and informative answer about its functionality and implications. The process involves understanding the code's purpose, examining its components, inferring its behavior, and connecting it to the broader context of web development.
好的，这是对提供的 `blink/renderer/core/layout/layout_shift_tracker.cc` 文件代码片段的功能归纳：

**文件功能归纳:**

这段代码定义了 `LayoutShiftTracker` 类，其主要功能是**追踪和计算页面布局偏移 (Layout Shift)**。布局偏移是指在页面加载后，已经可见的元素位置发生移动，从而影响用户体验。该跟踪器旨在量化这些不期望的布局变化，并为开发者提供优化的依据。

**核心功能点：**

1. **监控布局对象移动:** `LayoutShiftTracker` 监听布局过程中 `LayoutObject` (包括 `LayoutBox` 和 `LayoutText`) 的位置变化。它会比较元素在渲染前后的位置，并记录明显的偏移。

2. **定义偏移阈值:**  通过 `kMovementThreshold` 常量定义了触发布局偏移计算的最小移动距离，避免对微小的位置调整进行不必要的记录。

3. **计算布局偏移分数 (CLS):**  当检测到布局偏移时，`LayoutShiftTracker` 会计算一个布局偏移分数 (`score_`, `weighted_score_`)。这个分数通常与偏移元素的面积和移动距离有关，并会考虑元素是否在视口内。子框架的偏移会被加权计算。

4. **区分用户输入导致的偏移:** `LayoutShiftTracker` 能够识别在用户输入（如点击、键盘操作、滚动）后发生的布局偏移，并可以设置一个时间窗口 (`kTimerDelay`)，在此窗口内发生的偏移可能不计入最终的累积布局偏移分数，以避免将用户期望的交互反馈计算在内。这可以通过时间戳或者一个定时器 (`timer_`) 实现。

5. **记录影响布局偏移的元素:**  `LayoutShiftTracker` 会记录导致布局偏移的 DOM 节点 (`attributions_`)，以及它们偏移前后的可视区域，方便开发者定位问题根源。

6. **提供性能指标:**  计算出的布局偏移分数可以作为性能指标，通过 Performance API (例如 `LayoutShift` 性能条目) 暴露给开发者或监控系统。

7. **调试辅助:**  该跟踪器可以与 Chromium 的调试工具集成，例如通过 Heads-Up Display (HUD) 图层可视化布局偏移区域。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML:**  HTML 结构的变化，例如动态插入或删除元素，会导致布局偏移。`LayoutShiftTracker` 会捕捉到这些由 DOM 结构改变引起的偏移。
    * **例子:**  一个网页加载后，JavaScript 代码动态地在现有内容上方插入一个大的广告横幅，导致下方内容向下移动。`LayoutShiftTracker` 会检测到这些元素的垂直偏移。
* **CSS:**  CSS 属性的变化会直接影响布局。例如，改变元素的尺寸、位置、外边距等都可能引发布局偏移。
    * **例子:**  一个图片元素初始时没有指定 `width` 和 `height`，加载完成后会占据实际尺寸，导致周围的文字内容发生偏移。`LayoutShiftTracker` 会记录文字的偏移。
    * **例子:**  JavaScript 动态修改元素的 `position` 属性从 `static` 改为 `absolute` 或 `fixed`，可能会导致其他元素重新排列，被 `LayoutShiftTracker` 捕捉。
* **JavaScript:**  JavaScript 代码经常用于动态修改 DOM 和 CSS，从而导致布局变化。
    * **例子:**  JavaScript 实现了一个动画效果，改变一个 `div` 元素的 `top` 或 `left` 属性，导致该元素移动，`LayoutShiftTracker` 会跟踪这种移动。
    * **例子:**  JavaScript 代码根据用户的滚动位置动态加载更多内容，导致页面高度增加，下方的元素随之移动。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. 一个 `div` 元素在初始渲染时位于视口的左上角 (0, 0)，尺寸为 100x100 像素。
2. 一段时间后，JavaScript 代码修改了这个 `div` 的 CSS `left` 属性，将其移动到 (50, 0)。
3. 用户的视口大小为 800x600 像素。
4. `kMovementThreshold` 设置为 3 像素。

**逻辑推理和输出:**

*   `LayoutShiftTracker` 会检测到 `div` 元素的起始点发生了 50 像素的水平偏移 (大于 `kMovementThreshold`)。
*   它会计算偏移分数，可能基于偏移的面积（整个 `div` 都在视口内，面积为 100x100）和移动距离（50 像素）。
*   假设偏移分数的计算公式简化为 `(偏移区域面积 / 视口面积) * (偏移距离 / 视口最大维度)`，则分数大致为 `(10000 / 480000) * (50 / 800) = 0.0208 * 0.0625 = 0.0013`。
*   `LayoutShiftTracker` 会记录下该 `div` 元素的 DOM 节点 ID，以及偏移前后的可视区域。
*   最终，这个偏移信息会作为 `LayoutShift` 性能条目报告。

**用户或编程常见的使用错误举例：**

1. **图片或 iframe 缺少尺寸声明:**  如果 `<img>` 标签或 `<iframe>` 标签没有明确指定 `width` 和 `height` 属性，当图片或内嵌页面加载完成时，元素会调整到实际尺寸，可能导致下方的元素发生大的偏移。`LayoutShiftTracker` 会捕捉到这种不期望的偏移。

2. **字体加载导致的闪烁:**  使用 Web Font 时，浏览器会先使用一个默认字体渲染文本，当 Web Font 加载完成后再替换，如果两种字体的尺寸不同，会导致文本和周围元素发生偏移。

3. **动画效果没有预留空间:**  使用 JavaScript 或 CSS 动画改变元素的位置时，如果没有为其父元素预留足够的空间，可能会导致其他元素被推开或覆盖。

4. **动态插入内容:**  在页面加载完成后，通过 JavaScript 动态插入新的 DOM 元素，特别是插入到现有内容之上时，容易造成布局偏移。例如，插入一个通知栏或广告。

5. **不当使用绝对定位或固定定位:**  过度或不当使用 `position: absolute` 或 `position: fixed` 可能导致元素脱离正常的文档流，影响其他元素的布局，并可能导致意外的偏移。

**总结 (针对第 1 部分):**

`blink/renderer/core/layout/layout_shift_tracker.cc` 文件的核心功能是**监控和量化页面布局偏移**，以便识别和优化不稳定的布局行为。它通过监听布局对象的位置变化，计算布局偏移分数，并考虑用户输入的影响。该跟踪器与 HTML、CSS 和 JavaScript 都有密切关系，因为这些技术都是导致布局偏移的潜在因素。 它可以帮助开发者发现由于缺少尺寸声明、字体加载、动态内容插入等常见错误导致的布局不稳定性，并为提升用户体验提供数据支持。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_shift_tracker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"

#include "cc/layers/heads_up_display_layer.h"
#include "cc/layers/picture_layer.h"
#include "cc/trees/layer_tree_host.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_pointer_event.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/location.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_read_only.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/performance_entry.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/property_tree_state.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

using ReattachHookScope = LayoutShiftTracker::ReattachHookScope;
ReattachHookScope* ReattachHookScope::top_ = nullptr;

using ContainingBlockScope = LayoutShiftTracker::ContainingBlockScope;
ContainingBlockScope* ContainingBlockScope::top_ = nullptr;

namespace {

constexpr base::TimeDelta kTimerDelay = base::Milliseconds(500);
const float kMovementThreshold = 3.0;  // CSS pixels.

// Calculates the physical coordinates of the starting point in the current
// coordinate space. |paint_offset| is the physical offset of the top-left
// corner. The starting point can be any of the four corners of the box,
// depending on the writing mode and text direction. Note that the result is
// still in physical coordinates, just may be of a different corner.
// See https://wicg.github.io/layout-instability/#starting-point.
gfx::PointF StartingPoint(const PhysicalOffset& paint_offset,
                          const LayoutBox& box,
                          const PhysicalSize& size) {
  PhysicalOffset starting_point = paint_offset;
  auto writing_direction = box.StyleRef().GetWritingDirection();
  if (writing_direction.IsFlippedBlocks()) [[unlikely]] {
    starting_point.left += size.width;
  }
  if (writing_direction.IsRtl()) [[unlikely]] {
    if (writing_direction.IsHorizontal())
      starting_point.left += size.width;
    else
      starting_point.top += size.height;
  }
  return gfx::PointF(starting_point);
}

// Returns the part a rect logically below a starting point.
PhysicalRect RectBelowStartingPoint(const PhysicalRect& rect,
                                    const PhysicalOffset& starting_point,
                                    LayoutUnit logical_height,
                                    WritingDirectionMode writing_direction) {
  PhysicalRect result = rect;
  if (writing_direction.IsHorizontal()) {
    result.ShiftTopEdgeTo(starting_point.top);
    result.SetHeight(logical_height);
  } else {
    result.SetWidth(logical_height);
    if (writing_direction.IsFlippedBlocks())
      result.ShiftRightEdgeTo(starting_point.left);
    else
      result.ShiftLeftEdgeTo(starting_point.left);
  }
  return result;
}

float GetMoveDistance(const gfx::PointF& old_starting_point,
                      const gfx::PointF& new_starting_point) {
  gfx::Vector2dF location_delta = new_starting_point - old_starting_point;
  return std::max(fabs(location_delta.x()), fabs(location_delta.y()));
}

bool EqualWithinMovementThreshold(const gfx::PointF& a,
                                  const gfx::PointF& b,
                                  float threshold_physical_px) {
  return fabs(a.x() - b.x()) < threshold_physical_px &&
         fabs(a.y() - b.y()) < threshold_physical_px;
}

bool SmallerThanRegionGranularity(const PhysicalRect& rect) {
  // Normally we paint by snapping to whole pixels, so rects smaller than half
  // a pixel may be invisible.
  return rect.Width() < 0.5 || rect.Height() < 0.5;
}

void RectToTracedValue(const gfx::Rect& rect,
                       TracedValue& value,
                       const char* key = nullptr) {
  if (key)
    value.BeginArray(key);
  else
    value.BeginArray();
  value.PushInteger(rect.x());
  value.PushInteger(rect.y());
  value.PushInteger(rect.width());
  value.PushInteger(rect.height());
  value.EndArray();
}

void RegionToTracedValue(const LayoutShiftRegion& region, TracedValue& value) {
  cc::Region blink_region;
  for (const gfx::Rect& rect : region.GetRects())
    blink_region.Union(rect);

  value.BeginArray("region_rects");
  for (gfx::Rect rect : blink_region)
    RectToTracedValue(rect, value);
  value.EndArray();
}

bool ShouldLog(const LocalFrame& frame) {
  if (!VLOG_IS_ON(1))
    return false;

  DCHECK(frame.GetDocument());
  const String& url = frame.GetDocument()->Url().GetString();
  return !url.StartsWith("devtools:");
}

}  // namespace

LayoutShiftTracker::LayoutShiftTracker(LocalFrameView* frame_view)
    : frame_view_(frame_view),
      // This eliminates noise from the private Page object created by
      // SVGImage::DataChanged.
      is_active_(!frame_view->GetFrame()
                      .GetChromeClient()
                      .IsIsolatedSVGChromeClient()),
      score_(0.0),
      weighted_score_(0.0),
      timer_(frame_view->GetFrame().GetTaskRunner(TaskType::kInternalDefault),
             this,
             &LayoutShiftTracker::TimerFired),
      frame_max_distance_(0.0),
      overall_max_distance_(0.0),
      observed_input_or_scroll_(false),
      most_recent_input_timestamp_initialized_(false) {}

bool LayoutShiftTracker::NeedsToTrack(const LayoutObject& object) const {
  if (!is_active_)
    return false;

  if (object.GetDocument().IsPrintingOrPaintingPreview())
    return false;

  // SVG elements don't participate in the normal layout algorithms and are
  // more likely to be used for animations.
  if (object.IsSVGChild())
    return false;

  if (object.StyleRef().Visibility() != EVisibility::kVisible) {
    return false;
  }

  if (IsA<LayoutText>(object)) {
    if (!ContainingBlockScope::top_)
      return false;
    if (object.IsBR())
      return false;
    if (object.StyleRef().GetFont().ShouldSkipDrawing())
      return false;
    return true;
  }

  const auto* box = DynamicTo<LayoutBox>(object);
  if (!box) {
    return false;
  }

  if (SmallerThanRegionGranularity(box->VisualOverflowRectAllowingUnset())) {
    return false;
  }

  if (auto* display_lock_context = box->GetDisplayLockContext()) {
    if (display_lock_context->IsAuto() && display_lock_context->IsLocked())
      return false;
  }

  // Don't report shift of anonymous objects. Will report the children because
  // we want report real DOM nodes.
  if (box->IsAnonymous()) {
    return false;
  }

  // Ignore sticky-positioned objects that move on scroll.
  // TODO(skobes): Find a way to detect when these objects shift.
  if (box->IsStickyPositioned()) {
    return false;
  }

  // A LayoutView can't move by itself.
  if (box->IsLayoutView()) {
    return false;
  }

  if (Element* element = DynamicTo<Element>(object.GetNode())) {
    if (element->IsSliderThumbElement())
      return false;
  }

  if (const auto* block = DynamicTo<LayoutBlock>(box)) {
    // Just check the simplest case. For more complex cases, we should suggest
    // the developer to use visibility:hidden.
    if (block->FirstChild()) {
      return true;
    }
    if (box->HasBoxDecorationBackground() || box->GetScrollableArea() ||
        box->StyleRef().HasVisualOverflowingEffect()) {
      return true;
    }
    return false;
  }

  return true;
}

void LayoutShiftTracker::ObjectShifted(
    const LayoutObject& object,
    const PropertyTreeStateOrAlias& property_tree_state,
    const PhysicalRect& old_rect,
    const PhysicalRect& new_rect,
    const gfx::PointF& old_starting_point,
    const gfx::Vector2dF& translation_delta,
    const gfx::Vector2dF& scroll_delta,
    const gfx::Vector2dF& scroll_anchor_adjustment,
    const gfx::PointF& new_starting_point) {
  // The caller should ensure these conditions.
  DCHECK(!old_rect.IsEmpty());
  DCHECK(!new_rect.IsEmpty());

  float threshold_physical_px =
      kMovementThreshold * object.StyleRef().EffectiveZoom();

  // Check shift of starting point, including 2d-translation and scroll
  // deltas.
  if (EqualWithinMovementThreshold(old_starting_point, new_starting_point,
                                   threshold_physical_px))
    return;

  // Check shift of 2d-translation-indifferent starting point.
  if (!translation_delta.IsZero() &&
      EqualWithinMovementThreshold(old_starting_point + translation_delta,
                                   new_starting_point, threshold_physical_px))
    return;

  // Check shift of scroll-indifferent starting point.
  if (!scroll_delta.IsZero() &&
      EqualWithinMovementThreshold(old_starting_point + scroll_delta,
                                   new_starting_point, threshold_physical_px))
    return;

  if (!scroll_anchor_adjustment.IsZero() &&
      EqualWithinMovementThreshold(
          old_starting_point + scroll_delta + scroll_anchor_adjustment,
          new_starting_point, threshold_physical_px)) {
    return;
  }

  // Check shift of 2d-translation-and-scroll-indifferent starting point.
  gfx::Vector2dF translation_and_scroll_delta =
      scroll_delta + translation_delta;
  if (!translation_and_scroll_delta.IsZero() &&
      EqualWithinMovementThreshold(
          old_starting_point + translation_and_scroll_delta, new_starting_point,
          threshold_physical_px))
    return;

  const auto& root_state =
      object.View()->FirstFragment().LocalBorderBoxProperties();
  FloatClipRect clip_rect =
      GeometryMapper::LocalToAncestorClipRect(property_tree_state, root_state);
  if (frame_view_->GetFrame().IsMainFrame()) {
    // Apply the visual viewport clip.
    clip_rect.Intersect(FloatClipRect(
        frame_view_->GetPage()->GetVisualViewport().VisibleRect()));
  }

  // If the clip region is empty, then the resulting layout shift isn't visible
  // in the viewport so ignore it.
  if (clip_rect.Rect().IsEmpty())
    return;

  auto transform = GeometryMapper::SourceToDestinationProjection(
      property_tree_state.Transform(), root_state.Transform());
  // TODO(crbug.com/1187979): Shift by |scroll_delta| to keep backward
  // compatibility in https://crrev.com/c/2754969. See the bug for details.
  gfx::PointF old_starting_point_in_root =
      transform.MapPoint(old_starting_point + scroll_delta);
  gfx::PointF new_starting_point_in_root =
      transform.MapPoint(new_starting_point);

  if (EqualWithinMovementThreshold(old_starting_point_in_root,
                                   new_starting_point_in_root,
                                   threshold_physical_px))
    return;

  gfx::RectF old_rect_in_root(old_rect);
  // TODO(crbug.com/1187979): Shift by |scroll_delta| to keep backward
  // compatibility in https://crrev.com/c/2754969. See the bug for details.
  old_rect_in_root.Offset(scroll_delta);
  old_rect_in_root = transform.MapRect(old_rect_in_root);
  gfx::RectF new_rect_in_root(new_rect);
  new_rect_in_root = transform.MapRect(new_rect_in_root);

  gfx::Rect visible_old_rect = gfx::ToRoundedRect(
      gfx::IntersectRects(old_rect_in_root, clip_rect.Rect()));
  gfx::Rect visible_new_rect = gfx::ToRoundedRect(
      gfx::IntersectRects(new_rect_in_root, clip_rect.Rect()));
  if (visible_old_rect.IsEmpty() && visible_new_rect.IsEmpty())
    return;

  // If the object moved from or to out of view, ignore the shift if it's in
  // the inline direction only.
  if (visible_old_rect.IsEmpty() || visible_new_rect.IsEmpty()) {
    gfx::PointF old_inline_direction_indifferent_starting_point_in_root =
        old_starting_point_in_root;
    if (object.IsHorizontalWritingMode()) {
      old_inline_direction_indifferent_starting_point_in_root.set_x(
          new_starting_point_in_root.x());
    } else {
      old_inline_direction_indifferent_starting_point_in_root.set_y(
          new_starting_point_in_root.y());
    }
    if (EqualWithinMovementThreshold(
            old_inline_direction_indifferent_starting_point_in_root,
            new_starting_point_in_root, threshold_physical_px)) {
      return;
    }
  }

  // Compute move distance based on starting points in root, to accurately
  // determine how much the element moved.
  float move_distance =
      GetMoveDistance(old_starting_point_in_root, new_starting_point_in_root);
  if (!std::isfinite(move_distance)) {
    return;
  }
  DCHECK_GT(move_distance, 0.f);
  frame_max_distance_ = std::max(frame_max_distance_, move_distance);

  LocalFrame& frame = frame_view_->GetFrame();
  if (ShouldLog(frame)) {
    VLOG(2) << "in " << (frame.IsOutermostMainFrame() ? "" : "subframe ")
            << frame.GetDocument()->Url() << ", " << object << " moved from "
            << old_rect_in_root.ToString() << " to "
            << new_rect_in_root.ToString() << " (visible from "
            << visible_old_rect.ToString() << " to "
            << visible_new_rect.ToString() << ")";
    if (old_starting_point_in_root != old_rect_in_root.origin() ||
        new_starting_point_in_root != new_rect_in_root.origin() ||
        !translation_delta.IsZero() || !scroll_delta.IsZero()) {
      VLOG(2) << " (starting point from "
              << old_starting_point_in_root.ToString() << " to "
              << new_starting_point_in_root.ToString() << ")";
    }
  }

  region_.AddRect(visible_old_rect);
  region_.AddRect(visible_new_rect);

  if (Node* node = object.GetNode()) {
    MaybeRecordAttribution(
        {node->GetDomNodeId(), visible_old_rect, visible_new_rect});
  }
}

LayoutShiftTracker::Attribution::operator bool() const {
  return node_id != kInvalidDOMNodeId;
}

bool LayoutShiftTracker::Attribution::Encloses(const Attribution& other) const {
  return old_visual_rect.Contains(other.old_visual_rect) &&
         new_visual_rect.Contains(other.new_visual_rect);
}

uint64_t LayoutShiftTracker::Attribution::Area() const {
  uint64_t old_area = old_visual_rect.size().Area64();
  uint64_t new_area = new_visual_rect.size().Area64();

  gfx::Rect intersection =
      gfx::IntersectRects(old_visual_rect, new_visual_rect);
  uint64_t shared_area = intersection.size().Area64();
  return old_area + new_area - shared_area;
}

bool LayoutShiftTracker::Attribution::MoreImpactfulThan(
    const Attribution& other) const {
  return Area() > other.Area();
}

void LayoutShiftTracker::MaybeRecordAttribution(
    const Attribution& attribution) {
  Attribution* smallest = nullptr;
  for (auto& slot : attributions_) {
    if (!slot || attribution.Encloses(slot)) {
      slot = attribution;
      return;
    }
    if (slot.Encloses(attribution))
      return;
    if (!smallest || smallest->MoreImpactfulThan(slot))
      smallest = &slot;
  }
  // No empty slots or redundancies. Replace smallest existing slot if larger.
  if (attribution.MoreImpactfulThan(*smallest))
    *smallest = attribution;
}

void LayoutShiftTracker::NotifyBoxPrePaint(
    const LayoutBox& box,
    const PropertyTreeStateOrAlias& property_tree_state,
    const PhysicalRect& old_rect,
    const PhysicalRect& new_rect,
    const PhysicalOffset& old_paint_offset,
    const gfx::Vector2dF& translation_delta,
    const gfx::Vector2dF& scroll_delta,
    const gfx::Vector2dF& scroll_anchor_adjustment,
    const PhysicalOffset& new_paint_offset) {
  DCHECK(NeedsToTrack(box));
  ObjectShifted(box, property_tree_state, old_rect, new_rect,
                StartingPoint(old_paint_offset, box, box.PreviousSize()),
                translation_delta, scroll_delta, scroll_anchor_adjustment,
                StartingPoint(new_paint_offset, box, box.Size()));
}

void LayoutShiftTracker::NotifyTextPrePaint(
    const LayoutText& text,
    const PropertyTreeStateOrAlias& property_tree_state,
    const LogicalOffset& old_starting_point,
    const LogicalOffset& new_starting_point,
    const PhysicalOffset& old_paint_offset,
    const gfx::Vector2dF& translation_delta,
    const gfx::Vector2dF& scroll_delta,
    const gfx::Vector2dF& scroll_anchor_adjustment,
    const PhysicalOffset& new_paint_offset,
    LayoutUnit logical_height) {
  DCHECK(NeedsToTrack(text));
  auto* block = ContainingBlockScope::top_;
  DCHECK(block);

  auto writing_direction = text.StyleRef().GetWritingDirection();
  PhysicalOffset old_physical_starting_point =
      old_paint_offset + old_starting_point.ConvertToPhysical(writing_direction,
                                                              block->old_size_,
                                                              PhysicalSize());
  PhysicalOffset new_physical_starting_point =
      new_paint_offset + new_starting_point.ConvertToPhysical(writing_direction,
                                                              block->new_size_,
                                                              PhysicalSize());

  PhysicalRect old_rect =
      RectBelowStartingPoint(block->old_rect_, old_physical_starting_point,
                             logical_height, writing_direction);
  if (old_rect.IsEmpty())
    return;
  PhysicalRect new_rect =
      RectBelowStartingPoint(block->new_rect_, new_physical_starting_point,
                             logical_height, writing_direction);
  if (new_rect.IsEmpty())
    return;

  ObjectShifted(text, property_tree_state, old_rect, new_rect,
                gfx::PointF(old_physical_starting_point), translation_delta,
                scroll_delta, scroll_anchor_adjustment,
                gfx::PointF(new_physical_starting_point));
}

double LayoutShiftTracker::SubframeWeightingFactor() const {
  LocalFrame& frame = frame_view_->GetFrame();
  if (frame.IsOutermostMainFrame())
    return 1;

  // TODO(crbug.com/1346602): Enabling frames from a fenced frame tree to map
  // to the outermost main frame enables fenced content to learn about its
  // position in the embedder which can be used to communicate from embedder to
  // embeddee. For now, assume any frame in a fenced frame is fully visible to
  // avoid introducing a side channel but this will require design work to fix
  // in the long term.
  if (frame.IsInFencedFrameTree()) {
    return 1;
  }

  // Map the subframe view rect into the coordinate space of the local root.
  FloatClipRect subframe_cliprect(gfx::RectF(gfx::SizeF(frame_view_->Size())));
  const LocalFrame& local_root = frame.LocalFrameRoot();
  GeometryMapper::LocalToAncestorVisualRect(
      frame_view_->GetLayoutView()->FirstFragment().LocalBorderBoxProperties(),
      local_root.ContentLayoutObject()
          ->FirstFragment()
          .LocalBorderBoxProperties(),
      subframe_cliprect);
  auto subframe_rect = PhysicalRect::EnclosingRect(subframe_cliprect.Rect());

  // Intersect with the portion of the local root that overlaps the main frame.
  local_root.View()->MapToVisualRectInRemoteRootFrame(subframe_rect);
  gfx::Size subframe_visible_size = subframe_rect.PixelSnappedSize();
  gfx::Size main_frame_size = frame.GetPage()->GetVisualViewport().Size();

  if (main_frame_size.Area64() == 0) {
    return 0;
  }
  // TODO(crbug.com/940711): This comparison ignores page scale and CSS
  // transforms above the local root.
  return static_cast<double>(subframe_visible_size.Area64()) /
         main_frame_size.Area64();
}

void LayoutShiftTracker::NotifyPrePaintFinishedInternal() {
  if (!is_active_)
    return;
  if (region_.IsEmpty())
    return;

  gfx::Rect viewport = frame_view_->GetScrollableArea()->VisibleContentRect();
  if (viewport.IsEmpty())
    return;

  double viewport_area = double(viewport.width()) * double(viewport.height());
  double impact_fraction = region_.Area() / viewport_area;
  DCHECK_GT(impact_fraction, 0);

  DCHECK_GT(frame_max_distance_, 0.0);
  double viewport_max_dimension = std::max(viewport.width(), viewport.height());
  double move_distance_factor =
      (frame_max_distance_ < viewport_max_dimension)
          ? double(frame_max_distance_) / viewport_max_dimension
          : 1.0;
  double score_delta = impact_fraction * move_distance_factor;
  double weighted_score_delta = score_delta * SubframeWeightingFactor();

  overall_max_distance_ = std::max(overall_max_distance_, frame_max_distance_);

  LocalFrame& frame = frame_view_->GetFrame();
  if (ShouldLog(frame)) {
    VLOG(2) << "in " << (frame.IsOutermostMainFrame() ? "" : "subframe ")
            << frame.GetDocument()->Url() << ", viewport was "
            << (impact_fraction * 100) << "% impacted with distance fraction "
            << move_distance_factor << " and subframe weighting factor "
            << SubframeWeightingFactor();
  }

  if (pointerdown_pending_data_.num_pointerdowns > 0 ||
      pointerdown_pending_data_.num_pressed_mouse_buttons > 0) {
    pointerdown_pending_data_.score_delta += score_delta;
    pointerdown_pending_data_.weighted_score_delta += weighted_score_delta;
  } else {
    ReportShift(score_delta, weighted_score_delta);
  }

  if (!region_.IsEmpty() && !HasRecentInput()) {
    SendLayoutShiftRectsToHud(region_.GetRects());
  }
}

void LayoutShiftTracker::NotifyPrePaintFinished() {
  NotifyPrePaintFinishedInternal();

  // Reset accumulated state.
  region_.Reset();
  frame_max_distance_ = 0.0;
  attributions_.fill(Attribution());
}

LayoutShift::AttributionList LayoutShiftTracker::CreateAttributionList() const {
  LayoutShift::AttributionList list;
  for (const Attribution& att : attributions_) {
    if (att.node_id == kInvalidDOMNodeId)
      break;
    list.push_back(LayoutShiftAttribution::Create(
        DOMNodeIds::NodeForId(att.node_id),
        DOMRectReadOnly::FromRect(att.old_visual_rect),
        DOMRectReadOnly::FromRect(att.new_visual_rect)));
  }
  return list;
}

void LayoutShiftTracker::SubmitPerformanceEntry(double score_delta,
                                                bool had_recent_input) const {
  LocalDOMWindow* window = frame_view_->GetFrame().DomWindow();
  if (!window)
    return;
  WindowPerformance* performance = DOMWindowPerformance::performance(*window);
  DCHECK(performance);

  double input_timestamp = LastInputTimestamp();
  LayoutShift* entry =
      LayoutShift::Create(performance->now(), score_delta, had_recent_input,
                          input_timestamp, CreateAttributionList(), window);

  // Add WPT for LayoutShift. See crbug.com/1320878.

  performance->AddLayoutShiftEntry(entry);
}

void LayoutShiftTracker::ReportShift(double score_delta,
                                     double weighted_score_delta) {
  LocalFrame& frame = frame_view_->GetFrame();
  bool had_recent_input = HasRecentInput();

  if (!had_recent_input) {
    score_ += score_delta;
    if (weighted_score_delta > 0) {
      weighted_score_ += weighted_score_delta;
      frame.Client()->DidObserveLayoutShift(weighted_score_delta,
                                            observed_input_or_scroll_);
    }
  }

  SubmitPerformanceEntry(score_delta, had_recent_input);

  TRACE_EVENT_INSTANT2(
      "loading", "LayoutShift", TRACE_EVENT_SCOPE_THREAD, "data",
      PerFrameTraceData(score_delta, weighted_score_delta, had_recent_input),
      "frame", GetFrameIdForTracing(&frame));

  if (ShouldLog(frame)) {
    VLOG(2) << "in " << (frame.IsOutermostMainFrame() ? "" : "subframe ")
            << frame.GetDocument()->Url().GetString() << ", layout shift of "
            << score_delta
            << (had_recent_input ? " excluded by recent input" : " reported")
            << "; cumulative score is " << score_;
  }
}

void LayoutShiftTracker::NotifyInput(const WebInputEvent& event) {
  const WebInputEvent::Type type = event.GetType();
  bool release_all_mouse_buttons = false;
  if (type == WebInputEvent::Type::kMouseUp) {
    if (pointerdown_pending_data_.num_pressed_mouse_buttons > 0)
      pointerdown_pending_data_.num_pressed_mouse_buttons--;
    release_all_mouse_buttons =
        pointerdown_pending_data_.num_pressed_mouse_buttons == 0;
  }
  bool release_all_pointers = false;
  if (type == WebInputEvent::Type::kPointerUp) {
    if (pointerdown_pending_data_.num_pointerdowns > 0)
      pointerdown_pending_data_.num_pointerdowns--;
    release_all_pointers = pointerdown_pending_data_.num_pointerdowns == 0;
  }

  const bool event_type_stops_pointerdown_buffering =
      type == WebInputEvent::Type::kPointerCausedUaAction ||
      type == WebInputEvent::Type::kPointerCancel;

  // Only non-hovering pointerdown requires buffering.
  const bool is_hovering_pointerdown =
      type == WebInputEvent::Type::kPointerDown &&
      static_cast<const WebPointerEvent&>(event).hovering;

  const bool should_trigger_shift_exclusion =
      type == WebInputEvent::Type::kMouseDown ||
      type == WebInputEvent::Type::kKeyDown ||
      type == WebInputEvent::Type::kRawKeyDown ||
      // We need to explicitly include tap, as if there are no listeners, we
      // won't receive the pointer events.
      type == WebInputEvent::Type::kGestureTap || is_hovering_pointerdown ||
      release_all_pointers || release_all_mouse_buttons;

  if (should_trigger_shift_exclusion) {
    observed_input_or_scroll_ = true;

    if (!RuntimeEnabledFeatures::TimestampBasedCLSTrackingEnabled()) {
      // This cancels any previously scheduled task from the same timer.
      timer_.StartOneShot(kTimerDelay, FROM_HERE);
    }
    UpdateInputTimestamps(event.TimeStamp());
  }

  if (event_type_stops_pointerdown_buffering || release_all_mouse_buttons ||
      release_all_pointers) {
    double score_delta = pointerdown_pending_data_.score_delta;
    if (score_delta > 0)
      ReportShift(score_delta, pointerdown_pending_data_.weighted_score_delta);
    pointerdown_pending_data_ = PointerdownPendingData();
  }
  if (type == WebInputEvent::Type::kPointerDown && !is_hovering_pointerdown)
    pointerdown_pending_data_.num_pointerdowns++;
  if (type == WebInputEvent::Type::kMouseDown)
    pointerdown_pending_data_.num_pressed_mouse_buttons++;
}

void LayoutShiftTracker::UpdateInputTimestamps(base::TimeTicks timestamp) {
  most_recent_input_timestamp_initialized_ = true;
  most_recent_input_timestamp_ =
      std::max(timestamp, most_recent_input_timestamp_);
  most_recent_input_processing_timestamp_ = base::TimeTicks::Now();
}

bool LayoutShiftTracker::HasRecentInput() {
  if (!RuntimeEnabledFeatures::TimestampBasedCLSTrackingEnabled()) {
    return timer_.IsActive();
  }
  if (most_recent_input_processing_timestamp_.is_null()) {
    return false;
  }
  base::TimeDelta time_since_last_input =
      blink::Thread::Current()->CurrentTaskStartTime() -
      most_recent_input_processing_timestamp_;

  bool has_recent_input = time_since_last_input <= kTimerDelay;
  if (!has_recent_input) {
    most_recent_input_processing_timestamp_ = base::TimeTicks();
  }
  return has_recent_input;
}

void LayoutShiftTracker::NotifyScroll(mojom::blink::ScrollType scroll_type,
                                      ScrollOffset delta) {
  // Only set observed_input_or_scroll_ for user-initiated scrolls, and not
  // other scrolls such as hash fragment navigations.
  if (scroll_type == mojom::blink::ScrollType::kUser ||
      scroll_type == mojom::blink::ScrollType::kCompositor)
    observed_input_or_scroll_ = true;
}

void LayoutShiftTracker::NotifyViewportSizeChanged() {
  UpdateTimerAndInputTimestamp();
}

void LayoutShiftTracker::NotifyFindInPageInput() {
  UpdateTimerAndInputTimestamp();
}

void LayoutShiftTracker::NotifyChangeEvent() {
  UpdateTimerAndInputTimestamp();
}

void LayoutShiftTracker::NotifyZoomLevelChanged() {
  UpdateTimerAndInputTimestamp();
}

void LayoutShiftTracker::NotifyBrowserInitiatedSameDocumentNavigation() {
  UpdateTimerAndInputTimestamp();
}

void LayoutShiftTracker::UpdateTimerAndInputTimestamp() {
  // This cancels any previously scheduled task from the same timer.
  UpdateInputTimestamps(base::TimeTicks::Now());
  if (!RuntimeEnabledFeatures::TimestampBasedCLSTrackingEnabled()) {
    timer_.StartOneShot(kTimerDelay, FROM_HERE);
  }
}

double LayoutShiftTracker::LastInputTimestamp() const {
  LocalDOMWindow* window = frame_view_->GetFrame().DomWindow();
  if (!window)
    return 0.0;
  WindowPerformance* performance = DOMWindowPerformance::performance(*window);
  DCHECK(performance);

  return most_recent_input_timestamp_initialized_
             ? performance->MonotonicTimeToDOMHighResTimeStamp(
                   most_recent_input_timestamp_)
             : 0.0;
}

std::unique_ptr<TracedValue> LayoutShiftTracker::PerFrameTraceData(
    double score_delta,
    double weighted_score_delta,
    bool input_detected) const {
  auto value = std::make_unique<TracedValue>();
  value->SetDouble("score", score_delta);
  value->SetDouble("weighted_score_delta", weighted_score_delta);
  value->SetDouble("cumulative_score", score_);
  value->SetDouble("overall_max_distance", overall_max_distance_);
  value->SetDouble("frame_max_distance", frame_max_distance_);
  RegionToTracedValue(region_, *value);
  value->SetBoolean("is_main_frame",
                    frame_view_->GetFrame().IsOutermostMainFrame());
  value->SetBoolean("had_recent_input", input_detected);
  value->SetDouble("last_input_timestamp", LastInputTimestamp());
  AttributionsToTracedValue(*value);
  return value;
}

void LayoutShiftTracker::AttributionsToTracedValue(TracedValue& value) const {
  auto it = attributions_.begin();
  if (!*it)
    return;

  bool should_include_names;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(
      TRACE_DISABLED_BY_DEFAULT("layout_shift.debug"), &should_include_names);

  value.BeginArray("impacted_nodes");
  while (it != attributions_.end() && it->node_id != kInvalidDOMNodeId) {
    value.BeginDictionary();
    value.SetInteger("node_id", it->node_id);
    RectToTracedValue(it->old_visual_rect, value, "old_rect");
    RectToTracedValue(it->new_visual_rect, value, "new_rect");
    if (should_include_names) {
      Node* node = DOMNodeIds::NodeForId(it->node_id);
      value.SetString("debug_name", node ? node->DebugName() : "");
    }
    value.EndDictionary();
    it++;
  }
  value.EndArray();
}

void LayoutShiftTracker::SendLayoutShiftRectsToHud(
    const Vector<gfx::Rect>& int_rects) {
  // Store the layout shift rects in the HUD layer.
  auto* cc_layer = frame_view_->RootCcLayer();
  if (cc_layer && cc_layer->layer_tree_host()) {
    if (!cc_layer->layer_tree_host()->GetDebugState().show_layout_shift_regions)
      return;
    if (cc_layer->layer_tree_host()->hud_layer()) {
      WebVector<gfx::Rect> rects;
      cc::Region blink_region;
      for (const gfx::Rect& rect : int_rects)
        blink_region.Union(rect);
      for (gfx::Rect rect : blink_region)
        rects.emplace_back(rect);
      cc_layer->layer_tree_host()->hud_layer()->SetLayoutShiftRects(
          rects.ReleaseVector());
      cc_layer->layer_tree_host()->hud_layer()->SetNeedsPushProperties();
    }
  }
}

void LayoutShiftTracker::Dispose() {
  if (!RuntimeEnabledFeatures::TimestampBasedCLSTrackingEnabled()) {
    timer_.Stop();
  }
}

void LayoutShiftTracker::ResetTimerForTesting() {
  most_recent_input_processing_timestamp_ = base::TimeTicks();
  timer_.Stop();
}

void LayoutShiftTracker::Trace(Visitor* visitor) const {
  visitor->Trace(frame_view_);
  visitor->Trace(timer_);
}

ReattachHookScope::ReattachHookScope(const Node& node) : outer_(top_) {
  if (node.GetLayoutObject())
    top_ = this;
}

ReattachHookScope::~ReattachHookScope() {
  top_ = outer_;
}

void ReattachHookScope::NotifyDetach(const Node& node) {
  if (!top_)
    return;
  auto* layout_object = node.GetLayoutObject();
  if (!layout_object || layout_object->ShouldSkipNextLayoutShiftTracking() ||
      !layout_object->IsBox())
    return;

  auto& map = top_->geometries_before_detach_;
  auto& fragment = layout_object->GetMutableForPainting().FirstFragment();

  // Save the visual rect for restoration on future reattachment.
  const auto& box = To<LayoutBox
"""


```
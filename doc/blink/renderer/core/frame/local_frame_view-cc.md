Response:
The user wants me to analyze the provided C++ code snippet from the `local_frame_view.cc` file in the Chromium Blink engine. I need to identify its functionalities, explain its relationship with JavaScript, HTML, and CSS, provide examples with hypothetical inputs and outputs if it involves logical reasoning, illustrate common usage errors, and finally, summarize the functionalities covered in this first part.

**Plan:**

1. **Identify Core Functionalities:**  Based on the included headers and the methods defined in the snippet, I will list the primary responsibilities of `LocalFrameView`.
2. **Relate to Web Technologies:**  For each functionality, I will determine if and how it interacts with JavaScript, HTML, and CSS, providing concrete examples.
3. **Analyze Logical Reasoning:** If the code snippet contains any logical deductions or state management, I will create simple examples with hypothetical inputs and their corresponding outputs.
4. **Identify Potential Usage Errors:** I will look for patterns or common pitfalls that developers using or interacting with this code might encounter.
5. **Summarize Part 1:** I will condense the findings into a concise summary of the functionalities covered in the provided code.
这是 `blink/renderer/core/frame/local_frame_view.cc` 文件第一部分的功能归纳：

**主要功能:**

`LocalFrameView` 类是 Blink 渲染引擎中负责管理和呈现页面内容的关键组件。 它代表了一个本地框架（`LocalFrame`）的可视化呈现部分，并协调布局、绘制、滚动、事件处理等操作。

**具体功能点（基于代码片段）：**

1. **生命周期管理:**
    *   构造和析构 `LocalFrameView` 对象。
    *   管理视图的显示和隐藏 (`Show()`).
    *   在 `Dispose()` 方法中清理资源，断开与其他对象的连接，防止内存泄漏。

2. **子视图和插件管理:**
    *   提供遍历子框架视图和插件的方法 (`ForAllChildViewsAndPlugins`, `ForAllChildLocalFrameViews`, `ForAllNonThrottledLocalFrameViews`, `ForAllThrottledLocalFrameViews`, `ForAllRemoteFrameViews`).

3. **布局管理:**
    *   维护布局状态 (`has_pending_layout_`, `layout_scheduling_enabled_`).
    *   触发和执行布局过程 (`PerformLayout()`).
    *   跟踪需要布局的对象 (`layout_subtree_root_list_`).
    *   处理首次布局的特殊情况 (`first_layout_`, `first_layout_with_body_`).
    *   调整视图大小以适应内容 (`AdjustViewSize()`).
    *   确定是否需要进行子树布局 (`IsSubtreeLayout()`).
    *   记录布局次数 (用于测试) (`layout_count_for_testing_`).

4. **滚动管理:**
    *   管理滚动条的显示和隐藏 (`can_have_scrollbars_`).
    *   处理使用覆盖滚动条的更改 (`UsesOverlayScrollbarsChanged()`).
    *   管理与滚动锚定的相关逻辑 (`scroll_anchoring_scrollable_areas_`).
    *   维护可滚动区域的集合 (`scrollable_areas_`).

5. **插件更新:**
    *   使用定时器 (`update_plugins_timer_`) 协调插件的更新。

6. **样式和渲染:**
    *   存储和管理背景颜色 (`base_background_color_`).
    *   记录视觉上非空的字符和像素数量 (`visually_non_empty_character_count_`, `visually_non_empty_pixel_count_`).
    *   标记视图是否视觉上非空 (`is_visually_non_empty_`).
    *   处理自定义滚动条在激活状态改变时的失效 (`InvalidateAllCustomScrollbarsOnActiveChanged()`).

7. **框架尺寸和位置:**
    *   存储和更新框架的矩形区域 (`FrameRect()`).
    *   处理框架矩形变化 (`FrameRectsChanged()`) 并传播到子框架。

8. **文档生命周期:**
    *   管理文档生命周期状态 (`lifecycle_updates_throttled_`, `target_state_`).
    *   提供设置生命周期更新是否被节流的方法 (用于测试) (`SetLifecycleUpdatesThrottledForTesting()`).
    *   判断生命周期更新是否处于活动状态 (`LifecycleUpdatesActive()`).

9. **性能监控和调试:**
    *   包含用于性能分析和调试的工具，例如 `TRACE_EVENT` 宏。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **HTML:**  `LocalFrameView` 负责呈现 HTML 结构。 当浏览器解析 HTML 并创建 DOM 树时，`LocalFrameView` 会根据 DOM 树构建渲染树（Render Tree），这是布局和绘制的基础。例如，当 HTML 中包含 `<div>` 元素时，`LocalFrameView` 会创建一个对应的布局对象来表示这个 div。
*   **CSS:**  CSS 样式决定了 HTML 元素的视觉外观。 `LocalFrameView` 在布局阶段会考虑 CSS 样式信息（例如，大小、颜色、边距等）来计算元素的位置和尺寸。 例如，如果 CSS 规则设置了 `div { width: 100px; }`，`LocalFrameView` 在布局时会将该 div 的宽度设置为 100 像素。
*   **JavaScript:** JavaScript 可以操作 DOM 结构和 CSS 样式。 当 JavaScript 修改 DOM 或 CSS 时，可能会触发 `LocalFrameView` 重新布局和重绘页面。 例如，如果 JavaScript 代码使用 `element.style.width = '200px'` 修改了一个 div 的宽度，`LocalFrameView` 会收到通知并安排重新布局以反映这个变化。 JavaScript 还可以通过滚动 API 与 `LocalFrameView` 的滚动功能交互，例如 `window.scrollTo(0, 100)` 会导致 `LocalFrameView` 滚动到指定位置。

**逻辑推理示例（假设输入与输出）：**

在 `PerformLayout()` 方法中，会检查 `GetLayoutView()->NeedsLayout()`。

*   **假设输入:**  一个 HTML 元素的内容或样式被 JavaScript 修改，导致 `GetLayoutView()->NeedsLayout()` 返回 `true`。
*   **逻辑推理:**  `LocalFrameView` 判断需要进行布局，然后执行布局过程，计算元素的新位置和尺寸。
*   **输出:**  页面上的元素按照新的布局进行渲染。

*   **假设输入:**  页面首次加载完成，`first_layout_` 为 `true` 且 `GetFrame().GetDocument()->body()` 存在。
*   **逻辑推理:**  `LocalFrameView` 会执行首次布局的特殊逻辑，例如可能强制显示垂直滚动条。
*   **输出:**  页面完成首次布局，可能显示垂直滚动条。

**用户或编程常见的使用错误举例:**

*   **过度依赖同步布局:**  如果在 JavaScript 代码中频繁地读取需要布局信息的值（例如 `element.offsetWidth`）并紧接着修改样式，会导致浏览器被迫进行多次同步布局，影响性能。这是因为浏览器需要先完成布局才能提供准确的尺寸信息。
*   **不理解布局失效的边界:**  开发者可能会错误地认为修改一个元素的样式只会影响该元素自身，而忽略了它可能导致父元素甚至整个文档重新布局。这可能导致意外的性能问题。
*   **在不合适的时机操作 DOM:**  在某些生命周期阶段（例如布局或绘制过程中）直接操作 DOM 可能会导致崩溃或未定义的行为。Blink 引擎通常会进行检查并抛出错误。

**总结:**

`LocalFrameView` 的第一部分代码主要关注其生命周期管理、子视图和插件的组织、核心的布局机制（包括触发、执行和优化）、滚动条的管理、插件的更新协调以及与渲染和样式相关的基本属性维护。它奠定了 `LocalFrameView` 作为页面内容可视化呈现和管理中心的基础。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_frame_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1998, 1999 Torben Weis <weis@kde.org>
 *                     1999 Lars Knoll <knoll@kde.org>
 *                     1999 Antti Koivisto <koivisto@kde.org>
 *                     2000 Dirk Mueller <mueller@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2007, 2008 Apple Inc. All rights reserved.
 *           (C) 2006 Graham Dennis (graham.dennis@gmail.com)
 *           (C) 2006 Alexey Proskuryakov (ap@nypop.com)
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/frame/local_frame_view.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/auto_reset.h"
#include "base/feature_list.h"
#include "base/functional/callback.h"
#include "base/functional/function_ref.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial_params.h"
#include "base/numerics/safe_conversions.h"
#include "base/timer/lap_timer.h"
#include "base/trace_event/typed_macros.h"
#include "cc/animation/animation_host.h"
#include "cc/animation/animation_timeline.h"
#include "cc/base/features.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/layers/picture_layer.h"
#include "cc/tiles/frame_viewer_instrumentation.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/view_transition/view_transition_request.h"
#include "components/paint_preview/common/paint_preview_tracker.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/remote_frame.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scrollbar_mode.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_into_view_options.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/css/font_face_set_document.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/editing/drag_caret.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/events/error_event.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/fragment_directive/fragment_directive_utils.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/frame_overlay.h"
#include "third_party/blink/renderer/core/frame/frame_view_auto_size_info.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_ukm_aggregator.h"
#include "third_party/blink/renderer/core/frame/location.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/pagination_state.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/remote_frame_view.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/highlight/highlight_registry.h"
#include "third_party/blink/renderer/core/html/fenced_frame/document_fenced_frames.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element.h"
#include "third_party/blink/renderer/core/html/html_frame_set_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observation.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_controller.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/geometry/transform_state.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/layout_counter.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_object.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/legacy_layout_tree_walking.h"
#include "third_party/blink/renderer/core/layout/pagination_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/layout/traced_layout_object.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/media_type_names.h"
#include "third_party/blink/renderer/core/mobile_metrics/mobile_friendliness_checker.h"
#include "third_party/blink/renderer/core/mobile_metrics/tap_friendliness_checker.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/link_highlight.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/scrolling/fragment_anchor.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"
#include "third_party/blink/renderer/core/page/validation_message_client.h"
#include "third_party/blink/renderer/core/paint/cull_rect_updater.h"
#include "third_party/blink/renderer/core/paint/frame_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/pre_paint_tree_walk.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_controller.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/position_try_fallbacks.h"
#include "third_party/blink/renderer/core/svg/svg_document_extensions.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_request.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_performance.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_settings_builder.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/document_resource_coordinator.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "ui/base/cursor/cursor.h"
#include "ui/base/cursor/mojom/cursor_type.mojom-blink.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/quad_f.h"
#include "ui/gfx/geometry/rect_f.h"

// Used to check for dirty layouts violating document lifecycle rules.
// If arg evaluates to true, the program will continue. If arg evaluates to
// false, program will crash if DCHECK_IS_ON() or return false from the current
// function.
#define CHECK_FOR_DIRTY_LAYOUT(arg) \
  do {                              \
    DCHECK(arg);                    \
    if (!(arg)) {                   \
      return false;                 \
    }                               \
  } while (false)

namespace blink {
namespace {

// Logs a UseCounter for the size of the cursor that will be set. This will be
// used for compatibility analysis to determine whether the maximum size can be
// reduced.
void LogCursorSizeCounter(LocalFrame* frame, const ui::Cursor& cursor) {
  DCHECK(frame);
  if (cursor.type() != ui::mojom::blink::CursorType::kCustom) {
    return;
  }

  const SkBitmap& bitmap = cursor.custom_bitmap();
  if (bitmap.isNull()) {
    return;
  }

  // Should not overflow, this calculation is done elsewhere when determining
  // whether the cursor exceeds its maximum size (see event_handler.cc).
  auto scaled_size =
      gfx::ScaleToFlooredSize(gfx::Size(bitmap.width(), bitmap.height()),
                              1 / cursor.image_scale_factor());
  if (scaled_size.width() > 64 || scaled_size.height() > 64) {
    UseCounter::Count(frame->GetDocument(), WebFeature::kCursorImageGT64x64);
  } else if (scaled_size.width() > 32 || scaled_size.height() > 32) {
    UseCounter::Count(frame->GetDocument(), WebFeature::kCursorImageGT32x32);
  } else {
    UseCounter::Count(frame->GetDocument(), WebFeature::kCursorImageLE32x32);
  }
}

gfx::QuadF GetQuadForTimelinePaintEvent(const scoped_refptr<cc::Layer>& layer) {
  gfx::RectF rect(layer->update_rect());
  if (layer->transform_tree_index() != -1)
    rect = layer->ScreenSpaceTransform().MapRect(rect);
  return gfx::QuadF(rect);
}

// Default value for how long we want to delay the
// compositor commit beyond the start of document lifecycle updates to avoid
// flash between navigations. The delay should be small enough so that it won't
// confuse users expecting a new page to appear after navigation and the omnibar
// has updated the url display.
constexpr int kCommitDelayDefaultInMs = 500;  // 30 frames @ 60hz

}  // namespace

// The maximum number of updatePlugins iterations that should be done before
// returning.
static const unsigned kMaxUpdatePluginsIterations = 2;

// The number of |InvalidationDisallowedScope| class instances. Used to ensure
// that no more than one instance of this class exists at any given time.
int LocalFrameView::InvalidationDisallowedScope::instance_count_ = 0;

LocalFrameView::LocalFrameView(LocalFrame& frame)
    : LocalFrameView(frame, gfx::Rect()) {
  Show();
}

LocalFrameView::LocalFrameView(LocalFrame& frame, const gfx::Size& initial_size)
    : LocalFrameView(frame, gfx::Rect(gfx::Point(), initial_size)) {
  SetLayoutSizeInternal(initial_size);
  Show();
}

LocalFrameView::LocalFrameView(LocalFrame& frame, gfx::Rect frame_rect)
    : FrameView(frame_rect),
      frame_(frame),
      can_have_scrollbars_(true),
      has_pending_layout_(false),
      layout_scheduling_enabled_(true),
      layout_count_for_testing_(0),
      // We want plugin updates to happen in FIFO order with loading tasks.
      update_plugins_timer_(frame.GetTaskRunner(TaskType::kInternalLoading),
                            this,
                            &LocalFrameView::UpdatePluginsTimerFired),
      base_background_color_(Color::kWhite),
      media_type_(media_type_names::kScreen),
      visually_non_empty_character_count_(0),
      visually_non_empty_pixel_count_(0),
      is_visually_non_empty_(false),
      layout_size_fixed_to_frame_size_(true),
      needs_update_geometries_(false),
      root_layer_did_scroll_(false),
      // The compositor throttles the main frame using deferred begin main frame
      // updates. We can't throttle it here or it seems the root compositor
      // doesn't get setup properly.
      lifecycle_updates_throttled_(!GetFrame().IsMainFrame()),
      target_state_(DocumentLifecycle::kUninitialized),
      suppress_adjust_view_size_(false),
      intersection_observation_state_(kNotNeeded),
      main_thread_scrolling_reasons_(0),
      forced_layout_stack_depth_(0),
      paint_frame_count_(0),
      unique_id_(NewUniqueObjectId()),
      layout_shift_tracker_(MakeGarbageCollected<LayoutShiftTracker>(this)),
      paint_timing_detector_(MakeGarbageCollected<PaintTimingDetector>(this)),
      mobile_friendliness_checker_(MobileFriendlinessChecker::Create(*this)),
      tap_friendliness_checker_(TapFriendlinessChecker::CreateIfMobile(*this))
#if DCHECK_IS_ON()
      ,
      is_updating_descendant_dependent_flags_(false),
      is_updating_layout_(false)
#endif
{
  // Propagate the marginwidth/height and scrolling modes to the view.
  if (frame_->Owner() && frame_->Owner()->ScrollbarMode() ==
                             mojom::blink::ScrollbarMode::kAlwaysOff)
    SetCanHaveScrollbars(false);
}

LocalFrameView::~LocalFrameView() {
#if DCHECK_IS_ON()
  DCHECK(has_been_disposed_);
#endif
}

void LocalFrameView::Trace(Visitor* visitor) const {
  visitor->Trace(part_update_set_);
  visitor->Trace(frame_);
  visitor->Trace(update_plugins_timer_);
  visitor->Trace(layout_subtree_root_list_);
  visitor->Trace(fragment_anchor_);
  visitor->Trace(scroll_anchoring_scrollable_areas_);
  visitor->Trace(animating_scrollable_areas_);
  visitor->Trace(scrollable_areas_);
  visitor->Trace(background_attachment_fixed_objects_);
  visitor->Trace(auto_size_info_);
  visitor->Trace(pagination_state_);
  visitor->Trace(plugins_);
  visitor->Trace(scrollbars_);
  visitor->Trace(viewport_scrollable_area_);
  visitor->Trace(anchoring_adjustment_queue_);
  visitor->Trace(scroll_event_queue_);
  visitor->Trace(paint_controller_persistent_data_);
  visitor->Trace(paint_artifact_compositor_);
  visitor->Trace(layout_shift_tracker_);
  visitor->Trace(paint_timing_detector_);
  visitor->Trace(mobile_friendliness_checker_);
  visitor->Trace(tap_friendliness_checker_);
  visitor->Trace(lifecycle_observers_);
  visitor->Trace(fullscreen_video_elements_);
  visitor->Trace(pending_transform_updates_);
  visitor->Trace(pending_opacity_updates_);
  visitor->Trace(pending_sticky_updates_);
  visitor->Trace(pending_snap_updates_);
  visitor->Trace(pending_perform_snap_);
  visitor->Trace(disconnected_elements_with_remembered_size_);
}

void LocalFrameView::ForAllChildViewsAndPlugins(
    base::FunctionRef<void(EmbeddedContentView&)> function) {
  for (Frame* child = frame_->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    if (child->View())
      function(*child->View());
  }

  for (const auto& plugin : plugins_) {
    function(*plugin);
  }

  if (Document* document = frame_->GetDocument()) {
    if (DocumentFencedFrames* fenced_frames =
            DocumentFencedFrames::Get(*document)) {
      for (HTMLFencedFrameElement* fenced_frame :
           fenced_frames->GetFencedFrames()) {
        if (Frame* frame = fenced_frame->ContentFrame())
          function(*frame->View());
      }
    }
  }
}

void LocalFrameView::ForAllChildLocalFrameViews(
    base::FunctionRef<void(LocalFrameView&)> function) {
  for (Frame* child = frame_->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    auto* child_local_frame = DynamicTo<LocalFrame>(child);
    if (!child_local_frame)
      continue;
    if (LocalFrameView* child_view = child_local_frame->View())
      function(*child_view);
  }
}

// Note: if this logic is updated, `ForAllThrottledLocalFrameViews()` may
// need to be updated as well.
void LocalFrameView::ForAllNonThrottledLocalFrameViews(
    base::FunctionRef<void(LocalFrameView&)> function,
    TraversalOrder order) {
  if (ShouldThrottleRendering())
    return;

  if (order == kPreOrder)
    function(*this);

  ForAllChildLocalFrameViews([&function, order](LocalFrameView& child_view) {
    child_view.ForAllNonThrottledLocalFrameViews(function, order);
  });

  if (order == kPostOrder)
    function(*this);
}

// Note: if this logic is updated, `ForAllNonThrottledLocalFrameViews()` may
// need to be updated as well.
void LocalFrameView::ForAllThrottledLocalFrameViews(
    base::FunctionRef<void(LocalFrameView&)> function) {
  if (ShouldThrottleRendering())
    function(*this);

  ForAllChildLocalFrameViews([&function](LocalFrameView& child_view) {
    child_view.ForAllThrottledLocalFrameViews(function);
  });
}

void LocalFrameView::ForAllRemoteFrameViews(
    base::FunctionRef<void(RemoteFrameView&)> function) {
  for (Frame* child = frame_->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    if (child->IsLocalFrame()) {
      To<LocalFrame>(child)->View()->ForAllRemoteFrameViews(function);
    } else {
      DCHECK(child->IsRemoteFrame());
      if (RemoteFrameView* view = To<RemoteFrame>(child)->View())
        function(*view);
    }
  }
  if (Document* document = frame_->GetDocument()) {
    if (DocumentFencedFrames* fenced_frames =
            DocumentFencedFrames::Get(*document)) {
      for (HTMLFencedFrameElement* fenced_frame :
           fenced_frames->GetFencedFrames()) {
        if (RemoteFrame* frame =
                To<RemoteFrame>(fenced_frame->ContentFrame())) {
          if (RemoteFrameView* view = frame->View())
            function(*view);
        }
      }
    }
  }
}

void LocalFrameView::Dispose() {
  CHECK(!IsInPerformLayout());

  // TODO(dcheng): It's wrong that the frame can be detached before the
  // LocalFrameView. Figure out what's going on and fix LocalFrameView to be
  // disposed with the correct timing.

  // We need to clear the RootFrameViewport's animator since it gets called
  // from non-GC'd objects and RootFrameViewport will still have a pointer to
  // this class.
  if (viewport_scrollable_area_) {
    DCHECK(frame_->IsMainFrame());
    DCHECK(frame_->GetPage());

    viewport_scrollable_area_->ClearScrollableArea();
    viewport_scrollable_area_.Clear();
    frame_->GetPage()->GlobalRootScrollerController().Reset();
  }

  // If we have scheduled plugins to be updated, cancel it. They will still be
  // notified before they are destroyed.
  if (update_plugins_timer_.IsActive())
    update_plugins_timer_.Stop();
  part_update_set_.clear();

  // These are LayoutObjects whose layout has been deferred to a subsequent
  // lifecycle update. Not gonna happen.
  layout_subtree_root_list_.Clear();

  // TODO(szager): LayoutObjects are supposed to remove themselves from these
  // tracking groups when they update style or are destroyed, but sometimes they
  // are missed. It would be good to understand how/why that happens, but in the
  // mean time, it's not safe to keep pointers around to defunct LayoutObjects.
  background_attachment_fixed_objects_.clear();

  // Destroy |m_autoSizeInfo| as early as possible, to avoid dereferencing
  // partially destroyed |this| via |m_autoSizeInfo->m_frameView|.
  auto_size_info_.Clear();

  // FIXME: Do we need to do something here for OOPI?
  HTMLFrameOwnerElement* owner_element = frame_->DeprecatedLocalOwner();
  // TODO(dcheng): It seems buggy that we can have an owner element that points
  // to another EmbeddedContentView. This can happen when a plugin element loads
  // a frame (EmbeddedContentView A of type LocalFrameView) and then loads a
  // plugin (EmbeddedContentView B of type WebPluginContainerImpl). In this
  // case, the frame's view is A and the frame element's
  // OwnedEmbeddedContentView is B. See https://crbug.com/673170 for an example.
  if (owner_element && owner_element->OwnedEmbeddedContentView() == this)
    owner_element->SetEmbeddedContentView(nullptr);

  if (ukm_aggregator_) {
    LocalFrame& root_frame = GetFrame().LocalFrameRoot();
    Document* root_document = root_frame.GetDocument();
    if (root_document) {
      ukm_aggregator_->TransmitFinalSample(root_document->UkmSourceID(),
                                           root_document->UkmRecorder(),
                                           root_frame.IsMainFrame());
    }
    ukm_aggregator_.reset();
  }
  layout_shift_tracker_->Dispose();

#if DCHECK_IS_ON()
  has_been_disposed_ = true;
#endif
}

void LocalFrameView::InvalidateAllCustomScrollbarsOnActiveChanged() {
  bool uses_window_inactive_selector =
      frame_->GetDocument()->GetStyleEngine().UsesWindowInactiveSelector();

  ForAllChildLocalFrameViews([](LocalFrameView& frame_view) {
    frame_view.InvalidateAllCustomScrollbarsOnActiveChanged();
  });

  for (const auto& scrollbar : scrollbars_) {
    if (uses_window_inactive_selector && scrollbar->IsCustomScrollbar())
      scrollbar->StyleChanged();
  }
}

void LocalFrameView::UsesOverlayScrollbarsChanged() {
  for (const auto& scrollable_area : scrollable_areas_.Values()) {
    if (scrollable_area->ScrollsOverflow() || scrollable_area->HasScrollbar()) {
      scrollable_area->RemoveScrollbarsForReconstruction();
      if (auto* layout_box = scrollable_area->GetLayoutBox()) {
        layout_box->SetNeedsLayout(
            layout_invalidation_reason::kScrollbarChanged);
      }
    }
  }
}

bool LocalFrameView::DidFirstLayout() const {
  return !first_layout_;
}

bool LocalFrameView::LifecycleUpdatesActive() const {
  return !lifecycle_updates_throttled_;
}

void LocalFrameView::SetLifecycleUpdatesThrottledForTesting(bool throttled) {
  lifecycle_updates_throttled_ = throttled;
}

void LocalFrameView::FrameRectsChanged(const gfx::Rect& old_rect) {
  PropagateFrameRects();

  if (FrameRect() != old_rect) {
    if (auto* layout_view = GetLayoutView())
      layout_view->SetShouldCheckForPaintInvalidation();
  }

  if (Size() != old_rect.size()) {
    ViewportSizeChanged();
    if (frame_->IsMainFrame())
      frame_->GetPage()->GetVisualViewport().MainFrameDidChangeSize();
    GetFrame().Loader().RestoreScrollPositionAndViewState();
  }
}

Page* LocalFrameView::GetPage() const {
  return GetFrame().GetPage();
}

LayoutView* LocalFrameView::GetLayoutView() const {
  return GetFrame().ContentLayoutObject();
}

cc::AnimationHost* LocalFrameView::GetCompositorAnimationHost() const {
  if (!GetChromeClient())
    return nullptr;

  return GetChromeClient()->GetCompositorAnimationHost(*frame_);
}

cc::AnimationTimeline* LocalFrameView::GetScrollAnimationTimeline() const {
  if (!GetChromeClient())
    return nullptr;

  return GetChromeClient()->GetScrollAnimationTimeline(*frame_);
}

void LocalFrameView::SetLayoutOverflowSize(const gfx::Size& size) {
  if (size == layout_overflow_size_)
    return;

  layout_overflow_size_ = size;

  Page* page = GetFrame().GetPage();
  if (!page)
    return;
  page->GetChromeClient().ContentsSizeChanged(frame_.Get(), size);
}

void LocalFrameView::AdjustViewSize() {
  if (suppress_adjust_view_size_)
    return;

  LayoutView* layout_view = GetLayoutView();
  if (!layout_view)
    return;

  DCHECK_EQ(frame_->View(), this);
  SetLayoutOverflowSize(ToPixelSnappedRect(layout_view->DocumentRect()).size());
}

void LocalFrameView::CountObjectsNeedingLayout(unsigned& needs_layout_objects,
                                               unsigned& total_objects,
                                               bool& is_subtree) {
  needs_layout_objects = 0;
  total_objects = 0;
  is_subtree = IsSubtreeLayout();
  if (is_subtree) {
    layout_subtree_root_list_.CountObjectsNeedingLayout(needs_layout_objects,
                                                        total_objects);
  } else {
    LayoutSubtreeRootList::CountObjectsNeedingLayoutInRoot(
        GetLayoutView(), needs_layout_objects, total_objects);
  }
}

bool LocalFrameView::LayoutFromRootObject(LayoutObject& root) {
  if (!root.NeedsLayout())
    return false;

  if (DisplayLockUtilities::LockedAncestorPreventingLayout(root)) {
    // Note that since we're preventing the layout on a layout root, we have to
    // mark its ancestor chain for layout. The reason for this is that we will
    // clear the layout roots whether or not we have finished laying them out,
    // so the fact that this root still needs layout will be lost if we don't
    // mark its container chain.
    //
    // Also, since we know that this root has a layout-blocking ancestor, the
    // layout bit propagation will stop there.
    //
    // TODO(vmpstr): Note that an alternative to this approach is to keep `root`
    // as a layout root in `layout_subtree_root_list_`. It would mean that we
    // will keep it in the list while the display-lock prevents layout. We need
    // to investigate which of these approaches is better.
    root.MarkContainerChainForLayout();
    return false;
  }

  if (scroll_anchoring_scrollable_areas_) {
    for (auto& scrollable_area : *scroll_anchoring_scrollable_areas_) {
      if (scrollable_area->GetScrollAnchor() &&
          scrollable_area->ShouldPerformScrollAnchoring())
        scrollable_area->GetScrollAnchor()->NotifyBeforeLayout();
    }
  }

  To<LayoutBox>(root).LayoutSubtreeRoot();
  return true;
}

#define PERFORM_LAYOUT_TRACE_CATEGORIES \
  "blink,benchmark,rail," TRACE_DISABLED_BY_DEFAULT("blink.debug.layout")

void LocalFrameView::PerformLayout() {
  ScriptForbiddenScope forbid_script;

  has_pending_layout_ = false;

  FontCachePurgePreventer font_cache_purge_preventer;
  base::AutoReset<bool> change_scheduling_enabled(&layout_scheduling_enabled_,
                                                  false);
  // If the layout view was marked as needing layout after we added items in
  // the subtree roots we need to clear the roots and do the layout from the
  // layoutView.
  if (GetLayoutView()->NeedsLayout())
    ClearLayoutSubtreeRootsAndMarkContainingBlocks();
  GetLayoutView()->ClearHitTestCache();

  const bool in_subtree_layout = IsSubtreeLayout();

  Document* document = GetFrame().GetDocument();
  if (!in_subtree_layout) {
    ClearLayoutSubtreeRootsAndMarkContainingBlocks();
    Node* body = document->body();
    if (IsA<HTMLFrameSetElement>(body) && body->GetLayoutObject()) {
      body->GetLayoutObject()->SetChildNeedsLayout();
    }

    first_layout_ = false;

    if (first_layout_with_body_ && body) {
      first_layout_with_body_ = false;
      mojom::blink::ScrollbarMode h_mode;
      mojom::blink::ScrollbarMode v_mode;
      GetLayoutView()->CalculateScrollbarModes(h_mode, v_mode);
      if (v_mode == mojom::blink::ScrollbarMode::kAuto) {
        if (auto* scrollable_area = GetLayoutView()->GetScrollableArea())
          scrollable_area->ForceVerticalScrollbarForFirstLayout();
      }
    }
  }

  TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(
      TRACE_DISABLED_BY_DEFAULT("blink.debug.layout.trees"), "LayoutTree", this,
      TracedLayoutObject::Create(*GetLayoutView(), false));

  gfx::Size old_size(Size());

  DCHECK(in_subtree_layout || layout_subtree_root_list_.IsEmpty());

  double contents_height_before_layout =
      GetLayoutView()->DocumentRect().Height();
  TRACE_EVENT_BEGIN1(
      PERFORM_LAYOUT_TRACE_CATEGORIES, "LocalFrameView::performLayout",
      "contentsHeightBeforeLayout", contents_height_before_layout);

  DCHECK(!IsInPerformLayout());
  Lifecycle().AdvanceTo(DocumentLifecycle::kInPerformLayout);

  // performLayout is the actual guts of layout().
  // FIXME: The 300 other lines in layout() probably belong in other helper
  // functions so that a single human could understand what layout() is actually
  // doing.

  {
    // TODO(szager): Remove this after diagnosing crash.
    DocumentLifecycle::CheckNoTransitionScope check_no_transition(Lifecycle());
    if (in_subtree_layout) {
      // This map will be used to avoid rebuilding several times the fragment
      // tree spine of a common ancestor.
      HeapHashMap<Member<const LayoutBox>, unsigned> fragment_tree_spines;
      for (auto& root : layout_subtree_root_list_.Unordered()) {
        const LayoutBox* container_box = root->ContainingNGBox();
        if (container_box && container_box->PhysicalFragmentCount()) {
          auto add_result = fragment_tree_spines.insert(container_box, 0);
          ++add_result.stored_value->value;
        }
      }
      for (auto& root : layout_subtree_root_list_.Ordered()) {
        bool should_rebuild_fragments = false;
        L
"""


```
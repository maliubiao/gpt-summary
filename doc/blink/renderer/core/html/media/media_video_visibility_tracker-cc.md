Response:
Let's break down the thought process for analyzing this Chromium source code.

1. **Understand the Core Purpose:** The filename `media_video_visibility_tracker.cc` immediately suggests the primary function: tracking the visibility of video elements. The presence of "media" and "video" reinforces this.

2. **Identify Key Data Structures and Classes:** Scan the includes and the class declaration. Important elements jump out:
    * `HTMLVideoElement`: The core element being tracked.
    * `Document`, `Frame`, `VisualViewport`:  Contextual information about where the video exists in the page.
    * `LayoutVideo`, `PaintLayer`, `DisplayItem`, `DisplayItemList`:  Rendering-related classes indicating the visibility determination involves the rendering pipeline.
    * `HitTestResult`:  Crucial for determining what's occluding the video.
    * `MediaVideoVisibilityTracker`:  The central class for the logic.
    * `OcclusionState`:  A likely struct or class to hold information about occluding elements.
    * `Metrics`: A struct or class to track performance and debugging information.
    * `ReportVisibilityCb`, `RequestVisibilityCallback`: Callbacks for reporting visibility changes.

3. **Analyze Key Methods and Their Logic:** Focus on the most descriptive method names:
    * `Attach()`, `Detach()`: Control when the tracking is active. Look for conditions under which these are called (`UpdateVisibilityTrackerState()`).
    * `UpdateVisibilityTrackerState()`:  The logic for deciding when to start/stop tracking. Fullscreen and paused states are clearly important.
    * `ComputeOcclusion()`:  The heart of the visibility calculation. It involves hit testing and determining what's on top of the video. The `client_ids_set` seems to be an optimization.
    * `MeetsVisibilityThreshold()`:  Checks if enough of the video is visible based on a threshold.
    * `ComputeVisibility()`: Orchestrates the visibility check, including calculating the intersection with the viewport and then checking for occlusion.
    * `ComputeAreaOccludedByViewport()`: Specifically deals with occlusion caused by the viewport boundaries.
    * `MaybeComputeVisibility()`: The main entry point for triggering a visibility check, often throttled by time.
    * `RequestVisibility()`:  An asynchronous way to request the current visibility state.

4. **Trace the Data Flow:**  How does information move through the system?
    * The `HTMLVideoElement` is the starting point.
    * `LayoutVideo` provides size and position.
    * Hit testing (`HitTestForOcclusionRatio`) uses the rendering tree to find occluding elements.
    * `ComputeOcclusion()` accumulates the areas of occluding elements.
    * `OcclusionState` stores intermediate results.
    * `MeetsVisibilityThreshold()` compares the visible area to the `visibility_threshold_`.
    * `report_visibility_cb_` and `request_visibility_callback_` are used to notify the outside world.

5. **Identify Relationships with Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:**  The tracker is directly associated with `<video>` elements. The presence of fullscreen-related event listeners (`fullscreenchange`, `webkitfullscreenchange`) indicates interaction with the Fullscreen API.
    * **CSS:**  CSS properties like `opacity` are considered in `ComputeOcclusion()`. Layout and positioning (which CSS controls) are fundamental to determining the video's bounding box and the position of occluding elements.
    * **JavaScript:**  The `report_visibility_cb_` is likely a mechanism for informing JavaScript code about visibility changes. The Fullscreen API events are dispatched to JavaScript. JavaScript can control video playback (pause/play), which influences whether the tracker is active.

6. **Infer Logical Reasoning and Assumptions:**
    * **Assumption:**  Occlusion is primarily determined by elements that are painted on top of the video.
    * **Reasoning:** The hit testing logic penetrates through elements, collecting information about what's visually above the video. The area calculations are based on these overlapping rectangles.
    * **Assumption:** User-agent shadow roots (like video controls) are not considered occluding content from the user's perspective.

7. **Consider Potential User/Programming Errors:**
    * **Incorrect `visibility_threshold_`:** Setting it too high or too low will affect the sensitivity of the tracker.
    * **Not detaching the tracker:** If the video element is removed from the DOM without detaching, it could lead to memory leaks or unexpected behavior.
    * **Relying solely on this tracker for critical video logic:**  While useful, this tracker likely isn't the *only* factor determining video behavior. Other factors (network state, user interaction) are also important.

8. **Structure the Explanation:**  Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logical Reasoning, Usage Errors, Input/Output Examples. Use clear and concise language.

9. **Refine and Iterate:** Review the generated explanation for accuracy and completeness. Are there any ambiguities?  Can the examples be improved?  For instance, initially, I might not have explicitly mentioned the `client_ids_set` as an optimization; closer examination of the code reveals this. Similarly, I might have initially overlooked the specific CSS property (`opacity`) checked in `ComputeOcclusion()`.

By following this systematic process,  you can effectively analyze and understand complex source code like this. The key is to start with the high-level purpose and gradually delve into the details, making connections and inferences along the way.
这个C++源代码文件 `media_video_visibility_tracker.cc` 属于 Chromium Blink 引擎，其主要功能是 **追踪 HTML `<video>` 元素在页面中的可见性**。它会定期检查视频元素是否有足够的像素在用户的视口中可见，并根据配置的阈值报告可见性状态。

下面详细列举其功能以及与 JavaScript, HTML, CSS 的关系和一些使用场景：

**功能:**

1. **监控视频元素的可见区域:**  `MediaVideoVisibilityTracker` 负责计算视频元素实际在屏幕上可见的面积。这涉及到考虑视频元素的位置、大小以及是否有其他元素遮挡了它。

2. **基于阈值判断可见性:**  该类使用一个配置的 `visibility_threshold_` （可见性阈值）来判断视频是否被认为是“可见”的。只有当视频的可见面积超过这个阈值时，才会被判定为可见。

3. **利用 Hit-Testing 确定遮挡物:**  为了找出遮挡视频的元素，它使用了 Blink 的 Hit-Testing 机制 (`HitTestForOcclusionRatio`)。这个机制可以穿透页面元素，找出指定区域下方的所有元素。

4. **考虑透明度和阴影 Root:**  Hit-Testing 过程中，会忽略透明的元素 (`kIgnoreZeroOpacityObjects`) 以及用户代理（浏览器自身）的 Shadow Root 中的元素 (`IgnoredNodesUserAgentShadowRootCount`)。这是因为这些通常不被认为是用户感知的遮挡。

5. **处理 Fullscreen 状态:**  该类会监听全屏事件 (`webkitfullscreenchange`, `fullscreenchange`)，当视频元素进入或退出全屏状态时，会更新可见性追踪的状态。在全屏状态下，通常认为视频是可见的。

6. **优化 Hit-Testing:**  为了提高性能，它可能使用一些优化策略，例如只针对可能遮挡视频的特定 DisplayItem 进行 Hit-Testing (`GetClientIdsSet`)。

7. **记录性能指标:**  文件中包含了大量的 `UMA_HISTOGRAM_*` 宏，用于记录各种性能指标，例如 Hit-Testing 的耗时、被忽略的节点数量、遮挡矩形的数量等，用于 Chromium 的性能分析和优化。

8. **提供异步的可见性查询接口:**  通过 `RequestVisibility` 方法，可以异步地请求当前的可见性状态。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**  `MediaVideoVisibilityTracker` 直接关联到 HTML 的 `<video>` 元素。它的目标是判断这个 HTML 元素是否在视口中可见。
    * **举例:** 当一个 `<video>` 元素被添加到 DOM 中，并且开始播放时，`MediaVideoVisibilityTracker` 可能会被激活来追踪其可见性。

* **CSS:**  CSS 的样式会直接影响视频元素的布局、大小和位置，这些都是计算可见面积的基础。此外，CSS 的 `opacity` 属性也会被考虑，透明度为 0 的元素不会被认为是遮挡物。
    * **举例:** 如果一个 CSS 规则将一个 `<div>` 元素的 `z-index` 设置得比 `<video>` 元素高，并且覆盖了视频的一部分，`MediaVideoVisibilityTracker` 会通过 Hit-Testing 检测到这个 `<div>` 元素，并计算它遮挡的面积。
    * **举例:** 如果一个 CSS 规则将一个 `<div>` 元素的 `opacity` 设置为 0，即使它覆盖了视频，`MediaVideoVisibilityTracker` 也会忽略它，不会认为它遮挡了视频。

* **JavaScript:** JavaScript 可以控制视频元素的播放、暂停以及在 DOM 中的位置。JavaScript 可以通过 Chromium 提供的接口来获取 `MediaVideoVisibilityTracker` 报告的可见性状态，并根据这个状态执行相应的操作。
    * **举例:** JavaScript 代码可能会监听视频的可见性变化，当视频变为不可见时暂停播放，当视频再次可见时恢复播放，以节省资源或优化用户体验。
    * **举例:**  JavaScript 可以使用 Fullscreen API 来控制视频的全屏状态，这会触发 `MediaVideoVisibilityTracker` 的相应处理。

**逻辑推理的假设输入与输出:**

假设我们有一个简单的 HTML 结构：

```html
<div style="width: 200px; height: 200px; background-color: red; position: absolute; top: 50px; left: 50px; z-index: 2;"></div>
<video id="myVideo" width="300" height="200" style="position: absolute; top: 100px; left: 100px;" controls></video>
```

且 `visibility_threshold_` 设置为 5000 (表示需要至少 5000 像素可见)。

* **假设输入 1:** 页面加载完成，视频元素部分被红色 `div` 遮挡。
    * **计算:** `MediaVideoVisibilityTracker` 会计算视频元素的可见面积。视频总面积是 300 * 200 = 60000 像素。红色 `div` 与视频的重叠区域会从可见面积中减去。假设重叠区域是 100 * 100 = 10000 像素。则可见面积是 60000 - 10000 = 50000 像素。
    * **输出:** 由于 50000 > 5000，`MediaVideoVisibilityTracker` 会报告视频为 **可见**。

* **假设输入 2:**  用户滚动页面，导致视频元素完全移出视口。
    * **计算:**  `MediaVideoVisibilityTracker` 会检测到视频元素与视口没有交集，可见面积为 0。
    * **输出:** 由于 0 < 5000，`MediaVideoVisibilityTracker` 会报告视频为 **不可见**。

* **假设输入 3:** 用户点击全屏按钮，视频进入全屏模式。
    * **输出:** `MediaVideoVisibilityTracker` 监听到全屏事件，通常会直接认为视频为 **可见**，而不需要进行复杂的遮挡计算。

**用户或编程常见的使用错误:**

1. **错误的 `visibility_threshold_` 设置:**  如果 `visibility_threshold_` 设置得过高，即使视频只有一小部分被遮挡，也可能被错误地判断为不可见。反之，如果设置得过低，即使视频大部分被遮挡，也可能被错误地判断为可见。

2. **没有考虑 CSS 动画或过渡:**  如果 CSS 动画或过渡导致元素在短时间内遮挡或显示视频，`MediaVideoVisibilityTracker` 的定时检测可能无法捕捉到这些短暂的变化，导致可见性状态的更新不及时。

3. **在 Shadow DOM 中操作视频元素时未考虑隔离性:**  虽然 `MediaVideoVisibilityTracker` 会忽略用户代理的 Shadow Root，但如果开发者在自定义的 Shadow DOM 中创建遮挡元素，需要确保这些元素被正确地纳入可见性判断的考虑范围（尽管这个文件似乎没有直接处理自定义 Shadow DOM 的特殊情况，但这是使用 Shadow DOM 时需要注意的）。

4. **过度依赖可见性状态进行关键操作而不做额外验证:**  虽然 `MediaVideoVisibilityTracker` 提供了视频可见性的信息，但在执行一些关键操作（例如自动播放）时，仍然需要结合其他因素（例如用户交互、浏览器策略）进行判断，不能完全依赖这个组件的输出。

5. **忘记在不再需要时清理或取消注册监听器:**  虽然这个文件看起来是引擎内部的组件，但如果存在与之交互的上层逻辑，忘记清理相关的监听器或回调函数可能会导致内存泄漏或其他问题。

总而言之，`media_video_visibility_tracker.cc` 是 Blink 引擎中一个关键的组件，它负责准确地判断 HTML `<video>` 元素在用户视口中的可见性，这对于优化视频播放体验、节省资源以及实现一些基于可见性的功能至关重要。它深入地结合了 HTML 结构、CSS 样式以及 JavaScript 的交互，共同构建了强大的 Web 平台能力。

Prompt: 
```
这是目录为blink/renderer/core/html/media/media_video_visibility_tracker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/media_video_visibility_tracker.h"

#include "base/metrics/histogram_macros.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_video.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item_list.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_artifact.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

namespace {

// Do a rect-based penetrating list hit test, with a callback that is executed
// at each node.
HitTestResult HitTestForOcclusionRatio(
    const HTMLVideoElement& video_element,
    const PhysicalRect& hit_rect,
    std::optional<HitTestRequest::HitNodeCb> hit_node_cb) {
  LocalFrame* frame = video_element.GetDocument().GetFrame();
  DCHECK(!frame->View()->NeedsLayout());
  HitTestRequest::HitTestRequestType hit_type =
      HitTestRequest::kIgnorePointerEventsNone | HitTestRequest::kReadOnly |
      HitTestRequest::kIgnoreClipping |
      HitTestRequest::kIgnoreZeroOpacityObjects |
      HitTestRequest::kHitTestVisualOverflow | HitTestRequest::kListBased |
      HitTestRequest::kPenetratingList | HitTestRequest::kAvoidCache;
  HitTestLocation location(hit_rect);
  return frame->GetEventHandler().HitTestResultAtLocation(
      location, hit_type, video_element.GetLayoutObject(), true, hit_node_cb);
}

float ComputeArea(const PhysicalRect& rect) {
  return static_cast<float>(ToRoundedSize(rect.size).Area64());
}

bool HasEnoughVisibleAreaRemaining(float occluded_area,
                                   const PhysicalRect& video_element_rect,
                                   const int visibility_threshold) {
  return ComputeArea(video_element_rect) - occluded_area >=
         visibility_threshold;
}

float ComputeOccludingArea(const Vector<SkIRect>& occluding_rects,
                           float video_element_area) {
  // Record the total time spent computing the occluding area.
  SCOPED_UMA_HISTOGRAM_TIMER_MICROS(
      "Media.MediaVideoVisibilityTracker.ComputeOcclusion.ComputeOccludingArea."
      "TotalDuration");

  float occluding_area = 0.0;

  std::vector<SkIRect> sk_rects;
  for (const auto rect : occluding_rects) {
    sk_rects.push_back(rect);
  }

  SkRegion region;
  bool compute_area = region.setRects(sk_rects.data(), occluding_rects.size());

  if (!compute_area) {
    return occluding_area;
  }

  for (SkRegion::Iterator it(region); !it.done(); it.next()) {
    auto occluding_rect = it.rect();
    occluding_area +=
        ComputeArea(PhysicalRect(gfx::SkIRectToRect(occluding_rect)));

    if (occluding_area >= video_element_area) {
      return video_element_area;
    }
  }

  return occluding_area;
}

// Records various UMA metrics related to hit testing and occlusion. All metrics
// recorded by this method represent total counts/percentages after identifying
// whether the `VideoElement` visibility threshold is met (or not).
void RecordTotalCounts(const MediaVideoVisibilityTracker::Metrics& counts) {
  // Limit used to indicate whether a linear histogram will be recorded or not.
  // If any of the method parameters is <= kRecordLinearHistogramLimit, a linear
  // histogram will be recorded for that parameter.
  //
  // The limit is used to be able to get fine grained detail at the lower end of
  // the range. Once we know the overall distribution, future linear histograms
  // can be added as needed.
  const int kRecordLinearHistogramLimit = 101;

  //////////////////////////////////////////////////////////////////////////////
  // Record counts.

  // Record the total number of hit tested nodes that contribute to occlusion.
  UMA_HISTOGRAM_COUNTS_1000(
      "Media.MediaVideoVisibilityTracker."
      "HitTestedNodesContributingToOcclusionCount.ExponentialHistogram."
      "TotalCount",
      counts.total_hit_tested_nodes_contributing_to_occlusion);

  if (counts.total_hit_tested_nodes_contributing_to_occlusion <=
      kRecordLinearHistogramLimit) {
    UMA_HISTOGRAM_EXACT_LINEAR(
        "Media.MediaVideoVisibilityTracker."
        "HitTestedNodesContributingToOcclusionCount.LinearHistogram.TotalCount",
        counts.total_hit_tested_nodes_contributing_to_occlusion,
        kRecordLinearHistogramLimit);
  }

  // Record the total number of hit tested nodes.
  UMA_HISTOGRAM_COUNTS_1000(
      "Media.MediaVideoVisibilityTracker.HitTestedNodesCount."
      "ExponentialHistogram.TotalCount",
      counts.total_hit_tested_nodes);

  if (counts.total_hit_tested_nodes <= kRecordLinearHistogramLimit) {
    UMA_HISTOGRAM_EXACT_LINEAR(
        "Media.MediaVideoVisibilityTracker.HitTestedNodesCount.LinearHistogram."
        "TotalCount",
        counts.total_hit_tested_nodes, kRecordLinearHistogramLimit);
  }

  // Record the total number of hit tested nodes that are ignored due to not
  // being opaque.
  UMA_HISTOGRAM_COUNTS_1000(
      "Media.MediaVideoVisibilityTracker.IgnoredNodesNotOpaqueCount."
      "ExponentialHistogram.TotalCount",
      counts.total_ignored_nodes_not_opaque);

  if (counts.total_ignored_nodes_not_opaque <= kRecordLinearHistogramLimit) {
    UMA_HISTOGRAM_EXACT_LINEAR(
        "Media.MediaVideoVisibilityTracker.IgnoredNodesNotOpaqueCount."
        "LinearHistogram.TotalCount",
        counts.total_ignored_nodes_not_opaque, kRecordLinearHistogramLimit);
  }

  // Record the total number of hit tested nodes that are ignored due to being
  // in the shadow root and of user agent type.
  UMA_HISTOGRAM_COUNTS_1000(
      "Media.MediaVideoVisibilityTracker.IgnoredNodesUserAgentShadowRootCount."
      "ExponentialHistogram."
      "TotalCount",
      counts.total_ignored_nodes_user_agent_shadow_root);

  if (counts.total_ignored_nodes_user_agent_shadow_root <=
      kRecordLinearHistogramLimit) {
    UMA_HISTOGRAM_EXACT_LINEAR(
        "Media.MediaVideoVisibilityTracker."
        "IgnoredNodesUserAgentShadowRootCount.LinearHistogram.TotalCount",
        counts.total_ignored_nodes_user_agent_shadow_root,
        kRecordLinearHistogramLimit);
  }

  // Record the total number of occluding rects.
  UMA_HISTOGRAM_COUNTS_1000(
      "Media.MediaVideoVisibilityTracker.OccludingRectsCount."
      "ExponentialHistogram.TotalCount",
      counts.total_occluding_rects);

  if (counts.total_occluding_rects <= kRecordLinearHistogramLimit) {
    UMA_HISTOGRAM_EXACT_LINEAR(
        "Media.MediaVideoVisibilityTracker.OccludingRectsCount.LinearHistogram."
        "TotalCount",
        counts.total_occluding_rects, kRecordLinearHistogramLimit);
  }

  //////////////////////////////////////////////////////////////////////////////
  // Record percentages.

  int ignored_nodes_not_opaque_percentage = 0;
  int ignored_nodes_user_agent_shadow_root_percentage = 0;
  int total_hit_tested_nodes_contributing_to_occlusion_percentage = 0;

  if (counts.total_hit_tested_nodes != 0) {
    ignored_nodes_not_opaque_percentage =
        100 * counts.total_ignored_nodes_not_opaque /
        counts.total_hit_tested_nodes;
    ignored_nodes_user_agent_shadow_root_percentage =
        100 * counts.total_ignored_nodes_user_agent_shadow_root /
        counts.total_hit_tested_nodes;
    total_hit_tested_nodes_contributing_to_occlusion_percentage =
        100 * counts.total_hit_tested_nodes_contributing_to_occlusion /
        counts.total_hit_tested_nodes;
  }

  // Record the percentage of the total hit tested nodes that are ignored due to
  // not being opaque.
  UMA_HISTOGRAM_PERCENTAGE(
      "Media.MediaVideoVisibilityTracker.IgnoredNodesNotOpaque.Percentage",
      ignored_nodes_not_opaque_percentage);

  // Record the percentage of the total hit tested nodes that are ignored due to
  // being in the shadow root and of user agent type.
  UMA_HISTOGRAM_PERCENTAGE(
      "Media.MediaVideoVisibilityTracker.IgnoredNodesUserAgentShadowRoot."
      "Percentage",
      ignored_nodes_user_agent_shadow_root_percentage);

  // Record the percentage of the total hit tested nodes that contribute to
  // occlusion. total_hit_tested_nodes_contributing_to_occlusion_percentage
  UMA_HISTOGRAM_PERCENTAGE(
      "Media.MediaVideoVisibilityTracker."
      "NodesContributingToOcclusion.Percentage",
      total_hit_tested_nodes_contributing_to_occlusion_percentage);
}

const Vector<AtomicString>& FullscreenEventTypes() {
  DEFINE_STATIC_LOCAL(const Vector<AtomicString>, fullscreen_change_event_types,
                      ({event_type_names::kWebkitfullscreenchange,
                        event_type_names::kFullscreenchange}));
  return fullscreen_change_event_types;
}

// Returns true if `target` has `listener` event listener registered.
bool HasEventListenerRegistered(EventTarget& target,
                                const AtomicString& event_type,
                                const EventListener* listener) {
  EventListenerVector* listeners = target.GetEventListeners(event_type);
  if (!listeners) {
    return false;
  }

  for (const auto& registered_listener : *listeners) {
    if (registered_listener->Callback() == listener) {
      return true;
    }
  }

  return false;
}

// Returns true if `type` is of content type, false otherwise.
//
// In the context of the `MediaVideoVisibilityTracker`, we consider a
// `DisplayItem::Type` to be of content type if it is used to draw content that
// is relevant to occlusion computations.
bool IsContentType(DisplayItem::Type type) {
  return !(type == DisplayItem::kFrameOverlay ||
           type == DisplayItem::kForeignLayerLinkHighlight ||
           type == DisplayItem::kForeignLayerViewportScroll ||
           type == DisplayItem::kForeignLayerViewportScrollbar);
}

void RecordVideoOcclusionState(
    const HTMLVideoElement& video_element,
    const MediaVideoVisibilityTracker::OcclusionState& occlusion_state,
    bool has_sufficiently_visible_video,
    const int visibility_threshold) {
  std::ostringstream occluding_rects_stream;
  const auto& occluding_rects = occlusion_state.occluding_rects;

  for (wtf_size_t i = 0; i < occluding_rects.size(); ++i) {
    const auto& rect = gfx::SkIRectToRect(occluding_rects[i]);
    occluding_rects_stream << String::Format(
        "[x: %d, y: %d, width: %d, height: %d]", rect.x(), rect.y(),
        rect.width(), rect.height());
    if (i >= 0 && i < occluding_rects.size() - 1) {
      occluding_rects_stream << ", ";
    }
  }

  if (occluding_rects_stream.tellp() == 0) {
    occluding_rects_stream << "None";
  }

  const auto& intersection_rect = occlusion_state.intersection_rect;
  const String intersection_rect_string =
      intersection_rect.IsEmpty()
          ? "None"
          : String::Format("x: %d, y: %d, width: %d, height: %d",
                           intersection_rect.X().ToInt(),
                           intersection_rect.Y().ToInt(),
                           intersection_rect.Width().ToInt(),
                           intersection_rect.Height().ToInt());

  const auto& video_element_rect = occlusion_state.video_element_rect;
  const String video_element_rect_string =
      video_element_rect.IsEmpty()
          ? "None"
          : String::Format("x: %d, y: %d, width: %d, height: %d",
                           video_element_rect.X().ToInt(),
                           video_element_rect.Y().ToInt(),
                           video_element_rect.Width().ToInt(),
                           video_element_rect.Height().ToInt());

  const String occlusion_state_string = String::Format(
      "has sufficiently visible video: {%s}, occluded area: {%.2f}, occluding "
      "rects: {%s}, intersection rect: {%s}, video element rect: {%s}, "
      "visibility threshold: {%d}",
      has_sufficiently_visible_video ? "True" : "False",
      occlusion_state.occluded_area, occluding_rects_stream.str().c_str(),
      intersection_rect_string.Ascii().c_str(),
      video_element_rect_string.Ascii().c_str(), visibility_threshold);

  video_element.RecordVideoOcclusionState(
      occlusion_state_string.Ascii().c_str());
}

}  // anonymous namespace

MediaVideoVisibilityTracker::MediaVideoVisibilityTracker(
    HTMLVideoElement& video,
    const int visibility_threshold,
    ReportVisibilityCb report_visibility_cb,
    base::TimeDelta hit_test_interval)
    : video_element_(video),
      visibility_threshold_(visibility_threshold),
      report_visibility_cb_(std::move(report_visibility_cb)),
      hit_test_interval_(hit_test_interval) {
  DCHECK(report_visibility_cb_);
  DCHECK_GT(visibility_threshold_, 0)
      << "Invalid threshold: " << visibility_threshold_;
  DCHECK_GE(hit_test_interval_, kMinimumAllowedHitTestInterval);
}

MediaVideoVisibilityTracker::~MediaVideoVisibilityTracker() {
  DCHECK(!tracker_attached_to_document_);
}

void MediaVideoVisibilityTracker::Attach() {
  const auto& video_element = VideoElement();
  auto* document = &video_element.GetDocument();
  auto* document_view = document->View();

  if (tracker_attached_to_document_) {
    DCHECK_EQ(tracker_attached_to_document_, document);
    return;
  }

  if (!video_element.isConnected() || !document_view) {
    return;
  }

  document_view->RegisterForLifecycleNotifications(this);
  MaybeAddFullscreenEventListeners();

  tracker_attached_to_document_ = document;
}

void MediaVideoVisibilityTracker::Detach() {
  if (!tracker_attached_to_document_) {
    return;
  }

  if (auto* view = tracker_attached_to_document_->View()) {
    view->UnregisterFromLifecycleNotifications(this);
  }

  MaybeRemoveFullscreenEventListeners();

  meets_visibility_threshold_ = false;
  tracker_attached_to_document_ = nullptr;
}

void MediaVideoVisibilityTracker::UpdateVisibilityTrackerState() {
  const auto& video_element = VideoElement();

  // `fullscreen_element` is used to determine if any element within the
  // document is in fullscreen. This could be the video element itself, or any
  // other element.
  Element* fullscreen_element =
      Fullscreen::FullscreenElementFrom(video_element.GetDocument());

  if (video_element.GetWebMediaPlayer() &&
      video_element.GetExecutionContext() && !video_element.paused() &&
      !fullscreen_element) {
    Attach();
  } else {
    Detach();
  }
}

void MediaVideoVisibilityTracker::ElementDidMoveToNewDocument() {
  Detach();
}

void MediaVideoVisibilityTracker::Invoke(ExecutionContext* context,
                                         Event* event) {
  DCHECK(base::Contains(FullscreenEventTypes(), event->type()));

  // Video is not loaded yet.
  if (VideoElement().getReadyState() < HTMLMediaElement::kHaveMetadata) {
    return;
  }

  UpdateVisibilityTrackerState();
}

void MediaVideoVisibilityTracker::MaybeAddFullscreenEventListeners() {
  auto& document = VideoElement().GetDocument();
  for (const auto& event_type : FullscreenEventTypes()) {
    // Ignore event listeners that have already been registered.
    if (HasEventListenerRegistered(document, event_type, this)) {
      continue;
    }
    document.addEventListener(event_type, this, true);
  }
}

void MediaVideoVisibilityTracker::MaybeRemoveFullscreenEventListeners() {
  DCHECK(tracker_attached_to_document_);
  auto& video_element = VideoElement();
  auto& document = VideoElement().GetDocument();

  if (video_element.isConnected() &&
      document == tracker_attached_to_document_) {
    return;
  }

  if (!video_element.isConnected()) {
    // Ignore event listeners that have already been removed.
    for (const auto& event_type : FullscreenEventTypes()) {
      if (!HasEventListenerRegistered(document, event_type, this)) {
        continue;
      }
      document.removeEventListener(event_type, this, true);
    }
  }

  if (document != tracker_attached_to_document_) {
    // Ignore event listeners that have already been removed.
    for (const auto& event_type : FullscreenEventTypes()) {
      if (!HasEventListenerRegistered(*tracker_attached_to_document_.Get(),
                                      event_type, this)) {
        continue;
      }
      tracker_attached_to_document_->removeEventListener(event_type, this,
                                                         true);
    }
  }
}

void MediaVideoVisibilityTracker::RequestVisibility(
    RequestVisibilityCallback request_visibility_callback) {
  // Latest requests take precedence over old ones. Therefore, if we had a
  // pending request, we simply run the current callback with `false` and store
  // the new one.
  if (request_visibility_callback_) {
    std::move(request_visibility_callback_).Run(false);
  }

  request_visibility_callback_ = std::move(request_visibility_callback);
  MaybeComputeVisibility(ShouldReportVisibility::kNo);
}

const MediaVideoVisibilityTracker::ClientIdsSet
MediaVideoVisibilityTracker::GetClientIdsSet(
    DisplayItemClientId start_after_display_item_client_id) const {
  SCOPED_UMA_HISTOGRAM_TIMER(
      "Media.MediaVideoVisibilityTracker.GetClientIdsSet.SetConstruction."
      "TotalDuration");

  auto* document_view = VideoElement().GetDocument().View();

  if (!document_view) {
    return {};
  }

  LocalFrameView::InvalidationDisallowedScope invalidation_disallowed(
      *document_view);

  const auto& paint_artifact = document_view->GetPaintArtifact();
  const DisplayItemList& display_item_list =
      paint_artifact.GetDisplayItemList();
  if (display_item_list.IsEmpty()) {
    return {};
  }

  wtf_size_t begin_index = 0;
  wtf_size_t end_index = display_item_list.size();
  while (begin_index < end_index && display_item_list[begin_index].ClientId() !=
                                        start_after_display_item_client_id) {
    begin_index++;
  }

  // Skip DisplayItem with `start_after_display_item_client_id`
  // DisplayItemClientId.
  begin_index++;
  if (begin_index == kNotFound || begin_index >= end_index) {
    return {};
  }

  // TODO(crbug.com/40275580): Remove `IsContentType` method, if the set size is
  // not significantly reduced.
  //
  // Ignore display items that are not of content type.
  // This is strictly an optimization, in an attempt to reduce the resulting set
  // size.
  //
  // We start at the end of the list, since the `DisplayItemList` entries are
  // stored in paint order. `DisplayItem` s that are not of content type can
  // still appear in other locations within the list, however for most cases,
  // these `DisplayItem` types are painted last.
  int not_content_type_count = 0;
  while (end_index > begin_index &&
         !IsContentType(display_item_list[end_index - 1].GetType())) {
    not_content_type_count++;
    end_index--;
  }
  UMA_HISTOGRAM_COUNTS_10000(
      "Media.MediaVideoVisibilityTracker.GetClientIdsSet.NotContentTypeCount."
      "TotalCount",
      not_content_type_count);

  if (begin_index == end_index) {
    return {};
  }

  MediaVideoVisibilityTracker::ClientIdsSet set;
  for (const auto& display_item :
       display_item_list.ItemsInRange(begin_index, end_index)) {
    if (display_item.ClientId() != kInvalidDisplayItemClientId) {
      set.insert(display_item.ClientId());
    }
  }

  int set_size = base::saturated_cast<int>(set.size());
  UMA_HISTOGRAM_COUNTS_10000(
      "Media.MediaVideoVisibilityTracker.GetClientIdsSet.ItemsInSetCount."
      "TotalCount",
      set_size);

  int not_content_type_percentage = 0;
  if (set_size > 0) {
    not_content_type_percentage = 100 * not_content_type_count / set_size;
  }
  UMA_HISTOGRAM_PERCENTAGE(
      "Media.MediaVideoVisibilityTracker.GetClientIdsSet.NotContentType."
      "Percentage",
      not_content_type_percentage);

  return set;
}

ListBasedHitTestBehavior MediaVideoVisibilityTracker::ComputeOcclusion(
    const ClientIdsSet& client_ids_set,
    Metrics& counts,
    const Node& node) {
  counts.total_hit_tested_nodes++;

  if (node == VideoElement()) {
    return kStopHitTesting;
  }

  // Ignore nodes with a containing shadow root of type
  // ShadowRootType::kUserAgent (e.g Video Controls).
  if (node.IsInShadowTree() && node.ContainingShadowRoot() &&
      node.ContainingShadowRoot()->IsUserAgent()) {
    counts.total_ignored_nodes_user_agent_shadow_root++;
    return kContinueHitTesting;
  }

  // Ignore nodes that are not opaque. We are only interested on evaluating
  // nodes that visually occlude the video, as seen by the user.
  if (!node.GetLayoutObject()->HasNonZeroEffectiveOpacity()) {
    counts.total_ignored_nodes_not_opaque++;
    return kContinueHitTesting;
  }

  // Ignore nodes that do not produce any visual content.
  if (!client_ids_set.empty() &&
      !client_ids_set.Contains(node.GetLayoutObject()->Id())) {
    return kContinueHitTesting;
  }

  // Only account for the intersection of |node_rect| BoundingBox with
  // |occlusion_state_.intersection_rect|. Note that BoundingBox represents an
  // approximation of the total area that is painted. The actual painted area
  // can be larger (e.g., if the object paints drop shadows), or smaller (e.g.,
  // if the object is clipped).
  PhysicalRect node_rect = node.BoundingBox();
  node_rect.Intersect(occlusion_state_.intersection_rect);

  // Add the current occluding node rect to `occlusion_state_.occluding_rects`
  // and compute the total occluded area.
  occlusion_state_.occluding_rects.push_back(
      gfx::RectToSkIRect(ToPixelSnappedRect(node_rect)));
  occlusion_state_.occluded_area =
      ComputeOccludingArea(occlusion_state_.occluding_rects,
                           ComputeArea(occlusion_state_.video_element_rect));

  counts.total_hit_tested_nodes_contributing_to_occlusion++;

  if (HasEnoughVisibleAreaRemaining(occlusion_state_.occluded_area,
                                    occlusion_state_.video_element_rect,
                                    visibility_threshold_)) {
    return kContinueHitTesting;
  }

  return kStopHitTesting;
}

bool MediaVideoVisibilityTracker::MeetsVisibilityThreshold(
    Metrics& counts,
    const PhysicalRect& rect) {
  const ClientIdsSet client_ids_set =
      GetClientIdsSet(VideoElement().GetLayoutObject()->Id());

  {
    // Record the total time spent computing occlusion.
    SCOPED_UMA_HISTOGRAM_TIMER(
        "Media.MediaVideoVisibilityTracker.ComputeOcclusion.TotalDuration");

    HitTestResult result(HitTestForOcclusionRatio(
        VideoElement(), rect,
        WTF::BindRepeating(&MediaVideoVisibilityTracker::ComputeOcclusion,
                           WrapPersistent(this), client_ids_set,
                           std::ref(counts))));
  }

  return HasEnoughVisibleAreaRemaining(occlusion_state_.occluded_area,
                                       occlusion_state_.video_element_rect,
                                       visibility_threshold_)
             ? true
             : false;
}

bool MediaVideoVisibilityTracker::ComputeVisibility() {
  DCHECK(VideoElement().GetLayoutObject());
  occlusion_state_.occluded_area =
      ComputeOccludingArea(occlusion_state_.occluding_rects,
                           ComputeArea(occlusion_state_.video_element_rect));
  auto intersection_area = ComputeArea(occlusion_state_.intersection_rect);

  auto* layout = VideoElement().GetLayoutObject();
  // Return early if the area of the video that intersects with the view is
  // below |visibility_threshold_|.
  if (!layout || intersection_area < visibility_threshold_) {
    return false;
  }

  Metrics counts;
  bool meets_visibility_threshold =
      MeetsVisibilityThreshold(counts, occlusion_state_.intersection_rect);

  counts.total_occluding_rects =
      base::saturated_cast<int>(occlusion_state_.occluding_rects.size());
  RecordTotalCounts(counts);

  if (meets_visibility_threshold) {
    return true;
  }

  return false;
}

void MediaVideoVisibilityTracker::ComputeAreaOccludedByViewport(
    const LocalFrameView& local_frame_view) {
  DCHECK(VideoElement().GetLayoutObject());

  LayoutBox* box = To<LayoutBox>(VideoElement().GetLayoutObject());
  gfx::Rect bounds(box->AbsoluteBoundingBoxRect());

  gfx::Rect content_bounds;
  if (auto* layout_video =
          DynamicTo<LayoutVideo>(VideoElement().GetLayoutObject())) {
    PhysicalRect content_rect = layout_video->ReplacedContentRect();
    content_bounds = VideoElement().GetDocument().View()->FrameToViewport(
        ToEnclosingRect(layout_video->LocalToAbsoluteRect(content_rect)));
    content_bounds.Intersect(bounds);
  }

  // Fallback to using the video element bounds, if the computed
  // `content_bounds` is empty.
  if (content_bounds.IsEmpty()) {
    content_bounds = bounds;
  }

  gfx::Rect viewport_in_root_frame = ToEnclosingRect(
      local_frame_view.GetFrame().GetPage()->GetVisualViewport().VisibleRect());
  gfx::Rect absolute_viewport(
      local_frame_view.ConvertFromRootFrame(viewport_in_root_frame));
  occlusion_state_.intersection_rect =
      PhysicalRect(IntersectRects(absolute_viewport, content_bounds));

  occlusion_state_.video_element_rect = PhysicalRect(content_bounds);

  // Compute the VideoElement area that is occluded by the viewport, if any.
  SkRegion region;
  region.setRect(gfx::RectToSkIRect(content_bounds));
  if (region.op(gfx::RectToSkIRect(absolute_viewport),
                SkRegion::kDifference_Op)) {
    for (SkRegion::Iterator it(region); !it.done(); it.next()) {
      auto occluding_rect = it.rect();
      occlusion_state_.occluding_rects.push_back(occluding_rect);
      it.next();
    }
  }
}

void MediaVideoVisibilityTracker::MaybeComputeVisibility(
    ShouldReportVisibility should_report_visibility) {
  if (!tracker_attached_to_document_ ||
      !tracker_attached_to_document_->GetFrame()->View() ||
      !tracker_attached_to_document_->GetFrame()->IsOutermostMainFrame() ||
      !VideoElement().GetLayoutObject()) {
    if (request_visibility_callback_) {
      RecordVideoOcclusionState(VideoElement(), occlusion_state_, false,
                                visibility_threshold_);
      std::move(request_visibility_callback_).Run(false);
    }
    return;
  }

  if (VideoElement().GetDocument().Lifecycle().GetState() !=
      DocumentLifecycle::kPaintClean) {
    // If we have a pending visibility request, run it now with the cached
    // `meets_visibility_threshold_` value.
    if (request_visibility_callback_) {
      RecordVideoOcclusionState(VideoElement(), occlusion_state_,
                                meets_visibility_threshold_,
                                visibility_threshold_);
      std::move(request_visibility_callback_).Run(meets_visibility_threshold_);
    }
    return;
  }

  SCOPED_UMA_HISTOGRAM_TIMER(
      "Media.MediaVideoVisibilityTracker.UpdateTime.TotalDuration");

  occlusion_state_ = {};
  ComputeAreaOccludedByViewport(
      *tracker_attached_to_document_->GetFrame()->View());

  meets_visibility_threshold_ = ComputeVisibility();
  if (should_report_visibility == ShouldReportVisibility::kYes) {
    report_visibility_cb_.Run(meets_visibility_threshold_);
  }
  if (request_visibility_callback_) {
    RecordVideoOcclusionState(VideoElement(), occlusion_state_,
                              meets_visibility_threshold_,
                              visibility_threshold_);
    std::move(request_visibility_callback_).Run(meets_visibility_threshold_);
  }
}

void MediaVideoVisibilityTracker::DidFinishLifecycleUpdate(
    const LocalFrameView& local_frame_view) {
  if ((base::TimeTicks::Now() - last_hit_test_timestamp_ <
       hit_test_interval_) &&
      !request_visibility_callback_) {
    return;
  }

  if (!VideoElement().GetLayoutObject()) {
    return;
  }

  last_hit_test_timestamp_ = base::TimeTicks::Now();

  MaybeComputeVisibility(ShouldReportVisibility::kYes);
}

void MediaVideoVisibilityTracker::Trace(Visitor* visitor) const {
  NativeEventListener::Trace(visitor);
  visitor->Trace(video_element_);
  visitor->Trace(tracker_attached_to_document_);
}

}  // namespace blink

"""

```
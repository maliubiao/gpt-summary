Response:
Let's break down the thought process for analyzing this code and generating the comprehensive response.

1. **Understand the Goal:** The request asks for the functionality of `AnchorElementViewportPositionTracker.cc`, its relation to web technologies (HTML, CSS, JavaScript), logical reasoning examples, and potential user/developer errors.

2. **Initial Skim for High-Level Functionality:** Read through the code, focusing on class names, key methods, and included headers. Keywords like "viewport," "anchor," "intersection observer," "metrics," and "navigation predictor" immediately jump out. This suggests the core purpose is tracking the visibility and position of anchor elements within the viewport, likely for performance or prediction purposes.

3. **Identify Key Components and their Interactions:**
    * **`AnchorElementViewportPositionTracker`:** The main class, responsible for managing the tracking. It's a `Supplement` to `Document`, meaning it adds functionality to a document.
    * **`IntersectionObserver`:**  Crucial for detecting when anchor elements enter or leave the viewport. This explains the `UpdateVisibleAnchors` method.
    * **`Observer` (nested class/interface):**  A way for other parts of the browser to receive updates about anchor visibility and position.
    * **Timers (`position_update_timer_`):** Used to delay and coordinate position updates, potentially to avoid excessive calculations during rapid scrolling.
    * **Data Structures (`observed_anchors_`, `not_observed_anchors_`, `anchors_in_viewport_`):** These store information about the anchors being tracked. The use of a `std::set` for `observed_anchors_` suggests a need for ordered elements based on area.
    * **Metrics (`mojom::blink::AnchorElementMetrics`):**  Indicates that certain characteristics of anchor elements are being measured and used for decisions (e.g., area).
    * **Feature Flags (`features::kNavigationPredictor`, `features::kNavigationPredictorNewViewportFeatures`):**  This means the functionality is likely experimental or controlled by configuration.

4. **Map Functionality to Web Technologies:**
    * **HTML:** The code directly deals with `HTMLAnchorElementBase` and `HTMLAreaElement`. The purpose is clearly related to how hyperlinks behave. The `#` symbol in URLs and smooth scrolling come to mind.
    * **CSS:** While the code doesn't directly manipulate CSS, the concept of "viewport" is fundamental to CSS layout. The visibility and positioning of elements are directly influenced by CSS rules.
    * **JavaScript:**  Intersection Observers are a JavaScript API. This code provides the underlying implementation for that feature within the Blink rendering engine. Developers use JavaScript to create and configure `IntersectionObserver` instances.

5. **Develop Examples and Scenarios:**
    * **Intersection Observer:**  Demonstrate the core use case: detecting when an anchor becomes visible.
    * **Viewport Position Tracking:** Show how scrolling affects the reported position and how the timer might work.
    * **Navigation Prediction (Hypothesis):**  Infer the purpose of tracking anchor positions – potentially to prefetch resources for links likely to be clicked.
    * **User/Developer Errors:** Think about common mistakes when using related web features:
        * Incorrect `href` attributes.
        * Misunderstanding how `IntersectionObserver` thresholds work.
        * Forgetting to handle asynchronous updates.

6. **Construct Logical Reasoning Examples (Hypothetical Inputs and Outputs):**  Create simple scenarios to illustrate how the code might behave:
    * **Scenario 1 (Initial Load):**  Show how elements entering the viewport trigger events.
    * **Scenario 2 (Scrolling):** Demonstrate the effect of scrolling and how the timer might delay updates.

7. **Address Potential User/Developer Errors:**  Focus on practical mistakes developers might make when working with anchor elements and related APIs.

8. **Organize and Refine the Response:** Structure the information logically with clear headings and bullet points. Use precise language and avoid jargon where possible. Ensure the examples are easy to understand. Double-check for accuracy and completeness. For example, make sure the connection to the JavaScript `IntersectionObserver` API is explicitly stated.

9. **Self-Critique and Iteration (Internal):**  Review the generated response. Is it clear? Does it cover all aspects of the request?  Are the examples helpful?  Could anything be explained better?  For instance,  initially, I might have focused too heavily on the internal implementation details. The critique would push me to make the connections to web technologies more explicit and provide more practical examples. I also need to ensure that the explanation about the timer's purpose is clear – it's not just a random delay, but related to the debouncing of intersection events after scrolling.

This iterative process of understanding, connecting concepts, generating examples, and refining the explanation leads to a comprehensive and accurate response like the example provided in the initial prompt.
这个C++源代码文件 `anchor_element_viewport_position_tracker.cc` 是 Chromium Blink 渲染引擎的一部分，其主要功能是**追踪 HTML 锚点元素（`<a href="#...">`）在视口中的位置和可见性变化**。 它的目标是收集与锚点元素相关的指标，以便用于优化导航预测等功能。

以下是该文件功能的详细列表，并结合了与 JavaScript、HTML 和 CSS 的关系以及逻辑推理和常见错误示例：

**主要功能:**

1. **视口交叉状态监控 (Viewport Intersection Monitoring):**
   - 使用 `IntersectionObserver` API 来监听锚点元素何时进入或离开浏览器的视口。
   - **与 JavaScript 的关系:**  `IntersectionObserver` 本身是一个 JavaScript API，该 C++ 代码提供了 Blink 引擎对该 API 的底层实现和使用。 网页开发者可以使用 JavaScript 创建 `IntersectionObserver` 实例来观察元素（包括锚点）的视口交叉状态。
   - **与 HTML 的关系:** 追踪的目标是 HTML 的 `<a>` 和 `<area>` 元素，这些元素通过 `href` 属性指向文档内的其他部分。
   - **与 CSS 的关系:**  CSS 影响元素的布局和渲染，从而决定元素是否在视口内。例如，`overflow: hidden` 可能导致元素的一部分不可见，影响 `IntersectionObserver` 的判断。
   - **假设输入与输出:**
     - **输入:**  一个包含锚点元素的 HTML 页面被加载，用户滚动页面。
     - **输出:**  当锚点元素的部分或全部进入视口时，`IntersectionObserver` 会触发回调，`UpdateVisibleAnchors` 方法会被调用。当锚点元素离开视口时，也会触发回调。

2. **记录锚点元素的可见时间 (Recording Time in Viewport):**
   - 通过观察锚点元素的交叉状态，可以计算出每个锚点元素在视口中停留的时间。这可以用于分析哪些锚点最有可能被用户点击。

3. **记录指针按下事件 (Recording Pointer Down Events):**
   - 监听 `pointerdown` 事件，并记录下指针在视口中的 Y 坐标。
   - **与 JavaScript 的关系:**  `pointerdown` 是一个 JavaScript 事件。此代码在 C++ 层捕获该事件的信息。
   - **与 HTML 的关系:**  指针事件通常与用户与页面元素的交互相关，包括点击链接。
   - **假设输入与输出:**
     - **输入:** 用户在一个链接上按下鼠标左键（或其他指针设备）。
     - **输出:** `RecordPointerDown` 方法会被调用，记录下按下时的 Y 坐标。

4. **在滚动结束后更新锚点位置信息 (Updating Anchor Position After Scroll):**
   - 在页面滚动结束后，会触发一个定时器，延迟一段时间后更新视口内的锚点元素的位置信息。
   - **原因:**  `IntersectionObserver` 的回调可能存在一定的延迟，为了确保获取最新的交叉状态和位置信息，需要在滚动结束后等待一段时间。
   - **假设输入与输出:**
     - **输入:** 用户完成一次页面滚动。
     - **输出:**  `OnScrollEnd` 方法被调用，启动 `position_update_timer_`。一段时间后，`PositionUpdateTimerFired` 方法被调用，最终触发 `DispatchAnchorElementsPositionUpdates` 来计算和分发锚点的位置信息。

5. **分发锚点元素的位置更新 (Dispatching Anchor Element Position Updates):**
   - 计算当前视口内锚点元素的一些关键位置信息，例如：
     - 垂直位置（相对于视口高度的比例）
     - 到上次指针按下位置的距离
     - 在视口中的大小
   - 将这些信息通知给注册的观察者 (`observers_`)。
   - **与 JavaScript 的关系:**  虽然这个类本身不直接与 JavaScript 交互，但它收集到的数据可能会被用于浏览器内部的 JavaScript 代码进行进一步处理或用于性能优化。
   - **与 HTML 的关系:**  位置信息是基于 HTML 元素的布局计算的。
   - **与 CSS 的关系:**  CSS 的样式会影响元素的布局和大小，从而影响计算出的位置信息。
   - **假设输入与输出:**
     - **输入:**  `DispatchAnchorElementsPositionUpdates` 方法被调用。
     - **输出:**  对于视口内的每个锚点元素，会计算出其垂直位置、到上次指针按下位置的距离以及大小，并将这些信息封装在 `AnchorPositionUpdate` 对象中，然后通知给观察者。

6. **限制观察的锚点数量 (Limiting the Number of Observed Anchors):**
   - 通过 Feature Flag `kNavigationPredictor` 控制最大观察的锚点数量。
   - 只会观察一定数量的“最重要”的锚点，可能是根据其在视口中的面积或其他指标来判断。
   - 这样做可以避免过度消耗资源。

7. **使用 Feature Flags 控制功能 (Using Feature Flags):**
   - 代码中使用了 Feature Flags (`kNavigationPredictor`, `kNavigationPredictorNewViewportFeatures`) 来控制某些功能的启用或禁用，这是一种常见的 Chromium 开发实践，用于实验性和灰度发布功能。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:** 当用户点击一个带有 `href="#section2"` 的锚点链接时，浏览器会尝试滚动到 ID 为 `section2` 的元素。 `AnchorElementViewportPositionTracker` 可能会记录下该锚点链接在点击前后的视口位置。
* **CSS:**  如果一个锚点元素被 CSS 样式设置为 `display: none;`，那么 `IntersectionObserver` 不会认为它在视口内，相关的回调也不会触发。
* **JavaScript:** 网页开发者可以使用 JavaScript 的 `IntersectionObserver` API 来实现类似的功能，例如，当某个锚点元素进入视口时，动态加载相关内容。 `AnchorElementViewportPositionTracker` 提供了 Blink 引擎内部的实现基础。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **初始加载:** 页面加载完成，视口中显示了 3 个锚点元素 A, B, C。
2. **用户滚动:** 用户向下滚动页面，元素 A 完全离开视口，元素 D 进入视口。
3. **用户点击:** 用户点击了视口中显示的锚点元素 B。

**输出:**

1. **初始加载:** `UpdateVisibleAnchors` 会被调用，报告 A, B, C 进入视口。
2. **用户滚动:** `UpdateVisibleAnchors` 会被调用，报告 A 离开视口，D 进入视口。
3. **用户点击:** `RecordPointerDown` 会记录下点击事件发生时的 Y 坐标。 `DispatchAnchorElementsPositionUpdates` 在滚动结束后会被触发，计算并报告 B 的位置信息，包括其相对于视口的高度和到点击位置的距离。

**用户或编程常见的使用错误举例说明:**

1. **HTML 锚点链接配置错误:**
   - **错误:**  `<a>` 元素的 `href` 属性指向了一个不存在的 ID (`<a href="#nonexistent">`)。
   - **结果:**  点击该链接时，浏览器不会滚动到任何位置，`AnchorElementViewportPositionTracker` 可能会记录到该锚点的点击事件，但其位置信息可能没有意义。

2. **误解 `IntersectionObserver` 的工作原理:**
   - **错误:**  开发者认为只要元素在文档中，`IntersectionObserver` 就会一直报告其信息，而没有考虑到视口交叉的概念。
   - **结果:**  只有当被观察的锚点元素至少部分出现在视口中时，`AnchorElementViewportPositionTracker` 才会记录其可见性和位置信息。

3. **与 JavaScript 的 `IntersectionObserver` 冲突:**
   - **错误:**  网页上的 JavaScript 代码也创建了 `IntersectionObserver` 来观察相同的锚点元素，并且假设了 Blink 内部的追踪机制不存在。
   - **结果:**  可能会出现重复的事件处理或数据收集，导致性能问题或逻辑错误。 虽然 Blink 内部的 `IntersectionObserver` 主要用于浏览器自身的优化，通常不会直接暴露给网页 JavaScript，但理解其存在对于高级开发和调试仍然重要。

4. **依赖不稳定的 Feature Flags:**
   - **错误:**  开发者在进行性能分析或实验时，过度依赖由 Feature Flags 控制的功能，而没有意识到这些 Flags 可能会在未来的 Chromium 版本中被移除或更改。
   - **结果:**  依赖这些内部机制的代码可能会在 Chromium 更新后失效。

总而言之，`anchor_element_viewport_position_tracker.cc` 是 Blink 引擎中一个关键的组成部分，它默默地工作着，收集关于用户如何与页面中的锚点链接交互的数据，为浏览器的优化和功能改进提供支持。虽然网页开发者通常不会直接与之交互，但了解其功能有助于更好地理解浏览器的工作方式和相关 Web API 的底层实现。

### 提示词
```
这是目录为blink/renderer/core/html/anchor_element_viewport_position_tracker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/anchor_element_viewport_position_tracker.h"

#include <limits>

#include "base/metrics/field_trial_params.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/loader/navigation_predictor.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/screen.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/anchor_element_metrics.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/graphics/dom_node_id.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"

namespace blink {

namespace {

constexpr float kIntersectionRatioThreshold = 0.5f;

wtf_size_t GetMaxNumberOfObservations() {
  const base::FeatureParam<int> max_number_of_observations{
      &features::kNavigationPredictor, "max_intersection_observations", -1};
  int value = max_number_of_observations.Get();
  return value >= 0 ? value : std::numeric_limits<wtf_size_t>::max();
}

base::TimeDelta GetIntersectionObserverDelay() {
  const base::FeatureParam<base::TimeDelta> param{
      &features::kNavigationPredictor, "intersection_observer_delay",
      base::Milliseconds(100)};
  return param.Get();
}

bool ShouldReportViewportPositions() {
  return base::FeatureList::IsEnabled(
      features::kNavigationPredictorNewViewportFeatures);
}

float GetBrowserControlsHeight(Document& document) {
  BrowserControls& controls = document.GetPage()->GetBrowserControls();
  if (controls.ShrinkViewport()) {
    return controls.ContentOffset();
  }
  return 0.f;
}

}  // namespace

void AnchorElementViewportPositionTracker::Observer::AnchorPositionUpdate::
    Trace(Visitor* visitor) const {
  visitor->Trace(anchor_element);
}

// static
const char AnchorElementViewportPositionTracker::kSupplementName[] =
    "DocumentAnchorElementViewportPositionTracker";

AnchorElementViewportPositionTracker::AnchorElementViewportPositionTracker(
    Document& document)
    : Supplement<Document>(document),
      max_number_of_observations_(GetMaxNumberOfObservations()),
      intersection_observer_delay_(GetIntersectionObserverDelay()),
      position_update_timer_(
          document.GetExecutionContext()->GetTaskRunner(
              TaskType::kInternalDefault),
          this,
          &AnchorElementViewportPositionTracker::PositionUpdateTimerFired) {
  intersection_observer_ = IntersectionObserver::Create(
      document,
      WTF::BindRepeating(
          &AnchorElementViewportPositionTracker::UpdateVisibleAnchors,
          WrapWeakPersistent(this)),
      LocalFrameUkmAggregator::kAnchorElementMetricsIntersectionObserver,
      {.thresholds = {kIntersectionRatioThreshold},
       .delay = intersection_observer_delay_});
}

AnchorElementViewportPositionTracker::~AnchorElementViewportPositionTracker() =
    default;

void AnchorElementViewportPositionTracker::Trace(Visitor* visitor) const {
  Supplement<Document>::Trace(visitor);
  visitor->Trace(intersection_observer_);
  visitor->Trace(anchors_in_viewport_);
  visitor->Trace(position_update_timer_);
  visitor->Trace(observers_);
}

// static
AnchorElementViewportPositionTracker*
AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(Document& document) {
  if (!document.GetFrame() || !document.GetFrame()->IsOutermostMainFrame()) {
    return nullptr;
  }

  AnchorElementViewportPositionTracker* tracker =
      Supplement<Document>::From<AnchorElementViewportPositionTracker>(
          document);
  if (tracker) {
    return tracker;
  }

  tracker =
      MakeGarbageCollected<AnchorElementViewportPositionTracker>(document);
  ProvideTo(document, tracker);
  return tracker;
}

void AnchorElementViewportPositionTracker::AddObserver(
    AnchorElementViewportPositionTracker::Observer* observer) {
  observers_.insert(observer);
}

HTMLAnchorElementBase* AnchorElementViewportPositionTracker::MaybeObserveAnchor(
    HTMLAnchorElementBase& anchor_element,
    const mojom::blink::AnchorElementMetrics& metrics) {
  if (!max_number_of_observations_) {
    return nullptr;
  }

  int percent_area =
      std::clamp(static_cast<int>(metrics.ratio_area * 100.0f), 0, 100);
  bool should_observe = false;
  HTMLAnchorElementBase* anchor_unobserved = nullptr;
  if (observed_anchors_.size() < max_number_of_observations_) {
    should_observe = true;
  } else if (auto smallest_observed_anchor_it = observed_anchors_.begin();
             smallest_observed_anchor_it->percent_area < percent_area) {
    should_observe = true;
    Node* node =
        DOMNodeIds::NodeForId(smallest_observed_anchor_it->dom_node_id);
    CHECK(node);
    anchor_unobserved = To<HTMLAnchorElementBase>(node);
    intersection_observer_->unobserve(anchor_unobserved);
    not_observed_anchors_.insert(
        observed_anchors_.extract(smallest_observed_anchor_it));
  }

  if (should_observe) {
    // Observe the element to collect time_in_viewport stats.
    intersection_observer_->observe(&anchor_element);
    observed_anchors_.insert(
        {.percent_area = percent_area,
         .dom_node_id = DOMNodeIds::IdForNode(&anchor_element)});
  } else {
    not_observed_anchors_.insert(
        {.percent_area = percent_area,
         .dom_node_id = DOMNodeIds::IdForNode(&anchor_element)});
  }

  return anchor_unobserved;
}

void AnchorElementViewportPositionTracker::RemoveAnchor(
    HTMLAnchorElementBase& anchor) {
  if (DOMNodeId node_id = DOMNodeIds::ExistingIdForNode(&anchor);
      node_id && max_number_of_observations_) {
    // Note: We use base::ranges::find instead of std::set::find here
    // (and below) as we don't have a way to map HTMLAnchorElementBase ->
    // AnchorObservation. We could add one if doing an O(N) find here is too
    // expensive.
    if (auto observed_anchors_it = base::ranges::find(
            observed_anchors_, node_id, &AnchorObservation::dom_node_id);
        observed_anchors_it != observed_anchors_.end()) {
      intersection_observer_->unobserve(&anchor);
      observed_anchors_.erase(observed_anchors_it);
      if (!not_observed_anchors_.empty()) {
        auto largest_non_observed_anchor_it =
            std::prev(not_observed_anchors_.end());
        intersection_observer_->observe(To<Element>(DOMNodeIds::NodeForId(
            largest_non_observed_anchor_it->dom_node_id)));
        observed_anchors_.insert(
            not_observed_anchors_.extract(largest_non_observed_anchor_it));
      }
    } else if (auto not_observed_anchors_it =
                   base::ranges::find(not_observed_anchors_, node_id,
                                      &AnchorObservation::dom_node_id);
               not_observed_anchors_it != not_observed_anchors_.end()) {
      not_observed_anchors_.erase(not_observed_anchors_it);
    }
  }
}

void AnchorElementViewportPositionTracker::RecordPointerDown(
    const PointerEvent& pointer_event) {
  CHECK_EQ(pointer_event.type(), event_type_names::kPointerdown);
  Document* document = pointer_event.GetDocument();
  // TODO(crbug.com/347719430): LocalFrameView::FrameToViewport called below
  // doesn't work for subframes whose local root is not the main frame.
  if (!document || !document->GetFrame()->LocalFrameRoot().IsMainFrame()) {
    return;
  }

  gfx::PointF pointer_down_location = pointer_event.AbsoluteLocation();
  pointer_down_location =
      document->GetFrame()->View()->FrameToViewport(pointer_down_location);
  pointer_down_location.Offset(0,
                               GetBrowserControlsHeight(*GetSupplementable()));
  last_pointer_down_ = pointer_down_location.y();
}

void AnchorElementViewportPositionTracker::OnScrollEnd() {
  if (!ShouldReportViewportPositions()) {
    return;
  }

  // At this point, we're unsure of whether we have the latest
  // IntersectionObserver data or not (`intersection_observer_` is configured
  // with a delay), and the post-scroll intersection computations may or may not
  // have happened yet. We set a timer for `intersection_observer_delay_` and
  // wait for either:
  // 1) `UpdateVisibleAnchors` to be called before the timer (we stop the timer)
  // 2) The timer finishes (no intersection changes and `UpdateVisibleAnchors`
  //    wasn't called)
  // After either of the two conditions are met, we wait for a lifecycle update
  // before computing anchor element position metrics.

  // `position_update_timer_` might already be active in a scenario where a
  // second scroll completes before the timer finishes.
  if (!position_update_timer_.IsActive()) {
    position_update_timer_.StartOneShot(intersection_observer_delay_,
                                        FROM_HERE);
  }
}

IntersectionObserver*
AnchorElementViewportPositionTracker::GetIntersectionObserverForTesting() {
  return intersection_observer_;
}

void AnchorElementViewportPositionTracker::UpdateVisibleAnchors(
    const HeapVector<Member<IntersectionObserverEntry>>& entries) {
  DCHECK(base::FeatureList::IsEnabled(features::kNavigationPredictor));
  DCHECK(!entries.empty());
  if (!GetSupplementable()->GetFrame()) {
    return;
  }

  HeapVector<Member<const HTMLAnchorElementBase>> entered_viewport;
  HeapVector<Member<const HTMLAnchorElementBase>> left_viewport;

  for (const auto& entry : entries) {
    const Element* element = entry->target();
    const HTMLAnchorElementBase& anchor_element =
        To<HTMLAnchorElementBase>(*element);
    if (!entry->isIntersecting()) {
      // The anchor is leaving the viewport.
      anchors_in_viewport_.erase(&anchor_element);
      left_viewport.push_back(&anchor_element);
    } else {
      // The anchor is visible.
      anchors_in_viewport_.insert(&anchor_element);
      entered_viewport.push_back(&anchor_element);
    }
  }

  if (position_update_timer_.IsActive()) {
    CHECK(ShouldReportViewportPositions());
    position_update_timer_.Stop();
    RegisterForLifecycleNotifications();
  }

  for (Observer* observer : observers_) {
    observer->ViewportIntersectionUpdate(entered_viewport, left_viewport);
  }
}

void AnchorElementViewportPositionTracker::PositionUpdateTimerFired(
    TimerBase*) {
  CHECK(ShouldReportViewportPositions());
  if (LocalFrameView* view = GetSupplementable()->View()) {
    view->ScheduleAnimation();
    RegisterForLifecycleNotifications();
  }
}

void AnchorElementViewportPositionTracker::DidFinishLifecycleUpdate(
    const LocalFrameView& local_frame_view) {
  CHECK(ShouldReportViewportPositions());
  Document* document = local_frame_view.GetFrame().GetDocument();
  if (document->Lifecycle().GetState() <
      DocumentLifecycle::kAfterPerformLayout) {
    return;
  }
  if (!GetSupplementable()->GetFrame()) {
    return;
  }
  DispatchAnchorElementsPositionUpdates();
  DCHECK_EQ(&local_frame_view, GetSupplementable()->View());
  DCHECK(is_registered_for_lifecycle_notifications_);
  GetSupplementable()->View()->UnregisterFromLifecycleNotifications(this);
  is_registered_for_lifecycle_notifications_ = false;
}

void AnchorElementViewportPositionTracker::
    DispatchAnchorElementsPositionUpdates() {
  CHECK(ShouldReportViewportPositions());

  Screen* screen = GetSupplementable()->domWindow()->screen();
  FrameWidget* widget =
      GetSupplementable()->GetFrame()->GetWidgetForLocalRoot();
  Page* page = GetSupplementable()->GetPage();
  if (!screen || !widget || !page) {
    return;
  }

  const int screen_height_dips = screen->height();
  const int viewport_height = page->GetVisualViewport().Size().height();
  if (!screen_height_dips || !viewport_height) {
    return;
  }

  const float screen_height = widget->DIPsToBlinkSpace(screen_height_dips);
  const float browser_controls_height =
      GetBrowserControlsHeight(*GetSupplementable());

  HeapVector<Member<Observer::AnchorPositionUpdate>> position_updates;
  for (const HTMLAnchorElementBase* anchor : anchors_in_viewport_) {
    LocalFrame* frame = anchor->GetDocument().GetFrame();
    if (!frame) {
      continue;
    }
    const LocalFrame& local_root = frame->LocalFrameRoot();
    // TODO(crbug.com/347719430): LocalFrameView::FrameToViewport called below
    // doesn't work for subframes whose local root is not the main frame.
    if (!local_root.IsMainFrame()) {
      continue;
    }

    gfx::Rect rect = anchor->VisibleBoundsInLocalRoot();
    if (rect.IsEmpty()) {
      continue;
    }
    rect = local_root.View()->FrameToViewport(rect);
    rect.Offset(0, browser_controls_height);
    float center_point_y = gfx::RectF(rect).CenterPoint().y();

    // TODO(crbug.com/347638530): Ideally we would do this entire calculation
    // in screen coordinates and use screen_height (that would be a more useful
    // metric for us), but we don't have an accurate way to do so right now.
    float vertical_position =
        center_point_y / (viewport_height + browser_controls_height);

    std::optional<float> distance_from_pointer_down_ratio;
    if (last_pointer_down_.has_value()) {
      // Note: Distances in viewport space should be the same as distances in
      // screen space, so dividing by |screen_height| instead of viewport height
      // is fine (and likely a more useful metric).
      float distance_from_pointer_down =
          center_point_y - last_pointer_down_.value();
      distance_from_pointer_down_ratio =
          distance_from_pointer_down / screen_height;
    }
    auto* position_update =
        MakeGarbageCollected<Observer::AnchorPositionUpdate>();
    position_update->anchor_element = anchor;
    position_update->vertical_position = vertical_position;
    position_update->distance_from_pointer_down =
        distance_from_pointer_down_ratio;
    position_update->size_in_viewport =
        rect.size().GetCheckedArea().ValueOrDefault(
            std::numeric_limits<int>::max());
    position_updates.push_back(position_update);
  }

  for (Observer* observer : observers_) {
    observer->AnchorPositionsUpdated(position_updates);
  }
}

void AnchorElementViewportPositionTracker::RegisterForLifecycleNotifications() {
  if (is_registered_for_lifecycle_notifications_) {
    return;
  }

  if (LocalFrameView* view = GetSupplementable()->View()) {
    view->RegisterForLifecycleNotifications(this);
    is_registered_for_lifecycle_notifications_ = true;
  }
}

}  // namespace blink
```
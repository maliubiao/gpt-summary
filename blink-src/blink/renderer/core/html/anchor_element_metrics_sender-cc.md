Response:
Let's break down the thought process for analyzing this code and generating the answer.

1. **Understand the Goal:** The core request is to analyze the `AnchorElementMetricsSender.cc` file and explain its functionalities, relationships with web technologies, logic, and potential usage errors.

2. **Initial Scan for Keywords and Concepts:**  A quick read-through reveals key terms: `AnchorElement`, `Metrics`, `NavigationPredictor`, `PointerEvent`, `Viewport`, `Click`, `Hover`, `Layout`, `Document`, `Frame`, `JavaScript`, `HTML`, `CSS`. This immediately gives a high-level understanding that the code is about collecting data related to anchor elements for some kind of navigation prediction feature.

3. **Decompose Functionality by Class Methods:** The most structured way to understand the code is to go through each public method and understand its purpose.

    * **`From(Document& document)` and `GetForFrame(LocalFrame* frame)`:** These static methods are clearly about retrieving or creating an instance of the `AnchorElementMetricsSender`. The conditions in `ShouldHaveAnchorElementMetricsSender` give insights into *when* this sender is relevant (main frame, HTTP/HTTPS, secure context, feature enabled).

    * **`MaybeReportAnchorElementPointerDataOnHoverTimerFired`:** The name itself is very descriptive. It suggests a timer is involved in reporting data about the pointer (mouse/touch) hovering over an anchor.

    * **`MaybeReportClickedMetricsOnClick`:**  This is about reporting metrics when an anchor is clicked, specifically focusing on the time between navigation start and the click.

    * **`AddAnchorElement` and `RemoveAnchorElement`:** These are the core methods for tracking the lifecycle of anchor elements within the document for metric collection. The interaction with `anchor_elements_to_report_` and `removed_anchors_to_report_` is important here.

    * **`DocumentDetached`:**  Handles the scenario where a document (especially a subframe) is removed, cleaning up the tracked anchor elements.

    * **`MaybeReportAnchorElementPointerEvent`:** This seems to handle reporting metrics for various pointer events (over, out, down) on anchor elements, including timings.

    * **`EnqueueLeftViewport` and `EnqueueEnteredViewport`:** These methods are about tracking when anchor elements enter and leave the visible viewport.

    * **`RegisterForLifecycleNotifications` and `DidFinishLifecycleUpdate`:** This pair is crucial. It indicates that the sender relies on the document's lifecycle to know when layout is stable and metrics can be collected and sent.

    * **`MaybeUpdateMetrics` and `UpdateMetrics`:**  These methods handle the actual sending of the collected metrics to the browser process. The timer (`update_timer_`) suggests a mechanism for batching or delaying these updates.

    * **`ViewportIntersectionUpdate` and `AnchorPositionsUpdated`:** These deal with more granular updates about an anchor's visibility and position within the viewport.

4. **Identify Relationships with Web Technologies:**

    * **HTML:** The entire purpose revolves around `HTMLAnchorElement`. The code directly interacts with properties like `href`.
    * **JavaScript:** Although the C++ code doesn't *execute* JavaScript, it's triggered by events and actions initiated by JavaScript interactions (e.g., clicking a link). The data collected informs browser behavior related to navigation which is often triggered by JS.
    * **CSS:** CSS affects the layout and visibility of anchor elements. The code needs to wait for layout to be stable (`DidFinishLifecycleUpdate`) before collecting metrics, showing a dependency on CSS rendering. The concept of "viewport" is directly linked to CSS layout and scrolling.

5. **Infer Logic and Potential Inputs/Outputs:** For methods like `MaybeReportClickedMetricsOnClick`, the input is the `HTMLAnchorElement`. The output is a message sent to the browser process (`metrics_host_->ReportAnchorElementClick`). The logic involves calculating the time difference. Similarly, for pointer events, the input is the `PointerEvent` and the output is a different type of message.

6. **Consider User and Programming Errors:**

    * **User Errors:**  The code indirectly relates to user behavior (clicking, hovering). A user might mistakenly click a link. While the code doesn't prevent this, it collects data about it.
    * **Programming Errors (Internal):**  The code has `DCHECK` and `CHECK` statements, indicating internal assertions. A common programming error within this code might be failing to properly handle the lifecycle of anchor elements (adding without removing, or vice-versa). The comments about elements being added and removed between layout updates also point to potential race conditions or complex state management.

7. **Structure the Answer:**  Organize the findings into logical sections:

    * **Core Functionality:** Start with the main purpose of the class.
    * **Relationship with Web Technologies:**  Clearly explain the connection to HTML, JavaScript, and CSS with examples.
    * **Logic and Reasoning:**  Focus on the key methods and their logic, providing hypothetical input/output examples where relevant.
    * **Potential Usage Errors:**  Address both user and programming errors.

8. **Refine and Elaborate:** Review the generated answer for clarity, accuracy, and completeness. Add specific examples where necessary to illustrate the points. For example, in the JavaScript section, explaining how a JS event listener might trigger navigation.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive and informative answer to the prompt. The key is to move beyond just listing methods and to understand the underlying purpose and interactions of the code within the broader context of a web browser.
好的， 让我们来分析一下 `blink/renderer/core/html/anchor_element_metrics_sender.cc` 这个文件。

**核心功能：**

`AnchorElementMetricsSender` 类的主要功能是**收集和报告 HTML 锚元素（`<a>` 和 `<area>` 元素）的各种指标 (metrics) 给浏览器进程，用于导航预测 (Navigation Predictor) 功能。** 简单来说，它就像一个埋点工具，专门针对链接，收集用户与链接交互的数据，帮助浏览器提前预测用户可能点击的链接，从而优化页面加载速度。

**详细功能分解：**

1. **生命周期管理:**
   -  当一个文档满足特定条件（例如：是主框架，使用 HTTP/HTTPS 协议，处于安全上下文，并且 `kNavigationPredictor` 功能已启用）时，会为该文档创建一个 `AnchorElementMetricsSender` 实例。
   -  它监听文档中锚元素的添加和移除 (`AddAnchorElement`, `RemoveAnchorElement`)。
   -  当文档被分离 (`DocumentDetached`) 时，会清理相关的锚元素信息。

2. **事件监听与指标收集:**
   -  **悬停 (Hover):**  当鼠标指针悬停在锚元素上时 (`MaybeReportAnchorElementPointerEvent` 监听 `pointerover` 事件)，会记录悬停开始的时间。当鼠标指针离开时 (`pointerout`)，会计算悬停持续时间 (`hover_dwell_time`) 并报告。  还支持基于定时器的悬停数据报告 (`MaybeReportAnchorElementPointerDataOnHoverTimerFired`)，可能用于更精细的悬停行为分析。
   -  **点击 (Click):**  当锚元素被点击时 (`MaybeReportClickedMetricsOnClick`)，会记录从导航开始到点击发生的时间 (`navigation_start_to_click`) 并报告。
   -  **指针按下 (Pointer Down):**  当指针在锚元素上按下时 (`MaybeReportAnchorElementPointerEvent` 监听 `pointerdown` 事件)，会记录从导航开始到指针按下的时间。
   -  **进入/离开视口 (Viewport):**  当锚元素进入或离开用户的可视区域时 (`EnqueueEnteredViewport`, `EnqueueLeftViewport`)，会记录相关的时间戳，并计算在视口内的停留时间。
   -  **位置更新 (Position Update):**  如果启用 `kNavigationPredictorNewViewportFeatures`，会定期报告锚元素在视口中的垂直位置以及与最近一次指针按下事件的距离 (`AnchorPositionsUpdated`)。

3. **数据上报:**
   -  收集到的指标数据会被打包成 `mojom::blink::AnchorElementMetricsPtr` 等消息，通过 `metrics_host_` (一个与浏览器进程通信的接口) 发送给浏览器进程。
   -  数据上报的时机由定时器 (`update_timer_`) 控制，可能是为了批量发送，减少通信频率。

4. **采样 (Sampling):**
   -  为了控制上报的数据量，可以配置一个采样率 (`random_anchor_sampling_period_`)。只有被采样的锚元素才会上报详细的指标。

5. **与浏览器进程通信:**
   -  使用 `BrowserInterfaceBrokerProxy` 获取 `mojom::blink::NavigationPredictorHost` 接口 (`metrics_host_`)，用于向浏览器进程发送指标数据。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**  `AnchorElementMetricsSender` 的核心目标就是 **HTML 锚元素 (`<a>` 和 `<area>`)**。它追踪这些元素的添加、移除，并收集与之相关的用户交互数据。
    * **举例：** 当 HTML 中添加一个新的 `<a href="https://example.com">Example</a>` 标签时，`AddAnchorElement` 方法会被调用，开始监控这个链接。

* **JavaScript:**  虽然这个 C++ 文件本身不包含 JavaScript 代码，但它收集的指标数据是基于用户与页面交互产生的，而这些交互很多时候是通过 JavaScript 触发的。
    * **举例：**  用户点击一个通过 JavaScript 动态生成的 `<a>` 标签，或者通过 JavaScript 监听器触发了与链接相关的操作 (例如，显示一个包含链接的模态框)，`AnchorElementMetricsSender` 会捕捉到这些交互，并记录相关指标。
    * **再例如：**  一个网站可能使用 JavaScript 来修改链接的 `href` 属性。`AnchorElementMetricsSender` 会记录修改后的 `href`。

* **CSS:** CSS 影响锚元素的布局和可见性，这与 `AnchorElementMetricsSender` 的一些功能息息相关。
    * **举例：**  `AnchorElementMetricsSender` 需要等待文档布局稳定后 (`DidFinishLifecycleUpdate`) 才能准确地获取锚元素的位置和大小信息。这表明它依赖于 CSS 的渲染结果。
    * **再例如：** 判断锚元素是否在视口内，也依赖于 CSS 的布局信息和用户的滚动位置。

**逻辑推理与假设输入输出：**

假设用户在一个启用了 `kNavigationPredictor` 功能的页面上进行以下操作：

**假设输入：**

1. **HTML 结构:** 页面包含一个 `<a id="link1" href="https://example.com/page1">Page 1</a>` 元素。
2. **用户操作:**
   - 鼠标指针悬停在 "Page 1" 链接上 2 秒。
   - 然后点击了这个链接。

**逻辑推理与输出：**

1. **悬停事件 (`pointerover`, `pointerout`):**
   - 当鼠标悬停时，`MaybeReportAnchorElementPointerEvent` 会记录 `pointerover` 事件，并存储悬停开始时间。
   - 当鼠标移开时 (或点击时)，`MaybeReportAnchorElementPointerEvent` 会记录 `pointerout` 事件，计算悬停时间 (假设为 2 秒)，并通过 `metrics_host_->ReportAnchorElementPointerOut` 发送包含 `anchor_id` 和 `hover_dwell_time` (2秒) 的消息给浏览器进程。
   - **输出 (发送给浏览器进程的消息):**  `mojom::blink::AnchorElementPointerOut` 包含 `anchor_id` (基于 "link1" 元素生成) 和 `hover_dwell_time` (2秒)。

2. **点击事件 (`click`):**
   - 当链接被点击时，`MaybeReportClickedMetricsOnClick` 会被调用。
   - 它会计算从页面导航开始 (`NavigationStart()`) 到点击发生的时间差。
   - 它会创建一个 `mojom::blink::AnchorElementClick` 对象，包含 `anchor_id`，链接的 `href` (`https://example.com/page1`) 和时间差。
   - 通过 `metrics_host_->ReportAnchorElementClick` 发送这个消息。
   - **输出 (发送给浏览器进程的消息):** `mojom::blink::AnchorElementClick` 包含 `anchor_id`， `href` ("https://example.com/page1") 和 `navigation_start_to_click` (假设为 500 毫秒)。

**用户或编程常见的使用错误：**

* **用户错误：** 用户可能会误触链接，或者在链接加载完成前就取消了导航。虽然这不是 `AnchorElementMetricsSender` 直接处理的错误，但它收集的数据可以帮助分析这类用户行为。

* **编程错误（开发者）：**
    * **动态添加/删除链接后未及时更新:** 如果开发者使用 JavaScript 动态地添加或删除了链接，但相关的代码没有触发页面的重新布局，`AnchorElementMetricsSender` 可能无法正确地追踪这些链接。  例如，直接操作 DOM 节点而没有触发布局更新。
    * **错误地假设了指标上报的时机:** 开发者可能错误地认为每次用户与链接交互都会立即上报指标。实际上，由于定时器的存在，指标可能会被批量发送。
    * **在不满足条件的环境下使用:**  如果在非主框架、非 HTTP/HTTPS 协议或者 `kNavigationPredictor` 功能未启用的情况下尝试获取 `AnchorElementMetricsSender` 实例并进行操作，可能会得到空指针或者操作无效。

* **编程错误（Blink 内部）：**
    * **生命周期管理错误:**  如果在锚元素被移除后，`AnchorElementMetricsSender` 仍然持有对该元素的引用，可能会导致内存泄漏或访问悬空指针。
    * **数据同步问题:**  在多线程环境下，需要保证对共享数据（如 `anchor_elements_to_report_`）的访问是线程安全的，避免数据竞争。

总而言之，`AnchorElementMetricsSender` 是 Blink 引擎中一个重要的组件，它默默地收集着用户与网页链接交互的数据，为浏览器的导航预测功能提供关键信息，从而提升用户浏览体验。 它的功能与 HTML 结构、JavaScript 的交互行为以及 CSS 影响的布局息息相关。

Prompt: 
```
这是目录为blink/renderer/core/html/anchor_element_metrics_sender.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/anchor_element_metrics_sender.h"

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/not_fatal_until.h"
#include "base/rand_util.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_pointer_properties.h"
#include "third_party/blink/public/mojom/loader/navigation_predictor.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/loader/navigation_predictor.mojom-forward.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_including_tree_order_traversal.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/anchor_element_metrics.h"
#include "third_party/blink/renderer/core/html/anchor_element_viewport_position_tracker.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/pointer_type_names.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "ui/gfx/geometry/mojom/geometry.mojom-shared.h"

namespace blink {
namespace {
// Returns true if `document` should have an associated
// AnchorElementMetricsSender.
bool ShouldHaveAnchorElementMetricsSender(Document& document) {
  bool is_feature_enabled =
      base::FeatureList::IsEnabled(features::kNavigationPredictor);
  const KURL& url = document.Url();
  return is_feature_enabled && document.IsInOutermostMainFrame() &&
         url.IsValid() && url.ProtocolIsInHTTPFamily() &&
         document.GetExecutionContext() &&
         document.GetExecutionContext()->IsSecureContext();
}

bool ShouldReportViewportPositions() {
  return base::FeatureList::IsEnabled(
      features::kNavigationPredictorNewViewportFeatures);
}

}  // namespace

// static
const char AnchorElementMetricsSender::kSupplementName[] =
    "DocumentAnchorElementMetricsSender";

AnchorElementMetricsSender::~AnchorElementMetricsSender() = default;

// static
AnchorElementMetricsSender* AnchorElementMetricsSender::From(
    Document& document) {
  // Note that this method is on a hot path. If `sender` already exists, we
  // avoid a call to `ShouldHaveAnchorElementMetricsSender`. If we instead had
  // `ShouldHaveAnchorElementMetricsSender` as a guard clause here, that would
  // cause a measurable performance regression.

  AnchorElementMetricsSender* sender =
      Supplement<Document>::From<AnchorElementMetricsSender>(document);
  if (!sender && ShouldHaveAnchorElementMetricsSender(document)) {
    sender = MakeGarbageCollected<AnchorElementMetricsSender>(document);
    ProvideTo(document, sender);
  }
  return sender;
}

// static
AnchorElementMetricsSender* AnchorElementMetricsSender::GetForFrame(
    LocalFrame* frame) {
  if (!frame) {
    return nullptr;
  }

  if (frame->IsCrossOriginToOutermostMainFrame()) {
    return nullptr;
  }

  LocalFrame* local_main_frame = DynamicTo<LocalFrame>(frame->Tree().Top());
  if (!local_main_frame) {
    return nullptr;
  }

  Document* main_document = local_main_frame->GetDocument();
  if (!main_document) {
    return nullptr;
  }

  return From(*main_document);
}

void AnchorElementMetricsSender::
    MaybeReportAnchorElementPointerDataOnHoverTimerFired(
        AnchorId anchor_id,
        mojom::blink::AnchorElementPointerDataPtr pointer_data) {
  DCHECK(base::FeatureList::IsEnabled(features::kNavigationPredictor));
  if (!AssociateInterface()) {
    return;
  }
  auto msg = mojom::blink::AnchorElementPointerDataOnHoverTimerFired::New(
      anchor_id, std::move(pointer_data));
  metrics_host_->ReportAnchorElementPointerDataOnHoverTimerFired(
      std::move(msg));
}

void AnchorElementMetricsSender::MaybeReportClickedMetricsOnClick(
    const HTMLAnchorElementBase& anchor_element) {
  DCHECK(base::FeatureList::IsEnabled(features::kNavigationPredictor));
  Document* top_document = GetSupplementable();
  CHECK(top_document);
  if (!anchor_element.Href().ProtocolIsInHTTPFamily() ||
      !top_document->Url().ProtocolIsInHTTPFamily() ||
      !anchor_element.GetDocument().Url().ProtocolIsInHTTPFamily()) {
    return;
  }
  if (!AssociateInterface()) {
    return;
  }
  base::TimeDelta navigation_start_to_click =
      clock_->NowTicks() - NavigationStart();
  auto click = mojom::blink::AnchorElementClick::New(
      AnchorElementId(anchor_element), anchor_element.Href(),
      navigation_start_to_click);
  metrics_host_->ReportAnchorElementClick(std::move(click));
}

void AnchorElementMetricsSender::AddAnchorElement(
    HTMLAnchorElementBase& element) {
  DCHECK(base::FeatureList::IsEnabled(features::kNavigationPredictor));
  if (!GetSupplementable()->GetFrame()) {
    return;
  }

  // Add this element to the set of elements that we will try to report after
  // the next layout.
  // The anchor may already be in `removed_anchors_to_report_`. We don't remove
  // it from there because it may be reinserted and then removed again. We need
  // to be able to tell the difference from an anchor that was removed before
  // being reported.
  anchor_elements_to_report_.insert(&element);
  RegisterForLifecycleNotifications();
}

void AnchorElementMetricsSender::RemoveAnchorElement(
    HTMLAnchorElementBase& element) {
  DCHECK(base::FeatureList::IsEnabled(features::kNavigationPredictor));

  auto it = anchor_elements_to_report_.find(&element);
  if (it != anchor_elements_to_report_.end()) {
    // The element was going to be reported, but was removed from the document
    // before the next layout. We'll treat it as if it were never inserted. We
    // don't include it in `removed_anchors_to_report_` because the element
    // might get reinserted. We don't want to exclude from consideration
    // elements that are moved around before layout.
    anchor_elements_to_report_.erase(it);
  } else {
    // The element wasn't recently added, so we may have already informed the
    // browser about it. So we'll inform the browser of its removal so it can
    // prune its memory usage for old elements.
    removed_anchors_to_report_.push_back(AnchorElementId(element));

    if (auto* viewport_position_tracker =
            AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(
                *GetSupplementable())) {
      viewport_position_tracker->RemoveAnchor(element);
    }
  }
  RegisterForLifecycleNotifications();
}

void AnchorElementMetricsSender::DocumentDetached(Document& document) {
  // We don't need to do anything if the main frame's document is being detached
  // as we don't want to notify the browser of anchors being removed in that
  // scenario.
  if (document.IsInMainFrame()) {
    return;
  }
  // We also don't need to do anything if a subframe is being detached as part
  // of the main frame being detached, or when a navigation is committing.
  LocalFrame* main_frame = GetSupplementable()->GetFrame();
  CHECK(main_frame);
  if (!main_frame->IsAttached() ||
      main_frame->Loader().IsCommittingNavigation()) {
    return;
  }
  for (Node& node :
       ShadowIncludingTreeOrderTraversal::DescendantsOf(document)) {
    if (HTMLAnchorElementBase* anchor =
            DynamicTo<HTMLAnchorElementBase>(node)) {
      RemoveAnchorElement(*anchor);
    }
  }
}

void AnchorElementMetricsSender::Trace(Visitor* visitor) const {
  visitor->Trace(anchor_elements_to_report_);
  visitor->Trace(metrics_host_);
  visitor->Trace(update_timer_);
  Supplement<Document>::Trace(visitor);
  AnchorElementViewportPositionTracker::Observer::Trace(visitor);
}

bool AnchorElementMetricsSender::AllAnchorsSampledIn() const {
  return random_anchor_sampling_period_ == 1;
}

bool AnchorElementMetricsSender::AssociateInterface() {
  if (metrics_host_.is_bound()) {
    return true;
  }

  Document* document = GetSupplementable();
  // Unable to associate since no frame is attached.
  if (!document->GetFrame()) {
    return false;
  }

  document->GetFrame()->GetBrowserInterfaceBroker().GetInterface(
      metrics_host_.BindNewPipeAndPassReceiver(
          document->GetExecutionContext()->GetTaskRunner(
              TaskType::kInternalDefault)));

  metrics_host_->ShouldSkipUpdateDelays(
      WTF::BindOnce(&AnchorElementMetricsSender::SetShouldSkipUpdateDelays,
                    WrapWeakPersistent(this)));

  return true;
}

AnchorElementMetricsSender::AnchorElementMetricsSender(Document& document)
    : Supplement<Document>(document),
      metrics_host_(document.GetExecutionContext()),
      update_timer_(document.GetExecutionContext()->GetTaskRunner(
                        TaskType::kInternalDefault),
                    this,
                    &AnchorElementMetricsSender::UpdateMetrics),
      random_anchor_sampling_period_(base::GetFieldTrialParamByFeatureAsInt(
          blink::features::kNavigationPredictor,
          "random_anchor_sampling_period",
          100)),
      clock_(base::DefaultTickClock::GetInstance()) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(document.IsInOutermostMainFrame());
  DCHECK(clock_);

  if (auto* viewport_position_tracker =
          AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(document)) {
    viewport_position_tracker->AddObserver(this);
  }
}

void AnchorElementMetricsSender::SetNowAsNavigationStartForTesting() {
  mock_navigation_start_for_testing_ = clock_->NowTicks();
}

void AnchorElementMetricsSender::SetTickClockForTesting(
    const base::TickClock* clock) {
  clock_ = clock;
}

void AnchorElementMetricsSender::FireUpdateTimerForTesting() {
  if (update_timer_.IsActive()) {
    update_timer_.Stop();
  }
  UpdateMetrics(&update_timer_);
}

void AnchorElementMetricsSender::SetShouldSkipUpdateDelays(
    bool should_skip_for_testing) {
  if (!should_skip_for_testing) {
    return;
  }

  should_skip_update_delays_for_testing_ = true;

  if (update_timer_.IsActive()) {
    update_timer_.Stop();
  }
  UpdateMetrics(&update_timer_);
}

base::TimeTicks AnchorElementMetricsSender::NavigationStart() const {
  if (mock_navigation_start_for_testing_.has_value()) {
    return mock_navigation_start_for_testing_.value();
  }

  const Document* top_document = GetSupplementable();
  CHECK(top_document);

  return top_document->Loader()->GetTiming().NavigationStart();
}

void AnchorElementMetricsSender::MaybeReportAnchorElementPointerEvent(
    HTMLAnchorElementBase& element,
    const PointerEvent& pointer_event) {
  if (!AssociateInterface()) {
    return;
  }

  const auto anchor_id = AnchorElementId(element);
  const AtomicString& event_type = pointer_event.type();

  auto pointer_event_for_ml_model =
      mojom::blink::AnchorElementPointerEventForMLModel::New();
  pointer_event_for_ml_model->anchor_id = anchor_id;
  pointer_event_for_ml_model->is_mouse =
      pointer_event.pointerType() == pointer_type_names::kMouse;
  if (event_type == event_type_names::kPointerover) {
    pointer_event_for_ml_model->user_interaction_event_type = mojom::blink::
        AnchorElementUserInteractionEventForMLModelType::kPointerOver;
  } else if (event_type == event_type_names::kPointerout) {
    pointer_event_for_ml_model->user_interaction_event_type = mojom::blink::
        AnchorElementUserInteractionEventForMLModelType::kPointerOut;
  } else {
    pointer_event_for_ml_model->user_interaction_event_type =
        mojom::blink::AnchorElementUserInteractionEventForMLModelType::kUnknown;
  }
  metrics_host_->ProcessPointerEventUsingMLModel(
      std::move(pointer_event_for_ml_model));

  auto it = anchor_elements_timing_stats_.find(anchor_id);
  if (it == anchor_elements_timing_stats_.end()) {
    return;
  }
  AnchorElementTimingStats& element_timing = it->value;
  if (event_type == event_type_names::kPointerover) {
    if (!element_timing.pointer_over_timer_.has_value()) {
      element_timing.pointer_over_timer_ = clock_->NowTicks();

      base::TimeDelta navigation_start_to_pointer_over =
          clock_->NowTicks() - NavigationStart();
      auto msg = mojom::blink::AnchorElementPointerOver::New(
          anchor_id, navigation_start_to_pointer_over);

      metrics_host_->ReportAnchorElementPointerOver(std::move(msg));
    }
  } else if (event_type == event_type_names::kPointerout) {
    if (!element_timing.pointer_over_timer_.has_value()) {
      return;
    }

    base::TimeDelta hover_dwell_time =
        clock_->NowTicks() - element_timing.pointer_over_timer_.value();
    element_timing.pointer_over_timer_.reset();
    auto msg =
        mojom::blink::AnchorElementPointerOut::New(anchor_id, hover_dwell_time);
    metrics_host_->ReportAnchorElementPointerOut(std::move(msg));
  } else if (event_type == event_type_names::kPointerdown) {
    // TODO(crbug.com/1297312): Check if user changed the default mouse
    // settings
    if (pointer_event.button() !=
            static_cast<int>(WebPointerProperties::Button::kLeft) &&
        pointer_event.button() !=
            static_cast<int>(WebPointerProperties::Button::kMiddle)) {
      return;
    }

    base::TimeDelta navigation_start_to_pointer_down =
        clock_->NowTicks() - NavigationStart();
    auto msg = mojom::blink::AnchorElementPointerDown::New(
        anchor_id, navigation_start_to_pointer_down);
    metrics_host_->ReportAnchorElementPointerDown(std::move(msg));
  }
}

void AnchorElementMetricsSender::EnqueueLeftViewport(
    const HTMLAnchorElementBase& element) {
  const auto anchor_id = AnchorElementId(element);
  auto it = anchor_elements_timing_stats_.find(anchor_id);
  CHECK(it != anchor_elements_timing_stats_.end(), base::NotFatalUntil::M130);
  AnchorElementTimingStats& timing_stats = it->value;
  timing_stats.entered_viewport_should_be_enqueued_ = true;
  std::optional<base::TimeTicks>& entered_viewport =
      timing_stats.viewport_entry_time_;
  if (!entered_viewport.has_value()) {
    return;
  }

  base::TimeDelta time_in_viewport =
      clock_->NowTicks() - entered_viewport.value();
  entered_viewport.reset();
  auto msg =
      mojom::blink::AnchorElementLeftViewport::New(anchor_id, time_in_viewport);
  left_viewport_messages_.push_back(std::move(msg));
}

void AnchorElementMetricsSender::EnqueueEnteredViewport(
    const HTMLAnchorElementBase& element) {
  const auto anchor_id = AnchorElementId(element);
  auto it = anchor_elements_timing_stats_.find(anchor_id);
  CHECK(it != anchor_elements_timing_stats_.end(), base::NotFatalUntil::M130);
  AnchorElementTimingStats& timing_stats = it->value;
  timing_stats.viewport_entry_time_ = clock_->NowTicks();
  if (!timing_stats.entered_viewport_should_be_enqueued_) {
    return;
  }
  timing_stats.entered_viewport_should_be_enqueued_ = false;

  base::TimeDelta time_entered_viewport =
      clock_->NowTicks() - NavigationStart();
  auto msg = mojom::blink::AnchorElementEnteredViewport::New(
      anchor_id, time_entered_viewport);
  entered_viewport_messages_.push_back(std::move(msg));
}

void AnchorElementMetricsSender::RegisterForLifecycleNotifications() {
  if (is_registered_for_lifecycle_notifications_) {
    return;
  }

  if (LocalFrameView* view = GetSupplementable()->View()) {
    view->RegisterForLifecycleNotifications(this);
    is_registered_for_lifecycle_notifications_ = true;
  }
}

void AnchorElementMetricsSender::DidFinishLifecycleUpdate(
    const LocalFrameView& local_frame_view) {
  // Check that layout is stable. If it is, we can report pending
  // AnchorElements.
  Document* document = local_frame_view.GetFrame().GetDocument();
  if (document->Lifecycle().GetState() <
      DocumentLifecycle::kAfterPerformLayout) {
    return;
  }
  if (!GetSupplementable()->GetFrame()) {
    return;
  }

  auto* viewport_position_tracker =
      AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(
          *GetSupplementable());

  for (const auto& member_element : anchor_elements_to_report_) {
    HTMLAnchorElementBase& anchor_element = *member_element;

    mojom::blink::AnchorElementMetricsPtr anchor_element_metrics =
        CreateAnchorElementMetrics(anchor_element);
    if (!anchor_element_metrics) {
      continue;
    }

    int random = base::RandInt(1, random_anchor_sampling_period_);
    if (random == 1) {
      // This anchor element is sampled in.
      if (viewport_position_tracker) {
        HTMLAnchorElementBase* anchor_unobserved =
            viewport_position_tracker->MaybeObserveAnchor(
                anchor_element, *anchor_element_metrics);
        if (anchor_unobserved) {
          EnqueueLeftViewport(*anchor_unobserved);
        }
      }
      const auto anchor_id = AnchorElementId(anchor_element);
      anchor_elements_timing_stats_.insert(anchor_id,
                                           AnchorElementTimingStats{});
    }

    metrics_.push_back(std::move(anchor_element_metrics));
  }
  // Remove all anchors, including the ones that did not qualify. This means
  // that elements that are inserted in the DOM but have an empty bounding box
  // (e.g. because they're detached from the DOM, or not currently visible)
  // during the next layout will never be reported, unless they are re-inserted
  // into the DOM later or if they enter the viewport.
  anchor_elements_to_report_.clear();

  metrics_removed_anchors_.AppendVector(removed_anchors_to_report_);
  removed_anchors_to_report_.clear();

  if (!metrics_.empty() || !metrics_removed_anchors_.empty()) {
    // Note that if an element removal happens between the population of
    // `metrics_` and sending the update to the browser, we may have a scenario
    // where an update would report the same element as being added and removed.
    // We record information to disambiguate when flushing the metrics.
    std::pair<wtf_size_t, wtf_size_t> metrics_partition =
        std::make_pair(metrics_.size(), metrics_removed_anchors_.size());
    if (metrics_partitions_.empty() ||
        metrics_partitions_.back() != metrics_partition) {
      metrics_partitions_.push_back(metrics_partition);
    }
  }

  MaybeUpdateMetrics();

  DCHECK_EQ(&local_frame_view, GetSupplementable()->View());
  DCHECK(is_registered_for_lifecycle_notifications_);
  GetSupplementable()->View()->UnregisterFromLifecycleNotifications(this);
  is_registered_for_lifecycle_notifications_ = false;
}

void AnchorElementMetricsSender::MaybeUpdateMetrics() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (should_skip_update_delays_for_testing_) {
    DCHECK(!update_timer_.IsActive());
    UpdateMetrics(&update_timer_);
  } else if (!update_timer_.IsActive()) {
    update_timer_.StartOneShot(kUpdateMetricsTimeGap, FROM_HERE);
  }
}

void AnchorElementMetricsSender::UpdateMetrics(TimerBase* /*timer*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (metrics_.empty() && metrics_removed_anchors_.empty() &&
      entered_viewport_messages_.empty() && left_viewport_messages_.empty() &&
      position_update_messages_.empty()) {
    return;
  }

  if (!AssociateInterface()) {
    return;
  }

  if (!metrics_.empty() || !metrics_removed_anchors_.empty()) {
    CHECK(!metrics_partitions_.empty());
    CHECK(metrics_partitions_.back() ==
          std::make_pair(metrics_.size(), metrics_removed_anchors_.size()));

    // Multiple lifecycle updates, during which we buffer metrics updates, may
    // have happened before we send the buffered metrics updates here. Between
    // lifecycle updates, the anchors whose metrics are buffered may have
    // changed, so we now remove any stale updates which no longer accurately
    // represent the state of the page on the most recent lifecycle update. The
    // metrics from a more recent lifecycle update reflect the current state.
    // Within the changes of a single lifecycle update, if the same anchor is
    // both removed and added then it must have been removed first. So to
    // reconstruct the correct state, we do a pass over the buffered updates
    // where we process the removals of the first lifecycle update, then the
    // additions of the first lifecycle update, then the removals of the second
    // lifecycle update, then the additions of the second lifecycle update, and
    // so on.
    WTF::HashMap<AnchorId, bool> present;
    WTF::HashMap<AnchorId, bool> newly_removed;
    wtf_size_t insert_idx = 0;
    wtf_size_t remove_idx = 0;
    for (const auto& [insert_end, remove_end] : metrics_partitions_) {
      // For each partition, removals are processed before insertions.
      const auto removals = base::make_span(metrics_removed_anchors_)
                                .subspan(remove_idx, (remove_end - remove_idx));
      for (AnchorId removed_id : removals) {
        auto result = present.Set(removed_id, false);
        newly_removed.insert(removed_id, result.is_new_entry);
      }
      const auto insertions = base::make_span(metrics_).subspan(
          insert_idx, (insert_end - insert_idx));
      for (const auto& insertion : insertions) {
        present.Set(insertion->anchor_id, true);
      }
      insert_idx = insert_end;
      remove_idx = remove_end;
    }
    WTF::EraseIf(
        metrics_,
        [&present](const mojom::blink::AnchorElementMetricsPtr& metric) {
          return !present.at(metric->anchor_id);
        });
    WTF::EraseIf(metrics_removed_anchors_,
                 [&present, &newly_removed](AnchorId id) {
                   return !newly_removed.at(id) || present.at(id);
                 });

    metrics_host_->ReportNewAnchorElements(std::move(metrics_),
                                           std::move(metrics_removed_anchors_));
    metrics_.clear();
    metrics_removed_anchors_.clear();
    metrics_partitions_.clear();
  }
  if (!entered_viewport_messages_.empty()) {
    metrics_host_->ReportAnchorElementsEnteredViewport(
        std::move(entered_viewport_messages_));
    entered_viewport_messages_.clear();
  }
  if (!left_viewport_messages_.empty()) {
    metrics_host_->ReportAnchorElementsLeftViewport(
        std::move(left_viewport_messages_));
    left_viewport_messages_.clear();
  }
  if (!position_update_messages_.empty()) {
    CHECK(ShouldReportViewportPositions());
    metrics_host_->ReportAnchorElementsPositionUpdate(
        std::move(position_update_messages_));
    position_update_messages_.clear();
  }
}

void AnchorElementMetricsSender::ViewportIntersectionUpdate(
    const HeapVector<Member<const HTMLAnchorElementBase>>& entered_viewport,
    const HeapVector<Member<const HTMLAnchorElementBase>>& left_viewport) {
  if (!GetSupplementable()->GetFrame()) {
    return;
  }

  for (const HTMLAnchorElementBase* anchor : entered_viewport) {
    EnqueueEnteredViewport(*anchor);
  }
  for (const HTMLAnchorElementBase* anchor : left_viewport) {
    EnqueueLeftViewport(*anchor);
  }

  RegisterForLifecycleNotifications();
}

void AnchorElementMetricsSender::AnchorPositionsUpdated(
    HeapVector<Member<AnchorPositionUpdate>>& position_updates) {
  CHECK(ShouldReportViewportPositions());

  for (AnchorPositionUpdate* update : position_updates) {
    position_update_messages_.push_back(
        mojom::blink::AnchorElementPositionUpdate::New(
            AnchorElementId(*update->anchor_element), update->vertical_position,
            update->distance_from_pointer_down));
  }

  MaybeUpdateMetrics();
}

}  // namespace blink

"""

```
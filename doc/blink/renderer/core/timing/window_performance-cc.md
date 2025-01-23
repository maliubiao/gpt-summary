Response:
My goal is to analyze the provided C++ code snippet and address the user's request. Here's a breakdown of my thought process:

1. **Understanding the Core Request:** The user wants to understand the functionality of `window_performance.cc` within the Chromium Blink rendering engine. They are particularly interested in its connections to web technologies (JavaScript, HTML, CSS), logical inferences, potential usage errors, debugging information, and a concise summary of its purpose.

2. **Initial Code Scan and High-Level Understanding:** I first scanned the included headers and the overall structure of the code. Key observations:
    * **Headers:**  The included headers suggest this file deals with performance monitoring and reporting, touching upon areas like:
        * Time measurements (`<algorithm>`, `<optional>`, `<string>`, `base/time/time.h`)
        * Feature flags (`base/feature_list.h`)
        * Tracing (`base/trace_event`)
        * Metrics (`services/metrics/public/cpp/ukm_builders.h`)
        * Network loading (`services/network/public/mojom/load_timing_info.mojom-blink.h`)
        * DOM elements and events (`third_party/blink/renderer/core/dom/*`, `third_party/blink/renderer/core/events/*`)
        * Frames and windows (`third_party/blink/renderer/core/frame/*`)
        * HTML elements (`third_party/blink/renderer/core/html/*`)
        * Inspector/debugging (`third_party/blink/renderer/core/inspector/console_message.h`)
        * Performance-specific classes (`third_party/blink/renderer/core/timing/*`)
    * **Class `WindowPerformance`:** This is the central class, indicating that the file is responsible for managing performance metrics at the window level.
    * **Inheritance:** `WindowPerformance` inherits from `Performance`, `ExecutionContextClient`, and `PageVisibilityObserver`, suggesting it builds upon existing performance infrastructure, operates within a script execution context, and is aware of page visibility changes.

3. **Functionality Breakdown (Based on Code and Headers):** I then started to deduce the functionality by examining specific code blocks and the names of included headers and classes.

    * **Performance Timing:** The presence of `PerformanceTiming`, `PerformanceNavigationTiming`, `PerformanceResourceTiming`, etc., strongly indicates this file is involved in collecting and reporting performance timing data.
    * **Event Timing:** The sections dealing with `EventTimingProcessingStart`, `EventTimingProcessingEnd`, and `PerformanceEventTiming` clearly show this file tracks the timing of events (like clicks, key presses).
    * **Long Tasks:** The `ReportLongTask` function and the subscription to `PerformanceMonitor::kLongTask` indicate it identifies and reports long-running tasks that might block the main thread.
    * **Largest Contentful Paint (LCP) and Layout Shift:**  The inclusion of `largest_contentful_paint.h` and `layout_shift.h` suggests involvement in tracking these specific performance metrics.
    * **Navigation Timing:**  The `CreateNavigationTimingInstance` function and the `PerformanceNavigation` class show it handles timing related to page navigations.
    * **Memory Usage:** The `memory()` method provides access to memory usage information.
    * **Visibility State:**  The `PageVisibilityObserver` inheritance and `AddVisibilityStateEntry` suggest it tracks changes in page visibility.
    * **Cross-Origin Attribution:** The `SanitizedAttribution` function deals with determining the origin of events or tasks, considering cross-origin scenarios.
    * **Interaction Tracking:** The `responsiveness_metrics_` member and mentions of "interaction ID" suggest it's involved in tracking user interactions.
    * **Tracing:** The use of `TRACE_EVENT` indicates it integrates with Chromium's tracing infrastructure for performance analysis.

4. **Connecting to Web Technologies (JavaScript, HTML, CSS):**  With the functional understanding, I considered how these functionalities relate to web technologies:

    * **JavaScript:** The performance APIs (like `performance.timing`, `performance.now()`, `performance.getEntriesByType()`) exposed to JavaScript are backed by this code. The tracking of event timings directly relates to JavaScript event handlers.
    * **HTML:** The tracking of frame navigations, resource loading, and metrics like LCP (which often involves HTML elements) directly connects to HTML structure and content. The `HTMLFrameOwnerElement` usage is a clear link.
    * **CSS:** While not as direct, CSS can influence layout shifts and rendering performance, which are metrics tracked here.

5. **Logical Inferences and Examples:**  I tried to create simple scenarios to illustrate the logic:

    * **Long Task:** A long-running JavaScript function would be identified as a long task.
    * **Event Timing:** A user clicking a button would trigger event timing measurements.
    * **Cross-Origin:**  Accessing `performance.timing` in an iframe from a different origin would have restrictions.

6. **User/Programming Errors:** I thought about common mistakes related to performance measurement:

    * Incorrectly interpreting timing values (e.g., assuming `loadEventEnd` is always the moment the user sees the page).
    * Not accounting for cross-origin restrictions.

7. **Debugging and User Actions:** I considered how a developer might end up looking at this code:

    * Investigating slow page loads.
    * Analyzing performance metrics in DevTools.
    * Debugging issues related to event handling or responsiveness.

8. **Summarization (For Part 1):** Based on the analysis, I focused on the core responsibilities evident in the first part of the code: collecting basic timing information, handling navigation timing, and the initial stages of event timing.

9. **Structuring the Output:** I organized the information into the user's requested categories (functionality, relationship to web technologies, logical inferences, errors, debugging, and summary) for clarity. I used bullet points and examples to make the information easier to digest.

10. **Refinement:** I reviewed my analysis to ensure accuracy and completeness based on the provided code snippet. I tried to use precise terminology related to web development and browser internals. I made sure to explicitly mention that this was *part 1* and the summary reflected that.

This iterative process of scanning, analyzing specific parts, connecting to broader concepts, and structuring the information allowed me to address the user's comprehensive request effectively.
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 * Copyright (C) 2012 Intel Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/timing/window_performance.h"

#include <algorithm>
#include <optional>
#include <string>

#include "base/feature_list.h"
#include "base/trace_event/common/trace_event_common.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/trace_id_helper.h"
#include "components/viz/common/frame_timing_details.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/network/public/mojom/load_timing_info.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/frame/frame_owner_element_type.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_high_res_time_stamp.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/input_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#party/blink/renderer/core/frame/dom_window.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_hidden_state.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/timing/animation_frame_timing_info.h"
#include "third_party/blink/renderer/core/timing/largest_contentful_paint.h"
#include "third_party/blink/renderer/core/timing/layout_shift.h"
#include "third_party/blink/renderer/core/timing/performance_element_timing.h"
#include "third_party/blink/renderer/core/timing/performance_entry.h"
#include "third_party/blink/renderer/core/timing/performance_event_timing.h"
#include "third_party/blink/renderer/core/timing/performance_long_animation_frame_timing.h"
#include "third_party/blink/renderer/core/timing/performance_observer.h"
#include "third_party/blink/renderer/core/timing/performance_timing.h"
#include "third_party/blink/renderer/core/timing/performance_timing_for_reporting.h"
#include "third_party/blink/renderer/core/timing/responsiveness_metrics.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_entry.h"
#include "third_party/blink/renderer/core/timing/visibility_state_entry.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/forward.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

static constexpr base::TimeDelta kLongTaskObserverThreshold =
    base::Milliseconds(50);

namespace blink {

namespace {

AtomicString GetFrameAttribute(HTMLFrameOwnerElement* frame_owner,
                               const QualifiedName& attr_name) {
  AtomicString attr_value;
  if (frame_owner->hasAttribute(attr_name)) {
    attr_value = frame_owner->getAttribute(attr_name);
  }
  return attr_value;
}

AtomicString GetFrameOwnerType(HTMLFrameOwnerElement* frame_owner) {
  switch (frame_owner->OwnerType()) {
    case FrameOwnerElementType::kNone:
      return performance_entry_names::kWindow;
    case FrameOwnerElementType::kIframe:
      return html_names::kIFrameTag.LocalName();
    case FrameOwnerElementType::kObject:
      return html_names::kObjectTag.LocalName();
    case FrameOwnerElementType::kEmbed:
      return html_names::kEmbedTag.LocalName();
    case FrameOwnerElementType::kFrame:
      return html_names::kFrameTag.LocalName();
    case FrameOwnerElementType::kFencedframe:
      return html_names::kFencedframeTag.LocalName();
  }
  NOTREACHED();
}

AtomicString GetFrameSrc(HTMLFrameOwnerElement* frame_owner) {
  switch (frame_owner->OwnerType()) {
    case FrameOwnerElementType::kObject:
      return GetFrameAttribute(frame_owner, html_names::kDataAttr);
    default:
      return GetFrameAttribute(frame_owner, html_names::kSrcAttr);
  }
}

const AtomicString& SelfKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, kSelfAttribution, ("self"));
  return kSelfAttribution;
}

const AtomicString& SameOriginAncestorKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, kSameOriginAncestorAttribution,
                      ("same-origin-ancestor"));
  return kSameOriginAncestorAttribution;
}

const AtomicString& SameOriginDescendantKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, kSameOriginDescendantAttribution,
                      ("same-origin-descendant"));
  return kSameOriginDescendantAttribution;
}

const AtomicString& SameOriginKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, kSameOriginAttribution,
                      ("same-origin"));
  return kSameOriginAttribution;
}

AtomicString SameOriginAttribution(Frame* observer_frame,
                                   Frame* culprit_frame) {
  DCHECK(IsMainThread());
  if (observer_frame == culprit_frame) {
    return SelfKeyword();
  }
  if (observer_frame->Tree().IsDescendantOf(culprit_frame)) {
    return SameOriginAncestorKeyword();
  }
  if (culprit_frame->Tree().IsDescendantOf(observer_frame)) {
    return SameOriginDescendantKeyword();
  }
  return SameOriginKeyword();
}

// Eligible event types should be kept in sync with
// WebInputEvent::IsWebInteractionEvent().
bool IsEventTypeForInteractionId(const AtomicString& type) {
  return type == event_type_names::kPointercancel ||
         type == event_type_names::kContextmenu ||
         type == event_type_names::kPointerdown ||
         type == event_type_names::kPointerup ||
         type == event_type_names::kClick ||
         type == event_type_names::kKeydown ||
         type == event_type_names::kKeypress ||
         type == event_type_names::kKeyup ||
         type == event_type_names::kCompositionstart ||
         type == event_type_names::kCompositionupdate ||
         type == event_type_names::kCompositionend ||
         type == event_type_names::kInput;
}

}  // namespace

constexpr size_t kDefaultVisibilityStateEntrySize = 50;

base::TimeTicks WindowPerformance::GetTimeOrigin(LocalDOMWindow* window) {
  DocumentLoader* loader = window->GetFrame()->Loader().GetDocumentLoader();
  return loader->GetTiming().ReferenceMonotonicTime();
}

WindowPerformance::WindowPerformance(LocalDOMWindow* window)
    : Performance(GetTimeOrigin(window),
                  window->CrossOriginIsolatedCapability(),
                  window->GetTaskRunner(TaskType::kPerformanceTimeline),
                  window),
      ExecutionContextClient(window),
      PageVisibilityObserver(window->GetFrame()->GetPage()),
      responsiveness_metrics_(
          MakeGarbageCollected<ResponsivenessMetrics>(this)) {
  DCHECK(window);
  DCHECK(window->GetFrame()->GetPerformanceMonitor());
  if (!RuntimeEnabledFeatures::LongTaskFromLongAnimationFrameEnabled()) {
    window->GetFrame()->GetPerformanceMonitor()->Subscribe(
        PerformanceMonitor::kLongTask, kLongTaskObserverThreshold, this);
  }

  DCHECK(GetPage());
  AddVisibilityStateEntry(GetPage()->IsPageVisible(), base::TimeTicks());
}

WindowPerformance::~WindowPerformance() = default;

ExecutionContext* WindowPerformance::GetExecutionContext() const {
  return ExecutionContextClient::GetExecutionContext();
}

PerformanceTiming* WindowPerformance::timing() const {
  if (!timing_) {
    timing_ = MakeGarbageCollected<PerformanceTiming>(DomWindow());
  }

  return timing_.Get();
}

PerformanceTimingForReporting* WindowPerformance::timingForReporting() const {
  if (!timing_for_reporting_) {
    timing_for_reporting_ =
        MakeGarbageCollected<PerformanceTimingForReporting>(DomWindow());
  }

  return timing_for_reporting_.Get();
}

PerformanceNavigation* WindowPerformance::navigation() const {
  if (!navigation_) {
    navigation_ = MakeGarbageCollected<PerformanceNavigation>(DomWindow());
  }

  return navigation_.Get();
}

MemoryInfo* WindowPerformance::memory(ScriptState* script_state) const {
  // The performance.memory() API has been improved so that we report precise
  // values when the process is locked to a site. The intent (which changed
  // course over time about what changes would be implemented) can be found at
  // https://groups.google.com/a/chromium.org/forum/#!topic/blink-dev/no00RdMnGio,
  // and the relevant bug is https://crbug.com/807651.
  const bool is_locked_to_site = Platform::Current()->IsLockedToSite();
  auto* memory_info = MakeGarbageCollected<MemoryInfo>(
      is_locked_to_site ? MemoryInfo::Precision::kPrecise
                        : MemoryInfo::Precision::kBucketized);
  // Record Web Memory UKM.
  const uint64_t kBytesInKB = 1024;
  auto* execution_context = ExecutionContext::From(script_state);
  ukm::builders::PerformanceAPI_Memory_Legacy(execution_context->UkmSourceID())
      .SetJavaScript(memory_info->usedJSHeapSize() / kBytesInKB)
      .Record(execution_context->UkmRecorder());
  if (!is_locked_to_site) {
    UseCounter::Count(
        execution_context,
        WebFeature::kV8Performance_Memory_AttributeGetter_NotLockedToSite);
  }
  return memory_info;
}

namespace {

BASE_FEATURE(kAdjustNavigationalPrefetchTiming,
             "AdjustNavigationalPrefetchTiming",
             base::FEATURE_ENABLED_BY_DEFAULT);

enum class AdjustNavigationalPrefetchTimingBehavior {
  kRemoveLoadTiming,
  kClampToFetchStart,
};

constexpr base::FeatureParam<AdjustNavigationalPrefetchTimingBehavior>::Option
    kAdjustNavigationalPrefetchTimingBehaviorOptions[] = {
        {AdjustNavigationalPrefetchTimingBehavior::kRemoveLoadTiming,
         "remove_load_timing"},
        {AdjustNavigationalPrefetchTimingBehavior::kClampToFetchStart,
         "clamp_to_fetch_start"},
};

constexpr base::FeatureParam<AdjustNavigationalPrefetchTimingBehavior>
    kAdjustNavigationalPrefetchTimingBehavior{
        &kAdjustNavigationalPrefetchTiming,
        "adjust_navigational_prefetch_timing_behavior",
        AdjustNavigationalPrefetchTimingBehavior::kClampToFetchStart,
        &kAdjustNavigationalPrefetchTimingBehaviorOptions};

network::mojom::blink::LoadTimingInfoPtr
AdjustLoadTimingForNavigationalPrefetch(
    const DocumentLoadTiming& document_load_timing,
    network::mojom::blink::LoadTimingInfoPtr timing) {
  if (!base::FeatureList::IsEnabled(kAdjustNavigationalPrefetchTiming)) {
    return timing;
  }

  static const auto behavior = kAdjustNavigationalPrefetchTimingBehavior.Get();
  switch (behavior) {
    case AdjustNavigationalPrefetchTimingBehavior::kRemoveLoadTiming:
      return nullptr;

    case AdjustNavigationalPrefetchTimingBehavior::kClampToFetchStart:
      break;
  }

  // Everything that happened before the fetch start (this is the value that
  // will be exposed as fetchStart on PerformanceNavigationTiming).
  using network::mojom::blink::LoadTimingInfo;
  using network::mojom::blink::LoadTimingInfoConnectTiming;
  const base::TimeTicks min_ticks = document_load_timing.FetchStart();
  auto new_timing = LoadTimingInfo::New();
  new_timing->socket_reused = timing->socket_reused;
  new_timing->socket_log_id = timing->socket_log_id;

  // Copy the basic members of LoadTimingInfo, and clamp them.
  for (base::TimeTicks LoadTimingInfo::*ts :
       {&LoadTimingInfo::request_start, &LoadTimingInfo::send_start,
        &LoadTimingInfo::send_end, &LoadTimingInfo::receive_headers_start,
        &LoadTimingInfo::receive_headers_end,
        &LoadTimingInfo::receive_non_informational_headers_start,
        &LoadTimingInfo::first_early_hints_time}) {
    if (!((*timing).*ts).is_null()) {
      (*new_timing).*ts = std::max((*timing).*ts, min_ticks);
    }
  }

  // If connect timing is available, do the same to it.
  if (auto* connect_timing = timing->connect_timing.get()) {
    new_timing->connect_timing = LoadTimingInfoConnectTiming::New();
    auto& new_connect_timing = *new_timing->connect_timing;
    for (base::TimeTicks LoadTimingInfoConnectTiming::*ts : {
             &LoadTimingInfoConnectTiming::domain_lookup_start,
             &LoadTimingInfoConnectTiming::domain_lookup_end,
             &LoadTimingInfoConnectTiming::connect_start,
             &LoadTimingInfoConnectTiming::connect_end,
             &LoadTimingInfoConnectTiming::ssl_start,
             &LoadTimingInfoConnectTiming::ssl_end,
         }) {
      if (!(connect_timing->*ts).is_null()) {
        new_connect_timing.*ts = std::max(connect_timing->*ts, min_ticks);
      }
    }
  }

  return new_timing;
}

}  // namespace

void WindowPerformance::CreateNavigationTimingInstance(
    mojom::blink::ResourceTimingInfoPtr info) {
  DCHECK(DomWindow());

  // If this is navigational prefetch, it may be necessary to partially redact
  // the timings to avoid exposing when events that occurred during the prefetch
  // happened. Instead, they look like they happened very fast.
  DocumentLoader* loader = DomWindow()->document()->Loader();
  if (loader &&
      loader->GetNavigationDeliveryType() ==
          network::mojom::NavigationDeliveryType::kNavigationalPrefetch &&
      info->timing) {
    info->timing = AdjustLoadTimingForNavigationalPrefetch(
        loader->GetTiming(), std::move(info->timing));
  }

  navigation_timing_ = MakeGarbageCollected<PerformanceNavigationTiming>(
      *DomWindow(), std::move(info), time_origin_);
}

void WindowPerformance::OnBodyLoadFinished(int64_t encoded_body_size,
                                           int64_t decoded_body_size) {
  if (navigation_timing_) {
    navigation_timing_->OnBodyLoadFinished(encoded_body_size,
                                           decoded_body_size);
  }
}

void WindowPerformance::BuildJSONValue(V8ObjectBuilder& builder) const {
  Performance::BuildJSONValue(builder);
  builder.Add("timing", timing());
  builder.Add("navigation", navigation());
}

void WindowPerformance::Trace(Visitor* visitor) const {
  visitor->Trace(event_timing_entries_);
  visitor->Trace(first_pointer_down_event_timing_);
  visitor->Trace(event_counts_);
  visitor->Trace(navigation_);
  visitor->Trace(timing_);
  visitor->Trace(timing_for_reporting_);
  visitor->Trace(responsiveness_metrics_);
  visitor->Trace(current_event_);
  Performance::Trace(visitor);
  PerformanceMonitor::Client::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  PageVisibilityObserver::Trace(visitor);
}

static bool CanAccessOrigin(Frame* frame1, Frame* frame2) {
  const SecurityOrigin* security_origin1 =
      frame1->GetSecurityContext()->GetSecurityOrigin();
  const SecurityOrigin* security_origin2 =
      frame2->GetSecurityContext()->GetSecurityOrigin();
  return security_origin1->CanAccess(security_origin2);
}

/**
 * Report sanitized name based on cross-origin policy.
 * See detailed Security doc here: http://bit.ly/2duD3F7
 */
// static
std::pair<AtomicString, DOMWindow*> WindowPerformance::SanitizedAttribution(
    ExecutionContext* task_context,
    bool has_multiple_contexts,
    LocalFrame* observer_frame) {
  DCHECK(IsMainThread());
  if (has_multiple_contexts) {
    // Unable to attribute, multiple script execution contents were involved.
    DEFINE_STATIC_LOCAL(const AtomicString, kAmbiguousAttribution,
                        ("multiple-contexts"));
    return std::make_pair(kAmbiguousAttribution, nullptr);
  }

  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(task_context);
  if (!window || !window->GetFrame()) {
    // Unable to attribute as no script was involved.
    DEFINE_STATIC_LOCAL(const AtomicString, kUnknownAttribution, ("unknown"));
    return std::make_pair(kUnknownAttribution, nullptr);
  }

  // Exactly one culprit location, attribute based on origin boundary.
  Frame* culprit_frame = window->GetFrame();
  DCHECK(culprit_frame);
  if (CanAccessOrigin(observer_frame, culprit_frame)) {
    // From accessible frames or same origin, return culprit location URL.
    return std::make_pair(SameOriginAttribution(observer_frame, culprit_frame),
                          culprit_frame->DomWindow());
  }
  // For cross-origin, if the culprit is the descendant or ancestor of
  // observer then indicate the *closest* cross-origin frame between
  // the observer and the culprit, in the corresponding direction.
  if (culprit_frame->Tree().IsDescendantOf(observer_frame)) {
    // If the culprit is a descendant of the observer, then walk up the tree
    // from culprit to observer, and report the *last* cross-origin (from
    // observer) frame. If no intermediate cross-origin frame is found, then
    // report the culprit directly.
    Frame* last_cross_origin_frame = culprit_frame;
    for (Frame* frame = culprit_frame; frame != observer_frame;
         frame = frame->Tree().Parent()) {
      if (!CanAccessOrigin(observer_frame, frame)) {
        last_cross_origin_frame = frame;
      }
    }
    DEFINE_STATIC_LOCAL(const AtomicString, kCrossOriginDescendantAttribution,
                        ("cross-origin-descendant"));
    return std::make_pair(kCrossOriginDescendantAttribution,
                          last_cross_origin_frame->DomWindow());
  }
  if (observer_frame->Tree().IsDescendantOf(culprit_frame)) {
    DEFINE_STATIC_LOCAL(const AtomicString, kCrossOriginAncestorAttribution,
                        ("cross-origin-ancestor"));
    return std::make_pair(kCrossOriginAncestorAttribution, nullptr);
  }
  DEFINE_STATIC_LOCAL(const AtomicString, kCrossOriginAttribution,
                      ("cross-origin-unreachable"));
  return std::make_pair(kCrossOriginAttribution, nullptr);
}

void WindowPerformance::ReportLongTask(base::TimeTicks start_time,
                                       base::TimeTicks end_time,
                                       ExecutionContext* task_context,
                                       bool has_multiple_contexts) {
  if (!DomWindow()) {
    return;
  }
  std::pair<AtomicString, DOMWindow*> attribution =
      WindowPerformance::SanitizedAttribution(
          task_context, has_multiple_contexts, DomWindow()->GetFrame());
  DOMWindow* culprit_dom_window = attribution.second;
  if (!culprit_dom_window || !culprit_dom_window->GetFrame() ||
      !culprit_dom_window->GetFrame()->DeprecatedLocalOwner()) {
    AddLongTaskTiming(start_time, end_time, attribution.first,
                      performance_entry_names::kWindow, g_empty_atom,
                      g_empty_atom, g_empty_atom);
  } else {
    HTMLFrameOwnerElement* frame_owner =
        culprit_dom_window->GetFrame()->DeprecatedLocalOwner();
    AddLongTaskTiming(start_time, end_time, attribution.first,
                      GetFrameOwnerType(frame_owner), GetFrameSrc(frame_owner),
                      GetFrameAttribute(frame_owner, html_names::kIdAttr),
                      GetFrameAttribute(frame_owner, html_names::kNameAttr));
  }
}

void WindowPerformance::EventTimingProcessingStart(
    const Event& event,
    base::TimeTicks processing_start,
    EventTarget* hit_test_target) {
  if (!DomWindow() || !DomWindow()->GetFrame()) {
    return;
  }
  DCHECK(!processing_start.is_null());

  const AtomicString& event_type = event.type();

  // TODO(crbug.com/40930016): remove support for pointermove
  if (event_type == event_type_names::kPointermove) {
    return;
  }

  // Event Counts API.
  eventCounts()->Add(event_type);

  // Some events are neither pointer nor keyboard (i.e. mouse events)
  // But we only use pointer and keyboard event data for interactions.
  const PointerEvent* pointer_event = DynamicTo<PointerEvent>(event);
  const KeyboardEvent* key_event = DynamicTo<KeyboardEvent>(event);

  PerformanceEventTiming::EventTimingReportingInfo reporting_info{
      .enqueued_to_main_thread_time =
          responsiveness_metrics_->CurrentInteractionEventQueuedTimestamp(),
      .processing_start_time = processing_start,
  };

  if (pointer_event) {
    reporting_info.creation_time = pointer_event->OldestPlatformTimeStamp();
    reporting_info.pointer_id = pointer_event->pointerId();

    if (RuntimeEnabledFeaturesBase::
            EventTimingTapStopScrollNoInteractionIdEnabled()) {
      reporting_info.prevent_counting_as_interaction |=
          pointer_event->GetPreventCountingAsInteraction();
    };
  } else {
    reporting_info.creation_time = event.PlatformTimeStamp();

    if (key_event) {
      reporting_info.key_code = key_event->keyCode();
    }
  }

  // Set prevent_counting_as_interaction to true for all the event entries when
  // the selection autoscroll happens at the current event presentation frame
  // or the previous frame.
  if (RuntimeEnabledFeaturesBase::
          EventTimingSelectionAutoScrollNoInteractionIdEnabled()) {
    reporting_info.prevent_counting_as_interaction |= IsAutoscrollActive();
  }

  // We always have a Hit test target before starting event dispatch. During
  // event dispatch we might change target via event retargetting or
  // pointer-capture (or any number of other features).
  // The "final" target is attached to the blink::Event as target(). However,
  // its possible that we optimize out the event dispatch steps (i.e. we don't
  // have listeners). When that happens, Event Timing still measures and
  // reports entries, but Chromium leaves the blink::Event target() value as
  // nullptr. So, we cannot rely on always having a target(). We use the
  // following strategy:
  // 1. Start with `hit_test_target`, from ProcessingStart, before dispatch.
  // 2. Update to `event.target()`, from ProcessingEnd, if we can.
  // `hit_test_target` can still be null in tests.
  // `target` can be non-null but detached from DOM and GC-ed before observer
  // fires.
  PerformanceEventTiming* entry = PerformanceEventTiming::Create(
      event_type, reporting_info, event.cancelable(),
      hit_test_target ? hit_test_
### 提示词
```
这是目录为blink/renderer/core/timing/window_performance.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 * Copyright (C) 2012 Intel Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/timing/window_performance.h"

#include <algorithm>
#include <optional>
#include <string>

#include "base/feature_list.h"
#include "base/trace_event/common/trace_event_common.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/trace_id_helper.h"
#include "components/viz/common/frame_timing_details.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/network/public/mojom/load_timing_info.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/frame/frame_owner_element_type.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_high_res_time_stamp.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/input_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/frame/dom_window.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_hidden_state.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/timing/animation_frame_timing_info.h"
#include "third_party/blink/renderer/core/timing/largest_contentful_paint.h"
#include "third_party/blink/renderer/core/timing/layout_shift.h"
#include "third_party/blink/renderer/core/timing/performance_element_timing.h"
#include "third_party/blink/renderer/core/timing/performance_entry.h"
#include "third_party/blink/renderer/core/timing/performance_event_timing.h"
#include "third_party/blink/renderer/core/timing/performance_long_animation_frame_timing.h"
#include "third_party/blink/renderer/core/timing/performance_observer.h"
#include "third_party/blink/renderer/core/timing/performance_timing.h"
#include "third_party/blink/renderer/core/timing/performance_timing_for_reporting.h"
#include "third_party/blink/renderer/core/timing/responsiveness_metrics.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_entry.h"
#include "third_party/blink/renderer/core/timing/visibility_state_entry.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/forward.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

static constexpr base::TimeDelta kLongTaskObserverThreshold =
    base::Milliseconds(50);

namespace blink {

namespace {

AtomicString GetFrameAttribute(HTMLFrameOwnerElement* frame_owner,
                               const QualifiedName& attr_name) {
  AtomicString attr_value;
  if (frame_owner->hasAttribute(attr_name)) {
    attr_value = frame_owner->getAttribute(attr_name);
  }
  return attr_value;
}

AtomicString GetFrameOwnerType(HTMLFrameOwnerElement* frame_owner) {
  switch (frame_owner->OwnerType()) {
    case FrameOwnerElementType::kNone:
      return performance_entry_names::kWindow;
    case FrameOwnerElementType::kIframe:
      return html_names::kIFrameTag.LocalName();
    case FrameOwnerElementType::kObject:
      return html_names::kObjectTag.LocalName();
    case FrameOwnerElementType::kEmbed:
      return html_names::kEmbedTag.LocalName();
    case FrameOwnerElementType::kFrame:
      return html_names::kFrameTag.LocalName();
    case FrameOwnerElementType::kFencedframe:
      return html_names::kFencedframeTag.LocalName();
  }
  NOTREACHED();
}

AtomicString GetFrameSrc(HTMLFrameOwnerElement* frame_owner) {
  switch (frame_owner->OwnerType()) {
    case FrameOwnerElementType::kObject:
      return GetFrameAttribute(frame_owner, html_names::kDataAttr);
    default:
      return GetFrameAttribute(frame_owner, html_names::kSrcAttr);
  }
}

const AtomicString& SelfKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, kSelfAttribution, ("self"));
  return kSelfAttribution;
}

const AtomicString& SameOriginAncestorKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, kSameOriginAncestorAttribution,
                      ("same-origin-ancestor"));
  return kSameOriginAncestorAttribution;
}

const AtomicString& SameOriginDescendantKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, kSameOriginDescendantAttribution,
                      ("same-origin-descendant"));
  return kSameOriginDescendantAttribution;
}

const AtomicString& SameOriginKeyword() {
  DEFINE_STATIC_LOCAL(const AtomicString, kSameOriginAttribution,
                      ("same-origin"));
  return kSameOriginAttribution;
}

AtomicString SameOriginAttribution(Frame* observer_frame,
                                   Frame* culprit_frame) {
  DCHECK(IsMainThread());
  if (observer_frame == culprit_frame) {
    return SelfKeyword();
  }
  if (observer_frame->Tree().IsDescendantOf(culprit_frame)) {
    return SameOriginAncestorKeyword();
  }
  if (culprit_frame->Tree().IsDescendantOf(observer_frame)) {
    return SameOriginDescendantKeyword();
  }
  return SameOriginKeyword();
}

// Eligible event types should be kept in sync with
// WebInputEvent::IsWebInteractionEvent().
bool IsEventTypeForInteractionId(const AtomicString& type) {
  return type == event_type_names::kPointercancel ||
         type == event_type_names::kContextmenu ||
         type == event_type_names::kPointerdown ||
         type == event_type_names::kPointerup ||
         type == event_type_names::kClick ||
         type == event_type_names::kKeydown ||
         type == event_type_names::kKeypress ||
         type == event_type_names::kKeyup ||
         type == event_type_names::kCompositionstart ||
         type == event_type_names::kCompositionupdate ||
         type == event_type_names::kCompositionend ||
         type == event_type_names::kInput;
}

}  // namespace

constexpr size_t kDefaultVisibilityStateEntrySize = 50;

base::TimeTicks WindowPerformance::GetTimeOrigin(LocalDOMWindow* window) {
  DocumentLoader* loader = window->GetFrame()->Loader().GetDocumentLoader();
  return loader->GetTiming().ReferenceMonotonicTime();
}

WindowPerformance::WindowPerformance(LocalDOMWindow* window)
    : Performance(GetTimeOrigin(window),
                  window->CrossOriginIsolatedCapability(),
                  window->GetTaskRunner(TaskType::kPerformanceTimeline),
                  window),
      ExecutionContextClient(window),
      PageVisibilityObserver(window->GetFrame()->GetPage()),
      responsiveness_metrics_(
          MakeGarbageCollected<ResponsivenessMetrics>(this)) {
  DCHECK(window);
  DCHECK(window->GetFrame()->GetPerformanceMonitor());
  if (!RuntimeEnabledFeatures::LongTaskFromLongAnimationFrameEnabled()) {
    window->GetFrame()->GetPerformanceMonitor()->Subscribe(
        PerformanceMonitor::kLongTask, kLongTaskObserverThreshold, this);
  }

  DCHECK(GetPage());
  AddVisibilityStateEntry(GetPage()->IsPageVisible(), base::TimeTicks());
}

WindowPerformance::~WindowPerformance() = default;

ExecutionContext* WindowPerformance::GetExecutionContext() const {
  return ExecutionContextClient::GetExecutionContext();
}

PerformanceTiming* WindowPerformance::timing() const {
  if (!timing_) {
    timing_ = MakeGarbageCollected<PerformanceTiming>(DomWindow());
  }

  return timing_.Get();
}

PerformanceTimingForReporting* WindowPerformance::timingForReporting() const {
  if (!timing_for_reporting_) {
    timing_for_reporting_ =
        MakeGarbageCollected<PerformanceTimingForReporting>(DomWindow());
  }

  return timing_for_reporting_.Get();
}

PerformanceNavigation* WindowPerformance::navigation() const {
  if (!navigation_) {
    navigation_ = MakeGarbageCollected<PerformanceNavigation>(DomWindow());
  }

  return navigation_.Get();
}

MemoryInfo* WindowPerformance::memory(ScriptState* script_state) const {
  // The performance.memory() API has been improved so that we report precise
  // values when the process is locked to a site. The intent (which changed
  // course over time about what changes would be implemented) can be found at
  // https://groups.google.com/a/chromium.org/forum/#!topic/blink-dev/no00RdMnGio,
  // and the relevant bug is https://crbug.com/807651.
  const bool is_locked_to_site = Platform::Current()->IsLockedToSite();
  auto* memory_info = MakeGarbageCollected<MemoryInfo>(
      is_locked_to_site ? MemoryInfo::Precision::kPrecise
                        : MemoryInfo::Precision::kBucketized);
  // Record Web Memory UKM.
  const uint64_t kBytesInKB = 1024;
  auto* execution_context = ExecutionContext::From(script_state);
  ukm::builders::PerformanceAPI_Memory_Legacy(execution_context->UkmSourceID())
      .SetJavaScript(memory_info->usedJSHeapSize() / kBytesInKB)
      .Record(execution_context->UkmRecorder());
  if (!is_locked_to_site) {
    UseCounter::Count(
        execution_context,
        WebFeature::kV8Performance_Memory_AttributeGetter_NotLockedToSite);
  }
  return memory_info;
}

namespace {

BASE_FEATURE(kAdjustNavigationalPrefetchTiming,
             "AdjustNavigationalPrefetchTiming",
             base::FEATURE_ENABLED_BY_DEFAULT);

enum class AdjustNavigationalPrefetchTimingBehavior {
  kRemoveLoadTiming,
  kClampToFetchStart,
};

constexpr base::FeatureParam<AdjustNavigationalPrefetchTimingBehavior>::Option
    kAdjustNavigationalPrefetchTimingBehaviorOptions[] = {
        {AdjustNavigationalPrefetchTimingBehavior::kRemoveLoadTiming,
         "remove_load_timing"},
        {AdjustNavigationalPrefetchTimingBehavior::kClampToFetchStart,
         "clamp_to_fetch_start"},
};

constexpr base::FeatureParam<AdjustNavigationalPrefetchTimingBehavior>
    kAdjustNavigationalPrefetchTimingBehavior{
        &kAdjustNavigationalPrefetchTiming,
        "adjust_navigational_prefetch_timing_behavior",
        AdjustNavigationalPrefetchTimingBehavior::kClampToFetchStart,
        &kAdjustNavigationalPrefetchTimingBehaviorOptions};

network::mojom::blink::LoadTimingInfoPtr
AdjustLoadTimingForNavigationalPrefetch(
    const DocumentLoadTiming& document_load_timing,
    network::mojom::blink::LoadTimingInfoPtr timing) {
  if (!base::FeatureList::IsEnabled(kAdjustNavigationalPrefetchTiming)) {
    return timing;
  }

  static const auto behavior = kAdjustNavigationalPrefetchTimingBehavior.Get();
  switch (behavior) {
    case AdjustNavigationalPrefetchTimingBehavior::kRemoveLoadTiming:
      return nullptr;

    case AdjustNavigationalPrefetchTimingBehavior::kClampToFetchStart:
      break;
  }

  // Everything that happened before the fetch start (this is the value that
  // will be exposed as fetchStart on PerformanceNavigationTiming).
  using network::mojom::blink::LoadTimingInfo;
  using network::mojom::blink::LoadTimingInfoConnectTiming;
  const base::TimeTicks min_ticks = document_load_timing.FetchStart();
  auto new_timing = LoadTimingInfo::New();
  new_timing->socket_reused = timing->socket_reused;
  new_timing->socket_log_id = timing->socket_log_id;

  // Copy the basic members of LoadTimingInfo, and clamp them.
  for (base::TimeTicks LoadTimingInfo::*ts :
       {&LoadTimingInfo::request_start, &LoadTimingInfo::send_start,
        &LoadTimingInfo::send_end, &LoadTimingInfo::receive_headers_start,
        &LoadTimingInfo::receive_headers_end,
        &LoadTimingInfo::receive_non_informational_headers_start,
        &LoadTimingInfo::first_early_hints_time}) {
    if (!((*timing).*ts).is_null()) {
      (*new_timing).*ts = std::max((*timing).*ts, min_ticks);
    }
  }

  // If connect timing is available, do the same to it.
  if (auto* connect_timing = timing->connect_timing.get()) {
    new_timing->connect_timing = LoadTimingInfoConnectTiming::New();
    auto& new_connect_timing = *new_timing->connect_timing;
    for (base::TimeTicks LoadTimingInfoConnectTiming::*ts : {
             &LoadTimingInfoConnectTiming::domain_lookup_start,
             &LoadTimingInfoConnectTiming::domain_lookup_end,
             &LoadTimingInfoConnectTiming::connect_start,
             &LoadTimingInfoConnectTiming::connect_end,
             &LoadTimingInfoConnectTiming::ssl_start,
             &LoadTimingInfoConnectTiming::ssl_end,
         }) {
      if (!(connect_timing->*ts).is_null()) {
        new_connect_timing.*ts = std::max(connect_timing->*ts, min_ticks);
      }
    }
  }

  return new_timing;
}

}  // namespace

void WindowPerformance::CreateNavigationTimingInstance(
    mojom::blink::ResourceTimingInfoPtr info) {
  DCHECK(DomWindow());

  // If this is navigational prefetch, it may be necessary to partially redact
  // the timings to avoid exposing when events that occurred during the prefetch
  // happened. Instead, they look like they happened very fast.
  DocumentLoader* loader = DomWindow()->document()->Loader();
  if (loader &&
      loader->GetNavigationDeliveryType() ==
          network::mojom::NavigationDeliveryType::kNavigationalPrefetch &&
      info->timing) {
    info->timing = AdjustLoadTimingForNavigationalPrefetch(
        loader->GetTiming(), std::move(info->timing));
  }

  navigation_timing_ = MakeGarbageCollected<PerformanceNavigationTiming>(
      *DomWindow(), std::move(info), time_origin_);
}

void WindowPerformance::OnBodyLoadFinished(int64_t encoded_body_size,
                                           int64_t decoded_body_size) {
  if (navigation_timing_) {
    navigation_timing_->OnBodyLoadFinished(encoded_body_size,
                                           decoded_body_size);
  }
}

void WindowPerformance::BuildJSONValue(V8ObjectBuilder& builder) const {
  Performance::BuildJSONValue(builder);
  builder.Add("timing", timing());
  builder.Add("navigation", navigation());
}

void WindowPerformance::Trace(Visitor* visitor) const {
  visitor->Trace(event_timing_entries_);
  visitor->Trace(first_pointer_down_event_timing_);
  visitor->Trace(event_counts_);
  visitor->Trace(navigation_);
  visitor->Trace(timing_);
  visitor->Trace(timing_for_reporting_);
  visitor->Trace(responsiveness_metrics_);
  visitor->Trace(current_event_);
  Performance::Trace(visitor);
  PerformanceMonitor::Client::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  PageVisibilityObserver::Trace(visitor);
}

static bool CanAccessOrigin(Frame* frame1, Frame* frame2) {
  const SecurityOrigin* security_origin1 =
      frame1->GetSecurityContext()->GetSecurityOrigin();
  const SecurityOrigin* security_origin2 =
      frame2->GetSecurityContext()->GetSecurityOrigin();
  return security_origin1->CanAccess(security_origin2);
}

/**
 * Report sanitized name based on cross-origin policy.
 * See detailed Security doc here: http://bit.ly/2duD3F7
 */
// static
std::pair<AtomicString, DOMWindow*> WindowPerformance::SanitizedAttribution(
    ExecutionContext* task_context,
    bool has_multiple_contexts,
    LocalFrame* observer_frame) {
  DCHECK(IsMainThread());
  if (has_multiple_contexts) {
    // Unable to attribute, multiple script execution contents were involved.
    DEFINE_STATIC_LOCAL(const AtomicString, kAmbiguousAttribution,
                        ("multiple-contexts"));
    return std::make_pair(kAmbiguousAttribution, nullptr);
  }

  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(task_context);
  if (!window || !window->GetFrame()) {
    // Unable to attribute as no script was involved.
    DEFINE_STATIC_LOCAL(const AtomicString, kUnknownAttribution, ("unknown"));
    return std::make_pair(kUnknownAttribution, nullptr);
  }

  // Exactly one culprit location, attribute based on origin boundary.
  Frame* culprit_frame = window->GetFrame();
  DCHECK(culprit_frame);
  if (CanAccessOrigin(observer_frame, culprit_frame)) {
    // From accessible frames or same origin, return culprit location URL.
    return std::make_pair(SameOriginAttribution(observer_frame, culprit_frame),
                          culprit_frame->DomWindow());
  }
  // For cross-origin, if the culprit is the descendant or ancestor of
  // observer then indicate the *closest* cross-origin frame between
  // the observer and the culprit, in the corresponding direction.
  if (culprit_frame->Tree().IsDescendantOf(observer_frame)) {
    // If the culprit is a descendant of the observer, then walk up the tree
    // from culprit to observer, and report the *last* cross-origin (from
    // observer) frame.  If no intermediate cross-origin frame is found, then
    // report the culprit directly.
    Frame* last_cross_origin_frame = culprit_frame;
    for (Frame* frame = culprit_frame; frame != observer_frame;
         frame = frame->Tree().Parent()) {
      if (!CanAccessOrigin(observer_frame, frame)) {
        last_cross_origin_frame = frame;
      }
    }
    DEFINE_STATIC_LOCAL(const AtomicString, kCrossOriginDescendantAttribution,
                        ("cross-origin-descendant"));
    return std::make_pair(kCrossOriginDescendantAttribution,
                          last_cross_origin_frame->DomWindow());
  }
  if (observer_frame->Tree().IsDescendantOf(culprit_frame)) {
    DEFINE_STATIC_LOCAL(const AtomicString, kCrossOriginAncestorAttribution,
                        ("cross-origin-ancestor"));
    return std::make_pair(kCrossOriginAncestorAttribution, nullptr);
  }
  DEFINE_STATIC_LOCAL(const AtomicString, kCrossOriginAttribution,
                      ("cross-origin-unreachable"));
  return std::make_pair(kCrossOriginAttribution, nullptr);
}

void WindowPerformance::ReportLongTask(base::TimeTicks start_time,
                                       base::TimeTicks end_time,
                                       ExecutionContext* task_context,
                                       bool has_multiple_contexts) {
  if (!DomWindow()) {
    return;
  }
  std::pair<AtomicString, DOMWindow*> attribution =
      WindowPerformance::SanitizedAttribution(
          task_context, has_multiple_contexts, DomWindow()->GetFrame());
  DOMWindow* culprit_dom_window = attribution.second;
  if (!culprit_dom_window || !culprit_dom_window->GetFrame() ||
      !culprit_dom_window->GetFrame()->DeprecatedLocalOwner()) {
    AddLongTaskTiming(start_time, end_time, attribution.first,
                      performance_entry_names::kWindow, g_empty_atom,
                      g_empty_atom, g_empty_atom);
  } else {
    HTMLFrameOwnerElement* frame_owner =
        culprit_dom_window->GetFrame()->DeprecatedLocalOwner();
    AddLongTaskTiming(start_time, end_time, attribution.first,
                      GetFrameOwnerType(frame_owner), GetFrameSrc(frame_owner),
                      GetFrameAttribute(frame_owner, html_names::kIdAttr),
                      GetFrameAttribute(frame_owner, html_names::kNameAttr));
  }
}

void WindowPerformance::EventTimingProcessingStart(
    const Event& event,
    base::TimeTicks processing_start,
    EventTarget* hit_test_target) {
  if (!DomWindow() || !DomWindow()->GetFrame()) {
    return;
  }
  DCHECK(!processing_start.is_null());

  const AtomicString& event_type = event.type();

  // TODO(crbug.com/40930016): remove support for pointermove
  if (event_type == event_type_names::kPointermove) {
    return;
  }

  // Event Counts API.
  eventCounts()->Add(event_type);

  // Some events are neither pointer nor keyboard (i.e. mouse events)
  // But we only use pointer and keyboard event data for interactions.
  const PointerEvent* pointer_event = DynamicTo<PointerEvent>(event);
  const KeyboardEvent* key_event = DynamicTo<KeyboardEvent>(event);

  PerformanceEventTiming::EventTimingReportingInfo reporting_info{
      .enqueued_to_main_thread_time =
          responsiveness_metrics_->CurrentInteractionEventQueuedTimestamp(),
      .processing_start_time = processing_start,
  };

  if (pointer_event) {
    reporting_info.creation_time = pointer_event->OldestPlatformTimeStamp();
    reporting_info.pointer_id = pointer_event->pointerId();

    if (RuntimeEnabledFeaturesBase::
            EventTimingTapStopScrollNoInteractionIdEnabled()) {
      reporting_info.prevent_counting_as_interaction |=
          pointer_event->GetPreventCountingAsInteraction();
    };
  } else {
    reporting_info.creation_time = event.PlatformTimeStamp();

    if (key_event) {
      reporting_info.key_code = key_event->keyCode();
    }
  }

  // Set prevent_counting_as_interaction to true for all the event entries when
  // the selection autoscroll happens at the current event presentation frame
  // or the previous frame.
  if (RuntimeEnabledFeaturesBase::
          EventTimingSelectionAutoScrollNoInteractionIdEnabled()) {
    reporting_info.prevent_counting_as_interaction |= IsAutoscrollActive();
  }

  // We always have a Hit test target before starting event dispatch.  During
  // event dispatch we might change target via event retargetting or
  // pointer-capture (or any number of other features).
  // The "final" target is attached to the blink::Event as target().  However,
  // its possible that we optimize out the event dispatch steps (i.e. we don't
  // have listeners).  When that happens, Event Timing still measures and
  // reports entries, but Chromium leaves the blink::Event target() value as
  // nullptr.  So, we cannot rely on always having a target().  We use the
  // following strategy:
  // 1. Start with `hit_test_target`, from ProcessingStart, before dispatch.
  // 2. Update to `event.target()`, from ProcessingEnd, if we can.
  // `hit_test_target` can still be null in tests.
  // `target` can be non-null but detached from DOM and GC-ed before observer
  // fires.
  PerformanceEventTiming* entry = PerformanceEventTiming::Create(
      event_type, reporting_info, event.cancelable(),
      hit_test_target ? hit_test_target->ToNode() : nullptr, DomWindow());

  event_timing_entries_.push_back(entry);
  current_event_ = &event;
}

void WindowPerformance::EventTimingProcessingEnd(
    const Event& event,
    base::TimeTicks processing_end) {
  current_event_ = nullptr;
  DCHECK(!processing_end.is_null());

  if (!DomWindow() || !DomWindow()->GetFrame()) {
    return;
  }
  const AtomicString& event_type = event.type();

  // TODO(crbug.com/40930016): remove support for pointermove
  if (event_type == event_type_names::kPointermove) {
    // A trusted pointermove must be a PointerEvent.
    const PointerEvent* pointer_event = DynamicTo<PointerEvent>(event);
    if (pointer_event) {
      NotifyPotentialDrag(pointer_event->pointerId());
    }
    return;
  }

  auto iter = std::find_if(event_timing_entries_.rbegin(),
                           event_timing_entries_.rend(), [](const auto& event) {
                             return event->GetEventTimingReportingInfo()
                                 ->processing_end_time.is_null();
                           });
  CHECK(iter != event_timing_entries_.rend());
  PerformanceEventTiming* entry = *iter;
  CHECK(entry);

  PerformanceEventTiming::EventTimingReportingInfo* reporting_info =
      entry->GetEventTimingReportingInfo();
  CHECK(reporting_info);
  reporting_info->processing_end_time = processing_end;

  if (event.target()) {
    // `event->target()` is assigned as part of EventDispatch, and will be unset
    // whenever we skip dispatch. (See: crbug.com/1367329).
    // Note: target may be dom detached, and even GC-ed, before Observer fires.
    entry->SetTarget(event.target()->ToNode());
  }

  // Request presentation time first, because this might increment presentation
  // index
  // TODO(crbug.com/)
  if (need_new_promise_for_event_presentation_time_) {
    DomWindow()->GetFrame()->GetChromeClient().NotifyPresentationTime(
        *DomWindow()->GetFrame(),
        CrossThreadBindOnce(&WindowPerformance::OnPresentationPromiseResolved,
                            WrapCrossThreadWeakPersistent(this),
                            ++event_presentation_promise_count_));
    need_new_promise_for_event_presentation_time_ = false;
  }

  reporting_info->presentation_index = event_presentation_promise_count_;
}

void WindowPerformance::SetCommitFinishTimeStampForPendingEvents(
    base::TimeTicks commit_finish_time) {
  for (auto entry : event_timing_entries_) {
    // Skip events that don't need paint, or have already been painted
    if (entry->GetEventTimingReportingInfo()->commit_finish_time.has_value()) {
      continue;
    }
    if (entry->HasKnownEndTime()) {
      continue;
    }
    entry->GetEventTimingReportingInfo()->commit_finish_time =
        commit_finish_time;
  }
}

// Parameters:
// |presentation_index|     - The registering index of the presentation promise.
//                            First registered presentation promise will have an
//                            index of 1.
// |presentation_timestamp| - The frame presenting time or an early exit time
//                            due to no frame updates.
void WindowPerformance::OnPresentationPromiseResolved(
    uint64_t presentation_index,
    const viz::FrameTimingDetails& presentation_details) {
  if (!DomWindow() || !DomWindow()->document()) {
    return;
  }

  // If the resolved presentation promise is the latest one we registered, then
  // events arrive after will need a new presentation promise to provide
  // presentation feedback.
  if (presentation_index == event_presentation_promise_count_) {
    need_new_promise_for_event_presentation_time_ = true;
  }

  base::TimeTicks presentation_timestamp =
      presentation_details.presentation_feedback.timestamp;
  for (auto event_timing_entry : event_timing_entries_) {
    if (event_timing_entry->GetEventTimingReportingInfo()->presentation_index ==
        presentation_index) {
      event_timing_entry->GetEventTimingReportingInfo()->presentation_time =
          presentation_timestamp;
    }
  }
  ReportEventTimings();
}

void WindowPerformance::FlushEventTimingsOnPageHidden() {
  ReportAllPendingEventTimingsOnPageHidden();

  // Remove any remaining events that are not flushed by the above step.
  responsiveness_metrics_->FlushAllEventsAtPageHidden();
}

// At visibility change, we report event timings of current pending events. The
// registered presentation callback, when invoked, would be ignored.
void WindowPerformance::ReportAllPendingEventTimingsOnPageHidden() {
  // By the time visibility change happens, DomWindow object should still be
  // alive. This is just to be safe.
  if (!DomWindow() || !DomWindow()->document()) {
    return;
  }

  // For events which don't have an end_time yet, set a fallback time to the
  // processingEnd timestamp.
  // Ideally the fallback time could be the last_hidden_timestamp_, but we don't
  // actually have an accurate value for that (it would need to come from
  // browser IPC).
  for (auto event_timing_entry : event_timing_entries_) {
    if (!event_timing_entry->HasKnownEndTime()) {
      event_timing_entry->GetEventTimingReportingInfo()->fallback_time =
          event_timing_entry->GetEventTimingReportingInfo()
              ->processing_end_time;
    }
  }
  ReportEventTimings();
}

void WindowPerformance::ReportEventTimings() {
  CHECK(DomWindow() && DomWindow()->document());
  InteractiveDetector* interactive_detector =
      InteractiveDetector::From(*(DomWindow()->document()));

  bool tracing_enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED("devtools.timeline", &tracing_enabled);

  while (!event_timing_entries_.empty()) {
    // Find the range [first, last) of events with the same presentation_index
    auto first = event_timing_entries_.begin();
    uint64_t presentation_index =
        first->Get()->GetEventTimingReportingInfo()->presentation_index;
    auto last = std::find_if_not(
        first, event_timing_entries_.end(), [presentation_index](auto entry) {
          return presentation_index ==
                 entry->GetEventTimingReportingInfo()->presentation_index;
        });

    // Unless ALL events in this range are ready to be reported, break out.
    // Today: only a known EndTime is needed.
    // Soon: also enforce interactionID to know Known.
    if (!std::all_of(first, last,
                     [](auto entry) { return entry->HasKnownEndTime(); })) {
      break;
    }

    if (tracing_enabled) {
      auto scope = perfetto::Track::ThreadScoped(this);
      auto flowid = perfetto::Flow::ProcessScoped(presentation_index);

      auto* first_event_reporting_info =
          first->Get()->GetEventTimingReportingInfo();
      auto frame_start_time = first_event_reporting_info->processing_start_time;

      TRACE_EVENT_BEGIN("devtools.timeline", "EventsInAnimationFrame", scope,
                        frame_start_time, flowid);

      TRACE_EVENT_INSTANT("devtools.timeline", "EventCreation", scope,
                          first_event_reporting_info->creation_time, flowid);
    }

    // Report all the events in this frame
    std::for_each(first, last, [&](auto entry) {
      ReportEvent(interactive_detector, entry);
    });

    if (tracing_enabled) {
      auto scope = perfetto::Track::ThreadScoped(this);
      auto flowid = perfetto::Flow::ProcessScoped(presentation_index);

      auto* last_event_reporting_info =
          std::prev(last)->Get()->GetEventTimingReportingInfo();
      auto frame_end_time =
          last_event_reporting_info->commit_finish_time.value_or(
              last_event_reporting_info->processing_end_time);

      TRACE_EVENT_END("devtools.timeline", scope, frame_end_time);

      if (last_event_reporting_info->presentation_time.has_value()) {
        TRACE_EVENT_INSTANT(
            "devt
```
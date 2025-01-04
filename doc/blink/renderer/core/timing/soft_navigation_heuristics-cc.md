Response:
Let's break down the thought process for analyzing this `soft_navigation_heuristics.cc` file.

**1. Initial Understanding - The "What":**

* **File Name and Directory:**  `blink/renderer/core/timing/soft_navigation_heuristics.cc`. The "timing" and "heuristics" keywords are strong hints. It likely deals with detecting and measuring something related to navigation timing, but in a way that's not strictly defined (hence "heuristics"). "Soft navigation" is the key term to focus on.

* **Copyright Header:**  Indicates it's part of the Chromium project.

* **Includes:**  This is the first concrete information about what the code *does*. Let's categorize them:
    * **Core Blink/DOM:** `Event`, `Node`, `LocalFrameClient`, `LocalFrameView`, `Document`, `LocalDOMWindow`, `DOMWindowPerformance`. These suggest it interacts with the DOM structure and frame lifecycle.
    * **Timing/Paint:** `PaintTiming`, `PaintTimingDetector`. Confirms the connection to rendering and performance measurement.
    * **Soft Navigation Specific:** `SoftNavigationContext`. This will be a central class.
    * **Utility/Platform:** `base/logging`, `base/metrics`, `third_party/blink/public/common/features`, `third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h`, `third_party/blink/renderer/platform/scheduler/public/...`. These are for logging, metrics collection, feature flags, V8 integration, and task scheduling. The scheduler parts are particularly important for understanding how this interacts with asynchronous operations.
    * **Inspector/Console:** `ConsoleMessage`. Suggests debugging and developer visibility.

* **Namespace:** `blink`. This confirms it's part of the Blink rendering engine.

**2. Identifying Key Concepts - The "Why":**

* **Soft Navigation:** The primary focus. The code aims to *detect* these. What is a soft navigation?  The comments and variable names (like `potential_soft_navigations_`) provide clues. It's something that *looks like* a navigation to the user but doesn't involve a full page reload.

* **Heuristics:**  The code isn't using a perfect definition of soft navigation. It's using rules and conditions (heuristics) to infer when one has occurred. This explains the various checks for DOM modifications, paints, and user interactions.

* **Timing and Metrics:**  The code logs metrics (UMA), creates performance entries (`DOMWindowPerformance`), and interacts with paint timing mechanisms. This suggests the goal is not just detection but also *measurement* of soft navigations for performance analysis.

* **User Interaction:** The code tracks events like `click`, `keydown`, `keyup`, and `navigate`. User actions are clearly a trigger for considering a soft navigation.

* **Task Scheduling:** The inclusion of `TaskAttributionTracker` hints at how soft navigation detection is tied to asynchronous JavaScript execution.

**3. Analyzing the Code Structure - The "How":**

* **`SoftNavigationHeuristics` Class:** The central class. It's a `Supplement` to `LocalDOMWindow`, meaning it adds functionality to the window object.

* **`SoftNavigationContext`:**  Likely holds state related to a potential soft navigation. The code creates and manages instances of this class.

* **Event Handling:** The `CreateEventScope` and `MaybeCreateEventScopeForEvent` methods suggest a mechanism for tracking user interaction boundaries. The `EventScope` class itself acts as a RAII guard.

* **Conditions for Detection:**  The `EmitSoftNavigationEntryIfAllConditionsMet` function and the logging of `SoftNavigationOutcome` enums show the criteria for a soft navigation to be confirmed. Lack of paint, DOM modification, or a context are negative indicators.

* **Paint Tracking:** The `RecordPaint` function is crucial. A certain amount of painting is likely a necessary condition for a soft navigation.

* **Resetting Heuristics:** The `ResetHeuristic` function suggests that the detection process has a lifecycle and needs to be reset.

**4. Connecting to Web Technologies:**

* **JavaScript:**  JavaScript actions are the primary drivers of soft navigations. Think of single-page applications (SPAs) updating content dynamically without full reloads. The interaction with `ScriptState` and task scheduling confirms this.

* **HTML:** The DOM modifications tracked by the code directly relate to changes in the HTML structure.

* **CSS:** While not explicitly mentioned as a condition, CSS transitions and animations are often part of what makes a soft navigation feel smooth. The paint tracking implicitly includes the effects of CSS.

**5. Logical Reasoning and Assumptions:**

* **Assumption:** A user interaction triggers a JavaScript action that modifies the DOM and causes a visual update (paint) without a full navigation.
* **Input:** A user clicks a button on a webpage. This triggers a JavaScript function.
* **Output (Potential):** If the JavaScript modifies the DOM and causes a significant paint, the `SoftNavigationHeuristics` might detect a soft navigation.

**6. Common Usage Errors and Debugging:**

* **Error:** A developer implements dynamic content updates using JavaScript, but the updates are too small or don't trigger a repaint. The soft navigation might not be detected.
* **Debugging:**  The console messages (`AddConsoleMessage`) and trace events (`TRACE_EVENT_INSTANT`) are key debugging tools. Following the lifecycle of a `SoftNavigationContext` would be important.

**7. User Journey to the Code:**

This requires understanding how the Chromium rendering engine works:

1. **User Interaction:** The user interacts with the webpage (e.g., clicks a link, types in a search bar).
2. **Event Dispatch:** The browser dispatches an event (e.g., `click`, `keydown`).
3. **JavaScript Execution:**  The event triggers a JavaScript event handler.
4. **DOM Modification:** The JavaScript code modifies the DOM.
5. **Rendering Pipeline:** The browser's rendering engine processes the DOM changes and performs layout and paint.
6. **`SoftNavigationHeuristics` Interaction:**  At various points during this process (especially during event handling, DOM modification, and paint), the `SoftNavigationHeuristics` code is invoked to evaluate if a soft navigation is occurring.

**Self-Correction/Refinement during the process:**

* Initially, I might just see "navigation" and think of standard full-page navigations. But the "soft" qualifier and the context of SPAs quickly shift the understanding.
* Seeing the `potential_soft_navigations_` list clarifies that the detection is not immediate but involves tracking potential candidates.
* Understanding the RAII nature of `EventScope` is crucial for grasping how the code manages the lifecycle of tracking a user interaction.

By following these steps, breaking down the code into its components and their purposes, and then connecting it back to the broader web development context, we arrive at a comprehensive understanding of the `soft_navigation_heuristics.cc` file.
好的，让我们来分析一下 `blink/renderer/core/timing/soft_navigation_heuristics.cc` 这个文件的功能。

**文件功能概览**

`soft_navigation_heuristics.cc` 文件的主要功能是**通过一系列的启发式规则来检测页面中发生的“软导航” (Soft Navigation)**。

**什么是软导航？**

软导航指的是在单页应用程序 (SPA) 或富 Web 应用中，用户与页面交互时，URL 发生改变，但浏览器并没有进行传统的完整页面刷新。  内容更新通常是通过 JavaScript 动态加载和渲染实现的。  与传统的硬导航（完整的页面加载）相比，软导航速度更快，用户体验更流畅。

**该文件的具体功能：**

1. **检测软导航的发生:**
   - **监听用户交互事件:**  例如 `click` (点击), `keydown` (键盘按下), `keyup` (键盘松开), `navigate` (自定义的导航事件)。
   - **跟踪 DOM 变化:** 监测在用户交互后，DOM 结构是否发生了显著的修改。
   - **监控页面渲染:**  观察在用户交互后，页面是否发生了显著的绘制（paint）。
   - **基于启发式规则判断:**  综合考虑用户交互、DOM 修改和页面渲染等因素，根据预设的规则判断是否发生了软导航。

2. **记录软导航信息:**
   - **创建 `SoftNavigationContext`:**  当疑似发生软导航时，创建一个上下文对象来跟踪相关信息，例如 URL、用户交互时间戳等。
   - **存储潜在的软导航:**  将创建的上下文对象存储起来，等待进一步的确认。

3. **上报软导航指标:**
   - **记录 UMA (User Metrics Analysis) 数据:**  统计软导航的发生次数和结果（成功检测到或未满足条件）。
   - **生成性能指标:**  向 `DOMWindowPerformance` 添加软导航条目，以便开发者可以通过 Performance API 获取相关信息。
   - **向 UKM (User Keyed Metrics) 上报:**  通知 UKM 系统发生了软导航事件，用于更细粒度的性能分析。

4. **提供调试信息:**
   - **输出控制台消息:**  当检测到软导航时，在浏览器的开发者工具控制台中输出信息。
   - **生成 Trace Event:**  在 Chrome 的 tracing 系统中生成事件，方便开发者进行性能分析和调试。

5. **管理软导航状态:**
   - **重置启发式规则:**  在一次软导航检测完成后，或者在一定时间后，重置内部状态，准备下一次检测。
   - **处理垃圾回收:**  当与软导航相关的任务被垃圾回收时，进行清理工作。

**与 JavaScript, HTML, CSS 的关系**

该文件主要通过观察 JavaScript 的行为和对 HTML DOM 的修改来判断是否发生了软导航。CSS 的变化通常是 DOM 修改的副产品，也会影响页面的渲染。

**举例说明：**

* **JavaScript:**
    - **假设输入:** 用户点击了一个按钮，该按钮的 JavaScript 事件处理函数使用 `history.pushState()` 修改了 URL，并动态更新了页面内容（例如，通过 `innerHTML` 修改了某个 `div` 的内容）。
    - **`soft_navigation_heuristics.cc` 的逻辑:**  该文件会捕捉到 `click` 事件，并开始跟踪。如果后续检测到 DOM 发生显著变化（`ModifiedDOM()` 被调用）并且页面发生了绘制 (`RecordPaint()`),  则会判定为软导航。

* **HTML:**
    - **假设输入:**  上述 JavaScript 代码通过修改 HTML 结构 (`innerHTML`) 来更新页面内容。例如，将一个显示文章列表的 `<ul>` 元素的内容替换为新的列表。
    - **`soft_navigation_heuristics.cc` 的逻辑:** `ModifiedDOM()` 函数会被调用，并且会记录 DOM 的修改。这是判断软导航的关键条件之一。

* **CSS:**
    - **假设输入:**  JavaScript 代码修改了某个元素的 class 属性，从而应用了不同的 CSS 样式，导致页面布局或外观发生变化。
    - **`soft_navigation_heuristics.cc` 的逻辑:** 虽然该文件不直接解析 CSS，但 CSS 样式的变化会导致页面的重新渲染。 `RecordPaint()` 函数会记录渲染事件，这可以作为软导航的证据之一。

**逻辑推理的假设输入与输出**

假设我们简化一下软导航的检测逻辑，只考虑 URL 变化和 DOM 修改：

* **假设输入:**
    1. 用户点击页面上的一个链接。
    2. JavaScript 代码执行 `history.pushState('/new-page')` 修改了 URL。
    3. JavaScript 代码通过 `document.getElementById('content').innerHTML = '<h1>New Content</h1>'` 修改了页面内容。
* **`soft_navigation_heuristics.cc` 的逻辑推理:**
    1. `CreateEventScope(kClick)` 被调用，开始跟踪用户交互。
    2. `SameDocumentNavigationCommitted('/new-page')` 被调用，记录 URL 的变化。
    3. `ModifiedDOM()` 被调用，记录 DOM 的修改。
    4. `EmitSoftNavigationEntryIfAllConditionsMet()` 检查所有条件（例如，URL 已改变，DOM 已修改）。
* **输出:** 如果所有必要的条件都满足，则会记录一次软导航事件，并上报相关指标。

**用户或编程常见的使用错误**

1. **DOM 修改过小或不触发渲染:**  如果 JavaScript 代码对 DOM 的修改非常小，或者修改后没有触发浏览器进行明显的渲染，那么软导航可能不会被检测到。例如，仅仅修改一个隐藏元素的文本内容。
2. **过早或过晚地重置启发式规则:**  如果开发者在某些自定义逻辑中错误地调用了 `ResetHeuristic()`，可能会导致正在进行的软导航检测被中断。
3. **依赖于错误的事件类型:**  如果开发者使用了非标准的事件来模拟导航行为，`soft_navigation_heuristics.cc` 可能无法正确识别。

**用户操作如何一步步到达这里，作为调试线索**

假设开发者怀疑某个操作应该被识别为软导航，但实际上没有，以下是可能的调试步骤：

1. **用户操作:** 用户在页面上执行某个操作，例如点击一个按钮。
2. **事件触发:**  该操作触发了一个 JavaScript 事件（例如 `click`）。
3. **`MaybeCreateEventScopeForEvent()`:**  `soft_navigation_heuristics.cc` 中的这个函数可能会被调用，以判断是否需要为此事件创建一个 `EventScope` 来跟踪潜在的软导航。
4. **`CreateEventScope()`:** 如果判断需要跟踪，则创建一个 `EventScope` 和一个 `SoftNavigationContext`。
5. **JavaScript 执行:** 相关的 JavaScript 代码开始执行，可能会修改 DOM (`ModifiedDOM()`) 和/或触发 URL 变化 (`SameDocumentNavigationCommitted()`)。
6. **页面渲染:**  浏览器进行页面渲染 (`RecordPaint()`)。
7. **`EmitSoftNavigationEntryIfAllConditionsMet()`:**  在 `EventScope` 结束时 (`OnSoftNavigationEventScopeDestroyed()`)，或者在 DOM 修改或页面渲染发生后，会检查是否满足所有软导航的条件。
8. **调试线索:**
   - **查看控制台消息:** 检查是否有 "A soft navigation has been detected" 这样的消息输出。
   - **使用 Chrome DevTools 的 Performance 面板:** 查看是否有 "Soft Navigation" 类型的条目。
   - **查看 Trace Events:**  使用 `chrome://tracing` 可以查看更详细的软导航检测过程，例如 `SoftNavigationHeuristics::AsyncSameDocumentNavigationStarted`, `SoftNavigationHeuristics::SameDocumentNavigationCommitted`, `SoftNavigationHeuristics::ModifiedDOM`, `SoftNavigationHeuristics_RecordPaint` 等事件。
   - **断点调试:**  在 `soft_navigation_heuristics.cc` 中设置断点，例如在 `ModifiedDOM()`, `RecordPaint()`, `EmitSoftNavigationEntryIfAllConditionsMet()` 等关键函数中，逐步跟踪代码执行流程，查看哪些条件没有满足。
   - **检查 Feature Flag:** 确认 `features::kSoftNavigationDetection` 功能是否已启用。

总而言之，`soft_navigation_heuristics.cc` 是 Blink 渲染引擎中一个重要的组成部分，它通过观察用户的交互行为、DOM 的变化和页面的渲染情况，利用一系列的启发式规则来判断是否发生了软导航，并为开发者提供相关的性能指标和调试信息。 这对于理解和优化现代 Web 应用的性能至关重要。

Prompt: 
```
这是目录为blink/renderer/core/timing/soft_navigation_heuristics.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"

#include <utility>

#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_context.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_info.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"

namespace blink {

namespace {

const char kPageLoadInternalSoftNavigationOutcome[] =
    "PageLoad.Internal.SoftNavigationOutcome";

// These values are logged to UMA. Entries should not be renumbered and numeric
// values should never be reused. Please keep in sync with
// "SoftNavigationOutcome" in tools/metrics/histograms/enums.xml. Note also that
// these form a bitmask; future conditions should continue this pattern.
// LINT.IfChange
enum SoftNavigationOutcome {
  kSoftNavigationDetected = 0,

  kNoSoftNavContextDuringUrlChange = 1,
  kNoPaint = 2,
  kNoDomModification = 4,

  kNoPaintOrDomModification = kNoPaint | kNoDomModification,

  kMaxValue = kNoPaintOrDomModification,
};
// LINT.ThenChange(/tools/metrics/histograms/enums.xml:SoftNavigationOutcome)

void LogAndTraceDetectedSoftNavigation(LocalFrame* frame,
                                       LocalDOMWindow* window,
                                       const SoftNavigationContext& context) {
  CHECK(frame && frame->IsMainFrame());
  CHECK(window);
  if (!RuntimeEnabledFeatures::SoftNavigationHeuristicsEnabled(window)) {
    return;
  }
  auto* console_message = MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kJavaScript,
      mojom::blink::ConsoleMessageLevel::kInfo,
      String("A soft navigation has been detected: ") + context.Url());
  window->AddConsoleMessage(console_message);

  TRACE_EVENT_INSTANT("scheduler,devtools.timeline,loading",
                      "SoftNavigationHeuristics_SoftNavigationDetected",
                      context.UserInteractionTimestamp(), "frame",
                      GetFrameIdForTracing(frame), "url", context.Url(),
                      "navigationId", window->GetNavigationId());
}

constexpr bool IsInteractionStart(
    SoftNavigationHeuristics::EventScope::Type type) {
  return (type == SoftNavigationHeuristics::EventScope::Type::kClick ||
          type == SoftNavigationHeuristics::EventScope::Type::kKeydown ||
          type == SoftNavigationHeuristics::EventScope::Type::kNavigate);
}

constexpr bool IsInteractionEnd(
    SoftNavigationHeuristics::EventScope::Type type) {
  return (type == SoftNavigationHeuristics::EventScope::Type::kClick ||
          type == SoftNavigationHeuristics::EventScope::Type::kKeyup ||
          type == SoftNavigationHeuristics::EventScope::Type::kNavigate);
}

std::optional<SoftNavigationHeuristics::EventScope::Type>
EventScopeTypeFromEvent(const Event& event) {
  if (!event.isTrusted()) {
    return std::nullopt;
  }
  if (event.IsMouseEvent() && event.type() == event_type_names::kClick) {
    return SoftNavigationHeuristics::EventScope::Type::kClick;
  }
  if (event.type() == event_type_names::kNavigate) {
    return SoftNavigationHeuristics::EventScope::Type::kNavigate;
  }
  if (event.IsKeyboardEvent()) {
    Node* target_node = event.target() ? event.target()->ToNode() : nullptr;
    if (target_node && target_node->IsHTMLElement() &&
        DynamicTo<HTMLElement>(target_node)->IsHTMLBodyElement()) {
      if (event.type() == event_type_names::kKeydown) {
        return SoftNavigationHeuristics::EventScope::Type::kKeydown;
      } else if (event.type() == event_type_names::kKeypress) {
        return SoftNavigationHeuristics::EventScope::Type::kKeypress;
      } else if (event.type() == event_type_names::kKeyup) {
        return SoftNavigationHeuristics::EventScope::Type::kKeyup;
      }
    }
  }
  return std::nullopt;
}

}  // namespace

// static
const char SoftNavigationHeuristics::kSupplementName[] =
    "SoftNavigationHeuristics";

SoftNavigationHeuristics::SoftNavigationHeuristics(LocalDOMWindow& window)
    : Supplement<LocalDOMWindow>(window) {
  LocalFrame* frame = window.GetFrame();
  CHECK(frame && frame->View());
}

SoftNavigationHeuristics* SoftNavigationHeuristics::From(
    LocalDOMWindow& window) {
  if (!base::FeatureList::IsEnabled(features::kSoftNavigationDetection)) {
    return nullptr;
  }
  if (!window.GetFrame()->IsMainFrame()) {
    return nullptr;
  }
  SoftNavigationHeuristics* heuristics =
      Supplement<LocalDOMWindow>::From<SoftNavigationHeuristics>(window);
  if (!heuristics) {
    if (Document* document = window.document()) {
      // Don't measure soft navigations in devtools.
      if (document->Url().ProtocolIs("devtools")) {
        return nullptr;
      }
    }
    heuristics = MakeGarbageCollected<SoftNavigationHeuristics>(window);
    ProvideTo(window, heuristics);
  }
  return heuristics;
}

void SoftNavigationHeuristics::Dispose() {
  for (const auto& context : potential_soft_navigations_) {
    RecordUmaForNonSoftNavigationInteraction(*context.Get());
  }
}

void SoftNavigationHeuristics::RecordUmaForNonSoftNavigationInteraction(
    const SoftNavigationContext& context) const {
  // For all interactions which included a (soft nav context attributable) URL
  // modification, yet were not declared soft navs, log the criteria which were
  // not met.
  if (context.Url().empty()) {
    return;
  }

  if (!paint_conditions_met_ && !context.HasMainModification()) {
    base::UmaHistogramEnumeration(
        kPageLoadInternalSoftNavigationOutcome,
        SoftNavigationOutcome::kNoPaintOrDomModification);
  } else if (!paint_conditions_met_) {
    base::UmaHistogramEnumeration(kPageLoadInternalSoftNavigationOutcome,
                                  SoftNavigationOutcome::kNoPaint);
  } else if (!context.HasMainModification()) {
    base::UmaHistogramEnumeration(kPageLoadInternalSoftNavigationOutcome,
                                  SoftNavigationOutcome::kNoDomModification);
  }
}

void SoftNavigationHeuristics::SetIsTrackingSoftNavigationHeuristicsOnDocument(
    bool value) const {
  LocalDOMWindow* window = GetSupplementable();
  if (!window) {
    return;
  }
  if (Document* document = window->document()) {
    document->SetIsTrackingSoftNavigationHeuristics(value);
  }
}

void SoftNavigationHeuristics::ResetHeuristic() {
  // Reset previously seen indicators and task IDs.
  potential_soft_navigations_.clear();
  last_detected_soft_navigation_ = nullptr;
  active_interaction_context_ = nullptr;
  SetIsTrackingSoftNavigationHeuristicsOnDocument(false);
  did_commit_previous_paints_ = false;
  paint_conditions_met_ = false;
  softnav_painted_area_ = 0;
}

SoftNavigationContext*
SoftNavigationHeuristics::GetSoftNavigationContextForCurrentTask() {
  if (potential_soft_navigations_.empty()) {
    return nullptr;
  }
  auto* tracker = scheduler::TaskAttributionTracker::From(
      GetSupplementable()->GetIsolate());
  // The `tracker` must exist if `potential_soft_navigations_` is non-empty.
  CHECK(tracker);
  auto* task_state = tracker->RunningTask();
  if (!task_state) {
    return nullptr;
  }
  SoftNavigationContext* context =
      task_state ? task_state->GetSoftNavigationContext() : nullptr;
  // `task_state` can have null `context` in tests. `context` can be non-null
  // but not in `potential_soft_navigations_` if the heuristic was reset, e.g.
  // if `context` was already considered a soft navigation. In that case, return
  // null.
  if (!context || !potential_soft_navigations_.Contains(context)) {
    return nullptr;
  }
  return context;
}

std::optional<scheduler::TaskAttributionId>
SoftNavigationHeuristics::AsyncSameDocumentNavigationStarted() {
  auto* tracker = scheduler::TaskAttributionTracker::From(
      GetSupplementable()->GetIsolate());
  // `tracker` will be null if TaskAttributionInfrastructureDisabledForTesting
  // is enabled.
  if (!tracker) {
    return std::nullopt;
  }
  scheduler::TaskAttributionInfo* task_state = tracker->RunningTask();
  SoftNavigationContext* context =
      task_state ? task_state->GetSoftNavigationContext() : nullptr;
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("loading"),
               "SoftNavigationHeuristics::AsyncSameDocumentNavigationStarted",
               "has_context", !!context);
  if (context) {
    tracker->AddSameDocumentNavigationTask(task_state);
  }
  return context ? std::optional<scheduler::TaskAttributionId>(task_state->Id())
                 : std::nullopt;
}

void SoftNavigationHeuristics::SameDocumentNavigationCommitted(
    const String& url,
    SoftNavigationContext* context) {
  TRACE_EVENT2(TRACE_DISABLED_BY_DEFAULT("loading"),
               "SoftNavigationHeuristics::SameDocumentNavigationCommitted",
               "url", url, "has_context", !!context);
  if (context) {
    if (potential_soft_navigations_.Contains(context)) {
      context->SetUrl(url);
      EmitSoftNavigationEntryIfAllConditionsMet(context);
    }
  } else {
    base::UmaHistogramEnumeration(
        kPageLoadInternalSoftNavigationOutcome,
        SoftNavigationOutcome::kNoSoftNavContextDuringUrlChange);
  }
}

bool SoftNavigationHeuristics::ModifiedDOM() {
  SoftNavigationContext* context = GetSoftNavigationContextForCurrentTask();
  if (context) {
    context->MarkMainModification();
    EmitSoftNavigationEntryIfAllConditionsMet(context);
  }
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("loading"),
               "SoftNavigationHeuristics::ModifiedDOM", "has_context",
               !!context);
  return !!context;
}

void SoftNavigationHeuristics::EmitSoftNavigationEntryIfAllConditionsMet(
    SoftNavigationContext* context) {
  // If there's an `EventScope` on the stack, hold off checking to avoid
  // clearing state while it's in use.
  if (has_active_event_scope_) {
    return;
  }

  LocalFrame* frame = GetLocalFrameIfNotDetached();
  // TODO(crbug.com/1510706): See if we need to add `paint_conditions_met_` back
  // into this condition.
  if (!context || !context->IsSoftNavigation() ||
      context->UserInteractionTimestamp().is_null() || !frame ||
      !frame->IsOutermostMainFrame()) {
    return;
  }
  last_detected_soft_navigation_ = context;

  LocalDOMWindow* window = GetSupplementable();
  ++soft_navigation_count_;
  window->GenerateNewNavigationId();
  auto* performance = DOMWindowPerformance::performance(*window);
  performance->AddSoftNavigationEntry(AtomicString(context->Url()),
                                      context->UserInteractionTimestamp());

  CommitPreviousPaints(frame);

  LogAndTraceDetectedSoftNavigation(frame, window, *context);
  ReportSoftNavigationToMetrics(frame, context);
  ResetHeuristic();
}

// This is called from Text/ImagePaintTimingDetector when a paint is recorded
// there.
void SoftNavigationHeuristics::RecordPaint(
    LocalFrame* frame,
    uint64_t painted_area,
    bool is_modified_by_soft_navigation) {
  if (potential_soft_navigations_.empty()) {
    // We aren't measuring a soft-nav so we can just exit.
    return;
  }

  if (!is_modified_by_soft_navigation) {
    return;
  }

  softnav_painted_area_ += painted_area;

  uint64_t required_paint_area = CalculateRequiredPaintArea();

  if (required_paint_area == 0) {
    return;
  }

  bool is_above_threshold = (softnav_painted_area_ > required_paint_area);

  TRACE_EVENT_INSTANT(
      TRACE_DISABLED_BY_DEFAULT("loading"),
      "SoftNavigationHeuristics_RecordPaint", "softnav_painted_area",
      softnav_painted_area_, "required_paint_area", required_paint_area, "url",
      (last_detected_soft_navigation_ ? last_detected_soft_navigation_->Url()
                                      : ""),
      "is_above_threshold", is_above_threshold);

  // TODO(crbug.com/1510706): GC between DOM modification and paint could cause
  // `last_detected_soft_navigation_` to be cleared, preventing the entry from
  // being emitted if `paint_conditions_met_` wasn't set but will be in the
  // subsequent paint. This problem existed in task attribution v1 as well since
  // the heuristic is reset when `potential_soft_navigations_` becomes empty.
  if (is_above_threshold) {
    paint_conditions_met_ = true;
    EmitSoftNavigationEntryIfAllConditionsMet(
        last_detected_soft_navigation_.Get());
  }
}

void SoftNavigationHeuristics::ReportSoftNavigationToMetrics(
    LocalFrame* frame,
    SoftNavigationContext* context) const {
  auto* loader = frame->Loader().GetDocumentLoader();

  if (!loader) {
    return;
  }

  CHECK(!context->UserInteractionTimestamp().is_null());
  auto soft_navigation_start_time =
      loader->GetTiming().MonotonicTimeToPseudoWallTime(
          context->UserInteractionTimestamp());

  LocalDOMWindow* window = GetSupplementable();

  blink::SoftNavigationMetrics metrics = {soft_navigation_count_,
                                          soft_navigation_start_time,
                                          window->GetNavigationId().Utf8()};

  if (LocalFrameClient* frame_client = frame->Client()) {
    // This notifies UKM about this soft navigation.
    frame_client->DidObserveSoftNavigation(metrics);
  }

  // Count "successful soft nav" in histogram
  base::UmaHistogramEnumeration(kPageLoadInternalSoftNavigationOutcome,
                                SoftNavigationOutcome::kSoftNavigationDetected);
}

void SoftNavigationHeuristics::ResetPaintsIfNeeded() {
  LocalFrame* frame = GetLocalFrameIfNotDetached();
  if (!frame || !frame->IsOutermostMainFrame()) {
    return;
  }
  LocalFrameView* local_frame_view = frame->View();
  CHECK(local_frame_view);
  LocalDOMWindow* window = GetSupplementable();
  if (RuntimeEnabledFeatures::SoftNavigationHeuristicsEnabled(window)) {
    if (Document* document = window->document();
        document &&
        RuntimeEnabledFeatures::SoftNavigationHeuristicsExposeFPAndFCPEnabled(
            window)) {
      PaintTiming::From(*document).ResetFirstPaintAndFCP();
    }
    local_frame_view->GetPaintTimingDetector().RestartRecordingLCP();
  }

  local_frame_view->GetPaintTimingDetector().RestartRecordingLCPToUkm();
}

// Once all the soft navigation conditions are met (verified in
// `EmitSoftNavigationEntryIfAllConditionsMet()`), the previous paints are
// committed, to make sure accumulated FP, FCP and LCP entries are properly
// fired.
void SoftNavigationHeuristics::CommitPreviousPaints(LocalFrame* frame) {
  CHECK(frame && frame->IsOutermostMainFrame());
  LocalDOMWindow* window = GetSupplementable();
  if (!did_commit_previous_paints_) {
    LocalFrameView* local_frame_view = frame->View();

    CHECK(local_frame_view);

    local_frame_view->GetPaintTimingDetector().SoftNavigationDetected(window);
    if (RuntimeEnabledFeatures::SoftNavigationHeuristicsExposeFPAndFCPEnabled(
            window)) {
      PaintTiming::From(*window->document()).SoftNavigationDetected();
    }

    did_commit_previous_paints_ = true;
  }
}

void SoftNavigationHeuristics::Trace(Visitor* visitor) const {
  Supplement<LocalDOMWindow>::Trace(visitor);
  visitor->Trace(last_detected_soft_navigation_);
  visitor->Trace(active_interaction_context_);
  // Register a custom weak callback, which runs after processing weakness for
  // the container. This allows us to observe the collection becoming empty
  // without needing to observe individual element disposal.
  visitor->RegisterWeakCallbackMethod<
      SoftNavigationHeuristics,
      &SoftNavigationHeuristics::ProcessCustomWeakness>(this);
}

void SoftNavigationHeuristics::OnCreateTaskScope(
    scheduler::TaskAttributionInfo& task_state) {
  CHECK(active_interaction_context_);
  // A task scope can be created without a `SoftNavigationContext` or one that
  // differs from the one associated with the current `EventScope` if, for
  // example, a previously created and awaited promise is resolved in an event
  // handler.
  if (task_state.GetSoftNavigationContext() !=
      active_interaction_context_.Get()) {
    return;
  }

  // TODO(crbug.com/40942324): Replace task_id with either an id for the
  // `SoftNavigationContext` or a serialized version of the object.
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("loading"),
               "SoftNavigationHeuristics::OnCreateTaskScope", "task_id",
               task_state.Id().value());
  // This is invoked when executing a callback with an active `EventScope`,
  // which happens for click and keyboard input events, as well as
  // user-initiated navigation and popstate events. Running such an event
  // listener "activates" the `SoftNavigationContext` as a candidate soft
  // navigation.
  initial_interaction_encountered_ = true;
  SetIsTrackingSoftNavigationHeuristicsOnDocument(true);
}

void SoftNavigationHeuristics::ProcessCustomWeakness(
    const LivenessBroker& info) {
  if (potential_soft_navigations_.empty()) {
    return;
  }
  // When all the soft navigation tasks were garbage collected, that means that
  // all their descendant tasks are done, and there's no need to continue
  // searching for soft navigation signals, at least not until the next user
  // interaction.
  //
  // Note: This is not allowed to do Oilpan allocations. If that's needed, this
  // can schedule a task or microtask to reset the heuristic.
  Vector<UntracedMember<SoftNavigationContext>> dead_contexts;
  for (const auto& context : potential_soft_navigations_) {
    if (!info.IsHeapObjectAlive(context)) {
      RecordUmaForNonSoftNavigationInteraction(*context.Get());
      dead_contexts.push_back(context);
    }
  }
  potential_soft_navigations_.RemoveAll(dead_contexts);
  if (potential_soft_navigations_.empty()) {
    CHECK(!active_interaction_context_);
    ResetHeuristic();
  }
}

LocalFrame* SoftNavigationHeuristics::GetLocalFrameIfNotDetached() const {
  LocalDOMWindow* window = GetSupplementable();
  return window->IsCurrentlyDisplayedInFrame() ? window->GetFrame() : nullptr;
}

SoftNavigationHeuristics::EventScope SoftNavigationHeuristics::CreateEventScope(
    EventScope::Type type,
    ScriptState* script_state) {
  if (!has_active_event_scope_) {
    // Create a new `SoftNavigationContext`, which represents a candidate soft
    // navigation interaction. This context is propagated to all descendant
    // tasks created within this or any nested `EventScope`.
    //
    // For non-"new interactions", we want to reuse the context from the initial
    // "new interaction" (i.e. keydown), but will create a new one if that has
    // been cleared, which can happen in tests.
    if (IsInteractionStart(type) || !active_interaction_context_) {
      active_interaction_context_ =
          MakeGarbageCollected<SoftNavigationContext>();
      potential_soft_navigations_.insert(active_interaction_context_.Get());
    }

    // Ensure that paints would be reset, so that paint recording would continue
    // despite the user interaction.
    ResetPaintsIfNeeded();
  }
  CHECK(active_interaction_context_.Get());

  auto* tracker = scheduler::TaskAttributionTracker::From(
      GetSupplementable()->GetIsolate());
  bool is_nested = std::exchange(has_active_event_scope_, true);
  // `tracker` will be null if TaskAttributionInfrastructureDisabledForTesting
  // is enabled.
  if (!tracker) {
    return SoftNavigationHeuristics::EventScope(this,
                                                /*observer_scope=*/std::nullopt,
                                                /*task_scope=*/std::nullopt,
                                                type, is_nested);
  }
  return SoftNavigationHeuristics::EventScope(
      this, tracker->RegisterObserver(this),
      tracker->CreateTaskScope(script_state, active_interaction_context_.Get()),
      type, is_nested);
}

std::optional<SoftNavigationHeuristics::EventScope>
SoftNavigationHeuristics::MaybeCreateEventScopeForEvent(const Event& event) {
  std::optional<EventScope::Type> type = EventScopeTypeFromEvent(event);
  if (!type) {
    return std::nullopt;
  }
  auto* script_state = ToScriptStateForMainWorld(GetSupplementable());
  if (!script_state) {
    return std::nullopt;
  }
  return CreateEventScope(*type, script_state);
}

void SoftNavigationHeuristics::OnSoftNavigationEventScopeDestroyed(
    const EventScope& event_scope) {
  // Set the start time to the end of event processing. In case of nested event
  // scopes, we want this to be the end of the nested `navigate()` event
  // handler.
  CHECK(active_interaction_context_);
  if (active_interaction_context_->UserInteractionTimestamp().is_null()) {
    active_interaction_context_->SetUserInteractionTimestamp(
        base::TimeTicks::Now());
  }

  has_active_event_scope_ = event_scope.is_nested_;
  if (has_active_event_scope_) {
    return;
  }

  EmitSoftNavigationEntryIfAllConditionsMet(active_interaction_context_.Get());
  // For keyboard events, we can't clear `active_interaction_context_` until
  // keyup because keypress and keyup need to reuse the keydown context.
  if (IsInteractionEnd(event_scope.type_)) {
    active_interaction_context_ = nullptr;
  }

  // TODO(crbug.com/1502640): We should also reset the heuristic a few seconds
  // after a click event handler is done, to reduce potential cycles.
}

uint64_t SoftNavigationHeuristics::CalculateRequiredPaintArea() const {
  LocalDOMWindow* window = GetSupplementable();
  CHECK(window);
  LocalFrame* frame = window->GetFrame();
  CHECK(frame);
  LocalFrameView* local_frame_view = frame->View();
  CHECK(local_frame_view);

  constexpr int kSoftNavigationPaintAreaPercentage = 2;
  uint64_t viewport_area = local_frame_view->GetLayoutSize().Area64();
  uint64_t required_paint_area =
      (viewport_area * kSoftNavigationPaintAreaPercentage) / 100;
  CHECK_GE(required_paint_area, 0u);
  return required_paint_area;
}

// SoftNavigationHeuristics::EventScope implementation
// ///////////////////////////////////////////
SoftNavigationHeuristics::EventScope::EventScope(
    SoftNavigationHeuristics* heuristics,
    std::optional<ObserverScope> observer_scope,
    std::optional<TaskScope> task_scope,
    Type type,
    bool is_nested)
    : heuristics_(heuristics),
      observer_scope_(std::move(observer_scope)),
      task_scope_(std::move(task_scope)),
      type_(type),
      is_nested_(is_nested) {
  CHECK(heuristics_);
}

SoftNavigationHeuristics::EventScope::EventScope(EventScope&& other)
    : heuristics_(std::exchange(other.heuristics_, nullptr)),
      observer_scope_(std::move(other.observer_scope_)),
      task_scope_(std::move(other.task_scope_)),
      type_(other.type_),
      is_nested_(other.is_nested_) {}

SoftNavigationHeuristics::EventScope&
SoftNavigationHeuristics::EventScope::operator=(EventScope&& other) {
  heuristics_ = std::exchange(other.heuristics_, nullptr);
  observer_scope_ = std::move(other.observer_scope_);
  task_scope_ = std::move(other.task_scope_);
  type_ = other.type_;
  is_nested_ = other.is_nested_;
  return *this;
}

SoftNavigationHeuristics::EventScope::~EventScope() {
  if (!heuristics_) {
    return;
  }
  heuristics_->OnSoftNavigationEventScopeDestroyed(*this);
}

}  // namespace blink

"""

```
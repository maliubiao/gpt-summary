Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the comprehensive summary.

**1. Initial Understanding of the Request:**

The request asks for a detailed explanation of the `responsiveness_metrics.cc` file in the Chromium Blink engine. Key aspects to cover include:

* **Functionality:** What does this code *do*?
* **Relationship to Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
* **Logical Reasoning:**  Are there any conditional statements or data transformations that can be analyzed with example inputs and outputs?
* **Common Errors:** What mistakes might developers or users make that could relate to this code?
* **Debugging:** How does user interaction lead to this code being executed?
* **Summary:**  A concise overview of the file's purpose.

**2. First Pass - High-Level Overview (Skimming):**

I started by quickly skimming the code, paying attention to:

* **Includes:**  The included headers (`histogram_functions.h`, `time/time.h`, `trace_event/trace_event.h`, `ukm_builders.h`, `features.h`, `user_interaction_latency.h`, event-related headers, performance-related headers). This gives immediate clues about the file's purpose: collecting metrics, timing events, user interaction tracking, and potentially sending data to UKM (User Keyed Metrics).
* **Class Name:** `ResponsivenessMetrics`. This strongly suggests the file is responsible for measuring and tracking the responsiveness of web pages.
* **Key Member Variables:**  `window_performance_`, `pointer_flush_timer_`, `contextmenu_flush_timer_`, `composition_end_flush_timer_`, `current_interaction_id_for_event_timing_`, `pointer_id_entry_map_`, `key_code_to_interaction_info_map_`, `sequence_based_keyboard_interaction_info_`. These variables hint at how responsiveness is measured (timers, tracking pointer/keyboard events, managing interaction IDs).
* **Key Methods:**  `RecordUserInteractionUKM`, `SetPointerIdAndRecordLatency`, `SetKeyIdAndRecordLatency`, `FlushPointerup`, `FlushKeydown`, `FlushSequenceBasedKeyboardEvents`. These reveal core functionalities: recording user interactions, handling pointer and keyboard events, and flushing (processing and sending) collected data.
* **Histograms and UKM:** The presence of `base::UmaHistogram...` and `ukm::builders::Responsiveness_UserInteraction` clearly indicates metric collection and reporting.

**3. Deeper Dive - Analyzing Key Functions and Logic:**

Next, I focused on understanding the core methods and the logic within them:

* **`RecordUserInteractionUKM`:** This function takes timestamps of events within an interaction and records them to UKM and histograms. It also interacts with the `LocalDOMWindow` to notify the client about user interactions. The logic for finding the "longest event" within an interaction is important.
* **`SetPointerIdAndRecordLatency`:** This is a complex function handling various pointer events (`pointerdown`, `pointerup`, `pointercancel`, `contextmenu`, `click`). It uses a state machine approach (implicitly) to group pointer events into interactions. The `pointer_id_entry_map_` is crucial for tracking pointer events and associating them. The handling of "orphan" `pointerup` events is also noteworthy.
* **`SetKeyIdAndRecordLatency`:**  Similar to the pointer event handler, this deals with keyboard events (`keydown`, `keyup`, `keypress`, `compositionstart`, `compositionend`, `compositionupdate`, `input`). It manages the state of text composition using `composition_state_` and uses `key_code_to_interaction_info_map_` to associate `keydown` and `keyup` events. The handling of IME (Input Method Editor) interactions is evident.
* **Flush Methods:**  The `FlushPointerup`, `FlushKeydown`, and `FlushSequenceBasedKeyboardEvents` methods are responsible for processing the collected event data and potentially sending it to UKM when an interaction is considered complete or when a timer expires. This helps handle cases where events might be missed (e.g., a `pointerup` is not received).

**4. Identifying Relationships with Web Technologies:**

Based on the function names and the events being tracked, I could establish connections to:

* **JavaScript:**  Event listeners in JavaScript trigger the events that this code processes (e.g., `click`, `keydown`, `pointerdown`). The `PerformanceEventTiming` API, which this code interacts with, is exposed to JavaScript.
* **HTML:**  User interactions with HTML elements (buttons, links, input fields) generate the events being tracked.
* **CSS:** While not directly interacting, CSS can influence the timing of events (e.g., animations or transitions might delay event processing).

**5. Considering Logical Reasoning (Hypothetical Inputs/Outputs):**

For instance, in `SetPointerIdAndRecordLatency`, if a `pointerdown` event occurs, a new entry is created in `pointer_id_entry_map_`. If a subsequent `pointerup` with the same ID arrives, the timestamps are collected, and the interaction is recorded. If a `pointercancel` arrives instead, the interaction is aborted. Thinking through these scenarios helps understand the code's behavior.

**6. Identifying Potential User/Programming Errors:**

* **User Errors:**  Rapid, unintended clicks or key presses could lead to multiple interactions being recorded. Holding down a key might not always generate a corresponding `keyup` in some scenarios, which this code seems to handle.
* **Programming Errors:** Incorrectly implemented event handlers in JavaScript might lead to events not being fired or firing in unexpected sequences, potentially affecting the metrics collected by this code.

**7. Tracing User Operations:**

I considered how a user action (like clicking a button) translates to the execution of this code:

1. User clicks an element.
2. Browser receives the raw input event.
3. The input event is processed and dispatched as a `pointerdown` event (or similar).
4. The Blink rendering engine's event handling mechanism routes the event.
5. Code within `SetPointerIdAndRecordLatency` is executed for the `pointerdown` event.
6. If the click is completed, a `pointerup` and potentially a `click` event follow, leading to further execution within `SetPointerIdAndRecordLatency`.
7. Finally, `RecordUserInteractionUKM` is called to record the interaction.

**8. Structuring the Output:**

Finally, I organized the information into the requested sections: functionality, relationship to web technologies, logical reasoning examples, potential errors, debugging clues, and a summary. I used clear and concise language, providing specific examples where possible. I also paid attention to the prompt's request for numbered parts.

This iterative process of skimming, deeper analysis, connecting to web technologies, considering edge cases, and structuring the output allows for a comprehensive understanding and explanation of the given code snippet.
这是对 `blink/renderer/core/timing/responsiveness_metrics.cc` 文件功能的归纳总结，以及与 JavaScript、HTML、CSS 的关系、逻辑推理、常见错误和调试线索的说明。

**功能归纳（第 1 部分涵盖内容）:**

`responsiveness_metrics.cc` 文件的主要功能是**收集和记录用户交互的响应性指标**。它旨在衡量用户与网页的交互（例如点击、键盘输入、拖拽）的延迟和持续时间，并将这些数据用于性能分析和改进。

**具体来说，第 1 部分的功能包括：**

1. **定义和管理用户交互类型:** 它定义了 `UserInteractionType` 枚举，用于区分不同类型的用户交互，例如拖拽、键盘输入和点击/触摸。
2. **记录事件时间戳:** 它维护并使用 `EventTimestamps` 结构来记录用户交互中关键事件（如事件创建、排队到主线程、提交完成、事件结束）的时间戳。
3. **计算交互持续时间:**  它计算用户交互中各个事件的持续时间以及整个交互的总持续时间。
4. **使用 UKM (User Keyed Metrics) 记录指标:**  它使用 UKM API 将用户交互的持续时间和其他相关信息记录下来，以便进行聚合分析。它还实现了抽样机制，以避免发送过多的 UKM 数据。
5. **使用 UMA (User Metrics Analysis) 记录直方图:** 它使用 UMA API 将用户交互的最大事件持续时间记录到不同的直方图中，按交互类型（所有类型、键盘、点击/触摸、拖拽）进行区分。
6. **生成慢交互到下一次绘制的 Trace Event:** 当检测到交互到下一次绘制的时间超过阈值时，它会生成一个 Trace Event，用于性能调试。
7. **处理 Pointer 事件（部分）：** 它开始处理 Pointer 事件，例如 `pointerdown` 和 `pointerup`，并使用 `pointer_id_entry_map_` 来跟踪 Pointer 事件的状态，以便将它们组合成完整的交互。它还处理了 `contextmenu` 事件，并引入了定时器来处理 `contextmenu` 后可能缺失的 `pointerup` 事件。
8. **处理 Click 事件：** 它处理 `click` 事件，并尝试将其与之前的 `pointerdown` 和 `pointerup` 事件关联起来，以确定完整的交互。它还处理了键盘模拟的点击事件。
9. **维护 Interaction ID:**  它维护一个 `current_interaction_id_for_event_timing_`，并使用递增的策略为每个用户交互分配一个唯一的 ID，用于 `PerformanceEventTiming` API。
10. **处理 Drag 事件 (通过 `NotifyPotentialDrag`)：**  它提供了一个 `NotifyPotentialDrag` 方法，用于标记潜在的拖拽交互。
11. **管理 Flush 定时器:** 它使用了多个定时器 (`pointer_flush_timer_`, `contextmenu_flush_timer_`, `composition_end_flush_timer_`) 来延迟或触发某些操作，例如刷新未完成的 Pointer 或键盘交互。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    * 当 JavaScript 代码中添加了事件监听器（例如 `addEventListener('click', ...)`）并且用户触发了这些事件时，Blink 引擎会捕获这些事件。
    * `responsiveness_metrics.cc` 中的代码会接收到这些事件，并记录它们的时间戳。
    * **举例：** 用户点击一个按钮，JavaScript 的 `click` 事件处理函数开始执行。在 `responsiveness_metrics.cc` 中，`SetPointerIdAndRecordLatency` 函数会被调用来处理相关的 `pointerdown`、`pointerup` 和 `click` 事件，记录它们的发生时间，并最终通过 `RecordUserInteractionUKM` 记录这次点击交互的延迟。
    * **PerformanceEventTiming API:** JavaScript 可以通过 `performance.getEntriesByType("event")` 获取到 `PerformanceEventTiming` 类型的性能条目，其中包含了由该文件设置的 `interactionId` 等信息。

* **HTML:**
    * HTML 结构定义了用户可以与之交互的元素（例如按钮、链接、输入框）。
    * 用户与这些 HTML 元素的交互会触发相应的事件。
    * **举例：**  用户在一个 `<input>` 元素中输入文本。每一个按键操作都会触发 `keydown`、`keypress` (可能) 和 `keyup` 事件。`responsiveness_metrics.cc` 中的 `SetKeyIdAndRecordLatency` 函数会处理这些事件，并将它们关联到一个交互 ID，最终记录键盘输入的响应时间。

* **CSS:**
    * CSS 的动画和过渡效果可能会影响用户交互的感知延迟。
    * 虽然 `responsiveness_metrics.cc` 不直接操作 CSS，但 CSS 渲染导致的延迟会被捕捉到。
    * **举例：**  一个按钮在被点击时有一个 CSS 过渡动画。从用户点击到动画完成并页面做出响应的时间，会被 `responsiveness_metrics.cc` 记录下来，因为这影响了用户的交互体验。

**逻辑推理的假设输入与输出举例说明:**

**假设输入:**

1. 用户在屏幕上点击了一下 (Tap)。
2. 浏览器接收到 `touchstart` 事件，然后是 `touchend` 事件。 (假设映射为 pointerdown 和 pointerup)
3. `SetPointerIdAndRecordLatency` 先接收到 `pointerdown` 事件，`entry->name()` 为 "pointerdown"。
4. `pointer_id` 从事件中提取出来，假设为 123。
5. `pointer_id_entry_map_` 中不存在键为 123 的条目。
6. 创建一个新的 `PointerEntryAndInfo` 对象，包含 `pointerdown` 事件的 `PerformanceEventTiming` 条目和时间戳。
7. 将该对象添加到 `pointer_id_entry_map_` 中，键为 123。
8. `SetPointerIdAndRecordLatency` 接着接收到 `pointerup` 事件，`entry->name()` 为 "pointerup"， `pointer_id` 同样为 123。
9. `pointer_id_entry_map_` 中存在键为 123 的条目。
10. 获取到之前保存的 `PointerEntryAndInfo` 对象。
11. 将 `pointerup` 事件的时间戳添加到该对象的时间戳列表中。
12. 如果满足条件（例如没有正在进行的滚动），生成一个新的 `interactionId`。
13. 调用 `RecordDragTapOrClickUKM`，记录这次交互的指标。

**输出:**

* `pointer_id_entry_map_` 中会短暂存在一个键为 123 的条目。
* UKM 中会记录一条关于 Tap 或 Click 类型的用户交互的记录，包含交互的持续时间等信息。
* 相关的 UMA 直方图会被更新，反映这次交互的最大事件持续时间。

**用户或编程常见的使用错误举例说明:**

* **用户快速连续点击:**  用户可能会在短时间内进行多次点击，`responsiveness_metrics.cc` 会将这些点击作为多个独立的交互进行记录。如果网站没有针对快速点击进行优化，可能会导致性能问题。
* **JavaScript 代码中阻止了主线程:** 如果 JavaScript 代码中存在耗时的同步操作，会导致事件处理延迟，这会被 `responsiveness_metrics.cc` 捕捉到，表现为交互持续时间过长。例如，一个执行复杂计算的 JavaScript 函数在事件处理函数中同步执行，会阻塞后续事件的处理。
* **误用或不理解 `PerformanceEventTiming` API:**  开发者可能会错误地使用或解释 `PerformanceEventTiming` API 提供的信息，例如错误地假设 `interactionId` 可以用来精确计数交互次数，而实际上规范建议用户代理可以以不连续的方式递增这个值。
* **事件监听器绑定过多或处理逻辑复杂:**  过多的事件监听器或复杂的事件处理逻辑会导致事件处理延迟，从而影响响应性指标。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户操作:** 用户点击了网页上的一个链接或按钮。
2. **浏览器事件捕获:** 浏览器接收到用户的物理输入信号（例如鼠标按下）。
3. **事件分发:** 浏览器将物理输入信号转换为 DOM 事件，例如 `mousedown` 或 `pointerdown`。
4. **Blink 事件处理:** Blink 引擎接收到这些 DOM 事件。
5. **`EventTarget` 派发事件:** 事件被派发到目标元素。
6. **`PerformanceMonitor::HandleEvent`:**  性能监控模块可能会拦截事件以记录开始时间。
7. **`LocalFrameView::ProcessMouseEvent` 或 `LocalFrameView::ProcessKeyboardEvent`:**  取决于事件类型，相应的处理函数会被调用。
8. **`EventHandler::dispatchEvent`:** 事件被派发到注册的事件监听器。
9. **`ResponsivenessMetrics::SetPointerIdAndRecordLatency` 或 `ResponsivenessMetrics::SetKeyIdAndRecordLatency`:**  在事件处理的某个阶段，`PerformanceEventTiming` 对象会被创建或更新，并且这些函数会被调用来记录事件的时间戳并关联到用户交互。
10. **`RecordUserInteractionUKM` (最终):** 当一个完整的用户交互结束时（例如 `pointerup` 或 `keyup`），`RecordUserInteractionUKM` 会被调用来记录这次交互的性能指标。

**调试线索:**

* **Trace Event:** 可以通过 Chrome 的 tracing 工具 (chrome://tracing) 记录 "latency" 类别下的 "SlowInteractionToNextPaint" 事件，以查看哪些交互被认为是慢速的。
* **Performance 面板:** Chrome 开发者工具的 Performance 面板可以显示详细的事件时间线，包括用户交互事件的处理时间。
* **`PerformanceEventTiming` API:**  在控制台中使用 `performance.getEntriesByType("event")` 可以查看 `PerformanceEventTiming` 条目，检查 `interactionId` 和其他相关信息。
* **UKM 数据:** 如果开启了 UKM 收集，可以在 Chrome 的内部页面（例如 `chrome://ukm`）中查看相关的 `Responsiveness.UserInteraction` 数据。
* **断点调试:**  可以在 `responsiveness_metrics.cc` 中的关键函数（例如 `SetPointerIdAndRecordLatency`、`RecordUserInteractionUKM`）设置断点，逐步跟踪事件的处理流程，查看变量的值，以理解交互是如何被记录的。

总而言之，`responsiveness_metrics.cc` 的第 1 部分奠定了收集用户交互响应性指标的基础，涵盖了 Pointer 和部分键盘事件的处理，并提供了将这些指标记录到 UKM 和 UMA 的机制。它与 JavaScript、HTML 和 CSS 密切相关，因为它的功能是衡量用户与这些技术构建的网页的交互性能。

Prompt: 
```
这是目录为blink/renderer/core/timing/responsiveness_metrics.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/responsiveness_metrics.h"

#include <memory>

#include "base/metrics/histogram_functions.h"
#include "base/rand_util.h"
#include "base/strings/strcat.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/trace_id_helper.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/responsiveness_metrics/user_interaction_latency.h"
#include "third_party/blink/renderer/core/dom/dom_high_res_time_stamp.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/pointer_event_factory.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/core/timing/performance_event_timing.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/perfetto/include/perfetto/tracing/track.h"

namespace blink {

namespace {
// Minimum potentially generated value for UKM sampling.
constexpr int kMinValueForSampling = 1;
// Maximum potentially generated value for UKM sampling.
constexpr int kMaxValueForSampling = 100;
// UKM sampling rate. The sampling strategy is 1/N.
constexpr int kUkmSamplingRate = 10;
// Minimum potential value for the first Interaction ID.
constexpr uint32_t kMinFirstInteractionID = 100;
// Maximum potential value for the first Interaction ID.
constexpr uint32_t kMaxFirstInteractionID = 10000;
// Interaction ID increment. We increase this value by an integer greater than 1
// to discourage developers from using the value to 'count' the number of user
// interactions. This is consistent with the spec, which allows the increasing
// the user interaction value by a small number chosen by the user agent.
constexpr uint32_t kInteractionIdIncrement = 7;
// The length of the timer to flush entries from the time pointerup occurs.
constexpr base::TimeDelta kFlushTimerLength = base::Seconds(1);
// The name for the histogram which records interaction timings, and the names
// of the variants for keyboard, click/tap, and drag interactions.
const char kHistogramMaxEventDuration[] =
    "Blink.Responsiveness.UserInteraction.MaxEventDuration";
const char kHistogramAllTypes[] = ".AllTypes";
const char kHistogramKeyboard[] = ".Keyboard";
const char kHistogramTapOrClick[] = ".TapOrClick";
const char kHistogramDrag[] = ".Drag";

constexpr char kSlowInteractionToNextPaintTraceEventCategory[] = "latency";
constexpr char kSlowInteractionToNextPaintTraceEventName[] =
    "SlowInteractionToNextPaint";

const char kPageLoadInternalEventTimingClickInteractionEvents[] =
    "PageLoad.Internal.EventTiming.ClickInteractionEvents";

// These values are logged to UMA. Please keep in sync with
// "EventTimingClickInteractionEvents" in tools/metrics/histograms/enums.xml.
// LINT.IfChange
enum ClickInteractionEvents {
  kClickDetected = 0,
  kPointerClickWithPointerdownAndPointerup = 1,
  kPointerClickWithMissingPointerdownOnly = 2,
  kPointerClickWithMissingPointerupOnly = 3,
  kPointerClickWithMissingPointerdownAndPointerup = 4,
  kPointerClickPointerIdDifferFromLastPointerIdAndPointerIdExistInMap = 5,
  kPointerClickPointerIdDifferFromLastPointerIdAndOnlyLastPointerIdInMap = 6,
  kPointerClickPointerIdDifferFromLastPointerIdAndNeitherInMap = 7,
  kKeyboardClick = 8,
  kMaxValue = kKeyboardClick,
};
// LINT.ThenChange(/tools/metrics/histograms/enums.xml:EventTimingClickInteractionEvents)

void EmitSlowInteractionToNextPaintTraceEvent(
    const ResponsivenessMetrics::EventTimestamps& event) {
  uint64_t trace_id = base::trace_event::GetNextGlobalTraceId();
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN_WITH_TIMESTAMP0(
      kSlowInteractionToNextPaintTraceEventCategory,
      kSlowInteractionToNextPaintTraceEventName, trace_id, event.creation_time);
  TRACE_EVENT_NESTABLE_ASYNC_END_WITH_TIMESTAMP0(
      kSlowInteractionToNextPaintTraceEventCategory,
      kSlowInteractionToNextPaintTraceEventName, trace_id, event.end_time);
}

// Returns the longest event in `timestamps`.
ResponsivenessMetrics::EventTimestamps LongestEvent(
    const WTF::Vector<ResponsivenessMetrics::EventTimestamps>& events) {
  DCHECK(events.size());
  return *std::max_element(
      events.begin(), events.end(),
      [](const ResponsivenessMetrics::EventTimestamps& left,
         const ResponsivenessMetrics::EventTimestamps& right) {
        return left.duration() < right.duration();
      });
}

base::TimeDelta TotalEventDuration(
    // timestamps is sorted by the start_time of EventTimestamps.
    const WTF::Vector<ResponsivenessMetrics::EventTimestamps>& timestamps) {
  DCHECK(timestamps.size());
  // TODO(crbug.com/1229668): Once the event timestamp bug is fixed, add a
  // DCHECK(IsSorted) here.
  base::TimeDelta total_duration =
      timestamps[0].end_time - timestamps[0].creation_time;
  base::TimeTicks current_end_time = timestamps[0].end_time;
  for (WTF::wtf_size_t i = 1; i < timestamps.size(); ++i) {
    total_duration += timestamps[i].end_time - timestamps[i].creation_time;
    if (timestamps[i].creation_time < current_end_time) {
      total_duration -= std::min(current_end_time, timestamps[i].end_time) -
                        timestamps[i].creation_time;
    }
    current_end_time = std::max(current_end_time, timestamps[i].end_time);
  }
  return total_duration;
}

WTF::String InteractionTypeToString(UserInteractionType interaction_type) {
  switch (interaction_type) {
    case UserInteractionType::kDrag:
      return "drag";
    case UserInteractionType::kKeyboard:
      return "keyboard";
    case UserInteractionType::kTapOrClick:
      return "tapOrClick";
    default:
      NOTREACHED();
  }
}

std::unique_ptr<TracedValue> UserInteractionTraceData(
    base::TimeDelta max_duration,
    base::TimeDelta total_duration,
    UserInteractionType interaction_type) {
  auto traced_value = std::make_unique<TracedValue>();
  traced_value->SetInteger("maxDuration",
                           static_cast<int>(max_duration.InMilliseconds()));
  traced_value->SetInteger("totalDuration",
                           static_cast<int>(total_duration.InMilliseconds()));
  traced_value->SetString("interactionType",
                          InteractionTypeToString(interaction_type));
  return traced_value;
}

void LogResponsivenessHistogram(base::TimeDelta max_event_duration,
                                const char* suffix) {
  base::UmaHistogramCustomTimes(
      base::StrCat({kHistogramMaxEventDuration, suffix}), max_event_duration,
      base::Milliseconds(1), base::Seconds(60), 50);
}

}  // namespace

ResponsivenessMetrics::ResponsivenessMetrics(
    WindowPerformance* window_performance)
    : window_performance_(window_performance),
      pointer_flush_timer_(window_performance_->task_runner_,
                           this,
                           &ResponsivenessMetrics::FlushPointerTimerFired),
      contextmenu_flush_timer_(
          window_performance_->task_runner_,
          this,
          &ResponsivenessMetrics::ContextmenuFlushTimerFired),
      composition_end_flush_timer_(
          window_performance_->task_runner_,
          this,
          &ResponsivenessMetrics::FlushCompositionEndTimerFired),
      current_interaction_id_for_event_timing_(
          // Follow the spec by choosing a random integer as the initial value
          // to discourage developers from using interactionId to count the
          // number of interactions. See
          // https://wicg.github.io/event-timing/#user-interaction-value.
          base::RandInt(kMinFirstInteractionID, kMaxFirstInteractionID)) {}

ResponsivenessMetrics::~ResponsivenessMetrics() = default;

void ResponsivenessMetrics::RecordUserInteractionUKM(
    LocalDOMWindow* window,
    UserInteractionType interaction_type,
    const WTF::Vector<EventTimestamps>& timestamps,
    uint32_t interaction_offset) {
  if (!window) {
    return;
  }

  for (EventTimestamps timestamp : timestamps) {
    if (timestamp.creation_time == base::TimeTicks()) {
      return;
    }
  }

  EventTimestamps longest_event = LongestEvent(timestamps);
  base::TimeTicks max_event_start = longest_event.creation_time;
  base::TimeTicks max_event_end = longest_event.end_time;
  base::TimeTicks max_event_queued_main_thread =
      longest_event.queued_to_main_thread_time;
  base::TimeTicks max_event_commit_finish = longest_event.commit_finish_time;
  base::TimeDelta max_event_duration = longest_event.duration();
  base::TimeDelta total_event_duration = TotalEventDuration(timestamps);
  // We found some negative values in the data. Before figuring out the root
  // cause, we need this check to avoid sending nonsensical data.
  if (max_event_duration.InMilliseconds() >= 0) {
    window->GetFrame()->Client()->DidObserveUserInteraction(
        max_event_start, max_event_queued_main_thread, max_event_commit_finish,
        max_event_end, interaction_type, interaction_offset);
  }
  TRACE_EVENT2("devtools.timeline", "Responsiveness.Renderer.UserInteraction",
               "data",
               UserInteractionTraceData(max_event_duration,
                                        total_event_duration, interaction_type),
               "frame", GetFrameIdForTracing(window->GetFrame()));

  EmitInteractionToNextPaintTraceEvent(longest_event, interaction_type,
                                       total_event_duration);
  // Emit a trace event when "interaction to next paint" is considered "slow"
  // according to RAIL guidelines (web.dev/rail).
  constexpr base::TimeDelta kSlowInteractionToNextPaintThreshold =
      base::Milliseconds(100);
  if (longest_event.duration() > kSlowInteractionToNextPaintThreshold) {
    EmitSlowInteractionToNextPaintTraceEvent(longest_event);
  }

  LogResponsivenessHistogram(max_event_duration, kHistogramAllTypes);
  switch (interaction_type) {
    case UserInteractionType::kKeyboard:
      LogResponsivenessHistogram(max_event_duration, kHistogramKeyboard);
      break;
    case UserInteractionType::kTapOrClick:
      LogResponsivenessHistogram(max_event_duration, kHistogramTapOrClick);
      break;
    case UserInteractionType::kDrag:
      LogResponsivenessHistogram(max_event_duration, kHistogramDrag);
      break;
  }

  ukm::UkmRecorder* ukm_recorder = window->UkmRecorder();
  ukm::SourceId source_id = window->UkmSourceID();
  if (source_id != ukm::kInvalidSourceId &&
      (!sampling_ || base::RandInt(kMinValueForSampling,
                                   kMaxValueForSampling) <= kUkmSamplingRate)) {
    ukm::builders::Responsiveness_UserInteraction(source_id)
        .SetInteractionType(static_cast<int>(interaction_type))
        .SetMaxEventDuration(max_event_duration.InMilliseconds())
        .SetTotalEventDuration(total_event_duration.InMilliseconds())
        .Record(ukm_recorder);
  }
}

void ResponsivenessMetrics::NotifyPotentialDrag(PointerId pointer_id) {
  if (pointer_id_entry_map_.Contains(pointer_id)) {
    pointer_id_entry_map_.at(pointer_id)->SetIsDrag();
  }
}

void ResponsivenessMetrics::RecordDragTapOrClickUKM(
    LocalDOMWindow* window,
    PointerEntryAndInfo& pointer_info) {
  DCHECK(pointer_info.GetEntry());
  // Early return if all we got was a pointerdown.
  if (pointer_info.GetEntry()->name() == event_type_names::kPointerdown &&
      pointer_info.GetTimeStamps().size() == 1u) {
    return;
  }
  if (pointer_info.GetEntry()->interactionId() == 0u) {
    return;
  }
  RecordUserInteractionUKM(window,
                           pointer_info.IsDrag()
                               ? UserInteractionType::kDrag
                               : UserInteractionType::kTapOrClick,
                           pointer_info.GetTimeStamps(),
                           pointer_info.GetEntry()->interactionOffset());
}

// Event timing pointer events processing
//
// See also ./Pointer_interaction_state_machine.md
// (https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/core/timing/Pointer_interaction_state_machine.md)
// to help understand the logic below that how event timing group up pointer
// events as interactions.
bool ResponsivenessMetrics::SetPointerIdAndRecordLatency(
    PerformanceEventTiming* entry,
    EventTimestamps event_timestamps) {
  const AtomicString& event_type = entry->name();
  auto pointer_id = entry->GetEventTimingReportingInfo()->pointer_id.value();
  auto* pointer_info = pointer_id_entry_map_.Contains(pointer_id)
                           ? pointer_id_entry_map_.at(pointer_id)
                           : nullptr;
  LocalDOMWindow* window = window_performance_->DomWindow();
  if (event_type == event_type_names::kPointercancel && pointer_info) {
    NotifyPointerdown(pointer_info->GetEntry());
    // The pointer id of the pointerdown is no longer needed.
    pointer_id_entry_map_.erase(
        entry->GetEventTimingReportingInfo()->pointer_id.value());
    last_pointer_id_ = std::nullopt;
  } else if (event_type == event_type_names::kContextmenu) {
    // Start a timer to flush event timing entries when times up. On receiving a
    // new pointerup or pointerdown, the timer will be canceled and entries will
    // be flushed immediately.
    contextmenu_flush_timer_.StartOneShot(kFlushTimerLength, FROM_HERE);
  } else if (event_type == event_type_names::kPointerdown) {
    // If we were waiting for matching pointerup/keyup after a contextmenu, they
    // won't show up at this point.
    if (contextmenu_flush_timer_.IsActive()) {
      contextmenu_flush_timer_.Stop();
      FlushPointerdownAndPointerup();
      FlushKeydown();
    } else {
      if (pointer_info) {
        // Flush the existing entry. We are starting a new interaction.
        RecordDragTapOrClickUKM(window, *pointer_info);
        NotifyPointerdown(pointer_info->GetEntry());
        pointer_id_entry_map_.erase(pointer_id);
      }
      // Any existing pointerup in the map cannot fire a click.
      FlushPointerup();
    }

    pointer_id_entry_map_.Set(
        pointer_id, PointerEntryAndInfo::Create(entry, event_timestamps));

    // Waiting to see if we get a pointercancel or pointerup.
    last_pointer_id_ = pointer_id;
    return false;
  } else if (event_type == event_type_names::kPointerup) {
    if (contextmenu_flush_timer_.IsActive()) {
      contextmenu_flush_timer_.Stop();
    }

    // Any existing pointerup in the map cannot fire a click.
    FlushPointerup();

    is_last_pointerup_orphan_ = false;
    last_pointer_id_ = pointer_id;

    // Platforms like Android would create ever-increasing pointer_id for
    // interactions, whereas platforms like linux could reuse the same id for
    // different interactions. So resetting pointer_info here if it's flushed.
    if (!pointer_id_entry_map_.Contains(pointer_id)) {
      is_last_pointerup_orphan_ = true;

      // Reset if pointer_info got flushed.
      pointer_info = nullptr;

      // Early exit if it's an orphan pointerup, not treating it as an
      // interaction. crbug.com/40935137
      return true;
    }

    // Generate a new interaction id.
    // Do not generate any interaction id for the events when the scroll is
    // active.
    if (pointer_info && !pointer_info->GetEntry()->HasKnownInteractionID() &&
        !entry->HasKnownInteractionID()) {
      UpdateInteractionId();
      entry->SetInteractionIdAndOffset(GetCurrentInteractionId(),
                                       GetInteractionCount());
    }

    if (pointer_info &&
        pointer_info->GetEntry()->name() == event_type_names::kPointerdown) {
      // Set interaction id and notify the pointer down entry.
      PerformanceEventTiming* pointer_down_entry = pointer_info->GetEntry();
      if (entry->HasKnownInteractionID()) {
        pointer_down_entry->SetInteractionIdAndOffset(
            entry->interactionId(), entry->interactionOffset());
      }
      NotifyPointerdown(pointer_down_entry);
      pointer_info->GetTimeStamps().push_back(event_timestamps);
    } else {
      // There is no matching pointerdown: Set the map using pointerup, in
      // case a click event shows up.
      pointer_id_entry_map_.Set(
          pointer_id, PointerEntryAndInfo::Create(entry, event_timestamps));
    }
    // Start the timer to flush the entry just created later, if needed.
    pointer_flush_timer_.StartOneShot(kFlushTimerLength, FROM_HERE);
  } else if (event_type == event_type_names::kClick) {
    base::UmaHistogramEnumeration(
        kPageLoadInternalEventTimingClickInteractionEvents,
        ClickInteractionEvents::kClickDetected);
    if (pointer_id == PointerEventFactory::kReservedNonPointerId) {
      base::UmaHistogramEnumeration(
          kPageLoadInternalEventTimingClickInteractionEvents,
          ClickInteractionEvents::kKeyboardClick);
    } else if (is_last_pointerup_orphan_) {
      base::UmaHistogramEnumeration(
          kPageLoadInternalEventTimingClickInteractionEvents,
          ClickInteractionEvents::kPointerClickWithMissingPointerdownOnly);
      is_last_pointerup_orphan_ = false;
    }

    if (last_pointer_id_.has_value() && pointer_id != *last_pointer_id_ &&
        // Exclude keyboard clicks.
        pointer_id != PointerEventFactory::kReservedNonPointerId) {
      if (pointer_id_entry_map_.Contains(pointer_id)) {
        base::UmaHistogramEnumeration(
            kPageLoadInternalEventTimingClickInteractionEvents,
            ClickInteractionEvents::
                kPointerClickPointerIdDifferFromLastPointerIdAndPointerIdExistInMap);
      } else {
        if (pointer_id_entry_map_.Contains(*last_pointer_id_)) {
          base::UmaHistogramEnumeration(
              kPageLoadInternalEventTimingClickInteractionEvents,
              ClickInteractionEvents::
                  kPointerClickPointerIdDifferFromLastPointerIdAndOnlyLastPointerIdInMap);
        } else {
          base::UmaHistogramEnumeration(
              kPageLoadInternalEventTimingClickInteractionEvents,
              ClickInteractionEvents::
                  kPointerClickPointerIdDifferFromLastPointerIdAndNeitherInMap);
        }
      }
    }

    if (RuntimeEnabledFeaturesBase::
            EventTimingHandleKeyboardEventSimulatedClickEnabled()) {
      // Try handle keyboard event simulated click.
      if (TryHandleKeyboardEventSimulatedClick(entry, pointer_id)) {
        return true;
      }
    }

    // We do not rely on the |pointer_id| for clicks because they may be
    // inaccurate. Instead, we rely on the last pointer id seen.
    pointer_info = nullptr;
    if (last_pointer_id_.has_value() &&
        pointer_id_entry_map_.Contains(*last_pointer_id_)) {
      pointer_info = pointer_id_entry_map_.at(*last_pointer_id_);
    }
    if (pointer_info) {
      // There is a previous pointerdown or pointerup entry. Use its
      // interactionId.
      PerformanceEventTiming* previous_entry = pointer_info->GetEntry();

      if (previous_entry->name() == event_type_names::kPointerdown) {
        if (pointer_info->GetTimeStamps().size() > 1u) {
          base::UmaHistogramEnumeration(
              kPageLoadInternalEventTimingClickInteractionEvents,
              ClickInteractionEvents::kPointerClickWithPointerdownAndPointerup);
        } else {
          base::UmaHistogramEnumeration(
              kPageLoadInternalEventTimingClickInteractionEvents,
              ClickInteractionEvents::kPointerClickWithMissingPointerupOnly);
        }
      }

      // There are cases where we only see pointerdown and click, for instance
      // with contextmenu.
      if (!previous_entry->HasKnownInteractionID()) {
        UpdateInteractionId();
        previous_entry->SetInteractionIdAndOffset(GetCurrentInteractionId(),
                                                  GetInteractionCount());
      }
      entry->SetInteractionIdAndOffset(previous_entry->interactionId(),
                                       previous_entry->interactionOffset());
      pointer_info->GetTimeStamps().push_back(event_timestamps);
      RecordDragTapOrClickUKM(window, *pointer_info);
      // The pointer id of the pointerdown is no longer needed.
      pointer_id_entry_map_.erase(*last_pointer_id_);
    } else {
      // There is no previous pointerdown or pointerup entry. This can happen
      // when the user clicks using a non-pointer device. Generate a new
      // interactionId. No need to add to the map since this is the last event
      // in the interaction.
      UpdateInteractionId();
      entry->SetInteractionIdAndOffset(GetCurrentInteractionId(),
                                       GetInteractionCount());
      RecordDragTapOrClickUKM(
          window, *PointerEntryAndInfo::Create(entry, event_timestamps));

      // Exclude keyboard clicks.
      if (pointer_id != PointerEventFactory::kReservedNonPointerId) {
        // Note this also count if the click's corresponding pointerdown/up has
        // been over 1 secs thus flushed.
        base::UmaHistogramEnumeration(
            kPageLoadInternalEventTimingClickInteractionEvents,
            ClickInteractionEvents::
                kPointerClickWithMissingPointerdownAndPointerup);
      }
    }
    // Any existing pointerup in the map cannot fire a click.
    FlushPointerup();
    last_pointer_id_ = std::nullopt;
  }
  return true;
}

void ResponsivenessMetrics::RecordKeyboardUKM(
    LocalDOMWindow* window,
    const WTF::Vector<EventTimestamps>& event_timestamps,
    uint32_t interaction_offset) {
  RecordUserInteractionUKM(window, UserInteractionType::kKeyboard,
                           event_timestamps, interaction_offset);
}

// Event timing keyboard events processing
//
// See also ./Key_interaction_state_machine.md
// (https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/core/timing/Key_interaction_state_machine.md)
// to help understand the logic below that how event timing group up keyboard
// events as interactions.
void ResponsivenessMetrics::SetKeyIdAndRecordLatency(
    PerformanceEventTiming* entry,
    EventTimestamps event_timestamps) {
  last_pointer_id_ = std::nullopt;
  auto event_type = entry->name();
  if (event_type == event_type_names::kKeydown) {
    // If we were waiting for matching pointerup/keyup after a contextmenu, they
    // won't show up at this point.
    if (contextmenu_flush_timer_.IsActive()) {
      contextmenu_flush_timer_.Stop();
      FlushPointerdownAndPointerup();
      FlushKeydown();
    }

    CHECK(entry->GetEventTimingReportingInfo()->key_code.has_value());
    auto key_code = entry->GetEventTimingReportingInfo()->key_code.value();
    if (composition_state_ == kNonComposition) {
      if (IsHoldingKey(key_code)) {
        FlushSequenceBasedKeyboardEvents();
      }
      UpdateInteractionId();
    } else if (composition_state_ == kCompositionContinueOngoingInteraction) {
      // Continue interaction; Do not update Interaction Id
    } else if (composition_state_ == kCompositionStartNewInteractionOnKeydown) {
      FlushSequenceBasedKeyboardEvents();
      UpdateInteractionId();
      composition_state_ = kCompositionContinueOngoingInteraction;
    } else if (composition_state_ == kEndCompositionOnKeydown) {
      FlushSequenceBasedKeyboardEvents();
      UpdateInteractionId();
      composition_state_ = kNonComposition;
    }

    entry->SetInteractionIdAndOffset(GetCurrentInteractionId(),
                                     GetInteractionCount());
    sequence_based_keyboard_interaction_info_.SetInteractionIdAndOffset(
        GetCurrentInteractionId(), GetInteractionCount());
    sequence_based_keyboard_interaction_info_.AddTimestamps(event_timestamps);

    if (composition_state_ == kNonComposition) {
      InteractionInfo keydown_entry(GetCurrentInteractionId(),
                                    GetInteractionCount(), event_timestamps);
      key_code_to_interaction_info_map_.Set(key_code, std::move(keydown_entry));
    }
    last_keydown_keycode_info_ =
        KeycodeInfo(key_code, GetCurrentInteractionId(), GetInteractionCount());
  } else if (event_type == event_type_names::kKeyup) {
    if (composition_state_ == kNonComposition) {
      CHECK(entry->GetEventTimingReportingInfo()->key_code.has_value());
      auto key_code = entry->GetEventTimingReportingInfo()->key_code.value();
      if (!key_code_to_interaction_info_map_.Contains(key_code)) {
        return;
      }

      // Match the keydown entry with the keyup entry using keycode.
      auto& key_entry = key_code_to_interaction_info_map_.find(key_code)->value;
      entry->SetInteractionIdAndOffset(key_entry.GetInteractionId(),
                                       key_entry.GetInteractionOffset());
      key_entry.AddTimestamps(event_timestamps);
      RecordKeyboardUKM(window_performance_->DomWindow(),
                        key_entry.GetTimeStamps(),
                        key_entry.GetInteractionOffset());
      // Remove keycode from the map and reset other values
      key_code_to_interaction_info_map_.erase(key_code);
      sequence_based_keyboard_interaction_info_.Clear();
    } else {
      entry->SetInteractionIdAndOffset(GetCurrentInteractionId(),
                                       GetInteractionCount());
      sequence_based_keyboard_interaction_info_.SetInteractionIdAndOffset(
          GetCurrentInteractionId(), GetInteractionCount());
      sequence_based_keyboard_interaction_info_.AddTimestamps(event_timestamps);
    }
  } else if (event_type == event_type_names::kKeypress) {
    if (composition_state_ == kNonComposition &&
        last_keydown_keycode_info_.has_value() &&
        key_code_to_interaction_info_map_.find(
            last_keydown_keycode_info_.value().keycode) !=
            key_code_to_interaction_info_map_.end()) {
      // Set a interaction id generated by previous keydown entry
      entry->SetInteractionIdAndOffset(GetCurrentInteractionId(),
                                       GetInteractionCount());
      key_code_to_interaction_info_map_
          .find(last_keydown_keycode_info_.value().keycode)
          ->value.AddTimestamps(event_timestamps);
    }
  } else if (event_type == event_type_names::kCompositionstart) {
    composition_state_ = kCompositionContinueOngoingInteraction;
    key_code_to_interaction_info_map_.clear();
  } else if (event_type == event_type_names::kCompositionend) {
    composition_state_ = kEndCompositionOnKeydown;
    composition_end_flush_timer_.StartOneShot(kFlushTimerLength, FROM_HERE);
  } else if (event_type == event_type_names::kCompositionupdate) {
    if (!last_keydown_keycode_info_.has_value()) {
      composition_state_ = kCompositionStartNewInteractionOnInput;
    } else {
      composition_state_ = kCompositionStartNewInteractionOnKeydown;
    }
  } else if (event_type == event_type_names::kInput) {
    // Expose interactionId for Input events only under composition
    if (composition_state_ == kNonComposition) {
      return;
    }
    // Update Interaction Id when input is selected using IME suggestion without
    // pressing a key. In this case Input event starts and finishes interaction
    if (composition_state_ == kCompositionStartNewInteractionOnInput) {
      FlushSequenceBasedKeyboardEvents();
      UpdateInteractionId();
      entry->SetInteractionIdAndOffset(GetCurrentInteractionId(),
                                       GetInteractionCount());
      sequence_based_keyboard_interaction_info_.SetInteractionIdAndOffset(
          GetCurrentInteractionId(), GetInteractionCount());
      sequence_based_keyboard_interaction_info_.AddTimestamps(event_timestamps);
      FlushSequenceBasedKeyboardEvents();
      composition_state_ = kCompositionStartNewInteractionOnKeydown;
    } else {
      // TODO(crbug.com/1252856): fix counts in ChromeOS due to duplicate
      // events.
      entry->SetInteractionIdAndOffset(GetCurrentInteractionId(),
                                       GetInteractionCount());
      sequence_based_keyboard_interaction_info_.SetInteractionIdAndOffset(
          GetCurrentInteractionId(), GetInteractionCount());
      sequence_based_keyboard_interaction_info_.AddTimestamps(event_timestamps);
    }
    last_keydown_keycode_info_.reset();
  }
}

void ResponsivenessMetrics::FlushKeydown() {
  for (auto& entry : key_code_to_interaction_info_map_) {
    // Keydowns triggered contextmenu, though missing pairing keyups due to a
    // known issue - https://github.com/w3c/pointerevents/issues/408, should
    // still be counted as a valid interaction and get reported to UKM.
    RecordKeyboardUKM(window_performance_->DomWindow(),
                      entry.value.GetTimeStamps(),
                      entry.value.GetInteractionOffset());
  }
  key_code_to_interaction_info_map_.clear();
}

void ResponsivenessMetrics::FlushAllEventsAtPageHidden() {
  // Flush events that are waiting to be set an interaction id.
  FlushPointerdownAndPointerup();

  FlushKeydown();

  FlushSequenceBasedKeyboardEvents();
}

uint32_t ResponsivenessMetrics::GetInteractionCount() const {
  return interaction_count_;
}

void ResponsivenessMetrics::UpdateInteractionId() {
  current_interaction_id_for_event_timing_ += kInteractionIdIncrement;
  interaction_count_++;
}

uint32_t ResponsivenessMetrics::GetCurrentInteractionId() const {
  return current_interaction_id_for_event_timing_;
}

void ResponsivenessMetrics::SetCurrentInteractionEventQueuedTimestamp(
    base::TimeTicks queued_time) {
  current_interaction_event_queued_timestamp_ = queued_time;
}

base::TimeTicks ResponsivenessMetrics::CurrentInteractionEventQueuedTimestamp()
    const {
  return current_interaction_event_queued_timestamp_;
}

void ResponsivenessMetrics::FlushCompositionEndTimerFired(TimerBase*) {
  FlushSequenceBasedKeyboardEvents();
}

void ResponsivenessMetrics::FlushSequenceBasedKeyboardEvents() {
  LocalDOMWindow* window = window_performance_->DomWindow();
  if (!window) {
    return;
  }

  if (composition_end_flush_timer_.IsActive()) {
    composition_end_flush_timer_.Stop();
  }

  if (!sequence_based_keyboard_interaction_info_.Empty()) {
    RecordKeyboardUKM(
        window, sequence_based_keyboard_interaction_info_.GetTimeStamps(),
        sequence_based_keyboard_interaction_info_.GetInteractionOffset());
    sequence_based_keyboard_interaction_info_.Clear();
  }
}

// Determines if the key is is being held (pressed) for a sustained period of
// time. It is used when keyup does not appear in the end of a interaction (e.g
// Windows). In such cases the interaction is reported using
// sequence_based_keyboard_interaction_info_.
bool ResponsivenessMetrics::IsHoldingKey(std::optional<int> key_code) {
  return last_keydown_keycode_info_.has_value() &&
         last_keydown_keycode_info_->keycode == key_code;
}

void ResponsivenessMetrics::FlushPointerTimerFired(TimerBase*) {
  FlushPointerup();
}

void ResponsivenessMetrics::FlushPointerup() {
  LocalDOMWindow* window = window_performance_->DomWindow();
  if (!window) {
    return;
  }
  if (pointer_flush_timer_.IsActive()) {
    pointer_flush_timer_.Stop();
  }

  Vector<PointerId> pointer_ids_to_remove;
  for (const auto& item : pointer_id_entry_map_) {
    PerformanceEventTiming* entry = item.value->GetEntry();
    // Report pointerups that are currently waiting for a click. This could be
    // the case when the entry's name() is pointerup or when we have more than
    // one event for this |item|, which means we have pointerdown and pointerup.
    if (entry->name() == event_type_names::kPointerup ||
        item.value->GetTimeStamps().size() > 1u) {
      RecordDragTapOrClickUKM(window, *item.value);
      pointer_ids_to_remove.push_back(item.key);
    }
  }

  // map clean up
  pointer_id_entry_map_.RemoveAll(pointer_ids_to_remove);
}

void ResponsivenessMetrics::ContextmenuFlushTimerFired(TimerBase*) {
  // Pointerdown could be followed by a contextmenu without pointerup, in this
  // case we need to treat contextmenu as if pointerup and flush the previous
  // pointerdown with a valid interactionId. (crbug.com/1413096)
  FlushPointerdownAndPointerup();
"""


```
Response:
Let's break down the thought process for analyzing this code snippet and generating the desired output.

**1. Understanding the Core Request:**

The request asks for a functional summary of the `WindowPerformance.cc` file, specifically focusing on its relationship with web technologies (JavaScript, HTML, CSS), logical reasoning with input/output examples, common user/programming errors, debugging hints, and a final consolidated summary of its functionalities. The prompt explicitly mentions this is part 2 of 2, suggesting we should build upon previous knowledge (though we don't have that part here).

**2. Initial Code Scan and Keyword Identification:**

My first step is a quick scan of the code, looking for keywords and patterns that suggest functionality. I'd be looking for:

* **Performance-related terms:** "Performance", "Timing", "Event", "Paint", "LayoutShift", "LCP", "FID", "CLS", "Navigation".
* **JavaScript/Web API related terms:**  "PerformanceObserver", "PerformanceEntry", "dispatchEvent", "DOMHighResTimeStamp".
* **Event handling:** "ReportEvent", "NotifyObserversOfEntry", "addEventListener" (though not directly present, the context implies it).
* **Data structures:**  `std::vector`, `std::unique_ptr`, `std::optional`, suggesting storage and management of performance data.
* **Tracing and Debugging:** "TRACE_EVENT", "devtools.timeline".
* **Specific event names:** "click", "keydown", "pointerdown", "pointerup".
* **Conditional logic:** `if`, `else if`, suggesting different behaviors based on event types or states.
* **Specific metrics:**  "First Input Delay", "Largest Contentful Paint", "Layout Shift".

**3. Grouping Functionalities:**

Based on the keywords and patterns, I start mentally grouping the code into logical blocks of functionality:

* **Event Timing:**  The `ReportEvent` function and related logic clearly handle the timing of various events (mouse clicks, key presses, pointer events). The interactions with `InteractiveDetector` and the `first_input_timing_` member variable point to First Input Delay (FID) calculation.
* **Performance Observer Integration:**  The code checks for observers (`HasObserverFor`), notifies them (`NotifyObserversOfEntry`), and adds entries to buffers. This strongly suggests integration with the JavaScript `PerformanceObserver` API.
* **Specific Performance Metrics:**  Functions like `ReportLongAnimationFrameTiming`, `AddElementTiming`, `AddLayoutShiftEntry`, and `OnLargestContentfulPaintUpdated` indicate the tracking and reporting of specific performance metrics beyond basic event timing.
* **Visibility State Tracking:**  `AddVisibilityStateEntry` and `PageVisibilityChanged` track when the page is visible or hidden.
* **Soft Navigation:** `AddSoftNavigationEntry` suggests support for a specific type of navigation tracking.
* **Interaction Tracking:** The `SetInteractionIdAndRecordLatency` function and the mention of `responsiveness_metrics_` indicate tracking user interactions for metrics beyond FID.
* **Debugging and Tracing:** The `TRACE_EVENT` calls show the code is instrumented for debugging and performance analysis within the Chrome DevTools.
* **Fallback Time Logic:** The `SetFallbackTime` function addresses edge cases where the true event end time might be misleading (e.g., due to modal dialogs or visibility changes).

**4. Connecting to Web Technologies:**

Now, I explicitly link the identified functionalities to JavaScript, HTML, and CSS:

* **JavaScript:** The entire `PerformanceObserver` integration is directly tied to the JavaScript API. The reported metrics are accessible via JavaScript. The timing information is used by JavaScript frameworks and developers to understand user experience.
* **HTML:** The `AddElementTiming` function directly relates to HTML elements. The Largest Contentful Paint (LCP) metric is about rendering HTML content. The interaction with `HTMLImageElement` is a specific example.
* **CSS:** While not directly manipulating CSS, the layout shift (`AddLayoutShiftEntry`) is a performance metric heavily influenced by CSS changes and animations. The rendering aspects of LCP are also affected by CSS.

**5. Logical Reasoning and Examples:**

For each major functionality, I try to devise a simple input and expected output:

* **Event Timing:** User clicks a button -> An entry with timing information (start, end, processing time) is recorded.
* **LCP:** An image becomes the largest visible element -> An LCP entry with the image's URL, size, and timing information is recorded.
* **Layout Shift:**  An ad loads and pushes content down -> A layout shift entry with the shift amount is recorded.

**6. Identifying User/Programming Errors:**

I think about common mistakes related to these performance features:

* **Not using PerformanceObserver:** Developers might not be aware of or utilize the API to collect this data.
* **Misinterpreting fallback times:** Developers might not understand why the reported end time differs from the actual event end.
* **Causing layout shifts:**  Poor CSS practices can lead to unexpected layout shifts.

**7. Debugging Hints and User Steps:**

I consider how a developer would arrive at this code during debugging:

* **Performance issues:** Investigating slow interactions or poor loading performance.
* **PerformanceObserver usage:**  Debugging why a specific performance entry is not being recorded.
* **DevTools timeline:** Tracing event flow and identifying performance bottlenecks.

I then connect the user's actions (opening a webpage, interacting with it) to the code's execution.

**8. Consolidating the Summary:**

Finally, I synthesize the individual points into a concise summary of the file's overall purpose and key responsibilities. I aim for a high-level overview that captures the essence of the code.

**Self-Correction/Refinement:**

Throughout this process, I would review my understanding and look for inconsistencies or areas where I could be more precise. For example, initially, I might just say "handles events," but I would refine that to "measures and reports timing information for user interaction events."  I would also double-check that my examples are clear and illustrative. I also pay attention to the prompt's specific requests (like including input/output examples and debugging hints).
```
这是目录为blink/renderer/core/timing/window_performance.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

根据提供的代码片段，我们可以归纳一下 `blink/renderer/core/timing/window_performance.cc` 文件的功能：

**核心功能：性能监控与报告**

该文件主要负责收集、处理和报告与网页性能相关的各种指标，并将这些信息提供给 JavaScript 的 Performance API 以及 Chromium 的开发者工具。它扮演着 Blink 渲染引擎中性能数据收集和对外暴露的核心角色。

**具体功能点：**

1. **事件时序 (Event Timing) 监控和报告:**
   - 记录和报告用户交互事件 (例如 `click`, `keydown`, `pointerdown`, `pointerup`) 的详细时间信息，包括创建时间、入队时间、处理开始时间、处理结束时间、以及呈现时间等。
   - **与 JavaScript 的关系:**  这些数据会被封装成 `PerformanceEventTiming` 对象，可以通过 JavaScript 的 `PerformanceObserver` API 观察到。例如，开发者可以使用 `performance.observe({entryTypes: ['event']})` 来监听和获取这些事件的时序信息。
   - **与 HTML 的关系:** 用户的交互事件直接作用于 HTML 元素，`WindowPerformance` 需要感知这些事件的发生以及它们的目标元素。
   - **逻辑推理:**
     - **假设输入:** 用户点击一个按钮。
     - **输出:**  `ReportEvent` 函数会被调用，创建一个 `PerformanceEventTiming` 对象，记录该 `click` 事件的各项时间戳，并最终通过 `NotifyObserversOfEntry` 将其传递给 JavaScript 的 PerformanceObserver。
   - **用户/编程错误:**  开发者可能错误地假设事件处理是立即完成的，而忽略了事件入队、commit 等阶段的耗时，`WindowPerformance` 提供的详细时序信息可以帮助他们识别这些延迟。

2. **首次输入延迟 (First Input Delay - FID) 监控和报告:**
   - 特别关注首次用户输入事件的处理延迟，这是衡量页面响应性的重要指标。
   - **与 JavaScript 的关系:**  FID 数据最终会通过 `PerformanceObserver` (entryType: 'first-input') 暴露给 JavaScript。
   - **与 HTML 的关系:** FID 关注用户首次与页面上的可交互元素进行交互。
   - **逻辑推理:**
     - **假设输入:** 用户在页面加载完成后首次点击一个链接。
     - **输出:** `ReportEvent` 会识别到首次输入事件（例如 `pointerdown` 或 `mousedown`），记录相关时间戳，并在后续的 `pointerup` 或其他输入事件中计算 FID，最终通过 `DispatchFirstInputTiming` 将 `PerformanceEventTiming` 对象传递出去。

3. **长动画帧 (Long Animation Frame) 监控和报告:**
   - 记录和报告执行时间过长的动画帧，这可能导致页面卡顿。
   - **与 JavaScript 的关系:**  长动画帧信息会被封装成 `PerformanceLongAnimationFrameTiming` 对象，可以通过 JavaScript 的 `PerformanceObserver` API 观察到 (entryType: 'long-animation-frame')。
   - **与 CSS 的关系:** 动画通常由 CSS 触发和控制，`WindowPerformance` 需要捕获因 CSS 动画导致的过长帧。
   - **逻辑推理:**
     - **假设输入:**  一个复杂的 CSS 动画在主线程上执行时间超过了阈值。
     - **输出:** `ReportLongAnimationFrameTiming` 会被调用，创建一个 `PerformanceLongAnimationFrameTiming` 对象，包含该动画帧的开始时间和持续时间等信息。

4. **元素时序 (Element Timing) 监控和报告:**
   - 允许开发者标记特定的 HTML 元素，并监控这些元素的渲染时间和加载时间。
   - **与 JavaScript 的关系:**  元素时序信息会被封装成 `PerformanceElementTiming` 对象，可以通过 JavaScript 的 `PerformanceObserver` API 观察到 (entryType: 'element')。
   - **与 HTML 的关系:**  开发者需要通过 HTML 属性 (例如 `elementtiming` 属性) 来标记需要监控的元素。
   - **与 CSS 的关系:** 元素的渲染和加载会受到 CSS 样式的影响，`WindowPerformance` 记录的时间会反映这些影响。
   - **逻辑推理:**
     - **假设输入:** HTML 中有一个 `<img elementtiming="hero-image" src="...">` 标签。
     - **输出:**  当该图片开始渲染和加载完成时，`AddElementTiming` 会被调用，创建一个 `PerformanceElementTiming` 对象，包含图片的渲染时间、加载时间、URL 等信息。

5. **布局偏移 (Layout Shift) 监控和报告:**
   - 记录页面上发生的意外布局偏移，这会影响用户体验。
   - **与 JavaScript 的关系:** 布局偏移信息会被封装成 `LayoutShift` 对象，可以通过 JavaScript 的 `PerformanceObserver` API 观察到 (entryType: 'layout-shift')。
   - **与 HTML/CSS 的关系:** 布局偏移通常由 HTML 结构的动态变化或 CSS 样式的修改引起。
   - **逻辑推理:**
     - **假设输入:**  一个异步加载的广告导致页面上的其他元素向下移动。
     - **输出:** `AddLayoutShiftEntry` 会被调用，创建一个 `LayoutShift` 对象，记录布局偏移的大小和发生时间。

6. **可见性状态 (Visibility State) 监控和报告:**
   - 记录页面的可见性状态变化（例如，用户切换标签页导致页面变为不可见）。
   - **与 JavaScript 的关系:** 可见性状态信息会被封装成 `VisibilityStateEntry` 对象，可以通过 JavaScript 的 `PerformanceObserver` API 观察到 (entryType: 'visibility-state')。
   - **用户/编程错误:** 开发者可能没有考虑到页面在后台不可见时的行为，`WindowPerformance` 提供的可见性状态信息可以帮助他们了解页面何时进入后台。

7. **软导航 (Soft Navigation) 监控和报告:**
   - 记录客户端路由或单页应用中的导航事件。
   - **与 JavaScript 的关系:** 软导航信息会被封装成 `SoftNavigationEntry` 对象，可以通过 JavaScript 的 `PerformanceObserver` API 观察到 (entryType: 'soft-navigation')。
   - **与 JavaScript 框架的关系:**  软导航通常由 JavaScript 框架控制。

8. **最大内容绘制 (Largest Contentful Paint - LCP) 监控和报告:**
   - 记录视口内最大的可见元素开始渲染的时间，是衡量页面加载性能的重要指标。
   - **与 JavaScript 的关系:** LCP 信息会被封装成 `LargestContentfulPaint` 对象，可以通过 JavaScript 的 `PerformanceObserver` API 观察到 (entryType: 'largest-contentful-paint')。
   - **与 HTML/CSS 的关系:** LCP 关注的是 HTML 内容的渲染，会受到 CSS 样式和资源加载的影响。
   - **逻辑推理:**
     - **假设输入:** 页面上最大的图片完成加载和渲染。
     - **输出:** `OnLargestContentfulPaintUpdated` 会被调用，创建一个 `LargestContentfulPaint` 对象，包含该图片的相关信息和渲染时间。

9. **交互 ID (Interaction ID) 管理和延迟记录:**
    - 跟踪用户交互，为交互分配唯一的 ID，并记录与交互相关的延迟。
    - **与 JavaScript 的关系:**  虽然 JavaScript 不能直接访问 Interaction ID，但相关的延迟数据会影响到 Event Timing 等指标。

10. **事件计数 (Event Counts):**
    - 维护各种事件的计数器。

11. **页面可见性变化时的事件时序刷新:**
    - 当页面从可见变为不可见时，刷新并报告缓存的事件时序数据。

12. **模态对话框显示时的处理:**
    - 记录模态对话框显示的时间，并在计算事件时序时考虑模态对话框的影响。

13. **与 Chromium 开发者工具的集成:**
    - 使用 `TRACE_EVENT` 宏向 Chromium 的追踪系统报告性能事件，这些事件可以在开发者工具的 Performance 面板中查看。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户打开一个网页:**  当用户在 Chrome 浏览器中打开一个网页时，Blink 渲染引擎开始解析 HTML、CSS 和 JavaScript。
2. **用户与网页交互:** 用户执行各种操作，例如点击按钮、滚动页面、输入文本等。
3. **事件触发:** 用户的交互会触发相应的事件，例如 `mousedown`, `mouseup`, `click`, `keydown` 等。
4. **事件处理:** 这些事件会被 Blink 的事件处理机制捕获，并传递给相应的事件监听器。
5. **`WindowPerformance::ReportEvent` 被调用:**  在事件处理流程中，`WindowPerformance::ReportEvent` 函数会被调用，以记录该事件的性能相关信息。
6. **性能数据收集和报告:** `ReportEvent` 函数会创建 `PerformanceEventTiming` 对象，并将其添加到内部的缓冲区中。
7. **`PerformanceObserver` 回调:** 如果有 JavaScript 代码通过 `PerformanceObserver` 监听了 `'event'` 类型的条目，那么 `WindowPerformance` 会调用 `NotifyObserversOfEntry`，将 `PerformanceEventTiming` 对象传递给 JavaScript 代码。
8. **开发者工具的追踪:** 如果启用了 Chromium 开发者工具的 Performance 面板，`TRACE_EVENT` 宏记录的事件信息会被记录下来，供开发者分析。

**用户或编程常见的使用错误举例:**

1. **JavaScript 开发者没有使用 `PerformanceObserver` API:** 开发者可能不知道或者没有使用 `PerformanceObserver` API 来获取这些性能数据，导致无法监控和优化页面性能。
2. **错误地假设事件处理时间:** 开发者可能错误地认为事件处理是同步且立即完成的，而忽略了事件排队、commit 等阶段的耗时，导致对用户交互的响应性评估不准确。
3. **不合理的 CSS 动画导致长动画帧:** 开发者编写了复杂的、性能不佳的 CSS 动画，导致主线程繁忙，触发了长动画帧的报告。
4. **动态加载内容导致布局偏移:** 开发者在页面加载完成后动态地插入内容，没有合理地处理可能引起的布局偏移，导致用户体验下降。
5. **懒加载策略不当导致 LCP 延迟:** 开发者对首屏关键图片使用了过于激进的懒加载策略，导致 LCP 指标不佳。

**总结 `WindowPerformance` 的功能 (基于提供的代码片段):**

`WindowPerformance` 类是 Blink 渲染引擎中负责收集和报告关键网页性能指标的核心组件。它监控用户交互事件的时序、首次输入延迟、长动画帧、元素渲染和加载时间、布局偏移、页面可见性状态以及软导航等信息。这些数据通过 JavaScript 的 Performance API 暴露给开发者，并用于 Chromium 开发者工具的性能分析。`WindowPerformance` 的主要职责是提供精确的性能数据，帮助开发者理解和优化网页的用户体验。它通过与事件处理机制、渲染流程以及 JavaScript 引擎的集成来实现其功能。提供的代码片段主要关注事件时序的处理和报告，以及与其他性能指标监控功能的集成点。

### 提示词
```
这是目录为blink/renderer/core/timing/window_performance.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ools.timeline", "EventPresentation", scope,
            last_event_reporting_info->presentation_time.value(), flowid);
      }

      if (auto first_entry_with_fallback =
              std::find_if(first, last,
                           [](auto entry) {
                             return entry->GetEventTimingReportingInfo()
                                 ->fallback_time.has_value();
                           });
          first_entry_with_fallback != last) {
        TRACE_EVENT_INSTANT("devtools.timeline", "EventFallbackTime", scope,
                            first_entry_with_fallback->Get()
                                ->GetEventTimingReportingInfo()
                                ->fallback_time.value(),
                            flowid);
      }
    }

    // Remove reported EventData objects.
    event_timing_entries_.erase(first, last);
  }
}

void WindowPerformance::ReportEvent(
    InteractiveDetector* interactive_detector,
    Member<PerformanceEventTiming> event_timing_entry) {
  base::TimeTicks event_creation_time =
      event_timing_entry->GetEventTimingReportingInfo()->creation_time;
  base::TimeTicks processing_start =
      event_timing_entry->GetEventTimingReportingInfo()->processing_start_time;
  base::TimeTicks processing_end =
      event_timing_entry->GetEventTimingReportingInfo()->processing_end_time;
  SetFallbackTime(event_timing_entry);

  base::TimeTicks event_end_time = event_timing_entry->GetEndTime();

  base::TimeDelta time_to_next_paint = event_end_time - processing_end;

  // Round to 8ms.
  int rounded_duration =
      std::round((event_end_time - event_creation_time).InMillisecondsF() / 8) *
      8;

  event_timing_entry->SetDuration(rounded_duration);

  base::TimeDelta processing_duration = processing_end - processing_start;

  if (event_timing_entry->name() == "pointerdown") {
    pending_pointer_down_start_time_ = event_timing_entry->startTime();

    pending_pointer_down_processing_time_ = processing_duration;

    pending_pointer_down_time_to_next_paint_ = time_to_next_paint;
  } else if (event_timing_entry->name() == "pointerup") {
    if (pending_pointer_down_time_to_next_paint_.has_value() &&
        interactive_detector) {
      interactive_detector->RecordInputEventTimingUMA(
          pending_pointer_down_processing_time_.value(),
          pending_pointer_down_time_to_next_paint_.value());
    }
  } else if ((event_timing_entry->name() == "click" ||
              event_timing_entry->name() == "keydown" ||
              event_timing_entry->name() == "mousedown") &&
             interactive_detector) {
    interactive_detector->RecordInputEventTimingUMA(processing_duration,
                                                    time_to_next_paint);
  }

  // Event Timing
  ResponsivenessMetrics::EventTimestamps event_timestamps = {
      event_creation_time,
      event_timing_entry->GetEventTimingReportingInfo()
          ->enqueued_to_main_thread_time,
      event_timing_entry->GetEventTimingReportingInfo()
          ->commit_finish_time.value_or(
              event_timing_entry->GetEventTimingReportingInfo()
                  ->processing_end_time),
      event_end_time};

  if (SetInteractionIdAndRecordLatency(event_timing_entry, event_timestamps)) {
    NotifyAndAddEventTimingBuffer(event_timing_entry);
  }

  // First Input
  //
  // See also ./First_input_state_machine.md
  // (https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/core/timing/First_input_state_machine.md)
  // to understand the logics below.
  if (!first_input_timing_) {
    if (event_timing_entry->name() == event_type_names::kPointerdown) {
      first_pointer_down_event_timing_ =
          PerformanceEventTiming::CreateFirstInputTiming(event_timing_entry);
    } else if (event_timing_entry->name() == event_type_names::kPointerup &&
               first_pointer_down_event_timing_) {
      if (event_timing_entry->HasKnownInteractionID()) {
        first_pointer_down_event_timing_->SetInteractionIdAndOffset(
            event_timing_entry->interactionId(),
            event_timing_entry->interactionOffset());
      }
      DispatchFirstInputTiming(first_pointer_down_event_timing_);
    } else if (event_timing_entry->name() == event_type_names::kPointercancel) {
      first_pointer_down_event_timing_.Clear();
    } else if ((event_timing_entry->name() == event_type_names::kMousedown ||
                event_timing_entry->name() == event_type_names::kClick ||
                event_timing_entry->name() == event_type_names::kKeydown) &&
               !first_pointer_down_event_timing_) {
      DispatchFirstInputTiming(
          PerformanceEventTiming::CreateFirstInputTiming(event_timing_entry));
    }
  }
}

void WindowPerformance::NotifyAndAddEventTimingBuffer(
    PerformanceEventTiming* entry) {
  if (HasObserverFor(PerformanceEntry::kEvent)) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kEventTimingExplicitlyRequested);
    NotifyObserversOfEntry(*entry);
  }

  // TODO(npm): is 104 a reasonable buffering threshold or should it be
  // relaxed?
  if (entry->duration() >= PerformanceObserver::kDefaultDurationThreshold) {
    AddToEventTimingBuffer(*entry);
  }

  bool tracing_enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED("devtools.timeline", &tracing_enabled);

  if (tracing_enabled) {
    base::TimeTicks unsafe_start_time =
        entry->GetEventTimingReportingInfo()->creation_time;
    base::TimeTicks unsafe_end_time = entry->GetEndTime();
    unsigned hash = WTF::GetHash(entry->name());
    WTF::AddFloatToHash(hash, entry->startTime());
    auto track_id = perfetto::Track::ThreadScoped(this);
    auto flow_id = perfetto::Flow::FromPointer(entry);
    TRACE_EVENT_INSTANT("devtools.timeline", "EventCreation", track_id,
                        entry->GetEventTimingReportingInfo()->creation_time,
                        flow_id);
    TRACE_EVENT_INSTANT(
        "devtools.timeline", "EventEnqueuedToMainThread", track_id,
        entry->GetEventTimingReportingInfo()->enqueued_to_main_thread_time,
        flow_id);

    TRACE_EVENT_BEGIN(
        "devtools.timeline", "EventProcessing", track_id,
        entry->GetEventTimingReportingInfo()->processing_start_time, flow_id,
        [&](perfetto::EventContext ctx) {
          auto* event = ctx.event<perfetto::protos::pbzero::ChromeTrackEvent>();
          auto* data = event->set_event_timing();
          entry->SetPerfettoData(DomWindow()->GetFrame(), data,
                                 GetTimeOriginInternal());
        });
    TRACE_EVENT_END("devtools.timeline", track_id,
                    entry->GetEventTimingReportingInfo()->processing_end_time);

    // TODO(sullivan): Remove these events when DevTools migrates to the above
    // perfetto events.
    TRACE_EVENT_NESTABLE_ASYNC_BEGIN_WITH_TIMESTAMP1(
        "devtools.timeline", "EventTiming", hash, unsafe_start_time, "data",
        entry->ToTracedValue(DomWindow()->GetFrame()));

    TRACE_EVENT_NESTABLE_ASYNC_END_WITH_TIMESTAMP0(
        "devtools.timeline", "EventTiming", hash, unsafe_end_time);
  }
}

void WindowPerformance::SetFallbackTime(PerformanceEventTiming* entry) {
  if (entry->GetEventTimingReportingInfo()->fallback_time.has_value()) {
    return;
  }
  // For artificial events on MacOS, we will fallback entry's end time to its
  // processingEnd (as if there was no next paint needed). crbug.com/1321819.
  const bool is_artificial_pointerup_or_click =
      (entry->name() == event_type_names::kPointerup ||
       entry->name() == event_type_names::kClick) &&
      entry->startTime() == pending_pointer_down_start_time_;

  if (is_artificial_pointerup_or_click) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kEventTimingArtificialPointerupOrClick);
  }

  // If the page visibility was changed. We fallback entry's end time to its
  // processingEnd (as if there was no next paint needed). crbug.com/1312568.
  bool was_page_visibility_changed =
      last_hidden_timestamp_ >
          entry->GetEventTimingReportingInfo()->creation_time &&
      last_hidden_timestamp_ <
          entry->GetEventTimingReportingInfo()->presentation_time;

  // An javascript synchronous modal dialog showed before the event frame
  // got presented. User could wait for arbitrarily long on the dialog. Thus
  // we fall back presentation time to the pre dialog showing time.
  // crbug.com/1435448.
  bool fallback_end_time_to_dialog_time = false;
  base::TimeTicks first_modal_dialog_timestamp;

  // Clean up stale dialog times.
  while (!show_modal_dialog_timestamps_.empty() &&
         show_modal_dialog_timestamps_.front() <
             entry->GetEventTimingReportingInfo()->creation_time) {
    show_modal_dialog_timestamps_.pop_front();
  }

  if (!show_modal_dialog_timestamps_.empty() &&
      show_modal_dialog_timestamps_.front() <
          entry->GetEventTimingReportingInfo()->presentation_time) {
    fallback_end_time_to_dialog_time = true;
    first_modal_dialog_timestamp = show_modal_dialog_timestamps_.front();
  }

  const bool fallback_end_time_to_processing_end =
      was_page_visibility_changed
#if BUILDFLAG(IS_MAC)
      || is_artificial_pointerup_or_click
#endif  // BUILDFLAG(IS_MAC)
      ;

  // Set a fallback time.
  if (fallback_end_time_to_dialog_time && fallback_end_time_to_processing_end) {
    entry->GetEventTimingReportingInfo()->fallback_time =
        std::min(first_modal_dialog_timestamp,
                 entry->GetEventTimingReportingInfo()->processing_end_time);
  } else if (fallback_end_time_to_dialog_time) {
    entry->GetEventTimingReportingInfo()->fallback_time =
        first_modal_dialog_timestamp;
  } else if (fallback_end_time_to_processing_end) {
    entry->GetEventTimingReportingInfo()->fallback_time =
        entry->GetEventTimingReportingInfo()->processing_end_time;
  }
}

bool WindowPerformance::SetInteractionIdAndRecordLatency(
    PerformanceEventTiming* entry,
    ResponsivenessMetrics::EventTimestamps event_timestamps) {
  if (!IsEventTypeForInteractionId(entry->name())) {
    return true;
  }
  // We set the interactionId and record the metric in the
  // same logic, so we need to ignore the return value when InteractionId is
  // disabled.
  if (entry->GetEventTimingReportingInfo()->pointer_id.has_value()) {
    return responsiveness_metrics_->SetPointerIdAndRecordLatency(
        entry, event_timestamps);
  }
  responsiveness_metrics_->SetKeyIdAndRecordLatency(entry, event_timestamps);
  return true;
}

void WindowPerformance::ReportLongAnimationFrameTiming(
    AnimationFrameTimingInfo* info) {
  LocalDOMWindow* window = DomWindow();
  if (!window) {
    return;
  }

  PerformanceLongAnimationFrameTiming* entry =
      MakeGarbageCollected<PerformanceLongAnimationFrameTiming>(
          info, time_origin_, cross_origin_isolated_capability_, window);

  if (!IsLongAnimationFrameBufferFull()) {
    InsertEntryIntoSortedBuffer(long_animation_frame_buffer_, *entry,
                                kRecordSwaps);
  }

  NotifyObserversOfEntry(*entry);
}

void WindowPerformance::AddElementTiming(const AtomicString& name,
                                         const String& url,
                                         const gfx::RectF& rect,
                                         base::TimeTicks start_time,
                                         base::TimeTicks load_time,
                                         const AtomicString& identifier,
                                         const gfx::Size& intrinsic_size,
                                         const AtomicString& id,
                                         Element* element) {
  if (!DomWindow()) {
    return;
  }

  DOMHighResTimeStamp coarsened_load_time =
      MonotonicTimeToDOMHighResTimeStamp(load_time);

  DOMHighResTimeStamp coarsened_render_time =
      RenderTimeToDOMHighResTimeStamp(start_time);

  PerformanceElementTiming* entry = PerformanceElementTiming::Create(
      name, url, rect, coarsened_render_time, coarsened_load_time, identifier,
      intrinsic_size.width(), intrinsic_size.height(), id, element,
      DomWindow());
  TRACE_EVENT2("loading", "PerformanceElementTiming", "data",
               entry->ToTracedValue(), "frame",
               GetFrameIdForTracing(DomWindow()->GetFrame()));

  AddRenderCoarsenedEntry(
      WTF::BindOnce(
          [](Persistent<PerformanceElementTiming> entry,
             Performance& performance) {
            if (performance.HasObserverFor(PerformanceEntry::kElement)) {
              static_cast<WindowPerformance&>(performance)
                  .NotifyObserversOfEntry(*entry);
            }
            if (!performance.IsElementTimingBufferFull()) {
              performance.AddToElementTimingBuffer(*entry);
            }
          },
          WrapPersistent(entry)),
      coarsened_render_time);
}

void WindowPerformance::DispatchFirstInputTiming(
    PerformanceEventTiming* entry) {
  if (!entry) {
    return;
  }
  DCHECK_EQ("first-input", entry->entryType());
  if (HasObserverFor(PerformanceEntry::kFirstInput)) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kEventTimingExplicitlyRequested);
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kEventTimingFirstInputExplicitlyRequested);
    NotifyObserversOfEntry(*entry);
  }

  DCHECK(!first_input_timing_);
  first_input_timing_ = entry;
}

void WindowPerformance::AddLayoutShiftEntry(LayoutShift* entry) {
  if (HasObserverFor(PerformanceEntry::kLayoutShift)) {
    NotifyObserversOfEntry(*entry);
  }
  AddToLayoutShiftBuffer(*entry);
}

void WindowPerformance::AddVisibilityStateEntry(bool is_visible,
                                                base::TimeTicks timestamp) {
  VisibilityStateEntry* entry = MakeGarbageCollected<VisibilityStateEntry>(
      PageHiddenStateString(!is_visible),
      MonotonicTimeToDOMHighResTimeStamp(timestamp), DomWindow());

  if (HasObserverFor(PerformanceEntry::kVisibilityState)) {
    NotifyObserversOfEntry(*entry);
  }

  if (visibility_state_buffer_.size() < kDefaultVisibilityStateEntrySize) {
    visibility_state_buffer_.push_back(entry);
  }
}

void WindowPerformance::AddSoftNavigationEntry(const AtomicString& name,
                                               base::TimeTicks timestamp) {
  if (!RuntimeEnabledFeatures::SoftNavigationHeuristicsEnabled(
          GetExecutionContext())) {
    return;
  }
  SoftNavigationEntry* entry = MakeGarbageCollected<SoftNavigationEntry>(
      name, MonotonicTimeToDOMHighResTimeStamp(timestamp), DomWindow());

  if (HasObserverFor(PerformanceEntry::kSoftNavigation)) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kSoftNavigationHeuristics);
    NotifyObserversOfEntry(*entry);
  }

  AddSoftNavigationToPerformanceTimeline(entry);
}

void WindowPerformance::PageVisibilityChanged() {
  PageVisibilityChangedWithTimestamp(base::TimeTicks::Now());
}

void WindowPerformance::PageVisibilityChangedWithTimestamp(
    base::TimeTicks visibility_change_timestamp) {
  // Only flush event timing data when page visibility changes from visible to
  // invisible.
  if (!GetPage()->IsPageVisible()) {
    last_hidden_timestamp_ = visibility_change_timestamp;

    if (RuntimeEnabledFeaturesBase::
            ReportEventTimingAtVisibilityChangeEnabled()) {
      FlushEventTimingsOnPageHidden();
    }
  }
  AddVisibilityStateEntry(GetPage()->IsPageVisible(),
                          visibility_change_timestamp);
}

void WindowPerformance::WillShowModalDialog() {
  show_modal_dialog_timestamps_.push_back(base::TimeTicks::Now());
}

EventCounts* WindowPerformance::eventCounts() {
  if (!event_counts_) {
    event_counts_ = MakeGarbageCollected<EventCounts>();
  }
  return event_counts_.Get();
}

uint64_t WindowPerformance::interactionCount() const {
  return responsiveness_metrics_->GetInteractionCount();
}

void WindowPerformance::OnLargestContentfulPaintUpdated(
    base::TimeTicks start_time,
    base::TimeTicks render_time,
    uint64_t paint_size,
    base::TimeTicks load_time,
    base::TimeTicks first_animated_frame_time,
    const AtomicString& id,
    const String& url,
    Element* element,
    bool is_triggered_by_soft_navigation) {
  DOMHighResTimeStamp load_timestamp =
      MonotonicTimeToDOMHighResTimeStamp(load_time);
  DOMHighResTimeStamp start_timestamp =
      RenderTimeToDOMHighResTimeStamp(start_time);
  DOMHighResTimeStamp render_timestamp =
      RenderTimeToDOMHighResTimeStamp(render_time);
  DOMHighResTimeStamp first_animated_frame_timestamp =
      RenderTimeToDOMHighResTimeStamp(first_animated_frame_time);

  // TODO(yoav): Should we modify start to represent the animated frame?
  auto* entry = MakeGarbageCollected<LargestContentfulPaint>(
      start_timestamp, render_timestamp, paint_size, load_timestamp,
      first_animated_frame_timestamp, id, url, element, DomWindow(),
      is_triggered_by_soft_navigation);

  AddRenderCoarsenedEntry(
      WTF::BindOnce(
          [](Persistent<LargestContentfulPaint> entry,
             Performance& performance) {
            WindowPerformance& window_performance =
                static_cast<WindowPerformance&>(performance);
            if (!window_performance.DomWindow()) {
              return;
            }

            if (performance.HasObserverFor(
                    PerformanceEntry::kLargestContentfulPaint)) {
              window_performance.NotifyObserversOfEntry(*entry);
            }
            performance.AddLargestContentfulPaint(entry);
            window_performance.DomWindow()
                ->document()
                ->OnLargestContentfulPaintUpdated();
          },
          WrapPersistent(entry)),
      render_timestamp);

  if (HTMLImageElement* image_element = DynamicTo<HTMLImageElement>(element)) {
    image_element->SetIsLCPElement();
    if (image_element->HasLazyLoadingAttribute()) {
      element->GetDocument().CountUse(WebFeature::kLCPImageWasLazy);
    }
  }

  if (element) {
    if (LocalFrame* local_frame = element->GetDocument().GetFrame()) {
      if (LCPCriticalPathPredictor* lcpp = local_frame->GetLCPP()) {
        std::optional<KURL> maybe_url = std::nullopt;
        if (!url.empty()) {
          maybe_url = KURL(url);
        }
        lcpp->OnLargestContentfulPaintUpdated(*element, maybe_url);
      }
    }
  }
}

void WindowPerformance::OnPaintFinished() {
  // The event processed after a paint will have different presentation time
  // than previous ones, so we need to register a new presentation promise for
  // it.
  need_new_promise_for_event_presentation_time_ = true;
}

void WindowPerformance::NotifyPotentialDrag(PointerId pointer_id) {
  responsiveness_metrics_->NotifyPotentialDrag(pointer_id);
}

void WindowPerformance::OnPageScroll() {
  autoscroll_active_ =
      GetPage()->GetAutoscrollController().SelectionAutoscrollInProgress();
}

bool WindowPerformance::IsAutoscrollActive() {
  return autoscroll_active_;
}

}  // namespace blink
```
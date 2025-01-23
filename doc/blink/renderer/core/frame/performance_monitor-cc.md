Response:
Let's break down the thought process for analyzing this `performance_monitor.cc` file.

1. **Understand the Core Purpose:** The file name itself, "performance_monitor.cc," is a strong clue. The likely purpose is to monitor performance-related events within the Blink rendering engine. Reading the initial comments confirms this, mentioning tracking violations of performance thresholds.

2. **Identify Key Data Structures:**  Skimming the class definition reveals important members:
    * `thresholds_`: An array of `base::TimeDelta`, suggesting storage for time limits for different performance violations.
    * `subscriptions_`: A `HashMap` likely used to store clients interested in specific performance violations and their individual thresholds. The value is `ClientThresholds`, which appears to be another `HashMap` linking clients to their thresholds. This immediately suggests a publish/subscribe pattern.
    * `local_root_`: A pointer to `LocalFrame`, indicating the monitor is associated with a specific frame or frame tree.
    * Flags like `enabled_`, `task_should_be_reported_`, `task_has_multiple_contexts_`, etc., point towards state management for different monitoring scenarios.

3. **Analyze Key Methods:** Now, let's look at the significant functions:

    * **`Threshold()`:** This static method appears to retrieve the global threshold for a specific violation type. The `InstrumentingMonitorExcludingLongTasks` call is interesting and hints at different monitoring modes.
    * **`ReportGenericViolation()`:** Another static method for reporting violations. It takes the context, violation type, description, time, and source location. This is a core reporting mechanism.
    * **`Monitor()`:**  A static method to get the `PerformanceMonitor` instance for a given `ExecutionContext`. This suggests a one-to-one relationship between a frame and its monitor.
    * **`InstrumentingMonitorExcludingLongTasks()`:** Returns the monitor only if it's enabled and not specifically for long tasks. This separation is important.
    * **Constructor/Destructor/`Dispose()`/`Shutdown()`:** Standard lifecycle management. The `Dispose()` comment highlights a past bug and a temporary workaround, which is a valuable detail. `Shutdown()` handles cleanup.
    * **`Subscribe()`/`UnsubscribeAll()`:**  These clearly implement the publish/subscribe pattern, allowing clients to register interest in specific violations.
    * **`UpdateInstrumentation()`:**  This recalculates the effective thresholds based on the subscriptions. It takes the minimum threshold among all subscribers for a given violation.
    * **`WillExecuteScript()`/`DidExecuteScript()`:**  Track script execution depth. Used for heuristics related to long task attribution.
    * **`UpdateTaskAttribution()`/`UpdateTaskShouldBeReported()`:**  Determine the context and reporting eligibility for a task, particularly for long tasks.
    * **`Will()`/`Did()` methods for `RecalculateStyle`, `UpdateLayout`, `ExecuteScript`, `CallFunction`, `V8Compile`, `UserCallback`:** These are instrumentation points using the `probe` system. They capture start and end times for various performance-sensitive operations. The `CallFunction` and `UserCallback` methods specifically target JavaScript event handlers.
    * **`DocumentWriteFetchScript()`:** Detects blocking parser situations due to `document.write(<script>)`.
    * **`WillProcessTask()`/`DidProcessTask()`:**  These methods are called at the beginning and end of a task. `DidProcessTask` is crucial for checking if a long task or long layout occurred and notifying subscribers.
    * **`InnerReportGenericViolation()`:**  The internal implementation for reporting violations, iterating through subscribers and checking their thresholds.
    * **`Trace()`:** For Blink's tracing infrastructure.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):** Now, connect the functionality to web technologies:

    * **JavaScript:** The `WillExecuteScript`, `DidExecuteScript`, `CallFunction`, `UserCallback` probes directly relate to JavaScript execution and event handling. The long task detection and reporting are particularly relevant to JavaScript performance.
    * **HTML:** The `DocumentWriteFetchScript` method directly addresses a specific HTML parsing behavior. The overall parsing and rendering pipeline, implicitly monitored by other probes, is essential for displaying HTML.
    * **CSS:** The `Will(RecalculateStyle)` and `Did(RecalculateStyle)` methods monitor the CSSOM recalculation process. `Will(UpdateLayout)` and `Did(UpdateLayout)` track layout calculations, both crucial for how CSS affects rendering.

5. **Identify Logical Inferences and Examples:**

    * **Thresholding:**  The code clearly uses thresholds. If an operation exceeds the threshold, a violation is reported. Example: If the long task threshold is 50ms, and a JavaScript task takes 70ms, a long task violation will be reported.
    * **Subscription:** Clients can subscribe to specific violation types with their own thresholds. Example: A dev tool might subscribe to long task violations with a 100ms threshold, while the browser itself might use a 50ms threshold for internal monitoring.
    * **Long Task Attribution:** The code attempts to attribute long tasks to specific frames, though it acknowledges limitations.

6. **Consider User/Programming Errors:**

    * **Long-running scripts:**  The most obvious user error leading to long task violations. Example: A complex, synchronous JavaScript function that blocks the main thread.
    * **Inefficient CSS:**  Complex CSS selectors or forced synchronous layout can lead to long layout times. Example:  Repeatedly querying layout information in a loop and then making style changes.
    * **`document.write()` after initial load:** This is explicitly flagged as a blocking parser issue. Example: Dynamically injecting a `<script>` tag using `document.write` after the page has initially loaded.
    * **Too many event handlers or slow handlers:**  The monitoring of `CallFunction` and `UserCallback` highlights the potential for slow event handlers to impact performance.

7. **Refine and Organize:**  Finally, structure the information clearly using headings, bullet points, and code examples where appropriate. Ensure that the explanation of each feature is concise and easy to understand. The goal is to provide a comprehensive yet digestible overview of the file's functionality.
This `performance_monitor.cc` file in the Chromium Blink engine implements a system for **monitoring and reporting performance-related events** within a web page. Its primary goal is to identify and flag situations where the browser's main thread is being held up for too long, leading to a janky or unresponsive user experience.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Defining and Managing Performance Thresholds:**
   - It defines thresholds for various types of performance violations (e.g., long tasks, long layouts, slow event handlers).
   - These thresholds are stored in the `thresholds_` array.
   - The `Threshold()` static method allows querying the current threshold for a specific violation type within a given execution context.

2. **Registering Clients for Performance Notifications (Subscription):**
   - The `Subscribe()` method allows different parts of the browser (or potentially extensions) to register their interest in specific performance violations.
   - When a violation occurs that exceeds the registered threshold for a client, the client is notified.
   - The `subscriptions_` `HashMap` stores these client registrations, associating each violation type with a list of interested clients and their respective thresholds.
   - `UnsubscribeAll()` allows a client to stop receiving notifications.

3. **Detecting and Reporting Performance Violations:**
   - It uses "probes" (instrumentation points within the Blink engine) to monitor different stages of the rendering pipeline, such as:
     - **Script Execution:** `WillExecuteScript()`, `DidExecuteScript()`
     - **Style Calculation:** `Will(const probe::RecalculateStyle&)`, `Did(const probe::RecalculateStyle&)`
     - **Layout Calculation:** `Will(const probe::UpdateLayout&)`, `Did(const probe::UpdateLayout&)`
     - **JavaScript Function Calls (Event Handlers):** `Will(const probe::CallFunction&)`, `Did(const probe::CallFunction&)`, `Will(const probe::UserCallback&)`, `Did(const probe::UserCallback&)`
     - **V8 Compilation:** `Will(const probe::V8Compile&)`, `Did(const probe::V8Compile&)`
   - When a monitored operation exceeds a defined threshold, methods like `InnerReportGenericViolation()` are used to record and potentially report the violation to subscribed clients.

4. **Tracking Long Tasks:**
   - It specifically tracks "long tasks," which are JavaScript execution periods that block the main thread for an extended duration.
   - The `WillProcessTask()` and `DidProcessTask()` methods mark the beginning and end of a task on the main thread.
   - In `DidProcessTask()`, it checks if the task duration exceeds the `kLongTask` threshold and reports it to subscribed clients.
   - It also attempts to attribute long tasks to a specific frame's execution context.

5. **Handling `document.write(<script>)`:**
   - The `DocumentWriteFetchScript()` method detects when `document.write()` is used to insert a `<script>` tag, which can block the HTML parser and negatively impact performance.

**Relationship with JavaScript, HTML, and CSS:**

The `PerformanceMonitor` is deeply intertwined with the execution of JavaScript, the rendering of HTML, and the application of CSS. Here are examples:

* **JavaScript:**
    - **Long Tasks:**  When JavaScript code executes for a long time (e.g., complex computations, synchronous network requests), the `PerformanceMonitor` detects this as a long task violation.
        - **Hypothetical Input:** A JavaScript function that performs a complex animation calculation on a large dataset without using `requestAnimationFrame`.
        - **Hypothetical Output:** If the execution time exceeds the `kLongTask` threshold, the `PerformanceMonitor` will report a long task violation, including the start and end times and potentially the execution context (frame).
    - **Slow Event Handlers:** If a JavaScript event handler (e.g., an `onclick` handler) takes too long to execute, it can be flagged as a slow handler violation.
        - **Hypothetical Input:** A button's `onclick` handler that performs a blocking AJAX request before updating the UI.
        - **Hypothetical Output:** If the handler's execution time exceeds the threshold for `kHandler` or `kRecurringHandler` (for recurring events), a violation will be reported, including the handler's name and execution time.
    - **`document.write(<script>)`:** When JavaScript uses `document.write()` to insert a `<script>` tag after the initial page load, it blocks the HTML parser.
        - **Hypothetical Input:**  JavaScript code like `document.write('<script src="another.js"></script>')` executed after the initial page load.
        - **Hypothetical Output:** The `DocumentWriteFetchScript()` method will be called, and a `kBlockedParser` violation will be reported.

* **HTML:**
    - **Parser Blocking:** The `DocumentWriteFetchScript()` functionality directly relates to how HTML is parsed.
    - **Layout Thrashing:** While not directly triggered by HTML content itself, inefficient JavaScript that causes repeated layout calculations can lead to `kLongLayout` violations. The HTML structure and the CSS applied to it influence how expensive layout calculations are.

* **CSS:**
    - **Long Layouts:** If the browser spends an excessive amount of time calculating the layout of the page (e.g., due to complex CSS selectors or forced synchronous layout), the `PerformanceMonitor` detects this as a `kLongLayout` violation.
        - **Hypothetical Input:** JavaScript code that reads layout information (e.g., `offsetWidth`, `offsetHeight`) in a loop and then modifies the DOM, forcing the browser to recalculate layout repeatedly.
        - **Hypothetical Output:** If the accumulated time spent in layout calculations during a task exceeds the `kLongLayout` threshold, a violation will be reported.

**Logical Inference and Examples:**

* **Threshold-Based Reporting:** The core logic revolves around comparing the duration of certain operations with predefined thresholds.
    - **Assumption:** A long task threshold is set to 50ms.
    - **Input:** A JavaScript function takes 70ms to execute.
    - **Output:** A long task violation will be reported.

* **Subscription Mechanism:**  Different components can have different sensitivities to performance issues.
    - **Assumption:** A developer tool subscribes to long task violations with a threshold of 100ms, while the browser's internal monitoring uses a 50ms threshold.
    - **Input:** A JavaScript task takes 80ms.
    - **Output:** The browser's internal monitoring will report a violation, but the developer tool will not.

**User or Programming Common Usage Errors:**

1. **Long-Running Synchronous JavaScript:**  Performing heavy computations or blocking network requests directly in the main thread. This leads to long task violations and freezes the UI.
   - **Example:**  A complex image processing algorithm implemented entirely synchronously in JavaScript.

2. **Inefficient CSS Selectors:** Using overly complex CSS selectors that force the browser to spend a lot of time matching elements. This contributes to long layout times.
   - **Example:**  Selectors with many nested levels and universal selectors, like `body * div#content > .item:nth-child(even) a`.

3. **Forced Synchronous Layout (Layout Thrashing):** Reading layout properties (e.g., `offsetWidth`, `offsetHeight`) and then immediately making changes that invalidate the layout, causing the browser to recalculate layout repeatedly in a short period.
   - **Example:**  A loop that iterates through elements, reads their dimensions, and then updates their styles based on those dimensions.

4. **Excessive Use of `document.write()` After Initial Load:**  This can significantly disrupt the parsing and rendering process, leading to a poor user experience.
   - **Example:** Dynamically injecting large amounts of HTML or `<script>` tags using `document.write()` after the initial page has loaded.

5. **Slow Event Handlers:**  Performing time-consuming operations within event handlers, making the UI unresponsive to user interactions.
   - **Example:**  An `onclick` handler that initiates a large file download or performs a complex DOM manipulation without yielding to the main thread.

In summary, `performance_monitor.cc` is a crucial component in Blink for identifying and flagging performance bottlenecks related to JavaScript execution, HTML parsing, and CSS rendering. It provides a mechanism for different parts of the browser to be notified of these issues, enabling further analysis and potential optimization.

### 提示词
```
这是目录为blink/renderer/core/frame/performance_monitor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/performance_monitor.h"

#include "base/format_macros.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/core/core_probe_sink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event_listener.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/parser/html_document_parser.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "v8/include/v8-metrics.h"

namespace blink {

// static
base::TimeDelta PerformanceMonitor::Threshold(ExecutionContext* context,
                                              Violation violation) {
  // Calling InstrumentingMonitorExcludingLongTasks wouldn't work properly if
  // this query is for longtasks.
  DCHECK(violation != kLongTask);
  PerformanceMonitor* monitor =
      PerformanceMonitor::InstrumentingMonitorExcludingLongTasks(context);
  return monitor ? monitor->thresholds_[violation] : base::TimeDelta();
}

// static
void PerformanceMonitor::ReportGenericViolation(
    ExecutionContext* context,
    Violation violation,
    const String& text,
    base::TimeDelta time,
    std::unique_ptr<SourceLocation> location) {
  // Calling InstrumentingMonitorExcludingLongTasks wouldn't work properly if
  // this is a longtask violation.
  DCHECK(violation != kLongTask);
  PerformanceMonitor* monitor =
      PerformanceMonitor::InstrumentingMonitorExcludingLongTasks(context);
  if (!monitor)
    return;
  monitor->InnerReportGenericViolation(context, violation, text, time,
                                       std::move(location));
}

// static
PerformanceMonitor* PerformanceMonitor::Monitor(
    const ExecutionContext* context) {
  const auto* window = DynamicTo<LocalDOMWindow>(context);
  if (!window)
    return nullptr;
  LocalFrame* frame = window->GetFrame();
  if (!frame)
    return nullptr;
  return frame->GetPerformanceMonitor();
}

// static
PerformanceMonitor* PerformanceMonitor::InstrumentingMonitorExcludingLongTasks(
    const ExecutionContext* context) {
  PerformanceMonitor* monitor = PerformanceMonitor::Monitor(context);
  return monitor && monitor->enabled_ ? monitor : nullptr;
}

PerformanceMonitor::PerformanceMonitor(LocalFrame* local_root,
                                       v8::Isolate* isolate)
    : local_root_(local_root), isolate_(isolate) {
  std::fill(std::begin(thresholds_), std::end(thresholds_), base::TimeDelta());
  Thread::Current()->AddTaskTimeObserver(this);
  local_root_->GetProbeSink()->AddPerformanceMonitor(this);
}

PerformanceMonitor::~PerformanceMonitor() {
  DCHECK(!local_root_);
}

void PerformanceMonitor::Dispose() {
  if (!was_shutdown_) {
    // `PerformanceMonitor` should never be deleted without having been
    // `Shutdown()`. As a temporary workaround for crbug.com/337200890,
    // unregister as a `TaskTimeObserver` if `Shutdown()` wasn't called.
    //
    // TODO(crbug.com/337200890): Remove when the root cause of the bug has been
    // addressed.
    Thread::Current()->RemoveTaskTimeObserver(this);
  }
}

void PerformanceMonitor::Subscribe(Violation violation,
                                   base::TimeDelta threshold,
                                   Client* client) {
  DCHECK(violation < kAfterLast);
  ClientThresholds* client_thresholds = nullptr;

  auto it = subscriptions_.find(violation);
  if (it == subscriptions_.end()) {
    client_thresholds = MakeGarbageCollected<ClientThresholds>();
    subscriptions_.Set(violation, client_thresholds);
  } else {
    client_thresholds = it->value;
  }

  client_thresholds->Set(client, threshold);
  UpdateInstrumentation();
}

void PerformanceMonitor::UnsubscribeAll(Client* client) {
  for (const auto& it : subscriptions_)
    it.value->erase(client);
  UpdateInstrumentation();
}

void PerformanceMonitor::Shutdown() {
  if (!local_root_)
    return;
  subscriptions_.clear();
  UpdateInstrumentation();
  Thread::Current()->RemoveTaskTimeObserver(this);
  local_root_->GetProbeSink()->RemovePerformanceMonitor(this);
  local_root_ = nullptr;
  was_shutdown_ = true;
}

void PerformanceMonitor::UpdateInstrumentation() {
  std::fill(std::begin(thresholds_), std::end(thresholds_), base::TimeDelta());

  for (const auto& it : subscriptions_) {
    Violation violation = static_cast<Violation>(it.key);
    ClientThresholds* client_thresholds = it.value;
    for (const auto& client_threshold : *client_thresholds) {
      if (thresholds_[violation].is_zero() ||
          thresholds_[violation] > client_threshold.value)
        thresholds_[violation] = client_threshold.value;
    }
  }

  static_assert(kLongTask == 0u,
                "kLongTask should be the first value in Violation for the "
                "|enabled_| definition below to be correct");
  // Since kLongTask is the first in |thresholds_|, we count from one after
  // begin(thresholds_).
  enabled_ = std::count(std::begin(thresholds_) + 1, std::end(thresholds_),
                        base::TimeDelta()) < static_cast<int>(kAfterLast) - 1;
}

void PerformanceMonitor::WillExecuteScript(ExecutionContext* context) {
  // Heuristic for minimal frame context attribution: note the frame context
  // for each script execution. When a long task is encountered,
  // if there is only one frame context involved, then report it.
  // Otherwise don't report frame context.
  // NOTE: This heuristic is imperfect and will be improved in V2 API.
  // In V2, timing of script execution along with style & layout updates will be
  // accounted for detailed and more accurate attribution.
  ++script_depth_;
  UpdateTaskAttribution(context);
}

void PerformanceMonitor::DidExecuteScript() {
  --script_depth_;
}

void PerformanceMonitor::UpdateTaskAttribution(ExecutionContext* context) {
  // If |context| is not a window, unable to attribute a frame context.
  auto* window = DynamicTo<LocalDOMWindow>(context);
  if (!window)
    return;

  UpdateTaskShouldBeReported(window->GetFrame());
  if (!task_execution_context_)
    task_execution_context_ = context;
  else if (task_execution_context_ != context)
    task_has_multiple_contexts_ = true;
}

void PerformanceMonitor::UpdateTaskShouldBeReported(LocalFrame* frame) {
  if (frame && local_root_ == &(frame->LocalFrameRoot()))
    task_should_be_reported_ = true;
}

void PerformanceMonitor::Will(const probe::RecalculateStyle& probe) {
  UpdateTaskShouldBeReported(probe.document ? probe.document->GetFrame()
                                            : nullptr);
  if (enabled_ && !thresholds_[kLongLayout].is_zero() && script_depth_) {
    probe.CaptureStartTime();
  }
}

void PerformanceMonitor::Did(const probe::RecalculateStyle& probe) {
  if (enabled_ && script_depth_ && !thresholds_[kLongLayout].is_zero()) {
    per_task_style_and_layout_time_ += probe.Duration();
  }
}

void PerformanceMonitor::Will(const probe::UpdateLayout& probe) {
  UpdateTaskShouldBeReported(probe.document ? probe.document->GetFrame()
                                            : nullptr);
  ++layout_depth_;
  if (!enabled_)
    return;
  if (layout_depth_ > 1 || !script_depth_ || thresholds_[kLongLayout].is_zero())
    return;

  probe.CaptureStartTime();
}

void PerformanceMonitor::Did(const probe::UpdateLayout& probe) {
  --layout_depth_;
  if (!enabled_)
    return;
  if (!thresholds_[kLongLayout].is_zero() && script_depth_ && !layout_depth_)
    per_task_style_and_layout_time_ += probe.Duration();
}

void PerformanceMonitor::Will(const probe::ExecuteScript& probe) {
  WillExecuteScript(probe.context);
}

void PerformanceMonitor::Did(const probe::ExecuteScript& probe) {
  DidExecuteScript();
}

void PerformanceMonitor::Will(const probe::CallFunction& probe) {
  WillExecuteScript(probe.context);
  if (user_callback_)
    probe.CaptureStartTime();
}

void PerformanceMonitor::Did(const probe::CallFunction& probe) {
  DidExecuteScript();
  if (!enabled_ || !user_callback_)
    return;

  // Working around Oilpan - probes are STACK_ALLOCATED.
  const probe::UserCallback* user_callback =
      static_cast<const probe::UserCallback*>(user_callback_);
  Violation handler_type =
      user_callback->recurring ? kRecurringHandler : kHandler;
  base::TimeDelta threshold = thresholds_[handler_type];
  base::TimeDelta duration = probe.Duration();
  if (threshold.is_zero() || duration < threshold)
    return;

  String name = user_callback->name ? String(user_callback->name)
                                    : String(user_callback->atomic_name);
  String text = String::Format("'%s' handler took %" PRId64 "ms",
                               name.Utf8().c_str(), duration.InMilliseconds());
  InnerReportGenericViolation(
      probe.context, handler_type, text, duration,
      CaptureSourceLocation(probe.context->GetIsolate(), probe.function));
}

void PerformanceMonitor::Will(const probe::V8Compile& probe) {
  UpdateTaskAttribution(probe.context);
}

void PerformanceMonitor::Did(const probe::V8Compile& probe) {}

void PerformanceMonitor::Will(const probe::UserCallback& probe) {
  ++user_callback_depth_;
  UpdateTaskAttribution(probe.context);
  if (!enabled_ || user_callback_depth_ != 1 ||
      thresholds_[probe.recurring ? kRecurringHandler : kHandler].is_zero())
    return;

  DCHECK(!user_callback_);
  user_callback_ = &probe;
}

void PerformanceMonitor::Did(const probe::UserCallback& probe) {
  --user_callback_depth_;
  if (!user_callback_depth_)
    user_callback_ = nullptr;
  DCHECK(user_callback_ != &probe);
}

void PerformanceMonitor::DocumentWriteFetchScript(Document* document) {
  if (!enabled_)
    return;
  String text = "Parser was blocked due to document.write(<script>)";
  InnerReportGenericViolation(document->GetExecutionContext(), kBlockedParser,
                              text, base::TimeDelta(), nullptr);
}

void PerformanceMonitor::WillProcessTask(base::TimeTicks start_time) {
  // Reset m_taskExecutionContext. We don't clear this in didProcessTask
  // as it is needed in ReportTaskTime which occurs after didProcessTask.
  // Always reset variables needed for longtasks, regardless of the value of
  // |enabled_|.
  task_execution_context_ = nullptr;
  task_has_multiple_contexts_ = false;
  task_should_be_reported_ = false;
  v8::metrics::LongTaskStats::Reset(isolate_);

  if (!enabled_)
    return;

  // Reset everything for regular and nested tasks.
  script_depth_ = 0;
  layout_depth_ = 0;
  per_task_style_and_layout_time_ = base::TimeDelta();
  user_callback_ = nullptr;
}

void PerformanceMonitor::DidProcessTask(base::TimeTicks start_time,
                                        base::TimeTicks end_time) {
  if (!task_should_be_reported_)
    return;

  // Do not check the value of |enabled_| before processing longtasks.
  // |enabled_| can be false while there are subscriptions to longtask
  // violations.
  if (!thresholds_[kLongTask].is_zero()) {
    base::TimeDelta task_time = end_time - start_time;
    if (task_time > thresholds_[kLongTask]) {
      auto subscriptions_it = subscriptions_.find(kLongTask);
      if (subscriptions_it != subscriptions_.end()) {
        ClientThresholds* client_thresholds = subscriptions_it->value;
        DCHECK(client_thresholds);

        for (const auto& it : *client_thresholds) {
          if (it.value < task_time) {
            it.key->ReportLongTask(
                start_time, end_time,
                task_has_multiple_contexts_ ? nullptr : task_execution_context_,
                task_has_multiple_contexts_);
          }
        }
      }
    }
  }

  if (!enabled_)
    return;

  base::TimeDelta layout_threshold = thresholds_[kLongLayout];
  base::TimeDelta layout_time = per_task_style_and_layout_time_;
  if (!layout_threshold.is_zero() && layout_time > layout_threshold) {
    ClientThresholds* client_thresholds = subscriptions_.at(kLongLayout);
    DCHECK(client_thresholds);
    for (const auto& it : *client_thresholds) {
      if (it.value < layout_time)
        it.key->ReportLongLayout(layout_time);
    }
  }
}

void PerformanceMonitor::InnerReportGenericViolation(
    ExecutionContext* context,
    Violation violation,
    const String& text,
    base::TimeDelta time,
    std::unique_ptr<SourceLocation> location) {
  auto subscriptions_it = subscriptions_.find(violation);
  if (subscriptions_it == subscriptions_.end())
    return;

  if (!location)
    location = CaptureSourceLocation(context);

  ClientThresholds* client_thresholds = subscriptions_it->value;
  for (const auto& it : *client_thresholds) {
    if (it.value < time)
      it.key->ReportGenericViolation(violation, text, time, location.get());
  }
}

void PerformanceMonitor::Trace(Visitor* visitor) const {
  visitor->Trace(local_root_);
  visitor->Trace(task_execution_context_);
  visitor->Trace(subscriptions_);
}

}  // namespace blink
```
Response:
Let's break down the thought process for analyzing this `dom_timer.cc` file.

1. **Understand the Core Purpose:** The filename and the initial copyright notice hint at timer functionality. The `#include "third_party/blink/renderer/core/scheduler/dom_timer.h"` confirms this is the implementation file for `DOMTimer`. The term "DOM" suggests interaction with the Document Object Model, hinting at web browser functionality.

2. **Identify Key Responsibilities:**  Scan the code for major classes and functions. The `DOMTimer` class itself is obviously central. The `DOMTimerCoordinator` class also stands out as it manages a collection of `DOMTimer` objects. Functions like `setTimeout`, `setInterval`, `clearTimeout`, and `clearInterval` are clearly the entry points for users (via JavaScript). The `Fired()` method is likely the internal handler when a timer expires.

3. **Analyze `DOMTimerCoordinator`:** This class manages timer IDs and the nesting level. Its `Install` method assigns unique IDs, and `RemoveTimeoutByID` clears timers. The `timer_nesting_level_` variable is crucial for understanding the timer throttling mechanism.

4. **Deep Dive into `DOMTimer`:**
    * **Constructor:**  Pay close attention to the parameters: `ExecutionContext`, `ScheduledAction`, `timeout`, and `single_shot`. Notice how it interacts with `DOMTimerCoordinator` to get an ID and initial nesting level. The logic for adjusting the timeout based on nesting level and the minimum interval is important. The `TaskType` selection is relevant to scheduling within the browser.
    * **`Fired()`:** This is the heart of timer execution. It retrieves the `ScheduledAction`, executes it, and handles the differences between `setTimeout` and `setInterval`. The nesting level adjustments here are also critical. The logic for removing the timer after execution (`setTimeout`) vs. rescheduling (`setInterval`) is key.
    * **`Stop()` and `Dispose()`:**  These deal with cleaning up resources when a timer is cancelled or the associated context is destroyed. The disconnection from the `ExecutionContext` is important for preventing leaks.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `setTimeout` and `setInterval` functions in this C++ code directly implement the JavaScript functions of the same name. The arguments (`handler`, `timeout`, `arguments`) correspond to the JavaScript function parameters. The `clearTimeout` and `clearInterval` functions also directly map.
    * **HTML:** Timers are often used to manipulate the DOM (e.g., changing content, hiding/showing elements). The `ExecutionContext` is tied to a document or a worker.
    * **CSS:**  While timers don't directly manipulate CSS properties in the same way they do DOM elements, they can trigger JavaScript that *does* change CSS (e.g., adding/removing classes, changing inline styles).

6. **Identify Logic and Assumptions:**
    * **Nesting Level:** The concept of `kMaxTimerNestingLevel` and how the timeout is adjusted based on it is a crucial piece of logic. The assumption is that deeply nested or rapidly repeating timers might be resource-intensive and should be throttled.
    * **Minimum Interval:** The `kMinimumInterval` (4ms) is another deliberate constraint to prevent overly aggressive timers.
    * **Task Types:** The assignment of different `TaskType` values indicates different priority or scheduling strategies within the Chromium scheduler.

7. **Consider User/Programming Errors:**
    * **Incorrect `timeout` value:**  Setting a negative timeout is handled, but setting it to zero can have different interpretations.
    * **Forgetting to `clearTimeout`/`clearInterval`:** This can lead to unintended function executions and resource leaks, especially with `setInterval`.
    * **Infinite loops in timer callbacks:** A common mistake that can freeze the browser.
    * **Closures and variable scope:**  A JavaScript-specific issue where developers might not understand how variables are captured within timer callbacks.

8. **Structure the Output:** Organize the findings into clear categories as requested by the prompt:
    * Functionality: A high-level overview.
    * Relationship with JavaScript/HTML/CSS: Provide concrete examples.
    * Logic and Assumptions: Explain the reasoning behind specific parts of the code.
    * Common Errors:  Illustrate potential pitfalls for developers.

9. **Refine and Elaborate:** Review the initial analysis and add more detail or clarity where needed. For example, explaining *why* timer throttling is necessary is helpful. Providing specific code examples makes the explanations more concrete. Ensuring the input/output examples are meaningful is important.

This step-by-step approach helps to systematically understand a complex piece of code and extract the relevant information. It involves reading the code, understanding the underlying concepts (like event loops and scheduling), and connecting it to the broader context of web development.
好的，让我们来详细分析一下 `blink/renderer/core/scheduler/dom_timer.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能概述:**

`dom_timer.cc` 文件主要负责实现 HTML 规范中定义的 `setTimeout` 和 `setInterval` 这两个 Web API。它管理着页面中的定时器，负责在指定的延迟后执行 JavaScript 代码，或者按照指定的时间间隔重复执行 JavaScript 代码。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件是浏览器核心功能的一部分，直接关联着 JavaScript 和 HTML。CSS 间接相关，因为定时器触发的 JavaScript 代码可能会修改 CSS 样式。

* **与 JavaScript 的关系：**
    * **`setTimeout(function, delay)`:**  `DOMTimer::setTimeout` 方法实现了这个 JavaScript 函数的功能。当 JavaScript 代码调用 `setTimeout` 时，Blink 引擎会创建一个 `DOMTimer` 对象，并将要执行的 JavaScript 函数 (`handler`) 和延迟时间 (`timeout`) 存储起来。
        * **例子:** `setTimeout(() => { console.log("Hello after 1 second"); }, 1000);`  在这个例子中，`DOMTimer::setTimeout` 会创建一个定时器，在 1000 毫秒后执行 `console.log("Hello after 1 second")` 这段 JavaScript 代码。
    * **`setInterval(function, delay)`:** `DOMTimer::setInterval` 方法实现了这个 JavaScript 函数的功能。它与 `setTimeout` 类似，但会重复执行指定的 JavaScript 函数，直到被 `clearInterval` 清除。
        * **例子:** `setInterval(() => { console.log("Tick every 2 seconds"); }, 2000);`  `DOMTimer::setInterval` 会创建一个定时器，每隔 2000 毫秒执行一次 `console.log("Tick every 2 seconds")`。
    * **`clearTimeout(id)` 和 `clearInterval(id)`:** `DOMTimer::clearTimeout` 和 `DOMTimer::clearInterval` 方法实现了这两个 JavaScript 函数。它们用于取消之前通过 `setTimeout` 或 `setInterval` 创建的定时器。
        * **例子:**
          ```javascript
          let timerId = setTimeout(() => { console.log("Will not be executed"); }, 5000);
          clearTimeout(timerId);
          ```
          在这个例子中，`clearTimeout` 会阻止 `setTimeout` 设置的回调函数被执行。

* **与 HTML 的关系：**
    * 定时器通常与 HTML 文档中的事件或状态变化相关联。例如，用户点击按钮后启动一个定时器，或者页面加载完成后执行某些动画。
        * **例子:**
          ```html
          <button id="myButton">Start Timer</button>
          <script>
            document.getElementById('myButton').addEventListener('click', () => {
              setTimeout(() => { alert('Button clicked after 2 seconds!'); }, 2000);
            });
          </script>
          ```
          当用户点击按钮后，`setTimeout` 会在 2 秒后弹出一个警告框。
    * 定时器的作用域与 `ExecutionContext` 相关，这通常对应于一个 HTML 文档或 Worker。

* **与 CSS 的关系（间接）：**
    * 定时器触发的 JavaScript 代码经常用于动态修改 HTML 元素的 CSS 样式，实现动画、延迟显示等效果。
        * **例子:**
          ```html
          <div id="myDiv" style="opacity: 0;">This will fade in.</div>
          <script>
            let opacity = 0;
            let timer = setInterval(() => {
              opacity += 0.1;
              document.getElementById('myDiv').style.opacity = opacity;
              if (opacity >= 1) {
                clearInterval(timer);
              }
            }, 100);
          </script>
          ```
          这个例子使用 `setInterval` 逐步增加 `div` 元素的透明度，实现淡入效果。

**逻辑推理及假设输入与输出:**

* **假设输入:** JavaScript 代码调用 `setTimeout(() => { console.log("Delayed"); }, 100);`
* **逻辑推理:**
    1. `DOMTimer::setTimeout` 被调用，创建一个 `DOMTimer` 对象。
    2. 定时器的 `timeout` 被设置为 100 毫秒。
    3. `ScheduledAction` 对象被创建，封装了要执行的 JavaScript 代码。
    4. 定时器被注册到调度器中。
    5. 经过大约 100 毫秒后，调度器触发定时器。
    6. `DOMTimer::Fired` 方法被调用。
    7. `ScheduledAction::Execute` 方法执行 `console.log("Delayed");`。
* **输出:**  大约 100 毫秒后，控制台会输出 "Delayed"。

* **假设输入:** JavaScript 代码调用 `setInterval(() => { counter++; }, 500);`，然后调用 `clearInterval(timerId);`
* **逻辑推理:**
    1. `DOMTimer::setInterval` 被调用，创建一个 `DOMTimer` 对象。
    2. 定时器的 `timeout` 被设置为 500 毫秒，并且是重复执行的。
    3. `ScheduledAction` 对象被创建。
    4. 定时器被注册到调度器。
    5. 假设在定时器触发几次后，`clearInterval` 被调用，传入了该定时器的 `timeout_id_`。
    6. `DOMTimer::clearTimeout` (或 `clearInterval`) 被调用。
    7. `DOMTimerCoordinator::RemoveTimeoutByID` 方法根据 `timeout_id_` 找到对应的 `DOMTimer` 对象并停止它。
* **输出:** 定时器停止执行，`counter` 的值不再被定期递增。

**用户或编程常见的使用错误及举例说明:**

* **忘记清除 `setInterval` 创建的定时器:** 如果不调用 `clearInterval`，`setInterval` 会一直执行下去，可能导致性能问题或意料之外的行为。
    * **例子:**
      ```javascript
      setInterval(() => {
        console.log("This will keep printing forever if not cleared.");
      }, 1000);
      ```
      应该在不需要定时器时调用 `clearInterval` 来停止它。

* **在字符串形式的 `setTimeout` 或 `setInterval` 中使用 `eval` 相关的代码:**  这可能导致安全风险，并且违反了内容安全策略 (CSP)。
    * **例子:**
      ```javascript
      setTimeout("alert('This is generally discouraged')", 1000); // 不推荐
      ```
      推荐使用函数形式：
      ```javascript
      setTimeout(() => { alert('This is the preferred way'); }, 1000);
      ```

* **假设定时器会精确地在指定时间执行:** 由于浏览器的调度机制和主线程的繁忙程度，定时器的执行时间可能会有一定的延迟，尤其是在高负载情况下。

* **在 `beforeunload` 或 `unload` 事件处理程序中创建过多的定时器:** 这可能会干扰浏览器的卸载过程，导致性能问题或页面无法正常卸载。代码中 `IsAllowed` 函数检查了这种情况，并会记录相应的 WebFeature 使用计数。

* **混淆 `setTimeout` 和 `setInterval` 的用途:** `setTimeout` 用于延迟执行一次代码，而 `setInterval` 用于重复执行代码。错误地使用会导致不期望的行为。

* **在闭包中使用错误的变量引用:**  尤其在使用 `var` 声明变量时，可能会导致在定时器回调函数中访问到意料之外的变量值。推荐使用 `let` 或 `const` 来避免此类问题。
    * **例子:**
      ```javascript
      for (var i = 1; i <= 5; i++) {
        setTimeout(function() {
          console.log(i); // 可能会输出多次 6，而不是 1 到 5
        }, i * 1000);
      }
      ```
      应该使用闭包或 `let` 来捕获每次循环的 `i` 值。

**总结:**

`dom_timer.cc` 是 Blink 引擎中一个至关重要的文件，它实现了 Web 开发者常用的定时器功能。理解其工作原理、与 JavaScript/HTML/CSS 的关系以及常见的使用错误，对于编写高效且可靠的 Web 应用至关重要。该文件中的代码还涉及到浏览器内部的调度机制、安全策略以及性能优化等方面。

### 提示词
```
这是目录为blink/renderer/core/scheduler/dom_timer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2008 Apple Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "third_party/blink/renderer/core/scheduler/dom_timer.h"

#include <limits>

#include "base/check_deref.h"
#include "base/message_loop/message_pump.h"
#include "base/numerics/clamped_math.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/core_probes_inl.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/page_dismissal_scope.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/scheduler/scheduled_action.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/scheduler/public/scheduling_policy.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"

namespace blink {

namespace {

// Step 11 of the algorithm at
// https://html.spec.whatwg.org/multipage/timers-and-user-prompts.html requires
// that a timeout less than 4ms is increased to 4ms when the nesting level is
// greater than 5.
constexpr int kMaxTimerNestingLevel = 5;
constexpr base::TimeDelta kMinimumInterval = base::Milliseconds(4);

base::TimeDelta GetMaxHighResolutionInterval() {
  return base::MessagePump::GetAlignWakeUpsEnabled() &&
                 base::FeatureList::IsEnabled(
                     features::kLowerHighResolutionTimerThreshold)
             ? base::Milliseconds(4)
             : base::Milliseconds(32);
}

// Maintains a set of DOMTimers for a given ExecutionContext. Assigns IDs to
// timers; these IDs are the ones returned to web authors from setTimeout or
// setInterval. It also tracks recursive creation or iterative scheduling of
// timers, which is used as a signal for throttling repetitive timers.
class DOMTimerCoordinator : public GarbageCollected<DOMTimerCoordinator>,
                            public Supplement<ExecutionContext> {
 public:
  constexpr static const char kSupplementName[] = "DOMTimerCoordinator";

  static DOMTimerCoordinator& From(ExecutionContext& context) {
    CHECK(!context.IsWorkletGlobalScope());
    auto* coordinator =
        Supplement<ExecutionContext>::From<DOMTimerCoordinator>(context);
    if (!coordinator) {
      coordinator = MakeGarbageCollected<DOMTimerCoordinator>(context);
      Supplement<ExecutionContext>::ProvideTo(context, coordinator);
    }
    return *coordinator;
  }

  explicit DOMTimerCoordinator(ExecutionContext& context)
      : Supplement<ExecutionContext>(context) {}

  int Install(DOMTimer* timer) {
    int timeout_id = NextID();
    timers_.insert(timeout_id, timer);
    return timeout_id;
  }

  // Removes and disposes the timer with the specified ID, if any. This may
  // destroy the timer.
  DOMTimer* RemoveTimeoutByID(int timeout_id) {
    if (timeout_id <= 0) {
      return nullptr;
    }
    DOMTimer* removed_timer = timers_.Take(timeout_id);
    if (removed_timer) {
      removed_timer->Stop();
    }
    return removed_timer;
  }

  // Timers created during the execution of other timers, and
  // repeating timers, are throttled. Timer nesting level tracks the
  // number of linked timers or repetitions of a timer. See
  // https://html.spec.whatwg.org/C/#timers
  int TimerNestingLevel() { return timer_nesting_level_; }

  // Sets the timer nesting level. Set when a timer executes so that
  // any timers created while the timer is executing will incur a
  // deeper timer nesting level, see DOMTimer::DOMTimer.
  void SetTimerNestingLevel(int level) { timer_nesting_level_ = level; }

  void Trace(Visitor* visitor) const final {
    visitor->Trace(timers_);
    Supplement<ExecutionContext>::Trace(visitor);
  }

 private:
  int NextID() {
    while (true) {
      if (circular_sequential_id_ == std::numeric_limits<int>::max()) {
        circular_sequential_id_ = 1;
      } else {
        ++circular_sequential_id_;
      }

      if (!timers_.Contains(circular_sequential_id_)) {
        return circular_sequential_id_;
      }
    }
  }

  HeapHashMap<int, Member<DOMTimer>> timers_;
  int circular_sequential_id_ = 0;
  int timer_nesting_level_ = 0;
};

bool IsAllowed(ExecutionContext& context, bool is_eval, const String& source) {
  if (context.IsContextDestroyed()) {
    return false;
  }
  if (is_eval && !context.GetContentSecurityPolicy()->AllowEval(
                     ReportingDisposition::kReport,
                     ContentSecurityPolicy::kWillNotThrowException, source)) {
    return false;
  }
  if (auto* window = DynamicTo<LocalDOMWindow>(context);
      window && PageDismissalScope::IsActive()) {
    UseCounter::Count(window, window->document()->ProcessingBeforeUnload()
                                  ? WebFeature::kTimerInstallFromBeforeUnload
                                  : WebFeature::kTimerInstallFromUnload);
  }
  return true;
}

}  // namespace

int DOMTimer::setTimeout(ScriptState* script_state,
                         ExecutionContext& context,
                         V8Function* handler,
                         int timeout,
                         const HeapVector<ScriptValue>& arguments) {
  if (!IsAllowed(context, false, g_empty_string)) {
    return 0;
  }
  auto* action = MakeGarbageCollected<ScheduledAction>(script_state, context,
                                                       handler, arguments);
  return MakeGarbageCollected<DOMTimer>(context, action,
                                        base::Milliseconds(timeout), true)
      ->timeout_id_;
}

int DOMTimer::setTimeout(ScriptState* script_state,
                         ExecutionContext& context,
                         const String& handler,
                         int timeout,
                         const HeapVector<ScriptValue>&) {
  if (!IsAllowed(context, true, handler)) {
    return 0;
  }
  // Don't allow setting timeouts to run empty functions.  Was historically a
  // performance issue.
  if (handler.empty()) {
    return 0;
  }
  auto* action =
      MakeGarbageCollected<ScheduledAction>(script_state, context, handler);
  return MakeGarbageCollected<DOMTimer>(context, action,
                                        base::Milliseconds(timeout), true)
      ->timeout_id_;
}

int DOMTimer::setInterval(ScriptState* script_state,
                          ExecutionContext& context,
                          V8Function* handler,
                          int timeout,
                          const HeapVector<ScriptValue>& arguments) {
  if (!IsAllowed(context, false, g_empty_string)) {
    return 0;
  }
  auto* action = MakeGarbageCollected<ScheduledAction>(script_state, context,
                                                       handler, arguments);
  return MakeGarbageCollected<DOMTimer>(context, action,
                                        base::Milliseconds(timeout), false)
      ->timeout_id_;
}

int DOMTimer::setInterval(ScriptState* script_state,
                          ExecutionContext& context,
                          const String& handler,
                          int timeout,
                          const HeapVector<ScriptValue>&) {
  if (!IsAllowed(context, true, handler)) {
    return 0;
  }
  // Don't allow setting timeouts to run empty functions.  Was historically a
  // performance issue.
  if (handler.empty()) {
    return 0;
  }
  auto* action =
      MakeGarbageCollected<ScheduledAction>(script_state, context, handler);
  return MakeGarbageCollected<DOMTimer>(context, action,
                                        base::Milliseconds(timeout), false)
      ->timeout_id_;
}

void DOMTimer::clearTimeout(ExecutionContext& context, int timeout_id) {
  RemoveByID(context, timeout_id);
}

void DOMTimer::clearInterval(ExecutionContext& context, int timeout_id) {
  RemoveByID(context, timeout_id);
}

void DOMTimer::RemoveByID(ExecutionContext& context, int timeout_id) {
  DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT(
      "TimerRemove", inspector_timer_remove_event::Data, &context, timeout_id);
  // Eagerly unregister as ExecutionContext observer.
  if (DOMTimer* timer =
          DOMTimerCoordinator::From(context).RemoveTimeoutByID(timeout_id)) {
    // Eagerly unregister as ExecutionContext observer.
    timer->SetExecutionContext(nullptr);
  }
}

DOMTimer::DOMTimer(ExecutionContext& context,
                   ScheduledAction* action,
                   base::TimeDelta timeout,
                   bool single_shot)
    : ExecutionContextLifecycleObserver(&context),
      TimerBase(nullptr),
      timeout_id_(DOMTimerCoordinator::From(context).Install(this)),
      // Step 9:
      nesting_level_(DOMTimerCoordinator::From(context).TimerNestingLevel()),
      action_(action) {
  DCHECK_GT(timeout_id_, 0);

  // Step 10:
  if (timeout.is_negative()) {
    timeout = base::TimeDelta();
  }

  // Steps 12 and 13:
  // Note: The implementation increments the nesting level before using it to
  // adjust timeout, contrary to what the spec requires crbug.com/1108877.
  IncrementNestingLevel();

  // A timer with a long timeout probably doesn't need to run at a precise time,
  // so allow some leeway on it. On the other hand, a timer with a short timeout
  // may need to run on time to deliver the best user experience.
  // TODO(crbug.com/1153139): Remove IsAlignWakeUpsDisabledForProcess() in M121
  // once workaround is no longer needed by WebRTC apps.
  bool precise = (timeout < GetMaxHighResolutionInterval()) ||
                 scheduler::IsAlignWakeUpsDisabledForProcess();

  // Step 11:
  // Note: The implementation uses >= instead of >, contrary to what the spec
  // requires crbug.com/1108877.
  if (nesting_level_ >= kMaxTimerNestingLevel && timeout < kMinimumInterval) {
    timeout = kMinimumInterval;
  }

  // Select TaskType based on nesting level.
  TaskType task_type;
  if (nesting_level_ >= kMaxTimerNestingLevel) {
    task_type = TaskType::kJavascriptTimerDelayedHighNesting;
  } else if (timeout.is_zero()) {
    task_type = TaskType::kJavascriptTimerImmediate;
    DCHECK_LT(nesting_level_, kMaxTimerNestingLevel);
  } else {
    task_type = TaskType::kJavascriptTimerDelayedLowNesting;
  }
  MoveToNewTaskRunner(context.GetTaskRunner(task_type));

  // Clamping up to 1ms for historical reasons crbug.com/402694.
  // Removing clamp for single_shot behind a feature flag.
  if (!single_shot || !blink::features::IsSetTimeoutWithoutClampEnabled()) {
    timeout = std::max(timeout, base::Milliseconds(1));
  }

  if (single_shot) {
    StartOneShot(timeout, FROM_HERE, precise);
  } else {
    StartRepeating(timeout, FROM_HERE, precise);
  }

  DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT(
      "TimerInstall", inspector_timer_install_event::Data, &context,
      timeout_id_, timeout, single_shot);
  const char* name = single_shot ? "setTimeout" : "setInterval";
  async_task_context_.Schedule(&context, name);
  probe::BreakableLocation(&context, name);
}

DOMTimer::~DOMTimer() = default;

void DOMTimer::Dispose() {
  Stop();
}

void DOMTimer::Stop() {
  if (!action_) {
    return;
  }

  async_task_context_.Cancel();
  const bool is_interval = !RepeatInterval().is_zero();
  probe::BreakableLocation(GetExecutionContext(),
                           is_interval ? "clearInterval" : "clearTimeout");

  // Need to release JS objects potentially protected by ScheduledAction
  // because they can form circular references back to the ExecutionContext
  // which will cause a memory leak.
  if (action_) {
    action_->Dispose();
  }
  action_ = nullptr;
  TimerBase::Stop();
}

void DOMTimer::ContextDestroyed() {
  Stop();
}

void DOMTimer::Fired() {
  ExecutionContext* context = GetExecutionContext();
  DCHECK(context);
  DOMTimerCoordinator::From(*context).SetTimerNestingLevel(nesting_level_);
  DCHECK(!context->IsContextPaused());
  // Only the first execution of a multi-shot timer should get an affirmative
  // user gesture indicator.

  DEVTOOLS_TIMELINE_TRACE_EVENT("TimerFire", inspector_timer_fire_event::Data,
                                context, timeout_id_);
  const bool is_interval = !RepeatInterval().is_zero();

  probe::UserCallback probe(context, is_interval ? "setInterval" : "setTimeout",
                            g_null_atom, true);
  probe::InvokeCallback invoke_probe(
      CHECK_DEREF(action_->GetScriptState()),
      is_interval ? "TimerHandler:setInterval" : "TimerHandler:setTimeout",
      action_->CallbackFunction());
  probe::AsyncTask async_task(context, &async_task_context_,
                              is_interval ? "fired" : nullptr);

  // Simple case for non-one-shot timers.
  if (IsActive()) {
    DCHECK(is_interval);

    // Steps 12 and 13:
    // Note: The implementation increments the nesting level before using it to
    // adjust timeout, contrary to what the spec requires crbug.com/1108877.
    IncrementNestingLevel();

    // Step 11:
    // Make adjustments when the nesting level becomes >= |kMaxNestingLevel|.
    // Note: The implementation uses >= instead of >, contrary to what the spec
    // requires crbug.com/1108877.
    if (nesting_level_ == kMaxTimerNestingLevel &&
        RepeatInterval() < kMinimumInterval) {
      AugmentRepeatInterval(kMinimumInterval - RepeatInterval());
    }
    if (nesting_level_ == kMaxTimerNestingLevel) {
      // Move to the TaskType that corresponds to nesting level >=
      // |kMaxNestingLevel|.
      MoveToNewTaskRunner(
          context->GetTaskRunner(TaskType::kJavascriptTimerDelayedHighNesting));
    }

    DCHECK(nesting_level_ < kMaxTimerNestingLevel ||
           RepeatInterval() >= kMinimumInterval);

    // No access to member variables after this point, it can delete the timer.
    action_->Execute(context);

    DOMTimerCoordinator::From(*context).SetTimerNestingLevel(0);

    return;
  }

  // Unregister the timer from ExecutionContext before executing the action
  // for one-shot timers.
  ScheduledAction* action = action_.Release();
  DOMTimerCoordinator::From(*context).RemoveTimeoutByID(timeout_id_);

  action->Execute(context);

  // Eagerly clear out |action|'s resources.
  action->Dispose();

  // ExecutionContext might be already gone when we executed action->execute().
  ExecutionContext* execution_context = GetExecutionContext();
  if (!execution_context) {
    return;
  }

  DOMTimerCoordinator::From(*execution_context).SetTimerNestingLevel(0);
  // Eagerly unregister as ExecutionContext observer.
  SetExecutionContext(nullptr);
}

void DOMTimer::Trace(Visitor* visitor) const {
  visitor->Trace(action_);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void DOMTimer::IncrementNestingLevel() {
  nesting_level_ = base::ClampAdd(nesting_level_, 1);
}

}  // namespace blink
```
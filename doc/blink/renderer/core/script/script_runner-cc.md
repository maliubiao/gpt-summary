Response:
Let's break down the thought process for analyzing this `script_runner.cc` file.

**1. Initial Understanding of the Purpose:**

The filename itself, `script_runner.cc`, is a huge clue. It strongly suggests this code is responsible for managing the execution of scripts within the Blink rendering engine. The directory `blink/renderer/core/script/` reinforces this idea – it's clearly a core component for script handling.

**2. Examining the Includes:**

The `#include` directives provide further context:

*   Headers related to Blink's platform (`public/platform/*`):  Indicates interaction with the underlying operating system and browser environment (e.g., task scheduling).
*   Headers related to DOM (`core/dom/*`): Shows involvement with the Document Object Model, the tree-like representation of the HTML structure.
*   Headers related to Frames (`core/frame/*`):  Points to interactions with the frame structure within a web page.
*   Headers related to Loading (`core/loader/*`):  Suggests involvement in the process of fetching resources and loading the page.
*   Headers related to Scripting (`core/script/*`):  Confirms the focus on script management and likely interaction with other script-related components.
*   Headers from `base/`:  Indicates the use of common Chromium utilities, like task posting and histograms for performance monitoring.
*   Headers from `third_party/blink/public/common/features.h`: Shows feature flags are used to control behavior.

**3. Analyzing the Class Structure: `ScriptRunner` and `ScriptRunnerDelayer`:**

The core of the file revolves around the `ScriptRunner` class. This is where the primary logic for script execution resides. The `ScriptRunnerDelayer` class seems like a helper class for temporarily preventing scripts from running based on certain conditions.

**4. Deconstructing `ScriptRunner`'s Functionality (Method by Method):**

This is where the real work happens. Go through each method and understand its purpose:

*   **Constructor (`ScriptRunner::ScriptRunner`):**  Initializes the object, likely taking a `Document` as input, which is the context for the scripts. Note the use of `GetTaskRunner` – this implies scripts are executed on specific threads or task queues.
*   **`QueueScriptForExecution`:** This is a crucial function. It's responsible for adding scripts to internal queues based on their scheduling type (async, in-order, force-in-order). It also interacts with `PendingScript` and its load status.
*   **`AddDelayReason` and `RemoveDelayReason`:** These methods manage reasons why script execution might be delayed. This is a key mechanism for coordinating script execution with other page loading events.
*   **`RemoveDelayReasonFromScript`:**  Specifically handles removing delay reasons from asynchronous scripts. The added complexity with `PostDelayedTask` for `DelayReason::kMilestone` is important – it shows a mechanism to prevent indefinite delays.
*   **`ExecuteAsyncPendingScript`, `ExecuteForceInOrderPendingScript`:** These are the actual execution methods for different script types. They likely call into the JavaScript engine.
*   **`ExecuteParserBlockingScriptsBlockedByForceInOrder`:** A specialized method for handling scripts that were blocked during HTML parsing due to `force-in-order` scripts.
*   **`PendingScriptFinished`:**  Called when a script has finished loading/executing. It manages the execution of subsequent scripts in the queues.
*   **`ExecutePendingScript`:** The core execution logic. It calls a method on the `PendingScript` to actually run the script.
*   **`Trace`:**  Part of Blink's tracing infrastructure for debugging and memory management.

**5. Understanding the Script Scheduling Types:**

The different scheduling types (`kAsync`, `kInOrder`, `kForceInOrder`) are central to the `ScriptRunner`'s logic. Understanding when and why each type is used is crucial.

*   **Async:**  Scripts that can execute independently without blocking other scripts.
*   **In-Order:** Scripts that need to execute in the order they appear in the HTML.
*   **Force-In-Order:** Scripts that must execute strictly in order and can block the HTML parser.

**6. Connecting to JavaScript, HTML, and CSS:**

Think about how these different scheduling types relate to web development concepts:

*   **JavaScript:**  The code being executed. The `ScriptRunner` manages *when* it runs.
*   **HTML:** The `<script>` tags define the scripts and their attributes (e.g., `async`, `defer`). The `ScriptRunner` respects these attributes.
*   **CSS:**  While not directly involved in *running* CSS, the loading and parsing of CSS can influence when scripts are allowed to execute (e.g., render-blocking CSS). The delay mechanisms in `ScriptRunner` are relevant here.

**7. Considering User and Programming Errors:**

Think about common mistakes developers make that might involve the script execution process:

*   Placing blocking scripts in the `<head>`: This can delay page rendering.
*   Relying on specific execution order without using appropriate `async` or `defer` attributes.
*   Errors in JavaScript code that prevent scripts from finishing, potentially impacting the execution of subsequent scripts.

**8. Constructing the "User Journey" and Debugging:**

Imagine the steps a user takes that lead to the `ScriptRunner` being involved:

*   User requests a webpage.
*   Browser fetches the HTML.
*   Parser encounters `<script>` tags.
*   `ScriptRunner` is notified and manages the loading and execution of these scripts.

For debugging, think about how you might track script execution:

*   Breakpoints in `ScriptRunner` methods.
*   Logging statements to see which scripts are being queued and when.
*   Using browser developer tools to inspect the network requests for script files.

**9. Iterative Refinement:**

After the initial pass, review the code and refine your understanding. Pay attention to details like:

*   The use of `WrapWeakPersistent` and `WrapPersistent`: This relates to object lifetime management in Blink's architecture.
*   The use of histograms for performance metrics: This indicates a focus on efficiency.
*   The specific delay reasons and their implications.

By following these steps, you can systematically analyze a complex piece of code like `script_runner.cc` and develop a comprehensive understanding of its functionality and its role within the larger system. The key is to start with the high-level purpose and progressively drill down into the details, connecting the code to the broader concepts of web development.
This is the `script_runner.cc` file from the Chromium Blink rendering engine. Its primary function is to manage the execution of JavaScript code within a web page. It acts as a central coordinator for handling different types of scripts and ensuring they are executed at the appropriate time during the page loading process.

Here's a breakdown of its functionalities with examples and explanations:

**1. Core Function: Managing JavaScript Execution**

*   **Queuing Scripts:** The `ScriptRunner` receives `PendingScript` objects, which represent scripts to be executed. It categorizes and queues these scripts based on their scheduling type (e.g., `async`, `defer`, or inline).
    *   **Example (HTML):**
        ```html
        <script src="script1.js"></script>  <!-- In-order (by default) -->
        <script async src="script2.js"></script> <!-- Asynchronous -->
        <script defer src="script3.js"></script> <!-- Deferred -->
        <script>console.log("Inline script");</script>
        ```
    *   When the HTML parser encounters these `<script>` tags, it creates `PendingScript` objects and passes them to the `ScriptRunner`'s `QueueScriptForExecution` method.
*   **Delaying Execution:**  It handles scenarios where script execution needs to be delayed for various reasons, such as waiting for resources (like images or other stylesheets) or specific milestones in the page loading process.
    *   **Example (Scenario):** A script might depend on a CSS file being loaded to correctly calculate layout. The `ScriptRunner` can delay the script's execution until the CSSOM (CSS Object Model) is built.
*   **Executing Scripts:**  When the conditions for execution are met, the `ScriptRunner` triggers the actual execution of the JavaScript code within the appropriate JavaScript context.
    *   **Example (JavaScript):**  When `script1.js` is ready to run (in-order and no blocking reasons), the `ScriptRunner` calls a method on the `PendingScript` to execute its JavaScript code. This code might manipulate the DOM, interact with the browser's APIs, etc.

**2. Handling Different Script Scheduling Types**

The `ScriptRunner` distinguishes between different ways scripts are loaded and executed, which is crucial for controlling the page loading behavior:

*   **In-Order Scripts:** These scripts are executed in the order they appear in the HTML document. They block the HTML parser until they are fetched and executed.
    *   **Example (HTML):**  `<script src="scriptA.js"></script> <script src="scriptB.js"></script>`. `scriptA.js` will execute before `scriptB.js`.
*   **Asynchronous Scripts (`<script async>`)**: These scripts are fetched without blocking the HTML parser and executed as soon as they are available. Their execution order is not guaranteed relative to other scripts.
    *   **Example (HTML):** `<script async src="analytics.js"></script>`. The `analytics.js` script can load and execute independently without delaying the rendering of the page.
*   **Deferred Scripts (`<script defer>`)**: These scripts are fetched without blocking the HTML parser but are executed after the HTML parsing is complete, in the order they appear in the document.
    *   **Example (HTML):** `<script defer src="enhancements.js"></script>`. The `enhancements.js` script will be executed after the entire HTML structure is built.
*   **Force-In-Order Scripts:** This is likely an internal mechanism for scripts that absolutely need to be executed in a strict order and can potentially block parsing.

**3. Interaction with JavaScript, HTML, and CSS**

The `ScriptRunner` is deeply intertwined with how JavaScript, HTML, and CSS interact in a web browser:

*   **JavaScript:** The primary purpose is to execute JavaScript code. It manages the lifecycle of script execution from loading to completion.
*   **HTML:** The `<script>` tags in HTML are the triggers for the `ScriptRunner`'s actions. The attributes (`async`, `defer`) on these tags directly influence how the `ScriptRunner` schedules the scripts.
*   **CSS:** While the `ScriptRunner` doesn't directly execute CSS, it can delay script execution based on the loading and parsing of CSS. For instance, a script that needs to access computed styles might be delayed until the CSSOM is available.

**4. Logic and Control Flow (Hypothetical Input and Output)**

Let's consider a simplified scenario:

**Hypothetical Input (HTML Parser finds these tags):**

```html
<script src="inline_first.js"></script>
<script async src="analytics.js"></script>
<script defer src="dom_manipulation.js"></script>
```

**Logical Steps within `ScriptRunner`:**

1. **`QueueScriptForExecution` is called for each `<script>` tag.**
2. **`inline_first.js` (In-Order):** Added to the `pending_in_order_scripts_` queue.
3. **`analytics.js` (Async):** Added to the `pending_async_scripts_` map.
4. **`dom_manipulation.js` (Defer):** Added to the `pending_in_order_scripts_` queue (defer are handled similarly to in-order, but execution is delayed).
5. **The `ScriptRunner` starts monitoring the loading state of the scripts.**
6. **`inline_first.js` finishes loading:**
    *   `PendingScriptFinished` is called.
    *   The `ScriptRunner` checks if it's ready to execute (no blocking reasons).
    *   It posts a task to the appropriate thread to execute `inline_first.js`.
7. **`analytics.js` finishes loading (could happen before or after `inline_first.js`):**
    *   `PendingScriptFinished` is called.
    *   The `ScriptRunner` checks for any delay reasons. If none, it posts a task to execute `analytics.js`.
8. **HTML parsing completes:**
    *   This signals that deferred scripts can now be executed.
    *   The `ScriptRunner` checks the `pending_in_order_scripts_` queue and finds `dom_manipulation.js`.
    *   It posts a task to execute `dom_manipulation.js`.

**Hypothetical Output (Execution Order):**

The execution order would likely be:

1. `inline_first.js`
2. `analytics.js` (could happen before or after, depending on network speed)
3. `dom_manipulation.js`

**5. User and Programming Errors**

Common mistakes that involve the `ScriptRunner` include:

*   **Placing blocking scripts in the `<head>`:**  If you have a large, in-order script in the `<head>` section of your HTML, it will block the HTML parser, delaying the rendering of the page and potentially leading to a poor user experience.
    *   **Example (HTML):**
        ```html
        <head>
          <script src="huge_blocking_script.js"></script>
        </head>
        ```
    *   The user might experience a blank white screen for an extended period while `huge_blocking_script.js` is downloaded and executed.
*   **Relying on the execution order of asynchronous scripts:** If your code depends on `analytics.js` always running before another asynchronous script, you might encounter issues because their execution order is not guaranteed.
    *   **Example (JavaScript):**
        ```javascript
        // analytics.js
        window.analyticsReady = true;

        // another_script.js (async)
        if (window.analyticsReady) {
          // Use analytics functionality
        } else {
          console.error("Analytics not ready!");
        }
        ```
    *   If `another_script.js` loads and executes before `analytics.js`, the `window.analyticsReady` check will fail.
*   **Defer scripts that manipulate elements not yet parsed:** While deferred scripts run after parsing, they run *before* the `DOMContentLoaded` event. If a deferred script tries to access or manipulate DOM elements that haven't been fully constructed yet, it might encounter errors.

**6. User Operations and Debugging Clues**

How does a user operation lead to the execution of code in `script_runner.cc`?

1. **User enters a URL or clicks a link:** The browser starts fetching the HTML content of the webpage.
2. **HTML Parser starts parsing the HTML:** As the parser encounters `<script>` tags, it creates `PendingScript` objects.
3. **`ScriptRunner::QueueScriptForExecution` is called:** The parser passes these `PendingScript` objects to the `ScriptRunner`.
4. **`ScriptRunner` manages the loading and execution of scripts:** Based on the script type and current page state.
5. **JavaScript code executes:** Eventually, the `ScriptRunner` triggers the execution of the JavaScript code associated with the `PendingScript`.

**Debugging Clues:**

If you suspect issues related to script execution, you might look for these clues:

*   **Performance issues:** Slow page load times, especially during the initial rendering phase, could indicate problems with blocking scripts.
*   **JavaScript errors:** Errors occurring early in the page load might be due to scripts executing in an unexpected order or before necessary resources are available.
*   **Unexpected behavior:** Features on the page not working as expected might be caused by scripts not executing or executing at the wrong time.

**Stepping Through the Code (Hypothetical Debugging):**

To debug script execution issues, a Chromium developer might:

1. **Set breakpoints in `ScriptRunner::QueueScriptForExecution`:** To see which scripts are being queued and their scheduling types.
2. **Set breakpoints in `ScriptRunner::PendingScriptFinished`:** To track when scripts finish loading and become ready for execution.
3. **Set breakpoints in `ScriptRunner::ExecutePendingScript`:** To observe when and which scripts are actually being executed.
4. **Examine the `pending_async_scripts_`, `pending_in_order_scripts_`, and `pending_force_in_order_scripts_` queues:** To understand the current state of pending scripts.
5. **Analyze the `delay_reasons_`:** To determine why certain scripts might be delayed.

In summary, `script_runner.cc` is a fundamental part of the Blink rendering engine responsible for the crucial task of managing and executing JavaScript code within a web page. It handles different script types, manages dependencies and delays, and ensures that scripts are executed at the appropriate time during the page lifecycle. Understanding its functionality is essential for comprehending how web pages load and how JavaScript interacts with the browser environment.

### 提示词
```
这是目录为blink/renderer/core/script/script_runner.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google, Inc. All Rights Reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/script/script_runner.h"

#include <algorithm>

#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "base/strings/strcat.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/typed_macros.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/script/script_loader.h"
#include "third_party/blink/renderer/platform/scheduler/public/cooperative_scheduling_manager.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"

namespace {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class RaceTaskPriority {
  kLowerPriority = 0,
  kNormalPriority = 1,
  kMaxValue = kNormalPriority,
};

const char* RaceTaskPriorityToString(RaceTaskPriority task_priority) {
  switch (task_priority) {
    case RaceTaskPriority::kLowerPriority:
      return "LowerPriority";
    case RaceTaskPriority::kNormalPriority:
      return "NormalPriority";
  }
}

void PostTaskWithLowPriorityUntilTimeout(
    const base::Location& from_here,
    base::OnceClosure task,
    base::TimeDelta timeout,
    scoped_refptr<base::SingleThreadTaskRunner> lower_priority_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> normal_priority_task_runner) {
  using RefCountedOnceClosure = base::RefCountedData<base::OnceClosure>;
  scoped_refptr<RefCountedOnceClosure> ref_counted_task =
      base::MakeRefCounted<RefCountedOnceClosure>(std::move(task));

  // |run_task_once| runs on both of |lower_priority_task_runner| and
  // |normal_priority_task_runner|. |run_task_once| guarantees that the given
  // |task| doesn't run more than once. |task| runs on either of
  // |lower_priority_task_runner| and |normal_priority_task_runner| whichever
  // comes first.
  auto run_task_once = [](scoped_refptr<RefCountedOnceClosure> ref_counted_task,
                          RaceTaskPriority task_priority,
                          base::TimeTicks post_task_time) {
    if (!ref_counted_task->data.is_null()) {
      auto duration = base::TimeTicks::Now() - post_task_time;
      std::move(ref_counted_task->data).Run();
      base::UmaHistogramEnumeration(
          "Blink.Script.PostTaskWithLowPriorityUntilTimeout.RaceTaskPriority",
          task_priority);
      base::UmaHistogramMediumTimes(
          "Blink.Script.PostTaskWithLowPriorityUntilTimeout.Time", duration);
      base::UmaHistogramMediumTimes(
          base::StrCat(
              {"Blink.Script.PostTaskWithLowPriorityUntilTimeout.Time.",
               RaceTaskPriorityToString(task_priority)}),
          duration);
    }
  };

  base::TimeTicks post_task_time = base::TimeTicks::Now();

  lower_priority_task_runner->PostTask(
      from_here,
      WTF::BindOnce(run_task_once, ref_counted_task,
                    RaceTaskPriority::kLowerPriority, post_task_time));

  normal_priority_task_runner->PostDelayedTask(
      from_here,
      WTF::BindOnce(run_task_once, ref_counted_task,
                    RaceTaskPriority::kNormalPriority, post_task_time),
      timeout);
}

}  // namespace

namespace blink {

void PostTaskWithLowPriorityUntilTimeoutForTesting(
    const base::Location& from_here,
    base::OnceClosure task,
    base::TimeDelta timeout,
    scoped_refptr<base::SingleThreadTaskRunner> lower_priority_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> normal_priority_task_runner) {
  PostTaskWithLowPriorityUntilTimeout(from_here, std::move(task), timeout,
                                      std::move(lower_priority_task_runner),
                                      std::move(normal_priority_task_runner));
}

ScriptRunner::ScriptRunner(Document* document)
    : document_(document),
      task_runner_(document->GetTaskRunner(TaskType::kNetworking)),
      low_priority_task_runner_(
          document->GetTaskRunner(TaskType::kLowPriorityScriptExecution)) {
  DCHECK(document);
}

void ScriptRunner::QueueScriptForExecution(PendingScript* pending_script,
                                           DelayReasons delay_reasons) {
  DCHECK(pending_script);
  DCHECK(delay_reasons & static_cast<DelayReasons>(DelayReason::kLoad));
  document_->IncrementLoadEventDelayCount();

  switch (pending_script->GetSchedulingType()) {
    case ScriptSchedulingType::kAsync:
      pending_async_scripts_.insert(pending_script, delay_reasons);
      break;

    case ScriptSchedulingType::kInOrder:
      pending_in_order_scripts_.push_back(pending_script);
      break;

    case ScriptSchedulingType::kForceInOrder:
      pending_force_in_order_scripts_.push_back(pending_script);
      pending_force_in_order_scripts_count_ += 1;
      break;

    default:
      NOTREACHED();
  }

  // Note that WatchForLoad() can immediately call PendingScriptFinished().
  pending_script->WatchForLoad(this);
}

void ScriptRunner::AddDelayReason(DelayReason delay_reason) {
  DCHECK(!IsActive(delay_reason));
  active_delay_reasons_ |= static_cast<DelayReasons>(delay_reason);
}

void ScriptRunner::RemoveDelayReason(DelayReason delay_reason) {
  DCHECK(IsActive(delay_reason));
  active_delay_reasons_ &= ~static_cast<DelayReasons>(delay_reason);

  HeapVector<Member<PendingScript>> pending_async_scripts;
  CopyKeysToVector(pending_async_scripts_, pending_async_scripts);
  for (PendingScript* pending_script : pending_async_scripts) {
    RemoveDelayReasonFromScript(pending_script, delay_reason);
  }
}

void ScriptRunner::RemoveDelayReasonFromScript(PendingScript* pending_script,
                                               DelayReason delay_reason) {
  // |pending_script| can be null when |RemoveDelayReasonFromScript()| is called
  // via |PostDelayedTask()| below.
  if (!pending_script)
    return;

  auto it = pending_async_scripts_.find(pending_script);

  if (it == pending_async_scripts_.end())
    return;

  if (it->value &= ~static_cast<DelayReasons>(delay_reason)) {
    // The delay must be less than a few seconds because some scripts times out
    // otherwise. This is only applied to milestone based delay.
    const base::TimeDelta delay_limit =
        features::kDelayAsyncScriptExecutionDelayLimitParam.Get();
    if (!delay_limit.is_zero() && delay_reason == DelayReason::kLoad &&
        (it->value & static_cast<DelayReasons>(DelayReason::kMilestone))) {
      // PostDelayedTask to limit the delay amount of DelayAsyncScriptExecution
      // (see crbug/1340837). DelayReason::kMilestone is sent on
      // loading-milestones such as LCP, first_paint, or finished_parsing.
      // Once the script is completely loaded, even if the milestones delaying
      // execution aren't removed, we eventually want to trigger
      // script-execution anyway for compatibility reasons, since waiting too
      // long for the milestones can cause compatibility issues.
      // |pending_script| has to be wrapped by WrapWeakPersistent because the
      // following delayed task should not persist a PendingScript.
      task_runner_->PostDelayedTask(
          FROM_HERE,
          WTF::BindOnce(&ScriptRunner::RemoveDelayReasonFromScript,
                        WrapWeakPersistent(this),
                        WrapWeakPersistent(pending_script),
                        DelayReason::kMilestone),
          delay_limit);
    }
    // Still to be delayed.
    return;
  }

  // Script is really ready to evaluate.
  pending_async_scripts_.erase(it);
  base::OnceClosure task = WTF::BindOnce(
      &ScriptRunner::ExecuteAsyncPendingScript, WrapWeakPersistent(this),
      WrapPersistent(pending_script), base::TimeTicks::Now());
  if (pending_script->IsEligibleForLowPriorityAsyncScriptExecution()) {
    PostTaskWithLowPriorityUntilTimeout(
        FROM_HERE, std::move(task),
        features::kTimeoutForLowPriorityAsyncScriptExecution.Get(),
        low_priority_task_runner_, task_runner_);
  } else {
    task_runner_->PostTask(FROM_HERE, std::move(task));
  }
}

void ScriptRunner::ExecuteAsyncPendingScript(
    PendingScript* pending_script,
    base::TimeTicks ready_to_evaluate_time) {
  base::UmaHistogramMediumTimes(
      "Blink.Script.AsyncScript.FromReadyToStartExecution.Time",
      base::TimeTicks::Now() - ready_to_evaluate_time);
  ExecutePendingScript(pending_script);
}

void ScriptRunner::ExecuteForceInOrderPendingScript(
    PendingScript* pending_script) {
  DCHECK_GT(pending_force_in_order_scripts_count_, 0u);
  ExecutePendingScript(pending_script);
  pending_force_in_order_scripts_count_ -= 1;
}

void ScriptRunner::ExecuteParserBlockingScriptsBlockedByForceInOrder() {
  ScriptableDocumentParser* parser = document_->GetScriptableDocumentParser();
  if (parser && document_->IsScriptExecutionReady()) {
    parser->ExecuteScriptsWaitingForResources();
  }
}

void ScriptRunner::PendingScriptFinished(PendingScript* pending_script) {
  pending_script->StopWatchingForLoad();

  switch (pending_script->GetSchedulingType()) {
    case ScriptSchedulingType::kAsync:
      CHECK(pending_async_scripts_.Contains(pending_script));
      RemoveDelayReasonFromScript(pending_script, DelayReason::kLoad);
      break;

    case ScriptSchedulingType::kInOrder:
      while (!pending_in_order_scripts_.empty() &&
             pending_in_order_scripts_.front()->IsReady()) {
        PendingScript* pending_in_order = pending_in_order_scripts_.TakeFirst();
        task_runner_->PostTask(
            FROM_HERE, WTF::BindOnce(&ScriptRunner::ExecutePendingScript,
                                     WrapWeakPersistent(this),
                                     WrapPersistent(pending_in_order)));
      }
      break;

    case ScriptSchedulingType::kForceInOrder:
      while (!pending_force_in_order_scripts_.empty() &&
             pending_force_in_order_scripts_.front()->IsReady()) {
        PendingScript* pending_in_order =
            pending_force_in_order_scripts_.TakeFirst();
        task_runner_->PostTask(
            FROM_HERE,
            WTF::BindOnce(&ScriptRunner::ExecuteForceInOrderPendingScript,
                          WrapWeakPersistent(this),
                          WrapPersistent(pending_in_order)));
      }
      if (pending_force_in_order_scripts_.empty()) {
        task_runner_->PostTask(
            FROM_HERE,
            WTF::BindOnce(&ScriptRunner::
                              ExecuteParserBlockingScriptsBlockedByForceInOrder,
                          WrapWeakPersistent(this)));
      }
      break;

    default:
      NOTREACHED();
  }
}

void ScriptRunner::ExecutePendingScript(PendingScript* pending_script) {
  TRACE_EVENT("blink", "ScriptRunner::ExecutePendingScript");

  DCHECK(!document_->domWindow() || !document_->domWindow()->IsContextPaused());
  DCHECK(pending_script);

  pending_script->ExecuteScriptBlock();

  document_->DecrementLoadEventDelayCount();
}

void ScriptRunner::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(pending_in_order_scripts_);
  visitor->Trace(pending_async_scripts_);
  visitor->Trace(pending_force_in_order_scripts_);
  PendingScriptClient::Trace(visitor);
}

ScriptRunnerDelayer::ScriptRunnerDelayer(ScriptRunner* script_runner,
                                         ScriptRunner::DelayReason delay_reason)
    : script_runner_(script_runner), delay_reason_(delay_reason) {}

void ScriptRunnerDelayer::Activate() {
  if (activated_)
    return;
  activated_ = true;
  if (script_runner_)
    script_runner_->AddDelayReason(delay_reason_);
}

void ScriptRunnerDelayer::Deactivate() {
  if (!activated_)
    return;
  activated_ = false;
  if (script_runner_)
    script_runner_->RemoveDelayReason(delay_reason_);
}

void ScriptRunnerDelayer::Trace(Visitor* visitor) const {
  visitor->Trace(script_runner_);
}

}  // namespace blink
```
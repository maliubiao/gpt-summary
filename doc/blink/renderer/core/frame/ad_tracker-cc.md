Response:
Let's break down the thought process for analyzing the `ad_tracker.cc` file and generating the response.

1. **Understand the Core Purpose:** The file name `ad_tracker.cc` and the inclusion of terms like "ad frame," "ad script," and "known ad scripts" immediately suggest the primary function: tracking and identifying code and resources related to advertisements within a web page.

2. **Identify Key Data Structures:** Scan the class members and related data structures. Key elements that stand out are:
    * `known_ad_scripts_`:  A `HashMap` likely storing URLs of scripts identified as ads, keyed by `ExecutionContext`. This suggests persistent tracking of ad scripts within a given context.
    * `stack_frame_is_ad_`: A `Vector` of booleans indicating whether the current stack frame is executing ad-related code. This is important for determining the context of script execution.
    * `num_ads_in_stack_`: An integer counting the number of ad-related scripts in the current call stack.
    * `bottom_most_ad_script_`:  Stores information about the first ad script encountered in the call stack. This could be useful for attribution or identifying the origin of ad behavior.
    * `running_ad_async_tasks_`, `bottom_most_async_ad_script_`: Similar to the stack-related members, but for asynchronous tasks. This acknowledges that ad activity can happen outside the immediate call stack.

3. **Analyze Key Methods:** Focus on the public and crucial private methods:
    * `FromExecutionContext()`:  Provides a way to access the `AdTracker` instance associated with a given execution context. This is a common pattern in Blink for accessing per-frame or per-context data.
    * `IsAdScriptExecutingInDocument()`:  A static method to quickly check if an ad script is running within a specific document.
    * `WillExecuteScript()`, `DidExecuteScript()`: These methods are called before and after script execution. They are critical for marking stack frames as ad-related and updating the tracking information. The logic here, especially the handling of scripts without URLs (by ID) is important.
    * `Will()`, `Did()` (with `probe::ExecuteScript` and `probe::CallFunction`):  These methods integrate with Blink's probe system, which is used for instrumentation and debugging. They essentially forward calls to `WillExecuteScript` and `DidExecuteScript`.
    * `CalculateIfAdSubresource()`: This is crucial for identifying resources (scripts, images, etc.) loaded by ad-related contexts or scripts. The logic considering initiator type (CSS) is a notable detail.
    * `DidCreateAsyncTask()`, `DidStartAsyncTask()`, `DidFinishAsyncTask()`:  These methods handle the tracking of ad-related asynchronous tasks.
    * `IsAdScriptInStack()`:  A central method for determining if the current execution is happening within an ad-related context or was initiated by an ad script. The `StackType` parameter hints at different levels of stack analysis.
    * `IsKnownAdScript()`: Checks if a script URL is already identified as an ad script.
    * `AppendToKnownAdScripts()`:  Adds a script URL to the list of known ad scripts for a given context.

4. **Identify Connections to Web Technologies:**  Think about how the tracked information relates to JavaScript, HTML, and CSS:
    * **JavaScript:** The primary focus is on tracking JavaScript execution. The methods directly interact with V8 APIs (`v8::Isolate`, `v8::Context`, `v8::StackTrace`). The ability to identify scripts based on URLs and IDs is directly tied to how JavaScript is loaded and executed.
    * **HTML:** The `IsAdFrame()` check and the concept of an "ad frame" directly link to HTML structures. The creation and loading of iframes are common ways to embed ads.
    * **CSS:** The `CalculateIfAdSubresource()` method explicitly considers CSS-initiated requests. This acknowledges that CSS can trigger resource loading and that those resources might be ad-related.

5. **Consider Logic and Potential Errors:**
    * **Logical Reasoning:** The tracking of the call stack and asynchronous tasks is a form of logical inference. The assumption is that if a script within an ad frame or a script previously identified as an ad initiates further actions (script execution, resource loading, asynchronous tasks), those actions are also likely to be ad-related.
    * **User/Programming Errors:** Think about scenarios where the tracking might be inaccurate or where developers might make mistakes related to ad integration. Examples include:
        * Mislabeling of frames.
        * Dynamic script injection without proper tracking.
        * Asynchronous operations obscuring the origin of ad activity.

6. **Structure the Response:** Organize the findings into clear categories:
    * **Functionality:** Provide a concise summary of the core purpose and key features.
    * **Relationship to Web Technologies:**  Explain the connections to JavaScript, HTML, and CSS with concrete examples.
    * **Logical Reasoning:**  Illustrate how the code makes inferences about ad-related activity.
    * **Potential Errors:**  Highlight common pitfalls and edge cases.

7. **Refine and Elaborate:** Review the initial analysis and add more detail where necessary. For example, explicitly mention the purpose of the probe integration, or elaborate on the implications of tracking scripts by ID. Ensure the language is clear and easy to understand.

By following these steps, you can systematically analyze the source code and generate a comprehensive and insightful description of its functionality and relationships to the broader web development context.
好的，让我们来分析一下 `blink/renderer/core/frame/ad_tracker.cc` 这个文件。

**功能概述:**

`AdTracker` 类的主要功能是 **跟踪和识别网页中的广告相关活动**。它旨在判断特定的脚本执行、资源加载和异步任务是否与广告有关。 这对于浏览器实现诸如广告拦截、性能优化（针对广告）以及安全策略等功能至关重要。

**具体功能点:**

1. **识别广告框架 (Ad Frame):**  通过 `IsKnownAdExecutionContext` 函数，`AdTracker` 可以判断当前的执行上下文是否在一个已知的广告框架内。这通常基于框架的属性（例如，是否设置了 `<iframe>` 的 `ad` 属性或者通过其他启发式方法）。

2. **识别广告脚本 (Ad Script):**
   - 通过 `IsKnownAdScript` 函数，`AdTracker` 可以判断一个脚本的 URL 是否被标记为已知广告脚本。
   - 对于没有 URL 的动态插入脚本，它通过 `script_id` 和调用栈信息来判断。
   - `AppendToKnownAdScripts` 函数用于将新发现的广告脚本 URL 添加到已知列表中。
   - `IsAdScriptInStack` 函数检查当前的 JavaScript 调用栈中是否存在已知的广告脚本。

3. **跟踪脚本执行:**
   - `WillExecuteScript` 在脚本执行前被调用，记录脚本的 URL 或 ID，并判断其是否为广告脚本。
   - `DidExecuteScript` 在脚本执行后被调用，清理相关的状态。
   - 通过 `stack_frame_is_ad_` 记录当前调用栈帧是否是广告相关的。
   - `num_ads_in_stack_` 记录当前调用栈中广告脚本的数量。

4. **跟踪资源加载:**
   - `CalculateIfAdSubresource` 函数判断一个子资源（例如图片、脚本）的加载请求是否与广告相关。 这会考虑发起请求的上下文（是否在广告框架内）以及调用栈中是否存在广告脚本。
   - 它会区分不同类型的资源请求发起者（例如，CSS 发起的请求有特殊的处理）。

5. **跟踪异步任务:**
   - `DidCreateAsyncTask` 在创建异步任务时被调用，如果当前调用栈中有广告脚本，则将该任务标记为广告任务。
   - `DidStartAsyncTask` 和 `DidFinishAsyncTask` 用于跟踪广告相关的异步任务的开始和结束，并维护 `running_ad_async_tasks_` 和 `bottom_most_async_ad_script_` 等状态。

6. **与 Blink 探测系统集成:**
   - 通过 `Will(const probe::ExecuteScript&)` 和 `Did(const probe::ExecuteScript&)` 等函数，`AdTracker` 与 Blink 的探测系统集成，以便在脚本执行等关键事件发生时接收通知。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **识别广告脚本:**  当 JavaScript 代码尝试执行一个 URL 已知的广告脚本时，`IsKnownAdScript` 会返回 `true`。例如，如果一个脚本的 URL 是 `https://example.com/ads/banner.js` 并且之前被标记为广告，那么 `AdTracker` 会识别它。
    * **跟踪动态插入脚本:**  如果一个 JavaScript 脚本动态创建并插入了 `<script>` 标签，但没有 `src` 属性，`AdTracker` 会使用其内部 ID 和插入它的脚本的调用栈来判断是否是广告。
        * **假设输入:** 一个在广告框架内的脚本执行了 `document.createElement('script'); script.text = '...'; document.body.appendChild(script);`
        * **输出:** `AdTracker` 可能会根据执行 `createElement` 的脚本的上下文将新创建的脚本标记为广告脚本。
    * **异步操作:**  如果一个广告脚本使用 `setTimeout` 或 `Promise` 创建了一个异步任务，`AdTracker` 会跟踪这个任务，并能判断后续在异步任务中执行的代码是否与广告有关。

* **HTML:**
    * **识别广告框架:**  当浏览器解析 HTML 时，如果遇到一个带有 `ad` 属性的 `<iframe>` 标签（或者其他被认为是广告框架的标签），`IsKnownAdExecutionContext` 会对该框架返回 `true`。
        * **假设输入:**  HTML 中包含 `<iframe src="https://ads.example.com" ad></iframe>`
        * **输出:**  当这个 iframe 加载完成，其内部的 JavaScript 执行时，`IsKnownAdExecutionContext` 将返回 `true`。

* **CSS:**
    * **CSS 发起的资源请求:**  `CalculateIfAdSubresource` 特别处理了由 CSS 发起的资源请求。例如，如果一个广告框架内的 CSS 样式引用了一个背景图片。
        * **假设输入:** 一个在广告框架内的 CSS 文件包含 `background-image: url(https://ads.example.com/banner.png);`
        * **输出:** 当浏览器加载 `banner.png` 时，即使当前的 JavaScript 调用栈没有明显的广告脚本，`AdTracker` 也会根据发起请求的上下文（广告框架）将该资源标记为广告资源。

**逻辑推理的假设输入与输出:**

* **假设输入:**
    1. 一个非广告页面加载了一个来自 `known-ad-domain.com` 的 JavaScript 文件 (`<script src="https://known-ad-domain.com/script.js"></script>`).
    2. 这个脚本执行后，动态创建并插入了另一个没有 `src` 属性的脚本。
* **逻辑推理:**
    * `AdTracker` 会将来自 `known-ad-domain.com` 的脚本标记为已知广告脚本。
    * 当该脚本动态插入新脚本时，`AdTracker` 会检查当前调用栈，发现栈顶（或栈底）是已知的广告脚本，因此会将动态插入的脚本也标记为广告脚本。
* **输出:** 动态插入的脚本也会被 `AdTracker` 认为是广告脚本。

**涉及用户或者编程常见的使用错误 (可能导致 `AdTracker` 判断错误):**

1. **错误地标记非广告框架为广告框架:**  如果开发者错误地给非广告的 `<iframe>` 标签添加了 `ad` 属性或者使用了其他会被 `AdTracker` 误判的模式，会导致 `AdTracker` 将非广告内容误认为广告。
    * **举例:**  `<iframe src="/legitimate-content.html" ad></iframe>`

2. **在广告框架内执行非广告代码:**  虽然 `AdTracker` 会将广告框架内的脚本默认视为广告，但如果一个开发者有意在广告框架内运行一些与广告无关的第三方代码，`AdTracker` 的判断可能不符合预期。

3. **动态脚本注入和追踪困难:**  高度动态的 JavaScript 代码，特别是那些在运行时生成和注入脚本的代码，可能会使 `AdTracker` 的追踪变得复杂。如果动态注入的脚本没有明显的标记或与已知广告的关联，可能会被漏掉。

4. **异步操作导致的上下文丢失:**  过度依赖异步操作可能会模糊广告活动的来源。例如，一个广告脚本启动了一个延时的异步任务，而该任务执行时，原始的广告脚本可能已经不在调用栈中，这可能会使追踪变得困难。

5. **Mismatched 期望与实现细节:**  用户或开发者可能对 "广告" 的定义与 `AdTracker` 的实现细节存在差异。例如，某些用于分析或推广目的的脚本可能不被用户认为是广告，但可能被 `AdTracker` 标记为广告脚本。

总而言之，`AdTracker` 是 Chromium Blink 引擎中一个关键的组件，它通过分析执行上下文、脚本来源、调用栈和异步任务等信息，来识别网页中的广告相关活动，为浏览器的各种广告相关功能提供基础数据。理解其工作原理有助于我们更好地理解浏览器如何处理网页中的广告内容。

### 提示词
```
这是目录为blink/renderer/core/frame/ad_tracker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/ad_tracker.h"

#include <memory>
#include <optional>

#include "base/compiler_specific.h"
#include "base/feature_list.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/core_probe_sink.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/probe/async_task_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/thread_debugger.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "v8/include/v8-inspector.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

bool IsKnownAdExecutionContext(ExecutionContext* execution_context) {
  // TODO(jkarlin): Do the same check for worker contexts.
  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context)) {
    LocalFrame* frame = window->GetFrame();
    if (frame && frame->IsAdFrame())
      return true;
  }
  return false;
}

String GenerateFakeUrlFromScriptId(int script_id) {
  // Null string is used to represent scripts with neither a name nor an ID.
  if (script_id == v8::Message::kNoScriptIdInfo)
    return String();

  // The prefix cannot appear in real URLs.
  return String::Format("{ id %d }", script_id);
}

}  // namespace

// static
AdTracker* AdTracker::FromExecutionContext(
    ExecutionContext* execution_context) {
  if (!execution_context)
    return nullptr;
  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context)) {
    if (LocalFrame* frame = window->GetFrame()) {
      return frame->GetAdTracker();
    }
  }
  return nullptr;
}

// static
bool AdTracker::IsAdScriptExecutingInDocument(Document* document,
                                              StackType stack_type) {
  AdTracker* ad_tracker =
      document->GetFrame() ? document->GetFrame()->GetAdTracker() : nullptr;
  return ad_tracker && ad_tracker->IsAdScriptInStack(stack_type);
}

AdTracker::AdTracker(LocalFrame* local_root) : local_root_(local_root) {
  local_root_->GetProbeSink()->AddAdTracker(this);
}

AdTracker::~AdTracker() {
  DCHECK(!local_root_);
}

void AdTracker::Shutdown() {
  if (!local_root_)
    return;
  local_root_->GetProbeSink()->RemoveAdTracker(this);
  local_root_ = nullptr;
}

String AdTracker::ScriptAtTopOfStack() {
  // CurrentStackTrace is 10x faster than CaptureStackTrace if all that you need
  // is the url of the script at the top of the stack. See crbug.com/1057211 for
  // more detail.
  v8::Isolate* isolate = v8::Isolate::TryGetCurrent();
  if (!isolate) [[unlikely]] {
    return String();
  }

  v8::Local<v8::StackTrace> stack_trace =
      v8::StackTrace::CurrentStackTrace(isolate, /*frame_limit=*/1);
  if (stack_trace.IsEmpty() || stack_trace->GetFrameCount() < 1)
    return String();

  v8::Local<v8::StackFrame> frame = stack_trace->GetFrame(isolate, 0);
  v8::Local<v8::String> script_name = frame->GetScriptName();
  if (script_name.IsEmpty() || !script_name->Length())
    return GenerateFakeUrlFromScriptId(frame->GetScriptId());

  return ToCoreString(isolate, script_name);
}

ExecutionContext* AdTracker::GetCurrentExecutionContext() {
  // Determine the current ExecutionContext.
  v8::Isolate* isolate = v8::Isolate::TryGetCurrent();
  if (!isolate) {
    return nullptr;
  }
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  return context.IsEmpty() ? nullptr : ToExecutionContext(context);
}

v8_inspector::V8DebuggerId GetDebuggerIdForContext(
    const v8::Local<v8::Context>& v8_context) {
  if (v8_context.IsEmpty()) {
    return v8_inspector::V8DebuggerId();
  }
  int contextId = v8_inspector::V8ContextInfo::executionContextId(v8_context);
  ThreadDebugger* thread_debugger =
      ThreadDebugger::From(v8_context->GetIsolate());
  DCHECK(thread_debugger);
  v8_inspector::V8Inspector* inspector = thread_debugger->GetV8Inspector();
  DCHECK(inspector);
  return inspector->uniqueDebuggerId(contextId);
}

void AdTracker::WillExecuteScript(ExecutionContext* execution_context,
                                  const v8::Local<v8::Context>& v8_context,
                                  const String& script_url,
                                  int script_id) {
  bool is_ad = false;

  // We track scripts with no URL (i.e. dynamically inserted scripts with no
  // src) by IDs instead. We also check the stack as they are executed
  // immediately and should be tagged based on the script inserting them.
  bool should_track_with_id =
      script_url.empty() && script_id != v8::Message::kNoScriptIdInfo;
  if (should_track_with_id) {
    // This primarily checks if |execution_context| is a known ad context as we
    // don't need to keep track of scripts in ad contexts. However, two scripts
    // with identical text content can be assigned the same ID.
    String fake_url = GenerateFakeUrlFromScriptId(script_id);
    if (IsKnownAdScript(execution_context, fake_url)) {
      is_ad = true;
    } else if (IsAdScriptInStack(StackType::kBottomAndTop)) {
      AppendToKnownAdScripts(*execution_context, fake_url);
      is_ad = true;
    }
  }

  if (!should_track_with_id)
    is_ad = IsKnownAdScript(execution_context, script_url);

  stack_frame_is_ad_.push_back(is_ad);
  if (is_ad) {
    if (num_ads_in_stack_ == 0) {
      // Stash the first ad script on the stack.
      bottom_most_ad_script_ =
          AdScriptIdentifier(GetDebuggerIdForContext(v8_context), script_id);
    }
    num_ads_in_stack_ += 1;
  }
}

void AdTracker::DidExecuteScript() {
  if (stack_frame_is_ad_.back()) {
    DCHECK_LT(0, num_ads_in_stack_);
    num_ads_in_stack_ -= 1;
    if (num_ads_in_stack_ == 0)
      bottom_most_ad_script_.reset();
  }
  stack_frame_is_ad_.pop_back();
}

void AdTracker::Will(const probe::ExecuteScript& probe) {
  WillExecuteScript(probe.context, probe.v8_context, probe.script_url,
                    probe.script_id);
}

void AdTracker::Did(const probe::ExecuteScript& probe) {
  DidExecuteScript();
}

void AdTracker::Will(const probe::CallFunction& probe) {
  // Do not process nested microtasks as that might potentially lead to a
  // slowdown of custom element callbacks.
  if (probe.depth)
    return;

  v8::Local<v8::Value> resource_name =
      probe.function->GetScriptOrigin().ResourceName();
  String script_url;
  if (!resource_name.IsEmpty()) {
    v8::Isolate* isolate = ToIsolate(local_root_);
    v8::MaybeLocal<v8::String> resource_name_string =
        resource_name->ToString(isolate->GetCurrentContext());
    // Rarely, ToString() can return an empty result, even if |resource_name|
    // isn't empty (crbug.com/1086832).
    if (!resource_name_string.IsEmpty())
      script_url = ToCoreString(isolate, resource_name_string.ToLocalChecked());
  }
  WillExecuteScript(probe.context, probe.v8_context, script_url,
                    probe.function->ScriptId());
}

void AdTracker::Did(const probe::CallFunction& probe) {
  if (probe.depth)
    return;

  DidExecuteScript();
}

bool AdTracker::CalculateIfAdSubresource(
    ExecutionContext* execution_context,
    const KURL& request_url,
    ResourceType resource_type,
    const FetchInitiatorInfo& initiator_info,
    bool known_ad) {
  // Check if the document loading the resource is an ad.
  const bool is_ad_execution_context =
      IsKnownAdExecutionContext(execution_context);
  known_ad = known_ad || is_ad_execution_context;

  // We skip script checking for stylesheet-initiated resource requests as the
  // stack may represent the cause of a style recalculation rather than the
  // actual resources themselves. Instead, the ad bit is set according to the
  // CSSParserContext when the request is made. See crbug.com/1051605.
  if (initiator_info.name == fetch_initiator_type_names::kCSS ||
      initiator_info.name == fetch_initiator_type_names::kUacss) {
    return known_ad;
  }

  // Check if any executing script is an ad.
  known_ad = known_ad || IsAdScriptInStack(StackType::kBottomAndTop);

  // If it is a script marked as an ad and it's not in an ad context, append it
  // to the known ad script set. We don't need to keep track of ad scripts in ad
  // contexts, because any script executed inside an ad context is considered an
  // ad script by IsKnownAdScript.
  if (resource_type == ResourceType::kScript && known_ad &&
      !is_ad_execution_context) {
    AppendToKnownAdScripts(*execution_context, request_url.GetString());
  }

  return known_ad;
}

void AdTracker::DidCreateAsyncTask(probe::AsyncTaskContext* task_context) {
  DCHECK(task_context);
  std::optional<AdScriptIdentifier> id;
  if (IsAdScriptInStack(StackType::kBottomAndTop, &id)) {
    task_context->SetAdTask(id);
  }
}

void AdTracker::DidStartAsyncTask(probe::AsyncTaskContext* task_context) {
  DCHECK(task_context);
  if (task_context->IsAdTask()) {
    if (running_ad_async_tasks_ == 0) {
      DCHECK(!bottom_most_async_ad_script_.has_value());
      bottom_most_async_ad_script_ = task_context->ad_identifier();
    }

    running_ad_async_tasks_ += 1;
  }
}

void AdTracker::DidFinishAsyncTask(probe::AsyncTaskContext* task_context) {
  DCHECK(task_context);
  if (task_context->IsAdTask()) {
    DCHECK_GE(running_ad_async_tasks_, 1);
    running_ad_async_tasks_ -= 1;
    if (running_ad_async_tasks_ == 0)
      bottom_most_async_ad_script_.reset();
  }
}

bool AdTracker::IsAdScriptInStack(
    StackType stack_type,
    std::optional<AdScriptIdentifier>* out_ad_script) {
  // First check if async tasks are running, as `bottom_most_async_ad_script_`
  // is more likely to be what the caller is looking for than
  // `bottom_most_ad_script_`.
  if (running_ad_async_tasks_ > 0) {
    if (out_ad_script)
      *out_ad_script = bottom_most_async_ad_script_;
    return true;
  }

  if (num_ads_in_stack_ > 0) {
    if (out_ad_script)
      *out_ad_script = bottom_most_ad_script_;
    return true;
  }

  ExecutionContext* execution_context = GetCurrentExecutionContext();
  if (!execution_context)
    return false;

  // If we're in an ad context, then no matter what the executing script is it's
  // considered an ad.
  if (IsKnownAdExecutionContext(execution_context))
    return true;

  if (stack_type == StackType::kBottomOnly)
    return false;

  // The stack scanned by the AdTracker contains entry points into the stack
  // (e.g., when v8 is executed) but not the entire stack. For a small cost we
  // can also check the top of the stack (this is much cheaper than getting the
  // full stack from v8).
  return IsKnownAdScriptForCheckedContext(*execution_context, String());
}

bool AdTracker::IsKnownAdScript(ExecutionContext* execution_context,
                                const String& url) {
  if (!execution_context)
    return false;

  if (IsKnownAdExecutionContext(execution_context))
    return true;

  return IsKnownAdScriptForCheckedContext(*execution_context, url);
}

bool AdTracker::IsKnownAdScriptForCheckedContext(
    ExecutionContext& execution_context,
    const String& url) {
  DCHECK(!IsKnownAdExecutionContext(&execution_context));
  auto it = known_ad_scripts_.find(&execution_context);
  if (it == known_ad_scripts_.end())
    return false;

  if (it->value.empty())
    return false;

  // Delay calling ScriptAtTopOfStack() as much as possible due to its cost.
  String script_url = url.IsNull() ? ScriptAtTopOfStack() : url;
  if (script_url.empty())
    return false;
  return it->value.Contains(script_url);
}

// This is a separate function for testing purposes.
void AdTracker::AppendToKnownAdScripts(ExecutionContext& execution_context,
                                       const String& url) {
  DCHECK(!url.empty());
  auto add_result =
      known_ad_scripts_.insert(&execution_context, HashSet<String>());
  add_result.stored_value->value.insert(url);
}

void AdTracker::Trace(Visitor* visitor) const {
  visitor->Trace(local_root_);
  visitor->Trace(known_ad_scripts_);
}

}  // namespace blink
```
Response:
The user wants to understand the functionality of the `InspectorPerformanceAgent` class in the Chromium Blink rendering engine. I need to go through the code and identify its main responsibilities. Specifically, I should look for:

1. **Core Functionality:** What is the purpose of this agent?
2. **Relationship with Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logical Reasoning:** Can I provide examples of input and output for specific methods?
4. **Common Usage Errors:** What mistakes might developers make when using this agent (although it's mostly for internal use)?

**Plan:**

1. Read through the code to understand the class members and methods.
2. Identify the key methods related to enabling, disabling, and collecting performance metrics.
3. Analyze how the agent tracks events related to JavaScript execution, style recalculation, layout, and other browser activities.
4. Determine how the collected metrics are exposed through the DevTools protocol.
5. Formulate explanations and examples based on the code analysis.
`InspectorPerformanceAgent.cc` 文件的主要功能是**收集和报告渲染引擎的性能指标**，这些指标可以通过 Chrome DevTools 的 Performance 面板进行查看。它充当了 Blink 渲染引擎和 DevTools 之间的桥梁，将底层的性能数据转换为开发者可以理解和分析的指标。

**具体功能列举:**

1. **启用和禁用性能监控:**
   - `enable(Maybe<String> optional_time_domain)`: 允许通过 DevTools 启用性能监控。可以指定时间域 (TimeTicks 或 ThreadTicks)。
   - `disable()`: 禁用性能监控。
   - `InnerEnable()`: 内部启用逻辑，例如注册性能观察器。

2. **管理时间域:**
   - `setTimeDomain(const String& time_domain)`:  允许设置性能指标的时间域，决定时间戳的来源。
   - `GetTimeTicksNow()`: 获取当前时间戳，会根据设置的时间域选择使用 `base::subtle::TimeTicksNowIgnoringOverride()` 或 `GetThreadTimeNow()`。
   - `GetThreadTimeNow()`: 获取当前线程的时间戳。
   - `HasTimeDomain(const String& time_domain)`: 检查当前是否使用了指定的时间域。
   - `InnerSetTimeDomain(const String& time_domain)`: 内部设置时间域的逻辑。

3. **收集各种性能指标:**
   - **通用指标:**
     - `Timestamp`: 当前时间戳。
     - `ThreadTime`: 当前线程的执行时间。
     - `ProcessTime`: 当前进程的 CPU 使用时间。
   - **渲染过程指标:**
     - `LayoutCount`: 布局的次数。
     - `RecalcStyleCount`: 样式重计算的次数。
     - `LayoutDuration`: 布局所花费的时间。
     - `RecalcStyleDuration`: 样式重计算所花费的时间。
   - **脚本执行指标:**
     - `ScriptDuration`: JavaScript 执行所花费的时间。
   - **V8 编译指标:**
     - `V8CompileDuration`: V8 编译 JavaScript 代码所花费的时间。
   - **任务执行指标:**
     - `TaskDuration`: 所有任务执行所花费的时间。
     - `TaskOtherDuration`: 除了脚本、样式重计算、布局和 DevTools 命令之外的其他任务所花费的时间。
   - **DevTools 命令执行指标:**
     - `DevToolsCommandDuration`:  DevTools 命令执行所花费的时间。
   - **内存指标:**
     - `JSHeapUsedSize`: JavaScript 堆的已用大小。
     - `JSHeapTotalSize`: JavaScript 堆的总大小。
   - **页面加载指标:**
     - `FirstMeaningfulPaint`: 首次有意义绘制的时间。
     - `DomContentLoaded`: DOMContentLoaded 事件触发的时间。
     - `NavigationStart`: 导航开始的时间。
   - **实例计数器:**  各种 Blink 内部对象的实例数量 (例如，HTMLElement, CSSRule 等)。

4. **通过 DevTools 协议报告指标:**
   - `getMetrics(std::unique_ptr<protocol::Array<protocol::Performance::Metric>>* out_result)`:  获取所有收集到的性能指标，并将其封装成 DevTools 协议格式的数据。
   - `ConsoleTimeStamp(v8::Isolate* isolate, v8::Local<v8::String> label)`:  当 JavaScript 代码中调用 `console.timeStamp()` 时，收集当时的性能指标并发送给 DevTools。

5. **监听并记录关键事件的时间:**
   - **JavaScript 执行:**
     - `ScriptStarts()`, `ScriptEnds()`:  使用 `script_call_depth_` 来跟踪嵌套的脚本调用，并计算总的脚本执行时间。
     - `Will(const probe::CallFunction& probe)`, `Did(const probe::CallFunction& probe)`
     - `Will(const probe::ExecuteScript& probe)`, `Did(const probe::ExecuteScript& probe)`
   - **样式重计算:**
     - `Will(const probe::RecalculateStyle& probe)`, `Did(const probe::RecalculateStyle& probe)`: 记录样式重计算的开始和结束时间，并累加持续时间。
   - **布局:**
     - `Will(const probe::UpdateLayout& probe)`, `Did(const probe::UpdateLayout& probe)`: 使用 `layout_depth_` 来跟踪嵌套的布局，并计算总的布局时间。
   - **V8 编译:**
     - `Will(const probe::V8Compile& probe)`, `Did(const probe::V8Compile& probe)`: 记录 V8 编译的开始和结束时间。
   - **DevTools 调试器任务:**
     - `WillStartDebuggerTask()`, `DidFinishDebuggerTask()`: 记录 DevTools 调试器任务的开始和结束时间。
   - **通用任务处理:**
     - `WillProcessTask(base::TimeTicks start_time)`, `DidProcessTask(base::TimeTicks start_time, base::TimeTicks end_time)`: 记录任务处理的开始和结束时间。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - `ScriptDuration` 指标直接反映了 JavaScript 代码执行所花费的时间。
    - `V8CompileDuration` 指标反映了 JavaScript 代码编译所花费的时间。
    - 当 JavaScript 调用 `console.timeStamp("label")` 时，`ConsoleTimeStamp` 方法会被调用，它会收集当前的性能指标并附带标签 "label" 发送给 DevTools。
    - **假设输入:**  JavaScript 代码中执行了复杂的计算。
    - **输出:** `ScriptDuration` 指标的值会增加，反映出 JavaScript 执行的时间消耗。

* **HTML:**
    - `DomContentLoaded` 指标反映了浏览器解析 HTML 并构建 DOM 树完成的时间点。
    - `FirstMeaningfulPaint` 指标与 HTML 结构和渲染相关，表示用户首次看到页面主要内容的时间。
    - **假设输入:**  HTML 结构复杂，包含大量的 DOM 元素。
    - **输出:**  `DomContentLoaded` 的时间可能会延迟，因为浏览器需要更长的时间来解析和构建 DOM 树。

* **CSS:**
    - `RecalcStyleDuration` 指标反映了浏览器计算和应用 CSS 样式所花费的时间。
    - `LayoutDuration` 指标在很大程度上受到 CSS 样式的影响，特别是那些会触发重排 (reflow) 的属性。
    - **假设输入:**  CSS 样式表非常庞大且复杂，或者 JavaScript 修改了元素的样式。
    - **输出:** `RecalcStyleCount` 和 `RecalcStyleDuration` 的值会增加，表明浏览器进行了更多的样式重计算，并花费了更多的时间。如果样式修改导致了布局变化，`LayoutCount` 和 `LayoutDuration` 的值也会增加。

**逻辑推理的假设输入与输出:**

假设 DevTools 启用了 Performance 监控，并且时间域设置为 `TimeTicks`。

* **假设输入:**  用户在网页上触发了一个按钮点击事件，该事件绑定了一个复杂的 JavaScript 函数，并且该函数会修改多个 DOM 元素的样式，这些样式修改会导致页面的布局发生变化。
* **输出:**
    - `ScriptDuration` 指标会增加，反映出 JavaScript 函数执行的时间。
    - `RecalcStyleCount` 指标会增加，因为 DOM 元素的样式被修改。
    - `RecalcStyleDuration` 指标会增加，反映出样式重计算所花费的时间。
    - `LayoutCount` 指标会增加，因为样式修改导致了布局的发生。
    - `LayoutDuration` 指标会增加，反映出布局计算所花费的时间。
    - 如果在 JavaScript 函数执行过程中有 V8 编译发生，`V8CompileDuration` 也会增加。
    - `TaskDuration` 指标会包含上述所有操作的时间。

**涉及用户或者编程常见的使用错误:**

虽然 `InspectorPerformanceAgent` 主要是内部使用，开发者不会直接操作它，但理解其背后的原理有助于避免一些性能问题：

1. **过度使用 JavaScript 进行 DOM 操作:**  如果 JavaScript 代码频繁且大量地修改 DOM 结构或样式，会导致大量的样式重计算和布局，从而增加 `RecalcStyleDuration` 和 `LayoutDuration`。
    - **示例:** 在循环中不断地修改元素的 `style` 属性。

2. **复杂的 CSS 选择器:** 使用过于复杂的 CSS 选择器会增加浏览器匹配元素的时间，从而影响样式重计算的性能。
    - **示例:** 使用多层嵌套的、属性选择器和伪类组合而成的选择器。

3. **强制同步布局 (Forced Synchronous Layout):** 在 JavaScript 中先读取某个元素的布局信息（例如 `offsetWidth`），然后再立即修改该元素的样式，这会导致浏览器强制进行同步布局，阻塞主线程，影响性能。
    - **示例:**
      ```javascript
      const element = document.getElementById('myElement');
      const width = element.offsetWidth; // 读取布局信息
      element.style.width = width + 10 + 'px'; // 修改样式，触发强制同步布局
      ```

4. **不必要的重绘 (Repaint) 和重排 (Reflow):**  某些 CSS 属性的修改只会触发重绘，而另一些则会触发重排。重排的开销远大于重绘。理解哪些 CSS 属性会触发重排，可以帮助开发者避免不必要的性能消耗。

理解 `InspectorPerformanceAgent` 如何跟踪这些指标，可以帮助开发者更好地理解和优化他们的代码，从而提升网页的性能。虽然开发者不能直接使用这个类，但可以通过 Chrome DevTools 的 Performance 面板来查看这些指标，并根据这些指标来定位性能瓶颈。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_performance_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/inspector_performance_agent.h"

#include <utility>

#include "base/process/process.h"
#include "base/process/process_metrics.h"
#include "base/time/time_override.h"
#include "base/types/expected.h"
#include "build/build_config.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"

namespace blink {

namespace TimeDomain = protocol::Performance::SetTimeDomain::TimeDomainEnum;

namespace {
constexpr bool IsPlural(std::string_view str) {
  return !str.empty() && str.back() == 's';
}

static constexpr auto kInstanceCounterNames = std::to_array<const char*>({
#define INSTANCE_COUNTER_NAME(name) (IsPlural(#name) ? #name : #name "s"),
    INSTANCE_COUNTERS_LIST(INSTANCE_COUNTER_NAME)
#undef INSTANCE_COUNTER_NAME
});

std::unique_ptr<base::ProcessMetrics> GetCurrentProcessMetrics() {
  base::ProcessHandle handle = base::Process::Current().Handle();
#if BUILDFLAG(IS_MAC)
  // Port provider can be null if querying the current process.
  return base::ProcessMetrics::CreateProcessMetrics(handle, nullptr);
#else
  return base::ProcessMetrics::CreateProcessMetrics(handle);
#endif
}

base::TimeDelta GetCurrentProcessTime() {
  std::unique_ptr<base::ProcessMetrics> process_metrics =
      GetCurrentProcessMetrics();
  return process_metrics->GetCumulativeCPUUsage().value_or(base::TimeDelta());
}

}  // namespace

InspectorPerformanceAgent::InspectorPerformanceAgent(
    InspectedFrames* inspected_frames)
    : inspected_frames_(inspected_frames),
      enabled_(&agent_state_, /*default_value=*/false),
      use_thread_ticks_(&agent_state_, /*default_value=*/false) {}

InspectorPerformanceAgent::~InspectorPerformanceAgent() = default;

void InspectorPerformanceAgent::Restore() {
  if (enabled_.Get())
    InnerEnable();
}

void InspectorPerformanceAgent::InnerEnable() {
  instrumenting_agents_->AddInspectorPerformanceAgent(this);
  Thread::Current()->AddTaskTimeObserver(this);
  layout_start_ticks_ = base::TimeTicks();
  recalc_style_start_ticks_ = base::TimeTicks();
  task_start_ticks_ = base::TimeTicks();
  script_start_ticks_ = base::TimeTicks();
  v8compile_start_ticks_ = base::TimeTicks();
  devtools_command_start_ticks_ = base::TimeTicks();
  thread_time_origin_ = GetThreadTimeNow();
}

protocol::Response InspectorPerformanceAgent::enable(
    Maybe<String> optional_time_domain) {
  String time_domain = optional_time_domain.value_or(TimeDomain::TimeTicks);
  if (enabled_.Get()) {
    if (!HasTimeDomain(time_domain)) {
      return protocol::Response::ServerError(
          "Cannot change time domain while performance metrics collection is "
          "enabled.");
    }
    return protocol::Response::Success();
  }

  protocol::Response response = InnerSetTimeDomain(time_domain);
  if (!response.IsSuccess())
    return response;

  enabled_.Set(true);
  InnerEnable();
  return protocol::Response::Success();
}

protocol::Response InspectorPerformanceAgent::disable() {
  if (!enabled_.Get())
    return protocol::Response::Success();
  enabled_.Clear();
  instrumenting_agents_->RemoveInspectorPerformanceAgent(this);
  Thread::Current()->RemoveTaskTimeObserver(this);
  return protocol::Response::Success();
}

namespace {
void AppendMetric(protocol::Array<protocol::Performance::Metric>* container,
                  const String& name,
                  double value) {
  container->emplace_back(protocol::Performance::Metric::create()
                              .setName(name)
                              .setValue(value)
                              .build());
}
}  // namespace

// TODO(crbug.com/1056306): remove this redundant API.
protocol::Response InspectorPerformanceAgent::setTimeDomain(
    const String& time_domain) {
  if (enabled_.Get()) {
    return protocol::Response::ServerError(
        "Cannot set time domain while performance metrics collection"
        " is enabled.");
  }

  // Prevent this devtools command duration from being collected to avoid
  // using start and end time from different time domains.
  devtools_command_start_ticks_ = base::TimeTicks();

  return InnerSetTimeDomain(time_domain);
}

base::TimeTicks InspectorPerformanceAgent::GetTimeTicksNow() {
  return use_thread_ticks_.Get() ? GetThreadTimeNow()
                                 : base::subtle::TimeTicksNowIgnoringOverride();
}

base::TimeTicks InspectorPerformanceAgent::GetThreadTimeNow() {
  return base::TimeTicks() +
         base::Microseconds(
             base::ThreadTicks::Now().since_origin().InMicroseconds());
}

bool InspectorPerformanceAgent::HasTimeDomain(const String& time_domain) {
  return use_thread_ticks_.Get() ? time_domain == TimeDomain::ThreadTicks
                                 : time_domain == TimeDomain::TimeTicks;
}

protocol::Response InspectorPerformanceAgent::InnerSetTimeDomain(
    const String& time_domain) {
  DCHECK(!enabled_.Get());

  if (time_domain == TimeDomain::TimeTicks) {
    use_thread_ticks_.Clear();
    return protocol::Response::Success();
  }

  if (time_domain == TimeDomain::ThreadTicks) {
    if (!base::ThreadTicks::IsSupported()) {
      return protocol::Response::ServerError(
          "Thread time is not supported on this platform.");
    }
    base::ThreadTicks::WaitUntilInitialized();
    use_thread_ticks_.Set(true);
    return protocol::Response::Success();
  }

  return protocol::Response::ServerError("Invalid time domain specification.");
}

protocol::Response InspectorPerformanceAgent::getMetrics(
    std::unique_ptr<protocol::Array<protocol::Performance::Metric>>*
        out_result) {
  if (!enabled_.Get()) {
    *out_result =
        std::make_unique<protocol::Array<protocol::Performance::Metric>>();
    return protocol::Response::Success();
  }

  auto result =
      std::make_unique<protocol::Array<protocol::Performance::Metric>>();

  AppendMetric(result.get(), "Timestamp",
               base::TimeTicks::Now().since_origin().InSecondsF());

  // Renderer instance counters.
  for (size_t i = 0; i < std::size(kInstanceCounterNames); ++i) {
    AppendMetric(result.get(), kInstanceCounterNames[i],
                 InstanceCounters::CounterValue(
                     static_cast<InstanceCounters::CounterType>(i)));
  }

  // Page performance metrics.
  base::TimeTicks now = GetTimeTicksNow();
  AppendMetric(result.get(), "LayoutCount", static_cast<double>(layout_count_));
  AppendMetric(result.get(), "RecalcStyleCount",
               static_cast<double>(recalc_style_count_));
  AppendMetric(result.get(), "LayoutDuration", layout_duration_.InSecondsF());
  AppendMetric(result.get(), "RecalcStyleDuration",
               recalc_style_duration_.InSecondsF());

  base::TimeDelta devtools_command_duration = devtools_command_duration_;
  if (!devtools_command_start_ticks_.is_null())
    devtools_command_duration += now - devtools_command_start_ticks_;
  AppendMetric(result.get(), "DevToolsCommandDuration",
               devtools_command_duration.InSecondsF());

  base::TimeDelta script_duration = script_duration_;
  if (!script_start_ticks_.is_null())
    script_duration += now - script_start_ticks_;
  AppendMetric(result.get(), "ScriptDuration", script_duration.InSecondsF());

  base::TimeDelta v8compile_duration = v8compile_duration_;
  if (!v8compile_start_ticks_.is_null())
    v8compile_duration += now - v8compile_start_ticks_;
  AppendMetric(result.get(), "V8CompileDuration",
               v8compile_duration.InSecondsF());

  base::TimeDelta task_duration = task_duration_;
  if (!task_start_ticks_.is_null())
    task_duration += now - task_start_ticks_;
  AppendMetric(result.get(), "TaskDuration", task_duration.InSecondsF());

  // Compute task time not accounted for by other metrics.
  base::TimeDelta known_tasks_duration =
      script_duration + v8compile_duration + recalc_style_duration_ +
      layout_duration_ + devtools_command_duration;
  base::TimeDelta other_tasks_duration = task_duration - known_tasks_duration;
  AppendMetric(result.get(), "TaskOtherDuration",
               other_tasks_duration.InSecondsF());

  base::TimeDelta thread_time = GetThreadTimeNow() - thread_time_origin_;
  AppendMetric(result.get(), "ThreadTime", thread_time.InSecondsF());

  base::TimeDelta process_time = GetCurrentProcessTime();
  AppendMetric(result.get(), "ProcessTime", process_time.InSecondsF());

  // Performance timings.
  Document* document = inspected_frames_->Root()->GetDocument();
  if (document) {
    v8::HeapStatistics heap_statistics;
    document->GetAgent().isolate()->GetHeapStatistics(&heap_statistics);
    AppendMetric(result.get(), "JSHeapUsedSize",
                 heap_statistics.used_heap_size());
    AppendMetric(result.get(), "JSHeapTotalSize",
                 heap_statistics.total_heap_size());

    AppendMetric(result.get(), "FirstMeaningfulPaint",
                 PaintTiming::From(*document)
                     .FirstMeaningfulPaint()
                     .since_origin()
                     .InSecondsF());
    AppendMetric(result.get(), "DomContentLoaded",
                 document->GetTiming()
                     .DomContentLoadedEventStart()
                     .since_origin()
                     .InSecondsF());
    AppendMetric(result.get(), "NavigationStart",
                 document->Loader()
                     ->GetTiming()
                     .NavigationStart()
                     .since_origin()
                     .InSecondsF());
  }

  *out_result = std::move(result);
  return protocol::Response::Success();
}

void InspectorPerformanceAgent::ConsoleTimeStamp(v8::Isolate* isolate,
                                                 v8::Local<v8::String> label) {
  if (!enabled_.Get())
    return;
  std::unique_ptr<protocol::Array<protocol::Performance::Metric>> metrics;
  getMetrics(&metrics);
  GetFrontend()->metrics(std::move(metrics), ToCoreString(isolate, label));
}

void InspectorPerformanceAgent::ScriptStarts() {
  if (!script_call_depth_++)
    script_start_ticks_ = GetTimeTicksNow();
}

void InspectorPerformanceAgent::ScriptEnds() {
  if (--script_call_depth_)
    return;
  base::TimeDelta delta = GetTimeTicksNow() - script_start_ticks_;
  script_duration_ += delta;
  script_start_ticks_ = base::TimeTicks();

  // Exclude nested script execution from devtools command duration.
  if (!devtools_command_start_ticks_.is_null())
    devtools_command_start_ticks_ += delta;
}

void InspectorPerformanceAgent::Will(const probe::CallFunction& probe) {
  ScriptStarts();
}

void InspectorPerformanceAgent::Did(const probe::CallFunction& probe) {
  ScriptEnds();
}

void InspectorPerformanceAgent::Will(const probe::ExecuteScript& probe) {
  ScriptStarts();
}

void InspectorPerformanceAgent::Did(const probe::ExecuteScript& probe) {
  ScriptEnds();
}

void InspectorPerformanceAgent::Will(const probe::RecalculateStyle& probe) {
  recalc_style_start_ticks_ = GetTimeTicksNow();
}

void InspectorPerformanceAgent::Did(const probe::RecalculateStyle& probe) {
  if (recalc_style_start_ticks_.is_null())
    return;

  base::TimeDelta delta = GetTimeTicksNow() - recalc_style_start_ticks_;
  recalc_style_duration_ += delta;
  recalc_style_count_++;
  recalc_style_start_ticks_ = base::TimeTicks();

  // Exclude nested style re-calculations from script, layout and devtools
  // command durations.
  if (!script_start_ticks_.is_null())
    script_start_ticks_ += delta;
  if (!layout_start_ticks_.is_null())
    layout_start_ticks_ += delta;
  if (!devtools_command_start_ticks_.is_null())
    devtools_command_start_ticks_ += delta;
}

void InspectorPerformanceAgent::Will(const probe::UpdateLayout& probe) {
  if (!layout_depth_++)
    layout_start_ticks_ = GetTimeTicksNow();
}

void InspectorPerformanceAgent::Did(const probe::UpdateLayout& probe) {
  if (--layout_depth_ || layout_start_ticks_.is_null())
    return;

  base::TimeDelta delta = GetTimeTicksNow() - layout_start_ticks_;
  layout_duration_ += delta;
  layout_count_++;
  layout_start_ticks_ = base::TimeTicks();

  // Exclude nested layout update from script, style re-calculations and
  // devtools command durations.
  if (!script_start_ticks_.is_null())
    script_start_ticks_ += delta;
  if (!recalc_style_start_ticks_.is_null())
    recalc_style_start_ticks_ += delta;
  if (!devtools_command_start_ticks_.is_null())
    devtools_command_start_ticks_ += delta;
}

void InspectorPerformanceAgent::Will(const probe::V8Compile& probe) {
  DCHECK(v8compile_start_ticks_.is_null());
  v8compile_start_ticks_ = GetTimeTicksNow();
}

void InspectorPerformanceAgent::Did(const probe::V8Compile& probe) {
  if (v8compile_start_ticks_.is_null())
    return;

  base::TimeDelta delta = GetTimeTicksNow() - v8compile_start_ticks_;
  v8compile_duration_ += delta;
  v8compile_start_ticks_ = base::TimeTicks();

  // Exclude nested script compilation from devtools command duration.
  if (!devtools_command_start_ticks_.is_null())
    devtools_command_start_ticks_ += delta;
}

void InspectorPerformanceAgent::WillStartDebuggerTask() {
  devtools_command_start_ticks_ = GetTimeTicksNow();
}

void InspectorPerformanceAgent::DidFinishDebuggerTask() {
  if (devtools_command_start_ticks_.is_null())
    return;

  devtools_command_duration_ +=
      GetTimeTicksNow() - devtools_command_start_ticks_;
  devtools_command_start_ticks_ = base::TimeTicks();
}

// Will/DidProcessTask() ignore caller provided times to ensure time domain
// consistency with other metrics collected in this module.
void InspectorPerformanceAgent::WillProcessTask(base::TimeTicks start_time) {
  task_start_ticks_ = GetTimeTicksNow();
}

void InspectorPerformanceAgent::DidProcessTask(base::TimeTicks start_time,
                                               base::TimeTicks end_time) {
  if (task_start_ticks_.is_null())
    return;

  task_duration_ += GetTimeTicksNow() - task_start_ticks_;
  task_start_ticks_ = base::TimeTicks();
}

void InspectorPerformanceAgent::Trace(Visitor* visitor) const {
  visitor->Trace(inspected_frames_);
  InspectorBaseAgent<protocol::Performance::Metainfo>::Trace(visitor);
}

}  // namespace blink

"""

```
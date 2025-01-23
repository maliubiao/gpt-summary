Response:
Let's break down the thought process for analyzing the `profiler_group.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific Chromium Blink file and how it interacts with other web technologies. The request also specifically asks for examples, logic inference, common errors, and debugging hints.

2. **Initial Scan and Keyword Identification:** Quickly skim the code, looking for keywords and recognizable patterns. Keywords like `Profiler`, `Profiling`, `Sample`, `V8`, `JavaScript`, `DOM`, `Event`, `Time`, `Isolate`, `Promise`, etc., jump out. The inclusion of V8 headers strongly suggests this is related to JavaScript profiling.

3. **Identify the Core Class:** The central class is `ProfilerGroup`. This immediately tells us it's responsible for managing a *group* of profilers.

4. **Deconstruct the Class Structure:**  Examine the member variables and methods of `ProfilerGroup`. This reveals:
    * `isolate_`:  Connection to the V8 JavaScript engine.
    * `cpu_profiler_`:  A pointer to the V8 CPU profiler, confirming the purpose.
    * `profilers_`: A collection of `Profiler` objects, confirming the "group" aspect.
    * `context_observers_`:  Tracks execution contexts.
    * Methods like `CreateProfiler`, `StopProfiler`, `CancelProfiler`, indicating the lifecycle management of profilers.
    * `InitV8Profiler`, `TeardownV8Profiler`:  Initialization and cleanup of the underlying V8 profiler.
    * `DispatchSampleBufferFullEvent`: Handles events when the sample buffer is full.

5. **Trace Key Interactions:** Follow the flow of important methods:
    * **`InitializeIfEnabled` and `CanProfile`:** These methods control whether profiling is allowed, based on document policy. This links to HTML (document policy).
    * **`CreateProfiler`:**  This is where a new profiler instance is created. It takes `ProfilerInitOptions` (which are likely exposed to JavaScript), interacts with the V8 profiler (`StartProfiling`), and creates a `Profiler` object. This establishes the connection between JavaScript and the native profiling mechanism.
    * **`StopProfiler`:**  Stops the V8 profiler (`StopProfiling`), retrieves the profiling data, and uses `ProfilerTraceBuilder` to format it. The `ScriptPromiseResolver` suggests this is an asynchronous operation exposed to JavaScript.
    * **`CancelProfiler` and `CancelProfilerAsync`:**  Mechanisms for stopping profiling without necessarily retrieving the data. The asynchronous version suggests dealing with potential context destruction.

6. **Infer Functionality:** Based on the methods and members, deduce the overall purpose: `ProfilerGroup` manages the creation, starting, stopping, and cancellation of CPU profilers for JavaScript execution within a Blink rendering engine. It acts as an intermediary between the JavaScript API and the V8 engine's profiling capabilities.

7. **Connect to Web Technologies:**  Consider how this interacts with JavaScript, HTML, and CSS:
    * **JavaScript:**  The most direct link. JavaScript APIs would likely call methods in `ProfilerGroup` (or a related class that uses it) to start and stop profiling. The returned data would be used for analysis within JavaScript.
    * **HTML:** The `CanProfile` method checks document policy, which is defined in HTML. This shows how HTML can control browser features.
    * **CSS:**  Less direct. However, inefficient CSS can lead to more JavaScript execution (e.g., through layout thrashing or complex animations), which would be captured by the profiler. So, while not directly interacting with CSS parsing, it can help diagnose performance issues related to CSS.

8. **Develop Examples:** Create concrete examples to illustrate the interactions. Think about a typical JavaScript profiling workflow: starting, performing actions, stopping, and receiving the data. For HTML, focus on the document policy aspect.

9. **Consider Edge Cases and Errors:** Think about what could go wrong:
    * Invalid sample intervals.
    * Too many concurrent profilers.
    * Trying to profile when it's disabled by policy.
    * Issues with asynchronous operations and context destruction.

10. **Imagine Debugging Scenarios:**  How would a developer end up in this code?  Think about the steps leading to profiling: enabling dev tools, starting a profiling session, interacting with the page, and then the browser needing to manage the profiling.

11. **Structure the Answer:** Organize the findings logically into sections as requested: Functionality, Relationship to Web Tech, Logic Inference, Common Errors, and Debugging.

12. **Refine and Clarify:** Review the answer for clarity, accuracy, and completeness. Ensure the examples are understandable and the explanations are concise. For instance, initially, I might have just said "it profiles JavaScript." But refining it means explaining *how* it does this by interacting with V8, managing profiler instances, and handling events.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this directly handles the sampling. **Correction:**  The code interacts with the *V8* CPU profiler, which does the heavy lifting of sampling. `ProfilerGroup` is more of a manager.
* **Initial thought:**  The link to HTML is weak. **Correction:** The `CanProfile` method checks document policy, which is a significant HTML-related feature controlling browser behavior.
* **Initial thought:**  Focus only on the happy path. **Correction:**  Consider error conditions and how they are handled (e.g., throwing exceptions).
* **Initial thought:** Describe every single line of code. **Correction:** Focus on the *key functionalities* and interactions, avoiding overly granular details unless they are particularly important.

By following these steps, iterating, and refining, you can produce a comprehensive and accurate analysis of the given source code file.
好的，让我们来分析一下 `blink/renderer/core/timing/profiler_group.cc` 这个 Chromium Blink 引擎的源代码文件。

**功能概览:**

`ProfilerGroup` 类的主要功能是管理和协调 JavaScript CPU 的性能分析（Profiling）。它充当了 Blink 渲染引擎和 V8 JavaScript 引擎的 CPU Profiler 之间的桥梁。  更具体地说，它负责：

1. **创建和管理 Profiler 实例:**  当 JavaScript 代码请求开始性能分析时，`ProfilerGroup` 会创建 `Profiler` 类的实例来跟踪特定的分析会话。
2. **与 V8 CPU Profiler 交互:** 它使用 V8 引擎提供的 CPU Profiler API (`v8::CpuProfiler`) 来启动、停止和获取性能分析数据。
3. **控制 Profiling 的启用和禁用:** 它会检查诸如文档策略 (Document Policy) 等因素来决定是否允许进行性能分析。
4. **处理 Profiler 的生命周期:**  跟踪哪些 Profiler 正在运行，并在不再需要时清理资源。
5. **处理异步 Profiler 的取消:**  提供异步取消 Profiler 的机制，尤其是在关联的执行上下文可能被销毁的情况下。
6. **生成 Profiling 结果:** 将 V8 CPU Profiler 生成的原始数据转换为更易于使用的 `ProfilerTrace` 对象。
7. **处理 Profiler 相关的事件:** 例如，当采样缓冲区满时，会触发 `samplebufferfull` 事件。
8. **管理 Profiling 上下文:** 跟踪哪些执行上下文正在进行性能分析，并在上下文被销毁时进行清理。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**  `ProfilerGroup` 的核心功能是为 JavaScript 代码的性能分析提供支持。
    * **举例:**  JavaScript 代码可以使用浏览器提供的 Profiling API (例如，在 Chrome 开发者工具中点击 "Performance" 面板的 "Start profiling and record JavaScript CPU profile") 来触发 `ProfilerGroup` 创建和管理 Profiler 实例。  `ProfilerGroup` 最终会调用 V8 的 `cpu_profiler_->StartProfiling()` 来启动 JavaScript 的性能分析。
    * **假设输入与输出:**
        * **假设输入:**  JavaScript 代码调用 `console.profile('my-profile')` 或使用开发者工具启动性能分析。
        * **逻辑推理:**  Blink 接收到这个请求，`ProfilerGroup::CreateProfiler` 会被调用，与 V8 CPU Profiler 交互启动分析，并创建一个 `Profiler` 对象来跟踪这次会话。
        * **假设输入:** JavaScript 代码调用 `console.profileEnd('my-profile')` 或使用开发者工具停止性能分析。
        * **逻辑推理:** Blink 接收到停止请求，`ProfilerGroup::StopProfiler` 会被调用，与 V8 CPU Profiler 交互停止分析，并获取分析数据。然后使用 `ProfilerTraceBuilder` 将数据转换为 `ProfilerTrace` 对象，并通过 Promise 返回给 JavaScript。
* **HTML:**  `ProfilerGroup` 会检查文档策略，这与 HTML 中通过 `<meta>` 标签或其他方式设置的策略有关。
    * **举例:**  HTML 中可能包含如下的 `<meta>` 标签，禁止 JavaScript Profiling：
      ```html
      <meta http-equiv="document-policy" content="js-profiling=off">
      ```
    * **逻辑推理:** 当 JavaScript 尝试开始 Profiling 时，`ProfilerGroup::CanProfile` 会检查当前文档的策略。如果策略禁止 `js-profiling`，则会抛出一个 `NotAllowedError` 异常。
* **CSS:**  虽然 `ProfilerGroup` 不直接与 CSS 交互，但 CSS 的性能问题可能会导致 JavaScript 执行时间过长，从而被 Profiler 捕获。
    * **举例:**  一个复杂的 CSS 选择器或大量的 CSS 动画可能会导致浏览器在渲染时执行大量的 JavaScript 代码（例如，为了计算布局或更新动画）。当进行性能分析时，`ProfilerGroup` 会记录这些 JavaScript 执行的时间，从而间接地反映了 CSS 的性能影响。

**逻辑推理的假设输入与输出:**

* **假设输入:** 调用 `ProfilerGroup::From(isolate)`，并且该 `isolate` 还没有关联的 `ProfilerGroup`。
* **逻辑推理:** 代码会检查 `isolate_data->GetUserData(V8PerIsolateData::UserData::Key::kProfileGroup)` 是否为空。因为是第一次调用，所以为空。
* **输出:**  会创建一个新的 `ProfilerGroup` 对象，并将其存储在 `isolate_data` 中，然后返回该对象。
* **假设输入:** 调用 `ProfilerGroup::CreateProfiler`，传入一个有效的 `ScriptState` 和 `ProfilerInitOptions`，且当前没有达到最大 Profiler 数量限制。
* **逻辑推理:** 代码会调用 V8 CPU Profiler 的 `StartProfiling` 方法，创建一个新的 `Profiler` 对象，并将其添加到 `profilers_` 列表中。
* **输出:**  返回新创建的 `Profiler` 对象。

**用户或编程常见的使用错误举例:**

* **在文档策略禁用 Profiling 的情况下尝试启动 Profiler:**
    * **错误代码 (JavaScript):**
      ```javascript
      console.profile('my-profile'); // 如果文档策略禁止 profiling
      ```
    * **结果:**  `ProfilerGroup::CanProfile` 会返回 `false`，并抛出一个 `NotAllowedError` 异常。
* **提供无效的采样间隔:**
    * **错误代码 (JavaScript):**
      ```javascript
      performance.profile({sampleInterval: -10}); // 负的采样间隔
      ```
    * **结果:**  `ProfilerGroup::CreateProfiler` 中会检查 `sample_interval_us` 的值，如果小于 0 或超出最大值，会抛出一个 `RangeError` 异常。
* **尝试创建过多的 Profiler:**  V8 CPU Profiler 有并发数量限制。
    * **操作步骤:**  在很短的时间内，多次调用 `console.profile()` 但不调用 `console.profileEnd()`，导致创建大量的 Profiler 对象。
    * **结果:**  当达到 V8 的限制时，`cpu_profiler_->StartProfiling` 会返回 `v8::CpuProfilingStatus::kErrorTooManyProfilers`，`ProfilerGroup::CreateProfiler` 会抛出一个 `TypeError` 异常。
* **忘记停止 Profiler:**
    * **操作步骤:** 调用 `console.profile()` 后，代码执行完毕但没有调用 `console.profileEnd()`。
    * **结果:**  Profiler 会一直运行，消耗资源。虽然 `ProfilerGroup` 在其析构函数中会尝试清理，但最好还是显式地停止 Profiler。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在 Chrome 浏览器中访问了一个网页，并希望分析该网页的 JavaScript 性能。以下是用户操作如何逐步触发 `profiler_group.cc` 中的代码：

1. **用户打开 Chrome 开发者工具 (DevTools):**  这是一个开始调试和性能分析的入口点。
2. **用户切换到 "Performance" (或 "性能") 面板:**  这个面板提供了性能分析的相关功能。
3. **用户点击 "Start profiling and record JavaScript CPU profile" 按钮 (或类似的按钮):**  这个操作会触发 DevTools 向渲染进程发送消息，请求开始 JavaScript 的 CPU 性能分析。
4. **Blink 渲染引擎接收到该消息:**  渲染进程中的代码会处理这个请求。
5. **调用 JavaScript Profiling API:**  DevTools 通常会通过调用 JavaScript 提供的 Profiling API（例如 `console.profile()` 或 `performance.profile()`) 来启动性能分析。
6. **V8 引擎接收到 Profiling API 的调用:**  V8 引擎会处理这些 API 调用。
7. **V8 引擎通知 Blink 的 `ProfilerGroup`:**  V8 引擎会通知 Blink 的 `ProfilerGroup` 需要开始一个新的性能分析会话。这通常涉及到调用 `ProfilerGroup::CreateProfiler`。
8. **`ProfilerGroup` 与 V8 CPU Profiler 交互:**  `ProfilerGroup` 会调用 V8 CPU Profiler 的 `StartProfiling` 方法，启动底层的性能分析机制。
9. **性能分析进行中:**  V8 CPU Profiler 会定期采样 JavaScript 的调用栈信息。
10. **用户执行一些操作导致 JavaScript 代码执行:**  用户的交互行为（例如点击按钮、滚动页面、输入文本等）会触发 JavaScript 代码的执行。
11. **用户点击 "Stop" 按钮 (或类似的按钮):**  用户停止性能分析。
12. **DevTools 发送停止分析的请求:**  DevTools 向渲染进程发送消息，请求停止性能分析。
13. **Blink 渲染引擎接收到停止请求:**  渲染进程中的代码处理停止请求。
14. **调用 JavaScript Profiling API (停止):** DevTools 通常会通过调用 JavaScript 提供的 Profiling API（例如 `console.profileEnd()`) 来停止性能分析。
15. **V8 引擎接收到 Profiling API 的停止调用:**  V8 引擎处理停止调用。
16. **V8 引擎通知 Blink 的 `ProfilerGroup`:**  V8 引擎通知 Blink 的 `ProfilerGroup` 需要停止性能分析会话。这通常涉及到调用 `ProfilerGroup::StopProfiler`。
17. **`ProfilerGroup` 与 V8 CPU Profiler 交互 (停止):** `ProfilerGroup` 会调用 V8 CPU Profiler 的 `StopProfiling` 方法，停止底层的性能分析，并获取分析数据。
18. **`ProfilerGroup` 生成 Profiling 结果:**  `ProfilerGroup` 使用 `ProfilerTraceBuilder` 将 V8 CPU Profiler 返回的原始数据转换为 `ProfilerTrace` 对象。
19. **Profiling 结果返回给 DevTools:**  `ProfilerTrace` 对象被传递回 DevTools，用于在 "Performance" 面板中展示给用户。

**作为调试线索:**

如果在调试过程中怀疑性能分析功能存在问题，可以按照以下步骤进行：

1. **设置断点:** 在 `profiler_group.cc` 中关键的方法（例如 `CreateProfiler`, `StopProfiler`, `CanProfile`）设置断点。
2. **重现问题:**  在浏览器中执行导致问题的操作，触发性能分析流程。
3. **观察调用栈:**  当断点被触发时，查看调用栈，了解代码是如何一步步到达这里的。这可以帮助你理解问题的上下文。
4. **检查变量值:**  检查关键变量的值（例如 `init_options`, `sample_interval`, `status`），了解性能分析的参数和 V8 CPU Profiler 的状态。
5. **查看日志:**  在 `profiler_group.cc` 中添加一些调试日志，输出关键信息，例如 Profiler 的 ID，开始和停止的时间等。
6. **分析 V8 CPU Profiler 的行为:**  如果问题与 V8 CPU Profiler 本身有关，可能需要查看 V8 引擎的源代码或使用 V8 提供的调试工具。

总而言之，`profiler_group.cc` 是 Blink 渲染引擎中一个关键的组件，它负责管理 JavaScript 的 CPU 性能分析，并与 V8 引擎紧密合作，为开发者提供性能优化的重要工具。

### 提示词
```
这是目录为blink/renderer/core/timing/profiler_group.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/profiler_group.h"

#include "base/ranges/algorithm.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/profiler_trace_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_profiler_init_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_profiler_trace.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/timing/profiler.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "v8/include/v8-profiler.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

#if BUILDFLAG(IS_WIN)
// On Windows, assume we have the coarsest possible timer.
static constexpr int kBaseSampleIntervalMs =
    base::Time::kMinLowResolutionThresholdMs;
#else
// Default to a 10ms base sampling interval on other platforms.
// TODO(acomminos): Reevaluate based on empirical overhead.
static constexpr int kBaseSampleIntervalMs = 10;
#endif  // BUILDFLAG(IS_WIN)

}  // namespace

class ProfilerGroup::ProfilingContextObserver
    : public GarbageCollected<ProfilingContextObserver>,
      public ExecutionContextLifecycleObserver {
 public:
  ProfilingContextObserver(ProfilerGroup* profiler_group,
                           ExecutionContext* context)
      : ExecutionContextLifecycleObserver(context),
        profiler_group_(profiler_group) {}

  void ContextDestroyed() override {
    DCHECK(profiler_group_);
    profiler_group_->OnProfilingContextDestroyed(this);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(profiler_group_);
    ExecutionContextLifecycleObserver::Trace(visitor);
  }

  // Invariant: ProfilerGroup will outlive the tracked execution context, as
  // the execution context must live as long as the isolate.
  Member<ProfilerGroup> profiler_group_;
};

bool ProfilerGroup::CanProfile(LocalDOMWindow* local_window,
                               ExceptionState* exception_state,
                               ReportOptions report_options) {
  DCHECK(local_window);
  if (!local_window->IsFeatureEnabled(
          mojom::blink::DocumentPolicyFeature::kJSProfiling, report_options)) {
    if (exception_state) {
      exception_state->ThrowDOMException(
          DOMExceptionCode::kNotAllowedError,
          "JS profiling is disabled by Document Policy.");
    }
    return false;
  }

  return true;
}

void ProfilerGroup::InitializeIfEnabled(LocalDOMWindow* local_window) {
  if (ProfilerGroup::CanProfile(local_window)) {
    auto* profiler_group = ProfilerGroup::From(local_window->GetIsolate());
    profiler_group->OnProfilingContextAdded(local_window);
  }
}

ProfilerGroup* ProfilerGroup::From(v8::Isolate* isolate) {
  auto* isolate_data = V8PerIsolateData::From(isolate);
  auto* profiler_group =
      reinterpret_cast<ProfilerGroup*>(isolate_data->GetUserData(
          V8PerIsolateData::UserData::Key::kProfileGroup));
  if (!profiler_group) {
    profiler_group = MakeGarbageCollected<ProfilerGroup>(isolate);
    isolate_data->SetUserData(V8PerIsolateData::UserData::Key::kProfileGroup,
                              profiler_group);
  }
  return profiler_group;
}

base::TimeDelta ProfilerGroup::GetBaseSampleInterval() {
  return base::Milliseconds(kBaseSampleIntervalMs);
}

ProfilerGroup::ProfilerGroup(v8::Isolate* isolate)
    : isolate_(isolate),
      cpu_profiler_(nullptr),
      next_profiler_id_(0),
      num_active_profilers_(0) {}

void DiscardedSamplesDelegate::Notify() {
  if (profiler_group_) {
    profiler_group_->DispatchSampleBufferFullEvent(profiler_id_);
  }
}

void ProfilerGroup::OnProfilingContextAdded(ExecutionContext* context) {
  // Retain an observer for the context's lifetime. During which, keep the V8
  // profiler alive.
  auto* observer =
      MakeGarbageCollected<ProfilingContextObserver>(this, context);
  context_observers_.insert(observer);

  if (!cpu_profiler_) {
    InitV8Profiler();
    DCHECK(cpu_profiler_);
  }
}

void ProfilerGroup::DispatchSampleBufferFullEvent(String profiler_id) {
  for (const auto& profiler : profilers_) {
    if (profiler->ProfilerId() == profiler_id) {
      profiler->DispatchEvent(
          *Event::Create(event_type_names::kSamplebufferfull));
      break;
    }
  }
}

Profiler* ProfilerGroup::CreateProfiler(ScriptState* script_state,
                                        const ProfilerInitOptions& init_options,
                                        base::TimeTicks time_origin,
                                        ExceptionState& exception_state) {
  DCHECK_EQ(script_state->GetIsolate(), isolate_);
  DCHECK(init_options.hasSampleInterval());

  const base::TimeDelta sample_interval =
      base::Milliseconds(init_options.sampleInterval());
  const int64_t sample_interval_us = sample_interval.InMicroseconds();

  if (sample_interval_us < 0 ||
      sample_interval_us > std::numeric_limits<int>::max()) {
    exception_state.ThrowRangeError("Invalid sample interval");
    return nullptr;
  }

  if (!cpu_profiler_) {
    DCHECK(false);
    exception_state.ThrowTypeError("Error creating profiler");
    return nullptr;
  }

  String profiler_id = NextProfilerId();

  v8::CpuProfilingStatus status = cpu_profiler_->StartProfiling(
      V8String(isolate_, profiler_id),
      v8::CpuProfilingOptions(
          v8::kLeafNodeLineNumbers, init_options.maxBufferSize(),
          static_cast<int>(sample_interval_us), script_state->GetContext()),
      std::make_unique<DiscardedSamplesDelegate>(this, profiler_id));

  switch (status) {
    case v8::CpuProfilingStatus::kErrorTooManyProfilers: {
      exception_state.ThrowTypeError(
          "Reached maximum concurrent amount of profilers");
      return nullptr;
    }
    case v8::CpuProfilingStatus::kAlreadyStarted: {
      // Since we increment the profiler id for every invocation of
      // StartProfiling, we do not expect to hit kAlreadyStarted status
      DCHECK(false);
      return nullptr;
    }
    case v8::CpuProfilingStatus::kStarted: {
      // Limit non-crossorigin script frames to the origin that started the
      // profiler.
      auto* execution_context = ExecutionContext::From(script_state);
      scoped_refptr<const SecurityOrigin> source_origin(
          execution_context->GetSecurityOrigin());

      // The V8 CPU profiler ticks in multiples of the base sampling interval.
      // This effectively means that we gather samples at the multiple of the
      // base sampling interval that's greater than or equal to the requested
      // interval.
      int effective_sample_interval_ms =
          static_cast<int>(sample_interval.InMilliseconds());
      if (effective_sample_interval_ms % kBaseSampleIntervalMs != 0 ||
          effective_sample_interval_ms == 0) {
        effective_sample_interval_ms +=
            (kBaseSampleIntervalMs -
             effective_sample_interval_ms % kBaseSampleIntervalMs);
      }

      auto* profiler = MakeGarbageCollected<Profiler>(
          this, script_state, profiler_id, effective_sample_interval_ms,
          source_origin, time_origin);
      profilers_.insert(profiler);
      num_active_profilers_++;
      return profiler;
    }
  }
}

ProfilerGroup::~ProfilerGroup() {
  // v8::CpuProfiler should have been torn down by WillBeDestroyed.
  DCHECK(!cpu_profiler_);
}

void ProfilerGroup::WillBeDestroyed() {
  while (!profilers_.empty()) {
    Profiler* profiler = profilers_.begin()->Get();
    DCHECK(profiler);
    CancelProfiler(profiler);
    profiler->RemovedFromProfilerGroup();
    DCHECK(profiler->stopped());
    DCHECK(!profilers_.Contains(profiler));
  }

  StopDetachedProfilers();

  if (cpu_profiler_)
    TeardownV8Profiler();
}

void ProfilerGroup::Trace(Visitor* visitor) const {
  visitor->Trace(profilers_);
  visitor->Trace(context_observers_);
  V8PerIsolateData::UserData::Trace(visitor);
}

void ProfilerGroup::OnProfilingContextDestroyed(
    ProfilingContextObserver* observer) {
  context_observers_.erase(observer);
  if (context_observers_.size() == 0) {
    WillBeDestroyed();
  }
}

void ProfilerGroup::InitV8Profiler() {
  DCHECK(!cpu_profiler_);
  DCHECK_EQ(num_active_profilers_, 0);

  cpu_profiler_ =
      v8::CpuProfiler::New(isolate_, v8::kStandardNaming, v8::kEagerLogging);
#if BUILDFLAG(IS_WIN)
  // Avoid busy-waiting on Windows, clamping us to the system clock interrupt
  // interval in the worst case.
  cpu_profiler_->SetUsePreciseSampling(false);
#endif  // BUILDFLAG(IS_WIN)
  cpu_profiler_->SetSamplingInterval(kBaseSampleIntervalMs *
                                     base::Time::kMicrosecondsPerMillisecond);
}

void ProfilerGroup::TeardownV8Profiler() {
  DCHECK(cpu_profiler_);
  DCHECK_EQ(num_active_profilers_, 0);

  cpu_profiler_->Dispose();
  cpu_profiler_ = nullptr;
}

void ProfilerGroup::StopProfiler(
    ScriptState* script_state,
    Profiler* profiler,
    ScriptPromiseResolver<ProfilerTrace>* resolver) {
  DCHECK(cpu_profiler_);
  DCHECK(!profiler->stopped());

  v8::Local<v8::String> profiler_id =
      V8String(isolate_, profiler->ProfilerId());
  auto* profile = cpu_profiler_->StopProfiling(profiler_id);
  auto* trace = ProfilerTraceBuilder::FromProfile(
      script_state, profile, profiler->SourceOrigin(), profiler->TimeOrigin());
  resolver->Resolve(trace);

  if (profile)
    profile->Delete();

  profilers_.erase(profiler);
  --num_active_profilers_;
}

void ProfilerGroup::CancelProfiler(Profiler* profiler) {
  DCHECK(cpu_profiler_);
  DCHECK(!profiler->stopped());
  profilers_.erase(profiler);
  CancelProfilerImpl(profiler->ProfilerId());
}

void ProfilerGroup::CancelProfilerAsync(ScriptState* script_state,
                                        Profiler* profiler) {
  DCHECK(IsMainThread());
  DCHECK(cpu_profiler_);
  DCHECK(!profiler->stopped());
  profilers_.erase(profiler);

  // register the profiler to be cleaned up in case its associated context
  // gets destroyed before the cleanup task is executed.
  detached_profiler_ids_.push_back(profiler->ProfilerId());

  // Since it's possible for the profiler to get destructed along with its
  // associated context, dispatch a task to cleanup context-independent isolate
  // resources (rather than use the context's task runner).
  ThreadScheduler::Current()->V8TaskRunner()->PostTask(
      FROM_HERE, WTF::BindOnce(&ProfilerGroup::StopDetachedProfiler,
                               WrapPersistent(this), profiler->ProfilerId()));
}

void ProfilerGroup::StopDetachedProfiler(String profiler_id) {
  DCHECK(IsMainThread());

  // we use a vector instead of a map because the expected number of profiler
  // is expected to be very small
  auto it = base::ranges::find(detached_profiler_ids_, profiler_id);

  if (it == detached_profiler_ids_.end()) {
    // Profiler already stopped
    return;
  }

  CancelProfilerImpl(profiler_id);
  detached_profiler_ids_.erase(it);
}

void ProfilerGroup::StopDetachedProfilers() {
  DCHECK(IsMainThread());

  for (auto& detached_profiler_id : detached_profiler_ids_) {
    CancelProfilerImpl(detached_profiler_id);
  }
  detached_profiler_ids_.clear();
}

void ProfilerGroup::CancelProfilerImpl(String profiler_id) {
  if (!cpu_profiler_)
    return;

  v8::HandleScope scope(isolate_);
  v8::Local<v8::String> v8_profiler_id = V8String(isolate_, profiler_id);
  auto* profile = cpu_profiler_->StopProfiling(v8_profiler_id);

  profile->Delete();
  --num_active_profilers_;
}

String ProfilerGroup::NextProfilerId() {
  auto id = String::Format("blink::Profiler[%d]", next_profiler_id_);
  ++next_profiler_id_;
  return id;
}

}  // namespace blink
```